package masker

import (
	"bytes"
	"encoding"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type walker struct {
	masker       *Masker
	active       map[identity]struct{}
	activeStack  []identity
	rootPath     string
	pathStack    []string
	nodes        int
	indirections int
	errs         []*MaskError
	stop         bool
}

type identity struct {
	kind   reflect.Kind
	typeOf reflect.Type
	ptr    uintptr
	len    int
	cap    int
}

type fieldCandidate struct {
	field  reflect.StructField
	index  []int
	depth  int
	tagged bool
}

type omittedValue struct{}

var omittedResult = omittedValue{}

func (m *Masker) maskRoot(value any, source Source, root Field) (any, error) {
	w := &walker{masker: m, rootPath: root.Path}
	result := w.walk(reflect.ValueOf(value), root, 0, "")
	if isOmitted(result) {
		result = nil
	}
	return result, aggregateErrors(w.errs)
}

func isOmitted(value any) bool {
	_, ok := value.(omittedValue)
	return ok
}

func (m *Masker) maskScalarField(field Field, value any) (any, bool, error) {
	if !utf8.ValidString(field.Key) {
		return m.cfg.marker, true, maskError(CodeInvalidUTF8, "mask", field.Path)
	}
	reflected := reflect.ValueOf(value)
	if !reflected.IsValid() {
		// An untyped nil is decided by the walker like any other nil.
		return nil, false, nil
	}
	if textualValue(reflected) {
		// The walker renders it through MarshalText after the decision.
		return nil, false, nil
	}
	switch reflected.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.String:
	default:
		return nil, false, nil
	}

	if field.Kind == KindInvalid {
		field.Kind = kindOfReflect(reflected)
	}
	if reflected.Kind() == reflect.String && !utf8.ValidString(reflected.String()) {
		return m.cfg.marker, true, maskError(CodeInvalidUTF8, "mask", field.Path)
	}
	decision, err := callPolicy(m.policy, field)
	if err != nil {
		code := CodePolicyFailure
		if isPanicError(err) {
			code = CodePanic
		}
		return m.cfg.marker, true, aggregateErrors([]*MaskError{newFieldError(code, field, 0)})
	}
	if decision.Omit {
		return omittedResult, true, nil
	}
	if isNilRule(decision.Rule) {
		if s, ok := m.inspectableScalar(reflected); ok {
			nodes := 1
			var errs []*MaskError
			var stop bool
			state := inspectState{nodes: &nodes, errs: &errs, stop: &stop}
			masked, changed := m.inspectString(s, field, 0, state)
			if changed {
				if len(errs) > 0 {
					return m.cfg.marker, true, aggregateErrors(errs)
				}
				return masked, true, nil
			}
		}
		return safeScalar(reflected, m.cfg.preserveSafe, m.cfg.marker), true, nil
	}

	rule := decision.Rule
	if field.Source == SourceHeader {
		rule = FullRule()
	}
	result, err := applyRule(rule, RuleInput{
		Value:     scalarText(reflected),
		Kind:      field.Kind,
		Redaction: m.cfg.marker,
	})
	if err != nil {
		code := CodeRuleFailure
		if isPanicError(err) {
			code = CodePanic
		}
		return m.cfg.marker, true, aggregateErrors([]*MaskError{ruleFieldError(code, field, rule)})
	}
	return result, true, nil
}

func (w *walker) walk(value reflect.Value, field Field, depth int, tag string) any {
	if w.stop {
		return w.masker.cfg.marker
	}
	if !utf8.ValidString(field.Key) {
		w.fail(CodeInvalidUTF8, field, depth)
		return w.masker.cfg.marker
	}
	if depth > w.masker.cfg.maxDepth {
		w.fail(CodeDepthLimit, field, depth)
		return w.masker.cfg.marker
	}
	w.nodes++
	if w.nodes > w.masker.cfg.maxNodes {
		w.fail(CodeNodeLimit, field, depth)
		return w.masker.cfg.marker
	}
	value, nilValue := unwrapInterfaces(value)
	if nilValue || !value.IsValid() {
		return w.nilValue(field, tag)
	}

	trackedStart := len(w.activeStack)
	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			w.releaseTracked(trackedStart)
			return w.nilValue(field, tag)
		}
		if !w.track(value, field, depth) {
			w.releaseTracked(trackedStart)
			return w.masker.cfg.marker
		}
		if !w.dereference(field, depth) {
			w.releaseTracked(trackedStart)
			return w.masker.cfg.marker
		}
		value = value.Elem()
		value, nilValue = unwrapInterfaces(value)
		if nilValue || !value.IsValid() {
			w.releaseTracked(trackedStart)
			return w.nilValue(field, tag)
		}
	}
	if value.Type() == rawMessageType {
		// Pointers into a json.RawMessage cannot form a cycle through the
		// decoded tree, which is private to this walk.
		w.releaseTracked(trackedStart)
		decoded, ok := w.decodeRawMessage(value, field, depth)
		if !ok {
			return w.masker.cfg.marker
		}
		// The decoded root stands in for this node and is not counted twice.
		// It and its members are JSON, and are decided as MaskJSON decides
		// them, so a policy scoped to SourceJSON sees the same document; a
		// header value stays a header and keeps its full redaction.
		w.nodes--
		if field.Source != SourceHeader {
			field.Source = SourceJSON
		}
		return w.walk(reflect.ValueOf(decoded), field, depth, tag)
	}
	// A value that renders as text is decided as a string, but MarshalText
	// runs only once a rule or the safe output actually needs the text, so an
	// omitted or fully redacted field never calls it.
	textual := textualValue(value)
	if textual {
		field.Kind = KindString
	}
	if !textual && (value.Kind() == reflect.Map || value.Kind() == reflect.Slice) {
		if !w.track(value, field, depth) {
			w.releaseTracked(trackedStart)
			return w.masker.cfg.marker
		}
	}

	if field.Kind == KindInvalid {
		field.Kind = kindOfReflect(value)
	}
	if !textual && value.Kind() == reflect.String && !utf8.ValidString(value.String()) {
		w.fail(CodeInvalidUTF8, field, depth)
		w.releaseTracked(trackedStart)
		return w.masker.cfg.marker
	}
	if handled, result := w.applyFieldDecision(value, field, tag, depth); handled {
		w.releaseTracked(trackedStart)
		return result
	}
	if textual {
		w.releaseTracked(trackedStart)
		text, ok := w.renderText(value, field, depth)
		if !ok {
			return w.masker.cfg.marker
		}
		if w.masker.inspectable(text) {
			if masked, changed := w.inspect(text, field, depth); changed {
				return masked
			}
		}
		return w.safeScalar(reflect.ValueOf(text))
	}

	var result any
	switch value.Kind() {
	case reflect.String:
		result = w.safeScalar(value)
		if s, ok := w.masker.inspectableScalar(value); ok {
			if masked, changed := w.inspect(s, field, depth); changed {
				result = masked
			}
		}
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		result = w.safeScalar(value)
	case reflect.Map:
		result = w.mapValue(value, field, depth)
	case reflect.Slice, reflect.Array:
		result = w.arrayValue(value, field, depth)
	case reflect.Struct:
		result = w.structValue(value, field, depth)
	default:
		w.fail(CodeUnsupportedType, field, depth)
		result = w.masker.cfg.marker
	}
	w.releaseTracked(trackedStart)
	return result
}

// rawMessageType is json.RawMessage, which encoding/json embeds verbatim
// instead of encoding it as base64 like any other byte slice.
var rawMessageType = reflect.TypeFor[json.RawMessage]()

// decodeRawMessage decodes an embedded JSON document so the walker can mask it
// by its keys like any other map or slice. Base64 would hide nothing: it is
// reversible, and encoding/json would log the document itself. A nil message
// encodes as null; one that is not a single valid JSON value fails closed. The
// document is charged one node per byte before it is decoded, as a byte slice
// is before it is encoded.
func (w *walker) decodeRawMessage(value reflect.Value, field Field, depth int) (any, bool) {
	if value.IsNil() {
		return nil, true
	}
	data := value.Bytes()
	if !w.chargeCopy(len(data)) {
		w.fail(CodeNodeLimit, field, depth)
		return nil, false
	}
	if !utf8.Valid(data) {
		w.fail(CodeInvalidUTF8, field, depth)
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		w.fail(CodeInvalidJSON, field, depth)
		return nil, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		w.fail(CodeInvalidJSON, field, depth)
		return nil, false
	}
	return decoded, true
}

// textMarshalerType is the encoding.TextMarshaler interface type, resolved
// once so the walker can detect it with a cheap Implements call.
var textMarshalerType = reflect.TypeFor[encoding.TextMarshaler]()

// textualValue reports whether the walker renders value as text the way
// encoding/json would: an encoding.TextMarshaler becomes its text and a
// non-nil byte slice its base64 form. Only the type is inspected.
func textualValue(value reflect.Value) bool {
	return implementsTextMarshaler(value) || byteSliceValue(value)
}

// implementsTextMarshaler reports a value the walker renders through
// MarshalText: the value, or a pointer to it when it is addressable, as in
// encoding/json, implements encoding.TextMarshaler, and the method can run on
// a copy that shares no memory with the input. Any other marshaler is walked
// like an ordinary value, so user code never sees the input's storage.
func implementsTextMarshaler(value reflect.Value) bool {
	typ := value.Type()
	if typ.NumMethod() == 0 && !value.CanAddr() {
		// No exported methods at all, as for a plain string or number: the
		// cheapest check on the scalar hot path.
		return false
	}
	if !value.CanInterface() {
		return false
	}
	implements := typ.Implements(textMarshalerType) ||
		value.CanAddr() && reflect.PointerTo(typ).Implements(textMarshalerType)
	return implements && isolatableTextType(typ)
}

// byteSliceValue reports a non-nil byte slice encoded as base64. As in
// encoding/json, a slice whose elements marshal themselves is walked instead.
func byteSliceValue(value reflect.Value) bool {
	if value.Kind() != reflect.Slice || value.IsNil() {
		return false
	}
	elem := value.Type().Elem()
	return elem.Kind() == reflect.Uint8 &&
		!elem.Implements(textMarshalerType) && !reflect.PointerTo(elem).Implements(textMarshalerType)
}

// renderText renders a value textualValue accepted and records a failure.
// MarshalText runs on an isolated copy of the value. A byte slice is charged
// one node per byte before it is encoded, as it was when it was traversed
// element by element, so its length cannot force a proportional allocation
// past the node limit; copying a receiver is charged the same way.
func (w *walker) renderText(value reflect.Value, field Field, depth int) (string, bool) {
	if !implementsTextMarshaler(value) {
		if !w.chargeCopy(value.Len()) {
			w.fail(CodeNodeLimit, field, depth)
			return "", false
		}
		return base64.StdEncoding.EncodeToString(value.Bytes()), true
	}
	receiver, code, failDepth := w.isolatedReceiver(value, depth)
	if code != "" {
		w.fail(code, field, failDepth)
		return "", false
	}
	text, code := marshalText(receiver)
	if code != "" {
		w.fail(code, field, depth)
		return "", false
	}
	return text, true
}

// marshalText calls MarshalText through a pointer to the receiver, or on the
// value it points to when the method has a value receiver. A non-empty code
// reports the error category a failing MarshalText is reduced to.
func marshalText(receiver reflect.Value) (string, ErrorCode) {
	marshaler, ok := receiver.Interface().(encoding.TextMarshaler)
	if !ok || receiver.Type().Elem().Implements(textMarshalerType) {
		marshaler, _ = receiver.Elem().Interface().(encoding.TextMarshaler)
	}
	encoded, err := marshalTextSafely(marshaler)
	switch {
	case err != nil:
		if isPanicError(err) {
			return "", CodePanic
		}
		return "", CodeUnsupportedType
	case !utf8.ValidString(string(encoded)):
		return "", CodeInvalidUTF8
	default:
		return string(encoded), ""
	}
}

// marshalTextSafely calls MarshalText and converts a panic into the safe
// panic category, so hostile implementations fail closed like other
// caller-supplied callbacks.
func marshalTextSafely(marshaler encoding.TextMarshaler) (text []byte, err error) {
	defer func() {
		if recover() != nil {
			text = nil
			err = fmt.Errorf("%w: marshal text panic", errorSentinels[CodePanic])
		}
	}()
	return marshaler.MarshalText()
}

func (w *walker) track(value reflect.Value, field Field, depth int) bool {
	id, ok := valueIdentity(value)
	if !ok {
		return true
	}
	if _, active := w.active[id]; active {
		w.fail(CodeCycle, field, depth)
		return false
	}
	if w.active == nil {
		w.active = make(map[identity]struct{})
	}
	w.active[id] = struct{}{}
	w.activeStack = append(w.activeStack, id)
	return true
}

// releaseTracked removes the identities pushed since start, so a sibling
// branch never sees an ancestor's identity as an active cycle.
func (w *walker) releaseTracked(start int) {
	for index := len(w.activeStack) - 1; index >= start; index-- {
		delete(w.active, w.activeStack[index])
	}
	w.activeStack = w.activeStack[:start]
}

func (w *walker) applyFieldDecision(value reflect.Value, field Field, tag string, depth int) (bool, any) {
	if tag != "" {
		if tag == "omit" {
			return true, omittedResult
		}
		rule, known := w.masker.cfg.tagRules[tag]
		if !known {
			w.fail(CodeInvalidConfig, field, 0)
			return true, w.masker.cfg.marker
		}
		return true, w.apply(rule, value, field, depth)
	}

	decision, err := callPolicy(w.masker.policy, field)
	if err != nil {
		code := CodePolicyFailure
		if isPanicError(err) {
			code = CodePanic
		}
		w.fail(code, field, 0)
		return true, w.masker.cfg.marker
	}
	if decision.Omit {
		return true, omittedResult
	}
	if !isNilRule(decision.Rule) {
		if field.Source == SourceHeader {
			return true, w.apply(FullRule(), value, field, depth)
		}
		return true, w.apply(decision.Rule, value, field, depth)
	}
	return false, nil
}

// nilValue decides a nil value the way MaskJSON decides null: a tag or the
// policy can omit it or apply a rule to empty text, and otherwise it stays nil.
// The value itself is never rendered, so it needs no reflection.
func (w *walker) nilValue(field Field, tag string) any {
	field.Kind = KindNil
	var rule Rule
	if tag != "" {
		if tag == "omit" {
			return omittedResult
		}
		tagRule, known := w.masker.cfg.tagRules[tag]
		if !known {
			w.fail(CodeInvalidConfig, field, 0)
			return w.masker.cfg.marker
		}
		rule = tagRule
	} else {
		decision, err := callPolicy(w.masker.policy, field)
		if err != nil {
			code := CodePolicyFailure
			if isPanicError(err) {
				code = CodePanic
			}
			w.fail(code, field, 0)
			return w.masker.cfg.marker
		}
		if decision.Omit {
			return omittedResult
		}
		rule = decision.Rule
	}
	if isNilRule(rule) {
		return nil
	}
	if field.Source == SourceHeader {
		rule = FullRule()
	}
	result, err := applyRule(rule, RuleInput{Kind: KindNil, Redaction: w.masker.cfg.marker})
	if err != nil {
		code := CodeRuleFailure
		if isPanicError(err) {
			code = CodePanic
		}
		addRuleError(&w.errs, code, w.locate(field), rule)
		return w.masker.cfg.marker
	}
	return result
}

func (w *walker) apply(rule Rule, value reflect.Value, field Field, depth int) any {
	var text string
	switch {
	case rule == Rule(fullRule) || rule == Rule(passwordRule) || rule == Rule(tokenRule):
		// These rules redact fully and ignore the value, so it is never rendered.
	case textualValue(value):
		rendered, ok := w.renderText(value, field, depth)
		if !ok {
			return w.masker.cfg.marker
		}
		text = rendered
	default:
		text = scalarText(value)
	}
	result, err := applyRule(rule, RuleInput{Value: text, Kind: field.Kind, Redaction: w.masker.cfg.marker})
	if err != nil {
		code := CodeRuleFailure
		if isPanicError(err) {
			code = CodePanic
		}
		addRuleError(&w.errs, code, w.locate(field), rule)
		return w.masker.cfg.marker
	}
	return result
}

func (w *walker) mapValue(value reflect.Value, field Field, depth int) any {
	if value.Type().Key().Kind() != reflect.String {
		w.fail(CodeUnsupportedKey, field, depth)
		return w.masker.cfg.marker
	}
	result := make(map[string]any, w.resultCapacity(value.Len()))
	iter := value.MapRange()
	for iter.Next() {
		if w.stop {
			break
		}
		key := iter.Key()
		childValue := iter.Value()
		keyText := key.String()
		childField := Field{Key: keyText, Source: field.Source}
		if w.masker.cfg.needPaths {
			childField.Path = pathFor(field.Path, keyText)
		}
		if childField.Source == SourceUnknown {
			childField.Source = SourceMap
		}
		w.pushPath(keyText)
		childResult := w.walk(childValue, childField, depth+1, "")
		w.popPath()
		if w.stop {
			break
		}
		if isOmitted(childResult) {
			continue
		}
		result[keyText] = childResult
	}
	return result
}

func (w *walker) arrayValue(value reflect.Value, field Field, depth int) any {
	result := make([]any, 0, w.resultCapacity(value.Len()))
	for i := range value.Len() {
		if w.stop {
			break
		}
		childField := Field{Source: field.Source}
		if w.masker.cfg.needPaths {
			childField.Path = pathForIndex(field.Path, i)
		}
		w.pushPath(strconv.Itoa(i))
		childResult := w.walk(value.Index(i), childField, depth+1, "")
		w.popPath()
		if w.stop {
			break
		}
		if isOmitted(childResult) {
			result = append(result, nil)
			continue
		}
		result = append(result, childResult)
	}
	return result
}

func (w *walker) structValue(value reflect.Value, field Field, depth int) any {
	metadata := w.masker.structMetadata.load(value.Type(), w.masker.cfg.structTag, w.masker.cfg.tagRules, w.masker.policy)
	if metadata.flatScalar {
		return w.flatScalarStructValue(value, field, depth, metadata)
	}
	result := make(map[string]any, w.resultCapacity(len(metadata.fields)))
	for _, conflict := range metadata.conflicts {
		for _, conflicting := range conflict.conflicting {
			conflictField := Field{Key: conflict.field, Source: SourceStruct}
			if w.masker.cfg.needPaths {
				conflictField.Path = pathFor(field.Path, conflict.field)
			}
			w.pushPath(conflict.field)
			w.failConflict(conflictField, conflicting)
			w.popPath()
		}
	}
	for _, candidate := range metadata.fields {
		if w.stop {
			break
		}
		childValue, ok := fieldByIndex(value, candidate.index)
		if !ok {
			continue
		}
		if candidate.jsonOmit || candidate.maskTag == "omit" {
			continue
		}
		childField := Field{Key: candidate.jsonName, Source: SourceStruct}
		if w.masker.cfg.needPaths {
			childField.Path = pathFor(field.Path, candidate.jsonName)
		}
		w.pushPath(candidate.jsonName)
		var childResult any
		if candidate.flatScalar {
			// A scalar field of a mixed struct takes the flat path, which uses
			// the decision compiled for its key instead of calling the policy.
			childField.Kind = candidate.kind
			childResult = w.walkFlatScalar(childValue, childField, depth+1, candidate)
		} else {
			childResult = w.walk(childValue, childField, depth+1, candidate.maskTag)
		}
		w.popPath()
		if !isOmitted(childResult) {
			result[candidate.jsonName] = childResult
		}
	}
	return result
}

func (w *walker) flatScalarStructValue(value reflect.Value, field Field, depth int, metadata *structMetadata) any {
	result := make(map[string]any, w.resultCapacity(len(metadata.fields)))
	for _, candidate := range metadata.fields {
		if w.stop {
			break
		}
		if candidate.jsonOmit || candidate.maskTag == "omit" {
			continue
		}
		childField := Field{
			Key:    candidate.jsonName,
			Source: SourceStruct,
			Kind:   candidate.kind,
		}
		if w.masker.cfg.needPaths {
			childField.Path = pathFor(field.Path, candidate.jsonName)
		}
		w.pushPath(candidate.jsonName)
		childResult := w.walkFlatScalar(value.Field(candidate.index[0]), childField, depth+1, candidate)
		w.popPath()
		if w.stop {
			break
		}
		if !isOmitted(childResult) {
			result[candidate.jsonName] = childResult
		}
	}
	return result
}

func (w *walker) walkFlatScalar(value reflect.Value, field Field, depth int, metadata structFieldMetadata) any {
	var result any
	if depth > w.masker.cfg.maxDepth {
		w.fail(CodeDepthLimit, field, depth)
		result = w.masker.cfg.marker
	} else {
		w.nodes++
		if w.nodes > w.masker.cfg.maxNodes {
			w.fail(CodeNodeLimit, field, depth)
			result = w.masker.cfg.marker
		} else if value.Kind() == reflect.String && !utf8.ValidString(value.String()) {
			// walk rejects invalid UTF-8 before any decision; this fast path
			// must fail closed the same way.
			w.fail(CodeInvalidUTF8, field, depth)
			result = w.masker.cfg.marker
		} else if handled, decisionResult := w.applyCompiledFieldDecision(value, field, metadata, depth); handled {
			result = decisionResult
		} else {
			result = w.safeScalar(value)
			if s, ok := w.masker.inspectableScalar(value); ok {
				if masked, changed := w.inspect(s, field, depth); changed {
					result = masked
				}
			}
		}
	}
	return result
}

func (w *walker) applyCompiledFieldDecision(value reflect.Value, field Field, metadata structFieldMetadata, depth int) (bool, any) {
	if metadata.maskTag != "" {
		if metadata.maskTag == "omit" {
			return true, omittedResult
		}
		if !metadata.tagKnown {
			w.fail(CodeInvalidConfig, field, 0)
			return true, w.masker.cfg.marker
		}
		return true, w.apply(metadata.tagRule, value, field, depth)
	}
	if metadata.policy.known {
		if metadata.policy.omit {
			return true, omittedResult
		}
		if !isNilRule(metadata.policy.rule) {
			return true, w.apply(metadata.policy.rule, value, field, depth)
		}
		return false, nil
	}
	return w.applyFieldDecision(value, field, "", depth)
}

func (w *walker) dereference(field Field, depth int) bool {
	w.indirections++
	if w.indirections <= w.masker.cfg.maxNodes {
		return true
	}
	w.fail(CodeNodeLimit, field, depth)
	return false
}

func (w *walker) resultCapacity(length int) int {
	remaining := w.masker.cfg.maxNodes - w.nodes
	if remaining <= 0 {
		return 0
	}
	return min(length, remaining)
}

func (w *walker) safeScalar(value reflect.Value) any {
	return safeScalar(value, w.masker.cfg.preserveSafe, w.masker.cfg.marker)
}

// inspect masks a document carried in a string value, joining the walker's
// node and error budget. The field is located first: a candidate pays for the
// path, a plain string never reaches here.
func (w *walker) inspect(s string, field Field, depth int) (string, bool) {
	state := inspectState{nodes: &w.nodes, errs: &w.errs, stop: &w.stop}
	return w.masker.inspectString(s, w.locate(field), depth, state)
}

func safeScalar(value reflect.Value, preserveSafe bool, marker string) any {
	if value.IsValid() && value.Type() == reflect.TypeOf(json.Number("")) {
		return value.Interface()
	}
	if preserveSafe {
		return value.Interface()
	}
	switch value.Kind() {
	case reflect.String:
		return value.String()
	case reflect.Bool:
		return strconv.FormatBool(value.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(value.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return strconv.FormatUint(value.Uint(), 10)
	case reflect.Float32, reflect.Float64:
		return strconv.FormatFloat(value.Float(), 'g', -1, value.Type().Bits())
	default:
		return marker
	}
}

// pushPath and popPath keep the segments of the current position. A policy that
// never reads Field.Path makes building the string per node pure waste, so the
// walker keeps the cheap stack and materializes a path only when a policy asks
// for one or an error has to name a location.
func (w *walker) pushPath(segment string) {
	w.pathStack = append(w.pathStack, segment)
}

func (w *walker) popPath() {
	w.pathStack = w.pathStack[:len(w.pathStack)-1]
}

func (w *walker) currentPath() string {
	path := w.rootPath
	if path == "" {
		path = "$"
	}
	if len(w.pathStack) == 0 {
		return path
	}
	var builder strings.Builder
	builder.WriteString(path)
	for _, segment := range w.pathStack {
		builder.WriteByte('[')
		builder.WriteString(segment)
		builder.WriteByte(']')
	}
	return builder.String()
}

// locate fills in a path that was not built during the walk, so an error still
// names the field it came from.
func (w *walker) locate(field Field) Field {
	if field.Path == "" {
		field.Path = w.currentPath()
	}
	return field
}

func (w *walker) fail(code ErrorCode, field Field, depth int) {
	field = w.locate(field)
	if code == CodeDepthLimit || code == CodeNodeLimit {
		if w.stop {
			return
		}
		w.stop = true
		addPriorityFieldError(&w.errs, code, field, depth)
		return
	}
	addFieldError(&w.errs, code, field, depth)
}

// ruleFieldError names the rule that failed, so a caller reading the log can
// tell which of several configured rules produced the fallback value.
func ruleFieldError(code ErrorCode, field Field, rule Rule) *MaskError {
	err := newFieldError(code, field, 0)
	err.Rule = safeDiagnostic(ruleName(rule))
	return err
}

func addRuleError(errs *[]*MaskError, code ErrorCode, field Field, rule Rule) {
	if len(*errs) >= maxMaskErrorsPerOperation {
		return
	}
	addMaskError(errs, ruleFieldError(code, field, rule))
}

func newFieldError(code ErrorCode, field Field, depth int) *MaskError {
	err := maskError(code, "mask", field.Path)
	err.Field = safeDiagnostic(field.Key)
	err.Depth = depth
	return err
}

func addFieldError(errs *[]*MaskError, code ErrorCode, field Field, depth int) {
	if len(*errs) >= maxMaskErrorsPerOperation {
		return
	}
	addMaskError(errs, newFieldError(code, field, depth))
}

func addPriorityFieldError(errs *[]*MaskError, code ErrorCode, field Field, depth int) {
	addPriorityMaskError(errs, newFieldError(code, field, depth))
}

// addPriorityMaskError records err even when the list is full, replacing its
// last entry, so a limit failure is never dropped.
func addPriorityMaskError(errs *[]*MaskError, err *MaskError) {
	if len(*errs) < maxMaskErrorsPerOperation {
		addMaskError(errs, err)
		return
	}
	(*errs)[maxMaskErrorsPerOperation-1] = err
}

func (w *walker) failConflict(field Field, conflicting string) {
	if len(w.errs) >= maxMaskErrorsPerOperation {
		return
	}
	field = w.locate(field)
	err := maskError(CodeFieldConflict, "mask", field.Path)
	err.Field = safeDiagnostic(field.Key)
	err.ConflictingField = safeDiagnostic(conflicting)
	addMaskError(&w.errs, err)
}

func valueIdentity(value reflect.Value) (identity, bool) {
	switch value.Kind() {
	case reflect.Pointer:
		ptr := value.Pointer()
		if ptr == 0 {
			return identity{}, false
		}
		return identity{kind: value.Kind(), typeOf: value.Type(), ptr: ptr}, true
	case reflect.Map:
		ptr := uintptr(value.UnsafePointer())
		if ptr == 0 {
			return identity{}, false
		}
		return identity{kind: value.Kind(), typeOf: value.Type(), ptr: ptr}, true
	case reflect.Slice:
		ptr := value.Pointer()
		if ptr == 0 {
			return identity{}, false
		}
		return identity{kind: value.Kind(), typeOf: value.Type(), ptr: ptr, len: value.Len(), cap: value.Cap()}, true
	default:
		return identity{}, false
	}
}

func unwrap(value reflect.Value) (reflect.Value, bool) {
	value, nilValue := unwrapInterfaces(value)
	if nilValue || !value.IsValid() {
		return reflect.Value{}, true
	}
	for value.IsValid() && value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return reflect.Value{}, true
		}
		value = value.Elem()
	}
	return value, !value.IsValid()
}

func unwrapInterfaces(value reflect.Value) (reflect.Value, bool) {
	for value.IsValid() && value.Kind() == reflect.Interface {
		if value.IsNil() {
			return reflect.Value{}, true
		}
		value = value.Elem()
	}
	return value, !value.IsValid()
}

func scalarText(value reflect.Value) string {
	value, nilValue := unwrap(value)
	if nilValue {
		return ""
	}
	if value.Type() == reflect.TypeOf(json.Number("")) {
		// json.Number has string as its underlying type, so read it directly:
		// Interface() panics on values reached through an unexported field.
		return value.String()
	}
	switch value.Kind() {
	case reflect.String:
		return value.String()
	case reflect.Bool:
		return strconv.FormatBool(value.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(value.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return strconv.FormatUint(value.Uint(), 10)
	case reflect.Float32, reflect.Float64:
		return strconv.FormatFloat(value.Float(), 'g', -1, value.Type().Bits())
	default:
		return ""
	}
}

func kindOfReflect(value reflect.Value) ValueKind {
	value, nilValue := unwrap(value)
	if nilValue || !value.IsValid() {
		return KindNil
	}
	switch value.Kind() {
	case reflect.String:
		if value.Type() == reflect.TypeOf(json.Number("")) {
			return KindNumber
		}
		return KindString
	case reflect.Bool:
		return KindBool
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		return KindNumber
	case reflect.Map, reflect.Struct:
		return KindObject
	case reflect.Slice, reflect.Array:
		return KindArray
	default:
		return KindInvalid
	}
}

func kindOfType(typ reflect.Type) ValueKind {
	if typ == reflect.TypeOf(json.Number("")) {
		return KindNumber
	}
	switch typ.Kind() {
	case reflect.String:
		return KindString
	case reflect.Bool:
		return KindBool
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		return KindNumber
	case reflect.Map, reflect.Struct:
		return KindObject
	case reflect.Slice, reflect.Array:
		return KindArray
	default:
		return KindInvalid
	}
}

func valueKindOf(value any) ValueKind { return kindOfReflect(reflect.ValueOf(value)) }

func visibleFields(typ reflect.Type) ([]fieldCandidate, [][]fieldCandidate) {
	var candidates []fieldCandidate
	collectFields(typ, nil, 0, map[reflect.Type]bool{}, &candidates)
	byName := make(map[string][]fieldCandidate)
	for _, candidate := range candidates {
		name, _ := jsonFieldName(candidate.field)
		byName[name] = append(byName[name], candidate)
	}
	var result []fieldCandidate
	var conflicts [][]fieldCandidate
	for _, group := range byName {
		minDepth := group[0].depth
		for _, candidate := range group[1:] {
			if candidate.depth < minDepth {
				minDepth = candidate.depth
			}
		}
		best := make([]fieldCandidate, 0, len(group))
		for _, candidate := range group {
			if candidate.depth == minDepth {
				best = append(best, candidate)
			}
		}
		var tagged []fieldCandidate
		for _, candidate := range best {
			if candidate.tagged {
				tagged = append(tagged, candidate)
			}
		}
		if len(tagged) == 1 {
			best = tagged
		}
		if len(best) > 1 {
			conflicts = append(conflicts, best)
			continue
		}
		result = append(result, best[0])
	}
	slices.SortFunc(result, compareFieldCandidates)
	slices.SortFunc(conflicts, func(left, right []fieldCandidate) int {
		return compareFieldCandidates(left[0], right[0])
	})
	return result, conflicts
}

func compareFieldCandidates(left, right fieldCandidate) int {
	if result := strings.Compare(left.field.Name, right.field.Name); result != 0 {
		return result
	}
	if len(left.index) != len(right.index) {
		if len(left.index) < len(right.index) {
			return -1
		}
		return 1
	}
	for index := range left.index {
		if left.index[index] != right.index[index] {
			if left.index[index] < right.index[index] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func collectFields(typ reflect.Type, prefix []int, depth int, stack map[reflect.Type]bool, result *[]fieldCandidate) {
	if stack[typ] {
		return
	}
	stack[typ] = true
	defer delete(stack, typ)
	for i := range typ.NumField() {
		field := typ.Field(i)
		if field.PkgPath != "" && !field.Anonymous {
			continue
		}
		if field.PkgPath != "" && field.Anonymous {
			fieldType := field.Type
			if fieldType.Kind() == reflect.Pointer {
				fieldType = fieldType.Elem()
			}
			if fieldType.Kind() != reflect.Struct {
				continue
			}
		}
		_, omitted := jsonFieldName(field)
		if omitted {
			continue
		}
		index := append(append([]int(nil), prefix...), i)
		fieldType := field.Type
		// Only an embedding without a JSON name is promoted: encoding/json
		// keeps `json:"Credentials"` a named object even when the name equals
		// the Go field name, and the policy must see that key.
		if field.Anonymous && !jsonFieldTagged(field) {
			if fieldType.Kind() == reflect.Pointer {
				fieldType = fieldType.Elem()
			}
			if fieldType.Kind() == reflect.Struct {
				collectFields(fieldType, index, depth+1, stack, result)
				continue
			}
		}
		*result = append(*result, fieldCandidate{field: field, index: index, depth: depth, tagged: jsonFieldTagged(field)})
	}
}

func fieldByIndex(value reflect.Value, index []int) (reflect.Value, bool) {
	for _, part := range index {
		for value.IsValid() && value.Kind() == reflect.Pointer {
			if value.IsNil() {
				return reflect.Value{}, false
			}
			value = value.Elem()
		}
		if !value.IsValid() || value.Kind() != reflect.Struct || part >= value.NumField() {
			return reflect.Value{}, false
		}
		value = value.Field(part)
	}
	return value, value.IsValid()
}

func jsonFieldName(field reflect.StructField) (string, bool) {
	tag, ok := field.Tag.Lookup("json")
	if ok {
		// Only a bare "-" omits the field; "-," names it "-", as in encoding/json.
		if tag == "-" {
			return "", true
		}
		name, _, _ := strings.Cut(tag, ",")
		if validJSONTagName(name) {
			return name, false
		}
	}
	return field.Name, false
}

func jsonFieldTagged(field reflect.StructField) bool {
	tag, ok := field.Tag.Lookup("json")
	if !ok {
		return false
	}
	name, _, _ := strings.Cut(tag, ",")
	return validJSONTagName(name) && tag != "-"
}

// validJSONTagName reports a tag name encoding/json accepts in every Go
// release. Up to Go 1.26 encoding/json ignores any other name and writes the Go
// field name, which the walker uses too; see ambiguousJSONName for why such a
// field is still never decided by that name.
// ambiguousJSONTag is the mask tag given to a field whose JSON name depends on
// the Go release. No tag rule can have this name, because tag rule names
// cannot contain a space, so the field fails closed as an unknown tag.
const ambiguousJSONTag = " ambiguous json name"

// ambiguousJSONName reports a field whose json tag names it with a name that
// validJSONTagName rejects. Go 1.26 and earlier write such a field under its Go
// name, while Go 1.27, whose encoding/json is built on json v2, cuts the name
// at the first backslash or quote and accepts any other character, so no one
// key is the one encoding/json writes. Deciding the policy by either name
// could hide the key it matches, so the field is redacted instead.
func ambiguousJSONName(field reflect.StructField) bool {
	tag, ok := field.Tag.Lookup("json")
	if !ok || tag == "-" {
		return false
	}
	name, _, _ := strings.Cut(tag, ",")
	return name != "" && !validJSONTagName(name)
}

func validJSONTagName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		switch {
		case strings.ContainsRune("!#$%&()*+-./:;<=>?@[]^_{|}~ ", c):
			// Backslash and quote are reserved, but other punctuation is fine.
		case !unicode.IsLetter(c) && !unicode.IsDigit(c):
			return false
		}
	}
	return true
}

func structMaskTag(field reflect.StructField, tagName string) string {
	value, ok := field.Tag.Lookup(tagName)
	if !ok {
		return ""
	}
	return value
}
