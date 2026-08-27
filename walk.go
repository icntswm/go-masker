package masker

import (
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

type walker struct {
	masker       *Masker
	active       map[identity]struct{}
	activeStack  []identity
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
	w := &walker{masker: m}
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
		return m.cfg.marker, true, aggregateErrors([]*MaskError{newFieldError(code, field, 0)})
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
		return nil
	}

	trackedStart := len(w.activeStack)
	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			w.releaseTracked(trackedStart)
			return nil
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
			return nil
		}
	}
	if value.Kind() == reflect.Map || value.Kind() == reflect.Slice {
		if !w.track(value, field, depth) {
			w.releaseTracked(trackedStart)
			return w.masker.cfg.marker
		}
	}

	if field.Kind == KindInvalid {
		field.Kind = kindOfReflect(value)
	}
	if value.Kind() == reflect.String && !utf8.ValidString(value.String()) {
		w.fail(CodeInvalidUTF8, field, depth)
		w.releaseTracked(trackedStart)
		return w.masker.cfg.marker
	}
	if handled, result := w.applyFieldDecision(value, field, tag); handled {
		w.releaseTracked(trackedStart)
		return result
	}

	var result any
	switch value.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.String:
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

func (w *walker) releaseTracked(start int) {
	for index := len(w.activeStack) - 1; index >= start; index-- {
		delete(w.active, w.activeStack[index])
	}
	w.activeStack = w.activeStack[:start]
}

func (w *walker) applyFieldDecision(value reflect.Value, field Field, tag string) (bool, any) {
	if tag != "" {
		if tag == "omit" {
			return true, omittedResult
		}
		rule, known := w.masker.cfg.tagRules[tag]
		if !known {
			w.fail(CodeInvalidConfig, field, 0)
			return true, w.masker.cfg.marker
		}
		return true, w.apply(rule, value, field)
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
			return true, w.apply(FullRule(), value, field)
		}
		return true, w.apply(decision.Rule, value, field)
	}
	return false, nil
}

func (w *walker) apply(rule Rule, value reflect.Value, field Field) any {
	text := scalarText(value)
	result, err := applyRule(rule, RuleInput{Value: text, Kind: field.Kind, Redaction: w.masker.cfg.marker})
	if err != nil {
		code := CodeRuleFailure
		if isPanicError(err) {
			code = CodePanic
		}
		w.fail(code, field, 0)
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
		childField := Field{Key: keyText, Path: pathFor(field.Path, keyText), Source: field.Source}
		if childField.Source == SourceUnknown {
			childField.Source = SourceMap
		}
		childResult := w.walk(childValue, childField, depth+1, "")
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
	for i := 0; i < value.Len(); i++ {
		if w.stop {
			break
		}
		childField := Field{Path: pathForIndex(field.Path, i), Source: field.Source}
		childResult := w.walk(value.Index(i), childField, depth+1, "")
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
			conflictField := Field{Key: conflict.field, Path: pathFor(field.Path, conflict.field), Source: SourceStruct}
			w.failConflict(conflictField, conflicting)
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
		childField := Field{Key: candidate.jsonName, Path: pathFor(field.Path, candidate.jsonName), Source: SourceStruct}
		childResult := w.walk(childValue, childField, depth+1, candidate.maskTag)
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
		childResult := w.walkFlatScalar(value.Field(candidate.index[0]), childField, depth+1, candidate, field.Path)
		if w.stop {
			break
		}
		if !isOmitted(childResult) {
			result[candidate.jsonName] = childResult
		}
	}
	return result
}

func (w *walker) walkFlatScalar(value reflect.Value, field Field, depth int, metadata structFieldMetadata, parentPath string) any {
	errStart := len(w.errs)
	var result any
	if depth > w.masker.cfg.maxDepth {
		w.fail(CodeDepthLimit, field, depth)
		result = w.masker.cfg.marker
	} else {
		w.nodes++
		if w.nodes > w.masker.cfg.maxNodes {
			w.fail(CodeNodeLimit, field, depth)
			result = w.masker.cfg.marker
		} else if handled, decisionResult := w.applyCompiledFieldDecision(value, field, metadata); handled {
			result = decisionResult
		} else {
			result = w.safeScalar(value)
		}
	}
	if field.Path == "" && len(w.errs) > errStart {
		path := pathFor(parentPath, field.Key)
		for _, err := range w.errs[errStart:] {
			if err != nil && err.Path == "" {
				err.Path = path
			}
		}
	}
	return result
}

func (w *walker) applyCompiledFieldDecision(value reflect.Value, field Field, metadata structFieldMetadata) (bool, any) {
	if metadata.maskTag != "" {
		if metadata.maskTag == "omit" {
			return true, omittedResult
		}
		if !metadata.tagKnown {
			w.fail(CodeInvalidConfig, field, 0)
			return true, w.masker.cfg.marker
		}
		return true, w.apply(metadata.tagRule, value, field)
	}
	if metadata.policy.known {
		if metadata.policy.omit {
			return true, omittedResult
		}
		if !isNilRule(metadata.policy.rule) {
			return true, w.apply(metadata.policy.rule, value, field)
		}
		return false, nil
	}
	return w.applyFieldDecision(value, field, "")
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

func (w *walker) fail(code ErrorCode, field Field, depth int) {
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

func newFieldError(code ErrorCode, field Field, depth int) *MaskError {
	err := maskError(code, "mask", field.Path)
	err.Field = field.Key
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
	err := newFieldError(code, field, depth)
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
	err := maskError(CodeFieldConflict, "mask", field.Path)
	err.Field = field.Key
	err.ConflictingField = conflicting
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
		return value.Interface().(json.Number).String()
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
	for i := 0; i < typ.NumField(); i++ {
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
		name, omitted := jsonFieldName(field)
		if omitted {
			continue
		}
		index := append(append([]int(nil), prefix...), i)
		fieldType := field.Type
		if field.Anonymous && name == field.Name {
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
		name := strings.Split(tag, ",")[0]
		if name == "-" {
			return "", true
		}
		if name != "" {
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
	name := strings.Split(tag, ",")[0]
	return name != "" && name != "-"
}

func structMaskTag(field reflect.StructField, tagName string) string {
	value, ok := field.Tag.Lookup(tagName)
	if !ok {
		return ""
	}
	return value
}
