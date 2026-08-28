package masker

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"
)

type streamJSONWalker struct {
	masker          *Masker
	nodes           int
	errs            []*MaskError
	stop            bool
	path            []streamJSONPathPart
	keys            map[uint64][]streamJSONKey
	keyCacheEntries int
}

type streamJSONPathPart struct {
	key     string
	index   int
	isIndex bool
}

type streamJSONMember struct {
	key   string
	start int
	end   int
}

type streamJSONKey struct {
	key   string
	start int
	end   int
}

type skipJSONFrame struct {
	close byte
	state uint8
}

const (
	skipObjectKeyOrEnd uint8 = iota
	skipObjectKey
	skipObjectValue
	skipObjectCommaOrEnd
	skipArrayValueOrEnd
	skipArrayValue
	skipArrayCommaOrEnd
)

type streamObjectBuffers struct {
	scratch []byte
	members []streamJSONMember
}

const (
	streamObjectSmallScratchLimit = 64 << 10
	streamObjectMaxPooledScratch  = 16 << 20
	streamObjectLargeBufferSlots  = 4
	streamObjectMemberIndexCutoff = 32
	streamJSONKeyCacheMaxEntries  = 4096
	streamJSONKeyCacheMaxChain    = 8
)

// newStreamObjectBuffers is the single place the starting capacities live, so
// the pool and its fallback cannot drift apart.
func newStreamObjectBuffers() *streamObjectBuffers {
	return &streamObjectBuffers{
		scratch: make([]byte, 0, 256),
		members: make([]streamJSONMember, 0, 8),
	}
}

var streamObjectBufferPool = sync.Pool{
	New: func() any { return newStreamObjectBuffers() },
}

// Keep large buffers bounded; sync.Pool is intentionally not used for them,
// because it would drop them at the next GC and a wide document would pay the
// growth again. The ceiling is deliberate and process-wide: at most
// streamObjectLargeBufferSlots buffers of streamObjectMaxPooledScratch each,
// shared by every Masker in the process and held until the process exits.
var streamObjectLargeBufferPool = make(chan *streamObjectBuffers, streamObjectLargeBufferSlots)

func (m *Masker) maskJSONStream(data []byte) ([]byte, error) {
	w := &streamJSONWalker{masker: m}
	result := make([]byte, 0, len(data))
	next, ok, _ := w.appendValue(data, 0, Field{Path: "$", Source: SourceJSON}, 0, &result)
	if !ok || skipJSONSpace(data, next) != len(data) {
		return m.safeJSONFallback(), maskError(CodeInvalidJSON, "mask_json", "$")
	}
	if hasJSONResourceError(w.errs) && !validJSONDocument(data) {
		return m.safeJSONFallback(), maskError(CodeInvalidJSON, "mask_json", "$")
	}
	if err := aggregateErrors(w.errs); err != nil {
		return m.safeJSONFallback(), err
	}
	return result, nil
}

func hasJSONResourceError(errs []*MaskError) bool {
	for _, err := range errs {
		if err != nil && (err.Code == CodeDepthLimit || err.Code == CodeNodeLimit) {
			return true
		}
	}
	return false
}

func (w *streamJSONWalker) appendValue(data []byte, start int, field Field, depth int, out *[]byte) (int, bool, bool) {
	start = skipJSONSpace(data, start)
	if start >= len(data) {
		return start, false, false
	}
	if w.stop {
		end := skipJSONValue(data, start)
		*out = appendJSONString(*out, w.masker.cfg.marker)
		return end, end >= 0, false
	}
	if depth > w.masker.cfg.maxDepth {
		w.fail(CodeDepthLimit, field, depth)
		end := skipJSONValue(data, start)
		*out = appendJSONString(*out, w.masker.cfg.marker)
		return end, end >= 0, false
	}
	w.nodes++
	if w.nodes > w.masker.cfg.maxNodes {
		w.fail(CodeNodeLimit, field, depth)
		end := skipJSONValue(data, start)
		*out = appendJSONString(*out, w.masker.cfg.marker)
		return end, end >= 0, false
	}

	kind := streamJSONKind(data[start])
	if kind == KindInvalid {
		return start, false, false
	}
	if w.masker.cfg.needPaths {
		field.Path = w.currentPath()
	}
	field.Kind = kind
	scalarEnd, scalarOK := streamScalarEnd(data, start, kind)
	if !scalarOK {
		return start, false, false
	}
	if handled, end, omitted := w.decide(field, data, start, scalarEnd, out); handled {
		if end == 0 {
			end = skipJSONValue(data, start)
		}
		if omitted && len(w.path) == 0 {
			*out = append(*out, "null"...)
		}
		return end, end >= 0, omitted
	}

	switch kind {
	case KindString:
		var ok bool
		*out, ok = appendStreamJSONString(*out, data[start:scalarEnd])
		if !ok {
			return start, false, false
		}
		return scalarEnd, true, false
	case KindBool:
		if w.masker.cfg.preserveSafe {
			*out = append(*out, data[start:scalarEnd]...)
		} else {
			*out = appendJSONString(*out, string(data[start:scalarEnd]))
		}
		return scalarEnd, true, false
	case KindNil:
		*out = append(*out, "null"...)
		return scalarEnd, true, false
	case KindNumber:
		*out = append(*out, data[start:scalarEnd]...)
		return scalarEnd, true, false
	case KindObject:
		return w.appendObject(data, start, field, depth, out)
	case KindArray:
		return w.appendArray(data, start, field, depth, out)
	default:
		return start, false, false
	}
}

func (w *streamJSONWalker) decide(field Field, data []byte, start, scalarEnd int, out *[]byte) (bool, int, bool) {
	decision, err := callPolicy(w.masker.policy, field)
	if err != nil {
		code := CodePolicyFailure
		if isPanicError(err) {
			code = CodePanic
		}
		w.fail(code, field, 0)
		*out = appendJSONString(*out, w.masker.cfg.marker)
		return true, 0, false
	}
	if decision.Omit {
		return true, 0, true
	}
	if isNilRule(decision.Rule) {
		return false, 0, false
	}
	text := ""
	if field.Kind == KindString {
		var ok bool
		text, ok = streamJSONStringText(data[start:scalarEnd])
		if !ok {
			return true, -1, false
		}
	} else if scalarEnd > 0 && field.Kind != KindNil {
		text = string(data[start:scalarEnd])
	}
	result, err := applyRule(decision.Rule, RuleInput{
		Value:     text,
		Kind:      field.Kind,
		Redaction: w.masker.cfg.marker,
	})
	if err != nil {
		code := CodeRuleFailure
		if isPanicError(err) {
			code = CodePanic
		}
		addUniqueRuleError(&w.errs, code, field, decision.Rule)
		*out = appendJSONString(*out, w.masker.cfg.marker)
		return true, 0, false
	}
	*out = appendJSONString(*out, result)
	return true, 0, false
}

func streamJSONStringText(token []byte) (string, bool) {
	if len(token) < 2 || token[0] != '"' || token[len(token)-1] != '"' {
		return "", false
	}
	for index := 1; index < len(token)-1; index++ {
		if token[index] == '\\' || token[index] < 0x20 {
			var decoded string
			if err := json.Unmarshal(token, &decoded); err != nil {
				return "", false
			}
			return decoded, true
		}
	}
	return string(token[1 : len(token)-1]), true
}

func (w *streamJSONWalker) appendObject(data []byte, start int, field Field, depth int, out *[]byte) (int, bool, bool) {
	largeHint := depth == 0 && len(data)-start > streamObjectSmallScratchLimit
	buffers := acquireStreamObjectBuffers(largeHint)
	scratch := buffers.scratch[:0]
	members := buffers.members[:0]
	var memberIndex map[string]int
	defer func() {
		releaseStreamObjectBuffers(buffers, scratch, members)
	}()
	position := skipJSONSpace(data, start+1)
	if position < len(data) && data[position] == '}' {
		*out = append(*out, "{}"...)
		return position + 1, true, false
	}
	for {
		keyStart := position
		if keyStart >= len(data) || data[keyStart] != '"' {
			return start, false, false
		}
		keyEnd := scanJSONString(data, keyStart)
		if keyStart >= len(data) || keyEnd <= keyStart || keyEnd > len(data) {
			return start, false, false
		}
		key, ok := w.streamObjectKey(data, keyStart, keyEnd)
		if !ok {
			return start, false, false
		}
		position = skipJSONSpace(data, keyEnd)
		if position >= len(data) || data[position] != ':' {
			return start, false, false
		}
		position = skipJSONSpace(data, position+1)
		childField := Field{Key: key, Source: SourceJSON}
		memberStart := len(scratch)
		w.path = append(w.path, streamJSONPathPart{key: key})
		next, ok, omitted := w.appendValue(data, position, childField, depth+1, &scratch)
		w.path = w.path[:len(w.path)-1]
		if !ok {
			return start, false, false
		}
		if omitted {
			removeStreamMember(&members, &memberIndex, key)
		} else {
			memberEnd := len(scratch)
			upsertStreamMember(&members, &memberIndex, key, memberStart, memberEnd)
		}
		position = skipJSONSpace(data, next)
		if position >= len(data) {
			return start, false, false
		}
		switch data[position] {
		case ',':
			position = skipJSONSpace(data, position+1)
			continue
		case '}':
			sortStreamMembers(members)
			*out = append(*out, '{')
			for index, member := range members {
				if index > 0 {
					*out = append(*out, ',')
				}
				*out = appendJSONString(*out, member.key)
				*out = append(*out, ':')
				*out = append(*out, scratch[member.start:member.end]...)
			}
			*out = append(*out, '}')
			return position + 1, true, false
		default:
			return start, false, false
		}
	}
}

func upsertStreamMember(members *[]streamJSONMember, index *map[string]int, key string, start, end int) {
	if *index != nil {
		if memberIndex, ok := (*index)[key]; ok {
			(*members)[memberIndex].start = start
			(*members)[memberIndex].end = end
			return
		}
	} else {
		for memberIndex := range *members {
			if (*members)[memberIndex].key == key {
				(*members)[memberIndex].start = start
				(*members)[memberIndex].end = end
				return
			}
		}
	}
	*members = append(*members, streamJSONMember{key: key, start: start, end: end})
	if *index == nil && len(*members) >= streamObjectMemberIndexCutoff {
		*index = make(map[string]int, len(*members))
		for memberIndex, member := range *members {
			(*index)[member.key] = memberIndex
		}
	}
}

func removeStreamMember(members *[]streamJSONMember, index *map[string]int, key string) {
	memberIndex := -1
	if *index != nil {
		var ok bool
		memberIndex, ok = (*index)[key]
		if !ok {
			return
		}
	} else {
		for candidate := range *members {
			if (*members)[candidate].key == key {
				memberIndex = candidate
				break
			}
		}
		if memberIndex < 0 {
			return
		}
	}
	copy((*members)[memberIndex:], (*members)[memberIndex+1:])
	*members = (*members)[:len(*members)-1]
	if *index != nil {
		delete(*index, key)
		for candidate := memberIndex; candidate < len(*members); candidate++ {
			(*index)[(*members)[candidate].key] = candidate
		}
	}
}

func acquireStreamObjectBuffers(largeHint bool) *streamObjectBuffers {
	if largeHint {
		select {
		case buffers := <-streamObjectLargeBufferPool:
			return buffers
		default:
		}
	}
	if buffers, ok := streamObjectBufferPool.Get().(*streamObjectBuffers); ok {
		return buffers
	}
	// Only *streamObjectBuffers is ever pooled; allocate rather than panic.
	return newStreamObjectBuffers()
}

func releaseStreamObjectBuffers(buffers *streamObjectBuffers, scratch []byte, members []streamJSONMember) {
	// Clear to capacity, not to length: a shorter document leaves the keys of
	// a longer earlier one alive past the end of the slice, where nothing will
	// overwrite them.
	clear(members[:cap(members)])
	if cap(members) > 256 {
		return
	}
	buffers.scratch = scratch
	buffers.members = members
	if cap(scratch) <= streamObjectSmallScratchLimit {
		streamObjectBufferPool.Put(buffers)
		return
	}
	if cap(scratch) <= streamObjectMaxPooledScratch {
		select {
		case streamObjectLargeBufferPool <- buffers:
		default:
		}
	}
}

func (w *streamJSONWalker) appendArray(data []byte, start int, field Field, depth int, out *[]byte) (int, bool, bool) {
	*out = append(*out, '[')
	position := skipJSONSpace(data, start+1)
	if position < len(data) && data[position] == ']' {
		*out = append(*out, ']')
		return position + 1, true, false
	}
	index := 0
	for {
		if index > 0 {
			*out = append(*out, ',')
		}
		childField := Field{Source: SourceJSON}
		w.path = append(w.path, streamJSONPathPart{index: index, isIndex: true})
		next, ok, omitted := w.appendValue(data, position, childField, depth+1, out)
		w.path = w.path[:len(w.path)-1]
		if !ok {
			return start, false, false
		}
		if omitted {
			*out = append(*out, "null"...)
		}
		index++
		position = skipJSONSpace(data, next)
		if position >= len(data) {
			return start, false, false
		}
		switch data[position] {
		case ',':
			position = skipJSONSpace(data, position+1)
		case ']':
			*out = append(*out, ']')
			return position + 1, true, false
		default:
			return start, false, false
		}
	}
}

func streamJSONKind(first byte) ValueKind {
	switch first {
	case '{':
		return KindObject
	case '[':
		return KindArray
	case '"':
		return KindString
	case 't', 'f':
		return KindBool
	case 'n':
		return KindNil
	default:
		if first == '-' || first >= '0' && first <= '9' {
			return KindNumber
		}
		return KindInvalid
	}
}

func streamScalarEnd(data []byte, start int, kind ValueKind) (end int, ok bool) {
	switch kind {
	case KindString:
		end = scanJSONString(data, start)
		if end <= start || end > len(data) {
			return 0, false
		}
		return end, true
	case KindBool, KindNumber, KindNil:
		end = scanJSONPrimitive(data, start)
		if end <= start || end > len(data) || !validStreamPrimitive(data[start:end], kind) {
			return 0, false
		}
		return end, true
	default:
		return 0, true
	}
}

func validStreamPrimitive(token []byte, kind ValueKind) bool {
	switch kind {
	case KindBool:
		return (len(token) == 4 && token[0] == 't' && token[1] == 'r' && token[2] == 'u' && token[3] == 'e') ||
			(len(token) == 5 && token[0] == 'f' && token[1] == 'a' && token[2] == 'l' && token[3] == 's' && token[4] == 'e')
	case KindNil:
		return len(token) == 4 && token[0] == 'n' && token[1] == 'u' && token[2] == 'l' && token[3] == 'l'
	case KindNumber:
		return validJSONNumber(token)
	default:
		return false
	}
}

func validJSONDocument(data []byte) bool {
	end := skipJSONValue(data, 0)
	return end >= 0 && skipJSONSpace(data, end) == len(data)
}

func appendStreamJSONString(dst, token []byte) ([]byte, bool) {
	if streamJSONStringCanCopy(token) {
		return append(dst, token...), true
	}
	var decoded string
	if err := json.Unmarshal(token, &decoded); err != nil {
		return dst, false
	}
	return appendJSONString(dst, decoded), true
}

func streamJSONStringCanCopy(token []byte) bool {
	if len(token) < 2 || token[0] != '"' || token[len(token)-1] != '"' {
		return false
	}
	for index := 1; index < len(token)-1; index++ {
		char := token[index]
		if char == '\\' || char == '<' || char == '>' || char == '&' || char < 0x20 {
			return false
		}
		if char >= utf8.RuneSelf {
			runeValue, size := utf8.DecodeRune(token[index:])
			if runeValue == utf8.RuneError && size == 1 {
				return false
			}
			if runeValue == '\u2028' || runeValue == '\u2029' {
				return false
			}
			index += size - 1
		}
	}
	return true
}

func skipJSONValue(data []byte, start int) int {
	position := skipJSONSpace(data, start)
	if position >= len(data) {
		return -1
	}
	frames := make([]skipJSONFrame, 0, 8)
	needValue := true
	for {
		position = skipJSONSpace(data, position)
		if needValue {
			if position >= len(data) {
				return -1
			}
			switch data[position] {
			case '"':
				end, ok := scanJSONStringToken(data, position)
				if !ok {
					return -1
				}
				position = end
				needValue = false
				if !completeSkippedValue(frames) {
					return -1
				}
			case '{':
				frames = append(frames, skipJSONFrame{close: '}', state: skipObjectKeyOrEnd})
				position++
				needValue = false
			case '[':
				frames = append(frames, skipJSONFrame{close: ']', state: skipArrayValueOrEnd})
				position++
				needValue = false
			default:
				end := scanJSONPrimitive(data, position)
				if end <= position || !validSkippedPrimitive(data[position:end]) {
					return -1
				}
				position = end
				needValue = false
				if !completeSkippedValue(frames) {
					return -1
				}
			}
		}

		if len(frames) == 0 {
			return position
		}
		frame := &frames[len(frames)-1]
		position = skipJSONSpace(data, position)
		if position >= len(data) {
			return -1
		}
		switch frame.state {
		case skipObjectKeyOrEnd:
			if data[position] == frame.close {
				position++
				frames = frames[:len(frames)-1]
				if len(frames) == 0 {
					return position
				}
				if !completeSkippedValue(frames) {
					return -1
				}
				continue
			}
			if data[position] != '"' {
				return -1
			}
			keyEnd, ok := scanJSONStringToken(data, position)
			if !ok {
				return -1
			}
			position = skipJSONSpace(data, keyEnd)
			if position >= len(data) || data[position] != ':' {
				return -1
			}
			frame.state = skipObjectValue
			position++
			needValue = true
		case skipObjectKey:
			if data[position] != '"' {
				return -1
			}
			keyEnd, ok := scanJSONStringToken(data, position)
			if !ok {
				return -1
			}
			position = skipJSONSpace(data, keyEnd)
			if position >= len(data) || data[position] != ':' {
				return -1
			}
			frame.state = skipObjectValue
			position++
			needValue = true
		case skipObjectValue:
			needValue = true
		case skipObjectCommaOrEnd:
			switch data[position] {
			case ',':
				frame.state = skipObjectKey
				position++
			case '}':
				position++
				frames = frames[:len(frames)-1]
				if len(frames) == 0 {
					return position
				}
				if !completeSkippedValue(frames) {
					return -1
				}
			default:
				return -1
			}
		case skipArrayValueOrEnd:
			if data[position] == frame.close {
				position++
				frames = frames[:len(frames)-1]
				if len(frames) == 0 {
					return position
				}
				if !completeSkippedValue(frames) {
					return -1
				}
				continue
			}
			needValue = true
		case skipArrayValue:
			if data[position] == ']' {
				return -1
			}
			needValue = true
		case skipArrayCommaOrEnd:
			switch data[position] {
			case ',':
				frame.state = skipArrayValue
				position++
			case ']':
				position++
				frames = frames[:len(frames)-1]
				if len(frames) == 0 {
					return position
				}
				if !completeSkippedValue(frames) {
					return -1
				}
			default:
				return -1
			}
		}
	}
}

func completeSkippedValue(frames []skipJSONFrame) bool {
	if len(frames) == 0 {
		return true
	}
	frame := &frames[len(frames)-1]
	switch frame.state {
	case skipObjectValue:
		frame.state = skipObjectCommaOrEnd
	case skipArrayValueOrEnd, skipArrayValue:
		frame.state = skipArrayCommaOrEnd
	default:
		return false
	}
	return true
}

func scanJSONStringToken(data []byte, start int) (int, bool) {
	if start < 0 || start >= len(data) || data[start] != '"' {
		return 0, false
	}
	end := scanJSONString(data, start)
	if end <= start || end > len(data) || data[end-1] != '"' {
		return 0, false
	}
	for index := start + 1; index < end-1; index++ {
		if data[index] < 0x20 {
			return 0, false
		}
		if data[index] == '\\' {
			var decoded string
			if err := json.Unmarshal(data[start:end], &decoded); err != nil {
				return 0, false
			}
			break
		}
	}
	return end, true
}

func validSkippedPrimitive(token []byte) bool {
	if len(token) == 0 {
		return false
	}
	kind := streamJSONKind(token[0])
	switch kind {
	case KindBool, KindNil, KindNumber:
		return validStreamPrimitive(token, kind)
	default:
		return false
	}
}

func (w *streamJSONWalker) fail(code ErrorCode, field Field, depth int) {
	if field.Path == "" {
		field.Path = w.currentPath()
	}
	if code == CodeDepthLimit || code == CodeNodeLimit {
		if w.stop {
			return
		}
		w.stop = true
		addPriorityFieldError(&w.errs, code, field, depth)
		return
	}
	addUniqueFieldError(&w.errs, code, field, depth)
}

func addUniqueRuleError(errs *[]*MaskError, code ErrorCode, field Field, rule Rule) {
	addUnique(errs, ruleFieldError(code, field, rule))
}

func addUniqueFieldError(errs *[]*MaskError, code ErrorCode, field Field, depth int) {
	addUnique(errs, newFieldError(code, field, depth))
}

func addUnique(errs *[]*MaskError, err *MaskError) {
	for _, existing := range *errs {
		if existing != nil && *existing == *err {
			return
		}
	}
	addMaskError(errs, err)
}

// streamObjectKey decodes one object key. It relies on the caller having
// checked that data[start] is a quote, and on scanJSONString returning
// len(data) for an unterminated string: the caller's colon check then rejects
// the document, so a token reaching here is always properly delimited.
func (w *streamJSONWalker) streamObjectKey(data []byte, start, end int) (string, bool) {
	if end-start < 2 {
		return "", false
	}
	keyStart := start + 1
	keyEnd := end - 1
	escaped := false
	for index := start + 1; index < end-1; index++ {
		if data[index] < 0x20 {
			return "", false
		}
		if data[index] == '\\' {
			escaped = true
		}
	}

	bucket := streamJSONKeyBucket(data[keyStart:keyEnd])
	for _, cached := range w.keys[bucket] {
		if cached.end-cached.start == keyEnd-keyStart &&
			bytes.Equal(data[cached.start:cached.end], data[keyStart:keyEnd]) {
			return cached.key, true
		}
	}

	var key string
	if escaped {
		if err := json.Unmarshal(data[start:end], &key); err != nil {
			return "", false
		}
	} else {
		key = string(data[keyStart:keyEnd])
	}
	if w.keyCacheEntries >= streamJSONKeyCacheMaxEntries ||
		len(w.keys[bucket]) >= streamJSONKeyCacheMaxChain {
		return key, true
	}
	if w.keys == nil {
		w.keys = make(map[uint64][]streamJSONKey, 16)
	}
	w.keys[bucket] = append(w.keys[bucket], streamJSONKey{key: key, start: keyStart, end: keyEnd})
	w.keyCacheEntries++
	return key, true
}

func streamJSONKeyBucket(key []byte) uint64 {
	const (
		fnvOffset64 = uint64(14695981039346656037)
		fnvPrime64  = uint64(1099511628211)
	)
	hash := fnvOffset64
	for _, value := range key {
		hash ^= uint64(value)
		hash *= fnvPrime64
	}
	return hash
}

func sortStreamMembers(members []streamJSONMember) {
	slices.SortFunc(members, func(left, right streamJSONMember) int {
		return strings.Compare(left.key, right.key)
	})
}

func (w *streamJSONWalker) currentPath() string {
	path := "$"
	for _, part := range w.path {
		if part.isIndex {
			path = pathForIndex(path, part.index)
			continue
		}
		path = pathFor(path, part.key)
	}
	return path
}
