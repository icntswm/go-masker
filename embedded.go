package masker

import (
	"bytes"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/icntswm/go-masker/internal/detect"
	"github.com/icntswm/go-masker/internal/urlquery"
)

// jsonNumberType is json.Number, whose values are rendered as text but are
// never documents: a JSON number token carries no '=', "://" or brace,
// so the JSON walkers never inspect one. The reflection walkers exclude it
// for the same reason, keeping a hand-made json.Number of "a=b" out of the
// inspection path.
var jsonNumberType = reflect.TypeFor[json.Number]()

// embeddedCandidate reports, without allocating, whether s might be an
// embedded URL, JSON document, or form. Walkers call it before building a path.
func embeddedCandidate(s string) bool {
	for index := range len(s) {
		switch s[index] {
		case ' ', '\t', '\r', '\n':
		default:
			if s[index] == '{' || s[index] == '[' {
				return true
			}
			return strings.Contains(s, "://") || strings.IndexByte(s, '=') >= 0
		}
	}
	return false
}

// embeddedCandidateBytes mirrors embeddedCandidate over a byte slice, so the
// stream walker can prefilter a raw JSON string token without converting it.
// The two predicates must stay in step.
func embeddedCandidateBytes(s []byte) bool {
	for index := range s {
		switch s[index] {
		case ' ', '\t', '\r', '\n':
		default:
			if s[index] == '{' || s[index] == '[' {
				return true
			}
			return bytes.Contains(s, []byte("://")) || bytes.IndexByte(s, '=') >= 0
		}
	}
	return false
}

// inspectable reports, without allocating, whether inspectString may change
// s: whether it may be an embedded document or holds something a text
// detector finds. Walkers call it before building a path.
func (m *Masker) inspectable(s string) bool {
	return m.cfg.embedded && embeddedCandidate(s) ||
		m.cfg.textDetectors && detect.Candidate(s, m.cfg.detectSet)
}

// inspectableToken is inspectable for a raw JSON string token. Text without
// an escape is scanned as it lies; only escaped tokens, which are rare, pay
// for a decode before the check.
func (m *Masker) inspectableToken(token []byte) bool {
	if !m.cfg.embedded && !m.cfg.textDetectors || len(token) < 2 {
		return false
	}
	if bytes.IndexByte(token, '\\') >= 0 {
		decoded, ok := streamJSONStringText(token)
		return ok && m.inspectable(decoded)
	}
	text := token[1 : len(token)-1]
	return m.cfg.embedded && embeddedCandidateBytes(text) ||
		m.cfg.textDetectors && detect.Candidate(text, m.cfg.detectSet)
}

type inspectState struct {
	nodes *int
	errs  *[]*MaskError
	stop  *bool
}

// inspectableScalar returns the text of a scalar value the walker may
// inspect: only plain strings, never a json.Number, which no JSON walker can
// produce as a document and which the reflection walkers must therefore also
// leave alone.
func (m *Masker) inspectableScalar(value reflect.Value) (string, bool) {
	if value.Kind() != reflect.String || value.Type() == jsonNumberType {
		return "", false
	}
	s := value.String()
	if !m.inspectable(s) {
		return "", false
	}
	return s, true
}

// inspectString masks a document embedded in s or, when s is not one, the
// secrets the text detectors find in it. It returns s itself and false when
// nothing was masked.
func (m *Masker) inspectString(s string, field Field, depth int, state inspectState) (string, bool) {
	// The candidate is parsed before any walker sees its content, so the byte
	// limit that caps MaskJSON input caps it too.
	if int64(len(s)) > m.cfg.maxInputBytes {
		addFieldError(state.errs, CodeInputLimit, field, depth)
		return m.cfg.marker, true
	}
	if m.cfg.embedded {
		if masked, changed, ok := m.inspectURL(s, field, depth, state); ok {
			return masked, changed
		}
		if masked, changed, ok := m.inspectJSON(s, field, depth, state); ok {
			return masked, changed
		}
		if masked, changed, ok := m.inspectForm(s, field, depth, state); ok {
			return masked, changed
		}
	}
	if m.cfg.textDetectors {
		return m.inspectText(s, field, depth, state)
	}
	return s, false
}

// failInspect records a failure the way the walkers record it: limit failures
// stop the operation and keep priority, everything else joins the error list.
func (m *Masker) failInspect(state inspectState, code ErrorCode, field Field, depth int) {
	if code == CodeDepthLimit || code == CodeNodeLimit {
		if *state.stop {
			return
		}
		*state.stop = true
		addPriorityFieldError(state.errs, code, field, depth)
		return
	}
	addFieldError(state.errs, code, field, depth)
}

func (m *Masker) inspectURL(s string, field Field, depth int, state inspectState) (string, bool, bool) {
	if embeddedSchemeEnd(s) < 0 {
		return "", false, false
	}
	// A URL carried as a string is a single token: any space, control byte or
	// DEL means the text is prose that happens to contain "://", not a URL.
	for index := range len(s) {
		if s[index] <= 0x20 || s[index] == 0x7f {
			return "", false, false
		}
	}
	parsed, err := url.Parse(s)
	if err != nil || parsed.Opaque != "" || parsed.Host == "" {
		return "", false, false
	}
	result := *parsed
	changed := false
	if result.User != nil {
		// httpmask replaces the whole userinfo without consulting the policy;
		// the same reasoning applies here: a login and a password are not
		// separately interesting.
		result.User = url.User(m.cfg.marker)
		changed = true
	}
	if result.Fragment != "" {
		result.Fragment = m.cfg.marker
		result.RawFragment = ""
		changed = true
	}
	if result.RawQuery != "" {
		query, queryErr := m.maskQueryValues(result.RawQuery, field, depth, state, &changed)
		if queryErr != nil {
			// The text looked like a URL but its query does not parse, such as
			// one separated by ';'. The string becomes the marker, since a
			// secret may sit in that query, but the document around it is still
			// masked: a URL the policy never asked about must not fail the call.
			return m.cfg.marker, true, true
		}
		result.RawQuery = query
	}
	if !changed {
		return s, false, true
	}
	return result.String(), true, true
}

func (m *Masker) inspectJSON(s string, field Field, depth int, state inspectState) (string, bool, bool) {
	first, last := -1, -1
	for index := range len(s) {
		switch s[index] {
		case ' ', '\t', '\r', '\n':
		default:
			if first < 0 {
				first = index
			}
			last = index
		}
	}
	if first < 0 ||
		(s[first] != '{' || s[last] != '}') && (s[first] != '[' || s[last] != ']') {
		return "", false, false
	}
	data := []byte(s)
	if !validJSONDocument(data) {
		return "", false, false
	}
	// The document is masked by the production JSON walker, restarted under
	// the string's own path, so an embedded body is masked exactly as MaskJSON
	// masks it and shares the outer walker's node and error budget.
	inner := &streamJSONWalker{masker: m, nodes: *state.nodes, rootPath: field.Path}
	rootField := Field{Key: field.Key, Path: field.Path, Source: SourceJSON}
	var out []byte
	_, ok, _ := inner.appendValue(data, 0, rootField, depth+1, &out)
	*state.nodes = inner.nodes
	for _, innerErr := range inner.errs {
		addMaskError(state.errs, innerErr)
	}
	if inner.stop {
		*state.stop = true
	}
	if !ok {
		m.failInspect(state, CodeInvalidJSON, field, depth)
		return m.cfg.marker, true, true
	}
	if len(inner.errs) > 0 {
		return m.cfg.marker, true, true
	}
	if inner.changes == 0 {
		return s, false, true
	}
	return string(out), true, true
}

func (m *Masker) inspectForm(s string, field Field, depth int, state inspectState) (string, bool, bool) {
	if strings.IndexByte(s, '=') < 0 || !strictFormText(s) {
		return "", false, false
	}
	changed := false
	query, err := m.maskQueryValues(s, field, depth, state, &changed)
	if err != nil {
		// strictFormText has already rejected what urlquery cannot parse, so
		// this is unreachable; the marker keeps it fail-closed regardless.
		return m.cfg.marker, true, true
	}
	if !changed {
		return s, false, true
	}
	return query, true, true
}

// maskQueryValues decides every pair of a URL query or form body through the
// policy, treating a pair whose decision is zero as a string that may itself
// carry a document. changed reports whether any pair was masked, omitted or
// failed; an error is recorded in the shared state before it is returned.
func (m *Masker) maskQueryValues(raw string, field Field, depth int, state inspectState, changed *bool) (string, error) {
	return urlquery.Mask(raw, func(key, value string) (string, bool, error) {
		member := Field{Key: key, Path: pathFor(field.Path, key), Source: SourceURLQuery, Kind: KindString}
		masked, decided, keep := m.decideMember(member, value, depth, state)
		if decided {
			if !keep || masked != value {
				*changed = true
			}
			return masked, keep, nil
		}
		if nested, nestedChanged := m.inspectString(value, member, depth+1, state); nestedChanged {
			*changed = true
			return nested, true, nil
		}
		return value, true, nil
	})
}

// decideMember decides one member found inside a string, a query pair or a
// key=value pair of text, as walker.walk decides a node one level deeper.
// decided is false when the policy left the member alone; otherwise masked
// is its new value, or keep is false when the policy omits it. Failures are
// recorded in the shared state and decide the member as the marker.
func (m *Masker) decideMember(member Field, value string, depth int, state inspectState) (masked string, decided, keep bool) {
	if *state.stop {
		return m.cfg.marker, true, true
	}
	// The checks mirror walker.walk: key validity, then depth, then the node
	// count.
	if !utf8.ValidString(member.Key) {
		m.failInspect(state, CodeInvalidUTF8, member, depth+1)
		return m.cfg.marker, true, true
	}
	if depth+1 > m.cfg.maxDepth {
		m.failInspect(state, CodeDepthLimit, member, depth+1)
		return m.cfg.marker, true, true
	}
	*state.nodes++
	if *state.nodes > m.cfg.maxNodes {
		m.failInspect(state, CodeNodeLimit, member, depth+1)
		return m.cfg.marker, true, true
	}
	decision, err := callPolicy(m.policy, member)
	if err != nil {
		code := CodePolicyFailure
		if isPanicError(err) {
			code = CodePanic
		}
		addFieldError(state.errs, code, member, 0)
		return m.cfg.marker, true, true
	}
	if decision.Omit {
		return "", true, false
	}
	if isNilRule(decision.Rule) {
		return value, false, true
	}
	result, applyErr := applyRule(decision.Rule, RuleInput{
		Value:     value,
		Kind:      KindString,
		Redaction: m.cfg.marker,
	})
	if applyErr != nil {
		code := CodeRuleFailure
		if isPanicError(applyErr) {
			code = CodePanic
		}
		addRuleError(state.errs, code, member, decision.Rule)
		return m.cfg.marker, true, true
	}
	return result, true, true
}

// strictFormText reports whether every '&'-separated part of s is a non-empty
// "key=value" member with a non-empty, decodable key and value. The strict
// grammar runs before urlquery.Mask, which skips malformed parts instead of
// rejecting them.
func strictFormText(s string) bool {
	for index := range len(s) {
		char := s[index]
		if char <= 0x20 || char == 0x7f || char == ';' {
			return false
		}
	}
	for remaining := s; remaining != ""; {
		var part string
		part, remaining, _ = strings.Cut(remaining, "&")
		if part == "" {
			return false
		}
		key, value, ok := strings.Cut(part, "=")
		if !ok || key == "" {
			return false
		}
		if _, err := url.QueryUnescape(key); err != nil {
			return false
		}
		if _, err := url.QueryUnescape(value); err != nil {
			return false
		}
	}
	return true
}

// embeddedSchemeEnd returns the index of the ':' of a leading
// "scheme://" prefix, or -1. The scheme grammar is the one RFC 3986 allows;
// url.Parse is consulted afterwards, so nothing this function accepts is
// reinterpreted.
func embeddedSchemeEnd(s string) int {
	if s == "" || !isASCIILetter(s[0]) {
		return -1
	}
	index := 1
	for index < len(s) {
		char := s[index]
		if isASCIILetter(char) || char >= '0' && char <= '9' || char == '+' || char == '-' || char == '.' {
			index++
			continue
		}
		break
	}
	if index+2 < len(s) && s[index] == ':' && s[index+1] == '/' && s[index+2] == '/' {
		return index
	}
	return -1
}

func isASCIILetter(char byte) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z'
}
