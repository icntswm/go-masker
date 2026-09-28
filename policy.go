package masker

import (
	"fmt"
	"reflect"
	"strings"
	"unicode/utf8"
)

// Source identifies the input representation in a policy decision.
type Source uint8

const (
	// SourceUnknown identifies an unspecified input source.
	SourceUnknown Source = iota
	// SourceAny identifies reflection-based arbitrary input.
	SourceAny
	// SourceMap identifies map-like input.
	SourceMap
	// SourceStruct identifies struct input.
	SourceStruct
	// SourceJSON identifies JSON input.
	SourceJSON
	// SourceHeader identifies an HTTP header.
	SourceHeader
	// SourceURLQuery identifies a URL query parameter.
	SourceURLQuery
	// SourceURLUserInfo identifies URL userinfo.
	SourceURLUserInfo
	// SourceURLFragment identifies a URL fragment.
	SourceURLFragment
)

// ValueKind is the normalized kind visible to policies and rules.
type ValueKind uint8

const (
	// KindInvalid identifies an unknown value kind.
	KindInvalid ValueKind = iota
	// KindNil identifies a nil value.
	KindNil
	// KindString identifies a string value.
	KindString
	// KindBool identifies a boolean value.
	KindBool
	// KindNumber identifies a numeric value.
	KindNumber
	// KindObject identifies an object or map value.
	KindObject
	// KindArray identifies an array or slice value.
	KindArray
)

// Field is the diagnostic context passed to a Policy.
type Field struct {
	Key    string
	Path   string
	Source Source
	Kind   ValueKind
}

// Decision is a policy decision. A zero Decision means no opinion.
type Decision struct {
	Rule Rule
	Omit bool
}

// Policy decides how a field should be handled.
type Policy interface {
	Decide(Field) (Decision, error)
}

// PolicyFunc adapts a function to Policy.
type PolicyFunc func(Field) (Decision, error)

// Decide implements Policy.
func (f PolicyFunc) Decide(field Field) (Decision, error) {
	if f == nil {
		return Decision{}, fmt.Errorf("%w: nil policy", errorSentinels[CodePolicyFailure])
	}
	return f(field)
}

// Binding associates field keys with a rule. Keys compare equal when they
// differ only by Unicode case or by the separator characters "_", "-", and
// ".", so access_token, access-token, and accessToken are equivalent.
type Binding struct {
	Keys []string
	Rule Rule
}

// KeyPolicy matches complete keys across all naming conventions: keys compare
// equal when they differ only by Unicode case or by the separator characters
// "_", "-", and ".".
type KeyPolicy struct {
	// ordered holds every key with its separators already stripped, in
	// declaration order, for the Unicode fallback scan.
	ordered   []keyEntry
	entries   map[string][]keyEntry
	asciiOnly bool
}

type keyEntry struct {
	key  string
	rule Rule
}

func isASCII(value string) bool {
	for index := range len(value) {
		if value[index] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// stripKeySeparators removes the separators that naming conventions disagree
// on, so access_token, access-token and accessToken compare equal.
func stripKeySeparators(key string) string {
	if !strings.ContainsAny(key, "_-.") {
		return key
	}
	stripped := make([]byte, 0, len(key))
	for index := range len(key) {
		switch key[index] {
		case '_', '-', '.':
		default:
			stripped = append(stripped, key[index])
		}
	}
	return string(stripped)
}

// asciiKeyBufferSize bounds the stack buffer Decide normalizes ASCII keys
// into; longer keys take the allocating path.
const asciiKeyBufferSize = 64

// appendNormalizedASCIIKey lowercases an ASCII key and drops its separators
// in one pass, producing the same form as ToLower(stripKeySeparators(key)).
func appendNormalizedASCIIKey(dst []byte, key string) []byte {
	for index := range len(key) {
		char := key[index]
		switch {
		case char == '_' || char == '-' || char == '.':
		case 'A' <= char && char <= 'Z':
			dst = append(dst, char+('a'-'A'))
		default:
			dst = append(dst, char)
		}
	}
	return dst
}

// NewKeyPolicy validates and compiles key bindings. Keys compare equal when
// they differ only by Unicode case or by the separator characters "_", "-",
// and "."; a key that becomes empty once those separators are removed is
// rejected as an empty key. Duplicate detection is a one-time cost paid here
// so conflicting fold-equivalent keys never reach the per-decision hot path.
// Such keys are accepted only when they refer to the same comparable Rule
// instance; RuleFunc values are not comparable, so repeated fold-equivalent
// keys using a custom callback are rejected even when the callback function
// is the same.
func NewKeyPolicy(bindings ...Binding) (*KeyPolicy, error) {
	type acceptedKey struct {
		text string
		rule Rule
	}
	var accepted []acceptedKey
	asciiOnly := true
	copyBindings := make([]Binding, 0, len(bindings))
	for _, binding := range bindings {
		if isNilRule(binding.Rule) {
			return nil, fmt.Errorf("%w: nil rule", errorSentinels[CodeInvalidConfig])
		}
		keys := append([]string(nil), binding.Keys...)
		for _, key := range keys {
			stripped := stripKeySeparators(key)
			if stripped == "" {
				return nil, fmt.Errorf("%w: empty key", errorSentinels[CodeInvalidConfig])
			}
			if !isASCII(key) {
				asciiOnly = false
			}
			for _, previous := range accepted {
				if strings.EqualFold(previous.text, stripped) && !sameRule(previous.rule, binding.Rule) {
					return nil, fmt.Errorf("%w: duplicate key", errorSentinels[CodeInvalidConfig])
				}
			}
			accepted = append(accepted, acceptedKey{text: stripped, rule: binding.Rule})
		}
		copyBindings = append(copyBindings, Binding{Keys: keys, Rule: binding.Rule})
	}
	entries := make(map[string][]keyEntry)
	ordered := make([]keyEntry, 0, len(accepted))
	for _, binding := range copyBindings {
		for _, key := range binding.Keys {
			entry := keyEntry{key: stripKeySeparators(key), rule: binding.Rule}
			lowered := strings.ToLower(entry.key)
			entries[lowered] = append(entries[lowered], entry)
			ordered = append(ordered, entry)
		}
	}
	return &KeyPolicy{ordered: ordered, entries: entries, asciiOnly: asciiOnly}, nil
}

// Decide implements Policy.
func (p *KeyPolicy) Decide(field Field) (Decision, error) {
	if p == nil {
		return Decision{}, fmt.Errorf("%w: nil key policy", errorSentinels[CodePolicyFailure])
	}
	if p.asciiOnly && isASCII(field.Key) && len(field.Key) <= asciiKeyBufferSize {
		var buffer [asciiKeyBufferSize]byte
		// The string conversion in a map index does not allocate.
		entries := p.entries[string(appendNormalizedASCIIKey(buffer[:0], field.Key))]
		if len(entries) == 0 {
			return Decision{}, nil
		}
		return Decision{Rule: entries[0].rule}, nil
	}
	stripped := stripKeySeparators(field.Key)
	if stripped == "" {
		return Decision{}, nil
	}
	entries := p.entries[strings.ToLower(stripped)]
	if p.asciiOnly && isASCII(field.Key) {
		if len(entries) == 0 {
			return Decision{}, nil
		}
		return Decision{Rule: entries[0].rule}, nil
	}
	for _, entry := range entries {
		if strings.EqualFold(entry.key, stripped) {
			return Decision{Rule: entry.rule}, nil
		}
	}
	// The lowercase bucket is the fast path. This scan preserves stdlib
	// EqualFold parity for rare cross-script pairs such as k versus KELVIN.
	for _, entry := range p.ordered {
		if strings.EqualFold(entry.key, stripped) {
			return Decision{Rule: entry.rule}, nil
		}
	}
	return Decision{}, nil
}

var defaultBindings = []Binding{
	{Keys: []string{"password", "passwd", "passphrase"}, Rule: PasswordRule()},
	{Keys: []string{"token", "access_token", "refresh_token", "api_key", "apikey", "secret", "client_secret", "id_token", "private_key", "session_id", "credentials", "auth_token"}, Rule: TokenRule()},
	{Keys: []string{"email", "e-mail"}, Rule: EmailRule()},
	{Keys: []string{"phone", "phone_number", "mobile"}, Rule: PhoneRule()},
	{Keys: []string{"id", "user_id", "customer_id"}, Rule: IDRule()},
	{Keys: []string{"card", "card_number", "pan"}, Rule: CardRule()},
	{Keys: []string{"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "proxy-authorization", "x-csrf-token", "cvv", "cvc"}, Rule: FullRule()},
}

// DefaultBindings returns a defensive copy of the built-in key policy.
func DefaultBindings() []Binding {
	result := make([]Binding, len(defaultBindings))
	for i, binding := range defaultBindings {
		result[i] = Binding{Keys: append([]string(nil), binding.Keys...), Rule: binding.Rule}
	}
	return result
}

// DefaultPolicy returns the standard sensitive-key policy.
func DefaultPolicy() Policy {
	policy, _ := NewKeyPolicy(DefaultBindings()...)
	return policy
}

type chainPolicy struct{ policies []Policy }

// Chain evaluates policies in order until one gives an opinion.
func Chain(policies ...Policy) Policy {
	copyPolicies := append([]Policy(nil), policies...)
	return &chainPolicy{policies: copyPolicies}
}

func isEmptyPolicyChain(policy Policy) bool {
	chain, ok := policy.(*chainPolicy)
	if !ok || chain == nil {
		return false
	}
	for _, chained := range chain.policies {
		if !isEmptyPolicyChain(chained) {
			return false
		}
	}
	return true
}

func hasNilPolicyChain(policy Policy) bool {
	chain, ok := policy.(*chainPolicy)
	if !ok || chain == nil {
		return false
	}
	for _, chained := range chain.policies {
		if isNilPolicy(chained) || hasNilPolicyChain(chained) {
			return true
		}
	}
	return false
}

func (p *chainPolicy) Decide(field Field) (Decision, error) {
	if p == nil {
		return Decision{}, fmt.Errorf("%w: nil chain", errorSentinels[CodePolicyFailure])
	}
	for _, policy := range p.policies {
		if isNilPolicy(policy) {
			return Decision{}, fmt.Errorf("%w: nil chained policy", errorSentinels[CodePolicyFailure])
		}
		decision, err := callPolicy(policy, field)
		if err != nil {
			return Decision{}, err
		}
		if decision.Omit || !isNilRule(decision.Rule) {
			return decision, nil
		}
	}
	return Decision{}, nil
}

func callPolicy(policy Policy, field Field) (decision Decision, err error) {
	defer func() {
		if recover() != nil {
			decision = Decision{}
			err = fmt.Errorf("%w: policy panic", errorSentinels[CodePanic])
		}
	}()
	return policy.Decide(field)
}

func isNilPolicy(policy Policy) bool {
	if policy == nil {
		return true
	}
	value := reflect.ValueOf(policy)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func sameRule(left, right Rule) bool {
	if isNilRule(left) || isNilRule(right) {
		return isNilRule(left) && isNilRule(right)
	}
	leftValue := reflect.ValueOf(left)
	rightValue := reflect.ValueOf(right)
	if leftValue.Type() != rightValue.Type() {
		return false
	}
	// Value.Comparable looks at the dynamic values too: a comparable struct
	// holding a func in an interface field would make == panic.
	if !leftValue.Comparable() || !rightValue.Comparable() {
		return false
	}
	return leftValue.Equal(rightValue)
}

func policyNeedsPaths(policy Policy) bool {
	switch chain := policy.(type) {
	case *chainPolicy:
		for _, chained := range chain.policies {
			if policyNeedsPaths(chained) {
				return true
			}
		}
		return false
	case *KeyPolicy:
		return false
	default:
		return true
	}
}
