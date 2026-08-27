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

// Binding associates case-insensitive field keys with rules.
type Binding struct {
	Keys []string
	Rule Rule
}

// KeyPolicy matches complete keys using Unicode-aware EqualFold.
type KeyPolicy struct {
	bindings  []Binding
	entries   map[string][]keyEntry
	asciiOnly bool
}

type keyEntry struct {
	key  string
	rule Rule
}

func isASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// NewKeyPolicy validates and compiles key bindings. Duplicate detection is
// a one-time cost paid here so conflicting fold-equivalent keys never reach
// the per-decision hot path. Such keys are accepted only when they refer to
// the same comparable Rule instance; RuleFunc values are not comparable, so
// repeated fold-equivalent keys using a custom callback are rejected even when
// the callback function is the same.
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
			if key == "" {
				return nil, fmt.Errorf("%w: empty key", errorSentinels[CodeInvalidConfig])
			}
			if !isASCII(key) {
				asciiOnly = false
			}
			for _, previous := range accepted {
				if strings.EqualFold(previous.text, key) && !sameRule(previous.rule, binding.Rule) {
					return nil, fmt.Errorf("%w: duplicate key", errorSentinels[CodeInvalidConfig])
				}
			}
			accepted = append(accepted, acceptedKey{text: key, rule: binding.Rule})
		}
		copyBindings = append(copyBindings, Binding{Keys: keys, Rule: binding.Rule})
	}
	entries := make(map[string][]keyEntry)
	for _, binding := range copyBindings {
		for _, key := range binding.Keys {
			lowered := strings.ToLower(key)
			entries[lowered] = append(entries[lowered], keyEntry{key: key, rule: binding.Rule})
		}
	}
	return &KeyPolicy{bindings: copyBindings, entries: entries, asciiOnly: asciiOnly}, nil
}

// Decide implements Policy.
func (p *KeyPolicy) Decide(field Field) (Decision, error) {
	if p == nil {
		return Decision{}, fmt.Errorf("%w: nil key policy", errorSentinels[CodePolicyFailure])
	}
	if field.Key == "" {
		return Decision{}, nil
	}
	entries := p.entries[strings.ToLower(field.Key)]
	if p.asciiOnly && isASCII(field.Key) {
		if len(entries) == 0 {
			return Decision{}, nil
		}
		return Decision{Rule: entries[0].rule}, nil
	}
	for _, entry := range entries {
		if strings.EqualFold(entry.key, field.Key) {
			return Decision{Rule: entry.rule}, nil
		}
	}
	// The lowercase bucket is the fast path. This scan preserves stdlib
	// EqualFold parity for rare cross-script pairs such as k versus KELVIN.
	for _, binding := range p.bindings {
		for _, key := range binding.Keys {
			if strings.EqualFold(key, field.Key) {
				return Decision{Rule: binding.Rule}, nil
			}
		}
	}
	return Decision{}, nil
}

var defaultBindings = []Binding{
	{Keys: []string{"password", "passwd", "passphrase"}, Rule: PasswordRule()},
	{Keys: []string{"token", "access_token", "refresh_token", "api_key", "apikey", "secret"}, Rule: TokenRule()},
	{Keys: []string{"email", "e-mail"}, Rule: EmailRule()},
	{Keys: []string{"phone", "phone_number", "mobile"}, Rule: PhoneRule()},
	{Keys: []string{"id", "user_id", "customer_id"}, Rule: IDRule()},
	{Keys: []string{"card", "card_number", "pan"}, Rule: CardRule()},
	{Keys: []string{"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "proxy-authorization"}, Rule: FullRule()},
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
	if leftValue.Type().Comparable() {
		return leftValue.Interface() == rightValue.Interface()
	}
	return false
}

func policyNeedsPaths(policy Policy) bool {
	switch typed := policy.(type) {
	case *KeyPolicy:
		return false
	case *chainPolicy:
		for _, chained := range typed.policies {
			if policyNeedsPaths(chained) {
				return true
			}
		}
		return false
	default:
		return true
	}
}
