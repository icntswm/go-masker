package masker

import (
	"errors"
	"fmt"
	"reflect"
	"unicode/utf8"
)

// RuleInput is the safe context supplied to a Rule.
type RuleInput struct {
	Value     string
	Kind      ValueKind
	Redaction string
}

// Rule transforms one sensitive scalar into a safe string.
type Rule interface {
	Name() string
	Apply(RuleInput) (string, error)
}

// RuleFunc adapts a function to Rule. Its name is "custom".
type RuleFunc func(RuleInput) (string, error)

// Name implements Rule.
func (f RuleFunc) Name() string { return "custom" }

// Apply implements Rule.
func (f RuleFunc) Apply(input RuleInput) (string, error) {
	if f == nil {
		return "", fmt.Errorf("%w: nil rule", errorSentinels[CodeRuleFailure])
	}
	return f(input)
}

type namedRule struct {
	name string
	fn   RuleFunc
}

func (r namedRule) Name() string                          { return r.name }
func (r namedRule) Apply(input RuleInput) (string, error) { return r.fn(input) }

// NewRule validates and creates a named custom rule.
func NewRule(name string, fn RuleFunc) (Rule, error) {
	if name == "" || !utf8.ValidString(name) || fn == nil {
		return nil, fmt.Errorf("%w: rule", errorSentinels[CodeInvalidConfig])
	}
	return namedRule{name: name, fn: fn}, nil
}

func isNilRule(rule Rule) bool {
	if rule == nil {
		return true
	}
	value := reflect.ValueOf(rule)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func applyRule(rule Rule, input RuleInput) (result string, err error) {
	if isNilRule(rule) {
		return "", fmt.Errorf("%w: nil rule", errorSentinels[CodeRuleFailure])
	}
	defer func() {
		if recover() != nil {
			result = ""
			err = fmt.Errorf("%w: rule panic", errorSentinels[CodePanic])
		}
	}()
	result, err = rule.Apply(input)
	if err != nil {
		return "", fmt.Errorf("%w", errorSentinels[CodeRuleFailure])
	}
	if !utf8.ValidString(result) {
		return "", fmt.Errorf("%w: invalid output", errorSentinels[CodeRuleFailure])
	}
	return result, nil
}

func isPanicError(err error) bool { return errors.Is(err, errorSentinels[CodePanic]) }
