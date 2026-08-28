package masker

import (
	"fmt"
	"strconv"
)

const (
	// DefaultRedactionMarker is used for sensitive and fail-closed values.
	DefaultRedactionMarker = "[REDACTED]"
	// DefaultStructTag is the default struct tag name.
	DefaultStructTag = "mask"
)

// Option configures a Masker during construction. The option type is
// intentionally closed; callers use the exported With* constructors.
type Option func(*config) error

// Masker masks sensitive values according to an immutable policy.
type Masker struct {
	policy         Policy
	cfg            config
	structMetadata *structMetadataCache
}

// New validates configuration and returns a concurrency-safe Masker.
func New(policy Policy, opts ...Option) (*Masker, error) {
	if isNilPolicy(policy) {
		return nil, fmt.Errorf("%w: nil policy", errorSentinels[CodeInvalidConfig])
	}
	if isEmptyPolicyChain(policy) {
		return nil, fmt.Errorf("%w: empty policy chain", errorSentinels[CodeInvalidConfig])
	}
	if hasNilPolicyChain(policy) {
		return nil, fmt.Errorf("%w: nil policy in chain", errorSentinels[CodeInvalidConfig])
	}
	cfg := defaultConfig()
	for _, option := range opts {
		if option == nil {
			return nil, fmt.Errorf("%w: nil option", errorSentinels[CodeInvalidConfig])
		}
		if err := option(&cfg); err != nil {
			return nil, err
		}
	}
	cfg.needPaths = policyNeedsPaths(policy)
	return &Masker{policy: policy, cfg: cfg, structMetadata: &structMetadataCache{}}, nil
}

// MaskString applies a rule to one string and fails closed on rule errors.
func (m *Masker) MaskString(value string, rule Rule) (result string, err error) {
	if m == nil {
		return DefaultRedactionMarker, fmt.Errorf("%w: nil masker", errorSentinels[CodeInvalidConfig])
	}
	defer m.recoverString(&result, &err)
	result, err = applyRule(rule, RuleInput{Value: value, Kind: KindString, Redaction: m.cfg.marker})
	if err != nil {
		code := CodeRuleFailure
		if isPanicError(err) {
			code = CodePanic
		}
		failure := maskError(code, "mask_string", "$")
		failure.Rule = safeDiagnostic(ruleName(rule))
		return m.cfg.marker, failure
	}
	return result, nil
}

// MaskValue masks a value under a map-like key.
func (m *Masker) MaskValue(key string, value any) (any, error) {
	return m.MaskField(Field{Key: key, Path: "$[" + key + "]", Source: SourceMap}, value)
}

// MaskField masks a value using an explicit field context.
func (m *Masker) MaskField(field Field, value any) (result any, err error) {
	if m == nil {
		return DefaultRedactionMarker, fmt.Errorf("%w: nil masker", errorSentinels[CodeInvalidConfig])
	}
	defer m.recoverValue(&result, &err)
	if field.Path == "" {
		field.Path = "$[" + field.Key + "]"
	}
	if scalar, handled, scalarErr := m.maskScalarField(field, value); handled {
		if scalarErr != nil {
			return m.cfg.marker, scalarErr
		}
		if isOmitted(scalar) {
			return nil, nil
		}
		return scalar, nil
	}
	result, err = m.maskRoot(value, field.Source, field)
	if err != nil {
		return m.cfg.marker, err
	}
	return result, nil
}

// MaskAny masks an arbitrary supported value.
func (m *Masker) MaskAny(value any) (result any, err error) {
	if m == nil {
		return DefaultRedactionMarker, fmt.Errorf("%w: nil masker", errorSentinels[CodeInvalidConfig])
	}
	defer m.recoverValue(&result, &err)
	result, err = m.maskRoot(value, SourceAny, Field{Path: "$", Source: SourceAny})
	if err != nil {
		return m.cfg.marker, err
	}
	return result, nil
}

func (m *Masker) recoverString(result *string, err *error) {
	if recovered := recover(); recovered != nil {
		*result = m.cfg.marker
		*err = maskError(CodePanic, "mask_string", "$")
	}
}

func (m *Masker) recoverValue(result *any, err *error) {
	if recovered := recover(); recovered != nil {
		*result = m.cfg.marker
		*err = maskError(CodePanic, "mask", "$")
	}
}

func pathFor(parent, key string) string {
	if parent == "" {
		parent = "$"
	}
	return parent + "[" + key + "]"
}

func pathForIndex(parent string, index int) string {
	return parent + "[" + strconv.Itoa(index) + "]"
}
