package masker

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ErrorCode identifies a safe, non-sensitive masking failure category.
type ErrorCode string

const (
	CodeInvalidConfig   ErrorCode = "invalid_config"      // Invalid configuration.
	CodeInvalidJSON     ErrorCode = "invalid_json"        // Invalid JSON syntax.
	CodeInvalidUTF8     ErrorCode = "invalid_utf8"        // Invalid UTF-8 input.
	CodeInputLimit      ErrorCode = "input_limit"         // Input exceeded its byte limit.
	CodeDepthLimit      ErrorCode = "depth_limit"         // Traversal exceeded its depth limit.
	CodeNodeLimit       ErrorCode = "node_limit"          // Traversal exceeded its node limit.
	CodeCycle           ErrorCode = "cycle"               // An active traversal cycle was found.
	CodeUnsupportedType ErrorCode = "unsupported_type"    // A value type is unsupported.
	CodeUnsupportedKey  ErrorCode = "unsupported_map_key" // A map key type is unsupported.
	CodeFieldConflict   ErrorCode = "field_conflict"      // Visible fields conflict.
	CodePolicyFailure   ErrorCode = "policy_failure"      // A policy failed.
	CodeRuleFailure     ErrorCode = "rule_failure"        // A rule failed.
	CodePanic           ErrorCode = "panic"               // A callback panicked.
)

const maxMaskErrorsPerOperation = 64

var (
	// ErrInvalidConfig reports invalid masker configuration.
	ErrInvalidConfig = errors.New("masker: invalid configuration")
	// ErrInvalidJSON reports invalid JSON syntax.
	ErrInvalidJSON = errors.New("masker: invalid JSON")
	// ErrInvalidUTF8 reports invalid UTF-8 input.
	ErrInvalidUTF8 = errors.New("masker: invalid UTF-8")
	// ErrInputLimit reports input exceeding the configured byte limit.
	ErrInputLimit = errors.New("masker: input limit exceeded")
	// ErrDepthLimit reports traversal exceeding the configured depth limit.
	ErrDepthLimit = errors.New("masker: depth limit exceeded")
	// ErrNodeLimit reports traversal exceeding the configured node limit.
	ErrNodeLimit = errors.New("masker: node limit exceeded")
	// ErrCycle reports an active traversal cycle.
	ErrCycle = errors.New("masker: cycle detected")
	// ErrUnsupportedType reports an unsupported input value type.
	ErrUnsupportedType = errors.New("masker: unsupported type")
	// ErrUnsupportedKey reports an unsupported map key type.
	ErrUnsupportedKey = errors.New("masker: unsupported map key")
	// ErrFieldConflict reports conflicting visible fields.
	ErrFieldConflict = errors.New("masker: field conflict")
	// ErrPolicyFailure reports a policy failure.
	ErrPolicyFailure = errors.New("masker: policy failure")
	// ErrRuleFailure reports a rule failure.
	ErrRuleFailure = errors.New("masker: rule failure")
	// ErrPanic reports a panic from a policy or rule callback.
	ErrPanic = errors.New("masker: callback panic")
)

var errorSentinels = map[ErrorCode]error{
	CodeInvalidConfig:   ErrInvalidConfig,
	CodeInvalidJSON:     ErrInvalidJSON,
	CodeInvalidUTF8:     ErrInvalidUTF8,
	CodeInputLimit:      ErrInputLimit,
	CodeDepthLimit:      ErrDepthLimit,
	CodeNodeLimit:       ErrNodeLimit,
	CodeCycle:           ErrCycle,
	CodeUnsupportedType: ErrUnsupportedType,
	CodeUnsupportedKey:  ErrUnsupportedKey,
	CodeFieldConflict:   ErrFieldConflict,
	CodePolicyFailure:   ErrPolicyFailure,
	CodeRuleFailure:     ErrRuleFailure,
	CodePanic:           ErrPanic,
}

// MaskError describes one masking failure without exposing source values.
type MaskError struct {
	Code             ErrorCode
	Operation        string
	Path             string
	Field            string
	ConflictingField string
	Depth            int
	Rule             string
}

// Error returns a safe diagnostic that contains no input data.
func (e *MaskError) Error() string {
	if e == nil {
		return "masker: unknown error"
	}
	parts := []string{"masker", string(e.Code)}
	if e.Operation != "" {
		parts = append(parts, "operation="+e.Operation)
	}
	if e.Path != "" {
		parts = append(parts, "path="+e.Path)
	}
	if e.Field != "" {
		parts = append(parts, "field="+e.Field)
	}
	if e.ConflictingField != "" {
		parts = append(parts, "conflicting_field="+e.ConflictingField)
	}
	if e.Depth != 0 {
		parts = append(parts, fmt.Sprintf("depth=%d", e.Depth))
	}
	if e.Rule != "" {
		parts = append(parts, "rule="+e.Rule)
	}
	return strings.Join(parts, ": ")
}

// Unwrap makes errors.Is work for the corresponding safe category.
func (e *MaskError) Unwrap() error {
	if e == nil {
		return nil
	}
	return errorSentinels[e.Code]
}

// MaskErrors aggregates local failures without retaining unsafe callback errors.
type MaskErrors struct {
	Items []*MaskError
}

// Error returns a safe summary of the aggregate.
func (e *MaskErrors) Error() string {
	if e == nil || len(e.Items) == 0 {
		return "masker: no errors"
	}
	if len(e.Items) == 1 {
		return e.Items[0].Error()
	}
	return e.Items[0].Error() + " (and more errors)"
}

// Unwrap exposes aggregate members to errors.Is and errors.As.
func (e *MaskErrors) Unwrap() []error {
	if e == nil {
		return nil
	}
	result := make([]error, 0, len(e.Items))
	for _, item := range e.Items {
		if item != nil {
			result = append(result, item)
		}
	}
	return result
}

// maxDiagnosticLen bounds how much of a caller-supplied key or path a
// diagnostic may carry. The bound is on the original text: escaping produces at
// most four output bytes per input byte, the ratio of \x00 and of an invalid
// byte, so an escaped diagnostic is longer than this and still bounded. Per
// rune the escape reaches ten bytes, for an unprintable rune above the BMP.
const maxDiagnosticLen = 256

// safeDiagnostic makes a key or path safe to write into a log line. Keys come
// from the masked document, so they are attacker-controlled: a newline in one
// would otherwise split the record and let a forged entry be injected, a bidi
// override or a U+2028 line separator can make a record render as something it
// is not, a bare quote or backslash ends a value early, and a space starts a
// new logfmt field. Anything of that kind is escaped, printable text is left
// readable, and the result is truncated so one oversized key cannot dominate
// the output.
//
// The base test is "would quoting change this?", which cannot drift away from
// the quoting itself the way a hand-written list of control ranges does. It
// takes three named characters to express, because strconv.IsPrint and
// strconv.Quote do not agree: Quote escapes the quote and the backslash even
// though IsPrint calls them printable, so both are named to keep the test in
// step with the quoting. The space is the one character named for a reason
// Quote knows nothing about: Quote leaves it, and a key of "x=1 forged=true"
// would otherwise appear in the log as a field the attacker chose.
//
// This bounds what a key can do to a record; it does not make the message a
// logfmt value. The message carries spaces of its own, so a caller that splices
// it into a record raw still produces junk tokens - it should be logged as one
// field.
func safeDiagnostic(value string) string {
	if value == "" {
		return ""
	}
	// Truncate before escaping, never after: cutting quoted text can slice an
	// escape sequence in half or drop the closing quote, which is the kind of
	// malformed value the escaping exists to prevent. Cut on a rune boundary
	// so the remainder stays valid UTF-8.
	truncated := len(value) > maxDiagnosticLen
	if truncated {
		cut := maxDiagnosticLen
		for cut > 0 && !utf8.RuneStart(value[cut]) {
			cut--
		}
		value = value[:cut]
	}
	if needsQuoting(value) {
		value = strconv.Quote(value)
	}
	if truncated {
		value += "...(truncated)"
	}
	return value
}

// needsQuoting reports whether strconv.Quote would rewrite the value.
func needsQuoting(value string) bool {
	if !utf8.ValidString(value) {
		return true
	}
	for _, r := range value {
		// A space is the only whitespace strconv.IsPrint admits; every other
		// space rune is already unprintable to it.
		if !strconv.IsPrint(r) || r == '"' || r == '\\' || r == ' ' {
			return true
		}
	}
	return false
}

func maskError(code ErrorCode, operation, path string) *MaskError {
	return &MaskError{Code: code, Operation: operation, Path: safeDiagnostic(path)}
}

func addMaskError(errs *[]*MaskError, err *MaskError) {
	if err != nil && len(*errs) < maxMaskErrorsPerOperation {
		*errs = append(*errs, err)
	}
}

func aggregateErrors(errs []*MaskError) error {
	if len(errs) == 0 {
		return nil
	}
	return &MaskErrors{Items: errs}
}
