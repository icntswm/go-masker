package masker

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

type builtinRule struct {
	name string
	fn   func(RuleInput) string
}

func (r *builtinRule) Name() string { return r.name }
func (r *builtinRule) Apply(input RuleInput) (string, error) {
	return r.fn(input), nil
}

var (
	passwordRule = &builtinRule{name: "password", fn: fullMask}
	tokenRule    = &builtinRule{name: "token", fn: fullMask}
	fullRule     = &builtinRule{name: "full", fn: fullMask}
	emailRule    = &builtinRule{name: "email", fn: maskEmail}
	phoneRule    = &builtinRule{name: "phone", fn: maskLastFourDigits}
	idRule       = &builtinRule{name: "id", fn: maskLastFourUnits}
	cardRule     = &builtinRule{name: "card", fn: maskLastFourDigits}
)

// PasswordRule fully redacts passwords.
func PasswordRule() Rule { return passwordRule }

// TokenRule fully redacts tokens and secrets.
func TokenRule() Rule { return tokenRule }

// FullRule fully redacts a value.
func FullRule() Rule { return fullRule }

// EmailRule preserves a limited, safe email shape.
func EmailRule() Rule { return emailRule }

// PhoneRule masks all but the last four digits.
func PhoneRule() Rule { return phoneRule }

// IDRule masks all but the last four units.
func IDRule() Rule { return idRule }

// CardRule masks all but the last four ASCII digits.
func CardRule() Rule { return cardRule }

func fullMask(input RuleInput) string { return input.Redaction }

// builtinTagRules compiles the fixed struct-tag grammar for one Masker.
func builtinTagRules() map[string]Rule {
	return map[string]Rule{
		"full":     FullRule(),
		"email":    EmailRule(),
		"phone":    PhoneRule(),
		"id":       IDRule(),
		"card":     CardRule(),
		"password": PasswordRule(),
		"token":    TokenRule(),
	}
}

// controlRune reports a rune that changes how a log line or terminal renders
// rather than a character of the value: a control or format character, such
// as an escape sequence or a bidirectional override, or a line or paragraph
// separator. A partial rule keeps part of its input verbatim, so an input that
// holds one is malformed and is redacted in full instead.
func controlRune(r rune) bool {
	if r < utf8.RuneSelf {
		// No ASCII character is a format or separator character, and the
		// range tables below are costly enough to dominate a short value.
		return r < 0x20 || r == 0x7f
	}
	return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
}

// malformedEmail reports invalid UTF-8, a space, or a control rune, each of
// which makes a value that is not an address to keep part of.
func malformedEmail(value string) bool {
	for index := 0; index < len(value); {
		if char := value[index]; char < utf8.RuneSelf {
			// The ASCII spaces and controls are exactly these bytes.
			if char <= ' ' || char == 0x7f {
				return true
			}
			index++
			continue
		}
		r, size := utf8.DecodeRuneInString(value[index:])
		if r == utf8.RuneError && size == 1 || unicode.IsSpace(r) || controlRune(r) {
			return true
		}
		index += size
	}
	return false
}

func maskEmail(input RuleInput) string {
	value := input.Value
	if malformedEmail(value) {
		return input.Redaction
	}
	at := strings.IndexByte(value, '@')
	if at <= 0 || at == len(value)-1 || strings.IndexByte(value[at+1:], '@') >= 0 {
		return input.Redaction
	}
	local := []rune(value[:at])
	if len(local) == 0 {
		return input.Redaction
	}
	return string(local[0]) + "***@" + value[at+1:]
}

func maskLastFourDigits(input RuleInput) string {
	value := []rune(input.Value)
	digits := 0
	for _, r := range value {
		if r >= '0' && r <= '9' {
			digits++
			continue
		}
		if r != ' ' && !strings.ContainsRune("+-()./", r) {
			return input.Redaction
		}
	}
	if digits <= 4 {
		return input.Redaction
	}
	toMask := digits - 4
	for i, r := range value {
		if r >= '0' && r <= '9' && toMask > 0 {
			value[i] = '*'
			toMask--
		}
	}
	return string(value)
}

func maskLastFourUnits(input RuleInput) string {
	if strings.IndexFunc(input.Value, controlRune) >= 0 {
		return input.Redaction
	}
	runes := []rune(input.Value)
	if len(runes) <= 4 {
		return input.Redaction
	}
	for i := range len(runes) - 4 {
		if !unicode.IsSpace(runes[i]) {
			runes[i] = '*'
		}
	}
	return string(runes)
}
