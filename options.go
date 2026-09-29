package masker

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/icntswm/go-masker/internal/detect"
)

type config struct {
	marker        string
	markerAny     any
	maxDepth      int
	maxNodes      int
	maxInputBytes int64
	preserveSafe  bool
	embedded      bool
	textDetectors bool
	detectSet     detect.Set
	structTag     string
	tagRules      map[string]Rule
	needPaths     bool
}

func defaultConfig() config {
	return config{
		marker:        DefaultRedactionMarker,
		maxDepth:      32,
		maxNodes:      100_000,
		maxInputBytes: 8 << 20,
		structTag:     DefaultStructTag,
		tagRules:      builtinTagRules(),
		embedded:      true,
		textDetectors: true,
	}
}

// WithoutEmbeddedDocuments stops masking URLs, JSON documents and forms carried
// inside string values. By default a string whose field the policy leaves alone
// is masked as the document it holds, so a body or a callback URL logged as a
// string does not leak the secrets inside it.
func WithoutEmbeddedDocuments() Option {
	return func(cfg *config) error {
		cfg.embedded = false
		return nil
	}
}

// WithoutTextDetectors stops looking for secrets inside free text. By default
// a string whose field the policy leaves alone, and which is not a whole URL,
// JSON document or form, is searched for credentials recognizable by shape —
// a token after "Bearer" or "Basic", a PEM private key, a JWT, provider
// tokens such as "ghp_..." and the userinfo of a URL — and for key=value and
// key: value pairs, whose key the policy judges as a field of SourceText.
// Only the secret is replaced; the rest of the text is kept.
func WithoutTextDetectors() Option {
	return func(cfg *config) error {
		cfg.textDetectors = false
		return nil
	}
}

// WithoutValueInspection leaves every string the policy does not decide
// exactly as it is: it combines WithoutEmbeddedDocuments and
// WithoutTextDetectors.
func WithoutValueInspection() Option {
	return func(cfg *config) error {
		cfg.embedded = false
		cfg.textDetectors = false
		return nil
	}
}

// WithCardNumberDetection also finds payment card numbers in free text: 13
// to 19 digits, optionally grouped by spaces or dashes, that pass the Luhn
// check. They are masked by CardRule, keeping the last four digits. It is off
// by default because long numeric identifiers pass the Luhn check by chance
// one time in ten.
func WithCardNumberDetection() Option {
	return func(cfg *config) error {
		cfg.detectSet.Cards = true
		return nil
	}
}

// WithAWSKeyIDDetection also finds AWS access key ids, such as "AKIA..." with
// sixteen more uppercase letters or digits, in free text. A key id alone is
// not a credential, so it is off by default.
func WithAWSKeyIDDetection() Option {
	return func(cfg *config) error {
		cfg.detectSet.AWSKeyIDs = true
		return nil
	}
}

// WithPreserveSafeTypes keeps safe primitive values in their concrete types.
func WithPreserveSafeTypes() Option {
	return func(cfg *config) error {
		cfg.preserveSafe = true
		return nil
	}
}

// WithRedaction sets the marker used for sensitive and fail-closed values.
func WithRedaction(marker string) Option {
	return func(cfg *config) error {
		if marker == "" || !utf8.ValidString(marker) {
			return fmt.Errorf("%w: redaction marker", errorSentinels[CodeInvalidConfig])
		}
		cfg.marker = marker
		return nil
	}
}

// maxDepthLimit is the largest depth WithMaxDepth accepts. Traversal recurses
// once per nesting level, and a Go stack overflow is fatal rather than a panic
// that could be recovered and failed closed, so the depth cannot be unbounded.
const maxDepthLimit = 10_000

// WithMaxDepth limits recursive traversal depth. Zero permits root values only;
// values above 10000 are rejected.
func WithMaxDepth(depth int) Option {
	return func(cfg *config) error {
		if depth < 0 || depth > maxDepthLimit {
			return fmt.Errorf("%w: max depth", errorSentinels[CodeInvalidConfig])
		}
		cfg.maxDepth = depth
		return nil
	}
}

// WithMaxNodes limits the number of visited values in one operation.
func WithMaxNodes(nodes int) Option {
	return func(cfg *config) error {
		if nodes <= 0 {
			return fmt.Errorf("%w: max nodes", errorSentinels[CodeInvalidConfig])
		}
		cfg.maxNodes = nodes
		return nil
	}
}

// WithMaxInputBytes limits input accepted by MaskJSON and MaskJSONReader,
// and the length of every string value that is inspected for embedded
// documents or secrets in text: a longer string becomes the marker and the
// operation reports ErrInputLimit.
func WithMaxInputBytes(bytes int64) Option {
	return func(cfg *config) error {
		if bytes <= 0 {
			return fmt.Errorf("%w: max input bytes", errorSentinels[CodeInvalidConfig])
		}
		cfg.maxInputBytes = bytes
		return nil
	}
}

// WithStructTag changes the masking tag name. Empty selects the default name.
func WithStructTag(name string) Option {
	return func(cfg *config) error {
		if name == "" {
			name = DefaultStructTag
		}
		if !utf8.ValidString(name) {
			return fmt.Errorf("%w: struct tag", errorSentinels[CodeInvalidConfig])
		}
		cfg.structTag = name
		return nil
	}
}

// WithTagRule registers rule under name for the struct tag grammar, so a field
// tagged `mask:"name"` is masked by it. Built-in names and "omit" cannot be
// redefined: a tag that already means "hide this" must not quietly weaken.
func WithTagRule(name string, rule Rule) Option {
	return func(cfg *config) error {
		if name == "" || !utf8.ValidString(name) || name == "omit" ||
			strings.ContainsAny(name, ", \"") {
			return fmt.Errorf("%w: tag rule", errorSentinels[CodeInvalidConfig])
		}
		if _, known := cfg.tagRules[name]; known {
			return fmt.Errorf("%w: tag rule", errorSentinels[CodeInvalidConfig])
		}
		if isNilRule(rule) {
			return fmt.Errorf("%w: tag rule", errorSentinels[CodeInvalidConfig])
		}
		cfg.tagRules[name] = rule
		return nil
	}
}
