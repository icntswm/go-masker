package masker

import (
	"fmt"
	"unicode/utf8"
)

type config struct {
	marker        string
	maxDepth      int
	maxNodes      int
	maxInputBytes int64
	preserveSafe  bool
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

// WithMaxDepth limits recursive traversal depth. Zero permits root values only.
func WithMaxDepth(depth int) Option {
	return func(cfg *config) error {
		if depth < 0 {
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

// WithMaxInputBytes limits input accepted by MaskJSON and MaskJSONReader.
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
