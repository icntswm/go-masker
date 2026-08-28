package httpmask

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/icntswm/go-masker"
)

type config struct{ preserveFragment bool }

// Option configures an HTTP masking Adapter. The option type is intentionally
// closed; callers use the exported With* constructors.
type Option func(*config) error

// Adapter masks HTTP metadata using a core masker instance.
type Adapter struct {
	core *masker.Masker
	cfg  config
	mark string
}

type queryPair struct {
	key   string
	value string
}

// New creates an HTTP adapter around a configured core masker.
func New(core *masker.Masker, opts ...Option) (*Adapter, error) {
	if core == nil {
		return nil, fmt.Errorf("httpmask: nil core masker")
	}
	cfg := config{}
	for _, option := range opts {
		if option == nil {
			return nil, fmt.Errorf("httpmask: nil option")
		}
		if err := option(&cfg); err != nil {
			return nil, err
		}
	}
	mark, err := core.MaskString("", masker.FullRule())
	if err != nil {
		return nil, fmt.Errorf("httpmask: marker: %w", err)
	}
	return &Adapter{core: core, cfg: cfg, mark: mark}, nil
}

// WithPreserveFragment keeps the URL fragment intact.
//
// Fragments are redacted by default: an OAuth implicit-flow token lives in the
// fragment, and a library that fails closed should not need an opt-in to keep
// it out of a log. Use this option when the fragment carries client-side
// routing state that a reader needs.
func WithPreserveFragment() Option {
	return func(cfg *config) error {
		cfg.preserveFragment = true
		return nil
	}
}

// Headers returns a newly allocated masked header map.
func (a *Adapter) Headers(src http.Header) (http.Header, error) {
	if a == nil || a.core == nil {
		return http.Header{}, fmt.Errorf("httpmask: nil adapter")
	}
	result := make(http.Header, len(src))
	for key, values := range src {
		isCookie := strings.EqualFold(key, "Cookie") || strings.EqualFold(key, "Set-Cookie")
		field := masker.Field{
			Key:    key,
			Path:   "$[" + key + "]",
			Source: masker.SourceHeader,
			Kind:   masker.KindString,
		}
		copied := make([]string, 0, len(values))
		for _, value := range values {
			if isCookie {
				masked, err := a.core.MaskString(value, masker.FullRule())
				if err != nil {
					return http.Header{}, err
				}
				copied = append(copied, masked)
				continue
			}
			masked, err := a.core.MaskField(field, value)
			if err != nil {
				return http.Header{}, err
			}
			// A policy that omits the field asks for the value to disappear,
			// not to be replaced by a marker.
			if masked == nil {
				continue
			}
			stringValue, ok := masked.(string)
			if !ok {
				return http.Header{}, fmt.Errorf("httpmask: invalid masked header result")
			}
			copied = append(copied, stringValue)
		}
		// Dropping every value drops the header itself; an empty value list
		// would still be serialized as a header with no values.
		if len(copied) == 0 {
			continue
		}
		result[key] = copied
	}
	return result, nil
}

// URL returns a newly allocated masked URL.
func (a *Adapter) URL(src *url.URL) (*url.URL, error) {
	if a == nil {
		return &url.URL{Path: masker.DefaultRedactionMarker}, fmt.Errorf("httpmask: nil adapter")
	}
	if a.core == nil {
		return a.safeURL(), fmt.Errorf("httpmask: nil adapter")
	}
	if src == nil || src.Opaque != "" {
		return a.safeURL(), fmt.Errorf("httpmask: unsupported URL")
	}
	result := *src
	if err := a.maskURL(&result); err != nil {
		return a.safeURL(), err
	}
	return &result, nil
}

func (a *Adapter) maskURL(result *url.URL) error {
	if result.User != nil {
		result.User = url.User(a.marker())
	}

	if result.RawQuery == "" {
		a.maskFragment(result)
		return nil
	}

	query, err := a.maskQuery(result.RawQuery)
	if err != nil {
		return err
	}
	result.RawQuery = query
	a.maskFragment(result)
	return nil
}

func (a *Adapter) maskFragment(result *url.URL) {
	if a.cfg.preserveFragment || result.Fragment == "" {
		return
	}
	result.Fragment = a.marker()
	result.RawFragment = ""
}

// maxQueryPrealloc bounds the query pair slice preallocated from the separator
// count.
const maxQueryPrealloc = 1024

func (a *Adapter) maskQuery(raw string) (string, error) {
	// One separator does not imply one pair: a query of nothing but "&" would
	// preallocate a pair per byte, turning a few megabytes of input into tens
	// of megabytes of scratch. Start from a bounded hint and let append grow.
	pairs := make([]queryPair, 0, min(strings.Count(raw, "&")+1, maxQueryPrealloc))
	remaining := raw
	for remaining != "" {
		var part string
		part, remaining, _ = strings.Cut(remaining, "&")
		if strings.Contains(part, ";") {
			return "", fmt.Errorf("httpmask: invalid query")
		}
		if part == "" {
			continue
		}

		key, value, _ := strings.Cut(part, "=")
		if key == "" {
			continue
		}
		key, err := url.QueryUnescape(key)
		if err != nil {
			return "", fmt.Errorf("httpmask: invalid query")
		}
		value, err = url.QueryUnescape(value)
		if err != nil {
			return "", fmt.Errorf("httpmask: invalid query")
		}

		pairs = append(pairs, queryPair{key: key, value: value})
	}

	if len(pairs) == 0 {
		return "", nil
	}
	slices.SortStableFunc(pairs, func(left, right queryPair) int {
		return strings.Compare(left.key, right.key)
	})

	var builder strings.Builder
	builder.Grow(len(raw))
	for start := 0; start < len(pairs); {
		end := start + 1
		for end < len(pairs) && pairs[end].key == pairs[start].key {
			end++
		}
		field := masker.Field{
			Key:    pairs[start].key,
			Path:   "$[" + pairs[start].key + "]",
			Source: masker.SourceURLQuery,
			Kind:   masker.KindString,
		}
		keyEscaped := url.QueryEscape(pairs[start].key)
		for index := start; index < end; index++ {
			masked, maskErr := a.core.MaskField(field, pairs[index].value)
			if maskErr != nil {
				return "", maskErr
			}
			// An omitted parameter is dropped from the query, matching how an
			// omitted field disappears from a masked document.
			if masked == nil {
				continue
			}
			maskedValue, ok := masked.(string)
			if !ok {
				return "", fmt.Errorf("httpmask: invalid masked query result")
			}
			if builder.Len() > 0 {
				builder.WriteByte('&')
			}
			builder.WriteString(keyEscaped)
			builder.WriteByte('=')
			builder.WriteString(url.QueryEscape(maskedValue))
		}
		start = end
	}
	return builder.String(), nil
}

// URLString parses and masks a URL string.
func (a *Adapter) URLString(raw string) (string, error) {
	if a == nil || a.core == nil {
		return masker.DefaultRedactionMarker, fmt.Errorf("httpmask: nil adapter")
	}
	src, err := url.Parse(raw)
	if err != nil {
		return a.marker(), fmt.Errorf("httpmask: invalid URL")
	}
	if src.Opaque != "" {
		return a.marker(), fmt.Errorf("httpmask: unsupported URL")
	}
	result := *src
	if err := a.maskURL(&result); err != nil {
		return a.marker(), err
	}
	return result.String(), nil
}

func (a *Adapter) marker() string {
	if a.mark != "" {
		return a.mark
	}
	return masker.DefaultRedactionMarker
}

func (a *Adapter) safeURL() *url.URL { return &url.URL{Path: a.marker()} }
