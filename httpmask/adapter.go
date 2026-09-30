package httpmask

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/icntswm/go-masker"
	"github.com/icntswm/go-masker/internal/adapter"
	"github.com/icntswm/go-masker/internal/urlquery"
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
	if err := a.maskPath(result); err != nil {
		return err
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

// maskPath searches the path with the core's embedded document checks and
// text detectors, so a token written into it, such as a JWT in a reset link,
// does not reach the log. No policy judges the path, which has no key, and
// the rest of it is kept.
func (a *Adapter) maskPath(result *url.URL) error {
	if result.Path == "" {
		return nil
	}
	path, err := adapter.Text(a.core, "$.path", result.Path)
	if err != nil {
		return err
	}
	if path != result.Path {
		result.Path = path
		result.RawPath = ""
	}
	return nil
}

func (a *Adapter) maskFragment(result *url.URL) {
	if a.cfg.preserveFragment || result.Fragment == "" {
		return
	}
	result.Fragment = a.marker()
	result.RawFragment = ""
}

func (a *Adapter) maskQuery(raw string) (string, error) {
	query, err := urlquery.Mask(raw, a.maskQueryPair)
	if errors.Is(err, urlquery.ErrInvalidQuery) {
		return "", fmt.Errorf("httpmask: invalid query")
	}
	return query, err
}

// maskQueryPair decides one decoded query parameter through the core policy.
func (a *Adapter) maskQueryPair(key, value string) (string, bool, error) {
	field := masker.Field{
		Key:    key,
		Path:   "$[" + key + "]",
		Source: masker.SourceURLQuery,
		Kind:   masker.KindString,
	}
	masked, err := a.core.MaskField(field, value)
	if err != nil {
		return "", false, err
	}
	// An omitted parameter is dropped from the query, matching how an
	// omitted field disappears from a masked document.
	if masked == nil {
		return "", false, nil
	}
	maskedValue, ok := masked.(string)
	if !ok {
		return "", false, fmt.Errorf("httpmask: invalid masked query result")
	}
	return maskedValue, true, nil
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
