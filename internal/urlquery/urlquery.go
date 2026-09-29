// Package urlquery rewrites raw URL query and form text. It is shared by the
// HTTP adapter and the core masker and must not import the root package.
package urlquery

import (
	"errors"
	"net/url"
	"slices"
	"strings"
)

// ErrInvalidQuery reports query text that cannot be parsed: a ';' separator or
// an escape sequence that is not valid percent-encoding.
var ErrInvalidQuery = errors.New("invalid query")

// maxPrealloc bounds the query pair slice preallocated from the separator
// count.
const maxPrealloc = 1024

type pair struct {
	key   string
	value string
}

// Mask rewrites raw query/form text. Pairs are split on '&', keys and values
// unescaped with url.QueryUnescape, grouped by key after a stable sort, and
// each value passed to mask; keep=false drops the pair. The output is
// re-encoded with url.QueryEscape. An error returned
// by mask is passed through unchanged; malformed text returns ErrInvalidQuery.
func Mask(raw string, mask func(key, value string) (masked string, keep bool, err error)) (string, error) {
	// One separator does not imply one pair: a query of nothing but "&" would
	// preallocate a pair per byte, turning a few megabytes of input into tens
	// of megabytes of scratch. Start from a bounded hint and let append grow.
	pairs := make([]pair, 0, min(strings.Count(raw, "&")+1, maxPrealloc))
	remaining := raw
	for remaining != "" {
		var part string
		part, remaining, _ = strings.Cut(remaining, "&")
		if strings.Contains(part, ";") {
			return "", ErrInvalidQuery
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
			return "", ErrInvalidQuery
		}
		value, err = url.QueryUnescape(value)
		if err != nil {
			return "", ErrInvalidQuery
		}

		pairs = append(pairs, pair{key: key, value: value})
	}

	if len(pairs) == 0 {
		return "", nil
	}
	slices.SortStableFunc(pairs, func(left, right pair) int {
		return strings.Compare(left.key, right.key)
	})

	var builder strings.Builder
	builder.Grow(len(raw))
	for start := 0; start < len(pairs); {
		end := start + 1
		for end < len(pairs) && pairs[end].key == pairs[start].key {
			end++
		}
		keyEscaped := url.QueryEscape(pairs[start].key)
		for index := start; index < end; index++ {
			masked, keep, err := mask(pairs[index].key, pairs[index].value)
			if err != nil {
				return "", err
			}
			// A dropped pair disappears from the query, matching how an
			// omitted field disappears from a masked document.
			if !keep {
				continue
			}
			if builder.Len() > 0 {
				builder.WriteByte('&')
			}
			builder.WriteString(keyEscaped)
			builder.WriteByte('=')
			builder.WriteString(url.QueryEscape(masked))
		}
		start = end
	}
	return builder.String(), nil
}
