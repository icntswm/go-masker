package masker

import (
	"slices"
	"strings"

	"github.com/icntswm/go-masker/internal/detect"
)

// textEdit replaces s[start:end] with text.
type textEdit struct {
	start, end int
	text       string
}

// inspectText masks the secrets the text detectors find in s: every span
// becomes the marker, a card number keeps its last four digits, and the value
// of a key=value pair is decided by the policy under SourceText. Everything
// else in s is kept byte for byte.
//
// A pair the policy decides wins over a span inside its value, since the
// decision covers the whole value; a pair the policy leaves alone makes no
// edit, so a token inside its value is still masked by shape.
func (m *Masker) inspectText(s string, field Field, depth int, state inspectState) (string, bool) {
	spans, pairs := detect.Find(s, m.cfg.detectSet)
	if spans == nil && pairs == nil {
		return s, false
	}
	edits := make([]textEdit, 0, len(spans)+len(pairs))
	for _, pair := range pairs {
		key := s[pair.KeyStart:pair.KeyEnd]
		value := s[pair.ValueStart:pair.ValueEnd]
		member := Field{Key: key, Path: pathFor(field.Path, key), Source: SourceText, Kind: KindString}
		masked, decided, keep := m.decideMember(member, value, depth, state)
		if !decided {
			continue
		}
		if !keep {
			// Text has no member to drop, so an omitted value is the marker.
			masked = m.cfg.marker
		}
		edits = append(edits, textEdit{pair.ValueStart, pair.ValueEnd, masked})
	}
	for _, span := range spans {
		text := m.cfg.marker
		if span.Kind == detect.KindCard {
			text = maskLastFourDigits(RuleInput{
				Value:     s[span.Start:span.End],
				Kind:      KindString,
				Redaction: m.cfg.marker,
			})
		}
		edits = append(edits, textEdit{span.Start, span.End, text})
	}
	// The outermost edit wins an overlap: sorted by start, longer first, an
	// edit is kept only when it begins after the last kept one ends.
	slices.SortFunc(edits, func(a, b textEdit) int {
		if a.start != b.start {
			return a.start - b.start
		}
		return b.end - a.end
	})
	var out strings.Builder
	// last ends the last kept edit; written ends the text copied to out.
	last, written, changed := 0, 0, false
	for _, edit := range edits {
		if edit.start < last {
			continue
		}
		last = edit.end
		if edit.text == s[edit.start:edit.end] {
			continue
		}
		if !changed {
			out.Grow(len(s))
			changed = true
		}
		out.WriteString(s[written:edit.start])
		out.WriteString(edit.text)
		written = edit.end
	}
	if !changed {
		return s, false
	}
	out.WriteString(s[written:])
	return out.String(), true
}
