package masker

import (
	"log/slog"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/icntswm/go-masker/internal/adapter"
	"github.com/icntswm/go-masker/internal/detect"
)

func init() {
	// The adapters pass only a *Masker; anything else fails closed.
	adapter.Scalar = func(core any, groups []string, key string, value slog.Value) (adapter.Action, string) {
		m, ok := core.(*Masker)
		if !ok {
			return adapter.Fail, ""
		}
		return m.adapterScalar(groups, key, value)
	}
	adapter.Group = func(core any, groups []string) adapter.Action {
		m, ok := core.(*Masker)
		if !ok {
			return adapter.Fail
		}
		return m.adapterGroup(groups)
	}
	adapter.PreservesTypes = func(core any) bool {
		m, ok := core.(*Masker)
		return ok && m.cfg.preserveSafe
	}
}

// adapterPath builds the field path of an attribute inside groups, the way
// path does in the slog adapter. Callers check needPaths before calling it.
func adapterPath(groups []string, key string) string {
	var builder strings.Builder
	builder.WriteByte('$')
	for _, group := range groups {
		builder.WriteString("[" + group + "]")
	}
	builder.WriteString("[" + key + "]")
	return builder.String()
}

// adapterScalar decides and masks one scalar slog attribute without the
// reflection walk of MaskField, reproducing what maskScalarField produces for
// a scalar value. No rule or detector needing the text means no formatting.
func (m *Masker) adapterScalar(groups []string, key string, value slog.Value) (adapter.Action, string) {
	var kind ValueKind
	switch value.Kind() {
	case slog.KindBool:
		kind = KindBool
	case slog.KindInt64, slog.KindUint64, slog.KindFloat64, slog.KindDuration:
		kind = KindNumber
	default:
		kind = KindString
	}
	if !utf8.ValidString(key) {
		return adapter.Fail, ""
	}
	if value.Kind() == slog.KindString && !utf8.ValidString(value.String()) {
		return adapter.Fail, ""
	}
	field := Field{Key: key, Source: SourceMap, Kind: kind}
	if m.cfg.needPaths {
		field.Path = adapterPath(groups, key)
	}
	decision, err := callPolicy(m.policy, field)
	if err != nil {
		return adapter.Fail, ""
	}
	if decision.Omit {
		return adapter.Omit, ""
	}
	if !isNilRule(decision.Rule) {
		rule := decision.Rule
		if rule == Rule(fullRule) || rule == Rule(passwordRule) || rule == Rule(tokenRule) {
			return adapter.Replace, m.cfg.marker
		}
		text := adapterText(value)
		result, err := applyRule(rule, RuleInput{Value: text, Kind: kind, Redaction: m.cfg.marker})
		if err != nil {
			return adapter.Fail, ""
		}
		return finishScalar(text, result, m.cfg.marker)
	}
	switch value.Kind() {
	case slog.KindString:
		text := value.String()
		if !m.inspectable(text) {
			return adapter.Keep, ""
		}
		return m.adapterInspect(text, field)
	default:
		var buf [64]byte
		b := adapterAppend(buf[:0], value)
		candidate := m.cfg.embedded && embeddedCandidateBytes(b) ||
			m.cfg.textDetectors && detect.Candidate(b, m.cfg.detectSet)
		if !candidate {
			return adapter.Keep, ""
		}
		return m.adapterInspect(string(b), field)
	}
}

// adapterInspect runs the inspection of a candidate text, exactly like the
// walkers record it, and names the action to take on its result.
func (m *Masker) adapterInspect(text string, field Field) (adapter.Action, string) {
	nodes := 1
	var errs []*MaskError
	var stop bool
	masked, changed := m.inspectString(text, field, 0, inspectState{nodes: &nodes, errs: &errs, stop: &stop})
	if !changed {
		return adapter.Keep, ""
	}
	if len(errs) > 0 {
		return adapter.Fail, ""
	}
	return finishScalar(text, masked, m.cfg.marker)
}

// finishScalar reports the outcome of a masked text: a text the masking left
// alone is kept, the rest is replaced.
func finishScalar(text, masked, marker string) (adapter.Action, string) {
	if masked == text && masked != marker {
		return adapter.Keep, ""
	}
	return adapter.Replace, masked
}

// adapterGroup decides each enclosing group of an attribute as an object,
// outermost first, like MaskField decides an empty map under the group's own
// context. A masked or failed group redacts every member.
func (m *Masker) adapterGroup(groups []string) adapter.Action {
	for index, name := range groups {
		if !utf8.ValidString(name) {
			return adapter.Fail
		}
		field := Field{Key: name, Source: SourceMap, Kind: KindObject}
		if m.cfg.needPaths {
			field.Path = adapterPath(groups[:index], name)
		}
		decision, err := callPolicy(m.policy, field)
		if err != nil {
			return adapter.Fail
		}
		if decision.Omit {
			return adapter.Omit
		}
		if !isNilRule(decision.Rule) {
			return adapter.Fail
		}
	}
	return adapter.Keep
}

// adapterText renders a slog value the way the core reads it: a duration as
// its nanosecond count, everything else as slog's text form.
func adapterText(value slog.Value) string {
	if value.Kind() == slog.KindDuration {
		return strconv.FormatInt(int64(value.Duration()), 10)
	}
	return value.String()
}

// adapterAppend renders a slog value into dst, giving the bytes adapterText
// produces without allocating. It handles every scalar kind the slog adapter
// sends; KindString is not needed because a string keeps its text without a
// conversion.
func adapterAppend(dst []byte, value slog.Value) []byte {
	switch value.Kind() {
	case slog.KindInt64:
		return strconv.AppendInt(dst, value.Int64(), 10)
	case slog.KindUint64:
		return strconv.AppendUint(dst, value.Uint64(), 10)
	case slog.KindFloat64:
		return strconv.AppendFloat(dst, value.Float64(), 'g', -1, 64)
	case slog.KindBool:
		return strconv.AppendBool(dst, value.Bool())
	case slog.KindDuration:
		return strconv.AppendInt(dst, int64(value.Duration()), 10)
	default:
		return append(dst, value.String()...)
	}
}
