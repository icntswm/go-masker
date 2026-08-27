package masker

import (
	"encoding/json"
	"strconv"
)

type jsonWalker struct {
	masker *Masker
	nodes  int
	errs   []*MaskError
	stop   bool
}

func (m *Masker) maskJSONRoot(value any, root Field) (any, error) {
	w := &jsonWalker{masker: m}
	result := w.walk(value, root, 0)
	if isOmitted(result) {
		result = nil
	}
	return result, aggregateErrors(w.errs)
}

func (w *jsonWalker) walk(value any, field Field, depth int) any {
	if w.stop {
		return w.masker.cfg.marker
	}
	if depth > w.masker.cfg.maxDepth {
		w.fail(CodeDepthLimit, field, depth)
		return w.masker.cfg.marker
	}
	w.nodes++
	if w.nodes > w.masker.cfg.maxNodes {
		w.fail(CodeNodeLimit, field, depth)
		return w.masker.cfg.marker
	}
	if value == nil {
		return nil
	}

	if field.Kind == KindInvalid {
		field.Kind = jsonValueKind(value)
	}
	if handled, result := w.applyFieldDecision(value, field); handled {
		return result
	}

	// encoding/json builds a private, non-aliased acyclic tree, so this walker
	// mutates that tree in place and does not need reflection-style cycle state.
	switch typed := value.(type) {
	case bool:
		if w.masker.cfg.preserveSafe {
			return typed
		}
		return strconv.FormatBool(typed)
	case string:
		return typed
	case json.Number:
		return typed
	case map[string]any:
		for key, child := range typed {
			if w.stop {
				break
			}
			childField := Field{
				Key:    key,
				Path:   pathFor(field.Path, key),
				Source: SourceJSON,
				Kind:   jsonValueKind(child),
			}
			childResult := w.walk(child, childField, depth+1)
			if isOmitted(childResult) {
				delete(typed, key)
				continue
			}
			typed[key] = childResult
		}
		return typed
	case []any:
		return w.walkArray(typed, field, depth)
	default:
		w.fail(CodeUnsupportedType, field, depth)
		return w.masker.cfg.marker
	}
}

func (w *jsonWalker) walkArray(values []any, field Field, depth int) []any {
	for index, child := range values {
		if w.stop {
			break
		}
		childField := Field{
			Path:   pathForIndex(field.Path, index),
			Source: SourceJSON,
			Kind:   jsonValueKind(child),
		}
		childResult := w.walk(child, childField, depth+1)
		if isOmitted(childResult) {
			values[index] = nil
			continue
		}
		values[index] = childResult
	}
	return values
}

func (w *jsonWalker) applyFieldDecision(value any, field Field) (bool, any) {
	decision, err := callPolicy(w.masker.policy, field)
	if err != nil {
		code := CodePolicyFailure
		if isPanicError(err) {
			code = CodePanic
		}
		w.fail(code, field, 0)
		return true, w.masker.cfg.marker
	}
	if decision.Omit {
		return true, omittedResult
	}
	if isNilRule(decision.Rule) {
		return false, nil
	}
	return true, w.apply(decision.Rule, value, field)
}

func (w *jsonWalker) apply(rule Rule, value any, field Field) any {
	result, err := applyRule(rule, RuleInput{
		Value:     jsonScalarText(value),
		Kind:      field.Kind,
		Redaction: w.masker.cfg.marker,
	})
	if err != nil {
		code := CodeRuleFailure
		if isPanicError(err) {
			code = CodePanic
		}
		w.fail(code, field, 0)
		return w.masker.cfg.marker
	}
	return result
}

func (w *jsonWalker) fail(code ErrorCode, field Field, depth int) {
	if code == CodeDepthLimit || code == CodeNodeLimit {
		if w.stop {
			return
		}
		w.stop = true
		addPriorityFieldError(&w.errs, code, field, depth)
		return
	}
	addFieldError(&w.errs, code, field, depth)
}

func jsonValueKind(value any) ValueKind {
	switch value.(type) {
	case nil:
		return KindNil
	case string:
		return KindString
	case bool:
		return KindBool
	case json.Number:
		return KindNumber
	case map[string]any:
		return KindObject
	case []any:
		return KindArray
	default:
		return KindInvalid
	}
}

func jsonScalarText(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case bool:
		return strconv.FormatBool(typed)
	case json.Number:
		return typed.String()
	default:
		return ""
	}
}
