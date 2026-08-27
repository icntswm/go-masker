package masker

import (
	"reflect"
	"sync"
	"sync/atomic"
)

type structMetadataCache struct {
	entries sync.Map
	builds  atomic.Uint64
}

type structMetadata struct {
	fields     []structFieldMetadata
	conflicts  []structConflictMetadata
	flatScalar bool
}

type structFieldMetadata struct {
	index    []int
	jsonName string
	jsonOmit bool
	maskTag  string
	kind     ValueKind
	tagRule  Rule
	tagKnown bool
	policy   staticDecision
}

type staticDecision struct {
	known bool
	rule  Rule
	omit  bool
}

type structConflictMetadata struct {
	field       string
	conflicting []string
}

func (c *structMetadataCache) load(typ reflect.Type, tagName string, tagRules map[string]Rule, policy Policy) *structMetadata {
	if cached, ok := c.entries.Load(typ); ok {
		return cached.(*structMetadata)
	}

	c.builds.Add(1)
	built := buildStructMetadata(typ, tagName, tagRules, policy)
	actual, _ := c.entries.LoadOrStore(typ, built)
	return actual.(*structMetadata)
}

func buildStructMetadata(typ reflect.Type, tagName string, tagRules map[string]Rule, policy Policy) *structMetadata {
	candidates, conflicts := visibleFields(typ)
	metadata := &structMetadata{
		fields:    make([]structFieldMetadata, 0, len(candidates)),
		conflicts: make([]structConflictMetadata, 0, len(conflicts)),
	}
	for _, candidate := range candidates {
		name, omitted := jsonFieldName(candidate.field)
		maskTag := structMaskTag(candidate.field, tagName)
		fieldMetadata := structFieldMetadata{
			index:    append([]int(nil), candidate.index...),
			jsonName: name,
			jsonOmit: omitted,
			maskTag:  maskTag,
			kind:     kindOfType(candidate.field.Type),
		}
		if maskTag != "" && maskTag != "omit" {
			fieldMetadata.tagRule, fieldMetadata.tagKnown = tagRules[maskTag]
		} else if maskTag == "" && isStaticKeyPolicy(policy) {
			fieldMetadata.policy = staticPolicyDecision(policy, name, fieldMetadata.kind)
		}
		metadata.fields = append(metadata.fields, fieldMetadata)
	}
	for _, conflict := range conflicts {
		conflicting := make([]string, 0, len(conflict)-1)
		for _, candidate := range conflict[1:] {
			conflicting = append(conflicting, candidate.field.Name)
		}
		metadata.conflicts = append(metadata.conflicts, structConflictMetadata{
			field:       conflict[0].field.Name,
			conflicting: conflicting,
		})
	}
	metadata.flatScalar = isFlatScalarMetadata(typ, candidates, conflicts)
	return metadata
}

func isFlatScalarMetadata(typ reflect.Type, candidates []fieldCandidate, conflicts [][]fieldCandidate) bool {
	if typ.Kind() != reflect.Struct || len(conflicts) != 0 || len(candidates) == 0 {
		return false
	}
	for _, candidate := range candidates {
		if len(candidate.index) != 1 || candidate.field.PkgPath != "" || candidate.field.Type.Kind() == reflect.Invalid {
			return false
		}
		switch candidate.field.Type.Kind() {
		case reflect.Bool,
			reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
			reflect.Float32, reflect.Float64, reflect.String:
		default:
			return false
		}
	}
	return true
}

func isStaticKeyPolicy(policy Policy) bool {
	switch typed := policy.(type) {
	case *KeyPolicy:
		return typed != nil
	case *chainPolicy:
		if typed == nil {
			return false
		}
		for _, chained := range typed.policies {
			if !isStaticKeyPolicy(chained) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func staticPolicyDecision(policy Policy, key string, kind ValueKind) staticDecision {
	decision, err := policy.Decide(Field{Key: key, Source: SourceStruct, Kind: kind})
	if err != nil {
		return staticDecision{}
	}
	return staticDecision{known: true, rule: decision.Rule, omit: decision.Omit}
}
