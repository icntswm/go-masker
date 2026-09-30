package masker

import (
	"reflect"
	"slices"
	"strings"
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
	// sorted holds fields ordered by jsonName, the order encoding/json
	// writes the keys of the map the walker returns for the struct.
	sorted []structFieldMetadata
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
	// flatScalar marks a field that walkFlatScalar may take directly, even
	// when the struct as a whole has other kinds of fields.
	flatScalar bool
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

// load returns the metadata for one struct type, building it once. The entry
// is keyed by type alone even though the build also depends on tagName,
// tagRules and policy: a cache belongs to a single Masker, and all three are
// fixed at construction. Sharing a cache between Maskers would break that.
func (c *structMetadataCache) load(typ reflect.Type, tagName string, tagRules map[string]Rule, policy Policy) *structMetadata {
	if cached, ok := c.entries.Load(typ); ok {
		if metadata, ok := cached.(*structMetadata); ok {
			return metadata
		}
	}

	c.builds.Add(1)
	built := buildStructMetadata(typ, tagName, tagRules, policy)
	actual, _ := c.entries.LoadOrStore(typ, built)
	if metadata, ok := actual.(*structMetadata); ok {
		return metadata
	}
	// Only *structMetadata is ever stored; rebuild rather than panic.
	return built
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
		if maskTag == "" && ambiguousJSONName(candidate.field) {
			maskTag = ambiguousJSONTag
		}
		fieldMetadata := structFieldMetadata{
			index:    append([]int(nil), candidate.index...),
			jsonName: name,
			jsonOmit: omitted,
			maskTag:  maskTag,
			kind:     kindOfType(candidate.field.Type),
		}
		fieldMetadata.flatScalar = isFlatScalarField(candidate)
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
	sorted := make([]structFieldMetadata, len(metadata.fields))
	copy(sorted, metadata.fields)
	slices.SortStableFunc(sorted, func(a, b structFieldMetadata) int { return strings.Compare(a.jsonName, b.jsonName) })
	metadata.sorted = sorted
	return metadata
}

func isFlatScalarMetadata(typ reflect.Type, candidates []fieldCandidate, conflicts [][]fieldCandidate) bool {
	if typ.Kind() != reflect.Struct || len(conflicts) != 0 || len(candidates) == 0 {
		return false
	}
	for _, candidate := range candidates {
		if !isFlatScalarField(candidate) {
			return false
		}
	}
	return true
}

// isFlatScalarField reports a directly held, exported field of a basic scalar
// kind that walkFlatScalar decides exactly as walk would.
func isFlatScalarField(candidate fieldCandidate) bool {
	if len(candidate.index) != 1 || candidate.field.PkgPath != "" || candidate.field.Type.Kind() == reflect.Invalid {
		return false
	}
	// A scalar-kind type can still render text, for example a named int
	// with a MarshalText method. The flat fast path bypasses walk, so it
	// must not hide such a value from the TextMarshaler conversion.
	fieldType := candidate.field.Type
	if fieldType.Implements(textMarshalerType) || reflect.PointerTo(fieldType).Implements(textMarshalerType) {
		return false
	}
	switch fieldType.Kind() {
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.String:
		return true
	default:
		return false
	}
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
