package masker

import (
	"cmp"
	"math"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"time"
)

// readOnlyTextTypes are standard-library marshalers whose MarshalText only
// reads its receiver. Their unexported pointers cannot be copied through
// reflection, so a shallow copy is trusted to isolate them instead.
var readOnlyTextTypes = map[reflect.Type]bool{
	reflect.TypeFor[time.Time]():      true,
	reflect.TypeFor[netip.Addr]():     true,
	reflect.TypeFor[netip.AddrPort](): true,
	reflect.TypeFor[netip.Prefix]():   true,
}

// copyableTypes caches copyableType per type.
var copyableTypes sync.Map

// isolatableTextType reports whether MarshalText can run on a receiver that
// shares no memory with the input, so user code cannot mutate the input.
func isolatableTextType(typ reflect.Type) bool {
	if readOnlyTextTypes[typ] {
		return true
	}
	if cached, ok := copyableTypes.Load(typ); ok {
		copyable, _ := cached.(bool)
		return copyable
	}
	copyable := copyableType(typ)
	copyableTypes.Store(typ, copyable)
	return copyable
}

// copyableType reports whether a receiver of typ can be copied so that it
// shares no memory with the input. Copying is limited to values without
// pointers, maps, channels, functions, interfaces, or locks, whose slices
// sit in exported fields and hold reference-free elements: such a value has
// no cycles or shared graph to rebuild, so the copy is exact. Any other
// marshaler is walked like an ordinary value instead.
func copyableType(typ reflect.Type) bool {
	if isLock(typ) {
		return false
	}
	switch typ.Kind() {
	case reflect.Array:
		return copyableType(typ.Elem())
	case reflect.Slice:
		return !holdsReference(typ.Elem()) && !containsLock(typ.Elem())
	case reflect.Struct:
		for index := range typ.NumField() {
			field := typ.Field(index)
			if !field.IsExported() {
				if holdsReference(field.Type) || containsLock(field.Type) {
					return false
				}
				continue
			}
			if !copyableType(field.Type) {
				return false
			}
		}
		return true
	case reflect.Pointer, reflect.Map, reflect.Chan, reflect.Func, reflect.Interface,
		reflect.UnsafePointer, reflect.Invalid:
		return false
	default:
		return true
	}
}

// lockerType is the method set go vet's copylocks check treats as a lock.
var lockerType = reflect.TypeFor[sync.Locker]()

// isLock reports whether typ is a lock that must not be copied, such as
// sync.Mutex or the noCopy marker inside sync.WaitGroup and sync/atomic
// types. A copy of a held lock stays locked forever.
func isLock(typ reflect.Type) bool {
	return typ.Kind() == reflect.Struct && reflect.PointerTo(typ).Implements(lockerType)
}

// containsLock reports whether a value of typ holds a lock inline.
func containsLock(typ reflect.Type) bool {
	switch typ.Kind() {
	case reflect.Array:
		return containsLock(typ.Elem())
	case reflect.Struct:
		if isLock(typ) {
			return true
		}
		for index := range typ.NumField() {
			if containsLock(typ.Field(index).Type) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// holdsReference reports whether a value of typ can share memory with a copy
// of it. A recursive type always recurses through a reference, so this ends.
func holdsReference(typ reflect.Type) bool {
	switch typ.Kind() {
	case reflect.Array:
		return holdsReference(typ.Elem())
	case reflect.Struct:
		for index := range typ.NumField() {
			if holdsReference(typ.Field(index).Type) {
				return true
			}
		}
		return false
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer,
		reflect.Slice, reflect.UnsafePointer:
		return true
	default:
		return false
	}
}

// sliceKey identifies a slice in the receiver. Slices of one array may differ
// in type, length, and capacity.
type sliceKey struct {
	typ      reflect.Type
	pointer  uintptr
	length   int
	capacity int
}

// memoryRange is the storage a slice, or the receiver itself, occupies.
type memoryRange struct {
	start, end uintptr
}

// receiverCopy copies a receiver copyableType accepted in two passes. scan
// checks the depth limit, charges the node budget, and records the storage
// every slice refers to; copy then rebuilds the value, keeping a slice that
// appears twice shared and every slice's capacity. Slices of overlapping but
// different storage, such as buf[:2] and buf[1:], or a slice of the
// receiver's own array cannot be copied with their sharing intact, so such a
// receiver is rejected instead.
//
// It holds limits rather than the walker: scan recurses, and a walker pointer
// stored here would move every walker to the heap.
type receiverCopy struct {
	budget    int
	nodes     int
	maxDepth  int
	scanned   map[sliceKey]bool
	copies    map[sliceKey]reflect.Value
	ranges    []memoryRange
	failDepth int
}

// isolatedReceiver returns a pointer to a copy of value that shares no memory
// with it. The copy is charged one node per copied element before it is made,
// and its slices count toward the depth limit. On failure it also returns the
// depth the failure occurred at. The caller has checked isolatableTextType.
func (w *walker) isolatedReceiver(value reflect.Value, depth int) (reflect.Value, ErrorCode, int) {
	typ := value.Type()
	if readOnlyTextTypes[typ] {
		receiver := reflect.New(typ)
		receiver.Elem().Set(value)
		return receiver, "", depth
	}
	if !w.chargeCopy(inlineNodes(typ)) {
		return reflect.Value{}, CodeNodeLimit, depth
	}
	c := &receiverCopy{
		budget:   w.masker.cfg.maxNodes - w.nodes,
		maxDepth: w.masker.cfg.maxDepth,
		scanned:  map[sliceKey]bool{},
		copies:   map[sliceKey]reflect.Value{},
	}
	if value.CanAddr() {
		c.addRange(value.Addr().Pointer(), typ.Size())
	}
	if code := c.scan(value, depth); code != "" {
		return reflect.Value{}, code, c.failDepth
	}
	w.nodes += c.nodes
	if c.overlapping() {
		return reflect.Value{}, CodeUnsupportedType, depth
	}
	receiver := reflect.New(typ)
	receiver.Elem().Set(c.copy(value))
	return receiver, "", depth
}

func (c *receiverCopy) addRange(start, size uintptr) {
	if size > 0 {
		c.ranges = append(c.ranges, memoryRange{start: start, end: start + size})
	}
}

// overlapping reports whether two different slices, or a slice and the
// receiver, share storage.
func (c *receiverCopy) overlapping() bool {
	slices.SortFunc(c.ranges, func(left, right memoryRange) int { return cmp.Compare(left.start, right.start) })
	var end uintptr
	for index, current := range c.ranges {
		if index > 0 && current.start < end {
			return true
		}
		end = max(end, current.end)
	}
	return false
}

// fail records the depth a scan failure occurred at.
func (c *receiverCopy) fail(code ErrorCode, depth int) ErrorCode {
	c.failDepth = depth
	return code
}

// scan visits every slice the copy will rebuild, once each.
func (c *receiverCopy) scan(value reflect.Value, depth int) ErrorCode {
	typ := value.Type()
	if !holdsReference(typ) {
		return ""
	}
	if depth > c.maxDepth {
		return c.fail(CodeDepthLimit, depth)
	}
	switch typ.Kind() {
	case reflect.Slice:
		if value.IsNil() {
			return ""
		}
		key := sliceKey{typ: typ, pointer: value.Pointer(), length: value.Len(), capacity: value.Cap()}
		if c.scanned[key] {
			return ""
		}
		c.scanned[key] = true
		count := saturatingMul(value.Cap(), inlineNodes(typ.Elem()))
		if count > c.budget-c.nodes {
			return c.fail(CodeNodeLimit, depth)
		}
		c.nodes += count
		if value.Cap() > 0 {
			last := value.Slice3(0, value.Cap(), value.Cap()).Index(value.Cap() - 1)
			c.addRange(key.pointer, last.UnsafeAddr()-key.pointer+typ.Elem().Size())
		}
		return ""
	case reflect.Array:
		for index := range value.Len() {
			if code := c.scan(value.Index(index), depth+1); code != "" {
				return code
			}
		}
		return ""
	case reflect.Struct:
		for index := range typ.NumField() {
			if !typ.Field(index).IsExported() {
				continue
			}
			if code := c.scan(value.Field(index), depth+1); code != "" {
				return code
			}
		}
		return ""
	default:
		return ""
	}
}

// copy rebuilds a value scan accepted.
func (c *receiverCopy) copy(value reflect.Value) reflect.Value {
	typ := value.Type()
	if !holdsReference(typ) {
		return value
	}
	switch typ.Kind() {
	case reflect.Slice:
		if value.IsNil() {
			return reflect.Zero(typ)
		}
		key := sliceKey{typ: typ, pointer: value.Pointer(), length: value.Len(), capacity: value.Cap()}
		if copied, seen := c.copies[key]; seen {
			return copied
		}
		backing := reflect.MakeSlice(typ, value.Cap(), value.Cap())
		reflect.Copy(backing, value.Slice3(0, value.Cap(), value.Cap()))
		copied := backing.Slice3(0, value.Len(), value.Cap())
		c.copies[key] = copied
		return copied
	case reflect.Array:
		copied := reflect.New(typ).Elem()
		for index := range value.Len() {
			copied.Index(index).Set(c.copy(value.Index(index)))
		}
		return copied
	case reflect.Struct:
		// Unexported fields hold no references here, so copying the whole
		// struct copies them, and each exported slice is replaced.
		copied := reflect.New(typ).Elem()
		copied.Set(value)
		for index := range typ.NumField() {
			if typ.Field(index).IsExported() && holdsReference(typ.Field(index).Type) {
				copied.Field(index).Set(c.copy(value.Field(index)))
			}
		}
		return copied
	default:
		// copyableType admits no other kind that holds a reference.
		return reflect.Zero(typ)
	}
}

// maxInlineNodes caps inlineNodes; it exceeds any practical node budget.
const maxInlineNodes = math.MaxInt32

// inlineNodeCounts caches inlineNodes per type.
var inlineNodeCounts sync.Map

// inlineNodes is the number of nodes a value of typ holds without following
// references: one, or one per element of an array and per field of a
// struct, so a large fixed-size array is charged like a slice of that length.
func inlineNodes(typ reflect.Type) int {
	if cached, ok := inlineNodeCounts.Load(typ); ok {
		count, _ := cached.(int)
		return count
	}
	count := countInlineNodes(typ)
	inlineNodeCounts.Store(typ, count)
	return count
}

func countInlineNodes(typ reflect.Type) int {
	switch typ.Kind() {
	case reflect.Array:
		return saturatingMul(typ.Len(), countInlineNodes(typ.Elem()))
	case reflect.Struct:
		count := 0
		for index := range typ.NumField() {
			count = saturatingAdd(count, countInlineNodes(typ.Field(index).Type))
		}
		return max(count, 1)
	default:
		return 1
	}
}

func saturatingAdd(left, right int) int {
	if left > maxInlineNodes-right {
		return maxInlineNodes
	}
	return left + right
}

func saturatingMul(left, right int) int {
	if left == 0 || right == 0 {
		return 0
	}
	if left > maxInlineNodes/right {
		return maxInlineNodes
	}
	return left * right
}

// chargeCopy spends count nodes of the traversal budget on a copy.
func (w *walker) chargeCopy(count int) bool {
	if count > w.masker.cfg.maxNodes-w.nodes {
		return false
	}
	w.nodes += count
	return true
}
