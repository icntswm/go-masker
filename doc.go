// Package masker provides configurable, fail-closed masking of sensitive data.
//
// A Masker is immutable: it does not mutate input values, returns normalized
// copies of supported containers, and is safe for concurrent use after
// construction. The package
// requires Go 1.23 and uses only the standard library.
//
// Applications should use DefaultPolicy for the conservative built-in key
// bindings or provide a Policy that matches their own data model. Built-in
// rules include full, password, token, email, phone, ID, and card masking;
// struct tags can select them explicitly or omit a field.
//
// MaskJSON preserves json.Number precision and MaskJSONReader reads the whole
// input subject to WithMaxInputBytes. Reflection operations return normalized
// copies, never mutate inputs, and fail closed on invalid UTF-8, unsupported
// values, callback errors, cycles, or resource limits. WithPreserveSafeTypes
// keeps safe primitive types in reflection results.
//
// Error categories are available through errors.Is and the exported Err*
// values; detailed safe context is available through errors.As. The httpmask
// subpackage applies the same policy to headers and URLs, always fully
// redacting cookies and URL userinfo.
package masker
