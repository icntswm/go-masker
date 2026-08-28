// Package httpmask adapts masker to HTTP headers and URLs.
//
// Headers are copied before masking. Cookie and Set-Cookie values, URL
// userinfo, and configured sensitive query fields are fully redacted. URL
// fragments are redacted by default and can be kept with WithPreserveFragment.
package httpmask
