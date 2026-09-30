// Package httpmask adapts masker to HTTP headers and URLs.
//
// Headers are copied before masking. Cookie and Set-Cookie values, URL
// userinfo, and header values the policy selects are fully redacted. A query
// parameter is masked by the rule the policy selects for its key, so a
// partial rule such as the email rule keeps part of the value. The path is
// kept, except for what the core's text detectors find in it, such as a JWT
// in a reset link. URL fragments are redacted by default and can be kept
// with WithPreserveFragment.
package httpmask
