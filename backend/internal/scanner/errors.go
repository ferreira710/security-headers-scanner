// Package scanner holds the SSRF guard and the outbound fetch. It is the whole
// of the backend's behaviour: cmd/server and the Netlify function are two thin
// adapters over this package, so both entry points are covered by one suite.
package scanner

import "net/http"

// Code is a typed failure the frontend switches on, instead of parsing strings.
type Code string

const (
	CodeInvalidURL       Code = "invalid_url"
	CodeBlockedTarget    Code = "blocked_target"
	CodeDNSFailure       Code = "dns_failure"
	CodeUnreachable      Code = "unreachable"
	CodeTimeout          Code = "timeout"
	CodeTooManyRedirects Code = "too_many_redirects"
	CodeRateLimited      Code = "rate_limited"
)

// Error is raised anywhere in the scan pipeline and mapped to a JSON body by
// the HTTP layer.
type Error struct {
	Code    Code
	Message string
	// Status defaults to 400 when zero: every failure below is the caller
	// asking for something we refuse, not a fault on our side.
	Status int
}

func (e *Error) Error() string { return e.Message }

// StatusCode is the HTTP status this failure should be served with.
func (e *Error) StatusCode() int {
	if e.Status == 0 {
		return http.StatusBadRequest
	}
	return e.Status
}

func fail(code Code, message string) *Error {
	return &Error{Code: code, Message: message}
}
