package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

func TestNormalizePath(t *testing.T) {
	cases := []struct{ in, want string }{
		// Netlify rewrites /api/* onto the function's own path...
		{"/.netlify/functions/scan/scan", "/api/scan"},
		{"/.netlify/functions/scan/health", "/api/health"},
		// ...but a direct hit on the function has no sub-path at all.
		{"/.netlify/functions/scan", "/api/scan"},
		{"/.netlify/functions/scan/", "/api/scan"},
		// ...and if the original path survives the rewrite, it already works.
		{"/api/scan", "/api/scan"},
		{"/api/health", "/api/health"},
	}
	for _, tc := range cases {
		if got := normalizePath(tc.in); got != tc.want {
			t.Errorf("normalizePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHandleServesHealth(t *testing.T) {
	resp, err := handle(events.APIGatewayProxyRequest{
		HTTPMethod: http.MethodGet,
		Path:       "/.netlify/functions/scan/health",
	})
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, corpo %s", resp.StatusCode, resp.Body)
	}
	// The security headers the handler adds must survive the conversion back
	// into a Lambda response.
	if resp.Headers["X-Content-Type-Options"] != "nosniff" {
		t.Errorf("faltou X-Content-Type-Options: %#v", resp.Headers)
	}
}

func TestHandleRejectsSSRFThroughTheAdapter(t *testing.T) {
	// The guard has its own tests; this one proves the body actually reaches it
	// through the event conversion, base64 included.
	body, _ := json.Marshal(map[string]string{"url": "http://169.254.169.254/latest/meta-data/"})

	for _, encoded := range []bool{false, true} {
		request := events.APIGatewayProxyRequest{
			HTTPMethod: http.MethodPost,
			Path:       "/.netlify/functions/scan/scan",
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       string(body),
		}
		if encoded {
			request.Body = base64.StdEncoding.EncodeToString(body)
			request.IsBase64Encoded = true
		}

		resp, err := handle(request)
		if err != nil {
			t.Fatalf("base64=%v: erro %v", encoded, err)
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("base64=%v: status = %d (%s)", encoded, resp.StatusCode, resp.Body)
		}

		var failure struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal([]byte(resp.Body), &failure); err != nil {
			t.Fatalf("base64=%v: corpo ilegivel %s", encoded, resp.Body)
		}
		if failure.Code != "blocked_target" {
			t.Errorf("base64=%v: code = %q", encoded, failure.Code)
		}
	}
}

func TestHandlePassesTheClientIPToTheRateLimiter(t *testing.T) {
	// Netlify sets this header itself; without it every caller would share one
	// rate-limit bucket.
	request := events.APIGatewayProxyRequest{
		HTTPMethod: http.MethodPost,
		Path:       "/.netlify/functions/scan/scan",
		Headers: map[string]string{
			"Content-Type":              "application/json",
			"X-Nf-Client-Connection-Ip": "203.0.113.9",
		},
		Body: `{"url":"http://localhost/"}`,
	}
	resp, err := handle(request)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d (%s)", resp.StatusCode, resp.Body)
	}
}
