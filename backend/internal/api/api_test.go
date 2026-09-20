// End-to-end checks against the handler. No outbound network needed: every
// case here is rejected before a socket is opened.
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ferreira710/security-headers-scanner/backend/internal/config"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	settings := config.FromEnv()
	settings.CORSOrigins = []string{"http://localhost:5173"}
	return NewServer(settings)
}

func post(t *testing.T, server *Server, url string) *httptest.ResponseRecorder {
	t.Helper()
	body := strings.NewReader(`{"url":` + quote(url) + `}`)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, req)
	return recorder
}

func quote(s string) string {
	encoded, _ := json.Marshal(s)
	return string(encoded)
}

func decodeCode(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("resposta ilegivel (%s): %v", recorder.Body.String(), err)
	}
	return body.Code
}

func TestHealth(t *testing.T) {
	server := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if strings.TrimSpace(recorder.Body.String()) != `{"status":"ok"}` {
		t.Fatalf("corpo = %s", recorder.Body.String())
	}
}

func TestScanRejections(t *testing.T) {
	cases := []struct {
		name, url, wantCode string
		wantStatus          int
	}{
		{"non-http scheme", "file:///etc/passwd", "invalid_url", 400},
		// `localhost` looks like a name and lands on 127.0.0.1.
		{"loopback hostname", "http://localhost/", "blocked_target", 400},
		{"metadata endpoint", "http://169.254.169.254/latest/meta-data/", "blocked_target", 400},
		{"internal port", "http://example.com:6379/", "blocked_target", 400},
		{"credentials in url", "https://trusted.com@127.0.0.1/", "invalid_url", 400},
		{"ipv4 mapped loopback", "http://[::ffff:127.0.0.1]/", "blocked_target", 400},
		{"private range", "http://10.0.0.5/", "blocked_target", 400},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := newTestServer(t)
			recorder := post(t, server, tc.url)
			if recorder.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (%s)", recorder.Code, tc.wantStatus, recorder.Body.String())
			}
			if got := decodeCode(t, recorder); got != tc.wantCode {
				t.Errorf("code = %q, want %q", got, tc.wantCode)
			}
		})
	}
}

func TestEmptyURLIsAValidationError(t *testing.T) {
	server := newTestServer(t)
	recorder := post(t, server, "")
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d", recorder.Code)
	}
	// Unlike FastAPI's validation shape, this body is one the frontend can
	// switch on like any other failure.
	if got := decodeCode(t, recorder); got != "invalid_url" {
		t.Fatalf("code = %q", got)
	}
}

func TestRateLimitKicksIn(t *testing.T) {
	server := newTestServer(t)
	server.limiter = NewSlidingWindowLimiter(2, time.Minute)

	for i := 0; i < 2; i++ {
		post(t, server, "http://localhost/")
	}
	recorder := post(t, server, "http://localhost/")

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d", recorder.Code)
	}
	if got := decodeCode(t, recorder); got != "rate_limited" {
		t.Fatalf("code = %q", got)
	}
	if recorder.Header().Get("Retry-After") == "" {
		t.Fatal("faltou o header Retry-After")
	}

	var body struct {
		RetryAfterSeconds *int `json:"retryAfterSeconds"`
	}
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	if body.RetryAfterSeconds == nil {
		t.Fatal("retryAfterSeconds deveria vir preenchido")
	}
}

func TestResponsesCarryOurOwnSecurityHeaders(t *testing.T) {
	server := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, req)

	want := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
	}
	for name, value := range want {
		if got := recorder.Header().Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
}

func TestClientKeyIgnoresForwardedHeadersUnlessTrusted(t *testing.T) {
	// X-Forwarded-For is client-controlled: honouring it when we are not behind
	// a proxy we control hands every caller an unlimited supply of identities.
	server := newTestServer(t)
	server.settings.TrustProxyHeaders = false

	req := httptest.NewRequest(http.MethodPost, "/api/scan", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.RemoteAddr = "10.9.9.9:5555"
	if got := server.clientKey(req); got != "10.9.9.9" {
		t.Fatalf("sem confiar no proxy, a chave = %q", got)
	}

	server.settings.TrustProxyHeaders = true
	if got := server.clientKey(req); got != "1.2.3.4" {
		t.Fatalf("confiando no proxy, a chave = %q", got)
	}

	// Netlify sets this one itself, so it wins over the client-supplied list.
	req.Header.Set("X-Nf-Client-Connection-Ip", "5.6.7.8")
	if got := server.clientKey(req); got != "5.6.7.8" {
		t.Fatalf("o header da Netlify deveria ganhar, veio %q", got)
	}
}
