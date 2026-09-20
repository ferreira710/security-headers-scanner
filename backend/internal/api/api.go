// Package api is the HTTP surface. Thin on purpose: validate, rate-limit,
// fetch, return. Both entry points -- the container in cmd/server and the
// Netlify function -- mount this same handler, so there is one implementation
// to test and no "production behaves differently" gap between them.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ferreira710/security-headers-scanner/backend/internal/config"
	"github.com/ferreira710/security-headers-scanner/backend/internal/scanner"
)

const maxURLLength = 2048

// --- Wire format. These structs are the source of truth for the TS types. ---

type scanRequest struct {
	URL string `json:"url"`
}

type scanTarget struct {
	Requested  string   `json:"requested"`
	Final      string   `json:"final"`
	StatusCode int      `json:"statusCode"`
	Redirects  []string `json:"redirects"`
	ResolvedIP string   `json:"resolvedIp"`
}

type scanResponse struct {
	Target     scanTarget       `json:"target"`
	Headers    []scanner.Header `json:"headers"`
	DurationMs int              `json:"durationMs"`
	FetchedAt  string           `json:"fetchedAt"`
}

type errorResponse struct {
	Code              scanner.Code `json:"code"`
	Message           string       `json:"message"`
	RetryAfterSeconds *int         `json:"retryAfterSeconds"`
}

// Server owns the handler's dependencies.
type Server struct {
	settings config.Settings
	scanner  *scanner.Scanner
	limiter  *SlidingWindowLimiter
	// slots bounds concurrent outbound work, independent of who asked for it.
	// Without it, N slow targets tie up N goroutines and N sockets.
	slots chan struct{}
	now   func() time.Time
}

func NewServer(settings config.Settings) *Server {
	return &Server{
		settings: settings,
		scanner: &scanner.Scanner{
			Config: scanner.Config{
				ConnectTimeout: settings.ConnectTimeout,
				ReadTimeout:    settings.ReadTimeout,
				MaxRedirects:   settings.MaxRedirects,
				AllowedPorts:   settings.AllowedPorts,
				UserAgent:      settings.UserAgent,
			},
		},
		limiter: NewSlidingWindowLimiter(
			settings.RateLimitRequests,
			time.Duration(settings.RateLimitWindowSeconds)*time.Second,
		),
		slots: make(chan struct{}, settings.MaxConcurrentScans),
		now:   time.Now,
	}
}

// Handler is the full routing table, wrapped in the cross-cutting middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("POST /api/scan", s.handleScan)
	return s.withSecurityHeaders(s.withCORS(mux))
}

// withSecurityHeaders: a tool that grades headers should pass its own grader.
func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
		next.ServeHTTP(w, r)
	})
}

// withCORS is a backstop. Requests normally arrive same-origin -- the Vite dev
// proxy, nginx in Compose, and the Netlify redirect all keep /api on the page's
// own origin, which is what lets the frontend's CSP say connect-src 'self'.
func (s *Server) withCORS(next http.Handler) http.Handler {
	allowed := map[string]bool{}
	for _, origin := range s.settings.CORSOrigins {
		allowed[origin] = true
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" && allowed[origin] {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Content-Type")
			h.Set("Access-Control-Max-Age", "600")
			h.Add("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var payload scanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&payload); err != nil {
		writeError(w, http.StatusUnprocessableEntity,
			errorResponse{Code: scanner.CodeInvalidURL, Message: "Corpo da requisicao invalido."})
		return
	}

	// Matches the old pydantic bounds (min_length=1, max_length=2048), but with
	// a body the frontend can switch on instead of FastAPI's validation shape.
	if strings.TrimSpace(payload.URL) == "" || len(payload.URL) > maxURLLength {
		writeError(w, http.StatusUnprocessableEntity,
			errorResponse{Code: scanner.CodeInvalidURL, Message: "Informe uma URL de ate 2048 caracteres."})
		return
	}

	if allowed, retryAfter := s.limiter.Allow(s.clientKey(r), s.now()); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		writeError(w, http.StatusTooManyRequests, errorResponse{
			Code: scanner.CodeRateLimited,
			Message: "Limite de " + strconv.Itoa(s.settings.RateLimitRequests) + " scans por " +
				strconv.Itoa(s.settings.RateLimitWindowSeconds) + "s atingido. Tente de novo em " +
				strconv.Itoa(retryAfter) + "s.",
			RetryAfterSeconds: &retryAfter,
		})
		return
	}

	// Per-phase timeouts can still add up across redirect hops; this is the
	// hard ceiling for the whole scan.
	ctx, cancel := context.WithTimeout(r.Context(), s.settings.TotalTimeout)
	defer cancel()

	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
		writeError(w, http.StatusTooManyRequests,
			errorResponse{Code: scanner.CodeRateLimited, Message: "Servico ocupado. Tente de novo em instantes."})
		return
	}

	result, err := s.scanner.FetchHeaders(ctx, payload.URL)
	if err != nil {
		s.writeScanError(w, ctx, err)
		return
	}

	writeJSON(w, http.StatusOK, scanResponse{
		Target: scanTarget{
			Requested:  result.RequestedURL,
			Final:      result.FinalURL,
			StatusCode: result.StatusCode,
			Redirects:  result.RedirectChain,
			ResolvedIP: result.ResolvedIP,
		},
		Headers:    result.Headers,
		DurationMs: result.DurationMs,
		FetchedAt:  s.now().UTC().Format(time.RFC3339Nano),
	})
}

func (s *Server) writeScanError(w http.ResponseWriter, ctx context.Context, err error) {
	// A cancelled context means our own total-timeout fired, whatever the
	// underlying error says.
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		writeError(w, http.StatusBadRequest,
			errorResponse{Code: scanner.CodeTimeout, Message: "O alvo demorou demais para responder."})
		return
	}

	var scanErr *scanner.Error
	if errors.As(err, &scanErr) {
		writeError(w, scanErr.StatusCode(),
			errorResponse{Code: scanErr.Code, Message: scanErr.Message})
		return
	}

	writeError(w, http.StatusBadRequest,
		errorResponse{Code: scanner.CodeUnreachable, Message: "Nao consegui completar o scan."})
}

// clientKey decides who to rate-limit.
//
// Forwarded headers are client-controlled, so they are only read when we have
// been told we sit behind a proxy that rewrites them. Otherwise anyone gets an
// unlimited number of identities by sending a different header each time.
func (s *Server) clientKey(r *http.Request) string {
	if s.settings.TrustProxyHeaders {
		// Netlify sets this itself and does not pass through a client-supplied
		// copy, which makes it the trustworthy one when we run as a function.
		if ip := strings.TrimSpace(r.Header.Get("X-Nf-Client-Connection-Ip")); ip != "" {
			return ip
		}
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			if first := strings.TrimSpace(strings.Split(forwarded, ",")[0]); first != "" {
				return first
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		if r.RemoteAddr == "" {
			return "unknown"
		}
		return r.RemoteAddr
	}
	return host
}

// StartPruning drops expired rate-limit windows on an interval. Only cmd/server
// calls it: a function instance is too short-lived to leak.
func (s *Server) StartPruning(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				s.limiter.Prune(now)
			}
		}
	}()
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, body errorResponse) {
	writeJSON(w, status, body)
}
