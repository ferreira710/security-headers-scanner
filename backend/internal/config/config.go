// Package config reads runtime settings from the environment, once.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Settings is the whole tunable surface. Defaults are the values the Compose
// setup and the Netlify deploy both run with unless told otherwise.
type Settings struct {
	// --- Outbound fetch limits ---
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	TotalTimeout   time.Duration
	MaxRedirects   int
	// AllowedPorts are the only ports that may be reached. Anything else is a
	// good sign someone is probing internal services.
	AllowedPorts []int

	// --- Rate limiting ---
	RateLimitRequests      int
	RateLimitWindowSeconds int
	// MaxConcurrentScans caps how much outbound work happens at once, so one
	// client cannot pin the process.
	MaxConcurrentScans int
	// TrustProxyHeaders: only honour forwarded client IPs when we actually sit
	// behind a proxy we control.
	TrustProxyHeaders bool

	// --- HTTP surface ---
	CORSOrigins []string
	UserAgent   string

	// Port is the port cmd/server listens on. Unused by the Netlify function.
	Port string
}

func FromEnv() Settings {
	return Settings{
		ConnectTimeout:         time.Duration(envInt("SCAN_CONNECT_TIMEOUT", 4)) * time.Second,
		ReadTimeout:            time.Duration(envInt("SCAN_READ_TIMEOUT", 6)) * time.Second,
		TotalTimeout:           time.Duration(envInt("SCAN_TOTAL_TIMEOUT", 10)) * time.Second,
		MaxRedirects:           envInt("SCAN_MAX_REDIRECTS", 5),
		AllowedPorts:           []int{80, 443},
		RateLimitRequests:      envInt("RATE_LIMIT_REQUESTS", 10),
		RateLimitWindowSeconds: envInt("RATE_LIMIT_WINDOW_SECONDS", 60),
		MaxConcurrentScans:     envInt("MAX_CONCURRENT_SCANS", 8),
		TrustProxyHeaders:      envBool("TRUST_PROXY_HEADERS", false),
		CORSOrigins:            envList("CORS_ORIGINS", []string{"http://localhost:5173"}),
		UserAgent:              "SecurityHeadersScanner/1.0 (+https://github.com/)",
		Port:                   envString("PORT", "8000"),
	}
}

func envString(name, fallback string) string {
	if raw := strings.TrimSpace(os.Getenv(name)); raw != "" {
		return raw
	}
	return fallback
}

func envInt(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func envBool(name string, fallback bool) bool {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func envList(name string, fallback []string) []string {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	var out []string
	for _, item := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}
