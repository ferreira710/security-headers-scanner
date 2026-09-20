// Outbound fetch: retrieve response headers for a validated target.
//
// Two properties matter here beyond "it does a GET":
//
//   - The request is dialled against a *pinned IP*, with the real hostname sent
//     only in the Host header and the TLS SNI. That closes the DNS-rebinding
//     gap between "we checked the name" and "the socket connected". Go lets us
//     say this twice: DialContext ignores the address net/http computed and
//     dials the validated one, and Control re-checks the address the kernel is
//     about to connect to.
//   - The response body is *never read*. We need headers; a 4 GB download would
//     be somebody else's problem to pay for.
package scanner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Header is one header line as it came off the wire. A slice, not a map,
// because duplicate names are meaningful: two Content-Security-Policy headers
// are intersected by the browser.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Result is the raw evidence of one scan. Grading happens in the frontend.
type Result struct {
	RequestedURL  string
	FinalURL      string
	StatusCode    int
	Headers       []Header
	RedirectChain []string
	DurationMs    int
	ResolvedIP    string
}

// Config is the tunable part of a scan.
type Config struct {
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	MaxRedirects   int
	AllowedPorts   []int
	UserAgent      string
}

// Scanner runs scans. The zero Resolver means the system resolver.
type Scanner struct {
	Config   Config
	Resolver Resolver
}

func (s *Scanner) resolver() Resolver {
	if s.Resolver != nil {
		return s.Resolver
	}
	return net.DefaultResolver
}

// Validate is the full pipeline for one URL: used for the initial request and,
// unchanged, for every redirect hop.
func (s *Scanner) Validate(ctx context.Context, rawInput string) (PinnedTarget, error) {
	normalized, err := NormalizeInput(rawInput)
	if err != nil {
		return PinnedTarget{}, err
	}
	target, err := ParseTarget(normalized, s.Config.AllowedPorts)
	if err != nil {
		return PinnedTarget{}, err
	}
	return ResolveAndPin(ctx, s.resolver(), target)
}

// transportFor builds a one-shot transport bound to exactly one address.
func (s *Scanner) transportFor(pinned PinnedTarget) *http.Transport {
	dialer := &net.Dialer{
		Timeout: s.Config.ConnectTimeout,
		// Defence in depth: by the time Control runs, DNS is done and this is
		// the address the kernel is about to connect to. Validating here means
		// even a bug in the dial plumbing above cannot land a socket on an
		// internal host.
		Control: func(_, address string, _ syscall.RawConn) error {
			addrPort, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("endereco de socket ilegivel: %s", address)
			}
			if addrPort.Addr().Unmap() != pinned.IP {
				return fmt.Errorf("socket desviou do IP validado (%s -> %s)", pinned.IP, addrPort.Addr())
			}
			if !IsPublicAddr(addrPort.Addr()) {
				return fmt.Errorf("endereco interno no socket: %s", addrPort.Addr())
			}
			return nil
		},
	}

	return &http.Transport{
		// The address net/http derives from the URL is discarded: we dial the
		// IP we validated, so no second DNS lookup can happen.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, pinned.DialAddr())
		},
		TLSClientConfig: &tls.Config{
			// Verify the certificate against the hostname the user asked for,
			// not the IP we dialled.
			ServerName: pinned.Target.Host,
			MinVersion: tls.VersionTLS12,
		},
		// We want headers and nothing else, so this is the real read budget.
		ResponseHeaderTimeout: s.Config.ReadTimeout,
		TLSHandshakeTimeout:   s.Config.ConnectTimeout,
		DisableKeepAlives:     true,
		DisableCompression:    true,
	}
}

func (s *Scanner) requestOnce(ctx context.Context, pinned PinnedTarget) (*http.Response, error) {
	transport := s.transportFor(pinned)
	defer transport.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pinned.Target.URL(), nil)
	if err != nil {
		return nil, fail(CodeInvalidURL, "URL invalida.")
	}
	// Host travels in the header and the SNI; the socket goes to the IP.
	req.Host = pinned.HostHeader()
	req.Header.Set("User-Agent", s.Config.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "identity")

	// RoundTrip, not Client.Do: a Client would follow redirects for us, and
	// following them here is the whole point of layer 4.
	resp, err := transport.RoundTrip(req)
	if err != nil {
		return nil, describeDialFailure(err, pinned.Target.Host)
	}
	return resp, nil
}

func describeDialFailure(err error, host string) *Error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fail(CodeTimeout, fmt.Sprintf("%s nao respondeu a tempo.", host))
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fail(CodeTimeout, fmt.Sprintf("Tempo esgotado ao conectar em %s.", host))
	}
	var certErr *tls.CertificateVerificationError
	var recordErr tls.RecordHeaderError
	if errors.As(err, &certErr) || errors.As(err, &recordErr) {
		return fail(CodeUnreachable, fmt.Sprintf("Falha no handshake TLS em %s.", host))
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return fail(CodeUnreachable, fmt.Sprintf("Conexao recusada em %s.", host))
	}
	return fail(CodeUnreachable, fmt.Sprintf("Nao consegui alcancar %s.", host))
}

// collectHeaders flattens Go's header map into wire-style lines.
//
// Duplicates are preserved in arrival order, which is what the analysis needs:
// two Content-Security-Policy headers are intersected by the browser, and two
// Referrer-Policy values mean the last one the browser understands wins.
// Ordering *between* different names is not recoverable from net/http -- the
// headers land in a map -- so names are sorted, which at least makes the output
// deterministic.
func collectHeaders(header http.Header) []Header {
	names := make([]string, 0, len(header))
	for name := range header {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]Header, 0, len(names))
	for _, name := range names {
		for _, value := range header[name] {
			out = append(out, Header{Name: strings.ToLower(name), Value: value})
		}
	}
	return out
}

// nextHopURL resolves a Location header against the hop it came from.
//
// The base is the *logical* URL, never the pinned-IP one: resolving against
// the IP would make the next hop carry the IP as its hostname, which both
// breaks vhosts and quietly skips the name-based checks.
func nextHopURL(current Target, location string) (string, error) {
	base, err := url.Parse(current.URL())
	if err != nil {
		return "", fail(CodeInvalidURL, "O alvo redirecionou para uma URL invalida.")
	}
	next, err := url.Parse(location)
	if err != nil {
		return "", fail(CodeInvalidURL, "O alvo redirecionou para uma URL invalida.")
	}
	return base.ResolveReference(next).String(), nil
}

// FetchHeaders runs the whole scan: validate, dial the pinned IP, follow
// redirects by hand, return the headers of the final response.
func (s *Scanner) FetchHeaders(ctx context.Context, rawInput string) (Result, error) {
	requested, err := NormalizeInput(rawInput)
	if err != nil {
		return Result{}, err
	}
	pinned, err := s.Validate(ctx, requested)
	if err != nil {
		return Result{}, err
	}

	redirectChain := []string{}
	started := time.Now()

	for hop := 0; hop <= s.Config.MaxRedirects; hop++ {
		resp, err := s.requestOnce(ctx, pinned)
		if err != nil {
			return Result{}, err
		}

		location := resp.Header.Get("Location")
		isRedirect := resp.StatusCode >= 300 && resp.StatusCode < 400 && location != ""

		if !isRedirect {
			result := Result{
				RequestedURL:  requested,
				FinalURL:      pinned.Target.URL(),
				StatusCode:    resp.StatusCode,
				Headers:       collectHeaders(resp.Header),
				RedirectChain: redirectChain,
				DurationMs:    int(time.Since(started).Milliseconds()),
				ResolvedIP:    pinned.IP.String(),
			}
			// Headers are in hand; the body is somebody else's bandwidth.
			resp.Body.Close()
			return result, nil
		}

		nextURL, hopErr := nextHopURL(pinned.Target, location)
		resp.Body.Close()
		if hopErr != nil {
			return Result{}, hopErr
		}

		redirectChain = append(redirectChain, pinned.Target.URL())
		// Every hop is re-validated from scratch: a public host redirecting to
		// http://127.0.0.1/ is the standard way around a one-shot check.
		pinned, err = s.Validate(ctx, nextURL)
		if err != nil {
			return Result{}, err
		}
	}

	return Result{}, fail(CodeTooManyRedirects,
		fmt.Sprintf("Mais de %d redirecionamentos.", s.Config.MaxRedirects))
}
