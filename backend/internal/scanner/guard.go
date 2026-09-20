// URL validation and SSRF defence.
//
// The scanner makes an outbound HTTP request to a hostname supplied by an
// anonymous user, which is the textbook setup for Server-Side Request Forgery:
// without checks, http://169.254.169.254/latest/meta-data/ turns this service
// into a proxy for cloud credentials, and http://127.0.0.1:6379/ into a proxy
// for whatever else runs on the box.
//
// The defence has four layers:
//
//  1. Structural rules   -- only http/https, only ports 80/443, no credentials.
//  2. Address rules      -- every address the hostname resolves to must be a
//     public, globally-routable unicast address.
//  3. Pinning            -- we connect to the *specific IP we validated*, not
//     to the hostname, so DNS cannot answer differently the second time around
//     (DNS rebinding / TOCTOU). See Dialer in fetch.go, which also re-checks
//     the address at socket level via net.Dialer.Control.
//  4. Redirect re-checks -- redirects are followed manually, and every hop goes
//     through layers 1-3 again. A public host that 302s to localhost is the
//     most common way past a naive filter.
package scanner

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/net/idna"
)

const (
	maxURLLength      = 2048
	maxHostnameLength = 253
)

// blockedPrefixes is every range with no legitimate business being scanned.
//
// 64:ff9b::/96 is NAT64 and 2002::/16 is 6to4: both embed an IPv4 address, so
// they can carry a request to 127.0.0.1 over IPv6 on networks that deploy them.
// unwrap below follows those down to the address they really mean; the prefixes
// are listed here as well so the outer form is refused even where it does not.
var blockedPrefixes = []netip.Prefix{
	// --- IPv4 ---
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network", incl. unspecified
	netip.MustParsePrefix("10.0.0.0/8"),      // RFC1918
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT
	netip.MustParsePrefix("127.0.0.0/8"),     // loopback
	netip.MustParsePrefix("169.254.0.0/16"),  // link-local -- cloud metadata lives here
	netip.MustParsePrefix("172.16.0.0/12"),   // RFC1918
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 relay anycast
	netip.MustParsePrefix("192.168.0.0/16"),  // RFC1918
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("224.0.0.0/4"),     // multicast
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, incl. 255.255.255.255
	// --- IPv6 ---
	netip.MustParsePrefix("::/128"),         // unspecified
	netip.MustParsePrefix("::1/128"),        // loopback
	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64
	netip.MustParsePrefix("64:ff9b:1::/48"), // local-use NAT64
	netip.MustParsePrefix("100::/64"),       // discard-only
	netip.MustParsePrefix("2001::/32"),      // Teredo
	netip.MustParsePrefix("2001:20::/28"),   // ORCHIDv2
	netip.MustParsePrefix("2001:db8::/32"),  // documentation
	netip.MustParsePrefix("2002::/16"),      // 6to4
	netip.MustParsePrefix("fc00::/7"),       // unique-local
	netip.MustParsePrefix("fe80::/10"),      // link-local
	netip.MustParsePrefix("ff00::/8"),       // multicast
}

// Target is a URL that passed structural validation, not yet resolved.
type Target struct {
	Scheme       string
	Host         string
	Port         int
	PathAndQuery string
}

// URL is the logical URL: the one with the hostname in it, used for the
// response's `final` field and as the base for resolving relative redirects.
// It is never the URL we dial -- see PinnedTarget.DialAddr.
func (t Target) URL() string {
	host := t.Host
	if !t.isDefaultPort() {
		host = net.JoinHostPort(t.Host, fmt.Sprint(t.Port))
	}
	path, query, _ := strings.Cut(t.PathAndQuery, "?")
	if path == "" {
		path = "/"
	}
	u := url.URL{Scheme: t.Scheme, Host: host, Path: path, RawQuery: query}
	return u.String()
}

func (t Target) isDefaultPort() bool {
	return (t.Scheme == "https" && t.Port == 443) || (t.Scheme == "http" && t.Port == 80)
}

// PinnedTarget is a validated target bound to one specific IP address.
type PinnedTarget struct {
	Target Target
	IP     netip.Addr
}

// DialAddr is what the socket connects to: the literal IP, never the hostname.
// Handing a name to the dialler here would mean a second DNS lookup, and a
// second lookup is exactly the window a rebinding attack needs.
func (p PinnedTarget) DialAddr() string {
	return netip.AddrPortFrom(p.IP, uint16(p.Target.Port)).String()
}

// HostHeader is the name the origin expects; vhosts and TLS depend on it.
func (p PinnedTarget) HostHeader() string {
	if p.Target.isDefaultPort() {
		return p.Target.Host
	}
	return net.JoinHostPort(p.Target.Host, fmt.Sprint(p.Target.Port))
}

// NormalizeInput accepts what a human types: `example.com` means
// `https://example.com`.
func NormalizeInput(raw string) (string, error) {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return "", fail(CodeInvalidURL, "Informe uma URL para analisar.")
	}
	if len(candidate) > maxURLLength {
		return "", fail(CodeInvalidURL, "URL longa demais.")
	}
	if !strings.Contains(candidate, "://") {
		candidate = "https://" + candidate
	}
	return candidate, nil
}

// ParseTarget is layer 1: structural validation. It returns an error rather
// than anything downstream has to be careful about.
func ParseTarget(rawURL string, allowedPorts []int) (Target, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		// url.Parse fails on a malformed port, e.g. http://a:notaport/
		return Target{}, fail(CodeInvalidURL, "URL invalida.")
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		scheme := u.Scheme
		if scheme == "" {
			scheme = "nenhum"
		}
		return Target{}, fail(CodeInvalidURL,
			fmt.Sprintf("Apenas http e https sao suportados (recebido: %s).", scheme))
	}

	// `https://trusted.com@127.0.0.1/` -- a careless startswith check reads the
	// host as trusted.com; the real host is 127.0.0.1. url.Parse reads it
	// correctly, but we reject the shape outright.
	if u.User != nil {
		return Target{}, fail(CodeInvalidURL, "URLs com credenciais nao sao aceitas.")
	}

	hostname := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if hostname == "" {
		return Target{}, fail(CodeInvalidURL, "Nao consegui identificar o dominio nessa URL.")
	}
	if len(hostname) > maxHostnameLength {
		return Target{}, fail(CodeInvalidURL, "Dominio invalido.")
	}

	// Internationalised domains reach DNS as punycode; normalise now so the
	// name we validate is byte-for-byte the name we resolve. ASCII hostnames
	// are passed through untouched: running them through the IDNA profile
	// would reject shapes (underscores, say) that DNS and every browser
	// already accept.
	if !isASCII(hostname) {
		encoded, err := idna.Lookup.ToASCII(hostname)
		if err != nil {
			return Target{}, fail(CodeInvalidURL, "Dominio invalido.")
		}
		hostname = encoded
	}

	port, err := resolvePort(u, allowedPorts)
	if err != nil {
		return Target{}, err
	}

	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	pathAndQuery := path
	if u.RawQuery != "" {
		pathAndQuery += "?" + u.RawQuery
	}

	return Target{Scheme: u.Scheme, Host: hostname, Port: port, PathAndQuery: pathAndQuery}, nil
}

func resolvePort(u *url.URL, allowedPorts []int) (int, error) {
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if raw := u.Port(); raw != "" {
		parsed, err := netip.ParseAddrPort(net.JoinHostPort("0.0.0.0", raw))
		if err != nil {
			return 0, fail(CodeInvalidURL, "Porta invalida na URL.")
		}
		port = int(parsed.Port())
	}

	for _, allowed := range allowedPorts {
		if port == allowed {
			return port, nil
		}
	}

	// Anything else is a good sign someone is probing internal services
	// (6379 redis, 5432 postgres, 9200 elastic, ...).
	sorted := append([]int(nil), allowedPorts...)
	sort.Ints(sorted)
	labels := make([]string, len(sorted))
	for i, p := range sorted {
		labels[i] = fmt.Sprint(p)
	}
	return 0, fail(CodeBlockedTarget,
		fmt.Sprintf("Porta %d bloqueada. Portas permitidas: %s.", port, strings.Join(labels, ", ")))
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

// unwrap follows IPv6 transition mechanisms down to the address they really
// mean. ::ffff:127.0.0.1, 6to4 and Teredo all embed an IPv4 address that the
// OS will happily route, so classifying only the outer address is not enough.
func unwrap(addr netip.Addr) (netip.Addr, bool) {
	if addr.Is4In6() {
		return addr.Unmap(), true
	}
	if !addr.Is6() {
		return netip.Addr{}, false
	}
	b := addr.As16()

	// 6to4: 2002:AABB:CCDD::/48 carries AA.BB.CC.DD.
	if b[0] == 0x20 && b[1] == 0x02 {
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	// Teredo: 2001:0000::/32, client IPv4 in the last four bytes, obfuscated
	// by XOR with all-ones.
	if b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && b[3] == 0x00 {
		return netip.AddrFrom4([4]byte{^b[12], ^b[13], ^b[14], ^b[15]}), true
	}
	// NAT64 well-known prefix: 64:ff9b::/96 carries the IPv4 in the low word.
	if b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b {
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	}
	return netip.Addr{}, false
}

// IsPublicAddr is layer 2: is this address safe to send a stranger's request
// to? Both the address as given and anything it embeds must pass.
func IsPublicAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}

	candidates := []netip.Addr{addr.Unmap()}
	if embedded, ok := unwrap(addr); ok {
		candidates = append(candidates, embedded)
	}

	for _, candidate := range candidates {
		if !candidate.IsValid() || candidate.IsUnspecified() || candidate.IsLoopback() ||
			candidate.IsPrivate() || candidate.IsMulticast() ||
			candidate.IsLinkLocalUnicast() || candidate.IsLinkLocalMulticast() ||
			candidate.IsInterfaceLocalMulticast() {
			return false
		}
		for _, prefix := range blockedPrefixes {
			if prefix.Addr().Is4() == candidate.Is4() && prefix.Contains(candidate) {
				return false
			}
		}
	}
	return true
}

// IsPublicAddress is the string form, for callers holding un-parsed input.
// Anything that does not parse is not public.
func IsPublicAddress(raw string) bool {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return false
	}
	return IsPublicAddr(addr)
}

// Resolver is the DNS lookup used by ResolveAndPin. Swappable so tests can
// drive the address rules without touching the network.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// ResolveAndPin is layers 2 + 3: resolve once, reject the whole host if *any*
// answer is internal, then hand back the single IP we will dial.
//
// Rejecting on any bad answer -- rather than filtering to the good ones --
// matters because a round-robin record mixing a public and an internal address
// would otherwise be a coin flip away from reaching the internal one.
func ResolveAndPin(ctx context.Context, resolver Resolver, target Target) (PinnedTarget, error) {
	addresses, err := resolver.LookupNetIP(ctx, "ip", target.Host)
	if err != nil {
		return PinnedTarget{}, fail(CodeDNSFailure,
			fmt.Sprintf("Nao consegui resolver o dominio %s.", target.Host))
	}
	if len(addresses) == 0 {
		return PinnedTarget{}, fail(CodeDNSFailure,
			fmt.Sprintf("O dominio %s nao tem endereco IP.", target.Host))
	}

	for _, address := range addresses {
		if !IsPublicAddr(address) {
			return PinnedTarget{}, fail(CodeBlockedTarget, fmt.Sprintf(
				"%s aponta para um endereco interno (%s). "+
					"Enderecos privados, loopback e link-local sao bloqueados.",
				target.Host, address.Unmap()))
		}
	}

	return PinnedTarget{Target: target, IP: addresses[0].Unmap()}, nil
}
