// The SSRF filter is the part of this service that must not have a bad day.
package scanner

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

var webPorts = []int{80, 443}

func codeOf(t *testing.T, err error) Code {
	t.Helper()
	var scanErr *Error
	if !errors.As(err, &scanErr) {
		t.Fatalf("esperava *scanner.Error, recebi %#v", err)
	}
	return scanErr.Code
}

func TestNormalizeInput(t *testing.T) {
	t.Run("bare domain becomes https", func(t *testing.T) {
		got, err := NormalizeInput("example.com")
		if err != nil || got != "https://example.com" {
			t.Fatalf("got %q, err %v", got, err)
		}
	})

	t.Run("existing scheme is kept", func(t *testing.T) {
		got, err := NormalizeInput("  http://example.com/a  ")
		if err != nil || got != "http://example.com/a" {
			t.Fatalf("got %q, err %v", got, err)
		}
	})

	t.Run("empty input is rejected", func(t *testing.T) {
		_, err := NormalizeInput("   ")
		if got := codeOf(t, err); got != CodeInvalidURL {
			t.Fatalf("code = %q", got)
		}
	})

	t.Run("absurdly long url is rejected", func(t *testing.T) {
		if _, err := NormalizeInput("https://example.com/" + strings.Repeat("a", 3000)); err == nil {
			t.Fatal("esperava erro")
		}
	})
}

func TestParseTargetRejects(t *testing.T) {
	t.Run("only http schemes allowed", func(t *testing.T) {
		for _, raw := range []string{"file:///etc/passwd", "gopher://x/", "ftp://example.com"} {
			_, err := ParseTarget(raw, webPorts)
			if got := codeOf(t, err); got != CodeInvalidURL {
				t.Errorf("%s: code = %q", raw, got)
			}
		}
	})

	t.Run("credentials in url are rejected", func(t *testing.T) {
		// The `trusted.com@` prefix is what a naive startswith check reads as
		// the host; the real host is 127.0.0.1.
		_, err := ParseTarget("https://trusted.com@127.0.0.1/", webPorts)
		if got := codeOf(t, err); got != CodeInvalidURL {
			t.Fatalf("code = %q", got)
		}
	})

	t.Run("non-web ports are blocked", func(t *testing.T) {
		for _, port := range []string{"22", "6379", "5432", "8080", "9200", "11211"} {
			_, err := ParseTarget("http://example.com:"+port+"/", webPorts)
			if got := codeOf(t, err); got != CodeBlockedTarget {
				t.Errorf("porta %s: code = %q", port, got)
			}
		}
	})

	t.Run("malformed port is rejected", func(t *testing.T) {
		_, err := ParseTarget("https://example.com:notaport/", webPorts)
		if got := codeOf(t, err); got != CodeInvalidURL {
			t.Fatalf("code = %q", got)
		}
	})

	t.Run("missing host is rejected", func(t *testing.T) {
		_, err := ParseTarget("https:///apenas/caminho", webPorts)
		if got := codeOf(t, err); got != CodeInvalidURL {
			t.Fatalf("code = %q", got)
		}
	})
}

func TestParseTargetNormalises(t *testing.T) {
	t.Run("default ports are derived from scheme", func(t *testing.T) {
		https, err := ParseTarget("https://example.com/", webPorts)
		if err != nil || https.Port != 443 {
			t.Fatalf("https port = %d, err %v", https.Port, err)
		}
		plain, err := ParseTarget("http://example.com/", webPorts)
		if err != nil || plain.Port != 80 {
			t.Fatalf("http port = %d, err %v", plain.Port, err)
		}
	})

	t.Run("trailing dot and case are normalised", func(t *testing.T) {
		target, err := ParseTarget("https://ExAmPlE.COM./x", webPorts)
		if err != nil || target.Host != "example.com" {
			t.Fatalf("host = %q, err %v", target.Host, err)
		}
	})

	t.Run("idn host is punycoded", func(t *testing.T) {
		target, err := ParseTarget("https://bücher.example/", webPorts)
		if err != nil || target.Host != "xn--bcher-kva.example" {
			t.Fatalf("host = %q, err %v", target.Host, err)
		}
	})

	t.Run("ascii hosts pass through untouched", func(t *testing.T) {
		// Shapes DNS accepts but a strict IDNA profile would not.
		target, err := ParseTarget("https://my_service.example.com/", webPorts)
		if err != nil || target.Host != "my_service.example.com" {
			t.Fatalf("host = %q, err %v", target.Host, err)
		}
	})

	t.Run("path and query survive", func(t *testing.T) {
		target, err := ParseTarget("https://example.com/a/b?c=1&d=2", webPorts)
		if err != nil || target.PathAndQuery != "/a/b?c=1&d=2" {
			t.Fatalf("path = %q, err %v", target.PathAndQuery, err)
		}
	})

	t.Run("missing path becomes root", func(t *testing.T) {
		target, err := ParseTarget("https://example.com", webPorts)
		if err != nil || target.PathAndQuery != "/" {
			t.Fatalf("path = %q, err %v", target.PathAndQuery, err)
		}
	})
}

func TestIsPublicAddress(t *testing.T) {
	internal := []struct{ address, why string }{
		{"127.0.0.1", "loopback"},
		{"127.1", "nao parseia, logo nao e publico"},
		{"0.0.0.0", "unspecified"},
		{"10.0.0.5", "RFC1918"},
		{"172.16.0.1", "RFC1918"},
		{"192.168.1.1", "RFC1918"},
		{"169.254.169.254", "metadata da nuvem -- o premio classico de SSRF"},
		{"100.64.0.1", "CGNAT"},
		{"224.0.0.1", "multicast"},
		{"240.0.0.1", "reservado"},
		{"255.255.255.255", "broadcast"},
		{"198.18.0.1", "benchmarking"},
		{"192.0.2.1", "TEST-NET-1"},
		{"::1", "loopback IPv6"},
		{"fe80::1", "link-local IPv6"},
		{"fc00::1", "unique-local IPv6"},
		{"::ffff:127.0.0.1", "IPv4 mapeado em IPv6"},
		{"::ffff:169.254.169.254", "metadata via IPv4 mapeado"},
		{"64:ff9b::7f00:1", "loopback embutido em NAT64"},
		{"2002:7f00:1::", "loopback embutido em 6to4"},
		{"2001:0:0:0:0:0:ffff:ffff", "Teredo com cliente 0.0.0.0"},
		{"2001:db8::1", "documentacao"},
	}
	for _, tc := range internal {
		if IsPublicAddress(tc.address) {
			t.Errorf("%s (%s) passou como publico", tc.address, tc.why)
		}
	}

	for _, address := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"} {
		if !IsPublicAddress(address) {
			t.Errorf("%s deveria ser publico", address)
		}
	}

	if IsPublicAddress("not-an-ip") {
		t.Error("lixo nao e endereco publico")
	}
	if IsPublicAddr(netip.Addr{}) {
		t.Error("endereco zero nao e publico")
	}
}

func TestPinnedTarget(t *testing.T) {
	t.Run("dials the ip while the host header keeps the name", func(t *testing.T) {
		pinned := PinnedTarget{
			Target: Target{Scheme: "https", Host: "example.com", Port: 443, PathAndQuery: "/a?b=1"},
			IP:     netip.MustParseAddr("93.184.216.34"),
		}
		if got := pinned.DialAddr(); got != "93.184.216.34:443" {
			t.Errorf("DialAddr = %q", got)
		}
		if got := pinned.HostHeader(); got != "example.com" {
			t.Errorf("HostHeader = %q", got)
		}
		if got := pinned.Target.URL(); got != "https://example.com/a?b=1" {
			t.Errorf("URL = %q", got)
		}
	})

	t.Run("ipv6 literals are bracketed", func(t *testing.T) {
		pinned := PinnedTarget{
			Target: Target{Scheme: "https", Host: "example.com", Port: 443, PathAndQuery: "/"},
			IP:     netip.MustParseAddr("2606:4700:4700::1111"),
		}
		if got := pinned.DialAddr(); got != "[2606:4700:4700::1111]:443" {
			t.Errorf("DialAddr = %q", got)
		}
	})
}

// stubResolver returns a fixed answer set, so the address rules can be driven
// without touching DNS.
type stubResolver struct {
	addrs []netip.Addr
	err   error
}

func (s stubResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return s.addrs, s.err
}

func TestResolveAndPin(t *testing.T) {
	target := Target{Scheme: "https", Host: "example.com", Port: 443, PathAndQuery: "/"}

	t.Run("a single internal answer reproves the whole host", func(t *testing.T) {
		// The point of the rule: filtering to the good addresses would leave a
		// round-robin record a coin flip away from reaching the internal one.
		resolver := stubResolver{addrs: []netip.Addr{
			netip.MustParseAddr("93.184.216.34"),
			netip.MustParseAddr("127.0.0.1"),
		}}
		_, err := ResolveAndPin(context.Background(), resolver, target)
		if got := codeOf(t, err); got != CodeBlockedTarget {
			t.Fatalf("code = %q", got)
		}
	})

	t.Run("pins the first answer when every address is public", func(t *testing.T) {
		resolver := stubResolver{addrs: []netip.Addr{
			netip.MustParseAddr("93.184.216.34"),
			netip.MustParseAddr("8.8.8.8"),
		}}
		pinned, err := ResolveAndPin(context.Background(), resolver, target)
		if err != nil {
			t.Fatalf("erro inesperado: %v", err)
		}
		if pinned.IP.String() != "93.184.216.34" {
			t.Fatalf("IP fixado = %s", pinned.IP)
		}
	})

	t.Run("an empty answer is a dns failure", func(t *testing.T) {
		_, err := ResolveAndPin(context.Background(), stubResolver{}, target)
		if got := codeOf(t, err); got != CodeDNSFailure {
			t.Fatalf("code = %q", got)
		}
	})

	t.Run("a resolver error is a dns failure", func(t *testing.T) {
		_, err := ResolveAndPin(context.Background(), stubResolver{err: errors.New("nxdomain")}, target)
		if got := codeOf(t, err); got != CodeDNSFailure {
			t.Fatalf("code = %q", got)
		}
	})
}

func TestNextHopURL(t *testing.T) {
	current := Target{Scheme: "https", Host: "example.com", Port: 443, PathAndQuery: "/a/b?x=1"}

	cases := []struct{ location, want string }{
		{"/c", "https://example.com/c"},
		{"d", "https://example.com/a/d"},
		{"https://outro.example/z", "https://outro.example/z"},
		{"//outro.example/z", "https://outro.example/z"},
		{"http://127.0.0.1/", "http://127.0.0.1/"}, // resolvido aqui, barrado no Validate
	}
	for _, tc := range cases {
		got, err := nextHopURL(current, tc.location)
		if err != nil {
			t.Errorf("%s: erro %v", tc.location, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.location, got, tc.want)
		}
	}
}
