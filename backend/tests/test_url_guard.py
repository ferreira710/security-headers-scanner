"""The SSRF filter is the part of this service that must not have a bad day."""

from __future__ import annotations

import pytest

from app.errors import ScanError
from app.url_guard import Target, is_public_address, normalize_input, parse_target


class TestNormalizeInput:
    def test_bare_domain_becomes_https(self) -> None:
        assert normalize_input("example.com") == "https://example.com"

    def test_existing_scheme_is_kept(self) -> None:
        assert normalize_input("  http://example.com/a  ") == "http://example.com/a"

    def test_empty_input_is_rejected(self) -> None:
        with pytest.raises(ScanError) as exc:
            normalize_input("   ")
        assert exc.value.code == "invalid_url"

    def test_absurdly_long_url_is_rejected(self) -> None:
        with pytest.raises(ScanError):
            normalize_input("https://example.com/" + "a" * 3000)


class TestParseTarget:
    @pytest.mark.parametrize("url", ["file:///etc/passwd", "gopher://x/", "ftp://example.com"])
    def test_only_http_schemes_allowed(self, url: str) -> None:
        with pytest.raises(ScanError) as exc:
            parse_target(url)
        assert exc.value.code == "invalid_url"

    def test_credentials_in_url_are_rejected(self) -> None:
        # The `trusted.com@` prefix is what a naive `url.startswith` check reads
        # as the host; the real host is 127.0.0.1.
        with pytest.raises(ScanError) as exc:
            parse_target("https://trusted.com@127.0.0.1/")
        assert exc.value.code == "invalid_url"

    @pytest.mark.parametrize("port", [22, 6379, 5432, 8080, 9200, 11211])
    def test_non_web_ports_are_blocked(self, port: int) -> None:
        with pytest.raises(ScanError) as exc:
            parse_target(f"http://example.com:{port}/")
        assert exc.value.code == "blocked_target"

    def test_default_ports_are_derived_from_scheme(self) -> None:
        assert parse_target("https://example.com/").port == 443
        assert parse_target("http://example.com/").port == 80

    def test_trailing_dot_and_case_are_normalised(self) -> None:
        assert parse_target("https://ExAmPlE.COM./x").host == "example.com"

    def test_idn_host_is_punycoded(self) -> None:
        assert parse_target("https://bücher.example/").host == "xn--bcher-kva.example"

    def test_path_and_query_survive(self) -> None:
        target = parse_target("https://example.com/a/b?c=1&d=2")
        assert target.path_and_query == "/a/b?c=1&d=2"

    def test_missing_path_becomes_root(self) -> None:
        assert parse_target("https://example.com").path_and_query == "/"

    def test_malformed_port_is_rejected(self) -> None:
        with pytest.raises(ScanError) as exc:
            parse_target("https://example.com:notaport/")
        assert exc.value.code == "invalid_url"


class TestIsPublicAddress:
    @pytest.mark.parametrize(
        "address",
        [
            "127.0.0.1",          # loopback
            "127.1",              # still loopback once parsed
            "0.0.0.0",            # unspecified
            "10.0.0.5",           # RFC1918
            "172.16.0.1",         # RFC1918
            "192.168.1.1",        # RFC1918
            "169.254.169.254",    # cloud metadata -- the classic SSRF prize
            "100.64.0.1",         # CGNAT
            "224.0.0.1",          # multicast
            "240.0.0.1",          # reserved
            "::1",                # IPv6 loopback
            "fe80::1",            # IPv6 link-local
            "fc00::1",            # IPv6 unique-local
            "::ffff:127.0.0.1",   # IPv4-mapped loopback
            "::ffff:169.254.169.254",
            "64:ff9b::7f00:1",    # NAT64-embedded loopback
            "2002:7f00:1::",      # 6to4-embedded loopback
        ],
    )
    def test_internal_addresses_are_blocked(self, address: str) -> None:
        assert is_public_address(address) is False

    @pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"])
    def test_public_addresses_are_allowed(self, address: str) -> None:
        assert is_public_address(address) is True

    def test_garbage_is_not_public(self) -> None:
        assert is_public_address("not-an-ip") is False


class TestPinnedTarget:
    def test_connect_url_uses_the_ip_and_host_header_keeps_the_name(self) -> None:
        from app.url_guard import PinnedTarget

        pinned = PinnedTarget(
            target=Target(scheme="https", host="example.com", port=443, path_and_query="/a?b=1"),
            ip="93.184.216.34",
        )
        assert pinned.connect_url == "https://93.184.216.34:443/a?b=1"
        assert pinned.host_header == "example.com"

    def test_ipv6_literals_are_bracketed(self) -> None:
        from app.url_guard import PinnedTarget

        pinned = PinnedTarget(
            target=Target(scheme="https", host="example.com", port=443, path_and_query="/"),
            ip="2606:4700:4700::1111",
        )
        assert pinned.connect_url.startswith("https://[2606:4700:4700::1111]:443/")
