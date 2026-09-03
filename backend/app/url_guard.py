"""URL validation and SSRF defence.

The scanner makes an outbound HTTP request to a hostname supplied by an
anonymous user, which is the textbook setup for Server-Side Request Forgery:
without checks, `http://169.254.169.254/latest/meta-data/` turns this service
into a proxy for cloud credentials, and `http://127.0.0.1:6379/` into a proxy
for whatever else runs on the box.

The defence has four layers:

1. Structural rules -- only http/https, only ports 80/443, no credentials.
2. Address rules    -- every address the hostname resolves to must be a public,
                       globally-routable unicast address.
3. Pinning          -- we connect to the *specific IP we validated*, not to the
                       hostname, so DNS cannot answer differently the second
                       time around (DNS rebinding / TOCTOU).
4. Redirect re-checks -- redirects are followed manually, and every hop goes
                       through layers 1-3 again. A public host that 302s to
                       localhost is the most common way past a naive filter.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from .config import settings
from .errors import ScanError

#: Prefixes with no legitimate business being scanned, beyond what the stdlib
#: already classifies. 64:ff9b::/96 is NAT64: it embeds an IPv4 address, so it
#: can be used to reach 127.0.0.1 over IPv6 on networks that deploy it.
_EXTRA_BLOCKED_NETWORKS = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
)

_MAX_URL_LENGTH = 2048
_MAX_HOSTNAME_LENGTH = 253


@dataclass(frozen=True)
class Target:
    """A URL that passed structural validation, not yet resolved."""

    scheme: str
    host: str
    port: int
    path_and_query: str

    @property
    def url(self) -> str:
        netloc = self.host if _is_default_port(self.scheme, self.port) else f"{_bracket(self.host)}:{self.port}"
        split = urlsplit(self.path_and_query or "/")
        return urlunsplit((self.scheme, netloc, split.path or "/", split.query, ""))


@dataclass(frozen=True)
class PinnedTarget:
    """A validated target bound to one specific IP address."""

    target: Target
    ip: str

    @property
    def connect_url(self) -> str:
        """The URL httpx actually dials: the literal IP, never the hostname."""
        split = urlsplit(self.target.path_and_query or "/")
        netloc = f"{_bracket(self.ip)}:{self.target.port}"
        return urlunsplit((self.target.scheme, netloc, split.path or "/", split.query, ""))

    @property
    def host_header(self) -> str:
        """Host header the origin expects -- vhosts and TLS depend on it."""
        if _is_default_port(self.target.scheme, self.target.port):
            return self.target.host
        return f"{_bracket(self.target.host)}:{self.target.port}"


def _bracket(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def _is_default_port(scheme: str, port: int) -> bool:
    return (scheme == "https" and port == 443) or (scheme == "http" and port == 80)


def normalize_input(raw: str) -> str:
    """Accept what a human types. `example.com` means `https://example.com`."""
    candidate = raw.strip()
    if not candidate:
        raise ScanError("invalid_url", "Informe uma URL para analisar.")
    if len(candidate) > _MAX_URL_LENGTH:
        raise ScanError("invalid_url", "URL longa demais.")
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    return candidate


def parse_target(raw_url: str) -> Target:
    """Layer 1: structural validation. Raises ScanError, never returns junk."""
    split = urlsplit(raw_url)

    if split.scheme not in {"http", "https"}:
        raise ScanError(
            "invalid_url",
            f"Apenas http e https sao suportados (recebido: {split.scheme or 'nenhum'}).",
        )

    # `https://trusted.com@127.0.0.1/` -- the browser and a careless regex read
    # different hosts here. urlsplit reads it correctly, but we reject the shape
    # outright so nothing downstream has to be careful.
    if split.username is not None or split.password is not None:
        raise ScanError("invalid_url", "URLs com credenciais nao sao aceitas.")

    try:
        hostname = split.hostname
        port = split.port
    except ValueError as exc:  # malformed port, e.g. `http://a:notaport/`
        raise ScanError("invalid_url", "Porta invalida na URL.") from exc

    if not hostname:
        raise ScanError("invalid_url", "Nao consegui identificar o dominio nessa URL.")

    hostname = hostname.rstrip(".").lower()
    if not hostname or len(hostname) > _MAX_HOSTNAME_LENGTH:
        raise ScanError("invalid_url", "Dominio invalido.")

    # Internationalised domains reach DNS as punycode; normalise now so the name
    # we validate is byte-for-byte the name we resolve.
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        if not hostname.isascii():
            raise ScanError("invalid_url", "Dominio invalido.") from None

    resolved_port = port if port is not None else (443 if split.scheme == "https" else 80)
    if resolved_port not in settings.allowed_ports:
        allowed = ", ".join(str(p) for p in sorted(settings.allowed_ports))
        raise ScanError(
            "blocked_target",
            f"Porta {resolved_port} bloqueada. Portas permitidas: {allowed}.",
        )

    path_and_query = urlunsplit(("", "", split.path or "/", split.query, ""))
    return Target(scheme=split.scheme, host=hostname, port=resolved_port, path_and_query=path_and_query)


def _unwrap(ip: ipaddress.IPv4Address | ipaddress.IPv6Address):
    """Follow IPv6 transition mechanisms down to the address they really mean.

    `::ffff:127.0.0.1`, 6to4 and Teredo all embed an IPv4 address that the OS
    will happily route, so classifying only the outer address is not enough.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        for embedded in (ip.ipv4_mapped, ip.sixtofour, ip.teredo[1] if ip.teredo else None):
            if embedded is not None:
                return embedded
    return ip


def is_public_address(raw_ip: str) -> bool:
    """Layer 2: is this address safe to send a stranger's request to?"""
    try:
        ip = ipaddress.ip_address(raw_ip)
    except ValueError:
        return False

    for candidate in {ip, _unwrap(ip)}:
        if not candidate.is_global:
            return False
        if candidate.is_multicast or candidate.is_unspecified or candidate.is_reserved:
            return False
        if candidate.is_loopback or candidate.is_link_local or candidate.is_private:
            return False

    return not any(ip in network for network in _EXTRA_BLOCKED_NETWORKS if ip.version == network.version)


def _resolve_blocking(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    # dict.fromkeys keeps resolver order while de-duplicating.
    return list(dict.fromkeys(info[4][0] for info in infos))


async def resolve_and_pin(target: Target) -> PinnedTarget:
    """Layers 2 + 3: resolve once, reject the whole host if *any* answer is
    internal, then hand back the single IP we will dial.

    Rejecting on any bad answer -- rather than filtering to the good ones --
    matters because a round-robin record mixing a public and an internal
    address would otherwise be a coin flip away from reaching the internal one.
    """
    try:
        addresses = await asyncio.to_thread(_resolve_blocking, target.host, target.port)
    except socket.gaierror:
        raise ScanError("dns_failure", f"Nao consegui resolver o dominio {target.host}.") from None
    except OSError:
        raise ScanError("dns_failure", f"Falha ao resolver {target.host}.") from None

    if not addresses:
        raise ScanError("dns_failure", f"O dominio {target.host} nao tem endereco IP.")

    for address in addresses:
        if not is_public_address(address):
            raise ScanError(
                "blocked_target",
                f"{target.host} aponta para um endereco interno ({address}). "
                "Enderecos privados, loopback e link-local sao bloqueados.",
            )

    return PinnedTarget(target=target, ip=addresses[0])


async def validate(raw_input: str) -> PinnedTarget:
    """The full pipeline for one URL. Used for the initial request and,
    unchanged, for every redirect hop."""
    return await resolve_and_pin(parse_target(normalize_input(raw_input)))
