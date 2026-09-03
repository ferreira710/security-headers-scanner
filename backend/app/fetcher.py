"""Outbound fetch: retrieve response headers for a validated target.

Two properties matter here beyond "it does a GET":

* The request is dialled against a **pinned IP**, with the real hostname sent
  only in the `Host` header and the TLS SNI. That closes the DNS-rebinding gap
  between "we checked the name" and "the socket connected".
* The response body is **never read**. We need headers; a 4 GB download would
  be somebody else's problem to pay for.
"""

from __future__ import annotations

import ssl
import time
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

from .config import settings
from .errors import ScanError
from .url_guard import PinnedTarget, normalize_input, parse_target, resolve_and_pin, validate


@dataclass(frozen=True)
class FetchResult:
    requested_url: str
    final_url: str
    status_code: int
    headers: list[tuple[str, str]]
    redirect_chain: list[str]
    duration_ms: int
    resolved_ip: str


def _timeout() -> httpx.Timeout:
    return httpx.Timeout(
        connect=settings.connect_timeout,
        read=settings.read_timeout,
        write=settings.connect_timeout,
        pool=settings.connect_timeout,
    )


def _collect_headers(headers: httpx.Headers) -> list[tuple[str, str]]:
    """Wire order, lower-cased names, duplicates preserved.

    Duplicates are not a curiosity here. Two `Content-Security-Policy` headers
    are *intersected* by the browser, and two `Referrer-Policy` values mean the
    last one the browser understands wins -- collapsing them into one comma-
    joined string would quietly corrupt both analyses.
    """
    return [(name.lower(), value) for name, value in headers.multi_items()]


async def _request_once(client: httpx.AsyncClient, pinned: PinnedTarget) -> httpx.Response:
    request = client.build_request(
        "GET",
        pinned.connect_url,
        headers={
            "Host": pinned.host_header,
            "User-Agent": settings.user_agent,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Encoding": "identity",
        },
        # Verify TLS against the hostname the user asked for, not the IP we dialled.
        extensions={"sni_hostname": pinned.target.host},
    )
    # stream=True hands back the response as soon as headers arrive; the body is
    # closed unread by the caller.
    return await client.send(request, stream=True, follow_redirects=False)


async def fetch_headers(raw_input: str) -> FetchResult:
    requested = normalize_input(raw_input)
    pinned = await resolve_and_pin(parse_target(requested))

    redirect_chain: list[str] = []
    started = time.perf_counter()

    async with httpx.AsyncClient(
        timeout=_timeout(),
        follow_redirects=False,
        max_redirects=0,
        limits=httpx.Limits(max_connections=4, max_keepalive_connections=0),
    ) as client:
        for _ in range(settings.max_redirects + 1):
            try:
                response = await _request_once(client, pinned)
            except httpx.ConnectTimeout:
                raise ScanError("timeout", f"Tempo esgotado ao conectar em {pinned.target.host}.") from None
            except httpx.ReadTimeout:
                raise ScanError("timeout", f"{pinned.target.host} nao respondeu a tempo.") from None
            except (ssl.SSLError, httpx.ConnectError) as exc:
                detail = "Falha no handshake TLS" if isinstance(exc, ssl.SSLError) else "Conexao recusada"
                raise ScanError("unreachable", f"{detail} em {pinned.target.host}.") from None
            except httpx.HTTPError:
                raise ScanError("unreachable", f"Nao consegui alcancar {pinned.target.host}.") from None

            try:
                location = response.headers.get("location")
                is_redirect = 300 <= response.status_code < 400 and location

                if not is_redirect:
                    return FetchResult(
                        requested_url=requested,
                        final_url=pinned.target.url,
                        status_code=response.status_code,
                        headers=_collect_headers(response.headers),
                        redirect_chain=redirect_chain,
                        duration_ms=int((time.perf_counter() - started) * 1000),
                        resolved_ip=pinned.ip,
                    )

                # Relative Locations resolve against the logical URL, never the
                # pinned-IP one, or the next hop would carry the IP as its host.
                next_url = urljoin(pinned.target.url, location)
            finally:
                await response.aclose()

            redirect_chain.append(pinned.target.url)
            # Every hop is re-validated from scratch: a public host redirecting
            # to http://127.0.0.1/ is the standard way around a one-shot check.
            pinned = await validate(next_url)

    raise ScanError("too_many_redirects", f"Mais de {settings.max_redirects} redirecionamentos.")
