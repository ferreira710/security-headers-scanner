"""HTTP surface. Thin on purpose: validate, rate-limit, fetch, return."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import settings
from .errors import ScanError
from .fetcher import fetch_headers
from .rate_limit import limiter, scan_slots
from .schemas import ErrorResponse, Header, ScanRequest, ScanResponse, ScanTarget

PRUNE_INTERVAL_SECONDS = 300


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None]:
    async def prune_forever() -> None:
        while True:
            await asyncio.sleep(PRUNE_INTERVAL_SECONDS)
            await limiter.prune()

    task = asyncio.create_task(prune_forever())
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


app = FastAPI(
    title="Security Headers Scanner API",
    version="1.0.0",
    description="Proxy que le response headers de um alvo publico. Existe porque o "
    "browser nao expoe headers de terceiros por causa de CORS.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
    max_age=600,
)


@app.middleware("http")
async def own_security_headers(request: Request, call_next):
    """A tool that grades headers should pass its own grader."""
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
    )
    response.headers.setdefault(
        "Permissions-Policy", "geolocation=(), camera=(), microphone=()"
    )
    return response


def client_key(request: Request) -> str:
    """Who to rate-limit.

    X-Forwarded-For is client-controlled, so it is only read when we have been
    told we sit behind a proxy that rewrites it. Otherwise anyone gets an
    unlimited number of identities by sending a different header each time.
    """
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for", "")
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    return request.client.host if request.client else "unknown"


@app.exception_handler(ScanError)
async def scan_error_handler(_: Request, exc: ScanError) -> JSONResponse:
    body = ErrorResponse(
        code=exc.code,
        message=exc.message,
        retryAfterSeconds=(
            limiter.retry_after_seconds() if exc.code == "rate_limited" else None
        ),
    )
    headers = (
        {"Retry-After": str(limiter.retry_after_seconds())}
        if exc.code == "rate_limited"
        else {}
    )
    return JSONResponse(
        status_code=exc.status_code, content=body.model_dump(), headers=headers
    )


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/api/scan",
    response_model=ScanResponse,
    responses={400: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
async def scan(payload: ScanRequest, request: Request) -> ScanResponse:
    await limiter.check(client_key(request))

    async with scan_slots:
        try:
            # Per-phase timeouts can still add up across redirect hops; this is
            # the hard ceiling for the whole scan.
            result = await asyncio.wait_for(
                fetch_headers(payload.url), timeout=settings.total_timeout
            )
        except (asyncio.TimeoutError, TimeoutError):
            raise ScanError(
                "timeout", "O alvo demorou demais para responder."
            ) from None

    return ScanResponse(
        target=ScanTarget(
            requested=result.requested_url,
            final=result.final_url,
            statusCode=result.status_code,
            redirects=result.redirect_chain,
            resolvedIp=result.resolved_ip,
        ),
        headers=[Header(name=name, value=value) for name, value in result.headers],
        durationMs=result.duration_ms,
        fetchedAt=datetime.now(timezone.utc).isoformat(),
    )
