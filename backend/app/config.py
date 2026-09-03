"""Runtime configuration, read once from the environment at import time."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str, default: list[str]) -> list[str]:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    # --- Outbound fetch limits -------------------------------------------------
    connect_timeout: float = 4.0
    read_timeout: float = 6.0
    total_timeout: float = 10.0
    max_redirects: int = 5
    #: Only these ports may be reached. Anything else is a good sign someone is
    #: probing internal services (6379 redis, 5432 postgres, 9200 elastic, ...).
    allowed_ports: frozenset[int] = frozenset({80, 443})

    # --- Rate limiting ---------------------------------------------------------
    rate_limit_requests: int = 10
    rate_limit_window_seconds: int = 60
    #: Cap on how many scans run at once, so one client cannot pin the worker.
    max_concurrent_scans: int = 8
    #: Only honour X-Forwarded-For when we actually sit behind a proxy we control.
    trust_proxy_headers: bool = False

    # --- HTTP surface ----------------------------------------------------------
    cors_origins: list[str] = field(default_factory=lambda: ["http://localhost:5173"])
    user_agent: str = "SecurityHeadersScanner/1.0 (+https://github.com/)"

    @staticmethod
    def from_env() -> "Settings":
        return Settings(
            connect_timeout=float(_env_int("SCAN_CONNECT_TIMEOUT", 4)),
            read_timeout=float(_env_int("SCAN_READ_TIMEOUT", 6)),
            total_timeout=float(_env_int("SCAN_TOTAL_TIMEOUT", 10)),
            max_redirects=_env_int("SCAN_MAX_REDIRECTS", 5),
            rate_limit_requests=_env_int("RATE_LIMIT_REQUESTS", 10),
            rate_limit_window_seconds=_env_int("RATE_LIMIT_WINDOW_SECONDS", 60),
            max_concurrent_scans=_env_int("MAX_CONCURRENT_SCANS", 8),
            trust_proxy_headers=_env_bool("TRUST_PROXY_HEADERS", False),
            cors_origins=_env_list("CORS_ORIGINS", ["http://localhost:5173"]),
        )


settings = Settings.from_env()
