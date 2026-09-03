"""Typed failures the frontend can switch on, instead of parsing strings."""

from __future__ import annotations

from typing import Literal

ScanErrorCode = Literal[
    "invalid_url",
    "blocked_target",
    "dns_failure",
    "unreachable",
    "timeout",
    "too_many_redirects",
    "rate_limited",
]


class ScanError(Exception):
    """Raised anywhere in the scan pipeline; mapped to a JSON body in main.py."""

    def __init__(self, code: ScanErrorCode, message: str, *, status_code: int = 400) -> None:
        super().__init__(message)
        self.code: ScanErrorCode = code
        self.message = message
        self.status_code = status_code
