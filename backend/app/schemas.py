"""Request/response contracts. These are the source of truth for the TS types."""

from __future__ import annotations

from pydantic import BaseModel, Field

from .errors import ScanErrorCode


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048, description="URL ou dominio a analisar")


class ScanTarget(BaseModel):
    requested: str
    final: str
    statusCode: int
    redirects: list[str]
    resolvedIp: str


class Header(BaseModel):
    """One header line as it came off the wire. A list, not a dict, because
    duplicate names are meaningful."""

    name: str
    value: str


class ScanResponse(BaseModel):
    """Raw evidence only. Grading happens in the frontend, so the scoring rules
    stay unit-testable next to the UI that explains them."""

    target: ScanTarget
    headers: list[Header]
    durationMs: int
    fetchedAt: str


class ErrorResponse(BaseModel):
    code: ScanErrorCode
    message: str
    retryAfterSeconds: int | None = None
