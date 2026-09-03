"""End-to-end checks against the ASGI app. No outbound network needed: every
case here is rejected before a socket is opened."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.rate_limit import limiter


@pytest.fixture(autouse=True)
def _reset_limiter() -> None:
    limiter._hits.clear()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def test_health(client: TestClient) -> None:
    assert client.get("/api/health").json() == {"status": "ok"}


def test_scan_rejects_non_http_scheme(client: TestClient) -> None:
    response = client.post("/api/scan", json={"url": "file:///etc/passwd"})
    assert response.status_code == 400
    assert response.json()["code"] == "invalid_url"


def test_scan_rejects_loopback_hostname(client: TestClient) -> None:
    # `localhost` resolves publicly-looking but lands on 127.0.0.1.
    response = client.post("/api/scan", json={"url": "http://localhost/"})
    assert response.status_code == 400
    assert response.json()["code"] == "blocked_target"


def test_scan_rejects_metadata_endpoint(client: TestClient) -> None:
    response = client.post("/api/scan", json={"url": "http://169.254.169.254/latest/meta-data/"})
    assert response.status_code == 400
    assert response.json()["code"] == "blocked_target"


def test_scan_rejects_internal_port(client: TestClient) -> None:
    response = client.post("/api/scan", json={"url": "http://example.com:6379/"})
    assert response.json()["code"] == "blocked_target"


def test_empty_url_is_a_validation_error(client: TestClient) -> None:
    assert client.post("/api/scan", json={"url": ""}).status_code == 422


def test_rate_limit_kicks_in(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(limiter, "_limit", 2)
    for _ in range(2):
        client.post("/api/scan", json={"url": "http://localhost/"})
    response = client.post("/api/scan", json={"url": "http://localhost/"})
    assert response.status_code == 429
    assert response.json()["code"] == "rate_limited"
    assert "Retry-After" in response.headers


def test_responses_carry_our_own_security_headers(client: TestClient) -> None:
    headers = client.get("/api/health").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
