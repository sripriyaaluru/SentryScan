"""Integration tests for the FastAPI app itself -- exercised through the real routing layer
(unlike the other test files, which test pure business-logic functions directly). These
catch wiring bugs (bad response_model, missing dependency overrides, uncaught exceptions,
etc.) that unit tests on isolated functions can't see.

Uses an isolated in-memory SQLite database (via a get_db dependency override) so these tests
never touch the real PostgreSQL instance and can run with zero external services.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings
from app.db.base import Base, get_db
from app.main import app

_engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
_TestingSessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False, future=True)


def _override_get_db():
    db = _TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = _override_get_db
client = TestClient(app)


@pytest.fixture(autouse=True)
def _fresh_schema_and_settings():
    Base.metadata.create_all(_engine)
    get_settings.cache_clear()
    yield
    Base.metadata.drop_all(_engine)
    get_settings.cache_clear()


def test_health_check_reports_live_scans_disabled_by_default():
    res = client.get("/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert body["live_scans_enabled"] is False


def test_dashboard_loads_with_no_targets():
    res = client.get("/")
    assert res.status_code == 200
    assert "SentryScan" in res.text


def test_create_list_and_get_target_round_trip():
    create_res = client.post("/api/targets", json={"name": "Lab VM", "host": "127.0.0.1", "description": "demo"})
    assert create_res.status_code == 201
    created = create_res.json()
    assert created["is_authorized"] is True  # 127.0.0.1 is in the default allow-list
    target_id = created["id"]

    list_res = client.get("/api/targets")
    assert list_res.status_code == 200
    assert len(list_res.json()) == 1

    get_res = client.get(f"/api/targets/{target_id}")
    assert get_res.status_code == 200
    assert get_res.json()["host"] == "127.0.0.1"


def test_get_missing_target_returns_404():
    res = client.get("/api/targets/9999")
    assert res.status_code == 404


def test_delete_target_returns_204_and_removes_it():
    created = client.post("/api/targets", json={"name": "Temp", "host": "127.0.0.1"}).json()
    del_res = client.delete(f"/api/targets/{created['id']}")
    assert del_res.status_code == 204
    assert client.get(f"/api/targets/{created['id']}").status_code == 404


def test_recon_scan_blocked_when_live_scans_disabled():
    """Confirms the full HTTP path returns a clean 403 (not a 500) when ENABLE_LIVE_SCANS=false,
    the default. This is the exact code path that previously crashed app startup (see the
    targets.py response_model fix) and must keep working end-to-end."""
    target = client.post("/api/targets", json={"name": "Lab VM", "host": "127.0.0.1"}).json()
    res = client.post("/api/recon/scan", json={"target_id": target["id"], "arguments": "-sV -T4"})
    assert res.status_code == 403
    assert "disabled" in res.json()["detail"].lower()


def test_recon_scan_against_unknown_target_returns_404():
    res = client.post("/api/recon/scan", json={"target_id": 9999, "arguments": "-sV -T4"})
    assert res.status_code == 404


def test_risk_scores_empty_list_for_job_with_no_findings():
    res = client.get("/api/risk/9999")
    assert res.status_code == 200
    assert res.json() == []


def test_openapi_schema_is_served():
    """A smoke test that the whole app -- every route/response_model -- builds a valid
    OpenAPI schema without raising (this is what /docs renders from)."""
    res = client.get("/openapi.json")
    assert res.status_code == 200
    assert res.json()["info"]["title"] == "SentryScan"
