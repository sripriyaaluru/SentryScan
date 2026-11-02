"""Unit tests for the authorization guard -- the central safety mechanism.

These tests manipulate environment variables and clear the cached Settings object between
cases; no real network calls or scans happen here.
"""
import pytest

from app.core import authorization
from app.core.config import get_settings


@pytest.fixture(autouse=True)
def _reset_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_live_scans_disabled_by_default(monkeypatch):
    monkeypatch.delenv("ENABLE_LIVE_SCANS", raising=False)
    with pytest.raises(authorization.UnauthorizedTargetError, match="disabled"):
        authorization.require_authorization("127.0.0.1")


def test_authorized_loopback_allowed_when_enabled(monkeypatch):
    monkeypatch.setenv("ENABLE_LIVE_SCANS", "true")
    authorization.require_authorization("127.0.0.1")  # should not raise


def test_unauthorized_public_ip_blocked_even_when_enabled(monkeypatch):
    monkeypatch.setenv("ENABLE_LIVE_SCANS", "true")
    with pytest.raises(authorization.UnauthorizedTargetError, match="allow-list"):
        authorization.require_authorization("8.8.8.8")


def test_cidr_allowlist_entry_matches_ip_in_range():
    assert authorization._matches_allowlist_entry("192.168.1.50", "192.168.0.0/16") is True
    assert authorization._matches_allowlist_entry("8.8.8.8", "192.168.0.0/16") is False


def test_unresolvable_hostname_fails_closed(monkeypatch):
    monkeypatch.setenv("ENABLE_LIVE_SCANS", "true")
    assert authorization.is_target_authorized("this-host-should-not-exist.invalid.") is False


def test_empty_allowlist_denies_everything(monkeypatch):
    monkeypatch.setenv("ENABLE_LIVE_SCANS", "true")
    monkeypatch.setenv("AUTHORIZED_TARGETS", "")
    assert authorization.is_target_authorized("127.0.0.1") is False
