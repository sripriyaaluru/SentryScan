"""Unit tests for offline CVE/version matching (no DB required)."""
from app.modules.vuln_assessment.cve_matcher import match_offline_records


def test_exact_match_vsftpd_backdoor():
    matches = match_offline_records("vsftpd", "2.3.4")
    ids = {m["cve_id"] for m in matches}
    assert "CVE-2011-2523" in ids


def test_le_rule_matches_older_version():
    matches = match_offline_records("proftpd", "1.3.3")
    ids = {m["cve_id"] for m in matches}
    assert "CVE-2015-3306" in ids


def test_le_rule_excludes_newer_version():
    matches = match_offline_records("proftpd", "1.3.6")
    ids = {m["cve_id"] for m in matches}
    assert "CVE-2015-3306" not in ids


def test_wildcard_rule_matches_any_version():
    matches = match_offline_records("microsoft-ds", "whatever-banner-text")
    ids = {m["cve_id"] for m in matches}
    assert "CVE-2017-0144" in ids


def test_no_match_for_unknown_product():
    assert match_offline_records("totally-made-up-product", "1.0") == []


def test_no_product_returns_empty():
    assert match_offline_records(None, "1.0") == []
