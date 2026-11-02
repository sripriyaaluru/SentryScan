"""Unit tests for the Risk Analysis module's pure-function scoring rubric."""
from app.modules.risk_analysis.risk_engine import CredentialInput, VulnInput, compute_risk


def test_no_findings_is_info():
    result = compute_risk([], [])
    assert result.overall_score == 0.0
    assert result.severity_level == "Info"


def test_single_critical_finding_drives_base_score():
    vulns = [VulnInput(identifier="CVE-X", cvss_score=9.8, severity="Critical")]
    result = compute_risk(vulns, [])
    assert result.overall_score == 9.8
    assert result.severity_level == "Critical"


def test_breadth_bonus_is_capped():
    vulns = [VulnInput(identifier=f"CVE-{i}", cvss_score=9.0, severity="Critical") for i in range(10)]
    result = compute_risk(vulns, [])
    # base 9.0 + breadth bonus (capped at 1.5) = 10.5 -> capped at 10.0 overall
    assert result.overall_score == 10.0
    assert result.severity_level == "Critical"


def test_successful_credential_floors_score_at_high():
    vulns = [VulnInput(identifier="CVE-LOW", cvss_score=2.0, severity="Low")]
    creds = [CredentialInput(host="10.0.0.5", service="ssh", username="admin", success=True)]
    result = compute_risk(vulns, creds)
    assert result.overall_score >= 7.0
    assert result.severity_level == "High"


def test_failed_credential_attempt_has_no_bonus():
    vulns = [VulnInput(identifier="CVE-LOW", cvss_score=2.0, severity="Low")]
    creds = [CredentialInput(host="10.0.0.5", service="ssh", username="admin", success=False)]
    result = compute_risk(vulns, creds)
    assert result.overall_score == 2.0
    assert result.severity_level == "Low"
