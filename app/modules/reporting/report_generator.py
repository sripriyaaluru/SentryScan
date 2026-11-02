"""Reporting Module: turns scan results + risk analysis into a structured, human-readable
report (HTML, optionally rendered to PDF) with prioritized recommendations.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "templates"
REPORTS_DIR = Path(__file__).resolve().parents[3] / "reports"

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
)

_RECOMMENDATION_RULES: list[tuple[str, str]] = [
    ("backdoor", "Isolate the affected host immediately and rebuild from a known-clean image; a backdoor indicates likely prior compromise."),
    ("eternalblue", "Disable SMBv1 and apply MS17-010 / current SMB patches immediately; this flaw is wormable."),
    ("smb", "Review SMB share permissions, disable SMBv1 if still enabled, and keep the server patched."),
    ("telnet", "Disable Telnet and replace it with SSH; Telnet transmits credentials in plaintext."),
    ("ftp", "Disable anonymous FTP access, enforce strong credentials, and prefer SFTP/FTPS over plain FTP."),
    ("redis", "Require authentication (`requirepass`) and bind Redis to trusted interfaces only; never expose it directly to untrusted networks."),
    ("elasticsearch", "Enable authentication/authorization (e.g. via a security plugin) and restrict network exposure of the REST API."),
    ("heartbleed", "Upgrade OpenSSL to a patched release and reissue/revoke any certificates and keys that may have been exposed."),
    ("log4j", "Upgrade Log4j to a patched version (>=2.17.1) and disable JNDI message lookups."),
    ("rce", "Prioritize patching -- this finding allows remote code execution."),
]

_GENERIC_RECOMMENDATION = (
    "Review and remediate all identified findings, prioritizing Critical and High severity "
    "items first; re-scan after remediation to confirm closure."
)
_CREDENTIAL_RECOMMENDATION = (
    "Enforce a strong password policy and multi-factor authentication where possible; rotate "
    "any credentials found to be weak immediately."
)


@dataclass
class ReportFinding:
    identifier: str
    title: str
    description: str
    cvss_score: float | None
    severity: str
    host: str
    port: int | None = None


@dataclass
class ReportCredentialFinding:
    host: str
    service: str
    port: int
    username: str
    password: str


@dataclass
class ReportData:
    target_name: str
    target_host: str
    scan_job_id: int | None
    generated_at: datetime.datetime
    findings: list[ReportFinding]
    credential_findings: list[ReportCredentialFinding]
    overall_score: float
    severity_level: str
    rationale: str
    recommendations: list[str] = field(default_factory=list)


def build_recommendations(findings: list[ReportFinding], credential_findings: list[ReportCredentialFinding]) -> list[str]:
    """Rule-based recommendation generator keyed off finding descriptions/titles."""
    recs: list[str] = []
    haystacks = [f"{f.identifier} {f.title} {f.description}".lower() for f in findings]
    for keyword, recommendation in _RECOMMENDATION_RULES:
        if any(keyword in h for h in haystacks) and recommendation not in recs:
            recs.append(recommendation)

    if credential_findings and _CREDENTIAL_RECOMMENDATION not in recs:
        recs.append(_CREDENTIAL_RECOMMENDATION)

    recs.append(_GENERIC_RECOMMENDATION)
    return recs


def generate_html_report(data: ReportData) -> str:
    template = _env.get_template("report.html")
    return template.render(report=data)


def save_html_report(data: ReportData, filename: str | None = None) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    filename = filename or f"sentryscan_report_{data.scan_job_id or 'manual'}_{int(data.generated_at.timestamp())}.html"
    out_path = REPORTS_DIR / filename
    out_path.write_text(generate_html_report(data), encoding="utf-8")
    return out_path


def save_pdf_report(data: ReportData, filename: str | None = None) -> Path:
    """Render the report to PDF via WeasyPrint. Raises ImportError with guidance if unavailable."""
    try:
        from weasyprint import HTML
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise ImportError(
            "weasyprint is required for PDF export. Install it with `pip install weasyprint` "
            "(it also needs native Pango/Cairo libraries -- see https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation)."
        ) from exc

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    filename = filename or f"sentryscan_report_{data.scan_job_id or 'manual'}_{int(data.generated_at.timestamp())}.pdf"
    out_path = REPORTS_DIR / filename
    html_content = generate_html_report(data)
    HTML(string=html_content).write_pdf(str(out_path))
    return out_path
