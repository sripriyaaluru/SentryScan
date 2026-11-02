"""Risk Analysis Module: combines CVSS-scored vulnerabilities and credential-testing results
into a single aggregate risk score + severity level + human-readable rationale.

Pure-function design (no DB/network access) so it's easily unit-testable and reusable from
both the API layer and the reporting module.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class VulnInput:
    identifier: str  # CVE ID or NSE script id
    cvss_score: float
    severity: str  # "Critical" | "High" | "Medium" | "Low" | "Info"


@dataclass
class CredentialInput:
    host: str
    service: str
    username: str
    success: bool = True


@dataclass
class RiskResult:
    overall_score: float
    severity_level: str
    rationale: str
    contributing_factors: list[str] = field(default_factory=list)


_SEVERITY_THRESHOLDS = [
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
    (0.0, "Info"),
]

_CREDENTIAL_PENALTY = 2.0
_MULTI_FINDING_BONUS_STEP = 0.3
_MULTI_FINDING_BONUS_CAP = 1.5


def _score_to_severity(score: float) -> str:
    for threshold, label in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "Info"


def compute_risk(vulnerabilities: list[VulnInput], credential_findings: list[CredentialInput]) -> RiskResult:
    """Combine vulnerability + credential findings into one RiskResult.

    Rubric:
      - Base score = highest CVSS score among all findings (worst-case drives the headline risk).
      - +0.3 per additional Critical/High finding beyond the first, capped at +1.5 (breadth matters).
      - +2.0 flat if any weak-credential login succeeded (direct unauthorized access is severe
        regardless of the underlying CVSS of the service itself), floor of 7.0 ("High") in that case.
      - Final score capped at 10.0.
    """
    factors: list[str] = []

    if vulnerabilities:
        worst = max(vulnerabilities, key=lambda v: v.cvss_score)
        base_score = worst.cvss_score
        factors.append(f"Base score {base_score:.1f} from worst finding {worst.identifier} ({worst.severity}).")
    else:
        base_score = 0.0
        factors.append("No vulnerabilities identified by CVE/NSE matching.")

    high_or_critical = [v for v in vulnerabilities if v.severity in ("Critical", "High")]
    extra_findings = max(0, len(high_or_critical) - 1)
    breadth_bonus = min(_MULTI_FINDING_BONUS_CAP, extra_findings * _MULTI_FINDING_BONUS_STEP)
    if breadth_bonus:
        factors.append(
            f"+{breadth_bonus:.1f} because {len(high_or_critical)} High/Critical findings were present "
            "(breadth of exposure)."
        )

    successful_creds = [c for c in credential_findings if c.success]
    credential_bonus = _CREDENTIAL_PENALTY if successful_creds else 0.0
    if successful_creds:
        services = sorted({c.service for c in successful_creds})
        factors.append(
            f"+{_CREDENTIAL_PENALTY:.1f} because {len(successful_creds)} weak credential login(s) "
            f"succeeded on: {', '.join(services)}."
        )

    overall = min(10.0, base_score + breadth_bonus + credential_bonus)
    if successful_creds:
        overall = max(overall, 7.0)
        factors.append("Score floored at 7.0 (High) -- a successful credential compromise is never low-risk.")

    severity_level = _score_to_severity(overall)
    rationale = " ".join(factors) + f" Final overall score: {overall:.1f}/10 ({severity_level})."

    return RiskResult(overall_score=round(overall, 1), severity_level=severity_level, rationale=rationale, contributing_factors=factors)
