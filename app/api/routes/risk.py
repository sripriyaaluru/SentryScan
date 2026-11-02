"""Risk Analysis endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db.models import CredentialFinding, Host, Port, RiskScore, ScanJob, Severity, Vulnerability
from app.modules.risk_analysis.risk_engine import CredentialInput, VulnInput, compute_risk
from app.schemas.schemas import RiskScoreOut

router = APIRouter(prefix="/risk", tags=["risk"])


@router.post("/compute/{scan_job_id}", response_model=RiskScoreOut)
def compute_risk_for_job(scan_job_id: int, db: Session = Depends(get_db)) -> RiskScore:
    """Aggregate every vulnerability + credential finding for a scan job into one RiskScore
    (see app.modules.risk_analysis.risk_engine for the scoring rubric) and persist it."""
    job = db.get(ScanJob, scan_job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    vulns = (
        db.query(Vulnerability)
        .join(Port, Vulnerability.port_id == Port.id)
        .join(Host, Port.host_id == Host.id)
        .filter(Host.scan_job_id == scan_job_id)
        .all()
    )
    creds = db.query(CredentialFinding).filter(CredentialFinding.scan_job_id == scan_job_id).all()

    vuln_inputs = [
        VulnInput(identifier=v.cve_id or v.title, cvss_score=v.cvss_score or 0.0, severity=v.severity.value)
        for v in vulns
    ]
    cred_inputs = [
        CredentialInput(host=str(c.host_id), service=c.service, username=c.username, success=c.success)
        for c in creds
    ]

    result = compute_risk(vuln_inputs, cred_inputs)

    risk_score = RiskScore(
        scan_job_id=job.id,
        overall_score=result.overall_score,
        severity_level=Severity(result.severity_level),
        rationale=result.rationale,
    )
    db.add(risk_score)
    db.commit()
    db.refresh(risk_score)
    return risk_score


@router.get("/{scan_job_id}", response_model=list[RiskScoreOut])
def get_risk_scores(scan_job_id: int, db: Session = Depends(get_db)) -> list[RiskScore]:
    """List every previously computed risk score for a scan job, newest first."""
    return db.query(RiskScore).filter(RiskScore.scan_job_id == scan_job_id).order_by(RiskScore.computed_at.desc()).all()
