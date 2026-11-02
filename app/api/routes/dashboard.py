"""Dashboard (HTML) routes -- the human-facing view described in the synopsis's
"Dashboard and Report Generation Module".
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.authorization import is_target_authorized
from app.db.models import CredentialFinding, Host, Report, RiskScore, ScanJob, Target, Vulnerability

router = APIRouter(tags=["dashboard"])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[2] / "templates"))


@router.get("/")
def dashboard(request: Request, db: Session = Depends(get_db)):
    """Render the main dashboard: every target with its live authorization status and the
    most recent scan job + risk score, if any."""
    targets = db.query(Target).order_by(Target.created_at.desc()).all()
    target_rows = []
    for t in targets:
        latest_job = db.query(ScanJob).filter(ScanJob.target_id == t.id).order_by(ScanJob.created_at.desc()).first()
        latest_risk = None
        if latest_job:
            latest_risk = (
                db.query(RiskScore)
                .filter(RiskScore.scan_job_id == latest_job.id)
                .order_by(RiskScore.computed_at.desc())
                .first()
            )
        target_rows.append(
            {
                "target": t,
                "authorized": is_target_authorized(t.host),
                "latest_job": latest_job,
                "latest_risk": latest_risk,
            }
        )
    return templates.TemplateResponse("dashboard.html", {"request": request, "target_rows": target_rows})


@router.get("/targets/{target_id}/view")
def target_detail(request: Request, target_id: int, db: Session = Depends(get_db)):
    """Render the full detail page for one target: scan history, discovered hosts,
    vulnerabilities, credential findings, risk scores, and generated reports."""
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    jobs = db.query(ScanJob).filter(ScanJob.target_id == target_id).order_by(ScanJob.created_at.desc()).all()
    job_ids = [j.id for j in jobs]

    hosts = db.query(Host).filter(Host.scan_job_id.in_(job_ids)).all() if job_ids else []
    host_ids = [h.id for h in hosts]

    vulns = (
        db.query(Vulnerability)
        .join(Vulnerability.port)
        .filter(Vulnerability.port.has(Host.id.in_(host_ids)))
        .all()
        if host_ids
        else []
    )
    creds = db.query(CredentialFinding).filter(CredentialFinding.host_id.in_(host_ids)).all() if host_ids else []
    risk_scores = db.query(RiskScore).filter(RiskScore.scan_job_id.in_(job_ids)).all() if job_ids else []
    reports = db.query(Report).filter(Report.scan_job_id.in_(job_ids)).all() if job_ids else []

    return templates.TemplateResponse(
        "target_detail.html",
        {
            "request": request,
            "target": target,
            "authorized": is_target_authorized(target.host),
            "jobs": jobs,
            "hosts": hosts,
            "vulnerabilities": vulns,
            "credential_findings": creds,
            "risk_scores": risk_scores,
            "reports": reports,
        },
    )
