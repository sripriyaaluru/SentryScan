"""Report generation + download endpoints."""
from __future__ import annotations

import csv
import datetime
import io

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db.models import CredentialFinding, Host, Port, Report, RiskScore, ScanJob, Target, Vulnerability
from app.modules.reporting.report_generator import (
    ReportCredentialFinding,
    ReportData,
    ReportFinding,
    build_recommendations,
    save_html_report,
    save_pdf_report,
)
from app.schemas.schemas import ReportOut, ReportRequest

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/generate", response_model=ReportOut)
def generate_report(payload: ReportRequest, db: Session = Depends(get_db)) -> Report:
    """Build an HTML or PDF report for a scan job from its findings + latest risk score and
    save it to disk (PDF requires WeasyPrint's native Pango/Cairo libraries to be installed)."""
    job = db.get(ScanJob, payload.scan_job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    target = db.get(Target, job.target_id)

    vulns = (
        db.query(Vulnerability, Port, Host)
        .join(Port, Vulnerability.port_id == Port.id)
        .join(Host, Port.host_id == Host.id)
        .filter(Host.scan_job_id == job.id)
        .all()
    )
    creds = db.query(CredentialFinding, Host).join(Host, CredentialFinding.host_id == Host.id).filter(
        CredentialFinding.scan_job_id == job.id
    ).all()
    latest_risk = (
        db.query(RiskScore).filter(RiskScore.scan_job_id == job.id).order_by(RiskScore.computed_at.desc()).first()
    )

    findings = [
        ReportFinding(
            identifier=v.cve_id or v.title,
            title=v.title,
            description=v.description,
            cvss_score=v.cvss_score,
            severity=v.severity.value,
            host=h.ip_address,
            port=p.port_number,
        )
        for v, p, h in vulns
    ]
    credential_findings = [
        ReportCredentialFinding(host=h.ip_address, service=c.service, port=c.port, username=c.username, password=c.password)
        for c, h in creds
    ]

    report_data = ReportData(
        target_name=target.name if target else "Unknown",
        target_host=target.host if target else "Unknown",
        scan_job_id=job.id,
        generated_at=datetime.datetime.now(datetime.timezone.utc),
        findings=findings,
        credential_findings=credential_findings,
        overall_score=latest_risk.overall_score if latest_risk else 0.0,
        severity_level=latest_risk.severity_level.value if latest_risk else "Info",
        rationale=latest_risk.rationale if latest_risk else "Risk has not been computed yet for this scan job.",
    )
    report_data.recommendations = build_recommendations(findings, credential_findings)

    if payload.format == "pdf":
        try:
            path = save_pdf_report(report_data)
        except ImportError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
    else:
        path = save_html_report(report_data)

    report = Report(scan_job_id=job.id, format=payload.format, file_path=str(path))
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@router.get("/{report_id}/download")
def download_report(report_id: int, db: Session = Depends(get_db)) -> FileResponse:
    """Download a previously generated report file (HTML or PDF) by its report id."""
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    media_type = "application/pdf" if report.format == "pdf" else "text/html"
    return FileResponse(report.file_path, media_type=media_type, filename=f"sentryscan_report_{report.id}.{report.format}")


@router.get("/{scan_job_id}/export.csv")
def export_findings_csv(scan_job_id: int, db: Session = Depends(get_db)) -> StreamingResponse:
    """Export every vulnerability + credential finding for a scan job as a single CSV file --
    handy for spreadsheets/tickets without needing the full HTML/PDF report."""
    job = db.get(ScanJob, scan_job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    vulns = (
        db.query(Vulnerability, Port, Host)
        .join(Port, Vulnerability.port_id == Port.id)
        .join(Host, Port.host_id == Host.id)
        .filter(Host.scan_job_id == scan_job_id)
        .all()
    )
    creds = (
        db.query(CredentialFinding, Host)
        .join(Host, CredentialFinding.host_id == Host.id)
        .filter(CredentialFinding.scan_job_id == scan_job_id)
        .all()
    )

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["type", "host", "port", "identifier", "severity", "cvss_score", "username", "password", "description"])
    for v, p, h in vulns:
        writer.writerow(
            ["vulnerability", h.ip_address, p.port_number, v.cve_id or v.title, v.severity.value, v.cvss_score or "", "", "", v.description]
        )
    for c, h in creds:
        writer.writerow(
            ["credential", h.ip_address, c.port, c.service, "", "", c.username, c.password, "login succeeded" if c.success else "login failed"]
        )

    filename = f"sentryscan_findings_{scan_job_id}.csv"
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
