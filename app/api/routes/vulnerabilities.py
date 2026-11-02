"""Vulnerability Assessment endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.authorization import UnauthorizedTargetError
from app.db.models import Host, Port, ScanJob, Severity, Vulnerability
from app.modules.vuln_assessment.cve_matcher import match_cves
from app.modules.vuln_assessment.nse_runner import NseFinding, run_vuln_scripts
from app.schemas.schemas import VulnAssessmentRequest, VulnerabilityOut

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.post("/assess", response_model=list[VulnerabilityOut])
def assess_vulnerabilities(payload: VulnAssessmentRequest, db: Session = Depends(get_db)) -> list[Vulnerability]:
    """Match every discovered port's service/version against the offline CVE dataset, and
    optionally also run Nmap NSE vulnerability-category scripts, persisting all findings."""
    job = db.get(ScanJob, payload.scan_job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    hosts = db.query(Host).filter(Host.scan_job_id == job.id).all()
    created: list[Vulnerability] = []

    for host in hosts:
        for port in host.ports:
            for match in match_cves(db, port.service_product or port.service_name, port.service_version):
                vuln = Vulnerability(
                    port_id=port.id,
                    cve_id=None if match.cve_id.startswith("SENTRYSCAN-RULE") else match.cve_id,
                    source="cve-match",
                    title=match.title,
                    description=match.description,
                    cvss_score=match.cvss_score,
                    severity=Severity(match.severity),
                )
                db.add(vuln)
                created.append(vuln)

        if payload.run_nse_scripts:
            try:
                nse_findings: list[NseFinding] = run_vuln_scripts(host.ip_address)
            except UnauthorizedTargetError as exc:
                raise HTTPException(status_code=403, detail=str(exc)) from exc
            for finding in nse_findings:
                port = next((p for p in host.ports if p.port_number == finding.port), None)
                if port is None:
                    continue
                vuln = Vulnerability(
                    port_id=port.id,
                    cve_id=None,
                    source="nse-script",
                    title=f"NSE: {finding.script_id}",
                    description=finding.output,
                    cvss_score=None,
                    severity=Severity.MEDIUM,
                )
                db.add(vuln)
                created.append(vuln)

    db.commit()
    for v in created:
        db.refresh(v)
    return created
