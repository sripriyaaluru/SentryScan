"""Network Reconnaissance endpoints."""
from __future__ import annotations

import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.authorization import UnauthorizedTargetError
from app.db.models import Host, Port, ScanJob, ScanJobStatus, ScanJobType, Target
from app.modules.recon.scanner import NmapNotAvailableError, ReconScanner, get_nmap_version, is_nmap_available
from app.schemas.schemas import ReconRequest, ScanJobOut

router = APIRouter(prefix="/recon", tags=["recon"])


@router.get("/status")
def recon_status() -> dict:
    """Report whether the nmap binary is installed and on PATH (or NMAP_PATH), plus its version."""
    return {"nmap_available": is_nmap_available(), "nmap_version": get_nmap_version()}


@router.post("/scan", response_model=ScanJobOut)
def run_recon_scan(payload: ReconRequest, db: Session = Depends(get_db)) -> ScanJob:
    """Run an Nmap scan against a target's host and persist discovered hosts/ports.

    Returns 403 if the target is not on the allow-list or live scans are disabled, 503 if
    nmap isn't installed, or 500 for any other scan failure -- the ScanJob row is updated
    to BLOCKED/FAILED/COMPLETED accordingly in every case.
    """
    target = db.get(Target, payload.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    job = ScanJob(target_id=target.id, job_type=ScanJobType.RECON, status=ScanJobStatus.RUNNING)
    job.started_at = datetime.datetime.now(datetime.timezone.utc)
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        scanner = ReconScanner()
        host_results = scanner.scan(target.host, arguments=payload.arguments)

        for hr in host_results:
            host = Host(scan_job_id=job.id, ip_address=hr.ip_address, hostname=hr.hostname, os_guess=hr.os_guess, status=hr.status)
            db.add(host)
            db.flush()  # assign host.id
            for svc in hr.ports:
                db.add(
                    Port(
                        host_id=host.id,
                        port_number=svc.port,
                        protocol=svc.protocol,
                        state=svc.state,
                        service_name=svc.service_name,
                        service_product=svc.product,
                        service_version=svc.version,
                        banner=svc.banner,
                    )
                )

        job.status = ScanJobStatus.COMPLETED
        job.completed_at = datetime.datetime.now(datetime.timezone.utc)
        db.commit()
        db.refresh(job)
        return job

    except UnauthorizedTargetError as exc:
        job.status = ScanJobStatus.BLOCKED
        job.error_message = str(exc)
        db.commit()
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except NmapNotAvailableError as exc:
        job.status = ScanJobStatus.FAILED
        job.error_message = str(exc)
        db.commit()
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - surface any scan failure on the job record
        job.status = ScanJobStatus.FAILED
        job.error_message = str(exc)
        db.commit()
        raise HTTPException(status_code=500, detail=f"Recon scan failed: {exc}") from exc
