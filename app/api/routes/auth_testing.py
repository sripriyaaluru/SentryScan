"""Authentication Testing endpoints (Hydra-backed weak-credential checks)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.authorization import UnauthorizedTargetError
from app.db.models import CredentialFinding, Host, ScanJob, Target
from app.modules.auth_testing.hydra_runner import AuthTester, HydraNotAvailableError
from app.schemas.schemas import AuthTestRequest, CredentialFindingOut

router = APIRouter(prefix="/auth-testing", tags=["auth-testing"])


@router.get("/status")
def auth_testing_status() -> dict:
    """Report whether the hydra binary is installed and on PATH (or HYDRA_PATH)."""
    from app.modules.auth_testing.hydra_runner import is_hydra_available

    return {"hydra_available": is_hydra_available()}


@router.post("/test", response_model=list[CredentialFindingOut])
def run_auth_test(payload: AuthTestRequest, db: Session = Depends(get_db)) -> list[CredentialFinding]:
    """Run a lab-only weak-credential check (Hydra) against a target's already-recorded host
    for one service, using caller-supplied username/password lists. Returns only the logins
    that succeeded."""
    target = db.get(Target, payload.target_id)
    job = db.get(ScanJob, payload.scan_job_id)
    if not target or not job:
        raise HTTPException(status_code=404, detail="Target or scan job not found")

    host = db.query(Host).filter(Host.scan_job_id == job.id).first()
    if not host:
        raise HTTPException(status_code=400, detail="No host recorded for this scan job yet -- run recon first.")

    try:
        tester = AuthTester()
        results = tester.test_credentials(
            target.host, payload.service, payload.usernames, payload.passwords, port=payload.port
        )
    except UnauthorizedTargetError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except HydraNotAvailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    findings = []
    for r in results:
        cf = CredentialFinding(
            scan_job_id=job.id, host_id=host.id, service=r.service, port=r.port,
            username=r.username, password=r.password, success=r.success,
        )
        db.add(cf)
        findings.append(cf)
    db.commit()
    for f in findings:
        db.refresh(f)
    return findings
