"""SentryScan FastAPI application entrypoint.

Wires together all five modules described in the project synopsis:
  1. Network Reconnaissance       -> app/api/routes/recon.py
  2. Vulnerability Assessment     -> app/api/routes/vulnerabilities.py
  3. Authentication Testing       -> app/api/routes/auth_testing.py
  4. Risk Analysis                -> app/api/routes/risk.py
  5. Dashboard + Report Generation -> app/api/routes/dashboard.py, app/api/routes/reports.py
"""
from __future__ import annotations

import logging
import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import auth_testing, dashboard, recon, reports, risk, targets, vulnerabilities
from app.core.authorization import UnauthorizedTargetError
from app.core.config import get_settings
from app.modules.auth_testing.hydra_runner import HydraNotAvailableError
from app.modules.recon.scanner import NmapNotAvailableError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentryscan")

settings = get_settings()

app = FastAPI(
    title="SentryScan",
    description=(
        "Automated Network Penetration Testing and Vulnerability Assessment Platform. "
        "FOR USE ONLY AGAINST SYSTEMS YOU OWN OR ARE EXPLICITLY AUTHORIZED TO TEST, in a "
        "controlled lab environment."
    ),
    version="0.1.0",
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Audit-log every request (method, path, status, duration) -- a pentest tool should
    always leave a clear trail of what was run and when, independent of DB-level records."""
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - start) * 1000
    logger.info("%s %s -> %d (%.1fms)", request.method, request.url.path, response.status_code, duration_ms)
    return response


@app.exception_handler(UnauthorizedTargetError)
async def unauthorized_target_handler(request: Request, exc: UnauthorizedTargetError) -> JSONResponse:
    """Fallback safety net: any UnauthorizedTargetError not already caught locally by a route
    still returns a clean 403 instead of leaking a raw 500."""
    return JSONResponse(status_code=403, content={"detail": str(exc)})


@app.exception_handler(NmapNotAvailableError)
async def nmap_unavailable_handler(request: Request, exc: NmapNotAvailableError) -> JSONResponse:
    return JSONResponse(status_code=503, content={"detail": str(exc)})


@app.exception_handler(HydraNotAvailableError)
async def hydra_unavailable_handler(request: Request, exc: HydraNotAvailableError) -> JSONResponse:
    return JSONResponse(status_code=503, content={"detail": str(exc)})


STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

app.include_router(dashboard.router)
app.include_router(targets.router, prefix="/api")
app.include_router(recon.router, prefix="/api")
app.include_router(vulnerabilities.router, prefix="/api")
app.include_router(auth_testing.router, prefix="/api")
app.include_router(risk.router, prefix="/api")
app.include_router(reports.router, prefix="/api")


@app.get("/health")
def health() -> dict:
    """Liveness/readiness probe: confirms the app is up and reports whether live scans
    (the global safety switch) are currently enabled."""
    return {"status": "ok", "env": settings.app_env, "live_scans_enabled": settings.enable_live_scans}
