"""Pydantic request/response schemas for the API layer."""
from __future__ import annotations

import datetime

from pydantic import BaseModel, ConfigDict, Field


class TargetCreate(BaseModel):
    name: str
    host: str = Field(description="IP address or hostname; must be on the AUTHORIZED_TARGETS allow-list to scan.")
    description: str | None = None


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    host: str
    description: str | None
    created_at: datetime.datetime
    is_authorized: bool = Field(
        default=False, description="Computed live against AUTHORIZED_TARGETS; granting no permission by itself."
    )


class ScanJobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    target_id: int
    job_type: str
    status: str
    error_message: str | None = None
    started_at: datetime.datetime | None = None
    completed_at: datetime.datetime | None = None
    created_at: datetime.datetime


class ReconRequest(BaseModel):
    target_id: int
    arguments: str = Field(
        default="-sV -T4", description="Raw Nmap argument string (default: service/version detection, aggressive timing)."
    )


class PortOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    port_number: int
    protocol: str
    state: str
    service_name: str | None
    service_product: str | None
    service_version: str | None


class HostOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    ip_address: str
    hostname: str | None
    os_guess: str | None
    status: str
    ports: list[PortOut] = []


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    cve_id: str | None
    source: str
    title: str
    description: str
    cvss_score: float | None
    severity: str


class VulnAssessmentRequest(BaseModel):
    scan_job_id: int
    run_nse_scripts: bool = Field(
        default=False, description="If true, also run Nmap NSE 'vuln'-category scripts against each discovered host (slower)."
    )


class AuthTestRequest(BaseModel):
    target_id: int
    scan_job_id: int
    service: str = Field(description='e.g. "ssh", "ftp", "mysql" -- must match a Hydra module name.')
    usernames: list[str] = Field(description="Lab-only test usernames.")
    passwords: list[str] = Field(description="Lab-only test passwords.")
    port: int | None = None


class CredentialFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    host_id: int
    service: str
    port: int
    username: str
    password: str
    success: bool = Field(description="True if this username/password pair successfully authenticated.")
    tested_at: datetime.datetime


class RiskScoreOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_job_id: int
    overall_score: float
    severity_level: str
    rationale: str = Field(description="Human-readable breakdown of how overall_score was derived.")
    computed_at: datetime.datetime


class ReportRequest(BaseModel):
    scan_job_id: int
    format: str = Field(default="html", pattern="^(html|pdf)$")


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_job_id: int
    format: str
    file_path: str
    generated_at: datetime.datetime
