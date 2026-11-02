"""ORM models for SentryScan.

Schema overview
---------------
Target          -> a system authorized for testing (host/IP + metadata)
ScanJob         -> one run of a module (recon / vuln / auth / full) against a Target
Host            -> a live host discovered during a ScanJob (a Target may resolve to 1+ Host)
Port            -> an open port + detected service on a Host
Vulnerability   -> a CVE match or NSE-script finding tied to a Port (or Host-level)
CredentialFinding -> a weak-credential result from the Authentication Testing module
CveRecord       -> offline curated CVE dataset used for version-based matching
RiskScore       -> CVSS + rule-based aggregate risk for a ScanJob or Host
Report          -> a generated report artifact (HTML/PDF) for a ScanJob
"""
from __future__ import annotations

import datetime
import enum

from sqlalchemy import DateTime, Enum, Float, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class ScanJobType(str, enum.Enum):
    RECON = "recon"
    VULN_ASSESSMENT = "vuln_assessment"
    AUTH_TESTING = "auth_testing"
    FULL = "full"


class ScanJobStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"  # rejected by the authorization guard


class Severity(str, enum.Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    host: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan_jobs: Mapped[list["ScanJob"]] = relationship(back_populates="target", cascade="all, delete-orphan")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    job_type: Mapped[ScanJobType] = mapped_column(Enum(ScanJobType))
    status: Mapped[ScanJobStatus] = mapped_column(Enum(ScanJobStatus), default=ScanJobStatus.PENDING)
    raw_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    target: Mapped["Target"] = relationship(back_populates="scan_jobs")
    hosts: Mapped[list["Host"]] = relationship(back_populates="scan_job", cascade="all, delete-orphan")
    credential_findings: Mapped[list["CredentialFinding"]] = relationship(
        back_populates="scan_job", cascade="all, delete-orphan"
    )
    risk_scores: Mapped[list["RiskScore"]] = relationship(back_populates="scan_job", cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship(back_populates="scan_job", cascade="all, delete-orphan")


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"))
    ip_address: Mapped[str] = mapped_column(String(64))
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_guess: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="up")

    scan_job: Mapped["ScanJob"] = relationship(back_populates="hosts")
    ports: Mapped[list["Port"]] = relationship(back_populates="host", cascade="all, delete-orphan")
    credential_findings: Mapped[list["CredentialFinding"]] = relationship(back_populates="host")


class Port(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"))
    port_number: Mapped[int] = mapped_column()
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    state: Mapped[str] = mapped_column(String(32), default="open")
    service_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    service_product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    service_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)

    host: Mapped["Host"] = relationship(back_populates="ports")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="port", cascade="all, delete-orphan")


class CveRecord(Base):
    """Offline curated CVE dataset entry used for service/version matching."""

    __tablename__ = "cve_records"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    product: Mapped[str] = mapped_column(String(255), index=True)
    affected_version: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text)
    cvss_score: Mapped[float] = mapped_column(Float)
    severity: Mapped[Severity] = mapped_column(Enum(Severity))
    reference_url: Mapped[str | None] = mapped_column(String(512), nullable=True)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(primary_key=True)
    port_id: Mapped[int] = mapped_column(ForeignKey("ports.id"))
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source: Mapped[str] = mapped_column(String(32))  # "cve-match" | "nse-script"
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity))

    port: Mapped["Port"] = relationship(back_populates="vulnerabilities")


class CredentialFinding(Base):
    """Result of the Authentication Testing module (Hydra) against a lab-authorized host."""

    __tablename__ = "credential_findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"))
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"))
    service: Mapped[str] = mapped_column(String(64))  # ssh, ftp, http-post-form, etc.
    port: Mapped[int] = mapped_column()
    username: Mapped[str] = mapped_column(String(255))
    password: Mapped[str] = mapped_column(String(255))
    success: Mapped[bool] = mapped_column(default=False)
    tested_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan_job: Mapped["ScanJob"] = relationship(back_populates="credential_findings")
    host: Mapped["Host"] = relationship(back_populates="credential_findings")


class RiskScore(Base):
    __tablename__ = "risk_scores"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"))
    overall_score: Mapped[float] = mapped_column(Float)
    severity_level: Mapped[Severity] = mapped_column(Enum(Severity))
    rationale: Mapped[str] = mapped_column(Text)
    computed_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan_job: Mapped["ScanJob"] = relationship(back_populates="risk_scores")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"))
    format: Mapped[str] = mapped_column(String(16))  # "html" | "pdf"
    file_path: Mapped[str] = mapped_column(String(512))
    generated_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan_job: Mapped["ScanJob"] = relationship(back_populates="reports")
