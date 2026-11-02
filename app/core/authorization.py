"""Authorization guard: the single safety gate every scanning/testing module must pass through.

SentryScan is built for *authorized* lab/testing environments only (per project synopsis).
No module may execute a live Nmap scan or Hydra credential test without first passing this
check. This module intentionally fails closed: anything ambiguous is rejected.
"""
from __future__ import annotations

import ipaddress
import logging
import socket

from app.core.config import get_settings

logger = logging.getLogger("sentryscan.authorization")


class UnauthorizedTargetError(Exception):
    """Raised when a target is not on the authorized allow-list, or live scans are disabled."""


def _resolve_to_ips(target: str) -> list[str]:
    """Resolve a hostname to IP address(es). Falls back to the literal string on failure."""
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(target, None)
        return sorted({info[4][0] for info in infos})
    except socket.gaierror:
        return []


def _matches_allowlist_entry(ip: str, entry: str) -> bool:
    entry = entry.strip()
    if entry.lower() == "localhost":
        entry = "127.0.0.1"
    try:
        if "/" in entry:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(entry, strict=False)
        return ipaddress.ip_address(ip) == ipaddress.ip_address(entry)
    except ValueError:
        # Non-IP allow-list entries (plain hostnames) are compared case-insensitively.
        return ip.lower() == entry.lower()


def is_target_authorized(target: str) -> bool:
    """Return True only if *every* resolved IP for `target` is covered by the allow-list."""
    settings = get_settings()
    allowlist = settings.authorized_targets_list
    if not allowlist:
        return False

    if target.strip().lower() == "localhost":
        return any(_matches_allowlist_entry("127.0.0.1", e) for e in allowlist) or "localhost" in [
            e.lower() for e in allowlist
        ]

    resolved_ips = _resolve_to_ips(target)
    if not resolved_ips:
        # Could not resolve -> fail closed, cannot verify safety.
        return False

    return all(any(_matches_allowlist_entry(ip, entry) for entry in allowlist) for ip in resolved_ips)


def require_authorization(target: str) -> None:
    """Raise UnauthorizedTargetError unless `target` is authorized AND live scans are enabled.

    Call this at the top of every function that shells out to nmap/hydra against a target.
    Every decision (allowed or blocked) is logged for audit purposes.
    """
    settings = get_settings()
    if not settings.enable_live_scans:
        logger.warning("BLOCKED action against '%s': live scans are globally disabled.", target)
        raise UnauthorizedTargetError(
            "Live scans are disabled (ENABLE_LIVE_SCANS=false). Set it to true only inside an "
            "isolated lab environment you fully control and are authorized to test."
        )
    if not is_target_authorized(target):
        logger.warning("BLOCKED action against '%s': not on the AUTHORIZED_TARGETS allow-list.", target)
        raise UnauthorizedTargetError(
            f"Target '{target}' is not on the AUTHORIZED_TARGETS allow-list. "
            "Add it explicitly in .env before scanning. Never scan systems you do not own or "
            "have explicit written authorization to test."
        )
    logger.info("Authorized action proceeding against target: %s", target)
