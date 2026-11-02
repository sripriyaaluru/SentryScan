"""Wraps Nmap's vulnerability-focused NSE scripts (the `vuln` script category) as a
secondary vulnerability-detection source alongside CVE/version matching.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.core.authorization import require_authorization
from app.modules.recon.scanner import NmapNotAvailableError, is_nmap_available

try:
    import nmap
except ImportError:  # pragma: no cover
    nmap = None


@dataclass
class NseFinding:
    host: str
    port: int | None
    script_id: str
    output: str


def run_vuln_scripts(target: str, ports: str | None = None) -> list[NseFinding]:
    """Run Nmap's `vuln` NSE script category against `target`.

    Requires authorization (same gate as the recon scanner) and the nmap binary.
    """
    require_authorization(target)

    if not is_nmap_available() or nmap is None:
        raise NmapNotAvailableError(
            "nmap executable not found. Install it or set NMAP_PATH in .env."
        )

    scanner = nmap.PortScanner()
    args = "--script vuln"
    if ports:
        args += f" -p {ports}"
    scanner.scan(hosts=target, arguments=args)

    findings: list[NseFinding] = []
    for host in scanner.all_hosts():
        host_data = scanner[host]
        for proto in host_data.all_protocols():
            for port_num, port_data in host_data[proto].items():
                for script_id, output in port_data.get("script", {}).items():
                    findings.append(NseFinding(host=host, port=int(port_num), script_id=script_id, output=output))
    return findings
