"""Network Reconnaissance Module.

Wraps Nmap to perform host discovery, port scanning, and service/version detection.
Every call that touches the network goes through `require_authorization` first -- this
module will refuse to run against anything not on the AUTHORIZED_TARGETS allow-list,
and refuses entirely unless ENABLE_LIVE_SCANS=true.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field

from app.core.authorization import require_authorization
from app.core.config import get_settings

try:
    import nmap  # python-nmap
except ImportError:  # pragma: no cover - optional until requirements are installed
    nmap = None


@dataclass
class ServiceInfo:
    port: int
    protocol: str
    state: str
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None


@dataclass
class HostResult:
    ip_address: str
    hostname: str | None
    status: str
    os_guess: str | None = None
    ports: list[ServiceInfo] = field(default_factory=list)


class NmapNotAvailableError(RuntimeError):
    """Raised when the nmap binary cannot be found on PATH (or NMAP_PATH)."""


def is_nmap_available() -> bool:
    settings = get_settings()
    return shutil.which(settings.nmap_path) is not None


def get_nmap_version() -> str | None:
    settings = get_settings()
    path = shutil.which(settings.nmap_path)
    if not path:
        return None
    try:
        out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10, check=False)
        return out.stdout.splitlines()[0] if out.stdout else None
    except (subprocess.SubprocessError, OSError):
        return None


class ReconScanner:
    """Host/port/service discovery wrapper around Nmap."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._scanner = None
        # Only construct python-nmap's PortScanner when the binary is actually resolvable.
        # PortScanner() validates the binary eagerly (via subprocess) and raises a raw,
        # library-specific PortScannerError if it can't -- we want that case to surface
        # later as our own clean NmapNotAvailableError instead (see scan() below), and we
        # don't want a missing binary to blow up object construction before
        # require_authorization() even gets a chance to run.
        if nmap is not None and is_nmap_available():
            try:
                self._scanner = nmap.PortScanner(nmap_search_path=(self.settings.nmap_path,))
            except Exception:  # noqa: BLE001 - any construction failure just means "unavailable"
                self._scanner = None

    def scan(self, target: str, arguments: str = "-sV -T4") -> list[HostResult]:
        """Run an Nmap scan against `target` and return structured results.

        Raises UnauthorizedTargetError if the target isn't authorized or live scans are
        disabled. Raises NmapNotAvailableError if the nmap binary isn't installed.
        """
        require_authorization(target)

        if not is_nmap_available() or self._scanner is None:
            raise NmapNotAvailableError(
                "nmap executable not found. Install it (e.g. `winget install Insecure.Nmap`) "
                "or set NMAP_PATH in .env."
            )

        self._scanner.scan(hosts=target, arguments=arguments)
        return [self._parse_host(host) for host in self._scanner.all_hosts()]

    def _parse_host(self, ip: str) -> HostResult:
        data = self._scanner[ip]
        hostnames = data.hostnames() if hasattr(data, "hostnames") else []
        hostname = hostnames[0]["name"] if hostnames else None
        os_guess = None
        if "osmatch" in data and data["osmatch"]:
            os_guess = data["osmatch"][0].get("name")

        result = HostResult(ip_address=ip, hostname=hostname, status=data.state(), os_guess=os_guess)

        for proto in data.all_protocols():
            for port_num, port_data in data[proto].items():
                result.ports.append(
                    ServiceInfo(
                        port=int(port_num),
                        protocol=proto,
                        state=port_data.get("state", "unknown"),
                        service_name=port_data.get("name") or None,
                        product=port_data.get("product") or None,
                        version=port_data.get("version") or None,
                        banner=(f"{port_data.get('product', '')} {port_data.get('version', '')}".strip() or None),
                    )
                )
        return result
