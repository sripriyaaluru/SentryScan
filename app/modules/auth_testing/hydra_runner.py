"""Authentication Testing Module: wraps THC-Hydra for weak-credential checks.

This is the most sensitive module in SentryScan. Safeguards:
  1. `require_authorization` gates every call -- same allow-list + ENABLE_LIVE_SCANS flag
     as recon/vuln modules.
  2. Credential lists must be supplied explicitly by the caller (lab-only test accounts).
     This module never downloads or embeds real-world leaked credential lists.
  3. Designed for use strictly against accounts you created in your own lab VMs for testing.

Hydra does not ship a native Windows build; it typically runs under WSL2/Linux. If it isn't
found on PATH, calls raise HydraNotAvailableError with setup guidance instead of failing silently.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass

from app.core.authorization import require_authorization
from app.core.config import get_settings

_RESULT_LINE_RE = re.compile(
    r"\[(?P<port>\d+)\]\[(?P<service>[\w-]+)\]\s+host:\s+(?P<host>\S+)\s+login:\s+(?P<login>\S+)\s+password:\s+(?P<password>.*)"
)


class HydraNotAvailableError(RuntimeError):
    """Raised when the hydra binary cannot be found on PATH (or HYDRA_PATH)."""


@dataclass
class CredentialResult:
    host: str
    port: int
    service: str
    username: str
    password: str
    success: bool = True


def is_hydra_available() -> bool:
    settings = get_settings()
    return shutil.which(settings.hydra_path) is not None


class AuthTester:
    """Weak-credential checker for lab-authorized hosts only."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def test_credentials(
        self,
        target: str,
        service: str,
        usernames: list[str],
        passwords: list[str],
        port: int | None = None,
        timeout: int = 300,
    ) -> list[CredentialResult]:
        """Run Hydra against `target` for `service` (e.g. "ssh", "ftp") using the supplied
        lab-only username/password lists. Returns any successful logins found.
        """
        require_authorization(target)

        if not usernames or not passwords:
            raise ValueError("usernames and passwords must be non-empty lab-only test credential lists.")

        if not is_hydra_available():
            raise HydraNotAvailableError(
                "hydra executable not found. Hydra requires WSL2/Linux on Windows -- run "
                "`wsl --install` then install hydra inside WSL (e.g. `sudo apt install hydra`), "
                "or set HYDRA_PATH in .env to point at it."
            )

        cmd = self._build_command(target, service, usernames, passwords, port)

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return self._parse_output(proc.stdout)

    def _build_command(
        self, target: str, service: str, usernames: list[str], passwords: list[str], port: int | None
    ) -> list[str]:
        cmd = [self.settings.hydra_path]
        cmd += ["-L", _write_list_file(usernames, "users")]
        cmd += ["-p", passwords[0]] if len(passwords) == 1 else ["-P", _write_list_file(passwords, "passwords")]
        if port:
            cmd += ["-s", str(port)]
        cmd += ["-I", "-f", target, service]
        return cmd

    def _parse_output(self, stdout: str) -> list[CredentialResult]:
        results = []
        for line in stdout.splitlines():
            match = _RESULT_LINE_RE.search(line)
            if match:
                results.append(
                    CredentialResult(
                        host=match.group("host"),
                        port=int(match.group("port")),
                        service=match.group("service"),
                        username=match.group("login"),
                        password=match.group("password"),
                    )
                )
        return results


def _write_list_file(items: list[str], prefix: str) -> str:
    import tempfile

    fd = tempfile.NamedTemporaryFile(mode="w", delete=False, prefix=f"sentryscan_{prefix}_", suffix=".txt")
    fd.write("\n".join(items))
    fd.close()
    return fd.name
