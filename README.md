## Modules

| # | Module | What it does | Code |
|---|--------|---------------|------|
| 1 | Network Reconnaissance | Runs Nmap to discover live hosts, open ports, and service/version banners | `app/modules/recon/` |
| 2 | Vulnerability Assessment | Matches detected service/version against a curated offline CVE dataset + optional Nmap `--script vuln` NSE scripts | `app/modules/vuln_assessment/` |
| 3 | Authentication Testing | Runs Hydra against discovered services using caller-supplied lab-only credential lists | `app/modules/auth_testing/` |
| 4 | Risk Analysis | Combines CVSS scores + credential-compromise findings into one aggregate risk score/severity via a rule-based rubric | `app/modules/risk_analysis/` |
| 5 | Dashboard & Reporting | Web dashboard (FastAPI + Jinja2) to drive scans, plus HTML/PDF/CSV report export | `app/api/routes/dashboard.py`, `app/modules/reporting/` |

## Tech stack

Python 3.12 · FastAPI · SQLAlchemy 2.0 · PostgreSQL · Jinja2 · python-nmap · WeasyPrint (PDF) · pytest

## Prerequisites

| Component | Required? | Notes |
|---|---|---|
| Python 3.10+ (3.12 recommended) | Yes | Runtime |
| PostgreSQL | Yes | Storage backend; a `sentryscan` database is created for you |
| Nmap | Yes | Recon + vulnerability-assessment module |
| Hydra | Optional | Authentication Testing module only; no native Windows build (needs WSL2) — **installs natively via `apt` on Ubuntu/WSL** |
| WeasyPrint native libs (Pango/Cairo) | Optional | Only needed for **PDF** report export; HTML reports work without it. One `apt install` on Ubuntu; a separate GTK3 runtime download on Windows |

> **Recommended workflow:** edit in **VSCode on Windows** with the **WSL** extension
> (`ms-vscode-remote.remote-wsl`), but run/debug/test **inside WSL Ubuntu**. Nmap, Hydra,
> PostgreSQL, and WeasyPrint's native deps are all simpler to install and more fully
> supported on Linux than on native Windows. Open the project with
> `code .` from a WSL terminal in the project folder, or **Ctrl+Shift+P → "WSL: Reopen
> Folder in WSL"** from VSCode — the integrated terminal, Python interpreter, and
> debugger will then all run inside Ubuntu automatically.

### Automated setup (WSL Ubuntu / native Ubuntu or Debian)

From a WSL Ubuntu (or native Ubuntu/Debian) terminal, in the project root:

```bash
chmod +x scripts/setup_wsl.sh
./scripts/setup_wsl.sh
```

This installs Python/Nmap/PostgreSQL/Hydra/WeasyPrint's native libs via `apt` (skips
anything already present), creates the `sentryscan` database, sets up a `.venv`, installs
`requirements.txt`, and writes a `.env` file. Set `DB_PASSWORD=...`, `SKIP_POSTGRES=1`,
`SKIP_NMAP=1`, or `SKIP_HYDRA=1` as environment variables to customize. If you don't have
WSL installed yet on Windows, run (from an **elevated/Administrator** PowerShell, then
**reboot**): `wsl --install -d Ubuntu`.

### Automated setup (Windows, native — no WSL)

From an **Administrator PowerShell**, in the project root:

```powershell
.\scripts\setup_windows.ps1
```

This installs Python/Nmap/PostgreSQL via `winget` (skips anything already present), creates
the `sentryscan` database, sets up a `.venv`, installs `requirements.txt`, and writes a `.env`
file. Pass `-InstallHydraViaWSL` to also set up Hydra via WSL2 (requires a reboot the first
time). See `Get-Help .\scripts\setup_windows.ps1 -Full` for all parameters.

### Manual setup

**WSL Ubuntu / Linux (bash):**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # then edit DATABASE_URL / AUTHORIZED_TARGETS as needed
python scripts/init_db.py          # creates all tables
python scripts/seed_cve_data.py    # loads the offline CVE dataset
uvicorn app.main:app --reload
```

**Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env        # then edit DATABASE_URL / AUTHORIZED_TARGETS as needed
python scripts\init_db.py          # creates all tables
python scripts\seed_cve_data.py    # loads the offline CVE dataset
uvicorn app.main:app --reload
```

Then open **http://127.0.0.1:8000** for the dashboard, or **http://127.0.0.1:8000/health**
for a liveness check. (WSL2 automatically forwards `localhost` ports to Windows, so a
server started inside Ubuntu is reachable from a Windows browser with no extra config.)

## Running tests

```bash
# WSL Ubuntu / Linux
source .venv/bin/activate && pytest
```

```powershell
# Windows
.\.venv\Scripts\Activate.ps1; pytest
```

26 tests total: pure-function/unit-level tests (risk scoring rubric, offline CVE matching,
and the authorization guard) plus HTTP-level integration tests (`test_api_integration.py`,
using an in-memory SQLite DB via FastAPI's `TestClient` — exercises the real routing layer:
target CRUD, 404s, the recon-scan-blocked-403 path, and the generated OpenAPI schema). No
live network calls, no real Postgres, no real scans — fully offline and safe to run anywhere.

## Safety model

Every function that shells out to `nmap` or `hydra` calls
`app.core.authorization.require_authorization(target)` first, which enforces **two**
independent conditions:

1. `ENABLE_LIVE_SCANS=true` in `.env` (defaults to `false`).
2. The target's resolved IP address(es) match an entry in `AUTHORIZED_TARGETS` (a
   comma-separated list of exact IPs, CIDR ranges, or hostnames — defaults to loopback +
   RFC1918 private ranges).

Hostnames that fail to resolve, or targets outside the allow-list, are rejected
(**fails closed**). This project currently ships with **no live scans performed** — enabling
them is an explicit, deliberate opt-in step for use only in an isolated lab you control.

**Audit trail:** every HTTP request (method, path, status code, duration) is logged via a
request-logging middleware in `app/main.py`, and every authorization decision — allowed or
blocked, and why — is logged by `app/core/authorization.py`. A pentest tool should always
leave a clear record of what was run, against what, and when. Additionally, three global
FastAPI exception handlers in `main.py` guarantee that even an *uncaught*
`UnauthorizedTargetError` / `NmapNotAvailableError` / `HydraNotAvailableError` anywhere in the
app still returns a clean 403/503 JSON response instead of a raw 500 — defense-in-depth on
top of the per-route error handling that already existed.

> **Linux/WSL note:** some Nmap scan types (e.g. SYN scans, OS detection) need raw-socket
> privileges. Either run the app with `sudo`, or grant the capability once with
> `sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f .venv/bin/python)` (or on the
> `nmap` binary itself) so the app doesn't need to run as root. Not required for the
> default `-sV -T4` TCP-connect scan used by this project, and irrelevant until
> `ENABLE_LIVE_SCANS=true`.

## Project layout

```
app/
  core/          settings + the authorization guard
  db/            SQLAlchemy engine/session + ORM models
  modules/       the 5 modules listed above (recon, vuln_assessment, auth_testing,
                 risk_analysis, reporting)
  api/routes/    FastAPI routers (REST endpoints + dashboard HTML views)
  schemas/       Pydantic request/response models
  templates/     Jinja2 templates (dashboard, target detail, PDF/HTML report)
  static/        CSS + dashboard JS
scripts/         init_db.py, seed_cve_data.py, setup_windows.ps1, setup_wsl.sh
tests/           unit + integration tests (risk engine, CVE matcher, authorization, API)
reports/         generated HTML/PDF reports land here
```
