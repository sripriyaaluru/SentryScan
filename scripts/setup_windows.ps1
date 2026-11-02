<#
.SYNOPSIS
    One-shot, mostly-silent environment setup for SentryScan on a Windows desktop.

.DESCRIPTION
    Installs/verifies everything SentryScan needs to run:
      - Python 3.12            (via winget)
      - Nmap                   (via winget)  -- recon + vulnerability-assessment module
      - PostgreSQL 17          (via winget)  -- storage backend, creates the `sentryscan` DB
      - Python virtual env + pip dependencies from requirements.txt
      - .env file (copied from .env.example if missing)

    Hydra (the Authentication Testing module's engine) has no native Windows build and
    requires WSL2 + a Linux distro. That is NOT installed by default because it needs a
    reboot and a large download. Pass -InstallHydraViaWSL to attempt it.

.PARAMETER DbPassword
    Password to set for the PostgreSQL `postgres` superuser (dev/lab use only).

.PARAMETER InstallHydraViaWSL
    Also enable WSL2 and install Hydra inside it. Requires a reboot if WSL/VM Platform
    Windows features were not already enabled; re-run the script after rebooting.

.PARAMETER SkipPostgres
.PARAMETER SkipNmap
    Skip installing these components (e.g. if already managed separately).

.EXAMPLE
    # Run from an elevated (Administrator) PowerShell prompt, from the project root:
    .\scripts\setup_windows.ps1

.EXAMPLE
    .\scripts\setup_windows.ps1 -InstallHydraViaWSL
#>
[CmdletBinding()]
param(
    [string]$DbPassword = "sentryscan_dev",
    [switch]$InstallHydraViaWSL,
    [switch]$SkipPostgres,
    [switch]$SkipNmap
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    OK: $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "    WARN: $msg" -ForegroundColor Yellow }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warn2 "Not running as Administrator. winget installs (PostgreSQL/Nmap) and WSL setup may fail or prompt via UAC."
}

function Refresh-Path {
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
}

# ---------------------------------------------------------------------------
# 1. Python
# ---------------------------------------------------------------------------
Write-Step "Checking Python 3.12+"
Refresh-Path
$pythonOk = $false
try {
    $verOut = (python --version) 2>&1
    if ($verOut -match "Python 3\.(1[1-9]|[2-9]\d)") { $pythonOk = $true }
} catch { }

if ($pythonOk) {
    Write-Ok (python --version)
} else {
    Write-Host "    Installing Python 3.12 via winget..."
    winget install -e --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements --silent
    Refresh-Path
    Write-Ok (python --version)
}

# ---------------------------------------------------------------------------
# 2. Nmap
# ---------------------------------------------------------------------------
if (-not $SkipNmap) {
    Write-Step "Checking Nmap"
    if (Get-Command nmap -ErrorAction SilentlyContinue) {
        Write-Ok (nmap --version | Select-Object -First 1)
    } else {
        Write-Host "    Installing Nmap via winget (includes Npcap driver)..."
        winget install -e --id Insecure.Nmap --accept-source-agreements --accept-package-agreements --silent
        Refresh-Path
        if (Get-Command nmap -ErrorAction SilentlyContinue) { Write-Ok "Nmap installed" }
        else { Write-Warn2 "Nmap installed but not yet on PATH -- restart your terminal." }
    }
} else {
    Write-Warn2 "Skipping Nmap (per -SkipNmap). Recon + Vulnerability Assessment modules will not run live scans."
}

# ---------------------------------------------------------------------------
# 3. PostgreSQL
# ---------------------------------------------------------------------------
if (-not $SkipPostgres) {
    Write-Step "Checking PostgreSQL 17"
    $pgService = Get-Service -Name "postgresql-x64-17" -ErrorAction SilentlyContinue
    if ($pgService) {
        Write-Ok "PostgreSQL 17 service already installed ($($pgService.Status))"
        if ($pgService.Status -ne "Running") { Start-Service $pgService.Name }
    } else {
        Write-Host "    Installing PostgreSQL 17 via winget (unattended, superuser password set from -DbPassword)..."
        winget install -e --id PostgreSQL.PostgreSQL.17 --accept-source-agreements --accept-package-agreements --silent `
            --override "--mode unattended --unattendedmodeui minimal --superpassword $DbPassword --servicename postgresql-x64-17 --serverport 5432"
        Write-Ok "PostgreSQL 17 installed"
    }

    Write-Step "Ensuring the 'sentryscan' database exists"
    $psql = Get-ChildItem "C:\Program Files\PostgreSQL\*\bin\psql.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
    if (-not $psql) {
        Write-Warn2 "Could not locate psql.exe under C:\Program Files\PostgreSQL\*\bin -- create the 'sentryscan' database manually."
    } else {
        $env:PGPASSWORD = $DbPassword
        $dbExists = & $psql -U postgres -h localhost -tAc "SELECT 1 FROM pg_database WHERE datname='sentryscan'" 2>$null
        if ($dbExists -match "1") {
            Write-Ok "Database 'sentryscan' already exists"
        } else {
            & $psql -U postgres -h localhost -c "CREATE DATABASE sentryscan;" | Out-Null
            Write-Ok "Database 'sentryscan' created"
        }
        Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue
    }
} else {
    Write-Warn2 "Skipping PostgreSQL (per -SkipPostgres). Set DATABASE_URL in .env to point at your own instance."
}

# ---------------------------------------------------------------------------
# 4. Python virtual environment + dependencies
# ---------------------------------------------------------------------------
Write-Step "Creating virtual environment + installing Python dependencies"
Refresh-Path
Push-Location $ProjectRoot
try {
    if (-not (Test-Path ".venv")) {
        python -m venv .venv
    }
    & ".venv\Scripts\python.exe" -m pip install --upgrade pip --quiet
    & ".venv\Scripts\python.exe" -m pip install -r requirements.txt
    Write-Ok "Dependencies installed into .venv"
} finally {
    Pop-Location
}

# ---------------------------------------------------------------------------
# 5. .env file
# ---------------------------------------------------------------------------
Write-Step "Setting up .env"
$envPath = Join-Path $ProjectRoot ".env"
$envExamplePath = Join-Path $ProjectRoot ".env.example"
if (-not (Test-Path $envPath)) {
    Copy-Item $envExamplePath $envPath
    (Get-Content $envPath) -replace 'sentryscan_dev', $DbPassword | Set-Content $envPath
    Write-Ok ".env created from .env.example (DB password filled in)"
} else {
    Write-Ok ".env already exists -- left untouched"
}

# ---------------------------------------------------------------------------
# 6. Hydra via WSL2 (optional, opt-in)
# ---------------------------------------------------------------------------
if ($InstallHydraViaWSL) {
    Write-Step "Installing WSL2 + Hydra (optional Authentication Testing engine)"
    $wslInstalled = $false
    try { wsl --status *> $null; $wslInstalled = $true } catch { }

    if (-not $wslInstalled) {
        Write-Host "    Enabling WSL2 (this may require a reboot)..."
        wsl --install -d Ubuntu --no-launch
        Write-Warn2 "WSL2 was just enabled. REBOOT your machine, then re-run this script with -InstallHydraViaWSL to finish installing Hydra."
    } else {
        Write-Host "    Installing hydra inside the default WSL distro..."
        wsl -- bash -lc "sudo apt-get update -y && sudo apt-get install -y hydra"
        Write-Ok "Hydra installed inside WSL"
    }
} else {
    Write-Warn2 "Hydra/WSL2 not installed (pass -InstallHydraViaWSL to set it up). Not required except for live Authentication Testing."
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Step "Setup summary"
Refresh-Path
"Python"     | ForEach-Object { Write-Host ("  {0,-12}: {1}" -f $_, ((python --version) 2>&1)) }
Write-Host ("  {0,-12}: {1}" -f "Nmap", ((Get-Command nmap -ErrorAction SilentlyContinue) ? "installed" : "NOT found"))
Write-Host ("  {0,-12}: {1}" -f "PostgreSQL", ((Get-Service -Name 'postgresql-x64-17' -ErrorAction SilentlyContinue) ? "installed" : "NOT found"))
Write-Host ("  {0,-12}: {1}" -f "Hydra(WSL)", ((wsl -- which hydra 2>$null) ? "installed" : "not installed (optional)"))
Write-Host "`nNext steps:"
Write-Host "  1. Review/edit .env (especially AUTHORIZED_TARGETS and ENABLE_LIVE_SCANS)."
Write-Host "  2. .venv\Scripts\python.exe scripts\init_db.py      # create tables"
Write-Host "  3. .venv\Scripts\python.exe scripts\seed_cve_data.py # load offline CVE dataset"
Write-Host "  4. .venv\Scripts\python.exe -m uvicorn app.main:app --reload"
Write-Host "  5. Open http://127.0.0.1:8000 in a browser"
Write-Host "`nNote: PDF report export additionally requires WeasyPrint's native GTK libraries."
Write-Host "      See: https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#windows"
Write-Host "      HTML reports work out of the box without this."
