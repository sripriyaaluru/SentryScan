#!/usr/bin/env bash
# =============================================================================
# One-shot environment setup for SentryScan on WSL2 Ubuntu (or native Ubuntu/Debian).
#
# Installs/verifies everything SentryScan needs to run:
#   - Python 3.10+ (python3, python3-venv, python3-pip, python3-dev)
#   - Nmap                     -- recon + vulnerability-assessment module
#   - PostgreSQL               -- storage backend, creates the `sentryscan` DB
#   - Hydra                    -- Authentication Testing module's engine
#                                  (native on Linux -- no nested VM needed, unlike Windows)
#   - WeasyPrint native deps   -- libpango/cairo for PDF report export
#   - Python virtual env + pip dependencies from requirements.txt
#   - .env file (copied from .env.example if missing)
#
# Usage (from the project root, inside WSL Ubuntu or any Debian/Ubuntu box):
#   chmod +x scripts/setup_wsl.sh
#   ./scripts/setup_wsl.sh
#
# Options (env vars):
#   DB_PASSWORD=sentryscan_dev   ./scripts/setup_wsl.sh   # set postgres superuser password
#   SKIP_POSTGRES=1              ./scripts/setup_wsl.sh   # skip PostgreSQL install
#   SKIP_NMAP=1                  ./scripts/setup_wsl.sh   # skip Nmap install
#   SKIP_HYDRA=1                 ./scripts/setup_wsl.sh   # skip Hydra install
# =============================================================================
set -euo pipefail

DB_PASSWORD="${DB_PASSWORD:-sentryscan_dev}"
SKIP_POSTGRES="${SKIP_POSTGRES:-0}"
SKIP_NMAP="${SKIP_NMAP:-0}"
SKIP_HYDRA="${SKIP_HYDRA:-0}"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

step()  { printf "\n\033[1;36m==> %s\033[0m\n" "$1"; }
ok()    { printf "    \033[1;32mOK:\033[0m %s\n" "$1"; }
warn()  { printf "    \033[1;33mWARN:\033[0m %s\n" "$1"; }

if ! grep -qiE "ubuntu|debian" /etc/os-release 2>/dev/null; then
    warn "This script targets Ubuntu/Debian (apt-based). Detected OS may not be supported."
fi

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

step "Updating apt package index"
$SUDO apt-get update -y

# -----------------------------------------------------------------------------
# 1. Python
# -----------------------------------------------------------------------------
step "Checking Python 3.10+"
PYBIN=""
for cand in python3.12 python3.11 python3.10 python3; do
    if command -v "$cand" >/dev/null 2>&1; then
        ver="$("$cand" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
        major="${ver%%.*}"; minor="${ver##*.}"
        if [ "$major" -eq 3 ] && [ "$minor" -ge 10 ]; then
            PYBIN="$cand"
            break
        fi
    fi
done

if [ -n "$PYBIN" ]; then
    ok "$($PYBIN --version) (using '$PYBIN')"
else
    echo "    Installing python3, venv, pip, dev headers via apt..."
    $SUDO apt-get install -y python3 python3-venv python3-pip python3-dev
    PYBIN="python3"
    ok "$($PYBIN --version)"
fi

# -----------------------------------------------------------------------------
# 2. Nmap
# -----------------------------------------------------------------------------
if [ "$SKIP_NMAP" != "1" ]; then
    step "Checking Nmap"
    if command -v nmap >/dev/null 2>&1; then
        ok "$(nmap --version | head -n1)"
    else
        echo "    Installing nmap via apt..."
        $SUDO apt-get install -y nmap
        ok "Nmap installed"
    fi
else
    warn "Skipping Nmap (SKIP_NMAP=1). Recon + Vulnerability Assessment modules will not run live scans."
fi

# -----------------------------------------------------------------------------
# 3. PostgreSQL
# -----------------------------------------------------------------------------
if [ "$SKIP_POSTGRES" != "1" ]; then
    step "Checking PostgreSQL"
    if command -v psql >/dev/null 2>&1; then
        ok "PostgreSQL client already installed: $(psql --version)"
    else
        echo "    Installing postgresql + postgresql-contrib via apt..."
        $SUDO apt-get install -y postgresql postgresql-contrib
        ok "PostgreSQL installed"
    fi

    echo "    Ensuring the PostgreSQL service is running (WSL has no systemd by default)..."
    $SUDO service postgresql start || warn "Could not start postgresql via 'service' -- start it manually."

    echo "    Setting postgres superuser password and ensuring 'sentryscan' database exists..."
    $SUDO -u postgres psql -v ON_ERROR_STOP=1 -c "ALTER USER postgres WITH PASSWORD '${DB_PASSWORD}';" >/dev/null
    DB_EXISTS="$($SUDO -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='sentryscan'")"
    if [ "$DB_EXISTS" = "1" ]; then
        ok "Database 'sentryscan' already exists"
    else
        $SUDO -u postgres psql -c "CREATE DATABASE sentryscan;" >/dev/null
        ok "Database 'sentryscan' created"
    fi
else
    warn "Skipping PostgreSQL (SKIP_POSTGRES=1). Set DATABASE_URL in .env to point at your own instance."
fi

# -----------------------------------------------------------------------------
# 4. Hydra (native on Linux -- this is the one module that's painful on Windows)
# -----------------------------------------------------------------------------
if [ "$SKIP_HYDRA" != "1" ]; then
    step "Checking Hydra (Authentication Testing module engine)"
    if command -v hydra >/dev/null 2>&1; then
        ok "$(hydra -h 2>&1 | head -n1)"
    else
        echo "    Installing hydra via apt..."
        $SUDO apt-get install -y hydra
        ok "Hydra installed"
    fi
else
    warn "Skipping Hydra (SKIP_HYDRA=1). Authentication Testing module will not run live tests."
fi

# -----------------------------------------------------------------------------
# 5. WeasyPrint native dependencies (PDF report export)
# -----------------------------------------------------------------------------
step "Installing WeasyPrint native dependencies (Pango/Cairo for PDF export)"
$SUDO apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info \
    || $SUDO apt-get install -y libpango1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
ok "WeasyPrint native libraries installed (HTML reports always work; this enables PDF export too)"

# -----------------------------------------------------------------------------
# 6. Python virtual environment + dependencies
# -----------------------------------------------------------------------------
step "Creating virtual environment + installing Python dependencies"
if [ ! -d ".venv" ]; then
    "$PYBIN" -m venv .venv
fi
./.venv/bin/python -m pip install --upgrade pip --quiet
./.venv/bin/python -m pip install -r requirements.txt
ok "Dependencies installed into .venv"

# -----------------------------------------------------------------------------
# 7. .env file
# -----------------------------------------------------------------------------
step "Setting up .env"
if [ ! -f ".env" ]; then
    cp .env.example .env
    sed -i "s/sentryscan_dev/${DB_PASSWORD}/g" .env
    ok ".env created from .env.example (DB password filled in)"
else
    ok ".env already exists -- left untouched"
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
step "Setup summary"
echo "  Python      : $($PYBIN --version 2>&1)"
echo "  Nmap        : $(command -v nmap >/dev/null 2>&1 && echo "installed" || echo "NOT found")"
echo "  PostgreSQL  : $(command -v psql >/dev/null 2>&1 && echo "installed" || echo "NOT found")"
echo "  Hydra       : $(command -v hydra >/dev/null 2>&1 && echo "installed" || echo "not installed (optional)")"
echo
echo "Next steps:"
echo "  1. Review/edit .env (especially AUTHORIZED_TARGETS and ENABLE_LIVE_SCANS)."
echo "  2. ./.venv/bin/python scripts/init_db.py       # create tables"
echo "  3. ./.venv/bin/python scripts/seed_cve_data.py # load offline CVE dataset"
echo "  4. ./.venv/bin/python -m uvicorn app.main:app --reload"
echo "  5. Open http://127.0.0.1:8000 in a browser (from Windows, WSL2 localhost forwarding works automatically)"
echo
echo "Tip: if editing from VSCode on Windows, open this folder with the 'WSL' remote"
echo "     extension (Ctrl+Shift+P -> 'WSL: Open Folder in WSL') so the integrated"
echo "     terminal, debugger, and extensions all run inside this same Ubuntu environment."
