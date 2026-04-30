#!/usr/bin/env bash
# NIDS setup script — run once on any Linux machine to prepare the environment.
# Usage: bash setup.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${GREEN}[setup]${NC} $*"; }
warn()    { echo -e "${YELLOW}[warn]${NC}  $*"; }
die()     { echo -e "${RED}[error]${NC} $*" >&2; exit 1; }
section() { echo -e "\n${BOLD}$*${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── 1. Root check ─────────────────────────────────────────────────────────────
section "── 1/6  Privilege check"
if [[ $EUID -eq 0 ]]; then
    die "Do not run setup.sh as root. Run it as your normal user; sudo will be used where needed."
fi
info "Running as $(whoami) — OK"

# ── 2. Python version ─────────────────────────────────────────────────────────
section "── 2/6  Python version"
PYTHON=""
for candidate in python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c 'import sys; print(sys.version_info[:2])')
        # require >= (3, 10)
        if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    die "Python 3.10 or newer is required (needed for structural pattern matching).\n       Install it with your package manager and re-run this script."
fi
info "Using $PYTHON ($($PYTHON --version))"

# ── 3. System packages ────────────────────────────────────────────────────────
section "── 3/6  System packages"

# Detect package manager
if command -v apt-get &>/dev/null; then
    PKG_MGR="apt"
elif command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
elif command -v pacman &>/dev/null; then
    PKG_MGR="pacman"
else
    warn "Could not detect a supported package manager (apt/dnf/pacman)."
    warn "Make sure python3-venv and libpcap are installed manually."
    PKG_MGR="unknown"
fi

install_pkg() {
    # $1 = apt name, $2 = dnf name, $3 = pacman name
    local apt_name=$1 dnf_name=$2 pac_name=$3
    case "$PKG_MGR" in
        apt)    sudo apt-get install -y "$apt_name" ;;
        dnf)    sudo dnf install -y "$dnf_name" ;;
        pacman) sudo pacman -S --noconfirm "$pac_name" ;;
        *)      warn "Skip auto-install of $apt_name — install it manually." ;;
    esac
}

# python3-venv (may be a separate package on Debian/Ubuntu)
if ! "$PYTHON" -c "import venv" &>/dev/null; then
    info "Installing python3-venv..."
    install_pkg "python3-venv" "python3-venv" "python"
fi

# libpcap (required by Scapy for live capture)
if ! ldconfig -p 2>/dev/null | grep -q libpcap && ! ls /usr/lib*/libpcap* &>/dev/null 2>&1; then
    info "Installing libpcap..."
    install_pkg "libpcap-dev" "libpcap-devel" "libpcap"
fi

info "System packages OK"

# ── 4. Virtual environment ────────────────────────────────────────────────────
section "── 4/6  Virtual environment"

if [[ -d .venv ]]; then
    info ".venv already exists — skipping creation"
else
    info "Creating .venv..."
    "$PYTHON" -m venv .venv
fi

info "Upgrading pip..."
.venv/bin/pip install --quiet --upgrade pip

info "Installing requirements..."
.venv/bin/pip install --quiet -r requirements.txt

info "Dependencies installed:"
.venv/bin/pip show scapy flask python-dotenv | grep -E "^(Name|Version):" | paste - -

# ── 5. Project directories & files ───────────────────────────────────────────
section "── 5/6  Project layout"

mkdir -p logs
info "logs/ directory ready"

chmod +x nids
info "nids launcher is executable"

if [[ ! -f .env ]]; then
    cat > .env << 'EOF'
# NIDS environment variables
# Fill in the values you need; leave others blank to disable that feature.

# SMTP email alerts (optional — leave blank to disable email)
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
ALERT_EMAIL=

# Slack webhook alert (optional — leave blank to disable Slack)
SLACK_WEBHOOK=
EOF
    info ".env template created — edit it to enable email/Slack notifications"
else
    info ".env already exists — skipping"
fi

# ── 6. Interface suggestion ───────────────────────────────────────────────────
section "── 6/6  Network interface"

DEFAULT_IFACE=""
# Try to find the default route interface
if command -v ip &>/dev/null; then
    DEFAULT_IFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
fi

if [[ -n "$DEFAULT_IFACE" ]]; then
    info "Detected default interface: ${BOLD}$DEFAULT_IFACE${NC}"

    # Write INTERFACE to .env (config.py reads it via os.getenv).
    # This avoids modifying a git-tracked file.
    if grep -q '^INTERFACE=' .env 2>/dev/null; then
        sed -i "s/^INTERFACE=.*/INTERFACE=$DEFAULT_IFACE/" .env
    else
        echo "INTERFACE=$DEFAULT_IFACE" >> .env
    fi
    info ".env updated: INTERFACE=$DEFAULT_IFACE"
else
    warn "Could not detect a default interface — set INTERFACE in config.py manually."
    info "Available interfaces:"
    ip link show 2>/dev/null | awk -F': ' '/^[0-9]+:/ && !/lo/ {print "    " $2}' || true
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}Setup complete.${NC}"
echo ""
echo "  Start the NIDS:"
echo -e "    ${BOLD}./nids --interface ${DEFAULT_IFACE:-<iface>}${NC}"
echo -e "    ${BOLD}./nids --interface ${DEFAULT_IFACE:-<iface>} --stats-interval 10${NC}"
echo ""
echo "  Test the capture stack (no alerts, just prints packets):"
echo -e "    ${BOLD}sudo .venv/bin/python scripts/test_capture.py${NC}"
echo ""
echo "  Generate test attack traffic:"
echo -e "    ${BOLD}sudo .venv/bin/python scripts/gen_traffic.py --list${NC}"
echo ""
if [[ -f .env ]]; then
    echo "  Edit .env to enable email/Slack alerts:"
    echo -e "    ${BOLD}\$EDITOR .env${NC}"
    echo ""
fi
