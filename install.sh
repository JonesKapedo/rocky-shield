#!/data/data/com.termux/files/usr/bin/bash
# ROCKY SHIELD — Installer
# Run this ONCE in Termux to set up the full security system

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}"
echo "  ██████╗  ██████╗  ██████╗██╗  ██╗██╗   ██╗"
echo "  ██╔══██╗██╔═══██╗██╔════╝██║ ██╔╝╚██╗ ██╔╝"
echo "  ██████╔╝██║   ██║██║     █████╔╝  ╚████╔╝ "
echo "  ██╔══██╗██║   ██║██║     ██╔═██╗   ╚██╔╝  "
echo "  ██║  ██║╚██████╔╝╚██████╗██║  ██╗   ██║   "
echo "  ╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝   ╚═╝   "
echo -e "  ${CYAN}SHIELD v1.0 — Installer${NC}${NC}"
echo ""

SHIELD_DIR="$HOME/.rocky-shield"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ─── Step 1: Dependencies ───
echo -e "${CYAN}[1/5] Installing dependencies...${NC}"
pkg update -y 2>/dev/null
pkg install -y coreutils procps iproute2 openssl-tool 2>/dev/null
ok() { echo -e "${GREEN}  ✓ $1${NC}"; }
ok "Dependencies ready"

# ─── Step 2: Create directories ───
echo -e "${CYAN}[2/5] Setting up directories...${NC}"
mkdir -p "$SHIELD_DIR"/{logs,baseline}
ok "Directories created at $SHIELD_DIR"

# ─── Step 3: Install scripts ───
echo -e "${CYAN}[3/5] Installing security scripts...${NC}"

# Main scanner
if [ -f "$SCRIPT_DIR/rockyshield.sh" ]; then
  cp "$SCRIPT_DIR/rockyshield.sh" "$SHIELD_DIR/rockyshield.sh"
else
  echo -e "${YELLOW}  rockyshield.sh not found in $SCRIPT_DIR — copy it manually${NC}"
fi
chmod +x "$SHIELD_DIR/rockyshield.sh" 2>/dev/null

# Real-time monitor
if [ -f "$SCRIPT_DIR/monitor.sh" ]; then
  cp "$SCRIPT_DIR/monitor.sh" "$SHIELD_DIR/monitor.sh"
else
  echo -e "${YELLOW}  monitor.sh not found in $SCRIPT_DIR — copy it manually${NC}"
fi
chmod +x "$SHIELD_DIR/monitor.sh" 2>/dev/null

# Create convenient aliases
echo '# Rocky Shield aliases' >> "$HOME/.bashrc"
echo 'alias shield="$HOME/.rocky-shield/rockyshield.sh"' >> "$HOME/.bashrc"
echo 'alias shield-monitor="$HOME/.rocky-shield/monitor.sh"' >> "$HOME/.bashrc"
echo 'alias shield-stop="kill $(cat $HOME/.rocky-shield/monitor.pid 2>/dev/null) 2>/dev/null; echo Monitor stopped"' >> "$HOME/.bashrc"
echo 'alias shield-logs="tail -50 $HOME/.rocky-shield/logs/alerts.log"' >> "$HOME/.bashrc"
ok "Scripts installed, aliases added to .bashrc"

# ─── Step 4: Setup Termux:Boot ───
echo -e "${CYAN}[4/5] Setting up Termux:Boot auto-start...${NC}"
BOOT_DIR="$HOME/.termux/boot"
mkdir -p "$BOOT_DIR"

if [ -f "$SCRIPT_DIR/boot/rockyshield-boot" ]; then
  cp "$SCRIPT_DIR/boot/rockyshield-boot" "$BOOT_DIR/rockyshield"
else
  # Create inline
  cat > "$BOOT_DIR/rockyshield" << 'BOOTEOF'
#!/data/data/com.termux/files/usr/bin/bash
sleep 15
$HOME/.rocky-shield/rockyshield.sh full >> $HOME/.rocky-shield/logs/boot_scan.log 2>&1
BOOTEOF
fi
chmod +x "$BOOT_DIR/rockyshield"
ok "Boot script installed"
echo -e "  ${YELLOW}⚠ Make sure Termux:Boot app is installed from F-Droid!${NC}"
echo -e "  ${YELLOW}  Install it, then open it once to enable boot receiver.${NC}"

# ─── Step 5: Run initial baseline scan ───
echo -e "${CYAN}[5/5] Running initial baseline scan...${NC}"
echo -e "  ${YELLOW}This creates your security baseline (takes 30-60s)...${NC}"
"$SHIELD_DIR/rockyshield.sh" full 2>/dev/null || true
ok "Baseline scan complete"

# ─── Done ───
echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  ROCKY SHIELD INSTALLED ✓${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Commands:${NC}"
echo -e "    shield              — Full security scan"
echo -e "    shield pkg          — Package audit only"
echo -e "    shield net          — Network monitor only"
echo -e "    shield proc         — Process audit only"
echo -e "    shield persist      — Startup/persistence check"
echo -e "    shield integrity    — File integrity check"
echo -e "    shield perms        — Permission audit"
echo -e "    shield scripts      — Python/Node package audit"
echo -e "    shield-monitor      — Start real-time monitor (background)"
echo -e "    shield-stop         — Stop real-time monitor"
echo -e "    shield-logs         — View recent alerts"
echo ""
echo -e "  ${BOLD}Auto-start:${NC}"
echo -e "    Scans run automatically on Termux boot (via Termux:Boot)"
echo -e "    For real-time monitoring, run: ${CYAN}shield-monitor &${NC}"
echo ""
echo -e "  ${BOLD}Logs:${NC} $SHIELD_DIR/logs/"
echo -e "  ${BOLD}Baseline:${NC} $SHIELD_DIR/baseline/"
echo ""
echo -e "  ${YELLOW}Tip: Run 'shield-monitor &' to start real-time protection.${NC}"
echo -e "  ${YELLOW}Tip: Re-run 'shield' after installing any new package.${NC}"
