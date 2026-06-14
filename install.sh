#!/data/data/com.termux/files/usr/bin/bash
# ROCKY SHIELD v2.0 — Installer
# Run this ONCE in Termux

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
echo -e "  ${CYAN}SHIELD v2.0 — Installer${NC}${NC}"
echo ""

SHIELD_DIR="$HOME/.rocky-shield"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${CYAN}[1/6] Installing dependencies...${NC}"
pkg update -y 2>/dev/null
pkg install -y coreutils procps iproute2 openssl-tool 2>/dev/null
echo -e "${GREEN}  ✓ Dependencies ready${NC}"

echo -e "${CYAN}[2/6] Setting up directories...${NC}"
mkdir -p "$SHIELD_DIR"/{logs,baseline,quarantine,tasker}
echo -e "${GREEN}  ✓ Directories created${NC}"

echo -e "${CYAN}[3/6] Installing scripts...${NC}"
[ -f "$SCRIPT_DIR/rockyshield.sh" ] && cp "$SCRIPT_DIR/rockyshield.sh" "$SHIELD_DIR/rockyshield.sh"
[ -f "$SCRIPT_DIR/monitor.sh" ] && cp "$SCRIPT_DIR/monitor.sh" "$SHIELD_DIR/monitor.sh"
[ -f "$SCRIPT_DIR/tasker/shield-tasker" ] && cp "$SCRIPT_DIR/tasker/shield-tasker" "$SHIELD_DIR/tasker/shield-tasker"
chmod +x "$SHIELD_DIR/rockyshield.sh" "$SHIELD_DIR/monitor.sh" "$SHIELD_DIR/tasker/shield-tasker"
echo -e "${GREEN}  ✓ Scripts installed${NC}"

echo -e "${CYAN}[4/6] Setting up Termux:Boot...${NC}"
BOOT_DIR="$HOME/.termux/boot"
mkdir -p "$BOOT_DIR"
[ -f "$SCRIPT_DIR/boot/rockyshield-boot" ] && cp "$SCRIPT_DIR/boot/rockyshield-boot" "$BOOT_DIR/rockyshield"
chmod +x "$BOOT_DIR/rockyshield"
echo -e "${GREEN}  ✓ Boot script installed${NC}"
echo -e "  ${YELLOW}⚠ Install Termux:Boot from F-Droid and open it once!${NC}"

echo -e "${CYAN}[5/6] Setting up Termux:Widget shortcut...${NC}"
WIDGET_DIR="$HOME/.shortcuts"
mkdir -p "$WIDGET_DIR"
[ -f "$SCRIPT_DIR/widget/rockyshield-scan" ] && cp "$SCRIPT_DIR/widget/rockyshield-scan" "$WIDGET_DIR/rockyshield-scan"
chmod +x "$WIDGET_DIR/rockyshield-scan" 2>/dev/null
echo -e "${GREEN}  ✓ Widget shortcut installed${NC}"

echo -e "${CYAN}[6/6] Running initial baseline scan...${NC}"
"$SHIELD_DIR/rockyshield.sh" full 2>/dev/null || true
echo -e "${GREEN}  ✓ Baseline created${NC}"

# Add aliases
grep -q 'alias shield=' "$HOME/.bashrc" 2>/dev/null || {
  echo '' >> "$HOME/.bashrc"
  echo '# Rocky Shield' >> "$HOME/.bashrc"
  echo 'alias shield="$HOME/.rocky-shield/rockyshield.sh"' >> "$HOME/.bashrc"
  echo 'alias shield-mon="$HOME/.rocky-shield/monitor.sh"' >> "$HOME/.bashrc"
  echo 'alias shield-task="$HOME/.rocky-shield/tasker/shield-tasker"' >> "$HOME/.bashrc"
  echo 'alias shield-stop="kill $(cat $HOME/.rocky-shield/monitor.pid 2>/dev/null) 2>/dev/null; kill $(cat $HOME/.rocky-shield/watchdog.pid 2>/dev/null) 2>/dev/null; rm -f $HOME/.rocky-shield/monitor.pid $HOME/.rocky-shield/watchdog.pid; echo Monitor stopped"' >> "$HOME/.bashrc"
  echo 'alias shield-logs="tail -50 $HOME/.rocky-shield/logs/alerts.log"' >> "$HOME/.bashrc"
  echo 'alias shield-kills="tail -50 $HOME/.rocky-shield/logs/kills.log"' >> "$HOME/.bashrc"
  echo 'alias shield-status="echo \"Monitor: $(kill -0 $(cat $HOME/.rocky-shield/monitor.pid 2>/dev/null) 2>/dev/null && echo RUNNING || echo STOPPED)\"; echo \"Watchdog: $(kill -0 $(cat $HOME/.rocky-shield/watchdog.pid 2>/dev/null) 2>/dev/null && echo RUNNING || echo STOPPED)\"; echo \"Auto-kill: $([ -f $HOME/.rocky-shield/autokill.enabled ] && echo ON || echo OFF)\""' >> "$HOME/.bashrc"
}

echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  ROCKY SHIELD v2.0 INSTALLED ✓${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Commands:${NC}"
echo -e "    shield              Full security scan"
echo -e "    shield pkg          Package audit"
echo -e "    shield net          Network monitor"
echo -e "    shield proc         Process audit"
echo -e "    shield persist      Persistence check"
echo -e "    shield integrity    File integrity"
echo -e "    shield perms        Permission audit"
echo -e "    shield scripts      Python/Node audit"
echo -e "    shield files        Suspicious file scan"
echo -e "    shield autokill on  Enable auto-kill"
echo -e "    shield autokill off Disable auto-kill"
echo ""
echo -e "  ${BOLD}Monitor:${NC}"
echo -e "    shield-mon &        Start real-time monitor"
echo -e "    shield-stop         Stop real-time monitor + watchdog"
echo -e "    shield-status       Check monitor/watchdog status"
echo ""
echo -e "  ${BOLD}Tasker:${NC}"
echo -e "    shield-task scan    Scan via Tasker"
echo -e "    shield-task lockdown  Emergency lockdown"
echo -e "    shield-task status  Shield status"
echo ""
echo -e "  ${BOLD}Logs:${NC}"
echo -e "    shield-logs         View alerts"
echo -e "    shield-kills        View kills/quarantines"
echo ""
echo -e "  ${YELLOW}Next steps:${NC}"
echo -e "  1. Termux:Boot should already be installed — open it once more to re-activate"
echo -e "  2. Run: ${CYAN}shield autokill on${NC}"
echo -e "  3. Run: ${CYAN}shield-mon &${NC}  (or just reboot Termux — watchdog starts automatically)"
echo -e "  4. Run: ${CYAN}shield-status${NC}  to verify monitor + watchdog are running"
echo -e "  5. Add Tasker profile → see GitHub README"
echo ""
echo -e "  Repo: https://github.com/JonesKapedo/rocky-shield"
