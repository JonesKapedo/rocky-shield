#!/data/data/com.termux/files/usr/bin/bash
# ROCKY SHIELD v3.0 — Installer
# Run this ONCE in Termux

set -e

SHIELD_DIR="$HOME/.rocky-shield"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

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
echo -e "  ${CYAN}SHIELD v3.0 — Installer${NC}${NC}"
echo ""

echo -e "${CYAN}[1/4] Installing dependencies...${NC}"
pkg install -y coreutils procps iproute2 openssl-tool 2>/dev/null
echo -e "${GREEN}  ✓ Done${NC}"

echo -e "${CYAN}[2/4] Setting up directories...${NC}"
mkdir -p "$SHIELD_DIR"/{logs,baseline,quarantine}
echo -e "${GREEN}  ✓ Done${NC}"

echo -e "${CYAN}[3/4] Installing shield...${NC}"
cp "$SCRIPT_DIR/rockyshield.sh" "$SHIELD_DIR/rockyshield.sh"
chmod +x "$SHIELD_DIR/rockyshield.sh"
echo -e "${GREEN}  ✓ Done${NC}"

echo -e "${CYAN}[4/4] Setting up command alias...${NC}"
grep -q 'alias shield=' "$HOME/.bashrc" 2>/dev/null || {
  echo '' >> "$HOME/.bashrc"
  echo '# Rocky Shield' >> "$HOME/.bashrc"
  echo 'alias shield="$HOME/.rocky-shield/rockyshield.sh"' >> "$HOME/.bashrc"
}
echo -e "${GREEN}  ✓ Done${NC}"

# Run initial baseline scan
echo ""
echo -e "${CYAN}Running initial scan...${NC}"
"$SHIELD_DIR/rockyshield.sh" full 2>/dev/null || true
echo ""

echo -e "${GREEN}${BOLD}══════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  ROCKY SHIELD v3.0 INSTALLED ✓${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Quick start:${NC}"
echo -e "    shield              Full scan"
echo -e "    shield quick        Quick scan"
echo -e "    shield start        Start monitor"
echo -e "    shield status       Check status"
echo -e "    shield logs         View alerts"
echo -e "    shield authorize    Whitelist tools"
echo -e "    shield help         All commands"
echo ""
echo -e "  ${YELLOW}⚠ Close and reopen Termux to activate 'shield' command${NC}"
echo -e "  ${YELLOW}  (or run: source ~/.bashrc)${NC}"
echo ""
