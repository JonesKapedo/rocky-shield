#!/data/data/com.termux/files/usr/bin/bash
# ROCKY SHIELD - Termux Security Monitor v1.0
# Scans installed packages, network connections, file integrity, and suspicious activity
# Runs automatically on Termux startup

SHIELD_DIR="$HOME/.rocky-shield"
LOG_DIR="$SHIELD_DIR/logs"
BASELINE_DIR="$SHIELD_DIR/baseline"
ALERT_LOG="$LOG_DIR/alerts.log"
SCAN_LOG="$LOG_DIR/scan_$(date +%Y%m%d_%H%M%S).log"
PID_FILE="$SHIELD_DIR/shield.pid"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

mkdir -p "$LOG_DIR" "$BASELINE_DIR"
echo $$ > "$PID_FILE"

log() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$SCAN_LOG"; }
alert() { echo -e "${RED}[ALERT]${NC} $1" | tee -a "$SCAN_LOG" "$ALERT_LOG"; echo; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$SCAN_LOG"; }
ok() { echo -e "${GREEN}[OK]${NC} $1" | tee -a "$SCAN_LOG"; }
info() { echo -e "${CYAN}[INFO]${NC} $1" | tee -a "$SCAN_LOG"; }
header() { echo -e "\n${BOLD}══════════════════════════════════════${NC}\n${BOLD} $1${NC}\n${BOLD}══════════════════════════════════════${NC}" | tee -a "$SCAN_LOG"; }

# ─── SCAN 1: Installed Package Audit ───
scan_packages() {
  header "PACKAGE AUDIT"
  local pkg_list="$BASELINE_DIR/packages.list"
  local new_pkgs=0
  local removed_pkgs=0

  # Current installed packages
  dpkg -l 2>/dev/null | grep '^ii' | awk '{print $2, $3}' | sort > /tmp/shield_current_pkgs.txt

  if [ -f "$pkg_list" ]; then
    # Compare with baseline
    comm -23 "$pkg_list" /tmp/shield_current_pkgs.txt | while read -r line; do
      alert "NEW package installed: $line"
      ((new_pkgs++))
    done
    comm -13 "$pkg_list" /tmp/shield_current_pkgs.txt | while read -r line; do
      warn "Package REMOVED: $line"
      ((removed_pkgs++))
    done

    if [ "$new_pkgs" -eq 0 ] && [ "$removed_pkgs" -eq 0 ]; then
      ok "No package changes since last baseline"
    else
      info "Updating package baseline..."
      cp /tmp/shield_current_pkgs.txt "$pkg_list"
    fi
  else
    info "Creating initial package baseline ($(wc -l < /tmp/shield_current_pkgs.txt) packages)..."
    cp /tmp/shield_current_pkgs.txt "$pkg_list"
  fi

  # Check for suspicious package names
  grep -iE '(hack|exploit|crack|keylogger|sniff|spoof|backdoor|rootkit|trojan)' /tmp/shield_current_pkgs.txt | while read -r line; do
    alert "SUSPICIOUS package name: $line"
  done

  # Check packages without proper descriptions (possible disguised malware)
  dpkg -l 2>/dev/null | grep '^ii' | while read -r status name ver arch desc; do
    if [ -z "$desc" ] || echo "$desc" | grep -qiE '^(|n/a|none|^-|^[^a-zA-Z]+$)'; then
      warn "Package with vague description: $name ($ver) — '$desc'"
    fi
  done
}

# ─── SCAN 2: Network Connection Monitor ───
scan_network() {
  header "NETWORK MONITOR"

  # Active network connections
  info "Active connections:"
  if command -v ss &>/dev/null; then
    ss -tunap 2>/dev/null | grep -v "127.0.0.1\|::1" | while read -r line; do
      echo "$line" | tee -a "$SCAN_LOG"
    done
  elif command -v netstat &>/dev/null; then
    netstat -tunap 2>/dev/null | grep -v "127.0.0.1\|::1" | while read -r line; do
      echo "$line" | tee -a "$SCAN_LOG"
    done
  else
    warn "Neither ss nor netstat available — limited network scan"
    cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | tail -n +2 | head -30 | while read -r line; do
      echo "$line" | tee -a "$SCAN_LOG"
    done
  fi

  # Check for processes listening on ports
  info "Listening ports (external):"
  if command -v ss &>/dev/null; then
    ss -tlnp 2>/dev/null | grep -v "127.0.0.1\|::1" | while read -r line; do
      local port
      port=$(echo "$line" | grep -oP ':\K\d+' | tail -1)
      if [ -n "$port" ]; then
        alert "External listener on port $port: $line"
      fi
    done
    # Local-only listeners are OK
    local_count=$(ss -tlnp 2>/dev/null | grep -cE "127.0.0.1|::1")
    ok "Found $local_count localhost-only listeners (normal)"
  fi

  # Check DNS queries (possible C2 communication)
  if [ -f /etc/resolv.conf ]; then
    info "DNS configuration:"
    grep nameserver /etc/resolv.conf | while read -r line; do
      echo "$line" | tee -a "$SCAN_LOG"
    done
  fi
}

# ─── SCAN 3: Running Process Audit ───
scan_processes() {
  header "PROCESS AUDIT"
  local proc_list="$BASELINE_DIR/processes.list"

  ps -eo pid,user,ppid,comm,args --no-headers 2>/dev/null > /tmp/shield_current_procs.txt \
    || ps aux > /tmp/shield_current_procs.txt

  if [ -f "$proc_list" ]; then
    local new_procs
    new_procs=$(comm -23 <(sort /tmp/shield_current_procs.txt) <(sort "$proc_list") | head -20)
    if [ -n "$new_procs" ]; then
      warn "New/different processes since baseline:"
      echo "$new_procs" | while read -r line; do
        echo "  → $line" | tee -a "$SCAN_LOG"
      done
    else
      ok "No unexpected new processes"
    fi
  else
    info "Creating initial process baseline..."
    cp /tmp/shield_current_procs.txt "$proc_list"
  fi

  # Check for suspicious process patterns
  grep -iE '(nc |ncat|nmap|hydra|aircrack|ettercap|tcpdump|wireshark|john|hashcat|sqlmap|metasploit|msf|beef|cobalt)' /tmp/shield_current_procs.txt | while read -r line; do
    alert "SUSPICIOUS process running: $line"
  done

  # Zombie processes
  zombie_count=$(ps aux 2>/dev/null | awk '$8 ~ /Z/' | wc -l)
  if [ "$zombie_count" -gt 0 ]; then
    warn "$zombie_count zombie process(es) detected"
  else
    ok "No zombie processes"
  fi

  # Processes running as root (in Termux this is unusual)
  root_procs=$(ps -eo user,comm 2>/dev/null | grep -c '^root' || echo 0)
  if [ "$root_procs" -gt 0 ]; then
    warn "$root_procs process(es) running as root"
  fi
}

# ─── SCAN 4: Cron/Timer & Startup Persistence Check ───
scan_persistence() {
  header "PERSISTENCE CHECK (Startup Items)"

  # Crontab entries
  if command -v crontab &>/dev/null; then
    local cron_entries
    cron_entries=$(crontab -l 2>/dev/null)
    if [ -n "$cron_entries" ] && ! echo "$cron_entries" | grep -q "^no crontab"; then
      warn "Active crontab entries found:"
      echo "$cron_entries" | while read -r line; do
        echo "  ⏰ $line" | tee -a "$SCAN_LOG"
        if echo "$line" | grep -qiE '(curl|wget|nc|bash -i|/dev/tcp|reverse|connect back)'; then
          alert "DANGEROUS cron entry: $line"
        fi
      done
    else
      ok "No crontab entries (clean)"
    fi
  fi

  # Termux:Boot startup scripts
  local boot_dir="$HOME/.termux/boot"
  if [ -d "$boot_dir" ]; then
    local boot_count
    boot_count=$(find "$boot_dir" -type f | wc -l)
    info "Termux:Boot scripts: $boot_count"
    find "$boot_dir" -type f | while read -r f; do
      echo "  📌 $(basename "$f") → $f" | tee -a "$SCAN_LOG"
      # Check for dangerous commands in boot scripts
      if grep -qiE '(curl.*\|.*bash|wget.*\|.*bash|/dev/tcp|rm -rf /|mkfs|dd if=|cryptsetup)' "$f" 2>/dev/null; then
        alert "DANGEROUS command in boot script: $f"
      fi
    done
  else
    ok "No Termux:Boot scripts"
  fi

  # Shell profile modifications
  for rcfile in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile" "$HOME/.bash_profile"; do
    if [ -f "$rcfile" ]; then
      if grep -qiE '(curl.*\|.*bash|wget.*\|.*bash|/dev/tcp|nc -e|reverse.shell|python.*-c.*import.*socket|base64.*decode)' "$rcfile" 2>/dev/null; then
        alert "SUSPICIOUS command found in $rcfile"
      fi
    fi
  done
  ok "Shell profiles scanned"
}

# ─── SCAN 5: File Integrity Check ───
scan_file_integrity() {
  header "FILE INTEGRITY"
  local hash_file="$BASELINE_DIR/hashes.sha256"

  # Critical Termux binaries to monitor
  local critical_paths=(
    "/data/data/com.termux/files/usr/bin"
    "/data/data/com.termux/files/usr/lib"
  )

  info "Hashing critical binaries (this takes a moment)..."
  local current_hashes="/tmp/shield_current_hashes.txt"

  for p in "${critical_paths[@]}"; do
    if [ -d "$p" ]; then
      find "$p" -type f -executable 2>/dev/null | head -500 | while read -r f; do
        sha256sum "$f" 2>/dev/null
      done
    fi
  done | sort > "$current_hashes"

  if [ -f "$hash_file" ]; then
    local changed
    changed=$(comm -23 <(sort "$hash_file") <(sort "$current_hashes"))
    local added
    added=$(comm -13 <(sort "$hash_file") <(sort "$current_hashes") | head -20)

    if [ -n "$changed" ]; then
      alert "MODIFIED files since baseline (possible tampering):"
      echo "$changed" | while read -r line; do
        echo "  ✏️  $line" | tee -a "$SCAN_LOG"
      done
    else
      ok "No file modifications detected in critical paths"
    fi

    if [ -n "$added" ]; then
      warn "New executable files since baseline:"
      echo "$added" | while read -r line; do
        echo "  📄 $line" | tee -a "$SCAN_LOG"
      done
    fi

    cp "$current_hashes" "$hash_file"
  else
    info "Creating initial file integrity baseline..."
    cp "$current_hashes" "$hash_file"
    info "Baseline created with $(wc -l < "$hash_file") file hashes"
  fi

  # Check for hidden files in unusual places
  info "Checking for suspicious hidden files..."
  find /data/data/com.termux/files/usr -name ".*" -type f 2>/dev/null | head -20 | while read -r f; do
    local size
    size=$(stat -c%s "$f" 2>/dev/null || echo "0")
    if [ "$size" -gt 0 ]; then
      warn "Hidden file: $f (${size} bytes)"
    fi
  done
}

# ─── SCAN 6: Permission Audit ───
scan_permissions() {
  header "PERMISSION AUDIT"

  # World-writable files in bin directories
  local ww_files
  ww_files=$(find /data/data/com.termux/files/usr/bin -type f -perm -002 2>/dev/null | head -20)
  if [ -n "$ww_files" ]; then
    alert "World-writable executables found:"
    echo "$ww_files" | while read -r line; do
      echo "  🔓 $line" | tee -a "$SCAN_LOG"
    done
  else
    ok "No world-writable executables in bin"
  fi

  # SUID/SGID binaries (shouldn't exist in Termux normally)
  local suid_files
  suid_files=$(find /data/data/com.termux/files/usr -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -20)
  if [ -n "$suid_files" ]; then
    alert "SUID/SGID binaries found (unusual for Termux):"
    echo "$suid_files" | while read -r line; do
      echo "  ⚠️  $line" | tee -a "$SCAN_LOG"
    done
  else
    ok "No unexpected SUID/SGID binaries"
  fi

  # Check Termux:API permissions if available
  if [ -f "/data/data/com.termux/files/usr/bin/termux-info" ]; then
    info "Termux storage and API access:"
    [ -d "$HOME/storage" ] && echo "  📁 Storage access: GRANTED" || echo "  📁 Storage access: Not granted"
  fi
}

# ─── SCAN 7: Python/Node Package Audit ───
scan_script_packages() {
  header "SCRIPT PACKAGE AUDIT (pip/npm)"

  # Check pip packages
  if command -v pip &>/dev/null; then
    info "Python packages installed:"
    pip list --format=columns 2>/dev/null | tail -n +3 | head -50 | while read -r line; do
      echo "  🐍 $line" | tee -a "$SCAN_LOG"
    done

    # Check for known malicious pip packages
    pip list --format=freeze 2>/dev/null | grep -iE '(backdoor|exploit|hack|keylogger|steal|trojan|evil|malicious|discord\.py-self|request-mirror|beautifulsoup-usage)' | while read -r line; do
      alert "SUSPICIOUS pip package: $line"
    done

    local pip_count
    pip_count=$(pip list 2>/dev/null | tail -n +3 | wc -l)
    info "Total pip packages: $pip_count"
  fi

  # Check npm packages
  if command -v npm &>/dev/null; then
    info "Global npm packages:"
    npm list -g --depth=0 2>/dev/null | tail -n +2 | head -30 | while read -r line; do
      echo "  📦 $line" | tee -a "$SCAN_LOG"
    done

    local npm_count
    npm_count=$(npm list -g --depth=0 2>/dev/null | tail -n +2 | wc -l)
    info "Total global npm packages: $npm_count"
  fi
}

# ─── GENERATE REPORT ───
generate_report() {
  header "SCAN SUMMARY"

  local alert_count
  alert_count=$(grep -c '\[ALERT\]' "$SCAN_LOG" 2>/dev/null || echo 0)
  local warn_count
  warn_count=$(grep -c '\[WARN\]' "$SCAN_LOG" 2>/dev/null || echo 0)
  local ok_count
  ok_count=$(grep -c '\[OK\]' "$SCAN_LOG" 2>/dev/null || echo 0)

  echo -e "${BOLD}Results:${NC}"
  echo -e "  ${RED}Alerts:  $alert_count${NC}"
  echo -e "  ${YELLOW}Warnings: $warn_count${NC}"
  echo -e "  ${GREEN}Passed:  $ok_count${NC}"
  echo -e "\n  Full log: $SCAN_LOG"
  echo -e "  Alert log: $ALERT_LOG"

  if [ "$alert_count" -gt 0 ]; then
    echo -e "\n${RED}${BOLD}⚠️  SECURITY ALERTS DETECTED — REVIEW $ALERT_LOG IMMEDIATELY${NC}"
    return 1
  else
    echo -e "\n${GREEN}${BOLD}✓ SYSTEM CLEAN — No critical issues found${NC}"
    return 0
  fi
}

# ─── MAIN EXECUTION ───
clear 2>/dev/null
echo -e "${BOLD}"
echo "  ██████╗  ██████╗  ██████╗██╗  ██╗██╗   ██╗"
echo "  ██╔══██╗██╔═══██╗██╔════╝██║ ██╔╝╚██╗ ██╔╝"
echo "  ██████╔╝██║   ██║██║     █████╔╝  ╚████╔╝ "
echo "  ██╔══██╗██║   ██║██║     ██╔═██╗   ╚██╔╝  "
echo "  ██║  ██║╚██████╔╝╚██████╗██║  ██╗   ██║   "
echo "  ╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝   ╚═╝   "
echo -e "  ${CYAN}SHIELD v1.0 — Termux Security Monitor${NC}"
echo -e "  $(date)${NC}"
echo ""

case "${1:-full}" in
  full)
    scan_packages
    scan_network
    scan_processes
    scan_persistence
    scan_file_integrity
    scan_permissions
    scan_script_packages
    generate_report
    ;;
  pkg) scan_packages ;;
  net) scan_network ;;
  proc) scan_processes ;;
  persist) scan_persistence ;;
  integrity) scan_file_integrity ;;
  perms) scan_permissions ;;
  scripts) scan_script_packages ;;
  *)
    echo "Usage: rockyshield [full|pkg|net|proc|persist|integrity|perms|scripts]"
    ;;
esac
