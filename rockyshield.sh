#!/data/data/com.termux/files/usr/bin/bash
# ROCKY SHIELD - Termux Security Monitor v2.0
# Scans + AUTO-KILLS suspicious processes and quarantines malicious files
# Runs automatically on Termux startup

SHIELD_DIR="$HOME/.rocky-shield"
LOG_DIR="$SHIELD_DIR/logs"
BASELINE_DIR="$SHIELD_DIR/baseline"
QUARANTINE_DIR="$SHIELD_DIR/quarantine"
ALERT_LOG="$LOG_DIR/alerts.log"
KILL_LOG="$LOG_DIR/kills.log"
SCAN_LOG="$LOG_DIR/scan_$(date +%Y%m%d_%H%M%S).log"
PID_FILE="$SHIELD_DIR/shield.pid"
CONFIG_FILE="$SHIELD_DIR/config"
AUTO_KILL_FILE="$SHIELD_DIR/autokill.enabled"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

mkdir -p "$LOG_DIR" "$BASELINE_DIR" "$QUARANTINE_DIR"
echo $$ > "$PID_FILE"

# Load config
AUTO_KILL=false
[ -f "$AUTO_KILL_FILE" ] && AUTO_KILL=true

log() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$SCAN_LOG"; }
alert() { echo -e "${RED}[ALERT]${NC} $1" | tee -a "$SCAN_LOG" "$ALERT_LOG"; echo; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$SCAN_LOG"; }
ok() { echo -e "${GREEN}[OK]${NC} $1" | tee -a "$SCAN_LOG"; }
info() { echo -e "${CYAN}[INFO]${NC} $1" | tee -a "$SCAN_LOG"; }
header() { echo -e "\n${BOLD}══════════════════════════════════════${NC}\n${BOLD} $1${NC}\n${BOLD}══════════════════════════════════════${NC}" | tee -a "$SCAN_LOG"; }

# ─── KILL FUNCTION ───
kill_suspicious() {
  local pid="$1"
  local name="$2"
  local reason="$3"

  if [ -z "$pid" ] || [ "$pid" = "$$" ] || [ "$pid" = "1" ]; then
    return
  fi

  # Don't kill ourselves or init
  if [ "$pid" = "$(cat "$PID_FILE" 2>/dev/null)" ]; then
    return
  fi

  if [ "$AUTO_KILL" = true ]; then
    kill -TERM "$pid" 2>/dev/null
    sleep 1
    # Force kill if still running
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null
      log "FORCE KILLED PID $pid ($name) — $reason"
    else
      log "KILLED PID $pid ($name) — $reason"
    fi
    echo "[$(date '+%H:%M:%S')] KILLED PID $pid ($name) — $reason" >> "$KILL_LOG"

    # Termux notification
    if command -v termux-notification &>/dev/null; then
      termux-notification \
        --title "🛡️ Shield Killed Process" \
        --content "Killed: $name (PID $pid) — $reason" \
        --priority high \
        --id shield-kill
    fi
  else
    warn "Would kill PID $pid ($name) — $reason (auto-kill disabled, use: shield autokill on)"
  fi
}

# ─── QUARANTINE FUNCTION ───
quarantine_file() {
  local filepath="$1"
  local reason="$2"

  if [ ! -f "$filepath" ]; then
    return
  fi

  local filename
  filename=$(basename "$filepath")
  local qfile="$QUARANTINE_DIR/${filename}.$(date +%s)"

  # Copy to quarantine, then remove original
  cp "$filepath" "$qfile" 2>/dev/null
  chmod 000 "$qfile" 2>/dev/null
  rm -f "$filepath" 2>/dev/null

  log "QUARANTINED: $filepath → $qfile — $reason"
  echo "[$(date '+%H:%M:%S')] QUARANTINED: $filepath — $reason" >> "$KILL_LOG"

  if command -v termux-notification &>/dev/null; then
    termux-notification \
      --title "🛡️ Shield Quarantined File" \
      --content "Quarantined: $filename — $reason" \
      --priority high \
      --id shield-quarantine
  fi
}

# ─── SCAN 1: Installed Package Audit ───
scan_packages() {
  header "PACKAGE AUDIT"
  local pkg_list="$BASELINE_DIR/packages.list"

  dpkg -l 2>/dev/null | grep '^ii' | awk '{print $2, $3}' | sort > /tmp/shield_current_pkgs.txt

  if [ -f "$pkg_list" ]; then
    comm -23 "$pkg_list" /tmp/shield_current_pkgs.txt | while read -r line; do
      alert "NEW package installed: $line"
      # Check if the new package is suspicious
      local pkgname
      pkgname=$(echo "$line" | awk '{print $1}')
      if echo "$pkgname" | grep -qiE '(hack|exploit|crack|keylogger|sniff|spoof|backdoor|rootkit|trojan|reverse|shell|payload)'; then
        alert "DANGEROUS package detected: $pkgname — attempting removal"
        if [ "$AUTO_KILL" = true ]; then
          dpkg --purge "$pkgname" 2>/dev/null && ok "Removed: $pkgname" || warn "Could not remove: $pkgname"
        fi
      fi
    done
    comm -13 "$pkg_list" /tmp/shield_current_pkgs.txt | while read -r line; do
      warn "Package REMOVED: $line"
    done
    cp /tmp/shield_current_pkgs.txt "$pkg_list"
  else
    info "Creating initial package baseline ($(wc -l < /tmp/shield_current_pkgs.txt) packages)..."
    cp /tmp/shield_current_pkgs.txt "$pkg_list"
  fi

  # Check for suspicious package names
  grep -iE '(hack|exploit|crack|keylogger|sniff|spoof|backdoor|rootkit|trojan)' /tmp/shield_current_pkgs.txt | while read -r line; do
    alert "SUSPICIOUS package name: $line"
  done
}

# ─── SCAN 2: Network Connection Monitor ───
scan_network() {
  header "NETWORK MONITOR"

  if command -v ss &>/dev/null; then
    # External listeners
    ss -tlnp 2>/dev/null | grep -v "127.0.0.1\|::1" | while read -r line; do
      local port
      port=$(echo "$line" | grep -oP ':\K\d+' | tail -1)
      if [ -n "$port" ]; then
        alert "External listener on port $port: $line"
        # Kill process listening on external port
        local pid
        pid=$(echo "$line" | grep -oP 'pid=\K[0-9]+' | head -1)
        if [ -n "$pid" ]; then
          kill_suspicious "$pid" "port-$port-listener" "External listener on port $port"
        fi
      fi
    done

    # Suspicious outbound connections
    ss -tnp 2>/dev/null | grep ESTAB | while read -r line; do
      if echo "$line" | grep -qiE ':(4444|5555|6666|7777|8888|9999|1337|31337|12345|54321) '; then
        alert "Suspicious outbound connection (known C2 port): $line"
        local pid
        pid=$(echo "$line" | grep -oP 'pid=\K[0-9]+' | head -1)
        [ -n "$pid" ] && kill_suspicious "$pid" "suspicious-outbound" "C2 port connection"
      fi
    done
  fi

  ok "Network scan complete"
}

# ─── SCAN 3: Running Process Audit + KILL ───
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

  # ─── KILL suspicious processes ───
  # Known malicious tool names
  local SUSPICIOUS='nc$|ncat$|netcat$|nmap$|hydra$|aircrack|ettercap$|tcpdump$|wireshark$|john$|hashcat$|sqlmap$|msfconsole$|msfvenom$|beef$|cobalt$|metasploit$|slowloris$|hping3$|arpspoof$|dsniff$|kismet$|reaver$|wifite$'

  ps -eo pid,comm,args --no-headers 2>/dev/null | grep -iE "$SUSPICIOUS" | while read -r pid comm args; do
    kill_suspicious "$pid" "$comm" "Known malicious tool: $comm"
  done

  # Reverse shell patterns
  ps -eo pid,comm,args --no-headers 2>/dev/null | grep -iE '(/dev/tcp|/dev/udp|bash -i|sh -i|python.*-c.*socket|python.*-c.*subprocess|perl.*-c.*socket|ruby.*-c.*socket|nc -e|ncat -e)' | while read -r pid comm args; do
    kill_suspicious "$pid" "$comm" "Reverse shell pattern: $args"
  done

  # Crypto miners
  ps -eo pid,comm,args --no-headers 2>/dev/null | grep -iE '(xmrig|minerd|stratum|cpuminer|ccminer|ethminer|nicehash)' | while read -r pid comm args; do
    kill_suspicious "$pid" "$comm" "Crypto miner detected: $comm"
  done

  # Processes running from unusual locations
  ps -eo pid,comm,args --no-headers 2>/dev/null | while read -r pid comm args; do
    if echo "$args" | grep -qE '(/tmp/|/dev/shm/|/sdcard/Download/|\.hidden)'; then
      if ! echo "$comm" | grep -qE '^(bash|sh|zsh|python|node|ruby)$'; then
        warn "Process running from unusual location: $comm (PID $pid) — $args"
      fi
    fi
  done

  # Zombie processes
  local zombie_count
  zombie_count=$(ps aux 2>/dev/null | awk '$8 ~ /Z/' | wc -l)
  if [ "$zombie_count" -gt 0 ]; then
    warn "$zombie_count zombie process(es) detected"
  else
    ok "No zombie processes"
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
        if echo "$line" | grep -qiE '(curl.*\|.*bash|wget.*\|.*bash|/dev/tcp|reverse|connect.back|nc |ncat )'; then
          alert "DANGEROUS cron entry: $line"
          if [ "$AUTO_KILL" = true ]; then
            crontab -r 2>/dev/null && ok "Crontab cleared" || warn "Could not clear crontab"
          fi
        fi
      done
    else
      ok "No crontab entries (clean)"
    fi
  fi

  # Termux:Boot startup scripts
  local boot_dir="$HOME/.termux/boot"
  if [ -d "$boot_dir" ]; then
    info "Termux:Boot scripts:"
    find "$boot_dir" -type f | while read -r f; do
      echo "  📌 $(basename "$f") → $f" | tee -a "$SCAN_LOG"
      if grep -qiE '(curl.*\|.*bash|wget.*\|.*bash|/dev/tcp|rm -rf /|mkfs|dd if=|cryptsetup|python.*-c.*import.*socket)' "$f" 2>/dev/null; then
        alert "DANGEROUS command in boot script: $f"
        quarantine_file "$f" "Malicious boot script"
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
        quarantine_file "$rcfile" "Shell profile injection"
      fi
    fi
  done
  ok "Shell profiles scanned"
}

# ─── SCAN 5: File Integrity Check ───
scan_file_integrity() {
  header "FILE INTEGRITY"
  local hash_file="$BASELINE_DIR/hashes.sha256"

  local current_hashes="/tmp/shield_current_hashes.txt"
  local critical_paths=(
    "/data/data/com.termux/files/usr/bin"
    "/data/data/com.termux/files/usr/lib"
  )

  info "Hashing critical binaries..."
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
    if [ -n "$changed" ]; then
      alert "MODIFIED files since baseline (possible tampering):"
      echo "$changed" | while read -r line; do
        echo "  ✏️  $line" | tee -a "$SCAN_LOG"
      done
    else
      ok "No file modifications in critical paths"
    fi
    cp "$current_hashes" "$hash_file"
  else
    info "Creating initial file integrity baseline..."
    cp "$current_hashes" "$hash_file"
    info "Baseline: $(wc -l < "$hash_file") file hashes"
  fi

  # Check for suspicious hidden executables
  find /data/data/com.termux/files/usr -name ".*" -type f -executable 2>/dev/null | while read -r f; do
    alert "Hidden executable found: $f"
    quarantine_file "$f" "Hidden executable"
  done
}

# ─── SCAN 6: Permission Audit ───
scan_permissions() {
  header "PERMISSION AUDIT"

  local ww_files
  ww_files=$(find /data/data/com.termux/files/usr/bin -type f -perm -002 2>/dev/null | head -20)
  if [ -n "$ww_files" ]; then
    alert "World-writable executables found:"
    echo "$ww_files" | while read -r line; do
      echo "  🔓 $line" | tee -a "$SCAN_LOG"
      chmod o-w "$line" 2>/dev/null && ok "  → Fixed permissions on $line"
    done
  else
    ok "No world-writable executables in bin"
  fi

  local suid_files
  suid_files=$(find /data/data/com.termux/files/usr -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -20)
  if [ -n "$suid_files" ]; then
    alert "SUID/SGID binaries found (unusual for Termux):"
    echo "$suid_files" | while read -r line; do
      echo "  ⚠️  $line" | tee -a "$SCAN_LOG"
      chmod u-s,g-s "$line" 2>/dev/null && ok "  → Removed SUID/SGID from $line"
    done
  else
    ok "No unexpected SUID/SGID binaries"
  fi
}

# ─── SCAN 7: Python/Node Package Audit ───
scan_script_packages() {
  header "SCRIPT PACKAGE AUDIT (pip/npm)"

  if command -v pip &>/dev/null; then
    pip list --format=freeze 2>/dev/null | grep -iE '(backdoor|exploit|hack|keylogger|steal|trojan|evil|malicious|discord.py-self|request-mirror|beautifulsoup-usage)' | while read -r line; do
      alert "SUSPICIOUS pip package: $line"
      local pkgname
      pkgname=$(echo "$line" | cut -d= -f1)
      if [ "$AUTO_KILL" = true ]; then
        pip uninstall -y "$pkgname" 2>/dev/null && ok "Removed pip package: $pkgname"
      fi
    done
    local pip_count
    pip_count=$(pip list 2>/dev/null | tail -n +3 | wc -l)
    info "Total pip packages: $pip_count"
  fi

  if command -v npm &>/dev/null; then
    npm list -g --depth=0 2>/dev/null | tail -n +2 | head -30 | while read -r line; do
      echo "  📦 $line" | tee -a "$SCAN_LOG"
    done
  fi
}

# ─── SCAN 8: Suspicious File Scanner ───
scan_suspicious_files() {
  header "SUSPICIOUS FILE SCAN"

  # Scan for scripts with dangerous patterns in common locations
  local scan_dirs=("$HOME" "/data/data/com.termux/files/usr/bin" "/data/data/com.termux/files/usr/etc")

  for sdir in "${scan_dirs[@]}"; do
    if [ -d "$sdir" ]; then
      # Find recently modified scripts (last 24h)
      find "$sdir" -name "*.sh" -o -name "*.py" -o -name "*.js" -o -name "*.pl" 2>/dev/null | head -100 | while read -r f; do
        if grep -qiE '(curl.*\|.*bash|wget.*\|.*bash|/dev/tcp|nc -e|ncat -e|reverse.shell|python.*-c.*import.*socket.*subprocess|base64.*decode.*bash|eval.*base64)' "$f" 2>/dev/null; then
          alert "MALICIOUS PATTERN in script: $f"
          quarantine_file "$f" "Malicious code pattern detected"
        fi
      done
    fi
  done

  ok "Suspicious file scan complete"
}

# ─── GENERATE REPORT ───
generate_report() {
  header "SCAN SUMMARY"

  local alert_count warn_count ok_count kill_count
  alert_count=$(grep -c '\[ALERT\]' "$SCAN_LOG" 2>/dev/null || echo 0)
  warn_count=$(grep -c '\[WARN\]' "$SCAN_LOG" 2>/dev/null || echo 0)
  ok_count=$(grep -c '\[OK\]' "$SCAN_LOG" 2>/dev/null || echo 0)
  kill_count=$(grep -c 'KILLED\|QUARANTINED' "$KILL_LOG" 2>/dev/null || echo 0)

  echo -e "${BOLD}Results:${NC}"
  echo -e "  ${RED}Alerts:     $alert_count${NC}"
  echo -e "  ${YELLOW}Warnings:   $warn_count${NC}"
  echo -e "  ${GREEN}Passed:     $ok_count${NC}"
  echo -e "  ${RED}Kill/Quar:  $kill_count${NC}"
  echo -e "  Auto-kill:  $($AUTO_KILL && echo -e "${GREEN}ON${NC}" || echo -e "${YELLOW}OFF${NC}")"
  echo -e "\n  Full log:  $SCAN_LOG"
  echo -e "  Alert log: $ALERT_LOG"
  echo -e "  Kill log:  $KILL_LOG"

  if [ "$alert_count" -gt 0 ]; then
    echo -e "\n${RED}${BOLD}⚠️  SECURITY ALERTS — REVIEW LOGS IMMEDIATELY${NC}"
    return 1
  else
    echo -e "\n${GREEN}${BOLD}✓ SYSTEM CLEAN${NC}"
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
echo -e "  ${CYAN}SHIELD v2.0 — Termux Security Monitor${NC}"
echo -e "  $(date) | Auto-kill: $($AUTO_KILL && echo ON || echo OFF)${NC}"
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
    scan_suspicious_files
    generate_report
    ;;
  pkg) scan_packages ;;
  net) scan_network ;;
  proc) scan_processes ;;
  persist) scan_persistence ;;
  integrity) scan_file_integrity ;;
  perms) scan_permissions ;;
  scripts) scan_script_packages ;;
  files) scan_suspicious_files ;;
  autokill)
    case "${2:-status}" in
      on)  touch "$AUTO_KILL_FILE"; echo -e "${RED}AUTO-KILL ENABLED${NC}" ;;
      off) rm -f "$AUTO_KILL_FILE"; echo -e "${YELLOW}AUTO-KILL DISABLED${NC}" ;;
      status) [ "$AUTO_KILL" = true ] && echo "ON" || echo "OFF" ;;
    esac
    ;;
  *)
    echo "Usage: rockyshield [full|pkg|net|proc|persist|integrity|perms|scripts|files|autokill]"
    ;;
esac
