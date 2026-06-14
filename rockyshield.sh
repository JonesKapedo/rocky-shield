#!/data/data/com.termux/files/usr/bin/bash
# ROCKY SHIELD v3.0 — Termux Security Monitor
# Single command interface: shield <subcommand>

SHIELD_DIR="$HOME/.rocky-shield"
LOG_DIR="$SHIELD_DIR/logs"
BASELINE_DIR="$SHIELD_DIR/baseline"
QUARANTINE_DIR="$SHIELD_DIR/quarantine"
ALERT_LOG="$LOG_DIR/alerts.log"
KILL_LOG="$LOG_DIR/kills.log"
SCAN_LOG="$LOG_DIR/scan_$(date +%Y%m%d_%H%M%S).log"
PID_FILE="$SHIELD_DIR/shield.pid"
MON_PID_FILE="$SHIELD_DIR/monitor.pid"
WATCHDOG_PID_FILE="$SHIELD_DIR/watchdog.pid"
AUTO_KILL_FILE="$SHIELD_DIR/autokill.enabled"
AUTH_FILE="$SHIELD_DIR/authorized.list"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

mkdir -p "$LOG_DIR" "$BASELINE_DIR" "$QUARANTINE_DIR"
touch "$ALERT_LOG" "$KILL_LOG" "$AUTH_FILE"

AUTO_KILL=false
[ -f "$AUTO_KILL_FILE" ] && AUTO_KILL=true

log()   { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$SCAN_LOG"; }
alert() { echo -e "${RED}[ALERT]${NC} $1" | tee -a "$SCAN_LOG" "$ALERT_LOG"; echo; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$SCAN_LOG"; }
ok()    { echo -e "${GREEN}[OK]${NC} $1" | tee -a "$SCAN_LOG"; }
info()  { echo -e "${CYAN}[INFO]${NC} $1" | tee -a "$SCAN_LOG"; }
header(){ echo -e "\n${BOLD}══════════════════════════════════════\n $1\n══════════════════════════════════════${NC}" | tee -a "$SCAN_LOG"; }

# ─── Check if package/tool is authorized ───
is_authorized() {
  grep -qi "^$1$" "$AUTH_FILE" 2>/dev/null
}

# ─── KILL FUNCTION ───
kill_suspicious() {
  local pid="$1" name="$2" reason="$3"
  [ -z "$pid" ] && return
  [ "$pid" = "$$" ] && return
  [ "$pid" = "1" ] && return
  [ "$pid" = "$(cat "$MON_PID_FILE" 2>/dev/null)" ] && return
  [ "$pid" = "$(cat "$WATCHDOG_PID_FILE" 2>/dev/null)" ] && return

  if is_authorized "$name"; then
    warn "SKIPPED authorized tool: $name (PID $pid)"
    return
  fi

  if [ "$AUTO_KILL" = true ]; then
    kill -TERM "$pid" 2>/dev/null
    sleep 1
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null
      log "FORCE KILLED PID $pid ($name) — $reason"
    else
      log "KILLED PID $pid ($name) — $reason"
    fi
    echo "[$(date '+%H:%M:%S')] KILLED PID $pid ($name) — $reason" >> "$KILL_LOG"
    command -v termux-notification &>/dev/null && \
      termux-notification --title "🛡️ Shield Killed" \
        --content "Killed: $name (PID $pid)" --priority high --id shield-kill
  else
    warn "Would kill PID $pid ($name) — $reason (auto-kill off)"
  fi
}

# ─── QUARANTINE FUNCTION ───
quarantine_file() {
  local filepath="$1" reason="$2"
  [ ! -f "$filepath" ] && return
  local qf="$QUARANTINE_DIR/$(basename "$filepath").$(date +%s)"
  cp "$filepath" "$qf" 2>/dev/null
  chmod 000 "$qf" 2>/dev/null
  rm -f "$filepath" 2>/dev/null
  log "QUARANTINED: $filepath → $qf — $reason"
  echo "[$(date '+%H:%M:%S')] QUARANTINED: $filepath — $reason" >> "$KILL_LOG"
  command -v termux-notification &>/dev/null && \
    termux-notification --title "🛡️ Quarantined" \
      --content "$(basename "$filepath") — $reason" --priority high --id shield-quar
}

# ═══════════════════════════════════════════
# SCAN FUNCTIONS
# ═══════════════════════════════════════════

scan_packages() {
  header "PACKAGE AUDIT"
  local pkg_list="$BASELINE_DIR/packages.list"
  dpkg -l 2>/dev/null | grep '^ii' | awk '{print $2, $3}' | sort > /tmp/shield_cur_pkgs

  if [ -f "$pkg_list" ]; then
    comm -23 "$pkg_list" /tmp/shield_cur_pkgs | while read -r line; do
      local pkgname=$(echo "$line" | awk '{print $1}')
      if is_authorized "$pkgname"; then
        info "Authorized package installed: $pkgname"
      else
        alert "NEW package: $line"
        if echo "$pkgname" | grep -qiE '(hack|exploit|crack|keylogger|sniff|spoof|backdoor|rootkit|trojan|reverse|payload)'; then
          alert "DANGEROUS: $pkgname"
          [ "$AUTO_KILL" = true ] && dpkg --purge "$pkgname" 2>/dev/null && ok "Removed: $pkgname"
        fi
      fi
    done
    comm -13 "$pkg_list" /tmp/shield_cur_pkgs | while read -r line; do warn "Removed: $line"; done
    cp /tmp/shield_cur_pkgs "$pkg_list"
  else
    info "Creating package baseline ($(wc -l < /tmp/shield_cur_pkgs) packages)"
    cp /tmp/shield_cur_pkgs "$pkg_list"
  fi
  grep -iE '(hack|exploit|crack|keylogger|sniff|spoof|backdoor|rootkit|trojan)' /tmp/shield_cur_pkgs | while read -r line; do
    local pn=$(echo "$line" | awk '{print $1}')
    is_authorized "$pn" || alert "Suspicious package: $line"
  done
}

scan_network() {
  header "NETWORK MONITOR"
  if command -v ss &>/dev/null; then
    ss -tlnp 2>/dev/null | grep -v "127\.0\.0\.1\|::1" | while read -r line; do
      port=$(echo "$line" | grep -oP ':\K\d+' | tail -1)
      [ -z "$port" ] && continue
      pid=$(echo "$line" | grep -oP 'pid=\K[0-9]+' | head -1)
      [ -n "$pid" ] && kill_suspicious "$pid" "port-$port" "External listener port $port"
      alert "External listener port $port"
    done
    ss -tnp 2>/dev/null | grep ESTAB | grep -E ':(4444|5555|6666|7777|8888|9999|1337|31337|12345|54321) ' | while read -r line; do
      alert "Suspicious outbound (C2 port): $line"
      pid=$(echo "$line" | grep -oP 'pid=\K[0-9]+' | head -1)
      [ -n "$pid" ] && kill_suspicious "$pid" "c2-conn" "C2 connection"
    done
  fi
  ok "Network scan done"
}

scan_processes() {
  header "PROCESS AUDIT"
  ps -eo pid,comm,args --no-headers 2>/dev/null > /tmp/shield_cur_procs
  local SUSPICIOUS='nc$|ncat$|netcat$|nmap$|hydra$|aircrack|ettercap$|john$|hashcat$|sqlmap$|msfconsole$|msfvenom$|xmrig|minerd$|stratum$|slowloris$|hping3$|arpspoof$|dsniff$|reaver$|wifite$'
  ps -eo pid,comm,args --no-headers 2>/dev/null | grep -iE "$SUSPICIOUS" | while read -r pid comm args; do
    kill_suspicious "$pid" "$comm" "Malicious tool: $comm"
  done
  ps -eo pid,comm,args --no-headers 2>/dev/null | \
    grep -iE '(/dev/tcp|/dev/udp|bash -i|sh -i|python.*-c.*socket.*subprocess|perl.*-c.*socket|nc -e|ncat -e)' | \
    while read -r pid comm args; do
      kill_suspicious "$pid" "$comm" "Reverse shell: $args"
    done
  ps -eo pid,comm,args --no-headers 2>/dev/null | \
    grep -iE '(xmrig|minerd|stratum|cpuminer|ccminer|ethminer|nicehash)' | \
    while read -r pid comm args; do
      kill_suspicious "$pid" "$comm" "Crypto miner: $comm"
    done
  local zc=$(ps aux 2>/dev/null | awk '$8 ~ /Z/' | wc -l)
  [ "$zc" -gt 0 ] && warn "$zc zombie process(es)" || ok "No zombies"
}

scan_persistence() {
  header "PERSISTENCE CHECK"
  if command -v crontab &>/dev/null; then
    local ce=$(crontab -l 2>/dev/null)
    if [ -n "$ce" ] && ! echo "$ce" | grep -q "^no crontab"; then
      echo "$ce" | while read -r line; do
        echo "  ⏰ $line" | tee -a "$SCAN_LOG"
        if echo "$line" | grep -qiE '(curl.*\|.*bash|wget.*\|.*bash|/dev/tcp|nc |ncat )'; then
          alert "DANGEROUS cron: $line"
          [ "$AUTO_KILL" = true ] && crontab -r 2>/dev/null && ok "Crontab cleared"
        fi
      done
    else
      ok "No crontab entries"
    fi
  fi
  local bd="$HOME/.termux/boot"
  [ -d "$bd" ] && find "$bd" -type f 2>/dev/null | while read -r f; do
    if grep -qiE '(curl.*\|.*bash|wget.*\|.*bash|/dev/tcp|rm -rf /)' "$f" 2>/dev/null; then
      alert "Malicious boot script: $f"
      quarantine_file "$f" "Malicious boot script"
    fi
  done
  for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    [ -f "$rc" ] && grep -qiE '(curl.*\|.*bash|wget.*\|.*bash|/dev/tcp|nc -e|base64.*decode.*bash|eval.*base64)' "$rc" 2>/dev/null && \
      { alert "Injected shell profile: $rc"; quarantine_file "$rc" "Profile injection"; }
  done
  ok "Persistence scan done"
}

scan_integrity() {
  header "FILE INTEGRITY"
  local hf="$BASELINE_DIR/hashes.sha256"
  local ch="/tmp/shield_cur_hash"
  for p in /data/data/com.termux/files/usr/bin /data/data/com.termux/files/usr/lib; do
    [ -d "$p" ] && find "$p" -type f -executable 2>/dev/null | head -500 | while read -r f; do sha256sum "$f" 2>/dev/null; done
  done | sort > "$ch"
  if [ -f "$hf" ]; then
    local changed=$(comm -23 <(sort "$hf") <(sort "$ch"))
    [ -n "$changed" ] && { alert "MODIFIED files:"; echo "$changed" | while read -r l; do echo "  ✏️  $l"; done; } || ok "No file tampering"
    cp "$ch" "$hf"
  else
    info "Creating integrity baseline ($(wc -l < "$ch") files)"
    cp "$ch" "$hf"
  fi
  find /data/data/com.termux/files/usr -name ".*" -type f -executable 2>/dev/null | while read -r f; do
    alert "Hidden executable: $f"; quarantine_file "$f" "Hidden executable"
  done
}

scan_permissions() {
  header "PERMISSION AUDIT"
  local ww=$(find /data/data/com.termux/files/usr/bin -type f -perm -002 2>/dev/null | head -20)
  if [ -n "$ww" ]; then
    echo "$ww" | while read -r f; do chmod o-w "$f" 2>/dev/null && ok "Fixed: $f"; done
  else
    ok "No world-writable executables"
  fi
  local suid=$(find /data/data/com.termux/files/usr -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -20)
  if [ -n "$suid" ]; then
    echo "$suid" | while read -r f; do chmod u-s,g-s "$f" 2>/dev/null && ok "Removed SUID: $f"; done
  else
    ok "No unexpected SUID/SGID"
  fi
}

scan_scripts() {
  header "SCRIPT PACKAGE AUDIT"
  if command -v pip &>/dev/null; then
    pip list --format=freeze 2>/dev/null | grep -iE '(backdoor|exploit|hack|keylogger|steal|trojan|evil|malicious)' | while read -r line; do
      alert "Suspicious pip: $line"
      local pn=$(echo "$line" | cut -d= -f1)
      [ "$AUTO_KILL" = true ] && pip uninstall -y "$pn" 2>/dev/null && ok "Removed: $pn"
    done
    info "pip packages: $(pip list 2>/dev/null | tail -n +3 | wc -l)"
  fi
}

scan_files() {
  header "SUSPICIOUS FILE SCAN"
  for sd in "$HOME" /data/data/com.termux/files/usr/bin /data/data/com.termux/files/usr/etc; do
    [ -d "$sd" ] && find "$sd" \( -name "*.sh" -o -name "*.py" -o -name "*.js" -o -name "*.pl" \) 2>/dev/null | head -100 | while read -r f; do
      if grep -qiE '(curl.*\|.*bash|wget.*\|.*bash|/dev/tcp|nc -e|ncat -e|reverse.shell|python.*-c.*import.*socket.*subprocess|base64.*decode.*bash|eval.*base64)' "$f" 2>/dev/null; then
        alert "Malicious pattern in: $f"
        quarantine_file "$f" "Malicious code pattern"
      fi
    done
  done
  ok "File scan done"
}

generate_report() {
  header "SCAN SUMMARY"
  local ac=$(grep -c '\[ALERT\]' "$SCAN_LOG" 2>/dev/null || echo 0)
  local wc=$(grep -c '\[WARN\]' "$SCAN_LOG" 2>/dev/null || echo 0)
  local oc=$(grep -c '\[OK\]' "$SCAN_LOG" 2>/dev/null || echo 0)
  local kc=$(grep -c 'KILLED\|QUARANTINED' "$KILL_LOG" 2>/dev/null || echo 0)
  echo -e "${BOLD}Results:${NC}"
  echo -e "  ${RED}Alerts:   $ac${NC}"
  echo -e "  ${YELLOW}Warnings: $wc${NC}"
  echo -e "  ${GREEN}Passed:   $oc${NC}"
  echo -e "  ${RED}Killed:   $kc${NC}"
  echo -e "  Auto-kill: $([ "$AUTO_KILL" = true ] && echo -e "${GREEN}ON${NC}" || echo -e "${YELLOW}OFF${NC}")"
  echo -e "\n  Log: $SCAN_LOG"
  [ "$ac" -gt 0 ] && echo -e "\n${RED}${BOLD}⚠️  ALERTS FOUND — REVIEW LOGS${NC}" || echo -e "\n${GREEN}${BOLD}✓ SYSTEM CLEAN${NC}"
}

# ═══════════════════════════════════════════
# MONITOR (real-time daemon)
# ═══════════════════════════════════════════
start_monitor() {
  nohup bash -c '
    SHIELD_DIR="$HOME/.rocky-shield"
    LOG="$SHIELD_DIR/logs/realtime.log"
    KILL_LOG="$SHIELD_DIR/logs/kills.log"
    PID_FILE="$SHIELD_DIR/monitor.pid"
    AK_FILE="$SHIELD_DIR/autokill.enabled"
    AUTH_FILE="$SHIELD_DIR/authorized.list"
    echo $$ > "$PID_FILE"
    AK=false; [ -f "$AK_FILE" ] && AK=true
    dpkg -l 2>/dev/null | grep "^ii" | awk "{print \$2}" | sort > /tmp/sh_rt_pkgs
    ss -tlnp 2>/dev/null | awk "{print \$4}" | sort > /tmp/sh_rt_listen 2>/dev/null || touch /tmp/sh_rt_listen
    log() { echo "[$(date +%H:%M:%S)] $1" >> "$LOG"; }
    is_auth() { grep -qi "^$1$" "$AUTH_FILE" 2>/dev/null; }
    kill_it() {
      local pid="$1" name="$2" reason="$3"
      [ -z "$pid" ] || [ "$pid" = "$$" ] || [ "$pid" = "1" ] && return
      is_auth "$name" && { log "SKIPPED auth: $name (PID $pid)"; return; }
      if [ "$AK" = true ]; then
        kill -TERM "$pid" 2>/dev/null; sleep 1
        kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null && log "FORCE KILLED $pid ($name) — $reason"
        kill -0 "$pid" 2>/dev/null || log "KILLED $pid ($name) — $reason"
        echo "[$(date +%H:%M:%S)] KILLED $pid ($name) — $reason" >> "$KILL_LOG"
        command -v termux-notification &>/dev/null && termux-notification --title "🛡️ Killed" --content "$name (PID $pid)" --priority high --id shield-kill
      else
        log "WOULD KILL $pid ($name) — $reason"
      fi
    }
    log "Monitor started (PID: $$, auto-kill: $AK)"
    while true; do
      sleep 30
      AK=false; [ -f "$AK_FILE" ] && AK=true
      # New packages
      dpkg -l 2>/dev/null | grep "^ii" | awk "{print \$2}" | sort > /tmp/sh_new_pkgs
      comm -23 /tmp/sh_new_pkgs /tmp/sh_rt_pkgs | while read -r p; do
        log "NEW PKG: $p"
        echo "$p" | grep -qiE "(hack|exploit|crack|keylogger|backdoor|rootkit|trojan|payload)" && {
          log "DANGEROUS PKG: $p"
          [ "$AK" = true ] && dpkg --purge "$p" 2>/dev/null && log "REMOVED: $p"
          command -v termux-notification &>/dev/null && termux-notification --title "🛡️ Dangerous Pkg" --content "$p" --priority high --id shield-pkg
        }
      done
      mv /tmp/sh_new_pkgs /tmp/sh_rt_pkgs
      # Malicious processes
      SUSP="nc$|ncat$|netcat$|nmap$|hydra$|aircrack|ettercap$|john$|hashcat$|sqlmap$|msfconsole$|msfvenom$|xmrig|minerd$|stratum$|slowloris$|hping3$|arpspoof$|dsniff$|reaver$|wifite$"
      ps -eo pid,comm,args --no-headers 2>/dev/null | grep -iE "$SUSP" | while read -r pid comm args; do kill_it "$pid" "$comm" "Malicious tool"; done
      ps -eo pid,comm,args --no-headers 2>/dev/null | grep -iE "(/dev/tcp|/dev/udp|bash -i|sh -i|python.*-c.*socket.*subprocess|nc -e|ncat -e)" | while read -r pid comm args; do kill_it "$pid" "$comm" "Reverse shell"; done
      ps -eo pid,comm,args --no-headers 2>/dev/null | grep -iE "(xmrig|minerd|stratum|cpuminer|ccminer|ethminer|nicehash)" | while read -r pid comm args; do kill_it "$pid" "$comm" "Crypto miner"; done
      # New listeners
      ss -tlnp 2>/dev/null | awk "{print \$4}" | sort > /tmp/sh_new_listen 2>/dev/null || touch /tmp/sh_new_listen
      comm -23 /tmp/sh_new_listen /tmp/sh_rt_listen | while read -r port; do
        [ -z "$port" ] && continue
        echo "$port" | grep -qvE "127\.0\.0\.1|::1" && {
          log "NEW LISTENER: $port"
          pid=$(ss -tlnp 2>/dev/null | grep "$port" | grep -oP "pid=\K[0-9]+" | head -1)
          [ -n "$pid" ] && kill_it "$pid" "listener-$port" "External listener"
        }
      done
      mv /tmp/sh_new_listen /tmp/sh_rt_listen
      # C2 outbound
      ss -tnp 2>/dev/null | grep ESTAB | grep -E ":(4444|5555|6666|7777|8888|9999|1337|31337|12345|54321) " | while read -r line; do
        pid=$(echo "$line" | grep -oP "pid=\K[0-9]+" | head -1)
        [ -n "$pid" ] && kill_it "$pid" "c2" "C2 connection"
      done
      # Boot/profile tampering
      for f in "$HOME/.termux/boot/"*; do
        [ -f "$f" ] && [ "$f" -nt "$PID_FILE" ] 2>/dev/null && {
          grep -qiE "(curl.*\|.*bash|wget.*\|.*bash|/dev/tcp|nc -e)" "$f" 2>/dev/null && {
            qf="$SHIELD_DIR/quarantine/$(basename "$f").$(date +%s)"
            cp "$f" "$qf" 2>/dev/null; chmod 000 "$qf"; rm -f "$f"
            log "QUARANTINED boot script: $f"
          }
        }
      done
      for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
        [ -f "$rc" ] && [ "$rc" -nt "$PID_FILE" ] 2>/dev/null && {
          grep -qiE "(curl.*\|.*bash|wget.*\|.*bash|/dev/tcp|nc -e|reverse)" "$rc" 2>/dev/null && {
            qf="$SHIELD_DIR/quarantine/$(basename "$rc").$(date +%s)"
            cp "$rc" "$qf" 2>/dev/null; chmod 000 "$qf"; rm -f "$rc"
            log "QUARANTINED profile: $rc"
          }
        }
      done
    done
  ' > /dev/null 2>&1 &
  echo $! > "$MON_PID_FILE"
  echo -e "${GREEN}✓ Monitor started (PID: $(cat "$MON_PID_FILE"))${NC}"
}

stop_monitor() {
  local stopped=""
  if [ -f "$MON_PID_FILE" ]; then
    local mpid=$(cat "$MON_PID_FILE")
    kill "$mpid" 2>/dev/null && stopped="monitor"
    rm -f "$MON_PID_FILE"
  fi
  if [ -f "$WATCHDOG_PID_FILE" ]; then
    local wpid=$(cat "$WATCHDOG_PID_FILE")
    kill "$wpid" 2>/dev/null && stopped="$stopped watchdog"
    rm -f "$WATCHDOG_PID_FILE"
  fi
  # Also kill any leftover monitor processes
  pkill -f "shield.*monitor" 2>/dev/null
  [ -n "$stopped" ] && echo -e "${GREEN}✓ Stopped: $stopped${NC}" || echo -e "${YELLOW}No monitor running${NC}"
}

# ═══════════════════════════════════════════
# MAIN COMMAND DISPATCHER
# ═══════════════════════════════════════════

clear 2>/dev/null
echo -e "${BOLD}"
echo "  ██████╗  ██████╗  ██████╗██╗  ██╗██╗   ██╗"
echo "  ██╔══██╗██╔═══██╗██╔════╝██║ ██╔╝╚██╗ ██╔╝"
echo "  ██████╔╝██║   ██║██║     █████╔╝  ╚████╔╝ "
echo "  ██╔══██╗██║   ██║██║     ██╔═██╗   ╚██╔╝  "
echo "  ██║  ██║╚██████╔╝╚██████╗██║  ██╗   ██║   "
echo "  ╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝   ╚═╝   "
echo -e "  ${CYAN}SHIELD v3.0 — Termux Security${NC}${NC}"
echo -e "  $(date) | Auto-kill: $([ "$AUTO_KILL" = true ] && echo ON || echo OFF)${NC}"
echo ""

case "${1:-full}" in
  # ── Full scan ──
  full|scan)
    scan_packages; scan_network; scan_processes; scan_persistence
    scan_integrity; scan_permissions; scan_scripts; scan_files
    generate_report
    ;;

  # ── Quick scan (processes + network only) ──
  quick)
    scan_processes; scan_network
    generate_report
    ;;

  # ── Individual scans ──
  pkg|packages)    scan_packages ;;
  net|network)     scan_network ;;
  proc|processes)  scan_processes ;;
  persist)         scan_persistence ;;
  integrity)       scan_integrity ;;
  perms)           scan_permissions ;;
  scripts)         scan_scripts ;;
  files)           scan_files ;;

  # ── Monitor control ──
  start)
    start_monitor
    ;;
  stop)
    stop_monitor
    ;;
  restart)
    stop_monitor
    sleep 2
    start_monitor
    ;;
  status)
    echo -e "${BOLD}Shield Status:${NC}"
    if [ -f "$MON_PID_FILE" ] && kill -0 "$(cat "$MON_PID_FILE")" 2>/dev/null; then
      echo -e "  Monitor:  ${GREEN}RUNNING${NC} (PID $(cat "$MON_PID_FILE"))"
    else
      echo -e "  Monitor:  ${RED}STOPPED${NC}"
    fi
    if [ -f "$WATCHDOG_PID_FILE" ] && kill -0 "$(cat "$WATCHDOG_PID_FILE")" 2>/dev/null; then
      echo -e "  Watchdog: ${GREEN}RUNNING${NC} (PID $(cat "$WATCHDOG_PID_FILE"))"
    else
      echo -e "  Watchdog: ${RED}STOPPED${NC}"
    fi
    echo -e "  Auto-kill: $([ "$AUTO_KILL" = true ] && echo -e "${GREEN}ON${NC}" || echo -e "${YELLOW}OFF${NC}")"
    echo -e "  Authorized: $(wc -l < "$AUTH_FILE" 2>/dev/null || echo 0) tools"
    echo -e "  Alerts: $(grep -c '\[ALERT\]' "$ALERT_LOG" 2>/dev/null || echo 0)"
    echo -e "  Kills:  $(grep -c 'KILLED\|QUARANTINED' "$KILL_LOG" 2>/dev/null || echo 0)"
    ;;

  # ── Auto-kill toggle ──
  autokill)
    case "${2:-status}" in
      on)   touch "$AUTO_KILL_FILE"; echo -e "${RED}AUTO-KILL ENABLED${NC}" ;;
      off)  rm -f "$AUTO_KILL_FILE"; echo -e "${YELLOW}AUTO-KILL DISABLED${NC}" ;;
      *)    [ "$AUTO_KILL" = true ] && echo "ON" || echo "OFF" ;;
    esac
    ;;

  # ── Authorize a tool/package (whitelist) ──
  authorize)
    if [ -z "$2" ]; then
      echo -e "${BOLD}Authorized tools:${NC}"
      cat "$AUTH_FILE" 2>/dev/null | while read -r t; do echo "  ✓ $t"; done
      echo ""
      echo "Usage: shield authorize <toolname>"
      echo "Example: shield authorize nmap"
    else
      local tool=$(echo "$2" | tr '[:upper:]' '[:lower:]')
      if is_authorized "$tool"; then
        echo -e "${YELLOW}$tool is already authorized${NC}"
      else
        echo "$tool" >> "$AUTH_FILE"
        echo -e "${GREEN}✓ Authorized: $tool${NC}"
        echo -e "  Shield will NOT kill or flag this tool."
      fi
    fi
    ;;

  # ── Revoke authorization ──
  revoke)
    if [ -z "$2" ]; then
      echo -e "${BOLD}Authorized tools:${NC}"
      cat "$AUTH_FILE" 2>/dev/null | while read -r t; do echo "  ✓ $t"; done
      echo ""
      echo "Usage: shield revoke <toolname>"
    else
      local tool=$(echo "$2" | tr '[:upper:]' '[:lower:]')
      if is_authorized "$tool"; then
        sed -i "/^${tool}$/d" "$AUTH_FILE"
        echo -e "${RED}✓ Revoked: $tool${NC}"
        echo -e "  Shield will now monitor this tool."
      else
        echo -e "${YELLOW}$tool is not in the authorized list${NC}"
      fi
    fi
    ;;

  # ── View logs ──
  logs)
    echo -e "${BOLD}── Recent Alerts ──${NC}"
    tail -30 "$ALERT_LOG" 2>/dev/null || echo "No alerts yet"
    echo ""
    echo -e "${BOLD}── Recent Kills/Quarantines ──${NC}"
    tail -20 "$KILL_LOG" 2>/dev/null || echo "No kills yet"
    ;;

  # ── Quarantine management ──
  quarantine)
    echo -e "${BOLD}Quarantined files:${NC}"
    ls -la "$QUARANTINE_DIR" 2>/dev/null || echo "  (empty)"
    echo ""
    echo "Restore: shield restore <filename>"
    ;;
  restore)
    if [ -z "$2" ]; then
      echo "Usage: shield restore <filename>"
      ls "$QUARANTINE_DIR" 2>/dev/null
    else
      local qf=$(find "$QUARANTINE_DIR" -name "$2*" -type f 2>/dev/null | head -1)
      if [ -n "$qf" ]; then
        local orig="$HOME/$(basename "$2")"
        cp "$qf" "$orig" 2>/dev/null
        chmod 644 "$orig" 2>/dev/null
        echo -e "${GREEN}✓ Restored: $orig${NC}"
      else
        echo -e "${RED}Not found in quarantine${NC}"
      fi
    fi
    ;;

  # ── Help ──
  help|--help|-h)
    echo -e "${BOLD}SHIELD v3.0 — Commands${NC}"
    echo ""
    echo -e "  ${CYAN}Scans:${NC}"
    echo "    shield              Full 8-layer scan"
    echo "    shield quick        Quick scan (processes + network)"
    echo "    shield pkg          Package audit"
    echo "    shield net          Network monitor"
    echo "    shield proc         Process audit"
    echo "    shield persist      Persistence check"
    echo "    shield integrity    File integrity"
    echo "    shield perms        Permission audit"
    echo "    shield scripts      Python/Node audit"
    echo "    shield files        Suspicious file scan"
    echo ""
    echo -e "  ${CYAN}Monitor:${NC}"
    echo "    shield start        Start real-time monitor"
    echo "    shield stop         Stop monitor + watchdog"
    echo "    shield restart      Restart monitor"
    echo "    shield status       Show status"
    echo ""
    echo -e "  ${CYAN}Authorization:${NC}"
    echo "    shield authorize <tool>   Whitelist a tool (won't be killed)"
    echo "    shield authorize          List authorized tools"
    echo "    shield revoke <tool>      Remove from whitelist"
    echo ""
    echo -e "  ${CYAN}Other:${NC}"
    echo "    shield autokill on|off    Toggle auto-kill"
    echo "    shield logs               View alerts + kills"
    echo "    shield quarantine         List quarantined files"
    echo "    shield restore <file>     Restore quarantined file"
    ;;

  *)
    echo "Unknown command: $1"
    echo "Run 'shield help' for commands"
    ;;
esac
