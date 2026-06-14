#!/data/data/com.termux/files/usr/bin/bash
# ROCKY SHIELD — Real-Time Monitor Daemon v2.0
# Watches for suspicious activity every 30 seconds and AUTO-KILLS threats

SHIELD_DIR="$HOME/.rocky-shield"
LOG_FILE="$SHIELD_DIR/logs/realtime.log"
KILL_LOG="$SHIELD_DIR/logs/kills.log"
PID_FILE="$SHIELD_DIR/monitor.pid"
AUTO_KILL_FILE="$SHIELD_DIR/autokill.enabled"
CHECK_INTERVAL=30

mkdir -p "$SHIELD_DIR/logs"

AUTO_KILL=false
[ -f "$AUTO_KILL_FILE" ] && AUTO_KILL=true

echo $$ > "$PID_FILE"

# Initial snapshots
dpkg -l 2>/dev/null | grep '^ii' | awk '{print $2}' | sort > /tmp/shield_rt_pkgs
ps -eo pid,comm,args --no-headers 2>/dev/null > /tmp/shield_rt_procs
ss -tlnp 2>/dev/null | awk '{print $4}' | sort > /tmp/shield_rt_listen 2>/dev/null || touch /tmp/shield_rt_listen

log() { echo "[$(date '+%H:%M:%S')] $1" >> "$LOG_FILE"; }
kill_it() {
  local pid="$1" name="$2" reason="$3"
  [ -z "$pid" ] && return
  [ "$pid" = "$$" ] && return
  [ "$pid" = "1" ] && return
  [ "$pid" = "$(cat "$PID_FILE" 2>/dev/null)" ] && return

  if [ "$AUTO_KILL" = true ]; then
    kill -TERM "$pid" 2>/dev/null
    sleep 1
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null && log "FORCE KILLED PID $pid ($name) — $reason"
    kill -0 "$pid" 2>/dev/null || log "KILLED PID $pid ($name) — $reason"
    echo "[$(date '+%H:%M:%S')] KILLED PID $pid ($name) — $reason" >> "$KILL_LOG"

    command -v termux-notification &>/dev/null && \
      termux-notification --title "🛡️ Shield Killed Process" \
        --content "Killed: $name (PID $pid) — $reason" \
        --priority high --id shield-kill
  else
    log "WOULD KILL PID $pid ($name) — $reason (auto-kill off)"
  fi
}

log "Monitor started (PID: $$, interval: ${CHECK_INTERVAL}s, auto-kill: $AUTO_KILL)"

while true; do
  sleep "$CHECK_INTERVAL"

  # Reload auto-kill setting
  AUTO_KILL=false
  [ -f "$AUTO_KILL_FILE" ] && AUTO_KILL=true

  # ── 1. New packages ──
  dpkg -l 2>/dev/null | grep '^ii' | awk '{print $2}' | sort > /tmp/shield_new_pkgs
  new=$(comm -23 /tmp/shield_new_pkgs /tmp/shield_rt_pkgs)
  if [ -n "$new" ]; then
    echo "$new" | while read -r p; do
      log "NEW PACKAGE: $p"
      if echo "$p" | grep -qiE '(hack|exploit|crack|keylogger|backdoor|rootkit|trojan|reverse|payload)'; then
        log "DANGEROUS PACKAGE: $p"
        if [ "$AUTO_KILL" = true ]; then
          dpkg --purge "$p" 2>/dev/null && log "REMOVED: $p"
        fi
        command -v termux-notification &>/dev/null && \
          termux-notification --title "🛡️ Dangerous Package!" \
            --content "Detected: $p" --priority high --id shield-pkg
      fi
    done
  fi
  mv /tmp/shield_new_pkgs /tmp/shield_rt_pkgs

  # ── 2. Suspicious processes ──
  local SUSPICIOUS='nc$|ncat$|netcat$|nmap$|hydra$|aircrack|ettercap$|tcpdump$|john$|hashcat$|sqlmap$|msfconsole$|msfvenom$|xmrig|minerd$|stratum$|cpuminer$|slowloris$|hping3$|arpspoof$|dsniff$|reaver$|wifite$'
  ps -eo pid,comm,args --no-headers 2>/dev/null | grep -iE "$SUSPICIOUS" | while read -r pid comm args; do
    kill_it "$pid" "$comm" "Malicious tool: $comm"
  done

  # Reverse shells
  ps -eo pid,comm,args --no-headers 2>/dev/null | \
    grep -iE '(/dev/tcp|/dev/udp|bash -i|sh -i|python.*-c.*socket.*subprocess|perl.*-c.*socket|nc -e|ncat -e)' | \
    while read -r pid comm args; do
      kill_it "$pid" "$comm" "Reverse shell: $args"
    done

  # Crypto miners
  ps -eo pid,comm,args --no-headers 2>/dev/null | \
    grep -iE '(xmrig|minerd|stratum|cpuminer|ccminer|ethminer|nicehash)' | \
    while read -r pid comm args; do
      kill_it "$pid" "$comm" "Crypto miner: $comm"
    done

  # ── 3. New listeners ──
  ss -tlnp 2>/dev/null | awk '{print $4}' | sort > /tmp/shield_new_listen 2>/dev/null || touch /tmp/shield_new_listen
  comm -23 /tmp/shield_new_listen /tmp/shield_rt_listen | while read -r port; do
    [ -z "$port" ] && continue
    if echo "$port" | grep -qvE '127\.0\.0\.1|::1'; then
      log "NEW EXTERNAL LISTENER: $port"
      pid=$(ss -tlnp 2>/dev/null | grep "$port" | grep -oP 'pid=\K[0-9]+' | head -1)
      [ -n "$pid" ] && kill_it "$pid" "listener-$port" "New external listener on $port"
    fi
  done
  mv /tmp/shield_new_listen /tmp/shield_rt_listen

  # ── 4. Suspicious outbound (C2 ports) ──
  ss -tnp 2>/dev/null | grep ESTAB | grep -E ':(4444|5555|6666|7777|8888|9999|1337|31337|12345|54321) ' | \
    while read -r line; do
      log "SUSPICIOUS OUTBOUND: $line"
      pid=$(echo "$line" | grep -oP 'pid=\K[0-9]+' | head -1)
      [ -n "$pid" ] && kill_it "$pid" "c2-connection" "C2 port connection"
    done

  # ── 5. Boot script tampering ──
  BOOT_DIR="$HOME/.termux/boot"
  [ -d "$BOOT_DIR" ] && find "$BOOT_DIR" -newer "$PID_FILE" -type f 2>/dev/null | while read -r f; do
    log "BOOT SCRIPT MODIFIED: $f"
    if grep -qiE '(curl.*\|.*bash|wget.*\|.*bash|/dev/tcp|nc -e)' "$f" 2>/dev/null; then
      log "MALICIOUS BOOT SCRIPT: $f"
      qf="$SHIELD_DIR/quarantine/$(basename "$f").$(date +%s)"
      cp "$f" "$qf" 2>/dev/null; chmod 000 "$qf" 2>/dev/null; rm -f "$f" 2>/dev/null
      log "QUARANTINED: $f → $qf"
    fi
  done

  # ── 6. Shell profile tampering ──
  for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    if [ -f "$rc" ] && [ "$rc" -nt "$PID_FILE" ]; then
      log "PROFILE MODIFIED: $rc"
      if grep -qiE '(curl.*\|.*bash|wget.*\|.*bash|/dev/tcp|nc -e|reverse)' "$rc" 2>/dev/null; then
        log "MALICIOUS PROFILE: $rc"
        qf="$SHIELD_DIR/quarantine/$(basename "$rc").$(date +%s)"
        cp "$rc" "$qf" 2>/dev/null; chmod 000 "$qf" 2>/dev/null; rm -f "$rc" 2>/dev/null
        log "QUARANTINED: $rc → $qf"
      fi
    fi
  done

done
