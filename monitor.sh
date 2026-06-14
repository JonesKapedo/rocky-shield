#!/data/data/com.termux/files/usr/bin/bash
# ROCKY SHIELD — Real-Time Monitor Daemon
# Watches for: new installs, file changes, new network connections, suspicious processes
# Runs in background, logs to ~/.rocky-shield/logs/realtime.log

SHIELD_DIR="$HOME/.rocky-shield"
LOG_FILE="$SHIELD_DIR/logs/realtime.log"
PID_FILE="$SHIELD_DIR/monitor.pid"
CHECK_INTERVAL=30  # seconds between checks

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

mkdir -p "$SHIELD_DIR/logs"

log() { echo "[$(date '+%H:%M:%S')] $1" >> "$LOG_FILE"; }
alert() { echo -e "${RED}[ALERT]${NC} $1" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"; }

# Save PID
echo $$ > "$PID_FILE"

# Initial snapshots
SNAP_PACKAGES="/tmp/shield_snap_pkgs"
SNAP_PROCS="/tmp/shield_snap_procs"
SNAP_LISTEN="/tmp/shield_snap_listen"

dpkg -l 2>/dev/null | grep '^ii' | awk '{print $2}' | sort > "$SNAP_PACKAGES"
ps -eo comm --no-headers 2>/dev/null | sort > "$SNAP_PROCS"
ss -tlnp 2>/dev/null | awk '{print $4}' | sort > "$SNAP_LISTEN" 2>/dev/null || touch "$SNAP_LISTEN"

log "Monitor started (PID: $$, interval: ${CHECK_INTERVAL}s)"

# ─── MONITOR LOOP ───
while true; do
  sleep "$CHECK_INTERVAL"

  # 1. Check for new/removed packages
  dpkg -l 2>/dev/null | grep '^ii' | awk '{print $2}' | sort > /tmp/shield_new_pkgs
  new=$(comm -23 /tmp/shield_new_pkgs "$SNAP_PACKAGES")
  removed=$(comm -13 /tmp/shield_new_pkgs "$SNAP_PACKAGES")
  if [ -n "$new" ]; then
    echo "$new" | while read -r p; do
      alert "PACKAGE INSTALLED: $p"
      # Auto-scan the new package
      dpkg -L "$p" 2>/dev/null | grep -E '(/bin/|/lib.*\.so)' | head -10 | while read -r f; do
        warn "  → Installed file: $f"
      done
    done
  fi
  if [ -n "$removed" ]; then
    echo "$removed" | while read -r p; do
      warn "PACKAGE REMOVED: $p"
    done
  fi
  mv /tmp/shield_new_pkgs "$SNAP_PACKAGES"

  # 2. Check for new processes
  ps -eo comm --no-headers 2>/dev/null | sort > /tmp/shield_new_procs
  new_proc=$(comm -23 /tmp/shield_new_procs "$SNAP_PROCS")
  if [ -n "$new_proc" ]; then
    echo "$new_proc" | while read -r p; do
      # Filter out common noise
      if ! echo "$p" | grep -qE '^(ps|grep|awk|sort|comm|sleep|bash|sh)$'; then
        warn "NEW PROCESS: $p"
        # Check if it's suspicious
        if echo "$p" | grep -qiE '(nc|ncat|nmap|hydra|aircrack|ettercap|tcpdump|john|hashcat|sqlmap|msf|beef|cobalt|metasploit)'; then
          alert "SUSPICIOUS PROCESS DETECTED: $p"
        fi
      fi
    done
  fi
  mv /tmp/shield_new_procs "$SNAP_PROCS"

  # 3. Check for new listening ports
  ss -tlnp 2>/dev/null | awk '{print $4}' | sort > /tmp/shield_new_listen 2>/dev/null || touch /tmp/shield_new_listen
  new_port=$(comm -23 /tmp/shield_new_listen "$SNAP_LISTEN")
  if [ -n "$new_port" ]; then
    echo "$new_port" | while read -r port; do
      if [ -n "$port" ]; then
        if echo "$port" | grep -qvE '127\.0\.0\.1|::1'; then
          alert "NEW EXTERNAL LISTENER: $port"
        else
          warn "New localhost listener: $port"
        fi
      fi
    done
  fi
  mv /tmp/shield_new_listen "$SNAP_LISTEN"

  # 4. Check for new outbound connections (possible C2)
  if command -v ss &>/dev/null; then
    ss -tnp 2>/dev/null | grep ESTAB | grep -vE '127\.0\.0\.1|::1|:(22|80|443|8080|8443) ' | tail -5 | while read -r line; do
      # Only alert on truly unusual connections
      if echo "$line" | grep -qvE ':(53|123|443|80|853|8443) '; then
        warn "Unusual outbound: $line"
      fi
    done
  fi

  # 5. Check for modified boot scripts (persistence injection)
  BOOT_DIR="$HOME/.termux/boot"
  if [ -d "$BOOT_DIR" ]; then
    find "$BOOT_DIR" -newer "$PID_FILE" -type f 2>/dev/null | while read -r f; do
      alert "BOOT SCRIPT MODIFIED: $f"
    done
  fi

  # 6. Check shell profiles for tampering
  for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    if [ -f "$rc" ] && [ "$rc" -nt "$PID_FILE" ]; then
      warn "Shell profile modified: $rc"
      if grep -qiE '(curl.*\|.*bash|wget.*\|.*bash|/dev/tcp|nc -e|reverse)' "$rc" 2>/dev/null; then
        alert "MALICIOUS CODE in $rc — CHECK IMMEDIATELY"
      fi
    fi
  done

done
