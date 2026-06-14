# ROCKY SHIELD v2.0 — Termux Security Monitor

Auto-killing security system for Termux. Scans, detects, and **destroys** malware, reverse shells, crypto miners, and suspicious activity in real-time.

## What It Does

### 8-Layer Scanning
1. **Package Audit** — Tracks every installed package, auto-removes dangerous ones
2. **Network Monitor** — Kills external listeners and C2 connections (ports 4444, 1337, 31337, etc.)
3. **Process Audit** — Kills known malicious tools (nmap, hydra, metasploit, john, hashcat, sqlmap)
4. **Persistence Scan** — Quarantines malicious boot scripts, crontab entries, shell profile injections
5. **File Integrity** — SHA256 hashing of all binaries, detects tampering
6. **Permission Audit** — Removes world-write and SUID/SGID from unexpected files
7. **Script Package Audit** — Removes malicious pip/npm packages
8. **Suspicious File Scan** — Detects reverse shells, curl-pipe-bash, base64-encoded payloads

### Auto-Kill
When enabled (`shield autokill on`), the monitor **immediately kills**:
- Reverse shell processes (`/dev/tcp`, `bash -i`, `nc -e`)
- Network attack tools (nmap, hydra, metasploit, aircrack)
- Crypto miners (xmrig, minerd, stratum)
- Suspicious outbound connections (known C2 ports)
- External listeners on non-localhost ports
- Modified shell profiles with injected code
- Dangerous boot scripts
- Hidden executables in system paths

### Quarantine
Suspicious files are moved to `~/.rocky-shield/quarantine/` with permissions locked to 000.

## Install

```bash
pkg install git -y
cd ~
git clone https://github.com/JonesKapedo/rocky-shield
cd rocky-shield
bash install.sh
```

**Then:**
1. Install [Termux:Boot](https://f-droid.org/packages/com.termux.boot/) from F-Droid → open it once
2. Install [Termux:Widget](https://f-droid.org/packages/com.termux.widget/) from F-Droid
3. Install [Termux:Notification](https://f-droid.org/packages/com.termux.api/) from F-Droid
4. Enable auto-kill: `shield autokill on`
5. Start monitor: `shield-mon &`

## Commands

| Command | Description |
|---------|-------------|
| `shield` | Full 8-layer scan |
| `shield proc` | Process audit only |
| `shield net` | Network monitor only |
| `shield files` | Suspicious file scan |
| `shield autokill on` | Enable auto-kill mode |
| `shield autokill off` | Disable auto-kill mode |
| `shield-mon &` | Start real-time monitor |
| `shield-stop` | Stop monitor + watchdog |
| `shield-status` | Check monitor/watchdog status |
| `shield-logs` | View recent alerts |
| `shield-kills` | View killed/quarantined |

## Tasker Integration

### Setup

1. Install [Termux:Tasker](https://f-droid.org/packages/com.termux.tasker/) from F-Droid
2. In Termux:Tasker, set executable path: `~/.rocky-shield/tasker/shield-tasker`
3. In Tasker, create a new Profile → Event or State trigger
4. Add Task → Plugin → Termux:Tasker
5. Set arguments to one of the commands below

### Tasker Commands

| Command | Description |
|---------|-------------|
| `scan` | Run full security scan |
| `scan-quick` | Quick process + network scan |
| `monitor-start` | Start real-time monitor |
| `monitor-stop` | Stop real-time monitor |
| `autokill-on` | Enable auto-kill |
| `autokill-off` | Disable auto-kill |
| `status` | Get full shield status |
| `alerts` | View recent alerts |
| `kills` | View recent kills |
| `lockdown` | EMERGENCY: kill threats, enable autokill, scan everything |
| `quarantine` | List quarantined files |
| `restore <filename>` | Restore a quarantined file |
| `update` | Pull latest from GitHub |

### Recommended Tasker Profiles

**Auto-scan every 6 hours:**
- Profile: Time → Every 6 hours
- Task: Termux:Tasker → arguments: `scan-quick`

**Lockdown on USB connection (possible juice jacking):**
- Profile: State → USB Connected
- Task: Termux:Tasker → arguments: `lockdown`

**Scan on new WiFi connection:**
- Profile: State → WiFi Connected
- Task: Termux:Tasker → arguments: `scan-quick`

**Boot scan:**
- Profile: Event → System → Device Boot
- Task: Termux:Tasker → arguments: `monitor-start`

## Auto-Start on Boot

The Termux:Boot script (`~/.termux/boot/rockyshield`) automatically:
1. Runs a full security scan
2. Starts the real-time monitor daemon
3. Starts a **watchdog** that auto-restarts the monitor if it dies
4. Sends a notification with results

### Watchdog (Always-On Guarantee)

The watchdog is a parent process that watches the monitor. If Termux kills the monitor (memory pressure, background kills, etc.), the watchdog restarts it within 5 seconds. This ensures Shield stays running **24/7** as long as Termux is alive.

Check both are running:
```bash
shield-status
```
Output:
```
Monitor: RUNNING
Watchdog: RUNNING
Auto-kill: ON
```

Both are stopped by `shield-stop`.

## Architecture

```
~/.rocky-shield/
├── rockyshield.sh          # Main scanner (8 layers)
├── monitor.sh              # Real-time daemon (30s loop)
├── autokill.enabled        # Touch this file to enable auto-kill
├── shield.pid              # Scanner PID
├── monitor.pid             # Monitor PID
├── watchdog.pid            # Watchdog PID (auto-restarts monitor)
├── tasker/
│   └── shield-tasker       # Tasker bridge script
├── baseline/
│   ├── packages.list       # Known-good package state
│   ├── processes.list      # Known-good process state
│   └── hashes.sha256       # File integrity hashes
├── quarantine/             # Quarantined malicious files
└── logs/
    ├── alerts.log          # All alerts
    ├── kills.log           # All kills/quarantines
    ├── realtime.log        # Monitor daemon log
    ├── boot_scan.log       # Boot scan results
    ├── watchdog.log         # Watchdog restart events
    └── scan_*.log          # Individual scan logs
```

## Safety Notes

- Auto-kill defaults to OFF. Enable it after reviewing what gets killed.
- Check `~/.rocky-shield/logs/kills.log` regularly for false positives.
- Restore quarantined files with `shield-task restore <filename>`
- Baseline is created on first scan. Re-run `shield` after installing legitimate tools.

## License

MIT — Build it, break it, improve it.
