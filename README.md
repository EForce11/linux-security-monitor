# Linux Security Monitor

<div align="center">

**Zero-dependency Bash Mini-HIDS for Linux servers**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/Shell-Bash%205%2B-green.svg)](https://www.gnu.org/software/bash/)
[![Notifications](https://img.shields.io/badge/Alerts-ntfy.sh-yellow.svg)](https://ntfy.sh)

</div>

A lightweight, baseline-driven security auditing toolkit that monitors 12 critical areas of your Linux server. No agents, no dependencies, no bloat — just a single Bash script, a whitelist config, and `systemd` automation with real-time push notifications via [ntfy.sh](https://ntfy.sh).

## Features

- **🔍 12 Audit Modules** — Comprehensive coverage from SSH config to Docker bind mounts
- **📋 Whitelist-Based Detection** — Define your baseline; anything outside it gets flagged
- **📲 Push Notifications** — Instant alerts via [ntfy.sh](https://ntfy.sh) with severity-based priority
- **⏱️ systemd Timer** — Automated audits every 6 hours (replaces cron)
- **🚫 Zero Dependencies** — Pure Bash + standard Linux utilities (`ss`, `find`, `grep`, `systemctl`)
- **📄 Color-Stripped Logging** — Output to file with ANSI codes automatically removed
- **🎯 Selective Scanning** — Run individual modules or combinations via `--section`

## Architecture

```
security_audit.sh
├── Config: /etc/security_audit.conf
├── Modules: 12 independent audit sections
├── Output: Terminal (color) + Log file (plain text)
├── Alerts: ntfy.sh push notifications
└── Scheduler: systemd oneshot service + 6h timer
```

## Audit Modules

| # | Module | What It Checks |
|---|--------|----------------|
| 1 | `logins` | Last 10 successful logins (`last`) and failed attempts (`lastb`) |
| 2 | `sessions` | Currently active sessions (`who`) |
| 3 | `users` | Users with login shells vs. whitelist; new accounts created in 30 days (via `.profile` ctime) |
| 4 | `sudo` | Non-root sudoers rules and sudo group members |
| 5 | `ssh` | PermitRootLogin, PasswordAuthentication, PubkeyAuthentication, authorized keys |
| 6 | `ports` | Non-loopback listening ports vs. whitelist |
| 7 | `cron` | Per-user crontabs and system cron directories |
| 8 | `services` | Running services vs. whitelist; failed systemd units |
| 9 | `setuid` | SETUID binaries not matching the safe baseline regex |
| 10 | `files` | Files under `/etc` modified in the last 24 hours |
| 11 | `network` | Established external connections (non-loopback) |
| 12 | `docker` | Running containers, bind mounts vs. whitelist |

## Quick Start

### Automated Installation

```bash
git clone https://github.com/EForce11/linux-security-monitor.git
cd linux-security-monitor
sudo ./install.sh
```

The installer will:
1. Copy `security_audit.sh` to `/usr/local/bin/`
2. Create `/etc/security_audit.conf` from the example template
3. Install and enable `systemd` service + timer (runs every 6 hours)
4. Optionally configure your ntfy.sh topic for push notifications

### Manual Installation

```bash
# Copy script
sudo cp scripts/security_audit.sh /usr/local/bin/security_audit.sh
sudo chmod 755 /usr/local/bin/security_audit.sh

# Copy config
sudo cp config/security_audit.conf.example /etc/security_audit.conf
sudo chmod 600 /etc/security_audit.conf

# Install systemd units
sudo cp systemd/security-audit.service /etc/systemd/system/
sudo cp systemd/security-audit.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now security-audit.timer
```

## Usage

```bash
# Full audit (all 12 modules)
security_audit.sh

# Specific sections only
security_audit.sh --section users,ports,docker

# Save output to log file (colors auto-stripped)
security_audit.sh --output /var/log/security_audit.log

# Suppress informational messages, show only warnings/alerts
security_audit.sh --quiet

# Send results via ntfy.sh push notification
security_audit.sh --ntfy my-secret-topic

# Combine options
security_audit.sh --section ssh,ports --output /tmp/audit.log --ntfy my-topic --quiet
```

### Output Legend

| Symbol | Meaning | Action |
|--------|---------|--------|
| `[•]` | Informational | No action needed |
| `[✓]` Green | Passed check | Matches baseline |
| `[!]` Yellow | Warning | Review recommended |
| `[✗]` Red | Critical alert | Immediate action required |

## Configuration

Edit `/etc/security_audit.conf` (system-wide) or `~/.security_audit.conf` (per-user):

```bash
# Users that should have login shells (won't be flagged)
WHITELIST_USERS="root ubuntu sync opc"

# Expected running services
WHITELIST_SERVICES="systemd network ssh cron ufw fail2ban docker containerd tailscale rsyslog dbus accounts unattended snapd multipathd oracle unified polkit udisks ModemManager cloudflared fwupd getty serial-getty user@ security-audit"

# Expected listening ports
WHITELIST_PORTS="22 53"

# Expected Docker bind mount paths
WHITELIST_MOUNTS="/home/ubuntu/vaultwarden/vw-data"

# ntfy.sh Push Notification Settings
NTFY_TOPIC=""                  # Your private ntfy topic
NTFY_SERVER="https://ntfy.sh"  # Or self-hosted instance
NTFY_ONLY_ON_ISSUES=true       # Set to false to notify even when clean
```

## ntfy.sh Push Notifications

The audit script integrates with [ntfy.sh](https://ntfy.sh) for real-time push notifications:

| Condition | Priority | Tags |
|-----------|----------|------|
| Critical alerts (`[✗]`) found | 🔴 `urgent` | 🚨 rotating_light, skull |
| Warnings (`[!]`) only | 🟡 `default` | ⚠️ warning, shield |
| All checks passed | 🟢 `low` | ✅ white_check_mark |

**Setup:**

1. Pick a topic at [ntfy.sh](https://ntfy.sh) (e.g., `my-server-security`)
2. Subscribe on your phone via the [ntfy app](https://ntfy.sh/#subscribe)
3. Configure the topic:

```bash
# Option A: In the config file
NTFY_TOPIC="my-server-security"

# Option B: Via CLI flag (overrides config)
security_audit.sh --ntfy my-server-security
```

## systemd Timer Management

The audit runs automatically every 6 hours via `systemd` timer (replaces traditional cron).

```bash
# Check timer status
systemctl status security-audit.timer

# List all timers
systemctl list-timers --all | grep security

# View last audit logs
journalctl -u security-audit.service -n 50

# Follow logs in real-time
journalctl -u security-audit.service -f

# Manually trigger an audit
sudo systemctl start security-audit.service

# Temporarily disable
sudo systemctl stop security-audit.timer

# Re-enable
sudo systemctl start security-audit.timer
```

## Uninstallation

```bash
sudo ./uninstall.sh
```

Or manually:

```bash
sudo systemctl stop security-audit.timer
sudo systemctl disable security-audit.timer
sudo rm /etc/systemd/system/security-audit.service
sudo rm /etc/systemd/system/security-audit.timer
sudo systemctl daemon-reload
sudo rm /usr/local/bin/security_audit.sh
sudo rm /etc/security_audit.conf  # optional
```

## Project Structure

```
linux-security-monitor/
├── scripts/
│   └── security_audit.sh          # Main audit script (v3)
├── config/
│   └── security_audit.conf.example # Example configuration
├── systemd/
│   ├── security-audit.service      # systemd oneshot service
│   └── security-audit.timer        # 6-hour recurring timer
├── install.sh                      # Automated installer
├── uninstall.sh                    # Automated uninstaller
├── LICENSE
└── README.md
```

## v3 Changelog

- **Fixed:** Subshell variable loss — replaced pipe `|` with process substitution `< <(...)` in all `while read` loops
- **Fixed:** SETUID regex — collapsed multi-line BRE into single-line ERE (`grep -vE`)
- **Fixed:** Docker bind mount double-printing — replaced `A && B || C` with proper `if/elif/else`
- **Fixed:** New user detection — switched from `/home` `mtime` to `.profile` `ctime -30` to eliminate false positives
- **Added:** `WARN_COUNT` / `ALERT_COUNT` counters with issue tracking
- **Added:** ntfy.sh notification dispatch with severity-based priority (`urgent` / `default` / `low`)
- **Added:** systemd `Type=oneshot` service + 6-hour `.timer` (replaces cron)
- **Added:** Automated `install.sh` with config setup and systemd integration
- **Added:** System-wide config support (`/etc/security_audit.conf` checked before `~/.security_audit.conf`)

## License

MIT
