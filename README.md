# Linux Security Monitor

A lightweight, event-driven security monitoring toolkit for Linux servers. Watches system logs in real-time and sends instant push notifications via [ntfy.sh](https://ntfy.sh) when something critical happens — no polling, no noise, no false alarms unless there's something worth seeing.

---

## How It Works

```
┌─────────────────────────────────────────────────┐
│                  security_monitor               │
│                    (daemon)                     │
├─────────────┬──────────────┬────────────────────┤
│  /var/log/  │   systemd    │  custom app logs   │
│  auth.log   │   journal    │  (configurable)    │
└──────┬──────┴──────┬───────┴────────────┬───────┘
       │             │                    │
       └─────────────┴────────────────────┘
                     │
              pattern matched?
                     │
                     ▼
              ntfy.sh → your phone
```

**security_monitor.sh** runs as a systemd service and watches:
- `/var/log/auth.log` — SSH logins, new users, sudo changes
- systemd journal — service failures, OOM events
- `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` — file modifications via inotify
- Any custom application log you configure

**security_audit.sh** is a standalone script for on-demand full system audits.

---

## Notifications

Only notifies on actionable events:

| Event | Priority |
|-------|----------|
| New user created | 🚨 Urgent |
| Sudo privilege granted | 🚨 Urgent |
| Sensitive file modified (`/etc/passwd`, sudoers) | 🚨 Urgent |
| OOM killer triggered | 🚨 Urgent |
| Root access attempt | 🚨 Urgent |
| SSH login (success) | 🔑 Default |
| Service failed | ⚠️ High |
| SSH login failure | ⚠️ Low |
| Custom log pattern match | Configurable |

---

## Requirements

- Ubuntu 22.04+ (or any systemd-based Linux)
- `curl`
- `inotify-tools`
- A free [ntfy.sh](https://ntfy.sh) topic (or self-hosted ntfy instance)

---

## Installation

```bash
git clone https://github.com/yourusername/linux-security-monitor
cd linux-security-monitor
sudo ./install.sh
```

The installer will:
1. Install `curl` and `inotify-tools`
2. Copy scripts to your home directory
3. Ask for your ntfy topic and create config files
4. Install and start the systemd service

---

## Configuration

### Monitor config (`~/.security_monitor.conf`)

```bash
NTFY_SERVER="https://ntfy.sh"
NTFY_TOPIC="your-private-topic"
WHITELIST_SUDO_USERS="ubuntu"
```

### Audit config (`~/.security_audit.conf`)

```bash
WHITELIST_USERS="root ubuntu sync"
WHITELIST_PORTS="22 53"
WHITELIST_SERVICES="docker tailscale nginx ..."
```

Both files are created from `config/*.conf.example` during install. Your real configs are gitignored by default — never commit them.

---

## Adding Your Own Application Logs

You can watch any log file for any pattern by adding entries to `EXTRA_LOG_FILES` in `~/.security_monitor.conf`.

Each entry requires 4 values in this order:
1. Path to the log file
2. Pattern to match (grep-compatible string)
3. Notification title
4. Priority: `low` | `default` | `high` | `urgent`

```bash
# ~/.security_monitor.conf

EXTRA_LOG_FILES=()

# Vaultwarden — admin panel probe
EXTRA_LOG_FILES+=(
    "/home/ubuntu/vaultwarden/vw-data/vaultwarden.log"
    "Invalid admin token"
    "⚠️ Vaultwarden admin panel probe"
    "high"
)

# Nginx — rate limiting
EXTRA_LOG_FILES+=(
    "/var/log/nginx/error.log"
    "limiting requests"
    "⚠️ Nginx rate limit hit"
    "default"
)

# Your app — any pattern
EXTRA_LOG_FILES+=(
    "/var/log/myapp/app.log"
    "CRITICAL"
    "🚨 MyApp critical error"
    "urgent"
)
```

After editing, restart the service:
```bash
sudo systemctl restart security-monitor.service
```

---

## Manual Audit

Run a full system audit at any time:

```bash
~/security_audit.sh
```

Options:
```bash
# Run specific sections only
~/security_audit.sh --section users,ports,docker

# Save output to a file (colors stripped automatically)
~/security_audit.sh --output /var/log/audit.log

# Only show warnings and alerts
~/security_audit.sh --quiet
```

Available sections: `logins`, `sessions`, `users`, `sudo`, `ssh`, `ports`, `cron`, `services`, `setuid`, `files`, `network`, `docker`

---

## Useful Commands

```bash
# View live monitor logs
journalctl -u security-monitor.service -f

# Check service status
systemctl status security-monitor.service

# Restart after config change
sudo systemctl restart security-monitor.service
```

---

## License

MIT
