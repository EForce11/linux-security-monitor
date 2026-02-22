#!/bin/bash
# ============================================
# Security Monitor Daemon
# Watches logs and system events in real-time.
# Sends ntfy.sh notifications on critical events.
#
# Config: ~/.security_monitor.conf
# ============================================

CONFIG_FILE="$HOME/.security_monitor.conf"

# ============================================
# DEFAULTS (override in config file)
# ============================================
NTFY_SERVER="https://ntfy.sh"
NTFY_TOPIC=""
HOSTNAME=$(hostname)
AUTH_LOG="/var/log/auth.log"
EXTRA_LOG_FILES=()     # Add custom log files: ("path" "pattern" "title" "priority")

WHITELIST_SUDO_USERS="ubuntu"

# ============================================
# LOAD CONFIG
# ============================================
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
fi

if [[ -z "$NTFY_TOPIC" ]]; then
    echo "[ERROR] NTFY_TOPIC is not set. Please configure $CONFIG_FILE"
    exit 1
fi

# ============================================
# LOGGING
# ============================================
log()   { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]  $1"; }
warn()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN]  $1"; }
alert() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ALERT] $1"; }

# ============================================
# NTFY NOTIFICATION
# ============================================
notify() {
    local title="$1"
    local message="$2"
    local priority="${3:-high}"
    local tags="${4:-warning}"

    curl -s \
        -H "Title: [$HOSTNAME] $title" \
        -H "Priority: $priority" \
        -H "Tags: $tags" \
        -d "$message" \
        "$NTFY_SERVER/$NTFY_TOPIC" > /dev/null

    alert "$title | $message"
}

# ============================================
# WATCH: AUTH LOG
# ============================================
watch_auth_log() {
    if [[ ! -f "$AUTH_LOG" ]]; then
        warn "Auth log not found at $AUTH_LOG, skipping"
        return
    fi

    log "Watching auth log: $AUTH_LOG"
    tail -Fn0 "$AUTH_LOG" | while read -r line; do

        # New user created
        if echo "$line" | grep -q "useradd\|new user"; then
            NEW_USER=$(echo "$line" | grep -oP "name=\K\S+")
            notify \
                "🚨 New user created" \
                "User '$NEW_USER' was created\n\n$line" \
                "urgent" "skull,user"
        fi

        # User added to sudo group
        if echo "$line" | grep -qE "usermod.*sudo|adduser.*sudo|gpasswd.*-a.*sudo"; then
            notify \
                "🚨 Sudo privilege granted" \
                "A user was added to sudo group\n\n$line" \
                "urgent" "skull,key"
        fi

        # Successful SSH login
        if echo "$line" | grep -q "Accepted publickey\|Accepted password"; then
            USER=$(echo "$line" | grep -oP "for \K\S+")
            IP=$(echo "$line" | grep -oP "from \K[\d\.]+")
            notify \
                "🔑 SSH login" \
                "User '$USER' logged in from $IP" \
                "default" "key"
        fi

        # SSH login failure
        if echo "$line" | grep -q "Failed password\|Invalid user"; then
            IP=$(echo "$line" | grep -oP "from \K[\d\.]+")
            notify \
                "⚠️ SSH login failure" \
                "Failed attempt from $IP\n\n$line" \
                "low" "warning"
        fi

        # Root access attempt
        if echo "$line" | grep -q "FAILED su\|su.*root\|sudo.*root"; then
            notify \
                "🚨 Root access attempt" \
                "$line" \
                "urgent" "skull,rotating_light"
        fi

    done &
}

# ============================================
# WATCH: SYSTEMD JOURNAL
# ============================================
watch_journal() {
    log "Watching systemd journal for errors"
    journalctl -f -q --no-pager -p err 2>/dev/null | while read -r line; do

        # Service failed
        if echo "$line" | grep -qE "Failed to start|failed with result|Main process exited.*FAILURE"; then
            SVC=$(echo "$line" | grep -oP "\K[\w\-]+\.service" | head -1)
            notify \
                "⚠️ Service failed" \
                "${SVC:-Unknown service} failed\n\n$line" \
                "high" "rotating_light"
        fi

        # OOM killer
        if echo "$line" | grep -q "Out of memory\|oom.kill"; then
            notify \
                "🚨 OOM Killer triggered" \
                "Out of memory on $HOSTNAME\n\n$line" \
                "urgent" "skull"
        fi

    done &
}

# ============================================
# WATCH: SENSITIVE FILES (inotify)
# ============================================
watch_sensitive_files() {
    if ! command -v inotifywait &>/dev/null; then
        warn "inotifywait not found. Install: sudo apt install inotify-tools"
        warn "Skipping sensitive file watcher"
        return
    fi

    log "Watching sensitive files: /etc/passwd /etc/shadow /etc/sudoers"
    inotifywait -m -e modify,create,attrib \
        /etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d/ 2>/dev/null | \
    while read -r directory event filename; do
        notify \
            "🚨 Sensitive file modified" \
            "File: ${directory}${filename}\nEvent: $event" \
            "urgent" "skull,file_folder"
    done &
}

# ============================================
# WATCH: CUSTOM LOG FILES
# Configured via EXTRA_LOG_FILES in config.
#
# Format (one entry per log):
#   EXTRA_LOG_FILES+=(
#     "/path/to/app.log"       # log file path
#     "error pattern"          # grep pattern to match
#     "Alert title"            # notification title
#     "high"                   # priority: low, default, high, urgent
#   )
#
# Example for Vaultwarden:
#   EXTRA_LOG_FILES+=(
#     "/home/ubuntu/vaultwarden/vw-data/vaultwarden.log"
#     "Invalid admin token"
#     "⚠️ Vaultwarden admin probe"
#     "high"
#   )
# ============================================
watch_extra_logs() {
    local total=${#EXTRA_LOG_FILES[@]}
    if [[ $total -eq 0 ]]; then
        return
    fi

    local i=0
    while [[ $i -lt $total ]]; do
        local filepath="${EXTRA_LOG_FILES[$i]}"
        local pattern="${EXTRA_LOG_FILES[$((i+1))]}"
        local title="${EXTRA_LOG_FILES[$((i+2))]}"
        local priority="${EXTRA_LOG_FILES[$((i+3))]:-high}"

        if [[ ! -f "$filepath" ]]; then
            warn "Extra log not found: $filepath — skipping"
            i=$((i+4))
            continue
        fi

        log "Watching extra log: $filepath (pattern: '$pattern')"

        # Each extra log gets its own background watcher
        (
            tail -Fn0 "$filepath" | while read -r line; do
                if echo "$line" | grep -q "$pattern"; then
                    notify "$title" "$line" "$priority" "warning"
                fi
            done
        ) &

        i=$((i+4))
    done
}

# ============================================
# STARTUP
# ============================================
notify \
    "✅ Security monitor started" \
    "Monitoring active on $HOSTNAME" \
    "low" "white_check_mark"

log "Starting security monitor on $HOSTNAME"

watch_auth_log
watch_journal
watch_sensitive_files
watch_extra_logs

log "All watchers active."

# Keep daemon alive
while true; do
    wait -n 2>/dev/null || true
    sleep 5
done
