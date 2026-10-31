#!/bin/bash
# ============================================
# Linux Security Monitor - Audit Script (v3)
# Zero-dependency Mini-HIDS with systemd & ntfy.sh support
# ============================================

SECTIONS="logins,sessions,users,sudo,ssh,ports,cron,services,setuid,files,network,docker"
OUTPUT_FILE=""
QUIET=false

# Check system-wide config first, fallback to user home config
if [[ -f "/etc/security_audit.conf" ]]; then
    CONFIG_FILE="/etc/security_audit.conf"
else
    CONFIG_FILE="$HOME/.security_audit.conf"
fi

WHITELIST_USERS="root ubuntu sync opc"
WHITELIST_SERVICES="systemd network ssh cron ufw fail2ban docker containerd tailscale rsyslog dbus accounts unattended snapd multipathd oracle unified polkit udisks ModemManager cloudflared fwupd getty serial-getty user@ security-audit"
WHITELIST_PORTS="22 53"
WHITELIST_MOUNTS=""

# ntfy.sh Notification Settings
NTFY_TOPIC=""
NTFY_SERVER="https://ntfy.sh"
NTFY_ONLY_ON_ISSUES=true

if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --section) SECTIONS="$2"; shift 2 ;;
        --output)  OUTPUT_FILE="$2"; shift 2 ;;
        --quiet)   QUIET=true; shift ;;
        --ntfy)    NTFY_TOPIC="$2"; shift 2 ;;
        --help)
            echo "Usage: $0 [--section SECTIONS] [--output FILE] [--ntfy TOPIC] [--quiet]"
            echo ""
            echo "Sections: logins, sessions, users, sudo, ssh, ports, cron,"
            echo "          services, setuid, files, network, docker"
            echo "Config:   /etc/security_audit.conf or ~/.security_audit.conf"
            exit 0 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'

if [[ -n "$OUTPUT_FILE" ]]; then
    exec > >(tee >(sed 's/\x1b\[[0-9;]*m//g' >> "$OUTPUT_FILE")) 2>&1
fi

WARN_COUNT=0
ALERT_COUNT=0
ISSUES_LIST=""

log()   { echo -e "${BOLD}[•] $1${NC}"; }
ok()    { echo -e "${GREEN}[✓] $1${NC}"; }
warn()  { 
    echo -e "${YELLOW}[!] $1${NC}"
    ((WARN_COUNT++))
    ISSUES_LIST+="[!] $1"$'\n'
}
alert() { 
    echo -e "${RED}[✗] $1${NC}"
    ((ALERT_COUNT++))
    ISSUES_LIST+="[✗] $1"$'\n'
}
$QUIET && log() { :; }

should_run() { echo "$SECTIONS" | grep -qE "(^|,)$1(,|$)"; }

echo -e "${BOLD}================================================${NC}"
echo -e "${BOLD}   Security Audit - $(date '+%Y-%m-%d %H:%M')${NC}"
echo -e "${BOLD}   Host: $(hostname)${NC}"
[[ -n "$OUTPUT_FILE" ]] && echo -e "${BOLD}   Log:  $OUTPUT_FILE${NC}"
echo -e "${BOLD}   Sections: $SECTIONS${NC}"
echo -e "${BOLD}================================================${NC}"
echo ""

if should_run logins; then
    log "Last successful logins:"
    last -n 10 | grep -v "^$\|reboot\|wtmp"
    echo ""

    log "Last failed login attempts:"
    sudo lastb -n 10 2>/dev/null | grep -v "^$\|btmp" || echo "  (lastb requires sudo)"
    echo ""
fi

if should_run sessions; then
    log "Currently active sessions:"
    SESSIONS_OUT=$(who)
    [[ -z "$SESSIONS_OUT" ]] && ok "  No active sessions" || echo "$SESSIONS_OUT"
    echo ""
fi

if should_run users; then
    log "Users with login shells (suspicious ones flagged):"
    while IFS=: read -r user _ uid _ _ _ shell; do
        if [[ "$shell" != "/usr/sbin/nologin" && "$shell" != "/bin/false" && \
              "$shell" != "/usr/bin/false" && -n "$shell" ]]; then
            if echo "$WHITELIST_USERS" | grep -qw "$user"; then
                ok "  $user (uid=$uid, shell=$shell)"
            elif [[ "$uid" -ge 1000 ]]; then
                warn "User review: $user (uid=$uid, shell=$shell)"
            else
                warn "Non-standard system user: $user (uid=$uid, shell=$shell)"
            fi
        fi
    done < /etc/passwd
    echo ""

    log "Users created in the last 30 days:"
    NEWUSERS=$(sudo find /home -maxdepth 2 -name ".profile" -ctime -30 2>/dev/null | xargs -r dirname)
    if [[ -z "$NEWUSERS" ]]; then
        ok "  None"
    else
        while read -r d; do alert "New user home directory: $d"; done <<< "$NEWUSERS"
    fi
    echo ""
fi

if should_run sudo; then
    log "Users with sudo privileges:"
    while read -r line; do
        [[ -n "$line" ]] && warn "Sudoers rule: $line"
    done < <(sudo grep -E '^[^#]' /etc/sudoers 2>/dev/null | grep -v "^Defaults\|^User_Alias\|^Cmnd_Alias\|^Host_Alias\|^%\|^root")
    
    getent group sudo | awk -F: '{print $4}' | tr ',' '\n' | while read -r u; do
        [[ -n "$u" ]] && ok "  sudo group: $u"
    done
    echo ""
fi

if should_run ssh; then
    log "SSH configuration:"
    ROOT_LOGIN=$(sudo sshd -T 2>/dev/null | grep "^permitrootlogin " | awk '{print $2}')
    PASS_AUTH=$(sudo sshd -T 2>/dev/null | grep "^passwordauthentication " | awk '{print $2}')
    PUBKEY=$(sudo sshd -T 2>/dev/null | grep "^pubkeyauthentication " | awk '{print $2}')

    [[ "$ROOT_LOGIN" == "no" ]]  && ok "  PermitRootLogin: $ROOT_LOGIN"       || alert "SSH PermitRootLogin: $ROOT_LOGIN"
    [[ "$PASS_AUTH"  == "no" ]]  && ok "  PasswordAuthentication: $PASS_AUTH" || warn  "SSH PasswordAuthentication: $PASS_AUTH"
    [[ "$PUBKEY"     == "yes" ]] && ok "  PubkeyAuthentication: $PUBKEY"      || warn  "SSH PubkeyAuthentication: $PUBKEY"

    log "Authorized keys:"
    while read -r f; do
        COUNT=$(sudo grep -cve '^\s*$\|^\s*#' "$f" 2>/dev/null || echo 0)
        if [[ "$COUNT" -gt 0 ]]; then
            ok "  $f ($COUNT active key(s))"
        fi
    done < <(sudo find /home /root -name "authorized_keys" 2>/dev/null)
    echo ""
fi

if should_run ports; then
    log "Ports listening on non-loopback interfaces:"
    while read -r line; do
        port=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
        if echo "$WHITELIST_PORTS" | grep -qw "$port" || echo "$line" | grep -q "tailscaled"; then
            ok "  $line"
        else
            warn "Unexpected open port: $line"
        fi
    done < <(sudo ss -tlnp | grep -v "127.0.0.\|::1" | tail -n +2)
    echo ""
fi

if should_run cron; then
    log "Cron jobs for all users:"
    FOUND_CRON=false
    for user in $(cut -d: -f1 /etc/passwd); do
        crons=$(sudo crontab -u "$user" -l 2>/dev/null | grep -v "^#\|^$")
        if [[ -n "$crons" ]]; then
            warn "Cron job [$user]: $crons"
            FOUND_CRON=true
        fi
    done
    $FOUND_CRON || ok "  No user cron jobs found"

    log "System cron directories:"
    for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        files=$(ls "$dir" 2>/dev/null | grep -v "^placeholder$" | tr '\n' ' ')
        [[ -n "$files" ]] && echo "  $dir: $files"
    done
    echo ""
fi

if should_run services; then
    WHITELIST_GREP=$(echo "$WHITELIST_SERVICES" | tr ' ' '|')
    log "Running non-system services:"
    FOUND_SVC=false
    while read -r svc _; do
        if ! echo "$svc" | grep -qE "$WHITELIST_GREP"; then
            warn "Unexpected running service: $svc"
            FOUND_SVC=true
        fi
    done < <(systemctl list-units --type=service --state=running --no-legend)
    $FOUND_SVC || ok "  No unexpected services running"
    echo ""

    log "Failed services:"
    FAILED=$(systemctl --failed --no-legend | awk '{print $1}')
    if [[ -z "$FAILED" ]]; then
        ok "  None"
    else
        while read -r s; do alert "Failed systemd service: $s"; done <<< "$FAILED"
    fi
    echo ""
fi

if should_run setuid; then
    log "Unexpected SETUID files:"
    FOUND_SUID=false
    SAFE_SUID_REGEX="^/usr/bin/(sudo|su|passwd|gpasswd|chsh|chfn|newgrp|mount|umount|fusermount|fusermount3|pkexec|ssh-agent)$|^/usr/lib/openssh/ssh-keysign$|^/usr/lib/dbus-1.0/dbus-daemon-launch-helper$|^/usr/libexec/polkit-agent-helper-1$|^/usr/sbin/|^/bin/|^/sbin/|^/var/lib/containerd/"
    while read -r f; do
        warn "Unexpected SETUID binary: $f"
        FOUND_SUID=true
    done < <(sudo find / -xdev -perm /4000 -type f 2>/dev/null | grep -vE "$SAFE_SUID_REGEX")
    $FOUND_SUID || ok "  None (all SETUID binaries match baseline)"
    echo ""
fi

if should_run files; then
    log "Files modified under /etc in the last 24 hours:"
    FOUND_FILES=false
    while read -r f; do
        warn "Modified /etc file: $f ($(stat -c '%y' "$f" | cut -d. -f1))"
        FOUND_FILES=true
    done < <(sudo find /etc -mtime -1 -type f 2>/dev/null | grep -vE "\.cache|adjtime|resolv|unified-monitoring|ld\.so\.cache|security_audit\.conf")
    $FOUND_FILES || ok "  No unexpected changes"
    echo ""
fi

if should_run network; then
    log "Active external connections:"
    FOUND_NET=false
    while read -r line; do
        if echo "$line" | grep -qE "tailscaled|gomon|docker-proxy|cloudflared|sshd"; then
            ok "  $line"
        else
            warn "Unexpected external connection: $line"
        fi
        FOUND_NET=true
    done < <(sudo ss -tnp state established 2>/dev/null | grep -v "127.0.0.\|::1" | tail -n +2)
    $FOUND_NET || ok "  No external connections"
    echo ""
fi

if should_run docker && command -v docker &>/dev/null; then
    log "Docker containers:"
    docker ps --format "  {{.Names}}\t{{.Status}}\t{{.Ports}}"
    echo ""

    log "Docker bind mounts:"
    while read -r line; do
        mount_path=$(echo "$line" | awk -F': ' '{print $2}')
        if [[ -z "$mount_path" ]]; then
            ok "  $line (no bind mounts)"
        elif [[ -n "$WHITELIST_MOUNTS" ]] && echo "$line" | grep -qF "$WHITELIST_MOUNTS"; then
            ok "  $line"
        else
            warn "Unwhitelisted Docker mount: $line"
        fi
    done < <(docker ps -q | xargs -r -I {} docker inspect {} --format '{{.Name}}: {{range .Mounts}}{{if eq .Type "bind"}}{{.Source}} → {{.Destination}} {{end}}{{end}}' 2>/dev/null)
    echo ""
fi

# ============================================
# ntfy.sh Notification Dispatch
# ============================================
if [[ -n "$NTFY_TOPIC" ]]; then
    if [[ "$ALERT_COUNT" -gt 0 ]]; then
        curl -s -H "Title: [CRITICAL] $(hostname) Security Alert!" \
             -H "Priority: urgent" \
             -H "Tags: rotating_light,skull" \
             -d "$(echo -e "${ALERT_COUNT} critical, ${WARN_COUNT} warning(s) detected:\n\n${ISSUES_LIST}" | head -n 25)" \
             "${NTFY_SERVER}/${NTFY_TOPIC}" >/dev/null
    elif [[ "$WARN_COUNT" -gt 0 ]]; then
        curl -s -H "Title: [WARNING] $(hostname) Security Audit" \
             -H "Priority: default" \
             -H "Tags: warning,shield" \
             -d "$(echo -e "${WARN_COUNT} warning(s) require review:\n\n${ISSUES_LIST}" | head -n 25)" \
             "${NTFY_SERVER}/${NTFY_TOPIC}" >/dev/null
    elif [[ "$NTFY_ONLY_ON_ISSUES" == "false" ]]; then
        curl -s -H "Title: [OK] $(hostname) Security Audit Clean" \
             -H "Priority: low" \
             -H "Tags: white_check_mark" \
             -d "All security checks passed (0 alerts, 0 warnings)." \
             "${NTFY_SERVER}/${NTFY_TOPIC}" >/dev/null
    fi
fi

echo -e "${BOLD}================================================${NC}"
echo -e "${BOLD}   Audit complete (Alerts: $ALERT_COUNT, Warnings: $WARN_COUNT)${NC}"
echo -e "${BOLD}================================================${NC}"
echo -e "${YELLOW}[!] yellow${NC} = review recommended, ${RED}[✗] red${NC} = action required"
[[ -n "$OUTPUT_FILE" ]] && echo "  Log saved to: $OUTPUT_FILE"
