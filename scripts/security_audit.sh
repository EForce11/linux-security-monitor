#!/bin/bash
# ============================================
# Server Security Audit Script
# Usage:
#   ./security_audit.sh
#   ./security_audit.sh --section users
#   ./security_audit.sh --section ports,cron
#   ./security_audit.sh --output /var/log/audit.log
#   ./security_audit.sh --quiet
#
# Config file: ~/.security_audit.conf
# ============================================

SECTIONS="logins,sessions,users,sudo,ssh,ports,cron,services,setuid,files,network,docker"
OUTPUT_FILE=""
QUIET=false
CONFIG_FILE="$HOME/.security_audit.conf"

WHITELIST_USERS="root ubuntu sync"
WHITELIST_SERVICES="systemd network ssh cron ufw fail2ban docker tailscale rsyslog dbus accounts unattended snapd multipathd oracle unified polkit udisks ModemManager cloudflared"
WHITELIST_PORTS="22 53"
WHITELIST_MOUNTS=""

if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --section) SECTIONS="$2"; shift 2 ;;
        --output)  OUTPUT_FILE="$2"; shift 2 ;;
        --quiet)   QUIET=true; shift ;;
        --help)
            echo "Usage: $0 [--section SECTIONS] [--output FILE] [--quiet]"
            echo ""
            echo "Sections: logins, sessions, users, sudo, ssh, ports, cron,"
            echo "          services, setuid, files, network, docker"
            echo "          Use comma-separated values: --section users,ports"
            echo ""
            echo "Config:   ~/.security_audit.conf"
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

log()   { echo -e "${BOLD}[•] $1${NC}"; }
warn()  { echo -e "${YELLOW}[!] $1${NC}"; }
alert() { echo -e "${RED}[✗] $1${NC}"; }
ok()    { echo -e "${GREEN}[✓] $1${NC}"; }
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
                warn "  $user (uid=$uid, shell=$shell) ← review"
            else
                warn "  $user (uid=$uid, shell=$shell) ← non-standard system user"
            fi
        fi
    done < /etc/passwd
    echo ""

    log "Users created in the last 30 days:"
    NEWUSERS=$(sudo find /home -maxdepth 1 -newer /etc/passwd -type d 2>/dev/null | grep -v "^/home$")
    if [[ -z "$NEWUSERS" ]]; then ok "  None"
    else echo "$NEWUSERS" | while read d; do alert "  $d"; done; fi
    echo ""
fi

if should_run sudo; then
    log "Users with sudo privileges:"
    grep -E '^[^#]' /etc/sudoers 2>/dev/null | \
        grep -v "^Defaults\|^User_Alias\|^Cmnd_Alias\|^Host_Alias\|^%" | \
        while read line; do warn "  $line"; done
    getent group sudo | awk -F: '{print $4}' | tr ',' '\n' | while read u; do
        [[ -n "$u" ]] && echo "  sudo group: $u"
    done
    echo ""
fi

if should_run ssh; then
    log "SSH configuration:"
    ROOT_LOGIN=$(sudo sshd -T 2>/dev/null | grep "permitrootlogin" | awk '{print $2}')
    PASS_AUTH=$(sudo sshd -T 2>/dev/null | grep "passwordauthentication" | awk '{print $2}')
    PUBKEY=$(sudo sshd -T 2>/dev/null | grep "pubkeyauthentication" | awk '{print $2}')

    [[ "$ROOT_LOGIN" == "no" ]] && ok "  PermitRootLogin: $ROOT_LOGIN"      || alert "  PermitRootLogin: $ROOT_LOGIN ← DISABLE THIS!"
    [[ "$PASS_AUTH"  == "no" ]] && ok "  PasswordAuthentication: $PASS_AUTH" || warn  "  PasswordAuthentication: $PASS_AUTH ← key-only recommended"
    [[ "$PUBKEY"     == "yes" ]] && ok "  PubkeyAuthentication: $PUBKEY"      || warn  "  PubkeyAuthentication: $PUBKEY"

    log "Authorized keys:"
    find /home /root -name "authorized_keys" 2>/dev/null | while read f; do
        COUNT=$(wc -l < "$f")
        warn "  $f ($COUNT key(s))"
    done
    echo ""
fi

if should_run ports; then
    log "Ports listening on external interfaces:"
    sudo ss -tlnp | grep -v "127.0.0.1\|::1" | tail -n +2 | while read -r line; do
        port=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
        if echo "$WHITELIST_PORTS" | grep -qw "$port"; then ok "  $line"
        else warn "  $line"; fi
    done
    echo ""
fi

if should_run cron; then
    log "Cron jobs for all users:"
    FOUND_CRON=false
    for user in $(cut -d: -f1 /etc/passwd); do
        crons=$(sudo crontab -u "$user" -l 2>/dev/null | grep -v "^#\|^$")
        if [[ -n "$crons" ]]; then warn "  [$user] $crons"; FOUND_CRON=true; fi
    done
    $FOUND_CRON || ok "  No user cron jobs found"

    log "System cron directories:"
    for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        files=$(ls "$dir" 2>/dev/null | grep -v "^$")
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
            warn "  $svc"; FOUND_SVC=true
        fi
    done < <(systemctl list-units --type=service --state=running --no-legend)
    $FOUND_SVC || ok "  No unexpected services running"
    echo ""

    log "Failed services:"
    FAILED=$(systemctl --failed --no-legend | awk '{print $1}')
    if [[ -z "$FAILED" ]]; then ok "  None"
    else echo "$FAILED" | while read s; do alert "  $s"; done; fi
    echo ""
fi

if should_run setuid; then
    log "Unexpected SETUID files:"
    sudo find / -xdev -perm /4000 -type f 2>/dev/null | grep -v \
        "^/usr/bin/\(sudo\|su\|passwd\|gpasswd\|chsh\|chfn\|newgrp\|mount\|umount\|fusermount\|fusermount3\|pkexec\|ssh-agent\|ssh-keysign\)$\
        \|^/usr/sbin/\|^/bin/\|^/sbin/\|^/var/lib/containerd/" | \
        while read f; do warn "  $f"; done
    echo ""
fi

if should_run files; then
    log "Files modified under /etc in the last 24 hours:"
    FOUND_FILES=false
    sudo find /etc -mtime -1 -type f 2>/dev/null | \
        grep -v "\.cache\|adjtime\|resolv\|unified-monitoring" | \
        while read f; do
            warn "  $f ($(stat -c '%y' "$f" | cut -d. -f1))"
            FOUND_FILES=true
        done
    $FOUND_FILES || ok "  No unexpected changes"
    echo ""
fi

if should_run network; then
    log "Active external connections:"
    FOUND_NET=false
    sudo ss -tnp state established 2>/dev/null | grep -v "127.0.0.1\|::1" | tail -n +2 | \
        while read line; do warn "  $line"; FOUND_NET=true; done
    $FOUND_NET || ok "  No external connections"
    echo ""
fi

if should_run docker && command -v docker &>/dev/null; then
    log "Docker containers:"
    docker ps --format "  {{.Names}}\t{{.Status}}\t{{.Ports}}"
    echo ""

    log "Docker bind mounts:"
    docker ps -q | xargs -I {} docker inspect {} \
        --format '{{.Name}}: {{range .Mounts}}{{if eq .Type "bind"}}{{.Source}} → {{.Destination}} {{end}}{{end}}' \
        2>/dev/null | while read line; do
            [[ -z "$WHITELIST_MOUNTS" ]] && warn "  $line" || \
            echo "$line" | grep -qF "$WHITELIST_MOUNTS" && ok "  $line" || warn "  $line"
        done
    echo ""
fi

echo -e "${BOLD}================================================${NC}"
echo -e "${BOLD}   Audit complete${NC}"
echo -e "${BOLD}================================================${NC}"
echo -e "${YELLOW}[!] yellow${NC} = review recommended, ${RED}[✗] red${NC} = action required"
[[ -n "$OUTPUT_FILE" ]] && echo "  Log saved to: $OUTPUT_FILE"
