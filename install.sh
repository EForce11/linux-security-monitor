#!/bin/bash
# ============================================
# Linux Security Monitor - Install Script (v3)
# Installs security_audit.sh, config, and systemd timer
# Run with: sudo ./install.sh
# ============================================
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] Run with sudo: sudo ./install.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { echo -e "\e[1m[•] $1\e[0m"; }
ok()   { echo -e "\e[32m[✓] $1\e[0m"; }
warn() { echo -e "\e[33m[!] $1\e[0m"; }
die()  { echo -e "\e[31m[✗] $1\e[0m"; exit 1; }

echo -e "\e[1m================================================\e[0m"
echo -e "\e[1m   Linux Security Monitor - Installer (v3)\e[0m"
echo -e "\e[1m================================================\e[0m"
echo ""

# ============================================
# CHECK REQUIRED FILES
# ============================================
log "Checking required files..."
[[ -f "$SCRIPT_DIR/scripts/security_audit.sh" ]] || die "scripts/security_audit.sh not found"
[[ -f "$SCRIPT_DIR/config/security_audit.conf.example" ]] || die "config/security_audit.conf.example not found"
[[ -f "$SCRIPT_DIR/systemd/security-audit.service" ]] || die "systemd/security-audit.service not found"
[[ -f "$SCRIPT_DIR/systemd/security-audit.timer" ]] || die "systemd/security-audit.timer not found"
ok "All required files found"

# ============================================
# INSTALL AUDIT SCRIPT
# ============================================
log "Installing security_audit.sh to /usr/local/bin/..."
install -o root -g root -m 755 \
    "$SCRIPT_DIR/scripts/security_audit.sh" /usr/local/bin/security_audit.sh
ok "Audit script installed to /usr/local/bin/security_audit.sh"

# ============================================
# CONFIG FILE
# ============================================
CONFIG_FILE="/etc/security_audit.conf"

if [[ -f "$CONFIG_FILE" ]]; then
    warn "Config already exists at $CONFIG_FILE — skipping (will not overwrite)"
else
    log "Setting up config..."
    echo ""
    read -rp "  Enter your ntfy.sh topic (leave blank to configure later): " NTFY_TOPIC
    echo ""

    cp "$SCRIPT_DIR/config/security_audit.conf.example" "$CONFIG_FILE"
    if [[ -n "$NTFY_TOPIC" ]]; then
        sed -i "s|NTFY_TOPIC=\"\"|NTFY_TOPIC=\"$NTFY_TOPIC\"|" "$CONFIG_FILE"
    fi
    chmod 600 "$CONFIG_FILE"
    ok "Config created at $CONFIG_FILE"
fi

# ============================================
# SYSTEMD SERVICE & TIMER
# ============================================
log "Installing systemd units..."
cp "$SCRIPT_DIR/systemd/security-audit.service" /etc/systemd/system/security-audit.service
cp "$SCRIPT_DIR/systemd/security-audit.timer" /etc/systemd/system/security-audit.timer

systemctl daemon-reload
systemctl enable security-audit.timer
systemctl start security-audit.timer
ok "systemd timer installed and started (runs every 6 hours)"

# ============================================
# VERIFY
# ============================================
echo ""
log "Verifying installation..."

if systemctl is-active --quiet security-audit.timer; then
    ok "security-audit.timer is active"
else
    warn "Timer may not have started. Check: systemctl status security-audit.timer"
fi

# ============================================
# SUMMARY
# ============================================
echo ""
echo -e "\e[1m================================================\e[0m"
echo -e "\e[1m   Installation complete on $(hostname)\e[0m"
echo -e "\e[1m================================================\e[0m"
echo ""
echo "  Audit script:  /usr/local/bin/security_audit.sh"
echo "  Config file:   $CONFIG_FILE"
echo "  Service:       /etc/systemd/system/security-audit.service"
echo "  Timer:         /etc/systemd/system/security-audit.timer"
echo "  Log output:    /var/log/security_audit.log"
echo ""
echo "  Useful commands:"
echo "    security_audit.sh                              # run manually"
echo "    security_audit.sh --section users,ports         # specific sections"
echo "    security_audit.sh --ntfy my-topic               # with push notification"
echo "    systemctl status security-audit.timer           # timer status"
echo "    journalctl -u security-audit.service -n 50      # last audit logs"
echo ""

NTFY_TOPIC_VAL=$(grep "NTFY_TOPIC=" "$CONFIG_FILE" 2>/dev/null | cut -d'"' -f2)
if [[ -z "$NTFY_TOPIC_VAL" ]]; then
    warn "NTFY_TOPIC is not set. Edit $CONFIG_FILE to enable push notifications."
fi
