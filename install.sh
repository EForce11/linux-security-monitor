#!/bin/bash
# ============================================
# Security Monitor - Install Script
# Run with: sudo ./install.sh
# ============================================
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] Run with sudo: sudo ./install.sh"
    exit 1
fi

REAL_USER="${SUDO_USER:-ubuntu}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { echo -e "\e[1m[•] $1\e[0m"; }
ok()   { echo -e "\e[32m[✓] $1\e[0m"; }
warn() { echo -e "\e[33m[!] $1\e[0m"; }
die()  { echo -e "\e[31m[✗] $1\e[0m"; exit 1; }

echo -e "\e[1m================================================\e[0m"
echo -e "\e[1m   Linux Security Monitor - Installer\e[0m"
echo -e "\e[1m================================================\e[0m"
echo ""

# ============================================
# CHECK REQUIRED FILES
# ============================================
log "Checking required files..."
[[ -f "$SCRIPT_DIR/scripts/security_monitor.sh" ]] || die "scripts/security_monitor.sh not found"
[[ -f "$SCRIPT_DIR/scripts/security_audit.sh" ]]   || die "scripts/security_audit.sh not found"
ok "All required files found"

# ============================================
# DEPENDENCIES
# ============================================
log "Installing dependencies..."
apt-get update -qq
apt-get install -y -qq curl inotify-tools
ok "Dependencies installed (curl, inotify-tools)"

# ============================================
# INSTALL SCRIPTS
# ============================================
log "Installing scripts to $REAL_HOME/..."
install -o "$REAL_USER" -g "$REAL_USER" -m 750 \
    "$SCRIPT_DIR/scripts/security_monitor.sh" "$REAL_HOME/security_monitor.sh"
install -o "$REAL_USER" -g "$REAL_USER" -m 750 \
    "$SCRIPT_DIR/scripts/security_audit.sh" "$REAL_HOME/security_audit.sh"
ok "Scripts installed"

# ============================================
# CONFIG FILE
# ============================================
MONITOR_CONF="$REAL_HOME/.security_monitor.conf"
AUDIT_CONF="$REAL_HOME/.security_audit.conf"

if [[ -f "$MONITOR_CONF" ]]; then
    warn "Monitor config already exists at $MONITOR_CONF — skipping"
else
    log "Setting up monitor config..."
    echo ""
    read -rp "  Enter your ntfy.sh topic (leave blank to configure later): " NTFY_TOPIC
    echo ""

    cp "$SCRIPT_DIR/config/security_monitor.conf.example" "$MONITOR_CONF"
    sed -i "s|NTFY_TOPIC=\"\"|NTFY_TOPIC=\"$NTFY_TOPIC\"|" "$MONITOR_CONF"
    chown "$REAL_USER:$REAL_USER" "$MONITOR_CONF"
    chmod 600 "$MONITOR_CONF"
    ok "Monitor config created at $MONITOR_CONF"
fi

if [[ -f "$AUDIT_CONF" ]]; then
    warn "Audit config already exists at $AUDIT_CONF — skipping"
else
    cp "$SCRIPT_DIR/config/security_audit.conf.example" "$AUDIT_CONF"
    chown "$REAL_USER:$REAL_USER" "$AUDIT_CONF"
    chmod 600 "$AUDIT_CONF"
    ok "Audit config created at $AUDIT_CONF"
fi

# ============================================
# SYSTEMD SERVICE
# ============================================
log "Installing systemd service..."
sed "s|{{USER}}|$REAL_USER|g; s|{{HOME}}|$REAL_HOME|g" \
    "$SCRIPT_DIR/systemd/security-monitor.service" \
    > /etc/systemd/system/security-monitor.service

systemctl daemon-reload
systemctl enable security-monitor.service
systemctl restart security-monitor.service
ok "Service installed and started"

# ============================================
# VERIFY
# ============================================
echo ""
log "Verifying installation..."
sleep 2

if systemctl is-active --quiet security-monitor.service; then
    ok "security-monitor.service is running"
else
    die "Service failed to start. Check: journalctl -u security-monitor.service -n 20"
fi

# ============================================
# SUMMARY
# ============================================
echo ""
echo -e "\e[1m================================================\e[0m"
echo -e "\e[1m   Installation complete on $(hostname)\e[0m"
echo -e "\e[1m================================================\e[0m"
echo ""
echo "  Scripts:       $REAL_HOME/security_monitor.sh"
echo "                 $REAL_HOME/security_audit.sh"
echo "  Monitor conf:  $MONITOR_CONF"
echo "  Audit conf:    $AUDIT_CONF"
echo ""
echo "  Useful commands:"
echo "    journalctl -u security-monitor.service -f   # live logs"
echo "    systemctl status security-monitor.service   # status"
echo "    ~/security_audit.sh                         # manual audit"
echo ""

NTFY_TOPIC_VAL=$(grep "NTFY_TOPIC=" "$MONITOR_CONF" | cut -d'"' -f2)
if [[ -z "$NTFY_TOPIC_VAL" ]]; then
    warn "NTFY_TOPIC is not set. Edit $MONITOR_CONF and run:"
    warn "  sudo systemctl restart security-monitor.service"
fi
