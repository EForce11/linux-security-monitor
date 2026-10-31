#!/bin/bash
# ============================================
# Linux Security Monitor - Uninstall Script (v3)
# Run with: sudo ./uninstall.sh
# ============================================
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] Run with sudo: sudo ./uninstall.sh"
    exit 1
fi

log()  { echo -e "\e[1m[•] $1\e[0m"; }
ok()   { echo -e "\e[32m[✓] $1\e[0m"; }
warn() { echo -e "\e[33m[!] $1\e[0m"; }
die()  { echo -e "\e[31m[✗] $1\e[0m"; exit 1; }

echo -e "\e[1m================================================\e[0m"
echo -e "\e[1m   Linux Security Monitor - Uninstaller (v3)\e[0m"
echo -e "\e[1m================================================\e[0m"
echo ""

# ============================================
# SYSTEMD TIMER & SERVICE
# ============================================
log "Stopping and disabling systemd timer..."
if systemctl is-active --quiet security-audit.timer 2>/dev/null; then
    systemctl stop security-audit.timer 2>/dev/null || true
    ok "Timer stopped"
else
    log "Timer is not running"
fi

if systemctl is-enabled --quiet security-audit.timer 2>/dev/null; then
    systemctl disable security-audit.timer 2>/dev/null || true
    ok "Timer disabled"
else
    log "Timer is not enabled"
fi

log "Stopping audit service (if running)..."
systemctl stop security-audit.service 2>/dev/null || true

# ============================================
# REMOVE SYSTEMD UNIT FILES
# ============================================
log "Removing systemd unit files..."
for unit in /etc/systemd/system/security-audit.service /etc/systemd/system/security-audit.timer; do
    if [[ -f "$unit" ]]; then
        rm -f "$unit"
        ok "Removed $unit"
    else
        log "$unit not found — skipping"
    fi
done

# Also clean up legacy v1/v2 service if present
if [[ -f /etc/systemd/system/security-monitor.service ]]; then
    systemctl stop security-monitor.service 2>/dev/null || true
    systemctl disable security-monitor.service 2>/dev/null || true
    rm -f /etc/systemd/system/security-monitor.service
    ok "Removed legacy security-monitor.service"
fi

systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true
ok "Systemd daemon reloaded"

# ============================================
# REMOVE AUDIT SCRIPT
# ============================================
log "Removing audit script..."
if [[ -f /usr/local/bin/security_audit.sh ]]; then
    rm -f /usr/local/bin/security_audit.sh
    ok "Removed /usr/local/bin/security_audit.sh"
else
    log "/usr/local/bin/security_audit.sh not found — skipping"
fi

# Also clean up legacy home directory scripts
REAL_USER="${SUDO_USER:-$(whoami)}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
for script in "$REAL_HOME/security_monitor.sh" "$REAL_HOME/security_audit.sh"; do
    if [[ -f "$script" ]]; then
        rm -f "$script"
        ok "Removed legacy $script"
    fi
done

# ============================================
# CONFIG FILES (INTERACTIVE)
# ============================================
echo ""
log "Checking configuration files..."

# System-wide config
if [[ -f /etc/security_audit.conf ]]; then
    read -rp "  Remove system config (/etc/security_audit.conf)? [y/N]: " REMOVE_SYS_CONF
    if [[ "$REMOVE_SYS_CONF" =~ ^[Yy]$ ]]; then
        rm -f /etc/security_audit.conf
        ok "Removed /etc/security_audit.conf"
    else
        log "Kept /etc/security_audit.conf"
    fi
fi

# User config (legacy)
for conf in "$REAL_HOME/.security_audit.conf" "$REAL_HOME/.security_monitor.conf"; do
    if [[ -f "$conf" ]]; then
        read -rp "  Remove $conf? [y/N]: " REMOVE_CONF
        if [[ "$REMOVE_CONF" =~ ^[Yy]$ ]]; then
            rm -f "$conf"
            ok "Removed $conf"
        else
            log "Kept $conf"
        fi
    fi
done

# ============================================
# SUMMARY
# ============================================
echo ""
echo -e "\e[1m================================================\e[0m"
echo -e "\e[1m   Uninstallation complete on $(hostname)\e[0m"
echo -e "\e[1m================================================\e[0m"
echo ""
