#!/usr/bin/env bash
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: uninstall.sh
# Purpose: Clean removal. Detaches every hook, destroys the kernel sets, drops the
#          cron entries, and verifies that nothing was left behind.
# Reference: docs/DESIGN.md §19 (Clean Uninstall)
# ==============================================================================

set -euo pipefail

PURGE_DATA=0
[ "${1:-}" = "--purge" ] && PURGE_DATA=1

echo "=============================================================================="
echo " logwall — Uninstaller"
echo "=============================================================================="

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Uninstallation must run as root." >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load the operator's configured object names before removing anything.
[ -f /etc/logwall.conf ] && { set -a; . /etc/logwall.conf; set +a; }
# shellcheck source=lib/naming.sh
. "${SCRIPT_DIR}/lib/naming.sh"

if [ -f "${SCRIPT_DIR}/lib/cron_manager.sh" ]; then
    # shellcheck source=lib/cron_manager.sh
    . "${SCRIPT_DIR}/lib/cron_manager.sh"
    remove_crons && echo "[INFO] Removed logwall cron entries."
fi

if [ -f "${SCRIPT_DIR}/lib/system_discovery.sh" ]; then
    # shellcheck source=lib/system_discovery.sh
    . "${SCRIPT_DIR}/lib/system_discovery.sh"
    run_system_discovery
fi

if [ -f "${SCRIPT_DIR}/lib/chain_manager.sh" ]; then
    # shellcheck source=lib/chain_manager.sh
    . "${SCRIPT_DIR}/lib/chain_manager.sh"
    panic_remove_chains
    echo "[INFO] Detached logwall hooks and deleted the LOGWALL_* chains."
fi

if command -v ipset >/dev/null 2>&1; then
    # Only objects logwall created are destroyed. Sets belonging to another
    # blocker (BLACKLIST_SET, WHITELIST_SET, CSF, fail2ban) are never touched —
    # uninstalling logwall must not disarm the tool it was meant to replace.
    for set_name in $(logwall_owned_sets); do
        ipset destroy "$set_name" 2>/dev/null || true
        ipset destroy "${set_name}_TMP" 2>/dev/null || true
    done
    echo "[INFO] Destroyed logwall kernel sets: $(logwall_owned_sets)"
    echo "[INFO] Sets owned by other tools were left untouched."
fi

rm -f /usr/local/bin/logwall 2>/dev/null || true

# Restore the nftables config we displaced, if we ever displaced one.
if [ -f /etc/nftables.conf.logwall-orig ]; then
    mv /etc/nftables.conf.logwall-orig /etc/nftables.conf
    echo "[INFO] Restored the original /etc/nftables.conf"
fi

if [ "$PURGE_DATA" -eq 1 ]; then
    echo "[INFO] Purging data, configuration, and logs..."
    rm -rf /opt/logwall /etc/logwall /etc/logwall.conf /var/log/logwall
else
    echo "[INFO] Data kept: /opt/logwall, /etc/logwall, ${SCRIPT_DIR}"
    echo "[INFO] Re-run with --purge to remove them as well."
fi

# ---------------------------------------------------------------- verification
FAILED=0
if command -v iptables >/dev/null 2>&1; then
    if iptables -S 2>/dev/null | grep -q "LOGWALL"; then
        echo "[FAIL] LOGWALL rules are still present in iptables:" >&2
        iptables -S | grep "LOGWALL" >&2
        FAILED=1
    else
        echo "[ OK ] No LOGWALL rule remains in iptables."
    fi
fi

if command -v ipset >/dev/null 2>&1; then
    LEFTOVER=""
    for set_name in $(logwall_owned_sets); do
        ipset list -n 2>/dev/null | grep -qx "$set_name" && LEFTOVER="${LEFTOVER} ${set_name}"
    done
    if [ -n "$LEFTOVER" ]; then
        echo "[FAIL] logwall ipsets still present:${LEFTOVER}" >&2
        FAILED=1
    else
        echo "[ OK ] No logwall ipset remains."
    fi
fi

if crontab -l 2>/dev/null | grep -q "logwall-managed"; then
    echo "[FAIL] logwall cron entries still present." >&2
    FAILED=1
else
    echo "[ OK ] No logwall cron entry remains."
fi

if [ "$FAILED" -ne 0 ]; then
    echo "[ERROR] Uninstall finished with unresolved leftovers (see above)." >&2
    exit 1
fi

echo "=============================================================================="
echo " Verified: logwall removed cleanly."
echo "=============================================================================="
