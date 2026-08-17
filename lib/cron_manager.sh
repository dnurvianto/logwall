#!/usr/bin/env bash
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: lib/cron_manager.sh
# Purpose: Installs and removes logwall cron entries. Entries are identified by a
#          dedicated marker comment, never by the substring "logwall", so an
#          operator's own jobs whose paths happen to contain that word survive.
# Reference: docs/DESIGN.md §5 Step 9, §15.5 (Watchdog)
# ==============================================================================

CRON_MARKER="# logwall-managed"

# Prints the current root crontab with every logwall-managed line removed.
_crontab_without_logwall() {
    crontab -l 2>/dev/null | grep -v -F "$CRON_MARKER" || true
}

install_crons() {
    local tmp_cron interval watchdog
    interval="${BLOCKER_SCHEDULE:-*/2 * * * *}"
    watchdog="${WATCHDOG_SCHEDULE:-*/10 * * * *}"

    tmp_cron=$(mktemp) || return 1

    _crontab_without_logwall > "$tmp_cron"

    # Output goes to a run log, not to /dev/null. Every diagnostic logwall emits
    # — PROFILING_OFF, GUARD refusals, CSF_RESYNC, SETTING_RENAMED, CDN_NO_REALIP
    # — is written to stderr, and the line installed here used to discard all of
    # it. A host could have detection switched off for a day and look healthy.
    # logwall trims this file itself (see _trim_run_log), so no logrotate rule is
    # required for a tool whose whole point is running unattended.
    local runlog="${REPORT_DIR:-/var/log/logwall}/run.log"

    {
        echo "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/usr/sbin:/usr/bin:/bin ${CRON_MARKER}"
        echo "${interval} /opt/logwall/logwall firewall apply --no-confirm --quiet >>${runlog} 2>&1 ${CRON_MARKER}"
        echo "${watchdog} /opt/logwall/logwall selftest --repair --quiet >>${runlog} 2>&1 ${CRON_MARKER}"
        echo "5 0 * * * /opt/logwall/logwall firewall report --quiet >>${runlog} 2>&1 ${CRON_MARKER}"
    } >> "$tmp_cron"

    if ! crontab "$tmp_cron"; then
        echo "[ERROR] Failed to install crontab entries." >&2
        rm -f "$tmp_cron"
        return 1
    fi

    rm -f "$tmp_cron"
    return 0
}

remove_crons() {
    local tmp_cron
    tmp_cron=$(mktemp) || return 1

    _crontab_without_logwall > "$tmp_cron"

    if ! crontab "$tmp_cron"; then
        echo "[WARN] Failed to rewrite crontab while removing logwall entries." >&2
        rm -f "$tmp_cron"
        return 1
    fi

    rm -f "$tmp_cron"
    return 0
}

cron_selftest() {
    local count
    count=$(crontab -l 2>/dev/null | grep -c -F "$CRON_MARKER" || true)
    if [ "${count:-0}" -ge 3 ]; then
        echo "[ OK ] ${count} logwall cron entries registered"
        return 0
    fi
    echo "[FAIL] logwall cron entries missing (found ${count:-0})"
    return 1
}
