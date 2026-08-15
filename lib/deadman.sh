#!/usr/bin/env bash
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: lib/deadman.sh
# Purpose: Post-apply safety. Verifies that administrative connectivity survived,
#          then arms a deadman timer that rolls the ruleset back unless the
#          operator confirms. Works with systemd, `at`, or a plain background
#          process, so Alpine and minimal Arch are covered too.
# Reference: docs/DESIGN.md §7 (apply step 8-12), §15.3 (Deadman Switch)
# ==============================================================================

DEADMAN_STATE_DIR="${DEADMAN_STATE_DIR:-/opt/logwall/data/state}"
DEADMAN_MARKER="${DEADMAN_STATE_DIR}/deadman.marker"
DEADMAN_PIDFILE="${DEADMAN_STATE_DIR}/deadman.pid"

# Resolves the SSH port from sshd_config, falling back to 22.
detect_ssh_port() {
    local port=""
    if [ -f /etc/ssh/sshd_config ]; then
        port=$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/ {print $2; exit}' /etc/ssh/sshd_config 2>/dev/null)
    fi
    echo "${port:-22}"
}

# Counts established administrative sessions. Returns 0 when `ss` is unavailable.
count_admin_sessions() {
    local ssh_port
    ssh_port=$(detect_ssh_port)

    command -v ss >/dev/null 2>&1 || { echo "-1"; return 0; }

    ss -tn state established "( sport = :${ssh_port} )" 2>/dev/null \
        | tail -n +2 | grep -c . || true
}

# Confirms that administrative connectivity survived the rule change.
#
# The pre-apply count is required: an unattended cron run legitimately has zero
# sessions, and treating that as a lockout would roll back on every single cycle.
# Only losing sessions that existed before the change is a real failure.
verify_admin_connectivity() {
    local before="${1:--1}"
    local after

    if [ "$before" = "-1" ]; then
        echo "[WARN] 'ss' unavailable — administrative connectivity not verified." >&2
        return 0
    fi

    if [ "$before" -eq 0 ]; then
        echo "[INFO] No administrative session was open before apply — nothing to verify."
        return 0
    fi

    after=$(count_admin_sessions)

    if [ "$after" -ge 1 ]; then
        echo "[ OK ] ${after}/${before} administrative session(s) still established."
        return 0
    fi

    echo "[ERROR] All ${before} administrative session(s) disappeared after apply." >&2
    return 1
}

# Schedules an automatic rollback unless `logwall firewall confirm` clears it.
arm_deadman() {
    local snapshot_id="$1"
    local timeout_sec="${2:-300}"
    local logwall_bin="${3:-/opt/logwall/logwall}"

    mkdir -p "$DEADMAN_STATE_DIR" 2>/dev/null || true
    printf '%s\n' "$snapshot_id" > "$DEADMAN_MARKER"

    local rollback_cmd="${logwall_bin} firewall rollback ${snapshot_id} --deadman"

    if command -v systemd-run >/dev/null 2>&1 && [ "${INIT_SYSTEM:-}" = "systemd" ]; then
        systemd-run --quiet --on-active="${timeout_sec}" \
            --unit="logwall-deadman-${snapshot_id}" \
            /bin/sh -c "[ -f '${DEADMAN_MARKER}' ] && ${rollback_cmd}" >/dev/null 2>&1 && {
            echo "[DEADMAN] Armed via systemd-run (${timeout_sec}s). Run 'logwall firewall confirm' to cancel."
            return 0
        }
    fi

    if command -v at >/dev/null 2>&1; then
        local minutes=$(( (timeout_sec + 59) / 60 ))
        if echo "[ -f '${DEADMAN_MARKER}' ] && ${rollback_cmd}" | at now + "${minutes}" minutes >/dev/null 2>&1; then
            echo "[DEADMAN] Armed via at (${minutes}m). Run 'logwall firewall confirm' to cancel."
            return 0
        fi
    fi

    # Universal fallback: a detached shell. The marker file, not the process, is
    # what decides — if this process dies, `selftest` still sees a stale marker.
    setsid /bin/sh -c "sleep ${timeout_sec}; [ -f '${DEADMAN_MARKER}' ] && ${rollback_cmd}" \
        >/dev/null 2>&1 &
    echo $! > "$DEADMAN_PIDFILE"
    echo "[DEADMAN] Armed via background timer (${timeout_sec}s). Run 'logwall firewall confirm' to cancel."
    return 0
}

confirm_deadman() {
    if [ ! -f "$DEADMAN_MARKER" ]; then
        echo "[INFO] No pending apply to confirm."
        return 0
    fi

    local snapshot_id
    snapshot_id=$(cat "$DEADMAN_MARKER" 2>/dev/null)
    rm -f "$DEADMAN_MARKER"

    if [ -f "$DEADMAN_PIDFILE" ]; then
        local pid
        pid=$(cat "$DEADMAN_PIDFILE" 2>/dev/null)
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
        rm -f "$DEADMAN_PIDFILE"
    fi

    if command -v systemctl >/dev/null 2>&1 && [ "${INIT_SYSTEM:-}" = "systemd" ]; then
        systemctl stop "logwall-deadman-${snapshot_id}.timer" >/dev/null 2>&1 || true
    fi

    echo "[INFO] Apply confirmed (snapshot ${snapshot_id}). Deadman rollback cancelled."
    return 0
}

# Called by the watchdog: a marker older than the timeout means the operator
# never confirmed and the scheduled rollback did not fire either.
deadman_check_stale() {
    local timeout_sec="${1:-300}"
    local logwall_bin="${2:-/opt/logwall/logwall}"

    [ -f "$DEADMAN_MARKER" ] || return 0

    local now mtime age
    now=$(date +%s)
    mtime=$(stat -c %Y "$DEADMAN_MARKER" 2>/dev/null || stat -f %m "$DEADMAN_MARKER" 2>/dev/null || echo "$now")
    age=$((now - mtime))

    if [ "$age" -ge "$timeout_sec" ]; then
        local snapshot_id
        snapshot_id=$(cat "$DEADMAN_MARKER" 2>/dev/null)
        echo "[DEADMAN] Unconfirmed apply is ${age}s old — rolling back to ${snapshot_id}." >&2
        rm -f "$DEADMAN_MARKER"
        "$logwall_bin" firewall rollback "$snapshot_id" --deadman
        return 1
    fi
    return 0
}
