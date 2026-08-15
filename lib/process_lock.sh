#!/usr/bin/env bash
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: lib/process_lock.sh
# Purpose: Manages non-blocking file locking (`flock`) to prevent concurrent
#          execution races between cron tasks, manual applies, and watchdogs.
# Reference: docs/DESIGN.md §16.1 (File Lock & Stale Lock Management)
# ==============================================================================

LOCK_FD=200

# Acquire non-blocking file lock
# Exit code 4: Lock held by another active process (Ref: docs/DESIGN.md §18 Exit Codes)
acquire_lock() {
    local lock_file="${1:-/var/lock/logwall.lock}"
    local stale_min="${2:-30}"

    # Ensure lock directory exists
    mkdir -p "$(dirname "$lock_file")" 2>/dev/null || true

    # The lock file is never deleted. flock() is released by the kernel the moment
    # the holding process dies, so a leftover file is not a stale lock — but
    # unlinking it while another process still holds the old inode would let two
    # runs proceed at once, which is exactly the race this module exists to stop.
    eval "exec ${LOCK_FD}>>\"${lock_file}\"" || {
        echo "[ERROR] Cannot open lock file: ${lock_file}" >&2
        exit 2
    }

    if ! flock -n ${LOCK_FD}; then
        local holder="unknown"
        [ -r "$lock_file" ] && holder=$(head -n 1 "$lock_file" 2>/dev/null || echo unknown)

        # A genuinely long-running holder is worth reporting, but it is still a
        # live process — we refuse to run rather than fight it.
        if command -v stat >/dev/null 2>&1; then
            local now mtime age_min
            now=$(date +%s)
            mtime=$(stat -c %Y "$lock_file" 2>/dev/null || stat -f %m "$lock_file" 2>/dev/null || echo "$now")
            age_min=$(( (now - mtime) / 60 ))
            if [ "$age_min" -ge "$stale_min" ]; then
                echo "[WARN] Lock held by PID ${holder} for ${age_min}m (>= ${stale_min}m)." >&2
                echo "[WARN] Investigate that process; logwall will not force the lock." >&2
            fi
        fi

        echo "[ERROR] Another logwall instance holds the lock (PID ${holder}). Exiting (code 4)." >&2
        exit 4
    fi

    # Record the owning PID for traceability.
    : > "$lock_file"
    echo "$$" > "$lock_file"
}

# Release process lock
release_lock() {
    flock -u ${LOCK_FD} 2>/dev/null || true
    eval "exec ${LOCK_FD}>&-"
}
