#!/usr/bin/env bash
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: lib/rule_snapshot.sh
# Purpose: Timestamped ruleset snapshots and verified rollback. Pruning always
#          runs, including when an apply aborts, so snapshots cannot fill the disk.
# Reference: docs/DESIGN.md §7 (apply step 1), §16.6 (Snapshot Retention)
# ==============================================================================

SNAPSHOT_DIR="${SNAPSHOT_DIR:-/opt/logwall/data/snapshot}"

create_snapshot() {
    local timestamp target_dir
    timestamp=$(date '+%Y%m%d_%H%M%S')
    target_dir="${SNAPSHOT_DIR}/${timestamp}"

    mkdir -p "$target_dir" 2>/dev/null || {
        echo "[ERROR] Cannot create snapshot directory: ${target_dir}" >&2
        return 1
    }

    command -v iptables-save  >/dev/null 2>&1 && iptables-save  > "${target_dir}/iptables.rules"  2>/dev/null
    command -v ip6tables-save >/dev/null 2>&1 && ip6tables-save > "${target_dir}/ip6tables.rules" 2>/dev/null
    command -v ipset          >/dev/null 2>&1 && ipset save     > "${target_dir}/ipset.rules"     2>/dev/null

    [ -f "${BLACKLIST:-/etc/logwall/blacklist_ips.txt}" ] && \
        cp "${BLACKLIST:-/etc/logwall/blacklist_ips.txt}" "${target_dir}/blacklist_ips.txt" 2>/dev/null
    [ -f "${WHITELIST:-/etc/logwall/whitelist_ips.txt}" ] && \
        cp "${WHITELIST:-/etc/logwall/whitelist_ips.txt}" "${target_dir}/whitelist_ips.txt" 2>/dev/null

    echo "$timestamp"
    return 0
}

# Lists snapshot ids, oldest first. Uses a glob rather than `find -printf` or
# `ls` parsing so it behaves identically under busybox on Alpine.
list_snapshots() {
    local dir
    [ -d "$SNAPSHOT_DIR" ] || return 0
    for dir in "$SNAPSHOT_DIR"/*/; do
        [ -d "$dir" ] || continue
        dir="${dir%/}"
        printf '%s\n' "${dir##*/}"
    done | sort
}

# Returns the most recent snapshot id, or empty when none exists.
latest_snapshot() {
    list_snapshots | tail -n 1
}

# Restores a snapshot and verifies the result instead of assuming success.
restore_snapshot() {
    local snapshot_id="$1"
    local target_dir="${SNAPSHOT_DIR}/${snapshot_id}"
    local failures=0

    if [ ! -d "$target_dir" ]; then
        echo "[ERROR] Snapshot not found: ${target_dir}" >&2
        return 2
    fi

    if [ -f "${target_dir}/ipset.rules" ] && command -v ipset >/dev/null 2>&1; then
        # `ipset save` dumps every set on the host, including sets owned by other
        # tools. Rollback must touch ONLY logwall's own objects: flushing or
        # re-populating a foreign blocklist is not ours to do, and on a host
        # running a second blocker it would fight that tool on its next cycle.
        local set_name filtered
        filtered=$(mktemp)

        for set_name in $(logwall_owned_sets); do
            grep -E "^(create|add|flush) ${set_name}( |$)" "${target_dir}/ipset.rules" \
                >> "$filtered" 2>/dev/null || true
        done

        if [ -s "$filtered" ]; then
            # Emptied first because `ipset restore` adds to existing contents.
            # Flushed, never destroyed — an active iptables rule still refers to them.
            for set_name in $(logwall_owned_sets); do
                ipset flush "$set_name" 2>/dev/null || true
            done

            if ! ipset restore -exist < "$filtered"; then
                echo "[ERROR] ipset restore failed" >&2
                failures=$((failures + 1))
            fi
        fi

        rm -f "$filtered"
    fi

    if [ -f "${target_dir}/iptables.rules" ] && command -v iptables-restore >/dev/null 2>&1; then
        # Unlike the set restore above, this replaces the WHOLE ruleset — that is
        # what makes rollback trustworthy when the alternative is a locked-out
        # server. On a host sharing the ruleset with another blocker, that tool's
        # rules revert to their state at snapshot time until its next cycle.
        if command -v crontab >/dev/null 2>&1 && \
           crontab -l 2>/dev/null | grep -qvE "logwall-managed|^#|^$" && \
           crontab -l 2>/dev/null | grep -qE "block|firewall|ipset"; then
            echo "[WARN] Another blocking agent shares this ruleset; its rules revert to" >&2
            echo "[WARN] snapshot state until its own cycle runs again." >&2
        fi

        if ! iptables-restore < "${target_dir}/iptables.rules"; then
            echo "[ERROR] iptables-restore failed" >&2
            failures=$((failures + 1))
        fi
    fi

    if [ -f "${target_dir}/ip6tables.rules" ] && command -v ip6tables-restore >/dev/null 2>&1; then
        if ! ip6tables-restore < "${target_dir}/ip6tables.rules"; then
            echo "[ERROR] ip6tables-restore failed" >&2
            failures=$((failures + 1))
        fi
    fi

    if [ -f "${target_dir}/blacklist_ips.txt" ]; then
        cp "${target_dir}/blacklist_ips.txt" "${BLACKLIST:-/etc/logwall/blacklist_ips.txt}" 2>/dev/null || \
            failures=$((failures + 1))
    fi

    if [ "$failures" -ne 0 ]; then
        echo "[ERROR] Rollback to ${snapshot_id} completed with ${failures} failure(s)." >&2
        echo "[ERROR] Verify manually: iptables -S | head -n 20" >&2
        return 1
    fi

    echo "[INFO] Verified rollback to snapshot: ${snapshot_id}"
    return 0
}

# Keeps the newest N snapshots. Called from an EXIT trap so it still runs when an
# apply aborts halfway — otherwise a failing 2-minute cron fills the disk.
prune_snapshots() {
    local retention="${1:-30}"
    local victim

    [ -d "$SNAPSHOT_DIR" ] || return 0
    case "$retention" in
        ''|*[!0-9]*) retention=30 ;;
    esac

    list_snapshots | sort -r | tail -n "+$((retention + 1))" | while IFS= read -r victim; do
        case "$victim" in
            ''|*/*|.|..) continue ;;
        esac
        rm -rf "${SNAPSHOT_DIR:?}/${victim}"
    done
}
