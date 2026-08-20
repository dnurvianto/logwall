#!/usr/bin/env bash
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: lib/chain_manager.sh
# Purpose: Creates the isolated LOGWALL_* chains, hooks them into INPUT (and
#          DOCKER-USER when Docker is present), and installs the actual ACCEPT /
#          DROP rules that reference the kernel ipsets.
# Reference: docs/DESIGN.md §8.A1 (Isolated Chains), §8.D (Docker), §14 (Dual-Stack)
# ==============================================================================

# Object names come from lib/naming.sh so there is exactly one definition.

# Returns 0 when the named ipset exists in the kernel.
_set_exists() {
    ipset list -n 2>/dev/null | grep -qx "$1"
}

# Idempotent jump insertion.
#
# The check MUST use exactly the same rule specification as the insert, otherwise
# `iptables -C` never matches and a duplicate jump is appended on every single
# run. That is why no `-m comment` is attached here — the chain names already
# identify logwall's rules unambiguously.
_ensure_jump() {
    local cmd="$1" chain="$2" target="$3" position="$4"

    $cmd -L "$chain" -n >/dev/null 2>&1 || return 0

    if ! $cmd -C "$chain" -j "$target" 2>/dev/null; then
        $cmd -I "$chain" "$position" -j "$target" 2>/dev/null || return 1
    fi
    return 0
}

_ensure_rule() {
    local cmd="$1"; shift
    local chain="$1"; shift

    if ! $cmd -C "$chain" "$@" 2>/dev/null; then
        $cmd -A "$chain" "$@" 2>/dev/null || return 1
    fi
    return 0
}

_remove_rule() {
    local cmd="$1"; shift
    local chain="$1"; shift

    while $cmd -C "$chain" "$@" 2>/dev/null; do
        $cmd -D "$chain" "$@" 2>/dev/null || break
    done
}

_create_chains() {
    local cmd="$1"
    $cmd -N "$CHAIN_WL" 2>/dev/null || true
    $cmd -N "$CHAIN_BLOCK" 2>/dev/null || true
    $cmd -N "$CHAIN_RATE" 2>/dev/null || true
}

# Installs chains, jumps, and rules for one address family.
#   $1 = iptables | ip6tables
#   $2 = whitelist set name
#   $3 = blacklist set name
#   $4 = 1 to install the DROP rule, 0 to make sure it is absent
_setup_family() {
    local cmd="$1" white_set="$2" black_set="$3" enforce="$4"

    command -v "$cmd" >/dev/null 2>&1 || return 0
    $cmd -L INPUT -n >/dev/null 2>&1 || return 0

    _create_chains "$cmd"

    # Order matters: whitelist is evaluated before the blacklist, always.
    _ensure_jump "$cmd" INPUT "$CHAIN_WL" 1
    _ensure_jump "$cmd" INPUT "$CHAIN_BLOCK" 2
    _ensure_jump "$cmd" INPUT "$CHAIN_RATE" 3

    # Container traffic is delivered through FORWARD/DOCKER-USER and never
    # traverses INPUT, so the blacklist has to be hooked there as well.
    if $cmd -L DOCKER-USER -n >/dev/null 2>&1; then
        _ensure_jump "$cmd" DOCKER-USER "$CHAIN_BLOCK" 1
    fi

    if _set_exists "$white_set"; then
        _ensure_rule "$cmd" "$CHAIN_WL" -m set --match-set "$white_set" src -j ACCEPT
    fi

    if [ "$enforce" = "1" ] && _set_exists "$black_set"; then
        _ensure_rule "$cmd" "$CHAIN_BLOCK" -m set --match-set "$black_set" src -j DROP
    else
        # Enforcement disabled (or the set is missing): guarantee no stale DROP
        # rule survives, so the tool can never block while it is meant to observe.
        _remove_rule "$cmd" "$CHAIN_BLOCK" -m set --match-set "$black_set" src -j DROP
    fi
}

# ---------------------------------------------------------------------------
# Static admin whitelist backup — a second, independent way for a whitelisted
# address to reach ACCEPT. docs/DESIGN.md has described this ("dual protection
# whitelist") since before this repository's own history; no code here ever
# built it. This closes that gap.
#
# Why a second mechanism at all: CHAIN_WL and this one fail for different
# reasons. An ipset that gets flushed, destroyed, or rebuilt empty mid-cycle
# takes every whitelisted address down with it, silently — the jump rule is
# still there, `iptables -L` still looks correct, and the packet just falls
# through to whatever chain comes next. A rule matched on the source address
# alone has no such dependency, so the two do not share a failure mode.
#
# Position is the other half of it, not an afterthought: a backup rule sitting
# below CHAIN_BLOCK protects nothing, because a blacklisted packet is already
# gone before it gets there. Every rule this installs goes in at INPUT
# position 1 — ahead of CHAIN_WL, CHAIN_BLOCK, CHAIN_RATE, and ahead of
# whatever another manager (ufw, firewalld) put there before logwall ran.
# ---------------------------------------------------------------------------

# Emits one whitelist entry per line, filtered to the given address family
# ("4" or "6"), comments and blank lines dropped. The one place that reads the
# file, so the ipset loader and this backup can never disagree about its
# contents.
_admin_backup_entries() {
    local family="$1"
    local file="${WHITELIST:-/etc/logwall/whitelist_ips.txt}"
    [ -f "$file" ] || return 0

    local line
    while IFS= read -r line; do
        line="${line%%#*}"
        line="$(printf '%s' "$line" | tr -d '[:space:]')"
        [ -n "$line" ] || continue
        case "$family" in
            4) case "$line" in *:*) continue ;; esac ;;
            6) case "$line" in *:*) ;; *) continue ;; esac ;;
        esac
        printf '%s\n' "$line"
    done < "$file"
}

# Installs whatever is missing, in whitelist-file order. Each insert lands at
# INPUT position 1, so entries are walked in reverse — the file's last address
# goes in first — leaving the file's own top-to-bottom order once every entry
# has been placed. Idempotent: the -C spec matches the -I spec exactly, so a
# repeat run inserts only what is actually missing.
_setup_admin_backup() {
    local cmd="$1" family="$2"

    command -v "$cmd" >/dev/null 2>&1 || return 0
    $cmd -L INPUT -n >/dev/null 2>&1 || return 0

    local -a entries=()
    local entry
    while IFS= read -r entry; do
        entries+=("$entry")
    done < <(_admin_backup_entries "$family")

    local i
    for (( i = ${#entries[@]} - 1; i >= 0; i-- )); do
        entry="${entries[$i]}"
        if ! _fw_valid_ip "$entry" 2>/dev/null; then
            echo "[WARN] Skipping invalid whitelist entry for admin backup: ${entry}" >&2
            continue
        fi
        if ! $cmd -C INPUT -s "$entry" -m comment --comment "$ADMIN_BACKUP_COMMENT" -j ACCEPT 2>/dev/null; then
            $cmd -I INPUT 1 -s "$entry" -m comment --comment "$ADMIN_BACKUP_COMMENT" -j ACCEPT 2>/dev/null || \
                echo "[WARN] Failed to install admin backup rule for ${entry}" >&2
        fi
    done
}

# Removes any backup rule whose address is no longer in the whitelist file —
# otherwise an address taken out of the whitelist would keep working forever
# through the very rule meant to be independent of that list's enforcement.
_cleanup_admin_backup() {
    local cmd="$1" family="$2"

    command -v "$cmd" >/dev/null 2>&1 || return 0
    $cmd -L INPUT -n >/dev/null 2>&1 || return 0

    local current=" $(_admin_backup_entries "$family" | tr '\n' ' ') "
    local stale_ip

    while IFS= read -r stale_ip; do
        [ -n "$stale_ip" ] || continue
        case "$current" in
            *" ${stale_ip} "*) continue ;;
        esac
        _remove_rule "$cmd" INPUT -s "$stale_ip" -m comment --comment "$ADMIN_BACKUP_COMMENT" -j ACCEPT
    done < <($cmd -S INPUT 2>/dev/null | \
        sed -n "s/^-A INPUT -s \([^ ]*\) -m comment --comment ${ADMIN_BACKUP_COMMENT} -j ACCEPT\$/\1/p")
}

# Public entry point for the backup layer, called from setup_iptables_chains()
# before the ipset-backed chains go in. $1 = 1 to enforce blocking, 0 for
# observe-only — the backup installs either way, since it only ever ACCEPTs
# and observe-only was never a reason to leave admins depending on one path.
setup_admin_whitelist_backup() {
    [ "${WHITELIST_DOUBLE_BACKUP:-1}" = "1" ] || return 0

    _cleanup_admin_backup iptables 4
    _setup_admin_backup iptables 4

    if [ "${HAS_IPV6:-0}" = "1" ]; then
        _cleanup_admin_backup ip6tables 6
        _setup_admin_backup ip6tables 6
    fi
}

# Removes every rule setup_admin_whitelist_backup() installed. Ref: docs/DESIGN.md §15.4
#
# `-D` needs the exact spec it was inserted with, source address included, so
# this enumerates real rules from `-S` first rather than guessing one -C spec
# that would never match anything and silently remove nothing.
panic_remove_admin_backup() {
    local cmd stale_ip
    for cmd in iptables ip6tables; do
        command -v "$cmd" >/dev/null 2>&1 || continue
        while IFS= read -r stale_ip; do
            [ -n "$stale_ip" ] || continue
            _remove_rule "$cmd" INPUT -s "$stale_ip" -m comment --comment "$ADMIN_BACKUP_COMMENT" -j ACCEPT
        done < <($cmd -S INPUT 2>/dev/null | \
            sed -n "s/^-A INPUT -s \([^ ]*\) -m comment --comment ${ADMIN_BACKUP_COMMENT} -j ACCEPT\$/\1/p")
    done
}

# Public entry point. $1 = 1 to enforce blocking, 0 for observe-only.
setup_iptables_chains() {
    local enforce="${1:-0}"

    # Installed first: it must sit above CHAIN_WL/CHAIN_BLOCK/CHAIN_RATE, and
    # each of those is only ever inserted once (guarded by its own -C check),
    # so anything installed here after they already exist would never move
    # above them again.
    setup_admin_whitelist_backup

    _setup_family iptables "$SET_WHITE4" "$SET_BLACK4" "$enforce"

    if [ "${HAS_IPV6:-0}" = "1" ]; then
        _setup_family ip6tables "$SET_WHITE6" "$SET_BLACK6" "$enforce"
    fi
}

# Flushes only logwall's own chains. A global `iptables -F` is never acceptable:
# it would destroy the rules owned by the panel, CSF, fail2ban, and Docker.
flush_logwall_chains() {
    local cmd
    for cmd in iptables ip6tables; do
        command -v "$cmd" >/dev/null 2>&1 || continue
        $cmd -F "$CHAIN_WL" 2>/dev/null || true
        $cmd -F "$CHAIN_BLOCK" 2>/dev/null || true
        $cmd -F "$CHAIN_RATE" 2>/dev/null || true
    done
}

# Emergency recovery: detach every logwall hook and delete the chains.
# Ref: docs/DESIGN.md §15.4
panic_remove_chains() {
    local cmd chain
    for cmd in iptables ip6tables; do
        command -v "$cmd" >/dev/null 2>&1 || continue

        for chain in "$CHAIN_WL" "$CHAIN_BLOCK" "$CHAIN_RATE"; do
            while $cmd -C INPUT -j "$chain" 2>/dev/null; do
                $cmd -D INPUT -j "$chain" 2>/dev/null || break
            done
        done

        while $cmd -C DOCKER-USER -j "$CHAIN_BLOCK" 2>/dev/null; do
            $cmd -D DOCKER-USER -j "$CHAIN_BLOCK" 2>/dev/null || break
        done
    done

    panic_remove_admin_backup
    flush_logwall_chains

    for cmd in iptables ip6tables; do
        command -v "$cmd" >/dev/null 2>&1 || continue
        $cmd -X "$CHAIN_WL" 2>/dev/null || true
        $cmd -X "$CHAIN_BLOCK" 2>/dev/null || true
        $cmd -X "$CHAIN_RATE" 2>/dev/null || true
    done
}

# Reports hook health for `logwall selftest`. Prints one line per check and
# returns non-zero when anything is missing.
chain_selftest() {
    local enforce="${1:-0}"
    local failures=0
    local cmd chain

    for cmd in iptables ip6tables; do
        command -v "$cmd" >/dev/null 2>&1 || continue
        [ "$cmd" = "ip6tables" ] && [ "${HAS_IPV6:-0}" != "1" ] && continue
        $cmd -L INPUT -n >/dev/null 2>&1 || continue

        for chain in "$CHAIN_WL" "$CHAIN_BLOCK" "$CHAIN_RATE"; do
            if $cmd -C INPUT -j "$chain" 2>/dev/null; then
                local count
                count=$($cmd -S INPUT 2>/dev/null | grep -c -- "-j ${chain}\$" || true)
                if [ "${count:-0}" -gt 1 ]; then
                    echo "[FAIL] ${cmd}: ${count} duplicate jumps to ${chain} in INPUT"
                    failures=$((failures + 1))
                else
                    echo "[ OK ] ${cmd}: jump INPUT -> ${chain}"
                fi
            else
                echo "[FAIL] ${cmd}: missing jump INPUT -> ${chain}"
                failures=$((failures + 1))
            fi
        done
    done

    if [ "${WHITELIST_DOUBLE_BACKUP:-1}" = "1" ]; then
        local backup_family backup_cmd backup_missing=0 backup_total=0 entry
        for backup_family in 4 6; do
            backup_cmd=iptables
            [ "$backup_family" = "6" ] && backup_cmd=ip6tables
            [ "$backup_family" = "6" ] && [ "${HAS_IPV6:-0}" != "1" ] && continue
            command -v "$backup_cmd" >/dev/null 2>&1 || continue

            while IFS= read -r entry; do
                [ -n "$entry" ] || continue
                backup_total=$((backup_total + 1))
                _fw_valid_ip "$entry" 2>/dev/null || continue
                if ! $backup_cmd -C INPUT -s "$entry" -m comment --comment "$ADMIN_BACKUP_COMMENT" -j ACCEPT 2>/dev/null; then
                    backup_missing=$((backup_missing + 1))
                fi
            done < <(_admin_backup_entries "$backup_family")
        done

        if [ "$backup_missing" -gt 0 ]; then
            echo "[FAIL] admin whitelist backup: ${backup_missing}/${backup_total} static ACCEPT rule(s) missing from INPUT"
            failures=$((failures + 1))
        elif [ "$backup_total" -gt 0 ]; then
            echo "[ OK ] admin whitelist backup: ${backup_total} static ACCEPT rule(s) present"
        fi
    fi

    local white_set="$SET_WHITE4" black_set="$SET_BLACK4"
    if _set_exists "$white_set"; then
        echo "[ OK ] ipset ${white_set} present"
    else
        echo "[FAIL] ipset ${white_set} missing"
        failures=$((failures + 1))
    fi

    if [ "$enforce" = "1" ]; then
        if iptables -C "$CHAIN_BLOCK" -m set --match-set "$black_set" src -j DROP 2>/dev/null; then
            echo "[ OK ] enforcement rule active (DROP on ${black_set})"
        else
            echo "[FAIL] enforcement enabled but DROP rule missing"
            failures=$((failures + 1))
        fi
    else
        echo "[INFO] ENFORCE=0 — observe-only mode, no DROP rule installed"
    fi

    return "$failures"
}
