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

# Public entry point. $1 = 1 to enforce blocking, 0 for observe-only.
setup_iptables_chains() {
    local enforce="${1:-0}"

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
