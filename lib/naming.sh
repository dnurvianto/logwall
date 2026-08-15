#!/usr/bin/env bash
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: lib/naming.sh
# Purpose: Single source of truth for every kernel object logwall owns, plus the
#          guards that keep it from touching objects owned by somebody else.
#
# Why this exists: generic names like BLACKLIST_SET are what a first-generation
# blocker script picks, so they are exactly the names logwall must never claim.
# Swapping a set it did not create would silently replace another tool's
# blocklist — and on a host with `INPUT policy DROP`, replacing the whitelist set
# locks the operator out instantly.
# Reference: docs/DESIGN.md §8.A1, §8.E (Coexistence)
# ==============================================================================

# Overridable from /etc/logwall.conf. Every name is prefixed so a collision with
# another tool is not merely unlikely but impossible.
SET_WHITE4="${SET_WHITE4:-LOGWALL_WL4}"
SET_BLACK4="${SET_BLACK4:-LOGWALL_BL4}"
SET_WHITE6="${SET_WHITE6:-LOGWALL_WL6}"
SET_BLACK6="${SET_BLACK6:-LOGWALL_BL6}"

CHAIN_WL="${CHAIN_WL:-LOGWALL_WL}"
CHAIN_BLOCK="${CHAIN_BLOCK:-LOGWALL_BLOCK}"
CHAIN_RATE="${CHAIN_RATE:-LOGWALL_RATE}"

# Names logwall must never create, swap, flush, or destroy. These belong to
# first-generation blocker scripts and to other security tools.
# chain_DENY / chain_ALLOW (and their _6_ variants) are the sets CSF creates.
RESERVED_FOREIGN_SETS="BLACKLIST_SET WHITELIST_SET blacklist whitelist \
csf_deny csf_allow fail2ban f2b-sshd \
chain_DENY chain_ALLOW chain_6_DENY chain_6_ALLOW"

logwall_owned_sets() {
    printf '%s %s %s %s\n' "$SET_WHITE4" "$SET_BLACK4" "$SET_WHITE6" "$SET_BLACK6"
}

# Refuses to continue if the configuration points logwall at a set name that is
# reserved for another tool.
naming_guard() {
    local name reserved
    for name in $(logwall_owned_sets); do
        for reserved in $RESERVED_FOREIGN_SETS; do
            if [ "$name" = "$reserved" ]; then
                echo "[ERROR] Configured set name '${name}' is reserved for another tool." >&2
                echo "[ERROR] logwall refuses to manage it. Pick a prefixed name in /etc/logwall.conf." >&2
                return 2
            fi
        done

        # ipset limits object names to 31 characters.
        if [ "${#name}" -gt 27 ]; then
            echo "[ERROR] Set name '${name}' is too long (max 27 chars; _TMP suffix is appended)." >&2
            return 2
        fi
    done
    return 0
}

# Reports other blocking agents sharing this host. Never modifies anything —
# coexistence problems are surfaced to the operator, not resolved unilaterally.
detect_foreign_blockers() {
    local found=0 line set_name owned

    owned=" $(logwall_owned_sets) "

    if command -v iptables >/dev/null 2>&1; then
        local seen=" "
        while IFS= read -r line; do
            set_name=$(printf '%s\n' "$line" | sed -n 's/.*--match-set \([^ ]*\) .*/\1/p')
            [ -n "$set_name" ] || continue
            case "$owned" in
                *" ${set_name} "*) continue ;;
            esac

            # In coordination mode CSF's own sets are not a foreign agent to warn
            # about — they are the partner logwall was told to defer to, and
            # chain_DENY is precisely where its own blocks land. preflight.sh:282
            # already excludes them; this path did not, so `selftest`, `apply` and
            # `status` kept reporting the chosen configuration as something
            # unexpected. Calling a deliberate arrangement "foreign" is how a
            # report teaches an operator to skim past it.
            if [ "${BACKEND:-auto}" = "csf" ]; then
                case "$set_name" in
                    chain_DENY|chain_ALLOW|chain_6_DENY|chain_6_ALLOW) continue ;;
                esac
            fi

            # Deduplicated by set NAME, not by rule text: several rules commonly
            # reference one set, and `sort -u` on whole lines let the same set be
            # announced once per rule.
            case "$seen" in
                *" ${set_name} "*) continue ;;
            esac
            seen="${seen}${set_name} "

            echo "[FOREIGN] iptables rule uses set '${set_name}' (not managed by logwall)"
            found=1
        done < <(iptables -S 2>/dev/null | grep -- "--match-set" | grep -E "\-j (DROP|REJECT|ACCEPT)" | sort -u)
    fi

    if command -v crontab >/dev/null 2>&1; then
        while IFS= read -r line; do
            case "$line" in
                *logwall-managed*|'#'*|'') continue ;;
            esac
            case "$line" in
                *block*|*firewall*|*ipset*|*iptables*|*fail2ban*)
                    echo "[FOREIGN] competing cron job: ${line}"
                    found=1
                    ;;
            esac
        done < <(crontab -l 2>/dev/null)
    fi

    return "$found"
}

# Flags the case where IPv4 is filtered but IPv6 is wide open. Every IPv4 block
# is bypassable when the same services also listen on IPv6 unfiltered.
#
# Sets IPV6_EXPOSURE_DETAIL and returns 1 when exposed; prints nothing, so the CLI
# and preflight can render the same verdict in their own formats.
#
# The rule count deliberately EXCLUDES logwall's own jumps. Counting them meant the
# warning fired exactly once — on the first apply, before installation — and then
# went silent forever, because installing three LOGWALL_* jumps pushed the count
# past its own threshold. The tool masked a live exposure with its own presence:
# measured on a host still running IPv6 wide open, policy ACCEPT, ten services
# listening, and not a word said about it after the first run.
IPV6_EXPOSURE_DETAIL=""
check_ipv6_exposure() {
    IPV6_EXPOSURE_DETAIL=""
    command -v ip6tables >/dev/null 2>&1 || return 0
    [ "${HAS_IPV6:-0}" = "1" ] || return 0

    local v6_policy v6_rules v4_policy v6_listeners=""
    v6_policy=$(ip6tables -S 2>/dev/null | awk '/^-P INPUT/ {print $3}')
    v6_rules=$(ip6tables -S 2>/dev/null | grep '^-A INPUT' | grep -vc 'LOGWALL' || true)
    v4_policy=$(iptables -S 2>/dev/null | awk '/^-P INPUT/ {print $3}')

    if [ "$v6_policy" = "ACCEPT" ] && [ "${v6_rules:-0}" -lt 3 ] && [ "$v4_policy" = "DROP" ]; then
        # Wording matters more than it looks here. "IPv6 unprotected" does not say
        # WHO is failing to protect it, and a junior admin reads it as "logwall does
        # not cover IPv6" — the exact opposite of the truth. So the sentence opens
        # with what logwall IS doing, and only then names the gap and whose it is.
        if command -v ss >/dev/null 2>&1; then
            v6_listeners=$(ss -tlnH 2>/dev/null | awk '{print $4}' | grep -c '^\[' || true)
        fi
        IPV6_EXPOSURE_DETAIL="logwall protects IPv6 exactly as it protects IPv4 — same detection, same thresholds, blocking whole /64 ranges. The gap is elsewhere: THIS HOST has no IPv6 firewall at all. ip6tables INPUT policy is ACCEPT with ${v6_rules} rule(s) of its own, while IPv4 is DROP"
        if [ -n "$v6_listeners" ]; then
            IPV6_EXPOSURE_DETAIL="${IPV6_EXPOSURE_DETAIL}, and ${v6_listeners} service(s) are listening on IPv6"
        fi
        IPV6_EXPOSURE_DETAIL="${IPV6_EXPOSURE_DETAIL}. So anyone can reach those ports over IPv6, and every IPv4 restriction you set can be walked around."
        return 1
    fi
    return 0
}

# Renders the verdict for the CLI. Kept separate so preflight can use the same
# check without inheriting this output format.
report_ipv6_exposure() {
    check_ipv6_exposure && return 0
    echo "[IPV6_NO_BASELINE] ${IPV6_EXPOSURE_DETAIL}"
    echo "[IPV6_NO_BASELINE]   Nothing is wrong with logwall's IPv6 coverage — it is a denylist,"
    echo "[IPV6_NO_BASELINE]   and a denylist cannot close a port that nobody filters."
    return 1
}
