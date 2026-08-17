#!/usr/bin/env bash
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: preflight.sh
# Purpose: Decides — without a human and without an AI reading the output —
#          whether this host may run logwall at all. Emits BLOCKER / WARNING /
#          INFO findings, each with the exact command that fixes it.
#
# Contract (relied upon by install.sh and by the cron path):
#   exit 0  READY     no blockers, no warnings — safe to install
#   exit 1  WARNINGS  no blockers, but issues an operator must acknowledge
#   exit 2  BLOCKED   at least one blocker — installation must not proceed
#   exit 3  INTERNAL  preflight itself could not run
#
# Usage:
#   ./preflight.sh                 full pre-installation gate
#   ./preflight.sh --runtime       fast subset, run before every apply
#   ./preflight.sh --json          machine-readable findings
#   ./preflight.sh --no-probe      skip the create/destroy capability probes
# ==============================================================================

set -uo pipefail

PF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# cron runs with PATH=/usr/bin:/bin. ipset, iptables and ip live in /sbin and
# /usr/sbin, so without this every scheduled cycle aborts on "ipset disappeared"
# while a manual run from a login shell succeeds — the installation looks healthy
# and does nothing at all.
case ":${PATH}:" in
    *:/sbin:*) ;;
    *) PATH="/usr/local/sbin:/usr/local/bin:/sbin:/usr/sbin:${PATH}" ;;
esac
export PATH

MODE="install"
AS_JSON=0
DO_PROBE=1
QUIET=0

for arg in "$@"; do
    case "$arg" in
        --runtime)  MODE="runtime" ;;
        --json)     AS_JSON=1 ;;
        --no-probe) DO_PROBE=0 ;;
        --quiet)    QUIET=1 ;;
    esac
done

# Findings are stored as: ID|SEVERITY|MESSAGE|FIX
FINDINGS=()
N_BLOCK=0
N_WARN=0
N_INFO=0

pf_add() {
    local severity="$1" id="$2" message="$3" fix="${4:-}"
    FINDINGS+=("${id}|${severity}|${message}|${fix}")
    case "$severity" in
        BLOCKER) N_BLOCK=$((N_BLOCK + 1)) ;;
        WARNING) N_WARN=$((N_WARN + 1)) ;;
        INFO)    N_INFO=$((N_INFO + 1)) ;;
    esac
}

pf_block() { pf_add BLOCKER "$1" "$2" "${3:-}"; }
pf_warn()  { pf_add WARNING "$1" "$2" "${3:-}"; }
pf_info()  { pf_add INFO    "$1" "$2" "${3:-}"; }

# Load configuration and shared modules; without them we cannot judge anything.
#
# LOGWALL_CONF mirrors what config_loader.py already honours, so the Bash and
# Python halves can be pointed at the same alternative file. Without it the path
# was hardcoded, and sourcing it OVERWROTE any variable the caller had exported —
# which silently defeated the test suite on any host where logwall is installed:
# fixtures set WHITELIST or BACKEND, /etc/logwall.conf clobbered them, and 14 gate
# checks failed for reasons that had nothing to do with the gate.
LOGWALL_CONF="${LOGWALL_CONF:-/etc/logwall.conf}"
[ -f "$LOGWALL_CONF" ] && { set -a; . "$LOGWALL_CONF"; set +a; }

if [ ! -f "${PF_DIR}/lib/naming.sh" ] || [ ! -f "${PF_DIR}/lib/system_discovery.sh" ]; then
    echo "[INTERNAL] preflight cannot find lib/naming.sh or lib/system_discovery.sh" >&2
    exit 3
fi
# shellcheck source=lib/naming.sh
. "${PF_DIR}/lib/naming.sh"
# shellcheck source=lib/system_discovery.sh
. "${PF_DIR}/lib/system_discovery.sh"
# shellcheck source=lib/firewall_wrapper.sh
. "${PF_DIR}/lib/firewall_wrapper.sh"
run_system_discovery

# ==============================================================================
# 1. Identity and platform
# ==============================================================================
check_platform() {
    if [ "$(id -u)" -ne 0 ]; then
        pf_block ROOT_REQUIRED \
            "Not running as root; logwall manages kernel firewall objects." \
            "sudo ./preflight.sh"
    fi

    if [ "$OS_FAMILY" = "unknown" ] || [ "$OS_FAMILY" = "generic" ]; then
        pf_warn OS_UNKNOWN \
            "Distro family not recognised (ID=${OS_DISTRO}); persistence paths are a guess." \
            "Set the persistence path manually, or run with --no-cron and verify after reboot."
    fi

    if [ "$INIT_SYSTEM" = "sysvinit" ]; then
        pf_warn INIT_UNKNOWN \
            "Neither systemd nor OpenRC detected; boot-time rule restore is unverified." \
            "Confirm how this host restores firewall rules at boot before enabling ENFORCE."
    fi
}

# ==============================================================================
# 2. Runtime prerequisites
# ==============================================================================
check_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        local install_cmd
        case "$OS_FAMILY" in
            debian) install_cmd="apt-get update && apt-get install -y python3" ;;
            rhel)   install_cmd="dnf install -y python3" ;;
            arch)   install_cmd="pacman -S --noconfirm python" ;;
            alpine) install_cmd="apk add --no-cache python3" ;;
            *)      install_cmd="install python3 using this system's package manager" ;;
        esac
        pf_block PYTHON_MISSING "python3 is not installed." "$install_cmd"
        return
    fi

    local version major minor
    version=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null)
    major=${version%%.*}
    minor=${version##*.}

    if [ -z "$version" ]; then
        pf_block PYTHON_BROKEN "python3 exists but will not report its version." \
            "Repair the Python installation before continuing."
        return
    fi

    if [ "$major" -lt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -lt 6 ]; }; then
        pf_block PYTHON_TOO_OLD "python3 is ${version}; logwall requires 3.6 or newer." \
            "Install a newer python3 package."
        return
    fi

    if ! python3 -c "import json,re,subprocess,ipaddress,glob,os,sys,datetime" 2>/dev/null; then
        pf_block PYTHON_STDLIB "python3 ${version} is missing required stdlib modules." \
            "Install the full python3 package (some minimal images strip the stdlib)."
        return
    fi

    pf_info PYTHON_OK "python3 ${version} with a complete stdlib." ""
}

check_firewall_tools() {
    command -v iptables >/dev/null 2>&1 || pf_block IPTABLES_MISSING \
        "iptables is not installed." \
        "$(pkg_hint iptables)"

    # In CSF coordination mode logwall owns no sets at all — every block is pushed
    # with `csf -d` and the ipset branch is skipped outright (firewall_wrapper.sh).
    # Demanding a tool that will never be called is a requirement the host has to
    # satisfy for nothing. In practice CSF brings ipset along anyway, so this
    # changes little; it is here because a gate should ask only for what it uses.
    if ! command -v ipset >/dev/null 2>&1; then
        if [ "${BACKEND:-auto}" = "csf" ]; then
            pf_info IPSET_NOT_NEEDED \
                "ipset is absent, but BACKEND=csf means logwall creates no sets — CSF owns the blocklist." ""
        else
            pf_block IPSET_MISSING \
                "ipset is not installed; set-based blocking is impossible without it." \
                "$(pkg_hint ipset)"
        fi
    fi

    if [ "${HAS_IPV6:-0}" = "1" ] && ! command -v ip6tables >/dev/null 2>&1; then
        pf_warn IP6TABLES_MISSING \
            "Host has global IPv6 but ip6tables is absent; IPv6 cannot be filtered." \
            "$(pkg_hint iptables)"
    fi

    command -v ss >/dev/null 2>&1 || pf_warn SS_MISSING \
        "'ss' is absent; post-apply connectivity verification will be skipped." \
        "$(pkg_hint iproute2)"
}

pkg_hint() {
    case "$OS_FAMILY" in
        debian) echo "apt-get install -y $1" ;;
        rhel)   echo "dnf install -y $1" ;;
        arch)   echo "pacman -S --noconfirm $1" ;;
        alpine) echo "apk add --no-cache $1" ;;
        *)      echo "install '$1' with this system's package manager" ;;
    esac
}

# ==============================================================================
# 3. Kernel capability probes
#
# Creating an unreferenced chain or an empty set changes nothing about packet
# flow, and both are removed immediately. This is the only way to know for
# certain that a container or a locked-down kernel will actually allow it.
# ==============================================================================
check_kernel_capability() {
    [ "$DO_PROBE" -eq 1 ] || { pf_info PROBE_SKIPPED "Capability probes skipped (--no-probe)." ""; return; }
    command -v ipset >/dev/null 2>&1 || return
    command -v iptables >/dev/null 2>&1 || return

    local probe="LOGWALL_PREFLIGHT"

    if ipset create "$probe" hash:net family inet comment maxelem 1024 2>/dev/null; then
        ipset destroy "$probe" 2>/dev/null || true
        pf_info IPSET_CAPABLE "Kernel accepts ipset creation (hash:net + comment)." ""
    else
        pf_block IPSET_NO_CAPABILITY \
            "Kernel refused to create a test ipset (missing ip_set module or NET_ADMIN)." \
            "modprobe ip_set  # or run this host outside an unprivileged container"
    fi

    if iptables -N "$probe" 2>/dev/null; then
        iptables -X "$probe" 2>/dev/null || true
        pf_info IPTABLES_CAPABLE "Kernel accepts iptables chain creation." ""
    else
        pf_block IPTABLES_NO_CAPABILITY \
            "Kernel refused to create a test iptables chain." \
            "Grant NET_ADMIN, or run on a host where iptables is writable."
    fi

    if [ "${HAS_IPV6:-0}" = "1" ] && command -v ip6tables >/dev/null 2>&1; then
        if ip6tables -N "$probe" 2>/dev/null; then
            ip6tables -X "$probe" 2>/dev/null || true
        else
            pf_warn IP6TABLES_NO_CAPABILITY \
                "Kernel refused an ip6tables test chain; IPv6 blocking will not work." \
                "Check ip6table_filter module availability."
        fi
    fi
}

# ==============================================================================
# 4. Competing security agents — a hard stop
#
# Two agents writing the same ruleset is the outage class that is hardest to
# diagnose, and the second one to run always wins. logwall refuses to install
# next to another blocker; the operator retires one first.
# ==============================================================================
check_competing_agents() {
    local found=0

    # --- 4a. Cron jobs belonging to another blocker -------------------------
    if command -v crontab >/dev/null 2>&1; then
        local line
        while IFS= read -r line; do
            case "$line" in
                ''|'#'*|*logwall-managed*) continue ;;
            esac
            case "$line" in
                *auto_blocker*|*blocker*|*fail2ban*|*ipset*|*iptables*|*firewall*)
                    pf_block COMPETING_CRON \
                        "Another blocking agent runs from cron: ${line}" \
                        "crontab -e   # comment out or delete this line, then re-run preflight"
                    found=1
                    ;;
            esac
        done < <(crontab -l 2>/dev/null)
    fi

    # --- 4b. Foreign ipsets referenced by live DROP rules -------------------
    if command -v iptables >/dev/null 2>&1 && command -v ipset >/dev/null 2>&1; then
        local owned set_name
        owned=" $(logwall_owned_sets) "
        while IFS= read -r set_name; do
            [ -n "$set_name" ] || continue
            case "$owned" in
                *" ${set_name} "*) continue ;;
            esac
            # In coordination mode CSF's own sets are expected, not a conflict.
            if [ "${BACKEND:-auto}" = "csf" ]; then
                case "$set_name" in
                    chain_DENY|chain_ALLOW|chain_6_DENY|chain_6_ALLOW) continue ;;
                esac
            fi

            local count
            count=$(ipset list "$set_name" -t 2>/dev/null | awk '/^Number of entries:/ {print $4}')
            pf_block FOREIGN_IPSET \
                "Live firewall rules use ipset '${set_name}' (${count:-?} entries) owned by another tool." \
                "Retire that tool first. Preserve its list before removing it: ipset list ${set_name} > /root/${set_name}.backup"
            found=1
        done < <(iptables -S 2>/dev/null | grep -- "--match-set" \
                 | sed -n 's/.*--match-set \([^ ]*\) .*/\1/p' | sort -u)
    fi

    # --- 4c. Managed security services --------------------------------------
    #
    # CSF is the one agent logwall knows how to defer to: with BACKEND=csf it
    # installs no chains and routes every block through `csf -d` (docs/DESIGN.md §8.B).
    # That deference has to be chosen deliberately, though — an accidental
    # side-by-side install is still a blocker.
    local csf_coordinated=0
    if [ "${BACKEND:-auto}" = "csf" ]; then
        csf_coordinated=1
    fi

    # Only agents that block addresses *dynamically* are competitors. Two tools
    # adding and removing bans against the same ruleset is the outage class this
    # gate exists to prevent.
    #
    # `--now` is deliberately absent from the fix: stopping a firewall service
    # flushes its ruleset, and on a host whose baseline it owns that leaves the
    # machine open until a replacement is in place.
    local svc
    for svc in fail2ban crowdsec crowdsec-firewall-bouncer; do
        if svc_is_active "$svc" 2>/dev/null; then
            pf_block COMPETING_SERVICE \
                "Service '${svc}' is active and also blocks addresses dynamically." \
                "Retire it first: systemctl disable ${svc}   # then stop it in a maintenance window"
            found=1
        fi
    done

    # firewalld and ufw own the *baseline* but never block dynamically, so logwall
    # layers on top of them rather than competing — a baseline that already exists
    # is a prerequisite for logwall, not an obstacle.
    #
    # The one real hazard is that both rebuild the entire ruleset on reload and
    # discard foreign rules. Surviving that is exactly what the selftest --repair
    # watchdog is for, so this is a warning the operator acknowledges, not a block.
    #
    # How much of a hazard that reload is depends on where the manager keeps its
    # rules. Measured on AlmaLinux 9.7 + firewalld 1.3.4 (2026-08-14): with the
    # nftables backend firewalld owns `table inet firewalld` while iptables writes
    # to `table ip filter`, so --reload, --complete-reload and a full service
    # restart all left logwall's chains, jumps and sets untouched. An iptables-backed
    # manager shares those tables and can genuinely tear them out.
    local hazard managers_up=0 managers_list=""
    for svc in firewalld ufw; do
        if svc_is_active "$svc" 2>/dev/null; then
            managers_up=$((managers_up + 1))
            managers_list="${managers_list}${managers_list:+ and }${svc}"
        fi
    done

    # Two baseline managers on one host is a misconfiguration in its own right:
    # each rebuilds the ruleset from its own model on reload, so whichever ran
    # last wins and the other's rules vanish without an error anywhere. logwall
    # survives that (its chains are its own), but the operator's baseline does not.
    if [ "$managers_up" -gt 1 ]; then
        pf_warn TWO_BASELINE_MANAGERS \
            "${managers_list} are both active. Each rebuilds the whole ruleset from its own configuration on reload, so the one that runs last silently discards the other's rules." \
            "Pick one and disable the other: systemctl disable <the one you are dropping>   # then stop it in a maintenance window. logwall works with either, but not with the two of them fighting"
    fi

    for svc in firewalld ufw; do
        if svc_is_active "$svc" 2>/dev/null; then
            if [ "$svc" = "firewalld" ] &&
               grep -qE '^FirewallBackend=nftables' /etc/firewalld/firewalld.conf 2>/dev/null; then
                hazard="This firewalld uses the nftables backend, so its rules live in a separate table and its reloads leave logwall's chains alone."
            else
                hazard="A '${svc}' reload rebuilds the ruleset in the same tables logwall uses. Measured on firewalld with FirewallBackend=iptables: a restart, --reload and --complete-reload each DELETE logwall's chains outright, not merely its jumps. The 2-minute 'firewall apply' cron rebuilds them, so enforcement is off for up to 2 minutes after every reload."
            fi
            pf_warn COEXISTS_WITH_MANAGER \
                "Service '${svc}' owns the baseline ruleset. logwall adds its own chains alongside it and never flushes globally." \
                "${hazard} After any reload, verify with: logwall selftest"
        fi
    done

    # `csf -x` leaves the units looking active, so the marker file decides.
    for svc in csf lfd; do
        if [ -f /etc/csf/csf.disable ]; then
            continue
        fi
        if svc_is_active "$svc" 2>/dev/null; then
            if [ "$csf_coordinated" -eq 1 ]; then
                pf_info CSF_COORDINATED \
                    "Service '${svc}' is active; logwall runs in CSF coordination mode." ""
            else
                pf_block COMPETING_SERVICE \
                    "Service '${svc}' is active and manages firewall rules." \
                    "Choose deference: echo 'BACKEND=csf' >> /etc/logwall.conf   # create the file if this is a fresh host, install.sh merges it. Or disable CSF with its own switch: csf -x"
                found=1
            fi
        fi
    done

    if [ -f /etc/csf/csf.conf ] && [ ! -f /etc/csf/csf.disable ]; then
        if [ "$csf_coordinated" -eq 1 ]; then
            pf_warn CSF_COORDINATION_MODE \
                "CSF owns the blocklist. logwall will install NO chains and no sets; every block goes through 'csf -d'." \
                "Verify with: logwall firewall status   (Mode should read 'CSF coordination')"
        else
            pf_block CSF_PRESENT \
                "ConfigServer Firewall (CSF) is installed; it periodically flushes iptables, which would tear out logwall's chains." \
                "Set BACKEND=csf in /etc/logwall.conf to coordinate with it, or run 'csf -x' to disable CSF."
            found=1
        fi
    fi

    # --- 4d. Known first-generation scripts on disk --------------------------
    local script
    # Globbed rather than listed: homegrown blockers land in whatever directory
    # their author happened to use, and a fixed list only ever finds the layouts
    # its author had seen. An unmatched glob stays literal, and `[ -f ]` on a
    # literal is simply false, so this costs nothing when there is nothing there.
    for script in /root/auto_blocker.sh /root/*/auto_blocker.sh \
                  /usr/local/bin/auto_blocker.sh /opt/*/auto_blocker.sh; do
        if [ -f "$script" ] && [ "$found" -eq 0 ]; then
            pf_warn LEGACY_SCRIPT_PRESENT \
                "Found ${script} on disk but not scheduled; it may be run manually." \
                "Confirm it is retired before enabling ENFORCE=1."
        fi
    done

    # Panels ship their own firewall modules, and logwall knows none of them by
    # name. It can see WHICH panel is installed but not whether that module is
    # enforcing — aaPanel's BT firewall, Plesk's firewall extension, HestiaCP's
    # rules. Saying nothing would imply it checked and found them clean.
    #
    # Deliberately a warning, not a blocker: this is an admission of ignorance,
    # and refusing an installation over something unverified would be worse than
    # naming it. CSF-backed panels (cPanel, DirectAdmin, CyberPanel) are already
    # covered above when CSF itself is present.
    case "${PANEL_TYPE:-none}" in
        aapanel|hestiacp|plesk)
            pf_warn PANEL_FIREWALL_UNCHECKED                 "Control panel '${PANEL_TYPE}' is installed and ships its own firewall module. logwall does not know how to inspect it, so it cannot tell you whether that module is currently managing rules."                 "Check it yourself in the panel UI. If it is enforcing, treat it like any other manager: keep one owner of the baseline, and confirm it does not also block addresses dynamically — that would compete with logwall."
            ;;
    esac

    [ "$found" -eq 0 ] && pf_info NO_COMPETITION "No competing blocking agent detected." ""
}

# ==============================================================================
# 5. Lockout risk
# ==============================================================================
# Counts whitelist entries that could actually let an administrator back in.
# Loopback and the unspecified address are excluded: the shipped template
# contains 127.0.0.1 and ::1, and counting those would mean the "only one admin
# IP" warning could never fire on a fresh installation.
count_usable_whitelist() {
    local file="${WHITELIST:-/etc/logwall/whitelist_ips.txt}"
    [ -f "$file" ] || { echo 0; return; }

    if command -v python3 >/dev/null 2>&1; then
        python3 - "$file" <<'PYEOF' 2>/dev/null || echo 0
import ipaddress, sys
count = 0
with open(sys.argv[1], encoding="utf-8", errors="ignore") as f:
    for line in f:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            net = ipaddress.ip_network(line.split()[0], strict=False)
        except ValueError:
            continue
        if net.is_loopback or net.is_unspecified:
            continue
        count += 1
print(count)
PYEOF
    else
        grep -vE '^\s*(#|$)' "$file" 2>/dev/null \
            | grep -vE '^\s*(127\.|::1)' | grep -c . || true
    fi
}

count_ddns_hosts() {
    local file="${WHITELIST_DYNAMIC_HOSTS:-/etc/logwall/whitelist_hosts.txt}"
    [ -f "$file" ] || { echo 0; return; }
    grep -vE '^\s*(#|$)' "$file" 2>/dev/null | grep -c . || true
}

check_lockout_risk() {
    local policy admin_ips="" ssh_port whitelist_count ddns_count total_paths

    policy=$(iptables -S 2>/dev/null | awk '/^-P INPUT/ {print $3}')
    ssh_port=$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/ {print $2; exit}' /etc/ssh/sshd_config 2>/dev/null)
    ssh_port="${ssh_port:-22}"

    [ -n "${SSH_CLIENT:-}" ]     && admin_ips="${admin_ips} $(echo "$SSH_CLIENT" | awk '{print $1}')"
    [ -n "${SSH_CONNECTION:-}" ] && admin_ips="${admin_ips} $(echo "$SSH_CONNECTION" | awk '{print $1}')"

    if command -v ss >/dev/null 2>&1; then
        admin_ips="${admin_ips} $(ss -tn state established "( sport = :${ssh_port} )" 2>/dev/null \
            | tail -n +2 | awk '{print $4}' | sed 's/:[0-9]*$//; s/^\[//; s/\]$//' | tr '\n' ' ')"
    fi

    whitelist_count=$(count_usable_whitelist)
    ddns_count=$(count_ddns_hosts)

    # A live SSH session counts as a path only because install.sh bootstraps it
    # into the whitelist; without that bootstrap it grants nothing.
    local session_paths=0
    [ -n "$(echo "$admin_ips" | tr -d ' ')" ] && session_paths=1
    total_paths=$(( whitelist_count + ddns_count + session_paths ))

    # --- Layer 1: at least one path back in. Non-negotiable. ----------------
    if [ "$total_paths" -eq 0 ]; then
        pf_block NO_ADMIN_IP \
            "No administrative access path exists: no session detected, whitelist empty, no DDNS hostname." \
            "echo 'YOUR.IP.HERE  # admin' >> /etc/logwall/whitelist_ips.txt   then re-run ./preflight.sh"
        return
    fi

    # --- Layer 2: a second, independent path is strongly recommended --------
    #
    # Whether a changing address actually locks you out depends on HOW the baseline
    # grants SSH, not on how many whitelist entries exist:
    #
    #   port-based   -A INPUT -p tcp --dport 22 -j ACCEPT      any source reaches SSH
    #   source-based -A INPUT -s 1.2.3.4/32 -j ACCEPT          only that address does
    #
    # Warning about a dynamic IP on a host whose SSH port is open to the world is
    # noise; staying quiet on a host that grants SSH only per-address is the real
    # failure. Measured on a production host: `iptables -S INPUT | grep 3456` had
    # zero ACCEPT rules — every way in was a source-based rule, and a changing ISP
    # address would have cost the only key.
    #
    # This is also where logwall differs from CSF and where operators get it wrong:
    # logwall's whitelist is not an access grant. It means "never block this". Losing
    # it costs immunity, not entry — unless the baseline has no port-based path.
    local ssh_port_open=0
    if iptables -S INPUT 2>/dev/null |
       grep -E -- '-j ACCEPT' |
       grep -qE -- "--dport[s]?[= ][0-9,:]*(^|[ ,])?${ssh_port}([ ,]|$|:)|--dport ${ssh_port}\b"; then
        ssh_port_open=1
    fi

    if [ "$total_paths" -eq 1 ]; then
        if [ "$ssh_port_open" -eq 1 ]; then
            pf_warn SINGLE_ADMIN_IP \
                "Only ONE administrative access path is whitelisted. SSH itself stays reachable from any source (port ${ssh_port} has a port-based ACCEPT), so a changing address will not lock you out — it only costs you immunity from logwall's own blocking." \
                "Still worth a second entry so a temporary address never gets blocked while you are using it: add a VPN/tethering IP, or a DDNS hostname in /etc/logwall/whitelist_hosts.txt."
        else
            pf_warn SINGLE_ADMIN_IP \
                "Only ONE administrative access path exists, AND this host grants SSH by source address only — port ${ssh_port} has no port-based ACCEPT rule. If that address changes or its ISP fails, there is no way back in except the provider console." \
                "Add a second path before enabling ENFORCE=1: a VPN/tethering IP, or a DDNS hostname in /etc/logwall/whitelist_hosts.txt (DuckDNS, No-IP, Dynu). Note this is a property of your BASELINE, not of logwall — the same risk existed before logwall was installed. Confirm your provider's console/VNC works."
        fi
    else
        pf_info ADMIN_PATHS "${total_paths} administrative access path(s): ${whitelist_count} static, ${ddns_count} dynamic, ${session_paths} live session." ""
    fi

    # --- Layer 3: DDNS entries must actually resolve -------------------------
    if [ "$ddns_count" -gt 0 ] && command -v python3 >/dev/null 2>&1; then
        local unresolved
        unresolved=$(PYTHONPATH="${PF_DIR}/lib/py" python3 - <<'PYEOF' 2>/dev/null || echo ""
from config_loader import load_config
from ddns_resolver import DDNSResolver
resolver = DDNSResolver(load_config())
resolver.resolve()
print(" ".join(resolver.failed_hosts))
PYEOF
)
        if [ -n "$unresolved" ]; then
            pf_warn DDNS_UNRESOLVED \
                "DDNS hostname(s) never resolved and grant no access: ${unresolved}" \
                "Verify the hostname and that your DDNS updater is running."
        fi
    fi

    if [ "$policy" = "DROP" ]; then
        pf_warn POLICY_DROP \
            "INPUT policy is DROP; any whitelist mistake locks this host out immediately." \
            "Keep console/VNC access open during the first apply, and use 'logwall firewall confirm'."
    fi

    check_baseline_policy "$policy"

    # IPv6 gets the same scrutiny as IPv4, and for the same reason: a denylist on
    # top of an unfiltered family protects the addresses it has seen and nothing
    # else. This used to be printed only by `apply`, where it scrolled past once
    # and was then silenced by logwall's own jumps — so it never reached the one
    # place an operator actually reads before deciding.
    #
    # It is a BLOCKER, not a warning, but a blocker with a one-line exit. The
    # difference matters: `--accept-warnings` sweeps up THRESHOLD_TOO_LOW and
    # SINGLE_ADMIN_IP in the same breath, and a gap that makes every IPv4
    # restriction bypassable should not be dismissable by the same flag that
    # dismisses a threshold suggestion. Refusing outright would be wrong too —
    # the host may be fully protected on IPv4, and denying that protection over a
    # gap in another family trades a certain loss for one that can be declared.
    #
    # So: state it, or fix it. Same shape as BASELINE=external, which exists
    # because guessing on the operator's behalf is what this tool refuses to do.
    if ! check_ipv6_exposure; then
        case "${IPV6_BASELINE:-auto}" in
            external|accepted)
                pf_info IPV6_ACKNOWLEDGED \
                    "IPV6_BASELINE=${IPV6_BASELINE} — the operator has declared this IPv6 exposure understood and accepted." ""
                ;;
            *)
                # Whoever already closed IPv4 can almost always close IPv6 too,
                # and usually with one setting rather than a second ruleset. Saying
                # "set ip6tables policy DROP" to someone running firewalld or CSF
                # sends them to build by hand what their manager does for free.
                local v6_fix
                case "${FIREWALL_BACKEND:-iptables}" in
                    csf)
                        v6_fix="CSF already covers IPv6 — check 'IPV6 = \"1\"' in /etc/csf/csf.conf, mirror your open ports into TCP6_IN/UDP6_IN, then: csf -r"
                        ;;
                    firewalld)
                        v6_fix="firewalld covers both families with one rule set, so an open IPv6 means the zone is not applied to it — check: firewall-cmd --list-all --zone=public, and confirm the interface is in that zone"
                        ;;
                    ufw)
                        v6_fix="ufw covers both families — confirm 'IPV6=yes' in /etc/default/ufw, then: ufw reload   # existing rules then apply to IPv6 as well"
                        ;;
                    nftables)
                        v6_fix="Use an 'inet' family table — it filters IPv4 and IPv6 in one ruleset, so your existing rules cover both without a second copy"
                        ;;
                    *)
                        v6_fix="No manager here, so IPv6 needs its own ruleset: mirror your ip6tables rules on the IPv4 ones (allow the ports you serve, then set INPUT policy DROP), and persist them the same way — an unpersisted v6 ruleset vanishes on reboot"
                        ;;
                esac

                pf_block IPV6_NO_BASELINE \
                    "${IPV6_EXPOSURE_DETAIL}" \
                    "${v6_fix}. Do it over a session you can afford to lose, and keep console access open. Or, if you have seen this and accept it: echo 'IPV6_BASELINE=external' >> /etc/logwall.conf   # either way logwall keeps covering IPv6 — this is about the host's firewall, not about logwall"
                ;;
        esac
    fi

    pf_info SSH_PORT "Detected SSH port: ${ssh_port}." ""
}

# ==============================================================================
# 5b. Baseline policy — the boundary of what logwall is
#
# logwall is a denylist: traffic is accepted until an address proves malicious.
# That can only ever be a LAYER on top of a default-deny policy. Installing it on
# a host where everything is open produces the most dangerous outcome available —
# an administrator who believes they are protected while every port stays
# reachable by anyone who has not yet tripped a threshold.
# ==============================================================================
check_baseline_policy() {
    local policy="$1"

    if [ "${BASELINE:-auto}" = "external" ]; then
        pf_info BASELINE_EXTERNAL \
            "BASELINE=external — the operator declares a default-deny exists upstream (cloud security group, edge firewall)." ""
        return
    fi

    if [ "$policy" = "DROP" ] || [ "$policy" = "REJECT" ]; then
        pf_info BASELINE_OK "INPUT policy is ${policy}; a default-deny baseline is in place." ""
        return
    fi

    # An iptables view is blind to a native nftables ruleset. On a host whose
    # filtering lives in its own nft table, `iptables -S INPUT` reports
    # "-P INPUT ACCEPT" and zero rules — a host that looks completely unprotected
    # while it is not. Measured on firewalld/nftables: 23 rules present, none of
    # them visible to iptables.
    #
    # Only an input hook with a drop/reject policy counts. A table full of accept
    # rules is not a baseline.
    if command -v nft >/dev/null 2>&1; then
        local nft_base
        nft_base=$(nft --handle list ruleset 2>/dev/null |
                   grep -E 'type[[:space:]]+filter[[:space:]]+hook[[:space:]]+input' |
                   grep -cE 'policy[[:space:]]+(drop|reject)') || nft_base=0
        if [ "${nft_base:-0}" -gt 0 ]; then
            pf_info BASELINE_OK \
                "A native nftables input hook enforces a drop policy (${nft_base} chain(s)); iptables cannot see it." ""
            return
        fi
    fi

    # No default-deny here. A manager may still provide one — but "active" is not
    # the question. `csf -x` leaves the oneshot unit active while enforcing nothing,
    # so a host with a disabled CSF would be credited with a baseline it does not have,
    # masking the NO_BASELINE_POLICY blocker that should have fired.
    #
    # nftables.service is deliberately absent: it is a boot-time rule loader (the
    # counterpart of iptables-persistent), not a manager, so its being active says
    # nothing about whether a default-deny exists.
    local guardian=""
    local svc
    for svc in csf firewalld ufw; do
        if [ "$svc" = "csf" ] && [ -f /etc/csf/csf.disable ]; then
            continue
        fi
        if svc_is_active "$svc" 2>/dev/null; then
            guardian="$svc"
            break
        fi
    done

    if [ -n "$guardian" ]; then
        pf_info BASELINE_OK "Default-deny is managed by '${guardian}'." ""
        return
    fi

    # This is the one blocker that asks the operator to go install something else,
    # so the advice has to be usable. "firewalld, ufw, or an iptables ruleset" is
    # three options and no guidance — offered at the exact moment the tool refuses
    # to continue, to someone who may not know which one their distro expects.
    # The distro is already detected by this point, so name the one that belongs
    # here and give the command.
    local baseline_fix
    case "${OS_FAMILY:-unknown}" in
        rhel)
            baseline_fix="Your distro's default is firewalld: dnf install -y firewalld && systemctl enable --now firewalld   # then open the ports you serve, e.g. firewall-cmd --permanent --add-service=https && firewall-cmd --reload"
            ;;
        debian)
            # Ubuntu lands in the debian family, but its convention is ufw while
            # Debian's is nftables — pointing an Ubuntu operator at nftables sends
            # them away from the tool their distro actually expects.
            if [ "${OS_DISTRO:-}" = "ubuntu" ]; then
                baseline_fix="Ubuntu's default is ufw: ufw allow OpenSSH && ufw enable   # add the ports you serve, e.g. ufw allow 443/tcp. Do it over a session you can afford to lose"
            else
                baseline_fix="On Debian: apt-get install -y nftables && systemctl enable --now nftables   # write your ruleset to /etc/nftables.conf. Or keep iptables: apt-get install -y iptables-persistent ipset-persistent"
            fi
            ;;
        alpine)
            baseline_fix="On Alpine: apk add iptables ip6tables && rc-update add iptables default   # set INPUT policy DROP and allow SSH before enabling"
            ;;
        arch)
            baseline_fix="On Arch: pacman -S --needed nftables && systemctl enable --now nftables   # /etc/nftables.conf holds the ruleset"
            ;;
        *)
            baseline_fix="Establish a default-deny first (firewalld, ufw, or an iptables ruleset)"
            ;;
    esac

    # When BOTH families are open, the IPv6 finding stays silent — it measures the
    # ASYMMETRY between the two, and there is none here. Without saying so, the
    # operator fixes IPv4, re-runs, and only then discovers a second job waiting.
    local also_v6=""
    if [ "${HAS_IPV6:-0}" = "1" ] && command -v ip6tables >/dev/null 2>&1; then
        local v6_policy
        v6_policy=$(ip6tables -S 2>/dev/null | awk '/^-P INPUT/ {print $3}')
        if [ "$v6_policy" = "ACCEPT" ]; then
            also_v6=" IPv6 is open here too, so this is TWO jobs, not one — closing IPv4 alone still leaves every service reachable over IPv6."
        fi
    fi

    # "Protects almost nothing" was too strong: on a host with real traffic logwall
    # still blocks the scrapers and brute-forcers it observes. What it cannot do is
    # close a port. Overstating the case invites the operator to dismiss the whole
    # finding once they notice it blocking real attackers.
    pf_block NO_BASELINE_POLICY \
        "INPUT policy is ${policy:-ACCEPT} and no firewall agent is active. logwall will still block abusers it detects, but it is a denylist — it never closes a port, so everything you run stays reachable by anyone who has not tripped a threshold yet.${also_v6}" \
        "${baseline_fix}. Already have a baseline upstream (cloud security group, edge firewall)? Declare it instead: echo 'BASELINE=external' >> /etc/logwall.conf"
}



# ==============================================================================
# 6. Configuration sanity
# ==============================================================================
check_configuration() {
    if ! naming_guard >/dev/null 2>&1; then
        pf_block RESERVED_SET_NAME \
            "Configured set names collide with names reserved for other tools." \
            "Use the prefixed defaults in /etc/logwall.conf (LOGWALL_BL4, LOGWALL_WL4, ...)"
    fi

    # The old THRESHOLD_HITS counted per WINDOW_HOURS. A value tuned for that
    # meaning, read as a per-interval figure, would switch detection almost
    # entirely off and say nothing, so a leftover name is reported not obeyed.
    if [ -n "${THRESHOLD_HITS:-}" ]; then
        pf_warn THRESHOLD_RENAMED \
            "THRESHOLD_HITS=${THRESHOLD_HITS} is no longer read: it counted per WINDOW_HOURS, and volume now counts per interval. The value is IGNORED." \
            "sed -i '/^THRESHOLD_HITS=/d' /etc/logwall.conf   # then set THRESHOLD_HITS_PER_INTERVAL"
    fi

    local hits="${THRESHOLD_HITS_PER_INTERVAL:-60}"
    if [ "$hits" -lt 20 ] 2>/dev/null; then
        pf_warn THRESHOLD_TOO_LOW \
            "THRESHOLD_HITS_PER_INTERVAL=${hits} per ${EVAL_INTERVAL_SEC:-120}s. One page view is 30-80 requests, so an ordinary visitor would be over the line every time." \
            "sed -i 's/^THRESHOLD_HITS_PER_INTERVAL=.*/THRESHOLD_HITS_PER_INTERVAL=60/' /etc/logwall.conf"
    fi

    if [ "${ENFORCE:-0}" = "1" ]; then
        pf_warn ENFORCE_ON \
            "ENFORCE=1 — this installation will drop packets as soon as it applies." \
            "Set ENFORCE=0 until you have reviewed the blacklist at least once."
    fi
}

# ==============================================================================
# 7. Detection viability — a blocker that blocks nothing is worse than none
# ==============================================================================
check_detection_inputs() {
    local logs=0

    # Ask the parser itself rather than keeping a second copy of the path list.
    # A duplicated list drifts: preflight once reported "no access log" on a
    # DirectAdmin host whose logs the parser could see perfectly well, because
    # only one of the two lists knew about /var/log/httpd/domains/.
    if command -v python3 >/dev/null 2>&1; then
        logs=$(PYTHONPATH="${PF_DIR}/lib/py" python3 - "$PANEL_TYPE" <<'PYEOF' 2>/dev/null || echo 0
import sys
from config_loader import load_config
from log_parser import LogParserEngine
engine = LogParserEngine(load_config())
print(len(engine.discover_log_files(sys.argv[1])))
PYEOF
)
        logs=${logs:-0}
    fi

    if [ "$logs" -eq 0 ]; then
        pf_warn NO_ACCESS_LOG \
            "No web access log found; logwall would run but detect nothing." \
            "Point LOG_PATHS at your access logs, or verify the web server writes them."
    else
        pf_info ACCESS_LOGS "Found ${logs} access log file(s)." ""
    fi

    check_peer_identity
    check_crawler_ranges
}

# The search engine range list is static, so it goes stale: the operators add ranges
# and this file does not learn about them. A stale list does not break anything, it
# just stops sparing a crawler it used to spare — which shows up as a search engine
# quietly disappearing from the site's traffic.
check_crawler_ranges() {
    local file="${CRAWLER_RANGES_FILE:-/etc/logwall/crawler_ranges.txt}"
    local max_age="${CRAWLER_RANGES_MAX_AGE_DAYS:-180}"

    if [ ! -r "$file" ]; then
        pf_warn CRAWLER_RANGES_MISSING             "No search engine range list at ${file}; Googlebot and bingbot can be blocked by a volume rule, which costs search visibility rather than saving bandwidth."             "Reinstall to restore it, or set CRAWLER_RANGES_FILE to your own list."
        return 0
    fi

    local age_days
    age_days=$(( ( $(date +%s) - $(stat -c %Y "$file" 2>/dev/null || echo 0) ) / 86400 ))
    if [ "$age_days" -gt "$max_age" ] 2>/dev/null; then
        pf_warn CRAWLER_RANGES_STALE             "${file} is ${age_days} days old (limit ${max_age}). Search engines add ranges; a stale list stops sparing crawlers it used to spare."             "Re-fetch from the URLs in the file header, e.g. curl -s https://developers.google.com/static/search/apis/ipranges/googlebot.json"
    else
        pf_info CRAWLER_RANGES "Search engine range list is ${age_days} day(s) old." ""
    fi
}

# Can the client address in the access log be believed at all?
#
# A public web server cannot be reached FROM 10.0.0.5 or 127.0.0.1. One of those
# sitting in the client field proves the server is rewriting that field from a
# forwarding header the client itself supplied — and from then on an attacker
# decides who logwall blocks. Naming the operator's own whitelisted address is
# enough to become permanently unblockable, and the refusal looks like a routine
# guard hit.
#
# Measured, never parsed from config: this misconfiguration is
# `useIpInProxyHeader 1` in LiteSpeed, `RemoteIPHeader` with no trusted-proxy list
# in Apache, `set_real_ip_from 0.0.0.0/0` in nginx, and `trust proxy: true` one
# layer up in Express. Any list of directive names would always lag; the symptom
# is identical everywhere.
check_peer_identity() {
    command -v python3 >/dev/null 2>&1 || return 0

    local found
    found=$(PYTHONPATH="${PF_DIR}/lib/py" python3 - "$PANEL_TYPE" <<'PYEOF' 2>/dev/null || echo ""
import sys
from config_loader import load_config
from ip_guard import is_unroutable_source
from log_parser import COMBINED_RE, LogParserEngine

engine = LogParserEngine(load_config())
seen = {}
for path in engine.discover_log_files(sys.argv[1])[:8]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for index, line in enumerate(handle):
                if index >= 4000:
                    break
                match = COMBINED_RE.match(line)
                if not match:
                    continue
                peer = match.group("ip").strip("[]")
                if is_unroutable_source(peer):
                    seen[peer] = seen.get(peer, 0) + 1
    except OSError:
        continue
if seen:
    top = sorted(seen.items(), key=lambda kv: -kv[1])[:3]
    print(", ".join("%s x%d" % (ip, n) for ip, n in top))
PYEOF
)

    if [ -n "$found" ]; then
        # A warning, not a blocker. Refusing to install would punish an operator
        # for a misconfiguration they do not yet know they have, and a product that
        # will not start reads as broken rather than careful. logwall installs,
        # audits, reports — and declines to block until the addresses can be
        # trusted, which the engine enforces on its own regardless of ENFORCE.
        pf_warn IDENTITY_UNTRUSTED \
            "The access log carries private/reserved client addresses (${found}). A public server cannot be reached from those, so the web server is rewriting the client address from a header the client sent — which lets any visitor choose whose address gets blocked, including yours. logwall will keep auditing but will NOT block until this is fixed, even with ENFORCE=1." \
            "LiteSpeed: set useIpInProxyHeader to 0, or 2 with a Trusted IP list. nginx: add set_real_ip_from <your proxy range> (never 0.0.0.0/0). Apache: add RemoteIPTrustedProxy alongside RemoteIPHeader. Then re-run: logwall doctor"
    fi
}

# ==============================================================================
# 8. Resources and scheduling
# ==============================================================================
check_resources() {
    local free_mb
    free_mb=$(df -Pm /opt 2>/dev/null | awk 'NR==2 {print $4}')
    free_mb="${free_mb:-$(df -Pm / 2>/dev/null | awk 'NR==2 {print $4}')}"

    if [ -n "$free_mb" ] && [ "$free_mb" -lt 500 ] 2>/dev/null; then
        pf_block LOW_DISK \
            "Only ${free_mb} MB free; snapshots and state need headroom." \
            "Free up disk space before installing."
    elif [ -n "$free_mb" ] && [ "$free_mb" -lt 2048 ] 2>/dev/null; then
        pf_warn LOW_DISK_WARN "Only ${free_mb} MB free on the install filesystem." \
            "Consider lowering SNAPSHOT_RETENTION in /etc/logwall.conf."
    fi
}

# ==============================================================================
# 8b. Boot persistence
#
# Saving the ruleset to /etc/sysconfig/iptables (or rules.v4) is only half the
# job. On RHEL 8/9 the unit that reloads it lives in the optional
# iptables-services package, and firewalld is the supported path — so the default
# state is a file that nothing ever reads. Every rule then vanishes on reboot,
# quietly, while the tool reports success.
# ==============================================================================
check_boot_persistence() {
    case "$FIREWALL_BACKEND" in
        firewalld|ufw|csf)
            pf_info PERSISTENCE_MANAGED                 "Boot persistence is handled by '${FIREWALL_BACKEND}'." ""
            return
            ;;
    esac

    if fw_persistence_available "$OS_FAMILY" 2>/dev/null; then
        pf_info PERSISTENCE_OK             "A unit exists to reload the saved ruleset at boot." ""
        return
    fi

    pf_warn NO_BOOT_PERSISTENCE         "Nothing on this host reloads a saved iptables ruleset at boot. logwall would write the file and every rule would still disappear on the next reboot."         "$(fw_persistence_package "$OS_FAMILY" 2>/dev/null || echo 'install your distro iptables persistence package')"
}

check_cron() {
    if ! command -v crontab >/dev/null 2>&1; then
        pf_block CRON_MISSING \
            "'crontab' is absent; the blocker cycle cannot be scheduled." \
            "$(pkg_hint cronie)   # or install with --no-cron and schedule it yourself"
        return
    fi

    local running=0 svc
    for svc in crond cron cronie busybox-crond; do
        if svc_is_active "$svc" 2>/dev/null; then running=1; break; fi
    done

    if [ "$running" -eq 0 ]; then
        pf_block CRON_NOT_RUNNING \
            "No cron daemon is active; scheduled jobs would never fire." \
            "systemctl enable --now crond   # (or cron / cronie on your distro)"
    else
        pf_info CRON_OK "Cron daemon is running." ""
    fi
}

check_time_sync() {
    local svc
    for svc in chronyd systemd-timesyncd ntpd; do
        if svc_is_active "$svc" 2>/dev/null; then
            pf_info TIME_SYNC "Time synchronisation active (${svc})." ""
            return
        fi
    done
    pf_warn NO_TIME_SYNC \
        "No time synchronisation service detected; the sliding window and TEMP block expiry depend on a correct clock." \
        "systemctl enable --now chronyd"
}

# ==============================================================================
# 9. Existing installation
# ==============================================================================
check_existing_install() {
    if [ -d /opt/logwall ]; then
        local installed="unknown"
        [ -f /opt/logwall/VERSION ] && installed=$(cat /opt/logwall/VERSION 2>/dev/null)
        pf_info ALREADY_INSTALLED "logwall ${installed} is already installed at /opt/logwall (this will be an upgrade)." ""
    fi

    local writable
    writable=$(find /opt/logwall /etc/logwall -perm -0002 2>/dev/null | head -n 3)
    if [ -n "$writable" ]; then
        pf_block WORLD_WRITABLE \
            "World-writable logwall files exist; anything writable here runs as root from cron." \
            "chmod -R o-w /opt/logwall /etc/logwall"
    fi
}

# ==============================================================================
# Reporting
# ==============================================================================
render_text() {
    local verdict="$1"
    local entry id severity message fix

    echo "=============================================================================="
    echo " logwall preflight — $(hostname) — $(date '+%Y-%m-%d %H:%M:%S')"
    echo " ${OS_DISTRO} (${OS_FAMILY}) · init=${INIT_SYSTEM} · backend=${FIREWALL_BACKEND} · panel=${PANEL_TYPE} · ipv6=${HAS_IPV6}"
    echo "=============================================================================="

    for severity in BLOCKER WARNING INFO; do
        local printed=0
        for entry in ${FINDINGS[@]+"${FINDINGS[@]}"}; do
            IFS='|' read -r id sev message fix <<< "$entry"
            [ "$sev" = "$severity" ] || continue
            if [ "$printed" -eq 0 ]; then
                echo
                case "$severity" in
                    BLOCKER) echo "--- BLOCKERS (installation refused until fixed) ---" ;;
                    WARNING) echo "--- WARNINGS (acknowledge with --accept-warnings) ---" ;;
                    INFO)    [ "$QUIET" -eq 1 ] && break; echo "--- INFO ---" ;;
                esac
                printed=1
            fi
            printf '  [%s] %s\n' "$id" "$message"
            [ -n "$fix" ] && printf '      FIX: %s\n' "$fix"
        done
    done

    echo
    echo "------------------------------------------------------------------------------"
    printf ' blockers=%d  warnings=%d  info=%d\n' "$N_BLOCK" "$N_WARN" "$N_INFO"
    echo " VERDICT: ${verdict}"
    case "$verdict" in
        READY)
            echo " This host meets every requirement. Proceed:  ./install.sh"
            ;;
        WARNINGS)
            echo " No blockers, but the warnings above are unresolved."
            echo " Fix them, or install explicitly accepting them:"
            echo "     ./install.sh --accept-warnings"
            ;;
        BLOCKED)
            echo " Installation must NOT proceed. Resolve every BLOCKER above,"
            echo " then run ./preflight.sh again. install.sh will refuse until it passes."
            ;;
    esac
    echo "=============================================================================="
}

render_json() {
    local verdict="$1" entry id sev message fix first=1
    printf '{\n  "host": "%s",\n  "verdict": "%s",\n' "$(hostname)" "$verdict"
    printf '  "distro": "%s", "family": "%s", "init": "%s", "backend": "%s", "panel": "%s", "ipv6": %s,\n' \
        "$OS_DISTRO" "$OS_FAMILY" "$INIT_SYSTEM" "$FIREWALL_BACKEND" "$PANEL_TYPE" "${HAS_IPV6:-0}"
    printf '  "counts": {"blocker": %d, "warning": %d, "info": %d},\n' "$N_BLOCK" "$N_WARN" "$N_INFO"
    printf '  "findings": [\n'
    for entry in ${FINDINGS[@]+"${FINDINGS[@]}"}; do
        IFS='|' read -r id sev message fix <<< "$entry"
        [ "$first" -eq 0 ] && printf ',\n'
        first=0
        printf '    {"id": "%s", "severity": "%s", "message": "%s", "fix": "%s"}' \
            "$id" "$sev" "${message//\"/\'}" "${fix//\"/\'}"
    done
    printf '\n  ]\n}\n'
}

# ==============================================================================
# Main
# ==============================================================================
if [ "$MODE" = "runtime" ]; then
    # Fast subset for the cron path: only conditions that can appear AFTER a
    # successful installation and would make a run unsafe.
    check_competing_agents
    check_configuration
    if ! command -v ipset >/dev/null 2>&1 && [ "${BACKEND:-auto}" != "csf" ]; then
        pf_block IPSET_MISSING "ipset disappeared." "$(pkg_hint ipset)"
    fi
else
    check_platform
    check_python
    check_firewall_tools
    check_kernel_capability
    check_competing_agents
    check_lockout_risk
    check_configuration
    check_detection_inputs
    check_resources
    check_boot_persistence
    check_cron
    check_time_sync
    check_existing_install
fi

if [ "$N_BLOCK" -gt 0 ]; then
    VERDICT="BLOCKED"; EXIT_CODE=2
elif [ "$N_WARN" -gt 0 ]; then
    VERDICT="WARNINGS"; EXIT_CODE=1
else
    VERDICT="READY"; EXIT_CODE=0
fi

if [ "$AS_JSON" -eq 1 ]; then
    render_json "$VERDICT"
else
    render_text "$VERDICT"
fi

exit "$EXIT_CODE"
