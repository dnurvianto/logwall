#!/usr/bin/env bash
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: lib/system_discovery.sh
# Purpose: Auto-detects Linux OS Distro, Init Manager (systemd vs OpenRC),
#          Firewall Backend (nftables, firewalld, ufw, iptables, csf),
#          and Active Webservers / Control Panels.
# Reference: docs/DESIGN.md §5 (Step 1 & 1b) & §20 (Support Matrix)
# ==============================================================================

# System environment variables populated by discovery
OS_DISTRO="unknown"
OS_FAMILY="unknown"
INIT_SYSTEM="unknown"
FIREWALL_BACKEND="unknown"
PANEL_TYPE="none"
WEBSERVER_TYPE="unknown"
HAS_IPV6=0

# Detect Linux Distribution Family and ID
detect_os() {
    if [ -f /etc/os-release ]; then
        # Parse standard os-release file
        . /etc/os-release
        OS_DISTRO="${ID:-unknown}"
        
        case "$OS_DISTRO" in
            ubuntu|debian)
                OS_FAMILY="debian"
                ;;
            almalinux|rocky|rhel|centos|fedora)
                OS_FAMILY="rhel"
                ;;
            arch|manjaro)
                OS_FAMILY="arch"
                ;;
            alpine)
                OS_FAMILY="alpine"
                ;;
            *)
                if [[ "${ID_LIKE:-}" =~ (debian|ubuntu) ]]; then
                    OS_FAMILY="debian"
                elif [[ "${ID_LIKE:-}" =~ (rhel|fedora|centos) ]]; then
                    OS_FAMILY="rhel"
                else
                    OS_FAMILY="generic"
                fi
                ;;
        esac
    else
        OS_DISTRO="unknown"
        OS_FAMILY="generic"
    fi
}

# Detect Init System (systemd vs OpenRC vs sysvinit)
# Ref: docs/DESIGN.md §5 Step 1b
detect_init_system() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        INIT_SYSTEM="systemd"
    elif command -v rc-service >/dev/null 2>&1 || [ -f /sbin/openrc ]; then
        INIT_SYSTEM="openrc"
    else
        INIT_SYSTEM="sysvinit"
    fi
}

# Abstract Service Management (Prevent hardcoded systemctl calls)
# Ref: docs/DESIGN.md §5 Step 1b & §8.A
svc_enable() {
    local service_name="$1"
    case "$INIT_SYSTEM" in
        systemd)
            systemctl enable "$service_name" >/dev/null 2>&1 || true
            ;;
        openrc)
            rc-update add "$service_name" default >/dev/null 2>&1 || true
            ;;
        *)
            # Generic fallback
            chkconfig "$service_name" on >/dev/null 2>&1 || true
            ;;
    esac
}

svc_start() {
    local service_name="$1"
    case "$INIT_SYSTEM" in
        systemd)
            systemctl start "$service_name" >/dev/null 2>&1 || true
            ;;
        openrc)
            rc-service "$service_name" start >/dev/null 2>&1 || true
            ;;
        *)
            service "$service_name" start >/dev/null 2>&1 || true
            ;;
    esac
}

svc_is_active() {
    local service_name="$1"
    case "$INIT_SYSTEM" in
        systemd)
            systemctl is-active --quiet "$service_name" 2>/dev/null
            return $?
            ;;
        openrc)
            rc-service "$service_name" status >/dev/null 2>&1
            return $?
            ;;
        *)
            service "$service_name" status >/dev/null 2>&1
            return $?
            ;;
    esac
}

# "Will this run at boot?" — a different question from "is it running now?", and
# the one that decides who owns persistence. A unit can be active but not enabled
# (started by hand, gone after reboot) or enabled but not yet active.
svc_is_enabled() {
    local service_name="$1"
    case "$INIT_SYSTEM" in
        systemd)
            systemctl is-enabled "$service_name" >/dev/null 2>&1
            return $?
            ;;
        openrc)
            rc-update show default 2>/dev/null | grep -q "^ *${service_name} "
            return $?
            ;;
        *)
            # SysV: an rc?.d symlink is the enablement record.
            ls /etc/rc*.d/S*"${service_name}" >/dev/null 2>&1
            return $?
            ;;
    esac
}

# Decides whether this host really runs nftables natively.
#
# The presence of the `nft` binary proves nothing: on RHEL 9, Debian 12, Ubuntu
# 22.04 and anything else shipping iptables >= 1.8, `iptables` IS nftables under
# the hood and creates `table ip filter`, `table ip nat`, `table ip mangle`,
# `table ip raw` automatically. Treating that as a native nftables host makes
# logwall persist rules into /etc/nftables.conf — a file nothing restores when
# nftables.service is disabled, so the ruleset vanishes on reboot while logwall
# reports success. Positive evidence is required instead.
# Ref: docs/DESIGN.md §8.A2
_nft_is_native() {
    command -v nft >/dev/null 2>&1 || return 1
    nft list tables >/dev/null 2>&1 || return 1

    # 1. The distro service that restores a native ruleset at boot.
    if svc_is_active nftables 2>/dev/null; then
        return 0
    fi
    if command -v systemctl >/dev/null 2>&1 && \
       systemctl is-enabled nftables >/dev/null 2>&1; then
        return 0
    fi

    # 2. A populated /etc/nftables.conf used to count as evidence here, on the
    #    reasoning that "something is expected to load it". It is not evidence:
    #    Debian's nftables package SHIPS a sample config, so the file is non-empty
    #    on a stock host whose nftables.service is disabled and whose rules are
    #    really persisted by netfilter-persistent.
    #
    #    Believing it misrouted persistence on every such host — logwall wrote the
    #    ruleset into /etc/nftables.conf, which nothing loads, and left
    #    /etc/iptables/rules.v4 (the file that IS loaded) without a single logwall
    #    rule. Measured on Debian 12: rules present, reboot would lose all of them,
    #    and the run reported success.
    #
    #    A config file proves nothing about who reads it. Only the unit (check 1)
    #    and a live non-compat ruleset (check 3) do.

    # 3. Any table outside the iptables-nft compatibility set. A family `inet`
    #    table, or a custom table name, cannot have been created by iptables-nft.
    if nft list tables 2>/dev/null | awk '
            $1 == "table" {
                family = $2; name = $3
                if (family == "inet") { found = 1; exit }
                if (name != "filter" && name != "nat" && name != "mangle" &&
                    name != "raw" && name != "security") { found = 1; exit }
            }
            END { exit(found ? 0 : 1) }
        '; then
        return 0
    fi

    return 1
}

# Detect Active Firewall Backend in priority order
# Priority: CSF -> firewalld -> ufw -> nftables (native only) -> iptables
# Ref: docs/DESIGN.md §8 & §8.B
detect_firewall_backend() {
    # Check for ConfigServer Security & Firewall (CSF)
    #
    # Installed is not the same as enforcing. `csf -x` leaves the binary and the
    # config in place and drops a marker file; routing blocks to `csf -d` on such
    # a host writes entries to csf.deny that are never applied to the kernel —
    # blocking that looks like it worked and did nothing. The service unit is not
    # a reliable signal either: it is oneshot and stays "active" after `csf -x`.
    if [ -f /etc/csf/csf.conf ] && command -v csf >/dev/null 2>&1        && [ ! -f /etc/csf/csf.disable ]; then
        FIREWALL_BACKEND="csf"
        return 0
    fi

    # Check for firewalld active state
    if command -v firewall-cmd >/dev/null 2>&1 && svc_is_active firewalld; then
        FIREWALL_BACKEND="firewalld"
        return 0
    fi

    # Check for UFW active state
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        FIREWALL_BACKEND="ufw"
        return 0
    fi

    # Check for a genuinely nftables-native host
    if _nft_is_native; then
        FIREWALL_BACKEND="nftables"
        return 0
    fi

    # Fallback to iptables
    FIREWALL_BACKEND="iptables"
}

# Detect Installed Web Control Panel
# Ref: docs/DESIGN.md §8.C & §20.C
detect_control_panel() {
    if [ -d /usr/local/fastpanel2 ] || command -v fastpanel >/dev/null 2>&1; then
        PANEL_TYPE="fastpanel"
    elif [ -d /usr/local/cpanel ]; then
        PANEL_TYPE="cpanel"
    elif [ -d /usr/local/psa ]; then
        PANEL_TYPE="plesk"
    elif [ -d /usr/local/directadmin ]; then
        PANEL_TYPE="directadmin"
    elif [ -d /usr/local/CyberCP ]; then
        PANEL_TYPE="cyberpanel"
    elif [ -d /www/server/panel ]; then
        PANEL_TYPE="aapanel"
    elif [ -d /usr/local/hestia ]; then
        PANEL_TYPE="hestiacp"
    else
        PANEL_TYPE="none"
    fi
}

# Check for IPv6 Global Connectivity
# Ref: docs/DESIGN.md §14
detect_ipv6_support() {
    if [ -f /proc/net/if_inet6 ] && ip -6 addr show scope global | grep -q "inet6"; then
        HAS_IPV6=1
    else
        HAS_IPV6=0
    fi
}

# Run full discovery suite
run_system_discovery() {
    detect_os
    detect_init_system
    detect_firewall_backend
    detect_control_panel
    detect_ipv6_support
}
