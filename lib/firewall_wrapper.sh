#!/usr/bin/env bash
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: lib/firewall_wrapper.sh
# Purpose: Kernel-level abstraction over ipset / iptables / nftables / CSF.
#          Owns set creation, atomic set reloads, and rule persistence.
# Reference: docs/DESIGN.md §8 (Backend Abstraction), §8.A (Persistence), §8.A3 (Capacity)
# ==============================================================================

# Object names come from lib/naming.sh so there is exactly one definition.

fw_have_ipset() {
    command -v ipset >/dev/null 2>&1
}

_fw_set_exists() {
    ipset list -n 2>/dev/null | grep -qx "$1"
}

# Verifies that an existing set carries the `comment` extension. A set created by
# an older build without it will silently reject every `add ... comment "..."`.
_fw_set_has_comment() {
    ipset list -t "$1" 2>/dev/null | grep -qi "comment"
}

_fw_create_set() {
    local name="$1" family="$2" maxelem="$3"

    if _fw_set_exists "$name"; then
        # A pre-existing set under our own name must still match what we expect.
        # Adopting a set of the wrong type or family would corrupt it on the
        # first atomic swap.
        local actual_type actual_family
        actual_type=$(ipset list "$name" -t 2>/dev/null | awk '/^Type:/ {print $2}')
        actual_family=$(ipset list "$name" -t 2>/dev/null | sed -n 's/.*family \([a-z0-9]*\).*/\1/p' | head -1)

        if [ "$actual_type" != "hash:net" ] || \
           { [ -n "$actual_family" ] && [ "$actual_family" != "$family" ]; }; then
            echo "[ERROR] Set '${name}' already exists as type='${actual_type}' family='${actual_family}'," >&2
            echo "[ERROR] but logwall needs hash:net/${family}. Refusing to touch it." >&2
            return 1
        fi

        if ! _fw_set_has_comment "$name"; then
            echo "[WARN] ipset ${name} exists without the 'comment' extension." >&2
            echo "[WARN] Metadata will not be stored in the kernel set. Recreate it with:" >&2
            echo "[WARN]   ipset destroy ${name} && logwall firewall apply" >&2
        fi
        return 0
    fi

    if ! ipset create "$name" hash:net family "$family" comment maxelem "$maxelem" -exist 2>/dev/null; then
        echo "[ERROR] Failed to create ipset ${name} (family ${family})." >&2
        return 1
    fi
    return 0
}

# Ensures every kernel set exists before any rule can reference it.
fw_init_sets() {
    local maxelem="${1:-262144}"
    local rc=0

    # Never proceed if the configuration aims logwall at another tool's objects.
    naming_guard || return 2

    fw_have_ipset || {
        echo "[ERROR] 'ipset' is not installed — set-based blocking is unavailable." >&2
        return 3
    }

    _fw_create_set "$SET_WHITE4" inet "$maxelem" || rc=1
    _fw_create_set "$SET_BLACK4" inet "$maxelem" || rc=1

    if [ "${HAS_IPV6:-0}" = "1" ]; then
        _fw_create_set "$SET_WHITE6" inet6 "$maxelem" || rc=1
        _fw_create_set "$SET_BLACK6" inet6 "$maxelem" || rc=1
    fi

    return "$rc"
}

# Applies a generated `ipset restore` script. The script builds temporary sets and
# swaps them in, so the kernel is never left with a partially loaded blacklist.
fw_load_set_script() {
    local script_path="$1"

    [ -f "$script_path" ] || {
        echo "[ERROR] ipset script not found: ${script_path}" >&2
        return 2
    }

    fw_have_ipset || return 3

    if ! ipset restore < "$script_path"; then
        echo "[ERROR] 'ipset restore' failed — kernel sets were left unchanged." >&2
        return 1
    fi
    return 0
}

fw_set_count() {
    local name="$1"
    if _fw_set_exists "$name"; then
        ipset list "$name" 2>/dev/null | sed -n '/^Members:/,$p' | tail -n +2 | grep -c . || true
    else
        echo 0
    fi
}

# ------------------------------------------------------------------ persistence

_fw_backup_once() {
    local target="$1"
    if [ -f "$target" ] && [ ! -f "${target}.logwall-orig" ]; then
        cp -p "$target" "${target}.logwall-orig" 2>/dev/null || true
        echo "[INFO] Preserved original ${target} as ${target}.logwall-orig" >&2
    fi
}

# Names the unit that reloads the saved ruleset at boot, per distro, or nothing
# when this host has no such mechanism installed.
fw_persistence_units() {
    case "${1:-generic}" in
        rhel)   echo "iptables ip6tables ipset" ;;
        debian) echo "netfilter-persistent" ;;
        arch)   echo "iptables ip6tables" ;;
        alpine) echo "iptables ip6tables ipset" ;;
        *)      echo "" ;;
    esac
}

# Package that provides those units, for the message when they are absent.
fw_persistence_package() {
    case "${1:-generic}" in
        rhel)   echo "dnf install -y iptables-services ipset-service" ;;
        debian) echo "apt-get install -y iptables-persistent ipset-persistent" ;;
        arch)   echo "pacman -S --noconfirm iptables-nft" ;;
        alpine) echo "apk add --no-cache iptables-openrc ip6tables ipset-openrc" ;;
        *)      echo "install your distro's iptables persistence package" ;;
    esac
}

# True when at least one restoring unit actually exists on this host.
fw_persistence_available() {
    local os_family="${1:-generic}" unit
    for unit in $(fw_persistence_units "$os_family"); do
        case "${INIT_SYSTEM:-}" in
            systemd)
                systemctl cat "${unit}.service" >/dev/null 2>&1 && return 0
                ;;
            openrc)
                [ -x "/etc/init.d/${unit}" ] && return 0
                ;;
            *)
                command -v "$unit" >/dev/null 2>&1 && return 0
                ;;
        esac
    done
    return 1
}

# Writes the active ruleset to the location the distro restores from at boot.
#   $1 = OS family (rhel|debian|arch|alpine|generic)
#   $2 = active firewall backend (iptables|nftables|firewalld|ufw|csf)
# Writes the raw ruleset to wherever this distro's restore unit reads it from.
# Split out of fw_save_rules so the nftables branch can fall back to it when the
# host turns out not to be nftables-native after all.
_fw_save_os_family() {
    local os_family="${1:-generic}"
    case "$os_family" in
        rhel)
            mkdir -p /etc/sysconfig 2>/dev/null || true
            iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            [ "${HAS_IPV6:-0}" = "1" ] && ip6tables-save > /etc/sysconfig/ip6tables 2>/dev/null || true
            ;;
        debian)
            mkdir -p /etc/iptables 2>/dev/null || true
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            [ "${HAS_IPV6:-0}" = "1" ] && ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
            ;;
        arch)
            mkdir -p /etc/iptables 2>/dev/null || true
            iptables-save > /etc/iptables/iptables.rules 2>/dev/null || true
            [ "${HAS_IPV6:-0}" = "1" ] && ip6tables-save > /etc/iptables/ip6tables.rules 2>/dev/null || true
            ;;
        alpine)
            mkdir -p /etc/iptables 2>/dev/null || true
            iptables-save > /etc/iptables/rules-save 2>/dev/null || true
            [ "${HAS_IPV6:-0}" = "1" ] && ip6tables-save > /etc/iptables/rules6-save 2>/dev/null || true
            ;;
        *)
            echo "[WARN] Unknown OS family '${os_family}' — rules are active but not persisted." >&2
            ;;
    esac
}

fw_save_rules() {
    local os_family="${1:-generic}"
    local backend="${2:-iptables}"

    # firewalld, ufw, and CSF own their own persistence. Dumping a raw ruleset
    # underneath them creates two competing sources of truth at boot time.
    case "$backend" in
        firewalld|ufw|csf)
            echo "[INFO] Backend '${backend}' manages its own persistence — skipping raw rule dump." >&2
            ;;
        nftables)
            # The comment here used to promise that "only a genuinely
            # nftables-native host may own /etc/nftables.conf" while the condition
            # underneath tested nothing but whether the `nft` binary exists — true
            # on practically every modern distro. Overwriting another host's
            # nftables.conf is bad enough; worse is that it fires INSTEAD of the
            # ruleset dump the host actually restores from, so the rules land in a
            # file nothing reads while the real one stays empty.
            #
            # The unit is the only thing that decides. No unit, no ownership: fall
            # through to the OS-family path so persistence goes where the host will
            # actually look for it.
            if command -v nft >/dev/null 2>&1 && svc_is_enabled nftables 2>/dev/null; then
                _fw_backup_once /etc/nftables.conf
                nft list ruleset > /etc/nftables.conf 2>/dev/null || \
                    echo "[WARN] Failed to write /etc/nftables.conf" >&2
            else
                echo "[INFO] nftables.service is not enabled here — persisting through the distro ruleset file instead of /etc/nftables.conf." >&2
                _fw_save_os_family "$os_family"
            fi
            ;;
        *)
            _fw_save_os_family "$os_family"
            ;;
    esac

    # Writing the file is only half of persistence. On a host where the restoring
    # unit was never installed — the default on RHEL 8/9, where firewalld is the
    # supported path and iptables-services is optional — the ruleset is saved into
    # a file nothing ever reads, and every rule silently disappears on reboot.
    case "$backend" in
        firewalld|ufw|csf) ;;
        *)
            if fw_persistence_available "$os_family"; then
                local unit
                for unit in $(fw_persistence_units "$os_family"); do
                    svc_enable "$unit"
                done
            else
                echo "[WARN] Rules saved, but nothing on this host restores them at boot." >&2
                echo "[WARN] After a reboot the firewall would come up empty." >&2
                echo "[WARN] Fix: $(fw_persistence_package "$os_family")" >&2
            fi
            ;;
    esac

    # ipset state lives in its own file, and the path is not a matter of taste —
    # it is whatever this distro's restore hook actually reads.
    #
    # Getting it wrong is worse here than for plain rules. A saved ruleset that
    # nothing restores leaves the host unprotected; a ruleset that IS restored
    # while its sets are missing is worse still, because `-m set --match-set`
    # against a non-existent set makes iptables-restore fail outright — and a
    # failed restore at boot leaves the host with no rules at all.
    if fw_have_ipset && [ "$backend" != "csf" ]; then
        local ipset_target="" ipset_reader=""
        case "$os_family" in
            rhel)
                mkdir -p /etc/sysconfig 2>/dev/null || true
                ipset_target=/etc/sysconfig/ipset
                ipset_reader="ipset.service (package: ipset-service)"
                ;;
            debian)
                # netfilter-persistent's ipset plugin reads /etc/iptables/ipsets.
                # /etc/ipset.d is not a Debian convention: writing there produced a
                # file nothing ever loaded, while rules.v4 kept referencing sets
                # that would not exist at boot.
                mkdir -p /etc/iptables 2>/dev/null || true
                ipset_target=/etc/iptables/ipsets
                ipset_reader="netfilter-persistent (package: ipset-persistent)"
                ;;
            alpine)
                mkdir -p /etc/ipset.d 2>/dev/null || true
                ipset_target=/etc/ipset.d/logwall.conf
                ipset_reader="the ipset init script"
                ;;
            *)
                mkdir -p /etc/ipset.d 2>/dev/null || true
                ipset_target=/etc/ipset.d/logwall.conf
                ipset_reader=""
                ;;
        esac

        ipset save > "$ipset_target" 2>/dev/null || \
            echo "[WARN] Failed to write ipset state to ${ipset_target}" >&2

        # Same rule as for the ruleset: never report something saved without
        # checking that anything reads it.
        if ! fw_ipset_restore_available "$os_family"; then
            echo "[WARN] ipset state saved to ${ipset_target}, but nothing on this host restores it at boot." >&2
            echo "[WARN] The saved rules reference these sets, so at boot iptables-restore would FAIL" >&2
            echo "[WARN] and the host would come up with no firewall rules at all." >&2
            echo "[WARN] Fix: $(fw_ipset_package "$os_family")${ipset_reader:+   # read by ${ipset_reader}}" >&2
        fi
    fi
}

# Whether this host can restore ipset state at boot at all.
fw_ipset_restore_available() {
    case "${1:-generic}" in
        rhel)
            [ -f /usr/lib/systemd/system/ipset.service ] || \
            [ -f /etc/systemd/system/ipset.service ] || \
            [ -f /etc/init.d/ipset ]
            ;;
        debian)
            # The ipset-persistent package drops this plugin into netfilter-persistent.
            [ -f /usr/share/netfilter-persistent/plugins.d/10-ipset ] || \
            [ -f /usr/share/netfilter-persistent/plugins.d/05-ipset ]
            ;;
        alpine)
            [ -f /etc/init.d/ipset ]
            ;;
        *)
            return 1
            ;;
    esac
}

fw_ipset_package() {
    case "${1:-generic}" in
        rhel)   echo "dnf install -y ipset-service" ;;
        debian) echo "apt-get install -y ipset-persistent" ;;
        alpine) echo "apk add ipset-openrc" ;;
        *)      echo "install your distro's ipset persistence package" ;;
    esac
}

# ---------------------------------------------------------------- single IP ops

_fw_valid_ip() {
    # Validation happens in Python for bulk operations; this guards the manual
    # CLI path so an operator typo can never reach the kernel as a raw string.
    python3 - "$1" <<'PYEOF' 2>/dev/null
import ipaddress, sys
try:
    ipaddress.ip_network(sys.argv[1], strict=False)
except ValueError:
    sys.exit(1)
PYEOF
}

fw_block_ip() {
    local ip="$1"
    local reason="${2:-Blocked by logwall}"
    local backend="${3:-iptables}"

    _fw_valid_ip "$ip" || {
        echo "[ERROR] Refusing to block invalid address: ${ip}" >&2
        return 2
    }

    if [ "$backend" = "csf" ] && command -v csf >/dev/null 2>&1; then
        csf -d "$ip" "$reason" >/dev/null 2>&1 || {
            echo "[ERROR] csf -d failed for ${ip}" >&2
            return 1
        }
        return 0
    fi

    fw_have_ipset || return 3

    local target_set="$SET_BLACK4"
    case "$ip" in
        *:*) target_set="$SET_BLACK6" ;;
    esac

    if ! ipset add "$target_set" "$ip" comment "$reason" -exist 2>/dev/null; then
        echo "[ERROR] ipset add failed for ${ip} (set ${target_set} full or missing?)" >&2
        return 1
    fi
    return 0
}

fw_unblock_ip() {
    local ip="$1"
    local backend="${2:-iptables}"

    _fw_valid_ip "$ip" || {
        echo "[ERROR] Refusing to unban invalid address: ${ip}" >&2
        return 2
    }

    if [ "$backend" = "csf" ] && command -v csf >/dev/null 2>&1; then
        csf -dr "$ip" >/dev/null 2>&1 || true
        return 0
    fi

    fw_have_ipset || return 3

    local target_set="$SET_BLACK4"
    case "$ip" in
        *:*) target_set="$SET_BLACK6" ;;
    esac

    ipset del "$target_set" "$ip" 2>/dev/null || true
    return 0
}
