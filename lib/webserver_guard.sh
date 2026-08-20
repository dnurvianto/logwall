#!/usr/bin/env bash
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: lib/webserver_guard.sh
# Purpose: A second, independent enforcement point for the blacklist — this one
#          effective at the webserver layer instead of the kernel.
#
# Why a second enforcement point at all: iptables/ipset can only DROP by the
# packet's real source address. Behind a CDN or reverse proxy, that address is
# always the CDN's edge, never the attacker's — nginx's own realip module
# recovers the real client address for logging and for THIS check, but
# iptables never sees it, because the packet in front of it always came from
# Cloudflare (or whichever proxy). A blacklisted address that only ever
# arrives through a CDN is therefore never actually dropped at the kernel,
# no matter how correct the detection was. Measured on a live host: an address
# blacklisted for PanelBruteForce kept reaching the backend for 5+ hours
# afterward, answered normally, because every one of its packets arrived from
# a Cloudflare edge IP that iptables was never going to match against.
#
# Detection is unchanged — this reads the same blacklist file the kernel side
# already trusts, adding a second door with the same lock, not a new gate with
# new rules.
# Reference: docs/DESIGN.md §8.F (Real IP Behind a CDN / Reverse Proxy)
# ==============================================================================

WG_BLOCKLIST_FILE="${WG_BLOCKLIST_FILE:-/etc/nginx/logwall_blocklist.conf}"
WG_GEO_FILE="${WG_GEO_FILE:-/etc/nginx/conf.d/logwall_geo.conf}"
WG_GENERIC_GUARD="${WG_GENERIC_GUARD:-/etc/nginx/logwall-guard.conf}"
WG_FASTPANEL_INCLUDES_DIR="${WG_FASTPANEL_INCLUDES_DIR:-/etc/nginx/fastpanel2-includes}"
WG_FASTPANEL_GUARD="${WG_FASTPANEL_GUARD:-${WG_FASTPANEL_INCLUDES_DIR}/logwall-guard.conf}"

_wg_have_nginx() {
    command -v nginx >/dev/null 2>&1 && [ -d /etc/nginx ]
}

# Emits one `geo`-compatible line per BLACKLIST entry (IPv4, IPv6, and CIDR —
# unlike nginx's `map`, `geo` understands network ranges natively, which is
# why this uses `geo` and not `map`). Returns 0 when the file changed, 2 when
# it did not, so the caller only reloads nginx when there is something new.
_wg_write_blocklist_file() {
    local file="${BLACKLIST:-/etc/logwall/blacklist_ips.txt}"
    local tmp
    tmp=$(mktemp) || return 1

    if [ -f "$file" ]; then
        local raw ip
        while IFS= read -r raw; do
            ip="${raw%%#*}"
            ip="$(printf '%s' "$ip" | tr -d '[:space:]')"
            [ -n "$ip" ] || continue
            _fw_valid_ip "$ip" 2>/dev/null || continue
            printf '%s 1;\n' "$ip" >> "$tmp"
        done < "$file"
    fi

    if ! cmp -s "$tmp" "$WG_BLOCKLIST_FILE" 2>/dev/null; then
        mv "$tmp" "$WG_BLOCKLIST_FILE" || { rm -f "$tmp"; return 1; }
        return 0
    fi
    rm -f "$tmp"
    return 2
}

_wg_write_geo_file() {
    local tmp
    tmp=$(mktemp) || return 1
    cat > "$tmp" <<EOF
# logwall-managed — regenerated every apply cycle, do not edit by hand.
# Second enforcement point for the blacklist: iptables can only see the CDN
# edge as the packet source, never the real client behind it. This checks
# the address nginx's own realip module already recovered.
geo \$remote_addr \$logwall_blocked {
    default 0;
    include ${WG_BLOCKLIST_FILE};
}
EOF
    if ! cmp -s "$tmp" "$WG_GEO_FILE" 2>/dev/null; then
        mkdir -p "$(dirname "$WG_GEO_FILE")" 2>/dev/null || true
        mv "$tmp" "$WG_GEO_FILE" || { rm -f "$tmp"; return 1; }
        return 0
    fi
    rm -f "$tmp"
    return 2
}

_wg_guard_snippet_content() {
    cat <<'EOF'
# logwall-managed — regenerated every apply cycle, do not edit by hand.
if ($logwall_blocked) { return 403; }
EOF
}

# Writes the snippet an operator's own vhost includes to enforce the block.
# On FastPanel this reaches every vhost with zero manual steps, because
# fastpanel2-includes/*.conf is already included inside every generated
# server block. Anywhere else, the file is still written — ready to include —
# but wiring it into each vhost is left to the operator, because there is no
# safe, generic way to locate (or edit) an arbitrary hand-built vhost file
# without risking exactly the kind of breakage this project refuses to cause.
_wg_write_guard_snippet() {
    local target changed=2

    if [ "${PANEL_TYPE:-none}" = "fastpanel" ] && [ -d "$WG_FASTPANEL_INCLUDES_DIR" ]; then
        target="$WG_FASTPANEL_GUARD"
    else
        target="$WG_GENERIC_GUARD"
    fi

    local tmp
    tmp=$(mktemp) || return 1
    _wg_guard_snippet_content > "$tmp"

    if ! cmp -s "$tmp" "$target" 2>/dev/null; then
        mv "$tmp" "$target" || { rm -f "$tmp"; return 1; }
        changed=0
    else
        rm -f "$tmp"
    fi

    if [ "$target" = "$WG_GENERIC_GUARD" ]; then
        echo "[INFO] Webserver-layer enforcement is ready at ${WG_GENERIC_GUARD}, but needs one line" >&2
        echo "[INFO] added manually inside each nginx server block: include ${WG_GENERIC_GUARD};" >&2
        echo "[INFO] (auto-wired with zero manual steps only on FastPanel today, where a shared" >&2
        echo "[INFO] includes directory already reaches every vhost.)" >&2
    fi

    return "$changed"
}

_wg_remove_guard_snippet() {
    local removed=2
    for f in "$WG_FASTPANEL_GUARD" "$WG_GENERIC_GUARD"; do
        if [ -f "$f" ]; then
            rm -f "$f" 2>/dev/null && removed=0
        fi
    done
    return "$removed"
}

# Validates before touching the running config, and never reloads on a
# failing test — the same fail-safe logwall already applies on the kernel
# side: stay on the last-known-good config rather than risk breaking nginx
# outright for every site on the host over one bad line.
_wg_reload_nginx() {
    if ! nginx -t >/dev/null 2>&1; then
        echo "[ERROR] nginx -t failed after writing logwall's webserver guard — leaving the running config untouched." >&2
        nginx -t 2>&1 | sed 's/^/[ERROR]   /' >&2
        return 1
    fi
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet nginx 2>/dev/null; then
        systemctl reload nginx 2>/dev/null && return 0
    fi
    nginx -s reload 2>/dev/null
}

# Public entry point. $1 = 1 to enforce, 0 for observe-only. Mirrors
# setup_iptables_chains(): the blocklist and geo files are always kept
# current (harmless, useful for review), but the rule that actually returns
# 403 is only installed when ENFORCE=1, and removed the moment it is not.
webserver_guard_apply() {
    local enforce="${1:-0}"

    [ "${WEBSERVER_ENFORCE:-1}" = "1" ] || return 0
    _wg_have_nginx || return 0

    local changed=1
    _wg_write_blocklist_file; [ "$?" -eq 0 ] && changed=0
    _wg_write_geo_file;       [ "$?" -eq 0 ] && changed=0

    if [ "$enforce" = "1" ]; then
        _wg_write_guard_snippet; [ "$?" -eq 0 ] && changed=0
    else
        _wg_remove_guard_snippet; [ "$?" -eq 0 ] && changed=0
    fi

    [ "$changed" -eq 0 ] && _wg_reload_nginx
    return 0
}

# Removes every file this module writes and reloads nginx clean. Called from
# `logwall firewall panic`, alongside panic_remove_chains.
webserver_guard_panic() {
    _wg_have_nginx || return 0
    rm -f "$WG_BLOCKLIST_FILE" "$WG_GEO_FILE" "$WG_FASTPANEL_GUARD" "$WG_GENERIC_GUARD" 2>/dev/null || true
    _wg_reload_nginx
}

# Reports guard health for `logwall selftest`. Prints one line per check and
# returns non-zero when the enforcement snippet is missing while ENFORCE=1.
webserver_guard_selftest() {
    local enforce="${1:-0}"
    local failures=0

    [ "${WEBSERVER_ENFORCE:-1}" = "1" ] || return 0
    _wg_have_nginx || return 0

    if [ -f "$WG_GEO_FILE" ]; then
        echo "[ OK ] nginx: logwall geo block file present"
    else
        echo "[FAIL] nginx: logwall geo block file missing (${WG_GEO_FILE})"
        failures=$((failures + 1))
    fi

    if [ "$enforce" = "1" ]; then
        if [ -f "$WG_FASTPANEL_GUARD" ] || [ -f "$WG_GENERIC_GUARD" ]; then
            echo "[ OK ] nginx: webserver-layer enforcement snippet present"
        else
            echo "[FAIL] nginx: ENFORCE=1 but the webserver-layer guard snippet is missing"
            failures=$((failures + 1))
        fi
    fi

    if ! nginx -t >/dev/null 2>&1; then
        echo "[FAIL] nginx: config test fails (nginx -t) — logwall's guard files may be untested"
        failures=$((failures + 1))
    fi

    return "$failures"
}
