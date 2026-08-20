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

    if [ "${WEBSERVER_ENFORCE:-1}" = "1" ] && _wg_have_nginx; then
        local changed=1
        _wg_write_blocklist_file; [ "$?" -eq 0 ] && changed=0
        _wg_write_geo_file;       [ "$?" -eq 0 ] && changed=0

        if [ "$enforce" = "1" ]; then
            _wg_write_guard_snippet; [ "$?" -eq 0 ] && changed=0
        else
            _wg_remove_guard_snippet; [ "$?" -eq 0 ] && changed=0
        fi

        [ "$changed" -eq 0 ] && _wg_reload_nginx
    fi

    webserver_guard_apply_litespeed "$enforce"
    return 0
}

# Removes every file this module writes and reloads clean. Called from
# `logwall firewall panic`, alongside panic_remove_chains.
webserver_guard_panic() {
    if _wg_have_nginx; then
        rm -f "$WG_BLOCKLIST_FILE" "$WG_GEO_FILE" "$WG_FASTPANEL_GUARD" "$WG_GENERIC_GUARD" 2>/dev/null || true
        _wg_reload_nginx
    fi
    webserver_guard_panic_litespeed
}

# Reports guard health for `logwall selftest`. Prints one line per check and
# returns non-zero when the enforcement snippet is missing while ENFORCE=1.
webserver_guard_selftest() {
    local enforce="${1:-0}"
    local failures=0

    if [ "${WEBSERVER_ENFORCE:-1}" = "1" ] && _wg_have_nginx; then
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
    fi

    webserver_guard_selftest_litespeed "$enforce"
    failures=$((failures + $?))

    return "$failures"
}

# ==============================================================================
# LiteSpeed / OpenLiteSpeed
#
# No `geo`/`map` equivalent, and `RewriteMap` (the closest analogue — a file
# lookup) is rejected outright by this engine: verified live, `[ERROR] rewrite:
# invalid rewrite condition while parsing`. `RewriteCond`/`RewriteRule` with a
# literal regex alternation is what actually works — verified live the same
# way, `403` on a blocked address, `200` once removed. That is the only
# confirmed mechanism, so it is the only one this module uses.
#
# There is also no FastPanel-style shared includes directory reaching every
# vhost automatically, so each vhost.conf is edited directly — but only ones
# that already have an active `rewrite { enable 1 ... }` block. A vhost
# without one is left untouched and reported, the same choice made for a
# hand-built nginx vhost: there is no safe, generic way to turn rewriting on
# for a site that does not already have it on, without risking a behaviour
# change the operator never asked for.
# ==============================================================================

LS_LSWSCTRL="${LS_LSWSCTRL:-/usr/local/lsws/bin/lswsctrl}"
LS_CONF_DIR="${LS_CONF_DIR:-/usr/local/lsws/conf}"
LS_VHOSTS_GLOB="${LS_VHOSTS_GLOB:-${LS_CONF_DIR}/vhosts/*/vhost.conf}"
LS_MARK_BEGIN="# logwall-managed-guard-begin"
LS_MARK_END="# logwall-managed-guard-end"

_ls_have_litespeed() {
    [ -x "$LS_LSWSCTRL" ] && [ -d "$LS_CONF_DIR" ]
}

# Builds one regex alternation covering every IPv4 BLACKLIST entry — bare
# addresses, and CIDR blocks on a byte boundary (/8, /16, /24, /32), which is
# every CIDR width logwall's own subnet rollup ever produces. IPv6 and any
# non-byte-aligned CIDR are skipped: there is no live-verified way to express
# either in this engine's regex dialect yet, and a wrong pattern here fails
# open (the request stays unmatched) rather than blocking too much — the
# skip count is reported so the gap is visible, not silent.
#
# Echoes two lines: the pattern (possibly empty), then the skipped count.
# Callers invoke this through command substitution, which runs in a subshell —
# a global for the skip count would never make it back out, so both values
# travel out through stdout instead.
_ls_build_pattern() {
    local file="${BLACKLIST:-/etc/logwall/blacklist_ips.txt}"
    local skipped=0
    if [ ! -f "$file" ]; then
        printf '\n%d\n' "$skipped"
        return 0
    fi

    local raw entry a b c d prefix
    local -a alts=()
    while IFS= read -r raw; do
        entry="${raw%%#*}"
        entry="$(printf '%s' "$entry" | tr -d '[:space:]')"
        [ -n "$entry" ] || continue

        case "$entry" in
            *:*) skipped=$((skipped + 1)); continue ;;   # IPv6 — not yet supported here
        esac

        _fw_valid_ip "$entry" 2>/dev/null || continue

        if [ "${entry#*/}" != "$entry" ]; then
            prefix="${entry#*/}"
            IFS='.' read -r a b c d <<< "${entry%/*}"
            case "$prefix" in
                8)  alts+=("${a}\\.") ;;
                16) alts+=("${a}\\.${b}\\.") ;;
                24) alts+=("${a}\\.${b}\\.${c}\\.") ;;
                32) alts+=("${a}\\.${b}\\.${c}\\.${d}\$") ;;
                *)  skipped=$((skipped + 1)) ;;
            esac
        else
            IFS='.' read -r a b c d <<< "$entry"
            [ -n "$d" ] && alts+=("${a}\\.${b}\\.${c}\\.${d}\$")
        fi
    done < "$file"

    local joined=""
    if [ "${#alts[@]}" -gt 0 ]; then
        joined=$(IFS='|'; echo "${alts[*]}")
        joined="^(${joined})"
    fi
    printf '%s\n%d\n' "$joined" "$skipped"
}

# Idempotently rewrites the marked section inside one vhost.conf's rewrite
# block. $1 = file, $2 = regex pattern ("" removes the block). Echoes nothing;
# returns 0 when the file changed, 2 when it did not, 3 when this vhost has no
# active rewrite block to hook into (not a failure — just not eligible).
#
# Eligibility is checked as its own small, separate awk pass rather than
# folded into the rewrite below: mixing a control-flow signal into the same
# stream awk uses for its own diagnostics is exactly what broke this once —
# a plain `-v pat=...` warning about an unrecognized backslash escape landed
# in the same capture as the eligibility marker and made every vhost read as
# ineligible, verified locally against a fixture with `enable 1` on it.
_ls_vhost_eligible() {
    awk '
        /^rewrite[ \t]*\{/ { in_rw = 1 }
        in_rw && /^[ \t]*enable[ \t]+1[ \t]*$/ { print "yes"; exit }
        in_rw && /^\}/ { in_rw = 0 }
    ' "$1" | grep -q yes
}

_ls_update_vhost() {
    local file="$1" pattern="$2"

    _ls_vhost_eligible "$file" || return 3

    # awk's `-v` assignment processes backslash escapes in the value itself —
    # verified locally: `-v pat='a\.b'` silently becomes the string `a.b`,
    # turning an escaped literal dot into "match any character". Doubling
    # every backslash here is what survives that pass intact.
    local pattern_escaped="${pattern//\\/\\\\}"

    local tmp
    tmp=$(mktemp) || return 1

    awk -v mb="$LS_MARK_BEGIN" -v me="$LS_MARK_END" -v pat="$pattern_escaped" '
        BEGIN { in_rw=0; in_mk=0; inserted=0 }
        !in_rw && $0 ~ /^rewrite[ \t]*\{/ { in_rw=1; print; next }
        in_rw && $0 == mb { in_mk=1; next }
        in_rw && $0 == me { in_mk=0; next }
        in_rw && in_mk { next }
        in_rw && $0 ~ /^\}/ {
            if (pat != "" && !inserted) {
                print mb
                print "  RewriteCond             %{REMOTE_ADDR} " pat
                print "  RewriteRule             .* - [F,L]"
                print me
                inserted = 1
            }
            in_rw = 0
            print
            next
        }
        { print }
    ' "$file" > "$tmp" 2>/dev/null

    if ! cmp -s "$tmp" "$file" 2>/dev/null; then
        cp -p "$file" "${file}.logwall-orig" 2>/dev/null || true
        mv "$tmp" "$file" || { rm -f "$tmp"; return 1; }
        return 0
    fi
    rm -f "$tmp"
    return 2
}

_ls_reload() {
    "$LS_LSWSCTRL" reload >/dev/null 2>&1
}

# Public entry point. $1 = 1 to enforce, 0 for observe-only.
webserver_guard_apply_litespeed() {
    local enforce="${1:-0}"

    [ "${WEBSERVER_ENFORCE:-1}" = "1" ] || return 0
    _ls_have_litespeed || return 0

    local pattern="" ls_skipped=0
    if [ "$enforce" = "1" ]; then
        local ls_out
        ls_out="$(_ls_build_pattern)"
        pattern="${ls_out%$'\n'*}"
        ls_skipped="${ls_out##*$'\n'}"
    fi

    local vf changed=1 skipped_vhosts=0 rc
    for vf in $LS_VHOSTS_GLOB; do
        [ -f "$vf" ] || continue
        _ls_update_vhost "$vf" "$pattern"
        rc=$?
        case "$rc" in
            0) changed=0 ;;
            3) skipped_vhosts=$((skipped_vhosts + 1)) ;;
        esac
    done

    if [ "$skipped_vhosts" -gt 0 ]; then
        echo "[INFO] ${skipped_vhosts} LiteSpeed vhost(s) have no active 'rewrite { enable 1 }' block —" >&2
        echo "[INFO] webserver-layer enforcement not wired there. Enable rewrite for that vhost to cover it." >&2
    fi
    if [ "${ls_skipped:-0}" -gt 0 ] 2>/dev/null && [ "$enforce" = "1" ]; then
        echo "[INFO] ${ls_skipped} blacklist entr(y/ies) are IPv6 or non-byte-aligned CIDR — not yet" >&2
        echo "[INFO] expressible in LiteSpeed's rewrite regex, so skipped at this layer only." >&2
    fi

    [ "$changed" -eq 0 ] && _ls_reload
    return 0
}

# Strips every marked block this module ever wrote, across all vhosts.
webserver_guard_panic_litespeed() {
    _ls_have_litespeed || return 0
    local vf
    for vf in $LS_VHOSTS_GLOB; do
        [ -f "$vf" ] || continue
        _ls_update_vhost "$vf" ""
    done
    _ls_reload
}

# Reports guard health for `logwall selftest`.
webserver_guard_selftest_litespeed() {
    local enforce="${1:-0}"
    local failures=0

    [ "${WEBSERVER_ENFORCE:-1}" = "1" ] || return 0
    _ls_have_litespeed || return 0

    [ "$enforce" = "1" ] || { echo "[INFO] LiteSpeed: ENFORCE=0 — webserver-layer guard not installed by design"; return 0; }

    local vf covered=0 total=0
    for vf in $LS_VHOSTS_GLOB; do
        [ -f "$vf" ] || continue
        total=$((total + 1))
        grep -qF "$LS_MARK_BEGIN" "$vf" 2>/dev/null && covered=$((covered + 1))
    done

    if [ "$total" -eq 0 ]; then
        return 0
    elif [ "$covered" -eq 0 ]; then
        echo "[FAIL] LiteSpeed: ENFORCE=1 but no vhost carries the webserver-layer guard"
        failures=$((failures + 1))
    else
        echo "[ OK ] LiteSpeed: webserver-layer guard present in ${covered}/${total} vhost(s)"
    fi

    return "$failures"
}
