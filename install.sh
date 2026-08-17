#!/usr/bin/env bash
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: install.sh
# Purpose: Gated, transactional installer.
#
#   1. GATE        preflight.sh must return READY. A single BLOCKER aborts the
#                  installation before a single file is written.
#   2. TRANSACTION every action is journalled. Any failure at any point rolls
#                  the host back to its exact pre-installation state.
#   3. VERIFY      the installed copy is re-checked in place; if it cannot run,
#                  the installation is undone rather than left half-finished.
#
# Nothing here needs a human to interpret it: every refusal states the reason
# and the command that resolves it.
# Reference: docs/DESIGN.md §5, §15.1, §17
# ==============================================================================

set -Eeuo pipefail

INSTALL_DIR="/opt/logwall"
CONF_DIR="/etc/logwall"
# Same override the CLI and preflight honour, so all three halves can be pointed
# at one alternative file when testing on a host that already has logwall.
CONF_FILE="${LOGWALL_CONF:-/etc/logwall.conf}"
LOG_DIR="/var/log/logwall"

ACCEPT_WARNINGS=0
INSTALL_DEPS=0
SKIP_CRON=0
ALLOW_EMPTY_WHITELIST=0
CHOSEN_BACKEND=""

while [ $# -gt 0 ]; do
    case "$1" in
        --accept-warnings)       ACCEPT_WARNINGS=1 ;;
        --install-deps)          INSTALL_DEPS=1 ;;
        --no-cron)               SKIP_CRON=1 ;;
        --allow-empty-whitelist) ALLOW_EMPTY_WHITELIST=1 ;;
        --backend)               CHOSEN_BACKEND="${2:-}"; shift ;;
        --backend=*)             CHOSEN_BACKEND="${1#*=}" ;;
        --help|-h)
            cat <<'EOF'
Usage: ./install.sh [options]

  --accept-warnings        proceed when preflight reports warnings (never blockers)
  --install-deps           install missing iptables/ipset first, after showing what and asking
  --no-cron                install without registering cron entries
  --allow-empty-whitelist  proceed without a detected admin IP (lockout risk)
  --backend <name>         auto | iptables | nftables | firewalld | ufw | csf

On a host running CSF, `--backend csf` is the supported way in: logwall then
installs no chains and no sets of its own, and routes every block through
`csf -d`. Without it an active CSF is a blocker — two agents writing the same
ruleset is not a state to enter by accident.

Blockers can never be bypassed. Fix them and run ./preflight.sh again.
EOF
            exit 0
            ;;
    esac
    shift
done

case "$CHOSEN_BACKEND" in
    ""|auto|iptables|nftables|firewalld|ufw|csf) ;;
    *)
        echo "[ERROR] Unknown backend '${CHOSEN_BACKEND}'." >&2
        echo "        Valid: auto | iptables | nftables | firewalld | ufw | csf" >&2
        exit 2
        ;;
esac

# Exported so the gate below judges this host against the backend we are actually
# going to install with, rather than against the default.
if [ -n "$CHOSEN_BACKEND" ]; then
    export BACKEND="$CHOSEN_BACKEND"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ==============================================================================
# Installation transcript
#
# Buffered to a temporary file first. It is only moved into /var/log/logwall once
# that directory exists, so a refused installation still leaves no artefact
# behind — while the operator always gets told where to read the transcript.
# ==============================================================================
LOG_TMP="$(mktemp)"
LOG_FILE="${LOG_DIR}/install.log"
LOG_FINAL_PATH="$LOG_TMP"

exec 3>&1 4>&2
exec > >(tee -a "$LOG_TMP") 2>&1
TEE_PID=$!

finalize_log() {
    # Close the tee pipe before reading the file, otherwise the last lines may
    # still be buffered when we copy it.
    exec 1>&3 2>&4
    [ -n "${TEE_PID:-}" ] && wait "$TEE_PID" 2>/dev/null || true

    if [ -d "$LOG_DIR" ]; then
        {
            echo "=============================================================================="
            echo "logwall installation transcript — $(date '+%Y-%m-%d %H:%M:%S %Z')"
            echo "=============================================================================="
        } >> "$LOG_FILE" 2>/dev/null || true
        if cat "$LOG_TMP" >> "$LOG_FILE" 2>/dev/null; then
            chmod 0640 "$LOG_FILE" 2>/dev/null || true
            LOG_FINAL_PATH="$LOG_FILE"
            rm -f "$LOG_TMP"
        fi
    fi
}

echo "logwall install started $(date '+%Y-%m-%d %H:%M:%S') — argv: ${*:-<none>}"

# ==============================================================================
# Transaction journal
#
# Every mutating action appends one entry. On any failure the journal is replayed
# backwards, so a half-installed state can never survive.
# ==============================================================================
JOURNAL=()
INSTALL_COMPLETE=0

record() { JOURNAL+=("$1"); }

rollback_install() {
    local i entry kind target

    [ "${#JOURNAL[@]}" -eq 0 ] && return 0

    echo
    echo "[ROLLBACK] Undoing ${#JOURNAL[@]} installation step(s)..." >&2

    for (( i=${#JOURNAL[@]}-1; i>=0; i-- )); do
        entry="${JOURNAL[$i]}"
        kind="${entry%%:*}"
        target="${entry#*:}"

        case "$kind" in
            cron)
                if [ -f "${SCRIPT_DIR}/lib/cron_manager.sh" ]; then
                    . "${SCRIPT_DIR}/lib/cron_manager.sh"
                    remove_crons >/dev/null 2>&1 || true
                    echo "[ROLLBACK]   removed cron entries" >&2
                fi
                ;;
            symlink)
                rm -f "$target" 2>/dev/null || true
                echo "[ROLLBACK]   removed symlink ${target}" >&2
                ;;
            newfile)
                rm -f "$target" 2>/dev/null || true
                echo "[ROLLBACK]   removed ${target}" >&2
                ;;
            newdir)
                rmdir "$target" 2>/dev/null || true
                ;;
            newtree)
                rm -rf "${target:?}" 2>/dev/null || true
                echo "[ROLLBACK]   removed ${target}" >&2
                ;;
            restoreconf)
                # target is "backup_path>live_path"
                local backup="${target%%>*}" live="${target##*>}"
                if [ -f "$backup" ]; then
                    mv -f "$backup" "$live"
                    echo "[ROLLBACK]   restored ${live}" >&2
                fi
                ;;
        esac
    done

    echo "[ROLLBACK] Host returned to its pre-installation state." >&2
}

abort_install() {
    local reason="$1"
    local recommendation="${2:-}"

    echo >&2
    echo "==============================================================================" >&2
    echo " INSTALLATION ABORTED" >&2
    echo "==============================================================================" >&2
    echo " Reason: ${reason}" >&2
    [ -n "$recommendation" ] && { echo >&2; echo " What to do:" >&2; echo "   ${recommendation}" >&2; }
    echo >&2

    rollback_install
    finalize_log
    echo " Transcript: ${LOG_FINAL_PATH}" >&2
    exit 2
}

on_error() {
    local line="$1"
    echo >&2
    echo "[ERROR] Unexpected failure at install.sh line ${line}." >&2
    abort_install "An installation step failed unexpectedly (line ${line})." \
        "Re-run ./preflight.sh, resolve any finding, then retry ./install.sh"
}

trap 'on_error $LINENO' ERR
trap '[ "$INSTALL_COMPLETE" -eq 1 ] || rollback_install' EXIT

echo "=============================================================================="
echo " logwall — Installer"
echo "=============================================================================="

# ==============================================================================
# STAGE 1 — GATE: preflight must pass before anything is written
# ==============================================================================
if [ ! -x "${SCRIPT_DIR}/preflight.sh" ] && [ ! -f "${SCRIPT_DIR}/preflight.sh" ]; then
    abort_install "preflight.sh is missing from ${SCRIPT_DIR}." \
        "Restore the complete project directory and retry."
fi

# Installing packages is deliberately opt-in. The rollback journal below records
# directories, files, symlinks and cron entries — it does NOT record package
# state, so a half-finished package transaction is the one thing this installer
# cannot undo for you. A flag keeps that visible instead of surprising.
install_missing_deps() {
    local missing=""
    command -v iptables >/dev/null 2>&1 || missing="${missing} iptables"
    command -v ipset    >/dev/null 2>&1 || missing="${missing} ipset"
    [ -n "$(echo "$missing" | tr -d ' ')" ] || { echo "[DEPS] iptables and ipset are already present."; return 0; }

    local cmd
    case "$OS_FAMILY" in
        rhel)   cmd="dnf install -y${missing}" ;;
        debian) cmd="apt-get update && apt-get install -y${missing}" ;;
        arch)   cmd="pacman -S --noconfirm${missing}" ;;
        alpine) cmd="apk add --no-cache${missing}" ;;
        *)      echo "[DEPS] Unknown OS family '${OS_FAMILY}'; install${missing} yourself." >&2; return 1 ;;
    esac

    echo "[DEPS] Missing:${missing}"
    echo "[DEPS] Will run: ${cmd}"
    echo "[DEPS] Note: package state is NOT covered by this installer's rollback."
    if [ -t 0 ]; then
        printf "[DEPS] Proceed? [y/N] "
        read -r reply
        case "$reply" in [yY]*) ;; *) echo "[DEPS] Declined; nothing installed."; return 1 ;; esac
    else
        echo "[DEPS] No terminal to confirm on; --install-deps needs an interactive session." >&2
        return 1
    fi

    if eval "$cmd"; then
        echo "[DEPS] Done."
        return 0
    fi
    echo "[DEPS] Package installation failed; the host is unchanged by logwall." >&2
    return 1
}

if [ "$INSTALL_DEPS" -eq 1 ]; then
    echo "[STAGE 1/5] --install-deps: checking prerequisites first..."
    install_missing_deps || true
    echo
fi

echo "[STAGE 1/5] Running preflight checks..."
echo

# `set +e` does NOT suppress an ERR trap — only the `|| assignment` form is
# exempt from it. A non-zero preflight verdict is an expected outcome here, not
# an unexpected failure.
PREFLIGHT_RC=0
bash "${SCRIPT_DIR}/preflight.sh" || PREFLIGHT_RC=$?

case "$PREFLIGHT_RC" in
    0)
        echo
        echo "[STAGE 1/5] Preflight verdict: READY."
        ;;
    1)
        if [ "$ACCEPT_WARNINGS" -eq 1 ]; then
            echo
            echo "[STAGE 1/5] Preflight reported warnings; continuing (--accept-warnings)."
        elif [ -t 0 ]; then
            # Interactive operator: ask, and default to NO. The prompt lives here
            # and never in preflight.sh — preflight is also called from cron
            # (--runtime) and from `logwall doctor --json`, where a prompt would
            # hang the cycle forever.
            echo
            echo "------------------------------------------------------------------------------"
            echo " Preflight reported ${PREFLIGHT_WARN_LABEL:-warnings} that are not resolved."
            echo " Review the WARNING list above before answering."
            echo "------------------------------------------------------------------------------"
            printf ' Proceed with the installation anyway? [y/N]: '
            REPLY_RAW=""
            read -r REPLY_RAW || REPLY_RAW=""
            case "$REPLY_RAW" in
                y|Y|yes|YES|Yes)
                    echo "[STAGE 1/5] Warnings acknowledged interactively; continuing."
                    ;;
                *)
                    echo
                    echo " Installation cancelled. Nothing was changed on this host."
                    echo " Fix the warnings, then run ./preflight.sh again."
                    INSTALL_COMPLETE=1   # nothing to roll back
                    finalize_log
                    echo " Transcript: ${LOG_FINAL_PATH}"
                    exit 1
                    ;;
            esac
        else
            # No terminal: a prompt would read EOF and silently "answer" for the
            # operator, or swallow stdin meant for another process. Refuse instead.
            echo >&2
            echo "==============================================================================" >&2
            echo " INSTALLATION NOT STARTED" >&2
            echo "==============================================================================" >&2
            echo " Preflight reported warnings, none were acknowledged, and there is no" >&2
            echo " terminal to ask on (piped, CI, or non-interactive shell)." >&2
            echo >&2
            echo " Resolve the WARNING items above, then re-run:" >&2
            echo "     ./install.sh" >&2
            echo >&2
            echo " Or accept them deliberately:" >&2
            echo "     ./install.sh --accept-warnings" >&2
            echo "==============================================================================" >&2
            INSTALL_COMPLETE=1   # nothing to roll back
            finalize_log
            echo " Transcript: ${LOG_FINAL_PATH}" >&2
            exit 1
        fi
        ;;
    2)
        echo >&2
        echo "==============================================================================" >&2
        echo " INSTALLATION REFUSED" >&2
        echo "==============================================================================" >&2
        echo " Preflight found BLOCKER-level problems. These cannot be bypassed." >&2
        echo >&2
        echo " Apply the FIX shown for each blocker above, then verify:" >&2
        echo "     ./preflight.sh" >&2
        echo >&2
        echo " install.sh will refuse to run until preflight passes." >&2
        echo "==============================================================================" >&2
        INSTALL_COMPLETE=1   # nothing was written
        finalize_log
        echo " Transcript: ${LOG_FINAL_PATH}" >&2
        exit 2
        ;;
    *)
        INSTALL_COMPLETE=1
        abort_install "preflight.sh could not run (exit ${PREFLIGHT_RC})." \
            "Run it directly to see the error: bash ./preflight.sh"
        ;;
esac

# ==============================================================================
# STAGE 2 — Environment
# ==============================================================================
# shellcheck source=lib/naming.sh
. "${SCRIPT_DIR}/lib/naming.sh"
# shellcheck source=lib/system_discovery.sh
. "${SCRIPT_DIR}/lib/system_discovery.sh"
run_system_discovery

echo
echo "[STAGE 2/5] Target: ${OS_DISTRO} (${OS_FAMILY}) · init=${INIT_SYSTEM} · backend=${FIREWALL_BACKEND} · panel=${PANEL_TYPE}"

if [ "$OS_FAMILY" = "alpine" ] && ! command -v bash >/dev/null 2>&1; then
    abort_install "bash is required on Alpine but is not installed." "apk add bash"
fi

# ==============================================================================
# STAGE 3 — Install (journalled)
# ==============================================================================
echo "[STAGE 3/5] Installing..."

for d in "$INSTALL_DIR" "$CONF_DIR" "$LOG_DIR" \
         "${INSTALL_DIR}/data/state" "${INSTALL_DIR}/data/snapshot" "${INSTALL_DIR}/logs"; do
    if [ ! -d "$d" ]; then
        mkdir -p "$d"
        record "newdir:${d}"
    fi
done

if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
    HAD_INSTALL_DIR=0
    [ -f "${INSTALL_DIR}/VERSION" ] && HAD_INSTALL_DIR=1

    if ! cp -r "${SCRIPT_DIR}/." "${INSTALL_DIR}/"; then
        abort_install "Failed to copy project files to ${INSTALL_DIR}." \
            "Check disk space and permissions on /opt, then retry."
    fi
    [ "$HAD_INSTALL_DIR" -eq 0 ] && record "newtree:${INSTALL_DIR}"

    # `cp -r` adds and overwrites; it never removes. A module deleted upstream
    # therefore survives every future upgrade, and stale code in lib/py is code that
    # can still be imported by something written later. Found on a real upgrade:
    # fcrdns.py, removed from the release, still sitting in /opt/logwall after it.
    #
    # Scoped deliberately narrow — only *.py directly under lib/py, only files the
    # source no longer has. An installer that deletes by pattern is one typo away
    # from being the incident.
    if [ -d "${SCRIPT_DIR}/lib/py" ] && [ -d "${INSTALL_DIR}/lib/py" ]; then
        for installed in "${INSTALL_DIR}"/lib/py/*.py; do
            [ -e "$installed" ] || continue
            if [ ! -f "${SCRIPT_DIR}/lib/py/$(basename "$installed")" ]; then
                rm -f "$installed"
                echo "[INFO]   removed stale module $(basename "$installed")"
            fi
        done
        rm -rf "${INSTALL_DIR}/lib/py/__pycache__" 2>/dev/null || true
    fi
fi

chmod 0750 "${INSTALL_DIR}/logwall" "${INSTALL_DIR}/install.sh" \
           "${INSTALL_DIR}/uninstall.sh" "${INSTALL_DIR}/preflight.sh"

if [ ! -f "$CONF_FILE" ]; then
    cp "${SCRIPT_DIR}/conf/logwall.conf" "$CONF_FILE"
    record "newfile:${CONF_FILE}"
    echo "[INFO]   wrote ${CONF_FILE}"
else
    cp -p "$CONF_FILE" "${CONF_FILE}.preinstall"
    record "restoreconf:${CONF_FILE}.preinstall>${CONF_FILE}"

    ADDED=0
    while IFS= read -r line; do
        case "$line" in
            [A-Z]*=*)
                key="${line%%=*}"
                grep -q "^[[:space:]]*${key}=" "$CONF_FILE" || {
                    printf '%s\n' "$line" >> "$CONF_FILE"
                    ADDED=$((ADDED + 1))
                }
                ;;
        esac
    done < "${SCRIPT_DIR}/conf/logwall.conf"
    echo "[INFO]   merged ${ADDED} new config key(s); existing values untouched"
fi

# Persist the choice. Without this the very next cron cycle reads BACKEND=auto,
# the runtime gate sees an unexplained CSF, and every cycle refuses to run.
if [ -n "$CHOSEN_BACKEND" ]; then
    if grep -qE '^[[:space:]]*BACKEND=' "$CONF_FILE"; then
        sed -i "s|^[[:space:]]*BACKEND=.*|BACKEND=${CHOSEN_BACKEND}   # set by install.sh --backend|" "$CONF_FILE"
    else
        printf 'BACKEND=%s   # set by install.sh --backend
' "$CHOSEN_BACKEND" >> "$CONF_FILE"
    fi
    echo "[INFO]   backend pinned to '${CHOSEN_BACKEND}' in ${CONF_FILE}"
fi

for datafile in whitelist_ips.txt blacklist_ips.txt bypass_rules.txt cdn_networks.txt whitelist_hosts.txt; do
    if [ ! -f "${CONF_DIR}/${datafile}" ]; then
        cp "${SCRIPT_DIR}/data/${datafile}" "${CONF_DIR}/${datafile}"
        record "newfile:${CONF_DIR}/${datafile}"
    fi
done

# The search engine range list is REPLACED on every install, unlike the files above.
# Those hold operator decisions and must survive an upgrade; this one holds a copy of
# what Google, Microsoft and Apple publish, and a copy that never refreshes is the
# one failure mode a static list has. An operator's own exceptions belong in
# bypass_rules.txt, which is why the two are separate files.
if [ -f "${SCRIPT_DIR}/data/crawler_ranges.txt" ]; then
    cp "${SCRIPT_DIR}/data/crawler_ranges.txt" "${CONF_DIR}/crawler_ranges.txt"
    echo "[INFO]   search engine ranges refreshed ($(grep -cE '^[0-9a-fA-F]' "${CONF_DIR}/crawler_ranges.txt") prefixes)"
fi

# --- admin whitelist bootstrap -------------------------------------------------
echo "[INFO]   bootstrapping admin whitelist..."
ADMIN_IPS=""

valid_admin_ip() {
    python3 - "$1" <<'PYEOF' >/dev/null 2>&1
import ipaddress, sys
addr = ipaddress.ip_address(sys.argv[1])
if addr.is_loopback or addr.is_unspecified:
    raise SystemExit(1)
PYEOF
}

add_admin_ip() {
    local candidate="${1:-}"
    [ -n "$candidate" ] || return 0
    valid_admin_ip "$candidate" || return 0
    case " ${ADMIN_IPS} " in *" ${candidate} "*) return 0 ;; esac
    ADMIN_IPS="${ADMIN_IPS} ${candidate}"
}

[ -n "${SSH_CLIENT:-}" ]     && add_admin_ip "$(echo "$SSH_CLIENT" | awk '{print $1}')"
[ -n "${SSH_CONNECTION:-}" ] && add_admin_ip "$(echo "$SSH_CONNECTION" | awk '{print $1}')"

if command -v who >/dev/null 2>&1; then
    while IFS= read -r host; do add_admin_ip "$host"; done \
        < <(who 2>/dev/null | sed -n 's/.*(\([0-9a-fA-F.:]*\)).*/\1/p')
fi

SSH_PORT_DETECTED=$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/ {print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || true)
SSH_PORT_DETECTED="${SSH_PORT_DETECTED:-22}"

if command -v ss >/dev/null 2>&1; then
    while IFS= read -r peer; do add_admin_ip "$peer"; done \
        < <(ss -tn state established "( sport = :${SSH_PORT_DETECTED} )" 2>/dev/null \
            | tail -n +2 | awk '{print $4}' | sed 's/:[0-9]*$//; s/^\[//; s/\]$//')
fi

for ip in $ADMIN_IPS; do
    if ! grep -qE "^[[:space:]]*${ip}([[:space:]]|/|$)" "${CONF_DIR}/whitelist_ips.txt" 2>/dev/null; then
        echo "${ip}    # admin bootstrap $(date '+%Y-%m-%d %H:%M')" >> "${CONF_DIR}/whitelist_ips.txt"
        echo "[INFO]     whitelisted ${ip}"
    fi
done

if [ -z "$(echo "$ADMIN_IPS" | tr -d ' ')" ] && [ "$ALLOW_EMPTY_WHITELIST" -eq 0 ]; then
    abort_install "No administrative IP could be detected; installing now risks a lockout." \
        "echo 'YOUR.IP.HERE  # admin' >> ${CONF_DIR}/whitelist_ips.txt   then re-run ./install.sh"
fi

# --- permissions ---------------------------------------------------------------
chown -R root:root "$INSTALL_DIR" "$CONF_DIR" 2>/dev/null || true
chmod 0750 "$INSTALL_DIR" "$CONF_DIR"
find "$INSTALL_DIR" -type d -exec chmod 0750 {} \; 2>/dev/null || true
find "$INSTALL_DIR" -type f -exec chmod 0640 {} \; 2>/dev/null || true
chmod 0750 "${INSTALL_DIR}/logwall" "${INSTALL_DIR}/install.sh" \
           "${INSTALL_DIR}/uninstall.sh" "${INSTALL_DIR}/preflight.sh"
chmod 0600 "$CONF_FILE"
chmod 0640 "${CONF_DIR}"/*.txt 2>/dev/null || true

if [ ! -e /usr/local/bin/logwall ]; then
    ln -sf "${INSTALL_DIR}/logwall" /usr/local/bin/logwall
    record "symlink:/usr/local/bin/logwall"
fi

# ==============================================================================
# STAGE 4 — VERIFY the installed copy in place
#
# A copy that cannot execute is worse than no installation: cron would fail
# silently every two minutes. If verification fails, the install is undone.
# ==============================================================================
echo "[STAGE 4/5] Verifying the installed copy..."

if ! PYTHONPATH="${INSTALL_DIR}/lib/py" python3 -c \
        "import config_loader, ip_guard, log_parser, audit_engine, apply_engine, report_gen" 2>/dev/null; then
    abort_install "The installed Python modules cannot be imported." \
        "Run: PYTHONPATH=${INSTALL_DIR}/lib/py python3 -c 'import apply_engine'   to see the error."
fi

if ! bash -n "${INSTALL_DIR}/logwall"; then
    abort_install "The installed CLI failed its syntax check." \
        "The copy is corrupt; re-copy the project directory and retry."
fi

if ! "${INSTALL_DIR}/logwall" version >/dev/null 2>&1; then
    abort_install "The installed CLI cannot run." \
        "Run ${INSTALL_DIR}/logwall version   to see the error."
fi

# The absolute path is not the path a human types. Checking only that one is how
# a broken /usr/local/bin symlink reached a working installation unnoticed: cron
# uses the absolute path and kept working, while every interactive command failed.
if [ -L /usr/local/bin/logwall ] && ! /usr/local/bin/logwall version >/dev/null 2>&1; then
    abort_install "The CLI works by absolute path but fails through /usr/local/bin/logwall." \
        "The symlink is not being resolved. Run: /usr/local/bin/logwall version"
fi

# cron's environment is not a login shell's. Verifying only under the installer's
# own PATH is how a silently-aborting scheduled cycle passes as a healthy install.
if ! env -i /bin/sh -c "${INSTALL_DIR}/logwall version" >/dev/null 2>&1; then
    abort_install "The CLI fails under a cron-like empty environment."         "Run: env -i /bin/sh -c '${INSTALL_DIR}/logwall version'   to see the error."
fi

WORLD_WRITABLE=$(find "$INSTALL_DIR" "$CONF_DIR" -perm -0002 2>/dev/null | head -n 5 || true)
if [ -n "$WORLD_WRITABLE" ]; then
    abort_install "World-writable files remain after installation: ${WORLD_WRITABLE}" \
        "chmod -R o-w ${INSTALL_DIR} ${CONF_DIR}   then re-run ./install.sh"
fi

RUNTIME_RC=0
bash "${INSTALL_DIR}/preflight.sh" --runtime --quiet >/dev/null 2>&1 || RUNTIME_RC=$?
if [ "$RUNTIME_RC" -eq 2 ]; then
    abort_install "Post-install runtime check failed (a blocker appeared during installation)." \
        "bash ${INSTALL_DIR}/preflight.sh --runtime   to see which one."
fi

echo "[STAGE 4/5]   modules import OK · CLI runs OK · permissions OK · runtime gate OK"

# ==============================================================================
# STAGE 5 — Schedule
# ==============================================================================
echo "[STAGE 5/5] Scheduling..."

if [ "$SKIP_CRON" -eq 1 ]; then
    echo "[INFO]   cron registration skipped (--no-cron)"
else
    . "${INSTALL_DIR}/lib/cron_manager.sh"
    if install_crons; then
        record "cron:installed"
        if ! crontab -l 2>/dev/null | grep -q "logwall-managed"; then
            abort_install "Cron entries were reported installed but are not present." \
                "Check the cron daemon, then re-run ./install.sh"
        fi
        echo "[INFO]   registered logwall cron entries (verified present)"
    else
        abort_install "Cron registration failed." \
            "Install and start a cron daemon, or use ./install.sh --no-cron"
    fi
fi

INSTALL_COMPLETE=1
trap - ERR
trap - EXIT

# ------------------------------------------------------------------- summary
WL_ENTRIES=$(grep -vE '^\s*(#|$)' "${CONF_DIR}/whitelist_ips.txt" 2>/dev/null \
             | grep -vE '^\s*(127\.|::1)' | awk '{print $1}' | paste -sd' ' - 2>/dev/null || true)
[ -z "$WL_ENTRIES" ] && WL_ENTRIES="(none besides loopback)"

DDNS_ENTRIES=$(grep -vE '^\s*(#|$)' "${CONF_DIR}/whitelist_hosts.txt" 2>/dev/null \
               | awk '{print $1}' | paste -sd' ' - 2>/dev/null || true)
[ -z "$DDNS_ENTRIES" ] && DDNS_ENTRIES="(none configured)"

ENFORCE_STATE=$(grep -E '^\s*ENFORCE=' "$CONF_FILE" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
if [ "${ENFORCE_STATE:-0}" = "1" ]; then
    ENFORCE_LABEL="ENFORCE=1 — DROPPING TRAFFIC"
else
    ENFORCE_LABEL="ENFORCE=0 — observe only, nothing is dropped"
fi

cat <<EOF

==============================================================================
 INSTALLED — logwall $(cat "${INSTALL_DIR}/VERSION" 2>/dev/null || echo '?') at ${INSTALL_DIR}
==============================================================================

 [ADMIN ACCESS]
   Whitelisted IPs  : ${WL_ENTRIES}
   DDNS hostnames   : ${DDNS_ENTRIES}
   SSH port         : ${SSH_PORT_DETECTED}

 [ENFORCEMENT]
   ${ENFORCE_LABEL}

 [BEFORE YOU ENABLE ENFORCE=1 — verify these yourself, logwall cannot]
   [ ] A second admin path exists (backup IP, VPN/tethering, or DDNS hostname)
   [ ] Your provider's console/VNC access works and you have tested logging in
   [ ] THRESHOLD_HITS_PER_INTERVAL suits your traffic. The default 60, with
       STRIKES_REQUIRED=2, is calibrated against a real site - but read a few
       'logwall firewall audit' cycles before enabling enforcement anyway

 [NEXT]
   logwall doctor                    # re-check this host at any time
   logwall firewall audit            # what it would block; changes nothing
   logwall firewall apply --dry-run
   logwall firewall apply            # arms a deadman rollback
   logwall firewall confirm          # must run within CONFIRM_TIMEOUT_SEC

 [EMERGENCY]
   logwall firewall panic            # detach every logwall hook, keep other tools
   logwall firewall rollback         # restore the last snapshot

 [LOGS]
   Installation     : ${LOG_FILE}
   Operational      : ${LOG_DIR}/
   Config           : ${CONF_FILE}
==============================================================================
EOF

finalize_log
echo " Transcript saved: ${LOG_FINAL_PATH}"
