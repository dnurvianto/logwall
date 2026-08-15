#!/usr/bin/env bash
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: tests/gate_test.sh
# Purpose: Verifies the installation gate refuses what it is supposed to refuse.
#          Runs entirely against stubbed commands in a temp directory — touches
#          no firewall, no cron, no system path.
# Usage:   bash tests/gate_test.sh
# ==============================================================================

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK=$(mktemp -d)
STUB="${WORK}/bin"
mkdir -p "$STUB"

# An installed host has /etc/logwall.conf, and preflight sources it AFTER the
# environment is set — so every WHITELIST or BACKEND a fixture exports is silently
# overwritten by the host's real config. The suite then fails for reasons that have
# nothing to do with the gate. Pointing LOGWALL_CONF at a file that does not exist
# gives every run the same blank slate, on a workstation and on a live server alike.
export LOGWALL_CONF="${WORK}/no-such-logwall.conf"

PASS=0
FAIL=0

check() {
    local label="$1" condition="$2" detail="${3:-}"
    if [ "$condition" = "1" ]; then
        printf '[PASS] %s\n' "$label"
        PASS=$((PASS + 1))
    else
        printf '[FAIL] %s %s\n' "$label" "${detail:+-> $detail}"
        FAIL=$((FAIL + 1))
    fi
}

# Creates an executable stub that prints fixed output.
make_stub() {
    local name="$1"; shift
    printf '#!/bin/sh\n%s\n' "$*" > "${STUB}/${name}"
    chmod +x "${STUB}/${name}"
}

# The suite itself usually runs over SSH, and a live session is a genuine admin
# access path. Both session sources are neutralised so the fixtures measure only
# what they intend to: SSH_CLIENT/SSH_CONNECTION from the environment, and the
# established-session probe via `ss`.
# preflight hardens its own PATH: if /sbin is absent it PREPENDS the sbin
# directories, which pushes the stub directory behind the real /usr/sbin. On a
# workstation those directories do not exist, so the stubs won anyway and the
# suite looked green — but on any real Linux host the fixtures were silently
# bypassed and the tests measured the live system instead. Twelve checks failed
# on a production host for that reason alone.
#
# Including /sbin here satisfies preflight's check, so it leaves the order alone
# and the stubs stay in front. The product's hardening is correct and unchanged.
STUB_PATH="${STUB}:/usr/local/sbin:/usr/local/bin:/sbin:/usr/sbin:/usr/bin:/bin"

run_preflight() {
    # shellcheck disable=SC2097,SC2098
    env -u SSH_CLIENT -u SSH_CONNECTION PATH="${STUB_PATH}" \
        bash "${REPO}/preflight.sh" --no-probe "$@" 2>&1
}

preflight_code() {
    env -u SSH_CLIENT -u SSH_CONNECTION PATH="${STUB_PATH}" \
        bash "${REPO}/preflight.sh" --no-probe "$@" >/dev/null 2>&1
    echo $?
}

echo "=============================================================================="
echo " logwall gate test — stubbed environment, nothing real is touched"
echo "=============================================================================="

# ---------------------------------------------------------------------------
# 1. A competing blocker in cron must be a BLOCKER
# ---------------------------------------------------------------------------
make_stub crontab 'cat <<EOF
CRON_TZ="Asia/Jakarta"
*/2 * * * * /root/scripts/auto_blocker.sh > /dev/null 2>&1
*/5 * * * * python3 /root/scripts/cron_guard.py > /dev/null 2>&1
0 3 * * * /root/scripts/fastpanel_backup.sh
EOF'

OUT=$(run_preflight)
case "$OUT" in
    *COMPETING_CRON*auto_blocker*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "competing cron job (auto_blocker.sh) is detected" "$HIT"

case "$OUT" in
    *"crontab -e"*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "detection carries an actionable FIX command" "$HIT"

check "verdict is BLOCKED when a competing blocker exists" \
      "$([ "$(preflight_code)" = "2" ] && echo 1 || echo 0)" \
      "exit=$(preflight_code)"

# An unrelated cron job must NOT be flagged.
case "$OUT" in
    *"fastpanel_backup"*) HIT=0 ;;
    *) HIT=1 ;;
esac
check "unrelated cron job (backup) is not flagged" "$HIT"

# ---------------------------------------------------------------------------
# 2. logwall's own cron entries must never look like competition
# ---------------------------------------------------------------------------
make_stub crontab 'cat <<EOF
*/2 * * * * /opt/logwall/logwall firewall apply --no-confirm --quiet >/dev/null 2>&1 # logwall-managed
*/10 * * * * /opt/logwall/logwall selftest --repair --quiet >/dev/null 2>&1 # logwall-managed
EOF'

OUT=$(run_preflight)
case "$OUT" in
    *COMPETING_CRON*) HIT=0 ;;
    *) HIT=1 ;;
esac
check "logwall's own cron entries are not mistaken for a competitor" "$HIT"

# ---------------------------------------------------------------------------
# 3. A foreign ipset referenced by a live DROP rule must be a BLOCKER
# ---------------------------------------------------------------------------
make_stub crontab 'exit 1'
make_stub iptables 'case "$1" in
  -S) cat <<EOF
-P INPUT DROP
-A INPUT -m set --match-set WHITELIST_SET src -j ACCEPT
-A INPUT -m set --match-set BLACKLIST_SET src -j DROP
EOF
  ;;
  *) exit 0 ;;
esac'
make_stub ipset 'case "$1" in
  list)
    case "$2" in
      -n) printf "WHITELIST_SET\nBLACKLIST_SET\n" ;;
      *) printf "Name: %s\nType: hash:net\nNumber of entries: 1175\n" "$2" ;;
    esac
    ;;
  *) exit 0 ;;
esac'

OUT=$(run_preflight)
case "$OUT" in
    *FOREIGN_IPSET*BLACKLIST_SET*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "foreign ipset used by a live DROP rule is detected" "$HIT"

case "$OUT" in
    *"1175 entries"*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "foreign ipset report includes its entry count" "$HIT"

case "$OUT" in
    *"ipset list BLACKLIST_SET > /root/BLACKLIST_SET.backup"*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "foreign ipset finding recommends preserving the list first" "$HIT"

# ---------------------------------------------------------------------------
# 3b. Admin access-path counting (loopback must not count as a way back in)
# ---------------------------------------------------------------------------
make_stub crontab 'exit 1'
rm -f "${STUB}/iptables" "${STUB}/ipset"

# An established SSH session is a real admin access path, and this suite normally
# runs over SSH on the host being tested. Without this stub `ss` reports that
# live session and every expected count shifts by one — a failure that appears
# only on the target machine, never on the workstation where `ss` is absent.
make_stub ss 'exit 0'

printf '# template\n127.0.0.1\n::1\n' > "${WORK}/wl_loopback.txt"
printf '# admin\n203.0.113.9\n'       > "${WORK}/wl_one.txt"
printf '# admin\n203.0.113.9\n198.18.7.7\n' > "${WORK}/wl_two.txt"
: > "${WORK}/hosts_empty.txt"

export WHITELIST_DYNAMIC_HOSTS="${WORK}/hosts_empty.txt"

export WHITELIST="${WORK}/wl_loopback.txt"
OUT=$(run_preflight)
case "$OUT" in
    *NO_ADMIN_IP*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "whitelist containing only loopback counts as NO access path" "$HIT"

export WHITELIST="${WORK}/wl_one.txt"
OUT=$(run_preflight)
case "$OUT" in
    *SINGLE_ADMIN_IP*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "exactly one admin path raises SINGLE_ADMIN_IP" "$HIT"

case "$OUT" in
    *DuckDNS*|*"DDNS hostname"*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "SINGLE_ADMIN_IP suggests a concrete second path" "$HIT"

# Whether a changing address actually locks you out depends on HOW the baseline
# grants SSH, not on how many whitelist entries exist.
make_stub iptables 'case "$1" in
  -S) printf -- "-P INPUT DROP
-A INPUT -s 203.0.113.9/32 -j ACCEPT
" ;;
  *) exit 0 ;;
esac'
OUT=$(run_preflight)
case "$OUT" in
    *"grants SSH by source address only"*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "SSH granted per-source is named as the real lockout risk" "$HIT"

case "$OUT" in
    *"property of your BASELINE, not of logwall"*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "the lockout risk is attributed to the baseline, not to logwall" "$HIT"

# SSH port open to every source -> a changing address does not lock you out.
#
# The port MUST be read from the host, never hardcoded to 22. preflight matches
# rules against the real SSH port, so a fixture carrying `--dport 22` can never
# match on a host whose SSH lives on 3456 — the test would pass on port-22 hosts
# and fail on every other one, for a reason that has nothing to do with the gate.
HOST_SSH_PORT=$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/ {print $2; exit}' /etc/ssh/sshd_config 2>/dev/null)
HOST_SSH_PORT="${HOST_SSH_PORT:-22}"
make_stub iptables "case \"\$1\" in
  -S) printf -- \"-P INPUT DROP\n-A INPUT -p tcp -m tcp --dport ${HOST_SSH_PORT} -j ACCEPT\n\" ;;
  *) exit 0 ;;
esac"
OUT=$(run_preflight)
case "$OUT" in
    *"will not lock you out"*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "a port-based SSH ACCEPT downgrades the dynamic-IP warning" "$HIT"

rm -f "${STUB}/iptables"

export WHITELIST="${WORK}/wl_two.txt"
OUT=$(run_preflight)
case "$OUT" in
    *SINGLE_ADMIN_IP*) HIT=0 ;;
    *) HIT=1 ;;
esac
check "two admin paths do not raise SINGLE_ADMIN_IP" "$HIT"

case "$OUT" in
    *ADMIN_PATHS*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "admin path count is reported" "$HIT"

unset WHITELIST_DYNAMIC_HOSTS WHITELIST

# ---------------------------------------------------------------------------
# 3c. preflight must never block on input, whatever the mode
# ---------------------------------------------------------------------------
if command -v timeout >/dev/null 2>&1; then
    timeout 25 bash -c "PATH="${STUB_PATH}" bash '${REPO}/preflight.sh' --no-probe < /dev/null" \
        >/dev/null 2>&1
    RC=$?
    check "preflight never waits for input (no interactive prompt)" \
          "$([ "$RC" != "124" ] && echo 1 || echo 0)" "rc=${RC}"
fi

# ---------------------------------------------------------------------------
# 3d. CSF: blocker by default, coordination mode when chosen deliberately
# ---------------------------------------------------------------------------
make_stub crontab 'exit 1'
# svc_is_active() dispatches on the detected init system; outside systemd it
# uses `service`, so that is what has to be stubbed here.
make_stub systemctl 'for a in "$@"; do case "$a" in csf|lfd) exit 0 ;; esac; done; exit 1'
make_stub service 'case "$1" in
  csf|lfd) exit 0 ;;
  *) exit 1 ;;
esac'

export WHITELIST="${WORK}/wl_two.txt"

unset BACKEND
OUT=$(run_preflight)
case "$OUT" in
    *COMPETING_SERVICE*csf*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "active CSF is a BLOCKER when coordination was not chosen" "$HIT"

case "$OUT" in
    *"BACKEND=csf"*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "CSF blocker offers coordination as the remedy" "$HIT"

export BACKEND=csf
OUT=$(run_preflight)
case "$OUT" in
    *COMPETING_SERVICE*) HIT=0 ;;
    *) HIT=1 ;;
esac
check "BACKEND=csf downgrades the CSF service finding" "$HIT"

case "$OUT" in
    *CSF_COORDINATED*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "coordination mode is reported explicitly" "$HIT"

unset BACKEND WHITELIST
rm -f "${STUB}/systemctl" "${STUB}/service"

# ---------------------------------------------------------------------------
# 3e. Baseline managers coexist; only dynamic blockers compete
#
# firewalld and ufw own the baseline but never ban addresses on their own, so
# logwall layers on top of them. Blocking on their presence made logwall
# uninstallable on every RHEL-family default — while the very fix text for
# NO_BASELINE_POLICY tells the operator to install firewalld.
# ---------------------------------------------------------------------------
make_stub crontab 'exit 1'
export WHITELIST="${WORK}/wl_two.txt"

for MGR in firewalld ufw; do
    make_stub systemctl "for a in \"\$@\"; do case \"\$a\" in ${MGR}) exit 0 ;; esac; done; exit 1"
    make_stub service "case \"\$1\" in ${MGR}) exit 0 ;; *) exit 1 ;; esac"

    OUT=$(run_preflight)

    case "$OUT" in
        *COMPETING_SERVICE*) HIT=0 ;;
        *) HIT=1 ;;
    esac
    check "active ${MGR} is NOT a competing service" "$HIT"

    case "$OUT" in
        *COEXISTS_WITH_MANAGER*) HIT=1 ;;
        *) HIT=0 ;;
    esac
    check "active ${MGR} reports coexistence explicitly" "$HIT"

    case "$OUT" in
        *NO_BASELINE_POLICY*) HIT=0 ;;
        *) HIT=1 ;;
    esac
    check "${MGR} satisfies the default-deny baseline" "$HIT"
done

# The warning has to name the hazard it is warning about, or it is decoration.
# It used to be asserted that the text named "the watchdog" as the thing that
# repairs a torn-out chain. Measured 2026-08-15: the 2-minute apply cron does
# that, not the */10 selftest — so this check was pinning a false claim in place.
# What must be named now is the reload and the window during which nothing is
# enforced, because that is the part an operator has to plan around.
case "$OUT" in
    *reload*2\ minutes*|*2\ minutes*reload*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "coexistence warning names the reload hazard and the enforcement gap" "$HIT"

# Agents that ban addresses dynamically must still block, whatever their name.
for DYN in fail2ban crowdsec crowdsec-firewall-bouncer; do
    make_stub systemctl "for a in \"\$@\"; do case \"\$a\" in ${DYN}) exit 0 ;; esac; done; exit 1"
    make_stub service "case \"\$1\" in ${DYN}) exit 0 ;; *) exit 1 ;; esac"
    OUT=$(run_preflight)
    case "$OUT" in
        *COMPETING_SERVICE*${DYN}*) HIT=1 ;;
        *) HIT=0 ;;
    esac
    check "active ${DYN} is a BLOCKER (blocks addresses dynamically)" "$HIT"
done

# ---------------------------------------------------------------------------
# 3f. A native nftables ruleset is a baseline, even though iptables cannot see it
#
# On a host filtering through its own nft table, `iptables -S INPUT` reports
# "-P INPUT ACCEPT" and zero rules. Judging the baseline from that view alone
# calls a protected host unprotected.
# ---------------------------------------------------------------------------
rm -f "${STUB}/systemctl" "${STUB}/service"
make_stub iptables 'case "$1" in
  -S) printf -- "-P INPUT ACCEPT\n" ;;
  *) exit 0 ;;
esac'
make_stub nft 'printf "table inet fw {\n  chain input {\n    type filter hook input priority filter; policy drop;\n  }\n}\n"'

OUT=$(run_preflight)
case "$OUT" in
    *NO_BASELINE_POLICY*) HIT=0 ;;
    *) HIT=1 ;;
esac
check "native nftables drop policy counts as a baseline" "$HIT"

case "$OUT" in
    *BASELINE_OK*nftables*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "the nftables baseline is named in the finding" "$HIT"

# A table full of accept rules is not a default-deny.
#
# The guardian check runs after this one and asks whether a real manager is
# active. On a host where firewalld or CSF genuinely runs it answers yes — which
# is correct product behaviour — and NO_BASELINE_POLICY never fires. Without
# stubbing that away the fixture measures the host, not the nft output it set up.
make_stub systemctl 'exit 3'
make_stub service 'exit 1'
make_stub nft 'printf "table inet fw {\n  chain input {\n    type filter hook input priority filter; policy accept;\n  }\n}\n"'
OUT=$(run_preflight)
case "$OUT" in
    *NO_BASELINE_POLICY*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "an accept-policy nftables hook is NOT mistaken for a baseline" "$HIT"

# ---------------------------------------------------------------------------
# 3i. Stage 1: the four gaps the behaviour matrix uncovered
# ---------------------------------------------------------------------------
rm -f "${STUB}/nft" "${STUB}/iptables" "${STUB}/systemctl" "${STUB}/service"
make_stub crontab 'exit 1'
export WHITELIST="${WORK}/wl_two.txt"

# Two baseline owners overwrite each other's ruleset on reload; whichever runs
# last wins.
make_stub systemctl 'for a in "$@"; do case "$a" in firewalld|ufw) exit 0 ;; esac; done; exit 1'
make_stub service 'case "$1" in firewalld|ufw) exit 0 ;; *) exit 1 ;; esac'
make_stub firewall-cmd 'exit 0'
make_stub ufw 'case "$1" in status) printf "Status: active
" ;; esac; exit 0'
OUT=$(run_preflight)
case "$OUT" in
    *TWO_BASELINE_MANAGERS*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "two active baseline managers are flagged" "$HIT"

case "$OUT" in
    *"discards the other's rules"*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "the two-manager finding states what actually breaks" "$HIT"

# A single manager must not trigger it.
make_stub systemctl 'for a in "$@"; do case "$a" in firewalld) exit 0 ;; esac; done; exit 1'
make_stub service 'case "$1" in firewalld) exit 0 ;; *) exit 1 ;; esac'
rm -f "${STUB}/ufw"
OUT=$(run_preflight)
case "$OUT" in
    *TWO_BASELINE_MANAGERS*) HIT=0 ;;
    *) HIT=1 ;;
esac
check "a single manager does not trigger the two-manager finding" "$HIT"

# Both families open: the operator has to learn there are TWO jobs here, not one.
#
# systemctl/service are STUBBED to report "nothing active", not deleted. Deleting
# them lets the host's REAL systemctl through — on a host running firewalld or
# CSF the guardian then finds a genuine manager, BASELINE_OK wins, and
# NO_BASELINE_POLICY never fires. The test would pass on hosts without a manager
# and fail on every host that has one.
rm -f "${STUB}/firewall-cmd" "${STUB}/ufw"
make_stub systemctl 'case "$1" in is-enabled) exit 1 ;; is-active) exit 3 ;; *) exit 0 ;; esac'
make_stub service 'exit 1' 
make_stub ip 'case "$*" in *"-6 addr"*) printf "    inet6 2a11::a/64 scope global
" ;; *) exit 0 ;; esac'
make_stub iptables 'case "$1" in -S) printf -- "-P INPUT ACCEPT
" ;; *) exit 0 ;; esac'
make_stub ip6tables 'case "$1" in -S) printf -- "-P INPUT ACCEPT
" ;; *) exit 0 ;; esac'
make_stub nft 'exit 1'
OUT=$(run_preflight)
case "$OUT" in
    *"TWO jobs, not one"*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "both families open says it is two jobs, not one" "$HIT"

# The old wording overstated it; logwall still blocks whatever it detects.
case "$OUT" in
    *"protects almost nothing"*) HIT=0 ;;
    *) HIT=1 ;;
esac
check "NO_BASELINE_POLICY no longer claims it protects almost nothing" "$HIT"

rm -f "${STUB}/ip" "${STUB}/iptables" "${STUB}/ip6tables" "${STUB}/nft"
unset WHITELIST

# The next two cannot be stubbed: a missing binary is defeated by PATH hardening,
# and PANEL_TYPE is read from absolute directory paths. Pinned at source level.
case "$(sed -n '/^check_firewall_tools/,/^}/p' "${REPO}/preflight.sh" | grep -c 'IPSET_NOT_NEEDED')" in
    0) HIT=0 ;;
    *) HIT=1 ;;
esac
check "CSF mode does not demand ipset it never uses" "$HIT"

case "$(grep -c 'PANEL_FIREWALL_UNCHECKED' "${REPO}/preflight.sh")" in
    0) HIT=0 ;;
    *) HIT=1 ;;
esac
check "panels with their own firewall module are named as unverified" "$HIT"

# The one blocker that sends the operator elsewhere must name the tool their
# distro actually expects — three options and no guidance is not advice.
# Ubuntu reports OS_FAMILY=debian; its advice must still be ufw, not nftables.
case "$(sed -n '/local baseline_fix/,/^    esac/p' "${REPO}/preflight.sh" | grep -c 'OS_DISTRO:-.*= *"ubuntu"')" in
    0) HIT=0 ;;
    *) HIT=1 ;;
esac
check "Ubuntu gets ufw advice even though its family is debian" "$HIT"

for FAM in rhel debian alpine arch; do
    case "$(sed -n '/local baseline_fix/,/^    esac/p' "${REPO}/preflight.sh" | grep -c "^        ${FAM})")" in
        0) HIT=0 ;;
        *) HIT=1 ;;
    esac
    check "baseline advice is tailored for ${FAM}" "$HIT"
done

rm -f "${STUB}/nft" "${STUB}/iptables" "${STUB}/systemctl" "${STUB}/service"

# `--now` stops the service, and stopping a firewall service flushes its ruleset.
# That is how a MADC cleanup once left the host open for a minute.
case "$(grep -c 'disable --now' "${REPO}/preflight.sh")" in
    0) HIT=1 ;;
    *) HIT=0 ;;
esac
check "no FIX text tells the operator to 'systemctl disable --now' a firewall" "$HIT"

# nftables.service loads a saved ruleset at boot; it is not a manager and proves
# nothing about a default-deny existing.
case "$(sed -n '/No default-deny here/,/^    done/p' "${REPO}/preflight.sh" \
        | grep -E '^[[:space:]]*for svc in' | grep -c nftables)" in
    0) HIT=1 ;;
    *) HIT=0 ;;
esac
check "nftables.service is not treated as a baseline guardian" "$HIT"

unset WHITELIST
rm -f "${STUB}/systemctl" "${STUB}/service"

# ---------------------------------------------------------------------------
# 3g. nftables-native detection decides where persistence is written
#
# Debian's nftables package ships a sample /etc/nftables.conf, so "the config is
# non-empty" was true on stock hosts whose nftables.service is disabled and whose
# rules are really restored by netfilter-persistent. Believing it sent the ruleset
# into a file nothing loads while /etc/iptables/rules.v4 stayed without a single
# logwall rule — and the run reported success. Measured on Debian 12.
# ---------------------------------------------------------------------------
# Sourcing system_discovery.sh resets INIT_SYSTEM to "unknown", so it has to be
# set afterwards. A probe file avoids quoting the source path through bash -c.
cat > "${WORK}/nft_probe.sh" <<'PROBE'
#!/usr/bin/env bash
. "$1/lib/system_discovery.sh"
INIT_SYSTEM=systemd
_nft_is_native && echo native || echo not-native
PROBE
chmod +x "${WORK}/nft_probe.sh"

run_native_probe() {
    PATH="${STUB_PATH}" bash "${WORK}/nft_probe.sh" "${REPO}" 2>/dev/null
}

make_stub nft 'case "$1" in
  list) printf "table ip filter\ntable ip nat\ntable ip mangle\n" ;;
  *) exit 0 ;;
esac'
# Service present but NOT enabled — the stock Debian shape.
make_stub systemctl 'case "$1" in
  is-enabled) exit 1 ;;
  is-active)  exit 3 ;;
  *) exit 0 ;;
esac'

NATIVE=$(run_native_probe)
check "a disabled nftables.service is NOT an nftables-native host" \
      "$([ "$NATIVE" = "not-native" ] && echo 1 || echo 0)" "$NATIVE"

# The enabled unit is what makes it native — that check must still work.
make_stub systemctl 'case "$1" in
  is-enabled) exit 0 ;;
  is-active)  exit 3 ;;
  *) exit 0 ;;
esac'
NATIVE=$(run_native_probe)
check "an enabled nftables.service IS an nftables-native host" \
      "$([ "$NATIVE" = "native" ] && echo 1 || echo 0)" "$NATIVE"

# A live table outside the iptables-nft compat set is the other honest signal.
make_stub nft 'case "$1" in
  list) printf "table inet myfilter\n" ;;
  *) exit 0 ;;
esac'
make_stub systemctl 'case "$1" in
  is-enabled) exit 1 ;;
  is-active)  exit 3 ;;
  *) exit 0 ;;
esac'
NATIVE=$(run_native_probe)
check "a live inet table still counts as nftables-native" \
      "$([ "$NATIVE" = "native" ] && echo 1 || echo 0)" "$NATIVE"

# A config file says nothing about who reads it, so it must not be consulted.
case "$(sed -n '/_nft_is_native()/,/^}/p' "${REPO}/lib/system_discovery.sh" \
        | grep -cE '^[[:space:]]*if \[ -s /etc/nftables.conf')" in
    0) HIT=1 ;;
    *) HIT=0 ;;
esac
check "a populated /etc/nftables.conf is no longer treated as evidence" "$HIT"

# And the writer must ask the unit, not merely whether the nft binary exists.
case "$(sed -n '/^        nftables)/,/^            ;;/p' "${REPO}/lib/firewall_wrapper.sh" \
        | grep -c 'svc_is_enabled nftables')" in
    0) HIT=0 ;;
    *) HIT=1 ;;
esac
check "persistence writes to /etc/nftables.conf only when the unit is enabled" "$HIT"

rm -f "${STUB}/nft" "${STUB}/systemctl"

# ---------------------------------------------------------------------------
# 3h. IPv6 exposure must not be silenced by logwall's own presence
#
# The rule count used to include logwall's three LOGWALL_* jumps, so installing
# them pushed the count past the threshold and the warning stopped firing —
# on a host still accepting every IPv6 connection, with ten services listening.
# The tool masked a live exposure with its own footprint.
# ---------------------------------------------------------------------------
rm -f "${STUB}/systemctl" "${STUB}/service" "${STUB}/nft"
make_stub crontab 'exit 1'
export WHITELIST="${WORK}/wl_two.txt"

# IPv4 filtered, IPv6 wide open — and the only v6 rules present are logwall's own.
make_stub ip 'case "$*" in
  *"-6 addr"*) printf "    inet6 2a11:8083::a/64 scope global
" ;;
  *) exit 0 ;;
esac'
make_stub iptables 'case "$1" in
  -S) printf -- "-P INPUT DROP
" ;;
  *) exit 0 ;;
esac'
make_stub ip6tables 'case "$1" in
  -S) printf -- "-P INPUT ACCEPT
-A INPUT -j LOGWALL_WL
-A INPUT -j LOGWALL_BLOCK
-A INPUT -j LOGWALL_RATE
" ;;
  *) exit 0 ;;
esac'

OUT=$(run_preflight)
case "$OUT" in
    *IPV6_NO_BASELINE*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "IPv6 gap still reported when only logwall's own jumps exist" "$HIT"

# The wording must not let a junior admin read this as "logwall does not cover
# IPv6" — the opposite of the truth. It has to say who protects what, and where
# the gap actually is, before it says anything else.
case "$OUT" in
    *"logwall protects IPv6"*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "IPv6 finding says logwall DOES cover IPv6" "$HIT"

case "$OUT" in
    *"THIS HOST has no IPv6 firewall"*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "IPv6 finding names the host as the gap, not logwall" "$HIT"

case "$OUT" in
    *"every IPv4 restriction"*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "IPv6 finding states the consequence, not just the condition" "$HIT"


# --accept-warnings also dismisses threshold suggestions; a gap that makes every
# IPv4 restriction bypassable must not ride along with them.
check "unacknowledged IPv6 exposure is a BLOCKER, not a warning"       "$([ "$(preflight_code)" = "2" ] && echo 1 || echo 0)" "exit=$(preflight_code)"

case "$OUT" in
    *"IPV6_BASELINE=external"*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "the IPv6 blocker offers a one-line way out" "$HIT"

# The manager that already closed IPv4 can usually close IPv6 with one setting.
# Telling a firewalld or CSF operator to hand-write ip6tables sends them to build
# what their manager does for free.
case "$(sed -n '/local v6_fix/,/^                esac/p' "${REPO}/preflight.sh" | grep -cE "^                    (csf|firewalld|ufw|nftables)\)")" in
    4) HIT=1 ;;
    *) HIT=0 ;;
esac
check "IPv6 fix advice is tailored per firewall manager" "$HIT"

case "$OUT" in
    *"session you can afford to lose"*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "IPv6 fix warns about locking yourself out" "$HIT"

# Declaring it understood must clear the block — refusing outright would deny
# real IPv4 protection over a gap in another family.
OUT=$(IPV6_BASELINE=external run_preflight)
case "$OUT" in
    *IPV6_NO_BASELINE*) HIT=0 ;;
    *) HIT=1 ;;
esac
check "IPV6_BASELINE=external clears the block" "$HIT"

case "$OUT" in
    *IPV6_ACKNOWLEDGED*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "the acknowledgement is recorded as a finding, not silence" "$HIT"

# A real default-deny on v6 must clear it.
make_stub ip6tables 'case "$1" in
  -S) printf -- "-P INPUT DROP
-A INPUT -j LOGWALL_WL
" ;;
  *) exit 0 ;;
esac'
OUT=$(run_preflight)
case "$OUT" in
    *IPV6_NO_BASELINE*) HIT=0 ;;
    *) HIT=1 ;;
esac
check "a v6 default-deny clears the exposure finding" "$HIT"

# The count must exclude logwall's jumps, not merely raise the threshold.
case "$(sed -n '/^check_ipv6_exposure()/,/^}/p' "${REPO}/lib/naming.sh" | grep -c "grep -vc 'LOGWALL'")" in
    0) HIT=0 ;;
    *) HIT=1 ;;
esac
check "v6 rule count excludes logwall's own jumps" "$HIT"

# CSF enforces IPv6 only when its own switch is on.
case "$(grep -c 'IPV6\[\[:space:\]\]\*=' "${REPO}/logwall")" in
    0) HIT=0 ;;
    *) HIT=1 ;;
esac
check "CSF push checks csf.conf IPV6 before sending a v6 address" "$HIT"

unset WHITELIST
rm -f "${STUB}/ip" "${STUB}/iptables" "${STUB}/ip6tables"

# ---------------------------------------------------------------------------
# 4. Exit-code contract
# ---------------------------------------------------------------------------
make_stub iptables 'case "$1" in
  -S) printf -- "-P INPUT DROP\n-A INPUT -m set --match-set BLACKLIST_SET src -j DROP\n" ;;
  *) exit 0 ;;
esac'
make_stub ipset 'case "$1" in
  list)
    case "$2" in
      -n) printf "BLACKLIST_SET\n" ;;
      *) printf "Name: %s\nType: hash:net\nNumber of entries: 1175\n" "$2" ;;
    esac
    ;;
  *) exit 0 ;;
esac'
check "BLOCKED returns exit 2" \
      "$([ "$(preflight_code)" = "2" ] && echo 1 || echo 0)"

OUT=$(run_preflight --json)
if command -v python3 >/dev/null 2>&1; then
    printf '%s' "$OUT" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null \
        && HIT=1 || HIT=0
    check "--json emits parseable JSON" "$HIT"
fi

# ---------------------------------------------------------------------------
# 5. install.sh must refuse and write nothing while blocked
#
# "no artefact exists afterwards" is only the same question as "the refused run
# created nothing" on a host where logwall was never installed. Anywhere it IS
# installed, /opt/logwall and friends were created hours earlier and the check can
# never pass — it fails for a reason that has nothing to do with install.sh.
# What matters is whether a path appeared that was NOT there beforehand.
# ---------------------------------------------------------------------------
ARTEFACT_PATHS="/opt/logwall /etc/logwall /etc/logwall.conf"
PRE_EXISTING=""
for path in $ARTEFACT_PATHS; do
    [ -e "$path" ] && PRE_EXISTING="${PRE_EXISTING} ${path}"
done

INSTALL_OUT=$(PATH="${STUB_PATH}" bash "${REPO}/install.sh" 2>&1)
INSTALL_RC=$?

case "$INSTALL_OUT" in
    *"INSTALLATION REFUSED"*) HIT=1 ;;
    *) HIT=0 ;;
esac
check "install.sh refuses while blockers exist" "$HIT"

check "install.sh exits 2 when refused" \
      "$([ "$INSTALL_RC" = "2" ] && echo 1 || echo 0)" "exit=${INSTALL_RC}"

case "$INSTALL_OUT" in
    *"Unexpected failure"*) HIT=0 ;;
    *) HIT=1 ;;
esac
check "refusal is a clean message, not a crash" "$HIT"

HIT=1
NEW_ARTEFACTS=""
for path in $ARTEFACT_PATHS; do
    case " ${PRE_EXISTING} " in
        *" ${path} "*) continue ;;   # already there before this run
    esac
    if [ -e "$path" ]; then
        HIT=0
        NEW_ARTEFACTS="${NEW_ARTEFACTS} ${path}"
    fi
done
check "install.sh created no NEW artefact while refused" "$HIT" "${NEW_ARTEFACTS# }"

case "$INSTALL_OUT" in
    *"STAGE 3"*) HIT=0 ;;
    *) HIT=1 ;;
esac
check "install.sh never reached the writing stage" "$HIT"

echo
echo "------------------------------------------------------------------------------"
printf ' passed=%d failed=%d\n' "$PASS" "$FAIL"
rm -rf "$WORK"
[ "$FAIL" -eq 0 ] && { echo " RESULT: gate behaves as specified"; exit 0; }
echo " RESULT: ${FAIL} gate check(s) FAILED"
exit 1
