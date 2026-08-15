#!/usr/bin/env python3
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: lib/py/apply_engine.py
# Purpose: Turns audited candidates into blacklist entries. Owns the escalation
#          ladder (TEMP -> PERMANENT), deduplication, circuit breaker, and the
#          generation of an atomic `ipset restore` script for the Bash layer.
# Reference: docs/DESIGN.md §7 (apply), §12 (Escalation), §16.4 (Circuit Breaker)
# ==============================================================================

import argparse
import datetime
import ipaddress
import json
import os
import re
import sys
import time

from audit_engine import TIER_PERMANENT, TIER_TEMP, AuditEngine
from config_loader import get_bool, get_int, get_path, load_config
from ip_guard import load_networks

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_BREAKER = 6

# Defaults are deliberately prefixed. Generic names such as BLACKLIST_SET belong
# to first-generation blocker scripts, and swapping a set logwall did not create
# would wipe another tool's blocklist. See lib/naming.sh.
DEFAULT_SETS = {
    "SET_BLACK4": "LOGWALL_BL4",
    "SET_BLACK6": "LOGWALL_BL6",
    "SET_WHITE4": "LOGWALL_WL4",
    "SET_WHITE6": "LOGWALL_WL6",
}

RESERVED_FOREIGN_SETS = {
    "BLACKLIST_SET", "WHITELIST_SET", "BLACKLIST_SET6", "WHITELIST_SET6",
    "blacklist", "whitelist", "csf_deny", "csf_allow",
}

COMMENT_SAFE_RE = re.compile(r'[^\w\s.:/|=+-]')


def sanitize_comment(text):
    """ipset comments are quoted strings; keep them boring and short."""
    cleaned = COMMENT_SAFE_RE.sub("", str(text))
    cleaned = " ".join(cleaned.split())
    return cleaned[:200] if cleaned else "Blocked by logwall"


class BlacklistEntry:
    __slots__ = ("target", "date", "reason", "tier", "strike", "expires")

    def __init__(self, target, date, reason, tier, strike, expires):
        self.target = target
        self.date = date
        self.reason = reason
        self.tier = tier
        self.strike = strike
        self.expires = expires

    def is_expired(self, now):
        return self.tier == TIER_TEMP and self.expires and self.expires <= now

    def to_line(self):
        expires = str(self.expires) if self.expires else "-"
        return (f"{self.target}    # {self.date} | {self.reason} | {self.tier} | "
                f"strike={self.strike} | expires={expires}\n")


def parse_blacklist_line(line):
    """
    Accepts both the current format and the older `IP  # date | reason` layout.
    Unparseable lines are dropped by the caller rather than silently mangled.
    """
    body, _, comment = line.partition("#")
    target = body.strip()
    if not target:
        return None

    try:
        ipaddress.ip_network(target, strict=False)
    except ValueError:
        return None

    fields = [part.strip() for part in comment.split("|")] if comment else []
    date = fields[0] if fields else datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    reason = fields[1] if len(fields) > 1 else "Imported entry"
    tier = TIER_PERMANENT
    strike = 1
    expires = None

    for field in fields[2:]:
        upper = field.upper()
        if upper in (TIER_PERMANENT, TIER_TEMP):
            tier = upper
        elif field.startswith("strike="):
            try:
                strike = int(field.split("=", 1)[1])
            except ValueError:
                strike = 1
        elif field.startswith("expires="):
            value = field.split("=", 1)[1]
            expires = int(value) if value.isdigit() else None

    if tier == TIER_TEMP and expires is None:
        tier = TIER_PERMANENT

    return BlacklistEntry(target, date, reason, tier, strike, expires)


class ApplyEngine:
    def __init__(self, config=None):
        self.config = config if config is not None else load_config()
        self.blacklist_file = get_path(self.config, "BLACKLIST",
                                       "/etc/logwall/blacklist_ips.txt")
        self.whitelist_file = get_path(self.config, "WHITELIST",
                                       "/etc/logwall/whitelist_ips.txt")
        self.state_dir = get_path(self.config, "STATE_DIR", "/opt/logwall/data/state")
        self.history_file = os.path.join(self.state_dir, "offender_history.json")

        self.max_new_blocks = get_int(self.config, "MAX_NEW_BLOCKS_PER_RUN", 50)
        self.temp_hours = get_int(self.config, "TEMP_BLOCK_HOURS", 48)
        self.maxelem = get_int(self.config, "IPSET_MAXELEM", 262144)
        self.capacity_alert = get_int(self.config, "IPSET_CAPACITY_ALERT_PCT", 80)
        self.escalation = get_bool(self.config, "BLOCK_ESCALATION", True)

        self.sets = {key: get_path(self.config, key, default)
                     for key, default in DEFAULT_SETS.items()}
        for key, name in self.sets.items():
            if name in RESERVED_FOREIGN_SETS:
                raise SystemExit(
                    f"[ERROR] {key}={name} is reserved for another tool. "
                    f"logwall refuses to manage it — choose a prefixed name.")

        # Mirrors the Bash layer's HAS_IPV6, which is what decides whether the v6
        # kernel sets get created at all.
        self.ipv6_enabled = os.environ.get("HAS_IPV6", "0") == "1"

        self.audit = AuditEngine(self.config)
        self.guard = self.audit.guard

        self.added = []
        self.expired = []
        self.escalated = []

    # ------------------------------------------------------------------ state
    def load_history(self):
        if os.path.isfile(self.history_file):
            try:
                with open(self.history_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    return data
            except (OSError, ValueError):
                pass
        return {}

    def save_history(self, history):
        # How long an offender is remembered after its temporary block expired.
        # Past this, a repeat offence starts from strike 1 again — addresses do
        # get reassigned, and punishing a new owner for the last one is wrong.
        days = get_int(self.config, "OFFENDER_MEMORY_DAYS", 90)
        cutoff = int(time.time()) - days * 86400
        pruned = {ip: rec for ip, rec in history.items()
                  if rec.get("last", 0) >= cutoff}
        _atomic_write(self.history_file, json.dumps(pruned))

    def load_blacklist(self):
        entries = {}
        if not os.path.isfile(self.blacklist_file):
            return entries
        try:
            with open(self.blacklist_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    entry = parse_blacklist_line(stripped)
                    if entry:
                        entries[entry.target] = entry
        except OSError:
            pass
        return entries

    # ------------------------------------------------------------------ apply
    def execute(self, force_breaker=False, dry_run=False):
        now = int(time.time())
        candidates = self.audit.evaluate_candidates()
        entries = self.load_blacklist()
        history = self.load_history()

        # 1. Release expired TEMP blocks. This is the only automatic unban, and
        #    it only ever applies to the TEMP tier (docs/DESIGN.md §12).
        for target, entry in list(entries.items()):
            if entry.is_expired(now):
                del entries[target]
                self.expired.append(target)
                record = history.setdefault(target, {"strike": 0})
                record["strike"] = entry.strike
                record["last"] = now

        # 2. Merge candidates.
        date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        pending = []

        for ip, meta in candidates.items():
            if ip in entries:
                continue

            tier = meta["tier"]
            reason = meta["reason"]
            strike = history.get(ip, {}).get("strike", 0) + 1

            # A repeat offender that already served a TEMP block is escalated.
            if tier == TIER_TEMP and strike > 1:
                tier = TIER_PERMANENT
                self.escalated.append(ip)

            expires = now + self.temp_hours * 3600 if tier == TIER_TEMP else None
            pending.append(BlacklistEntry(ip, date_str, reason, tier, strike, expires))

        # 3. Circuit breaker: an unnatural spike is a parser or configuration
        #    fault far more often than a synchronised attack (docs/DESIGN.md §16.4).
        if len(pending) > self.max_new_blocks and not force_breaker:
            print(f"[BREAKER_TRIPPED] {len(pending)} new candidates exceed "
                  f"MAX_NEW_BLOCKS_PER_RUN={self.max_new_blocks}. No IP was blocked.",
                  file=sys.stderr)
            for entry in pending[:20]:
                print(f"[BREAKER_TRIPPED]   {entry.target} -> {entry.reason}",
                      file=sys.stderr)
            # State is still committed: the counters are real, and the same
            # candidates will be presented again on the next run.
            if not dry_run:
                self.audit.commit_state()
                self.save_history(history)
            return EXIT_BREAKER, entries

        for entry in pending:
            entries[entry.target] = entry
            history.setdefault(entry.target, {})["strike"] = entry.strike
            history[entry.target]["last"] = now
            self.added.append(entry)

        if dry_run:
            self.report(entries, dry_run=True)
            return EXIT_OK, entries

        self.write_blacklist(entries)
        self.audit.commit_state()
        self.save_history(history)
        self.report(entries, dry_run=False)
        return EXIT_OK, entries

    def write_blacklist(self, entries):
        header = (
            "# ==============================================================================\n"
            "# logwall — Blacklist Attacker IP & Subnet Database\n"
            "# Format: IP/CIDR    # YYYY-MM-DD HH:MM | Reason | TIER | strike=N | expires=EPOCH\n"
            "# Managed automatically. Manual edits are preserved on the next run.\n"
            "# Reference: docs/DESIGN.md §7 & §12\n"
            "# ==============================================================================\n"
        )
        body = "".join(entry.to_line() for entry in
                       sorted(entries.values(), key=lambda e: e.target))
        _atomic_write(self.blacklist_file, header + body)

    # ------------------------------------------------------------- ipset output
    def emit_ipset_script(self, entries, path):
        """
        Writes an `ipset restore` script that rebuilds both blacklist sets in a
        temporary set and swaps them in atomically, so there is never a window in
        which the server is unprotected.
        """
        lines = []

        def emit_set(name, tmp_name, family, targets):
            lines.append(f"create {tmp_name} hash:net family {family} comment "
                         f"maxelem {self.maxelem} -exist")
            lines.append(f"flush {tmp_name}")
            for target, comment in targets:
                lines.append(f'add {tmp_name} {target} comment "{comment}"')
            lines.append(f"swap {tmp_name} {name}")
            lines.append(f"destroy {tmp_name}")

        black4, black6 = [], []
        for entry in entries.values():
            try:
                net = ipaddress.ip_network(entry.target, strict=False)
            except ValueError:
                continue
            comment = sanitize_comment(f"{entry.date} | {entry.reason} | {entry.tier}")
            (black4 if net.version == 4 else black6).append((entry.target, comment))

        white4, white6 = [], []
        for net in load_networks(self.whitelist_file):
            target = str(net)
            comment = "logwall admin whitelist"
            (white4 if net.version == 4 else white6).append((target, comment))

        # Dynamic admin hostnames (DDNS) are resolved every run and pushed into
        # the same kernel set, so a changing admin IP never loses access.
        for address in getattr(self.guard, "ddns_addresses", []):
            try:
                net = ipaddress.ip_network(address, strict=False)
            except ValueError:
                continue
            entry = (str(net), "logwall admin whitelist (ddns)")
            target_list = white4 if net.version == 4 else white6
            if entry not in target_list:
                target_list.append(entry)

        emit_set(self.sets["SET_WHITE4"], self.sets["SET_WHITE4"] + "_TMP", "inet", white4)
        emit_set(self.sets["SET_BLACK4"], self.sets["SET_BLACK4"] + "_TMP", "inet", black4)

        # The v6 sets exist only on a host with global IPv6, because that is the
        # condition under which the Bash layer creates them. Emitting a `swap`
        # for a set that was never created aborts the whole restore — and with it
        # the v4 blocklist that was perfectly fine.
        if self.ipv6_enabled:
            emit_set(self.sets["SET_WHITE6"], self.sets["SET_WHITE6"] + "_TMP", "inet6", white6)
            emit_set(self.sets["SET_BLACK6"], self.sets["SET_BLACK6"] + "_TMP", "inet6", black6)
        elif black6 or white6:
            print(f"[IPV6_SKIPPED] {len(black6)} blacklist and {len(white6)} whitelist "
                  f"IPv6 entries were not loaded: this host has no global IPv6, so the "
                  f"v6 sets do not exist.", file=sys.stderr)

        _atomic_write(path, "\n".join(lines) + "\n")

        total = len(black4) + len(black6)
        if self.maxelem and total > self.maxelem * self.capacity_alert / 100:
            print(f"[SET_CAPACITY] Blacklist holds {total} entries, above "
                  f"{self.capacity_alert}% of IPSET_MAXELEM={self.maxelem}. "
                  f"Run `logwall firewall review` to aggregate ranges.", file=sys.stderr)

        return total, len(white4) + len(white6)

    def _csf_enforced(self):
        """Addresses CSF already enforces, read straight from csf.deny."""
        path = get_path(self.config, "CSF_DENY", "/etc/csf/csf.deny")
        known = set()
        if not os.path.isfile(path):
            return known
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    body = line.split("#", 1)[0].strip()
                    if not body:
                        continue
                    # csf.deny lines are "ip" or "ip # comment"; ports use "tcp|in|..".
                    token = body.split()[0]
                    if "|" not in token:
                        known.add(token)
        except OSError:
            pass
        return known

    def emit_csf_list(self, entries, path):
        """
        Writes 'ip<TAB>reason' for every blacklist entry CSF is not enforcing yet.

        Deltas keep the steady state free: each address costs one `csf -d`, and
        that is a fresh Perl process, so re-sending the whole list every cycle is
        not an option.

        But "added in THIS run" alone was not enough, and the gap was silent. A
        list seeded by hand — or carried over from a retired blocker, which is
        exactly what a migration produces — would sit in blacklist_ips.txt
        forever without a single address reaching CSF, while the run reported
        success. Measuring the delta against csf.deny itself closes that: once
        the two agree it costs one file read and emits nothing.

        The backlog is capped per run so a migration of thousands does not hang a
        single cycle on thousands of Perl processes; it drains over a few cycles.
        """
        already = self._csf_enforced()
        limit = get_int(self.config, "CSF_RESYNC_MAX_PER_RUN", 200)

        lines, seen = [], set()

        def queue(entry):
            if entry.target in already or entry.target in seen:
                return False
            seen.add(entry.target)
            lines.append("{}\t{}".format(entry.target,
                                         sanitize_comment(entry.reason)))
            return True

        for entry in self.added:
            queue(entry)

        backlog = [e for e in sorted(entries.values(), key=lambda e: e.target)
                   if e.target not in already and e.target not in seen]
        for entry in backlog[:max(0, limit - len(lines))]:
            queue(entry)

        remaining = len(backlog) - max(0, min(len(backlog), limit - len(self.added)))
        if backlog:
            print(f"[CSF_RESYNC] {len(backlog)} blacklist entry/entries are not in "
                  f"csf.deny yet; pushing up to {limit} this run.", file=sys.stderr)
            if remaining > 0:
                print(f"[CSF_RESYNC] {remaining} will follow on the next cycles.",
                      file=sys.stderr)

        _atomic_write(path, "\n".join(lines) + ("\n" if lines else ""))
        return len(lines)

    # ----------------------------------------------------------------- reports
    def report(self, entries, dry_run):
        prefix = "[DRY-RUN] " if dry_run else ""
        for entry in self.added:
            print(f"{prefix}[BLOCK] {entry.target} ({entry.tier}) — {entry.reason}")
        for target in self.expired:
            print(f"{prefix}[EXPIRED] {target} — TEMP block elapsed, released")
        for target in self.escalated:
            print(f"{prefix}[ESCALATE] {target} — repeat offender promoted to PERMANENT")

        ddns = getattr(self.guard, "ddns", None)
        if ddns is not None:
            for line in ddns.report_lines():
                print(f"{prefix}{line}", file=sys.stderr)

        flags = self.audit.health_flags()
        for reason, count in sorted(flags.get("GUARD_STATS", {}).items()):
            print(f"{prefix}[GUARD] {reason}: {count} candidate(s) refused")
        if flags.get("PARSE_FAIL"):
            print(f"{prefix}[PARSE_FAIL] {', '.join(flags['PARSE_FAIL'])}", file=sys.stderr)
        if flags.get("CDN_NO_REALIP"):
            print(f"{prefix}[CDN_NO_REALIP] {', '.join(flags['CDN_NO_REALIP'])}",
                  file=sys.stderr)
        if flags.get("LOG_NOT_FOUND"):
            print(f"{prefix}[LOG_NOT_FOUND] No access log discovered.", file=sys.stderr)

        print(f"{prefix}[SUMMARY] new={len(self.added)} expired={len(self.expired)} "
              f"escalated={len(self.escalated)} total={len(entries)}")


def _atomic_write(path, content):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp, path)


def main():
    parser = argparse.ArgumentParser(description="logwall apply engine")
    parser.add_argument("--force-breaker", action="store_true",
                        help="proceed even when the circuit breaker trips")
    parser.add_argument("--dry-run", action="store_true",
                        help="show what would change without writing anything")
    parser.add_argument("--emit-ipset", metavar="PATH",
                        help="write an ipset restore script to PATH")
    parser.add_argument("--emit-csf", metavar="PATH",
                        help="write newly blocked entries as 'ip<TAB>reason' for CSF")
    args = parser.parse_args()

    engine = ApplyEngine()
    code, entries = engine.execute(force_breaker=args.force_breaker,
                                   dry_run=args.dry_run)

    if not args.dry_run:
        if args.emit_ipset:
            engine.emit_ipset_script(entries, args.emit_ipset)
        if args.emit_csf:
            engine.emit_csf_list(entries, args.emit_csf)

    return code


if __name__ == "__main__":
    sys.exit(main())
