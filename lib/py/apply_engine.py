#!/usr/bin/env python3
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: lib/py/apply_engine.py
# Purpose: Turns audited candidates into blacklist entries. Owns the escalation
#          ladder (TEMP -> PERMANENT), deduplication, and the generation of an
#          atomic `ipset restore` script for the Bash layer.
# Reference: docs/DESIGN.md §7 (apply), §12 (Escalation)
# ==============================================================================

import argparse
import datetime
import ipaddress
import json
import os
import re
import sys
import time

from audit_engine import (TIER_PERMANENT, TIER_TEMP, AuditEngine,
                          format_refusals, format_shares)
from config_loader import get_bool, get_int, get_path, load_config
from ip_guard import contained_in, load_networks

EXIT_OK = 0
EXIT_CONFIG = 2

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

# Every verdict name logwall can write into a csf.deny comment. Used to recognise
# our own entries there — never to guess at ownership. lfd's comments begin with a
# distinct `lfd:` prefix, so the two cannot be confused.
LOGWALL_VERDICTS = frozenset((
    "AuthBruteForce", "BruteForce", "CloudScraper", "GenericLoginBrute",
    "HighBandwidth", "IntentComposite", "PanelBruteForce", "PathBruteForce",
    "ReconScanner", "RotatingOffender", "Subnet6AuthBruteForce",
    "Subnet6CoordinatedAttack", "Subnet6Flood", "Subnet6HighBandwidth",
    "SubnetAuthBruteForce", "SubnetCoordinatedAttack", "SubnetFlood",
    "SubnetHighBandwidth", "ToolSignature", "WebshellHunter", "XmlRpcExploit",
))


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
        self.superseded = []
        self.released = []

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
    def execute(self, dry_run=False):
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

        # 3. Every entry in `pending` came from a detection signal and has
        #    already passed every guard inside evaluate_candidates(). There is no
        #    other path into this list, so a large batch means a large number of
        #    offenders — not a fault. Capping it would only ever mean refusing to
        #    act on the tool's own findings.
        #
        #    A circuit breaker used to sit here and abort the whole run above
        #    MAX_NEW_BLOCKS_PER_RUN. It fired twice in production, both times on
        #    genuine abuse, blocking nothing while the attack continued — and it
        #    committed state as it went, so the same candidates returned two
        #    minutes later and tripped it again, silently, until a human noticed.
        #    Distorted input is now caught at the source instead: see
        #    LogParserEngine._detect_catchup().
        for entry in pending:
            entries[entry.target] = entry
            history.setdefault(entry.target, {})["strike"] = entry.strike
            history[entry.target]["last"] = now
            # The signal class, kept so a range can later be judged on whether its
            # offenders were one actor or many unrelated tenants. See
            # _rotating_ranges().
            history[entry.target]["class"] = entry.reason.split("|", 1)[0].strip()
            self.added.append(entry)

        # 3a. Recover the signal class for records written before it was stored.
        #
        # Requiring a class was right — a range must not qualify on evidence that
        # cannot be checked — but on first deployment it made the rule inert for
        # days while the history refilled, and the evidence was sitting in the
        # blacklist all along: every entry carries the reason that put it there.
        for target, entry in entries.items():
            record = history.get(target)
            if isinstance(record, dict) and not record.get("class"):
                record["class"] = entry.reason.split("|", 1)[0].strip()

        # 3b. Ranges whose offenders keep arriving from fresh addresses.
        for target, meta in self._rotating_ranges(history, entries).items():
            entry = BlacklistEntry(target, date_str, meta["reason"], meta["tier"],
                                   1, now + self.temp_hours * 3600
                                   if meta["tier"] == TIER_TEMP else None)
            entries[target] = entry
            self.added.append(entry)
            history.setdefault(target, {})["strike"] = 1
            history[target]["last"] = now
            history[target]["class"] = meta["class"]

        # 3c. Release entries a guard would refuse today.
        #
        # Guards only ever ran on CANDIDATES, so an entry blocked before a guard
        # existed — or before a whitelist grew, or before FCrDNS was implemented at
        # all — stayed blocked forever with nothing left to review it. Measured on a
        # production host: 38 Bingbot addresses, blocked as CloudScraper under an
        # earlier release, still enforced.
        #
        # Cheap in the steady state: the non-DNS guards are list lookups, and FCrDNS
        # has both a per-run budget and a thirty-day cache, so a large legacy list
        # drains over a few cycles instead of stalling one.
        self.released = self._release_now_protected(entries)

        # 4. Drop entries a wider accepted range already covers.
        #
        # evaluate_candidates() removes members covered by a range, but only among
        # the candidates of a single run. Nothing ever revisited an entry that was
        # ALREADY blocked when its covering range arrived later. Measured on a
        # production host: 70 individual /64 entries sitting under one accepted
        # /56 — 69% of that blacklist was redundant. Those happened to be TEMP and
        # aged out; on a host where they are PERMANENT the list grows forever and
        # eats ipset capacity for nothing.
        #
        # In CSF mode it is worse than wasted space: every redundant member is also
        # a permanent line in another agent's config file, which that agent has no
        # reason to ever clean up.
        self.superseded = self._prune_superseded(entries)

        if dry_run:
            self.report(entries, dry_run=True)
            return EXIT_OK, entries

        self.write_blacklist(entries)
        self.audit.commit_state()
        self.save_history(history)
        self.record_events(now)
        self.save_run_flags(now)
        self.guard.save_verification_cache()
        self.report(entries, dry_run=False)
        return EXIT_OK, entries

    def save_run_flags(self, now):
        """
        Persists this run's diagnostics so the daily report can state them.

        Everything below used to exist only on stderr, which the cron line logwall
        installs discards. PROFILING_OFF fired on every single run of one host for
        a day while its report said `[FLAG] none` — the report was not wrong, it
        simply had no way to know.
        """
        flags = self.audit.health_flags()
        notable = {}
        for key in ("IDENTITY_UNTRUSTED", "PROFILING_OFF", "CATCHUP_RUN",
                    "SETTING_RENAMED", "LOG_NOT_FOUND"):
            if flags.get(key):
                notable[key] = flags[key] if isinstance(flags[key], str) else True
        for key in ("CDN_NO_REALIP", "PARSE_FAIL"):
            detail = format_shares(flags.get(key))
            if detail:
                notable[key] = detail
        if self.audit.refused:
            notable["GUARD_REFUSED"] = format_refusals(self.audit.refused)

        try:
            os.makedirs(self.state_dir, exist_ok=True)
            _atomic_write(os.path.join(self.state_dir, "last_run_flags.json"),
                          json.dumps({"ts": now, "flags": notable}, indent=2) + "\n")
        except OSError:
            pass

    def _release_now_protected(self, entries):
        """Removes entries the guards would refuse if proposed today."""
        if not get_bool(self.config, "REVALIDATE_BLACKLIST", True):
            return []

        released = []
        for target in sorted(entries):
            if "/" in target:
                # A range is judged by the stricter network rules, which refuse on
                # OVERLAP rather than membership — exactly what should happen if a
                # whitelist has since grown into it.
                refusal = self.guard.refusal_reason_network(
                    target, get_int(self.config, "MAX_BLOCK_PREFIX_V4", 24),
                    get_int(self.config, "MAX_BLOCK_PREFIX_V6", 56))
            else:
                refusal = self.guard.refusal_reason(target)
            if refusal:
                released.append((target, refusal))

        for target, _reason in released:
            entries.pop(target, None)
        return released

    def _rotating_ranges(self, history, entries):
        """
        Ranges that keep producing new offenders from fresh addresses.

        The escalation ladder counts strikes per ADDRESS, so an actor who simply
        uses a different address each time never reaches strike 2 and is met with a
        fresh TEMP block forever. Measured on a production host: one crawler had
        eight addresses in the offender history, seven of them TEMP and expiring,
        while two more addresses had already appeared in the log unblocked. logwall
        punished correctly every single time and learned nothing.

        The existing subnet rules cannot reach this. `SubnetCoordinatedAttack` wants
        simultaneous activity, and the per-interval rollup wants volume: that /24
        averaged 94 hits per interval against a threshold of 300, because the actor
        spread 68,000 requests across a day and eight addresses.

        Two conditions, and the second is what makes a range block safe:

          count  at least ROTATION_MIN_OFFENDERS distinct addresses in the range
                 have each independently tripped a signal, at any time
          class  all of them tripped the SAME signal

        The class condition separates one actor from one bad neighbourhood, and the
        distinction is not theoretical. On the same host:

            216.73.216.0/24   8 addresses, 8x CloudScraper       -> one actor
            103.253.27.0/24   4 addresses, XmlRpc x3 + BruteForce -> a hosting
                                                                   provider whose
                                                                   tenants are
                                                                   independently
                                                                   compromised

        Blocking the second range would punish every other customer of that host for
        four of them. Blocking the first is the only thing that stops the rotation.

        Tier follows the existing philosophy rather than inventing a new one: a range
        whose offenders were volume-class gets TEMP and can age out, one whose
        offenders showed intent gets PERMANENT.
        """
        if not get_bool(self.config, "ROTATION_GUARD", True):
            return {}

        minimum = get_int(self.config, "ROTATION_MIN_OFFENDERS", 4)
        v4_prefix = get_int(self.config, "ROTATION_PREFIX_V4", 24)
        v6_prefix = get_int(self.config, "ROTATION_PREFIX_V6", 64)

        groups = {}
        for target, record in history.items():
            if not isinstance(record, dict):
                continue
            signal = record.get("class")
            if not signal:
                # Written by a version that did not record the class. Counting it
                # would let a range qualify on evidence we cannot check.
                continue
            try:
                net = ipaddress.ip_network(target, strict=False)
            except ValueError:
                continue
            if net.num_addresses > 1:
                continue
            prefix = v4_prefix if net.version == 4 else v6_prefix
            try:
                key = str(ipaddress.ip_network(
                    "%s/%d" % (net.network_address, prefix), strict=False))
            except ValueError:
                continue
            groups.setdefault(key, {"members": set(), "classes": set()})
            groups[key]["members"].add(target)
            groups[key]["classes"].add(signal)

        volume_classes = {"CloudScraper", "HighBandwidth", "Subnet6Flood",
                          "SubnetFlood", "PathBruteForce"}
        proposed = {}
        for key, group in groups.items():
            if len(group["members"]) < minimum or len(group["classes"]) != 1:
                continue
            if key in entries:
                continue
            signal = next(iter(group["classes"]))

            # A range is not an attacker's just because several of its addresses
            # tripped the same rule — a search engine crawls from many addresses in
            # one /24 and trips volume rules doing it. Verified on a production
            # host, where this guard proposed two /24s of msnbot-*.search.msn.com.
            #
            # The members that put the range on this list are exactly the addresses
            # worth asking about, which is what makes verifying a range affordable:
            # four lookups, not two hundred and fifty-six.
            ok, member, hostname = self.guard.verify_crawler_any(
                sorted(group["members"]))
            if ok:
                self.audit.refused[key] = "VERIFIED_CRAWLER (%s via %s)" % (
                    hostname, member)
                continue

            refusal = self.guard.refusal_reason_network(
                key, v4_prefix, get_int(self.config, "MAX_BLOCK_PREFIX_V6", 56))
            if refusal:
                self.audit.refused[key] = refusal
                continue
            proposed[key] = {
                "reason": "RotatingOffender | %d addresses, all %s"
                          % (len(group["members"]), signal),
                "tier": TIER_TEMP if signal in volume_classes else TIER_PERMANENT,
                "class": signal,
            }
        return proposed

    def _prune_superseded(self, entries):
        """
        Removes entries wholly contained in another, wider entry.

        Returns the list of removed targets so the caller can report them and, in
        CSF mode, release them from csf.deny. Silence would be the wrong choice
        here: an operator who finds seventy lines gone and no explanation has been
        given a reason to distrust the tool.

        A PERMANENT entry is never dropped in favour of a TEMP one — the wider
        block would expire and leave the member unprotected.
        """
        if not get_bool(self.config, "PRUNE_SUPERSEDED", True):
            return []

        nets = {}
        for target in entries:
            try:
                nets[target] = ipaddress.ip_network(target, strict=False)
            except ValueError:
                continue

        ranges = [(t, n) for t, n in nets.items() if n.num_addresses > 1]
        if not ranges:
            return []

        removed = []
        for target, net in nets.items():
            for parent_target, parent in ranges:
                if parent_target == target or parent.version != net.version:
                    continue
                if net.num_addresses >= parent.num_addresses:
                    continue
                if not contained_in(net, parent):
                    continue
                if (entries[target].tier == TIER_PERMANENT
                        and entries[parent_target].tier == TIER_TEMP):
                    continue
                removed.append((target, parent_target))
                break

        for target, _parent in removed:
            entries.pop(target, None)
        return removed

    # ------------------------------------------------------------- event record
    def record_events(self, now):
        """
        Appends what this run actually did to events.jsonl.

        The daily report used to count blacklist rows carrying today's date, which
        cannot work: a TEMP block created and expired between two reports leaves no
        row, so the one thing the report exists to state was unstateable. Counting
        events instead makes a released block still count as having happened.
        """
        path = os.path.join(self.state_dir, "events.jsonl")
        rows = []
        for entry in self.added:
            rows.append({"ts": now, "action": "BLOCK", "target": entry.target,
                         "tier": entry.tier, "reason": entry.reason})
        for target in self.expired:
            rows.append({"ts": now, "action": "EXPIRED", "target": target})
        for target in self.escalated:
            rows.append({"ts": now, "action": "ESCALATE", "target": target})
        for target, parent in self.superseded:
            rows.append({"ts": now, "action": "SUPERSEDED", "target": target,
                         "reason": "covered by " + parent})
        for target, reason in self.released:
            rows.append({"ts": now, "action": "RELEASED", "target": target,
                         "reason": reason})
        if not rows:
            return

        try:
            os.makedirs(self.state_dir, exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                for row in rows:
                    f.write(json.dumps(row, sort_keys=True) + "\n")
        except OSError:
            return

        self._trim_events(path)

    def _trim_events(self, path):
        """Keeps the file bounded. A blocker runs 720 times a day, for years."""
        keep = get_int(self.config, "EVENT_LOG_MAX_LINES", 20000)
        try:
            if os.path.getsize(path) < keep * 120:
                return
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            if len(lines) <= keep:
                return
            _atomic_write(path, "".join(lines[-keep:]))
        except OSError:
            pass

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

    def _pushed_record_path(self):
        return os.path.join(self.state_dir, "csf_pushed.json")

    def load_pushed_record(self):
        """
        Addresses logwall pushed to CSF, so it knows which are its to release.

        On the first run the file does not exist, and a record seeded as empty can
        never recover entries that were already pushed — three of them sat orphaned
        in csf.deny on the host this was verified against. So the record is seeded
        from csf.deny itself, matching only entries whose comment carries one of
        logwall's own verdict names.

        That is recognising our own output, not guessing at ownership. lfd writes a
        distinct prefix and the two are never confusable:

            78.153.140.39 # ReconScanner - Sat Aug 15 22:58:23 2026        <- ours
            185.x.x.x # lfd: (PERMBLOCK) ... has had more than ...         <- not
        """
        try:
            with open(self._pushed_record_path(), "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return set(str(item) for item in data)
        except (OSError, ValueError):
            pass
        return self._seed_pushed_from_csf()

    def _seed_pushed_from_csf(self):
        """Entries in csf.deny that carry a logwall verdict name in their comment."""
        path = get_path(self.config, "CSF_DENY", "/etc/csf/csf.deny")
        found = set()
        if not os.path.isfile(path):
            return found
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    body, _, comment = line.partition("#")
                    target = body.strip()
                    if not target or "|" in target:
                        continue
                    label = comment.strip().split("|", 1)[0].split("-", 1)[0].strip()
                    if label in LOGWALL_VERDICTS:
                        found.add(target.split()[0])
        except OSError:
            pass
        return found

    def emit_csf_release(self, path, entries=None):
        """
        Writes the addresses CSF should stop blocking, one per line.

        Without this, `csf -d` was a one-way door: logwall dropped an expired TEMP
        entry from its own blacklist and csf.deny kept it forever, which quietly
        turned every temporary block on a CSF host into a permanent one. An
        escalation ladder only means something if the bottom rung can be stepped
        off. Redundant members removed by _prune_superseded() go the same way.

        Derived from a durable record of what logwall has pushed, NOT from this
        run's deltas. The first version used the deltas and lost releases in
        silence, which showed up the first time it met a real host: three members
        pruned during a run with ENFORCE=0 left the blacklist, while the release
        list written by that run was overwritten by the next one before anything
        called `csf -dr`. Three entries stayed behind in another agent's config with
        nothing left tracking them.

        Diffing a record makes a missed release self-heal on the following run,
        which is how the push direction has always worked against csf.deny.
        Entries lfd added on its own never enter the record, so they are never
        touched.
        """
        current = set(entries or {})
        pushed = self.load_pushed_record()

        targets = sorted(pushed - current)
        _atomic_write(path, "\n".join(targets) + ("\n" if targets else ""))

        # The record tracks the blacklist, so a release only has to succeed once.
        _atomic_write(self._pushed_record_path(),
                      json.dumps(sorted(current)) + "\n")
        return len(targets)

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
        for target, parent in self.superseded:
            print(f"{prefix}[SUPERSEDED] {target} — already covered by {parent}, "
                  f"removed as redundant")
        for target, reason in self.released:
            print(f"{prefix}[RELEASED] {target} — a guard refuses this today "
                  f"({reason}); removed")

        ddns = getattr(self.guard, "ddns", None)
        if ddns is not None:
            for line in ddns.report_lines():
                print(f"{prefix}{line}", file=sys.stderr)

        flags = self.audit.health_flags()
        for line in format_refusals(self.audit.refused):
            print(f"{prefix}[GUARD] {line}")
        for label, detail in sorted(format_shares(flags.get("PARSE_FAIL")).items()):
            print(f"{prefix}[PARSE_FAIL] {label} ({detail})", file=sys.stderr)
        for label, detail in sorted(format_shares(flags.get("CDN_NO_REALIP")).items()):
            print(f"{prefix}[CDN_NO_REALIP] {label} ({detail})", file=sys.stderr)
        if flags.get("LOG_NOT_FOUND"):
            print(f"{prefix}[LOG_NOT_FOUND] No access log discovered.", file=sys.stderr)
        if flags.get("IDENTITY_UNTRUSTED"):
            print(f"{prefix}{flags['IDENTITY_UNTRUSTED']}")
        if flags.get("CATCHUP_RUN"):
            print(f"{prefix}[CATCHUP_RUN] {flags['CATCHUP_RUN']}")
        if flags.get("SETTING_RENAMED"):
            print(f"{prefix}{flags['SETTING_RENAMED']}")

        print(f"{prefix}[SUMMARY] new={len(self.added)} expired={len(self.expired)} "
              f"escalated={len(self.escalated)} superseded={len(self.superseded)} "
              f"released={len(self.released)} total={len(entries)}")


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
    parser.add_argument("--dry-run", action="store_true",
                        help="show what would change without writing anything")
    parser.add_argument("--emit-ipset", metavar="PATH",
                        help="write an ipset restore script to PATH")
    parser.add_argument("--emit-csf", metavar="PATH",
                        help="write newly blocked entries as 'ip<TAB>reason' for CSF")
    parser.add_argument("--emit-csf-release", metavar="PATH",
                        help="write addresses CSF should stop blocking, one per line")
    args = parser.parse_args()

    engine = ApplyEngine()
    code, entries = engine.execute(dry_run=args.dry_run)

    if not args.dry_run:
        if args.emit_ipset:
            engine.emit_ipset_script(entries, args.emit_ipset)
        if args.emit_csf:
            engine.emit_csf_list(entries, args.emit_csf)
        if args.emit_csf_release:
            engine.emit_csf_release(args.emit_csf_release, entries)

    return code


if __name__ == "__main__":
    sys.exit(main())
