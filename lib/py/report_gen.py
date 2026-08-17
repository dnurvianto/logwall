#!/usr/bin/env python3
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: lib/py/report_gen.py
# Purpose: Daily operational report. Always states the health flags, including
#          the ones that mean detection is NOT working, so a silently broken
#          installation cannot masquerade as a quiet one.
# Reference: docs/DESIGN.md §9 (Logging & Reports), §15.6 (Heartbeat)
# ==============================================================================

import datetime
import json
import os
import sys
import time

from config_loader import get_bool, get_int, get_path, load_config

TIER_TEMP = "TEMP"


class ReportGenerator:
    def __init__(self, config=None):
        self.config = config if config is not None else load_config()
        self.report_dir = get_path(self.config, "REPORT_DIR", "/var/log/logwall")
        self.blacklist_file = get_path(self.config, "BLACKLIST",
                                       "/etc/logwall/blacklist_ips.txt")
        self.whitelist_file = get_path(self.config, "WHITELIST",
                                       "/etc/logwall/whitelist_ips.txt")
        self.state_dir = get_path(self.config, "STATE_DIR", "/opt/logwall/data/state")
        self.retention_days = get_int(self.config, "REPORT_RETENTION_DAYS", 30)

    def _entries(self, filepath):
        rows = []
        if not os.path.isfile(filepath):
            return rows
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        rows.append(line)
        except OSError:
            pass
        return rows

    def _catchup(self):
        """Reason string when the last completed run was a catch-up, else None."""
        path = os.path.join(self.state_dir, "run_meta.json")
        if not os.path.isfile(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or not data.get("catchup"):
            return None
        return str(data.get("catchup_reason") or "volume rules were suspended")

    def _selftest(self):
        """Last recorded selftest result: (timestamp, failures, labels).

        The scheduled selftest writes this unconditionally, precisely because its
        console output is discarded by cron. Reading it here is what puts drift
        findings in front of an operator instead of leaving them on the floor.
        """
        path = os.path.join(self.state_dir, "selftest.last")
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                raw = f.readline().strip()
        except OSError:
            return None
        parts = raw.split("|", 2)
        if len(parts) != 3:
            return None
        try:
            failures = int(parts[1])
        except ValueError:
            return None
        return parts[0], failures, parts[2]

    def _window_age(self):
        """Heartbeat: how long ago the traffic window was last updated."""
        path = os.path.join(self.state_dir, "window.json")
        if not os.path.isfile(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return int(time.time()) - int(data.get("updated", 0))
        except (OSError, ValueError, TypeError):
            return None

    def _events(self, start, end):
        """Events recorded between two epochs, as {action: count}."""
        path = os.path.join(self.state_dir, "events.jsonl")
        tally = {}
        if not os.path.isfile(path):
            return None
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                        stamp = int(row.get("ts", 0))
                    except (ValueError, TypeError):
                        continue
                    if start <= stamp < end:
                        action = str(row.get("action", "?"))
                        tally[action] = tally.get(action, 0) + 1
        except OSError:
            return None
        return tally

    def _run_flags(self):
        """Diagnostics persisted by the last apply run, or {}."""
        path = os.path.join(self.state_dir, "last_run_flags.json")
        if not os.path.isfile(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return {}
        flags = data.get("flags") if isinstance(data, dict) else None
        return flags if isinstance(flags, dict) else {}

    def _period(self, now=None):
        """
        The day this report is about, as (label, start_epoch, end_epoch).

        Cron runs the report at 00:05, so "today" is five minutes old and counting
        it produced a number that was structurally almost always zero. The day a
        report summarises is the one that just ended.
        """
        moment = datetime.datetime.fromtimestamp(now) if now else datetime.datetime.now()
        midnight = moment.replace(hour=0, minute=0, second=0, microsecond=0)
        boundary = get_int(self.config, "REPORT_PERIOD_CUTOFF_HOUR", 12)
        if moment.hour < boundary:
            start = midnight - datetime.timedelta(days=1)
            end = midnight
        else:
            start = midnight
            end = midnight + datetime.timedelta(days=1)
        return (start.strftime("%Y-%m-%d"),
                int(start.timestamp()), int(end.timestamp()))

    def collect(self, now=None):
        blacklist = self._entries(self.blacklist_file)
        whitelist = self._entries(self.whitelist_file)

        temp_count = sum(1 for row in blacklist if f"| {TIER_TEMP} " in row)
        today, start, end = self._period(now)

        # Counted from the event record, so a TEMP block that was created AND
        # released inside the period still counts as having happened. The old
        # count read blacklist rows, which cannot see a block that is gone.
        events = self._events(start, end)
        if events is None:
            today_count = sum(1 for row in blacklist if f"# {today}" in row)
            counted_from = "blacklist rows (no event record yet)"
        else:
            today_count = events.get("BLOCK", 0)
            counted_from = "event record"
        released = (events or {}).get("EXPIRED", 0)
        escalated = (events or {}).get("ESCALATE", 0)

        flags = []
        enforce = get_bool(self.config, "ENFORCE", False)
        if not enforce:
            flags.append("ENFORCE_OFF (observe only — nothing is being dropped)")

        age = self._window_age()
        if age is None:
            flags.append("NO_STATE (the blocker has never completed a run)")
        else:
            stale_factor = get_int(self.config, "HEARTBEAT_STALE_FACTOR", 2)
            if age > stale_factor * 600:
                flags.append(f"STALE (last successful run was {age // 60} minutes ago)")

        if not os.path.isfile(self.blacklist_file):
            flags.append("NO_BLACKLIST_FILE")

        # A catch-up run suspends the volume rules, so the report has to say so.
        # Its predecessor, the circuit breaker, announced itself only on stderr —
        # which cron discards — and appeared in no report at all, so a host could
        # decline to block anything for hours and still look healthy here.
        catchup = self._catchup()
        if catchup:
            flags.append(f"CATCHUP_RUN ({catchup})")

        # Diagnostics the last run emitted on stderr, which cron discards. Without
        # this the report can only see the four flags it computes itself, and a
        # host whose detection is switched off looks identical to a quiet one.
        for label, detail in sorted(self._run_flags().items()):
            if isinstance(detail, str):
                flags.append(detail if detail.startswith("[") else
                             "{} ({})".format(label, detail))
            elif isinstance(detail, dict):
                for path, share in sorted(detail.items()):
                    flags.append("{}: {} ({})".format(label, path, share))
            elif isinstance(detail, list):
                for line in detail:
                    flags.append("{}: {}".format(label, line))
            else:
                flags.append(str(label))

        selftest = self._selftest()
        if selftest is None:
            selftest_line = "never recorded"
            flags.append("NO_SELFTEST (drift monitoring has never run)")
        else:
            ts, failures, labels = selftest
            if failures:
                selftest_line = f"{ts} — {failures} FAILED"
                flags.append(f"SELFTEST_FAILED ({failures}): {labels}")
            else:
                selftest_line = f"{ts} — clean"

        return {
            "date": today,
            "whitelist": len(whitelist),
            "blacklist": len(blacklist),
            "blacklist_temp": temp_count,
            "blocked_today": today_count,
            "released": released,
            "escalated": escalated,
            "counted_from": counted_from,
            "enforcing": enforce,
            "selftest": selftest_line,
            "flags": flags,
        }

    def prune_reports(self):
        if not os.path.isdir(self.report_dir):
            return
        cutoff = time.time() - self.retention_days * 86400
        for name in os.listdir(self.report_dir):
            if not name.startswith("report-"):
                continue
            path = os.path.join(self.report_dir, name)
            try:
                if os.path.getmtime(path) < cutoff:
                    os.unlink(path)
            except OSError:
                continue

    def render(self, data):
        flag_block = "\n".join(f"[FLAG]   {flag}" for flag in data["flags"]) \
            or "[FLAG]   none"
        return (
            "==============================================================================\n"
            f"logwall Daily Summary — {data['date']}\n"
            "==============================================================================\n"
            f"[STATUS] Enforcement            : {'ON' if data['enforcing'] else 'OFF (observe only)'}\n"
            f"[STATUS] Whitelist entries      : {data['whitelist']}\n"
            f"[STATUS] Blacklist entries      : {data['blacklist']} "
            f"({data['blacklist_temp']} temporary)\n"
            f"[STATUS] Blocked on {data['date']}   : {data['blocked_today']} "
            f"(released {data.get('released', 0)}, "
            f"escalated {data.get('escalated', 0)})\n"
            f"[STATUS] Counted from           : {data.get('counted_from', 'unknown')}\n"
            f"[STATUS] Last selftest          : {data.get('selftest', 'unknown')}\n"
            f"{flag_block}\n"
            "==============================================================================\n"
        )

    def generate(self, as_json=False):
        data = self.collect()

        os.makedirs(self.report_dir, exist_ok=True)
        report_file = os.path.join(self.report_dir, f"report-{data['date']}.log")
        content = self.render(data)

        try:
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(content)
        except OSError as exc:
            print(f"[ERROR] Cannot write {report_file}: {exc}", file=sys.stderr)

        self.prune_reports()
        print(json.dumps(data, indent=2) if as_json else content)
        return 0


if __name__ == "__main__":
    sys.exit(ReportGenerator().generate(as_json="--json" in sys.argv))
