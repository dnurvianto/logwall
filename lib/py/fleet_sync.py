#!/usr/bin/env python3
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: lib/py/fleet_sync.py
# Purpose: Export and import threat intelligence across logwall-managed servers.
# Reference: docs/DESIGN.md §19 (Multi-Server Fleet Operations)
# ==============================================================================

import argparse
import datetime
import os
import sys

from config_loader import get_path, load_config
from ip_guard import IPGuard


class FleetSyncEngine:
    def __init__(self, config=None):
        self.config = config if config is not None else load_config()
        self.blacklist_file = get_path(self.config, "BLACKLIST",
                                       "/etc/logwall/blacklist_ips.txt")
        # Imported entries pass through exactly the same protections as locally
        # detected ones — a misconfigured peer must not be able to poison us.
        self.guard = IPGuard(self.config)

    def export_blacklist(self, min_hits=3):
        """Exports permanent blacklist entries for fleet distribution."""
        entries = []
        if os.path.isfile(self.blacklist_file):
            with open(self.blacklist_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split("#", 1)
                        ip = parts[0].strip()
                        meta = parts[1].strip() if len(parts) > 1 else "FleetExport"
                        entries.append(f"{ip}\t{meta}")
        return entries

    def import_blacklist(self, import_filepath, source_host="fleet_node"):
        """Imports threat intelligence entries from peer nodes after filtering."""
        if not os.path.isfile(import_filepath):
            print(f"[ERROR] Import file not found: {import_filepath}", file=sys.stderr)
            return 0

        existing_ips = set()
        if os.path.isfile(self.blacklist_file):
            with open(self.blacklist_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        existing_ips.add(line.split()[0])

        date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        imported_count = 0
        refused_count = 0
        duplicate_count = 0

        with open(import_filepath, "r", encoding="utf-8", errors="ignore") as f_in, \
             open(self.blacklist_file, "a", encoding="utf-8") as f_out:
            for line in f_in:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                ip = parts[0].strip()
                meta = parts[1].strip() if len(parts) > 1 else "FleetImport"

                # The blocklist is a hash:net set, so a range is as valid an entry
                # as a single address — but refusal_reason() parses single
                # addresses only and rejected every CIDR as INVALID_IP. A retired
                # blocker's range blocks were silently dropped on import.
                if "/" in ip:
                    refusal = self.guard.refusal_reason_network(ip)
                else:
                    refusal = self.guard.refusal_reason(ip)

                if refusal:
                    refused_count += 1
                    print(f"[SKIP] {ip} refused by {refusal}", file=sys.stderr)
                    continue

                if ip in existing_ips:
                    duplicate_count += 1
                    continue

                f_out.write(f"{ip}    # {date_str} | {meta} | via {source_host} | "
                            f"PERMANENT | strike=1 | expires=-\n")
                existing_ips.add(ip)
                imported_count += 1

        # Refusals go to stderr one by one, so a summary that reports only the
        # successes reads as a clean import even when entries were dropped. The
        # counts belong on the same line the operator actually checks.
        print(f"[SUMMARY] Imported {imported_count} blacklist entries from "
              f"{source_host}; {refused_count} refused, {duplicate_count} already present.")
        if refused_count:
            print(f"[SUMMARY] {refused_count} entry/entries did NOT make it — "
                  f"review the [SKIP] lines above before assuming the list is complete.",
                  file=sys.stderr)
        return imported_count


def main():
    parser = argparse.ArgumentParser(description="logwall fleet blacklist sync")
    # `add_subparsers(required=...)` only exists from Python 3.7; AlmaLinux 8
    # ships 3.6.8, so the requirement is enforced by hand instead.
    sub = parser.add_subparsers(dest="mode")

    exporter = sub.add_parser("export")
    exporter.add_argument("--min-hits", type=int, default=3)

    importer = sub.add_parser("import")
    importer.add_argument("file")
    importer.add_argument("--source", default="fleet_node")

    args = parser.parse_args()
    if not args.mode:
        parser.error("a subcommand is required: export | import")

    engine = FleetSyncEngine()

    if args.mode == "export":
        for row in engine.export_blacklist(min_hits=args.min_hits):
            print(row)
        return 0

    return 0 if engine.import_blacklist(args.file, args.source) >= 0 else 1


if __name__ == "__main__":
    sys.exit(main())
