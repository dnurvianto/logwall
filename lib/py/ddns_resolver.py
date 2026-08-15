#!/usr/bin/env python3
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: lib/py/ddns_resolver.py
# Purpose: Resolves the admin's dynamic hostnames (DuckDNS, No-IP, Dynu, a
#          Cloudflare-hosted record, ...) into whitelist addresses on every run.
#
# Fail-safe by design: a DNS outage must never remove an administrator's access.
# When resolution fails the last known good answer is reused, and the cache is
# only replaced by a successful lookup.
# Reference: docs/DESIGN.md §15.2 (Dynamic Whitelist / DDNS)
# ==============================================================================

import json
import os
import socket
import time

from config_loader import get_int, get_path

CACHE_FILENAME = "ddns_cache.json"


def load_hostnames(filepath):
    """Reads one hostname per line; blank lines and comments are ignored."""
    hosts = []
    if not filepath or not os.path.isfile(filepath):
        return hosts
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                hosts.append(line.split()[0])
    except OSError:
        pass
    return hosts


class DDNSResolver:
    def __init__(self, config=None):
        config = config or {}
        self.hosts_file = get_path(config, "WHITELIST_DYNAMIC_HOSTS",
                                   "/etc/logwall/whitelist_hosts.txt")
        state_dir = get_path(config, "STATE_DIR", "/opt/logwall/data/state")
        self.cache_file = os.path.join(state_dir, CACHE_FILENAME)
        self.timeout = get_int(config, "EXT_CMD_TIMEOUT_SEC", 15)
        self.cache = self._load_cache()

        # Populated by resolve(); surfaced in reports so a silently stale entry
        # is visible rather than assumed fresh.
        self.stale_hosts = []
        self.failed_hosts = []

    def _load_cache(self):
        if os.path.isfile(self.cache_file):
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    return data
            except (OSError, ValueError):
                pass
        return {}

    def _save_cache(self):
        directory = os.path.dirname(self.cache_file)
        if directory:
            os.makedirs(directory, exist_ok=True)
        tmp = self.cache_file + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, indent=2)
            os.replace(tmp, self.cache_file)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def _lookup(self, hostname):
        """Returns every A/AAAA address for the hostname, or [] on failure."""
        previous = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.timeout)
        try:
            infos = socket.getaddrinfo(hostname, None, 0, socket.SOCK_STREAM)
        except (socket.gaierror, socket.timeout, OSError, UnicodeError):
            return []
        finally:
            socket.setdefaulttimeout(previous)

        addresses = []
        for info in infos:
            address = info[4][0]
            if address not in addresses:
                addresses.append(address)
        return addresses

    def resolve(self):
        """
        Returns the flat list of addresses for every configured hostname.

        A hostname that cannot be resolved falls back to its cached answer. Only
        a hostname that has never resolved contributes nothing.
        """
        hostnames = load_hostnames(self.hosts_file)
        if not hostnames:
            return []

        now = int(time.time())
        resolved = []
        self.stale_hosts = []
        self.failed_hosts = []

        for hostname in hostnames:
            addresses = self._lookup(hostname)

            if addresses:
                self.cache[hostname] = {"ips": addresses, "updated": now}
                resolved.extend(addresses)
                continue

            cached = self.cache.get(hostname, {})
            cached_ips = cached.get("ips", [])
            if cached_ips:
                # Keeping the stale answer is deliberate: dropping it would
                # revoke the admin's whitelist because of a DNS hiccup.
                self.stale_hosts.append(hostname)
                resolved.extend(cached_ips)
            else:
                self.failed_hosts.append(hostname)

        self._save_cache()

        unique = []
        for address in resolved:
            if address not in unique:
                unique.append(address)
        return unique

    def report_lines(self):
        lines = []
        for hostname in self.stale_hosts:
            age = int(time.time()) - self.cache.get(hostname, {}).get("updated", 0)
            lines.append(f"[DDNS_STALE] {hostname} did not resolve; using the cached "
                         f"answer from {age // 60} minute(s) ago.")
        for hostname in self.failed_hosts:
            lines.append(f"[DDNS_FAILED] {hostname} has never resolved; it grants no access.")
        return lines
