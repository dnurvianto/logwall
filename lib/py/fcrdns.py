#!/usr/bin/env python3
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: lib/py/fcrdns.py
# Purpose: Forward-confirmed reverse DNS. Decides whether an address really
#          belongs to a search engine that should never be blocked.
# Reference: docs/DESIGN.md §16 (FCrDNS verification, rdns_cache.json)
# ==============================================================================
"""
Verifies a crawler by asking the internet, not by trusting a list.

docs/DESIGN.md has promised this since 1.0 and no code ever implemented it. The
gap was found the hard way: on a host with 1,336 blocked addresses, 38 of them
were Bingbot, and the range guard added in rc13 escalated that into blocking two
whole /24s of `msnbot-*.search.msn.com`. Nothing in the product had ever checked.

Two directions are required, and one alone is worthless:

    PTR      40.77.167.123  ->  msnbot-40-77-167-123.search.msn.com
    forward  that hostname  ->  must resolve back to 40.77.167.123

The PTR record is published by whoever owns the address, so anyone can claim to be
`msnbot-*.search.msn.com`. Only Microsoft can make that name resolve forward to an
address they control. That is the whole reason a suffix list of domains is safe
here while a list of IP ranges is not: the domain list says who we would believe,
and the forward lookup is what proves it.

DNS is on the network, so nothing here may block a run for long or fail loudly.
An unverifiable address is simply not protected — verification only ever ADDS a
reason to spare, never a reason to block.
"""

import json
import os
import socket
import time

# Domains whose forward-confirmed names identify a crawler worth sparing.
#
# Matched as a suffix on a dot boundary, so `evil-msn.com` cannot pass as
# `search.msn.com` and `notgoogle.com` cannot pass as `google.com`.
CRAWLER_DOMAINS = (
    "googlebot.com", "google.com", "googleusercontent.com",
    "search.msn.com", "msn.com", "bing.com",
    "duckduckgo.com",
    "yandex.com", "yandex.ru", "yandex.net",
    "baidu.com", "baidu.jp",
    "applebot.apple.com", "apple.com",
    "facebook.com", "fbsv.net",
    "ahrefs.com", "semrush.com",
    "archive.org",
    "linkedin.com",
    "petalsearch.com", "aspiegel.com",
)


def _matches_crawler_domain(hostname):
    """Suffix match on a dot boundary. `evil-google.com` must not pass."""
    name = (hostname or "").strip().rstrip(".").lower()
    if not name:
        return None
    for domain in CRAWLER_DOMAINS:
        if name == domain or name.endswith("." + domain):
            return domain
    return None


class FCrDNS:
    """
    Forward-confirmed reverse DNS with an on-disk cache.

    Verification is only ever asked about a candidate that is otherwise ABOUT to be
    blocked, never per request. A busy host sees hundreds of thousands of requests
    and a handful of candidates, so the lookup budget is spent where it changes a
    decision.
    """

    def __init__(self, state_dir, enabled=True, timeout=3, cache_days=30,
                 max_lookups=400, max_seconds=10, resolver=None):
        self.enabled = enabled
        # Two budgets, and the clock is the one that matters.
        #
        # A count alone is the wrong instrument: it has to be tuned against a
        # latency nobody knows in advance. Measured on one host with a healthy
        # resolver, 0.06s per lookup — a cap of 50 there left a 1,325-entry
        # blacklist draining over 27 cycles for no reason, while on a host whose
        # resolver had stopped answering the same 50 would have cost 150 seconds.
        #
        # A time budget needs no tuning: fast DNS spends it on hundreds of lookups,
        # a dead resolver spends it on three and stops. The count stays as a second
        # ceiling so a very fast resolver cannot be walked indefinitely.
        self.max_lookups = max(0, int(max_lookups))
        self.max_seconds = max(1, int(max_seconds))
        # Started at the first LOOKUP, not at construction. Getting that wrong cost
        # an evening: IPGuard is built before the log parse, so on a busy host the
        # ten seconds were spent reading logs and the budget was already gone by the
        # time anything asked a question. The symptom was a run that managed two
        # lookups and looked, from the outside, like DNS being slow.
        self.started = None
        self.timeout = max(1, int(timeout))
        self.cache_ttl = max(1, int(cache_days)) * 86400
        self.path = os.path.join(state_dir, "rdns_cache.json")
        self.state_dir = state_dir
        self.lookups = 0
        self.failures = 0
        self.exhausted = False
        # Injectable so the suite can exercise every branch without touching DNS.
        # A test that needs the network is a test that will be skipped.
        self._resolver = resolver or _system_resolver
        self.cache = self._load()

    # ------------------------------------------------------------------ cache
    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return {}
        if not isinstance(data, dict):
            return {}
        now = int(time.time())
        fresh = {}
        for key, record in data.items():
            if not isinstance(record, dict):
                continue
            stamp = record.get("ts", 0)
            try:
                if now - int(stamp) < self.cache_ttl:
                    fresh[key] = record
            except (TypeError, ValueError):
                continue
        return fresh

    def save(self):
        if not self.state_dir:
            return
        try:
            os.makedirs(self.state_dir, exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(self.cache, handle)
            os.replace(tmp, self.path)
        except OSError:
            pass

    # ----------------------------------------------------------- verification
    def verify(self, ip_str):
        """
        Returns (verified, hostname). `verified` means both directions agreed AND
        the name belongs to a domain in CRAWLER_DOMAINS.

        A DNS failure returns (False, None) and is cached only briefly by being
        recorded as a failure, so a transient outage cannot pin a real crawler into
        the unverified state for thirty days.
        """
        if not self.enabled:
            return False, None

        key = str(ip_str)
        record = self.cache.get(key)
        if record is not None:
            return bool(record.get("ok")), record.get("host")

        if self.started is None:
            self.started = time.time()

        if (self.lookups >= self.max_lookups
                or time.time() - self.started >= self.max_seconds):
            self.exhausted = True
            return False, None

        hostname, addresses, failed = self._resolver(key, self.timeout)
        self.lookups += 1
        if failed:
            self.failures += 1
            # Not cached: a DNS outage must not decide anything for a month.
            return False, None

        domain = _matches_crawler_domain(hostname)
        confirmed = bool(domain) and key in addresses
        self.cache[key] = {"ok": confirmed, "host": hostname,
                           "ts": int(time.time())}
        return confirmed, hostname

    def verify_any(self, ip_list):
        """
        (verified, ip, hostname) for the first member that verifies, else
        (False, None, None).

        Used before blocking a RANGE. A range cannot be verified by enumerating it
        — 256 lookups per candidate is not a budget — but the addresses that put it
        on the list are known, and one confirmed crawler among them is enough to
        prove the range is not an attacker's.
        """
        for ip_str in ip_list:
            ok, hostname = self.verify(ip_str)
            if ok:
                return True, ip_str, hostname
        return False, None, None


def _system_resolver(ip_str, timeout):
    """
    Returns (hostname, addresses, failed).

    `failed` distinguishes "DNS said no such record" from "DNS did not answer".
    The first is an answer and may be cached; the second must not be.
    """
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        try:
            hostname = socket.gethostbyaddr(ip_str)[0]
        except socket.herror:
            return None, (), False          # no PTR: a real answer
        except (socket.gaierror, socket.timeout, OSError):
            return None, (), True           # resolver unreachable

        try:
            infos = socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            return hostname, (), False      # name does not resolve: an answer
        except (socket.timeout, OSError):
            return hostname, (), True

        addresses = set()
        for info in infos:
            sockaddr = info[4]
            if sockaddr:
                addresses.add(sockaddr[0])
        return hostname, addresses, False
    finally:
        socket.setdefaulttimeout(previous)
