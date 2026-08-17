#!/usr/bin/env python3
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: lib/py/ip_guard.py
# Purpose: Single choke point that decides whether an IP is allowed to be blocked.
#          Implements CIDR-aware whitelist matching, bypass list, CDN edge
#          hard-guard, and infrastructure protection (loopback, RFC1918, the
#          server's own addresses and its default gateways).
# Reference: docs/DESIGN.md §7 (apply step 5), §8.F (CDN hard-guard), §15 (anti-lockout)
# ==============================================================================

import ipaddress
import os
import subprocess

from config_loader import get_bool, get_int, get_path

# Reasons an IP is refused for blocking. Reported verbatim so an operator can
# always tell WHY a candidate never turned into a block.
REFUSE_WHITELIST = "WHITELIST"
REFUSE_BYPASS = "BYPASS_LIST"
REFUSE_CDN = "CDN_GUARD_HIT"
REFUSE_LOCAL = "LOCAL_INFRA"
REFUSE_SELF = "SERVER_OWN_IP"
REFUSE_GATEWAY = "DEFAULT_GATEWAY"
REFUSE_PRIVATE = "PRIVATE_RANGE"
REFUSE_INVALID = "INVALID_IP"
REFUSE_TOO_WIDE = "RANGE_TOO_WIDE"


def load_networks(filepath):
    """Loads a file of IP/CIDR entries into ip_network objects (v4 and v6)."""
    networks = []
    if not filepath or not os.path.isfile(filepath):
        return networks

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                token = line.split()[0]
                try:
                    networks.append(ipaddress.ip_network(token, strict=False))
                except ValueError:
                    continue
    except OSError:
        pass
    return networks


def parse_ip(ip_str):
    """Validates and normalises an address. Returns None when unusable."""
    if not ip_str:
        return None
    token = str(ip_str).strip()

    # Strip a trailing port only when it is unambiguous (IPv4:port or [v6]:port).
    if token.startswith("[") and "]" in token:
        token = token[1:token.index("]")]
    elif token.count(":") == 1 and "." in token:
        token = token.split(":", 1)[0]

    try:
        return ipaddress.ip_address(token)
    except ValueError:
        return None


# Ranges that cannot be the SOURCE of a request arriving at a public server.
#
# Spelled out rather than using `is_private`, which in Python also covers the
# documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Those are
# unroutable too, but they are what every test suite, tutorial and example config
# uses, so treating them as evidence of a misconfiguration would raise the alarm
# in precisely the places people experiment.
#
# 100.64.0.0/10 (CGNAT) is also left out on purpose: it appears legitimately
# inside some provider and container networks, and a false accusation here
# suspends blocking for the whole host.
UNROUTABLE_SOURCES = tuple(ipaddress.ip_network(cidr) for cidr in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC 1918
    "127.0.0.0/8",                                     # loopback
    "169.254.0.0/16",                                  # link-local
    "0.0.0.0/8",                                       # "this network"
    "224.0.0.0/4", "255.255.255.255/32",               # multicast, broadcast
    "::1/128", "::/128",                               # loopback, unspecified
    "fc00::/7",                                        # unique local
    "fe80::/10",                                       # link-local
    "ff00::/8",                                        # multicast
))


def contained_in(net, parent):
    """
    True when `net` lies entirely inside `parent` — the stdlib's subnet_of test.

    Written out because that method arrived in Python 3.7 and preflight accepts
    3.6 — a claim the code has to keep. It did not: a host running 3.6 crashed on
    every apply with AttributeError, and because cron discarded stderr the failure
    was invisible for days. The run log added in rc13 surfaced it within minutes of
    being switched on.
    """
    if net.version != parent.version:
        return False
    return (parent.network_address <= net.network_address
            and net.broadcast_address <= parent.broadcast_address)


def is_unroutable_source(ip_str):
    """
    True when an address cannot be a client arriving over the public internet.

    Used as proof, not as a heuristic: a public web server is not reachable FROM
    10.0.0.5 or 127.0.0.1. If one of those is sitting in the client field of an
    access log, something upstream rewrote it from a forwarding header it should
    never have trusted — and once that is happening, no identity in that log can be
    relied upon, including the ones that look perfectly ordinary.

    Deliberately server-agnostic. The same misconfiguration is
    `useIpInProxyHeader 1` in LiteSpeed, `RemoteIPHeader` with no trusted-proxy
    list in Apache, `set_real_ip_from 0.0.0.0/0` in nginx, and `trust proxy: true`
    one layer up in Express. Enumerating directive names would always lag behind;
    the symptom is identical everywhere.

    Known limit, stated plainly: this catches the MISCONFIGURATION, not every
    exploitation of it. An attacker who forges a plausible public address is not
    detected here. It still earns its place because automated scanners routinely
    send 127.0.0.1 and 10.0.0.1 in forwarding headers, so on an affected host the
    evidence shows up within days — and one detection suspends blocking for the
    whole host, which covers the forged-public case too.
    """
    address = parse_ip(ip_str)
    if address is None:
        return False
    return any(address in network for network in UNROUTABLE_SOURCES
               if network.version == address.version)


def _run(cmd, timeout):
    """Runs an external command with a list argv (never shell=True)."""
    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            universal_newlines=True,
            timeout=timeout,
        )
        if res.returncode == 0:
            return res.stdout
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def discover_local_addresses(timeout=15):
    """Returns every address configured on this host."""
    addresses = set()
    out = _run(["ip", "-o", "addr", "show"], timeout)
    for line in out.splitlines():
        parts = line.split()
        for idx, token in enumerate(parts):
            if token in ("inet", "inet6") and idx + 1 < len(parts):
                candidate = parts[idx + 1].split("/")[0]
                ip_obj = parse_ip(candidate)
                if ip_obj:
                    addresses.add(ip_obj)
    return addresses


def discover_gateways(timeout=15):
    """Returns the default gateways for IPv4 and IPv6."""
    gateways = set()
    for family in ("-4", "-6"):
        out = _run(["ip", family, "route", "show", "default"], timeout)
        for line in out.splitlines():
            parts = line.split()
            if "via" in parts:
                idx = parts.index("via")
                if idx + 1 < len(parts):
                    ip_obj = parse_ip(parts[idx + 1])
                    if ip_obj:
                        gateways.add(ip_obj)
    return gateways


class IPGuard:
    """
    Decides whether a candidate IP may be blocked.

    `refusal_reason()` returns None when blocking is allowed, otherwise a short
    constant naming the protection that fired.
    """

    def __init__(self, config=None):
        config = config or {}
        self.config = config

        self.whitelist_nets = load_networks(
            get_path(config, "WHITELIST", "/etc/logwall/whitelist_ips.txt"))

        # Dynamic admin hostnames count as whitelist entries too, otherwise an
        # administrator on a changing IP could be blocked by their own tool.
        self.ddns_addresses = []
        try:
            from ddns_resolver import DDNSResolver
            self.ddns = DDNSResolver(config)
            self.ddns_addresses = self.ddns.resolve()
        except Exception:
            self.ddns = None

        for address in self.ddns_addresses:
            try:
                self.whitelist_nets.append(ipaddress.ip_network(address, strict=False))
            except ValueError:
                continue
        self.bypass_nets = load_networks(
            get_path(config, "SKIP_LIST", "/etc/logwall/bypass_rules.txt"))
        self.cdn_nets = load_networks(
            get_path(config, "CDN_NETS_FILE", "/etc/logwall/cdn_networks.txt"))

        # Googlebot fast-path cache is expressed as a config value, not a file.
        for token in str(config.get("GOOGLE_BOT_NETS", "") or "").replace(",", " ").split():
            try:
                self.bypass_nets.append(ipaddress.ip_network(token, strict=False))
            except ValueError:
                continue

        timeout = get_int(config, "EXT_CMD_TIMEOUT_SEC", 15)
        self.block_private = get_bool(config, "BLOCK_PRIVATE", False)
        self.local_addresses = discover_local_addresses(timeout)
        self.gateways = discover_gateways(timeout)

        self.stats = {}

    def _in(self, ip_obj, networks):
        for net in networks:
            if ip_obj.version == net.version and ip_obj in net:
                return True
        return False

    def is_cdn_edge_ip(self, ip_str):
        """Kept for callers that only need the CDN hard-guard verdict."""
        ip_obj = parse_ip(ip_str)
        if ip_obj is None:
            return False
        return self._in(ip_obj, self.cdn_nets)

    def refusal_reason(self, ip_str):
        ip_obj = parse_ip(ip_str)
        if ip_obj is None:
            return self._count(REFUSE_INVALID)

        # Hard-guard first: blocking a CDN edge takes the whole site down.
        if self._in(ip_obj, self.cdn_nets):
            return self._count(REFUSE_CDN)

        if self._in(ip_obj, self.whitelist_nets):
            return self._count(REFUSE_WHITELIST)

        if self._in(ip_obj, self.bypass_nets):
            return self._count(REFUSE_BYPASS)

        if ip_obj in self.local_addresses:
            return self._count(REFUSE_SELF)

        if ip_obj in self.gateways:
            return self._count(REFUSE_GATEWAY)

        if (ip_obj.is_loopback or ip_obj.is_link_local
                or ip_obj.is_multicast or ip_obj.is_reserved
                or ip_obj.is_unspecified):
            return self._count(REFUSE_LOCAL)

        if ip_obj.is_private and not self.block_private:
            return self._count(REFUSE_PRIVATE)

        return None

    def refusal_reason_network(self, cidr_str, max_width_v4=24, max_width_v6=64):
        """
        The same verdict for a whole range — with stricter rules, because a /24
        is 256 addresses at once.

        Membership is not enough here: a range must be refused if it OVERLAPS
        anything protected. A single whitelisted address inside a candidate /24
        makes the whole range unblockable, otherwise enforcing it would lock the
        operator out of their own server.
        """
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
        except ValueError:
            return self._count(REFUSE_INVALID)

        # A typo turning /24 into /8 would take out 16 million addresses.
        limit = max_width_v4 if net.version == 4 else max_width_v6
        if net.prefixlen < limit:
            return self._count(REFUSE_TOO_WIDE)

        for protected, reason in ((self.cdn_nets, REFUSE_CDN),
                                  (self.whitelist_nets, REFUSE_WHITELIST),
                                  (self.bypass_nets, REFUSE_BYPASS)):
            for other in protected:
                if net.version == other.version and net.overlaps(other):
                    return self._count(reason)

        for address in self.local_addresses:
            if address.version == net.version and address in net:
                return self._count(REFUSE_SELF)

        for gateway in self.gateways:
            if gateway.version == net.version and gateway in net:
                return self._count(REFUSE_GATEWAY)

        if (net.is_loopback or net.is_link_local or net.is_multicast
                or net.is_reserved or net.is_unspecified):
            return self._count(REFUSE_LOCAL)

        if net.is_private and not self.block_private:
            return self._count(REFUSE_PRIVATE)

        return None

    def may_block(self, ip_str):
        return self.refusal_reason(ip_str) is None

    def _count(self, reason):
        self.stats[reason] = self.stats.get(reason, 0) + 1
        return reason
