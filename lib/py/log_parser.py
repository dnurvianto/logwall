#!/usr/bin/env python3
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: lib/py/log_parser.py
# Purpose: Access log parser for Nginx/Apache combined, LiteSpeed, and Caddy JSON.
#          Reads only new bytes per run (inode + offset cursor) and files each
#          request into a per-interval bucket, so volume rules can be judged one
#          interval at a time while intent rules sum over a short sliding window.
#
# Memory: parsing streams. Entries are yielded one at a time and the raw line is
#         never retained, so peak memory stays flat no matter how large the
#         backlog is — a 2 GB host handles the same log volume as a 32 GB one.
# Reference: docs/DESIGN.md §8.G (Log Formats), §16.2 (Cursor + Window), §16.3 (Sanity)
# ==============================================================================

import calendar
import collections
import glob
import ipaddress
import json
import os
import re
import subprocess
import time

from config_loader import get_bool, get_int, get_path
from ip_guard import is_unroutable_source, parse_ip

# ------------------------------------------------------------------ fact vs claim
#
# The structural rule this codebase learned the hard way, three times in one day:
#
#   The PEER address is the only fact in a log line. It completed a TCP handshake,
#   so it cannot be forged. Everything else — user-agent, referer, forwarding
#   header, request path — is a CLAIM the client chose to make.
#
# A claim is perfectly good evidence of INTENT: `nuclei` in a user-agent is a
# statement about what the sender came to do, and acting on it is sound. What a
# claim can never be is IDENTITY, or evidence of good faith:
#
#   "nuclei"   -> claim of hostile intent   -> usable as a signal
#   "GrokBot"  -> claim of good faith       -> NOT usable, and it fooled us
#   XFF: 1.2.3.4 -> claim about identity    -> only from a peer we already trust
#   an address inside the URI/referer/UA    -> never anything at all
#
# Splitting the two into named fields is the point of these containers. The parser
# previously passed a bare ten-tuple, and it was exactly that anonymity which let a
# line-scanning "recover the real IP" helper treat the user-agent as an identity
# source for three releases without anyone noticing.
RawRequest = collections.namedtuple("RawRequest", (
    "peer",       # FACT: completed the handshake
    "uri",        # claim
    "size",       # server-side, trustworthy
    "status",     # server-side, trustworthy
    "forwarded",  # CLAIM: only read when the peer is a trusted CDN edge
    "is_asset",   # derived from a claim (uri)
    "script_ua",  # derived from a claim (user-agent)
    "method",     # claim
    "attack_ua",  # derived from a claim — intent, never identity
    "moment",     # claim, sanity-checked against the run clock
))

Request = collections.namedtuple("Request", (
    "ip",         # the identity this request is attributed to
    "uri",
    "size",
    "status",
    "resolved",   # False -> no trustworthy identity, do not attribute or punish
    "is_asset",
    "script_ua",
    "method",
    "attack_ua",
    "moment",
))

# The only metrics kept beyond the intent window, and the only ones profiling may
# read. Both describe what a client fetched, never what it attempted, so neither
# can be turned into a punishment by a rule that reaches for the wider window.
PROFILE_METRICS = frozenset(("pages", "assets"))

METRIC_KEYS = ("hits", "wp", "xmlrpc", "scan", "bw", "p401", "auth",
               "pages", "assets", "sua", "p404", "aua", "lpost",
               "src404", "ok")

# Static resources a browser fetches on its own after receiving a page.
#
# This is the load-bearing signal for telling a real visitor from a script, and
# unlike the User-Agent it cannot be cheaply faked: a scraper that also downloads
# every stylesheet, font and image in order to look human burns exactly the
# bandwidth it came to steal.
ASSET_EXTENSIONS = frozenset("""
css js mjs map png jpg jpeg gif svg webp avif ico bmp
woff woff2 ttf eot otf
mp4 webm ogv mp3 ogg wav flac
wasm
""".split())

ASSET_PATH_HINTS = ("/static/", "/assets/", "/_next/", "/wp-content/",
                    "/wp-includes/", "/media/", "/dist/", "/build/")

# Clients that announce themselves as a tool rather than a browser. Anything
# worth worrying about sends a browser string, which is why none of this can
# justify a block on its own — but the two halves are not equivalent, so they are
# kept apart.
#
# GENERIC: HTTP libraries and scraping frameworks. Every one of them has an
# honest use — an API client, a monitoring probe, a customer's own integration.
# These may inform the browser-vs-script profile and nothing more. A rule that
# blocked on this list would take out the operator's own integrations.
SCRIPT_UA_GENERIC = (
    "curl/", "wget", "python-requests", "python-urllib", "aiohttp", "httpx",
    "go-http-client", "okhttp", "java/", "libwww", "guzzle", "axios",
    "node-fetch", "got/", "scrapy", "postmanruntime", "insomnia", "httpie",
    "lwp::simple", "mechanize",
)

# OFFENSIVE: vulnerability scanners and exploitation tools. None of these has a
# legitimate use against somebody else's server, so the name alone is a statement
# of intent rather than a hint about behaviour. Separated so a rule can act on it
# without inheriting the generic list.
ATTACK_UA_MARKERS = (
    "masscan", "nuclei", "zgrab", "nikto", "sqlmap", "wpscan", "dirbuster",
    "gobuster", "feroxbuster", "jshunt",
)

# `jshunt` earns its place the same way the rest do, and its limit is worth
# stating: this catches a bot that is honest about itself, and stops catching it
# the day its operator edits one line. It is hygiene, not a defence. Seen in the
# field 2026-08-18 harvesting bundled JavaScript for leaked keys — seven requests,
# three of them answered 200, which is exactly what made the behavioural veto in
# audit_engine._looks_like_a_client() read it as a visitor. The name is the only
# evidence that survives that veto.

# Profiling treats both halves the same: an attack tool is also a script. The
# union keeps browser-vs-script classification byte-for-byte identical to before
# the split.
SCRIPT_UA_MARKERS = SCRIPT_UA_GENERIC + ATTACK_UA_MARKERS


def classify_uri(uri):
    """True when the request is for a static resource rather than a page."""
    path = uri.split("?", 1)[0].split("#", 1)[0]
    lowered = path.lower()

    for hint in ASSET_PATH_HINTS:
        if hint in lowered:
            return True

    _, dot, extension = lowered.rpartition(".")
    if dot and "/" not in extension and extension in ASSET_EXTENSIONS:
        return True
    return False


def classify_user_agent(user_agent):
    """True when the client names itself as a tool rather than a browser."""
    if not user_agent or user_agent == "-":
        return True
    lowered = user_agent.lower()
    return any(marker in lowered for marker in SCRIPT_UA_MARKERS)


def classify_attack_ua(user_agent):
    """
    True when the client names itself as an offensive security tool.

    A missing or empty agent is NOT an attack signature — it is merely absent,
    and half the honest automation on the internet sends nothing. Only an
    explicit name counts here, which is what separates this from
    classify_user_agent() above.
    """
    if not user_agent or user_agent == "-":
        return False
    lowered = user_agent.lower()
    return any(marker in lowered for marker in ATTACK_UA_MARKERS)

# Failed-authentication patterns. Only failures are matched — a successful login
# must never contribute, or a busy admin would block themselves.
#
# Every pattern captures the address in a named group so the same reader serves
# sshd, Dovecot, Exim, and vsftpd without a per-service parser.
AUTH_FAIL_PATTERNS = [
    # sshd
    re.compile(r"Failed (?:password|publickey) for (?:invalid user )?\S+ from (?P<ip>\S+)"),
    re.compile(r"Invalid user \S+ from (?P<ip>\S+)"),
    re.compile(r"maximum authentication attempts exceeded for .* from (?P<ip>\S+)"),
    re.compile(r"Connection closed by authenticating user \S+ (?P<ip>\S+) port \d+ \[preauth\]"),
    re.compile(r"Received disconnect from (?P<ip>\S+) port \d+:\d+: .*\[preauth\]"),
    # Dovecot (IMAP/POP3)
    re.compile(r"auth failed.*rip=(?P<ip>[0-9a-fA-F:.]+)"),
    re.compile(r"Aborted login \(auth failed.*rip=(?P<ip>[0-9a-fA-F:.]+)"),
    re.compile(r"disconnected \(auth failed.*rip=(?P<ip>[0-9a-fA-F:.]+)"),
    # Exim (SMTP AUTH)
    re.compile(r"authenticator failed for .*\[(?P<ip>[0-9a-fA-F:.]+)\].*(?:535|authentication)"),
    # vsftpd / pure-ftpd
    re.compile(r"FTP LOGIN FAILED.*Client \"(?P<ip>[0-9a-fA-F:.]+)\""),
    re.compile(r"\[WARNING\] Authentication failed for user.*\[(?P<ip>[0-9a-fA-F:.]+)\]"),
]

# Anchored on the quoted request rather than on field positions.
#
# Positional splitting cannot tell these apart, and guessing wrong yields entries
# that look valid while carrying a garbage URI and zero bytes — detection goes
# blind without ever raising PARSE_FAIL:
#     IP - - [date] "GET /x HTTP/1.1" 200 123    <- combined (two placeholders)
#     IP -   [date] "GET /x HTTP/1.1" 200 123    <- FastPanel backend (one)
COMBINED_RE = re.compile(
    r'^(?P<ip>\[?[0-9A-Fa-f:.]+\]?)\s+'      # client address
    r'\S+\s+'                                 # identd placeholder
    r'(?:\S+\s+)?'                            # optional auth-user placeholder
    r'\[(?P<ts>[^\]]*)\]\s+'                  # [timestamp] — captured, see parse_stamp()
    r'"(?P<request>[^"]*)"\s+'                # "METHOD /uri PROTO"
    r'(?P<status>\d{3})\s+'                   # status
    r'(?P<bytes>\d+|-)'                       # bytes sent ("-" means zero)
    r'(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'     # "referer" "user-agent", when present
    r'(?:\s+"(?P<xff>[^"]*)")?'              # trailing forwarded-for field, if the
                                             # log_format appends one
)

MONTHS = {name: number for number, name in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), start=1)}

# Converting the stamp is worth doing per distinct SECOND, not per line: a busy
# log puts hundreds of requests inside the same second, and the conversion is the
# expensive half. Measured on 300k lines, Python 3.11: 0.45s with the stamp
# discarded, 1.53s converting every line, 0.69s with this cache.
_STAMP_CACHE = {}
_STAMP_CACHE_MAX = 8192


def parse_stamp(stamp):
    """
    "16/Aug/2026:06:52:01 +0700" -> epoch seconds, or None.

    Sliced rather than handed to strptime, which is an order of magnitude slower
    and would dominate a run on a busy host.
    """
    if not stamp:
        return None
    cached = _STAMP_CACHE.get(stamp)
    if cached is not None:
        return cached
    try:
        moment = calendar.timegm((
            int(stamp[7:11]), MONTHS[stamp[3:6]], int(stamp[0:2]),
            int(stamp[12:14]), int(stamp[15:17]), int(stamp[18:20]),
            0, 0, 0))
        offset = stamp[21:26]
        if len(offset) == 5 and offset[0] in "+-":
            shift = int(offset[1:3]) * 3600 + int(offset[3:5]) * 60
            moment += -shift if offset[0] == "+" else shift
    except (ValueError, KeyError, IndexError):
        return None
    if len(_STAMP_CACHE) >= _STAMP_CACHE_MAX:
        _STAMP_CACHE.clear()
    _STAMP_CACHE[stamp] = moment
    return moment


class TrafficWindow:
    """
    Per-address counters kept in per-interval buckets, not as one running total.

    The previous shape was a single number per address with a 24-hour idle TTL.
    That number never went down: prune() dropped an entry whole once it had been
    silent for a full day, so any address that appeared even once a day
    accumulated for as long as it kept visiting. A loyal low-rate visitor would
    eventually reach a volume threshold having done nothing wrong, and the
    thresholds documented as "per WINDOW_HOURS" actually meant "since first
    continuous activity".

    Buckets fix that, and they also make the two classes of signal answerable
    with one structure, because measurement showed the classes want opposite
    things (measured on a production host, 911,795 lines, 1,703 addresses):

      VOLUME (hits, bandwidth, 404s, login POSTs)
        Normal visitors are LOUD here — one modern page view is 30-80 requests,
        so p90 of the peak-per-interval was 6 but the tail reached 134 for people
        who simply opened three pages. A single interval cannot tell them from an
        attacker. What separates them is persistence: the visitor is loud once,
        the crawler is loud for hours. So volume is judged per interval and an
        address must be over the line in STRIKES_REQUIRED separate intervals.
        Measured: threshold 60 with one interval flagged 6 innocents; the same
        threshold requiring 2 intervals flagged none.

      INTENT (wp-login, xmlrpc, recon, 401/403, failed logins, scanner UA)
        Normal visitors are SILENT here — the base rate is zero, nobody browses
        to wp-login.php five times by accident. And attackers deliberately go
        slow: four addresses on that host were knocking on wp-login.php exactly
        TWICE per two-minute interval, sustained across 97 intervals. A
        per-interval threshold of 5 would have missed every one of them. So
        intent is summed across a short sliding window instead.

    Both windows genuinely slide: buckets fall off the back by time, so no
    counter grows without bound.
    """

    def __init__(self, state_dir, interval=120, strikes_window=10,
                 intent_minutes=30, max_ips=200000, v6_prefix=64,
                 profile_minutes=240):
        self.v6_prefix = v6_prefix
        self.path = os.path.join(state_dir, "window.json")
        self.state_dir = state_dir
        self.interval = max(1, interval)
        self.strikes_window = max(1, strikes_window)
        self.intent_buckets = max(1, (intent_minutes * 60) // self.interval)

        # Client characterisation is a third class of signal, and it wants the
        # opposite of what the other two want.
        #
        # Volume needs a single interval, because a burst is only meaningful
        # undiluted. Intent needs half an hour, because the base rate is zero and
        # attackers go slow. But "is there a browser attached to this address" can
        # only be answered from a client's whole visit — and until rc13 it was
        # answered from the intent window, because pages/assets were read with
        # intent_sum() like everything else.
        #
        # Measured on a medium-traffic government host: 9 of 331 addresses reached
        # 8 requests inside 30 minutes. A real visitor had 7. The profiling signal
        # was therefore inert in production, and the one host where it did fire had
        # traffic heavy enough to hide the problem.
        #
        # Widening the intent window instead would have been the wrong fix: it also
        # widens the window logwall PUNISHES over, so a brute force would be judged
        # on four hours of history and the risk of convicting the wrong address goes
        # up. Only these two metrics get the long view.
        self.profile_buckets = max(1, (profile_minutes * 60) // self.interval)
        self.keep_buckets = max(self.strikes_window, self.intent_buckets,
                                self.profile_buckets)
        self.max_ips = max_ips
        self.entries = {}
        self.dropped_legacy = 0
        self.load()

    # ------------------------------------------------------------------ state
    def load(self):
        if not os.path.isfile(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return

        ips = data.get("ips", {})
        if not isinstance(ips, dict):
            return

        # A state file from before bucketing holds one running total per address.
        # Those totals cover an unknown and unbounded span, so there is no honest
        # way to place them in a bucket. They are dropped rather than guessed at,
        # which costs one window of history exactly once.
        if data.get("format") != "buckets":
            self.dropped_legacy = len(ips)
            return

        for ip, buckets in ips.items():
            if not isinstance(buckets, dict):
                continue
            clean = {}
            for key, metrics in buckets.items():
                if not isinstance(metrics, dict):
                    continue
                index = _safe_int(key, -1)
                if index >= 0:
                    clean[index] = {m: _safe_int(v) for m, v in metrics.items()
                                    if m in METRIC_KEYS}
            if clean:
                self.entries[ip] = clean

        self._migrate_v6_keys()

    def save(self):
        payload = {
            "updated": int(time.time()),
            "format": "buckets",
            "interval": self.interval,
            "ips": {ip: {str(index): metrics for index, metrics in buckets.items()}
                    for ip, buckets in self.entries.items()},
        }
        _atomic_write_json(self.path, payload)

    def _migrate_v6_keys(self):
        """Folds bare IPv6 addresses into the /64 the rest of the code counts by."""
        if self.v6_prefix >= 128:
            return
        for ip in list(self.entries):
            if ":" not in ip or "/" in ip:
                continue
            folded = self._collapse_v6(ip)
            if folded == ip:
                continue
            target = self.entries.setdefault(folded, {})
            for index, metrics in self.entries.pop(ip).items():
                bucket = target.setdefault(index, {})
                for metric, value in metrics.items():
                    bucket[metric] = bucket.get(metric, 0) + value

    def _collapse_v6(self, ip_str):
        if ":" not in ip_str or "/" in ip_str or self.v6_prefix >= 128:
            return ip_str
        try:
            return str(ipaddress.ip_network(
                "{}/{}".format(ip_str, self.v6_prefix), strict=False))
        except ValueError:
            return ip_str

    # ------------------------------------------------------------- collection
    def add(self, ip, metric, value, stamp):
        ip = self._collapse_v6(ip)
        index = stamp // self.interval
        bucket = self.entries.setdefault(ip, {}).setdefault(index, {})
        bucket[metric] = bucket.get(metric, 0) + value

    def prune(self, now):
        current = now // self.interval
        oldest = current - self.keep_buckets
        intent_floor = current - self.intent_buckets

        for ip in list(self.entries):
            buckets = {}
            for index, metrics in self.entries[ip].items():
                if index <= oldest:
                    continue
                if index > intent_floor:
                    buckets[index] = metrics
                    continue
                # Past the intent window this bucket exists only to characterise a
                # client, so it carries only what that needs. Keeping every metric
                # here would nearly double the state file and, worse, would leave
                # punishable counters sitting in buckets that no punishing rule is
                # supposed to see.
                trimmed = {key: value for key, value in metrics.items()
                           if key in PROFILE_METRICS}
                if trimmed:
                    buckets[index] = trimmed
            if buckets:
                self.entries[ip] = buckets
            else:
                del self.entries[ip]

        # Hard cap so a flood of unique addresses cannot grow the state file
        # without bound. The busiest offenders are the ones worth remembering.
        if len(self.entries) > self.max_ips:
            ranked = sorted(self.entries.items(),
                            key=lambda kv: sum(b.get("hits", 0) for b in kv[1].values()),
                            reverse=True)
            self.entries = dict(ranked[:self.max_ips])

    # ------------------------------------------------------------- inspection
    def _recent(self, buckets, count):
        if not buckets:
            return []
        newest = max(buckets)
        floor = newest - count
        return [metrics for index, metrics in buckets.items() if index > floor]

    def intent_minutes(self):
        """The sliding intent window, in minutes, as actually bucketed."""
        return (self.intent_buckets * self.interval) // 60

    def intent_sum(self, metric):
        """Total over the intent window. For signals whose base rate is zero."""
        out = {}
        for ip, buckets in self.entries.items():
            total = sum(m.get(metric, 0)
                        for m in self._recent(buckets, self.intent_buckets))
            if total:
                out[ip] = total
        return out

    def profile_minutes(self):
        """The client-characterisation window, in minutes, as actually bucketed."""
        return (self.profile_buckets * self.interval) // 60

    def profile_sum(self, metric):
        """
        Total over the profiling window. Only for PROFILE_METRICS.

        Deliberately a separate method rather than a parameter on intent_sum(): a
        rule that punishes must not be able to reach this reach by accident, and a
        named boundary is harder to cross without noticing than an argument is.
        """
        if metric not in PROFILE_METRICS:
            raise ValueError("profile_sum is only for %s" % (PROFILE_METRICS,))
        out = {}
        for ip, buckets in self.entries.items():
            total = sum(m.get(metric, 0)
                        for m in self._recent(buckets, self.profile_buckets))
            if total:
                out[ip] = total
        return out

    def strikes(self, metric, threshold):
        """
        How many separate intervals this address was over the line.

        This is the whole reason a real visitor's burst does not become a block:
        opening three pages is loud in ONE interval and silent in the next.
        """
        out = {}
        if threshold <= 0:
            return out
        for ip, buckets in self.entries.items():
            count = sum(1 for m in self._recent(buckets, self.strikes_window)
                        if m.get(metric, 0) > threshold)
            if count:
                out[ip] = count
        return out

    def peak(self, metric):
        """Largest single-interval value, used to state the evidence in a reason."""
        out = {}
        for ip, buckets in self.entries.items():
            values = [m.get(metric, 0)
                      for m in self._recent(buckets, self.strikes_window)]
            top = max(values) if values else 0
            if top:
                out[ip] = top
        return out

    def get(self, ip, metric):
        buckets = self.entries.get(ip, {})
        return sum(m.get(metric, 0) for m in self._recent(buckets, self.intent_buckets))

    # ------------------------------------------------------------------ nets
    def subnet_rollup(self, prefix_v4=24, prefix_v6=64):
        """
        Sums every per-address bucket into its containing network, keeping the
        buckets intact so a range is judged by the same rules an address is.

        A flood spread across hundreds of addresses inside one or two /24s is a
        single coordinated source, not hundreds of weak ones. `members` is the
        number of distinct addresses seen; the caller requires evidence of
        coordination before ever proposing a range, so one busy visitor cannot
        drag 255 neighbours down.
        """
        rollup = {}

        for ip_str, buckets in self.entries.items():
            # Fast path for the common shapes; ip_network() on every one of up to
            # WINDOW_MAX_IPS entries would dominate the run.
            if prefix_v4 == 24 and "." in ip_str and ":" not in ip_str:
                octets = ip_str.split(".")
                if len(octets) != 4:
                    continue
                key = "{}.{}.{}.0/24".format(*octets[:3])
            else:
                # v6 keys already arrive as /64 CIDRs (IPV6_BLOCK_PREFIX), so the
                # network part is taken before re-aggregating at the wider prefix.
                base = ip_str.split("/", 1)[0]
                try:
                    key = str(ipaddress.ip_network(
                        "{}/{}".format(base,
                                       prefix_v4 if "." in base and ":" not in base
                                       else prefix_v6),
                        strict=False))
                except ValueError:
                    continue

            agg = rollup.get(key)
            if agg is None:
                agg = {"members": set(), "buckets": {}}
                rollup[key] = agg

            agg["members"].add(ip_str)
            for index, metrics in buckets.items():
                target = agg["buckets"].setdefault(index, {})
                for metric, value in metrics.items():
                    target[metric] = target.get(metric, 0) + value

        out = {}
        for key, agg in rollup.items():
            buckets = agg["buckets"]
            recent_strike = self._recent(buckets, self.strikes_window)
            recent_intent = self._recent(buckets, self.intent_buckets)
            entry = {"members": len(agg["members"])}
            for metric in METRIC_KEYS:
                values = [m.get(metric, 0) for m in recent_strike]
                entry["peak_" + metric] = max(values) if values else 0
                entry[metric] = sum(m.get(metric, 0) for m in recent_intent)
            entry["_buckets"] = recent_strike
            out[key] = entry
        return out

    def net_strikes(self, entry, metric, threshold):
        """Strike count for a rollup entry produced by subnet_rollup()."""
        if threshold <= 0:
            return 0
        return sum(1 for m in entry.get("_buckets", [])
                   if m.get(metric, 0) > threshold)


def _atomic_write_json(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class LogParserEngine:
    def __init__(self, config=None):
        self.config = config or {}
        self.state_dir = get_path(self.config, "STATE_DIR", "/opt/logwall/data/state")
        self.cursor_file = os.path.join(self.state_dir, "log_cursor.json")
        self.cursors = self._load_cursors()

        # Catch-up detection. Set by analyze_traffic(), read by the audit engine.
        self.run_meta_file = os.path.join(self.state_dir, "run_meta.json")
        self.catchup = False
        self.catchup_reason = ""
        self.span_start = None
        self.span_end = None
        self.stamped = 0
        self.unstamped = 0

        self.interval = max(1, get_int(self.config, "EVAL_INTERVAL_SEC", 120))
        self.window = TrafficWindow(
            self.state_dir,
            interval=self.interval,
            strikes_window=get_int(self.config, "STRIKES_WINDOW", 10),
            intent_minutes=get_int(self.config, "INTENT_WINDOW_MIN", 30),
            profile_minutes=get_int(self.config, "PROFILING_WINDOW_MIN", 240),
            max_ips=get_int(self.config, "WINDOW_MAX_IPS", 200000),
            v6_prefix=get_int(self.config, "IPV6_BLOCK_PREFIX", 64),
        )

        self.max_bytes_per_run = get_int(self.config, "LOG_MAX_MB_PER_RUN", 200) * 1024 * 1024
        self.cmd_timeout = get_int(self.config, "EXT_CMD_TIMEOUT_SEC", 15)

        # Paths nobody browses to by accident. `/.well-known/` is deliberately
        # absent: ACME and Let's Encrypt live there, and flagging it would have
        # the tool block the certificate renewal of the host it protects.
        self.sensitive_pattern = re.compile(
            r"\.env|\.sql|\.bak|phpmyadmin|\.git|"
            r"wp-config\.php|\.htpasswd|\.ssh/|id_rsa|\.aws/|\.svn/|"
            r"/vendor/|/actuator|/server-status|/server-info|"
            r"\.DS_Store|config\.json|\.npmrc|\.dockercfg|docker-compose\.ya?ml|"
            r"/phpinfo|/adminer|\.old$|\.orig$",
            re.IGNORECASE)

        # `/vendor/` is the one token in that list a browser can reach by
        # accident: WordPress core ships React and Moment under
        # /wp-includes/js/dist/vendor/, so one ordinary page load looks like four
        # probes. Measured in the field 2026-08-18 — an office address reading a
        # court calendar in Firefox, every request answered 200, blocked
        # PERMANENT sixty seconds later.
        #
        # A static asset is never the evidence. /vendor/…/eval-stdin.php is still
        # caught wherever it sits, because the exploit is never a .js file.
        self.sensitive_asset_exempt = re.compile(
            r"\.(?:js|mjs|css|map|png|jpe?g|gif|svg|webp|avif|ico|"
            r"woff2?|ttf|otf|eot)$", re.IGNORECASE)

        # A request for a SOURCE file that returned 404.
        #
        # 404 on a page is ordinary — a dead link, a stale search-engine index.
        # 404 on a source file has no innocent reading: visitors and crawlers
        # follow links, and nothing links to /dvoqqmkm.php. Measured on a busy
        # government site, 636k requests: 73 source-file 404s against 1,345 page
        # 404s, and all 19 addresses responsible were hostile.
        #
        # `wp-login.php` and `xmlrpc.php` are excluded on purpose — both already
        # have dedicated rules, and counting them here would punish twice for one
        # act. On the same host six addresses in one /24 each asked for
        # wp-login.php exactly once; this exclusion is what spares them.
        self.source_file_pattern = re.compile(
            self.config.get("SOURCE_FILE_EXTENSIONS")
            or r"\.(?:php|phtml|php[0-9]|asp|aspx|jsp|jspx|cgi|pl|py|rb|sh|"
               r"env|sql|bak|inc|ini|conf|yml|yaml|pem|key)$",
            re.IGNORECASE)
        self.source_file_exempt = re.compile(
            r"wp-login\.php$|xmlrpc\.php$", re.IGNORECASE)

        # Login endpoints outside WordPress. Kept configurable because every
        # framework names its own, and a wrong guess here punishes real users
        # who mistyped a password.
        self.login_path_pattern = re.compile(
            self.config.get("LOGIN_PATHS")
            or r"/login|/signin|/admin|/administrator|/user/login"
            r"|/api/auth|/api/login|/auth/login",
            re.IGNORECASE)

        # Set by the caller so the parser can recognise CDN edge addresses.
        self.cdn_check = None
        self._last_bytes_read = 0

        # Health flags surfaced in the report (docs/DESIGN.md §9).
        #
        # CDN_NO_REALIP and PARSE_FAIL carry a count, not just a filename. Naming
        # the whole file for one bad line reads as "this log is unusable" when the
        # truth may be "1 request of 537", and an operator who believes the first
        # will go looking for a problem that is not there.
        self.flags = {
            "PARSE_FAIL": {},          # path -> [unparsed, seen]
            "LOG_NOT_FOUND": False,
            "CDN_NO_REALIP": {},       # path -> [unresolved, seen]
            "PEER_NOT_ROUTABLE": {},   # address -> requests
            "ROTATED": [],
            "BACKEND_LOG_ONLY": [],
        }

    # ---------------------------------------------------------------- cursors
    def _load_cursors(self):
        if os.path.isfile(self.cursor_file):
            try:
                with open(self.cursor_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    return data
            except (OSError, ValueError):
                pass
        return {}

    def save_state(self):
        """Cursors and window counters are committed together, never separately."""
        _atomic_write_json(self.cursor_file, self.cursors)
        _atomic_write_json(self.run_meta_file, {
            "last_run": int(time.time()),
            "catchup": bool(self.catchup),
            "catchup_reason": self.catchup_reason,
            "span_seconds": (self.span_end - self.span_start
                             if self.span_start is not None
                             and self.span_end is not None else 0),
            "stamped": self.stamped,
            "unstamped": self.unstamped,
        })
        self.window.save()

    # --------------------------------------------------------------- catch-up
    def _detect_catchup(self, now):
        """
        Returns (is_catchup, reason) for a run whose data covers far more time
        than one cron interval.

        This is the ONE way an ordinary visitor crosses a volume threshold
        without having done anything: hand a single run six hours of log and
        every count in it is inflated by the same factor. It happens on a fresh
        install (no cursor exists, so the whole existing log is read from byte
        zero) and after a cursor reset.

        The span is MEASURED from the stamps of the lines just read, not guessed
        from the gap between runs. The difference is not academic — a host that
        was powered off for four hours wrote no log at all while it was down, so
        the gap is four hours and the span is zero. Guessing suspends the volume
        rules for nothing; measuring does not.

        Intent detections are unaffected either way and must keep firing: five
        probes for /.env are five probes whether they arrived over two minutes or
        two days. Only the volume rules stand down, and only for this run.
        """
        if not get_bool(self.config, "CATCHUP_GUARD", True):
            return False, ""

        max_gap = get_int(self.config, "CATCHUP_MAX_GAP_MIN", 15) * 60

        if self.span_start is not None and self.span_end is not None:
            span = self.span_end - self.span_start
            if span > max_gap:
                return True, (
                    "this run ingested {} minutes of log, more than "
                    "CATCHUP_MAX_GAP_MIN={}".format(span // 60, max_gap // 60))
            return False, ""

        # No parseable stamp anywhere — an unrecognised log format, or a run that
        # read nothing at all. Fall back to the gap between runs, which is the
        # weaker signal but the only one left.
        if self.stamped == 0 and self.unstamped > 0:
            last_run = self._last_run()
            if last_run is None:
                return True, ("first run on this host and no timestamp could be "
                              "read, so the age of this data is unknown")
            gap = now - last_run
            if gap > max_gap:
                return True, (
                    "no timestamp could be read and {} minutes passed since the "
                    "previous run".format(gap // 60))

        return False, ""

    def _last_run(self):
        if not os.path.isfile(self.run_meta_file):
            return None
        try:
            with open(self.run_meta_file, "r", encoding="utf-8") as f:
                return _safe_int(json.load(f).get("last_run"), 0) or None
        except (OSError, ValueError, AttributeError):
            return None

    # -------------------------------------------------------------- discovery
    def discover_log_files(self, panel_type="none"):
        logs = []

        if panel_type == "fastpanel":
            logs.extend(self._discover_fastpanel())

        if not logs:
            patterns = [
                "/var/www/*/data/logs/*-frontend.access.log",
                "/var/log/nginx/*access*.log",
                "/var/log/nginx/domains/*.log",
                "/var/log/apache2/*access*.log",
                "/var/log/httpd/*access*.log",
                "/var/log/httpd/domains/*.log",
                "/usr/local/lsws/logs/*access*.log",
                "/home/*/logs/*access*log",
                "/www/wwwlogs/*.log",
                "/var/log/caddy/*.log",
            ]
            for pattern in patterns:
                for path in glob.glob(pattern):
                    if not os.path.isfile(path):
                        continue
                    name = os.path.basename(path)
                    if path.endswith(".gz") or "old" in name or "error" in name:
                        continue
                    logs.append(path)

        logs = sorted(set(logs))
        if not logs:
            self.flags["LOG_NOT_FOUND"] = True
        return logs

    def _discover_fastpanel(self):
        """
        Reads the site inventory from the panel CLI.

        The CLI returns a bare JSON array, and the owning account lives under
        `owner.username` / `owner.home_dir`. Sites on one host do NOT all belong
        to the same account, so the owner must be read per site rather than
        assumed from the first one.
        """
        found = []
        try:
            res = subprocess.run(
                ["fastpanel", "--json", "sites", "list"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                universal_newlines=True,
                timeout=self.cmd_timeout,
            )
            if res.returncode != 0:
                return found
            data = json.loads(res.stdout)
        except (OSError, ValueError, subprocess.SubprocessError):
            return found

        if isinstance(data, list):
            sites = data
        elif isinstance(data, dict):
            sites = data.get("data") or data.get("sites") or []
        else:
            return found

        for site in sites:
            if not isinstance(site, dict):
                continue
            domain = site.get("domain")
            if not domain:
                continue

            bases = []
            owner = site.get("owner") or {}
            if isinstance(owner, dict):
                if owner.get("home_dir"):
                    bases.append(owner["home_dir"])
                if owner.get("username"):
                    bases.append("/var/www/{}/data".format(owner["username"]))

            # index_dir looks like /var/www/<account>/data/www/<domain>
            index_dir = site.get("index_dir") or ""
            if "/www/" in index_dir:
                bases.append(index_dir.rsplit("/www/", 1)[0])

            frontend = None
            backend = None
            for base in bases:
                candidate = os.path.join(base, "logs", "{}-frontend.access.log".format(domain))
                if frontend is None and os.path.isfile(candidate):
                    frontend = candidate
                candidate = os.path.join(base, "logs", "{}-backend.access.log".format(domain))
                if backend is None and os.path.isfile(candidate):
                    backend = candidate

            if frontend:
                found.append(frontend)
            elif backend:
                # The backend log sits behind the reverse proxy. Its addresses are
                # only trustworthy when the backend is configured to restore them;
                # flag it so the operator knows detection is running on second-hand
                # data for this site.
                found.append(backend)
                self.flags["BACKEND_LOG_ONLY"].append(domain)

        return found

    # ----------------------------------------------------------------- parsing
    def _real_ip_from_header(self, peer_ip, forwarded):
        """
        Returns (ip, resolved). Only called when the peer is a known CDN edge.

        That condition IS the trust anchor, and it is the whole reason this may be
        read at all — the same rule nginx enforces with `set_real_ip_from` and
        Apache with `RemoteIPTrustedProxy`. A forwarding header is a claim made by
        whoever sent it; it becomes evidence only when the sender is someone we
        already decided to trust.

        The rightmost element is taken deliberately: each proxy appends the address
        it received from, so anything a client invented is pushed left and ignored.

        What used to be here instead scanned the whole log line for any token
        shaped like an address and used the first one that was not the peer. The
        request URI, the referer and the user-agent are all in that line and all
        under the client's control, and `reversed()` preferred exactly those. A
        user-agent of "Mozilla/5.0 (8.8.8.8)" was enough to make logwall attribute
        traffic to 8.8.8.8 — or, worse, to the operator's own whitelisted address,
        which buys immunity from every guard.
        """
        if not forwarded:
            return peer_ip, False
        candidate = parse_ip(forwarded.split(",")[-1].strip())
        if candidate is None or self.cdn_check(str(candidate)):
            return peer_ip, False
        return str(candidate), True

    def _parse_line(self, line):
        """Returns (ip, uri, bytes, status, forwarded) or None."""
        if line.startswith("{"):
            try:
                data = json.loads(line)
            except ValueError:
                return None
            request = data.get("request") or {}
            ip_obj = parse_ip(request.get("client_ip") or request.get("remote_ip") or "")
            if ip_obj is None:
                return None

            headers = request.get("headers") or {}
            forwarded = ""
            for key in ("Cf-Connecting-Ip", "CF-Connecting-IP", "X-Forwarded-For"):
                value = headers.get(key)
                if value:
                    forwarded = value[0] if isinstance(value, list) else str(value)
                    break

            agent = headers.get("User-Agent") or headers.get("user-agent") or ""
            if isinstance(agent, list):
                agent = agent[0] if agent else ""
            uri = request.get("uri", "") or ""

            # Caddy writes `ts` as a float epoch, already UTC — no parsing needed.
            try:
                moment = int(float(data["ts"]))
            except (KeyError, TypeError, ValueError):
                moment = None

            return RawRequest(str(ip_obj), uri,
                              _safe_int(data.get("size", 0)),
                              _safe_int(data.get("status", 200), 200), forwarded,
                              classify_uri(uri), classify_user_agent(agent),
                              str(request.get("method", "") or "").upper(),
                              classify_attack_ua(agent), moment)

        match = COMBINED_RE.match(line)
        if not match:
            return None

        ip_obj = parse_ip(match.group("ip"))
        if ip_obj is None:
            return None

        request = match.group("request").split()
        uri = request[1] if len(request) >= 2 else (request[0] if request else "")
        method = request[0].upper() if len(request) >= 2 else ""
        agent = match.group("ua")

        # Captured, not scavenged. Only consulted when the peer is a CDN edge we
        # already trust — see _real_ip_from_header(). Before rc13 there was no
        # capture group at all and the address was recovered by scanning the whole
        # line for anything IP-shaped, which handed the client control of its own
        # identity through the user-agent field.
        return RawRequest(str(ip_obj), uri,
                          _safe_int(match.group("bytes")),
                          _safe_int(match.group("status"), 200),
                          (match.group("xff") or ""),
                          classify_uri(uri), classify_user_agent(agent),
                          method, classify_attack_ua(agent),
                          parse_stamp(match.group("ts")))

    def _read_new_lines(self, filepath):
        """
        Yields (line, bytes_read_so_far) for the bytes appended since last run.

        Owns the cursor, rotation handling, and the per-run byte budget, so the
        web parser and the auth parser share one implementation instead of two
        that can drift apart.
        """
        if not os.path.isfile(filepath):
            return

        try:
            stat_info = os.stat(filepath)
        except OSError:
            return

        current_inode = stat_info.st_ino
        current_size = stat_info.st_size

        saved = self.cursors.get(filepath, {})
        offset = saved.get("offset", 0)

        if saved.get("inode") != current_inode or current_size < offset:
            if saved:
                self.flags["ROTATED"].append(filepath)
            offset = 0

        if current_size == offset:
            return

        # Never read an unbounded backlog in a single run.
        budget = self.max_bytes_per_run
        if current_size - offset > budget:
            offset = current_size - budget

        bytes_read = 0
        new_offset = offset

        # Binary, not text, and the cursor is arithmetic rather than tell().
        #
        # In text mode Python only accepts a seek() offset of 0 or one that tell()
        # previously returned; an arbitrary byte position leaves the TextIOWrapper
        # in a state where the next tell() raises
        # "OSError: telling position disabled by next() call". The budget line
        # above computes exactly such an arbitrary offset, so the one path meant to
        # protect a host from an enormous backlog was the path that crashed on it.
        # Reproduced on Python 3.8, 3.11 and 3.12 — this was never version-specific.
        #
        # Binary mode fixes a second, quieter fault at the same time: len() on a
        # text line counts CHARACTERS, so every non-ASCII byte made bytes_read
        # drift below the real position, and that number is both the byte budget
        # and the saved cursor.
        try:
            handle = open(filepath, "rb")
        except OSError:
            return

        try:
            handle.seek(offset)
            for raw_line in handle:
                bytes_read += len(raw_line)
                line = raw_line.decode("utf-8", "ignore").strip()
                if line:
                    yield line, bytes_read
                if bytes_read >= budget:
                    break
            new_offset = offset + bytes_read
        finally:
            handle.close()

        self.cursors[filepath] = {"inode": current_inode, "offset": new_offset}
        self._last_bytes_read = bytes_read

    def parse_log_file(self, filepath):
        """
        Yields (ip, uri, bytes, status, resolved) for every new line.

        A generator on purpose: materialising a full backlog would cost hundreds
        of megabytes on the very first run, which is exactly when the host can
        least afford it.
        """
        self._last_bytes_read = 0
        parsed = 0
        seen = 0

        for line, _ in self._read_new_lines(filepath):
            seen += 1
            fields = self._parse_line(line)
            if fields is None:
                continue

            parsed += 1
            ip = fields.peer
            resolved = True

            # The peer address is the only fact in this line. It completed a TCP
            # handshake, so it cannot be forged. Everything else — the header, the
            # URI, the user-agent — is a claim the client chose to make.
            #
            # A forwarding header is therefore read ONLY when the peer is a CDN
            # edge we already trust. The previous version read it from anybody,
            # which let any client rename itself with one header: proven on a
            # production host, where a request from the admin's own address landed
            # in the log as 192.0.2.77 because the web server was configured to
            # believe headers too (see REKOMENDASI R12).
            if self.cdn_check is not None and self.cdn_check(ip):
                ip, resolved = self._real_ip_from_header(ip, fields.forwarded)
            elif is_unroutable_source(ip):
                # A public web server cannot be reached FROM a private address.
                # If one is in the peer field, something upstream is rewriting it
                # from a header it should not have trusted, and no identity in
                # this log can be relied on.
                self.flags["PEER_NOT_ROUTABLE"][ip] = \
                    self.flags["PEER_NOT_ROUTABLE"].get(ip, 0) + 1
                resolved = False

            # `line` goes out of scope here and is never stored.
            yield Request(ip, fields.uri, fields.size, fields.status, resolved,
                          fields.is_asset, fields.script_ua, fields.method,
                          fields.attack_ua, fields.moment)

        # A file that grew but produced nothing parseable means the log format is
        # unknown. Silently deciding "no attacks" from unreadable data is worse
        # than reporting the failure (docs/DESIGN.md §16.3).
        if self._last_bytes_read > 0 and parsed == 0:
            self.flags["PARSE_FAIL"][filepath] = [seen, seen]

    # ------------------------------------------------------ authentication logs
    def discover_auth_logs(self):
        """Service authentication logs: SSH, IMAP/POP3, SMTP AUTH, FTP."""
        candidates = [
            "/var/log/secure",          # RHEL family: sshd
            "/var/log/auth.log",        # Debian family: sshd
            "/var/log/maillog",         # RHEL: dovecot + exim/postfix
            "/var/log/mail.log",        # Debian: dovecot + exim/postfix
            "/var/log/dovecot.log",
            "/var/log/exim/mainlog",
            "/var/log/exim_mainlog",
            "/var/log/exim4/mainlog",
            "/var/log/vsftpd.log",
            "/var/log/pureftpd.log",
            "/var/log/messages",        # some distros route sshd here
        ]
        return [p for p in candidates if os.path.isfile(p) and os.access(p, os.R_OK)]

    def parse_auth_file(self, filepath):
        """Yields the client address of every FAILED authentication attempt."""
        for line, _ in self._read_new_lines(filepath):
            for pattern in AUTH_FAIL_PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue
                ip_obj = parse_ip(match.group("ip"))
                if ip_obj is not None:
                    yield str(ip_obj)
                break

    # ---------------------------------------------------------------- analysis
    def analyze_traffic(self, logs, auth_logs=None):
        now = int(time.time())
        self.span_start = None
        self.span_end = None
        self.stamped = 0
        self.unstamped = 0

        # Service auth logs carry a syslog stamp with no year, so those entries
        # keep the run's clock. Volume rules never read them, and the intent rule
        # that does is a plain count.
        for auth_path in (auth_logs or []):
            for ip in self.parse_auth_file(auth_path):
                self.window.add(ip, "auth", 1, now)

        for log_path in logs:
            share = self.flags["CDN_NO_REALIP"].setdefault(log_path, [0, 0])
            for request in self.parse_log_file(log_path):
                ip, uri, size, status = (request.ip, request.uri,
                                         request.size, request.status)
                resolved, is_asset = request.resolved, request.is_asset
                script_ua, method = request.script_ua, request.method
                attack_ua, moment = request.attack_ua, request.moment
                share[1] += 1
                if not resolved:
                    # CDN traffic without a usable real IP: audit only. The count
                    # is what makes this actionable — one line of 537 is noise, 537
                    # of 537 means detection on this log is dead.
                    share[0] += 1
                    continue

                # The request's own time, not the run's. A stamp ahead of the
                # clock means skew or a misread zone, and one far behind the
                # window would resurrect entries prune() is about to drop, so
                # both fall back rather than being trusted.
                if (moment is not None
                        and moment <= now + 300
                        and moment >= now - 400 * 86400):
                    stamp = moment
                    self.stamped += 1
                    if self.span_start is None or moment < self.span_start:
                        self.span_start = moment
                    if self.span_end is None or moment > self.span_end:
                        self.span_end = moment
                else:
                    stamp = now
                    self.unstamped += 1

                self.window.add(ip, "hits", 1, stamp)
                self.window.add(ip, "bw", size, stamp)
                self.window.add(ip, "assets" if is_asset else "pages", 1, stamp)
                if script_ua:
                    self.window.add(ip, "sua", 1, stamp)

                if attack_ua:
                    self.window.add(ip, "aua", 1, stamp)

                if "wp-login.php" in uri:
                    self.window.add(ip, "wp", 1, stamp)
                if "xmlrpc.php" in uri:
                    self.window.add(ip, "xmlrpc", 1, stamp)
                if self.sensitive_pattern.search(uri):
                    sens_path = uri.split("?", 1)[0].split("#", 1)[0]
                    if not self.sensitive_asset_exempt.search(sens_path):
                        self.window.add(ip, "scan", 1, stamp)
                if status in (401, 403):
                    self.window.add(ip, "p401", 1, stamp)
                if status == 404:
                    self.window.add(ip, "p404", 1, stamp)
                    path = uri.split("?", 1)[0].split("#", 1)[0]
                    if (self.source_file_pattern.search(path)
                            and not self.source_file_exempt.search(path)):
                        self.window.add(ip, "src404", 1, stamp)

                # Evidence that this client is a client: it got something back.
                # A dictionary sweeper collects nothing but 404s, so a successful
                # response is one of the two things that separate a real visitor
                # from a scanner (the other is fetching assets).
                elif status in (200, 201, 204, 206, 301, 302, 304):
                    self.window.add(ip, "ok", 1, stamp)

                # Only POST counts. A GET of /login is the login PAGE; a POST is
                # an attempt, and counting page views would flag every visitor
                # who simply looked at the form.
                if method == "POST" and self.login_path_pattern.search(uri):
                    self.window.add(ip, "lpost", 1, stamp)

        # A log where every line resolved is not a finding; drop it so the flag
        # only ever names logs that actually lost requests.
        self.flags["CDN_NO_REALIP"] = {
            path: share for path, share in self.flags["CDN_NO_REALIP"].items()
            if share[0] > 0}

        # Decided AFTER the read, from what the run actually swallowed, instead
        # of inferred beforehand from the gap between runs.
        self.catchup, self.catchup_reason = self._detect_catchup(now)

        self.window.prune(now)

        # Intent signals: summed over the intent window, because the base rate is
        # zero and attackers deliberately trickle below any per-interval line.
        # Volume signals: the engine asks for strikes and peaks itself, since
        # both need the threshold to compute.
        return {
            "wp_login": self.window.intent_sum("wp"),
            "xmlrpc": self.window.intent_sum("xmlrpc"),
            "scan": self.window.intent_sum("scan"),
            "panel_401": self.window.intent_sum("p401"),
            "auth_fail": self.window.intent_sum("auth"),
            "attack_ua": self.window.intent_sum("aua"),
            "pages": self.window.profile_sum("pages"),
            "assets": self.window.profile_sum("assets"),
            "script_ua": self.window.intent_sum("sua"),
            "hits": self.window.intent_sum("hits"),
            "bw": self.window.intent_sum("bw"),
            "panel_404": self.window.intent_sum("p404"),
            "login_post": self.window.intent_sum("lpost"),
            "source_404": self.window.intent_sum("src404"),
            "ok": self.window.intent_sum("ok"),
        }
