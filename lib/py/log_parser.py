#!/usr/bin/env python3
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: lib/py/log_parser.py
# Purpose: Access log parser for Nginx/Apache combined, LiteSpeed, and Caddy JSON.
#          Reads only new bytes per run (inode + offset cursor) and accumulates
#          the counters in a persistent sliding window, so thresholds keep meaning
#          "per WINDOW_HOURS" even though the blocker runs every few minutes.
#
# Memory: parsing streams. Entries are yielded one at a time and the raw line is
#         never retained, so peak memory stays flat no matter how large the
#         backlog is — a 2 GB host handles the same log volume as a 32 GB one.
# Reference: docs/DESIGN.md §8.G (Log Formats), §16.2 (Cursor + Window), §16.3 (Sanity)
# ==============================================================================

import glob
import ipaddress
import json
import os
import re
import subprocess
import time

from config_loader import get_int, get_path
from ip_guard import parse_ip

METRIC_KEYS = ("hits", "wp", "xmlrpc", "scan", "bw", "p401", "auth",
               "pages", "assets", "sua")

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

# Clients that announce themselves. Honest tools only — anything worth worrying
# about sends a browser string, which is why this is a secondary signal that can
# never justify a block on its own.
SCRIPT_UA_MARKERS = (
    "curl/", "wget", "python-requests", "python-urllib", "aiohttp", "httpx",
    "go-http-client", "okhttp", "java/", "libwww", "guzzle", "axios",
    "node-fetch", "got/", "scrapy", "postmanruntime", "insomnia",
    "masscan", "nuclei", "zgrab", "nikto", "sqlmap", "wpscan", "dirbuster",
    "gobuster", "feroxbuster", "httpie", "lwp::simple", "mechanize",
)


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
    r'\[[^\]]*\]\s+'                          # [timestamp]
    r'"(?P<request>[^"]*)"\s+'                # "METHOD /uri PROTO"
    r'(?P<status>\d{3})\s+'                   # status
    r'(?P<bytes>\d+|-)'                       # bytes sent ("-" means zero)
    r'(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'     # "referer" "user-agent", when present
)

# Used to recover the real client address when the peer turns out to be a CDN edge.
IP_TOKEN_RE = re.compile(
    r"(?<![\w.:])((?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]{2,}:[0-9A-Fa-f:.]+)(?![\w.])")


class TrafficWindow:
    """Persistent per-IP counters with a time-to-live of WINDOW_HOURS."""

    def __init__(self, state_dir, window_hours=24, max_ips=200000):
        self.path = os.path.join(state_dir, "window.json")
        self.state_dir = state_dir
        self.window_seconds = max(1, window_hours) * 3600
        self.max_ips = max_ips
        self.entries = {}
        self.load()

    def load(self):
        if os.path.isfile(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    self.entries = data.get("ips", {})
            except (OSError, ValueError):
                self.entries = {}

    def add(self, ip, metric, value, now):
        entry = self.entries.get(ip)
        if entry is None:
            entry = {key: 0 for key in METRIC_KEYS}
            entry["first"] = now
            self.entries[ip] = entry
        entry[metric] = entry.get(metric, 0) + value
        entry["last"] = now

    def prune(self, now):
        cutoff = now - self.window_seconds
        self.entries = {
            ip: entry for ip, entry in self.entries.items()
            if entry.get("last", 0) >= cutoff
        }

        # Hard cap so a flood of unique addresses cannot grow the state file
        # without bound. The busiest offenders are the ones worth remembering.
        if len(self.entries) > self.max_ips:
            ranked = sorted(self.entries.items(),
                            key=lambda kv: kv[1].get("hits", 0),
                            reverse=True)
            self.entries = dict(ranked[:self.max_ips])

    def counter(self, metric):
        return {ip: entry.get(metric, 0) for ip, entry in self.entries.items()}

    def subnet_rollup(self, prefix_v4=24, prefix_v6=64):
        """
        Sums every per-address counter into its containing network.

        A flood spread across hundreds of addresses inside one or two /24s is a
        single coordinated source, not hundreds of weak ones. Counting only per
        address means each member creeps toward the threshold separately and the
        block lands far too late — or not at all, once the circuit breaker sees
        hundreds of candidates appear at once.

        `members` is the number of distinct addresses seen in the network. The
        caller uses it to require evidence of coordination before ever proposing
        a range: one busy address must never drag its 255 neighbours down.
        """
        rollup = {}

        for ip_str, entry in self.entries.items():
            # Fast path for the common shapes; ip_network() on every one of up to
            # WINDOW_MAX_IPS entries would dominate the run.
            if prefix_v4 == 24 and "." in ip_str and ":" not in ip_str:
                octets = ip_str.split(".")
                if len(octets) != 4:
                    continue
                key = "{}.{}.{}.0/24".format(*octets[:3])
            else:
                try:
                    key = str(ipaddress.ip_network(
                        "{}/{}".format(ip_str,
                                       prefix_v4 if "." in ip_str and ":" not in ip_str
                                       else prefix_v6),
                        strict=False))
                except ValueError:
                    continue

            agg = rollup.get(key)
            if agg is None:
                agg = {metric: 0 for metric in METRIC_KEYS}
                agg["members"] = 0
                rollup[key] = agg

            agg["members"] += 1
            for metric in METRIC_KEYS:
                agg[metric] += entry.get(metric, 0)

        return rollup

    def get(self, ip, metric):
        return self.entries.get(ip, {}).get(metric, 0)

    def save(self):
        _atomic_write_json(self.path, {"updated": int(time.time()), "ips": self.entries})


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

        self.window = TrafficWindow(
            self.state_dir,
            window_hours=get_int(self.config, "WINDOW_HOURS", 24),
            max_ips=get_int(self.config, "WINDOW_MAX_IPS", 200000),
        )

        self.max_bytes_per_run = get_int(self.config, "LOG_MAX_MB_PER_RUN", 200) * 1024 * 1024
        self.cmd_timeout = get_int(self.config, "EXT_CMD_TIMEOUT_SEC", 15)
        self.sensitive_pattern = re.compile(
            r"\.env|\.sql|\.bak|phpmyadmin|\.git", re.IGNORECASE)

        # Set by the caller so the parser can recognise CDN edge addresses.
        self.cdn_check = None
        self._last_bytes_read = 0

        # Health flags surfaced in the report (docs/DESIGN.md §9).
        self.flags = {
            "PARSE_FAIL": [],
            "LOG_NOT_FOUND": False,
            "CDN_NO_REALIP": [],
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
        self.window.save()

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
    def _recover_real_ip(self, peer_ip, line):
        """
        Returns (ip, resolved). Only called when the peer is a CDN edge, so the
        raw line never has to be retained beyond this point.
        """
        for match in reversed(IP_TOKEN_RE.findall(line)):
            if match == peer_ip:
                continue
            candidate = parse_ip(match)
            if candidate is None or self.cdn_check(str(candidate)):
                continue
            return str(candidate), True
        return peer_ip, False

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

            return (str(ip_obj), uri,
                    _safe_int(data.get("size", 0)),
                    _safe_int(data.get("status", 200), 200), forwarded,
                    classify_uri(uri), classify_user_agent(agent))

        match = COMBINED_RE.match(line)
        if not match:
            return None

        ip_obj = parse_ip(match.group("ip"))
        if ip_obj is None:
            return None

        request = match.group("request").split()
        uri = request[1] if len(request) >= 2 else (request[0] if request else "")

        return (str(ip_obj), uri,
                _safe_int(match.group("bytes")),
                _safe_int(match.group("status"), 200), "",
                classify_uri(uri), classify_user_agent(match.group("ua")))

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

        for line, _ in self._read_new_lines(filepath):
            fields = self._parse_line(line)
            if fields is None:
                continue

            ip, uri, size, status, forwarded, is_asset, script_ua = fields
            parsed += 1
            resolved = True

            if forwarded:
                candidate = parse_ip(forwarded.split(",")[-1].strip())
                if candidate is not None:
                    ip = str(candidate)
            elif self.cdn_check is not None and self.cdn_check(ip):
                ip, resolved = self._recover_real_ip(ip, line)

            # `line` goes out of scope here and is never stored.
            yield (ip, uri, size, status, resolved, is_asset, script_ua)

        # A file that grew but produced nothing parseable means the log format is
        # unknown. Silently deciding "no attacks" from unreadable data is worse
        # than reporting the failure (docs/DESIGN.md §16.3).
        if self._last_bytes_read > 0 and parsed == 0:
            self.flags["PARSE_FAIL"].append(filepath)

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

        for auth_path in (auth_logs or []):
            for ip in self.parse_auth_file(auth_path):
                self.window.add(ip, "auth", 1, now)

        for log_path in logs:
            for ip, uri, size, status, resolved, is_asset, script_ua in                     self.parse_log_file(log_path):
                if not resolved:
                    # CDN traffic without a usable real IP: audit only.
                    if log_path not in self.flags["CDN_NO_REALIP"]:
                        self.flags["CDN_NO_REALIP"].append(log_path)
                    continue

                self.window.add(ip, "hits", 1, now)
                self.window.add(ip, "bw", size, now)
                self.window.add(ip, "assets" if is_asset else "pages", 1, now)
                if script_ua:
                    self.window.add(ip, "sua", 1, now)

                if "wp-login.php" in uri:
                    self.window.add(ip, "wp", 1, now)
                if "xmlrpc.php" in uri:
                    self.window.add(ip, "xmlrpc", 1, now)
                if self.sensitive_pattern.search(uri):
                    self.window.add(ip, "scan", 1, now)
                if status in (401, 403):
                    self.window.add(ip, "p401", 1, now)

        self.window.prune(now)

        return {
            "hits": self.window.counter("hits"),
            "wp_login": self.window.counter("wp"),
            "xmlrpc": self.window.counter("xmlrpc"),
            "scan": self.window.counter("scan"),
            "bw": self.window.counter("bw"),
            "panel_401": self.window.counter("p401"),
            "auth_fail": self.window.counter("auth"),
            "pages": self.window.counter("pages"),
            "assets": self.window.counter("assets"),
            "script_ua": self.window.counter("sua"),
        }
