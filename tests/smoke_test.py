#!/usr/bin/env python3
"""
logwall offline test suite.

Exercises the detection pipeline against synthetic logs in a temp directory.
Touches no firewall, no kernel set, and no system path — safe to run anywhere.
Usage: python3 tests/smoke_test.py
"""
import json
import os
import shutil
import sys
import tempfile
import time

# Resolve lib/py relative to this file so the suite runs from the repo or /opt/logwall.
BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib", "py")
sys.path.insert(0, os.path.normpath(BASE))

work = tempfile.mkdtemp(prefix="logwall_test_")
state = os.path.join(work, "state")
os.makedirs(state, exist_ok=True)


def write(name, text):
    path = os.path.join(work, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


conf = write("logwall.conf", f"""
WHITELIST={work}/whitelist.txt
BLACKLIST={work}/blacklist.txt
SKIP_LIST={work}/bypass.txt
CDN_NETS_FILE={work}/cdn.txt
STATE_DIR={state}
THRESHOLD_HITS=10
THRESHOLD_WP_LOGIN=3
THRESHOLD_XMLRPC=2
THRESHOLD_SENSITIVE_SCAN=2
THRESHOLD_BW_MB=1
WINDOW_HOURS=24
MAX_NEW_BLOCKS_PER_RUN=50
TEMP_BLOCK_HOURS=48
BLOCK_ESCALATION=1
GOOGLE_BOT_NETS="66.249.64.0/19"
REVIEW_SCHEDULE="0 3 * * 1"   # inline comment must be stripped
""")
write("whitelist.txt", "# admin\n203.0.113.0/24\n2001:db8:cafe::/48\n")
write("blacklist.txt", "")
write("bypass.txt", "# googlebot\n66.249.64.0/19\n")
write("cdn.txt", "# cloudflare\n104.16.0.0/13\n172.64.0.0/13\n")

os.environ["LOGWALL_CONF"] = conf
for key in ("WHITELIST", "BLACKLIST", "SKIP_LIST", "CDN_NETS_FILE", "STATE_DIR"):
    os.environ.pop(key, None)

import config_loader
import ip_guard
import log_parser
import apply_engine

failures = []


def check(label, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}" + (f"  -> {detail}" if detail else ""))
    if not condition:
        failures.append(label)


# ---------------------------------------------------------------- config
cfg = config_loader.load_config(conf)
check("config: file is parsed", cfg.get("THRESHOLD_HITS") == "10", cfg.get("THRESHOLD_HITS"))
check("config: inline comment stripped",
      cfg.get("GOOGLE_BOT_NETS") == "66.249.64.0/19", repr(cfg.get("GOOGLE_BOT_NETS")))
check("config: quoted value with spaces kept",
      cfg.get("REVIEW_SCHEDULE") == "0 3 * * 1", repr(cfg.get("REVIEW_SCHEDULE")))

# ---------------------------------------------------------------- ip_guard
guard = ip_guard.IPGuard(cfg)
check("guard: CIDR whitelist protects a member address",
      guard.refusal_reason("203.0.113.5") == ip_guard.REFUSE_WHITELIST,
      guard.refusal_reason("203.0.113.5"))
check("guard: IPv6 CIDR whitelist works",
      guard.refusal_reason("2001:db8:cafe::99") == ip_guard.REFUSE_WHITELIST)
check("guard: CDN edge is hard-guarded",
      guard.refusal_reason("104.16.1.1") == ip_guard.REFUSE_CDN)
check("guard: Googlebot range bypassed",
      guard.refusal_reason("66.249.66.1") == ip_guard.REFUSE_BYPASS)
check("guard: RFC1918 refused by default",
      guard.refusal_reason("192.168.1.50") == ip_guard.REFUSE_PRIVATE)
check("guard: loopback refused", guard.refusal_reason("127.0.0.1") is not None)
check("guard: ordinary public IP is blockable", guard.refusal_reason("185.199.108.153") is None)
check("guard: garbage rejected", guard.refusal_reason("not-an-ip") == ip_guard.REFUSE_INVALID)

# ------------------------------------------------------- IPv6 not truncated
check("parse: IPv6 survives intact", str(ip_guard.parse_ip("2001:db8::5")) == "2001:db8::5",
      str(ip_guard.parse_ip("2001:db8::5")))
check("parse: IPv4 with port trimmed", str(ip_guard.parse_ip("185.199.108.153:443")) == "185.199.108.153")

# ------------------------------------------------- sliding window across runs
log_path = write("access.log", "")
attacker = "185.199.108.153"


def append_hits(count, uri="/index.html", status=200, size=100):
    with open(log_path, "a", encoding="utf-8") as f:
        for _ in range(count):
            f.write(f'{attacker} - - [12/Aug/2026:10:00:00 +0700] "GET {uri} HTTP/1.1" '
                    f'{status} {size} "-" "curl/8"\n')


parser = log_parser.LogParserEngine(cfg)
parser.cdn_check = guard.is_cdn_edge_ip

append_hits(6)
m1 = parser.analyze_traffic([log_path])
parser.save_state()
check("window: run 1 counts 6 hits", m1["hits"].get(attacker) == 6, m1["hits"].get(attacker))

parser2 = log_parser.LogParserEngine(cfg)
parser2.cdn_check = guard.is_cdn_edge_ip
append_hits(6)
m2 = parser2.analyze_traffic([log_path])
parser2.save_state()
check("window: run 2 ACCUMULATES to 12 (the H4 fix)",
      m2["hits"].get(attacker) == 12, m2["hits"].get(attacker))

parser3 = log_parser.LogParserEngine(cfg)
parser3.cdn_check = guard.is_cdn_edge_ip
m3 = parser3.analyze_traffic([log_path])
check("window: run 3 with no new bytes does not double count",
      m3["hits"].get(attacker) == 12, m3["hits"].get(attacker))

# ---------------------------------------------- CDN peer without a real IP
cdn_log = write("cdn.log", "")
with open(cdn_log, "a", encoding="utf-8") as f:
    for _ in range(30):
        f.write('104.16.5.5 - - [12/Aug/2026:10:00:00 +0700] "GET / HTTP/1.1" 200 100 "-" "x"\n')
p_cdn = log_parser.LogParserEngine(cfg)
p_cdn.cdn_check = guard.is_cdn_edge_ip
m_cdn = p_cdn.analyze_traffic([cdn_log])
check("cdn: edge traffic with no real IP is not counted",
      m_cdn["hits"].get("104.16.5.5", 0) == 0, m_cdn["hits"].get("104.16.5.5", 0))
check("cdn: log flagged CDN_NO_REALIP", bool(p_cdn.flags["CDN_NO_REALIP"]))

# ------------------------------------------- CDN peer WITH a forwarded real IP
xff_log = write("xff.log", "")
with open(xff_log, "a", encoding="utf-8") as f:
    for _ in range(30):
        f.write('104.16.5.5 - - [12/Aug/2026:10:00:00 +0700] "GET / HTTP/1.1" 200 100 '
                '"-" "x" "203.0.113.44"\n')
p_xff = log_parser.LogParserEngine(cfg)
p_xff.cdn_check = guard.is_cdn_edge_ip
m_xff = p_xff.analyze_traffic([xff_log])
check("cdn: real IP recovered from the trailing XFF field",
      m_xff["hits"].get("203.0.113.44", 0) == 30, m_xff["hits"].get("203.0.113.44", 0))

# --------------------------------------------------------- parse-fail sanity
junk = write("junk.log", "this is not a web server log at all\n" * 50)
p_junk = log_parser.LogParserEngine(cfg)
p_junk.cdn_check = guard.is_cdn_edge_ip
p_junk.analyze_traffic([junk])
check("sanity: unparseable log raises PARSE_FAIL", bool(p_junk.flags["PARSE_FAIL"]))

# ------------------------------------------------------- escalation ladder
line = "185.199.108.9    # 2026-08-12 10:00 | CloudScraper | TEMP | strike=1 | expires=1000"
entry = apply_engine.parse_blacklist_line(line)
check("blacklist: current format parsed",
      entry and entry.tier == "TEMP" and entry.strike == 1 and entry.expires == 1000)
legacy = apply_engine.parse_blacklist_line("185.199.108.10    # 2026-08-01 09:00 | BruteForce")
check("blacklist: legacy format upgraded to PERMANENT",
      legacy and legacy.tier == "PERMANENT", legacy.tier if legacy else None)
check("blacklist: malformed line rejected",
      apply_engine.parse_blacklist_line("garbage line here") is None)
check("comment: shell metacharacters stripped for ipset",
      apply_engine.sanitize_comment('bad"; rm -rf /; #`whoami`') ==
      "bad rm -rf / whoami",
      apply_engine.sanitize_comment('bad"; rm -rf /; #`whoami`'))

# ------------------------------------------------------------- full apply run
#
# Log discovery must be silenced, or the engine walks the HOST's access logs.
# On a workstation there are none and the test looks correct; on a live web
# server it swept 557 real visitors into the run, tripped the circuit breaker,
# and returned EXIT_BREAKER instead of 0 — a failure that looked like a Python
# version problem and was nothing of the sort.
engine = apply_engine.ApplyEngine(cfg)
engine.audit.parser.discover_log_files = lambda *a, **k: []
engine.audit.parser.discover_auth_logs = lambda *a, **k: []
engine.audit.parser.cdn_check = engine.guard.is_cdn_edge_ip
engine.audit.parser.cursors = {}
code, entries = engine.execute()
check("apply: exits 0", code == 0, code)
check("apply: attacker blocked as TEMP (volume detection)",
      attacker in entries and entries[attacker].tier == "TEMP",
      entries.get(attacker).tier if attacker in entries else "absent")
check("apply: whitelisted IP never blocked", "203.0.113.5" not in entries)
check("apply: CDN edge never blocked", "104.16.5.5" not in entries)

script = os.path.join(work, "ipset.script")
total, white = engine.emit_ipset_script(entries, script)
content = open(script, encoding="utf-8").read()
check("ipset: script uses an atomic swap", "swap LOGWALL_BL4_TMP LOGWALL_BL4" in content)
check("ipset: whitelist CIDR pushed into the kernel set",
      "add LOGWALL_WL4_TMP 203.0.113.0/24" in content)
check("ipset: attacker present in blacklist set", f"add LOGWALL_BL4_TMP {attacker}" in content)

# ------------------------------------------------------------ circuit breaker
engine2 = apply_engine.ApplyEngine(cfg)
engine2.audit.parser.discover_log_files = lambda *a, **k: []
engine2.audit.parser.discover_auth_logs = lambda *a, **k: []
engine2.max_new_blocks = 0
engine2.audit.evaluate_candidates = lambda *a, **k: {
    "185.199.108.200": {"reason": "test", "tier": "PERMANENT"}}
code2, _ = engine2.execute()
check("breaker: trips and returns exit code 6", code2 == 6, code2)
after = open(os.path.join(work, "blacklist.txt"), encoding="utf-8").read()
check("breaker: nothing was written to the blacklist", "185.199.108.200" not in after)

# ------------------------------------------- web server log format fixtures
# Parsing is pure file I/O, so every supported web server is covered offline —
# no nginx, Apache, LiteSpeed, or Caddy has to be running anywhere.
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def parse_fixture(name, cdn_check=None):
    """Runs one fixture through a parser with a private state dir."""
    fx_state = os.path.join(work, "fx_state_" + name)
    os.makedirs(fx_state, exist_ok=True)
    fx_cfg = dict(cfg)
    fx_cfg["STATE_DIR"] = fx_state
    parser_fx = log_parser.LogParserEngine(fx_cfg)
    parser_fx.cdn_check = cdn_check if cdn_check is not None else guard.is_cdn_edge_ip
    metrics = parser_fx.analyze_traffic([os.path.join(FIXTURES, name)])
    return parser_fx, metrics


p, m = parse_fixture("nginx_combined.log")
check("fmt nginx: hits counted", m["hits"].get("185.199.108.10") == 2, m["hits"])
check("fmt nginx: wp-login detected", m["wp_login"].get("185.199.108.10") == 1)
check("fmt nginx: xmlrpc detected", m["xmlrpc"].get("185.199.108.11") == 1)
check("fmt nginx: sensitive file scan detected", m["scan"].get("185.199.108.11") == 1)
check("fmt nginx: bandwidth summed", m["bw"].get("185.199.108.10") == 5120 + 512,
      m["bw"].get("185.199.108.10"))
check("fmt nginx: 401 counted for panel brute force",
      m["panel_401"].get("185.199.108.10") == 1)
# The key is the /64, not the address: IPV6_BLOCK_PREFIX collapses IPv6 to the
# block a customer is actually handed. Both halves are asserted — the /64 carries
# the count AND the bare address is gone — so a silent regression to per-/128
# counting cannot pass.
check("fmt nginx: bare IPv6 client parsed, counted as its /64",
      m["hits"].get("2606:4700:20::/64") == 1,
      [k for k in m["hits"] if ":" in k])
check("fmt nginx: the /128 is NOT counted separately",
      "2606:4700:20::1" not in m["hits"],
      [k for k in m["hits"] if ":" in k])

# The FastPanel backend format carries ONE placeholder instead of two. Positional
# splitting silently produced a garbage URI and zero bytes here.
p, m = parse_fixture("fastpanel_backend.log")
check("fmt backend: one-placeholder variant parses", m["hits"].get("185.199.108.20") == 2,
      m["hits"])
check("fmt backend: URI extracted correctly (not the protocol token)",
      m["wp_login"].get("185.199.108.20") == 1, m["wp_login"])
check("fmt backend: bytes are real, not zero",
      m["bw"].get("185.199.108.20") == 10240 + 12288, m["bw"].get("185.199.108.20"))
check("fmt backend: phpmyadmin probe flagged as recon",
      m["scan"].get("185.199.108.21") == 1)
check("fmt backend: not reported as PARSE_FAIL", not p.flags["PARSE_FAIL"])

p, m = parse_fixture("apache_combined.log")
check("fmt apache: '-' byte field treated as zero",
      m["bw"].get("185.199.108.30") == 4096, m["bw"].get("185.199.108.30"))
check("fmt apache: authenticated-user field tolerated",
      m["hits"].get("185.199.108.31") == 1, m["hits"])

p, m = parse_fixture("litespeed.log")
check("fmt litespeed: parsed", m["hits"].get("185.199.108.40") == 2)
check("fmt litespeed: .sql probe flagged as recon", m["scan"].get("185.199.108.40") == 1)

p, m = parse_fixture("caddy.log")
check("fmt caddy: JSON lines parsed", m["hits"].get("185.199.108.50") == 2, m["hits"])
check("fmt caddy: uri field read from JSON", m["xmlrpc"].get("185.199.108.50") == 1)
check("fmt caddy: size field read from JSON",
      m["bw"].get("185.199.108.50") == 8192 + 256, m["bw"].get("185.199.108.50"))
check("fmt caddy: Cf-Connecting-Ip overrides the CDN peer",
      m["hits"].get("185.199.108.51") == 1 and m["hits"].get("104.16.5.5", 0) == 0,
      m["hits"])

p, m = parse_fixture("nginx_behind_cdn.log")
check("fmt cdn: real IP recovered from the trailing XFF field",
      m["hits"].get("185.199.108.60") == 2, m["hits"])
check("fmt cdn: line without a real IP is not counted against the edge",
      m["hits"].get("104.16.5.5", 0) == 0)
check("fmt cdn: unresolvable line flagged CDN_NO_REALIP", bool(p.flags["CDN_NO_REALIP"]))

p, m = parse_fixture("unknown_format.log")
check("fmt unknown: raises PARSE_FAIL instead of reporting 'no attacks'",
      bool(p.flags["PARSE_FAIL"]), p.flags["PARSE_FAIL"])
check("fmt unknown: nothing counted", not m["hits"])

# --------------------------------------------------- streaming (memory safety)
check("parser streams instead of materialising the file",
      hasattr(log_parser.LogParserEngine.parse_log_file, "__code__")
      and bool(log_parser.LogParserEngine.parse_log_file.__code__.co_flags & 0x20))

# -------------------------------------------------- failed service logins (auth)
auth_state = os.path.join(work, "auth_state")
os.makedirs(auth_state, exist_ok=True)
auth_cfg = dict(cfg)
auth_cfg["STATE_DIR"] = auth_state
p_auth = log_parser.LogParserEngine(auth_cfg)
p_auth.cdn_check = guard.is_cdn_edge_ip
m_auth = p_auth.analyze_traffic([], [os.path.join(FIXTURES, "auth_secure.log")])
af = m_auth["auth_fail"]

check("auth: sshd failed passwords counted", af.get("185.199.108.80") == 3, af)
check("auth: preauth/max-attempts variants counted", af.get("185.199.108.81") == 2, af)
check("auth: dovecot IMAP/POP3 failures counted", af.get("185.199.108.82") == 2, af)
check("auth: exim SMTP AUTH failure counted", af.get("185.199.108.83") == 1, af)
check("auth: IPv6 attacker counted, keyed by /64",
      af.get("2001:db8:beef::/64") == 1, af)
check("auth: a SUCCESSFUL login never counts",
      af.get("203.0.113.9", 0) == 0, af.get("203.0.113.9", 0))
# Entries are created with every metric zeroed, so the web counters legitimately
# list these addresses — what matters is that none of them registers a hit.
check("auth: no web hit is invented for an auth-only offender",
      all(v == 0 for v in m_auth["hits"].values()), m_auth["hits"])

# Taken from a real mail server: these lines contain the words "auth" and
# "failed" but describe a dropped connection or an unsupported SASL mechanism,
# not a rejected credential. Counting them would block clients with flaky links.
check("auth: 'no auth attempts' abort is NOT a failure",
      af.get("185.199.108.90", 0) == 0, af.get("185.199.108.90", 0))
check("auth: unsupported SASL mechanism is NOT a failure",
      af.get("185.199.108.91", 0) == 0, af.get("185.199.108.91", 0))
check("auth: plain preauth disconnect without a username is NOT a failure",
      af.get("185.199.108.92", 0) == 0, af.get("185.199.108.92", 0))

# ------------------------------------------------------ DDNS admin whitelist
import ddns_resolver

# `.invalid` is reserved by RFC 2606 and can never resolve, so the resolver that
# IPGuard builds for itself is guaranteed to fall through to the cache instead of
# reaching a real nameserver from the test machine.
hosts_file = write("whitelist_hosts.txt",
                   "# admin ddns\nadmin.logwall-test.invalid\ndead.logwall-test.invalid\n")
ddns_cfg = dict(cfg)
ddns_cfg["WHITELIST_DYNAMIC_HOSTS"] = hosts_file

resolver = ddns_resolver.DDNSResolver(ddns_cfg)
# No network in the test environment: substitute the lookup, never monkeypatch
# the socket module itself.
resolver._lookup = lambda host: ["185.199.110.99"] if host == "admin.logwall-test.invalid" else []
first = resolver.resolve()
check("ddns: a resolving hostname yields its address", first == ["185.199.110.99"], first)
check("ddns: a hostname that never resolved is reported as failed",
      resolver.failed_hosts == ["dead.logwall-test.invalid"], resolver.failed_hosts)

# Second run with DNS completely down must still return the cached answer —
# a resolver outage may not revoke the administrator's access.
resolver2 = ddns_resolver.DDNSResolver(ddns_cfg)
resolver2._lookup = lambda host: []
second = resolver2.resolve()
check("ddns: DNS outage falls back to the cached address (fail-safe)",
      second == ["185.199.110.99"], second)
check("ddns: the stale answer is flagged, not silently trusted",
      resolver2.stale_hosts == ["admin.logwall-test.invalid"], resolver2.stale_hosts)
check("ddns: stale entry produces a report line",
      any("DDNS_STALE" in line for line in resolver2.report_lines()))

guard_ddns = ip_guard.IPGuard(ddns_cfg)
check("ddns: resolved address is treated as whitelisted",
      guard_ddns.refusal_reason("185.199.110.99") == ip_guard.REFUSE_WHITELIST,
      guard_ddns.refusal_reason("185.199.110.99"))

eng_ddns = apply_engine.ApplyEngine(ddns_cfg)
ddns_script = os.path.join(work, "ddns.script")
eng_ddns.emit_ipset_script({}, ddns_script)
ddns_body = open(ddns_script, encoding="utf-8").read()
check("ddns: resolved address is pushed into the kernel whitelist set",
      "add LOGWALL_WL4_TMP 185.199.110.99/32" in ddns_body)

# ==================== browser vs script: telling a visitor from a scraper =====
from log_parser import classify_uri, classify_user_agent

check("profile: stylesheet is an asset", classify_uri("/theme/style.css"))
check("profile: font is an asset", classify_uri("/static/fonts/inter.woff2"))
check("profile: query string does not hide the extension",
      classify_uri("/app.js?v=1.2.3"))
check("profile: wp-content path counts as an asset", classify_uri("/wp-content/uploads/x"))
check("profile: an article page is NOT an asset",
      not classify_uri("/artikel/hukum-acara"))
check("profile: an API endpoint is NOT an asset",
      not classify_uri("/api/produk?page=2"))
check("profile: curl declares itself", classify_user_agent("curl/8.4.0"))
check("profile: python-requests declares itself",
      classify_user_agent("python-requests/2.31.0"))
check("profile: an empty UA counts as script-like", classify_user_agent("-"))
check("profile: Chrome does not declare itself",
      not classify_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0"))

prof_state = os.path.join(work, "prof_state")
os.makedirs(prof_state, exist_ok=True)
prof_cfg = dict(cfg)
prof_cfg["STATE_DIR"] = prof_state
prof_cfg["ASSET_MIN_SAMPLES"] = "4"
pp = log_parser.LogParserEngine(prof_cfg)
pp.cdn_check = guard.is_cdn_edge_ip
mp = pp.analyze_traffic([os.path.join(FIXTURES, "browser_vs_script.log")])

check("profile: browser client counted mostly assets",
      mp["assets"].get("203.0.113.201") == 4 and mp["pages"].get("203.0.113.201") == 1,
      (mp["assets"].get("203.0.113.201"), mp["pages"].get("203.0.113.201")))
check("profile: scraper with a Chrome UA fetched ZERO assets",
      mp["assets"].get("185.199.120.10") == 0 and mp["pages"].get("185.199.120.10") == 5,
      (mp["assets"].get("185.199.120.10"), mp["pages"].get("185.199.120.10")))
check("profile: self-declared tool is flagged even though volume is low",
      mp["script_ua"].get("185.199.120.11") == 2, mp["script_ua"])

# Same request count, opposite verdict — this is the whole point.
prof2 = dict(prof_cfg)
prof2["THRESHOLD_HITS"] = "4"
prof2["SUBNET_DETECTION"] = "0"
prof2["BROWSER_TOLERANCE_FACTOR"] = "3"
pe2 = log_parser.LogParserEngine(dict(prof2, STATE_DIR=os.path.join(work, "prof2")))
pe2.discover_log_files = lambda *a, **k: []
pe2.discover_auth_logs = lambda *a, **k: []
now_p = int(time.time())
for _ in range(5):                       # browser: 5 pages + 40 assets
    pe2.window.add("203.0.113.210", "hits", 1, now_p)
    pe2.window.add("203.0.113.210", "pages", 1, now_p)
for _ in range(40):
    pe2.window.add("203.0.113.210", "hits", 1, now_p)
    pe2.window.add("203.0.113.210", "assets", 1, now_p)
for _ in range(45):                      # script: 45 pages, no assets
    pe2.window.add("185.199.121.9", "hits", 1, now_p)
    pe2.window.add("185.199.121.9", "pages", 1, now_p)

ae2 = apply_engine.ApplyEngine(dict(prof2, STATE_DIR=os.path.join(work, "prof2")))
ae2.audit.parser = pe2
pe2.cdn_check = ae2.guard.is_cdn_edge_ip
v2 = ae2.audit.evaluate_candidates()

check("profile: identical volume — the script IS flagged",
      "185.199.121.9" in v2, sorted(v2))
check("profile: identical volume — the browser is NOT flagged",
      "203.0.113.210" not in v2, sorted(v2))
check("profile: a script-like client skips the grace round entirely",
      v2["185.199.121.9"]["tier"] == "PERMANENT", v2["185.199.121.9"]["tier"])
check("profile: the reason records the evidence",
      "assets 0%" in v2["185.199.121.9"]["reason"], v2["185.199.121.9"]["reason"])

# A site that serves its assets from a CDN must not have every visitor profiled
# as a script.
pe3 = log_parser.LogParserEngine(dict(prof2, STATE_DIR=os.path.join(work, "prof3")))
pe3.discover_log_files = lambda *a, **k: []
pe3.discover_auth_logs = lambda *a, **k: []
for host in range(1, 6):                 # everyone fetches pages only
    for _ in range(45):
        pe3.window.add(f"203.0.113.{220+host}", "hits", 1, now_p)
        pe3.window.add(f"203.0.113.{220+host}", "pages", 1, now_p)
ae3 = apply_engine.ApplyEngine(dict(prof2, STATE_DIR=os.path.join(work, "prof3")))
ae3.audit.parser = pe3
pe3.cdn_check = ae3.guard.is_cdn_edge_ip
ae3.audit.evaluate_candidates()
check("profile: profiling disables itself when the SITE has no assets in its log",
      ae3.audit.profiling is False, ae3.audit.profiling)
check("profile: and says so in the health flags",
      "PROFILING_OFF" in ae3.audit.health_flags())

# ============ escalation memory: TEMP expires, offender returns, goes permanent
esc_state = os.path.join(work, "esc_state")
os.makedirs(esc_state, exist_ok=True)
esc_cfg = dict(cfg)
esc_cfg["STATE_DIR"] = esc_state
esc_cfg["BLACKLIST"] = os.path.join(work, "esc_blacklist.txt")
esc_cfg["SUBNET_DETECTION"] = "0"
esc_cfg["TEMP_BLOCK_HOURS"] = "48"
esc_cfg["ESCALATE_IMMEDIATE_FACTOR"] = "10"
REPEAT = "185.199.111.50"
now_e = int(time.time())


LF = chr(10)


def run_escalation(hits, blacklist_body=None, history=None):
    if blacklist_body is not None:
        with open(esc_cfg["BLACKLIST"], "w", encoding="utf-8", newline=LF) as f:
            f.write(blacklist_body)
    if history is not None:
        import json as _json
        with open(os.path.join(esc_state, "offender_history.json"), "w",
                  encoding="utf-8", newline=LF) as f:
            _json.dump(history, f)
    pe = log_parser.LogParserEngine(esc_cfg)
    pe.discover_log_files = lambda *a, **k: []
    pe.discover_auth_logs = lambda *a, **k: []
    if hits:
        pe.window.add(REPEAT, "hits", hits, now_e)
    ee = apply_engine.ApplyEngine(esc_cfg)
    ee.audit.parser = pe
    pe.cdn_check = ee.guard.is_cdn_edge_ip
    _, ents = ee.execute()
    return ee, ents


# First offence: modest excess (500 vs threshold 10 = 50x)... use a small excess
esc_cfg["THRESHOLD_HITS"] = "400"
eng_a, ents_a = run_escalation(500, blacklist_body="", history={})
check("escalation: first volume offence is TEMPORARY",
      ents_a[REPEAT].tier == "TEMP" and ents_a[REPEAT].strike == 1,
      (ents_a[REPEAT].tier, ents_a[REPEAT].strike))

# The temporary block has expired and the same address is active again.
expired_line = (f"{REPEAT}    # 2026-08-11 07:00 | CloudScraper | TEMP | "
                f"strike=1 | expires={now_e - 10}" + LF)
eng_b, ents_b = run_escalation(500, blacklist_body=expired_line,
                               history={REPEAT: {"strike": 1, "last": now_e - 172800}})
check("escalation: the expired temporary block is released",
      REPEAT in eng_b.expired, eng_b.expired)
check("escalation: the returning offender is remembered and promoted",
      REPEAT in eng_b.escalated, eng_b.escalated)
check("escalation: it is now PERMANENT with strike=2",
      ents_b[REPEAT].tier == "PERMANENT" and ents_b[REPEAT].strike == 2,
      (ents_b[REPEAT].tier, ents_b[REPEAT].strike))
check("escalation: a permanent entry never expires",
      ents_b[REPEAT].expires is None)

# Excess far beyond the threshold is not ambiguous: no grace round at all.
eng_c, ents_c = run_escalation(50000, blacklist_body="", history={})
check("escalation: extreme excess is PERMANENT on first sighting",
      ents_c[REPEAT].tier == "PERMANENT", ents_c[REPEAT].tier)

# Zero-tolerance mode reproduces the old always-permanent behaviour.
zero_cfg = dict(esc_cfg)
zero_cfg["BLOCK_ESCALATION"] = "0"
pz = log_parser.LogParserEngine(zero_cfg)
pz.discover_log_files = lambda *a, **k: []
pz.discover_auth_logs = lambda *a, **k: []
pz.window.add("185.199.112.7", "hits", 500, now_e)
ez = apply_engine.ApplyEngine(zero_cfg)
ez.audit.parser = pz
pz.cdn_check = ez.guard.is_cdn_edge_ip
verdict_z = ez.audit.evaluate_candidates()
check("escalation: BLOCK_ESCALATION=0 blocks permanently on first sighting",
      verdict_z["185.199.112.7"]["tier"] == "PERMANENT",
      verdict_z["185.199.112.7"]["tier"])

# ================= subnet aggregation: the distributed-flood scenario =========
# Reproduces a real incident: ~1M requests spread over hundreds of addresses that
# all belonged to two /24s owned by one company. Counted per address, each member
# creeps toward the threshold separately and the circuit breaker then sees
# hundreds of candidates at once and blocks nothing.
sub_state = os.path.join(work, "sub_state")
os.makedirs(sub_state, exist_ok=True)
sub_cfg = dict(cfg)
sub_cfg["STATE_DIR"] = sub_state
sub_cfg["SUBNET_MIN_IPS"] = "5"
sub_cfg["THRESHOLD_SUBNET_HITS"] = "2000"
sub_cfg["MAX_NEW_BLOCKS_PER_RUN"] = "50"

flood = log_parser.LogParserEngine(sub_cfg)
# Must be "now": the sliding window prunes anything older than WINDOW_HOURS, and
# a fixed epoch would silently age out before the subnet pass ever sees it.
now_ts = int(time.time())
# Isolate from whatever logs happen to exist on the machine running the suite.
flood.discover_log_files = lambda *a, **k: []
flood.discover_auth_logs = lambda *a, **k: []
# 2 networks x 250 hosts x 45 hits = 22,500 hits per network
for third in (7, 8):
    for host in range(1, 251):
        for _ in range(45):
            flood.window.add(f"185.199.{third}.{host}", "hits", 1, now_ts)
# one lone heavy host in an unrelated /24 — must NOT drag its neighbours in
for _ in range(9000):
    flood.window.add("185.199.9.99", "hits", 1, now_ts)

rollup = flood.window.subnet_rollup(24, 64)
check("subnet: rollup groups hosts into their /24",
      rollup.get("185.199.7.0/24", {}).get("members") == 250,
      rollup.get("185.199.7.0/24", {}).get("members"))
check("subnet: rollup sums the whole network's hits",
      rollup["185.199.7.0/24"]["hits"] == 250 * 45,
      rollup["185.199.7.0/24"]["hits"])

sub_engine = apply_engine.ApplyEngine(sub_cfg)
sub_engine.audit.parser = flood
sub_engine.audit.parser.cdn_check = sub_engine.guard.is_cdn_edge_ip
verdict = sub_engine.audit.evaluate_candidates()

check("subnet: the two coordinated networks are proposed as RANGES",
      "185.199.7.0/24" in verdict and "185.199.8.0/24" in verdict,
      sorted(k for k in verdict if "/" in k))
check("subnet: member addresses are NOT listed separately",
      not any(k.startswith("185.199.7.") and "/" not in k for k in verdict),
      [k for k in verdict if k.startswith("185.199.7.") and "/" not in k])
check("subnet: 500 candidates collapse to a handful",
      len(verdict) <= 3, len(verdict))
check("subnet: below the breaker limit, so blocking actually happens",
      len(verdict) <= int(sub_cfg["MAX_NEW_BLOCKS_PER_RUN"]), len(verdict))
check("subnet: a lone heavy host is blocked as a HOST, not as its /24",
      "185.199.9.99" in verdict and "185.199.9.0/24" not in verdict,
      [k for k in verdict if k.startswith("185.199.9")])

# ---- IPv6 counted per /64: a rotating client is one visitor ----------------
# Privacy extensions rotate the host portion every few hours by default, so per
# address counting splits one visitor across many keys and none of them reaches
# the threshold. Before this, six rotations at 200 hits each produced six keys of
# 200 against a threshold of 400 — 1,200 requests, nothing detected.
rot_state = os.path.join(work, "rot_state")
os.makedirs(rot_state, exist_ok=True)
rot_cfg = dict(cfg); rot_cfg["STATE_DIR"] = rot_state
rot = log_parser.LogParserEngine(rot_cfg)
for host in range(6):
    for _ in range(200):
        rot.window.add("2001:db8:abcd:1234:%x::1" % host, "hits", 1, now_ts)

check("v6 /64: six rotating addresses collapse to ONE counter",
      len(rot.window.entries) == 1, list(rot.window.entries)[:3])
check("v6 /64: the counter holds every request the visitor made",
      rot.window.entries.get("2001:db8:abcd:1234::/64", {}).get("hits") == 1200,
      rot.window.entries.get("2001:db8:abcd:1234::/64", {}).get("hits"))

# The escape hatch has to work, or a host with unusual v6 allocation is stuck.
per_state = os.path.join(work, "per_state")
os.makedirs(per_state, exist_ok=True)
per_cfg = dict(cfg); per_cfg["STATE_DIR"] = per_state; per_cfg["IPV6_BLOCK_PREFIX"] = "128"
per = log_parser.LogParserEngine(per_cfg)
for host in range(6):
    per.window.add("2001:db8:abcd:1234:%x::1" % host, "hits", 200, now_ts)
check("v6 /64: IPV6_BLOCK_PREFIX=128 restores per-address counting",
      len(per.window.entries) == 6, len(per.window.entries))

# A state file written before the change must fold on load, or one source is
# counted twice for a whole window — once under its old bare key, once under the
# /64 — and neither necessarily crosses a threshold the total would have.
mig_state = os.path.join(work, "mig_state")
os.makedirs(mig_state, exist_ok=True)
with open(os.path.join(mig_state, "window.json"), "w", encoding="utf-8") as fh:
    json.dump({"ips": {
        "2001:db8:aaaa:1::5":  {"hits": 300, "first": now_ts, "last": now_ts},
        "2001:db8:aaaa:1::99": {"hits": 250, "first": now_ts, "last": now_ts},
        "185.199.108.10":      {"hits": 10,  "first": now_ts, "last": now_ts},
    }}, fh)
mig_cfg = dict(cfg); mig_cfg["STATE_DIR"] = mig_state
mig = log_parser.LogParserEngine(mig_cfg)
check("v6 /64: an old state file folds its bare keys into the /64 on load",
      mig.window.entries.get("2001:db8:aaaa:1::/64", {}).get("hits") == 550,
      dict(mig.window.entries))
check("v6 /64: folding leaves IPv4 keys untouched",
      mig.window.entries.get("185.199.108.10", {}).get("hits") == 10,
      list(mig.window.entries))

# ---- second-tier IPv6 rollup: one address per /64 ---------------------------
# /64 is IPv6's single-allocation unit — the analogue of ONE IPv4 address. A
# crawler taking one address out of each of its /64s aggregates to nothing at
# /64: every network holds exactly one member, so the source arrives as dozens of
# separate candidates and the circuit breaker aborts the run.
#
# Measured on a production host: 82 addresses shaped 2a03:2880:f800:XX::, ~3,000
# hits each. 70 candidates at /64; the breaker tripped and nothing was blocked.
v6_state = os.path.join(work, "v6_state")
os.makedirs(v6_state, exist_ok=True)
v6_cfg = dict(sub_cfg)
v6_cfg["STATE_DIR"] = v6_state

v6 = log_parser.LogParserEngine(v6_cfg)
v6.discover_log_files = lambda *a, **k: []
v6.discover_auth_logs = lambda *a, **k: []
for block in range(20):
    for _ in range(300):
        v6.window.add("2a03:2880:f800:%x::" % block, "hits", 1, now_ts)

r64 = v6.window.subnet_rollup(24, 64)
r56 = v6.window.subnet_rollup(24, 56)
check("v6 wide: at /64 each address is alone — nothing aggregates",
      max(a["members"] for a in r64.values()) == 1,
      max(a["members"] for a in r64.values()))
check("v6 wide: at /56 they collapse into ONE network",
      r56.get("2a03:2880:f800::/56", {}).get("members") == 20,
      r56.get("2a03:2880:f800::/56", {}).get("members"))

v6_engine = apply_engine.ApplyEngine(v6_cfg)
v6_engine.audit.parser = v6
v6_engine.audit.parser.cdn_check = v6_engine.guard.is_cdn_edge_ip
v6_verdict = v6_engine.audit.evaluate_candidates()

check("v6 wide: the /56 is proposed as a single range",
      "2a03:2880:f800::/56" in v6_verdict,
      [k for k in v6_verdict if ":" in k])
check("v6 wide: the member /64s are NOT listed separately",
      not [k for k in v6_verdict if k.startswith("2a03:2880:f800:") and k != "2a03:2880:f800::/56"],
      [k for k in v6_verdict if ":" in k])
check("v6 wide: dozens of candidates collapse below the breaker limit",
      len(v6_verdict) < int(v6_cfg["MAX_NEW_BLOCKS_PER_RUN"]), len(v6_verdict))

# Below the evidence threshold nothing wide is proposed: a handful of /64s is not
# proof of one coordinated source, and a /56 holds 256 of them.
few_state = os.path.join(work, "few_state")
os.makedirs(few_state, exist_ok=True)
few_cfg = dict(v6_cfg); few_cfg["STATE_DIR"] = few_state
few = log_parser.LogParserEngine(few_cfg)
few.discover_log_files = lambda *a, **k: []
few.discover_auth_logs = lambda *a, **k: []
for block in range(3):
    for _ in range(3000):
        few.window.add("2a03:2880:f900:%x::" % block, "hits", 1, now_ts)
few_engine = apply_engine.ApplyEngine(few_cfg)
few_engine.audit.parser = few
few_engine.audit.parser.cdn_check = few_engine.guard.is_cdn_edge_ip
few_verdict = few_engine.audit.evaluate_candidates()
check("v6 wide: 3 /64s is below the threshold — no /56 proposed",
      "2a03:2880:f900::/56" not in few_verdict,
      [k for k in few_verdict if ":" in k])

# ---- guards on ranges: stricter than on single addresses --------------------
gnet = ip_guard.IPGuard(cfg)
check("subnet guard: a whitelisted host inside the range blocks the WHOLE range",
      gnet.refusal_reason_network("203.0.113.0/24") == ip_guard.REFUSE_WHITELIST,
      gnet.refusal_reason_network("203.0.113.0/24"))
check("subnet guard: a range overlapping a CDN is refused",
      gnet.refusal_reason_network("104.16.5.0/24") == ip_guard.REFUSE_CDN)
check("subnet guard: a range wider than the limit is refused",
      gnet.refusal_reason_network("185.199.0.0/16") == ip_guard.REFUSE_TOO_WIDE,
      gnet.refusal_reason_network("185.199.0.0/16"))
check("subnet guard: an ordinary public /24 is blockable",
      gnet.refusal_reason_network("185.199.7.0/24") is None,
      gnet.refusal_reason_network("185.199.7.0/24"))
check("subnet guard: RFC1918 range refused", 
      gnet.refusal_reason_network("192.168.1.0/24") == ip_guard.REFUSE_PRIVATE)

# ---- coordination requirement ----------------------------------------------
few_state = os.path.join(work, "few_state")
os.makedirs(few_state, exist_ok=True)
few_cfg = dict(sub_cfg)
few_cfg["STATE_DIR"] = few_state
few = log_parser.LogParserEngine(few_cfg)
few.discover_log_files = lambda *a, **k: []
few.discover_auth_logs = lambda *a, **k: []
for host in range(1, 4):            # only 3 hosts, below SUBNET_MIN_IPS=5
    for _ in range(5000):
        few.window.add(f"185.199.20.{host}", "hits", 1, now_ts)
few_engine = apply_engine.ApplyEngine(few_cfg)
few_engine.audit.parser = few
few_engine.audit.parser.cdn_check = few_engine.guard.is_cdn_edge_ip
few_verdict = few_engine.audit.evaluate_candidates()
check("subnet: fewer hosts than SUBNET_MIN_IPS never yields a range",
      "185.199.20.0/24" not in few_verdict,
      [k for k in few_verdict if "/" in k])

# ------------------------------------------------- CSF coordination delta list
eng_csf = apply_engine.ApplyEngine(cfg)
eng_csf.added = [
    apply_engine.BlacklistEntry("185.199.108.77", "2026-08-12 10:00",
                                'BruteForce | /wp-login.php | Hits: 9x',
                                "PERMANENT", 1, None),
]
csf_path = os.path.join(work, "csf_push.list")

def _entry(ip, reason="BruteForce | /wp-login.php | Hits: 9x"):
    return apply_engine.BlacklistEntry(ip, "2026-08-12 10:00", reason,
                                       "PERMANENT", 1, None)

csf_deny = os.path.join(work, "csf.deny")
eng_csf.config["CSF_DENY"] = csf_deny
open(csf_deny, "w", encoding="utf-8").close()

written = eng_csf.emit_csf_list({}, csf_path)
csf_body = open(csf_path, encoding="utf-8").read()
check("csf: newly added entries are emitted", written == 1, written)
check("csf: line is tab separated ip<TAB>reason",
      csf_body.startswith("185.199.108.77	BruteForce"), repr(csf_body[:40]))
check("csf: reason is sanitised for the shell",
      '"' not in csf_body and "`" not in csf_body and ";" not in csf_body)

# A blocklist seeded from a retired tool never reaches CSF if only "new this
# run" is pushed: the entries sit in blacklist_ips.txt while the run reports
# success. That is a whole migration silently enforcing nothing.
eng_csf.added = []
seeded = {ip: _entry(ip, "Legacy import") for ip in
          ("185.199.108.10", "185.199.108.11", "185.199.108.12")}
written = eng_csf.emit_csf_list(seeded, csf_path)
check("csf: seeded blacklist entries missing from csf.deny are pushed",
      written == 3, written)

# Once CSF already enforces them the delta is empty, so the steady state stays
# free — one file read, zero `csf -d` processes.
with open(csf_deny, "w", encoding="utf-8") as fh:
    fh.write("# comment\n")
    fh.write("tcp|in|d=22|s=1.2.3.4\n")          # port rule, not an address
    for ip in seeded:
        fh.write(f"{ip} # Blocked by logwall\n")
written = eng_csf.emit_csf_list(seeded, csf_path)
check("csf: addresses already in csf.deny are never re-pushed", written == 0, written)

# The cap keeps one cycle from spawning thousands of Perl processes.
eng_csf.config["CSF_RESYNC_MAX_PER_RUN"] = 2
open(csf_deny, "w", encoding="utf-8").close()
written = eng_csf.emit_csf_list(seeded, csf_path)
check("csf: catch-up is capped per run so a migration drains over cycles",
      written == 2, written)
eng_csf.config.pop("CSF_RESYNC_MAX_PER_RUN", None)

eng_csf.added = []
written = eng_csf.emit_csf_list({}, csf_path)
check("csf: nothing pending means an empty push list",
      written == 0 and open(csf_path, encoding="utf-8").read() == "")

# ------------------------------------------- range width guard, on its own
# A retired blocker may have blocked a /16. Carrying that over unexamined would
# take out 65k addresses on the strength of a decision nobody here reviewed —
# so the guard refuses anything wider than /24 and names its reason.
check("guard: a range wider than /24 is refused",
      guard.refusal_reason_network("57.141.0.0/16") == ip_guard.REFUSE_TOO_WIDE,
      guard.refusal_reason_network("57.141.0.0/16"))
check("guard: a /24 is accepted",
      guard.refusal_reason_network("74.7.242.0/24") is None,
      guard.refusal_reason_network("74.7.242.0/24"))


# ------------------------- v6 sets are only emitted when the host has IPv6 -----
# A `swap` against a set the Bash layer never created aborts the entire restore,
# taking the healthy v4 blocklist down with it.
os.environ["HAS_IPV6"] = "0"
eng_v4 = apply_engine.ApplyEngine(cfg)
v4_path = os.path.join(work, "v4only.script")
eng_v4.emit_ipset_script({}, v4_path)
body_v4 = open(v4_path, encoding="utf-8").read()
check("ipv6 off: no v6 set is created or swapped",
      "LOGWALL_BL6" not in body_v4 and "LOGWALL_WL6" not in body_v4,
      [l for l in body_v4.splitlines() if "6" in l][:2])
check("ipv6 off: the v4 sets are still emitted",
      "swap LOGWALL_BL4_TMP LOGWALL_BL4" in body_v4)

os.environ["HAS_IPV6"] = "1"
eng_v6 = apply_engine.ApplyEngine(cfg)
v6_path = os.path.join(work, "dual.script")
eng_v6.emit_ipset_script({}, v6_path)
body_v6 = open(v6_path, encoding="utf-8").read()
check("ipv6 on: both families are emitted",
      "swap LOGWALL_BL6_TMP LOGWALL_BL6" in body_v6 and
      "swap LOGWALL_BL4_TMP LOGWALL_BL4" in body_v6)
os.environ.pop("HAS_IPV6", None)

# --------------------------------------------- foreign set-name protection
check("naming: default sets are prefixed, never generic",
      all(name.startswith("LOGWALL_") for name in apply_engine.DEFAULT_SETS.values()),
      apply_engine.DEFAULT_SETS)
check("naming: generic names are on the reserved list",
      {"BLACKLIST_SET", "WHITELIST_SET"} <= apply_engine.RESERVED_FOREIGN_SETS)

hostile = dict(cfg)
hostile["SET_BLACK4"] = "BLACKLIST_SET"
try:
    apply_engine.ApplyEngine(hostile)
    refused = False
except SystemExit:
    refused = True
check("naming: refuses to manage another tool's BLACKLIST_SET", refused)

custom = dict(cfg)
custom["SET_BLACK4"] = "LOGWALL_CUSTOM4"
eng3 = apply_engine.ApplyEngine(custom)
tmp_script = os.path.join(work, "custom.script")
eng3.emit_ipset_script({}, tmp_script)
body = open(tmp_script, encoding="utf-8").read()
check("naming: configured set name is honoured end to end",
      "swap LOGWALL_CUSTOM4_TMP LOGWALL_CUSTOM4" in body)
check("naming: generic set name never appears in the emitted script",
      "BLACKLIST_SET" not in body and "WHITELIST_SET" not in body)

print()
if failures:
    print(f"RESULT: {len(failures)} FAILURE(S): {failures}")
else:
    print("RESULT: all checks passed")
shutil.rmtree(work, ignore_errors=True)
sys.exit(1 if failures else 0)
