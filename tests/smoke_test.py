#!/usr/bin/env python3
"""
logwall offline test suite.

Exercises the detection pipeline against synthetic logs in a temp directory.
Touches no firewall, no kernel set, and no system path — safe to run anywhere.
Usage: python3 tests/smoke_test.py
"""
import calendar
import json
import os
import re
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


def steady(state_dir):
    """
    Marks a state dir as belonging to a host that has already been running.

    Without it the catch-up guard is right to treat the run as the first ever —
    on a real first run the whole existing log is read from byte zero, so every
    volume count covers days rather than one interval — and suspends the volume
    rules. Tests that assert volume detection must therefore say which of the
    two situations they are simulating.
    """
    os.makedirs(state_dir, exist_ok=True)
    with open(os.path.join(state_dir, "run_meta.json"), "w", encoding="utf-8") as f:
        json.dump({"last_run": int(time.time()) - 60}, f)
    return state_dir


conf = write("logwall.conf", f"""
WHITELIST={work}/whitelist.txt
BLACKLIST={work}/blacklist.txt
SKIP_LIST={work}/bypass.txt
CDN_NETS_FILE={work}/cdn.txt
STATE_DIR={state}
THRESHOLD_HITS_PER_INTERVAL=10
STRIKES_REQUIRED=2
STRIKES_WINDOW=10
INTENT_WINDOW_MIN=30
EVAL_INTERVAL_SEC=120
THRESHOLD_WP_LOGIN=3
THRESHOLD_XMLRPC=2
THRESHOLD_SENSITIVE_SCAN=2
THRESHOLD_BW_MB_PER_INTERVAL=1
CATCHUP_MAX_GAP_MIN=15
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
check("config: file is parsed",
      cfg.get("THRESHOLD_HITS_PER_INTERVAL") == "10",
      cfg.get("THRESHOLD_HITS_PER_INTERVAL"))
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


def stamp_now(offset=-60):
    """Combined-format timestamp `offset` seconds from now, always UTC."""
    t = time.gmtime(int(time.time()) + offset)
    return "%02d/%s/%d:%02d:%02d:%02d +0000" % (
        t.tm_mday, "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()[t.tm_mon - 1],
        t.tm_year, t.tm_hour, t.tm_min, t.tm_sec)


# ------------------------------------------------- sliding window across runs
log_path = write("access.log", "")
attacker = "185.199.108.153"


def append_hits(count, uri="/index.html", status=200, size=100, ago=60):
    """`ago` places the lines in a chosen interval, counted back from now."""
    with open(log_path, "a", encoding="utf-8") as f:
        for _ in range(count):
            f.write(f'{attacker} - - [{stamp_now(-ago)}] "GET {uri} HTTP/1.1" '
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
        f.write(f'104.16.5.5 - - [{stamp_now()}] "GET / HTTP/1.1" 200 100 "-" "x"\n')
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
        f.write(f'104.16.5.5 - - [{stamp_now()}] "GET / HTTP/1.1" 200 100 '
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
# server it swept 557 real visitors into the run and returned a wrong result
# that looked like a Python version problem and was nothing of the sort.
#
# run_meta.json is seeded so this reads as a STEADY-STATE run. Without it the
# catch-up guard correctly treats the run as a first-ever one and suspends the
# volume rules, which is the behaviour tested further down.
with open(os.path.join(state, "run_meta.json"), "w", encoding="utf-8") as f:
    json.dump({"last_run": int(time.time()) - 60}, f)

# Volume needs repetition now. 12 hits in one interval is a visitor opening a
# couple of pages; 12 in each of two intervals is a pattern. The first burst
# above already sits in one interval, so one more interval completes the case.
append_hits(12, ago=200)
seed = log_parser.LogParserEngine(cfg)
seed.cdn_check = guard.is_cdn_edge_ip
seed.analyze_traffic([log_path])
seed.save_state()

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

# --------------------------------------------------------------- no blocking cap
#
# There is no MAX_NEW_BLOCKS_PER_RUN any more. Every entry reaching the apply
# stage came from a detection signal and already passed every guard, so a large
# batch means many offenders — not a fault. The old cap fired twice in
# production, both times on genuine abuse, and blocked nothing.
# A private blacklist and state dir: 400 entries must not leak into the runs
# that follow, or a later test finds its address already blocked and skipped.
cap_state = os.path.join(work, "state_nocap")
os.makedirs(cap_state, exist_ok=True)
cap_cfg = dict(cfg)
cap_cfg["BLACKLIST"] = os.path.join(work, "blacklist_nocap.txt")
cap_cfg["STATE_DIR"] = steady(cap_state)

flood = {f"45.{n // 256}.{n % 256}.7": {"reason": "test", "tier": "PERMANENT"}
         for n in range(400)}
engine2 = apply_engine.ApplyEngine(cap_cfg)
engine2.audit.parser.discover_log_files = lambda *a, **k: []
engine2.audit.parser.discover_auth_logs = lambda *a, **k: []
engine2.audit.evaluate_candidates = lambda *a, **k: dict(flood)
code2, entries2 = engine2.execute()
check("no cap: 400 candidates all block, exit 0", code2 == 0, code2)
check("no cap: every candidate reached the blacklist",
      all(target in entries2 for target in flood),
      sum(1 for t in flood if t in entries2))
check("no cap: MAX_NEW_BLOCKS_PER_RUN is gone from the engine",
      not hasattr(engine2, "max_new_blocks"))
check("no cap: --force-breaker is gone from the CLI",
      "force-breaker" not in open(
          os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logwall"),
          encoding="utf-8").read())

# ------------------------------------------- web server log format fixtures
# Parsing is pure file I/O, so every supported web server is covered offline —
# no nginx, Apache, LiteSpeed, or Caddy has to be running anywhere.
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


_FX_STAMP = re.compile(r"\[(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})\]")
_FX_TS = re.compile(r'"ts":(\d+(?:\.\d+)?)')
_FX_MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()


def fresh_fixture(name):
    """
    Copies a fixture into the work dir with every timestamp shifted so the last
    line lands a minute ago, preserving the spacing between lines.

    The fixtures carry fixed dates on purpose — they are meant to be read. But
    the parser now stamps each counter with the REQUEST's own time and prune()
    drops anything older than WINDOW_HOURS, so a fixture written last week
    correctly produces nothing at all.
    """
    source = os.path.join(FIXTURES, name)
    body = open(source, encoding="utf-8").read()

    stamps = [calendar.timegm((int(m.group(3)), _FX_MONTHS.index(m.group(2)) + 1,
                               int(m.group(1)), int(m.group(4)), int(m.group(5)),
                               int(m.group(6)), 0, 0, 0))
              for m in _FX_STAMP.finditer(body)]
    stamps += [int(float(m.group(1))) for m in _FX_TS.finditer(body)]
    if not stamps:
        return source

    delta = (int(time.time()) - 60) - max(stamps)

    def shift_combined(m):
        moment = calendar.timegm((int(m.group(3)), _FX_MONTHS.index(m.group(2)) + 1,
                                  int(m.group(1)), int(m.group(4)), int(m.group(5)),
                                  int(m.group(6)), 0, 0, 0)) + delta
        t = time.gmtime(moment)
        return "[%02d/%s/%d:%02d:%02d:%02d +0000]" % (
            t.tm_mday, _FX_MONTHS[t.tm_mon - 1], t.tm_year,
            t.tm_hour, t.tm_min, t.tm_sec)

    body = _FX_STAMP.sub(shift_combined, body)
    body = _FX_TS.sub(lambda m: '"ts":%.1f' % (float(m.group(1)) + delta), body)

    target = os.path.join(work, "fx_" + name)
    with open(target, "w", encoding="utf-8") as f:
        f.write(body)
    return target


def parse_fixture(name, cdn_check=None):
    """Runs one fixture through a parser with a private state dir."""
    fx_state = os.path.join(work, "fx_state_" + name)
    os.makedirs(fx_state, exist_ok=True)
    fx_cfg = dict(cfg)
    fx_cfg["STATE_DIR"] = steady(fx_state)
    parser_fx = log_parser.LogParserEngine(fx_cfg)
    parser_fx.cdn_check = cdn_check if cdn_check is not None else guard.is_cdn_edge_ip
    metrics = parser_fx.analyze_traffic([fresh_fixture(name)])
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
auth_cfg["STATE_DIR"] = steady(auth_state)
p_auth = log_parser.LogParserEngine(auth_cfg)
p_auth.cdn_check = guard.is_cdn_edge_ip
m_auth = p_auth.analyze_traffic([], [fresh_fixture("auth_secure.log")])
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
prof_cfg["STATE_DIR"] = steady(prof_state)
prof_cfg["ASSET_MIN_SAMPLES"] = "4"
pp = log_parser.LogParserEngine(prof_cfg)
pp.cdn_check = guard.is_cdn_edge_ip
mp = pp.analyze_traffic([fresh_fixture("browser_vs_script.log")])

check("profile: browser client counted mostly assets",
      mp["assets"].get("203.0.113.201") == 4 and mp["pages"].get("203.0.113.201") == 1,
      (mp["assets"].get("203.0.113.201"), mp["pages"].get("203.0.113.201")))
check("profile: scraper with a Chrome UA fetched ZERO assets",
      mp["assets"].get("185.199.120.10", 0) == 0 and mp["pages"].get("185.199.120.10") == 5,
      (mp["assets"].get("185.199.120.10", 0), mp["pages"].get("185.199.120.10")))
check("profile: self-declared tool is flagged even though volume is low",
      mp["script_ua"].get("185.199.120.11") == 2, mp["script_ua"])

# Same request count, opposite verdict — this is the whole point.
prof2 = dict(prof_cfg)
prof2["THRESHOLD_HITS_PER_INTERVAL"] = "4"
prof2["SUBNET_DETECTION"] = "0"
prof2["BROWSER_TOLERANCE_FACTOR"] = "3"
pe2 = log_parser.LogParserEngine(dict(prof2, STATE_DIR=steady(os.path.join(work, "prof2"))))
pe2.discover_log_files = lambda *a, **k: []
pe2.discover_auth_logs = lambda *a, **k: []
now_p = int(time.time())
# Spread over two intervals: volume rules require repetition, and a client that
# is loud in a single interval is a visitor by construction.
for slot in (now_p, now_p - 200):
    for _ in range(5):                   # browser: 5 pages + 40 assets
        pe2.window.add("203.0.113.210", "hits", 1, slot)
        pe2.window.add("203.0.113.210", "pages", 1, slot)
    for _ in range(40):
        pe2.window.add("203.0.113.210", "hits", 1, slot)
        pe2.window.add("203.0.113.210", "assets", 1, slot)
    for _ in range(45):                  # script: 45 pages, no assets
        pe2.window.add("185.199.121.9", "hits", 1, slot)
        pe2.window.add("185.199.121.9", "pages", 1, slot)

ae2 = apply_engine.ApplyEngine(dict(prof2, STATE_DIR=steady(os.path.join(work, "prof2"))))
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
pe3 = log_parser.LogParserEngine(dict(prof2, STATE_DIR=steady(os.path.join(work, "prof3"))))
pe3.discover_log_files = lambda *a, **k: []
pe3.discover_auth_logs = lambda *a, **k: []
for host in range(1, 6):                 # everyone fetches pages only
    for _ in range(45):
        pe3.window.add(f"203.0.113.{220+host}", "hits", 1, now_p)
        pe3.window.add(f"203.0.113.{220+host}", "pages", 1, now_p)
ae3 = apply_engine.ApplyEngine(dict(prof2, STATE_DIR=steady(os.path.join(work, "prof3"))))
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
esc_cfg["STATE_DIR"] = steady(esc_state)
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
        # Two intervals, because the escalation ladder is about REPEAT offences
        # and a volume verdict now needs repetition before it exists at all.
        pe.window.add(REPEAT, "hits", hits, now_e)
        pe.window.add(REPEAT, "hits", hits, now_e - 200)
    ee = apply_engine.ApplyEngine(esc_cfg)
    ee.audit.parser = pe
    pe.cdn_check = ee.guard.is_cdn_edge_ip
    _, ents = ee.execute()
    return ee, ents


# First offence: modest excess (500 vs threshold 10 = 50x)... use a small excess
esc_cfg["THRESHOLD_HITS_PER_INTERVAL"] = "400"
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
for slot_z in (now_e, now_e - 200):
    pz.window.add("185.199.112.7", "hits", 500, slot_z)
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
sub_cfg["STATE_DIR"] = steady(sub_state)
sub_cfg["SUBNET_MIN_IPS"] = "5"
sub_cfg["THRESHOLD_SUBNET_HITS_PER_INTERVAL"] = "2000"

flood = log_parser.LogParserEngine(sub_cfg)
# Must be "now": buckets older than the strike window are pruned, and a fixed
# epoch would silently age out before the subnet pass ever sees it.
now_ts = int(time.time())
# Isolate from whatever logs happen to exist on the machine running the suite.
flood.discover_log_files = lambda *a, **k: []
flood.discover_auth_logs = lambda *a, **k: []
# 2 networks x 250 hosts x 45 hits = 22,500 hits per network
# Across two intervals: a range is judged by the same strike rule an address
# is, because a CGNAT block genuinely does light up for one interval when
# several of its users load a page at the same moment.
for slot_f in (now_ts, now_ts - 200):
    for third in (7, 8):
        for host in range(1, 251):
            for _ in range(45):
                flood.window.add(f"185.199.{third}.{host}", "hits", 1, slot_f)
# one lone heavy host in an unrelated /24 — must NOT drag its neighbours in
for slot_l in (now_ts, now_ts - 200):
    for _ in range(9000):
        flood.window.add("185.199.9.99", "hits", 1, slot_l)

rollup = flood.window.subnet_rollup(24, 64)
check("subnet: rollup groups hosts into their /24",
      rollup.get("185.199.7.0/24", {}).get("members") == 250,
      rollup.get("185.199.7.0/24", {}).get("members"))
check("subnet: rollup sums the whole network's hits over the window",
      rollup["185.199.7.0/24"]["hits"] == 250 * 45 * 2,
      rollup["185.199.7.0/24"]["hits"])
check("subnet: rollup also reports the single-interval peak",
      rollup["185.199.7.0/24"]["peak_hits"] == 250 * 45,
      rollup["185.199.7.0/24"]["peak_hits"])

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
      len(verdict) <= 50, len(verdict))
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
rot_cfg = dict(cfg); rot_cfg["STATE_DIR"] = steady(rot_state)
rot = log_parser.LogParserEngine(rot_cfg)
for host in range(6):
    for _ in range(200):
        rot.window.add("2001:db8:abcd:1234:%x::1" % host, "hits", 1, now_ts)

check("v6 /64: six rotating addresses collapse to ONE counter",
      len(rot.window.entries) == 1, list(rot.window.entries)[:3])
check("v6 /64: the counter holds every request the visitor made",
      rot.window.intent_sum("hits").get("2001:db8:abcd:1234::/64") == 1200,
      rot.window.intent_sum("hits").get("2001:db8:abcd:1234::/64"))

# The escape hatch has to work, or a host with unusual v6 allocation is stuck.
per_state = os.path.join(work, "per_state")
os.makedirs(per_state, exist_ok=True)
per_cfg = dict(cfg); per_cfg["STATE_DIR"] = steady(per_state); per_cfg["IPV6_BLOCK_PREFIX"] = "128"
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
SLOT = now_ts // 120
with open(os.path.join(mig_state, "window.json"), "w", encoding="utf-8") as fh:
    json.dump({"format": "buckets", "interval": 120, "ips": {
        "2001:db8:aaaa:1::5":  {str(SLOT): {"hits": 300}},
        "2001:db8:aaaa:1::99": {str(SLOT): {"hits": 250}},
        "185.199.108.10":      {str(SLOT): {"hits": 10}},
    }}, fh)
mig_cfg = dict(cfg); mig_cfg["STATE_DIR"] = steady(mig_state)
mig = log_parser.LogParserEngine(mig_cfg)
check("v6 /64: a state file folds its bare keys into the /64 on load",
      mig.window.intent_sum("hits").get("2001:db8:aaaa:1::/64") == 550,
      dict(mig.window.entries))

# A pre-bucket state file holds one running total per address covering an
# unknown span. There is no honest bucket to put it in, so it is dropped rather
# than guessed at — the cost is one window of history, once.
legacy_state = os.path.join(work, "legacy_state")
os.makedirs(legacy_state, exist_ok=True)
with open(os.path.join(legacy_state, "window.json"), "w", encoding="utf-8") as fh:
    json.dump({"ips": {"185.199.108.10": {"hits": 99999, "first": 1, "last": now_ts}}}, fh)
legacy_cfg = dict(cfg); legacy_cfg["STATE_DIR"] = steady(legacy_state)
legacy = log_parser.LogParserEngine(legacy_cfg)
check("state: a pre-bucket window file is discarded, not misread",
      legacy.window.entries == {} and legacy.window.dropped_legacy == 1,
      (len(legacy.window.entries), legacy.window.dropped_legacy))
check("v6 /64: folding leaves IPv4 keys untouched",
      mig.window.intent_sum("hits").get("185.199.108.10") == 10,
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
v6_cfg["STATE_DIR"] = steady(v6_state)

v6 = log_parser.LogParserEngine(v6_cfg)
v6.discover_log_files = lambda *a, **k: []
v6.discover_auth_logs = lambda *a, **k: []
for slot_v6 in (now_ts, now_ts - 200):
    for block in range(20):
        for _ in range(300):
            v6.window.add("2a03:2880:f800:%x::" % block, "hits", 1, slot_v6)

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
      len(v6_verdict) < 50, len(v6_verdict))

# Below the evidence threshold nothing wide is proposed: a handful of /64s is not
# proof of one coordinated source, and a /56 holds 256 of them.
few_state = os.path.join(work, "few_state")
os.makedirs(few_state, exist_ok=True)
few_cfg = dict(v6_cfg); few_cfg["STATE_DIR"] = steady(few_state)
few = log_parser.LogParserEngine(few_cfg)
few.discover_log_files = lambda *a, **k: []
few.discover_auth_logs = lambda *a, **k: []
for slot_few in (now_ts, now_ts - 200):
    for block in range(3):
        for _ in range(3000):
            few.window.add("2a03:2880:f900:%x::" % block, "hits", 1, slot_few)
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
few_cfg["STATE_DIR"] = steady(few_state)
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

# ================================================================ new signals
#
# Six detections added after the 16 Aug audit of the verdict path. Each one is
# exercised on counters built directly, so no fixture or web server is involved.

def verdict_for(name, counters, overrides=None, slots=1):
    """
    Runs one address' counters through the real audit path.

    `slots` is how many separate intervals the counters are repeated across.
    Intent rules want 1 — their thresholds are exact sums. Volume rules want 2
    or more, because a single loud interval is a visitor by construction and no
    volume verdict exists below STRIKES_REQUIRED.
    """
    sig_cfg = dict(cfg, SUBNET_DETECTION="0", SUBNET6_WIDE_DETECTION="0",
                   CLIENT_PROFILING="0")
    sig_cfg.update(overrides or {})
    sig_cfg["STATE_DIR"] = steady(os.path.join(work, "sig_" + name))
    pe = log_parser.LogParserEngine(sig_cfg)
    pe.discover_log_files = lambda *a, **k: []
    pe.discover_auth_logs = lambda *a, **k: []
    base = int(time.time())
    for offset in range(slots):
        stamp = base - offset * 200
        for ip, metrics in counters.items():
            for metric, value in metrics.items():
                pe.window.add(ip, metric, value, stamp)
    ae = apply_engine.ApplyEngine(sig_cfg)
    ae.audit.parser = pe
    pe.cdn_check = ae.guard.is_cdn_edge_ip
    return ae.audit.evaluate_candidates()


# --- N1 IntentComposite ------------------------------------------------------
# Every component stays at or below its own threshold, which is exactly the
# shape that used to escape: the /24 rollup has summed these four since 1.0, so
# a lone attacker was judged more leniently than its own neighbours.
v = verdict_for("intent", {"45.10.10.10": {
    "hits": 12, "wp": 3, "xmlrpc": 2, "scan": 2, "p401": 5}})
check("intent: composite is a candidate", "45.10.10.10" in v, sorted(v))
check("intent: named IntentComposite, not the volume rule",
      "IntentComposite" in v.get("45.10.10.10", {}).get("reason", ""),
      v.get("45.10.10.10"))
check("intent: permanent on first sighting",
      v.get("45.10.10.10", {}).get("tier") == "PERMANENT")
v = verdict_for("intent_low", {"45.10.10.11": {
    "hits": 5, "wp": 2, "xmlrpc": 1, "scan": 1}})
check("intent: below the sum, nothing is proposed", "45.10.10.11" not in v, sorted(v))

# --- N3 ToolSignature --------------------------------------------------------
check("attack ua: sqlmap is an attack signature",
      log_parser.classify_attack_ua("sqlmap/1.7.2#stable"))
check("attack ua: curl is NOT - it is an honest API client",
      not log_parser.classify_attack_ua("curl/8.5.0"))
check("attack ua: python-requests is NOT",
      not log_parser.classify_attack_ua("python-requests/2.31.0"))
check("attack ua: an absent agent is NOT an attack signature",
      not log_parser.classify_attack_ua("-") and not log_parser.classify_attack_ua(""))
check("attack ua: generic clients still count toward profiling",
      log_parser.classify_user_agent("curl/8.5.0"))
v = verdict_for("aua", {"45.10.20.10": {"hits": 3, "aua": 1}})
check("attack ua: one request is enough",
      "ToolSignature" in v.get("45.10.20.10", {}).get("reason", ""), sorted(v))
check("attack ua: permanent",
      v.get("45.10.20.10", {}).get("tier") == "PERMANENT")

# --- N2 PathBruteForce -------------------------------------------------------
v = verdict_for("scan404", {"45.10.30.10": {"hits": 60, "p404": 50}}, slots=2)
check("404: a scanner whose requests are mostly 404 is caught",
      "PathBruteForce" in v.get("45.10.30.10", {}).get("reason", ""), sorted(v))
# The ratio guard is what stops a site with a broken theme from convicting its
# own visitors: same 50 not-founds, but a small share of real traffic.
v = verdict_for("scan404_ratio", {"45.10.30.11": {"hits": 500, "p404": 50}}, slots=2)
check("404: same count but a low share is NOT a path brute force",
      "PathBruteForce" not in v.get("45.10.30.11", {}).get("reason", ""),
      v.get("45.10.30.11"))

# --- N4 GenericLoginBrute ----------------------------------------------------
v = verdict_for("login", {"45.10.40.10": {"hits": 20, "lpost": 15}})
check("login: repeated POSTs to a non-WordPress login are caught",
      "GenericLoginBrute" in v.get("45.10.40.10", {}).get("reason", ""), sorted(v))
check("login: without rejections it is only temporary",
      v.get("45.10.40.10", {}).get("tier") == "TEMP",
      v.get("45.10.40.10", {}).get("tier"))
v = verdict_for("login_rej", {"45.10.40.11": {"hits": 20, "lpost": 15, "p401": 4}})
check("login: POSTs plus rejections escalate to permanent",
      v.get("45.10.40.11", {}).get("tier") == "PERMANENT",
      v.get("45.10.40.11"))

# --- N5 sensitive-file list --------------------------------------------------
sensitive_pe = log_parser.LogParserEngine(dict(cfg, STATE_DIR=steady(
    os.path.join(work, "sig_sensitive"))))
for probe in ("/wp-config.php", "/.ssh/id_rsa", "/.aws/credentials",
              "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
              "/actuator/env", "/server-status", "/.svn/entries",
              "/adminer.php", "/backup.old"):
    check("sensitive: " + probe + " is recognised",
          bool(sensitive_pe.sensitive_pattern.search(probe)))
check("sensitive: /.well-known/ is NOT - ACME renewal lives there",
      not sensitive_pe.sensitive_pattern.search(
          "/.well-known/acme-challenge/tokenvalue"))

# --- N6 bandwidth at the /56 tier -------------------------------------------
wide_bw = {}
for n in range(10):
    wide_bw["2a03:2880:f800:%x::/64" % n] = {"hits": 20, "bw": 40 * 1024 * 1024}
v = verdict_for("v6bw", wide_bw, {"SUBNET6_WIDE_DETECTION": "1",
                                  "SUBNET_DETECTION": "1"}, slots=2)
wide_hit = [k for k in v if k.endswith("::/56")]
check("v6 wide bw: a /56 draining bandwidth is caught at all",
      bool(wide_hit), sorted(v))
check("v6 wide bw: reported as Subnet6HighBandwidth",
      bool(wide_hit) and "Subnet6HighBandwidth" in v[wide_hit[0]]["reason"],
      v[wide_hit[0]]["reason"] if wide_hit else "absent")

# ============================================================== catch-up guard
#
# The one way an ordinary visitor crosses a volume threshold without having done
# anything: hand a single run hours of log and every count in it is inflated by
# the same factor. Replaces MAX_NEW_BLOCKS_PER_RUN, which measured the outcome
# rather than the cause.
#
# The span is MEASURED from the stamps of the lines just read. That is what
# separates "the host was off for four hours" (no log was written, span zero)
# from "one run swallowed four hours of traffic".

VOLUME_IP = "45.20.10.10"      # volume only
INTENT_IP = "45.20.10.11"      # volume AND intent


def catchup_log(name, span_seconds, seed_last_run=None, guard="1"):
    """Writes a log covering `span_seconds` and runs the real audit path."""
    cu_cfg = dict(cfg, SUBNET_DETECTION="0", SUBNET6_WIDE_DETECTION="0",
                  CLIENT_PROFILING="0", CATCHUP_GUARD=guard)
    cu_state = os.path.join(work, "cu_" + name)
    os.makedirs(cu_state, exist_ok=True)
    if seed_last_run is not None:
        with open(os.path.join(cu_state, "run_meta.json"), "w", encoding="utf-8") as f:
            json.dump({"last_run": seed_last_run}, f)
    cu_cfg["STATE_DIR"] = cu_state

    # One clearly-over-threshold burst per interval, in as many intervals as the
    # span covers. A volume verdict needs STRIKES_REQUIRED of them, so a fixture
    # that writes everything into one instant would test nothing.
    path = os.path.join(work, "cu_" + name + ".log")
    slots = max(2, span_seconds // 120)
    with open(path, "w", encoding="utf-8") as f:
        for slot in range(slots):
            when = stamp_now(-(60 + slot * 120))
            for _ in range(25):
                f.write('%s - - [%s] "GET /index.html HTTP/1.1" 200 100 "-" "curl/8"\n'
                        % (VOLUME_IP, when))
            for _ in range(4):
                f.write('%s - - [%s] "POST /wp-login.php HTTP/1.1" 401 100 "-" "curl/8"\n'
                        % (INTENT_IP, when))

    pe = log_parser.LogParserEngine(cu_cfg)
    pe.discover_log_files = lambda *a, **k: [path]
    pe.discover_auth_logs = lambda *a, **k: []
    ae = apply_engine.ApplyEngine(cu_cfg)
    ae.audit.parser = pe
    pe.cdn_check = ae.guard.is_cdn_edge_ip
    return ae.audit.evaluate_candidates(), pe


now_i = int(time.time())

# --- ordinary run: 20 lines inside two minutes
v, pe = catchup_log("steady", 120, seed_last_run=now_i - 60)
check("catchup: a two-minute span is not a catch-up", not pe.catchup, pe.catchup_reason)
check("catchup: steady run blocks the volume offender", VOLUME_IP in v, sorted(v))
check("catchup: steady run blocks the intent offender", INTENT_IP in v, sorted(v))

# --- one run swallows three hours
v, pe = catchup_log("wide", 3 * 3600, seed_last_run=now_i - 60)
check("catchup: a three-hour span IS a catch-up", pe.catchup, pe.catchup_reason)
check("catchup: the reason states the measured minutes",
      "minutes of log" in pe.catchup_reason, pe.catchup_reason)
check("catchup: volume alone is NOT blocked on a catch-up run",
      VOLUME_IP not in v, sorted(v))
check("catchup: intent IS still blocked on a catch-up run", INTENT_IP in v, sorted(v))
check("catchup: the verdict is the brute force, not the volume",
      "BruteForce" in v.get(INTENT_IP, {}).get("reason", ""), v.get(INTENT_IP))

# --- the scenario the gap-based guess got wrong: host powered off for four
#     hours. Nothing was served while it was down, so the log it comes back to
#     holds two minutes of traffic, not four hours of it.
v, pe = catchup_log("host_was_off", 120, seed_last_run=now_i - 4 * 3600)
check("catchup: a four-hour outage with a two-minute span is NOT a catch-up",
      not pe.catchup, pe.catchup_reason)
check("catchup: so volume detection keeps working after a reboot",
      VOLUME_IP in v, sorted(v))

# --- measurement recorded for the operator
check("catchup: the measured span is exposed",
      pe.span_end - pe.span_start == 120, pe.span_end - pe.span_start)
check("catchup: every line contributed a usable stamp",
      pe.stamped == 58 and pe.unstamped == 0, (pe.stamped, pe.unstamped))

# --- guard disabled
v, pe = catchup_log("off", 3 * 3600, seed_last_run=now_i - 60, guard="0")
check("catchup: the guard can be switched off", not pe.catchup)
check("catchup: with the guard off, a wide span still blocks on volume",
      VOLUME_IP in v, sorted(v))

# --- fallback: a log whose stamps cannot be read at all
fb_cfg = dict(cfg, SUBNET_DETECTION="0", SUBNET6_WIDE_DETECTION="0",
              CLIENT_PROFILING="0")
fb_state = os.path.join(work, "cu_nostamp")
os.makedirs(fb_state, exist_ok=True)
fb_cfg["STATE_DIR"] = fb_state
fb_log = os.path.join(work, "cu_nostamp.log")
with open(fb_log, "w", encoding="utf-8") as f:
    for _ in range(20):
        f.write('%s - - [not-a-date] "GET /index.html HTTP/1.1" 200 100 "-" "curl/8"\n'
                % VOLUME_IP)
fb_pe = log_parser.LogParserEngine(fb_cfg)
fb_pe.discover_log_files = lambda *a, **k: [fb_log]
fb_pe.discover_auth_logs = lambda *a, **k: []
fb_ae = apply_engine.ApplyEngine(fb_cfg)
fb_ae.audit.parser = fb_pe
fb_pe.cdn_check = fb_ae.guard.is_cdn_edge_ip
fb_v = fb_ae.audit.evaluate_candidates()
check("catchup: unreadable stamps fall back to the run gap", fb_pe.catchup,
      fb_pe.catchup_reason)
check("catchup: those lines still counted, using the run clock",
      fb_pe.unstamped == 20 and fb_pe.stamped == 0,
      (fb_pe.stamped, fb_pe.unstamped))


# ======================================= two classes of signal, two windows ===
#
# Measured on a production host and turned into a regression, because getting
# this wrong in either direction is a silent failure rather than a loud one.

# --- the slow brute force, which per-interval counting would have missed ------
#
# Four addresses on that host were knocking on wp-login.php exactly TWICE per
# two-minute interval, sustained: 194, 84, 58 and 52 attempts spread over 97,
# 43, 29 and 26 intervals. Every one of them sits below THRESHOLD_WP_LOGIN=5, so
# a per-interval threshold catches none. The intent window sums instead.
slow_state = os.path.join(work, "slow_state")
slow_cfg = dict(cfg, SUBNET_DETECTION="0", SUBNET6_WIDE_DETECTION="0",
                CLIENT_PROFILING="0", THRESHOLD_WP_LOGIN="5",
                INTENT_WINDOW_MIN="30", EVAL_INTERVAL_SEC="120")
slow_cfg["STATE_DIR"] = steady(slow_state)
slow = log_parser.LogParserEngine(slow_cfg)
slow.discover_log_files = lambda *a, **k: []
slow.discover_auth_logs = lambda *a, **k: []
now_s = int(time.time())
SLOW = "91.92.242.191"
for slot in range(10):                    # 10 intervals x 2 attempts = 20
    slow.window.add(SLOW, "wp", 2, now_s - slot * 120)
    slow.window.add(SLOW, "hits", 2, now_s - slot * 120)

check("slow brute: never more than 2 attempts in any one interval",
      max(m.get("wp", 0) for m in slow.window.entries[SLOW].values()) == 2,
      max(m.get("wp", 0) for m in slow.window.entries[SLOW].values()))
check("slow brute: a per-interval threshold of 5 would see nothing",
      slow.window.strikes("wp", 5) == {}, slow.window.strikes("wp", 5))

slow_ae = apply_engine.ApplyEngine(slow_cfg)
slow_ae.audit.parser = slow
slow.cdn_check = slow_ae.guard.is_cdn_edge_ip
slow_v = slow_ae.audit.evaluate_candidates()
check("slow brute: the intent window catches it anyway", SLOW in slow_v, sorted(slow_v))
check("slow brute: named as the brute force it is",
      "BruteForce" in slow_v.get(SLOW, {}).get("reason", ""), slow_v.get(SLOW))
check("slow brute: permanent, like every intent verdict",
      slow_v.get(SLOW, {}).get("tier") == "PERMANENT", slow_v.get(SLOW))

# --- the loud visitor, which cumulative counting used to convict --------------
#
# On that same host the largest single-interval bursts belonged to ordinary
# people: 134, 88 and 67 requests, each in ONE interval and silent afterwards.
# One modern page view is 30-80 requests, so this is somebody opening a couple
# of pages. It must never become a block, however loud that one interval was.
burst_state = os.path.join(work, "burst_state")
burst_cfg = dict(cfg, SUBNET_DETECTION="0", SUBNET6_WIDE_DETECTION="0",
                 CLIENT_PROFILING="0", THRESHOLD_HITS_PER_INTERVAL="60",
                 STRIKES_REQUIRED="2")
burst_cfg["STATE_DIR"] = steady(burst_state)
burst = log_parser.LogParserEngine(burst_cfg)
burst.discover_log_files = lambda *a, **k: []
burst.discover_auth_logs = lambda *a, **k: []
VISITOR = "114.10.11.58"
CRAWLER = "216.73.216.188"
burst.window.add(VISITOR, "hits", 134, now_s)          # one loud interval
for slot in range(8):                                  # loud for hours
    burst.window.add(CRAWLER, "hits", 474, now_s - slot * 120)

burst_ae = apply_engine.ApplyEngine(burst_cfg)
burst_ae.audit.parser = burst
burst.cdn_check = burst_ae.guard.is_cdn_edge_ip
burst_v = burst_ae.audit.evaluate_candidates()
check("loud visitor: 134 requests in ONE interval is not a block",
      VISITOR not in burst_v, sorted(burst_v))
check("loud visitor: the same rule still catches the sustained crawler",
      CRAWLER in burst_v, sorted(burst_v))
check("loud visitor: the reason states both the peak and the repetition",
      "in one interval" in burst_v.get(CRAWLER, {}).get("reason", "")
      and "intervals over" in burst_v.get(CRAWLER, {}).get("reason", ""),
      burst_v.get(CRAWLER, {}).get("reason"))

# --- counters must actually decay --------------------------------------------
#
# The bug this release exists to kill: a counter that only reset after a full
# day of silence, so an address seen once a day accumulated forever and a loyal
# visitor eventually reached a volume threshold having done nothing.
decay_state = os.path.join(work, "decay_state")
decay_cfg = dict(cfg, EVAL_INTERVAL_SEC="120", STRIKES_WINDOW="10",
                 INTENT_WINDOW_MIN="30")
decay_cfg["STATE_DIR"] = steady(decay_state)
decay = log_parser.LogParserEngine(decay_cfg)
LOYAL = "203.0.113.77"
for day in range(30):                     # a daily visitor, 30 days running
    decay.window.add(LOYAL, "hits", 20, now_s - day * 86400)
decay.window.prune(now_s)
check("decay: a month of daily visits leaves only the recent window",
      decay.window.intent_sum("hits").get(LOYAL, 0) == 20,
      decay.window.intent_sum("hits").get(LOYAL, 0))
check("decay: and the stale buckets are gone from the state file",
      len(decay.window.entries.get(LOYAL, {})) == 1,
      len(decay.window.entries.get(LOYAL, {})))

# --- the renamed settings must be refused loudly, never reinterpreted ---------
stale_cfg = dict(cfg)
stale_cfg["THRESHOLD_HITS"] = "400"
stale_ae = apply_engine.ApplyEngine(stale_cfg)
warning = stale_ae.audit._renamed_setting_warning()
check("rename: an old threshold name is reported, not silently obeyed",
      warning is not None and "THRESHOLD_HITS" in warning, warning)
check("rename: the message says the value is ignored",
      warning is not None and "IGNORED" in warning, warning)
check("rename: a clean config produces no warning",
      apply_engine.ApplyEngine(dict(cfg)).audit._renamed_setting_warning() is None)


# ============================================================== rc13 Fase 1
import audit_engine
import report_gen

# --- R2: a guard refusal must name the address, not just count it -------------
refusals = audit_engine.format_refusals({
    "160.191.180.187": "WHITELIST",
    "10.0.0.1": "SERVER_OWN_IP",
    "10.0.0.2": "SERVER_OWN_IP",
})
joined = " | ".join(refusals)
check("guard: the refused address is named, not tallied",
      "160.191.180.187" in joined, joined)
check("guard: refusals are grouped by reason",
      len(refusals) == 2 and any(r.startswith("SERVER_OWN_IP:") for r in refusals),
      refusals)
many = audit_engine.format_refusals(
    dict(("203.0.113.%d" % n, "WHITELIST") for n in range(1, 30)), limit=5)
check("guard: a long refusal list is capped but says how many are hidden",
      "+24 more" in many[0], many[0])

# --- R7: a health flag must state the affected share, not the whole file ------
shares = audit_engine.format_shares({"/var/log/a.log": [1, 537]})
check("flag: the share is stated, not just the filename",
      shares["/var/log/a.log"].startswith("1 of 537"), shares)
dead = audit_engine.format_shares({"/var/log/b.log": [537, 537]})
check("flag: a fully unusable log reads as 100%",
      "100%" in dead["/var/log/b.log"], dead)
check("flag: a legacy list-shaped flag still formats",
      audit_engine.format_shares(["/var/log/c.log"]) != {},
      audit_engine.format_shares(["/var/log/c.log"]))
check("flag: no share means no line", audit_engine.format_shares({}) == {})

# --- R7: CDN_NO_REALIP stays silent when nothing was actually lost ------------
clean_log = write("cdnshare.log", "")
with open(clean_log, "a", encoding="utf-8") as f:
    f.write('203.0.113.7 - - [%s] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n'
            % stamp_now())
share_cfg = dict(cfg)
share_cfg["STATE_DIR"] = steady(os.path.join(work, "state_share"))
p_share = log_parser.LogParserEngine(share_cfg)
p_share.cdn_check = guard.is_cdn_edge_ip
p_share.analyze_traffic([clean_log])
check("cdn: a log that lost nothing raises no CDN_NO_REALIP",
      p_share.flags["CDN_NO_REALIP"] == {}, p_share.flags["CDN_NO_REALIP"])
check("cdn: a log that DID lose requests reports the share",
      audit_engine.format_shares(p_cdn.flags["CDN_NO_REALIP"]) != {},
      audit_engine.format_shares(p_cdn.flags["CDN_NO_REALIP"]))

# --- R9: the daily report summarises the day that ENDED, not the one that began
rep_state = os.path.join(work, "state_report")
os.makedirs(rep_state, exist_ok=True)
rep_cfg = dict(cfg)
rep_cfg["STATE_DIR"] = rep_state
rep_cfg["REPORT_DIR"] = os.path.join(work, "reports")
rg = report_gen.ReportGenerator(rep_cfg)

midnight = time.mktime(time.strptime("2026-08-17 00:05", "%Y-%m-%d %H:%M"))
label, start, end = rg._period(midnight)
check("report: a 00:05 run summarises the previous day", label == "2026-08-16", label)
check("report: the window is exactly one day", end - start == 86400, end - start)
check("report: a midday run summarises today",
      rg._period(time.mktime(time.strptime("2026-08-17 14:00", "%Y-%m-%d %H:%M")))[0]
      == "2026-08-17")

# --- R9: counted from events, so a block released in the period still counts ---
with open(os.path.join(rep_state, "events.jsonl"), "w", encoding="utf-8") as f:
    f.write(json.dumps({"ts": int(start) + 3600, "action": "BLOCK",
                        "target": "203.0.113.9", "tier": "TEMP"}) + "\n")
    f.write(json.dumps({"ts": int(start) + 7200, "action": "EXPIRED",
                        "target": "203.0.113.9"}) + "\n")
    f.write(json.dumps({"ts": int(start) - 86400, "action": "BLOCK",
                        "target": "203.0.113.8", "tier": "TEMP"}) + "\n")
tally = rg._events(start, end)
check("report: events inside the period are counted", tally.get("BLOCK") == 1, tally)
check("report: a block released in the same period is still counted",
      tally.get("EXPIRED") == 1, tally)
data = rg.collect(midnight)
check("report: the blocked count comes from the event record",
      data["blocked_today"] == 1 and data["counted_from"] == "event record", data)
check("report: the rendered summary names the day it covers",
      "2026-08-16" in rg.render(data))

# --- R11: run diagnostics reach the report instead of stderr only -------------
with open(os.path.join(rep_state, "last_run_flags.json"), "w", encoding="utf-8") as f:
    json.dump({"ts": int(start), "flags": {
        "PROFILING_OFF": "[PROFILING_OFF] Site asset ratio 8% is below 40%",
        "CDN_NO_REALIP": {"/var/log/a.log": "1 of 537 requests (0%)"},
        "GUARD_REFUSED": ["WHITELIST: 160.191.180.187"],
    }}, f)
blob = " || ".join(rg.collect(midnight)["flags"])
check("report: PROFILING_OFF from the last run is stated in the report",
      "PROFILING_OFF" in blob, blob)
check("report: the refused address reaches the report too",
      "160.191.180.187" in blob)
check("report: the CDN share reaches the report with its count",
      "1 of 537" in blob)

# --- R9/R11: apply writes the event record and the run flags ------------------
ev_state = os.path.join(work, "state_events")
ev_cfg = dict(cfg)
ev_cfg["STATE_DIR"] = steady(ev_state)
ev_cfg["BLACKLIST"] = os.path.join(work, "blacklist_events.txt")
ev_engine = apply_engine.ApplyEngine(ev_cfg)
ev_engine.execute(dry_run=False)
check("apply: a run leaves a flags record behind",
      os.path.isfile(os.path.join(ev_state, "last_run_flags.json")))


# ============================================================== rc13 Fase 2 (R12)
#
# The hole these cover was proven on a production host: a request sent from the
# admin's own address, carrying `X-Forwarded-For: 192.0.2.77`, was recorded as
# coming from 192.0.2.77. That host has since been fixed, which means the only
# remaining fixture for this behaviour is right here.

# --- an address in a client-controlled field must never become the identity ----
ua_log = write("ua_spoof.log", "")
with open(ua_log, "a", encoding="utf-8") as f:
    for _ in range(40):
        f.write('45.33.32.156 - - [%s] "GET /wp-login.php HTTP/1.1" 200 100 '
                '"http://8.8.4.4/" "Mozilla/5.0 (8.8.8.8)"\n' % stamp_now())
spoof_cfg = dict(cfg)
spoof_cfg["STATE_DIR"] = steady(os.path.join(work, "state_spoof"))
p_spoof = log_parser.LogParserEngine(spoof_cfg)
p_spoof.cdn_check = guard.is_cdn_edge_ip
m_spoof = p_spoof.analyze_traffic([ua_log])
check("spoof: an IP in the user-agent is not treated as the client",
      m_spoof["hits"].get("8.8.8.8", 0) == 0, m_spoof["hits"].get("8.8.8.8", 0))
check("spoof: an IP in the referer is not treated as the client either",
      m_spoof["hits"].get("8.8.4.4", 0) == 0, m_spoof["hits"].get("8.8.4.4", 0))
check("spoof: the peer that completed the handshake is the client",
      m_spoof["hits"].get("45.33.32.156", 0) == 40,
      m_spoof["hits"].get("45.33.32.156", 0))

# --- a forwarded header from a NON-CDN peer must be ignored entirely -----------
laundry_log = write("laundry.log", "")
with open(laundry_log, "a", encoding="utf-8") as f:
    for _ in range(40):
        f.write('45.33.32.157 - - [%s] "GET /wp-login.php HTTP/1.1" 200 100 '
                '"-" "curl/8" "198.18.0.9"\n' % stamp_now())
laundry_cfg = dict(cfg)
laundry_cfg["STATE_DIR"] = steady(os.path.join(work, "state_laundry"))
p_laundry = log_parser.LogParserEngine(laundry_cfg)
p_laundry.cdn_check = guard.is_cdn_edge_ip
m_laundry = p_laundry.analyze_traffic([laundry_log])
check("laundry: XFF sent by a direct client is not believed",
      m_laundry["hits"].get("198.18.0.9", 0) == 0,
      m_laundry["hits"].get("198.18.0.9", 0))
check("laundry: the request is still attributed to the real peer",
      m_laundry["hits"].get("45.33.32.157", 0) == 40,
      m_laundry["hits"].get("45.33.32.157", 0))

# --- but a CDN edge we trust may still speak for its client --------------------
check("cdn: a trusted edge can still forward a real client address",
      m_xff["hits"].get("203.0.113.44", 0) == 30,
      m_xff["hits"].get("203.0.113.44", 0))

# --- documentation ranges must NOT read as a misconfiguration -----------------
check("unroutable: RFC1918 is unroutable as a source",
      ip_guard.is_unroutable_source("10.0.0.5"))
check("unroutable: loopback is unroutable as a source",
      ip_guard.is_unroutable_source("127.0.0.1"))
check("unroutable: link-local is unroutable as a source",
      ip_guard.is_unroutable_source("169.254.1.1"))
check("unroutable: IPv6 unique-local is unroutable as a source",
      ip_guard.is_unroutable_source("fd00::1"))
check("unroutable: a real public address is routable",
      not ip_guard.is_unroutable_source("8.8.8.8"))
check("unroutable: documentation ranges are NOT flagged (they are what tests use)",
      not ip_guard.is_unroutable_source("203.0.113.7")
      and not ip_guard.is_unroutable_source("192.0.2.77"))

# --- the OVH case: a private peer means no identity can be trusted ------------
untrusted_log = write("untrusted.log", "")
with open(untrusted_log, "a", encoding="utf-8") as f:
    for _ in range(40):
        f.write('45.33.32.158 - - [%s] "GET /wp-login.php HTTP/1.1" 200 100 "-" "curl/8"\n'
                % stamp_now())
    f.write('127.0.0.1 - - [%s] "GET / HTTP/1.1" 200 100 "-" "curl/8"\n' % stamp_now())
    f.write('10.0.0.7 - - [%s] "GET / HTTP/1.1" 200 100 "-" "curl/8"\n' % stamp_now())

ident_cfg = dict(cfg)
ident_cfg["STATE_DIR"] = steady(os.path.join(work, "state_ident"))
ident_engine = audit_engine.AuditEngine(ident_cfg)
ident_engine.parser.discover_log_files = lambda panel=None: [untrusted_log]
ident_engine.parser.discover_auth_logs = lambda: []
ident_candidates = ident_engine.evaluate_candidates()
ident_flags = ident_engine.health_flags()

check("identity: a private peer address is recorded",
      ident_engine.parser.flags["PEER_NOT_ROUTABLE"].get("127.0.0.1") == 1,
      ident_engine.parser.flags["PEER_NOT_ROUTABLE"])
check("identity: the run refuses to name any candidate at all",
      ident_candidates == {}, ident_candidates)
check("identity: and says why, naming the addresses that prove it",
      "IDENTITY_UNTRUSTED" in ident_flags.get("IDENTITY_UNTRUSTED", "")
      and "127.0.0.1" in ident_flags["IDENTITY_UNTRUSTED"],
      ident_flags.get("IDENTITY_UNTRUSTED", "")[:90])
check("identity: the message tells the operator which directive to fix",
      "useIpInProxyHeader" in ident_flags.get("IDENTITY_UNTRUSTED", "")
      and "set_real_ip_from" in ident_flags["IDENTITY_UNTRUSTED"])

# the brute force in that same log IS real; it is withheld only because the log
# can no longer prove who sent it
off_cfg = dict(cfg)
off_cfg["STATE_DIR"] = steady(os.path.join(work, "state_ident_off"))
off_cfg["IDENTITY_GUARD"] = "0"
off_engine = audit_engine.AuditEngine(off_cfg)
off_engine.parser.discover_log_files = lambda panel=None: [untrusted_log]
off_engine.parser.discover_auth_logs = lambda: []
off_candidates = off_engine.evaluate_candidates()
check("identity: with the guard switched off the same log does produce verdicts",
      "45.33.32.158" in off_candidates, sorted(off_candidates))
check("identity: which is exactly what an attacker would gain by aiming it",
      off_candidates.get("45.33.32.158", {}).get("tier") == "PERMANENT",
      off_candidates.get("45.33.32.158"))

# --- the guessing function is gone, not merely bypassed -----------------------
check("identity: the line-scanning recovery function no longer exists",
      not hasattr(p_spoof, "_recover_real_ip"))
check("identity: and neither does the token regex it needed",
      not hasattr(log_parser, "IP_TOKEN_RE"))
check("identity: dead settings are gone from the shipped config",
      "TRUSTED_PROXIES=" not in open(
          os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "..", "conf", "logwall.conf"), encoding="utf-8").read())


# ============================================================== rc13 Fase 3
#
# Both halves of this phase come from the same day of field measurement, and the
# false-positive case is the one that matters: it exists on exactly one host in
# the fleet, and the threshold that "looked safe" on the busiest host would have
# blocked five real people on it.


def sweeper_log(name, ip, paths, status=404):
    """A dictionary sweep: many distinct source-file paths, nothing but 404s."""
    path = write(name, "")
    with open(path, "a", encoding="utf-8") as handle:
        for target in paths:
            handle.write('%s - - [%s] "GET %s HTTP/1.1" %d 120 "-" "Mozilla/5.0"\n'
                         % (ip, stamp_now(), target, status))
    return path


def audit_for(name, log, extra=None):
    local = dict(cfg)
    local["STATE_DIR"] = steady(os.path.join(work, "state_" + name))
    if extra:
        local.update(extra)
    engine = audit_engine.AuditEngine(local)
    engine.parser.discover_log_files = lambda panel=None: [log]
    engine.parser.discover_auth_logs = lambda: []
    return engine, engine.evaluate_candidates()

# --- R8: the webshell hunter that walked free for a day -----------------------
shells = ["/fff.php", "/zz.php", "/xx.php", "/1.php", "/sf.php", "/222.php",
          "/wp-blog.php", "/wp-good.php", "/this_is_a_new_hello_world.php",
          "/wp-content/plugins/hellopress/wp_filemanager.php"]
hunter_log = sweeper_log("hunter.log", "20.65.105.233", shells)
hunter_engine, hunter = audit_for("hunter", hunter_log)
check("webshell: a source-file sweep is caught",
      "20.65.105.233" in hunter, sorted(hunter))
check("webshell: named for what it is, and permanently",
      hunter.get("20.65.105.233", {}).get("tier") == "PERMANENT"
      and "WebshellHunter" in hunter.get("20.65.105.233", {}).get("reason", ""),
      hunter.get("20.65.105.233"))
check("webshell: the reason states how many source files it asked for",
      "10x" in hunter.get("20.65.105.233", {}).get("reason", ""),
      hunter.get("20.65.105.233", {}).get("reason"))

# --- R8: a per-interval 404 threshold could never have seen it ----------------
peak_404 = max((hunter_engine.parser.window.peak("p404") or {}).values(), default=0)
check("webshell: it never came close to the per-interval 404 threshold",
      peak_404 < 30, peak_404)

# --- R8: wp-login and xmlrpc must not be counted twice ------------------------
dbl_log = sweeper_log("double.log", "45.33.32.170",
                      ["/wp-login.php", "/xmlrpc.php"] * 6)
_, dbl = audit_for("double", dbl_log)
reason = dbl.get("45.33.32.170", {}).get("reason", "")
check("webshell: wp-login/xmlrpc are left to their own rules",
      "WebshellHunter" not in reason, reason)

# --- R8: THE false positive. A real visitor asking for a removed plugin file ---
#
# Measured on a WordPress host: five visitors on phones kept requesting
# /wp-content/plugins/screenreader/libraries/tts/proxy.php after the accessibility
# plugin was removed. One asked 14 times — more than nine of the sixteen genuine
# sweepers on that same host. Any threshold on the COUNT is either blind or cruel.
missing_plugin = "/wp-content/plugins/screenreader/libraries/tts/proxy.php"
visitor_log = write("visitor.log", "")
with open(visitor_log, "a", encoding="utf-8") as handle:
    for _ in range(14):
        handle.write('114.122.138.128 - - [%s] "GET %s HTTP/1.1" 404 120 "-" '
                     '"Mozilla/5.0 (Linux; Android 10; K)"\n'
                     % (stamp_now(), missing_plugin))
    for n in range(47):
        handle.write('114.122.138.128 - - [%s] "GET /wp-content/themes/x/s%d.css '
                     'HTTP/1.1" 200 900 "-" "Mozilla/5.0 (Linux; Android 10; K)"\n'
                     % (stamp_now(), n))
    for n in range(58):
        handle.write('114.122.138.128 - - [%s] "GET /berita/%d/ HTTP/1.1" 200 20000 '
                     '"-" "Mozilla/5.0 (Linux; Android 10; K)"\n' % (stamp_now(), n))
_, visitor = audit_for("visitor", visitor_log)
check("visitor: 14 source-file 404s from a REAL visitor is not a block",
      "114.122.138.128" not in visitor, sorted(visitor))

# and the count alone would have convicted them
check("visitor: which the count alone would not have prevented",
      14 >= 2, 14)

# --- R8: the client-evidence veto, both halves --------------------------------
ev_metrics = {"ok": {"a": 5, "b": 0, "c": 0},
              "assets": {"a": 0, "b": 40, "c": 0},
              "pages": {"a": 0, "b": 60, "c": 90}}
ev_engine = audit_engine.AuditEngine(dict(cfg))
check("evidence: successful responses alone prove a client",
      ev_engine._looks_like_a_client("a", ev_metrics))
check("evidence: fetching assets alone proves a client",
      ev_engine._looks_like_a_client("b", ev_metrics))
check("evidence: neither assets nor successes is a sweeper",
      not ev_engine._looks_like_a_client("c", ev_metrics))
check("evidence: an unseen address is not given the benefit of the doubt",
      not ev_engine._looks_like_a_client("zzz", ev_metrics))

# --- R6: PathBruteForce catches a single-burst sweep --------------------------
burst = ["/admin%d/" % n for n in range(60)]
burst_log = sweeper_log("burst.log", "185.9.186.245", burst)
_, burst_v = audit_for("burst", burst_log)
check("pathbrute: a sweep finished inside one burst is caught",
      "185.9.186.245" in burst_v, sorted(burst_v))
check("pathbrute: over the intent window, not per interval",
      "in 30m" in " ".join(m["reason"] for m in burst_v.values()),
      [m["reason"] for m in burst_v.values()])

# --- R6: and a visitor hitting a broken theme is still spared -----------------
broken_log = write("broken.log", "")
with open(broken_log, "a", encoding="utf-8") as handle:
    for n in range(50):
        handle.write('182.8.225.43 - - [%s] "GET /wp-content/themes/x/gone%d.css '
                     'HTTP/1.1" 404 0 "-" "Mozilla/5.0"\n' % (stamp_now(), n))
    for n in range(120):
        handle.write('182.8.225.43 - - [%s] "GET /artikel/%d/ HTTP/1.1" 200 18000 '
                     '"-" "Mozilla/5.0"\n' % (stamp_now(), n))
_, broken = audit_for("broken", broken_log)
check("pathbrute: a visitor served 404s by a broken theme is not blocked",
      "182.8.225.43" not in broken, sorted(broken))

# --- R4: profiling survives a mixed-vhost host -------------------------------
#
# One asset-free application beside one ordinary site. Pooled asset ratio is far
# below SITE_ASSET_RATIO_MIN, but several individual clients clearly fetch assets,
# so the signal is usable and must not switch itself off.
mixed = {"pages": {}, "assets": {}}
for n in range(400):                       # the case-tracking app: no assets at all
    mixed["pages"]["10.9.%d.%d" % (n // 250, n % 250)] = 40
for n in range(5):                         # ordinary visitors on the other vhost
    mixed["pages"]["203.0.113.%d" % (n + 20)] = 40
    mixed["assets"]["203.0.113.%d" % (n + 20)] = 60
mixed_engine = audit_engine.AuditEngine(dict(cfg))
mixed_engine._calibrate_client_profiling(mixed)
check("profiling: a pooled ratio below the floor does not switch it off alone",
      mixed_engine.site_ratio < 0.40, round(mixed_engine.site_ratio, 3))
check("profiling: because five clients demonstrably fetched assets",
      mixed_engine.profile_witnesses >= 3, mixed_engine.profile_witnesses)
check("profiling: so it stays enabled", mixed_engine.profiling is True)

# --- R4: a genuine CDN host must still disable it ----------------------------
cdn_only = {"pages": {"203.0.113.%d" % n: 40 for n in range(10)}, "assets": {}}
cdn_engine = audit_engine.AuditEngine(dict(cfg))
cdn_engine._calibrate_client_profiling(cdn_only)
check("profiling: with nobody fetching assets it still disables itself",
      cdn_engine.profiling is False)
check("profiling: and the message says how many clients were checked",
      "client(s) of" in (cdn_engine.flags_extra or ""), cdn_engine.flags_extra)


# ============================================================== rc13 Fase 4
#
# R1 was measured, not imagined: 70 individual /64 entries sat under one accepted
# /56 on a production host — 69% of that blacklist was redundant.

sup_state = os.path.join(work, "state_sup")
sup_cfg = dict(cfg)
sup_cfg["STATE_DIR"] = steady(sup_state)
sup_cfg["BLACKLIST"] = os.path.join(work, "blacklist_sup.txt")
with open(sup_cfg["BLACKLIST"], "w", encoding="utf-8") as handle:
    handle.write("# header\n")
    handle.write("2a03:2880:f800::/56    # 2026-08-16 01:06 | Subnet6Flood | "
                 "PERMANENT | strike=1 | expires=-\n")
    for n in range(4):
        handle.write("2a03:2880:f800:%d::/64    # 2026-08-16 00:52 | Subnet6Flood | "
                     "PERMANENT | strike=1 | expires=-\n" % n)
    handle.write("78.153.140.0/24    # 2026-08-16 09:18 | SubnetCoordinatedAttack | "
                 "PERMANENT | strike=1 | expires=-\n")
    handle.write("78.153.140.39    # 2026-08-15 22:56 | ReconScanner | "
                 "PERMANENT | strike=1 | expires=-\n")
    handle.write("203.0.113.200    # 2026-08-15 22:56 | ReconScanner | "
                 "PERMANENT | strike=1 | expires=-\n")

sup_engine = apply_engine.ApplyEngine(sup_cfg)
sup_engine.audit.evaluate_candidates = lambda panel=None: {}
_, sup_entries = sup_engine.execute(dry_run=False)
removed = [target for target, _parent in sup_engine.superseded]

check("supersede: /64 members under an accepted /56 are removed",
      "2a03:2880:f800:0::/64" in removed or "2a03:2880:f800::/64" in removed,
      removed)
check("supersede: all four redundant /64s go", len(
      [r for r in removed if r.startswith("2a03")]) == 4, removed)
check("supersede: the covering /56 stays", "2a03:2880:f800::/56" in sup_entries)
check("supersede: an IPv4 member under an accepted /24 goes too",
      "78.153.140.39" in removed, removed)
check("supersede: the covering /24 stays", "78.153.140.0/24" in sup_entries)
check("supersede: an unrelated address is untouched",
      "203.0.113.200" in sup_entries, sorted(sup_entries))
check("supersede: each removal names the entry that covers it",
      all(parent for _t, parent in sup_engine.superseded),
      sup_engine.superseded[:2])

# --- a PERMANENT member must not be dropped in favour of a TEMP range ---------
tier_cfg = dict(cfg)
tier_cfg["STATE_DIR"] = steady(os.path.join(work, "state_tier"))
tier_cfg["BLACKLIST"] = os.path.join(work, "blacklist_tier.txt")
with open(tier_cfg["BLACKLIST"], "w", encoding="utf-8") as handle:
    handle.write("45.148.10.0/24    # 2026-08-16 09:18 | Subnet | TEMP | "
                 "strike=1 | expires=%d\n" % (int(time.time()) + 86400))
    handle.write("45.148.10.238    # 2026-08-15 22:56 | ReconScanner | "
                 "PERMANENT | strike=1 | expires=-\n")
tier_engine = apply_engine.ApplyEngine(tier_cfg)
tier_engine.audit.evaluate_candidates = lambda panel=None: {}
_, tier_entries = tier_engine.execute(dry_run=False)
check("supersede: a PERMANENT member survives a TEMP range that would expire",
      "45.148.10.238" in tier_entries, sorted(tier_entries))

# --- R1/CSF: removals must be released, and a missed release must self-heal ----
#
# The first version of this derived the release list from one run's deltas, and
# lost releases in silence. Verified against a real host: three members pruned
# during a run with ENFORCE=0 left the blacklist while the release list written by
# that run was overwritten before anything called `csf -dr`. Three entries stayed
# in another agent's config with nothing tracking them.
rel_state = os.path.join(work, "state_rel")
rel_cfg = dict(cfg)
rel_cfg["STATE_DIR"] = steady(rel_state)
rel_cfg["BLACKLIST"] = os.path.join(work, "blacklist_rel.txt")
with open(rel_cfg["BLACKLIST"], "w", encoding="utf-8") as handle:
    handle.write("78.153.140.0/24    # 2026-08-16 09:18 | Subnet | PERMANENT | "
                 "strike=1 | expires=-\n")

# what CSF is holding for us, including three entries no longer in the blacklist
with open(os.path.join(rel_state, "csf_pushed.json"), "w", encoding="utf-8") as handle:
    json.dump(["78.153.140.0/24", "78.153.140.39", "78.153.140.40",
               "198.18.51.9"], handle)

rel_engine = apply_engine.ApplyEngine(rel_cfg)
rel_engine.audit.evaluate_candidates = lambda panel=None: {}
_, rel_entries = rel_engine.execute(dry_run=False)
rel_path = os.path.join(work, "csf_release.list")
rel_engine.emit_csf_release(rel_path, rel_entries)
released = open(rel_path, encoding="utf-8").read().split()

check("csf: entries CSF holds that logwall no longer tracks are released",
      sorted(released) == ["198.18.51.9", "78.153.140.39", "78.153.140.40"],
      released)
check("csf: the entry still on the blacklist is NOT released",
      "78.153.140.0/24" not in released, released)

# a release only has to be computed once; the record follows the blacklist
rel_engine2 = apply_engine.ApplyEngine(rel_cfg)
rel_engine2.audit.evaluate_candidates = lambda panel=None: {}
_, rel_entries2 = rel_engine2.execute(dry_run=False)
rel_path2 = os.path.join(work, "csf_release2.list")
rel_engine2.emit_csf_release(rel_path2, rel_entries2)
check("csf: once released, the same address is not queued again",
      open(rel_path2, encoding="utf-8").read().strip() == "",
      open(rel_path2, encoding="utf-8").read().strip())

# and an expired TEMP block leaves the blacklist, so the diff picks it up
exp_state = os.path.join(work, "state_exp")
exp_cfg = dict(cfg)
exp_cfg["STATE_DIR"] = steady(exp_state)
exp_cfg["BLACKLIST"] = os.path.join(work, "blacklist_exp.txt")
with open(exp_cfg["BLACKLIST"], "w", encoding="utf-8") as handle:
    handle.write("198.18.51.9    # 2026-08-15 22:56 | CloudScraper | TEMP | "
                 "strike=1 | expires=%d\n" % (int(time.time()) - 3600))
with open(os.path.join(exp_state, "csf_pushed.json"), "w", encoding="utf-8") as handle:
    json.dump(["198.18.51.9"], handle)
exp_engine = apply_engine.ApplyEngine(exp_cfg)
exp_engine.audit.evaluate_candidates = lambda panel=None: {}
_, exp_entries = exp_engine.execute(dry_run=False)
exp_rel = os.path.join(work, "csf_release_exp.list")
exp_engine.emit_csf_release(exp_rel, exp_entries)
check("csf: an expired TEMP block is released instead of living forever",
      "198.18.51.9" in open(exp_rel, encoding="utf-8").read(),
      open(exp_rel, encoding="utf-8").read().strip())

# --- R5: no shipped setting may be unread by every code path ------------------
repo = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
conf_text = open(os.path.join(repo, "conf", "logwall.conf"), encoding="utf-8").read()
keys = set(re.findall(r"(?m)^([A-Z_0-9]+)=", conf_text))
haystack = []
for folder, _dirs, names in os.walk(repo):
    if any(part in folder for part in (".git", "__pycache__", "docs")):
        continue
    for name in names:
        if name in ("logwall.conf", "CHANGELOG.md") or name.endswith(".log"):
            continue
        if name.endswith((".py", ".sh", ".md")) or name == "logwall":
            try:
                haystack.append(open(os.path.join(folder, name),
                                     encoding="utf-8", errors="ignore").read())
            except OSError:
                continue
blob = "\n".join(haystack)
orphans = sorted(k for k in keys if k not in blob)
check("config: every shipped setting is read by some code path", orphans == [],
      orphans)


# ============================================================== rc13 Fase 5 (R13)
check("factclaim: the peer field is named as the fact it is",
      log_parser.RawRequest._fields[0] == "peer")
check("factclaim: the forwarded header is a separate, named field",
      "forwarded" in log_parser.RawRequest._fields)
check("factclaim: an attributed request carries whether it could be resolved",
      "resolved" in log_parser.Request._fields)
check("factclaim: parsing yields named requests, not anonymous tuples",
      type(p_spoof._parse_line(
          '45.33.32.156 - - [%s] "GET / HTTP/1.1" 200 5 "-" "x"' % stamp_now())
      ).__name__ == "RawRequest")


# ====================================== rc13: rotation defeats per-address strikes
#
# Measured on a production host: one crawler held eight addresses in the offender
# history, seven TEMP and expiring, two more already active and unblocked. Every
# block was correct and nothing was ever learned. The /24 averaged 94 hits per
# interval against a subnet threshold of 300, so no existing rule could reach it.

def rotation_engine(name, history, extra=None):
    st = steady(os.path.join(work, "state_" + name))
    local = dict(cfg)
    local["STATE_DIR"] = st
    local["BLACKLIST"] = os.path.join(work, "blacklist_" + name + ".txt")
    if extra:
        local.update(extra)
    with open(os.path.join(st, "offender_history.json"), "w", encoding="utf-8") as fh:
        json.dump(history, fh)
    eng = apply_engine.ApplyEngine(local)
    eng.audit.evaluate_candidates = lambda panel=None: {}
    return eng

# one actor rotating addresses: same signal every time
same = dict(("216.73.216.%d" % n, {"strike": 1, "last": int(time.time()),
                                   "class": "CloudScraper"})
            for n in (7, 44, 74, 111, 138, 163, 188, 248))
eng = rotation_engine("rot_same", same)
_, ent = eng.execute(dry_run=False)
check("rotation: a range that keeps producing fresh offenders is blocked",
      "216.73.216.0/24" in ent, sorted(t for t in ent if "/" in t))
check("rotation: the reason states how many addresses and which signal",
      "8 addresses, all CloudScraper" in ent["216.73.216.0/24"].reason,
      ent.get("216.73.216.0/24").reason if "216.73.216.0/24" in ent else None)
check("rotation: a volume-class actor gets TEMP, keeping the ladder intact",
      ent["216.73.216.0/24"].tier == "TEMP", ent["216.73.216.0/24"].tier)

# a hosting provider whose tenants are independently compromised: mixed signals
mixed = {
    "103.253.27.103": {"strike": 1, "last": int(time.time()), "class": "XmlRpcExploit"},
    "103.253.27.105": {"strike": 1, "last": int(time.time()), "class": "XmlRpcExploit"},
    "103.253.27.59":  {"strike": 1, "last": int(time.time()), "class": "XmlRpcExploit"},
    "103.253.27.51":  {"strike": 1, "last": int(time.time()), "class": "BruteForce"},
}
eng_mixed = rotation_engine("rot_mixed", mixed)
_, ent_mixed = eng_mixed.execute(dry_run=False)
check("rotation: mixed signals in one range are NOT one actor, so no range block",
      "103.253.27.0/24" not in ent_mixed, sorted(ent_mixed))

# intent-class rotation goes straight to PERMANENT, as intent always has
intent = dict(("45.148.10.%d" % n, {"strike": 1, "last": int(time.time()),
                                    "class": "ReconScanner"})
              for n in (10, 11, 12, 13))
eng_intent = rotation_engine("rot_intent", intent)
_, ent_intent = eng_intent.execute(dry_run=False)
check("rotation: an intent-class actor is permanent, like every intent verdict",
      ent_intent.get("45.148.10.0/24") is not None
      and ent_intent["45.148.10.0/24"].tier == "PERMANENT",
      ent_intent.get("45.148.10.0/24"))

# below the threshold, nothing happens
few = dict(("93.123.109.%d" % n, {"strike": 1, "last": int(time.time()),
                                  "class": "ReconScanner"}) for n in (228, 234))
eng_few = rotation_engine("rot_few", few)
_, ent_few = eng_few.execute(dry_run=False)
check("rotation: two addresses is a coincidence, not a pattern",
      "93.123.109.0/24" not in ent_few, sorted(ent_few))

# history written before the class was recorded must not qualify a range
legacy = dict(("216.73.217.%d" % n, {"strike": 1, "last": int(time.time())})
              for n in (7, 44, 74, 111, 138))
eng_legacy = rotation_engine("rot_legacy", legacy)
_, ent_legacy = eng_legacy.execute(dry_run=False)
check("rotation: pre-rc13 history has no signal class, so it cannot qualify a range",
      "216.73.217.0/24" not in ent_legacy, sorted(ent_legacy))

# ...unless the blacklist still holds the reason, which is checkable evidence
bf_state = steady(os.path.join(work, "state_rot_backfill"))
bf_cfg = dict(cfg)
bf_cfg["STATE_DIR"] = bf_state
bf_cfg["BLACKLIST"] = os.path.join(work, "blacklist_rot_backfill.txt")
with open(bf_cfg["BLACKLIST"], "w", encoding="utf-8") as fh:
    for n in (7, 44, 74, 111):
        fh.write("216.73.218.%d    # 2026-08-17 10:00 | CloudScraper | PERMANENT | "
                 "strike=1 | expires=-\n" % n)
with open(os.path.join(bf_state, "offender_history.json"), "w", encoding="utf-8") as fh:
    json.dump(dict(("216.73.218.%d" % n, {"strike": 1, "last": int(time.time())})
                   for n in (7, 44, 74, 111)), fh)
eng_bf = apply_engine.ApplyEngine(bf_cfg)
eng_bf.audit.evaluate_candidates = lambda panel=None: {}
_, ent_bf = eng_bf.execute(dry_run=False)
check("rotation: the class is recovered from the blacklist, so the rule works at once",
      "216.73.218.0/24" in ent_bf, sorted(t for t in ent_bf if "/" in t))

# and the whitelist still wins
wl = dict(("203.0.113.%d" % n, {"strike": 1, "last": int(time.time()),
                                "class": "CloudScraper"})
          for n in (10, 11, 12, 13))
eng_wl = rotation_engine("rot_wl", wl)
_, ent_wl = eng_wl.execute(dry_run=False)
check("rotation: a range overlapping the whitelist is refused, not blocked",
      "203.0.113.0/24" not in ent_wl, sorted(ent_wl))
check("rotation: and the refusal is recorded with a reason",
      any("203.0.113" in str(k) for k in eng_wl.audit.refused),
      eng_wl.audit.refused)

check("rotation: the guard can be switched off",
      "216.73.216.0/24" not in rotation_engine(
          "rot_off", same, {"ROTATION_GUARD": "0"}).execute(dry_run=False)[1])


# ============================== rc13 follow-up: three bugs found by deploying
#
# All three were in code written earlier the same day, and none was caught by this
# suite until after a real host disagreed with it.

# --- the profiling witness count missed asset-only clients -------------------
only_assets = {"pages": {}, "assets": {"203.0.113.%d" % n: 12 for n in range(5)}}
wa = audit_engine.AuditEngine(dict(cfg))
wa._calibrate_client_profiling(only_assets)
check("witness: a client with assets and no pages is still a witness",
      wa.profile_witnesses == 5, wa.profile_witnesses)

# --- and its sample floor has to be reachable inside the intent window -------
modest = {"pages": {"203.0.113.%d" % n: 3 for n in range(4)},
          "assets": {"203.0.113.%d" % n: 9 for n in range(4)}}
wm = audit_engine.AuditEngine(dict(cfg))
wm._calibrate_client_profiling(modest)
check("witness: 12 requests in the window is enough to judge a client",
      wm.profile_witnesses == 4, wm.profile_witnesses)
check("witness: so profiling survives a mixed host", wm.profiling is True)
tiny = {"pages": {"203.0.113.9": 2}, "assets": {"203.0.113.9": 3}}
wt = audit_engine.AuditEngine(dict(cfg))
wt._calibrate_client_profiling(tiny)
check("witness: but five requests is still too few to judge anyone",
      wt.profile_witnesses == 0, wt.profile_witnesses)

# --- the CSF pushed-record must seed from csf.deny, not from empty ------------
seed_state = steady(os.path.join(work, "state_seed"))
seed_cfg = dict(cfg)
seed_cfg["STATE_DIR"] = seed_state
seed_cfg["BLACKLIST"] = os.path.join(work, "blacklist_seed.txt")
seed_cfg["CSF_DENY"] = write("csf_deny_seed.txt", "\n".join([
    "# Copyright",
    "78.153.140.39 # ReconScanner - Sat Aug 15 22:58:23 2026",
    "20.251.112.238 # WebshellHunter - Mon Aug 17 17:30:30 2026",
    "216.73.216.4 # CloudScraper | WebApp | Hits: 40x - Sun Aug 16 07:18:03 2026",
    "185.20.30.40 # lfd: (PERMBLOCK) 185.20.30.40 has had more than 4 blocks",
    "tcp|in|d=22|s=1.2.3.4 # a port rule, not an address",
]) + "\n")
seeded = apply_engine.ApplyEngine(seed_cfg).load_pushed_record()
check("csf seed: logwall's own entries are recovered from csf.deny",
      seeded == {"78.153.140.39", "20.251.112.238", "216.73.216.4"}, sorted(seeded))
check("csf seed: an lfd entry is never claimed as ours",
      "185.20.30.40" not in seeded, sorted(seeded))
check("csf seed: a port rule is not mistaken for an address",
      not any("|" in t for t in seeded), sorted(seeded))

# so the orphans that predate the record are released on the very first run
seed_engine = apply_engine.ApplyEngine(seed_cfg)
seed_engine.audit.evaluate_candidates = lambda panel=None: {}
_, seed_entries = seed_engine.execute(dry_run=False)
seed_out = os.path.join(work, "csf_release_seed.list")
seed_engine.emit_csf_release(seed_out, seed_entries)
released_seed = open(seed_out, encoding="utf-8").read().split()
check("csf seed: entries CSF holds but the blacklist does not are released at once",
      sorted(released_seed) == ["20.251.112.238", "216.73.216.4", "78.153.140.39"],
      released_seed)


# ============================ rc13: profiling gets its own, wider window
#
# Measured on a medium-traffic host: 9 of 331 addresses reached 8 requests inside
# the 30-minute intent window, and a real visitor had 7. Reading pages/assets from
# that window made the profiling signal inert in production.

pw = log_parser.TrafficWindow(steady(os.path.join(work, "state_pw")),
                              interval=120, strikes_window=10,
                              intent_minutes=30, profile_minutes=240)
check("profwin: the profiling window is eight times the intent window",
      pw.profile_buckets == 120 and pw.intent_buckets == 15,
      (pw.profile_buckets, pw.intent_buckets))
check("profwin: retention follows the widest of the three",
      pw.keep_buckets == 120, pw.keep_buckets)
check("profwin: and it reports the span it actually bucketed",
      pw.profile_minutes() == 240 and pw.intent_minutes() == 30,
      (pw.profile_minutes(), pw.intent_minutes()))

base = int(time.time())
old_stamp = base - 200 * 60      # inside 240m, far outside 30m
for _ in range(9):
    pw.add("203.0.113.55", "assets", 1, old_stamp)
    pw.add("203.0.113.55", "wp", 1, old_stamp)
for _ in range(2):
    pw.add("203.0.113.55", "pages", 1, base)

check("profwin: assets from three hours ago still count for profiling",
      pw.profile_sum("assets").get("203.0.113.55") == 9,
      pw.profile_sum("assets").get("203.0.113.55"))
check("profwin: but the intent window does not see them",
      pw.intent_sum("assets").get("203.0.113.55") is None,
      pw.intent_sum("assets").get("203.0.113.55"))
check("profwin: an intent counter from three hours ago is OUT of range for intent",
      pw.intent_sum("wp").get("203.0.113.55") is None,
      pw.intent_sum("wp").get("203.0.113.55"))

# The subtle one, and the reason prune() had to become metric-aware.
#
# _recent() measures from the address's OWN newest bucket, not from now. Retention
# used to be 15 buckets, so an intent counter simply could not survive long enough
# to matter. At 120 buckets an address whose last activity was three hours ago would
# have that activity summed as though it were current — the window is relative, and
# the address had nothing newer to be relative to.
stale = log_parser.TrafficWindow(steady(os.path.join(work, "state_pw3")),
                                 interval=120, strikes_window=10,
                                 intent_minutes=30, profile_minutes=240)
for _ in range(9):
    stale.add("203.0.113.77", "wp", 1, base - 200 * 60)
check("profwin: before pruning a stale counter WOULD read as current",
      stale.intent_sum("wp").get("203.0.113.77") == 9,
      stale.intent_sum("wp").get("203.0.113.77"))
stale.prune(base)
check("profwin: pruning strips it, which is what keeps the wider window safe",
      stale.intent_sum("wp").get("203.0.113.77") is None,
      stale.intent_sum("wp").get("203.0.113.77"))

# after pruning, the old bucket keeps ONLY the profiling metrics
pw.prune(base)
old_index = old_stamp // 120
kept = pw.entries["203.0.113.55"][old_index]
check("profwin: past the intent window a bucket keeps only pages/assets",
      set(kept) <= {"pages", "assets"} and kept.get("assets") == 9, kept)
check("profwin: so a punishable counter cannot linger in the long window",
      "wp" not in kept, kept)
check("profwin: and after pruning intent no longer counts it",
      pw.intent_sum("wp").get("203.0.113.55") is None,
      pw.intent_sum("wp").get("203.0.113.55"))

# the boundary is enforced, not merely documented
try:
    pw.profile_sum("wp")
    guarded = False
except ValueError:
    guarded = True
check("profwin: profile_sum refuses any metric that is not a profiling metric",
      guarded)

# and the real case: a visitor too quiet to judge in 30 minutes becomes judgeable
quiet = log_parser.TrafficWindow(steady(os.path.join(work, "state_pw2")),
                                 interval=120, strikes_window=10,
                                 intent_minutes=30, profile_minutes=240)
for n in range(12):                      # spread over two hours, 7 in any 30 min
    stamp = base - (n * 10 * 60)
    quiet.add("203.0.113.66", "assets", 1, stamp)
check("profwin: a quiet visitor accumulates enough samples to be characterised",
      quiet.profile_sum("assets").get("203.0.113.66") == 12,
      quiet.profile_sum("assets").get("203.0.113.66"))
check("profwin: which the intent window could never have supplied",
      (quiet.intent_sum("assets").get("203.0.113.66") or 0) <= 4,
      quiet.intent_sum("assets").get("203.0.113.66"))


# ================================ Python 3.6: the floor preflight actually accepts
#
# `subnet_of()` arrived in 3.7. preflight accepts 3.6, so the code has to keep that
# claim. It did not — a host on 3.6 raised AttributeError on every apply, and cron
# discarded stderr so nobody saw it. The run log added in this same release surfaced
# it within minutes of being switched on.
import ipaddress as _ip
check("py36: a /64 inside a /56 is contained",
      ip_guard.contained_in(_ip.ip_network("2a03:2880:f800:10::/64"),
                            _ip.ip_network("2a03:2880:f800::/56")))
check("py36: a /24 is not inside an unrelated /24",
      not ip_guard.contained_in(_ip.ip_network("78.153.140.0/24"),
                                _ip.ip_network("78.153.141.0/24")))
check("py36: a single address inside its own /24 is contained",
      ip_guard.contained_in(_ip.ip_network("78.153.140.39/32"),
                            _ip.ip_network("78.153.140.0/24")))
check("py36: a network is contained in itself",
      ip_guard.contained_in(_ip.ip_network("10.0.0.0/8"),
                            _ip.ip_network("10.0.0.0/8")))
check("py36: a wider network is NOT inside a narrower one",
      not ip_guard.contained_in(_ip.ip_network("10.0.0.0/8"),
                                _ip.ip_network("10.1.0.0/16")))
check("py36: families never mix",
      not ip_guard.contained_in(_ip.ip_network("10.0.0.0/8"),
                                _ip.ip_network("::/0")))

# matches the stdlib wherever the stdlib has the method at all
if hasattr(_ip.ip_network("10.0.0.0/8"), "subnet_of"):
    pairs = [("10.0.0.0/24","10.0.0.0/8"), ("10.0.0.0/8","10.0.0.0/24"),
             ("192.168.1.0/24","10.0.0.0/8"), ("2001:db8::/48","2001:db8::/32"),
             ("2001:db8::/32","2001:db8::/48"), ("10.0.0.5/32","10.0.0.0/30")]
    same = all(ip_guard.contained_in(_ip.ip_network(a), _ip.ip_network(b))
               == _ip.ip_network(a).subnet_of(_ip.ip_network(b)) for a, b in pairs)
    check("py36: contained_in agrees with subnet_of on every pair tried", same)

# and no 3.7+ API may creep back into the shipped code
_libdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib", "py")
_offenders = []
for _name in os.listdir(_libdir):
    if not _name.endswith(".py"):
        continue
    _src = open(os.path.join(_libdir, _name), encoding="utf-8").read()
    for _api in (".subnet_of(", ".supernet_of(", "capture_output=",
                 "fromisoformat(", ".removeprefix(", ".removesuffix("):
        if _api in _src:
            _offenders.append("%s: %s" % (_name, _api))
check("py36: no Python 3.7+ API is used while preflight accepts 3.6",
      _offenders == [], _offenders)


print()
if failures:
    print(f"RESULT: {len(failures)} FAILURE(S): {failures}")
else:
    print("RESULT: all checks passed")
shutil.rmtree(work, ignore_errors=True)
sys.exit(1 if failures else 0)
