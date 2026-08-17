# Changelog

Every significant change to logwall. Versions follow [SemVer](https://semver.org/).

## 1.0.0-rc13 — 2026-08-17 (say what the run did; stop believing what clients claim)

Twelve findings, every one of them measured on a live host rather than reasoned
about. They fall into two groups, and the second group is the reason the first one
had to be fixed first.

### The product was telling operators things that were not true

Five separate places where logwall reported something false, or withheld the one
fact that made the line actionable.

**The daily summary counted the wrong day.** Cron runs the report at 00:05, and it
counted blacklist rows stamped with "today" — a day that was five minutes old.
Measured: 22 blocks on one day reported as 0, and 25 blocks in the following period
reported as 1. A second defect sat in the same line: it counted rows, so a TEMP
block created and released between two reports left no row and was never counted
anywhere. The one thing a daily summary exists to state was unstateable. Reports
now summarise the day that ended and count from an append-only event record.

**Status reported an empty blocklist on a host with 46 live blocks.**

```
Enforcement via : CSF coordination — blocks pushed with 'csf -d'
Enforcement     : ON (dropping)
LOGWALL_BL4     : 0 entries        <- csf.deny held 46
```

The set-count block was gated on whether ipset exists, not on the backend. CSF
installs ipset itself, so logwall printed four of its own sets — which it never
creates in that mode. CSF hosts now report what csf.deny is actually enforcing.

**Guards reported a tally, not the address.** `[GUARD] WHITELIST: 1` is true and
useless. The address→reason mapping was already in memory; only the count was
printed. This cost real time: a prediction script bypassed the guard, reported an
address as a pending block, and the reason it could never be blocked was sitting in
that unprinted field.

**Health flags named the whole file for one bad line.** One unresolvable request in
537 read as "this log is unusable". Both flags now carry the affected share, and a
log that lost nothing raises no flag.

**And the cron line logwall installs discarded every diagnostic it emits.** It
ended in `>/dev/null 2>&1`, and PROFILING_OFF, GUARD refusals, CSF_RESYNC,
SETTING_RENAMED and CDN_NO_REALIP all go to stderr. On one host PROFILING_OFF fired
on every run for a day while the daily report said `[FLAG] none`. Output now goes
to a run log which logwall trims itself, and the last run's flags are persisted so
the report can state them hours later.

### A client could choose which address logwall blocked

`_recover_real_ip()` scanned the whole log line for anything shaped like an address
and used the first one that was not the peer, whenever the peer sat in a CDN range.
The URI, the referer and the user-agent are all in that line and all under the
client's control — and `reversed()` preferred exactly those, because they come last.

```
GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0 (8.8.8.8)"
                                          ^ became "the real client"
```

The useful direction for an attacker is the other one: forward the operator's own
whitelisted address and every guard refuses to block you, on every cycle, forever,
while the run log says only `[GUARD] WHITELIST: 1`.

Proven on a live host with no CDN involved at all — a request sent from the admin's
own address carrying `X-Forwarded-For: 192.0.2.77` was logged as 192.0.2.77,
because the web server trusted forwarding headers from anyone.

A forwarding header is now read only when the peer is a CDN edge already trusted,
which is the same rule nginx enforces with `set_real_ip_from`. Two things turned up
while implementing it: the trailing XFF field was never captured by the log regex
at all, so the "recover real IP from XFF" behaviour tested since 1.0 was
implemented *entirely* by the unsafe line scan; and Python's `is_private` covers
the documentation ranges every test and tutorial uses.

**And when the client field itself cannot be believed, logwall stops punishing.** A
public server cannot be reached from 10.0.0.5. One of those in the client field
proves something upstream is rewriting it from a client-supplied header, so
blocking is suspended, the addresses that prove it are named, and the fix is
printed for nginx, Apache and LiteSpeed. Measured rather than parsed from config,
because that misconfiguration wears a different directive name in every web server.

Preflight warns rather than refusing to install: a product that will not start
reads as broken rather than careful.

### Webshell hunters walked free for a day

Four addresses, 170/117/50/47 requests each, every one a 404, hunting for shells
somebody else had already planted. They slipped between four rules at once — no
scanner UA, random .php names absent from the sensitive-file list, xmlrpc touched
once, and 404 counted as volume at 30 per interval while 170 requests over twelve
hours is about one per interval.

That last one is rc12's lesson repeated in a different rule, and it failed in both
directions: one scanner escaped by finishing inside a single burst, the others by
going slow.

A 404 on a page is ordinary. A 404 on a **source file** is not, because visitors
and crawlers follow links and nothing links to `/dvoqqmkm.php`. Measured on 636,000
requests: 73 source-file 404s against 1,345 page 404s, and all 19 addresses
responsible were hostile — including two wearing legitimate crawler names.

**The count cannot carry the rule, and that is the part worth keeping.** On a
WordPress host that had removed an accessibility plugin, five real visitors on
phones kept asking for a file that no longer existed. One of them 14 times — more
than nine of the sixteen genuine sweepers on that host. Any threshold on the number
is either blind or cruel, and the number that looked safe on the busiest host would
have blocked real people reaching a court's website through its screen reader.

What separates them is whether the address behaved like a client at all:

```
16 sweepers        asset ratio 0.00, successes 0-1
 5 real visitors   asset ratio 0.39-0.81, successes 29-167
```

Not a gradient — a wall. Both 404 rules now consult a behavioural veto, the first
guard in logwall based on what an address did rather than who it is. Success is
counted separately from the asset ratio, because on a genuinely CDN-fronted site a
real visitor shows no asset requests either while their HTML still returns 200.

`PathBruteForce` moves to the intent window for the same reason.

### The profiling gate was asking the wrong question

```
Site asset ratio 8% is below 40%; assets are probably served elsewhere
```

False on the host that said it. Its real visitors were pulling 39-81% assets from
that very log. What dragged the pooled figure down was a court case-tracking
application sharing the host — 80% of traffic, genuinely asset-free — which
disabled profiling for the WordPress vhost too. "What is the average" is not "does
anybody here behave like a browser".

### Housekeeping with teeth

**Members covered by an accepted range are now removed.** 70 individual /64 entries
sat under one accepted /56 on a production host: 69% of that blacklist was
redundant. Removals are announced individually and name the entry that covers them.

**And CSF hosts can finally step off the escalation ladder.** `csf -d` was a
one-way door — logwall dropped an expired TEMP entry and csf.deny kept it forever,
so every temporary block on a CSF host was silently permanent.

**Sixteen dead settings removed**, and the suite now asserts that every shipped
setting is read by some code path. Two of them were worse than untidy:
`REAL_IP_FIELD` and `TRUSTED_PROXIES` promised that forwarded identities were being
verified while nothing verified anything.

### One structural change, no behaviour change

The parser's bare ten-tuple becomes named containers with the trust status of every
field written beside it. That anonymity was not incidental to the bug above: a
helper called `_recover_real_ip(peer_ip, line)` looked reasonable next to nine other
unnamed positional fields, and treated the user-agent as an identity source for
three releases.

### Rotation defeated the escalation ladder, and nothing noticed

Strikes are counted per address. An actor who uses a different address each time
never reaches strike 2, so it is met with a fresh TEMP block forever.

Measured on a production host: one crawler held eight addresses in the offender
history, seven of them TEMP and expiring, while two more were already active in the
log unblocked. Every block was correct. Nothing was ever learned.

No existing rule could reach it. `SubnetCoordinatedAttack` wants simultaneous
activity, and the per-interval rollup wants volume — that /24 averaged 94 hits per
interval against a threshold of 300, because 68,000 requests were spread across a
day and eight addresses. It was also, by bytes, the single largest bandwidth
consumer on the host: 290 MB.

A range is now blocked when enough distinct addresses inside it have each
independently tripped a signal — cumulative over the offender history, not within a
window. Two conditions, and the second is what makes a range block safe:

    count  ROTATION_MIN_OFFENDERS distinct addresses, at any time
    class  all of them tripped the SAME signal

The class condition separates one actor from one bad neighbourhood, and the
distinction is not theoretical. On the same host:

    216.73.216.0/24   8 addresses, 8x CloudScraper        -> one actor
    103.253.27.0/24   4 addresses, XmlRpc x3 + BruteForce -> a hosting provider whose
                                                            tenants are independently
                                                            compromised

Blocking the second would punish every other customer of that provider for four of
them. Blocking the first is the only thing that stops the rotation.

Tier follows the existing philosophy rather than inventing one: a range whose
offenders were volume-class gets TEMP and can age out; one whose offenders showed
intent gets PERMANENT. History written before rc13 carries no signal class. Where the entry is still in
the blacklist the class is recovered from it, because that evidence is checkable;
where the entry has already expired the record stays unclassified and is never
counted, because that evidence really is gone.

### Deliberately NOT in this release

Threshold recalibration. Field data says the current numbers are wrong for quiet
hosts — one has a p99 peak-per-interval of 4 against a threshold of 60 — but the
rules that decide what gets blocked changed in this release, so calibrating against
pre-rc13 measurements would be work thrown away. It needs several days of rc13 data
from hosts with different traffic shapes.

The direction of the current error is the safe one: too loose means the volume class
stays quiet, and on those hosts the intent class already carries everything — 23 of
23 blocks on the quietest host came from intent rules.

### Tests

205 → 293 offline checks. Gate unchanged at 72.

The false-positive case is a fixture, and it is verified to fail for the right
reason: the signal fires (14 source-file 404s against a threshold of 2) and the veto
is what spares the visitor. A test that passed because the rule never looked would
have been worse than no test at all.

## 1.0.0-rc12 — 2026-08-16 (counters decay; two classes of signal, two windows)

The counter never went down. `prune()` dropped an address whole once it had been
silent for a full day, so anything seen even once a day accumulated for as long
as it kept visiting. A loyal low-rate visitor would eventually reach a volume
threshold having done nothing, and the thresholds documented as "per
`WINDOW_HOURS`" actually meant "since first continuous activity".

Fixing that meant deciding what a threshold counts over, and measurement said
the answer is different for different signals — in opposite directions.

### Volume is judged per interval, and must repeat

Measured on a production host, 911,795 requests across 1,703 addresses: the
peak-per-interval was 2 at the median and 6 at p90. But the tail belonged to
ordinary people. The three largest single-interval bursts were 134, 88 and 67
requests, each from a residential address that was silent in the next interval —
one modern page view is 30-80 requests, so this is somebody opening a couple of
pages.

Inside a single interval that is indistinguishable from an attacker. What
separates them is repetition: the visitor is loud once, the crawler is loud for
hours.

```
threshold 60, 1 interval over the line   →  80 addresses,  6 of them innocent
threshold 60, 2 intervals over the line  →  64 addresses,  0 innocent
```

Requiring two intervals removed every false positive and lost no genuine
offender. `STRIKES_REQUIRED=2` over `STRIKES_WINDOW=10`.

### Intent is summed over a short sliding window

The opposite shape, because the traffic is the opposite shape. Nobody browses to
`wp-login.php` five times by accident, so a real visitor's base rate is zero —
and attackers exploit exactly that by going slow. On the same host:

```
91.92.242.191    2 attempts per interval, sustained across 97 intervals — 194 total
91.92.243.236    2 per interval, 43 intervals — 84 total
150.109.16.200   2 per interval, 29 intervals — 58 total
2a02:c207:...    2 per interval, 26 intervals — 52 total
```

Four patient brute-forcers, every one of them parked just under
`THRESHOLD_WP_LOGIN=5`. A per-interval threshold catches none of them. Intent
counters therefore sum over `INTENT_WINDOW_MIN=30` minutes instead — and that
window genuinely slides, because the counters live in per-interval buckets that
fall off the back.

Both classes are now regressions in the suite: the slow brute force must still
be caught, and the 134-request visitor must still not be.

### Settings were renamed rather than reinterpreted

`THRESHOLD_HITS`, `THRESHOLD_BW_MB`, `THRESHOLD_404`, `THRESHOLD_SUBNET_HITS` and
`THRESHOLD_SUBNET_BW_MB` counted per `WINDOW_HOURS`. The per-interval rules mean
something else, so the names changed:

| was | is | default |
|---|---|---|
| `THRESHOLD_HITS` | `THRESHOLD_HITS_PER_INTERVAL` | 60 |
| `THRESHOLD_BW_MB` | `THRESHOLD_BW_MB_PER_INTERVAL` | 20 |
| `THRESHOLD_404` | `THRESHOLD_404_PER_INTERVAL` | 30 |
| `THRESHOLD_SUBNET_HITS` | `THRESHOLD_SUBNET_HITS_PER_INTERVAL` | 300 |
| `THRESHOLD_SUBNET_BW_MB` | `THRESHOLD_SUBNET_BW_MB_PER_INTERVAL` | 60 |

A leftover old name is reported on every run and its value ignored. This is the
case that made it non-negotiable: a host running `THRESHOLD_HITS=400` for a day,
read as a per-interval figure on that same host — whose busiest address peaked at
474 — would have switched detection off almost entirely and said nothing about
it. Preflight reports the same thing under `THRESHOLD_RENAMED`.

### Ranges follow the same rule

`/24`, `/64` and `/56` rollups are judged per interval with the same strike
requirement, because a CGNAT or campus range genuinely does light up for one
interval when several of its users load a page at the same moment. Measured
across every range on that host: p99 of per-interval hits was 67, while the one
coordinated crawler sat at 3,031. Default 300.

### Bandwidth is a backstop, not a signal

Measured per interval, the busiest address on a real site pulled 8.1 MB and p99
was 1.04 MB. `THRESHOLD_BW_MB_PER_INTERVAL=20` is therefore inert on an ordinary
site by design, and the config says so — it exists for a host serving large
files, and needs raising there rather than lowering here.

### State

`window.json` now holds per-interval buckets. A file written by an earlier
version holds one running total per address covering an unknown span, so there
is no honest bucket to place it in: it is discarded on load rather than guessed
at, which costs one window of history exactly once.

### Stop advising a package the host cannot install

On a Debian-family host managed by ufw, logwall printed
`apt-get install -y ipset-persistent` as the way to close the reboot gap. That
package pulls in `netfilter-persistent`, and ufw declares `Breaks` against it:

```
$ apt-get install --simulate ipset-persistent
ufw : Breaks: netfilter-persistent but 1.0.20 is to be installed
E: pkgProblemResolver::Resolve generated breaks
```

apt refuses outright, and its own suggested way out is to remove ufw. logwall
prints `backend=ufw` one line above the advice, so it already knew — the package
was chosen from the distro family alone. Advice that contradicts the tool's own
detection is worse than no advice.

The message now states the gap plainly and, for ufw hosts, names the systemd
route instead of a package.

The gap itself was measured rather than assumed. On Ubuntu 24.04 + ufw, with the
chains detached and all four sets destroyed to reproduce what a reboot loses:

```
10:42:14  chains and sets gone
10:44:05  restored by the */2 apply cron   =  111 seconds
          members md5 before a3a05bde...  after a3a05bde...  identical
          3/3 jumps, DROP active, ufw's own 17 rules untouched throughout
```

Worst case is bounded by the cron interval, just under two minutes. The blocklist
file itself is never at risk — the kernel set is only a copy of it.

### Tests

190 → 205 offline checks.

## 1.0.0-rc11 — 2026-08-16 (the blocking cap is gone; six detections added)

An audit of the verdict path, prompted by a question that turned out to have no
good answer: what scenario is `MAX_NEW_BLOCKS_PER_RUN` for?

### The circuit breaker was removed

Every entry reaching the apply stage comes from `evaluate_candidates()` and has
already passed every guard — whitelist, CDN, DDNS, the host's own addresses, the
prefix-width ceiling. There is no other path into that list. So the cap could
only ever mean one thing: *the tool does not trust its own signals*. If that is
true, the signals are what need fixing.

Its record over the project's life:

| Event | What happened | What actually fixed it |
|---|---|---|
| 500 real addresses, one incident | tripped, blocked nothing | `/24` aggregation |
| 70 `/64`s of one crawler | tripped, blocked nothing | `/56` aggregation |
| a threshold regression | never tripped — the damage was gradual | nothing; it was invisible to a counter |

Two firings, both wrong, and blind to the one case that mattered. Three further
faults, each enough on its own:

- **It did not pause; it deadlocked.** State was committed as it aborted, so the
  same candidates returned two minutes later and tripped it again. The only exit
  was a human typing `apply --force-breaker`, which cron never passes.
- **It was silent.** `[BREAKER_TRIPPED]` went to stderr, cron discards stderr,
  and `report_gen.py` had zero references to it. A host could refuse to block
  anything for hours and look perfectly healthy.
- **It released the guilty along with the rest.** The abort cancelled the whole
  batch, intent verdicts included — sqlmap, SSH brute force, `.env` probes.

Measured on a production host (599,701 log lines, 1,298 addresses): of 78
addresses that a cumulative threshold would catch, **75 were already over the
limit inside a single two-minute interval**. The three that were not: the host's
own address, an uptime monitor, and a steady 6-requests-per-interval drip.

`MAX_NEW_BLOCKS_PER_RUN`, `EXIT_BREAKER` (exit code 6) and `--force-breaker` are
gone from the config, the CLI and the design document.

### Replaced by a guard that measures the cause

The hazard the breaker was groping at is real, but it is not "too many
candidates" — it is **time distortion**. A run that ingests hours of log instead
of one interval inflates every volume count by the same factor, and then ordinary
visitors cross a volume threshold without having done anything. It happens on a
fresh install (no cursor exists, so the whole existing log is read from byte
zero), after a cursor reset, and whenever cron stalled or the host was off.

`CATCHUP_GUARD` compares the gap since the previous run against
`CATCHUP_MAX_GAP_MIN` (default 15 minutes). On a catch-up run:

- **volume** detections stand down — hits, bandwidth, 404 storms, login POSTs,
  and the subnet flood and bandwidth rollups
- **intent** detections keep firing — brute force, recon, failed logins, scanner
  signatures. Five probes for `/.env` are five probes whether they arrived over
  two minutes or two days
- the run reports `CATCHUP_RUN` on stdout, in the daily report, and in
  `state/run_meta.json` — the visibility its predecessor never had

### The parser now reads the log's own clock

`COMBINED_RE` matched the `[timestamp]` field and threw it away — no capture
group — and Caddy's `ts` was never read either. Every counter was therefore
stamped with the wall clock at the moment of the run, so `window.json` recorded
when logwall *looked*, not when the visitor *arrived*.

Two things follow from fixing it.

**The catch-up guard measures instead of guessing.** It compares the span of the
data a run actually swallowed against `CATCHUP_MAX_GAP_MIN`. The difference is
not academic: a host powered off for four hours wrote no log at all while it was
down, so the gap between runs is four hours and the span of the data is two
minutes. Keying on the gap would suspend the volume rules for nothing; keying on
the span does not. The gap survives only as a fallback for logs whose stamps
cannot be read.

**The window ages on request time.** `prune()` drops entries older than
`WINDOW_HOURS` measured from the request, so the first run on a host — which
reads the whole existing log from byte zero — no longer treats a week of history
as if it had all arrived at once. A stamp ahead of the clock, or far enough
behind that it would resurrect an entry `prune()` is about to drop, falls back to
the run clock rather than being trusted.

Service auth logs keep the run clock: their syslog stamp carries no year, and the
only rule that reads them is a plain count.

Cost, measured over five runs of the full pipeline: **1.83s → 1.84s per 40,000
lines**, under 1%. Stamps are converted per distinct *second* rather than per
line, because a busy log puts hundreds of requests inside the same second — the
conversion alone is 1.53s per 300k lines uncached and 0.69s cached, against 0.45s
for discarding the field.

### Six detections added

The audit found that logwall was blind in places its own vocabulary already
covered.

**`IntentComposite`** — `wp-login` + `xmlrpc` + sensitive-file + `401/403`,
summed for one address (`THRESHOLD_INTENT_IP`, default 8). The `/24` rollup has
summed these four since 1.0, so a lone attacker was judged *more leniently than
its own neighbours*: 5 wp-login + 2 xmlrpc + 2 recon + 5 rejections passed every
individual threshold and was never even a candidate.

**`ToolSignature`** — an explicit offensive-scanner User-Agent
(`THRESHOLD_ATTACK_UA`, default 1). The marker list was recorded in every window
entry since 1.0 and used only to decorate a reason string with
`(self-declared)`.

The list was **split first**, and that split is the load-bearing part:
`SCRIPT_UA_GENERIC` (curl, wget, python-requests, axios, okhttp, scrapy, …)
informs the browser-vs-script profile and can never justify a block, because
every one of them is somebody's honest API client. `ATTACK_UA_MARKERS` (sqlmap,
nikto, wpscan, nuclei, masscan, zgrab, dirbuster, gobuster, feroxbuster) is the
blocking signal. Blocking the first list would have taken out the operator's own
integrations. An absent User-Agent counts as neither.

**`PathBruteForce`** — 404 responses (`THRESHOLD_404`, default 30) **and** a
minimum share of the address's requests (`RATIO_404_MIN`, default 0.60). Only
401/403 was counted before, so gobuster and feroxbuster — names logwall already
recognised — produced nothing. The ratio condition is mandatory: a site with a
broken theme serves 404s to real visitors, and without it the rule would convict
the victims of the operator's own bug.

**`GenericLoginBrute`** — POSTs to a login endpoint outside WordPress
(`THRESHOLD_LOGIN_POST` default 10, `LOGIN_PATHS` configurable). Only
`wp-login.php` and `xmlrpc.php` were ever hardcoded; `/login`, `/admin`,
`/api/auth` and every framework's own path had no rule at all. GETs are not
counted — a GET of `/login` is the form. Temporary unless the same address also
collected rejections, because a real user who forgot their password does post
repeatedly.

**Sensitive-file list widened** from five tokens to twenty-two: `wp-config.php`,
`.htpasswd`, `.ssh/`, `id_rsa`, `.aws/`, `.svn/`, `/vendor/`, `/actuator`,
`/server-status`, `.DS_Store`, `config.json`, `.npmrc`, `.dockercfg`,
`docker-compose.yml`, `/phpinfo`, `/adminer`, `.old`, `.orig`.
`/.well-known/` is deliberately excluded — ACME renewal lives there, and
flagging it would have the tool block its own certificate renewal.

**`Subnet6HighBandwidth`** — the `/56` tier had rules for failed logins, intent
and request volume but none for bandwidth, which the `/24` tier has had since
1.0. An IPv6 source draining bandwidth across many `/64`s was caught at no level
at all.

### Removed

`THRESHOLD_PANEL_HITS` was listed in the config and in §7 of the design document
and **read by no code**. It is deleted rather than implemented: `PanelBruteForce`
already covers the case through 401/403, and inventing a rule to justify a
setting name is the wrong direction. A scan of the whole config against the whole
codebase found 20 keys in that state; the rest are recorded and will be resolved
one at a time rather than in a batch.

### Tests

144 → 190 offline checks. The fixtures keep their fixed dates — they are meant
to be read — so the suite now shifts every stamp forward at run time; without
that, a fixture written last week correctly produces nothing at all, which is
itself a demonstration that the window is finally aging on the right clock. The new ones cover each detection above, the ordering
that makes an intent verdict win over a volume one for the same address, the
`/.well-known/` exclusion, that `curl` is not an attack signature, that 400
candidates in one run all block, and that a catch-up run suspends volume while
intent still fires.

## 1.0.0-rc10 — 2026-08-16 (IPv6 counted correctly; scope tightened)

Everything here came from one thing: installing on a host that had never seen this
tool, on a stack none of the others used — Ubuntu 24.04, ufw, CyberPanel's cousin
FastPanel, and real IPv6 traffic. Four defects, none of them findable by reading
the code.

### IPv6 was counted per address, not per /64

`IPV6_BLOCK_PREFIX=64` was documented in the config and twice in §14, and no code
read it. A /64 is the block a customer is actually handed, and privacy extensions
rotate the host portion every few hours by default on essentially every modern OS.

Measured: six rotations at 200 hits each produced six keys of 200 against a
threshold of 400. Twelve hundred requests from one visitor, nothing detected.
Blocking inherited the same fault — a `/128` entry is obsolete the moment the
client rotates, while the `/64` holds.

Counting now happens per `/64`, which lands in four places: window keys become
CIDRs, the guard judges them by overlap rather than membership (a `/64` holding
one whitelisted address is refused whole), the subnet rollup takes the network
part before re-aggregating, and state written before the change folds its bare
keys on load. That last part matters: without it a source is counted twice for a
full window and neither key necessarily crosses a threshold the total already
had. `IPV6_BLOCK_PREFIX=128` restores per-address counting.

### A single IPv6 source arrived as seventy candidates

Because a `/64` is the analogue of one IPv4 address, a crawler taking one address
out of each of its `/64`s aggregates to nothing: every network holds exactly one
member, far below `SUBNET_MIN_IPS`.

Measured on that host — a crawler presenting 82 addresses shaped
`2a03:2880:f800:XX::`, roughly 3,000 hits each:

```
before   75 candidates, MAX_NEW_BLOCKS_PER_RUN exceeded,
         [ABORT] Circuit breaker tripped — no firewall rule was changed
after     6 candidates
         2a03:2880:f800::/56   Subnet6Flood | 70 /64s | Hits: 220783x
```

The IPv4 side has always behaved correctly here; the million-request incident in
the README collapses to two candidates because `/24` rollup does its job. IPv6 had
no equivalent tier. It now aggregates at `/56` once `SUBNET6_WIDE_MIN_PREFIXES`
(8) distinct `/64`s show the same behaviour — `/56` rather than `/48` because the
measured distribution fit entirely inside a `/56`, and `/48` is 256× wider for no
additional reach. A `/56` holds 256 `/64`s, the same factor a `/24` aggregates for
IPv4, which keeps the two families symmetrical. `/56` is a hard ceiling.

`MAX_NEW_BLOCKS_PER_RUN` 50 → 100 as headroom, not as the fix. The config says so:
raising it far higher would blunt the guard that exists to catch parser faults,
which is the only reason it exists.

### The parser crashed on the one path meant to protect the host

Python accepts a text-mode `seek()` only for offset 0 or a value `tell()` returned.
An arbitrary byte position leaves the reader in a state where the next `tell()`
raises. The byte budget computes exactly such an offset:

```python
if current_size - offset > budget:
    offset = current_size - budget
```

So the path meant to stop an enormous backlog from exhausting a host was the path
that crashed when a backlog arrived — §16.2 promises a cap and delivered a
traceback. Reproduced on Python 3.8, 3.11 and 3.12; never version-specific.

Reading is now binary with an arithmetic cursor, which also closes a quieter
fault: `len()` on a text line counts CHARACTERS, so every non-ASCII byte made the
byte count drift below the true position — and that number is both the budget and
the saved cursor.

### Scope: fleet sync did not belong in the tree

The README lists fleet sync as roadmap item 5, deliberately outside 1.0. The tree
shipped `lib/py/fleet_sync.py` anyway — referenced by no CLI path, yet covered by
tests — and §7 and §19 documented two commands the CLI has never implemented.

Half-finished scope that ships without being reachable is not inert: it was
reached for during a host migration and used to attempt the one thing this project
explicitly refuses to do, which 1.4.0 removed `import-legacy` to prevent. The
module is gone, the phantom commands are gone from §7, and §19 states the boundary
plainly. Migrating another tool's blocklist is sysadmin work; preflight reports
what it found and names the command to secure the data, and the admin decides.

### Also

CSF's own sets are no longer reported as `[FOREIGN]` in coordination mode.
`preflight` already excluded them; `selftest`, `apply` and `status` did not, so the
chosen configuration was announced as something unexpected — `chain_DENY` is
precisely where logwall's own blocks land there. Third instance of one asymmetry
this release: a code path that knows about CSF coordination beside one that does
not.

144 smoke checks (was 132), gate 72/72.

## 1.0.0-rc9 — 2026-08-15 (two defects found by migrating four production hosts)

Both were found by running the tool, not by reading it, and one of them cost a
production host its enforcement for fifteen minutes.

### `uninstall.sh` never took the lock

§16.1 requires every writer to hold `flock`. `uninstall.sh` did not — being a separate
script rather than a `logwall` subcommand, it slipped past a rule written in terms of the
CLI's shape rather than in terms of who writes. It is the most destructive writer here.

Measured during a migration on a busy host, where a cron `apply` began in the same second:

```
20:42:02  cron apply begins       snapshot 20260815_204203
20:42:03  uninstall begins        detaches hooks, deletes chains, destroys sets
20:42:03  uninstall verifies      reports clean — correctly, at that instant
20:42:04  the in-flight apply     rebuilds the chains and the sets
```

The host was left with orphaned chains still referencing their sets. The next preflight
refused to install, reporting them as `FOREIGN_IPSET` belonging to another tool, and the
host sat unenforced until they were cleared by hand.

The verification was not broken — it was **outrun**, which is the point: checking at the
end is no substitute for holding the lock throughout. Three other hosts came through the
same migration clean, and that was luck, not safety: they were quieter, so their applies
did not overlap.

The lock is now taken before anything is touched, cron removal included. Verified on a
host in both directions — lock held: exit 4 with chains, sets and cron unchanged; lock
free: a complete uninstall leaving zero chains.

### The ipset persistence warning overstated its consequence

The ruleset persistence block already skips firewalld, ufw and CSF because those managers
own their own persistence. The ipset block below it guarded only against CSF, so on a
firewalld host it still announced that at boot `iptables-restore` would fail and the host
would come up "with no firewall rules at all".

Measured there: `/etc/sysconfig/iptables` did not exist and `iptables.service` was not
installed. With no saved ruleset there is no `--match-set` reference that could fail. What
actually happens is that firewalld brings the baseline up and the 2-minute apply cron
rebuilds the sets.

Right about the fact, wrong about the outcome — the same mistake `NO_BASELINE_POLICY` made
with "protects almost nothing", and corrected for the same reason: an operator who checks
one loud claim and finds it false stops believing the quiet ones. The loud wording now
applies only where logwall itself saved a ruleset referencing the sets.

## 1.0.0-rc8 — 2026-08-15 (English throughout; audit findings)

### Everything is now in English

The code always was. The documentation was not: `docs/DESIGN.md` was 42% Indonesian and
`CHANGELOG.md` 57%, both linked from the README as the reference material. Translated in
full, along with 17 comments in `tests/gate_test.sh` — two of which record why a fixture
must read the SSH port from the host and why `systemctl` is stubbed rather than deleted,
which is knowledge worth nothing to a reader who cannot read it.

### Fixes found by auditing the code

- **`bootstrap-baseline` could never read a manager's configuration.**
  `cmd_bootstrap_baseline` returns early unless the backend is iptables or nftables, while
  `_bootstrap_ports` only handled csf, firewalld and ufw. Those values can never meet, so
  the entire block was unreachable — while the comment above it listed it as the primary
  source, complete with field evidence, and the README promised it to users. It is now
  keyed on the presence of the configuration files rather than on the backend name.
- **firewalld ports added as services were dropped silently.** `firewall-cmd --list-ports`
  reports only ports added as bare numbers; anything added the documented way, with
  `--add-service`, appears under `--list-services`. Measured on a live host: the derivation
  produced `[3456]` while the zone also carried cockpit, ssh and dhcpv6-client. After
  reading services too: `[22 546 3456 9090]`. On a host whose operator used
  `--add-service=http`, the old code would have dropped 80 and 443 without a word.
- **The drift monitor's findings were thrown away.** Cron runs `selftest --repair` as
  `--quiet >/dev/null 2>&1`, so every duplicate jump, missing cron entry and orphaned
  deadman it detected was destroyed the moment it was printed. Results are now written to
  `state/selftest.last` unconditionally — `--quiet` governs the console, never the record —
  failures are appended to `${REPORT_DIR}/selftest.log`, and the last result appears in
  `logwall status` and the daily report.
- **The watchdog's last justification collapsed.** A fifth trigger was tested: firewalld
  with `FirewallBackend=iptables` genuinely deletes the `LOGWALL_*` chains, the only
  configuration proven to do so. But what restores them is the 2-minute `apply` cron, not
  the 10-minute selftest — measured at `07:25:58 jump=0` → `07:28:28 jump=3`, a `*/2` slot.
  Zero of five candidate triggers justify it as a repairer, so it is documented as a drift
  monitor instead (§15.5). One gate assertion was pinning the false claim in place and was
  corrected.
- **README corrections:** "Three things go wrong" was followed by four; the test counts
  were stale by 3× (smoke 124 → 137, gate 24 → 72); the firewalld coexistence claim is now
  qualified by backend, since separation is a property of the tables, not of firewalld.
- **Alpine and Arch claims withdrawn.** Both are T2 — complete code paths, never installed
  on a real host — but the README listed them flatly under *Supported*. The code is
  untouched; only the claim is gone, until it has been measured.

### Added

`CONTRIBUTING.md`, stating the scope boundary and the one rule that matters here: a change
in behaviour needs evidence from a real host. GitHub Actions runs all three suites on
Python 3.9, 3.11 and 3.13; the 3.6 floor stays and is verified by hand, because AlmaLinux 8
ships 3.6.

## 1.0.0-rc7 — 2026-08-14 (four real hosts: coexistence, coordination, Debian)

logwall was installed on four production hosts at once — one per mode — and every mode
found a defect of its own. Seven of the nine fixes below are the same class of failure:
**writing or reporting something without verifying that anything reads it.**

### Product position: firewalld and ufw are not competitors

Both own a **baseline** rather than blocking dynamically, so logwall layers on top of them
instead of competing. Previously an active firewalld was a BLOCKER while the
`NO_BASELINE_POLICY` message told the operator to install firewalld: **no sequence of steps
could pass on a stock AlmaLinux 9.** Now only dynamic blocking agents are blockers
(`fail2ban`, `crowdsec`, `crowdsec-firewall-bouncer`, and a CSF you have not opted to
coordinate with), and baseline managers raise `COEXISTS_WITH_MANAGER`.

Proven safe on real hosts, for two different reasons: firewalld places its rules in
`table inet firewalld`, a table separate from `ip filter`, while ufw only rebuilds chains of
its own. `reload`, `complete-reload` and a full service restart leave the `LOGWALL_*` chains
untouched on both.

### Fixes

- **CSF mode never pushed an existing blocklist.** `emit_csf_list()` sent only the entries
  detected on that run, so a list migrated from an older tool sat in `blacklist_ips.txt`
  without a single address reaching CSF — while the run reported success with
  `[CSF] No new addresses to push`. The delta is now measured against `csf.deny` itself;
  steady state stays free, and catch-up is capped by `CSF_RESYNC_MAX_PER_RUN`.
- **A populated `/etc/nftables.conf` was taken as proof of an nftables-native host.** The
  Debian `nftables` package **ships** a sample file, so every stock Debian was misclassified:
  the ruleset was written to an `/etc/nftables.conf` whose service is `disabled` — never read —
  while `/etc/iptables/rules.v4`, which really is loaded at boot, stayed free of logwall rules.
  A configuration file does not prove who reads it; the check was removed.
- **An `/etc/nftables.conf` guard whose comment lied.** The comment promised a host-native
  check; the condition was only `command -v nft`, true on almost every distribution. It now
  asks the unit itself through `svc_is_enabled` (new, completing the `svc_*` abstraction) and
  falls back to the distribution's persistence path otherwise.
- **Debian ipset was written to a path that is not the Debian convention.** What reads it is
  the `netfilter-persistent` plugin from the `ipset-persistent` package, via
  `/etc/iptables/ipsets` — and that package was never mentioned. Because the ruleset
  references `--match-set`, a set missing at boot makes `iptables-restore` **fail entirely**:
  the host comes up with no rules at all, not merely without logwall. Added
  `fw_ipset_restore_available()` and a warning that states the consequence.
- **`fleet_sync.py` refused every CIDR entry.** Validation went through `refusal_reason()`,
  which accepts single addresses only, even though the blocklist is `hash:net`. Range blocks
  from an older tool vanished during migration, and `[SUMMARY]` reported only the successes.
  CIDRs are now routed to `refusal_reason_network()`, and the summary states how many were
  **refused** and how many were duplicates.
- **The baseline check was blind to native nftables.** On a host filtering through its own
  nft tables, `iptables -S INPUT` reports `-P INPUT ACCEPT` and zero rules — a protected host
  that looks bare. The baseline now reads `nft`, and only input hooks with a drop or reject
  policy count.
- **A CSF disabled with `csf -x` was still credited with owning the baseline.** The guardian
  check used only `svc_is_active`, and CSF's oneshot unit stays `active` after being turned
  off — masking the `NO_BASELINE_POLICY` that should have appeared. `nftables` was also
  removed from the guardian list: `nftables.service` is a boot-time rule loader, not a manager.
- **`systemctl disable --now` removed from every FIX text.** `--now` stops the service, and
  stopping a firewall service flushes the ruleset — precisely the incident recorded in rc6.
- **CrowdSec detection** added as a dynamic blocking competitor.

### Clarity

`BACKEND` had been carrying two jobs. `status` now separates them:

```
Enforcement via : logwall chains + ipset (standalone layer)
Persistence by  : firewalld
```

Previously a single `Backend Active : firewalld` line, which read as though logwall enforced
*through* firewalld — something it has never done.

### IPv6 treated as the equal of IPv4

IPv6 has always travelled the same path as IPv4 — one parser, one window, one set of
thresholds, one blacklist file — and only diverges at the end, where the kernel forces
separate sets and tables. What was not equal was the **reporting**.

- **The IPv6 exposure warning no longer silences itself.** The check fired when there were
  fewer than three IPv6 rules — and installation adds exactly three `LOGWALL_*` jumps, so the
  warning fired once on the first apply and then **stayed quiet forever**. Measured on a host
  still accepting every IPv6 connection with ten services listening. The count now excludes
  logwall's own jumps: a tool that adds rules and then counts rules is measuring itself.
- **`IPV6_UNPROTECTED` became a preflight finding** instead of a line scrolling past during
  `apply` — and a **BLOCKER, not a warning**. `--accept-warnings` also swallows threshold
  advice and `SINGLE_ADMIN_IP`; a gap that lets **every IPv4 restriction be walked around**
  must not be swept away by the same flag. But a blocker with a one-line way out: refusing
  installation outright is also wrong, because a host may be perfectly protected on IPv4, and
  discarding that over a gap in the other family trades a certain loss for one that can simply
  be declared. **`IPV6_BASELINE=external`** declares it — the same pattern as
  `BASELINE=external`, because guessing on the operator's behalf is exactly what this tool
  refuses to do.

  Deliberately **not** part of the `--runtime` gate: a two-minute `apply` cycle must never
  stop for a decision that is waiting on a human.
- **`status` states coverage, not existence.** `IPv6 Enabled: 1` said only that the host has
  an address. It is now one of: `no global address` · `covered` · `⚠ ENFORCED BUT UNPROTECTED`.
- **The CSF push checks `IPV6` in `csf.conf`** before sending a v6 address. CSF enforces v6
  only when that switch is on; without it the entry lands in `csf.deny` and never in
  `ip6tables` — recorded, reported as sent, enforced not at all.

**Verified:** blocking IPv6 cut ping6 and tcp 3456/80/443 from a test host while IPv4 was
entirely unaffected; v6 aggregation uses **/64**, the sensible allocation unit.

### Baseline advice is now distribution-aware

`NO_BASELINE_POLICY` is the only blocker that tells the operator to install another piece of
software, so its advice has to be usable. Previously: *"firewalld, ufw, or an iptables
ruleset"* — three options with no guidance, offered at the exact moment the tool refuses to
proceed. It now names the one that matches the distribution, with the command. Ubuntu is
handled specially: its `OS_FAMILY` is `debian`, but its convention is ufw, not nftables.

### Upgrade path & drift

- **`selftest` prints `version=` and `fingerprint=`.** A fleet is patched file by file, and a
  version alone cannot tell two hosts apart when only a library changed. The fingerprint is a
  checksum over the code that actually runs (`tests/` excluded — never executed in
  production), so identical output means identical code.
- **The upgrade path was verified on a real host:** `install.sh` over an existing installation
  detects `ALREADY_INSTALLED`, backs the config up to `.preinstall`, adds only new keys, and
  **preserves values the operator has changed**. Whitelist, blacklist, ipsets and the number
  of cron entries were unchanged — **no duplicate cron**.

### Testing

`gate_test.sh` went **24 → 50 checks**, `smoke_test.py` gained 14. The old suite did not test
firewalld, ufw, CrowdSec, native-nftables detection or the `fleet_sync` import at all — a
full pass previously meant nothing for those areas.

**And the suite itself turned out never to have been properly tested.** Run for the first time
on an installed host: 44/44 on the workstation, but **31/45** on a production server. Five
fixture leaks were found — the host config overwriting the environment, PATH hardening pushing
stubs behind `/usr/sbin`, installation artefacts that genuinely already existed, log discovery
sweeping up **production access logs** (557 real visitors entered a single run), and a real
manager beating the stub. Zero of the five were visible on the workstation, because there the
thing that leaked simply was not present.

One of them looked briefly like a Python 3.6 bug — it was not. **The Python 3.6 floor stands,
and is proven**: smoke passes fully on 3.6.8, 3.9 and 3.11.

**Verified on real hosts:** reboot persistence on **AlmaLinux 8** (1,196 blocklist entries
restored intact) and **Debian 12** · firewalld and ufw coexistence · CSF coordination with
`csf -d` pushes reaching the kernel · detection of a real SSH brute force (75,722 failed
attempts).

---

## 1.0.0-rc6 — 2026-08-13 (standalone: reboot persistence proven)

CSF was disabled on the test host, a replacement baseline installed, logwall run with its own
chains and ipsets, and then the host was **genuinely rebooted**. Four defects surfaced, all
of them silent-failure class.

- **Persistence turned out not to persist.** logwall wrote `/etc/sysconfig/iptables` and
  `/etc/sysconfig/ipset` but **never enabled the units that restore them** — and on RHEL 8/9
  the `iptables-services` and `ipset-service` packages are not installed by default, because
  firewalld is the supported path. The files were written where nothing reads them. After the
  reboot: policy `ACCEPT`, every rule gone, the server open, and the tool reporting success.
  `fw_save_rules` now enables the units; if a unit does not exist it refuses quietly and names
  the command that installs the package. Added the preflight check **`NO_BOOT_PERSISTENCE`**.
- **A disabled CSF was still detected as the active backend.** `csf -x` leaves the binary and
  the configuration behind, and its unit stays `active` because it is a oneshot. Blocks would
  be sent to `csf -d` on a host enforcing nothing — recorded, never applied. The
  `/etc/csf/csf.disable` marker is now what decides, in detection, in `apply` and in preflight.
- **The ipset emitter emitted v6 sets that were never created.** The v6 sets are created only
  when `HAS_IPV6=1`, but the emitter always emitted all four; a `swap` against a set that does
  not exist **aborts the entire restore**, including the healthy v4 blocklist. The emitter now
  follows the same signal as the Bash layer, and reports `IPV6_SKIPPED` when v6 entries go
  unloaded.
- **The deadman is no longer armed in CSF mode.** There logwall changes no rule at all, so a
  full rollback would only undo CSF's work since the snapshot — arming it would create the
  very risk it exists to prevent.

**Verified after a real reboot:** policy `DROP` restored · `LOGWALL_*` chains back in positions
1-3 · ipsets back with their contents · `iptables.service` and `ipset.service` enabled and
active · `selftest` passing · SSH still reachable.

The safety machinery also proved itself in the field: when an ipset restore failed, `apply`
detected it, performed a verified rollback, exited with code 10, and **damaged nothing**. The
deadman switch was armed through `systemd-run` and then cancelled with
`logwall firewall confirm` — a path that until then had only been theory.

## 1.0.0-rc5 — 2026-08-13 (findings from a real installation on a CSF host)

Installed for real on AlmaLinux 9 + DirectAdmin + CSF, coordination mode, `ENFORCE=0`.
Four defects surfaced, not one of which could have been found from a workstation.

- **Cron failed silently on EVERY cycle.** cron runs with `PATH=/usr/bin:/bin`, while `ipset`,
  `iptables` and `ip` live in `/sbin` and `/usr/sbin`. The runtime gate reported
  `IPSET_MISSING` and aborted each cycle — while the installation looked healthy and a manual
  `apply` from a login shell always succeeded. The proof: two hours of running, ~60 cycles,
  **zero snapshots**. `logwall` and `preflight.sh` now enforce their own PATH, the crontab
  writes one too, and **installation verification now runs the CLI under `env -i`** — checking
  only with the installer's PATH is exactly what hid this.
- **The `/usr/local/bin/logwall` symlink was not resolved.** `BASH_SOURCE` holds the symlink,
  so `dirname` looked for `lib/` inside `/usr/local/bin`. Cron was safe because it uses an
  absolute path; **every interactive command was broken**. The symlink chain is now walked
  manually (`readlink -f` does not exist on busybox), and the installer verifies through the
  symlink as well.
- **There was no supported path for installing on a CSF host.** Environment variables got past
  the gate, but the config written still said `BACKEND=auto`, so every following cron cycle was
  blocked by the runtime gate. Added **`install.sh --backend <name>`**, which pins that choice
  into `/etc/logwall.conf`, plus its documentation in the README.
- **`grep -c` printed two lines again** — this time in `cmd_apply`, splitting the
  "0 new address(es)" message across two lines. The correct idiom remains
  `... | grep -c . || true`.
- **The runtime gate printed an installation report in the middle of `apply`**, including the
  contextually wrong advice to "run ./install.sh --accept-warnings". Its output is now captured
  and shown only when there is a BLOCKER.

Verified after the fixes: cron produced snapshots on cron timestamps, `iptables` stayed at 142
rules (the baseline), zero `LOGWALL` chains or ipsets, CSF's own `chain_DENY` stayed at 200
entries, and **zero logwall lines in `csf.deny`** — exactly as `ENFORCE=0` requires.

## 1.0.0-rc4 — 2026-08-13 (client profiling: browser vs script)

Until now the parser **discarded** User-Agent and Referer, and no code read `BOT_UA_FILE` from
the config. So a real user and a scraper looked identical to a request counter: 10 pages in a
browser ≈ 460 requests, a scraper pulling 500 articles ≈ 500 requests.

- **The primary signal is the asset ratio, not the User-Agent.** A browser fetches CSS, JS,
  fonts and images by itself once it has the page; a script fetches only what it came for. The
  UA is theatre — the scrapers worth worrying about send a Chrome UA. The asset ratio cannot be
  faked cheaply: a scraper that fetches assets to blend in **burns the bandwidth it came to
  steal**.
- **Calibrated against the site's own baseline.** If assets are served from a CDN or a separate
  domain, the origin log contains almost no asset requests — and **every visitor would look
  like a script**. So the signal disables itself when the site's asset ratio falls below
  `SITE_ASSET_RATIO_MIN`, and reports that as `PROFILING_OFF`.
- **A tier modifier only, never a trigger.** Script-like clients skip the TEMP round;
  browser-like clients must exceed the threshold × `BROWSER_TOLERANCE_FACTOR` before becoming
  candidates. This is what makes a low `THRESHOLD_HITS` safe.
- The UA is used as secondary confirmation only: self-declaring tools (`curl`,
  `python-requests`, `nuclei`, an empty UA) are recorded, but are never enough to block.
- The evidence is carried in the block reason: `client: script, assets 0%`.
- An honest limit that logs cannot close: headless Chrome and Puppeteer fetch assets and send a
  genuine UA → indistinguishable. Only volume and subnet aggregation catch those. TLS/HTTP2
  fingerprinting is WAF territory, not a log parser's.
- Tests: 124 (detection) + 24 (gate) + 1 (line endings), including a case of two clients with
  **identical volume** producing opposite verdicts.

## 1.0.0-rc3 — 2026-08-13 (offender memory proven and sharpened)

The question that prompted it: when a TEMP block expires and that address misbehaves again,
how does logwall know it was ever blocked?

- **The memory did exist, and is now proven end to end.**
  `data/state/offender_history.json` is separate from the blacklist, so it **survives the
  removal of the TEMP entry**. The cycle: first offence → TEMP `strike=1` → expiry → entry
  released but history kept → misbehaves again → `strike=2` → **PERMANENT**.
- **`ESCALATE_IMMEDIATE_FACTOR` (default 10)** — the TEMP tier exists for **doubt**: shared
  addresses (CGNAT, an office, a campus) can cross a volume threshold once without meaning
  harm. Ten times over the threshold is not doubt, so it skips the grace round and goes
  permanent on first sighting. The 500,000-hits-per-block incident was 250× the threshold →
  permanent immediately, not TEMP.
- **`OFFENDER_MEMORY_DAYS` (default 90)** — previously hardcoded to 90 days. Not forever,
  because addresses do change hands, and punishing the new owner for the old one's sins is
  wrong.
- Made explicit in the config: **intent-based detections** (login brute force, recon, xmlrpc)
  **are always permanent on first sighting** and never touch this ladder. Only volume
  detections are tiered.
- `BLOCK_ESCALATION=0` reproduces the old behaviour: permanent immediately, always.
- Tests: 105 (detection) + 24 (gate) + 1 (line endings).

## 1.0.0-rc2 — 2026-08-13 (subnet aggregation)

Prompted by a real incident: ~1 million requests in half a day, spread across hundreds of
addresses that all turned out to sit in **two /24 blocks owned by one company**. The bandwidth
was gone.

Counting per address only made that attack look like hundreds of weak attackers rather than
two strong ones. It failed twice as a result:

1. Each member crept toward the threshold on its own — the block landed at ~15 minutes instead
   of ~3.
2. Hundreds of candidates appeared at once → **circuit breaker trips → nothing blocked**, and
   it kept tripping on every following cycle while the bandwidth kept burning.

- **`TrafficWindow.subnet_rollup()`** — sums every per-address counter into its parent network
  (/24 for IPv4, /64 for IPv6), plus `members` = the number of distinct active addresses. A
  string-based fast path for the common case; `ip_network()` over 200,000 entries would
  dominate the run time.
- **`SUBNET_MIN_IPS`** (default 5) — evidence of coordination must exist before a **range** is
  proposed. Without it, one heavy visitor on shared hosting drags 255 neighbours down.
- **`IPGuard.refusal_reason_network()`** — stricter rules than for a single address. A range is
  refused if it **overlaps** anything protected: **one** whitelisted IP inside a /24 makes the
  whole range unblockable, because enforcing it would lock the admin out of their own server.
  Includes `RANGE_TOO_WIDE` — a /24 mistyped as /8 would block 16 million addresses.
- **Members are deduplicated against the parent range** — one entry, not 501.
- Verified against a simulation of the original incident: **1,000,000 hits / 500 addresses /
  2 blocks → 2 candidates**, the breaker did not trip, evaluation took 0.01 seconds.

Scope note: real per-ASN blocking needs an external database and stays on the roadmap. /24
aggregation catches the majority of cases with no dependencies at all — for this incident the
result was identical.

## 1.0.0-rc1 — 2026-08-13 (scope locked for release)

Renumbered to 1.0.0-rc1: the scope is now **fixed**, not growing.

- **Service login-failure detection** — sshd, Dovecot (IMAP/POP3), Exim (SMTP AUTH),
  vsftpd/pure-ftpd. Closes the largest detection gap and finally delivers the §12 promise that
  had lived only in the design document. `LOGIN_FAIL_BLOCK` is at last actually used.
  - **Precision over coverage.** Validated against a production maillog: 40 lines containing
    both "auth" and "fail" turned out to be `(no auth attempts)` and
    `Unsupported authentication mechanism` — a dropped connection and an unsupported SASL
    mechanism, not rejected credentials. Matching them would mean blocking clients with poor
    connectivity. All three are now negative regression tests.
  - File reading was unified (`_read_new_lines`) so the web and auth parsers share one
    implementation of cursors, byte budgets and rotation handling.
- **`NO_BASELINE_POLICY` — a new BLOCKER.** logwall is a denylist; it never closes a port and
  never sets a default policy. Installing it on a host with `INPUT policy ACCEPT` and no other
  firewall agent produces the most dangerous output available: an admin who feels protected
  while every port stays open to anyone who has not yet tripped a threshold. The way out is
  explicit: `BASELINE=external`.
- **The README as the definition of scope** — target servers, positioning and limits stated
  plainly, including the **What this is NOT** section.
- `LOGIN_RATE_PER_USER` marked as not implemented rather than left looking active.
- Tests: 85 (detection) + 24-25 (gate) + 1 (line endings).

### 1.7.0 — 2026-08-12 (CSF coordination, backend detection, cross-platform hardening)

Validated on a real DirectAdmin + CSF host (AlmaLinux 9, Python 3.9, behind NAT).

- **nftables detection tightened.** It used to be enough that "the `nft` binary exists and
  `nft list ruleset` runs" — but on RHEL 9, Debian 12 and Ubuntu 22+, `iptables` **is**
  nftables underneath and automatically creates `table ip filter/nat/mangle/raw`. logwall would
  therefore write persistence to `/etc/nftables.conf`, a file nothing restores while
  `nftables.service` is disabled → **rules gone after a reboot while logwall reported success.**
  It now demands positive evidence: the service active or enabled, a populated
  `/etc/nftables.conf`, or tables outside the iptables compatibility set.
- **CSF coordination mode (`BACKEND=csf`).** Resolves the contradiction between §8.B
  (coordination) and preflight (CSF = absolute BLOCKER). Now: without `BACKEND=csf`, CSF
  remains a BLOCKER; with it, logwall **installs no chains and no sets at all** and every block
  goes through `csf -d`. Only this run's delta is sent (`--emit-csf`) — resending the whole
  list every cycle would mean thousands of Perl processes.
- **CSF's own sets** (`chain_DENY`, `chain_ALLOW`, `chain_6_*`) were added to
  `RESERVED_FOREIGN_SETS`, and excluded from `FOREIGN_IPSET` when coordination mode is chosen.
- **The log path list was unified.** preflight used to keep its own copy of the globs and
  reported `NO_ACCESS_LOG` on a DirectAdmin host whose logs the parser read perfectly well.
  preflight now asks the parser instead of maintaining a second list.
- **`tests/lineending_test.sh`** — CRLF makes Linux bash refuse to run a script at all,
  `preflight.sh` included.
- **Gate fixtures neutralised** against the active SSH session and `systemctl` call patterns.
- A regression the suite caught on itself: observe mode briefly stopped populating the sets,
  even though inspecting a populated set is exactly how an operator decides that enforcement is
  safe to enable.
- Tests: 75 (detection) + 24 (gate) + 1 (line endings).

### 1.6.0 — 2026-08-12 (format-resilient, streaming parser)

Prompted by a read-only verification against panel CLIs and real logs. Three parser
assumptions proved wrong, and two of them **failed silently**:

- **Field-position parsing replaced with anchored regex.** Standard combined has two
  placeholders; some panels write one. The positional parser read `HTTP/1.1"` as the URI and
  `"referer"` as the byte count — the line still counted as a success, so `PARSE_FAIL` never
  fired, while wp-login/xmlrpc/recon detection was completely blind and bandwidth was always
  zero. The new regex is anchored on the quoted request with an optional second placeholder.
- **The panel CLI contract was corrected.** The JSON root is a bare array, not
  `{"data": [...]}`; the owning account is at `owner.username`/`owner.home_dir`, not
  `user.login`; and **the owner differs between sites on the same host** — inferring one
  account from the first site is wrong for all the rest. Before this, panel auto-discovery was
  never actually used: the exception was caught silently and the code fell back to globbing.
- **Backend logs are flagged `BACKEND_LOG_ONLY`** when they are all that is available — the
  addresses in them are those of a reverse proxy.
- **The parser became a generator.** Raw lines are never stored; they are used only momentarily
  to recover the real IP when the peer is a CDN edge. Peak memory on a 43.7 MB / 300,000-line
  log: **0.6 MB** (previously hundreds of MB on a large backlog).
- **`tests/fixtures/`** — sample logs for nginx, Apache (`-` bytes + auth-user), LiteSpeed,
  Caddy JSON (including `Cf-Connecting-Ip`), the one-placeholder backend variant, a log behind
  a CDN, and an unknown format. The web server axis is now fully covered offline.
- Tests: 71 (detection) + 20 (gate).

### 1.5.0 — 2026-08-12 (admin access layers & installation transparency)

- **DDNS finally implemented** (`lib/py/ddns_resolver.py`). `WHITELIST_DYNAMIC_HOSTS` was in
  the config and promised in design §15.2, but **not one line of code read it** — offering it
  as the answer to a dynamic IP meant promising something that did not work. It is now resolved
  every cycle into the kernel whitelist set and into `IPGuard`, with a fail-safe: DNS down →
  use the last cache, flagged `DDNS_STALE`.
- **`SINGLE_ADMIN_IP`** — a warning when only one administrative access path exists.
- **Loopback no longer counts as an access path.** The whitelist template contains `127.0.0.1`
  and `::1`; a naive count meant the warning above could never appear.
- **Interactive `[y/N]` confirmation in `install.sh`**, TTY-aware: no terminal → refuse, do not
  ask. The prompt is deliberately **not** in `preflight.sh`, because preflight is also called
  from cron and from `doctor --json`.
- **An installation transcript** to `/var/log/logwall/install.log`, buffered first so that a
  refusal still leaves no artefacts behind.
- **The closing summary** shows the whitelist, DDNS, SSH port, enforcement status and log
  locations — plus a pre-`ENFORCE=1` checklist marked **not yet verified** rather than claimed
  as status (a script cannot know your console or VNC works).
- **The `grep -c` bug fixed in 4 places.** `grep -c` prints `0` and **then** exits 1, so
  `|| echo 0` produced two lines; the value `0\n0` triggered an arithmetic error that aborted
  the entire admin access path check without a trace. The correct idiom:
  `... | grep -c . || true`.
- Tests: 45 (detection + DDNS) and 20 (gate).

### 1.4.0 — 2026-08-12 (scope boundary sharpened)

- **`import-legacy` and `lib/legacy_migrate.sh` removed.** Automatically migrating another
  tool's blocklist is not a decision this tool may take: every host has its own history,
  dependencies and risk tolerance. Instead `preflight.sh` blocks the installation and presents
  concrete findings (the set name, the entry count, the exact cron line) plus the command to
  secure the data first. The admin decides.
- Server-specific findings were removed from these notes; only the generally applicable
  principles remain.

### 1.3.0 — 2026-08-12 (pre-installation gate & transactional install)

- **New `preflight.sh`** — 12 BLOCKER classes, 12 WARNINGs, each with an ID and a fix command.
  An exit-code contract of 0/1/2/3. `--runtime` and `--json` modes.
- **Another blocker means a full stop.** Another blocker's cron, a foreign ipset used by a live
  DROP rule, an active fail2ban/CSF/lfd/firewalld → installation refused, with no bypass.
- **Kernel capability probing** — creates and then removes a test set and chain to confirm the
  kernel or container really allows it, rather than inferring from the presence of a binary.
- **`install.sh` became transactional** — a journal of 6 action types, automatic rollback on
  failure at any point, backup and restore of `/etc/logwall.conf`.
- **A VERIFY stage** — Python modules imported from the installed location, the CLI executed,
  permissions checked, cron verified as genuinely registered. Failure → installation aborted.
- **A runtime gate before every `apply`** — a new blocker means the cycle does not run.
- **`logwall doctor`** — the same gate, at any time.
- **ERR trap fix** — `set +e` does not disable `trap ERR`; a clean refusal briefly appeared as
  a crash. Replaced with the `cmd || RC=$?` form.
- **New `tests/gate_test.sh`** — 14 integration tests with stubbed commands, proving the gate
  refuses what it must and creates no artefacts at all.

### 1.2.0 — 2026-08-12 (collision avoidance & migration path)

The general lesson: generic set names are used by almost every first-generation blocker script,
and `apply` would `swap` against a production set — on a `policy DROP` host that means the
whitelist is overwritten and SSH dies.

- **New `lib/naming.sh`** — one source of truth for every object name. Defaults are now
  prefixed (`LOGWALL_BL4/BL6/WL4/WL6`) and can be overridden through `/etc/logwall.conf`.
- **`naming_guard`** — refuses to proceed (exit 2) if configured with a name reserved for
  another tool, or a name longer than 27 characters. Enforced in Bash **and** Python.
- **Set type verification** — an existing set carrying an logwall name is checked for `hash:net`
  and its family; a mismatch means refusal, not silent adoption.
- **`detect_foreign_blockers`** — detects iptables rules using foreign sets and other blockers'
  cron jobs; reported in `apply`, `status`, `selftest` and `install.sh`. Reported, **never**
  resolved unilaterally.
- **`check_ipv6_exposure`** — flags `IPV6_UNPROTECTED` when IPv4 is DROP but IPv6 is ACCEPT.
- **Rollback tightened** — ipset restore is filtered to logwall's own objects; another tool's
  sets are never flushed. A full `iptables-restore` is still used (that is what makes rollback
  useful during a lockout) but now warns about other agents.
- **`uninstall.sh` tightened** — it used to destroy `BLACKLIST_SET`/`WHITELIST_SET`, which meant
  removing logwall would disarm another blocker on the same host. Now only its own objects, and
  the final verification uses the same list.
- **Python 3.6 compatibility** — `add_subparsers(required=True)` (3.7+) replaced with manual
  validation. The whole codebase was scanned for other 3.7+ APIs: clean.
- Tests grew to **38**, including 5 dedicated to name protection.

### 1.1.0 — 2026-08-12 (security audit fixes)

**High-severity issues closed:**
- Duplicate `INPUT` jumps every cycle (`-C` did not match because of `-m comment`) → the specs
  were made identical
- Snapshots accumulating 720/day because pruning was never reached → moved to `trap EXIT`
- `/etc/nftables.conf` and `/etc/sysconfig/ipset` overwritten every 2 minutes unconditionally →
  restricted per backend + backup
- The effective threshold became per-2-minutes → a persistent sliding window (`window.json`)
- The whitelist was not enforced (string match, empty set, empty chain) → CIDR + set + ACCEPT
  rule
- No exclusion of local/gateway/own-server addresses → `ip_guard.py`
- No DROP or ACCEPT rules at all → real enforcement, gated by `ENFORCE`
- `restore_snapshot` reported success even when it failed → verification + exit code

**Medium:**
- `/etc/logwall.conf` was never read by Python → `config_loader.py`
- `bypass_rules.txt` (Googlebot) was never used → now active
- The CDN real IP was never extracted → XFF recovery + audit-only fail-safe
- IPv6 was truncated at the `:` character → normalised via `ipaddress`
- firewalld/ufw/CSF backends were overridden with raw iptables → now respected
- `xargs` used for parsing blacklist lines → removed; Python emits `ipset restore` + an atomic
  swap
- `grep -v logwall` deleted the admin's cron → a `# logwall-managed` marker
- Cron called a subcommand that did not exist → fixed
- Whitelist bootstrap failed silently → 4 sources + abort if empty
- File permissions were not enforced → 0750/0640/0600 + refuse-to-run if world-writable
- The lockfile was force-removed (opening a race) → now only warned about

**Added:** `ENFORCE` · the deadman switch · connectivity tests before and after · the
TEMP→PERMANENT escalation ladder · `firewall confirm` · `selftest --repair` · standard exit
codes · `--dry-run` · verified uninstall · `tests/smoke_test.py`

**Removed:** `lib/py/real_ip.py` — entirely superseded by `ip_guard.py` + `log_parser.py`;
keeping it would mean two sources of truth for the same decision.

### 1.0.0 — initial version
The first implementation. See the audit in the conversation history; in short: no enforcement
rules, thresholds off by orders of magnitude, a whitelist that did not work, and several paths
that could damage the server's firewall configuration.

---
*This document is alive: update it whenever testing on a server produces a finding.*
