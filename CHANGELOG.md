# Changelog

Every significant change to logwall. Versions follow [SemVer](https://semver.org/).

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
