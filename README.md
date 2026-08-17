# logwall

**An HTTP abuse blocker that is safe to install.**

logwall reads your web and authentication logs, works out which addresses are
actually abusing the server, and blocks them — without ever locking you out, and
without ever blocking your CDN.

It is a **layer**, not a firewall replacement. It sits on top of whatever you
already run: firewalld, ufw, a hand-written iptables ruleset, fail2ban, or CSF.

```
$ logwall firewall audit
185.199.108.80   PERMANENT   AuthBruteForce | failed service logins: 14x
45.148.10.92     PERMANENT   ReconScanner | SensitiveFile | Hits: 6x
91.240.118.22    TEMP        HighBandwidth | BW: 812.4MB | Hits: 2210x
[GUARD]   CDN_GUARD_HIT: 3          <- Cloudflare edges refused, as designed
[GUARD]   WHITELIST: 1
```

---

## Why this exists

Four things go wrong with the usual approaches, over and over:

**Your blocker blocks Cloudflare and the site goes down.** Behind a CDN every
request appears to come from a handful of edge addresses. A tool that counts
requests per source IP will eventually decide those edges are attacking you.
logwall recovers the real client address from `CF-Connecting-IP` / `X-Forwarded-For`,
and treats CDN ranges as a **hard guard**: they cannot enter the blocklist by any
path, at any threshold, ever.

**Your blocker locks you out at 3am.** A wrong rule on a `policy DROP` host means
a support ticket and an hour of downtime. logwall refuses to install on a host that
is not ready, verifies your session survived the change, and rolls itself back if
you do not confirm within five minutes.

**A visitor and a scraper look identical to a request counter.** Ten page views
in a browser is ~460 requests; a scraper pulling 500 articles is ~500. Any tool
counting requests per IP has to choose between missing the scraper and blocking
the customer. logwall separates them by what the client *fetches*: a browser pulls
the page's stylesheets, scripts, fonts and images by itself, a script does not.

**Your panel has no brute-force protection at the HTTP layer.** FastPanel,
CyberPanel, aaPanel, HestiaCP and a plain nginx box give you nothing that watches
request volume, bandwidth, or scanning patterns per address. fail2ban can, but
only after you write the jails and get the log paths right yourself.

---

## What it does

| | |
|---|---|
| **Detects** | Failed logins (SSH · IMAP/POP3 · SMTP AUTH · FTP · panel 401/403) · WordPress brute force · XML-RPC abuse · sensitive-file scanning (`.env`, `.git`, `.sql`, phpMyAdmin) · request floods · bandwidth abuse |
| **Understands** | Nginx & Apache combined, LiteSpeed, Caddy JSON, and the one-placeholder variant panels emit. Log paths discovered automatically for 7 control panels |
| **Measures** | Per-interval buckets in persistent state. Volume is judged one interval at a time and must repeat before it blocks; intent is summed over a short sliding window, because attackers deliberately trickle below any single-interval line |
| **Profiles** | Tells a real visitor from a script by whether the client fetches the stylesheets, scripts, fonts and images a browser pulls on its own — a signal a scraper cannot fake cheaply, because faking it means downloading the bandwidth it came to steal |
| **Aggregates** | Counters roll up per /24 and per /64. A flood spread over hundreds of addresses inside one or two networks is caught as **one coordinated source**, minutes earlier, as a handful of range entries instead of hundreds of host entries |
| **Protects** | Your whitelist (CIDR-aware) · dynamic DDNS hostnames · CDN edges · the server's own addresses · its default gateway · RFC1918 |
| **Reaches containers** | Docker publishes ports through `nat/PREROUTING` and `FORWARD` — those packets **never traverse `INPUT`**, so they bypass firewalld and ufw entirely. logwall hooks `DOCKER-USER`, the one chain Docker leaves to you. Measured: a published port answering `HTTP 200` from the internet while firewalld listed only SSH; once the source was blocked, `HTTP 000` |
| **Escalates** | Volume abuse gets a temporary block first; the offender is remembered in separate state, so a repeat offence after it expires becomes **permanent**. Excess far beyond the threshold skips the grace round. Unambiguous intent (brute force, recon) is permanent immediately. `BLOCK_ESCALATION=0` for zero tolerance |

## What makes it safe

This is the part that took the most work, and it is the reason to choose it.

- **Preflight gate** — refuses to install on a host that is not ready. Every
  finding carries an ID and the exact command that fixes it. Exit codes are a
  contract: `0` ready, `1` warnings, `2` blocked.
- **Transactional install** — every action is journalled; a failure at any stage
  rolls the host back to exactly how it was.
- **Deadman switch** — after `apply`, an automatic rollback is armed. If you
  cannot run `logwall firewall confirm`, the server restores itself.
- **Catch-up guard** — when a run reads hours of log instead of one interval
  (a fresh install, a cursor reset, a stalled cron), every volume count in it is
  inflated, so the volume rules stand down for that run and the intent rules
  carry on. The run says so in the report.
- **Observe-only by default** — `ENFORCE=0` on a fresh install. It watches and
  builds the list; it drops nothing until you have read the result and said so.
- **Coexists** — detects other agents and defers to them. With `BACKEND=csf` it
  installs no chains at all and routes blocks through `csf -d`.
- **`logwall firewall panic`** — one short command detaches every logwall hook and
  leaves every other tool's rules intact.

---

## A worked example

A real incident on a Singapore VPS, where egress is metered and the add-on
bandwidth is expensive: **one million requests in half a day.** Not from one
address — from hundreds. Checked by hand afterwards, they all belonged to two
/24 networks owned by the same company.

That shape defeats a per-address blocker twice over. Each member creeps toward
the threshold on its own, so the block lands ten-odd minutes late; and when they
finally cross it they cross *together*, so a tool with a sane cap on new blocks
per run sees hundreds of candidates at once and refuses to block anything at all.

logwall rolls the counters up per network before judging anything:

```
$ logwall firewall audit
distinct addresses in window : 500
total requests               : 1,000,000
candidates produced          : 2

185.199.7.0/24    PERMANENT  SubnetFlood | 250 hosts | Hits: 500000x | assets 0%
185.199.8.0/24    PERMANENT  SubnetFlood | 250 hosts | Hits: 500000x | assets 0%
```

Five hundred candidates become two, and both are blocked. `assets 0%` is the
client profile: not one of those 500
addresses ever fetched a stylesheet, a script or an image — no browser behaves
that way. Excess this far past the threshold is not ambiguous either, so both
ranges skip the temporary tier and land permanently on first sighting.

Blocking a /24 is 256 addresses at once, so it is fenced accordingly. A range is
proposed only when at least `SUBNET_MIN_IPS` distinct hosts inside it are active,
and it is refused outright if it overlaps your whitelist, a CDN range, the
server's own addresses, its gateway, or if it is wider than `/24`. **One
whitelisted address anywhere inside the range makes the whole range unblockable** —
enforcing it would lock you out of your own server.

---

## Scope

Read this section before installing. It is deliberately blunt.

### Supported

| | |
|---|---|
| **Distro** | AlmaLinux / Rocky / RHEL 8-9 · Debian 11-12 · Ubuntu 20.04-24.04 |
| **Web server** | Nginx · Apache · LiteSpeed / OpenLiteSpeed · Caddy |
| **Panel** | FastPanel · DirectAdmin · cPanel · Plesk · CyberPanel · aaPanel · HestiaCP · no panel at all |
| **Enforces through** | Its own `LOGWALL_*` chains + ipset (standalone), **or** CSF's blocklist via `csf -d` (coordination, `BACKEND=csf`) |
| **Coexists with** | **firewalld** (`FirewallBackend=nftables`, the default on RHEL 8+) and **ufw** — they own the baseline, logwall layers on top. Verified on both: reload, complete-reload and a full service restart leave its chains untouched. The separation is what makes this safe — firewalld's nftables backend writes to `table inet firewalld`, logwall to `table ip filter`. A firewalld set to `FirewallBackend=iptables` writes into the *same* table logwall uses, so its reload can drop logwall's jumps; preflight detects this and warns. That configuration is **not yet measured** |
| **Refuses to share with** | fail2ban · CrowdSec · a CSF you have not chosen to coordinate with — all of them block addresses dynamically, and two agents editing one ruleset is the outage class this gate exists to prevent |
| **Stack** | IPv4 **and IPv6, equally** — one parser, one window, one set of thresholds, one blacklist file; the two only diverge at the end where the kernel demands separate sets, and ranges roll up per /24 and per /64 respectively · behind a CDN · behind NAT |
| **Requires** | root · Python 3.6+ (stdlib only, no pip) · iptables + ipset · a cron daemon · a way to restore rules at boot (`iptables-services` on RHEL, `iptables-persistent` on Debian) — preflight checks for it and names the package if it is missing |

### Not supported

- **Windows / IIS**, **FreeBSD / pf** — different firewall architecture entirely.
- **Kernels without netfilter** — some OpenVZ hosts, unprivileged containers
  without `NET_ADMIN`. Preflight probes for this and refuses rather than guessing.
- **Log formats it cannot parse.** It says `PARSE_FAIL` and blocks nothing,
  rather than deciding from unreadable data that there are no attacks.
- **Alpine (OpenRC) and Arch** — *for now*. The code paths are complete and specific
  (`apk`, `rc-update`/`rc-service`, the non-systemd deadman fallback), and preflight will
  run there. But neither has been installed on a real host, so neither is claimed. Support
  gets listed above when it has been measured, not before.

### What this is NOT

**logwall does not close ports, and it does not set your default policy.**

It is a denylist: traffic is accepted until an address proves itself malicious.
That only works as a layer on top of a default-deny baseline. On a host where
everything is open, logwall still blocks the abusers it observes — that part is
real — but every port stays reachable by everyone who has not tripped a threshold
yet, including anything exploitable on first contact. A denylist cannot close a
door; it can only remember who to turn away.

Preflight therefore **refuses to install** when the INPUT policy is `ACCEPT` and
no firewall agent is running. If your baseline lives upstream in a cloud security
group, say so explicitly:

```bash
echo 'BASELINE=external' >> /etc/logwall.conf
```

### It is blind to load that spreads out

Thresholds catch concentrated abuse. A crawler that spreads politely across many
networks never trips one, at any setting. Measured on a live site: Bingbot,
**133 distinct addresses**, at most 44 requests each, and every /24 well under the
subnet threshold — 821 requests and 26 MB a day that logwall will never flag,
because no single source did anything unusual.

That is the honest boundary of a threshold-based denylist. For well-behaved
crawlers the right lever is `robots.txt` or the search engine's own crawl-rate
control, not a firewall.

### Your whitelist is not an access grant

This trips up operators coming from CSF, where `csf.allow` writes an `ACCEPT`
rule — lose that address and you lose the way in.

logwall's whitelist means only **"never block this"**. It grants nothing. If your
address changes, you keep whatever access the baseline already gave you; you lose
immunity from logwall's own blocking, not entry.

The exception worth knowing: if your baseline grants SSH **per source address**
rather than by port, then a changing address does lock you out — but that is a
property of the baseline, and it was true before logwall existed. Preflight tells
you which of the two you have.

### Installing changes nothing until you say so

`ENFORCE=0` is the shipping default. logwall installs, detects, records candidates
and populates its sets while **dropping no packet at all**. The equivalent of
CSF's `TESTING` mode, except it does not expire behind your back.

So installing on a fresh host over a dynamic-IP connection is safe: nothing is
enforced until you set `ENFORCE=1` yourself, and the first `apply` after that arms
a deadman that rolls the change back unless you confirm from a second session.

Also **not** in scope, and not planned for 1.0: port management, Layer-4 rate
limiting, geo-blocking, WAF / application-layer inspection, malware scanning,
file integrity monitoring.

---

## Alternatives

This is a crowded space and logwall is not the answer to every version of the
problem. Pick honestly.

| Tool | Choose it when |
|---|---|
| **[CrowdSec](https://crowdsec.net)** | You want community threat intelligence, a dashboard, and a bouncer ecosystem. It is the most capable tool here and it is actively funded — if you can install it, seriously consider it first. |
| **[fail2ban](https://github.com/fail2ban/fail2ban)** | You need something in every distro repo, you are happy writing jails, and your traffic is not behind a CDN. |
| **CSF / LFD** | You run cPanel or DirectAdmin and want port policy plus login-failure banning from one package. |
| **Imunify360 / BitNinja** (paid) | You run shared hosting and want WAF, malware scanning and reputation in a supported product with someone to call. |
| **Cloudflare** (free tier upward) | Your problem is at the edge and you can put a CDN in front. Rate limiting there beats anything log-based, because it stops traffic before it costs you bandwidth. |

### Where logwall is actually the better fit

- **Zero dependencies.** Bash plus the Python standard library. No Go binary, no
  agent, no `pip`, nothing to add to a locked-down panel server. Copy the
  directory, run `./preflight.sh`.
- **Your logs are behind a control panel.** FastPanel, DirectAdmin, cPanel,
  Plesk, CyberPanel, aaPanel, HestiaCP layouts are known already. No jail files,
  no acquisition config.
- **Bandwidth is what costs you.** Per-address byte accounting over a real
  24-hour window is a first-class detection here, not something to be expressed
  as a regex.
- **You are behind a CDN.** Recovering the real client address and treating CDN
  ranges as unblockable is built into the core, not a plugin — because the
  failure it prevents takes the whole site down.
- **You run containers.** A published Docker port is DNAT'd before the host
  filter, so firewalld and ufw never see it — `firewall-cmd --list-ports` can
  look clean while a container answers the internet. logwall hooks `DOCKER-USER`,
  which is the only place that traffic can be intercepted.
- **You have been locked out before.** The gate, the transactional install, the
  deadman switch and `panic` exist because that failure is common and expensive.

### Where it is genuinely weaker

- **No shared threat intelligence.** CrowdSec's network effect is real and logwall
  has no equivalent. Your blocklist only knows what your own logs saw.
- **No dashboard, no packages, no signed releases.** Terminal and config files.
- **Fewer detection scenarios** than CrowdSec's hub, and no marketplace.
- **It closes no ports and sets no default policy.** See *What this is NOT*.
- Young, and maintained by one person.

---

## Install

```bash
git clone https://github.com/dnurvianto/logwall.git
cd logwall

# 1. Nothing is written until this passes.
sudo ./preflight.sh

# 2. Install. Enforcement stays OFF.
sudo ./install.sh

# 3. See what it would block. Changes nothing.
sudo logwall firewall audit

# 4. When the candidate list looks right:
sudo sed -i 's/^ENFORCE=0/ENFORCE=1/' /etc/logwall.conf
sudo logwall firewall apply       # arms a deadman rollback
sudo logwall firewall confirm     # from a second terminal, within 5 minutes
```

Keep console/VNC access open the first time. That advice applies to every
firewall tool; logwall is simply the one that says it out loud.

### If the host has no firewall at all

Preflight will refuse, because a denylist on an open host protects less than it
appears to. Two ways forward — both explicit, neither decided for you:

```bash
# Let logwall build a minimal baseline. It derives the port list from an existing
# manager's config if there is one, from what is actually listening, and from the
# SSH port; shows you the list; then arms a deadman in case it got it wrong.
sudo logwall bootstrap-baseline

# Or, if the baseline genuinely lives upstream (cloud security group, edge firewall):
echo 'BASELINE=external' >> /etc/logwall.conf
```

`bootstrap-baseline` refuses to touch a host that already has a policy or a
manager. It exists for empty hosts, not to overrule your firewall.

Missing `iptables` or `ipset`? `./install.sh --install-deps` prints exactly what
it would install and asks first — package state is the one thing the installer's
rollback cannot undo, so it is never silent.

### If the host already runs CSF

An active CSF is a blocker by default — two agents writing the same ruleset is
not a state to enter by accident. Opt into coordination explicitly:

```bash
sudo ./preflight.sh          # BLOCKED, and the fix line tells you this
sudo ./install.sh --backend csf --accept-warnings
```

In that mode logwall installs **no chains and no sets of its own** and routes
every block through `csf -d`. CSF keeps owning the ruleset and its own
persistence; logwall only feeds it the addresses it detects.

### Tune before enforcing

`THRESHOLD_HITS_PER_INTERVAL` ships at 60 requests inside one two-minute
interval, and an address has to exceed that in `STRIKES_REQUIRED` separate
intervals before anything is blocked.

Those numbers are calibrated, not guessed: on a real site (911,795 requests,
1,703 addresses) the median peak-per-interval was 2 and p90 was 6, while the
sustained crawlers sat at 474. The gap between them is wide, which is why a
single default fits most sites. The strike requirement is what makes it safe —
one modern page view is 30-80 requests, so somebody opening three pages briefly
looks exactly like an attacker, and on that site the largest bursts (134, 88,
67) all belonged to ordinary people who were silent in the next interval.

Run `logwall firewall audit` for a few cycles before enabling enforcement and
read what it proposes. Raise the threshold if your pages are unusually heavy;
raise `STRIKES_REQUIRED` if you would rather be slower and surer.

---

## Commands

```
logwall doctor                    Environment gate; the same one install.sh must pass
logwall bootstrap-baseline        Create a default-deny baseline where none exists
                                 (refuses if one already exists, or if a manager owns it)
logwall firewall audit            Read-only detection report
logwall firewall apply            Apply the blocklist; arms a deadman rollback
logwall firewall confirm          Confirm the last apply
logwall firewall rollback [ID]    Restore a snapshot (verified, not assumed)
logwall firewall unban <IP>       Manual release
logwall firewall status           Backend, sets, enforcement, coexistence
logwall firewall panic            EMERGENCY: detach every logwall hook
logwall selftest [--repair]       Verify and optionally repair hooks and sets
logwall uninstall [--purge]       Clean removal, verified
```

## Tests

No root, no firewall, no network. Everything runs in a temp directory.

```bash
python3 tests/smoke_test.py       # 341 checks: parsers, window, subnets, profiling, guards, escalation
bash    tests/gate_test.sh        #  72 checks: the gate refuses what it must
bash    tests/lineending_test.sh  #   1 check: CRLF would break every script on Linux
```

## Documentation

- [`docs/DESIGN.md`](docs/DESIGN.md) — the full design: detection model, backend
  abstraction, log formats, anti-lockout machinery, support matrix
- [`CHANGELOG.md`](CHANGELOG.md) — release history
- [`conf/logwall.conf`](conf/logwall.conf) — every option documented inline,
  including why each default was chosen

## Contributing

Issues and pull requests are welcome. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) first — it
states what is in scope, what is deliberately out, and the one rule that matters most here:
**a change in behaviour needs evidence from a real host**, because nearly every defect in this
project's history passed cleanly on a workstation and failed on a server.

## Licence

Distributed under the MIT License. See [`LICENSE`](LICENSE) for the full text.
