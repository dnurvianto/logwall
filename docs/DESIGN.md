# 🛡️ logwall — Cross-Server & Cross-Panel Firewall Automation

> **Scope note.** This is the full design, including parts deliberately left out
> of 1.0. For what is actually implemented and supported today, read
> [`../README.md`](../README.md) — its **Scope** section is authoritative.
> Anything described here but absent from that section is not implemented.

## Overview (`logwall`)

`logwall` automates **server firewall** security management, designed to behave identically across:
* **Linux distributions:** Debian/Ubuntu, RHEL/AlmaLinux/Rocky/CentOS. Alpine (OpenRC) and Arch
  have complete code paths but are **untested in a real environment** — see tier T2 in §20.
  Neither is claimed as supported in the README until it has been measured.
* **Web servers:** Nginx, Apache, LiteSpeed/OpenLiteSpeed, Caddy.
* **Control panels:** FastPanel, cPanel, Plesk, DirectAdmin, CyberPanel, aaPanel, HestiaCP, and bare non-panel servers.

> Support levels per distribution / web server / panel (T1 validated, T2 supported, T3 best-effort)
> are detailed in **[§20 Support Matrix](#20-support-matrix-distro--web-server--panel)**.

---

## 🎯 Primary Functions

1. **Log- and byte-driven auto-blocker:** parses HTTP/HTTPS access logs (Nginx frontend/Apache) to detect brute force (`wp-login.php`), XML-RPC exploitation, sensitive-URL scanning (`.env`, `.sql`), request flooding, and **high bandwidth abuse (>30 MB)**.
2. **Panel log auto-discovery:** maps each site's log location through the panel CLI (FastPanel CLI, for example) or falls back to pattern matching, with no hardcoded paths.
3. **Identity-based bot blocking (aggressive crawler control):** uses `hash:net` sets keyed on User-Agent and attacker cloud ASN/CIDR ranges, and a shipped list of published search engine ranges so Googlebot is never blocked.
4. **Port ↔ service synchronisation:** opens the ports running services need and closes orphaned ones.
5. **L4 anti-DDoS and rate limiting:** kernel SYN cookie tuning (`sysctl`), conntrack rate limits, and dropping unknown UDP.
6. **Dual protection & safe lockout:** a two-layer admin whitelist (ipset + a top-of-chain iptables rule), plus guaranteed availability of the public web ports (80/443 TCP and UDP QUIC) and DNS (53 TCP/UDP).
7. **Safe operating flow:** the cycle **`audit` (read-only) → `apply` (auto-rollback if SSH drops) → `rollback` (--date)**.
8. **Periodic review and cleaning (`logwall firewall review`):** weekly cron maintenance that deduplicates the blacklist, aggregates CIDR ranges, and recommends unbanning single-hit entries.
9. **Dual-stack & CDN-aware:** uniform blocking across IPv4 **and** IPv6 (separate sets, `/64` aggregation), plus real-IP recovery behind Cloudflare/CDN with a hard guard so CDN edges can never be blocked.
10. **Layered anti-lockout:** a deadman switch (`apply` rolls back automatically when unconfirmed), an emergency `panic` command, and the `selftest --repair` drift monitor, which reports duplicate jumps, missing cron entries, orphaned deadmen and foreign blocking agents (§15.5 — restoring its own chains is the `*/2` `apply` cron's job, not this monitor's).
11. **Pre-installation gate (`preflight.sh`):** refuses to install while the environment is not fully ready — including a **full stop when another blocker is found** (cron, a foreign ipset, fail2ban/CSF). Every finding carries an ID and its fix command, and the installation is transactional (a failure at any point → full rollback).

---

## 📌 Scope Boundary (Firewall Only)

* **In scope (networking):** port-service synchronisation, log- and byte-driven IP blocking, UA/ASN/CIDR blocking, L4 rate limiting, admin whitelisting, permanent blocks with manual unban, rule persistence, rule backup and rollback.
* **NOT in scope (outside `logwall`):** crontab or file integrity inspection, SSH hardening, OS patching, SSL/TLS renewal, web application firewall (layer-7), FIM and malware scanning, health checks, data backup.

---

## Table of Contents

1. [Why the Firewall First](#1-why-the-firewall-first)
2. [Scope Boundary](#2-scope-boundary)
3. [Firewall Scope Components](#3-firewall-scope-components)
4. [Tech Stack](#4-tech-stack-bash--python-hybrid)
5. [Installation & Prerequisites (Python auto-install)](#5-installation--prerequisites-python-auto-install)
6. [Project Structure](#6-project-structure)
7. [CLI & Operating Modes](#7-cli--operating-modes)
8. [Firewall Backends (cross-distro & control-panel abstraction)](#8-firewall-backends-cross-distro--control-panel-abstraction)
9. [Logging & Reports (independent, local)](#9-logging--reports-independent-local)
10. [Baseline Thresholds & Basic Practice](#10-baseline-thresholds--basic-practice)
11. [Bot Control (AI scrapers / crawlers)](#11-bot-control-ai-scrapers--crawlers)
12. [Blocking Policy](#12-blocking-policy)
13. [Central Configuration](#13-central-configuration)
14. [Dual-Stack IPv6](#14-dual-stack-ipv6)
15. [Anti-Lockout & Emergency Recovery](#15-anti-lockout--emergency-recovery)
16. [Execution Reliability (locking, log cursors, catch-up guard)](#16-execution-reliability-locking-log-cursors-catch-up-guard)
17. [Hardening the Tool Itself](#17-hardening-the-tool-itself)
18. [Machine Output & Integration](#18-machine-output--integration)
19. [Uninstall](#19-uninstall)
20. [Support Matrix (Distro × Web Server × Panel)](#20-support-matrix-distro--web-server--panel)
21. [Pre-Installation Gate & Transactional Install](#21-pre-installation-gate--transactional-install)

---

---

## 1. Why the Firewall First

The firewall is the first scope worth automating end to end, because it meets every criterion
automation demands:

| Criterion | Firewall | Other scopes, for comparison |
|---|---|---|
| Inputs can be read automatically | ✅ open ports, access logs, services | Patching needs human policy; app-layer needs application context |
| Actions are reversible | ✅ unblock = undo; rules can be deleted | Deleting cron or files is destructive; a wrong SSH change is a lockout |
| Easy to make idempotent | ✅ `iptables -C` / `ipset -exist` | Panel CLIs all differ |
| Stable across operating systems | ✅ ufw/firewalld/nftables share a pattern | Package managers differ per distribution |
| Independent of application content | ✅ works from logs and connections | Malware scanning is prone to false positives |
| Risk can be tested | ✅ test connectivity after apply | Backups need remote infrastructure |

Initial validation targets: AlmaLinux (RHEL 8/9) + FastPanel, and Debian/Ubuntu + Nginx without
a panel.

## 2. Scope Boundary

**In scope (networking):**
- Port ↔ service synchronisation, log-driven IP blocking, identity blocking (UA/ASN/CIDR),
  L4 rate limiting and anti-DDoS, whitelisting, permanent blocks with manual unban, rule
  persistence, rule backup and rollback.

**NOT in scope (covered in `keamanan-lainnya.md`):**
- SSH hardening, patching, TLS renewal, headers/permissions/WAF, FIM and malware scanning,
  cron guarding, health checks, data backup, service auto-healing.

## 3. Firewall Scope Components

### Core (rules & blocking)
1. **Firewall backend detection** — ufw / firewalld / nftables / iptables; whichever is active
   becomes the target (never write to two at once). Details: §8.
2. **Port-service synchronisation** — read the ports running services listen on → open what is
   missing, close what is orphaned (no service owns it). Enabled through `MANAGE_PORTS=1`.
3. **Log-driven auto-blocker** — parse access logs (web server + panel) → detect patterns
   (brute force, xmlrpc, scanners, bandwidth) → blacklist → ipset. Thresholds: §10.
4. **Identity-based blocking** — UA plus ASN/CIDR for bots and crawlers (ipset hash:net), not
   per address.
5. **L4 rate limiting / anti-DDoS** — SYN cookies (`net.ipv4.tcp_syncookies=1`), per-address
   connection limits (conntrack), dropping foreign UDP (optional, production profile).

### Self-protection (never lock yourself out)
6. **Admin whitelist** — a whitelist file, an ACCEPT rule at the very top, absolute priority.
7. **Manual unban** — blocks are **permanent** (they never expire on their own); an address
   proven to be attacking gets no second chance. Released only through
   `harden firewall unban <ip>` by an admin (a legitimate user gets in touch, or a report
   review turns something up).
8. **Skip list** — ranges that must always pass (Googlebot /24, your own Cloudflare/CDN ranges).

### Operational
9. **Persistence** — save the backend's rules (`iptables-save` / `ipset save` /
   `firewall-cmd --permanent`), restore at boot through a service or `systemd` unit.
10. **Rule backup & rollback** — snapshot before changing anything (`data/snapshot/`), restore
    with `--date`.
11. **Idempotence** — check before adding (`iptables -C`, `ipset -exist`), never duplicate.
12. **Modes** — `audit` / `apply` / `rollback` / `report` / `status` / `unban` (§7).
13. **Reports & notification** — a daily log plus a blocking summary; local to the server is
    enough (independent, no external service).
14. **Panel compatibility** — detect a panel's firewall (CSF on cPanel/DirectAdmin) → warn, and
    coordinate so two layers never conflict.
15. **Periodic review** — routine maintenance through `harden firewall review` (weekly cron):
    blacklist optimisation (dedupe + CIDR aggregation), review of unused services and users
    (details: §7). Recommendations only — execution stays with the admin.

### Resilience (mandatory, and frequently skipped)
16. **Dual-stack IPv4 + IPv6** — separate sets and rules for `inet6`; a dual-stack server
    protected only on IPv4 is a wide-open back door (§14).
17. **Dedicated `LOGWALL_*` chains** — every rule lives in its own chain, never a global
    `iptables -F`; compatible alongside Docker, fail2ban, CSF and panels (§8.A1, §8.D, §8.E).
18. **Real IP behind a CDN** — parse `CF-Connecting-IP`/XFF plus a hard guard: CDN edge ranges
    may never enter the blacklist (blocking them takes the whole site down) (§8.F).
19. **Collision and miscount avoidance** — file locking, per-inode log cursors, a state-backed
    counting window, parser sanity checks, and a catch-up guard on distorted input (§16).
20. **Layered anti-lockout** — bootstrap the whitelist from the active SSH session, the deadman
    switch, `panic`, the `selftest --repair` monitor, and the STALE heartbeat (§15).
21. **Hardening the tool itself** — root-only files at 0640/0750, refuse-to-run when writable by
    non-root, zero `shell=True` (an attacker's User-Agent must never reach a shell) (§17).

## 4. Tech Stack (Bash + Python Hybrid)

**Decision: Option 1 — Bash + Python 3 (standard library only).**

| Component | Language | Role |
|---|---|---|
| `install.sh`, `harden` (CLI), firewall wrapper | **Bash** | Orchestration, subcommand dispatch, calling ipset/iptables/nftables, cron, installation |
| `parse_logs.py`, `audit.py`, `apply.py`, `report.py` | **Python 3 stdlib** | Log parsing, threshold arithmetic, panel CLI JSON, audit, rollback, reporting |

Non-negotiable rules:
- **Zero pip dependencies** — standard library modules only: `json`, `re`, `subprocess`,
  `ipaddress`, `glob`, `os`, `sys`, `datetime`. No `pip install` on any server, ever.
- Python is used for logic only (parsing, threshold arithmetic, JSON); everything that touches
  the kernel or the firewall goes through Bash — a clear responsibility boundary that is easy
  to debug.
- Python is invoked as `python3` (never `python`) — consistent across every modern distribution.

## 5. Installation & Prerequisites (Python auto-install)

`install.sh` runs as **root** and is idempotent (safe to re-run).

> **Absolute prerequisite:** installation may begin only after `./preflight.sh` returns
> **READY**. A single BLOCKER finding stops it before one file is written, and a failure at any
> stage unwinds every change. The gate, the BLOCKER/WARNING list and the transactional flow are
> detailed in **[§21](#21-pre-installation-gate--transactional-install)**.
> The steps below describe the *contents* of stages 2-5 of that flow.

```
Flow:
1. Detect the distribution (`/etc/os-release` → ID/ID_LIKE) → package manager & init system:
       apt      + systemd   (Debian/Ubuntu)
       dnf/yum  + systemd   (RHEL/Alma/Rocky/CentOS)
       pacman   + systemd   (Arch)
       apk      + OpenRC    (Alpine)   ← NOT systemd, see step 1b
1b. Set up the init abstraction (used throughout the tool; never call systemctl directly):
       svc_enable / svc_start / svc_status →
         systemd : systemctl enable|start|is-active <unit>
         OpenRC  : rc-update add <svc> default | rc-service <svc> start|status
    A distribution with neither (some other init) → WARN + persistence through a manual boot
    hook, exit non-fatal
2. Check python3: python3 --version → requires >= 3.6
   - Present and sufficient → continue (install nothing)
   - Absent → auto-install:
       apt-get install -y python3        (Debian/Ubuntu)
       dnf install -y python3            (Alma/Rocky/RHEL)
       pacman -S --noconfirm python      (Arch — the binary is still named python3)
       apk add python3                   (Alpine)
3. Verify the result: python3 -c "import json,re,subprocess,ipaddress"
4. Installation failed (no network, repository error) →
   - Abort with a clear message and a non-zero exit code
   - Bash-only degraded mode: audit and report still run (awk/grep);
     the full blocker logic needs Python → flagged "DEGRADED" in the report
5. Set up: copy the project tree → /opt/logwall, create data/logs,
   write /etc/logwall.conf from the template, install cron
6. Bootstrap the whitelist (MANDATORY, anti-lockout):
   - Take the installing session's address: $SSH_CLIENT / $SSH_CONNECTION → fall back to
     `who am i`, `ss -tn sport = :$SSH_PORT`
   - Add it to ip_whitelist.txt automatically (v4 and v6) and show the admin a confirmation
   - Detect the real SSH port from sshd_config (every Port line, plus Match) → PROTECTED_PORTS
   - Installation NEVER completes with an empty whitelist → abort if no admin address is found
7. Detect the active web server and its log format (§8.G) → write LOG_FORMAT per site into state
8. Set permissions and ownership (§17): root:root, dirs 0750, scripts 0750, conf 0600,
   state 0640
9. Install the monitor cron (`selftest --repair`) and run a final `logwall selftest`
```

Other prerequisites checked: `ipset` and `iptables` (or the active backend, §8) — both ship by
default on server distributions (on RHEL/Alma, `ipset` comes as a kernel module and is usually
present). Minimal Alpine and Arch installs frequently lack `ipset` → the native nftables backend
is used automatically (§8.A2). Cron: `cronie`/`cron` under systemd, `busybox crond` on Alpine —
checked and enabled through `svc_enable`. Panel CLI detection (FastPanel's
`fastpanel --json sites list` and similar) is optional and used only to auto-discover site log
paths; without a panel it falls back to globbing `/var/www/*/data/logs/*.log`.

## 6. Project Structure

```
/opt/logwall/
├── install.sh            # Project installation, Python auto-installer, cron & config setup
├── uninstall.sh          # Uninstaller: removes cron, LOGWALL_* chains, sets; --purge for full data wipe
├── logwall                # Main CLI wrapper (Bash, subcommand dispatcher)
├── VERSION               # Read by `logwall version` (Version + Backend + Init + OS Distro)
├── conf/
│   └── logwall.conf       # Central configuration file (Thresholds, timeouts, & file paths)
├── lib/
│   ├── system_discovery.sh # OS distro, init manager, firewall backend, & webserver detection
│   ├── firewall_wrapper.sh # Backend abstraction layer (ipset, iptables, nftables, ufw, csf)
│   ├── rule_snapshot.sh    # Firewall ruleset snapshot, backup, & rollback engine
│   ├── cron_manager.sh     # Cron job lifecycle & monitor installer
│   ├── process_lock.sh     # File locking mechanism & stale lock cleanup (§16.1)
│   ├── chain_manager.sh    # Isolated LOGWALL_* chain creator & Docker hook injector (§8.A1)
│   └── py/
│       ├── log_parser.py   # Multi-format log parsing engine (Nginx, Apache, LiteSpeed, Caddy JSON)
│       ├── audit_engine.py # Read-only audit mode: IP scoring, orphan ports, & recommendations
│       ├── apply_engine.py # Candidate filtering, blacklist file updater, & kernel set rebuilder
│       ├── real_ip.py      # CDN & reverse-proxy real IP resolver + CDN hard-guard (§8.F)
│       ├── fleet_sync.py   # Multi-server threat intelligence export & import (§19)
│       └── report_gen.py   # Daily & weekly health, block, and review report generator
├── data/
│   ├── whitelist_ips.txt   # Whitelisted admin IPs/CIDRs (IPv4 & IPv6, absolute priority)
│   ├── whitelist_hosts.txt # Dynamic DDNS hostnames resolved per cycle (§15.2)
│   ├── blacklist_ips.txt   # Blacklisted attacker IPs & metadata ("# YYYY-MM-DD | Reason")
│   ├── bypass_rules.txt    # Trusted search engine bots & internal network bypass list
│   ├── cdn_networks.txt    # Edge CDN IP ranges — STRICTLY PROTECTED from blocking (§8.F)
│   ├── snapshot/           # Timestamped rule snapshots for rollback (SNAPSHOT_RETENTION)
│   └── state/              # System state files & persistent caches
│                           # ├── review_state.json   (Review items: NEW / PENDING / REVIEWED)
│                           # ├── log_cursor.json     (Per-file inode & byte offset tracker, §16.2)
│                           # ├── window_state.json   (IP hit counter state with TTL window)
│                           # ├── trusted_history.json(Known-good IP history for escalation ladder)
│                           # └── orphan_ports.json   (Consecutive orphan port cycle tracker)
└── logs/                   # System operational logs & daily summaries (REPORT_RETENTION_DAYS)
```

## 7. CLI & Operating Modes

```
logwall firewall audit                    # read-only (default): backend, orphan ports, IP candidates + reasons, scores
logwall firewall apply                    # execute: snapshot → whitelist → port sync → rebuild ipset → test → persist
logwall firewall rollback --date 20260804_070000   # restore a rule snapshot
logwall firewall report                   # daily summary (local)
logwall firewall status                   # active sets, block counts, whitelist, backend
logwall firewall unban <ip>               # manual release, recorded in history
logwall firewall sync-ports               # port-service synchronisation only
logwall firewall review                   # periodic review (maintenance, read-only)
logwall firewall ack <id>                 # mark a review item as acted on (--ack-all for every item)

# --- Anti-lockout & emergency (§15) ---
logwall firewall confirm                  # confirm the apply worked → cancel the deadman rollback
logwall firewall panic                    # EMERGENCY: detach jumps + flush LOGWALL_* chains (other tools' rules untouched)
logwall selftest [--repair]               # verify chains/jumps/sets/permissions; --repair reinstalls what is missing

# --- Lifecycle ---
logwall version                           # tool version + distro + backend + panel + IPv6 status
logwall uninstall [--purge]               # remove cron and rules; --purge also deletes data and config
```

**Global flags (valid on every subcommand):**
`--json` (machine output, §18) · `--dry-run` (print the rule diff, execute nothing) ·
`--quiet` (for cron; the log file stays complete) · `--config <path>`

**Review item state (must be unambiguous — it keeps nagging until reviewed):**

```
NEW → PENDING_REVIEW → REVIEWED (through `logwall firewall ack <id>`)
```
- Every recommendation (unban candidate, service or user disable candidate) gets an **ID** and
  the state `PENDING_REVIEW`, stored in `data/state/review_state.json`.
- An item that has **not been acked** keeps appearing in every following report labelled
  **"[NOT REVIEWED]"** — the report repeats each cycle until the admin acts (`ack`, `unban`, or
  `review --auto-disable`).
- Once acked, the action and date are recorded and it stops appearing in reports (unless it is
  detected again as a new item).

**`review` — the periodic function (weekly cron, read-only):**

1. **Blacklist optimisation**:
   - Dedupe: an address appearing twice (from several detections or rounds) → one entry, with
     the metadata merged.
   - CIDR aggregation: adjacent addresses that are all blocked (ten consecutive ones, say) →
     merged into a single range (`203.0.113.0/28`) → a leaner blacklist file and ipset.
   - **Unban candidates**: an address blocked only once and absent from the logs for
     >= `REVIEW_SINGLE_HIT_DAYS` → recommended in the report (a recommendation only; running
     `unban` stays with the admin, consistent with the permanent-block policy).
2. **Service review**: the list of active services (`systemctl list-units`, or `rc-status -s` on
   OpenRC/Alpine — through the `svc_list` abstraction, §5) compared against used ports, active
   connections (`ss -tnp`) and log activity.
   - A service with no connections or activity for >= `REVIEW_SERVICE_IDLE_DAYS` is flagged
     **"disable candidate — almost certainly useless on this server"** in the report.
   - **Never auto-disabled** unless invoked with the explicit
     `logwall firewall review --auto-disable` flag (risky; the default is recommendation only).
3. **Account review**: panel users with no login or file activity for
   >= `REVIEW_SERVICE_IDLE_DAYS` → suspension candidates (recommended, not executed).
4. Results go into the **periodic report** (§9); every action remains manual, by the admin.

**The `apply` flow (mandatory order):**
0. **Take the lock** — `flock` (§16.1); if another process holds it, exit 4 rather than queue.
1. **Snapshot** — `iptables-save` + `ip6tables-save` + `ipset save` + a copy of the blacklist
   file → `data/snapshot/YYYYMMDD_HHMMSS/`.
2. **Load the whitelist** — the first ACCEPT rule (absolute priority, never subject to DROP);
   including DDNS hostname resolution (§15.2) and IPv6 entries.
3. **Port-service sync** (when `MANAGE_PORTS=1`) — subject to `PROTECTED_PORTS` and
   `PORT_ORPHAN_RUNS` (a port is closed only after being orphaned for N consecutive cycles).
4. **Parse logs** → IP candidates against the thresholds (§10), using the cursor and the state
   window (§16.2), with real-IP resolution when behind a CDN or proxy (§8.F).
5. **Filter candidates** — discard: the whitelist, the skip list, **CDN ranges (hard guard,
   refused at any score)**, published search engine ranges, local/loopback/RFC1918 addresses, the server's
   own addresses, and the gateway and DNS resolvers the server uses; record the reason for every
   address (traceable).
6. **Catch-up guard** — if this run ingested far more log than one interval covers, the
   **volume** rules are suspended for the run and the **intent** rules still apply; the report
   carries `CATCHUP_RUN` with the reason (§16.4). No cap is placed on how many addresses a run
   may block: every candidate came from a signal and already passed every guard in step 5.
7. **Rebuild the sets** — `WHITELIST_SET`/`BLACKLIST_SET` (v4) plus
   `WHITELIST_SET6`/`BLACKLIST_SET6` (v6); metadata is attached as an ipset comment, or stays in
   the file when the backend is nft (§8.A2).
8. **Arm the deadman** — schedule an auto-rollback `CONFIRM_TIMEOUT_SEC` ahead (§15.3).
9. **Test connectivity** — wait 10-20 seconds, verify the SSH session and admin port are still
   alive (check `ss -tn state established`, or a test connection from the admin address);
   **failure → automatic snapshot restore + alert, exit 10.**
10. **Persist** — `ipset save` + `iptables-save`/`ip6tables-save` (or the backend equivalent) +
    write state.
11. **Log & report** — newly blocked count, total, reasons, remaining set capacity.
12. **Wait for `confirm`** — the admin runs `logwall firewall confirm` → the deadman is cancelled.
    Without confirmation the rules revert automatically. (`apply --no-confirm` for a routine
    cron that has already proven stable.)

**Safety net (mandatory rules):**
1. The admin whitelist comes first and is never blocked.
2. Connectivity is tested after apply — failure means automatic rollback.
3. **The deadman switch** — an apply without `confirm` inside `CONFIRM_TIMEOUT_SEC` rolls itself
   back. The connectivity test only proves the session *currently running* is alive; the deadman
   catches the case where the admin is already cut off and cannot type anything.
4. **The CDN hard guard** — CDN edge ranges can never enter the blacklist, for any reason.
5. **The catch-up guard** — volume rules stand down when the run's input is time-distorted.
6. Idempotence — check for existence before adding a rule or entry.
7. Thresholds come from the configuration file, never hardcoded.
8. Blocks are permanent for intent-based detections; volume-based detections use the
   TEMP → PERMANENT escalation ladder (§12) so that a CGNAT or office address is not punished
   forever over a single incident. The blacklist grows continuously → routine review is
   mandatory, and the whitelist and skip list must be maintained strictly.

## 8. Firewall Backends (cross-distro & control-panel abstraction)

Detection, in priority order: **nftables** (`nft list ruleset` works) → **firewalld**
(`firewall-cmd --state` is active) → **ufw** (`ufw status` is active) → **iptables** (fallback).

### A. Backend Abstraction & Per-Distribution Persistence
- `lib/firewall.sh` is a wrapper with one function per action: `fw_add`, `fw_del`, `fw_check`,
  `fw_save`, `fw_restore` — implemented per backend.
- **One active backend** is chosen; if two are active (firewalld plus an iptables ruleset, say)
  → use firewalld and record a warning in the report.
- **Persistence per distribution:**
  - **RHEL / AlmaLinux / Rocky / CentOS:** `/etc/sysconfig/ipset`, `/etc/sysconfig/iptables`, `/etc/sysconfig/ip6tables` + `svc_enable ipset iptables ip6tables`.
  - **Debian / Ubuntu:** `/etc/iptables/rules.v4`, `/etc/iptables/rules.v6` and `/etc/iptables/ipsets` through `netfilter-persistent` / `iptables-persistent`.
  - **Arch:** `/etc/iptables/iptables.rules`, `/etc/iptables/ip6tables.rules` + `svc_enable iptables ip6tables` (the `iptables-nft` package is the default → usually straight to the nftables path).
  - **Alpine (OpenRC):** `/etc/iptables/rules-save`, `/etc/iptables/rules6-save`, `/etc/ipset.d/` + `rc-update add iptables ip6tables ipset default`. **No systemd** — every service call goes through the `svc_*` abstraction (§5 step 1b).
  - **nftables-native:** `nft list ruleset > /etc/nftables.conf` + `svc_enable nftables`.

> **Rule:** not one hardcoded `systemctl` line exists anywhere in the tool. Everything goes
> through `svc_enable` / `svc_start` / `svc_status`, or Alpine will fail silently — the command
> *exists* (exit 127 / command not found) while the rules are never restored at boot.

### A1. Dedicated Chain Architecture (absolute rule: never touch another tool's rules)

```
INPUT
 ├─ 1. -j LOGWALL_WL      → ACCEPT the admin whitelist (v4+v6, absolute priority)
 ├─ 2. -j LOGWALL_BLOCK   → DROP on BLACKLIST_SET / BLACKLIST_SET6
 ├─ 3. -j LOGWALL_RATE    → conntrack limits, SYN, drop foreign UDP
 └─ 4. …existing rules (panel / CSF / fail2ban / Docker) — NEVER touched
DOCKER-USER (when Docker is detected)
 └─ 1. -j LOGWALL_BLOCK   → container traffic does not traverse INPUT (§8.D)
```

- Every logwall rule lives in a chain of its own. `apply` only needs `-F LOGWALL_*`;
  **a global `iptables -F` is strictly forbidden** — that is what destroys panel and fail2ban
  rules.
- The rules are *jumps* from INPUT; the jump positions are re-checked every cycle (idempotent,
  `-C` first).
- `panic` (§15.4) removes the 3 jumps and flushes the chains → the server instantly returns to
  its previous behaviour.
- `uninstall` = panic + delete the chains + destroy the sets → no trace left behind.
- On nftables: a separate `table inet logwall` with a hook priority lower than the panel's table,
  so it never collides when the panel reloads its own ruleset.

### A2. The nftables Backend Without `ipset`

Minimal Debian 12 and RHEL 9 installs frequently **have no `ipset`** (and it is unavailable in
container-based images). Falling back to native nft sets is mandatory:

```
nft add table inet logwall
nft add set inet logwall blacklist4 { type ipv4_addr ; flags interval ; }
nft add set inet logwall blacklist6 { type ipv6_addr ; flags interval ; }
nft add chain inet logwall input { type filter hook input priority -10 ; }
nft add rule inet logwall input ip  saddr @blacklist4 drop
nft add rule inet logwall input ip6 saddr @blacklist6 drop
```

**Source-of-truth principle:** `data/ip_blacklist.txt` is the source of truth; the kernel set is
only a *cache*. nft sets do not support per-element comments on every version, so metadata (date,
reason, hits) always lives in the file — the set can be rebuilt from it in full at any time.
The design consequence: never read metadata back out of the kernel.

### A3. Set Capacity
- `ipset` defaults to `maxelem=65536`. With a permanent-block policy that limit **will
  certainly be reached** on a busy server — and `ipset add` then fails **silently**, so
  protection stops with no error.
- Sets are created with `maxelem=IPSET_MAXELEM` (default 262144) and a proportional `hashsize`.
- Every cycle: compute occupancy; >= `IPSET_CAPACITY_ALERT_PCT` → ALERT plus a recommendation to
  run `review` (CIDR aggregation cuts thousands of entries down to dozens of ranges).

### B. Handling Panel Firewalls (CSF / a panel's internal firewall)
- **CSF (ConfigServer Security & Firewall)** on cPanel/DirectAdmin:
  - Detect the CSF binary or files (`/usr/sbin/csf` or `/etc/csf/csf.conf`).
  - **Coordination rule:** when CSF is active, block and unban calls must be routed through the
    CSF CLI (`csf -d <IP> "<reason>"` and `csf -a <IP>`), because CSF periodically runs
    `iptables -F`, which would delete iptables rules created from outside.

### C. Cross-Panel Access Log Auto-Discovery
The tool maps frontend log paths dynamically, based on which panel it detects:

| Panel | Detection | Access log path | Web server behind it |
|---|---|---|---|
| **FastPanel** | `/usr/local/fastpanel2/` | CLI `fastpanel --json sites list` → **a bare array**; the path comes from `owner.home_dir` + `/logs/<domain>-frontend.access.log` (see §8.C1) | Nginx (frontend) + Apache (backend) |
| **cPanel** | `/usr/local/cpanel/` | `/var/log/apache2/domlogs/<domain>` · `/usr/local/apache/domlogs/<domain>` (with an Nginx proxy: `/var/log/nginx/access.log`) | Apache / EA-Nginx / LiteSpeed |
| **Plesk** | `/usr/local/psa/` | `/var/www/vhosts/system/<domain>/logs/access_log` (+ `access_ssl_log`, `proxy_access_log`) | Nginx + Apache |
| **DirectAdmin** | `/usr/local/directadmin/` | `/var/log/httpd/domains/<domain>.log` (+ `.bytes`) | Apache / OpenLiteSpeed / Nginx |
| **CyberPanel** | `/usr/local/CyberCP/` | `/home/<domain>/logs/<domain>.access_log` | **OpenLiteSpeed** (default) |
| **aaPanel / BT** | `/www/server/panel/` | `/www/wwwlogs/<domain>.log` (errors: `<domain>.error.log`) | Nginx / Apache / OpenLiteSpeed |
| **HestiaCP** | `/usr/local/hestia/` | `/var/log/nginx/domains/<domain>.log` (+ `.bytes`, `.error.log`) | Nginx + Apache/PHP-FPM |
| **No panel** | — | glob: `/var/log/nginx/*access*.log` · `/var/log/{httpd,apache2}/*access*log` · `/usr/local/lsws/logs/*access*.log` · `/var/log/caddy/*.log` · `/var/www/*/logs/*access*.log` | anything |

- Panel paths change between versions → discovery results are **always verified** (the file
  exists, is readable, and has new lines within 24 hours) before use; on failure it falls back to
  globbing and records that in the report.
- A site whose log cannot be found at all becomes `LOG_NOT_FOUND` in the report — **not**
  silently treated as "no attacks here".

#### C1. The FastPanel CLI Contract (verified, not assumed)

Three things that are easy to guess wrong and make auto-discovery fail **silently**:

1. **The JSON root is a bare array** (`[{...}, {...}]`), not an object wrapped as
   `{"data": [...]}`. A parser calling `.get("data")` on a list raises `AttributeError`, which
   the `except` swallows before falling back to globbing without a word.
2. **The owning account is at `owner.username` and `owner.home_dir`**, not `user.login`.
   `home_dir` (for example `/var/www/pnsleman/data`) is the most reliable base; `index_dir`
   (`.../data/www/<domain>`) serves as a fallback by trimming `/www/<domain>`.
3. **The owner differs between sites on the same host.** Inferring one account from the first
   site is wrong for all the others. The owner must be read per site.

Per-site log selection order: `<home_dir>/logs/<domain>-frontend.access.log` →
`/var/www/<username>/data/logs/...` → the `index_dir` derivative. When only the **backend** log
exists, it is used but flagged `BACKEND_LOG_ONLY` — the addresses in it sit behind a reverse
proxy and are trustworthy only if the backend is configured to recover them.

*Proxy architecture note:* on panels running Nginx (frontend) + Apache (backend), the log parser
**must read the Nginx frontend log** to obtain the visitor's real address (`$remote_addr`), which
is what prevents false-blocking localhost (`127.0.0.1`).

### D. Docker / Containers (the most frequently missed trap)

Docker, Podman and k8s publish ports through `nat/PREROUTING` and the `FORWARD` chain —
**packets destined for a container never traverse `INPUT`**. Which means an entire INPUT
blacklist has no effect whatsoever on traffic reaching an application inside a container.

- Detection: the `DOCKER-USER` chain exists, or the `/var/run/docker.sock` socket does.
- Required: insert `-I DOCKER-USER 1 -j LOGWALL_BLOCK` (v4 and v6).
- ~~Docker restart / daemon reload → the chain is rebuilt and the jump is lost → the watchdog
  must reinstall it every 10 minutes.~~ **Wrong — corrected 2026-08-14 by measurement.**
  `systemctl restart docker` does **not** discard the jump: `DOCKER-USER` is genuinely a
  user-owned chain, and Docker only flushes `DOCKER` and `DOCKER-ISOLATION-*`. Tested with a
  container published as `-p 8080:80`, the `-A DOCKER-USER -j LOGWALL_BLOCK` jump was intact
  before and after, and did not duplicate after two `--repair` runs.

  The monitor is still kept — but **that justification is a different one, and far weaker for a
  10-minute interval.** All four triggers once cited as its reason
  (`firewall-cmd --reload`, `ufw reload`, `csf -r`, `restart docker`) have been tested on real
  hosts and **not one of them tears a chain out**.

  **A fifth trigger was tested on 2026-08-15, and the result closes the question.** firewalld
  with `FirewallBackend=iptables` **does** delete the `LOGWALL_*` chains entirely — the only
  configuration proven to do so. But what puts them back is the `*/2` `apply` cron, **not** the
  `*/10` monitor. So out of five candidate triggers, **zero** justify this job as a repairer.
  Its role is restated as a drift monitor in §15.5.
- What genuinely does get lost: rules **injected into** another tool's chain.
  `systemctl restart ufw` deletes third-party rules in `ufw-before-input`, while a separate chain
  plus a jump survives. That is the reason for the "own your chain, never borrow one" design —
  not the monitor.
- The report flags `CONTAINER_EXPOSED` when a container port is published to `0.0.0.0` while the
  DOCKER-USER jump is not installed.

### E. Coexistence with Other Security Tools

| Detected | Treatment |
|---|---|
| **CSF** (`/etc/csf/csf.conf`) | Every block and unban is routed through `csf -d` / `csf -a` (CSF flushes iptables routinely) |
| **fail2ban** (`f2b-*` chains) | Never flush its chains. Detect overlapping jails (sshd, wordpress) → record `OVERLAP` in the report and recommend keeping a single source so counts do not double |
| **firewalld + a panel** | Use `--direct` or rich rules in the active zone; never write straight to iptables |
| **Imunify360 / BitNinja** | Audit-only mode + WARN — two active L3 agents means conflict, and one that is hard to diagnose |

Principle: logwall **never** modifies or deletes a rule that is not its own; conflicts are always
reported to the admin rather than resolved unilaterally.

### F. Real IP Behind a CDN / Reverse Proxy (the largest outage risk)

When a site sits behind Cloudflare or another CDN, `$remote_addr` in the log is the **CDN edge
address**, not the visitor's. Blocking it blocks every visitor to the site. This is the tool's
most severe failure mode, and it is handled in three layers:

1. **Hard guard (absolute):** `cdn_nets.txt` holds the CDN edge ranges. A block candidate that
   overlaps one of them is **always refused** — past the score, past the threshold, and even
   past a manual entry. Refused → WARN plus `CDN_GUARD_HIT` in the report.
2. **Real-IP resolution:** `REAL_IP_FIELD=auto` → use `$http_cf_connecting_ip`, or the
   **rightmost XFF entry that is not a trusted proxy** (the left-hand ones can be forged by an
   attacker). Prerequisite: the `log_format` includes that field.
3. **Fail-safe when the real IP is unavailable:** the log has only `$remote_addr` and that
   address turns out to belong to the CDN → that site **drops to audit-only mode**
   (`CDN_NO_REALIP_POLICY`), with concrete instructions for adding the field to `log_format`.
   Better to block nothing than to take the site down.

**A limit that must be stated explicitly in the report:** for a CDN-fronted site, an L3 block on
the real address **does not stop the traffic** — the packets still arrive from the CDN edge.
Enforcement has to happen at the CDN (firewall rules) or in the web server (`deny`). logwall
reports this as `ENFORCEMENT_ELSEWHERE` so the admin does not mistakenly believe they are
protected.

### G. Log Formats Across Web Servers (not just different paths — different structures)

The claim of working "across web servers" does not end at log paths. What breaks a parser is the
differing **format** and **byte field name**. Without this normalisation layer, `THRESHOLD_BW_MB_PER_INTERVAL`
miscounts on Apache and the parser dies outright on Caddy.

| Web server | Default format | Bytes-sent field | Parser notes |
|---|---|---|---|
| **Nginx** | `combined` | `$body_bytes_sent` (**body only**, no headers) | The baseline. Real-IP requires `$http_cf_connecting_ip`/`$http_x_forwarded_for` to be added to `log_format` by hand |
| **Apache** | `combined` (`%b`) | `%b` = body, `%O` = **body + headers** | `%b` writes `-` for a 0-byte response → must be treated as 0, not as a parse error |
| **LiteSpeed / OpenLiteSpeed** | Apache-compatible `combined` | `%b` / `%O` | Different paths (`/usr/local/lsws/logs/`, per-vhost `$VH_ROOT/logs/`); LSWS rotates internally rather than through logrotate → per-inode cursors (§16.2) are mandatory |
| **Caddy v2** | **JSON per line**, not combined | `size` (integer, body) | The combined regex **fails 100% of the time** → a dedicated JSON handler is required |

**The placeholder count is not uniform — and that is deceptive.** Standard combined has two
placeholders (identd and auth-user); some panels write only one:

```
IP - - [date] "GET /x HTTP/1.1" 200 123     ← combined (two)
IP -   [date] "GET /x HTTP/1.1" 200 123     ← FastPanel backend variant (one)
```

A parser working from **field positions** cannot tell them apart: on the second variant it reads
`HTTP/1.1"` as the URI and `"referer"` as the byte count. The line still counts as "parsed
successfully" — so `PARSE_FAIL` **never fires** — while wp-login, xmlrpc and recon detection are
completely blind and bandwidth is always zero.

The parser is therefore anchored on the **quoted request**, not on a field index, with the second
placeholder optional:

```
^<ip>\s+\S+\s+(?:\S+\s+)?\[<timestamp>\]\s+"<request>"\s+<status>\s+<bytes|->
```

**Format detection & configuration:**
- `LOG_FORMAT=auto` → a line starting with `{` that parses as JSON → `json`; a line matching the
  regex above → `combined`; anything else → `PARSE_FAIL` plus a request for a manual `LOG_REGEX`.
- The format is stored **per log file** in state, not globally — one server can run Nginx
  (combined) and Caddy (JSON) side by side.

**The JSON handler (Caddy) — field mapping:**

```
request.remote_ip / request.client_ip  → source address (client_ip already respects trusted_proxies)
request.headers.Cf-Connecting-Ip[0]    → the real address behind Cloudflare (§8.F)
request.uri                            → wp-login / xmlrpc / .env / .git detection
status                                 → 401/403 panel brute-force detection
size                                   → bandwidth per interval (THRESHOLD_BW_MB_PER_INTERVAL)
request.headers.User-Agent[0]          → bot control (§11)
```
A corrupt or truncated JSON line (the log was mid-write when it was read) → **skip that line
only**, never fail the whole cycle.

**Byte normalisation (mandatory):** every format is converted to one internal `bytes_sent` unit.
Apache with `%O` counts headers, so its number is larger than Nginx's `$body_bytes_sent` for the
same traffic — without normalisation a 30 MB threshold fires sooner on Apache and the admin
believes there is an attack when there is none. A missing field, or one holding `-`, means 0.

## 9. Logging & Reports (independent, local)

- Log format: `[YYYY-MM-DD HH:MM:SS] [LEVEL] [module] message` → `logs/`.
- Levels: INFO (normal), WARN (degraded or conflicting), ALERT (a new block), ERROR (apply
  failed).
- **Daily report** (through cron): new blocks and their reasons, blacklist total, manual unbans
  today, active whitelist, orphan ports, active backend, mode status (NORMAL/DEGRADED).
- **Weekly review report** (the output of `review`): deduplicated and aggregated entries, unban
  candidates (single-hit), service and user disable candidates, each with its reason — all of
  them recommendations.
- **Reminder state**: review items still at `PENDING_REVIEW` (not yet acked) are **repeated in
  every report** under the label `[NOT REVIEWED]` until the admin acts — no recommendation ever
  disappears quietly.
- **Health status must appear in every report** (not only when something was blocked):
  `STALE` (cron is not running, §15.6) · `PARSE_FAIL` (unrecognised log format, §16.3) ·
  `BREAKER_TRIPPED` (blocking was aborted, §16.4) · `CDN_GUARD_HIT` (a CDN candidate was refused,
  §8.F) · `ENFORCEMENT_ELSEWHERE` (a CDN-fronted site, where L3 blocking is ineffective) ·
  `CONTAINER_EXPOSED` (a container port without the DOCKER-USER jump, §8.D) ·
  `SET_CAPACITY` (ipset occupancy at or above the threshold) · `OVERLAP` (a clash with
  fail2ban/CSF, §8.E) · `IPV6=off` · `DEGRADED`.
- Retention `REPORT_RETENTION_DAYS` (default 30), rotated automatically.
- **No external service** — every output is local; email is optional and non-real-time.

## 10. Baseline Thresholds & Basic Practice

Default values for the blocker cycle (cron every 2 minutes) — all of them overridable through
`/etc/logwall.conf` (§13):

| Detection | Threshold | Notes / handling logic |
|---|---|---|
| `wp-login.php` | >5x | WordPress login brute force (`BruteForce`) |
| `xmlrpc.php` | >2x | XML-RPC exploitation (`XmlRpcExploit`) |
| Total hits per address | >40x | Scraper / request flood (`CloudScraper`) |
| Bandwidth per address | >30 MB | Bandwidth abuse (`HighBandwidth`) — uses the cross-web-server normalised `bytes_sent` (§8.G), not the raw field |
| Sensitive files (`.env/.sql/.bak/phpmyadmin/.git`) | >2x | Recon scanning (`ReconScanner`) |
| Failed panel logins (401/403) | >5x | FastPanel/cPanel brute force |
| Panel hits | >200x | Panel scraping |

Basic practices that must be present in every cycle:
- **FastPanel log auto-discovery:** read the domain list through `fastpanel --json sites list` to
  map frontend log paths (`/var/www/<user>/data/logs/<domain>-frontend.access.log`)
  automatically, with a glob fallback.
- **Skip Googlebot (CIDR check):** the `66.249.64.0/19` range is skipped automatically through
  Python's `ipaddress` module, so the official crawler is never blocked.
- **Kernel ipset comment metadata:** the blacklist is stored in a file
  (`IP # YYYY-MM-DD HH:MM | Reason`) and pushed directly into the kernel ipset
  (`hash:net comment`), so `ipset list` shows exactly the same metadata.
- **Dual protection whitelist:** besides the `LOGWALL_WL4`/`LOGWALL_WL6` ipset, every whitelist
  address is also injected as an individual `-s <address> -j ACCEPT` rule (comment
  `LOGWALL_ADMIN_BACKUP`), installed by `setup_admin_whitelist_backup()`
  (`lib/chain_manager.sh`) at INPUT position 1 — ahead of `LOGWALL_WL`, `LOGWALL_BLOCK` and
  `LOGWALL_RATE`. Position is not incidental: a backup rule below `LOGWALL_BLOCK` protects
  nothing, because a blacklisted packet is already gone before reaching it. The two mechanisms
  fail independently — an ipset flushed, destroyed, or rebuilt empty mid-cycle cannot take the
  static rule with it — which is what an accidental lockout actually looks like: the jump to
  `LOGWALL_WL` is still there, `iptables -L` still looks correct, and the packet falls through to
  whatever comes next anyway. Toggle: `WHITELIST_DOUBLE_BACKUP` (default `1`).
- **Guaranteed public port rules:** the public web ports (80, 443 TCP and UDP QUIC) and DNS
  (53 TCP/UDP) are re-inserted after the blacklist DROP rule on every cycle, keeping the site
  online with no risk from an iptables flush.
- **Automatic persistence:** output is saved to the distribution's persistence location (§8.A)
  and the boot-restore service is enabled through the `svc_enable` abstraction (systemd or
  OpenRC).

## 11. Bot Control (AI scrapers / crawlers)

Policy summary:

- Block by **UA + ASN/CIDR** (ipset hash:net) — bot addresses rotate, so per-address blocking is
  futile.
- **Search engines are spared from a shipped list of published ranges**
  (`/etc/logwall/crawler_ranges.txt`): Googlebot, bingbot and Applebot, taken from the JSON
  the operators publish themselves. Refreshed by every install, and preflight warns when the
  file is older than `CRAWLER_RANGES_MAX_AGE_DAYS`.
- The test for membership is **whose cost it is**. Blocking a search engine does not save
  bandwidth; it removes the site from search results, so the cost lands on the site owner.
  SEO tools, social preview fetchers, archives and AI training crawlers are deliberately
  absent — they consume bandwidth and send no visitors, and whether that trade is worth it
  belongs to whoever pays the bill. `bypass_rules.txt` is where an operator adds their own.
- **Known limitations, because a static list has them:**
  - It goes stale. Operators add ranges and the file does not learn.
  - **Yandex and Baidu publish no ranges at all** — both document reverse DNS as the only
    supported verification, so this file cannot cover them. Add addresses by hand if that
    traffic matters to you.
- Earlier revisions of this document specified FCrDNS (forward-confirmed reverse DNS) here,
  with an `rdns_cache.json` and a 30-day TTL, and **no release ever implemented it**. It was
  built in 1.0.0-rc13 and removed in the same release: it worked, but a published-range list
  had existed since 1.0 and the case for reaching past it was never made. The defect it
  exposed was not the mechanism — it was that nothing consulted *either* source, which is why
  40 Bingbot addresses were found blocked on a production host.
- The CIDR list is refreshed periodically (monthly cron, atomic swap) — cloud ranges change.
- **Light bots** (Googlebot: cheap requests, cache-friendly) → leave alone.
- **Heavy bots** (rendering crawlers such as BingPreview/Meta; persistent Ahrefs/Baidu) →
  block or rate-limit.
- A proven practice: blocking the /24 of a persistent cloud range saves bandwidth without
  upgrading the plan.
- A static cache or CDN is the first layer, so bots never reach the origin at all.

## 12. Blocking Policy

| Situation | Policy |
|---|---|
| Repeated failed logins (CMS/panel/SSH/FTP/SFTP) | **Permanent hard block** (low false-positive rate) plus the admin whitelist; released only by manual unban |
| One user, many addresses (credential stuffing) | Permanent per-address block **plus per-user rate limiting** (a second layer) |
| Automated port scanning / URL fuzzing | Permanent per-address block (volume-based) — never block over one or two 404s |
| SQLi/XSS/RCE (application layer) | **Do NOT hard block** — rate-limit instead (a wrong block hits legitimate users) |
| Spoofed / distributed DDoS | Do not block per address — rate-limit and mitigate upstream |
| Aggressive bots and crawlers | Block the identity (UA/ASN/CIDR) permanently, not the address |
| Admin addresses / your own ranges | Always whitelisted, never blocked |

The golden rule of blocking: block only **repeated attacks from a limited source, before
compromise**; post-compromise (rootkits, web shells) is not a firewall's job.
### The Escalation Ladder (a correction: "always permanent" is dangerous for volume detections)

The problem: a mobile carrier's CGNAT address, an office, a campus, a hotel — all of them are
**hundreds of legitimate users behind one address**. Blocking that permanently over 40 hits means
blocking customers, and it turns the blacklist into a rubbish heap that can never be reviewed.

| Detection type | Policy |
|---|---|
| **Clear malicious intent** — wp-login brute force, xmlrpc, `.env`/`.git`/`.sql` recon, failed panel logins | **PERMANENT immediately** (false-positive rate ~0) |
| **Volume-based** — total hits, bandwidth, panel hits | `TEMP` for `TEMP_BLOCK_HOURS` (default 48) → **a repeat after release = PERMANENT** |
| **Addresses in `known_good.json`** (a successful login, or a long history of legitimate traffic) | Drop one tier; never permanent straight from a volume detection |

- Each entry's state: `OBSERVE → TEMP → PERMANENT`, recorded in the blacklist as
  `IP # 2026-08-12 14:03 | HighBandwidth | TEMP(48h) | strike=1`.
- `BLOCK_ESCALATION=0` restores the old behaviour (everything permanent) if that is what you
  want.
- Expired `TEMP` entries are released automatically by the cycle — the single exception to the
  "unban is manual only" rule, and it applies to the TEMP tier alone.

**Per-country blocking (GeoIP) — optional, OFF by default:** for administrative ports (SSH,
panel) only, **never** for 80/443 (a public site means visitors from anywhere). It needs local
GeoIP data; without that data the feature disables itself quietly rather than erroring.

## 13. Central Configuration

Every threshold and path comes from one file (`/etc/logwall.conf`), never from hardcoded values:

```ini
# ===== General =====
BACKEND=auto                # auto | nftables | firewalld | ufw | iptables
MANAGE_PORTS=1              # 1 = synchronise ports with active services

# ===== Network / Blocker =====
WHITELIST=/etc/logwall/whitelist_ips.txt
BLACKLIST=/etc/logwall/blacklist_ips.txt
SKIP_LIST=/etc/logwall/bypass_rules.txt
THRESHOLD_WP_LOGIN=5          # wp-login.php attempts
THRESHOLD_XMLRPC=2            # xmlrpc.php attempts
THRESHOLD_HITS_PER_INTERVAL=60    # requests from one address inside one interval
THRESHOLD_BW_MB_PER_INTERVAL=20   # bandwidth from one address inside one interval
STRIKES_REQUIRED=2                # intervals over the line before a volume block
STRIKES_WINDOW=10                 # ...counted among the last this many intervals
THRESHOLD_SENSITIVE_SCAN=2    # access to .env/.sql/.bak/phpmyadmin/.git
THRESHOLD_PANEL_401=5         # failed panel logins (401/403)
THRESHOLD_PANEL_HITS=200      # panel hits
GOOGLE_BOT_NETS="66.249.64.0/19"   # light-bot ranges that are skipped

# ===== Bot Control =====
BOT_UA_FILE=/etc/logwall/bot_ua_deny.txt
BOT_ASN_FILE=/etc/logwall/bot_asn_deny.txt
UPDATE_INTERVAL_DAYS=30

# ===== Login =====
LOGIN_FAIL_BLOCK=5            # N failures → hard block
LOGIN_RATE_PER_USER=5         # failures per minute per username

# ===== Logging (local, independent) =====
REPORT_DIR=/var/log/logwall
REPORT_RETENTION_DAYS=30

# ===== Periodic Review (read-only, recommendations) =====
REVIEW_SCHEDULE="0 3 * * 1"       # weekly cron (Monday 03:00)
REVIEW_SINGLE_HIT_DAYS=30         # blocked once and unseen for >=30 days → unban candidate
REVIEW_SERVICE_IDLE_DAYS=30       # a service or user idle >=30 days → disable candidate

# ===== Dual-Stack IPv6 (§14) =====
IPV6=auto                         # auto | on | off
IPV6_BLOCK_PREFIX=64              # aggregate IPv6 blocks per /64, not /128

# ===== CDN / Reverse Proxy (§8.F) =====
CDN_NETS_FILE=/etc/logwall/cdn_networks.txt   # CDN edge ranges — blocking them is forbidden (hard guard)
REAL_IP_FIELD=auto                # auto | remote_addr | cf_connecting_ip | x_forwarded_for
TRUSTED_PROXIES=/etc/logwall/trusted_proxies.txt   # proxies that may be trusted in the XFF chain
CDN_NO_REALIP_POLICY=audit_only   # a log without a real IP → that site is audited, never blocked

# ===== Execution Reliability (§16) =====
LOCK_FILE=/var/lock/logwall.lock
LOCK_STALE_MIN=30                 # a lock older than this is treated as a crash → cleaned + WARN
INTENT_WINDOW_MIN=30              # how far back the INTENT counters sum
EVAL_INTERVAL_SEC=120             # interval width; keep equal to BLOCKER_SCHEDULE
WEBSERVER=auto                    # auto | nginx | apache | litespeed | caddy (§8.G)
LOG_FORMAT=auto                   # auto | combined | json | custom (pair with LOG_REGEX)
APACHE_BYTES_FIELD=auto           # auto | b | O — %O includes headers and must be normalised
LOG_MAX_MB_PER_RUN=200            # read cap per cycle (protection against enormous logs)
CATCHUP_GUARD=1                   # suspend volume rules when a run ingests a backlog
CATCHUP_MAX_GAP_MIN=15            # a longer gap than this means the next run is a catch-up
IPSET_MAXELEM=262144              # kernel default is 65536 → once full, ipset add fails SILENTLY
IPSET_CAPACITY_ALERT_PCT=80
SNAPSHOT_RETENTION=30             # prune old snapshots; never fill the disk
EXT_CMD_TIMEOUT_SEC=15            # timeout for panel CLI / rDNS / resolution — cron must never hang

# ===== Anti-Lockout (§15) =====
CONFIRM_TIMEOUT_SEC=300           # deadman: apply auto-rollback when `confirm` never arrives
WHITELIST_DYNAMIC_HOSTS=/etc/logwall/whitelist_hosts.txt   # the admin's DDNS hostnames
WATCHDOG_SCHEDULE="*/10 * * * *"  # selftest --repair
HEARTBEAT_STALE_FACTOR=2          # last_run > 2x the interval → flag STALE in the report
SSH_PORT=auto                     # auto-detected from sshd_config (every Port line + Match)
PROTECTED_PORTS="22,80,443,53"    # never closed by sync-ports (SSH is always included automatically)
PORT_ORPHAN_RUNS=3                # a port is closed only after N consecutive orphaned cycles

# ===== Block Escalation (§12) =====
BLOCK_ESCALATION=1                # 1 = volume detections use the TEMP → PERMANENT ladder
TEMP_BLOCK_HOURS=48
KNOWN_GOOD_FILE=/etc/logwall/state/trusted_history.json

# ===== Multi-Server Fleet (§19, optional) =====
FLEET_IMPORT_MIN_HITS=3           # ignore imported entries with fewer hits than this
FLEET_IMPORT_MAX_AGE_DAYS=90

# ===== Geo (optional, OFF by default — §12) =====
GEOBLOCK_COUNTRIES=""             # empty = off; applied ONLY to admin ports, never 80/443
GEOIP_DATA=/etc/logwall/geoip/     # local data; absent → the feature disables itself quietly
```

**Config upgrade rule:** re-running `install.sh` **merges** new keys into `/etc/logwall.conf`
(writing defaults that are missing, with their comments) and **never overwrites** a value the
admin has already set. An unrecognised key produces a WARN, not a fatal error.

## 14. Dual-Stack IPv6

Modern servers (Alma 9, Debian 12, nearly every VPS) have **IPv6 enabled by default**. A firewall
that closes only IPv4 is half a protection: an attacker simply moves to the `AAAA` record and the
entire blacklist becomes decoration. This was the most fatal gap in the original design.

- **Separate sets:** `WHITELIST_SET6` / `BLACKLIST_SET6` —
  `ipset create ... hash:net family inet6`. inet and inet6 sets cannot be mixed; the rules are
  installed in `ip6tables` / `nft ip6 saddr`.
- **Aggregate at `/64`, not `/128`.** A customer is normally handed an entire `/64` and can
  rotate addresses inside it at will — blocking a `/128` is pointless. `IPV6_BLOCK_PREFIX=64`.
  For providers who hand out a `/48` per customer, `review` may aggregate to `/56` once 8 or more
  distinct `/64`s from the same prefix have been blocked.
- **The admin whitelist must be dual-stack.** Logging in over IPv6 while the whitelist holds only
  IPv4 is an instant lockout at apply time. The bootstrap (§5 step 6) takes both families from
  the active session.
- **Port synchronisation must be dual-stack** — a port closed on v4 but open on v6 is a hole
  invisible to a v4 audit. `ss -tlnp` is inspected for `tcp6`/`udp6` as well.
- **Parser:** addresses are normalised through `ipaddress.ip_address()` (the compressed and full
  forms are the same address — without normalisation the threshold is never reached because they
  count as different addresses).
- **Detecting a disabled IPv6** (`net.ipv6.conf.all.disable_ipv6=1`, or no global address) →
  skip quietly with `IPV6=off` in `status`, rather than erroring.
- Persistence: `/etc/sysconfig/ip6tables` (RHEL) / `/etc/iptables/rules.v6` (Debian).

## 15. Anti-Lockout & Emergency Recovery

The connectivity test in §7 only proves the session *currently running* is alive. That is not
enough: an old session often survives because of the `ESTABLISHED` rule, while **new connections**
are already dead. The admin finds out the next morning when they try to log in. The five layers
below close that gap.

1. **Whitelist bootstrap at installation** — take the address from `$SSH_CLIENT` /
   `$SSH_CONNECTION`, falling back to `who am i` and
   `ss -tn state established '( sport = :22 )'`. It enters the whitelist automatically (v4 and
   v6) and is displayed for confirmation. **Installation fails (exit 2) if the whitelist ends up
   empty** — no path exists that produces a server with no way in.
2. **Dynamic whitelist (DDNS)** — an admin whose home or ISP address changes puts a *hostname* in
   `whitelist_hosts.txt`; it is resolved every cycle (timeout `EXT_CMD_TIMEOUT_SEC`) and the
   result enters the kernel whitelist set **and** the block-candidate filter.
   - **Resolution failed → use the last cache, never delete the rule.** A DNS hiccup must not
     turn into a lockout. Entries served from cache are flagged `DDNS_STALE` along with their
     age, so they are never quietly treated as fresh.
   - A hostname that has **never** resolved successfully becomes `DDNS_FAILED`; it grants no
     access at all, and preflight flags it `DDNS_UNRESOLVED`.
   - Common free providers: **DuckDNS**, **No-IP**, **Dynu**, or your own domain through the
     Cloudflare API. Whichever it is, the updater has to run **on the machine the admin connects
     from**, not on the server — otherwise the record goes stale and this file grants nothing.
3. **The deadman switch** — `apply` schedules an automatic rollback `CONFIRM_TIMEOUT_SEC` ahead.
   The scheduler is chosen in order of what the distribution provides (Alpine has no systemd, a
   minimal Arch has no `at`) — **there is always a fallback; this feature may never be absent**:
   1. `systemd-run --on-active=<seconds> logwall firewall rollback --deadman` (systemd)
   2. `echo 'logwall firewall rollback --deadman' | at now + N minutes` (when `at` exists)
   3. The universal fallback: a background process,
      `setsid sh -c 'sleep N; [ -f $MARKER ] && logwall firewall rollback --deadman' &`,
      with its PID stored in `state/deadman.pid`; `confirm` removes the marker **and** kills the
      PID.
   The marker file is what decides, not the process — if the process dies first, `selftest`
   (§15.5) sees a marker older than `CONFIRM_TIMEOUT_SEC` and performs the rollback.
   An admin who can still get in runs `logwall firewall confirm` to cancel it. An admin who is
   already locked out **does nothing at all** and the server restores itself. This is the only
   mechanism that works precisely when the admin cannot type anything.
   - Routine cron uses `apply --no-confirm` once the profile has proven stable.
4. **`logwall firewall panic`** — detach the `LOGWALL_*` jumps from INPUT and DOCKER-USER and flush
   the chains. Other tools' rules (panel, CSF, fail2ban) are untouched. Run from a VNC, serial or
   rescue console when SSH is no longer usable. The command is deliberately short and takes no
   arguments — a person in a panic must not be asked to remember syntax.
5. **Drift monitor `logwall selftest --repair`** (cron `*/10`) — verifies:
   the chain jumps are installed · the whitelist rules exist · the sets are loaded in the kernel ·
   the `DOCKER-USER` chain still has its jump · file permissions are correct · the configuration
   parses.

   > **Corrected 2026-08-15 by measurement — calling it a "watchdog" was misleading.**
   > Its *repair* half (`fw_init_sets` + `setup_iptables_chains`) is **exactly** what
   > `firewall apply` already does every **2 minutes**, so it is not a repairer: it is
   > always 5× too slow. Tested on firewalld with `FirewallBackend=iptables`, the only
   > configuration that genuinely deletes the `LOGWALL_*` chains:
   > `07:25:58 jump=0` → `07:28:28 jump=3` — the recovery came from the `*/2` slot, not `*/10`.
   >
   > **Its real value is drift detection, not repair:** duplicate jumps (`chain_selftest`),
   > missing cron entries (`cron_selftest`), an orphaned deadman (`deadman_check_stale`),
   > a foreign blocking agent that appeared after installation, and changes in IPv6
   > exposure. `apply` checks none of them.
   >
   > **A limit that has to be stated honestly:** `cron_selftest` cannot save itself — if
   > every logwall cron entry is deleted, the checker dies with them. It protects against
   > losing **some** entries, not all of them.

   Something missing → reinstall it; **the whitelist is always restored before the blacklist**,
   without exception. Every run's result is written to `state/selftest.last` **regardless of
   `--quiet`**, failures are appended to `${REPORT_DIR}/selftest.log`, and the last result
   appears in `logwall status` and in the daily report. Before this, cron ran it with
   `--quiet >/dev/null 2>&1`, so **every finding was discarded** — a monitor whose output goes
   nowhere is decoration.
6. **Heartbeat** — `state/last_run` is written every cycle. A `last_run` older than
   `HEARTBEAT_STALE_FACTOR` × the cron interval → the report flags **STALE**. A security tool
   that dies quietly is more dangerous than one that was never installed, because the admin
   believes they are protected.

## 16. Execution Reliability (locking, log cursors, catch-up guard)

1. **File locking.** The `*/2` cron, a manual `apply`, the weekly `review` and the monitor can
   all overlap. Two processes writing the ipset and `ip_blacklist.txt` at once → a corrupt file
   or a half-built set. Every **writer** must take `flock $LOCK_FILE`; failing to
   acquire it means exit 4 (never queue, never force). A lock older than `LOCK_STALE_MIN` is
   treated as crash residue, cleaned up with a WARN.

   > **This rule said "every subcommand that writes", and that wording had a hole.**
   > `uninstall.sh` is a separate script rather than a `logwall` subcommand, so it was never
   > covered — while being the most destructive writer in the project. Measured on a busy
   > host: a cron `apply` began in the same second as an uninstall. The uninstall detached
   > the hooks, deleted the chains, destroyed the sets and verified itself clean — correctly,
   > at the instant it looked. One second later the in-flight `apply` rebuilt the chains and
   > sets, and the host was left with orphaned chains that the next preflight refused to
   > install over, reporting them as another tool's.
   >
   > Both halves of the failure are worth naming. The verification was not wrong; it was
   > **outrun** — proof that checking at the end is no substitute for holding the lock
   > throughout. And the hole existed because the rule was written in terms of the CLI's
   > shape rather than in terms of who writes.
   >
   > `uninstall.sh` now takes the lock before touching anything, cron removal included: an
   > apply already running means nothing has changed yet, so exiting is free, and an apply
   > that fires while the lock is held exits without rebuilding a thing.

2. **Per-inode log cursors.** Without them, reading a "24-hour window" every 2 minutes means
   **the same request is counted 720 times a day** — an already-blocked address keeps appearing
   as a candidate, the numbers in the report explode, and CPU cost grows linearly with log size.
   - `log_cursor.json` stores `{path: {inode, size, offset}}`; each cycle reads only the new
     bytes.
   - The inode changed **or** `size < offset` → a rotation happened → read whatever remains
     unread in the old file (`.1`, `.1.gz`), then start from offset 0 on the new one.
   - Per-address counters live in `window.json` as **per-interval buckets**, rather than being
     recomputed from zero every cycle or accumulated into one running total. Buckets fall off
     the back by time, so nothing grows without bound. Before 1.0.0-rc12 a counter reset only
     after a full day of complete silence, which meant an address seen once a day accumulated
     forever and a loyal visitor could reach a volume threshold having done nothing.
   - `LOG_MAX_MB_PER_RUN` caps a surge (after the tool has been dead for a week, say) so that a
     single cycle cannot exhaust the server's RAM or CPU.

3. **Parser sanity check.** The file grew but **0 lines parsed successfully** → an unrecognised
   log format (a custom log_format, a panel that changed its template, JSON logs). Required:
   WARN + the `PARSE_FAIL` status + **make no blocking decision at all from empty data**. The
   format can be forced through `LOG_FORMAT`/`LOG_REGEX`.

4. **Catch-up guard.** There is **no cap** on how many addresses one run may block. Every
   entry reaching the apply stage came from a detection signal and had already passed every
   guard, so a large batch means many offenders, and refusing to act on the tool's own findings
   is not a safety measure.

   A circuit breaker used to sit here: candidates > `MAX_NEW_BLOCKS_PER_RUN` aborted the whole
   run. It was removed in 1.0.0-rc11. It fired twice in production and was wrong both times — 500
   genuine addresses in one incident, 70 `/64`s of one crawler in the other — blocking nothing
   while the abuse continued. It committed state as it aborted, so the same candidates returned
   two minutes later and tripped it again; and it announced itself only on stderr, which cron
   discards, so a host could decline to block anything for hours and still look healthy. It also
   cancelled the **intent** verdicts along with the volume ones, releasing the most clearly
   guilty addresses on the run.

   What it was groping at is real, and is now measured at the source. Each line's own timestamp
   is parsed (`parse_stamp()`, §8.G), so `_detect_catchup()` compares the **measured span** of the
   data this run swallowed against `CATCHUP_MAX_GAP_MIN` — it does not guess from the gap between
   runs. The difference is not academic: a host powered off for four hours wrote no log while it
   was down, so the gap is four hours and the span is two minutes, and only the measurement gets
   that right. When no timestamp anywhere in the batch can be read, the run gap is used as the
   weaker fallback. On a catch-up run:

   - **volume** detections stand down — request counts, bandwidth, 404 storms, login POSTs, and
     the subnet flood/bandwidth rollups
   - **intent** detections keep firing — brute force, recon, failed logins, scanner signatures.
     Five probes for `/.env` are five probes whether they arrived over two minutes or two days
   - the run is reported as `CATCHUP_RUN` on stdout, in the daily report, and in
     `state/run_meta.json`

5. **Set capacity** — see §8.A3 (a full set means `ipset add` fails silently).

6. **Snapshot retention** — `SNAPSHOT_RETENTION` (default 30), pruned automatically on every
   `apply`. An `iptables-save` snapshot on a busy server can run to tens of MB; a full disk means
   a dead server, which would be an ironic way for a tool whose job is protecting uptime to fail.

7. **Timeouts on every external call** — the panel CLI (`fastpanel --json ...`), rDNS, DDNS
   resolution. A panel CLI that hangs without a timeout will hang cron forever and pile up
   processes until the server runs out of PIDs.

## 17. Hardening the Tool Itself

This tool runs as **root, from cron**. Which means anyone who can write a file under
`/opt/logwall/**` has root. A security tool that becomes the privilege escalation path is the
worst possible outcome.

- **Required ownership and permissions:** `root:root` · directories `0750` · scripts `0750` ·
  `/etc/logwall.conf` `0600` · data and state `0640`.
- **Refuse to run** (ERROR + exit 2, not merely a warning) if any logwall file is writable by
  non-root, or if `/opt/logwall` sits under a path with a world-writable component. Verified by
  `install.sh` **and** by `selftest`.
- **`ip_whitelist.txt` is a firewall bypass path** — treat it like a credentials file. Every
  change is logged with a before and after hash, so a quiet addition is visible during an audit.
- **Zero `shell=True`.** Everything coming from an access log (User-Agent, path, referer) is
  entirely attacker-controlled. External calls use `subprocess.run([list])`, never a shell
  string. A UA containing `` ; rm -rf / `` must end up as plain text, not as a command.
- **Validation before execution:** every address is verified with `ipaddress.ip_network()`
  before it reaches `ipset add` or `nft`. Invalid ones are discarded and recorded, never passed
  through.
- **Absolute PATHs** for every binary (`/sbin/ipset`, `/sbin/iptables`, `/usr/bin/python3`) —
  cron with an influenceable PATH means executing a forged binary.
- Logs never contain whitelist contents or credentials; a recorded UA is truncated to 200
  characters and escaped so it cannot corrupt whatever parses the log next (log injection).

## 18. Machine Output & Integration

Without this, the tool can only be driven by a human one server at a time — unsuitable for
running many.

- **`--json`** on `audit | status | report | review | version` → consumed by monitoring
  (Zabbix, Netdata, your own scripts) with no fragile text parsing.
- **Standard exit codes** (a contract; these must not change between versions):

  | Code | Meaning |
  |---|---|
  | 0 | Success, nothing found |
  | 1 | Findings or candidates exist (audit mode — normal, not an error) |
  | 2 | Configuration, file permission or prerequisite error |
  | 3 | No firewall backend detected |
  | 4 | The lock is held by another process |
  | 5 | DEGRADED mode (Python unavailable, §5) |
  | 10 | An automatic rollback happened (connectivity test or deadman failed) |

- **`--dry-run`** on `apply` — print the exact diff of rules and entries that would be added or
  removed, touching nothing. Mandatory the first time you install on someone else's server.
- **`--quiet`** for cron (silent stdout, the log file still complete) so cron does not flood
  root's mail.
- **`logwall version`** shows the tool version + distribution + init system + active backend +
  the detected web server and log format + the detected panel + IPv6 status +
  **support tier (§20)** + DEGRADED status. This is the first thing anyone needs when diagnosing
  a problem across servers.

## 19. Uninstall

> **Fleet sync is not a feature.** Sharing blocklists between your own servers is deliberately
> outside 1.0. It is described here only so the intent is on record; **nothing implements it**,
> and this section previously documented two CLI commands that did not exist.
>
> That gap was not harmless. Half-finished scope shipped as `lib/py/fleet_sync.py` — never
> called by the CLI, yet present and tested — and it was reached for during a migration and
> misused. Documenting a command that does not exist invites exactly that.
>
> **Migrating another tool's blocklist is not in scope at all** and never will be (1.4.0
> removed `import-legacy` for that reason). Every host has its own history, dependencies and
> risk tolerance. preflight reports what it found and names the command to secure the data;
> the admin decides and acts. That is sysadmin work, not something this tool performs.

**A clean uninstall (`logwall uninstall`).** Without a clean way out, this tool is not fit to try
on someone else's production server.

1. Remove every cron entry (`logwall`, the monitor, review).
2. `panic` — detach the jumps, flush and delete the `LOGWALL_*` chains, destroy the sets (v4 and
   v6).
3. Remove logwall's own persistence and rewrite the rule files without its entries (other tools'
   rules preserved intact).
4. `--purge` → delete `/opt/logwall`, `/etc/logwall*`, data, state and logs.
   Without `--purge` → data and the blacklist are kept so it can be reinstalled without losing
   history.
5. Final verification: `iptables -S | grep LOGWALL` empty, `ipset list -n | grep LOGWALL` empty,
   and the SSH connection still alive → report the result.

## 20. Support Matrix (Distro × Web Server × Panel)

Support levels are stated honestly, so that a claim of "works everywhere" is never larger than
the reality:

- **T1 — Validated:** tested end to end (`audit` → `apply` → `rollback` → reboot).
- **T2 — Supported:** the code path is complete and specific, but untested in a real environment.
- **T3 — Best-effort:** through the generic fallbacks (log globbing, common backend detection);
  it runs, but with no guarantee about specific paths or formats.

`logwall version` prints the tier detected on that server, so an admin knows where they stand
before running `apply` for the first time.

### A. Linux Distributions

| Distribution | Pkg manager | Init | Rule persistence | Usual backend | Tier |
|---|---|---|---|---|---|
| AlmaLinux / Rocky / RHEL / CentOS 8-9 | dnf/yum | systemd | `/etc/sysconfig/{ipset,iptables,ip6tables}` | firewalld → nftables | **T1** |
| Debian 11-12 | apt | systemd | `/etc/iptables/rules.v{4,6}` (netfilter-persistent) | nftables (`iptables-nft`) | **T1** |
| Ubuntu 20.04-24.04 | apt | systemd | same as Debian | ufw → nftables | **T1** |
| Arch Linux | pacman | systemd | `/etc/iptables/{iptables,ip6tables}.rules` | nftables | **T2** |
| Alpine 3.x | apk | **OpenRC** | `/etc/iptables/rules-save`, `/etc/ipset.d/` | nftables (frequently without `ipset`) | **T2** |
| Other systemd distros with `/etc/os-release` | detected through ID_LIKE | systemd | generic | detected | **T3** |

Important notes per distribution:
- **Alpine** is not systemd → `systemctl` and `systemd-run` do not exist. Everything goes through
  `svc_*` (§5.1b) and the deadman switch uses the background-process fallback (§15.3).
  `busybox crond`, not cronie.
- **Minimal Alpine and Arch** frequently lack `ipset` → the native nftables path is used
  automatically (§8.A2).
- A container or LXC without `NET_ADMIN` or without the `ip_set` module → initial detection fails
  → exit 3 with a clear message, rather than getting halfway.

### B. Web Servers

| Web server | Default log format | Usual paths | CDN real IP | Tier |
|---|---|---|---|---|
| Nginx | combined | `/var/log/nginx/*access*.log` | `$http_cf_connecting_ip` / XFF (must be added to `log_format`) | **T1** |
| Apache httpd | combined (`%b`/`%O`) | `/var/log/{httpd,apache2}/`, `domlogs/` | `%{CF-Connecting-IP}i` or `mod_remoteip` | **T2** |
| OpenLiteSpeed / LiteSpeed Ent | Apache-compatible | `/usr/local/lsws/logs/`, `$VH_ROOT/logs/` | header through a custom log format | **T2** |
| Caddy v2 | **JSON per line** | `/var/log/caddy/*.log` | `request.client_ip` + `trusted_proxies` | **T2** |
| Nginx (frontend) + Apache (backend) | combined | the frontend log only | must read the frontend, never the backend | **T1** |
| Anything else / custom | through a manual `LOG_REGEX` | glob | manual | **T3** |

The absolute rule of proxy architecture: **always parse the outermost layer's log**. Reading
Apache's log behind Nginx yields `127.0.0.1` on every line — and if that gets past the filters,
the server blocks itself (§8.C, §8.F).

### C. Control Panels

| Panel | Log discovery | Built-in firewall | Tier |
|---|---|---|---|
| FastPanel | CLI `fastpanel --json sites list` | — | **T1** |
| No panel (bare VPS) | glob per web server | — | **T1** |
| cPanel / WHM | `domlogs/` | **CSF** → coordination mode required (§8.B) | **T2** |
| Plesk | `/var/www/vhosts/system/*/logs/` | fail2ban included → check `OVERLAP` (§8.E) | **T2** |
| DirectAdmin | `/var/log/httpd/domains/` | **CSF** in common use | **T2** |
| CyberPanel | `/home/<domain>/logs/` | firewalld + ModSecurity | **T2** |
| aaPanel / BT Panel | `/www/wwwlogs/` | its own panel firewall → check for conflicts | **T2** |
| HestiaCP | `/var/log/nginx/domains/` | iptables + fail2ban included | **T2** |

A panel with its own firewall (CSF, a panel firewalld, a bundled fail2ban) is **never** taken
over. logwall adapts to it (§8.B) or reports the conflict (§8.E) — two L3 agents flushing each
other is the hardest kind of downtime to diagnose.

### D. Explicitly NOT Supported

- Windows Server / IIS — out of scope, no code path exists.
- FreeBSD / OPNsense (pf, not netfilter) — an entirely different firewall architecture.
- Distributions without netfilter (a locked container kernel, some older OpenVZ VPSes).
- Proprietary panels whose log paths cannot be discovered → they fall back to the T3 glob; if
  that also fails, `LOG_NOT_FOUND` and the tool refuses to block for that site.

## 21. Pre-Installation Gate & Transactional Install

**Principle:** a tool that manages the firewall as root must not be installed into an environment
that is not fully ready. Refusing with a clear reason beats installing halfway and then failing
silently every 2 minutes from cron.

The verdict has to be readable by machines and by ordinary people — **without anyone having to
interpret the output**. Every finding carries an **ID, an explanation and its fix command**.

### A. The `preflight.sh` Contract

| Exit | Verdict | Meaning |
|---|---|---|
| `0` | **READY** | Zero blockers, zero warnings → installation may proceed |
| `1` | **WARNINGS** | No blockers, but something must be acknowledged explicitly |
| `2` | **BLOCKED** | A blocker exists → **installation refused, with no bypass** |
| `3` | INTERNAL | preflight itself could not run |

```
./preflight.sh              # the full gate, before installation
./preflight.sh --json       # for monitoring / orchestration
./preflight.sh --runtime    # a fast subset, called before every apply
./preflight.sh --no-probe   # skip the kernel capability probe
logwall doctor               # the same gate, at any time after installation
```

Sample output:

```
[COMPETING_CRON] Another blocking agent runs from cron:
                 */2 * * * * /root/scripts/auto_blocker.sh
    FIX: crontab -e   # comment out or delete this line, then re-run preflight
```

### B. BLOCKERS — installation stops, with no way past

| Group | IDs |
|---|---|
| Identity | `ROOT_REQUIRED` |
| Runtime | `PYTHON_MISSING` · `PYTHON_TOO_OLD` (< 3.6) · `PYTHON_STDLIB` · `PYTHON_BROKEN` |
| Firewall tooling | `IPTABLES_MISSING` · `IPSET_MISSING` |
| Kernel capability | `IPSET_NO_CAPABILITY` · `IPTABLES_NO_CAPABILITY` |
| **Other agents** | **`COMPETING_CRON` · `FOREIGN_IPSET` · `COMPETING_SERVICE` · `CSF_PRESENT`** |
| Anti-lockout | `NO_ADMIN_IP` |
| Configuration | `RESERVED_SET_NAME` |
| Scheduling | `CRON_MISSING` · `CRON_NOT_RUNNING` |
| Resources | `LOW_DISK` (< 500 MB) |
| Self-security | `WORLD_WRITABLE` |

**WARNINGS** (requiring `--accept-warnings` or interactive confirmation): `OS_UNKNOWN` ·
`INIT_UNKNOWN` · `IP6TABLES_MISSING` · `SS_MISSING` · `POLICY_DROP` · `THRESHOLD_TOO_LOW` ·
`ENFORCE_ON` · `NO_ACCESS_LOG` · `NO_TIME_SYNC` · `LOW_DISK_WARN` · `LEGACY_SCRIPT_PRESENT` ·
`IPV6_UNPROTECTED` · **`SINGLE_ADMIN_IP`** · `DDNS_UNRESOLVED`.

### B1. Admin Access Layers

A firewall locked the wrong way makes its own server unreachable, so these layers are treated as
requirements rather than advice.

| Layer | Status | Enforcement |
|---|---|---|
| **1. Primary IP whitelist** | **REQUIRED (>=1)** | The SSH session's address is bootstrapped automatically at installation. Zero paths → `NO_ADMIN_IP` **BLOCKER** |
| **2. A backup path** | **STRONGLY RECOMMENDED** | A second address (VPN, tethering, another ISP) or a DDNS hostname. Only one path → `SINGLE_ADMIN_IP` **WARNING** |
| **3. Provider console / VNC** | **THE SAFETY NET** | A program cannot detect it → shown as an **unverified checklist item**, never claimed as status |
| **4. DDNS** | **OPTIONAL** | For dynamic addresses (§15.2) |

**Loopback does not count as an access path.** The whitelist template contains `127.0.0.1` and
`::1`; counting them would mean the "only one path" warning could never appear on a fresh
installation — exactly the case that needs it most.

### B2. Interactive Confirmation

When preflight returns **WARNINGS** and they are not acknowledged through `--accept-warnings`:

- **A terminal is present** → `install.sh` asks `[y/N]`, defaulting to **no**.
- **No terminal** (a pipe, CI, `curl | bash`) → **refused**, not asked. A prompt without a TTY
  receives EOF immediately and "answers" on the operator's behalf, or swallows another process's
  stdin.

The prompt lives in `install.sh` and **never in `preflight.sh`**: preflight is also called from
cron (`--runtime`) and from `logwall doctor --json`, where a prompt would hang the cycle forever.
That is why preflight's contract is purely exit codes.

### C. Finding Another Blocker Means Stopping, Not Coexisting

Two agents writing the same ruleset is the hardest class of outage to diagnose, and whichever
runs last always wins. Detection happens along four paths:

1. **Cron** — jobs running another blocker's script (`auto_blocker.sh`, fail2ban, and so on).
   logwall's own jobs are tagged `# logwall-managed` so they are never mistaken for a competitor;
   unrelated jobs (backups, monitoring) are not tagged.
2. **Foreign ipsets** — a set referenced by a live DROP rule that does not belong to logwall.
   Reported **along with its entry count**, plus the command to secure its contents first
   (`ipset list <SET> > /root/<SET>.backup`) before the old tool is retired.
3. **Services** — an active `fail2ban`, `csf`, `lfd` or `firewalld`.
4. **Files** — `/etc/csf/csf.conf`, or first-generation scripts still sitting on disk.

logwall **never** shuts another tool down on its own, and **provides no automatic migration path**
for another tool's blocklist. Every host has its own history, dependencies and risk tolerance —
moving someone else's data is not this tool's decision to make. What logwall provides is a
concrete finding and the command to secure that data first; the admin decides what comes next.
Retire one, then install the other (§19).

### D. Kernel Capability Probing

The presence of the `ipset` binary does not prove the kernel permits it — a container without
`NET_ADMIN`, or a kernel without the `ip_set` module, still has the binary. So preflight
**creates and then immediately deletes** one test set and one test chain named
`LOGWALL_PREFLIGHT`.

A chain nothing references and an empty set change packet flow not at all. This is the only way
to get a definite answer rather than a guess. It can be skipped with `--no-probe`.

### E. Transactional Installation (5 stages)

| Stage | Contents | On failure |
|---|---|---|
| 1 **GATE** | Run `preflight.sh` | Refuse (exit 1/2) — **zero artefacts created** |
| 2 **ENV** | Detect distro/init/backend/panel, distro-specific prerequisites | Abort + rollback |
| 3 **INSTALL** | Directories, files, config merge, whitelist bootstrap, permissions | Abort + rollback |
| 4 **VERIFY** | Import the Python modules **from the installed location**, `bash -n` the CLI, run `logwall version`, check permissions, `preflight --runtime` | Abort + rollback |
| 5 **CRON** | Install cron **then verify the entries are genuinely registered** | Abort + rollback |

Every action that changes the system is recorded in a journal (`newdir`, `newfile`, `newtree`,
`symlink`, `cron`, `restoreconf`). A failure at any point plays that journal **backwards**, so
the host returns exactly to its pre-installation state. An existing `/etc/logwall.conf` is backed
up to `.preinstall` and restored on rollback; values the admin has already set are never
overwritten, only new keys are added.

Stage 4 exists because **an installation that cannot run is worse than none at all** — cron would
fail silently every 2 minutes while the admin believes they are protected.

**The transcript.** All installation output is written to `/var/log/logwall/install.log`. The
transcript is buffered in a temporary file first and only moved once the log directory exists, so
a refused installation still leaves no artefacts behind — while the operator is always told where
the transcript can be read. The closing summary shows the active whitelist, DDNS hostnames, SSH
port, enforcement status, log locations, and a pre-`ENFORCE=1` checklist marked
**not yet verified**.

### F. The Runtime Gate

`logwall firewall apply` runs `preflight.sh --runtime` first, on **every** cycle. Conditions can
appear long after installation: someone re-enables the old blocker, `ipset` is removed during an
update, the config is edited into a name collision. A blocker at the runtime gate means **that
cycle does not run at all** — zero rules changed, the reason recorded.

### G. Verifying the Gate Itself

`tests/gate_test.sh` runs preflight and the installer against stubbed commands (a fake crontab,
iptables, ipset) inside a temporary directory. It proves the gate refuses what it must, does not
flag unrelated jobs, and **creates no artefacts at all** when refusing — without touching the
firewall, cron, or any system path.

*Implementation note:* `trap ... ERR` stays armed even while `set +e` is in effect. Calls whose
non-zero exit is expected (preflight among them) must use the `cmd || RC=$?` form, which is
exempt from the ERR trap — getting this pattern wrong makes a clean refusal look like a crash.

---
*This document is alive: it is updated as production experience and discussion produce findings.*
