#!/usr/bin/env python3
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: lib/py/audit_engine.py
# Purpose: Read-only audit engine. Turns sliding-window traffic counters into
#          block candidates, classifies the severity tier, and applies every
#          protection guard before an IP is ever proposed for blocking.
# Reference: docs/DESIGN.md §7 (audit), §12 (Escalation Ladder), §16 (Reliability)
# ==============================================================================

import ipaddress
import json
import os
import sys

from config_loader import get_bool, get_int, load_config
from ip_guard import IPGuard
from log_parser import LogParserEngine

# Detections that indicate unmistakable intent are blocked permanently.
# Volume-based detections use the TEMP -> PERMANENT ladder so that shared
# addresses (CGNAT, offices, campuses) are not punished forever for one burst.
TIER_PERMANENT = "PERMANENT"
TIER_TEMP = "TEMP"

# How a client behaves, inferred from whether it fetches the resources a browser
# would fetch on its own. Never a reason to block by itself — only a modifier.
PROFILE_BROWSER = "browser"
PROFILE_SCRIPT = "script"
PROFILE_UNKNOWN = "unknown"


class AuditEngine:
    def __init__(self, config=None):
        self.config = config if config is not None else load_config()
        self.parser = LogParserEngine(self.config)
        self.guard = IPGuard(self.config)
        self.parser.cdn_check = self.guard.is_cdn_edge_ip
        self.escalation = get_bool(self.config, "BLOCK_ESCALATION", True)
        self.refused = {}

    def evaluate_candidates(self, panel_type=None):
        panel_type = panel_type or os.environ.get("PANEL_TYPE", "none")

        logs = self.parser.discover_log_files(panel_type)
        auth_logs = self.parser.discover_auth_logs()
        metrics = self.parser.analyze_traffic(logs, auth_logs)

        candidates = {}

        def consider(ip, reason, tier):
            if ip in candidates:
                return
            candidates[ip] = {"reason": reason, "tier": tier}

        threshold_wp = get_int(self.config, "THRESHOLD_WP_LOGIN", 5)
        for ip, count in metrics["wp_login"].items():
            if count > threshold_wp:
                consider(ip, f"BruteForce | /wp-login.php | Hits: {count}x", TIER_PERMANENT)

        threshold_xmlrpc = get_int(self.config, "THRESHOLD_XMLRPC", 2)
        for ip, count in metrics["xmlrpc"].items():
            if count > threshold_xmlrpc:
                consider(ip, f"XmlRpcExploit | /xmlrpc.php | Hits: {count}x", TIER_PERMANENT)

        threshold_scan = get_int(self.config, "THRESHOLD_SENSITIVE_SCAN", 2)
        for ip, count in metrics["scan"].items():
            if count > threshold_scan:
                consider(ip, f"ReconScanner | SensitiveFile | Hits: {count}x", TIER_PERMANENT)

        # Failed service logins (SSH, IMAP/POP3, SMTP AUTH, FTP). Intent here is
        # unambiguous, so it lands on the permanent tier like the other
        # intent-based detections.
        threshold_auth = get_int(self.config, "LOGIN_FAIL_BLOCK", 5)
        for ip, count in metrics.get("auth_fail", {}).items():
            if count > threshold_auth:
                consider(ip, f"AuthBruteForce | failed service logins: {count}x",
                         TIER_PERMANENT)

        threshold_401 = get_int(self.config, "THRESHOLD_PANEL_401", 5)
        for ip, count in metrics["panel_401"].items():
            if count > threshold_401:
                consider(ip, f"PanelBruteForce | 401/403 | Hits: {count}x", TIER_PERMANENT)

        # A self-declared offensive tool. The name alone is the evidence: none of
        # ATTACK_UA_MARKERS has a legitimate use against somebody else's server.
        # Deliberately separate from the generic script list — curl, wget and
        # python-requests are honest API clients and blocking them would take out
        # the operator's own integrations.
        threshold_attack_ua = get_int(self.config, "THRESHOLD_ATTACK_UA", 1)
        for ip, count in metrics.get("attack_ua", {}).items():
            if count >= threshold_attack_ua:
                consider(ip, f"ToolSignature | offensive scanner UA | Hits: {count}x",
                         TIER_PERMANENT)

        # Intent that stayed under every individual threshold but is unmistakable
        # once added up. The /24 rollup has summed these four since 1.0; a single
        # address was judged more leniently than its own neighbours until now.
        threshold_intent_ip = get_int(self.config, "THRESHOLD_INTENT_IP", 8)
        for ip in metrics["hits"]:
            intent = (metrics["wp_login"].get(ip, 0)
                      + metrics["xmlrpc"].get(ip, 0)
                      + metrics["scan"].get(ip, 0)
                      + metrics["panel_401"].get(ip, 0))
            if intent > threshold_intent_ip:
                consider(ip, f"IntentComposite | brute force/recon: {intent}x",
                         TIER_PERMANENT)

        self._calibrate_client_profiling(metrics)

        # Path brute force. Directory scanners produce 404 by the thousand, and
        # until now only 401/403 was counted — so gobuster and feroxbuster, whose
        # names logwall already recognised, were invisible.
        #
        # The ratio condition is not optional. A site with a broken theme or a
        # missing favicon serves 404s to real visitors, and without the ratio
        # this rule would convict the victims of the operator's own bug.
        threshold_404 = get_int(self.config, "THRESHOLD_404", 30)
        ratio_404_min = float(self.config.get("RATIO_404_MIN", 0.60) or 0.60)
        for ip, count in metrics.get("panel_404", {}).items():
            hits = metrics["hits"].get(ip, 0)
            if count <= threshold_404 or hits <= 0 or self._volume_suspended():
                continue
            ratio = count / hits
            if ratio < ratio_404_min:
                continue
            profile, label = self._client_profile(ip, metrics)
            consider(ip, f"PathBruteForce | 404: {count}x of {hits} ({ratio:.0%}){label}",
                     self._volume_tier(count, threshold_404, profile))

        # Login attempts outside WordPress. Only POST counts — a GET of /login is
        # the form itself, and counting it would flag everyone who looked at it.
        threshold_login_post = get_int(self.config, "THRESHOLD_LOGIN_POST", 10)
        for ip, count in metrics.get("login_post", {}).items():
            if count <= threshold_login_post or self._volume_suspended():
                continue
            # A real user who forgot their password does post repeatedly. What
            # they do not do is collect rejections while doing it.
            rejected = metrics["panel_401"].get(ip, 0)
            tier = TIER_PERMANENT if rejected > 0 else self._volume_tier(
                count, threshold_login_post)
            consider(ip, f"GenericLoginBrute | login POST: {count}x"
                         f"{f' | rejected: {rejected}x' if rejected else ''}", tier)

        threshold_hits = get_int(self.config, "THRESHOLD_HITS", 40)
        for ip, count in metrics["hits"].items():
            profile, label = self._client_profile(ip, metrics)
            effective = self._effective_threshold(threshold_hits, profile)
            if count > effective and not self._volume_suspended():
                consider(ip, f"CloudScraper | WebApp | Hits: {count}x{label}",
                         self._volume_tier(count, threshold_hits, profile))

        threshold_bw = get_int(self.config, "THRESHOLD_BW_MB", 30) * 1024 * 1024
        for ip, total in metrics["bw"].items():
            profile, label = self._client_profile(ip, metrics)
            effective = self._effective_threshold(threshold_bw, profile)
            if total > effective and not self._volume_suspended():
                mb = total / 1024 / 1024
                hits = metrics["hits"].get(ip, 0)
                consider(ip, f"HighBandwidth | BW: {mb:.1f}MB | Hits: {hits}x{label}",
                         self._volume_tier(total, threshold_bw, profile))

        # Every guard runs here, once, for every candidate.
        allowed = {}
        for ip, meta in candidates.items():
            # IPv6 counters are keyed by /64 (IPV6_BLOCK_PREFIX), so those
            # candidates are ranges and must be judged by the range guard —
            # which checks OVERLAP, not membership. A /64 holding one whitelisted
            # address is refused whole, exactly as a /24 would be.
            if "/" in ip:
                refusal = self.guard.refusal_reason_network(
                    ip, get_int(self.config, "SUBNET_MAX_WIDTH_V4", 24),
                    get_int(self.config, "SUBNET_MAX_WIDTH_V6", 64))
            else:
                refusal = self.guard.refusal_reason(ip)
            if refusal:
                self.refused[ip] = refusal
                continue
            allowed[ip] = meta

        networks = self._evaluate_subnets()

        # A member address covered by a blocked range must not be listed twice.
        # This is what turns 500 separate candidates into 2 entries that say what
        # actually happened: one source, not five hundred.
        if networks:
            nets = []
            for cidr in networks:
                try:
                    nets.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    continue
            for ip in list(allowed):
                try:
                    member = ipaddress.ip_network(ip, strict=False)
                except ValueError:
                    continue
                if any(member.version == n.version and member.subnet_of(n)
                       for n in nets):
                    del allowed[ip]

            allowed.update(networks)

        return allowed

    def _volume_suspended(self):
        """
        True on a catch-up run, where every volume count is inflated by however
        much log the run happened to swallow.

        This replaces MAX_NEW_BLOCKS_PER_RUN, which counted the OUTCOME —
        candidates produced — and could never tell "many genuine offenders" from
        "the input was distorted". It capped both alike, and in the only two
        cases it ever fired, both were genuine.

        The suspension is deliberately narrow. Intent detections keep running:
        five probes for /.env are five probes whether they arrived over two
        minutes or two days, so a catch-up run still blocks brute force, recon,
        and self-declared scanners. Only counts that mean nothing without a
        known time span are held back, and only for this run.
        """
        return bool(getattr(self.parser, "catchup", False))

    def _volume_tier(self, value, threshold, profile=PROFILE_UNKNOWN):
        """
        Picks the tier for a volume-based detection.

        The temporary tier exists for AMBIGUITY: a shared address (CGNAT, an
        office, a campus) can cross a volume threshold once without being an
        attacker. Excess far beyond the threshold is not ambiguous, so it skips
        the grace round and lands permanently on the first sighting — and neither
        is a client that never once fetched a stylesheet.
        """
        if not self.escalation:
            return TIER_PERMANENT

        if profile == PROFILE_SCRIPT:
            return TIER_PERMANENT

        factor = get_int(self.config, "ESCALATE_IMMEDIATE_FACTOR", 10)
        if factor > 0 and threshold > 0 and value > threshold * factor:
            return TIER_PERMANENT
        return TIER_TEMP

    # ------------------------------------------------------- client profiling
    def _calibrate_client_profiling(self, metrics):
        """
        Learns what "normal" looks like on THIS site before judging any client.

        A browser fetches a page and then pulls its stylesheets, scripts, fonts
        and images by itself; a script fetches only what it wants. But on a site
        whose assets are served from a CDN or a separate domain, the origin log
        contains almost no asset requests at all — and then EVERY visitor looks
        like a script. So the signal is calibrated against the site's own
        baseline and switches itself off when that baseline is too low to mean
        anything.
        """
        self.profiling = get_bool(self.config, "CLIENT_PROFILING", True)
        self.profile_min_samples = get_int(self.config, "ASSET_MIN_SAMPLES", 30)
        self.ratio_script = float(self.config.get("ASSET_RATIO_SCRIPT", 0.20) or 0.20)
        self.ratio_browser = float(self.config.get("ASSET_RATIO_BROWSER", 0.50) or 0.50)
        self.browser_tolerance = get_int(self.config, "BROWSER_TOLERANCE_FACTOR", 3)

        total_pages = sum(metrics.get("pages", {}).values())
        total_assets = sum(metrics.get("assets", {}).values())
        total = total_pages + total_assets
        site_ratio = (total_assets / total) if total else 0.0

        minimum = float(self.config.get("SITE_ASSET_RATIO_MIN", 0.40) or 0.40)
        if self.profiling and site_ratio < minimum:
            self.profiling = False
            self.flags_extra = (
                f"[PROFILING_OFF] Site asset ratio {site_ratio:.0%} is below "
                f"{minimum:.0%}; assets are probably served elsewhere, so "
                f"browser-vs-script profiling is disabled for this run.")
        self.site_ratio = site_ratio

    def _client_profile(self, ip, metrics):
        """Returns (profile, label) where label is appended to the block reason."""
        if not getattr(self, "profiling", False):
            return PROFILE_UNKNOWN, ""

        pages = metrics.get("pages", {}).get(ip, 0)
        assets = metrics.get("assets", {}).get(ip, 0)
        total = pages + assets
        if total < self.profile_min_samples:
            return PROFILE_UNKNOWN, ""

        ratio = assets / total
        script_ua = metrics.get("script_ua", {}).get(ip, 0)

        # A self-declared tool corroborates, but never decides on its own.
        if ratio < self.ratio_script:
            marker = " | client: script"
            if script_ua:
                marker += " (self-declared)"
            return PROFILE_SCRIPT, f"{marker}, assets {ratio:.0%}"

        if ratio >= self.ratio_browser:
            return PROFILE_BROWSER, f" | client: browser, assets {ratio:.0%}"

        return PROFILE_UNKNOWN, f" | client: mixed, assets {ratio:.0%}"

    def _effective_threshold(self, threshold, profile):
        """
        A client that behaves like a browser has to try considerably harder
        before it is treated as abusive. This is what makes a low THRESHOLD_HITS
        safe: real visitors generate large request counts legitimately.
        """
        if profile == PROFILE_BROWSER and self.browser_tolerance > 1:
            return threshold * self.browser_tolerance
        return threshold

    def _evaluate_subnets(self):
        """
        Proposes whole ranges when a network behaves as one coordinated source.

        Requires SUBNET_MIN_IPS distinct active addresses before a range is even
        considered: without that, one heavy visitor on shared hosting would drag
        255 innocent neighbours down with them.
        """
        if not get_bool(self.config, "SUBNET_DETECTION", True):
            return {}

        min_members = get_int(self.config, "SUBNET_MIN_IPS", 5)
        prefix_v4 = get_int(self.config, "SUBNET_PREFIX_V4", 24)
        prefix_v6 = get_int(self.config, "SUBNET_PREFIX_V6", 64)
        max_width_v4 = get_int(self.config, "SUBNET_MAX_WIDTH_V4", 24)
        max_width_v6 = get_int(self.config, "SUBNET_MAX_WIDTH_V6", 64)

        threshold_hits = get_int(self.config, "THRESHOLD_SUBNET_HITS", 2000)
        threshold_bw = get_int(self.config, "THRESHOLD_SUBNET_BW_MB", 300) * 1024 * 1024
        threshold_auth = get_int(self.config, "THRESHOLD_SUBNET_AUTH", 20)
        threshold_intent = get_int(self.config, "THRESHOLD_SUBNET_INTENT", 20)

        proposed = {}

        for cidr, agg in self.parser.window.subnet_rollup(prefix_v4, prefix_v6).items():
            members = agg.get("members", 0)
            if members < min_members:
                continue

            reason = None
            tier = None

            intent = agg["wp"] + agg["xmlrpc"] + agg["scan"] + agg["p401"]
            if agg["auth"] > threshold_auth:
                reason = (f"SubnetAuthBruteForce | {members} hosts | "
                          f"failed logins: {agg['auth']}x")
                tier = TIER_PERMANENT
            elif intent > threshold_intent:
                reason = (f"SubnetCoordinatedAttack | {members} hosts | "
                          f"brute force/recon: {intent}x")
                tier = TIER_PERMANENT
            elif agg["bw"] > threshold_bw and not self._volume_suspended():
                mb = agg["bw"] / 1024 / 1024
                reason = (f"SubnetHighBandwidth | {members} hosts | "
                          f"BW: {mb:.1f}MB | Hits: {agg['hits']}x")
                tier = self._volume_tier(agg["bw"], threshold_bw)
            elif agg["hits"] > threshold_hits and not self._volume_suspended():
                total = agg["pages"] + agg["assets"]
                ratio = (agg["assets"] / total) if total else 0.0
                profile = PROFILE_UNKNOWN
                if getattr(self, "profiling", False) and total >= self.profile_min_samples:
                    profile = (PROFILE_SCRIPT if ratio < self.ratio_script
                               else PROFILE_BROWSER if ratio >= self.ratio_browser
                               else PROFILE_UNKNOWN)
                suffix = f" | assets {ratio:.0%}" if total else ""
                reason = (f"SubnetFlood | {members} hosts | "
                          f"Hits: {agg['hits']}x{suffix}")
                tier = self._volume_tier(agg["hits"], threshold_hits, profile)

            if reason is None:
                continue

            refusal = self.guard.refusal_reason_network(cidr, max_width_v4, max_width_v6)
            if refusal:
                self.refused[cidr] = refusal
                continue

            proposed[cidr] = {"reason": reason, "tier": tier}

        proposed.update(self._evaluate_wide_v6(proposed))
        return proposed

    def _evaluate_wide_v6(self, already_proposed):
        """
        Second-tier IPv6 rollup, for a source that uses one address per /64.

        /64 is IPv6's single-allocation unit: it is the analogue of ONE IPv4
        address, not of a /24. So when a crawler takes one address out of each of
        its /64s, the /64 rollup aggregates nothing — every network holds exactly
        one member, far below SUBNET_MIN_IPS, and the source arrives as dozens of
        separate candidates.

        Measured on a production host: 82 distinct addresses of the form
        2a03:2880:f800:XX::, ~3,000 hits each. At /64 that was 70 candidates and
        the circuit breaker aborted the run, blocking nothing. At /56 it is one.

        /56 rather than /48: /56 covered 100% of that case, and /48 would be 256x
        wider for no additional reach. The rule is to go no wider than the
        evidence requires — a /56 is 256 /64s, the same factor a /24 aggregates
        for IPv4, which keeps the two families symmetrical.
        """
        if not get_bool(self.config, "SUBNET6_WIDE_DETECTION", True):
            return {}

        prefix = get_int(self.config, "SUBNET6_WIDE_PREFIX", 56)
        min_members = get_int(self.config, "SUBNET6_WIDE_MIN_PREFIXES", 8)
        max_width = get_int(self.config, "SUBNET6_WIDE_MAX_WIDTH", 56)

        threshold_hits = get_int(self.config, "THRESHOLD_SUBNET_HITS", 2000)
        threshold_bw = get_int(self.config, "THRESHOLD_SUBNET_BW_MB", 300) * 1024 * 1024
        threshold_auth = get_int(self.config, "THRESHOLD_SUBNET_AUTH", 20)
        threshold_intent = get_int(self.config, "THRESHOLD_SUBNET_INTENT", 20)

        wide = {}

        for cidr, agg in self.parser.window.subnet_rollup(24, prefix).items():
            if ":" not in cidr:
                continue
            members = agg.get("members", 0)
            if members < min_members:
                continue

            intent = agg["wp"] + agg["xmlrpc"] + agg["scan"] + agg["p401"]
            if agg["auth"] > threshold_auth:
                reason = (f"Subnet6AuthBruteForce | {members} /64s | "
                          f"failed logins: {agg['auth']}x")
                tier = TIER_PERMANENT
            elif intent > threshold_intent:
                reason = (f"Subnet6CoordinatedAttack | {members} /64s | "
                          f"brute force/recon: {intent}x")
                tier = TIER_PERMANENT
            elif self._volume_suspended():
                continue
            elif agg["bw"] > threshold_bw:
                # The /24 tier has had a bandwidth rule since 1.0; this tier did
                # not, so an IPv6 source draining bandwidth across many /64s was
                # caught at no level at all.
                mb = agg["bw"] / 1024 / 1024
                reason = (f"Subnet6HighBandwidth | {members} /64s | "
                          f"BW: {mb:.1f}MB | Hits: {agg['hits']}x")
                tier = self._volume_tier(agg["bw"], threshold_bw)
            elif agg["hits"] > threshold_hits:
                reason = f"Subnet6Flood | {members} /64s | Hits: {agg['hits']}x"
                tier = self._volume_tier(agg["hits"], threshold_hits)
            else:
                continue

            refusal = self.guard.refusal_reason_network(cidr, 24, max_width)
            if refusal:
                self.refused[cidr] = refusal
                continue

            wide[cidr] = {"reason": reason, "tier": tier}

        # A /64 already covered by an accepted /56 is noise: one entry, not
        # eighty. Same rule the /24 rollup applies to its own members.
        if wide:
            nets = [ipaddress.ip_network(c) for c in wide]
            for cidr in list(already_proposed):
                if ":" not in cidr:
                    continue
                try:
                    net = ipaddress.ip_network(cidr)
                except ValueError:
                    continue
                if any(net.subnet_of(parent) for parent in nets):
                    already_proposed.pop(cidr, None)

        return wide

    def health_flags(self):
        flags = dict(self.parser.flags)
        flags["GUARD_STATS"] = dict(self.guard.stats)
        if getattr(self, "flags_extra", None):
            flags["PROFILING_OFF"] = self.flags_extra
        if getattr(self.parser, "catchup", False):
            # Stated out loud on every channel. The circuit breaker this
            # replaced announced itself only on stderr, which cron discards, and
            # no report ever mentioned it — so a host could refuse to block
            # anything for hours and look perfectly healthy.
            flags["CATCHUP_RUN"] = (
                "Volume rules suspended for this run: {}. Intent detections "
                "(brute force, recon, scanner signatures) still applied."
                .format(self.parser.catchup_reason))
        return flags

    def commit_state(self):
        """Persists cursors + window counters. Only called once a run succeeds."""
        self.parser.save_state()


def main():
    as_json = "--json" in sys.argv
    engine = AuditEngine()
    candidates = engine.evaluate_candidates()
    flags = engine.health_flags()

    # Audit is read-only with respect to the firewall, but the traffic window has
    # to advance or the same log bytes would be counted again on the next run.
    engine.commit_state()

    if as_json:
        print(json.dumps({
            "candidates": candidates,
            "refused": engine.refused,
            "flags": flags,
        }, indent=2))
    else:
        for ip, meta in candidates.items():
            print(f"{ip}\t{meta['tier']}\t{meta['reason']}")

        if engine.refused:
            print(f"[GUARD] {len(engine.refused)} candidate(s) refused by protection rules.",
                  file=sys.stderr)
        for reason, count in sorted(flags.get("GUARD_STATS", {}).items()):
            print(f"[GUARD]   {reason}: {count}", file=sys.stderr)
        if flags.get("PARSE_FAIL"):
            print(f"[PARSE_FAIL] Unrecognised log format: {', '.join(flags['PARSE_FAIL'])}",
                  file=sys.stderr)
        if flags.get("CDN_NO_REALIP"):
            print(f"[CDN_NO_REALIP] Real client IP unavailable, audit only: "
                  f"{', '.join(flags['CDN_NO_REALIP'])}", file=sys.stderr)
        if flags.get("LOG_NOT_FOUND"):
            print("[LOG_NOT_FOUND] No access log discovered — detection is inactive.",
                  file=sys.stderr)
        if flags.get("PROFILING_OFF"):
            print(flags["PROFILING_OFF"], file=sys.stderr)
        if flags.get("CATCHUP_RUN"):
            print(f"[CATCHUP_RUN] {flags['CATCHUP_RUN']}", file=sys.stderr)

    # Exit 1 means "findings present", not failure (docs/DESIGN.md §18).
    return 1 if candidates else 0


if __name__ == "__main__":
    sys.exit(main())
