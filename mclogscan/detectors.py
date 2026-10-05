"""Behavioural (stateful) detectors.

Signature rules look at one line at a time. These detectors look at patterns
*across* lines within a sliding time window, e.g. many failed logins from one
IP in a minute (brute force) or many new accounts from one IP (bot attack).
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta
from typing import Deque, Dict, Iterable, List, Optional, Set

from .findings import Finding
from .parser import LogEntry


@dataclass
class Thresholds:
    brute_force_attempts: int = 5
    brute_force_window: int = 60  # seconds
    flood_joins: int = 10
    flood_window: int = 30
    accounts_per_ip: int = 4  # distinct usernames from one IP in a whole log
    spam_messages: int = 8
    spam_window: int = 10
    spam_repeats: int = 5  # identical messages in a row


AUTH_FAILURE_RE = re.compile(
    r"wrong password|incorrect password|failed login|login failed|"
    r"Failed to verify username|You are not whitelisted|You are banned",
    re.IGNORECASE,
)
# Auth plugins such as AuthMe log "[AuthMe] Steve used the wrong password"
AUTH_PLUGIN_NAME_RE = re.compile(r"^\[\w+\] (?:Player )?([A-Za-z0-9_]{1,16}) ")


class Detector:
    """Base class: feed entries in order, then collect findings."""

    def __init__(self, thresholds: Thresholds):
        self.t = thresholds
        self.findings: List[Finding] = []

    def feed(self, entry: LogEntry) -> None:
        raise NotImplementedError

    def finish(self) -> None:
        """Called after the last entry, for detectors that summarise at the end."""


class _WindowCounter:
    """Keeps the timestamps of recent events per key, dropping old ones."""

    def __init__(self, window_seconds: int):
        self.window = timedelta(seconds=window_seconds)
        self.events: Dict[str, Deque[LogEntry]] = defaultdict(deque)

    def add(self, key: str, entry: LogEntry) -> int:
        q = self.events[key]
        q.append(entry)
        while q and entry.timestamp - q[0].timestamp > self.window:
            q.popleft()
        return len(q)

    def reset(self, key: str) -> None:
        self.events[key].clear()


class BruteForceDetector(Detector):
    """Many authentication failures from one IP (or against one player)."""

    def __init__(self, thresholds: Thresholds):
        super().__init__(thresholds)
        self.counter = _WindowCounter(thresholds.brute_force_window)

    def feed(self, entry: LogEntry) -> None:
        if not AUTH_FAILURE_RE.search(entry.message):
            return
        if entry.player is None:
            m = AUTH_PLUGIN_NAME_RE.match(entry.message)
            if m:
                entry.player = m.group(1)
        key = entry.ip or entry.player
        if not key:
            return
        count = self.counter.add(key, entry)
        if count >= self.t.brute_force_attempts:
            self.findings.append(
                Finding(
                    rule_id="MC-BEHAV-BRUTE",
                    name="Brute-force login attempt",
                    severity="high",
                    category="Credential Access",
                    description=(
                        f"{count} authentication failures from {key} within "
                        f"{self.t.brute_force_window}s."
                    ),
                    timestamp=entry.timestamp,
                    source=entry.source,
                    line_no=entry.line_no,
                    evidence=entry.raw,
                    player=entry.player,
                    ip=entry.ip,
                    recommendation=(
                        "Block the IP at the firewall, enable login rate limiting "
                        "(e.g. AuthMe max login attempts) and require strong passwords."
                    ),
                    references=["MITRE ATT&CK T1110 Brute Force"],
                )
            )
            # Report once per burst rather than once per extra failure.
            self.counter.reset(key)


class ConnectionFloodDetector(Detector):
    """Bot attacks: a burst of joins from one IP, or one IP using many accounts."""

    def __init__(self, thresholds: Thresholds):
        super().__init__(thresholds)
        self.counter = _WindowCounter(thresholds.flood_window)
        self.names_by_ip: Dict[str, Set[str]] = defaultdict(set)
        self.first_seen: Dict[str, LogEntry] = {}

    def feed(self, entry: LogEntry) -> None:
        if entry.event != "join" or not entry.ip:
            return
        self.names_by_ip[entry.ip].add(entry.player or "?")
        self.first_seen.setdefault(entry.ip, entry)

        count = self.counter.add(entry.ip, entry)
        if count >= self.t.flood_joins:
            self.findings.append(
                Finding(
                    rule_id="MC-BEHAV-FLOOD",
                    name="Connection flood / bot attack",
                    severity="high",
                    category="Denial of Service",
                    description=(
                        f"{count} logins from {entry.ip} within {self.t.flood_window}s. "
                        "Bot attacks fill the server with fake players to crash it or spam chat."
                    ),
                    timestamp=entry.timestamp,
                    source=entry.source,
                    line_no=entry.line_no,
                    evidence=entry.raw,
                    player=entry.player,
                    ip=entry.ip,
                    recommendation=(
                        "Rate-limit connections per IP (e.g. connection-throttle in bukkit.yml, "
                        "or an anti-bot plugin) and block the IP."
                    ),
                    references=["MITRE ATT&CK T1498 Network Denial of Service"],
                )
            )
            self.counter.reset(entry.ip)

    def finish(self) -> None:
        for ip, names in self.names_by_ip.items():
            if len(names) < self.t.accounts_per_ip:
                continue
            entry = self.first_seen[ip]
            self.findings.append(
                Finding(
                    rule_id="MC-BEHAV-ALTS",
                    name="Many accounts from one IP",
                    severity="medium",
                    category="Defense Evasion",
                    description=(
                        f"{len(names)} different usernames joined from {ip}: "
                        f"{', '.join(sorted(names))}. This suggests alt accounts or ban evasion."
                    ),
                    timestamp=entry.timestamp,
                    source=entry.source,
                    line_no=entry.line_no,
                    evidence=entry.raw,
                    ip=ip,
                    recommendation="Check whether any of these accounts were previously banned; consider IP bans.",
                    references=["MITRE ATT&CK T1078 Valid Accounts"],
                )
            )


class ChatSpamDetector(Detector):
    """Chat flooding: too many messages too quickly, or the same message repeated."""

    def __init__(self, thresholds: Thresholds):
        super().__init__(thresholds)
        self.counter = _WindowCounter(thresholds.spam_window)
        self.last_message: Dict[str, str] = {}
        self.repeat_count: Dict[str, int] = defaultdict(int)

    def _report(self, entry: LogEntry, description: str) -> None:
        self.findings.append(
            Finding(
                rule_id="MC-BEHAV-SPAM",
                name="Chat spam / flood",
                severity="low",
                category="Impact",
                description=description,
                timestamp=entry.timestamp,
                source=entry.source,
                line_no=entry.line_no,
                evidence=entry.raw,
                player=entry.player,
                ip=entry.ip,
                recommendation="Mute the player and consider an anti-spam plugin.",
                references=[],
            )
        )

    def feed(self, entry: LogEntry) -> None:
        if entry.event != "chat" or not entry.player:
            return
        player = entry.player
        text = (entry.content or "").strip().lower()

        if text == self.last_message.get(player):
            self.repeat_count[player] += 1
        else:
            self.last_message[player] = text
            self.repeat_count[player] = 1
        if self.repeat_count[player] == self.t.spam_repeats:
            self._report(entry, f"{player} sent the same message {self.t.spam_repeats} times in a row.")

        count = self.counter.add(player, entry)
        if count >= self.t.spam_messages:
            self._report(entry, f"{player} sent {count} messages within {self.t.spam_window}s.")
            self.counter.reset(player)


def run_detectors(entries: Iterable[LogEntry], thresholds: Optional[Thresholds] = None) -> List[Finding]:
    thresholds = thresholds or Thresholds()
    detectors: List[Detector] = [
        BruteForceDetector(thresholds),
        ConnectionFloodDetector(thresholds),
        ChatSpamDetector(thresholds),
    ]
    for entry in entries:
        for detector in detectors:
            detector.feed(entry)
    findings: List[Finding] = []
    for detector in detectors:
        detector.finish()
        findings.extend(detector.findings)
    return findings
