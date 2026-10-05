"""Glue: find logs -> parse -> run signatures + detectors -> ScanResult."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .detectors import Thresholds, run_detectors
from .findings import SEVERITIES, SEVERITY_RANK, Finding
from .parser import LogEntry, find_log_files, parse_file
from .signatures import DEFAULT_RULES_PATH, SignatureRule, load_rules, scan_signatures


@dataclass
class ScanResult:
    files: List[str]
    lines_scanned: int
    findings: List[Finding]
    rules_loaded: int
    started: datetime = field(default_factory=datetime.now)
    players_seen: int = 0
    ips_seen: int = 0

    def severity_counts(self) -> dict:
        counts = Counter(f.severity for f in self.findings)
        return {sev: counts.get(sev, 0) for sev in reversed(SEVERITIES)}

    def highest_severity(self) -> Optional[str]:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: f.rank).severity

    def top_offenders(self, limit: int = 5) -> List[tuple]:
        """Players/IPs with the most findings, weighted by severity."""
        scores: Counter = Counter()
        for f in self.findings:
            who = f.player or f.ip
            if who:
                scores[who] += 1 + f.rank
        return scores.most_common(limit)


def scan_entries(
    entries: List[LogEntry],
    rules_path: "str | Path | List[SignatureRule]" = DEFAULT_RULES_PATH,
    thresholds: Optional[Thresholds] = None,
    min_severity: str = "info",
) -> List[Finding]:
    rules = rules_path if isinstance(rules_path, list) else load_rules(rules_path)
    # Detectors need events in time order; sorted() is stable so line order is kept.
    entries = sorted(entries, key=lambda e: e.timestamp)
    findings = list(scan_signatures(entries, rules))
    findings += run_detectors(entries, thresholds)
    floor = SEVERITY_RANK[min_severity]
    findings = [f for f in findings if f.rank >= floor]
    findings.sort(key=lambda f: (-f.rank, f.timestamp, f.line_no))
    return findings


def scan_path(
    target: "str | Path",
    rules_path: "str | Path" = DEFAULT_RULES_PATH,
    thresholds: Optional[Thresholds] = None,
    min_severity: str = "info",
) -> ScanResult:
    files = find_log_files(target)
    entries: List[LogEntry] = []
    for path in files:
        entries.extend(parse_file(path))

    rules = load_rules(rules_path)
    findings = scan_entries(entries, rules, thresholds, min_severity)
    return ScanResult(
        files=[str(p) for p in files],
        lines_scanned=len(entries),
        findings=findings,
        rules_loaded=len(rules),
        players_seen=len({e.player for e in entries if e.player}),
        ips_seen=len({e.ip for e in entries if e.ip}),
    )
