#signature/pattern based detection
#this is the part of the scanner that catches visible attacks in a single line
#file works with signatures.json

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, List, Optional

from .findings import SEVERITIES, Finding
from .parser import LogEntry

DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "signatures.json"

REQUIRED_KEYS = ("id", "name", "severity", "pattern")
VALID_FIELDS = ("message", "content", "raw", "player")


class RuleError(ValueError):
    """Raised when a rule file is malformed."""


@dataclass
class SignatureRule:
    id: str
    name: str
    severity: str
    pattern: re.Pattern
    category: str = "General"
    description: str = ""
    event: Optional[str] = None  # only match entries of this event type
    fields: List[str] = field(default_factory=lambda: ["message"])
    references: List[str] = field(default_factory=list)
    recommendation: str = ""

    def match(self, entry: LogEntry) -> Optional[str]:
        """Return the text that matched, or None."""
        if self.event and entry.event != self.event:
            return None
        for name in self.fields:
            value = getattr(entry, name, None)
            if value and self.pattern.search(value):
                return value
        return None


def _build_rule(data: dict, index: int) -> SignatureRule:
    missing = [k for k in REQUIRED_KEYS if k not in data]
    if missing:
        raise RuleError(f"rule #{index} is missing {', '.join(missing)}")
    if data["severity"] not in SEVERITIES:
        raise RuleError(f"rule {data['id']}: unknown severity {data['severity']!r}")
    fields = data.get("fields", ["message"])
    bad = [f for f in fields if f not in VALID_FIELDS]
    if bad:
        raise RuleError(f"rule {data['id']}: unknown field(s) {bad}")
    try:
        pattern = re.compile(data["pattern"], re.IGNORECASE)
    except re.error as exc:
        raise RuleError(f"rule {data['id']}: invalid regex: {exc}") from exc

    return SignatureRule(
        id=data["id"],
        name=data["name"],
        severity=data["severity"],
        pattern=pattern,
        category=data.get("category", "General"),
        description=data.get("description", ""),
        event=data.get("event"),
        fields=fields,
        references=data.get("references", []),
        recommendation=data.get("recommendation", ""),
    )


def load_rules(path: "str | Path" = DEFAULT_RULES_PATH) -> List[SignatureRule]:
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    if not isinstance(raw, list):
        raise RuleError("rule file must contain a JSON list of rules")
    rules = [_build_rule(item, i) for i, item in enumerate(raw)]
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise RuleError(f"duplicate rule id(s): {', '.join(sorted(dupes))}")
    return rules


def scan_signatures(entries: Iterable[LogEntry], rules: List[SignatureRule]) -> Iterator[Finding]:
    for entry in entries:
        for rule in rules:
            matched = rule.match(entry)
            if matched is None:
                continue
            yield Finding(
                rule_id=rule.id,
                name=rule.name,
                severity=rule.severity,
                category=rule.category,
                description=rule.description,
                timestamp=entry.timestamp,
                source=entry.source,
                line_no=entry.line_no,
                evidence=entry.raw,
                player=entry.player,
                ip=entry.ip,
                recommendation=rule.recommendation,
                references=list(rule.references),
            )
