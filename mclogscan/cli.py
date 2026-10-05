"""Command-line interface: python -m mclogscan <log file or folder>"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .findings import SEVERITIES, SEVERITY_RANK
from .report import RENDERERS
from .scanner import scan_path
from .signatures import DEFAULT_RULES_PATH, RuleError

EXIT_OK, EXIT_ERROR, EXIT_FINDINGS = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mclogscan",
        description="Scan Minecraft server logs for attacks and suspicious activity.",
        epilog="Exit codes: 0 = clean, 1 = error, 2 = findings at or above --fail-on.",
    )
    p.add_argument("target", help="a log file (.log / .log.gz) or a server's logs/ folder")
    p.add_argument("-f", "--format", choices=sorted(RENDERERS), default="text", help="report format (default: text)")
    p.add_argument("-o", "--output", help="write the report to this file instead of stdout")
    p.add_argument("-r", "--rules", default=str(DEFAULT_RULES_PATH), help="path to a signature rules JSON file")
    p.add_argument("--min-severity", choices=SEVERITIES, default="info", help="hide findings below this severity")
    p.add_argument("--fail-on", choices=SEVERITIES, default="high", help="exit with code 2 if any finding is at least this severe")
    p.add_argument("--no-colour", "--no-color", dest="colour", action="store_false", help="disable coloured output")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = scan_path(args.target, rules_path=args.rules, min_severity=args.min_severity)
    except (FileNotFoundError, RuleError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.format == "text":
        colour = args.colour and args.output is None and sys.stdout.isatty()
        report = RENDERERS["text"](result, colour=colour)
    else:
        report = RENDERERS[args.format](result)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"Report written to {args.output} ({len(result.findings)} findings)")
    else:
        print(report)

    worst = result.highest_severity()
    if worst and SEVERITY_RANK[worst] >= SEVERITY_RANK[args.fail_on]:
        return EXIT_FINDINGS
    return EXIT_OK
