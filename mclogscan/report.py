"""Render a ScanResult as text, JSON or HTML."""

from __future__ import annotations

import html
import json
import re

from . import __version__
from .scanner import ScanResult

COLOURS = {
    "critical": "\033[1;97;41m",
    "high": "\033[1;31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[37m",
}
RESET = "\033[0m"

# Log lines are attacker-controlled, so strip control characters (including
# ANSI escapes) before printing them to a terminal.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _safe(text: str) -> str:
    return _CONTROL_RE.sub(lambda m: f"\\x{ord(m.group()):02x}", text)


def render_text(result: ScanResult, colour: bool = False) -> str:
    def c(sev: str, text: str) -> str:
        return f"{COLOURS[sev]}{text}{RESET}" if colour else text

    out = []
    out.append("=" * 70)
    out.append(f" Minecraft Log Security Scan  (mclogscan {__version__})")
    out.append("=" * 70)
    out.append(f" Files scanned : {len(result.files)}")
    out.append(f" Lines scanned : {result.lines_scanned}")
    out.append(f" Rules loaded  : {result.rules_loaded} signatures + 3 behavioural detectors")
    out.append(f" Players / IPs : {result.players_seen} / {result.ips_seen}")
    out.append(f" Findings      : {len(result.findings)}")
    counts = "  ".join(c(sev, f"{sev.upper()}: {n}") for sev, n in result.severity_counts().items() if n)
    if counts:
        out.append(f"                 {counts}")
    out.append("")

    if not result.findings:
        out.append(" No suspicious activity found.")
        return "\n".join(out)

    offenders = result.top_offenders()
    if offenders:
        out.append(" Top offenders:")
        for who, score in offenders:
            out.append(f"   {_safe(who):<20} risk score {score}")
        out.append("")

    for f in result.findings:
        out.append("-" * 70)
        out.append(f" {c(f.severity, f'[{f.severity.upper()}]')} {f.rule_id}  {f.name}")
        out.append(f"   When     : {f.timestamp:%Y-%m-%d %H:%M:%S}   ({f.source}:{f.line_no})")
        who = ", ".join(x for x in (f.player and f"player {f.player}", f.ip and f"IP {f.ip}") if x)
        if who:
            out.append(f"   Who      : {_safe(who)}")
        out.append(f"   Category : {f.category}")
        out.append(f"   Evidence : {_safe(f.evidence)}")
        out.append(f"   Details  : {f.description}")
        if f.recommendation:
            out.append(f"   Fix      : {f.recommendation}")
        if f.references:
            out.append(f"   Refs     : {'; '.join(f.references)}")
    out.append("-" * 70)
    return "\n".join(out)


def render_json(result: ScanResult) -> str:
    return json.dumps(
        {
            "tool": "mclogscan",
            "version": __version__,
            "scanned_at": result.started.isoformat(timespec="seconds"),
            "summary": {
                "files": result.files,
                "lines_scanned": result.lines_scanned,
                "rules_loaded": result.rules_loaded,
                "players_seen": result.players_seen,
                "ips_seen": result.ips_seen,
                "total_findings": len(result.findings),
                "by_severity": result.severity_counts(),
                "highest_severity": result.highest_severity(),
                "top_offenders": [{"name": n, "score": s} for n, s in result.top_offenders()],
            },
            "findings": [f.to_dict() for f in result.findings],
        },
        indent=2,
    )


_HTML_STYLE = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1d2330;--muted:#5d6675;--line:#e1e4ea;
--critical:#b3261e;--high:#d9480f;--medium:#b7791f;--low:#1c7ed6;--info:#6b7280}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1b1f27;--text:#e6e8ec;
--muted:#9aa3b2;--line:#2c323d}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1000px;margin:auto;padding:32px 16px}h1{margin:0 0 4px;font-size:1.6rem}
.muted{color:var(--muted)}.tiles{display:flex;flex-wrap:wrap;gap:12px;margin:24px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:120px}
.tile b{display:block;font-size:1.5rem}.tile.sev b{color:var(--c)}
.finding{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--c);
border-radius:10px;padding:14px 18px;margin:12px 0}
.badge{display:inline-block;background:var(--c);color:#fff;border-radius:5px;padding:1px 8px;
font-size:.75rem;font-weight:700;letter-spacing:.04em;margin-right:8px}
.finding h3{margin:0 0 6px;font-size:1.05rem}code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.85rem}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px 10px;
overflow-x:auto;white-space:pre-wrap;word-break:break-all;margin:8px 0}
dl{display:grid;grid-template-columns:max-content 1fr;gap:2px 14px;margin:6px 0 0}dt{color:var(--muted)}dd{margin:0}
table{border-collapse:collapse}td{padding:2px 14px 2px 0}
"""


def render_html(result: ScanResult) -> str:
    e = html.escape  # every attacker-controlled string goes through this (prevents XSS)
    tiles = [
        f'<div class="tile"><b>{result.lines_scanned}</b><span class="muted">lines scanned</span></div>',
        f'<div class="tile"><b>{len(result.findings)}</b><span class="muted">findings</span></div>',
    ]
    for sev, n in result.severity_counts().items():
        tiles.append(
            f'<div class="tile sev" style="--c:var(--{sev})"><b>{n}</b>'
            f'<span class="muted">{sev}</span></div>'
        )

    offenders = "".join(
        f"<tr><td><code>{e(who)}</code></td><td>risk score {score}</td></tr>"
        for who, score in result.top_offenders()
    )

    cards = []
    for f in result.findings:
        refs = "; ".join(e(r) for r in f.references)
        rows = [("When", f"{f.timestamp:%Y-%m-%d %H:%M:%S}"), ("Location", f"{e(f.source)}:{f.line_no}")]
        if f.player:
            rows.append(("Player", f"<code>{e(f.player)}</code>"))
        if f.ip:
            rows.append(("IP", f"<code>{e(f.ip)}</code>"))
        rows.append(("Category", e(f.category)))
        if f.recommendation:
            rows.append(("Fix", e(f.recommendation)))
        if refs:
            rows.append(("References", refs))
        dl = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows)
        cards.append(
            f'<section class="finding" style="--c:var(--{f.severity})">'
            f'<h3><span class="badge">{f.severity.upper()}</span>{e(f.name)} '
            f'<span class="muted">{e(f.rule_id)}</span></h3>'
            f"<div>{e(f.description)}</div><pre>{e(_safe(f.evidence))}</pre><dl>{dl}</dl></section>"
        )

    body = "".join(cards) or "<p>No suspicious activity found.</p>"
    files = "".join(f"<li><code>{e(p)}</code></li>" for p in result.files)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Minecraft Log Security Report</title><style>{_HTML_STYLE}</style></head>
<body><main>
<h1>Minecraft Log Security Report</h1>
<div class="muted">Generated {result.started:%Y-%m-%d %H:%M} by mclogscan {__version__} &middot;
{result.rules_loaded} signatures + 3 behavioural detectors &middot;
{result.players_seen} players, {result.ips_seen} IPs</div>
<div class="tiles">{''.join(tiles)}</div>
{'<h2>Top offenders</h2><table>' + offenders + '</table>' if offenders else ''}
<h2>Findings</h2>{body}
<h2>Files scanned</h2><ul>{files}</ul>
</main></body></html>
"""


RENDERERS = {"text": render_text, "json": render_json, "html": render_html}
