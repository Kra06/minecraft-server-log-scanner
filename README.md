# Minecraft server logs security scanner

[![tests](https://github.com/Kra06/minecraft-server-log-scanner/actions/workflows/tests.yml/badge.svg)](https://github.com/Kra06/minecraft-server-log-scanner/actions/workflows/tests.yml)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

This tool is for Minecraft servers, and detects intruders or malicious actors based off logs on public servers. This was created because public servers let anyone connect, which makes them a common target for common exploits including Log4Shell, bot floods, brute force logins, backdoored plugins and crash exploits. The tool
reads a server's logs to detect these attacks and produces a prioritised incident
report with evidence and potential fixes.


## Features

- **Two detection engines**
  - **Signature-based**: 14 regex rules in an editable JSON rule pack (like Snort/Sigma rules)
  - **Behavioural**: sliding-window detectors for brute force, bot floods, alt accounts and chat spam (like fail2ban)
- **Parses Vanilla, Spigot, Paper and Forge** log formats, including rotated `.log.gz` files and whole `logs/` folders
- **Reports in text, JSON (for SIEM ingestion) or HTML**
- **CI/cron friendly exit codes**: `0` clean, `1` error, `2` threats found
- **Safe on hostile input**: logs contain attacker-controlled text, so the HTML report escapes everything (no XSS), terminal output neutralises ANSI escape injection, and malformed bytes never crash the parser
- **No dependencies**: standard library only

## What it detects

- Log4Shell exploit attempts, including disguised versions
- Players gaining operator powers or switching off server protections
- Backdoored plugins and shell command injection
- Crash exploits and malformed packets
- Brute-force logins, bot floods and alt accounts used to dodge bans
- Phishing links, chat spam, griefing commands, cheating and log tampering

Findings are linked to CVE and MITRE ATT&CK references where relevant.

## Installation

```bash
git clone https://github.com/Kra06/minecraft-server-log-scanner.git
cd minecraft-server-log-scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
mclogscan samples/attack-2026-09-20.log               # coloured text report
mclogscan /path/to/server/logs/                       # scan every log in a folder
mclogscan logs/ -f html -o report.html                # HTML report
mclogscan logs/ -f json -o report.json                # JSON for other tools / SIEM
mclogscan logs/ --min-severity medium                 # hide low/info findings
mclogscan logs/ --fail-on critical                    # exit 2 only for critical findings
mclogscan logs/ --rules my-rules.json                 # use a custom rule pack
python -m mclogscan ...                               # works without installing
```

## How it works

1. **Read**: `parser.py` reads each log line and picks out the time, player, IP address and what happened.
2. **Detect**: two engines check the lines.
   - `signatures.py` matches each line against known attack patterns stored in `rules/signatures.json`.
   - `detectors.py` looks for suspicious behaviour across many lines, such as repeated failed logins.
3. **Combine**: `scanner.py` merges the results, ranks them by severity and gives each player a risk score.
4. **Report**: `report.py` writes the report as text, JSON or HTML. `cli.py` is the command you run.

## Writing your own rules

Add an object to `rules/signatures.json` (or your own file passed with `--rules`):

```json
{
  "id": "CUSTOM-001",
  "name": "Advertising another server",
  "severity": "low",
  "category": "Spam",
  "description": "Player is advertising a server address.",
  "pattern": "\\b(?:play|mc)\\.[a-z0-9-]+\\.(?:net|com|org)\\b",
  "event": "chat",
  "fields": ["content"],
  "references": [],
  "recommendation": "Mute the player."
}
```

- `pattern`: a case-insensitive Python regex
- `event` (optional): only match `join`, `leave`, `chat`, `command`, `disconnect`, `other` or `raw` lines
- `fields`: which part of the entry to search: `message` (whole message), `content` (chat/command text only), `raw` (full line) or `player`

Rule files are validated on load, so a bad regex, unknown severity or duplicate ID gives a clear error instead of silently not detecting anything.

## Testing

```bash
pytest -v
```

85 tests cover the parser (all formats, gzip, invalid bytes, rollover), **a true-positive and false-positive test for every rule**, the behavioural thresholds, XSS and escape-injection resistance of the reports, and CLI exit codes. A test fails if any rule is added without a matching positive test.

## Limitations and future work

- Signature detection only catches known patterns; novel attacks need new rules.
- Vanilla logs don't record the IP on every line, so some findings are attributed to a player only.
- Ideas: live monitoring (`tail -f` mode), GeoIP lookups on offending IPs, Discord webhook alerts, exporting rules to Sigma format, detecting suspicious plugin jars.
