# Minecraft server logs security scanner


This tool is for Minecraft servers, and detects intruders or malicious actors based off logs on public servers. This was created because public servers let anyone connect, which makes them a common target for common exploits including Log4Shell, bot floods, brute force logins, backdoored plugins and crash exploits. The tool
reads a server's logs to detect these attacks and produces a prioritised incident
report with evidence and potential fixes.


## features

- There are two attack detection engines
  - One is signature based. There are 14 regex rules in an editable JSON rule pack
  - One is behavioural based. There are sliding window detectors for brute force, bot floods, alt accounts and chat spam
- It parses different minecraft log formats including Vanilla, Spigot, Paper and Forge, also rotated `.log.gz` files and whole `logs/` folders
- Reports outcomes in text, JSON or HTML
- exit codes: `0` clean, `1` error, `2` threats found
- Safe on hostile inputs. logs contain attacker controlled text, so the HTML report escapes everything (no XSS), terminal output neutralises ANSI escape injection, and malformed bytes do not crash the parser
- No dependencies

## What it detects

- Log4Shell exploit attempts, including disguised versions
- Players gaining operator powers or switching off server protections
- Backdoored plugins and shell command injection
- Crash exploits and malformed packets
- Brute-force logins, bot floods and alt accounts used to dodge bans
- Phishing links, chat spam, griefing commands, cheating and log tampering

Findings are linked to CVE and MITRE ATT&CK references where relevant.

## How to install

```bash
git clone https://github.com/Kra06/minecraft-server-log-scanner.git
cd minecraft-server-log-scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## How to use

```bash
mclogscan samples/attack-2026-09-20.log               #produce coloured text report
mclogscan /path/to/server/logs/                       #scan every log in a folder
mclogscan logs/ -f html -o report.html                #produce HTML report
mclogscan logs/ -f json -o report.json                #produce JSON for other tools / SIEM
mclogscan logs/ --min-severity medium                 #hide low/info findings
mclogscan logs/ --fail-on critical                    #exit 2 only for critical findings
mclogscan logs/ --rules my-rules.json                 #use a custom rule pack
python -m mclogscan ...                               #how to use without installing
```

## How it works

1. `parser.py` reads each log line and picks out the time, player, IP address and what happened
2. DETECT: two engines check the lines
  `signatures.py` matches each line against known attack patterns in `rules/signatures.json`.
  `detectors.py` looks for suspicious behaviour across multiple lines eg repeated failed logins
3. `scanner.py` merges the results, ranks them by severity and gives each player a risk score
4. `report.py` writes the report as text, JSON or HTML. `cli.py` is the command run.

## How to write custom rules

Add an object to `rules/signatures.json` or your own file passed with `--rules`

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

- `pattern` is a case insensitive python regex
- `event` which is optional only matches `join`, `leave`, `chat`, `command`, `disconnect`, `other` or `raw` lines
- `fields` are which part of the entry to search: `message` for the whole message, `content` for chat or command text only, `raw` for the full line or `player`

Rule files are validated on load, so a bad regex, unknown severity or duplicate ID gives a clear error instead of not detecting anything and not notifying the user

## Testing

```bash
pytest -v
```

85 tests cover the parser
there is a 'true positive' test for every rule, 'false positive' tests on harmless lines, the behavioural thresholds, XSS and escape injection resistance of the reports, and exit codes. A test fails if any rule is added without a matching positive test.

## Limitations and future additions

- Signature detection only catches known patterns meaning new attacks need new rules
- Vanilla logs don't record the IP on every line so some findings are attributed to a player only.
- Would be more useful with live monitoring so you can be notified of attackers in real time on the server
- GeoIP lookups on offending IPs
- detecting suspicious plugin jars so that installed files can be scanned for malware and not only logs are scanned for attacks
