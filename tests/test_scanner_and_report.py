import json

from mclogscan.cli import main
from mclogscan.parser import parse_lines
from mclogscan.report import render_html, render_json, render_text
from mclogscan.scanner import ScanResult, scan_entries, scan_path


# --- End-to-end on the sample logs -----------------------------------------

def test_attack_log_detects_everything(attack_log):
    result = scan_path(attack_log)
    found = {f.rule_id for f in result.findings}
    expected = {
        "MC-L4S-001", "MC-L4S-002", "MC-PRIV-001", "MC-ADMIN-001", "MC-GRIEF-001",
        "MC-CRASH-001", "MC-CRASH-002", "MC-CMDI-001", "MC-BACKDOOR-001", "MC-PHISH-001",
        "MC-RECON-001", "MC-HACK-001", "MC-AUTH-001",
        "MC-BEHAV-BRUTE", "MC-BEHAV-FLOOD", "MC-BEHAV-ALTS", "MC-BEHAV-SPAM",
    }
    assert expected <= found
    assert result.highest_severity() == "critical"
    assert result.top_offenders()[0][0] == "xX_h4ck3r_Xx"


def test_clean_log_has_no_false_positives(clean_log):
    assert scan_path(clean_log).findings == []


def test_findings_sorted_by_severity(attack_log):
    ranks = [f.rank for f in scan_path(attack_log).findings]
    assert ranks == sorted(ranks, reverse=True)


def test_min_severity_filter(attack_log):
    result = scan_path(attack_log, min_severity="high")
    assert result.findings
    assert {f.severity for f in result.findings} <= {"high", "critical"}


# --- Reports ---------------------------------------------------------------

def _result_for(line):
    entries = list(parse_lines([line]))
    return ScanResult(files=["test.log"], lines_scanned=1, findings=scan_entries(entries), rules_loaded=1)


def test_html_report_escapes_attacker_input():
    # A player puts an XSS payload next to a Log4Shell string in chat.
    result = _result_for("[18:00:00] [Server thread/INFO]: <Eve> ${jndi:ldap://x/<script>alert(1)</script>}")
    html = render_html(result)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_text_report_neutralises_terminal_escapes():
    result = _result_for("[18:00:00] [Server thread/INFO]: <Eve> hide\x1b[2K ${jndi:ldap://x/a}")
    text = render_text(result)
    assert "\x1b" not in text
    assert "\\x1b" in text


def test_json_report_structure(attack_log):
    data = json.loads(render_json(scan_path(attack_log)))
    assert data["summary"]["total_findings"] == len(data["findings"])
    assert data["summary"]["by_severity"]["critical"] == 2
    first = data["findings"][0]
    assert {"rule_id", "severity", "timestamp", "evidence", "recommendation"} <= first.keys()


def test_empty_report(clean_log):
    assert "No suspicious activity found." in render_text(scan_path(clean_log))


# --- CLI exit codes ---------------------------------------------------------

def test_cli_exit_codes(attack_log, clean_log, tmp_path, capsys):
    assert main([str(clean_log)]) == 0
    assert main([str(attack_log)]) == 2
    assert main([str(attack_log), "--fail-on", "critical"]) == 2
    assert main([str(tmp_path / "missing.log")]) == 1
    assert "error:" in capsys.readouterr().err


def test_cli_writes_report_file(attack_log, tmp_path):
    out = tmp_path / "report.html"
    main([str(attack_log), "-f", "html", "-o", str(out)])
    assert out.read_text().startswith("<!doctype html>")


def test_cli_fail_on_threshold(clean_log, tmp_path):
    log = tmp_path / "2026-09-22-1.log"
    log.write_text("[10:00:00] [Server thread/INFO]: Steve issued server command: /plugins\n")
    assert main([str(log)]) == 0  # low finding, default --fail-on high
    assert main([str(log), "--fail-on", "low"]) == 2
