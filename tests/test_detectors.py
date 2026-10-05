from mclogscan.detectors import Thresholds, run_detectors


def join(t, name, ip):
    return f"[{t}] [Server thread/INFO]: {name}[/{ip}:5000] logged in with entity id 1 at ([world]0, 0, 0)"


def chat(t, name, text):
    return f"[{t}] [Async Chat Thread - #0/INFO]: <{name}> {text}"


def ids(findings):
    return [f.rule_id for f in findings]


# --- Brute force ------------------------------------------------------------

def test_brute_force_triggers_once_per_burst(parse):
    lines = "\n".join(f"[18:10:{s:02d}] [Server thread/INFO]: [AuthMe] Admin used the wrong password" for s in range(0, 60, 5))
    findings = run_detectors(parse(lines))  # 12 failures -> 2 bursts of 5 (+2 left over)
    assert ids(findings) == ["MC-BEHAV-BRUTE", "MC-BEHAV-BRUTE"]
    assert findings[0].player == "Admin"


def test_slow_failures_outside_window_ignored(parse):
    # one failure every 20s: never 5 within 60s
    lines = "\n".join(
        f"[18:{m:02d}:{s:02d}] [Server thread/INFO]: [AuthMe] Admin used the wrong password"
        for m in range(10, 13) for s in (0, 20, 40)
    )
    assert run_detectors(parse(lines)) == []


def test_brute_force_keyed_by_ip(parse):
    lines = "\n".join(
        f"[18:00:0{i}] [Server thread/INFO]: Disconnecting User{i} (/6.6.6.6:1{i}): You are not whitelisted on this server!"
        for i in range(5)
    )
    [finding] = run_detectors(parse(lines))
    assert finding.rule_id == "MC-BEHAV-BRUTE"
    assert finding.ip == "6.6.6.6"


def test_thresholds_are_configurable(parse):
    lines = "\n".join(f"[18:10:0{s}] [Server thread/INFO]: [AuthMe] Admin used the wrong password" for s in range(3))
    assert run_detectors(parse(lines)) == []
    assert ids(run_detectors(parse(lines), Thresholds(brute_force_attempts=3))) == ["MC-BEHAV-BRUTE"]


# --- Connection flood / alts ------------------------------------------------

def test_bot_flood_and_alts_detected(parse):
    lines = "\n".join(join(f"18:12:{i:02d}", f"Bot{i}", "9.9.9.9") for i in range(10))
    assert sorted(ids(run_detectors(parse(lines)))) == ["MC-BEHAV-ALTS", "MC-BEHAV-FLOOD"]


def test_normal_joins_from_different_ips_ok(parse):
    lines = "\n".join(join(f"18:12:{i:02d}", f"Player{i}", f"10.0.0.{i}") for i in range(20))
    assert run_detectors(parse(lines)) == []


def test_same_player_rejoining_is_not_alts(parse):
    lines = "\n".join(join(f"18:{m:02d}:00", "Steve", "1.1.1.1") for m in range(10))
    assert run_detectors(parse(lines)) == []


# --- Chat spam --------------------------------------------------------------

def test_repeated_message_spam(parse):
    lines = "\n".join(chat(f"18:00:{i * 3:02d}", "Spammer", "JOIN MY SERVER") for i in range(5))
    [finding] = run_detectors(parse(lines))
    assert finding.rule_id == "MC-BEHAV-SPAM"
    assert "same message" in finding.description


def test_rapid_message_spam(parse):
    lines = "\n".join(chat(f"18:00:0{i}", "Spammer", f"msg {i}") for i in range(8))
    [finding] = run_detectors(parse(lines))
    assert "8 messages" in finding.description


def test_normal_conversation_not_spam(parse):
    lines = "\n".join(chat(f"18:0{i}:00", "Steve" if i % 2 else "Alex", f"message {i}") for i in range(10))
    assert run_detectors(parse(lines)) == []
