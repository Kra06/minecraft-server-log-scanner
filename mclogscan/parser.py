"""Parse Minecraft server logs into structured LogEntry objects.

Supported formats:
Vanilla/Spigot : [12:34:56] [Server thread/INFO]: message
Paper/Purpur   : [12:34:56 INFO]: message
Forge/NeoForge : [24Sep2026 12:34:56.789] [Server thread/INFO] [minecraft/DedicatedServer]: message

log files are treated as untrusted input so undecodable bytes are replaced rather
than raising, and lines that match no known format are still kept as raw
entries so that nothing an attacker writes into the log escapes scanning.

to summarise, sorts the logs from the log file, which are just lines of text, into labelled boxes by reading each line of text. 
enables the rest of the program can ask simple questions like ‘who was the player?’
"""

from __future__ import annotations

import gzip
import os
import re #regex
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Iterable, Iterator, List, Optional

#line formats that are supported (using regex)

VANILLA_RE = re.compile( #turns pattern into ready to use tool
    r"^\[(?P<time>\d{2}:\d{2}:\d{2})\] \[(?P<thread>[^\]]+)/(?P<level>[A-Z]+)\]: (?P<message>.*)$"
)
PAPER_RE = re.compile(
    r"^\[(?P<time>\d{2}:\d{2}:\d{2}) (?P<level>[A-Z]+)\]: (?P<message>.*)$"
)
FORGE_RE = re.compile(
    r"^\[(?P<date>\d{2}[A-Za-z]{3}\d{4}) (?P<time>\d{2}:\d{2}:\d{2})\.\d+\] "
    r"\[(?P<thread>[^\]]+)/(?P<level>[A-Z]+)\] \[[^\]]*\]: (?P<message>.*)$"
)
LINE_FORMATS = (VANILLA_RE, PAPER_RE, FORGE_RE) #put all patterns in a group so can try each format until one fits

#event formats applied to the message part of a line
#if a message fits a template we can pull out details to figure out what happened

#minecraft usernames are 3-16 chars of [A-Za-z0-9_]; allow 1+ so that
#malformed names used by attack tools are still captured
_NAME = r"(?P<player>[A-Za-z0-9_]{1,16})"
_IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)"

JOIN_RE = re.compile(rf"^{_NAME}\[/{_IP}:\d+\] logged in with entity id")
LEAVE_RE = re.compile(rf"^{_NAME} left the game")

#server side messages about a player
PLAYER_NOTICE_RE = re.compile(rf"^{_NAME} (?:moved too quickly|moved wrongly|was kicked for)")
CHAT_RE = re.compile(rf"^(?:\[Not Secure\] )?<{_NAME}> (?P<content>.*)$")
COMMAND_RE = re.compile(rf"^{_NAME} issued server command: (?P<content>.*)$")
DISCONNECT_RE = re.compile(r"lost connection: (?P<content>.*)$|^Disconnecting .*?: (?P<content2>.*)$")

ANY_IP_RE = re.compile(r"/(\d{1,3}(?:\.\d{1,3}){3}):\d+")
PROFILE_NAME_RE = re.compile(r"name=([A-Za-z0-9_]{1,16})")
LEADING_NAME_RE = re.compile(r"^(?:Disconnecting )?([A-Za-z0-9_]{1,16})\b")

#rotated logs like 2026-09-24-1.log.gz
FILENAME_DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")


@dataclass
class LogEntry:
    #one line of a Minecraft log plus whatever we could extract from it

    line_no: int
    timestamp: datetime
    level: str  #info, warn or error
    message: str
    raw: str
    source: str = "<memory>"
    thread: str = ""
    event: str = "other"  # join | leave | chat | command | disconnect | other | raw
    player: Optional[str] = None
    ip: Optional[str] = None
    content: Optional[str] = None  # chat text / command text / disconnect reason
    extra: dict = field(default_factory=dict)

#this fucntion takes one entry and tries the templates one after another
def _classify(entry: LogEntry) -> None:
    #fill in event/player/ip/content by matching known message formats
    msg = entry.message

    m = JOIN_RE.match(msg)
    if m:
        entry.event, entry.player, entry.ip = "join", m["player"], m["ip"]
        return
    m = CHAT_RE.match(msg)
    if m:
        entry.event, entry.player, entry.content = "chat", m["player"], m["content"]
        return
    m = COMMAND_RE.match(msg)
    if m:
        entry.event, entry.player, entry.content = "command", m["player"], m["content"]
        return
    m = LEAVE_RE.match(msg)
    if m:
        entry.event, entry.player = "leave", m["player"]
        return
    m = PLAYER_NOTICE_RE.match(msg)
    if m:
        entry.player = m["player"]
        return
    m = DISCONNECT_RE.search(msg)
    if m:
        entry.event = "disconnect"
        entry.content = m["content"] or m["content2"]
        name = PROFILE_NAME_RE.search(msg) or LEADING_NAME_RE.match(msg)
        entry.player = name.group(1) if name else None

    #pick up an IP address from any line that contains one for example when somoene disconnects
    if entry.ip is None:
        ip = ANY_IP_RE.search(msg)
        if ip:
            entry.ip = ip.group(1)

#main loop
def parse_lines(
    lines: Iterable[str], base_date: Optional[date] = None, source: str = "<memory>"
) -> Iterator[LogEntry]:
    """parse the log lines
    Vanilla/Paper logs only record the time of day, so `base_date` supplies
    the date. if the time goes backwards the log has passed midnight so we
    move on to the next day
    """
    current_day = base_date or date(1970, 1, 1)
    last_ts: Optional[datetime] = None
    last_level = "INFO"

    for line_no, line in enumerate(lines, start=1): #number the line starting at 1 so it matches text editor
        line = line.rstrip("\r\n")
        if not line.strip():    #skip if line is blank
            continue

        match = None    #try the 3 line formats and use the first one that fits
        for fmt in LINE_FORMATS:
            match = fmt.match(line)
            if match:
                break

        if match is None:
            #if no formats fit it could be stack traces, plugin banners, or attacker controlled garbage
            #keep it so signatures still run against it
            ts = last_ts or datetime.combine(current_day, datetime.min.time())
            yield LogEntry(line_no, ts, last_level, line, line, source, event="raw")
            continue

        groups = match.groupdict()  #work out the date and time from the file
        t = datetime.strptime(groups["time"], "%H:%M:%S").time()
        if groups.get("date"):
            current_day = datetime.strptime(groups["date"], "%d%b%Y").date()
        ts = datetime.combine(current_day, t)
        if last_ts and ts < last_ts and not groups.get("date"):     #check for midnight, means a new day started
            current_day += timedelta(days=1)
            ts = datetime.combine(current_day, t)

        entry = LogEntry(   #fill in the boxes
            line_no=line_no,
            timestamp=ts,
            level=groups["level"],
            message=groups["message"],
            raw=line,
            source=source,
            thread=groups.get("thread") or "",
        )
        _classify(entry)
        last_ts, last_level = ts, entry.level
        yield entry     #hand the entry back

#works out which day a log is from
def _date_for_file(path: Path) -> date:
    m = FILENAME_DATE_RE.search(path.name)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y-%m-%d").date()
        except ValueError:
            pass
    return datetime.fromtimestamp(os.path.getmtime(path)).date()

#opens a log file and runs main loop on it
def parse_file(path: "str | os.PathLike[str]") -> List[LogEntry]:
    #Parse a .log or rotated .log.gz file
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
        return list(parse_lines(fh, base_date=_date_for_file(path), source=str(path)))

#return log files for a path, lets us point the scanner at the file itself or every log in a directory
def find_log_files(target: "str | os.PathLike[str]") -> List[Path]:
    target = Path(target)
    if target.is_file():
        return [target]
    if target.is_dir():
        files = [p for p in target.rglob("*") if p.is_file() and (p.name.endswith(".log") or p.name.endswith(".log.gz"))]
        return sorted(files)
    raise FileNotFoundError(f"No such file or directory: {target}")
