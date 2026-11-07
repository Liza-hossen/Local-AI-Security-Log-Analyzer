"""Streaming log parser.

Turns a log file into LogEntry objects, one at a time (a generator), so the whole
file is never held in memory as a second copy.

Supports:
- JSON-lines logs (like the sample) -> fields read by key name.
- Plain-text logs (Apache/nginx/app style) -> fields pulled out with regexes.
- Multi-line entries: indented lines / stack-trace lines are glued onto the
  previous entry, which keeps the line range [line_start, line_end].
Lines that cannot be understood are kept as "malformed" raw entries, never dropped.
"""
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional
from urllib.parse import unquote

import config


class LogValidationError(ValueError):
    """Raised for uploads we refuse to analyze (wrong type, empty file)."""


@dataclass
class LogEntry:
    line_start: int                  # 1-based line number in the original file
    line_end: int                    # same as line_start unless continuation lines were joined
    raw: str                         # original text (continuation lines joined with \n)
    timestamp: Optional[str] = None
    ip: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None
    user: Optional[str] = None
    message: Optional[str] = None
    level: Optional[str] = None
    user_agent: Optional[str] = None
    extra: dict = field(default_factory=dict)  # any other fields worth showing the model
    malformed: bool = False


# ------------------------------------------------------------------ validation
def validate_upload(filename: str, path: Path) -> None:
    """Reject non-.log/.txt files and files with no content."""
    if not filename or not filename.lower().endswith(config.ALLOWED_EXTENSIONS):
        raise LogValidationError(
            f"Unsupported file type '{filename}'. Only .log and .txt files are accepted."
        )
    # Stream until the first non-whitespace character instead of reading it all.
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.strip():
                return
    raise LogValidationError("The uploaded file is empty.")


# ------------------------------------------------------------------ JSON lines
# Different log producers use different key names for the same thing.
_KEYS = {
    "timestamp": ("time", "timestamp", "@timestamp", "ts"),
    "ip": ("client_ip", "ip", "src_ip", "remote_addr", "source_ip"),
    "method": ("method", "http_method"),
    "path": ("path", "url", "uri", "request_uri"),
    "status": ("status", "status_code", "http_status_code"),
    "user": ("username", "user", "account", "user_name"),
    "message": ("message", "msg"),
    "level": ("level", "severity", "log_level"),
    "user_agent": ("user_agent", "ua", "http_user_agent"),
}
_ALL_KNOWN_KEYS = {k for names in _KEYS.values() for k in names}


def _first(d: dict, names) -> Optional[object]:
    for name in names:
        if d.get(name) not in (None, ""):
            return d[name]
    return None


def _to_int(value) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_json(entry: LogEntry, data: dict) -> None:
    entry.timestamp = _str_or_none(_first(data, _KEYS["timestamp"]))
    entry.ip = _str_or_none(_first(data, _KEYS["ip"]))
    entry.method = _str_or_none(_first(data, _KEYS["method"]))
    entry.path = _str_or_none(_first(data, _KEYS["path"]))
    entry.status = _to_int(_first(data, _KEYS["status"]))
    entry.user = _str_or_none(_first(data, _KEYS["user"]))
    entry.message = _str_or_none(_first(data, _KEYS["message"]))
    entry.level = _str_or_none(_first(data, _KEYS["level"]))
    entry.user_agent = _str_or_none(_first(data, _KEYS["user_agent"]))
    entry.extra = {k: v for k, v in data.items() if k not in _ALL_KNOWN_KEYS}


def _str_or_none(value) -> Optional[str]:
    return None if value is None else str(value)


# ------------------------------------------------------------------ plain text
_TS_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    r"|\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\]"
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_REQ_RE = re.compile(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)")
_STATUS_RE = re.compile(r'(?:HTTP/[\d.]+"?\s+|\bstatus[=:]\s*)(\d{3})\b', re.I)
_USER_RE = re.compile(r"\b(?:user(?:name)?|account)[=:]\s*\"?([\w.@-]+)", re.I)
_LEVEL_RE = re.compile(r"\b(DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL)\b")


def _parse_text(entry: LogEntry, line: str) -> None:
    ts, ip = _TS_RE.search(line), _IP_RE.search(line)
    req, level = _REQ_RE.search(line), _LEVEL_RE.search(line)
    if not (ts or ip or req or level):
        # Nothing recognisable: keep it, but flag it so it is always reviewed.
        entry.malformed = True
        entry.message = line
        return
    entry.timestamp = ts.group(0).strip("[]") if ts else None
    entry.ip = ip.group(0) if ip else None
    if req:
        entry.method, entry.path = req.group(1), req.group(2)
    status = _STATUS_RE.search(line)
    entry.status = int(status.group(1)) if status else None
    user = _USER_RE.search(line)
    entry.user = user.group(1) if user else None
    entry.level = level.group(1) if level else None
    entry.message = line


# ------------------------------------------------------------------ entry building
# A line continues the previous entry if it is indented or looks like a stack frame.
_CONTINUATION_RE = re.compile(r"^(\s+\S|at |Caused by|Traceback|\.\.\. \d+ more)")


def _new_entry(line: str, line_no: int) -> LogEntry:
    entry = LogEntry(line_start=line_no, line_end=line_no, raw=line)
    if line.lstrip().startswith("{"):
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                _parse_json(entry, data)
                return entry
        except json.JSONDecodeError:
            pass
        # Looked like JSON but was broken (e.g. cut off mid-line).
        entry.malformed = True
        entry.message = line
        return entry
    _parse_text(entry, line)
    return entry


def parse_lines(lines) -> Iterator[LogEntry]:
    """Parse any iterable of text lines. Yields one LogEntry per logical entry."""
    current: Optional[LogEntry] = None
    for line_no, line in enumerate(lines, start=1):
        line = line.rstrip("\r\n")
        if not line.strip():
            continue  # blank lines carry no information
        if current is not None and _CONTINUATION_RE.match(line):
            current.raw += "\n" + line
            current.line_end = line_no
            continue
        if current is not None:
            yield current
        current = _new_entry(line, line_no)
    if current is not None:
        yield current


def parse_file(path: Path) -> Iterator[LogEntry]:
    """Stream a log file from disk. errors='replace' so bad bytes never crash us."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        yield from parse_lines(fh)


# ------------------------------------------------------------------ helpers shared by other modules
def decode_path(path: Optional[str]) -> str:
    """URL-decode up to twice so double-encoded attacks (%252e) become visible."""
    if not path:
        return ""
    once = unquote(path)
    return unquote(once)


def _short_ua(ua: Optional[str]) -> Optional[str]:
    # Full browser strings are long and say little; tools (curl, python-requests) matter.
    if ua and ua.startswith("Mozilla/"):
        return "browser"
    return ua


# Fields that cost tokens but rarely help classify an attack.
_NOISE_FIELDS = {"host", "request_id", "duration_ms"}


def to_model_text(entry: LogEntry) -> str:
    """Compact one-line rendering that is sent to the model.

    Drops noisy fields so ~2x more entries fit per chunk. The original raw line
    is kept on the entry for evidence display.
    """
    if entry.malformed:
        return _one_line(entry.raw)
    parts = []
    if entry.timestamp:
        parts.append(entry.timestamp.replace(".000", ""))
    if entry.level and entry.level.upper() != "INFO":
        parts.append(entry.level)
    if entry.ip:
        parts.append(entry.ip)
    if entry.method or entry.path:
        parts.append(f"{entry.method or ''} {decode_path(entry.path)}".strip())
    if entry.status is not None:
        parts.append(str(entry.status))
    if entry.user:
        parts.append(f"user={entry.user}")
    if entry.message:
        parts.append(f"msg={entry.message}")
    for key, value in entry.extra.items():
        if key in _NOISE_FIELDS:
            continue
        if key == "response_bytes" and _to_int(value) is not None and int(value) < config.LARGE_RESPONSE_BYTES:
            continue
        parts.append(f"{key}={_compact(value)}")
    ua = _short_ua(entry.user_agent)
    if ua:
        parts.append(f"ua={ua}")
    text = " ".join(parts)
    # Keep stack-trace continuation lines, flattened onto one line.
    if entry.line_end > entry.line_start:
        tail = entry.raw.split("\n", 1)[1]
        text += " | " + tail
    return _one_line(text)


def _compact(value) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def _one_line(text: str) -> str:
    # Newlines inside a log value must never be able to start a fake prompt line.
    return " ".join(text.split())
