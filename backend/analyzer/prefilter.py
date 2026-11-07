"""Cheap rule-based pre-filter.

Goal: spend model tokens only on entries that could matter.

An entry is LOW-INTEREST (not sent to the model) only if ALL of these hold:
  1. it parsed correctly (not malformed),
  2. it is an HTTP GET/HEAD request,
  3. the status is 2xx or 3xx,
  4. the level is INFO (or missing),
  5. security_signals() finds nothing (no SQLi, traversal, scan path, sensitive
     path, auth result, security_rule, rate field, injection text, huge response),
  6. it is either a static asset, a health check, or a normal browser request.

Everything else is kept. Low-interest entries are still counted per IP so request
rates stay correct. security_signals() is also reused later by the context manager.
"""
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Iterator

import config
from analyzer.log_parser import LogEntry, decode_path

SQLI_RE = re.compile(
    r"('|\")\s*(or|and)\s+[\w'\"]+\s*=\s*[\w'\"]+"   # ' OR 1=1
    r"|union(\s+all)?\s+select"
    r"|;\s*(select|drop|insert|update|delete|exec)\b"
    r"|\b(sleep|benchmark|pg_sleep)\s*\("
    r"|information_schema|xp_cmdshell|waitfor\s+delay",
    re.I,
)
TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\|/etc/passwd|win\.ini|boot\.ini", re.I)
SCAN_PATH_RE = re.compile(
    r"/\.env|/\.git|/\.aws|/\.ssh|wp-admin|wp-login|xmlrpc\.php|phpmyadmin|/actuator"
    r"|server-status|/cgi-bin|backup\.(sql|zip|tar|gz)|config\.(json|php|ya?ml)|\.bak$",
    re.I,
)
SENSITIVE_PATH_RE = re.compile(
    r"/admin|/auth|/login|/logout|/export|/users|/settings|/token|/password|/files", re.I
)
# Subset of sensitive paths where a 2xx answer means privileged data/actions were
# reached. Login pages are excluded: viewing /login is not access to anything.
PRIVILEGED_PATH_RE = re.compile(r"/admin|/export|/users|/settings|/token|/password|/files", re.I)
STATIC_PATH_RE = re.compile(
    r"^/(assets|static|public)/|\.(css|js|svg|png|jpe?g|gif|ico|woff2?|map)$", re.I
)
INJECTION_TEXT_RE = re.compile(
    r"ignore (all |any )?(previous|prior|above) instructions"
    r"|disregard (all |the )?(previous |prior )?instructions"
    r"|report (all|every)\w* .{0,20}as safe|you are now|system prompt",
    re.I,
)
# Extra fields whose mere presence means a security component reacted.
SECURITY_FIELDS = ("security_rule", "validation_error", "auth_result", "submitted_text")


def security_signals(entry: LogEntry) -> list[str]:
    """Return short tags describing why an entry looks security-relevant."""
    tags = []
    if entry.malformed:
        tags.append("malformed")
    path = decode_path(entry.path)
    path_no_query = path.split("?", 1)[0]
    if path and SQLI_RE.search(path):
        tags.append("sqli_pattern")
    if path and TRAVERSAL_RE.search(path):
        tags.append("traversal_pattern")
    if path and SCAN_PATH_RE.search(path_no_query):
        tags.append("scan_path")
    if path and SENSITIVE_PATH_RE.search(path_no_query):
        tags.append("sensitive_path")
    tags.extend(_status_tags(entry.status))
    tags.extend(_field_tags(entry))
    if INJECTION_TEXT_RE.search(entry.raw):
        tags.append("injection_text")
    # De-duplicate (a 401 + auth_result=invalid both say auth_failure) so that
    # per-IP counters count each line once.
    return list(dict.fromkeys(tags))


def _status_tags(status) -> list[str]:
    if status is None:
        return []
    named = {401: "auth_failure", 403: "access_denied", 429: "rate_limited"}
    if status in named:
        return [named[status]]
    if status >= 500:
        return ["server_error"]
    if status >= 400:
        return ["client_error"]
    return []


def _field_tags(entry: LogEntry) -> list[str]:
    tags = []
    auth = str(entry.extra.get("auth_result", "")).lower()
    if auth == "success":
        tags.append("auth_success")
    elif auth:
        tags.append("auth_failure")
    for name in ("security_rule", "validation_error", "submitted_text"):
        if name in entry.extra:
            tags.append(name)
    if "requests_in_window" in entry.extra:
        tags.append("high_rate")
    size = entry.extra.get("response_bytes")
    if isinstance(size, (int, float)) and size >= config.LARGE_RESPONSE_BYTES:
        tags.append("large_response")
    return tags


def is_low_interest(entry: LogEntry) -> bool:
    """True only for plain, boring traffic. See the module docstring for the rules."""
    if entry.malformed or entry.method not in ("GET", "HEAD"):
        return False
    if entry.status is None or not 200 <= entry.status < 400:
        return False
    if entry.level and entry.level.upper() != "INFO":
        return False
    if security_signals(entry):
        return False
    path = decode_path(entry.path).split("?", 1)[0]
    is_static = bool(STATIC_PATH_RE.search(path))
    is_health = path in config.HEALTH_PATHS
    is_browser = bool(entry.user_agent and entry.user_agent.startswith("Mozilla/"))
    return is_static or is_health or is_browser


@dataclass
class FilterStats:
    total_entries: int = 0
    low_interest: int = 0
    interesting: int = 0
    malformed: int = 0
    duplicates: int = 0          # exact repeated lines, counted once (set by the pipeline)
    low_interest_by_ip: Counter = field(default_factory=Counter)  # keeps request counts honest


def partition(entries: Iterable[LogEntry], stats: FilterStats) -> Iterator[LogEntry]:
    """Yield only interesting entries; count the low-interest ones in stats."""
    for entry in entries:
        stats.total_entries += 1
        if entry.malformed:
            stats.malformed += 1
        if is_low_interest(entry):
            stats.low_interest += 1
            stats.low_interest_by_ip[entry.ip or "unknown"] += 1
            continue
        stats.interesting += 1
        yield entry
