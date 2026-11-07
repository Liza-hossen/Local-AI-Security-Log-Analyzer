"""Deterministic per-IP memory across ALL chunks.

Why: a 2B model cannot remember earlier chunks, and we only have 250 tokens to
carry context. So plain code does the remembering:

  Pass 1 (cheap, no model): observe() every entry of the file, including the
          low-interest ones, and keep per-IP counters + line numbers.
  Pass 2 (model, per chunk): summary_for(chunk) gives the model a compact,
          most-suspicious-first summary of only the IPs that appear in that chunk.

The same state is reused by correlation (Prompt 3) to detect sequences such as
failed logins -> success -> admin access, with real line numbers.
"""
from dataclasses import dataclass, field
from typing import Optional

import config
from analyzer.chunker import Chunk
from analyzer.log_parser import LogEntry, decode_path
from analyzer.prefilter import PRIVILEGED_PATH_RE, security_signals
from analyzer.token_counter import estimate_tokens

MAX_STORED_LINES = 50   # per event type per IP; counts stay exact, line lists are capped

# How much each event adds to an IP's suspicion score (only used for ordering).
SCORE_WEIGHTS = {
    "sqli_pattern": 5, "traversal_pattern": 5, "injection_text": 4, "scan_path": 3,
    "auth_failure": 2, "sensitive_success": 2, "large_response": 3, "high_rate": 1,
    "access_denied": 1, "rate_limited": 1, "security_rule": 1, "auth_success": 1,
}
# Order and short names used in the summary text.
SUMMARY_EVENTS = [
    ("auth_failure", "failed_login"), ("auth_success", "login_ok"),
    ("sensitive_success", "sensitive_ok"), ("large_response", "large_resp"),
    ("sqli_pattern", "sqli"), ("traversal_pattern", "traversal"), ("scan_path", "scan"),
    ("injection_text", "injection_text"), ("access_denied", "403"), ("rate_limited", "429"),
    ("high_rate", "high_rate"),
]


@dataclass
class EventLines:
    count: int = 0
    lines: list[int] = field(default_factory=list)  # first MAX_STORED_LINES occurrences
    last: Optional[int] = None                      # always the true last occurrence

    def add(self, line: int) -> None:
        self.count += 1
        self.last = line
        if len(self.lines) < MAX_STORED_LINES:
            self.lines.append(line)


@dataclass
class IPState:
    ip: str
    requests: int = 0
    first_line: Optional[int] = None
    last_line: Optional[int] = None
    users: set[str] = field(default_factory=set)
    events: dict[str, EventLines] = field(default_factory=dict)

    def add_event(self, name: str, line: int) -> None:
        self.events.setdefault(name, EventLines()).add(line)

    def count(self, name: str) -> int:
        return self.events[name].count if name in self.events else 0

    @property
    def score(self) -> int:
        return sum(SCORE_WEIGHTS.get(name, 0) * ev.count for name, ev in self.events.items())


@dataclass(frozen=True)
class LineInfo:
    """What correlation needs to know about one line without re-reading the file."""
    ip: Optional[str]
    status: Optional[int]
    signals: tuple[str, ...]


class ContextManager:
    def __init__(self) -> None:
        self.states: dict[str, IPState] = {}
        self.line_info: dict[int, LineInfo] = {}   # lines with an IP or a security signal
        self.duplicates: dict[int, int] = {}       # duplicate line -> first identical line
        self._seen: dict[int, int] = {}            # hash(raw text) -> first line

    # ---------------------------------------------------------------- pass 1
    def observe(self, entry: LogEntry) -> bool:
        """Record one entry. Called for every entry, even low-interest ones.

        Returns False for an exact duplicate (same raw text incl. timestamp): the
        same event logged twice must not be counted twice.
        """
        if entry.timestamp:
            key = hash(entry.raw)
            if key in self._seen:
                self.duplicates[entry.line_start] = self._seen[key]
                return False
            self._seen[key] = entry.line_start
        signals = security_signals(entry)
        if entry.ip or signals:
            self.line_info[entry.line_start] = LineInfo(entry.ip, entry.status, tuple(signals))
        if not entry.ip:
            return True
        state = self.states.setdefault(entry.ip, IPState(ip=entry.ip))
        state.requests += 1
        state.first_line = state.first_line or entry.line_start
        state.last_line = entry.line_start
        if entry.user:
            state.users.add(entry.user)
        for name in signals:
            state.add_event(name, entry.line_start)
        # A privileged endpoint (admin, export, users...) that actually answered 2xx
        # is what turns "attempts" into "possible access". Login pages do not count.
        is_ok = entry.status is not None and 200 <= entry.status < 300
        path = decode_path(entry.path).split("?", 1)[0]
        if is_ok and PRIVILEGED_PATH_RE.search(path):
            state.add_event("sensitive_success", entry.line_start)
        return True

    # ---------------------------------------------------------------- pass 2
    def summary_for(self, chunk: Chunk, budget: int = config.CONTEXT_TOKENS) -> tuple[str, dict[int, str]]:
        """Compact summary of suspicious IPs in this chunk + {cited line: its IP}."""
        ips = {e.ip for e in chunk.entries if e.ip}
        states = sorted(
            (self.states[ip] for ip in ips if ip in self.states and self.states[ip].score > 0),
            key=lambda s: s.score, reverse=True,
        )
        lines_out, cited = [], {}
        used = 0
        for state in states:
            text, lines = format_state(state)
            cost = estimate_tokens(text) + 1
            if used + cost > budget:
                break  # most suspicious IPs come first, so we drop the least important
            lines_out.append(text)
            cited.update({n: state.ip for n in lines})
            used += cost
        return "\n".join(lines_out), cited


def _sample(ev: EventLines) -> tuple[str, set[int]]:
    """Show at most 4 line numbers: first two and last two."""
    if ev.count <= 4:
        shown = list(ev.lines)
        return ",".join(f"L{n}" for n in shown), set(shown)
    shown = ev.lines[:2] + [ev.last]
    return f"L{shown[0]},L{shown[1]},..,L{shown[2]}", set(shown)


def format_state(state: IPState) -> tuple[str, set[int]]:
    parts = [f"{state.ip} req={state.requests}"]
    if state.users:
        parts.append("users=" + ",".join(sorted(state.users)[:3]))
    cited: set[int] = set()
    for key, short in SUMMARY_EVENTS:
        if key in state.events:
            ev = state.events[key]
            sample, lines = _sample(ev)
            parts.append(f"{short} x{ev.count} {sample}")
            cited |= lines
    return " | ".join(parts), cited
