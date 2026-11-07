"""Splits parsed entries into token-bounded chunks.

Rules:
- A chunk's log text never exceeds config.CHUNK_TOKENS (estimated tokens).
- An entry is never split across chunks. If one entry alone is too big, its text
  is truncated with a "[truncated]" marker but it keeps its line number.
- Each rendered line starts with its original line number, e.g. "[L42] ..." or
  "[L42-45] ..." for multi-line entries, so the model can cite real lines.
"""
from dataclasses import dataclass, field
from typing import Iterable, Iterator

import config
from analyzer.log_parser import LogEntry, to_model_text
from analyzer.token_counter import estimate_tokens, truncate_to_tokens


@dataclass
class Chunk:
    index: int                                       # 0-based chunk number
    entries: list[LogEntry] = field(default_factory=list)
    lines: list[str] = field(default_factory=list)  # rendered text, one per entry
    token_count: int = 0
    truncated_lines: list[int] = field(default_factory=list)

    @property
    def text(self) -> str:
        return "\n".join(self.lines)

    @property
    def line_numbers(self) -> set[int]:
        """Every original line covered by this chunk (used to reject fake evidence)."""
        return {n for e in self.entries for n in range(e.line_start, e.line_end + 1)}


def line_label(entry: LogEntry) -> str:
    if entry.line_end > entry.line_start:
        return f"[L{entry.line_start}-{entry.line_end}]"
    return f"[L{entry.line_start}]"


def render_entry(entry: LogEntry, budget: int) -> tuple[str, bool]:
    """Render one entry as a prompt line, truncating it if it alone exceeds the budget."""
    label = line_label(entry) + " "
    body = to_model_text(entry)
    # +1 token for the newline that joins lines inside a chunk.
    available = budget - estimate_tokens(label) - 1
    cut = truncate_to_tokens(body, available)
    return label + cut, cut != body


def build_chunks(entries: Iterable[LogEntry], budget: int = config.CHUNK_TOKENS) -> Iterator[Chunk]:
    """Greedily pack entries into chunks. Streams: only one chunk is held at a time."""
    chunk = Chunk(index=0)
    for entry in entries:
        line, was_truncated = render_entry(entry, budget)
        cost = estimate_tokens(line) + 1
        if chunk.entries and chunk.token_count + cost > budget:
            yield chunk
            chunk = Chunk(index=chunk.index + 1)
        chunk.entries.append(entry)
        chunk.lines.append(line)
        chunk.token_count += cost
        if was_truncated:
            chunk.truncated_lines.append(entry.line_start)
    if chunk.entries:
        yield chunk
