import config
from analyzer.chunker import build_chunks
from analyzer.log_parser import parse_file, parse_lines
from analyzer.token_counter import estimate_tokens
from tests.conftest import SAMPLE_LOG, gateway_line


def _check_chunks(chunks, entries, budget):
    """Shared invariants: budget respected, every entry exactly once, in order, never split."""
    seen = [e for c in chunks for e in c.entries]
    assert [e.line_start for e in seen] == [e.line_start for e in entries]
    for c in chunks:
        assert c.token_count <= budget
        # Recount independently so a bookkeeping bug cannot hide an overflow.
        assert estimate_tokens(c.text) <= budget
        assert len(c.lines) == len(c.entries)
        for line, e in zip(c.lines, c.entries):
            assert line.startswith(f"[L{e.line_start}")


def test_chunks_respect_budget_and_never_split_entries():
    entries = list(parse_lines([gateway_line(i) for i in range(200)]))
    chunks = list(build_chunks(entries, budget=300))
    assert len(chunks) > 5
    _check_chunks(chunks, entries, 300)


def test_multiline_entry_stays_whole_in_one_chunk():
    lines = [gateway_line(i) for i in range(30)]
    lines[10:10] = ["2026-11-01 08:00:00 ERROR crash", "    at a.b(C.java:1)", "    at d.e(F.java:2)"]
    entries = list(parse_lines(lines))
    chunks = list(build_chunks(entries, budget=200))
    holder = [c for c in chunks for e in c.entries if e.line_start == 11]
    assert len(holder) == 1
    assert any(l.startswith("[L11-13]") for l in holder[0].lines)
    assert {11, 12, 13} <= holder[0].line_numbers


def test_very_long_line_is_truncated_but_keeps_line_number():
    huge = gateway_line(2, path="/search?q=" + "A" * 50_000)
    entries = list(parse_lines([gateway_line(1), huge, gateway_line(3)]))
    chunks = list(build_chunks(entries))
    _check_chunks(chunks, entries, config.CHUNK_TOKENS)
    big = [c for c in chunks if any(e.line_start == 2 for e in c.entries)][0]
    assert big.truncated_lines == [2]
    line = [l for l in big.lines if l.startswith("[L2]")][0]
    assert line.endswith(config.TRUNCATION_MARKER)


def test_large_20k_token_file(write_log):
    lines = [gateway_line(i, ip=f"198.51.100.{i % 50}") for i in range(1200)]
    path = write_log(lines)
    raw_tokens = estimate_tokens(path.read_text(encoding="utf-8"))
    assert raw_tokens > 20_000
    entries = list(parse_file(path))
    chunks = list(build_chunks(entries))
    _check_chunks(chunks, entries, config.CHUNK_TOKENS)


def test_sample_log_chunks():
    entries = list(parse_file(SAMPLE_LOG))
    chunks = list(build_chunks(entries))
    _check_chunks(chunks, entries, config.CHUNK_TOKENS)


def test_budget_adds_up_to_2048():
    total = (config.SYSTEM_PROMPT_TOKENS + config.CONTEXT_TOKENS + config.CHUNK_TOKENS
             + config.OUTPUT_TOKENS + config.SAFETY_MARGIN_TOKENS)
    assert total == config.MAX_TOKENS_PER_CALL == 2048
    assert config.OUTPUT_TOKENS >= 500
