"""Runs one analysis job end to end:

  parse (stream) -> per-IP state + duplicate removal -> pre-filter -> chunks
  -> model, one chunk at a time, each result saved immediately
  -> correlation -> report

Re-running a job resumes: chunks already saved as OK are skipped. Chunking is
deterministic (same file + same config = same chunks), so indexes line up.
"""
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from analyzer.ai_analyzer import ModelNotFoundError, analyze_chunks
from analyzer.chunker import Chunk, build_chunks
from analyzer.context_manager import ContextManager
from analyzer.correlation import correlate
from analyzer.log_parser import LogEntry, parse_file
from analyzer.prefilter import FilterStats, partition
from analyzer.report_generator import build_report
from database.storage import Storage

log = logging.getLogger(__name__)


@dataclass
class Prepared:
    ctx: ContextManager
    stats: FilterStats
    chunks: list[Chunk]
    line_chunk: dict[int, int]   # original line -> chunk index (for cross-chunk display)


def prepare(path: Path) -> Prepared:
    """One streaming pass over the file. Afterwards ctx holds the WHOLE-file state,
    which is what the per-chunk summaries need. Only interesting entries stay in memory."""
    ctx, stats = ContextManager(), FilterStats()

    def unique_entries() -> Iterator[LogEntry]:
        for entry in parse_file(path):
            if ctx.observe(entry):
                yield entry
            else:
                stats.duplicates += 1

    chunks = list(build_chunks(partition(unique_entries(), stats)))
    line_chunk = {n: c.index for c in chunks for n in c.line_numbers}
    return Prepared(ctx, stats, chunks, line_chunk)


def run_job(job_id: str, store: Storage, client, sleep: Callable[[float], None] = time.sleep) -> None:
    """Never raises: any problem ends up in the job's state/error fields."""
    job = store.get_job(job_id)
    try:
        store.update_job(job_id, state="running", error=None, started_at=job["started_at"] or time.time())
        prep = prepare(Path(job["path"]))
        done = store.ok_chunk_indexes(job_id)
        chunk_sizes = {c.index: len(c.entries) for c in prep.chunks}
        base = prep.stats.low_interest + prep.stats.duplicates   # handled without the model
        store.update_job(job_id, total_chunks=len(prep.chunks),
                         total_entries=prep.stats.total_entries + prep.stats.duplicates,
                         entries_processed=base + sum(chunk_sizes[i] for i in done if i in chunk_sizes))

        def on_start(chunk: Chunk) -> None:
            store.update_job(job_id, current_chunk=chunk.index + 1)

        def on_result(result) -> None:
            store.save_chunk_result(job_id, result)        # persist immediately
            done.add(result.chunk_index)
            store.update_job(job_id, entries_processed=base + sum(chunk_sizes[i] for i in done))

        try:
            analyze_chunks(prep.chunks, prep.ctx, client, on_result=on_result, on_start=on_start,
                           skip=store.ok_chunk_indexes(job_id), sleep=sleep)
        except ModelNotFoundError as exc:
            store.update_job(job_id, state="failed", error=str(exc), finished_at=time.time())
            return

        results = store.load_chunk_results(job_id)
        findings, correlations = correlate(results, prep.ctx, prep.line_chunk)
        report = build_report(store.get_job(job_id), prep.stats, prep.ctx, results, findings, correlations)
        store.save_report(job_id, report)
        state = "completed" if all(r.ok for r in results) else "completed_with_errors"
        store.update_job(job_id, state=state, finished_at=time.time(), current_chunk=len(prep.chunks))
    except Exception as exc:  # last line of defence for the background thread
        log.exception("job %s crashed", job_id)
        store.update_job(job_id, state="failed", error=f"{type(exc).__name__}: {exc}", finished_at=time.time())
