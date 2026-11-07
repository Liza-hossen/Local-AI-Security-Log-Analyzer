"""SQLite storage for jobs, per-chunk results and reports.

Each chunk result is written the moment it finishes, so a crash or restart loses
at most the chunk that was running. A new connection per call keeps it safe to use
from the API thread and the background worker thread at the same time.
"""
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Optional

from analyzer.schemas import ChunkResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    path TEXT NOT NULL,
    state TEXT NOT NULL,          -- uploaded | queued | running | completed | completed_with_errors | failed
    model TEXT,
    created_at REAL NOT NULL,
    started_at REAL,
    finished_at REAL,
    total_chunks INTEGER DEFAULT 0,
    current_chunk INTEGER DEFAULT 0,
    total_entries INTEGER DEFAULT 0,
    entries_processed INTEGER DEFAULT 0,
    error TEXT
);
CREATE TABLE IF NOT EXISTS chunk_results (
    job_id TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    ok INTEGER NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (job_id, chunk_index)
);
CREATE TABLE IF NOT EXISTS reports (
    job_id TEXT PRIMARY KEY,
    data TEXT NOT NULL
);
"""


class Storage:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------ jobs
    def create_job(self, filename: str, path: Path, model: str) -> str:
        job_id = uuid.uuid4().hex[:12]
        with self._conn() as conn:
            conn.execute("INSERT INTO jobs (id, filename, path, state, model, created_at) VALUES (?,?,?,?,?,?)",
                         (job_id, filename, str(path), "uploaded", model, time.time()))
        return job_id

    def get_job(self, job_id: str) -> Optional[dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return dict(row) if row else None

    _JOB_FIELDS = {"state", "started_at", "finished_at", "total_chunks", "current_chunk",
                   "total_entries", "entries_processed", "error", "model"}

    def update_job(self, job_id: str, **fields) -> None:
        unknown = set(fields) - self._JOB_FIELDS
        if unknown:  # column names are interpolated below, so only allow known ones
            raise ValueError(f"unknown job fields: {unknown}")
        sets = ", ".join(f"{k} = ?" for k in fields)
        with self._conn() as conn:
            conn.execute(f"UPDATE jobs SET {sets} WHERE id = ?", (*fields.values(), job_id))

    def jobs_in_states(self, *states: str) -> list[dict[str, Any]]:
        marks = ",".join("?" * len(states))
        with self._conn() as conn:
            rows = conn.execute(f"SELECT * FROM jobs WHERE state IN ({marks}) ORDER BY created_at", states)
            return [dict(r) for r in rows.fetchall()]

    # ------------------------------------------------------------------ chunk results
    def save_chunk_result(self, job_id: str, result: ChunkResult) -> None:
        with self._conn() as conn:
            conn.execute("INSERT OR REPLACE INTO chunk_results (job_id, chunk_index, ok, data) VALUES (?,?,?,?)",
                         (job_id, result.chunk_index, int(result.ok), result.model_dump_json()))

    def load_chunk_results(self, job_id: str) -> list[ChunkResult]:
        with self._conn() as conn:
            rows = conn.execute("SELECT data FROM chunk_results WHERE job_id = ? ORDER BY chunk_index",
                                (job_id,)).fetchall()
        return [ChunkResult.model_validate_json(r["data"]) for r in rows]

    def ok_chunk_indexes(self, job_id: str) -> set[int]:
        """Chunks that succeeded. Failed chunks are retried on resume."""
        with self._conn() as conn:
            rows = conn.execute("SELECT chunk_index FROM chunk_results WHERE job_id = ? AND ok = 1",
                                (job_id,)).fetchall()
        return {r["chunk_index"] for r in rows}

    def clear_results(self, job_id: str) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM chunk_results WHERE job_id = ?", (job_id,))
            conn.execute("DELETE FROM reports WHERE job_id = ?", (job_id,))

    # ------------------------------------------------------------------ reports
    def save_report(self, job_id: str, report: dict) -> None:
        with self._conn() as conn:
            conn.execute("INSERT OR REPLACE INTO reports (job_id, data) VALUES (?,?)",
                         (job_id, json.dumps(report)))

    def get_report(self, job_id: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute("SELECT data FROM reports WHERE job_id = ?", (job_id,)).fetchone()
        return json.loads(row["data"]) if row else None
