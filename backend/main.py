"""FastAPI app.

Endpoints:
  POST /upload                   store a .log/.txt file, returns job_id
  POST /analyze/{id}             queue analysis (runs in the background)
  GET  /status/{id}              progress, elapsed time, RAM
  GET  /findings/{id}            findings so far (final once the report exists)
  GET  /report/{id}              final report
  GET  /report/{id}/download     same report as a JSON file download
  GET  /lines/{id}?numbers=1,2   raw text of evidence lines (for the detail view)

One worker thread = one analysis at a time; extra jobs wait in its queue.
"""
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Callable, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

import config
from analyzer.ai_analyzer import OllamaClient
from analyzer.log_parser import LogValidationError, validate_upload
from analyzer.pipeline import run_job
from analyzer.system_stats import backend_ram_mb, model_ram_mb
from database.storage import Storage

logging.basicConfig(level=logging.INFO)
ACTIVE_STATES = ("queued", "running")


def create_app(data_dir: Path = config.DATA_DIR,
               client_factory: Optional[Callable] = None,
               sleep: Callable[[float], None] = time.sleep) -> FastAPI:
    store = Storage(data_dir / "analyzer.db")
    upload_dir = data_dir / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    make_client = client_factory or OllamaClient
    worker = ThreadPoolExecutor(max_workers=1)   # strictly one job at a time

    def submit(job_id: str) -> None:
        store.update_job(job_id, state="queued")
        worker.submit(run_job, job_id, store, make_client(), sleep)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        # Resume: jobs interrupted by a restart continue; finished chunks are skipped.
        for job in store.jobs_in_states(*ACTIVE_STATES):
            submit(job["id"])
        yield
        worker.shutdown(wait=False, cancel_futures=True)

    app = FastAPI(title="Local AI Security Log Analyzer", lifespan=lifespan)
    app.add_middleware(CORSMiddleware, allow_origins=config.CORS_ORIGINS,
                       allow_methods=["*"], allow_headers=["*"])
    app.state.store = store

    def job_or_404(job_id: str) -> dict:
        job = store.get_job(job_id)
        if not job:
            raise HTTPException(404, f"Job '{job_id}' not found")
        return job

    @app.get("/health")
    def health():
        return {"ok": True, "model": config.MODEL_NAME}

    @app.post("/upload")
    async def upload(file: UploadFile = File(...)):
        name = Path(file.filename or "").name
        if not name.lower().endswith(config.ALLOWED_EXTENSIONS):
            raise HTTPException(400, f"Unsupported file type '{name}'. Only .log and .txt files are accepted.")
        target = upload_dir / f"{time.time_ns()}_{name}"
        size, limit = 0, config.MAX_UPLOAD_MB * 2**20
        with open(target, "wb") as out:          # stream to disk, never the whole file in RAM
            while block := await file.read(2**20):
                size += len(block)
                if size > limit:
                    out.close()
                    target.unlink(missing_ok=True)
                    raise HTTPException(413, f"File larger than {config.MAX_UPLOAD_MB} MB.")
                out.write(block)
        try:
            validate_upload(name, target)
        except LogValidationError as exc:
            target.unlink(missing_ok=True)
            raise HTTPException(400, str(exc))
        job_id = store.create_job(name, target, config.MODEL_NAME)
        return {"job_id": job_id, "filename": name, "size_bytes": size}

    @app.post("/analyze/{job_id}")
    def analyze(job_id: str, restart: bool = False):
        job = job_or_404(job_id)
        if job["state"] in ACTIVE_STATES:
            raise HTTPException(409, "This job is already queued or running.")
        if restart:
            store.clear_results(job_id)
            store.update_job(job_id, started_at=None, finished_at=None, current_chunk=0, entries_processed=0)
        submit(job_id)
        return {"job_id": job_id, "state": "queued"}

    @app.get("/status/{job_id}")
    def status(job_id: str):
        job = job_or_404(job_id)
        results = store.load_chunk_results(job_id)
        end = job["finished_at"] or time.time()
        return {
            "job_id": job_id, "filename": job["filename"], "state": job["state"], "model": job["model"],
            "current_chunk": job["current_chunk"], "total_chunks": job["total_chunks"],
            "chunks_done": len(results), "chunks_failed": sum(not r.ok for r in results),
            "entries_processed": job["entries_processed"], "total_entries": job["total_entries"],
            "elapsed_s": round(end - job["started_at"], 1) if job["started_at"] else 0,
            "error": job["error"],
            "ram_mb": {"backend": backend_ram_mb(), "model": model_ram_mb()},
        }

    @app.get("/findings/{job_id}")
    def findings(job_id: str):
        job_or_404(job_id)
        report = store.get_report(job_id)
        if report:
            return {"final": True, "findings": report["findings"]}
        # Before correlation: raw, validated model findings so the UI can show progress.
        raw = [f.model_dump(mode="json") for r in store.load_chunk_results(job_id) for f in r.findings]
        return {"final": False, "findings": raw}

    @app.get("/lines/{job_id}")
    def lines(job_id: str, numbers: str):
        """Raw text of specific log lines (for showing evidence). numbers='5,13,196'."""
        job = job_or_404(job_id)
        try:
            wanted = {int(n) for n in numbers.split(",") if n.strip()}
        except ValueError:
            raise HTTPException(400, "numbers must be a comma-separated list of integers")
        if len(wanted) > 200:
            raise HTTPException(400, "at most 200 lines per request")
        found = {}
        with open(job["path"], encoding="utf-8", errors="replace") as fh:   # streamed
            for n, text in enumerate(fh, start=1):
                if n in wanted:
                    found[n] = text.rstrip("\r\n")[:2000]
                    if len(found) == len(wanted):
                        break
        return {"lines": [{"line": n, "text": found[n]} for n in sorted(found)]}

    def report_or_409(job_id: str) -> dict:
        job = job_or_404(job_id)
        report = store.get_report(job_id)
        if not report:
            raise HTTPException(409, f"Report not ready (state: {job['state']}).")
        return report

    @app.get("/report/{job_id}")
    def report(job_id: str):
        return report_or_409(job_id)

    @app.get("/report/{job_id}/download")
    def download(job_id: str):
        data = report_or_409(job_id)
        return JSONResponse(data, headers={
            "Content-Disposition": f'attachment; filename="security-report-{job_id}.json"'})

    return app


app = create_app()
