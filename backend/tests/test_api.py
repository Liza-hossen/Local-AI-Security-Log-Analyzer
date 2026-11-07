"""API tests with a mocked model client and a temporary data directory."""
import time

import pytest
from fastapi.testclient import TestClient

from main import create_app
from tests.conftest import gateway_line
from tests.test_ai_pipeline import FakeClient, _reply, no_sleep


@pytest.fixture
def api(tmp_path):
    app = create_app(data_dir=tmp_path, client_factory=lambda: FakeClient(*[_reply()] * 50), sleep=no_sleep)
    with TestClient(app) as client:
        yield client


def _upload(api, content: bytes, name="test.log"):
    return api.post("/upload", files={"file": (name, content, "text/plain")})


def _wait_done(api, job_id, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = api.get(f"/status/{job_id}").json()
        if status["state"] not in ("queued", "running"):
            return status
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_upload_rejects_bad_type_and_empty(api):
    r = _upload(api, b"%PDF-1.4", name="report.pdf")
    assert r.status_code == 400 and "Only .log and .txt" in r.json()["detail"]
    r = _upload(api, b"   \n\n")
    assert r.status_code == 400 and "empty" in r.json()["detail"]


def test_full_flow(api):
    lines = [gateway_line(i, ip="203.0.113.44", method="POST", path="/api/v1/auth/login", status=401,
                          ua="python-requests/2.32", auth_result="invalid_password") for i in range(1, 8)]
    r = _upload(api, ("\n".join(lines) + "\n").encode())
    assert r.status_code == 200
    job_id = r.json()["job_id"]

    assert api.get(f"/report/{job_id}").status_code == 409          # not analyzed yet
    assert api.post(f"/analyze/{job_id}").json()["state"] == "queued"
    status = _wait_done(api, job_id)
    assert status["state"] == "completed"
    assert status["entries_processed"] == status["total_entries"] == 7
    assert status["total_chunks"] >= 1 and "backend" in status["ram_mb"]

    findings = api.get(f"/findings/{job_id}").json()
    assert findings["final"] is True
    assert findings["findings"][0]["attack_type"] == "Brute Force"
    assert findings["findings"][0]["source"] == "rules"

    report = api.get(f"/report/{job_id}").json()
    assert report["totals"]["total_entries"] == 7
    dl = api.get(f"/report/{job_id}/download")
    assert "attachment" in dl.headers["content-disposition"]
    assert dl.json() == report


def test_lines_endpoint_returns_raw_text(api):
    lines = [gateway_line(i) for i in range(1, 6)]
    job_id = _upload(api, ("\n".join(lines) + "\n").encode()).json()["job_id"]
    got = api.get(f"/lines/{job_id}", params={"numbers": "2,4,99"}).json()["lines"]
    assert [g["line"] for g in got] == [2, 4]
    assert got[0]["text"] == lines[1]
    assert api.get(f"/lines/{job_id}", params={"numbers": "a,b"}).status_code == 400


def test_unknown_job_is_404(api):
    assert api.get("/status/nope").status_code == 404
    assert api.post("/analyze/nope").status_code == 404
