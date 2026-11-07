import json
from pathlib import Path

import pytest

SAMPLE_LOG = Path(__file__).resolve().parents[2] / "sample_logs" / "Cultive8_Workspace_Agrigen_Server.log"


def gateway_line(n: int, ip="198.51.100.10", path="/api/v1/items", status=200,
                 ua="Mozilla/5.0 X", method="GET", **extra) -> str:
    """Build one JSON gateway line in the same shape as the sample log."""
    data = {"time": f"2026-11-01T08:{n // 60 % 60:02d}:{n % 60:02d}.000Z", "app": "demo",
            "service": "gateway", "level": "INFO", "client_ip": ip, "request_id": f"req-{n}",
            "method": method, "path": path, "status": status, "response_bytes": 1000,
            "duration_ms": 10, "user_agent": ua}
    data.update(extra)
    return json.dumps(data)


@pytest.fixture
def write_log(tmp_path):
    def _write(lines, name="test.log"):
        p = tmp_path / name
        p.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        return p
    return _write
