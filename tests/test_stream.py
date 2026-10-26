import json

from clocked_sdk import AuthenticationError
from fastapi.testclient import TestClient

import app.main as main_mod

client = TestClient(main_mod.app)


def _events(res):
    return [json.loads(line) for line in res.text.splitlines() if line.strip()]


def test_stream_scan_emits_steps_then_result(monkeypatch):
    def fake_scan(text, progress=None):
        for key in ("injection", "pii", "verdict"):
            progress(key)
        return {"action": {"choice": "allow"}}

    monkeypatch.setattr(main_mod, "scan", fake_scan)
    res = client.post("/api/scan?stream=1", json={"text": "hello"})
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("application/x-ndjson")
    events = _events(res)
    assert [e["step"] for e in events if e["type"] == "step"] == ["injection", "pii", "verdict"]
    assert events[-1] == {"type": "result", "data": {"action": {"choice": "allow"}}}


def test_stream_maps_clocked_errors_to_error_event(monkeypatch):
    def fake_scan(text, progress=None):
        raise AuthenticationError("bad key")

    monkeypatch.setattr(main_mod, "scan", fake_scan)
    events = _events(client.post("/api/scan?stream=1", json={"text": "hello"}))
    assert events[-1]["type"] == "error" and events[-1]["status"] == 401


def test_stream_validation_errors_stay_plain_http(monkeypatch):
    res = client.post("/api/scan?stream=1", json={"text": "   "})
    assert res.status_code == 400


def test_stream_url_starts_with_fetch_step(monkeypatch):
    monkeypatch.setattr(main_mod, "summarize_url", lambda url, *, allow_private=False: {"host": "x"})

    def fake_scan_url(url, summary, progress=None):
        progress("extract")
        return {"ok": True}

    monkeypatch.setattr(main_mod, "scan_url", fake_scan_url)
    events = _events(client.post("/api/scan-url?stream=1", json={"url": "example.com"}))
    assert [e["step"] for e in events if e["type"] == "step"] == ["fetch", "extract"]
    assert events[-1]["data"] == {"ok": True}


def test_stream_url_fetch_failure_is_error_event(monkeypatch):
    def boom(url, *, allow_private=False):
        raise ValueError("not allowed")

    monkeypatch.setattr(main_mod, "summarize_url", boom)
    events = _events(client.post("/api/scan-url?stream=1", json={"url": "example.com"}))
    assert events[-1] == {"type": "error", "status": 400, "detail": "not allowed"}


def test_stream_batch_emits_one_step_per_item(monkeypatch):
    def fake_scan(text, progress=None):
        return {"action": {"choice": "allow", "probabilities": {}, "confidence": 1},
                "layers": {"injection": {"injection": 0, "verdict": "benign", "severity": "none"},
                           "script": None, "pii": {"entities": []}},
                "total_ms": 1}

    monkeypatch.setattr(main_mod, "scan", fake_scan)
    monkeypatch.setattr(main_mod, "compare_batch", lambda items: {"groups": [], "conflicts": [], "usage": {}, "ms": 1})
    events = _events(client.post("/api/scan-batch?stream=1", json={"items": ["a", "b", "c"]}))
    assert [e["step"] for e in events if e["type"] == "step"] == ["item:0", "item:1", "item:2", "compare"]
    assert events[-1]["data"]["count"] == 3
