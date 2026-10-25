"""API layer tests - the scan function is stubbed; the Clocked API is never touched."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from clocked_sdk import AuthenticationError, RateLimitError, RequestTimeoutError

import app.main as main_mod


@pytest.fixture
def client():
    return TestClient(main_mod.app)


@pytest.fixture
def stub_scan(monkeypatch):
    def _stub(impl):
        monkeypatch.setattr(main_mod, "scan", impl)

    return _stub


def test_index_serves_the_app(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "Preflight" in res.text
    assert "/static/style.css" in res.text


def test_static_assets_are_served(client):
    assert client.get("/static/style.css").status_code == 200
    assert client.get("/static/app.js").status_code == 200


def test_scan_empty_text_is_rejected(client):
    res = client.post("/api/scan", json={"text": "   "})
    assert res.status_code == 400


def test_scan_over_limit_is_rejected(client):
    res = client.post("/api/scan", json={"text": "x" * 20_001})
    assert res.status_code == 400


def test_scan_success_returns_report(client, stub_scan):
    payload = {
        "action": {"choice": "block", "probabilities": {}, "confidence": 0.99},
        "routing": {"contains_code": True},
        "layers": {},
        "usage": {"calls": 5, "input_tokens": 259, "output_tokens": 5},
        "total_ms": 2427,
    }
    stub_scan(lambda text: payload)
    res = client.post("/api/scan", json={"text": "some content"})
    assert res.status_code == 200
    assert res.json()["action"]["choice"] == "block"
    assert res.json()["usage"]["calls"] == 5


def test_auth_error_maps_to_401(client, stub_scan):
    def boom(text):
        raise AuthenticationError("invalid api key")

    stub_scan(boom)
    res = client.post("/api/scan", json={"text": "some content"})
    assert res.status_code == 401
    assert "CLOCKED_API_KEY" in res.json()["detail"]


def test_rate_limit_maps_to_429(client, stub_scan):
    def boom(text):
        raise RateLimitError("slow down", status=429)

    stub_scan(boom)
    res = client.post("/api/scan", json={"text": "some content"})
    assert res.status_code == 429


def test_timeout_maps_to_504(client, stub_scan):
    def boom(text):
        raise RequestTimeoutError("timed out")

    stub_scan(boom)
    res = client.post("/api/scan", json={"text": "some content"})
    assert res.status_code == 504


# ---------- batch ----------


def _report(action="allow", injection=0.01):
    return {
        "action": {"choice": action, "probabilities": {}, "confidence": 0.9},
        "routing": {"contains_code": False, "probabilities": {}, "confidence": 0.9},
        "layers": {
            "injection": {"injection": injection, "verdict": "benign", "severity": "none", "evidence": []},
            "script": None,
            "pii": {"entities": [], "counts": {}, "mentions": [], "anonymized_text": None},
        },
        "usage": {"calls": 4, "input_tokens": 100, "output_tokens": 4},
        "total_ms": 500,
        "source": {"kind": "text", "name": ""},
    }


def test_batch_rejects_empty(client):
    res = client.post("/api/scan-batch", json={"items": ["", "   "]})
    assert res.status_code == 400


def test_batch_rejects_more_than_ten(client):
    res = client.post("/api/scan-batch", json={"items": [f"item {i}" for i in range(11)]})
    assert res.status_code == 400


def test_batch_ranks_block_before_allow(client, stub_scan):
    stub_scan(lambda text: _report("block" if "bad" in text else "allow", 0.9 if "bad" in text else 0.1))
    res = client.post("/api/scan-batch", json={"items": ["good item", "bad item"]})
    assert res.status_code == 200
    body = res.json()
    assert body["count"] == 2
    assert body["results"][0]["action"]["choice"] == "block"
    assert body["results"][0]["preview"] == "bad item"
    assert body["results"][1]["action"]["choice"] == "allow"
    assert "full" in body["results"][0]


# ---------- file scan ----------


def test_scan_file_rejects_unsupported_type(client):
    res = client.post(
        "/api/scan-file",
        files={"file": ("notes.txt", b"just text", "text/plain")},
    )
    assert res.status_code == 400
    assert "PDF and image" in res.json()["detail"]


def test_scan_file_empty_is_rejected(client):
    res = client.post(
        "/api/scan-file",
        files={"file": ("empty.pdf", b"", "application/pdf")},
    )
    assert res.status_code == 400


def test_scan_file_pdf_passes_bytes_to_scanner(client, monkeypatch):
    captured = {}

    def fake_scan(**kw):
        captured.update(kw)
        return _report("block", 0.99)

    monkeypatch.setattr(main_mod, "scan", fake_scan)
    res = client.post(
        "/api/scan-file",
        files={"file": ("contract.pdf", b"%PDF-1.4 fake bytes", "application/pdf")},
    )
    assert res.status_code == 200
    assert captured["pdf"] == b"%PDF-1.4 fake bytes"
    assert captured["source_name"] == "contract.pdf"


def test_scan_file_image_passes_images_to_scanner(client, monkeypatch):
    captured = {}

    def fake_scan(**kw):
        captured.update(kw)
        return _report("review", 0.4)

    monkeypatch.setattr(main_mod, "scan", fake_scan)
    res = client.post(
        "/api/scan-file",
        files={"file": ("shot.png", b"\x89PNG fake", "image/png")},
    )
    assert res.status_code == 200
    assert captured["images"] == [b"\x89PNG fake"]
