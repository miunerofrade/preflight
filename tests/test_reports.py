"""Focused checks for optional report generation; no network calls."""
import copy

import pytest
from fastapi.testclient import TestClient
from clocked_sdk import RequestTimeoutError

import app.main as main
from app.reports import generate_review


def sample():
    return {"source": {"kind": "text"}, "action": {"choice": "block"},
            "layers": {"injection": {"verdict": "injection", "evidence": [{"quote": "Untrusted instruction"}]}},
            "handoff": {"status": "withheld", "reason": "residual_risk", "draft_text": "DO NOT SEND TO FILL"}}


def test_fill_only_generates_notes_and_keeps_fixed_facts():
    report = sample()
    before = copy.deepcopy(report)

    class Client:
        def fill(self, **request):
            assert "Simplified Chinese" in request["instructions"]
            assert "DO NOT SEND TO FILL" not in request["text"]
            assert all(field["type"] == "generate" for field in request["fields"].values())
            return {"fields": {key: {"value": "null" if key == "review_steps" else "Generated note"}
                               for key in request["fields"]}, "usage": {"input_tokens": 12}}

    result = generate_review(report, "zh", _client=Client())
    assert report == before
    assert result["facts"]["action"]["choice"] == "block"
    assert result["facts"]["handoff"]["status"] == "withheld"
    assert result["language"] == "zh" and result["calls"] == 1
    assert result["field_sources"]["review_steps"] == "template"
    assert result["generated"]["review_steps"] != "null"


def test_report_endpoint_validates_language_and_maps_fill_failure(monkeypatch):
    client = TestClient(main.app)
    assert client.post("/api/review-report", json={"report": sample(), "language": "fr"}).status_code == 422
    assert client.post("/api/review-report", json={"report": {}}).status_code == 400

    def timeout(*_):
        raise RequestTimeoutError("timeout")

    monkeypatch.setattr(main, "generate_review", timeout)
    assert client.post("/api/review-report", json={"report": sample(), "language": "en"}).status_code == 504


def test_incomplete_fill_response_is_not_a_finished_report():
    class Client:
        def fill(self, **_):
            return {"fields": {"title": {"value": "Only a title"}}}

    with pytest.raises(ValueError, match="incomplete"):
        generate_review(sample(), "en", _client=Client())
