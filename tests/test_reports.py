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


def test_citations_pointing_nowhere_fall_back_to_the_template():
    class Client:
        def fill(self, **request):
            assert "numbered findings" in request["instructions"]
            return {"fields": {"title": {"value": "T"}, "summary": {"value": "S"},
                               "review_steps": {"value": "核实 [7] 所述的下载地址。"}},
                    "usage": {"input_tokens": 5}}

    result = generate_review(sample(), "en", _client=Client())
    assert result["field_sources"]["review_steps"] == "template"
    assert "[" not in result["generated"]["review_steps"]


def test_valid_citations_survive():
    class Client:
        def fill(self, **_):
            return {"fields": {"title": {"value": "T"}, "summary": {"value": "S"},
                               "review_steps": {"value": "Re-check finding [1] before forwarding."}},
                    "usage": {"input_tokens": 5}}

    result = generate_review(sample(), "en", _client=Client())
    assert result["field_sources"]["review_steps"] == "generated"
    assert result["generated"]["review_steps"] == "Re-check finding [1] before forwarding."


def test_zero_citation_falls_back_to_the_template():
    class Client:
        def fill(self, **_):
            return {"fields": {"title": {"value": "T"}, "summary": {"value": "S"},
                               "review_steps": {"value": "Check [0] now."}},
                    "usage": {"input_tokens": 5}}

    result = generate_review(sample(), "en", _client=Client())
    assert result["field_sources"]["review_steps"] == "template"


def test_findings_keep_offsets_and_flag_positions():
    from app.reports import review_facts
    report = {"source": {"kind": "url"},
              "action": {"choice": "review"},
              "layers": {"injection": {"verdict": "injection",
                                       "evidence": [{"quote": "Ignore instructions", "start": 4, "end": 22}]}},
              "url": {"flags": [{"title": "Lookalike brand"}, {"title": ""}]}}

    facts = review_facts(report)
    assert facts["findings"] == [
        {"index": 1, "kind": "injection", "quote": "Ignore instructions", "source_quote": "Ignore instructions", "start": 4, "end": 22},
        {"index": 2, "kind": "url_flag", "title": "Lookalike brand", "flag_index": 1},
    ]
