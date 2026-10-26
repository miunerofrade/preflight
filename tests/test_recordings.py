"""Replay public synthetic-case recordings, with no key, network or paid calls."""
import json
from pathlib import Path

import pytest

from app.recordings import ReplayClient
from app.scanner import scan
from scripts.record_cases import outcome

ROOT = Path(__file__).resolve().parent.parent
RECORDINGS = sorted((ROOT / "tests" / "fixtures" / "recordings").glob("*.json"))


def test_every_versioned_case_has_a_recording():
    cases = json.loads((ROOT / "cases" / "text.json").read_text(encoding="utf-8"))
    assert {case["id"] for case in cases} == {path.stem for path in RECORDINGS}


@pytest.mark.parametrize("path", RECORDINGS, ids=lambda p: p.stem)
def test_real_responses_replay_the_entire_scan_and_copy_checks(path):
    recording = json.loads(path.read_text(encoding="utf-8"))
    replay = ReplayClient(recording["calls"])
    report = scan(recording["case"]["text"], _client=replay)
    replay.assert_complete()
    assert outcome(report) == recording["outcome"]
    assert report["action"]["choice"] == recording["case"]["expected_action"]
    assert report["usage"] == recording["report"]["usage"]
    assert all(call["metadata"]["status"] == 200 for call in recording["calls"])


def test_replay_refuses_different_requests_and_never_falls_back_to_api():
    replay = ReplayClient([{"method": "injection", "request": {"text": "recorded"}, "response": {}}])
    with pytest.raises(AssertionError, match="request changed"):
        replay.injection(text="different")
