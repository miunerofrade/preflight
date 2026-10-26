"""Record real Clocked responses for the versioned, synthetic text corpus.

Run: uv run python -m scripts.record_cases --record
Without --record, replay existing fixtures offline. Existing recordings are never
overwritten; use a new output directory to record a later model/policy snapshot.
"""
from __future__ import annotations

import argparse
import datetime as dt
import importlib.metadata
import json
import os
from pathlib import Path

from clocked_sdk import Clocked

from app.policy import POLICY_VERSION
from app.recordings import RecordingClient, ReplayClient
from app.scanner import scan

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = ROOT / "tests" / "fixtures" / "recordings"


def outcome(report: dict) -> dict:
    handoff = report["handoff"]
    return {"action": report["action"]["choice"], "model_choice": report["action"]["model_choice"],
            "handoff": handoff["status"], "changes": handoff["changes"],
            "copy": handoff["text"], "reason": handoff["reason"]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", action="store_true", help="Spend credits recording the synthetic corpus")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--case", action="append", help="Record/replay only this case id (repeatable)")
    args = parser.parse_args()
    cases = json.loads((ROOT / "cases" / "text.json").read_text(encoding="utf-8"))
    if args.case:
        unknown = set(args.case) - {case["id"] for case in cases}
        if unknown:
            parser.error(f"Unknown case ids: {', '.join(sorted(unknown))}")
        cases = [case for case in cases if case["id"] in args.case]
    if args.record:
        env = ROOT / ".env"
        if env.exists():
            for line in env.read_text(encoding="utf-8").splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    key, value = line.split("=", 1)
                    if key.strip() == "CLOCKED_API_KEY":
                        os.environ.setdefault("CLOCKED_API_KEY", value.strip())
        if not os.environ.get("CLOCKED_API_KEY"):
            parser.error("Set CLOCKED_API_KEY before recording.")
        existing = [case["id"] for case in cases if (args.output / f"{case['id']}.json").exists()]
        if existing:
            parser.error(f"Will not overwrite recordings: {', '.join(existing)}")
        client = RecordingClient(Clocked(timeout=40, max_attempts=2))
        args.output.mkdir(parents=True, exist_ok=True)
    rows = []
    for case in cases:
        path = args.output / f"{case['id']}.json"
        if args.record:
            first = len(client.calls)
            report = scan(case["text"], _client=client)
            recording = {"schema_version": 1, "recorded_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                         "sdk_version": importlib.metadata.version("clocked-sdk"), "policy_version": POLICY_VERSION,
                         "case": case, "calls": client.calls[first:], "outcome": outcome(report), "report": report}
            path.write_text(json.dumps(recording, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        else:
            recording = json.loads(path.read_text(encoding="utf-8"))
            replay = ReplayClient(recording["calls"])
            report = scan(recording["case"]["text"], _client=replay)
            replay.assert_complete()
            assert outcome(report) == recording["outcome"], f"Behavior changed for {case['id']}"
        observed = outcome(report)
        matches = observed["action"] == case["expected_action"] and observed["handoff"] == case["expected_handoff"]
        credits = sum((call.get("metadata") or {}).get("credits") or 0 for call in recording["calls"])
        row = {"case": case["id"], "expected": case["expected_action"], "actual": observed["action"],
               "expected_handoff": case["expected_handoff"], "handoff": observed["handoff"],
               "matches": matches, "calls": len(recording["calls"]), "credits": credits}
        rows.append(row)
        print(json.dumps(row, ensure_ascii=False), flush=True)
    print(f"{sum(row['matches'] for row in rows)}/{len(rows)} cases match expectations. "
          "This is a small synthetic regression corpus, not an accuracy benchmark.")


if __name__ == "__main__":
    main()
