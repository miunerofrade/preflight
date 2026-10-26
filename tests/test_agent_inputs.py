"""Input snapshots and human release use no live model calls."""
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

import app.main as main
import app.agent_inputs as agent_module
from app.agent_inputs import AgentInputStore, digest


def report(status="review", text="Checked copy"):
    return {"source": {"kind": "text"}, "action": {"choice": "allow" if status == "ready" else "block"},
            "layers": {}, "handoff": {"status": status, "text": text}, "usage": {"calls": 4}}


def pending(store):
    result = store.add("inbox/note.txt", "RAW PRIVATE CONTENT", report(), "zh")
    token = parse_qs(urlsplit(result["review_url"]).query)["review_token"][0]
    return result["ticket"], token


def test_only_exact_approved_snapshot_is_released_and_rejection_is_final():
    store = AgentInputStore()
    ticket, token = pending(store)
    assert "content" not in store.result(ticket)
    with pytest.raises(PermissionError):
        store.decide(ticket, "wrong", digest("Checked copy"), True)
    with pytest.raises(ValueError, match="hash"):
        store.decide(ticket, token, digest("different"), True)
    store.decide(ticket, token, digest("Checked copy"), True)
    result = store.result(ticket)
    assert result["content"] == "Checked copy"
    assert store.review(ticket, token)["receipt"]["human_approved"] is True
    assert set(result) == {"ticket", "status", "content"}
    assert "RAW PRIVATE CONTENT" not in str(result)
    second, token = pending(store)
    store.decide(second, token, digest("Checked copy"), False)
    assert "content" not in store.result(second)
    with pytest.raises(ValueError):
        store.decide(second, token, digest("Checked copy"), True)


def test_ready_blocked_expired_and_queue_bounds():
    store = AgentInputStore(capacity=2)
    ready = store.add("note.txt", "Clean", report("ready", "Clean"), "en")
    assert ready["content"] == "Clean" and "report" not in ready and "receipt" not in ready
    blocked = store.add("note.txt", "Raw", report("withheld", None), "en")
    assert blocked["status"] == "blocked" and "content" not in blocked
    with pytest.raises(ValueError, match="full"):
        pending(store)
    store.ttl = 0
    with pytest.raises(KeyError):
        store.result(ready["ticket"])


def test_file_reader_is_workspace_scoped_and_snapshots_utf8():
    with TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "note.txt").write_text("📋 Ordinary note", encoding="utf-8")
        (root / ".env").write_text("DO NOT READ", encoding="utf-8")
        store = AgentInputStore(root)
        assert store.read_file("note.txt") == ("📋 Ordinary note", None)
        with pytest.raises(ValueError):
            store.read_file("../outside.txt")
        with pytest.raises(ValueError):
            store.read_file(".env")


def test_browser_approval_requires_local_origin_token_and_copy_hash(monkeypatch):
    store = AgentInputStore()
    monkeypatch.setattr(main, "agent_inputs", store)
    ticket, token = pending(store)
    client = TestClient(main.app, base_url="http://127.0.0.1")
    response = client.get(f"/api/agent-inputs/{ticket}", params={"review_token": token})
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    assert response.json()["report"]["handoff"]["text"] == "Checked copy"
    body = {"review_token": token, "candidate_sha256": digest("Checked copy"), "approve": True}
    url = f"/api/agent-inputs/{ticket}/decision"
    assert client.post(url, json=body, headers={"Origin": "https://other.example"}).status_code == 403
    assert "content" not in store.result(ticket)
    assert client.post(url, json=body, headers={"Origin": "http://127.0.0.1"}).json() == {"status": "released"}
    assert store.result(ticket)["content"] == "Checked copy"


def test_file_check_releases_a_snapshot_and_blocked_url_does_not_scan_body(monkeypatch):
    with TemporaryDirectory() as directory:
        root = Path(directory)
        path = root / "note.txt"
        path.write_text("Checked original snapshot", encoding="utf-8")
        store = AgentInputStore(root)
        monkeypatch.setattr(agent_module, "scan", lambda text, **_: report("ready", text))
        result = store.check("note.txt")
        path.write_text("Changed after checking", encoding="utf-8")
        assert store.result(result["ticket"])["content"] == "Checked original snapshot"
        monkeypatch.setattr(agent_module, "summarize_url", lambda _: {"page": {"body_text": "Raw page body"}})
        monkeypatch.setattr(agent_module, "scan_url", lambda *_: report("withheld", None))
        monkeypatch.setattr(agent_module, "scan", lambda *_a, **_k: pytest.fail("blocked URL must stop early"))
        blocked = store.check("https://example.com")
        assert blocked["status"] == "blocked" and "content" not in blocked


def test_revision_rebinds_a_pending_ticket_to_the_rescanned_copy():
    store = AgentInputStore()
    ticket, token = pending(store)
    revised = store.revise(ticket, token, report("review", "Edited checked copy"))
    assert revised["status"] == "pending"
    review = store.review(ticket, token)
    assert review["candidate_sha256"] == digest("Edited checked copy")
    # approval now binds to the new copy; the old hash no longer releases anything
    with pytest.raises(ValueError, match="hash"):
        store.decide(ticket, token, digest("Checked copy"), True)
    store.decide(ticket, token, digest("Edited checked copy"), True)
    assert store.result(ticket)["content"] == "Edited checked copy"


def test_revision_rejects_wrong_token_released_and_blocked_rescans():
    store = AgentInputStore()
    ticket, token = pending(store)
    with pytest.raises(PermissionError):
        store.revise(ticket, "wrong", report("review", "x"))
    store.revise(ticket, token, report("review", "Edited"))
    store.decide(ticket, token, digest("Edited"), True)
    with pytest.raises(ValueError, match="pending"):
        store.revise(ticket, token, report("review", "Again"))
    second, second_token = pending(store)
    store.revise(second, second_token, report("withheld", None))
    assert store.review(second, second_token)["candidate_sha256"] is None
    assert store.result(second)["status"] == "blocked"
