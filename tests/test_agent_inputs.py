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


def test_revision_scans_server_side_and_rebinds(monkeypatch):
    store = AgentInputStore()
    ticket, token = pending(store)
    old_hash = store.review(ticket, token)["candidate_sha256"]

    calls = []

    def fake_scan(text, **_):
        calls.append(text)
        return report("review", f"Copy of {text}")

    monkeypatch.setattr(agent_module, "scan", fake_scan)
    result = store.revise(ticket, token, 0, "req-1", "Edited by human")
    assert result["status"] == "bound" and result["revision"] == 1
    assert result["ticket_status"] == "pending"  # a human edit always needs one more confirm
    assert result["candidate_sha256"] == digest("Copy of Edited by human")
    assert calls == ["Edited by human"]  # the server scanned the submitted text itself

    # the old version and the old hash can no longer be approved
    with pytest.raises(ValueError, match="hash"):
        store.decide(ticket, token, old_hash, True)
    store.decide(ticket, token, digest("Copy of Edited by human"), True)
    assert store.result(ticket)["content"] == "Copy of Edited by human"
    summary = store.review(ticket, token)["revisions"]
    assert [(r["index"], r["parent"]) for r in summary] == [(0, -1), (1, 0)]
    assert summary[1]["submitted_sha256"] == digest("Edited by human")


def test_forged_report_cannot_release_text(monkeypatch):
    """The revision endpoint takes text only; there is no way to submit a verdict,
    a candidate or a hash from the client."""
    store = AgentInputStore()
    ticket, token = pending(store)

    def fake_scan(text, **_):
        return report("review", "Server copy")

    monkeypatch.setattr(agent_module, "scan", fake_scan)
    store.revise(ticket, token, 0, "req-1", "honest edit")
    assert store.result(ticket)["status"] == "pending"
    assert "content" not in store.result(ticket)
    # a forged report is not a valid revision payload: revise() has no report parameter,
    # and decide still requires the server-computed hash
    with pytest.raises(ValueError):
        store.decide(ticket, token, digest("FORGED RELEASE"), True)
    assert store.review(ticket, token)["candidate_sha256"] == digest("Server copy")


def test_failed_revision_blocks_the_old_copy_until_resolved(monkeypatch):
    store = AgentInputStore()
    ticket, token = pending(store)

    def boom(text, **_):
        raise RuntimeError("scan down")

    monkeypatch.setattr(agent_module, "scan", boom)
    with pytest.raises(RuntimeError):
        store.revise(ticket, token, 0, "req-1", "Edited by human")
    review = store.review(ticket, token)
    assert review["revising"]["state"] == "failed" and "scan down" in review["revising"]["error"]
    with pytest.raises(ValueError, match="revision is in progress"):
        store.decide(ticket, token, review["candidate_sha256"], True)
    assert "content" not in store.result(ticket)

    # retrying the same operation id and text reruns the scan and succeeds
    monkeypatch.setattr(agent_module, "scan", lambda text, **_: report("review", f"Copy of {text}"))
    result = store.revise(ticket, token, 0, "req-1", "Edited by human")
    assert result["status"] == "bound" and result["candidate_sha256"] == digest("Copy of Edited by human")

    # abandoning an unresolved revision restores the previous version explicitly
    ticket2, token2 = pending(store)
    monkeypatch.setattr(agent_module, "scan", boom)
    with pytest.raises(RuntimeError):
        store.revise(ticket2, token2, 0, "req-2", "Another edit")
    store.abandon_revision(ticket2, token2)
    review2 = store.review(ticket2, token2)
    assert review2["revising"] is None and review2["revision"] == 0
    store.decide(ticket2, token2, review2["candidate_sha256"], True)
    assert store.result(ticket2)["content"] == "Checked copy"


def test_revision_idempotency_and_conflicts(monkeypatch):
    store = AgentInputStore()
    ticket, token = pending(store)
    calls = []

    def fake_scan(text, **_):
        calls.append(text)
        return report("review", f"Copy of {text}")

    monkeypatch.setattr(agent_module, "scan", fake_scan)
    first = store.revise(ticket, token, 0, "req-1", "Edited once")
    replay = store.revise(ticket, token, 0, "req-1", "Edited once")
    assert replay["candidate_sha256"] == first["candidate_sha256"] and calls == ["Edited once"]

    with pytest.raises(ValueError, match="different content"):
        store.revise(ticket, token, 0, "req-1", "Edited differently")
    with pytest.raises(ValueError, match="updated elsewhere"):
        store.revise(ticket, token, 0, "req-2", "Second edit")
    second = store.revise(ticket, token, 1, "req-2", "Second edit")
    assert second["revision"] == 2 and second["report"] == store.review(ticket, token)["report"]
    with pytest.raises(ValueError, match="updated elsewhere"):
        store.revise(ticket, token, 0, "req-3", "Stale page edit")
