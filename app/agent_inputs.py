"""Bounded, process-local Codex input tickets and explicit human release."""
from __future__ import annotations

import datetime as dt
import hashlib
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pymupdf

from .pdfcheck import inspect_pdf
from .policy import enforce_policy
from .scanner import scan, scan_url
from .webcheck import summarize_url

ROOT = Path(__file__).resolve().parent.parent
MAX_TEXT = 20_000
MAX_BYTES = 10 * 1024 * 1024
TEXT_SUFFIXES = {".txt", ".md", ".rst", ".csv", ".json", ".yaml", ".yml", ".xml", ".html", ".htm",
                 ".log", ".py", ".js", ".ts", ".sh", ".ps1", ".sql", ".toml"}


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class Revision:
    """One bound version of a ticket. The server, not the client, produced the report
    and the candidate; submitted_* describes what the human sent for this version."""
    index: int
    parent: int
    submitted_sha256: str
    report: dict[str, Any]
    candidate: str | None
    candidate_sha256: str | None
    created: float
    submitted_text: str = ""
    approved: bool = False
    decided_at: float | None = None
    decision: str | None = None

    def summary(self) -> dict[str, Any]:
        return {
            "index": self.index, "parent": self.parent,
            "submitted_sha256": self.submitted_sha256,
            "candidate_sha256": self.candidate_sha256,
            "created": dt.datetime.fromtimestamp(self.created, dt.timezone.utc).isoformat(),
            "approved": self.approved, "decision": self.decision,
            "decided_at": (dt.datetime.fromtimestamp(self.decided_at, dt.timezone.utc).isoformat()
                           if self.decided_at is not None else None),
            "submitted_text": self.submitted_text, "candidate": self.candidate, "report": self.report,
        }


@dataclass
class AgentInput:
    ticket: str
    review_token: str
    created: float
    language: str
    source: str
    text: str
    report: dict[str, Any]
    candidate: str | None
    candidate_sha256: str | None
    status: str
    approved: bool = False
    revision: int = 0
    revisions: list[Revision] = field(default_factory=list)
    # an accepted revision operation: {request_id, text_sha256, state, error, result};
    # while it exists the previously bound copy cannot be approved
    revising: dict[str, Any] | None = None
    operations: dict[str, dict[str, Any]] = field(default_factory=dict)


def _candidate_and_status(report: dict) -> tuple[str | None, str]:
    """The checkable copy and ticket status a scan report implies (shared by add/revise)."""
    handoff = report.get("handoff") or {}
    candidate = handoff.get("text")
    action = (report.get("action") or {}).get("choice")
    status = ("released" if handoff.get("status") == "ready" and action == "allow" else "pending") if (
        isinstance(candidate, str) and handoff.get("status") in {"ready", "review"}) else "blocked"
    if status == "blocked":
        candidate = None
    return candidate, status


class AgentInputStore:
    def __init__(self, root: Path = ROOT, *, ttl: int = 1800, capacity: int = 32):
        self.root = root.resolve()
        self.ttl = ttl
        self.capacity = capacity
        self.base_url = ""
        self._items: dict[str, AgentInput] = {}
        self._lock = threading.RLock()

    def _prune(self) -> None:
        now = time.monotonic()
        for ticket, item in list(self._items.items()):
            if now - item.created >= self.ttl:
                del self._items[ticket]

    def read_file(self, source: str) -> tuple[str, dict | None]:
        requested = Path(source)
        if requested.is_absolute() and not requested.is_relative_to(self.root):
            raise ValueError("File must be inside the Preflight workspace.")
        path = (self.root / requested).resolve()
        if not path.is_relative_to(self.root):
            raise ValueError("File must be inside the Preflight workspace.")
        relative = path.relative_to(self.root)
        if any(part.lower() in {".git", ".venv", "node_modules", ".codex", ".cache"} for part in relative.parts):
            raise ValueError("Internal configuration and dependency directories are not input documents.")
        if path.name.lower().startswith(".env") or path.suffix.lower() in {".pem", ".key", ".pfx"}:
            raise ValueError("Credential files are not input documents.")
        if path.suffix.lower() not in TEXT_SUFFIXES | {".pdf"}:
            raise ValueError("Use a UTF-8 text document or a text-layer PDF.")
        with path.open("rb") as stream:
            data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError("Document exceeds the 10 MB limit.")
        pdf = None
        if path.suffix.lower() == ".pdf":
            with pymupdf.open(stream=data, filetype="pdf") as document:
                if document.needs_pass or len(document) > 20:
                    raise ValueError("Use an unencrypted PDF with at most 20 pages.")
                text = "\n".join(page.get_text("text", sort=True) for page in document)
            pdf = inspect_pdf(data)
        else:
            text = data.decode("utf-8-sig")
        if not text.strip() or len(text) > MAX_TEXT or "\x00" in text:
            raise ValueError("Document must contain 1–20,000 readable text characters.")
        return text, pdf

    def check(self, source: str, language: str = "en") -> dict:
        if language not in {"en", "zh"}:
            raise ValueError("Language must be en or zh.")
        with self._lock:
            self._prune()
            if len(self._items) >= self.capacity:
                raise ValueError("Review queue is full. Wait for old tickets to expire or reconnect.")
        url_report = None
        if source.startswith(("http://", "https://")):
            page = summarize_url(source)  # Keep the existing SSRF checks, including every redirect.
            text = page["page"]["body_text"]
            if not text.strip() or len(text) > MAX_TEXT:
                raise ValueError("Page text must contain 1–20,000 characters; it is not silently truncated.")
            url_report = scan_url(source, page)
            if url_report["action"]["choice"] == "block":
                return self.add(source, text, url_report, language)
            pdf = None
        else:
            text, pdf = self.read_file(source)
        # The text pipeline also checks PII and constructs a source-validated copy.
        report = scan(text, source_name=source)
        if pdf is not None:
            report["pdf_inspection"] = pdf
            enforce_policy(report)
            if report["action"]["choice"] != "allow" and report["handoff"]["status"] == "ready":
                report["handoff"]["status"] = "review"
            if pdf.get("status") != "complete":
                report["handoff"]["status"] = "withheld"
                report["handoff"]["text"] = None
        if url_report:
            report["url_report"] = url_report
            for key in ("input_tokens", "output_tokens", "calls"):
                report["usage"][key] += url_report["usage"].get(key, 0)
            report["total_ms"] += url_report["total_ms"]
            if url_report["action"]["choice"] == "block":
                report["handoff"].update(status="withheld", text=None, reason="agent_url_blocked")
            elif url_report["action"]["choice"] == "review" and report["handoff"]["status"] == "ready":
                report["handoff"]["status"] = "review"
            rank = {"allow": 0, "review": 1, "block": 2}
            if rank[url_report["action"]["choice"]] > rank[report["action"]["choice"]]:
                report["action"]["choice"] = url_report["action"]["choice"]
                report["action"]["overridden"] = True
            report["policy"]["reasons"].extend(url_report["policy"]["reasons"])
        return self.add(source, text, report, language)

    def add(self, source: str, text: str, report: dict, language: str) -> dict:
        candidate, status = _candidate_and_status(report)
        item = AgentInput(secrets.token_urlsafe(24), secrets.token_urlsafe(32), time.monotonic(), language,
                          source, text, report, candidate, digest(candidate) if candidate is not None else None, status)
        item.revisions = [Revision(0, -1, digest(text), report, candidate,
                                   item.candidate_sha256, time.time(), submitted_text=text)]
        with self._lock:
            self._prune()
            if len(self._items) >= self.capacity:
                raise ValueError("Review queue is full. Wait for old tickets to expire or reconnect.")
            self._items[item.ticket] = item
            return self._result(item)

    def _get(self, ticket: str) -> AgentInput:
        self._prune()
        if ticket not in self._items:
            raise KeyError("Input ticket expired or does not exist. Scan the source again.")
        return self._items[ticket]

    def _result(self, item: AgentInput) -> dict:
        result: dict[str, Any] = {
            "ticket": item.ticket, "status": item.status,
        }
        if item.status == "released":
            result["content"] = item.candidate
        elif item.status in {"pending", "blocked"}:
            result["review_url"] = f"{self.base_url}/?agent_input={item.ticket}&review_token={item.review_token}"
        return result

    def result(self, ticket: str) -> dict:
        with self._lock:
            return self._result(self._get(ticket))

    def _authorized(self, ticket: str, token: str) -> AgentInput:
        item = self._get(ticket)
        if not secrets.compare_digest(item.review_token.encode("utf-8"), token.encode("utf-8")):
            raise PermissionError("Invalid review token.")
        return item

    def review(self, ticket: str, token: str) -> dict:
        with self._lock:
            item = self._authorized(ticket, token)
            op = item.revising
            revising = ({key: op[key] for key in
                         ("request_id", "base_revision", "text", "state", "error")} if op else None)
            return {"source": item.source, "text": item.revisions[-1].submitted_text,
                    "original_text": item.text, "report": item.report,
                    "candidate_sha256": item.candidate_sha256, "status": item.status, "language": item.language,
                    "revision": item.revision, "revising": revising,
                    "revisions": [r.summary() for r in item.revisions],
                    "receipt": {"source_sha256": digest(item.text),
                                "submitted_sha256": item.revisions[-1].submitted_sha256,
                                "copy_sha256": item.candidate_sha256, "human_approved": item.approved}}

    def revise(self, ticket: str, token: str, base_revision: int, request_id: str, text: str) -> dict:
        if not text.strip() or len(text) > MAX_TEXT or "\x00" in text:
            raise ValueError("The edited text must contain 1-20,000 readable characters.")
        if not request_id or len(request_id) > 128:
            raise ValueError("A request id of at most 128 characters is required.")
        text_sha = digest(text)
        with self._lock:
            item = self._authorized(ticket, token)
            op = item.operations.get(request_id)
            if op is not None:
                if op["text_sha256"] != text_sha or op["base_revision"] != base_revision:
                    raise ValueError("This request id was already used with different content or version.")
                if op["state"] == "done":
                    return op["result"]
                if op["state"] == "abandoned":
                    raise ValueError("This revision was abandoned. Use a new request id.")
                if op["state"] == "scanning":
                    return {"status": "revising", "request_id": request_id}
            if base_revision != item.revision:
                raise ValueError("This ticket was updated elsewhere. Refresh the review page.")
            if item.status != "pending":
                raise ValueError("Only a pending ticket can be revised.")
            if item.revising is not None and item.revising is not op:
                raise ValueError("Another revision is unresolved. Refresh the review page.")
            if op is None:
                if len(item.operations) >= 64:
                    raise ValueError("Revision limit reached. Start a new input ticket.")
                op = {"request_id": request_id, "base_revision": base_revision,
                      "text_sha256": text_sha, "text": text, "state": "scanning", "error": None}
                item.operations[request_id] = op
            op.update(state="scanning", error=None)
            item.revising = op
        # No global lock during paid work. Abandonment invalidates this exact operation.
        try:
            report = scan(text, source_name=item.source)
        except Exception:
            with self._lock:
                if item.revising is op and op["state"] == "scanning":
                    op.update(state="failed", error="Revision check failed. Retry or abandon this edit.")
            raise
        with self._lock:
            current = self._get(ticket)  # Also enforce TTL when the scan finishes.
            if (current is not item or item.revising is not op or op["state"] != "scanning"
                    or item.revision != base_revision or item.status != "pending"):
                raise ValueError("The ticket changed during the revision. Refresh the review page.")
            candidate, status = _candidate_and_status(report)
            if status == "released":
                status = "pending"  # Editing is never implicit approval.
            entry = Revision(item.revision + 1, item.revision, text_sha, report, candidate,
                             digest(candidate) if candidate is not None else None, time.time(),
                             submitted_text=text)
            item.revisions.append(entry)
            item.revision = entry.index
            item.report, item.candidate = report, candidate
            item.candidate_sha256, item.status, item.approved = entry.candidate_sha256, status, False
            result = {"status": "bound", "request_id": request_id, "revision": entry.index,
                      "ticket_status": status, "candidate_sha256": entry.candidate_sha256}
            op.update(state="done", result=result)
            item.revising = None
            return result

    def abandon_revision(self, ticket: str, token: str, base_revision: int, request_id: str) -> dict:
        with self._lock:
            item = self._authorized(ticket, token)
            op = item.revising
            if (op is None or op["request_id"] != request_id or base_revision != item.revision):
                raise ValueError("The revision changed. Refresh the review page.")
            op["state"] = "abandoned"
            item.revising = None
            return {"status": item.status, "revision": item.revision,
                    "candidate_sha256": item.candidate_sha256}

    def decide(self, ticket: str, token: str, candidate_sha256: str, approve: bool,
               base_revision: int) -> dict:
        with self._lock:
            item = self._authorized(ticket, token)
            if base_revision != item.revision:
                raise ValueError("This ticket was updated elsewhere. Refresh the review page.")
            if item.revising is not None:
                raise ValueError("A revision is in progress. Abandon it or wait for it to finish.")
            if item.status != "pending" or item.candidate is None:
                raise ValueError("Only a pending, checked copy can be approved or rejected.")
            if not secrets.compare_digest((item.candidate_sha256 or "").encode("utf-8"), candidate_sha256.encode("utf-8")):
                raise ValueError("Copy hash changed. Review the current copy first.")
            item.status = "released" if approve else "rejected"
            item.approved = approve
            entry = item.revisions[-1]
            entry.approved, entry.decision, entry.decided_at = approve, item.status, time.time()
            return {"status": item.status}


agent_inputs = AgentInputStore()
