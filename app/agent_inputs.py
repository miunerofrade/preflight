"""Bounded, process-local Codex input tickets and explicit human release."""
from __future__ import annotations

import hashlib
import secrets
import threading
import time
from dataclasses import dataclass
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

    def review(self, ticket: str, token: str) -> dict:
        with self._lock:
            item = self._get(ticket)
            if not secrets.compare_digest(item.review_token.encode("utf-8"), token.encode("utf-8")):
                raise PermissionError("Invalid review token.")
            return {"source": item.source, "text": item.text, "report": item.report,
                    "candidate_sha256": item.candidate_sha256, "status": item.status, "language": item.language,
                    "receipt": {"source_sha256": digest(item.text), "copy_sha256": item.candidate_sha256,
                                "human_approved": item.approved}}

    def revise(self, ticket: str, token: str, report: dict) -> dict:
        """Rebind a pending ticket to a freshly rescanned copy after a human edit.
        The new candidate, its hash and the status replace the old ones, so a later
        approval can never release a version other than the one now on screen."""
        with self._lock:
            item = self._get(ticket)
            if not secrets.compare_digest(item.review_token.encode("utf-8"), token.encode("utf-8")):
                raise PermissionError("Invalid review token.")
            if item.status != "pending":
                raise ValueError("Only a pending ticket can be revised.")
            candidate, status = _candidate_and_status(report)
            item.report = report
            item.candidate = candidate
            item.candidate_sha256 = digest(candidate) if candidate is not None else None
            item.status = status
            item.approved = False
            return {"status": item.status, "candidate_sha256": item.candidate_sha256}

    def decide(self, ticket: str, token: str, candidate_sha256: str, approve: bool) -> dict:
        with self._lock:
            item = self._get(ticket)
            self.review(ticket, token)
            if item.status != "pending" or item.candidate is None:
                raise ValueError("Only a pending, checked copy can be approved or rejected.")
            if not secrets.compare_digest((item.candidate_sha256 or "").encode("utf-8"), candidate_sha256.encode("utf-8")):
                raise ValueError("Copy hash changed. Review the current copy first.")
            item.status = "released" if approve else "rejected"
            item.approved = approve
            return {"status": item.status}


agent_inputs = AgentInputStore()
