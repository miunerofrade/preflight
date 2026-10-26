"""Preflight - FastAPI backend serving the scan API and the single-page UI."""
from __future__ import annotations

import json
import os
import queue
import threading
from pathlib import Path
from typing import Any, Callable, Literal

import httpx
from clocked_sdk import (
    AuthenticationError,
    ClockedError,
    InsufficientCreditsError,
    RateLimitError,
    RequestTimeoutError,
    ValidationError,
)
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .scanner import compare_batch, scan, scan_url
from .webcheck import summarize_url
from .reports import ReportGenerationError, generate_review
from .agent_inputs import agent_inputs

BASE_DIR = Path(__file__).resolve().parent
MAX_CHARS = 20_000
MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MB per upload

# local dev convenience: load ./.env when CLOCKED_API_KEY is not already set
_env_file = BASE_DIR.parent / ".env"
if _env_file.exists() and not os.environ.get("CLOCKED_API_KEY"):
    for line in _env_file.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.strip().startswith("#"):
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())

app = FastAPI(
    title="Preflight",
    description="Security preflight for anything you are about to feed an AI agent.",
)


class ScanRequest(BaseModel):
    text: str


class ScanBatchRequest(BaseModel):
    items: list[str]


class ScanUrlRequest(BaseModel):
    url: str


class AgentDecisionRequest(BaseModel):
    review_token: str
    candidate_sha256: str
    approve: bool


def _agent_review_request(request: Request) -> None:
    if request.url.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise HTTPException(status_code=403, detail="Agent reviews are local only.")
    origin = request.headers.get("origin")
    if origin and origin.rstrip("/") != str(request.base_url).rstrip("/"):
        raise HTTPException(status_code=403, detail="Cross-origin review is not allowed.")


@app.get("/api/agent-inputs/{ticket}")
def get_agent_input(ticket: str, review_token: str, request: Request) -> JSONResponse:
    _agent_review_request(request)
    try:
        data = agent_inputs.review(ticket, review_token)
    except KeyError:
        raise HTTPException(status_code=404, detail="Input ticket expired. Scan again.")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Invalid review token.")
    return JSONResponse(data, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})


@app.post("/api/agent-inputs/{ticket}/decision")
def decide_agent_input(ticket: str, req: AgentDecisionRequest, request: Request) -> dict:
    _agent_review_request(request)
    try:
        return agent_inputs.decide(ticket, req.review_token, req.candidate_sha256, req.approve)
    except KeyError:
        raise HTTPException(status_code=404, detail="Input ticket expired. Scan again.")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Invalid review token.")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


class ReviewReportRequest(BaseModel):
    report: dict[str, Any]
    language: Literal["en", "zh"] = "en"


@app.post("/api/review-report")
def run_review_report(req: ReviewReportRequest) -> dict:
    if len(json.dumps(req.report, ensure_ascii=False)) > 250_000:
        raise HTTPException(status_code=400, detail="Report is too large.")
    try:
        return _guarded(lambda: generate_review(req.report, req.language))
    except ReportGenerationError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def _guarded(fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    """Run a scan and translate Clocked errors into honest HTTP responses."""
    try:
        return fn()
    except AuthenticationError:
        raise HTTPException(status_code=401, detail="Invalid or missing CLOCKED_API_KEY.")
    except InsufficientCreditsError:
        raise HTTPException(status_code=402, detail="Out of Clocked credits.")
    except RateLimitError:
        raise HTTPException(status_code=429, detail="Rate limited by Clocked (4 concurrent requests on this plan). Wait a moment and try again.")
    except RequestTimeoutError:
        raise HTTPException(status_code=504, detail="Clocked request timed out. Try again.")
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except ClockedError as exc:
        raise HTTPException(status_code=502, detail=f"Clocked API error: {exc}")


class FetchError(HTTPException):
    """The target page could not be fetched; `code` lets the UI show a translated message."""

    def __init__(self, detail: str, code: str, vars: dict[str, Any]) -> None:
        super().__init__(status_code=502, detail=detail)
        self.code = code
        self.vars = vars


def _stream(work: Callable[[Callable[[str], None]], dict[str, Any]]) -> StreamingResponse:
    """Run a scan in a worker thread and stream NDJSON: one {"type": "step"} line as each
    stage starts, then a final {"type": "result"} or {"type": "error"} line."""
    events: queue.Queue = queue.Queue()

    def emit(key: str) -> None:
        events.put({"type": "step", "step": key})

    def run() -> None:
        try:
            events.put({"type": "result", "data": _guarded(lambda: work(emit))})
        except HTTPException as exc:
            event = {"type": "error", "status": exc.status_code, "detail": exc.detail}
            if isinstance(exc, FetchError):
                event.update(code=exc.code, vars=exc.vars)
            events.put(event)
        except Exception as exc:
            events.put({"type": "error", "status": 500, "detail": f"Scan failed: {exc}"})
        finally:
            events.put(None)

    threading.Thread(target=run, daemon=True).start()

    def body():
        while (event := events.get()) is not None:
            yield json.dumps(event, ensure_ascii=False) + "\n"

    return StreamingResponse(body(), media_type="application/x-ndjson")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "index.html", headers={"Referrer-Policy": "no-referrer"})


app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.post("/api/scan")
def run_scan(req: ScanRequest, stream: bool = False) -> Any:
    text = req.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Paste some content first.")
    if len(text) > MAX_CHARS:
        raise HTTPException(status_code=400, detail=f"Content too long for one check ({MAX_CHARS:,} character limit).")
    if stream:
        return _stream(lambda emit: scan(text, progress=emit))
    return _guarded(lambda: scan(text))


@app.post("/api/scan-file")
async def run_scan_file(file: UploadFile = File(...), stream: bool = False) -> Any:
    data = await file.read()
    name = file.filename or "upload"
    ctype = (file.content_type or "").lower()
    if not data:
        raise HTTPException(status_code=400, detail="The file is empty.")
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(status_code=400, detail="File is over the 10 MB limit.")
    if name.lower().endswith(".pdf") or "pdf" in ctype:
        kwargs: dict[str, Any] = {"pdf": data}
    elif ctype.startswith("image/"):
        kwargs = {"images": [data]}
    else:
        raise HTTPException(status_code=400, detail="Only PDF and image files are supported.")
    if stream:
        return _stream(lambda emit: scan(**kwargs, source_name=name, progress=emit))
    return _guarded(lambda: scan(**kwargs, source_name=name))


@app.post("/api/scan-batch")
def run_scan_batch(req: ScanBatchRequest, stream: bool = False) -> Any:
    items = [item.strip() for item in req.items if item.strip()]
    if not items:
        raise HTTPException(status_code=400, detail="No content to scan.")
    if len(items) > 10:
        raise HTTPException(status_code=400, detail="Batch limit is 10 items per run.")
    for index, item in enumerate(items):
        if len(item) > MAX_CHARS:
            raise HTTPException(status_code=400, detail=f"Item {index + 1} is over the {MAX_CHARS:,} character limit.")

    def batch(emit: Callable[[str], None] = lambda _key: None) -> dict[str, Any]:
        results = []
        for index, item in enumerate(items):
            emit(f"item:{index}")
            report = scan(item)
            results.append({
                "index": index,
                "preview": item[:120],
                "chars": len(item),
                "action": report["action"],
                "injection": {
                    "score": report["layers"]["injection"]["injection"],
                    "verdict": report["layers"]["injection"]["verdict"],
                    "severity": report["layers"]["injection"]["severity"],
                },
                "script": None
                if report["layers"]["script"] is None
                else {
                    "score": report["layers"]["script"]["malicious"],
                    "verdict": report["layers"]["script"]["verdict"],
                },
                "pii_count": len(report["layers"]["pii"]["entities"]),
                "total_ms": report["total_ms"],
                "full": report,
            })
        rank = {"block": 0, "review": 1, "allow": 2}
        similarity = None
        if len(items) >= 2:
            emit("compare")
            try:
                similarity = compare_batch(items)
            except ClockedError:
                # grouping is an add-on: the per-item verdicts above still stand
                similarity = {"groups": [], "conflicts": [], "failed": True}
        # items that are the same content reworded share the worst verdict of their group
        group_of: dict[int, int] = {}
        for g, members in enumerate((similarity or {}).get("groups") or []):
            for i in members:
                group_of[i] = g
        worst: dict[int, int] = {}
        for r in results:
            g = group_of.get(r["index"])
            if g is not None:
                worst[g] = min(worst.get(g, 2), rank[r["action"]["choice"]])
        for r in results:
            g = group_of.get(r["index"])
            r["group"] = g
            r["group_worst"] = None if g is None else ["block", "review", "allow"][worst[g]]
        results.sort(
            key=lambda r: (
                rank[r["group_worst"] or r["action"]["choice"]],
                rank[r["action"]["choice"]],
                -r["injection"]["score"],
            )
        )
        return {"count": len(results), "results": results, "similarity": similarity}

    if stream:
        return _stream(batch)
    return _guarded(batch)


@app.post("/api/scan-url")
def run_scan_url(req: ScanUrlRequest, stream: bool = False) -> Any:
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="Provide a URL.")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if len(url) > 2000:
        raise HTTPException(status_code=400, detail="URL is too long.")
    # Local demo escape hatch: scanning private/loopback targets is blocked unless
    # PREFLIGHT_ALLOW_PRIVATE_URLS is set (needed to scan the bundled demo page).
    allow_private = os.environ.get("PREFLIGHT_ALLOW_PRIVATE_URLS", "").lower() in ("1", "true", "yes")

    def fetch() -> dict[str, Any]:
        try:
            return summarize_url(url, allow_private=allow_private)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            raise FetchError(f"The site refused the request (HTTP {status}).", "fetchStatus", {"s": status})
        except Exception as exc:  # network errors: DNS, TLS, timeouts
            raise FetchError(f"Could not fetch the page: {exc}", "fetchFailed", {})

    if stream:
        def work(emit: Callable[[str], None]) -> dict[str, Any]:
            emit("fetch")
            return scan_url(url, fetch(), progress=emit)
        return _stream(work)
    summary = fetch()
    return _guarded(lambda: scan_url(url, summary))
