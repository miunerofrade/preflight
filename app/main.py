"""Preflight - FastAPI backend serving the scan API and the single-page UI."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

from clocked_sdk import (
    AuthenticationError,
    ClockedError,
    InsufficientCreditsError,
    RateLimitError,
    RequestTimeoutError,
    ValidationError,
)
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .scanner import scan, scan_url
from .webcheck import summarize_url

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


@app.get("/")
def index() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "index.html")


app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.post("/api/scan")
def run_scan(req: ScanRequest) -> dict[str, Any]:
    text = req.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Paste some content first.")
    if len(text) > MAX_CHARS:
        raise HTTPException(status_code=400, detail=f"Content too long for one check ({MAX_CHARS:,} character limit).")
    return _guarded(lambda: scan(text))


@app.post("/api/scan-file")
async def run_scan_file(file: UploadFile = File(...)) -> dict[str, Any]:
    data = await file.read()
    name = file.filename or "upload"
    ctype = (file.content_type or "").lower()
    if not data:
        raise HTTPException(status_code=400, detail="The file is empty.")
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(status_code=400, detail="File is over the 10 MB limit.")
    if name.lower().endswith(".pdf") or "pdf" in ctype:
        return _guarded(lambda: scan(pdf=data, source_name=name))
    if ctype.startswith("image/"):
        return _guarded(lambda: scan(images=[data], source_name=name))
    raise HTTPException(status_code=400, detail="Only PDF and image files are supported.")


@app.post("/api/scan-batch")
def run_scan_batch(req: ScanBatchRequest) -> dict[str, Any]:
    items = [item.strip() for item in req.items if item.strip()]
    if not items:
        raise HTTPException(status_code=400, detail="No content to scan.")
    if len(items) > 10:
        raise HTTPException(status_code=400, detail="Batch limit is 10 items per run.")
    for index, item in enumerate(items):
        if len(item) > MAX_CHARS:
            raise HTTPException(status_code=400, detail=f"Item {index + 1} is over the {MAX_CHARS:,} character limit.")

    def batch() -> dict[str, Any]:
        results = []
        for index, item in enumerate(items):
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
        results.sort(
            key=lambda r: (
                {"block": 0, "review": 1, "allow": 2}[r["action"]["choice"]],
                -r["injection"]["score"],
            )
        )
        return {"count": len(results), "results": results}

    return _guarded(batch)


@app.post("/api/scan-url")
def run_scan_url(req: ScanUrlRequest) -> dict[str, Any]:
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
    try:
        summary = summarize_url(url, allow_private=allow_private)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # httpx network/HTTP errors
        raise HTTPException(status_code=502, detail=f"Could not fetch the page: {exc}")
    return _guarded(lambda: scan_url(url, summary))