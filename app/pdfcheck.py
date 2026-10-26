"""Bounded PDF text-layer inspection. No rasterization, OCR or visual comparison."""
from __future__ import annotations

import re

import pymupdf

MAX_PAGES = 20
MAX_SPANS = 5000
MAX_FINDINGS = 40
DIRECTIVE = re.compile(r"ignore.{0,40}(?:previous|instructions)|AI\s*assistant|system prompt|忽略.{0,30}指令|AI\s*助手|系统提示", re.I)
INVISIBLE = re.compile(r"[\u202d\u202e\U000e0020-\U000e007f]|(?<=\w)[\u200b\u2060\ufeff]+(?=\w)")


def inspect_pdf(data: bytes) -> dict:
    result = {"status": "unavailable", "scope": "text_layer_only", "reason": None,
              "pages": 0, "pages_checked": 0, "findings": [], "metadata": []}
    try:
        with pymupdf.open(stream=data, filetype="pdf") as doc:
            result["pages"] = len(doc)
            if doc.needs_pass:
                return {**result, "reason": "encrypted"}
            for field in ("title", "subject", "keywords"):
                value = (doc.metadata or {}).get(field) or ""
                if value:
                    result["metadata"].append({"field": field, "value": value[:1000]})
                    match = DIRECTIVE.search(value)
                    if match:
                        result["findings"].append({"kind": "metadata_instruction", "page": None,
                                                   "field": field, "text": value[max(0, match.start() - 40):match.start() + 200],
                                                   "requires_review": True})
            spans_read = 0
            characters = 0
            limited = len(doc) > MAX_PAGES
            for page in doc:
                if result["pages_checked"] >= MAX_PAGES or spans_read >= MAX_SPANS or len(result["findings"]) >= MAX_FINDINGS:
                    limited = True
                    break
                result["pages_checked"] += 1
                rect = page.rect * page.derotation_matrix
                for span in page.get_texttrace():
                    spans_read += 1
                    if spans_read > MAX_SPANS or len(result["findings"]) >= MAX_FINDINGS:
                        limited = True
                        break
                    text = "".join(chr(c[0]) for c in span["chars"] if 0 <= c[0] <= 0x10FFFF)
                    if not text.strip():
                        continue
                    characters += len(text)
                    x0, y0, x1, y1 = span["bbox"]
                    area = max(0, x1 - x0) * max(0, y1 - y0)
                    inside = max(0, min(x1, rect.x1) - max(x0, rect.x0)) * max(0, min(y1, rect.y1) - max(y0, rect.y0))
                    kinds = []
                    if span.get("type") == 3 or span.get("opacity", 1) <= 0.05:
                        kinds.append("invisible_text")
                    if span.get("size", 12) < 4:
                        kinds.append("tiny_text")
                    if area > 0 and inside / area < 0.25:
                        kinds.append("off_page")
                    if INVISIBLE.search(text):
                        kinds.append("unicode_controls")
                    color = span.get("color", ())
                    if isinstance(color, (list, tuple)) and color and all(c >= 0.95 for c in color):
                        kinds.append("light_text")  # background isn't inspected: this alone is not a hidden-text verdict
                    for kind in kinds:
                        if len(result["findings"]) >= MAX_FINDINGS:
                            limited = True
                            break
                        result["findings"].append({"kind": kind, "page": page.number + 1, "text": text[:240],
                            "bbox": [round(n, 2) for n in span["bbox"]], "font_size": round(span.get("size", 0), 2),
                            "requires_review": kind != "light_text"})
            result["status"] = "partial" if limited or characters == 0 else "complete"
            result["reason"] = "limit" if limited else "no_text" if characters == 0 else None
    except Exception:
        result["status"] = "unavailable"
        result["reason"] = "unreadable"
    return result
