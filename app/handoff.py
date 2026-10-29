"""Prepare a text copy from validated source offsets; never treat masking as screening."""
from __future__ import annotations

import re
from typing import Any, Callable

from clocked_sdk import ClockedError

from .policy import sensitive_pii

SCRIPT_REPLACEMENT = "[Script removed]"
RISKY_SCRIPT = {"malicious", "suspicious"}
# overlapping edits keep the strongest kind: a cut script block swallows anything inside it
_EDIT_RANK = {"mask": 0, "remove": 1, "remove_script_block": 2}
_EDIT_MARKER = {"mask": "[REDACTED]", "remove": "[Instruction removed]", "remove_script_block": SCRIPT_REPLACEMENT}
_FENCE = re.compile(r"^(?P<fence>`{3,}|~{3,})[^\n]*\n.*?^(?P=fence)[ \t]*$", re.M | re.S)
_SCRIPT_TAG = re.compile(r"<script\b[^>]*>.*?</script\s*>", re.I | re.S)


def code_blocks(text: str) -> list[tuple[int, int]]:
    """Closed Markdown fences and HTML script elements; unclosed fences are not blocks."""
    spans = sorted({m.span() for m in _FENCE.finditer(text)} | {m.span() for m in _SCRIPT_TAG.finditer(text)})
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def risky_script_blocks(text: str, script: dict) -> list[tuple[int, int]] | None:
    """Blocks to cut when every script finding sits inside a delimited code block.

    None means the input must be replaced in full: no evidence, an offset that does
    not match the source, or a finding outside any block (code mixed into prose).
    """
    evidence = script.get("evidence") or []
    blocks = code_blocks(text)
    if not evidence or not blocks:
        return None
    hit: set[tuple[int, int]] = set()
    for item in evidence:
        quote = item.get("line", item.get("quote"))
        start, end = item.get("start"), item.get("end")
        if (type(start) is not int or type(end) is not int or not 0 <= start < end <= len(text)
                or not isinstance(quote, str) or text[start:end] != quote):
            return None
        block = next((b for b in blocks if b[0] <= start and end <= b[1]), None)
        if block is None:
            return None
        hit.add(block)
    return sorted(hit)


def _replace_whole(text: str, edits_out: list | None) -> tuple[str, dict[str, int]]:
    if edits_out is not None:
        edits_out.append({"kind": "remove_script", "start": 0, "end": len(text), "before": text,
                          "after": SCRIPT_REPLACEMENT, "copy_start": 0, "copy_end": len(SCRIPT_REPLACEMENT)})
    return SCRIPT_REPLACEMENT, {"removed": 0, "masked": 0, "scripts_removed": 1}


def _span(text: str, item: dict, value_key: str) -> tuple[int, int]:
    start, end = item.get("start"), item.get("end")
    if (type(start) is not int or type(end) is not int or not 0 <= start < end <= len(text)
            or not isinstance(item.get(value_key), str) or text[start:end] != item[value_key]):
        raise ValueError("Evidence does not match the original source.")
    return start, end


def prepare_text(text: str, layers: dict, *, edits_out: list | None = None) -> tuple[str, dict[str, int]]:
    """Apply edits in one pass using Python/Clocked Unicode code-point offsets.

    Overlapping spans are merged; a removal wins over masking. Any invalid source
    offset withholds the entire copy, rather than making a best-effort edit.
    A risky script whose findings all sit in delimited code blocks loses only those
    blocks; otherwise the input is replaced in full by a fixed marker, with no
    evidence offsets or original source content used for that replacement.
    """
    script = layers.get("script") or {}
    edits: list[tuple[int, int, str]] = []
    if script.get("verdict") in RISKY_SCRIPT:
        blocks = risky_script_blocks(text, script)
        if blocks is None:
            return _replace_whole(text, edits_out)
        edits.extend((start, end, "remove_script_block") for start, end in blocks)
    injection = layers["injection"]
    evidence = injection.get("evidence") or []
    flagged = injection.get("verdict") != "benign"
    if flagged and not evidence:
        raise ValueError("No injection evidence to remove.")
    if flagged:
        for item in evidence:
            edits.append((*_span(text, item, "quote"), "remove"))
    pii = layers["pii"]
    mentions = pii.get("mentions") or []
    mask_required = sensitive_pii(pii)
    entities = [*(pii.get("entities") or []), *(mentions if isinstance(mentions, list) else [])] if mask_required else []
    seen: set[tuple[int, int]] = set()
    for item in entities:
        # Some API versions include aggregate mention summaries without offsets.
        # These aren't source locations; entity spans above remain mandatory.
        if "start" not in item and isinstance(mentions, list) and item in mentions:
            continue
        span = _span(text, item, "value")
        if span not in seen:
            edits.append((*span, "mask"))
            seen.add(span)
    if mask_required and not seen:
        raise ValueError("Personal data was reported without valid source offsets.")

    merged: list[tuple[int, int, str]] = []
    for start, end, kind in sorted(edits):
        if merged and start < merged[-1][1]:
            a, b, previous = merged[-1]
            merged[-1] = (a, max(end, b), max(kind, previous, key=_EDIT_RANK.__getitem__))
        else:
            merged.append((start, end, kind))
    chunks: list[str] = []
    cursor = 0
    copy_cursor = 0
    for start, end, kind in merged:
        unchanged = text[cursor:start]
        replacement = _EDIT_MARKER[kind]
        copy_cursor += len(unchanged)
        if edits_out is not None:
            edits_out.append({"kind": kind, "start": start, "end": end, "before": text[start:end],
                              "after": replacement, "copy_start": copy_cursor, "copy_end": copy_cursor + len(replacement)})
        chunks.extend((unchanged, replacement))
        copy_cursor += len(replacement)
        cursor = end
    chunks.append(text[cursor:])
    changes = {
        "removed": sum(kind == "remove" for _, _, kind in merged),
        "masked": sum(kind == "mask" for _, _, kind in merged),
    }
    blocks_removed = sum(kind == "remove_script_block" for _, _, kind in merged)
    if blocks_removed:
        changes["script_blocks_removed"] = blocks_removed
    return "".join(chunks), changes


def build_handoff(text: str | None, report: dict, recheck: Callable[[str], dict]) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "withheld", "text": None, "changes": {"removed": 0, "masked": 0},
                              "verification": None, "reason": None, "edits": [], "draft_text": None}
    if text is None:
        return {**result, "status": "unavailable", "reason": "file_source"}
    layers = report["layers"]
    script = layers.get("script")
    incomplete = any(r["code"] in {"routing_uncertain", "guard_incomplete", "checks_incomplete"}
                     for r in report["policy"]["reasons"])

    def whole_replacement() -> dict[str, Any]:
        # No source characters survive: this is a fixed non-executable marker,
        # not an attempted repair of arbitrary source code or a model clearance.
        edits: list = []
        candidate, changes = _replace_whole(text, edits)
        return {**result, "status": "review", "text": candidate, "changes": changes, "edits": edits,
                "reason": "script_removed", "validation": {"method": "fixed_script_replacement",
                                                            "retains_source_content": False}}

    risky = bool(script) and script.get("verdict") in RISKY_SCRIPT
    if risky and (incomplete or risky_script_blocks(text, script) is None):
        return whole_replacement()
    if script and script.get("verdict") not in {"benign", *RISKY_SCRIPT}:
        return {**result, "reason": "script_risk"}
    if (report.get("routing") or {}).get("contains_code") and script is None:
        return {**result, "reason": "code_unchecked"}
    if incomplete:
        return {**result, "reason": "checks_incomplete"}
    try:
        candidate, changes = prepare_text(text, layers, edits_out=result["edits"])
    except ValueError:
        # surrounding evidence can't be applied, so keeping any of the text is unsafe
        return whole_replacement() if risky else {**result, "reason": "evidence_invalid"}
    if risky:
        # the remaining prose and code still go through the full recheck below
        result["validation"] = {"method": "script_blocks_removed", "retains_source_content": True}
    result["changes"] = changes
    if candidate == text:
        if report["action"]["choice"] == "block":
            return {**result, "reason": "original_blocked"}
        return {**result, "status": "ready" if report["action"]["choice"] == "allow" else "review",
                "text": candidate, "reason": "original_checked"}
    try:
        verification = recheck(candidate)
    except ClockedError:
        return {**result, "reason": "recheck_failed", "draft_text": candidate}
    result["verification"] = verification
    # A second masking recommendation is not permission to send unmasked leftovers.
    unresolved = any(r["code"] != "model_uncertain" for r in verification["policy"]["reasons"])
    if verification["action"]["choice"] == "block" or unresolved:
        return {**result, "reason": "residual_risk", "draft_text": candidate}
    review = changes["removed"] > 0 or changes.get("script_blocks_removed") or verification["action"]["choice"] != "allow" or report["action"]["choice"] == "block"
    return {**result, "status": "review" if review else "ready", "text": candidate,
            "reason": "edited_checked"}
