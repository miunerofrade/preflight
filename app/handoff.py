"""Prepare a text copy from validated source offsets; never treat masking as screening."""
from __future__ import annotations

from typing import Any, Callable

from clocked_sdk import ClockedError

from .policy import sensitive_pii


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
    """
    edits: list[tuple[int, int, str]] = []
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
            merged[-1] = (a, max(end, b), "remove" if "remove" in (kind, previous) else "mask")
        else:
            merged.append((start, end, kind))
    chunks: list[str] = []
    cursor = 0
    copy_cursor = 0
    for start, end, kind in merged:
        unchanged = text[cursor:start]
        replacement = "[Instruction removed]" if kind == "remove" else "[REDACTED]"
        copy_cursor += len(unchanged)
        if edits_out is not None:
            edits_out.append({"kind": kind, "start": start, "end": end, "before": text[start:end],
                              "after": replacement, "copy_start": copy_cursor, "copy_end": copy_cursor + len(replacement)})
        chunks.extend((unchanged, replacement))
        copy_cursor += len(replacement)
        cursor = end
    chunks.append(text[cursor:])
    return "".join(chunks), {
        "removed": sum(kind == "remove" for _, _, kind in merged),
        "masked": sum(kind == "mask" for _, _, kind in merged),
    }


def build_handoff(text: str | None, report: dict, recheck: Callable[[str], dict]) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "withheld", "text": None, "changes": {"removed": 0, "masked": 0},
                              "verification": None, "reason": None, "edits": [], "draft_text": None}
    if text is None:
        return {**result, "status": "unavailable", "reason": "file_source"}
    layers = report["layers"]
    script = layers.get("script")
    if script and script.get("verdict") != "benign":
        return {**result, "reason": "script_risk"}
    if (report.get("routing") or {}).get("contains_code") and script is None:
        return {**result, "reason": "code_unchecked"}
    if any(r["code"] in {"routing_uncertain", "guard_incomplete", "checks_incomplete"} for r in report["policy"]["reasons"]):
        return {**result, "reason": "checks_incomplete"}
    try:
        candidate, changes = prepare_text(text, layers, edits_out=result["edits"])
    except ValueError:
        return {**result, "reason": "evidence_invalid"}
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
    review = changes["removed"] > 0 or verification["action"]["choice"] != "allow" or report["action"]["choice"] == "block"
    return {**result, "status": "review" if review else "ready", "text": candidate,
            "reason": "edited_checked"}
