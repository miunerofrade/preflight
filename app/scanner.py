"""One preflight scan = three safety layers + two Decide calls.

Layer order (each result shapes what the app shows next):
1. Guard    - client.injection(): prompt-injection score, categories, evidence
2. Protect  - client.pii():       PII entities + ready-made anonymized text
3. Routing  - client.decide():    does the content contain executable code?
4. Inspect  - client.script():    script safety, only when code is present
5. Verdict  - client.decide():    allow / review / block from a summary of all layers
"""
from __future__ import annotations

import time
from typing import Any

from clocked_sdk import Clocked

CODE_QUESTION = {
    "contains_executable_code": {
        "type": "choice",
        "criteria": {
            "code": "Contains executable code, shell commands, scripts, or machine-readable config that a computer would run.",
            "no_code": "Plain prose or data only; nothing a machine would execute.",
        },
    }
}

ACTION_QUESTION = {
    "action": {
        "type": "choice",
        "criteria": {
            "allow": "No meaningful risk found; safe to paste into an AI agent as-is.",
            "review": "Some risk signals a human should glance at before sending.",
            "block": "Active attack, credential theft, or critical data exposure; do not send this to an agent.",
        },
    }
}

SEV_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _verdict_summary(text: str | None, inj: dict, script: dict | None, pii: dict, label: str) -> str:
    kinds = ", ".join(sorted(pii.get("counts", {}))) or "none"
    if text is not None:
        head = f"Content under review ({len(text)} chars), first part: {text[:200]!r}"
    else:
        head = f"Content under review: {label}"
    lines = [
        head,
        f"Prompt injection scan: score {inj.get('injection', 0):.3f}, verdict {inj.get('verdict')}, "
        f"category {inj.get('category')}, severity {inj.get('severity')}.",
    ]
    if script is not None:
        lines.append(
            f"Script safety scan: malicious {script.get('malicious', 0):.3f}, verdict {script.get('verdict')}, "
            f"category {script.get('category')}, severity {script.get('severity')}."
        )
    else:
        lines.append("Script safety scan: not run; no executable code detected.")
    lines.append(
        f"Personal data scan: {len(pii.get('entities', []))} entities found, types: {kinds}; "
        "a masked copy of the text is available."
    )
    return "\n".join(lines)


def scan(
    text: str | None = None,
    *,
    pdf: bytes | None = None,
    images: list[bytes] | None = None,
    source_name: str = "",
) -> dict[str, Any]:
    """Run one preflight scan over pasted text, a PDF, or one or more images.

    Exactly one of text / pdf / images must be given. PDF and image scans run
    Guard, Protect and the routing Decide; Inspect (script safety) is a
    text-only endpoint and is skipped with a note for file scans.
    """
    if sum(x is not None for x in (text, pdf, images)) != 1:
        raise ValueError("pass exactly one of text, pdf, images")

    if pdf is not None:
        kind, label = "pdf", source_name or "a PDF document"
    elif images is not None:
        kind = "image"
        label = source_name or f"{len(images)} image(s)"
    else:
        kind, label = "text", ""

    client = Clocked()
    started = time.perf_counter()
    report: dict[str, Any] = {
        "layers": {},
        "usage": {"input_tokens": 0, "output_tokens": 0, "calls": 0},
        "source": {"kind": kind, "name": source_name},
    }

    def tracked(res: dict) -> dict:
        usage = res.get("usage") or {}
        report["usage"]["input_tokens"] += usage.get("input_tokens", 0)
        report["usage"]["output_tokens"] += usage.get("output_tokens", 0)
        report["usage"]["calls"] += 1
        return res

    def ms_of(res: dict) -> int | None:
        return (res.get("timing") or {}).get("total_ms")

    def target_kwargs(**extra: Any) -> dict[str, Any]:
        if text is not None:
            return {"text": text, **extra}
        if pdf is not None:
            return {"pdf": pdf, **extra}
        return {"images": images, **extra}

    def decide_kwargs(**extra: Any) -> dict[str, Any]:
        # decide takes `state` for text, and `pdf`/`images` stand in for it
        if text is not None:
            return {"state": text, **extra}
        if pdf is not None:
            return {"pdf": pdf, **extra}
        return {"images": images, **extra}

    # 1 - Guard: prompt injection
    inj = tracked(client.injection(**target_kwargs(evidence=True)))
    report["layers"]["injection"] = {
        key: inj.get(key)
        for key in ("injection", "verdict", "category", "categories",
                    "severity", "severities", "evidence", "residual")
    }
    report["layers"]["injection"]["ms"] = ms_of(inj)

    # 2 - Protect: PII entities + sanitized copy
    pii = tracked(client.pii(**target_kwargs(anonymize="mask", mask_keep=2)))
    report["layers"]["pii"] = {
        "entities": pii.get("entities", []),
        "counts": pii.get("counts", {}),
        "mentions": pii.get("mentions", []),
        "anonymized_text": pii.get("anonymized_text"),
        "ms": ms_of(pii),
    }

    # 3 - Routing (Decide): is there executable code worth inspecting?
    route = tracked(client.decide(**decide_kwargs(questions=CODE_QUESTION)))
    route_answer = route["answers"]["contains_executable_code"]
    has_code = route_answer["choice"] == "code"
    report["routing"] = {
        "contains_code": has_code,
        "probabilities": route_answer["probabilities"],
        "confidence": route_answer["confidence"],
    }

    # 4 - Inspect: script safety (conditional on routing; text-only endpoint)
    script_layer: dict[str, Any] | None = None
    if text is not None and has_code:
        scr = tracked(client.script(script=text, evidence=True))
        script_layer = {
            key: scr.get(key)
            for key in ("malicious", "suspicious", "verdict", "category",
                        "categories", "severity", "severities", "evidence")
        }
        script_layer["ms"] = ms_of(scr)
    elif text is None and has_code:
        report["notes"] = [
            "Executable code was detected, but script inspection runs on pasted "
            "text only - paste the script to inspect it."
        ]
    report["layers"]["script"] = script_layer

    # 5 - Final verdict (Decide): allow / review / block
    verdict = tracked(client.decide(
        state=_verdict_summary(text, inj, script_layer, pii, label),
        questions=ACTION_QUESTION,
    ))
    action = verdict["answers"]["action"]
    report["action"] = {
        "choice": action["choice"],
        "probabilities": action["probabilities"],
        "confidence": action["confidence"],
    }

    report["total_ms"] = round((time.perf_counter() - started) * 1000)
    return report
