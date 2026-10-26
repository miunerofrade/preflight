"""Local disposition rules. Model scores remain evidence, never policy confidence."""
from __future__ import annotations

from typing import Any

POLICY_VERSION = "2026-10-26.1"
RANK = {"allow": 0, "review": 1, "block": 2}
NAME_ONLY_TYPES = {"person"}


def detector_complete(result: dict, score: str) -> bool:
    value = result.get(score)
    return (type(value) in (int, float) and 0 <= value <= 1
            and isinstance(result.get("verdict"), str) and isinstance(result.get("severity"), str))


def sensitive_pii(pii: dict) -> bool:
    return any(v for k, v in (pii.get("counts") or {}).items() if k not in NAME_ONLY_TYPES) or any(
        e.get("type") not in NAME_ONLY_TYPES for e in pii.get("entities") or []
    )


def enforce_policy(report: dict[str, Any]) -> None:
    """Only raise the disposition floor; retain the unmodified model answer and scores.

    Detector verdicts drive rules instead of copying another app's probability cutoffs.
    Missing required results are review, never clean. Transport failures still surface
    as API errors, with no report or transferable copy.
    """
    action = report["action"]
    reasons: list[dict[str, str]] = []

    def require(code: str, floor: str = "review") -> None:
        reasons.append({"code": code, "action": floor})

    if action.get("uncertain"):
        require("model_uncertain")
    if any(complete is not True for complete in report.get("checks", {}).values()):
        require("checks_incomplete")
    layers = report["layers"]
    pdf = report.get("pdf_inspection")
    if pdf is not None:
        if pdf.get("status") != "complete":
            require("pdf_incomplete")
        if any(f.get("requires_review") for f in pdf.get("findings", [])):
            require("pdf_hidden_content")
    inj = layers.get("injection") or {}
    if inj.get("verdict") == "injection":
        require("injection_high" if inj.get("severity") in {"high", "critical"} else "injection_flagged",
                "block" if inj.get("severity") in {"high", "critical"} else "review")
    elif inj.get("verdict") != "benign":
        require("guard_incomplete" if inj.get("verdict") in {None, "not_run"} else "injection_uncertain")

    scr = layers.get("script")
    if scr is not None:
        if scr.get("verdict") == "malicious":
            require("script_high" if scr.get("severity") in {"high", "critical"} else "script_flagged",
                    "block" if scr.get("severity") in {"high", "critical"} else "review")
        elif scr.get("verdict") != "benign":
            require("script_flagged")

    source = report.get("source", {}).get("kind", "text")
    route = report.get("routing") or {}
    if source != "url":
        if sensitive_pii(layers.get("pii") or {}):
            require("personal_data")
        if route.get("confidence", 0) < 0.5:
            require("routing_uncertain")
        if route.get("contains_code") and scr is None:
            require("code_unchecked")
    else:
        imp = layers.get("impersonation") or {}
        intent = imp.get("intent") or {}
        if intent.get("choice") == "credential_harvesting":
            require("credential_harvesting", "block" if intent.get("confidence", 0) >= 0.5 else "review")
        elif intent.get("choice") in {"scam_or_bait", "not_established", None}:
            require("page_intent_uncertain")
        if (imp.get("brand") or {}).get("choice") == "impersonation":
            require("identity_mismatch")

    choice = action["choice"]
    for reason in reasons:
        if RANK[reason["action"]] > RANK[choice]:
            choice = reason["action"]
    action["choice"] = choice
    action["overridden"] = choice != action.get("model_choice", choice)
    report["policy"] = {"version": POLICY_VERSION, "reasons": reasons}
