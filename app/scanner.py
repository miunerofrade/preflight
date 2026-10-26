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

from .reputation import reputation

IDENTITY_FIELDS = {
    "organization": "The company or organization the site says it belongs to or that makes the product (e.g. the publisher or vendor named in the title, description, copyright or structured data).",
    "product": "The product or service name the site is presenting.",
}

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

URL_QUESTIONS = {
    "brand_impersonation": {
        "type": "choice",
        "criteria": {
            "impersonation": "The domain or the page impersonates a well-known brand: lookalike domain, homoglyphs, or brand claims from an unrelated domain.",
            "legitimate": "Domain and page consistently belong to the brand they reference; no impersonation pattern.",
            "not_established": "Not enough information to establish impersonation or legitimacy.",
        },
    },
    "content_intent": {
        "type": "choice",
        "criteria": {
            "credential_harvesting": "The page asks for credentials, payment details or personal data under time pressure or threats.",
            "scam_or_bait": "Urgency, prizes, fake warnings or fake support patterns without a direct credential request.",
            "benign": "Ordinary page content with no manipulation pattern.",
            "not_established": "Not enough information to judge the intent.",
        },
    },
}

UNCERTAIN_ALLOW = 0.5

SITE_RISK_QUESTION = {
    "site_risk": {
        "type": "choice",
        "criteria": {
            "malicious_or_pirated": "The site is a phishing page, a scam, an impersonation of another organization, or an unofficial / pirated mirror distributing someone else's software.",
            "legitimate": "The site is operated by the organization it presents itself as, or makes no false identity claim and shows no malicious pattern.",
        },
    }
}
URL_VERDICT_QUESTIONS = {**ACTION_QUESTION, **SITE_RISK_QUESTION}


def _apply_band(action: dict) -> dict:
    """An ALLOW the model itself is unsure about is shown as REVIEW; the model's own
    choice is kept so the report never hides what Clocked actually said."""
    out = {
        "choice": action["choice"],
        "probabilities": action["probabilities"],
        "confidence": action["confidence"],
        "model_choice": action["choice"],
        "uncertain": False,
    }
    if action["choice"] == "allow" and action["confidence"] < UNCERTAIN_ALLOW:
        out["choice"] = "review"
        out["uncertain"] = True
    return out


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
    report["action"] = _apply_band(action)

    report["total_ms"] = round((time.perf_counter() - started) * 1000)
    return report


# --------------------------------------------------------------------------
# URL scans (web content preflight)
# --------------------------------------------------------------------------

def _url_state_text(summary: dict) -> str:
    """Structured facts about the URL and page - the input the Decide questions judge."""
    page = summary["page"]
    lines = [
        f"URL under review: {summary['url']}",
        f"Host: {summary['host']}",
    ]
    for flag in summary["flags"]:
        lines.append(f"Deterministic flag [{flag['severity']}]: {flag['title']} - {flag['detail']}")
    if not summary["flags"]:
        lines.append("Deterministic flags: none.")
    lines.append(f"Page title: {page['title'] or '(none)'}")
    if page["headings"]:
        lines.append("Headings: " + " | ".join(page["headings"][:6]))
    for form in page["forms"]:
        fields = ", ".join(f"{f['name'] or '?'}({f['type']})" for f in form["fields"]) or "(no fields)"
        lines.append(f"Form -> action: {form['action'] or '(this page)'}; fields: {fields}")
    if page["links"]:
        lines.append("Links (text -> href):")
        for link in page["links"][:10]:
            lines.append(f"  - {link['text'] or '(no text)'} -> {link['href']}")
    lines.append(f"Inline scripts: {page['inline_script_count']}; external scripts: {len(page['script_srcs'])}")
    lines.append(f"Visible text (truncated): {page['body_text'][:1500]!r}")
    return "\n".join(lines)


def _url_verdict_state(summary: dict, layers: dict) -> str:
    imp, ident = layers["impersonation"], layers.get("identity")
    lines = [
        f"URL: {summary['url']} (host {summary['host']})",
        f"Deterministic flags: "
        + ("; ".join(f"{f['severity']}: {f['title']}" for f in summary["flags"]) or "none"),
        f"Page asks for a password: {'yes' if summary['has_password_form'] else 'no'}",
        f"Brand impersonation verdict: {imp['brand']['choice']} "
        f"(confidence {imp['brand']['confidence']:.3f})",
        f"Content intent verdict: {imp['intent']['choice']} "
        f"(confidence {imp['intent']['confidence']:.3f})",
        f"Prompt injection scan: score {layers['injection']['injection']:.3f}, "
        f"verdict {layers['injection']['verdict']}, severity {layers['injection']['severity']}.",
    ]
    scr = layers.get("script")
    if scr:
        lines.append(f"Script scan: malicious {scr['malicious']:.3f}, verdict {scr['verdict']}, severity {scr['severity']}.")
    else:
        lines.append("Script scan: not run (no inline scripts found).")
    rep = layers.get("reputation") or {}
    age = rep.get("age") or {}
    if age.get("created"):
        lines.append(f"Domain registered: {age['created']} ({age['age_days']} days ago).")
    else:
        lines.append("Domain registration date: unknown.")
    if rep.get("rank"):
        lines.append(f"Tranco global popularity rank: {rep['rank']}.")
    for item in rep.get("identity") or []:
        if item.get("matches") is True:
            lines.append(f"Claimed identity '{item['claimed']}': the host is on its official domains "
                         f"({', '.join(item['domains'])}).")
        elif item.get("matches") is False and item.get("weak"):
            lines.append(f"Claimed identity '{item['claimed']}': public records list "
                         f"{', '.join(item['domains'])} but not this domain; the domain itself is long-established "
                         "and globally popular, and large groups run many domains, so this is weak evidence.")
        elif item.get("matches") is False:
            lines.append(f"Claimed identity '{item['claimed']}': the host is NOT on its official domains "
                         f"({', '.join(item['domains'])}).")
    if ident:
        lines.append(f"Identity grounding against public registry records: "
                     f"{ident.get('verdict') or 'returned'}.")
    return "\n".join(lines)


def _identity_reference(host: str, rep: dict) -> str:
    """Public facts about who owns what - the reference the identity claim is checked against."""
    lines = []
    for item in rep.get("identity") or []:
        if item.get("domains"):
            lines.append(f"Wikidata {item.get('entity')} ('{item.get('label') or item['claimed']}') lists its "
                         f"official websites on: {', '.join(item['domains'])}.")
    domain = rep.get("domain") or host
    lines.append(f"The host {host} belongs to the registrable domain {domain}.")
    age = rep.get("age") or {}
    if age.get("created"):
        lines.append(f"{domain} was registered on {age['created']}.")
    if rep.get("rank"):
        lines.append(f"{domain} ranks #{rep['rank']} among the most visited sites worldwide (Tranco).")
    return " ".join(lines)


def scan_url(url: str, summary: dict) -> dict[str, Any]:
    """Preflight a URL: impersonation + intent (one dual-question Decide), Guard over
    the page text, conditional Inspect over inline scripts, conditional identity
    Grounding, then the final allow / review / block verdict."""
    client = Clocked()
    started = time.perf_counter()
    page = summary["page"]
    report: dict[str, Any] = {
        "source": {"kind": "url", "name": summary["host"]},
        "layers": {},
        "usage": {"input_tokens": 0, "output_tokens": 0, "calls": 0},
        "url": {
            "url": url,
            "host": summary["host"],
            "flags": summary["flags"],
            "brands_mentioned": summary["brands_mentioned"],
            "has_password_form": summary["has_password_form"],
            "title": page["title"],
            "headings": page["headings"],
            "forms": page["forms"],
            "links": page["links"][:10],
        },
    }

    def tracked(res: dict) -> dict:
        usage = res.get("usage") or {}
        report["usage"]["input_tokens"] += usage.get("input_tokens", 0)
        report["usage"]["output_tokens"] += usage.get("output_tokens", 0)
        report["usage"]["calls"] += 1
        return res

    def ms_of(res: dict) -> int | None:
        return (res.get("timing") or {}).get("total_ms")

    # 0 - who does the page claim to be? (Clocked extract, any language, no brand list)
    identity_text = " | ".join(
        x for x in (page["title"], page.get("description", ""), " | ".join(page["headings"]),
                    page.get("claims_text", "")) if x
    )
    claimed_orgs: list[str] = []
    if identity_text:
        ext = tracked(client.extract(text=identity_text[:4000], fields=IDENTITY_FIELDS))
        fields = ext.get("fields") or {}
        claimed_orgs = [
            (fields.get(k) or {}).get("value") or ""
            for k in ("organization", "product")
            if (fields.get(k) or {}).get("confidence", 0) >= 0.5
        ]
        claimed_orgs = [o for o in claimed_orgs if o]
    dl = page.get("download") or {}
    offers_download = bool(dl.get("cta_count") or dl.get("installer_links") or dl.get("script_targets"))
    rep = reputation(summary["host"], claimed_orgs, offers_download)
    # A brand word somewhere on the page ("download for macOS", a LinkedIn link in
    # structured data) is not an identity claim; keep brand-table flags only for
    # brands that the extracted identity actually names.
    named = " ".join(claimed_orgs).lower()
    claimed_brands = [b for b in summary["brands_mentioned"] if b in named]
    summary = {
        **summary,
        "brands_mentioned": claimed_brands,
        "flags": [f for f in summary["flags"] if f.get("brand") in (None, *claimed_brands)] + rep["flags"],
    }
    report["url"]["brands_mentioned"] = claimed_brands
    report["url"]["flags"] = summary["flags"]
    report["url"]["claimed_identity"] = claimed_orgs
    report["layers"]["reputation"] = {k: rep.get(k) for k in ("domain", "age", "rank", "identity", "note")}

    state = _url_state_text(summary)

    # 1 - dual-question Decide: brand impersonation + content intent
    res = tracked(client.decide(state=state, questions=URL_QUESTIONS))
    report["layers"]["impersonation"] = {
        "brand": res["answers"]["brand_impersonation"],
        "intent": res["answers"]["content_intent"],
    }

    # 2 - Guard: prompt injection over what an agent would actually read
    guard_text = " ".join(
        x for x in (page["title"], " | ".join(page["headings"]), page["body_text"]) if x
    )
    if guard_text.strip():
        inj = tracked(client.injection(text=guard_text, evidence=True))
        report["layers"]["injection"] = {
            key: inj.get(key)
            for key in ("injection", "verdict", "category", "categories",
                        "severity", "severities", "evidence", "residual")
        }
        report["layers"]["injection"]["ms"] = ms_of(inj)
    else:
        # client-rendered pages ship an empty HTML shell; there is no text to scan
        report["layers"]["injection"] = {"injection": 0.0, "verdict": "not_run", "category": None,
                                         "categories": {}, "severity": "none", "severities": {},
                                         "evidence": [], "residual": None, "ms": None}
        report.setdefault("notes", []).append(
            "The page has no readable text in its HTML (it is rendered by JavaScript), "
            "so the prompt-injection scan was skipped.")

    # 3 - Inspect: static analysis of inline scripts (they are never executed)
    if page["script_blob"]:
        scr = tracked(client.script(script=page["script_blob"], evidence=True))
        report["layers"]["script"] = {
            key: scr.get(key)
            for key in ("malicious", "suspicious", "verdict", "category",
                        "categories", "severity", "severities", "evidence")
        }
        report["layers"]["script"]["ms"] = ms_of(scr)
    else:
        report["layers"]["script"] = None

    # 4 - identity grounding: does the brand claim survive scrutiny?
    claimed_all = list(dict.fromkeys([*claimed_orgs, *summary["brands_mentioned"]]))
    if claimed_all:
        brands = ", ".join(claimed_all)
        g = tracked(client.grounding(
            documents=[_identity_reference(summary["host"], rep)],
            question="Is this website an official property of the brand it claims to represent?",
            answer=f"The website at {summary['host']} is an official website of {brands}.",
            evidence="all",
        ))
        report["layers"]["identity"] = {
            key: g.get(key)
            for key in ("grounded", "verdict", "summary", "claims", "evidence")
            if g.get(key) is not None
        }
        report["layers"]["identity"]["ms"] = ms_of(g)
    else:
        report["layers"]["identity"] = None

    # 5 - final verdict + probability that the site is malicious / pirated (one call)
    verdict = tracked(client.decide(
        state=_url_verdict_state(summary, report["layers"]),
        questions=URL_VERDICT_QUESTIONS,
    ))
    action = verdict["answers"]["action"]
    report["action"] = _apply_band(action)
    risk = verdict["answers"].get("site_risk") or {}
    report["risk"] = {
        "malicious_probability": (risk.get("probabilities") or {}).get("malicious_or_pirated"),
        "choice": risk.get("choice"),
        "confidence": risk.get("confidence"),
    }

    report["total_ms"] = round((time.perf_counter() - started) * 1000)
    return report
