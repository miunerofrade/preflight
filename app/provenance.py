"""Receipts and source quotations for URL conclusions; no additional requests."""
from __future__ import annotations

import re


def claim_sources(text: str, fields: dict) -> list[dict]:
    claims = []
    for key in ("organization", "product"):
        item = fields.get(key) or {}
        if not item.get("value") or item.get("confidence", 0) < 0.5:
            continue
        start, end = item.get("start"), item.get("end")
        exact = (type(start) is int and type(end) is int and 0 <= start < end <= len(text)
                 and text[start:end] == item["value"])
        claims.append({"field": key, "value": item["value"], "quote": text[start:end] if exact else None,
                       "start": start if exact else None, "end": end if exact else None,
                       "status": "quoted" if exact else "unlocated"})
    return claims


def public_sources(rep: dict) -> list[dict]:
    age = rep.get("age") or {}
    sources = [{"kind": "registration", "status": "known" if age.get("created") else "unknown",
                "value": age.get("created"), "provider": age.get("source"), "url": age.get("source_url"),
                "server": age.get("server"), "checked_at": age.get("checked_at")},
               {"kind": "rank", "status": rep.get("rank_status", "known" if rep.get("rank") else "unknown"),
                "value": rep.get("rank"), "provider": "Tranco", "url": "https://tranco-list.eu/",
                "checked_at": rep.get("rank_updated_at")}]
    for identity in rep.get("identity") or []:
        record = identity.get("via") or identity.get("entity") or ""
        sources.append({"kind": "identity", "claimed": identity["claimed"],
                        "status": "matches" if identity.get("matches") is True else
                                  "not_listed" if identity.get("matches") is False else "unknown",
                        "domains": identity.get("domains") or [],
                        "url": f"https://www.wikidata.org/wiki/{record}" if re.fullmatch(r"Q\d+", record) else None,
                        "provider": "Wikidata", "checked_at": identity.get("checked_at")})
    return sources
