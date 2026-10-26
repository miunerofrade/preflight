"""Offline tests for app.reputation: every network lookup is replaced."""
import datetime as dt

import pytest

from app import reputation as rep


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    rep.domain_age.cache_clear()
    rep.official_domains.cache_clear()
    monkeypatch.setattr(rep, "_rdap_created", lambda d: None)
    monkeypatch.setattr(rep, "_whois_created", lambda d: None)
    monkeypatch.setattr(rep, "_tranco_ranks", lambda: {"163.com": 418, "paypal.com": 174})
    monkeypatch.setattr(rep, "official_domains", lambda name: (
        {"entity": "Q196259", "label": "网易", "domains": ["163.com", "netease.com"]}
        if name == "网易" else {"entity": None, "label": None, "domains": []}))
    yield


def test_registrable_domain_handles_two_label_suffix():
    assert rep.registrable_domain("uuyc.163.com") == "163.com"
    assert rep.registrable_domain("www.uuycpro.com.cn") == "uuycpro.com.cn"


def test_parse_date_accepts_registry_formats():
    for raw in ("2026-09-14 19:02:22", "1997-09-15T04:00:00Z", "2013/03/08"):
        assert isinstance(rep._parse_date(raw), dt.datetime)
    assert rep._parse_date("no date here") is None


def test_whois_fallback_used_when_rdap_has_nothing(monkeypatch):
    created = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=42)
    monkeypatch.setattr(rep, "_whois_created", lambda d: created)
    age = rep.domain_age("fake.com.cn")
    assert age["source"] == "whois" and age["age_days"] == 42


def test_lookup_failures_are_unknown_not_risk(monkeypatch):
    def boom(_):
        raise OSError("network down")
    monkeypatch.setattr(rep, "_rdap_created", boom)
    monkeypatch.setattr(rep, "_whois_created", boom)
    assert rep.domain_age("x.com") == {"created": None, "age_days": None, "source": None}


def test_identity_mismatch_new_and_unranked_domain(monkeypatch):
    created = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=42)
    monkeypatch.setattr(rep, "_whois_created", lambda d: created)
    out = rep.reputation("uuycpro.com.cn", ["网易"], offers_download=True)
    titles = [f["title"] for f in out["flags"]]
    assert any("does not own" in t for t in titles)
    assert any("Newly registered" in t for t in titles)
    assert any("Tranco" in t for t in titles)
    assert out["flags"][0]["severity"] == "high"


def test_official_subdomain_gets_no_flags():
    out = rep.reputation("uuyc.163.com", ["网易"], offers_download=True)
    assert out["flags"] == []
    assert out["identity"][0]["matches"] is True


def test_local_hosts_skip_lookups():
    out = rep.reputation("127.0.0.1", ["PayPal"], offers_download=False)
    assert out["flags"] == [] and "skipped" in out["note"]
