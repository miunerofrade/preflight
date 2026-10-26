"""Deterministic URL checks + page parsing tests - no network, no Clocked."""
from __future__ import annotations

import pytest

from app.webcheck import (
    HOMOGLYPHS,
    brand_mentions,
    fetch_page,
    levenshtein,
    parse_page,
    url_flags,
)


def test_levenshtein_basic():
    assert levenshtein("paypal", "paypa1") == 1
    assert levenshtein("paypal", "paypal") == 0
    assert levenshtein("paypal", "microsoft") > 2


def test_homoglyph_normalization():
    assert "paypa1".translate(HOMOGLYPHS) == "paypal"
    assert "g00gle".translate(HOMOGLYPHS) == "google"


def test_official_brand_domain_has_no_lookalike_flag():
    flags = url_flags("https://www.paypal.com/signin")
    assert not [f for f in flags if "Lookalike" in f["title"]]


def test_lookalike_domain_is_flagged():
    flags = url_flags("https://paypa1.com/login")
    lookalike = [f for f in flags if "Lookalike" in f["title"]]
    assert lookalike and lookalike[0]["severity"] == "high"
    assert "paypal" in lookalike[0]["detail"]


def test_http_scheme_flagged():
    flags = url_flags("http://example.com/login")
    assert any(f["title"] == "No HTTPS" for f in flags)


def test_raw_ip_host_flagged():
    flags = url_flags("https://192.168.1.20/signin")
    assert any(f["title"] == "Raw IP address host" for f in flags)


def test_punycode_host_flagged():
    flags = url_flags("https://xn--pple-43d.com/signin")
    assert any(f["title"] == "Punycode host" for f in flags)


def test_suspicious_tld_flagged():
    flags = url_flags("https://secure-login.xyz/signin")
    assert any("Commonly-abused TLD" in f["title"] for f in flags)


def test_brand_mentions():
    text = "Apple ID sign-in - Apple Support and PayPal verification"
    assert "apple" in brand_mentions(text)
    assert "paypal" in brand_mentions(text)


PAGE = """
<html><head><title>Acme Billing</title>
<meta name="description" content="Pay your bill"></head>
<body>
  <h1>Acme Billing</h1>
  <h2>Statement</h2>
  <form action="/pay" method="post">
    <input type="email" name="email">
    <input type="password" name="pwd">
    <button>Pay</button>
  </form>
  <a href="/help">Help Center</a>
  <a href="https://ads.example.test">Sponsored</a>
  <script>var x = 1; fetch("http://evil.example/x");</script>
  <script src="/app.js"></script>
</body></html>
"""


def test_parse_page_semantics():
    p = parse_page(PAGE, "https://acme.example.com/billing")
    assert p["title"] == "Acme Billing"
    assert p["headings"][0] == "Acme Billing"
    assert len(p["forms"]) == 1
    assert p["forms"][0]["asks_password"] is True
    assert {"name": "pwd", "type": "password"} in p["forms"][0]["fields"]
    assert p["inline_script_count"] == 1
    assert "evil.example" in p["script_blob"]
    assert p["script_srcs"] == ["/app.js"]
    assert len(p["links"]) == 2


def test_fetch_page_blocks_loopback_by_default():
    with pytest.raises(ValueError, match="Raw-IP|not allowed"):
        fetch_page("http://127.0.0.1:8000/static/demo/phish.html")


def test_fetch_page_rejects_non_http():
    with pytest.raises(ValueError):
        fetch_page("ftp://example.com/x")


def _dl_page(script_targets=(), cta=3):
    return {"base_url": "https://example.test/",
            "download": {"cta_count": cta, "installer_links": [], "script_targets": list(script_targets)}}


def test_unofficial_download_source_is_flagged():
    from app.webcheck import page_flags
    flags = page_flags("github-desktop.example", _dl_page(["https://github-desktop.example/"]), ["github"])
    titles = [f["title"] for f in flags]
    assert any("Unofficial download source" in t for t in titles)
    assert any("set by script" in t for t in titles)
    assert flags[0]["severity"] == "high"


def test_vendor_site_mentioning_platforms_is_not_flagged():
    from app.webcheck import page_flags
    # official vendor page that also says "download for macOS / iOS"
    assert page_flags("desktop.github.com", _dl_page(), ["apple", "github"]) == []


def test_raw_ip_url_is_rejected():
    with pytest.raises(ValueError, match="Raw-IP"):
        fetch_page("https://8.8.8.8/")


def test_teredo_is_not_blocked_but_ula_is():
    import ipaddress
    from app.webcheck import _is_blocked
    assert not _is_blocked(ipaddress.ip_address("2001::ae24:c4f2"))
    assert _is_blocked(ipaddress.ip_address("fd00::1"))
    assert _is_blocked(ipaddress.ip_address("10.0.0.5"))


def test_redirect_to_private_host_is_refused(monkeypatch):
    import httpx
    from app import webcheck

    def fake_assert(host):
        if host == "internal.example":
            raise ValueError("not allowed")

    monkeypatch.setattr(webcheck, "_assert_public_host", fake_assert)

    def handler(request):
        if request.url.host == "public.example":
            return httpx.Response(302, headers={"Location": "http://internal.example/admin"})
        return httpx.Response(200, text="secret")

    real_client = httpx.Client

    def client_with_mock(**kw):
        return real_client(transport=httpx.MockTransport(handler), **kw)

    monkeypatch.setattr(webcheck.httpx, "Client", client_with_mock)
    with pytest.raises(ValueError, match="not allowed"):
        webcheck.fetch_page("http://public.example/")


def test_client_redirect_shell_is_detected():
    from app.webcheck import find_client_redirect
    html = ('<html><head><title></title><script>window.location.href="https://im.qq.com/index"'
            '</script></head><body></body></html>')
    assert find_client_redirect(html, "https://im.qq.com/") == "https://im.qq.com/index"


def test_meta_refresh_relative_target():
    from app.webcheck import find_client_redirect
    html = '<meta http-equiv="refresh" content="0; url=/home">'
    assert find_client_redirect(html, "https://example.com/") == "https://example.com/home"


def test_page_with_content_is_not_a_redirect_shell():
    from app.webcheck import find_client_redirect
    html = '<body><h1>Welcome</h1><script>if(x){location.href="/a"}</script></body>'
    assert find_client_redirect(html, "https://example.com/") is None


def test_javascript_scheme_target_is_ignored():
    from app.webcheck import find_client_redirect
    assert find_client_redirect('<script>location.href="javascript:void(0)"</script>',
                                "https://example.com/") is None
