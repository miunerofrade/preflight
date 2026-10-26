"""URL preflight: fetch a page safely, summarize its semantics, run deterministic
brand-impersonation checks. Everything here is local/static - no page JS is ever
executed, so analyzing a hostile page is safe."""
from __future__ import annotations

import ipaddress
import socket
import urllib.parse

import httpx
from bs4 import BeautifulSoup

MAX_HTML_BYTES = 2 * 1024 * 1024  # 2 MB of HTML is plenty
MAX_REDIRECTS = 3
FETCH_TIMEOUT = 15.0

# Brand -> domains that legitimately belong to it.
BRAND_DOMAINS = {
    "paypal": ["paypal.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "bing.com"],
    "google": ["google.com", "gmail.com", "googleusercontent.com", "youtube.com"],
    "amazon": ["amazon.com", "amazonpay.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "meta.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "github": ["github.com"],
    "linkedin": ["linkedin.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "discord": ["discord.com", "discordapp.com"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "hsbc": ["hsbc.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "usps": ["usps.com"],
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "online", "site", "icu", "cfd", "click", "live",
    "rest", "buzz", "surf", "monster", "quest", "sbs", "cam",
}

# single-character homoglyphs commonly used in lookalike domains
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "$": "s", "@": "a"})


def levenshtein(a: str, b: str, cap: int = 3) -> int:
    """Small Levenshtein with an early-exit cap (returns cap+1 when further away)."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        row_min = i
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            cur.append(v)
            row_min = min(row_min, v)
        if row_min > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def _registrable_parts(host: str) -> tuple[str, str]:
    """Return (root_label, tld) with a dumb-but-deterministic two-label split."""
    labels = host.split(".")
    if len(labels) >= 2:
        return labels[-2], labels[-1]
    return host, ""


def url_flags(url: str) -> list[dict]:
    """Deterministic impersonation / structure checks on the URL itself."""
    flags: list[dict] = []
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")

    if scheme != "https":
        flags.append({"severity": "low", "title": "No HTTPS",
                      "detail": f"Scheme is '{scheme or 'none'}'; legitimate login pages are always HTTPS."})

    # IP-literal host
    try:
        ipaddress.ip_address(host)
        flags.append({"severity": "high", "title": "Raw IP address host",
                      "detail": f"Host is the literal IP {host}; brands never serve logins from bare IPs."})
    except ValueError:
        pass

    if host.startswith("xn--") or ".xn--" in host:
        flags.append({"severity": "high", "title": "Punycode host",
                      "detail": "Punycode (xn--) hosts can visually mimic non-Latin brand names."})

    root, tld = _registrable_parts(host)
    tld_root = root.translate(HOMOGLYPHS)

    # brand containment / lookalike distance
    matched_brand = None
    for brand, official in BRAND_DOMAINS.items():
        if host in official or host.endswith("." + official[0]):
            matched_brand = (brand, official, "official")
            break
    if matched_brand is None:
        for brand, official in BRAND_DOMAINS.items():
            norm_brand = brand.translate(HOMOGLYPHS)
            inside = norm_brand in tld_root or brand in host
            close = levenshtein(tld_root, brand, cap=2) <= 2
            if inside or close:
                matched_brand = (brand, official, "lookalike")
                flags.append({
                    "severity": "high",
                    "title": f"Lookalike domain for '{brand}'",
                    "detail": f"'{host}' is close to brand domain '{official[0]}' "
                              f"(normalized '{tld_root}' vs '{brand}'), but it is not an official domain.",
                })
                break

    if tld in SUSPICIOUS_TLDS:
        flags.append({"severity": "low", "title": f"Commonly-abused TLD '.{tld}'",
                      "detail": "This TLD shows up in phishing campaigns disproportionately often."})

    return flags


def brand_mentions(text: str) -> list[str]:
    """Which known brands does the page text claim to be? (title/headings are preferred input)"""
    lowered = text.lower()
    return [brand for brand in BRAND_DOMAINS if brand in lowered]


def parse_page(html: str, base_url: str) -> dict:
    """Semantic summary of the page - the poor man's accessibility tree."""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["style", "noscript", "svg"]):
        tag.decompose()

    title = (soup.title.string or "").strip() if soup.title else ""
    meta = soup.find("meta", attrs={"name": "description"})
    description = (meta.get("content") or "").strip() if meta else ""

    headings = [" ".join(h.get_text(" ", strip=True).split()) for h in soup.find_all(["h1", "h2"], limit=8)]
    headings = [h for h in headings if h][:8]

    forms = []
    for form in soup.find_all("form", limit=5):
        fields = []
        for inp in form.find_all(["input", "textarea", "select"], limit=15):
            ftype = (inp.get("type") or "text").lower() if inp.name == "input" else inp.name
            fields.append({"name": inp.get("name") or inp.get("id") or "", "type": ftype})
        forms.append({
            "action": form.get("action") or "",
            "method": (form.get("method") or "get").lower(),
            "fields": fields,
            "asks_password": any(f["type"] == "password" for f in fields),
        })

    links = []
    for a in soup.find_all("a", href=True, limit=40):
        href = a["href"]
        text = " ".join(a.get_text(" ", strip=True).split())[:60]
        if text or href.startswith(("http", "/")):
            links.append({"text": text, "href": href})
    links = links[:20]

    inline_scripts = []
    for s in soup.find_all("script"):
        if s.get("src"):
            continue
        code = (s.string or "").strip()
        if code:
            inline_scripts.append(code)
    script_blob = "\n\n".join(inline_scripts)[:8000]
    script_srcs = [s["src"] for s in soup.find_all("script", src=True, limit=10)]

    body_text = " ".join(soup.get_text(" ", strip=True).split())[:4000]

    return {
        "title": title[:200],
        "description": description[:300],
        "headings": headings,
        "forms": forms,
        "links": links,
        "inline_script_count": len(inline_scripts),
        "script_srcs": script_srcs,
        "script_blob": script_blob,
        "body_text": body_text,
        "base_url": base_url,
    }


def _assert_public_host(host: str) -> None:
    """SSRF guard: reject hosts that resolve to private/loopback/link-local space."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve host '{host}'.") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise ValueError(
                f"Host '{host}' resolves to a non-public address ({ip}); "
                "fetching private network targets is not allowed."
            )


def fetch_page(url: str, *, allow_private: bool = False) -> str:
    """Fetch a page's HTML without executing anything it contains."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Provide a valid http(s) URL.")
    if not allow_private:
        host = parsed.hostname.strip("[]")
        try:
            ipaddress.ip_address(host)
            raise ValueError("Raw-IP URLs are not accepted; use a hostname.")
        except ValueError:
            pass  # hostname, not an IP literal - DNS check below decides
        _assert_public_host(host)

    with httpx.Client(
        timeout=FETCH_TIMEOUT,
        follow_redirects=True,
        max_redirects=MAX_REDIRECTS,
        headers={"User-Agent": "PreflightBot/1.0 (security preflight; fetch-only, no JS)"},
    ) as client:
        res = client.get(url)
        res.raise_for_status()
        if len(res.content) > MAX_HTML_BYTES:
            raise ValueError("Page is over the 2 MB analysis limit.")
        return res.text


def summarize_url(url: str, *, allow_private: bool = False) -> dict:
    """Fetch + parse + deterministic flags in one call (no Clocked involvement)."""
    page_html = fetch_page(url, allow_private=allow_private)
    parsed = urllib.parse.urlsplit(url)
    host = (parsed.hostname or "").lower()
    page = parse_page(page_html, url)
    return {
        "url": url,
        "host": host,
        "page": page,
        "flags": url_flags(url),
        "brands_mentioned": brand_mentions(" ".join([page["title"], *page["headings"]])),
        "has_password_form": any(f["asks_password"] for f in page["forms"]),
    }
