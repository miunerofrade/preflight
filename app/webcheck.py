"""URL preflight: fetch a page safely, summarize its semantics, run deterministic
brand-impersonation checks. Everything here is local/static - no page JS is ever
executed, so analyzing a hostile page is safe."""
from __future__ import annotations

import ipaddress
import re
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

# Public suffixes with two labels, so "uuycpro.com.cn" splits as ("uuycpro", "com.cn").
MULTI_LABEL_SUFFIXES = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "co.uk", "org.uk",
    "com.hk", "com.tw", "co.jp", "com.au", "co.kr", "com.br",
}

INSTALLER_EXTENSIONS = (".exe", ".msi", ".dmg", ".pkg", ".apk", ".deb", ".rpm", ".appimage")
DOWNLOAD_WORDS = ("下载", "download", "安装包", "installer")

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
    """Return (root_label, suffix), aware of two-label suffixes like com.cn."""
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return labels[-3], ".".join(labels[-2:])
    if len(labels) >= 2:
        return labels[-2], labels[-1]
    return host, ""


def is_official(host: str, brand: str) -> bool:
    """True when host is one of the brand's domains or a subdomain of any of them."""
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in BRAND_DOMAINS.get(brand, []))


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
        if is_official(host, brand):
            matched_brand = (brand, official, "official")
            break
    if matched_brand is None:
        for brand, official in BRAND_DOMAINS.items():
            # short keys ("ups", "dhl") would match inside ordinary words like "groups"
            if len(brand) < 4:
                continue
            norm_brand = brand.translate(HOMOGLYPHS)
            inside = norm_brand in tld_root or brand in host
            close = len(brand) >= 5 and levenshtein(tld_root, brand, cap=2) <= 2
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
    return [brand for brand in BRAND_DOMAINS if len(brand) >= 4 and brand in lowered]


def _host_of(url: str, base_url: str) -> str:
    return (urllib.parse.urlsplit(urllib.parse.urljoin(base_url, url)).hostname or "").lower()


def page_flags(host: str, page: dict, claimed: list[str]) -> list[dict]:
    """Checks that need the page: brand claims from a foreign domain, and
    downloads offered for a brand's software from outside that brand's domains."""
    flags: list[dict] = []
    own = [b for b in claimed if is_official(host, b)]
    if own:
        # On a vendor's own domain, other brand names are platforms or partners
        # ("download for macOS"), not identity claims.
        claimed = own
    unofficial = [b for b in claimed if not is_official(host, b)]
    dl = page.get("download") or {}
    offers_download = bool(dl.get("cta_count") or dl.get("installer_links") or dl.get("script_targets"))

    for brand in unofficial:
        official = ", ".join(BRAND_DOMAINS[brand])
        if offers_download:
            flags.append({
                "severity": "high",
                "brand": brand,
                "title": f"Unofficial download source for '{brand}' software",
                "detail": f"The page attributes its software to {brand} and offers "
                          f"{dl.get('cta_count', 0)} download action(s), but '{host}' is not one of the "
                          f"official domains ({official}). Repackaged installers on lookalike mirrors are a "
                          "common malware vector; download only from the vendor's own domain.",
            })
        else:
            flags.append({
                "severity": "medium",
                "brand": brand,
                "title": f"Claims to be '{brand}' from an unofficial domain",
                "detail": f"The page identifies itself as {brand}, but '{host}' is not one of {official}.",
            })

    for target in dl.get("script_targets", []):
        target_host = _host_of(target, page.get("base_url", ""))
        foreign = any(not is_official(target_host, b) for b in claimed) if claimed else False
        flags.append({
            "severity": "medium" if foreign else "low",
            "title": "Download destination is set by script",
            "detail": f"The download buttons have no visible link; a script variable sends them to "
                      f"'{target}'. The destination can be swapped server-side at any time and is "
                      "invisible to someone hovering the button.",
        })

    for link in dl.get("installer_links", []):
        link_host = _host_of(link, page.get("base_url", ""))
        if claimed and all(not is_official(link_host, b) for b in claimed):
            flags.append({
                "severity": "high",
                "title": "Installer hosted outside the vendor's domains",
                "detail": f"Direct installer link '{link}' is served from '{link_host}'.",
            })
    return flags


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

    # structured data often states who the site claims to be ("网易出品")
    claims_text = []
    inline_scripts = []
    for s in soup.find_all("script"):
        if s.get("src"):
            continue
        code = (s.string or "").strip()
        if not code:
            continue
        if (s.get("type") or "").lower() == "application/ld+json":
            claims_text.append(code[:2000])
        inline_scripts.append(code)

    installer_links = []
    cta_count = 0
    for a in soup.find_all(["a", "button"]):
        href = a.get("href") or ""
        label = " ".join(a.get_text(" ", strip=True).split()).lower()
        if href.lower().split("?")[0].endswith(INSTALLER_EXTENSIONS):
            installer_links.append(href)
        if a.has_attr("data-dl") or any(w in label for w in DOWNLOAD_WORDS):
            cta_count += 1
    script_targets = re.findall(
        r"""(?:download_?url|dl_?url)\s*[=:]\s*["']([^"']+)["']""",
        "\n".join(inline_scripts), flags=re.IGNORECASE,
    )
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
        "claims_text": " ".join(claims_text)[:3000],
        "download": {
            "cta_count": cta_count,
            "installer_links": installer_links[:10],
            "script_targets": list(dict.fromkeys(script_targets))[:5],
        },
    }


TEREDO = ipaddress.ip_network("2001::/32")


def _is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # Teredo (2001::/32) is a tunnelling range some resolvers hand out for public
    # sites; it never reaches this machine's private network, so it is not blocked.
    if ip.version == 6 and ip in TEREDO:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast


def _assert_public_host(host: str) -> None:
    """SSRF guard: reject a host if ANY address it resolves to is private,
    loopback, link-local, reserved or multicast."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Raw-IP URLs are not accepted; use a hostname.")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve host '{host}'.") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if _is_blocked(ip):
            raise ValueError(
                f"Host '{host}' resolves to a non-public address ({ip}); "
                "fetching private network targets is not allowed."
            )


def fetch_page(url: str, *, allow_private: bool = False) -> str:
    """Fetch a page's HTML without executing anything it contains."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Provide a valid http(s) URL.")
    hooks = {}
    if not allow_private:
        _assert_public_host(parsed.hostname.strip("[]"))

        def check_hop(request: httpx.Request) -> None:
            # every redirect hop is re-checked, not just the first URL
            _assert_public_host(request.url.host.strip("[]"))

        hooks = {"request": [check_hop]}

    with httpx.Client(
        event_hooks=hooks,
        timeout=FETCH_TIMEOUT,
        follow_redirects=True,
        max_redirects=MAX_REDIRECTS,
        headers={"User-Agent": "PreflightBot/1.0 (security preflight; fetch-only, no JS)"},
    ) as client:
        try:
            res = client.get(url)
        except httpx.ConnectError:
            res = client.get(url)  # one retry: TLS resets on flaky links are common
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
    claimed = brand_mentions(" ".join([page["title"], page["description"], *page["headings"], page["claims_text"]]))
    return {
        "url": url,
        "host": host,
        "page": page,
        "flags": url_flags(url) + page_flags(host, page, claimed),
        "brands_mentioned": claimed,
        "has_password_form": any(f["asks_password"] for f in page["forms"]),
    }
