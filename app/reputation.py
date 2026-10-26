"""Brand-agnostic domain reputation: how old is the domain, how popular is it,
and does it belong to the organization the page claims to be?

No brand list is involved. The page's claimed identity comes from Clocked
extract; the identity's official domains come from Wikidata; age comes from
RDAP (WHOIS port 43 where the TLD has no RDAP); popularity from the Tranco
top-1M list. Every lookup fails soft: an unreachable source yields "unknown",
never an exception, and unknown is never treated as evidence of risk."""
from __future__ import annotations

import csv
import datetime as dt
import functools
import ipaddress
import io
import pathlib
import re
import socket
import zipfile

import httpx

from .webcheck import MULTI_LABEL_SUFFIXES

LOOKUP_TIMEOUT = 8.0
NEW_DOMAIN_DAYS = 90
# a domain this popular and this old is treated as established
ESTABLISHED_RANK = 100_000
ESTABLISHED_DAYS = 3 * 365
USER_AGENT = "PreflightBot/1.0 (https://github.com/miunerofrade/preflight; security preflight research)"
CACHE_DIR = pathlib.Path(__file__).resolve().parent.parent / ".cache"
TRANCO_FILE = CACHE_DIR / "tranco-top1m.csv"

WHOIS_SERVERS = {
    "cn": "whois.cnnic.cn",
    "io": "whois.nic.io",
    "ru": "whois.tcinet.ru",
    "de": "whois.denic.de",
    "jp": "whois.jprs.jp",
}
WHOIS_DATE_PATTERNS = (
    r"Registration Time:\s*([0-9][0-9:\- T]+)",
    r"Creation Date:\s*([0-9][0-9:\-TZ.]+)",
    r"created:\s*([0-9][0-9:\-TZ.]+)",
    r"\[Created on\]\s*([0-9/]+)",
)


PSL_FILE = CACHE_DIR / "psl.dat"
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"


@functools.lru_cache(maxsize=1)
def _public_suffixes() -> frozenset[str]:
    """Public Suffix List (cached on disk). Includes hosting platforms such as
    vercel.app or github.io, so 'x.vercel.app' is its own site, not vercel.app."""
    try:
        if not PSL_FILE.exists():
            with _client() as c:
                res = c.get(PSL_URL)
            res.raise_for_status()
            CACHE_DIR.mkdir(exist_ok=True)
            PSL_FILE.write_text(res.text, encoding="utf-8")
        rules = set()
        for line in PSL_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip().lower()
            if line and not line.startswith(("//", "!")):
                rules.add(line[2:] if line.startswith("*.") else line)
        return frozenset(rules)
    except Exception:
        return frozenset(MULTI_LABEL_SUFFIXES)


def registrable_domain(host: str) -> str:
    """'uuyc.163.com' -> '163.com', 'a.example.com.cn' -> 'example.com.cn',
    'fake.vercel.app' -> 'fake.vercel.app'."""
    labels = host.lower().rstrip(".").split(".")
    suffixes = _public_suffixes()
    for i in range(1, len(labels)):
        if ".".join(labels[i:]) in suffixes:
            return ".".join(labels[i - 1:])
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _skip_lookup(host: str) -> bool:
    if host == "localhost" or host.endswith((".localhost", ".invalid", ".test")):
        return True
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _client() -> httpx.Client:
    return httpx.Client(timeout=LOOKUP_TIMEOUT, follow_redirects=True, headers={"User-Agent": USER_AGENT})


def _parse_date(raw: str) -> dt.datetime | None:
    """Registries disagree on formats; the calendar date is all that matters here."""
    m = re.search(r"(\d{4})[-/](\d{2})[-/](\d{2})", raw)
    if not m:
        return None
    return dt.datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=dt.timezone.utc)


# --------------------------------------------------------------------------
# domain age: RDAP first, WHOIS port 43 for TLDs without RDAP (.cn, .io, .ru ...)
# --------------------------------------------------------------------------

@functools.lru_cache(maxsize=1)
def _rdap_bootstrap() -> dict[str, str]:
    with _client() as c:
        data = c.get("https://data.iana.org/rdap/dns.json").json()
    return {tld.lower(): urls[0] for tlds, urls in data.get("services", []) for tld in tlds}


def _rdap_created(domain: str) -> dt.datetime | None:
    base = _rdap_bootstrap().get(domain.rsplit(".", 1)[-1])
    if not base:
        return None
    with _client() as c:
        res = c.get(base.rstrip("/") + "/domain/" + domain)
    if res.status_code != 200:
        return None
    for event in res.json().get("events", []):
        if event.get("eventAction") == "registration":
            return _parse_date(event.get("eventDate", ""))
    return None


def _whois_query(server: str, query: str) -> str:
    with socket.create_connection((server, 43), timeout=LOOKUP_TIMEOUT) as sock:
        sock.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _whois_created(domain: str) -> dt.datetime | None:
    server = WHOIS_SERVERS.get(domain.rsplit(".", 1)[-1])
    if not server:
        return None
    text = _whois_query(server, domain)
    for pattern in WHOIS_DATE_PATTERNS:
        m = re.search(pattern, text, flags=re.IGNORECASE)
        if m:
            return _parse_date(m.group(1))
    return None


@functools.lru_cache(maxsize=512)
def domain_age(domain: str) -> dict:
    """{'created': iso|None, 'age_days': int|None, 'source': 'rdap'|'whois'|None}."""
    for source, fn in (("rdap", _rdap_created), ("whois", _whois_created)):
        try:
            created = fn(domain)
        except Exception:  # network / parse failures are "unknown", not risk
            created = None
        if created:
            age = (dt.datetime.now(dt.timezone.utc) - created).days
            return {"created": created.date().isoformat(), "age_days": age, "source": source}
    return {"created": None, "age_days": None, "source": None}


# --------------------------------------------------------------------------
# popularity: Tranco top-1M (downloaded once, cached on disk)
# --------------------------------------------------------------------------

def _download_tranco() -> None:
    with _client() as c:
        latest = c.get("https://tranco-list.eu/api/lists/date/latest").json()
        res = c.get(latest["download"], timeout=120.0)
    res.raise_for_status()
    CACHE_DIR.mkdir(exist_ok=True)
    body = res.content
    if body[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(body)) as z:
            body = z.read(z.namelist()[0])
    TRANCO_FILE.write_bytes(body)


@functools.lru_cache(maxsize=1)
def _tranco_ranks() -> dict[str, int]:
    if not TRANCO_FILE.exists():
        _download_tranco()
    ranks: dict[str, int] = {}
    with TRANCO_FILE.open(encoding="utf-8") as f:
        for row in csv.reader(f):
            if len(row) >= 2:
                ranks[row[1].strip().lower()] = int(row[0])
    return ranks


def tranco_rank(domain: str) -> int | None:
    try:
        return _tranco_ranks().get(domain)
    except Exception:
        return None


def tranco_available() -> bool:
    try:
        return bool(_tranco_ranks())
    except Exception:
        return False


# --------------------------------------------------------------------------
# claimed identity -> official domains (Wikidata P856 "official website")
# --------------------------------------------------------------------------

WIKIDATA_API = "https://www.wikidata.org/w/api.php"
OFFICIAL_WEBSITE = "P856"
# developer, manufacturer, owned by, parent organization: where a product's
# vendor lives when the product item itself lists no website
OWNER_PROPERTIES = ("P178", "P176", "P127", "P749")
# words pages bolt onto a name ("钉钉官网", "Zoom download") that break the search
NAME_NOISE = re.compile(r"(官方网站|官网|官方|下载中心|下载|客户端|电脑版|official site|official|download)", re.I)


def _claims(c: httpx.Client, entity: str) -> dict:
    return c.get(WIKIDATA_API, params={"action": "wbgetclaims", "entity": entity, "format": "json"}
                 ).json().get("claims", {})


def _websites(claims: dict) -> list[str]:
    urls = [cl["mainsnak"].get("datavalue", {}).get("value", "") for cl in claims.get(OFFICIAL_WEBSITE, [])]
    return sorted({registrable_domain(httpx.URL(u).host) for u in urls if isinstance(u, str) and u.startswith("http")})


def _owner_ids(claims: dict) -> list[str]:
    ids = []
    for prop in OWNER_PROPERTIES:
        for cl in claims.get(prop, []):
            value = cl["mainsnak"].get("datavalue", {}).get("value") or {}
            if isinstance(value, dict) and value.get("id"):
                ids.append(value["id"])
    return list(dict.fromkeys(ids))


def _norm(name: str) -> str:
    return re.sub(r"[\s\W_]+", "", name.lower())


@functools.lru_cache(maxsize=256)
def official_domains(name: str) -> dict:
    """Look up an organization or product by name; return its Wikidata id and official
    domains. Products without a website fall back to their developer / owner's domains."""
    cleaned = NAME_NOISE.sub("", name).strip(" -|·")
    if not cleaned:
        return {"entity": None, "label": None, "domains": [], "via": None}
    try:
        with _client() as c:
            lang = "zh" if re.search(r"[\u4e00-\u9fff]", cleaned) else "en"
            hits = c.get(WIKIDATA_API, params={
                "action": "wbsearchentities", "search": cleaned, "language": lang,
                "uselang": lang, "type": "item", "limit": 3, "format": "json",
            }).json().get("search", [])
            for hit in hits:
                # search is fuzzy ("ToDesk" also finds "ToDesktop"); only an exact
                # label/alias match counts as the same organization
                matched = (hit.get("match") or {}).get("text") or hit.get("label") or ""
                if _norm(matched) != _norm(cleaned):
                    continue
                claims = _claims(c, hit["id"])
                domains = _websites(claims)
                if domains:
                    return {"entity": hit["id"], "label": hit.get("label"), "domains": domains, "via": None}
                for owner in _owner_ids(claims)[:3]:
                    owner_domains = _websites(_claims(c, owner))
                    if owner_domains:
                        return {"entity": hit["id"], "label": hit.get("label"),
                                "domains": owner_domains, "via": owner}
    except Exception:
        pass
    return {"entity": None, "label": None, "domains": [], "via": None}


def host_belongs_to(host: str, domains: list[str]) -> bool:
    reg = registrable_domain(host)
    return any(reg == d or host == d or host.endswith("." + d) for d in domains)


# --------------------------------------------------------------------------
# combine into flags
# --------------------------------------------------------------------------

def reputation(host: str, claimed_orgs: list[str], offers_download: bool) -> dict:
    """Look everything up and turn it into severity-tagged flags."""
    host = host.lower().rstrip(".")
    if _skip_lookup(host):
        return {"domain": host, "age": None, "rank": None, "identity": [], "flags": [],
                "note": "Local or reserved host: reputation lookups skipped."}

    domain = registrable_domain(host)
    age = domain_age(domain)
    rank = tranco_rank(domain)
    ranked_known = tranco_available()
    identity = []
    for org in dict.fromkeys(o for o in claimed_orgs if o):
        info = official_domains(org)
        identity.append({"claimed": org, **info,
                         "matches": host_belongs_to(host, info["domains"]) if info["domains"] else None})

    flags: list[dict] = []
    mismatched = [i for i in identity if i["matches"] is False]
    if any(i["matches"] is True for i in identity):
        # the host is official for one claimed name (product on its own domain,
        # parent group listed elsewhere): the other names are not counter-evidence
        mismatched = []
    established = bool(rank and rank <= ESTABLISHED_RANK and (age["age_days"] or 0) >= ESTABLISHED_DAYS)
    if established and mismatched:
        names = ", ".join(i["claimed"] for i in mismatched)
        for item in mismatched:
            item["weak"] = True
        flags.append({
            "severity": "low",
            "title": f"'{names}' does not list this domain",
            "detail": f"Wikidata does not list '{domain}' for {names}, but the domain is "
                      f"{age['age_days'] // 365} years old and ranks #{rank} worldwide. Large groups run "
                      "many domains, so this is weak evidence on an established domain.",
        })
        mismatched = []
    for item in mismatched:
        sev = "high" if offers_download else "medium"
        what = "offers software downloads" if offers_download else "presents itself"
        flags.append({
            "severity": sev,
            "title": f"Claims to be '{item['claimed']}' from a domain it does not own",
            "detail": f"The page {what} as {item['claimed']}, whose official domains per Wikidata "
                      f"({item['entity']}) are {', '.join(item['domains'])}; '{domain}' is not one of them.",
        })
    if age["age_days"] is not None and age["age_days"] < NEW_DOMAIN_DAYS:
        flags.append({
            "severity": "medium" if (mismatched or offers_download) else "low",
            "title": f"Newly registered domain ({age['age_days']} days old)",
            "detail": f"'{domain}' was registered on {age['created']} (via {age['source']}). "
                      "New domains are common for phishing and fake download mirrors, "
                      "though new legitimate sites exist too.",
        })
    if ranked_known and rank is None:
        flags.append({
            "severity": "low",
            "title": "Not in the global top-1M sites (Tranco)",
            "detail": f"'{domain}' has no Tranco rank. Official vendor sites almost always rank; "
                      "on its own this only means the site is small.",
        })
    return {"domain": domain, "age": age, "rank": rank, "identity": identity, "flags": flags}
