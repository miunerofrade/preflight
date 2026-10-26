# Preflight

**Security check for anything you are about to feed an AI agent.**

Agents now read email, web pages, documents and code written by strangers. Preflight is the
30-second check you run *before* that content reaches your agent: paste it (or drop a PDF /
image, or give it a URL), get an **allow / review / block** verdict with character-exact
evidence, and a sanitized copy of the text with personal data masked.

Built for the **Clocked Build Challenge** (Oct 21 – Nov 10, 2026).

## The problem

Prompt injection is the #1 risk in the OWASP Top 10 for LLM applications, and real zero-click
agent leaks have already shipped in the wild. Meanwhile the standard workflow is still
"copy suspicious content, paste it into your agent, hope for the best". Preflight makes the
paranoid step automatic — for **any** kind of agent input, not one vertical.

## Features

- **Single scan** — paste text, get the full three-layer report with annotated source.
- **PDF & image scans** — drop a contract PDF or a screenshot; multimodal endpoints do the rest.
- **URL scan** — give it a link: deterministic domain checks (lookalike/homoglyph brands,
  suspicious TLDs, punycode, raw IPs) plus a semantic page summary (forms, links, headings,
  inline scripts) judged by Clocked. The page is fetched **statically — its JavaScript is
  never executed**, so analyzing hostile pages is safe.
- **Batch triage** — paste up to 10 items separated by `---`; results are ranked by risk and
  each row opens the full report.
- **One-click examples** — three canned cases (phishing email, malicious script, benign notes)
  for a 30-second demo.
- **Export** — every report downloads as JSON or a Markdown audit artifact.

## How a scan works

Worst case five Clocked calls, ~2.5 seconds, a few hundred tokens:

| # | Layer | Clocked endpoint | How the output changes the app |
|---|-------|------------------|--------------------------------|
| 1 | Guard | `injection` | Injection score, category breakdown and severity drive the Guard card; every evidence span (`start`/`end`) is highlighted in red in the annotated source. |
| 2 | Protect | `pii` | Entity list populates the Personal data card; the returned `anonymized_text` is the one-click sanitized copy. |
| 3 | Routing | `decide` | Decides whether the content contains executable code. If not, layer 4 is skipped entirely — no unnecessary API calls. |
| 4 | Inspect | `script` | Malicious/suspicious scores and threat category drive the Script card; evidence spans are highlighted in purple. Runs **only** when routing says there is code. |
| 5 | Verdict | `decide` | Reads a structured summary of layers 1–4 and issues the final `allow / review / block` with calibrated probabilities. |

PDF/image scans run layers 1–3 and 5 (4 calls); `script` is a text-only endpoint, so file
scans say so explicitly instead of pretending.

### URL scans (link preflight)

The page is fetched without executing its JS and parsed into a semantic summary (title,
description, headings, JSON-LD structured data, forms + field types, link text→href pairs,
download buttons, inline script sources). No brand list is needed to judge it:

- **Who does the page claim to be?** Clocked `extract` pulls the claimed organization and
  product from the title, description and structured data, in any language.
- **Where does that identity really live?** The claimed name is looked up on Wikidata
  ("official website", falling back to the developer / owner when a product lists none).
- **How trustworthy is the domain?** Registration date via RDAP (WHOIS port 43 for TLDs
  without RDAP, such as `.cn`), and popularity via the Tranco top-1M list (cached locally).
- Small deterministic checks stay: punycode, raw-IP hosts, missing HTTPS, download targets
  hidden in script variables.

Then up to six calls covering **all three Clocked capability groups**:

| # | Layer | Endpoint | What it decides |
|---|-------|----------|-----------------|
| 0 | Claimed identity | `extract` | Organization / product the page presents itself as, with character offsets. |
| 1 | Impersonation + intent | `decide` (dual question) | Impersonation vs legitimate; credential harvesting vs scam vs benign. |
| 2 | Guard | `injection` | Prompt injection aimed at agents reading the page. |
| 3 | Inspect | `script` (conditional) | Static analysis of inline scripts (never executed). |
| 4 | Identity | `grounding` (conditional) | Checks "this site is an official property of X" against the public record (Wikidata domains, registration date, rank). |
| 5 | Verdict | `decide` | allow / review / block. An `allow` below 0.5 confidence is shown as **review**, with the model's own choice kept in the report. |

Lookups fail soft: an unreachable registry or Wikidata yields "unknown", never a risk signal.
**Data flow note:** URL scans send the scanned domain to IANA/RDAP or WHOIS registries,
Wikidata and (once) Tranco, in addition to Clocked.

Field test (Oct 26, 2026, real APIs): five fake Chinese download mirrors (UU远程 ×2, 腾讯会议,
钉钉, 夸克网盘) were all blocked at 0.95–0.99, and the official `y.qq.com` download page was
allowed at 0.99 — with no Chinese brand in any table.

SSRF-safe by construction: private/loopback/link-local targets are refused unless
`PREFLIGHT_ALLOW_PRIVATE_URLS=1` (used only to scan the bundled synthetic demo page at
`/static/demo/phish.html`, whose exfil target is the reserved `.invalid` TLD).

Awards entered: **Best Use of Protect/Guard/Inspect** (all three endpoints, full breadth) and
**Best Overall App** — URL scans additionally cross into the grounding/compare/rerank group,
so Preflight meaningfully uses endpoints from every capability group.

## Run it locally

```bash
uv sync                              # install clocked-sdk + fastapi + uvicorn
cp .env.example .env                 # then put your key in .env
uv run uvicorn app.main:app          # http://127.0.0.1:8000
```

No build step, no database, no external services beyond the Clocked API.
The API key lives only in `.env` (git-ignored) and is never exposed to the browser.

## Tests

```bash
uv run pytest -q        # 43 tests, all Clocked responses mocked - no key, no network needed
```

CI (`.github/workflows/ci.yml`) runs the suite plus a JS syntax check on every push.
Tests lock the pipeline contract: call ordering, the conditional Inspect skip, masking
parameters, verdict-summary forwarding, usage aggregation, the API error mapping,
deterministic URL checks, and SSRF refusal.

## Measured costs (real runs, Oct 2026)

| Scenario | Calls | Tokens | Wall time |
|---|---|---|---|
| Text scan with code (5 layers) | 5 | 259 in / 5 out | ~2.4 s |
| PDF scan, 1 page (4 layers) | 4 | 93 in / 5 out | ~2.2 s |
| URL scan, synthetic phishing page (5 layers) | 5 | 424 in / 10 out | ~3.0 s |
| URL scan, real site with reputation lookups (6 layers) | 6 | ~1,500 in / 10 out | 3–7 s (first scan +10 s to load Tranco) |
| Batch of 2 | 8–9 | ~500 in | ~4 s |

A full development cycle fits comfortably inside the 20,000 challenge credits.

## Limitations (honest section)

- Preflight is a pre-screening aid, not a guarantee: treat every verdict as one signal.
- Deterministic forgeries (fake invoices with correct checksums, lookalike domains) are out of
  scope; Preflight judges content semantics, not business-logic truth.
- Script inspection requires pasted code text; PDFs with embedded scripts get the verdict
  from the other layers and an explicit note instead of a pretend result.
- URL reputation is evidence, not proof: a new, unranked domain can be a legitimate new
  site, and Wikidata does not know every product (e.g. 夸克网盘); then the verdict rests on the
  other layers. A fake download source is flagged, but the installer itself is never fetched
  or analyzed.
- Batch is capped at 10 items and 20,000 characters each; this is a preflight gate, not a
  streaming pipeline.

## Stack

- Python 3.10+, managed with [uv](https://docs.astral.sh/uv/)
- `clocked-sdk` 0.7.0 (sync client, retries and idempotency built in)
- FastAPI + one static HTML/CSS/JS page — no frontend build chain
