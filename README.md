# Preflight

**Security check for anything you are about to feed an AI agent.**

Agents now read email, web pages, documents and code written by strangers. Preflight is the
30-second check you run *before* that content reaches your agent: paste it (or drop a PDF /
image), get an **allow / review / block** verdict with character-exact evidence, and a
sanitized copy of the text with personal data masked.

Built for the **Clocked Build Challenge** (Oct 21 – Nov 10, 2026).

## The problem

Prompt injection is the #1 risk in the OWASP Top 10 for LLM applications, and real zero-click
agent leaks have already shipped in the wild. Meanwhile the standard workflow is still
"copy suspicious content, paste it into your agent, hope for the best". Preflight makes the
paranoid step automatic — for **any** kind of agent input, not one vertical.

## Features

- **Single scan** — paste text, get the full three-layer report with annotated source.
- **PDF & image scans** — drop a contract PDF or a screenshot; multimodal endpoints do the rest.
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

Awards entered: **Best Use of Protect/Guard/Inspect** (all three endpoints, full breadth) and
**Best Overall App** (the two Decide calls cross into the Decide/Extract/Fill group).

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
uv run pytest -q        # 24 tests, all Clocked responses mocked - no key, no network
```

CI (`.github/workflows/ci.yml`) runs the suite plus a JS syntax check on every push.
Tests lock the pipeline contract: call ordering, the conditional Inspect skip, masking
parameters, verdict-summary forwarding, usage aggregation, and the API error mapping.

## Measured costs (real runs, Oct 2026)

| Scenario | Calls | Tokens | Wall time |
|---|---|---|---|
| Text scan with code (5 layers) | 5 | 259 in / 5 out | ~2.4 s |
| PDF scan, 1 page (4 layers) | 4 | 93 in / 5 out | ~2.2 s |
| Batch of 2 | 8–9 | ~500 in | ~4 s |

A full development cycle fits comfortably inside the 20,000 challenge credits.

## Limitations (honest section)

- Preflight is a pre-screening aid, not a guarantee: treat every verdict as one signal.
- Deterministic forgeries (fake invoices with correct checksums, lookalike domains) are out of
  scope; Preflight judges content semantics, not business-logic truth.
- Script inspection requires pasted code text; PDFs with embedded scripts get the verdict
  from the other layers and an explicit note instead of a pretend result.
- Batch is capped at 10 items and 20,000 characters each; this is a preflight gate, not a
  streaming pipeline.

## Stack

- Python 3.10+, managed with [uv](https://docs.astral.sh/uv/)
- `clocked-sdk` 0.7.0 (sync client, retries and idempotency built in)
- FastAPI + one static HTML/CSS/JS page — no frontend build chain
