# Codex input workflow

Preflight provides a local stdio MCP server with two tools. Codex supplies the reference
to an unfamiliar input; Preflight reads and screens it before returning the checked text.

## Setup

Run `uv sync` in this repository. Put this entry in the trusted project's
`.codex/config.toml`, adjusting the checkout path and command for your machine:

```toml
[mcp_servers.preflight]
command = "uv"
args = ["run", "--frozen", "python", "-m", "app.codex_mcp"]
cwd = "/absolute/path/to/preflight"
env_vars = ["CLOCKED_API_KEY"]
startup_timeout_sec = 20
tool_timeout_sec = 180
```

Use an absolute path to `uv` for `command` if it is not on the desktop app's PATH.
The server also reads `CLOCKED_API_KEY` from this repository's ignored `.env`.
Never put the key itself in a committed configuration file. The machine-specific
`.codex/config.toml` in this checkout is ignored.

Refresh the MCP connection or start a new Codex session after adding it. `codex mcp list`
checks configuration; it does not prove a model scan succeeded. Codex's official
[MCP configuration documentation](https://developers.openai.com/codex/mcp) describes
project configuration, stdio launch commands and client restart requirements.

## Tools and release contract

| Tool | Input | Result |
|---|---|---|
| `preflight_open` | `source`: workspace path or public URL; `language`: `en` or `zh` | Returns only a ticket, status and, when needed, review link. Only `released` includes usable `content`. Clocked usage is paid normally. |
| `preflight_read` | The ticket from `preflight_open` | Returns the exact stored copy after human approval, without rescanning. It cannot approve an input. |

Clean, ready text is released immediately. Copies requiring review return `pending`
without body text. Codex shows the `review_url` to the person and waits. The local web
page displays the existing scan report, source annotations and edit comparison. The
person checks the copy, then selects **Allow Codex to read**, or rejects the handoff.
The decision is stored on the server and bound to the revision number and candidate's SHA-256. Codex calls
`preflight_read` after the person's response. Repeated polling is unnecessary.

`blocked`, `rejected`, expired tickets and errors never return body text or an unchecked
draft through MCP. Full reports, approval records and source/copy hashes remain on the
review side rather than being returned to Codex. The original disposition stays intact
when an edited copy is eligible for release. If the task only needs a summary, Codex
summarizes the released content; no extra Fill call is required. Source changes after
checking do not change an already reviewed snapshot; use a new ticket to check them.

There is no MCP approval tool. Agents must not call the web decision endpoint or
operate the review UI on the person's behalf. This is a cooperative workflow, not a
sandbox or network interceptor that prevents Codex from using arbitrary shell/browser
tools. The `AGENTS.md` instruction is part of the integration contract.

### Editing a pending copy

The browser submits `text`, `base_revision`, `request_id` and its review token to
`POST /api/agent-inputs/{ticket}/revision`. The server scans the text and binds the
result; client-supplied reports are rejected. A human edit always requires a fresh
confirmation, even when its scan passes. The browser then reads the current review
snapshot rather than displaying a cached operation result.

The original source is retained separately from each revision's submitted text,
scan report and prepared copy. Approval includes `base_revision` and
`candidate_sha256`; stale revisions are refused even when their copies are identical.
JSON exports include the version records; Markdown lists their parents, hashes and
approval times. These records are available only on the human review side.

Operation IDs are retained for the ticket's lifetime (at most 64 operations per
ticket). Repeating the same ID, version and text reuses completed work; a different
payload is refused. A failed edit and its operation ID survive browser refresh and
can be retried. While a revision is unresolved, the old copy cannot be approved.
Explicit abandonment names both the operation ID and base revision; a scan that
finishes after abandonment cannot overwrite another version. Review-page polling
only reads status, stops after 90 seconds per wait, and can be resumed manually.

## Supported sources

- UTF-8 workspace text documents and code files, up to 20,000 characters and 10 MB.
  Paths and resolved symlinks must stay inside the checkout; internal dependency,
  configuration, `.env` and private-key files are excluded.
- Text-layer PDFs up to 20 pages, 10 MB and 20,000 extracted characters. Local PDF
  structure checks accompany the text scan. Encrypted, image-only, incomplete or
  over-limit documents are not silently treated as clean. No OCR or visual pipeline
  is added here.
- Public HTTP(S) URLs through the existing SSRF-checked fetch and identity analysis.
  A blocked URL stops before text handoff processing. Other pages also pass the text
  pipeline for PII and copy construction. Only page body text is handed over: scripts
  are not executed and installers are not downloaded. Long pages are rejected rather
  than silently truncated for handoff.

Unsupported image/document formats remain available for the existing web risk-report
workflow where applicable; this MCP path does not manufacture a text copy for them.

## Local process and data lifetime

Each Codex MCP connection starts its own loopback review server on an available port;
the normal `uvicorn` web app does not need to be running. The SDK owns stdio protocol
handling. Review logs do not print capability URLs to stdout. Tokens, source text,
reports and copies remain in process memory for at most 30 minutes, with a 32-ticket
limit, and disappear when the connection stops. Nothing is written to a review database.
The browser review routes check the local host, same origin and per-ticket token; the
approval request must name the revision number and candidate hash. Expired links require a new check.

Text and document contents are sent to Clocked for scanning. URL checks additionally
use the existing public reputation sources. Review pages use the shared UI, language
catalogs and styles. Fill is optional and does not approve or change the copy.

This implementation stops at functional integration and focused checks. Demonstration
production and publishing are intentionally left to the person assigned that work.
