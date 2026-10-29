# Real-response text regression corpus

Recorded against Clocked on October 26, 2026 (the last five cases on October 29) using `clocked-sdk` 0.7.0 and the synthetic
inputs in `cases/text.json`. Every top-level JSON includes the input and expectations,
ordered request bodies, unmodified response bodies, selected billing metadata, observed
outcome and full report. API keys and authorization headers are never recorded.

| Case | Expected / observed original | Expected copy | Observed copy | Calls | Credits |
|---|---|---|---|---:|---:|
| clean-notes | allow / allow | ready | ready | 4 | 6 |
| private-ticket | review / review | ready | review | 8 | 14 |
| hidden-instruction | block / block | review | review | 8 | 13 |
| hidden-instruction-zh | block / block | review | review | 8 | 13 |
| credential-script | block / block | review | review | 5 | 11 |
| ordinary-script | allow / allow | ready | ready | 5 | 9 |
| quoted-security-guide | allow / allow | ready | ready | 4 | 6 |
| normal-zh-notice | allow / allow | ready | ready | 4 | 6 |
| download-lure-zh | block / block | review | withheld | 4 | 10 |
| mixed-doc-risky-block | block / block | review | review | 9 | 18 |
| mixed-doc-benign-block | allow / allow | ready | ready | 5 | 12 |
| long-page-buried-zh | block / block | review | review | 8 | 27 |
| Total | 12 / 12 original dispositions matched | | 10 / 12 complete outcomes matched | 72 | 145 |

Five cases were added on October 29, 2026: a Chinese office notice, a Chinese third-party
download lure, a long Chinese weekly report with one buried instruction, and a mixed setup
guide in two versions (one fenced block that exfiltrates credentials, and the same shape
with an ordinary block as a control). Their original dispositions all matched. Cost and
timing across the twelve cases (one run from one machine, including network time and
retries, not asserted by any test): 72 calls, 145 credits (about $0.029), and
1.6 to 10.6 s of wall-clock time per case.

`download-lure-zh` keeps an observed deviation from its expected review copy. Guard found
one critical evidence span and the original is blocked, but the routing question answered
no_code with only 0.13 confidence, so the local policy records routing_uncertain, treats
the checks as incomplete and withholds any copy. The recording is kept as observed.

`mixed-doc-risky-block` exercises cutting a single fenced block. Its first attempt is kept
in `initial/mixed-doc-risky-block.json`: the block was cut correctly, and Guard, Protect
and the final Decide passed on the remainder (allow, 0.99), but the routing question read
the `[Script removed]` marker as possible code (no_code 0.65, confidence 0.29), so the copy
was withheld as residual risk. The copy recheck now states in the routing question that
the marker is not code, and only when the text contains it; every other recorded request
is unchanged. The top-level recording is the rerun with that request.

The private ticket has no remaining personal-data entities after masking. The final
Decide still recommends review, so its copy requires human acknowledgement. This is
kept as an observed deviation from the original expectation of an immediately ready
copy. Tests assert the recorded behavior, not an invented successful outcome.

The credential script's original five request/response bodies are unchanged. Its handoff
now replaces the entire input with the fixed `[Script removed]` marker and requires
confirmation, without another model call. The previous withheld outcome is preserved in
`initial/credential-script.json`; the top-level report and expected handoff reflect the
current deterministic replacement behavior.

## A real failure that changed the implementation

`initial/private-ticket.json` preserves the first attempt. Protect classified literal
`[REDACTED]` editing markers as address entities at 0.5 confidence during the recheck.
Preflight correctly withheld the candidate. The copy recheck now explicitly explains
that those markers are not personal data while still asking Protect to detect any real
data around them. The top-level private-ticket recording shows the later result.

The other two `initial/` files preserve the earlier instruction-removal runs before this
request clarification. They are historical evidence, not current-contract replay tests.
Nothing in these recorded scripts or attack examples is executed by Preflight.

## Reproduce offline

```sh
uv run python -m scripts.record_cases
uv run pytest tests/test_recordings.py -q
```

Replay checks every request body, endpoint and call order, and fails on any extra,
missing or changed request. It has no live fallback. Runtime timings are not asserted.

## Make a new recording

```sh
# Uses the configured CLOCKED_API_KEY and spends credits; synthetic corpus only.
uv run python -m scripts.record_cases --record --output recordings/2026-10-27
# Select a subset with repeatable --case flags.
uv run python -m scripts.record_cases --record --case private-ticket --output recordings/new-run
```

The recorder refuses to overwrite files. It stops sending further requests after its
64-call limit or observed 1,500-credit budget is reached; a single in-flight request
can cross the observed-credit boundary. Only selected response metadata is saved,
never request headers. Re-record after intentional request-contract changes and
review the changed behavior before replacing current regression fixtures.

These twelve authored cases are not a held-out accuracy benchmark. They do not establish
false-positive rates, adversarial robustness, or performance across real documents.
