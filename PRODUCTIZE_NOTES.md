
## 2026-08-28 — fleet-green pass

Two open PRs both rewrote `analyze.yml` and would have conflicted. This change
lands the union of their intent on `main` so every product caller sees one
contract:

- **Secrets are all `required: false`** (from PR #1). `required: true` was the
  fleet-wide blocker: any product repo missing a key failed at the secrets gate
  before a single step ran, which is what killed the shadowscan / surge /
  dynamic-experience-analyzer scans. A missing key now degrades enrichment (that
  provider reports an errored model) instead of failing the caller's scan.
- **`consensus_b64` output + `post_to_api` input** (from PR #2). Callers that
  must keep findings on the Firestore path take the output and store it
  themselves; the legacy ingest-API POST is preserved as the default so no
  existing caller changes behaviour.
- **Shell hardening** (from PR #1): caller values reach the engine through env,
  never interpolated into a script body; base64 and JSON are validated before
  the engine sees them; the ingest POST checks its HTTP code.
- **`workflow_dispatch` self-test.** `analyze.yml` was `workflow_call`-only, so
  it could never produce a green run of its own — its newest run on `main` was a
  7-month-old startup failure from a push. It now runs standalone against
  `tests/sample_findings.json`, which both fixes the red default branch and
  gives the engine a real smoke test.

### Model ID refresh (`src/consensus_engine.py`)

7 of 15 models were dead against the live APIs — the providers retired the IDs.
Every replacement below was probed against the real endpoint before being
swapped in. Result: 14/15 models now respond (was 7/15).

| was | now | why |
|---|---|---|
| `llama-3.3-70b-versatile` (Groq) | `openai/gpt-oss-120b` | Groq retired all Llama 3.x; 404 |
| `llama-3.1-8b-instant` (Groq) | `openai/gpt-oss-20b` | same |
| `google/gemini-2.0-flash-exp:free` | `google/gemini-2.5-flash` | 404 |
| `x-ai/grok-2-1212` | `x-ai/grok-4.5` | 404 |
| `microsoft/phi-3-medium-128k-instruct` | `microsoft/phi-4` | 404 |
| `cohere/command-r` | `cohere/command-r-08-2024` | 404 |

`MODEL_WEIGHTS` keys follow the two renamed Groq labels; every other weight is
unchanged, so consensus scoring is not re-tuned by this change.

### Known-bad credential (needs Bill)

`GEMINI_API_KEY` is **suspended by Google** — the direct Gemini call returns
`403 CONSUMER_SUSPENDED` on every request, including `GET /v1beta/models`. This
is not a code fault and cannot be fixed from here; it needs a new key minted in
the Google Cloud console. Gemini coverage is not lost in the meantime, because
`google/gemini-2.5-flash` reaches the same family through OpenRouter. That one
model is the 15th, and the only one still failing.

### Credential leak in the result JSON (found by the first green self-test)

The self-test run went green but GitHub annotated it:

> Skip output 'consensus_b64' since it may contain secret.

That was not a false positive. Gemini authenticates by **query parameter**, so a
failed request raises with the API key sitting in the URL, and `requests` puts
that whole URL in the exception string. The string went straight into
`ModelResponse.error`, which is serialised into the consensus result — so
`GEMINI_API_KEY` appeared verbatim 4 times in the output that gets uploaded as a
30-day artifact, POSTed to the ingest API, and rendered on the client-facing
dashboard.

It also broke the delivery path this same PR had just added: GitHub refuses to
emit a job output containing a masked secret, so `consensus_b64` was being
dropped and every caller would have received an empty string.

Fixed with a `_redact()` helper applied inside `_error_response()` — the single
point every provider error passes through. It replaces the three held keys by
value and additionally regex-strips any `?key=`/`&key=` parameter, so a provider
echoing back a credential we do not hold is caught too. Verified: 0 occurrences
of key material in the result, 14/15 models, `consensus_b64` populated.
