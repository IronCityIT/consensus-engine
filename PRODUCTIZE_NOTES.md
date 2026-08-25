
---

# `post_to_api` opt-out + `consensus_b64` output

**Date:** 2026-08-25 · Branch `productize/consensus-engine` · **REVIEW ONLY — not merged, not deployed.**

## Why
`analyze.yml` unconditionally POSTed the consensus result to the ingest API
(`api.ironcityit.com/ingest`) whenever `scan_id` was non-empty. Every product that passes a
`scan_id` therefore sent analysis output off the Firestore path — including Threat Inspector,
which passes one on every run. For regulated scan data the standing rule is
`storeScanResults -> Firestore ONLY`, so this default made that rule unsatisfiable for any
caller of the shared engine.

There was no way to opt out: `api_url` is a plain string with no disable semantics, and the
workflow declared **no outputs at all**, so a caller who suppressed the POST would simply lose
the analysis. Both halves had to change together.

## What changed (`.github/workflows/analyze.yml` only — no engine logic touched)
- **`post_to_api` input** (boolean, `default: true`). Gates the POST step. Default preserves
  existing behaviour for every current caller; no caller is forced to change.
- **`consensus_b64` workflow output.** Job output carrying the base64 result JSON, so a caller
  that sets `post_to_api: false` can store the analysis itself. This is what makes the opt-out
  real rather than a way to silently discard the result.
- **`IRONCITY_API_KEY` is now `required: false`.** Callers that store results themselves no
  longer need to hold the key. The POST step fails loudly if the key is missing while
  `post_to_api` is true, rather than curl-ing with an empty header.
- **Hardening, incidental:** caller-controlled `findings_json` / `product` / `client_id` moved
  out of inline `${{ }}` interpolation into `env:` (script-injection surface), and the POST now
  uses `--fail-with-body` so an ingest error surfaces instead of passing silently.

## Verification
- YAML parses clean.
- `ruff check src` — all checks passed. `compileall` OK.
- Engine CLI contract re-verified against the workflow's invocation: `-p` / `-c` short forms
  resolve (argparse prefix match) and exit 0 on an empty findings set.
- No unit tests exist in this repo (`tests/` holds only `sample_findings.json`) — nothing to run.

## Not done
- **Not merged, not deployed.** `consensus-engine` is REVIEW ONLY. Left for Bill.
- Threat Inspector's `_consensus-store.yml` is written to consume `post_to_api: false` +
  `consensus_b64`, but that wiring cannot go live until this PR merges to `main`, because
  products pin `@main`.
