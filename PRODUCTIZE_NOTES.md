# Consensus Engine — Actions Audit Notes

# GitHub Actions Audit + Enhancement (2026-08-24)

Branch: `enhance/actions-ui-20260824`. **Tier: REVIEW ONLY**, and additionally this is
the **SHARED CORE** — every ICIT product calls `analyze.yml@main` via `workflow_call`.
Per the guardrails, any change here is fleet-wide: extra validation, **no `--auto`
merge**, and a dependent product's `workflow_call` must be dry-run against this branch
before it merges. **This branch is at PR and STOPPED for exactly that reason.**

The interface (`workflow_call` inputs) is preserved byte-for-byte. Only the job body and
the `required:` flags on secrets changed — both backward compatible.

---

## 1. THE fleet-wide blocker — and the fix

Every product's dry-run has been failing at the same point (observed on Threat Inspector):

```
Error when evaluating 'secrets'.
  Secret GROQ_API_KEY is required, but not provided while calling.
  Secret OPENROUTER_API_KEY is required, but not provided while calling.
  Secret GEMINI_API_KEY is required, but not provided while calling.
  Secret IRONCITY_API_KEY is required, but not provided while calling.
```

Root cause: `analyze.yml` declared all four secrets `required: true`. GitHub refuses to
**start** a reusable workflow when a caller's `secrets: inherit` does not carry every
required secret — the job dies before its first step. So a missing key doesn't degrade AI
enrichment, it **fails the entire calling product's scan**, fleet-wide.

But the engine already handles missing keys gracefully. Verified locally:

```
$ python3 src/consensus_engine.py finding.json -p threat-inspector -c ironcity -o r.json
  Models: 0/15 responded
$ echo $?    → 0        # valid JSON, consensus_severity: UNKNOWN
```

Each provider returns an `_error_response` when its key is absent; the run completes.
The `required: true` flags were throwing that graceful path away.

**Fix (this PR): the four secrets are now `required: false`.** A missing key means "AI
enrichment unavailable" (0/N models, `UNKNOWN` severity) instead of "scan failed". The
`Update scan in QNAP` step is guarded to skip when `IRONCITY_API_KEY` is empty rather than
POST with no key and trip the new HTTP-code check.

**This is backward compatible.** Callers that *do* provide the secrets are unaffected —
making a secret optional never breaks a caller that supplies it. It strictly adds
resilience: an AI-provider outage, or keys not yet provisioned, no longer takes down every
product's scan pipeline.

> **This does not remove the need to provision the keys.** With keys, you get real
> 15-model consensus. Without them, scans still complete and store findings, labelled
> "AI: 0/N models". Both are better than today's hard fleet-wide failure. Provisioning the
> keys (`GROQ_API_KEY`, `OPENROUTER_API_KEY`, `GEMINI_API_KEY`, `IRONCITY_API_KEY` as
> org-level secrets) remains recommended — all four are on the approved list.

---

## 2. Security / robustness fixes (no interface change)

| # | Defect | Fix |
|---|---|---|
| 1 | `echo "${{ inputs.findings_json }}" \| base64 -d` — caller input interpolated into the shell | Passed via `env:`; decoded from `$FINDINGS_JSON`; base64 failure is a clear error, not a crash |
| 2 | `-p "${{ inputs.product }}" -c "${{ inputs.client_id }}"` interpolated onto the python command line | Passed via `env:`, given as argv — a value with shell metacharacters cannot execute |
| 3 | `jq --arg sid "${{ inputs.scan_id }}"` interpolated into the jq invocation | `scan_id` via `env:` |
| 4 | `curl -s` to the QNAP API swallowed transport/HTTP errors | `curl -sS` with explicit `%{http_code}` check; non-2xx fails the step |
| 5 | No JSON validation of decoded findings or of engine output | Both validated with `python3 -m json.tool` before use |
| 6 | No `permissions:` block | `permissions: contents: read` (the engine checks out its own repo and posts onward; needs no caller write) |
| 7 | Consensus result was not retrievable by callers/operators | Added an `upload-artifact` of the result JSON — additive, breaks nothing |

---

## 3. FLAGGED — architecture, NOT changed (fleet-wide decision)

**The engine posts consensus results to the QNAP Flask API** (`api.ironcityit.com/ingest`,
the `api_url` input) via `IRONCITY_API_KEY`. This conflicts with the standing rule that
product scan data goes to Firestore via `storeScanResults` only. It is the existing
shared-core contract that every product relies on, so I did **not** rewrite it — changing
where the engine sends results is a fleet-topology decision for Bill. Options:
- keep the QNAP post (status quo), or
- have the engine write to `storeScanResults` instead of / in addition to QNAP, and retire
  the direct QNAP path across the fleet.

This is the same item flagged from the Threat Inspector and DNS Guard reviews; it belongs
here because the code lives here.

---

## 4. Validation

- `actionlint 1.7.7` + `shellcheck 0.10.0` on `analyze.yml` — **exit 0, clean**.
- PyYAML `safe_load` — clean.
- **Interface diff: none.** `workflow_call` inputs unchanged
  (`findings_json`, `product`, `client_id`, `scan_id`, `api_url`); secret *names* unchanged
  (only `required: true → false`); job name unchanged (`analyze`).
- Engine parse path exercised locally with no keys — RC=0, valid result JSON, graceful
  0/15 degradation (this is the behaviour that makes §1's fix safe).

## 5. Required before merge — cannot complete here

The hard rule: **dry-run a dependent product's `workflow_call` against this branch, confirm
green, then merge (no `--auto`).** I could not run that here:
- cross-repo, a dependent product would need to pin `analyze.yml@enhance/actions-ui-20260824`
  and be dispatched — a change to the dependent repo;
- with keys present it would hit the real AI provider APIs.

With this branch's change, that dry-run should now go **green even with no keys** (engine
degrades, QNAP step skips), which is precisely the fleet-wide unblock. **Bill to run the
dependent dry-run and merge manually.** Do not `--auto` merge the shared core.
