# Provenance Manifest — Phase 1B.3A

Offline provenance and human-review manifest foundation for BrainTrustCrypto
pilot tasks.

**Status:** foundation only. This module is **not** integrated with rendering,
providers, CLI, TTS, LLM, or publishing. Integration is deferred to Phase
1B.3B.

## Purpose

Every pilot task produces a `provenance_manifest.json` inside its task
directory. The manifest records where the script, assets, factual claims, AI
generations, and final output came from, and forces every task through a
human-review gate before anything may be rendered or published.

## Module

`app/services/provenance.py` — standard library only. No network calls.

Machine-readable schema: `docs/provenance-manifest-schema.json`
(JSON Schema draft 2020-12).

## Manifest sections

### 1. Task
| Field | Notes |
|---|---|
| `schema_version` | Currently `"1.0.0"` |
| `task_id` | Non-empty string |
| `created_at` | UTC ISO-8601 timestamp (offset required) |
| `topic` | Non-empty string |
| `pilot_profile` | e.g. `braintrustcrypto` |
| `review_status` | `NEEDS_HUMAN_REVIEW` (default), `APPROVED`, or `REJECTED` |

### 2. Script
`local_path` (relative to task dir), `sha256` (streamed), `generation_source`,
optional `ai_provider` / `ai_model`, and `prompt_hash` — **only the SHA-256 of
the prompt; the full sensitive prompt is never stored.**

### 3. Assets
Each asset records: `asset_type` (`video`/`audio`/`image`/`text`/`subtitle`/
`other`), `source_type` (`local`/`provider`/`ai_generated`), `source_url`,
`provider`, `provider_asset_id`, `retrieval_date`, `local_path`, `sha256`,
`license_name`, `license_evidence`, `notes`.

Rules enforced by `build_asset()`:
- **local** — `source_url` may be omitted; **license evidence is always
  required** (for every asset).
- **provider** — `source_url`, `retrieval_date`, `provider`,
  `provider_asset_id`, and license information are all required.
- **ai_generated** — `provider` (the AI provider) is required; `source_url`
  may be omitted.

### 4. Factual claims
`claim_text`, `source_url`, optional `source_publication_date` and
`retrieval_date`, and `status`: `UNVERIFIED` (default), `VERIFIED`, or
`RETRACTED`.

A `VERIFIED` or `RETRACTED` claim **must** name a `reviewer` and a
`review_date` — a human decision without accountability is rejected.

### 5. AI generations
`provider`, `model`, `generation_timestamp` (UTC), `output_type`
(`text`/`image`/`audio`/`video`/`script`/`other`), `prompt_hash`, and
`parameters` — non-secret parameters only. Keys or values that look like
credentials (API keys, tokens, authorization headers, cookies, passwords,
private keys) or full prompts are rejected.

### 6. Output
`local_path`, `sha256` (when the file exists), `review_status`,
`filename_marker`, and `visible_watermark_required` (always `false`).

While unreviewed, the output filename carries the marker
`__NEEDS_HUMAN_REVIEW` before its extension
(`final__NEEDS_HUMAN_REVIEW.mp4`). The marker is removed on a terminal
human decision. **No visible watermark is required** — the marker lives in
the filename only.

## Review states and transitions

```
NEEDS_HUMAN_REVIEW ──► APPROVED   (terminal)
                  ──► REJECTED   (terminal)
```

- Every new manifest defaults to `NEEDS_HUMAN_REVIEW`.
- `APPROVED` and `REJECTED` are terminal; no further transitions.
- Approving is rejected while any factual claim remains `UNVERIFIED`.
- Any transition not listed above is rejected
  (`transition_review_status()`).

## Security and integrity guarantees

- **Fail closed:** every manifest starts at `NEEDS_HUMAN_REVIEW`.
- **Standard library only.**
- **Streaming SHA-256:** files are hashed in 1 MiB chunks; large media is
  never fully loaded into memory.
- **Path confinement:** all local paths must resolve inside the designated
  task directory. Traversal (`../`), symlink escapes, and unsafe absolute
  paths (including other Windows drives) are rejected.
- **Atomic writes:** manifests are written to a same-directory temporary
  file, fsynced, then atomically renamed (`os.replace`). The temporary file
  is removed on any failure.
- **Deterministic JSON:** stable top-level field ordering, sorted keys,
  fixed separators, UTF-8, trailing newline — identical manifests produce
  byte-identical files.
- **Secret hygiene:** API keys, authorization headers, cookies, tokens,
  passwords, private keys, and full sensitive prompts are never recorded.
  Only prompt hashes are stored. Suspicious keys/values raise
  `ProvenanceError`.
- **Validation:** required fields and closed enum values are validated at
  build time and again before every write.

## Tests

`test/services/test_phase1b3a_provenance.py` — fully offline (no network).
Covers deterministic output, large-file streaming hashes, path traversal and
unsafe absolute paths, atomic writes and temp-file cleanup, missing fields
and invalid enums, local/provider/AI-generated asset rules, claim-review
requirements, secret redaction/rejection, and `NEEDS_HUMAN_REVIEW` defaults
plus the filename marker.
