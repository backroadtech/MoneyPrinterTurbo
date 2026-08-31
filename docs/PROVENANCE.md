# Provenance Manifest — Phase 1B.3A / 1B.3C.2A

Offline provenance and human-review manifest foundation for BrainTrustCrypto
pilot tasks.

**Status:** foundation plus offline review-integrity primitives (schema
1.1.0). This module is **not** integrated with rendering, providers,
publishing, or review CLI commands. CLI integration is deferred to a later
phase.

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
| `schema_version` | `"1.1.0"` for new manifests; `"1.0.0"` manifests remain valid for read/validate and explicit migration only |
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

Accountability (schema 1.0.0 legacy path): a `VERIFIED` or `RETRACTED` claim
must name a `reviewer` and a `review_date`.

Schema 1.1.0 adds optional fields: `supporting_sources` (list of URLs),
`reviewer_id`, `reviewer_display_name`, `review_timestamp_utc`, and `notes`.

Reviewer identity rules (1.1.0):
- `reviewer_id` — lowercase only, 1–64 characters,
  `[a-z0-9][a-z0-9._-]{0,63}`.
- `reviewer_display_name` — 1–128 characters, control characters rejected.
  Manually supplied during the pilot; no authentication or credentials yet.

Supporting-source rules (1.1.0):
- A `VERIFIED` claim requires **at least one valid supporting HTTPS URL**.
  The existing `source_url` may satisfy this; `supporting_sources` entries
  are optional extras.
- A `RETRACTED` claim using the 1.1.0 identity fields requires
  `reviewer_id`, `reviewer_display_name`, `review_timestamp_utc`, and
  explanatory `notes`.
- Active `UNVERIFIED` and `RETRACTED` claims **block task approval**
  (`assert_no_blocking_claims()`).

### 5. AI generations
`provider`, `model`, `generation_timestamp` (UTC), `output_type`
(`text`/`image`/`audio`/`video`/`script`/`other`), `prompt_hash`, and
`parameters` — non-secret parameters only. Keys or values that look like
credentials (API keys, tokens, authorization headers, cookies, passwords,
private keys) or full prompts are rejected.

### 6. Output
`local_path`, `sha256` (when the file exists), `review_status`,
`filename_marker`, and `visible_watermark_required` (always `false`).

Schema 1.1.0 output `review_status` values: `NEEDS_HUMAN_REVIEW`,
`APPROVED`, `REJECTED`, `SUPERSEDED`. **`REVOKED` is intentionally not a
value** — revocation is recorded via an immutable receipt, never by
mutating `output.review_status`.

While unreviewed, the output filename carries the marker
`__NEEDS_HUMAN_REVIEW` before its extension
(`final__NEEDS_HUMAN_REVIEW.mp4`). The marker is removed on a terminal
human decision. **No visible watermark is required** — the marker lives in
the filename only.

## Schema 1.1.0 and migration

- New manifests are built with `schema_version = "1.1.0"`.
- Existing `1.0.0` manifests remain valid: `validate_manifest()` accepts
  both versions and applies the legacy rules to 1.0.0 documents.
- `migrate_manifest_1_0_0_to_1_1_0()` performs an **explicit, additive-only**
  migration: it validates the 1.0.0 manifest, deep-copies it, sets
  `schema_version` to `1.1.0`, initializes the new claim fields to `null`,
  and re-validates. A 1.0.0 manifest is **never silently reinterpreted or
  overwritten in place** — the input dict is not mutated.

## Canonical JSON for hashes

Audit events, receipts, and manifest snapshots are hashed over canonical
UTF-8 JSON bytes with these exact rules:

- `sort_keys=True`
- `separators=(",", ":")` (compact)
- `ensure_ascii=False`
- `allow_nan=False`
- no trailing whitespace; the hashed bytes have **no trailing newline**
- **floating-point values are rejected** in any structure that is hashed
  (cross-platform float serialization would break hash stability)

`provenance.canonical_json_bytes()` and `provenance.canonical_sha256()`
implement these rules; serialization is deterministic across repeated calls.

## Review-integrity primitives (Phase 1B.3C.2A)

`app/services/review_integrity.py` — standard library only, fully offline.
Standalone primitives confined to the task directory:

- `manifest-history/000001_<manifest-sha256>.json` — immutable manifest
  snapshots; never overwritten; verified against the hash in the filename.
- `review-events/000001_<event-id>.json` — sequential, hash-chained audit
  events. Each event carries `schema_version`, `sequence`, `event_id`,
  `event_type`, `timestamp_utc`, `reviewer_id`, `reviewer_display_name`,
  `reason` (when required), `previous_event_hash`, `manifest_hash_before`,
  `manifest_hash_after`, `details`, and `event_hash`. The chain fails closed
  on missing, reordered, duplicated, malformed, or modified events.
- `approvals/000001_<receipt-id>.json` — sequential, hash-chained
  APPROVAL/REVOCATION receipts. A REVOCATION must reference the
  `receipt_id` and `receipt_hash` of the APPROVAL it revokes; double
  revocation is rejected. Receipts are canonical, immutable, atomically
  created, and never overwritten.
- `review.lock` — task-local exclusive lock (`lock_token`, `process_id`,
  `hostname`, `created_at_utc`, reviewer identity). Acquisition fails closed
  when a lock exists or is malformed; release requires the matching token;
  **age alone is never treated as abandonment**. Explicit recovery
  (`recover_review_lock()`) requires reviewer identity and a reason, removes
  the lock, and records a `LOCK_RECOVERED` audit event — including whether
  the original lock was malformed (captured **before** removal).

All creation is atomic: same-directory temporary file, flush + fsync, then
exclusive finalization; temporary files are cleaned up after failure, and
the last valid state is preserved. All paths are confined to the task
directory (traversal, unsafe absolute paths, symlink escapes, and junction
escapes are rejected where testable).

No operator CLI commands (approve/revoke/audit/recover-lock) are exposed
yet.

## Review states and transitions

```
NEEDS_HUMAN_REVIEW ──► APPROVED   (terminal)
                  ──► REJECTED   (terminal)
```

- Every new manifest defaults to `NEEDS_HUMAN_REVIEW`.
- `APPROVED` and `REJECTED` are terminal; no further transitions.
- Approving is rejected while any factual claim remains `UNVERIFIED`
  (schema 1.1.0: `UNVERIFIED` or `RETRACTED`).
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
