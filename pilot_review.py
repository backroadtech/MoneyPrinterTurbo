"""
Phase 1B.3C.2B.2C — BrainTrustCrypto pilot review CLI.

Standalone, offline review entry point for BrainTrustCrypto pilot tasks.
Exposes exactly five commands:

    status        — concise, sanitized snapshot of a task's review state
    audit         — read-only integrity validation (PASS/FAIL + reason codes)
    verify-claim  — verify one factual claim through the approved crash-safe
                    claim-mutation transaction
    retract-claim — retract one factual claim (with an explicit reason)
                    through the same crash-safe claim-mutation transaction
    resume-transaction — resume an interrupted claim-mutation transaction
                    forward-only to COMMITTED finalization through the
                    approved journaled resume cascade

status and audit NEVER mutate the task directory. They do not create,
modify, move, delete, recover, or rewrite any file, and they leave the
task directory byte-for-byte unchanged.

verify-claim, retract-claim, and resume-transaction are the only
mutating commands. verify-claim and retract-claim mutate only through
the approved 17-step journaled transaction:
claim_id-only preconditions, exclusive lock, in-memory proposed manifest,
frozen event planning, durable journal, immutable snapshot,
byte-identical proposed manifest, planned event, checkpoint advance,
atomic install, COMMITTED verification, matching-token lock release, and
journal removal last. resume-transaction resumes an interrupted
transaction through the approved forward-only resume cascade: stage-exact
adapters revalidate the journaled evidence, re-execute the remaining
steps, finalize the immutable recovery receipt, reconcile the
matching-token lock under the COMMITTED two-state rule, and remove the
journal last. All three are non-interactive (no confirmation prompts),
forward-only, and fail-closed: an interruption leaves explicit journaled
state for resume-transaction, never unjournaled committed state.

Other mutating review operations (approve, reject, revoke, supersede,
recover-lock, tail-recovery) are NOT exposed here yet and arrive with
their own approved checkpoints.

NOTE on recovery primitives: discard_uncommitted_tail() and
recover_review_lock() are intentionally NOT wired to this CLI. Those
primitives mutate state and require a separate audit before any future CLI
exposure. Do not surface them here.

Usage:
    python pilot_review.py status --task-dir <task-directory>
    python pilot_review.py audit  --task-dir <task-directory>
    python pilot_review.py verify-claim --task-dir <task-directory>
        --claim-id claim-<32-hex> --reviewer-id <reviewer_id>
        --reviewer-display-name "<display_name>" [--notes "<notes>"]
    python pilot_review.py retract-claim --task-dir <task-directory>
        --claim-id claim-<32-hex> --reviewer-id <reviewer_id>
        --reviewer-display-name "<display_name>" --reason "<reason>"
    python pilot_review.py resume-transaction --task-dir <task-directory>
        --transaction-id <32-hex> --reviewer-id <reviewer_id>
        --reviewer-display-name "<display_name>" --reason "<reason>"

Exit codes:
    0 - command completed successfully
    1 - policy, validation, integrity, hash, lock, transaction, or
        approval-state failure
    2 - command-line usage error

For `status`, a valid NEEDS_HUMAN_REVIEW task may exit 0 while reporting
approval readiness BLOCKED, provided no integrity failure exists.

Guarantees:
- Requires MPT_PILOT_PROFILE=braintrustcrypto and a valid, safe pilot
  policy; fails closed when the profile is inactive or the policy is
  missing, malformed, or unsafe.
- status and audit are read-only: no file in the task directory is
  created or changed. verify-claim, retract-claim, and resume-transaction
  mutate only through the approved journaled transaction and resume
  cascade above.
- Sanitized output: never prints complete claim text, prompts, secrets,
  credentials, authorization data, query strings, or environment values.
- Transaction status is always reported (`transaction status: none` or
  `INCOMPLETE_TRANSACTION` with only a sanitized transaction id and a
  validated known stage) without exposing journal contents.
- Makes no network request and invokes no provider, renderer, or publisher.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import sys
import uuid
from urllib.parse import urlsplit

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

MANIFEST_FILENAME = "provenance_manifest.json"


class ReviewError(Exception):
    """Raised for any policy, validation, or integrity failure."""


# ---------------------------------------------------------------------------
# Pilot-policy gate (same fail-closed pattern as pilot_prepare)
# ---------------------------------------------------------------------------


def _require_pilot_policy():
    """Load the pilot policy, failing closed on any problem."""
    from app.services.pilot_policy import PilotPolicyError, load_pilot_policy

    try:
        policy = load_pilot_policy()
    except PilotPolicyError as exc:
        raise ReviewError(f"pilot policy failure: {exc}") from exc
    if policy is None:
        raise ReviewError(
            "pilot policy failure: MPT_PILOT_PROFILE is not 'braintrustcrypto'"
        )
    return policy


# ---------------------------------------------------------------------------
# Sanitization helpers — never leak secrets, query strings, or full text
# ---------------------------------------------------------------------------


def _strip_query(url: str) -> str:
    """Return scheme://host/path with any query string or fragment removed."""
    if not isinstance(url, str):
        return "<invalid>"
    for sep in ("?", "#"):
        idx = url.find(sep)
        if idx != -1:
            url = url[:idx]
    return url


def _truncate(text: str, limit: int = 48) -> str:
    """Truncate long free-text for safe one-line display."""
    if not isinstance(text, str):
        return "<invalid>"
    text = text.replace("\n", " ").replace("\r", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# Read-only manifest loading and confinement
# ---------------------------------------------------------------------------


def _resolve_task_dir(task_dir: str) -> str:
    from app.services import provenance as prov

    if not isinstance(task_dir, str) or not task_dir.strip():
        raise ReviewError("task directory must be a non-empty path")
    candidate = os.path.expanduser(task_dir.strip())
    lexical = os.path.normcase(os.path.abspath(candidate))
    base = os.path.realpath(candidate)
    if lexical != os.path.normcase(base):
        raise ReviewError("task directory path traverses a link or junction")
    if not os.path.isdir(base):
        raise ReviewError(f"task directory does not exist: {task_dir!r}")
    return base


def _load_manifest(task_dir: str) -> tuple[dict, str, str]:
    """Load and validate the manifest. Returns (manifest, path, sha256)."""
    from app.services import provenance as prov

    base = _resolve_task_dir(task_dir)
    manifest_path = os.path.join(base, MANIFEST_FILENAME)
    if not os.path.isfile(manifest_path):
        raise ReviewError(f"manifest not found: {MANIFEST_FILENAME}")
    try:
        with open(manifest_path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise ReviewError(f"cannot read manifest: {exc}") from exc
    manifest_sha = hashlib.sha256(raw).hexdigest()
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewError(f"manifest is malformed JSON: {exc}") from exc
    if not isinstance(manifest, dict):
        raise ReviewError("manifest is not a JSON object")
    try:
        prov.validate_manifest(manifest)
    except prov.ProvenanceError as exc:
        raise ReviewError(f"manifest validation: {exc}") from exc
    return manifest, manifest_path, manifest_sha


def _hash_current(task_dir: str, rel_path: str) -> str | None:
    """Return the current streamed SHA-256 of a confined file, or None."""
    from app.services import provenance as prov

    try:
        resolved = prov.resolve_task_path(task_dir, rel_path, must_exist=True)
    except prov.ProvenanceError:
        return None
    if not os.path.isfile(resolved):
        return None
    try:
        return prov.sha256_file_streamed(resolved)
    except prov.ProvenanceError:
        return None


# ---------------------------------------------------------------------------
# Claim-mutation transaction engine (Phase 1B.3C.2B.2C — approved Steps 1-7)
# ---------------------------------------------------------------------------
# Internal orchestration for verify-claim and retract-claim: preconditions,
# claim_id-only lookup, the exact five-field mutation builder, in-memory
# proposed-manifest construction and hashing, frozen timestamp_utc/event_id,
# deterministic event planning, and journal creation. The complete approved
# 17-step transaction is implemented in this file (Steps 8-17 below) and is
# reachable from the CLI through the verify-claim and retract-claim commands.

_CLAIM_ID_ARG_PATTERN = re.compile(r"claim-[0-9a-f]{32}")

_CLAIM_OPERATIONS = frozenset({"verify-claim", "retract-claim"})

_CLAIM_EVENT_TYPES = {
    "verify-claim": "CLAIM_VERIFIED",
    "retract-claim": "CLAIM_RETRACTED",
}

# Secret-like shapes rejected in reviewer free text (--notes / --reason).
# Mirrors provenance's secret-value patterns: credentials never enter
# manifests, events, journals, or receipts.
_SECRET_TEXT_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        r"(?i)bearer\s+[a-z0-9._\-]+",
        r"(?i)(api[_-]?key|token|secret|password|authorization|cookie)\s*[:=]\s*\S+",
        r"sk-[a-zA-Z0-9]{16,}",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    )
)


def _sanitize_free_text(value, field: str) -> str:
    """Reject secret-like content in reviewer free text. Returns the text."""
    if not isinstance(value, str):
        raise ReviewError(f"{field}: must be a string")
    for pattern in _SECRET_TEXT_PATTERNS:
        if pattern.search(value):
            raise ReviewError(
                f"{field}: value appears to contain a credential or secret; "
                "secrets are never recorded"
            )
    return value


def _validate_reviewer_args(reviewer_id, reviewer_display_name) -> None:
    """Validate reviewer identity arguments with approved reason codes."""
    from app.services import provenance as prov

    try:
        prov.validate_reviewer_id(reviewer_id)
    except prov.ProvenanceError as exc:
        raise ReviewError(f"REVIEWER_ID_INVALID: {exc}") from exc
    try:
        prov.validate_reviewer_display_name(reviewer_display_name)
    except prov.ProvenanceError as exc:
        raise ReviewError(f"REVIEWER_NAME_INVALID: {exc}") from exc


def _find_claim(manifest: dict, claim_id) -> dict:
    """Select exactly one claim by claim_id only (never index or text)."""
    if not isinstance(claim_id, str) or not _CLAIM_ID_ARG_PATTERN.fullmatch(claim_id):
        raise ReviewError(
            "CLAIM_NOT_FOUND: claim_id must match claim-[0-9a-f]{32}"
        )
    matches = [
        claim
        for claim in manifest.get("factual_claims", [])
        if claim.get("claim_id") == claim_id
    ]
    if len(matches) != 1:
        raise ReviewError(
            f"CLAIM_NOT_FOUND: claim_id {claim_id!r} matches "
            f"{len(matches)} claim(s)"
        )
    return matches[0]


def _has_https_support(claim: dict) -> bool:
    """True when the claim has at least one valid HTTPS supporting source."""
    candidates = []
    source_url = claim.get("source_url")
    if isinstance(source_url, str):
        candidates.append(source_url)
    for url in claim.get("supporting_sources") or []:
        if isinstance(url, str):
            candidates.append(url)
    for url in candidates:
        try:
            parts = urlsplit(url.strip())
        except ValueError:
            continue
        if parts.scheme == "https" and parts.netloc:
            return True
    return False


def _validate_claim_preconditions(
    manifest: dict,
    *,
    operation: str,
    claim_id,
    reviewer_id,
    reviewer_display_name,
    reason,
    notes,
) -> dict:
    """Evaluate every approved verify-claim/retract-claim pre-condition.

    Returns the matched claim. Any failure raises ReviewError with the
    approved sanitized reason code before any lock acquisition or mutation.
    """
    if operation not in _CLAIM_OPERATIONS:
        raise ReviewError(f"unknown claim operation: {operation!r}")
    task = manifest.get("task", {})
    if task.get("review_status") != "NEEDS_HUMAN_REVIEW":
        raise ReviewError(
            "TASK_NOT_IN_REVIEW: manifest review_status is "
            f"{task.get('review_status')!r}"
        )
    if task.get("schema_version") != "1.2.0":
        raise ReviewError(
            "SCHEMA_TOO_OLD: claim operations require schema 1.2.0; "
            "run explicit migration first"
        )
    claim = _find_claim(manifest, claim_id)
    status = claim.get("status")
    if operation == "verify-claim":
        if status != "UNVERIFIED":
            raise ReviewError(
                f"CLAIM_NOT_UNVERIFIED: claim status is {status!r}"
            )
        if not _has_https_support(claim):
            raise ReviewError(
                "NO_SUPPORTING_SOURCE: claim has no valid HTTPS "
                "supporting source"
            )
        if notes is not None:
            _sanitize_free_text(notes, "notes")
    else:
        if status not in ("UNVERIFIED", "VERIFIED"):
            raise ReviewError(
                f"CLAIM_ALREADY_RETRACTED: claim status is {status!r}"
            )
        if not isinstance(reason, str) or not reason.strip():
            raise ReviewError(
                "REASON_REQUIRED: retract-claim requires a non-empty reason"
            )
        _sanitize_free_text(reason, "reason")
    _validate_reviewer_args(reviewer_id, reviewer_display_name)
    return claim


def _assert_no_transaction_journal(task_dir: str, *, context: str) -> None:
    """Fail closed when any journal exists (Steps 1/4).

    A valid journal fails with INCOMPLETE_TRANSACTION; a malformed journal
    fails with TRANSACTION_JOURNAL_CORRUPT (Section 2.6).
    """
    from app.services import review_integrity as ri

    try:
        journal = ri.read_transaction_journal(task_dir)
    except ri.ReviewIntegrityError:
        journal = None
        malformed = True
    else:
        malformed = False
    if malformed:
        raise ReviewError(
            "TRANSACTION_JOURNAL_CORRUPT: a malformed transaction journal "
            f"exists ({context})"
        )
    if journal is not None:
        raise ReviewError(
            f"INCOMPLETE_TRANSACTION: a transaction journal exists ({context})"
        )


def _build_proposed_manifest(
    manifest: dict,
    *,
    operation: str,
    claim_id: str,
    reviewer_id: str,
    reviewer_display_name: str,
    review_timestamp_utc: str,
    notes,
) -> dict:
    """Construct the proposed manifest in memory (approved Step 5).

    Applies only the approved five-field claim mutation to a deep copy of
    the validated active manifest; every other field is preserved exactly.
    The result is validated in memory; nothing is written.
    """
    from app.services import provenance as prov

    proposed = copy.deepcopy(manifest)
    target = None
    for claim in proposed.get("factual_claims", []):
        if claim.get("claim_id") == claim_id:
            target = claim
            break
    if target is None:  # defensive; the claim was matched during preconditions
        raise ReviewError(f"CLAIM_NOT_FOUND: claim_id {claim_id!r}")
    target["status"] = "VERIFIED" if operation == "verify-claim" else "RETRACTED"
    target["reviewer_id"] = reviewer_id
    target["reviewer_display_name"] = reviewer_display_name
    target["review_timestamp_utc"] = review_timestamp_utc
    target["notes"] = notes
    try:
        prov.validate_manifest(proposed)
    except prov.ProvenanceError as exc:
        raise ReviewError(f"MANIFEST_INVALID: proposed manifest: {exc}") from exc
    return proposed


def _predict_snapshot_relative_path(
    task_dir: str, starting_manifest_hash: str
) -> str:
    """Predict the immutable snapshot path recorded in the journal (Step 7).

    The snapshot filename embeds the starting manifest's canonical hash;
    its sequence is one beyond the current manifest-history depth. Step 9
    verifies the created snapshot against this journal-recorded path.
    """
    from app.services import review_integrity as ri

    history = ri.list_manifest_history(task_dir)
    sequence = len(history) + 1
    return f"manifest-history/{sequence:06d}_{starting_manifest_hash}.json"


def _plan_claim_transaction(
    task_dir: str,
    *,
    operation: str,
    claim_id,
    reviewer_id,
    reviewer_display_name,
    reason=None,
    notes=None,
) -> dict:
    """Execute approved Steps 1-7 and return the frozen transaction plan.

    Step 1: refuse while any transaction journal exists (pre-lock).
    Step 2: validate the manifest, review-event chain, and checkpoints.
    Step 3: acquire the exclusive task lock and retain its matching token.
    Step 4: re-check for a journal post-acquisition; on hit, release only
            the newly acquired matching token and fail (no journal made).
    Step 5: construct the proposed manifest in memory with only the
            approved five-field mutation, canonically serialize it in
            memory, and calculate starting/proposed hashes (no writes).
    Step 6: freeze event_id, then plan the exact event with
            plan_review_event() using those exact manifest hashes.
    Step 7: atomically create the journal at INITIATED recording the lock
            token, the exact manifest hashes, the planned event
            identity/hash, and the proposed target claim's exact notes
            value (claim_notes, approved resume-payload correction).

    On any pre-journal failure after lock acquisition, the newly acquired
    matching-token lock is released when no journal exists (Section 2.4).
    Returns the plan dict consumed by the implemented Steps 8-17
    transaction pipeline below.
    """
    from app.services import provenance as prov
    from app.services import review_integrity as ri

    _require_pilot_policy()
    base = _resolve_task_dir(task_dir)
    try:
        manifest, _manifest_path, _manifest_sha = _load_manifest(base)
    except ReviewError as exc:
        raise ReviewError(f"MANIFEST_INVALID: {exc}") from exc

    # Step 1 — pre-lock journal check.
    _assert_no_transaction_journal(base, context="pre-lock check")

    # Step 2 — validate the manifest, review-event chain, and checkpoints.
    try:
        ri.validate_review_event_chain(base)
    except ri.ReviewIntegrityError as exc:
        raise ReviewError(f"EVENT_CHAIN: {exc}") from exc

    # Approved pre-conditions (Sections 3.1 / 4.1).
    _validate_claim_preconditions(
        manifest,
        operation=operation,
        claim_id=claim_id,
        reviewer_id=reviewer_id,
        reviewer_display_name=reviewer_display_name,
        reason=reason,
        notes=notes,
    )

    # Step 3 — acquire the exclusive task lock; retain the matching token.
    # One frozen timestamp serves the claim review field, the journal
    # created_at_utc, and the event timestamp (deterministic resume input).
    timestamp_utc = prov.utc_now_iso()
    try:
        lock = ri.acquire_review_lock(
            base,
            reviewer_id=reviewer_id,
            reviewer_display_name=reviewer_display_name,
            created_at_utc=timestamp_utc,
        )
    except ri.ReviewIntegrityError as exc:
        raise ReviewError(f"LOCK_HELD: {exc}") from exc
    lock_token = lock["lock_token"]

    try:
        # Step 4 — post-acquisition journal recheck; creates no journal.
        try:
            _assert_no_transaction_journal(
                base, context="post-acquisition recheck"
            )
        except ReviewError:
            try:
                ri.release_review_lock(base, lock_token=lock_token)
            except ri.ReviewIntegrityError:
                pass
            raise

        # Step 5 — in-memory proposed manifest, canonical bytes, hashes.
        starting_manifest_hash = prov.canonical_sha256(manifest)
        proposed = _build_proposed_manifest(
            manifest,
            operation=operation,
            claim_id=claim_id,
            reviewer_id=reviewer_id,
            reviewer_display_name=reviewer_display_name,
            review_timestamp_utc=timestamp_utc,
            notes=(notes if operation == "verify-claim" else reason),
        )
        proposed_manifest_bytes = prov.canonical_json_bytes(proposed)
        proposed_manifest_hash = prov.canonical_sha256(proposed)

        # Step 6 — freeze event_id, then plan the exact event (no writes).
        event_id = uuid.uuid4().hex
        planned_event = ri.plan_review_event(
            base,
            event_type=_CLAIM_EVENT_TYPES[operation],
            reviewer_id=reviewer_id,
            reviewer_display_name=reviewer_display_name,
            timestamp_utc=timestamp_utc,
            event_id=event_id,
            reason=(reason if operation == "retract-claim" else None),
            manifest_hash_before=starting_manifest_hash,
            manifest_hash_after=proposed_manifest_hash,
        )

        # Step 7 — create the journal at INITIATED with the exact manifest
        # hashes and the planned event identity/hash.
        proposed_manifest_relative_path = (
            f".proposed_manifest.json.{uuid.uuid4().hex}.tmp"
        )
        snapshot_relative_path = _predict_snapshot_relative_path(
            base, starting_manifest_hash
        )
        # Approved resume-payload correction (amendment Section 2.1/2.4):
        # the journal records the exact notes value carried by the Step-5
        # proposed target claim — sanitized --notes for verify-claim (null
        # when omitted), sanitized --reason for retract-claim — derived
        # from that claim, never re-read from the CLI argument. The value
        # is re-checked against the current secret patterns immediately
        # before journal creation; null carries no content and is skipped.
        claim_notes = _find_claim(proposed, claim_id).get("notes")
        if claim_notes is not None:
            _sanitize_free_text(
                claim_notes,
                field="notes" if operation == "verify-claim" else "reason",
            )
        try:
            journal = ri.create_transaction_journal(
                base,
                operation=operation,
                task_id=manifest.get("task", {}).get("task_id"),
                claim_id=claim_id,
                claim_notes=claim_notes,
                starting_manifest_hash=starting_manifest_hash,
                proposed_manifest_hash=proposed_manifest_hash,
                proposed_manifest_relative_path=proposed_manifest_relative_path,
                snapshot_relative_path=snapshot_relative_path,
                expected_event_id=planned_event["event_id"],
                expected_event_hash=planned_event["event_hash"],
                lock_token=lock_token,
                created_at_utc=timestamp_utc,
                original_reviewer_id=reviewer_id,
                original_reviewer_display_name=reviewer_display_name,
            )
        except ri.ReviewIntegrityError as exc:
            raise ReviewError(f"TRANSACTION_JOURNAL: {exc}") from exc
    except BaseException:
        # Section 2.4: before review-transaction.json exists, the owning
        # command may release only the matching token it acquired.
        try:
            if ri.read_transaction_journal(base) is None:
                try:
                    ri.release_review_lock(base, lock_token=lock_token)
                except ri.ReviewIntegrityError:
                    pass
        except ri.ReviewIntegrityError:
            pass
        raise

    return {
        "operation": operation,
        "task_id": manifest.get("task", {}).get("task_id"),
        "claim_id": claim_id,
        "reviewer_id": reviewer_id,
        "reviewer_display_name": reviewer_display_name,
        "timestamp_utc": timestamp_utc,
        "event_id": event_id,
        "lock": lock,
        "lock_token": lock_token,
        "starting_manifest": manifest,
        "starting_manifest_hash": starting_manifest_hash,
        "proposed_manifest": proposed,
        "proposed_manifest_bytes": proposed_manifest_bytes,
        "proposed_manifest_hash": proposed_manifest_hash,
        "proposed_manifest_relative_path": proposed_manifest_relative_path,
        "snapshot_relative_path": snapshot_relative_path,
        "planned_event": planned_event,
        "journal": journal,
    }


# ---------------------------------------------------------------------------
# Claim-mutation durable phase (Phase 1B.3C.2B.2C — approved Steps 8-11)
# ---------------------------------------------------------------------------
# Executes the durable transaction from the frozen Step 1-7 plan: journal and
# matching-lock validation, the immutable starting-manifest snapshot, the
# byte-identical durable proposed manifest, and the planned claim-review
# event, advancing the journal through LOCK_ACQUIRED, SNAPSHOT_CREATED,
# PROPOSED_MANIFEST_READY, and EVENT_CREATED. Once review-transaction.json
# exists, every failure retains both the journal and the lock for explicit
# forward resume (Section 2.4): nothing here rolls back, repairs, releases
# the lock, or deletes any artifact. Steps 12-17 are implemented below;
# the full transaction is reachable from the CLI through verify-claim and
# retract-claim.


def _assert_starting_manifest_unchanged(base: str, starting_manifest_hash: str) -> None:
    """Fail closed when the active manifest drifted from the Step 5 hash."""
    from app.services import provenance as prov

    try:
        manifest, _manifest_path, _manifest_sha = _load_manifest(base)
    except ReviewError as exc:
        raise ReviewError(f"MANIFEST_INVALID: {exc}") from exc
    if prov.canonical_sha256(manifest) != starting_manifest_hash:
        raise ReviewError(
            "STATE_DRIFT: active manifest no longer matches "
            "starting_manifest_hash"
        )


def _validate_journal_and_lock(base: str, plan: dict) -> dict:
    """Re-validate the journal and the matching lock (approved Step 8).

    The on-disk journal must equal the record created at Step 7, still sit
    at INITIATED, and record the exact lock token of the currently held
    lock. A missing, changed, or mismatched lock fails closed without
    recreating, replacing, or releasing it (Section 2.4).
    """
    from app.services import review_integrity as ri

    try:
        journal = ri.read_transaction_journal(base)
    except ri.ReviewIntegrityError as exc:
        raise ReviewError(
            "TRANSACTION_JOURNAL: transaction journal failed validation"
        ) from exc
    if journal is None:
        raise ReviewError("TRANSACTION_JOURNAL: no transaction journal exists")
    if journal != plan["journal"]:
        raise ReviewError(
            "STATE_DRIFT: transaction journal no longer matches the record "
            "created at Step 7"
        )
    if journal["transaction_stage"] != "INITIATED":
        raise ReviewError(
            "TRANSACTION_JOURNAL: expected stage INITIATED, found "
            f"{journal['transaction_stage']!r}"
        )
    try:
        held_lock = ri.read_review_lock(base)
    except ri.ReviewIntegrityError as exc:
        raise ReviewError(
            "LOCK_HELD: review lock failed validation"
        ) from exc
    if held_lock is None:
        raise ReviewError("LOCK_HELD: the journal-recorded lock is missing")
    if held_lock["lock_token"] != journal["lock_token"]:
        raise ReviewError(
            "LOCK_HELD: held lock token does not match the journal-recorded "
            "token"
        )
    return journal


def _create_and_verify_snapshot(base: str, plan: dict) -> str:
    """Create and verify the immutable starting-manifest snapshot (Step 9).

    The active manifest must still match starting_manifest_hash; the created
    snapshot must land at the journal-recorded snapshot_relative_path and
    hash exactly to starting_manifest_hash.
    """
    from app.services import provenance as prov
    from app.services import review_integrity as ri

    _assert_starting_manifest_unchanged(base, plan["starting_manifest_hash"])
    try:
        snapshot_path = ri.snapshot_manifest(base, plan["starting_manifest"])
    except (prov.ProvenanceError, ri.ReviewIntegrityError) as exc:
        raise ReviewError(f"SNAPSHOT: {exc}") from exc
    relative = os.path.relpath(snapshot_path, base).replace(os.sep, "/")
    if relative != plan["snapshot_relative_path"]:
        raise ReviewError(
            "STATE_DRIFT: created snapshot path does not match the "
            "journal-recorded snapshot_relative_path"
        )
    try:
        with open(snapshot_path, "rb") as handle:
            snapshot = json.loads(handle.read().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewError(
            f"SNAPSHOT: cannot re-read created snapshot: {exc}"
        ) from exc
    if prov.canonical_sha256(snapshot) != plan["starting_manifest_hash"]:
        raise ReviewError(
            "STATE_DRIFT: snapshot content does not hash to "
            "starting_manifest_hash"
        )
    return snapshot_path


def _write_durable_proposed_manifest(base: str, plan: dict) -> str:
    """Write the durable proposed manifest byte-identically (Step 10).

    Writes exactly the frozen Step 5 canonical bytes to the journal-recorded
    task-confined temporary path (exclusive create, flush + fsync), then
    verifies the written file hashes exactly to proposed_manifest_hash.
    """
    from app.services import provenance as prov

    _assert_starting_manifest_unchanged(base, plan["starting_manifest_hash"])
    try:
        temp_path = prov.resolve_task_path(
            base, plan["proposed_manifest_relative_path"], must_exist=False
        )
    except prov.ProvenanceError as exc:
        raise ReviewError(f"PROPOSED_MANIFEST: {exc}") from exc
    try:
        with open(temp_path, "xb") as handle:
            handle.write(plan["proposed_manifest_bytes"])
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise ReviewError(f"PROPOSED_MANIFEST: write failed: {exc}") from exc
    actual = _hash_current(base, plan["proposed_manifest_relative_path"])
    if actual != plan["proposed_manifest_hash"]:
        raise ReviewError(
            "STATE_DRIFT: durable proposed manifest does not hash to "
            "proposed_manifest_hash"
        )
    return temp_path


def _create_and_verify_planned_event(base: str, plan: dict) -> dict:
    """Create the planned claim-review event and verify equality (Step 11).

    Creates the immutable event file through the split event primitive with
    exactly the planned inputs and the frozen event_id, then requires the
    created record to equal the planned record exactly (identity and hash)
    and to match the journal-recorded expected event identity/hash; any
    state drift fails closed without mutation, rollback, or tail deletion.
    """
    from app.services import review_integrity as ri

    planned_event = plan["planned_event"]
    try:
        created_event = ri.create_review_event_file(
            base,
            event_type=planned_event["event_type"],
            reviewer_id=planned_event["reviewer_id"],
            reviewer_display_name=planned_event["reviewer_display_name"],
            timestamp_utc=planned_event["timestamp_utc"],
            reason=planned_event["reason"],
            manifest_hash_before=planned_event["manifest_hash_before"],
            manifest_hash_after=planned_event["manifest_hash_after"],
            details=planned_event["details"],
            event_id=planned_event["event_id"],
        )
    except ri.ReviewIntegrityError as exc:
        raise ReviewError(f"EVENT: {exc}") from exc
    if created_event != planned_event:
        raise ReviewError(
            "STATE_DRIFT: created event record differs from the planned "
            "record"
        )
    if (
        created_event["event_id"] != plan["journal"]["expected_event_id"]
        or created_event["event_hash"] != plan["journal"]["expected_event_hash"]
    ):
        raise ReviewError(
            "STATE_DRIFT: created event identity/hash does not match the "
            "journal-recorded expected event"
        )
    return created_event


def _execute_claim_transaction_durable(task_dir: str, plan: dict) -> dict:
    """Execute approved Steps 8-11 and return the durable-phase result.

    Step 8:  re-validate the journal and the matching lock; advance the
             journal to LOCK_ACQUIRED.
    Step 9:  create and verify the immutable starting-manifest snapshot;
             advance to SNAPSHOT_CREATED.
    Step 10: write the durable proposed manifest byte-identically to the
             frozen Step 5 plan; advance to PROPOSED_MANIFEST_READY.
    Step 11: create the planned claim-review event with the frozen
             event_id and verify exact equality with the planned record;
             advance to EVENT_CREATED.

    Every failure after journal creation retains both the journal and the
    matching lock for explicit forward resume (Section 2.4).
    """
    from app.services import review_integrity as ri

    base = _resolve_task_dir(task_dir)
    journal = _validate_journal_and_lock(base, plan)
    transaction_id = journal["transaction_id"]

    def _advance(new_stage: str) -> dict:
        try:
            return ri.update_transaction_stage(
                base, transaction_id=transaction_id, new_stage=new_stage
            )
        except ri.ReviewIntegrityError as exc:
            raise ReviewError(f"TRANSACTION_JOURNAL: {exc}") from exc

    journal = _advance("LOCK_ACQUIRED")
    snapshot_path = _create_and_verify_snapshot(base, plan)
    journal = _advance("SNAPSHOT_CREATED")
    proposed_temp_path = _write_durable_proposed_manifest(base, plan)
    journal = _advance("PROPOSED_MANIFEST_READY")
    created_event = _create_and_verify_planned_event(base, plan)
    journal = _advance("EVENT_CREATED")

    return {
        "journal": journal,
        "snapshot_path": snapshot_path,
        "proposed_manifest_temp_path": proposed_temp_path,
        "created_event": created_event,
    }


# ---------------------------------------------------------------------------
# Claim-mutation finalization (Phase 1B.3C.2B.2C — approved Steps 12-17)
# ---------------------------------------------------------------------------
# Completes the direct transaction: commits the planned event through the
# split checkpoint primitive, atomically installs the exact proposed
# manifest, verifies every committed artifact and chain, advances the
# journal to COMMITTED, reconciles the matching-token lock, and removes the
# journal last. A direct completion writes NO recovery receipt (Step 16 is
# resume-transaction only). Every failure before COMMITTED retains both the
# journal and the lock (Section 2.4); a failure at or after COMMITTED
# leaves the COMMITTED journal in place for explicit finalization. Together
# with Steps 1-11 above, this completes the approved 17-step transaction
# reachable from the CLI through verify-claim and retract-claim.


def _advance_transaction_stage(base: str, transaction_id: str, new_stage: str) -> dict:
    """Advance the journal one approved stage forward, failing closed."""
    from app.services import review_integrity as ri

    try:
        return ri.update_transaction_stage(
            base, transaction_id=transaction_id, new_stage=new_stage
        )
    except ri.ReviewIntegrityError as exc:
        raise ReviewError(
            "TRANSACTION_JOURNAL: transaction stage update failed"
        ) from exc


def _advance_event_checkpoint(base: str, plan: dict, durable: dict) -> None:
    """Commit the planned event through the checkpoint primitive (Step 12).

    Advances the chain-head checkpoint to exactly the created tail event,
    then requires the fully validated committed chain head to be the
    journal-recorded expected event (identity and hash).
    """
    from app.services import review_integrity as ri

    created_event = durable["created_event"]
    journal = plan["journal"]
    try:
        ri.advance_review_event_checkpoint(
            base,
            sequence=created_event["sequence"],
            event_id=created_event["event_id"],
            event_hash=created_event["event_hash"],
        )
        committed = ri.validate_review_event_chain(base)
    except ri.ReviewIntegrityError as exc:
        raise ReviewError(f"EVENT_CHECKPOINT: {exc}") from exc
    head = committed[-1]
    if (
        head != created_event
        or head["event_id"] != journal["expected_event_id"]
        or head["event_hash"] != journal["expected_event_hash"]
    ):
        raise ReviewError(
            "STATE_DRIFT: committed chain head is not the expected event"
        )


def _install_proposed_manifest(base: str, plan: dict, durable: dict) -> None:
    """Atomically install the exact proposed manifest as active (Step 13).

    Re-verifies the active manifest still matches starting_manifest_hash and
    the durable temporary file still hashes to proposed_manifest_hash, then
    atomically replaces provenance_manifest.json with the exact proposed
    bytes and verifies the installed hash.
    """
    from app.services import provenance as prov

    _assert_starting_manifest_unchanged(base, plan["starting_manifest_hash"])
    relative = plan["proposed_manifest_relative_path"]
    if _hash_current(base, relative) != plan["proposed_manifest_hash"]:
        raise ReviewError(
            "STATE_DRIFT: durable proposed manifest no longer hashes to "
            "proposed_manifest_hash"
        )
    try:
        temp_path = prov.resolve_task_path(base, relative, must_exist=True)
        active_path = prov.resolve_task_path(
            base, MANIFEST_FILENAME, must_exist=True
        )
    except prov.ProvenanceError as exc:
        raise ReviewError(f"MANIFEST_INSTALL: {exc}") from exc
    try:
        os.replace(temp_path, active_path)
    except OSError as exc:
        raise ReviewError(f"MANIFEST_INSTALL: {exc}") from exc
    if _hash_current(base, MANIFEST_FILENAME) != plan["proposed_manifest_hash"]:
        raise ReviewError(
            "STATE_DRIFT: installed manifest does not hash to "
            "proposed_manifest_hash"
        )


def _verify_committed_state(base: str, plan: dict, durable: dict, journal: dict) -> None:
    """Verify every committed artifact and invariant (Step 14).

    Requires the installed active manifest, the immutable snapshot, the
    committed event and checkpoint, the complete manifest-history and
    review-event chains, the unchanged journal (at MANIFEST_INSTALLED), and
    the retained matching-token lock to validate exactly against the
    journal-recorded identity and hashes before COMMITTED.
    """
    from app.services import provenance as prov
    from app.services import review_integrity as ri

    # Active manifest hashes exactly to proposed_manifest_hash.
    try:
        manifest, _manifest_path, _manifest_sha = _load_manifest(base)
    except ReviewError as exc:
        raise ReviewError(f"MANIFEST_INVALID: {exc}") from exc
    if prov.canonical_sha256(manifest) != plan["proposed_manifest_hash"]:
        raise ReviewError(
            "STATE_DRIFT: active manifest does not hash to "
            "proposed_manifest_hash"
        )

    # Immutable snapshot still hashes exactly to starting_manifest_hash.
    try:
        snapshot_path = prov.resolve_task_path(
            base, plan["snapshot_relative_path"], must_exist=True
        )
        with open(snapshot_path, "rb") as handle:
            snapshot = json.loads(handle.read().decode("utf-8"))
    except (prov.ProvenanceError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewError(
            "SNAPSHOT: snapshot evidence failed validation"
        ) from exc
    if prov.canonical_sha256(snapshot) != plan["starting_manifest_hash"]:
        raise ReviewError(
            "STATE_DRIFT: snapshot no longer hashes to starting_manifest_hash"
        )

    # Complete chains validate; the committed head is the expected event
    # with the journal-recorded before/after manifest hashes.
    try:
        ri.list_manifest_history(base)
        committed = ri.validate_review_event_chain(base)
    except ri.ReviewIntegrityError as exc:
        raise ReviewError(
            "EVENT_CHAIN: event chain failed validation"
        ) from exc
    head = committed[-1]
    if (
        head["event_id"] != plan["journal"]["expected_event_id"]
        or head["event_hash"] != plan["journal"]["expected_event_hash"]
        or head["manifest_hash_before"] != plan["starting_manifest_hash"]
        or head["manifest_hash_after"] != plan["proposed_manifest_hash"]
    ):
        raise ReviewError(
            "STATE_DRIFT: committed event does not match the expected "
            "identity and hashes"
        )

    # Journal unchanged at MANIFEST_INSTALLED; matching-token lock retained.
    try:
        current = ri.read_transaction_journal(base)
    except ri.ReviewIntegrityError as exc:
        raise ReviewError(
            "TRANSACTION_JOURNAL: transaction journal failed validation"
        ) from exc
    if current is None:
        raise ReviewError("TRANSACTION_JOURNAL: journal removed before COMMITTED")
    if current != journal:
        raise ReviewError(
            "STATE_DRIFT: transaction journal changed before COMMITTED"
        )
    try:
        held_lock = ri.read_review_lock(base)
    except ri.ReviewIntegrityError as exc:
        raise ReviewError(
            "LOCK_HELD: review lock failed validation"
        ) from exc
    if held_lock is None or held_lock["lock_token"] != journal["lock_token"]:
        raise ReviewError(
            "LOCK_HELD: matching-token lock not retained through COMMITTED "
            "verification"
        )


def _reconcile_committed_lock(base: str, journal: dict) -> None:
    """Release/reconcile the lock under the COMMITTED rule (Step 15).

    Exactly two states are permitted: the matching journal-recorded lock
    exists — release it and verify its absence; or no lock exists — the
    matching-token release is treated as already completed. Any other lock
    token or a malformed lock state fails closed.
    """
    from app.services import review_integrity as ri

    try:
        held_lock = ri.read_review_lock(base)
    except ri.ReviewIntegrityError as exc:
        raise ReviewError(f"LOCK_HELD: {exc}") from exc
    if held_lock is None:
        return
    if held_lock["lock_token"] != journal["lock_token"]:
        raise ReviewError(
            "LOCK_HELD: COMMITTED lock reconciliation found a non-matching "
            "lock token; failing closed"
        )
    try:
        ri.release_review_lock(base, lock_token=journal["lock_token"])
        absent = ri.read_review_lock(base)
    except ri.ReviewIntegrityError as exc:
        raise ReviewError(f"LOCK_HELD: {exc}") from exc
    if absent is not None:
        raise ReviewError(
            "LOCK_HELD: lock release did not remove the matching lock"
        )


def _finalize_claim_transaction(task_dir: str, plan: dict, durable: dict) -> dict:
    """Execute approved Steps 12-17 and return the completion summary.

    Step 12: commit the planned event through the split checkpoint
             primitive; validate the committed head is the expected event;
             advance to CHECKPOINT_UPDATED.
    Step 13: atomically install the exact proposed manifest as active
             provenance_manifest.json and verify its hash; advance to
             MANIFEST_INSTALLED.
    Step 14: verify the committed manifest, snapshot, event, checkpoint,
             complete chains, journal, and retained matching-token lock;
             advance to COMMITTED.
    Step 15: release/reconcile the lock under the COMMITTED matching-token
             rule.
    Step 16: no recovery receipt — direct completion only; receipts are
             finalized exclusively by resume-transaction.
    Step 17: remove the completed journal last.

    Every pre-COMMITTED failure retains the journal and lock (Section 2.4).
    """
    from app.services import review_integrity as ri

    base = _resolve_task_dir(task_dir)
    transaction_id = plan["journal"]["transaction_id"]

    _advance_event_checkpoint(base, plan, durable)
    journal = _advance_transaction_stage(base, transaction_id, "CHECKPOINT_UPDATED")
    _install_proposed_manifest(base, plan, durable)
    journal = _advance_transaction_stage(base, transaction_id, "MANIFEST_INSTALLED")
    _verify_committed_state(base, plan, durable, journal)
    journal = _advance_transaction_stage(base, transaction_id, "COMMITTED")
    _reconcile_committed_lock(base, journal)
    # Step 16: direct completion finalizes no recovery receipt.
    try:
        ri.delete_transaction_journal(base)
    except ri.ReviewIntegrityError as exc:
        raise ReviewError(f"TRANSACTION_JOURNAL: {exc}") from exc

    return {
        "operation": plan["operation"],
        "task_id": plan["task_id"],
        "claim_id": plan["claim_id"],
        "transaction_id": transaction_id,
        "reviewer_id": plan["reviewer_id"],
        "reviewer_display_name": plan["reviewer_display_name"],
        "review_timestamp_utc": plan["timestamp_utc"],
        "starting_manifest_hash": plan["starting_manifest_hash"],
        "proposed_manifest_hash": plan["proposed_manifest_hash"],
        "snapshot_relative_path": plan["snapshot_relative_path"],
        "event": durable["created_event"],
    }


def _run_claim_transaction(
    task_dir: str,
    *,
    operation: str,
    claim_id,
    reviewer_id,
    reviewer_display_name,
    reason=None,
    notes=None,
) -> dict:
    """Run the complete direct claim-mutation transaction (Steps 1-17).

    Chains the frozen plan (Steps 1-7), the durable phase (Steps 8-11), and
    finalization (Steps 12-17). Reached from the CLI by cmd_verify_claim
    and cmd_retract_claim.
    """
    plan = _plan_claim_transaction(
        task_dir,
        operation=operation,
        claim_id=claim_id,
        reviewer_id=reviewer_id,
        reviewer_display_name=reviewer_display_name,
        reason=reason,
        notes=notes,
    )
    durable = _execute_claim_transaction_durable(task_dir, plan)
    return _finalize_claim_transaction(task_dir, plan, durable)


# ---------------------------------------------------------------------------
# Read-only state assembly (shared by status and audit)
# ---------------------------------------------------------------------------


def _assemble_state(task_dir: str) -> dict:
    """Gather every read-only fact needed by status and audit.

    Performs no mutation. Returns a dict of facts plus a list of integrity
    failures (reason codes). An empty failures list means integrity holds.
    """
    from app.services import provenance as prov
    from app.services import review_integrity as ri

    base = _resolve_task_dir(task_dir)
    failures: list[str] = []
    state: dict = {"task_dir": base}

    # --- manifest ---
    try:
        manifest, manifest_path, manifest_sha = _load_manifest(base)
    except ReviewError as exc:
        state["manifest_error"] = str(exc)
        state["failures"] = [f"manifest:{exc}"]
        return state
    state["manifest"] = manifest
    state["manifest_sha256"] = manifest_sha
    state["schema_version"] = manifest.get("task", {}).get("schema_version")

    # --- current hash checks (script / assets / output) ---
    script = manifest.get("script")
    script_status = "not-present"
    if script:
        current = _hash_current(base, script.get("local_path", ""))
        if current is None:
            script_status = "missing"
            failures.append("script:missing")
        elif current != script.get("sha256"):
            script_status = "changed"
            failures.append("script:hash-mismatch")
        else:
            script_status = "ok"
    state["script_status"] = script_status

    asset_statuses = []
    for asset in manifest.get("assets", []):
        current = _hash_current(base, asset.get("local_path", ""))
        if current is None:
            asset_statuses.append("missing")
            failures.append(f"asset:missing:{asset.get('local_path')}")
        elif current != asset.get("sha256"):
            asset_statuses.append("changed")
            failures.append(f"asset:hash-mismatch:{asset.get('local_path')}")
        else:
            asset_statuses.append("ok")
    state["asset_statuses"] = asset_statuses

    output = manifest.get("output")
    output_status = "not-present"
    if output:
        if output.get("sha256") is None:
            output_status = "not-present"
        else:
            current = _hash_current(base, output.get("local_path", ""))
            if current is None:
                output_status = "missing"
                failures.append("output:missing")
            elif current != output.get("sha256"):
                output_status = "changed"
                failures.append("output:hash-mismatch")
            else:
                output_status = "ok"
    state["output_status"] = output_status

    # --- asset provenance completeness ---
    incomplete_assets = []
    for asset in manifest.get("assets", []):
        if not asset.get("license_name") or not asset.get("license_evidence"):
            incomplete_assets.append(asset.get("local_path"))
        if asset.get("source_type") == "provider":
            for field in ("source_url", "provider", "provider_asset_id",
                          "retrieval_date"):
                if not asset.get(field):
                    incomplete_assets.append(asset.get("local_path"))
    state["incomplete_assets"] = incomplete_assets
    if incomplete_assets:
        failures.append("asset:provenance-incomplete")

    # --- claim counts and blockers ---
    claims = manifest.get("factual_claims", [])
    counts = {"UNVERIFIED": 0, "VERIFIED": 0, "RETRACTED": 0}
    for claim in claims:
        status = claim.get("status")
        if status in counts:
            counts[status] += 1
    state["claim_counts"] = counts
    blocking = [c for c in claims if c.get("status") in ("UNVERIFIED", "RETRACTED")]
    state["blocking_claims"] = len(blocking)

    # --- review-event chain + checkpoint ---
    try:
        events = ri.validate_review_event_chain(base)
        state["event_count"] = len(events)
        state["event_chain_valid"] = True
        state["event_head_hash"] = events[-1]["event_hash"] if events else None
    except ri.ReviewIntegrityError as exc:
        state["event_count"] = None
        state["event_chain_valid"] = False
        state["event_chain_error"] = str(exc)
        failures.append(f"event-chain:{exc}")

    # --- receipt chain + checkpoint ---
    try:
        receipts = ri.validate_receipt_chain(base)
        state["receipt_count"] = len(receipts)
        state["receipt_chain_valid"] = True
        state["receipts"] = receipts
    except ri.ReviewIntegrityError as exc:
        state["receipt_count"] = None
        state["receipt_chain_valid"] = False
        state["receipt_chain_error"] = str(exc)
        failures.append(f"receipt-chain:{exc}")

    # --- uncommitted tails ---
    for chain_type in ("review-events", "approvals"):
        try:
            tail = ri.find_uncommitted_tail(base, chain_type)
            state[f"{chain_type}_uncommitted"] = len(tail)
            if tail:
                failures.append(f"{chain_type}:uncommitted-tail")
        except ri.ReviewIntegrityError:
            state[f"{chain_type}_uncommitted"] = None

    # --- lock status (read-only; never acquired or removed) ---
    try:
        lock = ri.read_review_lock(base)
        state["lock_held"] = lock is not None
        if lock is not None:
            state["lock_holder"] = lock.get("reviewer_id")
    except ri.ReviewIntegrityError as exc:
        state["lock_held"] = None
        state["lock_error"] = str(exc)
        failures.append(f"lock:{exc}")

    # --- transaction journal (read-only detection) ---
    try:
        journal = ri.read_transaction_journal(base)
        state["transaction_journal"] = journal
        if journal is not None:
            failures.append("INCOMPLETE_TRANSACTION")
    except ri.ReviewIntegrityError as exc:
        state["transaction_journal"] = None
        state["transaction_journal_error"] = str(exc)
        failures.append("INCOMPLETE_TRANSACTION")

    # --- unexpected partial/temp files ---
    partials = []
    for sub in ("review-events", "approvals", "manifest-history"):
        subdir = os.path.join(base, sub)
        if os.path.isdir(subdir):
            for name in os.listdir(subdir):
                if name.startswith(".tmp-") or name.endswith(".part") or \
                        name.endswith(".tmp"):
                    partials.append(f"{sub}/{name}")
    for name in os.listdir(base):
        if name.startswith(".tmp-") or name.endswith(".part"):
            partials.append(name)
    state["partial_files"] = partials
    if partials:
        failures.append("partial-files-present")

    state["failures"] = failures
    return state


# ---------------------------------------------------------------------------
# Effective task status (derived read-only; never inferred from manifest alone)
# ---------------------------------------------------------------------------


def _effective_status(state: dict) -> tuple[str, list[str]]:
    """Derive the effective task status without modifying files.

    Returns (status, blocking_reasons). Status is one of:
    NEEDS_HUMAN_REVIEW, APPROVED, REVOKED, REJECTED, INVALID.
    """
    reasons: list[str] = []
    if "manifest" not in state:
        return "INVALID", ["manifest unreadable or invalid"]
    if state.get("failures"):
        # Any integrity failure forces fail-closed.
        return "INVALID", ["integrity failure: " + "; ".join(
            f.split(":", 1)[0] for f in state["failures"][:3]
        )]

    manifest = state["manifest"]
    task_status = manifest.get("task", {}).get("review_status")
    receipts = state.get("receipts") or []

    approvals = [r for r in receipts if r.get("receipt_type") == "APPROVAL"]
    revocations = [r for r in receipts if r.get("receipt_type") == "REVOCATION"]

    # Revocation linked to a valid approval => REVOKED.
    if approvals and revocations:
        approval_ids = {a["receipt_id"] for a in approvals}
        if any(r.get("approval_receipt_id") in approval_ids for r in revocations):
            return "REVOKED", []

    if task_status == "APPROVED":
        # Do NOT infer approval from the manifest alone: a receipt is required.
        if not approvals:
            return "INVALID", ["manifest APPROVED but no approval receipt"]
        # Receipt must anchor this manifest version.
        latest = approvals[-1]
        if latest.get("manifest_sha256") != state.get("manifest_sha256"):
            reasons.append("approval receipt manifest hash mismatch")
            return "INVALID", reasons
        return "APPROVED", []

    if task_status == "REJECTED":
        return "REJECTED", []

    if task_status == "NEEDS_HUMAN_REVIEW":
        if approvals:
            return "INVALID", ["approval receipt exists for unapproved manifest"]
        return "NEEDS_HUMAN_REVIEW", []

    return "INVALID", [f"unknown task review_status: {task_status!r}"]


def _approval_readiness(state: dict, effective: str) -> tuple[str, list[str]]:
    """Return (READY|BLOCKED, reasons)."""
    reasons: list[str] = []
    if effective != "NEEDS_HUMAN_REVIEW":
        return "BLOCKED", [f"effective status is {effective}, not NEEDS_HUMAN_REVIEW"]
    if state.get("failures"):
        reasons.append("integrity failure present")
    if state.get("blocking_claims"):
        reasons.append(
            f"{state['blocking_claims']} claim(s) UNVERIFIED/RETRACTED"
        )
    if state.get("incomplete_assets"):
        reasons.append(f"{len(state['incomplete_assets'])} asset(s) incomplete")
    if state.get("script_status") not in ("ok", "not-present"):
        reasons.append(f"script {state['script_status']}")
    if any(s != "ok" for s in state.get("asset_statuses", [])):
        reasons.append("asset hash issue")
    if state.get("lock_held"):
        reasons.append("review lock held")
    return ("BLOCKED", reasons) if reasons else ("READY", [])


# ---------------------------------------------------------------------------
# Resume-transaction request loading (Phase 1B.3C.2B.2C Slice 3, Section 2.8)
# ---------------------------------------------------------------------------
# Read-only loading and validation for the explicit, forward-only resume
# command. These helpers perform ZERO writes: no stage advancement, no
# artifact creation, no lock mutation, and no receipt creation. They are
# private and unreachable from the CLI until the resume-transaction wiring
# lands in a later checkpoint.

_TRANSACTION_ID_ARG_PATTERN = re.compile(r"[0-9a-f]{32}")


def _validate_transaction_id_arg(transaction_id) -> str:
    """Require the --transaction-id argument to be uuid4-hex (32 lower hex).

    A malformed value can never equal a journal's validated transaction_id,
    so it fails closed with the approved TRANSACTION_ID_MISMATCH code.
    """
    if not isinstance(
        transaction_id, str
    ) or not _TRANSACTION_ID_ARG_PATTERN.fullmatch(transaction_id):
        raise ReviewError(
            "TRANSACTION_ID_MISMATCH: transaction-id must be a 32-char "
            "lowercase hex string (uuid4 hex)"
        )
    return transaction_id


def _resume_read_transaction_journal(base: str):
    """Read the transaction journal under the approved resume taxonomy.

    Converts every ReviewIntegrityError from the integrity layer into
    exactly TRANSACTION_JOURNAL_CORRUPT: transaction journal failed
    validation, retaining the original exception only as the chained
    cause. No native text, paths, values, or payloads are surfaced.
    """
    from app.services import review_integrity as ri

    try:
        return ri.read_transaction_journal(base)
    except ri.ReviewIntegrityError as exc:
        raise ReviewError(
            "TRANSACTION_JOURNAL_CORRUPT: transaction journal failed "
            "validation"
        ) from exc


def _load_resume_request(
    task_dir: str,
    *,
    transaction_id,
    reviewer_id,
    reviewer_display_name,
    reason,
) -> dict:
    """Load and validate a resume-transaction request (approved Section 2.8).

    Read-only: performs zero writes. Validation order and failure codes:

    1. active manifest exists and validates (MANIFEST_INVALID);
    2. journal exists and validates (TRANSACTION_NOT_FOUND when absent,
       TRANSACTION_JOURNAL_CORRUPT when unvalidatable);
    3. --transaction-id argument shape and journal match
       (TRANSACTION_ID_MISMATCH — a malformed value can never match the
       journal's validated id);
    4. resuming reviewer ID (REVIEWER_ID_INVALID);
    5. resuming reviewer display name (REVIEWER_NAME_INVALID);
    6. --reason provided, non-empty, sanitized (REASON_REQUIRED);
    7. pilot policy gate (POLICY_FAILURE);
    8. non-null journal claim_notes re-checked against the current secret
       patterns after structural and self-hash validation, before any use
       (TRANSACTION_JOURNAL_CORRUPT; approved resume-payload correction
       amendment — null carries no content and is skipped);
    9. recorded operation supported and immutable journal identity
       consistent with the active manifest (TRANSACTION_JOURNAL_CORRUPT /
       TRANSACTION_AMBIGUOUS).

    Returns the frozen request context consumed by the resume dispatchers.
    """
    from app.services import review_integrity as ri

    base = _resolve_task_dir(task_dir)

    # Approved Section 2.8 row 1: the active manifest loads first.
    try:
        manifest, _manifest_path, _manifest_sha = _load_manifest(base)
    except ReviewError as exc:
        raise ReviewError(f"MANIFEST_INVALID: {exc}") from exc

    # Approved Section 2.8 row 2: journal presence versus validity.
    journal = _resume_read_transaction_journal(base)
    if journal is None:
        raise ReviewError(
            "TRANSACTION_NOT_FOUND: no transaction journal exists"
        )

    # Approved Section 2.8 row 3: validate the argument shape, then match.
    transaction_id = _validate_transaction_id_arg(transaction_id)
    if journal["transaction_id"] != transaction_id:
        raise ReviewError(
            "TRANSACTION_ID_MISMATCH: supplied transaction-id does not "
            "match the transaction journal"
        )

    # Approved Section 2.8 rows 4-6: resuming reviewer identity and reason.
    _validate_reviewer_args(reviewer_id, reviewer_display_name)
    if not isinstance(reason, str) or not reason.strip():
        raise ReviewError(
            "REASON_REQUIRED: resume-transaction requires a non-empty reason"
        )
    _sanitize_free_text(reason, "reason")

    # Approved Section 2.8 row 7: pilot policy gate.
    _require_pilot_policy()

    # Approved amendment Section 2.1: re-check a non-null claim_notes
    # against the current secret patterns after structural and self-hash
    # validation, before any use; null carries no content and is skipped.
    claim_notes = journal["claim_notes"]
    if isinstance(claim_notes, str):
        try:
            _sanitize_free_text(claim_notes, "claim_notes")
        except ReviewError as exc:
            raise ReviewError(
                "TRANSACTION_JOURNAL_CORRUPT: journal claim_notes rejected "
                "by the current secret-pattern check"
            ) from exc

    # Recorded operation must be one of the approved transaction operations
    # (defense in depth; read validation already rejects unknown values).
    if journal["operation"] not in ri.TRANSACTION_OPERATIONS:
        raise ReviewError(
            "TRANSACTION_JOURNAL_CORRUPT: unsupported recorded operation"
        )

    # Immutable journal identity must be consistent with the active
    # manifest (approved Section 2.8: inconsistency fails closed).
    if journal["task_id"] != manifest.get("task", {}).get("task_id"):
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: journal task_id is inconsistent with "
            "the active manifest"
        )
    matches = [
        claim
        for claim in manifest.get("factual_claims", [])
        if claim.get("claim_id") == journal["claim_id"]
    ]
    if len(matches) != 1:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: journal claim_id does not select "
            "exactly one claim in the active manifest"
        )

    return {
        "manifest": manifest,
        "journal": journal,
        "transaction_id": transaction_id,
        "reviewer_id": reviewer_id,
        "reviewer_display_name": reviewer_display_name,
        "reason": reason,
    }


# ---------------------------------------------------------------------------
# Resume-transaction plan reconstruction (Phase 1B.3C.2B.2C Slice 3, 2.8)
# ---------------------------------------------------------------------------
# Rebuilds the frozen Slice 2 plan from the validated resume request and
# durable evidence. Every helper in this section is read-only: no stage
# advancement, no filesystem writes, no artifact creation, no lock
# mutation, and no receipt creation. Durable journal identity fields are
# validated at read time by review_integrity (operation enum, claim_id
# format, original reviewer identity, frozen created_at_utc timestamp,
# hash formats, confined relative paths, stage enum, self-hash); this
# section adds the consistency layer — stage invariants, hash equalities,
# deterministic event identity, and exact claim_notes equality. Missing
# evidence that is valid for the recorded stage is reconstructed in
# memory only; inconsistent, extra, escaping, or hash-mismatched evidence
# fails closed TRANSACTION_AMBIGUOUS before any write. The resuming
# reviewer and reason are preserved separately in the returned resume
# context and are never substituted into the original mutation or event.


def _resume_evidence_path(base: str, relative_path: str, field: str) -> str:
    """Resolve a journal-recorded evidence path; escaping fails closed."""
    from app.services import provenance as prov

    try:
        return prov.resolve_task_path(base, relative_path, must_exist=False)
    except prov.ProvenanceError as exc:
        raise ReviewError(
            f"TRANSACTION_AMBIGUOUS: journal {field} escapes the task "
            "directory"
        ) from exc


def _resume_snapshot_starting_manifest(base: str, journal: dict) -> dict:
    """Load the recorded snapshot; require starting_manifest_hash exactly."""
    from app.services import provenance as prov

    snapshot_path = _resume_evidence_path(
        base, journal["snapshot_relative_path"], "snapshot_relative_path"
    )
    try:
        with open(snapshot_path, "rb") as handle:
            snapshot = json.loads(handle.read().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: snapshot evidence failed validation"
        ) from exc
    if prov.canonical_sha256(snapshot) != journal["starting_manifest_hash"]:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: snapshot does not hash to "
            "starting_manifest_hash"
        )
    return snapshot


def _resume_proposed_from_temp(base: str, journal: dict) -> tuple[dict, bytes]:
    """Validate the durable proposed-manifest temp against the journal.

    Requires confinement, exact byte-hash equality with
    proposed_manifest_hash, canonical-byte stability, manifest validity,
    exactly one journal-recorded target claim, and exact target-claim
    notes equality with the journal claim_notes (approved amendment
    Section 2.6). Returns (proposed_manifest, exact_bytes).
    """
    from app.services import provenance as prov

    temp_path = _resume_evidence_path(
        base,
        journal["proposed_manifest_relative_path"],
        "proposed_manifest_relative_path",
    )
    try:
        with open(temp_path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: proposed manifest evidence failed "
            "validation"
        ) from exc
    if hashlib.sha256(raw).hexdigest() != journal["proposed_manifest_hash"]:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: durable proposed manifest does not "
            "hash to proposed_manifest_hash"
        )
    try:
        proposed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: proposed manifest evidence failed "
            "validation"
        ) from exc
    if prov.canonical_json_bytes(proposed) != raw:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: durable proposed manifest bytes are "
            "not canonical"
        )
    try:
        prov.validate_manifest(proposed)
    except prov.ProvenanceError as exc:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: proposed manifest evidence failed "
            "validation"
        ) from exc
    matches = [
        claim
        for claim in proposed.get("factual_claims", [])
        if claim.get("claim_id") == journal["claim_id"]
    ]
    if len(matches) != 1:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: durable proposed manifest does not "
            "contain exactly one journal-recorded target claim"
        )
    if matches[0].get("notes") != journal["claim_notes"]:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: durable proposed manifest target "
            "claim notes differ from the journal claim_notes"
        )
    return proposed, raw


def _resume_proposed_rebuilt(
    starting_manifest: dict, journal: dict
) -> tuple[dict, bytes]:
    """Rebuild the proposed manifest in memory from journal identity.

    Approved amendment Section 2.6: the reconstruction inputs are exactly
    the journal-recorded operation, claim_id, original reviewer identity,
    frozen created_at_utc timestamp, and claim_notes; the resuming
    reviewer and resume reason are never substituted. The rebuilt
    manifest must hash exactly to proposed_manifest_hash. Returns
    (proposed_manifest, canonical_bytes); nothing is written.
    """
    from app.services import provenance as prov

    try:
        proposed = _build_proposed_manifest(
            starting_manifest,
            operation=journal["operation"],
            claim_id=journal["claim_id"],
            reviewer_id=journal["original_reviewer_id"],
            reviewer_display_name=journal["original_reviewer_display_name"],
            review_timestamp_utc=journal["created_at_utc"],
            notes=journal["claim_notes"],
        )
    except ReviewError as exc:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: proposed manifest reconstruction "
            "failed validation"
        ) from exc
    if prov.canonical_sha256(proposed) != journal["proposed_manifest_hash"]:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: rebuilt proposed manifest does not "
            "hash to proposed_manifest_hash"
        )
    return proposed, prov.canonical_json_bytes(proposed)


def _resume_find_uncommitted_tail(base: str) -> list:
    """Read the uncommitted review-event tail under the resume taxonomy.

    Converts every ReviewIntegrityError or OSError into exactly
    TRANSACTION_AMBIGUOUS: event tail evidence failed validation,
    retaining the original exception only as the chained cause. No
    native text, paths, filenames, or payloads are surfaced.
    """
    from app.services import review_integrity as ri

    try:
        return ri.find_uncommitted_tail(base, ri.CHAIN_TYPE_REVIEW_EVENTS)
    except (ri.ReviewIntegrityError, OSError) as exc:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: event tail evidence failed validation"
        ) from exc


def _resume_tail_event(base: str, journal: dict, tail: list) -> dict:
    """Require the sole uncommitted tail to be the journal-expected event.

    Deep tail semantics are fully validated by the checkpoint-advance
    primitive before any write (approved Section 2.8); this read-only
    gate requires exactly one tail record matching the journal-recorded
    expected identity and hash.
    """
    from app.services import review_integrity as ri

    if len(tail) != 1:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: multiple uncommitted review-event "
            "tail records; deferred forensic recovery required"
        )
    sequence, filename = tail[0]
    path = os.path.join(base, ri.REVIEW_EVENTS_DIR, filename)
    try:
        with open(path, "rb") as handle:
            event = json.loads(handle.read().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: event tail evidence failed validation"
        ) from exc
    if not isinstance(event, dict):
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: uncommitted tail event is not an "
            "object"
        )
    if (
        event.get("sequence") != sequence
        or event.get("event_id") != journal["expected_event_id"]
        or event.get("event_hash") != journal["expected_event_hash"]
    ):
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: uncommitted tail is not the "
            "journal-expected event"
        )
    return event


def _resume_expected_event(base: str, journal: dict, stage_index: int) -> dict:
    """Validate and return the journal-expected event evidence (read-only).

    Stage-aware sourcing (approved Section 2.8):
    - Before PROPOSED_MANIFEST_READY: no event tail may exist; the event
      is re-planned deterministically from the journal-recorded inputs
      and must hash exactly to expected_event_hash.
    - PROPOSED_MANIFEST_READY: with no tail, re-plan as above; with the
      exact sole tail, verify it without rewriting; any different,
      multiple, or malformed tail fails closed.
    - EVENT_CREATED: the exact sole tail must exist and verify.
    - CHECKPOINT_UPDATED and beyond: the tail must be empty and the
      committed chain head must be the expected event with the
      journal-recorded before/after manifest hashes.
    """
    from app.services import review_integrity as ri

    stages = ri.TRANSACTION_STAGES
    tail = _resume_find_uncommitted_tail(base)

    if stage_index < stages.index("EVENT_CREATED"):
        if tail:
            if stage_index == stages.index("PROPOSED_MANIFEST_READY"):
                return _resume_tail_event(base, journal, tail)
            raise ReviewError(
                "TRANSACTION_AMBIGUOUS: unexpected uncommitted "
                "review-event tail for the recorded stage"
            )
        try:
            planned = ri.plan_review_event(
                base,
                event_type=_CLAIM_EVENT_TYPES[journal["operation"]],
                reviewer_id=journal["original_reviewer_id"],
                reviewer_display_name=journal[
                    "original_reviewer_display_name"
                ],
                timestamp_utc=journal["created_at_utc"],
                event_id=journal["expected_event_id"],
                reason=(
                    journal["claim_notes"]
                    if journal["operation"] == "retract-claim"
                    else None
                ),
                manifest_hash_before=journal["starting_manifest_hash"],
                manifest_hash_after=journal["proposed_manifest_hash"],
            )
        except ri.ReviewIntegrityError as exc:
            raise ReviewError(
                "TRANSACTION_AMBIGUOUS: committed event evidence failed "
                "validation"
            ) from exc
        if planned["event_hash"] != journal["expected_event_hash"]:
            raise ReviewError(
                "TRANSACTION_AMBIGUOUS: re-planned event hash differs "
                "from expected_event_hash"
            )
        return planned

    if stage_index == stages.index("EVENT_CREATED"):
        if not tail:
            raise ReviewError(
                "TRANSACTION_AMBIGUOUS: recorded stage EVENT_CREATED "
                "but no uncommitted review-event tail exists"
            )
        return _resume_tail_event(base, journal, tail)

    # CHECKPOINT_UPDATED and beyond: the expected event is committed.
    if tail:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: unexpected uncommitted review-event "
            "tail beyond the committed checkpoint"
        )
    try:
        committed = ri.validate_review_event_chain(base)
    except ri.ReviewIntegrityError as exc:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: committed event evidence failed "
            "validation"
        ) from exc
    if not committed:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: review-event chain has no committed "
            "events"
        )
    head = committed[-1]
    if (
        head["event_id"] != journal["expected_event_id"]
        or head["event_hash"] != journal["expected_event_hash"]
        or head["manifest_hash_before"] != journal["starting_manifest_hash"]
        or head["manifest_hash_after"] != journal["proposed_manifest_hash"]
    ):
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: committed chain head is not the "
            "journal-expected event"
        )
    return head


def _reconstruct_resume_plan(task_dir: str, request: dict) -> dict:
    """Reconstruct the frozen Slice 2 plan for a validated resume request.

    Read-only: performs zero writes. Evidence sources by recorded stage
    (approved Section 2.8):

    - starting manifest: the active manifest before MANIFEST_INSTALLED
      (must hash to starting_manifest_hash); the hash-verified snapshot
      at MANIFEST_INSTALLED/COMMITTED (the active manifest must then
      hash to proposed_manifest_hash);
    - proposed manifest: the validated durable temp from
      PROPOSED_MANIFEST_READY through CHECKPOINT_UPDATED; an in-memory
      rebuild from journal identity plus claim_notes when the temp is
      legitimately absent (before PROPOSED_MANIFEST_READY); the validated
      exact durable temp used as-is at SNAPSHOT_CREATED when a crash
      between the Step-10 write and the stage advance left it behind
      (approved amendment Section 2.6); the active manifest after
      installation (the temp is consumed by the atomic install);
    - expected event: deterministic re-planning while uncreated, the
      verified sole uncommitted tail once created, the validated
      committed chain head once checkpointed.

    Extra, missing-required, escaping, or hash-mismatched evidence fails
    closed TRANSACTION_AMBIGUOUS before any write. Returns
    {"plan": plan, "resume": resume_context}; the resume context carries
    the resuming reviewer identity, reason, and interrupted stage for
    later receipt creation, never the original mutation or event.
    """
    from app.services import provenance as prov
    from app.services import review_integrity as ri

    base = _resolve_task_dir(task_dir)
    journal = request["journal"]
    active = request["manifest"]
    stages = ri.TRANSACTION_STAGES
    stage_index = stages.index(journal["transaction_stage"])
    installed = stage_index >= stages.index("MANIFEST_INSTALLED")

    # Active-manifest invariant for the recorded stage.
    active_hash = prov.canonical_sha256(active)
    if installed:
        if active_hash != journal["proposed_manifest_hash"]:
            raise ReviewError(
                "TRANSACTION_AMBIGUOUS: active manifest does not hash to "
                "proposed_manifest_hash after installation"
            )
    elif active_hash != journal["starting_manifest_hash"]:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: active manifest no longer hashes to "
            "starting_manifest_hash"
        )

    # Snapshot presence and the starting-manifest source.
    snapshot_path = _resume_evidence_path(
        base, journal["snapshot_relative_path"], "snapshot_relative_path"
    )
    snapshot_required = stage_index >= stages.index("SNAPSHOT_CREATED")
    snapshot_present = os.path.isfile(snapshot_path)
    if snapshot_present and not snapshot_required:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: snapshot exists before the recorded "
            "stage created it"
        )
    if snapshot_required and not snapshot_present:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: recorded snapshot is missing"
        )
    snapshot = None
    if snapshot_present:
        snapshot = _resume_snapshot_starting_manifest(base, journal)
    starting_manifest = snapshot if installed else active

    # Proposed-temp presence and the proposed-manifest source.
    temp_path = _resume_evidence_path(
        base,
        journal["proposed_manifest_relative_path"],
        "proposed_manifest_relative_path",
    )
    temp_required = (
        stages.index("PROPOSED_MANIFEST_READY")
        <= stage_index
        < stages.index("MANIFEST_INSTALLED")
    )
    # Approved amendment Section 2.6: at SNAPSHOT_CREATED a durable temp
    # left by a crash between the Step-10 write and the stage advance is
    # legitimate evidence, validated and used as-is — never rewritten.
    temp_permitted = temp_required or (
        journal["transaction_stage"] == "SNAPSHOT_CREATED"
    )
    temp_present = os.path.isfile(temp_path)
    if temp_present and not temp_permitted:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: proposed-manifest temp is extra for "
            "the recorded stage"
        )
    if temp_required and not temp_present:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: recorded proposed-manifest temp is "
            "missing"
        )
    if temp_present:
        proposed_manifest, proposed_bytes = _resume_proposed_from_temp(
            base, journal
        )
    elif installed:
        proposed_manifest = active
        proposed_bytes = prov.canonical_json_bytes(active)
    else:
        proposed_manifest, proposed_bytes = _resume_proposed_rebuilt(
            starting_manifest, journal
        )

    planned_event = _resume_expected_event(base, journal, stage_index)

    plan = {
        "operation": journal["operation"],
        "task_id": journal["task_id"],
        "claim_id": journal["claim_id"],
        "reviewer_id": journal["original_reviewer_id"],
        "reviewer_display_name": journal["original_reviewer_display_name"],
        "timestamp_utc": journal["created_at_utc"],
        "event_id": journal["expected_event_id"],
        "lock_token": journal["lock_token"],
        "starting_manifest": starting_manifest,
        "starting_manifest_hash": journal["starting_manifest_hash"],
        "proposed_manifest": proposed_manifest,
        "proposed_manifest_bytes": proposed_bytes,
        "proposed_manifest_hash": journal["proposed_manifest_hash"],
        "proposed_manifest_relative_path": journal[
            "proposed_manifest_relative_path"
        ],
        "proposed_temp_present": temp_present,
        "snapshot_relative_path": journal["snapshot_relative_path"],
        "planned_event": planned_event,
        "journal": journal,
    }
    resume = {
        "resuming_reviewer_id": request["reviewer_id"],
        "resuming_reviewer_display_name": request["reviewer_display_name"],
        "reason": request["reason"],
        "interrupted_stage": journal["transaction_stage"],
    }
    return {"plan": plan, "resume": resume}


# ---------------------------------------------------------------------------
# Resume-transaction early-stage adapters (Phase 1B.3C.2B.2C Slice 3, 2.8)
# ---------------------------------------------------------------------------
# Forward-only resume execution for INITIATED, LOCK_ACQUIRED, and
# SNAPSHOT_CREATED. Each adapter accepts only its exact recorded stage,
# revalidates the mutable on-disk inputs (journal, matching lock, active
# starting manifest) immediately before its single mutation, advances
# exactly one stage via the update primitive, and retains the journal and
# the matching lock on any failure — no rollback, no overwrite, no lock
# release, no receipt creation. Errors from re-executed Slice 2 mutation
# helpers are translated to the approved resume taxonomy: MANIFEST_INVALID
# passes through; every other ReviewError and any raw OSError surfaces as
# a static TRANSACTION_AMBIGUOUS message with the original exception
# retained only as the internal chained cause, so resume never surfaces
# STATE_DRIFT, SNAPSHOT, PROPOSED_MANIFEST, bare TRANSACTION_JOURNAL, or
# uncoded errors. The resume-specific classification checks fail
# TRANSACTION_AMBIGUOUS / TRANSACTION_JOURNAL_CORRUPT /
# TRANSACTION_NOT_FOUND / LOCK_HELD / MANIFEST_INVALID per approved
# Section 2.8. Later stages, dispatch, and CLI wiring land in later
# checkpoints; these adapters are private and unreachable from the CLI.


def _require_resume_stage(journal: dict, expected: str) -> None:
    """Fail closed unless the journal sits at exactly the expected stage."""
    if journal["transaction_stage"] != expected:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: resume adapter reached at stage "
            f"{journal['transaction_stage']!r}, expected {expected!r}"
        )


def _resume_revalidate_journal_and_lock(base: str, journal: dict) -> dict:
    """Re-read the journal and matching lock immediately before mutation.

    The on-disk journal must equal the validated request journal exactly
    (stage included); the held lock must exist and carry the exact
    journal-recorded token (approved Section 2.8: before COMMITTED, a
    missing or mismatched lock fails closed). Performs no writes.
    """
    from app.services import review_integrity as ri

    current = _resume_read_transaction_journal(base)
    if current is None:
        raise ReviewError(
            "TRANSACTION_NOT_FOUND: transaction journal disappeared "
            "during resume"
        )
    if current != journal:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: transaction journal changed during "
            "resume"
        )
    try:
        held_lock = ri.read_review_lock(base)
    except ri.ReviewIntegrityError as exc:
        raise ReviewError("LOCK_HELD: review lock failed validation") from exc
    if held_lock is None:
        raise ReviewError(
            "LOCK_HELD: the journal-recorded lock is missing"
        )
    if held_lock["lock_token"] != journal["lock_token"]:
        raise ReviewError(
            "LOCK_HELD: held lock token does not match the "
            "journal-recorded token"
        )
    return current


def _resume_revalidate_active_starting(base: str, plan: dict) -> None:
    """Re-require the active manifest to hash to starting_manifest_hash."""
    from app.services import provenance as prov

    try:
        manifest, _manifest_path, _manifest_sha = _load_manifest(base)
    except ReviewError as exc:
        raise ReviewError(f"MANIFEST_INVALID: {exc}") from exc
    if prov.canonical_sha256(manifest) != plan["starting_manifest_hash"]:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: active manifest no longer hashes to "
            "starting_manifest_hash"
        )


def _resume_revalidate_active_proposed(base: str, plan: dict) -> None:
    """Re-require the active manifest to hash to proposed_manifest_hash."""
    from app.services import provenance as prov

    try:
        manifest, _manifest_path, _manifest_sha = _load_manifest(base)
    except ReviewError as exc:
        raise ReviewError(f"MANIFEST_INVALID: {exc}") from exc
    if prov.canonical_sha256(manifest) != plan["proposed_manifest_hash"]:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: active manifest no longer hashes to "
            "proposed_manifest_hash"
        )


def _resume_step_translated(description: str, step, *args):
    """Run a re-executed Slice 2 mutation step under the resume taxonomy.

    MANIFEST_INVALID passes through unchanged (approved Section 2.8
    row 1). Every other ReviewError — and any raw OSError — surfaces as
    a static TRANSACTION_AMBIGUOUS message (approved Section 2.8:
    ambiguous or inconsistent state fails closed). The surfaced message
    never contains native exception text, paths, journal contents, or
    payloads; the original exception is retained only as the internal
    chained cause.
    """
    try:
        return step(*args)
    except ReviewError as exc:
        if str(exc).startswith("MANIFEST_INVALID"):
            raise
        raise ReviewError(
            f"TRANSACTION_AMBIGUOUS: {description} failed during resume"
        ) from exc
    except OSError as exc:
        raise ReviewError(
            f"TRANSACTION_AMBIGUOUS: {description} failed during resume"
        ) from exc


def _resume_from_initiated(base: str, reconstructed: dict) -> dict:
    """Advance a validated INITIATED resume to LOCK_ACQUIRED only.

    Revalidates the journal, the matching lock, the active starting
    manifest, and the reconstructed plan (hash-verified by
    _reconstruct_resume_plan); creates no artifact; advances exactly one
    stage. On any failure the journal and matching lock are retained
    unchanged.
    """
    plan = reconstructed["plan"]
    journal = plan["journal"]
    _require_resume_stage(journal, "INITIATED")
    _resume_revalidate_journal_and_lock(base, journal)
    _resume_revalidate_active_starting(base, plan)
    return _resume_step_translated(
        "journal stage advance",
        _advance_transaction_stage,
        base,
        journal["transaction_id"],
        "LOCK_ACQUIRED",
    )


def _resume_from_lock_acquired(base: str, reconstructed: dict) -> dict:
    """Create the recorded snapshot; advance to SNAPSHOT_CREATED only.

    Revalidates journal/lock/active starting manifest, then creates and
    verifies exactly the journal-recorded snapshot (approved Step 9 via
    the Slice 2 step function). Advances exactly one stage. On any
    failure the journal and matching lock are retained unchanged.
    """
    plan = reconstructed["plan"]
    journal = plan["journal"]
    _require_resume_stage(journal, "LOCK_ACQUIRED")
    _resume_revalidate_journal_and_lock(base, journal)
    _resume_revalidate_active_starting(base, plan)
    _resume_step_translated(
        "snapshot creation/verification",
        _create_and_verify_snapshot,
        base,
        plan,
    )
    return _resume_step_translated(
        "journal stage advance",
        _advance_transaction_stage,
        base,
        journal["transaction_id"],
        "SNAPSHOT_CREATED",
    )


def _resume_from_snapshot_created(base: str, reconstructed: dict) -> dict:
    """Write or accept the proposed temp; advance one stage only.

    Revalidates journal/lock/active starting manifest, then resolves the
    durable proposed temp per approved amendment Section 2.6: when the
    reconstruction validated an exact temp already present (a crash
    between the Step-10 write and the stage advance), it is used as-is —
    never rewritten, never deleted; otherwise the byte-identical
    reconstructed proposed manifest is written exclusively to the
    journal-recorded confined path (approved Step 10 via the Slice 2
    step function — exclusive create, no overwrite). The temp is then
    re-validated against the journal: exact hash, canonical bytes,
    target-claim identity, and exact claim_notes equality. Advances
    exactly one stage. On any failure the journal and matching lock are
    retained unchanged.
    """
    plan = reconstructed["plan"]
    journal = plan["journal"]
    _require_resume_stage(journal, "SNAPSHOT_CREATED")
    _resume_revalidate_journal_and_lock(base, journal)
    _resume_revalidate_active_starting(base, plan)
    if not plan["proposed_temp_present"]:
        _resume_step_translated(
            "durable proposed-manifest write",
            _write_durable_proposed_manifest,
            base,
            plan,
        )
    _resume_proposed_from_temp(base, journal)
    return _resume_step_translated(
        "journal stage advance",
        _advance_transaction_stage,
        base,
        journal["transaction_id"],
        "PROPOSED_MANIFEST_READY",
    )


# ---------------------------------------------------------------------------
# Resume-transaction event-recovery adapters (Slice 3 checkpoint D2A, 2.8)
# ---------------------------------------------------------------------------
# Forward-only resume execution for PROPOSED_MANIFEST_READY and
# EVENT_CREATED. Each adapter accepts only its exact recorded stage,
# revalidates the mutable on-disk evidence (journal, matching lock, active
# starting manifest, recorded snapshot, recorded proposed temp, and the
# uncommitted event tail) immediately before its mutations, creates or
# commits exactly the journal-expected event, and advances exactly one
# stage. The journal and matching lock are retained on any failure — no
# rollback, no overwrite, no lock release, no receipt creation. Reused
# Slice 2 mutation helpers (and any raw OSError) are routed through the
# approved resume translation wrapper. Manifest installation, COMMITTED
# finalization, cascading dispatch, and CLI wiring land in later
# checkpoints; these adapters are private and unreachable from the CLI.


def _resume_from_proposed_manifest_ready(
    base: str, reconstructed: dict
) -> dict:
    """Create/verify the planned event; advance to EVENT_CREATED only.

    Revalidates the exact stage, the journal, the matching lock, the
    active starting manifest, the recorded snapshot, the recorded
    proposed temp, and the reconstructed plan (hash-verified by
    _reconstruct_resume_plan). Three-branch event behavior (approved
    Section 2.8):
    - no uncommitted tail: create exactly the planned event with the
      frozen event_id via the Slice 2 Step-11 helper, verifying full
      equality plus the journal-expected identity/hash;
    - the exact sole planned tail already exists: verify it read-only
      against the journal and never rewrite it;
    - any other or extra tail: fail closed TRANSACTION_AMBIGUOUS.
    Advances exactly one stage to EVENT_CREATED. On any failure the
    journal and matching lock are retained unchanged.
    """
    from app.services import review_integrity as ri

    plan = reconstructed["plan"]
    journal = plan["journal"]
    _require_resume_stage(journal, "PROPOSED_MANIFEST_READY")
    _resume_revalidate_journal_and_lock(base, journal)
    _resume_revalidate_active_starting(base, plan)
    _resume_snapshot_starting_manifest(base, journal)
    _resume_proposed_from_temp(base, journal)
    tail = _resume_find_uncommitted_tail(base)
    if tail:
        # The exact sole planned tail already exists: verify read-only,
        # never rewrite. A multiple, different, or malformed tail fails
        # closed TRANSACTION_AMBIGUOUS inside _resume_tail_event.
        _resume_tail_event(base, journal, tail)
    else:
        # No uncommitted event exists: create exactly the planned event
        # with the frozen event_id and verify full equality/expected hash.
        _resume_step_translated(
            "planned event creation/verification",
            _create_and_verify_planned_event,
            base,
            plan,
        )
    return _resume_step_translated(
        "journal stage advance",
        _advance_transaction_stage,
        base,
        journal["transaction_id"],
        "EVENT_CREATED",
    )


def _resume_from_event_created(base: str, reconstructed: dict) -> dict:
    """Commit the expected event; advance to CHECKPOINT_UPDATED only.

    Revalidates the exact stage, the journal, the matching lock, the
    active starting manifest, the recorded snapshot, the recorded
    proposed temp, and the exact sole uncommitted event tail (read-only).
    Advances the review-event checkpoint to exactly that event via the
    Slice 2 Step-12 helper, then requires the committed chain head to be
    the journal-expected event (identity and hash). Advances exactly one
    stage to CHECKPOINT_UPDATED. On any failure the journal and matching
    lock are retained unchanged.
    """
    from app.services import review_integrity as ri

    plan = reconstructed["plan"]
    journal = plan["journal"]
    _require_resume_stage(journal, "EVENT_CREATED")
    _resume_revalidate_journal_and_lock(base, journal)
    _resume_revalidate_active_starting(base, plan)
    _resume_snapshot_starting_manifest(base, journal)
    _resume_proposed_from_temp(base, journal)
    tail = _resume_find_uncommitted_tail(base)
    event = _resume_tail_event(base, journal, tail)
    _resume_step_translated(
        "event checkpoint advance",
        _advance_event_checkpoint,
        base,
        plan,
        {"created_event": event},
    )
    return _resume_step_translated(
        "journal stage advance",
        _advance_transaction_stage,
        base,
        journal["transaction_id"],
        "CHECKPOINT_UPDATED",
    )


# ---------------------------------------------------------------------------
# Resume-transaction install/commit adapters (Slice 3 checkpoint D2B, 2.8)
# ---------------------------------------------------------------------------
# Forward-only resume execution for CHECKPOINT_UPDATED and
# MANIFEST_INSTALLED. Each adapter accepts only its exact recorded stage,
# revalidates the mutable on-disk evidence (journal, matching lock, active
# manifest for the recorded stage, recorded snapshot, recorded durable
# proposed manifest while it must exist, and the committed event
# chain/head with every recorded hash and identity) immediately before its
# mutations, then advances exactly one stage. The journal and matching
# lock are retained on every pre-COMMITTED failure — no rollback, no
# overwrite, no lock release, no receipt creation, no journal deletion.
# Reused Slice 2 helpers (and any raw OSError) are routed through the
# approved resume translation wrapper. Lock reconciliation, recovery
# receipt finalization, journal removal, cascading dispatch, and CLI
# wiring land in later checkpoints; these adapters are private and
# unreachable from the CLI.


def _resume_from_checkpoint_updated(base: str, reconstructed: dict) -> dict:
    """Install the recorded proposed manifest; advance one stage only.

    Revalidates the exact stage, the journal, the matching lock, the
    active starting manifest, the recorded snapshot, the recorded durable
    proposed manifest, the committed event chain/head, and every recorded
    hash/identity (the reconstructed plan is hash-verified by
    _reconstruct_resume_plan). Atomically installs only the recorded
    proposed manifest via the Slice 2 Step-13 helper — the confined temp
    replaces the active manifest and the installed hash must equal
    proposed_manifest_hash — then advances exactly one stage to
    MANIFEST_INSTALLED. On any failure the journal and matching lock are
    retained unchanged.
    """
    from app.services import review_integrity as ri

    plan = reconstructed["plan"]
    journal = plan["journal"]
    _require_resume_stage(journal, "CHECKPOINT_UPDATED")
    _resume_revalidate_journal_and_lock(base, journal)
    _resume_revalidate_active_starting(base, plan)
    _resume_snapshot_starting_manifest(base, journal)
    _resume_proposed_from_temp(base, journal)
    head = _resume_expected_event(
        base, journal, ri.TRANSACTION_STAGES.index("CHECKPOINT_UPDATED")
    )
    # The reused Step-13 helper re-verifies from plan and journal; the
    # durable mapping is carried only for call-shape compatibility.
    _resume_step_translated(
        "proposed-manifest installation",
        _install_proposed_manifest,
        base,
        plan,
        {"created_event": head},
    )
    return _resume_step_translated(
        "journal stage advance",
        _advance_transaction_stage,
        base,
        journal["transaction_id"],
        "MANIFEST_INSTALLED",
    )


def _resume_from_manifest_installed(base: str, reconstructed: dict) -> dict:
    """Verify the full committed state; advance to COMMITTED only.

    Revalidates the exact stage, the journal, the matching lock, the
    active proposed manifest, the starting snapshot, the committed event
    chain/head, and the journal-recorded before/after hashes, then runs
    the approved full committed-state verification (Slice 2 Step 14:
    active manifest, immutable snapshot, complete manifest-history and
    review-event chains, unchanged journal, retained matching-token
    lock). Advances exactly one stage to COMMITTED. The lock is never
    released, no receipt is created, and the journal is never deleted
    here; on any pre-COMMITTED failure both are retained unchanged.
    """
    from app.services import review_integrity as ri

    plan = reconstructed["plan"]
    journal = plan["journal"]
    _require_resume_stage(journal, "MANIFEST_INSTALLED")
    _resume_revalidate_journal_and_lock(base, journal)
    _resume_revalidate_active_proposed(base, plan)
    _resume_snapshot_starting_manifest(base, journal)
    head = _resume_expected_event(
        base, journal, ri.TRANSACTION_STAGES.index("MANIFEST_INSTALLED")
    )
    # The reused Step-14 helper re-verifies from plan and journal; the
    # durable mapping is carried only for call-shape compatibility.
    _resume_step_translated(
        "committed-state verification",
        _verify_committed_state,
        base,
        plan,
        {"created_event": head},
        journal,
    )
    return _resume_step_translated(
        "journal stage advance",
        _advance_transaction_stage,
        base,
        journal["transaction_id"],
        "COMMITTED",
    )


# ---------------------------------------------------------------------------
# Resume-transaction COMMITTED finalization (Slice 3 checkpoint E, 2.8)
# ---------------------------------------------------------------------------
# Forward-only finalization for a journal already at COMMITTED: re-read and
# verify the exact COMMITTED journal, revalidate the committed evidence,
# reconcile the lock under the approved COMMITTED two-state rule, finalize
# the standalone immutable recovery receipt (create if absent, verify if
# exact, never rewrite), and delete the journal last. Any failure before
# journal deletion retains the COMMITTED journal for another finalization
# attempt. Reused helpers and any raw OSError are routed through the
# approved resume translation wrapper; no paths, payloads, or native
# exception text surface. Cascading dispatch and CLI wiring land in a later
# checkpoint; this function is private and unreachable from the CLI.


def _resume_finalize_committed(base: str, reconstructed: dict) -> dict:
    """Finalize a COMMITTED resume: receipt, lock, journal deletion.

    Re-reads the journal and requires the exact COMMITTED record: every
    field unchanged from the validated request journal except the stage
    (COMMITTED) and the re-derived self-hash. Revalidates the installed
    proposed manifest, the starting snapshot, and the committed event
    chain/head (expected identity/hash plus before/after manifest
    hashes). Reconciles the lock under the approved COMMITTED two-state
    rule — a matching journal token is released and verified absent, an
    already-absent lock is accepted, and a foreign or malformed lock
    fails closed without replacement or release. Finalizes the
    closed-schema recovery receipt from the resume context — the
    resuming reviewer identity and the resume reason, never the original
    reviewer and never claim_notes: an absent receipt is created
    immutably only after all COMMITTED evidence is valid; an existing
    receipt is verified against the COMMITTED evidence and never
    rewritten (its resumed_at_utc and interrupted_stage are accepted as
    recorded — a later attempt cannot recompute them; the read path
    validates their structure and the receipt self-hash). The receipt is
    verified after creation/existing-read. Deletes the journal last and
    verifies it absent. Any failure before deletion retains the
    COMMITTED journal for another finalization attempt.
    """
    from app.services import provenance as prov
    from app.services import review_integrity as ri

    plan = reconstructed["plan"]
    resume = reconstructed["resume"]
    journal = plan["journal"]

    # Exact COMMITTED journal: stage advanced, every other field frozen.
    current = _resume_read_transaction_journal(base)
    if current is None:
        raise ReviewError(
            "TRANSACTION_NOT_FOUND: transaction journal disappeared "
            "during resume"
        )
    _require_resume_stage(current, "COMMITTED")
    expected_unsigned = {
        key: value for key, value in journal.items() if key != "journal_hash"
    }
    expected_unsigned["transaction_stage"] = "COMMITTED"
    current_unsigned = {
        key: value for key, value in current.items() if key != "journal_hash"
    }
    if current_unsigned != expected_unsigned:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: COMMITTED journal fields differ from "
            "the validated request journal"
        )

    # Committed evidence revalidation (read-only).
    _resume_revalidate_active_proposed(base, plan)
    _resume_snapshot_starting_manifest(base, journal)
    head = _resume_expected_event(
        base, journal, ri.TRANSACTION_STAGES.index("COMMITTED")
    )

    # Approved COMMITTED two-state lock reconciliation.
    _resume_step_translated(
        "committed lock reconciliation",
        _reconcile_committed_lock,
        base,
        current,
    )

    def _read_receipt():
        try:
            return ri.read_recovery_receipt(
                base, transaction_id=journal["transaction_id"]
            )
        except ri.ReviewIntegrityError as exc:
            raise ReviewError(f"RECEIPT: {exc}") from exc

    receipt = _resume_step_translated("recovery receipt read", _read_receipt)
    if receipt is None:
        # Create immutably only after all COMMITTED evidence is valid.
        def _create_receipt():
            try:
                return ri.create_recovery_receipt(
                    base,
                    transaction_id=journal["transaction_id"],
                    interrupted_stage=resume["interrupted_stage"],
                    resuming_reviewer_id=resume["resuming_reviewer_id"],
                    resuming_reviewer_display_name=resume[
                        "resuming_reviewer_display_name"
                    ],
                    reason=resume["reason"],
                    resumed_at_utc=prov.utc_now_iso(),
                    resulting_manifest_hash=journal["proposed_manifest_hash"],
                    resulting_audit_chain_head=journal["expected_event_hash"],
                )
            except ri.ReviewIntegrityError as exc:
                raise ReviewError(f"RECEIPT: {exc}") from exc

        receipt = _resume_step_translated(
            "recovery receipt creation", _create_receipt
        )
        reread = _resume_step_translated(
            "recovery receipt read", _read_receipt
        )
        if reread != receipt:
            raise ReviewError(
                "TRANSACTION_AMBIGUOUS: recovery receipt changed after "
                "creation"
            )
    else:
        # The exact receipt exists: verify against the COMMITTED evidence
        # and never rewrite. resumed_at_utc and interrupted_stage are
        # accepted as recorded (validated structurally by the read path).
        expected_fields = {
            "transaction_id": journal["transaction_id"],
            "resuming_reviewer_id": resume["resuming_reviewer_id"],
            "resuming_reviewer_display_name": (
                resume["resuming_reviewer_display_name"]
            ),
            "reason": resume["reason"],
            "resulting_manifest_hash": journal["proposed_manifest_hash"],
            "resulting_audit_chain_head": journal["expected_event_hash"],
        }
        for field, expected in expected_fields.items():
            if receipt[field] != expected:
                raise ReviewError(
                    "TRANSACTION_AMBIGUOUS: existing recovery receipt "
                    "does not match the COMMITTED evidence"
                )

    # Delete the journal last; verify it is absent.
    def _delete_journal():
        try:
            ri.delete_transaction_journal(base)
        except ri.ReviewIntegrityError as exc:
            raise ReviewError(f"TRANSACTION_JOURNAL: {exc}") from exc

    _resume_step_translated("journal deletion", _delete_journal)
    remaining = _resume_read_transaction_journal(base)
    if remaining is not None:
        raise ReviewError(
            "TRANSACTION_AMBIGUOUS: transaction journal still present "
            "after deletion"
        )

    return {
        "operation": plan["operation"],
        "task_id": plan["task_id"],
        "claim_id": plan["claim_id"],
        "transaction_id": journal["transaction_id"],
        "reviewer_id": plan["reviewer_id"],
        "reviewer_display_name": plan["reviewer_display_name"],
        "review_timestamp_utc": plan["timestamp_utc"],
        "starting_manifest_hash": plan["starting_manifest_hash"],
        "proposed_manifest_hash": plan["proposed_manifest_hash"],
        "snapshot_relative_path": plan["snapshot_relative_path"],
        "event": head,
        "receipt": receipt,
    }


# ---------------------------------------------------------------------------
# Resume-transaction dispatcher (Slice 3 checkpoint F1, 2.8)
# ---------------------------------------------------------------------------
# Internal cascading resume orchestration. Loads and validates the resume
# request, freezes the receipt identity (the initially discovered
# interrupted stage, the resuming reviewer identity, and the reason), then
# iterates: reconstruct and revalidate the durable evidence for the
# current stage, dispatch exactly the current stage's adapter, reload the
# journal, and rebuild the stage-aware context after each successful
# advance. The cascade is strictly forward and monotone: a strict
# bounded-transition guard fails closed TRANSACTION_AMBIGUOUS on any
# no-advance, skip, reversal, unknown stage, or excess iteration, and the
# loop ends only when COMMITTED finalization removes the journal. The
# dispatcher never acquires or replaces a lock, and the resuming reviewer
# is never substituted into the original mutation or event. The sanitized
# completion summary is returned only after receipt verification and
# journal removal. CLI wiring lands in a later checkpoint; everything here
# is private and unreachable from the CLI.


_RESUME_STAGE_ADAPTERS = {
    "INITIATED": _resume_from_initiated,
    "LOCK_ACQUIRED": _resume_from_lock_acquired,
    "SNAPSHOT_CREATED": _resume_from_snapshot_created,
    "PROPOSED_MANIFEST_READY": _resume_from_proposed_manifest_ready,
    "EVENT_CREATED": _resume_from_event_created,
    "CHECKPOINT_UPDATED": _resume_from_checkpoint_updated,
    "MANIFEST_INSTALLED": _resume_from_manifest_installed,
    "COMMITTED": _resume_finalize_committed,
}


def _resume_claim_transaction(
    task_dir: str,
    *,
    transaction_id,
    reviewer_id,
    reviewer_display_name,
    reason,
) -> dict:
    """Cascade a validated resume to COMMITTED finalization (approved 2.8).

    Starts with _load_resume_request (approved validation order), freezes
    the initially discovered interrupted stage plus the resuming reviewer
    identity and reason for the receipt, then loops: reconstruct and
    revalidate the durable evidence for the current stage, dispatch
    exactly one adapter, reload the journal, and require the strictly
    forward one-stage advance. COMMITTED finalization must remove the
    journal; its sanitized completion summary is returned only after
    receipt verification and journal removal. Any no-advance, skip,
    reversal, unknown stage, or excess iteration fails closed
    TRANSACTION_AMBIGUOUS. Never acquires or replaces a lock.
    """
    from app.services import review_integrity as ri

    base = _resolve_task_dir(task_dir)
    request = _load_resume_request(
        base,
        transaction_id=transaction_id,
        reviewer_id=reviewer_id,
        reviewer_display_name=reviewer_display_name,
        reason=reason,
    )
    reconstructed = _reconstruct_resume_plan(base, request)
    # Freeze the receipt identity from the initially discovered state;
    # per-iteration reconstructions would otherwise drift the recorded
    # interrupted stage as the cascade advances.
    resume_context = dict(reconstructed["resume"])
    journal = request["journal"]
    stages = ri.TRANSACTION_STAGES

    for _iteration in range(len(stages)):
        stage = journal["transaction_stage"]
        adapter = _RESUME_STAGE_ADAPTERS.get(stage)
        if adapter is None:
            raise ReviewError(
                "TRANSACTION_AMBIGUOUS: no resume adapter for recorded "
                f"stage {stage!r}"
            )
        result = adapter(base, reconstructed)
        if stage == "COMMITTED":
            # Finalization verified the receipt and removed the journal;
            # re-verify removal before returning the summary.
            remaining = _resume_read_transaction_journal(base)
            if remaining is not None:
                raise ReviewError(
                    "TRANSACTION_AMBIGUOUS: transaction journal present "
                    "after COMMITTED finalization"
                )
            return result

        # Reload the journal; require the strictly forward one-stage
        # advance (bounded-transition guard).
        advanced = _resume_read_transaction_journal(base)
        if advanced is None:
            raise ReviewError(
                "TRANSACTION_NOT_FOUND: transaction journal disappeared "
                "during resume"
            )
        expected_next = stages[stages.index(stage) + 1]
        after_stage = advanced["transaction_stage"]
        if after_stage != expected_next:
            raise ReviewError(
                f"TRANSACTION_AMBIGUOUS: resume stage transition "
                f"{stage!r} -> {after_stage!r} is not the approved "
                f"one-stage advance to {expected_next!r}"
            )

        # Rebuild the stage-aware context for the next iteration; the
        # frozen receipt identity never drifts.
        journal = advanced
        try:
            manifest, _manifest_path, _manifest_sha = _load_manifest(base)
        except ReviewError as exc:
            raise ReviewError(f"MANIFEST_INVALID: {exc}") from exc
        reconstructed = _reconstruct_resume_plan(
            base, {**request, "journal": journal, "manifest": manifest}
        )
        reconstructed["resume"] = dict(resume_context)

    raise ReviewError(
        "TRANSACTION_AMBIGUOUS: resume cascade exceeded the bounded "
        "stage count"
    )


# ---------------------------------------------------------------------------
# status command
# ---------------------------------------------------------------------------


def cmd_status(args: argparse.Namespace) -> int:
    _require_pilot_policy()
    state = _assemble_state(args.task_dir)

    if "manifest_error" in state:
        print(f"error: {state['manifest_error']}", file=sys.stderr)
        return EXIT_FAILURE

    manifest = state["manifest"]
    task = manifest.get("task", {})
    effective, eff_reasons = _effective_status(state)
    readiness, ready_reasons = _approval_readiness(state, effective)

    # Any integrity failure, or an INVALID effective status (contradiction,
    # missing required receipt, mismatched hash), is a hard failure => exit 1.
    # A valid NEEDS_HUMAN_REVIEW draft that is merely BLOCKED exits 0.
    integrity_failures = state.get("failures", [])
    hard_failure = bool(integrity_failures) or effective == "INVALID"

    print("BrainTrustCrypto pilot review — status")
    print(f"  task_id:              {task.get('task_id')}")
    print(f"  schema_version:       {state.get('schema_version')}")
    print(f"  manifest status:      {task.get('review_status')}")
    print(f"  effective status:     {effective}")
    print(f"  manifest sha256:      {state.get('manifest_sha256')}")
    print(f"  script hash:          {state.get('script_status')}")
    asset_statuses = state.get("asset_statuses", [])
    if asset_statuses:
        summary = ",".join(sorted(set(asset_statuses)))
        print(f"  asset hashes:         {summary} ({len(asset_statuses)} asset(s))")
    else:
        print("  asset hashes:         none")
    print(f"  output hash:          {state.get('output_status')}")

    counts = state.get("claim_counts", {})
    print(f"  claims:               UNVERIFIED={counts.get('UNVERIFIED', 0)} "
          f"VERIFIED={counts.get('VERIFIED', 0)} "
          f"RETRACTED={counts.get('RETRACTED', 0)}")

    incomplete = state.get("incomplete_assets", [])
    print(f"  asset provenance:     "
          f"{'incomplete (' + str(len(incomplete)) + ')' if incomplete else 'complete'}")

    event_count = state.get("event_count")
    print(f"  review events:        "
          f"{event_count if event_count is not None else 'chain-error'}")
    print(f"  event checkpoint:     "
          f"{'ok' if state.get('event_chain_valid') else 'INVALID'}")

    receipt_count = state.get("receipt_count")
    print(f"  receipts:             "
          f"{receipt_count if receipt_count is not None else 'chain-error'}")
    print(f"  receipt checkpoint:   "
          f"{'ok' if state.get('receipt_chain_valid') else 'INVALID'}")

    audit_valid = state.get("event_chain_valid") and state.get("receipt_chain_valid")
    print(f"  audit-chain validity: {'valid' if audit_valid else 'INVALID'}")

    lock_held = state.get("lock_held")
    if lock_held is None:
        print("  lock status:          error (malformed lock)")
    elif lock_held:
        print(f"  lock status:          held by {state.get('lock_holder')}")
    else:
        print("  lock status:          free")

    print(f"  approval readiness:   {readiness}")
    for reason in ready_reasons:
        print(f"    - {_truncate(reason)}")

    # Transaction journal status (read-only). Prints only the sanitized
    # transaction id and a validated known stage — never the operation,
    # claim ids, reasons, tokens, parser details, or other journal data.
    from app.services import review_integrity as ri

    journal = state.get("transaction_journal")
    journal_error = state.get("transaction_journal_error")
    if journal is None and journal_error is None:
        print("  transaction status: none")
    else:
        transaction_id = "invalid"
        transaction_stage = "invalid"
        if journal is not None:
            candidate_id = journal.get("transaction_id")
            if isinstance(candidate_id, str) and re.fullmatch(
                r"[0-9a-f]{32}", candidate_id
            ):
                transaction_id = candidate_id
            candidate_stage = journal.get("transaction_stage")
            if candidate_stage in ri.TRANSACTION_STAGES:
                transaction_stage = candidate_stage
        print("  transaction status: INCOMPLETE_TRANSACTION")
        print(f"  transaction id: {transaction_id}")
        print(f"  transaction stage: {transaction_stage}")

    if hard_failure:
        return EXIT_FAILURE
    return EXIT_OK


# ---------------------------------------------------------------------------
# audit command
# ---------------------------------------------------------------------------


def cmd_audit(args: argparse.Namespace) -> int:
    _require_pilot_policy()
    state = _assemble_state(args.task_dir)

    reason_codes: list[str] = []

    if "manifest_error" in state:
        reason_codes.append("MANIFEST_INVALID")
    else:
        # Map internal failures to concise sanitized reason codes.
        for failure in state.get("failures", []):
            category = failure.split(":", 1)[0]
            code = {
                "script": "SCRIPT_HASH",
                "asset": "ASSET_INTEGRITY",
                "output": "OUTPUT_HASH",
                "event-chain": "EVENT_CHAIN",
                "receipt-chain": "RECEIPT_CHAIN",
                "review-events": "UNCOMMITTED_TAIL",
                "approvals": "UNCOMMITTED_TAIL",
                "lock": "LOCK_STATE",
                "partial-files-present": "PARTIAL_FILES",
                "INCOMPLETE_TRANSACTION": "INCOMPLETE_TRANSACTION",
            }.get(category, category.upper().replace("-", "_"))
            if code not in reason_codes:
                reason_codes.append(code)

        effective, _ = _effective_status(state)
        if effective == "INVALID" and not state.get("failures"):
            reason_codes.append("APPROVAL_STATE")

    passed = not reason_codes
    print("BrainTrustCrypto pilot review — audit")
    print(f"  task_id:    "
          f"{state.get('manifest', {}).get('task', {}).get('task_id', '<unknown>')}")
    print(f"  result:     {'PASS' if passed else 'FAIL'}")
    if reason_codes:
        print(f"  reasons:    {', '.join(sorted(set(reason_codes)))}")

    return EXIT_OK if passed else EXIT_FAILURE


# ---------------------------------------------------------------------------
# verify-claim command (mutating; approved crash-safe transaction)
# ---------------------------------------------------------------------------


def cmd_verify_claim(args: argparse.Namespace) -> int:
    _require_pilot_policy()
    result = _run_claim_transaction(
        args.task_dir,
        operation="verify-claim",
        claim_id=args.claim_id,
        reviewer_id=args.reviewer_id,
        reviewer_display_name=args.reviewer_display_name,
        notes=args.notes,
    )
    manifest, _manifest_path, _manifest_sha = _load_manifest(args.task_dir)
    event = result["event"]
    print("BrainTrustCrypto pilot review — verify-claim")
    print(f"  task_id:              {result['task_id']}")
    print(f"  claim_id:             {result['claim_id']}")
    print(f"  operation:            {result['operation']}")
    print("  result:               SUCCESS")
    print(f"  manifest sha256:      {result['proposed_manifest_hash']}")
    print(f"  event sequence:       {event['sequence']}")
    print(f"  event hash:           {event['event_hash']}")
    print(f"  snapshot:             {result['snapshot_relative_path']}")
    print(f"  status:               {manifest.get('task', {}).get('review_status')}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# retract-claim command (mutating; approved crash-safe transaction)
# ---------------------------------------------------------------------------


def cmd_retract_claim(args: argparse.Namespace) -> int:
    _require_pilot_policy()
    result = _run_claim_transaction(
        args.task_dir,
        operation="retract-claim",
        claim_id=args.claim_id,
        reviewer_id=args.reviewer_id,
        reviewer_display_name=args.reviewer_display_name,
        reason=args.reason,
    )
    manifest, _manifest_path, _manifest_sha = _load_manifest(args.task_dir)
    event = result["event"]
    print("BrainTrustCrypto pilot review — retract-claim")
    print(f"  task_id:              {result['task_id']}")
    print(f"  claim_id:             {result['claim_id']}")
    print(f"  operation:            {result['operation']}")
    print("  result:               SUCCESS")
    print(f"  manifest sha256:      {result['proposed_manifest_hash']}")
    print(f"  event sequence:       {event['sequence']}")
    print(f"  event hash:           {event['event_hash']}")
    print(f"  snapshot:             {result['snapshot_relative_path']}")
    print(f"  status:               {manifest.get('task', {}).get('review_status')}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# resume-transaction command (mutating; approved forward-only resume)
# ---------------------------------------------------------------------------


def cmd_resume_transaction(args: argparse.Namespace) -> int:
    # No handler-level policy call: the single approved policy gate lives
    # inside _load_resume_request (approved Section 2.8 validation order).
    result = _resume_claim_transaction(
        args.task_dir,
        transaction_id=args.transaction_id,
        reviewer_id=args.reviewer_id,
        reviewer_display_name=args.reviewer_display_name,
        reason=args.reason,
    )
    manifest, _manifest_path, _manifest_sha = _load_manifest(args.task_dir)
    event = result["event"]
    print("BrainTrustCrypto pilot review — resume-transaction")
    print(f"  task_id:              {result['task_id']}")
    print(f"  claim_id:             {result['claim_id']}")
    print(f"  transaction_id:       {result['transaction_id']}")
    print(f"  operation:            {result['operation']}")
    print("  result:               RESUMED")
    print(f"  manifest sha256:      {result['proposed_manifest_hash']}")
    print(f"  event sequence:       {event['sequence']}")
    print(f"  event hash:           {event['event_hash']}")
    print(f"  snapshot:             {result['snapshot_relative_path']}")
    print(f"  status:               {manifest.get('task', {}).get('review_status')}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pilot_review",
        description=(
            "BrainTrustCrypto pilot review. Commands: status, audit "
            "(read-only); verify-claim, retract-claim, resume-transaction "
            "(mutating claim transactions)."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)
    for name, helptext in (
        ("status", "read-only snapshot of review state"),
        ("audit", "read-only integrity validation (PASS/FAIL)"),
    ):
        cmd = sub.add_parser(name, help=helptext)
        cmd.add_argument(
            "--task-dir",
            required=True,
            help="designated task directory (read-only)",
        )
    verify = sub.add_parser(
        "verify-claim",
        help="verify one factual claim (mutating crash-safe transaction)",
    )
    verify.add_argument(
        "--task-dir",
        required=True,
        help="designated task directory",
    )
    verify.add_argument(
        "--claim-id",
        required=True,
        help="claim identifier matching claim-[0-9a-f]{32}",
    )
    verify.add_argument(
        "--reviewer-id",
        required=True,
        help="reviewer identity id",
    )
    verify.add_argument(
        "--reviewer-display-name",
        required=True,
        help="reviewer display name",
    )
    verify.add_argument(
        "--notes",
        default=None,
        help="optional review notes (sanitized for secrets)",
    )
    retract = sub.add_parser(
        "retract-claim",
        help="retract one factual claim (mutating crash-safe transaction)",
    )
    retract.add_argument(
        "--task-dir",
        required=True,
        help="designated task directory",
    )
    retract.add_argument(
        "--claim-id",
        required=True,
        help="claim identifier matching claim-[0-9a-f]{32}",
    )
    retract.add_argument(
        "--reviewer-id",
        required=True,
        help="reviewer identity id",
    )
    retract.add_argument(
        "--reviewer-display-name",
        required=True,
        help="reviewer display name",
    )
    retract.add_argument(
        "--reason",
        required=True,
        help="non-empty explanatory retraction reason (sanitized for secrets)",
    )
    resume = sub.add_parser(
        "resume-transaction",
        help="resume an interrupted claim transaction (mutating, "
        "forward-only to COMMITTED finalization)",
    )
    resume.add_argument(
        "--task-dir",
        required=True,
        help="designated task directory",
    )
    resume.add_argument(
        "--transaction-id",
        required=True,
        help="transaction identifier (uuid4 hex, 32 lowercase hex)",
    )
    resume.add_argument(
        "--reviewer-id",
        required=True,
        help="resuming reviewer identity id",
    )
    resume.add_argument(
        "--reviewer-display-name",
        required=True,
        help="resuming reviewer display name",
    )
    resume.add_argument(
        "--reason",
        required=True,
        help="non-empty explanatory resume reason (sanitized for secrets)",
    )
    return parser


_COMMANDS = {
    "status": cmd_status,
    "audit": cmd_audit,
    "verify-claim": cmd_verify_claim,
    "retract-claim": cmd_retract_claim,
    "resume-transaction": cmd_resume_transaction,
}


def run(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    handler = _COMMANDS.get(args.command)
    if handler is None:
        parser.error(f"unknown command: {args.command}")
        return EXIT_USAGE  # unreachable
    try:
        return handler(args)
    except ReviewError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    except OSError:
        print("error: filesystem failure", file=sys.stderr)
        return EXIT_FAILURE


if __name__ == "__main__":
    raise SystemExit(run())
