"""
Phase 1B.3C.2B.2C — BrainTrustCrypto pilot review CLI.

Standalone, offline review entry point for BrainTrustCrypto pilot tasks.
Exposes exactly four commands:

    status        — concise, sanitized snapshot of a task's review state
    audit         — read-only integrity validation (PASS/FAIL + reason codes)
    verify-claim  — verify one factual claim through the approved crash-safe
                    claim-mutation transaction
    retract-claim — retract one factual claim (with an explicit reason)
                    through the same crash-safe claim-mutation transaction

status and audit NEVER mutate the task directory. They do not create,
modify, move, delete, recover, or rewrite any file, and they leave the
task directory byte-for-byte unchanged.

verify-claim and retract-claim are the only mutating commands. They
mutate only through the approved 17-step journaled transaction:
claim_id-only preconditions, exclusive lock, in-memory proposed manifest,
frozen event planning, durable journal, immutable snapshot,
byte-identical proposed manifest, planned event, checkpoint advance,
atomic install, COMMITTED verification, matching-token lock release, and
journal removal last. They are non-interactive (no confirmation prompts),
forward-only, and fail-closed: an interruption leaves explicit journaled
state for resume-transaction, never unjournaled committed state.

Other mutating review operations (resume-transaction, approve, reject,
revoke, supersede, recover-lock, tail-recovery) are NOT exposed here yet
and arrive with their own approved checkpoints.

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
  created or changed. verify-claim and retract-claim mutate only through
  the approved journaled transaction above.
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
    base = os.path.realpath(os.path.expanduser(task_dir.strip()))
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
            token, the exact manifest hashes, and the planned event
            identity/hash.

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
        try:
            journal = ri.create_transaction_journal(
                base,
                operation=operation,
                task_id=manifest.get("task", {}).get("task_id"),
                claim_id=claim_id,
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
        raise ReviewError(f"TRANSACTION_JOURNAL: {exc}") from exc
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
        raise ReviewError(f"LOCK_HELD: {exc}") from exc
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
        raise ReviewError(f"TRANSACTION_JOURNAL: {exc}") from exc


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
        raise ReviewError(f"SNAPSHOT: {exc}") from exc
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
        raise ReviewError(f"EVENT_CHAIN: {exc}") from exc
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
        raise ReviewError(f"TRANSACTION_JOURNAL: {exc}") from exc
    if current is None:
        raise ReviewError("TRANSACTION_JOURNAL: journal removed before COMMITTED")
    if current != journal:
        raise ReviewError(
            "STATE_DRIFT: transaction journal changed before COMMITTED"
        )
    try:
        held_lock = ri.read_review_lock(base)
    except ri.ReviewIntegrityError as exc:
        raise ReviewError(f"LOCK_HELD: {exc}") from exc
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
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pilot_review",
        description=(
            "BrainTrustCrypto pilot review. Commands: status, audit "
            "(read-only); verify-claim, retract-claim (mutating claim "
            "transactions)."
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
    return parser


_COMMANDS = {
    "status": cmd_status,
    "audit": cmd_audit,
    "verify-claim": cmd_verify_claim,
    "retract-claim": cmd_retract_claim,
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
    except OSError as exc:
        print(f"error: filesystem failure: {exc}", file=sys.stderr)
        return EXIT_FAILURE


if __name__ == "__main__":
    raise SystemExit(run())
