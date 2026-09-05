"""
Phase 1B.3C.2A — Offline review-integrity primitives.

Standalone, offline primitives for the BrainTrustCrypto pilot review
lifecycle:

- manifest-history/   immutable manifest snapshots
- review-events/      sequential, hash-chained audit events
- approvals/          sequential, hash-chained approval/revocation receipts
- review lock         task-local exclusive lock with token-verified release

This module is intentionally NOT integrated with pilot_prepare.py, the CLI,
rendering, providers, or publishing. It only creates and validates files
confined to a designated task directory.

Security properties:
- Standard library only; zero network access.
- All paths are confined to the task directory (traversal, unsafe absolute
  paths, symlink escapes, and junction escapes are rejected where testable).
- Event, receipt, and history files are immutable: they are created
  exclusively and never overwritten.
- Creation is atomic: same-directory temporary file, flush + fsync, then
  os.replace() to a name that must not already exist.
- Canonical JSON (see provenance.canonical_json_bytes) is used for every
  hash. Floating-point values are rejected in hashed structures.
- Hash chains fail closed on any defect: missing, reordered, duplicated,
  malformed, or modified entries are all detected.
- The review lock fails closed: an existing, malformed, or unreadable lock
  blocks acquisition; age alone is never treated as abandonment.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import tempfile
import uuid

from app.services import provenance as prov


SCHEMA_VERSION = "1.2.0"

# ---------------------------------------------------------------------------
# Directory names (confined to the task directory)
# ---------------------------------------------------------------------------

MANIFEST_HISTORY_DIR = "manifest-history"
REVIEW_EVENTS_DIR = "review-events"
APPROVALS_DIR = "approvals"
REVIEW_LOCK_NAME = "review.lock"

# Chain-head checkpoint filenames (one per chain, inside the chain's dir).
EVENTS_CHECKPOINT_NAME = "chain-head.json"
RECEIPTS_CHECKPOINT_NAME = "chain-head.json"

CHAIN_TYPE_REVIEW_EVENTS = "review-events"
CHAIN_TYPE_APPROVALS = "approvals"

# ---------------------------------------------------------------------------
# Chain-head checkpoints
# ---------------------------------------------------------------------------
# A checkpoint is an atomically maintained index of the current chain head.
# It is NOT an immutable review event: it is replaced (atomically) on every
# committed append. It lets validation detect deletion/truncation of the
# chain tail, which a pure sequence scan cannot see.
#
# Empty-chain rule: an empty chain has NO checkpoint file. The presence of
# any record without a checkpoint, or a checkpoint without its referenced
# final record, fails closed.
#
# Security limitation: checkpoints detect accidental deletion, truncation,
# corruption, and ordinary manual modification. Without digital signatures
# or an external trusted anchor, a fully capable local attacker could roll
# back both the chain and its checkpoint together. Digital signatures and
# external anchoring are deferred; no cryptographic tamper-proofing is
# claimed here.


def _checkpoint_path(directory: str) -> str:
    return os.path.join(directory, EVENTS_CHECKPOINT_NAME)


def _checkpoint_unsigned_fields(checkpoint: dict) -> dict:
    return {k: v for k, v in checkpoint.items() if k != "checkpoint_hash"}


def _write_checkpoint_atomic(directory: str, checkpoint: dict) -> None:
    """Atomically replace the chain-head checkpoint (temp + fsync + rename)."""
    payload = _canonical_bytes(checkpoint) + b"\n"
    path = _checkpoint_path(directory)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", suffix=".part", dir=directory)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _build_checkpoint(
    *, chain_type: str, sequence: int, record_id: str, record_hash: str
) -> dict:
    checkpoint = {
        "schema_version": SCHEMA_VERSION,
        "chain_type": chain_type,
        "last_sequence": sequence,
        "last_record_id": record_id,
        "last_record_hash": record_hash,
    }
    checkpoint["checkpoint_hash"] = _canonical_hash(
        _checkpoint_unsigned_fields(checkpoint)
    )
    return checkpoint


def _read_checkpoint(directory: str) -> dict | None:
    path = _checkpoint_path(directory)
    if not os.path.exists(path):
        return None
    return _read_json_file(path, "chain-head checkpoint")


def _validate_checkpoint(
    directory: str,
    chain_type: str,
    entries: list[tuple[int, str]],
    records: list[dict],
    id_field: str,
    hash_field: str,
) -> None:
    """Fail closed on any checkpoint/chain disagreement.

    Detects: missing checkpoint on a nonempty chain, malformed checkpoint,
    invalid checkpoint hash, missing final record, final-record hash
    mismatch, records beyond the checkpoint, and sequence disagreement.
    """
    checkpoint = _read_checkpoint(directory)
    if not entries:
        # Empty chain: no checkpoint is the only valid state.
        if checkpoint is not None:
            raise ReviewIntegrityError(
                f"{chain_type} checkpoint exists but the chain is empty"
            )
        return
    if checkpoint is None:
        raise ReviewIntegrityError(
            f"{chain_type} chain is nonempty but the chain-head checkpoint "
            "is missing"
        )

    for field in ("schema_version", "chain_type", "last_sequence",
                  "last_record_id", "last_record_hash", "checkpoint_hash"):
        if field not in checkpoint:
            raise ReviewIntegrityError(
                f"{chain_type} checkpoint missing field: {field}"
            )
    if checkpoint["schema_version"] != SCHEMA_VERSION:
        raise ReviewIntegrityError(
            f"{chain_type} checkpoint has unsupported schema_version: "
            f"{checkpoint['schema_version']!r}"
        )
    if checkpoint["chain_type"] != chain_type:
        raise ReviewIntegrityError(
            f"{chain_type} checkpoint chain_type mismatch: "
            f"{checkpoint['chain_type']!r}"
        )
    recomputed = _canonical_hash(_checkpoint_unsigned_fields(checkpoint))
    if recomputed != checkpoint["checkpoint_hash"]:
        raise ReviewIntegrityError(
            f"{chain_type} checkpoint modified: checkpoint_hash mismatch"
        )

    last_seq, last_name = entries[-1]
    last_record = records[-1]
    if checkpoint["last_sequence"] != last_seq:
        raise ReviewIntegrityError(
            f"{chain_type} checkpoint sequence {checkpoint['last_sequence']} "
            f"disagrees with records (last sequence {last_seq})"
        )
    if checkpoint["last_record_id"] != last_record[id_field]:
        raise ReviewIntegrityError(
            f"{chain_type} checkpoint last_record_id does not match the "
            "final record"
        )
    if checkpoint["last_record_hash"] != last_record[hash_field]:
        raise ReviewIntegrityError(
            f"{chain_type} checkpoint last_record_hash does not match the "
            "final record"
        )

# Transaction journal (schema 1.2.0)
# ---------------------------------------------------------------------------

TRANSACTION_JOURNAL_NAME = "review-transaction.json"

# Approved eight-stage forward-only sequence (order matters).
TRANSACTION_STAGES = (
    "INITIATED",
    "LOCK_ACQUIRED",
    "SNAPSHOT_CREATED",
    "PROPOSED_MANIFEST_READY",
    "EVENT_CREATED",
    "CHECKPOINT_UPDATED",
    "MANIFEST_INSTALLED",
    "COMMITTED",
)

TRANSACTION_OPERATIONS = frozenset({"verify-claim", "retract-claim"})

# Required journal fields, in the approved schema order. Unknown fields are
# rejected; journal_hash is the canonical self-hash over every other field.
_JOURNAL_REQUIRED_FIELDS = (
    "schema_version",
    "transaction_id",
    "operation",
    "task_id",
    "claim_id",
    "starting_manifest_hash",
    "proposed_manifest_hash",
    "proposed_manifest_relative_path",
    "snapshot_relative_path",
    "expected_event_id",
    "expected_event_hash",
    "lock_token",
    "transaction_stage",
    "created_at_utc",
    "original_reviewer_id",
    "original_reviewer_display_name",
    "journal_hash",
)

# Immutable fields that must never change after journal creation. Only
# transaction_stage (and the derived journal_hash) may change, and only
# through the update primitive.
_JOURNAL_IMMUTABLE_FIELDS = frozenset(
    {
        "schema_version",
        "transaction_id",
        "operation",
        "task_id",
        "claim_id",
        "starting_manifest_hash",
        "proposed_manifest_hash",
        "proposed_manifest_relative_path",
        "snapshot_relative_path",
        "expected_event_id",
        "expected_event_hash",
        "lock_token",
        "created_at_utc",
        "original_reviewer_id",
        "original_reviewer_display_name",
    }
)


def _journal_path(task_dir: str) -> str:
    """Resolve the transaction journal path, confined to the task directory."""
    base = _resolve_task_dir(task_dir)
    path = os.path.realpath(os.path.join(base, TRANSACTION_JOURNAL_NAME))
    if os.path.commonpath([base, path]) != base:
        raise ReviewIntegrityError("unsafe transaction-journal path")
    return path


def _journal_unsigned_fields(journal: dict) -> dict:
    """Return the journal fields covered by journal_hash (everything but it)."""
    return {k: v for k, v in journal.items() if k != "journal_hash"}


def _validate_journal_relative_path(base: str, value, field: str) -> None:
    """Require a task-confined relative path.

    Absolute paths, parent traversal, and resolved paths escaping the task
    directory are rejected.
    """
    if not isinstance(value, str) or not value.strip():
        raise ReviewIntegrityError(
            f"transaction journal {field} must be a non-empty relative path"
        )
    if os.path.isabs(value):
        raise ReviewIntegrityError(
            f"transaction journal {field} must be relative, not absolute"
        )
    resolved = os.path.realpath(os.path.join(base, value))
    try:
        common = os.path.commonpath([base, resolved])
    except ValueError as exc:  # different drives on Windows
        raise ReviewIntegrityError(
            f"transaction journal {field} escapes the task directory"
        ) from exc
    if common != base:
        raise ReviewIntegrityError(
            f"transaction journal {field} escapes the task directory"
        )


def _validate_journal_structure(journal: dict, base: str) -> None:
    """Validate journal fields, stage, paths, and hash. Fails closed on any defect."""
    for field in _JOURNAL_REQUIRED_FIELDS:
        if field not in journal:
            raise ReviewIntegrityError(
                f"transaction journal missing field: {field}"
            )
    unknown = set(journal) - set(_JOURNAL_REQUIRED_FIELDS)
    if unknown:
        raise ReviewIntegrityError(
            f"transaction journal has unknown field(s): {sorted(unknown)!r}"
        )
    if journal["schema_version"] != SCHEMA_VERSION:
        raise ReviewIntegrityError(
            f"transaction journal has unsupported schema_version: "
            f"{journal['schema_version']!r}"
        )
    if journal["operation"] not in TRANSACTION_OPERATIONS:
        raise ReviewIntegrityError(
            f"transaction journal has unknown operation: "
            f"{journal['operation']!r}"
        )
    if journal["transaction_stage"] not in TRANSACTION_STAGES:
        raise ReviewIntegrityError(
            f"transaction journal has unknown stage: "
            f"{journal['transaction_stage']!r}"
        )
    if not isinstance(journal["task_id"], str) or not journal["task_id"].strip():
        raise ReviewIntegrityError(
            "transaction journal task_id must be a non-empty string"
        )
    _validate_reviewer(
        journal["original_reviewer_id"], journal["original_reviewer_display_name"]
    )
    _validate_timestamp(journal["created_at_utc"], "journal.created_at_utc")
    for field in ("starting_manifest_hash", "proposed_manifest_hash",
                  "expected_event_hash"):
        value = journal[field]
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ReviewIntegrityError(
                f"transaction journal {field} must be a SHA-256 hex digest"
            )
    for field in ("transaction_id", "lock_token", "expected_event_id"):
        value = journal[field]
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value):
            raise ReviewIntegrityError(
                f"transaction journal {field} must be a 32-char hex string"
            )
    prov.validate_claim_id(journal["claim_id"], "journal.claim_id")
    _validate_journal_relative_path(
        base, journal["proposed_manifest_relative_path"],
        "proposed_manifest_relative_path",
    )
    _validate_journal_relative_path(
        base, journal["snapshot_relative_path"], "snapshot_relative_path"
    )
    # Verify journal hash.
    recomputed = _canonical_hash(_journal_unsigned_fields(journal))
    if recomputed != journal["journal_hash"]:
        raise ReviewIntegrityError(
            "transaction journal modified: journal_hash mismatch"
        )


def create_transaction_journal(
    task_dir: str,
    *,
    operation: str,
    task_id: str,
    claim_id: str,
    starting_manifest_hash: str,
    proposed_manifest_hash: str,
    proposed_manifest_relative_path: str,
    snapshot_relative_path: str,
    expected_event_id: str,
    expected_event_hash: str,
    lock_token: str,
    created_at_utc: str,
    original_reviewer_id: str,
    original_reviewer_display_name: str,
) -> dict:
    """Create a new transaction journal atomically at INITIATED.

    Fails closed if a journal already exists (overwrite conflict) or any
    field fails validation. Returns the created journal record.
    """
    if operation not in TRANSACTION_OPERATIONS:
        raise ReviewIntegrityError(f"unknown operation: {operation!r}")
    if not isinstance(task_id, str) or not task_id.strip():
        raise ReviewIntegrityError("task_id must be a non-empty string")
    _validate_reviewer(original_reviewer_id, original_reviewer_display_name)
    _validate_timestamp(created_at_utc, "journal.created_at_utc")
    for field_name, value in (
        ("starting_manifest_hash", starting_manifest_hash),
        ("proposed_manifest_hash", proposed_manifest_hash),
        ("expected_event_hash", expected_event_hash),
    ):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ReviewIntegrityError(
                f"{field_name} must be a SHA-256 hex digest"
            )
    if not isinstance(lock_token, str) or not re.fullmatch(r"[0-9a-f]{32}", lock_token):
        raise ReviewIntegrityError(
            "lock_token must be a 32-char hex string"
        )
    if not isinstance(expected_event_id, str) or not re.fullmatch(
        r"[0-9a-f]{32}", expected_event_id
    ):
        raise ReviewIntegrityError(
            "expected_event_id must be a 32-char hex string"
        )
    prov.validate_claim_id(claim_id, "journal.claim_id")

    path = _journal_path(task_dir)
    base = os.path.dirname(path)
    _validate_journal_relative_path(
        base, proposed_manifest_relative_path, "proposed_manifest_relative_path"
    )
    _validate_journal_relative_path(
        base, snapshot_relative_path, "snapshot_relative_path"
    )

    if os.path.exists(path):
        raise ReviewIntegrityError(
            f"transaction journal already exists: {TRANSACTION_JOURNAL_NAME!r}"
        )

    journal = {
        "schema_version": SCHEMA_VERSION,
        "transaction_id": uuid.uuid4().hex,
        "operation": operation,
        "task_id": task_id,
        "claim_id": claim_id,
        "starting_manifest_hash": starting_manifest_hash,
        "proposed_manifest_hash": proposed_manifest_hash,
        "proposed_manifest_relative_path": proposed_manifest_relative_path,
        "snapshot_relative_path": snapshot_relative_path,
        "expected_event_id": expected_event_id,
        "expected_event_hash": expected_event_hash,
        "lock_token": lock_token,
        "transaction_stage": "INITIATED",
        "created_at_utc": created_at_utc,
        "original_reviewer_id": original_reviewer_id,
        "original_reviewer_display_name": original_reviewer_display_name,
    }
    journal["journal_hash"] = _canonical_hash(_journal_unsigned_fields(journal))

    _atomic_create_exclusive(path, _canonical_bytes(journal) + b"\n")
    return journal


def read_transaction_journal(task_dir: str) -> dict | None:
    """Read and validate the transaction journal, or None if absent.

    A malformed journal raises ReviewIntegrityError (fail closed).
    """
    path = _journal_path(task_dir)
    if not os.path.exists(path):
        return None
    journal = _read_json_file(path, "transaction journal")
    _validate_journal_structure(journal, os.path.dirname(path))
    return journal


def update_transaction_stage(
    task_dir: str,
    *,
    transaction_id: str,
    new_stage: str,
) -> dict:
    """Update the transaction stage atomically.

    Fails closed if:
    - No journal exists
    - transaction_id does not match
    - new_stage is not the immediately following stage
    - Any immutable field would change

    Returns the updated journal record.
    """
    if new_stage not in TRANSACTION_STAGES:
        raise ReviewIntegrityError(f"unknown transaction stage: {new_stage!r}")
    if not re.fullmatch(r"[0-9a-f]{32}", transaction_id or ""):
        raise ReviewIntegrityError(
            "transaction_id must be a 32-char hex string"
        )

    journal = read_transaction_journal(task_dir)
    if journal is None:
        raise ReviewIntegrityError("no transaction journal to update")
    if journal["transaction_id"] != transaction_id:
        raise ReviewIntegrityError(
            f"transaction_id mismatch: expected {journal['transaction_id']!r}, "
            f"got {transaction_id!r}"
        )

    # Validate strictly-forward transition: only the immediately following
    # stage is permitted. Skips, repeats, and reversals fail closed.
    stage_order = TRANSACTION_STAGES
    current_idx = stage_order.index(journal["transaction_stage"])
    new_idx = stage_order.index(new_stage)
    if new_idx != current_idx + 1:
        raise ReviewIntegrityError(
            f"invalid stage transition: {journal['transaction_stage']} -> {new_stage} "
            "(only the immediately following stage is allowed)"
        )

    # Build updated journal with only the stage changed.
    updated = dict(journal)
    updated["transaction_stage"] = new_stage
    updated["journal_hash"] = _canonical_hash(_journal_unsigned_fields(updated))

    # Verify no immutable fields changed.
    for field in _JOURNAL_IMMUTABLE_FIELDS:
        if updated[field] != journal[field]:
            raise ReviewIntegrityError(
                f"immutable journal field changed: {field}"
            )

    path = _journal_path(task_dir)
    payload = _canonical_bytes(updated) + b"\n"
    fd, tmp_path = tempfile.mkstemp(
        prefix=".review-transaction.json.", suffix=".tmp", dir=os.path.dirname(path)
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return updated


def delete_transaction_journal(task_dir: str) -> None:
    """Delete the transaction journal. Fails closed if no journal exists."""
    path = _journal_path(task_dir)
    if not os.path.exists(path):
        raise ReviewIntegrityError("no transaction journal to delete")
    try:
        os.unlink(path)
    except OSError as exc:
        raise ReviewIntegrityError(
            f"failed to delete transaction journal"
        ) from exc


# ---------------------------------------------------------------------------
# Event types (closed set)
# ---------------------------------------------------------------------------

EVENT_TYPES = frozenset(
    {
        "CLAIM_VERIFIED",
        "CLAIM_RETRACTED",
        "CLAIM_SUPERSEDED",
        "MANIFEST_SNAPSHOT",
        "LOCK_ACQUIRED",
        "LOCK_RELEASED",
        "LOCK_RECOVERED",
    }
)

# Event types that require a reason.
_EVENT_REASON_REQUIRED = frozenset(
    {"CLAIM_RETRACTED", "CLAIM_SUPERSEDED", "LOCK_RECOVERED"}
)

RECEIPT_TYPES = frozenset({"APPROVAL", "REVOCATION"})

_GENESIS_HASH = "0" * 64  # previous hash for sequence 1 entries


class ReviewIntegrityError(prov.ProvenanceError):
    """Raised for any review-integrity validation, chain, or lock failure."""


# ---------------------------------------------------------------------------
# Path confinement helpers
# ---------------------------------------------------------------------------


def _resolve_task_dir(task_dir: str) -> str:
    if not isinstance(task_dir, str) or not task_dir:
        raise ReviewIntegrityError("task_dir must be a non-empty string")
    base = os.path.realpath(task_dir)
    if not os.path.isdir(base):
        raise ReviewIntegrityError(f"task directory does not exist: {task_dir!r}")
    return base


def _sub_dir(task_dir: str, name: str, *, create: bool = True) -> str:
    """Resolve (and optionally create) a named subdirectory of the task dir."""
    base = _resolve_task_dir(task_dir)
    path = os.path.realpath(os.path.join(base, name))
    if os.path.commonpath([base, path]) != base:
        raise ReviewIntegrityError(f"unsafe subdirectory path: {name!r}")
    if create:
        os.makedirs(path, exist_ok=True)
    return path


def _confined_file_path(task_dir: str, subdir: str, filename: str) -> str:
    """Resolve a file path inside a task subdirectory, rejecting escapes."""
    base = _resolve_task_dir(task_dir)
    directory = _sub_dir(base, subdir)
    if not filename or os.path.basename(filename) != filename:
        raise ReviewIntegrityError(f"unsafe filename: {filename!r}")
    path = os.path.realpath(os.path.join(directory, filename))
    if os.path.commonpath([base, path]) != base:
        raise ReviewIntegrityError(f"path escapes the task directory: {filename!r}")
    return path


# ---------------------------------------------------------------------------
# Atomic, never-overwrite file creation
# ---------------------------------------------------------------------------


def _atomic_create_exclusive(path: str, payload: bytes) -> None:
    """Create a file atomically, failing if it already exists.

    Writes to a same-directory temporary file, flushes and fsyncs, then
    uses os.link() as an atomic create-exclusive primitive (hard link from
    temp to target fails if target exists), followed by removing the temp
    name. On filesystems without hard-link support, falls back to
    os.open(..., O_CREAT | O_EXCL) for the final step.
    """
    directory = os.path.dirname(path)
    fd, tmp_path = tempfile.mkstemp(
        prefix=".tmp-", suffix=".part", dir=directory
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if os.path.exists(path):
            raise ReviewIntegrityError(
                f"refusing to overwrite existing file: {os.path.basename(path)!r}"
            )
        try:
            os.link(tmp_path, path)
        except FileExistsError:
            raise ReviewIntegrityError(
                f"refusing to overwrite existing file: {os.path.basename(path)!r}"
            )
        except OSError:
            # Filesystem without hard-link support: use exclusive create.
            try:
                final_fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            except FileExistsError:
                raise ReviewIntegrityError(
                    f"refusing to overwrite existing file: "
                    f"{os.path.basename(path)!r}"
                )
            with os.fdopen(final_fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    else:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _read_json_file(path: str, what: str) -> dict:
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise ReviewIntegrityError(f"cannot read {what}: {path!r}") from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewIntegrityError(f"malformed {what}: {path!r}") from exc
    if not isinstance(data, dict):
        raise ReviewIntegrityError(f"malformed {what} (not an object): {path!r}")
    return data


# ---------------------------------------------------------------------------
# Sequence scanning
# ---------------------------------------------------------------------------

_SEQ_NAME_PATTERN = re.compile(r"(\d{6})_[^/\\]+\.json")


def _scan_sequence(directory: str) -> list[tuple[int, str]]:
    """Return sorted (sequence, filename) pairs for NNNNNN_*.json files."""
    entries: list[tuple[int, str]] = []
    if not os.path.isdir(directory):
        return entries
    for name in os.listdir(directory):
        match = _SEQ_NAME_PATTERN.fullmatch(name)
        if match:
            entries.append((int(match.group(1)), name))
    entries.sort()
    return entries


def _next_sequence(directory: str) -> int:
    entries = _scan_sequence(directory)
    if not entries:
        return 1
    return entries[-1][0] + 1


def _assert_contiguous(entries: list[tuple[int, str]], what: str) -> None:
    for expected, (seq, name) in enumerate(entries, start=1):
        if seq != expected:
            raise ReviewIntegrityError(
                f"{what} chain defect: expected sequence {expected}, "
                f"found {seq} ({name})"
            )


# ---------------------------------------------------------------------------
# Canonical hashing helpers
# ---------------------------------------------------------------------------


def _canonical_hash(obj: dict) -> str:
    try:
        return prov.canonical_sha256(obj)
    except prov.ProvenanceError as exc:
        raise ReviewIntegrityError(str(exc)) from exc


def _canonical_bytes(obj: dict) -> bytes:
    try:
        return prov.canonical_json_bytes(obj)
    except prov.ProvenanceError as exc:
        raise ReviewIntegrityError(str(exc)) from exc


def _validate_timestamp(value, field: str) -> str:
    try:
        return prov._require_utc_timestamp(value, field)
    except prov.ProvenanceError as exc:
        raise ReviewIntegrityError(str(exc)) from exc


def _validate_reviewer(reviewer_id, reviewer_display_name) -> None:
    try:
        prov.validate_reviewer_id(reviewer_id)
        prov.validate_reviewer_display_name(reviewer_display_name)
    except prov.ProvenanceError as exc:
        raise ReviewIntegrityError(str(exc)) from exc


# ---------------------------------------------------------------------------
# Manifest history snapshots
# ---------------------------------------------------------------------------


def snapshot_manifest(task_dir: str, manifest: dict) -> str:
    """Store an immutable manifest snapshot in manifest-history/.

    The snapshot filename embeds the sequence number and the manifest's own
    canonical SHA-256: manifest-history/000001_<manifest-sha256>.json
    Returns the snapshot file path. Never overwrites an existing snapshot.
    """
    prov.validate_manifest(manifest)
    manifest_hash = _canonical_hash(manifest)
    directory = _sub_dir(task_dir, MANIFEST_HISTORY_DIR)
    sequence = _next_sequence(directory)
    filename = f"{sequence:06d}_{manifest_hash}.json"
    path = _confined_file_path(task_dir, MANIFEST_HISTORY_DIR, filename)
    payload = _canonical_bytes(manifest) + b"\n"
    _atomic_create_exclusive(path, payload)
    return path


def list_manifest_history(task_dir: str) -> list[dict]:
    """Load and validate every manifest snapshot, failing closed on defects."""
    directory = _sub_dir(task_dir, MANIFEST_HISTORY_DIR, create=False)
    entries = _scan_sequence(directory)
    _assert_contiguous(entries, "manifest-history")
    snapshots = []
    for seq, name in entries:
        path = os.path.join(directory, name)
        data = _read_json_file(path, "manifest snapshot")
        expected_hash = name.split("_", 1)[1][: -len(".json")]
        actual_hash = _canonical_hash(data)
        if actual_hash != expected_hash:
            raise ReviewIntegrityError(
                f"manifest snapshot modified: {name} "
                f"(expected {expected_hash}, got {actual_hash})"
            )
        snapshots.append(data)
    return snapshots


# ---------------------------------------------------------------------------
# Review events (sequential, hash-chained)
# ---------------------------------------------------------------------------


def _event_unsigned_hash_fields(event: dict) -> dict:
    """Return the event fields covered by event_hash (everything but it)."""
    return {k: v for k, v in event.items() if k != "event_hash"}


def _validate_event_record(
    event: dict,
    name: str,
    *,
    expected_seq: int,
    previous_hash: str,
    seen_ids: set[str],
) -> None:
    """Fully validate one review event's structure, semantics, and linkage.

    Applies every deterministic per-event rule used by chain validation:
    required fields, schema version, sequence position, the closed
    event-type set, duplicate-id rejection, reviewer and timestamp
    validity, required reasons, previous-hash linkage, and event_hash
    recomputation. Fails closed on any defect; on success the event id is
    recorded in seen_ids.
    """
    required = (
        "schema_version", "sequence", "event_id", "event_type",
        "timestamp_utc", "reviewer_id", "reviewer_display_name",
        "reason", "previous_event_hash", "manifest_hash_before",
        "manifest_hash_after", "details", "event_hash",
    )
    for field in required:
        if field not in event:
            raise ReviewIntegrityError(
                f"review event {name} missing field: {field}"
            )
    if event["schema_version"] != SCHEMA_VERSION:
        raise ReviewIntegrityError(
            f"review event {name} has unsupported schema_version: "
            f"{event['schema_version']!r}"
        )
    if event["sequence"] != expected_seq:
        raise ReviewIntegrityError(
            f"review event {name} out of order: sequence "
            f"{event['sequence']} != {expected_seq}"
        )
    if event["event_type"] not in EVENT_TYPES:
        raise ReviewIntegrityError(
            f"review event {name} has unknown event_type: "
            f"{event['event_type']!r}"
        )
    if event["event_id"] in seen_ids:
        raise ReviewIntegrityError(
            f"duplicate review event id: {event['event_id']}"
        )
    seen_ids.add(event["event_id"])
    _validate_reviewer(event["reviewer_id"], event["reviewer_display_name"])
    _validate_timestamp(event["timestamp_utc"], "event.timestamp_utc")
    if event["event_type"] in _EVENT_REASON_REQUIRED:
        if not isinstance(event["reason"], str) or not event["reason"].strip():
            raise ReviewIntegrityError(
                f"review event {name} of type {event['event_type']} "
                "requires a non-empty reason"
            )
    if event["previous_event_hash"] != previous_hash:
        raise ReviewIntegrityError(
            f"review event {name} chain broken: previous_event_hash "
            f"{event['previous_event_hash']!r} != {previous_hash!r}"
        )
    recomputed = _canonical_hash(_event_unsigned_hash_fields(event))
    if recomputed != event["event_hash"]:
        raise ReviewIntegrityError(
            f"review event {name} modified: event_hash mismatch"
        )


def _validate_event_inputs(
    *,
    event_type: str,
    reviewer_id: str,
    reviewer_display_name: str,
    timestamp_utc: str,
    reason: str | None,
    manifest_hash_before: str | None,
    manifest_hash_after: str | None,
    details: dict | None,
    event_id: str | None,
    event_id_required: bool,
) -> None:
    """Validate every event input. Performs no filesystem access."""
    if event_type not in EVENT_TYPES:
        raise ReviewIntegrityError(f"unknown event_type: {event_type!r}")
    _validate_reviewer(reviewer_id, reviewer_display_name)
    _validate_timestamp(timestamp_utc, "event.timestamp_utc")
    if event_type in _EVENT_REASON_REQUIRED:
        if not isinstance(reason, str) or not reason.strip():
            raise ReviewIntegrityError(
                f"event_type {event_type} requires a non-empty reason"
            )
    if reason is not None and not isinstance(reason, str):
        raise ReviewIntegrityError("reason must be a string")
    for field, value in (
        ("manifest_hash_before", manifest_hash_before),
        ("manifest_hash_after", manifest_hash_after),
    ):
        if value is not None and not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ReviewIntegrityError(
                f"{field} must be a lowercase SHA-256 hex digest"
            )
    if details is not None and not isinstance(details, dict):
        raise ReviewIntegrityError("details must be a mapping")
    if event_id is None:
        if event_id_required:
            raise ReviewIntegrityError(
                "event_id is required and must be frozen by the caller"
            )
    elif not isinstance(event_id, str) or not re.fullmatch(r"[0-9a-f]{32}", event_id):
        raise ReviewIntegrityError(
            "event_id must be a 32-char lowercase hex string"
        )


def _construct_next_event(
    task_dir: str,
    *,
    create_directory: bool,
    event_type: str,
    reviewer_id: str,
    reviewer_display_name: str,
    timestamp_utc: str,
    reason: str | None,
    manifest_hash_before: str | None,
    manifest_hash_after: str | None,
    details: dict | None,
    event_id: str | None,
    event_id_required: bool,
) -> dict:
    """Validate inputs and the committed chain, then build the exact next event.

    Single shared construction path used by plan_review_event() (no
    writes) and create_review_event_file() (durable exclusive create) so
    the planner and the writer cannot drift. This helper performs no
    filesystem mutation itself; the caller controls directory creation
    through create_directory and performs any durable write.
    """
    _validate_event_inputs(
        event_type=event_type,
        reviewer_id=reviewer_id,
        reviewer_display_name=reviewer_display_name,
        timestamp_utc=timestamp_utc,
        reason=reason,
        manifest_hash_before=manifest_hash_before,
        manifest_hash_after=manifest_hash_after,
        details=details,
        event_id=event_id,
        event_id_required=event_id_required,
    )
    directory = _sub_dir(task_dir, REVIEW_EVENTS_DIR, create=create_directory)
    # Validate the existing committed chain before appending (fail closed).
    # An uncommitted tail from a prior create_review_event_file call makes
    # this raise, blocking further construction until the tail is committed.
    committed = validate_review_event_chain(task_dir)

    entries = _scan_sequence(directory)
    sequence = entries[-1][0] + 1 if entries else 1
    previous_event_hash = (
        _read_json_file(os.path.join(directory, entries[-1][1]), "review event")[
            "event_hash"
        ]
        if entries
        else _GENESIS_HASH
    )

    if event_id is not None:
        if any(event["event_id"] == event_id for event in committed):
            raise ReviewIntegrityError(
                f"duplicate review event id: {event_id}"
            )
    else:
        event_id = uuid.uuid4().hex

    event = {
        "schema_version": SCHEMA_VERSION,
        "sequence": sequence,
        "event_id": event_id,
        "event_type": event_type,
        "timestamp_utc": timestamp_utc,
        "reviewer_id": reviewer_id,
        "reviewer_display_name": reviewer_display_name,
        "reason": reason,
        "previous_event_hash": previous_event_hash,
        "manifest_hash_before": manifest_hash_before,
        "manifest_hash_after": manifest_hash_after,
        "details": details,
    }
    event["event_hash"] = _canonical_hash(_event_unsigned_hash_fields(event))
    return event


def create_review_event_file(
    task_dir: str,
    *,
    event_type: str,
    reviewer_id: str,
    reviewer_display_name: str,
    timestamp_utc: str,
    reason: str | None = None,
    manifest_hash_before: str | None = None,
    manifest_hash_after: str | None = None,
    details: dict | None = None,
    event_id: str | None = None,
) -> dict:
    """Create the next immutable review-event file without advancing the checkpoint.

    Applies the full existing event validation and construction behavior,
    then durably creates only the immutable event file (exclusive create,
    fsync, never overwrite). The new event is an uncommitted tail: chain
    validation fails closed on it until advance_review_event_checkpoint()
    commits exactly this event. An existing uncommitted tail blocks further
    creation (fail closed, no repair or rollback). Never advances the
    checkpoint, overwrites or deletes events, repairs tails, or rolls back.
    """
    event = _construct_next_event(
        task_dir,
        create_directory=True,
        event_type=event_type,
        reviewer_id=reviewer_id,
        reviewer_display_name=reviewer_display_name,
        timestamp_utc=timestamp_utc,
        reason=reason,
        manifest_hash_before=manifest_hash_before,
        manifest_hash_after=manifest_hash_after,
        details=details,
        event_id=event_id,
        event_id_required=False,
    )

    filename = f"{event['sequence']:06d}_{event['event_id']}.json"
    path = _confined_file_path(task_dir, REVIEW_EVENTS_DIR, filename)
    _atomic_create_exclusive(path, _canonical_bytes(event) + b"\n")

    # Deliberately no checkpoint write and no post-creation chain validation:
    # committing the tail is advance_review_event_checkpoint()'s sole job.
    return event


def plan_review_event(
    task_dir: str,
    *,
    event_type: str,
    reviewer_id: str,
    reviewer_display_name: str,
    timestamp_utc: str,
    event_id: str,
    reason: str | None = None,
    manifest_hash_before: str | None = None,
    manifest_hash_after: str | None = None,
    details: dict | None = None,
) -> dict:
    """Plan the exact next review event deterministically, performing no writes.

    Validates the committed chain and all inputs, computes the exact next
    sequence, previous hash, complete event record, and event_hash, and
    returns the planned record. Creates, modifies, or deletes no file,
    directory, or checkpoint. The caller freezes event_id before planning.
    Shares the same internal event-construction logic as
    create_review_event_file() so planner and writer cannot drift.
    """
    return _construct_next_event(
        task_dir,
        create_directory=False,
        event_type=event_type,
        reviewer_id=reviewer_id,
        reviewer_display_name=reviewer_display_name,
        timestamp_utc=timestamp_utc,
        reason=reason,
        manifest_hash_before=manifest_hash_before,
        manifest_hash_after=manifest_hash_after,
        details=details,
        event_id=event_id,
        event_id_required=True,
    )


def advance_review_event_checkpoint(
    task_dir: str,
    *,
    sequence: int,
    event_id: str,
    event_hash: str,
) -> dict:
    """Advance the review-event chain-head checkpoint to an existing tail event.

    The referenced event must exist as the exact sole next-sequence tail
    beyond the committed checkpoint. Every deterministic check runs BEFORE
    the checkpoint write: the existing checkpoint itself (structure and
    self-hash), the full committed event prefix (contiguity, complete
    per-event structure and semantics, hash linkage from genesis, and
    exact checkpoint agreement), and the candidate tail's complete event
    structure and semantics (including linkage to the committed chain
    head) are all fully validated first. Only then is the checkpoint
    atomically advanced, and the resulting committed chain is fully
    validated again (fail closed). A rejected advance never mutates the
    checkpoint. Never creates, modifies, overwrites, or deletes event
    files.
    """
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise ReviewIntegrityError("sequence must be a positive integer")
    if not isinstance(event_id, str) or not re.fullmatch(r"[0-9a-f]{32}", event_id):
        raise ReviewIntegrityError(
            "event_id must be a 32-char lowercase hex string"
        )
    if not isinstance(event_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", event_hash):
        raise ReviewIntegrityError(
            "event_hash must be a lowercase SHA-256 hex digest"
        )

    directory = _sub_dir(task_dir, REVIEW_EVENTS_DIR, create=False)
    entries = _scan_sequence(directory)
    if not entries:
        raise ReviewIntegrityError(
            "no review events exist; nothing to advance to"
        )

    # ------------------------------------------------------------------
    # Pre-write validation: every deterministic check runs before
    # _write_checkpoint_atomic. The checkpoint is mutated only after the
    # existing checkpoint, the committed event prefix, and the candidate
    # tail have all fully validated.
    # ------------------------------------------------------------------

    # 1. Fully validate the existing checkpoint itself (structure and
    #    self-hash) before trusting its last_sequence.
    checkpoint = _read_checkpoint(directory)
    if checkpoint is not None:
        for field in ("schema_version", "chain_type", "last_sequence",
                      "last_record_id", "last_record_hash", "checkpoint_hash"):
            if field not in checkpoint:
                raise ReviewIntegrityError(
                    f"chain-head checkpoint malformed: missing field: {field}"
                )
        if checkpoint["schema_version"] != SCHEMA_VERSION:
            raise ReviewIntegrityError(
                "chain-head checkpoint malformed: unsupported schema_version: "
                f"{checkpoint['schema_version']!r}"
            )
        if checkpoint["chain_type"] != CHAIN_TYPE_REVIEW_EVENTS:
            raise ReviewIntegrityError(
                "chain-head checkpoint malformed: chain_type mismatch: "
                f"{checkpoint['chain_type']!r}"
            )
        if (
            not isinstance(checkpoint["last_sequence"], int)
            or isinstance(checkpoint["last_sequence"], bool)
            or checkpoint["last_sequence"] < 1
        ):
            raise ReviewIntegrityError(
                "chain-head checkpoint malformed: last_sequence must be a "
                "positive integer"
            )
        recomputed = _canonical_hash(_checkpoint_unsigned_fields(checkpoint))
        if recomputed != checkpoint["checkpoint_hash"]:
            raise ReviewIntegrityError(
                "chain-head checkpoint modified: checkpoint_hash mismatch"
            )
    committed_sequence = checkpoint["last_sequence"] if checkpoint is not None else 0

    # 2. Fully validate the committed event prefix: contiguous sequence,
    #    complete per-event structure and semantics, hash linkage from
    #    genesis, and exact agreement with the checkpoint.
    committed_entries = entries[:committed_sequence]
    _assert_contiguous(committed_entries, "review-events")
    seen_ids: set[str] = set()
    committed_records: list[dict] = []
    previous_hash = _GENESIS_HASH
    for expected_seq, (seq, name) in enumerate(committed_entries, start=1):
        record = _read_json_file(os.path.join(directory, name), "review event")
        _validate_event_record(
            record,
            name,
            expected_seq=expected_seq,
            previous_hash=previous_hash,
            seen_ids=seen_ids,
        )
        previous_hash = record["event_hash"]
        committed_records.append(record)
    _validate_checkpoint(
        directory, CHAIN_TYPE_REVIEW_EVENTS, committed_entries,
        committed_records, id_field="event_id", hash_field="event_hash",
    )

    # 3. Require exactly one uncommitted tail at exactly the next sequence.
    tails = entries[committed_sequence:]
    if len(tails) != 1:
        raise ReviewIntegrityError(
            f"expected exactly one uncommitted tail beyond committed "
            f"sequence {committed_sequence}, found {len(tails)}"
        )
    tail_seq, tail_name = tails[0]
    if tail_seq != sequence:
        raise ReviewIntegrityError(
            f"referenced sequence {sequence} is not the chain tail "
            f"(tail is sequence {tail_seq})"
        )
    if tail_seq != committed_sequence + 1:
        raise ReviewIntegrityError(
            f"tail sequence {tail_seq} is not exactly one beyond the "
            f"committed checkpoint sequence {committed_sequence}"
        )
    expected_name = f"{sequence:06d}_{event_id}.json"
    if tail_name != expected_name:
        raise ReviewIntegrityError(
            f"tail file {tail_name!r} does not match the referenced event "
            f"{expected_name!r}"
        )

    # 4. Fully validate the candidate tail's complete structure and
    #    semantics, including linkage to the committed chain head.
    event = _read_json_file(os.path.join(directory, tail_name), "review event")
    _validate_event_record(
        event,
        tail_name,
        expected_seq=sequence,
        previous_hash=previous_hash,
        seen_ids=seen_ids,
    )
    if event["event_id"] != event_id:
        raise ReviewIntegrityError(
            "tail event event_id does not match the referenced event_id"
        )
    if event["event_hash"] != event_hash:
        raise ReviewIntegrityError(
            "tail event hash mismatch; refusing to advance the checkpoint"
        )

    # 5. All deterministic checks passed; only now advance the checkpoint.
    new_checkpoint = _build_checkpoint(
        chain_type=CHAIN_TYPE_REVIEW_EVENTS,
        sequence=sequence,
        record_id=event_id,
        record_hash=event_hash,
    )
    _write_checkpoint_atomic(directory, new_checkpoint)

    # Fail closed if the advance did not produce a fully valid committed chain.
    validate_review_event_chain(task_dir)
    return new_checkpoint


def create_review_event(
    task_dir: str,
    *,
    event_type: str,
    reviewer_id: str,
    reviewer_display_name: str,
    timestamp_utc: str,
    reason: str | None = None,
    manifest_hash_before: str | None = None,
    manifest_hash_after: str | None = None,
    details: dict | None = None,
) -> dict:
    """Append a new review event to the hash chain.

    Backward-compatible wrapper with the exact pre-split signature and
    observable behavior: create the immutable event file, then advance the
    chain-head checkpoint to it. The event is validated, hash-linked to the
    current chain head, written atomically, and never overwrites an
    existing event file; any defect fails closed.
    """
    event = create_review_event_file(
        task_dir,
        event_type=event_type,
        reviewer_id=reviewer_id,
        reviewer_display_name=reviewer_display_name,
        timestamp_utc=timestamp_utc,
        reason=reason,
        manifest_hash_before=manifest_hash_before,
        manifest_hash_after=manifest_hash_after,
        details=details,
    )
    advance_review_event_checkpoint(
        task_dir,
        sequence=event["sequence"],
        event_id=event["event_id"],
        event_hash=event["event_hash"],
    )
    return event


def validate_review_event_chain(task_dir: str) -> list[dict]:
    """Validate the full review-event hash chain; return events in order.

    Detects missing, reordered, duplicated, malformed, or modified events.
    Any defect raises ReviewIntegrityError (fail closed).
    """
    directory = _sub_dir(task_dir, REVIEW_EVENTS_DIR, create=False)
    entries = _scan_sequence(directory)
    _assert_contiguous(entries, "review-events")

    seen_ids: set[str] = set()
    events: list[dict] = []
    previous_hash = _GENESIS_HASH

    for expected_seq, (seq, name) in enumerate(entries, start=1):
        path = os.path.join(directory, name)
        event = _read_json_file(path, "review event")
        _validate_event_record(
            event,
            name,
            expected_seq=expected_seq,
            previous_hash=previous_hash,
            seen_ids=seen_ids,
        )
        previous_hash = event["event_hash"]
        events.append(event)

    # Chain-head checkpoint validation: detects deletion/truncation of the
    # tail, missing/malformed/modified checkpoint, and records beyond the
    # checkpoint (uncommitted tail). Fails closed on any disagreement.
    _validate_checkpoint(
        directory, CHAIN_TYPE_REVIEW_EVENTS, entries, events,
        id_field="event_id", hash_field="event_hash",
    )
    return events


def review_chain_head_hash(task_dir: str) -> str:
    """Return the event_hash of the chain head (genesis hash when empty)."""
    events = validate_review_event_chain(task_dir)
    return events[-1]["event_hash"] if events else _GENESIS_HASH


# ---------------------------------------------------------------------------
# Approval / revocation receipts (sequential, hash-chained)
# ---------------------------------------------------------------------------


def _receipt_unsigned_fields(receipt: dict) -> dict:
    return {k: v for k, v in receipt.items() if k != "receipt_hash"}


def create_receipt(
    task_dir: str,
    *,
    receipt_type: str,
    task_id: str,
    manifest_version: str,
    manifest_relative_path: str,
    manifest_sha256: str,
    audit_head_hash: str,
    created_at_utc: str,
    reviewer_id: str,
    reviewer_display_name: str,
    approval_receipt_id: str | None = None,
    approval_receipt_hash: str | None = None,
    reason: str | None = None,
) -> dict:
    """Append an APPROVAL or REVOCATION receipt to the receipt chain.

    Receipts are canonical, immutable, sequential, hash-linked, atomically
    created, and never overwritten. REVOCATION receipts must reference the
    APPROVAL receipt they revoke.
    """
    if receipt_type not in RECEIPT_TYPES:
        raise ReviewIntegrityError(f"unknown receipt_type: {receipt_type!r}")
    if not isinstance(task_id, str) or not task_id.strip():
        raise ReviewIntegrityError("task_id must be a non-empty string")
    if not isinstance(manifest_version, str) or not manifest_version.strip():
        raise ReviewIntegrityError("manifest_version must be a non-empty string")
    if not isinstance(manifest_relative_path, str) or not manifest_relative_path.strip():
        raise ReviewIntegrityError(
            "manifest_relative_path must be a non-empty string"
        )
    if os.path.isabs(manifest_relative_path) or ".." in manifest_relative_path.split(
        os.sep
    ):
        raise ReviewIntegrityError(
            "manifest_relative_path must be a safe relative path"
        )
    if not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256 or ""):
        raise ReviewIntegrityError(
            "manifest_sha256 must be a lowercase SHA-256 hex digest"
        )
    if not re.fullmatch(r"[0-9a-f]{64}", audit_head_hash or ""):
        raise ReviewIntegrityError(
            "audit_head_hash must be a lowercase SHA-256 hex digest"
        )
    _validate_timestamp(created_at_utc, "receipt.created_at_utc")
    _validate_reviewer(reviewer_id, reviewer_display_name)

    if receipt_type == "REVOCATION":
        if not isinstance(approval_receipt_id, str) or not approval_receipt_id.strip():
            raise ReviewIntegrityError(
                "REVOCATION requires approval_receipt_id"
            )
        if not re.fullmatch(r"[0-9a-f]{64}", approval_receipt_hash or ""):
            raise ReviewIntegrityError(
                "REVOCATION requires approval_receipt_hash (SHA-256 hex)"
            )
        if not isinstance(reason, str) or not reason.strip():
            raise ReviewIntegrityError("REVOCATION requires a non-empty reason")
    else:
        if approval_receipt_id is not None or approval_receipt_hash is not None:
            raise ReviewIntegrityError(
                "APPROVAL receipts must not reference another receipt"
            )

    directory = _sub_dir(task_dir, APPROVALS_DIR)
    # Validate the existing receipt chain before appending (fail closed).
    existing = validate_receipt_chain(task_dir)

    if receipt_type == "REVOCATION":
        target = None
        for receipt in existing:
            if receipt["receipt_id"] == approval_receipt_id:
                target = receipt
        if target is None:
            raise ReviewIntegrityError(
                f"REVOCATION references unknown approval receipt: "
                f"{approval_receipt_id!r}"
            )
        if target["receipt_type"] != "APPROVAL":
            raise ReviewIntegrityError(
                "REVOCATION must reference an APPROVAL receipt"
            )
        if target["receipt_hash"] != approval_receipt_hash:
            raise ReviewIntegrityError(
                "REVOCATION approval_receipt_hash does not match the "
                "referenced APPROVAL receipt"
            )
        for receipt in existing:
            if (
                receipt["receipt_type"] == "REVOCATION"
                and receipt.get("approval_receipt_id") == approval_receipt_id
            ):
                raise ReviewIntegrityError(
                    f"approval receipt {approval_receipt_id!r} is already revoked"
                )

    entries = _scan_sequence(directory)
    sequence = entries[-1][0] + 1 if entries else 1
    previous_receipt_hash = existing[-1]["receipt_hash"] if existing else _GENESIS_HASH

    receipt_id = uuid.uuid4().hex
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "receipt_id": receipt_id,
        "sequence": sequence,
        "receipt_type": receipt_type,
        "task_id": task_id,
        "manifest_version": manifest_version,
        "manifest_relative_path": manifest_relative_path,
        "manifest_sha256": manifest_sha256,
        "audit_head_hash": audit_head_hash,
        "created_at_utc": created_at_utc,
        "reviewer_id": reviewer_id,
        "reviewer_display_name": reviewer_display_name,
        "effective_status": "APPROVED" if receipt_type == "APPROVAL" else "REVOKED",
        "previous_receipt_hash": previous_receipt_hash,
    }
    if receipt_type == "REVOCATION":
        receipt["approval_receipt_id"] = approval_receipt_id
        receipt["approval_receipt_hash"] = approval_receipt_hash
        receipt["reason"] = reason
    receipt["receipt_hash"] = _canonical_hash(_receipt_unsigned_fields(receipt))

    filename = f"{sequence:06d}_{receipt_id}.json"
    path = _confined_file_path(task_dir, APPROVALS_DIR, filename)
    _atomic_create_exclusive(path, _canonical_bytes(receipt) + b"\n")

    # Write ordering: the immutable receipt exists before the checkpoint. An
    # interruption here leaves an uncommitted tail that fails closed on the
    # next validation and requires explicit recovery.
    checkpoint = _build_checkpoint(
        chain_type=CHAIN_TYPE_APPROVALS,
        sequence=sequence,
        record_id=receipt_id,
        record_hash=receipt["receipt_hash"],
    )
    _write_checkpoint_atomic(directory, checkpoint)

    # Fail closed if the append did not produce a valid chain.
    validate_receipt_chain(task_dir)
    return receipt


def validate_receipt_chain(task_dir: str) -> list[dict]:
    """Validate the full receipt hash chain; return receipts in order.

    Detects missing, reordered, duplicated, malformed, or modified receipts
    and invalid APPROVAL/REVOCATION linkage. Fails closed on any defect.
    """
    directory = _sub_dir(task_dir, APPROVALS_DIR, create=False)
    entries = _scan_sequence(directory)
    _assert_contiguous(entries, "approvals")

    seen_ids: set[str] = set()
    receipts: list[dict] = []
    previous_hash = _GENESIS_HASH
    revoked: set[str] = set()

    for expected_seq, (seq, name) in enumerate(entries, start=1):
        path = os.path.join(directory, name)
        receipt = _read_json_file(path, "approval receipt")

        required = (
            "schema_version", "receipt_id", "sequence", "receipt_type",
            "task_id", "manifest_version", "manifest_relative_path",
            "manifest_sha256", "audit_head_hash", "created_at_utc",
            "reviewer_id", "reviewer_display_name", "effective_status",
            "previous_receipt_hash", "receipt_hash",
        )
        for field in required:
            if field not in receipt:
                raise ReviewIntegrityError(
                    f"receipt {name} missing field: {field}"
                )
        if receipt["schema_version"] != SCHEMA_VERSION:
            raise ReviewIntegrityError(
                f"receipt {name} has unsupported schema_version: "
                f"{receipt['schema_version']!r}"
            )
        if receipt["sequence"] != expected_seq:
            raise ReviewIntegrityError(
                f"receipt {name} out of order: sequence "
                f"{receipt['sequence']} != {expected_seq}"
            )
        if receipt["receipt_type"] not in RECEIPT_TYPES:
            raise ReviewIntegrityError(
                f"receipt {name} has unknown receipt_type: "
                f"{receipt['receipt_type']!r}"
            )
        expected_status = (
            "APPROVED" if receipt["receipt_type"] == "APPROVAL" else "REVOKED"
        )
        if receipt["effective_status"] != expected_status:
            raise ReviewIntegrityError(
                f"receipt {name} effective_status mismatch: "
                f"{receipt['effective_status']!r} != {expected_status!r}"
            )
        if receipt["receipt_id"] in seen_ids:
            raise ReviewIntegrityError(
                f"duplicate receipt id: {receipt['receipt_id']}"
            )
        seen_ids.add(receipt["receipt_id"])
        _validate_reviewer(receipt["reviewer_id"], receipt["reviewer_display_name"])
        _validate_timestamp(receipt["created_at_utc"], "receipt.created_at_utc")
        if not re.fullmatch(r"[0-9a-f]{64}", receipt["manifest_sha256"]):
            raise ReviewIntegrityError(
                f"receipt {name} has invalid manifest_sha256"
            )
        if not re.fullmatch(r"[0-9a-f]{64}", receipt["audit_head_hash"]):
            raise ReviewIntegrityError(
                f"receipt {name} has invalid audit_head_hash"
            )
        if receipt["previous_receipt_hash"] != previous_hash:
            raise ReviewIntegrityError(
                f"receipt {name} chain broken: previous_receipt_hash "
                f"{receipt['previous_receipt_hash']!r} != {previous_hash!r}"
            )

        if receipt["receipt_type"] == "REVOCATION":
            for field in ("approval_receipt_id", "approval_receipt_hash", "reason"):
                if field not in receipt:
                    raise ReviewIntegrityError(
                        f"REVOCATION receipt {name} missing field: {field}"
                    )
            if not isinstance(receipt["reason"], str) or not receipt["reason"].strip():
                raise ReviewIntegrityError(
                    f"REVOCATION receipt {name} requires a non-empty reason"
                )
            target = None
            for prior in receipts:
                if prior["receipt_id"] == receipt["approval_receipt_id"]:
                    target = prior
            if target is None:
                raise ReviewIntegrityError(
                    f"REVOCATION receipt {name} references unknown approval "
                    f"receipt {receipt['approval_receipt_id']!r}"
                )
            if target["receipt_type"] != "APPROVAL":
                raise ReviewIntegrityError(
                    f"REVOCATION receipt {name} must reference an APPROVAL"
                )
            if target["receipt_hash"] != receipt["approval_receipt_hash"]:
                raise ReviewIntegrityError(
                    f"REVOCATION receipt {name} approval_receipt_hash mismatch"
                )
            if target["receipt_id"] in revoked:
                raise ReviewIntegrityError(
                    f"approval receipt {target['receipt_id']!r} revoked twice"
                )
            revoked.add(target["receipt_id"])

        recomputed = _canonical_hash(_receipt_unsigned_fields(receipt))
        if recomputed != receipt["receipt_hash"]:
            raise ReviewIntegrityError(
                f"receipt {name} modified: receipt_hash mismatch"
            )
        previous_hash = receipt["receipt_hash"]
        receipts.append(receipt)

    # Chain-head checkpoint validation (same fail-closed rules as events).
    _validate_checkpoint(
        directory, CHAIN_TYPE_APPROVALS, entries, receipts,
        id_field="receipt_id", hash_field="receipt_hash",
    )
    return receipts


def receipt_chain_head_hash(task_dir: str) -> str:
    """Return the receipt_hash of the chain head (genesis hash when empty)."""
    receipts = validate_receipt_chain(task_dir)
    return receipts[-1]["receipt_hash"] if receipts else _GENESIS_HASH


# ---------------------------------------------------------------------------
# Uncommitted-tail recovery (explicit, low-level; no CLI command yet)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Standalone transaction recovery receipts (Phase 1B.3C.2B.2C)
# ---------------------------------------------------------------------------
# Exactly one immutable receipt per resumed transaction, stored outside the
# review-event chain at
# review-recovery/transaction-resumed-<transaction_id>.json. The sanitized
# transaction_id determines the filename; the path must remain inside the
# task directory. Receipts are canonical UTF-8 JSON, created exclusively
# (never overwritten), flushed/fsynced, and self-hash verified.

REVIEW_RECOVERY_DIR = "review-recovery"

RECOVERY_RECEIPT_TYPE = "TRANSACTION_RESUMED"

# Required recovery-receipt fields, in the approved schema order. Unknown
# fields are rejected; receipt_hash is the canonical self-hash over every
# other field.
_RECOVERY_RECEIPT_REQUIRED_FIELDS = (
    "schema_version",
    "receipt_type",
    "transaction_id",
    "interrupted_stage",
    "resuming_reviewer_id",
    "resuming_reviewer_display_name",
    "reason",
    "resumed_at_utc",
    "resulting_manifest_hash",
    "resulting_audit_chain_head",
    "receipt_hash",
)


def _recovery_receipt_unsigned_fields(receipt: dict) -> dict:
    """Return the receipt fields covered by receipt_hash (everything but it)."""
    return {k: v for k, v in receipt.items() if k != "receipt_hash"}


def _recovery_receipt_path(task_dir: str, transaction_id: str) -> str:
    """Resolve the confined recovery-receipt path for a transaction id.

    The 32-hex transaction_id fully determines the filename; anything else
    (including traversal or path separators) fails closed before any path
    is built, so the resolved path can never escape the task directory.
    """
    if not isinstance(transaction_id, str) or not re.fullmatch(
        r"[0-9a-f]{32}", transaction_id
    ):
        raise ReviewIntegrityError(
            "transaction_id must be a 32-char lowercase hex string"
        )
    base = _resolve_task_dir(task_dir)
    directory = _sub_dir(base, REVIEW_RECOVERY_DIR, create=False)
    filename = f"transaction-resumed-{transaction_id}.json"
    path = os.path.realpath(os.path.join(directory, filename))
    if os.path.commonpath([base, path]) != base:
        raise ReviewIntegrityError(
            "recovery-receipt path escapes the task directory"
        )
    return path


def _validate_recovery_receipt_fields(receipt: dict) -> None:
    """Validate every recovery-receipt field value (not the self-hash)."""
    if receipt["schema_version"] != SCHEMA_VERSION:
        raise ReviewIntegrityError(
            f"recovery receipt has unsupported schema_version: "
            f"{receipt['schema_version']!r}"
        )
    if receipt["receipt_type"] != RECOVERY_RECEIPT_TYPE:
        raise ReviewIntegrityError(
            f"recovery receipt has unknown receipt_type: "
            f"{receipt['receipt_type']!r}"
        )
    transaction_id = receipt["transaction_id"]
    if not isinstance(transaction_id, str) or not re.fullmatch(
        r"[0-9a-f]{32}", transaction_id
    ):
        raise ReviewIntegrityError(
            "recovery receipt transaction_id must be a 32-char lowercase "
            "hex string"
        )
    if receipt["interrupted_stage"] not in TRANSACTION_STAGES:
        raise ReviewIntegrityError(
            f"recovery receipt has unknown interrupted_stage: "
            f"{receipt['interrupted_stage']!r}"
        )
    _validate_reviewer(
        receipt["resuming_reviewer_id"], receipt["resuming_reviewer_display_name"]
    )
    if not isinstance(receipt["reason"], str) or not receipt["reason"].strip():
        raise ReviewIntegrityError(
            "recovery receipt reason must be a non-empty string"
        )
    _validate_timestamp(receipt["resumed_at_utc"], "recovery_receipt.resumed_at_utc")
    for field in ("resulting_manifest_hash", "resulting_audit_chain_head"):
        value = receipt[field]
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ReviewIntegrityError(
                f"recovery receipt {field} must be a SHA-256 hex digest"
            )


def _validate_recovery_receipt_structure(receipt: dict) -> None:
    """Validate recovery-receipt fields and self-hash. Fails closed."""
    for field in _RECOVERY_RECEIPT_REQUIRED_FIELDS:
        if field not in receipt:
            raise ReviewIntegrityError(
                f"recovery receipt missing field: {field}"
            )
    unknown = set(receipt) - set(_RECOVERY_RECEIPT_REQUIRED_FIELDS)
    if unknown:
        raise ReviewIntegrityError(
            f"recovery receipt has unknown field(s): {sorted(unknown)!r}"
        )
    _validate_recovery_receipt_fields(receipt)
    recomputed = _canonical_hash(_recovery_receipt_unsigned_fields(receipt))
    if recomputed != receipt["receipt_hash"]:
        raise ReviewIntegrityError(
            "recovery receipt modified: receipt_hash mismatch"
        )


def create_recovery_receipt(
    task_dir: str,
    *,
    transaction_id: str,
    interrupted_stage: str,
    resuming_reviewer_id: str,
    resuming_reviewer_display_name: str,
    reason: str,
    resumed_at_utc: str,
    resulting_manifest_hash: str,
    resulting_audit_chain_head: str,
) -> dict:
    """Create the standalone immutable recovery receipt for a transaction.

    Canonical UTF-8 JSON, created exclusively (never overwritten),
    flushed/fsynced, and self-hash verified. An existing receipt for the
    same transaction_id fails closed without modification; verify an
    exact existing receipt through read_recovery_receipt() — the receipt
    is never rewritten.
    """
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "receipt_type": RECOVERY_RECEIPT_TYPE,
        "transaction_id": transaction_id,
        "interrupted_stage": interrupted_stage,
        "resuming_reviewer_id": resuming_reviewer_id,
        "resuming_reviewer_display_name": resuming_reviewer_display_name,
        "reason": reason,
        "resumed_at_utc": resumed_at_utc,
        "resulting_manifest_hash": resulting_manifest_hash,
        "resulting_audit_chain_head": resulting_audit_chain_head,
    }
    _validate_recovery_receipt_fields(receipt)
    path = _recovery_receipt_path(task_dir, transaction_id)
    receipt["receipt_hash"] = _canonical_hash(
        _recovery_receipt_unsigned_fields(receipt)
    )
    # Create the directory only after every input has validated.
    _sub_dir(task_dir, REVIEW_RECOVERY_DIR)
    _atomic_create_exclusive(path, _canonical_bytes(receipt) + b"\n")
    return receipt


def read_recovery_receipt(task_dir: str, *, transaction_id: str) -> dict | None:
    """Read and validate a recovery receipt, or None when absent.

    A malformed, hash-mismatched, or identity-mismatched receipt raises
    ReviewIntegrityError (fail closed). Never rewrites the receipt.
    """
    path = _recovery_receipt_path(task_dir, transaction_id)
    if not os.path.exists(path):
        return None
    receipt = _read_json_file(path, "recovery receipt")
    _validate_recovery_receipt_structure(receipt)
    if receipt["transaction_id"] != transaction_id:
        raise ReviewIntegrityError(
            "recovery receipt transaction_id does not match the receipt path"
        )
    return receipt


def find_uncommitted_tail(task_dir: str, chain_type: str) -> list[tuple[int, str]]:
    """Return (sequence, filename) records beyond the committed checkpoint.

    These are records that were created but whose checkpoint update did not
    complete (interrupted append). They are NOT silently accepted or
    deleted; an explicit recovery decision is required.
    """
    if chain_type == CHAIN_TYPE_REVIEW_EVENTS:
        directory = _sub_dir(task_dir, REVIEW_EVENTS_DIR, create=False)
    elif chain_type == CHAIN_TYPE_APPROVALS:
        directory = _sub_dir(task_dir, APPROVALS_DIR, create=False)
    else:
        raise ReviewIntegrityError(f"unknown chain_type: {chain_type!r}")
    entries = _scan_sequence(directory)
    checkpoint = _read_checkpoint(directory)
    committed_seq = checkpoint["last_sequence"] if checkpoint else 0
    return [(seq, name) for seq, name in entries if seq > committed_seq]


def discard_uncommitted_tail(
    task_dir: str,
    *,
    chain_type: str,
    reviewer_id: str,
    reviewer_display_name: str,
    reason: str,
    timestamp_utc: str,
) -> dict:
    """Explicitly discard uncommitted tail records after an interrupted append.

    Requires reviewer identity and a reason. Removes only records beyond the
    committed checkpoint, then records a LOCK_RECOVERED-style audit event in
    the review-event chain (when discarding from the receipt chain) so the
    recovery itself leaves audit evidence. Never touches committed records.

    Note: discarding from the review-events chain rewrites that chain's
    checkpoint to the last committed record; discarding from the receipt
    chain appends an audit event to the review-events chain.
    """
    _validate_reviewer(reviewer_id, reviewer_display_name)
    if not isinstance(reason, str) or not reason.strip():
        raise ReviewIntegrityError("tail recovery requires a non-empty reason")
    _validate_timestamp(timestamp_utc, "recovery timestamp_utc")

    tail = find_uncommitted_tail(task_dir, chain_type)
    if not tail:
        raise ReviewIntegrityError(
            f"no uncommitted tail in the {chain_type} chain to recover"
        )

    if chain_type == CHAIN_TYPE_REVIEW_EVENTS:
        directory = _sub_dir(task_dir, REVIEW_EVENTS_DIR, create=False)
    else:
        directory = _sub_dir(task_dir, APPROVALS_DIR, create=False)

    discarded = []
    for seq, name in tail:
        record = _read_json_file(os.path.join(directory, name), "tail record")
        discarded.append(record)
        try:
            os.unlink(os.path.join(directory, name))
        except OSError as exc:
            raise ReviewIntegrityError(
                f"failed to remove uncommitted tail record {name}"
            ) from exc

    # Audit evidence of the recovery. When recovering the receipt chain we
    # can append a review event; when recovering the event chain itself we
    # cannot (its checkpoint is stale), so we rebuild its checkpoint to the
    # last committed record and report via the return value.
    audit_event = None
    if chain_type == CHAIN_TYPE_APPROVALS:
        audit_event = create_review_event(
            task_dir,
            event_type="LOCK_RECOVERED",
            reviewer_id=reviewer_id,
            reviewer_display_name=reviewer_display_name,
            timestamp_utc=timestamp_utc,
            reason=f"discarded uncommitted receipt-chain tail: {reason}",
            details={
                "recovered_chain": chain_type,
                "discarded_count": len(discarded),
                "discarded_ids": [
                    r.get("receipt_id") for r in discarded
                ],
            },
        )
    else:
        # Rebuild the event-chain checkpoint to the committed head.
        events_dir = _sub_dir(task_dir, REVIEW_EVENTS_DIR, create=False)
        remaining = _scan_sequence(events_dir)
        checkpoint = _read_checkpoint(events_dir)
        committed_seq = checkpoint["last_sequence"] if checkpoint else 0
        committed = [(s, n) for s, n in remaining if s <= committed_seq]
        if committed:
            last_seq, last_name = committed[-1]
            last_record = _read_json_file(
                os.path.join(events_dir, last_name), "review event"
            )
            new_checkpoint = _build_checkpoint(
                chain_type=CHAIN_TYPE_REVIEW_EVENTS,
                sequence=last_seq,
                record_id=last_record["event_id"],
                record_hash=last_record["event_hash"],
            )
            _write_checkpoint_atomic(events_dir, new_checkpoint)

    return {
        "chain_type": chain_type,
        "discarded": discarded,
        "audit_event": audit_event,
    }


# ---------------------------------------------------------------------------
# Exclusive review lock
# ---------------------------------------------------------------------------


def _lock_path(task_dir: str) -> str:
    base = _resolve_task_dir(task_dir)
    path = os.path.realpath(os.path.join(base, REVIEW_LOCK_NAME))
    if os.path.commonpath([base, path]) != base:
        raise ReviewIntegrityError("unsafe review-lock path")
    return path


def acquire_review_lock(
    task_dir: str,
    *,
    reviewer_id: str,
    reviewer_display_name: str,
    created_at_utc: str,
) -> dict:
    """Acquire the task-local exclusive review lock.

    Fails closed if a lock already exists, or if an existing lock file is
    malformed or unreadable. Returns the lock record (including the token
    needed for release). Age alone is never treated as abandonment.
    """
    _validate_reviewer(reviewer_id, reviewer_display_name)
    _validate_timestamp(created_at_utc, "lock.created_at_utc")
    path = _lock_path(task_dir)

    if os.path.exists(path):
        # Fail closed: report the existing lock if readable, otherwise fail.
        try:
            existing = _read_json_file(path, "review lock")
            holder = existing.get("reviewer_id", "<unknown>")
        except ReviewIntegrityError:
            raise ReviewIntegrityError(
                "review lock exists but is malformed or unreadable; "
                "failing closed (use explicit recovery with reviewer "
                "identity and reason)"
            )
        raise ReviewIntegrityError(
            f"review lock already held by {holder!r}; "
            "concurrent review is not allowed"
        )

    lock = {
        "schema_version": SCHEMA_VERSION,
        "lock_token": uuid.uuid4().hex,
        "process_id": os.getpid(),
        "hostname": socket.gethostname(),
        "created_at_utc": created_at_utc,
        "reviewer_id": reviewer_id,
        "reviewer_display_name": reviewer_display_name,
    }
    _atomic_create_exclusive(path, _canonical_bytes(lock) + b"\n")
    return lock


def read_review_lock(task_dir: str) -> dict | None:
    """Return the current lock record, or None when no lock exists.

    A malformed lock raises ReviewIntegrityError (fail closed).
    """
    path = _lock_path(task_dir)
    if not os.path.exists(path):
        return None
    lock = _read_json_file(path, "review lock")
    for field in ("lock_token", "process_id", "hostname", "created_at_utc"):
        if field not in lock:
            raise ReviewIntegrityError(
                f"review lock missing field {field!r}; failing closed"
            )
    return lock


def release_review_lock(task_dir: str, *, lock_token: str) -> None:
    """Release the caller's lock, verified by token.

    Only removes the lock when the presented token matches the held lock.
    A malformed lock fails closed (use explicit recovery instead).
    """
    if not isinstance(lock_token, str) or not lock_token:
        raise ReviewIntegrityError("lock_token must be a non-empty string")
    path = _lock_path(task_dir)
    lock = read_review_lock(task_dir)
    if lock is None:
        raise ReviewIntegrityError("no review lock to release")
    if lock["lock_token"] != lock_token:
        raise ReviewIntegrityError("lock_token does not match the held lock")
    try:
        os.unlink(path)
    except OSError as exc:
        raise ReviewIntegrityError("failed to remove review lock") from exc


def recover_review_lock(
    task_dir: str,
    *,
    reviewer_id: str,
    reviewer_display_name: str,
    reason: str,
    timestamp_utc: str,
) -> dict:
    """Explicit low-level lock recovery primitive.

    Removes an existing lock regardless of its state and records a
    LOCK_RECOVERED audit event with the recovering reviewer's identity and
    reason. Age alone is never sufficient; recovery is always explicit.
    """
    _validate_reviewer(reviewer_id, reviewer_display_name)
    if not isinstance(reason, str) or not reason.strip():
        raise ReviewIntegrityError("lock recovery requires a non-empty reason")
    _validate_timestamp(timestamp_utc, "lock.recovery timestamp_utc")
    path = _lock_path(task_dir)

    prior: dict | None
    lock_was_malformed = False
    if os.path.exists(path):
        try:
            prior = _read_json_file(path, "review lock")
        except ReviewIntegrityError:
            prior = None  # malformed lock; still recoverable explicitly
            lock_was_malformed = True
        try:
            os.unlink(path)
        except OSError as exc:
            raise ReviewIntegrityError(
                "failed to remove existing review lock during recovery"
            ) from exc
    else:
        prior = None

    event = create_review_event(
        task_dir,
        event_type="LOCK_RECOVERED",
        reviewer_id=reviewer_id,
        reviewer_display_name=reviewer_display_name,
        timestamp_utc=timestamp_utc,
        reason=reason,
        details={
            "recovered_lock": prior,
            "lock_was_malformed": lock_was_malformed,
        },
    )
    return {"recovered_lock": prior, "audit_event": event}
