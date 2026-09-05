"""Phase 1B.3C.2B.2C Slice 1 — deterministic event planner and recovery receipt.

Fully offline (zero network access). Tests use
tempfile.TemporaryDirectory() for isolation.

Covers the Slice 1 primitives in app/services/review_integrity.py:

- plan_review_event(): deterministic no-write planner that shares event
  construction with create_review_event_file()
- create_recovery_receipt() / read_recovery_receipt(): standalone
  immutable recovery receipts at
  review-recovery/transaction-resumed-<transaction_id>.json
"""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from app.services import provenance as prov
from app.services import review_integrity as ri

REVIEWER_ID = "rick"
REVIEWER_NAME = "Rick Gamboa"
TIMESTAMP = "2026-09-05T00:00:00Z"
TIMESTAMP_LATER = "2026-09-05T01:00:00Z"
EVENT_ID_A = "a" * 32
EVENT_ID_B = "b" * 32
HASH_A = "a" * 64
HASH_B = "b" * 64
TRANSACTION_ID_A = "1" * 32
TRANSACTION_ID_B = "2" * 32
GENESIS_HASH = "0" * 64

RECOVERY_RECEIPT_FIELDS = {
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
}


class _NetworkBlocker:
    """Raise AssertionError on any network attempt (test plan section 6.14)."""

    def __init__(self) -> None:
        self._patchers = []

    def start(self) -> None:
        def _blocked(*args, **kwargs):
            raise AssertionError("network access is not allowed in tests")

        for target in (
            "socket.socket",
            "socket.create_connection",
            "socket.getaddrinfo",
        ):
            patcher = mock.patch(target, side_effect=_blocked)
            patcher.start()
            self._patchers.append(patcher)

    def stop(self) -> None:
        for patcher in self._patchers:
            patcher.stop()
        self._patchers = []


def _tree_snapshot(base: str) -> dict:
    """Map every directory and file under base: relative path -> bytes/None."""
    snapshot = {}
    for root, dirs, files in os.walk(base):
        for name in dirs:
            snapshot[os.path.relpath(os.path.join(root, name), base)] = None
        for name in files:
            path = os.path.join(root, name)
            with open(path, "rb") as handle:
                snapshot[os.path.relpath(path, base)] = handle.read()
    return snapshot


def _unsigned(record: dict, hash_field: str) -> dict:
    return {k: v for k, v in record.items() if k != hash_field}


class _Slice1TestBase(unittest.TestCase):
    """Temp task directory plus a hard network block for every test."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.task_dir = self._tmp.name
        self._network = _NetworkBlocker()
        self._network.start()
        self.addCleanup(self._network.stop)

    def _plan(self, **overrides):
        kwargs = {
            "event_type": "CLAIM_VERIFIED",
            "reviewer_id": REVIEWER_ID,
            "reviewer_display_name": REVIEWER_NAME,
            "timestamp_utc": TIMESTAMP,
            "event_id": EVENT_ID_B,
            "manifest_hash_before": HASH_A,
            "manifest_hash_after": HASH_B,
        }
        kwargs.update(overrides)
        return ri.plan_review_event(self.task_dir, **kwargs)

    def _commit_event(self, *, event_id: str, event_type: str = "LOCK_ACQUIRED"):
        event = ri.create_review_event_file(
            self.task_dir,
            event_type=event_type,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=TIMESTAMP,
            event_id=event_id,
        )
        ri.advance_review_event_checkpoint(
            self.task_dir,
            sequence=event["sequence"],
            event_id=event["event_id"],
            event_hash=event["event_hash"],
        )
        return event

    def _create_receipt(self, **overrides):
        kwargs = {
            "transaction_id": TRANSACTION_ID_A,
            "interrupted_stage": "EVENT_CREATED",
            "resuming_reviewer_id": REVIEWER_ID,
            "resuming_reviewer_display_name": REVIEWER_NAME,
            "reason": "resume after interruption",
            "resumed_at_utc": TIMESTAMP_LATER,
            "resulting_manifest_hash": HASH_A,
            "resulting_audit_chain_head": HASH_B,
        }
        kwargs.update(overrides)
        return ri.create_recovery_receipt(self.task_dir, **kwargs)

    def _receipt_path(self, transaction_id: str = TRANSACTION_ID_A) -> str:
        return os.path.join(
            self.task_dir,
            "review-recovery",
            f"transaction-resumed-{transaction_id}.json",
        )


class TestPlanReviewEvent(_Slice1TestBase):
    """Deterministic, no-write event planning (test plan section 6.16)."""

    def test_plan_review_event_deterministic(self):
        first = self._plan()
        second = self._plan()
        self.assertEqual(first, second)
        self.assertEqual(first["sequence"], 1)
        self.assertEqual(first["event_id"], EVENT_ID_B)
        self.assertEqual(first["previous_event_hash"], GENESIS_HASH)
        self.assertEqual(
            first["event_hash"],
            prov.canonical_sha256(_unsigned(first, "event_hash")),
        )

    def test_plan_review_event_requires_event_id(self):
        with self.assertRaises(TypeError):
            ri.plan_review_event(
                self.task_dir,
                event_type="CLAIM_VERIFIED",
                reviewer_id=REVIEWER_ID,
                reviewer_display_name=REVIEWER_NAME,
                timestamp_utc=TIMESTAMP,
            )

    def test_plan_review_event_validates_event_id(self):
        for bad in (None, "", "A" * 32, "g" * 32, "a" * 31, "a" * 33, 123):
            with self.assertRaises(ri.ReviewIntegrityError, msg=repr(bad)):
                self._plan(event_id=bad)

    def test_plan_review_event_validates_inputs(self):
        bad_calls = (
            {"event_type": "NO_SUCH_TYPE"},
            {"event_type": "CLAIM_RETRACTED"},  # requires a non-empty reason
            {"reviewer_id": "RICK"},
            {"reviewer_id": ""},
            {"reviewer_display_name": ""},
            {"reviewer_display_name": "bad\nname"},
            {"timestamp_utc": "not-a-timestamp"},
            {"timestamp_utc": "2026-09-05 00:00:00"},  # no UTC offset
            {"manifest_hash_before": "xyz"},
            {"manifest_hash_after": "A" * 64},
            {"details": ["not-a-dict"]},
        )
        for overrides in bad_calls:
            with self.assertRaises(ri.ReviewIntegrityError, msg=repr(overrides)):
                self._plan(**overrides)

    def test_plan_review_event_validates_committed_chain(self):
        committed = self._commit_event(event_id=EVENT_ID_A)
        # Tamper with the committed event file: the chain must fail closed.
        path = os.path.join(
            self.task_dir,
            "review-events",
            f"{committed['sequence']:06d}_{EVENT_ID_A}.json",
        )
        with open(path, "rb") as handle:
            raw = handle.read()
        with open(path, "wb") as handle:
            handle.write(raw.replace(b"LOCK_ACQUIRED", b"LOCK_RELEASED"))
        with self.assertRaises(ri.ReviewIntegrityError):
            self._plan()

    def test_plan_review_event_rejects_duplicate_event_id(self):
        self._commit_event(event_id=EVENT_ID_A)
        with self.assertRaises(ri.ReviewIntegrityError):
            self._plan(event_id=EVENT_ID_A)

    def test_plan_review_event_no_writes(self):
        self._commit_event(event_id=EVENT_ID_A)
        manifest_path = os.path.join(self.task_dir, "provenance_manifest.json")
        with open(manifest_path, "wb") as handle:
            handle.write(b'{"task": {"task_id": "task-001"}}\n')
        before = _tree_snapshot(self.task_dir)
        planned = self._plan()
        after = _tree_snapshot(self.task_dir)
        self.assertEqual(before, after)
        self.assertEqual(planned["sequence"], 2)
        self.assertNotIn("review-recovery", after)

    def test_plan_then_create_exact_equality(self):
        planned = self._plan()
        created = ri.create_review_event_file(
            self.task_dir,
            event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=TIMESTAMP,
            event_id=EVENT_ID_B,
            manifest_hash_before=HASH_A,
            manifest_hash_after=HASH_B,
        )
        self.assertEqual(planned, created)
        self.assertEqual(planned["event_id"], created["event_id"])
        self.assertEqual(planned["event_hash"], created["event_hash"])

    def test_planned_event_drift_fails_closed(self):
        planned = self._plan()
        # Advance the chain head after planning: the plan is now stale.
        self._commit_event(event_id=EVENT_ID_A)
        drifted = ri.create_review_event_file(
            self.task_dir,
            event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=TIMESTAMP,
            event_id=EVENT_ID_B,
            manifest_hash_before=HASH_A,
            manifest_hash_after=HASH_B,
        )
        self.assertNotEqual(planned["event_hash"], drifted["event_hash"])
        # Committing with the stale planned identity/hash fails closed.
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.advance_review_event_checkpoint(
                self.task_dir,
                sequence=planned["sequence"],
                event_id=planned["event_id"],
                event_hash=planned["event_hash"],
            )


class TestRecoveryReceipt(_Slice1TestBase):
    """Standalone immutable recovery receipts (proposal section 2.8)."""

    def test_recovery_receipt_create_and_read_roundtrip(self):
        receipt = self._create_receipt()
        self.assertEqual(receipt["schema_version"], "1.2.0")
        self.assertEqual(receipt["receipt_type"], "TRANSACTION_RESUMED")
        self.assertEqual(set(receipt), RECOVERY_RECEIPT_FIELDS)
        self.assertEqual(
            receipt["receipt_hash"],
            prov.canonical_sha256(_unsigned(receipt, "receipt_hash")),
        )
        path = self._receipt_path()
        self.assertTrue(os.path.isfile(path))
        with open(path, "rb") as handle:
            raw = handle.read()
        self.assertEqual(raw, prov.canonical_json_bytes(receipt) + b"\n")
        loaded = ri.read_recovery_receipt(
            self.task_dir, transaction_id=TRANSACTION_ID_A
        )
        self.assertEqual(loaded, receipt)
        self.assertIsNone(
            ri.read_recovery_receipt(self.task_dir, transaction_id=TRANSACTION_ID_B)
        )

    def test_recovery_receipt_field_validation(self):
        bad_calls = (
            {"transaction_id": "A" * 32},
            {"transaction_id": "a" * 31},
            {"transaction_id": "../escape"},
            {"interrupted_stage": "NO_SUCH_STAGE"},
            {"resuming_reviewer_id": "RICK"},
            {"resuming_reviewer_display_name": "bad\nname"},
            {"reason": ""},
            {"reason": "   "},
            {"resumed_at_utc": "not-a-timestamp"},
            {"resulting_manifest_hash": "xyz"},
            {"resulting_audit_chain_head": "B" * 64},
        )
        for overrides in bad_calls:
            with self.assertRaises(ri.ReviewIntegrityError, msg=repr(overrides)):
                self._create_receipt(**overrides)
        # Rejected creates must leave no directory or file behind.
        self.assertEqual(_tree_snapshot(self.task_dir), {})

    def test_recovery_receipt_exclusive_immutable_creation(self):
        receipt = self._create_receipt()
        path = self._receipt_path()
        with open(path, "rb") as handle:
            before = handle.read()
        with self.assertRaises(ri.ReviewIntegrityError):
            self._create_receipt()
        with open(path, "rb") as handle:
            after = handle.read()
        self.assertEqual(before, after)
        loaded = ri.read_recovery_receipt(
            self.task_dir, transaction_id=TRANSACTION_ID_A
        )
        self.assertEqual(loaded, receipt)

    def test_recovery_receipt_exact_existing_idempotent(self):
        receipt = self._create_receipt()
        path = self._receipt_path()
        with open(path, "rb") as handle:
            before = handle.read()
        first = ri.read_recovery_receipt(
            self.task_dir, transaction_id=TRANSACTION_ID_A
        )
        second = ri.read_recovery_receipt(
            self.task_dir, transaction_id=TRANSACTION_ID_A
        )
        self.assertEqual(first, receipt)
        self.assertEqual(second, receipt)
        with open(path, "rb") as handle:
            after = handle.read()
        self.assertEqual(before, after)

    def test_recovery_receipt_malformed_fails_closed(self):
        os.makedirs(os.path.join(self.task_dir, "review-recovery"))
        path = self._receipt_path()
        with open(path, "wb") as handle:
            handle.write(b"not json\n")
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.read_recovery_receipt(self.task_dir, transaction_id=TRANSACTION_ID_A)

    def test_recovery_receipt_modified_fails_closed(self):
        receipt = self._create_receipt()
        tampered = dict(receipt, reason="tampered reason")
        path = self._receipt_path()
        with open(path, "wb") as handle:
            handle.write(prov.canonical_json_bytes(tampered) + b"\n")
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.read_recovery_receipt(self.task_dir, transaction_id=TRANSACTION_ID_A)

    def test_recovery_receipt_identity_mismatch_fails_closed(self):
        self._create_receipt()
        # Move the receipt to another transaction id's path: content/path
        # identity mismatch must fail closed even though the self-hash is
        # valid for the stored content.
        os.replace(self._receipt_path(), self._receipt_path(TRANSACTION_ID_B))
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.read_recovery_receipt(
                self.task_dir, transaction_id=TRANSACTION_ID_B
            )
        self.assertIsNone(
            ri.read_recovery_receipt(self.task_dir, transaction_id=TRANSACTION_ID_A)
        )

    def test_recovery_receipt_path_escaping_rejected(self):
        bad_ids = (
            "../escape",
            "..\\escape",
            "a/b",
            "a\\b",
            "A" * 32,
            "g" * 32,
            "",
            "a" * 31,
        )
        for bad in bad_ids:
            with self.assertRaises(ri.ReviewIntegrityError, msg=repr(bad)):
                ri.read_recovery_receipt(self.task_dir, transaction_id=bad)
            with self.assertRaises(ri.ReviewIntegrityError, msg=repr(bad)):
                self._create_receipt(transaction_id=bad)
        self.assertEqual(_tree_snapshot(self.task_dir), {})

    def test_recovery_receipt_no_event_or_checkpoint_mutation(self):
        self._commit_event(event_id=EVENT_ID_A)
        before = _tree_snapshot(self.task_dir)
        self._create_receipt()
        ri.read_recovery_receipt(self.task_dir, transaction_id=TRANSACTION_ID_A)
        after = _tree_snapshot(self.task_dir)
        added = set(after) - set(before)
        self.assertEqual(
            added,
            {
                "review-recovery",
                os.path.join(
                    "review-recovery",
                    f"transaction-resumed-{TRANSACTION_ID_A}.json",
                ),
            },
        )
        for rel_path, content in before.items():
            self.assertEqual(after[rel_path], content, msg=rel_path)


if __name__ == "__main__":
    unittest.main()
