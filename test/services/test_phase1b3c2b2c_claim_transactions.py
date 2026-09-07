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

import argparse
import contextlib
import copy
import hashlib
import io
import os
import tempfile
import unittest
from unittest import mock

import pilot_review
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


# ---------------------------------------------------------------------------
# Slice 2 — verify-claim command transaction tests
# ---------------------------------------------------------------------------

TASK_ID = "task-001"
CLAIM_ID_A = "claim-" + "a" * 32
CLAIM_ID_B = "claim-" + "b" * 32
HTTPS_SOURCE = "https://example.com/evidence"
HTTP_SOURCE = "http://example.com/evidence"
NON_URL_SOURCE = "not-a-url"
RETRACTION_REASON = "no longer supported by source"
SECOND_REVIEWER_ID = "casey"
SECOND_REVIEWER_NAME = "Casey Reviewer"


class _ClaimCommandTestBase(_Slice1TestBase):
    """Manifest fixtures plus a neutralized policy gate for command tests.

    The policy gate is mocked per-test for isolation: hardening.toml is a
    local, gitignored operator file, and the sections covered here (6.4,
    6.5, 6.7, 6.13, 6.16) exercise claim-transaction behavior, not policy
    loading. The gate itself is covered by TestVerifyClaimPolicyGate.
    """

    def setUp(self) -> None:
        super().setUp()
        policy_gate = mock.patch.object(pilot_review, "_require_pilot_policy")
        policy_gate.start()
        self.addCleanup(policy_gate.stop)

    def _write_manifest(self, claims) -> dict:
        manifest = prov.build_manifest(
            task=prov.build_task_section(
                task_id=TASK_ID,
                topic="BrainTrustCrypto pilot task",
                pilot_profile="braintrustcrypto",
                created_at=TIMESTAMP,
                review_status="NEEDS_HUMAN_REVIEW",
            ),
            factual_claims=claims,
        )
        path = os.path.join(self.task_dir, "provenance_manifest.json")
        with open(path, "wb") as handle:
            handle.write(prov.canonical_json_bytes(manifest) + b"\n")
        return manifest

    def _unverified_claim(self, claim_id=CLAIM_ID_A, *,
                          source_url=HTTPS_SOURCE, supporting_sources=None,
                          text="Claim text one"):
        return prov.build_claim(
            claim_text=text,
            source_url=source_url,
            supporting_sources=supporting_sources,
            claim_id=claim_id,
        )

    def _run_verify(self, *, claim_id=CLAIM_ID_A, reviewer_id=REVIEWER_ID,
                    reviewer_display_name=REVIEWER_NAME, notes=None):
        return pilot_review._run_claim_transaction(
            self.task_dir,
            operation="verify-claim",
            claim_id=claim_id,
            reviewer_id=reviewer_id,
            reviewer_display_name=reviewer_display_name,
            notes=notes,
        )

    def _load_post_manifest(self) -> dict:
        manifest, _path, _sha = pilot_review._load_manifest(self.task_dir)
        return manifest

    def _transaction_artifacts(self) -> dict:
        names = set(os.listdir(self.task_dir))
        return {
            "journal": "review-transaction.json" in names,
            "lock": "review.lock" in names,
            "proposed_temps": sorted(
                name for name in names
                if name.startswith(".proposed_manifest.json.")
            ),
            "recovery_dir": os.path.exists(
                os.path.join(self.task_dir, "review-recovery")
            ),
        }

    def _lock_path(self) -> str:
        return os.path.join(self.task_dir, "review.lock")

    def _journal_path(self) -> str:
        return os.path.join(self.task_dir, "review-transaction.json")

    def _hold_foreign_lock(self) -> dict:
        """Hold the task lock with a foreign (other reviewer's) token."""
        return ri.acquire_review_lock(
            self.task_dir,
            reviewer_id=SECOND_REVIEWER_ID,
            reviewer_display_name=SECOND_REVIEWER_NAME,
            created_at_utc=TIMESTAMP,
        )

    def _seed_foreign_journal(self) -> dict:
        """Create a journal as if left by an interrupted foreign transaction."""
        return ri.create_transaction_journal(
            self.task_dir,
            operation="verify-claim",
            task_id=TASK_ID,
            claim_id=CLAIM_ID_A,
            claim_notes="foreign transaction notes",
            starting_manifest_hash=HASH_A,
            proposed_manifest_hash=HASH_B,
            proposed_manifest_relative_path=(
                ".proposed_manifest.json." + "7" * 32 + ".tmp"
            ),
            snapshot_relative_path=f"manifest-history/000001_{HASH_A}.json",
            expected_event_id=EVENT_ID_A,
            expected_event_hash=HASH_B,
            lock_token="9" * 32,
            created_at_utc=TIMESTAMP,
            original_reviewer_id=SECOND_REVIEWER_ID,
            original_reviewer_display_name=SECOND_REVIEWER_NAME,
        )

    def _verified_claim(self, claim_id=CLAIM_ID_A, *, text="Verified claim"):
        return prov.build_claim(
            claim_text=text,
            source_url=HTTPS_SOURCE,
            status="VERIFIED",
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            review_timestamp_utc=TIMESTAMP,
            claim_id=claim_id,
        )

    def _retracted_claim(self, claim_id=CLAIM_ID_A, *, text="Retracted claim"):
        return prov.build_claim(
            claim_text=text,
            source_url=HTTPS_SOURCE,
            status="RETRACTED",
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            review_timestamp_utc=TIMESTAMP,
            notes="fixture retraction reason",
            claim_id=claim_id,
        )

    def _run_retract(self, *, claim_id=CLAIM_ID_A, reviewer_id=REVIEWER_ID,
                     reviewer_display_name=REVIEWER_NAME,
                     reason=RETRACTION_REASON):
        return pilot_review._run_claim_transaction(
            self.task_dir,
            operation="retract-claim",
            claim_id=claim_id,
            reviewer_id=reviewer_id,
            reviewer_display_name=reviewer_display_name,
            reason=reason,
        )


class TestVerifyClaimTransitions(_ClaimCommandTestBase):
    """Valid and invalid claim transitions (test plan section 6.4)."""

    def test_verify_unverified_claim(self):
        before = self._write_manifest([
            self._unverified_claim(),
            self._unverified_claim(CLAIM_ID_B, text="Claim text two"),
        ])
        result = self._run_verify(notes="solid evidence")
        post = self._load_post_manifest()

        # Exactly the approved five-field mutation on the target claim only.
        expected = copy.deepcopy(before)
        for claim in expected["factual_claims"]:
            if claim["claim_id"] == CLAIM_ID_A:
                claim["status"] = "VERIFIED"
                claim["reviewer_id"] = REVIEWER_ID
                claim["reviewer_display_name"] = REVIEWER_NAME
                claim["review_timestamp_utc"] = result["review_timestamp_utc"]
                claim["notes"] = "solid evidence"
        self.assertEqual(post, expected)

        self.assertEqual(result["operation"], "verify-claim")
        event = result["event"]
        self.assertEqual(event["event_type"], "CLAIM_VERIFIED")
        self.assertEqual(
            event["manifest_hash_before"], prov.canonical_sha256(before)
        )
        self.assertEqual(
            event["manifest_hash_after"], prov.canonical_sha256(post)
        )
        self.assertTrue(
            os.path.isfile(
                os.path.join(self.task_dir, result["snapshot_relative_path"])
            )
        )
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(
            [committed_event["event_id"] for committed_event in committed],
            [event["event_id"]],
        )

    def test_verify_already_verified_claim(self):
        self._write_manifest([
            prov.build_claim(
                claim_text="Already verified claim",
                source_url=HTTPS_SOURCE,
                status="VERIFIED",
                reviewer_id=REVIEWER_ID,
                reviewer_display_name=REVIEWER_NAME,
                review_timestamp_utc=TIMESTAMP,
                claim_id=CLAIM_ID_A,
            )
        ])
        with self.assertRaises(pilot_review.ReviewError) as caught:
            self._run_verify()
        self.assertIn("CLAIM_NOT_UNVERIFIED", str(caught.exception))
        artifacts = self._transaction_artifacts()
        self.assertFalse(artifacts["journal"])
        self.assertFalse(artifacts["lock"])

    def test_verify_retracted_claim(self):
        self._write_manifest([
            prov.build_claim(
                claim_text="Retracted claim",
                source_url=HTTPS_SOURCE,
                status="RETRACTED",
                reviewer_id=REVIEWER_ID,
                reviewer_display_name=REVIEWER_NAME,
                review_timestamp_utc=TIMESTAMP,
                notes="fixture retraction reason",
                claim_id=CLAIM_ID_A,
            )
        ])
        with self.assertRaises(pilot_review.ReviewError) as caught:
            self._run_verify()
        self.assertIn("CLAIM_NOT_UNVERIFIED", str(caught.exception))
        artifacts = self._transaction_artifacts()
        self.assertFalse(artifacts["journal"])
        self.assertFalse(artifacts["lock"])


class TestVerifyClaimSupportingSources(_ClaimCommandTestBase):
    """HTTPS supporting-source requirements (test plan section 6.5)."""

    def test_verify_no_https_source(self):
        self._write_manifest([self._unverified_claim(source_url=HTTP_SOURCE)])
        with self.assertRaises(pilot_review.ReviewError) as caught:
            self._run_verify()
        self.assertIn("NO_SUPPORTING_SOURCE", str(caught.exception))

    def test_verify_no_source_at_all(self):
        self._write_manifest([self._unverified_claim(source_url=NON_URL_SOURCE)])
        with self.assertRaises(pilot_review.ReviewError) as caught:
            self._run_verify()
        self.assertIn("NO_SUPPORTING_SOURCE", str(caught.exception))

    def test_verify_https_in_supporting_sources(self):
        self._write_manifest([
            self._unverified_claim(
                source_url=HTTP_SOURCE, supporting_sources=[HTTPS_SOURCE]
            )
        ])
        result = self._run_verify()
        post = self._load_post_manifest()
        self.assertEqual(post["factual_claims"][0]["status"], "VERIFIED")
        self.assertEqual(result["event"]["event_type"], "CLAIM_VERIFIED")


class TestVerifyClaimReviewerValidation(_ClaimCommandTestBase):
    """Reviewer identity validation (test plan section 6.7)."""

    def test_verify_invalid_reviewer_id(self):
        self._write_manifest([self._unverified_claim()])
        for bad in ("RICK", "", "a" * 65, "bad id!", "-bad"):
            with self.assertRaises(
                pilot_review.ReviewError, msg=repr(bad)
            ) as caught:
                self._run_verify(reviewer_id=bad)
            self.assertIn("REVIEWER_ID_INVALID", str(caught.exception))

    def test_verify_invalid_reviewer_name(self):
        self._write_manifest([self._unverified_claim()])
        for bad in ("", "x" * 129, "bad\nname", "\t"):
            with self.assertRaises(
                pilot_review.ReviewError, msg=repr(bad)
            ) as caught:
                self._run_verify(reviewer_display_name=bad)
            self.assertIn("REVIEWER_NAME_INVALID", str(caught.exception))


class TestVerifyClaimNoAutoApproval(_ClaimCommandTestBase):
    """No automatic approval (test plan section 6.13)."""

    def test_verify_does_not_approve_task(self):
        self._write_manifest([self._unverified_claim()])
        self._run_verify()
        post = self._load_post_manifest()
        self.assertEqual(
            post["task"]["review_status"], "NEEDS_HUMAN_REVIEW"
        )


class TestVerifyClaimPlanningDeterminism(_ClaimCommandTestBase):
    """Deterministic in-memory planning (test plan section 6.16)."""

    def test_proposed_manifest_planned_in_memory_before_event_and_journal(self):
        self._write_manifest([self._unverified_claim()])
        manifest_tree = _tree_snapshot(self.task_dir)

        plan = pilot_review._plan_claim_transaction(
            self.task_dir,
            operation="verify-claim",
            claim_id=CLAIM_ID_A,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            notes="planned notes",
        )

        # Canonical, hash-consistent in-memory plan.
        self.assertEqual(
            plan["proposed_manifest_bytes"],
            prov.canonical_json_bytes(plan["proposed_manifest"]),
        )
        self.assertEqual(
            plan["proposed_manifest_hash"],
            prov.canonical_sha256(plan["proposed_manifest"]),
        )
        self.assertEqual(
            plan["starting_manifest_hash"],
            prov.canonical_sha256(plan["starting_manifest"]),
        )
        planned_event = plan["planned_event"]
        self.assertEqual(
            planned_event["manifest_hash_before"], plan["starting_manifest_hash"]
        )
        self.assertEqual(
            planned_event["manifest_hash_after"], plan["proposed_manifest_hash"]
        )

        # The journal records exactly the planned values.
        journal = ri.read_transaction_journal(self.task_dir)
        self.assertIsNotNone(journal)
        self.assertEqual(
            journal["starting_manifest_hash"], plan["starting_manifest_hash"]
        )
        self.assertEqual(
            journal["proposed_manifest_hash"], plan["proposed_manifest_hash"]
        )
        self.assertEqual(journal["expected_event_id"], planned_event["event_id"])
        self.assertEqual(
            journal["expected_event_hash"], planned_event["event_hash"]
        )

        # Planning wrote only the lock and journal: no event file, snapshot,
        # proposed-manifest temp, or recovery receipt exists yet.
        after_tree = _tree_snapshot(self.task_dir)
        added = set(after_tree) - set(manifest_tree)
        self.assertEqual(added, {"review.lock", "review-transaction.json"})
        self.assertNotIn("review-recovery", after_tree)

    def test_durable_proposed_manifest_matches_in_memory_plan(self):
        self._write_manifest([self._unverified_claim()])
        plan = pilot_review._plan_claim_transaction(
            self.task_dir,
            operation="verify-claim",
            claim_id=CLAIM_ID_A,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            notes="durable notes",
        )
        durable = pilot_review._execute_claim_transaction_durable(
            self.task_dir, plan
        )
        temp_path = durable["proposed_manifest_temp_path"]
        self.assertTrue(os.path.isfile(temp_path))
        with open(temp_path, "rb") as handle:
            raw = handle.read()
        self.assertEqual(raw, plan["proposed_manifest_bytes"])
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(), plan["proposed_manifest_hash"]
        )
        journal = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(journal["transaction_stage"], "EVENT_CREATED")


class TestVerifyClaimDirectCompletionCleanup(_ClaimCommandTestBase):
    """Direct completion cleanup (test plan sections 6.8/6.10)."""

    def test_direct_completion_leaves_no_transaction_artifacts(self):
        self._write_manifest([self._unverified_claim()])
        result = self._run_verify()
        artifacts = self._transaction_artifacts()
        self.assertFalse(artifacts["journal"])
        self.assertFalse(artifacts["lock"])
        self.assertEqual(artifacts["proposed_temps"], [])
        self.assertFalse(artifacts["recovery_dir"])

        # Committed artifacts remain and validate.
        self.assertTrue(
            os.path.isfile(
                os.path.join(self.task_dir, result["snapshot_relative_path"])
            )
        )
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        self.assertEqual(committed[0]["event_type"], "CLAIM_VERIFIED")
        post = self._load_post_manifest()
        self.assertEqual(
            prov.canonical_sha256(post), result["proposed_manifest_hash"]
        )


class TestVerifyClaimPolicyGate(_ClaimCommandTestBase):
    """Policy gate invocation and fail-closed behavior (proposal §5.6)."""

    def test_verify_claim_policy_gate_fails_closed_before_transaction(self):
        self._write_manifest([self._unverified_claim()])
        before = _tree_snapshot(self.task_dir)
        with mock.patch.object(
            pilot_review,
            "_require_pilot_policy",
            side_effect=pilot_review.ReviewError(
                "pilot policy failure: sentinel"
            ),
        ) as gate:
            with self.assertRaises(pilot_review.ReviewError) as caught:
                self._run_verify()
        self.assertIn("pilot policy failure", str(caught.exception))
        gate.assert_called_once_with()
        self.assertEqual(_tree_snapshot(self.task_dir), before)


class TestRetractClaimTransitions(_ClaimCommandTestBase):
    """Valid and invalid retract transitions (test plan section 6.4)."""

    def test_retract_unverified_claim(self):
        before = self._write_manifest([
            self._unverified_claim(),
            self._unverified_claim(CLAIM_ID_B, text="Claim text two"),
        ])
        result = self._run_retract()
        post = self._load_post_manifest()

        # Exactly the approved five-field mutation on the target claim only;
        # for retract-claim the notes field records the retraction reason.
        expected = copy.deepcopy(before)
        for claim in expected["factual_claims"]:
            if claim["claim_id"] == CLAIM_ID_A:
                claim["status"] = "RETRACTED"
                claim["reviewer_id"] = REVIEWER_ID
                claim["reviewer_display_name"] = REVIEWER_NAME
                claim["review_timestamp_utc"] = result["review_timestamp_utc"]
                claim["notes"] = RETRACTION_REASON
        self.assertEqual(post, expected)

        self.assertEqual(result["operation"], "retract-claim")
        event = result["event"]
        self.assertEqual(event["event_type"], "CLAIM_RETRACTED")
        self.assertEqual(event["reason"], RETRACTION_REASON)
        self.assertEqual(
            event["manifest_hash_before"], prov.canonical_sha256(before)
        )
        self.assertEqual(
            event["manifest_hash_after"], prov.canonical_sha256(post)
        )
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(
            [committed_event["event_id"] for committed_event in committed],
            [event["event_id"]],
        )

    def test_retract_verified_claim(self):
        before = self._write_manifest([self._verified_claim()])
        result = self._run_retract(
            reviewer_id=SECOND_REVIEWER_ID,
            reviewer_display_name=SECOND_REVIEWER_NAME,
        )
        post = self._load_post_manifest()

        # The retracting reviewer's identity replaces the prior reviewer.
        expected = copy.deepcopy(before)
        claim = expected["factual_claims"][0]
        claim["status"] = "RETRACTED"
        claim["reviewer_id"] = SECOND_REVIEWER_ID
        claim["reviewer_display_name"] = SECOND_REVIEWER_NAME
        claim["review_timestamp_utc"] = result["review_timestamp_utc"]
        claim["notes"] = RETRACTION_REASON
        self.assertEqual(post, expected)
        self.assertEqual(result["event"]["event_type"], "CLAIM_RETRACTED")

    def test_retract_already_retracted_claim(self):
        self._write_manifest([self._retracted_claim()])
        with self.assertRaises(pilot_review.ReviewError) as caught:
            self._run_retract()
        self.assertIn("CLAIM_ALREADY_RETRACTED", str(caught.exception))
        artifacts = self._transaction_artifacts()
        self.assertFalse(artifacts["journal"])
        self.assertFalse(artifacts["lock"])


class TestRetractClaimReasonValidation(_ClaimCommandTestBase):
    """Required non-empty retraction reason (test plan section 6.6)."""

    def test_retract_without_reason(self):
        self._write_manifest([self._unverified_claim()])
        with self.assertRaises(pilot_review.ReviewError) as caught:
            self._run_retract(reason=None)
        self.assertIn("REASON_REQUIRED", str(caught.exception))

    def test_retract_empty_reason(self):
        self._write_manifest([self._unverified_claim()])
        with self.assertRaises(pilot_review.ReviewError) as caught:
            self._run_retract(reason="")
        self.assertIn("REASON_REQUIRED", str(caught.exception))

    def test_retract_whitespace_reason(self):
        self._write_manifest([self._unverified_claim()])
        with self.assertRaises(pilot_review.ReviewError) as caught:
            self._run_retract(reason="   ")
        self.assertIn("REASON_REQUIRED", str(caught.exception))


class TestRetractClaimReviewerValidation(_ClaimCommandTestBase):
    """Reviewer identity validation for retract-claim (section 6.7)."""

    def test_retract_invalid_reviewer_id(self):
        self._write_manifest([self._unverified_claim()])
        for bad in ("RICK", "", "a" * 65, "bad id!", "-bad"):
            with self.assertRaises(
                pilot_review.ReviewError, msg=repr(bad)
            ) as caught:
                self._run_retract(reviewer_id=bad)
            self.assertIn("REVIEWER_ID_INVALID", str(caught.exception))

    def test_retract_invalid_reviewer_name(self):
        self._write_manifest([self._unverified_claim()])
        for bad in ("", "x" * 129, "bad\nname", "\t"):
            with self.assertRaises(
                pilot_review.ReviewError, msg=repr(bad)
            ) as caught:
                self._run_retract(reviewer_display_name=bad)
            self.assertIn("REVIEWER_NAME_INVALID", str(caught.exception))


class TestRetractClaimPreservation(_ClaimCommandTestBase):
    """History and unrelated-state preservation across a retraction (6.11)."""

    def test_retract_preserves_history_and_unrelated_state(self):
        before = self._write_manifest([
            self._unverified_claim(),
            self._unverified_claim(CLAIM_ID_B, text="Claim text two"),
        ])
        verify_result = self._run_verify()
        verified = self._load_post_manifest()
        verify_event = verify_result["event"]

        retract_result = self._run_retract(
            claim_id=CLAIM_ID_B, reason="source retracted the claim"
        )
        post = self._load_post_manifest()

        # Only claim B's five approved fields changed relative to `verified`.
        expected = copy.deepcopy(verified)
        for claim in expected["factual_claims"]:
            if claim["claim_id"] == CLAIM_ID_B:
                claim["status"] = "RETRACTED"
                claim["reviewer_id"] = REVIEWER_ID
                claim["reviewer_display_name"] = REVIEWER_NAME
                claim["review_timestamp_utc"] = retract_result[
                    "review_timestamp_utc"
                ]
                claim["notes"] = "source retracted the claim"
        self.assertEqual(post, expected)

        # Snapshots are immutable pre-mutation states, preserved in order.
        history = ri.list_manifest_history(self.task_dir)
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0], before)
        self.assertEqual(history[1], verified)
        snap1_path = os.path.join(
            self.task_dir, verify_result["snapshot_relative_path"]
        )
        with open(snap1_path, "rb") as handle:
            self.assertEqual(
                handle.read(), prov.canonical_json_bytes(before) + b"\n"
            )

        # The prior event is preserved unchanged as the chain prefix.
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 2)
        self.assertEqual(committed[0], verify_event)
        retract_event = retract_result["event"]
        self.assertEqual(committed[1], retract_event)
        self.assertEqual(retract_event["event_type"], "CLAIM_RETRACTED")
        self.assertEqual(
            retract_event["previous_event_hash"], verify_event["event_hash"]
        )
        self.assertEqual(
            retract_event["manifest_hash_before"],
            prov.canonical_sha256(verified),
        )
        self.assertEqual(
            retract_event["manifest_hash_after"],
            prov.canonical_sha256(post),
        )


class TestRetractClaimNoAutoApproval(_ClaimCommandTestBase):
    """No automatic approval or rejection (test plan section 6.13)."""

    def test_retract_does_not_approve_task(self):
        self._write_manifest([self._unverified_claim()])
        self._run_retract()
        post = self._load_post_manifest()
        self.assertEqual(
            post["task"]["review_status"], "NEEDS_HUMAN_REVIEW"
        )
        self.assertNotEqual(post["task"]["review_status"], "APPROVED")

    def test_retract_does_not_reject_task(self):
        self._write_manifest([self._unverified_claim()])
        self._run_retract()
        post = self._load_post_manifest()
        self.assertEqual(
            post["task"]["review_status"], "NEEDS_HUMAN_REVIEW"
        )
        self.assertNotEqual(post["task"]["review_status"], "REJECTED")


class TestRetractClaimDirectCompletionCleanup(_ClaimCommandTestBase):
    """Direct retract completion cleanup (sections 6.8/6.10)."""

    def test_retract_direct_completion_leaves_no_transaction_artifacts(self):
        self._write_manifest([self._unverified_claim()])
        result = self._run_retract()
        artifacts = self._transaction_artifacts()
        self.assertFalse(artifacts["journal"])
        self.assertFalse(artifacts["lock"])
        self.assertEqual(artifacts["proposed_temps"], [])
        self.assertFalse(artifacts["recovery_dir"])

        self.assertTrue(
            os.path.isfile(
                os.path.join(self.task_dir, result["snapshot_relative_path"])
            )
        )
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        self.assertEqual(committed[0]["event_type"], "CLAIM_RETRACTED")
        post = self._load_post_manifest()
        self.assertEqual(
            prov.canonical_sha256(post), result["proposed_manifest_hash"]
        )


class TestRetractClaimPolicyGate(_ClaimCommandTestBase):
    """Policy gate invocation and fail-closed behavior (proposal §5.6)."""

    def test_retract_claim_policy_gate_fails_closed_before_transaction(self):
        self._write_manifest([self._unverified_claim()])
        before = _tree_snapshot(self.task_dir)
        with mock.patch.object(
            pilot_review,
            "_require_pilot_policy",
            side_effect=pilot_review.ReviewError(
                "pilot policy failure: sentinel"
            ),
        ) as gate:
            with self.assertRaises(pilot_review.ReviewError) as caught:
                self._run_retract()
        self.assertIn("pilot policy failure", str(caught.exception))
        gate.assert_called_once_with()
        self.assertEqual(_tree_snapshot(self.task_dir), before)


class TestClaimTransactionJournalPayload(_ClaimCommandTestBase):
    """The journal records the exact Step-5 proposed target claim notes.

    Approved resume-payload correction amendment: verify-claim records the
    sanitized --notes value (null when omitted); retract-claim records the
    sanitized --reason as the claim notes value.
    """

    def _proposed_target_notes(self, plan):
        for claim in plan["proposed_manifest"].get("factual_claims", []):
            if claim.get("claim_id") == CLAIM_ID_A:
                return claim.get("notes")
        self.fail("proposed manifest is missing the target claim")

    def test_verify_journal_records_exact_proposed_notes(self):
        self._write_manifest([self._unverified_claim()])
        plan = pilot_review._plan_claim_transaction(
            self.task_dir,
            operation="verify-claim",
            claim_id=CLAIM_ID_A,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            notes="exact verify notes 123",
        )
        journal = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(journal["claim_notes"], "exact verify notes 123")
        self.assertEqual(
            journal["claim_notes"], self._proposed_target_notes(plan)
        )

    def test_retract_journal_records_reason_as_notes(self):
        self._write_manifest([self._verified_claim()])
        plan = pilot_review._plan_claim_transaction(
            self.task_dir,
            operation="retract-claim",
            claim_id=CLAIM_ID_A,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            reason="exact retract reason 456",
        )
        journal = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(journal["claim_notes"], "exact retract reason 456")
        self.assertEqual(
            journal["claim_notes"], self._proposed_target_notes(plan)
        )

    def test_verify_journal_omitted_notes_records_null(self):
        self._write_manifest([self._unverified_claim()])
        plan = pilot_review._plan_claim_transaction(
            self.task_dir,
            operation="verify-claim",
            claim_id=CLAIM_ID_A,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
        )
        journal = ri.read_transaction_journal(self.task_dir)
        self.assertIsNone(journal["claim_notes"])
        self.assertIsNone(self._proposed_target_notes(plan))


class TestClaimTransactionPreJournalLock(_ClaimCommandTestBase):
    """Pre-journal lock contention and refusal (test plan section 6.8).

    test_resume_with_existing_lock is explicitly deferred to Slice 3
    (resume-transaction command wiring).
    """

    def test_verify_with_existing_lock(self):
        self._write_manifest([self._unverified_claim()])
        foreign = self._hold_foreign_lock()
        with open(self._lock_path(), "rb") as handle:
            lock_bytes_before = handle.read()
        tree_before = _tree_snapshot(self.task_dir)

        with self.assertRaises(pilot_review.ReviewError) as caught:
            self._run_verify()

        # LOCK_HELD names the holder; the foreign token is neither
        # replaced nor released.
        message = str(caught.exception)
        self.assertIn("LOCK_HELD", message)
        self.assertIn(SECOND_REVIEWER_ID, message)
        with open(self._lock_path(), "rb") as handle:
            self.assertEqual(handle.read(), lock_bytes_before)
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], foreign["lock_token"])

        # No journal; no manifest/event/checkpoint mutation.
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))
        self.assertEqual(_tree_snapshot(self.task_dir), tree_before)

    def test_retract_with_existing_lock(self):
        self._write_manifest([self._unverified_claim()])
        foreign = self._hold_foreign_lock()
        with open(self._lock_path(), "rb") as handle:
            lock_bytes_before = handle.read()
        tree_before = _tree_snapshot(self.task_dir)

        with self.assertRaises(pilot_review.ReviewError) as caught:
            self._run_retract()

        message = str(caught.exception)
        self.assertIn("LOCK_HELD", message)
        self.assertIn(SECOND_REVIEWER_ID, message)
        with open(self._lock_path(), "rb") as handle:
            self.assertEqual(handle.read(), lock_bytes_before)
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], foreign["lock_token"])

        # No journal; no manifest/event/checkpoint mutation.
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))
        self.assertEqual(_tree_snapshot(self.task_dir), tree_before)

    def test_matching_lock_released_after_pre_journal_failure(self):
        self._write_manifest([self._unverified_claim()])
        tree_before = _tree_snapshot(self.task_dir)
        acquired = {}
        real_acquire = ri.acquire_review_lock

        def _capturing_acquire(*args, **kwargs):
            lock = real_acquire(*args, **kwargs)
            acquired["lock"] = lock
            return lock

        # Fail at Step 6 event planning: after lock acquisition (Step 3),
        # before journal creation (Step 7).
        with mock.patch.object(
            ri, "acquire_review_lock", side_effect=_capturing_acquire
        ), mock.patch.object(
            ri,
            "plan_review_event",
            side_effect=ri.ReviewIntegrityError(
                "sentinel pre-journal failure"
            ),
        ):
            with self.assertRaises(ri.ReviewIntegrityError) as caught:
                self._run_verify()

        self.assertIn("sentinel pre-journal failure", str(caught.exception))
        # The command acquired its own token before the failure...
        self.assertIn("lock", acquired)
        # ...and released exactly that matching token afterward.
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        # No newly retained journal; no manifest/event/checkpoint mutation.
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))
        artifacts = self._transaction_artifacts()
        self.assertFalse(artifacts["journal"])
        self.assertFalse(artifacts["lock"])
        self.assertEqual(artifacts["proposed_temps"], [])
        self.assertEqual(_tree_snapshot(self.task_dir), tree_before)

    def test_journal_present_before_lock_refusal(self):
        self._write_manifest([self._unverified_claim()])
        seeded = self._seed_foreign_journal()
        with open(self._journal_path(), "rb") as handle:
            journal_bytes_before = handle.read()
        tree_before = _tree_snapshot(self.task_dir)

        with mock.patch.object(
            ri, "acquire_review_lock", wraps=ri.acquire_review_lock
        ) as acquire_spy:
            for run in (self._run_verify, self._run_retract):
                with self.assertRaises(pilot_review.ReviewError) as caught:
                    run()
                self.assertIn(
                    "INCOMPLETE_TRANSACTION", str(caught.exception)
                )
        acquire_spy.assert_not_called()

        # Refusal preceded any lock acquisition; no lock exists.
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        # The pre-existing journal is preserved byte-for-byte.
        with open(self._journal_path(), "rb") as handle:
            self.assertEqual(handle.read(), journal_bytes_before)
        self.assertEqual(ri.read_transaction_journal(self.task_dir), seeded)
        # No manifest/event/checkpoint mutation.
        self.assertEqual(_tree_snapshot(self.task_dir), tree_before)

    def test_journal_found_on_recheck_releases_own_token(self):
        self._write_manifest([self._unverified_claim()])
        tree_before = _tree_snapshot(self.task_dir)
        real_acquire = ri.acquire_review_lock
        interleaved = {}

        def _interleaved_acquire(*args, **kwargs):
            lock = real_acquire(*args, **kwargs)
            interleaved["own_lock"] = lock
            # A foreign journal appears before the post-acquisition recheck.
            interleaved["foreign_journal"] = self._seed_foreign_journal()
            return lock

        with mock.patch.object(
            ri, "acquire_review_lock", side_effect=_interleaved_acquire
        ):
            with self.assertRaises(pilot_review.ReviewError) as caught:
                self._run_verify()

        self.assertIn("INCOMPLETE_TRANSACTION", str(caught.exception))
        # Only the command's own newly acquired matching token was released.
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        # The command created no journal; the appeared foreign journal is
        # preserved unchanged, still recording its foreign token.
        journal = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(journal, interleaved["foreign_journal"])
        self.assertEqual(journal["lock_token"], "9" * 32)
        self.assertNotEqual(
            journal["lock_token"], interleaved["own_lock"]["lock_token"]
        )
        # No manifest/event/checkpoint mutation: only the preserved journal
        # was added relative to the manifest-only starting tree.
        tree_after = _tree_snapshot(self.task_dir)
        self.assertEqual(
            set(tree_after) - set(tree_before), {"review-transaction.json"}
        )
        for rel_path, content in tree_before.items():
            self.assertEqual(tree_after[rel_path], content, msg=rel_path)

    def test_malformed_journal_startup_refusal(self):
        # Section 2.6: a malformed pre-existing journal fails closed with
        # TRANSACTION_JOURNAL_CORRUPT at mutating-command startup.
        self._write_manifest([self._unverified_claim()])
        marker = "SENSITIVE-MALFORMED-JOURNAL-MARKER-9f8e7d6c"
        malformed = b'{"transaction_id": "' + marker.encode() + b'", broken'
        with open(self._journal_path(), "wb") as handle:
            handle.write(malformed)
        tree_before = _tree_snapshot(self.task_dir)

        with mock.patch.object(
            ri, "acquire_review_lock", wraps=ri.acquire_review_lock
        ) as acquire_spy:
            for run in (self._run_verify, self._run_retract):
                with self.subTest(run=run.__name__):
                    with self.assertRaises(
                        pilot_review.ReviewError
                    ) as caught:
                        run()
                    message = str(caught.exception)
                    self.assertIn("TRANSACTION_JOURNAL_CORRUPT", message)
                    # No sensitive journal contents are echoed.
                    self.assertNotIn(marker, message)
        acquire_spy.assert_not_called()

        # Refusal preceded any lock acquisition; no lock exists.
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        # The malformed journal is preserved byte-for-byte; the task tree
        # is otherwise unchanged.
        with open(self._journal_path(), "rb") as handle:
            self.assertEqual(handle.read(), malformed)
        self.assertEqual(_tree_snapshot(self.task_dir), tree_before)


class TestClaimTransactionPostJournalLock(_ClaimCommandTestBase):
    """Post-journal lock retention and shared assertions (section 6.8).

    test_resume_with_existing_lock remains explicitly deferred to Slice 3.
    """

    def _plan_verify(self) -> dict:
        """Run Steps 1-7: journal at INITIATED plus the matching lock."""
        return pilot_review._plan_claim_transaction(
            self.task_dir,
            operation="verify-claim",
            claim_id=CLAIM_ID_A,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            notes="post-journal lock check",
        )

    def test_lock_retained_after_post_journal_failure(self):
        self._write_manifest([self._unverified_claim()])
        plan = self._plan_verify()
        journal_initiated = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(journal_initiated["transaction_stage"], "INITIATED")
        with open(self._lock_path(), "rb") as handle:
            lock_bytes = handle.read()

        # Interruption at Step 9 snapshot creation: after the journal
        # exists, before COMMITTED.
        with mock.patch.object(
            ri,
            "snapshot_manifest",
            side_effect=ri.ReviewIntegrityError(
                "sentinel post-journal failure"
            ),
        ):
            with self.assertRaises(pilot_review.ReviewError) as caught:
                pilot_review._execute_claim_transaction_durable(
                    self.task_dir, plan
                )
        self.assertIn("sentinel post-journal failure", str(caught.exception))

        # The journal is retained at the failure stage, immutable fields
        # intact, for explicit forward resume.
        retained = ri.read_transaction_journal(self.task_dir)
        self.assertIsNotNone(retained)
        self.assertEqual(retained["transaction_stage"], "LOCK_ACQUIRED")
        self.assertEqual(
            retained["transaction_id"], journal_initiated["transaction_id"]
        )
        self.assertEqual(retained["lock_token"], plan["lock_token"])
        self.assertEqual(
            retained["starting_manifest_hash"],
            plan["starting_manifest_hash"],
        )
        self.assertEqual(
            retained["proposed_manifest_hash"],
            plan["proposed_manifest_hash"],
        )
        self.assertEqual(
            retained["expected_event_id"],
            plan["journal"]["expected_event_id"],
        )
        self.assertEqual(
            retained["expected_event_hash"],
            plan["journal"]["expected_event_hash"],
        )

        # The matching-token lock is retained byte-for-byte.
        with open(self._lock_path(), "rb") as handle:
            self.assertEqual(handle.read(), lock_bytes)
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], plan["lock_token"])

    def test_lock_released_after_success(self):
        self._write_manifest([
            self._unverified_claim(),
            self._unverified_claim(CLAIM_ID_B, text="Claim text two"),
        ])

        # Normal completion releases the matching token after COMMITTED.
        self._run_verify()
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))

        # Same success-path release for retract-claim.
        self._run_retract(claim_id=CLAIM_ID_B)
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))

    def test_missing_lock_after_journal_fails_closed(self):
        self._write_manifest([self._unverified_claim()])
        plan = self._plan_verify()
        journal_before = ri.read_transaction_journal(self.task_dir)
        os.unlink(self._lock_path())

        with self.assertRaises(pilot_review.ReviewError) as caught:
            pilot_review._execute_claim_transaction_durable(
                self.task_dir, plan
            )

        self.assertIn("LOCK_HELD", str(caught.exception))
        # The missing lock is never recreated.
        self.assertFalse(os.path.exists(self._lock_path()))
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        # The journal is retained unchanged at INITIATED.
        journal_after = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(journal_after, journal_before)
        self.assertEqual(journal_after["transaction_stage"], "INITIATED")

    def test_mismatched_lock_after_journal_fails_closed(self):
        self._write_manifest([self._unverified_claim()])
        plan = self._plan_verify()
        journal_before = ri.read_transaction_journal(self.task_dir)
        # Replace the matching lock with a foreign-token lock.
        ri.release_review_lock(self.task_dir, lock_token=plan["lock_token"])
        foreign = self._hold_foreign_lock()
        with open(self._lock_path(), "rb") as handle:
            foreign_bytes = handle.read()

        with self.assertRaises(pilot_review.ReviewError) as caught:
            pilot_review._execute_claim_transaction_durable(
                self.task_dir, plan
            )

        self.assertIn("LOCK_HELD", str(caught.exception))
        # The other token is neither replaced nor released.
        with open(self._lock_path(), "rb") as handle:
            self.assertEqual(handle.read(), foreign_bytes)
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], foreign["lock_token"])
        # The journal is retained unchanged at INITIATED.
        journal_after = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(journal_after, journal_before)
        self.assertEqual(journal_after["transaction_stage"], "INITIATED")

    def test_malformed_lock_after_journal_fails_closed(self):
        self._write_manifest([self._unverified_claim()])
        plan = self._plan_verify()
        journal_before = ri.read_transaction_journal(self.task_dir)
        with open(self._lock_path(), "wb") as handle:
            handle.write(b"not json\n")

        with self.assertRaises(pilot_review.ReviewError) as caught:
            pilot_review._execute_claim_transaction_durable(
                self.task_dir, plan
            )

        self.assertIn("LOCK_HELD", str(caught.exception))
        # The malformed lock is left exactly as-is: never recreated,
        # replaced, or released.
        with open(self._lock_path(), "rb") as handle:
            self.assertEqual(handle.read(), b"not json\n")
        # The journal is retained unchanged at INITIATED.
        journal_after = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(journal_after, journal_before)
        self.assertEqual(journal_after["transaction_stage"], "INITIATED")

    def test_status_and_audit_never_release_lock(self):
        self._write_manifest([self._unverified_claim()])
        args = argparse.Namespace(task_dir=self.task_dir)

        # Lock-only state: status/audit succeed read-only, release nothing.
        foreign = self._hold_foreign_lock()
        with open(self._lock_path(), "rb") as handle:
            foreign_bytes = handle.read()
        for command in (pilot_review.cmd_status, pilot_review.cmd_audit):
            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = command(args)
            self.assertEqual(exit_code, pilot_review.EXIT_OK)
            held = ri.read_review_lock(self.task_dir)
            self.assertEqual(held["lock_token"], foreign["lock_token"])
        with open(self._lock_path(), "rb") as handle:
            self.assertEqual(handle.read(), foreign_bytes)

        # Post-journal state: both report INCOMPLETE_TRANSACTION, exit 1,
        # and remain byte-for-byte read-only.
        ri.release_review_lock(
            self.task_dir, lock_token=foreign["lock_token"]
        )
        plan = self._plan_verify()
        with open(self._lock_path(), "rb") as handle:
            lock_bytes = handle.read()
        with open(self._journal_path(), "rb") as handle:
            journal_bytes = handle.read()
        tree_before = _tree_snapshot(self.task_dir)
        for command in (pilot_review.cmd_status, pilot_review.cmd_audit):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                exit_code = command(args)
            self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
            self.assertIn("INCOMPLETE_TRANSACTION", output.getvalue())
        with open(self._lock_path(), "rb") as handle:
            self.assertEqual(handle.read(), lock_bytes)
        with open(self._journal_path(), "rb") as handle:
            self.assertEqual(handle.read(), journal_bytes)
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], plan["lock_token"])
        self.assertEqual(_tree_snapshot(self.task_dir), tree_before)

    def test_lock_age_never_permits_takeover_or_release(self):
        self._write_manifest([self._unverified_claim()])
        stale = ri.acquire_review_lock(
            self.task_dir,
            reviewer_id=SECOND_REVIEWER_ID,
            reviewer_display_name=SECOND_REVIEWER_NAME,
            created_at_utc="2020-01-01T00:00:00Z",
        )
        with open(self._lock_path(), "rb") as handle:
            stale_bytes = handle.read()
        tree_before = _tree_snapshot(self.task_dir)

        # A years-old lock still blocks takeover, naming the holder.
        with self.assertRaises(pilot_review.ReviewError) as caught:
            self._run_verify()
        message = str(caught.exception)
        self.assertIn("LOCK_HELD", message)
        self.assertIn(SECOND_REVIEWER_ID, message)

        # Age alone permits no automatic release, replacement, or
        # abandonment takeover.
        with open(self._lock_path(), "rb") as handle:
            self.assertEqual(handle.read(), stale_bytes)
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held, stale)
        self.assertEqual(held["created_at_utc"], "2020-01-01T00:00:00Z")

        # A foreign token still cannot release it, whatever its age.
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.release_review_lock(self.task_dir, lock_token="0" * 32)
        self.assertEqual(ri.read_review_lock(self.task_dir), stale)
        self.assertEqual(_tree_snapshot(self.task_dir), tree_before)


class TestClaimTransactionSecretDisclosure(_ClaimCommandTestBase):
    """No secret disclosure in command output (test plan section 6.15).

    Assertions use custom messages so a failure never prints a secret
    fixture in the test report.
    """

    def _run_cli(self, argv):
        """Run the real CLI surface; return (exit_code, stdout, stderr)."""
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            exit_code = pilot_review.run(argv)
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def _assert_not_disclosed(self, needle, output, where):
        """assertNotIn without echoing the fixture in the test report."""
        self.assertNotIn(
            needle, output, f"secret fixture disclosed in {where}"
        )

    def _verify_argv(self, claim_id=CLAIM_ID_A, notes=None):
        argv = [
            "verify-claim",
            "--task-dir", self.task_dir,
            "--claim-id", claim_id,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
        ]
        if notes is not None:
            argv += ["--notes", notes]
        return argv

    def _retract_argv(self, claim_id=CLAIM_ID_A, reason=RETRACTION_REASON):
        return [
            "retract-claim",
            "--task-dir", self.task_dir,
            "--claim-id", claim_id,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
            "--reason", reason,
        ]

    def test_output_no_claim_text(self):
        text_a = "Quixotic zebra lantern alpha evidence"
        text_b = "Obsidian mango harbor beta testimony"
        self._write_manifest([
            self._unverified_claim(text=text_a),
            self._unverified_claim(CLAIM_ID_B, text=text_b),
        ])

        # Success paths: both commands, stdout and stderr.
        for argv in (
            self._verify_argv(notes="clean notes"),
            self._retract_argv(claim_id=CLAIM_ID_B),
        ):
            exit_code, out, err = self._run_cli(argv)
            self.assertEqual(exit_code, pilot_review.EXIT_OK)
            for output, where in ((out, "success stdout"),
                                  (err, "success stderr")):
                self._assert_not_disclosed(text_a, output, where)
                self._assert_not_disclosed(text_b, output, where)

        # Failure paths: already-mutated claims and an unknown claim_id.
        failure_cases = (
            self._verify_argv(),                        # A now VERIFIED
            self._retract_argv(claim_id=CLAIM_ID_B),    # B now RETRACTED
            self._verify_argv(claim_id="claim-" + "f" * 32),
        )
        for argv in failure_cases:
            exit_code, out, err = self._run_cli(argv)
            self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
            for output, where in ((out, "failure stdout"),
                                  (err, "failure stderr")):
                self._assert_not_disclosed(text_a, output, where)
                self._assert_not_disclosed(text_b, output, where)

    def test_output_no_query_strings(self):
        sid = "sid=" + "x" * 24
        ref = "ref=" + "y" * 24
        query_url = f"https://example.com/evidence?{sid}&{ref}"
        http_query_url = f"http://example.com/insecure?{sid}&{ref}"
        markers = ("?sid=", sid, "&ref=", ref)

        # Success verify then retract: claim carries a query-string URL.
        self._write_manifest([self._unverified_claim(source_url=query_url)])
        for argv in (self._verify_argv(), self._retract_argv()):
            exit_code, out, err = self._run_cli(argv)
            self.assertEqual(exit_code, pilot_review.EXIT_OK)
            for output, where in ((out, "success stdout"),
                                  (err, "success stderr")):
                for marker in markers:
                    self._assert_not_disclosed(marker, output, where)

        # Failure path: HTTP-only source with a query string.
        self._write_manifest([
            self._unverified_claim(CLAIM_ID_B, source_url=http_query_url),
        ])
        exit_code, out, err = self._run_cli(
            self._verify_argv(claim_id=CLAIM_ID_B)
        )
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        for output, where in ((out, "failure stdout"),
                              (err, "failure stderr")):
            for marker in markers:
                self._assert_not_disclosed(marker, output, where)

    def test_output_no_secrets(self):
        self._write_manifest([
            self._unverified_claim(),
            self._unverified_claim(CLAIM_ID_B, text="Claim text two"),
        ])
        env = {
            "MPT_TEST_API_KEY": "api_key=" + "a" * 24,
            "MPT_TEST_BEARER": "Bearer " + "b" * 40,
            "MPT_TEST_SK": "sk-" + "s" * 24,
            "MPT_TEST_COOKIE": "cookie: sessionid=" + "c" * 24,
            "MPT_TEST_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----",
        }
        fixtures = tuple(env.values())
        with mock.patch.dict(os.environ, env):
            # Success paths for both commands.
            for argv in (
                self._verify_argv(notes="clean notes"),
                self._retract_argv(claim_id=CLAIM_ID_B),
            ):
                exit_code, out, err = self._run_cli(argv)
                self.assertEqual(exit_code, pilot_review.EXIT_OK)
                for output, where in ((out, "success stdout"),
                                      (err, "success stderr")):
                    for fixture in fixtures:
                        self._assert_not_disclosed(fixture, output, where)
            # Failure paths for both commands.
            for argv in (
                self._verify_argv(),                      # A now VERIFIED
                self._retract_argv(claim_id=CLAIM_ID_B),  # B now RETRACTED
            ):
                exit_code, out, err = self._run_cli(argv)
                self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
                for output, where in ((out, "failure stdout"),
                                      (err, "failure stderr")):
                    for fixture in fixtures:
                        self._assert_not_disclosed(fixture, output, where)

    def test_notes_sanitized(self):
        secret_fixtures = (
            "Bearer " + "b" * 40,
            "api_key=" + "a" * 24,
            "sk-" + "s" * 24,
            "cookie: sessionid=" + "c" * 24,
            "-----BEGIN PRIVATE KEY-----",
        )
        for fixture in secret_fixtures:
            self._write_manifest([self._unverified_claim()])
            tree_before = _tree_snapshot(self.task_dir)

            # verify-claim --notes carrying a secret is rejected.
            exit_code, out, err = self._run_cli(
                self._verify_argv(notes=fixture)
            )
            self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
            self.assertIn(
                "notes: value appears to contain a credential", err
            )
            self._assert_not_disclosed(fixture, out, "notes rejection stdout")
            self._assert_not_disclosed(fixture, err, "notes rejection stderr")
            # Rejection happens before lock acquisition or mutation.
            artifacts = self._transaction_artifacts()
            self.assertFalse(artifacts["journal"])
            self.assertFalse(artifacts["lock"])
            self.assertEqual(_tree_snapshot(self.task_dir), tree_before)

            # retract-claim --reason carrying a secret is rejected.
            exit_code, out, err = self._run_cli(
                self._retract_argv(reason=fixture)
            )
            self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
            self.assertIn(
                "reason: value appears to contain a credential", err
            )
            self._assert_not_disclosed(
                fixture, out, "reason rejection stdout"
            )
            self._assert_not_disclosed(
                fixture, err, "reason rejection stderr"
            )
            artifacts = self._transaction_artifacts()
            self.assertFalse(artifacts["journal"])
            self.assertFalse(artifacts["lock"])
            self.assertEqual(_tree_snapshot(self.task_dir), tree_before)


class TestClaimTransactionOSErrorSanitization(_ClaimCommandTestBase):
    """CLI-boundary OSError sanitization (approved direct-path correction).

    Every uncaught OSError reaching the CLI boundary prints exactly the
    static line "error: filesystem failure" and exits 1 — no errno, path,
    or payload disclosure. Transaction behavior is unchanged: a failure
    before the journal exists releases only the command's own matching
    token; a failure after journal creation retains the byte-identical
    journal and the matching lock for explicit forward resume (2.4).
    """

    _CANARY = "CANARY-FS-TOKEN-5b4a3c2d1e0f"

    def _run_cli(self, argv):
        """Run the real CLI surface; return (exit_code, stdout, stderr)."""
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            exit_code = pilot_review.run(argv)
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def _verify_argv(self):
        return [
            "verify-claim",
            "--task-dir", self.task_dir,
            "--claim-id", CLAIM_ID_A,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
        ]

    def _retract_argv(self):
        return [
            "retract-claim",
            "--task-dir", self.task_dir,
            "--claim-id", CLAIM_ID_A,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
            "--reason", RETRACTION_REASON,
        ]

    def _canary_oserror(self):
        """OSError carrying a canary in errno, message, and filename."""
        return OSError(
            123,
            f"sentinel filesystem failure {self._CANARY}",
            os.path.join(self.task_dir, f"{self._CANARY}.tmp"),
        )

    def _assert_static_failure(self, exit_code, out, err):
        """Exact static stderr, exit 1, and zero disclosure (custom msgs)."""
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(pilot_review.EXIT_FAILURE, 1)
        self.assertEqual(err, "error: filesystem failure\n")
        self.assertEqual(out, "")
        for output, where in ((out, "stdout"), (err, "stderr")):
            self.assertNotIn(
                self._CANARY, output, f"canary disclosed in {where}"
            )
            self.assertNotIn(
                self.task_dir, output, f"task path disclosed in {where}"
            )
            self.assertNotIn(
                "Errno 123", output, f"errno disclosed in {where}"
            )

    def test_verify_stage_advance_oserror_retains_initiated_journal(self):
        self._write_manifest([self._unverified_claim()])

        created = {}
        real_create = ri.create_transaction_journal

        def _capturing_create(*args, **kwargs):
            journal = real_create(*args, **kwargs)
            created["journal"] = journal
            with open(self._journal_path(), "rb") as handle:
                created["initiated_bytes"] = handle.read()
            return journal

        real_update = ri.update_transaction_stage

        def _fail_first_advance(*args, **kwargs):
            if kwargs.get("new_stage") == "LOCK_ACQUIRED":
                raise self._canary_oserror()
            return real_update(*args, **kwargs)

        with mock.patch.object(
            ri, "create_transaction_journal", side_effect=_capturing_create
        ), mock.patch.object(
            ri, "update_transaction_stage", side_effect=_fail_first_advance
        ) as advance_mock:
            exit_code, out, err = self._run_cli(self._verify_argv())

        self._assert_static_failure(exit_code, out, err)
        # The injected seam is exactly the first journal-stage advance
        # after journal creation (Step 8: INITIATED -> LOCK_ACQUIRED).
        advance_mock.assert_called_once()
        self.assertEqual(
            advance_mock.call_args.kwargs["new_stage"], "LOCK_ACQUIRED"
        )
        self.assertIn("journal", created)
        self.assertEqual(
            created["journal"]["transaction_stage"], "INITIATED"
        )

        # The INITIATED journal is retained byte-identically.
        with open(self._journal_path(), "rb") as handle:
            self.assertEqual(handle.read(), created["initiated_bytes"])
        retained = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(retained, created["journal"])
        self.assertEqual(retained["transaction_stage"], "INITIATED")

        # The matching-token lock is retained.
        held = ri.read_review_lock(self.task_dir)
        self.assertIsNotNone(held)
        self.assertEqual(
            held["lock_token"], created["journal"]["lock_token"]
        )

    def test_retract_journal_creation_oserror_releases_own_lock(self):
        self._write_manifest([self._unverified_claim()])
        tree_before = _tree_snapshot(self.task_dir)

        acquired = {}
        real_acquire = ri.acquire_review_lock

        def _capturing_acquire(*args, **kwargs):
            lock = real_acquire(*args, **kwargs)
            acquired["own_lock"] = lock
            return lock

        with mock.patch.object(
            ri, "acquire_review_lock", side_effect=_capturing_acquire
        ) as acquire_mock, mock.patch.object(
            ri,
            "create_transaction_journal",
            side_effect=self._canary_oserror(),
        ) as create_mock:
            exit_code, out, err = self._run_cli(self._retract_argv())

        self._assert_static_failure(exit_code, out, err)
        # The seam is deterministic: the command acquired its own lock
        # (Step 3), then failed inside journal creation (Step 7).
        acquire_mock.assert_called_once()
        create_mock.assert_called_once()
        self.assertIn("own_lock", acquired)

        # No journal was created.
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))
        self.assertFalse(os.path.exists(self._journal_path()))

        # The command's own matching-token lock was released.
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))

        # Nothing else changed: the tree is exactly the manifest-only
        # starting state.
        self.assertEqual(_tree_snapshot(self.task_dir), tree_before)


class TestResumeTransactionCliRefusals(_ClaimCommandTestBase):
    """Slice 3 checkpoints G1A/G1B: resume CLI surface and refusals.

    resume-transaction requires exactly five arguments and rejects the
    verify/retract-only flags; every refusal below happens before any
    mutation, with sanitized output (approved Section 2.8).
    """

    _RESUME_REASON = "resume-refusal-canary-3c9d2e1f"

    def _run_cli(self, argv):
        """Run the real CLI surface; return (exit_code, stdout, stderr)."""
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            exit_code = pilot_review.run(argv)
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def _resume_argv(self, transaction_id=TRANSACTION_ID_A, *,
                     reviewer_id=REVIEWER_ID,
                     reviewer_display_name=REVIEWER_NAME, reason=None):
        return [
            "resume-transaction",
            "--task-dir", self.task_dir,
            "--transaction-id", transaction_id,
            "--reviewer-id", reviewer_id,
            "--reviewer-display-name", reviewer_display_name,
            "--reason", self._RESUME_REASON if reason is None else reason,
        ]

    def _plan_interrupted(self):
        """Steps 1-7: a legitimate journal at INITIATED plus its lock.

        Returns the created journal's exact transaction_id so every
        resume CLI invocation supplies the matching identifier.
        """
        plan = pilot_review._plan_claim_transaction(
            self.task_dir,
            operation="verify-claim",
            claim_id=CLAIM_ID_A,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            notes="resume refusal seam notes",
        )
        return plan["journal"]["transaction_id"]

    def test_resume_cli_argument_surface(self):
        # All five arguments are required; the verify/retract-only flags
        # are rejected. argparse exits 2 before any command logic runs.
        self._write_manifest([self._unverified_claim()])
        tree_before = _tree_snapshot(self.task_dir)
        full_argv = self._resume_argv()

        for flag in (
            "--task-dir",
            "--transaction-id",
            "--reviewer-id",
            "--reviewer-display-name",
            "--reason",
        ):
            with self.subTest(missing=flag):
                argv = list(full_argv)
                index = argv.index(flag)
                del argv[index:index + 2]
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as caught:
                        pilot_review.run(argv)
                self.assertEqual(caught.exception.code, 2)

        for extra in (
            ["--claim-id", CLAIM_ID_A],
            ["--notes", "rejected notes"],
        ):
            with self.subTest(rejected=extra[0]):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as caught:
                        pilot_review.run(full_argv + extra)
                self.assertEqual(caught.exception.code, 2)

        # argparse refused every invocation before command logic: no
        # transaction files or durable state were created.
        self.assertEqual(_tree_snapshot(self.task_dir), tree_before)

    def test_resume_transaction_not_found(self):
        # A valid task manifest with no journal fails TRANSACTION_NOT_FOUND.
        self._write_manifest([self._unverified_claim()])
        tree_before = _tree_snapshot(self.task_dir)

        exit_code, out, err = self._run_cli(self._resume_argv())

        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertIn("TRANSACTION_NOT_FOUND", err)
        self.assertEqual(out, "")
        self.assertNotIn(
            self.task_dir, err, "task path disclosed in stderr"
        )
        self.assertNotIn(
            TRANSACTION_ID_A, err, "transaction id disclosed in stderr"
        )
        self.assertNotIn(
            self._RESUME_REASON, err, "resume reason disclosed in stderr"
        )
        # No manifest, event, checkpoint, receipt, lock, or journal
        # mutation: the tree is byte-identical.
        self.assertEqual(_tree_snapshot(self.task_dir), tree_before)

    def test_resume_malformed_journal(self):
        # A malformed journal fails closed with exactly the sanitized
        # TRANSACTION_JOURNAL_CORRUPT line and is retained byte-for-byte.
        self._write_manifest([self._unverified_claim()])
        marker = "CANARY-MALFORMED-JOURNAL-4d3c2b1a"
        invalid_json = (
            b'{"transaction_id": "' + marker.encode() + b'", broken'
        )

        def structural_bytes(mutate):
            # Self-hash-consistent structural corruption: seed a valid
            # journal, mutate one field, and recompute the self-hash so
            # only structural validation can fail.
            if os.path.exists(self._journal_path()):
                os.unlink(self._journal_path())
            record = dict(self._seed_foreign_journal())
            mutate(record)
            record["journal_hash"] = ri._canonical_hash(
                ri._journal_unsigned_fields(record)
            )
            return prov.canonical_json_bytes(record) + b"\n"

        corruptions = (
            ("invalid_json", lambda: invalid_json),
            (
                "unknown_field",
                lambda: structural_bytes(
                    lambda record: record.__setitem__(
                        "unexpected_field", marker
                    )
                ),
            ),
            (
                "invalid_recorded_stage",
                lambda: structural_bytes(
                    lambda record: record.__setitem__(
                        "transaction_stage", marker
                    )
                ),
            ),
        )
        for name, make_content in corruptions:
            with self.subTest(corruption=name):
                content = make_content()
                with open(self._journal_path(), "wb") as handle:
                    handle.write(content)
                tree_before = _tree_snapshot(self.task_dir)

                exit_code, out, err = self._run_cli(self._resume_argv())

                self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
                self.assertEqual(
                    err,
                    "error: TRANSACTION_JOURNAL_CORRUPT: transaction "
                    "journal failed validation\n",
                )
                self.assertEqual(out, "")
                for output, where in ((out, "stdout"), (err, "stderr")):
                    self.assertNotIn(
                        marker, output, f"canary disclosed in {where}"
                    )
                self.assertNotIn(
                    self.task_dir, err, "task path disclosed in stderr"
                )
                self.assertNotIn(
                    "review-transaction.json",
                    err,
                    "journal filename disclosed in stderr",
                )
                # The malformed journal is retained byte-for-byte; no
                # lock, receipt, event, checkpoint, or manifest mutation.
                with open(self._journal_path(), "rb") as handle:
                    self.assertEqual(handle.read(), content)
                self.assertEqual(_tree_snapshot(self.task_dir), tree_before)

    def test_resume_transaction_id_mismatch(self):
        # A legitimately interrupted transaction (Steps 1-7: journal at
        # INITIATED plus the matching lock) rejects a malformed-shape id
        # and a valid-shape nonmatching id before any mutation (2.8 row 3).
        self._write_manifest([self._unverified_claim()])
        notes = "CANARY-ID-MISMATCH-NOTES-7e6f5a4b"
        plan = pilot_review._plan_claim_transaction(
            self.task_dir,
            operation="verify-claim",
            claim_id=CLAIM_ID_A,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            notes=notes,
        )
        real_id = plan["journal"]["transaction_id"]
        lock_token = plan["lock_token"]
        nonmatching = ("0" if real_id[0] != "0" else "1") + real_id[1:]
        tree_before = _tree_snapshot(self.task_dir)

        for name, supplied in (
            ("malformed_shape", "not-a-transaction-id"),
            ("valid_shape_nonmatching", nonmatching),
        ):
            with self.subTest(case=name):
                exit_code, out, err = self._run_cli(
                    self._resume_argv(transaction_id=supplied)
                )
                self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
                self.assertIn("TRANSACTION_ID_MISMATCH", err)
                self.assertEqual(out, "")
                for value, what in (
                    (real_id, "journal transaction id"),
                    (supplied, "supplied transaction id"),
                    (self.task_dir, "task path"),
                    (notes, "claim notes"),
                    (self._RESUME_REASON, "resume reason"),
                    (lock_token, "lock token"),
                ):
                    self.assertNotIn(
                        value, err, f"{what} disclosed in stderr"
                    )
                # The original journal and matching lock are retained
                # byte-for-byte; manifest, events, checkpoint, and
                # receipt are unchanged/absent.
                self.assertEqual(_tree_snapshot(self.task_dir), tree_before)

    def test_resume_invalid_reviewer_id(self):
        # The same five invalid shapes as the verify/retract tests; each
        # fails REVIEWER_ID_INVALID before any mutation (2.8 row 4).
        self._write_manifest([self._unverified_claim()])
        transaction_id = self._plan_interrupted()
        tree_before = _tree_snapshot(self.task_dir)
        for bad in ("RICK", "", "a" * 65, "bad id!", "-bad"):
            with self.subTest(reviewer_id=repr(bad)):
                argv = self._resume_argv(transaction_id, reviewer_id=bad)
                if bad.startswith("-"):
                    # "--reviewer-id -bad" would be parsed as an option;
                    # the equals form delivers the value to production
                    # reviewer validation.
                    index = argv.index("--reviewer-id")
                    argv[index:index + 2] = [f"--reviewer-id={bad}"]
                exit_code, out, err = self._run_cli(argv)
                self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
                self.assertIn("REVIEWER_ID_INVALID", err)
                self.assertEqual(out, "")
                # Matching journal and lock remain byte-for-byte
                # unchanged; manifest, events, checkpoint, and receipt
                # are unchanged/absent.
                self.assertEqual(_tree_snapshot(self.task_dir), tree_before)

    def test_resume_invalid_reviewer_name(self):
        # The same four invalid display-name shapes as verify/retract;
        # each fails REVIEWER_NAME_INVALID before any mutation (2.8 row 4).
        self._write_manifest([self._unverified_claim()])
        transaction_id = self._plan_interrupted()
        tree_before = _tree_snapshot(self.task_dir)
        for bad in ("", "x" * 129, "bad\nname", "\t"):
            with self.subTest(reviewer_display_name=repr(bad)):
                exit_code, out, err = self._run_cli(
                    self._resume_argv(
                        transaction_id, reviewer_display_name=bad
                    )
                )
                self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
                self.assertIn("REVIEWER_NAME_INVALID", err)
                self.assertEqual(out, "")
                # Identical durable-state preservation as the
                # reviewer-ID cases.
                self.assertEqual(_tree_snapshot(self.task_dir), tree_before)

    def test_resume_reason_validation(self):
        # Missing --reason is an argparse exit 2, already covered by
        # test_resume_cli_argument_surface (deliberately not duplicated
        # here). Empty and whitespace-only values fail REASON_REQUIRED
        # (2.8 row 5); secret-shaped values fail with the static
        # sanitized rejection before any mutation.
        self._write_manifest([self._unverified_claim()])
        transaction_id = self._plan_interrupted()
        tree_before = _tree_snapshot(self.task_dir)

        for bad in ("", "   "):
            with self.subTest(reason=repr(bad)):
                exit_code, out, err = self._run_cli(
                    self._resume_argv(transaction_id, reason=bad)
                )
                self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
                self.assertIn("REASON_REQUIRED", err)
                self.assertEqual(out, "")
                self.assertEqual(
                    _tree_snapshot(self.task_dir), tree_before
                )

        secret_fixtures = (
            "Bearer " + "b" * 40,
            "api_key=" + "a" * 24,
            "sk-" + "s" * 24,
            "cookie: sessionid=" + "c" * 24,
            "-----BEGIN PRIVATE KEY-----",
        )
        for index, fixture in enumerate(secret_fixtures):
            # The fixture is never echoed in subtest names or messages.
            with self.subTest(secret_pattern=index):
                exit_code, out, err = self._run_cli(
                    self._resume_argv(transaction_id, reason=fixture)
                )
                self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
                self.assertIn(
                    "reason: value appears to contain a credential", err
                )
                self.assertNotIn(
                    fixture, out, "secret fixture disclosed in stdout"
                )
                self.assertNotIn(
                    fixture, err, "secret fixture disclosed in stderr"
                )
                # The fixture reaches no journal, receipt, event, or
                # manifest — the matching journal and lock and the whole
                # tree are byte-identical.
                self.assertEqual(
                    _tree_snapshot(self.task_dir), tree_before
                )

    def test_resume_policy_gate_order_and_failure(self):
        # 2.8 validation order: reviewer (row 4) and reason (row 5)
        # failures precede the policy gate (row 6); with otherwise valid
        # inputs the gate is called exactly once and its static failure
        # surfaces verbatim. The class-level default policy mock is
        # deliberately replaced here by the failing sentinel.
        self._write_manifest([self._unverified_claim()])
        transaction_id = self._plan_interrupted()
        tree_before = _tree_snapshot(self.task_dir)
        sentinel = pilot_review.ReviewError(
            "POLICY_FAILURE: sentinel policy refusal"
        )

        with mock.patch.object(
            pilot_review, "_require_pilot_policy", side_effect=sentinel
        ) as gate:
            # Invalid reviewer input fails before the gate: not called.
            exit_code, out, err = self._run_cli(
                self._resume_argv(transaction_id, reviewer_id="RICK")
            )
            self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
            self.assertIn("REVIEWER_ID_INVALID", err)
            self.assertEqual(out, "")
            gate.assert_not_called()

            # Invalid reason fails before the gate: still not called.
            exit_code, out, err = self._run_cli(
                self._resume_argv(transaction_id, reason="")
            )
            self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
            self.assertIn("REASON_REQUIRED", err)
            self.assertEqual(out, "")
            gate.assert_not_called()

            # Otherwise valid inputs: the gate is called exactly once
            # and its static POLICY_FAILURE surfaces verbatim.
            exit_code, out, err = self._run_cli(
                self._resume_argv(transaction_id)
            )
            self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
            self.assertEqual(
                err, "error: POLICY_FAILURE: sentinel policy refusal\n"
            )
            self.assertEqual(out, "")
            gate.assert_called_once_with()

        # After every case the journal and matching lock are
        # byte-for-byte unchanged and the complete task tree is
        # unchanged.
        self.assertEqual(_tree_snapshot(self.task_dir), tree_before)

    def test_resume_rechecks_journal_claim_notes_for_secrets(self):
        # Amendment Section 2.1 / acceptance criterion 7: every resume
        # load reapplies the CURRENT secret-pattern check to a non-null
        # claim_notes after structural and self-hash validation and
        # after the policy gate, before any use. The narrowest existing
        # seam simulates credential-rule evolution: the journal is
        # planned with the real patterns (notes accepted; journal fully
        # legitimate and hash-consistent), then one canary-matching
        # pattern is appended to pilot_review._SECRET_TEXT_PATTERNS so
        # the same journaled value is credential-shaped only at resume.
        import re

        notes = "resume recheck notes Nd73qxKf2"
        reason = "resume recheck reason Qx84mzLp3"
        self._write_manifest([self._unverified_claim()])
        plan = pilot_review._plan_claim_transaction(
            self.task_dir,
            operation="verify-claim",
            claim_id=CLAIM_ID_A,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            notes=notes,
        )
        journal = plan["journal"]
        transaction_id = journal["transaction_id"]
        lock_token = plan["lock_token"]
        self.assertEqual(journal["claim_notes"], notes)

        # Capture the exact pre-resume state: journal, lock, manifest,
        # and the complete tree.
        with open(self._journal_path(), "rb") as handle:
            journal_bytes = handle.read()
        with open(self._lock_path(), "rb") as handle:
            lock_bytes = handle.read()
        manifest_path = os.path.join(
            self.task_dir, "provenance_manifest.json"
        )
        with open(manifest_path, "rb") as handle:
            manifest_bytes = handle.read()
        tree_before = _tree_snapshot(self.task_dir)

        # The journaled notes become credential-shaped only now; the
        # gate spy proves the policy gate is reached (approved order)
        # before the claim_notes re-check fails closed.
        evolved = pilot_review._SECRET_TEXT_PATTERNS + (
            re.compile(re.escape("Nd73qxKf2")),
        )
        with (
            mock.patch.object(
                pilot_review, "_SECRET_TEXT_PATTERNS", evolved
            ),
            mock.patch.object(
                pilot_review, "_require_pilot_policy"
            ) as gate,
        ):
            exit_code, out, err = self._run_cli(
                self._resume_argv(transaction_id, reason=reason)
            )
        gate.assert_called_once_with()

        # Exit 1, empty stdout, byte-exact static production line: the
        # failure is the claim_notes re-check itself — transaction id,
        # reviewer, reason, policy, journal hash, and structure all
        # passed first (the gate was called exactly once).
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(out, "")
        self.assertEqual(
            err,
            "error: TRANSACTION_JOURNAL_CORRUPT: journal claim_notes "
            "rejected by the current secret-pattern check\n",
        )

        # No disclosure: the journaled notes/credential canary, resume
        # reason, task path, journal path, lock token, or native text.
        disclosures = (
            (notes, "journal claim_notes canary"),
            ("Nd73qxKf2", "credential-pattern canary"),
            (reason, "resume reason canary"),
            (self.task_dir, "task path"),
            (self._journal_path(), "journal path"),
            (lock_token, "lock token"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # Journal and matching lock remain byte-for-byte unchanged; the
        # active manifest is unchanged; no snapshot, proposed temp,
        # event, checkpoint, or receipt was created; the complete task
        # tree is byte-for-byte unchanged.
        with open(self._journal_path(), "rb") as handle:
            self.assertEqual(handle.read(), journal_bytes)
        with open(self._lock_path(), "rb") as handle:
            self.assertEqual(handle.read(), lock_bytes)
        self.assertEqual(
            ri.read_review_lock(self.task_dir)["lock_token"], lock_token
        )
        with open(manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), manifest_bytes)
        artifacts = self._transaction_artifacts()
        self.assertEqual(artifacts["proposed_temps"], [])
        self.assertFalse(artifacts["recovery_dir"])
        self.assertFalse(
            os.path.exists(os.path.join(self.task_dir, "review-events"))
        )
        self.assertFalse(
            os.path.exists(os.path.join(self.task_dir, "manifest-history"))
        )
        self.assertEqual(_tree_snapshot(self.task_dir), tree_before)


class TestResumeTransactionSuccess(_ClaimCommandTestBase):
    """Slice 3 checkpoint G2A1: successful resume of an interrupted
    verify transaction (approved Section 2.8 forward-only cascade).
    """

    _CLAIM_CANARY = "resumeCanaryQz7Lantern"
    _QS_CANARY = "resumeqsx7k2q9"
    _NOTES_CANARY = "resumeCanaryNotesNd83kf"
    _REASON_CANARY = "resumeCanaryReasonP29dvq"

    def _run_cli(self, argv):
        """Run the real CLI surface; return (exit_code, stdout, stderr)."""
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            exit_code = pilot_review.run(argv)
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def _assert_interrupted_surfaces_read_only(self, expected_stage):
        """Prove status, audit, verify-claim, and retract-claim stay
        read-only while a transaction journal sits interrupted at
        ``expected_stage``: status and audit each exit 1 reporting
        INCOMPLETE_TRANSACTION, status names the interrupted stage,
        verify-claim and retract-claim refuse without advancing the
        journal, and the entire task tree remains byte-for-byte
        unchanged throughout.
        """
        # status and audit each report INCOMPLETE_TRANSACTION, exit 1,
        # and leave the entire task tree byte-for-byte unchanged.
        tree_before = _tree_snapshot(self.task_dir)
        status_code, status_out, _se = self._run_cli([
            "status", "--task-dir", self.task_dir,
        ])
        self.assertEqual(status_code, pilot_review.EXIT_FAILURE)
        self.assertIn("INCOMPLETE_TRANSACTION", status_out)
        self.assertIn(expected_stage, status_out)
        audit_code, audit_out, _ae = self._run_cli([
            "audit", "--task-dir", self.task_dir,
        ])
        self.assertEqual(audit_code, pilot_review.EXIT_FAILURE)
        self.assertIn("INCOMPLETE_TRANSACTION", audit_out)
        self.assertEqual(_tree_snapshot(self.task_dir), tree_before)

        # verify-claim and retract-claim refuse; neither advances the
        # transaction.
        verify_code, verify_out, verify_err = self._run_cli([
            "verify-claim",
            "--task-dir", self.task_dir,
            "--claim-id", CLAIM_ID_A,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
            "--notes", "read-only refusal probe notes",
        ])
        self.assertEqual(verify_code, pilot_review.EXIT_FAILURE)
        self.assertIn("INCOMPLETE_TRANSACTION", verify_err)
        self.assertEqual(verify_out, "")
        retract_code, retract_out, retract_err = self._run_cli([
            "retract-claim",
            "--task-dir", self.task_dir,
            "--claim-id", CLAIM_ID_A,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
            "--reason", RETRACTION_REASON,
        ])
        self.assertEqual(retract_code, pilot_review.EXIT_FAILURE)
        self.assertIn("INCOMPLETE_TRANSACTION", retract_err)
        self.assertEqual(retract_out, "")
        self.assertEqual(_tree_snapshot(self.task_dir), tree_before)
        journal = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(journal["transaction_stage"], expected_stage)

    def test_resume_transaction_success(self):
        claim_text = f"Resume claim text {self._CLAIM_CANARY} evidence"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        notes = f"resume notes {self._NOTES_CANARY}"
        reason = f"resume reason {self._REASON_CANARY}"
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        self._write_manifest([original_claim])

        # Real Steps 1-7 seam: a legitimate journal at INITIATED plus
        # the matching lock, interrupted before the durable phase.
        plan = pilot_review._plan_claim_transaction(
            self.task_dir,
            operation="verify-claim",
            claim_id=CLAIM_ID_A,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            notes=notes,
        )
        journal = plan["journal"]
        transaction_id = journal["transaction_id"]
        lock_token = plan["lock_token"]

        exit_code, out, err = self._run_cli([
            "resume-transaction",
            "--task-dir", self.task_dir,
            "--transaction-id", transaction_id,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
            "--reason", reason,
        ])

        # Exit 0, empty stderr, and the approved sanitized RESUMED
        # summary shape.
        self.assertEqual(exit_code, pilot_review.EXIT_OK)
        self.assertEqual(err, "")
        self.assertTrue(
            out.startswith(
                "BrainTrustCrypto pilot review — resume-transaction\n"
            )
        )
        self.assertRegex(out, r"(?m)^  result:\s+RESUMED$")
        self.assertIn(TASK_ID, out)
        self.assertIn(CLAIM_ID_A, out)
        self.assertIn(transaction_id, out)
        self.assertIn("verify-claim", out)
        self.assertIn(plan["proposed_manifest_hash"], out)
        self.assertIn(journal["expected_event_hash"], out)
        self.assertIn(plan["snapshot_relative_path"], out)
        self.assertIn("NEEDS_HUMAN_REVIEW", out)

        # Non-disclosure: no canary, absolute path, traceback, errno,
        # or native exception text; custom messages never echo canaries.
        disclosures = (
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            (self._NOTES_CANARY, "claim notes canary"),
            (self._REASON_CANARY, "resume reason canary"),
            (lock_token, "lock token"),
            (self.task_dir, "task path"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # The active manifest is the planned proposed manifest,
        # byte-for-byte under canonical hashing.
        manifest, _path, _sha = pilot_review._load_manifest(self.task_dir)
        self.assertEqual(manifest, plan["proposed_manifest"])
        self.assertEqual(
            prov.canonical_sha256(manifest), plan["proposed_manifest_hash"]
        )

        # The target claim carries exactly the approved five mutations.
        installed = None
        for claim in manifest["factual_claims"]:
            if claim.get("claim_id") == CLAIM_ID_A:
                installed = claim
                break
        self.assertIsNotNone(installed)
        expected_claim = dict(original_claim)
        expected_claim.update({
            "status": "VERIFIED",
            "reviewer_id": REVIEWER_ID,
            "reviewer_display_name": REVIEWER_NAME,
            "review_timestamp_utc": journal["created_at_utc"],
            "notes": notes,
        })
        self.assertEqual(installed, expected_claim)

        # The immutable starting snapshot exists and hashes exactly to
        # the starting manifest.
        snapshot_path = os.path.join(
            self.task_dir, plan["snapshot_relative_path"]
        )
        self.assertTrue(os.path.exists(snapshot_path))
        history = ri.list_manifest_history(self.task_dir)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0], plan["starting_manifest"])
        self.assertEqual(
            prov.canonical_sha256(history[0]),
            plan["starting_manifest_hash"],
        )

        # Exactly one committed event with the journal-recorded identity
        # and correct before/after manifest hashes; the chain validates.
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        event = committed[0]
        self.assertEqual(event["sequence"], 1)
        self.assertEqual(event["event_id"], journal["expected_event_id"])
        self.assertEqual(
            event["event_hash"], journal["expected_event_hash"]
        )
        self.assertEqual(
            event["manifest_hash_before"], plan["starting_manifest_hash"]
        )
        self.assertEqual(
            event["manifest_hash_after"], plan["proposed_manifest_hash"]
        )
        self.assertEqual(event["event_type"], "CLAIM_VERIFIED")
        self.assertEqual(event["reviewer_id"], REVIEWER_ID)
        self.assertEqual(event["reviewer_display_name"], REVIEWER_NAME)
        self.assertEqual(event["timestamp_utc"], journal["created_at_utc"])

        # The checkpoint points to exactly that event.
        checkpoint = ri._read_checkpoint(
            os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        )
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint["last_sequence"], event["sequence"])
        self.assertEqual(checkpoint["last_record_id"], event["event_id"])
        self.assertEqual(
            checkpoint["last_record_hash"], event["event_hash"]
        )

        # Exactly one valid immutable recovery receipt with the full
        # approved identity.
        recovery_dir = os.path.join(self.task_dir, "review-recovery")
        self.assertEqual(
            sorted(os.listdir(recovery_dir)),
            [f"transaction-resumed-{transaction_id}.json"],
        )
        self.assertTrue(
            os.path.exists(self._receipt_path(transaction_id))
        )
        receipt = ri.read_recovery_receipt(
            self.task_dir, transaction_id=transaction_id
        )
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["transaction_id"], transaction_id)
        self.assertEqual(receipt["interrupted_stage"], "INITIATED")
        self.assertEqual(receipt["resuming_reviewer_id"], REVIEWER_ID)
        self.assertEqual(
            receipt["resuming_reviewer_display_name"], REVIEWER_NAME
        )
        self.assertEqual(receipt["reason"], reason)
        self.assertEqual(
            receipt["resulting_manifest_hash"],
            plan["proposed_manifest_hash"],
        )
        self.assertEqual(
            receipt["resulting_audit_chain_head"],
            journal["expected_event_hash"],
        )

        # Journal and lock are absent; no uncommitted event tail.
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))
        self.assertFalse(os.path.exists(self._journal_path()))
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

    def test_different_authorized_reviewer_may_resume(self):
        claim_text = f"Retract resume claim text {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        retraction_reason = f"retraction reason {self._NOTES_CANARY}"
        resume_reason = f"resume reason {self._REASON_CANARY}"
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        self._write_manifest([original_claim])

        # Real Steps 1-7 seam: a legitimate retract-claim journal at
        # INITIATED plus the matching lock, planned by the original
        # transaction reviewer and interrupted before the durable phase.
        plan = pilot_review._plan_claim_transaction(
            self.task_dir,
            operation="retract-claim",
            claim_id=CLAIM_ID_A,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            reason=retraction_reason,
        )
        journal = plan["journal"]
        transaction_id = journal["transaction_id"]
        lock_token = plan["lock_token"]

        # A different authorized reviewer resumes through the real CLI
        # with a new resume reason.
        exit_code, out, err = self._run_cli([
            "resume-transaction",
            "--task-dir", self.task_dir,
            "--transaction-id", transaction_id,
            "--reviewer-id", SECOND_REVIEWER_ID,
            "--reviewer-display-name", SECOND_REVIEWER_NAME,
            "--reason", resume_reason,
        ])

        # Exit 0, empty stderr, and the approved sanitized RESUMED
        # summary shape.
        self.assertEqual(exit_code, pilot_review.EXIT_OK)
        self.assertEqual(err, "")
        self.assertTrue(
            out.startswith(
                "BrainTrustCrypto pilot review — resume-transaction\n"
            )
        )
        self.assertRegex(out, r"(?m)^  result:\s+RESUMED$")
        self.assertIn(TASK_ID, out)
        self.assertIn(CLAIM_ID_A, out)
        self.assertIn(transaction_id, out)
        self.assertIn("retract-claim", out)
        self.assertIn(plan["proposed_manifest_hash"], out)
        self.assertIn(journal["expected_event_hash"], out)
        self.assertIn(plan["snapshot_relative_path"], out)
        self.assertIn("NEEDS_HUMAN_REVIEW", out)

        # Non-disclosure: neither reason, claim text, query strings,
        # claim_notes, lock token, absolute path, or native exception
        # text ever reaches stdout/stderr.
        disclosures = (
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            (self._NOTES_CANARY, "retraction reason canary"),
            (self._REASON_CANARY, "resume reason canary"),
            (lock_token, "lock token"),
            (self.task_dir, "task path"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # The active manifest is the planned proposed manifest,
        # byte-for-byte under canonical hashing.
        manifest, _path, _sha = pilot_review._load_manifest(self.task_dir)
        self.assertEqual(manifest, plan["proposed_manifest"])
        self.assertEqual(
            prov.canonical_sha256(manifest), plan["proposed_manifest_hash"]
        )

        # The target claim carries exactly the approved five mutations,
        # retaining the original transaction reviewer, the frozen
        # journal timestamp, and the original retraction reason as
        # notes — the resuming reviewer is absent.
        installed = None
        for claim in manifest["factual_claims"]:
            if claim.get("claim_id") == CLAIM_ID_A:
                installed = claim
                break
        self.assertIsNotNone(installed)
        expected_claim = dict(original_claim)
        expected_claim.update({
            "status": "RETRACTED",
            "reviewer_id": REVIEWER_ID,
            "reviewer_display_name": REVIEWER_NAME,
            "review_timestamp_utc": journal["created_at_utc"],
            "notes": retraction_reason,
        })
        self.assertEqual(installed, expected_claim)

        # The immutable starting snapshot exists and hashes exactly to
        # the starting manifest.
        snapshot_path = os.path.join(
            self.task_dir, plan["snapshot_relative_path"]
        )
        self.assertTrue(os.path.exists(snapshot_path))
        history = ri.list_manifest_history(self.task_dir)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0], plan["starting_manifest"])
        self.assertEqual(
            prov.canonical_sha256(history[0]),
            plan["starting_manifest_hash"],
        )

        # Exactly one committed CLAIM_RETRACTED event with the
        # journal-recorded identity, original reviewer, frozen
        # timestamp, original reason, and planned hashes.
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        event = committed[0]
        self.assertEqual(event["sequence"], 1)
        self.assertEqual(event["event_id"], journal["expected_event_id"])
        self.assertEqual(
            event["event_hash"], journal["expected_event_hash"]
        )
        self.assertEqual(
            event["manifest_hash_before"], plan["starting_manifest_hash"]
        )
        self.assertEqual(
            event["manifest_hash_after"], plan["proposed_manifest_hash"]
        )
        self.assertEqual(event["event_type"], "CLAIM_RETRACTED")
        self.assertEqual(event["reason"], retraction_reason)
        self.assertEqual(event["reviewer_id"], REVIEWER_ID)
        self.assertEqual(event["reviewer_display_name"], REVIEWER_NAME)
        self.assertEqual(event["timestamp_utc"], journal["created_at_utc"])

        # The checkpoint points to exactly that event.
        checkpoint = ri._read_checkpoint(
            os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        )
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint["last_sequence"], event["sequence"])
        self.assertEqual(checkpoint["last_record_id"], event["event_id"])
        self.assertEqual(
            checkpoint["last_record_hash"], event["event_hash"]
        )

        # Exactly one valid immutable recovery receipt — the only place
        # the second reviewer and the new resume reason appear.
        recovery_dir = os.path.join(self.task_dir, "review-recovery")
        self.assertEqual(
            sorted(os.listdir(recovery_dir)),
            [f"transaction-resumed-{transaction_id}.json"],
        )
        self.assertTrue(
            os.path.exists(self._receipt_path(transaction_id))
        )
        receipt = ri.read_recovery_receipt(
            self.task_dir, transaction_id=transaction_id
        )
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["transaction_id"], transaction_id)
        self.assertEqual(receipt["interrupted_stage"], "INITIATED")
        self.assertEqual(
            receipt["resuming_reviewer_id"], SECOND_REVIEWER_ID
        )
        self.assertEqual(
            receipt["resuming_reviewer_display_name"], SECOND_REVIEWER_NAME
        )
        self.assertEqual(receipt["reason"], resume_reason)
        self.assertEqual(
            receipt["resulting_manifest_hash"],
            plan["proposed_manifest_hash"],
        )
        self.assertEqual(
            receipt["resulting_audit_chain_head"],
            journal["expected_event_hash"],
        )

        # Journal and lock are absent; no uncommitted event tail.
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))
        self.assertFalse(os.path.exists(self._journal_path()))
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

    def test_resume_with_existing_lock(self):
        claim_text = f"Lock resume claim text {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        notes = f"lock resume notes {self._NOTES_CANARY}"
        reason = f"lock resume reason {self._REASON_CANARY}"
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        self._write_manifest([original_claim])

        # One legitimate INITIATED transaction with its matching lock.
        plan = pilot_review._plan_claim_transaction(
            self.task_dir,
            operation="verify-claim",
            claim_id=CLAIM_ID_A,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            notes=notes,
        )
        journal = plan["journal"]
        transaction_id = journal["transaction_id"]
        lock_token = plan["lock_token"]
        argv = [
            "resume-transaction",
            "--task-dir", self.task_dir,
            "--transaction-id", transaction_id,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
            "--reason", reason,
        ]
        with open(self._lock_path(), "rb") as handle:
            original_lock_bytes = handle.read()
        tree_before = _tree_snapshot(self.task_dir)

        # Scenario 1: the matching lock is replaced by a valid foreign
        # lock (different token, different holder).
        os.remove(self._lock_path())
        foreign = ri.acquire_review_lock(
            self.task_dir,
            reviewer_id=SECOND_REVIEWER_ID,
            reviewer_display_name=SECOND_REVIEWER_NAME,
            created_at_utc=TIMESTAMP,
        )
        with open(self._lock_path(), "rb") as handle:
            foreign_lock_bytes = handle.read()

        exit_code, out, err = self._run_cli(argv)

        # Exit 1, empty stdout, exactly the approved static LOCK_HELD
        # line: no token, holder, or journal data.
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(out, "")
        self.assertEqual(
            err,
            "error: LOCK_HELD: held lock token does not match the "
            "journal-recorded token\n",
        )

        # The foreign lock is neither released nor replaced; the
        # journal is byte-for-byte unchanged at INITIATED; the manifest,
        # snapshot, event, checkpoint, and receipt are unchanged/absent
        # (the only tree delta is the lock replacement itself).
        with open(self._lock_path(), "rb") as handle:
            self.assertEqual(handle.read(), foreign_lock_bytes)
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], foreign["lock_token"])
        self.assertEqual(
            ri.read_transaction_journal(self.task_dir), journal
        )
        expected_tree = dict(tree_before)
        expected_tree["review.lock"] = foreign_lock_bytes
        self.assertEqual(_tree_snapshot(self.task_dir), expected_tree)

        disclosures = (
            (lock_token, "journal-recorded lock token"),
            (foreign["lock_token"], "foreign lock token"),
            (SECOND_REVIEWER_ID, "foreign holder reviewer id"),
            (SECOND_REVIEWER_NAME, "foreign holder display name"),
            (self.task_dir, "task path"),
            (self._CLAIM_CANARY, "claim text canary"),
            (self._NOTES_CANARY, "claim notes canary"),
            (self._REASON_CANARY, "resume reason canary"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            self.assertNotIn(value, out, f"{what} disclosed in stdout")
            self.assertNotIn(value, err, f"{what} disclosed in stderr")

        # Scenario 2: the original matching lock bytes are restored as
        # fixture setup; the same resume command now succeeds.
        with open(self._lock_path(), "wb") as handle:
            handle.write(original_lock_bytes)

        exit_code, out, err = self._run_cli(argv)

        self.assertEqual(exit_code, pilot_review.EXIT_OK)
        self.assertEqual(err, "")
        self.assertTrue(
            out.startswith(
                "BrainTrustCrypto pilot review — resume-transaction\n"
            )
        )
        self.assertRegex(out, r"(?m)^  result:\s+RESUMED$")
        self.assertIn(TASK_ID, out)
        self.assertIn(CLAIM_ID_A, out)
        self.assertIn(transaction_id, out)
        self.assertIn("verify-claim", out)
        self.assertIn(plan["proposed_manifest_hash"], out)
        self.assertIn(journal["expected_event_hash"], out)
        self.assertIn(plan["snapshot_relative_path"], out)
        self.assertIn("NEEDS_HUMAN_REVIEW", out)

        # Sanitized output discloses neither lock token, holder
        # identity, task path, claim text, notes/reason, nor native
        # exception text.
        for value, what in disclosures:
            self.assertNotIn(value, out, f"{what} disclosed in stdout")
            self.assertNotIn(value, err, f"{what} disclosed in stderr")

        # The active manifest is the planned proposed manifest,
        # byte-for-byte under canonical hashing.
        manifest, _path, _sha = pilot_review._load_manifest(self.task_dir)
        self.assertEqual(manifest, plan["proposed_manifest"])
        self.assertEqual(
            prov.canonical_sha256(manifest), plan["proposed_manifest_hash"]
        )

        # The target claim carries exactly the approved five mutations.
        installed = None
        for claim in manifest["factual_claims"]:
            if claim.get("claim_id") == CLAIM_ID_A:
                installed = claim
                break
        self.assertIsNotNone(installed)
        expected_claim = dict(original_claim)
        expected_claim.update({
            "status": "VERIFIED",
            "reviewer_id": REVIEWER_ID,
            "reviewer_display_name": REVIEWER_NAME,
            "review_timestamp_utc": journal["created_at_utc"],
            "notes": notes,
        })
        self.assertEqual(installed, expected_claim)

        # The immutable starting snapshot exists and hashes exactly to
        # the starting manifest.
        snapshot_path = os.path.join(
            self.task_dir, plan["snapshot_relative_path"]
        )
        self.assertTrue(os.path.exists(snapshot_path))
        history = ri.list_manifest_history(self.task_dir)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0], plan["starting_manifest"])
        self.assertEqual(
            prov.canonical_sha256(history[0]),
            plan["starting_manifest_hash"],
        )

        # Exactly one committed event with the journal-recorded
        # identity and correct before/after hashes; the chain validates.
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        event = committed[0]
        self.assertEqual(event["sequence"], 1)
        self.assertEqual(event["event_id"], journal["expected_event_id"])
        self.assertEqual(
            event["event_hash"], journal["expected_event_hash"]
        )
        self.assertEqual(
            event["manifest_hash_before"], plan["starting_manifest_hash"]
        )
        self.assertEqual(
            event["manifest_hash_after"], plan["proposed_manifest_hash"]
        )
        self.assertEqual(event["event_type"], "CLAIM_VERIFIED")
        self.assertEqual(event["reviewer_id"], REVIEWER_ID)
        self.assertEqual(event["reviewer_display_name"], REVIEWER_NAME)
        self.assertEqual(event["timestamp_utc"], journal["created_at_utc"])

        # The checkpoint points to exactly that event.
        checkpoint = ri._read_checkpoint(
            os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        )
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint["last_sequence"], event["sequence"])
        self.assertEqual(checkpoint["last_record_id"], event["event_id"])
        self.assertEqual(
            checkpoint["last_record_hash"], event["event_hash"]
        )

        # Exactly one valid immutable recovery receipt.
        recovery_dir = os.path.join(self.task_dir, "review-recovery")
        self.assertEqual(
            sorted(os.listdir(recovery_dir)),
            [f"transaction-resumed-{transaction_id}.json"],
        )
        self.assertTrue(
            os.path.exists(self._receipt_path(transaction_id))
        )
        receipt = ri.read_recovery_receipt(
            self.task_dir, transaction_id=transaction_id
        )
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["transaction_id"], transaction_id)
        self.assertEqual(receipt["interrupted_stage"], "INITIATED")
        self.assertEqual(receipt["resuming_reviewer_id"], REVIEWER_ID)
        self.assertEqual(
            receipt["resuming_reviewer_display_name"], REVIEWER_NAME
        )
        self.assertEqual(receipt["reason"], reason)
        self.assertEqual(
            receipt["resulting_manifest_hash"],
            plan["proposed_manifest_hash"],
        )
        self.assertEqual(
            receipt["resulting_audit_chain_head"],
            journal["expected_event_hash"],
        )

        # Journal and lock are absent; no uncommitted event tail.
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))
        self.assertFalse(os.path.exists(self._journal_path()))
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

    def test_resume_snapshot_created_reuses_exact_proposed_temp(self):
        claim_text = f"Snapshot temp claim text {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        notes = f"snapshot temp notes {self._NOTES_CANARY}"
        reason = f"snapshot temp resume reason {self._REASON_CANARY}"
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        self._write_manifest([original_claim])

        plan = pilot_review._plan_claim_transaction(
            self.task_dir,
            operation="verify-claim",
            claim_id=CLAIM_ID_A,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            notes=notes,
        )
        journal = plan["journal"]
        transaction_id = journal["transaction_id"]
        lock_token = plan["lock_token"]

        # Real Steps 8-9 seam: fail the Step-10 write so the real
        # durable flow retains the journal at SNAPSHOT_CREATED with its
        # matching lock and verified snapshot (approved Section 2.4).
        seam = pilot_review.ReviewError("SNAPSHOT_CREATED fixture seam")
        with mock.patch.object(
            pilot_review,
            "_write_durable_proposed_manifest",
            side_effect=seam,
        ):
            with self.assertRaises(pilot_review.ReviewError):
                pilot_review._execute_claim_transaction_durable(
                    self.task_dir, plan
                )

        retained = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(
            retained["transaction_stage"], "SNAPSHOT_CREATED"
        )
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], lock_token)
        snapshot_path = os.path.join(
            self.task_dir, plan["snapshot_relative_path"]
        )
        self.assertTrue(os.path.exists(snapshot_path))

        # The crash window approved by amendment Section 2.6: the exact
        # planned proposed bytes landed at the recorded temp path but
        # the journal never advanced.
        temp_path = os.path.join(
            self.task_dir, plan["proposed_manifest_relative_path"]
        )
        self.assertFalse(os.path.exists(temp_path))
        with open(temp_path, "xb") as handle:
            handle.write(plan["proposed_manifest_bytes"])
        with open(temp_path, "rb") as handle:
            temp_bytes = handle.read()
        self.assertEqual(temp_bytes, plan["proposed_manifest_bytes"])

        # Resume with the write helper sentinel-patched: a valid exact
        # temp must be accepted as-is, never rewritten.
        write_sentinel = AssertionError(
            "_write_durable_proposed_manifest must not be called"
        )
        with mock.patch.object(
            pilot_review,
            "_write_durable_proposed_manifest",
            side_effect=write_sentinel,
        ) as write_mock:
            exit_code, out, err = self._run_cli([
                "resume-transaction",
                "--task-dir", self.task_dir,
                "--transaction-id", transaction_id,
                "--reviewer-id", REVIEWER_ID,
                "--reviewer-display-name", REVIEWER_NAME,
                "--reason", reason,
            ])
        write_mock.assert_not_called()

        # Exit 0, empty stderr, and the approved sanitized RESUMED
        # summary shape.
        self.assertEqual(exit_code, pilot_review.EXIT_OK)
        self.assertEqual(err, "")
        self.assertTrue(
            out.startswith(
                "BrainTrustCrypto pilot review — resume-transaction\n"
            )
        )
        self.assertRegex(out, r"(?m)^  result:\s+RESUMED$")
        self.assertIn(TASK_ID, out)
        self.assertIn(CLAIM_ID_A, out)
        self.assertIn(transaction_id, out)
        self.assertIn("verify-claim", out)
        self.assertIn(plan["proposed_manifest_hash"], out)
        self.assertIn(journal["expected_event_hash"], out)
        self.assertIn(plan["snapshot_relative_path"], out)
        self.assertIn("NEEDS_HUMAN_REVIEW", out)

        # Non-disclosure: no canary, lock token, absolute path, or
        # native exception text on either stream.
        disclosures = (
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            (self._NOTES_CANARY, "claim notes canary"),
            (self._REASON_CANARY, "resume reason canary"),
            (lock_token, "lock token"),
            (self.task_dir, "task path"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # The active manifest is the planned proposed manifest — the
        # exact temp bytes, accepted rather than rewritten.
        manifest, _path, _sha = pilot_review._load_manifest(self.task_dir)
        self.assertEqual(manifest, plan["proposed_manifest"])
        self.assertEqual(
            prov.canonical_sha256(manifest), plan["proposed_manifest_hash"]
        )

        # The target claim carries exactly the approved five mutations.
        installed = None
        for claim in manifest["factual_claims"]:
            if claim.get("claim_id") == CLAIM_ID_A:
                installed = claim
                break
        self.assertIsNotNone(installed)
        expected_claim = dict(original_claim)
        expected_claim.update({
            "status": "VERIFIED",
            "reviewer_id": REVIEWER_ID,
            "reviewer_display_name": REVIEWER_NAME,
            "review_timestamp_utc": journal["created_at_utc"],
            "notes": notes,
        })
        self.assertEqual(installed, expected_claim)

        # The immutable starting snapshot exists and hashes exactly to
        # the starting manifest.
        self.assertTrue(os.path.exists(snapshot_path))
        history = ri.list_manifest_history(self.task_dir)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0], plan["starting_manifest"])
        self.assertEqual(
            prov.canonical_sha256(history[0]),
            plan["starting_manifest_hash"],
        )

        # Exactly one committed event with the journal-recorded
        # identity and correct before/after hashes; the chain validates.
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        event = committed[0]
        self.assertEqual(event["sequence"], 1)
        self.assertEqual(event["event_id"], journal["expected_event_id"])
        self.assertEqual(
            event["event_hash"], journal["expected_event_hash"]
        )
        self.assertEqual(
            event["manifest_hash_before"], plan["starting_manifest_hash"]
        )
        self.assertEqual(
            event["manifest_hash_after"], plan["proposed_manifest_hash"]
        )
        self.assertEqual(event["event_type"], "CLAIM_VERIFIED")
        self.assertEqual(event["reviewer_id"], REVIEWER_ID)
        self.assertEqual(event["reviewer_display_name"], REVIEWER_NAME)
        self.assertEqual(event["timestamp_utc"], journal["created_at_utc"])

        # The checkpoint points to exactly that event.
        checkpoint = ri._read_checkpoint(
            os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        )
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint["last_sequence"], event["sequence"])
        self.assertEqual(checkpoint["last_record_id"], event["event_id"])
        self.assertEqual(
            checkpoint["last_record_hash"], event["event_hash"]
        )

        # Exactly one valid immutable recovery receipt recording the
        # SNAPSHOT_CREATED interruption.
        recovery_dir = os.path.join(self.task_dir, "review-recovery")
        self.assertEqual(
            sorted(os.listdir(recovery_dir)),
            [f"transaction-resumed-{transaction_id}.json"],
        )
        self.assertTrue(
            os.path.exists(self._receipt_path(transaction_id))
        )
        receipt = ri.read_recovery_receipt(
            self.task_dir, transaction_id=transaction_id
        )
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["transaction_id"], transaction_id)
        self.assertEqual(
            receipt["interrupted_stage"], "SNAPSHOT_CREATED"
        )
        self.assertEqual(receipt["resuming_reviewer_id"], REVIEWER_ID)
        self.assertEqual(
            receipt["resuming_reviewer_display_name"], REVIEWER_NAME
        )
        self.assertEqual(receipt["reason"], reason)
        self.assertEqual(
            receipt["resulting_manifest_hash"],
            plan["proposed_manifest_hash"],
        )
        self.assertEqual(
            receipt["resulting_audit_chain_head"],
            journal["expected_event_hash"],
        )

        # Journal and lock are removed only after completion; no
        # uncommitted event tail remains.
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))
        self.assertFalse(os.path.exists(self._journal_path()))
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

    def test_resume_snapshot_created_rejects_mismatched_proposed_temp(self):
        claim_text = f"Mismatch temp claim text {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        notes = f"mismatch temp notes {self._NOTES_CANARY}"
        reason = f"mismatch temp resume reason {self._REASON_CANARY}"
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        self._write_manifest([original_claim])

        plan = pilot_review._plan_claim_transaction(
            self.task_dir,
            operation="verify-claim",
            claim_id=CLAIM_ID_A,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            notes=notes,
        )
        journal = plan["journal"]
        transaction_id = journal["transaction_id"]
        lock_token = plan["lock_token"]

        # Real Steps 8-9 seam: fail the Step-10 write so the real
        # durable flow retains the journal at SNAPSHOT_CREATED with its
        # matching lock and verified snapshot (approved Section 2.4).
        seam = pilot_review.ReviewError("SNAPSHOT_CREATED fixture seam")
        with mock.patch.object(
            pilot_review,
            "_write_durable_proposed_manifest",
            side_effect=seam,
        ):
            with self.assertRaises(pilot_review.ReviewError):
                pilot_review._execute_claim_transaction_durable(
                    self.task_dir, plan
                )

        retained = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(
            retained["transaction_stage"], "SNAPSHOT_CREATED"
        )
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], lock_token)
        snapshot_path = os.path.join(
            self.task_dir, plan["snapshot_relative_path"]
        )
        self.assertTrue(os.path.exists(snapshot_path))

        # Tampered test evidence: deliberately mismatched bytes at the
        # recorded confined temp path, journal never advanced. Every
        # other byte on disk came from real production transitions.
        temp_path = os.path.join(
            self.task_dir, plan["proposed_manifest_relative_path"]
        )
        self.assertFalse(os.path.exists(temp_path))
        tampered_bytes = plan["proposed_manifest_bytes"].replace(
            b'"VERIFIED"', b'"VERIFXED"', 1
        )
        self.assertNotEqual(tampered_bytes, plan["proposed_manifest_bytes"])
        with open(temp_path, "xb") as handle:
            handle.write(tampered_bytes)

        # Capture the complete tree plus exact temp/journal/lock bytes.
        with open(temp_path, "rb") as handle:
            temp_bytes_before = handle.read()
        with open(self._journal_path(), "rb") as handle:
            journal_bytes_before = handle.read()
        with open(self._lock_path(), "rb") as handle:
            lock_bytes_before = handle.read()
        tree_before = _tree_snapshot(self.task_dir)

        # Resume with the write helper sentinel-patched: a mismatched
        # temp must fail closed before any overwrite attempt.
        write_sentinel = AssertionError(
            "_write_durable_proposed_manifest must not be called"
        )
        with mock.patch.object(
            pilot_review,
            "_write_durable_proposed_manifest",
            side_effect=write_sentinel,
        ) as write_mock:
            exit_code, out, err = self._run_cli([
                "resume-transaction",
                "--task-dir", self.task_dir,
                "--transaction-id", transaction_id,
                "--reviewer-id", REVIEWER_ID,
                "--reviewer-display-name", REVIEWER_NAME,
                "--reason", reason,
            ])
        write_mock.assert_not_called()

        # Exit 1, empty stdout, exactly the approved static
        # TRANSACTION_AMBIGUOUS line: no payload, path, filename,
        # token, or native exception text.
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(out, "")
        self.assertEqual(
            err,
            "error: TRANSACTION_AMBIGUOUS: durable proposed manifest "
            "does not hash to proposed_manifest_hash\n",
        )
        disclosures = (
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            (self._NOTES_CANARY, "claim notes canary"),
            (self._REASON_CANARY, "resume reason canary"),
            (lock_token, "lock token"),
            (self.task_dir, "task path"),
            (plan["proposed_manifest_relative_path"], "temp path"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # The mismatched temp, journal, and matching lock are retained
        # byte-for-byte; the manifest, snapshot, events, checkpoint,
        # and receipt receive no further mutation (tree identical).
        with open(temp_path, "rb") as handle:
            self.assertEqual(handle.read(), temp_bytes_before)
        with open(self._journal_path(), "rb") as handle:
            self.assertEqual(handle.read(), journal_bytes_before)
        with open(self._lock_path(), "rb") as handle:
            self.assertEqual(handle.read(), lock_bytes_before)
        retained = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(
            retained["transaction_stage"], "SNAPSHOT_CREATED"
        )
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], lock_token)
        self.assertEqual(_tree_snapshot(self.task_dir), tree_before)

    def test_resume_proposed_temp_notes_mismatch_fails_closed(self):
        # Amendment Section 2.6 / acceptance criterion 8: at resume a
        # durable proposed temp whose target-claim notes differ from the
        # journal claim_notes fails closed TRANSACTION_AMBIGUOUS before
        # any write; the temp is never deleted and never overwritten.
        # The inconsistency below reaches exactly that check: the journal
        # stays structurally valid with a recomputed self-hash, and the
        # temp still hashes to proposed_manifest_hash — only the recorded
        # notes value diverges.
        import json

        claim_text = f"Temp notes mismatch claim text {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        notes = f"original planned notes {self._NOTES_CANARY}"
        altered_notes = f"altered recorded notes {self._NOTES_CANARY}"
        reason = f"temp notes mismatch reason {self._REASON_CANARY}"
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        self._write_manifest([original_claim])

        plan = pilot_review._plan_claim_transaction(
            self.task_dir,
            operation="verify-claim",
            claim_id=CLAIM_ID_A,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            notes=notes,
        )
        journal = plan["journal"]
        transaction_id = journal["transaction_id"]
        lock_token = plan["lock_token"]
        self.assertEqual(journal["claim_notes"], notes)

        # Real Steps 8-9 seam (C3T fixture strategy): fail the Step-10
        # write so the real durable flow retains the journal at
        # SNAPSHOT_CREATED with its matching lock and verified snapshot.
        seam = pilot_review.ReviewError("SNAPSHOT_CREATED fixture seam")
        with mock.patch.object(
            pilot_review,
            "_write_durable_proposed_manifest",
            side_effect=seam,
        ):
            with self.assertRaises(pilot_review.ReviewError):
                pilot_review._execute_claim_transaction_durable(
                    self.task_dir, plan
                )

        retained = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(
            retained["transaction_stage"], "SNAPSHOT_CREATED"
        )
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], lock_token)
        snapshot_path = os.path.join(
            self.task_dir, plan["snapshot_relative_path"]
        )
        self.assertTrue(os.path.exists(snapshot_path))

        # The exact planned proposed bytes at the recorded temp path,
        # journal never advanced (the approved crash window).
        temp_path = os.path.join(
            self.task_dir, plan["proposed_manifest_relative_path"]
        )
        self.assertFalse(os.path.exists(temp_path))
        with open(temp_path, "xb") as handle:
            handle.write(plan["proposed_manifest_bytes"])

        # Deliberate evidence inconsistency, nothing else: the recorded
        # claim_notes becomes a different safe, non-secret value and
        # journal_hash is recomputed with the production canonical
        # helper. proposed_manifest_hash, the temp bytes, and every
        # other journal field are unchanged.
        with open(self._journal_path(), encoding="utf-8") as handle:
            altered = json.load(handle)
        altered["claim_notes"] = altered_notes
        altered["journal_hash"] = ri._canonical_hash(
            ri._journal_unsigned_fields(altered)
        )
        with open(self._journal_path(), "w", encoding="utf-8") as handle:
            json.dump(altered, handle)

        # The rewritten journal still validates through the production
        # read path (structure and self-hash), and the temp still hashes
        # to proposed_manifest_hash — the notes-equality check is the
        # only reachable failure.
        reread = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(reread["claim_notes"], altered_notes)
        self.assertEqual(
            pilot_review._hash_current(
                self.task_dir, plan["proposed_manifest_relative_path"]
            ),
            plan["proposed_manifest_hash"],
        )

        # Capture the complete pre-resume state.
        with open(temp_path, "rb") as handle:
            temp_bytes = handle.read()
        with open(self._journal_path(), "rb") as handle:
            journal_bytes = handle.read()
        with open(self._lock_path(), "rb") as handle:
            lock_bytes = handle.read()
        with open(snapshot_path, "rb") as handle:
            snapshot_bytes = handle.read()
        manifest_path = os.path.join(
            self.task_dir, "provenance_manifest.json"
        )
        with open(manifest_path, "rb") as handle:
            manifest_bytes = handle.read()
        tree_before = _tree_snapshot(self.task_dir)

        # Resume with the write helper sentinel-patched: the notes
        # mismatch must fail closed before any write attempt.
        write_sentinel = AssertionError(
            "_write_durable_proposed_manifest must not be called"
        )
        with mock.patch.object(
            pilot_review,
            "_write_durable_proposed_manifest",
            side_effect=write_sentinel,
        ) as write_mock:
            exit_code, out, err = self._run_cli([
                "resume-transaction",
                "--task-dir", self.task_dir,
                "--transaction-id", transaction_id,
                "--reviewer-id", REVIEWER_ID,
                "--reviewer-display-name", REVIEWER_NAME,
                "--reason", reason,
            ])
        write_mock.assert_not_called()

        # Exit 1, empty stdout, byte-exact static production line.
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(out, "")
        self.assertEqual(
            err,
            "error: TRANSACTION_AMBIGUOUS: durable proposed manifest "
            "target claim notes differ from the journal claim_notes\n",
        )

        # No disclosure: neither notes value, resume reason, task/temp/
        # journal paths, lock token, claim/query data, or native text.
        disclosures = (
            (notes, "original notes value"),
            (altered_notes, "altered notes value"),
            (reason, "resume reason canary"),
            (self.task_dir, "task path"),
            (temp_path, "temp path"),
            (self._journal_path(), "journal path"),
            (lock_token, "lock token"),
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # Temp, journal, matching lock, snapshot, and active manifest
        # remain byte-for-byte unchanged; no event, checkpoint, or
        # receipt exists; the journal remains SNAPSHOT_CREATED; the
        # complete task tree is byte-for-byte unchanged.
        with open(temp_path, "rb") as handle:
            self.assertEqual(handle.read(), temp_bytes)
        with open(self._journal_path(), "rb") as handle:
            self.assertEqual(handle.read(), journal_bytes)
        with open(self._lock_path(), "rb") as handle:
            self.assertEqual(handle.read(), lock_bytes)
        with open(snapshot_path, "rb") as handle:
            self.assertEqual(handle.read(), snapshot_bytes)
        with open(manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), manifest_bytes)
        self.assertEqual(
            ri.read_review_lock(self.task_dir)["lock_token"], lock_token
        )
        retained = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(
            retained["transaction_stage"], "SNAPSHOT_CREATED"
        )
        artifacts = self._transaction_artifacts()
        self.assertEqual(
            artifacts["proposed_temps"], [os.path.basename(temp_path)]
        )
        self.assertFalse(artifacts["recovery_dir"])
        self.assertFalse(
            os.path.exists(os.path.join(self.task_dir, "review-events"))
        )
        self.assertEqual(_tree_snapshot(self.task_dir), tree_before)

    _OS_CANARY = "CANARY-FS-H1-2f6c8d4a9e"

    def _canary_oserror(self):
        """OSError carrying a canary in errno, message, and filename."""
        return OSError(
            123,
            f"sentinel filesystem failure {self._OS_CANARY}",
            os.path.join(self.task_dir, f"{self._OS_CANARY}.tmp"),
        )

    def _verify_cli_interrupted(self, target, notes=None):
        """Real verify-claim CLI with a one-time canary OSError at the
        named pilot_review boundary; returns (exit_code, stdout, stderr).
        Supports this and later per-stage interruption tests (6.9).
        """
        argv = [
            "verify-claim",
            "--task-dir", self.task_dir,
            "--claim-id", CLAIM_ID_A,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
        ]
        if notes is not None:
            argv += ["--notes", notes]
        with mock.patch.object(
            pilot_review, target, side_effect=self._canary_oserror()
        ):
            return self._run_cli(argv)

    def test_restart_initiated(self):
        claim_text = f"Restart initiated claim text {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        notes = f"restart initiated notes {self._NOTES_CANARY}"
        reason = f"restart initiated resume reason {self._REASON_CANARY}"
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        self._write_manifest([original_claim])
        manifest_path = os.path.join(
            self.task_dir, "provenance_manifest.json"
        )
        with open(manifest_path, "rb") as handle:
            starting_manifest_bytes = handle.read()

        # Real direct verify-claim CLI; the one-time OSError fires at
        # the first stage advance (new_stage=LOCK_ACQUIRED), after
        # Steps 1-7 created the INITIATED journal and acquired the
        # matching lock, but before any snapshot, proposed temp,
        # event, checkpoint, or receipt exists (Section 6.9).
        real_update = ri.update_transaction_stage

        def _fail_first_advance(*args, **kwargs):
            if kwargs.get("new_stage") == "LOCK_ACQUIRED":
                raise self._canary_oserror()
            return real_update(*args, **kwargs)

        argv = [
            "verify-claim",
            "--task-dir", self.task_dir,
            "--claim-id", CLAIM_ID_A,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
            "--notes", notes,
        ]
        with mock.patch.object(
            ri,
            "update_transaction_stage",
            side_effect=_fail_first_advance,
        ):
            exit_code, out, err = self._run_cli(argv)

        # The direct command fails with the exact static filesystem
        # error; nothing native is disclosed.
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(err, "error: filesystem failure\n")
        self.assertEqual(out, "")
        for output in (out, err):
            self.assertNotIn(self._OS_CANARY, output)
            self.assertNotIn("Errno 123", output)

        # Journal at exactly INITIATED; the matching journal-recorded
        # lock is retained; the active manifest is unchanged; no
        # snapshot, proposed temp, event, checkpoint, or receipt.
        journal = ri.read_transaction_journal(self.task_dir)
        self.assertIsNotNone(journal)
        self.assertEqual(journal["transaction_stage"], "INITIATED")
        transaction_id = journal["transaction_id"]
        lock_token = journal["lock_token"]
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], lock_token)
        with open(manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), starting_manifest_bytes)
        self.assertEqual(ri.list_manifest_history(self.task_dir), [])
        artifacts = self._transaction_artifacts()
        self.assertTrue(artifacts["journal"])
        self.assertTrue(artifacts["lock"])
        self.assertEqual(artifacts["proposed_temps"], [])
        self.assertFalse(artifacts["recovery_dir"])
        events_dir = os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        self.assertFalse(os.path.exists(events_dir))

        # status, audit, verify-claim, and retract-claim stay
        # read-only while the journal sits at INITIATED.
        self._assert_interrupted_surfaces_read_only("INITIATED")
        with open(manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), starting_manifest_bytes)

        # Explicit resume-transaction through the real CLI.
        exit_code, out, err = self._run_cli([
            "resume-transaction",
            "--task-dir", self.task_dir,
            "--transaction-id", transaction_id,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
            "--reason", reason,
        ])
        self.assertEqual(exit_code, pilot_review.EXIT_OK)
        self.assertEqual(err, "")

        # Standard static non-disclosure: no canary, lock token,
        # absolute path, or native exception text on either stream.
        disclosures = (
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            (self._NOTES_CANARY, "claim notes canary"),
            (self._REASON_CANARY, "resume reason canary"),
            (lock_token, "lock token"),
            (self.task_dir, "task path"),
            (self._OS_CANARY, "filesystem canary"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # The resulting manifest, event, and checkpoint hashes match
        # the journal-recorded plan.
        manifest, _path, _sha = pilot_review._load_manifest(self.task_dir)
        self.assertEqual(
            prov.canonical_sha256(manifest),
            journal["proposed_manifest_hash"],
        )
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        self.assertEqual(
            committed[0]["event_id"], journal["expected_event_id"]
        )
        self.assertEqual(
            committed[0]["event_hash"], journal["expected_event_hash"]
        )
        checkpoint = ri._read_checkpoint(events_dir)
        self.assertIsNotNone(checkpoint)
        self.assertEqual(
            checkpoint["last_record_hash"],
            journal["expected_event_hash"],
        )

        # Exactly one valid recovery receipt recording the INITIATED
        # interruption.
        self.assertTrue(
            os.path.exists(self._receipt_path(transaction_id))
        )
        receipt = ri.read_recovery_receipt(
            self.task_dir, transaction_id=transaction_id
        )
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["interrupted_stage"], "INITIATED")
        self.assertEqual(
            receipt["resulting_manifest_hash"],
            journal["proposed_manifest_hash"],
        )
        self.assertEqual(
            receipt["resulting_audit_chain_head"],
            journal["expected_event_hash"],
        )

        # The journal and lock are removed; no uncommitted tail.
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))
        self.assertFalse(os.path.exists(self._journal_path()))
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

    def test_restart_lock_acquired(self):
        claim_text = f"Restart lock claim text {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        notes = f"restart lock notes {self._NOTES_CANARY}"
        reason = f"restart lock resume reason {self._REASON_CANARY}"
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        starting = self._write_manifest([original_claim])
        manifest_path = os.path.join(
            self.task_dir, "provenance_manifest.json"
        )
        with open(manifest_path, "rb") as handle:
            starting_manifest_bytes = handle.read()

        # Real direct verify-claim CLI; the one-time OSError fires at
        # snapshot creation, after the journal advanced to
        # LOCK_ACQUIRED but before any snapshot exists (Section 6.9).
        exit_code, out, err = self._verify_cli_interrupted(
            "_create_and_verify_snapshot", notes=notes
        )

        # The direct command fails with the exact static filesystem
        # error; nothing native is disclosed.
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(err, "error: filesystem failure\n")
        self.assertEqual(out, "")
        for output in (out, err):
            self.assertNotIn(self._OS_CANARY, output)
            self.assertNotIn("Errno 123", output)

        # Journal at exactly LOCK_ACQUIRED; matching lock retained;
        # active manifest still the starting bytes; no snapshot,
        # proposed temp, event, checkpoint, or receipt exists.
        journal = ri.read_transaction_journal(self.task_dir)
        self.assertIsNotNone(journal)
        self.assertEqual(journal["transaction_stage"], "LOCK_ACQUIRED")
        transaction_id = journal["transaction_id"]
        lock_token = journal["lock_token"]
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], lock_token)
        with open(manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), starting_manifest_bytes)
        artifacts = self._transaction_artifacts()
        self.assertTrue(artifacts["journal"])
        self.assertTrue(artifacts["lock"])
        self.assertEqual(artifacts["proposed_temps"], [])
        self.assertFalse(artifacts["recovery_dir"])
        self.assertFalse(
            os.path.exists(
                os.path.join(self.task_dir, "manifest-history")
            )
        )
        self.assertFalse(
            os.path.exists(
                os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
            )
        )

        # status, audit, verify-claim, and retract-claim stay
        # read-only while the journal is interrupted at LOCK_ACQUIRED.
        self._assert_interrupted_surfaces_read_only("LOCK_ACQUIRED")

        # Explicit resume-transaction completes the transaction.
        exit_code, out, err = self._run_cli([
            "resume-transaction",
            "--task-dir", self.task_dir,
            "--transaction-id", transaction_id,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
            "--reason", reason,
        ])

        # Exit 0, empty stderr, and the approved sanitized RESUMED
        # summary shape.
        self.assertEqual(exit_code, pilot_review.EXIT_OK)
        self.assertEqual(err, "")
        self.assertTrue(
            out.startswith(
                "BrainTrustCrypto pilot review — resume-transaction\n"
            )
        )
        self.assertRegex(out, r"(?m)^  result:\s+RESUMED$")
        self.assertIn(TASK_ID, out)
        self.assertIn(CLAIM_ID_A, out)
        self.assertIn(transaction_id, out)
        self.assertIn("verify-claim", out)
        self.assertIn(journal["proposed_manifest_hash"], out)
        self.assertIn(journal["expected_event_hash"], out)
        self.assertIn(journal["snapshot_relative_path"], out)
        self.assertIn("NEEDS_HUMAN_REVIEW", out)

        # Non-disclosure: no canary, lock token, absolute path, or
        # native exception text on either stream.
        disclosures = (
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            (self._NOTES_CANARY, "claim notes canary"),
            (self._REASON_CANARY, "resume reason canary"),
            (lock_token, "lock token"),
            (self.task_dir, "task path"),
            (self._OS_CANARY, "filesystem canary"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # The active manifest hashes exactly to the journal-recorded
        # proposed manifest hash.
        manifest, _path, _sha = pilot_review._load_manifest(self.task_dir)
        self.assertEqual(
            prov.canonical_sha256(manifest),
            journal["proposed_manifest_hash"],
        )

        # The target claim carries exactly the approved five mutations.
        installed = None
        for claim in manifest["factual_claims"]:
            if claim.get("claim_id") == CLAIM_ID_A:
                installed = claim
                break
        self.assertIsNotNone(installed)
        expected_claim = dict(original_claim)
        expected_claim.update({
            "status": "VERIFIED",
            "reviewer_id": REVIEWER_ID,
            "reviewer_display_name": REVIEWER_NAME,
            "review_timestamp_utc": journal["created_at_utc"],
            "notes": notes,
        })
        self.assertEqual(installed, expected_claim)

        # The immutable starting snapshot exists and hashes exactly to
        # the starting manifest.
        snapshot_path = os.path.join(
            self.task_dir, journal["snapshot_relative_path"]
        )
        self.assertTrue(os.path.exists(snapshot_path))
        history = ri.list_manifest_history(self.task_dir)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0], starting)
        self.assertEqual(
            prov.canonical_sha256(history[0]),
            journal["starting_manifest_hash"],
        )

        # Exactly one committed event with the journal-recorded
        # identity and correct before/after hashes; the chain validates.
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        event = committed[0]
        self.assertEqual(event["sequence"], 1)
        self.assertEqual(event["event_id"], journal["expected_event_id"])
        self.assertEqual(
            event["event_hash"], journal["expected_event_hash"]
        )
        self.assertEqual(
            event["manifest_hash_before"],
            journal["starting_manifest_hash"],
        )
        self.assertEqual(
            event["manifest_hash_after"],
            journal["proposed_manifest_hash"],
        )
        self.assertEqual(event["event_type"], "CLAIM_VERIFIED")
        self.assertEqual(event["reviewer_id"], REVIEWER_ID)
        self.assertEqual(event["reviewer_display_name"], REVIEWER_NAME)
        self.assertEqual(event["timestamp_utc"], journal["created_at_utc"])

        # The checkpoint points to exactly that event.
        checkpoint = ri._read_checkpoint(
            os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        )
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint["last_sequence"], event["sequence"])
        self.assertEqual(checkpoint["last_record_id"], event["event_id"])
        self.assertEqual(
            checkpoint["last_record_hash"], event["event_hash"]
        )

        # Exactly one valid immutable recovery receipt recording the
        # LOCK_ACQUIRED interruption.
        recovery_dir = os.path.join(self.task_dir, "review-recovery")
        self.assertEqual(
            sorted(os.listdir(recovery_dir)),
            [f"transaction-resumed-{transaction_id}.json"],
        )
        self.assertTrue(
            os.path.exists(self._receipt_path(transaction_id))
        )
        receipt = ri.read_recovery_receipt(
            self.task_dir, transaction_id=transaction_id
        )
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["transaction_id"], transaction_id)
        self.assertEqual(
            receipt["interrupted_stage"], "LOCK_ACQUIRED"
        )
        self.assertEqual(receipt["resuming_reviewer_id"], REVIEWER_ID)
        self.assertEqual(
            receipt["resuming_reviewer_display_name"], REVIEWER_NAME
        )
        self.assertEqual(receipt["reason"], reason)
        self.assertEqual(
            receipt["resulting_manifest_hash"],
            journal["proposed_manifest_hash"],
        )
        self.assertEqual(
            receipt["resulting_audit_chain_head"],
            journal["expected_event_hash"],
        )

        # Journal and lock are removed only after completion; no
        # uncommitted event tail remains.
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))
        self.assertFalse(os.path.exists(self._journal_path()))
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

    def test_restart_snapshot_created(self):
        claim_text = f"Restart snapshot claim text {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        notes = f"restart snapshot notes {self._NOTES_CANARY}"
        reason = f"restart snapshot resume reason {self._REASON_CANARY}"
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        starting = self._write_manifest([original_claim])
        manifest_path = os.path.join(
            self.task_dir, "provenance_manifest.json"
        )
        with open(manifest_path, "rb") as handle:
            starting_manifest_bytes = handle.read()

        # Real direct verify-claim CLI; the one-time OSError fires at
        # the durable proposed-manifest write, after the journal
        # advanced to SNAPSHOT_CREATED and the immutable starting
        # snapshot exists, but before any proposed temp (Section 6.9).
        exit_code, out, err = self._verify_cli_interrupted(
            "_write_durable_proposed_manifest", notes=notes
        )

        # The direct command fails with the exact static filesystem
        # error; nothing native is disclosed.
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(err, "error: filesystem failure\n")
        self.assertEqual(out, "")
        for output in (out, err):
            self.assertNotIn(self._OS_CANARY, output)
            self.assertNotIn("Errno 123", output)

        # Journal at exactly SNAPSHOT_CREATED; matching lock retained;
        # the immutable starting snapshot exists and hashes exactly to
        # the journal-recorded starting manifest hash; the active
        # manifest is still the starting bytes; no proposed temp,
        # event, checkpoint, or receipt exists.
        journal = ri.read_transaction_journal(self.task_dir)
        self.assertIsNotNone(journal)
        self.assertEqual(journal["transaction_stage"], "SNAPSHOT_CREATED")
        transaction_id = journal["transaction_id"]
        lock_token = journal["lock_token"]
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], lock_token)
        with open(manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), starting_manifest_bytes)
        snapshot_path = os.path.join(
            self.task_dir, journal["snapshot_relative_path"]
        )
        self.assertTrue(os.path.exists(snapshot_path))
        history = ri.list_manifest_history(self.task_dir)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0], starting)
        self.assertEqual(
            prov.canonical_sha256(history[0]),
            journal["starting_manifest_hash"],
        )
        artifacts = self._transaction_artifacts()
        self.assertTrue(artifacts["journal"])
        self.assertTrue(artifacts["lock"])
        self.assertEqual(artifacts["proposed_temps"], [])
        self.assertFalse(artifacts["recovery_dir"])
        self.assertFalse(
            os.path.exists(
                os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
            )
        )

        # status, audit, verify-claim, and retract-claim stay
        # read-only while the journal sits at SNAPSHOT_CREATED.
        self._assert_interrupted_surfaces_read_only("SNAPSHOT_CREATED")

        # Explicit resume-transaction completes the transaction.
        exit_code, out, err = self._run_cli([
            "resume-transaction",
            "--task-dir", self.task_dir,
            "--transaction-id", transaction_id,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
            "--reason", reason,
        ])

        # Exit 0 with empty stderr; essential final state only. The
        # exhaustive summary-shape and five-field claim assertions
        # live in test_resume_transaction_success.
        self.assertEqual(exit_code, pilot_review.EXIT_OK)
        self.assertEqual(err, "")

        # Standard static non-disclosure: no canary, lock token,
        # absolute path, or native exception text on either stream.
        disclosures = (
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            (self._NOTES_CANARY, "claim notes canary"),
            (self._REASON_CANARY, "resume reason canary"),
            (lock_token, "lock token"),
            (self.task_dir, "task path"),
            (self._OS_CANARY, "filesystem canary"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # The active manifest hashes exactly to the journal-recorded
        # proposed manifest hash.
        manifest, _path, _sha = pilot_review._load_manifest(self.task_dir)
        self.assertEqual(
            prov.canonical_sha256(manifest),
            journal["proposed_manifest_hash"],
        )

        # Exactly one committed event with the journal-recorded
        # identity and before/after hashes; the checkpoint points to
        # exactly that event.
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        event = committed[0]
        self.assertEqual(event["event_id"], journal["expected_event_id"])
        self.assertEqual(
            event["event_hash"], journal["expected_event_hash"]
        )
        self.assertEqual(
            event["manifest_hash_before"],
            journal["starting_manifest_hash"],
        )
        self.assertEqual(
            event["manifest_hash_after"],
            journal["proposed_manifest_hash"],
        )
        checkpoint = ri._read_checkpoint(
            os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        )
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint["last_sequence"], event["sequence"])
        self.assertEqual(checkpoint["last_record_id"], event["event_id"])
        self.assertEqual(
            checkpoint["last_record_hash"], event["event_hash"]
        )

        # Exactly one valid immutable recovery receipt recording the
        # SNAPSHOT_CREATED interruption.
        self.assertTrue(
            os.path.exists(self._receipt_path(transaction_id))
        )
        receipt = ri.read_recovery_receipt(
            self.task_dir, transaction_id=transaction_id
        )
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["transaction_id"], transaction_id)
        self.assertEqual(
            receipt["interrupted_stage"], "SNAPSHOT_CREATED"
        )
        self.assertEqual(
            receipt["resulting_manifest_hash"],
            journal["proposed_manifest_hash"],
        )
        self.assertEqual(
            receipt["resulting_audit_chain_head"],
            journal["expected_event_hash"],
        )

        # Journal and lock are removed only after completion; no
        # uncommitted event tail remains.
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))
        self.assertFalse(os.path.exists(self._journal_path()))
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

    def test_restart_snapshot_created_retract_rebuilds_from_claim_notes(self):
        # Amendment Section 5 (B2): retract-side exact-stage fixture.
        # A real retract-claim transaction interrupted after Step 9
        # (snapshot written, durable write failed, no proposed temp)
        # rebuilds the deterministic proposed manifest from journal
        # fields at resume; the installed claim notes and the committed
        # CLAIM_RETRACTED event reason carry exactly the original
        # journal claim_notes (amendment Section 2.4), and the recovery
        # receipt is the only place the new resume reason appears.
        claim_text = f"Retract restart claim text {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        original_reason = (
            f"original retraction reason {self._NOTES_CANARY}"
        )
        resume_reason = (
            f"retract restart resume reason {self._REASON_CANARY}"
        )
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        self._write_manifest([original_claim])
        manifest_path = os.path.join(
            self.task_dir, "provenance_manifest.json"
        )

        # Begin with a VERIFIED claim via the real verify-claim CLI.
        verify_code, _vo, verify_err = self._run_cli([
            "verify-claim",
            "--task-dir", self.task_dir,
            "--claim-id", CLAIM_ID_A,
            "--reviewer-id", "verifier-original",
            "--reviewer-display-name", "Verifier Original",
            "--notes", "initial verification",
        ])
        self.assertEqual(verify_code, pilot_review.EXIT_OK, verify_err)
        with open(manifest_path, "rb") as handle:
            verified_manifest_bytes = handle.read()
        verified_manifest, _vp, _vs = pilot_review._load_manifest(
            self.task_dir
        )
        verified_claim = None
        for claim in verified_manifest["factual_claims"]:
            if claim.get("claim_id") == CLAIM_ID_A:
                verified_claim = claim
                break
        self.assertIsNotNone(verified_claim)
        checkpoint_before = ri._read_checkpoint(
            os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        )
        self.assertIsNotNone(checkpoint_before)

        # Real retract-claim CLI; the one-time canary OSError fires at
        # the durable proposed-manifest write — the exact mirror of
        # test_restart_snapshot_created's Section 6.9 stage.
        with mock.patch.object(
            pilot_review,
            "_write_durable_proposed_manifest",
            side_effect=self._canary_oserror(),
        ):
            exit_code, out, err = self._run_cli([
                "retract-claim",
                "--task-dir", self.task_dir,
                "--claim-id", CLAIM_ID_A,
                "--reviewer-id", REVIEWER_ID,
                "--reviewer-display-name", REVIEWER_NAME,
                "--reason", original_reason,
            ])
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(err, "error: filesystem failure\n")
        self.assertEqual(out, "")
        for output in (out, err):
            self.assertNotIn(self._OS_CANARY, output)
            self.assertNotIn("Errno 123", output)

        # Journal at exactly SNAPSHOT_CREATED carrying the original
        # retraction reason as claim_notes; matching lock retained.
        journal = ri.read_transaction_journal(self.task_dir)
        self.assertIsNotNone(journal)
        self.assertEqual(
            journal["transaction_stage"], "SNAPSHOT_CREATED"
        )
        self.assertEqual(journal["operation"], "retract-claim")
        self.assertEqual(journal["claim_notes"], original_reason)
        transaction_id = journal["transaction_id"]
        lock_token = journal["lock_token"]
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], lock_token)

        # The active manifest remains the verified starting manifest,
        # byte-for-byte; the immutable starting snapshot exists and
        # hashes exactly to the journal-recorded starting hash.
        with open(manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), verified_manifest_bytes)
        snapshot_path = os.path.join(
            self.task_dir, journal["snapshot_relative_path"]
        )
        self.assertTrue(os.path.exists(snapshot_path))
        history = ri.list_manifest_history(self.task_dir)
        self.assertEqual(len(history), 2)
        self.assertEqual(
            prov.canonical_sha256(history[-1]),
            journal["starting_manifest_hash"],
        )

        # No proposed temp; the interrupted retract created no event,
        # advanced no checkpoint, and wrote no receipt.
        artifacts = self._transaction_artifacts()
        self.assertTrue(artifacts["journal"])
        self.assertTrue(artifacts["lock"])
        self.assertEqual(artifacts["proposed_temps"], [])
        self.assertFalse(artifacts["recovery_dir"])
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        self.assertEqual(committed[0]["event_type"], "CLAIM_VERIFIED")
        self.assertEqual(
            ri._read_checkpoint(
                os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
            ),
            checkpoint_before,
        )
        self.assertFalse(
            os.path.exists(self._receipt_path(transaction_id))
        )

        # status, audit, verify-claim, and retract-claim stay
        # read-only while the journal sits at SNAPSHOT_CREATED.
        self._assert_interrupted_surfaces_read_only("SNAPSHOT_CREATED")

        # Explicit resume-transaction rebuilds and completes.
        exit_code, out, err = self._run_cli([
            "resume-transaction",
            "--task-dir", self.task_dir,
            "--transaction-id", transaction_id,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
            "--reason", resume_reason,
        ])
        self.assertEqual(exit_code, pilot_review.EXIT_OK)
        self.assertEqual(err, "")

        # Standard static non-disclosure on the resume streams.
        disclosures = (
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            (self._NOTES_CANARY, "claim notes canary"),
            (self._REASON_CANARY, "resume reason canary"),
            (original_reason, "original retraction reason"),
            (lock_token, "lock token"),
            (self.task_dir, "task path"),
            (self._OS_CANARY, "filesystem canary"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # The deterministically rebuilt proposed manifest — journal
        # fields alone, no temp ever existed — installs byte-exact
        # under canonical hashing.
        manifest, _path, _sha = pilot_review._load_manifest(self.task_dir)
        self.assertEqual(
            prov.canonical_sha256(manifest),
            journal["proposed_manifest_hash"],
        )

        # The target claim is RETRACTED, still attributed to the
        # original transaction reviewer at the frozen original
        # timestamp; its notes are exactly the original journal
        # claim_notes.
        installed = None
        for claim in manifest["factual_claims"]:
            if claim.get("claim_id") == CLAIM_ID_A:
                installed = claim
                break
        self.assertIsNotNone(installed)
        expected_claim = dict(verified_claim)
        expected_claim.update({
            "status": "RETRACTED",
            "reviewer_id": REVIEWER_ID,
            "reviewer_display_name": REVIEWER_NAME,
            "review_timestamp_utc": journal["created_at_utc"],
            "notes": original_reason,
        })
        self.assertEqual(installed, expected_claim)

        # Exactly one new committed CLAIM_RETRACTED event with the
        # journal-recorded identity and hashes; its reason is exactly
        # the original journal claim_notes.
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 2)
        event = committed[1]
        self.assertEqual(event["sequence"], 2)
        self.assertEqual(event["event_id"], journal["expected_event_id"])
        self.assertEqual(
            event["event_hash"], journal["expected_event_hash"]
        )
        self.assertEqual(
            event["manifest_hash_before"],
            journal["starting_manifest_hash"],
        )
        self.assertEqual(
            event["manifest_hash_after"],
            journal["proposed_manifest_hash"],
        )
        self.assertEqual(event["event_type"], "CLAIM_RETRACTED")
        self.assertEqual(event["reason"], original_reason)
        self.assertEqual(event["reviewer_id"], REVIEWER_ID)
        self.assertEqual(event["reviewer_display_name"], REVIEWER_NAME)
        self.assertEqual(
            event["timestamp_utc"], journal["created_at_utc"]
        )

        # The checkpoint points to exactly that event.
        checkpoint = ri._read_checkpoint(
            os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        )
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint["last_sequence"], event["sequence"])
        self.assertEqual(
            checkpoint["last_record_id"], event["event_id"]
        )
        self.assertEqual(
            checkpoint["last_record_hash"], event["event_hash"]
        )

        # Exactly one valid immutable recovery receipt — the only place
        # the resuming reviewer and the new resume reason appear; the
        # original claim_notes never enter it.
        recovery_dir = os.path.join(self.task_dir, "review-recovery")
        self.assertEqual(
            sorted(os.listdir(recovery_dir)),
            [f"transaction-resumed-{transaction_id}.json"],
        )
        receipt = ri.read_recovery_receipt(
            self.task_dir, transaction_id=transaction_id
        )
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["transaction_id"], transaction_id)
        self.assertEqual(
            receipt["interrupted_stage"], "SNAPSHOT_CREATED"
        )
        self.assertEqual(
            receipt["resuming_reviewer_id"], REVIEWER_ID
        )
        self.assertEqual(
            receipt["resuming_reviewer_display_name"], REVIEWER_NAME
        )
        self.assertEqual(receipt["reason"], resume_reason)
        self.assertEqual(
            receipt["resulting_manifest_hash"],
            journal["proposed_manifest_hash"],
        )
        self.assertEqual(
            receipt["resulting_audit_chain_head"],
            journal["expected_event_hash"],
        )
        self.assertNotIn("claim_notes", receipt)
        self.assertNotIn(original_reason, str(receipt))

        # Journal and lock are removed; the snapshot is retained; no
        # uncommitted event tail remains.
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))
        self.assertFalse(os.path.exists(self._journal_path()))
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        self.assertTrue(os.path.exists(snapshot_path))
        history = ri.list_manifest_history(self.task_dir)
        self.assertEqual(len(history), 2)
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

    def test_restart_proposed_manifest_ready(self):
        claim_text = f"Restart proposed claim text {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        notes = f"restart proposed notes {self._NOTES_CANARY}"
        reason = f"restart proposed resume reason {self._REASON_CANARY}"
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        starting = self._write_manifest([original_claim])
        manifest_path = os.path.join(
            self.task_dir, "provenance_manifest.json"
        )
        with open(manifest_path, "rb") as handle:
            starting_manifest_bytes = handle.read()

        # Real direct verify-claim CLI; the one-time OSError fires at
        # planned event creation, after the journal advanced to
        # PROPOSED_MANIFEST_READY with the durable proposed temp
        # written, but before any event exists (Section 6.9).
        exit_code, out, err = self._verify_cli_interrupted(
            "_create_and_verify_planned_event", notes=notes
        )

        # The direct command fails with the exact static filesystem
        # error; nothing native is disclosed.
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(err, "error: filesystem failure\n")
        self.assertEqual(out, "")
        for output in (out, err):
            self.assertNotIn(self._OS_CANARY, output)
            self.assertNotIn("Errno 123", output)

        # Journal at exactly PROPOSED_MANIFEST_READY; matching lock
        # retained; the immutable starting snapshot exists and hashes
        # to starting_manifest_hash; the exact journal-recorded
        # durable proposed temp is present and hashes to
        # proposed_manifest_hash; the active manifest is still the
        # starting bytes; no event tail, checkpoint, or receipt.
        journal = ri.read_transaction_journal(self.task_dir)
        self.assertIsNotNone(journal)
        self.assertEqual(
            journal["transaction_stage"], "PROPOSED_MANIFEST_READY"
        )
        transaction_id = journal["transaction_id"]
        lock_token = journal["lock_token"]
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], lock_token)
        with open(manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), starting_manifest_bytes)
        snapshot_path = os.path.join(
            self.task_dir, journal["snapshot_relative_path"]
        )
        self.assertTrue(os.path.exists(snapshot_path))
        history = ri.list_manifest_history(self.task_dir)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0], starting)
        self.assertEqual(
            prov.canonical_sha256(history[0]),
            journal["starting_manifest_hash"],
        )
        artifacts = self._transaction_artifacts()
        self.assertTrue(artifacts["journal"])
        self.assertTrue(artifacts["lock"])
        self.assertEqual(
            artifacts["proposed_temps"],
            [journal["proposed_manifest_relative_path"]],
        )
        self.assertEqual(
            pilot_review._hash_current(
                self.task_dir,
                journal["proposed_manifest_relative_path"],
            ),
            journal["proposed_manifest_hash"],
        )
        self.assertFalse(artifacts["recovery_dir"])
        self.assertFalse(
            os.path.exists(
                os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
            )
        )
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

        # status, audit, verify-claim, and retract-claim stay
        # read-only while the journal sits at PROPOSED_MANIFEST_READY.
        self._assert_interrupted_surfaces_read_only(
            "PROPOSED_MANIFEST_READY"
        )

        # Explicit resume-transaction completes the transaction; with
        # no uncommitted tail the no-tail branch creates exactly the
        # journal-planned event (approved Section 2.8).
        exit_code, out, err = self._run_cli([
            "resume-transaction",
            "--task-dir", self.task_dir,
            "--transaction-id", transaction_id,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
            "--reason", reason,
        ])

        # Exit 0 with empty stderr; essential final state only. The
        # exhaustive summary-shape and five-field claim assertions
        # live in test_resume_transaction_success.
        self.assertEqual(exit_code, pilot_review.EXIT_OK)
        self.assertEqual(err, "")

        # Standard static non-disclosure: no canary, lock token,
        # absolute path, or native exception text on either stream.
        disclosures = (
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            (self._NOTES_CANARY, "claim notes canary"),
            (self._REASON_CANARY, "resume reason canary"),
            (lock_token, "lock token"),
            (self.task_dir, "task path"),
            (self._OS_CANARY, "filesystem canary"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # The proposed manifest is installed: the active manifest
        # hashes exactly to the journal-recorded proposed hash.
        manifest, _path, _sha = pilot_review._load_manifest(self.task_dir)
        self.assertEqual(
            prov.canonical_sha256(manifest),
            journal["proposed_manifest_hash"],
        )

        # Exactly one committed event with the journal-planned
        # identity and before/after hashes; the checkpoint is
        # committed at exactly that event.
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        event = committed[0]
        self.assertEqual(event["event_id"], journal["expected_event_id"])
        self.assertEqual(
            event["event_hash"], journal["expected_event_hash"]
        )
        self.assertEqual(
            event["manifest_hash_before"],
            journal["starting_manifest_hash"],
        )
        self.assertEqual(
            event["manifest_hash_after"],
            journal["proposed_manifest_hash"],
        )
        checkpoint = ri._read_checkpoint(
            os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        )
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint["last_sequence"], event["sequence"])
        self.assertEqual(checkpoint["last_record_id"], event["event_id"])
        self.assertEqual(
            checkpoint["last_record_hash"], event["event_hash"]
        )

        # Exactly one valid immutable recovery receipt recording the
        # PROPOSED_MANIFEST_READY interruption.
        self.assertTrue(
            os.path.exists(self._receipt_path(transaction_id))
        )
        receipt = ri.read_recovery_receipt(
            self.task_dir, transaction_id=transaction_id
        )
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["transaction_id"], transaction_id)
        self.assertEqual(
            receipt["interrupted_stage"], "PROPOSED_MANIFEST_READY"
        )
        self.assertEqual(
            receipt["resulting_manifest_hash"],
            journal["proposed_manifest_hash"],
        )
        self.assertEqual(
            receipt["resulting_audit_chain_head"],
            journal["expected_event_hash"],
        )

        # Journal and lock are removed only after completion; no
        # uncommitted event tail remains.
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))
        self.assertFalse(os.path.exists(self._journal_path()))
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

    def test_restart_proposed_manifest_ready_exact_tail(self):
        claim_text = f"Restart exact-tail claim text {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        notes = f"restart exact-tail notes {self._NOTES_CANARY}"
        reason = f"restart exact-tail resume reason {self._REASON_CANARY}"
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        starting = self._write_manifest([original_claim])
        manifest_path = os.path.join(
            self.task_dir, "provenance_manifest.json"
        )
        with open(manifest_path, "rb") as handle:
            starting_manifest_bytes = handle.read()

        # Real direct verify-claim CLI; a one-time canary OSError
        # fires when the journal advance to EVENT_CREATED is
        # attempted, after Step 11 created the planned event. The
        # crash window leaves exactly the journal-planned event as an
        # uncommitted tail at PROPOSED_MANIFEST_READY (Section 6.9).
        real_update_stage = ri.update_transaction_stage

        def _fail_event_created_advance(*args, **kwargs):
            if kwargs.get("new_stage") == "EVENT_CREATED":
                raise self._canary_oserror()
            return real_update_stage(*args, **kwargs)

        argv = [
            "verify-claim",
            "--task-dir", self.task_dir,
            "--claim-id", CLAIM_ID_A,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
            "--notes", notes,
        ]
        with mock.patch.object(
            ri,
            "update_transaction_stage",
            side_effect=_fail_event_created_advance,
        ) as advance_mock:
            exit_code, out, err = self._run_cli(argv)

        # The direct command fails with the exact static filesystem
        # error; nothing native is disclosed.
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(err, "error: filesystem failure\n")
        self.assertEqual(out, "")
        for output in (out, err):
            self.assertNotIn(self._OS_CANARY, output)
            self.assertNotIn("Errno 123", output)

        # The injected seam is exactly the journal-stage advance after
        # Step 11: three advances passed through to the real function,
        # the fourth (EVENT_CREATED) raised the canary OSError.
        self.assertEqual(advance_mock.call_count, 4)
        self.assertEqual(
            advance_mock.call_args.kwargs["new_stage"], "EVENT_CREATED"
        )

        # Journal remains at exactly PROPOSED_MANIFEST_READY; matching
        # lock retained; the immutable starting snapshot exists and
        # hashes to starting_manifest_hash; the exact journal-recorded
        # durable proposed temp is present and hashes to
        # proposed_manifest_hash; the active manifest is still the
        # starting bytes.
        journal = ri.read_transaction_journal(self.task_dir)
        self.assertIsNotNone(journal)
        self.assertEqual(
            journal["transaction_stage"], "PROPOSED_MANIFEST_READY"
        )
        transaction_id = journal["transaction_id"]
        lock_token = journal["lock_token"]
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], lock_token)
        with open(manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), starting_manifest_bytes)
        snapshot_path = os.path.join(
            self.task_dir, journal["snapshot_relative_path"]
        )
        self.assertTrue(os.path.exists(snapshot_path))
        history = ri.list_manifest_history(self.task_dir)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0], starting)
        self.assertEqual(
            prov.canonical_sha256(history[0]),
            journal["starting_manifest_hash"],
        )
        artifacts = self._transaction_artifacts()
        self.assertTrue(artifacts["journal"])
        self.assertTrue(artifacts["lock"])
        self.assertEqual(
            artifacts["proposed_temps"],
            [journal["proposed_manifest_relative_path"]],
        )
        self.assertEqual(
            pilot_review._hash_current(
                self.task_dir,
                journal["proposed_manifest_relative_path"],
            ),
            journal["proposed_manifest_hash"],
        )
        self.assertFalse(artifacts["recovery_dir"])

        # Exactly one uncommitted tail exists: the journal-planned
        # event, never checkpointed. Capture its bytes.
        tail = ri.find_uncommitted_tail(
            self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
        )
        self.assertEqual(len(tail), 1)
        tail_sequence, tail_name = tail[0]
        self.assertEqual(tail_sequence, 1)
        events_dir = os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        tail_path = os.path.join(events_dir, tail_name)
        tail_event = ri._read_json_file(tail_path, "planned event")
        self.assertEqual(
            tail_event["event_id"], journal["expected_event_id"]
        )
        self.assertEqual(
            tail_event["event_hash"], journal["expected_event_hash"]
        )
        with open(tail_path, "rb") as handle:
            tail_event_bytes = handle.read()

        # No checkpoint committed the event; no receipt exists.
        self.assertIsNone(ri._read_checkpoint(events_dir))

        # status, audit, verify-claim, and retract-claim stay
        # read-only while the journal sits at PROPOSED_MANIFEST_READY.
        self._assert_interrupted_surfaces_read_only(
            "PROPOSED_MANIFEST_READY"
        )

        # Explicit resume-transaction: the exact sole planned tail is
        # verified read-only (approved Section 2.8) — the planned
        # event creation step must never run.
        create_sentinel = AssertionError(
            "_create_and_verify_planned_event must not be called"
        )
        with mock.patch.object(
            pilot_review,
            "_create_and_verify_planned_event",
            side_effect=create_sentinel,
        ) as create_mock:
            exit_code, out, err = self._run_cli([
                "resume-transaction",
                "--task-dir", self.task_dir,
                "--transaction-id", transaction_id,
                "--reviewer-id", REVIEWER_ID,
                "--reviewer-display-name", REVIEWER_NAME,
                "--reason", reason,
            ])

        # Exit 0 with empty stderr; the creation step was never called.
        self.assertEqual(exit_code, pilot_review.EXIT_OK)
        self.assertEqual(err, "")
        create_mock.assert_not_called()

        # Standard static non-disclosure: no canary, lock token,
        # absolute path, or native exception text on either stream.
        disclosures = (
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            (self._NOTES_CANARY, "claim notes canary"),
            (self._REASON_CANARY, "resume reason canary"),
            (lock_token, "lock token"),
            (self.task_dir, "task path"),
            (self._OS_CANARY, "filesystem canary"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # The committed event is byte-for-byte the captured tail event.
        with open(tail_path, "rb") as handle:
            self.assertEqual(handle.read(), tail_event_bytes)

        # The proposed manifest is installed: the active manifest
        # hashes exactly to the journal-recorded proposed hash.
        manifest, _path, _sha = pilot_review._load_manifest(self.task_dir)
        self.assertEqual(
            prov.canonical_sha256(manifest),
            journal["proposed_manifest_hash"],
        )

        # Exactly one committed event with the journal-planned
        # identity and before/after hashes; the checkpoint is
        # committed at exactly that event.
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        event = committed[0]
        self.assertEqual(event["event_id"], journal["expected_event_id"])
        self.assertEqual(
            event["event_hash"], journal["expected_event_hash"]
        )
        self.assertEqual(
            event["manifest_hash_before"],
            journal["starting_manifest_hash"],
        )
        self.assertEqual(
            event["manifest_hash_after"],
            journal["proposed_manifest_hash"],
        )
        checkpoint = ri._read_checkpoint(events_dir)
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint["last_sequence"], event["sequence"])
        self.assertEqual(checkpoint["last_record_id"], event["event_id"])
        self.assertEqual(
            checkpoint["last_record_hash"], event["event_hash"]
        )

        # Exactly one valid immutable recovery receipt recording the
        # PROPOSED_MANIFEST_READY interruption.
        self.assertTrue(
            os.path.exists(self._receipt_path(transaction_id))
        )
        receipt = ri.read_recovery_receipt(
            self.task_dir, transaction_id=transaction_id
        )
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["transaction_id"], transaction_id)
        self.assertEqual(
            receipt["interrupted_stage"], "PROPOSED_MANIFEST_READY"
        )
        self.assertEqual(
            receipt["resulting_manifest_hash"],
            journal["proposed_manifest_hash"],
        )
        self.assertEqual(
            receipt["resulting_audit_chain_head"],
            journal["expected_event_hash"],
        )

        # Journal and lock are removed only after completion; no
        # uncommitted event tail remains.
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))
        self.assertFalse(os.path.exists(self._journal_path()))
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

    def test_restart_proposed_manifest_ready_conflicting_tail(self):
        claim_text = f"Restart conflict claim text {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        notes = f"restart conflict notes {self._NOTES_CANARY}"
        reason = f"restart conflict resume reason {self._REASON_CANARY}"
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        starting = self._write_manifest([original_claim])
        manifest_path = os.path.join(
            self.task_dir, "provenance_manifest.json"
        )
        with open(manifest_path, "rb") as handle:
            starting_manifest_bytes = handle.read()

        # Real direct verify-claim CLI; the one-time OSError fires at
        # planned event creation, leaving the journal at
        # PROPOSED_MANIFEST_READY with the immutable snapshot and the
        # exact durable proposed temp but no event (Section 6.9).
        exit_code, out, err = self._verify_cli_interrupted(
            "_create_and_verify_planned_event", notes=notes
        )

        # The direct command fails with the exact static filesystem
        # error; nothing native is disclosed.
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(err, "error: filesystem failure\n")
        self.assertEqual(out, "")
        for output in (out, err):
            self.assertNotIn(self._OS_CANARY, output)
            self.assertNotIn("Errno 123", output)

        # Legitimate interrupted state: journal at exactly
        # PROPOSED_MANIFEST_READY; matching lock retained; immutable
        # starting snapshot present and hashing to
        # starting_manifest_hash; the exact journal-recorded durable
        # proposed temp present and hashing to proposed_manifest_hash;
        # active manifest still the starting bytes; no event yet.
        journal = ri.read_transaction_journal(self.task_dir)
        self.assertIsNotNone(journal)
        self.assertEqual(
            journal["transaction_stage"], "PROPOSED_MANIFEST_READY"
        )
        transaction_id = journal["transaction_id"]
        lock_token = journal["lock_token"]
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], lock_token)
        with open(manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), starting_manifest_bytes)
        snapshot_path = os.path.join(
            self.task_dir, journal["snapshot_relative_path"]
        )
        self.assertTrue(os.path.exists(snapshot_path))
        history = ri.list_manifest_history(self.task_dir)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0], starting)
        self.assertEqual(
            prov.canonical_sha256(history[0]),
            journal["starting_manifest_hash"],
        )
        artifacts = self._transaction_artifacts()
        self.assertTrue(artifacts["journal"])
        self.assertTrue(artifacts["lock"])
        self.assertEqual(
            artifacts["proposed_temps"],
            [journal["proposed_manifest_relative_path"]],
        )
        self.assertEqual(
            pilot_review._hash_current(
                self.task_dir,
                journal["proposed_manifest_relative_path"],
            ),
            journal["proposed_manifest_hash"],
        )
        self.assertFalse(artifacts["recovery_dir"])
        self.assertFalse(
            os.path.exists(
                os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
            )
        )

        # Conflicting sole tail via the real review-event planning and
        # creation primitives (never hand-written): one structurally
        # valid CLAIM_VERIFIED event carrying the journal's before/
        # after manifest hashes but a different identity than the
        # journal-expected event.
        planned_conflict = ri.plan_review_event(
            self.task_dir,
            event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=TIMESTAMP,
            event_id=EVENT_ID_B,
            manifest_hash_before=journal["starting_manifest_hash"],
            manifest_hash_after=journal["proposed_manifest_hash"],
        )
        created_conflict = ri.create_review_event_file(
            self.task_dir,
            event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=TIMESTAMP,
            event_id=EVENT_ID_B,
            manifest_hash_before=journal["starting_manifest_hash"],
            manifest_hash_after=journal["proposed_manifest_hash"],
        )
        self.assertEqual(created_conflict, planned_conflict)

        # The sole tail is structurally valid but conflicts with the
        # journal's expected event identity and hash.
        tail = ri.find_uncommitted_tail(
            self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
        )
        self.assertEqual(len(tail), 1)
        tail_sequence, tail_name = tail[0]
        self.assertEqual(tail_sequence, 1)
        events_dir = os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        tail_path = os.path.join(events_dir, tail_name)
        tail_event = ri._read_json_file(tail_path, "conflicting event")
        self.assertEqual(tail_event["sequence"], 1)
        self.assertEqual(tail_event["event_type"], "CLAIM_VERIFIED")
        self.assertEqual(tail_event["event_id"], EVENT_ID_B)
        self.assertNotEqual(
            tail_event["event_id"], journal["expected_event_id"]
        )
        self.assertNotEqual(
            tail_event["event_hash"], journal["expected_event_hash"]
        )
        self.assertEqual(
            tail_event["manifest_hash_before"],
            journal["starting_manifest_hash"],
        )
        self.assertEqual(
            tail_event["manifest_hash_after"],
            journal["proposed_manifest_hash"],
        )
        self.assertIsNone(ri._read_checkpoint(events_dir))

        # Capture the complete tree plus the exact journal, lock,
        # temp, and conflicting event bytes before resume.
        tree_before = _tree_snapshot(self.task_dir)
        with open(self._journal_path(), "rb") as handle:
            journal_bytes = handle.read()
        with open(self._lock_path(), "rb") as handle:
            lock_bytes = handle.read()
        temp_path = os.path.join(
            self.task_dir, journal["proposed_manifest_relative_path"]
        )
        with open(temp_path, "rb") as handle:
            temp_bytes = handle.read()
        with open(tail_path, "rb") as handle:
            conflict_event_bytes = handle.read()

        # status, audit, verify-claim, and retract-claim stay
        # read-only while the journal sits at PROPOSED_MANIFEST_READY.
        self._assert_interrupted_surfaces_read_only(
            "PROPOSED_MANIFEST_READY"
        )

        # The real resume CLI fails closed: the conflicting sole tail
        # is not the journal-expected event (approved Section 2.8).
        exit_code, out, err = self._run_cli([
            "resume-transaction",
            "--task-dir", self.task_dir,
            "--transaction-id", transaction_id,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
            "--reason", reason,
        ])
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(out, "")
        self.assertIn("TRANSACTION_AMBIGUOUS", err)

        # Standard static non-disclosure: no canary, lock token,
        # absolute path, or native exception text on either stream.
        disclosures = (
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            (self._NOTES_CANARY, "claim notes canary"),
            (self._REASON_CANARY, "resume reason canary"),
            (lock_token, "lock token"),
            (self.task_dir, "task path"),
            (self._OS_CANARY, "filesystem canary"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # The conflicting event is not rewritten, deleted, committed,
        # or replaced; journal, lock, temp, and the complete tree are
        # byte-for-byte unchanged.
        self.assertTrue(os.path.exists(tail_path))
        with open(tail_path, "rb") as handle:
            self.assertEqual(handle.read(), conflict_event_bytes)
        with open(self._journal_path(), "rb") as handle:
            self.assertEqual(handle.read(), journal_bytes)
        with open(self._lock_path(), "rb") as handle:
            self.assertEqual(handle.read(), lock_bytes)
        with open(temp_path, "rb") as handle:
            self.assertEqual(handle.read(), temp_bytes)
        self.assertEqual(_tree_snapshot(self.task_dir), tree_before)

        # The journal remains at PROPOSED_MANIFEST_READY with the
        # matching lock; the tail is still exactly the conflicting
        # event; checkpoint and receipt remain absent.
        retained = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(
            retained["transaction_stage"], "PROPOSED_MANIFEST_READY"
        )
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], lock_token)
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            tail,
        )
        self.assertIsNone(ri._read_checkpoint(events_dir))
        self.assertFalse(
            os.path.exists(
                os.path.join(self.task_dir, "review-recovery")
            )
        )

    def test_restart_event_created(self):
        claim_text = f"Restart event-created claim text {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        notes = f"restart event-created notes {self._NOTES_CANARY}"
        reason = f"restart event-created resume reason {self._REASON_CANARY}"
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        starting = self._write_manifest([original_claim])
        manifest_path = os.path.join(
            self.task_dir, "provenance_manifest.json"
        )
        with open(manifest_path, "rb") as handle:
            starting_manifest_bytes = handle.read()

        # Real direct verify-claim CLI; the one-time OSError fires at
        # the checkpoint advance (Step 12), after the journal advanced
        # to EVENT_CREATED with the planned event created but not yet
        # committed (Section 6.9).
        exit_code, out, err = self._verify_cli_interrupted(
            "_advance_event_checkpoint", notes=notes
        )

        # The direct command fails with the exact static filesystem
        # error; nothing native is disclosed.
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(err, "error: filesystem failure\n")
        self.assertEqual(out, "")
        for output in (out, err):
            self.assertNotIn(self._OS_CANARY, output)
            self.assertNotIn("Errno 123", output)

        # Journal at exactly EVENT_CREATED; matching lock retained;
        # the immutable starting snapshot exists and hashes to
        # starting_manifest_hash; the exact journal-recorded durable
        # proposed temp is present and hashes to
        # proposed_manifest_hash; the active manifest is still the
        # starting bytes.
        journal = ri.read_transaction_journal(self.task_dir)
        self.assertIsNotNone(journal)
        self.assertEqual(journal["transaction_stage"], "EVENT_CREATED")
        transaction_id = journal["transaction_id"]
        lock_token = journal["lock_token"]
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], lock_token)
        with open(manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), starting_manifest_bytes)
        snapshot_path = os.path.join(
            self.task_dir, journal["snapshot_relative_path"]
        )
        self.assertTrue(os.path.exists(snapshot_path))
        history = ri.list_manifest_history(self.task_dir)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0], starting)
        self.assertEqual(
            prov.canonical_sha256(history[0]),
            journal["starting_manifest_hash"],
        )
        artifacts = self._transaction_artifacts()
        self.assertTrue(artifacts["journal"])
        self.assertTrue(artifacts["lock"])
        self.assertEqual(
            artifacts["proposed_temps"],
            [journal["proposed_manifest_relative_path"]],
        )
        self.assertEqual(
            pilot_review._hash_current(
                self.task_dir,
                journal["proposed_manifest_relative_path"],
            ),
            journal["proposed_manifest_hash"],
        )
        self.assertFalse(artifacts["recovery_dir"])

        # Exactly one uncommitted tail exists: the journal-planned
        # event, never checkpointed. Capture its bytes.
        tail = ri.find_uncommitted_tail(
            self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
        )
        self.assertEqual(len(tail), 1)
        tail_sequence, tail_name = tail[0]
        self.assertEqual(tail_sequence, 1)
        events_dir = os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        tail_path = os.path.join(events_dir, tail_name)
        tail_event = ri._read_json_file(tail_path, "planned event")
        self.assertEqual(
            tail_event["event_id"], journal["expected_event_id"]
        )
        self.assertEqual(
            tail_event["event_hash"], journal["expected_event_hash"]
        )
        with open(tail_path, "rb") as handle:
            tail_event_bytes = handle.read()

        # No checkpoint committed the event; no receipt exists.
        self.assertIsNone(ri._read_checkpoint(events_dir))

        # status, audit, verify-claim, and retract-claim stay
        # read-only while the journal sits at EVENT_CREATED.
        self._assert_interrupted_surfaces_read_only("EVENT_CREATED")

        # Explicit resume-transaction commits exactly the existing
        # event and completes the transaction.
        exit_code, out, err = self._run_cli([
            "resume-transaction",
            "--task-dir", self.task_dir,
            "--transaction-id", transaction_id,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
            "--reason", reason,
        ])

        # Exit 0 with empty stderr; essential final state only. The
        # exhaustive summary-shape and five-field claim assertions
        # live in test_resume_transaction_success.
        self.assertEqual(exit_code, pilot_review.EXIT_OK)
        self.assertEqual(err, "")

        # Standard static non-disclosure: no canary, lock token,
        # absolute path, or native exception text on either stream.
        disclosures = (
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            (self._NOTES_CANARY, "claim notes canary"),
            (self._REASON_CANARY, "resume reason canary"),
            (lock_token, "lock token"),
            (self.task_dir, "task path"),
            (self._OS_CANARY, "filesystem canary"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # The existing event is committed byte-for-byte unchanged.
        with open(tail_path, "rb") as handle:
            self.assertEqual(handle.read(), tail_event_bytes)

        # The proposed manifest is installed: the active manifest
        # hashes exactly to the journal-recorded proposed hash.
        manifest, _path, _sha = pilot_review._load_manifest(self.task_dir)
        self.assertEqual(
            prov.canonical_sha256(manifest),
            journal["proposed_manifest_hash"],
        )

        # Exactly one committed event with the journal-planned
        # identity and before/after hashes; the checkpoint advanced to
        # exactly that event.
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        event = committed[0]
        self.assertEqual(event["event_id"], journal["expected_event_id"])
        self.assertEqual(
            event["event_hash"], journal["expected_event_hash"]
        )
        self.assertEqual(
            event["manifest_hash_before"],
            journal["starting_manifest_hash"],
        )
        self.assertEqual(
            event["manifest_hash_after"],
            journal["proposed_manifest_hash"],
        )
        checkpoint = ri._read_checkpoint(events_dir)
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint["last_sequence"], event["sequence"])
        self.assertEqual(checkpoint["last_record_id"], event["event_id"])
        self.assertEqual(
            checkpoint["last_record_hash"], event["event_hash"]
        )

        # Exactly one valid immutable recovery receipt recording the
        # EVENT_CREATED interruption.
        self.assertTrue(
            os.path.exists(self._receipt_path(transaction_id))
        )
        receipt = ri.read_recovery_receipt(
            self.task_dir, transaction_id=transaction_id
        )
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["transaction_id"], transaction_id)
        self.assertEqual(
            receipt["interrupted_stage"], "EVENT_CREATED"
        )
        self.assertEqual(
            receipt["resulting_manifest_hash"],
            journal["proposed_manifest_hash"],
        )
        self.assertEqual(
            receipt["resulting_audit_chain_head"],
            journal["expected_event_hash"],
        )

        # Journal and lock are removed only after completion; no
        # uncommitted event tail remains.
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))
        self.assertFalse(os.path.exists(self._journal_path()))
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

    def test_restart_checkpoint_updated(self):
        claim_text = f"Restart checkpoint claim text {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        notes = f"restart checkpoint notes {self._NOTES_CANARY}"
        reason = f"restart checkpoint resume reason {self._REASON_CANARY}"
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        starting = self._write_manifest([original_claim])
        manifest_path = os.path.join(
            self.task_dir, "provenance_manifest.json"
        )
        with open(manifest_path, "rb") as handle:
            starting_manifest_bytes = handle.read()

        # Real direct verify-claim CLI; the one-time OSError fires at
        # the proposed-manifest install, after the journal advanced to
        # CHECKPOINT_UPDATED with the planned event committed and the
        # checkpoint pointing to it (Section 6.9).
        exit_code, out, err = self._verify_cli_interrupted(
            "_install_proposed_manifest", notes=notes
        )

        # The direct command fails with the exact static filesystem
        # error; nothing native is disclosed.
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(err, "error: filesystem failure\n")
        self.assertEqual(out, "")
        for output in (out, err):
            self.assertNotIn(self._OS_CANARY, output)
            self.assertNotIn("Errno 123", output)

        # Journal at exactly CHECKPOINT_UPDATED; matching lock
        # retained; the immutable starting snapshot exists and hashes
        # to starting_manifest_hash; the exact journal-recorded
        # durable proposed temp is present and hashes to
        # proposed_manifest_hash; the active manifest is still the
        # starting bytes; no receipt exists.
        journal = ri.read_transaction_journal(self.task_dir)
        self.assertIsNotNone(journal)
        self.assertEqual(
            journal["transaction_stage"], "CHECKPOINT_UPDATED"
        )
        transaction_id = journal["transaction_id"]
        lock_token = journal["lock_token"]
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], lock_token)
        with open(manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), starting_manifest_bytes)
        snapshot_path = os.path.join(
            self.task_dir, journal["snapshot_relative_path"]
        )
        self.assertTrue(os.path.exists(snapshot_path))
        history = ri.list_manifest_history(self.task_dir)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0], starting)
        self.assertEqual(
            prov.canonical_sha256(history[0]),
            journal["starting_manifest_hash"],
        )
        artifacts = self._transaction_artifacts()
        self.assertTrue(artifacts["journal"])
        self.assertTrue(artifacts["lock"])
        self.assertEqual(
            artifacts["proposed_temps"],
            [journal["proposed_manifest_relative_path"]],
        )
        self.assertEqual(
            pilot_review._hash_current(
                self.task_dir,
                journal["proposed_manifest_relative_path"],
            ),
            journal["proposed_manifest_hash"],
        )
        self.assertFalse(artifacts["recovery_dir"])

        # The journal-expected event is committed and the checkpoint
        # points to exactly that event; no uncommitted tail remains.
        events_dir = os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        event = committed[0]
        self.assertEqual(event["event_id"], journal["expected_event_id"])
        self.assertEqual(
            event["event_hash"], journal["expected_event_hash"]
        )
        self.assertEqual(
            event["manifest_hash_before"],
            journal["starting_manifest_hash"],
        )
        self.assertEqual(
            event["manifest_hash_after"],
            journal["proposed_manifest_hash"],
        )
        checkpoint = ri._read_checkpoint(events_dir)
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint["last_sequence"], event["sequence"])
        self.assertEqual(checkpoint["last_record_id"], event["event_id"])
        self.assertEqual(
            checkpoint["last_record_hash"], event["event_hash"]
        )
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

        # Capture the exact committed event and checkpoint bytes.
        entries = ri._scan_sequence(events_dir)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0][0], 1)
        event_path = os.path.join(events_dir, entries[0][1])
        checkpoint_path = ri._checkpoint_path(events_dir)
        with open(event_path, "rb") as handle:
            event_bytes = handle.read()
        with open(checkpoint_path, "rb") as handle:
            checkpoint_bytes = handle.read()

        # status, audit, verify-claim, and retract-claim stay
        # read-only while the journal sits at CHECKPOINT_UPDATED.
        self._assert_interrupted_surfaces_read_only("CHECKPOINT_UPDATED")

        # Explicit resume-transaction installs the proposed manifest
        # and completes the transaction.
        exit_code, out, err = self._run_cli([
            "resume-transaction",
            "--task-dir", self.task_dir,
            "--transaction-id", transaction_id,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
            "--reason", reason,
        ])

        # Exit 0 with empty stderr; essential final state only. The
        # exhaustive summary-shape and five-field claim assertions
        # live in test_resume_transaction_success.
        self.assertEqual(exit_code, pilot_review.EXIT_OK)
        self.assertEqual(err, "")

        # Standard static non-disclosure: no canary, lock token,
        # absolute path, or native exception text on either stream.
        disclosures = (
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            (self._NOTES_CANARY, "claim notes canary"),
            (self._REASON_CANARY, "resume reason canary"),
            (lock_token, "lock token"),
            (self.task_dir, "task path"),
            (self._OS_CANARY, "filesystem canary"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # The committed event and checkpoint files are unchanged
        # byte-for-byte; the chain still validates to exactly the
        # journal-expected event.
        with open(event_path, "rb") as handle:
            self.assertEqual(handle.read(), event_bytes)
        with open(checkpoint_path, "rb") as handle:
            self.assertEqual(handle.read(), checkpoint_bytes)
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        self.assertEqual(
            committed[0]["event_hash"], journal["expected_event_hash"]
        )

        # The proposed manifest is installed: the active manifest
        # hashes exactly to the journal-recorded proposed hash.
        manifest, _path, _sha = pilot_review._load_manifest(self.task_dir)
        self.assertEqual(
            prov.canonical_sha256(manifest),
            journal["proposed_manifest_hash"],
        )

        # Exactly one valid immutable recovery receipt recording the
        # CHECKPOINT_UPDATED interruption.
        self.assertTrue(
            os.path.exists(self._receipt_path(transaction_id))
        )
        receipt = ri.read_recovery_receipt(
            self.task_dir, transaction_id=transaction_id
        )
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["transaction_id"], transaction_id)
        self.assertEqual(
            receipt["interrupted_stage"], "CHECKPOINT_UPDATED"
        )
        self.assertEqual(
            receipt["resulting_manifest_hash"],
            journal["proposed_manifest_hash"],
        )
        self.assertEqual(
            receipt["resulting_audit_chain_head"],
            journal["expected_event_hash"],
        )

        # Journal and lock are removed only after completion; no
        # uncommitted event tail remains.
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))
        self.assertFalse(os.path.exists(self._journal_path()))
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

    def test_restart_manifest_installed(self):
        claim_text = f"Restart installed claim text {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        notes = f"restart installed notes {self._NOTES_CANARY}"
        reason = f"restart installed resume reason {self._REASON_CANARY}"
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        starting = self._write_manifest([original_claim])
        manifest_path = os.path.join(
            self.task_dir, "provenance_manifest.json"
        )

        # Real direct verify-claim CLI; the one-time OSError fires at
        # the committed-state verification, after the journal advanced
        # to MANIFEST_INSTALLED with the proposed manifest installed
        # and the durable proposed temp consumed (Section 6.9).
        exit_code, out, err = self._verify_cli_interrupted(
            "_verify_committed_state", notes=notes
        )

        # The direct command fails with the exact static filesystem
        # error; nothing native is disclosed.
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(err, "error: filesystem failure\n")
        self.assertEqual(out, "")
        for output in (out, err):
            self.assertNotIn(self._OS_CANARY, output)
            self.assertNotIn("Errno 123", output)

        # Journal at exactly MANIFEST_INSTALLED; matching lock
        # retained; the active manifest is installed and hashes to
        # proposed_manifest_hash; the durable proposed temp is
        # consumed; the immutable starting snapshot remains valid;
        # the expected event is committed with the checkpoint pointing
        # to it; no uncommitted tail; no receipt.
        journal = ri.read_transaction_journal(self.task_dir)
        self.assertIsNotNone(journal)
        self.assertEqual(journal["transaction_stage"], "MANIFEST_INSTALLED")
        transaction_id = journal["transaction_id"]
        lock_token = journal["lock_token"]
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], lock_token)
        manifest, _path, _sha = pilot_review._load_manifest(self.task_dir)
        self.assertEqual(
            prov.canonical_sha256(manifest),
            journal["proposed_manifest_hash"],
        )
        snapshot_path = os.path.join(
            self.task_dir, journal["snapshot_relative_path"]
        )
        self.assertTrue(os.path.exists(snapshot_path))
        history = ri.list_manifest_history(self.task_dir)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0], starting)
        self.assertEqual(
            prov.canonical_sha256(history[0]),
            journal["starting_manifest_hash"],
        )
        artifacts = self._transaction_artifacts()
        self.assertTrue(artifacts["journal"])
        self.assertTrue(artifacts["lock"])
        self.assertEqual(artifacts["proposed_temps"], [])
        self.assertFalse(artifacts["recovery_dir"])
        events_dir = os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        event = committed[0]
        self.assertEqual(event["event_id"], journal["expected_event_id"])
        self.assertEqual(
            event["event_hash"], journal["expected_event_hash"]
        )
        self.assertEqual(
            event["manifest_hash_before"],
            journal["starting_manifest_hash"],
        )
        self.assertEqual(
            event["manifest_hash_after"],
            journal["proposed_manifest_hash"],
        )
        checkpoint = ri._read_checkpoint(events_dir)
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint["last_sequence"], event["sequence"])
        self.assertEqual(checkpoint["last_record_id"], event["event_id"])
        self.assertEqual(
            checkpoint["last_record_hash"], event["event_hash"]
        )
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

        # Capture the active manifest, immutable snapshot, committed
        # event, and checkpoint bytes.
        with open(manifest_path, "rb") as handle:
            installed_manifest_bytes = handle.read()
        with open(snapshot_path, "rb") as handle:
            snapshot_bytes = handle.read()
        entries = ri._scan_sequence(events_dir)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0][0], 1)
        event_path = os.path.join(events_dir, entries[0][1])
        checkpoint_path = ri._checkpoint_path(events_dir)
        with open(event_path, "rb") as handle:
            event_bytes = handle.read()
        with open(checkpoint_path, "rb") as handle:
            checkpoint_bytes = handle.read()

        # status, audit, verify-claim, and retract-claim stay
        # read-only while the journal sits at MANIFEST_INSTALLED.
        self._assert_interrupted_surfaces_read_only("MANIFEST_INSTALLED")

        # Explicit resume-transaction: record every journal stage
        # advance to prove the committed-state verification advances
        # the journal to COMMITTED before finalization.
        stages_seen = []
        real_update_stage = ri.update_transaction_stage

        def _recording_advance(*args, **kwargs):
            stages_seen.append(kwargs.get("new_stage"))
            return real_update_stage(*args, **kwargs)

        with mock.patch.object(
            ri,
            "update_transaction_stage",
            side_effect=_recording_advance,
        ):
            exit_code, out, err = self._run_cli([
                "resume-transaction",
                "--task-dir", self.task_dir,
                "--transaction-id", transaction_id,
                "--reviewer-id", REVIEWER_ID,
                "--reviewer-display-name", REVIEWER_NAME,
                "--reason", reason,
            ])

        # Exit 0 with empty stderr; the only journal stage advance
        # during resume is MANIFEST_INSTALLED -> COMMITTED (the
        # terminal stage); finalization then removes journal and lock.
        self.assertEqual(exit_code, pilot_review.EXIT_OK)
        self.assertEqual(err, "")
        self.assertEqual(stages_seen, ["COMMITTED"])

        # Standard static non-disclosure: no canary, lock token,
        # absolute path, or native exception text on either stream.
        disclosures = (
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            (self._NOTES_CANARY, "claim notes canary"),
            (self._REASON_CANARY, "resume reason canary"),
            (lock_token, "lock token"),
            (self.task_dir, "task path"),
            (self._OS_CANARY, "filesystem canary"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # All captured committed artifact bytes remain unchanged; the
        # chain still validates to exactly the journal-expected event.
        with open(manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), installed_manifest_bytes)
        with open(snapshot_path, "rb") as handle:
            self.assertEqual(handle.read(), snapshot_bytes)
        with open(event_path, "rb") as handle:
            self.assertEqual(handle.read(), event_bytes)
        with open(checkpoint_path, "rb") as handle:
            self.assertEqual(handle.read(), checkpoint_bytes)
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        self.assertEqual(
            committed[0]["event_hash"], journal["expected_event_hash"]
        )

        # Exactly one valid immutable recovery receipt recording the
        # MANIFEST_INSTALLED interruption.
        self.assertTrue(
            os.path.exists(self._receipt_path(transaction_id))
        )
        receipt = ri.read_recovery_receipt(
            self.task_dir, transaction_id=transaction_id
        )
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["transaction_id"], transaction_id)
        self.assertEqual(
            receipt["interrupted_stage"], "MANIFEST_INSTALLED"
        )
        self.assertEqual(
            receipt["resulting_manifest_hash"],
            journal["proposed_manifest_hash"],
        )
        self.assertEqual(
            receipt["resulting_audit_chain_head"],
            journal["expected_event_hash"],
        )

        # Journal and lock are removed only after completion; no
        # uncommitted event tail remains.
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))
        self.assertFalse(os.path.exists(self._journal_path()))
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

    def test_restart_committed(self):
        claim_text = f"Restart committed claim text {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        notes = f"restart committed notes {self._NOTES_CANARY}"
        reason = f"restart committed resume reason {self._REASON_CANARY}"
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        starting = self._write_manifest([original_claim])
        manifest_path = os.path.join(
            self.task_dir, "provenance_manifest.json"
        )

        # Real direct verify-claim CLI; the one-time OSError fires at
        # the COMMITTED lock reconciliation (Step 15), after the
        # journal advanced to COMMITTED with the matching
        # journal-recorded lock still held (Section 6.9).
        exit_code, out, err = self._verify_cli_interrupted(
            "_reconcile_committed_lock", notes=notes
        )

        # The direct command fails with the exact static filesystem
        # error; nothing native is disclosed.
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(err, "error: filesystem failure\n")
        self.assertEqual(out, "")
        for output in (out, err):
            self.assertNotIn(self._OS_CANARY, output)
            self.assertNotIn("Errno 123", output)

        # Journal at exactly COMMITTED; the matching journal-recorded
        # lock is still held; the active manifest is installed and
        # hashes to proposed_manifest_hash; the durable proposed temp
        # is consumed; the immutable starting snapshot remains valid;
        # the expected event is committed with the checkpoint pointing
        # to it; no uncommitted tail; no receipt.
        journal = ri.read_transaction_journal(self.task_dir)
        self.assertIsNotNone(journal)
        self.assertEqual(journal["transaction_stage"], "COMMITTED")
        transaction_id = journal["transaction_id"]
        lock_token = journal["lock_token"]
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], lock_token)
        manifest, _path, _sha = pilot_review._load_manifest(self.task_dir)
        self.assertEqual(
            prov.canonical_sha256(manifest),
            journal["proposed_manifest_hash"],
        )
        snapshot_path = os.path.join(
            self.task_dir, journal["snapshot_relative_path"]
        )
        self.assertTrue(os.path.exists(snapshot_path))
        history = ri.list_manifest_history(self.task_dir)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0], starting)
        self.assertEqual(
            prov.canonical_sha256(history[0]),
            journal["starting_manifest_hash"],
        )
        artifacts = self._transaction_artifacts()
        self.assertTrue(artifacts["journal"])
        self.assertTrue(artifacts["lock"])
        self.assertEqual(artifacts["proposed_temps"], [])
        self.assertFalse(artifacts["recovery_dir"])
        events_dir = os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        event = committed[0]
        self.assertEqual(event["event_id"], journal["expected_event_id"])
        self.assertEqual(
            event["event_hash"], journal["expected_event_hash"]
        )
        self.assertEqual(
            event["manifest_hash_before"],
            journal["starting_manifest_hash"],
        )
        self.assertEqual(
            event["manifest_hash_after"],
            journal["proposed_manifest_hash"],
        )
        checkpoint = ri._read_checkpoint(events_dir)
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint["last_sequence"], event["sequence"])
        self.assertEqual(checkpoint["last_record_id"], event["event_id"])
        self.assertEqual(
            checkpoint["last_record_hash"], event["event_hash"]
        )
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

        # Capture the committed artifact bytes: active manifest,
        # immutable snapshot, committed event, and checkpoint.
        with open(manifest_path, "rb") as handle:
            installed_manifest_bytes = handle.read()
        with open(snapshot_path, "rb") as handle:
            snapshot_bytes = handle.read()
        entries = ri._scan_sequence(events_dir)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0][0], 1)
        event_path = os.path.join(events_dir, entries[0][1])
        checkpoint_path = ri._checkpoint_path(events_dir)
        with open(event_path, "rb") as handle:
            event_bytes = handle.read()
        with open(checkpoint_path, "rb") as handle:
            checkpoint_bytes = handle.read()

        # status, audit, verify-claim, and retract-claim stay
        # read-only while the journal sits at COMMITTED.
        self._assert_interrupted_surfaces_read_only("COMMITTED")

        # Explicit resume-transaction: record the finalization calls
        # to prove the matching lock is released through the real
        # primitive, the receipt is created next, and the journal is
        # deleted last (approved Section 2.8).
        finalize_calls = []
        real_release_lock = ri.release_review_lock
        real_create_receipt = ri.create_recovery_receipt
        real_delete_journal = ri.delete_transaction_journal

        def _recording_release_lock(*args, **kwargs):
            finalize_calls.append("release_lock")
            return real_release_lock(*args, **kwargs)

        def _recording_create_receipt(*args, **kwargs):
            finalize_calls.append("create_receipt")
            return real_create_receipt(*args, **kwargs)

        def _recording_delete_journal(*args, **kwargs):
            finalize_calls.append("delete_journal")
            return real_delete_journal(*args, **kwargs)

        with (
            mock.patch.object(
                ri,
                "release_review_lock",
                side_effect=_recording_release_lock,
            ),
            mock.patch.object(
                ri,
                "create_recovery_receipt",
                side_effect=_recording_create_receipt,
            ),
            mock.patch.object(
                ri,
                "delete_transaction_journal",
                side_effect=_recording_delete_journal,
            ),
        ):
            exit_code, out, err = self._run_cli([
                "resume-transaction",
                "--task-dir", self.task_dir,
                "--transaction-id", transaction_id,
                "--reviewer-id", REVIEWER_ID,
                "--reviewer-display-name", REVIEWER_NAME,
                "--reason", reason,
            ])

        # Exit 0 with empty stderr; the matching lock is released, the
        # receipt is created, and the journal is deleted — in exactly
        # that order, the journal last.
        self.assertEqual(exit_code, pilot_review.EXIT_OK)
        self.assertEqual(err, "")
        self.assertEqual(
            finalize_calls,
            ["release_lock", "create_receipt", "delete_journal"],
        )

        # Standard static non-disclosure: no canary, lock token,
        # absolute path, or native exception text on either stream.
        disclosures = (
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            (self._NOTES_CANARY, "claim notes canary"),
            (self._REASON_CANARY, "resume reason canary"),
            (lock_token, "lock token"),
            (self.task_dir, "task path"),
            (self._OS_CANARY, "filesystem canary"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # All committed artifact bytes remain unchanged; the chain
        # still validates to exactly the journal-expected event.
        with open(manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), installed_manifest_bytes)
        with open(snapshot_path, "rb") as handle:
            self.assertEqual(handle.read(), snapshot_bytes)
        with open(event_path, "rb") as handle:
            self.assertEqual(handle.read(), event_bytes)
        with open(checkpoint_path, "rb") as handle:
            self.assertEqual(handle.read(), checkpoint_bytes)
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        self.assertEqual(
            committed[0]["event_hash"], journal["expected_event_hash"]
        )

        # The matching lock is released and verified absent.
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))

        # Exactly one valid immutable recovery receipt recording the
        # COMMITTED interruption.
        self.assertTrue(
            os.path.exists(self._receipt_path(transaction_id))
        )
        receipt = ri.read_recovery_receipt(
            self.task_dir, transaction_id=transaction_id
        )
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["transaction_id"], transaction_id)
        self.assertEqual(receipt["interrupted_stage"], "COMMITTED")
        self.assertEqual(
            receipt["resulting_manifest_hash"],
            journal["proposed_manifest_hash"],
        )
        self.assertEqual(
            receipt["resulting_audit_chain_head"],
            journal["expected_event_hash"],
        )

        # The journal is removed (last, proven above); no uncommitted
        # event tail remains.
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))
        self.assertFalse(os.path.exists(self._journal_path()))
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

    def test_restart_committed_lock_absent(self):
        claim_text = f"Restart committed lock-absent text {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        notes = f"restart committed lock-absent notes {self._NOTES_CANARY}"
        reason = f"restart committed lock-absent reason {self._REASON_CANARY}"
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        starting = self._write_manifest([original_claim])
        manifest_path = os.path.join(
            self.task_dir, "provenance_manifest.json"
        )

        # Real direct verify-claim CLI; the one-time OSError fires at
        # the final journal deletion (Step 16), after the journal
        # advanced to COMMITTED and the matching lock was already
        # released by the Step-15 reconciliation (pilot_review.py
        # 1113-1117). Direct completion creates no recovery receipt.
        argv = [
            "verify-claim",
            "--task-dir", self.task_dir,
            "--claim-id", CLAIM_ID_A,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
            "--notes", notes,
        ]
        with mock.patch.object(
            ri,
            "delete_transaction_journal",
            side_effect=self._canary_oserror(),
        ):
            exit_code, out, err = self._run_cli(argv)

        # The direct command fails with the exact static filesystem
        # error; nothing native is disclosed.
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(err, "error: filesystem failure\n")
        self.assertEqual(out, "")
        for output in (out, err):
            self.assertNotIn(self._OS_CANARY, output)
            self.assertNotIn("Errno 123", output)

        # Journal at exactly COMMITTED; the lock is already absent
        # (released by the successful Step-15 reconciliation); no
        # receipt; the active manifest is installed and hashes to
        # proposed_manifest_hash; the durable proposed temp is
        # consumed; the immutable starting snapshot remains valid;
        # the expected event is committed with the checkpoint pointing
        # to it; no uncommitted tail.
        journal = ri.read_transaction_journal(self.task_dir)
        self.assertIsNotNone(journal)
        self.assertEqual(journal["transaction_stage"], "COMMITTED")
        transaction_id = journal["transaction_id"]
        lock_token = journal["lock_token"]
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        manifest, _path, _sha = pilot_review._load_manifest(self.task_dir)
        self.assertEqual(
            prov.canonical_sha256(manifest),
            journal["proposed_manifest_hash"],
        )
        snapshot_path = os.path.join(
            self.task_dir, journal["snapshot_relative_path"]
        )
        self.assertTrue(os.path.exists(snapshot_path))
        history = ri.list_manifest_history(self.task_dir)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0], starting)
        self.assertEqual(
            prov.canonical_sha256(history[0]),
            journal["starting_manifest_hash"],
        )
        artifacts = self._transaction_artifacts()
        self.assertTrue(artifacts["journal"])
        self.assertFalse(artifacts["lock"])
        self.assertEqual(artifacts["proposed_temps"], [])
        self.assertFalse(artifacts["recovery_dir"])
        events_dir = os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        event = committed[0]
        self.assertEqual(event["event_id"], journal["expected_event_id"])
        self.assertEqual(
            event["event_hash"], journal["expected_event_hash"]
        )
        checkpoint = ri._read_checkpoint(events_dir)
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint["last_sequence"], event["sequence"])
        self.assertEqual(checkpoint["last_record_id"], event["event_id"])
        self.assertEqual(
            checkpoint["last_record_hash"], event["event_hash"]
        )
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

        # Capture the committed artifact bytes (active manifest,
        # immutable snapshot, committed event, checkpoint) and the
        # interrupted journal bytes.
        with open(manifest_path, "rb") as handle:
            installed_manifest_bytes = handle.read()
        with open(snapshot_path, "rb") as handle:
            snapshot_bytes = handle.read()
        entries = ri._scan_sequence(events_dir)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0][0], 1)
        event_path = os.path.join(events_dir, entries[0][1])
        checkpoint_path = ri._checkpoint_path(events_dir)
        with open(event_path, "rb") as handle:
            event_bytes = handle.read()
        with open(checkpoint_path, "rb") as handle:
            checkpoint_bytes = handle.read()
        with open(self._journal_path(), "rb") as handle:
            journal_bytes = handle.read()

        # status, audit, verify-claim, and retract-claim stay
        # read-only while the journal sits at COMMITTED.
        self._assert_interrupted_surfaces_read_only("COMMITTED")

        # The read-only probes did not mutate the interrupted journal.
        with open(self._journal_path(), "rb") as handle:
            self.assertEqual(handle.read(), journal_bytes)

        # Explicit resume-transaction: the already-absent lock must be
        # treated as previously reconciled, so a failing sentinel on
        # the release primitive proves no release is attempted; the
        # receipt/journal-deletion recorder proves the journal is
        # removed last (approved Section 2.8).
        finalize_calls = []
        real_create_receipt = ri.create_recovery_receipt
        real_delete_journal = ri.delete_transaction_journal

        def _recording_create_receipt(*args, **kwargs):
            finalize_calls.append("create_receipt")
            return real_create_receipt(*args, **kwargs)

        def _recording_delete_journal(*args, **kwargs):
            finalize_calls.append("delete_journal")
            return real_delete_journal(*args, **kwargs)

        with (
            mock.patch.object(
                ri,
                "release_review_lock",
                side_effect=AssertionError(
                    "release_review_lock must not be called"
                ),
            ) as release_sentinel,
            mock.patch.object(
                ri,
                "create_recovery_receipt",
                side_effect=_recording_create_receipt,
            ),
            mock.patch.object(
                ri,
                "delete_transaction_journal",
                side_effect=_recording_delete_journal,
            ),
        ):
            exit_code, out, err = self._run_cli([
                "resume-transaction",
                "--task-dir", self.task_dir,
                "--transaction-id", transaction_id,
                "--reviewer-id", REVIEWER_ID,
                "--reviewer-display-name", REVIEWER_NAME,
                "--reason", reason,
            ])

        # Exit 0 with empty stderr; no release was attempted; the
        # receipt is created and the journal is deleted last.
        self.assertEqual(exit_code, pilot_review.EXIT_OK)
        self.assertEqual(err, "")
        release_sentinel.assert_not_called()
        self.assertEqual(
            finalize_calls, ["create_receipt", "delete_journal"]
        )

        # Standard static non-disclosure: no canary, lock token,
        # absolute path, or native exception text on either stream.
        disclosures = (
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            (self._NOTES_CANARY, "claim notes canary"),
            (self._REASON_CANARY, "resume reason canary"),
            (lock_token, "lock token"),
            (self.task_dir, "task path"),
            (self._OS_CANARY, "filesystem canary"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # All committed artifact bytes remain unchanged; the chain
        # still validates to exactly the journal-expected event.
        with open(manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), installed_manifest_bytes)
        with open(snapshot_path, "rb") as handle:
            self.assertEqual(handle.read(), snapshot_bytes)
        with open(event_path, "rb") as handle:
            self.assertEqual(handle.read(), event_bytes)
        with open(checkpoint_path, "rb") as handle:
            self.assertEqual(handle.read(), checkpoint_bytes)
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        self.assertEqual(
            committed[0]["event_hash"], journal["expected_event_hash"]
        )

        # The lock remains absent after resume.
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))

        # Exactly one valid immutable recovery receipt recording the
        # COMMITTED interruption.
        self.assertTrue(
            os.path.exists(self._receipt_path(transaction_id))
        )
        receipt = ri.read_recovery_receipt(
            self.task_dir, transaction_id=transaction_id
        )
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["transaction_id"], transaction_id)
        self.assertEqual(receipt["interrupted_stage"], "COMMITTED")
        self.assertEqual(
            receipt["resulting_manifest_hash"],
            journal["proposed_manifest_hash"],
        )
        self.assertEqual(
            receipt["resulting_audit_chain_head"],
            journal["expected_event_hash"],
        )

        # The journal is removed (last, proven above); no uncommitted
        # event tail remains.
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))
        self.assertFalse(os.path.exists(self._journal_path()))
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

    def test_restart_committed_foreign_lock_fails_closed(self):
        claim_text = f"Restart committed foreign lock {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        notes = f"restart committed foreign lock notes {self._NOTES_CANARY}"
        reason = (
            f"restart committed foreign lock reason {self._REASON_CANARY}"
        )
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        self._write_manifest([original_claim])
        manifest_path = os.path.join(
            self.task_dir, "provenance_manifest.json"
        )

        # Same real interruption seam as test_restart_committed: the
        # one-time OSError fires at _reconcile_committed_lock, leaving
        # the journal at COMMITTED with the matching journal-recorded
        # lock still held (Section 6.9).
        exit_code, out, err = self._verify_cli_interrupted(
            "_reconcile_committed_lock", notes=notes
        )
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(err, "error: filesystem failure\n")
        self.assertEqual(out, "")

        journal = ri.read_transaction_journal(self.task_dir)
        self.assertIsNotNone(journal)
        self.assertEqual(journal["transaction_stage"], "COMMITTED")
        transaction_id = journal["transaction_id"]
        lock_token = journal["lock_token"]
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], lock_token)

        # Replace the matching lock with a valid foreign lock through
        # the real lock primitives (different token, different holder).
        ri.release_review_lock(self.task_dir, lock_token=lock_token)
        foreign = ri.acquire_review_lock(
            self.task_dir,
            reviewer_id=SECOND_REVIEWER_ID,
            reviewer_display_name=SECOND_REVIEWER_NAME,
            created_at_utc=TIMESTAMP,
        )
        self.assertNotEqual(foreign["lock_token"], lock_token)

        # Capture the complete tree and the exact journal, foreign
        # lock, manifest, snapshot, event, and checkpoint bytes.
        snapshot_path = os.path.join(
            self.task_dir, journal["snapshot_relative_path"]
        )
        events_dir = os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        entries = ri._scan_sequence(events_dir)
        self.assertEqual(len(entries), 1)
        event_path = os.path.join(events_dir, entries[0][1])
        checkpoint_path = ri._checkpoint_path(events_dir)
        tree_before = _tree_snapshot(self.task_dir)
        with open(self._journal_path(), "rb") as handle:
            journal_bytes = handle.read()
        with open(self._lock_path(), "rb") as handle:
            foreign_lock_bytes = handle.read()
        with open(manifest_path, "rb") as handle:
            manifest_bytes = handle.read()
        with open(snapshot_path, "rb") as handle:
            snapshot_bytes = handle.read()
        with open(event_path, "rb") as handle:
            event_bytes = handle.read()
        with open(checkpoint_path, "rb") as handle:
            checkpoint_bytes = handle.read()

        # Real resume-transaction CLI against the foreign lock.
        exit_code, out, err = self._run_cli([
            "resume-transaction",
            "--task-dir", self.task_dir,
            "--transaction-id", transaction_id,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
            "--reason", reason,
        ])

        # Exit 1, empty stdout, exactly the approved static fail-closed
        # resume taxonomy: the COMMITTED lock reconciliation surfaces
        # the non-matching lock as ambiguous state (Section 2.8).
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(out, "")
        self.assertEqual(
            err,
            "error: TRANSACTION_AMBIGUOUS: committed lock "
            "reconciliation failed during resume\n",
        )

        # No holder, token, path, payload, or native-error disclosure
        # on either stream.
        disclosures = (
            (lock_token, "journal-recorded lock token"),
            (foreign["lock_token"], "foreign lock token"),
            (SECOND_REVIEWER_ID, "foreign holder reviewer id"),
            (SECOND_REVIEWER_NAME, "foreign holder display name"),
            (self.task_dir, "task path"),
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            (self._NOTES_CANARY, "claim notes canary"),
            (self._REASON_CANARY, "resume reason canary"),
            (self._OS_CANARY, "filesystem canary"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # The foreign lock is neither released nor replaced.
        with open(self._lock_path(), "rb") as handle:
            self.assertEqual(handle.read(), foreign_lock_bytes)
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], foreign["lock_token"])

        # The COMMITTED journal and every committed artifact remain
        # byte-for-byte unchanged.
        with open(self._journal_path(), "rb") as handle:
            self.assertEqual(handle.read(), journal_bytes)
        with open(manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), manifest_bytes)
        with open(snapshot_path, "rb") as handle:
            self.assertEqual(handle.read(), snapshot_bytes)
        with open(event_path, "rb") as handle:
            self.assertEqual(handle.read(), event_bytes)
        with open(checkpoint_path, "rb") as handle:
            self.assertEqual(handle.read(), checkpoint_bytes)

        # No recovery receipt is created; no uncommitted tail appears;
        # the complete tree is byte-for-byte unchanged.
        self.assertFalse(
            os.path.exists(self._receipt_path(transaction_id))
        )
        self.assertFalse(self._transaction_artifacts()["recovery_dir"])
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )
        self.assertEqual(_tree_snapshot(self.task_dir), tree_before)

    def test_restart_committed_malformed_lock_fails_closed(self):
        claim_text = f"Restart committed malformed lock {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        notes = (
            f"restart committed malformed lock notes {self._NOTES_CANARY}"
        )
        reason = (
            f"restart committed malformed lock reason {self._REASON_CANARY}"
        )
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        self._write_manifest([original_claim])
        manifest_path = os.path.join(
            self.task_dir, "provenance_manifest.json"
        )

        # Same real interruption seam as test_restart_committed: the
        # one-time OSError fires at _reconcile_committed_lock, leaving
        # the journal at COMMITTED with the matching journal-recorded
        # lock still held (Section 6.9).
        exit_code, out, err = self._verify_cli_interrupted(
            "_reconcile_committed_lock", notes=notes
        )
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(err, "error: filesystem failure\n")
        self.assertEqual(out, "")

        journal = ri.read_transaction_journal(self.task_dir)
        self.assertIsNotNone(journal)
        self.assertEqual(journal["transaction_stage"], "COMMITTED")
        transaction_id = journal["transaction_id"]
        lock_token = journal["lock_token"]
        held = ri.read_review_lock(self.task_dir)
        self.assertEqual(held["lock_token"], lock_token)

        # Replace only the lock file with malformed canary-bearing
        # bytes (unparseable JSON; read_review_lock fails closed).
        malformed_canary = "malformedLockCanaryQv58zt"
        malformed_bytes = (
            '{"lock_token": "' + malformed_canary + '", truncated'
        ).encode("utf-8")
        with open(self._lock_path(), "wb") as handle:
            handle.write(malformed_bytes)

        # Capture the complete tree and the exact malformed-lock,
        # journal, manifest, snapshot, event, and checkpoint bytes.
        snapshot_path = os.path.join(
            self.task_dir, journal["snapshot_relative_path"]
        )
        events_dir = os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        entries = ri._scan_sequence(events_dir)
        self.assertEqual(len(entries), 1)
        event_path = os.path.join(events_dir, entries[0][1])
        checkpoint_path = ri._checkpoint_path(events_dir)
        tree_before = _tree_snapshot(self.task_dir)
        with open(self._lock_path(), "rb") as handle:
            malformed_lock_bytes = handle.read()
        self.assertEqual(malformed_lock_bytes, malformed_bytes)
        with open(self._journal_path(), "rb") as handle:
            journal_bytes = handle.read()
        with open(manifest_path, "rb") as handle:
            manifest_bytes = handle.read()
        with open(snapshot_path, "rb") as handle:
            snapshot_bytes = handle.read()
        with open(event_path, "rb") as handle:
            event_bytes = handle.read()
        with open(checkpoint_path, "rb") as handle:
            checkpoint_bytes = handle.read()

        # Real resume-transaction CLI against the malformed lock.
        exit_code, out, err = self._run_cli([
            "resume-transaction",
            "--task-dir", self.task_dir,
            "--transaction-id", transaction_id,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
            "--reason", reason,
        ])

        # Exit 1, empty stdout, exactly the static COMMITTED
        # reconciliation TRANSACTION_AMBIGUOUS line (Section 2.8).
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(out, "")
        self.assertEqual(
            err,
            "error: TRANSACTION_AMBIGUOUS: committed lock "
            "reconciliation failed during resume\n",
        )

        # No malformed bytes, canary, filename, absolute path, holder/
        # token, or native exception disclosure on either stream.
        disclosures = (
            (malformed_canary, "malformed lock canary"),
            ("review.lock", "lock filename"),
            (lock_token, "journal-recorded lock token"),
            (self.task_dir, "task path"),
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            (self._NOTES_CANARY, "claim notes canary"),
            (self._REASON_CANARY, "resume reason canary"),
            (self._OS_CANARY, "filesystem canary"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # The malformed lock is neither deleted, replaced, nor
        # repaired: the file remains with its exact bytes.
        self.assertTrue(os.path.exists(self._lock_path()))
        with open(self._lock_path(), "rb") as handle:
            self.assertEqual(handle.read(), malformed_bytes)

        # The COMMITTED journal and every committed artifact remain
        # byte-for-byte unchanged.
        with open(self._journal_path(), "rb") as handle:
            self.assertEqual(handle.read(), journal_bytes)
        with open(manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), manifest_bytes)
        with open(snapshot_path, "rb") as handle:
            self.assertEqual(handle.read(), snapshot_bytes)
        with open(event_path, "rb") as handle:
            self.assertEqual(handle.read(), event_bytes)
        with open(checkpoint_path, "rb") as handle:
            self.assertEqual(handle.read(), checkpoint_bytes)

        # No recovery receipt is created; no uncommitted tail appears;
        # the complete tree is byte-for-byte unchanged.
        self.assertFalse(
            os.path.exists(self._receipt_path(transaction_id))
        )
        self.assertFalse(self._transaction_artifacts()["recovery_dir"])
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )
        self.assertEqual(_tree_snapshot(self.task_dir), tree_before)

    def test_recovery_receipt_existing_verified_not_rewritten(self):
        claim_text = f"Receipt existing claim text {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        notes = f"receipt existing notes {self._NOTES_CANARY}"
        reason = f"receipt existing resume reason {self._REASON_CANARY}"
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        self._write_manifest([original_claim])
        manifest_path = os.path.join(
            self.task_dir, "provenance_manifest.json"
        )

        # Legitimate COMMITTED transaction with the matching lock held
        # (same seam as test_restart_committed, Section 6.9).
        exit_code, out, err = self._verify_cli_interrupted(
            "_reconcile_committed_lock", notes=notes
        )
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(err, "error: filesystem failure\n")
        self.assertEqual(out, "")

        journal = ri.read_transaction_journal(self.task_dir)
        self.assertIsNotNone(journal)
        self.assertEqual(journal["transaction_stage"], "COMMITTED")
        transaction_id = journal["transaction_id"]
        lock_token = journal["lock_token"]

        # Capture the committed artifact bytes before any resume.
        snapshot_path = os.path.join(
            self.task_dir, journal["snapshot_relative_path"]
        )
        events_dir = os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        entries = ri._scan_sequence(events_dir)
        self.assertEqual(len(entries), 1)
        event_path = os.path.join(events_dir, entries[0][1])
        checkpoint_path = ri._checkpoint_path(events_dir)
        with open(manifest_path, "rb") as handle:
            manifest_bytes = handle.read()
        with open(snapshot_path, "rb") as handle:
            snapshot_bytes = handle.read()
        with open(event_path, "rb") as handle:
            event_bytes = handle.read()
        with open(checkpoint_path, "rb") as handle:
            checkpoint_bytes = handle.read()

        # First real resume CLI; the one-time OSError fires at the
        # final journal deletion, after the matching lock is released
        # and the recovery receipt is created (Section 6.12).
        argv = [
            "resume-transaction",
            "--task-dir", self.task_dir,
            "--transaction-id", transaction_id,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
            "--reason", reason,
        ]
        with mock.patch.object(
            ri,
            "delete_transaction_journal",
            side_effect=self._canary_oserror(),
        ):
            exit_code, out, err = self._run_cli(argv)

        # Exit 1 with the exact static translated failure; nothing
        # native is disclosed.
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(out, "")
        self.assertEqual(
            err,
            "error: TRANSACTION_AMBIGUOUS: journal deletion failed "
            "during resume\n",
        )
        for output in (out, err):
            self.assertNotIn(self._OS_CANARY, output)
            self.assertNotIn(self.task_dir, output)
            self.assertNotIn("Errno 123", output)

        # The valid COMMITTED journal is retained unchanged; the lock
        # is absent; exactly one valid recovery receipt is present;
        # every committed artifact is unchanged.
        self.assertEqual(
            ri.read_transaction_journal(self.task_dir), journal
        )
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        receipt_path = self._receipt_path(transaction_id)
        self.assertTrue(os.path.exists(receipt_path))
        receipt = ri.read_recovery_receipt(
            self.task_dir, transaction_id=transaction_id
        )
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["transaction_id"], transaction_id)
        self.assertEqual(receipt["interrupted_stage"], "COMMITTED")
        self.assertEqual(receipt["resuming_reviewer_id"], REVIEWER_ID)
        self.assertEqual(
            receipt["resuming_reviewer_display_name"], REVIEWER_NAME
        )
        self.assertEqual(receipt["reason"], reason)
        self.assertEqual(
            receipt["resulting_manifest_hash"],
            journal["proposed_manifest_hash"],
        )
        self.assertEqual(
            receipt["resulting_audit_chain_head"],
            journal["expected_event_hash"],
        )
        with open(manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), manifest_bytes)
        with open(snapshot_path, "rb") as handle:
            self.assertEqual(handle.read(), snapshot_bytes)
        with open(event_path, "rb") as handle:
            self.assertEqual(handle.read(), event_bytes)
        with open(checkpoint_path, "rb") as handle:
            self.assertEqual(handle.read(), checkpoint_bytes)

        # Capture the exact receipt bytes.
        with open(receipt_path, "rb") as handle:
            receipt_bytes = handle.read()

        # Second real resume CLI with receipt creation sentinel-patched:
        # the existing receipt must be verified, never recreated.
        delete_calls = []
        real_delete_journal = ri.delete_transaction_journal

        def _recording_delete_journal(*args, **kwargs):
            delete_calls.append("delete_journal")
            return real_delete_journal(*args, **kwargs)

        with (
            mock.patch.object(
                ri,
                "create_recovery_receipt",
                side_effect=AssertionError(
                    "create_recovery_receipt must not be called"
                ),
            ) as create_sentinel,
            mock.patch.object(
                ri,
                "delete_transaction_journal",
                side_effect=_recording_delete_journal,
            ),
        ):
            exit_code, out, err = self._run_cli(argv)

        # Resume succeeds; the creation sentinel is never called; the
        # journal is deleted through the real primitive.
        self.assertEqual(exit_code, pilot_review.EXIT_OK)
        self.assertEqual(err, "")
        create_sentinel.assert_not_called()
        self.assertEqual(delete_calls, ["delete_journal"])

        # Sanitized output: no receipt reason, payload canaries, lock
        # token, absolute path, or native exception text.
        disclosures = (
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            (self._NOTES_CANARY, "claim notes canary"),
            (self._REASON_CANARY, "receipt reason canary"),
            (lock_token, "lock token"),
            (self.task_dir, "task path"),
            (self._OS_CANARY, "filesystem canary"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # The exact existing receipt remains byte-for-byte unchanged;
        # every committed artifact remains unchanged.
        with open(receipt_path, "rb") as handle:
            self.assertEqual(handle.read(), receipt_bytes)
        with open(manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), manifest_bytes)
        with open(snapshot_path, "rb") as handle:
            self.assertEqual(handle.read(), snapshot_bytes)
        with open(event_path, "rb") as handle:
            self.assertEqual(handle.read(), event_bytes)
        with open(checkpoint_path, "rb") as handle:
            self.assertEqual(handle.read(), checkpoint_bytes)

        # The journal is removed (the sole/last mutation above); the
        # lock remains absent; no uncommitted tail remains.
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))
        self.assertFalse(os.path.exists(self._journal_path()))
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

    def test_recovery_receipt_created_after_resume(self):
        claim_text = f"Receipt created claim text {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        notes = f"receipt created notes {self._NOTES_CANARY}"
        reason = f"receipt created resume reason {self._REASON_CANARY}"
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        self._write_manifest([original_claim])

        # Smallest legitimate interrupted transaction: the one-time
        # OSError fires at snapshot creation, leaving the journal at
        # LOCK_ACQUIRED with the matching lock retained (Section 6.9).
        exit_code, out, err = self._verify_cli_interrupted(
            "_create_and_verify_snapshot", notes=notes
        )
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(err, "error: filesystem failure\n")
        self.assertEqual(out, "")

        journal = ri.read_transaction_journal(self.task_dir)
        self.assertIsNotNone(journal)
        self.assertEqual(journal["transaction_stage"], "LOCK_ACQUIRED")
        transaction_id = journal["transaction_id"]
        lock_token = journal["lock_token"]
        self.assertEqual(
            ri.read_review_lock(self.task_dir)["lock_token"], lock_token
        )

        # No receipt exists before resume.
        receipt_path = self._receipt_path(transaction_id)
        self.assertFalse(os.path.exists(receipt_path))
        self.assertFalse(self._transaction_artifacts()["recovery_dir"])

        # Real resume CLI; record stage advances, receipt creation,
        # and journal deletion through the real primitives to prove
        # creation happens after the journal is COMMITTED and the
        # journal deletion is last (approved Section 2.8).
        calls = []
        real_update = ri.update_transaction_stage
        real_create = ri.create_recovery_receipt
        real_delete = ri.delete_transaction_journal

        def _recording_update(*args, **kwargs):
            calls.append(f"stage:{kwargs['new_stage']}")
            return real_update(*args, **kwargs)

        def _recording_create(*args, **kwargs):
            calls.append("create_receipt")
            return real_create(*args, **kwargs)

        def _recording_delete(*args, **kwargs):
            calls.append("delete_journal")
            return real_delete(*args, **kwargs)

        with (
            mock.patch.object(
                ri,
                "update_transaction_stage",
                side_effect=_recording_update,
            ),
            mock.patch.object(
                ri,
                "create_recovery_receipt",
                side_effect=_recording_create,
            ),
            mock.patch.object(
                ri,
                "delete_transaction_journal",
                side_effect=_recording_delete,
            ),
        ):
            exit_code, out, err = self._run_cli([
                "resume-transaction",
                "--task-dir", self.task_dir,
                "--transaction-id", transaction_id,
                "--reviewer-id", REVIEWER_ID,
                "--reviewer-display-name", REVIEWER_NAME,
                "--reason", reason,
            ])

        # Successful sanitized resume.
        self.assertEqual(exit_code, pilot_review.EXIT_OK)
        self.assertEqual(err, "")

        # Creation occurs exactly once, after the journal advanced to
        # COMMITTED; the journal deletion is last.
        self.assertEqual(calls.count("create_receipt"), 1)
        self.assertEqual(
            calls[-3:],
            ["stage:COMMITTED", "create_receipt", "delete_journal"],
        )

        # Standard static non-disclosure on both streams.
        disclosures = (
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            (self._NOTES_CANARY, "claim notes canary"),
            (self._REASON_CANARY, "resume reason canary"),
            (lock_token, "lock token"),
            (self.task_dir, "task path"),
            (self._OS_CANARY, "filesystem canary"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # Exactly one receipt exists at the canonical
        # transaction-derived path; the production read path validates
        # it (structure, closed schema, and receipt_hash).
        self.assertTrue(os.path.exists(receipt_path))
        self.assertEqual(
            os.listdir(os.path.dirname(receipt_path)),
            [os.path.basename(receipt_path)],
        )
        receipt = ri.read_recovery_receipt(
            self.task_dir, transaction_id=transaction_id
        )
        self.assertIsNotNone(receipt)

        # All 11 closed-schema fields are present and correct;
        # claim_notes is absent (amendment).
        self.assertEqual(
            set(receipt),
            {
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
            },
        )
        self.assertEqual(receipt["schema_version"], "1.2.0")
        self.assertEqual(receipt["receipt_type"], "TRANSACTION_RESUMED")
        self.assertEqual(receipt["transaction_id"], transaction_id)
        self.assertEqual(receipt["interrupted_stage"], "LOCK_ACQUIRED")
        self.assertEqual(receipt["resuming_reviewer_id"], REVIEWER_ID)
        self.assertEqual(
            receipt["resuming_reviewer_display_name"], REVIEWER_NAME
        )
        self.assertEqual(receipt["reason"], reason)
        self.assertTrue(receipt["resumed_at_utc"].endswith("Z"))
        self.assertEqual(
            receipt["resulting_manifest_hash"],
            journal["proposed_manifest_hash"],
        )
        self.assertEqual(
            receipt["resulting_audit_chain_head"],
            journal["expected_event_hash"],
        )
        self.assertEqual(len(receipt["receipt_hash"]), 64)
        self.assertNotIn("claim_notes", receipt)

        # The journal and lock are absent only after the successful
        # resume (both were present in the interrupted state above).
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))
        self.assertFalse(os.path.exists(self._journal_path()))
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))

        # The final manifest, event, and checkpoint remain valid and
        # match the journal-recorded plan; no uncommitted tail.
        manifest, _path, _sha = pilot_review._load_manifest(self.task_dir)
        self.assertEqual(
            prov.canonical_sha256(manifest),
            journal["proposed_manifest_hash"],
        )
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        self.assertEqual(
            committed[0]["event_id"], journal["expected_event_id"]
        )
        self.assertEqual(
            committed[0]["event_hash"], journal["expected_event_hash"]
        )
        events_dir = os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        checkpoint = ri._read_checkpoint(events_dir)
        self.assertIsNotNone(checkpoint)
        self.assertEqual(
            checkpoint["last_record_hash"],
            journal["expected_event_hash"],
        )
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

    def test_recovery_receipt_missing_requires_committed_journal(self):
        claim_text = f"Receipt missing claim text {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        notes = f"receipt missing notes {self._NOTES_CANARY}"
        reason = f"receipt missing resume reason {self._REASON_CANARY}"
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        self._write_manifest([original_claim])

        # Legitimate interruption before COMMITTED: the one-time
        # OSError fires at _verify_committed_state, leaving the
        # journal at MANIFEST_INSTALLED with the matching lock
        # retained and no receipt (Section 6.9; H4A seam).
        exit_code, out, err = self._verify_cli_interrupted(
            "_verify_committed_state", notes=notes
        )
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(err, "error: filesystem failure\n")
        self.assertEqual(out, "")

        journal = ri.read_transaction_journal(self.task_dir)
        self.assertIsNotNone(journal)
        self.assertEqual(
            journal["transaction_stage"], "MANIFEST_INSTALLED"
        )
        transaction_id = journal["transaction_id"]
        lock_token = journal["lock_token"]
        self.assertEqual(
            ri.read_review_lock(self.task_dir)["lock_token"], lock_token
        )

        # No receipt exists before resume: none is created while the
        # journal sits at MANIFEST_INSTALLED.
        receipt_path = self._receipt_path(transaction_id)
        self.assertFalse(os.path.exists(receipt_path))
        self.assertFalse(self._transaction_artifacts()["recovery_dir"])

        # Real resume CLI; record stage advances and journal deletion,
        # and read the live journal stage at the moment the receipt is
        # created (approved Section 2.8: a missing receipt may be
        # created only from a valid COMMITTED journal).
        calls = []
        create_stage_reads = []
        real_update = ri.update_transaction_stage
        real_create = ri.create_recovery_receipt
        real_delete = ri.delete_transaction_journal

        def _recording_update(*args, **kwargs):
            calls.append(f"stage:{kwargs['new_stage']}")
            return real_update(*args, **kwargs)

        def _recording_create(*args, **kwargs):
            live = ri.read_transaction_journal(self.task_dir)
            create_stage_reads.append(live["transaction_stage"])
            calls.append("create_receipt")
            return real_create(*args, **kwargs)

        def _recording_delete(*args, **kwargs):
            calls.append("delete_journal")
            return real_delete(*args, **kwargs)

        with (
            mock.patch.object(
                ri,
                "update_transaction_stage",
                side_effect=_recording_update,
            ),
            mock.patch.object(
                ri,
                "create_recovery_receipt",
                side_effect=_recording_create,
            ),
            mock.patch.object(
                ri,
                "delete_transaction_journal",
                side_effect=_recording_delete,
            ),
        ):
            exit_code, out, err = self._run_cli([
                "resume-transaction",
                "--task-dir", self.task_dir,
                "--transaction-id", transaction_id,
                "--reviewer-id", REVIEWER_ID,
                "--reviewer-display-name", REVIEWER_NAME,
                "--reason", reason,
            ])

        # Successful sanitized resume.
        self.assertEqual(exit_code, pilot_review.EXIT_OK)
        self.assertEqual(err, "")

        # The journal is advanced to COMMITTED before creation; at the
        # create call the live journal stage is exactly COMMITTED;
        # creation occurs exactly once; journal deletion follows
        # creation and is last. From MANIFEST_INSTALLED the only
        # advance is COMMITTED, so the full call list is exact.
        self.assertEqual(
            calls,
            ["stage:COMMITTED", "create_receipt", "delete_journal"],
        )
        self.assertEqual(create_stage_reads, ["COMMITTED"])

        # Standard static non-disclosure on both streams.
        disclosures = (
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            (self._NOTES_CANARY, "claim notes canary"),
            (self._REASON_CANARY, "resume reason canary"),
            (lock_token, "lock token"),
            (self.task_dir, "task path"),
            (self._OS_CANARY, "filesystem canary"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # Exactly one receipt exists; the production read path
        # validates it; it matches the transaction, resumer, reason,
        # and journal-linked result hashes.
        self.assertTrue(os.path.exists(receipt_path))
        self.assertEqual(
            os.listdir(os.path.dirname(receipt_path)),
            [os.path.basename(receipt_path)],
        )
        receipt = ri.read_recovery_receipt(
            self.task_dir, transaction_id=transaction_id
        )
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["transaction_id"], transaction_id)
        self.assertEqual(
            receipt["interrupted_stage"], "MANIFEST_INSTALLED"
        )
        self.assertEqual(receipt["resuming_reviewer_id"], REVIEWER_ID)
        self.assertEqual(
            receipt["resuming_reviewer_display_name"], REVIEWER_NAME
        )
        self.assertEqual(receipt["reason"], reason)
        self.assertEqual(
            receipt["resulting_manifest_hash"],
            journal["proposed_manifest_hash"],
        )
        self.assertEqual(
            receipt["resulting_audit_chain_head"],
            journal["expected_event_hash"],
        )

        # The journal and lock are absent only after the successful
        # resume (both were present in the interrupted state above).
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))
        self.assertFalse(os.path.exists(self._journal_path()))
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))

        # The final manifest, event, and checkpoint validate; no
        # uncommitted tail remains.
        manifest, _path, _sha = pilot_review._load_manifest(self.task_dir)
        self.assertEqual(
            prov.canonical_sha256(manifest),
            journal["proposed_manifest_hash"],
        )
        committed = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(committed), 1)
        self.assertEqual(
            committed[0]["event_hash"], journal["expected_event_hash"]
        )
        events_dir = os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        checkpoint = ri._read_checkpoint(events_dir)
        self.assertIsNotNone(checkpoint)
        self.assertEqual(
            checkpoint["last_record_hash"],
            journal["expected_event_hash"],
        )
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )

    def test_recovery_receipt_bad_evidence_fails_closed(self):
        claim_text = f"Receipt bad evidence text {self._CLAIM_CANARY}"
        source_url = f"https://example.com/evidence?{self._QS_CANARY}=1"
        notes = f"receipt bad evidence notes {self._NOTES_CANARY}"
        planted_reason = f"planted receipt reason {self._REASON_CANARY}"
        resume_reason = f"actual resume reason {self._REASON_CANARY}"
        original_claim = prov.build_claim(
            claim_text=claim_text,
            source_url=source_url,
            supporting_sources=None,
            claim_id=CLAIM_ID_A,
        )
        self._write_manifest([original_claim])
        manifest_path = os.path.join(
            self.task_dir, "provenance_manifest.json"
        )

        # Legitimate COMMITTED transaction with the lock already
        # absent and no receipt (H4C seam): the one-time OSError fires
        # at the direct flow's final journal deletion, after COMMITTED
        # verification and matching-lock reconciliation.
        verify_argv = [
            "verify-claim",
            "--task-dir", self.task_dir,
            "--claim-id", CLAIM_ID_A,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
            "--notes", notes,
        ]
        with mock.patch.object(
            ri,
            "delete_transaction_journal",
            side_effect=self._canary_oserror(),
        ):
            exit_code, out, err = self._run_cli(verify_argv)
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(err, "error: filesystem failure\n")
        self.assertEqual(out, "")

        journal = ri.read_transaction_journal(self.task_dir)
        self.assertIsNotNone(journal)
        self.assertEqual(journal["transaction_stage"], "COMMITTED")
        transaction_id = journal["transaction_id"]
        lock_token = journal["lock_token"]
        self.assertIsNone(ri.read_review_lock(self.task_dir))

        # Plant one structurally valid but mismatched receipt through
        # the real primitive: a different resume reason at the
        # canonical transaction-derived path, otherwise valid fields.
        planted = ri.create_recovery_receipt(
            self.task_dir,
            transaction_id=transaction_id,
            interrupted_stage="COMMITTED",
            resuming_reviewer_id=REVIEWER_ID,
            resuming_reviewer_display_name=REVIEWER_NAME,
            reason=planted_reason,
            resumed_at_utc=TIMESTAMP,
            resulting_manifest_hash=journal["proposed_manifest_hash"],
            resulting_audit_chain_head=journal["expected_event_hash"],
        )
        self.assertIsNotNone(
            ri.read_recovery_receipt(
                self.task_dir, transaction_id=transaction_id
            )
        )

        # Capture the complete tree and the exact receipt, journal,
        # manifest, snapshot, event, and checkpoint bytes.
        receipt_path = self._receipt_path(transaction_id)
        snapshot_path = os.path.join(
            self.task_dir, journal["snapshot_relative_path"]
        )
        events_dir = os.path.join(self.task_dir, ri.REVIEW_EVENTS_DIR)
        entries = ri._scan_sequence(events_dir)
        self.assertEqual(len(entries), 1)
        event_path = os.path.join(events_dir, entries[0][1])
        checkpoint_path = ri._checkpoint_path(events_dir)
        tree_before = _tree_snapshot(self.task_dir)
        with open(receipt_path, "rb") as handle:
            receipt_bytes = handle.read()
        with open(self._journal_path(), "rb") as handle:
            journal_bytes = handle.read()
        with open(manifest_path, "rb") as handle:
            manifest_bytes = handle.read()
        with open(snapshot_path, "rb") as handle:
            snapshot_bytes = handle.read()
        with open(event_path, "rb") as handle:
            event_bytes = handle.read()
        with open(checkpoint_path, "rb") as handle:
            checkpoint_bytes = handle.read()

        # Real resume-transaction CLI against the mismatched receipt.
        exit_code, out, err = self._run_cli([
            "resume-transaction",
            "--task-dir", self.task_dir,
            "--transaction-id", transaction_id,
            "--reviewer-id", REVIEWER_ID,
            "--reviewer-display-name", REVIEWER_NAME,
            "--reason", resume_reason,
        ])

        # Exit 1, empty stdout, exactly the static fail-closed line
        # (Section 2.8: existing receipt must match the COMMITTED
        # evidence; never rewritten).
        self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
        self.assertEqual(out, "")
        self.assertEqual(
            err,
            "error: TRANSACTION_AMBIGUOUS: existing recovery receipt "
            "does not match the COMMITTED evidence\n",
        )

        # No receipt value, reason, path, claim/query/notes data,
        # token, or native exception disclosure on either stream.
        disclosures = (
            (planted_reason, "planted receipt reason"),
            (resume_reason, "resume reason"),
            (planted["receipt_hash"], "receipt hash value"),
            (lock_token, "journal-recorded lock token"),
            (self.task_dir, "task path"),
            (self._CLAIM_CANARY, "claim text canary"),
            (self._QS_CANARY, "query string canary"),
            (self._NOTES_CANARY, "claim notes canary"),
            (self._REASON_CANARY, "reason canary"),
            (self._OS_CANARY, "filesystem canary"),
            ("Traceback", "traceback text"),
            ("Errno", "errno text"),
        )
        for value, what in disclosures:
            for output, where in ((out, "stdout"), (err, "stderr")):
                self.assertNotIn(
                    value, output, f"{what} disclosed in {where}"
                )

        # The receipt is not rewritten, deleted, or replaced.
        self.assertTrue(os.path.exists(receipt_path))
        with open(receipt_path, "rb") as handle:
            self.assertEqual(handle.read(), receipt_bytes)

        # The COMMITTED journal and every committed artifact remain
        # byte-for-byte unchanged.
        with open(self._journal_path(), "rb") as handle:
            self.assertEqual(handle.read(), journal_bytes)
        with open(manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), manifest_bytes)
        with open(snapshot_path, "rb") as handle:
            self.assertEqual(handle.read(), snapshot_bytes)
        with open(event_path, "rb") as handle:
            self.assertEqual(handle.read(), event_bytes)
        with open(checkpoint_path, "rb") as handle:
            self.assertEqual(handle.read(), checkpoint_bytes)

        # The lock remains absent; no uncommitted tail appears; the
        # complete tree is byte-for-byte unchanged.
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertFalse(os.path.exists(self._lock_path()))
        self.assertEqual(
            ri.find_uncommitted_tail(
                self.task_dir, ri.CHAIN_TYPE_REVIEW_EVENTS
            ),
            [],
        )
        self.assertEqual(_tree_snapshot(self.task_dir), tree_before)


class TestCliTaskDirLinkJunctionRejection(_ClaimCommandTestBase):
    """J3T: the shared CLI resolver rejects a linked/junctioned task dir.

    Every command resolves --task-dir through pilot_review._resolve_task_dir
    (J3), so one read-only command (status) and one mutating command
    (verify-claim) stand for all five: the exact static rejection must fire
    before any manifest, journal, lock, snapshot, event, checkpoint, or
    receipt access, disclosing neither path, no claim data, and no native
    exception text.
    """

    def _run_cli(self, argv):
        """Run the real CLI surface; return (exit_code, stdout, stderr)."""
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            exit_code = pilot_review.run(argv)
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def test_cli_task_dir_link_or_junction_rejected(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        self._write_manifest([self._unverified_claim()])
        link_parent = tempfile.mkdtemp()
        link = os.path.join(link_parent, "task-dir-link")
        try:
            os.symlink(self.task_dir, link, target_is_directory=True)
        except OSError:
            os.rmdir(link_parent)
            self.skipTest("symlink creation not permitted")

        def _remove_link_tree():
            # os.rmdir removes the directory symlink itself, never follows.
            with contextlib.suppress(OSError):
                os.rmdir(link)
            with contextlib.suppress(OSError):
                os.rmdir(link_parent)

        self.addCleanup(_remove_link_tree)
        tree_before = _tree_snapshot(self.task_dir)

        invocations = [
            ["status", "--task-dir", link],
            [
                "verify-claim",
                "--task-dir", link,
                "--claim-id", CLAIM_ID_A,
                "--reviewer-id", REVIEWER_ID,
                "--reviewer-display-name", REVIEWER_NAME,
            ],
        ]
        for argv in invocations:
            with self.subTest(command=argv[0]):
                exit_code, out, err = self._run_cli(argv)

                self.assertEqual(exit_code, pilot_review.EXIT_FAILURE)
                self.assertEqual(out, "")
                # Byte-exact stderr: nothing beyond the static line can
                # leak either path, claim data, or native error text.
                self.assertEqual(
                    err,
                    "error: task directory path traverses a link or "
                    "junction\n",
                )
                self.assertNotIn(link, err, "symlink path disclosed")
                self.assertNotIn(self.task_dir, err, "real path disclosed")
                self.assertNotIn(CLAIM_ID_A, err, "claim data disclosed")

                # No transaction journal, lock, proposed temp, snapshot,
                # event, checkpoint, or receipt exists; the real tree is
                # byte-for-byte unchanged after each rejected invocation.
                self.assertEqual(
                    self._transaction_artifacts(),
                    {
                        "journal": False,
                        "lock": False,
                        "proposed_temps": [],
                        "recovery_dir": False,
                    },
                )
                self.assertFalse(
                    os.path.exists(
                        os.path.join(self.task_dir, "review-events")
                    )
                )
                self.assertFalse(
                    os.path.exists(
                        os.path.join(self.task_dir, "manifest-history")
                    )
                )
                self.assertEqual(
                    _tree_snapshot(self.task_dir),
                    tree_before,
                    "task tree changed by a rejected CLI invocation",
                )


if __name__ == "__main__":
    unittest.main()
