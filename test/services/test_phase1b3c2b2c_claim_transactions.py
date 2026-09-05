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


if __name__ == "__main__":
    unittest.main()
