"""
Phase 1B.3C.2B.2B — Schema 1.2.0, claim IDs, migration, journal primitives.

Fully offline tests (zero network access). Covers:
- deterministic claim IDs
- duplicate claims (distinct IDs via ordinal)
- NFC and line-ending normalization
- collision failure
- immutable claim IDs
- new 1.2.0 manifests
- deterministic 1.0.0/1.1.0 draft migration
- input remains unchanged after migration
- APPROVED/REJECTED migration rejection
- journal creation and validation
- every valid stage
- invalid stage
- skipped, repeated, or reversed stage rejection
- journal-hash modification
- immutable-field modification
- unknown or missing journal fields
- traversal and unsafe paths
- journal overwrite conflict
- atomic cleanup after injected failures
- status/audit with no journal
- status/audit with valid, malformed, or modified journal
- read-only byte-for-byte guarantees
- TRANSACTION_RESUMED rejection (fail closed)
- split event-file creation and checkpoint advancement primitives
- no checkpoint mutation on rejected advancement (fail-closed pre-write)
- version-conditional JSON Schema document assertions (1.2.0 requires
  non-null claim_id; legacy manifests remain valid without it)
- exact transaction-status output, safe placeholders, and redaction
- split-boundary independent failure detection and recovery
- no network access
"""

import hashlib
import json
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.services import provenance as prov
from app.services import review_integrity as ri


UTC = "2026-08-30T12:00:00Z"
UTC2 = "2026-08-30T13:00:00Z"
REVIEWER_ID = "rick.gamboa"
REVIEWER_NAME = "Rick Gamboa"
HASH_A = "a" * 64
HASH_B = "b" * 64

JOURNAL_KWARGS = dict(
    operation="verify-claim",
    task_id="task-001",
    claim_id="claim-" + "a" * 32,
    starting_manifest_hash=HASH_A,
    proposed_manifest_hash=HASH_B,
    proposed_manifest_relative_path=".proposed_manifest.json.abc123.tmp",
    snapshot_relative_path="manifest-history/000001_" + HASH_A + ".json",
    expected_event_id="e" * 32,
    expected_event_hash="c" * 64,
    lock_token="b" * 32,
    created_at_utc=UTC,
    original_reviewer_id=REVIEWER_ID,
    original_reviewer_display_name=REVIEWER_NAME,
)


def _blocked_socket(*args, **kwargs):
    raise AssertionError("network access is forbidden in Phase 1B.3C.2B.2B tests")


class _NetworkBlocker:
    def __enter__(self):
        self._patches = [
            patch.object(socket, "socket", side_effect=_blocked_socket),
            patch.object(socket, "create_connection", side_effect=_blocked_socket),
            patch.object(socket, "getaddrinfo", side_effect=_blocked_socket),
        ]
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in self._patches:
            p.stop()
        return False


class _TaskDirBase(unittest.TestCase):
    def setUp(self):
        self._net = _NetworkBlocker()
        self._net.__enter__()
        self._tmp = tempfile.TemporaryDirectory()
        self.task_dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()
        self._net.__exit__(None, None, None)

    def write_file(self, name, data=b"x"):
        path = os.path.join(self.task_dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def task_section(self, **overrides):
        kwargs = dict(
            task_id="task-001",
            topic="bitcoin basics",
            pilot_profile="braintrustcrypto",
            created_at=UTC,
        )
        kwargs.update(overrides)
        return prov.build_task_section(**kwargs)

    def simple_manifest(self, claims=None):
        self.write_file("final.mp4", b"out")
        return prov.build_manifest(
            task=self.task_section(),
            factual_claims=claims or [],
            output=prov.build_output_section(self.task_dir, local_path="final.mp4"),
        )


# ---------------------------------------------------------------------------
# Deterministic claim IDs
# ---------------------------------------------------------------------------


class TestClaimIdGeneration(_TaskDirBase):
    def test_deterministic_same_inputs(self):
        id1 = prov.generate_claim_id(
            task_id="task-001",
            ordinal=0,
            claim_text="Bitcoin supply is capped at 21 million.",
            source_url="https://bitcoin.org/bitcoin.pdf",
        )
        id2 = prov.generate_claim_id(
            task_id="task-001",
            ordinal=0,
            claim_text="Bitcoin supply is capped at 21 million.",
            source_url="https://bitcoin.org/bitcoin.pdf",
        )
        self.assertEqual(id1, id2)
        self.assertRegex(id1, r"^claim-[0-9a-f]{32}$")

    def test_different_task_id_different_id(self):
        id1 = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text="c", source_url="https://x.com/y"
        )
        id2 = prov.generate_claim_id(
            task_id="task-002", ordinal=0, claim_text="c", source_url="https://x.com/y"
        )
        self.assertNotEqual(id1, id2)

    def test_different_ordinal_different_id(self):
        id1 = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text="c", source_url="https://x.com/y"
        )
        id2 = prov.generate_claim_id(
            task_id="task-001", ordinal=1, claim_text="c", source_url="https://x.com/y"
        )
        self.assertNotEqual(id1, id2)

    def test_different_text_different_id(self):
        id1 = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text="c1", source_url="https://x.com/y"
        )
        id2 = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text="c2", source_url="https://x.com/y"
        )
        self.assertNotEqual(id1, id2)

    def test_different_url_different_id(self):
        id1 = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text="c", source_url="https://x.com/y1"
        )
        id2 = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text="c", source_url="https://x.com/y2"
        )
        self.assertNotEqual(id1, id2)

    def test_duplicate_text_distinct_via_ordinal(self):
        id1 = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text="same", source_url="https://x.com/y"
        )
        id2 = prov.generate_claim_id(
            task_id="task-001", ordinal=1, claim_text="same", source_url="https://x.com/y"
        )
        self.assertNotEqual(id1, id2)


# ---------------------------------------------------------------------------
# NFC and line-ending normalization
# ---------------------------------------------------------------------------


class TestClaimTextNormalization(_TaskDirBase):
    def test_nfc_normalization(self):
        # é as single codepoint vs decomposed e + combining accent
        text1 = "caf\u00e9"  # NFC
        text2 = "cafe\u0301"  # NFD
        id1 = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text=text1, source_url="https://x.com/y"
        )
        id2 = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text=text2, source_url="https://x.com/y"
        )
        self.assertEqual(id1, id2)

    def test_crlf_to_lf(self):
        text1 = "line1\nline2"
        text2 = "line1\r\nline2"
        id1 = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text=text1, source_url="https://x.com/y"
        )
        id2 = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text=text2, source_url="https://x.com/y"
        )
        self.assertEqual(id1, id2)

    def test_cr_to_lf(self):
        text1 = "line1\nline2"
        text2 = "line1\rline2"
        id1 = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text=text1, source_url="https://x.com/y"
        )
        id2 = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text=text2, source_url="https://x.com/y"
        )
        self.assertEqual(id1, id2)

    def test_trim_leading_trailing_whitespace(self):
        text1 = "hello"
        text2 = "  hello  "
        text3 = "\n\nhello\n\n"
        id1 = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text=text1, source_url="https://x.com/y"
        )
        id2 = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text=text2, source_url="https://x.com/y"
        )
        id3 = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text=text3, source_url="https://x.com/y"
        )
        self.assertEqual(id1, id2)
        self.assertEqual(id1, id3)

    def test_preserve_internal_whitespace(self):
        text1 = "hello  world"
        text2 = "hello world"
        id1 = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text=text1, source_url="https://x.com/y"
        )
        id2 = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text=text2, source_url="https://x.com/y"
        )
        self.assertNotEqual(id1, id2)


# ---------------------------------------------------------------------------
# Collision failure
# ---------------------------------------------------------------------------


class TestClaimIdCollision(_TaskDirBase):
    def test_collision_fails_closed(self):
        # Identical inputs produce identical IDs — collision detected.
        id1 = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text="c", source_url="https://x.com/y"
        )
        id2 = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text="c", source_url="https://x.com/y"
        )
        self.assertEqual(id1, id2)
        # In a manifest, duplicate claim_id is rejected.
        claim1 = prov.build_claim(
            claim_text="c", source_url="https://x.com/y", claim_id=id1
        )
        claim2 = prov.build_claim(
            claim_text="c", source_url="https://x.com/y", claim_id=id2
        )
        with self.assertRaises(prov.ProvenanceError):
            self.simple_manifest([claim1, claim2])


# ---------------------------------------------------------------------------
# Immutable claim IDs
# ---------------------------------------------------------------------------


class TestClaimIdImmutability(_TaskDirBase):
    def test_claim_id_preserved_in_build(self):
        claim_id = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text="c", source_url="https://x.com/y"
        )
        claim = prov.build_claim(
            claim_text="c", source_url="https://x.com/y", claim_id=claim_id
        )
        self.assertEqual(claim["claim_id"], claim_id)

    def test_claim_id_validated_on_build(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.build_claim(
                claim_text="c", source_url="https://x.com/y", claim_id="invalid"
            )

    def test_claim_id_required_for_1_2_0(self):
        claim = prov.build_claim(
            claim_text="c", source_url="https://x.com/y"
        )
        # claim_id is None — build_manifest must reject it (no silent generation).
        self.assertIsNone(claim["claim_id"])
        with self.assertRaises(prov.ProvenanceError):
            self.simple_manifest([claim])
        # validate_manifest must also reject a 1.2.0 manifest with claim_id=None.
        claim_with_id = prov.build_claim(
            claim_text="c", source_url="https://x.com/y",
            claim_id=prov.generate_claim_id(
                task_id="task-001", ordinal=0,
                claim_text="c", source_url="https://x.com/y",
            ),
        )
        manifest = self.simple_manifest([claim_with_id])
        # Strip the claim_id to test validation.
        manifest["factual_claims"][0]["claim_id"] = None
        with self.assertRaises(prov.ProvenanceError):
            prov.validate_manifest(manifest)


# ---------------------------------------------------------------------------
# New 1.2.0 manifests
# ---------------------------------------------------------------------------


class TestSchema120(_TaskDirBase):
    def test_new_manifests_default_to_1_2_0(self):
        task = self.task_section()
        self.assertEqual(task["schema_version"], "1.2.0")
        self.assertEqual(prov.SCHEMA_VERSION, "1.2.0")

    def test_1_2_0_manifest_with_claim_ids_validates(self):
        claim_id = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text="c", source_url="https://x.com/y"
        )
        claim = prov.build_claim(
            claim_text="c", source_url="https://x.com/y", claim_id=claim_id
        )
        manifest = self.simple_manifest([claim])
        prov.validate_manifest(manifest)  # must not raise

    def test_1_1_0_manifest_still_validates(self):
        manifest = self.simple_manifest()
        manifest["task"]["schema_version"] = "1.1.0"
        # Remove claim_id to simulate 1.1.0.
        for claim in manifest["factual_claims"]:
            claim.pop("claim_id", None)
        prov.validate_manifest(manifest)  # must not raise

    def test_1_0_0_manifest_still_validates(self):
        manifest = self.simple_manifest()
        manifest["task"]["schema_version"] = "1.0.0"
        # Remove 1.1.0+ fields to simulate 1.0.0.
        for claim in manifest["factual_claims"]:
            for key in ("claim_id", "supporting_sources", "reviewer_id",
                        "reviewer_display_name", "review_timestamp_utc", "notes"):
                claim.pop(key, None)
        prov.validate_manifest(manifest)  # must not raise

    def test_1_2_0_missing_claim_id_key_rejected(self):
        claim = prov.build_claim(
            claim_text="c", source_url="https://x.com/y",
            claim_id=prov.generate_claim_id(
                task_id="task-001", ordinal=0,
                claim_text="c", source_url="https://x.com/y",
            ),
        )
        manifest = self.simple_manifest([claim])
        del manifest["factual_claims"][0]["claim_id"]
        with self.assertRaises(prov.ProvenanceError):
            prov.validate_manifest(manifest)

    def test_1_2_0_null_and_malformed_claim_id_rejected(self):
        claim = prov.build_claim(
            claim_text="c", source_url="https://x.com/y",
            claim_id=prov.generate_claim_id(
                task_id="task-001", ordinal=0,
                claim_text="c", source_url="https://x.com/y",
            ),
        )
        manifest = self.simple_manifest([claim])
        for bad in (None, "invalid", "claim-" + "A" * 32, "claim-" + "a" * 31):
            manifest["factual_claims"][0]["claim_id"] = bad
            with self.assertRaises(prov.ProvenanceError):
                prov.validate_manifest(manifest)

    def test_legacy_null_or_absent_claim_id_preserved(self):
        claim = prov.build_claim(
            claim_text="c", source_url="https://x.com/y",
            claim_id=prov.generate_claim_id(
                task_id="task-001", ordinal=0,
                claim_text="c", source_url="https://x.com/y",
            ),
        )
        manifest = self.simple_manifest([claim])
        manifest["task"]["schema_version"] = "1.1.0"
        manifest["factual_claims"][0]["claim_id"] = None
        prov.validate_manifest(manifest)  # null tolerated for legacy
        del manifest["factual_claims"][0]["claim_id"]
        prov.validate_manifest(manifest)  # absent tolerated for legacy
        manifest["task"]["schema_version"] = "1.0.0"
        for key in ("supporting_sources", "reviewer_id",
                    "reviewer_display_name", "review_timestamp_utc", "notes"):
            manifest["factual_claims"][0].pop(key, None)
        prov.validate_manifest(manifest)  # 1.0.0 stays valid without claim_id


# ---------------------------------------------------------------------------
# Deterministic migration
# ---------------------------------------------------------------------------


class TestMigration(_TaskDirBase):
    def _make_1_0_0_manifest(self):
        self.write_file("final.mp4", b"out")
        claim_id = prov.generate_claim_id(
            task_id="task-001",
            ordinal=0,
            claim_text="Bitcoin supply is capped at 21 million.",
            source_url="https://bitcoin.org/bitcoin.pdf",
        )
        claim = prov.build_claim(
            claim_text="Bitcoin supply is capped at 21 million.",
            source_url="https://bitcoin.org/bitcoin.pdf",
            status="VERIFIED",
            reviewer="rick",
            review_date=UTC2,
            claim_id=claim_id,
        )
        manifest = prov.build_manifest(
            task=self.task_section(),
            factual_claims=[claim],
            output=prov.build_output_section(self.task_dir, local_path="final.mp4"),
        )
        # Strip 1.1.0+ fields to simulate 1.0.0.
        manifest["task"]["schema_version"] = "1.0.0"
        for claim in manifest["factual_claims"]:
            for key in ("claim_id", "supporting_sources", "reviewer_id",
                        "reviewer_display_name", "review_timestamp_utc", "notes"):
                claim.pop(key, None)
        return manifest

    def _make_1_1_0_manifest(self):
        self.write_file("final.mp4", b"out")
        claim_id = prov.generate_claim_id(
            task_id="task-001",
            ordinal=0,
            claim_text="Bitcoin supply is capped at 21 million.",
            source_url="https://bitcoin.org/bitcoin.pdf",
        )
        claim = prov.build_claim(
            claim_text="Bitcoin supply is capped at 21 million.",
            source_url="https://bitcoin.org/bitcoin.pdf",
            status="VERIFIED",
            reviewer="rick",
            review_date=UTC2,
            claim_id=claim_id,
        )
        manifest = prov.build_manifest(
            task=self.task_section(),
            factual_claims=[claim],
            output=prov.build_output_section(self.task_dir, local_path="final.mp4"),
        )
        # Strip claim_id to simulate 1.1.0.
        manifest["task"]["schema_version"] = "1.1.0"
        for claim in manifest["factual_claims"]:
            claim.pop("claim_id", None)
        return manifest

    def test_migrate_1_0_0_to_1_2_0(self):
        manifest = self._make_1_0_0_manifest()
        original_json = json.dumps(manifest, sort_keys=True)
        migrated = prov.migrate_manifest_to_1_2_0(manifest)
        # Input not mutated.
        self.assertEqual(json.dumps(manifest, sort_keys=True), original_json)
        self.assertEqual(manifest["task"]["schema_version"], "1.0.0")
        # Output upgraded.
        self.assertEqual(migrated["task"]["schema_version"], "1.2.0")
        prov.validate_manifest(migrated)
        # claim_id added.
        for claim in migrated["factual_claims"]:
            self.assertIsNotNone(claim["claim_id"])
            self.assertRegex(claim["claim_id"], r"^claim-[0-9a-f]{32}$")

    def test_migrate_1_1_0_to_1_2_0(self):
        manifest = self._make_1_1_0_manifest()
        original_json = json.dumps(manifest, sort_keys=True)
        migrated = prov.migrate_manifest_to_1_2_0(manifest)
        # Input not mutated.
        self.assertEqual(json.dumps(manifest, sort_keys=True), original_json)
        # Output upgraded.
        self.assertEqual(migrated["task"]["schema_version"], "1.2.0")
        prov.validate_manifest(migrated)
        # claim_id added.
        for claim in migrated["factual_claims"]:
            self.assertIsNotNone(claim["claim_id"])

    def test_migration_deterministic(self):
        manifest = self._make_1_0_0_manifest()
        migrated1 = prov.migrate_manifest_to_1_2_0(manifest)
        migrated2 = prov.migrate_manifest_to_1_2_0(manifest)
        self.assertEqual(
            json.dumps(migrated1, sort_keys=True),
            json.dumps(migrated2, sort_keys=True),
        )

    def test_migration_rejects_approved(self):
        manifest = self._make_1_0_0_manifest()
        manifest["task"]["review_status"] = "APPROVED"
        with self.assertRaises(prov.ProvenanceError):
            prov.migrate_manifest_to_1_2_0(manifest)

    def test_migration_rejects_rejected(self):
        manifest = self._make_1_0_0_manifest()
        manifest["task"]["review_status"] = "REJECTED"
        with self.assertRaises(prov.ProvenanceError):
            prov.migrate_manifest_to_1_2_0(manifest)

    def test_migration_rejects_unsupported_version(self):
        manifest = self._make_1_0_0_manifest()
        manifest["task"]["schema_version"] = "2.0.0"
        with self.assertRaises(prov.ProvenanceError):
            prov.migrate_manifest_to_1_2_0(manifest)

    def test_migration_1_0_0_to_1_1_0_rejects_approved(self):
        manifest = self._make_1_0_0_manifest()
        manifest["task"]["review_status"] = "APPROVED"
        with self.assertRaises(prov.ProvenanceError):
            prov.migrate_manifest_1_0_0_to_1_1_0(manifest)


# ---------------------------------------------------------------------------
# Transaction journal primitives
# ---------------------------------------------------------------------------


class TestTransactionJournal(_TaskDirBase):
    def _create_journal(self, **overrides):
        kwargs = dict(JOURNAL_KWARGS)
        kwargs.update(overrides)
        return ri.create_transaction_journal(self.task_dir, **kwargs)

    def test_create_and_read_journal(self):
        journal = self._create_journal()
        self.assertEqual(journal["transaction_stage"], "INITIATED")
        self.assertRegex(journal["journal_hash"], r"^[0-9a-f]{64}$")
        read_back = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(read_back["transaction_id"], journal["transaction_id"])

    def test_journal_overwrite_conflict(self):
        self._create_journal()
        with self.assertRaises(ri.ReviewIntegrityError):
            self._create_journal()

    def test_journal_invalid_operation(self):
        with self.assertRaises(ri.ReviewIntegrityError):
            self._create_journal(operation="approve")

    def test_journal_invalid_claim_id(self):
        with self.assertRaises(prov.ProvenanceError):
            self._create_journal(claim_id="invalid")

    def test_journal_invalid_hash(self):
        with self.assertRaises(ri.ReviewIntegrityError):
            self._create_journal(starting_manifest_hash="not-a-hash")

    def test_read_malformed_journal_fails_closed(self):
        with open(os.path.join(self.task_dir, "review-transaction.json"), "w") as h:
            h.write("{corrupt")
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.read_transaction_journal(self.task_dir)

    def test_read_modified_journal_hash_fails_closed(self):
        journal = self._create_journal()
        path = os.path.join(self.task_dir, "review-transaction.json")
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        data["transaction_stage"] = "LOCK_ACQUIRED"
        with open(path, "w", encoding="utf-8") as h:
            json.dump(data, h)
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.read_transaction_journal(self.task_dir)

    def test_read_modified_immutable_field_fails_closed(self):
        journal = self._create_journal()
        path = os.path.join(self.task_dir, "review-transaction.json")
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        data["operation"] = "retract-claim"
        with open(path, "w", encoding="utf-8") as h:
            json.dump(data, h)
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.read_transaction_journal(self.task_dir)

    def test_update_stage_forward(self):
        journal = self._create_journal()
        updated = ri.update_transaction_stage(
            self.task_dir,
            transaction_id=journal["transaction_id"],
            new_stage="LOCK_ACQUIRED",
        )
        self.assertEqual(updated["transaction_stage"], "LOCK_ACQUIRED")
        read_back = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(read_back["transaction_stage"], "LOCK_ACQUIRED")

    def test_update_stage_all_valid_stages(self):
        journal = self._create_journal()
        stages = [
            "LOCK_ACQUIRED",
            "SNAPSHOT_CREATED",
            "PROPOSED_MANIFEST_READY",
            "EVENT_CREATED",
            "CHECKPOINT_UPDATED",
            "MANIFEST_INSTALLED",
            "COMMITTED",
        ]
        for stage in stages:
            updated = ri.update_transaction_stage(
                self.task_dir,
                transaction_id=journal["transaction_id"],
                new_stage=stage,
            )
            self.assertEqual(updated["transaction_stage"], stage)

    def test_update_stage_invalid_stage(self):
        journal = self._create_journal()
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.update_transaction_stage(
                self.task_dir,
                transaction_id=journal["transaction_id"],
                new_stage="INVALID_STAGE",
            )

    def test_update_stage_backward_rejected(self):
        journal = self._create_journal()
        ri.update_transaction_stage(
            self.task_dir,
            transaction_id=journal["transaction_id"],
            new_stage="LOCK_ACQUIRED",
        )
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.update_transaction_stage(
                self.task_dir,
                transaction_id=journal["transaction_id"],
                new_stage="INITIATED",
            )
        read_back = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(read_back["transaction_stage"], "LOCK_ACQUIRED")

    def test_update_stage_skip_rejected(self):
        journal = self._create_journal()
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.update_transaction_stage(
                self.task_dir,
                transaction_id=journal["transaction_id"],
                new_stage="SNAPSHOT_CREATED",
            )
        read_back = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(read_back["transaction_stage"], "INITIATED")

    def test_update_stage_repeat_rejected(self):
        journal = self._create_journal()
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.update_transaction_stage(
                self.task_dir,
                transaction_id=journal["transaction_id"],
                new_stage="INITIATED",
            )
        read_back = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(read_back["transaction_stage"], "INITIATED")

    def test_update_stage_skip_rejected_later(self):
        journal = self._create_journal()
        ri.update_transaction_stage(
            self.task_dir,
            transaction_id=journal["transaction_id"],
            new_stage="LOCK_ACQUIRED",
        )
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.update_transaction_stage(
                self.task_dir,
                transaction_id=journal["transaction_id"],
                new_stage="EVENT_CREATED",
            )
        read_back = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(read_back["transaction_stage"], "LOCK_ACQUIRED")

    def test_update_stage_wrong_transaction_id(self):
        journal = self._create_journal()
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.update_transaction_stage(
                self.task_dir,
                transaction_id="f" * 32,
                new_stage="LOCK_ACQUIRED",
            )

    def test_update_stage_no_journal(self):
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.update_transaction_stage(
                self.task_dir,
                transaction_id="a" * 32,
                new_stage="LOCK_ACQUIRED",
            )

    def test_delete_journal(self):
        self._create_journal()
        ri.delete_transaction_journal(self.task_dir)
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))

    def test_delete_journal_no_journal(self):
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.delete_transaction_journal(self.task_dir)

    def test_journal_path_traversal_rejected(self):
        with self.assertRaises(ri.ReviewIntegrityError):
            ri._journal_path(os.path.join(self.task_dir, "..", "outside"))

    def test_journal_atomic_cleanup_on_failure(self):
        # Simulate failure during journal creation.
        original_link = os.link
        ri.os.link = lambda *a, **k: (_ for _ in ()).throw(OSError("boom"))
        original_open = os.open

        def open_boom(path, flags, *args, **kwargs):
            if flags & os.O_EXCL:
                raise OSError("boom")
            return original_open(path, flags, *args, **kwargs)

        ri.os.open = open_boom
        try:
            with self.assertRaises(OSError):
                self._create_journal()
        finally:
            ri.os.link = original_link
            ri.os.open = original_open
        # No temp files left behind.
        leftovers = [f for f in os.listdir(self.task_dir) if "tmp" in f or "part" in f]
        self.assertEqual(leftovers, [])

    def test_create_absolute_path_rejected(self):
        absolute = os.path.join(self.task_dir, "elsewhere.json")
        with self.assertRaises(ri.ReviewIntegrityError):
            self._create_journal(proposed_manifest_relative_path=absolute)
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))

    def test_create_parent_traversal_rejected(self):
        with self.assertRaises(ri.ReviewIntegrityError):
            self._create_journal(snapshot_relative_path="../escape.json")
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))

    def test_create_nested_escape_rejected(self):
        with self.assertRaises(ri.ReviewIntegrityError):
            self._create_journal(
                proposed_manifest_relative_path="subdir/../../escape.json"
            )
        self.assertIsNone(ri.read_transaction_journal(self.task_dir))

    def _rewrite_journal_file(self, mutate):
        path = os.path.join(self.task_dir, "review-transaction.json")
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        mutate(data)
        data["journal_hash"] = ri._canonical_hash(ri._journal_unsigned_fields(data))
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        return data

    def test_read_unknown_field_fails_closed(self):
        self._create_journal()
        self._rewrite_journal_file(lambda d: d.__setitem__("unexpected_field", 1))
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.read_transaction_journal(self.task_dir)

    def test_read_missing_field_fails_closed(self):
        self._create_journal()
        self._rewrite_journal_file(lambda d: d.__delitem__("task_id"))
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.read_transaction_journal(self.task_dir)

    def test_read_modified_original_reviewer_fails_closed(self):
        self._create_journal()
        path = os.path.join(self.task_dir, "review-transaction.json")
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        data["original_reviewer_id"] = "mallory"
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.read_transaction_journal(self.task_dir)

    def test_update_writes_canonical_atomic_replacement(self):
        journal = self._create_journal()
        updated = ri.update_transaction_stage(
            self.task_dir,
            transaction_id=journal["transaction_id"],
            new_stage="LOCK_ACQUIRED",
        )
        path = os.path.join(self.task_dir, "review-transaction.json")
        with open(path, "rb") as handle:
            raw = handle.read()
        self.assertTrue(raw.endswith(b"\n"))
        on_disk = json.loads(raw.decode("utf-8"))
        self.assertEqual(on_disk, updated)
        read_back = ri.read_transaction_journal(self.task_dir)
        self.assertEqual(read_back["transaction_stage"], "LOCK_ACQUIRED")
        leftovers = [
            f for f in os.listdir(self.task_dir) if "tmp" in f or "part" in f
        ]
        self.assertEqual(leftovers, [])


# ---------------------------------------------------------------------------
# TRANSACTION_RESUMED rejection (fail closed; resume evidence is a receipt)
# ---------------------------------------------------------------------------


class TestTransactionResumedRejected(_TaskDirBase):
    def test_transaction_resumed_not_in_event_types(self):
        self.assertNotIn("TRANSACTION_RESUMED", ri.EVENT_TYPES)

    def test_create_transaction_resumed_event_rejected(self):
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.create_review_event(
                self.task_dir,
                event_type="TRANSACTION_RESUMED",
                reviewer_id=REVIEWER_ID,
                reviewer_display_name=REVIEWER_NAME,
                timestamp_utc=UTC,
                reason="resuming interrupted transaction",
                details={"transaction_id": "a" * 32},
            )
        events_dir = os.path.join(self.task_dir, "review-events")
        self.assertEqual(ri._scan_sequence(events_dir), [])

    def test_create_transaction_resumed_event_file_rejected(self):
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.create_review_event_file(
                self.task_dir,
                event_type="TRANSACTION_RESUMED",
                reviewer_id=REVIEWER_ID,
                reviewer_display_name=REVIEWER_NAME,
                timestamp_utc=UTC,
                reason="resuming interrupted transaction",
                details={"transaction_id": "a" * 32},
            )
        events_dir = os.path.join(self.task_dir, "review-events")
        self.assertEqual(ri._scan_sequence(events_dir), [])

    def test_forged_transaction_resumed_event_fails_chain_validation(self):
        committed = ri.create_review_event(
            self.task_dir,
            event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC,
        )
        forged = {
            "schema_version": ri.SCHEMA_VERSION,
            "sequence": 2,
            "event_id": "f" * 32,
            "event_type": "TRANSACTION_RESUMED",
            "timestamp_utc": UTC2,
            "reviewer_id": REVIEWER_ID,
            "reviewer_display_name": REVIEWER_NAME,
            "reason": "forged resume evidence",
            "previous_event_hash": committed["event_hash"],
            "manifest_hash_before": None,
            "manifest_hash_after": None,
            "details": None,
        }
        forged["event_hash"] = ri._canonical_hash(
            ri._event_unsigned_hash_fields(forged)
        )
        events_dir = os.path.join(self.task_dir, "review-events")
        path = os.path.join(events_dir, "000002_" + "f" * 32 + ".json")
        with open(path, "wb") as handle:
            handle.write(ri._canonical_bytes(forged) + b"\n")
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.validate_review_event_chain(self.task_dir)


# ---------------------------------------------------------------------------
# Version-conditional JSON Schema document assertions
# ---------------------------------------------------------------------------


SCHEMA_DOC_PATH = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "provenance-manifest-schema.json"
)


class TestJsonSchemaVersionConditional(_TaskDirBase):
    """Pin the exact version-conditional claim_id encoding in the schema doc.

    Structural assertions only — no general-purpose JSON Schema evaluator.
    Proves schema 1.2.0 conditionally requires a non-null claim_id matching
    ^claim-[0-9a-f]{32}$ while legacy 1.0.0/1.1.0 manifests remain valid
    without it.
    """

    @classmethod
    def setUpClass(cls):
        with open(SCHEMA_DOC_PATH, encoding="utf-8") as handle:
            cls.schema = json.load(handle)

    def _claim_items(self):
        return self.schema["properties"]["factual_claims"]["items"]

    def _conditional(self):
        blocks = self.schema.get("allOf")
        self.assertIsInstance(blocks, list)
        self.assertEqual(len(blocks), 1)
        return blocks[0]

    def test_claim_id_not_unconditionally_required(self):
        required = self._claim_items()["required"]
        self.assertNotIn("claim_id", required)
        for field in ("claim_text", "source_url", "status"):
            self.assertIn(field, required)

    def test_claim_id_base_property_nullable_with_pattern(self):
        claim_id = self._claim_items()["properties"]["claim_id"]
        self.assertEqual(claim_id["type"], ["string", "null"])
        self.assertEqual(claim_id["pattern"], "^claim-[0-9a-f]{32}$")

    def test_conditional_if_targets_schema_1_2_0(self):
        condition = self._conditional()["if"]
        self.assertEqual(condition["required"], ["task"])
        task = condition["properties"]["task"]
        self.assertEqual(task["required"], ["schema_version"])
        self.assertEqual(task["properties"]["schema_version"], {"const": "1.2.0"})

    def test_conditional_then_requires_non_null_claim_id(self):
        then = self._conditional()["then"]
        items = then["properties"]["factual_claims"]["items"]
        self.assertIn("claim_id", items["required"])
        # Non-null override: under 1.2.0 the type narrows to string only.
        self.assertEqual(items["properties"]["claim_id"]["type"], "string")

    def test_schema_version_enum_covers_all_supported(self):
        enum = self.schema["properties"]["task"]["properties"]["schema_version"][
            "enum"
        ]
        for version in ("1.2.0", "1.1.0", "1.0.0"):
            self.assertIn(version, enum)

    def test_uniqueness_documented_as_python_enforced(self):
        description = self._claim_items()["properties"]["claim_id"]["description"]
        self.assertIn("uniqueness", description.lower())
        self.assertIn("python", description.lower())


# ---------------------------------------------------------------------------
# Split event-file creation / checkpoint advancement primitives
# ---------------------------------------------------------------------------


class TestCreateReviewEventFile(_TaskDirBase):
    def _create_file(self, **overrides):
        kwargs = dict(
            event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC,
        )
        kwargs.update(overrides)
        return ri.create_review_event_file(self.task_dir, **kwargs)

    def test_creates_event_file_without_advancing_checkpoint(self):
        event = self._create_file()
        events_dir = os.path.join(self.task_dir, "review-events")
        entries = ri._scan_sequence(events_dir)
        self.assertEqual(len(entries), 1)
        self.assertEqual(event["sequence"], 1)
        self.assertIsNone(ri._read_checkpoint(events_dir))
        # The uncommitted tail fails closed on committed-chain validation.
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.validate_review_event_chain(self.task_dir)

    def test_caller_supplied_event_id_used(self):
        event = self._create_file(event_id="d" * 32)
        self.assertEqual(event["event_id"], "d" * 32)
        events_dir = os.path.join(self.task_dir, "review-events")
        entries = ri._scan_sequence(events_dir)
        self.assertEqual(entries[0][1], "000001_" + "d" * 32 + ".json")

    def test_invalid_event_id_rejected(self):
        for bad_id in ("not-hex", "D" * 32, "d" * 31, "d" * 33, 123):
            with self.assertRaises(ri.ReviewIntegrityError):
                self._create_file(event_id=bad_id)
        events_dir = os.path.join(self.task_dir, "review-events")
        self.assertEqual(ri._scan_sequence(events_dir), [])

    def test_event_validation_preserved(self):
        with self.assertRaises(ri.ReviewIntegrityError):
            self._create_file(event_type="NO_SUCH_TYPE")
        with self.assertRaises(ri.ReviewIntegrityError):
            self._create_file(event_type="CLAIM_RETRACTED")  # reason required
        with self.assertRaises(ri.ReviewIntegrityError):
            self._create_file(manifest_hash_before="not-a-hash")
        events_dir = os.path.join(self.task_dir, "review-events")
        self.assertEqual(ri._scan_sequence(events_dir), [])

    def test_duplicate_committed_event_id_rejected(self):
        first = self._create_file(event_id="d" * 32)
        ri.advance_review_event_checkpoint(
            self.task_dir,
            sequence=first["sequence"],
            event_id=first["event_id"],
            event_hash=first["event_hash"],
        )
        with self.assertRaises(ri.ReviewIntegrityError):
            self._create_file(event_id="d" * 32)
        events = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(events), 1)

    def test_uncommitted_tail_blocks_second_file(self):
        self._create_file()
        with self.assertRaises(ri.ReviewIntegrityError):
            self._create_file()
        events_dir = os.path.join(self.task_dir, "review-events")
        self.assertEqual(len(ri._scan_sequence(events_dir)), 1)

    def test_retry_same_event_id_does_not_overwrite(self):
        self._create_file(event_id="d" * 32)
        events_dir = os.path.join(self.task_dir, "review-events")
        path = os.path.join(events_dir, "000001_" + "d" * 32 + ".json")
        with open(path, "rb") as handle:
            before = handle.read()
        with self.assertRaises(ri.ReviewIntegrityError):
            self._create_file(event_id="d" * 32)
        with open(path, "rb") as handle:
            after = handle.read()
        self.assertEqual(before, after)


class TestAdvanceReviewEventCheckpoint(_TaskDirBase):
    def _create_tail(self, **overrides):
        kwargs = dict(
            event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC,
        )
        kwargs.update(overrides)
        return ri.create_review_event_file(self.task_dir, **kwargs)

    def test_advances_to_exact_tail(self):
        event = self._create_tail(event_id="d" * 32)
        checkpoint = ri.advance_review_event_checkpoint(
            self.task_dir,
            sequence=event["sequence"],
            event_id=event["event_id"],
            event_hash=event["event_hash"],
        )
        self.assertEqual(checkpoint["last_sequence"], 1)
        self.assertEqual(checkpoint["last_record_id"], event["event_id"])
        self.assertEqual(checkpoint["last_record_hash"], event["event_hash"])
        self.assertEqual(checkpoint["chain_type"], "review-events")
        recomputed = ri._canonical_hash(ri._checkpoint_unsigned_fields(checkpoint))
        self.assertEqual(checkpoint["checkpoint_hash"], recomputed)
        events = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_id"], event["event_id"])

    def test_no_events_refused(self):
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.advance_review_event_checkpoint(
                self.task_dir,
                sequence=1,
                event_id="d" * 32,
                event_hash=HASH_A,
            )

    def test_no_tail_refused_checkpoint_unchanged(self):
        event = self._create_tail()
        ri.advance_review_event_checkpoint(
            self.task_dir,
            sequence=event["sequence"],
            event_id=event["event_id"],
            event_hash=event["event_hash"],
        )
        events_dir = os.path.join(self.task_dir, "review-events")
        checkpoint_path = os.path.join(events_dir, "chain-head.json")
        with open(checkpoint_path, "rb") as handle:
            before = handle.read()
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.advance_review_event_checkpoint(
                self.task_dir,
                sequence=event["sequence"],
                event_id=event["event_id"],
                event_hash=event["event_hash"],
            )
        with open(checkpoint_path, "rb") as handle:
            after = handle.read()
        self.assertEqual(before, after)

    def test_wrong_event_id_refused(self):
        event = self._create_tail(event_id="d" * 32)
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.advance_review_event_checkpoint(
                self.task_dir,
                sequence=event["sequence"],
                event_id="e" * 32,
                event_hash=event["event_hash"],
            )
        events_dir = os.path.join(self.task_dir, "review-events")
        self.assertIsNone(ri._read_checkpoint(events_dir))

    def test_wrong_event_hash_refused(self):
        event = self._create_tail(event_id="d" * 32)
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.advance_review_event_checkpoint(
                self.task_dir,
                sequence=event["sequence"],
                event_id=event["event_id"],
                event_hash=HASH_B,
            )
        events_dir = os.path.join(self.task_dir, "review-events")
        self.assertIsNone(ri._read_checkpoint(events_dir))

    def test_wrong_sequence_refused(self):
        event = self._create_tail(event_id="d" * 32)
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.advance_review_event_checkpoint(
                self.task_dir,
                sequence=event["sequence"] + 1,
                event_id=event["event_id"],
                event_hash=event["event_hash"],
            )
        events_dir = os.path.join(self.task_dir, "review-events")
        self.assertIsNone(ri._read_checkpoint(events_dir))

    def test_invalid_parameters_rejected(self):
        self._create_tail()
        bad_calls = (
            dict(sequence=0, event_id="d" * 32, event_hash=HASH_A),
            dict(sequence="1", event_id="d" * 32, event_hash=HASH_A),
            dict(sequence=1, event_id="bad", event_hash=HASH_A),
            dict(sequence=1, event_id="d" * 32, event_hash="bad"),
        )
        for kwargs in bad_calls:
            with self.assertRaises(ri.ReviewIntegrityError):
                ri.advance_review_event_checkpoint(self.task_dir, **kwargs)
        events_dir = os.path.join(self.task_dir, "review-events")
        self.assertIsNone(ri._read_checkpoint(events_dir))

    def test_tampered_tail_event_fails_closed(self):
        event = self._create_tail(event_id="d" * 32)
        events_dir = os.path.join(self.task_dir, "review-events")
        path = os.path.join(events_dir, "000001_" + "d" * 32 + ".json")
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        data["reason"] = "tampered after creation"
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.advance_review_event_checkpoint(
                self.task_dir,
                sequence=event["sequence"],
                event_id=event["event_id"],
                event_hash=event["event_hash"],
            )
        self.assertIsNone(ri._read_checkpoint(events_dir))

    def test_advance_verifies_previous_event_linkage(self):
        ri.create_review_event(
            self.task_dir,
            event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC,
        )
        second = self._create_tail(event_id="e" * 32, timestamp_utc=UTC2)
        events_dir = os.path.join(self.task_dir, "review-events")
        path = os.path.join(events_dir, "000002_" + "e" * 32 + ".json")
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        data["previous_event_hash"] = HASH_B  # break linkage only
        data["event_hash"] = ri._canonical_hash(ri._event_unsigned_hash_fields(data))
        with open(path, "wb") as handle:
            handle.write(ri._canonical_bytes(data) + b"\n")
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.advance_review_event_checkpoint(
                self.task_dir,
                sequence=second["sequence"],
                event_id=second["event_id"],
                event_hash=data["event_hash"],
            )
        checkpoint = ri._read_checkpoint(events_dir)
        self.assertEqual(checkpoint["last_sequence"], 1)

    def test_extra_tail_beyond_reference_fails_closed(self):
        first = self._create_tail(event_id="d" * 32)
        forged = {
            "schema_version": ri.SCHEMA_VERSION,
            "sequence": 2,
            "event_id": "f" * 32,
            "event_type": "CLAIM_VERIFIED",
            "timestamp_utc": UTC2,
            "reviewer_id": REVIEWER_ID,
            "reviewer_display_name": REVIEWER_NAME,
            "reason": None,
            "previous_event_hash": first["event_hash"],
            "manifest_hash_before": None,
            "manifest_hash_after": None,
            "details": None,
        }
        forged["event_hash"] = ri._canonical_hash(
            ri._event_unsigned_hash_fields(forged)
        )
        events_dir = os.path.join(self.task_dir, "review-events")
        path = os.path.join(events_dir, "000002_" + "f" * 32 + ".json")
        with open(path, "wb") as handle:
            handle.write(ri._canonical_bytes(forged) + b"\n")
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.advance_review_event_checkpoint(
                self.task_dir,
                sequence=first["sequence"],
                event_id=first["event_id"],
                event_hash=first["event_hash"],
            )
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.advance_review_event_checkpoint(
                self.task_dir,
                sequence=forged["sequence"],
                event_id=forged["event_id"],
                event_hash=forged["event_hash"],
            )
        self.assertIsNone(ri._read_checkpoint(events_dir))

    def test_advance_does_not_modify_event_file(self):
        event = self._create_tail(event_id="d" * 32)
        events_dir = os.path.join(self.task_dir, "review-events")
        path = os.path.join(events_dir, "000001_" + "d" * 32 + ".json")
        with open(path, "rb") as handle:
            before = handle.read()
        ri.advance_review_event_checkpoint(
            self.task_dir,
            sequence=event["sequence"],
            event_id=event["event_id"],
            event_hash=event["event_hash"],
        )
        with open(path, "rb") as handle:
            after = handle.read()
        self.assertEqual(before, after)

    def _committed_head(self):
        return ri.create_review_event(
            self.task_dir,
            event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC,
        )

    def _checkpoint_bytes(self):
        events_dir = os.path.join(self.task_dir, "review-events")
        with open(os.path.join(events_dir, "chain-head.json"), "rb") as handle:
            return handle.read()

    def _forge_tail(self, committed, event_id="f" * 32, omit=(), **overrides):
        forged = {
            "schema_version": ri.SCHEMA_VERSION,
            "sequence": committed["sequence"] + 1,
            "event_id": event_id,
            "event_type": "CLAIM_VERIFIED",
            "timestamp_utc": UTC2,
            "reviewer_id": REVIEWER_ID,
            "reviewer_display_name": REVIEWER_NAME,
            "reason": None,
            "previous_event_hash": committed["event_hash"],
            "manifest_hash_before": None,
            "manifest_hash_after": None,
            "details": None,
        }
        forged.update(overrides)
        for field in omit:
            del forged[field]
        # Recompute a matching hash over the (possibly invalid) structure so
        # rejection must come from structural/semantic validation, not the
        # self-hash check.
        forged["event_hash"] = ri._canonical_hash(
            ri._event_unsigned_hash_fields(forged)
        )
        events_dir = os.path.join(self.task_dir, "review-events")
        name = f"{forged['sequence']:06d}_{event_id}.json"
        with open(os.path.join(events_dir, name), "wb") as handle:
            handle.write(ri._canonical_bytes(forged) + b"\n")
        return forged

    def test_invalid_existing_checkpoint_hash_no_mutation(self):
        self._committed_head()
        tail = self._create_tail(event_id="e" * 32, timestamp_utc=UTC2)
        events_dir = os.path.join(self.task_dir, "review-events")
        checkpoint_path = os.path.join(events_dir, "chain-head.json")
        with open(checkpoint_path, encoding="utf-8") as handle:
            checkpoint = json.load(handle)
        checkpoint["last_record_id"] = "0" * 32  # invalidates checkpoint_hash
        with open(checkpoint_path, "w", encoding="utf-8") as handle:
            json.dump(checkpoint, handle)
        before = self._checkpoint_bytes()
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.advance_review_event_checkpoint(
                self.task_dir,
                sequence=tail["sequence"],
                event_id=tail["event_id"],
                event_hash=tail["event_hash"],
            )
        self.assertEqual(before, self._checkpoint_bytes())
        self.assertEqual(ri._read_checkpoint(events_dir)["last_sequence"], 1)

    def test_corrupted_committed_prefix_event_no_mutation(self):
        committed = self._committed_head()
        tail = self._create_tail(event_id="e" * 32, timestamp_utc=UTC2)
        events_dir = os.path.join(self.task_dir, "review-events")
        committed_path = os.path.join(
            events_dir, "000001_" + committed["event_id"] + ".json"
        )
        with open(committed_path, encoding="utf-8") as handle:
            data = json.load(handle)
        data["reviewer_display_name"] = "Mallory"  # corrupt without rehash
        with open(committed_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        before = self._checkpoint_bytes()
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.advance_review_event_checkpoint(
                self.task_dir,
                sequence=tail["sequence"],
                event_id=tail["event_id"],
                event_hash=tail["event_hash"],
            )
        self.assertEqual(before, self._checkpoint_bytes())
        self.assertEqual(ri._read_checkpoint(events_dir)["last_sequence"], 1)

    def test_unknown_event_type_tail_recomputed_hash_no_mutation(self):
        committed = self._committed_head()
        forged = self._forge_tail(committed, event_type="NO_SUCH_TYPE")
        events_dir = os.path.join(self.task_dir, "review-events")
        before = self._checkpoint_bytes()
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.advance_review_event_checkpoint(
                self.task_dir,
                sequence=forged["sequence"],
                event_id=forged["event_id"],
                event_hash=forged["event_hash"],
            )
        self.assertEqual(before, self._checkpoint_bytes())
        self.assertEqual(ri._read_checkpoint(events_dir)["last_sequence"], 1)

    def test_structurally_malformed_tail_recomputed_hash_no_mutation(self):
        committed = self._committed_head()
        forged = self._forge_tail(committed, omit=("details",))
        events_dir = os.path.join(self.task_dir, "review-events")
        before = self._checkpoint_bytes()
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.advance_review_event_checkpoint(
                self.task_dir,
                sequence=forged["sequence"],
                event_id=forged["event_id"],
                event_hash=forged["event_hash"],
            )
        self.assertEqual(before, self._checkpoint_bytes())
        self.assertEqual(ri._read_checkpoint(events_dir)["last_sequence"], 1)


class TestCreateReviewEventWrapper(_TaskDirBase):
    def test_wrapper_signature_and_end_state_preserved(self):
        event = ri.create_review_event(
            self.task_dir,
            event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC,
            manifest_hash_before=HASH_A,
            manifest_hash_after=HASH_B,
            details={"key": "value"},
        )
        self.assertEqual(event["sequence"], 1)
        self.assertEqual(event["event_type"], "CLAIM_VERIFIED")
        self.assertEqual(event["details"], {"key": "value"})
        recomputed = ri._canonical_hash(ri._event_unsigned_hash_fields(event))
        self.assertEqual(event["event_hash"], recomputed)
        events = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(events), 1)
        events_dir = os.path.join(self.task_dir, "review-events")
        checkpoint = ri._read_checkpoint(events_dir)
        self.assertEqual(checkpoint["last_record_hash"], event["event_hash"])

    def test_wrapper_sequential_appends(self):
        first = ri.create_review_event(
            self.task_dir,
            event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC,
        )
        second = ri.create_review_event(
            self.task_dir,
            event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC2,
        )
        self.assertEqual(second["sequence"], 2)
        self.assertEqual(second["previous_event_hash"], first["event_hash"])
        events = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(events), 2)

    def test_wrapper_equivalent_to_split_composition(self):
        # The wrapper's end state must equal the two primitives composed:
        # event file present, checkpoint committed to it, chain validates.
        event = ri.create_review_event(
            self.task_dir,
            event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC,
        )
        events_dir = os.path.join(self.task_dir, "review-events")
        entries = ri._scan_sequence(events_dir)
        self.assertEqual(entries, [(1, "000001_" + event["event_id"] + ".json")])
        checkpoint = ri._read_checkpoint(events_dir)
        self.assertEqual(checkpoint["last_sequence"], 1)
        self.assertEqual(checkpoint["last_record_id"], event["event_id"])
        self.assertEqual(checkpoint["last_record_hash"], event["event_hash"])

    def test_wrapper_validation_unchanged(self):
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.create_review_event(
                self.task_dir,
                event_type="NO_SUCH_TYPE",
                reviewer_id=REVIEWER_ID,
                reviewer_display_name=REVIEWER_NAME,
                timestamp_utc=UTC,
            )
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.create_review_event(
                self.task_dir,
                event_type="CLAIM_RETRACTED",
                reviewer_id=REVIEWER_ID,
                reviewer_display_name=REVIEWER_NAME,
                timestamp_utc=UTC,
            )
        self.assertEqual(ri.validate_review_event_chain(self.task_dir), [])


class TestSplitIndependentFailure(_TaskDirBase):
    def test_interruption_between_split_steps_detected_and_recovered(self):
        # Simulate a crash after event-file creation, before advancement.
        event = ri.create_review_event_file(
            self.task_dir,
            event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC,
            event_id="d" * 32,
        )
        # Detection: committed-chain validation fails closed on the tail.
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.validate_review_event_chain(self.task_dir)
        # Recovery: advancing with the exact expected parameters commits it.
        checkpoint = ri.advance_review_event_checkpoint(
            self.task_dir,
            sequence=event["sequence"],
            event_id=event["event_id"],
            event_hash=event["event_hash"],
        )
        self.assertEqual(checkpoint["last_record_id"], "d" * 32)
        events = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_hash"], event["event_hash"])

    def test_recovery_with_wrong_parameters_fails_closed(self):
        event = ri.create_review_event_file(
            self.task_dir,
            event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC,
            event_id="d" * 32,
        )
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.advance_review_event_checkpoint(
                self.task_dir,
                sequence=event["sequence"],
                event_id="e" * 32,
                event_hash=event["event_hash"],
            )
        events_dir = os.path.join(self.task_dir, "review-events")
        self.assertIsNone(ri._read_checkpoint(events_dir))
        # The tail remains uncommitted and still fails closed.
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.validate_review_event_chain(self.task_dir)


# ---------------------------------------------------------------------------
# Read-only CLI detection (status/audit with journals)
# ---------------------------------------------------------------------------


def _PatchedPath(root: str):
    real_path = Path

    class _Factory:
        def __call__(self, *args):
            if args and str(args[0]).endswith("pilot_policy.py"):
                return real_path(root) / "app" / "services" / "pilot_policy.py"
            return real_path(*args)

    return _Factory()


VALID_POLICY = """
[pilot]
mode = "cli"
api_server_enabled = false
webui_enabled = false
upload_post_enabled = false
redis_enabled = false

[bgm]
source = "none"

[materials]
video_source = "local"
"""


class TestReadOnlyCliDetection(unittest.TestCase):
    """Test that status and audit detect journals without modifying anything.

    Uses the established pilot-review fixture pattern: sandboxed project root
    with hardening.toml, task dir as a subdirectory, and patched policy Path.
    """

    def setUp(self):
        self._net = _NetworkBlocker()
        self._net.__enter__()

        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        # Policy file lives at the sandboxed project root.
        (Path(self.root) / "hardening.toml").write_text(
            VALID_POLICY, encoding="utf-8"
        )
        self.task_dir = os.path.join(self.root, "task-001")
        os.makedirs(self.task_dir)

        # Point the pilot-policy loader at the sandboxed root and activate.
        self._env = patch.dict(
            os.environ, {"MPT_PILOT_PROFILE": "braintrustcrypto"}
        )
        self._env.start()
        from app.services.pilot_policy import reset_pilot_policy_cache
        reset_pilot_policy_cache()
        self._root_patch = patch(
            "app.services.pilot_policy.Path",
            _PatchedPath(self.root),
        )
        self._root_patch.start()

        # Create a minimal valid manifest for CLI tests.
        self.write_file("script.txt", b"script body")
        self.write_file("final.mp4", b"out")
        claim_id = prov.generate_claim_id(
            task_id="task-001", ordinal=0, claim_text="c", source_url="https://x.com/y"
        )
        claim = prov.build_claim(
            claim_text="c", source_url="https://x.com/y", claim_id=claim_id
        )
        task = prov.build_task_section(
            task_id="task-001", topic="t", pilot_profile="braintrustcrypto",
            created_at=UTC,
        )
        script = prov.build_script_section(
            self.task_dir, local_path="script.txt", generation_source="local"
        )
        output = prov.build_output_section(
            self.task_dir, local_path="final.mp4"
        )
        manifest = prov.build_manifest(
            task=task, script=script, factual_claims=[claim], output=output
        )
        prov.write_manifest_atomic(self.task_dir, manifest)

    def tearDown(self):
        self._root_patch.stop()
        self._env.stop()
        from app.services.pilot_policy import reset_pilot_policy_cache
        reset_pilot_policy_cache()
        self._tmp.cleanup()
        self._net.__exit__(None, None, None)

    def write_file(self, name, data=b"x"):
        path = os.path.join(self.task_dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def _snapshot_tree(self):
        snapshot = {}
        for dirpath, _dirnames, filenames in os.walk(self.task_dir):
            for name in filenames:
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, self.task_dir)
                with open(full, "rb") as handle:
                    snapshot[rel] = hashlib.sha256(handle.read()).hexdigest()
        return snapshot

    def _run_cli(self, command):
        from io import StringIO
        import pilot_review

        out, err = StringIO(), StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            code = pilot_review.run([command, "--task-dir", self.task_dir])
        finally:
            sys.stdout, sys.stderr = old_out, old_err
        return code, out.getvalue(), err.getvalue()

    def test_status_with_no_journal(self):
        code, out, _ = self._run_cli("status")
        self.assertEqual(code, 0)
        self.assertIn("  transaction status: none\n", out)
        self.assertNotIn("INCOMPLETE_TRANSACTION", out)

    def test_status_with_valid_journal(self):
        journal = ri.create_transaction_journal(self.task_dir, **JOURNAL_KWARGS)
        code, out, _ = self._run_cli("status")
        self.assertEqual(code, 1)
        block = (
            "  transaction status: INCOMPLETE_TRANSACTION\n"
            f"  transaction id: {journal['transaction_id']}\n"
            "  transaction stage: INITIATED\n"
        )
        self.assertIn(block, out)

    def test_status_with_malformed_journal(self):
        with open(os.path.join(self.task_dir, "review-transaction.json"), "w") as h:
            h.write("{corrupt")
        code, out, _ = self._run_cli("status")
        self.assertEqual(code, 1)
        block = (
            "  transaction status: INCOMPLETE_TRANSACTION\n"
            "  transaction id: invalid\n"
            "  transaction stage: invalid\n"
        )
        self.assertIn(block, out)
        self.assertNotIn("{corrupt", out)

    def test_status_transaction_output_redaction(self):
        ri.create_transaction_journal(self.task_dir, **JOURNAL_KWARGS)
        code, out, _ = self._run_cli("status")
        self.assertEqual(code, 1)
        for leaked in (
            JOURNAL_KWARGS["claim_id"],
            JOURNAL_KWARGS["lock_token"],
            JOURNAL_KWARGS["expected_event_id"],
            JOURNAL_KWARGS["expected_event_hash"],
            JOURNAL_KWARGS["starting_manifest_hash"],
            JOURNAL_KWARGS["proposed_manifest_hash"],
            "verify-claim",
            "operation",
        ):
            self.assertNotIn(leaked, out)

    def test_audit_with_no_journal(self):
        code, out, _ = self._run_cli("audit")
        self.assertEqual(code, 0)
        self.assertIn("PASS", out)

    def test_audit_with_valid_journal(self):
        journal = ri.create_transaction_journal(self.task_dir, **JOURNAL_KWARGS)
        code, out, _ = self._run_cli("audit")
        self.assertEqual(code, 1)
        self.assertIn("FAIL", out)
        self.assertIn("INCOMPLETE_TRANSACTION", out)
        self.assertNotIn(journal["transaction_id"], out)
        self.assertNotIn(JOURNAL_KWARGS["claim_id"], out)
        self.assertNotIn(JOURNAL_KWARGS["lock_token"], out)

    def test_audit_with_malformed_journal(self):
        with open(os.path.join(self.task_dir, "review-transaction.json"), "w") as h:
            h.write("{corrupt")
        code, out, _ = self._run_cli("audit")
        self.assertEqual(code, 1)
        self.assertIn("FAIL", out)
        self.assertIn("INCOMPLETE_TRANSACTION", out)

    def test_read_only_byte_for_byte_with_journal(self):
        ri.create_transaction_journal(self.task_dir, **JOURNAL_KWARGS)
        before = self._snapshot_tree()
        code, _, _ = self._run_cli("status")
        after = self._snapshot_tree()
        self.assertEqual(code, 1)
        self.assertEqual(before, after)

    def test_read_only_byte_for_byte_audit_with_journal(self):
        ri.create_transaction_journal(self.task_dir, **JOURNAL_KWARGS)
        before = self._snapshot_tree()
        code, _, _ = self._run_cli("audit")
        after = self._snapshot_tree()
        self.assertEqual(code, 1)
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
