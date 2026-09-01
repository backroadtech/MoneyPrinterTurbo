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
- journal-hash modification
- immutable-field modification
- traversal and unsafe paths
- journal overwrite conflict
- atomic cleanup after injected failures
- status/audit with no journal
- status/audit with valid, malformed, or modified journal
- read-only byte-for-byte guarantees
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
        kwargs = dict(
            operation="verify-claim",
            starting_manifest_hash=HASH_A,
            proposed_manifest_hash=HASH_B,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            claim_id="claim-" + "a" * 32,
            created_at_utc=UTC,
            lock_token="b" * 32,
        )
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
        data = json.loads(open(path, encoding="utf-8").read())
        data["transaction_stage"] = "LOCK_ACQUIRED"
        with open(path, "w", encoding="utf-8") as h:
            json.dump(data, h)
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.read_transaction_journal(self.task_dir)

    def test_read_modified_immutable_field_fails_closed(self):
        journal = self._create_journal()
        path = os.path.join(self.task_dir, "review-transaction.json")
        data = json.loads(open(path, encoding="utf-8").read())
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
            "EVENT_CREATED",
            "CHECKPOINT_UPDATED",
            "MANIFEST_WRITTEN",
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


# ---------------------------------------------------------------------------
# TRANSACTION_RESUMED event type
# ---------------------------------------------------------------------------


class TestTransactionResumedEvent(_TaskDirBase):
    def test_transaction_resumed_event_type_recognized(self):
        self.assertIn("TRANSACTION_RESUMED", ri.EVENT_TYPES)

    def test_create_transaction_resumed_event(self):
        event = ri.create_review_event(
            self.task_dir,
            event_type="TRANSACTION_RESUMED",
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC,
            reason="resuming interrupted transaction",
            details={"transaction_id": "a" * 32, "stage_at_resume": "LOCK_ACQUIRED"},
        )
        self.assertEqual(event["event_type"], "TRANSACTION_RESUMED")


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
        self.assertIn("transaction status:   none", out)

    def test_status_with_valid_journal(self):
        ri.create_transaction_journal(
            self.task_dir,
            operation="verify-claim",
            starting_manifest_hash=HASH_A,
            proposed_manifest_hash=HASH_B,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            claim_id="claim-" + "a" * 32,
            created_at_utc=UTC,
            lock_token="b" * 32,
        )
        code, out, _ = self._run_cli("status")
        self.assertEqual(code, 1)
        self.assertIn("INCOMPLETE_TRANSACTION", out)

    def test_status_with_malformed_journal(self):
        with open(os.path.join(self.task_dir, "review-transaction.json"), "w") as h:
            h.write("{corrupt")
        code, out, _ = self._run_cli("status")
        self.assertEqual(code, 1)
        self.assertIn("INCOMPLETE_TRANSACTION", out)

    def test_audit_with_no_journal(self):
        code, out, _ = self._run_cli("audit")
        self.assertEqual(code, 0)
        self.assertIn("PASS", out)

    def test_audit_with_valid_journal(self):
        ri.create_transaction_journal(
            self.task_dir,
            operation="verify-claim",
            starting_manifest_hash=HASH_A,
            proposed_manifest_hash=HASH_B,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            claim_id="claim-" + "a" * 32,
            created_at_utc=UTC,
            lock_token="b" * 32,
        )
        code, out, _ = self._run_cli("audit")
        self.assertEqual(code, 1)
        self.assertIn("FAIL", out)
        self.assertIn("INCOMPLETE_TRANSACTION", out)

    def test_audit_with_malformed_journal(self):
        with open(os.path.join(self.task_dir, "review-transaction.json"), "w") as h:
            h.write("{corrupt")
        code, out, _ = self._run_cli("audit")
        self.assertEqual(code, 1)
        self.assertIn("FAIL", out)
        self.assertIn("INCOMPLETE_TRANSACTION", out)

    def test_read_only_byte_for_byte_with_journal(self):
        ri.create_transaction_journal(
            self.task_dir,
            operation="verify-claim",
            starting_manifest_hash=HASH_A,
            proposed_manifest_hash=HASH_B,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            claim_id="claim-" + "a" * 32,
            created_at_utc=UTC,
            lock_token="b" * 32,
        )
        before = self._snapshot_tree()
        code, _, _ = self._run_cli("status")
        after = self._snapshot_tree()
        self.assertEqual(code, 1)
        self.assertEqual(before, after)

    def test_read_only_byte_for_byte_audit_with_journal(self):
        ri.create_transaction_journal(
            self.task_dir,
            operation="verify-claim",
            starting_manifest_hash=HASH_A,
            proposed_manifest_hash=HASH_B,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            claim_id="claim-" + "a" * 32,
            created_at_utc=UTC,
            lock_token="b" * 32,
        )
        before = self._snapshot_tree()
        code, _, _ = self._run_cli("audit")
        after = self._snapshot_tree()
        self.assertEqual(code, 1)
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
