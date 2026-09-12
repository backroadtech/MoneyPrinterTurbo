"""
Phase 1B.3C.2A — Offline review-integrity primitives.

Fully offline tests (zero network access). Covers:
- schema 1.1.0 defaults and explicit 1.0.0 compatibility/migration
- canonical JSON determinism, float/NaN rejection
- reviewer identity validation (format, control characters)
- supporting-source rules (VERIFIED needs HTTPS; RETRACTED needs identity+notes)
- UNVERIFIED/RETRACTED claims blocking approval
- review-event chain creation and validation
- modified, missing, reordered, duplicated events; unexpected files
- approval/revocation receipt linkage and chain validation
- immutable no-overwrite behavior for events, receipts, history
- path traversal and escape rejection
- lock acquisition, contention, token-verified release
- malformed-lock fail-closed behavior
- explicit recovery with reason and audit event
- temp-file cleanup after injected failures
"""

import json
import math
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.services import provenance as prov
from app.services import review_integrity as ri


UTC = "2026-08-30T12:00:00Z"
UTC2 = "2026-08-30T13:00:00Z"
UTC3 = "2026-08-30T14:00:00Z"
REVIEWER_ID = "rick.gamboa"
REVIEWER_NAME = "Rick Gamboa"
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64


class _TaskDirBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.task_dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

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
        # Give every claim a deterministic claim_id for schema 1.2.0.
        claims = claims or []
        for ordinal, claim in enumerate(claims):
            if claim.get("claim_id") is None:
                claim["claim_id"] = prov.generate_claim_id(
                    task_id="task-001",
                    ordinal=ordinal,
                    claim_text=claim["claim_text"],
                    source_url=claim["source_url"],
                )
        return prov.build_manifest(
            task=self.task_section(),
            factual_claims=claims,
            output=prov.build_output_section(self.task_dir, local_path="final.mp4"),
        )


# ---------------------------------------------------------------------------
# Schema 1.1.0 defaults and 1.0.0 compatibility / migration
# ---------------------------------------------------------------------------


class TestSchemaVersioning(_TaskDirBase):
    def test_new_manifests_default_to_1_2_0(self):
        task = self.task_section()
        self.assertEqual(task["schema_version"], "1.2.0")
        self.assertEqual(prov.SCHEMA_VERSION, "1.2.0")

    def test_1_0_0_manifest_still_validates(self):
        manifest = self.simple_manifest()
        manifest["task"]["schema_version"] = "1.0.0"
        # Strip 1.1.0-only claim fields to look like a true 1.0.0 doc.
        for claim in manifest["factual_claims"]:
            for key in ("supporting_sources", "reviewer_id",
                        "reviewer_display_name", "review_timestamp_utc", "notes"):
                claim.pop(key, None)
        prov.validate_manifest(manifest)  # must not raise

    def test_unsupported_schema_version_rejected(self):
        manifest = self.simple_manifest()
        manifest["task"]["schema_version"] = "2.0.0"
        with self.assertRaises(prov.ProvenanceError):
            prov.validate_manifest(manifest)

    def test_migration_1_0_0_to_1_1_0_is_explicit_and_non_mutating(self):
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
        # Strip 1.1.0+ fields to simulate a true 1.0.0 doc.
        manifest["task"]["schema_version"] = "1.0.0"
        for claim in manifest["factual_claims"]:
            for key in ("claim_id", "supporting_sources", "reviewer_id",
                        "reviewer_display_name", "review_timestamp_utc", "notes"):
                claim.pop(key, None)
        original_json = json.dumps(manifest, sort_keys=True)

        migrated = prov.migrate_manifest_1_0_0_to_1_1_0(manifest)
        # Input not mutated.
        self.assertEqual(json.dumps(manifest, sort_keys=True), original_json)
        self.assertEqual(manifest["task"]["schema_version"], "1.0.0")
        # Output upgraded and valid.
        self.assertEqual(migrated["task"]["schema_version"], "1.1.0")
        prov.validate_manifest(migrated)
        for c in migrated["factual_claims"]:
            for key in ("supporting_sources", "reviewer_id",
                        "reviewer_display_name", "review_timestamp_utc", "notes"):
                self.assertIn(key, c)
                self.assertIsNone(c[key])

    def test_migration_rejects_non_1_0_0(self):
        manifest = self.simple_manifest()  # already 1.1.0
        with self.assertRaises(prov.ProvenanceError):
            prov.migrate_manifest_1_0_0_to_1_1_0(manifest)

    def test_revoked_not_in_output_review_status(self):
        self.assertNotIn("REVOKED", prov.OUTPUT_REVIEW_STATUSES)
        self.write_file("final.mp4", b"out")
        with self.assertRaises(prov.ProvenanceError):
            prov.build_output_section(
                self.task_dir, local_path="final.mp4", review_status="REVOKED"
            )


# ---------------------------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------------------------


class TestCanonicalJson(unittest.TestCase):
    def test_deterministic_across_repeated_serialization(self):
        obj = {"b": 1, "a": [3, 2, 1], "c": {"z": "x", "y": "w"}}
        first = prov.canonical_json_bytes(obj)
        second = prov.canonical_json_bytes(json.loads(first.decode("utf-8")))
        self.assertEqual(first, second)

    def test_canonical_rules(self):
        obj = {"b": "é", "a": 1}  # non-ASCII to prove ensure_ascii=False
        raw = prov.canonical_json_bytes(obj)
        text = raw.decode("utf-8")
        self.assertEqual(text, '{"a":1,"b":"é"}')  # sorted, compact, UTF-8
        self.assertFalse(raw.endswith(b"\n"))       # no trailing newline
        self.assertNotIn(b" ", raw)                 # no whitespace

    def test_float_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.canonical_json_bytes({"value": 1.5})

    def test_nested_float_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.canonical_json_bytes({"outer": {"inner": [0.25]}})

    def test_nan_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.canonical_json_bytes({"value": math.nan})

    def test_infinity_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.canonical_json_bytes({"value": math.inf})

    def test_canonical_sha256_stable(self):
        obj = {"x": [1, 2], "y": "z"}
        self.assertEqual(prov.canonical_sha256(obj), prov.canonical_sha256(dict(obj)))
        self.assertRegex(prov.canonical_sha256(obj), r"^[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# Reviewer identity
# ---------------------------------------------------------------------------


class TestReviewerValidation(unittest.TestCase):
    def test_valid_reviewer_ids(self):
        for rid in ("a", "rick.gamboa", "r-1_c.d", "0" * 64):
            self.assertEqual(prov.validate_reviewer_id(rid), rid)

    def test_invalid_reviewer_ids(self):
        for rid in ("", "A", "UPPER", "-lead", ".lead", "_lead", "has space",
                    "has/slash", "a" * 65, None, 42, "café"):
            with self.assertRaises(prov.ProvenanceError, msg=repr(rid)):
                prov.validate_reviewer_id(rid)

    def test_valid_display_names(self):
        self.assertEqual(prov.validate_reviewer_display_name("Rick Gamboa"), "Rick Gamboa")
        self.assertEqual(prov.validate_reviewer_display_name("x" * 128), "x" * 128)

    def test_invalid_display_names(self):
        for name in ("", "x" * 129, None, 7):
            with self.assertRaises(prov.ProvenanceError, msg=repr(name)):
                prov.validate_reviewer_display_name(name)

    def test_control_characters_rejected(self):
        for bad in ("a\tb", "a\nb", "a\rb", "a\x00b", "a\x7fb", "a\x1bb"):
            with self.assertRaises(prov.ProvenanceError, msg=repr(bad)):
                prov.validate_reviewer_display_name(bad)


# ---------------------------------------------------------------------------
# Supporting-source rules and approval blocking
# ---------------------------------------------------------------------------


class TestSupportingSources(_TaskDirBase):
    def test_verified_requires_https_source(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.build_claim(
                claim_text="c", source_url="http://insecure.example/x",
                status="VERIFIED", reviewer="rick", review_date=UTC2,
            )

    def test_verified_ok_with_https_source_url(self):
        claim = prov.build_claim(
            claim_text="c", source_url="https://bitcoin.org/bitcoin.pdf",
            status="VERIFIED", reviewer="rick", review_date=UTC2,
        )
        self.assertEqual(claim["status"], "VERIFIED")

    def test_verified_ok_with_https_supporting_source(self):
        claim = prov.build_claim(
            claim_text="c", source_url="http://weak.example/x",
            status="VERIFIED", reviewer="rick", review_date=UTC2,
            supporting_sources=["https://strong.example/evidence"],
        )
        self.assertEqual(claim["supporting_sources"], ["https://strong.example/evidence"])

    def test_retracted_1_1_0_requires_identity_timestamp_notes(self):
        base = dict(claim_text="c", source_url="https://x.example/y",
                    status="RETRACTED", reviewer_id=REVIEWER_ID,
                    reviewer_display_name=REVIEWER_NAME)
        with self.assertRaises(prov.ProvenanceError):  # missing timestamp + notes
            prov.build_claim(**base)
        with self.assertRaises(prov.ProvenanceError):  # missing notes
            prov.build_claim(**base, review_timestamp_utc=UTC2)
        claim = prov.build_claim(**base, review_timestamp_utc=UTC2,
                                 notes="source retracted the figure")
        self.assertEqual(claim["notes"], "source retracted the figure")

    def test_retracted_rejects_invalid_reviewer_id(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.build_claim(
                claim_text="c", source_url="https://x.example/y",
                status="RETRACTED", reviewer_id="INVALID ID",
                reviewer_display_name=REVIEWER_NAME,
                review_timestamp_utc=UTC2, notes="n",
            )

    def test_unverified_claims_block_approval(self):
        claim = prov.build_claim(claim_text="c", source_url="https://x.example/y")
        manifest = self.simple_manifest([claim])
        with self.assertRaises(prov.ProvenanceError):
            prov.transition_review_status(manifest, "APPROVED")

    def test_retracted_claims_block_approval(self):
        claim = prov.build_claim(
            claim_text="c", source_url="https://x.example/y", status="RETRACTED",
            reviewer_id=REVIEWER_ID, reviewer_display_name=REVIEWER_NAME,
            review_timestamp_utc=UTC2, notes="bad source",
        )
        manifest = self.simple_manifest([claim])
        with self.assertRaises(prov.ProvenanceError):
            prov.transition_review_status(manifest, "APPROVED")

    def test_verified_claims_allow_approval(self):
        claim = prov.build_claim(
            claim_text="c", source_url="https://x.example/y", status="VERIFIED",
            reviewer="rick", review_date=UTC2,
        )
        manifest = self.simple_manifest([claim])
        prov.transition_review_status(manifest, "APPROVED")
        self.assertEqual(manifest["task"]["review_status"], "APPROVED")


# ---------------------------------------------------------------------------
# Manifest history snapshots
# ---------------------------------------------------------------------------


class TestManifestHistory(_TaskDirBase):
    def test_snapshot_and_list_roundtrip(self):
        manifest = self.simple_manifest()
        path = ri.snapshot_manifest(self.task_dir, manifest)
        self.assertTrue(os.path.isfile(path))
        name = os.path.basename(path)
        self.assertRegex(name, r"^000001_[0-9a-f]{64}\.json$")
        snapshots = ri.list_manifest_history(self.task_dir)
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0]["task"]["task_id"], "task-001")

    def test_snapshot_never_overwrites(self):
        manifest = self.simple_manifest()
        ri.snapshot_manifest(self.task_dir, manifest)
        # Same manifest again -> new sequence number, no overwrite.
        path2 = ri.snapshot_manifest(self.task_dir, manifest)
        self.assertTrue(os.path.basename(path2).startswith("000002_"))
        self.assertEqual(len(ri.list_manifest_history(self.task_dir)), 2)

    def test_modified_snapshot_detected(self):
        manifest = self.simple_manifest()
        path = ri.snapshot_manifest(self.task_dir, manifest)
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        data["task"]["topic"] = "tampered"
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.list_manifest_history(self.task_dir)


# ---------------------------------------------------------------------------
# Review events
# ---------------------------------------------------------------------------


class TestReviewEvents(_TaskDirBase):
    def _event(self, **overrides):
        kwargs = dict(
            event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC,
            manifest_hash_before=HASH_A,
            manifest_hash_after=HASH_B,
        )
        kwargs.update(overrides)
        return ri.create_review_event(self.task_dir, **kwargs)

    def test_create_and_validate_chain(self):
        event = self._event()
        self.assertEqual(event["sequence"], 1)
        self.assertEqual(event["previous_event_hash"], "0" * 64)
        self.assertRegex(event["event_hash"], r"^[0-9a-f]{64}$")
        events = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_id"], event["event_id"])

    def test_chain_links_sequentially(self):
        e1 = self._event()
        e2 = self._event(timestamp_utc=UTC2)
        e3 = self._event(timestamp_utc=UTC3)
        self.assertEqual(e2["previous_event_hash"], e1["event_hash"])
        self.assertEqual(e3["previous_event_hash"], e2["event_hash"])
        self.assertEqual([e["sequence"] for e in
                          ri.validate_review_event_chain(self.task_dir)], [1, 2, 3])
        self.assertEqual(ri.review_chain_head_hash(self.task_dir), e3["event_hash"])

    def test_reason_required_event_types(self):
        for etype in ("CLAIM_RETRACTED", "CLAIM_SUPERSEDED", "LOCK_RECOVERED"):
            with self.assertRaises(ri.ReviewIntegrityError, msg=etype):
                self._event(event_type=etype, reason=None)
            with self.assertRaises(ri.ReviewIntegrityError, msg=etype + " blank"):
                self._event(event_type=etype, reason="   ")

    def test_unknown_event_type_rejected(self):
        with self.assertRaises(ri.ReviewIntegrityError):
            self._event(event_type="PUBLISHED")

    def test_invalid_reviewer_rejected(self):
        with self.assertRaises(ri.ReviewIntegrityError):
            self._event(reviewer_id="BAD ID")

    def test_invalid_hash_fields_rejected(self):
        with self.assertRaises(ri.ReviewIntegrityError):
            self._event(manifest_hash_before="not-a-hash")

    def test_missing_event_detected(self):
        e1 = self._event()
        self._event(timestamp_utc=UTC2)
        # Remove the FIRST event, leaving a sequence gap (000002 without 000001).
        os.unlink(os.path.join(self.task_dir, "review-events",
                               f"000001_{e1['event_id']}.json"))
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.validate_review_event_chain(self.task_dir)

    def test_missing_final_event_detected(self):
        self._event()
        e2 = self._event(timestamp_utc=UTC2)
        # Delete the TAIL event. The checkpoint still points at it, so
        # validation must fail closed even though the sequence is contiguous.
        os.unlink(os.path.join(self.task_dir, "review-events",
                               f"000002_{e2['event_id']}.json"))
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.validate_review_event_chain(self.task_dir)

    def test_reordered_event_detected(self):
        self._event()
        e2 = self._event(timestamp_utc=UTC2)
        path = os.path.join(self.task_dir, "review-events",
                            f"000002_{e2['event_id']}.json")
        data = json.loads(open(path, encoding="utf-8").read())
        data["sequence"] = 99
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.validate_review_event_chain(self.task_dir)

    def test_duplicate_event_id_detected(self):
        e1 = self._event()
        e2 = self._event(timestamp_utc=UTC2)
        path2 = os.path.join(self.task_dir, "review-events",
                             f"000002_{e2['event_id']}.json")
        data = json.loads(open(path2, encoding="utf-8").read())
        data["event_id"] = e1["event_id"]  # duplicate id
        with open(path2, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.validate_review_event_chain(self.task_dir)

    def test_altered_content_detected(self):
        e1 = self._event()
        path = os.path.join(self.task_dir, "review-events",
                            f"000001_{e1['event_id']}.json")
        data = json.loads(open(path, encoding="utf-8").read())
        data["reviewer_display_name"] = "Mallory"
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.validate_review_event_chain(self.task_dir)

    def test_broken_previous_hash_detected(self):
        self._event()
        e2 = self._event(timestamp_utc=UTC2)
        path = os.path.join(self.task_dir, "review-events",
                            f"000002_{e2['event_id']}.json")
        data = json.loads(open(path, encoding="utf-8").read())
        data["previous_event_hash"] = "f" * 64
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.validate_review_event_chain(self.task_dir)

    def test_unexpected_files_ignored_by_sequence_scan(self):
        self._event()
        # Non-matching files do not corrupt the chain.
        with open(os.path.join(self.task_dir, "review-events", "notes.txt"), "w") as h:
            h.write("scratch")
        events = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(events), 1)

    def test_malformed_event_json_detected(self):
        self._event()
        events_dir = os.path.join(self.task_dir, "review-events")
        with open(os.path.join(events_dir, "000002_bad.json"), "w") as h:
            h.write("{not json")
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.validate_review_event_chain(self.task_dir)

    def test_event_file_never_overwritten(self):
        e1 = self._event()
        path = os.path.join(self.task_dir, "review-events",
                            f"000001_{e1['event_id']}.json")
        with self.assertRaises(ri.ReviewIntegrityError):
            ri._atomic_create_exclusive(path, b"{}")


# ---------------------------------------------------------------------------
# Receipts
# ---------------------------------------------------------------------------


class TestReceipts(_TaskDirBase):
    def _approval(self, **overrides):
        kwargs = dict(
            receipt_type="APPROVAL",
            task_id="task-001",
            manifest_version="1.1.0",
            manifest_relative_path="provenance_manifest.json",
            manifest_sha256=HASH_A,
            audit_head_hash=HASH_B,
            created_at_utc=UTC,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
        )
        kwargs.update(overrides)
        return ri.create_receipt(self.task_dir, **kwargs)

    def test_approval_receipt_fields(self):
        receipt = self._approval()
        self.assertEqual(receipt["receipt_type"], "APPROVAL")
        self.assertEqual(receipt["effective_status"], "APPROVED")
        self.assertEqual(receipt["sequence"], 1)
        self.assertEqual(receipt["previous_receipt_hash"], "0" * 64)
        self.assertRegex(receipt["receipt_hash"], r"^[0-9a-f]{64}$")
        self.assertNotIn("approval_receipt_id", receipt)

    def test_approval_rejects_revocation_fields(self):
        with self.assertRaises(ri.ReviewIntegrityError):
            self._approval(approval_receipt_id="x", approval_receipt_hash=HASH_C)

    def test_revocation_links_to_approval(self):
        approval = self._approval()
        revocation = ri.create_receipt(
            self.task_dir,
            receipt_type="REVOCATION",
            task_id="task-001",
            manifest_version="1.1.0",
            manifest_relative_path="provenance_manifest.json",
            manifest_sha256=HASH_A,
            audit_head_hash=HASH_B,
            created_at_utc=UTC2,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            approval_receipt_id=approval["receipt_id"],
            approval_receipt_hash=approval["receipt_hash"],
            reason="source material withdrawn",
        )
        self.assertEqual(revocation["effective_status"], "REVOKED")
        self.assertEqual(revocation["approval_receipt_id"], approval["receipt_id"])
        self.assertEqual(revocation["previous_receipt_hash"], approval["receipt_hash"])
        receipts = ri.validate_receipt_chain(self.task_dir)
        self.assertEqual([r["receipt_type"] for r in receipts],
                         ["APPROVAL", "REVOCATION"])

    def test_revocation_requires_reason(self):
        approval = self._approval()
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.create_receipt(
                self.task_dir, receipt_type="REVOCATION", task_id="task-001",
                manifest_version="1.1.0",
                manifest_relative_path="provenance_manifest.json",
                manifest_sha256=HASH_A, audit_head_hash=HASH_B,
                created_at_utc=UTC2, reviewer_id=REVIEWER_ID,
                reviewer_display_name=REVIEWER_NAME,
                approval_receipt_id=approval["receipt_id"],
                approval_receipt_hash=approval["receipt_hash"],
                reason="",
            )

    def test_revocation_unknown_approval_rejected(self):
        self._approval()
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.create_receipt(
                self.task_dir, receipt_type="REVOCATION", task_id="task-001",
                manifest_version="1.1.0",
                manifest_relative_path="provenance_manifest.json",
                manifest_sha256=HASH_A, audit_head_hash=HASH_B,
                created_at_utc=UTC2, reviewer_id=REVIEWER_ID,
                reviewer_display_name=REVIEWER_NAME,
                approval_receipt_id="nonexistent",
                approval_receipt_hash=HASH_C, reason="r",
            )

    def test_revocation_hash_mismatch_rejected(self):
        approval = self._approval()
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.create_receipt(
                self.task_dir, receipt_type="REVOCATION", task_id="task-001",
                manifest_version="1.1.0",
                manifest_relative_path="provenance_manifest.json",
                manifest_sha256=HASH_A, audit_head_hash=HASH_B,
                created_at_utc=UTC2, reviewer_id=REVIEWER_ID,
                reviewer_display_name=REVIEWER_NAME,
                approval_receipt_id=approval["receipt_id"],
                approval_receipt_hash=HASH_C,  # wrong hash
                reason="r",
            )

    def test_double_revocation_rejected(self):
        approval = self._approval()
        kwargs = dict(
            receipt_type="REVOCATION", task_id="task-001",
            manifest_version="1.1.0",
            manifest_relative_path="provenance_manifest.json",
            manifest_sha256=HASH_A, audit_head_hash=HASH_B,
            reviewer_id=REVIEWER_ID, reviewer_display_name=REVIEWER_NAME,
            approval_receipt_id=approval["receipt_id"],
            approval_receipt_hash=approval["receipt_hash"], reason="r",
        )
        ri.create_receipt(self.task_dir, created_at_utc=UTC2, **kwargs)
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.create_receipt(self.task_dir, created_at_utc=UTC3, **kwargs)

    def test_receipt_chain_detects_modification(self):
        approval = self._approval()
        path = os.path.join(self.task_dir, "approvals",
                            f"000001_{approval['receipt_id']}.json")
        data = json.loads(open(path, encoding="utf-8").read())
        data["task_id"] = "task-999"
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.validate_receipt_chain(self.task_dir)

    def test_receipt_file_never_overwritten(self):
        approval = self._approval()
        path = os.path.join(self.task_dir, "approvals",
                            f"000001_{approval['receipt_id']}.json")
        with self.assertRaises(ri.ReviewIntegrityError):
            ri._atomic_create_exclusive(path, b"{}")

    def test_receipt_rejects_bad_hashes_and_paths(self):
        with self.assertRaises(ri.ReviewIntegrityError):
            self._approval(manifest_sha256="nope")
        with self.assertRaises(ri.ReviewIntegrityError):
            self._approval(audit_head_hash="nope")
        with self.assertRaises(ri.ReviewIntegrityError):
            self._approval(manifest_relative_path="..\\evil.json")
        with self.assertRaises(ri.ReviewIntegrityError):
            self._approval(manifest_relative_path="C:\\abs\\evil.json")


# ---------------------------------------------------------------------------
# Path confinement
# ---------------------------------------------------------------------------


class TestPathConfinement(_TaskDirBase):
    def test_traversal_rejected(self):
        with self.assertRaises(ri.ReviewIntegrityError):
            ri._confined_file_path(self.task_dir, "review-events", "..\\evil.json")

    def test_nested_traversal_rejected(self):
        with self.assertRaises(ri.ReviewIntegrityError):
            ri._confined_file_path(
                self.task_dir, "review-events", "sub/../../evil.json"
            )

    def test_missing_task_dir_rejected(self):
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.create_review_event(
                os.path.join(self.task_dir, "nope"),
                event_type="CLAIM_VERIFIED",
                reviewer_id=REVIEWER_ID, reviewer_display_name=REVIEWER_NAME,
                timestamp_utc=UTC,
            )

    def test_symlink_escape_rejected_where_testable(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        outside = tempfile.mkdtemp()
        self.addCleanup(lambda: os.path.isdir(outside) and os.rmdir(outside))
        link = os.path.join(self.task_dir, "link-escape")
        try:
            os.symlink(outside, link, target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation not permitted")
        with self.assertRaises(ri.ReviewIntegrityError):
            ri._sub_dir(link, "review-events")


# ---------------------------------------------------------------------------
# Exclusive review lock
# ---------------------------------------------------------------------------


class TestReviewLock(_TaskDirBase):
    def _acquire(self, **overrides):
        kwargs = dict(
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            created_at_utc=UTC,
        )
        kwargs.update(overrides)
        return ri.acquire_review_lock(self.task_dir, **kwargs)

    def test_acquire_and_release(self):
        lock = self._acquire()
        self.assertRegex(lock["lock_token"], r"^[0-9a-f]{32}$")
        self.assertEqual(lock["process_id"], os.getpid())
        self.assertTrue(lock["hostname"])
        ri.release_review_lock(self.task_dir, lock_token=lock["lock_token"])
        self.assertIsNone(ri.read_review_lock(self.task_dir))

    def test_contention_fails_closed(self):
        self._acquire()
        with self.assertRaises(ri.ReviewIntegrityError):
            self._acquire(reviewer_id="other.reviewer")

    def test_release_requires_matching_token(self):
        self._acquire()
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.release_review_lock(self.task_dir, lock_token="wrong-token")
        # Original lock still held.
        self.assertIsNotNone(ri.read_review_lock(self.task_dir))

    def test_release_without_lock_fails(self):
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.release_review_lock(self.task_dir, lock_token="x" * 32)

    def test_malformed_lock_fails_closed_on_acquire(self):
        with open(os.path.join(self.task_dir, "review.lock"), "w") as h:
            h.write("{corrupt")
        with self.assertRaises(ri.ReviewIntegrityError):
            self._acquire()

    def test_malformed_lock_fails_closed_on_release(self):
        with open(os.path.join(self.task_dir, "review.lock"), "w") as h:
            h.write("{corrupt")
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.release_review_lock(self.task_dir, lock_token="x" * 32)

    def test_no_age_based_recovery(self):
        lock = self._acquire(created_at_utc="2020-01-01T00:00:00Z")
        # Even a very old lock still blocks acquisition.
        with self.assertRaises(ri.ReviewIntegrityError):
            self._acquire(reviewer_id="other.reviewer")
        ri.release_review_lock(self.task_dir, lock_token=lock["lock_token"])

    def test_recovery_requires_reason_and_identity(self):
        self._acquire()
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.recover_review_lock(
                self.task_dir, reviewer_id=REVIEWER_ID,
                reviewer_display_name=REVIEWER_NAME, reason="", timestamp_utc=UTC2,
            )
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.recover_review_lock(
                self.task_dir, reviewer_id="BAD ID",
                reviewer_display_name=REVIEWER_NAME, reason="r", timestamp_utc=UTC2,
            )

    def test_recovery_removes_lock_and_records_event(self):
        lock = self._acquire()
        result = ri.recover_review_lock(
            self.task_dir, reviewer_id="admin.reviewer",
            reviewer_display_name="Admin Reviewer",
            reason="holder process crashed", timestamp_utc=UTC2,
        )
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertEqual(result["recovered_lock"]["lock_token"], lock["lock_token"])
        self.assertFalse(result["audit_event"]["details"]["lock_was_malformed"])
        events = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "LOCK_RECOVERED")
        self.assertEqual(events[0]["reason"], "holder process crashed")
        self.assertEqual(events[0]["reviewer_id"], "admin.reviewer")

    def test_recovery_of_malformed_lock_records_malformed_flag(self):
        with open(os.path.join(self.task_dir, "review.lock"), "w") as h:
            h.write("{corrupt")
        result = ri.recover_review_lock(
            self.task_dir, reviewer_id="admin.reviewer",
            reviewer_display_name="Admin Reviewer",
            reason="lock file corrupted", timestamp_utc=UTC2,
        )
        self.assertIsNone(ri.read_review_lock(self.task_dir))
        self.assertIsNone(result["recovered_lock"])
        self.assertTrue(result["audit_event"]["details"]["lock_was_malformed"])
        events = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(events[0]["event_type"], "LOCK_RECOVERED")

    def test_recovery_without_lock_still_records_event(self):
        result = ri.recover_review_lock(
            self.task_dir, reviewer_id="admin.reviewer",
            reviewer_display_name="Admin Reviewer",
            reason="confirming clean state", timestamp_utc=UTC2,
        )
        self.assertIsNone(result["recovered_lock"])
        self.assertEqual(
            ri.validate_review_event_chain(self.task_dir)[0]["event_type"],
            "LOCK_RECOVERED",
        )


# ---------------------------------------------------------------------------
# Chain-head checkpoints
# ---------------------------------------------------------------------------


class TestChainHeadCheckpoint(_TaskDirBase):
    def _event(self, **overrides):
        kwargs = dict(
            event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC,
            manifest_hash_before=HASH_A,
            manifest_hash_after=HASH_B,
        )
        kwargs.update(overrides)
        return ri.create_review_event(self.task_dir, **kwargs)

    def _approval(self, **overrides):
        kwargs = dict(
            receipt_type="APPROVAL",
            task_id="task-001",
            manifest_version="1.1.0",
            manifest_relative_path="provenance_manifest.json",
            manifest_sha256=HASH_A,
            audit_head_hash=HASH_B,
            created_at_utc=UTC,
            reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
        )
        kwargs.update(overrides)
        return ri.create_receipt(self.task_dir, **kwargs)

    def _events_dir(self):
        return os.path.join(self.task_dir, "review-events")

    def _approvals_dir(self):
        return os.path.join(self.task_dir, "approvals")

    def _checkpoint_path(self, chain_dir):
        return os.path.join(chain_dir, "chain-head.json")

    # -- checkpoint structure ------------------------------------------------

    def test_checkpoint_created_and_canonical(self):
        event = self._event()
        cp = json.loads(open(self._checkpoint_path(self._events_dir()),
                             encoding="utf-8").read())
        for field in ("schema_version", "chain_type", "last_sequence",
                      "last_record_id", "last_record_hash", "checkpoint_hash"):
            self.assertIn(field, cp)
        self.assertEqual(cp["chain_type"], "review-events")
        self.assertEqual(cp["last_sequence"], 1)
        self.assertEqual(cp["last_record_id"], event["event_id"])
        self.assertEqual(cp["last_record_hash"], event["event_hash"])
        # checkpoint_hash is canonical over the unsigned fields.
        unsigned = {k: v for k, v in cp.items() if k != "checkpoint_hash"}
        self.assertEqual(cp["checkpoint_hash"], prov.canonical_sha256(unsigned))

    def test_checkpoint_advances_with_each_append(self):
        e1 = self._event()
        e2 = self._event(timestamp_utc=UTC2)
        cp = json.loads(open(self._checkpoint_path(self._events_dir()),
                             encoding="utf-8").read())
        self.assertEqual(cp["last_sequence"], 2)
        self.assertEqual(cp["last_record_id"], e2["event_id"])

    def test_empty_chain_has_no_checkpoint(self):
        # Chosen rule: an empty chain has NO checkpoint file.
        self.assertEqual(ri.validate_review_event_chain(self.task_dir), [])
        self.assertFalse(os.path.exists(self._checkpoint_path(self._events_dir())))

    # -- event-chain checkpoint defects --------------------------------------

    def test_deleted_checkpoint_detected(self):
        self._event()
        os.unlink(self._checkpoint_path(self._events_dir()))
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.validate_review_event_chain(self.task_dir)

    def test_malformed_checkpoint_detected(self):
        self._event()
        with open(self._checkpoint_path(self._events_dir()), "w") as h:
            h.write("{corrupt")
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.validate_review_event_chain(self.task_dir)

    def test_modified_checkpoint_detected(self):
        self._event()
        path = self._checkpoint_path(self._events_dir())
        cp = json.loads(open(path, encoding="utf-8").read())
        cp["last_sequence"] = 99
        with open(path, "w", encoding="utf-8") as h:
            json.dump(cp, h)
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.validate_review_event_chain(self.task_dir)

    def test_checkpoint_pointing_to_earlier_record_detected(self):
        e1 = self._event()
        self._event(timestamp_utc=UTC2)
        # Rewrite the checkpoint to point back at e1 (roll back the head).
        path = self._checkpoint_path(self._events_dir())
        rolled = ri._build_checkpoint(
            chain_type="review-events", sequence=1,
            record_id=e1["event_id"], record_hash=e1["event_hash"],
        )
        with open(path, "w", encoding="utf-8") as h:
            h.write(json.dumps(rolled))
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.validate_review_event_chain(self.task_dir)

    def test_extra_record_beyond_checkpoint_detected(self):
        e1 = self._event()
        # Manually add a second event file WITHOUT updating the checkpoint.
        e2 = {
            "schema_version": "1.1.0", "sequence": 2, "event_id": "f" * 32,
            "event_type": "CLAIM_VERIFIED", "timestamp_utc": UTC2,
            "reviewer_id": REVIEWER_ID, "reviewer_display_name": REVIEWER_NAME,
            "reason": None, "previous_event_hash": e1["event_hash"],
            "manifest_hash_before": HASH_A, "manifest_hash_after": HASH_B,
            "details": None,
        }
        e2["event_hash"] = prov.canonical_sha256(
            {k: v for k, v in e2.items() if k != "event_hash"}
        )
        path = os.path.join(self._events_dir(), f"000002_{e2['event_id']}.json")
        with open(path, "w", encoding="utf-8") as h:
            h.write(prov.canonical_json_bytes(e2).decode("utf-8") + "\n")
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.validate_review_event_chain(self.task_dir)

    # -- receipt-chain checkpoint defects ------------------------------------

    def test_receipt_checkpoint_created(self):
        receipt = self._approval()
        cp = json.loads(open(self._checkpoint_path(self._approvals_dir()),
                             encoding="utf-8").read())
        self.assertEqual(cp["chain_type"], "approvals")
        self.assertEqual(cp["last_record_id"], receipt["receipt_id"])
        self.assertEqual(cp["last_record_hash"], receipt["receipt_hash"])

    def test_deleted_final_receipt_detected(self):
        self._approval()
        r2 = self._approval(created_at_utc=UTC2)
        os.unlink(os.path.join(self._approvals_dir(),
                               f"000002_{r2['receipt_id']}.json"))
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.validate_receipt_chain(self.task_dir)

    def test_deleted_receipt_checkpoint_detected(self):
        self._approval()
        os.unlink(self._checkpoint_path(self._approvals_dir()))
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.validate_receipt_chain(self.task_dir)

    def test_modified_receipt_checkpoint_detected(self):
        self._approval()
        path = self._checkpoint_path(self._approvals_dir())
        cp = json.loads(open(path, encoding="utf-8").read())
        cp["last_record_hash"] = "0" * 64
        with open(path, "w", encoding="utf-8") as h:
            json.dump(cp, h)
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.validate_receipt_chain(self.task_dir)

    # -- crash recovery: uncommitted tail ------------------------------------

    def test_crash_after_record_before_checkpoint_fails_closed(self):
        self._event()
        # Simulate a crash: create event 2's file but never update checkpoint.
        original_write_cp = ri._write_checkpoint_atomic
        ri._write_checkpoint_atomic = lambda *a, **k: (_ for _ in ()).throw(
            OSError("simulated crash before checkpoint")
        )
        try:
            with self.assertRaises(OSError):
                self._event(timestamp_utc=UTC2)
        finally:
            ri._write_checkpoint_atomic = original_write_cp
        # The uncommitted tail record exists on disk.
        tail = ri.find_uncommitted_tail(self.task_dir, "review-events")
        self.assertEqual(len(tail), 1)
        self.assertEqual(tail[0][0], 2)
        # Validation fails closed: record exists beyond the checkpoint.
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.validate_review_event_chain(self.task_dir)

    def test_explicit_recovery_of_uncommitted_event_tail(self):
        self._event()
        original_write_cp = ri._write_checkpoint_atomic
        ri._write_checkpoint_atomic = lambda *a, **k: (_ for _ in ()).throw(
            OSError("crash")
        )
        try:
            with self.assertRaises(OSError):
                self._event(timestamp_utc=UTC2)
        finally:
            ri._write_checkpoint_atomic = original_write_cp
        # Explicit recovery discards the uncommitted tail.
        result = ri.discard_uncommitted_tail(
            self.task_dir, chain_type="review-events",
            reviewer_id="admin.reviewer", reviewer_display_name="Admin",
            reason="interrupted append", timestamp_utc=UTC3,
        )
        self.assertEqual(len(result["discarded"]), 1)
        # Chain is valid again and back to one committed event.
        events = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(events), 1)
        self.assertEqual(ri.find_uncommitted_tail(self.task_dir, "review-events"),
                         [])

    def test_explicit_recovery_of_uncommitted_receipt_tail(self):
        self._approval()
        original_write_cp = ri._write_checkpoint_atomic
        ri._write_checkpoint_atomic = lambda *a, **k: (_ for _ in ()).throw(
            OSError("crash")
        )
        try:
            with self.assertRaises(OSError):
                self._approval(created_at_utc=UTC2)
        finally:
            ri._write_checkpoint_atomic = original_write_cp
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.validate_receipt_chain(self.task_dir)
        result = ri.discard_uncommitted_tail(
            self.task_dir, chain_type="approvals",
            reviewer_id="admin.reviewer", reviewer_display_name="Admin",
            reason="interrupted receipt append", timestamp_utc=UTC3,
        )
        self.assertEqual(len(result["discarded"]), 1)
        # Receipt chain valid again; recovery left an audit event.
        self.assertEqual(len(ri.validate_receipt_chain(self.task_dir)), 1)
        self.assertIsNotNone(result["audit_event"])
        events = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(events[-1]["event_type"], "LOCK_RECOVERED")

    def test_recovery_requires_reason(self):
        self._event()
        original_write_cp = ri._write_checkpoint_atomic
        ri._write_checkpoint_atomic = lambda *a, **k: (_ for _ in ()).throw(
            OSError("crash")
        )
        try:
            with self.assertRaises(OSError):
                self._event(timestamp_utc=UTC2)
        finally:
            ri._write_checkpoint_atomic = original_write_cp
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.discard_uncommitted_tail(
                self.task_dir, chain_type="review-events",
                reviewer_id="admin.reviewer", reviewer_display_name="Admin",
                reason="", timestamp_utc=UTC3,
            )

    def test_recovery_without_tail_fails(self):
        self._event()
        with self.assertRaises(ri.ReviewIntegrityError):
            ri.discard_uncommitted_tail(
                self.task_dir, chain_type="review-events",
                reviewer_id="admin.reviewer", reviewer_display_name="Admin",
                reason="nothing to do", timestamp_utc=UTC3,
            )


# ---------------------------------------------------------------------------
# Atomic creation and temp-file cleanup after injected failures
# ---------------------------------------------------------------------------


class TestAtomicBehavior(_TaskDirBase):
    def test_temp_files_cleaned_on_write_failure(self):
        original_link = os.link

        def boom(*args, **kwargs):
            raise OSError("simulated link failure")

        ri.os.link = boom
        # Force fallback path to also fail by blocking O_EXCL create.
        original_open = os.open

        def open_boom(path, flags, *args, **kwargs):
            if flags & os.O_EXCL:
                raise OSError("simulated exclusive-create failure")
            return original_open(path, flags, *args, **kwargs)

        ri.os.open = open_boom
        try:
            with self.assertRaises(OSError):
                ri.create_review_event(
                    self.task_dir, event_type="CLAIM_VERIFIED",
                    reviewer_id=REVIEWER_ID, reviewer_display_name=REVIEWER_NAME,
                    timestamp_utc=UTC,
                )
        finally:
            ri.os.link = original_link
            ri.os.open = original_open
        events_dir = os.path.join(self.task_dir, "review-events")
        leftovers = [f for f in os.listdir(events_dir) if "tmp" in f or "part" in f]
        self.assertEqual(leftovers, [])
        # Chain remains valid (empty) — last valid state preserved.
        self.assertEqual(ri.validate_review_event_chain(self.task_dir), [])

    def test_failed_append_preserves_existing_chain(self):
        e1 = ri.create_review_event(
            self.task_dir, event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID, reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC,
        )
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
                ri.create_review_event(
                    self.task_dir, event_type="CLAIM_VERIFIED",
                    reviewer_id=REVIEWER_ID, reviewer_display_name=REVIEWER_NAME,
                    timestamp_utc=UTC2,
                )
        finally:
            ri.os.link = original_link
            ri.os.open = original_open
        events = ri.validate_review_event_chain(self.task_dir)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_id"], e1["event_id"])


if __name__ == "__main__":
    unittest.main()
