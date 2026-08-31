"""
Phase 1B.3A — Offline provenance and human-review manifest foundation.

Fully offline tests (no network calls). Covers:
- deterministic output (byte-identical serialization)
- large-file streaming SHA-256
- path traversal and unsafe absolute paths
- atomic writes and temp-file cleanup
- missing fields and invalid enums
- local / provider / AI-generated asset rules
- claim-review requirements (VERIFIED/RETRACTED need reviewer + date)
- secret redaction/rejection
- NEEDS_HUMAN_REVIEW defaults and __NEEDS_HUMAN_REVIEW filename marker
- approval-state transition rules
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.services import provenance as prov


UTC = "2026-08-30T12:00:00Z"
UTC2 = "2026-08-30T13:00:00Z"
PROMPT_HASH = prov.sha256_text("a sensitive prompt that must never be stored")


class _TaskDirTestBase(unittest.TestCase):
    """Create an isolated task directory per test."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.task_dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def write_file(self, name: str, data: bytes) -> str:
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


# ---------------------------------------------------------------------------
# Streaming SHA-256
# ---------------------------------------------------------------------------


class TestStreamingHash(_TaskDirTestBase):
    def test_streamed_hash_matches_reference(self):
        data = b"provenance" * 1000
        path = self.write_file("a.bin", data)
        self.assertEqual(
            prov.sha256_file_streamed(path), hashlib.sha256(data).hexdigest()
        )

    def test_large_file_streaming_hash(self):
        # ~8 MiB, larger than the 1 MiB chunk size, forces multiple reads.
        block = os.urandom(1024 * 1024)
        path = os.path.join(self.task_dir, "large.bin")
        expected = hashlib.sha256()
        with open(path, "wb") as handle:
            for _ in range(8):
                handle.write(block)
                expected.update(block)
        self.assertEqual(prov.sha256_file_streamed(path), expected.hexdigest())

    def test_hash_missing_file_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.sha256_file_streamed(os.path.join(self.task_dir, "nope.bin"))

    def test_prompt_hash_only(self):
        digest = prov.hash_prompt("super secret prompt")
        self.assertEqual(digest, prov.sha256_text("super secret prompt"))
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        with self.assertRaises(prov.ProvenanceError):
            prov.hash_prompt("")


# ---------------------------------------------------------------------------
# Path confinement
# ---------------------------------------------------------------------------


class TestPathConfinement(_TaskDirTestBase):
    def test_relative_path_inside_task_dir_ok(self):
        self.write_file("asset.mp4", b"x")
        resolved = prov.resolve_task_path(self.task_dir, "asset.mp4")
        self.assertTrue(resolved.startswith(os.path.realpath(self.task_dir)))

    def test_traversal_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.resolve_task_path(self.task_dir, "../outside.txt")

    def test_deep_traversal_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.resolve_task_path(self.task_dir, "sub/../../outside.txt")

    def test_unsafe_absolute_path_rejected(self):
        outside = os.path.join(tempfile.gettempdir(), "outside_abs.txt")
        with open(outside, "wb") as handle:
            handle.write(b"x")
        try:
            with self.assertRaises(prov.ProvenanceError):
                prov.resolve_task_path(self.task_dir, outside)
        finally:
            os.unlink(outside)

    def test_absolute_path_inside_task_dir_ok(self):
        path = self.write_file("inside.txt", b"x")
        resolved = prov.resolve_task_path(self.task_dir, path)
        self.assertEqual(resolved, os.path.realpath(path))

    def test_empty_path_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.resolve_task_path(self.task_dir, "")

    def test_missing_path_rejected_when_required(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.resolve_task_path(self.task_dir, "missing.txt")


# ---------------------------------------------------------------------------
# Task section + defaults
# ---------------------------------------------------------------------------


class TestTaskSection(_TaskDirTestBase):
    def test_defaults_to_needs_human_review(self):
        task = self.task_section()
        self.assertEqual(task["review_status"], "NEEDS_HUMAN_REVIEW")
        self.assertEqual(task["schema_version"], prov.SCHEMA_VERSION)

    def test_missing_required_field_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.build_task_section(
                task_id="", topic="t", pilot_profile="p", created_at=UTC
            )

    def test_invalid_review_status_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            self.task_section(review_status="PUBLISHED")

    def test_naive_timestamp_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            self.task_section(created_at="2026-08-30 12:00:00")

    def test_bad_timestamp_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            self.task_section(created_at="not-a-date")


# ---------------------------------------------------------------------------
# Asset rules
# ---------------------------------------------------------------------------


class TestAssetRules(_TaskDirTestBase):
    def _base(self, **overrides):
        self.write_file("asset.mp4", b"video-bytes")
        kwargs = dict(
            asset_type="video",
            source_type="local",
            local_path="asset.mp4",
            license_name="CC0",
            license_evidence="https://creativecommons.org/publicdomain/zero/1.0/",
        )
        kwargs.update(overrides)
        return kwargs

    def test_local_asset_without_source_url_ok(self):
        asset = prov.build_asset(self.task_dir, **self._base())
        self.assertIsNone(asset["source_url"])
        self.assertEqual(asset["source_type"], "local")
        self.assertRegex(asset["sha256"], r"^[0-9a-f]{64}$")

    def test_local_asset_requires_license_evidence(self):
        kwargs = self._base(license_evidence="")
        with self.assertRaises(prov.ProvenanceError):
            prov.build_asset(self.task_dir, **kwargs)

    def test_provider_asset_requires_all_fields(self):
        base = self._base(source_type="provider")
        for field in ("source_url", "provider", "provider_asset_id", "retrieval_date"):
            kwargs = dict(base)
            kwargs.update(
                source_url="https://provider.example/asset/1",
                provider="pexels",
                provider_asset_id="12345",
                retrieval_date=UTC,
            )
            kwargs[field] = None
            with self.assertRaises(prov.ProvenanceError, msg=field):
                prov.build_asset(self.task_dir, **kwargs)

    def test_provider_asset_complete_ok(self):
        asset = prov.build_asset(
            self.task_dir,
            **self._base(
                source_type="provider",
                source_url="https://provider.example/asset/1",
                provider="pexels",
                provider_asset_id="12345",
                retrieval_date=UTC,
            ),
        )
        self.assertEqual(asset["provider"], "pexels")

    def test_ai_generated_asset_requires_provider(self):
        kwargs = self._base(source_type="ai_generated")
        with self.assertRaises(prov.ProvenanceError):
            prov.build_asset(self.task_dir, **kwargs)
        asset = prov.build_asset(
            self.task_dir, **self._base(source_type="ai_generated", provider="openai")
        )
        self.assertEqual(asset["provider"], "openai")

    def test_invalid_asset_type_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.build_asset(self.task_dir, **self._base(asset_type="hologram"))

    def test_invalid_source_type_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.build_asset(self.task_dir, **self._base(source_type="torrent"))

    def test_asset_path_traversal_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.build_asset(self.task_dir, **self._base(local_path="../evil.mp4"))

    def test_secret_in_source_url_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.build_asset(
                self.task_dir,
                **self._base(source_url="https://x.example/?api_key=sk-abcdefghijklmnop1234"),
            )


# ---------------------------------------------------------------------------
# Claim rules
# ---------------------------------------------------------------------------


class TestClaimRules(_TaskDirTestBase):
    def _claim(self, **overrides):
        kwargs = dict(
            claim_text="Bitcoin supply is capped at 21 million.",
            source_url="https://bitcoin.org/bitcoin.pdf",
            retrieval_date=UTC,
        )
        kwargs.update(overrides)
        return kwargs

    def test_default_status_unverified(self):
        claim = prov.build_claim(**self._claim())
        self.assertEqual(claim["status"], "UNVERIFIED")

    def test_verified_requires_reviewer_and_date(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.build_claim(**self._claim(status="VERIFIED"))
        with self.assertRaises(prov.ProvenanceError):
            prov.build_claim(**self._claim(status="VERIFIED", reviewer="rick"))
        claim = prov.build_claim(
            **self._claim(status="VERIFIED", reviewer="rick", review_date=UTC2)
        )
        self.assertEqual(claim["reviewer"], "rick")

    def test_retracted_requires_reviewer_and_date(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.build_claim(**self._claim(status="RETRACTED"))
        claim = prov.build_claim(
            **self._claim(status="RETRACTED", reviewer="rick", review_date=UTC2)
        )
        self.assertEqual(claim["status"], "RETRACTED")

    def test_invalid_status_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.build_claim(**self._claim(status="MAYBE"))


# ---------------------------------------------------------------------------
# AI generation + secret hygiene
# ---------------------------------------------------------------------------


class TestAIGeneration(_TaskDirTestBase):
    def _gen(self, **overrides):
        kwargs = dict(
            provider="openai",
            model="gpt-4o",
            generation_timestamp=UTC,
            output_type="text",
            prompt_hash=PROMPT_HASH,
        )
        kwargs.update(overrides)
        return kwargs

    def test_valid_generation_ok(self):
        gen = prov.build_ai_generation(
            **self._gen(parameters={"temperature": 0.7, "max_tokens": 512})
        )
        self.assertEqual(gen["parameters"]["temperature"], 0.7)

    def test_invalid_prompt_hash_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.build_ai_generation(**self._gen(prompt_hash="not-a-hash"))

    def test_full_prompt_field_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.build_ai_generation(
                **self._gen(parameters={"prompt": "the full sensitive prompt"})
            )

    def test_api_key_field_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.build_ai_generation(
                **self._gen(parameters={"api_key": "sk-abcdefghijklmnop1234"})
            )

    def test_authorization_value_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.build_ai_generation(
                **self._gen(parameters={"note": "Authorization: Bearer abc123"})
            )

    def test_cookie_value_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.build_ai_generation(
                **self._gen(parameters={"headers": "cookie: session=xyz"})
            )

    def test_private_key_value_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.build_ai_generation(
                **self._gen(
                    parameters={"pem": "-----BEGIN PRIVATE KEY----- abc"}
                )
            )

    def test_nested_secret_key_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.build_ai_generation(
                **self._gen(parameters={"auth": {"access_token": "abc"}})
            )

    def test_invalid_output_type_rejected(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.build_ai_generation(**self._gen(output_type="mind-control"))


# ---------------------------------------------------------------------------
# Output section + filename marker
# ---------------------------------------------------------------------------


class TestOutputSection(_TaskDirTestBase):
    def test_marker_inserted_before_extension(self):
        self.write_file("final.mp4", b"out")
        out = prov.build_output_section(self.task_dir, local_path="final.mp4")
        self.assertEqual(out["review_status"], "NEEDS_HUMAN_REVIEW")
        self.assertEqual(
            os.path.basename(out["filename_marker"]),
            "final__NEEDS_HUMAN_REVIEW.mp4",
        )
        self.assertFalse(out["visible_watermark_required"])

    def test_marker_not_duplicated(self):
        name = prov.marked_filename("final__NEEDS_HUMAN_REVIEW.mp4")
        self.assertEqual(name, "final__NEEDS_HUMAN_REVIEW.mp4")

    def test_marker_removed_on_terminal_status(self):
        name = prov.marked_filename("final__NEEDS_HUMAN_REVIEW.mp4", "APPROVED")
        self.assertEqual(name, "final.mp4")

    def test_hash_none_when_output_absent(self):
        out = prov.build_output_section(
            self.task_dir, local_path="planned/final.mp4", compute_hash=False
        )
        self.assertIsNone(out["sha256"])


# ---------------------------------------------------------------------------
# Manifest assembly, deterministic output, atomic write
# ---------------------------------------------------------------------------


class TestManifest(_TaskDirTestBase):
    def _full_manifest(self):
        self.write_file("script.txt", b"script body")
        self.write_file("asset.mp4", b"video-bytes")
        self.write_file("final.mp4", b"out")
        return prov.build_manifest(
            task=self.task_section(),
            script=prov.build_script_section(
                self.task_dir,
                local_path="script.txt",
                generation_source="ai",
                ai_provider="openai",
                ai_model="gpt-4o",
                prompt_hash=PROMPT_HASH,
            ),
            assets=[
                prov.build_asset(
                    self.task_dir,
                    asset_type="video",
                    source_type="local",
                    local_path="asset.mp4",
                    license_name="CC0",
                    license_evidence="https://creativecommons.org/publicdomain/zero/1.0/",
                )
            ],
            factual_claims=[
                prov.build_claim(
                    claim_text="Bitcoin supply is capped at 21 million.",
                    source_url="https://bitcoin.org/bitcoin.pdf",
                    retrieval_date=UTC,
                )
            ],
            ai_generations=[
                prov.build_ai_generation(
                    provider="openai",
                    model="gpt-4o",
                    generation_timestamp=UTC,
                    output_type="script",
                    prompt_hash=PROMPT_HASH,
                    parameters={"temperature": 0.7},
                )
            ],
            output=prov.build_output_section(self.task_dir, local_path="final.mp4"),
        )

    def test_manifest_defaults_to_needs_human_review(self):
        manifest = self._full_manifest()
        self.assertEqual(manifest["task"]["review_status"], "NEEDS_HUMAN_REVIEW")
        self.assertEqual(manifest["output"]["review_status"], "NEEDS_HUMAN_REVIEW")
        self.assertIn("__NEEDS_HUMAN_REVIEW", manifest["output"]["filename_marker"])

    def test_deterministic_serialization(self):
        manifest = self._full_manifest()
        first = prov.manifest_to_json(manifest)
        second = prov.manifest_to_json(json.loads(first))
        self.assertEqual(first, second)
        self.assertTrue(first.endswith("\n"))
        # Stable top-level ordering.
        keys = list(json.loads(first, object_pairs_hook=dict).keys())
        self.assertEqual(
            keys,
            ["task", "script", "assets", "factual_claims", "ai_generations", "output"],
        )

    def test_missing_section_rejected(self):
        manifest = self._full_manifest()
        del manifest["assets"]
        with self.assertRaises(prov.ProvenanceError):
            prov.validate_manifest(manifest)

    def test_atomic_write_and_reload(self):
        manifest = self._full_manifest()
        target = prov.write_manifest_atomic(self.task_dir, manifest)
        self.assertTrue(os.path.isfile(target))
        with open(target, encoding="utf-8") as handle:
            loaded = json.load(handle)
        self.assertEqual(loaded["task"]["task_id"], "task-001")
        # No temp files left behind.
        leftovers = [f for f in os.listdir(self.task_dir) if f.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_temp_file_cleaned_on_failure(self):
        manifest = self._full_manifest()
        original_replace = os.replace

        def boom(*args, **kwargs):
            raise OSError("simulated rename failure")

        prov.os.replace = boom
        try:
            with self.assertRaises(OSError):
                prov.write_manifest_atomic(self.task_dir, manifest)
        finally:
            prov.os.replace = original_replace
        leftovers = [f for f in os.listdir(self.task_dir) if f.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_write_rejects_invalid_manifest(self):
        with self.assertRaises(prov.ProvenanceError):
            prov.write_manifest_atomic(self.task_dir, {"task": {}})

    def test_write_rejects_missing_task_dir(self):
        manifest = self._full_manifest()
        with self.assertRaises(prov.ProvenanceError):
            prov.write_manifest_atomic(
                os.path.join(self.task_dir, "does-not-exist"), manifest
            )


# ---------------------------------------------------------------------------
# Approval-state transitions
# ---------------------------------------------------------------------------


class TestTransitions(_TaskDirTestBase):
    def _manifest(self, claim_status="UNVERIFIED", **claim_kwargs):
        self.write_file("final.mp4", b"out")
        claims = []
        if claim_status is not None:
            claims.append(
                prov.build_claim(
                    claim_text="claim",
                    source_url="https://example.com/src",
                    status=claim_status,
                    retrieval_date=UTC,
                    **claim_kwargs,
                )
            )
        return prov.build_manifest(
            task=self.task_section(),
            factual_claims=claims,
            output=prov.build_output_section(self.task_dir, local_path="final.mp4"),
        )

    def test_approve_with_unverified_claims_rejected(self):
        manifest = self._manifest()
        with self.assertRaises(prov.ProvenanceError):
            prov.transition_review_status(manifest, "APPROVED")

    def test_approve_with_verified_claims_ok(self):
        manifest = self._manifest(
            "VERIFIED", reviewer="rick", review_date=UTC2
        )
        prov.transition_review_status(manifest, "APPROVED")
        self.assertEqual(manifest["task"]["review_status"], "APPROVED")
        self.assertEqual(manifest["output"]["review_status"], "APPROVED")
        self.assertNotIn("__NEEDS_HUMAN_REVIEW", manifest["output"]["filename_marker"])

    def test_reject_ok_and_terminal(self):
        manifest = self._manifest()
        prov.transition_review_status(manifest, "REJECTED")
        with self.assertRaises(prov.ProvenanceError):
            prov.transition_review_status(manifest, "APPROVED")

    def test_approved_is_terminal(self):
        manifest = self._manifest("VERIFIED", reviewer="rick", review_date=UTC2)
        prov.transition_review_status(manifest, "APPROVED")
        with self.assertRaises(prov.ProvenanceError):
            prov.transition_review_status(manifest, "REJECTED")

    def test_invalid_target_status_rejected(self):
        manifest = self._manifest()
        with self.assertRaises(prov.ProvenanceError):
            prov.transition_review_status(manifest, "PUBLISHED")

    def test_noop_transition_rejected(self):
        manifest = self._manifest()
        with self.assertRaises(prov.ProvenanceError):
            prov.transition_review_status(manifest, "NEEDS_HUMAN_REVIEW")


if __name__ == "__main__":
    unittest.main()
