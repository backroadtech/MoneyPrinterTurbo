"""
Phase 1B.3C.2B.1 — Read-only human-review CLI (pilot_review.py).

Fully offline tests (zero network access). Covers:
- pilot-policy gate (inactive profile, missing/malformed/unsafe policy)
- status command on a valid draft (exit 0, readiness BLOCKED)
- approval-ready and blocked drafts
- UNVERIFIED / RETRACTED claim blocking
- incomplete asset provenance
- changed script / asset / output detection
- valid approval receipt -> APPROVED
- valid revocation receipt -> REVOKED
- manifest APPROVED without receipt -> INVALID
- broken event chain, deleted final event
- broken receipt chain, deleted final receipt
- missing / modified checkpoint
- uncommitted tails
- malformed and existing locks
- unsupported schema
- traversal / unsafe paths
- output sanitization (no query strings, no full claim text, no secrets)
- read-only guarantee (byte-for-byte task-dir snapshot before/after)
- correct exit codes
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

import pilot_review
from app.services import provenance as prov
from app.services import review_integrity as ri
from app.services.pilot_policy import reset_pilot_policy_cache


UTC = "2026-08-30T12:00:00Z"
UTC2 = "2026-08-30T13:00:00Z"
REVIEWER_ID = "rick.gamboa"
REVIEWER_NAME = "Rick Gamboa"
HASH_B = "b" * 64

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


def _blocked_socket(*args, **kwargs):
    raise AssertionError("network access is forbidden in Phase 1B.3C.2B.1 tests")


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


def _PatchedPath(root: str):
    real_path = Path

    class _Factory:
        def __call__(self, *args):
            if args and str(args[0]).endswith("pilot_policy.py"):
                return real_path(root) / "app" / "services" / "pilot_policy.py"
            return real_path(*args)

    return _Factory()


def _snapshot_tree(root: str) -> dict:
    """Map relative path -> sha256 for every file under root (read-only check)."""
    snapshot = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            with open(full, "rb") as handle:
                snapshot[rel] = hashlib.sha256(handle.read()).hexdigest()
    return snapshot


class _ReviewTestBase(unittest.TestCase):
    """Sandboxed project root with a valid hardening.toml and a task dir."""

    def setUp(self):
        self._net = _NetworkBlocker()
        self._net.__enter__()

        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        (Path(self.root) / "hardening.toml").write_text(
            VALID_POLICY, encoding="utf-8"
        )
        self.task_dir = os.path.join(self.root, "task-001")
        os.makedirs(self.task_dir)

        self._env = patch.dict(
            os.environ, {"MPT_PILOT_PROFILE": "braintrustcrypto"}
        )
        self._env.start()
        reset_pilot_policy_cache()
        self._root_patch = patch(
            "app.services.pilot_policy.Path", _PatchedPath(self.root)
        )
        self._root_patch.start()

    def tearDown(self):
        self._root_patch.stop()
        self._env.stop()
        reset_pilot_policy_cache()
        self._tmp.cleanup()
        self._net.__exit__(None, None, None)

    # -- helpers -----------------------------------------------------------

    def write_task_file(self, name: str, data: bytes = b"x") -> str:
        path = os.path.join(self.task_dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def run_cli(self, *argv):
        """Run pilot_review.run capturing stdout/stderr and exit code."""
        from io import StringIO

        out, err = StringIO(), StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            code = pilot_review.run(list(argv))
        finally:
            sys.stdout, sys.stderr = old_out, old_err
        return code, out.getvalue(), err.getvalue()

    def make_manifest(self, claims=None, assets=None, review_status="NEEDS_HUMAN_REVIEW",
                      write=True):
        self.write_task_file("script.txt", b"script body")
        self.write_task_file("final.mp4", b"out")
        task = prov.build_task_section(
            task_id="task-001", topic="bitcoin basics",
            pilot_profile="braintrustcrypto", created_at=UTC,
            review_status=review_status,
        )
        script = prov.build_script_section(
            self.task_dir, local_path="script.txt", generation_source="local"
        )
        output = prov.build_output_section(
            self.task_dir, local_path="final.mp4", review_status=review_status
        )
        manifest = prov.build_manifest(
            task=task, script=script, assets=assets or [],
            factual_claims=claims or [], output=output,
        )
        if write:
            prov.write_manifest_atomic(self.task_dir, manifest)
        return manifest

    def write_manifest_raw(self, manifest: dict):
        """Write a manifest dict directly, bypassing build-time validation.

        Used to create invalid/edge-case on-disk states (unsupported schema,
        stripped provenance, etc.) that the read-only CLI must then detect.
        """
        path = os.path.join(self.task_dir, "provenance_manifest.json")
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
        return path

    def verified_claim(self):
        return prov.build_claim(
            claim_text="Bitcoin supply is capped at 21 million.",
            source_url="https://bitcoin.org/bitcoin.pdf",
            status="VERIFIED", reviewer="rick", review_date=UTC2,
        )

    def make_approval_receipt(self, manifest):
        manifest_json = prov.manifest_to_json(manifest).encode("utf-8")
        manifest_sha = hashlib.sha256(
            (prov.manifest_to_json(manifest)).encode("utf-8")
        ).hexdigest()
        # The CLI hashes the raw file bytes; recompute from the written file.
        with open(os.path.join(self.task_dir, "provenance_manifest.json"), "rb") as h:
            file_sha = hashlib.sha256(h.read()).hexdigest()
        return ri.create_receipt(
            self.task_dir, receipt_type="APPROVAL", task_id="task-001",
            manifest_version="1.1.0",
            manifest_relative_path="provenance_manifest.json",
            manifest_sha256=file_sha,
            audit_head_hash=ri.review_chain_head_hash(self.task_dir),
            created_at_utc=UTC2, reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
        )


# ---------------------------------------------------------------------------
# Policy gate
# ---------------------------------------------------------------------------


class TestPolicyGate(_ReviewTestBase):
    def test_inactive_profile_fails_closed(self):
        os.environ.pop("MPT_PILOT_PROFILE", None)
        reset_pilot_policy_cache()
        self.make_manifest()
        code, _out, err = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)
        self.assertIn("pilot policy failure", err)

    def test_missing_policy_fails_closed(self):
        os.unlink(Path(self.root) / "hardening.toml")
        reset_pilot_policy_cache()
        self.make_manifest()
        code, _out, err = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)
        self.assertIn("pilot policy failure", err)

    def test_malformed_policy_fails_closed(self):
        (Path(self.root) / "hardening.toml").write_text("not [valid toml",
                                                        encoding="utf-8")
        reset_pilot_policy_cache()
        self.make_manifest()
        code, _out, err = self.run_cli("audit", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)

    def test_unsafe_policy_fails_closed(self):
        (Path(self.root) / "hardening.toml").write_text(
            VALID_POLICY.replace("api_server_enabled = false",
                                 "api_server_enabled = true"),
            encoding="utf-8",
        )
        reset_pilot_policy_cache()
        self.make_manifest()
        code, _out, err = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)


# ---------------------------------------------------------------------------
# status command
# ---------------------------------------------------------------------------


class TestStatusCommand(_ReviewTestBase):
    def test_valid_draft_status_exit0_blocked(self):
        # A draft with an UNVERIFIED claim is valid but BLOCKED; exit 0.
        claim = prov.build_claim(
            claim_text="c", source_url="https://x.example/y"
        )
        self.make_manifest(claims=[claim])
        code, out, _ = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertEqual(code, 0)
        self.assertIn("task_id:", out)
        self.assertIn("1.1.0", out)
        self.assertIn("NEEDS_HUMAN_REVIEW", out)
        self.assertIn("approval readiness:   BLOCKED", out)

    def test_approval_ready_draft(self):
        self.make_manifest(claims=[self.verified_claim()])
        code, out, _ = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertEqual(code, 0)
        self.assertIn("approval readiness:   READY", out)

    def test_unverified_claim_blocks(self):
        claim = prov.build_claim(
            claim_text="c", source_url="https://x.example/y"
        )
        self.make_manifest(claims=[claim])
        code, out, _ = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertEqual(code, 0)  # valid draft, just blocked
        self.assertIn("BLOCKED", out)
        self.assertIn("UNVERIFIED=1", out)

    def test_retracted_claim_blocks(self):
        claim = prov.build_claim(
            claim_text="c", source_url="https://x.example/y", status="RETRACTED",
            reviewer_id=REVIEWER_ID, reviewer_display_name=REVIEWER_NAME,
            review_timestamp_utc=UTC2, notes="bad source",
        )
        self.make_manifest(claims=[claim])
        code, out, _ = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertIn("RETRACTED=1", out)
        self.assertIn("BLOCKED", out)

    def test_incomplete_asset_provenance(self):
        # Stripped license evidence is rejected by manifest validation
        # (fail closed) before any status report.
        self.write_task_file("clip.mp4", b"vid")
        asset = prov.build_asset(
            self.task_dir, asset_type="video", source_type="local",
            local_path="clip.mp4", license_name="CC0",
            license_evidence="https://creativecommons.org/publicdomain/zero/1.0/",
        )
        manifest = self.make_manifest(assets=[asset], write=False)
        manifest["assets"][0]["license_evidence"] = ""
        self.write_manifest_raw(manifest)
        code, _out, err = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)
        self.assertIn("manifest validation", err)

    def test_provider_asset_missing_field_detected(self):
        # A provider asset missing provider_asset_id fails validation.
        self.write_task_file("clip.mp4", b"vid")
        asset = prov.build_asset(
            self.task_dir, asset_type="video", source_type="provider",
            local_path="clip.mp4", license_name="CC0",
            license_evidence="https://x.example/lic",
            source_url="https://provider.example/asset/1", provider="pexels",
            provider_asset_id="12345", retrieval_date=UTC,
        )
        manifest = self.make_manifest(assets=[asset], write=False)
        manifest["assets"][0]["provider_asset_id"] = None
        self.write_manifest_raw(manifest)
        code, _out, err = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)
        self.assertIn("manifest validation", err)

    def test_changed_script_detected(self):
        self.make_manifest()
        self.write_task_file("script.txt", b"tampered script")
        code, out, _ = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)
        self.assertIn("script hash:          changed", out)

    def test_changed_asset_detected(self):
        self.write_task_file("clip.mp4", b"vid")
        asset = prov.build_asset(
            self.task_dir, asset_type="video", source_type="local",
            local_path="clip.mp4", license_name="CC0",
            license_evidence="https://creativecommons.org/publicdomain/zero/1.0/",
        )
        self.make_manifest(assets=[asset])
        self.write_task_file("clip.mp4", b"tampered video")
        code, out, _ = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)
        self.assertIn("changed", out)

    def test_changed_output_detected(self):
        self.make_manifest()
        self.write_task_file("final.mp4", b"tampered output")
        code, out, _ = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)
        self.assertIn("output hash:          changed", out)

    def test_missing_output_not_present(self):
        self.write_task_file("script.txt", b"script body")
        task = prov.build_task_section(
            task_id="task-001", topic="t", pilot_profile="braintrustcrypto",
            created_at=UTC,
        )
        script = prov.build_script_section(
            self.task_dir, local_path="script.txt", generation_source="local"
        )
        output = prov.build_output_section(
            self.task_dir, local_path="planned/final.mp4", compute_hash=False
        )
        manifest = prov.build_manifest(task=task, script=script, output=output)
        prov.write_manifest_atomic(self.task_dir, manifest)
        code, out, _ = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertIn("output hash:          not-present", out)

    def test_approved_with_valid_receipt(self):
        manifest = self.make_manifest(claims=[self.verified_claim()],
                                      review_status="APPROVED")
        self.make_approval_receipt(manifest)
        code, out, _ = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertEqual(code, 0)
        self.assertIn("effective status:     APPROVED", out)

    def test_revoked_with_valid_revocation(self):
        manifest = self.make_manifest(claims=[self.verified_claim()],
                                      review_status="APPROVED")
        approval = self.make_approval_receipt(manifest)
        ri.create_receipt(
            self.task_dir, receipt_type="REVOCATION", task_id="task-001",
            manifest_version="1.1.0",
            manifest_relative_path="provenance_manifest.json",
            manifest_sha256=approval["manifest_sha256"],
            audit_head_hash=ri.review_chain_head_hash(self.task_dir),
            created_at_utc=UTC2, reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME,
            approval_receipt_id=approval["receipt_id"],
            approval_receipt_hash=approval["receipt_hash"],
            reason="source withdrawn",
        )
        code, out, _ = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertIn("effective status:     REVOKED", out)

    def test_manifest_approved_without_receipt_is_invalid(self):
        self.make_manifest(claims=[self.verified_claim()],
                           review_status="APPROVED")
        code, out, _ = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)
        self.assertIn("effective status:     INVALID", out)

    def test_rejected_manifest(self):
        self.make_manifest(review_status="REJECTED")
        code, out, _ = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertIn("effective status:     REJECTED", out)

    def test_lock_held_reported(self):
        self.make_manifest()
        ri.acquire_review_lock(
            self.task_dir, reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME, created_at_utc=UTC,
        )
        code, out, _ = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertIn("lock status:          held by rick.gamboa", out)

    def test_malformed_lock_reported_as_failure(self):
        self.make_manifest()
        with open(os.path.join(self.task_dir, "review.lock"), "w") as h:
            h.write("{corrupt")
        code, out, _ = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)
        self.assertIn("lock status:          error", out)

    def test_unsupported_schema_rejected(self):
        manifest = self.make_manifest(write=False)
        manifest["task"]["schema_version"] = "9.9.9"
        self.write_manifest_raw(manifest)
        code, _out, err = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)
        self.assertIn("manifest validation", err)

    def test_missing_task_dir_fails(self):
        code, _out, err = self.run_cli(
            "status", "--task-dir", os.path.join(self.root, "nope")
        )
        self.assertEqual(code, 1)
        self.assertIn("does not exist", err)

    def test_missing_manifest_fails(self):
        code, _out, err = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)
        self.assertIn("manifest not found", err)


# ---------------------------------------------------------------------------
# audit command
# ---------------------------------------------------------------------------


class TestAuditCommand(_ReviewTestBase):
    def test_audit_pass_on_valid_draft(self):
        self.make_manifest()
        code, out, _ = self.run_cli("audit", "--task-dir", self.task_dir)
        self.assertEqual(code, 0)
        self.assertIn("result:     PASS", out)

    def test_audit_pass_with_verified_claim(self):
        self.make_manifest(claims=[self.verified_claim()])
        code, out, _ = self.run_cli("audit", "--task-dir", self.task_dir)
        self.assertEqual(code, 0)
        self.assertIn("PASS", out)

    def test_audit_fail_changed_script(self):
        self.make_manifest()
        self.write_task_file("script.txt", b"tampered")
        code, out, _ = self.run_cli("audit", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)
        self.assertIn("FAIL", out)
        self.assertIn("SCRIPT_HASH", out)

    def test_audit_fail_broken_event_chain(self):
        self.make_manifest()
        e1 = ri.create_review_event(
            self.task_dir, event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID, reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC,
        )
        path = os.path.join(self.task_dir, "review-events",
                            f"000001_{e1['event_id']}.json")
        data = json.loads(open(path, encoding="utf-8").read())
        data["reviewer_display_name"] = "Mallory"
        with open(path, "w", encoding="utf-8") as h:
            json.dump(data, h)
        code, out, _ = self.run_cli("audit", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)
        self.assertIn("EVENT_CHAIN", out)

    def test_audit_fail_deleted_final_event(self):
        self.make_manifest()
        ri.create_review_event(
            self.task_dir, event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID, reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC,
        )
        e2 = ri.create_review_event(
            self.task_dir, event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID, reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC2,
        )
        os.unlink(os.path.join(self.task_dir, "review-events",
                               f"000002_{e2['event_id']}.json"))
        code, out, _ = self.run_cli("audit", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)
        self.assertIn("EVENT_CHAIN", out)

    def test_audit_fail_broken_receipt_chain(self):
        manifest = self.make_manifest(claims=[self.verified_claim()],
                                      review_status="APPROVED")
        approval = self.make_approval_receipt(manifest)
        path = os.path.join(self.task_dir, "approvals",
                            f"000001_{approval['receipt_id']}.json")
        data = json.loads(open(path, encoding="utf-8").read())
        data["task_id"] = "task-999"
        with open(path, "w", encoding="utf-8") as h:
            json.dump(data, h)
        code, out, _ = self.run_cli("audit", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)
        self.assertIn("RECEIPT_CHAIN", out)

    def test_audit_fail_deleted_final_receipt(self):
        manifest = self.make_manifest(claims=[self.verified_claim()],
                                      review_status="APPROVED")
        self.make_approval_receipt(manifest)
        r2 = self.make_approval_receipt(manifest)
        os.unlink(os.path.join(self.task_dir, "approvals",
                               f"000002_{r2['receipt_id']}.json"))
        code, out, _ = self.run_cli("audit", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)
        self.assertIn("RECEIPT_CHAIN", out)

    def test_audit_fail_missing_checkpoint(self):
        self.make_manifest()
        ri.create_review_event(
            self.task_dir, event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID, reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC,
        )
        os.unlink(os.path.join(self.task_dir, "review-events", "chain-head.json"))
        code, out, _ = self.run_cli("audit", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)
        self.assertIn("EVENT_CHAIN", out)

    def test_audit_fail_modified_checkpoint(self):
        self.make_manifest()
        ri.create_review_event(
            self.task_dir, event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID, reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC,
        )
        cp_path = os.path.join(self.task_dir, "review-events", "chain-head.json")
        cp = json.loads(open(cp_path, encoding="utf-8").read())
        cp["last_sequence"] = 99
        with open(cp_path, "w", encoding="utf-8") as h:
            json.dump(cp, h)
        code, out, _ = self.run_cli("audit", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)
        self.assertIn("EVENT_CHAIN", out)

    def test_audit_fail_uncommitted_tail(self):
        self.make_manifest()
        ri.create_review_event(
            self.task_dir, event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID, reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC,
        )
        original = ri._write_checkpoint_atomic
        ri._write_checkpoint_atomic = lambda *a, **k: (_ for _ in ()).throw(
            OSError("crash")
        )
        try:
            with self.assertRaises(OSError):
                ri.create_review_event(
                    self.task_dir, event_type="CLAIM_VERIFIED",
                    reviewer_id=REVIEWER_ID, reviewer_display_name=REVIEWER_NAME,
                    timestamp_utc=UTC2,
                )
        finally:
            ri._write_checkpoint_atomic = original
        code, out, _ = self.run_cli("audit", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)
        self.assertIn("FAIL", out)

    def test_audit_fail_partial_files(self):
        self.make_manifest()
        os.makedirs(os.path.join(self.task_dir, "review-events"), exist_ok=True)
        with open(os.path.join(self.task_dir, "review-events", ".tmp-x.part"),
                  "w") as h:
            h.write("partial")
        code, out, _ = self.run_cli("audit", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)
        self.assertIn("PARTIAL_FILES", out)

    def test_audit_fail_malformed_lock(self):
        self.make_manifest()
        with open(os.path.join(self.task_dir, "review.lock"), "w") as h:
            h.write("{corrupt")
        code, out, _ = self.run_cli("audit", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)
        self.assertIn("LOCK_STATE", out)


# ---------------------------------------------------------------------------
# Output sanitization
# ---------------------------------------------------------------------------


class TestSanitization(_ReviewTestBase):
    def test_no_full_claim_text_in_status(self):
        secret_claim = "Bitcoin will definitely reach one million dollars by Tuesday"
        claim = prov.build_claim(
            claim_text=secret_claim, source_url="https://x.example/y"
        )
        self.make_manifest(claims=[claim])
        code, out, _ = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertNotIn(secret_claim, out)

    def test_no_query_strings_in_output(self):
        self.make_manifest()
        code, out, _ = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertNotIn("?api_key=", out)
        self.assertNotIn("?token=", out)

    def test_no_env_values_in_output(self):
        os.environ["SECRET_TEST_VALUE"] = "super-secret-should-not-appear"
        try:
            self.make_manifest()
            code, out, err = self.run_cli("status", "--task-dir", self.task_dir)
            self.assertNotIn("super-secret-should-not-appear", out)
            self.assertNotIn("super-secret-should-not-appear", err)
        finally:
            os.environ.pop("SECRET_TEST_VALUE", None)


# ---------------------------------------------------------------------------
# Read-only guarantee
# ---------------------------------------------------------------------------


class TestReadOnlyGuarantee(_ReviewTestBase):
    def test_status_leaves_task_dir_unchanged(self):
        self.make_manifest(claims=[self.verified_claim()])
        ri.create_review_event(
            self.task_dir, event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID, reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC,
        )
        before = _snapshot_tree(self.task_dir)
        self.run_cli("status", "--task-dir", self.task_dir)
        after = _snapshot_tree(self.task_dir)
        self.assertEqual(before, after)

    def test_audit_leaves_task_dir_unchanged(self):
        self.make_manifest()
        before = _snapshot_tree(self.task_dir)
        self.run_cli("audit", "--task-dir", self.task_dir)
        after = _snapshot_tree(self.task_dir)
        self.assertEqual(before, after)

    def test_audit_does_not_remove_existing_lock(self):
        self.make_manifest()
        lock = ri.acquire_review_lock(
            self.task_dir, reviewer_id=REVIEWER_ID,
            reviewer_display_name=REVIEWER_NAME, created_at_utc=UTC,
        )
        before = _snapshot_tree(self.task_dir)
        self.run_cli("audit", "--task-dir", self.task_dir)
        after = _snapshot_tree(self.task_dir)
        self.assertEqual(before, after)
        # Lock still held afterwards.
        self.assertIsNotNone(ri.read_review_lock(self.task_dir))
        ri.release_review_lock(self.task_dir, lock_token=lock["lock_token"])

    def test_audit_does_not_recover_uncommitted_tail(self):
        self.make_manifest()
        ri.create_review_event(
            self.task_dir, event_type="CLAIM_VERIFIED",
            reviewer_id=REVIEWER_ID, reviewer_display_name=REVIEWER_NAME,
            timestamp_utc=UTC,
        )
        original = ri._write_checkpoint_atomic
        ri._write_checkpoint_atomic = lambda *a, **k: (_ for _ in ()).throw(
            OSError("crash")
        )
        try:
            with self.assertRaises(OSError):
                ri.create_review_event(
                    self.task_dir, event_type="CLAIM_VERIFIED",
                    reviewer_id=REVIEWER_ID, reviewer_display_name=REVIEWER_NAME,
                    timestamp_utc=UTC2,
                )
        finally:
            ri._write_checkpoint_atomic = original
        before = _snapshot_tree(self.task_dir)
        code, out, _ = self.run_cli("audit", "--task-dir", self.task_dir)
        after = _snapshot_tree(self.task_dir)
        # Audit reports FAIL but does NOT repair the tail.
        self.assertEqual(code, 1)
        self.assertEqual(before, after)
        self.assertEqual(
            len(ri.find_uncommitted_tail(self.task_dir, "review-events")), 1
        )


# ---------------------------------------------------------------------------
# Traversal / unsafe paths
# ---------------------------------------------------------------------------


class TestPathSafety(_ReviewTestBase):
    def test_manifest_with_traversal_asset_rejected(self):
        self.make_manifest()
        manifest_path = os.path.join(self.task_dir, "provenance_manifest.json")
        manifest = json.loads(open(manifest_path, encoding="utf-8").read())
        manifest["assets"] = [{
            "asset_type": "video", "source_type": "local",
            "source_url": None, "provider": None, "provider_asset_id": None,
            "retrieval_date": None, "local_path": "../outside.mp4",
            "sha256": "a" * 64, "license_name": "CC0",
            "license_evidence": "https://x.example/lic", "notes": None,
        }]
        with open(manifest_path, "w", encoding="utf-8") as h:
            json.dump(manifest, h)
        # The traversal asset resolves outside -> treated as missing, not read.
        code, out, _ = self.run_cli("audit", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------


class TestExitCodes(_ReviewTestBase):
    def test_usage_error_exit2(self):
        with self.assertRaises(SystemExit) as ctx:
            pilot_review.run(["bogus-command"])
        self.assertEqual(ctx.exception.code, 2)

    def test_missing_task_dir_arg_exit2(self):
        with self.assertRaises(SystemExit) as ctx:
            pilot_review.run(["status"])
        self.assertEqual(ctx.exception.code, 2)

    def test_valid_status_exit0(self):
        self.make_manifest()
        code, _, _ = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertEqual(code, 0)

    def test_integrity_failure_exit1(self):
        self.make_manifest()
        self.write_task_file("script.txt", b"tampered")
        code, _, _ = self.run_cli("status", "--task-dir", self.task_dir)
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
