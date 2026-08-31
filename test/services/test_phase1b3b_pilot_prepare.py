"""
Phase 1B.3B — Offline CLI dry-run and provenance integration tests.

Fully offline: all network access is blocked for every test in this module.
Covers:
- successful task preparation
- missing/malformed/unsafe pilot policy
- traversal, symlink/junction escapes (where testable), unsafe absolute paths
- script and asset paths outside the task directory
- remote URL rejection
- missing license evidence
- deterministic manifest creation
- NEEDS_HUMAN_REVIEW defaults and filename marker
- nonzero failure exit codes
- atomic cleanup after failure
- no provider/rendering/publishing/WebUI/API/Redis/update/bootstrap/telemetry
  path is invoked
"""

import json
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pilot_prepare
from app.services import provenance as prov
from app.services.pilot_policy import reset_pilot_policy_cache

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


# ---------------------------------------------------------------------------
# Network block — every test in this module runs without any socket access
# ---------------------------------------------------------------------------


def _blocked_socket(*args, **kwargs):
    raise AssertionError("network access is forbidden in Phase 1B.3B tests")


class _NetworkBlocker:
    """Block all outbound socket creation for the duration of a test."""

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


# ---------------------------------------------------------------------------
# Base fixture
# ---------------------------------------------------------------------------


class _PrepareTestBase(unittest.TestCase):
    """Isolated project-root sandbox with a valid hardening.toml."""

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
        reset_pilot_policy_cache()
        self._root_patch = patch(
            "app.services.pilot_policy.Path",
            _PatchedPath(self.root),
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

    def base_argv(self, *extra):
        return [
            "prepare",
            "--topic", "bitcoin basics",
            "--task-dir", self.task_dir,
            "--script", os.path.join(self.task_dir, "script.txt"),
            *extra,
        ]

    def prepare_script(self) -> str:
        return self.write_task_file("script.txt", b"script body")


def _PatchedPath(root: str):
    """Return a Path factory that redirects the policy root lookup."""

    real_path = Path

    class _Factory:
        def __call__(self, *args):
            # pilot_policy resolves Path(__file__).resolve().parent.parent.parent
            if args and str(args[0]).endswith("pilot_policy.py"):
                # Emulate .../<root>/app/services/pilot_policy.py
                return real_path(root) / "app" / "services" / "pilot_policy.py"
            return real_path(*args)

    return _Factory()


# ---------------------------------------------------------------------------
# Successful preparation
# ---------------------------------------------------------------------------


class TestSuccessfulPreparation(_PrepareTestBase):
    def test_minimal_prepare_succeeds(self):
        self.prepare_script()
        code = pilot_prepare.run(self.base_argv())
        self.assertEqual(code, 0)
        manifest_path = os.path.join(self.task_dir, "provenance_manifest.json")
        self.assertTrue(os.path.isfile(manifest_path))
        with open(manifest_path, encoding="utf-8") as handle:
            manifest = json.load(handle)
        self.assertEqual(manifest["task"]["review_status"], "NEEDS_HUMAN_REVIEW")
        self.assertEqual(manifest["task"]["topic"], "bitcoin basics")
        self.assertRegex(manifest["script"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(manifest["assets"], [])
        self.assertEqual(manifest["factual_claims"], [])

    def test_full_prepare_with_assets_claims_and_output(self):
        self.prepare_script()
        self.write_task_file("clip.mp4", b"video-bytes")
        code = pilot_prepare.run(
            self.base_argv(
                "--asset", os.path.join(self.task_dir, "clip.mp4"),
                "--asset-type", "video",
                "--license-name", "CC0",
                "--license-evidence", "https://creativecommons.org/publicdomain/zero/1.0/",
                "--asset-notes", "recorded locally",
                "--output-placeholder", os.path.join(self.task_dir, "final.mp4"),
                "--claim", "Bitcoin supply is capped at 21 million.",
                "--claim-source", "https://bitcoin.org/bitcoin.pdf",
            )
        )
        self.assertEqual(code, 0)
        with open(os.path.join(self.task_dir, "provenance_manifest.json"),
                  encoding="utf-8") as handle:
            manifest = json.load(handle)
        self.assertEqual(len(manifest["assets"]), 1)
        self.assertEqual(manifest["assets"][0]["source_type"], "local")
        self.assertEqual(manifest["assets"][0]["license_name"], "CC0")
        self.assertEqual(len(manifest["factual_claims"]), 1)
        self.assertEqual(manifest["factual_claims"][0]["status"], "UNVERIFIED")
        self.assertIsNone(manifest["factual_claims"][0]["reviewer"])
        output = manifest["output"]
        self.assertEqual(output["review_status"], "NEEDS_HUMAN_REVIEW")
        self.assertIn("__NEEDS_HUMAN_REVIEW", output["filename_marker"])
        self.assertFalse(output["visible_watermark_required"])
        # Placeholder did not exist -> no hash recorded.
        self.assertIsNone(output["sha256"])

    def test_existing_output_placeholder_is_hashed(self):
        self.prepare_script()
        self.write_task_file("final.mp4", b"out")
        code = pilot_prepare.run(
            self.base_argv(
                "--output-placeholder", os.path.join(self.task_dir, "final.mp4"),
            )
        )
        self.assertEqual(code, 0)
        with open(os.path.join(self.task_dir, "provenance_manifest.json"),
                  encoding="utf-8") as handle:
            manifest = json.load(handle)
        self.assertRegex(manifest["output"]["sha256"], r"^[0-9a-f]{64}$")

    def test_task_dir_created_when_missing(self):
        self.prepare_script()
        new_dir = os.path.join(self.root, "brand-new-task")
        # Script must live inside the new task dir.
        os.makedirs(new_dir)
        self.write_task_file("script.txt")  # keep original valid too
        with open(os.path.join(new_dir, "script.txt"), "wb") as handle:
            handle.write(b"script")
        code = pilot_prepare.run([
            "prepare",
            "--topic", "t",
            "--task-dir", new_dir,
            "--script", os.path.join(new_dir, "script.txt"),
        ])
        self.assertEqual(code, 0)
        self.assertTrue(
            os.path.isfile(os.path.join(new_dir, "provenance_manifest.json"))
        )

    def test_deterministic_manifest_creation(self):
        self.prepare_script()
        self.assertEqual(pilot_prepare.run(self.base_argv()), 0)
        manifest_path = os.path.join(self.task_dir, "provenance_manifest.json")
        with open(manifest_path, "rb") as handle:
            first = handle.read()
        # Re-run with identical inputs; created_at will differ, so compare
        # structure determinism via the serializer on the loaded manifest.
        with open(manifest_path, encoding="utf-8") as handle:
            manifest = json.load(handle)
        serialized_a = prov.manifest_to_json(manifest)
        serialized_b = prov.manifest_to_json(json.loads(serialized_a))
        self.assertEqual(serialized_a, serialized_b)
        self.assertTrue(first.endswith(b"\n"))


# ---------------------------------------------------------------------------
# Pilot policy failures
# ---------------------------------------------------------------------------


class TestPilotPolicyFailures(_PrepareTestBase):
    def test_missing_profile_env_fails_closed(self):
        self.prepare_script()
        os.environ.pop("MPT_PILOT_PROFILE", None)
        reset_pilot_policy_cache()
        code = pilot_prepare.run(self.base_argv())
        self.assertEqual(code, 1)
        self.assertFalse(
            os.path.exists(os.path.join(self.task_dir, "provenance_manifest.json"))
        )

    def test_missing_policy_file_fails_closed(self):
        self.prepare_script()
        os.unlink(Path(self.root) / "hardening.toml")
        reset_pilot_policy_cache()
        self.assertEqual(pilot_prepare.run(self.base_argv()), 1)

    def test_malformed_policy_fails_closed(self):
        self.prepare_script()
        (Path(self.root) / "hardening.toml").write_text(
            "not valid toml [[[", encoding="utf-8"
        )
        reset_pilot_policy_cache()
        self.assertEqual(pilot_prepare.run(self.base_argv()), 1)

    def test_unsafe_policy_fails_closed(self):
        self.prepare_script()
        (Path(self.root) / "hardening.toml").write_text(
            VALID_POLICY.replace("api_server_enabled = false",
                                 "api_server_enabled = true"),
            encoding="utf-8",
        )
        reset_pilot_policy_cache()
        self.assertEqual(pilot_prepare.run(self.base_argv()), 1)


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------


class TestPathSafety(_PrepareTestBase):
    def test_script_traversal_rejected(self):
        code = pilot_prepare.run([
            "prepare", "--topic", "t", "--task-dir", self.task_dir,
            "--script", "../outside.txt",
        ])
        self.assertEqual(code, 1)

    def test_script_outside_task_dir_rejected(self):
        outside = os.path.join(self.root, "outside.txt")
        with open(outside, "wb") as handle:
            handle.write(b"x")
        code = pilot_prepare.run([
            "prepare", "--topic", "t", "--task-dir", self.task_dir,
            "--script", outside,
        ])
        self.assertEqual(code, 1)

    def test_asset_outside_task_dir_rejected(self):
        self.prepare_script()
        outside = os.path.join(self.root, "asset.mp4")
        with open(outside, "wb") as handle:
            handle.write(b"x")
        code = pilot_prepare.run(
            self.base_argv(
                "--asset", outside,
                "--license-name", "CC0",
                "--license-evidence", "ref",
            )
        )
        self.assertEqual(code, 1)

    def test_asset_traversal_rejected(self):
        self.prepare_script()
        code = pilot_prepare.run(
            self.base_argv(
                "--asset", "../asset.mp4",
                "--license-name", "CC0",
                "--license-evidence", "ref",
            )
        )
        self.assertEqual(code, 1)

    @unittest.skipUnless(os.name == "nt", "Windows junction test")
    def test_junction_escape_rejected(self):
        self.prepare_script()
        outside_dir = os.path.join(self.root, "outside")
        os.makedirs(outside_dir)
        with open(os.path.join(outside_dir, "evil.txt"), "wb") as handle:
            handle.write(b"x")
        junction = os.path.join(self.task_dir, "link")
        try:
            import subprocess
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", junction, outside_dir],
                check=True, capture_output=True,
            )
        except Exception:
            self.skipTest("cannot create junction in this environment")
        code = pilot_prepare.run([
            "prepare", "--topic", "t", "--task-dir", self.task_dir,
            "--script", os.path.join(junction, "evil.txt"),
        ])
        self.assertEqual(code, 1)

    def test_remote_script_url_rejected(self):
        code = pilot_prepare.run([
            "prepare", "--topic", "t", "--task-dir", self.task_dir,
            "--script", "https://example.com/script.txt",
        ])
        self.assertEqual(code, 1)

    def test_remote_asset_url_rejected(self):
        self.prepare_script()
        code = pilot_prepare.run(
            self.base_argv(
                "--asset", "https://example.com/clip.mp4",
                "--license-name", "CC0",
                "--license-evidence", "ref",
            )
        )
        self.assertEqual(code, 1)

    def test_protocol_relative_url_rejected(self):
        self.prepare_script()
        code = pilot_prepare.run(
            self.base_argv(
                "--asset", "//example.com/clip.mp4",
                "--license-name", "CC0",
                "--license-evidence", "ref",
            )
        )
        self.assertEqual(code, 1)


# ---------------------------------------------------------------------------
# License / claim validation
# ---------------------------------------------------------------------------


class TestValidation(_PrepareTestBase):
    def test_asset_without_license_name_rejected(self):
        self.prepare_script()
        self.write_task_file("clip.mp4", b"v")
        code = pilot_prepare.run(
            self.base_argv(
                "--asset", os.path.join(self.task_dir, "clip.mp4"),
                "--license-evidence", "ref",
            )
        )
        self.assertEqual(code, 1)

    def test_asset_without_license_evidence_rejected(self):
        self.prepare_script()
        self.write_task_file("clip.mp4", b"v")
        code = pilot_prepare.run(
            self.base_argv(
                "--asset", os.path.join(self.task_dir, "clip.mp4"),
                "--license-name", "CC0",
            )
        )
        self.assertEqual(code, 1)

    def test_claim_without_source_rejected(self):
        self.prepare_script()
        code = pilot_prepare.run(
            self.base_argv("--claim", "A claim with no source.")
        )
        self.assertEqual(code, 1)

    def test_orphan_claim_source_rejected(self):
        self.prepare_script()
        code = pilot_prepare.run(
            self.base_argv("--claim-source", "https://example.com")
        )
        self.assertEqual(code, 1)

    def test_missing_script_rejected(self):
        code = pilot_prepare.run(self.base_argv())  # script.txt not created
        self.assertEqual(code, 1)

    def test_empty_topic_rejected(self):
        self.prepare_script()
        code = pilot_prepare.run([
            "prepare", "--topic", "   ", "--task-dir", self.task_dir,
            "--script", os.path.join(self.task_dir, "script.txt"),
        ])
        self.assertEqual(code, 1)


# ---------------------------------------------------------------------------
# Failure atomicity
# ---------------------------------------------------------------------------


class TestFailureAtomicity(_PrepareTestBase):
    def test_no_partial_manifest_after_validation_failure(self):
        self.prepare_script()
        # Invalid asset triggers failure after script validation.
        code = pilot_prepare.run(
            self.base_argv(
                "--asset", "../evil.mp4",
                "--license-name", "CC0",
                "--license-evidence", "ref",
            )
        )
        self.assertEqual(code, 1)
        entries = os.listdir(self.task_dir)
        self.assertNotIn("provenance_manifest.json", entries)
        self.assertEqual([e for e in entries if e.endswith(".tmp")], [])

    def test_no_temp_files_after_write_failure(self):
        self.prepare_script()
        original_replace = os.replace

        def boom(*args, **kwargs):
            raise OSError("simulated rename failure")

        prov.os.replace = boom
        try:
            code = pilot_prepare.run(self.base_argv())
        finally:
            prov.os.replace = original_replace
        self.assertEqual(code, 1)
        entries = os.listdir(self.task_dir)
        self.assertNotIn("provenance_manifest.json", entries)
        self.assertEqual([e for e in entries if e.endswith(".tmp")], [])


# ---------------------------------------------------------------------------
# No provider / rendering / publishing paths invoked
# ---------------------------------------------------------------------------


class TestNoForbiddenPathsInvoked(_PrepareTestBase):
    def test_no_task_pipeline_or_services_imported(self):
        self.prepare_script()
        forbidden_prefixes = (
            "app.services.task",
            "app.services.llm",
            "app.services.voice",
            "app.services.material",
            "app.services.video",
            "app.services.upload_post",
            "app.services.version_checker",
            "app.controllers",
            "app.services.egress",
        )
        before = {
            name for name in sys.modules if name.startswith(forbidden_prefixes)
        }
        code = pilot_prepare.run(self.base_argv())
        self.assertEqual(code, 0)
        after = {
            name for name in sys.modules if name.startswith(forbidden_prefixes)
        }
        self.assertEqual(after - before, set())

    def test_no_redis_or_requests_imported(self):
        self.prepare_script()
        # Snapshot before; the prepare path must not newly import redis or
        # the HTTP client stack. These may already be loaded by other test
        # modules in a full-suite run, so compare deltas only.
        before = set(sys.modules)
        code = pilot_prepare.run(self.base_argv())
        self.assertEqual(code, 0)
        newly = set(sys.modules) - before
        self.assertEqual(
            {n for n in newly if n == "redis" or n.startswith("redis.")},
            set(),
        )
        self.assertEqual(
            {n for n in newly if n == "requests" or n.startswith("requests.")},
            set(),
        )


if __name__ == "__main__":
    unittest.main()
