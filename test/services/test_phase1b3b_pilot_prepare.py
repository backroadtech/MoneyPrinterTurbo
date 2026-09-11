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

import dataclasses
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

import pilot_prepare
import pilot_review
from app.models import const
from app.models.schema import VideoAspect, VideoConcatMode
from app.services import provenance as prov
from app.services import voice
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


# ---------------------------------------------------------------------------
# Render-local request validation (pure, in-memory)
# ---------------------------------------------------------------------------


class TestRenderLocalRequestValidation(_PrepareTestBase):
    """Focused tests for the pure _validate_render_local_request validator."""

    @staticmethod
    def _valid_kwargs() -> dict:
        """Canary-laden inputs that pass validation."""
        return {
            "topic": "topic canary 1a2b3c",
            "script_path": "canary-script-dir-4d5e6f/script.txt",
            "material_paths": ["canary-material-7g8h9i/clip.mp4"],
            "license_names": ["license canary 0j1k2l"],
            "license_evidence": ["evidence canary 3m4n5o"],
            "claims": ["claim canary 6p7q8r"],
            "claim_sources": ["source canary 9s0t1u"],
        }

    @staticmethod
    def _canary_values(kwargs) -> list:
        """Every supplied value carrying a unique canary marker."""
        found = []
        for value in kwargs.values():
            candidates = [value] if isinstance(value, str) else list(value)
            found.extend(c for c in candidates if "canary" in c.lower())
        return found

    # -- 1. policy gate runs first -----------------------------------------

    def test_policy_gate_runs_before_any_input_processing(self):
        sentinel = pilot_prepare.PrepareError("policy gate sentinel")
        with patch.object(
            pilot_prepare, "_require_pilot_policy", side_effect=sentinel
        ) as gate, patch.object(
            pilot_prepare,
            "_is_remote_url",
            side_effect=AssertionError("_is_remote_url must not run"),
        ) as remote_check:
            with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                pilot_prepare._validate_render_local_request(
                    topic="   ",
                    script_path="https://canary.invalid/script.txt",
                    material_paths=[],
                    license_names=[],
                    license_evidence=[],
                )
        self.assertIs(ctx.exception, sentinel)
        gate.assert_called_once_with()
        remote_check.assert_not_called()

    # -- 2. valid request ---------------------------------------------------

    def test_valid_request_returns_frozen_ordered_dataclasses(self):
        request = pilot_prepare._validate_render_local_request(
            topic="  bitcoin basics  ",
            script_path="  task-001/script.txt ",
            material_paths=[" task-001/clip-b.mp4 ", "task-001/clip-a.mp4"],
            license_names=[" CC0 ", "ODbL"],
            license_evidence=[" ref-b ", "ref-a"],
            claims=[" claim one ", "claim two"],
            claim_sources=[" src-1 ", "src-2"],
        )
        self.assertIsInstance(request, pilot_prepare.RenderLocalRequest)
        self.assertEqual(request.topic, "bitcoin basics")
        self.assertEqual(request.script_path, "task-001/script.txt")
        self.assertIsInstance(request.materials, tuple)
        self.assertIsInstance(request.claims, tuple)
        for material in request.materials:
            self.assertIsInstance(
                material, pilot_prepare.RenderLocalMaterialRequest
            )
        # Positional pairing and input order are preserved after stripping.
        self.assertEqual(
            [
                (m.path, m.license_name, m.license_evidence)
                for m in request.materials
            ],
            [
                ("task-001/clip-b.mp4", "CC0", "ref-b"),
                ("task-001/clip-a.mp4", "ODbL", "ref-a"),
            ],
        )
        self.assertEqual(
            request.claims,
            (("claim one", "src-1"), ("claim two", "src-2")),
        )
        # Both dataclasses are immutable.
        with self.assertRaises(dataclasses.FrozenInstanceError):
            request.topic = "mutated"
        with self.assertRaises(dataclasses.FrozenInstanceError):
            request.materials[0].path = "mutated"

    # -- 3/4. table-driven PrepareError cases, canary leak checks -----------

    def test_prepare_error_cases(self):
        cases = [
            ("empty topic",
             {"topic": "   "},
             "render-local topic must be a non-empty string"),
            ("empty script path",
             {"script_path": "  "},
             "render-local script path must be a non-empty string"),
            ("zero materials",
             {"material_paths": []},
             "render-local requires at least one material"),
            ("empty material path",
             {"material_paths": ["  "]},
             "render-local material path must be a non-empty string"),
            ("empty license name",
             {"license_names": [" "]},
             "render-local material license name must be a non-empty string"),
            ("empty license evidence",
             {"license_evidence": ["\t"]},
             "render-local material license evidence must be a "
             "non-empty string"),
            ("mismatched material/license counts",
             {"material_paths": ["canary-material-7g8h9i/clip.mp4",
                                 "canary-material-2b3c4d/clip2.mp4"]},
             "render-local material path, license name, and license evidence "
             "counts must match"),
            ("mismatched claim/source counts",
             {"claims": ["claim canary 6p7q8r", "claim canary 5e6f7g"]},
             "render-local claim and claim source counts must match"),
            ("empty claim",
             {"claims": ["   "],
              "claim_sources": ["source canary 9s0t1u"]},
             "render-local claim must be a non-empty string"),
            ("empty claim source",
             {"claim_sources": ["  "]},
             "render-local claim source must be a non-empty string"),
            ("remote script URL",
             {"script_path":
              "https://canary-host-8h9i0j.example.com/script.txt"},
             "render-local script path must be a local path, not a remote URL"),
            ("remote material URL",
             {"material_paths":
              ["ftp://canary-host-1k2l3m.example.com/clip.mp4"]},
             "render-local material path must be a local path, not a "
             "remote URL"),
        ]
        for name, override, expected_message in cases:
            with self.subTest(case=name):
                kwargs = self._valid_kwargs()
                kwargs.update(override)
                with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                    pilot_prepare._validate_render_local_request(**kwargs)
                message = str(ctx.exception)
                self.assertEqual(message, expected_message)
                # Static messages never echo supplied canary values or paths.
                for canary in self._canary_values(kwargs):
                    self.assertNotIn(canary, message)


# ---------------------------------------------------------------------------
# Render-local input loading (read-only filesystem checks + script load)
# ---------------------------------------------------------------------------


class TestRenderLocalInputLoading(unittest.TestCase):
    """Read-only _load_render_local_inputs tests on real temp files.

    The helper performs no policy call, so these tests intentionally run
    without any pilot policy fixture.
    """

    def setUp(self):
        self._net = _NetworkBlocker()
        self._net.__enter__()
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()
        self._net.__exit__(None, None, None)

    # -- fixture helpers ----------------------------------------------------

    def write_file(self, path: str, data: bytes) -> str:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def make_request(self, script_path, material_paths=(),
                     claims=(("claim", "source"),)):
        return pilot_prepare.RenderLocalRequest(
            topic="render-local topic",
            script_path=script_path,
            materials=tuple(
                pilot_prepare.RenderLocalMaterialRequest(
                    path=path,
                    license_name=f"license-{index}",
                    license_evidence=f"evidence-{index}",
                )
                for index, path in enumerate(material_paths)
            ),
            claims=tuple(claims),
        )

    def tree_snapshot(self):
        dirs = set()
        files = {}
        for dirpath, dirnames, filenames in os.walk(self.root):
            for dirname in dirnames:
                dirs.add(os.path.relpath(os.path.join(dirpath, dirname),
                                         self.root))
            for filename in filenames:
                full = os.path.join(dirpath, filename)
                with open(full, "rb") as handle:
                    files[os.path.relpath(full, self.root)] = handle.read()
        return dirs, files

    def _symlink(self, target, link):
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")

    # -- 1. happy path --------------------------------------------------------

    def test_happy_path_preserves_bytes_text_paths_and_pairing(self):
        script_bytes = (
            b"Bitcoin basics line one.\r\n"
            + "Línea dos con café y 中文.\r\n".encode("utf-8")
            + b"last line without newline"
        )
        script_path = self.write_file(
            os.path.join(self.root, "task", "script.txt"), script_bytes
        )
        material_b = self.write_file(
            os.path.join(self.root, "task", "media", "clip-b.mp4"), b"bytes-b"
        )
        material_a = self.write_file(
            os.path.join(self.root, "task", "media", "clip-a.mp4"), b"bytes-a"
        )
        request = self.make_request(script_path, [material_b, material_a])

        result = pilot_prepare._load_render_local_inputs(request)

        self.assertIs(result.request, request)
        self.assertEqual(result.script_bytes, script_bytes)
        self.assertEqual(result.script_text, script_bytes.decode("utf-8"))
        self.assertEqual(
            result.script_path,
            os.path.realpath(os.path.abspath(script_path)),
        )
        self.assertIsInstance(result.material_paths, tuple)
        self.assertEqual(
            result.material_paths,
            (
                os.path.realpath(os.path.abspath(material_b)),
                os.path.realpath(os.path.abspath(material_a)),
            ),
        )
        # Material order stays aligned with the license pairing.
        self.assertEqual(
            [m.license_name for m in result.request.materials],
            ["license-0", "license-1"],
        )
        self.assertEqual(result.request.claims, (("claim", "source"),))
        # Result dataclass is immutable.
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.script_text = "mutated"
        # Source files are untouched by the read-only load.
        with open(script_path, "rb") as handle:
            self.assertEqual(handle.read(), script_bytes)
        with open(material_b, "rb") as handle:
            self.assertEqual(handle.read(), b"bytes-b")
        with open(material_a, "rb") as handle:
            self.assertEqual(handle.read(), b"bytes-a")

    # -- 2/3/4. refusal fixtures, canary checks, tree-unchanged -------------
    # Each builder creates fixtures inside case_dir and returns the request
    # plus every canary-bearing supplied value.

    def _fixture_missing_script(self, case_dir):
        material = self.write_file(
            os.path.join(case_dir, "clip-CANARY-ms1.mp4"), b"m"
        )
        request = self.make_request(
            os.path.join(case_dir, "missing-CANARY-ms2.txt"), [material]
        )
        return request, ["CANARY-ms1", "CANARY-ms2"]

    def _fixture_script_is_directory(self, case_dir):
        material = self.write_file(
            os.path.join(case_dir, "clip-CANARY-sd1.mp4"), b"m"
        )
        os.makedirs(os.path.join(case_dir, "dir-CANARY-sd2.txt"))
        request = self.make_request(
            os.path.join(case_dir, "dir-CANARY-sd2.txt"), [material]
        )
        return request, ["CANARY-sd1", "CANARY-sd2"]

    def _fixture_invalid_utf8(self, case_dir):
        script = self.write_file(
            os.path.join(case_dir, "script-CANARY-iu1.txt"),
            b"invalid utf-8 \xff\xfe CANARY-content-iu2",
        )
        material = self.write_file(
            os.path.join(case_dir, "clip-CANARY-iu3.mp4"), b"m"
        )
        return self.make_request(script, [material]), [
            "CANARY-iu1", "CANARY-content-iu2", "CANARY-iu3",
        ]

    def _fixture_utf8_bom(self, case_dir):
        script = self.write_file(
            os.path.join(case_dir, "script-CANARY-bom1.txt"),
            b"\xef\xbb\xbfCANARY-content-bom2",
        )
        material = self.write_file(
            os.path.join(case_dir, "clip-CANARY-bom3.mp4"), b"m"
        )
        return self.make_request(script, [material]), [
            "CANARY-bom1", "CANARY-content-bom2", "CANARY-bom3",
        ]

    def _fixture_empty_script(self, case_dir):
        script = self.write_file(
            os.path.join(case_dir, "script-CANARY-es1.txt"), b""
        )
        material = self.write_file(
            os.path.join(case_dir, "clip-CANARY-es2.mp4"), b"m"
        )
        return self.make_request(script, [material]), [
            "CANARY-es1", "CANARY-es2",
        ]

    def _fixture_whitespace_script(self, case_dir):
        script = self.write_file(
            os.path.join(case_dir, "script-CANARY-ws1.txt"), b" \t\r\n  "
        )
        material = self.write_file(
            os.path.join(case_dir, "clip-CANARY-ws2.mp4"), b"m"
        )
        return self.make_request(script, [material]), [
            "CANARY-ws1", "CANARY-ws2",
        ]

    def _fixture_symlinked_script(self, case_dir):
        target = self.write_file(
            os.path.join(case_dir, "real-CANARY-sl1.txt"), b"real script"
        )
        link = os.path.join(case_dir, "link-CANARY-sl2.txt")
        self._symlink(target, link)
        material = self.write_file(
            os.path.join(case_dir, "clip-CANARY-sl3.mp4"), b"m"
        )
        return self.make_request(link, [material]), [
            "CANARY-sl1", "CANARY-sl2", "CANARY-sl3",
        ]

    def _fixture_missing_material(self, case_dir):
        script = self.write_file(
            os.path.join(case_dir, "script-CANARY-mm1.txt"), b"ok"
        )
        request = self.make_request(
            script, [os.path.join(case_dir, "missing-CANARY-mm2.mp4")]
        )
        return request, ["CANARY-mm1", "CANARY-mm2"]

    def _fixture_material_is_directory(self, case_dir):
        script = self.write_file(
            os.path.join(case_dir, "script-CANARY-md1.txt"), b"ok"
        )
        os.makedirs(os.path.join(case_dir, "dir-CANARY-md2.mp4"))
        request = self.make_request(
            script, [os.path.join(case_dir, "dir-CANARY-md2.mp4")]
        )
        return request, ["CANARY-md1", "CANARY-md2"]

    def _fixture_symlinked_material(self, case_dir):
        script = self.write_file(
            os.path.join(case_dir, "script-CANARY-sm1.txt"), b"ok"
        )
        target = self.write_file(
            os.path.join(case_dir, "real-CANARY-sm2.mp4"), b"m"
        )
        link = os.path.join(case_dir, "link-CANARY-sm3.mp4")
        self._symlink(target, link)
        return self.make_request(script, [link]), [
            "CANARY-sm1", "CANARY-sm2", "CANARY-sm3",
        ]

    def _fixture_duplicate_basename(self, case_dir):
        script = self.write_file(
            os.path.join(case_dir, "script-CANARY-db1.txt"), b"ok"
        )
        first = self.write_file(
            os.path.join(case_dir, "one", "clip-CANARY-db2.mp4"), b"1"
        )
        second = self.write_file(
            os.path.join(case_dir, "two", "clip-CANARY-db2.mp4"), b"2"
        )
        return self.make_request(script, [first, second]), [
            "CANARY-db1", "CANARY-db2",
        ]

    def _fixture_case_basename_collision(self, case_dir):
        if os.path.normcase("Aa") != os.path.normcase("aa"):
            self.skipTest("platform uses case-sensitive path comparison")
        script = self.write_file(
            os.path.join(case_dir, "script-CANARY-cc1.txt"), b"ok"
        )
        first = self.write_file(
            os.path.join(case_dir, "one", "clip-CANARY-cc2.mp4"), b"1"
        )
        second = self.write_file(
            os.path.join(case_dir, "two", "CLIP-CANARY-cc2.mp4"), b"2"
        )
        return self.make_request(script, [first, second]), [
            "CANARY-cc1", "CANARY-cc2",
        ]

    def test_refusals(self):
        cases = [
            ("missing script", self._fixture_missing_script,
             "render-local script path must be an existing regular file"),
            ("script is directory", self._fixture_script_is_directory,
             "render-local script path must be an existing regular file"),
            ("invalid utf-8", self._fixture_invalid_utf8,
             "render-local script must be valid UTF-8"),
            ("utf-8 BOM", self._fixture_utf8_bom,
             "render-local script must not start with a UTF-8 BOM"),
            ("empty script", self._fixture_empty_script,
             "render-local script must not be empty or whitespace-only"),
            ("whitespace script", self._fixture_whitespace_script,
             "render-local script must not be empty or whitespace-only"),
            ("symlinked script", self._fixture_symlinked_script,
             "render-local script path contains a link or junction"),
            ("missing material", self._fixture_missing_material,
             "render-local material path must be an existing regular file"),
            ("material is directory", self._fixture_material_is_directory,
             "render-local material path must be an existing regular file"),
            ("symlinked material", self._fixture_symlinked_material,
             "render-local material path contains a link or junction"),
            ("duplicate basename", self._fixture_duplicate_basename,
             "render-local material basenames must be unique"),
            ("case basename collision", self._fixture_case_basename_collision,
             "render-local material basenames must be unique"),
        ]
        for name, builder, expected_message in cases:
            with self.subTest(case=name):
                case_dir = os.path.join(self.root, name.replace(" ", "_"))
                os.makedirs(case_dir)
                request, canaries = builder(case_dir)
                before = self.tree_snapshot()
                with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                    pilot_prepare._load_render_local_inputs(request)
                message = str(ctx.exception)
                self.assertEqual(message, expected_message)
                # Static messages never echo supplied paths or content.
                for canary in canaries:
                    self.assertNotIn(canary, message)
                # Refusals leave the whole temp tree untouched.
                self.assertEqual(self.tree_snapshot(), before)


# ---------------------------------------------------------------------------
# Render-local task staging (task-local copies, hashing, owned rollback)
# ---------------------------------------------------------------------------


class TestRenderLocalTaskStaging(unittest.TestCase):
    """Focused tests for _stage_render_local_task.

    The storage root is isolated by pointing pilot_prepare.__file__ at the
    temp sandbox, and utils.get_uuid is patched to a known canonical UUID.
    Real storage artifacts are never touched.
    """

    KNOWN_TASK_ID = "12345678-1234-5678-1234-567812345678"

    def setUp(self):
        self._net = _NetworkBlocker()
        self._net.__enter__()
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.storage_root = os.path.join(self.root, "storage", "tasks")
        self._file_patch = patch.object(
            pilot_prepare,
            "__file__",
            os.path.join(self.root, "pilot_prepare.py"),
        )
        self._file_patch.start()
        self._uuid_patch = patch(
            "app.utils.utils.get_uuid", return_value=self.KNOWN_TASK_ID
        )
        self._uuid_patch.start()

    def tearDown(self):
        self._uuid_patch.stop()
        self._file_patch.stop()
        self._tmp.cleanup()
        self._net.__exit__(None, None, None)

    # -- fixture helpers ----------------------------------------------------

    def write_source(self, name: str, data: bytes) -> str:
        path = os.path.join(self.root, "src", name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def make_loaded(self, script_bytes, materials):
        script_src = self.write_source("script.txt", script_bytes)
        resolved_paths = []
        material_requests = []
        for index, (name, data) in enumerate(materials):
            src = self.write_source(name, data)
            resolved_paths.append(os.path.realpath(src))
            material_requests.append(
                pilot_prepare.RenderLocalMaterialRequest(
                    path=src,
                    license_name=f"license-{index}",
                    license_evidence=f"evidence-{index}",
                )
            )
        request = pilot_prepare.RenderLocalRequest(
            topic="topic",
            script_path=script_src,
            materials=tuple(material_requests),
            claims=(("claim", "source"),),
        )
        return pilot_prepare.RenderLocalLoadedInputs(
            request=request,
            script_path=os.path.realpath(script_src),
            script_bytes=script_bytes,
            script_text=script_bytes.decode("utf-8"),
            material_paths=tuple(resolved_paths),
        )

    def tree_snapshot(self):
        dirs = set()
        files = {}
        for dirpath, dirnames, filenames in os.walk(self.root):
            for dirname in dirnames:
                dirs.add(os.path.relpath(os.path.join(dirpath, dirname),
                                         self.root))
            for filename in filenames:
                full = os.path.join(dirpath, filename)
                with open(full, "rb") as handle:
                    files[os.path.relpath(full, self.root)] = handle.read()
        return dirs, files

    # -- 1. happy path --------------------------------------------------------

    def test_happy_path_stages_and_hashes_task_local_copies(self):
        script_bytes = "Script line one\r\ncafé 中文\r\n".encode("utf-8")
        loaded = self.make_loaded(
            script_bytes,
            [("clip-b.mp4", b"bytes-b"), ("clip-a.mp4", b"bytes-a")],
        )
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
        before_modules = {
            name for name in sys.modules if name.startswith(forbidden_prefixes)
        }

        result = pilot_prepare._stage_render_local_task(loaded)

        after_modules = {
            name for name in sys.modules if name.startswith(forbidden_prefixes)
        }
        self.assertEqual(after_modules - before_modules, set())

        self.assertEqual(result.task_id, self.KNOWN_TASK_ID)
        self.assertEqual(os.path.basename(result.task_dir), self.KNOWN_TASK_ID)
        self.assertTrue(os.path.isdir(result.task_dir))
        self.assertIs(result.loaded, loaded)

        # script.md holds the exact loaded bytes.
        self.assertEqual(os.path.basename(result.script_path), "script.md")
        self.assertEqual(os.path.dirname(result.script_path), result.task_dir)
        with open(result.script_path, "rb") as handle:
            self.assertEqual(handle.read(), script_bytes)
        self.assertEqual(result.script_text, script_bytes.decode("utf-8"))
        self.assertEqual(
            result.script_sha256,
            prov.sha256_file_streamed(result.script_path),
        )
        self.assertEqual(
            result.script_sha256, hashlib.sha256(script_bytes).hexdigest()
        )

        # Materials: inside task_dir/materials, ordered, bytes equal,
        # hashes equal the production streamed SHA-256 results.
        expected_names = ["clip-b.mp4", "clip-a.mp4"]
        expected_bytes = [b"bytes-b", b"bytes-a"]
        self.assertEqual(len(result.materials), 2)
        for index, (staged_path, staged_hash) in enumerate(result.materials):
            self.assertEqual(
                os.path.dirname(staged_path),
                os.path.join(result.task_dir, "materials"),
            )
            self.assertEqual(
                os.path.basename(staged_path), expected_names[index]
            )
            with open(staged_path, "rb") as handle:
                self.assertEqual(handle.read(), expected_bytes[index])
            self.assertEqual(
                staged_hash, prov.sha256_file_streamed(staged_path)
            )
            self.assertEqual(
                staged_hash,
                hashlib.sha256(expected_bytes[index]).hexdigest(),
            )

        # Ordering stays aligned with the original license evidence.
        self.assertEqual(
            [m.license_evidence for m in result.loaded.request.materials],
            ["evidence-0", "evidence-1"],
        )

        # External sources remain byte-for-byte unchanged.
        with open(loaded.script_path, "rb") as handle:
            self.assertEqual(handle.read(), script_bytes)
        for index, source in enumerate(loaded.material_paths):
            with open(source, "rb") as handle:
                self.assertEqual(handle.read(), expected_bytes[index])

        # No manifest and no stray files are created by staging.
        self.assertFalse(
            os.path.exists(
                os.path.join(result.task_dir, "provenance_manifest.json")
            )
        )
        staged_files = []
        for dirpath, _, filenames in os.walk(result.task_dir):
            for filename in filenames:
                staged_files.append(
                    os.path.relpath(os.path.join(dirpath, filename),
                                    result.task_dir)
                )
        self.assertEqual(
            sorted(staged_files),
            [
                os.path.join("materials", "clip-a.mp4"),
                os.path.join("materials", "clip-b.mp4"),
                "script.md",
            ],
        )

        # Returned structure is immutable.
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.task_id = "mutated"

    # -- 2. fresh-directory refusal -------------------------------------------

    def test_existing_task_directory_refused(self):
        loaded = self.make_loaded(
            b"script CANARY-ex1", [("clip-CANARY-e1.mp4", b"m")]
        )
        existing = os.path.join(self.storage_root, self.KNOWN_TASK_ID)
        os.makedirs(existing)
        sentinel = os.path.join(existing, "sentinel-CANARY-ex2.txt")
        with open(sentinel, "wb") as handle:
            handle.write(b"keep me")
        before = self.tree_snapshot()

        with self.assertRaises(pilot_prepare.PrepareError) as ctx:
            pilot_prepare._stage_render_local_task(loaded)

        message = str(ctx.exception)
        self.assertEqual(
            message, "render-local staging task directory already exists"
        )
        self.assertIsInstance(ctx.exception.__cause__, FileExistsError)
        self.assertNotIn("CANARY-ex1", message)
        self.assertNotIn("CANARY-ex2", message)
        self.assertNotIn(self.KNOWN_TASK_ID, message)
        # Existing directory/tree remains byte-for-byte unchanged.
        self.assertEqual(self.tree_snapshot(), before)

    # -- 3. injected failure during the second material copy ------------------

    def test_rollback_on_second_material_copy_failure(self):
        loaded = self.make_loaded(
            b"script CANARY-script",
            [
                ("clip-one-CANARY-m1.mp4", b"m1-bytes"),
                ("clip-two-CANARY-m2.mp4", b"m2-bytes"),
            ],
        )
        os.makedirs(self.storage_root)  # pre-existing parents must remain
        real_write = pilot_prepare._atomic_write_stream

        def flaky(target, chunks):
            if target.endswith("clip-two-CANARY-m2.mp4"):
                raise OSError("injected copy failure CANARY-inject")
            return real_write(target, chunks)

        before = self.tree_snapshot()
        with patch.object(
            pilot_prepare, "_atomic_write_stream", side_effect=flaky
        ):
            with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                pilot_prepare._stage_render_local_task(loaded)

        message = str(ctx.exception)
        self.assertEqual(message, "render-local staging failed")
        # Native failure survives only as the internal cause.
        self.assertIsInstance(ctx.exception.__cause__, OSError)
        for canary in (
            "CANARY-script",
            "CANARY-m1",
            "CANARY-m2",
            "CANARY-inject",
            self.KNOWN_TASK_ID,
        ):
            self.assertNotIn(canary, message)
        # No script, material, temp, or generated task directory remains.
        self.assertFalse(
            os.path.exists(os.path.join(self.storage_root,
                                        self.KNOWN_TASK_ID))
        )
        self.assertEqual(os.listdir(self.storage_root), [])
        # Pre-existing parents remain; external inputs unchanged.
        self.assertTrue(os.path.isdir(self.storage_root))
        self.assertEqual(self.tree_snapshot(), before)

    # -- 4. injected script-write / hash failure ------------------------------

    def _assert_rollback_guarantees(self, ctx, before, canaries):
        message = str(ctx.exception)
        self.assertEqual(message, "render-local staging failed")
        self.assertIsInstance(ctx.exception.__cause__, OSError)
        for canary in canaries:
            self.assertNotIn(canary, message)
        self.assertFalse(
            os.path.exists(os.path.join(self.storage_root,
                                        self.KNOWN_TASK_ID))
        )
        self.assertEqual(os.listdir(self.storage_root), [])
        self.assertTrue(os.path.isdir(self.storage_root))
        self.assertEqual(self.tree_snapshot(), before)

    def test_rollback_on_script_write_failure(self):
        loaded = self.make_loaded(
            b"script CANARY-wf1", [("clip-CANARY-w1.mp4", b"m")]
        )
        os.makedirs(self.storage_root)

        def boom(target, chunks):
            raise OSError("injected write failure CANARY-writeinject")

        before = self.tree_snapshot()
        with patch.object(
            pilot_prepare, "_atomic_write_stream", side_effect=boom
        ), patch(
            "shutil.rmtree",
            side_effect=AssertionError("recursive deletion forbidden"),
        ):
            with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                pilot_prepare._stage_render_local_task(loaded)

        self._assert_rollback_guarantees(
            ctx,
            before,
            ("CANARY-wf1", "CANARY-w1", "CANARY-writeinject",
             self.KNOWN_TASK_ID),
        )

    def test_rollback_on_hash_failure(self):
        loaded = self.make_loaded(
            b"script CANARY-hash1", [("clip-CANARY-h1.mp4", b"m")]
        )
        os.makedirs(self.storage_root)
        before = self.tree_snapshot()
        with patch(
            "app.services.provenance.sha256_file_streamed",
            side_effect=OSError("injected hash failure CANARY-hashinject"),
        ), patch(
            "shutil.rmtree",
            side_effect=AssertionError("recursive deletion forbidden"),
        ):
            with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                pilot_prepare._stage_render_local_task(loaded)

        self._assert_rollback_guarantees(
            ctx,
            before,
            ("CANARY-hash1", "CANARY-h1", "CANARY-hashinject",
             self.KNOWN_TASK_ID),
        )


# ---------------------------------------------------------------------------
# Render-local draft preparation (output-null manifest, durable write)
# ---------------------------------------------------------------------------


class TestRenderLocalDraftPreparation(_PrepareTestBase):
    """Focused tests for _prepare_render_local_draft.

    Uses the real validation/loading/staging helpers inside an isolated
    temporary storage root (pilot_prepare.__file__ points at the sandbox;
    utils.get_uuid returns a known canonical UUID).
    """

    KNOWN_TASK_ID = "12345678-1234-5678-1234-567812345678"

    def setUp(self):
        super().setUp()
        self.storage_root = os.path.join(self.root, "storage", "tasks")
        self._file_patch = patch.object(
            pilot_prepare,
            "__file__",
            os.path.join(self.root, "pilot_prepare.py"),
        )
        self._file_patch.start()
        self._uuid_patch = patch(
            "app.utils.utils.get_uuid", return_value=self.KNOWN_TASK_ID
        )
        self._uuid_patch.start()

    def tearDown(self):
        self._uuid_patch.stop()
        self._file_patch.stop()
        super().tearDown()

    # -- fixture helpers ----------------------------------------------------

    def write_source(self, name: str, data: bytes) -> str:
        path = os.path.join(self.root, "src", name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def run_chain(self, script_bytes, materials, claims=()):
        """Real validate -> load -> stage chain against sandbox sources."""
        script_src = self.write_source("script.txt", script_bytes)
        material_paths = [
            self.write_source(name, data) for name, data in materials
        ]
        request = pilot_prepare._validate_render_local_request(
            topic="draft topic",
            script_path=script_src,
            material_paths=material_paths,
            license_names=[f"license-{i}" for i in range(len(materials))],
            license_evidence=[f"evidence-{i}" for i in range(len(materials))],
            claims=[text for text, _ in claims],
            claim_sources=[source for _, source in claims],
        )
        loaded = pilot_prepare._load_render_local_inputs(request)
        return pilot_prepare._stage_render_local_task(loaded)

    def tree_snapshot(self):
        dirs = set()
        files = {}
        for dirpath, dirnames, filenames in os.walk(self.root):
            for dirname in dirnames:
                dirs.add(os.path.relpath(os.path.join(dirpath, dirname),
                                         self.root))
            for filename in filenames:
                full = os.path.join(dirpath, filename)
                with open(full, "rb") as handle:
                    files[os.path.relpath(full, self.root)] = handle.read()
        return dirs, files

    # -- 1/2. happy path and successful preservation --------------------------

    def test_happy_path_writes_durable_output_null_manifest(self):
        script_bytes = "Draft script\r\ncafé 中文\r\n".encode("utf-8")
        claims = (("Bitcoin supply is capped at 21 million.",
                   "https://bitcoin.org/bitcoin.pdf"),)
        staged = self.run_chain(
            script_bytes,
            [("clip-b.mp4", b"bytes-b"), ("clip-a.mp4", b"bytes-a")],
            claims=claims,
        )
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
        before_modules = {
            n for n in sys.modules if n.startswith(forbidden_prefixes)
        }

        draft = pilot_prepare._prepare_render_local_draft(staged)

        after_modules = {
            n for n in sys.modules if n.startswith(forbidden_prefixes)
        }
        self.assertEqual(after_modules - before_modules, set())
        self.assertIs(draft.staged, staged)
        self.assertEqual(
            draft.manifest_path,
            os.path.join(staged.task_dir, "provenance_manifest.json"),
        )
        self.assertTrue(os.path.isfile(draft.manifest_path))
        # Production validation accepts the durable manifest.
        prov.validate_manifest(draft.manifest)

        task = draft.manifest["task"]
        self.assertEqual(task["schema_version"], "1.2.0")
        self.assertEqual(task["review_status"], "NEEDS_HUMAN_REVIEW")
        self.assertIsNone(draft.manifest["output"])

        script_section = draft.manifest["script"]
        self.assertEqual(script_section["local_path"], "script.md")
        self.assertEqual(script_section["sha256"], staged.script_sha256)
        self.assertEqual(
            script_section["sha256"],
            hashlib.sha256(script_bytes).hexdigest(),
        )

        assets = draft.manifest["assets"]
        self.assertEqual(len(assets), 2)
        for index, asset in enumerate(assets):
            self.assertEqual(asset["asset_type"], "video")
            self.assertEqual(asset["source_type"], "local")
            self.assertEqual(
                asset["local_path"],
                os.path.join("materials", ("clip-b.mp4",
                                           "clip-a.mp4")[index]),
            )
            self.assertEqual(asset["sha256"], staged.materials[index][1])
            self.assertEqual(
                asset["sha256"],
                hashlib.sha256((b"bytes-b", b"bytes-a")[index]).hexdigest(),
            )
            # Exact per-material license pairing and ordering.
            self.assertEqual(asset["license_name"], f"license-{index}")
            self.assertEqual(
                asset["license_evidence"], f"evidence-{index}"
            )

        factual_claims = draft.manifest["factual_claims"]
        self.assertEqual(len(factual_claims), 1)
        self.assertEqual(factual_claims[0]["status"], "UNVERIFIED")
        self.assertEqual(
            factual_claims[0]["claim_id"],
            prov.generate_claim_id(
                task_id=self.KNOWN_TASK_ID,
                ordinal=0,
                claim_text=claims[0][0],
                source_url=claims[0][1],
            ),
        )

        # Draft tree is complete; no output video files exist.
        staged_files = []
        for dirpath, _, filenames in os.walk(staged.task_dir):
            for filename in filenames:
                staged_files.append(
                    os.path.relpath(os.path.join(dirpath, filename),
                                    staged.task_dir)
                )
        self.assertEqual(
            sorted(staged_files),
            [
                os.path.join("materials", "clip-a.mp4"),
                os.path.join("materials", "clip-b.mp4"),
                "provenance_manifest.json",
                "script.md",
            ],
        )

    def test_successful_draft_preserves_tree_sources_and_parents(self):
        script_bytes = b"preserve me"
        staged = self.run_chain(
            script_bytes, [("clip-CANARY-p1.mp4", b"source-bytes")]
        )
        draft = pilot_prepare._prepare_render_local_draft(staged)
        after_return = self.tree_snapshot()

        # Complete draft tree remains after return.
        self.assertTrue(os.path.isfile(draft.manifest_path))
        with open(staged.script_path, "rb") as handle:
            self.assertEqual(handle.read(), script_bytes)
        with open(staged.materials[0][0], "rb") as handle:
            self.assertEqual(handle.read(), b"source-bytes")
        # External source files remain byte-for-byte unchanged.
        with open(os.path.join(self.root, "src", "script.txt"), "rb") as h:
            self.assertEqual(h.read(), script_bytes)
        with open(
            os.path.join(self.root, "src", "clip-CANARY-p1.mp4"), "rb"
        ) as h:
            self.assertEqual(h.read(), b"source-bytes")
        # Storage parents remain; only the generated task dir was added.
        self.assertTrue(os.path.isdir(self.storage_root))
        self.assertEqual(os.listdir(self.storage_root), [self.KNOWN_TASK_ID])
        self.assertEqual(self.tree_snapshot(), after_return)

    # -- 3. injected failures with full owned-path rollback -------------------

    def _assert_failure_rollback(self, ctx, before, expected_message,
                                 canaries):
        message = str(ctx.exception)
        self.assertEqual(message, expected_message)
        for canary in canaries:
            self.assertNotIn(canary, message)
        task_dir = os.path.join(self.storage_root, self.KNOWN_TASK_ID)
        self.assertFalse(os.path.exists(task_dir))
        self.assertEqual(os.listdir(self.storage_root), [])
        self.assertTrue(os.path.isdir(self.storage_root))
        self.assertEqual(self.tree_snapshot(), before)

    def _run_failure_case(self, patcher, expected_message, extra_canaries):
        script_bytes = b"script CANARY-f0"
        script_src = self.write_source("script.txt", script_bytes)
        material_src = self.write_source("clip-CANARY-f1.mp4", b"m-bytes")
        os.makedirs(self.storage_root)
        # True pre-staging baseline: only external source fixtures and the
        # intentionally pre-existing storage/tasks parents exist.
        before = self.tree_snapshot()
        request = pilot_prepare._validate_render_local_request(
            topic="draft topic",
            script_path=script_src,
            material_paths=[material_src],
            license_names=["license-0"],
            license_evidence=["evidence-0"],
        )
        loaded = pilot_prepare._load_render_local_inputs(request)
        staged = pilot_prepare._stage_render_local_task(loaded)
        with patcher, patch(
            "shutil.rmtree",
            side_effect=AssertionError("recursive deletion forbidden"),
        ):
            with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                pilot_prepare._prepare_render_local_draft(staged)
        self._assert_failure_rollback(
            ctx,
            before,
            expected_message,
            ("CANARY-f0", "CANARY-f1", self.KNOWN_TASK_ID, script_src,
             material_src) + extra_canaries,
        )
        return ctx

    def test_script_hash_mismatch_rolls_back(self):
        real_builder = prov.build_script_section

        def wrong_hash(task_dir, **kwargs):
            section = real_builder(task_dir, **kwargs)
            section["sha256"] = "0" * 64
            return section

        patcher = patch(
            "app.services.provenance.build_script_section",
            side_effect=wrong_hash,
        )
        ctx = self._run_failure_case(
            patcher, "render-local staged script hash mismatch", ()
        )
        self.assertIsNone(ctx.exception.__cause__)

    def test_material_hash_mismatch_rolls_back(self):
        real_builder = prov.build_asset

        def wrong_hash(task_dir, **kwargs):
            asset = real_builder(task_dir, **kwargs)
            asset["sha256"] = "0" * 64
            return asset

        patcher = patch(
            "app.services.provenance.build_asset", side_effect=wrong_hash
        )
        ctx = self._run_failure_case(
            patcher, "render-local staged material hash mismatch", ()
        )
        self.assertIsNone(ctx.exception.__cause__)

    def test_manifest_build_failure_rolls_back(self):
        patcher = patch(
            "app.services.provenance.build_manifest",
            side_effect=prov.ProvenanceError("injected CANARY-build"),
        )
        ctx = self._run_failure_case(
            patcher,
            "render-local draft preparation failed",
            ("CANARY-build",),
        )
        self.assertIsInstance(ctx.exception.__cause__, prov.ProvenanceError)

    def test_manifest_write_failure_rolls_back(self):
        patcher = patch(
            "app.services.provenance.write_manifest_atomic",
            side_effect=OSError("injected CANARY-write"),
        )
        ctx = self._run_failure_case(
            patcher,
            "render-local draft preparation failed",
            ("CANARY-write",),
        )
        self.assertIsInstance(ctx.exception.__cause__, OSError)

    def test_durable_validation_failure_rolls_back(self):
        real_validate = prov.validate_manifest
        calls = []

        def flaky(manifest):
            calls.append(1)
            if len(calls) > 1:
                raise prov.ProvenanceError("injected CANARY-validate")
            return real_validate(manifest)

        patcher = patch(
            "app.services.provenance.validate_manifest", side_effect=flaky
        )
        ctx = self._run_failure_case(
            patcher,
            "render-local draft preparation failed",
            ("CANARY-validate",),
        )
        self.assertIsInstance(ctx.exception.__cause__, prov.ProvenanceError)

    # -- 4. rollback helper ---------------------------------------------------

    def test_rollback_tolerates_absent_owned_paths(self):
        staged = self.run_chain(b"script", [("clip.mp4", b"m")])
        os.unlink(staged.script_path)
        os.unlink(staged.materials[0][0])
        os.rmdir(os.path.join(staged.task_dir, "materials"))
        pilot_prepare._rollback_staged_task(staged)  # must not raise
        self.assertFalse(os.path.exists(staged.task_dir))

    def test_rollback_never_removes_preexisting_parent(self):
        os.makedirs(self.storage_root)
        staged = self.run_chain(b"script", [("clip.mp4", b"m")])
        self.assertNotIn(
            ("dir", self.storage_root), list(staged.created_paths)
        )
        pilot_prepare._rollback_staged_task(staged)
        self.assertTrue(os.path.isdir(self.storage_root))
        self.assertEqual(os.listdir(self.storage_root), [])


# ---------------------------------------------------------------------------
# Render-local verified render semantics (post-render evidence verification)
# ---------------------------------------------------------------------------


class TestRenderLocalVerifiedRenderSemantics(_PrepareTestBase):
    """Happy-path semantics for _verify_render_local_render.

    Builds a real prepared draft with the validate/load/stage/draft helpers
    inside an isolated temporary storage root (pilot_prepare.__file__ points
    at the sandbox; utils.get_uuid returns a known canonical UUID), attaches
    renderer-shaped evidence (script.json + final-1.mp4), and confirms a
    successful completion task result verifies strictly read-only.
    """

    KNOWN_TASK_ID = "12345678-1234-5678-1234-567812345678"

    def setUp(self):
        super().setUp()
        self._file_patch = patch.object(
            pilot_prepare,
            "__file__",
            os.path.join(self.root, "pilot_prepare.py"),
        )
        self._file_patch.start()
        self._uuid_patch = patch(
            "app.utils.utils.get_uuid", return_value=self.KNOWN_TASK_ID
        )
        self._uuid_patch.start()

    def tearDown(self):
        self._uuid_patch.stop()
        self._file_patch.stop()
        super().tearDown()

    # -- helpers ------------------------------------------------------------

    def write_source(self, name: str, data: bytes) -> str:
        path = os.path.join(self.root, "src", name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def tree_snapshot(self, root):
        dirs = set()
        files = {}
        for dirpath, dirnames, filenames in os.walk(root):
            for dirname in dirnames:
                dirs.add(
                    os.path.relpath(os.path.join(dirpath, dirname), root)
                )
            for filename in filenames:
                full = os.path.join(dirpath, filename)
                with open(full, "rb") as handle:
                    files[os.path.relpath(full, root)] = handle.read()
        return dirs, files

    # -- shared fixtures ------------------------------------------------------

    def build_verifiable_fixtures(self):
        """Real prepared draft plus renderer-shaped script.json/final-1.mp4.

        Runs the validate/load/stage/draft helpers under isolated temporary
        storage, then attaches the fixture-shaped post-render evidence the
        verifier consumes. Returns (draft, script_json_target,
        script_json_fixture, output_target, output_bytes).
        """
        script_bytes = b"Bitcoin basics verified render script.\n"
        material_specs = [
            ("clip-b.mp4", b"material-bytes-b"),
            ("clip-a.mp4", b"material-bytes-a"),
        ]

        # 1. Real prepared draft via the validate/load/stage/draft helpers
        #    under isolated temporary storage.
        script_src = self.write_source("script.txt", script_bytes)
        material_srcs = [
            self.write_source(name, data) for name, data in material_specs
        ]
        request = pilot_prepare._validate_render_local_request(
            topic="verified render topic",
            script_path=script_src,
            material_paths=material_srcs,
            license_names=["CC0", "ODbL"],
            license_evidence=["ref-b", "ref-a"],
        )
        loaded = pilot_prepare._load_render_local_inputs(request)
        staged = pilot_prepare._stage_render_local_task(loaded)
        draft = pilot_prepare._prepare_render_local_draft(staged)
        task_dir = staged.task_dir

        # 2. Fixture-shaped script.json: exact prepared script + fixed params.
        script_json_fixture = {
            "script": staged.script_text,
            "params": {
                "video_script": staged.script_text,
                "video_source": "local",
                "video_count": 1,
                "video_aspect": VideoAspect.landscape.value,
                "video_concat_mode": VideoConcatMode.sequential.value,
                "video_clip_duration": 5,
                "voice_name": voice.NO_VOICE_NAME,
                "subtitle_enabled": False,
                "bgm_type": "none",
                "video_materials": [
                    {
                        "provider": "local",
                        "url": os.path.relpath(staged_path, task_dir),
                    }
                    for staged_path, _ in staged.materials
                ],
            },
        }
        script_json_target = os.path.join(task_dir, "script.json")
        with open(script_json_target, "w", encoding="utf-8") as handle:
            json.dump(script_json_fixture, handle)

        # 3. One final-1.mp4 fixture with known bytes.
        output_bytes = b"known-final-video-bytes\x00\x01\x02\xff"
        output_target = os.path.join(task_dir, "final-1.mp4")
        with open(output_target, "wb") as handle:
            handle.write(output_bytes)

        return (
            draft,
            script_json_target,
            script_json_fixture,
            output_target,
            output_bytes,
        )

    # -- happy path -----------------------------------------------------------

    def test_verified_render_happy_path(self):
        (
            draft,
            script_json_target,
            script_json_fixture,
            output_target,
            output_bytes,
        ) = self.build_verifiable_fixtures()
        staged = draft.staged
        task_dir = staged.task_dir

        # 4. Successful TASK_STATE_COMPLETE / progress-100 task result.
        task_result = {
            "task_id": staged.task_id,
            "state": const.TASK_STATE_COMPLETE,
            "progress": 100,
            "videos": [os.path.relpath(output_target, task_dir)],
        }

        before_tree = self.tree_snapshot(task_dir)
        verified = pilot_prepare._verify_render_local_render(
            draft, task_result
        )

        # Returned draft identity.
        self.assertIs(verified.draft, draft)
        self.assertIs(verified.draft.staged, staged)

        # script.json path and data.
        self.assertEqual(
            verified.script_json_path,
            os.path.realpath(os.path.abspath(script_json_target)),
        )
        self.assertEqual(verified.script_json, script_json_fixture)

        # Final output path.
        self.assertEqual(
            verified.output_path,
            os.path.realpath(os.path.abspath(output_target)),
        )
        self.assertTrue(os.path.isfile(verified.output_path))

        # Production and independent SHA-256 agree.
        self.assertEqual(
            verified.output_sha256,
            prov.sha256_file_streamed(verified.output_path),
        )
        self.assertEqual(
            verified.output_sha256,
            hashlib.sha256(output_bytes).hexdigest(),
        )

        # Complete task tree is byte-for-byte unchanged by verification.
        self.assertEqual(self.tree_snapshot(task_dir), before_tree)

        # Returned dataclass is immutable.
        with self.assertRaises(dataclasses.FrozenInstanceError):
            verified.output_sha256 = "mutated"

    # -- optional task-result fields ------------------------------------------

    def test_task_result_optional_fields_absent_are_accepted(self):
        (
            draft,
            _script_json_target,
            _script_json_fixture,
            output_target,
            output_bytes,
        ) = self.build_verifiable_fixtures()
        task_dir = draft.staged.task_dir

        # Only the required completion-contract fields are present; task_id
        # and videos are genuinely optional under the implemented contract.
        task_result = {
            "state": const.TASK_STATE_COMPLETE,
            "progress": 100,
        }
        before_tree = self.tree_snapshot(task_dir)
        verified = pilot_prepare._verify_render_local_render(
            draft, task_result
        )

        self.assertIs(verified.draft, draft)
        self.assertEqual(
            verified.output_path,
            os.path.realpath(os.path.abspath(output_target)),
        )
        self.assertEqual(
            verified.output_sha256,
            prov.sha256_file_streamed(verified.output_path),
        )
        self.assertEqual(
            verified.output_sha256,
            hashlib.sha256(output_bytes).hexdigest(),
        )
        self.assertEqual(verified.task_result, task_result)
        self.assertEqual(self.tree_snapshot(task_dir), before_tree)

    # -- task-result refusals -------------------------------------------------

    def test_incomplete_or_mismatched_task_result_refused(self):
        (
            draft,
            _script_json_target,
            _script_json_fixture,
            output_target,
            _output_bytes,
        ) = self.build_verifiable_fixtures()
        task_dir = draft.staged.task_dir
        output_rel = os.path.relpath(output_target, task_dir)
        foreign_path = os.path.join(self.root, "foreign-CANARY-vfr.mp4")
        remote_url = "https://example.com/CANARY-vru/final-1.mp4"
        wrong_task_id = "canary-task-id-CANARY-vtid"

        success = {
            "state": const.TASK_STATE_COMPLETE,
            "progress": 100,
        }
        disagree = (
            "render-local task result outputs disagree with the prepared "
            "draft"
        )
        cases = [
            ("non-mapping result",
             "not-a-mapping-CANARY-vnm",
             "render-local task result must be a non-empty mapping",
             ("not-a-mapping-CANARY-vnm",)),
            ("empty mapping",
             {},
             "render-local task result must be a non-empty mapping",
             ()),
            # A failed task that left final-1.mp4 behind never qualifies.
            ("failure state with valid output",
             {**success, "state": const.TASK_STATE_FAILED},
             "render-local task result state is not complete",
             ()),
            ("incomplete progress",
             {**success, "progress": 50},
             "render-local task result progress is not complete",
             ()),
            ("mismatched task id",
             {**success, "task_id": wrong_task_id},
             "render-local task result task ID disagrees with the prepared "
             "draft",
             (wrong_task_id, self.KNOWN_TASK_ID)),
            ("videos present but empty",
             {**success, "videos": []},
             disagree,
             ()),
            ("videos present with extra entries",
             {**success, "videos": [output_rel, "extra-CANARY-vex.mp4"]},
             disagree,
             ("extra-CANARY-vex.mp4",)),
            ("videos present with a foreign path",
             {**success, "videos": [foreign_path]},
             disagree,
             (foreign_path,)),
            ("videos present with a remote URL",
             {**success, "videos": [remote_url]},
             disagree,
             (remote_url,)),
        ]
        for name, task_result, expected_message, leaked in cases:
            with self.subTest(case=name):
                before_tree = self.tree_snapshot(task_dir)
                with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                    pilot_prepare._verify_render_local_render(
                        draft, task_result
                    )
                message = str(ctx.exception)
                self.assertEqual(message, expected_message)
                for supplied in leaked:
                    self.assertNotIn(supplied, message)
                self.assertEqual(self.tree_snapshot(task_dir), before_tree)

    # -- script / fixed render-parameter drift refusals -----------------------

    def test_script_or_fixed_render_parameter_drift_refused(self):
        (
            draft,
            script_json_target,
            script_json_fixture,
            output_target,
            _output_bytes,
        ) = self.build_verifiable_fixtures()
        staged = draft.staged
        task_dir = staged.task_dir
        # Task result and final-1.mp4 stay otherwise valid in every subtest.
        task_result = {
            "task_id": staged.task_id,
            "state": const.TASK_STATE_COMPLETE,
            "progress": 100,
            "videos": [os.path.relpath(output_target, task_dir)],
        }

        cases = [
            ("top-level script",
             ("script",), "altered script CANARY-ds1",
             "render-local script manifest script disagrees with the "
             "prepared script",
             ("altered script CANARY-ds1", staged.script_text)),
            ("params video_script",
             ("params", "video_script"), "altered video script CANARY-ds2",
             "render-local params video_script disagrees with the "
             "prepared script",
             ("altered video script CANARY-ds2", staged.script_text)),
            ("video_source",
             ("params", "video_source"), "pexels-CANARY-ds3",
             "render-local params video_source must be local",
             ("pexels-CANARY-ds3",)),
            ("video_count",
             ("params", "video_count"), 2,
             "render-local params video_count must be 1",
             ("2",)),
            ("video_aspect",
             ("params", "video_aspect"), "9:16-CANARY-ds5",
             "render-local params video_aspect must be 16:9",
             ("9:16-CANARY-ds5",)),
            ("video_concat_mode",
             ("params", "video_concat_mode"), "random-CANARY-ds6",
             "render-local params video_concat_mode must be sequential",
             ("random-CANARY-ds6",)),
            ("video_clip_duration",
             ("params", "video_clip_duration"), 6,
             "render-local params video_clip_duration must be 5",
             ("6",)),
            ("voice_name",
             ("params", "voice_name"), "en-US-AriaNeural-CANARY-ds8",
             "render-local params voice_name must be no-voice",
             ("en-US-AriaNeural-CANARY-ds8",)),
            ("subtitle_enabled",
             ("params", "subtitle_enabled"), True,
             "render-local params subtitle_enabled must be false",
             ("True",)),
            ("bgm_type",
             ("params", "bgm_type"), "upbeat-CANARY-ds10",
             "render-local params bgm_type must be none",
             ("upbeat-CANARY-ds10",)),
        ]
        for name, key_path, drift_value, expected_message, leaked in cases:
            with self.subTest(case=name):
                # Deep-copy the fixture and alter exactly one value.
                altered = json.loads(json.dumps(script_json_fixture))
                target = altered
                for key in key_path[:-1]:
                    target = target[key]
                target[key_path[-1]] = drift_value
                with open(script_json_target, "w", encoding="utf-8") as h:
                    json.dump(altered, h)

                before_tree = self.tree_snapshot(task_dir)
                with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                    pilot_prepare._verify_render_local_render(
                        draft, task_result
                    )
                message = str(ctx.exception)
                self.assertEqual(message, expected_message)
                for supplied in leaked:
                    self.assertNotIn(supplied, message)
                self.assertEqual(self.tree_snapshot(task_dir), before_tree)

    # -- material drift refusals ----------------------------------------------

    def test_render_material_drift_refused(self):
        (
            draft,
            script_json_target,
            script_json_fixture,
            output_target,
            _output_bytes,
        ) = self.build_verifiable_fixtures()
        staged = draft.staged
        task_dir = staged.task_dir
        # Task result, fixed parameters, script, and final-1.mp4 stay valid.
        task_result = {
            "task_id": staged.task_id,
            "state": const.TASK_STATE_COMPLETE,
            "progress": 100,
            "videos": [os.path.relpath(output_target, task_dir)],
        }
        valid_materials = script_json_fixture["params"]["video_materials"]
        match_msg = (
            "render-local params video_materials must match the staged "
            "materials"
        )

        cases = [
            ("missing material",
             valid_materials[:1],
             match_msg,
             (valid_materials[1]["url"],)),
            ("extra material",
             valid_materials + [
                 {"provider": "local",
                  "url": "materials/extra-CANARY-mx.mp4"}
             ],
             match_msg,
             ("extra-CANARY-mx",)),
            ("reversed order",
             [valid_materials[1], valid_materials[0]],
             "render-local material path disagrees with the staged copy",
             tuple(entry["url"] for entry in valid_materials)),
            ("non-local provider",
             [{"provider": "pexels-CANARY-mp",
               "url": valid_materials[0]["url"]},
              valid_materials[1]],
             "render-local material provider must be local",
             ("pexels-CANARY-mp",)),
            ("mismatched local path",
             [{"provider": "local", "url": "materials/wrong-CANARY-mm.mp4"},
              valid_materials[1]],
             "render-local material path disagrees with the staged copy",
             ("wrong-CANARY-mm",)),
            ("remote URL",
             [{"provider": "local",
               "url": "https://example.com/CANARY-mr/clip.mp4"},
              valid_materials[1]],
             "render-local material path must be a local path",
             ("https://example.com/CANARY-mr/clip.mp4",)),
            ("non-mapping entry",
             ["not-a-mapping-CANARY-me", valid_materials[1]],
             match_msg,
             ("not-a-mapping-CANARY-me",)),
        ]
        for name, materials_value, expected_message, leaked in cases:
            with self.subTest(case=name):
                # Deep-copy the fixture and alter only params.video_materials.
                altered = json.loads(json.dumps(script_json_fixture))
                altered["params"]["video_materials"] = json.loads(
                    json.dumps(materials_value)
                )
                with open(script_json_target, "w", encoding="utf-8") as h:
                    json.dump(altered, h)

                before_tree = self.tree_snapshot(task_dir)
                with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                    pilot_prepare._verify_render_local_render(
                        draft, task_result
                    )
                message = str(ctx.exception)
                self.assertEqual(message, expected_message)
                for supplied in leaked:
                    self.assertNotIn(supplied, message)
                self.assertEqual(self.tree_snapshot(task_dir), before_tree)

    # -- script.json file/shape refusals --------------------------------------

    def test_script_json_file_or_shape_refused(self):
        (
            draft,
            script_json_target,
            script_json_fixture,
            output_target,
            _output_bytes,
        ) = self.build_verifiable_fixtures()
        staged = draft.staged
        task_dir = staged.task_dir
        # Task result and final-1.mp4 stay otherwise valid in every subtest.
        task_result = {
            "task_id": staged.task_id,
            "state": const.TASK_STATE_COMPLETE,
            "progress": 100,
            "videos": [os.path.relpath(output_target, task_dir)],
        }

        def clear_script_json():
            if os.path.islink(script_json_target) or os.path.isfile(
                script_json_target
            ):
                os.unlink(script_json_target)
            elif os.path.isdir(script_json_target):
                os.rmdir(script_json_target)

        def write_raw(data: bytes):
            clear_script_json()
            with open(script_json_target, "wb") as handle:
                handle.write(data)

        def write_altered(payload):
            clear_script_json()
            with open(script_json_target, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)

        def fixture_copy():
            return json.loads(json.dumps(script_json_fixture))

        def fixture_drop_top(key):
            altered = fixture_copy()
            del altered[key]
            return altered

        def fixture_drop_param(key):
            altered = fixture_copy()
            del altered["params"][key]
            return altered

        def fixture_set(key_path, value):
            altered = fixture_copy()
            target = altered
            for key in key_path[:-1]:
                target = target[key]
            target[key_path[-1]] = value
            return altered

        file_msg = (
            "render-local script manifest must be an existing regular file"
        )
        shape_msg = "render-local script manifest has an unexpected shape"
        match_msg = (
            "render-local params video_materials must match the staged "
            "materials"
        )

        cases = [
            ("script.json missing",
             clear_script_json,
             file_msg,
             (script_json_target,)),
            ("script.json is a directory",
             lambda: (clear_script_json(), os.mkdir(script_json_target)),
             file_msg,
             (script_json_target,)),
            ("malformed JSON",
             lambda: write_raw(b'{"script": CANARY-sj4 not json'),
             "render-local script manifest is not valid JSON",
             ("CANARY-sj4", "Expecting")),
            ("top-level JSON is not an object",
             lambda: write_altered(["CANARY-sj5"]),
             "render-local script manifest must be a JSON object",
             ("CANARY-sj5",)),
            ("missing top-level script",
             lambda: write_altered(fixture_drop_top("script")),
             shape_msg,
             (staged.script_text,)),
            ("top-level script is not a string",
             lambda: write_altered(fixture_set(("script",), 123)),
             shape_msg,
             ()),
            ("missing params",
             lambda: write_altered(fixture_drop_top("params")),
             shape_msg,
             ()),
            ("params is not an object",
             lambda: write_altered(fixture_set(("params",), "CANARY-sj9")),
             shape_msg,
             ("CANARY-sj9",)),
            ("missing required fixed-profile field",
             lambda: write_altered(fixture_drop_param("video_source")),
             "render-local params video_source must be local",
             ()),
            ("video_materials is not a list",
             lambda: write_altered(
                 fixture_set(
                     ("params", "video_materials"), "materials-CANARY-sj11"
                 )
             ),
             match_msg,
             ("materials-CANARY-sj11",)),
        ]
        for name, setup, expected_message, leaked in cases:
            with self.subTest(case=name):
                setup()
                before_tree = self.tree_snapshot(task_dir)
                with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                    pilot_prepare._verify_render_local_render(
                        draft, task_result
                    )
                message = str(ctx.exception)
                self.assertEqual(message, expected_message)
                for supplied in leaked:
                    self.assertNotIn(supplied, message)
                # No new files; the deliberately altered fixture is untouched.
                self.assertEqual(self.tree_snapshot(task_dir), before_tree)

        # Symlinked script.json, where the platform permits creating one.
        with self.subTest(case="script.json symlinked"):
            clear_script_json()
            real_target = os.path.join(
                task_dir, "real-script-CANARY-sj3.json"
            )
            with open(real_target, "w", encoding="utf-8") as handle:
                json.dump(script_json_fixture, handle)
            try:
                os.symlink(real_target, script_json_target)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            before_tree = self.tree_snapshot(task_dir)
            with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                pilot_prepare._verify_render_local_render(
                    draft, task_result
                )
            message = str(ctx.exception)
            self.assertEqual(
                message,
                "render-local script manifest contains a link or junction",
            )
            for supplied in (script_json_target, real_target, "CANARY-sj3"):
                self.assertNotIn(supplied, message)
            self.assertEqual(self.tree_snapshot(task_dir), before_tree)

    # -- renderer output inventory refusals -----------------------------------

    def test_render_output_inventory_refused(self):
        (
            draft,
            _script_json_target,
            _script_json_fixture,
            output_target,
            output_bytes,
        ) = self.build_verifiable_fixtures()
        staged = draft.staged
        task_dir = staged.task_dir
        # script.json and the task result stay otherwise valid.
        task_result = {
            "task_id": staged.task_id,
            "state": const.TASK_STATE_COMPLETE,
            "progress": 100,
            "videos": [os.path.relpath(output_target, task_dir)],
        }

        output_names = (
            "final-1.mp4",
            "final-2.mp4",
            "final-1__NEEDS_HUMAN_REVIEW.mp4",
            "notes__NEEDS_HUMAN_REVIEW-CANARY-o7.txt",
            "real-output-CANARY-o3.mp4",
        )

        def clear_output_fixtures():
            for name in output_names:
                full = os.path.join(task_dir, name)
                if os.path.islink(full) or os.path.isfile(full):
                    os.unlink(full)
                elif os.path.isdir(full):
                    os.rmdir(full)

        def write_rel(name, data):
            with open(os.path.join(task_dir, name), "wb") as handle:
                handle.write(data)

        marked_msg = (
            "render-local marked output must not exist before verification"
        )
        cases = [
            ("final-1.mp4 missing",
             clear_output_fixtures,
             "render-local output final-1.mp4 is missing",
             (output_target,)),
            ("final-1.mp4 is a directory",
             lambda: (clear_output_fixtures(), os.mkdir(output_target)),
             "render-local output final-1.mp4 must be an existing regular "
             "file",
             (output_target,)),
            ("extra final-2.mp4",
             lambda: (clear_output_fixtures(),
                      write_rel("final-1.mp4", output_bytes),
                      write_rel("final-2.mp4", b"extra-CANARY-o4")),
             "render-local unexpected extra final video output",
             ("final-2.mp4", "extra-CANARY-o4")),
            ("only final-2.mp4 exists",
             lambda: (clear_output_fixtures(),
                      write_rel("final-2.mp4", b"extra-CANARY-o5")),
             "render-local output final-1.mp4 is missing",
             (output_target, "final-2.mp4", "CANARY-o5")),
            ("pre-existing marked final output",
             lambda: (clear_output_fixtures(),
                      write_rel("final-1.mp4", output_bytes),
                      write_rel("final-1__NEEDS_HUMAN_REVIEW.mp4",
                                b"marked-CANARY-o6")),
             marked_msg,
             ("final-1__NEEDS_HUMAN_REVIEW.mp4",
              prov.NEEDS_HUMAN_REVIEW_MARKER, "CANARY-o6")),
            ("another marked filename",
             lambda: (clear_output_fixtures(),
                      write_rel("final-1.mp4", output_bytes),
                      write_rel("notes__NEEDS_HUMAN_REVIEW-CANARY-o7.txt",
                                b"marked")),
             marked_msg,
             ("notes__NEEDS_HUMAN_REVIEW-CANARY-o7.txt",
              prov.NEEDS_HUMAN_REVIEW_MARKER, "CANARY-o7")),
        ]
        for name, setup, expected_message, leaked in cases:
            with self.subTest(case=name):
                setup()
                before_tree = self.tree_snapshot(task_dir)
                with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                    pilot_prepare._verify_render_local_render(
                        draft, task_result
                    )
                message = str(ctx.exception)
                self.assertEqual(message, expected_message)
                for supplied in leaked:
                    self.assertNotIn(supplied, message)
                # Verification creates no marked file or other output; the
                # deliberately altered tree stays byte-for-byte unchanged.
                self.assertEqual(self.tree_snapshot(task_dir), before_tree)

        # Symlinked final-1.mp4, where the platform permits creating one.
        with self.subTest(case="final-1.mp4 symlinked"):
            clear_output_fixtures()
            real_output = os.path.join(
                task_dir, "real-output-CANARY-o3.mp4"
            )
            with open(real_output, "wb") as handle:
                handle.write(output_bytes)
            try:
                os.symlink(real_output, output_target)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            before_tree = self.tree_snapshot(task_dir)
            with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                pilot_prepare._verify_render_local_render(
                    draft, task_result
                )
            message = str(ctx.exception)
            self.assertEqual(
                message, "render-local output contains a link or junction"
            )
            for supplied in (output_target, real_output, "CANARY-o3"):
                self.assertNotIn(supplied, message)
            self.assertEqual(self.tree_snapshot(task_dir), before_tree)

        # Injected streamed-hash read failure.
        with self.subTest(case="streamed-hash read failure"):
            clear_output_fixtures()
            write_rel("final-1.mp4", output_bytes)
            before_tree = self.tree_snapshot(task_dir)
            with patch(
                "app.services.provenance.sha256_file_streamed",
                side_effect=OSError("injected hash failure CANARY-o8"),
            ):
                with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                    pilot_prepare._verify_render_local_render(
                        draft, task_result
                    )
            message = str(ctx.exception)
            self.assertEqual(
                message, "render-local output must be readable for hashing"
            )
            for supplied in (output_target, "injected", "CANARY-o8"):
                self.assertNotIn(supplied, message)
            self.assertEqual(self.tree_snapshot(task_dir), before_tree)


# ---------------------------------------------------------------------------
# Render-local marked-output finalization (happy path)
# ---------------------------------------------------------------------------


class TestRenderLocalMarkedOutputFinalization(_PrepareTestBase):
    """Happy-path test for _finalize_render_local_marked_output.

    Builds real verified evidence with the existing helpers inside an
    isolated temporary storage root (pilot_prepare.__file__ points at the
    sandbox; utils.get_uuid returns a known canonical UUID).
    """

    KNOWN_TASK_ID = "12345678-1234-5678-1234-567812345678"

    def setUp(self):
        super().setUp()
        self._file_patch = patch.object(
            pilot_prepare,
            "__file__",
            os.path.join(self.root, "pilot_prepare.py"),
        )
        self._file_patch.start()
        self._uuid_patch = patch(
            "app.utils.utils.get_uuid", return_value=self.KNOWN_TASK_ID
        )
        self._uuid_patch.start()

    def tearDown(self):
        self._uuid_patch.stop()
        self._file_patch.stop()
        super().tearDown()

    # -- helpers ------------------------------------------------------------

    def write_source(self, name: str, data: bytes) -> str:
        path = os.path.join(self.root, "src", name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def tree_snapshot(self, root):
        dirs = set()
        files = {}
        for dirpath, dirnames, filenames in os.walk(root):
            for dirname in dirnames:
                dirs.add(
                    os.path.relpath(os.path.join(dirpath, dirname), root)
                )
            for filename in filenames:
                full = os.path.join(dirpath, filename)
                with open(full, "rb") as handle:
                    files[os.path.relpath(full, root)] = handle.read()
        return dirs, files

    def build_verified_render(self):
        """Real validate/load/stage/draft chain plus verified evidence."""
        script_bytes = b"Bitcoin basics finalization script.\n"
        script_src = self.write_source("script.txt", script_bytes)
        material_srcs = [
            self.write_source("clip-b.mp4", b"material-bytes-b"),
            self.write_source("clip-a.mp4", b"material-bytes-a"),
        ]
        request = pilot_prepare._validate_render_local_request(
            topic="finalization topic",
            script_path=script_src,
            material_paths=material_srcs,
            license_names=["CC0", "ODbL"],
            license_evidence=["ref-b", "ref-a"],
            claims=["Bitcoin supply is capped at 21 million."],
            claim_sources=["https://bitcoin.org/bitcoin.pdf"],
        )
        loaded = pilot_prepare._load_render_local_inputs(request)
        staged = pilot_prepare._stage_render_local_task(loaded)
        draft = pilot_prepare._prepare_render_local_draft(staged)
        task_dir = staged.task_dir

        script_json = {
            "script": staged.script_text,
            "params": {
                "video_script": staged.script_text,
                "video_source": "local",
                "video_count": 1,
                "video_aspect": VideoAspect.landscape.value,
                "video_concat_mode": VideoConcatMode.sequential.value,
                "video_clip_duration": 5,
                "voice_name": voice.NO_VOICE_NAME,
                "subtitle_enabled": False,
                "bgm_type": "none",
                "video_materials": [
                    {
                        "provider": "local",
                        "url": os.path.relpath(staged_path, task_dir),
                    }
                    for staged_path, _ in staged.materials
                ],
            },
        }
        with open(os.path.join(task_dir, "script.json"), "w",
                  encoding="utf-8") as handle:
            json.dump(script_json, handle)

        output_bytes = b"final-video-bytes\x00\x01\x02\xff"
        output_target = os.path.join(task_dir, "final-1.mp4")
        with open(output_target, "wb") as handle:
            handle.write(output_bytes)

        task_result = {
            "task_id": staged.task_id,
            "state": const.TASK_STATE_COMPLETE,
            "progress": 100,
            "videos": [os.path.relpath(output_target, task_dir)],
        }
        verified = pilot_prepare._verify_render_local_render(
            draft, task_result
        )
        return verified, output_bytes

    # -- happy path -----------------------------------------------------------

    def test_finalize_marked_output_happy_path(self):
        verified, output_bytes = self.build_verified_render()
        draft = verified.draft
        task_dir = draft.staged.task_dir

        before_dirs, before_files = self.tree_snapshot(task_dir)
        finalized = pilot_prepare._finalize_render_local_marked_output(
            verified
        )
        after_dirs, after_files = self.tree_snapshot(task_dir)

        # Verified evidence is carried through identically.
        self.assertIs(finalized.verified, verified)
        self.assertIs(finalized.verified.draft, draft)

        # Original final-1.mp4 remains byte-identical.
        with open(verified.output_path, "rb") as handle:
            self.assertEqual(handle.read(), output_bytes)

        # Marked filename comes from provenance.marked_filename.
        marked_name = prov.marked_filename("final-1.mp4")
        self.assertEqual(marked_name, "final-1__NEEDS_HUMAN_REVIEW.mp4")
        self.assertEqual(
            os.path.basename(finalized.marked_output_path), marked_name
        )
        self.assertEqual(
            os.path.dirname(finalized.marked_output_path), task_dir
        )

        # Marked bytes/hash equal the original and the verified hash.
        with open(finalized.marked_output_path, "rb") as handle:
            self.assertEqual(handle.read(), output_bytes)
        self.assertEqual(
            finalized.marked_output_sha256,
            hashlib.sha256(output_bytes).hexdigest(),
        )
        self.assertEqual(
            finalized.marked_output_sha256, verified.output_sha256
        )

        # Durable manifest validates and matches the on-disk reread.
        prov.validate_manifest(finalized.manifest)
        self.assertEqual(
            finalized.manifest_path,
            os.path.join(task_dir, "provenance_manifest.json"),
        )
        with open(finalized.manifest_path, encoding="utf-8") as handle:
            durable_final = json.load(handle)
        self.assertEqual(durable_final, finalized.manifest)

        # Output section points to the marked file with the correct hash.
        output = finalized.manifest["output"]
        self.assertEqual(output["local_path"], marked_name)
        self.assertEqual(output["sha256"], verified.output_sha256)
        self.assertEqual(output["filename_marker"], marked_name)
        self.assertFalse(output["visible_watermark_required"])

        # review_status remains NEEDS_HUMAN_REVIEW everywhere.
        self.assertEqual(output["review_status"], "NEEDS_HUMAN_REVIEW")
        self.assertEqual(
            finalized.manifest["task"]["review_status"],
            "NEEDS_HUMAN_REVIEW",
        )

        # Every prepared section and immutable timestamp is preserved.
        for section in (
            "task", "script", "assets", "factual_claims", "ai_generations"
        ):
            self.assertEqual(
                finalized.manifest[section], draft.manifest[section]
            )
        self.assertEqual(
            finalized.manifest["task"]["created_at"],
            draft.manifest["task"]["created_at"],
        )

        # Only the marked output and the manifest differ from the tree.
        self.assertEqual(after_dirs, before_dirs)
        self.assertEqual(
            set(after_files) - set(before_files), {marked_name}
        )
        self.assertEqual(set(before_files) - set(after_files), set())
        changed = {
            name
            for name in before_files
            if before_files[name] != after_files[name]
        }
        self.assertEqual(changed, {"provenance_manifest.json"})

        # pilot_review status/audit assembly accepts the task.
        state = pilot_review._assemble_state(task_dir)
        self.assertEqual(state.get("failures"), [])
        self.assertEqual(state.get("script_status"), "ok")
        self.assertEqual(state.get("asset_statuses"), ["ok", "ok"])
        self.assertEqual(state.get("output_status"), "ok")

        # Returned dataclass is immutable.
        with self.assertRaises(dataclasses.FrozenInstanceError):
            finalized.marked_output_sha256 = "mutated"

    # -- pre-mutation refusal: marked target already exists -------------------

    def test_finalize_refuses_existing_marked_output(self):
        verified, output_bytes = self.build_verified_render()
        draft = verified.draft
        task_dir = draft.staged.task_dir

        # Pre-create the exact marked target with canary bytes.
        marked_name = prov.marked_filename("final-1.mp4")
        marked_path = os.path.join(task_dir, marked_name)
        canary = b"preexisting-marked-CANARY-mx1"
        with open(marked_path, "wb") as handle:
            handle.write(canary)
        with open(draft.manifest_path, "rb") as handle:
            manifest_before = handle.read()
        before_dirs, before_files = self.tree_snapshot(task_dir)

        with patch("shutil.rmtree") as rmtree_mock:
            with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                pilot_prepare._finalize_render_local_marked_output(verified)

        # Exact static refusal; no canary or path leaks into the message.
        message = str(ctx.exception)
        self.assertEqual(
            message, "render-local marked output already exists"
        )
        self.assertIsNone(ctx.exception.__cause__)
        self.assertNotIn("CANARY-mx1", message)
        self.assertNotIn(marked_name, message)
        self.assertNotIn(marked_path, message)
        rmtree_mock.assert_not_called()

        # Complete task tree is byte-for-byte unchanged.
        after_dirs, after_files = self.tree_snapshot(task_dir)
        self.assertEqual(after_dirs, before_dirs)
        self.assertEqual(after_files, before_files)

        # Pre-existing marked file unchanged.
        with open(marked_path, "rb") as handle:
            self.assertEqual(handle.read(), canary)

        # Original final-1.mp4 unchanged.
        with open(verified.output_path, "rb") as handle:
            self.assertEqual(handle.read(), output_bytes)

        # Manifest unchanged (still the prepared draft evidence).
        with open(draft.manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), manifest_before)

    # -- pre-replacement refusal: verified output hash drifted ----------------

    def test_finalize_refuses_output_hash_drift(self):
        verified, output_bytes = self.build_verified_render()
        draft = verified.draft
        task_dir = draft.staged.task_dir

        # Drift the verified output bytes after verification.
        drifted = b"drifted-output-CANARY-d1"
        self.assertNotEqual(drifted, output_bytes)
        with open(verified.output_path, "wb") as handle:
            handle.write(drifted)
        with open(draft.manifest_path, "rb") as handle:
            manifest_before = handle.read()
        before_dirs, before_files = self.tree_snapshot(task_dir)

        with patch("shutil.rmtree") as rmtree_mock:
            with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                pilot_prepare._finalize_render_local_marked_output(verified)

        # Exact static refusal; no drifted bytes or paths leak.
        message = str(ctx.exception)
        self.assertEqual(
            message,
            "render-local verified output hash changed since verification",
        )
        self.assertIsNone(ctx.exception.__cause__)
        self.assertNotIn("CANARY-d1", message)
        self.assertNotIn(verified.output_path, message)
        self.assertNotIn(
            prov.marked_filename("final-1.mp4"), message
        )
        rmtree_mock.assert_not_called()

        # Complete task tree is byte-for-byte unchanged.
        after_dirs, after_files = self.tree_snapshot(task_dir)
        self.assertEqual(after_dirs, before_dirs)
        self.assertEqual(after_files, before_files)

        # Altered final-1.mp4 is preserved untouched.
        with open(verified.output_path, "rb") as handle:
            self.assertEqual(handle.read(), drifted)

        # No marked output was created (copied target unlinked).
        marked_path = os.path.join(
            task_dir, prov.marked_filename("final-1.mp4")
        )
        self.assertFalse(os.path.lexists(marked_path))

        # Manifest byte-for-byte unchanged.
        with open(draft.manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), manifest_before)

    # -- pre-mutation refusal: durable manifest drifted -----------------------

    def test_finalize_refuses_durable_manifest_drift(self):
        verified, output_bytes = self.build_verified_render()
        draft = verified.draft
        task_dir = draft.staged.task_dir

        # Drift one non-secret manifest field, keeping it schema-valid.
        with open(draft.manifest_path, encoding="utf-8") as handle:
            durable = json.load(handle)
        durable["task"]["topic"] = "drifted topic CANARY-mf1"
        prov.write_manifest_atomic(task_dir, durable)
        with open(draft.manifest_path, "rb") as handle:
            altered_manifest = handle.read()
        before_dirs, before_files = self.tree_snapshot(task_dir)

        with patch("shutil.rmtree") as rmtree_mock:
            with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                pilot_prepare._finalize_render_local_marked_output(verified)

        # Exact static refusal; no altered value or paths leak.
        message = str(ctx.exception)
        self.assertEqual(
            message,
            "render-local durable manifest disagrees with the prepared "
            "draft",
        )
        self.assertIsNone(ctx.exception.__cause__)
        self.assertNotIn("CANARY-mf1", message)
        self.assertNotIn("drifted topic", message)
        self.assertNotIn(draft.manifest_path, message)
        rmtree_mock.assert_not_called()

        # Complete task tree is byte-for-byte unchanged.
        after_dirs, after_files = self.tree_snapshot(task_dir)
        self.assertEqual(after_dirs, before_dirs)
        self.assertEqual(after_files, before_files)

        # Altered durable manifest is preserved exactly.
        with open(draft.manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), altered_manifest)

        # Original final-1.mp4 unchanged.
        with open(verified.output_path, "rb") as handle:
            self.assertEqual(handle.read(), output_bytes)

        # No marked output was created.
        marked_path = os.path.join(
            task_dir, prov.marked_filename("final-1.mp4")
        )
        self.assertFalse(os.path.lexists(marked_path))

    # -- pre-mutation refusal: durable script hash drifted --------------------

    def test_finalize_refuses_durable_script_drift(self):
        verified, output_bytes = self.build_verified_render()
        draft = verified.draft
        staged = draft.staged
        task_dir = staged.task_dir

        # Drift the staged script bytes after verification (valid UTF-8).
        drifted_script = b"drifted script CANARY-s1\n"
        with open(staged.script_path, "wb") as handle:
            handle.write(drifted_script)
        with open(draft.manifest_path, "rb") as handle:
            manifest_before = handle.read()
        before_dirs, before_files = self.tree_snapshot(task_dir)

        with patch("shutil.rmtree") as rmtree_mock:
            with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                pilot_prepare._finalize_render_local_marked_output(verified)

        # Exact static refusal; no altered content or paths leak.
        message = str(ctx.exception)
        self.assertEqual(
            message,
            "render-local staged script hash changed since preparation",
        )
        self.assertIsNone(ctx.exception.__cause__)
        self.assertNotIn("CANARY-s1", message)
        self.assertNotIn(staged.script_path, message)
        rmtree_mock.assert_not_called()

        # Complete task tree is byte-for-byte unchanged.
        after_dirs, after_files = self.tree_snapshot(task_dir)
        self.assertEqual(after_dirs, before_dirs)
        self.assertEqual(after_files, before_files)

        # Altered script is preserved exactly.
        with open(staged.script_path, "rb") as handle:
            self.assertEqual(handle.read(), drifted_script)

        # Durable manifest unchanged.
        with open(draft.manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), manifest_before)

        # Original final-1.mp4 unchanged.
        with open(verified.output_path, "rb") as handle:
            self.assertEqual(handle.read(), output_bytes)

        # No marked output was created.
        marked_path = os.path.join(
            task_dir, prov.marked_filename("final-1.mp4")
        )
        self.assertFalse(os.path.lexists(marked_path))

    # -- pre-mutation refusal: durable material hash drifted ------------------

    def test_finalize_refuses_durable_material_drift(self):
        verified, output_bytes = self.build_verified_render()
        draft = verified.draft
        staged = draft.staged
        task_dir = staged.task_dir

        # Drift one task-local material after verification.
        target_path, _target_hash = staged.materials[0]
        other_path, _other_hash = staged.materials[1]
        drifted_material = b"drifted-material-CANARY-m1"
        with open(other_path, "rb") as handle:
            other_before = handle.read()
        with open(target_path, "wb") as handle:
            handle.write(drifted_material)
        with open(draft.manifest_path, "rb") as handle:
            manifest_before = handle.read()
        before_dirs, before_files = self.tree_snapshot(task_dir)

        with patch("shutil.rmtree") as rmtree_mock:
            with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                pilot_prepare._finalize_render_local_marked_output(verified)

        # Exact static refusal; no altered content or paths leak.
        message = str(ctx.exception)
        self.assertEqual(
            message,
            "render-local staged material hash changed since preparation",
        )
        self.assertIsNone(ctx.exception.__cause__)
        self.assertNotIn("CANARY-m1", message)
        self.assertNotIn(target_path, message)
        rmtree_mock.assert_not_called()

        # Complete task tree is byte-for-byte unchanged.
        after_dirs, after_files = self.tree_snapshot(task_dir)
        self.assertEqual(after_dirs, before_dirs)
        self.assertEqual(after_files, before_files)

        # Altered material is preserved exactly; the other is unchanged.
        with open(target_path, "rb") as handle:
            self.assertEqual(handle.read(), drifted_material)
        with open(other_path, "rb") as handle:
            self.assertEqual(handle.read(), other_before)

        # Durable manifest unchanged.
        with open(draft.manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), manifest_before)

        # Original final-1.mp4 unchanged.
        with open(verified.output_path, "rb") as handle:
            self.assertEqual(handle.read(), output_bytes)

        # No marked output was created.
        marked_path = os.path.join(
            task_dir, prov.marked_filename("final-1.mp4")
        )
        self.assertFalse(os.path.lexists(marked_path))

    # -- injected failure during the marked-output copy -----------------------

    def test_finalize_copy_failure_preserves_draft(self):
        verified, output_bytes = self.build_verified_render()
        draft = verified.draft
        task_dir = draft.staged.task_dir
        marked_name = prov.marked_filename("final-1.mp4")
        marked_path = os.path.join(task_dir, marked_name)

        with open(draft.manifest_path, "rb") as handle:
            manifest_before = handle.read()
        before_dirs, before_files = self.tree_snapshot(task_dir)

        # Fail only the narrow marked-output copy seam.
        real_write = pilot_prepare._atomic_write_stream

        def flaky(target, chunks):
            if target.endswith(marked_name):
                raise OSError("injected copy failure CANARY-c1")
            return real_write(target, chunks)

        with patch("shutil.rmtree") as rmtree_mock:
            with patch.object(
                pilot_prepare, "_atomic_write_stream", side_effect=flaky
            ):
                with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                    pilot_prepare._finalize_render_local_marked_output(
                        verified
                    )

        # Exact static refusal; native failure survives only as the cause.
        message = str(ctx.exception)
        self.assertEqual(message, "render-local finalization failed")
        self.assertIsInstance(ctx.exception.__cause__, OSError)
        self.assertNotIn("CANARY-c1", message)
        self.assertNotIn("injected copy failure", message)
        self.assertNotIn(marked_name, message)
        self.assertNotIn(marked_path, message)
        rmtree_mock.assert_not_called()

        # Complete task tree is byte-for-byte unchanged.
        after_dirs, after_files = self.tree_snapshot(task_dir)
        self.assertEqual(after_dirs, before_dirs)
        self.assertEqual(after_files, before_files)

        # Original final-1.mp4 unchanged; manifest/evidence unchanged.
        with open(verified.output_path, "rb") as handle:
            self.assertEqual(handle.read(), output_bytes)
        with open(draft.manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), manifest_before)

        # No marked output or temporary file survives.
        self.assertFalse(os.path.lexists(marked_path))

    # -- injected failure hashing the newly marked output ---------------------

    def test_finalize_marked_hash_failure_preserves_draft(self):
        verified, output_bytes = self.build_verified_render()
        draft = verified.draft
        task_dir = draft.staged.task_dir
        marked_name = prov.marked_filename("final-1.mp4")
        marked_path = os.path.join(task_dir, marked_name)

        with open(draft.manifest_path, "rb") as handle:
            manifest_before = handle.read()
        before_dirs, before_files = self.tree_snapshot(task_dir)

        # Fail only hashing the newly marked output; other hashing is real.
        real_hash = prov.sha256_file_streamed

        def flaky_hash(path, *args, **kwargs):
            if str(path).endswith(marked_name):
                raise OSError("injected hash failure CANARY-h1")
            return real_hash(path, *args, **kwargs)

        with patch("shutil.rmtree") as rmtree_mock:
            with patch.object(
                prov, "sha256_file_streamed", side_effect=flaky_hash
            ):
                with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                    pilot_prepare._finalize_render_local_marked_output(
                        verified
                    )

        # Exact static refusal; native failure survives only as the cause.
        message = str(ctx.exception)
        self.assertEqual(message, "render-local finalization failed")
        self.assertIsInstance(ctx.exception.__cause__, OSError)
        self.assertNotIn("CANARY-h1", message)
        self.assertNotIn("injected hash failure", message)
        self.assertNotIn(marked_name, message)
        self.assertNotIn(marked_path, message)
        rmtree_mock.assert_not_called()

        # Complete task tree restored byte-for-byte.
        after_dirs, after_files = self.tree_snapshot(task_dir)
        self.assertEqual(after_dirs, before_dirs)
        self.assertEqual(after_files, before_files)

        # Original final-1.mp4 unchanged; manifest/evidence unchanged.
        with open(verified.output_path, "rb") as handle:
            self.assertEqual(handle.read(), output_bytes)
        with open(draft.manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), manifest_before)

        # Created marked output and all temps are removed.
        self.assertFalse(os.path.lexists(marked_path))

    # -- injected failure building the output section -------------------------

    def test_finalize_output_builder_failure_preserves_draft(self):
        verified, output_bytes = self.build_verified_render()
        draft = verified.draft
        task_dir = draft.staged.task_dir
        marked_name = prov.marked_filename("final-1.mp4")
        marked_path = os.path.join(task_dir, marked_name)

        with open(draft.manifest_path, "rb") as handle:
            manifest_before = handle.read()
        before_dirs, before_files = self.tree_snapshot(task_dir)

        with patch("shutil.rmtree") as rmtree_mock:
            with patch.object(
                prov,
                "build_output_section",
                side_effect=prov.ProvenanceError(
                    "injected builder failure CANARY-b1"
                ),
            ):
                with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                    pilot_prepare._finalize_render_local_marked_output(
                        verified
                    )

        # Exact static refusal; native failure survives only as the cause.
        message = str(ctx.exception)
        self.assertEqual(message, "render-local finalization failed")
        self.assertIsInstance(ctx.exception.__cause__, prov.ProvenanceError)
        self.assertNotIn("CANARY-b1", message)
        self.assertNotIn("injected builder failure", message)
        self.assertNotIn(marked_name, message)
        self.assertNotIn(marked_path, message)
        rmtree_mock.assert_not_called()

        # Complete task tree restored byte-for-byte.
        after_dirs, after_files = self.tree_snapshot(task_dir)
        self.assertEqual(after_dirs, before_dirs)
        self.assertEqual(after_files, before_files)

        # Original final-1.mp4 unchanged; manifest/evidence unchanged.
        with open(verified.output_path, "rb") as handle:
            self.assertEqual(handle.read(), output_bytes)
        with open(draft.manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), manifest_before)

        # Created marked output and all temps are removed.
        self.assertFalse(os.path.lexists(marked_path))

    # -- injected failure during the atomic manifest replacement --------------

    def test_finalize_manifest_write_failure_preserves_draft(self):
        verified, output_bytes = self.build_verified_render()
        draft = verified.draft
        task_dir = draft.staged.task_dir
        marked_name = prov.marked_filename("final-1.mp4")
        marked_path = os.path.join(task_dir, marked_name)

        with open(draft.manifest_path, "rb") as handle:
            manifest_before = handle.read()
        before_dirs, before_files = self.tree_snapshot(task_dir)

        with patch("shutil.rmtree") as rmtree_mock:
            with patch.object(
                prov,
                "write_manifest_atomic",
                side_effect=OSError(
                    "injected manifest write failure CANARY-w1"
                ),
            ):
                with self.assertRaises(pilot_prepare.PrepareError) as ctx:
                    pilot_prepare._finalize_render_local_marked_output(
                        verified
                    )

        # Exact static refusal; native failure survives only as the cause.
        message = str(ctx.exception)
        self.assertEqual(message, "render-local finalization failed")
        self.assertIsInstance(ctx.exception.__cause__, OSError)
        self.assertNotIn("CANARY-w1", message)
        self.assertNotIn("injected manifest write failure", message)
        self.assertNotIn(marked_name, message)
        self.assertNotIn(marked_path, message)
        self.assertNotIn(draft.manifest_path, message)
        rmtree_mock.assert_not_called()

        # Complete task tree restored byte-for-byte.
        after_dirs, after_files = self.tree_snapshot(task_dir)
        self.assertEqual(after_dirs, before_dirs)
        self.assertEqual(after_files, before_files)

        # Original manifest bytes unchanged.
        with open(draft.manifest_path, "rb") as handle:
            self.assertEqual(handle.read(), manifest_before)

        # Original final-1.mp4 and prepared evidence unchanged.
        with open(verified.output_path, "rb") as handle:
            self.assertEqual(handle.read(), output_bytes)

        # Created marked output and all temps are removed.
        self.assertFalse(os.path.lexists(marked_path))

    # -- injected failure during post-replacement durable verification --------

    def test_finalize_durable_verification_failure_restores_draft(self):
        verified, output_bytes = self.build_verified_render()
        draft = verified.draft
        task_dir = draft.staged.task_dir
        marked_name = prov.marked_filename("final-1.mp4")
        marked_path = os.path.join(task_dir, marked_name)

        with open(draft.manifest_path, "rb") as handle:
            manifest_before = handle.read()
        before_dirs, before_files = self.tree_snapshot(task_dir)

        # Fail only the durable verification after the finalized manifest
        # has replaced the draft; restoration uses the real implementation.
        real_validate = prov.validate_manifest
        real_write = prov.write_manifest_atomic
        replaced = []

        def tracking_write(*args, **kwargs):
            result = real_write(*args, **kwargs)
            replaced.append(True)
            return result

        def flaky_validate(manifest):
            if replaced and manifest.get("output") is not None:
                raise prov.ProvenanceError(
                    "injected durable verification failure CANARY-v1"
                )
            return real_validate(manifest)

        with patch("shutil.rmtree") as rmtree_mock:
            with patch.object(
                prov, "write_manifest_atomic", side_effect=tracking_write
            ):
                with patch.object(
                    prov, "validate_manifest", side_effect=flaky_validate
                ):
                    with self.assertRaises(
                        pilot_prepare.PrepareError
                    ) as ctx:
                        pilot_prepare._finalize_render_local_marked_output(
                            verified
                        )

        # The finalized manifest replacement was reached.
        self.assertTrue(replaced)

        # Exact static refusal; injected failure survives only as the cause.
        message = str(ctx.exception)
        self.assertEqual(message, "render-local finalization failed")
        self.assertIsInstance(ctx.exception.__cause__, prov.ProvenanceError)
        self.assertNotIn("CANARY-v1", message)
        self.assertNotIn("injected durable verification failure", message)
        self.assertNotIn(marked_name, message)
        self.assertNotIn(marked_path, message)
        self.assertNotIn(draft.manifest_path, message)
        rmtree_mock.assert_not_called()

        # Original manifest restored byte-for-byte and validates.
        with open(draft.manifest_path, "rb") as handle:
            restored_bytes = handle.read()
        self.assertEqual(restored_bytes, manifest_before)
        prov.validate_manifest(json.loads(restored_bytes))

        # Marked output removed; original final and evidence unchanged.
        self.assertFalse(os.path.lexists(marked_path))
        with open(verified.output_path, "rb") as handle:
            self.assertEqual(handle.read(), output_bytes)

        # Complete tree restored byte-for-byte; no temps survive.
        after_dirs, after_files = self.tree_snapshot(task_dir)
        self.assertEqual(after_dirs, before_dirs)
        self.assertEqual(after_files, before_files)


# ---------------------------------------------------------------------------
# Render-local fixed render-parameter builder (in-memory)
# ---------------------------------------------------------------------------


class TestBuildRenderLocalVideoParams(_PrepareTestBase):
    """In-memory unit test for _build_render_local_video_params."""

    def test_build_render_local_video_params_fixed_values(self):
        task_dir = os.path.join("storage", "tasks", "task-fixed")
        script_text = "fixed params script CANARY-p1.\n"
        script_bytes = script_text.encode("utf-8")
        request = pilot_prepare.RenderLocalRequest(
            topic="fixed params topic CANARY-p2",
            script_path="src/script.txt",
            materials=(
                pilot_prepare.RenderLocalMaterialRequest(
                    path="src/clip-b.mp4",
                    license_name="CC0",
                    license_evidence="ref-b",
                ),
                pilot_prepare.RenderLocalMaterialRequest(
                    path="src/clip-a.mp4",
                    license_name="ODbL",
                    license_evidence="ref-a",
                ),
            ),
            claims=(("claim one", "https://example.org/source"),),
        )
        loaded = pilot_prepare.RenderLocalLoadedInputs(
            request=request,
            script_path=request.script_path,
            script_bytes=script_bytes,
            script_text=script_text,
            material_paths=tuple(m.path for m in request.materials),
        )
        staged_paths = (
            os.path.join(task_dir, "materials", "clip-b.mp4"),
            os.path.join(task_dir, "materials", "clip-a.mp4"),
        )
        staged = pilot_prepare.RenderLocalStagedTask(
            loaded=loaded,
            task_id="task-fixed",
            task_dir=task_dir,
            script_path=os.path.join(task_dir, "script.md"),
            script_sha256=hashlib.sha256(script_bytes).hexdigest(),
            script_text=script_text,
            materials=(
                (staged_paths[0], "hash-b"),
                (staged_paths[1], "hash-a"),
            ),
            created_paths=(),
        )
        draft = pilot_prepare.RenderLocalPreparedDraft(
            staged=staged,
            manifest_path=os.path.join(
                task_dir, "provenance_manifest.json"
            ),
            manifest={},
        )

        forbidden_prefixes = ("app.services.task",)
        before = {
            name
            for name in sys.modules
            if name.startswith(forbidden_prefixes)
        }
        with patch.object(
            pilot_prepare, "_require_pilot_policy"
        ) as policy_mock:
            with patch(
                "builtins.open",
                side_effect=AssertionError("filesystem access"),
            ):
                params = pilot_prepare._build_render_local_video_params(
                    draft
                )
        after = {
            name
            for name in sys.modules
            if name.startswith(forbidden_prefixes)
        }

        # No policy call, no task import, no filesystem access.
        policy_mock.assert_not_called()
        self.assertEqual(after - before, set())

        # Fixed render-local values.
        self.assertEqual(
            params.video_subject, "fixed params topic CANARY-p2"
        )
        self.assertEqual(params.video_script, script_text)
        self.assertEqual(params.video_script.encode("utf-8"), script_bytes)
        self.assertEqual(params.video_source, "local")
        self.assertEqual(
            [m.provider for m in params.video_materials],
            ["local", "local"],
        )
        self.assertEqual(
            [m.url for m in params.video_materials],
            [
                os.path.relpath(staged_paths[0], task_dir),
                os.path.relpath(staged_paths[1], task_dir),
            ],
        )
        self.assertEqual(params.video_count, 1)
        self.assertEqual(params.video_aspect, VideoAspect.landscape.value)
        self.assertEqual(
            params.video_concat_mode, VideoConcatMode.sequential.value
        )
        self.assertEqual(params.video_clip_duration, 5)
        self.assertEqual(params.voice_name, voice.NO_VOICE_NAME)
        self.assertFalse(params.subtitle_enabled)
        self.assertEqual(params.bgm_type, "none")

        # Input dataclasses are unchanged (identical frozen objects).
        self.assertIs(draft.staged, staged)
        self.assertIs(staged.loaded, loaded)
        self.assertIs(loaded.request, request)
        self.assertEqual(staged.script_text, script_text)
        self.assertEqual(
            tuple(path for path, _ in staged.materials), staged_paths
        )


# ---------------------------------------------------------------------------
# Render-local orchestrator wiring (all stages stubbed)
# ---------------------------------------------------------------------------


class TestRunRenderLocalTaskOrchestration(_PrepareTestBase):
    """Happy-path order/identity test for _run_render_local_task."""

    def test_run_render_local_task_order_and_identity(self):
        import app.services as app_services

        order = []
        calls = {}

        def record(name, result):
            def stage(*args, **kwargs):
                order.append(name)
                calls[name] = (args, kwargs)
                return result

            return stage

        sentinel_request = object()
        sentinel_loaded = object()
        sentinel_staged = unittest.mock.Mock()
        sentinel_staged.task_id = "staged-task-id-CANARY-o2"
        sentinel_draft = object()
        sentinel_params = object()
        sentinel_task_result = object()
        sentinel_verified = object()
        sentinel_finalized = object()

        raw = dict(
            topic="orch topic CANARY-o1",
            script_path="src/script.txt",
            material_paths=["m1", "m2"],
            license_names=["CC0", "ODbL"],
            license_evidence=["e1", "e2"],
            claims=["c1"],
            claim_sources=["s1"],
        )

        start_mock = unittest.mock.Mock(
            side_effect=record("task.start", sentinel_task_result)
        )
        fake_task_module = unittest.mock.Mock()
        fake_task_module.start = start_mock

        before = {
            name
            for name in sys.modules
            if name.startswith("app.services.task")
        }
        with patch.object(
            pilot_prepare,
            "_validate_render_local_request",
            side_effect=record("validate", sentinel_request),
        ) as validate_mock, patch.object(
            pilot_prepare,
            "_load_render_local_inputs",
            side_effect=record("load", sentinel_loaded),
        ), patch.object(
            pilot_prepare,
            "_stage_render_local_task",
            side_effect=record("stage", sentinel_staged),
        ), patch.object(
            pilot_prepare,
            "_prepare_render_local_draft",
            side_effect=record("draft", sentinel_draft),
        ), patch.object(
            pilot_prepare,
            "_build_render_local_video_params",
            side_effect=record("params", sentinel_params),
        ), patch.object(
            pilot_prepare,
            "_verify_render_local_render",
            side_effect=record("verify", sentinel_verified),
        ), patch.object(
            pilot_prepare,
            "_finalize_render_local_marked_output",
            side_effect=record("finalize", sentinel_finalized),
        ), patch.object(
            app_services, "task", fake_task_module, create=True
        ):
            result = pilot_prepare._run_render_local_task(**raw)
        after = {
            name
            for name in sys.modules
            if name.startswith("app.services.task")
        }

        # No real renderer module was imported.
        self.assertEqual(after - before, set())

        # Exact stage order.
        self.assertEqual(
            order,
            [
                "validate",
                "load",
                "stage",
                "draft",
                "params",
                "task.start",
                "verify",
                "finalize",
            ],
        )

        # Raw arguments forwarded unchanged to the validator.
        validate_mock.assert_called_once_with(**raw)
        for key, value in raw.items():
            self.assertIs(calls["validate"][1][key], value)

        # Each stage result flows by identity into the next stage.
        self.assertIs(calls["load"][0][0], sentinel_request)
        self.assertIs(calls["stage"][0][0], sentinel_loaded)
        self.assertIs(calls["draft"][0][0], sentinel_staged)
        self.assertIs(calls["params"][0][0], sentinel_draft)

        # task.start receives the exact staged ID, params, and stop_at.
        start_mock.assert_called_once_with(
            task_id="staged-task-id-CANARY-o2",
            params=sentinel_params,
            stop_at="video",
        )
        self.assertIs(calls["task.start"][1]["params"], sentinel_params)

        # Verifier receives the exact draft and task result.
        self.assertIs(calls["verify"][0][0], sentinel_draft)
        self.assertIs(calls["verify"][0][1], sentinel_task_result)

        # Finalizer receives the exact verified result.
        self.assertIs(calls["finalize"][0][0], sentinel_verified)

        # The orchestrator returns the finalized object by identity.
        self.assertIs(result, sentinel_finalized)

    def test_renderer_exception_preserves_prepared_draft(self):
        import app.services as app_services

        known_task_id = "12345678-1234-5678-1234-567812345678"
        src_dir = os.path.join(self.root, "src")
        os.makedirs(src_dir)
        script_bytes = b"renderer failure script CANARY-r1.\n"
        script_src = os.path.join(src_dir, "script.txt")
        with open(script_src, "wb") as handle:
            handle.write(script_bytes)
        material_bytes = b"material-bytes-CANARY-r2"
        material_src = os.path.join(src_dir, "clip-a.mp4")
        with open(material_src, "wb") as handle:
            handle.write(material_bytes)

        start_mock = unittest.mock.Mock(
            side_effect=OSError("injected renderer failure CANARY-r3")
        )
        fake_task_module = unittest.mock.Mock()
        fake_task_module.start = start_mock

        # Real validation/load/stage/draft/params; only task.start fails.
        with patch.object(
            pilot_prepare,
            "__file__",
            os.path.join(self.root, "pilot_prepare.py"),
        ):
            with patch(
                "app.utils.utils.get_uuid", return_value=known_task_id
            ):
                with patch("shutil.rmtree") as rmtree_mock:
                    with patch.object(
                        app_services, "task", fake_task_module,
                        create=True,
                    ):
                        with self.assertRaises(
                            pilot_prepare.PrepareError
                        ) as ctx:
                            pilot_prepare._run_render_local_task(
                                topic="renderer failure topic",
                                script_path=script_src,
                                material_paths=[material_src],
                                license_names=["CC0"],
                                license_evidence=["ref-a"],
                                claims=["claim one"],
                                claim_sources=["https://example.org/s"],
                            )

        # Exact static refusal; native failure survives only as the cause.
        message = str(ctx.exception)
        self.assertEqual(message, "render-local render failed")
        self.assertIsInstance(ctx.exception.__cause__, OSError)
        for leaked in (
            "CANARY-r3",
            "injected renderer failure",
            self.root,
            script_src,
            material_src,
        ):
            self.assertNotIn(leaked, message)

        # task.start called once with exact task ID, fixed params, stop_at.
        start_mock.assert_called_once()
        start_kwargs = start_mock.call_args[1]
        self.assertEqual(start_kwargs["task_id"], known_task_id)
        self.assertEqual(start_kwargs["stop_at"], "video")
        params = start_kwargs["params"]
        self.assertEqual(params.video_subject, "renderer failure topic")
        self.assertEqual(
            params.video_script, script_bytes.decode("utf-8")
        )
        self.assertEqual(params.video_source, "local")
        self.assertEqual(
            [m.provider for m in params.video_materials], ["local"]
        )
        self.assertEqual(params.video_count, 1)
        self.assertEqual(params.video_aspect, VideoAspect.landscape.value)
        self.assertEqual(
            params.video_concat_mode, VideoConcatMode.sequential.value
        )
        self.assertEqual(params.video_clip_duration, 5)
        self.assertEqual(params.voice_name, voice.NO_VOICE_NAME)
        self.assertFalse(params.subtitle_enabled)
        self.assertEqual(params.bgm_type, "none")

        # No rollback or recursive deletion after the durable draft.
        rmtree_mock.assert_not_called()

        # Generated task directory remains with intact prepared evidence.
        task_dir = os.path.join(
            self.root, "storage", "tasks", known_task_id
        )
        self.assertTrue(os.path.isdir(task_dir))
        manifest_path = os.path.join(task_dir, "provenance_manifest.json")
        with open(manifest_path, encoding="utf-8") as handle:
            manifest = json.load(handle)
        prov.validate_manifest(manifest)
        self.assertIsNone(manifest.get("output"))
        self.assertEqual(
            manifest["task"]["review_status"], "NEEDS_HUMAN_REVIEW"
        )

        # script.md and the task-local material/hash remain correct.
        with open(os.path.join(task_dir, "script.md"), "rb") as handle:
            self.assertEqual(handle.read(), script_bytes)
        staged_material = os.path.join(task_dir, "materials", "clip-a.mp4")
        with open(staged_material, "rb") as handle:
            staged_material_bytes = handle.read()
        self.assertEqual(staged_material_bytes, material_bytes)
        self.assertEqual(
            hashlib.sha256(staged_material_bytes).hexdigest(),
            manifest["assets"][0]["sha256"],
        )

        # External inputs unchanged.
        with open(script_src, "rb") as handle:
            self.assertEqual(handle.read(), script_bytes)
        with open(material_src, "rb") as handle:
            self.assertEqual(handle.read(), material_bytes)

        # No marked output exists.
        self.assertFalse(
            os.path.lexists(
                os.path.join(
                    task_dir, prov.marked_filename("final-1.mp4")
                )
            )
        )

    def test_failed_renderer_result_preserves_prepared_draft(self):
        import app.services as app_services

        known_task_id = "12345678-1234-5678-1234-567812345678"
        src_dir = os.path.join(self.root, "src")
        os.makedirs(src_dir)
        script_bytes = b"failed renderer script CANARY-f1.\n"
        script_src = os.path.join(src_dir, "script.txt")
        with open(script_src, "wb") as handle:
            handle.write(script_bytes)
        material_bytes = b"material-bytes-CANARY-f2"
        material_src = os.path.join(src_dir, "clip-a.mp4")
        with open(material_src, "wb") as handle:
            handle.write(material_bytes)

        # Established failed-task result shape (task._mark_task_failed).
        failed_result = {
            "task_id": known_task_id,
            "state": const.TASK_STATE_FAILED,
            "progress": 40,
            "failed_stage": "pipeline",
            "error": "renderer exploded CANARY-f3",
        }
        start_mock = unittest.mock.Mock(return_value=failed_result)
        fake_task_module = unittest.mock.Mock()
        fake_task_module.start = start_mock

        # Real validation/load/stage/draft/params; only task.start patched.
        with patch.object(
            pilot_prepare,
            "__file__",
            os.path.join(self.root, "pilot_prepare.py"),
        ):
            with patch(
                "app.utils.utils.get_uuid", return_value=known_task_id
            ):
                with patch("shutil.rmtree") as rmtree_mock:
                    with patch.object(
                        app_services, "task", fake_task_module,
                        create=True,
                    ):
                        with self.assertRaises(
                            pilot_prepare.PrepareError
                        ) as ctx:
                            pilot_prepare._run_render_local_task(
                                topic="failed renderer topic",
                                script_path=script_src,
                                material_paths=[material_src],
                                license_names=["CC0"],
                                license_evidence=["ref-a"],
                                claims=["claim one"],
                                claim_sources=["https://example.org/s"],
                            )

        # The existing verifier raises its exact static refusal (proving
        # the verifier was reached); the finalizer never ran (no marked
        # output, manifest still output-null). No failure details,
        # canaries, or paths leak into the message.
        message = str(ctx.exception)
        self.assertEqual(
            message, "render-local task result state is not complete"
        )
        self.assertIsNone(ctx.exception.__cause__)
        for leaked in (
            "CANARY-f3",
            "renderer exploded",
            self.root,
            script_src,
            material_src,
        ):
            self.assertNotIn(leaked, message)

        # task.start called once with exact task ID, fixed params, stop_at.
        start_mock.assert_called_once()
        start_kwargs = start_mock.call_args[1]
        self.assertEqual(start_kwargs["task_id"], known_task_id)
        self.assertEqual(start_kwargs["stop_at"], "video")
        params = start_kwargs["params"]
        self.assertEqual(params.video_subject, "failed renderer topic")
        self.assertEqual(
            params.video_script, script_bytes.decode("utf-8")
        )
        self.assertEqual(params.video_source, "local")
        self.assertEqual(
            [m.provider for m in params.video_materials], ["local"]
        )
        self.assertEqual(params.video_count, 1)
        self.assertEqual(params.video_aspect, VideoAspect.landscape.value)
        self.assertEqual(
            params.video_concat_mode, VideoConcatMode.sequential.value
        )
        self.assertEqual(params.video_clip_duration, 5)
        self.assertEqual(params.voice_name, voice.NO_VOICE_NAME)
        self.assertFalse(params.subtitle_enabled)
        self.assertEqual(params.bgm_type, "none")

        # No rollback or recursive deletion after the durable draft.
        rmtree_mock.assert_not_called()

        # Generated task directory remains with intact prepared evidence.
        task_dir = os.path.join(
            self.root, "storage", "tasks", known_task_id
        )
        self.assertTrue(os.path.isdir(task_dir))
        manifest_path = os.path.join(task_dir, "provenance_manifest.json")
        with open(manifest_path, encoding="utf-8") as handle:
            manifest = json.load(handle)
        prov.validate_manifest(manifest)
        self.assertIsNone(manifest.get("output"))
        self.assertEqual(
            manifest["task"]["review_status"], "NEEDS_HUMAN_REVIEW"
        )

        # script.md and the task-local material/hash remain correct.
        with open(os.path.join(task_dir, "script.md"), "rb") as handle:
            self.assertEqual(handle.read(), script_bytes)
        staged_material = os.path.join(task_dir, "materials", "clip-a.mp4")
        with open(staged_material, "rb") as handle:
            staged_material_bytes = handle.read()
        self.assertEqual(staged_material_bytes, material_bytes)
        self.assertEqual(
            hashlib.sha256(staged_material_bytes).hexdigest(),
            manifest["assets"][0]["sha256"],
        )

        # External inputs unchanged.
        with open(script_src, "rb") as handle:
            self.assertEqual(handle.read(), script_bytes)
        with open(material_src, "rb") as handle:
            self.assertEqual(handle.read(), material_bytes)

        # No marked output exists.
        self.assertFalse(
            os.path.lexists(
                os.path.join(
                    task_dir, prov.marked_filename("final-1.mp4")
                )
            )
        )

    def test_successful_fake_renderer_completes_provenance(self):
        import app.services as app_services

        known_task_id = "12345678-1234-5678-1234-567812345678"
        src_dir = os.path.join(self.root, "src")
        os.makedirs(src_dir)
        script_bytes = b"successful orchestration script CANARY-g1.\n"
        script_src = os.path.join(src_dir, "script.txt")
        with open(script_src, "wb") as handle:
            handle.write(script_bytes)
        material_bytes = b"material-bytes-CANARY-g2"
        material_src = os.path.join(src_dir, "clip-a.mp4")
        with open(material_src, "wb") as handle:
            handle.write(material_bytes)
        output_bytes = b"fake-rendered-video-CANARY-g3\x00\xff"

        captured = {}

        def fake_start(task_id, params, stop_at):
            # Exact task ID, fixed params, and stop_at arrive unchanged.
            self.assertEqual(task_id, known_task_id)
            self.assertEqual(stop_at, "video")
            task_dir = os.path.join(
                self.root, "storage", "tasks", task_id
            )
            self.assertEqual(
                params.video_subject, "successful orchestration topic"
            )
            self.assertEqual(
                params.video_script, script_bytes.decode("utf-8")
            )
            self.assertEqual(params.video_source, "local")
            self.assertEqual(
                [m.provider for m in params.video_materials], ["local"]
            )
            self.assertEqual(
                [m.url for m in params.video_materials],
                [os.path.join("materials", "clip-a.mp4")],
            )
            self.assertEqual(params.video_count, 1)
            self.assertEqual(
                params.video_aspect, VideoAspect.landscape.value
            )
            self.assertEqual(
                params.video_concat_mode, VideoConcatMode.sequential.value
            )
            self.assertEqual(params.video_clip_duration, 5)
            self.assertEqual(params.voice_name, voice.NO_VOICE_NAME)
            self.assertFalse(params.subtitle_enabled)
            self.assertEqual(params.bgm_type, "none")

            # Capture the prepared output-null draft before mutation.
            with open(
                os.path.join(task_dir, "provenance_manifest.json"),
                encoding="utf-8",
            ) as handle:
                captured["draft_manifest"] = json.load(handle)

            # Fixture-shaped script.json built from the received params.
            script_json = {
                "script": params.video_script,
                "params": {
                    "video_script": params.video_script,
                    "video_source": params.video_source,
                    "video_count": params.video_count,
                    "video_aspect": params.video_aspect,
                    "video_concat_mode": params.video_concat_mode,
                    "video_clip_duration": params.video_clip_duration,
                    "voice_name": params.voice_name,
                    "subtitle_enabled": params.subtitle_enabled,
                    "bgm_type": params.bgm_type,
                    "video_materials": [
                        {"provider": m.provider, "url": m.url}
                        for m in params.video_materials
                    ],
                },
            }
            with open(
                os.path.join(task_dir, "script.json"), "w",
                encoding="utf-8",
            ) as handle:
                json.dump(script_json, handle)
            with open(
                os.path.join(task_dir, "final-1.mp4"), "wb"
            ) as handle:
                handle.write(output_bytes)
            return {
                "task_id": task_id,
                "state": const.TASK_STATE_COMPLETE,
                "progress": 100,
                "videos": ["final-1.mp4"],
            }

        fake_task_module = unittest.mock.Mock()
        fake_task_module.start = fake_start

        forbidden = ("app.services.task", "app.services.upload_post")
        before = {
            name for name in sys.modules if name.startswith(forbidden)
        }
        with patch.object(
            pilot_prepare,
            "__file__",
            os.path.join(self.root, "pilot_prepare.py"),
        ):
            with patch(
                "app.utils.utils.get_uuid", return_value=known_task_id
            ):
                with patch.object(
                    app_services, "task", fake_task_module, create=True
                ):
                    finalized = pilot_prepare._run_render_local_task(
                        topic="successful orchestration topic",
                        script_path=script_src,
                        material_paths=[material_src],
                        license_names=["CC0"],
                        license_evidence=["ref-a"],
                        claims=[
                            "Bitcoin supply is capped at 21 million."
                        ],
                        claim_sources=["https://bitcoin.org/bitcoin.pdf"],
                    )
        after = {
            name for name in sys.modules if name.startswith(forbidden)
        }

        # No real renderer or upload module was imported.
        self.assertEqual(after - before, set())

        task_dir = os.path.join(
            self.root, "storage", "tasks", known_task_id
        )
        marked_name = prov.marked_filename("final-1.mp4")

        # Returned finalized structure.
        self.assertIsInstance(
            finalized, pilot_prepare.RenderLocalFinalizedRender
        )
        self.assertEqual(
            finalized.verified.draft.staged.task_id, known_task_id
        )
        self.assertEqual(
            os.path.basename(finalized.marked_output_path), marked_name
        )
        self.assertEqual(
            os.path.dirname(finalized.marked_output_path), task_dir
        )
        self.assertEqual(
            finalized.manifest_path,
            os.path.join(task_dir, "provenance_manifest.json"),
        )

        # Original and marked output bytes/hash match.
        with open(
            os.path.join(task_dir, "final-1.mp4"), "rb"
        ) as handle:
            self.assertEqual(handle.read(), output_bytes)
        with open(finalized.marked_output_path, "rb") as handle:
            self.assertEqual(handle.read(), output_bytes)
        self.assertEqual(
            finalized.marked_output_sha256,
            hashlib.sha256(output_bytes).hexdigest(),
        )
        self.assertEqual(
            finalized.marked_output_sha256,
            finalized.verified.output_sha256,
        )

        # Durable manifest validates with the marked output recorded.
        prov.validate_manifest(finalized.manifest)
        with open(finalized.manifest_path, encoding="utf-8") as handle:
            self.assertEqual(json.load(handle), finalized.manifest)
        output = finalized.manifest["output"]
        self.assertEqual(output["local_path"], marked_name)
        self.assertEqual(
            output["sha256"], finalized.verified.output_sha256
        )
        self.assertEqual(output["filename_marker"], marked_name)
        self.assertFalse(output["visible_watermark_required"])

        # NEEDS_HUMAN_REVIEW preserved everywhere.
        self.assertEqual(output["review_status"], "NEEDS_HUMAN_REVIEW")
        self.assertEqual(
            finalized.manifest["task"]["review_status"],
            "NEEDS_HUMAN_REVIEW",
        )

        # Prepared sections survive finalization verbatim.
        draft_manifest = captured["draft_manifest"]
        for section in (
            "task", "script", "assets", "factual_claims", "ai_generations"
        ):
            self.assertEqual(
                finalized.manifest[section], draft_manifest[section]
            )

        # Task-local script/material/license/claim evidence is correct.
        self.assertEqual(
            draft_manifest["script"]["sha256"],
            hashlib.sha256(script_bytes).hexdigest(),
        )
        self.assertEqual(
            draft_manifest["assets"][0]["sha256"],
            hashlib.sha256(material_bytes).hexdigest(),
        )
        assets_json = json.dumps(draft_manifest["assets"])
        self.assertIn("CC0", assets_json)
        self.assertIn("ref-a", assets_json)
        claims_json = json.dumps(draft_manifest["factual_claims"])
        self.assertIn(
            "Bitcoin supply is capped at 21 million.", claims_json
        )
        self.assertIn("https://bitcoin.org/bitcoin.pdf", claims_json)

        # External inputs unchanged.
        with open(script_src, "rb") as handle:
            self.assertEqual(handle.read(), script_bytes)
        with open(material_src, "rb") as handle:
            self.assertEqual(handle.read(), material_bytes)

        # pilot_review status/audit assembly accepts the task.
        state = pilot_review._assemble_state(task_dir)
        self.assertEqual(state.get("failures"), [])
        self.assertEqual(state.get("script_status"), "ok")
        self.assertEqual(state.get("asset_statuses"), ["ok"])
        self.assertEqual(state.get("output_status"), "ok")


if __name__ == "__main__":
    unittest.main()
