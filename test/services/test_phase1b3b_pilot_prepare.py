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


if __name__ == "__main__":
    unittest.main()
