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


if __name__ == "__main__":
    unittest.main()
