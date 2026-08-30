"""
Phase 1B.2D.1 — Block automatic/background network activity in BrainTrustCrypto pilot mode.

When MPT_PILOT_PROFILE=braintrustcrypto:
1. Version/update checking must fail closed or return a clearly disabled result
   before any network request.
2. docs/skill/mpt_agent.py must refuse ZIP/bootstrap downloads before urlopen,
   file creation, extraction, subprocess execution, or repository replacement.
3. No automatic startup path may contact GitHub, update servers, telemetry
   services, or bootstrap endpoints.
4. Preserve upstream behavior outside BrainTrustCrypto pilot mode.

All tests use mocks only. No live network requests are made.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import requests

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.services import version_checker
from app.services.pilot_policy import reset_pilot_policy_cache


# Load mpt_agent module for testing under a unique temporary module name.
# The module is registered in sys.modules before exec_module() so that
# importlib.reload() works correctly, and removed during cleanup.
SKILL_SCRIPT = (
    Path(__file__).parent.parent.parent / "docs" / "skill" / "mpt_agent.py"
)
_MPT_AGENT_MODULE_NAME = "mpt_agent_skill_phase1b2d1"
SPEC = importlib.util.spec_from_file_location(_MPT_AGENT_MODULE_NAME, SKILL_SCRIPT)
mpt_agent = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[_MPT_AGENT_MODULE_NAME] = mpt_agent
try:
    SPEC.loader.exec_module(mpt_agent)
except Exception:
    sys.modules.pop(_MPT_AGENT_MODULE_NAME, None)
    raise


class _PilotTestBase(unittest.TestCase):
    """Shared setup/teardown for pilot-mode tests."""

    def setUp(self):
        reset_pilot_policy_cache()
        self._env_patcher = patch.dict(
            os.environ, {"MPT_PILOT_PROFILE": "braintrustcrypto"}
        )
        self._env_patcher.start()

    def tearDown(self):
        self._env_patcher.stop()
        reset_pilot_policy_cache()


# ---------------------------------------------------------------------------
# 1. Version checking fails closed in pilot mode
# ---------------------------------------------------------------------------

class TestVersionCheckerDeniedInPilotMode(_PilotTestBase):
    """Version checking must fail closed before any network request."""

    def test_version_check_returns_none_before_network(self):
        """get_available_update must return None before any requests call."""
        with patch("app.services.version_checker.requests.get") as mock_get:
            result = version_checker.get_available_update("1.3.2")
            self.assertIsNone(result)
            mock_get.assert_not_called()

    def test_version_check_returns_none_for_any_version(self):
        """Denial applies regardless of version string."""
        with patch("app.services.version_checker.requests.get") as mock_get:
            for version in ("1.0.0", "v2.0.0", "development", ""):
                with self.subTest(version=version):
                    result = version_checker.get_available_update(version)
                    self.assertIsNone(result)
            mock_get.assert_not_called()

    def test_async_checker_returns_disabled_result(self):
        """AsyncUpdateChecker.poll must return complete with no update."""
        checker = version_checker.AsyncUpdateChecker()
        snapshot = checker.poll("1.3.2")
        # In pilot mode, the checker should immediately return a disabled result
        # without starting any background thread or network request
        self.assertTrue(snapshot.complete)
        self.assertIsNone(snapshot.available_version)

    def test_async_checker_no_background_thread_started(self):
        """No background thread should be started in pilot mode."""
        checker = version_checker.AsyncUpdateChecker()
        with patch.object(checker, "_run_check") as mock_run:
            snapshot = checker.poll("1.3.2")
            # The snapshot should be complete immediately
            self.assertTrue(snapshot.complete)
            # _run_check should never be called
            mock_run.assert_not_called()

    def test_poll_available_update_returns_disabled(self):
        """poll_available_update must return disabled result in pilot mode."""
        with patch("app.services.version_checker.requests.get") as mock_get:
            snapshot = version_checker.poll_available_update("1.3.2")
            self.assertTrue(snapshot.complete)
            self.assertIsNone(snapshot.available_version)
            mock_get.assert_not_called()


# ---------------------------------------------------------------------------
# 2. mpt_agent bootstrap denied before urlopen/file/subprocess
# ---------------------------------------------------------------------------

class TestMptAgentBootstrapDeniedInPilotMode(_PilotTestBase):
    """mpt_agent must refuse ZIP/bootstrap downloads before any network or file ops."""

    def test_ensure_project_denied_before_urlopen(self):
        """ensure_project must raise SkillError before urlopen is called."""
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "MoneyPrinterTurbo"
            with patch.object(mpt_agent.urllib.request, "urlopen") as mock_urlopen:
                with self.assertRaises(mpt_agent.SkillError) as ctx:
                    mpt_agent.ensure_project(root)
                self.assertIn("pilot", str(ctx.exception).lower())
                mock_urlopen.assert_not_called()

    def test_ensure_project_denied_before_file_creation(self):
        """ensure_project must raise before any file is created."""
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "MoneyPrinterTurbo"
            with patch.object(mpt_agent.tempfile, "TemporaryDirectory") as mock_temp:
                with self.assertRaises(mpt_agent.SkillError):
                    mpt_agent.ensure_project(root)
                mock_temp.assert_not_called()

    def test_ensure_project_denied_before_extraction(self):
        """ensure_project must raise before any ZIP extraction."""
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "MoneyPrinterTurbo"
            with patch.object(mpt_agent.zipfile, "ZipFile") as mock_zip:
                with self.assertRaises(mpt_agent.SkillError):
                    mpt_agent.ensure_project(root)
                mock_zip.assert_not_called()

    def test_ensure_project_denied_before_subprocess(self):
        """ensure_project must raise before any subprocess execution."""
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "MoneyPrinterTurbo"
            with patch.object(mpt_agent.subprocess, "run") as mock_run:
                with self.assertRaises(mpt_agent.SkillError):
                    mpt_agent.ensure_project(root)
                mock_run.assert_not_called()

    def test_ensure_project_denied_before_repository_replacement(self):
        """ensure_project must raise before any repository replacement."""
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "MoneyPrinterTurbo"
            with patch.object(mpt_agent.shutil, "move") as mock_move:
                with self.assertRaises(mpt_agent.SkillError):
                    mpt_agent.ensure_project(root)
                mock_move.assert_not_called()

    def test_generate_video_denied_before_subprocess(self):
        """generate_video must raise SkillError before subprocess execution."""
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with patch.object(mpt_agent.subprocess, "run") as mock_run:
                with self.assertRaises(mpt_agent.SkillError) as ctx:
                    mpt_agent.generate_video(root, "test subject", [])
                self.assertIn("pilot", str(ctx.exception).lower())
                mock_run.assert_not_called()

    def test_generate_video_denied_before_uv_check(self):
        """generate_video must raise before checking for uv."""
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with patch.object(mpt_agent.shutil, "which") as mock_which:
                with self.assertRaises(mpt_agent.SkillError):
                    mpt_agent.generate_video(root, "test subject", [])
                mock_which.assert_not_called()


# ---------------------------------------------------------------------------
# 3. No automatic startup path contacts external services
# ---------------------------------------------------------------------------

class TestNoAutomaticStartupNetworkInPilotMode(_PilotTestBase):
    """No automatic startup path may contact GitHub, update servers, or telemetry."""

    def test_version_checker_no_network_on_import(self):
        """version_checker module must not make network calls on import."""
        # Re-import the module to verify no network calls happen
        with patch("app.services.version_checker.requests.get") as mock_get:
            import importlib
            importlib.reload(version_checker)
            mock_get.assert_not_called()

    def test_mpt_agent_no_network_on_import(self):
        """mpt_agent module must not make network calls on import."""
        # Patch urlopen before re-executing the module to prove no network
        # occurs during import. Re-execute via spec.loader.exec_module() rather
        # than importlib.reload() because the module was loaded from a file
        # path, not through the import system.
        with patch.object(mpt_agent.urllib.request, "urlopen") as mock_urlopen:
            SPEC.loader.exec_module(mpt_agent)
            mock_urlopen.assert_not_called()


# ---------------------------------------------------------------------------
# 4. Non-pilot upstream behavior unchanged
# ---------------------------------------------------------------------------

class TestNonPilotUpstreamBehaviorUnchanged(unittest.TestCase):
    """When pilot mode is NOT active, all behavior must remain unchanged."""

    def setUp(self):
        reset_pilot_policy_cache()
        # Ensure MPT_PILOT_PROFILE is NOT set
        self._env_patcher = patch.dict(os.environ, {}, clear=False)
        self._env_patcher.start()
        if "MPT_PILOT_PROFILE" in os.environ:
            del os.environ["MPT_PILOT_PROFILE"]

    def tearDown(self):
        self._env_patcher.stop()
        reset_pilot_policy_cache()

    def test_version_check_works_without_pilot(self):
        """Version checking proceeds normally when pilot mode is off."""
        fake_response = MagicMock()
        fake_response.raise_for_status.return_value = None
        fake_response.json.return_value = {"tag_name": "v1.4.0"}

        with patch("app.services.version_checker.requests.get", return_value=fake_response):
            result = version_checker.get_available_update("1.3.2")
            self.assertEqual(result, "1.4.0")

    def test_version_check_network_failure_ignored(self):
        """Network failures are still handled gracefully without pilot mode."""
        with patch("app.services.version_checker.requests.get",
                   side_effect=requests.Timeout("timeout")):
            result = version_checker.get_available_update("1.3.2")
            self.assertIsNone(result)

    def test_mpt_agent_ensure_project_works_without_pilot(self):
        """ensure_project proceeds normally when pilot mode is off."""
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "MoneyPrinterTurbo"
            # Create a minimal valid project structure
            root.mkdir()
            (root / "cli.py").write_text("", encoding="utf-8")
            (root / "config.example.toml").write_text("", encoding="utf-8")

            # Should not raise
            mpt_agent.ensure_project(root)

    def test_mpt_agent_generate_video_works_without_pilot(self):
        """generate_video proceeds normally when pilot mode is off."""
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            task_id = "12345678-1234-1234-1234-123456789abc"

            def finish_cli(command, **kwargs):
                task_dir = root / "storage" / "tasks" / task_id
                task_dir.mkdir(parents=True)
                (task_dir / "final-1.mp4").write_bytes(b"video")
                return SimpleNamespace(returncode=0)

            with (
                patch.object(mpt_agent.shutil, "which", return_value="uv"),
                patch.object(mpt_agent, "run_checked"),
                patch.object(mpt_agent.uuid, "uuid4", return_value=task_id),
                patch.object(mpt_agent.subprocess, "run", side_effect=finish_cli),
            ):
                videos, _, _, _ = mpt_agent.generate_video(root, "test", [])
                self.assertEqual(len(videos), 1)


# ---------------------------------------------------------------------------
# 5. Error message quality
# ---------------------------------------------------------------------------

class TestErrorMessageQuality(_PilotTestBase):
    """Error messages must be informative."""

    def test_ensure_project_error_mentions_pilot_mode(self):
        """Error message must clearly indicate pilot mode restriction."""
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "MoneyPrinterTurbo"
            with self.assertRaises(mpt_agent.SkillError) as ctx:
                mpt_agent.ensure_project(root)
            error_msg = str(ctx.exception).lower()
            self.assertIn("pilot", error_msg)
            self.assertIn("bootstrap", error_msg)

    def test_generate_video_error_mentions_pilot_mode(self):
        """Error message must clearly indicate pilot mode restriction."""
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with self.assertRaises(mpt_agent.SkillError) as ctx:
                mpt_agent.generate_video(root, "test", [])
            error_msg = str(ctx.exception).lower()
            self.assertIn("pilot", error_msg)
            self.assertIn("subprocess", error_msg)


if __name__ == "__main__":
    unittest.main()
