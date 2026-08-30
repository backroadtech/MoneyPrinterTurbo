"""
Phase 1B.1 validation tests for BrainTrustCrypto runtime pilot-policy loading
and publishing interlocks.

These tests confirm:
1. Missing policy fails closed
2. Malformed policy fails closed
3. Unsafe boolean values fail closed
4. Upload attempts are denied before credential/network access
5. API startup is denied in pilot mode
6. WebUI startup is denied in pilot mode
7. Redis is denied in pilot mode
8. Restricted assets are rejected
9. Safe CLI initialization succeeds without external calls
10. Existing Phase 1A tests remain passing (verified by full suite)
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

# Project root is two levels up from this test file
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def _write_policy(tmp_path: Path, content: str) -> Path:
    """Write a temporary hardening.toml for testing."""
    policy_path = tmp_path / "hardening.toml"
    policy_path.write_text(content, encoding="utf-8")
    return policy_path


def _valid_policy() -> str:
    return """
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


class TestMissingPolicyFailsClosed:
    """Missing policy file must fail closed."""

    def test_missing_policy_file_raises(self, tmp_path):
        from app.services.pilot_policy import PilotPolicyError, _load_policy_file

        with pytest.raises(PilotPolicyError, match="not found"):
            _load_policy_file(tmp_path / "nonexistent.toml")

    def test_load_pilot_policy_missing_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MPT_PILOT_PROFILE", "braintrustcrypto")
        # Point root_dir at tmp_path so hardening.toml is missing
        monkeypatch.setattr(
            "app.services.pilot_policy.Path",
            lambda *args: tmp_path if args == ("app", "services", "pilot_policy.py") else Path(*args),
        )
        # Re-import to trigger load with patched path
        from app.services.pilot_policy import PilotPolicyError, load_pilot_policy

        with pytest.raises(PilotPolicyError, match="not found"):
            load_pilot_policy()


class TestMalformedPolicyFailsClosed:
    """Malformed TOML must fail closed."""

    def test_malformed_toml_raises(self, tmp_path):
        from app.services.pilot_policy import PilotPolicyError, _load_policy_file

        policy_path = _write_policy(tmp_path, "not valid toml [[[")
        with pytest.raises(PilotPolicyError, match="malformed TOML"):
            _load_policy_file(policy_path)

    def test_empty_toml_raises(self, tmp_path):
        from app.services.pilot_policy import PilotPolicy, PilotPolicyError

        policy_path = _write_policy(tmp_path, "")
        with pytest.raises(PilotPolicyError, match="missing \\[pilot\\] section"):
            PilotPolicy({}, str(policy_path))


class TestUnsafeBooleanValuesFailClosed:
    """Unsafe boolean values must fail closed."""

    def test_api_server_enabled_true_fails(self, tmp_path):
        from app.services.pilot_policy import PilotPolicy, PilotPolicyError

        content = _valid_policy().replace(
            "api_server_enabled = false", "api_server_enabled = true"
        )
        policy_path = _write_policy(tmp_path, content)
        import tomllib

        with open(policy_path, "rb") as f:
            raw = tomllib.load(f)
        with pytest.raises(PilotPolicyError, match="api_server_enabled"):
            PilotPolicy(raw, str(policy_path))

    def test_webui_enabled_true_fails(self, tmp_path):
        from app.services.pilot_policy import PilotPolicy, PilotPolicyError

        content = _valid_policy().replace(
            "webui_enabled = false", "webui_enabled = true"
        )
        policy_path = _write_policy(tmp_path, content)
        import tomllib

        with open(policy_path, "rb") as f:
            raw = tomllib.load(f)
        with pytest.raises(PilotPolicyError, match="webui_enabled"):
            PilotPolicy(raw, str(policy_path))

    def test_upload_post_enabled_true_fails(self, tmp_path):
        from app.services.pilot_policy import PilotPolicy, PilotPolicyError

        content = _valid_policy().replace(
            "upload_post_enabled = false", "upload_post_enabled = true"
        )
        policy_path = _write_policy(tmp_path, content)
        import tomllib

        with open(policy_path, "rb") as f:
            raw = tomllib.load(f)
        with pytest.raises(PilotPolicyError, match="upload_post_enabled"):
            PilotPolicy(raw, str(policy_path))

    def test_redis_enabled_true_fails(self, tmp_path):
        from app.services.pilot_policy import PilotPolicy, PilotPolicyError

        content = _valid_policy().replace(
            "redis_enabled = false", "redis_enabled = true"
        )
        policy_path = _write_policy(tmp_path, content)
        import tomllib

        with open(policy_path, "rb") as f:
            raw = tomllib.load(f)
        with pytest.raises(PilotPolicyError, match="redis_enabled"):
            PilotPolicy(raw, str(policy_path))

    def test_bgm_source_not_none_fails(self, tmp_path):
        from app.services.pilot_policy import PilotPolicy, PilotPolicyError

        content = _valid_policy().replace('source = "none"', 'source = "random"')
        policy_path = _write_policy(tmp_path, content)
        import tomllib

        with open(policy_path, "rb") as f:
            raw = tomllib.load(f)
        with pytest.raises(PilotPolicyError, match="bgm.source"):
            PilotPolicy(raw, str(policy_path))

    def test_mode_not_cli_fails(self, tmp_path):
        from app.services.pilot_policy import PilotPolicy, PilotPolicyError

        content = _valid_policy().replace('mode = "cli"', 'mode = "api"')
        policy_path = _write_policy(tmp_path, content)
        import tomllib

        with open(policy_path, "rb") as f:
            raw = tomllib.load(f)
        with pytest.raises(PilotPolicyError, match="mode"):
            PilotPolicy(raw, str(policy_path))


class TestUploadDeniedBeforeCredentials:
    """Upload attempts must be denied before credential/network access."""

    def _make_policy(self, tmp_path):
        from app.services.pilot_policy import (
            PilotPolicy,
            PilotPolicyError,
            reset_pilot_policy_cache,
        )

        policy_path = _write_policy(tmp_path, _valid_policy())
        import tomllib

        with open(policy_path, "rb") as f:
            raw = tomllib.load(f)
        policy = PilotPolicy(raw, str(policy_path))
        reset_pilot_policy_cache()
        return policy, PilotPolicyError

    def test_upload_video_denied_before_credentials(self, tmp_path):
        from app.services.pilot_policy import reset_pilot_policy_cache

        policy, PilotPolicyError = self._make_policy(tmp_path)

        with patch("app.services.pilot_policy._cached_policy", policy), \
             patch("app.services.pilot_policy._policy_loaded", True):
            from app.services.upload_post import UploadPostService

            service = UploadPostService()
            with pytest.raises(PilotPolicyError, match="prohibits upload-post"):
                service.upload_video("/tmp/fake.mp4", "test")

        reset_pilot_policy_cache()

    def test_check_status_denied_before_credentials(self, tmp_path):
        from app.services.pilot_policy import reset_pilot_policy_cache

        policy, PilotPolicyError = self._make_policy(tmp_path)

        with patch("app.services.pilot_policy._cached_policy", policy), \
             patch("app.services.pilot_policy._policy_loaded", True):
            from app.services.upload_post import UploadPostService

            service = UploadPostService()
            with pytest.raises(PilotPolicyError, match="prohibits upload-post"):
                service.check_status("fake-request-id")

        reset_pilot_policy_cache()

    def test_is_configured_denied_before_credentials(self, tmp_path):
        from app.services.pilot_policy import reset_pilot_policy_cache

        policy, PilotPolicyError = self._make_policy(tmp_path)

        with patch("app.services.pilot_policy._cached_policy", policy), \
             patch("app.services.pilot_policy._policy_loaded", True):
            from app.services.upload_post import UploadPostService

            service = UploadPostService()
            with pytest.raises(PilotPolicyError, match="prohibits upload-post"):
                service.is_configured()

        reset_pilot_policy_cache()


class TestApiStartupDenied:
    """API startup must be denied in pilot mode."""

    def test_main_py_refuses_to_start(self, tmp_path):
        # Write policy at project root so the subprocess finds it
        policy_path = PROJECT_ROOT / "hardening.toml"
        policy_path.write_text(_valid_policy(), encoding="utf-8")
        try:
            env = os.environ.copy()
            env["MPT_PILOT_PROFILE"] = "braintrustcrypto"

            result = subprocess.run(
                [sys.executable, str(PROJECT_ROOT / "main.py")],
                capture_output=True,
                text=True,
                env=env,
                timeout=10,
            )
            assert result.returncode != 0
            assert "prohibits API server startup" in result.stderr
        finally:
            policy_path.unlink(missing_ok=True)


class TestWebUIStartupDenied:
    """WebUI startup must be denied in pilot mode."""

    def test_webui_refuses_to_start(self, tmp_path):
        # Write policy at project root so the subprocess finds it
        policy_path = PROJECT_ROOT / "hardening.toml"
        policy_path.write_text(_valid_policy(), encoding="utf-8")
        try:
            env = os.environ.copy()
            env["MPT_PILOT_PROFILE"] = "braintrustcrypto"

            result = subprocess.run(
                [sys.executable, str(PROJECT_ROOT / "webui" / "Main.py")],
                capture_output=True,
                text=True,
                env=env,
                timeout=10,
            )
            assert result.returncode != 0
            assert "prohibits WebUI startup" in result.stderr
        finally:
            policy_path.unlink(missing_ok=True)


class TestRedisDenied:
    """Redis initialization must be denied in pilot mode."""

    def test_redis_state_denied_integration(self, tmp_path):
        """
        True integration test: launch a clean subprocess, activate the
        BrainTrustCrypto profile, supply a valid pilot policy, make the
        application configuration request enable_redis=true, import
        app.services.state through its real production path, and prove
        PilotPolicyError occurs before any Redis client, connection, or
        task manager is created.
        """
        # Write policy at project root so the subprocess finds it
        policy_path = PROJECT_ROOT / "hardening.toml"
        policy_path.write_text(_valid_policy(), encoding="utf-8")

        # Backup original config.toml
        config_path = PROJECT_ROOT / "config.toml"
        original_config = config_path.read_text(encoding="utf-8")

        try:
            # Modify config.toml to enable Redis
            modified_config = original_config.replace(
                "enable_redis = false", "enable_redis = true"
            )
            config_path.write_text(modified_config, encoding="utf-8")

            env = os.environ.copy()
            env["MPT_PILOT_PROFILE"] = "braintrustcrypto"

            # Create a subprocess script that imports state.py through its
            # real production path. The script must trigger the gate before
            # any Redis client or connection is created.
            test_script = tmp_path / "test_redis_integration.py"
            test_script.write_text(
                """
import sys
sys.path.insert(0, r"{}")

# Import state.py through its real production path.
# This will execute the module-level code that checks enable_redis
# and calls get_pilot_policy().require_not_redis() when the pilot
# policy is active and enable_redis is true.
try:
    import app.services.state
    # If we reach here, the gate did not fire — this is a failure
    print("ERROR: state.py imported without raising PilotPolicyError", file=sys.stderr)
    sys.exit(1)
except Exception as exc:
    # We expect PilotPolicyError with "prohibits Redis" in the message
    if "prohibits Redis" in str(exc):
        print(f"SUCCESS: PilotPolicyError raised: {{exc}}", file=sys.stderr)
        sys.exit(0)
    else:
        print(f"ERROR: Unexpected exception: {{type(exc).__name__}}: {{exc}}", file=sys.stderr)
        sys.exit(1)
""".format(str(PROJECT_ROOT).replace("\\", "\\\\")),
                encoding="utf-8",
            )

            result = subprocess.run(
                [sys.executable, str(test_script)],
                capture_output=True,
                text=True,
                env=env,
                timeout=15,
            )

            # The subprocess should exit 0 (gate fired correctly)
            assert result.returncode == 0, (
                f"Subprocess failed: stdout={{result.stdout}}, stderr={{result.stderr}}"
            )
            assert "SUCCESS: PilotPolicyError raised" in result.stderr
            assert "prohibits Redis" in result.stderr

        finally:
            # Restore original config.toml
            config_path.write_text(original_config, encoding="utf-8")
            policy_path.unlink(missing_ok=True)

    def test_redis_disabled_allows_memory_state(self, tmp_path):
        """
        Prove that enable_redis=false selects or permits the in-memory
        task manager even when the pilot policy is active.
        """
        # Write policy at project root so the subprocess finds it
        policy_path = PROJECT_ROOT / "hardening.toml"
        policy_path.write_text(_valid_policy(), encoding="utf-8")

        # Backup original config.toml
        config_path = PROJECT_ROOT / "config.toml"
        original_config = config_path.read_text(encoding="utf-8")

        try:
            # Ensure config.toml has enable_redis = false (default)
            modified_config = original_config.replace(
                "enable_redis = true", "enable_redis = false"
            )
            config_path.write_text(modified_config, encoding="utf-8")

            env = os.environ.copy()
            env["MPT_PILOT_PROFILE"] = "braintrustcrypto"

            # Create a subprocess script that imports state.py and verifies
            # MemoryState is selected when enable_redis=false
            test_script = tmp_path / "test_redis_disabled.py"
            test_script.write_text(
                """
import sys
sys.path.insert(0, r"{}")

# Import state.py through its real production path.
# With enable_redis=false, this should succeed and select MemoryState.
try:
    import app.services.state
    # Verify MemoryState was selected
    state_type = type(app.services.state.state).__name__
    if state_type == "MemoryState":
        print(f"SUCCESS: MemoryState selected: {{state_type}}", file=sys.stderr)
        sys.exit(0)
    else:
        print(f"ERROR: Expected MemoryState, got {{state_type}}", file=sys.stderr)
        sys.exit(1)
except Exception as exc:
    print(f"ERROR: Unexpected exception: {{type(exc).__name__}}: {{exc}}", file=sys.stderr)
    sys.exit(1)
""".format(str(PROJECT_ROOT).replace("\\", "\\\\")),
                encoding="utf-8",
            )

            result = subprocess.run(
                [sys.executable, str(test_script)],
                capture_output=True,
                text=True,
                env=env,
                timeout=15,
            )

            # The subprocess should exit 0 (MemoryState selected)
            assert result.returncode == 0, (
                f"Subprocess failed: stdout={{result.stdout}}, stderr={{result.stderr}}"
            )
            assert "SUCCESS: MemoryState selected" in result.stderr

        finally:
            # Restore original config.toml
            config_path.write_text(original_config, encoding="utf-8")
            policy_path.unlink(missing_ok=True)


class TestRestrictedAssetsRejected:
    """Restricted bundled songs and fonts must be rejected."""

    def test_bgm_random_rejected(self, tmp_path):
        from app.services.pilot_policy import PilotPolicy, PilotPolicyError

        policy_path = _write_policy(tmp_path, _valid_policy())
        import tomllib

        with open(policy_path, "rb") as f:
            raw = tomllib.load(f)
        policy = PilotPolicy(raw, str(policy_path))

        with pytest.raises(PilotPolicyError, match="prohibits BGM source"):
            policy.require_bgm_source_allowed("random")

    def test_bgm_custom_rejected(self, tmp_path):
        from app.services.pilot_policy import PilotPolicy, PilotPolicyError

        policy_path = _write_policy(tmp_path, _valid_policy())
        import tomllib

        with open(policy_path, "rb") as f:
            raw = tomllib.load(f)
        policy = PilotPolicy(raw, str(policy_path))

        with pytest.raises(PilotPolicyError, match="prohibits BGM source"):
            policy.require_bgm_source_allowed("custom")

    def test_bgm_file_rejected(self, tmp_path):
        from app.services.pilot_policy import PilotPolicy, PilotPolicyError

        policy_path = _write_policy(tmp_path, _valid_policy())
        import tomllib

        with open(policy_path, "rb") as f:
            raw = tomllib.load(f)
        policy = PilotPolicy(raw, str(policy_path))

        with pytest.raises(PilotPolicyError, match="prohibits custom BGM file"):
            policy.require_bgm_source_allowed("", "song.mp3")

    def test_font_rejected(self, tmp_path):
        from app.services.pilot_policy import PilotPolicy, PilotPolicyError

        policy_path = _write_policy(tmp_path, _valid_policy())
        import tomllib

        with open(policy_path, "rb") as f:
            raw = tomllib.load(f)
        policy = PilotPolicy(raw, str(policy_path))

        with pytest.raises(PilotPolicyError, match="prohibits font"):
            policy.require_font_allowed("STHeitiMedium.ttc")


class TestSafeCLIInitialization:
    """Safe CLI initialization must succeed without external calls."""

    def test_valid_policy_loads(self, tmp_path):
        from app.services.pilot_policy import PilotPolicy

        policy_path = _write_policy(tmp_path, _valid_policy())
        import tomllib

        with open(policy_path, "rb") as f:
            raw = tomllib.load(f)
        policy = PilotPolicy(raw, str(policy_path))
        assert policy.is_pilot_active is False  # env var not set

    def test_valid_policy_with_env_var(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MPT_PILOT_PROFILE", "braintrustcrypto")
        from app.services.pilot_policy import PilotPolicy

        policy_path = _write_policy(tmp_path, _valid_policy())
        import tomllib

        with open(policy_path, "rb") as f:
            raw = tomllib.load(f)
        policy = PilotPolicy(raw, str(policy_path))
        assert policy.is_pilot_active is True

    def test_bgm_none_allowed(self, tmp_path):
        from app.services.pilot_policy import PilotPolicy

        policy_path = _write_policy(tmp_path, _valid_policy())
        import tomllib

        with open(policy_path, "rb") as f:
            raw = tomllib.load(f)
        policy = PilotPolicy(raw, str(policy_path))

        # Should not raise
        policy.require_bgm_source_allowed("")
        policy.require_bgm_source_allowed("none")

    def test_cli_help_works_without_policy(self):
        """CLI --help must work even without a policy file (no pilot mode)."""
        result = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "cli.py"), "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert "Generate MoneyPrinterTurbo videos" in result.stdout
