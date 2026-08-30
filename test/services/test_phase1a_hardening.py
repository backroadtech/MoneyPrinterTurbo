"""
Phase 1A validation tests for BrainTrustCrypto hardening.

These tests confirm:
1. Publishing (upload_post) is disabled
2. Quarantined assets cannot load from their original paths
3. Secrets and generated output directories are gitignored
4. The pilot configuration is CLI-only (no API server, no WebUI, no Redis)
"""

import os
import re
import tomllib
from pathlib import Path

import pytest

# Project root is two levels up from this test file
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class TestPublishingDisabled:
    """Verify upload_post is disabled in the pilot configuration."""

    def test_upload_post_disabled_in_hardening_template(self):
        """hardening.example.toml must have upload_post_enabled = false."""
        template_path = PROJECT_ROOT / "hardening.example.toml"
        assert template_path.exists(), "hardening.example.toml not found"
        with open(template_path, "rb") as f:
            config = tomllib.load(f)
        assert config["pilot"]["upload_post_enabled"] is False

    def test_upload_post_disabled_in_config_example(self):
        """config.example.toml must have upload_post_enabled = false."""
        config_path = PROJECT_ROOT / "config.example.toml"
        assert config_path.exists(), "config.example.toml not found"
        with open(config_path, "rb") as f:
            config = tomllib.load(f)
        assert config["app"]["upload_post_enabled"] is False

    def test_upload_post_auto_upload_disabled(self):
        """config.example.toml must have upload_post_auto_upload = false."""
        config_path = PROJECT_ROOT / "config.example.toml"
        with open(config_path, "rb") as f:
            config = tomllib.load(f)
        assert config["app"]["upload_post_auto_upload"] is False


class TestQuarantinedAssets:
    """Verify quarantined assets are not accessible from original paths."""

    def test_songs_directory_empty(self):
        """resource/songs/ must be empty after quarantine."""
        songs_dir = PROJECT_ROOT / "resource" / "songs"
        if songs_dir.exists():
            mp3_files = list(songs_dir.glob("*.mp3"))
            assert len(mp3_files) == 0, (
                f"resource/songs/ still contains {len(mp3_files)} MP3 files"
            )

    def test_fonts_directory_empty(self):
        """resource/fonts/ must be empty after quarantine."""
        fonts_dir = PROJECT_ROOT / "resource" / "fonts"
        if fonts_dir.exists():
            font_files = (
                list(fonts_dir.glob("*.ttf"))
                + list(fonts_dir.glob("*.ttc"))
                + list(fonts_dir.glob("*.otf"))
            )
            assert len(font_files) == 0, (
                f"resource/fonts/ still contains {len(font_files)} font files"
            )

    def test_quarantine_directory_exists(self):
        """quarantine/ directory must exist with songs and fonts."""
        quarantine_dir = PROJECT_ROOT / "quarantine"
        assert quarantine_dir.exists(), "quarantine/ directory not found"
        assert (quarantine_dir / "songs").exists(), "quarantine/songs/ not found"
        assert (quarantine_dir / "fonts").exists(), "quarantine/fonts/ not found"

    def test_quarantine_songs_not_empty(self):
        """quarantine/songs/ must contain the moved MP3 files."""
        songs_dir = PROJECT_ROOT / "quarantine" / "songs"
        mp3_files = list(songs_dir.glob("*.mp3"))
        assert len(mp3_files) > 0, "quarantine/songs/ is empty"

    def test_quarantine_fonts_not_empty(self):
        """quarantine/fonts/ must contain the moved font files."""
        fonts_dir = PROJECT_ROOT / "quarantine" / "fonts"
        font_files = (
            list(fonts_dir.glob("*.ttf"))
            + list(fonts_dir.glob("*.ttc"))
            + list(fonts_dir.glob("*.otf"))
        )
        assert len(font_files) > 0, "quarantine/fonts/ is empty"

    def test_quarantine_documentation_exists(self):
        """docs/QUARANTINED_ASSETS.md must exist."""
        doc_path = PROJECT_ROOT / "docs" / "QUARANTINED_ASSETS.md"
        assert doc_path.exists(), "docs/QUARANTINED_ASSETS.md not found"
        content = doc_path.read_text(encoding="utf-8")
        assert "quarantine" in content.lower()
        assert "license" in content.lower()


class TestGitignore:
    """Verify secrets and generated output are gitignored."""

    def _read_gitignore(self) -> str:
        gitignore_path = PROJECT_ROOT / ".gitignore"
        assert gitignore_path.exists(), ".gitignore not found"
        return gitignore_path.read_text(encoding="utf-8")

    def test_secrets_directory_ignored(self):
        """secrets/ must be in .gitignore."""
        content = self._read_gitignore()
        assert "/secrets/" in content or "secrets/" in content

    def test_config_toml_ignored(self):
        """config.toml must be in .gitignore."""
        content = self._read_gitignore()
        assert "config.toml" in content

    def test_storage_ignored(self):
        """storage/ must be in .gitignore."""
        content = self._read_gitignore()
        assert "/storage/" in content or "storage/" in content

    def test_quarantine_ignored(self):
        """quarantine/ must be in .gitignore."""
        content = self._read_gitignore()
        assert "/quarantine/" in content or "quarantine/" in content

    def test_pem_files_ignored(self):
        """*.pem must be in .gitignore."""
        content = self._read_gitignore()
        assert "*.pem" in content

    def test_key_files_ignored(self):
        """*.key must be in .gitignore."""
        content = self._read_gitignore()
        assert "*.key" in content

    def test_hardening_toml_ignored(self):
        """hardening.toml must be in .gitignore."""
        content = self._read_gitignore()
        assert "hardening.toml" in content

    def test_braintrustcrypto_output_ignored(self):
        """storage/braintrustcrypto_output/ must be in .gitignore."""
        content = self._read_gitignore()
        assert "braintrustcrypto_output" in content


class TestPilotConfigCLIOnly:
    """Verify the pilot configuration is CLI-only."""

    def test_api_server_disabled(self):
        """hardening.example.toml must have api_server_enabled = false."""
        template_path = PROJECT_ROOT / "hardening.example.toml"
        with open(template_path, "rb") as f:
            config = tomllib.load(f)
        assert config["pilot"]["api_server_enabled"] is False

    def test_webui_disabled(self):
        """hardening.example.toml must have webui_enabled = false."""
        template_path = PROJECT_ROOT / "hardening.example.toml"
        with open(template_path, "rb") as f:
            config = tomllib.load(f)
        assert config["pilot"]["webui_enabled"] is False

    def test_redis_disabled(self):
        """hardening.example.toml must have redis_enabled = false."""
        template_path = PROJECT_ROOT / "hardening.example.toml"
        with open(template_path, "rb") as f:
            config = tomllib.load(f)
        assert config["pilot"]["redis_enabled"] is False

    def test_mode_is_cli(self):
        """hardening.example.toml must have mode = 'cli'."""
        template_path = PROJECT_ROOT / "hardening.example.toml"
        with open(template_path, "rb") as f:
            config = tomllib.load(f)
        assert config["pilot"]["mode"] == "cli"

    def test_no_llm_provider_configured(self):
        """hardening.example.toml must have empty LLM provider."""
        template_path = PROJECT_ROOT / "hardening.example.toml"
        with open(template_path, "rb") as f:
            config = tomllib.load(f)
        assert config["llm"]["provider"] == ""

    def test_video_source_is_local(self):
        """hardening.example.toml must have video_source = 'local'."""
        template_path = PROJECT_ROOT / "hardening.example.toml"
        with open(template_path, "rb") as f:
            config = tomllib.load(f)
        assert config["materials"]["video_source"] == "local"

    def test_bgm_source_is_none(self):
        """hardening.example.toml must have bgm source = 'none'."""
        template_path = PROJECT_ROOT / "hardening.example.toml"
        with open(template_path, "rb") as f:
            config = tomllib.load(f)
        assert config["bgm"]["source"] == "none"

    def test_egress_allowed_hosts_empty(self):
        """hardening.example.toml must have empty egress allowed_hosts."""
        template_path = PROJECT_ROOT / "hardening.example.toml"
        with open(template_path, "rb") as f:
            config = tomllib.load(f)
        assert config["egress"]["allowed_hosts"] == []

    def test_egress_blocked_hosts_includes_social(self):
        """hardening.example.toml must block social media hosts."""
        template_path = PROJECT_ROOT / "hardening.example.toml"
        with open(template_path, "rb") as f:
            config = tomllib.load(f)
        blocked = config["egress"]["blocked_hosts"]
        assert "*.tiktok.com" in blocked
        assert "*.instagram.com" in blocked
        assert "*.youtube.com" in blocked
        assert "upload-post.com" in blocked


class TestSecretsTemplate:
    """Verify the secrets template exists and contains no real keys."""

    def test_secrets_example_exists(self):
        """secrets.example.toml must exist."""
        template_path = PROJECT_ROOT / "secrets.example.toml"
        assert template_path.exists(), "secrets.example.toml not found"

    def test_secrets_example_has_no_real_keys(self):
        """secrets.example.toml must not contain real API keys."""
        template_path = PROJECT_ROOT / "secrets.example.toml"
        content = template_path.read_text(encoding="utf-8")
        # All values should be empty strings or empty lists
        # Check for patterns that look like real keys (long alphanumeric strings)
        suspicious = re.findall(r'=\s*"[^"]{8,}"', content)
        assert len(suspicious) == 0, (
            f"secrets.example.toml may contain real keys: {suspicious}"
        )
