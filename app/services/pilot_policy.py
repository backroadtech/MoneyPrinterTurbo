"""
BrainTrustCrypto pilot policy enforcement.

This module provides runtime loading and validation of the BrainTrustCrypto
hardening policy (hardening.toml). When a pilot profile is active, it gates
entry points and services to enforce the pilot restrictions.

Policy activation:
- Set environment variable MPT_PILOT_PROFILE=braintrustcrypto to activate
- The policy file must exist at hardening.toml (gitignored, local only)
- Missing, malformed, or unsafe policy values fail closed (raise PilotPolicyError)

Gate functions:
- require_pilot_policy() — validate policy at import time for gated entry points
- gate_api_server() — refuse API startup in pilot mode
- gate_webui() — refuse WebUI startup in pilot mode
- gate_redis() — refuse Redis initialization in pilot mode
- gate_upload_post() — refuse upload-post before credentials/network
- gate_bgm_selection() — refuse restricted BGM sources in pilot mode
- gate_font_selection() — refuse restricted fonts in pilot mode
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any


class PilotPolicyError(RuntimeError):
    """Raised when a pilot policy violation is detected."""

    def __init__(self, message: str, *, policy_path: str | None = None):
        self.policy_path = policy_path
        super().__init__(message)


class PilotPolicy:
    """Loaded and validated BrainTrustCrypto pilot policy."""

    def __init__(self, raw: dict[str, Any], policy_path: str):
        self._raw = raw
        self.policy_path = policy_path
        self._validate()

    def _validate(self) -> None:
        """Fail closed on any missing, malformed, or unsafe value."""
        pilot = self._raw.get("pilot")
        if not isinstance(pilot, dict):
            raise PilotPolicyError(
                "pilot policy missing [pilot] section",
                policy_path=self.policy_path,
            )

        # Required boolean fields — must be exactly False, not just falsy
        required_false = (
            "api_server_enabled",
            "webui_enabled",
            "upload_post_enabled",
            "redis_enabled",
        )
        for field in required_false:
            value = pilot.get(field)
            if value is not False:
                raise PilotPolicyError(
                    f"pilot policy requires {field} = false, got {value!r}",
                    policy_path=self.policy_path,
                )

        # Mode must be exactly "cli"
        mode = pilot.get("mode")
        if mode != "cli":
            raise PilotPolicyError(
                f"pilot policy requires mode = 'cli', got {mode!r}",
                policy_path=self.policy_path,
            )

        # BGM source must be exactly "none"
        bgm = self._raw.get("bgm", {})
        if not isinstance(bgm, dict):
            raise PilotPolicyError(
                "pilot policy missing [bgm] section",
                policy_path=self.policy_path,
            )
        bgm_source = bgm.get("source")
        if bgm_source != "none":
            raise PilotPolicyError(
                f"pilot policy requires bgm.source = 'none', got {bgm_source!r}",
                policy_path=self.policy_path,
            )

        # Materials video_source must be "local" or absent (defaults to local)
        materials = self._raw.get("materials", {})
        if isinstance(materials, dict):
            video_source = materials.get("video_source")
            if video_source is not None and video_source != "local":
                raise PilotPolicyError(
                    f"pilot policy requires materials.video_source = 'local', "
                    f"got {video_source!r}",
                    policy_path=self.policy_path,
                )

    @property
    def is_pilot_active(self) -> bool:
        """True when the BrainTrustCrypto pilot profile is explicitly selected."""
        return os.getenv("MPT_PILOT_PROFILE", "").strip().lower() == "braintrustcrypto"

    @property
    def egress_allowed_hosts(self) -> frozenset[str]:
        """
        Return the egress hostname allowlist from hardening.toml.

        Missing or empty allowlist fails closed (returns empty frozenset).
        """
        egress = self._raw.get("egress", {})
        if not isinstance(egress, dict):
            return frozenset()
        hosts = egress.get("allowed_hosts", [])
        if not isinstance(hosts, list):
            return frozenset()
        return frozenset(str(h).strip() for h in hosts if h and str(h).strip())

    @property
    def egress_allow_redirects(self) -> bool:
        """Whether redirects are allowed for media downloads."""
        egress = self._raw.get("egress", {})
        if not isinstance(egress, dict):
            return False
        return bool(egress.get("allow_redirects", False))

    @property
    def egress_max_redirects(self) -> int:
        """Maximum number of revalidated redirects."""
        egress = self._raw.get("egress", {})
        if not isinstance(egress, dict):
            return 0
        try:
            return max(0, min(3, int(egress.get("max_redirects", 3))))
        except (TypeError, ValueError):
            return 0

    def require_not_api_server(self) -> None:
        """Refuse API server startup in pilot mode."""
        raise PilotPolicyError(
            "BrainTrustCrypto pilot mode prohibits API server startup. "
            "Use CLI mode only.",
            policy_path=self.policy_path,
        )

    def require_not_webui(self) -> None:
        """Refuse WebUI startup in pilot mode."""
        raise PilotPolicyError(
            "BrainTrustCrypto pilot mode prohibits WebUI startup. "
            "Use CLI mode only.",
            policy_path=self.policy_path,
        )

    def require_not_redis(self) -> None:
        """Refuse Redis initialization in pilot mode."""
        raise PilotPolicyError(
            "BrainTrustCrypto pilot mode prohibits Redis. "
            "Use in-memory state only.",
            policy_path=self.policy_path,
        )

    def require_not_upload_post(self) -> None:
        """Refuse upload-post before credentials are read or network occurs."""
        raise PilotPolicyError(
            "BrainTrustCrypto pilot mode prohibits upload-post publishing. "
            "All publishing is disabled.",
            policy_path=self.policy_path,
        )

    def require_bgm_source_allowed(self, bgm_type: str, bgm_file: str = "") -> None:
        """Refuse restricted BGM sources in pilot mode."""
        if bgm_type not in ("", "none"):
            raise PilotPolicyError(
                f"BrainTrustCrypto pilot mode prohibits BGM source '{bgm_type}'. "
                "Only 'none' is allowed.",
                policy_path=self.policy_path,
            )
        if bgm_file:
            raise PilotPolicyError(
                f"BrainTrustCrypto pilot mode prohibits custom BGM file '{bgm_file}'. "
                "No bundled or custom music is allowed.",
                policy_path=self.policy_path,
            )

    def require_font_allowed(self, font_name: str) -> None:
        """Refuse restricted fonts in pilot mode."""
        # All bundled fonts are UNVERIFIED_RESTRICTED
        raise PilotPolicyError(
            f"BrainTrustCrypto pilot mode prohibits font '{font_name}'. "
            "All bundled fonts are UNVERIFIED_RESTRICTED.",
            policy_path=self.policy_path,
        )


def _load_policy_file(policy_path: Path) -> dict[str, Any]:
    """Load and parse hardening.toml, failing closed on any error."""
    if not policy_path.is_file():
        raise PilotPolicyError(
            f"pilot policy file not found: {policy_path}",
            policy_path=str(policy_path),
        )

    try:
        with open(policy_path, "rb") as f:
            return tomllib.load(f)
    except tomllib.TOMLDecodeError as exc:
        raise PilotPolicyError(
            f"pilot policy file is malformed TOML: {exc}",
            policy_path=str(policy_path),
        ) from exc
    except OSError as exc:
        raise PilotPolicyError(
            f"pilot policy file cannot be read: {exc}",
            policy_path=str(policy_path),
        ) from exc


def load_pilot_policy() -> PilotPolicy | None:
    """
    Load the BrainTrustCrypto pilot policy if the profile is active.

    Returns None when MPT_PILOT_PROFILE is not set to 'braintrustcrypto'.
    Raises PilotPolicyError when the profile is active but the policy is
    missing, malformed, or contains unsafe values.
    """
    profile = os.getenv("MPT_PILOT_PROFILE", "").strip().lower()
    if profile != "braintrustcrypto":
        return None

    # Policy file lives at project root, gitignored
    root_dir = Path(__file__).resolve().parent.parent.parent
    policy_path = root_dir / "hardening.toml"

    raw = _load_policy_file(policy_path)
    return PilotPolicy(raw, str(policy_path))


_cached_policy: PilotPolicy | None = None
_policy_loaded = False


def get_pilot_policy() -> PilotPolicy | None:
    """
    Lazily load and return the BrainTrustCrypto pilot policy.

    Returns None when MPT_PILOT_PROFILE is not set to 'braintrustcrypto'.
    Raises PilotPolicyError when the profile is active but the policy is
    missing, malformed, or contains unsafe values.
    Result is cached after first call.
    """
    global _cached_policy, _policy_loaded
    if _policy_loaded:
        return _cached_policy

    _cached_policy = load_pilot_policy()
    _policy_loaded = True
    return _cached_policy


def reset_pilot_policy_cache() -> None:
    """Reset the lazy cache. Used by tests to re-resolve policy."""
    global _cached_policy, _policy_loaded
    _cached_policy = None
    _policy_loaded = False
