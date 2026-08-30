"""
Phase 1B.2C.3 — Deny unapproved material providers in BrainTrustCrypto pilot mode.

When MPT_PILOT_PROFILE=braintrustcrypto:
1. Pixabay search must fail closed before any network request.
2. Coverr search must fail closed before any network request.
3. Wavespeed submission must fail closed before credentials are read, SDKs
   are initialized, or network requests occur.
4. Wavespeed polling must fail closed before any network request.
5. Pexels remains the only potentially permitted stock-media provider.
6. Pexels must remain unusable until a real host allowlist and API key are
   separately approved.
7. Non-pilot upstream behavior remains unchanged.

All tests use mocks only. No live network requests are made.
"""

import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import requests

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.config import config
from app.services import material
from app.services.pilot_policy import PilotPolicyError, reset_pilot_policy_cache


class _PilotTestBase(unittest.TestCase):
    """Shared setup/teardown for pilot-mode tests."""

    def setUp(self):
        reset_pilot_policy_cache()
        self._env_patcher = patch.dict(
            os.environ, {"MPT_PILOT_PROFILE": "braintrustcrypto"}
        )
        self._env_patcher.start()
        self._original_app_config = dict(config.app)
        self._original_proxy_config = dict(config.proxy)

    def tearDown(self):
        self._env_patcher.stop()
        reset_pilot_policy_cache()
        config.app.clear()
        config.app.update(self._original_app_config)
        config.proxy.clear()
        config.proxy.update(self._original_proxy_config)

    @staticmethod
    def _make_policy(hosts=("api.pexels.com",)):
        """Minimal pilot policy stub with egress accessors."""
        return SimpleNamespace(
            egress_allowed_hosts=frozenset(hosts),
            egress_allow_redirects=False,
            egress_max_redirects=0,
            policy_path="/fake/hardening.toml",
        )


# ---------------------------------------------------------------------------
# 1. Pixabay denied before network access
# ---------------------------------------------------------------------------

class TestPixabayDeniedInPilotMode(_PilotTestBase):
    """Pixabay search must fail closed before any network request."""

    def test_pixabay_denied_before_network(self):
        policy = self._make_policy()
        with patch("app.services.material.get_pilot_policy", return_value=policy), \
             patch("app.services.material.requests.get") as mock_get, \
             patch("app.services.material.requests.post") as mock_post, \
             patch("app.services.material.safe_json_get") as mock_sjg, \
             patch("app.services.material.safe_download") as mock_sd:
            with self.assertRaises(PilotPolicyError) as ctx:
                material.search_videos_pixabay("nature", minimum_duration=5)
            self.assertIn("pixabay", str(ctx.exception).lower())
            mock_get.assert_not_called()
            mock_post.assert_not_called()
            mock_sjg.assert_not_called()
            mock_sd.assert_not_called()

    def test_pixabay_denied_before_api_key_read(self):
        """The gate must fire before get_api_key is called for pixabay."""
        policy = self._make_policy()
        with patch("app.services.material.get_pilot_policy", return_value=policy), \
             patch("app.services.material.get_api_key") as mock_key:
            with self.assertRaises(PilotPolicyError):
                material.search_videos_pixabay("nature", minimum_duration=5)
            mock_key.assert_not_called()

    def test_pixabay_denied_regardless_of_aspect(self):
        """Denial applies to all video aspects."""
        policy = self._make_policy()
        for aspect in (
            material.VideoAspect.portrait,
            material.VideoAspect.landscape,
            material.VideoAspect.square,
        ):
            with self.subTest(aspect=aspect), \
                 patch("app.services.material.get_pilot_policy", return_value=policy), \
                 patch("app.services.material.requests.get") as mock_get:
                with self.assertRaises(PilotPolicyError):
                    material.search_videos_pixabay(
                        "nature", minimum_duration=5, video_aspect=aspect
                    )
                mock_get.assert_not_called()

    def test_pixabay_no_fallback_to_original_implementation(self):
        """Prove Pixabay does not fall back to its original network path."""
        policy = self._make_policy()
        config.app["pixabay_api_keys"] = ["pixabay-key"]
        config.proxy.clear()
        with patch("app.services.material.get_pilot_policy", return_value=policy), \
             patch("app.services.material.requests.get") as mock_get:
            with self.assertRaises(PilotPolicyError):
                material.search_videos_pixabay("nature", minimum_duration=5)
            mock_get.assert_not_called()


# ---------------------------------------------------------------------------
# 2. Coverr denied before network access
# ---------------------------------------------------------------------------

class TestCoverrDeniedInPilotMode(_PilotTestBase):
    """Coverr search must fail closed before any network request."""

    def test_coverr_denied_before_network(self):
        policy = self._make_policy()
        with patch("app.services.material.get_pilot_policy", return_value=policy), \
             patch("app.services.material.requests.get") as mock_get, \
             patch("app.services.material.requests.post") as mock_post, \
             patch("app.services.material.safe_json_get") as mock_sjg, \
             patch("app.services.material.safe_download") as mock_sd:
            with self.assertRaises(PilotPolicyError) as ctx:
                material.search_videos_coverr("nature", minimum_duration=5)
            self.assertIn("coverr", str(ctx.exception).lower())
            mock_get.assert_not_called()
            mock_post.assert_not_called()
            mock_sjg.assert_not_called()
            mock_sd.assert_not_called()

    def test_coverr_denied_before_api_key_read(self):
        """The gate must fire before get_api_key is called for coverr."""
        policy = self._make_policy()
        with patch("app.services.material.get_pilot_policy", return_value=policy), \
             patch("app.services.material.get_api_key") as mock_key:
            with self.assertRaises(PilotPolicyError):
                material.search_videos_coverr("nature", minimum_duration=5)
            mock_key.assert_not_called()

    def test_coverr_denied_regardless_of_aspect(self):
        """Denial applies to all video aspects."""
        policy = self._make_policy()
        for aspect in (
            material.VideoAspect.portrait,
            material.VideoAspect.landscape,
            material.VideoAspect.square,
        ):
            with self.subTest(aspect=aspect), \
                 patch("app.services.material.get_pilot_policy", return_value=policy), \
                 patch("app.services.material.requests.get") as mock_get:
                with self.assertRaises(PilotPolicyError):
                    material.search_videos_coverr(
                        "nature", minimum_duration=5, video_aspect=aspect
                    )
                mock_get.assert_not_called()

    def test_coverr_no_fallback_to_original_implementation(self):
        """Prove Coverr does not fall back to its original network path."""
        policy = self._make_policy()
        config.app["coverr_api_keys"] = ["coverr-key"]
        config.proxy.clear()
        with patch("app.services.material.get_pilot_policy", return_value=policy), \
             patch("app.services.material.requests.get") as mock_get:
            with self.assertRaises(PilotPolicyError):
                material.search_videos_coverr("nature", minimum_duration=5)
            mock_get.assert_not_called()


# ---------------------------------------------------------------------------
# 3. Wavespeed submission denied before credential or network access
# ---------------------------------------------------------------------------

class TestWavespeedSubmissionDeniedInPilotMode(_PilotTestBase):
    """Wavespeed submission must fail closed before credentials or network."""

    def test_wavespeed_submission_denied_before_network(self):
        policy = self._make_policy()
        with patch("app.services.material.get_pilot_policy", return_value=policy), \
             patch("app.services.material.requests.get") as mock_get, \
             patch("app.services.material.requests.post") as mock_post, \
             patch("app.services.material.safe_json_get") as mock_sjg, \
             patch("app.services.material.safe_download") as mock_sd:
            with self.assertRaises(PilotPolicyError) as ctx:
                material.generate_videos_wavespeed("sunrise", minimum_duration=5)
            self.assertIn("wavespeed", str(ctx.exception).lower())
            mock_get.assert_not_called()
            mock_post.assert_not_called()
            mock_sjg.assert_not_called()
            mock_sd.assert_not_called()

    def test_wavespeed_submission_denied_before_api_key_read(self):
        """The gate must fire before get_api_key is called for wavespeed."""
        policy = self._make_policy()
        with patch("app.services.material.get_pilot_policy", return_value=policy), \
             patch("app.services.material.get_api_key") as mock_key:
            with self.assertRaises(PilotPolicyError):
                material.generate_videos_wavespeed("sunrise", minimum_duration=5)
            mock_key.assert_not_called()

    def test_wavespeed_submission_denied_regardless_of_aspect(self):
        """Denial applies to all video aspects."""
        policy = self._make_policy()
        for aspect in (
            material.VideoAspect.portrait,
            material.VideoAspect.landscape,
            material.VideoAspect.square,
        ):
            with self.subTest(aspect=aspect), \
                 patch("app.services.material.get_pilot_policy", return_value=policy), \
                 patch("app.services.material.requests.post") as mock_post:
                with self.assertRaises(PilotPolicyError):
                    material.generate_videos_wavespeed(
                        "sunrise", minimum_duration=5, video_aspect=aspect
                    )
                mock_post.assert_not_called()

    def test_wavespeed_no_fallback_to_original_implementation(self):
        """Prove Wavespeed does not fall back to its original network path."""
        policy = self._make_policy()
        config.app["wavespeed_api_keys"] = ["wavespeed-key"]
        config.proxy.clear()
        with patch("app.services.material.get_pilot_policy", return_value=policy), \
             patch("app.services.material.requests.post") as mock_post, \
             patch("app.services.material.requests.get") as mock_get:
            with self.assertRaises(PilotPolicyError):
                material.generate_videos_wavespeed("sunrise", minimum_duration=5)
            mock_post.assert_not_called()
            mock_get.assert_not_called()

    def test_wavespeed_denied_before_config_model_read(self):
        """The gate must fire before wavespeed_text_to_video_model is read."""
        policy = self._make_policy()
        original_get = config.app.get
        config_reads = []

        def tracking_get(key, default=None):
            config_reads.append(key)
            return original_get(key, default)

        with patch("app.services.material.get_pilot_policy", return_value=policy), \
             patch.object(config.app, "get", side_effect=tracking_get):
            with self.assertRaises(PilotPolicyError):
                material.generate_videos_wavespeed("sunrise", minimum_duration=5)
            # wavespeed_text_to_video_model should never be read
            self.assertNotIn("wavespeed_text_to_video_model", config_reads)


# ---------------------------------------------------------------------------
# 4. Wavespeed polling denied before network access
# ---------------------------------------------------------------------------

class TestWavespeedPollingDeniedInPilotMode(_PilotTestBase):
    """Wavespeed polling must fail closed before any network request."""

    def test_wavespeed_polling_denied_before_network(self):
        policy = self._make_policy()
        with patch("app.services.material.get_pilot_policy", return_value=policy), \
             patch("app.services.material.requests.get") as mock_get, \
             patch("app.services.material.requests.post") as mock_post:
            with self.assertRaises(PilotPolicyError) as ctx:
                material._wait_for_wavespeed_prediction(
                    prediction_id="pred-123",
                    headers={"Authorization": "Bearer key"},
                    api_key="key",
                )
            self.assertIn("wavespeed", str(ctx.exception).lower())
            mock_get.assert_not_called()
            mock_post.assert_not_called()

    def test_wavespeed_polling_denied_regardless_of_prediction_id(self):
        """Denial applies regardless of prediction ID value."""
        policy = self._make_policy()
        for pred_id in ("pred-abc", "pred-123", "", "pred-xyz-789"):
            with self.subTest(prediction_id=pred_id), \
                 patch("app.services.material.get_pilot_policy", return_value=policy), \
                 patch("app.services.material.requests.get") as mock_get:
                with self.assertRaises(PilotPolicyError):
                    material._wait_for_wavespeed_prediction(
                        prediction_id=pred_id,
                        headers={},
                        api_key="key",
                    )
                mock_get.assert_not_called()


# ---------------------------------------------------------------------------
# 5. Pexels remains the only potentially permitted provider
# ---------------------------------------------------------------------------

class TestPexelsRemainsPotentiallyPermitted(_PilotTestBase):
    """Pexels must not be blocked by the provider gate itself."""

    def test_pexels_not_blocked_by_provider_gate(self):
        """
        _require_pilot_provider_allowed must NOT raise for pexels.
        Pexels has its own separate gating (allowlist + API key) from 1B.2C.2.
        """
        policy = self._make_policy()
        with patch("app.services.material.get_pilot_policy", return_value=policy):
            # This should NOT raise — pexels is not in the denied list
            # The function _require_pilot_provider_allowed is only called for
            # non-pexels providers, so we verify indirectly that pexels search
            # proceeds to its own pilot path (which requires allowlist + key).
            config.app["pexels_api_keys"] = ["test-key"]
            with patch("app.services.material.safe_json_get",
                       return_value={"videos": []}):
                results = material.search_videos_pexels("nature", minimum_duration=5)
                self.assertEqual(results, [])

    def test_pexels_still_requires_allowlist(self):
        """Pexels remains unusable without a real host allowlist."""
        policy = self._make_policy(hosts=())
        config.app["pexels_api_keys"] = ["test-key"]
        with patch("app.services.material.get_pilot_policy", return_value=policy), \
             patch("app.services.material.safe_json_get") as mock_sjg:
            with self.assertRaises(PilotPolicyError):
                material.search_videos_pexels("nature", minimum_duration=5)
            mock_sjg.assert_not_called()

    def test_pexels_still_requires_api_key(self):
        """Pexels remains unusable without an API key."""
        policy = self._make_policy()
        with patch("app.services.material.get_pilot_policy", return_value=policy), \
             patch("app.services.material.get_api_key", return_value=""), \
             patch("app.services.material.safe_json_get") as mock_sjg:
            with self.assertRaises(PilotPolicyError):
                material.search_videos_pexels("nature", minimum_duration=5)
            mock_sjg.assert_not_called()


# ---------------------------------------------------------------------------
# 6. download_videos routing in pilot mode
# ---------------------------------------------------------------------------

class TestDownloadVideosRoutingInPilotMode(_PilotTestBase):
    """download_videos must route denied providers through the gate."""

    def test_download_videos_pixabay_denied(self):
        policy = self._make_policy()
        with patch("app.services.material.get_pilot_policy", return_value=policy), \
             patch("app.services.material.requests.get") as mock_get:
            with self.assertRaises(PilotPolicyError):
                material.download_videos(
                    task_id="test-pixabay-denied",
                    search_terms=["nature"],
                    source="pixabay",
                    audio_duration=5,
                    max_clip_duration=5,
                )
            mock_get.assert_not_called()

    def test_download_videos_coverr_denied(self):
        policy = self._make_policy()
        with patch("app.services.material.get_pilot_policy", return_value=policy), \
             patch("app.services.material.requests.get") as mock_get:
            with self.assertRaises(PilotPolicyError):
                material.download_videos(
                    task_id="test-coverr-denied",
                    search_terms=["nature"],
                    source="coverr",
                    audio_duration=5,
                    max_clip_duration=5,
                )
            mock_get.assert_not_called()

    def test_download_videos_wavespeed_denied(self):
        policy = self._make_policy()
        with patch("app.services.material.get_pilot_policy", return_value=policy), \
             patch("app.services.material.requests.post") as mock_post, \
             patch("app.services.material.requests.get") as mock_get:
            with self.assertRaises(PilotPolicyError):
                material.download_videos(
                    task_id="test-wavespeed-denied",
                    search_terms=["nature"],
                    source="wavespeed",
                    audio_duration=5,
                    max_clip_duration=5,
                )
            mock_post.assert_not_called()
            mock_get.assert_not_called()


# ---------------------------------------------------------------------------
# 7. Non-pilot upstream behavior unchanged
# ---------------------------------------------------------------------------

class TestNonPilotUpstreamBehaviorUnchanged(unittest.TestCase):
    """When pilot mode is NOT active, all providers must work as before."""

    def setUp(self):
        reset_pilot_policy_cache()
        self._original_app_config = dict(config.app)
        self._original_proxy_config = dict(config.proxy)
        # Ensure MPT_PILOT_PROFILE is NOT set
        self._env_patcher = patch.dict(os.environ, {}, clear=False)
        self._env_patcher.start()
        # Remove the env var if it was set
        if "MPT_PILOT_PROFILE" in os.environ:
            del os.environ["MPT_PILOT_PROFILE"]

    def tearDown(self):
        self._env_patcher.stop()
        reset_pilot_policy_cache()
        config.app.clear()
        config.app.update(self._original_app_config)
        config.proxy.clear()
        config.proxy.update(self._original_proxy_config)

    def test_pixabay_works_without_pilot(self):
        """Pixabay search proceeds normally when pilot mode is off."""
        config.app["pixabay_api_keys"] = ["pixabay-key"]
        config.proxy.clear()

        fake_response = SimpleNamespace(
            status_code=200,
            headers={"content-type": "application/json"},
            text="",
            json=lambda: {
                "hits": [
                    {
                        "id": 1,
                        "duration": 8,
                        "videos": {
                            "large": {
                                "width": 1080,
                                "height": 1920,
                                "url": "https://example.com/pixabay.mp4",
                            }
                        },
                    }
                ]
            },
        )

        with patch("app.services.material.requests.get", return_value=fake_response):
            results = material.search_videos_pixabay(
                "nature", minimum_duration=1, video_aspect=material.VideoAspect.portrait
            )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].provider, "pixabay")

    def test_coverr_works_without_pilot(self):
        """Coverr search proceeds normally when pilot mode is off."""
        config.app["coverr_api_keys"] = ["coverr-key"]
        config.proxy.clear()

        fake_response = SimpleNamespace(
            json=lambda: {
                "hits": [
                    {
                        "id": "abc",
                        "duration": 10,
                        "max_width": 1080,
                        "max_height": 1920,
                        "urls": {"mp4_download": "https://example.com/coverr.mp4"},
                    }
                ]
            }
        )

        with patch("app.services.material.requests.get", return_value=fake_response):
            results = material.search_videos_coverr(
                "nature", minimum_duration=1, video_aspect=material.VideoAspect.portrait
            )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].provider, "coverr")

    def test_wavespeed_works_without_pilot(self):
        """Wavespeed generation proceeds normally when pilot mode is off."""
        config.app["wavespeed_api_keys"] = ["wavespeed-key"]
        config.proxy.clear()

        submit_response = SimpleNamespace(
            status_code=200,
            json=lambda: {"code": 200, "data": {"id": "pred-1"}},
        )
        poll_response = SimpleNamespace(
            status_code=200,
            json=lambda: {
                "code": 200,
                "data": {
                    "id": "pred-1",
                    "status": "completed",
                    "outputs": ["https://cdn.example.com/out.mp4"],
                },
            },
        )

        with patch("app.services.material.requests.post", return_value=submit_response), \
             patch("app.services.material.requests.get", return_value=poll_response):
            results = material.generate_videos_wavespeed(
                "sunrise", minimum_duration=5, video_aspect=material.VideoAspect.portrait
            )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].provider, "wavespeed")

    def test_pexels_works_without_pilot(self):
        """Pexels search proceeds normally when pilot mode is off."""
        config.app["pexels_api_keys"] = ["pexels-key"]
        config.proxy.clear()

        fake_response = SimpleNamespace(
            json=lambda: {
                "videos": [
                    {
                        "id": 1,
                        "duration": 8,
                        "video_files": [
                            {
                                "id": 11,
                                "width": 1080,
                                "height": 1920,
                                "link": "https://example.com/pexels.mp4",
                            }
                        ],
                    }
                ]
            }
        )

        with patch("app.services.material.requests.get", return_value=fake_response):
            results = material.search_videos_pexels(
                "nature", minimum_duration=1, video_aspect=material.VideoAspect.portrait
            )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].provider, "pexels")

    def test_provider_gate_is_noop_without_pilot(self):
        """_require_pilot_provider_allowed must be a no-op when pilot is off."""
        # Should not raise for any provider
        material._require_pilot_provider_allowed("pixabay")
        material._require_pilot_provider_allowed("coverr")
        material._require_pilot_provider_allowed("wavespeed")
        material._require_pilot_provider_allowed("pexels")


# ---------------------------------------------------------------------------
# 8. Error message quality
# ---------------------------------------------------------------------------

class TestErrorMessageQuality(_PilotTestBase):
    """Error messages must be informative and not leak secrets."""

    def test_error_message_includes_provider_name(self):
        policy = self._make_policy()
        for provider, func in [
            ("pixabay", material.search_videos_pixabay),
            ("coverr", material.search_videos_coverr),
            ("wavespeed", material.generate_videos_wavespeed),
        ]:
            with self.subTest(provider=provider), \
                 patch("app.services.material.get_pilot_policy", return_value=policy):
                with self.assertRaises(PilotPolicyError) as ctx:
                    func("test", minimum_duration=5)
                self.assertIn(provider, str(ctx.exception).lower())

    def test_error_message_mentions_pexels_as_alternative(self):
        policy = self._make_policy()
        with patch("app.services.material.get_pilot_policy", return_value=policy):
            with self.assertRaises(PilotPolicyError) as ctx:
                material.search_videos_pixabay("test", minimum_duration=5)
            self.assertIn("Pexels", str(ctx.exception))

    def test_error_message_does_not_leak_api_keys(self):
        policy = self._make_policy()
        config.app["pixabay_api_keys"] = ["super-secret-pixabay-key-12345"]
        config.app["coverr_api_keys"] = ["super-secret-coverr-key-12345"]
        config.app["wavespeed_api_keys"] = ["super-secret-wavespeed-key-12345"]
        with patch("app.services.material.get_pilot_policy", return_value=policy):
            for func in [
                material.search_videos_pixabay,
                material.search_videos_coverr,
                material.generate_videos_wavespeed,
            ]:
                with self.assertRaises(PilotPolicyError) as ctx:
                    func("test", minimum_duration=5)
                error_msg = str(ctx.exception)
                self.assertNotIn("super-secret", error_msg)
                self.assertNotIn("12345", error_msg)


if __name__ == "__main__":
    unittest.main()
