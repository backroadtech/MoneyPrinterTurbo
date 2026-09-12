"""
Phase 1C.1 — braintrustcrypto-briefing-v1 render-local profile tests.

Fully offline: all network access is blocked for every test in this module.
Covers the named production profile only:
- closed-set --profile CLI selection (accepted and refused values)
- request validation of the profile field
- fixed profile render parameters (chatterbox stock voice, whisper
  subtitles, deterministic 6-second clips, 16:9, sequential, no BGM)
- fail-closed narration/subtitle verification (missing, drift)
- finalized manifest narration ai_generation + hashed subtitle asset
- unchanged default behavior when no profile is selected

Runtime generation is stubbed: no Chatterbox server, no Whisper model,
and no real render is involved anywhere in this module.
"""

import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pilot_prepare
from app.models.schema import VideoAspect, VideoConcatMode
from app.services import provenance as prov
from app.services import voice
from app.services.pilot_policy import reset_pilot_policy_cache
from test.services.test_phase1b3b_pilot_prepare import (
    VALID_POLICY,
    _NetworkBlocker,
    _PatchedPath,
)

PROFILE_NAME = pilot_prepare.RENDER_LOCAL_PROFILE_BRIEFING_V1
PROFILE = pilot_prepare._RENDER_LOCAL_PROFILES[PROFILE_NAME]
STOCK_VOICE = "chatterbox:default-Female"


class _BriefingProfileBase(unittest.TestCase):
    """Isolated project-root sandbox with a valid hardening.toml."""

    def setUp(self):
        self._net = _NetworkBlocker()
        self._net.__enter__()
        self._tmp = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._tmp.name)
        (Path(self.root) / "hardening.toml").write_text(
            VALID_POLICY, encoding="utf-8"
        )
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

    # -- fixtures ----------------------------------------------------------

    def make_request(self, profile=PROFILE_NAME):
        return pilot_prepare.RenderLocalRequest(
            topic="briefing topic CANARY-c1",
            script_path="ext/script.md",
            materials=(
                pilot_prepare.RenderLocalMaterialRequest(
                    path="ext/clip1.mp4",
                    license_name="CC0",
                    license_evidence="ref-1",
                ),
            ),
            claims=(),
            profile=profile,
        )

    def make_draft(self, profile=PROFILE_NAME):
        """On-disk staged task plus durable output-null draft manifest."""
        task_id = "task-brief-001"
        task_dir = os.path.realpath(
            os.path.join(self.root, "storage", "tasks", task_id)
        )
        materials_dir = os.path.join(task_dir, "materials")
        os.makedirs(materials_dir)
        script_text = "briefing script body CANARY-c2.\n"
        script_bytes = script_text.encode("utf-8")
        script_path = os.path.join(task_dir, "script.md")
        with open(script_path, "wb") as handle:
            handle.write(script_bytes)
        material_bytes = b"material-one-bytes"
        material_path = os.path.join(materials_dir, "clip1.mp4")
        with open(material_path, "wb") as handle:
            handle.write(material_bytes)
        request = self.make_request(profile)
        loaded = pilot_prepare.RenderLocalLoadedInputs(
            request=request,
            script_path=request.script_path,
            script_bytes=script_bytes,
            script_text=script_text,
            material_paths=("ext/clip1.mp4",),
        )
        staged = pilot_prepare.RenderLocalStagedTask(
            loaded=loaded,
            task_id=task_id,
            task_dir=task_dir,
            script_path=script_path,
            script_sha256=hashlib.sha256(script_bytes).hexdigest(),
            script_text=script_text,
            materials=(
                (material_path, hashlib.sha256(material_bytes).hexdigest()),
            ),
            created_paths=(),
        )
        task_section = prov.build_task_section(
            task_id=task_id,
            topic=request.topic,
            pilot_profile="braintrustcrypto",
        )
        script_section = prov.build_script_section(
            task_dir,
            local_path="script.md",
            generation_source="local",
        )
        asset = prov.build_asset(
            task_dir,
            asset_type="video",
            source_type="local",
            local_path=os.path.join("materials", "clip1.mp4"),
            license_name="CC0",
            license_evidence="ref-1",
        )
        manifest = prov.build_manifest(
            task=task_section,
            script=script_section,
            assets=[asset],
            factual_claims=[],
            output=None,
        )
        manifest_path = prov.write_manifest_atomic(task_dir, manifest)
        with open(manifest_path, "r", encoding="utf-8") as handle:
            durable = json.load(handle)
        return pilot_prepare.RenderLocalPreparedDraft(
            staged=staged,
            manifest_path=manifest_path,
            manifest=durable,
        )

    def write_render_artifacts(self, draft, narration=True, subtitle=True):
        """Stub renderer outputs (script.json, final-1.mp4, optional
        audio.mp3/subtitle.srt); returns (task_result, hashes)."""
        staged = draft.staged
        task_dir = staged.task_dir
        params = pilot_prepare._build_render_local_video_params(draft)
        if hasattr(params, "model_dump"):
            params_dict = params.model_dump()
        else:
            params_dict = params.dict()
        script_json = {
            "script": staged.script_text.strip(),
            "params": params_dict,
        }
        with open(
            os.path.join(task_dir, "script.json"), "w", encoding="utf-8"
        ) as handle:
            json.dump(script_json, handle)
        output_bytes = b"final-video-bytes"
        output_path = os.path.join(task_dir, "final-1.mp4")
        with open(output_path, "wb") as handle:
            handle.write(output_bytes)
        narration_bytes = b"narration-audio-bytes"
        if narration:
            with open(
                os.path.join(task_dir, "audio.mp3"), "wb"
            ) as handle:
                handle.write(narration_bytes)
        subtitle_bytes = (
            b"1\n00:00:00,000 --> 00:00:02,000\nbriefing script body.\n"
        )
        if subtitle:
            with open(
                os.path.join(task_dir, "subtitle.srt"), "wb"
            ) as handle:
                handle.write(subtitle_bytes)
        task_result = {
            "task_id": staged.task_id,
            "videos": [output_path],
        }
        hashes = {
            "output": hashlib.sha256(output_bytes).hexdigest(),
            "narration": hashlib.sha256(narration_bytes).hexdigest(),
            "subtitle": hashlib.sha256(subtitle_bytes).hexdigest(),
        }
        return task_result, hashes


# ---------------------------------------------------------------------------
# Profile resolution and request validation
# ---------------------------------------------------------------------------


class TestBriefingProfileValidation(_BriefingProfileBase):
    def test_resolve_named_profile(self):
        self.assertIs(
            pilot_prepare._resolve_render_local_profile(PROFILE_NAME), PROFILE
        )
        self.assertIsNone(pilot_prepare._resolve_render_local_profile(None))

    def test_resolve_unknown_profile_refused(self):
        with self.assertRaises(pilot_prepare.PrepareError) as ctx:
            pilot_prepare._resolve_render_local_profile("bogus-profile")
        self.assertIn("accepted named profiles", str(ctx.exception))
        self.assertNotIn("bogus-profile", str(ctx.exception))

    def test_validate_request_profile_pass_through(self):
        request = pilot_prepare._validate_render_local_request(
            topic="t",
            script_path="s",
            material_paths=["m"],
            license_names=["L"],
            license_evidence=["E"],
            profile=PROFILE_NAME,
        )
        self.assertEqual(request.profile, PROFILE_NAME)
        default_request = pilot_prepare._validate_render_local_request(
            topic="t",
            script_path="s",
            material_paths=["m"],
            license_names=["L"],
            license_evidence=["E"],
        )
        self.assertIsNone(default_request.profile)

    def test_validate_request_unknown_profile_refused(self):
        with self.assertRaises(pilot_prepare.PrepareError):
            pilot_prepare._validate_render_local_request(
                topic="t",
                script_path="s",
                material_paths=["m"],
                license_names=["L"],
                license_evidence=["E"],
                profile="bogus-profile",
            )


# ---------------------------------------------------------------------------
# Fixed profile render parameters
# ---------------------------------------------------------------------------


class TestBriefingProfileParams(_BriefingProfileBase):
    def test_profile_params(self):
        draft = self.make_draft()
        params = pilot_prepare._build_render_local_video_params(draft)
        self.assertEqual(params.voice_name, STOCK_VOICE)
        self.assertIs(params.subtitle_enabled, True)
        self.assertEqual(params.video_clip_duration, 6)
        self.assertEqual(params.video_aspect, VideoAspect.landscape.value)
        self.assertEqual(
            params.video_concat_mode, VideoConcatMode.sequential.value
        )
        self.assertEqual(params.bgm_type, "none")
        self.assertEqual(params.video_count, 1)
        self.assertEqual(params.video_source, "local")
        self.assertEqual(params.video_script, "briefing script body CANARY-c2.\n")
        self.assertEqual(
            [m.provider for m in params.video_materials], ["local"]
        )

    def test_default_params_unchanged(self):
        draft = self.make_draft(profile=None)
        params = pilot_prepare._build_render_local_video_params(draft)
        self.assertEqual(params.voice_name, voice.NO_VOICE_NAME)
        self.assertIs(params.subtitle_enabled, False)
        self.assertEqual(params.video_clip_duration, 5)
        self.assertEqual(params.bgm_type, "none")


# ---------------------------------------------------------------------------
# CLI profile selection
# ---------------------------------------------------------------------------


class TestBriefingProfileCLI(_BriefingProfileBase):
    def _argv(self, *extra):
        return [
            "render-local",
            "--topic", "cli profile topic",
            "--script", "ext/script.md",
            "--material", "ext/clip1.mp4",
            "--license-name", "CC0",
            "--license-evidence", "ref-1",
            *extra,
        ]

    def _finalized_mock(self):
        task_dir = os.path.join("storage", "tasks", "task-cli-brief")
        finalized = unittest.mock.Mock()
        finalized.verified.draft.staged.task_id = "task-cli-brief"
        finalized.verified.draft.staged.task_dir = task_dir
        finalized.manifest_path = os.path.join(
            task_dir, "provenance_manifest.json"
        )
        finalized.marked_output_path = os.path.join(
            task_dir, "final-1__NEEDS_HUMAN_REVIEW.mp4"
        )
        return finalized

    def test_cli_profile_accepted(self):
        finalized = self._finalized_mock()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with patch.object(
            pilot_prepare,
            "_run_render_local_task",
            return_value=finalized,
        ) as orch_mock, patch("sys.stdout", stdout), patch(
            "sys.stderr", stderr
        ):
            code = pilot_prepare.run(self._argv("--profile", PROFILE_NAME))
        self.assertEqual(code, 0)
        orch_mock.assert_called_once_with(
            topic="cli profile topic",
            script_path="ext/script.md",
            material_paths=["ext/clip1.mp4"],
            license_names=["CC0"],
            license_evidence=["ref-1"],
            claims=[],
            claim_sources=[],
            profile=PROFILE_NAME,
        )
        self.assertEqual(stderr.getvalue(), "")

    def test_cli_unknown_profile_rejected(self):
        stderr = io.StringIO()
        with patch.object(
            pilot_prepare, "_run_render_local_task"
        ) as orch_mock, patch("sys.stderr", stderr):
            with self.assertRaises(SystemExit) as ctx:
                pilot_prepare.run(self._argv("--profile", "bogus-profile"))
        self.assertEqual(ctx.exception.code, 2)
        orch_mock.assert_not_called()


# ---------------------------------------------------------------------------
# Fail-closed narration/subtitle verification
# ---------------------------------------------------------------------------


class TestBriefingProfileVerify(_BriefingProfileBase):
    def test_verify_happy_path(self):
        draft = self.make_draft()
        task_result, hashes = self.write_render_artifacts(draft)
        verified = pilot_prepare._verify_render_local_render(
            draft, task_result
        )
        self.assertEqual(verified.output_sha256, hashes["output"])
        self.assertEqual(verified.narration_sha256, hashes["narration"])
        self.assertEqual(verified.subtitle_sha256, hashes["subtitle"])
        self.assertTrue(verified.narration_path.endswith("audio.mp3"))
        self.assertTrue(verified.subtitle_path.endswith("subtitle.srt"))

    def test_verify_missing_narration_refused(self):
        draft = self.make_draft()
        task_result, _hashes = self.write_render_artifacts(
            draft, narration=False
        )
        with self.assertRaises(pilot_prepare.PrepareError):
            pilot_prepare._verify_render_local_render(draft, task_result)

    def test_verify_missing_subtitle_refused(self):
        draft = self.make_draft()
        task_result, _hashes = self.write_render_artifacts(
            draft, subtitle=False
        )
        with self.assertRaises(pilot_prepare.PrepareError):
            pilot_prepare._verify_render_local_render(draft, task_result)

    def test_verify_profile_param_drift_refused(self):
        draft = self.make_draft()
        task_result, _hashes = self.write_render_artifacts(draft)
        script_json_path = os.path.join(draft.staged.task_dir, "script.json")
        with open(script_json_path, "r", encoding="utf-8") as handle:
            script_json = json.load(handle)
        script_json["params"]["voice_name"] = voice.NO_VOICE_NAME
        script_json["params"]["subtitle_enabled"] = False
        script_json["params"]["video_clip_duration"] = 5
        with open(script_json_path, "w", encoding="utf-8") as handle:
            json.dump(script_json, handle)
        with self.assertRaises(pilot_prepare.PrepareError):
            pilot_prepare._verify_render_local_render(draft, task_result)


# ---------------------------------------------------------------------------
# Finalized manifest provenance
# ---------------------------------------------------------------------------


class TestBriefingProfileFinalization(_BriefingProfileBase):
    def test_finalize_records_narration_and_subtitle(self):
        draft = self.make_draft()
        task_result, hashes = self.write_render_artifacts(draft)
        verified = pilot_prepare._verify_render_local_render(
            draft, task_result
        )
        finalized = pilot_prepare._finalize_render_local_marked_output(
            verified
        )
        manifest = finalized.manifest

        # Marked output and output section.
        self.assertTrue(os.path.isfile(finalized.marked_output_path))
        self.assertEqual(manifest["output"]["sha256"], hashes["output"])
        self.assertEqual(
            manifest["output"]["review_status"], "NEEDS_HUMAN_REVIEW"
        )

        # Narration recorded as an ai_generation.
        self.assertEqual(len(manifest["ai_generations"]), 1)
        narration_entry = manifest["ai_generations"][0]
        self.assertEqual(narration_entry["provider"], "chatterbox")
        self.assertEqual(narration_entry["model"], "chatterbox")
        self.assertEqual(narration_entry["output_type"], "audio")
        self.assertEqual(
            narration_entry["prompt_hash"],
            hashlib.sha256(
                "briefing script body CANARY-c2.\n".encode("utf-8")
            ).hexdigest(),
        )
        self.assertEqual(
            narration_entry["parameters"]["voice_name"], STOCK_VOICE
        )
        self.assertEqual(
            narration_entry["parameters"]["audio_sha256"],
            hashes["narration"],
        )

        # Generated SRT recorded as a hashed manifest asset; the original
        # material asset is preserved first and unchanged.
        self.assertEqual(len(manifest["assets"]), 2)
        self.assertEqual(
            manifest["assets"][0]["sha256"],
            draft.staged.materials[0][1],
        )
        subtitle_asset = manifest["assets"][1]
        self.assertEqual(subtitle_asset["asset_type"], "subtitle")
        self.assertEqual(subtitle_asset["source_type"], "ai_generated")
        self.assertEqual(subtitle_asset["provider"], "faster-whisper")
        self.assertEqual(subtitle_asset["sha256"], hashes["subtitle"])
        self.assertTrue(
            subtitle_asset["local_path"].endswith("subtitle.srt")
        )

        prov.validate_manifest(manifest)

    def test_finalize_default_profile_unchanged(self):
        draft = self.make_draft(profile=None)
        task_result, hashes = self.write_render_artifacts(
            draft, narration=False, subtitle=False
        )
        verified = pilot_prepare._verify_render_local_render(
            draft, task_result
        )
        self.assertIsNone(verified.narration_path)
        self.assertIsNone(verified.subtitle_path)
        finalized = pilot_prepare._finalize_render_local_marked_output(
            verified
        )
        manifest = finalized.manifest
        self.assertEqual(manifest["ai_generations"], [])
        self.assertEqual(len(manifest["assets"]), 1)
        self.assertEqual(manifest["output"]["sha256"], hashes["output"])
        prov.validate_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
