"""
Phase 1B.3B — Offline CLI dry-run and provenance integration.

Safe pilot CLI that prepares a BrainTrustCrypto task directory and a draft
provenance manifest WITHOUT calling providers, downloading assets, rendering
media, or publishing anything.

This is a standalone entry point, intentionally separate from cli.py so the
dry-run path shares no code with the rendering pipeline (app.services.task).

Usage:
    python pilot_prepare.py prepare \\
        --topic "Bitcoin basics" \\
        --task-dir ./storage/pilot/task-001 \\
        --script ./storage/pilot/task-001/script.txt \\
        [--asset ./storage/pilot/task-001/clip.mp4 \\
         --asset-type video --license-name CC0 \\
         --license-evidence https://creativecommons.org/publicdomain/zero/1.0/ \\
         --asset-notes "recorded locally"] \\
        [--output-placeholder ./storage/pilot/task-001/final.mp4] \\
        [--claim "Bitcoin supply is capped at 21 million." \\
         --claim-source https://bitcoin.org/bitcoin.pdf]

Exit codes:
    0 — manifest prepared successfully
    1 — validation or policy failure (no partial manifest left behind)
    2 — argument parsing failure

Guarantees:
- Requires an active, valid BrainTrustCrypto pilot policy; fails closed when
  the policy is missing, malformed, or unsafe.
- Creates or uses only the designated task directory.
- Validates and confines every referenced path to the task directory.
- Hashes the local script and registered local assets via the Phase 1B.3A
  provenance service (streaming SHA-256).
- Writes the manifest through the Phase 1B.3A atomic writer.
- Defaults to NEEDS_HUMAN_REVIEW with the __NEEDS_HUMAN_REVIEW marker.
- Prints only safe local paths and a concise summary.
- Makes no network request and invokes no LLM, TTS, media provider, API,
  WebUI, Redis, version checker, telemetry, or publishing path.
"""

from __future__ import annotations

import argparse
import codecs
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

# URL scheme detection for remote-URL rejection. Anything with a scheme like
# http://, https://, ftp://, or a protocol-relative //host/path is remote.
_REMOTE_URL_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://|^//")


class PrepareError(ValueError):
    """Raised for any validation or policy failure during preparation."""


def _is_remote_url(value: str) -> bool:
    return bool(_REMOTE_URL_PATTERN.match(value.strip()))


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pilot_prepare",
        description=(
            "BrainTrustCrypto pilot dry-run: prepare a task directory and a "
            "draft provenance manifest. No providers, downloads, rendering, "
            "or publishing."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser(
        "prepare",
        help="prepare a dry-run task directory and draft provenance manifest",
    )
    prep.add_argument("--topic", required=True, help="task topic")
    prep.add_argument(
        "--task-dir",
        required=True,
        help="designated task directory (created if missing)",
    )
    prep.add_argument(
        "--script",
        required=True,
        help="local script path, inside the task directory",
    )
    prep.add_argument(
        "--asset",
        action="append",
        default=[],
        metavar="PATH",
        help="local asset path inside the task directory (repeatable)",
    )
    prep.add_argument(
        "--asset-type",
        default=None,
        help="asset type applied to every --asset (video/audio/image/text/subtitle/other)",
    )
    prep.add_argument(
        "--license-name",
        default=None,
        help="license name applied to every --asset (required with --asset)",
    )
    prep.add_argument(
        "--license-evidence",
        default=None,
        help="license evidence/reference applied to every --asset (required with --asset)",
    )
    prep.add_argument(
        "--asset-notes",
        default=None,
        help="optional notes applied to every --asset",
    )
    prep.add_argument(
        "--output-placeholder",
        default=None,
        metavar="PATH",
        help="local output placeholder path inside the task directory",
    )
    prep.add_argument(
        "--claim",
        action="append",
        default=[],
        metavar="TEXT",
        help="factual claim text (repeatable); stays UNVERIFIED",
    )
    prep.add_argument(
        "--claim-source",
        action="append",
        default=[],
        metavar="URL",
        help="source URL for the matching --claim (repeatable, same order)",
    )
    render = sub.add_parser(
        "render-local",
        help=(
            "prepare, render locally, and finalize a provenance-bound "
            "marked output in one offline run"
        ),
    )
    render.add_argument("--topic", required=True, help="task topic")
    render.add_argument(
        "--script",
        required=True,
        help="local script path",
    )
    render.add_argument(
        "--material",
        action="append",
        required=True,
        metavar="PATH",
        help="local material path (repeatable, ordered)",
    )
    render.add_argument(
        "--license-name",
        action="append",
        required=True,
        metavar="TEXT",
        help="license name for the matching --material (repeatable, same order)",
    )
    render.add_argument(
        "--license-evidence",
        action="append",
        required=True,
        metavar="TEXT",
        help="license evidence for the matching --material (repeatable, same order)",
    )
    render.add_argument(
        "--claim",
        action="append",
        default=[],
        metavar="TEXT",
        help="factual claim text (repeatable, optional)",
    )
    render.add_argument(
        "--claim-source",
        action="append",
        default=[],
        metavar="URL",
        help="source URL for the matching --claim (repeatable, same order)",
    )
    return parser


# ---------------------------------------------------------------------------
# Preparation logic
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RenderLocalMaterialRequest:
    path: str
    license_name: str
    license_evidence: str


@dataclass(frozen=True)
class RenderLocalRequest:
    topic: str
    script_path: str
    materials: tuple[RenderLocalMaterialRequest, ...]
    claims: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class RenderLocalLoadedInputs:
    """Resolved local inputs and loaded script for a validated request."""

    request: RenderLocalRequest
    script_path: str
    script_bytes: bytes
    script_text: str
    material_paths: tuple[str, ...]


@dataclass(frozen=True)
class RenderLocalStagedTask:
    """Task-local staged copies, hashes, and owned-path cleanup metadata."""

    loaded: RenderLocalLoadedInputs
    task_id: str
    task_dir: str
    script_path: str
    script_sha256: str
    script_text: str
    materials: tuple[tuple[str, str], ...]
    # ("dir" | "file", path) pairs in creation order. Only paths created by
    # the staging invocation are recorded, including owned parent dirs.
    created_paths: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class RenderLocalPreparedDraft:
    """Staged task plus its durable output-null draft manifest."""

    staged: RenderLocalStagedTask
    manifest_path: str
    manifest: dict


@dataclass(frozen=True)
class RenderLocalVerifiedRender:
    """Verified post-render evidence for a prepared draft."""

    draft: RenderLocalPreparedDraft
    script_json_path: str
    script_json: dict
    output_path: str
    output_sha256: str
    task_result: dict


@dataclass(frozen=True)
class RenderLocalFinalizedRender:
    """Finalized marked-output evidence for a verified local render."""

    verified: RenderLocalVerifiedRender
    marked_output_path: str
    marked_output_sha256: str
    manifest_path: str
    manifest: dict


def _require_pilot_policy():
    """Load the pilot policy, failing closed on any problem.

    Returns the validated PilotPolicy. Raises PrepareError when the profile
    is inactive or the policy is missing/malformed/unsafe.
    """
    from app.services.pilot_policy import PilotPolicyError, load_pilot_policy

    try:
        policy = load_pilot_policy()
    except PilotPolicyError as exc:
        raise PrepareError(f"pilot policy failure: {exc}") from exc
    if policy is None:
        raise PrepareError(
            "pilot policy failure: MPT_PILOT_PROFILE is not 'braintrustcrypto'"
        )
    return policy


def _validate_render_local_request(
    *,
    topic: str,
    script_path: str,
    material_paths: list[str] | tuple[str, ...],
    license_names: list[str] | tuple[str, ...],
    license_evidence: list[str] | tuple[str, ...],
    claims: list[str] | tuple[str, ...] | None = None,
    claim_sources: list[str] | tuple[str, ...] | None = None,
) -> RenderLocalRequest:
    """Pure in-memory validation of a render-local request.

    The pilot policy gate runs first; everything after it is string-only
    validation with no filesystem, hashing, UUID, or network access. Every
    PrepareError message is static and never echoes supplied values or paths.
    """
    _require_pilot_policy()

    clean_topic = topic.strip()
    if not clean_topic:
        raise PrepareError("render-local topic must be a non-empty string")

    clean_script = script_path.strip()
    if not clean_script:
        raise PrepareError("render-local script path must be a non-empty string")
    if _is_remote_url(clean_script):
        raise PrepareError(
            "render-local script path must be a local path, not a remote URL"
        )

    if not material_paths:
        raise PrepareError("render-local requires at least one material")
    if not (len(material_paths) == len(license_names) == len(license_evidence)):
        raise PrepareError(
            "render-local material path, license name, and license evidence "
            "counts must match"
        )

    materials = []
    for raw_path, raw_name, raw_evidence in zip(
        material_paths, license_names, license_evidence
    ):
        clean_path = raw_path.strip()
        clean_name = raw_name.strip()
        clean_evidence = raw_evidence.strip()
        if not clean_path:
            raise PrepareError(
                "render-local material path must be a non-empty string"
            )
        if not clean_name:
            raise PrepareError(
                "render-local material license name must be a non-empty string"
            )
        if not clean_evidence:
            raise PrepareError(
                "render-local material license evidence must be a non-empty string"
            )
        if _is_remote_url(clean_path):
            raise PrepareError(
                "render-local material path must be a local path, not a remote URL"
            )
        materials.append(
            RenderLocalMaterialRequest(
                path=clean_path,
                license_name=clean_name,
                license_evidence=clean_evidence,
            )
        )

    raw_claims = claims or ()
    raw_sources = claim_sources or ()
    if len(raw_claims) != len(raw_sources):
        raise PrepareError(
            "render-local claim and claim source counts must match"
        )
    claim_pairs = []
    for raw_claim, raw_source in zip(raw_claims, raw_sources):
        clean_claim = raw_claim.strip()
        clean_source = raw_source.strip()
        if not clean_claim:
            raise PrepareError("render-local claim must be a non-empty string")
        if not clean_source:
            raise PrepareError(
                "render-local claim source must be a non-empty string"
            )
        claim_pairs.append((clean_claim, clean_source))

    return RenderLocalRequest(
        topic=clean_topic,
        script_path=clean_script,
        materials=tuple(materials),
        claims=tuple(claim_pairs),
    )


def _load_render_local_inputs(
    request: RenderLocalRequest,
) -> RenderLocalLoadedInputs:
    """Resolve local inputs and load the script for a validated request.

    Performs no policy call; _validate_render_local_request owns policy-first
    enforcement and must run before this helper. Filesystem reads only: no
    writes, copies, hashing, UUID generation, directory creation, manifest
    work, or renderer calls. Every PrepareError message is static and never
    echoes supplied paths or content.
    """
    lexical_script = os.path.abspath(request.script_path.strip())
    script_path = os.path.realpath(lexical_script)
    if os.path.normcase(lexical_script) != os.path.normcase(script_path):
        raise PrepareError(
            "render-local script path contains a link or junction"
        )
    if not os.path.isfile(script_path):
        raise PrepareError(
            "render-local script path must be an existing regular file"
        )

    material_paths = []
    seen_basenames = set()
    for material in request.materials:
        lexical = os.path.abspath(material.path.strip())
        resolved = os.path.realpath(lexical)
        if os.path.normcase(lexical) != os.path.normcase(resolved):
            raise PrepareError(
                "render-local material path contains a link or junction"
            )
        if not os.path.isfile(resolved):
            raise PrepareError(
                "render-local material path must be an existing regular file"
            )
        basename = os.path.normcase(os.path.basename(resolved))
        if basename in seen_basenames:
            raise PrepareError(
                "render-local material basenames must be unique"
            )
        seen_basenames.add(basename)
        material_paths.append(resolved)

    with open(script_path, "rb") as handle:
        script_bytes = handle.read()
    try:
        script_text = script_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PrepareError(
            "render-local script must be valid UTF-8"
        ) from exc
    if script_bytes.startswith(codecs.BOM_UTF8):
        raise PrepareError(
            "render-local script must not start with a UTF-8 BOM"
        )
    if not script_text.strip():
        raise PrepareError(
            "render-local script must not be empty or whitespace-only"
        )

    return RenderLocalLoadedInputs(
        request=request,
        script_path=script_path,
        script_bytes=script_bytes,
        script_text=script_text,
        material_paths=tuple(material_paths),
    )


_STAGING_COPY_CHUNK_SIZE = 1024 * 1024  # 1 MiB, mirrors provenance streaming


def _atomic_write_stream(target: str, chunks) -> None:
    """Write chunks to target via a same-directory temp file + os.replace.

    Follows the provenance.write_manifest_atomic pattern: the temporary
    file lives in the target directory so os.replace is an atomic rename
    on the same filesystem, and the temp file is removed on any failure.
    """
    fd, tmp_path = tempfile.mkstemp(
        prefix=f".{os.path.basename(target)}.",
        suffix=".tmp",
        dir=os.path.dirname(target),
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            for chunk in chunks:
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, target)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _stage_render_local_task(
    loaded: RenderLocalLoadedInputs,
) -> RenderLocalStagedTask:
    """Stage validated local inputs into a fresh confined task directory.

    Creates storage/tasks/<task-id>/ plus a materials/ child, writes the
    exact validated script bytes to script.md, streams each validated
    material to materials/<basename>, and hashes only the task-local
    copies with the production streaming SHA-256 helper. External source
    paths are read for copying but never hashed or recorded. On any
    failure, removes only files and directories created by this
    invocation, in reverse order, using unlink/rmdir only (never
    recursive deletion). All PrepareError messages are static and never
    echo supplied paths or content; native failures are chained only as
    internal causes.
    """
    from app.services import provenance as prov
    from app.utils import utils

    task_id = utils.get_uuid()
    module_root = os.path.realpath(os.path.dirname(os.path.abspath(__file__)))
    storage_root = os.path.join(module_root, "storage", "tasks")

    created: list[tuple[str, str]] = []  # ("dir" | "file", path), in order
    try:
        if not os.path.isdir(storage_root):
            storage_parent = os.path.dirname(storage_root)
            parent_missing = not os.path.isdir(storage_parent)
            os.makedirs(storage_root)
            if parent_missing:
                created.append(("dir", storage_parent))
            created.append(("dir", storage_root))

        task_dir = prov.resolve_task_path(storage_root, task_id,
                                          must_exist=False)
        try:
            os.mkdir(task_dir)
        except FileExistsError as exc:
            raise PrepareError(
                "render-local staging task directory already exists"
            ) from exc
        created.append(("dir", task_dir))
        materials_dir = os.path.join(task_dir, "materials")
        os.mkdir(materials_dir)
        created.append(("dir", materials_dir))

        script_target = os.path.join(task_dir, "script.md")
        _atomic_write_stream(script_target, (loaded.script_bytes,))
        created.append(("file", script_target))
        script_sha256 = prov.sha256_file_streamed(script_target)

        staged_materials = []
        for source in loaded.material_paths:
            target = os.path.join(materials_dir, os.path.basename(source))
            with open(source, "rb") as handle:
                _atomic_write_stream(
                    target,
                    iter(lambda: handle.read(_STAGING_COPY_CHUNK_SIZE), b""),
                )
            created.append(("file", target))
            staged_materials.append((target, prov.sha256_file_streamed(target)))

        return RenderLocalStagedTask(
            loaded=loaded,
            task_id=task_id,
            task_dir=task_dir,
            script_path=script_target,
            script_sha256=script_sha256,
            script_text=loaded.script_text,
            materials=tuple(staged_materials),
            created_paths=tuple(created),
        )
    except Exception as exc:
        _rollback_created_paths(created)
        if isinstance(exc, PrepareError):
            raise
        raise PrepareError("render-local staging failed") from exc


def _rollback_created_paths(created) -> None:
    """Remove recorded created paths in reverse order, best effort.

    Uses unlink/rmdir only (never recursive deletion) and tolerates
    already-absent owned paths. Paths not recorded by the owning
    invocation are never touched, so pre-existing parents and external
    inputs are always preserved.
    """
    for kind, path in reversed(list(created)):
        try:
            if kind == "file":
                os.unlink(path)
            else:
                os.rmdir(path)
        except OSError:
            pass


def _rollback_staged_task(staged: RenderLocalStagedTask) -> None:
    """Remove only the paths recorded as created by this staged task."""
    _rollback_created_paths(staged.created_paths)


def _prepare_render_local_draft(
    staged: RenderLocalStagedTask,
) -> RenderLocalPreparedDraft:
    """Build and durably write the output-null draft manifest.

    Reuses the Phase 1B.3A provenance builders end to end: task metadata
    defaults to NEEDS_HUMAN_REVIEW, the script section comes from the
    task-local script.md, one local video asset is built per staged
    task-local material with its original license pairing and ordering,
    claims stay UNVERIFIED with deterministic claim IDs, and output is
    None. The manifest is written last via the atomic writer, then read
    back and re-validated before returning. On any build, validation,
    write, or durable-read failure the staged task is rolled back; only
    a static sanitized PrepareError surfaces, with native details
    chained solely as internal causes. Once the durable valid manifest
    exists and is verified, the complete draft is preserved.
    """
    from app.services import provenance as prov

    task_dir = staged.task_dir
    manifest_target = os.path.join(task_dir, "provenance_manifest.json")
    try:
        task_section = prov.build_task_section(
            task_id=staged.task_id,
            topic=staged.loaded.request.topic,
            pilot_profile="braintrustcrypto",
        )
        script_section = prov.build_script_section(
            task_dir,
            local_path="script.md",
            generation_source="local",
        )
        if script_section["sha256"] != staged.script_sha256:
            raise PrepareError("render-local staged script hash mismatch")

        assets = []
        request_materials = staged.loaded.request.materials
        for index, (staged_path, staged_hash) in enumerate(staged.materials):
            asset = prov.build_asset(
                task_dir,
                asset_type="video",
                source_type="local",
                local_path=os.path.relpath(staged_path, task_dir),
                license_name=request_materials[index].license_name,
                license_evidence=request_materials[index].license_evidence,
            )
            if asset["sha256"] != staged_hash:
                raise PrepareError(
                    "render-local staged material hash mismatch"
                )
            assets.append(asset)

        claims = []
        for index, (claim_text, source) in enumerate(
            staged.loaded.request.claims
        ):
            claims.append(
                prov.build_claim(
                    claim_text=claim_text,
                    source_url=source,
                    status="UNVERIFIED",
                    retrieval_date=prov.utc_now_iso(),
                    claim_id=prov.generate_claim_id(
                        task_id=staged.task_id,
                        ordinal=index,
                        claim_text=claim_text,
                        source_url=source,
                    ),
                )
            )

        manifest = prov.build_manifest(
            task=task_section,
            script=script_section,
            assets=assets,
            factual_claims=claims,
            output=None,
        )
        manifest_path = prov.write_manifest_atomic(task_dir, manifest)
        with open(manifest_path, "r", encoding="utf-8") as handle:
            durable = json.load(handle)
        prov.validate_manifest(durable)
        return RenderLocalPreparedDraft(
            staged=staged,
            manifest_path=manifest_path,
            manifest=durable,
        )
    except Exception as exc:
        try:
            os.unlink(manifest_target)
        except OSError:
            pass
        _rollback_staged_task(staged)
        if isinstance(exc, PrepareError):
            raise
        raise PrepareError("render-local draft preparation failed") from exc


def _build_render_local_video_params(
    draft: RenderLocalPreparedDraft,
) -> "VideoParams":
    """Fixed render parameters for a prepared render-local draft.

    Purely in-memory: binds the validated topic, the exact staged script
    text, and the task-local staged material paths (original order,
    provider local) into the established VideoParams shape with the fixed
    render-local constants; unrelated fields keep their existing
    defaults. No policy call, filesystem access, mutation, parser
    wiring, task.start, or rendering.
    """
    from app.models.schema import (
        MaterialInfo,
        VideoAspect,
        VideoConcatMode,
        VideoParams,
    )
    from app.services import voice

    staged = draft.staged
    task_dir = staged.task_dir
    return VideoParams(
        video_subject=staged.loaded.request.topic,
        video_script=staged.script_text,
        video_source="local",
        video_materials=[
            MaterialInfo(
                provider="local",
                url=os.path.relpath(staged_path, task_dir),
            )
            for staged_path, _staged_hash in staged.materials
        ],
        video_count=1,
        video_aspect=VideoAspect.landscape.value,
        video_concat_mode=VideoConcatMode.sequential.value,
        video_clip_duration=5,
        voice_name=voice.NO_VOICE_NAME,
        subtitle_enabled=False,
        bgm_type="none",
    )


def _verify_render_local_render(
    draft: RenderLocalPreparedDraft,
    task_result: dict,
) -> RenderLocalVerifiedRender:
    """Verify post-render evidence for a prepared draft, strictly read-only.

    The task result must satisfy the successful completion contract: a
    non-empty mapping with state TASK_STATE_COMPLETE and progress 100,
    so a failed task that happened to leave final-1.mp4 behind never
    qualifies; task ID and output references, where present, must agree
    with the prepared draft. script.json is resolved inside the
    confined prepared task directory and must be a regular, non-linked
    JSON object whose script and params match the prepared evidence
    exactly. Exactly one unmarked final-1.mp4 is required and hashed
    with the production streamed SHA-256 helper. Performs no writes,
    copies, renames, manifest updates, or cleanup. Every PrepareError
    message is static and never exposes script content, paths, JSON or
    parser details, or native errors.
    """
    from app.models import const
    from app.models.schema import VideoAspect, VideoConcatMode
    from app.services import provenance as prov
    from app.services import voice

    staged = draft.staged
    task_dir = staged.task_dir

    # 1. task.start successful completion contract.
    if not isinstance(task_result, dict) or not task_result:
        raise PrepareError(
            "render-local task result must be a non-empty mapping"
        )
    if task_result.get("state") != const.TASK_STATE_COMPLETE:
        raise PrepareError("render-local task result state is not complete")
    if task_result.get("progress") != 100:
        raise PrepareError("render-local task result progress is not complete")
    if "task_id" in task_result and task_result["task_id"] != staged.task_id:
        raise PrepareError(
            "render-local task result task ID disagrees with the prepared draft"
        )

    # 2. script.json — confined, regular, non-linked, JSON object.
    lexical_manifest = os.path.abspath(os.path.join(task_dir, "script.json"))
    script_json_path = os.path.realpath(lexical_manifest)
    if os.path.normcase(lexical_manifest) != os.path.normcase(script_json_path):
        raise PrepareError(
            "render-local script manifest contains a link or junction"
        )
    if not os.path.isfile(script_json_path):
        raise PrepareError(
            "render-local script manifest must be an existing regular file"
        )
    try:
        with open(script_json_path, "r", encoding="utf-8") as handle:
            script_json = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PrepareError(
            "render-local script manifest is not valid JSON"
        ) from exc
    if not isinstance(script_json, dict):
        raise PrepareError("render-local script manifest must be a JSON object")
    script_field = script_json.get("script")
    params = script_json.get("params")
    if not isinstance(script_field, str) or not isinstance(params, dict):
        raise PrepareError("render-local script manifest has an unexpected shape")

    # 3. Exact script and VideoParams evidence fields.
    if script_field != staged.script_text:
        raise PrepareError(
            "render-local script manifest script disagrees with the prepared script"
        )
    if params.get("video_script") != staged.script_text:
        raise PrepareError(
            "render-local params video_script disagrees with the prepared script"
        )
    if params.get("video_source") != "local":
        raise PrepareError("render-local params video_source must be local")
    if params.get("video_count") != 1:
        raise PrepareError("render-local params video_count must be 1")
    if params.get("video_aspect") != VideoAspect.landscape.value:
        raise PrepareError("render-local params video_aspect must be 16:9")
    if params.get("video_concat_mode") != VideoConcatMode.sequential.value:
        raise PrepareError(
            "render-local params video_concat_mode must be sequential"
        )
    if params.get("video_clip_duration") != 5:
        raise PrepareError("render-local params video_clip_duration must be 5")
    if params.get("voice_name") != voice.NO_VOICE_NAME:
        raise PrepareError("render-local params voice_name must be no-voice")
    if params.get("subtitle_enabled") is not False:
        raise PrepareError(
            "render-local params subtitle_enabled must be false"
        )
    if params.get("bgm_type") != "none":
        raise PrepareError("render-local params bgm_type must be none")

    # 4. video_materials — ordered local copies of the staged evidence.
    materials_param = params.get("video_materials")
    if not isinstance(materials_param, list) or len(materials_param) != len(
        staged.materials
    ):
        raise PrepareError(
            "render-local params video_materials must match the staged materials"
        )
    for index, entry in enumerate(materials_param):
        if not isinstance(entry, dict):
            raise PrepareError(
                "render-local params video_materials must match the staged "
                "materials"
            )
        if entry.get("provider") != "local":
            raise PrepareError("render-local material provider must be local")
        url = entry.get("url")
        if not isinstance(url, str) or not url.strip() or _is_remote_url(url):
            raise PrepareError("render-local material path must be a local path")
        candidate = url.strip()
        if not os.path.isabs(candidate):
            candidate = os.path.join(task_dir, candidate)
        staged_path = staged.materials[index][0]
        if os.path.normcase(os.path.realpath(candidate)) != os.path.normcase(
            staged_path
        ):
            raise PrepareError(
                "render-local material path disagrees with the staged copy"
            )

    # 5. Exactly one regular, non-linked, unmarked final-1.mp4 output.
    try:
        entries = os.listdir(task_dir)
    except OSError as exc:
        raise PrepareError(
            "render-local task directory is not readable"
        ) from exc
    finals = [
        name for name in entries if re.fullmatch(r"final-\d+\.mp4", name)
    ]
    if "final-1.mp4" not in finals:
        raise PrepareError("render-local output final-1.mp4 is missing")
    if len(finals) != 1:
        raise PrepareError("render-local unexpected extra final video output")
    if any(prov.NEEDS_HUMAN_REVIEW_MARKER in name for name in entries):
        raise PrepareError(
            "render-local marked output must not exist before verification"
        )
    lexical_output = os.path.abspath(os.path.join(task_dir, "final-1.mp4"))
    output_path = os.path.realpath(lexical_output)
    if os.path.normcase(lexical_output) != os.path.normcase(output_path):
        raise PrepareError("render-local output contains a link or junction")
    if not os.path.isfile(output_path):
        raise PrepareError(
            "render-local output final-1.mp4 must be an existing regular file"
        )

    # Output references in the task result, where present, must agree.
    if "videos" in task_result:
        videos = task_result["videos"]
        if not isinstance(videos, (list, tuple)) or len(videos) != 1:
            raise PrepareError(
                "render-local task result outputs disagree with the prepared "
                "draft"
            )
        video_ref = videos[0]
        if not isinstance(video_ref, str) or _is_remote_url(video_ref):
            raise PrepareError(
                "render-local task result outputs disagree with the prepared "
                "draft"
            )
        if not os.path.isabs(video_ref):
            video_ref = os.path.join(task_dir, video_ref)
        if os.path.normcase(os.path.realpath(video_ref)) != os.path.normcase(
            output_path
        ):
            raise PrepareError(
                "render-local task result outputs disagree with the prepared "
                "draft"
            )

    # 6. Hash the verified renderer output with the production helper.
    try:
        output_sha256 = prov.sha256_file_streamed(output_path)
    except (prov.ProvenanceError, OSError) as exc:
        raise PrepareError(
            "render-local output must be readable for hashing"
        ) from exc

    return RenderLocalVerifiedRender(
        draft=draft,
        script_json_path=script_json_path,
        script_json=script_json,
        output_path=output_path,
        output_sha256=output_sha256,
        task_result=dict(task_result),
    )


def _restore_draft_manifest(manifest_path, original_bytes, marked_path,
                            cause):
    """Best-effort restore of the exact original manifest bytes.

    Atomically rewrites the original draft manifest, removes the marked
    copy, and rereads the manifest to verify restoration where possible.
    Always raises a static PrepareError chaining the given cause.
    """
    try:
        _atomic_write_stream(manifest_path, (original_bytes,))
    except OSError:
        pass
    try:
        os.unlink(marked_path)
    except OSError:
        pass
    try:
        with open(manifest_path, "rb") as handle:
            restored_ok = handle.read() == original_bytes
    except OSError:
        restored_ok = False
    if restored_ok:
        raise PrepareError("render-local finalization failed") from cause
    raise PrepareError(
        "render-local finalization failed and the draft manifest could "
        "not be restored"
    ) from cause


def _finalize_render_local_marked_output(
    verified: RenderLocalVerifiedRender,
) -> RenderLocalFinalizedRender:
    """Finalize a verified render into marked-output form, atomically.

    Before mutating anything, durably rereads provenance_manifest.json,
    revalidates it through production validation, requires it to equal
    the prepared draft evidence with output still None, reverifies the
    current script and task-local material hashes against it, and
    requires the marked target derived through
    provenance.marked_filename("final-1.mp4") to be absent.

    Finalization stream-copies final-1.mp4 to the marked target via
    same-directory temp + fsync + os.replace, requires the original and
    marked copy hashes to equal the verified output hash, builds the
    output section through the production provenance builder, rebuilds
    the complete manifest through production builders with every
    prepared section (schema/task identity, NEEDS_HUMAN_REVIEW, script,
    ordered assets/licenses, claims, created timestamps) preserved
    verbatim, validates it, and atomically replaces
    provenance_manifest.json last, then durably rereads and revalidates
    the final manifest before returning.

    The exact original manifest bytes are captured before mutation. Any
    failure before replacement removes only the marked temp/copy; the
    original draft manifest and renderer evidence stay unchanged. If
    replacement succeeds but durable final verification fails, the
    original manifest bytes are atomically restored and the marked copy
    removed, with restoration verified where possible. final-1.mp4,
    script.json, script.md, materials, and external inputs are never
    altered or deleted; deletion is unlink-only, never recursive. All
    PrepareError surfaces are static, with native details chained only
    as internal causes. A crash may leave either the valid draft or a
    fully valid finalized manifest, never a half-written one.
    """
    from app.services import provenance as prov

    draft = verified.draft
    staged = draft.staged
    task_dir = staged.task_dir
    manifest_path = draft.manifest_path

    # 1. Durably reread the prepared manifest; capture exact bytes.
    try:
        with open(manifest_path, "rb") as handle:
            original_bytes = handle.read()
    except OSError as exc:
        raise PrepareError(
            "render-local durable manifest is unreadable"
        ) from exc
    try:
        durable = json.loads(original_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PrepareError(
            "render-local durable manifest is not valid JSON"
        ) from exc

    # 2. Production validation of the durable manifest.
    try:
        prov.validate_manifest(durable)
    except prov.ProvenanceError as exc:
        raise PrepareError(
            "render-local durable manifest failed validation"
        ) from exc

    # 3. Must equal the prepared draft evidence, still output-null.
    if durable != draft.manifest:
        raise PrepareError(
            "render-local durable manifest disagrees with the prepared "
            "draft"
        )
    if durable.get("output") is not None:
        raise PrepareError(
            "render-local durable manifest already records an output"
        )

    # 4. Reverify current script and task-local material hashes.
    try:
        current_script_hash = prov.sha256_file_streamed(staged.script_path)
    except (prov.ProvenanceError, OSError) as exc:
        raise PrepareError(
            "render-local staged script must be readable for hashing"
        ) from exc
    if current_script_hash != durable["script"]["sha256"]:
        raise PrepareError(
            "render-local staged script hash changed since preparation"
        )
    for index, (staged_path, _staged_hash) in enumerate(staged.materials):
        try:
            current_hash = prov.sha256_file_streamed(staged_path)
        except (prov.ProvenanceError, OSError) as exc:
            raise PrepareError(
                "render-local staged material must be readable for "
                "hashing"
            ) from exc
        if current_hash != durable["assets"][index]["sha256"]:
            raise PrepareError(
                "render-local staged material hash changed since "
                "preparation"
            )

    # 5. The marked target must not already exist.
    marked_name = prov.marked_filename("final-1.mp4")
    marked_path = os.path.join(task_dir, marked_name)
    if os.path.lexists(marked_path):
        raise PrepareError("render-local marked output already exists")

    # 6-9. Copy, hash-check, and rebuild before the atomic replacement.
    marked_created = False
    try:
        with open(verified.output_path, "rb") as handle:
            _atomic_write_stream(
                marked_path,
                iter(lambda: handle.read(_STAGING_COPY_CHUNK_SIZE), b""),
            )
        marked_created = True

        original_hash = prov.sha256_file_streamed(verified.output_path)
        if original_hash != verified.output_sha256:
            raise PrepareError(
                "render-local verified output hash changed since "
                "verification"
            )
        marked_hash = prov.sha256_file_streamed(marked_path)
        if marked_hash != verified.output_sha256:
            raise PrepareError(
                "render-local marked output hash mismatch"
            )

        output_section = prov.build_output_section(
            task_dir,
            local_path=marked_name,
            compute_hash=True,
        )
        if output_section["sha256"] != verified.output_sha256:
            raise PrepareError(
                "render-local marked output hash mismatch"
            )

        rebuilt = prov.build_manifest(
            task=durable["task"],
            script=durable["script"],
            assets=durable["assets"],
            factual_claims=durable["factual_claims"],
            ai_generations=durable["ai_generations"],
            output=output_section,
        )
        prov.validate_manifest(rebuilt)
    except Exception as exc:
        if marked_created:
            try:
                os.unlink(marked_path)
            except OSError:
                pass
        if isinstance(exc, PrepareError):
            raise
        raise PrepareError("render-local finalization failed") from exc

    # 10. Atomically replace provenance_manifest.json last.
    try:
        final_path = prov.write_manifest_atomic(task_dir, rebuilt)
    except Exception as exc:
        try:
            os.unlink(marked_path)
        except OSError:
            pass
        raise PrepareError("render-local finalization failed") from exc

    # 11. Durably reread and revalidate the final manifest; on failure,
    # restore the exact original bytes and remove the marked copy.
    try:
        with open(final_path, "rb") as handle:
            final_bytes = handle.read()
        final_manifest = json.loads(final_bytes)
        prov.validate_manifest(final_manifest)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError,
            prov.ProvenanceError) as exc:
        _restore_draft_manifest(final_path, original_bytes, marked_path,
                                exc)
    if final_manifest != rebuilt:
        _restore_draft_manifest(final_path, original_bytes, marked_path,
                                None)

    # 12. Immutable finalized information.
    return RenderLocalFinalizedRender(
        verified=verified,
        marked_output_path=marked_path,
        marked_output_sha256=marked_hash,
        manifest_path=final_path,
        manifest=final_manifest,
    )


def _run_render_local_task(
    topic: str,
    script_path: str,
    material_paths: list[str] | tuple[str, ...],
    license_names: list[str] | tuple[str, ...],
    license_evidence: list[str] | tuple[str, ...],
    claims: list[str] | tuple[str, ...] | None = None,
    claim_sources: list[str] | tuple[str, ...] | None = None,
) -> RenderLocalFinalizedRender:
    """Run the render-local pipeline end to end, internally.

    Validates the raw request (the pilot policy gate runs first),
    loads, stages, and prepares the durable draft, then builds the
    fixed render parameters. The renderer is imported lazily only
    after the durable draft exists, and task.start runs with the exact
    staged task ID and the exact built params at stop_at="video". Any
    escaped renderer exception surfaces as a static sanitized
    PrepareError with the native exception chained only as the cause;
    a failed or incomplete returned result flows through the existing
    verifier unchanged. Once the durable draft exists it is never
    rolled back for renderer, verification, or finalization failure.
    No validation or schema logic is duplicated here.
    """
    request = _validate_render_local_request(
        topic=topic,
        script_path=script_path,
        material_paths=material_paths,
        license_names=license_names,
        license_evidence=license_evidence,
        claims=claims,
        claim_sources=claim_sources,
    )
    loaded = _load_render_local_inputs(request)
    staged = _stage_render_local_task(loaded)
    draft = _prepare_render_local_draft(staged)
    params = _build_render_local_video_params(draft)

    from app.services import task

    try:
        task_result = task.start(
            task_id=staged.task_id,
            params=params,
            stop_at="video",
        )
    except Exception as exc:
        raise PrepareError("render-local render failed") from exc

    verified = _verify_render_local_render(draft, task_result)
    return _finalize_render_local_marked_output(verified)


def _resolve_and_confine(task_dir: str, raw_path: str, *, must_exist: bool,
                         description: str) -> str:
    """Resolve raw_path inside task_dir with provenance confinement rules."""
    from app.services import provenance as prov

    if _is_remote_url(raw_path):
        raise PrepareError(
            f"{description} must be a local path, not a remote URL: {raw_path!r}"
        )
    try:
        return prov.resolve_task_path(task_dir, raw_path, must_exist=must_exist)
    except prov.ProvenanceError as exc:
        raise PrepareError(f"{description}: {exc}") from exc


def prepare(args: argparse.Namespace) -> int:
    from app.services import provenance as prov

    # 1. Policy gate — fail closed before touching the filesystem.
    _require_pilot_policy()

    topic = args.topic.strip()
    if not topic:
        raise PrepareError("topic must be a non-empty string")

    # 2. Create or use only the designated task directory.
    task_dir = os.path.realpath(os.path.expanduser(args.task_dir.strip()))
    os.makedirs(task_dir, exist_ok=True)
    if not os.path.isdir(task_dir):
        raise PrepareError(f"task directory is not a directory: {args.task_dir!r}")

    # 3. Script — required, must exist inside the task directory.
    script_path = _resolve_and_confine(
        task_dir, args.script, must_exist=True, description="script"
    )
    if not os.path.isfile(script_path):
        raise PrepareError(f"script is not a file: {args.script!r}")

    # 4. Assets — optional, all confined and hashed.
    if args.asset and not (args.license_name and args.license_evidence):
        raise PrepareError(
            "--license-name and --license-evidence are required with --asset"
        )
    asset_type = args.asset_type or "other"
    assets = []
    for raw_asset in args.asset:
        resolved = _resolve_and_confine(
            task_dir, raw_asset, must_exist=True, description="asset"
        )
        if not os.path.isfile(resolved):
            raise PrepareError(f"asset is not a file: {raw_asset!r}")
        try:
            assets.append(
                prov.build_asset(
                    task_dir,
                    asset_type=asset_type,
                    source_type="local",
                    local_path=os.path.relpath(resolved, task_dir),
                    license_name=args.license_name,
                    license_evidence=args.license_evidence,
                    notes=args.asset_notes,
                )
            )
        except prov.ProvenanceError as exc:
            raise PrepareError(f"asset {raw_asset!r}: {exc}") from exc

    # 5. Factual claims — always UNVERIFIED in a dry run.
    if len(args.claim_source) > len(args.claim):
        raise PrepareError("--claim-source without a matching --claim")
    claims = []
    for index, claim_text in enumerate(args.claim):
        source = (
            args.claim_source[index] if index < len(args.claim_source) else None
        )
        if not source:
            raise PrepareError(f"--claim {index + 1} requires a --claim-source")
        try:
            # Generate deterministic claim_id for schema 1.2.0.
            claim_id = prov.generate_claim_id(
                task_id=os.path.basename(task_dir),
                ordinal=index,
                claim_text=claim_text,
                source_url=source,
            )
            claims.append(
                prov.build_claim(
                    claim_text=claim_text,
                    source_url=source,
                    status="UNVERIFIED",
                    retrieval_date=prov.utc_now_iso(),
                    claim_id=claim_id,
                )
            )
        except prov.ProvenanceError as exc:
            raise PrepareError(f"claim {index + 1}: {exc}") from exc

    # 6. Output placeholder — optional; no hash when the file does not exist.
    output_section = None
    if args.output_placeholder:
        resolved_output = _resolve_and_confine(
            task_dir,
            args.output_placeholder,
            must_exist=False,
            description="output placeholder",
        )
        exists = os.path.isfile(resolved_output)
        try:
            output_section = prov.build_output_section(
                task_dir,
                local_path=os.path.relpath(resolved_output, task_dir),
                compute_hash=exists,
            )
        except prov.ProvenanceError as exc:
            raise PrepareError(f"output placeholder: {exc}") from exc

    # 7. Build the manifest through the Phase 1B.3A service.
    try:
        task_section = prov.build_task_section(
            task_id=os.path.basename(task_dir),
            topic=topic,
            pilot_profile="braintrustcrypto",
        )
        script_section = prov.build_script_section(
            task_dir,
            local_path=os.path.relpath(script_path, task_dir),
            generation_source="local",
        )
        manifest = prov.build_manifest(
            task=task_section,
            script=script_section,
            assets=assets,
            factual_claims=claims,
            output=output_section,
        )
    except prov.ProvenanceError as exc:
        raise PrepareError(f"manifest validation: {exc}") from exc

    # 8. Atomic write — temp file cleaned automatically on failure.
    try:
        manifest_path = prov.write_manifest_atomic(task_dir, manifest)
    except prov.ProvenanceError as exc:
        raise PrepareError(f"manifest write: {exc}") from exc

    # 9. Concise, safe summary — local paths only.
    print("BrainTrustCrypto pilot dry-run prepared")
    print(f"  task_dir:  {task_dir}")
    print(f"  manifest:  {manifest_path}")
    print(f"  script:    {script_path}")
    for asset in assets:
        print(f"  asset:     {os.path.join(task_dir, asset['local_path'])}")
    if output_section:
        print(f"  output:    {output_section['filename_marker']}")
    print(f"  claims:    {len(claims)} (all UNVERIFIED)")
    print(f"  status:    {manifest['task']['review_status']}")
    return EXIT_OK


def render_local(args) -> int:
    """Run the render-local pipeline once from CLI arguments.

    The validator owns all cardinality and content checks; ordered
    option lists pass through unchanged. On success, print only the
    task ID and the task-relative manifest and marked-output paths —
    never script content, licenses, claims, external paths, or native
    exception text.
    """
    finalized = _run_render_local_task(
        topic=args.topic,
        script_path=args.script,
        material_paths=args.material,
        license_names=args.license_name,
        license_evidence=args.license_evidence,
        claims=args.claim,
        claim_sources=args.claim_source,
    )
    task_dir = finalized.verified.draft.staged.task_dir
    print("BrainTrustCrypto pilot render-local finalized")
    print(f"  task_id:   {finalized.verified.draft.staged.task_id}")
    print(
        f"  manifest:  "
        f"{os.path.relpath(finalized.manifest_path, task_dir)}"
    )
    print(
        f"  output:    "
        f"{os.path.relpath(finalized.marked_output_path, task_dir)}"
    )
    return EXIT_OK


def run(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "prepare":
        try:
            return prepare(args)
        except PrepareError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_FAILURE
        except OSError as exc:
            print(f"error: filesystem failure: {exc}", file=sys.stderr)
            return EXIT_FAILURE
    if args.command == "render-local":
        try:
            return render_local(args)
        except PrepareError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_FAILURE
    parser.error(f"unknown command: {args.command}")
    return EXIT_USAGE  # unreachable; parser.error exits


if __name__ == "__main__":
    raise SystemExit(run())
