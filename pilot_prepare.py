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
    parser.error(f"unknown command: {args.command}")
    return EXIT_USAGE  # unreachable; parser.error exits


if __name__ == "__main__":
    raise SystemExit(run())
