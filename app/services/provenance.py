"""
Phase 1B.3A — Offline provenance and human-review manifest foundation.

Standalone provenance-manifest service for BrainTrustCrypto pilot tasks.

This module is intentionally NOT integrated with rendering, providers, CLI,
TTS, LLM, or publishing. It only builds, validates, and writes provenance
manifest JSON documents confined to a designated task directory.

Security properties:
- Standard library only.
- SHA-256 is streamed in fixed-size chunks; large media is never fully
  loaded into memory.
- All local paths referenced by a manifest must resolve inside the task
  directory. Traversal and unsafe absolute paths are rejected.
- Manifests are written via a same-directory temporary file followed by an
  atomic rename. Temporary files are removed on failure.
- JSON output is deterministic: stable field ordering, sorted keys within
  the canonical field layout, fixed separators, UTF-8, trailing newline.
- Secrets are never recorded: API keys, authorization headers, cookies,
  tokens, and full sensitive prompts are rejected or redacted. Only prompt
  hashes are stored.
- Every new manifest defaults to review_status=NEEDS_HUMAN_REVIEW and the
  output filename marker __NEEDS_HUMAN_REVIEW.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone

SCHEMA_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Enums (closed sets)
# ---------------------------------------------------------------------------

REVIEW_STATUSES = frozenset({"NEEDS_HUMAN_REVIEW", "APPROVED", "REJECTED"})
ASSET_TYPES = frozenset({"video", "audio", "image", "text", "subtitle", "other"})
SOURCE_TYPES = frozenset({"local", "provider", "ai_generated"})
CLAIM_STATUSES = frozenset({"UNVERIFIED", "VERIFIED", "RETRACTED"})
OUTPUT_TYPES = frozenset({"text", "image", "audio", "video", "script", "other"})

DEFAULT_REVIEW_STATUS = "NEEDS_HUMAN_REVIEW"
NEEDS_HUMAN_REVIEW_MARKER = "__NEEDS_HUMAN_REVIEW"

# Allowed approval-state transitions. Anything not listed is rejected.
# A manifest starts at NEEDS_HUMAN_REVIEW and may only move to a terminal
# human decision. Terminal states do not transition further.
_ALLOWED_TRANSITIONS = {
    "NEEDS_HUMAN_REVIEW": {"APPROVED", "REJECTED"},
    "APPROVED": set(),
    "REJECTED": set(),
}

_CHUNK_SIZE = 1024 * 1024  # 1 MiB streaming chunks for SHA-256

# ---------------------------------------------------------------------------
# Secret detection — never record credentials or full sensitive prompts
# ---------------------------------------------------------------------------

_SECRET_FIELD_NAMES = frozenset(
    {
        "api_key",
        "apikey",
        "api_secret",
        "secret",
        "secret_key",
        "access_token",
        "refresh_token",
        "token",
        "auth_token",
        "authorization",
        "auth_header",
        "cookie",
        "cookies",
        "set_cookie",
        "password",
        "passwd",
        "private_key",
        "client_secret",
        "bearer",
        "session_id",
        "session",
        "prompt",  # full prompts are sensitive; only prompt_hash is stored
        "full_prompt",
        "system_prompt",
    }
)

# Matches common credential shapes inside arbitrary string values.
_SECRET_VALUE_PATTERNS = [
    re.compile(r"(?i)bearer\s+[a-z0-9._\-]+"),
    re.compile(r"(?i)(api[_-]?key|token|secret|password|authorization|cookie)\s*[:=]\s*\S+"),
    re.compile(r"sk-[a-zA-Z0-9]{16,}"),  # OpenAI-style keys
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]


class ProvenanceError(ValueError):
    """Raised for any manifest validation, path, or secret-handling failure."""


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------


def sha256_file_streamed(path: str) -> str:
    """Compute SHA-256 of a file by streaming fixed-size chunks.

    Never loads the whole file into memory. Raises ProvenanceError if the
    path is not a readable regular file.
    """
    if not os.path.isfile(path):
        raise ProvenanceError(f"cannot hash missing file: {path!r}")
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    """Compute SHA-256 of a UTF-8 string (used for prompt hashes)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_prompt(prompt: str) -> str:
    """Return the only allowable representation of a prompt: its hash.

    The full prompt text is never stored in a manifest.
    """
    if not isinstance(prompt, str) or not prompt:
        raise ProvenanceError("prompt must be a non-empty string to hash")
    return sha256_text(prompt)


# ---------------------------------------------------------------------------
# Secret redaction / rejection
# ---------------------------------------------------------------------------


def _assert_no_secret_field(name: str) -> None:
    # Split on non-alphanumeric boundaries so that legitimate parameter
    # names like "max_tokens" or "prompt_hash" are not falsely flagged,
    # while "api_key", "access-token", "fullPrompt", etc. still match.
    parts = set(re.split(r"[^a-z0-9]+", name.lower()))
    normalized = re.sub(r"[^a-z0-9]", "", name.lower())
    for secret_name in _SECRET_FIELD_NAMES:
        secret_norm = re.sub(r"[^a-z0-9]", "", secret_name)
        if secret_norm in parts or secret_norm == normalized:
            raise ProvenanceError(
                f"field name {name!r} is not allowed in a manifest: "
                "secrets and full prompts are never recorded"
            )
    # CamelCase joins ("fullPrompt" -> "fullprompt") and exact compounds.
    if normalized in {"fullprompt", "systemprompt", "fullsensitiveprompt"}:
        raise ProvenanceError(
            f"field name {name!r} is not allowed in a manifest: "
            "secrets and full prompts are never recorded"
        )


def _assert_no_secret_value(value: str) -> None:
    for pattern in _SECRET_VALUE_PATTERNS:
        if pattern.search(value):
            raise ProvenanceError(
                "value appears to contain a credential or secret; "
                "secrets are never recorded in a manifest"
            )


def sanitize_parameters(params: dict | None) -> dict:
    """Validate non-secret generation parameters.

    Only plain JSON scalar containers are allowed. Any key that looks like
    a credential/prompt field, or any string value that looks like a secret,
    causes rejection. Returns a new dict with deterministic key ordering.
    """
    if params is None:
        return {}
    if not isinstance(params, dict):
        raise ProvenanceError("parameters must be a mapping")

    clean: dict = {}

    def _walk(prefix: str, obj) -> None:
        if isinstance(obj, dict):
            for key in sorted(obj.keys(), key=str):
                if not isinstance(key, str):
                    raise ProvenanceError("parameter keys must be strings")
                _assert_no_secret_field(key)
                _walk(f"{prefix}{key}.", obj[key])
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                _walk(prefix, item)
        elif isinstance(obj, str):
            _assert_no_secret_value(obj)
        elif isinstance(obj, (int, float, bool)) or obj is None:
            pass
        else:
            raise ProvenanceError(
                f"parameter {prefix!r} has unsupported type {type(obj).__name__}"
            )

    _walk("", params)
    for key in sorted(params.keys(), key=str):
        clean[key] = params[key]
    return clean


# ---------------------------------------------------------------------------
# Path confinement
# ---------------------------------------------------------------------------


def resolve_task_path(task_dir: str, candidate: str, *, must_exist: bool = True) -> str:
    """Resolve candidate inside task_dir, rejecting traversal/unsafe paths.

    - Empty paths are rejected.
    - Absolute paths must already live inside the task directory.
    - Relative paths are joined to the task directory.
    - The fully resolved path must share the task directory as its common
      path; otherwise it is rejected (covers ``..``, symlinks, drive changes).
    """
    if not candidate or not isinstance(candidate, str):
        raise ProvenanceError("empty path is not allowed")

    base_real = os.path.realpath(task_dir)
    resolved = candidate
    if not os.path.isabs(resolved):
        resolved = os.path.join(base_real, resolved)
    resolved = os.path.realpath(resolved)

    try:
        common = os.path.commonpath([base_real, resolved])
    except ValueError as exc:  # different drives on Windows
        raise ProvenanceError("path is outside the task directory") from exc
    if common != base_real:
        raise ProvenanceError("path is outside the task directory")

    if must_exist and not os.path.exists(resolved):
        raise ProvenanceError(f"path does not exist: {candidate!r}")
    return resolved


# ---------------------------------------------------------------------------
# Field validators
# ---------------------------------------------------------------------------


def _require_str(value, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProvenanceError(f"{field} must be a non-empty string")
    return value


def _require_enum(value, field: str, allowed: frozenset) -> str:
    if value not in allowed:
        raise ProvenanceError(
            f"{field} must be one of {sorted(allowed)}; got {value!r}"
        )
    return value


def _require_utc_timestamp(value, field: str) -> str:
    value = _require_str(value, field)
    # Accept ISO-8601 with explicit UTC offset/Z only.
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProvenanceError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ProvenanceError(f"{field} must include a UTC offset")
    return value


def utc_now_iso() -> str:
    """Current UTC time in deterministic ISO-8601 form (seconds precision)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_prompt_hash(value, field: str) -> str:
    value = _require_str(value, field)
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ProvenanceError(
            f"{field} must be a lowercase SHA-256 hex digest (prompt hash only)"
        )
    return value


# ---------------------------------------------------------------------------
# Section builders — each returns a dict with stable field ordering
# ---------------------------------------------------------------------------


def build_task_section(
    *,
    task_id: str,
    topic: str,
    pilot_profile: str,
    created_at: str | None = None,
    review_status: str = DEFAULT_REVIEW_STATUS,
) -> dict:
    created_at = created_at or utc_now_iso()
    _require_str(task_id, "task.task_id")
    _require_str(topic, "task.topic")
    _require_str(pilot_profile, "task.pilot_profile")
    _require_utc_timestamp(created_at, "task.created_at")
    _require_enum(review_status, "task.review_status", REVIEW_STATUSES)
    return {
        "schema_version": SCHEMA_VERSION,
        "task_id": task_id,
        "created_at": created_at,
        "topic": topic,
        "pilot_profile": pilot_profile,
        "review_status": review_status,
    }


def build_script_section(
    task_dir: str,
    *,
    local_path: str,
    generation_source: str,
    ai_provider: str | None = None,
    ai_model: str | None = None,
    prompt_hash: str | None = None,
) -> dict:
    resolved = resolve_task_path(task_dir, local_path)
    _require_str(generation_source, "script.generation_source")
    if prompt_hash is not None:
        _validate_prompt_hash(prompt_hash, "script.prompt_hash")
    return {
        "local_path": os.path.relpath(resolved, os.path.realpath(task_dir)),
        "sha256": sha256_file_streamed(resolved),
        "generation_source": generation_source,
        "ai_provider": ai_provider,
        "ai_model": ai_model,
        "prompt_hash": prompt_hash,
    }


def build_asset(
    task_dir: str,
    *,
    asset_type: str,
    source_type: str,
    local_path: str,
    license_name: str,
    license_evidence: str,
    source_url: str | None = None,
    provider: str | None = None,
    provider_asset_id: str | None = None,
    retrieval_date: str | None = None,
    notes: str | None = None,
) -> dict:
    """Build one asset entry enforcing local/provider/AI-generated rules.

    - local assets: source_url may be omitted, but license evidence is
      required (enforced for every asset type).
    - provider assets: source_url, retrieval_date, provider, and
      provider_asset_id are all required, plus license information.
    - ai_generated assets: provider (the AI provider) is required;
      source_url may be omitted.
    """
    _require_enum(asset_type, "asset.asset_type", ASSET_TYPES)
    _require_enum(source_type, "asset.source_type", SOURCE_TYPES)
    resolved = resolve_task_path(task_dir, local_path)
    _require_str(license_name, "asset.license_name")
    _require_str(license_evidence, "asset.license_evidence")

    if source_type == "provider":
        _require_str(source_url, "asset.source_url (provider assets)")
        _require_str(provider, "asset.provider (provider assets)")
        _require_str(provider_asset_id, "asset.provider_asset_id (provider assets)")
        _require_utc_timestamp(retrieval_date, "asset.retrieval_date (provider assets)")
    elif source_type == "ai_generated":
        _require_str(provider, "asset.provider (ai_generated assets)")
    # local: source_url optional; license evidence already required above.

    if source_url is not None:
        _assert_no_secret_value(source_url)
    if notes is not None:
        _assert_no_secret_value(notes)

    return {
        "asset_type": asset_type,
        "source_type": source_type,
        "source_url": source_url,
        "provider": provider,
        "provider_asset_id": provider_asset_id,
        "retrieval_date": retrieval_date,
        "local_path": os.path.relpath(resolved, os.path.realpath(task_dir)),
        "sha256": sha256_file_streamed(resolved),
        "license_name": license_name,
        "license_evidence": license_evidence,
        "notes": notes,
    }


def build_claim(
    *,
    claim_text: str,
    source_url: str,
    status: str = "UNVERIFIED",
    source_publication_date: str | None = None,
    retrieval_date: str | None = None,
    reviewer: str | None = None,
    review_date: str | None = None,
) -> dict:
    _require_str(claim_text, "claim.claim_text")
    _require_str(source_url, "claim.source_url")
    _assert_no_secret_value(source_url)
    _require_enum(status, "claim.status", CLAIM_STATUSES)
    if retrieval_date is not None:
        _require_utc_timestamp(retrieval_date, "claim.retrieval_date")

    if status in ("VERIFIED", "RETRACTED"):
        # A human decision is meaningless without accountability.
        _require_str(reviewer, f"claim.reviewer ({status} claims)")
        _require_utc_timestamp(review_date, f"claim.review_date ({status} claims)")

    return {
        "claim_text": claim_text,
        "source_url": source_url,
        "source_publication_date": source_publication_date,
        "retrieval_date": retrieval_date,
        "status": status,
        "reviewer": reviewer,
        "review_date": review_date,
    }


def build_ai_generation(
    *,
    provider: str,
    model: str,
    generation_timestamp: str,
    output_type: str,
    prompt_hash: str,
    parameters: dict | None = None,
) -> dict:
    _require_str(provider, "ai_generation.provider")
    _require_str(model, "ai_generation.model")
    _require_utc_timestamp(generation_timestamp, "ai_generation.generation_timestamp")
    _require_enum(output_type, "ai_generation.output_type", OUTPUT_TYPES)
    _validate_prompt_hash(prompt_hash, "ai_generation.prompt_hash")
    return {
        "provider": provider,
        "model": model,
        "generation_timestamp": generation_timestamp,
        "output_type": output_type,
        "prompt_hash": prompt_hash,
        "parameters": sanitize_parameters(parameters),
    }


def build_output_section(
    task_dir: str,
    *,
    local_path: str,
    review_status: str = DEFAULT_REVIEW_STATUS,
    compute_hash: bool = True,
) -> dict:
    _require_enum(review_status, "output.review_status", REVIEW_STATUSES)
    resolved = resolve_task_path(task_dir, local_path, must_exist=compute_hash)
    rel = os.path.relpath(resolved, os.path.realpath(task_dir))
    return {
        "local_path": rel,
        "sha256": sha256_file_streamed(resolved) if compute_hash else None,
        "review_status": review_status,
        "filename_marker": marked_filename(rel, review_status),
        "visible_watermark_required": False,
    }


# ---------------------------------------------------------------------------
# Filename marker
# ---------------------------------------------------------------------------


def marked_filename(filename: str, review_status: str = DEFAULT_REVIEW_STATUS) -> str:
    """Insert the __NEEDS_HUMAN_REVIEW marker before the extension.

    Files that still need human review must be visibly marked. Approved or
    rejected outputs drop the marker. No visible watermark is required —
    the marker lives in the filename only.
    """
    if review_status != DEFAULT_REVIEW_STATUS:
        return filename.replace(NEEDS_HUMAN_REVIEW_MARKER, "").replace("__.", ".")
    base, ext = os.path.splitext(filename)
    if base.endswith(NEEDS_HUMAN_REVIEW_MARKER):
        return filename
    return f"{base}{NEEDS_HUMAN_REVIEW_MARKER}{ext}"


# ---------------------------------------------------------------------------
# Manifest assembly, validation, atomic write
# ---------------------------------------------------------------------------

# Canonical top-level field ordering for deterministic output.
_MANIFEST_FIELD_ORDER = (
    "task",
    "script",
    "assets",
    "factual_claims",
    "ai_generations",
    "output",
)


def build_manifest(
    *,
    task: dict,
    script: dict | None = None,
    assets: list[dict] | None = None,
    factual_claims: list[dict] | None = None,
    ai_generations: list[dict] | None = None,
    output: dict | None = None,
) -> dict:
    if not isinstance(task, dict) or task.get("schema_version") != SCHEMA_VERSION:
        raise ProvenanceError("manifest requires a valid task section")
    manifest = {
        "task": task,
        "script": script,
        "assets": assets or [],
        "factual_claims": factual_claims or [],
        "ai_generations": ai_generations or [],
        "output": output,
    }
    validate_manifest(manifest)
    return manifest


def validate_manifest(manifest: dict) -> None:
    """Validate required fields and allowed enum values for a full manifest."""
    if not isinstance(manifest, dict):
        raise ProvenanceError("manifest must be a mapping")
    for field in _MANIFEST_FIELD_ORDER:
        if field not in manifest:
            raise ProvenanceError(f"manifest missing required section: {field}")

    task = manifest["task"]
    for field in ("schema_version", "task_id", "created_at", "topic",
                  "pilot_profile", "review_status"):
        if field not in task:
            raise ProvenanceError(f"task missing required field: {field}")
    _require_enum(task["review_status"], "task.review_status", REVIEW_STATUSES)

    for asset in manifest["assets"]:
        _require_enum(asset.get("asset_type"), "asset.asset_type", ASSET_TYPES)
        _require_enum(asset.get("source_type"), "asset.source_type", SOURCE_TYPES)
        _require_str(asset.get("license_name"), "asset.license_name")
        _require_str(asset.get("license_evidence"), "asset.license_evidence")
        if asset["source_type"] == "provider":
            for field in ("source_url", "provider", "provider_asset_id",
                          "retrieval_date"):
                if not asset.get(field):
                    raise ProvenanceError(
                        f"provider asset missing required field: {field}"
                    )

    for claim in manifest["factual_claims"]:
        _require_enum(claim.get("status"), "claim.status", CLAIM_STATUSES)
        if claim["status"] in ("VERIFIED", "RETRACTED"):
            if not claim.get("reviewer") or not claim.get("review_date"):
                raise ProvenanceError(
                    f"{claim['status']} claim requires reviewer and review_date"
                )


def transition_review_status(manifest: dict, new_status: str) -> dict:
    """Move task review_status to a new state, rejecting invalid transitions.

    Approvals/rejections must be complete: a terminal human decision on the
    task requires that no factual claim remains UNVERIFIED.
    """
    _require_enum(new_status, "review_status", REVIEW_STATUSES)
    current = manifest["task"]["review_status"]
    if new_status not in _ALLOWED_TRANSITIONS.get(current, set()):
        raise ProvenanceError(
            f"invalid review-status transition: {current} -> {new_status}"
        )
    if new_status == "APPROVED":
        unverified = [
            c for c in manifest.get("factual_claims", [])
            if c.get("status") == "UNVERIFIED"
        ]
        if unverified:
            raise ProvenanceError(
                "cannot approve: factual claims remain UNVERIFIED"
            )
    manifest["task"]["review_status"] = new_status
    if manifest.get("output"):
        manifest["output"]["review_status"] = new_status
        manifest["output"]["filename_marker"] = marked_filename(
            manifest["output"]["local_path"], new_status
        )
    return manifest


def manifest_to_json(manifest: dict) -> str:
    """Serialize deterministically: stable ordering, fixed separators."""
    ordered = {field: manifest[field] for field in _MANIFEST_FIELD_ORDER}
    # Top-level order comes from _MANIFEST_FIELD_ORDER; nested objects are
    # built with fixed insertion order by the section builders, so output
    # is deterministic without sort_keys (which would reorder top level).
    return json.dumps(
        ordered,
        ensure_ascii=False,
        indent=2,
        separators=(",", ": "),
    ) + "\n"


def write_manifest_atomic(task_dir: str, manifest: dict,
                          filename: str = "provenance_manifest.json") -> str:
    """Write manifest via same-directory temp file + atomic rename.

    The temporary file is created in the task directory itself so the final
    os.replace() is a true atomic rename on the same filesystem. On any
    failure the temporary file is removed.
    """
    validate_manifest(manifest)
    payload = manifest_to_json(manifest)
    base_real = os.path.realpath(task_dir)
    if not os.path.isdir(base_real):
        raise ProvenanceError(f"task directory does not exist: {task_dir!r}")
    target = os.path.join(base_real, filename)

    fd, tmp_path = tempfile.mkstemp(
        prefix=f".{filename}.", suffix=".tmp", dir=base_real
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, target)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return target
