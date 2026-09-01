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
import os
import re
import sys
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
