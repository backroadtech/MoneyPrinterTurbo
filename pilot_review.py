"""
Phase 1B.3C.2B.1 — Read-only human-review CLI.

Standalone, offline, READ-ONLY review-inspection entry point for
BrainTrustCrypto pilot tasks. Exposes exactly two commands:

    status  — concise, sanitized snapshot of a task's review state
    audit   — read-only integrity validation (PASS/FAIL + reason codes)

This tool NEVER mutates the task directory. It does not create, modify,
move, delete, recover, or rewrite any file. Both commands leave the task
directory byte-for-byte unchanged.

Mutating review operations (verify-claim, retract-claim, approve, reject,
revoke, supersede, recover-lock, tail-recovery) are NOT exposed here and
are deferred to Phase 1B.3C.2B.2.

NOTE on recovery primitives: discard_uncommitted_tail() and
recover_review_lock() are intentionally NOT wired to this CLI. Those
primitives mutate state and require a separate audit before any future CLI
exposure. Do not surface them here.

Usage:
    python pilot_review.py status --task-dir <task-directory>
    python pilot_review.py audit  --task-dir <task-directory>

Exit codes:
    0 - read-only check completed and state is valid
    1 - policy, validation, integrity, hash, lock, or approval-state failure
    2 - command-line usage error

For `status`, a valid NEEDS_HUMAN_REVIEW task may exit 0 while reporting
approval readiness BLOCKED, provided no integrity failure exists.

Guarantees:
- Requires MPT_PILOT_PROFILE=braintrustcrypto and a valid, safe pilot
  policy; fails closed when the profile is inactive or the policy is
  missing, malformed, or unsafe.
- Read-only: no file in the task directory is created or changed.
- Sanitized output: never prints complete claim text, prompts, secrets,
  credentials, authorization data, query strings, or environment values.
- Makes no network request and invokes no provider, renderer, or publisher.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

MANIFEST_FILENAME = "provenance_manifest.json"


class ReviewError(Exception):
    """Raised for any policy, validation, or integrity failure."""


# ---------------------------------------------------------------------------
# Pilot-policy gate (same fail-closed pattern as pilot_prepare)
# ---------------------------------------------------------------------------


def _require_pilot_policy():
    """Load the pilot policy, failing closed on any problem."""
    from app.services.pilot_policy import PilotPolicyError, load_pilot_policy

    try:
        policy = load_pilot_policy()
    except PilotPolicyError as exc:
        raise ReviewError(f"pilot policy failure: {exc}") from exc
    if policy is None:
        raise ReviewError(
            "pilot policy failure: MPT_PILOT_PROFILE is not 'braintrustcrypto'"
        )
    return policy


# ---------------------------------------------------------------------------
# Sanitization helpers — never leak secrets, query strings, or full text
# ---------------------------------------------------------------------------


def _strip_query(url: str) -> str:
    """Return scheme://host/path with any query string or fragment removed."""
    if not isinstance(url, str):
        return "<invalid>"
    for sep in ("?", "#"):
        idx = url.find(sep)
        if idx != -1:
            url = url[:idx]
    return url


def _truncate(text: str, limit: int = 48) -> str:
    """Truncate long free-text for safe one-line display."""
    if not isinstance(text, str):
        return "<invalid>"
    text = text.replace("\n", " ").replace("\r", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# Read-only manifest loading and confinement
# ---------------------------------------------------------------------------


def _resolve_task_dir(task_dir: str) -> str:
    from app.services import provenance as prov

    if not isinstance(task_dir, str) or not task_dir.strip():
        raise ReviewError("task directory must be a non-empty path")
    base = os.path.realpath(os.path.expanduser(task_dir.strip()))
    if not os.path.isdir(base):
        raise ReviewError(f"task directory does not exist: {task_dir!r}")
    return base


def _load_manifest(task_dir: str) -> tuple[dict, str, str]:
    """Load and validate the manifest. Returns (manifest, path, sha256)."""
    from app.services import provenance as prov

    base = _resolve_task_dir(task_dir)
    manifest_path = os.path.join(base, MANIFEST_FILENAME)
    if not os.path.isfile(manifest_path):
        raise ReviewError(f"manifest not found: {MANIFEST_FILENAME}")
    try:
        with open(manifest_path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise ReviewError(f"cannot read manifest: {exc}") from exc
    manifest_sha = hashlib.sha256(raw).hexdigest()
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewError(f"manifest is malformed JSON: {exc}") from exc
    if not isinstance(manifest, dict):
        raise ReviewError("manifest is not a JSON object")
    try:
        prov.validate_manifest(manifest)
    except prov.ProvenanceError as exc:
        raise ReviewError(f"manifest validation: {exc}") from exc
    return manifest, manifest_path, manifest_sha


def _hash_current(task_dir: str, rel_path: str) -> str | None:
    """Return the current streamed SHA-256 of a confined file, or None."""
    from app.services import provenance as prov

    try:
        resolved = prov.resolve_task_path(task_dir, rel_path, must_exist=True)
    except prov.ProvenanceError:
        return None
    if not os.path.isfile(resolved):
        return None
    try:
        return prov.sha256_file_streamed(resolved)
    except prov.ProvenanceError:
        return None


# ---------------------------------------------------------------------------
# Read-only state assembly (shared by status and audit)
# ---------------------------------------------------------------------------


def _assemble_state(task_dir: str) -> dict:
    """Gather every read-only fact needed by status and audit.

    Performs no mutation. Returns a dict of facts plus a list of integrity
    failures (reason codes). An empty failures list means integrity holds.
    """
    from app.services import provenance as prov
    from app.services import review_integrity as ri

    base = _resolve_task_dir(task_dir)
    failures: list[str] = []
    state: dict = {"task_dir": base}

    # --- manifest ---
    try:
        manifest, manifest_path, manifest_sha = _load_manifest(base)
    except ReviewError as exc:
        state["manifest_error"] = str(exc)
        state["failures"] = [f"manifest:{exc}"]
        return state
    state["manifest"] = manifest
    state["manifest_sha256"] = manifest_sha
    state["schema_version"] = manifest.get("task", {}).get("schema_version")

    # --- current hash checks (script / assets / output) ---
    script = manifest.get("script")
    script_status = "not-present"
    if script:
        current = _hash_current(base, script.get("local_path", ""))
        if current is None:
            script_status = "missing"
            failures.append("script:missing")
        elif current != script.get("sha256"):
            script_status = "changed"
            failures.append("script:hash-mismatch")
        else:
            script_status = "ok"
    state["script_status"] = script_status

    asset_statuses = []
    for asset in manifest.get("assets", []):
        current = _hash_current(base, asset.get("local_path", ""))
        if current is None:
            asset_statuses.append("missing")
            failures.append(f"asset:missing:{asset.get('local_path')}")
        elif current != asset.get("sha256"):
            asset_statuses.append("changed")
            failures.append(f"asset:hash-mismatch:{asset.get('local_path')}")
        else:
            asset_statuses.append("ok")
    state["asset_statuses"] = asset_statuses

    output = manifest.get("output")
    output_status = "not-present"
    if output:
        if output.get("sha256") is None:
            output_status = "not-present"
        else:
            current = _hash_current(base, output.get("local_path", ""))
            if current is None:
                output_status = "missing"
                failures.append("output:missing")
            elif current != output.get("sha256"):
                output_status = "changed"
                failures.append("output:hash-mismatch")
            else:
                output_status = "ok"
    state["output_status"] = output_status

    # --- asset provenance completeness ---
    incomplete_assets = []
    for asset in manifest.get("assets", []):
        if not asset.get("license_name") or not asset.get("license_evidence"):
            incomplete_assets.append(asset.get("local_path"))
        if asset.get("source_type") == "provider":
            for field in ("source_url", "provider", "provider_asset_id",
                          "retrieval_date"):
                if not asset.get(field):
                    incomplete_assets.append(asset.get("local_path"))
    state["incomplete_assets"] = incomplete_assets
    if incomplete_assets:
        failures.append("asset:provenance-incomplete")

    # --- claim counts and blockers ---
    claims = manifest.get("factual_claims", [])
    counts = {"UNVERIFIED": 0, "VERIFIED": 0, "RETRACTED": 0}
    for claim in claims:
        status = claim.get("status")
        if status in counts:
            counts[status] += 1
    state["claim_counts"] = counts
    blocking = [c for c in claims if c.get("status") in ("UNVERIFIED", "RETRACTED")]
    state["blocking_claims"] = len(blocking)

    # --- review-event chain + checkpoint ---
    try:
        events = ri.validate_review_event_chain(base)
        state["event_count"] = len(events)
        state["event_chain_valid"] = True
        state["event_head_hash"] = events[-1]["event_hash"] if events else None
    except ri.ReviewIntegrityError as exc:
        state["event_count"] = None
        state["event_chain_valid"] = False
        state["event_chain_error"] = str(exc)
        failures.append(f"event-chain:{exc}")

    # --- receipt chain + checkpoint ---
    try:
        receipts = ri.validate_receipt_chain(base)
        state["receipt_count"] = len(receipts)
        state["receipt_chain_valid"] = True
        state["receipts"] = receipts
    except ri.ReviewIntegrityError as exc:
        state["receipt_count"] = None
        state["receipt_chain_valid"] = False
        state["receipt_chain_error"] = str(exc)
        failures.append(f"receipt-chain:{exc}")

    # --- uncommitted tails ---
    for chain_type in ("review-events", "approvals"):
        try:
            tail = ri.find_uncommitted_tail(base, chain_type)
            state[f"{chain_type}_uncommitted"] = len(tail)
            if tail:
                failures.append(f"{chain_type}:uncommitted-tail")
        except ri.ReviewIntegrityError:
            state[f"{chain_type}_uncommitted"] = None

    # --- lock status (read-only; never acquired or removed) ---
    try:
        lock = ri.read_review_lock(base)
        state["lock_held"] = lock is not None
        if lock is not None:
            state["lock_holder"] = lock.get("reviewer_id")
    except ri.ReviewIntegrityError as exc:
        state["lock_held"] = None
        state["lock_error"] = str(exc)
        failures.append(f"lock:{exc}")

    # --- transaction journal (read-only detection) ---
    try:
        journal = ri.read_transaction_journal(base)
        state["transaction_journal"] = journal
        if journal is not None:
            failures.append("INCOMPLETE_TRANSACTION")
    except ri.ReviewIntegrityError as exc:
        state["transaction_journal"] = None
        state["transaction_journal_error"] = str(exc)
        failures.append("INCOMPLETE_TRANSACTION")

    # --- unexpected partial/temp files ---
    partials = []
    for sub in ("review-events", "approvals", "manifest-history"):
        subdir = os.path.join(base, sub)
        if os.path.isdir(subdir):
            for name in os.listdir(subdir):
                if name.startswith(".tmp-") or name.endswith(".part") or \
                        name.endswith(".tmp"):
                    partials.append(f"{sub}/{name}")
    for name in os.listdir(base):
        if name.startswith(".tmp-") or name.endswith(".part"):
            partials.append(name)
    state["partial_files"] = partials
    if partials:
        failures.append("partial-files-present")

    state["failures"] = failures
    return state


# ---------------------------------------------------------------------------
# Effective task status (derived read-only; never inferred from manifest alone)
# ---------------------------------------------------------------------------


def _effective_status(state: dict) -> tuple[str, list[str]]:
    """Derive the effective task status without modifying files.

    Returns (status, blocking_reasons). Status is one of:
    NEEDS_HUMAN_REVIEW, APPROVED, REVOKED, REJECTED, INVALID.
    """
    reasons: list[str] = []
    if "manifest" not in state:
        return "INVALID", ["manifest unreadable or invalid"]
    if state.get("failures"):
        # Any integrity failure forces fail-closed.
        return "INVALID", ["integrity failure: " + "; ".join(
            f.split(":", 1)[0] for f in state["failures"][:3]
        )]

    manifest = state["manifest"]
    task_status = manifest.get("task", {}).get("review_status")
    receipts = state.get("receipts") or []

    approvals = [r for r in receipts if r.get("receipt_type") == "APPROVAL"]
    revocations = [r for r in receipts if r.get("receipt_type") == "REVOCATION"]

    # Revocation linked to a valid approval => REVOKED.
    if approvals and revocations:
        approval_ids = {a["receipt_id"] for a in approvals}
        if any(r.get("approval_receipt_id") in approval_ids for r in revocations):
            return "REVOKED", []

    if task_status == "APPROVED":
        # Do NOT infer approval from the manifest alone: a receipt is required.
        if not approvals:
            return "INVALID", ["manifest APPROVED but no approval receipt"]
        # Receipt must anchor this manifest version.
        latest = approvals[-1]
        if latest.get("manifest_sha256") != state.get("manifest_sha256"):
            reasons.append("approval receipt manifest hash mismatch")
            return "INVALID", reasons
        return "APPROVED", []

    if task_status == "REJECTED":
        return "REJECTED", []

    if task_status == "NEEDS_HUMAN_REVIEW":
        if approvals:
            return "INVALID", ["approval receipt exists for unapproved manifest"]
        return "NEEDS_HUMAN_REVIEW", []

    return "INVALID", [f"unknown task review_status: {task_status!r}"]


def _approval_readiness(state: dict, effective: str) -> tuple[str, list[str]]:
    """Return (READY|BLOCKED, reasons)."""
    reasons: list[str] = []
    if effective != "NEEDS_HUMAN_REVIEW":
        return "BLOCKED", [f"effective status is {effective}, not NEEDS_HUMAN_REVIEW"]
    if state.get("failures"):
        reasons.append("integrity failure present")
    if state.get("blocking_claims"):
        reasons.append(
            f"{state['blocking_claims']} claim(s) UNVERIFIED/RETRACTED"
        )
    if state.get("incomplete_assets"):
        reasons.append(f"{len(state['incomplete_assets'])} asset(s) incomplete")
    if state.get("script_status") not in ("ok", "not-present"):
        reasons.append(f"script {state['script_status']}")
    if any(s != "ok" for s in state.get("asset_statuses", [])):
        reasons.append("asset hash issue")
    if state.get("lock_held"):
        reasons.append("review lock held")
    return ("BLOCKED", reasons) if reasons else ("READY", [])


# ---------------------------------------------------------------------------
# status command
# ---------------------------------------------------------------------------


def cmd_status(args: argparse.Namespace) -> int:
    _require_pilot_policy()
    state = _assemble_state(args.task_dir)

    if "manifest_error" in state:
        print(f"error: {state['manifest_error']}", file=sys.stderr)
        return EXIT_FAILURE

    manifest = state["manifest"]
    task = manifest.get("task", {})
    effective, eff_reasons = _effective_status(state)
    readiness, ready_reasons = _approval_readiness(state, effective)

    # Any integrity failure, or an INVALID effective status (contradiction,
    # missing required receipt, mismatched hash), is a hard failure => exit 1.
    # A valid NEEDS_HUMAN_REVIEW draft that is merely BLOCKED exits 0.
    integrity_failures = state.get("failures", [])
    hard_failure = bool(integrity_failures) or effective == "INVALID"

    print("BrainTrustCrypto pilot review — status")
    print(f"  task_id:              {task.get('task_id')}")
    print(f"  schema_version:       {state.get('schema_version')}")
    print(f"  manifest status:      {task.get('review_status')}")
    print(f"  effective status:     {effective}")
    print(f"  manifest sha256:      {state.get('manifest_sha256')}")
    print(f"  script hash:          {state.get('script_status')}")
    asset_statuses = state.get("asset_statuses", [])
    if asset_statuses:
        summary = ",".join(sorted(set(asset_statuses)))
        print(f"  asset hashes:         {summary} ({len(asset_statuses)} asset(s))")
    else:
        print("  asset hashes:         none")
    print(f"  output hash:          {state.get('output_status')}")

    counts = state.get("claim_counts", {})
    print(f"  claims:               UNVERIFIED={counts.get('UNVERIFIED', 0)} "
          f"VERIFIED={counts.get('VERIFIED', 0)} "
          f"RETRACTED={counts.get('RETRACTED', 0)}")

    incomplete = state.get("incomplete_assets", [])
    print(f"  asset provenance:     "
          f"{'incomplete (' + str(len(incomplete)) + ')' if incomplete else 'complete'}")

    event_count = state.get("event_count")
    print(f"  review events:        "
          f"{event_count if event_count is not None else 'chain-error'}")
    print(f"  event checkpoint:     "
          f"{'ok' if state.get('event_chain_valid') else 'INVALID'}")

    receipt_count = state.get("receipt_count")
    print(f"  receipts:             "
          f"{receipt_count if receipt_count is not None else 'chain-error'}")
    print(f"  receipt checkpoint:   "
          f"{'ok' if state.get('receipt_chain_valid') else 'INVALID'}")

    audit_valid = state.get("event_chain_valid") and state.get("receipt_chain_valid")
    print(f"  audit-chain validity: {'valid' if audit_valid else 'INVALID'}")

    lock_held = state.get("lock_held")
    if lock_held is None:
        print("  lock status:          error (malformed lock)")
    elif lock_held:
        print(f"  lock status:          held by {state.get('lock_holder')}")
    else:
        print("  lock status:          free")

    print(f"  approval readiness:   {readiness}")
    for reason in ready_reasons:
        print(f"    - {_truncate(reason)}")

    # Transaction journal status (read-only).
    journal = state.get("transaction_journal")
    journal_error = state.get("transaction_journal_error")
    if journal is None and journal_error is None:
        print("  transaction status:   none")
    else:
        print(f"  transaction status:   INCOMPLETE_TRANSACTION")
        if journal is not None:
            print(f"    stage:              {journal.get('transaction_stage')}")
            print(f"    operation:          {journal.get('operation')}")
            print(f"    claim_id:           {journal.get('claim_id')}")
            print(f"    transaction_id:     {journal.get('transaction_id')}")
        else:
            print(f"    error:              {_truncate(journal_error)}")

    if hard_failure:
        return EXIT_FAILURE
    return EXIT_OK


# ---------------------------------------------------------------------------
# audit command
# ---------------------------------------------------------------------------


def cmd_audit(args: argparse.Namespace) -> int:
    _require_pilot_policy()
    state = _assemble_state(args.task_dir)

    reason_codes: list[str] = []

    if "manifest_error" in state:
        reason_codes.append("MANIFEST_INVALID")
    else:
        # Map internal failures to concise sanitized reason codes.
        for failure in state.get("failures", []):
            category = failure.split(":", 1)[0]
            code = {
                "script": "SCRIPT_HASH",
                "asset": "ASSET_INTEGRITY",
                "output": "OUTPUT_HASH",
                "event-chain": "EVENT_CHAIN",
                "receipt-chain": "RECEIPT_CHAIN",
                "review-events": "UNCOMMITTED_TAIL",
                "approvals": "UNCOMMITTED_TAIL",
                "lock": "LOCK_STATE",
                "partial-files-present": "PARTIAL_FILES",
                "INCOMPLETE_TRANSACTION": "INCOMPLETE_TRANSACTION",
            }.get(category, category.upper().replace("-", "_"))
            if code not in reason_codes:
                reason_codes.append(code)

        effective, _ = _effective_status(state)
        if effective == "INVALID" and not state.get("failures"):
            reason_codes.append("APPROVAL_STATE")

    passed = not reason_codes
    print("BrainTrustCrypto pilot review — audit")
    print(f"  task_id:    "
          f"{state.get('manifest', {}).get('task', {}).get('task_id', '<unknown>')}")
    print(f"  result:     {'PASS' if passed else 'FAIL'}")
    if reason_codes:
        print(f"  reasons:    {', '.join(sorted(set(reason_codes)))}")

    return EXIT_OK if passed else EXIT_FAILURE


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pilot_review",
        description=(
            "BrainTrustCrypto pilot read-only review inspection. Commands: "
            "status, audit. Never mutates the task directory."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)
    for name, helptext in (
        ("status", "read-only snapshot of review state"),
        ("audit", "read-only integrity validation (PASS/FAIL)"),
    ):
        cmd = sub.add_parser(name, help=helptext)
        cmd.add_argument(
            "--task-dir",
            required=True,
            help="designated task directory (read-only)",
        )
    return parser


_COMMANDS = {"status": cmd_status, "audit": cmd_audit}


def run(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    handler = _COMMANDS.get(args.command)
    if handler is None:
        parser.error(f"unknown command: {args.command}")
        return EXIT_USAGE  # unreachable
    try:
        return handler(args)
    except ReviewError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    except OSError as exc:
        print(f"error: filesystem failure: {exc}", file=sys.stderr)
        return EXIT_FAILURE


if __name__ == "__main__":
    raise SystemExit(run())
