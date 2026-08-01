"""Typed apply/rollback engine for connector writes (R4C.1B).

This is the first phase allowed to WRITE a host configuration, and the
whole module is shaped around what that permission does and does not
mean. Applying a plan edits a file. It does not launch a host, it does
not complete a handshake, and it does not make Relinkra reachable from
an agent — so a successful apply reports ``config_applied_host_
unverified`` and nothing stronger, and the human output says the host
must be restarted and proven before anything is claimed.

The mechanics deliberately assemble existing, separately tested
primitives rather than re-inventing them:

    inspect_connector     re-read the world; never trust stale data
    build_plan            gate on the same decision the user reviewed
    decide_member         add / no_op / update / conflict
    safe_replace          backup, atomic write, precondition, rollback

REFUSAL IS A FIRST-CLASS OUTCOME. Anything that would make the write
unsafe or dishonest — a malformed config, a symlink target, an
unmanaged entry under our name, a direct CBM exposure beside ours, a
file changed since inspection — stops the engine BEFORE any write is
attempted and returns an honest :class:`ApplyResult` with the reason
and the suggested action. Exit-code mapping lives in the CLI; this
module only states facts.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence, Tuple

from .backend_detection import classify_entry
from .backend_policy import BACKEND_CBM, DETECTION_DETECTED
from .config_merge import (
    ACTION_NO_OP,
    MergeError,
    apply_member,
    decide_member,
    detect_indent,
    ownership_test,
    parse_json_document,
    serialize_json_document,
    validate_json_text,
)
from .connector import (
    DISCOVERY_CONFIG_MALFORMED,
    DISCOVERY_CONFIG_UNSUPPORTED,
    DISCOVERY_DISCOVERED,
    FORMAT_JSON,
    MANAGED_SERVER_NAME,
    PLAN_READY,
    LaunchContract,
    pinned_project_id,
)
from .connectors import (
    ConnectorSpec,
    build_plan,
    container_path_for,
    entry_tokens,
    inspect_connector,
    launch_contract_document,
    launches_relinkra,
)
from .handoff import contains_absolute_path, scrub_absolute_paths
from .host_discovery import DiscoveryEnvironment
from .memory import sanitize_error
from .registry import interprocess_lock
from .safe_write import (
    BACKUP_SUFFIX,
    ContentValidationError,
    PreconditionError,
    SafeWriteError,
    UnsafeTargetError,
    assert_writable_target,
    atomic_write_text,
    detect_newline,
    digest_text,
    read_bounded_text,
    safe_replace,
)

#: Bumped when the machine receipt shape changes. Consumers pin it.
RECEIPT_VERSION = "relinkra.connect-apply/v1"

#: Receipt directory, relative to the workspace root. Covered by the
#: existing ``.relinkra/`` git-ignore rule.
RECEIPT_DIRNAME = "connect-apply"
_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "host",
        "timestamp",
        "target_path",
        "backup_path",
        "digest_before",
        "digest_after",
        "backup_digest",
        "launch_fingerprint",
        "workspace_root",
        "project_id",
    }
)
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_RECEIPT_MAX_BYTES = 64 * 1024
_INVALID_RECEIPT = "__invalid_receipt__"


def _reject_duplicate_receipt_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate receipt key: {key!r}")
        result[key] = value
    return result


def _reject_nonfinite_receipt(value):
    raise ValueError(f"non-finite receipt value: {value!r}")

#: The only claim an apply may make about verification. Everything
#: past it requires the real host, which proves itself separately.
#: Known debt: this stage string lives outside the VERIFICATION_STAGES
#: taxonomy in connect_verification; unifying them is deliberate
#: follow-up work, not something to improvise inside a write path.
STAGE_CONFIG_APPLIED_HOST_UNVERIFIED = "config_applied_host_unverified"

#: Structural classes for an MCP server entry. Classification looks at
#: what an entry LAUNCHES, never at the configuration key it sits under.
CLASS_RELINKRA = "relinkra"
CLASS_CBM = "cbm"
CLASS_FOREIGN = "foreign"
ENTRY_CLASSES = frozenset({CLASS_RELINKRA, CLASS_CBM, CLASS_FOREIGN})


# ---------------------------------------------------------------------------
# Launch fingerprint
# ---------------------------------------------------------------------------


def launch_fingerprint(launch: LaunchContract) -> str:
    """Stable digest of the portable launch contract.

    Two renders of the same contract fingerprint identically on any
    machine, and any change to the contract — distribution shape,
    argument arity, environment keys — changes the digest. Verification
    evidence pins this value, so a contract change invalidates old
    proofs instead of letting them masquerade as current.
    """
    document = launch_contract_document(launch)
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Structural entry classification
# ---------------------------------------------------------------------------


def _env_mapping(entry: Any) -> dict:
    """The entry's environment as a plain mapping, either field shape."""
    if not isinstance(entry, Mapping):
        return {}
    env = entry.get("env") or entry.get("environment") or {}
    if not isinstance(env, Mapping):
        return {}
    return {str(key): str(value) for key, value in env.items()}


def entries_equivalent(existing: Any, desired: Any) -> bool:
    """Whether two entries are the SAME registration on this machine.

    Exact, on purpose: the launch token sequence must match token for
    token and the environment mapping must match key AND value. This is
    the predicate the no-op and post-write verification paths trust, so
    it cannot be tolerant — a registration pinned to a DIFFERENT
    ``--workspace-root`` is a different registration, and calling it
    equivalent would turn a needed UPDATE into a silent no-op.

    The tolerant "does this launch Relinkra at all" classification lives
    separately in ``launches_relinkra``; the two answer different
    questions and must not drift into one.
    """
    return (
        entry_tokens(existing) == entry_tokens(desired)
        and _env_mapping(existing) == _env_mapping(desired)
    )


def classify_server_entry(entry: Any) -> str:
    """What an MCP entry structurally IS, by launch target alone.

    The configuration key is never consulted: an entry named
    ``relinkra`` that launches node is foreign, and an entry named
    ``totally-other`` that launches ``codebase-memory-mcp`` is a direct
    CBM exposure. The CBM markers are the declared table from
    ``backend_detection`` — one definition of "what CBM looks like",
    shared by detection and by this gate, so the two cannot drift.
    """
    if launches_relinkra(entry):
        return CLASS_RELINKRA
    detection = classify_entry("", entry)
    if detection.backend == BACKEND_CBM and detection.confidence == DETECTION_DETECTED:
        return CLASS_CBM
    return CLASS_FOREIGN


# ---------------------------------------------------------------------------
# Result contract
# ---------------------------------------------------------------------------


def _sanitize(text: str) -> str:
    """Make an exception message safe to show: secrets out, paths out."""
    return scrub_absolute_paths(sanitize_error(text or ""))


@dataclass
class ApplyResult:
    """What an apply or rollback actually did, field by field.

    Every stage of the engine gets its own boolean, because "it failed"
    is four different user situations depending on whether the file was
    read, the write was attempted, the write landed, or the write landed
    and was rolled back. ``to_dict`` is the portable rendering and is
    the default; the machine-only paths live in separate attributes and
    surface only through :meth:`to_machine_dict`.
    """

    host: str
    #: Portable display hint for the config (``~/.claude/settings.json``).
    config_path: str = ""
    discovered: bool = False
    readable: bool = False
    format_supported: bool = False
    plan_ready: bool = False
    change_required: bool = False
    backup_created: bool = False
    write_attempted: bool = False
    write_succeeded: bool = False
    validation_succeeded: bool = False
    rollback_attempted: bool = False
    rollback_succeeded: bool = False
    registration_present: bool = False
    registration_managed: bool = False
    registration_matches_expected: bool = False
    host_restart_required: bool = False
    #: Always False from apply. Hosts prove themselves; files do not.
    real_host_verified: bool = False
    verification_stage: str = ""
    warnings: Tuple[str, ...] = ()
    actions: Tuple[str, ...] = ()
    error: str = ""
    digest_before: Optional[str] = None
    digest_after: Optional[str] = None
    backup_digest: Optional[str] = None
    refusal_reason: str = ""
    #: Portable backup identity (the file NAME, never its directory).
    backup_ref: str = ""
    #: Machine-local values. Never rendered by to_dict.
    real_config_path: str = ""
    real_backup_path: str = ""
    workspace_root: str = ""
    launch_fingerprint: str = ""

    @property
    def refused(self) -> bool:
        return bool(self.refusal_reason)

    @property
    def ok(self) -> bool:
        """Whether the engine's goal was met (including an honest no-op)."""
        if self.refused or self.error:
            return False
        if self.rollback_attempted:
            return self.rollback_succeeded and self.validation_succeeded
        if not self.change_required:
            return self.registration_matches_expected
        return self.write_succeeded and self.validation_succeeded

    def to_dict(self) -> dict:
        """Portable rendering: no absolute paths, no environment values."""
        return {
            "host": self.host,
            "config_path": self.config_path,
            "discovered": self.discovered,
            "readable": self.readable,
            "format_supported": self.format_supported,
            "plan_ready": self.plan_ready,
            "change_required": self.change_required,
            "backup_created": self.backup_created,
            "backup_ref": self.backup_ref,
            "write_attempted": self.write_attempted,
            "write_succeeded": self.write_succeeded,
            "validation_succeeded": self.validation_succeeded,
            "rollback_attempted": self.rollback_attempted,
            "rollback_succeeded": self.rollback_succeeded,
            "registration_present": self.registration_present,
            "registration_managed": self.registration_managed,
            "registration_matches_expected": self.registration_matches_expected,
            "host_restart_required": self.host_restart_required,
            "real_host_verified": self.real_host_verified,
            "verification_stage": self.verification_stage,
            "launch_fingerprint": self.launch_fingerprint,
            "digest_before": self.digest_before,
            "digest_after": self.digest_after,
            "backup_digest": self.backup_digest,
            "refusal_reason": self.refusal_reason,
            "error": self.error,
            "warnings": list(self.warnings),
            "actions": list(self.actions),
        }

    def to_machine_dict(self) -> dict:
        """Machine-local rendering, emitted only on explicit request."""
        data = self.to_dict()
        data["real_config_path"] = self.real_config_path
        data["real_backup_path"] = self.real_backup_path
        data["workspace_root"] = self.workspace_root
        return data


def _refuse(
    result: ApplyResult, reason: str, actions: Sequence[str] = ()
) -> ApplyResult:
    result.refusal_reason = reason
    result.actions = tuple(actions)
    return result


# ---------------------------------------------------------------------------
# Machine receipts
# ---------------------------------------------------------------------------


def _receipt_path(root, connector_id: str) -> Path:
    return Path(root) / ".relinkra" / RECEIPT_DIRNAME / f"{connector_id}.json"


def _project_id_for(root) -> str:
    """The pinned project id, best effort; empty when uninitialized."""
    try:
        from .product_cli import WorkspaceConfig

        config = WorkspaceConfig.load(Path(root))
        return config.project_id if config else ""
    except Exception:
        return ""


def _persist_receipt(result: ApplyResult, *, backup_path: Optional[Path]) -> None:
    """Write the machine receipt. Failure degrades to a warning.

    The receipt is what explicit rollback and check freshness read, but
    the apply itself already succeeded by the time it is written — a
    read-only state directory must not convert a good write into a
    reported failure. Rollback then falls back to newest-backup
    discovery.
    """
    if not result.workspace_root:
        result.warnings += (
            "no workspace root was resolved, so no machine receipt was "
            "recorded; rollback will fall back to backup-file discovery",
        )
        return
    payload = {
        "schema_version": RECEIPT_VERSION,
        "host": result.host,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_path": result.real_config_path,
        "backup_path": str(backup_path) if backup_path else None,
        "digest_before": result.digest_before,
        "digest_after": result.digest_after,
        "backup_digest": result.backup_digest,
        "launch_fingerprint": result.launch_fingerprint,
        "workspace_root": result.workspace_root,
        "project_id": _project_id_for(result.workspace_root),
    }
    try:
        path = _receipt_path(result.workspace_root, result.host)
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    except OSError as exc:
        result.warnings += (
            f"the machine receipt could not be recorded ({_sanitize(str(exc))}); "
            "rollback will fall back to backup-file discovery",
        )


def _load_receipt(root, connector_id: str) -> Optional[dict]:
    try:
        path = _receipt_path(root, connector_id)
        if not _regular_non_reparse_file(path):
            return None
        data = json.loads(
            read_bounded_text(path, max_bytes=_RECEIPT_MAX_BYTES),
            object_pairs_hook=_reject_duplicate_receipt_keys,
            parse_constant=_reject_nonfinite_receipt,
        )
        if not isinstance(data, dict) or set(data) != set(_RECEIPT_KEYS):
            return {_INVALID_RECEIPT: "receipt schema is incomplete or has unknown fields"}
        if data.get("schema_version") != RECEIPT_VERSION:
            return {_INVALID_RECEIPT: "unsupported receipt schema"}
        if data.get("host") != connector_id:
            return {_INVALID_RECEIPT: "receipt host does not match the connector"}
        for key in (
            "timestamp", "target_path", "launch_fingerprint", "workspace_root", "project_id",
        ):
            if (
                not isinstance(data.get(key), str)
                or (not data[key] and key != "project_id")
                or len(data[key]) > 1024
                or any(ord(char) < 32 or ord(char) == 127 for char in data[key])
            ):
                return {_INVALID_RECEIPT: f"receipt field {key!r} is invalid"}
        for key in ("digest_before", "digest_after", "backup_digest"):
            value = data.get(key)
            if value is not None and (
                not isinstance(value, str)
                or (value and not _HEX64_RE.fullmatch(value))
            ):
                return {_INVALID_RECEIPT: f"receipt digest {key!r} is invalid"}
        backup_path = data.get("backup_path")
        if backup_path is not None and (not isinstance(backup_path, str) or not backup_path):
            return {_INVALID_RECEIPT: "receipt backup_path is invalid"}
        return data
    except (OSError, ValueError, RecursionError, TypeError):
        # The receipt exists but cannot be parsed.  Never fall back to a
        # guessed sibling backup in that case.
        return {_INVALID_RECEIPT: "receipt is malformed or oversized"}


def _regular_non_reparse_file(path: Path) -> bool:
    """Return true only for a plain file, without following a link."""
    try:
        info = os.lstat(str(path))
    except OSError:
        return False
    if not stat.S_ISREG(info.st_mode):
        return False
    # Windows exposes reparse points through this attribute.  The fallback
    # is harmless on POSIX, where lstat already rejects symlinks above.
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return not bool(getattr(info, "st_file_attributes", 0) & reparse)


def _same_real_path(left: Path, right: Path) -> bool:
    try:
        return os.path.normcase(os.path.realpath(str(left))) == os.path.normcase(
            os.path.realpath(str(right))
        )
    except (OSError, ValueError):
        return False


def _safe_receipt_path(path: Path) -> bool:
    """Reject receipt paths that are not local absolute managed paths."""
    value = str(path)
    if not path.is_absolute() or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return False
    if os.name == "nt" and (
        value.startswith(("\\\\", "//", "\\\\?\\", "\\\\.\\"))
    ):
        return False
    return True


# ---------------------------------------------------------------------------
# Shared inspection plumbing
# ---------------------------------------------------------------------------


def _preferred_location(spec: ConnectorSpec, inspection):
    """Where a write would go: the active config, else the first candidate."""
    if inspection.location is not None:
        return inspection.location
    return inspection.locations[0] if inspection.locations else None


def _container(document: Mapping[str, Any], path: Sequence[str]) -> Any:
    node: Any = document
    for key in path:
        if not isinstance(node, Mapping):
            return None
        node = node.get(key)
    return node


def _direct_cbm_entries(document: Mapping[str, Any], container_path: Sequence[str]) -> int:
    """Count direct CBM entries in every effective Claude JSON scope.

    Claude's project-local container is not the only scope that can affect a
    process: a top-level ``mcpServers`` registration is inherited by hosts
    that do not override it.  The friendly key is deliberately ignored.
    """
    containers = []
    target = _container(document, container_path)
    if isinstance(target, Mapping):
        containers.append(target)
    top_level = document.get("mcpServers") if isinstance(document, Mapping) else None
    if isinstance(top_level, Mapping) and top_level is not target:
        containers.append(top_level)
    return sum(
        1
        for container in containers
        for entry in container.values()
        if classify_server_entry(entry) == CLASS_CBM
    )


def _workspace_scope_direct_cbm(env: DiscoveryEnvironment) -> Tuple[int, bool]:
    """Inspect the present project ``.mcp.json`` without guessing paths.

    Returns ``(count, readable)``.  An unreadable authoritative scope is not
    reported as clean; callers fail closed rather than claiming direct CBM is
    absent.
    """
    if env.workspace_root is None:
        return 0, True
    path = Path(str(env.workspace_root)) / ".mcp.json"
    if not path.exists():
        return 0, True
    try:
        if not _regular_non_reparse_file(path):
            return 0, False
        document = parse_json_document(read_bounded_text(path))
    except (OSError, SafeWriteError, ValueError):
        return 0, False
    if not isinstance(document, Mapping):
        return 0, False
    container = document.get("mcpServers")
    if not isinstance(container, Mapping):
        return 0, True
    return (
        sum(1 for entry in container.values() if classify_server_entry(entry) == CLASS_CBM),
        True,
    )


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------


def apply_connector(
    spec: ConnectorSpec, launch: LaunchContract, env: DiscoveryEnvironment
) -> ApplyResult:
    """Execute the connector's plan against its real configuration file.

    Re-inspects everything first: a plan reviewed five minutes ago
    describes a file that may no longer exist, and the only config this
    engine trusts is the one it just read. Expected operator errors are
    folded into the result; no traceback propagates.
    """
    result = ApplyResult(host=spec.connector_id)
    result.launch_fingerprint = launch_fingerprint(launch)
    if env.workspace_root is not None:
        result.workspace_root = str(Path(str(env.workspace_root)).resolve())

    try:
        return _apply_inner(spec, launch, env, result)
    except Exception as exc:  # expected operator errors are handled inside
        result.error = _sanitize(str(exc))
        return result


def _apply_inner(
    spec: ConnectorSpec,
    launch: LaunchContract,
    env: DiscoveryEnvironment,
    result: ApplyResult,
) -> ApplyResult:
    if not spec.apply_available:
        return _refuse(
            result,
            spec.apply_unavailable_reason
            or "this connector does not support writes in this phase.",
            ("Run 'relinkra connect plan' and apply the change by hand.",),
        )

    if not launch.resolved:
        return _refuse(
            result,
            "the MCP launch contract could not be resolved on this machine, "
            "so there is nothing honest to register.",
            ("Resolve the Relinkra installation first, then re-run apply.",),
        )

    if spec.config_format != FORMAT_JSON or spec.entry_builder is None:
        return _refuse(
            result,
            "this host's configuration format is not writable in this phase.",
            ("Run 'relinkra connect plan' and apply the change by hand.",),
        )

    inspection = inspect_connector(spec, env)
    result.warnings += tuple(
        f"{warning.code}: {warning.message}" for warning in inspection.warnings
    )
    result.discovered = inspection.discovery_status == DISCOVERY_DISCOVERED

    if inspection.discovery_status in (
        DISCOVERY_CONFIG_MALFORMED,
        DISCOVERY_CONFIG_UNSUPPORTED,
    ):
        detail = next(
            (warning.message for warning in inspection.warnings),
            "the existing configuration could not be parsed.",
        )
        return _refuse(
            result,
            f"the host configuration is {inspection.discovery_status}: {detail}",
            (
                "Repair the configuration by hand, then re-run "
                "'relinkra connect apply'.",
            ),
        )

    location = _preferred_location(spec, inspection)
    if location is None or location.path is None:
        return _refuse(
            result,
            "no configuration location applies to this platform.",
            ("Install the host or create its configuration, then re-run apply.",),
        )
    target = Path(str(location.path))
    result.config_path = location.display_hint
    result.real_config_path = str(target)

    if location.exists and not location.readable:
        return _refuse(
            result,
            "the host configuration exists but could not be read.",
            ("Fix the file permissions, then re-run apply.",),
        )
    result.readable = True

    try:
        assert_writable_target(target)
    except UnsafeTargetError as exc:
        return _refuse(
            result,
            f"the configuration target is not a plain writable file: {exc}",
            (
                "Replace the symlink or reparse point with a regular file; "
                "Relinkra never writes through indirection.",
            ),
        )

    document = inspection.document if inspection.document is not None else {}
    result.format_supported = True
    # The container the inspection read — workspace-resolved for hosts
    # like Claude Code whose LOCAL scope is keyed by project.
    container_path = inspection.container_path or container_path_for(
        spec, env.workspace_root
    )

    cbm_exposures = _direct_cbm_entries(document, container_path)
    workspace_cbm_exposures, workspace_scope_readable = _workspace_scope_direct_cbm(env)
    if not workspace_scope_readable:
        return _refuse(
            result,
            "an authoritative project MCP scope could not be read; refusing to claim direct CBM is absent.",
            ("Repair or remove the unreadable .mcp.json, then re-run apply. Nothing was changed.",),
        )
    cbm_exposures += workspace_cbm_exposures
    if cbm_exposures:
        result.warnings += (
            "direct_cbm_exposure: the configuration registers the "
            "codebase-memory backend directly, beside the entry Relinkra "
            "would manage.",
        )
        return _refuse(
            result,
            "a direct codebase-memory (CBM) registration is present in this "
            "configuration. Relinkra does not apply alongside direct CBM "
            "exposure: CBM is Relinkra's private backend, and two routes to "
            "it cannot be reconciled from here.",
            (
                "Remove the direct codebase-memory registration yourself, "
                "then re-run 'relinkra connect apply'. Nothing was changed.",
            ),
        )

    plan = build_plan(spec, inspection, launch)
    result.plan_ready = plan.status == PLAN_READY and not plan.conflicts
    if not result.plan_ready:
        reason = plan.unavailable_reason or (
            "; ".join(plan.conflicts)
            if plan.conflicts
            else f"plan status is '{plan.status}'"
        )
        actions = ["Run 'relinkra connect plan' to review what blocks the write."]
        if plan.conflicts:
            actions.append(
                f"Rename or remove the '{MANAGED_SERVER_NAME}' entry owned by "
                "another server; Relinkra never overwrites it."
            )
        return _refuse(result, reason, actions)

    desired = spec.entry_builder(launch)
    is_managed = ownership_test(launches_relinkra, marker_allowed=spec.marker_allowed)
    try:
        decision = decide_member(
            document,
            container_path,
            MANAGED_SERVER_NAME,
            desired,
            is_managed=is_managed,
        )
    except MergeError as exc:
        return _refuse(result, str(exc), ("Repair the configuration, then re-run apply.",))

    raw_text = inspection.raw_text
    result.change_required = decision.changes_anything

    if decision.action == ACTION_NO_OP:
        # Idempotent re-apply: no backup, no write. Everything is
        # verified by re-reading instead of by trusting the inspection.
        _verify_registration(
            result, target, container_path, desired, is_managed=is_managed
        )
        result.validation_succeeded = result.registration_matches_expected
        result.verification_stage = STAGE_CONFIG_APPLIED_HOST_UNVERIFIED
        result.actions = (
            f"No change required. Restart the host if it has not loaded "
            f"this registration yet, then run 'relinkra connect check "
            f"{spec.connector_id}'.",
        )
        return result

    merged = apply_member(
        document, container_path, MANAGED_SERVER_NAME, decision.member
    )
    # Newline and trailing-newline detection must look at the raw BYTES:
    # the inspection text went through universal-newline reading, which
    # has already normalized every CRLF away. Reformatting the user's
    # line endings would turn a one-member addition into a whole-file
    # diff in their VCS — the exact outcome formatting preservation
    # exists to avoid.
    byte_text = ""
    if location.exists:
        try:
            byte_text = target.read_bytes().decode("utf-8", errors="replace")
        except OSError as exc:
            return _refuse(
                result,
                f"the host configuration could not be read: {_sanitize(str(exc))}",
                ("Fix the file permissions, then re-run apply.",),
            )
    text = serialize_json_document(
        merged,
        indent=detect_indent(raw_text or ""),
        newline=detect_newline(byte_text),
        trailing_newline=(not byte_text) or byte_text.endswith("\n"),
    )
    expected_digest = digest_text(raw_text) if raw_text is not None else None

    def _validate_written_registration(candidate: str) -> None:
        """Validate syntax and semantics while safe_replace still holds its lock.

        A post-write semantic failure must take the same automatic restore
        path as a parse failure; validating only after safe_replace returned
        used to leave a semantically invalid config on disk.
        """
        validate_json_text(candidate)
        candidate_document = parse_json_document(candidate)
        candidate_container = _container(candidate_document, container_path)
        candidate_entry = (
            candidate_container.get(MANAGED_SERVER_NAME)
            if isinstance(candidate_container, Mapping)
            else None
        )
        if candidate_entry is None or not launches_relinkra(candidate_entry):
            raise MergeError("the written configuration has no managed Relinkra entry")
        candidate_decision = decide_member(
            candidate_document,
            container_path,
            MANAGED_SERVER_NAME,
            desired,
            is_managed=is_managed,
        )
        if candidate_decision.action != ACTION_NO_OP:
            raise MergeError("the written Relinkra registration is not semantically equivalent")

    try:
        receipt = safe_replace(
            target,
            text,
            validator=_validate_written_registration,
            expected_digest=expected_digest,
        )
    except PreconditionError as exc:
        # The file changed between inspection and write. Nothing was
        # written; the honest answer is "re-plan", not a retry loop.
        return _refuse(
            result,
            str(exc),
            (
                "Re-run 'relinkra connect plan' to review the new state, "
                "then apply again.",
            ),
        )
    except UnsafeTargetError as exc:
        return _refuse(
            result,
            f"the configuration target became unsafe before the write: {exc}",
            ("Replace the target with a regular file, then re-run apply.",),
        )
    except ContentValidationError as exc:
        result.write_attempted = True
        result.rollback_attempted = True
        result.rollback_succeeded = bool(exc.rolled_back)
        result.error = _sanitize(str(exc))
        result.actions = (
            "The written content failed validation and the original file "
            "was restored. Re-run 'relinkra connect plan' before retrying.",
        )
        return result
    except (SafeWriteError, OSError) as exc:
        result.write_attempted = True
        result.error = _sanitize(str(exc))
        result.actions = (
            "Resolve the filesystem error above, then re-run apply. The "
            "original configuration was left untouched.",
        )
        return result

    result.write_attempted = True
    result.write_succeeded = True
    result.backup_created = receipt.backup_created
    result.digest_before = receipt.digest_before
    result.digest_after = receipt.digest_after
    if receipt.backup_path is not None:
        result.real_backup_path = str(receipt.backup_path)
        result.backup_ref = receipt.backup_path.name
        try:
            result.backup_digest = digest_text(read_bounded_text(receipt.backup_path))
        except (SafeWriteError, OSError):
            result.backup_digest = None

    _verify_registration(
        result, target, container_path, desired, is_managed=is_managed
    )
    result.validation_succeeded = (
        result.registration_present and result.registration_matches_expected
    )
    if not result.validation_succeeded:
        result.error = (
            "the written configuration did not verify: the Relinkra entry "
            "is absent or does not match the planned registration"
        )
        return result

    result.host_restart_required = True
    result.verification_stage = STAGE_CONFIG_APPLIED_HOST_UNVERIFIED
    result.actions = (
        spec.restart_instruction or "Restart the host so it re-reads its configuration.",
        f"After the restart, run 'relinkra connect check {spec.connector_id}' "
        "to confirm the configuration side, and 'relinkra connect verify "
        f"{spec.connector_id} --proof <file>' to record real host evidence.",
        f"To undo the change, run 'relinkra connect rollback {spec.connector_id}'.",
    )
    _persist_receipt(result, backup_path=receipt.backup_path)
    return result


def _verify_registration(
    result: ApplyResult,
    target: Path,
    container_path: Sequence[str],
    desired: Any,
    *,
    is_managed,
) -> None:
    """Re-read the file and semantically verify the Relinkra entry.

    Trusts nothing from before the write: the proof that the entry is
    there and correct is the bytes on disk right now. "Correct" uses the
    same merge semantics the apply itself used — re-running the decision
    against the written file must yield NO_OP. Comparing against the raw
    desired entry instead would falsely fail entries carrying operator
    additions the merge rules deliberately preserve.
    """
    try:
        written = read_bounded_text(target)
        document = parse_json_document(written)
    except (SafeWriteError, OSError, ValueError) as exc:
        result.error = _sanitize(str(exc))
        return
    if result.digest_after is None:
        result.digest_after = digest_text(written)
    container = _container(document, container_path)
    entry = container.get(MANAGED_SERVER_NAME) if isinstance(container, Mapping) else None
    result.registration_present = entry is not None
    result.registration_managed = bool(entry is not None and launches_relinkra(entry))
    try:
        decision = decide_member(
            document,
            container_path,
            MANAGED_SERVER_NAME,
            desired,
            is_managed=is_managed,
        )
    except MergeError as exc:
        result.error = _sanitize(str(exc))
        result.registration_matches_expected = False
        return
    result.registration_matches_expected = decision.action == ACTION_NO_OP


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------


def _backup_index(target: Path, candidate: Path) -> int:
    """Sort key for backup siblings. ``-1`` means "not one of ours"."""
    prefix = target.name + BACKUP_SUFFIX
    if not candidate.name.startswith(prefix):
        return -1
    tail = candidate.name[len(prefix):]
    if tail == "":
        return 0
    if tail.startswith("-") and tail[1:].isdigit():
        return int(tail[1:])
    return -1


def _newest_backup(target: Path) -> Optional[Path]:
    """The newest backup sibling of ``target``, deterministically.

    "Newest" is the highest collision suffix, not the mtime: timestamps
    lie across copies and filesystems, and the suffix order is the order
    the backups were created in.
    """
    try:
        candidates = [
            path
            for path in target.parent.glob(target.name + BACKUP_SUFFIX + "*")
            if _regular_non_reparse_file(path)
        ]
    except OSError:
        return None
    indexed = [
        (index, path)
        for path in candidates
        for index in (_backup_index(target, path),)
        if index >= 0
    ]
    if not indexed:
        return None
    return max(indexed, key=lambda pair: pair[0])[1]


def rollback_connector(
    spec: ConnectorSpec, env: DiscoveryEnvironment, *, workspace_root
) -> ApplyResult:
    """Restore the pre-apply configuration from its backup.

    Two safety rules make this a restore and never a guess.

    RECEIPT DIGEST GATE. When a machine receipt exists, the current file
    must still digest to what the apply left behind. Anything else means
    someone edited the file after us, and overwriting their edit with
    our backup would be the same silent data loss the apply path refuses
    to cause.

    PROVENANCE GATE. Without a receipt, a restore happens only when the
    current file parses and still contains a structurally Relinkra-owned
    entry — proof that what is about to be replaced is plausibly ours.
    A file that fails that test is left alone and reported.
    """
    result = ApplyResult(host=spec.connector_id)
    if not spec.apply_available:
        return _refuse(
            result,
            spec.apply_unavailable_reason
            or "rollback is disabled for this connector because apply is disabled.",
            ("This connector has no Relinkra-managed rollback path. Nothing was changed.",),
        )
    root = Path(workspace_root) if workspace_root else None
    if root is not None:
        result.workspace_root = str(root.resolve())

    try:
        return _rollback_inner(spec, env, root, result)
    except Exception as exc:
        result.error = _sanitize(str(exc))
        return result


def _rollback_inner(
    spec: ConnectorSpec,
    env: DiscoveryEnvironment,
    root: Optional[Path],
    result: ApplyResult,
) -> ApplyResult:
    receipt = _load_receipt(root, spec.connector_id) if root is not None else None
    if receipt is not None and receipt.get(_INVALID_RECEIPT):
        return _refuse(
            result,
            "the machine receipt is malformed or unsupported; refusing to guess a target or backup.",
            ("Remove the stale receipt and restore the configuration by hand. Nothing was changed.",),
        )
    if receipt is not None:
        fingerprint = str(receipt.get("launch_fingerprint") or "")
        result.launch_fingerprint = fingerprint

    inspection = inspect_connector(spec, env)
    location = _preferred_location(spec, inspection)
    target: Optional[Path] = None
    # Discovery is authoritative.  A receipt can corroborate this target,
    # but it can never select an arbitrary path for rollback.
    if location is not None and location.path is not None:
        target = Path(str(location.path))
        result.config_path = location.display_hint
        result.real_config_path = str(target)
    if target is None:
        return _refuse(
            result,
            "no configuration target could be resolved for this host.",
            ("Nothing was changed.",),
        )
    result.discovered = inspection.discovery_status == DISCOVERY_DISCOVERED
    result.format_supported = spec.config_format == FORMAT_JSON
    container_path = inspection.container_path or container_path_for(
        spec, env.workspace_root
    )

    # Target confinement: a receipt may only point at one of this host's
    # known configuration locations. The receipt lives in a user-writable,
    # git-ignored directory, so its target is a CLAIM, not a fact —
    # adopting it blindly would let a stale or crafted receipt aim the
    # restore (and the created-by-apply unlink) at an arbitrary file.
    if receipt is not None:
        recorded_target = Path(str(receipt["target_path"]))
        if not _safe_receipt_path(recorded_target) or not _same_real_path(
            recorded_target, target
        ):
            return _refuse(
                result,
                "the machine receipt names a configuration target outside "
                "this host's known locations; refusing to touch it.",
                (
                    "Remove the stale receipt or restore by hand. "
                    "Nothing was changed.",
                ),
            )
        if receipt.get("workspace_root") != str(root.resolve() if root else ""):
            return _refuse(
                result,
                "the machine receipt belongs to another workspace; refusing rollback.",
                ("Use the connector from the workspace that created the receipt. Nothing was changed.",),
            )
        project_id = _project_id_for(root) if root is not None else ""
        if project_id and receipt.get("project_id") != project_id:
            return _refuse(
                result,
                "the machine receipt belongs to another project; refusing rollback.",
                ("Use the workspace that created the receipt. Nothing was changed.",),
            )

    # Backup selection is receipt-first. When a receipt exists, ONLY the
    # backup it names is acceptable: silently substituting the newest
    # sibling could restore bytes from a different, older apply. The
    # newest-sibling discovery fallback exists for exactly one case —
    # the receipt itself was never persisted (a degraded apply warned
    # about) — so "no receipt" is the only path that may guess.
    backup: Optional[Path] = None
    if receipt is not None:
        if receipt.get("backup_path"):
            recorded = Path(str(receipt["backup_path"]))
            expected_parent = target.parent.resolve()
            valid_name = _backup_index(target, recorded) >= 0
            if valid_name and not recorded.exists() and not recorded.is_symlink():
                return _refuse(
                    result,
                    "the machine receipt names a backup that no longer exists; refusing to guess which sibling backup belongs to this apply.",
                    ("Restore the configuration by hand from a trusted copy. Nothing was changed.",),
                )
            if (
                _safe_receipt_path(recorded)
                and
                valid_name
                and recorded.parent.resolve() == expected_parent
                and _regular_non_reparse_file(recorded)
            ):
                backup = recorded
            else:
                return _refuse(
                    result,
                    "the machine receipt names a backup outside the target's managed backup contract; refusing rollback.",
                    ("Restore from a trusted copy by hand. Nothing was changed.",),
                )
            if receipt.get("digest_before") is not None and receipt.get("backup_digest") is None:
                return _refuse(
                    result,
                    "the machine receipt has no backup digest; refusing rollback without provenance.",
                    (
                        "Restore the configuration by hand if you kept a "
                        "copy. Nothing was changed.",
                    ),
                )
    elif receipt is None:
        backup = _newest_backup(target)
    if backup is not None:
        result.backup_ref = backup.name
        result.real_backup_path = str(backup)

    created_by_apply = bool(receipt is not None and receipt.get("digest_before") is None)
    if backup is None and not created_by_apply:
        return _refuse(
            result,
            "no machine receipt and no backup file were found for this host, "
            "so there is nothing safe to restore from.",
            (
                "If you kept a copy of the pre-apply configuration, restore "
                "it by hand. Nothing was changed.",
            ),
        )

    try:
        assert_writable_target(target)
        current = read_bounded_text(target)
    except UnsafeTargetError as exc:
        return _refuse(
            result,
            f"the configuration target is not a plain writable file: {exc}",
            ("Restore the file by hand. Nothing was changed.",),
        )
    except (SafeWriteError, OSError) as exc:
        return _refuse(
            result,
            f"the current configuration could not be read: {_sanitize(str(exc))}",
            ("Restore the file by hand. Nothing was changed.",),
        )
    result.readable = True
    current_digest = digest_text(current)
    result.digest_before = current_digest

    recorded_after = ""
    if receipt is not None:
        recorded_after = str(receipt.get("digest_after") or "")
        if not recorded_after:
            # Fail closed: without the post-apply digest the external-edit
            # gate cannot run, and skipping it would convert the
            # strongest protection into a restore over a stranger's edits.
            return _refuse(
                result,
                "the machine receipt is incomplete (no post-apply digest); "
                "refusing to roll back against an unverifiable state.",
                (
                    "Restore the configuration by hand from the backup. "
                    "Nothing was changed.",
                ),
            )
        if current_digest != recorded_after:
            return _refuse(
                result,
                "the configuration was edited after Relinkra applied it; "
                "rolling back would overwrite those external edits.",
                (
                    f"Restore manually from the backup '{result.backup_ref or '(unknown)'}' "
                    "if you are certain, then re-run 'relinkra connect check'. "
                    "Nothing was changed.",
                ),
            )
    else:
        # Provenance gate: without a receipt, only a file that still
        # holds a structurally Relinkra-owned entry is eligible.
        try:
            document = parse_json_document(current)
        except ValueError as exc:
            return _refuse(
                result,
                f"the current configuration does not parse ({_sanitize(str(exc))}), "
                "so its provenance cannot be established.",
                ("Restore the file by hand. Nothing was changed.",),
            )
        container = _container(document, container_path)
        entry = (
            container.get(MANAGED_SERVER_NAME)
            if isinstance(container, Mapping)
            else None
        )
        if not (entry is not None and launches_relinkra(entry)):
            return _refuse(
                result,
                "the current configuration contains no Relinkra-managed "
                "entry, so there is nothing attributable to roll back.",
                ("Nothing was changed.",),
            )

    result.rollback_attempted = True

    restored_text: Optional[str] = None
    recorded_backup_digest = (
        str(receipt.get("backup_digest") or "") if receipt is not None else ""
    )
    if not created_by_apply:
        try:
            backup_bytes = backup.read_bytes()
            restored_text = backup_bytes.decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            result.error = _sanitize(str(exc))
            return result
        if recorded_backup_digest and digest_text(restored_text) != recorded_backup_digest:
            return _refuse(
                result,
                "the recorded backup does not match the receipt's backup "
                "digest; refusing to restore an unattributed backup.",
                (
                    "Restore the configuration by hand from a copy you "
                    "trust. Nothing was changed.",
                ),
            )

    try:
        mode: Optional[int] = os.stat(str(target)).st_mode & 0o777
    except OSError:
        mode = None

    # One lock for the whole verify-then-mutate sequence, with the digest
    # and safety gates RE-CHECKED inside it. The checks above are the
    # cheap early rejection; the host can rewrite its own state file at
    # any moment, and only the in-lock re-read proves the bytes about to
    # be replaced are still the bytes the gates approved.
    with interprocess_lock(str(target)):
        try:
            assert_writable_target(target)
            current_now = read_bounded_text(target)
        except UnsafeTargetError as exc:
            return _refuse(
                result,
                f"the configuration target became unsafe before the restore: {exc}",
                ("Restore the file by hand. Nothing was changed.",),
            )
        except (SafeWriteError, OSError) as exc:
            return _refuse(
                result,
                f"the current configuration could not be re-read: {_sanitize(str(exc))}",
                ("Restore the file by hand. Nothing was changed.",),
            )
        if receipt is not None and digest_text(current_now) != recorded_after:
            return _refuse(
                result,
                "the configuration was edited after Relinkra applied it; "
                "rolling back would overwrite those external edits.",
                (
                    f"Restore manually from the backup '{result.backup_ref or '(unknown)'}' "
                    "if you are certain, then re-run 'relinkra connect check'. "
                    "Nothing was changed.",
                ),
            )
        if receipt is None:
            # The provenance gate is re-run on the in-lock bytes too.
            try:
                document_now = parse_json_document(current_now)
            except ValueError:
                return _refuse(
                    result,
                    "the current configuration no longer parses, so its "
                    "provenance cannot be re-established.",
                    ("Restore the file by hand. Nothing was changed.",),
                )
            container_now = _container(document_now, container_path)
            entry_now = (
                container_now.get(MANAGED_SERVER_NAME)
                if isinstance(container_now, Mapping)
                else None
            )
            if not (entry_now is not None and launches_relinkra(entry_now)):
                return _refuse(
                    result,
                    "the Relinkra-managed entry disappeared before the "
                    "restore; there is nothing attributable to roll back.",
                    ("Nothing was changed.",),
                )

        # Re-read and re-authenticate the backup while the target lock is
        # held.  The pre-lock read is only an early refusal; using those
        # bytes after an external backup edit would restore stale or forged
        # content even though the target itself passed its digest gate.
        if not created_by_apply:
            if backup is None or not _regular_non_reparse_file(backup):
                return _refuse(
                    result,
                    "the managed backup became unavailable or unsafe before restore; refusing rollback.",
                    ("Restore the configuration by hand. Nothing was changed.",),
                )
            try:
                restored_text = backup.read_bytes().decode("utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                return _refuse(
                    result,
                    f"the managed backup could not be read before restore: {_sanitize(str(exc))}",
                    ("Restore the configuration by hand. Nothing was changed.",),
                )
            if recorded_backup_digest and digest_text(restored_text) != recorded_backup_digest:
                return _refuse(
                    result,
                    "the managed backup changed before restore; refusing rollback.",
                    ("Restore from a trusted copy by hand. Nothing was changed.",),
                )

        if created_by_apply:
            # The pre-apply state is ABSENT: Relinkra created the file, so
            # the honest restore removes exactly the file it created.
            try:
                os.unlink(str(target))
            except OSError as exc:
                result.error = _sanitize(str(exc))
                return result
            result.rollback_succeeded = True
            result.validation_succeeded = not target.exists()
            result.registration_present = False
            result.actions = (
                f"Run 'relinkra connect check {spec.connector_id}' to confirm "
                "the configuration side.",
            )
            return result

        try:
            atomic_write_text(target, restored_text, mode=mode)
            written = read_bounded_text(target)
            validate_json_text(written)
        except (SafeWriteError, OSError, ValueError) as exc:
            result.error = _sanitize(str(exc))
            return result

    restored_digest = digest_text(written)
    result.digest_after = restored_digest
    result.backup_digest = recorded_backup_digest or digest_text(restored_text)

    # Cross-check the restore against the recorded pre-apply state. A
    # mismatch means the restored bytes are NOT what the apply saw, and
    # that is a failed restore, never a success with a caveat.
    recorded_before = receipt.get("digest_before") if receipt else None
    if recorded_before and restored_digest != recorded_before:
        result.rollback_succeeded = False
        result.error = (
            "the restored content does not match the recorded pre-apply "
            "digest; the file was left in the restored state — inspect it "
            "before re-applying or rolling back again"
        )
        return result

    result.rollback_succeeded = True
    result.validation_succeeded = True

    container = _container(parse_json_document(written), container_path)
    entry = (
        container.get(MANAGED_SERVER_NAME) if isinstance(container, Mapping) else None
    )
    result.registration_present = entry is not None
    result.registration_managed = bool(entry is not None and launches_relinkra(entry))
    result.registration_matches_expected = False
    result.actions = (
        f"Run 'relinkra connect check {spec.connector_id}' to confirm the "
        "configuration side after the restore.",
    )
    return result


__all__ = [
    "CLASS_CBM",
    "CLASS_FOREIGN",
    "CLASS_RELINKRA",
    "ENTRY_CLASSES",
    "RECEIPT_DIRNAME",
    "RECEIPT_VERSION",
    "STAGE_CONFIG_APPLIED_HOST_UNVERIFIED",
    "ApplyResult",
    "apply_connector",
    "classify_server_entry",
    "entries_equivalent",
    "launch_fingerprint",
    "rollback_connector",
]
