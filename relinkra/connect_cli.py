"""``relinkra connect`` — the connector CLI surface (R4B + R4C.1B).

Read-only commands:

    connect list             known connectors and their honest state
    connect inspect <agent>  read-only discovery of one host
    connect plan <agent>     deterministic mutation plan, writes nothing
    connect check <agent>    validate an existing registration, plus the
                             persisted host-verification evidence
    connect generic          emit the host-neutral MCP launch contract
    connect routing          report backend ownership and context routing

Write commands (R4C.1B Claude Code, R4C.1C OpenCode):

    connect apply <agent>              execute the plan against the real
                                       host config (backup, atomic write,
                                       rollback on validation failure)
    connect rollback <agent>           restore the pre-apply configuration
                                       from its backup, digest-gated
    connect verify <agent> --proof F   record operator-supplied evidence
                                       that the real host launched and
                                       served Relinkra

An apply edits a file; it does not launch a host. Every write command
reports ``config_applied_host_unverified`` and points at ``check`` /
``verify`` for the host-side truth, and no output claims readiness from
a config file alone.

Exit codes extend the R4A contract unchanged:

    0  the command ran and the outcome is good
    1  the command itself failed (unknown connector, not a repository)
    2  the command ran, but the outcome needs a human decision
       (a conflict, an unavailable plan, an invalid registration, a
       refused apply or rollback, an invalid proof)

Portability is enforced rather than intended: every payload rendered
without ``--reveal-paths`` is audited for machine-local paths immediately
before printing, and a leak fails the command instead of reaching the
user's terminal.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, List, Optional, Tuple

from .backend_detection import assess_workspace
from .backend_policy import agent_instruction_document
from .config_merge import MergeError
from .connect_render import (
    render_apply,
    render_check,
    render_generic,
    render_inspect,
    render_list,
    render_plan,
    render_rollback,
    render_routing,
    render_verify,
)
from .connect_verification import (
    STATUS_ABSENT,
    STATUS_VALID,
    ProofError,
    assess_verification,
    build_proof_from_payload,
    parse_proof_json,
    record_verification,
)
from .connector import (
    PLAN_READY,
    ConnectorReport,
    ConnectorWarning,
    UnknownConnectorError,
    iter_strings,
)
from .connector_apply import (
    apply_connector,
    authoritative_scope_status,
    connector_safety_preflight,
    launch_fingerprint,
    legacy_scope_findings,
    preferred_connector_target_path,
    rollback_connector,
)
from .connectors import (
    CONNECTORS,
    build_plan,
    build_report,
    check_registration,
    inspect_connector,
    launch_contract_document,
    resolve_connector,
    resolve_host_launch,
    resolve_launch,
)
from .handoff import contains_absolute_path
from .host_discovery import DiscoveryEnvironment
from .safe_write import SafeWriteError, read_bounded_text
from .backend_policy import ROUTE_MANAGED
from .product_cli import (
    EXIT_ACTION_REQUIRED,
    EXIT_ERROR,
    EXIT_OK,
    WorkspaceConfig,
    _fail,
    _repo_root,
    registry_path,
)


def _emit(payload: Any, text: str, *, as_json: bool, allow_paths: bool) -> int:
    """Render one result, refusing to print a machine-local path.

    The audit runs over BOTH renderings, not just the JSON one — the
    human text is the form most people actually paste into an issue, so
    it is the more likely leak, not the less.

    Failing the command on a leak is deliberate. A warning would still
    have printed the path, and the whole point of the guarantee is that
    the user never has to check.
    """
    if not allow_paths:
        leaked = [
            item for item in iter_strings(payload) if contains_absolute_path(item)
        ]
        if contains_absolute_path(text):
            leaked.append(text)
        if leaked:
            _fail(
                f"refusing to print output: {len(leaked)} field(s) contain a "
                "machine-local path.",
                "This is a Relinkra bug — please report it.",
            )
            return EXIT_ERROR
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(text)
    return EXIT_OK


def _environment(args) -> Tuple[Optional[Any], Optional[DiscoveryEnvironment]]:
    """Resolve the workspace and build a discovery environment.

    A missing repository is not fatal for discovery — ``list`` and
    ``inspect`` describe user-scope host configs that exist regardless —
    so the root is returned as ``None`` and each command decides whether
    it can proceed without one.
    """
    root = _repo_root(getattr(args, "path", None))
    return root, DiscoveryEnvironment.current(workspace_root=root)


def _launch_for(root, connector_id: Optional[str] = None) -> Any:
    """Resolve the launch policy for one connector.

    The generic contract remains pinned for compatibility. Host-specific
    connectors opt into the approved binding policy: OpenCode/Codex are
    bare global entries, while ZCode carries the workspace-local cwd.
    """
    if connector_id:
        return resolve_host_launch(
            connector_id,
            root,
            registry_path(root) if root else None,
        )
    return resolve_launch(root, registry_path(root) if root else None)


def _add_generated_state_guidance(spec, root, inspection) -> None:
    """Report ZCode generated-state ownership without changing Git/files."""
    if spec.connector_id != "zcode" or root is None:
        return
    lock = Path(root) / ".zcode" / "config.json.lock"
    if lock.exists():
        inspection.warn(
            "zcode_lock_present",
            "ZCode's workspace-local config lock is present; it is host-owned "
            "generated state. Relinkra will not delete it or edit .gitignore.",
        )
    config = Path(root) / ".zcode" / "config.json"
    if config.exists():
        inspection.warn(
            "zcode_workspace_state",
            "ZCode configuration is workspace-local generated state. Review "
            "Git ownership/ignore policy yourself; Relinkra does not silently "
            "edit .gitignore.",
        )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_list(args) -> int:
    """Every registered connector and what is actually proven about it."""
    root, env = _environment(args)
    launch = _launch_for(root) if root is not None else None

    reports: List[ConnectorReport] = []
    for spec in CONNECTORS:
        inspection = inspect_connector(spec, env)
        _add_generated_state_guidance(spec, root, inspection)
        # Planned here too, not only in `connect plan`: without it the
        # "registration planned" capability could never be true and the
        # column would be decorative. Planning is free — the config was
        # already read for the inspection.
        spec_launch = (
            _launch_for(root, spec.connector_id) if root is not None else None
        )
        plan = build_plan(spec, inspection, spec_launch) if spec_launch else None
        reports.append(build_report(spec, inspection, spec_launch, plan))

    payload = {
        "connectors": [report.to_dict() for report in reports],
        "real_host_launch_proven": any(
            report.capabilities.real_host_launch_proven for report in reports
        ),
    }
    return _emit(
        payload, render_list(reports), as_json=args.json, allow_paths=False
    )


def cmd_inspect(args) -> int:
    """Read-only discovery for one host. Changes nothing, ever."""
    try:
        spec = resolve_connector(args.agent)
    except UnknownConnectorError as exc:
        _fail(str(exc), "Run 'relinkra connect list' to see known connectors.")
        return EXIT_ERROR

    root, env = _environment(args)
    launch = (
        _launch_for(root, spec.connector_id) if root is not None else None
    )
    inspection = inspect_connector(spec, env)
    _add_generated_state_guidance(spec, root, inspection)
    plan = build_plan(spec, inspection, launch) if launch else None
    report = build_report(spec, inspection, launch, plan)

    reveal = bool(getattr(args, "reveal_paths", False))
    payload = report.to_dict()
    payload["format_evidence"] = spec.format_evidence
    if reveal:
        payload["locations"] = [loc.to_machine_dict() for loc in report.locations]
    return _emit(
        payload,
        render_inspect(spec, report, reveal=reveal),
        as_json=args.json,
        allow_paths=reveal,
    )


def cmd_plan(args) -> int:
    """Build a deterministic mutation plan. Touches no file.

    ``--dry-run`` is accepted and reported so a script can pass it
    uniformly, but it changes nothing: planning is already the read-only
    half of the lifecycle, and pretending the flag matters here would
    imply that omitting it writes something.
    """
    try:
        spec = resolve_connector(args.agent)
    except UnknownConnectorError as exc:
        _fail(str(exc), "Run 'relinkra connect list' to see known connectors.")
        return EXIT_ERROR

    root, env = _environment(args)
    if root is None:
        _fail(
            "Not inside a git repository.",
            "Run 'relinkra connect plan' from inside a git repository.",
        )
        return EXIT_ERROR

    launch = _launch_for(root, spec.connector_id)
    inspection = inspect_connector(spec, env)
    _add_generated_state_guidance(spec, root, inspection)
    plan = build_plan(spec, inspection, launch)

    payload = plan.to_dict()
    payload["dry_run"] = True
    code = _emit(
        payload, render_plan(plan), as_json=args.json, allow_paths=False
    )
    if code != EXIT_OK:
        return code
    if plan.status == PLAN_READY and not plan.conflicts:
        return EXIT_OK
    # A blocked or unavailable plan ran fine; it is the OUTCOME that
    # needs a person, which is exactly what exit 2 means here.
    return EXIT_ACTION_REQUIRED


def cmd_connect(args) -> int:
    """Safe normal-user front door for one host connector.

    It reuses inspect -> plan -> apply.  A valid registration is an
    immediate no-op; every write requires an explicit confirmation and the
    existing apply engine remains responsible for backup, validation,
    rollback, and restart guidance.
    """
    try:
        spec = resolve_connector(args.frontdoor_agent)
    except UnknownConnectorError as exc:
        _fail(str(exc), "Run 'relinkra connect list' to see known connectors.")
        return EXIT_ERROR

    root, env = _environment(args)
    if root is None:
        _fail(
            "Not inside a git repository.",
            "Run 'relinkra connect <agent>' from inside a git repository.",
        )
        return EXIT_ERROR

    launch = _launch_for(root, spec.connector_id)
    inspection = inspect_connector(spec, env)
    _add_generated_state_guidance(spec, root, inspection)
    plan = build_plan(spec, inspection, launch)
    if plan.status != PLAN_READY:
        payload = plan.to_dict()
        payload["front_door"] = True
        return _emit(
            payload,
            render_plan(plan),
            as_json=args.json,
            allow_paths=False,
        ) or EXIT_ACTION_REQUIRED

    preflight = connector_safety_preflight(
        spec,
        launch,
        env,
        inspection=inspection,
        plan=plan,
    )
    for message in preflight.legacy_warnings:
        plan.warnings.append(ConnectorWarning("legacy_scope", message))
    if preflight.refused:
        if any(
            warning.startswith("direct_cbm_exposure:")
            for warning in preflight.warnings
        ):
            plan.warnings.append(
                ConnectorWarning(
                    "direct_cbm_exposure",
                    "the configuration registers the codebase-memory backend "
                    "directly, beside the entry Relinkra would manage.",
                )
            )
        payload = plan.to_dict()
        payload.update(
            {
                "front_door": True,
                "safety_refusal": True,
                "refusal_reason": preflight.refusal_reason,
                "actions": list(preflight.actions),
            }
        )
        code = _emit(
            payload,
            render_plan(plan)
            + "\nAction required: "
            + preflight.refusal_reason
            + ("\n" + "\n".join(preflight.actions) if preflight.actions else ""),
            as_json=args.json,
            allow_paths=False,
        )
        return EXIT_ACTION_REQUIRED if code == EXIT_OK else code

    if plan.idempotent and preflight.no_op_verified:
        payload = plan.to_dict()
        payload["front_door"] = True
        payload["no_op"] = True
        return _emit(
            payload,
            render_plan(plan),
            as_json=args.json,
            allow_paths=False,
        )

    prompt = (
        f"Relinkra will update the {spec.display_name} configuration after "
        "the existing inspect/plan checks."
    )
    if args.json:
        print(prompt, file=sys.stderr)
    else:
        print(prompt)
    try:
        answer = input("" if args.json else "Continue and write the configuration? [y/N] ")
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer.strip().lower() not in {"y", "yes"}:
        payload = plan.to_dict()
        payload.update({"front_door": True, "confirmation": "declined"})
        return _emit(
            payload,
            render_plan(plan) + "\nConfirmation declined; no file was changed.",
            as_json=args.json,
            allow_paths=False,
        ) or EXIT_ACTION_REQUIRED

    result = apply_connector(
        spec, launch, env, inspection=inspection, plan=plan
    )
    payload = result.to_machine_dict() if getattr(args, "reveal_paths", False) else result.to_dict()
    payload["front_door"] = True
    code = _emit(
        payload,
        render_apply(result, reveal=bool(getattr(args, "reveal_paths", False))),
        as_json=args.json,
        allow_paths=bool(getattr(args, "reveal_paths", False)),
    )
    if code != EXIT_OK:
        return code
    return _write_exit_code(result)


def _verification_section(root, host: str, fingerprint: str) -> dict:
    """The persisted host-evidence view for ``check``.

    Read-only and portable: statuses, stage booleans and tool names —
    never paths, never conversation text.
    """
    try:
        status, record, reasons = assess_verification(root, host, fingerprint)
    except Exception:
        # A corrupt or undecodable evidence store must never crash
        # ``check``: the honest state is "evidence unavailable", which is
        # reported exactly like absent evidence, with the reason named.
        status, record = STATUS_ABSENT, None
        reasons = (
            "the host evidence store could not be assessed; treating the "
            "evidence as absent.",
        )
    locally_verified = bool(
        status == STATUS_VALID
        and record is not None
        and record.stages
        and all(record.stages.values())
        and record.handoff_ok
    )
    return {
        "status": status,
        "reasons": list(reasons),
        "record": record.to_dict() if record is not None else None,
        # A writable local file is useful operational evidence, but it is
        # never an independent attestation of another process.  Keep the
        # old field for JSON compatibility while making its meaning honest.
        "evidence_class": "local_operational" if status == STATUS_VALID else "none",
        "locally_verified": locally_verified,
        "currently_revalidated": False,
        "independently_attested": False,
        "fully_verified": False,
    }


def _apply_capable_host_ids() -> Tuple[str, ...]:
    """Connectors with an open write path, from the registry — never a
    hardcoded list, so a newly opened connector appears everywhere the
    per-host evidence view is rendered."""
    return tuple(spec.connector_id for spec in CONNECTORS if spec.apply_available)


def cmd_check(args) -> int:
    """Validate an existing registration without modifying it.

    Also reports the persisted host-verification evidence, honestly:
    config-side validity decides the exit code, and the host side is a
    reported state (absent/stale/expired/valid), never an inference from
    file existence. Every apply-capable host gets its own row; they are
    never collapsed into one boolean.
    """
    try:
        spec = resolve_connector(args.agent)
    except UnknownConnectorError as exc:
        _fail(str(exc), "Run 'relinkra connect list' to see known connectors.")
        return EXIT_ERROR

    root, env = _environment(args)
    if root is None:
        _fail(
            "Not inside a git repository.",
            "Run 'relinkra connect check' from inside a git repository.",
        )
        return EXIT_ERROR

    launch = _launch_for(root, spec.connector_id)
    inspection = inspect_connector(spec, env)
    _add_generated_state_guidance(spec, root, inspection)
    unreadable_scope_finding, shadow_hints = authoritative_scope_status(
        spec,
        env,
        target_path=preferred_connector_target_path(spec, inspection),
    )
    result = check_registration(
        spec,
        inspection,
        launch,
        shadow_hints=shadow_hints,
        authoritative_scope_finding=unreadable_scope_finding or "",
        legacy_scope_findings=legacy_scope_findings(spec, env),
    )
    fingerprint = launch_fingerprint(launch)
    verification = _verification_section(root, spec.connector_id, fingerprint)
    host_verification = {
        host_id: _verification_section(root, host_id, fingerprint)
        for host_id in _apply_capable_host_ids()
    }

    payload = result.to_dict()
    payload["verification"] = verification
    payload["host_verification_sections"] = host_verification
    code = _emit(
        payload,
        render_check(
            result,
            verification=verification,
            host_verification_sections=host_verification,
        ),
        as_json=args.json,
        allow_paths=False,
    )
    if code != EXIT_OK:
        return code
    return EXIT_OK if result.valid else EXIT_ACTION_REQUIRED


def _write_exit_code(result) -> int:
    """Map an ApplyResult onto the exit-code contract.

    A refusal ran fine and needs a person (2); an unexpected error is a
    command failure (1); success — including an honest no-op — is 0.
    """
    if result.refused:
        return EXIT_ACTION_REQUIRED
    if result.error:
        return EXIT_ERROR
    return EXIT_OK


def cmd_apply(args) -> int:
    """Execute the connector's plan against its real host configuration.

    The output states what was inspected, whether a change was required,
    whether a backup exists, that the host must be restarted, and that
    real host verification has NOT occurred — in those words, because
    a written file is precisely the evidence people over-read.
    """
    try:
        spec = resolve_connector(args.agent)
    except UnknownConnectorError as exc:
        _fail(str(exc), "Run 'relinkra connect list' to see known connectors.")
        return EXIT_ERROR

    root, env = _environment(args)
    if root is None:
        _fail(
            "Not inside a git repository.",
            "Run 'relinkra connect apply' from inside a git repository.",
        )
        return EXIT_ERROR

    launch = _launch_for(root, spec.connector_id)
    result = apply_connector(spec, launch, env)

    reveal = bool(getattr(args, "reveal_paths", False))
    payload = result.to_machine_dict() if reveal else result.to_dict()
    code = _emit(
        payload,
        render_apply(result, reveal=reveal),
        as_json=args.json,
        allow_paths=reveal,
    )
    if code != EXIT_OK:
        return code
    return _write_exit_code(result)


def cmd_rollback(args) -> int:
    """Restore the pre-apply configuration from its backup.

    Digest-gated: a file edited after the apply is never overwritten,
    and the refusal says so with the manual recovery path.
    """
    try:
        spec = resolve_connector(args.agent)
    except UnknownConnectorError as exc:
        _fail(str(exc), "Run 'relinkra connect list' to see known connectors.")
        return EXIT_ERROR

    root, env = _environment(args)
    if root is None:
        _fail(
            "Not inside a git repository.",
            "Run 'relinkra connect rollback' from inside a git repository.",
        )
        return EXIT_ERROR

    result = rollback_connector(spec, env, workspace_root=root)

    reveal = bool(getattr(args, "reveal_paths", False))
    payload = result.to_machine_dict() if reveal else result.to_dict()
    code = _emit(
        payload,
        render_rollback(result, reveal=reveal),
        as_json=args.json,
        allow_paths=reveal,
    )
    if code != EXIT_OK:
        return code
    return _write_exit_code(result)


def cmd_verify(args) -> int:
    """Record operator-supplied proof that the real host served Relinkra.

    The proof is machine-readable JSON produced from the real host. It
    is validated whole — unknown hosts, malformed shapes, absolute
    paths and credential-shaped keys are all refused — then persisted
    as the single latest record, pinned to the CURRENT launch-contract
    fingerprint so a contract change invalidates it automatically.
    """
    try:
        spec = resolve_connector(args.agent)
    except UnknownConnectorError as exc:
        _fail(str(exc), "Run 'relinkra connect list' to see known connectors.")
        return EXIT_ERROR

    root, env = _environment(args)
    if root is None:
        _fail(
            "Not inside a git repository.",
            "Run 'relinkra connect verify' from inside a git repository.",
        )
        return EXIT_ERROR
    del env  # verification reads the workspace evidence store, not hosts

    proof_arg = getattr(args, "proof", None)
    if not proof_arg:
        _fail(
            "Missing --proof <file>.",
            "Produce a proof JSON from the real host and pass it with --proof.",
        )
        return EXIT_ERROR

    try:
        # Same discipline as every config this tool reads: bounded size,
        # BOM tolerated, adversarial nesting converted into a refusal
        # instead of a RecursionError traceback.
        payload = parse_proof_json(
            read_bounded_text(proof_arg, max_bytes=64 * 1024)
        )
    except (OSError, SafeWriteError, MergeError, ProofError, ValueError) as exc:
        _fail(
            f"the proof file could not be read: {exc.__class__.__name__}",
            "Supply a readable JSON file produced by the real host.",
        )
        return EXIT_ACTION_REQUIRED

    launch = _launch_for(root, spec.connector_id)
    try:
        record = build_proof_from_payload(
            spec.connector_id,
            payload,
            root=root,
            fingerprint=launch_fingerprint(launch),
        )
    except ProofError as exc:
        _fail(
            "the proof was rejected: " + "; ".join(exc.reasons),
            "Fix the proof payload and re-run 'relinkra connect verify'.",
        )
        return EXIT_ACTION_REQUIRED
    except RecursionError:
        _fail(
            "the proof was rejected: nesting too deep to process safely.",
            "Fix the proof payload and re-run 'relinkra connect verify'.",
        )
        return EXIT_ACTION_REQUIRED

    try:
        record_verification(root, record)
    except ProofError as exc:
        _fail(
            "the proof was rejected during persistence: " + "; ".join(exc.reasons),
            "Fix the proof payload and re-run 'relinkra connect verify'.",
        )
        return EXIT_ACTION_REQUIRED
    except (OSError, SafeWriteError) as exc:
        _fail(
            f"the verification record could not be persisted ({exc.__class__.__name__}).",
            "Check that .relinkra/ is writable.",
        )
        return EXIT_ERROR

    rendered = render_verify(record, payload)
    code = _emit(
        record.to_dict(), rendered, as_json=args.json, allow_paths=False
    )
    return code


def cmd_routing(args) -> int:
    """Report how project context actually reaches an agent. Read-only.

    Surveys every host configuration on this machine, classifies each MCP
    registration by what it LAUNCHES, and renders the routing verdict. It
    inspects; it never registers, disables, migrates or deletes anything,
    including the servers it recognises as competing with Relinkra.

    Deliberately CONFIGURATION-ONLY: no backend is probed and no process
    is spawned, so the command stays fast and provably read-only. That
    costs one distinction — a Gentleman-marked Engram registration cannot
    be reported as ``shared_separated`` without knowing the backend is
    reachable — and ``relinkra doctor``, which does probe, is where the
    fuller picture belongs.

    Exit 2 when the route is anything other than managed — the command
    ran fine, and the outcome needs a person.
    """
    root, env = _environment(args)
    if root is None:
        _fail(
            "Not inside a git repository.",
            "Run 'relinkra connect routing' from inside a git repository.",
        )
        return EXIT_ERROR

    launch = _launch_for(root)
    config = WorkspaceConfig.load(root)

    try:
        assessment = assess_workspace(
            env,
            health=None,
            launch_resolved=bool(launch.resolved),
            advanced_cbm_allowed=bool(
                config is not None and config.advanced_direct_cbm
            ),
            verification_fingerprint=launch_fingerprint(launch),
        )
    except Exception as exc:
        # Same guard ``doctor`` has, for the same reason. This command
        # exists to describe a machine whose wiring may be broken, so
        # failing to survey it is a result to report — with the honest
        # unverified defaults — not a traceback.
        _fail(
            f"Could not assess context routing: {exc}",
            "Run 'relinkra connect inspect <agent>' to narrow it down.",
        )
        return EXIT_ERROR

    payload = assessment.to_dict()
    payload["agent_instructions"] = agent_instruction_document()

    code = _emit(
        payload, render_routing(assessment), as_json=args.json, allow_paths=False
    )
    if code != EXIT_OK:
        return code
    return EXIT_OK if assessment.context_route == ROUTE_MANAGED else EXIT_ACTION_REQUIRED


def cmd_generic(args) -> int:
    """Emit the host-neutral stdio launch contract."""
    root, _ = _environment(args)
    if root is None:
        _fail(
            "Not inside a git repository.",
            "Run 'relinkra connect generic' from inside a git repository.",
        )
        return EXIT_ERROR

    launch = _launch_for(root)
    reveal = bool(getattr(args, "reveal_paths", False))
    payload = launch_contract_document(launch)
    if reveal:
        payload["machine_local"] = launch.to_machine_dict()
        payload["classification"] = "machine_local"

    code = _emit(
        payload,
        render_generic(launch, reveal=reveal),
        as_json=args.json,
        allow_paths=reveal,
    )
    if code != EXIT_OK:
        return code
    return EXIT_OK if launch.resolved else EXIT_ACTION_REQUIRED


# ---------------------------------------------------------------------------
# Parser wiring
# ---------------------------------------------------------------------------

#: (name, handler, help, takes_agent, extra_flags)
_COMMANDS = (
    ("list", cmd_list, "list known connectors and their proven state", False, ()),
    ("inspect", cmd_inspect, "read-only discovery for one host", True, ("reveal",)),
    ("plan", cmd_plan, "show a deterministic mutation plan", True, ("dry-run",)),
    ("check", cmd_check, "validate an existing registration", True, ()),
    (
        "routing",
        cmd_routing,
        "report backend ownership, context routing and metrics trust",
        False,
        (),
    ),
    ("generic", cmd_generic, "emit the generic MCP launch contract", False, ("reveal",)),
    (
        "apply",
        cmd_apply,
        "apply the connector plan to the real host config (writes)",
        True,
        ("reveal",),
    ),
    (
        "rollback",
        cmd_rollback,
        "restore the pre-apply host configuration from its backup",
        True,
        ("reveal",),
    ),
    (
        "verify",
        cmd_verify,
        "record operator proof that the real host served Relinkra",
        True,
        ("proof",),
    ),
)


def register(subparsers) -> None:
    """Attach the ``connect`` command group to the product CLI parser."""
    connect = subparsers.add_parser(
        "connect", help="connect an agent host to this workspace"
    )
    nested = connect.add_subparsers(dest="connect_command", required=True)
    for name, handler, help_text, takes_agent, extras in _COMMANDS:
        command = nested.add_parser(name, help=help_text)
        if takes_agent:
            command.add_argument(
                "agent", help="connector id or alias (see 'connect list')"
            )
        command.add_argument(
            "--path",
            default=None,
            help="workspace directory (defaults to the current directory)",
        )
        command.add_argument(
            "--json", action="store_true", help="emit machine-readable JSON"
        )
        if "reveal" in extras:
            command.add_argument(
                "--reveal-paths",
                action="store_true",
                help="include machine-local paths and environment values",
            )
        if "dry-run" in extras:
            command.add_argument(
                "--dry-run",
                action="store_true",
                help="accepted for symmetry; planning never writes",
            )
        if "proof" in extras:
            command.add_argument(
                "--proof",
                default=None,
                help="path to the operator proof JSON produced by the real host",
            )
        command.set_defaults(func=handler)

    # Normal-user front door.  These are deliberately separate nested
    # commands so the established advanced command grammar is unchanged.
    for agent in ("codex", "opencode", "claude", "devin-desktop", "zcode"):
        command = nested.add_parser(
            agent,
            help=f"safely connect {agent} (inspect, plan, confirm, apply)",
        )
        command.add_argument(
            "--path",
            default=None,
            help="workspace directory (defaults to the current directory)",
        )
        command.add_argument(
            "--json", action="store_true", help="emit machine-readable JSON"
        )
        command.add_argument(
            "--reveal-paths",
            action="store_true",
            help="include machine-local paths and environment values",
        )
        command.set_defaults(func=cmd_connect, frontdoor_agent=agent)


def main(argv: Optional[List[str]] = None) -> int:
    """Standalone entry point, used by tests and ``python -m``."""
    from .product_cli import main as product_main

    return product_main(["connect", *(argv or [])])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
