"""``relinkra connect`` — the connector CLI surface (R4B).

Five read-only commands:

    connect list             known connectors and their honest state
    connect inspect <agent>  read-only discovery of one host
    connect plan <agent>     deterministic mutation plan, writes nothing
    connect check <agent>    validate an existing registration
    connect generic          emit the host-neutral MCP launch contract

There is deliberately NO apply command. Every safety primitive it would
need exists and is tested (``safe_write``, ``config_merge``), but a plan
proves a file could be edited and proves nothing about a host then
successfully launching the server. Until that has happened against a real
host, writing to a developer's live configuration would be asserting
something Relinkra has not earned.

Exit codes extend the R4A contract unchanged:

    0  the command ran and the outcome is good
    1  the command itself failed (unknown connector, not a repository)
    2  the command ran, but the outcome needs a human decision
       (a conflict, an unavailable plan, an invalid registration)

Portability is enforced rather than intended: every payload rendered
without ``--reveal-paths`` is audited for machine-local paths immediately
before printing, and a leak fails the command instead of reaching the
user's terminal.
"""

from __future__ import annotations

import json
import sys
from typing import Any, List, Optional, Tuple

from .backend_detection import assess_workspace
from .backend_policy import agent_instruction_document
from .connect_render import (
    render_check,
    render_generic,
    render_inspect,
    render_list,
    render_plan,
    render_routing,
)
from .connector import (
    PLAN_READY,
    ConnectorReport,
    UnknownConnectorError,
    iter_strings,
)
from .connectors import (
    CONNECTORS,
    build_plan,
    build_report,
    check_registration,
    inspect_connector,
    launch_contract_document,
    resolve_connector,
    resolve_launch,
)
from .handoff import contains_absolute_path
from .host_discovery import DiscoveryEnvironment
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


def _launch_for(root) -> Any:
    return resolve_launch(root, registry_path(root) if root else None)


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
        # Planned here too, not only in `connect plan`: without it the
        # "registration planned" capability could never be true and the
        # column would be decorative. Planning is free — the config was
        # already read for the inspection.
        plan = build_plan(spec, inspection, launch) if launch else None
        reports.append(build_report(spec, inspection, launch, plan))

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
    launch = _launch_for(root) if root is not None else None
    inspection = inspect_connector(spec, env)
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

    launch = _launch_for(root)
    inspection = inspect_connector(spec, env)
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


def cmd_check(args) -> int:
    """Validate an existing registration without modifying it."""
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

    launch = _launch_for(root)
    inspection = inspect_connector(spec, env)
    result = check_registration(spec, inspection, launch)

    code = _emit(
        result.to_dict(),
        render_check(result),
        as_json=args.json,
        allow_paths=False,
    )
    if code != EXIT_OK:
        return code
    return EXIT_OK if result.valid else EXIT_ACTION_REQUIRED


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
        command.set_defaults(func=handler)


def main(argv: Optional[List[str]] = None) -> int:
    """Standalone entry point, used by tests and ``python -m``."""
    from .product_cli import main as product_main

    return product_main(["connect", *(argv or [])])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
