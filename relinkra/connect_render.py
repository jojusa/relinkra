"""Human-readable rendering for ``relinkra connect`` (R4B).

Separated from ``connect_cli`` so that control flow (which command, which
exit code) and presentation (what the terminal shows) can each be read on
their own. Every function here is pure: it takes already-computed report
objects and returns a string. Nothing renders anything it had to go and
fetch.

Machine-local values appear only when ``reveal`` is true. The caller
audits the result before printing either way, so a mistake here fails the
command rather than reaching the user.
"""

from __future__ import annotations

from typing import List, Sequence

from .backend_policy import (
    AGENT_INSTRUCTIONS,
    STAGE_NOT_PROVEN,
    STAGE_PROVEN,
    STAGE_UNVERIFIED,
)
from .connector import (
    MANAGED_SERVER_NAME,
    PLAN_READY,
    CapabilityMatrix,
    ConnectorPlan,
    ConnectorReport,
    LaunchContract,
)
from .product_cli import _aligned

_CAPABILITY_LABELS = (
    ("implementation_exists", "connector implementation exists"),
    ("configuration_format_verified", "configuration format verified"),
    ("registration_detected", "registration detected"),
    ("registration_planned", "registration planned"),
    ("configuration_validated", "configuration validated"),
    ("mcp_process_contract_validated", "MCP process contract validated"),
    ("real_host_launch_proven", "real host launch proven"),
)


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _bullets(title: str, items: Sequence[str]) -> List[str]:
    if not items:
        return []
    return [title, *[f"  - {item}" for item in items], ""]


def render_list(reports: Sequence[ConnectorReport]) -> str:
    """One row per connector, plus the honesty footer.

    The footer is not decoration. A table of "supported" connectors reads
    as "these work", and none of them has been proven against a live host
    yet — so the table says so directly rather than letting the reader
    infer it.
    """
    header = ("ID", "HOST", "SUPPORT", "DISCOVERY", "REGISTRATION", "PROVEN")
    rows = [header]
    for report in reports:
        rows.append(
            (
                report.connector_id,
                report.host_type,
                report.support_status,
                report.discovery_status,
                report.registration_state,
                _yes_no(report.capabilities.real_host_launch_proven),
            )
        )
    widths = [
        max(len(str(row[index])) for row in rows) + 2 for index in range(len(header))
    ]
    lines = ["", "Relinkra connectors", ""]
    for row in rows:
        lines.append(
            "".join(str(cell).ljust(width) for cell, width in zip(row, widths)).rstrip()
        )
    lines.append("")
    proven = [r for r in reports if r.capabilities.real_host_launch_proven]
    if len(proven) < len(reports):
        lines.append(
            "PROVEN means a real host has launched the Relinkra MCP server."
        )
        lines.append(
            "No connector has been proven yet, so treat every row as a plan, "
            "not a guarantee."
            if not proven
            else "Unproven rows are plans, not guarantees."
        )
        lines.append("")
    lines.append("Next: 'relinkra connect inspect <agent>' or 'connect generic'.")
    return "\n".join(lines)


def _render_capabilities(capabilities: CapabilityMatrix) -> List[str]:
    lines = ["Capabilities"]
    data = capabilities.to_dict()
    width = max(len(label) for _, label in _CAPABILITY_LABELS) + 2
    for key, label in _CAPABILITY_LABELS:
        lines.append(f"  {label:<{width}}{_yes_no(bool(data[key]))}")
    lines.append("")
    return lines


def render_inspect(spec, report: ConnectorReport, *, reveal: bool = False) -> str:
    lines = ["", f"{report.display_name} ({report.connector_id})", ""]
    rows = [
        ("Support", report.support_status),
        ("Discovery", report.discovery_status),
        ("Registration", report.registration_state),
        ("Executable", "found on PATH" if report.executable_found else "not on PATH"),
        ("Transport", report.transport),
    ]
    if report.aliases:
        rows.append(("Aliases", ", ".join(report.aliases)))
    if report.env_keys:
        rows.append(("Env keys", ", ".join(report.env_keys)))
    lines.extend(_aligned(rows))
    lines.append("")

    if report.locations:
        lines.append("Configuration locations")
        for location in report.locations:
            state = "present" if location.exists else "absent"
            if location.exists and not location.readable:
                state = "unreadable"
            active = " (active)" if location.location_id == report.active_location_id else ""
            shown = str(location.path) if reveal and location.path else location.display_hint
            lines.append(
                f"  {shown}  [{location.scope}, {location.classification}, "
                f"{state}]{active}"
            )
        if not reveal:
            lines.append(
                "  Paths shown as portable hints; --reveal-paths shows the "
                "resolved machine-local paths."
            )
        lines.append("")
    else:
        lines.append("This connector owns no host configuration file.")
        lines.append("")

    if getattr(spec, "format_evidence", ""):
        lines.append("Format evidence")
        lines.append(f"  {spec.format_evidence}")
        lines.append("")

    lines.extend(_render_capabilities(report.capabilities))
    lines.extend(
        _bullets("Warnings", [f"{w.code}: {w.message}" for w in report.warnings])
    )
    lines.extend(_bullets("Security", report.security_notes))
    if report.restart_instruction:
        lines.append("Restart")
        lines.append(f"  {report.restart_instruction}")
        lines.append("")
    return "\n".join(lines)


def render_plan(plan: ConnectorPlan) -> str:
    lines = ["", f"Plan — {plan.connector_id}", ""]
    rows = [
        ("Status", plan.status),
        ("Registration", plan.registration_state),
        ("Target", plan.target_ref or "(none)"),
        ("Idempotent", _yes_no(plan.idempotent)),
        ("Apply", "available" if plan.apply_available else "unavailable"),
    ]
    lines.extend(_aligned(rows))
    lines.append("")

    if plan.unavailable_reason:
        lines.append("Why apply is unavailable")
        lines.append(f"  {plan.unavailable_reason}")
        lines.append("")

    lines.extend(_bullets("Conflicts", plan.conflicts))

    if plan.operations:
        lines.append("Operations")
        for index, operation in enumerate(plan.operations, start=1):
            lines.append(f"  {index}. {operation.op}")
            if operation.detail:
                lines.append(f"     {operation.detail}")
            for precondition in operation.preconditions:
                lines.append(f"     pre:      {precondition}")
            for postcondition in operation.postconditions:
                lines.append(f"     post:     {postcondition}")
            if operation.rollback:
                lines.append(f"     rollback: {operation.rollback}")
        lines.append("")
    elif plan.status == PLAN_READY:
        lines.append("Nothing to do.")
        lines.append("")

    lines.extend(
        _bullets("Warnings", [f"{w.code}: {w.message}" for w in plan.warnings])
    )
    lines.append("This command wrote nothing. Planning is always read-only.")
    lines.append("")
    return "\n".join(lines)


def render_check(result) -> str:
    lines = ["", f"Check — {result.connector_id}", ""]
    matches = result.matches_workspace
    lines.extend(
        _aligned(
            [
                ("Registration", result.registration_state),
                ("Valid", _yes_no(result.valid)),
                ("Target", result.target_ref or "(none)"),
                (
                    "Workspace",
                    "unknown" if matches is None else ("matches" if matches else "differs"),
                ),
            ]
        )
    )
    lines.append("")
    lines.extend(_bullets("Findings", result.findings))
    lines.extend(
        _bullets("Warnings", [f"{w.code}: {w.message}" for w in result.warnings])
    )
    lines.append("This command wrote nothing.")
    lines.append("")
    return "\n".join(lines)


_STAGE_GLYPH = {
    STAGE_PROVEN: "proven",
    STAGE_NOT_PROVEN: "not proven",
    STAGE_UNVERIFIED: "unverified",
}


def render_routing(assessment) -> str:
    """The routing verdict, its evidence, and what to do about it.

    Ordered verdict-first. Someone running this command has one question
    — "is my agent actually going through Relinkra?" — and the answer is
    the first thing on the screen; the per-host detail below it exists to
    justify that answer, not to bury it.
    """
    lines = ["", "Relinkra context routing", ""]
    lines.extend(
        _aligned(
            [
                ("Context route", assessment.context_route),
                ("CBM ownership", assessment.cbm_ownership),
                ("Engram ownership", assessment.engram_ownership),
                ("Metrics trust", assessment.metrics_trust),
                ("Duplicate risk", assessment.duplicate_risk),
                ("Bypass detected", _yes_no(assessment.bypass_detected)),
            ]
        )
    )
    lines.append("")

    lines.append("Hosts")
    for host in assessment.hosts:
        detections = host.get("detections") or []
        summary = (
            ", ".join(
                f"{item['ref']} ({item['confidence']})" for item in detections
            )
            or "no MCP registrations found"
        )
        lines.append(f"  {host['connector_id']}  [{host['discovery_status']}]")
        lines.append(f"     {summary}")
        if host.get("naming") in ("legacy", "unverified"):
            lines.append(f"     naming: {host['naming']}")
    lines.append("")

    lines.append("Duplicate read/write risk")
    for finding in assessment.duplicate_findings:
        lines.append(
            f"  {finding.kind}: {finding.risk} ({finding.observability})"
        )
        if finding.detail:
            lines.append(f"     {finding.detail}")
    lines.append("")

    lines.append("Integration trust")
    for stage in assessment.ladder.stages:
        lines.append(f"  {stage.stage:<34}{_STAGE_GLYPH[stage.state]}")
        if stage.evidence:
            lines.append(f"     {stage.evidence}")
    lines.append("")

    lines.extend(_bullets("Notes", list(assessment.notes)))
    lines.extend(_bullets("Suggested action", list(assessment.remediation)))
    lines.append("Agent instruction contract (not written to any host)")
    lines.extend(f"  {item.text}" for item in AGENT_INSTRUCTIONS)
    lines.append("")
    lines.append(
        "This command wrote nothing. No host configuration, MCP registration "
        "or backend was modified."
    )
    lines.append("")
    return "\n".join(lines)


def render_generic(launch: LaunchContract, *, reveal: bool = False) -> str:
    """The copyable launch contract.

    Without ``--reveal-paths`` the arity and order of the invocation are
    still visible — enough to check the contract is the shape you expect
    — while the interpreter location, the workspace root and every
    environment value stay off the screen.
    """
    view = launch.to_machine_dict() if reveal else launch.to_dict()
    lines = ["", "Relinkra generic MCP launch contract", ""]
    rows = [
        ("Server name", MANAGED_SERVER_NAME),
        ("Transport", view["transport"]),
        ("Distribution", view["distribution"]),
        ("Module", view["module"]),
        ("Resolved", _yes_no(bool(view["resolved"]))),
        ("Command", view["command"] or "(unresolved)"),
        ("Arguments", " ".join(view["args"]) if view["args"] else "(none)"),
    ]
    if reveal:
        env = view.get("env") or {}
        rows.append(
            (
                "Environment",
                ", ".join(f"{key}={value}" for key, value in sorted(env.items()))
                or "(none)",
            )
        )
    else:
        rows.append(
            ("Env keys", ", ".join(view["env_keys"]) if view["env_keys"] else "(none)")
        )
    lines.extend(_aligned(rows))
    lines.append("")
    lines.extend(_bullets("Warnings", list(view.get("warnings") or [])))
    if not reveal:
        lines.append(
            "Machine-local values are redacted. Run with --reveal-paths to "
            "emit the real command."
        )
        lines.append("")
    lines.append(
        "Register this as an stdio MCP server named "
        f"'{MANAGED_SERVER_NAME}' in your host, then restart the host."
    )
    lines.append("")
    return "\n".join(lines)
