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


def render_check(result, verification=None, host_verification_sections=None) -> str:
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
    if verification is not None:
        lines.extend(_render_verification(verification))
    if host_verification_sections:
        lines.extend(_render_host_verification(host_verification_sections))
    lines.append("This command wrote nothing.")
    lines.append("")
    return "\n".join(lines)


def _render_host_verification(host_verification) -> List[str]:
    """One row per apply-capable host, each with its own evidence state.

    Rendered independently on purpose: a valid record for one host must
    never read as evidence about another, and a single collapsed boolean
    would do exactly that.
    """
    lines = ["Per-host verification"]
    for host_id, section in host_verification.items():
        status = section.get("status", "absent")
        locally = _yes_no(bool(section.get("locally_verified")))
        lines.append(
            f"  {host_id:<16}host evidence: {status}; "
            f"locally recorded: {locally}; independently attested: no"
        )
        evidence_class = section.get("evidence_class", "none")
        if evidence_class != "none":
            lines.append(f"  {'':<16}evidence class: {evidence_class}")
    lines.append("")
    return lines


def _render_verification(verification) -> List[str]:
    """The persisted host-evidence section of ``check``.

    Config-side validity is reported by the rows above; this section is
    strictly about what a real host has been observed doing, and it is
    explicit when the answer is "nothing has been observed".
    """
    status = verification.get("status", "absent")
    record = verification.get("record")
    lines = ["Verification", f"  Host evidence: {status}"]
    for reason in verification.get("reasons") or []:
        lines.append(f"  - {reason}")
    if record:
        lines.append(f"  Recorded at: {record.get('timestamp', '(unknown)')}")
        lines.append("  Stages")
        for stage, achieved in (record.get("stages") or {}).items():
            lines.append(f"    {stage:<24}{_yes_no(bool(achieved))}")
        tools = record.get("tools_visible") or []
        if tools:
            lines.append("  Tools visible: " + ", ".join(tools))
        invoked = record.get("tools_invoked") or []
        if invoked:
            lines.append("  Tools invoked: " + ", ".join(invoked))
        lines.append(f"  Handoff round trip: {_yes_no(bool(record.get('handoff_ok')))}")
    lines.append(
        f"  Locally recorded evidence: {_yes_no(bool(verification.get('locally_verified')))}"
    )
    lines.append("  Independently attested: no")
    lines.append("  Current host revalidation: no")
    if status == "valid":
        lines.append(
            "  This is bounded local operational evidence; it is not independent attestation."
        )
    else:
        lines.append(
            "  A host proves itself: run the host, then record evidence with "
            "'relinkra connect verify <agent> --proof <file>'."
        )
    lines.append("")
    return lines


def render_apply(result, *, reveal: bool = False) -> str:
    """What an apply did, stated as facts with the next actions attached.

    Deliberately no readiness wording: a written configuration is a
    config-side fact, and the output says exactly what has NOT happened
    (host restart, real host verification) so the reader cannot walk
    away believing more than the evidence supports.
    """
    lines = ["", f"Apply — {result.host}", ""]
    shown_path = result.real_config_path if reveal else result.config_path
    lines.extend(
        _aligned(
            [
                ("Config", shown_path or "(unresolved)"),
                ("Change required", _yes_no(result.change_required)),
                ("Backup", result.backup_ref if result.backup_created else "(none)"),
                ("Applied", _yes_no(result.write_succeeded)),
                ("Host restart", "required" if result.host_restart_required else "not required by this apply"),
                ("Real host verified", _yes_no(result.real_host_verified)),
                ("Stage", result.verification_stage or "(none)"),
            ]
        )
    )
    lines.append("")

    if result.refusal_reason:
        lines.append("Apply refused")
        lines.append(f"  {result.refusal_reason}")
        lines.append("  No write was attempted; the configuration is untouched.")
        lines.append("")
    elif result.error:
        lines.append("Apply failed")
        lines.append(f"  {result.error}")
        if result.rollback_attempted:
            lines.append(
                "  The original configuration was restored."
                if result.rollback_succeeded
                else "  The original configuration could NOT be restored; "
                "restore it from the backup."
            )
        lines.append("")
    elif not result.change_required:
        lines.append(
            "No change required: the existing registration already matches "
            "the planned contract (verified by re-reading the file)."
        )
        lines.append("")
    else:
        lines.append(f"The configuration at {shown_path or 'the host config'} was inspected and updated.")
        if result.backup_created:
            lines.append(
                f"A backup of the previous configuration was created ({result.backup_ref})."
            )
        else:
            lines.append("No backup was needed: the configuration file did not exist before.")
        lines.append("")
        lines.append("The host has NOT re-read this file yet.")
        lines.append(
            "Real host verification has NOT occurred: a written configuration "
            "proves the file changed, nothing more."
        )
        lines.append("")

    lines.extend(_bullets("Warnings", list(result.warnings)))
    lines.extend(_bullets("Next actions", list(result.actions)))
    return "\n".join(lines)


def render_rollback(result, *, reveal: bool = False) -> str:
    """What a rollback restored, and what state the entry is in now."""
    lines = ["", f"Rollback — {result.host}", ""]
    shown_path = result.real_config_path if reveal else result.config_path
    lines.extend(
        _aligned(
            [
                ("Config", shown_path or "(unresolved)"),
                ("Backup used", result.backup_ref or "(none)"),
                ("Restored", _yes_no(result.rollback_succeeded)),
                ("Validated", _yes_no(result.validation_succeeded)),
                (
                    "Relinkra entry",
                    "present" if result.registration_present else "absent",
                ),
            ]
        )
    )
    lines.append("")
    if result.refusal_reason:
        lines.append("Rollback refused")
        lines.append(f"  {result.refusal_reason}")
        lines.append("  The current configuration was left untouched.")
        lines.append("")
    elif result.error:
        lines.append("Rollback failed")
        lines.append(f"  {result.error}")
        lines.append("")
    else:
        lines.append(
            f"The previous configuration bytes were restored to {shown_path or 'the host config'} "
            "and re-validated as JSON."
        )
        if result.registration_present:
            lines.append(
                "A Relinkra entry is still present afterwards (it predates the "
                "rolled-back apply)."
            )
        else:
            lines.append("No Relinkra entry remains in the configuration.")
        lines.append("")
    lines.extend(_bullets("Warnings", list(result.warnings)))
    lines.extend(_bullets("Next actions", list(result.actions)))
    return "\n".join(lines)


def render_verify(record, payload: dict) -> str:
    """What an operator proof recorded, and when it stops counting."""
    lines = ["", f"Verify — {record.host}", ""]
    lines.append(f"Recorded at: {record.timestamp}")
    lines.append("Stages")
    for stage, achieved in sorted(record.stages.items()):
        lines.append(f"  {stage:<24}{_yes_no(bool(achieved))}")
    if record.tools_visible:
        lines.append("Tools visible: " + ", ".join(record.tools_visible))
    if record.tools_invoked:
        lines.append("Tools invoked: " + ", ".join(record.tools_invoked))
    lines.append(f"Handoff round trip: {_yes_no(record.handoff_ok)}")
    lines.append("")
    lines.append(
        f"This evidence expires {record.ttl_seconds}s after recording and is "
        "invalidated automatically whenever the launch contract changes "
        "(fingerprint mismatch)."
    )
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

    host_verification = getattr(assessment, "host_verification", ()) or ()
    if host_verification:
        lines.append("Per-host verification")
        for row in host_verification:
            stages = row.get("stages") or {}
            stage_summary = ", ".join(
                f"{stage}={'yes' if value else ('unverified' if value is None else 'no')}"
                for stage, value in stages.items()
            )
            lines.append(f"  {row['connector_id']}")
            lines.append(
                f"     config present: {_yes_no(bool(row.get('config_present')))}; "
                f"managed registration: {_yes_no(bool(row.get('managed_registration')))}"
            )
            lines.append(
                f"     host evidence: {row.get('verification_status', 'absent')}; "
                f"handoff: {'proven' if row.get('handoff_proven') else 'unverified'}; "
                f"independently attested: no"
            )
            if stage_summary:
                lines.append(f"     {stage_summary}")
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
