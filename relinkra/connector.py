"""Connector domain model (R4B).

The typed vocabulary every connector speaks. This module holds NO I/O,
no host knowledge and no filesystem access — it defines the states, the
launch contract, the mutation plan and the capability matrix, so that
``connectors``, ``host_discovery`` and ``connect_cli`` can disagree about
hosts while agreeing about meaning.

Two rules shape every type here.

PORTABLE BY DEFAULT. A machine-local path (a user's home, a workspace
root, an interpreter location) is data the CLI resolves but does not
print. Each type that carries one exposes two renderings: ``to_dict()``
is the portable form and is what normal output and ``--json`` emit;
``to_machine_dict()`` is the machine-local form, produced only when the
user explicitly asks for it. A type never leaks a path by omission,
because the portable renderer is the default one.

HONEST BY CONSTRUCTION. ``CapabilityMatrix`` separates "we implemented a
connector" from "a real host actually launched Relinkra". A plan that can
be generated proves the first and says nothing about the last, so the two
never collapse into a single "supported" boolean.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Mapping, Optional, Sequence

#: Bumped when the shape of a rendered plan changes. Consumers pin it.
PLAN_VERSION = "relinkra.connector-plan/v1"

#: Bumped when the shape of the generic launch contract changes.
CONTRACT_VERSION = "relinkra.mcp-launch/v1"

#: The MCP server name Relinkra registers under in a host config. Also
#: the key a plan reads back to decide whether it already registered.
MANAGED_SERVER_NAME = "relinkra"

#: Optional ownership marker. A host connector opts in only when unknown
#: members are known to be tolerated by that host; otherwise ownership is
#: decided structurally (see ``connectors.launches_relinkra``).
MARKER_KEY = "x-relinkra"
MARKER_VALUE = "managed"


# ---------------------------------------------------------------------------
# States
# ---------------------------------------------------------------------------

#: How far a connector has been taken. ``supported`` still says nothing
#: about a live host — that is ``CapabilityMatrix.real_host_launch_proven``.
SUPPORT_SUPPORTED = "supported"
SUPPORT_EXPERIMENTAL = "experimental"
SUPPORT_UNSUPPORTED = "unsupported"
SUPPORT_STATUSES = frozenset(
    {SUPPORT_SUPPORTED, SUPPORT_EXPERIMENTAL, SUPPORT_UNSUPPORTED}
)

#: What read-only discovery found. The four failure shapes are kept
#: distinct on purpose: "no config" and "broken config" call for opposite
#: user actions, and collapsing them into "not working" hides that.
DISCOVERY_DISCOVERED = "discovered"
DISCOVERY_NOT_INSTALLED = "not_installed"
DISCOVERY_CONFIG_MISSING = "config_missing"
DISCOVERY_CONFIG_MALFORMED = "config_malformed"
DISCOVERY_CONFIG_UNSUPPORTED = "config_unsupported"
DISCOVERY_UNVERIFIED = "unverified"
DISCOVERY_STATUSES = frozenset(
    {
        DISCOVERY_DISCOVERED,
        DISCOVERY_NOT_INSTALLED,
        DISCOVERY_CONFIG_MISSING,
        DISCOVERY_CONFIG_MALFORMED,
        DISCOVERY_CONFIG_UNSUPPORTED,
        DISCOVERY_UNVERIFIED,
    }
)

#: Whether Relinkra is already registered with this host, and how well.
REGISTRATION_ABSENT = "absent"
REGISTRATION_ALREADY_CONNECTED = "already_connected"
REGISTRATION_NEEDS_UPDATE = "needs_update"
REGISTRATION_CONFLICT = "conflict"
REGISTRATION_UNKNOWN = "unknown"
REGISTRATION_STATES = frozenset(
    {
        REGISTRATION_ABSENT,
        REGISTRATION_ALREADY_CONNECTED,
        REGISTRATION_NEEDS_UPDATE,
        REGISTRATION_CONFLICT,
        REGISTRATION_UNKNOWN,
    }
)

#: Where a path lives, and therefore whether it may be printed.
PATH_MACHINE_LOCAL = "machine_local"
PATH_WORKSPACE_LOCAL = "workspace_local"
PATH_PORTABLE = "portable"

#: Config scope, independent of classification: a workspace file and a
#: user file are both machine-local, but only one travels with the repo.
SCOPE_USER = "user"
SCOPE_WORKSPACE = "workspace"

FORMAT_JSON = "json"
FORMAT_TOML = "toml"

TRANSPORT_STDIO = "stdio"

#: Which invocation shape the launch contract resolved to.
DISTRIBUTION_CONSOLE_SCRIPT = "console_script"
DISTRIBUTION_INSTALLED_MODULE = "installed_module"
DISTRIBUTION_SOURCE_CHECKOUT = "source_checkout"
DISTRIBUTION_UNRESOLVED = "unresolved"


# ---------------------------------------------------------------------------
# Plan operations
# ---------------------------------------------------------------------------

OP_NO_OP = "no_op"
OP_BACKUP_FILE = "backup_file"
OP_CREATE_FILE = "create_file"
OP_ADD_OBJECT_MEMBER = "add_object_member"
OP_REPLACE_MANAGED_MEMBER = "replace_managed_member"
OP_VALIDATE_JSON = "validate_json"
OP_REQUEST_RESTART = "request_restart"
OPERATIONS = frozenset(
    {
        OP_NO_OP,
        OP_BACKUP_FILE,
        OP_CREATE_FILE,
        OP_ADD_OBJECT_MEMBER,
        OP_REPLACE_MANAGED_MEMBER,
        OP_VALIDATE_JSON,
        OP_REQUEST_RESTART,
    }
)

#: A plan is one of three things, never a bare boolean: it can be run, it
#: is refusing to run because of a conflict, or it could not be built at
#: all because this phase does not support writing to that host.
PLAN_READY = "ready"
PLAN_BLOCKED = "blocked"
PLAN_UNAVAILABLE = "unavailable"
PLAN_STATUSES = frozenset({PLAN_READY, PLAN_BLOCKED, PLAN_UNAVAILABLE})


class ConnectorError(Exception):
    """Base error for connector failures."""


class UnknownConnectorError(ConnectorError, ValueError):
    """Raised when a name resolves to no registered connector."""


# ---------------------------------------------------------------------------
# Value types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConfigLocation:
    """One candidate configuration file for a host.

    ``path`` is the resolved machine-local location and is deliberately
    absent from :meth:`to_dict`. ``display_hint`` is a DECLARED template
    (``"~/.claude/settings.json"``) rather than anything derived from
    ``path``, so the portable rendering describes the convention without
    disclosing this machine's layout — and stays identical across
    machines, which is what makes plan output comparable at all.
    """

    location_id: str
    scope: str
    classification: str
    config_format: str
    display_hint: str
    path: Optional[Any] = None
    exists: bool = False
    readable: bool = True
    size_bytes: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "location_id": self.location_id,
            "scope": self.scope,
            "classification": self.classification,
            "format": self.config_format,
            "display_hint": self.display_hint,
            "exists": self.exists,
            "readable": self.readable,
            "size_bytes": self.size_bytes,
        }

    def to_machine_dict(self) -> dict:
        data = self.to_dict()
        data["path"] = str(self.path) if self.path is not None else None
        return data


@dataclass(frozen=True)
class LaunchContract:
    """How a host should start the Relinkra MCP server.

    Structured on purpose: ``command`` plus ``args`` as separate values,
    never one string. A single string would have to be re-split by
    whoever runs it, and the only general way to re-split it is a shell —
    which is exactly the injection surface this model exists to avoid. A
    workspace root containing a space or an ``&`` stays inert here.

    ``env`` holds machine-local VALUES and never reaches portable output;
    ``env_keys`` is the sorted list of names, which is all a reader needs
    to know what the server depends on.
    """

    transport: str = TRANSPORT_STDIO
    command: str = ""
    args: Sequence[str] = field(default_factory=tuple)
    env: Mapping[str, str] = field(default_factory=dict)
    distribution: str = DISTRIBUTION_UNRESOLVED
    module: str = "relinkra.mcp_cli"
    resolved: bool = False
    warnings: Sequence[str] = field(default_factory=tuple)

    @property
    def env_keys(self) -> List[str]:
        return sorted(self.env)

    def to_dict(self) -> dict:
        """Portable rendering: shapes and names, no machine-local values.

        ``args`` is reduced to its non-path tokens plus a placeholder for
        each value that is machine-local, so a reader still sees the
        ARITY and ORDER of the invocation — enough to sanity-check the
        contract — without seeing where anything lives.
        """
        return {
            "transport": self.transport,
            "distribution": self.distribution,
            "module": self.module,
            "resolved": self.resolved,
            "command": "<interpreter>" if self.command else "",
            "args": [_portable_token(token) for token in self.args],
            "env_keys": self.env_keys,
            "warnings": list(self.warnings),
        }

    def to_machine_dict(self) -> dict:
        """Machine-local rendering. Emitted only on explicit request."""
        return {
            "transport": self.transport,
            "distribution": self.distribution,
            "module": self.module,
            "resolved": self.resolved,
            "command": self.command,
            "args": list(self.args),
            "env": dict(self.env),
            "env_keys": self.env_keys,
            "warnings": list(self.warnings),
        }


def _portable_token(token: str) -> str:
    """Keep flags and module names; replace anything path-shaped.

    Imported lazily-free: the absolute-path test already lives in the
    handoff layer, which is the single definition of "machine-local
    string" in this codebase. Re-implementing it here would let the two
    drift, and the portability self-audit uses that one.
    """
    from .handoff import contains_absolute_path

    return "<path>" if contains_absolute_path(token) else token


@dataclass(frozen=True)
class CapabilityMatrix:
    """What is actually proven, stage by stage.

    Read strictly left to right. Each field answers a narrower question
    than the one before it, and a later field is never implied by an
    earlier one — in particular ``real_host_launch_proven`` requires a
    real host to have started this server, which no amount of planning
    can establish.
    """

    implementation_exists: bool = False
    configuration_format_verified: bool = False
    registration_detected: bool = False
    registration_planned: bool = False
    configuration_validated: bool = False
    mcp_process_contract_validated: bool = False
    real_host_launch_proven: bool = False

    def to_dict(self) -> dict:
        return {
            "implementation_exists": self.implementation_exists,
            "configuration_format_verified": self.configuration_format_verified,
            "registration_detected": self.registration_detected,
            "registration_planned": self.registration_planned,
            "configuration_validated": self.configuration_validated,
            "mcp_process_contract_validated": self.mcp_process_contract_validated,
            "real_host_launch_proven": self.real_host_launch_proven,
        }


@dataclass(frozen=True)
class PlanOperation:
    """One step of a mutation plan.

    ``target_ref`` is a SEMANTIC identifier (``claude:user_settings``),
    never a path: it names which configuration the step touches in terms
    that mean the same thing on every machine.

    Preconditions and postconditions are carried as data rather than
    checked inline because the plan is produced by one process and would
    be executed by another; the executor re-checks them at write time,
    which is what closes the gap between planning and applying.
    """

    op: str
    target_ref: str
    detail: str = ""
    preconditions: Sequence[str] = field(default_factory=tuple)
    postconditions: Sequence[str] = field(default_factory=tuple)
    rollback: str = ""

    def to_dict(self) -> dict:
        return {
            "op": self.op,
            "target_ref": self.target_ref,
            "detail": self.detail,
            "preconditions": list(self.preconditions),
            "postconditions": list(self.postconditions),
            "rollback": self.rollback,
        }


@dataclass(frozen=True)
class ConnectorWarning:
    """A non-fatal finding. Same {code, message} shape as the R1E/R2/R3
    warnings, so an agent parses one warning type across all layers."""

    code: str
    message: str

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message}


@dataclass
class ConnectorPlan:
    """A deterministic, side-effect-free description of a mutation.

    Building one touches no file. Two builds from the same inputs produce
    equal dicts, which is what makes ``plan`` safe to run repeatedly and
    what lets the idempotency proof compare runs directly.
    """

    connector_id: str
    status: str = PLAN_UNAVAILABLE
    registration_state: str = REGISTRATION_UNKNOWN
    target_ref: str = ""
    operations: List[PlanOperation] = field(default_factory=list)
    warnings: List[ConnectorWarning] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    restart_instruction: str = ""
    apply_available: bool = False
    unavailable_reason: str = ""
    plan_version: str = PLAN_VERSION

    @property
    def idempotent(self) -> bool:
        """True when running this plan changes nothing.

        Derived, never stored: a plan whose only operation is a no-op is
        idempotent by definition, and computing it keeps the flag from
        contradicting the operation list.
        """
        return all(op.op in (OP_NO_OP, OP_VALIDATE_JSON) for op in self.operations)

    def to_dict(self) -> dict:
        return {
            "connector_id": self.connector_id,
            "plan_version": self.plan_version,
            "status": self.status,
            "registration_state": self.registration_state,
            "target_ref": self.target_ref,
            "operations": [op.to_dict() for op in self.operations],
            "warnings": [w.to_dict() for w in self.warnings],
            "conflicts": list(self.conflicts),
            "restart_instruction": self.restart_instruction,
            "apply_available": self.apply_available,
            "unavailable_reason": self.unavailable_reason,
            "idempotent": self.idempotent,
        }


@dataclass
class ConnectorReport:
    """The result of read-only inspection of one connector.

    Everything ``inspect`` and ``list`` render comes from here, so the
    two commands can never describe the same connector differently.
    """

    connector_id: str
    display_name: str
    host_type: str
    aliases: Sequence[str] = field(default_factory=tuple)
    support_status: str = SUPPORT_EXPERIMENTAL
    discovery_status: str = DISCOVERY_UNVERIFIED
    registration_state: str = REGISTRATION_UNKNOWN
    transport: str = TRANSPORT_STDIO
    executable_found: bool = False
    locations: List[ConfigLocation] = field(default_factory=list)
    active_location_id: str = ""
    env_keys: List[str] = field(default_factory=list)
    warnings: List[ConnectorWarning] = field(default_factory=list)
    capabilities: CapabilityMatrix = field(default_factory=CapabilityMatrix)
    restart_instruction: str = ""
    security_notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "connector_id": self.connector_id,
            "display_name": self.display_name,
            "host_type": self.host_type,
            "aliases": list(self.aliases),
            "support_status": self.support_status,
            "discovery_status": self.discovery_status,
            "registration_state": self.registration_state,
            "transport": self.transport,
            "executable_found": self.executable_found,
            "locations": [loc.to_dict() for loc in self.locations],
            "active_location_id": self.active_location_id,
            "env_keys": sorted(self.env_keys),
            "warnings": [w.to_dict() for w in self.warnings],
            "capabilities": self.capabilities.to_dict(),
            "restart_instruction": self.restart_instruction,
            "security_notes": list(self.security_notes),
        }


def iter_strings(value: Any):
    """Yield every string reachable in a JSON-shaped payload.

    The portability audit and its tests all need to walk a rendered
    payload looking for machine-local values. Defined once here so the
    thing being audited and the thing asserting the audit cannot drift
    into two subtly different traversals.
    """
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from iter_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from iter_strings(item)
