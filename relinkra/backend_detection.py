"""Structural detection of MCP registrations and routing assessment (R4C.0).

Extends the R4B inspection layer from "is Relinkra registered here?" to
"what else is registered here, and what does that mean for the route?".

The detector answers by looking at what an entry WOULD EXECUTE, never at
what it is called. That choice is the whole design. A friendly name is
user-supplied text: an entry named ``relinkra`` that launches the code
indexer is not a Relinkra registration, and an entry named
``code-search`` that launches ``codebase-memory-mcp`` is a direct CBM
exposure whatever the label says. Trusting the name is how a tool ends up
reporting a managed route that does not exist.

Four rules keep it honest.

MARKERS ARE DECLARED. Every backend has a fixed, reviewable table of
module tokens, executable basenames and package names, each traceable to
a real artifact. Nothing is inferred from a substring of a path.

NAME AND TARGET ARE SEPARATE EVIDENCE. When they agree, the detection is
``detected``. When they disagree, it is ``conflicting`` — reported, never
resolved in favour of either.

UNKNOWN ENTRIES SURVIVE. An unrecognised server is reported as
``unknown`` and left completely alone. Relinkra classifies what it finds;
it does not curate someone else's configuration.

NOTHING FROM THE FILE SURVIVES INTO OUTPUT. Detection reads absolute
paths and user-authored server names — that is what a launch command is
made of — and emits only DECLARED marker names plus synthetic refs. The
portable-output audit therefore has nothing to catch, and neither does a
reader of someone's pasted diagnostics.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .backend_policy import (
    BACKEND_CBM,
    BACKEND_ENGRAM,
    BACKEND_RELINKRA,
    BACKEND_UNKNOWN,
    CBM_DIRECTLY_EXPOSED,
    DETECTION_CONFLICTING,
    DETECTION_DETECTED,
    DETECTION_LIKELY,
    DETECTION_UNKNOWN,
    REMEDIATION_BYPASSED,
    REMEDIATION_MIXED,
    REMEDIATION_UNCLASSIFIED_ENGRAM,
    REMEDIATION_UNVERIFIED,
    ROUTE_BYPASSED,
    ROUTE_MANAGED,
    ROUTE_MIXED,
    STAGE_BACKEND_BYPASS_ABSENT,
    STAGE_CONFIGURATION_PRESENT,
    STAGE_CONTEXT_ROUTE_MANAGED,
    STAGE_HANDOFF_ROUND_TRIP,
    STAGE_HANDSHAKE_VERIFIED,
    STAGE_MCP_CONTRACT_CONFIGURED,
    STAGE_METRICS_TRUSTWORTHY,
    STAGE_PROTOCOL_COMPATIBLE,
    STAGE_REAL_HOST_LAUNCH,
    STAGE_REGISTRATION_DETECTED,
    STAGE_REQUIRED_TOOLS_CALLABLE,
    STAGE_TOOLS_VISIBLE,
    TRUST_HIGH,
    ENGRAM_DIRECT_UNCLASSIFIED,
    RouteInputs,
    RoutingAssessment,
    TrustLadder,
    TrustStage,
    aggregate_duplicate_risk,
    classify_cbm_ownership,
    classify_context_route,
    classify_engram_ownership,
    classify_metrics_trust,
    duplicate_risk_findings,
)
from .connect_verification import (
    HANDOFF_ROUNDTRIP,
    HANDSHAKE_SUCCEEDED,
    HOST_LAUNCHED,
    PROTOCOL_COMPATIBLE,
    STATUS_ABSENT,
    STATUS_EXPIRED,
    STATUS_INVALID,
    STATUS_STALE_FINGERPRINT,
    STATUS_VALID,
    TOOLS_CALLABLE,
    TOOLS_VISIBLE,
    assess_verification,
)
from .connectors import (
    CONNECTORS,
    ConnectorSpec,
    InspectionResult,
    entry_tokens,
    inspect_connector,
)
from .config_formats import adapter_for
from .config_merge import MergeError
from .host_discovery import DiscoveryEnvironment
from .safe_write import SafeWriteError, read_bounded_text

#: How much of a configuration key is read AS EVIDENCE. Nothing echoes a
#: server name (see :class:`BackendDetection`), but the name is still
#: lowercased and split to look for hints, and a hostile config can make
#: a key arbitrarily long. Bounding it keeps that comparison cheap.
MAX_SERVER_NAME_CHARS = 64


# ---------------------------------------------------------------------------
# Marker tables
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BackendMarkers:
    """Declared structural fingerprints for one backend.

    ``evidence`` names where each fingerprint came from, so a reviewer
    can check the table against reality instead of trusting it.
    """

    backend: str
    #: Exact token match, e.g. a ``-m relinkra.mcp_cli`` module argument.
    module_tokens: frozenset = frozenset()
    #: Executable basename, matched with and without a Windows suffix.
    executables: frozenset = frozenset()
    #: Package name as it appears in an ``npx``/``uvx`` invocation, with
    #: any ``@version`` suffix stripped before comparison.
    packages: frozenset = frozenset()
    #: Friendly-name hints. EVIDENCE ONLY — never sufficient on their own
    #: when a launch target is present and says something else.
    name_hints: frozenset = frozenset()
    evidence: str = ""


#: Windows-only suffixes a real installer produces. Compared explicitly
#: rather than stripped, so ``engram.exe`` matches and ``engramx`` does
#: not.
_EXECUTABLE_SUFFIXES = ("", ".exe", ".cmd", ".bat", ".ps1")

RELINKRA_MARKERS = BackendMarkers(
    backend=BACKEND_RELINKRA,
    module_tokens=frozenset({"relinkra.mcp_cli"}),
    executables=frozenset({"relinkra-mcp", "relinkra"}),
    packages=frozenset({"relinkra"}),
    name_hints=frozenset({"relinkra"}),
    evidence="Relinkra's own stdio entry point (relinkra.mcp_cli) and console script.",
)

CBM_MARKERS = BackendMarkers(
    backend=BACKEND_CBM,
    module_tokens=frozenset({"codebase_memory_mcp", "codebase_memory_mcp.cli"}),
    executables=frozenset(
        {
            "codebase-memory-mcp",
            "codebase-memory-mcp.payload",
            "cbm",
            "cbm-mcp",
        }
    ),
    packages=frozenset({"codebase-memory-mcp"}),
    name_hints=frozenset(
        {"cbm", "codebase-memory", "codebase-memory-mcp", "codebase_memory_mcp"}
    ),
    evidence=(
        "upstream codebase-memory-mcp: installer binary name, npm/PyPI package "
        "name, and the documented 'mcpServers.codebase-memory-mcp' entry."
    ),
)

ENGRAM_MARKERS = BackendMarkers(
    backend=BACKEND_ENGRAM,
    module_tokens=frozenset({"engram.mcp", "engram_mcp"}),
    executables=frozenset({"engram", "engram-mcp"}),
    packages=frozenset({"engram", "engram-mcp"}),
    name_hints=frozenset({"engram"}),
    evidence=(
        "Engram's documented stdio invocation ('engram mcp'), verified against "
        "a real local MCP registration."
    ),
)

BACKEND_MARKERS: Tuple[BackendMarkers, ...] = (
    RELINKRA_MARKERS,
    CBM_MARKERS,
    ENGRAM_MARKERS,
)

#: Launch-target tokens that attribute a registration to Gentleman.
#:
#: Narrow on purpose, and deliberately TARGET-ONLY. Gentleman ownership
#: is a CLAIM whose consequence is ``shared_separated`` — a healthy PASS
#: — so a wrong claim here turns an unclassified direct Engram server
#: into a clean bill of health. The same rule that governs backend
#: identification governs this: the name is user text, the launch target
#: is evidence. Absent one of these tokens the honest answer is
#: "unclassified", which is exactly what the policy layer expects.
#:
#: A plugin-scoped server name (``plugin:engram:engram``) is deliberately
#: NOT sufficient. It says a plugin manages the entry; it does not say
#: WHICH system does, and Engram has plugin distributions that have
#: nothing to do with Gentleman.
GENTLEMAN_TOKENS = frozenset({"gentleman", "gentle-ai", "gentleai", "gentle_ai"})


def _basename(token: str) -> str:
    """Last path segment, treating both separators as separators.

    A config written on Windows gets read on Linux and back, so the local
    ``PurePath`` flavour is the wrong tool: it would not split a
    backslash path when running on POSIX.
    """
    for separator in ("\\", "/"):
        token = token.rsplit(separator, 1)[-1]
    return token


def _package_name(token: str) -> str:
    """Strip an ``@version`` suffix from an npx-style package token.

    Scoped packages keep their leading ``@``; only a version separator
    after the first character is removed.
    """
    base = _basename(token)
    at = base.rfind("@")
    return base[:at] if at > 0 else base


def _matches(markers: BackendMarkers, tokens: Sequence[str]) -> Tuple[str, ...]:
    """Which declared fingerprints of ``markers`` these tokens carry."""
    found: List[str] = []
    for token in tokens:
        text = str(token)
        if text in markers.module_tokens:
            found.append(f"module:{text}")
            continue
        base = _basename(text).lower()
        for suffix in _EXECUTABLE_SUFFIXES:
            if suffix and not base.endswith(suffix):
                continue
            stem = base[: -len(suffix)] if suffix else base
            if stem in markers.executables:
                found.append(f"executable:{stem}")
                break
        else:
            package = _package_name(text).lower()
            if package in markers.packages:
                found.append(f"package:{package}")
    # Ordered and de-duplicated: the marker list is rendered, and a
    # rendering whose order depends on dict iteration is not comparable
    # between runs.
    return tuple(sorted(set(found)))


def _matches_entry(
    markers: BackendMarkers, entry: Any, tokens: Sequence[str]
) -> Tuple[str, ...]:
    """Apply launch-shape ownership before matching Relinkra markers."""
    if markers.backend == BACKEND_RELINKRA:
        # Keep backend classification aligned with connector ownership. In
        # particular, a wrapper or node command must not become Relinkra
        # merely because it carries the module token as an argument.
        from .connectors import launches_relinkra

        if not launches_relinkra(entry):
            return ()
    return _matches(markers, tokens)


def _name_backends(server_name: str) -> Tuple[str, ...]:
    """Backends whose name hints the server name carries."""
    lowered = (server_name or "").strip().lower()
    if not lowered:
        return ()
    found = []
    for markers in BACKEND_MARKERS:
        for hint in markers.name_hints:
            if hint == lowered or hint in lowered.split("-") or hint in lowered.split(
                "_"
            ):
                found.append(markers.backend)
                break
    return tuple(sorted(set(found)))


def _evidence_name(name: Any) -> str:
    """The configuration key, bounded, for USE AS EVIDENCE ONLY.

    Never reaches output — see :class:`BackendDetection`. Bounded anyway
    because it is user-controlled text that gets lowercased and split, and
    an unbounded key would turn a name comparison into a cost.
    """
    text = str(name or "")
    return text[:MAX_SERVER_NAME_CHARS]


def _gentleman_marked(tokens: Sequence[str]) -> bool:
    """Whether a registration is attributable to Gentleman.

    One signal, and it comes from the LAUNCH TARGET: a Gentleman-owned
    token anywhere in the command — including as a path segment, which is
    why the raw token is searched rather than only its basename. The
    server name is not consulted, for the same reason it does not decide
    which backend an entry is.
    """
    for token in tokens:
        text = str(token).lower().replace("\\", "/")
        segments = set(text.split("/"))
        segments.update(text.split("-"))
        segments.update(text.split("_"))
        # Leading dots stripped because the convention that hides a
        # directory is exactly the convention Gentleman installs under:
        # '~/.gentleman/bin' would otherwise never match 'gentleman'.
        segments.update(segment.lstrip(".") for segment in tuple(segments))
        if segments & GENTLEMAN_TOKENS:
            return True
    return False


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BackendDetection:
    """What one MCP registration turned out to be.

    The configured server NAME is used as evidence and never emitted. A
    name is user-authored text living in a private config — it can carry
    a client, an internal codename or a hostname — and Relinkra's output
    guarantee is that a user can paste it into an issue without reading
    it first. ``ref`` is a synthetic, stable label that identifies the
    entry within a report, and ``name_suggests`` carries the diagnostic
    value the name had (which backend it implied) without the string.
    """

    backend: str
    confidence: str
    ref: str = ""
    markers: Tuple[str, ...] = ()
    name_suggests: Tuple[str, ...] = ()
    gentleman_marked: bool = False
    detail: str = ""

    @property
    def trustworthy(self) -> bool:
        """Whether this detection may drive a routing conclusion."""
        return self.confidence == DETECTION_DETECTED

    def with_ref(self, ref: str) -> "BackendDetection":
        return BackendDetection(
            backend=self.backend,
            confidence=self.confidence,
            ref=ref,
            markers=self.markers,
            name_suggests=self.name_suggests,
            gentleman_marked=self.gentleman_marked,
            detail=self.detail,
        )

    def to_dict(self) -> dict:
        return {
            "ref": self.ref,
            "backend": self.backend,
            "confidence": self.confidence,
            "markers": list(self.markers),
            "name_suggests": list(self.name_suggests),
            "gentleman_marked": self.gentleman_marked,
            "detail": self.detail,
        }


def classify_entry(server_name: Any, entry: Any) -> BackendDetection:
    """Classify one MCP entry structurally.

    The decision table, in the order it is applied:

    * exactly one backend matched by launch tokens, and the name agrees
      (or says nothing)                                    -> ``detected``
    * exactly one matched, but the name names a different
      backend                                           -> ``conflicting``
    * more than one matched                              -> ``conflicting``
    * nothing matched, tokens present, name names one    -> ``conflicting``
    * nothing matched, NO tokens (a remote/URL entry),
      name names one                                        -> ``likely``
    * nothing matched, name says nothing                    -> ``unknown``

    The fourth row is the one that matters. Tokens that match nothing are
    positive evidence AGAINST the name: the entry launches something, and
    that something is not what it is called.
    """
    name = _evidence_name(server_name)
    tokens = entry_tokens(entry)
    nominal = _name_backends(name)
    gentleman = _gentleman_marked(tokens)

    matched: Dict[str, Tuple[str, ...]] = {}
    for markers in BACKEND_MARKERS:
        found = _matches_entry(markers, entry, tokens)
        if found:
            matched[markers.backend] = found

    if len(matched) == 1:
        backend, found = next(iter(matched.items()))
        disagreeing = tuple(item for item in nominal if item != backend)
        if disagreeing:
            return BackendDetection(
                backend,
                DETECTION_CONFLICTING,
                "",
                found,
                nominal,
                gentleman,
                "the entry name suggests a different backend than it launches; "
                "the launch target wins and the entry is left untouched.",
            )
        return BackendDetection(
            backend,
            DETECTION_DETECTED,
            "",
            found,
            nominal,
            gentleman,
            "identified from the launch target.",
        )

    if len(matched) > 1:
        every = tuple(sorted(item for found in matched.values() for item in found))
        return BackendDetection(
            BACKEND_UNKNOWN,
            DETECTION_CONFLICTING,
            "",
            every,
            nominal,
            gentleman,
            "the entry carries markers for more than one backend.",
        )

    if nominal and tokens:
        return BackendDetection(
            BACKEND_UNKNOWN,
            DETECTION_CONFLICTING,
            "",
            (),
            nominal,
            gentleman,
            "the entry name suggests a known backend, but its launch target "
            "matches none; ownership is not inferred from a name.",
        )

    if nominal:
        return BackendDetection(
            nominal[0],
            DETECTION_LIKELY,
            "",
            (),
            nominal,
            gentleman,
            "no local launch target to inspect (a remote entry); the name is "
            "the only evidence available.",
        )

    return BackendDetection(
        BACKEND_UNKNOWN,
        DETECTION_UNKNOWN,
        "",
        (),
        (),
        gentleman,
        "not a backend Relinkra manages; preserved untouched.",
    )


def entry_matches_backend(entry: Any, backend: str) -> bool:
    """Whether an entry carries a launch marker for ``backend``.

    This deliberately ignores the configured server name and confidence.
    A mixed launch is a conflicting detection for reporting, but it still
    contains a direct CBM route and must trip write-path safety gates.
    """
    tokens = entry_tokens(entry)
    return any(
        markers.backend == backend and bool(_matches_entry(markers, entry, tokens))
        for markers in BACKEND_MARKERS
    )


def detect_registrations(inspection: InspectionResult) -> Tuple[BackendDetection, ...]:
    """Classify every MCP entry in one host's parsed configuration.

    Returns empty when the config could not be read or parsed — an
    unreadable file yields NO detections rather than a confident "nothing
    is registered", which the caller then reports as unverified.
    """
    document = inspection.document
    spec = inspection.spec
    container_path = inspection.container_path or spec.container_path
    if document is None or not container_path:
        return ()
    node: Any = document
    for key in container_path:
        if not isinstance(node, Mapping):
            return ()
        node = node.get(key)
        if node is None:
            return ()
    if not isinstance(node, Mapping):
        return ()
    containers = [node]
    # Hosts can declare containers inherited beside the selected target.
    # Inspect each effective scope without allowing an alias of the target
    # (or the same inherited container declared twice) to duplicate entries.
    for inherited_path in getattr(spec, "inherited_container_paths", ()):
        inherited: Any = document
        for key in inherited_path:
            if not isinstance(inherited, Mapping):
                break
            inherited = inherited.get(key)
            if inherited is None:
                break
        if isinstance(inherited, Mapping) and not any(
            inherited is container for container in containers
        ):
            containers.append(inherited)
    detections = [
        classify_entry(name, entry)
        for container in containers
        for name, entry in sorted(container.items(), key=str)
    ]
    # Refs are assigned here rather than in ``classify_entry`` because
    # they are positional: an entry's label only means anything relative
    # to the other entries in the same file. Sorting by the configuration
    # key first keeps them stable across runs without ever emitting it.
    counters: Dict[str, int] = {}
    labelled = []
    for detection in detections:
        counters[detection.backend] = counters.get(detection.backend, 0) + 1
        labelled.append(
            detection.with_ref(f"{detection.backend}#{counters[detection.backend]}")
        )
    return tuple(labelled)


# ---------------------------------------------------------------------------
# Per-host routing view
# ---------------------------------------------------------------------------

NAMING_CURRENT = "current"
NAMING_LEGACY = "legacy"
NAMING_NOT_APPLICABLE = "not_applicable"
NAMING_UNVERIFIED = "unverified"


@dataclass(frozen=True)
class HostRouting:
    """One host's contribution to the routing picture."""

    connector_id: str
    discovery_status: str
    config_readable: bool
    detections: Tuple[BackendDetection, ...] = ()
    naming: str = NAMING_NOT_APPLICABLE
    active_location_id: str = ""
    authoritative_scope_unreadable: bool = False

    def backends(self, backend: str) -> Tuple[BackendDetection, ...]:
        return tuple(
            item
            for item in self.detections
            if item.backend == backend and item.trustworthy
        )

    def to_dict(self) -> dict:
        return {
            "connector_id": self.connector_id,
            "discovery_status": self.discovery_status,
            "config_readable": self.config_readable,
            "naming": self.naming,
            "active_location_id": self.active_location_id,
            "authoritative_scope_unreadable": self.authoritative_scope_unreadable,
            "detections": [item.to_dict() for item in self.detections],
        }


def _naming_state(spec: ConnectorSpec, inspection: InspectionResult) -> str:
    """Whether this host's ACTIVE config sits at a legacy location.

    Only meaningful for a connector that declares both. Everything else
    gets ``not_applicable``, which is a different statement from "current"
    and is why the two are separate values.
    """
    legacy_ids = getattr(spec, "legacy_location_ids", ())
    if not legacy_ids:
        return NAMING_NOT_APPLICABLE
    if inspection.location is None:
        return NAMING_UNVERIFIED
    return (
        NAMING_LEGACY
        if inspection.location.location_id in legacy_ids
        else NAMING_CURRENT
    )


def host_routing(spec: ConnectorSpec, inspection: InspectionResult) -> HostRouting:
    return HostRouting(
        connector_id=spec.connector_id,
        discovery_status=inspection.discovery_status,
        config_readable=inspection.document is not None,
        detections=detect_registrations(inspection),
        naming=_naming_state(spec, inspection),
        active_location_id=(
            inspection.location.location_id if inspection.location else ""
        ),
    )


def _authoritative_scope_survey(
    spec: ConnectorSpec, env: DiscoveryEnvironment
) -> Tuple[Tuple[BackendDetection, ...], bool]:
    """Cross-scope direct-CBM survey of one connector's authoritative scopes.

    Reads every DECLARED location the host loads MCP servers from
    (``mcp_authoritative``) — user and workspace scope alike, so a
    merged-in sibling (OpenCode's ``.jsonc``) cannot hide a direct CBM
    registration — and classifies what it finds under the connector's
    static container path. An authoritative scope that exists but cannot
    be read, parsed or walked is reported UNREADABLE — fail closed,
    never "clean" — exactly like an unreadable active config. Aligned
    with the apply scanner: a scope that exists but has no container (or
    a non-mapping container) registers no servers, which is clean, not
    unreadable.
    """
    detections: List[BackendDetection] = []
    unreadable = False
    for location in spec.locations:
        if not location.mcp_authoritative:
            continue
        pure = location.build(env)
        if pure is None:
            continue
        scope_path = Path(str(pure))
        if not scope_path.exists():
            continue
        try:
            if scope_path.is_symlink() or not scope_path.is_file():
                raise OSError("authoritative MCP scope is not a regular file")
            adapter = adapter_for(location.config_format)
            if adapter is None:
                raise MergeError("no parser for the scope's declared format")
            scope_document = adapter.parse(read_bounded_text(scope_path))
        except (OSError, SafeWriteError, ValueError, TypeError, RecursionError, MergeError):
            unreadable = True
            continue
        if not isinstance(scope_document, Mapping):
            unreadable = True
            continue
        node: Any = scope_document
        for key in spec.container_path:
            if not isinstance(node, Mapping):
                node = None
                break
            node = node.get(key)
        if not isinstance(node, Mapping):
            # The scope exists but registers no servers; that is clean,
            # not unreadable.
            continue
        detections.extend(
            classify_entry(name, entry)
            for name, entry in sorted(node.items(), key=str)
        )
    return tuple(detections), unreadable


def survey_hosts(
    env: DiscoveryEnvironment,
    specs: Sequence[ConnectorSpec] = CONNECTORS,
) -> Tuple[HostRouting, ...]:
    """Read-only survey of every registered connector. Writes nothing."""
    surveyed = []
    for spec in specs:
        if not spec.container_path:
            continue
        inspection = inspect_connector(spec, env)
        host = host_routing(spec, inspection)
        scope_detections, unreadable = _authoritative_scope_survey(spec, env)
        if scope_detections or unreadable:
            host = HostRouting(
                connector_id=host.connector_id,
                discovery_status=host.discovery_status,
                config_readable=host.config_readable and not unreadable,
                detections=host.detections + scope_detections,
                naming=host.naming,
                active_location_id=host.active_location_id,
                authoritative_scope_unreadable=unreadable,
            )
        surveyed.append(host)
    return tuple(surveyed)


# ---------------------------------------------------------------------------
# Trust ladder
# ---------------------------------------------------------------------------


def build_trust_ladder(
    hosts: Sequence[HostRouting],
    *,
    launch_resolved: bool,
    relinkra_registered: bool,
    route: str,
    metrics_trust: str,
    bypass_detected: bool,
    handoffs_available: Optional[bool],
    tools_declared: int,
    real_host_launch_proven: bool,
    workspace_root=None,
    verification_fingerprint: str = "",
) -> TrustLadder:
    """Assemble the twelve-rung ladder from what is actually known.

    ``None`` appears wherever the evidence needs a running host: a
    handshake, a tool call arriving from an agent, a completed handoff
    round trip. Those cannot be established from a configuration file,
    and this phase does not launch hosts to find out — so they stay
    unverified and render as WARN. Turning any of them into a PASS on
    the strength of the config would be exactly the false confidence the
    ladder exists to prevent.

    When ``workspace_root`` is supplied, the six host-side rungs are
    populated from persisted local operational evidence instead,
    assessed independently for EVERY apply-capable connector: a VALID
    record from at least one host records a rung (``valid local host
    evidence (<host>) <timestamp>``), and absent, stale or expired
    evidence leaves the rung UNVERIFIED with the reason named per host.
    One host's missing evidence never degrades another's valid record.
    Config-side rungs keep their structural behaviour either way.
    """
    configured = any(host.config_readable for host in hosts)

    # Local operational evidence is assessed PER HOST, for every
    # connector the registry says can be written — never for one
    # hardcoded host. A host-side rung is proven when at least one host
    # holds VALID evidence recording that stage, and the evidence string
    # names the host(s) providing it. One host's missing or stale
    # evidence never degrades another host's valid evidence.
    host_evidence: Dict[str, Tuple[str, Any]] = {}
    if workspace_root is not None:
        for spec in CONNECTORS:
            if not spec.apply_available:
                continue
            try:
                status, record, _reasons = assess_verification(
                    workspace_root, spec.connector_id, verification_fingerprint
                )
            except Exception:
                # Evidence that cannot be read is evidence that does not
                # exist; the ladder reports unverified, never a traceback.
                status, record = STATUS_ABSENT, None
            host_evidence[spec.connector_id] = (status, record)

    _STATUS_NOTES = {
        STATUS_ABSENT: "no local host evidence has been recorded",
        STATUS_STALE_FINGERPRINT: (
            "the recorded local host evidence is stale: the launch contract changed"
        ),
        STATUS_EXPIRED: "the recorded local host evidence expired",
        STATUS_INVALID: "the recorded local host evidence is structurally invalid",
    }

    def _host_stage(stage_key: str, default_value, default_evidence: str):
        if workspace_root is None:
            return default_value, default_evidence
        proving = []
        reported_not_achieved = []
        for host_id, (status, record) in host_evidence.items():
            if status == STATUS_VALID and record is not None:
                if bool(record.stages.get(stage_key, False)):
                    proving.append((host_id, record.timestamp))
                else:
                    reported_not_achieved.append((host_id, record.timestamp))
        if proving:
            named = ", ".join(f"({host}) {stamp}" for host, stamp in proving)
            return (
                True,
                f"valid local host evidence {named}; not independently attested",
            )
        if reported_not_achieved:
            named = ", ".join(
                f"({host}) {stamp}" for host, stamp in reported_not_achieved
            )
            return (
                False,
                f"local host evidence {named} reports this stage as not achieved",
            )
        if not host_evidence or all(
            status == STATUS_ABSENT for status, _ in host_evidence.values()
        ):
            note = "no local host evidence has been recorded"
        else:
            note = "; ".join(
                f"{host_id}: {_STATUS_NOTES.get(status, 'local host evidence is unavailable')}"
                for host_id, (status, _record) in host_evidence.items()
            )
        return None, f"{default_evidence}; {note}"

    handshake_value, handshake_evidence = _host_stage(
        HANDSHAKE_SUCCEEDED,
        None,
        "no host has completed an initialize handshake with this server",
    )
    tools_value, tools_evidence = _host_stage(
        TOOLS_VISIBLE,
        bool(tools_declared),
        f"{tools_declared} tool(s) declared and importable in this process; "
        "visibility to an agent is a separate, unverified question",
    )
    callable_value, callable_evidence = _host_stage(
        TOOLS_CALLABLE,
        None,
        "no tool call has arrived from a host",
    )
    handoff_value, handoff_evidence = _host_stage(
        HANDOFF_ROUNDTRIP,
        False if handoffs_available is False else None,
        "the memory backend is unavailable, so no handoff can round-trip"
        if handoffs_available is False
        else "no handoff has been written and read back through a host",
    )
    launch_value, launch_evidence = _host_stage(
        HOST_LAUNCHED,
        real_host_launch_proven,
        "a real host has launched this server"
        if real_host_launch_proven
        else "no real host has been observed launching this server",
    )
    protocol_value, protocol_evidence = _host_stage(
        PROTOCOL_COMPATIBLE,
        None,
        "the host's protocol version is only observable during a "
        "handshake, which this phase does not perform",
    )

    stages = (
        TrustStage(
            STAGE_CONFIGURATION_PRESENT,
            configured,
            "at least one host configuration was read"
            if configured
            else "no readable host configuration was found",
        ),
        TrustStage(
            STAGE_REGISTRATION_DETECTED,
            relinkra_registered,
            "a registration launching relinkra.mcp_cli was found"
            if relinkra_registered
            else "no host registers the Relinkra MCP server",
        ),
        TrustStage(
            STAGE_MCP_CONTRACT_CONFIGURED,
            launch_resolved,
            "the stdio launch contract resolved on this machine"
            if launch_resolved
            else "the launch contract could not be resolved",
        ),
        TrustStage(
            STAGE_PROTOCOL_COMPATIBLE,
            protocol_value,
            protocol_evidence,
        ),
        TrustStage(
            STAGE_HANDSHAKE_VERIFIED,
            handshake_value,
            handshake_evidence,
        ),
        TrustStage(
            STAGE_TOOLS_VISIBLE,
            tools_value,
            tools_evidence,
        ),
        TrustStage(
            STAGE_REQUIRED_TOOLS_CALLABLE,
            callable_value,
            callable_evidence,
        ),
        TrustStage(
            STAGE_HANDOFF_ROUND_TRIP,
            handoff_value,
            handoff_evidence,
        ),
        TrustStage(
            STAGE_REAL_HOST_LAUNCH,
            launch_value,
            launch_evidence,
        ),
        TrustStage(
            STAGE_CONTEXT_ROUTE_MANAGED,
            route == ROUTE_MANAGED,
            f"context route is '{route}'",
        ),
        TrustStage(
            STAGE_BACKEND_BYPASS_ABSENT,
            not bypass_detected,
            "a direct backend registration was found beside Relinkra"
            if bypass_detected
            else "no direct backend registration bypasses Relinkra",
        ),
        TrustStage(
            STAGE_METRICS_TRUSTWORTHY,
            metrics_trust == TRUST_HIGH,
            f"metrics trust is '{metrics_trust}'",
        ),
    )
    return TrustLadder(stages=stages)


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------


def host_verification_view(
    hosts: Sequence[HostRouting],
    *,
    workspace_root=None,
    verification_fingerprint: str = "",
) -> Tuple[dict, ...]:
    """Per-host verification state, one portable row per apply-capable host.

    Each row states INDEPENDENTLY what is known about one host: whether
    its configuration was read, whether a managed Relinkra registration
    was detected in it, and what the persisted local host evidence says
    about launch, handshake, tools and handoff. Rows are never collapsed
    into one boolean, and no row is promoted by another host's evidence.
    """
    if workspace_root is None:
        return ()
    routing_by_id = {host.connector_id: host for host in hosts}
    rows = []
    for spec in CONNECTORS:
        if not spec.apply_available:
            continue
        host_id = spec.connector_id
        try:
            status, record, _reasons = assess_verification(
                workspace_root, host_id, verification_fingerprint
            )
        except Exception:
            status, record = STATUS_ABSENT, None
        valid = status == STATUS_VALID and record is not None
        stages = record.stages if valid else {}
        routing = routing_by_id.get(host_id)
        rows.append(
            {
                "connector_id": host_id,
                "config_present": bool(routing and routing.config_readable),
                "managed_registration": bool(
                    routing and routing.backends(BACKEND_RELINKRA)
                ),
                "verification_status": status,
                "stages": {
                    stage: (bool(stages.get(stage)) if valid else None)
                    for stage in (
                        HOST_LAUNCHED,
                        HANDSHAKE_SUCCEEDED,
                        TOOLS_VISIBLE,
                        TOOLS_CALLABLE,
                        HANDOFF_ROUNDTRIP,
                    )
                },
                "handoff_proven": (
                    bool(record.handoff_ok) if valid else None
                ),
                "locally_verified": bool(
                    valid
                    and record.stages
                    and all(record.stages.values())
                    and record.handoff_ok
                ),
                "evidence_class": "local_operational" if valid else "none",
                "independently_attested": False,
            }
        )
    return tuple(rows)


def _declared_tool_count() -> int:
    """How many MCP tools this installation declares. Never spawns one."""
    try:
        from .mcp_server import TOOLS
    except ImportError:  # pragma: no cover - the module is part of the package
        return 0
    return len(TOOLS)


def assess_routing(
    hosts: Sequence[HostRouting],
    *,
    launch_resolved: bool = False,
    advanced_cbm_allowed: bool = False,
    cbm_backend_available: bool = False,
    engram_backend_available: bool = False,
    relinkra_health_degraded: bool = False,
    relinkra_verified: bool = False,
    handoffs_available: Optional[bool] = None,
    real_host_launch_proven: bool = False,
    tools_declared: Optional[int] = None,
    workspace_root=None,
    verification_fingerprint: str = "",
) -> RoutingAssessment:
    """Turn a host survey plus backend health into one verdict.

    ``relinkra_verified`` is the caller's assertion that something beyond
    a config file was independently revalidated. A persisted operator proof
    is only local operational evidence: it may explain the ladder, but a
    writable file must never promote route trust by itself.
    """
    relinkra_registered = any(host.backends(BACKEND_RELINKRA) for host in hosts)

    # Do not derive this flag from the writable verification file.  Callers
    # must supply independently revalidated host evidence when the route is
    # to be trusted beyond configuration/locally-recorded evidence.

    cbm_hosts = [host for host in hosts if host.backends(BACKEND_CBM)]
    engram_detections = [
        item for host in hosts for item in host.backends(BACKEND_ENGRAM)
    ]
    name_conflicting = any(
        item.confidence == DETECTION_CONFLICTING
        for host in hosts
        for item in host.detections
    )
    scope_unreadable = any(
        getattr(host, "authoritative_scope_unreadable", False) for host in hosts
    )
    conflicting = name_conflicting or scope_unreadable

    inputs = RouteInputs(
        hosts_inspected=sum(1 for host in hosts if host.config_readable),
        relinkra_registered=relinkra_registered,
        relinkra_verified=relinkra_verified,
        direct_cbm_registered=bool(cbm_hosts),
        advanced_cbm_allowed=advanced_cbm_allowed,
        cbm_backend_available=cbm_backend_available,
        engram_registered=bool(engram_detections),
        engram_gentleman_marked=any(
            item.gentleman_marked for item in engram_detections
        ),
        engram_backend_available=engram_backend_available,
        relinkra_health_degraded=relinkra_health_degraded,
        conflicting_detection=conflicting,
    )

    route = classify_context_route(inputs)
    cbm_ownership = classify_cbm_ownership(inputs)
    engram_ownership = classify_engram_ownership(inputs)
    metrics_trust = classify_metrics_trust(
        route, advanced_cbm_allowed=advanced_cbm_allowed
    )
    findings = duplicate_risk_findings(inputs)

    # The route's own remediation is chosen from the route, not from
    # whatever happens to be first in the list: a routing warning that
    # suggests fixing memory ownership answers a question nobody asked.
    route_remediation = ""
    if route == ROUTE_MIXED:
        route_remediation = REMEDIATION_MIXED
    elif route == ROUTE_BYPASSED:
        route_remediation = REMEDIATION_BYPASSED
    elif route != ROUTE_MANAGED:
        route_remediation = REMEDIATION_UNVERIFIED

    remediation: List[str] = []
    if route_remediation:
        remediation.append(route_remediation)
    if engram_ownership == ENGRAM_DIRECT_UNCLASSIFIED:
        remediation.append(REMEDIATION_UNCLASSIFIED_ENGRAM)

    notes: List[str] = []
    if name_conflicting:
        notes.append(
            "At least one registration's name disagrees with what it launches; "
            "ownership was not inferred from the name."
        )
    if scope_unreadable:
        notes.append(
            "An authoritative MCP scope could not be read; its registrations "
            "are unknown. Repair or remove the unreadable configuration file."
        )
    unknown = sum(
        1
        for host in hosts
        for item in host.detections
        if item.confidence == DETECTION_UNKNOWN
    )
    if unknown:
        notes.append(
            f"{unknown} unrecognised MCP server(s) were preserved untouched."
        )
    legacy = [host.connector_id for host in hosts if host.naming == NAMING_LEGACY]
    if legacy:
        notes.append(
            "Legacy configuration locations are in use for: " + ", ".join(legacy)
        )

    bypass = cbm_ownership in (CBM_DIRECTLY_EXPOSED,) or (
        advanced_cbm_allowed and bool(cbm_hosts)
    )

    return RoutingAssessment(
        context_route=route,
        cbm_ownership=cbm_ownership,
        engram_ownership=engram_ownership,
        metrics_trust=metrics_trust,
        duplicate_risk=aggregate_duplicate_risk(findings),
        duplicate_findings=findings,
        ladder=build_trust_ladder(
            hosts,
            launch_resolved=launch_resolved,
            relinkra_registered=relinkra_registered,
            route=route,
            metrics_trust=metrics_trust,
            bypass_detected=bypass,
            handoffs_available=handoffs_available,
            tools_declared=(
                _declared_tool_count() if tools_declared is None else tools_declared
            ),
            real_host_launch_proven=real_host_launch_proven,
            workspace_root=workspace_root,
            verification_fingerprint=verification_fingerprint,
        ),
        hosts=tuple(host.to_dict() for host in hosts),
        host_verification=host_verification_view(
            hosts,
            workspace_root=workspace_root,
            verification_fingerprint=verification_fingerprint,
        ),
        remediation=tuple(remediation),
        route_remediation=route_remediation,
        notes=tuple(notes),
    )


def assess_workspace(
    env: DiscoveryEnvironment,
    *,
    health: Optional[Mapping[str, Any]] = None,
    launch_resolved: bool = False,
    advanced_cbm_allowed: bool = False,
    specs: Sequence[ConnectorSpec] = CONNECTORS,
    verification_fingerprint: str = "",
) -> RoutingAssessment:
    """Survey the machine and assess it, reading only. The one entry point
    both ``doctor`` and ``connect routing`` call, so they cannot disagree.
    """
    hosts = survey_hosts(env, specs)
    components = (health or {}).get("components") or {}
    capabilities = (health or {}).get("capabilities") or {}
    return assess_routing(
        hosts,
        launch_resolved=launch_resolved,
        advanced_cbm_allowed=advanced_cbm_allowed,
        cbm_backend_available=bool((components.get("cbm") or {}).get("available")),
        engram_backend_available=bool(
            (components.get("engram") or {}).get("available")
        ),
        relinkra_health_degraded=bool((health or {}).get("degraded")),
        handoffs_available=(
            bool(capabilities.get("handoffs")) if capabilities else None
        ),
        real_host_launch_proven=any(
            getattr(spec, "real_host_launch_proven", False) for spec in specs
        ),
        workspace_root=(
            Path(str(env.workspace_root)) if env.workspace_root is not None else None
        ),
        verification_fingerprint=verification_fingerprint,
    )


__all__ = [
    "BACKEND_MARKERS",
    "CBM_MARKERS",
    "ENGRAM_MARKERS",
    "GENTLEMAN_TOKENS",
    "MAX_SERVER_NAME_CHARS",
    "NAMING_CURRENT",
    "NAMING_LEGACY",
    "NAMING_NOT_APPLICABLE",
    "NAMING_UNVERIFIED",
    "RELINKRA_MARKERS",
    "BackendDetection",
    "BackendMarkers",
    "HostRouting",
    "assess_routing",
    "assess_workspace",
    "build_trust_ladder",
    "classify_entry",
    "detect_registrations",
    "entry_matches_backend",
    "host_routing",
    "host_verification_view",
    "survey_hosts",
]
