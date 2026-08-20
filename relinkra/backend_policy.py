"""Backend ownership, routing and trust policy (R4C.0).

Relinkra is the context control plane. Agents are supposed to reach the
project through it — not around it — and this module is where that
sentence stops being a slogan and becomes a set of typed states a machine
can check.

Pure domain. No filesystem, no host knowledge, no I/O of any kind.
``backend_detection`` supplies the observations; this module supplies the
vocabulary and the rules that turn observations into a verdict, so the
rules can be tested without a machine that happens to have Windsurf
installed.

Three principles shape everything below.

OWNERSHIP IS A STATE, NOT A STRING. Every axis — who owns CBM, who owns
Engram, how context is routed, how much the metrics can be trusted, how
likely duplicate work is — is a closed enum with a documented meaning.
Loose strings scattered through the code is precisely how "healthy"
starts meaning four different things in four different files.

BYPASS IS NOT FAILURE, BUT IT IS NEVER HEALTH. A user who exposes CBM
directly to their agent has made a choice Relinkra will describe, not
overrule. What Relinkra refuses to do is keep calling the route "managed"
afterwards, or keep attributing the resulting token savings to itself.

UNVERIFIED IS ITS OWN ANSWER. Most of what happens between an agent and
its backends happens in another process, and Relinkra cannot see it. The
honest states for that are :data:`ROUTE_UNVERIFIED` and
:data:`DUPLICATE_UNVERIFIED` — never "managed" and never "none".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

#: Bumped when the shape of a rendered assessment changes.
POLICY_VERSION = "relinkra.backend-policy/v1"

#: Bumped when the agent instruction contract changes.
INSTRUCTION_VERSION = "relinkra.agent-instructions/v1"


# ---------------------------------------------------------------------------
# Backend kinds and detection confidence
# ---------------------------------------------------------------------------

BACKEND_RELINKRA = "relinkra"
BACKEND_CBM = "cbm"
BACKEND_ENGRAM = "engram"
BACKEND_UNKNOWN = "unknown"
BACKEND_KINDS = frozenset(
    {BACKEND_RELINKRA, BACKEND_CBM, BACKEND_ENGRAM, BACKEND_UNKNOWN}
)

#: How sure the structural detector is about one registration.
#:
#: ``conflicting`` is the interesting one: it means the friendly name and
#: the launch target disagree. An entry called "relinkra" that starts the
#: code indexer is not a Relinkra registration, and calling it one — on
#: the strength of its name — is how a tool ends up reporting a managed
#: route that does not exist.
DETECTION_DETECTED = "detected"
DETECTION_LIKELY = "likely"
DETECTION_UNKNOWN = "unknown"
DETECTION_CONFLICTING = "conflicting"
DETECTION_CONFIDENCES = frozenset(
    {
        DETECTION_DETECTED,
        DETECTION_LIKELY,
        DETECTION_UNKNOWN,
        DETECTION_CONFLICTING,
    }
)


# ---------------------------------------------------------------------------
# Backend ownership
# ---------------------------------------------------------------------------

#: CBM is Relinkra's private code-graph backend. The supported topology is
#: agent -> Relinkra -> CBM, so anything else is a state to report.
CBM_RELINKRA_PRIVATE = "relinkra_private"
CBM_DIRECTLY_EXPOSED = "directly_exposed"
CBM_EXPLICITLY_ALLOWED_ADVANCED = "explicitly_allowed_advanced"
CBM_UNAVAILABLE = "unavailable"
CBM_UNKNOWN = "unknown"
CBM_OWNERSHIP_STATES = frozenset(
    {
        CBM_RELINKRA_PRIVATE,
        CBM_DIRECTLY_EXPOSED,
        CBM_EXPLICITLY_ALLOWED_ADVANCED,
        CBM_UNAVAILABLE,
        CBM_UNKNOWN,
    }
)

#: Engram is shared on purpose. Gentleman keeps SDD workflow state there
#: and has every right to; Relinkra keeps agent-neutral project memory
#: there. ``shared_separated`` is the healthy state for a machine running
#: both, and is NOT a degradation.
ENGRAM_RELINKRA_MANAGED = "relinkra_managed"
ENGRAM_GENTLEMAN_MANAGED = "gentleman_managed"
ENGRAM_SHARED_SEPARATED = "shared_separated"
ENGRAM_DIRECT_UNCLASSIFIED = "direct_unclassified"
ENGRAM_UNAVAILABLE = "unavailable"
ENGRAM_UNKNOWN = "unknown"
ENGRAM_OWNERSHIP_STATES = frozenset(
    {
        ENGRAM_RELINKRA_MANAGED,
        ENGRAM_GENTLEMAN_MANAGED,
        ENGRAM_SHARED_SEPARATED,
        ENGRAM_DIRECT_UNCLASSIFIED,
        ENGRAM_UNAVAILABLE,
        ENGRAM_UNKNOWN,
    }
)


# ---------------------------------------------------------------------------
# Context route
# ---------------------------------------------------------------------------

#: How project context actually reaches the agent.
#:
#: ``managed``    every observed path goes through Relinkra, and Relinkra
#:                itself is more than configured.
#: ``mixed``      Relinkra is registered AND a private backend is exposed
#:                directly beside it.
#: ``bypassed``   a private backend is exposed and Relinkra is not there.
#: ``degraded``   Relinkra owns the route but cannot fully serve it.
#: ``unverified`` nothing observable supports any of the above.
ROUTE_MANAGED = "managed"
ROUTE_MIXED = "mixed"
ROUTE_BYPASSED = "bypassed"
ROUTE_DEGRADED = "degraded"
ROUTE_UNVERIFIED = "unverified"
CONTEXT_ROUTE_STATES = frozenset(
    {
        ROUTE_MANAGED,
        ROUTE_MIXED,
        ROUTE_BYPASSED,
        ROUTE_DEGRADED,
        ROUTE_UNVERIFIED,
    }
)


# ---------------------------------------------------------------------------
# Metrics trust
# ---------------------------------------------------------------------------

#: How much a later telemetry number may be believed.
#:
#: This exists because the tempting lie is easy: measure the tokens
#: Relinkra's budgeter removed, call it "tokens saved", and publish it
#: while the agent is also reading files directly and querying CBM behind
#: Relinkra's back. Attribution is only as good as the route.
TRUST_HIGH = "high"
TRUST_DEGRADED = "degraded"
TRUST_UNRELIABLE = "unreliable"
TRUST_UNVERIFIED = "unverified"
METRICS_TRUST_STATES = frozenset(
    {TRUST_HIGH, TRUST_DEGRADED, TRUST_UNRELIABLE, TRUST_UNVERIFIED}
)


# ---------------------------------------------------------------------------
# Duplicate read/write risk
# ---------------------------------------------------------------------------

DUPLICATE_NONE = "none"
DUPLICATE_POSSIBLE = "possible"
DUPLICATE_DETECTED = "detected"
DUPLICATE_UNVERIFIED = "unverified"
DUPLICATE_RISK_STATES = frozenset(
    {DUPLICATE_NONE, DUPLICATE_POSSIBLE, DUPLICATE_DETECTED, DUPLICATE_UNVERIFIED}
)

#: The five distinct ways the same work gets done twice. Kept apart
#: because the remediations differ: a duplicate backend query costs
#: latency, a duplicate persisted memory costs correctness, and a
#: duplicate token attribution costs credibility.
DUP_CONTEXT_RETRIEVAL = "duplicate_project_context_retrieval"
DUP_BACKEND_QUERY = "duplicate_backend_query"
DUP_PERSISTED_MEMORY = "duplicate_persisted_memory"
DUP_TASK_RESULT = "duplicate_task_result_recording"
DUP_TOKEN_ATTRIBUTION = "duplicate_token_attribution"
DUPLICATE_KINDS: Tuple[str, ...] = (
    DUP_CONTEXT_RETRIEVAL,
    DUP_BACKEND_QUERY,
    DUP_PERSISTED_MEMORY,
    DUP_TASK_RESULT,
    DUP_TOKEN_ATTRIBUTION,
)

#: Where the evidence for a duplicate-risk finding could come from.
#: ``outside_process`` is the honest label for agent behaviour Relinkra
#: cannot observe, and it can never produce a ``none`` verdict.
OBSERVABILITY_HOST_CONFIG = "host_configuration"
OBSERVABILITY_IN_PROCESS = "in_process"
OBSERVABILITY_OUTSIDE_PROCESS = "outside_process"
OBSERVABILITY_LEVELS = frozenset(
    {
        OBSERVABILITY_HOST_CONFIG,
        OBSERVABILITY_IN_PROCESS,
        OBSERVABILITY_OUTSIDE_PROCESS,
    }
)

#: Worst-wins ordering. Higher sorts later and therefore wins.
_DUPLICATE_SEVERITY = {
    DUPLICATE_NONE: 0,
    DUPLICATE_UNVERIFIED: 1,
    DUPLICATE_POSSIBLE: 2,
    DUPLICATE_DETECTED: 3,
}


@dataclass(frozen=True)
class DuplicateRiskFinding:
    """One named duplication risk, with how it was (or was not) observed."""

    kind: str
    risk: str
    observability: str
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "risk": self.risk,
            "observability": self.observability,
            "detail": self.detail,
        }


def aggregate_duplicate_risk(findings: Sequence[DuplicateRiskFinding]) -> str:
    """Collapse per-kind findings into one verdict, worst wins.

    No findings at all means nothing was even considered, which is
    ``unverified`` — not ``none``. ``none`` is a claim, and a claim needs
    someone to have looked.
    """
    if not findings:
        return DUPLICATE_UNVERIFIED
    return max(
        (finding.risk for finding in findings),
        key=lambda risk: _DUPLICATE_SEVERITY.get(risk, 1),
    )


# ---------------------------------------------------------------------------
# Ownership authority matrix
# ---------------------------------------------------------------------------

AUTHORITY_RELINKRA = "relinkra"
AUTHORITY_GENTLEMAN = "gentleman"

#: What a system stores for a domain it does not own. ``reference`` means
#: an id or a compact summary — never a second copy of the payload, which
#: is the whole point of having an authority at all.
RECORD_FULL = "full_record"
RECORD_REFERENCE = "reference_or_summary"
RECORD_NONE = "none"


@dataclass(frozen=True)
class OwnershipRule:
    """Who owns one domain of shared Engram, and what the other side keeps."""

    domain: str
    authority: str
    relinkra_stores: str
    gentleman_stores: str
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "authority": self.authority,
            "relinkra_stores": self.relinkra_stores,
            "gentleman_stores": self.gentleman_stores,
            "note": self.note,
        }


#: The coexistence contract. Gentleman keeps its workflow; Relinkra keeps
#: the agent-neutral, portable half. Exactly one side stores the full
#: record for every domain — an invariant asserted by the tests, because
#: a matrix that drifts into double ownership is how two systems start
#: writing the same decision twice under different ids.
OWNERSHIP_MATRIX: Tuple[OwnershipRule, ...] = (
    OwnershipRule(
        domain="sdd_workflow_state",
        authority=AUTHORITY_GENTLEMAN,
        relinkra_stores=RECORD_NONE,
        gentleman_stores=RECORD_FULL,
        note="Phase progress and continuation belong to the workflow that runs them.",
    ),
    OwnershipRule(
        domain="gentleman_reviews_and_receipts",
        authority=AUTHORITY_GENTLEMAN,
        relinkra_stores=RECORD_REFERENCE,
        gentleman_stores=RECORD_FULL,
        note="Relinkra may reference a lineage; it never re-records the receipt.",
    ),
    OwnershipRule(
        domain="gentleman_workflow_checkpoints",
        authority=AUTHORITY_GENTLEMAN,
        relinkra_stores=RECORD_NONE,
        gentleman_stores=RECORD_FULL,
    ),
    OwnershipRule(
        domain="gentleman_specific_artifacts",
        authority=AUTHORITY_GENTLEMAN,
        relinkra_stores=RECORD_NONE,
        gentleman_stores=RECORD_FULL,
    ),
    OwnershipRule(
        domain="cross_agent_handoffs",
        authority=AUTHORITY_RELINKRA,
        relinkra_stores=RECORD_FULL,
        gentleman_stores=RECORD_REFERENCE,
        note="A handoff must be readable by an agent that has never run Gentleman.",
    ),
    OwnershipRule(
        domain="agent_neutral_project_memory",
        authority=AUTHORITY_RELINKRA,
        relinkra_stores=RECORD_FULL,
        gentleman_stores=RECORD_REFERENCE,
    ),
    OwnershipRule(
        domain="context_packets_and_selection_metadata",
        authority=AUTHORITY_RELINKRA,
        relinkra_stores=RECORD_FULL,
        gentleman_stores=RECORD_NONE,
    ),
    OwnershipRule(
        domain="portable_memory_code_linkage",
        authority=AUTHORITY_RELINKRA,
        relinkra_stores=RECORD_FULL,
        gentleman_stores=RECORD_NONE,
    ),
    OwnershipRule(
        domain="git_linked_task_results",
        authority=AUTHORITY_RELINKRA,
        relinkra_stores=RECORD_FULL,
        gentleman_stores=RECORD_REFERENCE,
    ),
    OwnershipRule(
        domain="relinkra_verification_summaries",
        authority=AUTHORITY_RELINKRA,
        relinkra_stores=RECORD_FULL,
        gentleman_stores=RECORD_NONE,
    ),
)


def duplicate_full_ownership() -> Tuple[str, ...]:
    """Domains where BOTH systems would store the full record.

    Must always be empty. Exposed as a function rather than asserted
    inline so the invariant has a name a test can call, and so a future
    edit to the matrix fails loudly instead of quietly duplicating data.
    """
    return tuple(
        rule.domain
        for rule in OWNERSHIP_MATRIX
        if rule.relinkra_stores == RECORD_FULL
        and rule.gentleman_stores == RECORD_FULL
    )


def authority_for(domain: str) -> Optional[str]:
    for rule in OWNERSHIP_MATRIX:
        if rule.domain == domain:
            return rule.authority
    return None


# ---------------------------------------------------------------------------
# The trust ladder
# ---------------------------------------------------------------------------

#: Ordered stages, narrowest evidence last. Each is a SEPARATE question,
#: and the whole reason the ladder exists is that the first rung —
#: "a config file mentions Relinkra" — is the one most likely to be
#: mistaken for the last.
STAGE_CONFIGURATION_PRESENT = "configuration_present"
STAGE_REGISTRATION_DETECTED = "relinkra_registration_detected"
STAGE_MCP_CONTRACT_CONFIGURED = "mcp_contract_configured"
STAGE_PROTOCOL_COMPATIBLE = "protocol_compatible"
STAGE_HANDSHAKE_VERIFIED = "handshake_verified"
STAGE_TOOLS_VISIBLE = "tools_visible"
STAGE_REQUIRED_TOOLS_CALLABLE = "required_tools_callable"
STAGE_HANDOFF_ROUND_TRIP = "handoff_round_trip_verified"
STAGE_REAL_HOST_LAUNCH = "real_host_launch_proven"
STAGE_CONTEXT_ROUTE_MANAGED = "context_route_managed"
STAGE_BACKEND_BYPASS_ABSENT = "backend_bypass_absent"
STAGE_METRICS_TRUSTWORTHY = "metrics_trustworthy"

TRUST_STAGES: Tuple[str, ...] = (
    STAGE_CONFIGURATION_PRESENT,
    STAGE_REGISTRATION_DETECTED,
    STAGE_MCP_CONTRACT_CONFIGURED,
    STAGE_PROTOCOL_COMPATIBLE,
    STAGE_HANDSHAKE_VERIFIED,
    STAGE_TOOLS_VISIBLE,
    STAGE_REQUIRED_TOOLS_CALLABLE,
    STAGE_HANDOFF_ROUND_TRIP,
    STAGE_REAL_HOST_LAUNCH,
    STAGE_CONTEXT_ROUTE_MANAGED,
    STAGE_BACKEND_BYPASS_ABSENT,
    STAGE_METRICS_TRUSTWORTHY,
)

STAGE_PROVEN = "proven"
STAGE_NOT_PROVEN = "not_proven"
STAGE_UNVERIFIED = "unverified"
STAGE_STATES = frozenset({STAGE_PROVEN, STAGE_NOT_PROVEN, STAGE_UNVERIFIED})


@dataclass(frozen=True)
class TrustStage:
    """One rung, its state, and how that state was reached.

    ``value`` is deliberately tri-state. ``None`` means nobody looked or
    nobody could look, and it renders as ``unverified`` — never as a
    pass. That single rule is what stops "config present" from being
    promoted into "ready".
    """

    stage: str
    value: Optional[bool]
    evidence: str = ""

    @property
    def state(self) -> str:
        if self.value is None:
            return STAGE_UNVERIFIED
        return STAGE_PROVEN if self.value else STAGE_NOT_PROVEN

    @property
    def proven(self) -> bool:
        return self.value is True

    def to_dict(self) -> dict:
        return {
            "stage": self.stage,
            "state": self.state,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class TrustLadder:
    """The full ladder for one workspace."""

    stages: Tuple[TrustStage, ...] = ()

    def by_stage(self) -> Dict[str, TrustStage]:
        return {stage.stage: stage for stage in self.stages}

    @property
    def all_proven(self) -> bool:
        return bool(self.stages) and all(stage.proven for stage in self.stages)

    def unproven(self) -> Tuple[TrustStage, ...]:
        return tuple(stage for stage in self.stages if not stage.proven)

    def to_dict(self) -> dict:
        return {
            "all_proven": self.all_proven,
            "stages": [stage.to_dict() for stage in self.stages],
        }


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RouteInputs:
    """Everything the route classifier is allowed to consider.

    A flat record rather than a pile of parameters so a test can state a
    whole machine's situation in one literal, and so adding a future
    signal cannot silently change an existing call's meaning.
    """

    hosts_inspected: int = 0
    relinkra_registered: bool = False
    relinkra_verified: bool = False
    direct_cbm_registered: bool = False
    advanced_cbm_allowed: bool = False
    cbm_backend_available: bool = False
    engram_registered: bool = False
    engram_gentleman_marked: bool = False
    engram_backend_available: bool = False
    relinkra_health_degraded: bool = False
    conflicting_detection: bool = False


def classify_context_route(inputs: RouteInputs) -> str:
    """Decide how project context actually reaches the agent.

    Read in order — the earlier a rule sits, the less it is willing to
    assume. Conflicting evidence beats everything, because a config whose
    name and launch target disagree is not evidence of a route at all;
    then bypass, then mixture, then Relinkra's own condition. ``managed``
    is reachable only from the bottom, after every other reading has been
    ruled out.
    """
    if inputs.conflicting_detection or inputs.hosts_inspected <= 0:
        return ROUTE_UNVERIFIED
    if inputs.direct_cbm_registered and not inputs.relinkra_registered:
        return ROUTE_BYPASSED
    if not inputs.relinkra_registered:
        # No Relinkra and no direct backend either: this machine simply
        # has not been wired up. Nothing has been bypassed and nothing is
        # managed — there is no route to describe yet.
        return ROUTE_UNVERIFIED
    if inputs.direct_cbm_registered:
        return ROUTE_MIXED
    if inputs.relinkra_health_degraded:
        return ROUTE_DEGRADED
    if not inputs.relinkra_verified:
        # Registered is not running. Until something beyond the config
        # file has been observed, the route is a plan.
        return ROUTE_UNVERIFIED
    return ROUTE_MANAGED


def classify_cbm_ownership(inputs: RouteInputs) -> str:
    """Who owns the code-graph backend on this machine.

    ``relinkra_private`` is a claim about who the backend belongs TO, and
    it requires Relinkra to actually be in the picture. Without a
    registration anywhere, a reachable CBM that nothing exposes is owned
    by nobody observable — ``unknown``, not "safely private". The
    distinction matters because ``relinkra_private`` renders as a PASS,
    and a PASS beside an unverified route reads as a contradiction the
    user has to resolve themselves.
    """
    if inputs.conflicting_detection:
        return CBM_UNKNOWN
    if inputs.direct_cbm_registered:
        return (
            CBM_EXPLICITLY_ALLOWED_ADVANCED
            if inputs.advanced_cbm_allowed
            else CBM_DIRECTLY_EXPOSED
        )
    if not inputs.cbm_backend_available:
        # No backend and no direct exposure: there is nothing to own, and
        # that is a definite, safe answer rather than an absent one.
        return CBM_UNAVAILABLE
    if not inputs.relinkra_registered:
        return CBM_UNKNOWN
    return CBM_RELINKRA_PRIVATE


def classify_engram_ownership(inputs: RouteInputs) -> str:
    """Who owns the memory backend, given that sharing it is legitimate.

    Direct exposure is NOT an error here. Gentleman needs Engram for SDD
    state and gets it. What the classifier separates is the case where
    the direct registration carries a Gentleman ownership marker from the
    case where it carries none — the second is not a failure either, it
    is simply unclassified, and saying so beats guessing.
    """
    if inputs.engram_registered and inputs.engram_gentleman_marked:
        return (
            ENGRAM_SHARED_SEPARATED
            if inputs.engram_backend_available
            else ENGRAM_GENTLEMAN_MANAGED
        )
    if inputs.engram_registered:
        return ENGRAM_DIRECT_UNCLASSIFIED
    if not inputs.engram_backend_available:
        return ENGRAM_UNAVAILABLE
    # Same rule as CBM: "Relinkra manages it" needs Relinkra to be
    # registered somewhere. A reachable backend nothing routes to is
    # unowned, and saying so beats a PASS that contradicts the route.
    if not inputs.relinkra_registered:
        return ENGRAM_UNKNOWN
    return ENGRAM_RELINKRA_MANAGED


def classify_metrics_trust(route: str, *, advanced_cbm_allowed: bool = False) -> str:
    """How much later telemetry may be believed, given the route.

    Attribution is a function of the route and nothing else. A mixed
    route the user opted into deliberately is ``degraded`` rather than
    ``unreliable`` — the numbers are still incomplete, but the gap is
    known and documented instead of accidental.
    """
    if route == ROUTE_MANAGED:
        return TRUST_HIGH
    if route == ROUTE_MIXED:
        return TRUST_DEGRADED if advanced_cbm_allowed else TRUST_UNRELIABLE
    if route == ROUTE_BYPASSED:
        return TRUST_UNRELIABLE
    if route == ROUTE_DEGRADED:
        return TRUST_DEGRADED
    return TRUST_UNVERIFIED


def duplicate_risk_findings(inputs: RouteInputs) -> Tuple[DuplicateRiskFinding, ...]:
    """Classify each duplication risk against what is actually observable.

    Note what is NOT claimed. Relinkra can see a host configuration, so a
    direct CBM entry beside its own is ``detected`` from
    ``host_configuration``. It cannot see an agent deciding to read forty
    files by hand, so that stays ``unverified`` from
    ``outside_process`` — permanently, and by design.
    """
    findings: List[DuplicateRiskFinding] = []

    if inputs.direct_cbm_registered and inputs.relinkra_registered:
        findings.append(
            DuplicateRiskFinding(
                DUP_CONTEXT_RETRIEVAL,
                DUPLICATE_DETECTED,
                OBSERVABILITY_HOST_CONFIG,
                "Relinkra and a direct CBM server are registered with the same "
                "host, so the agent can retrieve project context twice.",
            )
        )
        findings.append(
            DuplicateRiskFinding(
                DUP_BACKEND_QUERY,
                DUPLICATE_DETECTED,
                OBSERVABILITY_HOST_CONFIG,
                "The same code-graph backend is reachable through Relinkra and "
                "directly.",
            )
        )
        findings.append(
            DuplicateRiskFinding(
                DUP_TOKEN_ATTRIBUTION,
                DUPLICATE_DETECTED,
                OBSERVABILITY_HOST_CONFIG,
                "Context delivered by the direct backend is invisible to "
                "Relinkra's budgeter, so savings cannot be attributed.",
            )
        )
    elif inputs.direct_cbm_registered:
        findings.append(
            DuplicateRiskFinding(
                DUP_CONTEXT_RETRIEVAL,
                DUPLICATE_POSSIBLE,
                OBSERVABILITY_HOST_CONFIG,
                "A direct CBM server is registered without Relinkra; retrieval "
                "is unbudgeted and unattributed.",
            )
        )
        findings.append(
            DuplicateRiskFinding(
                DUP_TOKEN_ATTRIBUTION,
                DUPLICATE_UNVERIFIED,
                OBSERVABILITY_OUTSIDE_PROCESS,
                "No Relinkra route exists to attribute against.",
            )
        )
    else:
        findings.append(
            DuplicateRiskFinding(
                DUP_CONTEXT_RETRIEVAL,
                DUPLICATE_NONE,
                OBSERVABILITY_HOST_CONFIG,
                "No direct code-graph backend is registered beside Relinkra.",
            )
        )
        findings.append(
            DuplicateRiskFinding(
                DUP_BACKEND_QUERY,
                DUPLICATE_NONE,
                OBSERVABILITY_HOST_CONFIG,
                "The code-graph backend is reachable only through Relinkra.",
            )
        )
        # Single-sourced attribution needs BOTH facts: no competing
        # registration, and a Relinkra route that was actually observed.
        # The first alone only proves nothing was found in a config file.
        findings.append(
            DuplicateRiskFinding(
                DUP_TOKEN_ATTRIBUTION,
                DUPLICATE_NONE if inputs.relinkra_verified else DUPLICATE_UNVERIFIED,
                OBSERVABILITY_HOST_CONFIG,
                "Attribution is single-sourced: no competing registration, and "
                "the Relinkra route was observed."
                if inputs.relinkra_verified
                else "No competing registration was found, but no Relinkra "
                "route has been observed to attribute against.",
            )
        )

    if inputs.engram_registered and inputs.engram_gentleman_marked:
        findings.append(
            DuplicateRiskFinding(
                DUP_PERSISTED_MEMORY,
                DUPLICATE_POSSIBLE,
                OBSERVABILITY_IN_PROCESS,
                "Relinkra and Gentleman share Engram. Relinkra reads only its "
                "own envelope, so records stay separated, but a shared event "
                "written by both sides would duplicate.",
            )
        )
        findings.append(
            DuplicateRiskFinding(
                DUP_TASK_RESULT,
                DUPLICATE_POSSIBLE,
                OBSERVABILITY_IN_PROCESS,
                "Review and task results have one authority per domain; a "
                "workflow that ignores the matrix can still record both.",
            )
        )
    elif inputs.engram_registered:
        findings.append(
            DuplicateRiskFinding(
                DUP_PERSISTED_MEMORY,
                DUPLICATE_UNVERIFIED,
                OBSERVABILITY_OUTSIDE_PROCESS,
                "A direct Engram registration was found with no ownership "
                "marker; what it writes cannot be classified from here.",
            )
        )
        findings.append(
            DuplicateRiskFinding(
                DUP_TASK_RESULT,
                DUPLICATE_UNVERIFIED,
                OBSERVABILITY_OUTSIDE_PROCESS,
                "Unclassified direct memory access may record results Relinkra "
                "also records.",
            )
        )
    else:
        findings.append(
            DuplicateRiskFinding(
                DUP_PERSISTED_MEMORY,
                DUPLICATE_NONE if inputs.engram_backend_available else DUPLICATE_UNVERIFIED,
                OBSERVABILITY_IN_PROCESS,
                "No direct memory registration was found beside Relinkra.",
            )
        )
        findings.append(
            DuplicateRiskFinding(
                DUP_TASK_RESULT,
                DUPLICATE_NONE if inputs.engram_backend_available else DUPLICATE_UNVERIFIED,
                OBSERVABILITY_IN_PROCESS,
                "Task results are recorded by Relinkra alone on this host.",
            )
        )

    return tuple(findings)


# ---------------------------------------------------------------------------
# Remediation — descriptive, never destructive
# ---------------------------------------------------------------------------

#: Remediations are TEXT. Nothing in this phase disables a user's server,
#: deletes an entry, or rewrites a host config — a tool that silently
#: removes the CBM registration someone installed on purpose has replaced
#: one wrong assumption with a worse one.
REMEDIATION_MIXED = (
    "Use Relinkra for project context and keep the direct CBM server "
    "disabled for this host. Relinkra queries CBM for you, with relevance "
    "ranking, budgeting, memory linkage and attribution attached. Nothing "
    "was changed — disable or remove the direct entry yourself if you want "
    "the managed route."
)
REMEDIATION_BYPASSED = (
    "Register Relinkra with this host and keep the direct CBM server "
    "disabled for ordinary project work. Direct CBM calls bypass Relinkra "
    "relevance, budgeting, memory integration, Git intelligence, handoffs "
    "and metrics."
)
REMEDIATION_UNCLASSIFIED_ENGRAM = (
    "A direct Engram server is registered and could not be attributed to "
    "Gentleman or to Relinkra. This is allowed — Gentleman legitimately "
    "needs Engram for SDD workflow state. Keep direct Engram use to the "
    "workflows that require it, and route agent-neutral project memory and "
    "handoffs through Relinkra so records are not written twice."
)
REMEDIATION_UNVERIFIED = (
    "Relinkra has not been observed serving this host. Register it, start "
    "the host, and re-run 'relinkra doctor' — configuration presence alone "
    "is never treated as readiness."
)


# ---------------------------------------------------------------------------
# Agent instruction contract
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentInstruction:
    """One host-neutral rule an agent should follow.

    Structured rather than prose so a future ``relinkra connect <agent>``
    can render it into whatever a given host accepts — a system prompt, a
    rules file, an MCP instructions field — without re-deriving the
    meaning each time.
    """

    instruction_id: str
    text: str
    rationale: str

    def to_dict(self) -> dict:
        return {
            "id": self.instruction_id,
            "text": self.text,
            "rationale": self.rationale,
        }


AGENT_GUIDANCE = (
    "Relinkra is the shared project context layer. When a task asks about "
    "architecture, callers, dependencies, impact, cross-module relationships, "
    "prior project decisions or memory, handoff continuity, or Git history, "
    "prefer checking the relevant Relinkra tool early when it can reduce "
    "broad exploration. Do not use it for trivial or purely local tasks. "
    "Verify stale/advisory evidence against current source. Native search, "
    "read, edit, test, and validation tools remain fully available."
)

AGENT_INSTRUCTIONS: Tuple[AgentInstruction, ...] = (
    AgentInstruction(
        "when_relinkra_helps",
        AGENT_GUIDANCE,
        "A compact host-neutral rule improves tool discoverability without "
        "forcing every request through Relinkra or replacing native tools.",
    ),
)


def agent_instruction_document() -> dict:
    """The structured connector metadata a future ``connect`` will emit.

    Returned as data, never written anywhere in this phase: R4C.0 does
    not touch a live host configuration.
    """
    return {
        "instruction_version": INSTRUCTION_VERSION,
        "applies_to": "any MCP-capable agent host",
        "written_to_host": False,
        "instructions": [item.to_dict() for item in AGENT_INSTRUCTIONS],
    }


def agent_instruction_text() -> str:
    """The same contract as plain lines, for documentation and previews."""
    return "\n".join(f"- {item.text}" for item in AGENT_INSTRUCTIONS)


# ---------------------------------------------------------------------------
# Recommended topology
# ---------------------------------------------------------------------------

#: The managed mode Relinkra recommends. Stated as requirements rather
#: than a diagram so ``doctor`` can name the one that is missing.
MANAGED_MODE_REQUIREMENTS: Tuple[str, ...] = (
    "Relinkra MCP is visible to the agent.",
    "Gentleman tools and workflows remain available.",
    "Direct CBM MCP is hidden or disabled for ordinary project context.",
    "Direct Engram access is limited to Gentleman workflows that require it.",
    "Project context, memory lookup and handoffs are routed through Relinkra.",
)

RECOMMENDED_TOPOLOGY: Tuple[str, ...] = (
    "agent -> Relinkra MCP -> CBM",
    "agent -> Relinkra MCP -> Engram",
    "agent -> Relinkra MCP -> Git",
    "Gentleman -> Engram (SDD-specific ownership)",
)


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------


@dataclass
class RoutingAssessment:
    """The complete verdict for one workspace.

    Everything ``doctor`` and ``connect routing`` render comes from here,
    so the two commands cannot describe the same machine differently.
    """

    context_route: str = ROUTE_UNVERIFIED
    cbm_ownership: str = CBM_UNKNOWN
    engram_ownership: str = ENGRAM_UNKNOWN
    metrics_trust: str = TRUST_UNVERIFIED
    duplicate_risk: str = DUPLICATE_UNVERIFIED
    duplicate_findings: Tuple[DuplicateRiskFinding, ...] = ()
    ladder: TrustLadder = field(default_factory=TrustLadder)
    hosts: Tuple[dict, ...] = ()
    #: Per-host verification rows (one per apply-capable connector), so
    #: doctor and check can show each host's evidence independently.
    host_verification: Tuple[dict, ...] = ()
    #: Everything worth telling the user, in priority order.
    remediation: Tuple[str, ...] = ()
    #: The single remediation that addresses the ROUTE specifically.
    #: Separate from the list because a check about routing that suggests
    #: fixing Engram ownership reads as a non-sequitur, and a
    #: non-sequitur is how users learn to ignore suggested actions.
    route_remediation: str = ""
    notes: Tuple[str, ...] = ()
    policy_version: str = POLICY_VERSION

    @property
    def bypass_detected(self) -> bool:
        return self.cbm_ownership in (
            CBM_DIRECTLY_EXPOSED,
            CBM_EXPLICITLY_ALLOWED_ADVANCED,
        )

    def to_dict(self) -> dict:
        return {
            "policy_version": self.policy_version,
            "context_route": self.context_route,
            "cbm_ownership": self.cbm_ownership,
            "engram_ownership": self.engram_ownership,
            "metrics_trust": self.metrics_trust,
            "duplicate_risk": self.duplicate_risk,
            "bypass_detected": self.bypass_detected,
            "duplicate_findings": [f.to_dict() for f in self.duplicate_findings],
            "trust_ladder": self.ladder.to_dict(),
            "hosts": list(self.hosts),
            "host_verification": list(self.host_verification),
            "remediation": list(self.remediation),
            "route_remediation": self.route_remediation,
            "notes": list(self.notes),
        }


__all__ = [
    "AGENT_INSTRUCTIONS",
    "AUTHORITY_GENTLEMAN",
    "AUTHORITY_RELINKRA",
    "BACKEND_CBM",
    "BACKEND_ENGRAM",
    "BACKEND_KINDS",
    "BACKEND_RELINKRA",
    "BACKEND_UNKNOWN",
    "CBM_DIRECTLY_EXPOSED",
    "CBM_EXPLICITLY_ALLOWED_ADVANCED",
    "CBM_OWNERSHIP_STATES",
    "CBM_RELINKRA_PRIVATE",
    "CBM_UNAVAILABLE",
    "CBM_UNKNOWN",
    "CONTEXT_ROUTE_STATES",
    "DETECTION_CONFIDENCES",
    "DETECTION_CONFLICTING",
    "DETECTION_DETECTED",
    "DETECTION_LIKELY",
    "DETECTION_UNKNOWN",
    "DUPLICATE_DETECTED",
    "DUPLICATE_KINDS",
    "DUPLICATE_NONE",
    "DUPLICATE_POSSIBLE",
    "DUPLICATE_RISK_STATES",
    "DUPLICATE_UNVERIFIED",
    "DUP_BACKEND_QUERY",
    "DUP_CONTEXT_RETRIEVAL",
    "DUP_PERSISTED_MEMORY",
    "DUP_TASK_RESULT",
    "DUP_TOKEN_ATTRIBUTION",
    "ENGRAM_DIRECT_UNCLASSIFIED",
    "ENGRAM_GENTLEMAN_MANAGED",
    "ENGRAM_OWNERSHIP_STATES",
    "ENGRAM_RELINKRA_MANAGED",
    "ENGRAM_SHARED_SEPARATED",
    "ENGRAM_UNAVAILABLE",
    "ENGRAM_UNKNOWN",
    "INSTRUCTION_VERSION",
    "AGENT_GUIDANCE",
    "MANAGED_MODE_REQUIREMENTS",
    "METRICS_TRUST_STATES",
    "OBSERVABILITY_HOST_CONFIG",
    "OBSERVABILITY_IN_PROCESS",
    "OBSERVABILITY_OUTSIDE_PROCESS",
    "OWNERSHIP_MATRIX",
    "POLICY_VERSION",
    "RECOMMENDED_TOPOLOGY",
    "RECORD_FULL",
    "RECORD_NONE",
    "RECORD_REFERENCE",
    "REMEDIATION_BYPASSED",
    "REMEDIATION_MIXED",
    "REMEDIATION_UNCLASSIFIED_ENGRAM",
    "REMEDIATION_UNVERIFIED",
    "ROUTE_BYPASSED",
    "ROUTE_DEGRADED",
    "ROUTE_MANAGED",
    "ROUTE_MIXED",
    "ROUTE_UNVERIFIED",
    "STAGE_BACKEND_BYPASS_ABSENT",
    "STAGE_CONFIGURATION_PRESENT",
    "STAGE_CONTEXT_ROUTE_MANAGED",
    "STAGE_HANDOFF_ROUND_TRIP",
    "STAGE_HANDSHAKE_VERIFIED",
    "STAGE_MCP_CONTRACT_CONFIGURED",
    "STAGE_METRICS_TRUSTWORTHY",
    "STAGE_NOT_PROVEN",
    "STAGE_PROTOCOL_COMPATIBLE",
    "STAGE_PROVEN",
    "STAGE_REAL_HOST_LAUNCH",
    "STAGE_REGISTRATION_DETECTED",
    "STAGE_REQUIRED_TOOLS_CALLABLE",
    "STAGE_STATES",
    "STAGE_TOOLS_VISIBLE",
    "STAGE_UNVERIFIED",
    "TRUST_DEGRADED",
    "TRUST_HIGH",
    "TRUST_STAGES",
    "TRUST_UNRELIABLE",
    "TRUST_UNVERIFIED",
    "AgentInstruction",
    "DuplicateRiskFinding",
    "OwnershipRule",
    "RouteInputs",
    "RoutingAssessment",
    "TrustLadder",
    "TrustStage",
    "aggregate_duplicate_risk",
    "agent_instruction_document",
    "agent_instruction_text",
    "authority_for",
    "classify_cbm_ownership",
    "classify_context_route",
    "classify_engram_ownership",
    "classify_metrics_trust",
    "duplicate_full_ownership",
    "duplicate_risk_findings",
]
