"""Ecosystem metrics vocabulary and typed records (R4C.0).

The types a later telemetry phase will fill in. Nothing here collects
anything, and that is deliberate — the shape has to be right BEFORE the
first number is recorded, because the first number is the one everyone
quotes afterwards.

Two mistakes this module is built to prevent.

ATTRIBUTING THE ECOSYSTEM TO ONE COMPONENT. "CBM saved 40% of tokens" is
the easy story and almost never the true one. The saving comes from
relevance ranking, budgeting, deduplication, handoff reuse and Git
intelligence together — and it is reduced, invisibly, every time the
agent explores files directly. So every sample names its
:data:`METRIC_SOURCES` contributor, and ``direct_agent_exploration`` and
``unknown_external`` are first-class sources rather than a rounding
error.

REPORTING A NUMBER NOBODY MEASURED. A metric this runtime cannot observe
gets :data:`OBSERVABILITY_UNAVAILABLE` and a ``None`` value, never a
plausible zero. :func:`empty_record` builds exactly that: the complete
metric set, entirely unmeasured, which is the honest state of telemetry
in R4C.0.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .backend_policy import (
    METRICS_TRUST_STATES,
    TRUST_UNVERIFIED,
)

#: Bumped when the shape of a rendered metrics record changes.
METRICS_VERSION = "relinkra.metrics/v1"


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

SOURCE_REGISTRY = "registry"
SOURCE_ENGRAM = "engram"
SOURCE_CBM = "cbm"
SOURCE_GIT = "git"
SOURCE_RELEVANCE = "relevance"
SOURCE_BUDGET = "budget"
SOURCE_HANDOFF = "handoff"
SOURCE_DEDUPLICATION = "deduplication"
#: Work the agent did on its own — reading files, grepping, guessing.
#: Not a failure, but it is context Relinkra neither delivered nor
#: budgeted, so it must be attributable to something other than Relinkra.
SOURCE_DIRECT_AGENT_EXPLORATION = "direct_agent_exploration"
#: Anything reaching the agent from outside the observed route. The
#: bucket that keeps the others honest.
SOURCE_UNKNOWN_EXTERNAL = "unknown_external"

METRIC_SOURCES: Tuple[str, ...] = (
    SOURCE_REGISTRY,
    SOURCE_ENGRAM,
    SOURCE_CBM,
    SOURCE_GIT,
    SOURCE_RELEVANCE,
    SOURCE_BUDGET,
    SOURCE_HANDOFF,
    SOURCE_DEDUPLICATION,
    SOURCE_DIRECT_AGENT_EXPLORATION,
    SOURCE_UNKNOWN_EXTERNAL,
)


# ---------------------------------------------------------------------------
# Observability
# ---------------------------------------------------------------------------

#: Counted or measured directly by Relinkra.
OBSERVABILITY_OBSERVED = "observed"
#: Computed from observed values. Inherits their trust, never exceeds it.
OBSERVABILITY_DERIVED = "derived"
#: This runtime cannot observe it at all. Permanent for anything that
#: happens entirely inside the agent's process.
OBSERVABILITY_UNAVAILABLE = "unavailable"
#: Observable in principle, not instrumented yet.
OBSERVABILITY_UNVERIFIED = "unverified"

OBSERVABILITY_LEVELS: Tuple[str, ...] = (
    OBSERVABILITY_OBSERVED,
    OBSERVABILITY_DERIVED,
    OBSERVABILITY_UNAVAILABLE,
    OBSERVABILITY_UNVERIFIED,
)


# ---------------------------------------------------------------------------
# Units
# ---------------------------------------------------------------------------

UNIT_TOKENS = "tokens"
UNIT_COUNT = "count"
UNIT_MILLISECONDS = "milliseconds"
UNIT_RATIO = "ratio"
UNIT_STATE = "state"
UNITS: Tuple[str, ...] = (
    UNIT_TOKENS,
    UNIT_COUNT,
    UNIT_MILLISECONDS,
    UNIT_RATIO,
    UNIT_STATE,
)


# ---------------------------------------------------------------------------
# Metric definitions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MetricDefinition:
    """What one ecosystem metric means and who could ever measure it.

    ``instrumentable`` records whether Relinkra could measure it AT ALL
    from inside its own process — not whether it does today. A metric
    marked false stays unavailable no matter how much instrumentation
    gets added later, because the event happens somewhere Relinkra is
    not.
    """

    metric: str
    unit: str
    sources: Tuple[str, ...]
    instrumentable: bool
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "metric": self.metric,
            "unit": self.unit,
            "sources": list(self.sources),
            "instrumentable": self.instrumentable,
            "note": self.note,
        }


METRIC_DEFINITIONS: Tuple[MetricDefinition, ...] = (
    MetricDefinition(
        "total_task_tokens",
        UNIT_TOKENS,
        (SOURCE_UNKNOWN_EXTERNAL,),
        False,
        "Belongs to the agent's own accounting; Relinkra sees only what it "
        "delivered.",
    ),
    MetricDefinition(
        "context_tokens_delivered",
        UNIT_TOKENS,
        (SOURCE_BUDGET, SOURCE_RELEVANCE, SOURCE_CBM, SOURCE_ENGRAM, SOURCE_GIT),
        True,
        "The size of the packets Relinkra actually returned.",
    ),
    MetricDefinition(
        "tokens_removed_by_budget",
        UNIT_TOKENS,
        (SOURCE_BUDGET,),
        True,
        "What the budgeter shed. A saving only when the agent did not then "
        "fetch it another way.",
    ),
    MetricDefinition(
        "tool_calls",
        UNIT_COUNT,
        (SOURCE_UNKNOWN_EXTERNAL,),
        False,
        "Relinkra counts calls to itself; the agent's other tools are its own.",
    ),
    MetricDefinition(
        "files_explored",
        UNIT_COUNT,
        (SOURCE_DIRECT_AGENT_EXPLORATION,),
        False,
        "Direct file reads happen in the agent's process.",
    ),
    MetricDefinition(
        "cbm_queries", UNIT_COUNT, (SOURCE_CBM,), True,
        "Only those issued through Relinkra; a direct registration is invisible.",
    ),
    MetricDefinition(
        "engram_queries", UNIT_COUNT, (SOURCE_ENGRAM,), True,
        "Only those issued through Relinkra.",
    ),
    MetricDefinition("git_queries", UNIT_COUNT, (SOURCE_GIT,), True),
    MetricDefinition(
        "duplicate_retrievals_avoided",
        UNIT_COUNT,
        (SOURCE_DEDUPLICATION,),
        True,
        "Repeat retrievals Relinkra collapsed inside one operation.",
    ),
    MetricDefinition(
        "duplicate_retrievals_detected",
        UNIT_COUNT,
        (SOURCE_DEDUPLICATION, SOURCE_UNKNOWN_EXTERNAL),
        True,
        "Observable on Relinkra's own side only; a bypassing agent is not "
        "counted here.",
    ),
    MetricDefinition(
        "handoff_reuse", UNIT_COUNT, (SOURCE_HANDOFF,), True,
        "Handoffs consumed by an agent other than the one that wrote them.",
    ),
    MetricDefinition(
        "time_to_first_useful_action",
        UNIT_MILLISECONDS,
        (SOURCE_UNKNOWN_EXTERNAL,),
        False,
        "Requires knowing when the agent acted, which Relinkra does not see.",
    ),
    MetricDefinition(
        "total_task_duration", UNIT_MILLISECONDS, (SOURCE_UNKNOWN_EXTERNAL,), False,
    ),
    MetricDefinition(
        "rework", UNIT_COUNT, (SOURCE_GIT, SOURCE_UNKNOWN_EXTERNAL), False,
        "Partly inferable from Git churn, but attributing it to a task needs "
        "the agent's own record.",
    ),
    MetricDefinition(
        "tests_quality_result", UNIT_STATE, (SOURCE_UNKNOWN_EXTERNAL,), False,
        "Produced by the project's own test run, not by Relinkra.",
    ),
    MetricDefinition(
        "attribution_trust", UNIT_STATE, (SOURCE_REGISTRY,), True,
        "The routing verdict this record was collected under.",
    ),
)

METRIC_DEFINITIONS_BY_NAME: Dict[str, MetricDefinition] = {
    definition.metric: definition for definition in METRIC_DEFINITIONS
}


# ---------------------------------------------------------------------------
# Samples and records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MetricSample:
    """One measurement, or one honest absence of a measurement.

    ``value`` is ``Optional`` on purpose. A metric that was not measured
    holds ``None``, never ``0`` — a zero is a claim that something did
    not happen, and an unmeasured metric makes no claim at all.
    """

    metric: str
    value: Optional[float]
    unit: str
    source: str
    observability: str
    trust: str
    detail: str = ""

    @property
    def measured(self) -> bool:
        return self.value is not None and self.observability in (
            OBSERVABILITY_OBSERVED,
            OBSERVABILITY_DERIVED,
        )

    def to_dict(self) -> dict:
        return {
            "metric": self.metric,
            "value": self.value,
            "unit": self.unit,
            "source": self.source,
            "observability": self.observability,
            "trust": self.trust,
            "measured": self.measured,
            "detail": self.detail,
        }

    @classmethod
    def unmeasured(
        cls,
        definition: MetricDefinition,
        *,
        trust: str = TRUST_UNVERIFIED,
        detail: str = "",
    ) -> "MetricSample":
        """A sample for a metric nothing has measured.

        Chooses between ``unavailable`` and ``unverified`` from the
        definition itself: a metric Relinkra can never see is
        permanently unavailable, while one it simply has not
        instrumented yet is unverified. Collapsing the two would hide
        which gaps are closeable.
        """
        return cls(
            metric=definition.metric,
            value=None,
            unit=definition.unit,
            source=definition.sources[0] if definition.sources else SOURCE_UNKNOWN_EXTERNAL,
            observability=(
                OBSERVABILITY_UNVERIFIED
                if definition.instrumentable
                else OBSERVABILITY_UNAVAILABLE
            ),
            trust=trust,
            detail=detail or definition.note,
        )


@dataclass
class EcosystemMetricsRecord:
    """One task's ecosystem measurements, at whatever trust the route allows.

    ``trust`` is a property of the RECORD, not of any single sample: a
    number collected while an agent was also querying a backend directly
    is not more believable because it was measured carefully. It is the
    route that decides, which is why the field is filled from
    :func:`~relinkra.backend_policy.classify_metrics_trust`.
    """

    project_id: str = ""
    task_id: str = ""
    context_route: str = ""
    trust: str = TRUST_UNVERIFIED
    samples: List[MetricSample] = field(default_factory=list)
    metrics_version: str = METRICS_VERSION

    @property
    def measured_count(self) -> int:
        return sum(1 for sample in self.samples if sample.measured)

    def by_metric(self) -> Dict[str, MetricSample]:
        return {sample.metric: sample for sample in self.samples}

    def sources_used(self) -> Tuple[str, ...]:
        return tuple(sorted({sample.source for sample in self.samples}))

    def to_dict(self) -> dict:
        return {
            "metrics_version": self.metrics_version,
            "project_id": self.project_id,
            "task_id": self.task_id,
            "context_route": self.context_route,
            "trust": self.trust,
            "measured_count": self.measured_count,
            "total_metrics": len(self.samples),
            "sources_used": list(self.sources_used()),
            "samples": [sample.to_dict() for sample in self.samples],
        }


def empty_record(
    *,
    project_id: str = "",
    task_id: str = "",
    context_route: str = "",
    trust: str = TRUST_UNVERIFIED,
    definitions: Sequence[MetricDefinition] = METRIC_DEFINITIONS,
) -> EcosystemMetricsRecord:
    """The complete metric set with nothing measured.

    This is what R4C.0 can honestly produce, and it is a deliverable
    rather than a placeholder: a consumer can already see every metric
    that will exist, which source will feed it, and which ones no amount
    of instrumentation will ever fill.
    """
    if trust not in METRICS_TRUST_STATES:
        raise ValueError(f"unsupported metrics trust state: {trust!r}")
    return EcosystemMetricsRecord(
        project_id=project_id,
        task_id=task_id,
        context_route=context_route,
        trust=trust,
        samples=[
            MetricSample.unmeasured(definition, trust=trust)
            for definition in definitions
        ],
    )


__all__ = [
    "METRICS_VERSION",
    "METRIC_DEFINITIONS",
    "METRIC_DEFINITIONS_BY_NAME",
    "METRIC_SOURCES",
    "OBSERVABILITY_DERIVED",
    "OBSERVABILITY_LEVELS",
    "OBSERVABILITY_OBSERVED",
    "OBSERVABILITY_UNAVAILABLE",
    "OBSERVABILITY_UNVERIFIED",
    "SOURCE_BUDGET",
    "SOURCE_CBM",
    "SOURCE_DEDUPLICATION",
    "SOURCE_DIRECT_AGENT_EXPLORATION",
    "SOURCE_ENGRAM",
    "SOURCE_GIT",
    "SOURCE_HANDOFF",
    "SOURCE_REGISTRY",
    "SOURCE_RELEVANCE",
    "SOURCE_UNKNOWN_EXTERNAL",
    "UNITS",
    "UNIT_COUNT",
    "UNIT_MILLISECONDS",
    "UNIT_RATIO",
    "UNIT_STATE",
    "UNIT_TOKENS",
    "EcosystemMetricsRecord",
    "MetricDefinition",
    "MetricSample",
    "empty_record",
]
