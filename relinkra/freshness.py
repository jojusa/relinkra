"""Deterministic, advisory freshness evaluation for Relinkra evidence.

Freshness is a typed observation, never a permission decision.  The model
prefers revision evidence for code-bound facts, uses time only where the
evidence class owns a meaningful lifetime, and returns ``UNKNOWN`` rather
than turning missing provenance into confidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Mapping, Optional


FRESHNESS_VERSION = "freshness-v1"
DEFAULT_MEMORY_FRESH_SECONDS = 30 * 24 * 60 * 60
DEFAULT_HANDOFF_FRESH_SECONDS = 7 * 24 * 60 * 60
_GIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")


class FreshnessState(str, Enum):
    FRESH = "fresh"
    AGING = "aging"
    STALE = "stale"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class RevisionRelationState(str, Enum):
    SAME = "same"
    ANCESTOR = "ancestor"
    DESCENDANT = "descendant"
    UNRELATED = "unrelated"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class RevisionRelation:
    state: RevisionRelationState
    distance: Optional[int] = None
    bounded: bool = True
    shallow: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "state": self.state.value,
            "distance": self.distance,
            "bounded": self.bounded,
            "shallow": self.shallow,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class FreshnessContext:
    as_of: str
    project_id: Optional[str] = None
    current_revision: Optional[str] = None
    dirty: Optional[bool] = None


@dataclass(frozen=True)
class RevisionSnapshot:
    """Registered-vs-current revision facts for one read surface.

    ``registered_revision`` is persisted metadata; ``current_revision`` is
    read from the live checkout.  Keeping both in one value prevents callers
    from accidentally presenting a registration snapshot as current HEAD.
    """

    registered_revision: Optional[str]
    current_revision: Optional[str]
    revision_source: str
    freshness: FreshnessResult
    relation: Optional[str]
    revision_distance: Optional[int]
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "registered_head_sha": self.registered_revision,
            "current_revision": self.current_revision,
            "revision_source": self.revision_source,
            "freshness": self.freshness.to_dict(),
            "relation": self.relation,
            "revision_distance": self.revision_distance,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class FreshnessResult:
    state: FreshnessState
    reason_code: str
    explanation: str
    observed_at: Optional[str] = None
    source_revision: Optional[str] = None
    current_revision: Optional[str] = None
    age_seconds: Optional[int] = None
    ttl_seconds: Optional[int] = None
    revision_distance: Optional[int] = None
    relation: Optional[str] = None
    trust_limitations: tuple[str, ...] = ()
    recommended_action: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "state": self.state.value,
            "reason_code": self.reason_code,
            "explanation": self.explanation,
            "observed_at": self.observed_at,
            "source_revision": self.source_revision,
            "current_revision": self.current_revision,
            "age_seconds": self.age_seconds,
            "ttl_seconds": self.ttl_seconds,
            "revision_distance": self.revision_distance,
            "relation": self.relation,
            "trust_limitations": list(self.trust_limitations),
            "recommended_action": self.recommended_action,
        }


def assess_revision_snapshot(
    registered_revision: Any,
    current_revision: Any,
    *,
    as_of: str,
    relation_resolver: Optional[RelationResolver] = None,
    dirty: Optional[bool] = None,
) -> RevisionSnapshot:
    """Evaluate persisted registration metadata against live Git.

    This is intentionally narrower than evidence freshness: it describes
    the workspace registration itself and is reused by project resolution,
    context packets, and diagnostics.  Missing live Git is explicit
    uncertainty, never a stale/fresh guess.
    """
    registered = normalize_git_revision(registered_revision)
    current = normalize_git_revision(current_revision)
    context = FreshnessContext(
        as_of=as_of,
        current_revision=current,
        dirty=dirty,
    )
    warnings: tuple[str, ...] = ()
    if current is None:
        freshness = _result(
            FreshnessState.UNKNOWN,
            "current_revision_unavailable",
            "The current repository revision could not be read from Git.",
            context=context,
            source_revision=registered,
            limitations=("registered snapshot cannot be compared with live Git",),
            action="Restore Git access and run the check again.",
        )
        warnings = ("current_revision_unavailable",)
        return RevisionSnapshot(
            registered, None, "registry", freshness, None, None, warnings
        )
    if registered is None:
        freshness = _result(
            FreshnessState.UNKNOWN,
            "registered_revision_missing",
            "The workspace has no valid registered Git revision snapshot.",
            context=context,
            limitations=("registration currency cannot be established",),
            action="Run the existing workspace registration workflow.",
        )
        warnings = ("registered_revision_missing",)
        return RevisionSnapshot(
            None, current, "registry", freshness, None, None, warnings
        )

    # Keep the registered workspace comparison on the same authoritative
    # revision primitive used by the rest of the freshness model.  In
    # particular, this preserves bounded ancestor distance and explicit
    # UNKNOWN results when Git cannot relate two revisions.
    freshness = _revision_result(
        evidence_type="registered_workspace",
        source_revision=registered,
        observed_at=None,
        context=context,
        resolver=relation_resolver,
        current_git_fact=True,
    )
    if freshness.state != FreshnessState.FRESH:
        warnings = ("registered_revision_differs",)
    return RevisionSnapshot(
        registered,
        current,
        "registry",
        freshness,
        freshness.relation,
        freshness.revision_distance,
        warnings,
    )


RelationResolver = Callable[[str, str], RevisionRelation]


_CONNECTOR_VALID = "valid"
_CONNECTOR_STALE_FINGERPRINT = "stale_fingerprint"
_CONNECTOR_EXPIRED = "expired"
_CONNECTOR_INVALID = "invalid"
_CONNECTOR_ABSENT = "absent"
_CONNECTOR_STATUSES = frozenset(
    {
        _CONNECTOR_VALID,
        _CONNECTOR_STALE_FINGERPRINT,
        _CONNECTOR_EXPIRED,
        _CONNECTOR_INVALID,
        _CONNECTOR_ABSENT,
    }
)


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _first_metadata(mapping: Mapping[str, Any], keys: tuple[str, ...]):
    """Return the first explicitly supplied non-None metadata value."""
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key], True
    return None, False


def _normalize_revision_metadata(
    mapping: Mapping[str, Any], keys: tuple[str, ...]
) -> tuple[Optional[str], bool]:
    """Normalize a revision while retaining malformed-vs-absent provenance."""
    normalized_value = None
    for key in keys:
        if key not in mapping or mapping[key] is None:
            continue
        normalized = normalize_git_revision(mapping[key])
        if normalized is None:
            return None, True
        if normalized_value is None:
            normalized_value = normalized
    return normalized_value, False


def _timestamp_issue(observed_at: Any, as_of: Any) -> Optional[str]:
    """Return a typed clock issue without treating future time as age zero."""
    if observed_at is None:
        return None
    observed = _parse_time(observed_at)
    current = _parse_time(as_of)
    if observed is None or current is None:
        return "timestamp_invalid"
    if observed > current:
        return "timestamp_from_future"
    return None


def _age_seconds(observed_at: Optional[str], as_of: str) -> Optional[int]:
    observed = _parse_time(observed_at)
    current = _parse_time(as_of)
    if observed is None or current is None:
        return None
    delta = (current - observed).total_seconds()
    return int(delta) if delta >= 0 else None


def _mapping(value: Any) -> Optional[Mapping[str, Any]]:
    """Return native evidence as a mapping without importing its owner."""
    if isinstance(value, Mapping):
        return value
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        try:
            rendered = to_dict()
        except Exception:
            return None
        return rendered if isinstance(rendered, Mapping) else None
    return None


def normalize_git_revision(value: Any) -> Optional[str]:
    """Return a portable Git SHA or ``None`` for untrusted metadata.

    Revision fields cross storage and explainability boundaries.  Accept only
    complete or safely abbreviated object names, never paths, refs, or opaque
    source-tool strings that could otherwise be projected back to callers.
    """
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not _GIT_SHA_RE.fullmatch(candidate):
        return None
    return candidate.lower()


def equivalent_git_revision(left: Any, right: Any) -> bool:
    """Compare validated full or safely abbreviated Git object names."""
    first = normalize_git_revision(left)
    second = normalize_git_revision(right)
    if not first or not second:
        return False
    if first == second:
        return True
    return min(len(first), len(second)) >= 7 and (
        first.startswith(second) or second.startswith(first)
    )


def _same_revision(left: Any, right: Any) -> bool:
    """Private compatibility alias for the shared safe comparison policy."""
    return equivalent_git_revision(left, right)


def _trust_stage(stages: Any, name: str) -> Optional[Mapping[str, Any]]:
    """Find one native CBM TrustStage in object or serialized form."""
    if not isinstance(stages, (list, tuple)):
        return None
    wanted = name.strip().lower()
    matches = []
    for raw in stages:
        stage = _mapping(raw)
        if stage is None:
            stage_name = str(getattr(raw, "name", "")).strip().lower()
            if stage_name == wanted:
                matches.append({
                    "name": getattr(raw, "name", ""),
                    "status": getattr(raw, "status", ""),
                    "detail": getattr(raw, "detail", ""),
                })
            continue
        if str(stage.get("name") or "").strip().lower() == wanted:
            matches.append(stage)
    if not matches:
        return None
    statuses = {
        str(stage.get("status") or "").strip().upper() for stage in matches
    }
    if len(matches) > 1 and len(statuses) > 1:
        # Conflicting native attestations are uncertainty, never PASS.
        return {"name": name, "status": "WARN"}
    return matches[0]


def _result(
    state: FreshnessState,
    code: str,
    explanation: str,
    *,
    context: FreshnessContext,
    observed_at: Optional[str] = None,
    source_revision: Optional[str] = None,
    age_seconds: Optional[int] = None,
    ttl_seconds: Optional[int] = None,
    relation: Optional[RevisionRelation] = None,
    limitations: tuple[str, ...] = (),
    action: Optional[str] = None,
) -> FreshnessResult:
    return FreshnessResult(
        state=state,
        reason_code=code,
        explanation=explanation,
        observed_at=observed_at,
        source_revision=normalize_git_revision(source_revision),
        current_revision=normalize_git_revision(context.current_revision),
        age_seconds=age_seconds,
        ttl_seconds=ttl_seconds,
        revision_distance=relation.distance if relation else None,
        relation=relation.state.value if relation else None,
        trust_limitations=limitations,
        recommended_action=action,
    )


def _metadata_unknown_result(
    *,
    code: str,
    explanation: str,
    context: FreshnessContext,
    observed_at: Optional[str] = None,
    source_revision: Optional[str] = None,
    limitation: str,
) -> FreshnessResult:
    return _result(
        FreshnessState.UNKNOWN,
        code,
        explanation,
        context=context,
        observed_at=observed_at,
        source_revision=source_revision,
        limitations=(limitation,),
        action="Refresh the source or independently verify its metadata.",
    )


def _same_revision_result(
    *,
    observed_at: Optional[str],
    source_revision: str,
    context: FreshnessContext,
    current_git_fact: bool,
    relation: Optional[RevisionRelation] = None,
) -> FreshnessResult:
    """Render direct and resolver-confirmed SAME relations consistently."""
    relation = relation or RevisionRelation(RevisionRelationState.SAME, distance=0)
    if context.dirty and not current_git_fact:
        return _result(
            FreshnessState.AGING,
            "dirty_worktree_uncertainty",
            "The committed revision matches, but uncommitted changes may differ.",
            context=context,
            observed_at=observed_at,
            source_revision=source_revision,
            relation=relation,
            limitations=("working tree contains uncommitted changes",),
            action="Inspect the working tree when present behavior matters.",
        )
    return _result(
        FreshnessState.FRESH,
        "same_revision",
        "The evidence is bound to the current Git revision.",
        context=context,
        observed_at=observed_at,
        source_revision=source_revision,
        relation=relation,
        limitations=(
            ("working tree contains uncommitted changes",) if context.dirty else ()
        ),
        action=(
            "Inspect uncommitted changes for workspace-sensitive questions."
            if context.dirty
            else None
        ),
    )


def _revision_result(
    *,
    evidence_type: str,
    source_revision: Optional[str],
    observed_at: Optional[str],
    context: FreshnessContext,
    resolver: Optional[RelationResolver],
    current_git_fact: bool = False,
) -> FreshnessResult:
    if not context.current_revision:
        return _result(
            FreshnessState.UNKNOWN,
            "current_revision_unavailable",
            "The current repository revision is unavailable.",
            context=context,
            observed_at=observed_at,
            source_revision=source_revision,
            limitations=("revision comparison unavailable",),
            action="Inspect the repository before relying on current-code claims.",
        )
    if not source_revision:
        return _result(
            FreshnessState.UNKNOWN,
            "source_revision_missing",
            "The evidence does not attest the revision it describes.",
            context=context,
            observed_at=observed_at,
            limitations=("source revision not attested",),
            action="Refresh the source or independently inspect the code.",
        )
    if _same_revision(source_revision, context.current_revision):
        return _same_revision_result(
            observed_at=observed_at,
            source_revision=source_revision,
            context=context,
            current_git_fact=current_git_fact,
        )
    if resolver is None:
        relation = RevisionRelation(
            RevisionRelationState.UNAVAILABLE,
            reason="revision relation resolver unavailable",
        )
    else:
        try:
            relation = resolver(source_revision, context.current_revision)
        except Exception:
            # Relation resolvers may cross a subprocess/repository boundary.
            # Their errors are neither evidence nor safe portable output.
            relation = RevisionRelation(
                RevisionRelationState.UNAVAILABLE,
                reason="revision relation resolver failed",
            )
        if not isinstance(relation, RevisionRelation):
            relation = RevisionRelation(
                RevisionRelationState.UNAVAILABLE,
                reason="revision relation resolver returned invalid evidence",
            )
    if relation.state == RevisionRelationState.SAME:
        return _same_revision_result(
            observed_at=observed_at,
            source_revision=source_revision,
            context=context,
            current_git_fact=current_git_fact,
            relation=relation,
        )
    if relation.state == RevisionRelationState.ANCESTOR:
        if relation.distance is not None and relation.distance <= 1:
            return _result(
                FreshnessState.AGING,
                "revision_behind",
                "The evidence revision is one bounded step behind current Git.",
                context=context,
                observed_at=observed_at,
                source_revision=source_revision,
                relation=relation,
                limitations=("code may have changed after the evidence revision",),
                action="Verify affected code when the intervening change is relevant.",
            )
        return _result(
            FreshnessState.STALE,
            "revision_stale",
            "The evidence revision is behind current Git.",
            context=context,
            observed_at=observed_at,
            source_revision=source_revision,
            relation=relation,
            limitations=("evidence describes an older code revision",),
            action="Refresh the source or inspect current code.",
        )
    if relation.state == RevisionRelationState.DESCENDANT:
        return _result(
            FreshnessState.UNKNOWN,
            "revision_from_future",
            "The evidence revision is not an ancestor of the current checkout.",
            context=context,
            observed_at=observed_at,
            source_revision=source_revision,
            relation=relation,
            limitations=("evidence may describe another checkout state",),
            action="Confirm the intended checkout and inspect code.",
        )
    return _result(
        FreshnessState.UNKNOWN,
        "revision_relation_unknown",
        "The evidence revision cannot be related to current Git with certainty.",
        context=context,
        observed_at=observed_at,
        source_revision=source_revision,
        relation=relation,
        limitations=(
            "shallow history limits revision comparison"
            if relation.shallow
            else "revision relationship unavailable",
        ),
        action="Independently inspect current code before relying on this evidence.",
    )


def _cbm_result(
    evidence: Mapping[str, Any],
    *,
    source_revision: Optional[str],
    observed_at: Optional[str],
    context: FreshnessContext,
    resolver: Optional[RelationResolver],
) -> FreshnessResult:
    """Adapt CBM's existing graph/trust evidence before revision fallback."""
    index_key = next(
        (
            key
            for key in ("index_status", "cbm_index_status", "native_index_status")
            if key in evidence
        ),
        None,
    )
    stages_key = next(
        (
            key
            for key in ("trust_stages", "cbm_trust_stages", "native_trust_stages")
            if key in evidence
        ),
        None,
    )

    graph_head: Optional[str] = None
    if index_key is None:
        return _result(
            FreshnessState.UNKNOWN,
            "cbm_graph_revision_missing",
            "CBM evidence does not attest the graph revision.",
            context=context,
            observed_at=observed_at,
            limitations=("native CBM graph revision is unavailable",),
            action="Run the existing CBM trust check before using the graph.",
        )
    index_status = _mapping(evidence.get(index_key))
    if index_status is None:
        return _result(
            FreshnessState.UNKNOWN,
            "cbm_index_evidence_invalid",
            "CBM index freshness evidence has an invalid shape.",
            context=context,
            observed_at=observed_at,
            limitations=("native CBM index evidence is unusable",),
            action="Run the existing CBM trust check before using the graph.",
        )
    git_facts = _mapping(index_status.get("git"))
    graph_metadata = git_facts if git_facts is not None else index_status
    graph_head, graph_revision_malformed = _normalize_revision_metadata(
        graph_metadata, ("head_sha", "revision")
    )
    if graph_revision_malformed:
        return _metadata_unknown_result(
            code="cbm_graph_revision_invalid",
            explanation="CBM index evidence contains malformed revision metadata.",
            context=context,
            observed_at=observed_at,
            limitation="native CBM graph revision is malformed",
        )
    if not graph_head:
        return _result(
            FreshnessState.UNKNOWN,
            "cbm_graph_revision_missing",
            "CBM index evidence does not attest the graph revision.",
            context=context,
            observed_at=observed_at,
            limitations=("native CBM graph revision is unavailable",),
            action="Run the existing CBM trust check before using the graph.",
        )
    if not context.current_revision:
        return _result(
            FreshnessState.UNKNOWN,
            "current_revision_unavailable",
            "The current repository revision is unavailable.",
            context=context,
            observed_at=observed_at,
            source_revision=graph_head,
            limitations=("CBM graph cannot be compared with repository HEAD",),
            action="Restore Git metadata before using the CBM graph.",
        )
    if not _same_revision(graph_head, context.current_revision):
        return _result(
            FreshnessState.STALE,
            "cbm_graph_revision_mismatch",
            "The CBM graph is bound to a different repository revision.",
            context=context,
            observed_at=observed_at,
            source_revision=graph_head,
            limitations=("native CBM graph does not match current HEAD",),
            action="Re-index the workspace with the existing CBM workflow.",
        )

    # A current graph SHA is necessary but not sufficient: without the
    # native trust ladder's graph verdict, CBM evidence cannot be promoted to
    # FRESH.  Treat an absent, malformed, or incomplete stage list the same as
    # an absent graph stage and fail honest to UNKNOWN.
    stages = evidence.get(stages_key) if stages_key is not None else None
    graph_stage = _trust_stage(stages, "CBM graph")
    if graph_stage is None:
        return _result(
            FreshnessState.UNKNOWN,
            "cbm_graph_trust_missing",
            "CBM trust evidence does not include a graph verdict.",
            context=context,
            observed_at=observed_at,
            source_revision=graph_head or source_revision,
            limitations=("native CBM graph trust was not established",),
            action="Run the existing CBM trust check before using the graph.",
        )
    if str(graph_stage.get("status") or "").strip().upper() != "PASS":
        return _result(
            FreshnessState.UNKNOWN,
            "cbm_graph_trust_unverified",
            "The native CBM trust ladder did not verify the graph as current.",
            context=context,
            observed_at=observed_at,
            source_revision=graph_head or source_revision,
            limitations=("native CBM graph trust did not pass",),
            action="Follow the existing CBM trust-stage remediation.",
        )

    # Native index evidence is the graph's own binding.  When supplied it
    # outranks a copied source_revision that may describe a different fact.
    return _revision_result(
        evidence_type="cbm",
        source_revision=graph_head or source_revision,
        observed_at=observed_at,
        context=context,
        resolver=resolver,
    )


def _connector_result(
    evidence: Mapping[str, Any],
    *,
    observed_at: Optional[str],
    source_revision: Optional[str],
    context: FreshnessContext,
) -> FreshnessResult:
    """Adapt connector verification authority; TTL alone never proves it."""
    envelope = _mapping(evidence.get("verification")) or evidence
    record = _mapping(envelope.get("record")) or _mapping(
        evidence.get("verification_record")
    )
    if record is None:
        record = envelope

    raw_observed_at, has_record_timestamp = _first_metadata(
        record, ("timestamp", "observed_at")
    )
    observed_at = raw_observed_at if has_record_timestamp else observed_at
    timestamp_issue = _timestamp_issue(observed_at, context.as_of)
    if timestamp_issue:
        return _metadata_unknown_result(
            code=timestamp_issue,
            explanation=(
                "Connector verification timestamp is not trustworthy."
                if timestamp_issue == "timestamp_from_future"
                else "Connector verification timestamp is malformed."
            ),
            context=context,
            observed_at=observed_at,
            source_revision=source_revision,
            limitation=(
                "connector timestamp is from the future"
                if timestamp_issue == "timestamp_from_future"
                else "connector timestamp is malformed"
            ),
        )
    raw_revision, has_record_revision = _first_metadata(record, ("revision",))
    if has_record_revision:
        source_revision = normalize_git_revision(raw_revision)
        if source_revision is None:
            return _metadata_unknown_result(
                code="source_revision_invalid",
                explanation="Connector verification contains malformed revision metadata.",
                context=context,
                observed_at=observed_at,
                limitation="connector revision metadata is malformed",
            )
    ttl_raw = record.get("ttl_seconds")
    try:
        ttl = (
            int(ttl_raw)
            if ttl_raw is not None and not isinstance(ttl_raw, bool)
            else None
        )
    except (TypeError, ValueError):
        ttl = None
    age = _age_seconds(observed_at, context.as_of)

    status = None
    for container in (envelope, evidence, record):
        raw_status = (
            container.get("verification_status")
            or container.get("assessment_status")
            or container.get("status")
        )
        candidate = str(raw_status or "").strip().lower()
        if candidate in _CONNECTOR_STATUSES:
            status = candidate
            break

    raw_reasons = envelope.get("reasons")
    if raw_reasons is None:
        raw_reasons = evidence.get("reasons")
    if isinstance(raw_reasons, str):
        assessment_reasons = (raw_reasons,)
    elif isinstance(raw_reasons, (list, tuple)):
        assessment_reasons = tuple(
            str(reason) for reason in raw_reasons if str(reason).strip()
        )
    else:
        assessment_reasons = ()
    revision_mismatch_reasons = tuple(
        reason
        for reason in assessment_reasons
        if "different git revision" in reason.lower()
    )

    if status == _CONNECTOR_STALE_FINGERPRINT:
        return _result(
            FreshnessState.STALE,
            "verification_stale_fingerprint",
            "The connector verification authority rejected the launch fingerprint.",
            context=context,
            observed_at=observed_at,
            source_revision=source_revision,
            age_seconds=age,
            ttl_seconds=ttl,
            limitations=("connector launch contract changed",),
            action="Run the connector's existing verification workflow.",
        )
    if status == _CONNECTOR_EXPIRED:
        return _result(
            FreshnessState.STALE,
            "verification_expired",
            "The connector verification authority reports expired evidence.",
            context=context,
            observed_at=observed_at,
            source_revision=source_revision,
            age_seconds=age,
            ttl_seconds=ttl,
            limitations=("connector proof expired",),
            action="Refresh connector verification.",
        )
    if (
        status == _CONNECTOR_INVALID
        and revision_mismatch_reasons
        and len(revision_mismatch_reasons) == len(assessment_reasons)
    ):
        return _result(
            FreshnessState.STALE,
            "verification_revision_mismatch",
            "The connector verification authority rejected a different Git revision.",
            context=context,
            observed_at=observed_at,
            source_revision=source_revision,
            age_seconds=age,
            ttl_seconds=ttl,
            limitations=("connector proof does not match current HEAD",),
            action="Refresh connector verification for the current revision.",
        )
    if status in {_CONNECTOR_INVALID, _CONNECTOR_ABSENT}:
        return _result(
            FreshnessState.UNKNOWN,
            "verification_unavailable",
            "The connector verification authority has no usable current proof.",
            context=context,
            observed_at=observed_at,
            source_revision=source_revision,
            age_seconds=age,
            ttl_seconds=ttl,
            limitations=("connector verification is absent or invalid",),
            action="Run the connector's existing verification workflow.",
        )

    actual_host = str(record.get("host") or "").strip().lower()
    expected_host = str(
        evidence.get("expected_host")
        or evidence.get("current_host")
        or evidence.get("connector_id")
        or ""
    ).strip().lower()
    if actual_host and expected_host and actual_host != expected_host:
        return _result(
            FreshnessState.STALE,
            "verification_host_mismatch",
            "The connector proof belongs to a different host.",
            context=context,
            observed_at=observed_at,
            source_revision=source_revision,
            age_seconds=age,
            ttl_seconds=ttl,
            limitations=("connector host identity differs",),
            action="Verify the intended connector host.",
        )

    actual_fingerprint = str(record.get("registration_fingerprint") or "").strip()
    expected_fingerprint = str(
        evidence.get("current_registration_fingerprint")
        or evidence.get("current_fingerprint")
        or evidence.get("verification_fingerprint")
        or ""
    ).strip()
    if (
        actual_fingerprint
        and expected_fingerprint
        and actual_fingerprint != expected_fingerprint
    ):
        return _result(
            FreshnessState.STALE,
            "verification_stale_fingerprint",
            "The connector proof was made against a different launch contract.",
            context=context,
            observed_at=observed_at,
            source_revision=source_revision,
            age_seconds=age,
            ttl_seconds=ttl,
            limitations=("connector launch contract changed",),
            action="Run the connector's existing verification workflow.",
        )

    if (
        source_revision
        and context.current_revision
        and not _same_revision(source_revision, context.current_revision)
    ):
        return _result(
            FreshnessState.STALE,
            "verification_revision_mismatch",
            "The connector proof belongs to a different Git revision.",
            context=context,
            observed_at=observed_at,
            source_revision=source_revision,
            age_seconds=age,
            ttl_seconds=ttl,
            limitations=("connector proof does not match current HEAD",),
            action="Refresh connector verification for the current revision.",
        )

    stage_result = envelope.get("stage_result")
    if stage_result is None:
        stage_result = evidence.get("stage_result")
    stages = _mapping(record.get("stages")) or _mapping(envelope.get("stages"))
    selected_stage = str(
        evidence.get("stage") or evidence.get("verification_stage") or ""
    ).strip()
    if selected_stage and stages is not None:
        stage_result = stages.get(selected_stage)
    if stage_result is False or envelope.get("locally_verified") is False:
        return _result(
            FreshnessState.UNKNOWN,
            "verification_stage_unproven",
            "The connector's current verification did not prove the requested stage.",
            context=context,
            observed_at=observed_at,
            source_revision=source_revision,
            age_seconds=age,
            ttl_seconds=ttl,
            limitations=("connector verification stage was not achieved",),
            action="Complete the connector's existing staged verification.",
        )

    if status != _CONNECTOR_VALID:
        return _result(
            FreshnessState.UNKNOWN,
            "verification_authority_missing",
            "TTL alone cannot establish connector verification freshness.",
            context=context,
            observed_at=observed_at,
            source_revision=source_revision,
            age_seconds=age,
            ttl_seconds=ttl,
            limitations=("native connector verification status is unavailable",),
            action="Use the connector's existing verification assessment.",
        )
    # ``assess_verification`` owns the record lifetime.  Re-applying TTL here
    # would create a second clock/expiry authority that can contradict the
    # native assessment.  Age and TTL remain useful advisory metadata only.
    return _result(
        FreshnessState.FRESH,
        "verification_authority_valid",
        "The connector's existing verification authority reports current evidence.",
        context=context,
        observed_at=observed_at,
        source_revision=source_revision,
        age_seconds=age,
        ttl_seconds=ttl,
    )


def evaluate_freshness(
    evidence_type: str,
    evidence: Mapping[str, Any],
    context: FreshnessContext,
    *,
    relation_resolver: Optional[RelationResolver] = None,
) -> FreshnessResult:
    """Evaluate one evidence record without hiding, deleting, or gating it."""
    kind = str(evidence_type or "").strip().lower()
    raw_observed_at, has_observed_at = _first_metadata(
        evidence, ("observed_at", "timestamp")
    )
    observed_at = raw_observed_at if has_observed_at else None
    source_revision, revision_malformed = _normalize_revision_metadata(
        evidence, ("source_revision", "commit_sha", "revision", "head_sha")
    )
    context = FreshnessContext(
        as_of=context.as_of,
        project_id=context.project_id,
        current_revision=normalize_git_revision(context.current_revision),
        dirty=context.dirty,
    )

    evidence_project = evidence.get("project_id")
    if (
        evidence_project
        and context.project_id
        and str(evidence_project) != str(context.project_id)
    ):
        return _result(
            FreshnessState.STALE,
            "project_identity_mismatch",
            "The evidence belongs to a different logical project.",
            context=context,
            observed_at=observed_at,
            source_revision=source_revision,
            limitations=("logical project identity differs",),
            action="Resolve the project identity conflict before reuse.",
        )

    if kind in {"static", "registry", "project_identity"}:
        return _result(
            FreshnessState.NOT_APPLICABLE,
            "static_evidence",
            "This structural evidence has no meaningful time-to-live.",
            context=context,
            observed_at=observed_at,
        )

    if kind in {"memory", "handoff", "code", "cbm", "git", "connector"}:
        if revision_malformed:
            return _metadata_unknown_result(
                code="source_revision_invalid",
                explanation="The evidence contains malformed revision metadata.",
                context=context,
                observed_at=observed_at,
                limitation="revision metadata is malformed",
            )
        timestamp_issue = _timestamp_issue(observed_at, context.as_of)
        if timestamp_issue:
            return _metadata_unknown_result(
                code=timestamp_issue,
                explanation=(
                    "The evidence timestamp is from the future."
                    if timestamp_issue == "timestamp_from_future"
                    else "The evidence timestamp is malformed."
                ),
                context=context,
                observed_at=observed_at,
                source_revision=source_revision,
                limitation=(
                    "observed timestamp is from the future"
                    if timestamp_issue == "timestamp_from_future"
                    else "observed timestamp is malformed"
                ),
            )

    if kind == "cbm":
        return _cbm_result(
            evidence,
            source_revision=source_revision,
            observed_at=observed_at,
            context=context,
            resolver=relation_resolver,
        )

    if kind == "code":
        return _revision_result(
            evidence_type=kind,
            source_revision=source_revision,
            observed_at=observed_at,
            context=context,
            resolver=relation_resolver,
        )

    if kind in {"memory", "handoff"} and source_revision:
        return _revision_result(
            evidence_type=kind,
            source_revision=source_revision,
            observed_at=observed_at,
            context=context,
            resolver=relation_resolver,
        )

    if kind == "git":
        return _revision_result(
            evidence_type=kind,
            source_revision=source_revision or context.current_revision,
            observed_at=observed_at,
            context=context,
            resolver=relation_resolver,
            current_git_fact=True,
        )

    if kind == "connector":
        return _connector_result(
            evidence,
            observed_at=observed_at,
            source_revision=source_revision,
            context=context,
        )

    if kind not in {"memory", "handoff"}:
        return _result(
            FreshnessState.UNKNOWN,
            "unsupported_evidence_type",
            "No freshness policy exists for this evidence type.",
            context=context,
            observed_at=observed_at,
            source_revision=source_revision,
            limitations=("evidence type is not recognized",),
            action="Verify independently when currency matters.",
        )

    age = _age_seconds(observed_at, context.as_of)
    if age is None:
        return _result(
            FreshnessState.UNKNOWN,
            "timestamp_unknown",
            "No usable timestamp or revision establishes freshness.",
            context=context,
            observed_at=observed_at,
            source_revision=source_revision,
            limitations=("freshness provenance incomplete",),
            action="Verify independently when currency matters.",
        )

    threshold = (
        DEFAULT_HANDOFF_FRESH_SECONDS
        if kind == "handoff"
        else DEFAULT_MEMORY_FRESH_SECONDS
    )
    if age <= threshold:
        return _result(
            FreshnessState.FRESH,
            "age_within_advisory_window",
            "The evidence is within its advisory age window.",
            context=context,
            observed_at=observed_at,
            age_seconds=age,
            ttl_seconds=threshold,
            limitations=("no revision binding",),
        )
    return _result(
        FreshnessState.AGING,
        "old_without_revision",
        "The evidence is old, but age alone does not make it invalid.",
        context=context,
        observed_at=observed_at,
        age_seconds=age,
        ttl_seconds=threshold,
        limitations=("no revision binding", "age is advisory only"),
        action="Verify independently when the fact may have changed.",
    )
