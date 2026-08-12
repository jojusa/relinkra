"""Deterministic contradiction detection for narrowly structured facts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Optional

from .freshness import equivalent_git_revision, normalize_git_revision


CONTRADICTION_VERSION = "contradiction-v1"
_ID_NAMESPACE = b"relinkra/contradiction/v1\x00"
_TEMPORAL_KEYS = frozenset({"status", "state", "resolution_state"})


class ContradictionType(str, Enum):
    SAME_KEY_DIFFERENT_VALUE = "same_key_different_value"
    REVISION_MISMATCH = "revision_mismatch"
    STATUS_CONFLICT = "status_conflict"
    IDENTITY_CONFLICT = "identity_conflict"
    SOURCE_DISAGREEMENT = "source_disagreement"
    TEMPORAL_SUPERSESSION = "temporal_supersession"


@dataclass(frozen=True)
class EvidenceFact:
    evidence_id: str
    authority_domain: str
    source_system: str
    subject: str
    key: str
    value: Any
    observed_at: Optional[str] = None
    revision: Optional[str] = None

    def canonical_value(self) -> str:
        return json.dumps(
            self.value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )


@dataclass(frozen=True)
class Contradiction:
    contradiction_id: str
    type: ContradictionType
    severity: str
    subject: str
    key: str
    evidence_refs: tuple[str, ...]
    values: tuple[Any, ...]
    source_systems: tuple[str, ...]
    observed_revisions: tuple[str, ...]
    observed_at: tuple[str, ...]
    explanation: str
    recommended_action: str
    newer_evidence_ref: Optional[str] = None
    newer_value: Any = None

    def to_dict(self) -> dict:
        rendered = {
            "contradiction_id": self.contradiction_id,
            "type": self.type.value,
            "severity": self.severity,
            "subject": self.subject,
            "key": self.key,
            "evidence_refs": list(self.evidence_refs),
            "values": list(self.values),
            "source_systems": list(self.source_systems),
            "observed_revisions": list(self.observed_revisions),
            "observed_at": list(self.observed_at),
            "explanation": self.explanation,
            "recommended_action": self.recommended_action,
        }
        if self.type == ContradictionType.TEMPORAL_SUPERSESSION:
            rendered["newer_evidence_ref"] = self.newer_evidence_ref
            rendered["newer_value"] = self.newer_value
        return rendered


def _parse_observed_at(value: Any, evidence_id: str) -> Optional[datetime]:
    """Parse usable chronology without rejecting legacy evidence records.

    Stored evidence remains useful even when old producers emitted malformed
    timestamps.  Such records participate in advisory conflicts, but cannot
    establish a temporal supersession relation.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _format_observed_at(value: datetime) -> str:
    timespec = "microseconds" if value.microsecond else "seconds"
    return value.isoformat(timespec=timespec).replace("+00:00", "Z")


def _canonical_observed_at(fact: EvidenceFact, key: str) -> Optional[str]:
    if fact.observed_at is None:
        return None
    if key in _TEMPORAL_KEYS:
        parsed = _parse_observed_at(fact.observed_at, fact.evidence_id)
        return _format_observed_at(parsed) if parsed is not None else None
    return fact.observed_at


def _fact_order_key(fact: EvidenceFact, key: str) -> tuple:
    return (
        fact.subject,
        fact.key,
        fact.authority_domain,
        fact.source_system,
        fact.evidence_id,
        fact.canonical_value(),
        _canonical_observed_at(fact, key) or "",
        fact.revision or "",
        fact.observed_at or "",
    )


def _stable_id(
    contradiction_type: ContradictionType,
    subject: str,
    key: str,
    facts: tuple[EvidenceFact, ...],
) -> str:
    evidence = [
        {
            "id": fact.evidence_id,
            "domain": fact.authority_domain,
            "source": fact.source_system,
            "value": fact.value,
            "observed_at": _canonical_observed_at(fact, key),
            "revision": fact.revision,
        }
        for fact in facts
    ]
    evidence.sort(
        key=lambda item: json.dumps(
            item, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
    )
    payload = {
        "type": contradiction_type.value,
        "subject": subject,
        "key": key,
        "evidence": evidence,
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return "ctr_" + hashlib.sha256(_ID_NAMESPACE + encoded).hexdigest()[:32]


def _build(
    contradiction_type: ContradictionType,
    subject: str,
    key: str,
    facts: tuple[EvidenceFact, ...],
) -> Contradiction:
    if contradiction_type == ContradictionType.TEMPORAL_SUPERSESSION:
        facts = tuple(
            sorted(
                facts,
                key=lambda fact: (
                    _parse_observed_at(fact.observed_at, fact.evidence_id),
                    _fact_order_key(fact, key),
                ),
            )
        )
    else:
        facts = tuple(sorted(facts, key=lambda fact: _fact_order_key(fact, key)))

    if contradiction_type == ContradictionType.TEMPORAL_SUPERSESSION:
        severity = "info"
        explanation = (
            "A newer structured value supersedes an older value from the same "
            "authority domain. Both remain available as evidence."
        )
        action = "Prefer the newer same-authority value for current status questions."
    elif contradiction_type == ContradictionType.REVISION_MISMATCH:
        severity = "warning"
        explanation = "Evidence for the same subject is bound to different revisions."
        action = "Prefer current revision-bound evidence and inspect code when needed."
    elif contradiction_type == ContradictionType.IDENTITY_CONFLICT:
        severity = "warning"
        explanation = "Structured evidence disagrees about logical identity."
        action = "Resolve the identity explicitly; preserve both records until confirmed."
    elif contradiction_type == ContradictionType.STATUS_CONFLICT:
        severity = "warning"
        explanation = "Same-authority structured status values conflict."
        action = "Refresh the source or resolve the status manually."
    elif contradiction_type == ContradictionType.SOURCE_DISAGREEMENT:
        severity = "warning"
        explanation = "Sources in the same authority domain report different values."
        action = "Refresh both sources and inspect the authoritative system."
    else:
        severity = "warning"
        explanation = "The same structured key has different values."
        action = "Inspect the underlying sources and resolve manually."
    values = tuple(
        json.loads(value)
        for value in sorted({fact.canonical_value() for fact in facts})
    )
    if key in _TEMPORAL_KEYS:
        observed_at = tuple(
            sorted(
                {
                    _format_observed_at(parsed)
                    if parsed is not None
                    else str(f.observed_at)
                    for f in facts
                    for parsed in [_parse_observed_at(f.observed_at, f.evidence_id)]
                    if f.observed_at is not None
                }
            )
        )
    else:
        observed_at = tuple(sorted({f.observed_at for f in facts if f.observed_at}))
    newer = (
        facts[-1]
        if contradiction_type == ContradictionType.TEMPORAL_SUPERSESSION
        else None
    )
    observed_revisions = tuple(
        sorted(
            {
                normalized
                for fact in facts
                for normalized in [normalize_git_revision(fact.revision)]
                if normalized is not None
            }
        )
    )
    return Contradiction(
        contradiction_id=_stable_id(contradiction_type, subject, key, facts),
        type=contradiction_type,
        severity=severity,
        subject=subject,
        key=key,
        evidence_refs=tuple(f.evidence_id for f in facts),
        values=values,
        source_systems=tuple(sorted({f.source_system for f in facts})),
        observed_revisions=observed_revisions,
        observed_at=observed_at,
        explanation=explanation,
        recommended_action=action,
        newer_evidence_ref=newer.evidence_id if newer else None,
        newer_value=newer.value if newer else None,
    )


def detect_contradictions(facts: Iterable[EvidenceFact]) -> list[Contradiction]:
    """Return stable, grouped contradictions; never select or delete a winner.

    Ordinary keys are compared only inside one authority domain. Identity and
    revision keys are the intentional exceptions: disagreement across domains
    is itself relevant evidence, but still advisory.
    """
    unique: dict[tuple, EvidenceFact] = {}
    for fact in facts:
        canonical = (
            fact.evidence_id,
            fact.authority_domain,
            fact.source_system,
            fact.subject,
            fact.key,
            fact.canonical_value(),
            fact.observed_at or "",
            fact.revision or "",
        )
        unique[canonical] = fact
    ordered = sorted(
        unique.values(),
        key=lambda fact: _fact_order_key(fact, fact.key),
    )
    groups: dict[tuple, list[EvidenceFact]] = {}
    for fact in ordered:
        cross_domain = fact.key in {
            "project_id", "repository_identity", "workspace_id", "revision"
        }
        group_key = (
            fact.subject,
            fact.key,
            "*" if cross_domain else fact.authority_domain,
        )
        groups.setdefault(group_key, []).append(fact)

    found: list[Contradiction] = []
    for (subject, key, _domain), members in sorted(groups.items()):
        values = {member.canonical_value() for member in members}
        if len(values) <= 1:
            continue
        if key == "revision" and all(
            equivalent_git_revision(members[0].value, member.value)
            for member in members[1:]
        ):
            continue
        facts_tuple = tuple(members)
        if key == "revision":
            contradiction_type = ContradictionType.REVISION_MISMATCH
        elif key in {"project_id", "repository_identity", "workspace_id"}:
            contradiction_type = ContradictionType.IDENTITY_CONFLICT
        elif key in _TEMPORAL_KEYS:
            timestamps = [
                _parse_observed_at(member.observed_at, member.evidence_id)
                if member.observed_at is not None
                else None
                for member in members
            ]
            if all(timestamp is not None for timestamp in timestamps) and len(
                set(timestamps)
            ) == len(timestamps):
                contradiction_type = ContradictionType.TEMPORAL_SUPERSESSION
            else:
                contradiction_type = ContradictionType.STATUS_CONFLICT
        elif len({member.source_system for member in members}) > 1:
            contradiction_type = ContradictionType.SOURCE_DISAGREEMENT
        else:
            contradiction_type = ContradictionType.SAME_KEY_DIFFERENT_VALUE
        found.append(_build(contradiction_type, subject, key, facts_tuple))
    return sorted(
        found,
        key=lambda item: (
            item.subject,
            item.key,
            item.type.value,
            item.contradiction_id,
        ),
    )
