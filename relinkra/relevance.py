"""Relinkra deterministic Relevance Scoring (R1G).

R1E composes a ContextPacket; R1F controls HOW MUCH of it fits; R1G
controls WHICH context is preferred. It is POWERFUL INSIDE (every score
is an integer sum of named, documented signals) and SIMPLE OUTSIDE (one
RankedContext JSON plus an optional relevance-aware budget pass):

    ContextPacket -> score_packet() -> RankedContext -> apply_budget()
                  -> bounded best-fit context

Hard rules:

- NO embeddings, NO LLM ranking, NO semantic/vector scoring, NO provider
  APIs, NO stemming, NO NLP packages. Pure stdlib integer arithmetic.
  Same packet + same inputs always yields a byte-identical RankedContext.
- ``as_of`` is REQUIRED and injected: no wall-clock, no randomness in
  pure functions. The CLI passes its injected clock.
- A score is NOT a probability and is NOT clamped: totals may go
  negative (penalty signals) and are only meaningful relative to other
  candidates in the same packet.
- EVERY signal lives in ``RelevanceWeights`` / ``DEFAULT_WEIGHTS``:
  no magic numbers elsewhere. Every candidate's explanation is the
  fixed-order signal list; zero-point signals are omitted from the JSON
  by default but always count toward the deterministic order.
- NO signal for the requesting agent: provenance is not reputation.
  Equal-quality memories score identically regardless of ``agent_type``.
- Resolution penalties apply ONLY to code candidates (code_references /
  code_facts). Memories keep their historical value: a memory linked to
  stale or missing code still earns type / task / recency points.
- Scores are DERIVED, never persisted: nothing is written back to
  Engram, the packet is never mutated, and the score report carries
  ids / token-level metadata only — never raw bodies, never absolute
  paths.

Tokenizer contract (deterministic, stdlib ``re`` + ``unicodedata``):

1. camelCase / CamelCase boundaries are split FIRST (before casefold,
   which would erase the boundary): ``generateOnly`` -> ``generate,
   only``; acronym runs split too (``XMLHttpRequest`` -> ``xml, http,
   request``). Letter/digit boundaries are NOT split (``r1g`` stays
   ``r1g``).
2. ``str.casefold()`` (Unicode-safe lowercasing), then NFKD
   normalization and stripping of combining marks: accented Spanish is
   ASCII-folded, so ``árbol`` -> ``arbol``. Characters without a
   decomposition (CJK, ``ø``) are kept as-is.
3. snake_case, kebab-case and dotted symbols split on their separators
   (``src.invoice.generate`` -> ``src, invoice, generate``); every run
   of non-word characters collapses to a boundary.
4. Tokens shorter than 2 characters are dropped; duplicates are removed
   preserving first-occurrence order.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .code_reference import CodeRefValidationError, normalize_repo_path
from .context_packet import ContextPacket, PacketItem
from .linkage import AMBIGUOUS, MISSING, RESOLVED, STALE

RELEVANCE_VERSION = "relevance-v1"

SCORED_SECTIONS = ("memories", "code_references", "code_facts",
                   "pending", "handoffs")
MEMORY_SECTIONS = ("memories", "pending", "handoffs")
CODE_SECTIONS = ("code_references", "code_facts")

# Fixed explanation order: every RelevanceScore carries its signals in
# exactly this order (zero-point entries omitted from JSON by default).
SIGNAL_ORDER = (
    "direct_code_link",
    "symbol_match",
    "file_match",
    "memory_type",
    "task_keyword_overlap",
    "recency",
    "workspace_match",
    "resolution",
)

# Tie-break type ordering (ascending = more preferred). Unknown memory
# types rank just above code references; this is the documented
# extension point of the chain.
TYPE_RANK_ORDER = (
    "constraint",
    "decision",
    "bug",
    "handoff",
    "pending",
    "architecture",
    "discovery",
    "verification",
    "task_result",
)
TYPE_RANK_UNKNOWN_MEMORY = len(TYPE_RANK_ORDER)
TYPE_RANK_CODE_REFERENCE = len(TYPE_RANK_ORDER) + 1
TYPE_RANK_CODE_FACT = len(TYPE_RANK_ORDER) + 2

_SECONDS_PER_DAY = 86400.0

_CAMEL_BOUNDARY_RE = re.compile(
    r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])"
)
_WORD_RUN_RE = re.compile(r"[\w]+", re.UNICODE)


class RelevanceError(Exception):
    """Base error for relevance scoring failures."""


class RelevanceValidationError(RelevanceError, ValueError):
    """Raised when relevance input or model data is invalid."""


def tokenize(text: Optional[str]) -> Tuple[str, ...]:
    """Deterministic lexical tokenizer (see module docstring)."""
    if not text:
        return ()
    split = _CAMEL_BOUNDARY_RE.sub(" ", str(text))
    folded = unicodedata.normalize("NFKD", split.casefold())
    folded = "".join(ch for ch in folded if not unicodedata.combining(ch))
    folded = folded.replace("_", " ")
    seen: Dict[str, None] = {}
    for match in _WORD_RUN_RE.findall(folded):
        if len(match) >= 2 and match not in seen:
            seen[match] = None
    return tuple(seen)


@dataclass(frozen=True)
class RelevanceWeights:
    """Every v1 signal weight, central and explicit. Defaults ARE v1."""

    direct_code_link: int = 40
    symbol_match: int = 35
    file_match: int = 25
    type_constraint: int = 20
    type_decision: int = 18
    type_bug: int = 15
    type_handoff: int = 15
    type_pending: int = 14
    type_architecture: int = 12
    type_discovery: int = 6
    type_verification: int = 4
    type_task_result: int = 2
    keyword_title_each: int = 6
    keyword_title_cap: int = 18
    keyword_code_each: int = 5
    keyword_code_cap: int = 15
    keyword_body_each: int = 2
    keyword_body_cap: int = 10
    recency_day: int = 8
    recency_week: int = 6
    recency_month: int = 4
    recency_quarter: int = 2
    workspace_match: int = 5
    resolution_resolved: int = 4
    resolution_stale: int = -8
    resolution_ambiguous: int = -6
    resolution_missing: int = -10

    def memory_type_points(self, memory_type: Optional[str]) -> int:
        """Per-type points; unknown/None types earn 0 (documented)."""
        field_name = _TYPE_POINTS_FIELDS.get(memory_type or "")
        if field_name is None:
            return 0
        return getattr(self, field_name)


_TYPE_POINTS_FIELDS = {
    "constraint": "type_constraint",
    "decision": "type_decision",
    "bug": "type_bug",
    "handoff": "type_handoff",
    "pending": "type_pending",
    "architecture": "type_architecture",
    "discovery": "type_discovery",
    "verification": "type_verification",
    "task_result": "type_task_result",
}

DEFAULT_WEIGHTS = RelevanceWeights()


@dataclass
class RelevanceScore:
    """One candidate's deterministic explanation.

    ``signals`` is a tuple of ``(name, points)`` in ``SIGNAL_ORDER``;
    ``total`` is their exact integer sum (never clamped, may be
    negative). Tie-break fields travel with the score: ``type_rank``,
    ``timestamp`` and ``source_id``.
    """

    source_id: str
    section: str
    occurrence_index: int
    total: int
    signals: Tuple[Tuple[str, int], ...]
    type_rank: int
    timestamp: Optional[str] = None

    def to_dict(self, *, include_zero: bool = False) -> dict:
        signals = [
            {"name": name, "points": points}
            for name, points in self.signals
            if include_zero or points != 0
        ]
        return {
            "source_id": self.source_id,
            "section": self.section,
            "occurrence_index": self.occurrence_index,
            "total": self.total,
            "signals": signals,
            "type_rank": self.type_rank,
            "timestamp": self.timestamp,
        }


@dataclass
class RankedContext:
    """Deterministic ranking of every scored section of one packet.

    Per-section lists are ordered best-first by the documented
    tie-break chain. Lookup keys are ``(section, source_id,
    occurrence_index)`` — the same 0-based occurrence counting the R1F
    audit uses — so budget decisions and relevance explanations always
    refer to the same candidate. NEVER mutates the packet.
    """

    original_packet_id: str
    relevance_version: str
    as_of: str
    scores: Dict[str, Tuple[RelevanceScore, ...]] = field(default_factory=dict)
    packet_fingerprint: tuple = ()

    def score_for(
        self, section: str, source_id: str, occurrence_index: int
    ) -> Optional[RelevanceScore]:
        for score in self.scores.get(section, ()):
            if (
                score.source_id == source_id
                and score.occurrence_index == occurrence_index
            ):
                return score
        return None

    def worst_first(self, section: str) -> Tuple[RelevanceScore, ...]:
        """Ascending relevance: the budget ladder's removal order."""
        return tuple(reversed(self.scores.get(section, ())))

    def to_dict(self) -> dict:
        return {
            "relevance_version": self.relevance_version,
            "as_of": self.as_of,
            "original_packet_id": self.original_packet_id,
            "packet_fingerprint": {
                section: [list(pair) for pair in pairs]
                for section, pairs in self.packet_fingerprint
            },
            "scores": {
                section: [s.to_dict() for s in self.scores.get(section, ())]
                for section in SCORED_SECTIONS
            },
        }

    def to_json(self, *, pretty: bool = False) -> str:
        """Deterministic JSON: keys always sorted."""
        if pretty:
            return json.dumps(
                self.to_dict(), indent=2, sort_keys=True, ensure_ascii=False
            )
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        )


# -- candidate extraction ----------------------------------------------------


def _source_id(section: str, item: PacketItem) -> str:
    """Same keying rule as the R1F accountant."""
    if section in CODE_SECTIONS:
        return (
            item.provenance.code_reference_id
            or item.data.get("code_reference_id")
            or ""
        )
    return item.provenance.memory_id or ""


@dataclass
class _Candidate:
    section: str
    source_id: str
    occurrence_index: int
    is_code: bool
    memory_type: Optional[str]
    timestamp: Optional[str]
    scope_channel: str
    title: str
    body: str
    ref_fields: Tuple[Mapping, ...]
    linked_code_reference_ids: Tuple[str, ...]
    resolution_state: Optional[str]


def _candidates(packet: ContextPacket) -> List[_Candidate]:
    candidates: List[_Candidate] = []
    for section in SCORED_SECTIONS:
        counters: Dict[str, int] = {}
        for item in getattr(packet, section):
            source_id = _source_id(section, item)
            occurrence = counters.get(source_id, 0)
            counters[source_id] = occurrence + 1
            if section in MEMORY_SECTIONS:
                refs = tuple(
                    ref
                    for ref in (item.data.get("code_refs") or ())
                    if isinstance(ref, Mapping)
                )
                candidates.append(
                    _Candidate(
                        section=section,
                        source_id=source_id,
                        occurrence_index=occurrence,
                        is_code=False,
                        memory_type=item.data.get("memory_type"),
                        timestamp=item.data.get("timestamp"),
                        scope_channel=str(item.data.get("scope_channel") or ""),
                        title=str(item.data.get("title") or ""),
                        body=str(item.data.get("body") or ""),
                        ref_fields=refs,
                        linked_code_reference_ids=_linked_ref_ids(
                            item.provenance.code_reference_id, refs
                        ),
                        resolution_state=None,
                    )
                )
            elif section == "code_references":
                reference = item.data.get("reference")
                refs = (reference,) if isinstance(reference, Mapping) else ()
                candidates.append(
                    _Candidate(
                        section=section,
                        source_id=source_id,
                        occurrence_index=occurrence,
                        is_code=True,
                        memory_type=None,
                        timestamp=None,
                        scope_channel="",
                        title="",
                        body="",
                        ref_fields=refs,
                        linked_code_reference_ids=(),
                        resolution_state=(
                            item.data.get("resolution_state")
                            or item.provenance.resolution_state
                        ),
                    )
                )
            else:  # code_facts
                candidates.append(
                    _Candidate(
                        section=section,
                        source_id=source_id,
                        occurrence_index=occurrence,
                        is_code=True,
                        memory_type=None,
                        timestamp=None,
                        scope_channel="",
                        title="",
                        body="",
                        ref_fields=(item.data,),
                        linked_code_reference_ids=(),
                        resolution_state=(
                            item.data.get("resolution_state")
                            or item.provenance.resolution_state
                        ),
                    )
                )
    return candidates


def _linked_ref_ids(
    provenance_ref_id: Optional[str], refs: Tuple[Mapping, ...]
) -> Tuple[str, ...]:
    """Every code_reference_id a memory candidate is linked to: the
    provenance field (handcrafted packets) PLUS each validated
    ``code_refs`` entry — the only linkage ContextBuilder-produced
    packets carry. Defensive: non-str/empty ids are ignored, order is
    first-occurrence, duplicates collapse."""
    linked: List[str] = []
    seen = set()
    for ref_id in (
        [provenance_ref_id]
        + [ref.get("code_reference_id") for ref in refs]
    ):
        if isinstance(ref_id, str) and ref_id and ref_id not in seen:
            seen.add(ref_id)
            linked.append(ref_id)
    return tuple(linked)


# -- signals -------------------------------------------------------------------


def _parse_instant(value: Optional[str]) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text[-1:] in ("Z", "z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _recency_points(
    timestamp: Optional[str], as_of: datetime, weights: RelevanceWeights
) -> int:
    """Fixed age buckets. A FUTURE timestamp has negative age and so
    clamps into the freshest bucket (<= 1 day); a missing or
    unparseable timestamp earns 0."""
    instant = _parse_instant(timestamp)
    if instant is None:
        return 0
    age_days = (as_of - instant).total_seconds() / _SECONDS_PER_DAY
    if age_days <= 1:
        return weights.recency_day
    if age_days <= 7:
        return weights.recency_week
    if age_days <= 30:
        return weights.recency_month
    if age_days <= 90:
        return weights.recency_quarter
    return 0


def _resolution_points(
    candidate: _Candidate, weights: RelevanceWeights
) -> int:
    """Code candidates only; memories keep their historical value."""
    if not candidate.is_code:
        return 0
    state = candidate.resolution_state
    if state == RESOLVED:
        return weights.resolution_resolved
    if state == STALE:
        return weights.resolution_stale
    if state == AMBIGUOUS:
        return weights.resolution_ambiguous
    if state == MISSING:
        return weights.resolution_missing
    return 0


def _keyword_points(
    candidate: _Candidate,
    task_tokens: Tuple[str, ...],
    weights: RelevanceWeights,
) -> int:
    """Set-based overlap: each DISTINCT shared token scores once, so
    repeating a keyword never inflates the score (no occurrence spam)."""
    if not task_tokens:
        return 0
    task_set = set(task_tokens)
    title_hits = len(task_set & set(tokenize(candidate.title)))
    body_hits = len(task_set & set(tokenize(candidate.body)))
    code_text = " ".join(
        str(ref.get(key) or "")
        for ref in candidate.ref_fields
        for key in ("file_path", "qualified_name", "symbol_name")
    )
    code_hits = len(task_set & set(tokenize(code_text)))
    return (
        min(
            weights.keyword_title_cap,
            weights.keyword_title_each * title_hits,
        )
        + min(
            weights.keyword_code_cap,
            weights.keyword_code_each * code_hits,
        )
        + min(
            weights.keyword_body_cap,
            weights.keyword_body_each * body_hits,
        )
    )


def _score_candidate(
    candidate: _Candidate,
    *,
    task_tokens: Tuple[str, ...],
    focus_file: Optional[str],
    focus_symbol: Optional[str],
    focus_code_reference_id: Optional[str],
    workspace_channel: Optional[str],
    as_of: datetime,
    weights: RelevanceWeights,
) -> RelevanceScore:
    direct_link = 0
    if (
        not candidate.is_code
        and focus_code_reference_id
        and focus_code_reference_id in candidate.linked_code_reference_ids
    ):
        direct_link = weights.direct_code_link

    symbol_match = 0
    if focus_symbol:
        for ref in candidate.ref_fields:
            if focus_symbol in (
                ref.get("qualified_name"),
                ref.get("symbol_name"),
            ):
                symbol_match = weights.symbol_match
                break

    file_match = 0
    if focus_file:
        for ref in candidate.ref_fields:
            if ref.get("file_path") == focus_file:
                file_match = weights.file_match
                break

    type_points = (
        0
        if candidate.is_code
        else weights.memory_type_points(candidate.memory_type)
    )
    keyword = _keyword_points(candidate, task_tokens, weights)
    recency = (
        0
        if candidate.is_code
        else _recency_points(candidate.timestamp, as_of, weights)
    )
    workspace = 0
    if (
        not candidate.is_code
        and workspace_channel
        and candidate.scope_channel == workspace_channel
    ):
        workspace = weights.workspace_match
    resolution = _resolution_points(candidate, weights)

    points = {
        "direct_code_link": direct_link,
        "symbol_match": symbol_match,
        "file_match": file_match,
        "memory_type": type_points,
        "task_keyword_overlap": keyword,
        "recency": recency,
        "workspace_match": workspace,
        "resolution": resolution,
    }
    signals = tuple((name, points[name]) for name in SIGNAL_ORDER)
    if candidate.is_code:
        type_rank = (
            TYPE_RANK_CODE_REFERENCE
            if candidate.section == "code_references"
            else TYPE_RANK_CODE_FACT
        )
    else:
        try:
            type_rank = TYPE_RANK_ORDER.index(candidate.memory_type or "")
        except ValueError:
            type_rank = TYPE_RANK_UNKNOWN_MEMORY
    return RelevanceScore(
        source_id=candidate.source_id,
        section=candidate.section,
        occurrence_index=candidate.occurrence_index,
        total=sum(points.values()),
        signals=signals,
        type_rank=type_rank,
        timestamp=None if candidate.is_code else candidate.timestamp,
    )


def _best_first(scores: List[RelevanceScore]) -> Tuple[RelevanceScore, ...]:
    """total DESC -> type_rank ASC -> timestamp DESC (chronological over
    parsed aware datetimes; missing or unparseable timestamps last) ->
    source_id ASC. Successive stable sorts; no randomness."""
    ordered = sorted(scores, key=lambda s: s.source_id)
    parsed = [(_parse_instant(s.timestamp), s) for s in ordered]
    with_ts = sorted(
        (pair for pair in parsed if pair[0] is not None),
        key=lambda pair: pair[0],
        reverse=True,
    )
    ordered = [s for _, s in with_ts] + [
        s for instant, s in parsed if instant is None
    ]
    ordered = sorted(ordered, key=lambda s: s.type_rank)
    ordered = sorted(ordered, key=lambda s: s.total, reverse=True)
    return tuple(ordered)


def _fingerprint(candidates: List[_Candidate]) -> tuple:
    by_section: Dict[str, List[Tuple[str, int]]] = {
        section: [] for section in SCORED_SECTIONS
    }
    for candidate in candidates:
        by_section[candidate.section].append(
            (candidate.source_id, candidate.occurrence_index)
        )
    return tuple(
        (section, tuple(by_section[section])) for section in SCORED_SECTIONS
    )


def packet_fingerprint(packet: ContextPacket) -> tuple:
    """Deterministic fingerprint of the packet's scored sections: per
    section, the ordered (source_id, occurrence_index) pairs. Stored in
    RankedContext at score time so apply_budget can reject a ranking
    built from a DIFFERENT packet that shares the same packet_id
    (packet ids are selection-order- and content-insensitive)."""
    if not isinstance(packet, ContextPacket):
        raise RelevanceValidationError("packet must be a ContextPacket")
    return _fingerprint(_candidates(packet))


def score_packet(
    packet: ContextPacket,
    *,
    task: Optional[str] = None,
    focus_file: Optional[str] = None,
    focus_symbol: Optional[str] = None,
    focus_code_reference_id: Optional[str] = None,
    workspace_id: Optional[str] = None,
    as_of,
    weights: RelevanceWeights = DEFAULT_WEIGHTS,
) -> RankedContext:
    """Score every typed-section candidate of ``packet``.

    ``as_of`` is REQUIRED (ISO-8601 string or aware/naive-as-UTC
    datetime): no implicit wall-clock. ``task=None`` disables only the
    keyword signal; all other signals still differentiate. The packet
    is never mutated.
    """
    if not isinstance(packet, ContextPacket):
        raise RelevanceValidationError("packet must be a ContextPacket")
    if not isinstance(weights, RelevanceWeights):
        raise RelevanceValidationError("weights must be RelevanceWeights")
    if isinstance(as_of, datetime):
        as_of_dt = (
            as_of
            if as_of.tzinfo is not None
            else as_of.replace(tzinfo=timezone.utc)
        )
        as_of_text = as_of_dt.isoformat()
    else:
        as_of_dt = _parse_instant(as_of)
        if as_of_dt is None:
            raise RelevanceValidationError(
                "as_of is required and must be an ISO-8601 timestamp"
            )
        as_of_text = str(as_of)

    normalized_file = None
    if focus_file:
        try:
            normalized_file = normalize_repo_path(focus_file)
        except CodeRefValidationError as exc:
            raise RelevanceValidationError(
                f"invalid focus_file: {exc}"
            ) from exc
    normalized_symbol = (focus_symbol or "").strip() or None
    workspace_channel = f"ws/{workspace_id}" if workspace_id else None
    task_tokens = tokenize(task)

    per_section: Dict[str, List[RelevanceScore]] = {
        section: [] for section in SCORED_SECTIONS
    }
    candidates = _candidates(packet)
    for candidate in candidates:
        per_section[candidate.section].append(
            _score_candidate(
                candidate,
                task_tokens=task_tokens,
                focus_file=normalized_file,
                focus_symbol=normalized_symbol,
                focus_code_reference_id=focus_code_reference_id,
                workspace_channel=workspace_channel,
                as_of=as_of_dt,
                weights=weights,
            )
        )
    return RankedContext(
        original_packet_id=packet.packet_id,
        relevance_version=RELEVANCE_VERSION,
        as_of=as_of_text,
        scores={
            section: _best_first(per_section[section])
            for section in SCORED_SECTIONS
        },
        packet_fingerprint=_fingerprint(candidates),
    )
