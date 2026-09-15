"""Relinkra deterministic Context Budget Accountant (R1F).

R1E composes a ContextPacket; R1F answers a different question: given that
packet and a FIXED context budget, what fits, what must be reduced or
omitted, and why. It is POWERFUL INSIDE (every byte is accounted, every
reduction is an auditable decision) and SIMPLE OUTSIDE (one bounded
ContextPacket plus one JSON budget report).

Hard rules:

- NO embeddings, NO LLM ranking, NO semantic scoring, NO provider APIs,
  NO recency/similarity scoring. Reduction is a fixed deterministic
  ladder over fixed section classes. Same packet + same budget always
  yields the same decisions and a byte-identical report.
- Token estimation is provider-independent and replaceable: method
  ``chars-per-token`` version ``cpt1`` counts ``ceil(len(text) /
  chars_per_token)`` over the ACTUAL serialized payload (data +
  provenance + metadata + warnings), never just raw bodies. ``len()``
  counts Unicode code points, so cpt1 is a deliberate approximation:
  it may diverge from real provider tokenizers (especially CJK/emoji).
  ``DEFAULT_CHARS_PER_TOKEN = 3.0`` is conservative on purpose (below
  the common ~4.0 English heuristic) so code and multilingual text are
  over- rather than under-counted. The version field allows future
  exact-tokenizer adapters.
- Section classification is fixed policy:
  ESSENTIAL (always protected first): project identity/facts, task/focus,
  ALL warnings, minimal packet-level provenance. Identity and degradation
  signals must survive any budget.
  IMPORTANT: pending, handoffs, memories of type constraint/decision/
  architecture/bug, code_references (metadata only), and code_fact
  metadata rows (WITHOUT their snippet payloads).
  OPTIONAL: snippet payloads themselves, memories of type discovery/
  verification/task_result and any unknown/other memory type.
- Reduction ladder (exact order, each step exhaustive before the next,
  re-estimate after every mutation, stop as soon as it fits):
  1. SNIPPET TRUNCATE: snippets longer than 400 chars are cut to 400
     chars + the marker ``\\n...[truncated by budget]`` (snippets in the
     401..425 char range may grow by a few chars from the marker; step 2
     removes them if the budget still demands it). action=truncated,
     reason=snippet_budget_ladder.
  2. SNIPPET REFERENCE-ONLY: drop the snippet payload entirely, keep all
     code_fact metadata + code_reference_id. action=reference_only,
     reason=snippet_budget_ladder.
  3. OMIT OPTIONAL MEMORIES: whole memories of optional types, from the
     END of the list first. Bodies are never cut mid-sentence.
     reason=optional_section_budget_exhausted.
  4. OMIT OPTIONAL STRUCTURAL CODE FACTS: CBM architecture/traversal facts
     are shed before any direct code fact, including when they are the only
     code facts.
  5. OMIT OPTIONAL CODE FACTS: code_facts beyond the FIRST one (the
     direct focus is important), from the end.
     reason=optional_section_budget_exhausted.
  6. OMIT IMPORTANT ITEMS from the end: important memories, then pending,
     then handoffs, then code_references beyond the first.
     reason=important_section_budget_exhausted.
  6. Still over ``budget - reserve`` -> BUDGET_UNSATISFIABLE typed
     result (packet=None). NEVER silently exceed.
- The ORIGINAL packet is never mutated: survivors are deep-copied into a
  NEW ContextPacket. The budgeted packet KEEPS the original ``packet_id``
  and records ``diagnostics["budget"] = {"budgeted": True, ...}``. This
  is safe because ``compute_packet_id`` hashes only identity fields and
  sorted source ids; warnings, diagnostics and created_at never
  participate in packet identity.
- Diagnostics are split, never falsified: the ORIGINAL R1E composition
  diagnostics are moved verbatim under ``diagnostics["composition"]``,
  while ``diagnostics["budget"]`` describes the FINAL budgeted packet
  (final per-section counts, included/omitted/truncated source ids,
  final total chars/tokens, satisfied) plus the budget policy fields.
  The final-state fields are part of the measured payload itself, so the
  ladder always measures the packet WITH its final diagnostics and the
  hard guarantee covers them (``final_total_chars`` is self-referential
  and resolved by deterministic fixed-point iteration).
  Measurement basis: the ladder always measures ``to_json()`` — the form
  that KEEPS ``diagnostics["local"]``. Portable emission
  (``to_portable_json()``) strips that channel, so the shipped document
  is always <= the measured size. The hard budget therefore still holds
  as a strict upper bound; ``final_total_chars`` describes the measured
  (local) form, which over-states the portable bytes by exactly the
  stripped channel. Measuring the superset is deliberate: the same
  packet may also be persisted in local form, and a budget that only
  covered the portable projection would under-count that case.
- Audit bookkeeping is collision-free: decisions/actions are keyed
  internally by (kind, source_id, occurrence_index) where the occurrence
  index is the deterministic 0-based occurrence count of that
  (section, source_id) pair in packet order. Duplicated or empty source
  ids therefore each get their OWN decision; ``BudgetDecision.source_id``
  keeps its public shape, and the report id hashes
  section:source_id:occurrence plus the final portable packet bytes so
  identical inputs stay byte-identical, local paths cannot affect the id,
  and post-budget metadata cannot leave a stale report identity behind.
- Typed malformed packets are REJECTED at the boundary: a code_fact
  ``snippet`` that is neither a string nor None raises
  BudgetValidationError naming the section/index and the offending TYPE
  (never the value, which could carry secrets). None or an absent key is
  safe and treated as no snippet.
- Warnings are never removed by the ladder and the budget layer never
  ADDS warnings: omissions are reported in the budget report and in
  ``diagnostics["budget"]``, keeping warning bytes identical.
- OPTIONAL pre-budget ranking (R1G): ``apply_budget(..., relevance=...)``
  accepts a RankedContext for the same packet. The ladder STRUCTURE is
  unchanged (essential protected, snippet steps 1-2, class order of
  steps 3-5); only the removal order inside steps 3-5 becomes ascending
  relevance instead of from-end. With ``relevance=None`` the accountant
  is byte-identical to plain R1F.
- Hard guarantee: when status is OK, ``estimate_tokens`` of the budgeted
  packet's compact JSON is <= ``max_estimated_tokens`` (and its length is
  <= ``max_characters`` when set). The ladder targets
  ``max_estimated_tokens - reserve_tokens`` so the guarantee holds with
  headroom; a final assertion-style check re-verifies it before OK is
  returned. ``reserve_tokens`` is genuinely reserved: content that only
  fits inside the reserve is unsatisfiable.

R6C salience and metadata explainability (additive on top of R1F):

- Salience tiers are explicit and agent-visible (relinkra.salience):
  MUST_KEEP items are NEVER omitted by the ladder — the current (most
  recent active) handoff, all pending items, plus the essential frame.
  HIGH_SALIENCE covers important memories, handoffs, code references,
  the direct code fact and important git facts; OPTIONAL covers
  snippets, optional memories/facts and verbose metadata. The ladder
  order already sheds OPTIONAL before HIGH_SALIENCE; R6C adds one
  invariant on top: OPTIONAL consumption can never cause a MUST_KEEP
  item to be dropped.
- METADATA COMPACTION is a ladder step (after optional shedding, BEFORE
  any important item is omitted). While over budget it deterministically
  shrinks, in fixed order: per-item explain sidecars (full relevance
  signals -> total, trust dropped, freshness reduced to state/reason),
  packet-level freshness notices (grouped by state/reason/action with
  shared evidence refs), ``selected_source_ids`` and
  ``included_source_ids`` (derivable from the packet sections), then
  duplicated provenance fields and redundant memory-envelope bookkeeping
  (``v``, ``dedup_key``, ``source_tool``, ``agent_id``, packet-equal
  ``project_id``/``repository_identity``). Compaction is recorded as
  ``diagnostics.budget.metadata_compacted``. Roomy budgets never
  compact: with no pressure the packet keeps the full R4D sidecars.
- Snippet truncation is explicit: the truncated fact declares
  ``snippet_original_length``, ``snippet_returned_length`` and
  ``snippet_continuation_ref`` (the code_reference_id) alongside the
  existing ``snippet_truncated`` flag. Nothing truncates silently.
- The budgeted packet carries an additive ``packet_status`` block:
  packet_complete, budget_exhausted, omitted_sections,
  omitted_high_salience_count, omitted_item_types, recommended_next
  (deterministic recovery hints naming real tools), context_sufficiency
  (conservative; implementation/security stay
  ``source_verification_required`` with code evidence), salience counts
  and cpt1 token accounting. Under extreme pressure the block shrinks
  along the same fixed order instead of breaking the budget guarantee.
- ``BudgetedContext`` grows additive ``minimum_useful_tokens`` /
  ``recommended_max_tokens`` guidance: the cpt1 cost of the must-keep
  skeleton and of the no-high-salience-omission packet. A budget below
  the minimum is unsatisfiable WITH guidance, not a bare retry.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .context_packet import PACKET_VERSION, ContextPacket, PacketItem
from .salience import (  # noqa: F401  (re-exported: the shared classification
    # source moved to salience in R6C; import paths stay stable)
    IMPORTANT_GIT_FACT_KINDS,
    IMPORTANT_MEMORY_TYPES,
    MUST_KEEP,
    STRUCTURAL_EVIDENCE_KINDS,
    _attach_settled_rebuild,
    _conservative_status_choice,
    _status_claim_settled,
    build_status,
    build_status_skeleton,
    classify_git_fact,
    classify_item,
    classify_memory_type,
    current_handoff_memory_id,
    is_structural_code_fact,
    shrink_status,
    status_omitted_item_types,
)

ESTIMATION_METHOD = "chars-per-token"
ESTIMATION_VERSION = "cpt1"
DEFAULT_CHARS_PER_TOKEN = 3.0

SNIPPET_LADDER_CAP = 400
TRUNCATION_MARKER = "\n...[truncated by budget]"

# Fixed profiles: small = compact agent handoff, medium = normal coding
# task, large = architecture/debug session.
BUDGET_PROFILES = {"small": 2000, "medium": 8000, "large": 24000}

STATUS_OK = "OK"
STATUS_UNSATISFIABLE = "BUDGET_UNSATISFIABLE"

ACTION_INCLUDED = "included"
ACTION_TRUNCATED = "truncated"
ACTION_REFERENCE_ONLY = "reference_only"
ACTION_OMITTED = "omitted"

REASON_WITHIN_BUDGET = "within_budget"
REASON_SNIPPET_LADDER = "snippet_budget_ladder"
REASON_OPTIONAL_EXHAUSTED = "optional_section_budget_exhausted"
REASON_IMPORTANT_EXHAUSTED = "important_section_budget_exhausted"

REPORT_ID_PREFIX = "bgr_"
_REPORT_NAMESPACE = b"relinkra/budget-report/v1\x00"

_ITEM_SECTIONS = ("memories", "code_references", "code_facts", "pending",
                  "handoffs", "git_facts")
_SECTION_KINDS = {"memories": "memory", "code_references": "code_reference",
                  "code_facts": "code_fact", "pending": "pending",
                  "handoffs": "handoff", "git_facts": "git_fact"}

# Within-class deterministic shedding order for git facts when relevance
# has no position for them (git_facts is currently unscored). Lower rank
# = lower value = shed first. Repository/HEAD state are essential-ish and
# are kept until the very end of the important class.
_GIT_FACT_SHED_RANK = {
    "co_change": 10,
    "diff_fact": 20,
    "working_tree_change": 30,
    "recent_commit": 40,
    "file_history": 50,
    "current_change_state": 60,
    "head_facts": 70,
    "repository_state": 80,
}


def _git_fact_shed_rank(item: PacketItem) -> int:
    return _GIT_FACT_SHED_RANK.get(item.data.get("kind"), 0)


class BudgetError(Exception):
    """Base error for context budget failures."""


class BudgetValidationError(BudgetError, ValueError):
    """Raised when budget input or model data is invalid."""


def estimate_tokens(
    text: str, chars_per_token: float = DEFAULT_CHARS_PER_TOKEN
) -> int:
    """Deterministic cpt1 estimate: ceil(code points / chars_per_token)."""
    if (
        not isinstance(chars_per_token, (int, float))
        or isinstance(chars_per_token, bool)
        or not math.isfinite(chars_per_token)
        or chars_per_token <= 0
    ):
        raise BudgetValidationError(
            "chars_per_token must be a positive finite number"
        )
    if not text:
        return 0
    return math.ceil(len(text) / chars_per_token)


def _tokens_for_chars(chars: int, chars_per_token: float) -> int:
    return math.ceil(chars / chars_per_token) if chars > 0 else 0


def _carries_git_section(packet: ContextPacket) -> bool:
    """Only rlkctx2 packets serialize a git_facts section; rlkctx1 packets
    must keep byte-identical pre-git accounting (no section anywhere)."""
    return packet.packet_version == PACKET_VERSION


@dataclass
class ContextBudget:
    """Relinkra-owned budget. ``reserve_tokens`` is stored as given;
    ``resolve_budget`` applies the profile default when it is not given."""

    max_estimated_tokens: int
    max_characters: Optional[int] = None
    reserve_tokens: int = 0
    chars_per_token: float = DEFAULT_CHARS_PER_TOKEN
    estimation_method: str = ESTIMATION_METHOD
    estimation_version: str = ESTIMATION_VERSION

    def __post_init__(self) -> None:
        if (
            not isinstance(self.max_estimated_tokens, int)
            or isinstance(self.max_estimated_tokens, bool)
            or self.max_estimated_tokens < 1
        ):
            raise BudgetValidationError(
                "max_estimated_tokens must be a positive integer"
            )
        if self.max_characters is not None and (
            not isinstance(self.max_characters, int)
            or isinstance(self.max_characters, bool)
            or self.max_characters < 1
        ):
            raise BudgetValidationError(
                "max_characters must be a positive integer or None"
            )
        if (
            not isinstance(self.reserve_tokens, int)
            or isinstance(self.reserve_tokens, bool)
            or self.reserve_tokens < 0
        ):
            raise BudgetValidationError(
                "reserve_tokens must be a non-negative integer"
            )
        if (
            not isinstance(self.chars_per_token, (int, float))
            or isinstance(self.chars_per_token, bool)
            or not math.isfinite(self.chars_per_token)
            or self.chars_per_token <= 0
        ):
            raise BudgetValidationError(
                "chars_per_token must be a positive finite number"
            )

    def to_dict(self) -> dict:
        return {
            "max_estimated_tokens": self.max_estimated_tokens,
            "max_characters": self.max_characters,
            "reserve_tokens": self.reserve_tokens,
            "chars_per_token": self.chars_per_token,
            "estimation_method": self.estimation_method,
            "estimation_version": self.estimation_version,
        }

    @staticmethod
    def from_dict(data: Mapping) -> "ContextBudget":
        return ContextBudget(
            max_estimated_tokens=int(data.get("max_estimated_tokens") or 0),
            max_characters=data.get("max_characters"),
            reserve_tokens=int(data.get("reserve_tokens") or 0),
            chars_per_token=float(
                data.get("chars_per_token") or DEFAULT_CHARS_PER_TOKEN
            ),
            estimation_method=str(
                data.get("estimation_method") or ESTIMATION_METHOD
            ),
            estimation_version=str(
                data.get("estimation_version") or ESTIMATION_VERSION
            ),
        )


def resolve_budget(
    *,
    profile: Optional[str] = None,
    max_tokens: Optional[int] = None,
    max_characters: Optional[int] = None,
    reserve_tokens: Optional[int] = None,
    chars_per_token: float = DEFAULT_CHARS_PER_TOKEN,
) -> ContextBudget:
    """Resolve a ContextBudget from a fixed profile and/or explicit cap.

    An explicit ``max_tokens`` always WINS over ``profile``. With neither,
    a BudgetValidationError is raised. When ``reserve_tokens`` is not
    given, the default is ``max(64, ceil(0.05 * max_estimated_tokens))``.
    """
    if max_tokens is None:
        if profile is None:
            raise BudgetValidationError(
                "a budget profile or an explicit max_tokens is required"
            )
        if profile not in BUDGET_PROFILES:
            raise BudgetValidationError(
                f"unknown budget profile: {profile!r}"
            )
        max_tokens = BUDGET_PROFILES[profile]
    if reserve_tokens is None:
        reserve_tokens = max(64, math.ceil(0.05 * max_tokens))
    return ContextBudget(
        max_estimated_tokens=max_tokens,
        max_characters=max_characters,
        reserve_tokens=reserve_tokens,
        chars_per_token=chars_per_token,
    )


@dataclass
class BudgetDecision:
    """One auditable accounting entry per content unit (item, snippet
    payload, or the essential structural block)."""

    source_id: str
    section: str
    action: str
    reason: str
    original_chars: int
    original_estimated_tokens: int
    final_chars: int
    final_estimated_tokens: int

    def to_dict(self) -> dict:
        return {
            "source_id": self.source_id,
            "section": self.section,
            "action": self.action,
            "reason": self.reason,
            "original_chars": self.original_chars,
            "original_estimated_tokens": self.original_estimated_tokens,
            "final_chars": self.final_chars,
            "final_estimated_tokens": self.final_estimated_tokens,
        }

    @staticmethod
    def from_dict(data: Mapping) -> "BudgetDecision":
        return BudgetDecision(
            source_id=str(data.get("source_id") or ""),
            section=str(data.get("section") or ""),
            action=str(data.get("action") or ""),
            reason=str(data.get("reason") or ""),
            original_chars=int(data.get("original_chars") or 0),
            original_estimated_tokens=int(
                data.get("original_estimated_tokens") or 0
            ),
            final_chars=int(data.get("final_chars") or 0),
            final_estimated_tokens=int(data.get("final_estimated_tokens") or 0),
        )


@dataclass
class ContextUsage:
    """Serialized-size accounting. The totals measure the ACTUAL compact
    packet JSON; ``sections`` is the per-section breakdown (item payloads
    plus essential framing — container bytes like commas/brackets live in
    the totals, so section sums may differ slightly from the total).
    Counts treat each item and each snippet payload as one unit;
    truncated_count includes reference_only reductions."""

    total_chars: int
    estimated_tokens: int
    sections: Dict[str, dict] = field(default_factory=dict)
    included_count: int = 0
    omitted_count: int = 0
    truncated_count: int = 0

    def to_dict(self) -> dict:
        return {
            "total_chars": self.total_chars,
            "estimated_tokens": self.estimated_tokens,
            "sections": self.sections,
            "included_count": self.included_count,
            "omitted_count": self.omitted_count,
            "truncated_count": self.truncated_count,
        }

    @staticmethod
    def from_dict(data: Mapping) -> "ContextUsage":
        return ContextUsage(
            total_chars=int(data.get("total_chars") or 0),
            estimated_tokens=int(data.get("estimated_tokens") or 0),
            sections=dict(data.get("sections") or {}),
            included_count=int(data.get("included_count") or 0),
            omitted_count=int(data.get("omitted_count") or 0),
            truncated_count=int(data.get("truncated_count") or 0),
        )


@dataclass
class BudgetedContext:
    """Result of applying a budget: the bounded packet (or None when
    unsatisfiable) plus the full audit trail. No timestamps: the report is
    byte-identical for identical inputs; ``report_id`` is content-hashed.
    ``relevance_version`` records the R1G ranker when one guided the
    ladder (None otherwise)."""

    original_packet_id: str
    budget: ContextBudget
    status: str
    original_usage: ContextUsage
    final_usage: ContextUsage
    decisions: List[BudgetDecision]
    packet: Optional[ContextPacket]
    satisfied: bool
    report_id: str = ""
    relevance_version: Optional[str] = None
    # R6C additive budget guidance (deterministic cpt1 estimates):
    # ``minimum_useful_tokens`` is the cost of the must-keep skeleton
    # (essential frame + protected items + focused code evidence);
    # ``recommended_max_tokens`` is the cost of the packet with nothing
    # high-salience omitted. A budget below the minimum is unsatisfiable
    # WITH guidance rather than a bare retry.
    minimum_useful_tokens: Optional[int] = None
    recommended_max_tokens: Optional[int] = None
    # R6C: per-type omission counts for the REPORT (bounded, sorted).
    # Lives here rather than in the budgeted packet's status block so the
    # block's byte footprint stays bounded while the report stays
    # informative; counts only, never omitted payloads.
    omitted_item_types: Optional[Dict[str, int]] = None

    def reconcile_final_packet(self, packet: ContextPacket) -> None:
        """Rebind the report to a packet mutated after the budget ladder.

        Additive metadata may be attached only after the ladder has produced
        its decisions.  Callers must then re-account those exact final bytes;
        otherwise ``satisfied``, ``final_usage`` and ``report_id`` describe a
        packet that was never returned.
        """
        satisfied = _hard_guarantee(packet, self.budget)
        budget_diagnostics = packet.diagnostics.get("budget")
        if isinstance(budget_diagnostics, dict):
            budget_diagnostics["satisfied"] = satisfied
            if satisfied and not _hard_guarantee(packet, self.budget):
                # ``false`` is one byte longer than ``true`` today, but keep
                # this fail-honest if the representation changes later.
                satisfied = False
                budget_diagnostics["satisfied"] = False
        usage = _usage(packet, self.budget.chars_per_token, self.decisions)
        self.final_usage = usage
        self.satisfied = satisfied
        self.status = STATUS_OK if satisfied else STATUS_UNSATISFIABLE
        self.packet = packet if satisfied else None
        self.report_id = _report_id(
            self.original_packet_id,
            self.budget,
            self.decisions,
            packet,
        )

    def to_dict(self) -> dict:
        return {
            "report_id": self.report_id,
            "estimation_method": self.budget.estimation_method,
            "estimation_version": self.budget.estimation_version,
            "original_packet_id": self.original_packet_id,
            "status": self.status,
            "satisfied": self.satisfied,
            "relevance_version": self.relevance_version,
            "minimum_useful_tokens": self.minimum_useful_tokens,
            "recommended_max_tokens": self.recommended_max_tokens,
            "omitted_item_types": self.omitted_item_types,
            "budget": self.budget.to_dict(),
            "original_usage": self.original_usage.to_dict(),
            "final_usage": self.final_usage.to_dict(),
            "decisions": [d.to_dict() for d in self.decisions],
            "packet": self.packet.to_dict() if self.packet is not None else None,
        }

    def to_portable_dict(self) -> dict:
        """Portable budget report: strips machine-local diagnostics from
        the embedded packet so absolute paths do not leak via CLI stderr.
        """
        data = self.to_dict()
        if data.get("packet") is not None:
            data["packet"] = self.packet.to_portable_dict()
        return data

    @staticmethod
    def from_dict(data: Mapping) -> "BudgetedContext":
        packet_raw = data.get("packet")
        return BudgetedContext(
            original_packet_id=str(data.get("original_packet_id") or ""),
            budget=ContextBudget.from_dict(data.get("budget") or {}),
            status=str(data.get("status") or ""),
            original_usage=ContextUsage.from_dict(
                data.get("original_usage") or {}
            ),
            final_usage=ContextUsage.from_dict(data.get("final_usage") or {}),
            decisions=[
                BudgetDecision.from_dict(d) for d in data.get("decisions") or []
            ],
            packet=(
                ContextPacket.from_dict(packet_raw)
                if isinstance(packet_raw, Mapping)
                else None
            ),
            satisfied=bool(data.get("satisfied")),
            report_id=str(data.get("report_id") or ""),
            relevance_version=data.get("relevance_version"),
            minimum_useful_tokens=(
                int(data["minimum_useful_tokens"])
                if data.get("minimum_useful_tokens") is not None
                else None
            ),
            recommended_max_tokens=(
                int(data["recommended_max_tokens"])
                if data.get("recommended_max_tokens") is not None
                else None
            ),
            omitted_item_types=(
                dict(data.get("omitted_item_types"))
                if isinstance(data.get("omitted_item_types"), Mapping)
                else None
            ),
        )

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


# -- measurement -------------------------------------------------------------


def _compact_json(obj: Any) -> str:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def _item_chars(item: PacketItem) -> int:
    """Cost of one item: compact JSON of data + provenance (metadata is
    never free)."""
    return len(_compact_json(item.to_dict()))


def _essential_chars(packet: ContextPacket) -> int:
    """Cost of the essential block: identity, task/focus, project facts,
    packet-level provenance and diagnostics framing, with all item lists
    and warnings emptied."""
    data = packet.to_dict()
    for key in _ITEM_SECTIONS + ("warnings",):
        if key in data:  # rlkctx1 packets have no git_facts key at all
            data[key] = []
    return len(_compact_json(data))


def _budget_diagnostics(budget: ContextBudget) -> dict:
    return {
        "budgeted": True,
        "max_estimated_tokens": budget.max_estimated_tokens,
        "max_characters": budget.max_characters,
        "reserve_tokens": budget.reserve_tokens,
        "chars_per_token": budget.chars_per_token,
        "estimation_method": budget.estimation_method,
        "estimation_version": budget.estimation_version,
    }


def prepare_budgeted_packet(
    packet: ContextPacket, budget: ContextBudget
) -> ContextPacket:
    """Deepcopy of ``packet`` with the diagnostics split applied: the
    original R1E composition diagnostics are preserved verbatim under
    ``diagnostics["composition"]`` and ``diagnostics["budget"]`` carries
    the policy fields plus the final-state stats of the current working
    state (all items included, pre-ladder). The original packet is never
    mutated."""
    _validate_inputs(packet, budget)
    working = copy.deepcopy(packet)
    working.diagnostics = {
        "composition": dict(working.diagnostics),
        "budget": _budget_diagnostics(budget),
    }
    _budget_stats(packet, working, budget, {}, True)
    return working


def _validate_inputs(packet: ContextPacket, budget: ContextBudget) -> None:
    if not isinstance(packet, ContextPacket):
        raise BudgetValidationError("packet must be a ContextPacket")
    if not isinstance(budget, ContextBudget):
        raise BudgetValidationError("budget must be a ContextBudget")
    _validate_snippet_types(packet)


def _validate_snippet_types(packet: ContextPacket) -> None:
    """Reject typed malformed packets: a snippet must be str or None.
    The message names section/index and the offending TYPE, never the
    value (it could carry secrets)."""
    for index, item in enumerate(packet.code_facts):
        if "snippet" not in item.data:
            continue
        snippet = item.data["snippet"]
        if snippet is not None and not isinstance(snippet, str):
            raise BudgetValidationError(
                f"code_facts[{index}] snippet must be a string or None; "
                f"got {type(snippet).__name__}"
            )


def _budget_stats(
    packet: ContextPacket,
    working: ContextPacket,
    budget: ContextBudget,
    actions: Dict[Tuple[str, str, int], Tuple[str, str]],
    satisfied: bool,
) -> str:
    """Refresh the final-state fields of ``diagnostics["budget"]`` so they
    describe the CURRENT working packet exactly: final per-section counts,
    surviving source ids in packet order, omitted/truncated source ids in
    original packet order, final totals and the satisfied flag. Counts and
    id lists only — never item copies. ``final_total_chars`` is
    self-referential (it is part of the measured payload) and is resolved
    by a deterministic fixed-point iteration. Returns the converged
    payload so callers can measure it without re-serializing."""
    diag = working.diagnostics["budget"]
    diag["final_counts"] = {
        "memories": len(working.memories),
        "code_references": len(working.code_references),
        "code_facts": len(working.code_facts),
        "pending": len(working.pending),
        "handoffs": len(working.handoffs),
        "warnings": len(working.warnings),
    }
    if _carries_git_section(working):
        diag["final_counts"]["git_facts"] = len(working.git_facts)
    diag["included_source_ids"] = (
        [
            _source_id(section, item)
            for section in _ITEM_SECTIONS
            for item in getattr(working, section)
        ]
        # R6C metadata compaction drops this list from the SHIPPED packet
        # (it is fully derivable from the packet sections); the flag keeps
        # the refresh from silently re-adding it after compaction fired.
        if not diag.get("metadata_compacted")
        else None
    )
    if diag["included_source_ids"] is None:
        del diag["included_source_ids"]
    omitted: List[str] = []
    truncated: List[str] = []
    counters: Dict[Tuple[str, str], int] = {}
    for section in _ITEM_SECTIONS:
        kind = _SECTION_KINDS[section]
        for item in getattr(packet, section):
            source_id = _source_id(section, item)
            key = (kind, source_id)
            occurrence = counters.get(key, 0)
            counters[key] = occurrence + 1
            action = actions.get((kind, source_id, occurrence))
            item_omitted = action is not None and action[0] == ACTION_OMITTED
            if item_omitted:
                omitted.append(source_id)
            if kind == "code_fact" and not item_omitted:
                snippet_action = actions.get(("snippet", source_id, occurrence))
                if snippet_action is not None and snippet_action[0] in (
                    ACTION_TRUNCATED,
                    ACTION_REFERENCE_ONLY,
                ):
                    truncated.append(source_id)
    diag["omitted_source_ids"] = omitted
    diag["truncated_source_ids"] = truncated
    diag["satisfied"] = satisfied
    # Self-referential totals: the payload contains these very fields, so
    # iterate to a fixed point. Previous values are kept as a warm start
    # (digit widths are almost always stable), converging in one dump.
    diag.setdefault("final_total_chars", 0)
    diag.setdefault("final_estimated_tokens", 0)
    payload = ""
    for _ in range(4):
        payload = working.to_json()
        chars = len(payload)
        tokens = estimate_tokens(payload, budget.chars_per_token)
        previous = (diag["final_total_chars"], diag["final_estimated_tokens"])
        if chars == previous[0]:
            break
        diag["final_total_chars"] = chars
        diag["final_estimated_tokens"] = tokens
        if len(str(chars)) == len(str(previous[0])) and len(
            str(tokens)
        ) == len(str(previous[1])):
            # Same digit widths: writing the new totals cannot change the
            # payload length, so these values are already the fixed point
            # (the returned payload is exact in length, which is all the
            # budget measurement uses).
            break
    return payload


def _usage(
    packet: ContextPacket,
    chars_per_token: float,
    decisions: Optional[List[BudgetDecision]] = None,
) -> ContextUsage:
    sections: Dict[str, dict] = {}
    essential = _essential_chars(packet)
    sections["essential"] = {
        "chars": essential,
        "estimated_tokens": _tokens_for_chars(essential, chars_per_token),
        "item_count": 1,
    }
    for section in _ITEM_SECTIONS:
        if section == "git_facts" and not _carries_git_section(packet):
            continue
        chars = sum(_item_chars(item) for item in getattr(packet, section))
        items = len(getattr(packet, section))
        snippets = 0
        if section == "code_facts":
            for item in packet.code_facts:
                snippet = item.data.get("snippet")
                if isinstance(snippet, str):
                    snippets += 1
        sections[section] = {
            "chars": chars,
            "estimated_tokens": _tokens_for_chars(chars, chars_per_token),
            "item_count": items + snippets,
        }
    warning_chars = sum(len(_compact_json(w.to_dict())) for w in packet.warnings)
    sections["warnings"] = {
        "chars": warning_chars,
        "estimated_tokens": _tokens_for_chars(warning_chars, chars_per_token),
        "item_count": len(packet.warnings),
    }
    payload = packet.to_json()
    usage = ContextUsage(
        total_chars=len(payload),
        estimated_tokens=estimate_tokens(payload, chars_per_token),
        sections=sections,
    )
    if decisions is None:
        units = sum(len(getattr(packet, s)) for s in _ITEM_SECTIONS)
        units += sum(
            1
            for item in packet.code_facts
            if isinstance(item.data.get("snippet"), str)
        )
        usage.included_count = units
    else:
        for decision in decisions:
            if decision.section == "essential":
                continue
            if decision.action == ACTION_INCLUDED:
                usage.included_count += 1
            elif decision.action == ACTION_OMITTED:
                usage.omitted_count += 1
            elif decision.action in (ACTION_TRUNCATED, ACTION_REFERENCE_ONLY):
                usage.truncated_count += 1
    return usage


def _fits(
    working: ContextPacket, budget: ContextBudget, payload: str = None
) -> bool:
    """True when the working packet fits within budget MINUS reserve.
    The token reserve is token-denominated; the character cap is exact."""
    if payload is None:
        payload = working.to_json()
    if (
        estimate_tokens(payload, budget.chars_per_token)
        > budget.max_estimated_tokens - budget.reserve_tokens
    ):
        return False
    if (
        budget.max_characters is not None
        and len(payload) > budget.max_characters
    ):
        return False
    return True


def _source_id(section: str, item: PacketItem) -> str:
    if section in ("code_references", "code_facts"):
        return (
            item.provenance.code_reference_id
            or item.data.get("code_reference_id")
            or ""
        )
    if section == "git_facts":
        return (
            item.provenance.code_reference_id
            or str(item.data.get("kind") or "")
        )
    return item.provenance.memory_id or ""


def _is_structural_code_fact(item: PacketItem) -> bool:
    """CBM structural facts are optional, never the protected code focus."""
    return is_structural_code_fact(item)


# -- the accountant ------------------------------------------------------------


def apply_budget(
    packet: ContextPacket,
    budget: ContextBudget,
    *,
    relevance=None,
) -> BudgetedContext:
    """Apply the fixed reduction ladder. Returns a BudgetedContext; never
    raises for an over-budget packet (typed BUDGET_UNSATISFIABLE instead)
    and never mutates the input packet. The ladder measures the packet
    WITH its final budget diagnostics, so the hard guarantee covers the
    exact shipped payload.

    ``relevance`` is an optional R1G RankedContext for THIS packet (its
    ``original_packet_id`` must match, and when it carries a
    ``packet_fingerprint`` the scored-section (source_id, occurrence)
    layout must match too — packet ids are content-insensitive). When supplied, the ladder
    STRUCTURE is unchanged — essential stays protected, snippet steps
    1-2 are untouched, and the class order of steps 3-5 is preserved —
    but the REMOVAL ORDER inside steps 3, 4 and 5 becomes ascending
    relevance (lowest total first, ties by the documented R1G chain)
    instead of strictly-from-end. With ``relevance=None`` behavior is
    byte-identical to plain R1F."""
    _validate_inputs(packet, budget)
    if relevance is not None:
        if getattr(relevance, "original_packet_id", None) != packet.packet_id:
            raise BudgetValidationError(
                "relevance ranking does not belong to this packet"
            )
        fingerprint = getattr(relevance, "packet_fingerprint", None)
        if fingerprint:
            from .relevance import packet_fingerprint

            if fingerprint != packet_fingerprint(packet):
                raise BudgetValidationError(
                    "relevance ranking does not belong to this packet"
                )
    cpt = budget.chars_per_token
    original_usage = _usage(packet, cpt)
    working = prepare_budgeted_packet(packet, budget)
    current_handoff_id = current_handoff_memory_id(packet)
    # R6C: the mandated metadata (salience labels + packet_status block)
    # is attached BEFORE the ladder so the ladder measures its footprint
    # and sheds items only after the metadata had its chance to compact.
    # The skeleton carries the worst-case block footprint; the true block
    # replaces it after the ladder.
    _attach_salience_labels(working, current_handoff_id)
    working.packet_status = build_status_skeleton(working, cpt)

    # Original-packet occurrence per working item, computed BEFORE any
    # removal: identical to the from-end prefix counting when relevance
    # is None, and correct for arbitrary relevance-driven removal order.
    occ_map: Dict[int, int] = {}
    for section in _ITEM_SECTIONS:
        counters: Dict[str, int] = {}
        for item in getattr(working, section):
            sid = _source_id(section, item)
            occ_map[id(item)] = counters.get(sid, 0)
            counters[sid] = counters.get(sid, 0) + 1

    actions: Dict[Tuple[str, str, int], Tuple[str, str]] = {}

    # fits() is called before every candidate mutation; the stats refresh
    # and re-measurement only happen when the working state actually
    # changed since the last call. The key is exact: every ladder mutation
    # either shrinks a section, adds an action entry, or changes the
    # snippet payload total (truncation shortens it, reference-only drops
    # the key entirely — and both also cover action-entry overwrites).
    # Metadata compaction mutates NONE of the tracked sizes, so it
    # invalidates the probe explicitly via probe["key"] = None.
    probe = {"key": None, "fits": False}

    def fits() -> bool:
        # Refresh the final-state diagnostics first: they are part of the
        # measured payload, so what is measured is what would ship.
        key = (
            len(actions),
            len(working.memories),
            len(working.code_references),
            len(working.code_facts),
            len(working.pending),
            len(working.handoffs),
            len(working.git_facts),
            len(working.warnings),
            sum(
                len(fact.data["snippet"])
                for fact in working.code_facts
                if isinstance(fact.data.get("snippet"), str)
            ),
        )
        if key != probe["key"]:
            payload = _budget_stats(packet, working, budget, actions, True)
            probe["key"] = key
            probe["fits"] = _fits(working, budget, payload)
        return probe["fits"]

    while not fits():
        snapshot = working.to_json()
        _ladder(working, actions, fits, occ_map, relevance,
                current_handoff_id, probe)
        if working.to_json() == snapshot:
            # Ladder exhausted against the worst-case skeleton block.
            # The true (post-ladder) block is never larger, so rebuild it
            # once and re-check before declaring the budget
            # unsatisfiable.
            _settle_packet_status(
                packet, working, budget, actions, cpt, current_handoff_id
            )
            if not (_hard_guarantee(working, budget) and _fits(working, budget)):
                working.packet_status = _shrink_to_fit(
                    packet, working, budget, actions
                )
            break

    # R6C: salience labels on survivors (only where an R4D sidecar
    # exists) and the additive packet_status block, both measured by the
    # hard guarantee. Token accounting is self-referential (the block is
    # part of the measured payload), so the block is rebuilt to a fixed
    # point exactly like the diagnostics totals. The block shrinks along
    # a fixed order instead of ever breaking the budget.
    _attach_salience_labels(working, current_handoff_id)
    _settle_packet_status(
        packet, working, budget, actions, cpt, current_handoff_id
    )
    if not (_hard_guarantee(working, budget) and _fits(working, budget)):
        working.packet_status = _shrink_to_fit(
            packet, working, budget, actions
        )

    satisfied = _fits(working, budget) and _hard_guarantee(working, budget)
    _budget_stats(packet, working, budget, actions, satisfied)
    if satisfied and not (
        _fits(working, budget) and _hard_guarantee(working, budget)
    ):
        # The definitive stats write shifted the payload across the line.
        satisfied = False
        _budget_stats(packet, working, budget, actions, False)

    decisions = _build_decisions(packet, working, actions, cpt, occ_map)
    status = STATUS_OK if satisfied else STATUS_UNSATISFIABLE
    final_packet = working if satisfied else None
    final_usage = _usage(working, cpt, decisions)
    result = BudgetedContext(
        original_packet_id=packet.packet_id,
        budget=budget,
        status=status,
        original_usage=original_usage,
        final_usage=final_usage,
        decisions=decisions,
        packet=final_packet,
        satisfied=satisfied,
        relevance_version=(
            getattr(relevance, "relevance_version", None)
            if relevance is not None
            else None
        ),
        minimum_useful_tokens=_minimum_useful_tokens(
            packet, budget, current_handoff_id
        ),
        recommended_max_tokens=_recommended_max_tokens(
            packet, budget, current_handoff_id
        ),
        omitted_item_types=status_omitted_item_types(
            packet, _omitted_items(packet, actions)
        ),
    )
    result.report_id = _report_id(
        packet.packet_id,
        budget,
        decisions,
        working,
    )
    return result


def _omitted_items(
    packet: ContextPacket,
    actions: Dict[Tuple[str, str, int], Tuple[str, str]],
) -> List[Tuple[str, PacketItem]]:
    """(section, original_item) pairs the ladder omitted, packet order."""
    omitted: List[Tuple[str, PacketItem]] = []
    for section in _ITEM_SECTIONS:
        kind = _SECTION_KINDS[section]
        counters: Dict[str, int] = {}
        for item in getattr(packet, section):
            sid = _source_id(section, item)
            key = (kind, sid)
            occurrence = counters.get(key, 0)
            counters[key] = occurrence + 1
            action = actions.get((kind, sid, occurrence))
            if action is not None and action[0] == ACTION_OMITTED:
                omitted.append((section, item))
    return omitted


def _budget_truncated(
    actions: Dict[Tuple[str, str, int], Tuple[str, str]],
) -> bool:
    """True when any ladder action reduced content without omitting it:
    snippet truncation or reference-only reduction. R6C-FIX: a
    truncation-only reduction is budget-driven loss and must be reported
    by the packet status block (uses the existing action constants, no
    duplicated semantics)."""
    return any(
        action[0] in (ACTION_TRUNCATED, ACTION_REFERENCE_ONLY)
        for action in actions.values()
    )


def _settle_packet_status(
    packet: ContextPacket,
    working: ContextPacket,
    budget: ContextBudget,
    actions: Dict[Tuple[str, str, int], Tuple[str, str]],
    cpt: float,
    current_handoff_id: Optional[str],
) -> None:
    """Rebuild the TRUE packet_status block to a fixed point: the block
    carries token accounting measured over the payload it ships in, so
    each round re-settles the self-referential diagnostics totals and
    rebuilds until the block re-measures to itself (bounded rounds;
    digit-width convergence exactly like the diagnostics totals).

    Conservative fallback: near a digit boundary the block totals and
    the diagnostics totals can chase each other (both are part of the
    bytes they measure) and neither state is exactly self-consistent.
    The shipped state is then chosen deterministically by
    :func:`_conservative_status_choice` — exact if possible, else the
    over-estimating one, never an under-count."""
    omitted_pairs = _omitted_items(packet, actions)
    budget_truncated = _budget_truncated(actions)

    def rebuild() -> dict:
        return build_status(
            working,
            original_packet=packet,
            budget_omitted_items=omitted_pairs,
            budget_truncated=budget_truncated,
            chars_per_token=cpt,
        )

    def settle_pass() -> bool:
        """One bounded settle round: rebuild until the block re-measures
        to itself, else apply the conservative choice. Returns whether
        the shipped block is exactly self-consistent."""
        attached = working.packet_status
        rebuilt = rebuild()
        for _ in range(3):
            if _status_claim_settled(attached, rebuilt):
                return True
            attached = _attach_settled_rebuild(attached, rebuilt)
            working.packet_status = attached
            _budget_stats(packet, working, budget, actions, True)
            rebuilt = rebuild()
        if _status_claim_settled(attached, rebuilt):
            return True
        working.packet_status = _conservative_status_choice(
            working, (attached, rebuilt), cpt
        )
        _budget_stats(packet, working, budget, actions, True)
        return False

    if not settle_pass():
        # The trailing diagnostics refresh can shift bytes across a width
        # boundary after the conservative choice; one re-pass settles the
        # claim over the refreshed bytes (bounded, deterministic).
        settle_pass()


def _actions_from_decisions(
    decisions: List[BudgetDecision],
) -> Dict[Tuple[str, str, int], Tuple[str, str]]:
    """Rebuild the ladder's (kind, source_id, occurrence) action map from
    the audit decisions. Decisions are emitted in original packet order,
    one row per content unit, so the same (section, source_id) counting
    reproduces the exact occurrence indices; snippet rows carry their
    parent fact's occurrence under the ``snippet:`` source-id prefix."""
    actions: Dict[Tuple[str, str, int], Tuple[str, str]] = {}
    counters: Dict[Tuple[str, str], int] = {}
    for decision in decisions or ():
        if decision.section == "essential":
            continue
        key = (decision.section, decision.source_id)
        occurrence = counters.get(key, 0)
        counters[key] = occurrence + 1
        kind = _SECTION_KINDS.get(decision.section)
        if kind is None:
            continue
        source_id = decision.source_id
        if source_id.startswith("snippet:"):
            actions[("snippet", source_id[len("snippet:"):], occurrence)] = (
                decision.action,
                decision.reason,
            )
        else:
            actions[(kind, source_id, occurrence)] = (
                decision.action,
                decision.reason,
            )
    return actions


def settle_delivered_status(
    packet: ContextPacket,
    working: ContextPacket,
    decisions: List[BudgetDecision],
    budget: ContextBudget,
) -> None:
    """Re-settle ``working``'s status block after post-ladder mutations.

    The ladder settled ``packet_status`` against ITS final bytes; any
    additive metadata attached afterwards (per-item budget treatments,
    freshness tags) shifts those bytes, leaving the block's
    ``token_accounting`` describing a packet that is no longer the one
    delivered. This rebuilds the block and the self-referential
    diagnostics totals to a fixed point over the exact delivered
    payload. Call BEFORE ``reconcile_final_packet`` so the report is
    rebound to the settled bytes.

    When the ladder already SHRANK the block (extreme pressure; no
    ``token_accounting`` key left), the shrink decision is preserved:
    only the self-referential diagnostics totals are refreshed, and the
    block is never grown back over a budget that forced it down.
    """
    actions = _actions_from_decisions(decisions)
    status = working.packet_status
    if status and "token_accounting" not in status:
        _budget_stats(packet, working, budget, actions, True)
        return
    _settle_packet_status(
        packet,
        working,
        budget,
        actions,
        budget.chars_per_token,
        current_handoff_memory_id(packet),
    )


def _shrink_to_fit(
    packet: ContextPacket,
    working: ContextPacket,
    budget: ContextBudget,
    actions: Dict[Tuple[str, str, int], Tuple[str, str]],
) -> dict:
    """Deterministic shrink cascade for the status block: drop keys in
    fixed value order (token accounting, recovery hints, counts,
    sufficiency) until the payload fits again. Last resort is an empty
    block — the completeness booleans then live only in the budget
    report and the omissions stay visible through the audit decisions."""
    status = working.packet_status or {}
    while True:
        working.packet_status = status
        _budget_stats(packet, working, budget, actions, True)
        if _hard_guarantee(working, budget) and _fits(working, budget):
            return status
        shrunk = shrink_status(status)
        if shrunk is None:
            working.packet_status = {}
            _budget_stats(packet, working, budget, actions, True)
            return {}
        status = shrunk


def _attach_salience_labels(
    working: ContextPacket, current_handoff_id: Optional[str]
) -> None:
    """Per-item ``explain["salience"]`` tier labels on survivors.

    Labels attach only where an R4D sidecar already exists; packets
    without explainability keep their exact wire form (tier counts are
    still visible in ``packet_status``).
    """
    seen_direct = False
    for section in _ITEM_SECTIONS:
        for item in getattr(working, section):
            if item.explain is None:
                continue
            is_direct = False
            if section == "code_facts" and not _is_structural_code_fact(item):
                is_direct = not seen_direct
                seen_direct = True
            item.explain["salience"] = classify_item(
                section,
                item,
                current_handoff_memory_id=current_handoff_id,
                is_direct_code_fact=is_direct,
            )


def _skeleton_packet(
    packet: ContextPacket, current_handoff_id: Optional[str]
) -> ContextPacket:
    """Deepcopy pruned to the must-keep skeleton: the essential frame,
    protected items (pending + current handoff), the first code
    reference and the direct (first non-structural) code fact."""
    skeleton = copy.deepcopy(packet)
    skeleton.memories = []
    skeleton.pending = list(packet.pending)
    skeleton.handoffs = [
        item
        for item in packet.handoffs
        if item.provenance.memory_id == current_handoff_id
    ]
    skeleton.code_references = list(packet.code_references[:1])
    direct_fact = None
    for item in packet.code_facts:
        if not _is_structural_code_fact(item):
            direct_fact = item
            break
    skeleton.code_facts = [copy.deepcopy(direct_fact)] if direct_fact else []
    skeleton.git_facts = []
    return skeleton


def _high_salience_packet(
    packet: ContextPacket, current_handoff_id: Optional[str]
) -> ContextPacket:
    """Deepcopy with every OPTIONAL-tier item removed: the packet shape
    that omits nothing high-salience (snippets kept intact)."""
    pruned = copy.deepcopy(packet)
    pruned.memories = [
        item
        for item in packet.memories
        if classify_memory_type(item.data.get("memory_type")) == "important"
    ]
    pruned.handoffs = list(packet.handoffs)
    pruned.pending = list(packet.pending)
    pruned.code_references = list(packet.code_references)
    pruned.git_facts = [
        item for item in packet.git_facts if classify_git_fact(
            item.data.get("kind")
        ) == "important"
    ]
    kept_fact = False
    facts: List[PacketItem] = []
    for item in packet.code_facts:
        if _is_structural_code_fact(item):
            continue
        if kept_fact:
            continue
        kept_fact = True
        facts.append(copy.deepcopy(item))
    pruned.code_facts = facts
    return pruned


def _minimum_useful_tokens(
    packet: ContextPacket, budget: ContextBudget, current_handoff_id: Optional[str]
) -> int:
    skeleton = prepare_budgeted_packet(
        _skeleton_packet(packet, current_handoff_id), budget
    )
    _attach_salience_labels(skeleton, current_handoff_id)
    skeleton.packet_status = build_status_skeleton(
        skeleton, budget.chars_per_token
    )
    # Full metadata compaction with no budget gate: the honest floor the
    # ladder can actually produce while keeping every must-keep item.
    _compact_metadata(skeleton, None, None)
    _budget_stats(skeleton, skeleton, budget, {}, True)
    return estimate_tokens(skeleton.to_json(), budget.chars_per_token)


def _recommended_max_tokens(
    packet: ContextPacket, budget: ContextBudget, current_handoff_id: Optional[str]
) -> int:
    prepared = prepare_budgeted_packet(
        _high_salience_packet(packet, current_handoff_id), budget
    )
    _attach_salience_labels(prepared, current_handoff_id)
    prepared.packet_status = build_status_skeleton(
        prepared, budget.chars_per_token
    )
    size = estimate_tokens(prepared.to_json(), budget.chars_per_token)
    return size + budget.reserve_tokens


def _hard_guarantee(working: ContextPacket, budget: ContextBudget) -> bool:
    """Assertion-style check against the FULL budget (no reserve) over the
    exact payload that would ship, diagnostics included."""
    payload = working.to_json()
    if (
        estimate_tokens(payload, budget.chars_per_token)
        > budget.max_estimated_tokens
    ):
        return False
    if (
        budget.max_characters is not None
        and len(payload) > budget.max_characters
    ):
        return False
    return True


def _ladder(
    working: ContextPacket,
    actions: Dict[Tuple[str, str, int], Tuple[str, str]],
    fits,
    occ_map: Dict[int, int],
    relevance,
    current_handoff_id: Optional[str] = None,
    probe: Optional[dict] = None,
) -> None:
    # Step 1: truncate oversized snippets to the fixed ladder cap.
    counters: Dict[str, int] = {}
    for fact in working.code_facts:
        if fits():
            return
        sid = _source_id("code_facts", fact)
        occurrence = counters.get(sid, 0)
        counters[sid] = occurrence + 1
        snippet = fact.data.get("snippet")
        if isinstance(snippet, str) and len(snippet) > SNIPPET_LADDER_CAP:
            original_length = len(snippet)
            fact.data["snippet"] = snippet[:SNIPPET_LADDER_CAP] + TRUNCATION_MARKER
            fact.data["snippet_truncated"] = True
            # R6C: truncation is never silent — the fact declares what
            # was cut and where the full evidence remains available.
            fact.data["snippet_original_length"] = original_length
            fact.data["snippet_returned_length"] = len(fact.data["snippet"])
            fact.data["snippet_continuation_ref"] = sid or None
            actions[("snippet", sid, occurrence)] = (
                ACTION_TRUNCATED,
                REASON_SNIPPET_LADDER,
            )
    # Step 2: drop snippet payloads entirely (reference-only facts).
    counters = {}
    for fact in working.code_facts:
        if fits():
            return
        sid = _source_id("code_facts", fact)
        occurrence = counters.get(sid, 0)
        counters[sid] = occurrence + 1
        if isinstance(fact.data.get("snippet"), str):
            fact.data.pop("snippet", None)
            fact.data.pop("snippet_truncated", None)
            fact.data.pop("snippet_original_length", None)
            fact.data.pop("snippet_returned_length", None)
            fact.data.pop("snippet_continuation_ref", None)
            actions[("snippet", sid, occurrence)] = (
                ACTION_REFERENCE_ONLY,
                REASON_SNIPPET_LADDER,
            )
    if relevance is None:
        _ladder_fixed_order(working, actions, fits, occ_map,
                            current_handoff_id)
    else:
        _ladder_ranked_order(working, actions, fits, occ_map, relevance,
                             current_handoff_id)
    # R6C metadata compaction: verbose metadata is sacrificed BEFORE any
    # high-salience or must-keep item. Each sub-step checks fits() and
    # mutates only while over budget; the probe is invalidated because
    # compaction changes bytes without changing any tracked size.
    if not fits():
        _compact_metadata(working, fits, probe)
    if not fits():
        if relevance is None:
            _omit_important_fixed_order(working, actions, fits, occ_map,
                                        current_handoff_id)
        else:
            _omit_important_ranked_order(working, actions, fits, occ_map,
                                         relevance, current_handoff_id)


# -- R6C metadata compaction ---------------------------------------------------


_COMPACT_FRESHNESS_KEYS = ("state", "reason_code")


def _compact_item_explain(explain: dict) -> bool:
    """Reduce one item's R4D sidecar to its compact form. Returns True
    when anything changed. Kept: salience, budget treatment, evidence
    ref, contradiction ids, freshness state/reason_code and the relevance
    TOTAL. Dropped: per-signal relevance dumps, trust detail, verbose
    freshness fields."""
    changed = False
    selection = explain.get("selection")
    if isinstance(selection, dict):
        relevance = selection.get("relevance")
        if isinstance(relevance, Mapping) and "total" in relevance:
            if set(relevance) != {"total"}:
                selection["relevance"] = {"total": relevance["total"]}
                changed = True
        if selection.pop("reasons", None) is not None:
            changed = True
    if explain.pop("trust", None) is not None:
        changed = True
    freshness = explain.get("freshness")
    if isinstance(freshness, dict) and set(freshness) != set(
        _COMPACT_FRESHNESS_KEYS
    ):
        compact = {
            key: freshness[key]
            for key in _COMPACT_FRESHNESS_KEYS
            if key in freshness
        }
        explain["freshness"] = compact
        changed = True
    return changed


def _group_notices(packet: ContextPacket) -> bool:
    """Group packet-level freshness notices by (state, reason_code,
    recommended_action) with a shared evidence_ref list. Same typing,
    one action string instead of one per item."""
    explainability = packet.explainability
    notices = explainability.get("notices") if isinstance(
        explainability, dict
    ) else None
    if not notices or not isinstance(notices, list):
        return False
    if notices and isinstance(notices[0], dict) and "evidence_refs" in notices[0]:
        return False  # already grouped
    groups: Dict[Tuple[str, str, str], List[str]] = {}
    order: List[Tuple[str, str, str]] = []
    for notice in notices:
        if not isinstance(notice, dict):
            continue
        key = (
            str(notice.get("state") or ""),
            str(notice.get("reason_code") or ""),
            str(notice.get("recommended_action") or ""),
        )
        if key not in groups:
            groups[key] = []
            order.append(key)
        ref = notice.get("evidence_ref")
        if ref:
            groups[key].append(str(ref))
    if len(order) == len(notices) and all(
        len(groups[key]) == 1 for key in order
    ):
        return False  # grouping would not save anything
    grouped = []
    for key in order:
        state, reason_code, action = key
        entry = {"state": state}
        if reason_code:
            entry["reason_code"] = reason_code
        entry["evidence_refs"] = groups[key]
        if action:
            entry["recommended_action"] = action
        grouped.append(entry)
    explainability["notices"] = grouped
    return True


# Envelope fields that are storage/bookkeeping duplication inside a
# single-project packet: envelope version, dedupe key, and fields whose
# packet-level value already states the same fact.
_SIGNED_FIELDS_ALWAYS_DROPPED = ("v", "dedup_key")


def _slim_memory_envelope(data: dict, working: ContextPacket) -> bool:
    changed = False
    for key in _SIGNED_FIELDS_ALWAYS_DROPPED:
        if key in data:
            del data[key]
            changed = True
    if data.get("source_tool") == "relinkra" and "source_tool" in data:
        del data["source_tool"]
        changed = True
    if "agent_id" in data and data.get("agent_id") in (
        None, "", data.get("agent_type"),
    ):
        del data["agent_id"]
        changed = True
    if (
        "project_id" in data
        and data.get("project_id") == working.project_id
    ):
        del data["project_id"]
        changed = True
    if (
        "repository_identity" in data
        and working.repository_identity is not None
        and data.get("repository_identity") == working.repository_identity
    ):
        del data["repository_identity"]
        changed = True
    return changed


# Provenance fields duplicated verbatim in the item data; the provenance
# copy is the redundant one (source, why_included, memory_id and
# code_reference_id always stay).
_DUPLICATED_PROVENANCE_FIELDS = (
    ("agent_type", "agent_type"),
    ("topic_key", "topic_key"),
    ("workspace_id", "workspace_id"),
    ("cbm_project_name", "cbm_project_name"),
    ("resolution_state", "resolution_state"),
)


def _slim_provenance(item: PacketItem) -> bool:
    changed = False
    data = item.data if isinstance(item.data, dict) else {}
    for field_name, data_key in _DUPLICATED_PROVENANCE_FIELDS:
        value = getattr(item.provenance, field_name)
        if value is not None and data.get(data_key) == value:
            setattr(item.provenance, field_name, None)
            changed = True
    return changed


def _compact_metadata(
    working: ContextPacket, fits, probe: Optional[dict]
) -> None:
    """R6C ladder step: deterministic metadata compaction, most valuable
    first. Runs only while over budget; every mutation invalidates the
    fits() probe because compaction changes bytes without changing any
    tracked size. ``fits=None`` runs every sub-step unconditionally
    (used to measure the true must-keep floor for budget guidance)."""
    def invalidated():
        if probe is not None:
            probe["key"] = None

    def over() -> bool:
        return fits is None or not fits()

    # a) per-item explain sidecars (all sections, fixed order)
    for section in _ITEM_SECTIONS:
        for item in getattr(working, section):
            if not over():
                return
            if item.explain and _compact_item_explain(item.explain):
                invalidated()
    # b) packet-level freshness notices -> grouped form
    if over() and _group_notices(working):
        invalidated()
    # c) composition selected_source_ids: duplicated by the sections plus
    #    the audit trail
    composition = working.diagnostics.get("composition")
    if (
        over()
        and isinstance(composition, dict)
        and composition.pop("selected_source_ids", None) is not None
    ):
        invalidated()
    # d) budget included_source_ids: fully derivable from the sections
    budget_diag = working.diagnostics.get("budget")
    if over() and isinstance(budget_diag, dict):
        if budget_diag.pop("included_source_ids", None) is not None:
            budget_diag["metadata_compacted"] = True
            invalidated()
    # e) provenance fields duplicated in the item data
    for section in _ITEM_SECTIONS:
        for item in getattr(working, section):
            if not over():
                return
            if _slim_provenance(item):
                invalidated()
    # f) memory-envelope bookkeeping (memories/pending/handoffs)
    for section in ("memories", "pending", "handoffs"):
        for item in getattr(working, section):
            if not over():
                return
            if isinstance(item.data, dict) and _slim_memory_envelope(
                item.data, working
            ):
                invalidated()
    # g) notices reduce to a count; advisory detail is reconstructible by
    #    re-running the read with a larger budget
    explainability = working.explainability
    if (
        over()
        and isinstance(explainability, dict)
        and explainability.pop("notices", None) is not None
    ):
        explainability["freshness_notice_count"] = _count_notices(working)
        invalidated()
    # h) code-reference payloads drop identity fields duplicated at
    #    packet/item level (the code_reference_id stays: it IS the
    #    continuation reference)
    for item in working.code_references:
        if not over():
            return
        reference = item.data.get("reference") if isinstance(
            item.data, dict
        ) else None
        if isinstance(reference, dict) and _slim_reference_payload(reference):
            invalidated()


_NOTICE_STATE_KEYS = ("aging", "stale", "unknown")


def _count_notices(working: ContextPacket) -> int:
    """Deterministic count of freshness notices that would have been
    grouped (states that require independent verification)."""
    count = 0
    for section in _ITEM_SECTIONS:
        for item in getattr(working, section):
            freshness = (item.explain or {}).get("freshness") or {}
            if str(freshness.get("state") or "") in _NOTICE_STATE_KEYS:
                count += 1
    return count


# Reference payload fields duplicated at packet/item level inside a
# code_reference item's embedded CodeReference dict.
_REFERENCE_DUPLICATED_KEYS = (
    "project_id",
    "workspace_id",
    "repository_identity",
    "cbm_project_name",
)


def _slim_reference_payload(reference: dict) -> bool:
    changed = False
    for key in _REFERENCE_DUPLICATED_KEYS:
        if key in reference:
            del reference[key]
            changed = True
    for key in ("commit_sha", "symbol_kind"):
        if key in reference and reference.get(key) is None:
            del reference[key]
            changed = True
    return changed


def _omit_important_fixed_order(
    working: ContextPacket,
    actions: Dict[Tuple[str, str, int], Tuple[str, str]],
    fits,
    occ_map: Dict[int, int],
    current_handoff_id: Optional[str],
) -> None:
    """Step 6 exactly as plain R1F, minus MUST_KEEP items: important
    memories from the end, then non-current handoffs, then git facts,
    then code_references beyond the first. Pending items and the current
    handoff are protected (R6C salience)."""
    index = len(working.memories) - 1
    while index >= 0:
        if fits():
            return
        item = working.memories[index]
        working.memories.pop(index)
        sid = _source_id("memories", item)
        actions[("memory", sid, occ_map[id(item)])] = (
            ACTION_OMITTED, REASON_IMPORTANT_EXHAUSTED,
        )
        index -= 1
    index = len(working.handoffs) - 1
    while index >= 0:
        if fits():
            return
        item = working.handoffs[index]
        if item.provenance.memory_id != current_handoff_id:
            working.handoffs.pop(index)
            sid = _source_id("handoffs", item)
            actions[("handoff", sid, occ_map[id(item)])] = (
                ACTION_OMITTED, REASON_IMPORTANT_EXHAUSTED,
            )
        index -= 1
    while working.git_facts:
        if fits():
            return
        item = working.git_facts.pop()
        sid = _source_id("git_facts", item)
        actions[("git_fact", sid, occ_map[id(item)])] = (
            ACTION_OMITTED, REASON_IMPORTANT_EXHAUSTED,
        )
    while len(working.code_references) > 1:
        if fits():
            return
        item = working.code_references.pop()
        sid = _source_id("code_references", item)
        actions[("code_reference", sid, occ_map[id(item)])] = (
            ACTION_OMITTED, REASON_IMPORTANT_EXHAUSTED,
        )


def _omit_important_ranked_order(
    working: ContextPacket,
    actions: Dict[Tuple[str, str, int], Tuple[str, str]],
    fits,
    occ_map: Dict[int, int],
    relevance,
    current_handoff_id: Optional[str],
) -> None:
    """Step 6 with R1G guidance, minus MUST_KEEP items (R6C)."""
    positions = _rank_positions(relevance, "memories")
    for item in _worst_first(
        list(working.memories), "memories", positions, occ_map
    ):
        if fits():
            return
        sid = _source_id("memories", item)
        _remove_item(working.memories, item)
        actions[("memory", sid, occ_map[id(item)])] = (
            ACTION_OMITTED, REASON_IMPORTANT_EXHAUSTED,
        )
    positions = _rank_positions(relevance, "handoffs")
    sheddable = [
        item
        for item in working.handoffs
        if item.provenance.memory_id != current_handoff_id
    ]
    for item in _worst_first(sheddable, "handoffs", positions, occ_map):
        if fits():
            return
        sid = _source_id("handoffs", item)
        _remove_item(working.handoffs, item)
        actions[("handoff", sid, occ_map[id(item)])] = (
            ACTION_OMITTED, REASON_IMPORTANT_EXHAUSTED,
        )
    positions = _rank_positions(relevance, "git_facts")
    for item in _worst_first(
        list(working.git_facts), "git_facts", positions, occ_map,
        _git_fact_shed_rank,
    ):
        if fits():
            return
        sid = _source_id("git_facts", item)
        _remove_item(working.git_facts, item)
        actions[("git_fact", sid, occ_map[id(item)])] = (
            ACTION_OMITTED, REASON_IMPORTANT_EXHAUSTED,
        )
    positions = _rank_positions(relevance, "code_references")
    ref_extras = list(working.code_references[1:])
    for item in _worst_first(ref_extras, "code_references", positions, occ_map):
        if fits():
            return
        if len(working.code_references) <= 1:
            return
        sid = _source_id("code_references", item)
        _remove_item(working.code_references, item)
        actions[("code_reference", sid, occ_map[id(item)])] = (
            ACTION_OMITTED, REASON_IMPORTANT_EXHAUSTED,
        )


def _ladder_fixed_order(
    working: ContextPacket,
    actions: Dict[Tuple[str, str, int], Tuple[str, str]],
    fits,
    occ_map: Dict[int, int],
    current_handoff_id: Optional[str] = None,
) -> None:
    """Steps 3-5 exactly as plain R1F: removal from the END of each list.
    Byte-identical to the pre-relevance accountant. (Step 6 lives in
    ``_omit_important_fixed_order`` and runs after metadata compaction.)"""
    # Step 3: omit optional memories, from the END of the list first.
    index = len(working.memories) - 1
    while index >= 0:
        if fits():
            return
        item = working.memories[index]
        if classify_memory_type(item.data.get("memory_type")) == "optional":
            sid = _source_id("memories", item)
            working.memories.pop(index)
            actions[("memory", sid, occ_map[id(item)])] = (
                ACTION_OMITTED,
                REASON_OPTIONAL_EXHAUSTED,
            )
        index -= 1
    # Step 3b: omit OPTIONAL git facts (co_change, diff_fact, unknown
    # kinds), from the END of the list first.
    index = len(working.git_facts) - 1
    while index >= 0:
        if fits():
            return
        item = working.git_facts[index]
        if classify_git_fact(item.data.get("kind")) == "optional":
            sid = _source_id("git_facts", item)
            working.git_facts.pop(index)
            actions[("git_fact", sid, occ_map[id(item)])] = (
                ACTION_OMITTED,
                REASON_OPTIONAL_EXHAUSTED,
            )
        index -= 1
    # Step 4: shed optional CBM structural facts before protecting the direct
    # code fact. This also removes the sole code fact when it is structural.
    index = len(working.code_facts) - 1
    while index >= 0:
        if fits():
            return
        item = working.code_facts[index]
        if _is_structural_code_fact(item):
            working.code_facts.pop(index)
            sid = _source_id("code_facts", item)
            actions[("code_fact", sid, occ_map[id(item)])] = (
                ACTION_OMITTED,
                REASON_OPTIONAL_EXHAUSTED,
            )
        index -= 1
    # Step 5: omit code_facts beyond the FIRST (the direct focus), end first.
    while len(working.code_facts) > 1:
        if fits():
            return
        item = working.code_facts.pop()
        sid = _source_id("code_facts", item)
        actions[("code_fact", sid, occ_map[id(item)])] = (
            ACTION_OMITTED,
            REASON_OPTIONAL_EXHAUSTED,
        )


def _rank_positions(relevance, section: str) -> Dict[Tuple[str, int], int]:
    """(source_id, occurrence) -> best-first position in the R1G ranking."""
    positions: Dict[Tuple[str, int], int] = {}
    for position, score in enumerate(relevance.scores.get(section, ())):
        positions[(score.source_id, score.occurrence_index)] = position
    return positions


def _worst_first(
    items: List[PacketItem],
    section: str,
    positions: Dict[Tuple[str, int], int],
    occ_map: Dict[int, int],
    fallback_rank=None,
) -> List[PacketItem]:
    """Ascending relevance (worst first). The R1G best-first order already
    encodes the full tie-break chain (total DESC -> type_rank ASC ->
    timestamp DESC -> source_id ASC, duplicates in packet order), so
    reversing it removes lowest-score first and, on exact ties, the
    highest occurrence index first — matching the from-end R1F tie rule.

    For unscored sections (git_facts), ``fallback_rank`` provides a
    deterministic value order; lower rank means lower value, so the
    reverse sort removes the lowest-value fact first.
    """

    def key(item: PacketItem):
        sid = _source_id(section, item)
        pos = positions.get((sid, occ_map[id(item)]), float("inf"))
        if fallback_rank is None:
            return (pos,)
        return (pos, -fallback_rank(item))

    return sorted(items, key=key, reverse=True)


def _remove_item(items: List[PacketItem], item: PacketItem) -> None:
    """Remove by identity (duplicated PacketItems may compare equal)."""
    for index, candidate in enumerate(items):
        if candidate is item:
            items.pop(index)
            return


def _ladder_ranked_order(
    working: ContextPacket,
    actions: Dict[Tuple[str, str, int], Tuple[str, str]],
    fits,
    occ_map: Dict[int, int],
    relevance,
    current_handoff_id: Optional[str] = None,
) -> None:
    """Steps 3-5 with R1G guidance: same ladder STRUCTURE, but removal
    inside each step is ascending relevance instead of from-end. (Step 6
    lives in ``_omit_important_ranked_order`` and runs after metadata
    compaction.)"""
    # Step 3: omit optional memories, lowest relevance first.
    positions = _rank_positions(relevance, "memories")
    optional = [
        item
        for item in working.memories
        if classify_memory_type(item.data.get("memory_type")) == "optional"
    ]
    for item in _worst_first(optional, "memories", positions, occ_map):
        if fits():
            return
        sid = _source_id("memories", item)
        _remove_item(working.memories, item)
        actions[("memory", sid, occ_map[id(item)])] = (
            ACTION_OMITTED,
            REASON_OPTIONAL_EXHAUSTED,
        )
    # Step 3b: omit OPTIONAL git facts, lowest relevance first (unscored
    # section: relevance has no git_facts positions, so this degrades to
    # the deterministic end-first order).
    positions = _rank_positions(relevance, "git_facts")
    optional_git = [
        item
        for item in working.git_facts
        if classify_git_fact(item.data.get("kind")) == "optional"
    ]
    for item in _worst_first(
        optional_git, "git_facts", positions, occ_map, _git_fact_shed_rank
    ):
        if fits():
            return
        sid = _source_id("git_facts", item)
        _remove_item(working.git_facts, item)
        actions[("git_fact", sid, occ_map[id(item)])] = (
            ACTION_OMITTED,
            REASON_OPTIONAL_EXHAUSTED,
        )
    # Step 4: shed all optional CBM structural facts before protecting the
    # direct focus. Relevance may choose which structural fact disappears
    # first, but never makes one essential.
    positions = _rank_positions(relevance, "code_facts")
    structural = [
        item for item in working.code_facts if _is_structural_code_fact(item)
    ]
    for item in _worst_first(structural, "code_facts", positions, occ_map):
        if fits():
            return
        sid = _source_id("code_facts", item)
        _remove_item(working.code_facts, item)
        actions[("code_fact", sid, occ_map[id(item)])] = (
            ACTION_OMITTED,
            REASON_OPTIONAL_EXHAUSTED,
        )
    # Step 5: omit non-structural code_facts beyond the FIRST, lowest
    # relevance first.
    extras = [
        item for item in working.code_facts if not _is_structural_code_fact(item)
    ][1:]
    for item in _worst_first(extras, "code_facts", positions, occ_map):
        if fits():
            return
        if len(working.code_facts) <= 1:
            return
        sid = _source_id("code_facts", item)
        _remove_item(working.code_facts, item)
        actions[("code_fact", sid, occ_map[id(item)])] = (
            ACTION_OMITTED,
            REASON_OPTIONAL_EXHAUSTED,
        )


def _build_decisions(
    packet: ContextPacket,
    working: ContextPacket,
    actions: Dict[Tuple[str, str, int], Tuple[str, str]],
    cpt: float,
    occ_map: Dict[int, int],
) -> List[BudgetDecision]:
    """Deterministic audit: one decision per original content unit, in
    fixed section order, plus the essential structural block first.
    Bookkeeping is keyed by (kind, source_id, occurrence_index) so
    duplicated or empty source ids each get their OWN decision. The
    occurrence index is the ORIGINAL packet occurrence (``occ_map``):
    correct both for from-end removal and for R1G relevance-driven
    removal, which does not preserve a surviving prefix."""
    surviving: Dict[Tuple[str, str, int], PacketItem] = {}
    for section in _ITEM_SECTIONS:
        kind = _SECTION_KINDS[section]
        for item in getattr(working, section):
            source_id = _source_id(section, item)
            surviving[(kind, source_id, occ_map[id(item)])] = item

    decisions: List[BudgetDecision] = []
    orig_essential = _essential_chars(packet)
    final_essential = _essential_chars(working)
    decisions.append(
        BudgetDecision(
            source_id="essential",
            section="essential",
            action=ACTION_INCLUDED,
            reason=REASON_WITHIN_BUDGET,
            original_chars=orig_essential,
            original_estimated_tokens=_tokens_for_chars(orig_essential, cpt),
            final_chars=final_essential,
            final_estimated_tokens=_tokens_for_chars(final_essential, cpt),
        )
    )
    counters = {}
    for section in _ITEM_SECTIONS:
        kind = _SECTION_KINDS[section]
        for item in getattr(packet, section):
            source_id = _source_id(section, item)
            key = (kind, source_id)
            occurrence = counters.get(key, 0)
            counters[key] = occurrence + 1
            original_chars = _item_chars(item)
            action, reason = actions.get(
                (kind, source_id, occurrence),
                (ACTION_INCLUDED, REASON_WITHIN_BUDGET),
            )
            final_chars = (
                0
                if action == ACTION_OMITTED
                else _item_chars(surviving[(kind, source_id, occurrence)])
            )
            decisions.append(
                BudgetDecision(
                    source_id=source_id,
                    section=section,
                    action=action,
                    reason=reason,
                    original_chars=original_chars,
                    original_estimated_tokens=_tokens_for_chars(
                        original_chars, cpt
                    ),
                    final_chars=final_chars,
                    final_estimated_tokens=_tokens_for_chars(final_chars, cpt),
                )
            )
            snippet = item.data.get("snippet")
            if kind == "code_fact" and isinstance(snippet, str):
                if action == ACTION_OMITTED:
                    snip_action, snip_reason = ACTION_OMITTED, reason
                else:
                    snip_action, snip_reason = actions.get(
                        ("snippet", source_id, occurrence),
                        (ACTION_INCLUDED, REASON_WITHIN_BUDGET),
                    )
                if snip_action in (ACTION_OMITTED, ACTION_REFERENCE_ONLY):
                    final_snippet = ""
                else:
                    final_snippet = surviving[
                        (kind, source_id, occurrence)
                    ].data.get("snippet") or ""
                decisions.append(
                    BudgetDecision(
                        source_id=f"snippet:{source_id}",
                        section="code_facts",
                        action=snip_action,
                        reason=snip_reason,
                        original_chars=len(snippet),
                        original_estimated_tokens=_tokens_for_chars(
                            len(snippet), cpt
                        ),
                        final_chars=len(final_snippet),
                        final_estimated_tokens=_tokens_for_chars(
                            len(final_snippet), cpt
                        ),
                    )
                )
    return decisions


def _report_id(
    original_packet_id: str,
    budget: ContextBudget,
    decisions: List[BudgetDecision],
    final_packet: ContextPacket,
) -> str:
    """Hash policy, decisions and the exact final portable packet bytes."""
    counters: Dict[Tuple[str, str], int] = {}
    parts: List[str] = []
    for decision in decisions:
        key = (decision.section, decision.source_id)
        occurrence = counters.get(key, 0)
        counters[key] = occurrence + 1
        parts.append(f"{decision.section}:{decision.source_id}:{occurrence}")
    payload = (
        _REPORT_NAMESPACE
        + original_packet_id.encode("utf-8")
        + b"\x00"
        + _compact_json(budget.to_dict()).encode("utf-8")
        + b"\x00"
        + "\n".join(parts).encode("utf-8")
        + b"\x00"
        + final_packet.to_portable_json().encode("utf-8")
    )
    return REPORT_ID_PREFIX + hashlib.sha256(payload).hexdigest()[:32]
