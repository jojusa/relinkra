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
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .context_packet import PACKET_VERSION, ContextPacket, PacketItem

ESTIMATION_METHOD = "chars-per-token"
ESTIMATION_VERSION = "cpt1"
DEFAULT_CHARS_PER_TOKEN = 3.0

SNIPPET_LADDER_CAP = 400
TRUNCATION_MARKER = "\n...[truncated by budget]"

# Fixed profiles: small = compact agent handoff, medium = normal coding
# task, large = architecture/debug session.
BUDGET_PROFILES = {"small": 2000, "medium": 8000, "large": 24000}

IMPORTANT_MEMORY_TYPES = frozenset(
    {"constraint", "decision", "architecture", "bug"}
)

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

STRUCTURAL_EVIDENCE_KINDS = frozenset(
    {
        "architecture_fact",
        "caller_relationship",
        "dependency_relationship",
        "bounded_path",
    }
)

# Git fact policy classes (design §3): repository state, HEAD facts, the
# focused file's change state, working-tree changes, commit lists and file
# history are IMPORTANT; co-change and diff facts are OPTIONAL. Unknown
# future kinds default to optional (shed first, safest).
IMPORTANT_GIT_FACT_KINDS = frozenset(
    {
        "repository_state",
        "head_facts",
        "current_change_state",
        "working_tree_change",
        "recent_commit",
        "file_history",
    }
)

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


def classify_memory_type(memory_type: Optional[str]) -> str:
    """Fixed section class: important baseline types, everything else
    (discovery, verification, task_result, unknown) is optional."""
    if memory_type in IMPORTANT_MEMORY_TYPES:
        return "important"
    return "optional"


def classify_git_fact(kind: Optional[str]) -> str:
    """Fixed git-fact class (see IMPORTANT_GIT_FACT_KINDS)."""
    if kind in IMPORTANT_GIT_FACT_KINDS:
        return "important"
    return "optional"


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
    diag["included_source_ids"] = [
        _source_id(section, item)
        for section in _ITEM_SECTIONS
        for item in getattr(working, section)
    ]
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
    return item.data.get("evidence_kind") in STRUCTURAL_EVIDENCE_KINDS


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
        _ladder(working, actions, fits, occ_map, relevance)
        if working.to_json() == snapshot:
            break  # ladder exhausted: budget is unsatisfiable

    satisfied = fits() and _hard_guarantee(working, budget)
    _budget_stats(packet, working, budget, actions, satisfied)
    if satisfied and not _hard_guarantee(working, budget):
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
    )
    result.report_id = _report_id(
        packet.packet_id,
        budget,
        decisions,
        working,
    )
    return result


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
            fact.data["snippet"] = snippet[:SNIPPET_LADDER_CAP] + TRUNCATION_MARKER
            fact.data["snippet_truncated"] = True
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
            actions[("snippet", sid, occurrence)] = (
                ACTION_REFERENCE_ONLY,
                REASON_SNIPPET_LADDER,
            )
    if relevance is None:
        _ladder_fixed_order(working, actions, fits, occ_map)
    else:
        _ladder_ranked_order(working, actions, fits, occ_map, relevance)


def _ladder_fixed_order(
    working: ContextPacket,
    actions: Dict[Tuple[str, str, int], Tuple[str, str]],
    fits,
    occ_map: Dict[int, int],
) -> None:
    """Steps 3-5 exactly as plain R1F: removal from the END of each list.
    Byte-identical to the pre-relevance accountant."""
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
    # Step 6: omit important items, from the end of each list first.
    for section in ("memories", "pending", "handoffs"):
        items = getattr(working, section)
        while items:
            if fits():
                return
            item = items.pop()
            sid = _source_id(section, item)
            actions[
                (_SECTION_KINDS[section], sid, occ_map[id(item)])
            ] = (ACTION_OMITTED, REASON_IMPORTANT_EXHAUSTED)
    while working.git_facts:
        if fits():
            return
        item = working.git_facts.pop()
        sid = _source_id("git_facts", item)
        actions[("git_fact", sid, occ_map[id(item)])] = (
            ACTION_OMITTED,
            REASON_IMPORTANT_EXHAUSTED,
        )
    while len(working.code_references) > 1:
        if fits():
            return
        item = working.code_references.pop()
        sid = _source_id("code_references", item)
        actions[
            ("code_reference", sid, occ_map[id(item)])
        ] = (ACTION_OMITTED, REASON_IMPORTANT_EXHAUSTED)


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
) -> None:
    """Steps 3-5 with R1G guidance: same ladder STRUCTURE, but removal
    inside each step is ascending relevance instead of from-end."""
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
    # Step 6: omit important items, lowest relevance first per list.
    for section in ("memories", "pending", "handoffs"):
        items = getattr(working, section)
        positions = _rank_positions(relevance, section)
        for item in _worst_first(list(items), section, positions, occ_map):
            if fits():
                return
            sid = _source_id(section, item)
            _remove_item(items, item)
            actions[
                (_SECTION_KINDS[section], sid, occ_map[id(item)])
            ] = (ACTION_OMITTED, REASON_IMPORTANT_EXHAUSTED)
    positions = _rank_positions(relevance, "git_facts")
    for item in _worst_first(
        list(working.git_facts),
        "git_facts",
        positions,
        occ_map,
        _git_fact_shed_rank,
    ):
        if fits():
            return
        sid = _source_id("git_facts", item)
        _remove_item(working.git_facts, item)
        actions[("git_fact", sid, occ_map[id(item)])] = (
            ACTION_OMITTED,
            REASON_IMPORTANT_EXHAUSTED,
        )
    positions = _rank_positions(relevance, "code_references")
    ref_extras = list(working.code_references[1:])
    for item in _worst_first(
        ref_extras, "code_references", positions, occ_map
    ):
        if fits():
            return
        if len(working.code_references) <= 1:
            return
        sid = _source_id("code_references", item)
        _remove_item(working.code_references, item)
        actions[
            ("code_reference", sid, occ_map[id(item)])
        ] = (ACTION_OMITTED, REASON_IMPORTANT_EXHAUSTED)


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
