"""Relinkra deterministic salience tiers and packet explainability (R6C).

R6C answers the dogfood question: when a budget is tight, WHERE does the
money go and WHAT disappears? Measured evidence showed packets spending
large shares of small budgets on metadata (per-item explain sidecars,
freshness notices, duplicated source-id lists) while the reduction ladder
shed items first and could drop the active handoff, relevant memories and
the focused code fact. This module makes salience explicit and
deterministic so the ladder can sacrifice verbose metadata BEFORE it
sacrifices high-value content.

Agent-visible tiers (deterministic, no embeddings, no LLM ranking):

- ``must_keep``: project identity / current revision / freshness (the
  essential frame), the ACTIVE/CURRENT handoff (the most recent active
  handoff memory), and the unresolved-work channel (``pending`` items).
  The ladder never omits these; only an unsatisfiable budget with
  ``minimum_useful_tokens`` guidance can leave them out.
- ``high_salience``: task-relevant decisions/constraints/architecture/bug
  memories, the focused code reference and the direct (non-structural)
  code fact, important git facts, and older-but-still-active handoffs.
- ``optional``: verbose provenance/metadata, distant history, discovery/
  verification/task_result memories, structural CBM facts, extra code
  facts, optional git facts (co-change, diffs).

Classification is a pure function of the packet: same packet + same
current-handoff determination always yields the same tiers. Code facts
are ORIENTATION EVIDENCE, never source authority: the sufficiency signal
keeps ``source_verification_required`` for implementation and security
whenever code evidence is present.

The packet-level ``packet_status`` block (built by :func:`build_status`)
is ADDITIVE metadata: completeness, omissions, deterministic recovery
hints that name only tools the MCP surface actually exposes, a
conservative sufficiency signal, salience counts, and cpt1 token
accounting. It never claims provider billing tokens and it never
repeats omitted payloads.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .context_packet import ContextPacket, PacketItem

SALIENCE_VERSION = "salience-v1"

MUST_KEEP = "must_keep"
HIGH_SALIENCE = "high_salience"
OPTIONAL = "optional"
SALIENCE_TIERS = (MUST_KEEP, HIGH_SALIENCE, OPTIONAL)

# Internal budget classes (moved here from R1F so salience and the
# ladder share one classification source; context_budget re-exports them).
IMPORTANT_MEMORY_TYPES = frozenset(
    {"constraint", "decision", "architecture", "bug"}
)

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

STRUCTURAL_EVIDENCE_KINDS = frozenset(
    {
        "architecture_fact",
        "caller_relationship",
        "dependency_relationship",
        "bounded_path",
    }
)

_ITEM_SECTIONS = ("memories", "code_references", "code_facts", "pending",
                  "handoffs", "git_facts")

# cpt1 defaults; the budget layer passes its own chars_per_token when one
# applies so accounting always matches the budget's estimator.
DEFAULT_CHARS_PER_TOKEN = 3.0
ESTIMATION_METHOD = "chars-per-token"
ESTIMATION_VERSION = "cpt1"
ACCOUNTING_BASIS = "serialized_compact_json"


def classify_memory_type(memory_type: Optional[str]) -> str:
    """Fixed budget class: important baseline types, everything else
    (discovery, verification, task_result, unknown) is optional."""
    if memory_type in IMPORTANT_MEMORY_TYPES:
        return "important"
    return "optional"


def classify_git_fact(kind: Optional[str]) -> str:
    """Fixed git-fact budget class (see IMPORTANT_GIT_FACT_KINDS)."""
    if kind in IMPORTANT_GIT_FACT_KINDS:
        return "important"
    return "optional"


def is_structural_code_fact(item: PacketItem) -> bool:
    """CBM structural facts are optional, never the protected code focus."""
    data = item.data if isinstance(item.data, dict) else {}
    return data.get("evidence_kind") in STRUCTURAL_EVIDENCE_KINDS


def current_handoff_memory_id(packet: ContextPacket) -> Optional[str]:
    """The CURRENT handoff: the most recent ACTIVE handoff memory.

    Deterministic maximum over ``(timestamp, memory_id)``; only handoff
    memories with ``status == "active"`` qualify. R1C visibility already
    hides superseded records, so the status check is a defensive
    re-statement of policy, not a second authority.
    """
    best: Optional[Tuple[str, str]] = None
    for item in packet.handoffs:
        data = item.data if isinstance(item.data, dict) else {}
        if data.get("memory_type") != "handoff":
            continue
        if str(data.get("status") or "active") != "active":
            continue
        key = (str(data.get("timestamp") or ""), str(data.get("memory_id") or ""))
        if best is None or key > best:
            best = key
    return best[1] if best else None


def classify_item(
    section: str,
    item: PacketItem,
    *,
    current_handoff_memory_id: Optional[str] = None,
    is_direct_code_fact: bool = False,
) -> str:
    """Agent-visible salience tier for one packet item.

    Pure function of section, item data, the current-handoff id and, for
    code facts, whether the item IS the direct focus (the first
    non-structural code fact in list order — the ladder protects exactly
    that one). Position-dependent classification is computed by
    :func:`classify_packet_items`; the flag keeps this function pure.
    """
    data = item.data if isinstance(item.data, dict) else {}
    if section == "pending":
        return MUST_KEEP
    if section == "handoffs":
        if (
            current_handoff_memory_id is not None
            and data.get("memory_id") == current_handoff_memory_id
        ):
            return MUST_KEEP
        return HIGH_SALIENCE
    if section == "memories":
        if classify_memory_type(data.get("memory_type")) == "important":
            return HIGH_SALIENCE
        return OPTIONAL
    if section == "code_references":
        return HIGH_SALIENCE
    if section == "code_facts":
        if is_structural_code_fact(item) or not is_direct_code_fact:
            return OPTIONAL
        return HIGH_SALIENCE
    if section == "git_facts":
        if classify_git_fact(data.get("kind")) == "important":
            return HIGH_SALIENCE
        return OPTIONAL
    return OPTIONAL


def classify_packet_items(
    packet: ContextPacket,
) -> List[Tuple[str, PacketItem, str]]:
    """Deterministic (section, item, tier) for every item in packet order.

    The direct code fact is the first non-structural code fact; the
    current handoff is the most recent active handoff memory. Same
    packet always yields the same tiers.
    """
    current = current_handoff_memory_id(packet)
    classified: List[Tuple[str, PacketItem, str]] = []
    seen_direct = False
    for section in _ITEM_SECTIONS:
        for item in getattr(packet, section):
            is_direct = False
            if section == "code_facts" and not is_structural_code_fact(item):
                is_direct = not seen_direct
                seen_direct = True
            classified.append((
                section,
                item,
                classify_item(
                    section,
                    item,
                    current_handoff_memory_id=current,
                    is_direct_code_fact=is_direct,
                ),
            ))
    return classified


def attach_salience(packet: ContextPacket) -> ContextPacket:
    """Attach per-item ``explain["salience"]`` tier labels in place.

    Only items that already carry an R4D ``explain`` sidecar are labeled:
    packets without explainability keep their exact historical wire form.
    Returns the same packet.
    """
    for section, item, tier in classify_packet_items(packet):
        if item.explain is not None:
            item.explain["salience"] = tier
    return packet


def salience_counts(packet: ContextPacket) -> Dict[str, int]:
    """Survivor counts per tier, in deterministic tier order."""
    counts = {tier: 0 for tier in SALIENCE_TIERS}
    for _section, _item, tier in classify_packet_items(packet):
        counts[tier] += 1
    return counts


# -- packet status -------------------------------------------------------------


def _compact_json(obj: Any) -> str:
    import json

    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def _useful_chars(packet: ContextPacket) -> int:
    """Chars of the USEFUL payload: item data plus the identity frame.

    Item ``data`` is what the agent consumes; the identity frame is the
    MUST_KEEP project/revision/task context. Everything else
    (provenance, explain sidecars, diagnostics, packet-level metadata) is
    metadata for the ``metadata_tokens`` column.
    """
    useful = 0
    for section in _ITEM_SECTIONS:
        for item in getattr(packet, section):
            useful += len(_compact_json(item.data))
    identity = {
        "packet_version": packet.packet_version,
        "packet_id": packet.packet_id,
        "mode": packet.mode,
        "project_id": packet.project_id,
        "workspace_id": packet.workspace_id,
        "repository_identity": packet.repository_identity,
        "task": packet.task,
        "focus": packet.focus,
        "project_facts": packet.project_facts,
    }
    return useful + len(_compact_json(identity))


def _duplicate_stats(packet: ContextPacket) -> Tuple[int, Optional[int]]:
    """R6B duplicate accounting from builder diagnostics.

    ``duplicate_memory_ids_skipped`` counts records suppressed at
    collection time (the builder's deterministic dedupe); the char basis
    is the suppressed copy's own envelope length, measured before the
    skip (method ``suppressed_copy_envelope_estimate``). Returns
    (count, estimated_chars_or_None).
    """
    diagnostics = packet.diagnostics if isinstance(packet.diagnostics, dict) else {}
    composition = diagnostics.get("composition")
    sources = (
        [diagnostics, composition]
        + ([diagnostics.get("budget")] if isinstance(
            diagnostics.get("budget"), dict) else [])
    )
    count: Optional[int] = None
    chars: Optional[int] = None
    for source in sources:
        if not isinstance(source, dict):
            continue
        if count is None and "duplicate_memory_ids_skipped" in source:
            count = int(source.get("duplicate_memory_ids_skipped") or 0)
        if chars is None and "duplicate_memory_chars_skipped" in source:
            chars = int(source.get("duplicate_memory_chars_skipped") or 0)
    if count is None:
        return 0, None
    return count, chars or 0


def _token_accounting(packet: ContextPacket, chars_per_token: float) -> dict:
    payload = packet.to_json()
    total_chars = len(payload)
    useful_chars = _useful_chars(packet)
    metadata_chars = max(0, total_chars - useful_chars)
    dup_count, dup_chars = _duplicate_stats(packet)
    accounting = {
        "estimation_method": ESTIMATION_METHOD,
        "estimation_version": ESTIMATION_VERSION,
        "accounting_basis": ACCOUNTING_BASIS,
        "chars_per_token": chars_per_token,
        "total_estimated_tokens": _tokens_for_chars(total_chars, chars_per_token),
        "useful_payload_tokens": _tokens_for_chars(useful_chars, chars_per_token),
        "metadata_tokens": _tokens_for_chars(metadata_chars, chars_per_token),
        "compression_ratio": (
            round(_tokens_for_chars(useful_chars, chars_per_token)
                  / _tokens_for_chars(total_chars, chars_per_token), 4)
            if total_chars else 0.0
        ),
        "duplicate_items_suppressed": dup_count,
    }
    if dup_chars is not None:
        accounting["duplicate_tokens_estimated"] = _tokens_for_chars(
            dup_chars, chars_per_token
        )
        accounting["duplicate_tokens_method"] = (
            "suppressed_copy_envelope_estimate"
        )
    else:
        accounting["duplicate_tokens_estimated"] = None
    return accounting


def _tokens_for_chars(chars: int, chars_per_token: float) -> int:
    return math.ceil(chars / chars_per_token) if chars > 0 else 0


def _guardrail_omissions(packet: ContextPacket) -> Dict[str, int]:
    """Composition-time (R1E guardrail) omissions by section key."""
    diagnostics = packet.diagnostics if isinstance(packet.diagnostics, dict) else {}
    composition = diagnostics.get("composition")
    source = composition if isinstance(composition, dict) else diagnostics
    omitted = source.get("omitted")
    if not isinstance(omitted, dict):
        return {}
    return {
        str(key): int(value or 0)
        for key, value in omitted.items()
        if int(value or 0) > 0
    }


def _sufficiency(packet: ContextPacket, *, has_omissions: bool) -> dict:
    """Conservative sufficiency signal. Relinkra provides ORIENTATION,
    not final proof: implementation and security stay
    ``source_verification_required`` whenever code evidence is present,
    and ``implementation`` is never ``sufficient`` from memory alone."""
    total_items = sum(len(getattr(packet, section)) for section in _ITEM_SECTIONS)
    identity_ok = bool(packet.project_id) and bool(packet.project_facts)
    has_code = bool(packet.code_references or packet.code_facts)
    if not identity_ok or total_items == 0:
        orientation = "insufficient"
    elif has_omissions:
        orientation = "partial"
    else:
        orientation = "sufficient"
    if has_code:
        implementation = "source_verification_required"
        security = "source_verification_required"
    else:
        implementation = "partial"
        security = "not_applicable"
    return {
        "orientation": orientation,
        "implementation": implementation,
        "security_verdict": security,
    }


_RECOVERY_TOOL_BY_SECTION = (
    ("handoffs", "handoff_get(project_id='{project_id}')"),
    ("memories", "memory_search(project_id='{project_id}')"),
    ("pending", "memory_search(project_id='{project_id}', memory_type='pending')"),
    ("code_facts", "code_architecture(project_id='{project_id}')"),
    ("code_references", "code_architecture(project_id='{project_id}')"),
    ("git_facts", "git_context(project_id='{project_id}')"),
)


def _recommended_next(
    packet: ContextPacket, omitted_sections: List[str]
) -> List[str]:
    """Deterministic recovery hints naming only tools this surface has.

    No filler: a section appears here only when something from it was
    omitted, and the mapping names the exact MCP tool that retrieves
    more of that kind of evidence.
    """
    hints: List[str] = []
    for section, template in _RECOVERY_TOOL_BY_SECTION:
        if section in omitted_sections:
            hint = template.format(project_id=packet.project_id)
            if hint not in hints:
                hints.append(hint)
        if len(hints) >= 4:
            break
    return hints


def _truncation_recovery_hint(packet: ContextPacket) -> Optional[str]:
    """Continuation hint for a truncation-only budget reduction.

    A budget-driven snippet truncation or reference-only reduction means
    the shipped code fact lost its payload; the exact recovery path is
    resolving the fact's own file. Emits nothing when no qualifying code
    fact ships (no invented ids, no memory/handoff guesses).
    """
    for item in packet.code_facts:
        data = item.data if isinstance(item.data, dict) else {}
        if is_structural_code_fact(item):
            continue
        file_path = data.get("file_path")
        if isinstance(file_path, str) and file_path:
            return "code_resolve(project_id='%s', file='%s')" % (
                packet.project_id,
                file_path,
            )
    return None


def _omission_sections(
    *, budget_omitted: List[str], guardrail: Dict[str, int]
) -> List[str]:
    sections = set(budget_omitted)
    mapping = {
        "memories": "memories",
        "pending": "pending",
        "handoffs": "handoffs",
        "code_refs": "code_references",
        "code_facts": "code_facts",
        "git_facts": "git_facts",
        "warnings": "warnings",
    }
    for key, value in guardrail.items():
        if value and mapping.get(key):
            sections.add(mapping[key])
    return sorted(sections)


def build_status(
    packet: ContextPacket,
    *,
    original_packet: Optional[ContextPacket] = None,
    budget_omitted_items: Optional[List[Tuple[str, PacketItem]]] = None,
    budget_truncated: bool = False,
    chars_per_token: float = DEFAULT_CHARS_PER_TOKEN,
) -> dict:
    """Deterministic agent-visible packet status block.

    ``packet`` is the packet the block will ship with (its survivor
    counts, guardrail omissions, sufficiency and token accounting are
    measured on it). ``original_packet`` is the pre-budget packet used
    to attribute salience tiers to OMITTED items (position-aware
    classification needs the original list order); ``None`` means no
    budget was applied. ``budget_omitted_items`` carries the
    (section, original_item) pairs the budget ladder omitted.

    Per-type omission detail (``omitted_item_types``) deliberately lives
    in the budget REPORT, not in this block: the block is part of the
    budgeted bytes, and its maximum footprint must stay bounded and
    predictable.
    """
    omitted_pairs = list(budget_omitted_items or ())
    guardrail = _guardrail_omissions(packet)
    budget_omitted_sections = sorted({section for section, _ in omitted_pairs})
    omitted_sections = _omission_sections(
        budget_omitted=budget_omitted_sections, guardrail=guardrail
    )
    has_omissions = bool(omitted_sections) or budget_truncated

    status: Dict[str, Any] = {
        "version": SALIENCE_VERSION,
        "packet_complete": not has_omissions,
        "budget_exhausted": bool(omitted_pairs) or budget_truncated,
        "omitted_sections": omitted_sections,
    }

    if omitted_pairs:
        high_salience = 0
        # Tiers are computed on the ORIGINAL packet (position-aware); the
        # omitted pairs reference those exact items.
        tiers = {
            id(item): tier
            for _s, item, tier in classify_packet_items(
                original_packet if original_packet is not None else packet
            )
        }
        for _section, item in omitted_pairs:
            if tiers.get(id(item), OPTIONAL) in (MUST_KEEP, HIGH_SALIENCE):
                high_salience += 1
        status["omitted_high_salience_count"] = high_salience
    else:
        # Guardrail omissions are counted by section only; per-item
        # attribution is unavailable, so the count stays honestly null.
        status["omitted_high_salience_count"] = (
            None if guardrail else 0
        )

    if omitted_sections:
        status["recommended_next"] = _recommended_next(packet, omitted_sections)
    elif budget_truncated:
        # R6C-FIX: a truncation-only budget run omits nothing but still
        # loses (or compresses) a code-fact snippet. The honest recovery
        # path is the code fact's own continuation: code_resolve on the
        # fact's file (a real MCP tool; the fact keeps its file_path and
        # code_reference_id). Never filler, never invented ids.
        hint = _truncation_recovery_hint(packet)
        if hint:
            status["recommended_next"] = [hint]

    status["context_sufficiency"] = _sufficiency(
        packet, has_omissions=has_omissions
    )
    status["salience"] = salience_counts(packet)
    status["token_accounting"] = _token_accounting(packet, chars_per_token)
    return status


def build_status_skeleton(
    packet: ContextPacket, chars_per_token: float = DEFAULT_CHARS_PER_TOKEN
) -> dict:
    """Worst-case-footprint status block for pre-ladder attachment.

    The budget ladder must measure the mandated metadata BEFORE shedding
    content, so apply_budget attaches this skeleton first: same key set
    as any final block, with the maximum deterministic values (every
    section listed as omitted, all four recovery hints). After the
    ladder, the block is rebuilt with true values; the true block can
    only shrink or stay equal in footprint.
    """
    skeleton = build_status(packet, chars_per_token=chars_per_token)
    skeleton["omitted_sections"] = sorted(_ITEM_SECTIONS)
    skeleton["omitted_high_salience_count"] = (
        skeleton.get("omitted_high_salience_count") or 0
    )
    skeleton["recommended_next"] = _recommended_next(
        packet, sorted(_ITEM_SECTIONS)
    )
    return skeleton


def status_omitted_item_types(
    original_packet: ContextPacket,
    budget_omitted_items: List[Tuple[str, PacketItem]],
) -> dict:
    """Per-type omission counts for the budget report (bounded, sorted)."""
    omitted_types: Dict[str, int] = {}
    for section, item in budget_omitted_items:
        data = item.data if isinstance(item.data, dict) else {}
        if section == "memories":
            type_key = str(data.get("memory_type") or "unknown")
        elif section == "code_facts":
            type_key = (
                "structural_code_fact"
                if is_structural_code_fact(item)
                else "code_fact"
            )
        else:
            type_key = section
        omitted_types[type_key] = omitted_types.get(type_key, 0) + 1
    return dict(sorted(omitted_types.items())[:16])


def shrink_status(status: dict) -> Optional[dict]:
    """Next-smaller deterministic form of a packet_status block.

    Returns the shrunk dict, or ``None`` when nothing remains. Order is
    fixed so the same block always shrinks the same way: token
    accounting first, then recovery hints, then type detail, then
    counts, then sufficiency.
    """
    shrunk = dict(status)
    for key in (
        "token_accounting",
        "recommended_next",
        "omitted_item_types",
        "salience",
        "context_sufficiency",
        "omitted_high_salience_count",
    ):
        if key in shrunk:
            del shrunk[key]
            return shrunk
    return None
