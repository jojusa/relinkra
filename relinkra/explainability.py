"""Machine-first R4D explainability sidecars for context and tool results."""

from __future__ import annotations

import json
import math
from typing import Any, Iterable, Mapping, Optional

from .contradictions import EvidenceFact, detect_contradictions
from .freshness import (
    FRESHNESS_VERSION,
    FreshnessContext,
    RelationResolver,
    evaluate_freshness,
    normalize_git_revision,
)


EXPLAINABILITY_VERSION = "explain-v1"

_SECTIONS = (
    "memories",
    "code_references",
    "code_facts",
    "pending",
    "handoffs",
    "git_facts",
)


def _json_mapping(value: Any) -> dict:
    if isinstance(value, Mapping):
        return dict(value)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        try:
            rendered = to_dict()
        except Exception:
            return {}
        return dict(rendered) if isinstance(rendered, Mapping) else {}
    if not isinstance(value, str) or not value.lstrip().startswith("{"):
        return {}
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return {}
    return dict(parsed) if isinstance(parsed, Mapping) else {}


def _native_cbm_fields(data: Mapping[str, Any]) -> tuple[dict, list[Any]]:
    """Return only CBM-owned revision/trust evidence.

    These names mirror the adapters accepted by :mod:`freshness`; the
    extraction is deliberately targeted rather than a recursive flattening of
    arbitrary payloads.  A nested handoff status must never become a CBM graph
    status merely because both happen to be named ``status``.
    """
    index = {}
    for key in ("index_status", "cbm_index_status", "native_index_status"):
        if key in data:
            index = _json_mapping(data.get(key))
            break
    stages: list[Any] = []
    for key in ("trust_stages", "cbm_trust_stages", "native_trust_stages"):
        if key in data and isinstance(data.get(key), (list, tuple)):
            stages = list(data[key])
            break
    return index, stages


def _cbm_graph_revision(data: Mapping[str, Any]) -> Optional[str]:
    index, _stages = _native_cbm_fields(data)
    git = _json_mapping(index.get("git"))
    value = (
        git.get("head_sha")
        or index.get("head_sha")
        or index.get("revision")
    )
    return normalize_git_revision(value)


def source_id(section: str, item: Any) -> str:
    provenance = item.provenance
    if section in {"code_references", "code_facts"}:
        return str(
            provenance.code_reference_id
            or item.data.get("code_reference_id")
            or ""
        )
    if section == "git_facts":
        return str(
            provenance.code_reference_id
            or item.data.get("kind")
            or "git_fact"
        )
    return str(provenance.memory_id or item.data.get("memory_id") or "")


def evidence_ref(section: str, item: Any, occurrence: int) -> str:
    identifier = source_id(section, item) or "anonymous"
    return f"{section}:{identifier}:{occurrence}"


def _source_revision(section: str, item: Any) -> Optional[str]:
    data = item.data
    if section == "git_facts":
        value = data.get("head_sha") or data.get("sha")
        return normalize_git_revision(value)
    # The native graph binding is CBM's authority.  It must not be flattened
    # into or overwritten by a copied result-level revision.
    native_cbm_revision = (
        _cbm_graph_revision(data)
        if section in {"code_references", "code_facts"}
        or item.provenance.source == "cbm"
        else None
    )
    if (
        section in {"code_references", "code_facts"}
        or item.provenance.source == "cbm"
    ):
        # A copied result-level revision is not a graph attestation.  CBM
        # evidence is revision-bound only when its native index says so.
        return native_cbm_revision
    value = (
        data.get("source_revision")
        or data.get("commit_sha")
        or data.get("revision")
        or data.get("head_sha")
    )
    if value:
        return normalize_git_revision(value)
    if section in {"handoffs", "pending", "memories"}:
        body = _json_mapping(data.get("body"))
        git_state = body.get("git_state")
        if isinstance(git_state, Mapping) and git_state.get("head_sha"):
            return normalize_git_revision(git_state["head_sha"])
    reference = data.get("reference")
    if isinstance(reference, Mapping):
        value = (
            reference.get("source_revision")
            or reference.get("commit_sha")
            or reference.get("revision")
        )
        if value:
            return normalize_git_revision(value)
    return None


def _evidence_type(section: str, item: Any) -> str:
    if section == "git_facts":
        return "git"
    if section in {"code_references", "code_facts"}:
        index, stages = _native_cbm_fields(item.data)
        return "cbm" if index or stages else "code"
    if section == "handoffs" or item.data.get("memory_type") == "handoff":
        return "handoff"
    return "memory"


def _freshness_input(section: str, item: Any) -> dict:
    data = item.data
    evidence = {
        "observed_at": data.get("timestamp") or data.get("created_at"),
        "source_revision": _source_revision(section, item),
        "project_id": data.get("project_id"),
    }
    # Pass through native CBM authority without copying the surrounding result
    # body.  Freshness knows how to validate these exact narrow structures.
    if section in {"code_references", "code_facts"} or item.provenance.source == "cbm":
        for key in (
            "index_status",
            "cbm_index_status",
            "native_index_status",
            "trust_stages",
            "cbm_trust_stages",
            "native_trust_stages",
        ):
            if key in data:
                evidence[key] = data[key]
    return evidence


def _current_context(packet: Any, as_of: str) -> FreshnessContext:
    current_revision = None
    dirty = None
    for item in packet.git_facts:
        if item.data.get("kind") == "repository_state":
            current_revision = (
                normalize_git_revision(item.data.get("head_sha"))
                or current_revision
            )
            clean = item.data.get("clean")
            dirty = None if clean is None else not bool(clean)
        elif item.data.get("kind") == "head_facts":
            current_revision = (
                normalize_git_revision(item.data.get("head_sha"))
                or current_revision
            )
    return FreshnessContext(
        as_of=as_of,
        project_id=packet.project_id,
        current_revision=current_revision,
        dirty=dirty,
    )


def _authority_domain(section: str, item: Any) -> str:
    if section == "git_facts":
        return "git_code"
    if section in {"code_references", "code_facts"}:
        return "cbm_code"
    if section == "handoffs" or item.data.get("memory_type") == "handoff":
        return "handoff"
    return "engram_memory"


def _compact_freshness(freshness: Any) -> dict:
    """Serialize freshness once, without repeated prose or null fields."""
    rendered = freshness.to_dict()
    # ``explanation`` repeats reason_code prose across every selected item;
    # packet-level notices retain the actionable operator message instead.
    rendered.pop("explanation", None)
    rendered.pop("trust_limitations", None)
    return {key: value for key, value in rendered.items() if value is not None}


def _compact_contradiction(contradiction: Any) -> dict:
    """Packet-safe contradiction metadata; never retain raw fact values."""
    rendered = contradiction.to_dict()
    # Values may be arbitrary structured evidence and can be as large or as
    # sensitive as an omitted body.  Refs + subject/key/source explain the
    # conflict without smuggling the removed payload back into the packet.
    rendered.pop("values", None)
    rendered.pop("explanation", None)
    rendered.pop("newer_value", None)
    return rendered


def _fact(
    facts: list[EvidenceFact],
    *,
    ref: str,
    domain: str,
    source: str,
    subject: str,
    key: str,
    value: Any,
    observed_at: Optional[str],
    revision: Optional[str] = None,
) -> None:
    if value is None:
        return
    facts.append(
        EvidenceFact(
            ref,
            domain,
            source,
            subject,
            key,
            value,
            observed_at=observed_at,
            revision=revision,
        )
    )


def _structured_facts(
    packet: Any, refs: Mapping[int, str], context: FreshnessContext
) -> list[EvidenceFact]:
    facts: list[EvidenceFact] = []
    if packet.project_id:
        facts.append(
            EvidenceFact(
                evidence_id="packet:project_identity",
                authority_domain="registry_identity",
                source_system="registry",
                subject="logical_project",
                key="project_id",
                value=packet.project_id,
            )
        )
    if context.current_revision:
        facts.append(
            EvidenceFact(
                evidence_id="packet:current_revision",
                authority_domain="git_code",
                source_system="git",
                subject="repository",
                key="revision",
                value=context.current_revision,
                revision=context.current_revision,
            )
        )
    for section in _SECTIONS:
        for item in getattr(packet, section):
            ref = refs[id(item)]
            data = item.data
            domain = _authority_domain(section, item)
            source = item.provenance.source
            observed_at = data.get("timestamp") or data.get("created_at")
            handoff = (
                _json_mapping(data.get("body"))
                if section == "handoffs" or data.get("memory_type") == "handoff"
                else {}
            )
            handoff_id = handoff.get("handoff_id") or data.get("handoff_id")
            subject = (
                handoff_id
                or item.provenance.topic_key
                or item.provenance.code_reference_id
                or data.get("topic_key")
                or data.get("memory_id")
                or ("repository" if section == "git_facts" else ref)
            )
            project_value = (
                handoff.get("project_id")
                if "project_id" in handoff
                else data.get("project_id")
            )
            if "project_id" in data or "project_id" in handoff:
                _fact(
                    facts,
                    ref=ref,
                    domain=domain,
                    source=source,
                    subject="logical_project",
                    key="project_id",
                    value=project_value,
                    observed_at=observed_at,
                )
            # Missing workspace is not a value. Explicit null remains distinct
            # from a missing key but does not conflict with absence.
            workspace_present = "workspace_id" in handoff or "workspace_id" in data
            workspace_value = (
                handoff.get("workspace_id")
                if "workspace_id" in handoff
                else data.get("workspace_id")
            )
            if workspace_present and workspace_value is not None:
                _fact(
                    facts,
                    ref=ref,
                    domain=domain,
                    source=source,
                    subject=str(subject),
                    key="workspace_id",
                    value=workspace_value,
                    observed_at=observed_at,
                )
            for key in ("status", "state", "resolution_state"):
                if key in data and data.get(key) is not None:
                    _fact(
                        facts,
                        ref=ref,
                        domain=domain,
                        source=source,
                        subject=str(subject),
                        key=key,
                        value=data.get(key),
                        observed_at=observed_at,
                    )
            # Handoff lifecycle/identity is nested in the serialized body.
            # Extract only the schema-owned fields and retain the handoff
            # authority domain instead of recursively merging arbitrary JSON.
            for key in ("status", "state", "resolution_state"):
                if key in handoff and handoff.get(key) is not None:
                    _fact(
                        facts,
                        ref=ref,
                        domain="handoff",
                        source=source,
                        subject=str(subject),
                        key=key,
                        value=handoff.get(key),
                        observed_at=observed_at,
                    )
            revision = _source_revision(section, item)
            if revision:
                _fact(
                    facts,
                    ref=ref,
                    domain=domain,
                    source=source,
                    subject="repository",
                    key="revision",
                    value=revision,
                    observed_at=observed_at,
                    revision=revision,
                )
            _index, trust_stages = (
                _native_cbm_fields(data) if domain == "cbm_code" else ({}, [])
            )
            for raw_stage in trust_stages:
                stage = _json_mapping(raw_stage)
                name = str(stage.get("name") or "").strip()
                status = stage.get("status")
                if name and status is not None:
                    _fact(
                        facts,
                        ref=ref,
                        domain="cbm_code",
                        source="cbm",
                        subject=f"cbm_trust:{name.lower()}",
                        key="status",
                        value=status,
                        observed_at=observed_at,
                        revision=revision,
                    )
            if "key" in data and "value" in data:
                _fact(
                    facts,
                    ref=ref,
                    domain=domain,
                    source=source,
                    subject=str(subject),
                    key=str(data["key"]),
                    value=data["value"],
                    observed_at=observed_at,
                    revision=revision,
                )
    return facts


def annotate_packet(
    packet: Any,
    *,
    as_of: Optional[str] = None,
    relation_resolver: Optional[RelationResolver] = None,
) -> Any:
    """Attach additive R4D sidecars and return the same packet.

    The caller supplies ``as_of`` (normally the packet's injected-clock
    ``created_at``), so repeated builds never depend on an implicit wall clock.
    """
    resolved_as_of = as_of or packet.created_at
    context = _current_context(packet, resolved_as_of)
    refs: dict[int, str] = {}
    notices: list[dict] = []
    for section in _SECTIONS:
        counters: dict[str, int] = {}
        for item in getattr(packet, section):
            sid = source_id(section, item)
            occurrence = counters.get(sid, 0)
            counters[sid] = occurrence + 1
            ref = evidence_ref(section, item, occurrence)
            refs[id(item)] = ref
            freshness = evaluate_freshness(
                _evidence_type(section, item),
                _freshness_input(section, item),
                context,
                relation_resolver=relation_resolver,
            )
            compact_freshness = _compact_freshness(freshness)
            action = compact_freshness.pop("recommended_action", None)
            compact_freshness.pop("current_revision", None)
            limitations = list(freshness.trust_limitations)
            item.explain = {
                "selection": {
                    "reason_ref": "provenance.why_included",
                    "relevance": None,
                },
                "freshness": compact_freshness,
                "budget": {
                    "treatment": "full",
                    "reason": "selected_before_budget",
                },
                "provenance": {
                    "evidence_ref": ref,
                },
                "contradictions": [],
                "trust": {
                    "advisory_only": True,
                },
            }
            if (
                freshness.state.value in {"aging", "stale", "unknown"}
                or limitations
                or action
            ):
                notices.append(
                    {
                        "evidence_ref": ref,
                        "state": freshness.state.value,
                        "reason_code": freshness.reason_code,
                        "limitations": limitations,
                        "recommended_action": action,
                    }
                )

    contradictions = detect_contradictions(_structured_facts(packet, refs, context))
    packet.contradictions = [_compact_contradiction(item) for item in contradictions]
    by_ref: dict[str, list[str]] = {}
    for contradiction in contradictions:
        for ref in contradiction.evidence_refs:
            by_ref.setdefault(ref, []).append(contradiction.contradiction_id)
    for section in _SECTIONS:
        for item in getattr(packet, section):
            ref = refs[id(item)]
            item.explain["contradictions"] = sorted(by_ref.get(ref, []))
    packet.explainability = {
        "version": EXPLAINABILITY_VERSION,
        "freshness_version": FRESHNESS_VERSION,
        "as_of": resolved_as_of,
        "advisory_only": True,
        "current_revision": context.current_revision,
        "dirty_worktree": context.dirty,
        "contradiction_count": len(contradictions),
        "authority_policy": "domain_scoped_no_global_winner",
    }
    if notices:
        # Packet-level notices survive whole-item omission.  They contain only
        # refs, typed states and actions -- never the source body's text.
        packet.explainability["notices"] = notices
    return packet


def attach_relevance(packet: Any, ranked: Any) -> Any:
    """Join existing deterministic relevance signals into item sidecars."""
    if ranked is None:
        return packet
    for section in _SECTIONS:
        counters: dict[str, int] = {}
        for item in getattr(packet, section):
            sid = source_id(section, item)
            occurrence = counters.get(sid, 0)
            counters[sid] = occurrence + 1
            score = ranked.score_for(section, sid, occurrence)
            if item.explain is not None:
                item.explain["selection"]["relevance"] = (
                    score.to_dict() if score is not None else None
                )
    return packet


def attach_budget(packet: Any, decisions: Iterable[Any]) -> Any:
    """Join budget treatment and re-account the exact serialized packet.

    R1F leaves reserve for metadata, but the guarantee is checked again here
    because explainability is attached *after* the ladder.  The method keeps
    the historical two-argument API and obtains the authoritative cap from
    ``diagnostics.budget``.
    """
    decision_map: dict[tuple[str, str, int], Any] = {}
    snippet_map: dict[tuple[str, str, int], Any] = {}
    counters: dict[tuple[str, str], int] = {}
    omitted: list[dict] = []
    for decision in decisions or ():
        key = (decision.section, decision.source_id)
        occurrence = counters.get(key, 0)
        counters[key] = occurrence + 1
        if decision.section == "code_facts" and decision.source_id.startswith(
            "snippet:"
        ):
            parent_id = decision.source_id[len("snippet:") :]
            snippet_map[(decision.section, parent_id, occurrence)] = decision
        else:
            decision_map[
                (decision.section, decision.source_id, occurrence)
            ] = decision
        if decision.action == "omitted" and not decision.source_id.startswith(
            "snippet:"
        ):
            omitted.append(
                {
                    "section": decision.section,
                    "source_id": decision.source_id,
                    "occurrence_index": occurrence,
                    "evidence_ref": (
                        f"{decision.section}:"
                        f"{decision.source_id or 'anonymous'}:{occurrence}"
                    ),
                    "treatment": decision.action,
                    "reason": decision.reason,
                }
            )
    for section in _SECTIONS:
        section_counters: dict[str, int] = {}
        for item in getattr(packet, section):
            sid = source_id(section, item)
            occurrence = section_counters.get(sid, 0)
            section_counters[sid] = occurrence + 1
            decision = decision_map.get((section, sid, occurrence))
            snippet_decision = snippet_map.get((section, sid, occurrence))
            # A reduced snippet is the user-visible treatment of its surviving
            # code fact; the whole-item INCLUDED row must not hide it.
            if snippet_decision is not None and snippet_decision.action in {
                "truncated",
                "reference_only",
            }:
                decision = snippet_decision
            if decision is not None and item.explain is not None:
                item.explain["budget"] = {
                    "treatment": decision.action,
                    "reason": decision.reason,
                }
    if packet.explainability:
        packet.explainability["budget"] = {
            "omitted": omitted,
            "metadata_accounted": False,
            "contradictions_single_copy": True,
        }
    else:
        # Legacy/non-explain requests carry no R4D sidecar.  Preserve their
        # exact wire form and the R1F accounting already performed.
        return packet
    _compact_packet_metadata(packet)
    budget = _budget_diagnostics(packet)
    if budget is None:
        # There is no cap to verify.  Reporting "accounted" here would be a
        # false assurance even though the metadata itself remains useful.
        return packet

    payload = _settle_budget_measurement(packet, budget)
    if not _within_budget(payload, budget):
        _shrink_explainability(packet)
        payload = _settle_budget_measurement(packet, budget)
    if not _within_budget(payload, budget):
        _minimize_explainability(packet)
        payload = _settle_budget_measurement(packet, budget)
    if _within_budget(payload, budget):
        packet.explainability["budget"]["metadata_accounted"] = True
        payload = _settle_budget_measurement(packet, budget)
        # ``true`` is shorter than ``false``, nevertheless verify the final
        # bytes rather than relying on that incidental JSON detail.
        if not _within_budget(payload, budget):
            packet.explainability["budget"]["metadata_accounted"] = False
            _settle_budget_measurement(packet, budget)
    else:
        # A caller supplying hand-built, internally inconsistent diagnostics
        # must not inherit R1F's earlier satisfied flag.
        packet.diagnostics["budget"]["satisfied"] = False
        _settle_budget_measurement(packet, budget)
    return packet


def _budget_diagnostics(packet: Any) -> Optional[dict]:
    diagnostics = getattr(packet, "diagnostics", None)
    if not isinstance(diagnostics, Mapping):
        return None
    budget = diagnostics.get("budget")
    if not isinstance(budget, Mapping):
        return None
    max_tokens = budget.get("max_estimated_tokens")
    chars_per_token = budget.get("chars_per_token")
    if not isinstance(max_tokens, int) or isinstance(max_tokens, bool):
        return None
    if not isinstance(chars_per_token, (int, float)) or chars_per_token <= 0:
        return None
    return budget


def _settle_budget_measurement(packet: Any, budget: Mapping[str, Any]) -> str:
    """Update R1F's self-referential totals to the post-attach fixed point."""
    mutable = packet.diagnostics["budget"]
    mutable.setdefault("final_total_chars", 0)
    mutable.setdefault("final_estimated_tokens", 0)
    payload = ""
    for _ in range(8):
        payload = packet.to_json()
        chars = len(payload)
        tokens = math.ceil(chars / float(budget["chars_per_token"])) if chars else 0
        current = (
            mutable.get("final_total_chars"),
            mutable.get("final_estimated_tokens"),
        )
        if current == (chars, tokens):
            return payload
        mutable["final_total_chars"] = chars
        mutable["final_estimated_tokens"] = tokens
    return packet.to_json()


def _within_budget(payload: str, budget: Mapping[str, Any]) -> bool:
    chars = len(payload)
    tokens = (
        math.ceil(chars / float(budget["chars_per_token"])) if chars else 0
    )
    max_characters = budget.get("max_characters")
    return tokens <= int(budget["max_estimated_tokens"]) and (
        max_characters is None or chars <= int(max_characters)
    )


def _compact_packet_metadata(packet: Any) -> None:
    """Normalize legacy/round-tripped R4D metadata to the compact form."""
    for contradiction in packet.contradictions:
        contradiction.pop("values", None)
        contradiction.pop("explanation", None)
        contradiction.pop("newer_value", None)
    for section in _SECTIONS:
        for item in getattr(packet, section):
            explain = item.explain or {}
            freshness = explain.get("freshness")
            if isinstance(freshness, dict):
                freshness.pop("explanation", None)
                limitations = freshness.pop("trust_limitations", None)
                if limitations:
                    explain.setdefault("trust", {}).setdefault(
                        "limitations", list(limitations)
                    )
                for key in tuple(freshness):
                    if freshness[key] is None:
                        freshness.pop(key)


def _shrink_explainability(packet: Any) -> None:
    """Deterministically spend less metadata while retaining warnings/refs."""
    for section in _SECTIONS:
        for item in getattr(packet, section):
            explain = item.explain or {}
            selection = explain.get("selection")
            if isinstance(selection, dict):
                relevance = selection.get("relevance")
                if isinstance(relevance, Mapping) and "total" in relevance:
                    selection["relevance"] = {"total": relevance["total"]}
                # why_included already exists in immutable provenance.
                selection.pop("reasons", None)
            provenance = explain.get("provenance")
            if isinstance(provenance, dict):
                # source is already present in PacketItem.provenance; the ref
                # remains because warnings and contradictions point to it.
                provenance.pop("source", None)
            trust = explain.get("trust")
            if isinstance(trust, dict):
                # Limitations/actions are retained in packet-level notices,
                # which survive OMITTED.  advisory_only is packet-level too.
                trust.clear()
                if not trust:
                    explain.pop("trust", None)

    # If many omitted rows share a reason, keep the required ref/treatment and
    # reason, but discard lookup fields derivable from the evidence ref.
    packet_budget = packet.explainability.get("budget") or {}
    for omitted in packet_budget.get("omitted") or []:
        omitted.pop("section", None)
        omitted.pop("source_id", None)
        omitted.pop("occurrence_index", None)


def _minimize_explainability(packet: Any) -> None:
    """Last compact form: keep typed warnings, actions and evidence links."""
    for section in _SECTIONS:
        for item in getattr(packet, section):
            explain = item.explain or {}
            freshness = explain.get("freshness") or {}
            budget = explain.get("budget") or {}
            provenance = explain.get("provenance") or {}
            minimal = {
                "freshness": {
                    key: freshness[key]
                    for key in ("state", "reason_code")
                    if key in freshness
                },
                "budget": {
                    "treatment": budget.get("treatment", "included")
                },
                "provenance": {
                    "evidence_ref": provenance.get("evidence_ref")
                },
                "contradictions": list(explain.get("contradictions") or []),
            }
            item.explain = minimal

    for key in (
        "freshness_version",
        "as_of",
        "current_revision",
        "dirty_worktree",
        "contradiction_count",
    ):
        packet.explainability.pop(key, None)
    for contradiction in packet.contradictions:
        for key in ("observed_revisions", "observed_at", "newer_evidence_ref"):
            contradiction.pop(key, None)
    for omitted in (packet.explainability.get("budget") or {}).get("omitted") or []:
        omitted.pop("reason", None)


def explain_record(
    evidence_type: str,
    record: Mapping[str, Any],
    *,
    context: FreshnessContext,
    relation_resolver: Optional[RelationResolver] = None,
) -> dict:
    """Compact freshness/trust sidecar for non-packet MCP results."""
    freshness = evaluate_freshness(
        evidence_type,
        record,
        context,
        relation_resolver=relation_resolver,
    )
    return {
        "version": EXPLAINABILITY_VERSION,
        "freshness": _compact_freshness(freshness),
        "trust": {
            "limitations": list(freshness.trust_limitations),
            "advisory_only": True,
        },
    }


def human_summary(packet: Any) -> str:
    """Concise operator view: selection, freshness, conflicts, next checks."""
    lines = ["# RELINKRA CONTEXT EXPLANATION", ""]
    total = sum(len(getattr(packet, section)) for section in _SECTIONS)
    lines.append(f"- selected items: {total}")
    states: dict[str, int] = {}
    actions: set[str] = set()
    for section in _SECTIONS:
        for item in getattr(packet, section):
            freshness = (item.explain or {}).get("freshness") or {}
            state = freshness.get("state", "unknown")
            states[state] = states.get(state, 0) + 1
            if freshness.get("recommended_action"):
                actions.add(str(freshness["recommended_action"]))
    notices = list((packet.explainability or {}).get("notices") or [])
    for notice in notices:
        if notice.get("recommended_action"):
            actions.add(str(notice["recommended_action"]))
    for contradiction in packet.contradictions:
        if contradiction.get("recommended_action"):
            actions.add(str(contradiction["recommended_action"]))
    lines.append(
        "- freshness: "
        + (", ".join(f"{key}={states[key]}" for key in sorted(states)) or "none")
    )
    lines.append(f"- contradictions: {len(packet.contradictions)}")
    lines.append("- advisory only: yes; agents may inspect, search, and verify freely")
    lines.extend(["", "## Why selected", ""])
    for section in _SECTIONS:
        for item in getattr(packet, section):
            selection = (item.explain or {}).get("selection") or {}
            reasons = selection.get("reasons") or [
                item.provenance.why_included or "selected by context policy"
            ]
            lines.append(f"- {source_id(section, item) or section}: {reasons[0]}")
    lines.extend(["", "## Freshness warnings", ""])
    if notices:
        for notice in notices:
            ref = notice.get("evidence_ref") or "unknown evidence"
            state = notice.get("state") or "unknown"
            reason = notice.get("reason_code") or "freshness warning"
            action = notice.get("recommended_action") or (
                "Inspect the referenced source before relying on it."
            )
            lines.append(
                f"- {ref} is {state} ({reason}). Recommended action: {action}"
            )
    else:
        lines.append("- No freshness-specific warning was reported.")
    lines.extend(["", "## Conflicts", ""])
    if packet.contradictions:
        for contradiction in packet.contradictions:
            subject = contradiction.get("subject") or "unknown subject"
            key = contradiction.get("key") or "unknown fact"
            sources = ", ".join(contradiction.get("source_systems") or [])
            refs = ", ".join(contradiction.get("evidence_refs") or [])
            action = contradiction.get("recommended_action") or (
                "Inspect the referenced sources and resolve the conflict."
            )
            lines.append(
                f"- {subject}.{key} conflicts across sources "
                f"{sources or 'unknown'} (evidence: {refs or 'unavailable'}). "
                f"Recommended action: {action}"
            )
    else:
        lines.append("- No structured conflicts were detected.")
    lines.extend(["", "## What to verify", ""])
    if actions:
        lines.extend(f"- {action}" for action in sorted(actions))
    else:
        lines.append("- No freshness-specific follow-up is required.")
    return "\n".join(lines) + "\n"


def explanation_document(packet: Any) -> dict:
    """Stable compact JSON for operators; excludes raw evidence bodies."""
    items = []
    for section in _SECTIONS:
        counters: dict[str, int] = {}
        for item in getattr(packet, section):
            sid = source_id(section, item)
            occurrence = counters.get(sid, 0)
            counters[sid] = occurrence + 1
            items.append(
                {
                    "section": section,
                    "source_id": sid,
                    "occurrence_index": occurrence,
                    "explain": item.explain or {},
                }
            )
    return {
        "explainability_version": EXPLAINABILITY_VERSION,
        "packet_id": packet.packet_id,
        "advisory_only": True,
        "summary": dict(packet.explainability),
        "items": items,
        "contradictions": list(packet.contradictions),
    }
