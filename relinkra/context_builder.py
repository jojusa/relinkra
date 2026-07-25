"""Deterministic Project Context Packet builder (R1E).

Composition, not relevance ranking: the builder selects a bounded,
deterministic slice of the R1C memory store and the R1D linkage graph
and packs it with explicit provenance.

Selection rules (all deterministic, no embeddings, no LLM ranking):

- Mode precedence: symbol > file > task > workspace > project.
- Memory visibility delegates to the R1C query policy: active only, no
  superseded/obsolete/history; project mode reads the shared channel,
  workspace-bearing modes read shared + the workspace channel, and
  agent_private is read ONLY when ``include_agent_private`` is set and
  the requesting agent matches.
- Type priority: handoff, pending, constraint, decision, architecture,
  bug, discovery, verification, task_result; then timestamp desc, then
  memory_id asc. Pending and handoff are first-class sections.
- Task mode adds a keyword filter: tokens of length >= 4 from the task
  text must appear in title/body; baseline types (handoff, pending,
  constraint, decision, architecture) always stay eligible.
- Code-focused modes resolve ONE focused reference through the R1D
  LinkageService and pull directly linked active memories. No recursive
  graph walk, no full-file ingestion; snippets are bounded and only for
  an exactly resolved symbol.
- Fixed structural guardrails (never token budgets); omitted and
  truncated counts are reported in diagnostics and surfaced as warnings.
- Portable output never leaks machine-local infrastructure paths: an
  ABSOLUTE CBM cache dir (Windows drive/UNC or POSIX) is dropped from
  ``project_facts`` and exposed only under ``diagnostics["local"]``,
  which is a machine-local diagnostic channel that must not be shipped
  as portable context (Markdown never renders diagnostics).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, List, Optional

from .cbm_adapter import CBMAdapterError
from .code_reference import (
    CodeRefError,
    CodeReference,
    normalize_repo_path,
)
from .context_packet import (
    PACKET_VERSION,
    ContextPacket,
    PacketItem,
    PacketValidationError,
    PacketWarning,
    Provenance,
    compute_packet_id,
    normalize_task_text,
)
from .linkage import (
    AMBIGUOUS,
    MISSING,
    RESOLVED,
    STALE,
    LinkageService,
    ResolvedReference,
    candidate_to_reference,
)
from .memory import (
    STORE_PAGE_LIMIT,
    MemoryError,
    MemoryService,
    sanitize_error,
    validate_project_id,
    validate_workspace_id,
)

TYPE_PRIORITY = (
    "handoff",
    "pending",
    "constraint",
    "decision",
    "architecture",
    "bug",
    "discovery",
    "verification",
    "task_result",
)
BASELINE_TYPES = frozenset(
    {"handoff", "pending", "constraint", "decision", "architecture"}
)

WARN_STALE = "stale_code_reference"
WARN_MISSING = "missing_code_reference"
WARN_AMBIGUOUS = "ambiguous_code_reference"
WARN_CBM_UNAVAILABLE = "cbm_unavailable"
WARN_ENGRAM_UNAVAILABLE = "engram_unavailable"
WARN_WORKSPACE_MISMATCH = "workspace_mismatch"
WARN_WORKSPACE_NOT_REGISTERED = "workspace_not_registered"
WARN_ITEMS_OMITTED = "items_omitted"
WARN_CONTENT_TRUNCATED = "content_truncated"

_TASK_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ContextBuildError(Exception):
    """Fatal build failure: invalid input or project mismatch.

    Everything else degrades to a partial packet plus warnings.
    """

    def __init__(self, message: str, exit_code: int = 1):
        super().__init__(message)
        self.exit_code = exit_code


@dataclass
class Guardrails:
    """Fixed structural limits. Not token budgets."""

    max_memories: int = 12
    max_code_refs: int = 8
    max_snippets: int = 2
    max_snippet_chars: int = 1200
    max_pending: int = 5
    max_handoffs: int = 3
    max_warnings: int = 10


@dataclass
class ContextRequest:
    project_id: str
    workspace_id: Optional[str] = None
    task: Optional[str] = None
    file: Optional[str] = None
    symbol: Optional[str] = None
    requesting_agent: str = ""
    include_agent_private: bool = False


def _type_rank(memory_type: str) -> int:
    try:
        return TYPE_PRIORITY.index(memory_type)
    except ValueError:
        return len(TYPE_PRIORITY)


def _priority_sort(memories: List) -> List:
    """Type priority asc, then timestamp desc, then memory_id asc."""
    ordered = sorted(memories, key=lambda m: m.memory_id)
    ordered = sorted(ordered, key=lambda m: m.timestamp, reverse=True)
    ordered = sorted(ordered, key=lambda m: _type_rank(m.memory_type))
    return ordered


def _is_absolute_infra_path(value: str) -> bool:
    """True for Windows drive/UNC or POSIX absolute paths. Deliberately
    platform-independent (no os.path.isabs): the portability policy must
    hold for packets BUILT on one OS and READ on another."""
    if value.startswith(("/", "\\")):
        return True
    return (
        len(value) > 2
        and value[0].isalpha()
        and value[1] == ":"
        and value[2] in ("/", "\\")
    )


class ContextBuilder:
    """Builds ContextPackets from a MemoryService + optional CBM/Registry."""

    def __init__(
        self,
        memory_service: Optional[MemoryService] = None,
        cbm_adapter: Any = None,
        registry: Any = None,
        workspace_root: Optional[str] = None,
        guardrails: Optional[Guardrails] = None,
        clock=_utcnow,
    ):
        self.memories = memory_service
        self.cbm = cbm_adapter
        self.registry = registry
        self.workspace_root = workspace_root
        self.guardrails = guardrails or Guardrails()
        self._clock = clock
        self.linkage = LinkageService(memory_service, cbm_adapter)

    # -- public API -----------------------------------------------------

    def build(self, request: ContextRequest) -> ContextPacket:
        g = self.guardrails
        warnings: List[PacketWarning] = []
        omitted = {
            "memories": 0,
            "pending": 0,
            "handoffs": 0,
            "code_facts": 0,
            "warnings": 0,
        }
        diagnostics: dict[str, Any] = {"skipped_malformed": 0}

        project_id = self._validate_project(request.project_id)
        workspace_id = None
        if request.workspace_id:
            try:
                workspace_id = validate_workspace_id(request.workspace_id)
            except MemoryError as exc:
                raise ContextBuildError(str(exc)) from exc

        mode = self._mode_for(request, workspace_id)
        task = (request.task or "").strip() or None

        project, workspace = self._registry_context(
            project_id, workspace_id, warnings
        )
        repository_identity = (
            project.repository_identity.to_dict() if project is not None else None
        )
        project_facts = self._project_facts(project, workspace)
        local_diagnostics = self._local_diagnostics(workspace)
        if local_diagnostics:
            diagnostics["local"] = local_diagnostics

        scope = "workspace_local" if workspace_id else "project_shared"

        candidates, linked_ids, engram_ok = self._collect_memories(
            request, project_id, workspace_id, scope, warnings, diagnostics
        )

        focus, code_ref_items, code_fact_items, focus_linked_ids, snip_stats = (
            self._build_code_focus(
                request, mode, project_id, workspace_id, scope,
                warnings, omitted, engram_ok,
            )
        )
        linked_ids |= focus_linked_ids

        matched_tokens = self._task_token_map(mode, task, candidates)
        ordered = _priority_sort(candidates)
        if mode == "task":
            ordered = [m for m in ordered if m.memory_id in matched_tokens]
        pending_items, handoff_items, memory_items = self._split_selection(
            ordered, linked_ids, matched_tokens, scope, omitted
        )

        omitted["code_refs"] = max(0, len(code_ref_items) - g.max_code_refs)
        code_ref_items = code_ref_items[: g.max_code_refs]

        source_ids = sorted(
            [item.provenance.memory_id for item in (
                memory_items + pending_items + handoff_items
            ) if item.provenance.memory_id]
            + [
                item.provenance.code_reference_id
                for item in (code_ref_items + code_fact_items)
                if item.provenance.code_reference_id
            ]
        )
        packet_id = compute_packet_id(
            project_id=project_id,
            workspace_id=workspace_id,
            mode=mode,
            task=task,
            focus=focus,
            source_ids=tuple(source_ids),
        )

        omission_warnings: List[PacketWarning] = []
        self._omission_warnings(omission_warnings, omitted, snip_stats)
        # Omission/truncation warnings are appended AFTER truncation and
        # get deterministic priority: they are never silently dropped by
        # the max_warnings guardrail.
        reserved = min(len(omission_warnings), g.max_warnings)
        keep = g.max_warnings - reserved
        if len(warnings) > keep:
            omitted["warnings"] = len(warnings) - keep
            warnings = warnings[:keep]
        warnings.extend(omission_warnings)

        sources = sorted(
            {item.provenance.source for item in (
                memory_items + pending_items + handoff_items
                + code_ref_items + code_fact_items
            )}
            | ({"registry"} if project is not None else set())
            | {"relinkra"}
        )
        diagnostics.update(
            {
                "mode": mode,
                "counts": {
                    "memories": len(memory_items),
                    "pending": len(pending_items),
                    "handoffs": len(handoff_items),
                    "code_references": len(code_ref_items),
                    "code_facts": len(code_fact_items),
                    "warnings": len(warnings),
                    "snippets": snip_stats["snippets"],
                },
                "omitted": {k: v for k, v in sorted(omitted.items())},
                "truncated_snippets": snip_stats["truncated"],
                "selected_source_ids": source_ids,
            }
        )

        return ContextPacket(
            packet_id=packet_id,
            created_at=self._clock(),
            mode=mode,
            project_id=project_id,
            workspace_id=workspace_id,
            repository_identity=repository_identity,
            requesting_agent=(request.requesting_agent or ""),
            task=task,
            focus=focus,
            project_facts=project_facts,
            memories=memory_items,
            code_references=code_ref_items,
            code_facts=code_fact_items,
            pending=pending_items,
            handoffs=handoff_items,
            warnings=warnings,
            provenance={
                "builder": "relinkra.context_builder",
                "packet_version": PACKET_VERSION,
                "sources": sources,
                "ranking": "deterministic (type priority + keyword filter); "
                "no embeddings, no LLM ranking, no token budgets",
            },
            diagnostics=diagnostics,
        )

    # -- validation / registry ------------------------------------------

    @staticmethod
    def _validate_project(project_id: str) -> str:
        try:
            return validate_project_id(project_id)
        except MemoryError as exc:
            raise ContextBuildError(str(exc)) from exc

    @staticmethod
    def _mode_for(request: ContextRequest, workspace_id: Optional[str]) -> str:
        if (request.symbol or "").strip():
            return "symbol"
        if (request.file or "").strip():
            return "file"
        if (request.task or "").strip():
            return "task"
        if workspace_id:
            return "workspace"
        return "project"

    def _registry_context(self, project_id, workspace_id, warnings):
        project = None
        workspace = None
        if self.registry is None:
            return None, None
        project = self.registry.projects.get(project_id)
        if project is None:
            raise ContextBuildError(
                "project_id is not registered in the registry "
                "(project mismatch)",
                exit_code=2,
            )
        if workspace_id:
            workspace = self.registry.get_workspace(workspace_id)
            if workspace is None:
                warnings.append(
                    PacketWarning(
                        WARN_WORKSPACE_NOT_REGISTERED,
                        "workspace_id is not present in the registry; "
                        "continuing without workspace metadata",
                    )
                )
            elif workspace.project_id != project_id:
                raise ContextBuildError(
                    "workspace_id belongs to a different project "
                    "(project mismatch)",
                    exit_code=2,
                )
        if workspace is not None and self.workspace_root:
            from .identity import canonicalize_path

            if canonicalize_path(self.workspace_root) != workspace.canonical_path:
                warnings.append(
                    PacketWarning(
                        WARN_WORKSPACE_MISMATCH,
                        "workspace_root does not match the registered "
                        "workspace path",
                    )
                )
        return project, workspace

    @staticmethod
    def _project_facts(project, workspace) -> dict:
        facts: dict[str, Any] = {
            "registered": project is not None,
        }
        if project is not None:
            facts["display_name"] = project.display_name
            facts["created_at"] = project.created_at
        if workspace is not None:
            git = workspace.git or {}
            cbm = workspace.cbm or {}
            facts["workspace"] = {
                "workspace_id": workspace.workspace_id,
                "os": workspace.os,
                "branch": git.get("branch") or None,
                "head_sha": git.get("head_sha") or None,
                "cbm_project_name": cbm.get("project_name") or None,
            }
            cache_dir = cbm.get("cache_dir") or None
            if cache_dir is not None and not _is_absolute_infra_path(cache_dir):
                # Portable only when repo/machine-relative; absolute infra
                # paths live in diagnostics["local"] instead.
                facts["workspace"]["cbm_cache_dir"] = cache_dir
        return facts

    @staticmethod
    def _local_diagnostics(workspace) -> dict:
        """Machine-local diagnostics channel: values that must never ship
        in portable project_facts (absolute infrastructure paths)."""
        local: dict[str, Any] = {}
        if workspace is not None:
            cache_dir = (workspace.cbm or {}).get("cache_dir") or None
            if cache_dir is not None and _is_absolute_infra_path(cache_dir):
                local["cbm_cache_dir"] = cache_dir
        return local

    # -- memory selection -------------------------------------------------

    def _collect_memories(
        self, request, project_id, workspace_id, scope, warnings, diagnostics
    ):
        """Active visible memories via the R1C policy. Never raises."""
        candidates: List = []
        if self.memories is None:
            warnings.append(
                PacketWarning(
                    WARN_ENGRAM_UNAVAILABLE,
                    "no memory service configured; packet has no memories",
                )
            )
            return candidates, set(), False
        try:
            result = self.memories.query(
                project_id=project_id,
                scope=scope,
                workspace_id=workspace_id,
                include_history=False,
                limit=STORE_PAGE_LIMIT,
            )
            candidates.extend(result.memories)
            diagnostics["skipped_malformed"] += result.skipped_malformed
        except MemoryError as exc:
            warnings.append(
                PacketWarning(
                    WARN_ENGRAM_UNAVAILABLE,
                    f"memory query failed: {sanitize_error(str(exc))}",
                )
            )
            return candidates, set(), False

        if request.include_agent_private and (request.requesting_agent or "").strip():
            try:
                private = self.memories.query(
                    project_id=project_id,
                    scope="agent_private",
                    agent_type=request.requesting_agent.strip(),
                    include_history=False,
                    limit=STORE_PAGE_LIMIT,
                )
                candidates.extend(private.memories)
                diagnostics["skipped_malformed"] += private.skipped_malformed
            except MemoryError as exc:
                warnings.append(
                    PacketWarning(
                        WARN_ENGRAM_UNAVAILABLE,
                        "agent-private memory query failed: "
                        f"{sanitize_error(str(exc))}",
                    )
                )

        seen = set()
        unique = []
        for memory in candidates:
            if memory.memory_id in seen:
                continue
            seen.add(memory.memory_id)
            unique.append(memory)
        return unique, set(), True

    def _task_token_map(self, mode, task, candidates):
        """memory_id -> sorted matched task tokens (empty for non-task)."""
        if mode != "task" or not task:
            return {}
        tokens = sorted(
            {t for t in _TASK_TOKEN_RE.findall(task.lower()) if len(t) >= 4}
        )
        matched = {}
        for memory in candidates:
            if memory.memory_type in BASELINE_TYPES:
                matched[memory.memory_id] = []
                continue
            haystack = f"{memory.title} {memory.body}".lower()
            hits = [t for t in tokens if t in haystack]
            if hits:
                matched[memory.memory_id] = hits
        return matched

    def _split_selection(self, ordered, linked_ids, matched_tokens, scope, omitted):
        g = self.guardrails
        pending_items: List[PacketItem] = []
        handoff_items: List[PacketItem] = []
        memory_items: List[PacketItem] = []
        for memory in ordered:
            if memory.memory_type == "pending":
                if len(pending_items) < g.max_pending:
                    pending_items.append(
                        self._memory_item(memory, linked_ids, matched_tokens)
                    )
                else:
                    omitted["pending"] += 1
            elif memory.memory_type == "handoff":
                if len(handoff_items) < g.max_handoffs:
                    handoff_items.append(
                        self._memory_item(memory, linked_ids, matched_tokens)
                    )
                else:
                    omitted["handoffs"] += 1
            else:
                if len(memory_items) < g.max_memories:
                    memory_items.append(
                        self._memory_item(memory, linked_ids, matched_tokens)
                    )
                else:
                    omitted["memories"] += 1
        return pending_items, handoff_items, memory_items

    @staticmethod
    def _memory_item(memory, linked_ids, matched_tokens) -> PacketItem:
        if memory.memory_id in linked_ids:
            why = "directly linked to the focused code"
        elif memory.scope_channel.startswith("agent/"):
            why = "agent-private memory of the requesting agent"
        elif memory.memory_type in ("pending", "handoff"):
            why = f"active {memory.memory_type} (first-class section)"
        elif matched_tokens.get(memory.memory_id):
            why = "task keyword match: " + ", ".join(
                matched_tokens[memory.memory_id]
            )
        else:
            why = (
                f"baseline active {memory.memory_type} "
                f"({memory.scope_channel} channel)"
            )
        return PacketItem(
            data=memory.to_dict(),
            provenance=Provenance(
                source="engram",
                why_included=why,
                memory_id=memory.memory_id,
                agent_type=memory.agent_type or None,
                topic_key=memory.topic_key or None,
                workspace_id=memory.workspace_id,
            ),
        )

    # -- code focus -------------------------------------------------------

    def _build_code_focus(
        self, request, mode, project_id, workspace_id, scope,
        warnings, omitted, engram_ok,
    ):
        g = self.guardrails
        focus = None
        code_ref_items: List[PacketItem] = []
        code_fact_items: List[PacketItem] = []
        linked_ids: set = set()
        snip_stats = {"snippets": 0, "truncated": 0}
        if mode not in ("file", "symbol"):
            return focus, code_ref_items, code_fact_items, linked_ids, snip_stats

        if mode == "file":
            ref = self._file_ref(request, project_id, workspace_id)
            focus = {"reference_kind": "file", "file_path": ref.file_path}
            resolution, adapter_failed = self._resolve_focus(ref, warnings)
            if not adapter_failed:
                self._resolution_warning(resolution, warnings)
            code_ref_items.append(self._code_ref_item(ref, resolution, mode))
            fact = self._fact_item(
                resolution.candidate, resolution.state, snip_stats,
                snippet_ref=None,
            )
            if fact is not None:
                code_fact_items.append(fact)
            linked_ids |= self._linked_memory_ids(
                project_id, scope, workspace_id, engram_ok, warnings,
                file_path=ref.file_path,
            )
        else:
            ref, extra_candidates = self._symbol_ref(
                request, project_id, workspace_id, warnings
            )
            raw_symbol = (request.symbol or "").strip()
            focus = {"reference_kind": "symbol", "symbol": raw_symbol}
            if ref is not None:
                focus = {
                    "reference_kind": "symbol",
                    "file_path": ref.file_path,
                    "qualified_name": ref.qualified_name or ref.symbol_name,
                }
                resolution, adapter_failed = self._resolve_focus(ref, warnings)
                if not adapter_failed:
                    self._resolution_warning(resolution, warnings)
                code_ref_items.append(self._code_ref_item(ref, resolution, mode))
                snippet_ref = (
                    ref
                    if (
                        ref.reference_kind == "symbol"
                        and resolution.state == RESOLVED
                        and snip_stats["snippets"] < g.max_snippets
                    )
                    else None
                )
                fact = self._fact_item(
                    resolution.candidate, resolution.state, snip_stats,
                    snippet_ref=snippet_ref,
                )
                if fact is not None:
                    code_fact_items.append(fact)
            for candidate in extra_candidates:
                if len(code_fact_items) >= g.max_code_refs:
                    omitted["code_facts"] += 1
                    continue
                fact = self._fact_item(
                    candidate.to_dict(), AMBIGUOUS, snip_stats, snippet_ref=None
                )
                if fact is not None:
                    code_fact_items.append(fact)
            symbol_query = raw_symbol
            if ref is not None:
                symbol_query = ref.qualified_name or ref.symbol_name or raw_symbol
            linked_ids |= self._linked_memory_ids(
                project_id, scope, workspace_id, engram_ok, warnings,
                symbol=symbol_query,
            )
        return focus, code_ref_items, code_fact_items, linked_ids, snip_stats

    def _resolve_focus(self, ref, warnings):
        """Resolve the focused ref; an adapter outage degrades to a
        ``missing`` resolution plus WARN_CBM_UNAVAILABLE (never a silent
        ``missing_code_reference``). Returns (resolution, adapter_failed).
        """
        try:
            return self.linkage.resolve_reference(ref), False
        except CBMAdapterError as exc:
            warnings.append(
                PacketWarning(
                    WARN_CBM_UNAVAILABLE,
                    "CBM adapter configured but failed: "
                    f"{sanitize_error(str(exc))}",
                )
            )
            return (
                ResolvedReference(
                    reference=ref.to_dict(),
                    state=MISSING,
                    note="CBM adapter unavailable; preserving historical "
                    "reference",
                ),
                True,
            )

    def _file_ref(self, request, project_id, workspace_id) -> CodeReference:
        try:
            path = normalize_repo_path(request.file or "")
            return CodeReference(
                project_id=project_id,
                workspace_id=workspace_id,
                reference_kind="file",
                file_path=path,
            )
        except CodeRefError as exc:
            raise ContextBuildError(f"invalid --file input: {exc}") from exc

    def _symbol_ref(self, request, project_id, workspace_id, warnings):
        """Resolve the symbol input to (CodeReference|None, extra candidates)."""
        raw = (request.symbol or "").strip()
        parsed = None
        if raw.startswith("{"):
            try:
                parsed = json.loads(raw)
            except ValueError:
                parsed = None
        if isinstance(parsed, dict) and parsed.get("reference_kind"):
            try:
                ref = CodeReference.from_dict(parsed)
            except CodeRefError as exc:
                raise ContextBuildError(
                    f"invalid --symbol code reference: {exc}"
                ) from exc
            if ref.project_id != project_id:
                raise ContextBuildError(
                    "symbol code reference belongs to a different project "
                    "(project mismatch)",
                    exit_code=2,
                )
            return ref, []

        if self.cbm is None:
            warnings.append(
                PacketWarning(
                    WARN_CBM_UNAVAILABLE,
                    "no CBM adapter configured; symbol not resolved against "
                    "a live index",
                )
            )
            return None, []
        query = raw.rsplit(".", 1)[-1] or raw
        try:
            candidates, invalid = self.linkage._find_candidates(
                CodeReference(
                    project_id=project_id,
                    workspace_id=workspace_id,
                    reference_kind="symbol",
                    file_path="_focus/query",
                    symbol_name=query,
                    qualified_name=raw if "." in raw else None,
                )
            )
        except CBMAdapterError as exc:
            warnings.append(
                PacketWarning(
                    WARN_CBM_UNAVAILABLE,
                    "CBM adapter configured but failed: "
                    f"{sanitize_error(str(exc))}",
                )
            )
            return None, []
        exact = [
            c
            for c in candidates
            if c.qualified_name == raw or c.symbol_name == raw
        ]
        chosen = None
        if len(exact) == 1:
            chosen = exact[0]
        elif len(candidates) == 1:
            chosen = candidates[0]
        if chosen is not None:
            rest = [c for c in candidates if c is not chosen]
            return chosen, rest
        if candidates:
            warnings.append(
                PacketWarning(
                    WARN_AMBIGUOUS,
                    f"symbol {raw!r} has {len(candidates)} live candidates; "
                    "all returned, none chosen silently",
                )
            )
            return None, candidates
        warnings.append(
            PacketWarning(
                WARN_MISSING,
                f"symbol {raw!r} has no live CBM candidate",
            )
        )
        return None, []

    def _resolution_warning(self, resolution, warnings) -> None:
        if resolution.state == STALE:
            warnings.append(
                PacketWarning(
                    WARN_STALE,
                    resolution.note or "stored reference drifted from the index",
                )
            )
        elif resolution.state == AMBIGUOUS:
            warnings.append(
                PacketWarning(
                    WARN_AMBIGUOUS,
                    resolution.note or "multiple live candidates",
                )
            )
        elif resolution.state == MISSING:
            if self.cbm is None:
                warnings.append(
                    PacketWarning(
                        WARN_CBM_UNAVAILABLE,
                        "no CBM adapter configured; cannot resolve the "
                        "focused reference",
                    )
                )
            else:
                warnings.append(
                    PacketWarning(
                        WARN_MISSING,
                        resolution.note or "no live CBM candidate",
                    )
                )

    @staticmethod
    def _code_ref_item(ref, resolution, mode) -> PacketItem:
        return PacketItem(
            data={
                "reference": ref.to_dict(),
                "resolution_state": resolution.state,
                "note": resolution.note,
            },
            provenance=Provenance(
                source="cbm" if resolution.state != MISSING else "relinkra",
                why_included=f"focused {ref.reference_kind} (mode={mode})",
                code_reference_id=ref.code_reference_id,
                workspace_id=ref.workspace_id,
                cbm_project_name=ref.cbm_project_name,
                resolution_state=resolution.state,
            ),
        )

    def _fact_item(self, candidate, state, snip_stats, snippet_ref):
        """Minimal CBM fact; optional bounded snippet for exact symbols."""
        if not candidate:
            return None
        try:
            ref = CodeReference.from_dict(candidate)
        except CodeRefError:
            return None
        data = {
            "code_reference_id": ref.code_reference_id,
            "file_path": ref.file_path,
            "qualified_name": ref.qualified_name,
            "symbol_name": ref.symbol_name,
            "symbol_kind": ref.symbol_kind,
            "language": ref.language,
            "start_line": ref.start_line,
            "end_line": ref.end_line,
            "resolution_state": state,
        }
        if snippet_ref is not None:
            snippet, truncated = self._read_snippet(snippet_ref)
            if snippet is not None:
                data["snippet"] = snippet
                data["snippet_truncated"] = truncated
                snip_stats["snippets"] += 1
                if truncated:
                    snip_stats["truncated"] += 1
        return PacketItem(
            data=data,
            provenance=Provenance(
                source="cbm",
                why_included="minimal CBM fact for the focused code",
                code_reference_id=ref.code_reference_id,
                workspace_id=ref.workspace_id,
                cbm_project_name=ref.cbm_project_name,
                resolution_state=state,
            ),
        )

    def _read_snippet(self, ref) -> tuple:
        """Bounded line-range snippet from the workspace; never full files."""
        if not self.workspace_root or not ref.start_line:
            return None, False
        path = os.path.join(
            self.workspace_root, *ref.file_path.split("/")
        )
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            return None, False
        end = ref.end_line or ref.start_line
        text = "\n".join(lines[ref.start_line - 1 : end])
        truncated = False
        limit = self.guardrails.max_snippet_chars
        if len(text) > limit:
            text = text[:limit]
            truncated = True
        return text, truncated

    def _linked_memory_ids(
        self, project_id, scope, workspace_id, engram_ok, warnings,
        file_path=None, symbol=None,
    ) -> set:
        if not engram_ok or self.memories is None:
            return set()
        try:
            matches = self.linkage.code_to_memory(
                project_id=project_id,
                file_path=file_path,
                symbol=symbol,
                scope=scope,
                workspace_id=workspace_id,
                include_history=False,
                limit=STORE_PAGE_LIMIT,
            )
        except MemoryError as exc:
            warnings.append(
                PacketWarning(
                    WARN_ENGRAM_UNAVAILABLE,
                    f"code-to-memory query failed: {sanitize_error(str(exc))}",
                )
            )
            return set()
        return {m["memory"]["memory_id"] for m in matches}

    # -- warnings ------------------------------------------------------------

    @staticmethod
    def _omission_warnings(warnings, omitted, snip_stats) -> None:
        dropped = {k: v for k, v in omitted.items() if v}
        if dropped:
            detail = ", ".join(f"{k}={v}" for k, v in sorted(dropped.items()))
            warnings.append(
                PacketWarning(
                    WARN_ITEMS_OMITTED,
                    f"guardrail limits omitted items: {detail}",
                )
            )
        if snip_stats["truncated"]:
            warnings.append(
                PacketWarning(
                    WARN_CONTENT_TRUNCATED,
                    f"{snip_stats['truncated']} snippet(s) truncated to the "
                    "character guardrail",
                )
            )
