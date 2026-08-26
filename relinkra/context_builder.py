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

import hashlib
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
    PACKET_VERSION_V1,
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
from .git_intelligence import (
    GIT_DEFAULT_COMMITS,
    GitIntelligenceService,
)
from .explainability import annotate_packet
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
WARN_CBM_STRUCTURAL = "cbm_structural_unavailable"
WARN_ENGRAM_UNAVAILABLE = "engram_unavailable"
WARN_WORKSPACE_MISMATCH = "workspace_mismatch"
WARN_WORKSPACE_NOT_REGISTERED = "workspace_not_registered"
WARN_ITEMS_OMITTED = "items_omitted"
WARN_CONTENT_TRUNCATED = "content_truncated"
WARN_GIT_CONFLICTS = "git_conflicts"
WARN_GIT_UNAVAILABLE = "git_unavailable"

# Git-fact cap priority (quality-first, handoff Phase 18): essential repo
# state and focused-file/anchored kinds outrank bulk listing kinds when
# the total cap trims. Everything not listed here (working_tree_change,
# recent_commit) is bulk and is shed first.
GIT_FACT_CAP_PRIORITY_KINDS = frozenset(
    {
        "repository_state",
        "head_facts",
        "current_change_state",
        "file_history",
        "diff_fact",
        "co_change",
    }
)

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
    max_git_facts: int = 24
    max_git_diff_entries: int = 8
    max_git_cochange: int = 10
    max_structural_facts: int = 4
    max_structural_relationships: int = 12


@dataclass
class ContextRequest:
    project_id: str
    workspace_id: Optional[str] = None
    task: Optional[str] = None
    file: Optional[str] = None
    symbol: Optional[str] = None
    requesting_agent: str = ""
    include_agent_private: bool = False
    include_git: bool = False
    git_history_limit: Optional[int] = None
    git_include_diff_snippets: bool = False
    # Additive capability negotiation for legacy direct-builder consumers.
    # Agent-facing service/CLI entry points enable R4D explicitly.
    include_explain: bool = False


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
        git_service: Any = None,
    ):
        self.memories = memory_service
        self.cbm = cbm_adapter
        self.registry = registry
        self.workspace_root = workspace_root
        self.guardrails = guardrails or Guardrails()
        self._clock = clock
        self.linkage = LinkageService(memory_service, cbm_adapter)
        self.git = git_service if git_service is not None else GitIntelligenceService()

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
        diagnostics: dict[str, Any] = {
            "skipped_malformed": 0,
            "skipped_truncated": 0,
        }

        project_id = self._validate_project(request.project_id)
        workspace_id = None
        if request.workspace_id:
            try:
                workspace_id = validate_workspace_id(request.workspace_id)
            except MemoryError as exc:
                raise ContextBuildError(str(exc)) from exc

        mode = self._mode_for(request, workspace_id)
        task = (request.task or "").strip() or None
        # Packet identity stays in the rlkctx1 namespace: compute_packet_id
        # is always fed PACKET_VERSION_V1 so a git-off packet is
        # byte-identical to a pre-git build AND a git-on packet with the
        # same selected sources yields the SAME packet_id (git facts never
        # participate in identity). The emitted packet_version field alone
        # reflects rlkctx2 when git facts are requested.
        packet_version = (
            PACKET_VERSION if request.include_git else PACKET_VERSION_V1
        )

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

        code_fact_items.extend(
            self._build_structural_evidence(
                request,
                mode,
                project_id,
                focus,
                code_fact_items,
                warnings,
                omitted,
            )
        )

        try:
            git_items = self._collect_git_facts(
                request, mode, focus, project_id, workspace_id,
                warnings, omitted, diagnostics,
            )
        except Exception:
            # Git is an additive read-side source. Unexpected adapter/runtime
            # failures must not take down memory, handoff, or code reads, and
            # exception text may contain machine-local paths or credentials.
            warnings.append(
                PacketWarning(
                    WARN_GIT_UNAVAILABLE,
                    "git context collection failed unexpectedly",
                )
            )
            git_items = []

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
            packet_version=PACKET_VERSION_V1,
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
                + code_ref_items + code_fact_items + git_items
            )}
            | ({"registry"} if project is not None else set())
            | {"relinkra"}
        )
        counts = {
            "memories": len(memory_items),
            "pending": len(pending_items),
            "handoffs": len(handoff_items),
            "code_references": len(code_ref_items),
            "code_facts": len(code_fact_items),
            "warnings": len(warnings),
            "snippets": snip_stats["snippets"],
        }
        if request.include_git:
            counts["git_facts"] = len(git_items)
        diagnostics.update(
            {
                "mode": mode,
                "counts": counts,
                "omitted": {k: v for k, v in sorted(omitted.items())},
                "truncated_snippets": snip_stats["truncated"],
                "selected_source_ids": source_ids,
            }
        )

        created_at = self._clock()
        packet = ContextPacket(
            packet_id=packet_id,
            created_at=created_at,
            mode=mode,
            project_id=project_id,
            packet_version=packet_version,
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
            git_facts=git_items,
            warnings=warnings,
            provenance={
                "builder": "relinkra.context_builder",
                "packet_version": packet_version,
                "sources": sources,
                "ranking": "deterministic (type priority + keyword filter); "
                "no embeddings, no LLM ranking, no token budgets",
            },
            diagnostics=diagnostics,
        )
        relation_resolver = None
        if self.workspace_root and hasattr(self.git, "collect_revision_relation"):
            relation_resolver = (
                lambda evidence, current: self.git.collect_revision_relation(
                    self.workspace_root, evidence, current
                )
            )
        # R4D is read-time metadata only. It neither filters evidence nor
        # mutates Engram/CBM records, and uses the same injected clock value
        # already captured in ``created_at``.
        if request.include_explain:
            return annotate_packet(
                packet,
                as_of=created_at,
                relation_resolver=relation_resolver,
            )
        return packet

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

    # -- git facts (R2, opt-in) --------------------------------------------

    def _collect_git_facts(
        self, request, mode, focus, project_id, workspace_id,
        warnings, omitted, diagnostics,
    ) -> List[PacketItem]:
        """Collect opt-in git facts as typed PacketItems (source="git").

        Mode mapping (design §2): every mode gets repository_state +
        head_facts; workspace-and-above adds working_tree_change entries
        and recent_commit; file/symbol add current_change_state,
        file_history, diff_fact (focused file first) and co_change anchored
        at FILE level; task adds co_change only with a file anchor. Every
        section degrades to partial facts + WARN_GIT_* warnings — the
        packet always stays valid. The absolute repository root is exposed
        ONLY under diagnostics["local"] (machine-local channel).
        """
        if not request.include_git:
            return []
        if not self.workspace_root:
            # No resolvable workspace root: git is silently skipped.
            return []
        g = self.guardrails
        root = self.workspace_root
        caps, cap_warnings = self.git.collect_capabilities(root)
        for git_warning in cap_warnings:
            warnings.append(PacketWarning(git_warning.code, git_warning.message))
        if caps.repository_root:
            local = diagnostics.setdefault("local", {})
            local["git_repository_root"] = caps.repository_root
        if not (caps.git_available and caps.repository_detected):
            return []

        items: List[PacketItem] = []

        def add(kind, data, why, ref_id=None):
            payload = {"kind": kind}
            payload.update(data)
            items.append(
                PacketItem(
                    data=payload,
                    provenance=Provenance(
                        source="git",
                        why_included=why,
                        code_reference_id=ref_id,
                    ),
                )
            )

        def extend_warnings(section_warnings):
            for git_warning in section_warnings:
                warnings.append(
                    PacketWarning(git_warning.code, git_warning.message)
                )

        state, state_warnings = self.git.collect_repository_state(
            root, capabilities=caps
        )
        extend_warnings(state_warnings)
        if state is not None:
            add(
                "repository_state",
                state.to_dict(),
                f"git repository state (mode={mode})",
            )
        head, head_warnings = self.git.collect_head_facts(root, state=state)
        extend_warnings(head_warnings)
        if head is not None:
            add("head_facts", head.to_dict(), f"git HEAD facts (mode={mode})")
        if mode == "project":
            return self._cap_git_facts(items, omitted)

        tree, tree_warnings = self.git.collect_working_tree(root)
        extend_warnings(tree_warnings)
        if tree is not None:
            if tree.conflicted:
                warnings.append(
                    PacketWarning(
                        WARN_GIT_CONFLICTS,
                        f"{len(tree.conflicted)} conflicted path(s) in the "
                        "working tree",
                    )
                )
            buckets = (
                ("conflicted", tree.conflicted),
                ("staged", tree.staged),
                ("unstaged", tree.unstaged),
                ("untracked", tree.untracked),
                ("deleted", tree.deleted),
            )
            for bucket_state, paths in buckets:
                for path in paths:
                    add(
                        "working_tree_change",
                        {"path": path, "state": bucket_state, "old_path": None},
                        f"git working tree change (mode={mode})",
                    )
            for old_path, new_path in tree.renamed:
                add(
                    "working_tree_change",
                    {"path": new_path, "state": "renamed", "old_path": old_path},
                    f"git working tree change (mode={mode})",
                )
        limit = (
            request.git_history_limit
            if request.git_history_limit is not None
            else GIT_DEFAULT_COMMITS
        )
        commits, commit_warnings = self.git.collect_recent_commits(
            root, limit=limit
        )
        extend_warnings(commit_warnings)
        for commit in commits:
            add(
                "recent_commit",
                commit.to_dict(),
                f"git recent commit (mode={mode})",
            )

        anchor = None
        if mode in ("file", "symbol") and focus:
            anchor = focus.get("file_path")
        elif mode == "task" and (request.file or "").strip():
            anchor = normalize_repo_path(request.file)
        if anchor is None:
            return self._cap_git_facts(items, omitted)
        anchor_ref_id = CodeReference(
            project_id=project_id,
            workspace_id=workspace_id,
            reference_kind="file",
            file_path=anchor,
        ).code_reference_id

        if mode in ("file", "symbol"):
            change, change_warnings = self.git.collect_current_change_state(
                root, anchor
            )
            extend_warnings(change_warnings)
            if change is not None:
                add(
                    "current_change_state",
                    {"file_path": anchor, "state": change.value},
                    f"git current change state for the focused file "
                    f"(mode={mode})",
                    anchor_ref_id,
                )
            history, history_warnings = self.git.collect_file_history(
                root, anchor, limit=request.git_history_limit
            )
            extend_warnings(history_warnings)
            if history:
                add(
                    "file_history",
                    {
                        "file_path": anchor,
                        "commits": [c.to_dict() for c in history],
                    },
                    f"git file history for the focused file (mode={mode})",
                    anchor_ref_id,
                )
            diffs, diff_warnings = self.git.collect_diff(
                root, include_snippets=request.git_include_diff_snippets
            )
            extend_warnings(diff_warnings)
            # Stable partition: the focused file's diff facts lead, the
            # rest keep git's path order.
            ordered_diffs = [f for f in diffs if f.path == anchor] + [
                f for f in diffs if f.path != anchor
            ]
            for fact in ordered_diffs[: g.max_git_diff_entries]:
                add(
                    "diff_fact",
                    fact.to_dict(),
                    f"git diff fact (mode={mode})",
                )
        cochange, cochange_warnings = self.git.collect_cochange(root, anchor)
        extend_warnings(cochange_warnings)
        for fact in cochange[: g.max_git_cochange]:
            add(
                "co_change",
                fact.to_dict(),
                f"git co-changed path for the focused file (mode={mode})",
                anchor_ref_id,
            )
        return self._cap_git_facts(items, omitted)

    def _cap_git_facts(self, items, omitted) -> List[PacketItem]:
        """Total git-fact guardrail: deterministic priority-first
        shedding, reported through the shared omission channel.

        Essentials (repository_state/head_facts) and focused-file kinds
        (current_change_state, file_history, diff_fact, co_change) are
        kept before bulk listing kinds (working_tree_change,
        recent_commit); within each class the original append order is
        preserved and shedding is from the end of the class. Survivors
        keep their original append order in the packet.
        """
        limit = self.guardrails.max_git_facts
        if len(items) <= limit:
            return items
        omitted["git_facts"] = (
            omitted.get("git_facts", 0) + len(items) - limit
        )
        priority_idx = [
            i
            for i, item in enumerate(items)
            if item.data.get("kind") in GIT_FACT_CAP_PRIORITY_KINDS
        ]
        bulk_idx = [
            i
            for i, item in enumerate(items)
            if item.data.get("kind") not in GIT_FACT_CAP_PRIORITY_KINDS
        ]
        keep = set(priority_idx[:limit])
        keep.update(bulk_idx[: max(0, limit - len(keep))])
        return [item for i, item in enumerate(items) if i in keep]

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
            diagnostics["skipped_truncated"] += result.skipped_truncated
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
                diagnostics["skipped_truncated"] += private.skipped_truncated
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

    @staticmethod
    def _structural_request_kinds(request) -> tuple[bool, bool]:
        """Use deterministic task words, never an LLM, for optional reads."""
        tokens = set(
            _TASK_TOKEN_RE.findall((request.task or "").casefold())
        )
        architecture = bool(
            tokens
            & {
                "architecture", "architectural", "orientation", "module",
                "modules", "component", "components", "boundary",
                "boundaries", "layer", "layers", "structure", "impact",
            }
        )
        traversal = bool(
            tokens
            & {
                "caller", "callers", "callee", "callees", "dependency",
                "dependencies", "impact", "path", "paths", "relationship",
                "relationships", "trace", "traversal",
            }
        )
        return architecture, traversal

    @staticmethod
    def _structural_source_id(kind: str, data: dict) -> str:
        payload = json.dumps(
            {"kind": kind, "data": data},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return "struct_" + hashlib.sha256(payload).hexdigest()[:32]

    @staticmethod
    def _structural_item(
        *,
        project_id: str,
        kind: str,
        result: dict,
        payload: dict,
        why: str,
    ) -> PacketItem:
        authority = result.get("authority") or {}
        data = {
            "evidence_kind": kind,
            "project_id": project_id,
            "freshness": result.get("freshness") or {
                "state": "unknown",
                "reason": "graph freshness was not provided",
            },
        }
        for key in ("index_status", "trust_stages"):
            if key in authority:
                data[key] = authority[key]
        data.update(payload)
        return PacketItem(
            data=data,
            provenance=Provenance(
                source="cbm",
                why_included=why,
                code_reference_id=ContextBuilder._structural_source_id(
                    kind, data
                ),
            ),
        )

    def _build_structural_evidence(
        self,
        request,
        mode,
        project_id,
        focus,
        code_fact_items,
        warnings,
        omitted,
    ) -> List[PacketItem]:
        g = self.guardrails
        wants_architecture, wants_traversal = self._structural_request_kinds(request)
        if not (wants_architecture or wants_traversal):
            return []
        if self.cbm is None:
            warnings.append(
                PacketWarning(
                    WARN_CBM_STRUCTURAL,
                    "optional CBM structural evidence is unavailable; "
                    "continue with native file and symbol exploration",
                )
            )
            return []

        items: List[PacketItem] = []
        if wants_architecture and len(items) < g.max_structural_facts:
            path = None
            if request.file:
                try:
                    path = normalize_repo_path(request.file)
                except CodeRefError:
                    path = None
            result = self.linkage.architecture_orientation(
                path=path, limit=min(5, g.max_structural_facts)
            )
            if result.get("evidence") is not None:
                evidence = result["evidence"]
                items.append(
                    self._structural_item(
                        project_id=project_id,
                        kind="architecture_fact",
                        result=result,
                        payload={
                            "architecture": evidence,
                            "coverage": {
                                "complete": False,
                                "qualification": (
                                    "Architecture is a compact bounded view; "
                                    "native repository exploration remains available."
                                ),
                            },
                        },
                        why=f"compact CBM architecture orientation (mode={mode})",
                    )
                )
            else:
                warnings.append(
                    PacketWarning(
                        WARN_CBM_STRUCTURAL,
                        result.get("warning")
                        or "optional CBM architecture evidence was omitted",
                    )
                )

        if wants_traversal and len(items) < g.max_structural_facts:
            function_name = self._structural_function_name(focus, code_fact_items)
            if not function_name:
                warnings.append(
                    PacketWarning(
                        WARN_CBM_STRUCTURAL,
                        "caller/dependency evidence needs a resolved symbol; "
                        "continue with native symbol navigation",
                    )
                )
            else:
                direction = self._structural_direction(request.task)
                result = self.linkage.trace_relationships(
                    function_name=function_name,
                    direction=direction,
                    max_hops=2,
                    limit=g.max_structural_relationships,
                )
                if result.get("evidence") is not None:
                    evidence = result["evidence"]
                    items.append(
                        self._structural_item(
                            project_id=project_id,
                            kind="bounded_path",
                            result=result,
                            payload=evidence,
                            why=f"bounded CBM relationships (direction={direction})",
                        )
                    )
                else:
                    warnings.append(
                        PacketWarning(
                            WARN_CBM_STRUCTURAL,
                            result.get("warning")
                            or "optional CBM relationship evidence was omitted",
                        )
                    )
        if len(items) > g.max_structural_facts:
            omitted["code_facts"] += len(items) - g.max_structural_facts
            items = items[: g.max_structural_facts]
        return items

    @staticmethod
    def _structural_direction(task: Optional[str]) -> str:
        tokens = set(_TASK_TOKEN_RE.findall((task or "").casefold()))
        inbound = bool(tokens & {"caller", "callers"})
        outbound = bool(
            tokens & {"callee", "callees", "dependency", "dependencies"}
        )
        if inbound and not outbound:
            return "inbound"
        if outbound and not inbound:
            return "outbound"
        return "both"

    @staticmethod
    def _structural_function_name(focus, code_fact_items) -> Optional[str]:
        # Traversal is allowed only for the explicitly resolved focus. The
        # ambiguous path intentionally creates several code facts, but none
        # of those candidates is a safe traversal target.
        if not isinstance(focus, dict):
            return None
        if focus.get("resolution_state") not in (RESOLVED, STALE):
            return None
        qn = str(focus.get("qualified_name") or "").strip()
        slug = str(focus.get("cbm_project_name") or "").strip()
        if qn and slug:
            return f"{slug}.{qn}"
        for item in code_fact_items:
            data = item.data
            if data.get("resolution_state") not in (RESOLVED, STALE):
                continue
            if str(data.get("qualified_name") or "").strip() != qn:
                continue
            slug = str(item.provenance.cbm_project_name or "").strip()
            if qn and slug:
                return f"{slug}.{qn}"
        return None

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
        # Legacy direct-builder callers do not pay for or observe R4D
        # authority. Agent-facing reads negotiate explainability and receive
        # one native CBM attestation shared by every code item in this build.
        cbm_authority = (
            self.linkage.code_evidence_authority()
            if request.include_explain
            else {}
        )

        if mode == "file":
            ref = self._file_ref(request, project_id, workspace_id)
            focus = {"reference_kind": "file", "file_path": ref.file_path}
            resolution, adapter_failed = self._resolve_focus(ref, warnings)
            if not adapter_failed:
                self._resolution_warning(resolution, warnings)
            code_ref_items.append(
                self._code_ref_item(ref, resolution, mode, cbm_authority)
            )
            fact = self._fact_item(
                resolution.candidate, resolution.state, snip_stats,
                snippet_ref=None, cbm_authority=cbm_authority,
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
                    "cbm_project_name": ref.cbm_project_name,
                }
                resolution, adapter_failed = self._resolve_focus(ref, warnings)
                focus["resolution_state"] = resolution.state
                if not adapter_failed:
                    self._resolution_warning(resolution, warnings)
                code_ref_items.append(
                    self._code_ref_item(ref, resolution, mode, cbm_authority)
                )
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
                    snippet_ref=snippet_ref, cbm_authority=cbm_authority,
                )
                if fact is not None:
                    code_fact_items.append(fact)
            for candidate in extra_candidates:
                if len(code_fact_items) >= g.max_code_refs:
                    omitted["code_facts"] += 1
                    continue
                fact = self._fact_item(
                    candidate.to_dict(), AMBIGUOUS, snip_stats,
                    snippet_ref=None, cbm_authority=cbm_authority,
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
    def _code_ref_item(ref, resolution, mode, cbm_authority=None) -> PacketItem:
        data = {
            "reference": ref.to_dict(),
            "resolution_state": resolution.state,
            "note": resolution.note,
        }
        data.update(cbm_authority or {})
        return PacketItem(
            data=data,
            provenance=Provenance(
                source="cbm" if resolution.state != MISSING else "relinkra",
                why_included=f"focused {ref.reference_kind} (mode={mode})",
                code_reference_id=ref.code_reference_id,
                workspace_id=ref.workspace_id,
                cbm_project_name=ref.cbm_project_name,
                resolution_state=resolution.state,
            ),
        )

    def _fact_item(
        self, candidate, state, snip_stats, snippet_ref, cbm_authority=None
    ):
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
        data.update(cbm_authority or {})
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
