"""Relinkra application services — the agent-facing control plane (R3).

This layer is what the MCP transport calls. It owns orchestration and
NOTHING else: identity resolution, memory policy, linkage, context
composition, budgeting, relevance, git intelligence, and handoffs all
stay in their existing R1/R2 modules and are merely sequenced here.

Two rules keep the layering honest:

- No business logic in the MCP handlers. They validate, call one method
  here, and serialize the typed result.
- No duplicated R1E/R1F/R1G logic here. ``context_get`` runs the SAME
  build -> relevance -> budget -> portable pipeline the R1E CLI runs; it
  does not re-implement selection, ranking, or shedding.

Degradation follows the R1E philosophy: one failing subsystem produces a
typed warning and a partial result, never an exception that takes down an
unrelated tool.
"""

from __future__ import annotations

import os
import shutil
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import __version__, cbm_support
from .cbm_adapter import (
    ARCHITECTURE_MAX_LIMIT,
    CBMAdapterError,
    CBMCLIAdapter,
    TRACE_MAX_DEPTH,
    TRACE_MAX_LIMIT,
)
from .code_reference import CodeRefError, normalize_repo_path
from .context_budget import (
    BudgetValidationError,
    apply_budget,
    resolve_budget,
)
from .context_builder import (
    ContextBuildError,
    ContextBuilder,
    ContextRequest,
    _utcnow,
)
from .context_packet import (
    PACKET_VERSION,
    PACKET_VERSION_V1,
    strip_portable_cbm_labels,
)
from .explainability import attach_budget, attach_relevance, explain_record
from .freshness import (
    FreshnessContext,
    RevisionRelation,
    RevisionRelationState,
)
from .engram_adapter import EngramCLIAdapter
from .git_intelligence import (
    GIT_DEFAULT_COMMITS,
    GitError,
    GitIntelligenceService,
)
from .handoff import (
    HANDOFF_VERSION,
    HandoffError,
    HandoffService,
    HandoffValidationError,
    scrub_absolute_paths,
)
from .identity import AmbiguousIdentityError
from .identity import GitError as IdentityGitError
from .identity import discover_repository_identity
from .memory import (
    ENVELOPE_VERSION,
    MEMORY_TYPES,
    SCOPES,
    MemoryError,
    MemoryService,
    MemoryValidationError,
    sanitize_error,
)
from .linkage import LinkageService
from .registry import DEFAULT_REGISTRY_PATH, Registry, RegistryError
from .relevance import RELEVANCE_VERSION, RelevanceError, score_packet

CONTRACT_VERSION = "relinkra.mcp/v1"

#: Typed error codes. The MCP layer maps these onto JSON-RPC errors; the
#: set is closed so a client can branch on them.
ERR_INVALID_INPUT = "invalid_input"
ERR_NOT_FOUND = "not_found"
ERR_PROJECT_MISMATCH = "project_mismatch"
ERR_UNAVAILABLE = "unavailable"
ERR_INTERNAL = "internal_error"


def sanitize_wire_text(text: str) -> str:
    """Make free-form text safe to put on the wire.

    ``sanitize_error`` removes credentials but NOT paths, and the text
    that reaches an agent is frequently an underlying error message that
    embeds one — ``engram executable not found: C:\\Users\\me\\...`` is a
    real example from a misconfigured binary. Every free-text field this
    layer emits therefore goes through BOTH filters: redact secrets, then
    replace machine-local absolute paths.
    """
    return scrub_absolute_paths(sanitize_error(text or ""))


class ServiceError(Exception):
    """A typed, already-sanitized application error."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = sanitize_wire_text(message)

    def to_dict(self) -> dict:
        return {"error": {"code": self.code, "message": self.message}}


@dataclass
class ServiceWarning:
    """A non-fatal degradation surfaced to the caller.

    Same {code, message} shape as PacketWarning (R1E) and GitWarning
    (R2); named for its layer, matching that convention.
    """

    code: str
    message: str

    def to_dict(self) -> dict:
        return {"code": self.code, "message": sanitize_wire_text(self.message)}


@dataclass
class ServiceConfig:
    """Server-owned configuration.

    Paths live HERE, never in tool arguments. An agent cannot ask
    Relinkra to read an arbitrary directory: filesystem and git reach are
    bounded by what the operator configured at startup.
    """

    workspace_root: Optional[str] = None
    registry_path: str = DEFAULT_REGISTRY_PATH
    engram_bin: str = "engram"
    engram_project_alias: Optional[str] = None
    cbm_bin: Optional[str] = None
    cbm_cache_dir: Optional[str] = None
    cbm_project_name: Optional[str] = None
    default_project_id: Optional[str] = None
    default_workspace_id: Optional[str] = None
    git_history_limit: int = GIT_DEFAULT_COMMITS


@dataclass
class _Probe:
    """Availability of one underlying engine."""

    available: Optional[bool]
    detail: str = ""
    checked: bool = True
    state: Optional[str] = None

    def resolved_state(self) -> str:
        if self.state:
            return self.state
        if not self.checked:
            return "unprobed"
        return "available" if self.available else "unavailable"

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "checked": self.checked,
            "state": self.resolved_state(),
            "detail": sanitize_wire_text(self.detail),
        }


#: Minimum seconds between two real CBM liveness probes per services
#: instance. ``health(deep=True)`` spawns a bounded subprocess, and the
#: MCP surface lets any connected agent request it — the TTL caps that
#: trigger rate without weakening the default cheap probe.
DEEP_CBM_PROBE_TTL_SECONDS = 60.0


@dataclass
class RelinkraServices:
    """Facade over the R1/R2 domain modules."""

    config: ServiceConfig = field(default_factory=ServiceConfig)
    store: Any = None
    cbm_adapter: Any = None
    git_service: Any = None
    registry: Any = None
    clock: Any = None

    def __post_init__(self) -> None:
        if self.store is None:
            self.store = EngramCLIAdapter(
                engram_bin=self.config.engram_bin,
                project_alias=self.config.engram_project_alias,
            )
        clock = self.clock or _utcnow
        self.memories = MemoryService(self.store, clock=clock)
        self.handoffs = HandoffService(self.memories, clock=clock)
        self._cbm_config_error = ""
        if self.git_service is None:
            self.git_service = GitIntelligenceService()
        if self.cbm_adapter is None and self.config.cbm_bin:
            # Production wiring receives exactly the doctor trust policy;
            # injected adapters above stay available as deliberate test seams.
            record = {
                "project_name": self.config.cbm_project_name,
                "cache_dir": self.config.cbm_cache_dir,
            }
            try:
                self.cbm_adapter = cbm_support.certify_configured_adapter(
                    self.config.workspace_root or "",
                    record,
                    self.config.cbm_bin,
                    adapter_factory=CBMCLIAdapter,
                )
            except Exception as exc:
                # CBM is optional. A failed trust gate degrades code resolution
                # rather than preventing the server from starting.
                self.cbm_adapter = None
                self._cbm_config_error = (
                    sanitize_wire_text(str(exc))
                    or "CBM trust verification failed"
                )
        self._registry_error: Optional[str] = None
        if self.registry is None:
            self.registry = self._load_registry()

    # -- infrastructure ---------------------------------------------------

    def _load_registry(self) -> Optional[Registry]:
        path = self.config.registry_path
        if not path or not os.path.exists(path):
            return None
        try:
            return Registry(path)
        except RegistryError as exc:
            # A RegistryError commonly embeds the registry file path.
            self._registry_error = sanitize_wire_text(str(exc))
            return None

    def _now(self) -> str:
        return (self.clock or _utcnow)()

    def _builder(self) -> ContextBuilder:
        kwargs: Dict[str, Any] = {}
        if self.clock is not None:
            kwargs["clock"] = self.clock
        return ContextBuilder(
            memory_service=self.memories,
            cbm_adapter=self.cbm_adapter,
            registry=self.registry,
            workspace_root=self.config.workspace_root,
            git_service=self.git_service,
            **kwargs,
        )

    def _freshness_context(self, project_id: str) -> tuple[FreshnessContext, Any]:
        """Bounded current-Git context for read-side R4D tool metadata."""
        current_revision = None
        dirty = None
        root = self.config.workspace_root
        if root:
            try:
                state, _warnings = self.git_service.collect_repository_state(root)
                if state is not None:
                    current_revision = state.head_sha
                    dirty = not state.clean
            except Exception:
                # Git is advisory on memory/handoff/code read surfaces.
                # Unexpected adapter/runtime details are neither evidence nor
                # safe portable output, so fail closed to UNKNOWN locally.
                pass
        context = FreshnessContext(
            as_of=self._now(),
            project_id=project_id,
            current_revision=current_revision,
            dirty=dirty,
        )
        resolver = None
        if root and hasattr(self.git_service, "collect_revision_relation"):
            def resolver(evidence, current):
                try:
                    return self.git_service.collect_revision_relation(
                        root, evidence, current
                    )
                except Exception:
                    return RevisionRelation(
                        RevisionRelationState.UNAVAILABLE,
                        reason="revision relation resolver failed",
                    )
        return context, resolver

    def _resolve_project_id(self, project_id: Optional[str]) -> str:
        """Resolve project identity for one tool call.

        Resolution order: explicit argument -> configured server default
        -> deterministic discovery from the bound workspace context. An
        explicit value is honored verbatim and never replaced — even an
        unregistered one keeps its existing per-tool semantics.

        Auto-resolution applies ONLY when both the argument and the
        configured default are absent, and fails closed with a typed,
        actionable ServiceError when the workspace cannot be matched to
        exactly one registered project.
        """
        resolved = (project_id or self.config.default_project_id or "").strip()
        if resolved:
            return resolved
        return self._auto_resolve_project_id()

    def _auto_resolve_project_id(self) -> str:
        """Derive the current project from the bound workspace context.

        Uses the same discovery machinery ``project_resolve`` uses — the
        server-owned workspace root and registry, never a caller-supplied
        path — narrowed to a strict single-match contract: zero matches
        and multiple matches both fail closed instead of guessing, so
        auto-resolution can never bind another repository's identity.
        """
        if not self.config.workspace_root:
            raise ServiceError(
                ERR_NOT_FOUND,
                "project_id could not be auto-resolved: this server was "
                "launched without --workspace-root, so there is no "
                "workspace context; pass an explicit project_id",
            )
        if self.registry is None:
            detail = f": {self._registry_error}" if self._registry_error else ""
            raise ServiceError(
                ERR_NOT_FOUND,
                "project_id could not be auto-resolved: the project "
                f"registry is unavailable{detail}; pass an explicit "
                "project_id or call project_resolve",
            )
        discovered, discovery_warning = self._discover_identity()
        if discovered is None:
            reason = (
                discovery_warning.message
                if discovery_warning is not None
                else "unknown discovery failure"
            )
            raise ServiceError(
                ERR_NOT_FOUND,
                "project_id could not be auto-resolved: repository "
                f"identity discovery failed ({reason}); pass an explicit "
                "project_id or call project_resolve",
            )
        matches = [
            project
            for project in self.registry.projects.values()
            if project.repository_identity.value == discovered.value
        ]
        if len(matches) == 1:
            return matches[0].project_id
        if len(matches) > 1:
            raise ServiceError(
                ERR_NOT_FOUND,
                "project_id could not be auto-resolved: "
                f"{len(matches)} registered projects share this "
                "repository identity; pass an explicit project_id",
            )
        raise ServiceError(
            ERR_NOT_FOUND,
            "project_id could not be auto-resolved: the current workspace "
            "does not match any registered Relinkra project; register it "
            "(relinkra connect), pass an explicit project_id, or call "
            "project_resolve for diagnostics",
        )

    def _resolve_workspace_id(
        self, workspace_id: Optional[str]
    ) -> Optional[str]:
        return (
            workspace_id or self.config.default_workspace_id or ""
        ).strip() or None

    def _repository_identity(self, project_id: str) -> dict:
        """The repository identity a write must be bound to.

        Sourced from the registry, never from tool arguments: letting a
        caller pass its own identity would let one project's memory be
        written under another project's provenance.
        """
        if self.registry is not None:
            project = self.registry.projects.get(project_id)
            if project is not None:
                return project.repository_identity.to_dict()
        raise ServiceError(
            ERR_NOT_FOUND,
            f"project is not registered: {project_id}",
        )

    # -- tools ------------------------------------------------------------

    def project_resolve(
        self,
        *,
        project_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> dict:
        """Resolve the logical project identity for this server.

        Resolution order: explicit project_id -> configured default ->
        discovery from the configured workspace root. Discovery never
        accepts a caller-supplied path.
        """
        warnings: List[ServiceWarning] = []
        if self._registry_error:
            warnings.append(
                ServiceWarning("registry_unavailable", self._registry_error)
            )

        wanted = (project_id or self.config.default_project_id or "").strip()
        workspace_id = self._resolve_workspace_id(workspace_id)

        project = None
        if self.registry is not None and wanted:
            project = self.registry.projects.get(wanted)

        discovered = None
        if project is None and self.registry is not None:
            discovered, discovery_warning = self._discover_identity()
            if discovery_warning is not None:
                warnings.append(discovery_warning)
            if discovered is not None:
                project = self.registry.find_project_by_identity(discovered)

        if project is None:
            raise ServiceError(
                ERR_NOT_FOUND,
                "no registered project resolved; register a workspace first",
            )

        workspace = None
        if workspace_id and self.registry is not None:
            workspace = self.registry.get_workspace(workspace_id)
            if workspace is None:
                warnings.append(
                    ServiceWarning(
                        "workspace_not_registered",
                        f"unknown workspace_id: {workspace_id}",
                    )
                )
            elif workspace.project_id != project.project_id:
                raise ServiceError(
                    ERR_PROJECT_MISMATCH,
                    "workspace_id belongs to a different project",
                )

        payload = {
            "project_id": project.project_id,
            "display_name": project.display_name,
            "repository_identity": project.repository_identity.to_dict(),
            "workspace_id": workspace.workspace_id if workspace else None,
            "resolved_from": "registry" if wanted else "discovery",
            "warnings": [w.to_dict() for w in warnings],
        }
        if workspace is not None:
            git_info = dict(workspace.git or {})
            # Field-by-field on purpose: Workspace also carries
            # absolute_path/canonical_path, which are machine-local and
            # must never reach portable output. Never dump to_dict().
            payload["workspace"] = {
                "workspace_id": workspace.workspace_id,
                "os_family": workspace.os,
                "branch": git_info.get("branch"),
                "head_sha": git_info.get("head_sha"),
            }
        return payload

    def _discover_identity(self):
        root = self.config.workspace_root
        if not root:
            return None, ServiceWarning(
                "workspace_root_unset",
                "no workspace root is configured for discovery",
            )
        try:
            return discover_repository_identity(root), None
        except (IdentityGitError, AmbiguousIdentityError, ValueError) as exc:
            return None, ServiceWarning("discovery_failed", str(exc))

    def context_get(
        self,
        *,
        project_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        task: Optional[str] = None,
        file: Optional[str] = None,
        symbol: Optional[str] = None,
        requesting_agent: str = "",
        include_git: bool = True,
        budget: Optional[str] = None,
        max_tokens: Optional[int] = None,
        rank: bool = True,
        format: str = "json",
    ) -> dict:
        """Compose one portable Project Context Packet.

        Pipeline (unchanged from R1E/R1F/R1G, merely sequenced):
        build -> relevance -> budget -> portable serialization.
        Handoffs enter through the SAME R1E memory selection every other
        memory type uses, because a handoff is persisted as a handoff
        memory. Nothing about handoffs is special-cased here.
        """
        project_id = self._resolve_project_id(project_id)
        workspace_id = self._resolve_workspace_id(workspace_id)
        if format not in ("json", "markdown"):
            raise ServiceError(
                ERR_INVALID_INPUT, "format must be 'json' or 'markdown'"
            )

        request = ContextRequest(
            project_id=project_id,
            workspace_id=workspace_id,
            task=task,
            file=file,
            symbol=symbol,
            requesting_agent=requesting_agent or "",
            # AGENT_PRIVATE is never reachable through the MCP surface.
            # The control plane is a cross-agent channel by definition.
            include_agent_private=False,
            include_git=bool(include_git),
            include_explain=True,
            git_history_limit=self.config.git_history_limit,
        )

        try:
            packet = self._builder().build(request)
        except ContextBuildError as exc:
            code = (
                ERR_PROJECT_MISMATCH
                if getattr(exc, "exit_code", 1) == 2
                else ERR_INVALID_INPUT
            )
            raise ServiceError(code, str(exc)) from exc
        except (MemoryError, ValueError) as exc:
            raise ServiceError(ERR_INVALID_INPUT, str(exc)) from exc

        ranked = None
        if rank:
            focus = packet.focus or {}
            focus_symbol = None
            if symbol and not str(symbol).strip().startswith("{"):
                focus_symbol = str(symbol).strip()
            elif focus.get("reference_kind") == "symbol":
                focus_symbol = focus.get("qualified_name")
            focus_ref_id = None
            if packet.code_references:
                focus_ref_id = packet.code_references[0].provenance.code_reference_id
            try:
                ranked = score_packet(
                    packet,
                    task=task,
                    focus_file=file or focus.get("file_path"),
                    focus_symbol=focus_symbol,
                    focus_code_reference_id=focus_ref_id,
                    workspace_id=workspace_id,
                    as_of=self._now(),
                )
            except RelevanceError as exc:
                raise ServiceError(ERR_INVALID_INPUT, str(exc)) from exc
            attach_relevance(packet, ranked)

        budget_report = None
        if budget is not None or max_tokens is not None:
            try:
                resolved = resolve_budget(profile=budget, max_tokens=max_tokens)
                result = apply_budget(packet, resolved, relevance=ranked)
            except BudgetValidationError as exc:
                raise ServiceError(ERR_INVALID_INPUT, str(exc)) from exc
            if not result.satisfied:
                raise ServiceError(
                    ERR_INVALID_INPUT,
                    "budget_unsatisfiable: the essential packet exceeds "
                    f"max_estimated_tokens={resolved.max_estimated_tokens}",
                )
            packet = result.packet
            if ranked is not None:
                packet.diagnostics["relevance"] = {
                    "ranked": True,
                    "relevance_version": RELEVANCE_VERSION,
                    "as_of": ranked.as_of,
                }
            attach_budget(packet, result.decisions)
            result.reconcile_final_packet(packet)
            if not result.satisfied:
                raise ServiceError(
                    ERR_INVALID_INPUT,
                    "budget_unsatisfiable: the final packet metadata exceeds "
                    f"max_estimated_tokens={resolved.max_estimated_tokens}",
                )
            budget_report = result.to_portable_dict()
            # The report embeds the bounded packet, which this response
            # already returns under "packet". Shipping both would double
            # the payload — self-defeating on a surface whose entire
            # purpose is respecting a token budget.
            budget_report.pop("packet", None)

        if ranked is not None and budget_report is None:
            packet.diagnostics["relevance"] = {
                "ranked": True,
                "relevance_version": RELEVANCE_VERSION,
                "as_of": ranked.as_of,
            }

        payload: Dict[str, Any] = {
            "packet_version": packet.packet_version,
            "packet_id": packet.packet_id,
            "project_id": packet.project_id,
        }
        if format == "markdown":
            payload["markdown"] = packet.to_markdown()
        else:
            payload["packet"] = strip_portable_cbm_labels(packet.to_portable_dict())
        if budget_report is not None:
            payload["budget_report"] = budget_report
        return payload

    def memory_search(
        self,
        *,
        project_id: Optional[str] = None,
        query: Optional[str] = None,
        memory_type: Optional[str] = None,
        workspace_id: Optional[str] = None,
        include_history: bool = False,
        limit: int = 20,
    ) -> dict:
        """Search shared project memory under the R1C scope policy."""
        project_id = self._resolve_project_id(project_id)
        workspace_id = self._resolve_workspace_id(workspace_id)
        if memory_type and memory_type not in MEMORY_TYPES:
            raise ServiceError(
                ERR_INVALID_INPUT, f"unsupported memory_type: {memory_type}"
            )
        try:
            limit = int(limit)
        except (TypeError, ValueError) as exc:
            raise ServiceError(ERR_INVALID_INPUT, "limit must be an integer") from exc
        limit = max(1, min(limit, 100))

        # Never agent_private: the MCP surface is a cross-agent channel.
        scope = "workspace_local" if workspace_id else "project_shared"
        try:
            result = self.memories.query(
                project_id=project_id,
                scope=scope,
                workspace_id=workspace_id,
                text=query,
                memory_type=memory_type,
                include_history=bool(include_history),
                limit=limit,
            )
        except MemoryValidationError as exc:
            raise ServiceError(ERR_INVALID_INPUT, str(exc)) from exc
        except MemoryError as exc:
            raise ServiceError(ERR_UNAVAILABLE, str(exc)) from exc

        freshness_context, relation_resolver = self._freshness_context(project_id)
        explained_memories = []
        for memory in result.memories:
            record = memory.to_dict()
            record["explain"] = explain_record(
                "memory",
                {
                    "timestamp": record.get("timestamp"),
                    "commit_sha": record.get("commit_sha"),
                    "project_id": record.get("project_id"),
                },
                context=freshness_context,
                relation_resolver=relation_resolver,
            )
            explained_memories.append(record)
        return {
            "project_id": project_id,
            "count": len(result.memories),
            "skipped_malformed": result.skipped_malformed,
            "memories": explained_memories,
            "explainability": {
                "as_of": freshness_context.as_of,
                "advisory_only": True,
                "current_revision": freshness_context.current_revision,
            },
        }

    def memory_save(
        self,
        *,
        project_id: Optional[str] = None,
        memory_type: str = "",
        title: str = "",
        body: str = "",
        scope: str = "project_shared",
        workspace_id: Optional[str] = None,
        agent_id: str = "",
        confidence: Optional[float] = None,
        code_refs: Any = None,
    ) -> dict:
        """Save one memory through the R1C policy layer."""
        project_id = self._resolve_project_id(project_id)
        workspace_id = self._resolve_workspace_id(workspace_id)
        if memory_type not in MEMORY_TYPES:
            raise ServiceError(
                ERR_INVALID_INPUT, f"unsupported memory_type: {memory_type}"
            )
        if scope not in SCOPES:
            raise ServiceError(ERR_INVALID_INPUT, f"unsupported scope: {scope}")
        if scope == "agent_private":
            # Writing a private memory through a shared control plane
            # would create context no other agent can see but that this
            # surface implies is shared. Refuse rather than mislead.
            raise ServiceError(
                ERR_INVALID_INPUT,
                "agent_private scope is not writable through the MCP surface",
            )
        repository_identity = self._repository_identity(project_id)
        try:
            memory, deduplicated, superseded = self.memories.save(
                project_id=project_id,
                memory_type=memory_type,
                title=title,
                body=body,
                repository_identity=repository_identity,
                scope=scope,
                workspace_id=workspace_id,
                agent_id=agent_id or "",
                agent_type="",
                confidence=confidence,
                source_tool="relinkra",
                code_refs=code_refs,
            )
        except (MemoryValidationError, CodeRefError) as exc:
            raise ServiceError(ERR_INVALID_INPUT, str(exc)) from exc
        except MemoryError as exc:
            raise ServiceError(ERR_UNAVAILABLE, str(exc)) from exc

        return {
            "memory_id": memory.memory_id,
            "project_id": memory.project_id,
            "memory_type": memory.memory_type,
            "scope": memory.scope,
            "topic_key": memory.topic_key,
            "deduplicated": deduplicated,
            "superseded": list(superseded),
        }

    def code_resolve(
        self,
        *,
        project_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        file: Optional[str] = None,
        symbol: Optional[str] = None,
    ) -> dict:
        """Resolve a file/symbol to a portable CodeReference via R1D."""
        project_id = self._resolve_project_id(project_id)
        workspace_id = self._resolve_workspace_id(workspace_id)
        if not (file or symbol):
            raise ServiceError(
                ERR_INVALID_INPUT, "one of file or symbol is required"
            )
        # Reuse the R1E code-focus path rather than re-deriving symbol
        # lookup here: the builder already owns candidate search, the
        # ambiguity rules, and CBM-outage degradation. Duplicating any of
        # that would let the two paths drift apart.
        request = ContextRequest(
            project_id=project_id,
            workspace_id=workspace_id,
            file=file,
            symbol=symbol,
            include_agent_private=False,
            # Git facts remain private to this composition pass but let R4D
            # compare revision-bound CBM/memory evidence to the checkout.
            include_git=True,
            include_explain=True,
        )
        try:
            packet = self._builder().build(request)
        except ContextBuildError as exc:
            code = (
                ERR_PROJECT_MISMATCH
                if getattr(exc, "exit_code", 1) == 2
                else ERR_INVALID_INPUT
            )
            raise ServiceError(code, str(exc)) from exc
        except (MemoryError, CodeRefError, ValueError) as exc:
            raise ServiceError(ERR_INVALID_INPUT, str(exc)) from exc

        references = [
            strip_portable_cbm_labels(item.to_dict())
            for item in packet.code_references
        ]
        facts = [
            strip_portable_cbm_labels(item.to_dict())
            for item in packet.code_facts
        ]
        state = None
        if packet.code_references:
            state = packet.code_references[0].data.get("resolution_state")

        return strip_portable_cbm_labels({
            "project_id": project_id,
            "focus": packet.focus,
            "resolution_state": state,
            "code_references": references,
            "code_facts": facts,
            "linked_memories": [
                item.to_dict() for item in packet.memories
            ],
            "warnings": [w.to_dict() for w in packet.warnings],
            "contradictions": packet.contradictions,
            "explainability": packet.explainability,
        })

    def code_architecture(
        self,
        *,
        project_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        path: Optional[str] = None,
    ) -> dict:
        """Return compact optional architecture evidence, never raw CBM."""
        project_id = self._resolve_project_id(project_id)
        self._resolve_workspace_id(workspace_id)
        normalized_path = None
        if path:
            try:
                normalized_path = normalize_repo_path(path)
            except CodeRefError as exc:
                raise ServiceError(ERR_INVALID_INPUT, str(exc)) from exc
        result = LinkageService(self.memories, self.cbm_adapter).architecture_orientation(
            path=normalized_path, limit=min(5, ARCHITECTURE_MAX_LIMIT)
        )
        return self._structural_response(
            project_id, result, "architecture_fact", "architecture"
        )

    def code_relationships(
        self,
        *,
        project_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        symbol: str = "",
        direction: str = "both",
        max_hops: int = 2,
        limit: int = 20,
    ) -> dict:
        """Return high-level callers/dependencies for one resolved symbol."""
        project_id = self._resolve_project_id(project_id)
        self._resolve_workspace_id(workspace_id)
        symbol = str(symbol or "").strip()
        if not symbol:
            raise ServiceError(ERR_INVALID_INPUT, "symbol is required")
        direction = str(direction or "both").strip().lower()
        if direction not in ("inbound", "outbound", "both"):
            raise ServiceError(
                ERR_INVALID_INPUT,
                "direction must be inbound, outbound, or both",
            )
        if isinstance(max_hops, bool) or not isinstance(max_hops, int):
            raise ServiceError(ERR_INVALID_INPUT, "max_hops must be an integer")
        if not 1 <= max_hops <= TRACE_MAX_DEPTH:
            raise ServiceError(
                ERR_INVALID_INPUT,
                f"max_hops must be between 1 and {TRACE_MAX_DEPTH}",
            )
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ServiceError(ERR_INVALID_INPUT, "limit must be an integer")
        if not 1 <= limit <= TRACE_MAX_LIMIT:
            raise ServiceError(
                ERR_INVALID_INPUT,
                f"limit must be between 1 and {TRACE_MAX_LIMIT}",
            )

        linkage = LinkageService(self.memories, self.cbm_adapter)
        authority = linkage.structural_evidence_authority()
        if authority["freshness"]["state"] not in ("fresh", "stale"):
            return self._structural_response(
                project_id,
                {
                    "evidence": None,
                    "freshness": authority["freshness"],
                    "authority": authority["authority"],
                    "warning": authority["freshness"]["reason"],
                },
                "bounded_path",
                "relationships",
            )
        target, warning = self._resolve_structural_target(symbol)
        if target is None:
            return self._structural_response(
                project_id,
                {
                    "evidence": None,
                    "freshness": authority["freshness"],
                    "authority": authority["authority"],
                    "warning": warning,
                },
                "bounded_path",
                "relationships",
            )
        result = linkage.trace_relationships(
            function_name=target,
            direction=direction,
            max_hops=max_hops,
            limit=limit,
        )
        return self._structural_response(
            project_id, result, "bounded_path", "relationships"
        )

    def _resolve_structural_target(self, symbol: str):
        if self.cbm_adapter is None:
            return None, "optional CBM traversal is unavailable"
        query = symbol.rsplit(".", 1)[-1] or symbol
        try:
            candidates = self.cbm_adapter.search_symbols(query=query, limit=10)
        except Exception as exc:
            return None, sanitize_wire_text(str(exc))
        candidates = [c for c in candidates if isinstance(c, dict)]
        exact = [
            c
            for c in candidates
            if c.get("relative_qualified_name") == symbol
            or c.get("qualified_name") == symbol
        ]
        if len(exact) == 1:
            candidate = exact[0]
        elif len(candidates) == 1:
            candidate = candidates[0]
        elif not candidates:
            return None, (
                "symbol was not resolved in the current graph; native symbol "
                "navigation remains available"
            )
        else:
            return None, (
                "symbol is ambiguous in the current graph; use native symbol "
                "navigation to choose the intended target"
            )
        qualified_name = str(candidate.get("qualified_name") or "").strip()
        if not qualified_name:
            return None, "resolved symbol had no usable graph identity"
        return qualified_name, None

    @staticmethod
    def _structural_response(
        project_id: str, result: dict, kind: str, label: str
    ) -> dict:
        warnings = []
        if result.get("warning"):
            warnings.append(
                ServiceWarning(
                    "cbm_structural_unavailable", result["warning"]
                ).to_dict()
            )
        evidence = result.get("evidence")
        payload = {
            "project_id": project_id,
            "available": evidence is not None,
            "evidence_kind": kind,
            "freshness": result.get("freshness") or {
                "state": "unknown",
                "reason": "graph freshness was not provided",
            },
            "authority": result.get("authority") or {},
            "evidence": evidence,
            "warnings": warnings,
            "advisory_only": True,
            "native_tools_remain_available": True,
        }
        if evidence is not None:
            payload["evidence"] = dict(evidence)
        return strip_portable_cbm_labels(payload)

    def git_context(
        self,
        *,
        project_id: Optional[str] = None,
        file: Optional[str] = None,
        history_limit: Optional[int] = None,
        include_diff: bool = True,
    ) -> dict:
        """Read-only R2 git facts for the configured workspace root.

        The path is ALWAYS the server's configured root. Git is never
        pointed at a caller-supplied path, and every git call in R2 is
        read-only by construction.
        """
        project_id = self._resolve_project_id(project_id)
        root = self.config.workspace_root
        warnings: List[ServiceWarning] = []
        if not root:
            freshness_context = FreshnessContext(
                as_of=self._now(),
                project_id=project_id,
                current_revision=None,
                dirty=None,
            )
            return {
                "project_id": project_id,
                "available": False,
                "warnings": [
                    ServiceWarning(
                        "git_unavailable",
                        "no workspace root is configured",
                    ).to_dict()
                ],
                "explain": explain_record(
                    "git", {}, context=freshness_context
                ),
            }

        limit = history_limit or self.config.git_history_limit
        try:
            limit = max(1, min(int(limit), 100))
        except (TypeError, ValueError):
            limit = self.config.git_history_limit

        payload: Dict[str, Any] = {"project_id": project_id, "available": True}

        def _collect(name: str, fn, *args, **kwargs):
            try:
                value, git_warnings = fn(*args, **kwargs)
            except GitError as exc:
                warnings.append(ServiceWarning(f"git_{name}_failed", str(exc)))
                return None
            except Exception:
                warnings.append(
                    ServiceWarning(
                        f"git_{name}_failed",
                        "git operation failed unexpectedly",
                    )
                )
                return None
            for gw in git_warnings or ():
                warnings.append(ServiceWarning(gw.code, gw.message))
            return value

        state = _collect("state", self.git_service.collect_repository_state, root)
        if state is None:
            payload["available"] = False
            payload["warnings"] = [w.to_dict() for w in warnings]
            freshness_context = FreshnessContext(
                as_of=self._now(),
                project_id=project_id,
                current_revision=None,
                dirty=None,
            )
            payload["explain"] = explain_record(
                "git", {}, context=freshness_context
            )
            return payload
        payload["repository_state"] = state.to_dict()

        head = _collect("head", self.git_service.collect_head_facts, root)
        if head is not None:
            payload["head"] = head.to_dict()

        commits = _collect(
            "commits", self.git_service.collect_recent_commits, root, limit=limit
        )
        if commits is not None:
            payload["recent_commits"] = [c.to_dict() for c in commits]

        if include_diff:
            diff = _collect(
                "diff", self.git_service.collect_diff, root, include_snippets=False
            )
            if diff is not None:
                payload["diff"] = [d.to_dict() for d in diff]

        if file:
            history = _collect(
                "file_history",
                self.git_service.collect_file_history,
                root,
                file_path=file,
                limit=limit,
            )
            if history is not None:
                payload["file_history"] = [c.to_dict() for c in history]

        payload["warnings"] = [w.to_dict() for w in warnings]
        freshness_context = FreshnessContext(
            as_of=self._now(),
            project_id=project_id,
            current_revision=state.head_sha,
            dirty=not state.clean,
        )
        payload["explain"] = explain_record(
            "git",
            {"head_sha": state.head_sha},
            context=freshness_context,
        )
        return payload

    def handoff_create(
        self,
        *,
        project_id: Optional[str] = None,
        source_agent: str = "",
        task: str = "",
        workspace_id: Optional[str] = None,
        target_agent: Optional[str] = None,
        summary: Optional[str] = None,
        completed_work: Any = None,
        pending_work: Any = None,
        decisions: Any = None,
        warnings: Any = None,
        related_memory_ids: Any = None,
        related_code_reference_ids: Any = None,
        context_packet_id: Optional[str] = None,
        supersedes: Optional[str] = None,
        include_git_state: bool = True,
    ) -> dict:
        """Create a deterministic, portable, PROJECT_SHARED handoff."""
        project_id = self._resolve_project_id(project_id)
        workspace_id = self._resolve_workspace_id(workspace_id)
        repository_identity = self._repository_identity(project_id)

        service_warnings: List[ServiceWarning] = []
        git_state = None
        if include_git_state and not self.config.workspace_root:
            # The caller explicitly asked for git state. Dropping it
            # silently would violate the degradation contract, so say why
            # — the same way git_context does for this condition.
            service_warnings.append(
                ServiceWarning(
                    "git_unavailable",
                    "no workspace root is configured; git state omitted",
                )
            )
        if include_git_state and self.config.workspace_root:
            try:
                state, git_warnings = self.git_service.collect_repository_state(
                    self.config.workspace_root
                )
                git_state = state
                for gw in git_warnings or ():
                    service_warnings.append(ServiceWarning(gw.code, gw.message))
            except GitError as exc:
                service_warnings.append(ServiceWarning("git_unavailable", str(exc)))

        try:
            handoff, deduplicated, policy_warnings = self.handoffs.create(
                project_id=project_id,
                source_agent=source_agent,
                task=task,
                repository_identity=repository_identity,
                workspace_id=workspace_id,
                target_agent=target_agent,
                summary=summary,
                completed_work=completed_work,
                pending_work=pending_work,
                decisions=decisions,
                warnings=warnings,
                related_memory_ids=related_memory_ids,
                related_code_reference_ids=related_code_reference_ids,
                git_state=git_state,
                context_packet_id=context_packet_id,
                supersedes=supersedes,
            )
        except HandoffValidationError as exc:
            raise ServiceError(ERR_INVALID_INPUT, str(exc)) from exc
        except HandoffError as exc:
            raise ServiceError(ERR_INTERNAL, str(exc)) from exc
        except MemoryValidationError as exc:
            raise ServiceError(ERR_INVALID_INPUT, str(exc)) from exc
        except MemoryError as exc:
            raise ServiceError(ERR_UNAVAILABLE, str(exc)) from exc

        for message in policy_warnings:
            service_warnings.append(ServiceWarning("reference_dropped", message))

        return {
            "handoff": handoff.to_portable_dict(),
            "deduplicated": deduplicated,
            "warnings": [w.to_dict() for w in service_warnings],
        }

    def handoff_get(
        self,
        *,
        project_id: Optional[str] = None,
        handoff_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        target_agent: Optional[str] = None,
        include_history: bool = False,
        limit: int = 10,
    ) -> dict:
        """Fetch one handoff by id, or list the most recent ones."""
        project_id = self._resolve_project_id(project_id)
        workspace_id = self._resolve_workspace_id(workspace_id)
        try:
            if handoff_id:
                handoff = self.handoffs.get(
                    project_id=project_id, handoff_id=handoff_id
                )
                if handoff is None:
                    raise ServiceError(
                        ERR_NOT_FOUND, f"unknown handoff_id: {handoff_id}"
                    )
                record = handoff.to_portable_dict()
                freshness_context, relation_resolver = self._freshness_context(
                    project_id
                )
                record["explain"] = explain_record(
                    "handoff",
                    {
                        "observed_at": record.get("created_at"),
                        "source_revision": (record.get("git_state") or {}).get(
                            "head_sha"
                        ),
                        "project_id": record.get("project_id"),
                    },
                    context=freshness_context,
                    relation_resolver=relation_resolver,
                )
                return {
                    "project_id": project_id,
                    "handoff": record,
                }
            handoffs = self.handoffs.list(
                project_id=project_id,
                workspace_id=workspace_id,
                target_agent=target_agent,
                include_history=bool(include_history),
                limit=max(1, min(int(limit or 10), 50)),
            )
        except HandoffValidationError as exc:
            raise ServiceError(ERR_INVALID_INPUT, str(exc)) from exc
        except MemoryValidationError as exc:
            raise ServiceError(ERR_INVALID_INPUT, str(exc)) from exc
        except MemoryError as exc:
            raise ServiceError(ERR_UNAVAILABLE, str(exc)) from exc

        freshness_context, relation_resolver = self._freshness_context(project_id)
        records = []
        for handoff in handoffs:
            record = handoff.to_portable_dict()
            record["explain"] = explain_record(
                "handoff",
                {
                    "observed_at": record.get("created_at"),
                    "source_revision": (record.get("git_state") or {}).get(
                        "head_sha"
                    ),
                    "project_id": record.get("project_id"),
                },
                context=freshness_context,
                relation_resolver=relation_resolver,
            )
            records.append(record)
        return {
            "project_id": project_id,
            "count": len(handoffs),
            "handoffs": records,
        }

    def health(self, deep: bool = False) -> dict:
        """Report contract, engine availability, and degraded components.

        Never emits secrets or absolute machine paths: the workspace root
        is reported as a boolean, not a value.

        With ``deep=True`` the CBM probe issues a REAL bounded query
        instead of only checking configuration, so the report
        distinguishes "configured" from "callable" (checked=True).
        """
        engram = self._probe_engram()
        cbm = self._probe_cbm(deep=deep)
        git = self._probe_git()
        degraded = [
            name
            for name, probe in (
                ("engram", engram),
                ("cbm", cbm),
                ("git", git),
            )
            if probe.resolved_state() in {"unavailable", "stale", "degraded"}
        ]
        if self._registry_error or self.registry is None:
            degraded.append("registry")

        project_status = "unresolved"
        project_id = None
        try:
            resolved = self.project_resolve()
            project_status = "resolved"
            project_id = resolved["project_id"]
        except ServiceError:
            project_status = "unresolved"
        except Exception:
            # health() is the tool an operator reaches for when things
            # are already broken. It must report degradation, never
            # become another failure.
            project_status = "error"
            degraded.append("project_resolution")

        return {
            "status": "degraded" if degraded else "ok",
            "relinkra_version": __version__,
            "contract_version": CONTRACT_VERSION,
            "schema_versions": {
                "packet": PACKET_VERSION,
                "packet_legacy": PACKET_VERSION_V1,
                "memory_envelope": ENVELOPE_VERSION,
                "handoff": HANDOFF_VERSION,
                "relevance": RELEVANCE_VERSION,
            },
            "project": {
                "status": project_status,
                "project_id": project_id,
            },
            "components": {
                "engram": engram.to_dict(),
                "cbm": cbm.to_dict(),
                "git": git.to_dict(),
                "registry": _Probe(
                    available=self.registry is not None,
                    detail=self._registry_error or "",
                ).to_dict(),
            },
            "degraded": sorted(set(degraded)),
            # Each flag must describe something the server can actually
            # execute RIGHT NOW, not something it implements in principle.
            # Anything that needs a working memory write path is reported
            # against Engram's real availability, because advertising
            # "handoffs" while Engram is down would be a lie an agent
            # only discovers by failing.
            "capabilities": {
                "tools": True,
                # Degrades to a partial packet plus warnings rather than
                # failing, so it stays available even with engines down.
                "context_packets": True,
                "budgeting": True,
                "relevance_ranking": True,
                "memory_read": engram.available,
                "memory_write": engram.available,
                "handoffs": engram.available,
                "code_resolution": cbm.available if cbm.checked else None,
                "git_intelligence": git.available,
                # The generic deep probe proves the code index route, but
                # not each structural operation independently. Null means
                # unprobed, never a false negative.
                "code_architecture": (
                    None if cbm.resolved_state() == "unprobed" else cbm.available
                ),
                "code_relationships": (
                    None if cbm.resolved_state() == "unprobed" else cbm.available
                ),
                # Deliberate, permanent absences — not degradations.
                "agent_private_access": False,
                "git_write": False,
            },
            "capability_states": {
                "memory_read": engram.resolved_state(),
                "memory_write": engram.resolved_state(),
                "handoffs": engram.resolved_state(),
                "code_resolution": cbm.resolved_state(),
                "code_architecture": (
                    "unavailable"
                    if cbm.resolved_state() == "unavailable"
                    else "unprobed"
                ),
                "code_relationships": (
                    "unavailable"
                    if cbm.resolved_state() == "unavailable"
                    else "unprobed"
                ),
                "git_intelligence": git.resolved_state(),
            },
            # Capabilities whose backing component was NOT liveness-probed
            # this call. Listed explicitly so a caller can tell "verified
            # working" from "configured, unverified".
            "capabilities_unchecked": sorted(
                name
                for name, probe in (
                    ("memory_read", engram),
                    ("memory_write", engram),
                    ("handoffs", engram),
                    ("code_resolution", cbm),
                    ("git_intelligence", git),
                )
                if not probe.checked
            )
            + sorted(
                name
                for name in ("code_architecture", "code_relationships")
                if self.cbm_adapter is not None
            ),
            # Boolean, never the path itself.
            "workspace_root_configured": bool(self.config.workspace_root),
        }

    # -- probes -----------------------------------------------------------

    def _probe_engram(self) -> _Probe:
        # HTTP is a read accelerator only. Memory writes and handoffs still
        # execute through the Engram CLI, so a reachable HTTP endpoint must
        # not advertise the full capability set when that executable is
        # absent.
        if isinstance(self.store, EngramCLIAdapter) and not shutil.which(
            self.store.engram_bin
        ):
            return _Probe(
                available=False,
                detail=(
                    "Engram HTTP is read-only here; the Engram CLI is "
                    "required for memory writes and handoffs"
                ),
            )
        try:
            self.store.search_records(
                query=ENVELOPE_VERSION, project="rlk_" + "0" * 32, limit=1
            )
            return _Probe(available=True)
        except MemoryError as exc:
            return _Probe(available=False, detail=str(exc))
        except Exception as exc:
            return _Probe(available=False, detail=sanitize_wire_text(str(exc)))

    @staticmethod
    def _cbm_stat_identity(path: str) -> tuple:
        """Return opaque filesystem metadata for a CBM trust-cache input."""
        try:
            stat = os.stat(path)
        except OSError:
            return ("missing",)
        return (
            "present",
            stat.st_dev,
            stat.st_ino,
            stat.st_size,
            stat.st_mtime_ns,
            stat.st_ctime_ns,
        )

    def _deep_cbm_probe_identity(self) -> Optional[tuple]:
        """Fingerprint the local inputs that make a deep CBM PASS trustworthy.

        Production adapters expose the binary/cache/project attributes below.
        Injected test adapters need not expose them, in which case their
        existing per-instance TTL behavior remains unchanged.
        """
        adapter = self.cbm_adapter
        identities = []
        cbm_bin = getattr(adapter, "cbm_bin", None)
        if cbm_bin:
            identities.append(("binary", self._cbm_stat_identity(str(cbm_bin))))
            verifier = getattr(adapter, "_verify_binary", None)
            if callable(verifier):
                verifier()

        cache_dir = getattr(adapter, "cache_dir", None)
        project_name = getattr(adapter, "cbm_project_name", None)
        if cache_dir and project_name:
            database = os.path.join(str(cache_dir), f"{project_name}.db")
            identities.extend(
                (
                    ("database", self._cbm_stat_identity(database)),
                    ("database-wal", self._cbm_stat_identity(database + "-wal")),
                    ("database-shm", self._cbm_stat_identity(database + "-shm")),
                )
            )
        return tuple(identities) if identities else None

    def _probe_cbm(self, deep: bool = False) -> _Probe:
        """Configuration check by default — deliberately NOT liveness.

        A live CBM probe on every health request would shell out to the
        code indexer, which is too expensive for a status endpoint, so
        the default reports ``checked=False`` honestly rather than
        implying a verification that did not happen. ``deep=True``
        (doctor, explicit operator checks) pays for one bounded real
        query and reports ``checked=True`` with the actual outcome.
        """
        if self.cbm_adapter is None:
            return _Probe(
                available=False,
                detail=self._cbm_config_error or "no CBM adapter configured",
                checked=True,
            )
        if not deep:
            return _Probe(
                available=None,
                checked=False,
                detail="configured; not liveness-checked",
                state="unprobed",
            )
        cached = getattr(self, "_deep_cbm_probe", None)
        now = time.monotonic()
        if (
            cached is not None
            and now - cached[0] < DEEP_CBM_PROBE_TTL_SECONDS
        ):
            try:
                if self._deep_cbm_probe_identity() == cached[2]:
                    return cached[1]
            except Exception:
                # A certified binary must be re-verified before a prior
                # PASS can be reused. Fall through to the bounded query.
                pass
            self._deep_cbm_probe = None
        try:
            # A real, bounded graph query: an empty result set still
            # proves the binary, the cache, and the index are callable.
            self.cbm_adapter.search_symbols(query="relinkra_health_probe", limit=1)
            probe = _Probe(available=True, checked=True, detail="query probe succeeded")
        except Exception as exc:
            probe = _Probe(
                available=False,
                checked=True,
                detail=sanitize_wire_text(str(exc)),
            )
        try:
            identity = self._deep_cbm_probe_identity()
        except Exception:
            probe = _Probe(
                available=False,
                checked=True,
                detail="CBM executable identity verification failed",
            )
            identity = None
        self._deep_cbm_probe = (now, probe, identity)
        return probe

    def _probe_git(self) -> _Probe:
        root = self.config.workspace_root
        if not root:
            return _Probe(available=False, detail="no workspace root configured")
        try:
            capabilities, warnings = self.git_service.collect_capabilities(root)
        except GitError as exc:
            return _Probe(available=False, detail=str(exc))
        available = bool(getattr(capabilities, "git_available", False)) and bool(
            getattr(capabilities, "repository_detected", False)
        )
        detail = ""
        if warnings:
            detail = warnings[0].message
        return _Probe(available=available, detail=detail)
