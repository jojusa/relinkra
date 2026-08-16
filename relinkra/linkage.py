"""Memory<->code linkage service (R1D).

Resolves stored CodeReferences against a live CBM index and answers
both directions of the linkage query:

- memory -> code: the refs stored on a memory, each with a typed
  resolution state (``resolved`` | ``ambiguous`` | ``missing`` |
  ``stale``).
- code -> memory: active Relinkra memories directly linked to a file
  or symbol, enforcing the R1C scope/workspace/agent_private/lifecycle
  policy (superseded memories are excluded by default).

Resolution rules:

- Exact: ``cbm_project_name + "." + project-relative qualified_name``
  resolves uniquely via get_code_snippet.
- Unique search: exactly one live candidate for a short name.
- Ambiguous: multiple candidates -> all candidates returned, never a
  silent choice.
- Missing: no live candidate. The historical reference is preserved
  verbatim; symbol deletion never rewrites history.
- Stale: a candidate resolved, but file/line metadata drifted from the
  stored hint. The stored reference is still not rewritten.

The adapter is duck-typed: any object with ``search_symbols(...)`` and
``get_snippet(qualified_name)`` returning normalized candidate dicts
(see ``relinkra.cbm_adapter``) works. No adapter -> every ref reports
``missing`` with an explanatory note. A CONFIGURED adapter that fails
(timeout, crash, bad payload) is NOT "missing": the failure is
propagated as ``CBMAdapterError`` so callers can distinguish an outage
from a genuinely absent symbol.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, List, Mapping, Optional

from .cbm_adapter import CBMAdapterError
from .code_reference import (
    CodeRefError,
    CodeReference,
    derive_language,
    normalize_repo_path,
)
from .memory import (
    STORE_PAGE_LIMIT,
    MemoryNotFoundError,
    MemoryService,
    MemoryValidationError,
    sanitize_error,
    validate_project_id,
)

RESOLVED = "resolved"
AMBIGUOUS = "ambiguous"
MISSING = "missing"
STALE = "stale"
RESOLUTION_STATES = (RESOLVED, AMBIGUOUS, MISSING, STALE)
_GRAPH_REVISION_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")


@dataclass
class ResolvedReference:
    """A stored reference plus its live resolution state.

    ``reference`` is the historical stored ref, byte-for-byte as
    persisted. ``candidate`` is the live CBM-backed ref (for
    resolved/stale); ``candidates`` lists all live matches (for
    ambiguous). ``invalid_candidates`` lists live candidates that
    failed portable-identity validation (typed error per entry) so
    they are surfaced as counts/errors, never silently dropped.
    """

    reference: dict
    state: str
    candidate: Optional[dict] = None
    candidates: List[dict] = field(default_factory=list)
    note: str = ""
    invalid_candidates: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "reference": self.reference,
            "state": self.state,
            "candidate": self.candidate,
            "candidates": self.candidates,
            "note": self.note,
            "invalid_candidates": self.invalid_candidates,
        }


def _note_with_invalid(note: str, invalid: List[dict]) -> str:
    if not invalid:
        return note
    suffix = (
        f"{len(invalid)} invalid candidate(s) surfaced, not silently "
        "dropped (see invalid_candidates)"
    )
    return f"{note}; {suffix}" if note else suffix


def candidate_to_reference(
    candidate: dict,
    *,
    project_id: str,
    workspace_id: Optional[str] = None,
) -> CodeReference:
    """Build a CodeReference from a normalized CBM candidate dict."""
    rel_qn = (candidate.get("relative_qualified_name") or "").strip() or None
    kind = "symbol" if (rel_qn or candidate.get("name")) else "file"
    return CodeReference(
        project_id=project_id,
        workspace_id=workspace_id,
        reference_kind=kind,
        file_path=candidate["file_path"],
        symbol_name=candidate.get("name"),
        qualified_name=rel_qn,
        symbol_kind=candidate.get("label"),
        language=derive_language(candidate.get("file_path") or ""),
        start_line=candidate.get("start_line"),
        end_line=candidate.get("end_line"),
        cbm_project_name=candidate.get("cbm_project_name"),
    )


def _last_qn_segment(qualified_name: Optional[str]) -> Optional[str]:
    if not qualified_name:
        return None
    return qualified_name.rsplit(".", 1)[-1] or None


def _adapter_call(operation: str, func, *args, **kwargs):
    """Invoke one CBM adapter operation with typed failure propagation.

    Any exception is normalized to ``CBMAdapterError`` (an adapter
    outage), NEVER swallowed into an empty result: an outage must not
    masquerade as a genuinely missing symbol/file.
    """
    try:
        return func(*args, **kwargs)
    except CBMAdapterError:
        raise
    except Exception as exc:
        raise CBMAdapterError(
            f"cbm {operation} failed: {sanitize_error(str(exc))}"
        ) from exc


def _portable_cbm_authority(raw: Any) -> dict:
    """Allowlist one native CBM graph attestation for packet evidence.

    Adapter responses are infrastructure-owned.  Re-project them even when an
    injected adapter claims to be portable so roots, project slugs, credentials,
    host configuration, and trust-stage detail can never enter a packet.
    """
    if not isinstance(raw, Mapping):
        return {}
    has_index = "index_status" in raw
    has_stages = "trust_stages" in raw
    if not (has_index or has_stages):
        return {}

    result: dict = {}
    if has_index:
        index = raw.get("index_status")
        git_facts = index.get("git") if isinstance(index, Mapping) else None
        revision = (
            git_facts.get("head_sha")
            if isinstance(git_facts, Mapping)
            else None
        )
        revision = str(revision or "").strip()
        portable_git = {}
        if _GRAPH_REVISION_RE.fullmatch(revision):
            portable_git["head_sha"] = revision
        result["index_status"] = {"git": portable_git}

    graph_status = "WARN"
    stages = raw.get("trust_stages")
    if isinstance(stages, (list, tuple)):
        graph_statuses = []
        for stage in stages:
            if not isinstance(stage, Mapping):
                continue
            if str(stage.get("name") or "").strip().lower() != "cbm graph":
                continue
            graph_statuses.append(str(stage.get("status") or "").strip().upper())
        # A single PASS is trustworthy.  Conflicting duplicate attestations
        # are not: never collapse [PASS, WARN] into synthetic PASS.
        if graph_statuses and all(status == "PASS" for status in graph_statuses):
            graph_status = "PASS"
    result["trust_stages"] = [
        {"name": "CBM graph", "status": graph_status}
    ]
    return result


class LinkageService:
    """Resolution and query service over a MemoryService + CBM adapter."""

    def __init__(self, memory_service: MemoryService, cbm_adapter: Any = None):
        self.memories = memory_service
        self.cbm = cbm_adapter

    def code_evidence_authority(self) -> dict:
        """Read the adapter's optional native graph attestation safely.

        Attestation is additive: legacy adapters without the capability keep
        resolving code exactly as before, while R4D freshness remains UNKNOWN.
        A failed authority probe never turns a usable symbol lookup into an
        outage and never borrows trust from copied result metadata.
        """
        provider = getattr(self.cbm, "code_evidence_authority", None)
        if not callable(provider):
            return {}
        try:
            raw = provider()
        except Exception:
            return {}
        return _portable_cbm_authority(raw)

    def structural_evidence_authority(self) -> dict:
        """Project CBM graph authority into a compact structural contract.

        Structural reads are advisory.  A PASS graph is ``fresh``; the
        existing stale-index/worktree-drift warnings are classified as
        ``stale``; all other missing or malformed authority is ``unknown``.
        Raw adapter details never cross this boundary.
        """
        provider = getattr(self.cbm, "code_evidence_authority", None)
        if not callable(provider):
            return {
                "freshness": {
                    "state": "unknown",
                    "reason": "graph authority is unavailable",
                },
                "authority": {},
            }
        try:
            raw = provider()
        except Exception:
            return {
                "freshness": {
                    "state": "unknown",
                    "reason": "graph authority could not be verified",
                },
                "authority": {},
            }
        projected = _portable_cbm_authority(raw)
        stages = raw.get("trust_stages") if isinstance(raw, Mapping) else []
        graph_stage = None
        if isinstance(stages, (list, tuple)):
            for stage in stages:
                if not isinstance(stage, Mapping):
                    continue
                if str(stage.get("name") or "").strip().lower() == "cbm graph":
                    graph_stage = stage
                    break
        status = str((graph_stage or {}).get("status") or "").strip().upper()
        detail = str((graph_stage or {}).get("detail") or "").strip().lower()
        index = projected.get("index_status") or {}
        git = index.get("git") if isinstance(index, Mapping) else {}
        revision = git.get("head_sha") if isinstance(git, Mapping) else None
        if status == "PASS" and isinstance(revision, str) and revision:
            state = "fresh"
            reason = "graph matches the workspace revision"
        elif status == "WARN" and (
            "stale index" in detail or "worktree has" in detail
        ):
            state = "stale"
            reason = "graph is older than the current workspace"
        else:
            state = "unknown"
            reason = "graph freshness could not be established"
        return {
            "freshness": {
                "state": state,
                "reason": reason,
                "source_revision": revision,
                "advisory_only": True,
            },
            "authority": projected,
        }

    def architecture_orientation(
        self, *, path: Optional[str] = None, limit: int = 5
    ) -> dict:
        """Read optional compact architecture evidence without failing callers."""
        authority = self.structural_evidence_authority()
        freshness = authority["freshness"]["state"]
        if freshness not in ("fresh", "stale"):
            return {
                "evidence": None,
                "freshness": authority["freshness"],
                "authority": authority["authority"],
                "warning": authority["freshness"]["reason"],
            }
        method = getattr(self.cbm, "architecture_orientation", None)
        if not callable(method):
            return {
                "evidence": None,
                "freshness": authority["freshness"],
                "authority": authority["authority"],
                "warning": "CBM architecture capability is unavailable",
            }
        try:
            evidence = _adapter_call(
                "architecture_orientation", method, path=path, limit=limit
            )
        except CBMAdapterError as exc:
            return {
                "evidence": None,
                "freshness": authority["freshness"],
                "authority": authority["authority"],
                "warning": str(exc),
            }
        if not isinstance(evidence, Mapping):
            return {
                "evidence": None,
                "freshness": authority["freshness"],
                "authority": authority["authority"],
                "warning": "CBM architecture capability returned malformed evidence",
            }
        return {
            "evidence": dict(evidence),
            "freshness": authority["freshness"],
            "authority": authority["authority"],
            "warning": None,
        }

    def trace_relationships(
        self,
        *,
        function_name: str,
        direction: str = "both",
        max_hops: int = 2,
        limit: int = 20,
    ) -> dict:
        """Read optional bounded callers/dependencies evidence."""
        authority = self.structural_evidence_authority()
        freshness = authority["freshness"]["state"]
        if freshness not in ("fresh", "stale"):
            return {
                "evidence": None,
                "freshness": authority["freshness"],
                "authority": authority["authority"],
                "warning": authority["freshness"]["reason"],
            }
        method = getattr(self.cbm, "trace_relationships", None)
        if not callable(method):
            return {
                "evidence": None,
                "freshness": authority["freshness"],
                "authority": authority["authority"],
                "warning": "CBM traversal capability is unavailable",
            }
        try:
            evidence = _adapter_call(
                "trace_relationships",
                method,
                function_name=function_name,
                direction=direction,
                max_hops=max_hops,
                limit=limit,
            )
        except CBMAdapterError as exc:
            return {
                "evidence": None,
                "freshness": authority["freshness"],
                "authority": authority["authority"],
                "warning": str(exc),
            }
        if not isinstance(evidence, Mapping):
            return {
                "evidence": None,
                "freshness": authority["freshness"],
                "authority": authority["authority"],
                "warning": "CBM traversal capability returned malformed evidence",
            }
        return {
            "evidence": dict(evidence),
            "freshness": authority["freshness"],
            "authority": authority["authority"],
            "warning": None,
        }

    # -- resolution ---------------------------------------------------

    def resolve_reference(self, ref: Any) -> ResolvedReference:
        """Resolve one stored ref against the live CBM index.

        The stored ref is returned unchanged in every state; resolution
        NEVER rewrites history.
        """
        if not isinstance(ref, CodeReference):
            ref = CodeReference.from_dict(ref)
        stored = ref.to_dict()
        if self.cbm is None:
            return ResolvedReference(
                reference=stored,
                state=MISSING,
                note="no CBM adapter configured; cannot resolve live state",
            )
        candidates, invalid = self._find_candidates(ref)
        if not candidates:
            return ResolvedReference(
                reference=stored,
                state=MISSING,
                note=_note_with_invalid(
                    "no live CBM candidate; preserving historical reference",
                    invalid,
                ),
                invalid_candidates=invalid,
            )
        if ref.reference_kind == "file":
            # A file ref resolves when the file is present in the index;
            # per-symbol ambiguity does not apply to file identity.
            return ResolvedReference(
                reference=stored,
                state=RESOLVED,
                candidate=candidates[0].to_dict(),
                note=_note_with_invalid(
                    f"file present in index ({len(candidates)} symbol(s))",
                    invalid,
                ),
                invalid_candidates=invalid,
            )
        if len(candidates) > 1 and ref.qualified_name:
            exact = [
                c
                for c in candidates
                if c.qualified_name == ref.qualified_name
                and c.file_path == ref.file_path
            ]
            if len(exact) == 1:
                candidates = exact
        if len(candidates) > 1:
            return ResolvedReference(
                reference=stored,
                state=AMBIGUOUS,
                candidates=[c.to_dict() for c in candidates],
                note=_note_with_invalid(
                    "multiple live candidates; returning all, never "
                    "choosing silently",
                    invalid,
                ),
                invalid_candidates=invalid,
            )
        candidate = candidates[0]
        drift = []
        if candidate.file_path != ref.file_path:
            drift.append(
                f"file_path drifted: stored {ref.file_path} -> "
                f"live {candidate.file_path}"
            )
        if (
            ref.qualified_name
            and candidate.qualified_name
            and candidate.qualified_name != ref.qualified_name
        ):
            drift.append("qualified_name drifted")
        if (
            ref.start_line is not None
            and candidate.start_line is not None
            and candidate.start_line != ref.start_line
        ):
            drift.append(
                f"start_line drifted: stored {ref.start_line} -> "
                f"live {candidate.start_line}"
            )
        if drift:
            return ResolvedReference(
                reference=stored,
                state=STALE,
                candidate=candidate.to_dict(),
                note=_note_with_invalid("; ".join(drift), invalid),
                invalid_candidates=invalid,
            )
        return ResolvedReference(
            reference=stored,
            state=RESOLVED,
            candidate=candidate.to_dict(),
            note=_note_with_invalid("", invalid),
            invalid_candidates=invalid,
        )

    def _find_candidates(self, ref: CodeReference) -> tuple:
        cbm = self.cbm
        raw: List[dict] = []
        if ref.reference_kind == "symbol":
            if ref.qualified_name and ref.cbm_project_name:
                full_qn = f"{ref.cbm_project_name}.{ref.qualified_name}"
                hit = _adapter_call("get_snippet", cbm.get_snippet, full_qn)
                if hit:
                    raw = [hit]
            if not raw:
                query = ref.symbol_name or _last_qn_segment(ref.qualified_name)
                if query:
                    raw = list(
                        _adapter_call(
                            "search_symbols", cbm.search_symbols, query=query
                        )
                    )
        else:
            raw = list(
                _adapter_call(
                    "search_symbols",
                    cbm.search_symbols,
                    file_path=ref.file_path,
                )
            )
        candidates: List[CodeReference] = []
        invalid: List[dict] = []
        for node in raw:
            if not isinstance(node, dict) or not node.get("file_path"):
                invalid.append(
                    {
                        "file_path": (
                            node.get("file_path") if isinstance(node, dict) else None
                        ),
                        "error": "candidate is not a normalized node with a "
                        "file_path",
                    }
                )
                continue
            try:
                candidates.append(
                    candidate_to_reference(
                        node,
                        project_id=ref.project_id,
                        workspace_id=ref.workspace_id,
                    )
                )
            except CodeRefError as exc:
                invalid.append(
                    {"file_path": node.get("file_path"), "error": str(exc)}
                )
        return candidates, invalid

    # -- queries --------------------------------------------------------

    def memory_to_code(self, *, project_id: str, memory_id: str) -> dict:
        """memory -> code: stored refs with their live resolution state."""
        project_id = validate_project_id(project_id)
        memory = self.memories.get(project_id=project_id, memory_id=memory_id)
        if memory is None:
            raise MemoryNotFoundError(f"unknown memory_id: {memory_id}")
        resolutions = []
        for raw in memory.code_refs:
            try:
                ref = CodeReference.from_dict(raw)
            except CodeRefError:
                resolutions.append(
                    ResolvedReference(
                        reference=raw if isinstance(raw, dict) else {},
                        state=MISSING,
                        note="malformed stored code reference",
                    ).to_dict()
                )
                continue
            resolutions.append(self.resolve_reference(ref).to_dict())
        return {
            "memory": memory.to_dict(),
            "references": resolutions,
        }

    def code_to_memory(
        self,
        *,
        project_id: str,
        reference: Any = None,
        file_path: Optional[str] = None,
        symbol: Optional[str] = None,
        scope: str = "project_shared",
        workspace_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        include_history: bool = False,
        limit: int = 50,
    ) -> List[dict]:
        """code -> memory: active memories directly linked to the target.

        Delegates visibility to the R1C query policy (scope channels,
        agent privacy, lifecycle). Superseded/obsolete memories are
        excluded unless include_history is set. File-only links are
        supported via ``file_path``.
        """
        project_id = validate_project_id(project_id)
        target_ref = None
        if reference is not None:
            target_ref = (
                reference
                if isinstance(reference, CodeReference)
                else CodeReference.from_dict(reference)
            )
            if target_ref.project_id != project_id:
                raise MemoryValidationError(
                    "code reference project_id must match the query project_id"
                )
        target_file = None
        if file_path:
            try:
                target_file = normalize_repo_path(file_path)
            except CodeRefError as exc:
                raise MemoryValidationError(str(exc)) from exc
        target_symbol = (symbol or "").strip() or None
        if target_ref is None and target_file is None and target_symbol is None:
            raise MemoryValidationError(
                "a code target is required: reference, file_path, or symbol"
            )
        try:
            limit = int(limit)
        except (TypeError, ValueError) as exc:
            raise MemoryValidationError(
                f"limit must be a positive integer: {limit!r}"
            ) from exc
        if limit <= 0:
            raise MemoryValidationError(
                f"limit must be a positive integer: {limit!r}"
            )

        result = self.memories.query(
            project_id=project_id,
            scope=scope,
            workspace_id=workspace_id,
            agent_type=agent_type,
            include_history=include_history,
            limit=STORE_PAGE_LIMIT,
        )
        matches = []
        for memory in result.memories:
            matched = [
                stored
                for stored in memory.code_refs
                if self._ref_matches(stored, target_ref, target_file, target_symbol)
            ]
            if matched:
                matches.append(
                    {"memory": memory.to_dict(), "matched_refs": matched}
                )
        return matches[-limit:]

    @staticmethod
    def _ref_matches(
        stored_raw: Any,
        target_ref: Optional[CodeReference],
        target_file: Optional[str],
        target_symbol: Optional[str],
    ) -> bool:
        try:
            stored = CodeReference.from_dict(stored_raw)
        except CodeRefError:
            return False
        if target_ref is not None:
            return stored.code_reference_id == target_ref.code_reference_id
        if target_file is not None and stored.file_path != target_file:
            return False
        if target_symbol is not None:
            qn = stored.qualified_name or ""
            if not (
                stored.symbol_name == target_symbol
                or qn == target_symbol
                or qn.endswith("." + target_symbol)
            ):
                return False
        return True
