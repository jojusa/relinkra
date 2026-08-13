"""Relinkra deterministic cross-agent Handoff model (R3).

A Handoff is the portable, first-class record one agent leaves for the
next: what the task was, what got done, what is still pending, which
decisions were made, and which memories / code references / git state
they attach to.

Hard rules (mirroring the R1E packet and R1C memory invariants):

- DETERMINISTIC IDENTITY. ``handoff_id`` is a content hash over the
  semantic payload. ``created_at`` and ``provenance`` NEVER participate,
  so replaying the same handoff yields the same id and the R1C dedup
  layer collapses it instead of writing a second record.
- AGENT-NEUTRAL. ``source_agent`` is recorded as data only. It never
  reaches a scope channel, never becomes an ``agent_type``, and never
  feeds relevance scoring. ``target_agent`` may be absent.
- PORTABLE. No absolute paths, no credentials. Every free-text field is
  pushed through the R1C redactor BEFORE the id is computed, so the
  stored bytes and the identity always agree.
- APPEND-ONLY. A handoff may be superseded by another handoff, which is
  an explicit new record linked via ``supersedes``. Nothing is rewritten
  in place.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, List, Mapping, Optional

from .memory import (
    STORE_PAGE_LIMIT,
    MemoryValidationError,
    redact_text,
    slugify,
    validate_project_id,
    validate_workspace_id,
)

HANDOFF_VERSION = "rlkho1"
HANDOFF_ID_PREFIX = "hof_"
HANDOFF_ID_RE = re.compile(r"^hof_[0-9a-f]{32}$")
_HANDOFF_NAMESPACE = b"relinkra/handoff/v1\x00"

# memory_id is ``mem_`` + secrets.token_hex(8), i.e. 16 hex characters —
# NOT the 32 used by ref_/pkt_/hof_ ids. The upper bound leaves room for
# the generator to widen without invalidating stored handoffs.
MEMORY_ID_RE = re.compile(r"^mem_[0-9a-f]{16,64}$")
CODE_REF_ID_RE = re.compile(r"^ref_[0-9a-f]{32}$")
PACKET_ID_RE = re.compile(r"^pkt_[0-9a-f]{32}$")

# Structural guardrails. Not token budgets: a handoff is a summary, not a
# transcript. Anything longer is silently truncated to the cap — bounding
# is the contract, so over-long input is a caller error, not an event.
MAX_TASK_CHARS = 400
MAX_SUMMARY_CHARS = 2000
MAX_ITEM_CHARS = 400
MAX_LIST_ITEMS = 20
MAX_RELATED_IDS = 40
MAX_AGENT_CHARS = 64

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Platform-independent on purpose: a handoff written on Windows must stay
# portable when read on POSIX, so we never delegate to os.path.isabs.
# The POSIX form deliberately requires MORE THAN ONE segment so that
# arithmetic like "3 /4" is not mistaken for a path.
_ABS_PATH_RES = (
    # C:\x or C:/x. The lookbehind keeps URL schemes out: the "e:/" in
    # "remote://git/..." is not a drive letter.
    re.compile(r"(?<![A-Za-z0-9_])[A-Za-z]:[\\/][^\s]*"),
    # UNC share. Must run BEFORE the root-relative pattern below so that
    # \\server\share is consumed here rather than half-matched there.
    re.compile(r"\\\\[^\s\\]+(?:\\[^\s\\]+)*"),
    # Root-relative Windows path: a SINGLE leading backslash, as produced
    # by os.path.join(os.sep + "opt", ...) on Windows. Drive-less but
    # still absolute, and missed by every other pattern here. The
    # lookbehind excludes UNC (already consumed) and relative fragments
    # like "src\mod\file.py"; 2+ segments keeps stray escapes out.
    re.compile(r"(?<![\\A-Za-z0-9_])\\[A-Za-z0-9_.\-]+(?:\\[A-Za-z0-9_.\-]*)+"),
    # POSIX absolute. Matches at the start of the text, after whitespace,
    # or after an opening quote/bracket — OSError messages embed QUOTED
    # paths ("Is a directory: '/tmp/x'"), and leaving those unscrubbed
    # leaks the local layout (R5C). Everything else is excluded by
    # construction: "a/b", "./rel", "~/.config/x", "%APPDATA%/x" and
    # "http://h/p" all have a non-boundary character before the slash.
    # Needs 2+ segments so "3 /4" is not mistaken for a path.
    re.compile(r"(?:^|(?<=[\s'\"(<]))/[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]*)+"),
)
_PATH_PLACEHOLDER = "<path>"


class HandoffError(Exception):
    """Base error for handoff failures."""


class HandoffValidationError(HandoffError, ValueError):
    """Raised when handoff input is structurally invalid."""


def scrub_absolute_paths(text: str) -> str:
    """Replace machine-local absolute paths with a portable placeholder.

    A handoff is read on a machine that is not the one that wrote it, so
    an absolute path in free text is at best meaningless and at worst a
    disclosure of the author's filesystem layout. Repo-relative paths are
    left untouched — those are the portable way to point at code.
    """
    if not text:
        return text
    for pattern in _ABS_PATH_RES:
        text = pattern.sub(_PATH_PLACEHOLDER, text)
    return text


def _clean_text(value: Any, *, limit: int, field_name: str) -> str:
    """Redact, de-path, strip control characters, and bound length.

    Order matters: sanitation runs BEFORE the caller hashes the result,
    so the stored bytes and the handoff identity can never disagree.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        raise HandoffValidationError(f"{field_name} must be a string")
    text = _CONTROL_RE.sub("", value).strip()
    text = redact_text(text)
    text = scrub_absolute_paths(text)
    if len(text) > limit:
        text = text[:limit].rstrip()
    return text


def _clean_list(value: Any, *, field_name: str) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str) or not isinstance(value, (list, tuple)):
        raise HandoffValidationError(f"{field_name} must be a list of strings")
    items: List[str] = []
    for entry in value:
        text = _clean_text(entry, limit=MAX_ITEM_CHARS, field_name=field_name)
        if text:
            items.append(text)
        if len(items) >= MAX_LIST_ITEMS:
            break
    return items


def _clean_agent(value: Any, *, field_name: str) -> str:
    """Agent labels are opaque identity strings, never authority.

    Sanitized exactly like any other free text. The label is
    caller-supplied, so the "no secrets, no absolute paths" rule applies
    to it too — an agent label is not a trusted enum.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        raise HandoffValidationError(f"{field_name} must be a string")
    text = _CONTROL_RE.sub("", value).strip()
    text = redact_text(text)
    text = scrub_absolute_paths(text)
    if len(text) > MAX_AGENT_CHARS:
        text = text[:MAX_AGENT_CHARS].rstrip()
    return text


def _clean_ids(value: Any, pattern: re.Pattern, *, field_name: str) -> List[str]:
    """Keep only well-formed ids, de-duplicated and sorted.

    Sorting is what makes the identity hash independent of the order the
    caller happened to collect the references in.
    """
    if value is None:
        return []
    if isinstance(value, str) or not isinstance(value, (list, tuple)):
        raise HandoffValidationError(f"{field_name} must be a list of ids")
    seen = set()
    for entry in value:
        if not isinstance(entry, str):
            raise HandoffValidationError(f"{field_name} entries must be strings")
        candidate = entry.strip()
        if not pattern.match(candidate):
            raise HandoffValidationError(
                f"{field_name} contains a malformed id: {candidate!r}"
            )
        seen.add(candidate)
    return sorted(seen)[:MAX_RELATED_IDS]


def contains_absolute_path(value: str) -> bool:
    """True when a string carries a Windows drive/UNC or POSIX abs path.

    The exact inverse of :func:`scrub_absolute_paths`, so a scrubbed
    string always tests False. Used by the portability assertions.
    """
    if not value:
        return False
    return any(pattern.search(value) for pattern in _ABS_PATH_RES)


@dataclass(frozen=True)
class GitStateRef:
    """The portable slice of R2 git state a handoff carries.

    Deliberately a subset of GitRepositoryState: identity plus dirtiness,
    never paths, never remotes, never author email.
    """

    branch: Optional[str] = None
    head_sha: Optional[str] = None
    short_head_sha: Optional[str] = None
    detached: bool = False
    clean: Optional[bool] = None
    staged_count: int = 0
    unstaged_count: int = 0
    untracked_count: int = 0
    conflicted_count: int = 0

    def to_dict(self) -> dict:
        return {
            "branch": self.branch,
            "head_sha": self.head_sha,
            "short_head_sha": self.short_head_sha,
            "detached": self.detached,
            "clean": self.clean,
            "counts": {
                "staged": self.staged_count,
                "unstaged": self.unstaged_count,
                "untracked": self.untracked_count,
                "conflicted": self.conflicted_count,
            },
        }

    @staticmethod
    def from_dict(data: Optional[Mapping]) -> "GitStateRef":
        if not data:
            return GitStateRef()
        if not isinstance(data, Mapping):
            raise HandoffValidationError("git_state must be a JSON object")
        counts = data.get("counts") or {}
        if not isinstance(counts, Mapping):
            counts = {}

        def _count(key: str) -> int:
            try:
                return max(0, int(counts.get(key, 0) or 0))
            except (TypeError, ValueError):
                return 0

        def _sha(key: str) -> Optional[str]:
            raw = data.get(key)
            if raw in (None, ""):
                return None
            text = str(raw).strip()
            if not re.match(r"^[0-9a-f]{4,64}$", text):
                raise HandoffValidationError(f"git_state.{key} is not a sha")
            return text

        branch = data.get("branch")
        if branch is not None:
            branch = _clean_text(
                str(branch), limit=MAX_ITEM_CHARS, field_name="git_state.branch"
            ) or None
        clean = data.get("clean")
        return GitStateRef(
            branch=branch,
            head_sha=_sha("head_sha"),
            short_head_sha=_sha("short_head_sha"),
            detached=bool(data.get("detached", False)),
            clean=None if clean is None else bool(clean),
            staged_count=_count("staged"),
            unstaged_count=_count("unstaged"),
            untracked_count=_count("untracked"),
            conflicted_count=_count("conflicted"),
        )

    @staticmethod
    def from_repository_state(state: Any) -> "GitStateRef":
        """Project an R2 GitRepositoryState onto the portable subset.

        ``branch`` is sanitized on this path exactly as it is in
        ``from_dict``. Git's own ref-name rules make a hostile branch
        unlikely, but the portability invariant must hold on EVERY
        construction path, not just the one that happens to take
        untrusted input today.
        """
        if state is None:
            return GitStateRef()
        branch = getattr(state, "branch", None)
        if branch is not None:
            branch = _clean_text(
                str(branch), limit=MAX_ITEM_CHARS, field_name="git_state.branch"
            ) or None
        return GitStateRef(
            branch=branch,
            head_sha=getattr(state, "head_sha", None),
            short_head_sha=getattr(state, "short_head_sha", None),
            detached=bool(getattr(state, "detached", False)),
            clean=getattr(state, "clean", None),
            staged_count=int(getattr(state, "staged_count", 0) or 0),
            unstaged_count=int(getattr(state, "unstaged_count", 0) or 0),
            untracked_count=int(getattr(state, "untracked_count", 0) or 0),
            conflicted_count=int(getattr(state, "conflicted_count", 0) or 0),
        )


def compute_handoff_id(
    *,
    project_id: str,
    workspace_id: Optional[str],
    source_agent: str,
    target_agent: Optional[str],
    task: str,
    summary: str,
    completed_work: List[str],
    pending_work: List[str],
    decisions: List[str],
    warnings: List[str],
    related_memory_ids: List[str],
    related_code_reference_ids: List[str],
    git_state: GitStateRef,
    context_packet_id: Optional[str],
    supersedes: Optional[str] = None,
    handoff_version: str = HANDOFF_VERSION,
) -> str:
    """hof_ + first 32 hex of sha256 over the semantic payload.

    ``created_at`` and ``provenance`` are excluded so the same logical
    handoff is stable across clocks and machines. ``supersedes`` IS part
    of identity: superseding handoff B of A is a different fact from a
    standalone B, and both must be able to coexist in history.
    """
    payload = {
        "v": handoff_version,
        "project_id": project_id,
        "workspace_id": workspace_id or "",
        "source_agent": source_agent,
        "target_agent": target_agent or "",
        "task": task,
        "summary": summary,
        "completed_work": completed_work,
        "pending_work": pending_work,
        "decisions": decisions,
        "warnings": warnings,
        "related_memory_ids": related_memory_ids,
        "related_code_reference_ids": related_code_reference_ids,
        "git_state": git_state.to_dict(),
        "context_packet_id": context_packet_id or "",
        "supersedes": supersedes or "",
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    digest = hashlib.sha256(_HANDOFF_NAMESPACE + encoded).hexdigest()
    return HANDOFF_ID_PREFIX + digest[:32]


@dataclass
class Handoff:
    """One deterministic cross-agent handoff record."""

    handoff_id: str
    project_id: str
    source_agent: str
    task: str
    created_at: str
    handoff_version: str = HANDOFF_VERSION
    workspace_id: Optional[str] = None
    target_agent: Optional[str] = None
    summary: str = ""
    completed_work: List[str] = field(default_factory=list)
    pending_work: List[str] = field(default_factory=list)
    decisions: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    related_memory_ids: List[str] = field(default_factory=list)
    related_code_reference_ids: List[str] = field(default_factory=list)
    git_state: GitStateRef = field(default_factory=GitStateRef)
    context_packet_id: Optional[str] = None
    supersedes: Optional[str] = None
    superseded_by: Optional[str] = None
    status: str = "active"
    provenance: dict = field(default_factory=dict)
    memory_id: Optional[str] = None

    def to_portable_dict(self) -> dict:
        """The canonical wire form. Identity fields plus bookkeeping.

        ``memory_id`` is storage bookkeeping and is emitted so a reader
        can follow the record back through the R1C layer; it carries no
        machine-local information.
        """
        return {
            "handoff_version": self.handoff_version,
            "handoff_id": self.handoff_id,
            "project_id": self.project_id,
            "workspace_id": self.workspace_id,
            "source_agent": self.source_agent,
            "target_agent": self.target_agent,
            "created_at": self.created_at,
            "task": self.task,
            "summary": self.summary,
            "completed_work": list(self.completed_work),
            "pending_work": list(self.pending_work),
            "decisions": list(self.decisions),
            "warnings": list(self.warnings),
            "related_memory_ids": list(self.related_memory_ids),
            "related_code_reference_ids": list(self.related_code_reference_ids),
            "git_state": self.git_state.to_dict(),
            "context_packet_id": self.context_packet_id,
            "supersedes": self.supersedes,
            "superseded_by": self.superseded_by,
            "status": self.status,
            "provenance": dict(self.provenance),
            "memory_id": self.memory_id,
        }

    def to_json(self, *, pretty: bool = False) -> str:
        data = self.to_portable_dict()
        if pretty:
            return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)
        return json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )

    def to_storage_dict(self) -> dict:
        """The exact bytes persisted in the R1C memory body.

        ``created_at`` is deliberately ABSENT, and this is load-bearing.
        R1C derives its dedup key from the normalised title plus body, so
        a wall-clock value in the body would make two replays of the SAME
        logical handoff hash differently: dedup would miss, and the
        topic-based auto-supersede path would instead write a second
        record superseding the first, growing a chain forever while
        reporting ``deduplicated=False``. Keeping the body a pure
        function of handoff content is what makes the documented
        "identical handoff collapses" behaviour actually true.

        The timestamp is not lost — the memory envelope carries its own
        ``timestamp``, which :meth:`HandoffService._parse` reads back into
        ``created_at``. The other omitted fields are lifecycle state owned
        by the memory layer, not content.
        """
        data = self.to_portable_dict()
        for owned_by_storage in (
            "created_at",
            "memory_id",
            "superseded_by",
            "status",
        ):
            data.pop(owned_by_storage, None)
        return data

    def to_storage_json(self) -> str:
        return json.dumps(
            self.to_storage_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    @staticmethod
    def from_dict(data: Mapping) -> "Handoff":
        if not isinstance(data, Mapping):
            raise HandoffValidationError("handoff must be a JSON object")
        if str(data.get("handoff_version") or "") != HANDOFF_VERSION:
            raise HandoffValidationError("unsupported handoff_version")
        for required in ("handoff_id", "project_id", "source_agent", "created_at"):
            if not data.get(required):
                raise HandoffValidationError(
                    f"handoff missing required field: {required}"
                )
        handoff_id = str(data["handoff_id"])
        if not HANDOFF_ID_RE.match(handoff_id):
            raise HandoffValidationError("malformed handoff_id")
        return Handoff(
            handoff_version=HANDOFF_VERSION,
            handoff_id=handoff_id,
            project_id=validate_project_id(str(data["project_id"])),
            workspace_id=(
                str(data["workspace_id"]) if data.get("workspace_id") else None
            ),
            source_agent=str(data["source_agent"]),
            target_agent=(
                str(data["target_agent"]) if data.get("target_agent") else None
            ),
            created_at=str(data["created_at"]),
            task=str(data.get("task") or ""),
            summary=str(data.get("summary") or ""),
            completed_work=[str(x) for x in data.get("completed_work") or []],
            pending_work=[str(x) for x in data.get("pending_work") or []],
            decisions=[str(x) for x in data.get("decisions") or []],
            warnings=[str(x) for x in data.get("warnings") or []],
            related_memory_ids=[
                str(x) for x in data.get("related_memory_ids") or []
            ],
            related_code_reference_ids=[
                str(x) for x in data.get("related_code_reference_ids") or []
            ],
            git_state=GitStateRef.from_dict(data.get("git_state")),
            context_packet_id=data.get("context_packet_id") or None,
            supersedes=data.get("supersedes") or None,
            superseded_by=data.get("superseded_by") or None,
            status=str(data.get("status") or "active"),
            provenance=dict(data.get("provenance") or {}),
            memory_id=data.get("memory_id") or None,
        )


def build_handoff(
    *,
    project_id: str,
    source_agent: str,
    task: str,
    created_at: str,
    workspace_id: Optional[str] = None,
    target_agent: Optional[str] = None,
    summary: Optional[str] = None,
    completed_work: Any = None,
    pending_work: Any = None,
    decisions: Any = None,
    warnings: Any = None,
    related_memory_ids: Any = None,
    related_code_reference_ids: Any = None,
    git_state: Any = None,
    context_packet_id: Optional[str] = None,
    supersedes: Optional[str] = None,
    provenance: Optional[Mapping] = None,
) -> Handoff:
    """Validate, redact, and hash a handoff into its canonical form.

    Redaction happens BEFORE hashing so the stored bytes and the id can
    never disagree.
    """
    project_id = validate_project_id(project_id)
    if workspace_id:
        workspace_id = validate_workspace_id(workspace_id)
    else:
        workspace_id = None

    source = _clean_agent(source_agent, field_name="source_agent")
    if not source:
        raise HandoffValidationError("source_agent must be non-empty")
    target = _clean_agent(target_agent, field_name="target_agent") or None

    task_text = _clean_text(task, limit=MAX_TASK_CHARS, field_name="task")
    if not task_text:
        raise HandoffValidationError("task must be non-empty")
    summary_text = _clean_text(
        summary, limit=MAX_SUMMARY_CHARS, field_name="summary"
    )

    completed = _clean_list(completed_work, field_name="completed_work")
    pending = _clean_list(pending_work, field_name="pending_work")
    decision_list = _clean_list(decisions, field_name="decisions")
    warning_list = _clean_list(warnings, field_name="warnings")

    memory_ids = _clean_ids(
        related_memory_ids, MEMORY_ID_RE, field_name="related_memory_ids"
    )
    code_ref_ids = _clean_ids(
        related_code_reference_ids,
        CODE_REF_ID_RE,
        field_name="related_code_reference_ids",
    )

    if isinstance(git_state, GitStateRef):
        git = git_state
    elif git_state is None or isinstance(git_state, Mapping):
        git = GitStateRef.from_dict(git_state)
    else:
        git = GitStateRef.from_repository_state(git_state)

    packet_id = (context_packet_id or "").strip() or None
    if packet_id and not PACKET_ID_RE.match(packet_id):
        raise HandoffValidationError("malformed context_packet_id")

    prior = (supersedes or "").strip() or None
    if prior and not HANDOFF_ID_RE.match(prior):
        raise HandoffValidationError("malformed supersedes handoff_id")

    handoff_id = compute_handoff_id(
        project_id=project_id,
        workspace_id=workspace_id,
        source_agent=source,
        target_agent=target,
        task=task_text,
        summary=summary_text,
        completed_work=completed,
        pending_work=pending,
        decisions=decision_list,
        warnings=warning_list,
        related_memory_ids=memory_ids,
        related_code_reference_ids=code_ref_ids,
        git_state=git,
        context_packet_id=packet_id,
        supersedes=prior,
    )

    return Handoff(
        handoff_id=handoff_id,
        project_id=project_id,
        workspace_id=workspace_id,
        source_agent=source,
        target_agent=target,
        created_at=created_at,
        task=task_text,
        summary=summary_text,
        completed_work=completed,
        pending_work=pending,
        decisions=decision_list,
        warnings=warning_list,
        related_memory_ids=memory_ids,
        related_code_reference_ids=code_ref_ids,
        git_state=git,
        context_packet_id=packet_id,
        supersedes=prior,
        provenance=dict(provenance or {}),
    )


def handoff_title(handoff: Handoff) -> str:
    """Human-readable title that is ALSO unique per handoff.

    Uniqueness matters structurally, not cosmetically: R1C derives
    ``topic_key`` from the title and auto-supersedes the previous active
    memory on the same topic. A title that collapsed two distinct
    handoffs onto one topic would silently rewrite history, which the
    handoff contract forbids. Embedding a 12-hex slice of the content
    hash keeps every handoff on its own topic while leaving the task
    readable in Markdown briefs.
    """
    short = handoff.handoff_id[len(HANDOFF_ID_PREFIX):][:12]
    task_slug = slugify(handoff.task, max_len=40)
    return f"handoff {short} {task_slug}"


class HandoffService:
    """Persists and reads handoffs through the R1C memory policy layer.

    Deliberately thin: it owns NO storage of its own. Every write goes
    through MemoryService (which owns redaction, dedup, supersession, and
    scope) and therefore through the Engram adapter. Nothing here touches
    Engram SQLite directly.
    """

    #: Handoffs intended for another agent are shared by definition.
    SCOPE = "project_shared"

    def __init__(self, memory_service: Any, clock: Any = None):
        self.memories = memory_service
        self._clock = clock

    # -- write ------------------------------------------------------------

    def create(
        self,
        *,
        project_id: str,
        source_agent: str,
        task: str,
        repository_identity: Any,
        workspace_id: Optional[str] = None,
        target_agent: Optional[str] = None,
        summary: Optional[str] = None,
        completed_work: Any = None,
        pending_work: Any = None,
        decisions: Any = None,
        warnings: Any = None,
        related_memory_ids: Any = None,
        related_code_reference_ids: Any = None,
        git_state: Any = None,
        context_packet_id: Optional[str] = None,
        supersedes: Optional[str] = None,
        agent_id: str = "",
    ) -> tuple:
        """Create a handoff. Returns (handoff, deduplicated, policy_warnings).

        ``policy_warnings`` reports references that were dropped for
        policy reasons (an AGENT_PRIVATE memory, or one owned by another
        project) rather than failing the whole call: a partial handoff
        plus an explicit warning beats no handoff.
        """
        created_at = self._now()
        policy_warnings: List[str] = []

        memory_ids = _clean_ids(
            related_memory_ids, MEMORY_ID_RE, field_name="related_memory_ids"
        )
        visible_ids = self._filter_shareable(
            project_id, memory_ids, policy_warnings
        )

        prior_memory_id = None
        if supersedes:
            prior = self.get(project_id=project_id, handoff_id=supersedes)
            if prior is None:
                raise HandoffValidationError(
                    f"unknown supersedes handoff_id: {supersedes}"
                )
            prior_memory_id = prior.memory_id

        handoff = build_handoff(
            project_id=project_id,
            source_agent=source_agent,
            task=task,
            created_at=created_at,
            workspace_id=workspace_id,
            target_agent=target_agent,
            summary=summary,
            completed_work=completed_work,
            pending_work=pending_work,
            decisions=decisions,
            warnings=warnings,
            related_memory_ids=visible_ids,
            related_code_reference_ids=related_code_reference_ids,
            git_state=git_state,
            context_packet_id=context_packet_id,
            supersedes=supersedes,
            provenance={
                "producer": "relinkra.handoff",
                "handoff_version": HANDOFF_VERSION,
                "scope": self.SCOPE,
            },
        )

        memory, deduplicated, _ = self.memories.save(
            project_id=handoff.project_id,
            memory_type="handoff",
            title=handoff_title(handoff),
            body=handoff.to_storage_json(),
            repository_identity=repository_identity,
            scope=self.SCOPE,
            workspace_id=handoff.workspace_id,
            agent_id=agent_id or "",
            # agent_type stays EMPTY on purpose. A non-empty agent_type
            # would be an authority signal; source_agent is data only.
            agent_type="",
            branch=handoff.git_state.branch,
            commit_sha=handoff.git_state.head_sha,
            source_tool="relinkra",
            status="active",
            supersedes=prior_memory_id,
            code_refs=None,
        )
        handoff.memory_id = memory.memory_id
        return handoff, deduplicated, policy_warnings

    # -- read -------------------------------------------------------------

    def get(
        self, *, project_id: str, handoff_id: str
    ) -> Optional[Handoff]:
        """Fetch one handoff by its content id, including superseded ones.

        The lookup is a TARGETED store search on the id rather than a
        scan of recent memories. R1C fetches a fixed store page
        (STORE_PAGE_LIMIT) spanning every memory type and filters by type
        afterwards, so on a project with more than a page of shared
        memories a scan would silently miss older handoffs — reporting a
        false "unknown handoff_id" both here and, worse, when resolving a
        supersedes target. Searching for the id keeps the record
        reachable regardless of how much other memory exists.
        """
        project_id = validate_project_id(project_id)
        handoff_id = (handoff_id or "").strip()
        if not HANDOFF_ID_RE.match(handoff_id):
            raise HandoffValidationError("malformed handoff_id")
        for handoff in self._query(
            project_id=project_id,
            text=handoff_id,
            include_history=True,
        ):
            if handoff.handoff_id == handoff_id:
                return handoff
        return None

    def list(
        self,
        *,
        project_id: str,
        workspace_id: Optional[str] = None,
        target_agent: Optional[str] = None,
        include_history: bool = False,
        limit: int = 20,
    ) -> List[Handoff]:
        """List handoffs newest-first under the R1C shared-scope policy.

        ``target_agent`` filters on the recorded intent only. It is NOT
        an access control: every handoff here is already PROJECT_SHARED
        and readable by any agent on the project. Filtering is a
        convenience for "what was left for me", never a permission.
        """
        project_id = validate_project_id(project_id)
        handoffs = self._query(
            project_id=project_id,
            workspace_id=workspace_id,
            include_history=include_history,
            limit=limit,
        )
        if target_agent:
            handoffs = [
                h for h in handoffs if h.target_agent == target_agent
            ]
        if not include_history:
            handoffs = handoffs[:limit]
        return handoffs

    def _query(
        self,
        *,
        project_id: str,
        text: Optional[str] = None,
        workspace_id: Optional[str] = None,
        include_history: bool = False,
        limit: int = 20,
    ) -> List[Handoff]:
        """Read handoff memories, newest-first.

        ``text`` defaults to the handoff envelope version, which appears
        in every handoff body and in no other memory type. That narrows
        the fixed store page to handoff records instead of spending it on
        unrelated decisions and discoveries — without it, a busy project
        pushes handoffs out of reach.
        """
        scope = "workspace_local" if workspace_id else self.SCOPE
        result = self.memories.query(
            project_id=project_id,
            scope=scope,
            workspace_id=workspace_id,
            text=text or HANDOFF_VERSION,
            memory_type="handoff",
            include_history=include_history,
            limit=max(1, int(limit)) if not include_history else STORE_PAGE_LIMIT,
        )
        handoffs: List[Handoff] = []
        for memory in result.memories:
            handoff = self._parse(memory)
            if handoff is not None:
                handoffs.append(handoff)
        handoffs.sort(key=lambda h: (h.created_at, h.handoff_id), reverse=True)
        return handoffs

    # -- internals --------------------------------------------------------

    def _now(self) -> str:
        if self._clock is not None:
            return self._clock()
        from .context_builder import _utcnow

        return _utcnow()

    @staticmethod
    def _parse(memory: Any) -> Optional[Handoff]:
        """Decode a stored envelope, skipping anything malformed.

        A single corrupt record must never take down a whole listing.
        """
        try:
            data = json.loads(memory.body)
        except (ValueError, TypeError):
            return None
        if not isinstance(data, dict):
            return None
        # The body omits created_at so it stays a pure function of
        # content (see Handoff.to_storage_dict); the envelope timestamp is
        # the authority. setdefault also keeps records written before that
        # split readable.
        data.setdefault("created_at", memory.timestamp)
        try:
            handoff = Handoff.from_dict(data)
        except (HandoffValidationError, MemoryValidationError):
            return None
        if handoff.project_id != memory.project_id:
            # Cross-project payload smuggled into another project's
            # channel: refuse it rather than surface it.
            return None
        handoff.memory_id = memory.memory_id
        handoff.status = memory.status
        if getattr(memory, "superseded_by", None):
            handoff.superseded_by = memory.superseded_by
        return handoff

    def _filter_shareable(
        self, project_id: str, memory_ids: List[str], warnings: List[str]
    ) -> List[str]:
        """Drop references that must not travel in a shared handoff.

        MemoryService.get resolves by id WITHOUT applying a scope filter,
        so an AGENT_PRIVATE memory is reachable here. Publishing its id
        in a PROJECT_SHARED handoff would leak private context across the
        agent boundary, so those are dropped with a warning.
        """
        if not memory_ids:
            return []
        kept: List[str] = []
        for memory_id in memory_ids:
            try:
                memory = self.memories.get(
                    project_id=project_id, memory_id=memory_id
                )
            except Exception:
                memory = None
            if memory is None:
                warnings.append(
                    f"dropped unknown related memory: {memory_id}"
                )
                continue
            if memory.scope == "agent_private":
                warnings.append(
                    f"dropped agent_private related memory: {memory_id}"
                )
                continue
            kept.append(memory_id)
        return sorted(set(kept))
