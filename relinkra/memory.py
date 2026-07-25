"""Relinkra shared memory policy model (R1C).

Logical memory model layered over a physical store (Engram by default).
This module owns policy: memory types, scopes, project binding, envelope
serialization, dedup, lifecycle/supersession, scope-based retrieval, and
credential redaction. Storage mechanics live in ``engram_adapter``.

Design invariants:

- Logical model is separate from storage. Relinkra memory types map
  conservatively onto Engram storage types; the relinkra ``memory_type``
  is always preserved inside the content envelope.
- Isolation is policy-enforced, not physical. The backend is shared; scope
  channels (``shared``, ``ws/<workspace_id>``, ``agent/<agent_type>``)
  decide visibility at query time.
- project_id is ALWAYS a valid R1B ``rlk_`` id. Never a filesystem path,
  CBM name, branch, or HEAD SHA.
- Secrets are redacted before persistence. Redaction is defense in depth,
  not perfect.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import string
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional

from .code_reference import CodeRefError, CodeReference
from .identity import redact_url

ENVELOPE_VERSION = "rlkmem1"
ENGRAM_SCOPE = "project"
TOPIC_PREFIX = "relinkra/v1"

# Fixed store page size for queries: the store is asked for a page large
# enough that policy filtering (channels, type, lifecycle) never starves
# the caller-visible limit. The user limit is applied AFTER filtering.
STORE_PAGE_LIMIT = 200

PROJECT_ID_RE = re.compile(r"^rlk_[0-9a-f]{32}$")
WORKSPACE_ID_RE = re.compile(r"^ws_[0-9a-f]{32}$")

MEMORY_TYPES = (
    "decision",
    "discovery",
    "constraint",
    "bug",
    "architecture",
    "task_result",
    "verification",
    "pending",
    "handoff",
)

STORAGE_TYPE_MAP = {
    "decision": "decision",
    "discovery": "discovery",
    "architecture": "architecture",
    "bug": "bugfix",
    "constraint": "config",
    "task_result": "manual",
    "verification": "manual",
    "pending": "manual",
    "handoff": "manual",
}

SCOPES = ("project_shared", "workspace_local", "agent_private")
SCOPE_ALIASES = {
    "shared": "project_shared",
    "project": "project_shared",
    "workspace": "workspace_local",
    "ws": "workspace_local",
    "local": "workspace_local",
    "agent": "agent_private",
    "private": "agent_private",
}

STATUSES = ("active", "superseded", "obsolete")

_REPO_KINDS = ("remote", "explicit", "local_root")
_REPO_VALUE_RE = re.compile(r"^(remote://git/|explicit://|local-root://)\S+$")


class MemoryError(Exception):
    """Base error for memory policy violations."""


class MemoryValidationError(MemoryError, ValueError):
    """Raised when a memory fails validation before persistence."""


class MemoryNotFoundError(MemoryError):
    """Raised when a referenced memory_id cannot be resolved."""


class MemoryStoreError(MemoryError):
    """Raised when the backing store fails."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_memory_id() -> str:
    return "mem_" + secrets.token_hex(8)


def normalize_scope(scope: str) -> str:
    s = (scope or "").strip().lower()
    s = SCOPE_ALIASES.get(s, s)
    if s not in SCOPES:
        raise MemoryValidationError(f"unsupported memory scope: {scope!r}")
    return s


def storage_type_for(memory_type: str) -> str:
    if memory_type not in STORAGE_TYPE_MAP:
        raise MemoryValidationError(f"unsupported memory_type: {memory_type!r}")
    return STORAGE_TYPE_MAP[memory_type]


def slugify(text: str, max_len: int = 48) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)
    if len(slug) > max_len:
        slug = slug[:max_len].rstrip("-")
    return slug or "untitled"


def validate_project_id(project_id: str) -> str:
    pid = (project_id or "").strip()
    if not PROJECT_ID_RE.match(pid):
        raise MemoryValidationError(
            "project_id must be a valid R1B rlk_ id (never a filesystem "
            "path, CBM name, branch, or HEAD SHA)"
        )
    return pid


def validate_workspace_id(workspace_id: str) -> str:
    wid = (workspace_id or "").strip()
    if not WORKSPACE_ID_RE.match(wid):
        raise MemoryValidationError("workspace_id must be a valid R1B ws_ id")
    return wid


def validate_repository_identity(identity: Any) -> dict:
    """Validate a repository identity mapping from R1B.

    Rejects path-like values outright: identity is never a filesystem
    location, branch, or commit.
    """
    if isinstance(identity, Mapping):
        kind = str(identity.get("kind", ""))
        value = str(identity.get("value", ""))
        trust = str(identity.get("trust", ""))
    else:
        raise MemoryValidationError("repository_identity must be a mapping")
    if kind not in _REPO_KINDS:
        raise MemoryValidationError(f"unsupported identity kind: {kind!r}")
    if trust not in ("strong", "weak"):
        raise MemoryValidationError(f"unsupported identity trust: {trust!r}")
    if not _REPO_VALUE_RE.match(value):
        raise MemoryValidationError(
            "repository_identity value is not a canonical R1B identity"
        )
    if "@" in value:
        raise MemoryValidationError("repository_identity contains credentials")
    if "\\" in value or re.match(r"^[A-Za-z]:", value):
        raise MemoryValidationError(
            "repository_identity must not be a filesystem path"
        )
    return {"kind": kind, "value": value, "trust": trust}


def validate_code_refs(code_refs: Any, project_id: Optional[str] = None) -> list:
    """Validate/normalize a list of code references (R1D).

    Each entry must be a CodeReference or a mapping accepted by
    ``CodeReference.from_dict``; normalized dicts are returned so the
    envelope stores canonical form. When ``project_id`` is given every
    ref must belong to that project — a memory never links code across
    logical projects. ``None``/empty yields ``[]`` so pre-R1D envelopes
    parse unchanged.
    """
    if code_refs in (None, ""):
        return []
    if not isinstance(code_refs, list):
        raise MemoryValidationError("code_refs must be a list")
    validated = []
    for item in code_refs:
        try:
            ref = (
                item
                if isinstance(item, CodeReference)
                else CodeReference.from_dict(item)
            )
        except (CodeRefError, TypeError, ValueError) as exc:
            raise MemoryValidationError(
                f"invalid code reference: {exc}"
            ) from exc
        if project_id is not None and ref.project_id != project_id:
            raise MemoryValidationError(
                "code reference project_id must match the memory project_id"
            )
        validated.append(ref.to_dict())
    return validated


# ---------------------------------------------------------------------------
# Redaction (defense in depth — NOT perfect)
# ---------------------------------------------------------------------------

_REDACTED = "[REDACTED]"

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_URL_PASSWORD_RE = re.compile(
    r"([A-Za-z][A-Za-z0-9+.-]*://)([^/\s:@]+):([^@/\s]+)@"
)
_BEARER_RE = re.compile(r"\b(Bearer\s+)[A-Za-z0-9._~+/\-]{6,}={0,2}", re.IGNORECASE)
_KNOWN_TOKEN_RE = re.compile(
    r"\b("
    r"sk[_-](?:live|test)[_-][A-Za-z0-9]{8,}"
    r"|sk-[A-Za-z0-9]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|glpat-[A-Za-z0-9_\-]{15,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|AIza[0-9A-Za-z_\-]{35}"
    r"|hf_[A-Za-z0-9]{20,}"
    r"|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"
    r")\b"
)
_KV_SECRET_RE = re.compile(
    r"(?i)\b("
    r"token|api[_-]?key|apikey|api[_-]?secret|password|passwd|secret"
    r"|client[_-]?secret|access[_-]?key|auth[_-]?token|private[_-]?token"
    r")(\s*[:=]\s*)(\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;&`]+)"
)


def redact_text(text: str) -> str:
    """Best-effort secret redaction applied before persistence.

    Handles bearer tokens, common API-key prefixes, passwords in URLs,
    PEM private key blocks, and generic ``token=`` / ``api_key=`` /
    ``password=`` style key-values. This is defense in depth, not a
    guarantee: do not put secrets in memories.
    """
    if not isinstance(text, str) or not text:
        return text
    out = _PRIVATE_KEY_RE.sub(_REDACTED, text)
    out = _URL_PASSWORD_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}:{_REDACTED}@", out)
    out = _BEARER_RE.sub(lambda m: m.group(1) + _REDACTED, out)
    out = _KNOWN_TOKEN_RE.sub(_REDACTED, out)

    def _kv(m: re.Match) -> str:
        value = m.group(3)
        if value.startswith(('"', "'")) and len(value) >= 2:
            quote = value[0]
            return f"{m.group(1)}{m.group(2)}{quote}{_REDACTED}{quote}"
        return f"{m.group(1)}{m.group(2)}{_REDACTED}"

    out = _KV_SECRET_RE.sub(_kv, out)
    return out


def sanitize_error(message: str) -> str:
    """Redact an error message so secrets are never echoed to stderr."""
    return redact_url(redact_text(message or ""))


# ---------------------------------------------------------------------------
# Dedup
# ---------------------------------------------------------------------------

_PUNCT_EDGES = string.punctuation


def normalize_for_dedup(text: str) -> str:
    """Lowercase, collapse whitespace, strip punctuation at the edges."""
    t = (text or "").lower()
    t = re.sub(r"\s+", " ", t).strip()
    t = t.strip(_PUNCT_EDGES).strip()
    return t


def compute_dedup_key(
    project_id: str, scope: str, memory_type: str, title: str, body: str
) -> str:
    """Deterministic conservative dedup key (no embeddings, no LLM).

    sha256 over project_id + scope + memory_type + normalized title +
    normalized body. Computed over REDACTED text so the stored key never
    derives from raw secrets. Limitation: only exact post-normalization
    duplicates are caught; paraphrases are not.
    """
    payload = "\n".join(
        [
            project_id,
            scope,
            memory_type,
            normalize_for_dedup(title),
            normalize_for_dedup(body),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


def scope_channel_for(
    scope: str,
    workspace_id: Optional[str] = None,
    agent_type: Optional[str] = None,
) -> str:
    """Map a logical scope to its topic_key channel.

    shared | ws/<workspace_id> | agent/<agent_type>
    """
    scope = normalize_scope(scope)
    if scope == "project_shared":
        return "shared"
    if scope == "workspace_local":
        if not workspace_id:
            raise MemoryValidationError(
                "workspace_local scope requires workspace_id"
            )
        return f"ws/{validate_workspace_id(workspace_id)}"
    if not agent_type or not str(agent_type).strip():
        raise MemoryValidationError("agent_private scope requires agent_type")
    return f"agent/{slugify(str(agent_type), max_len=32)}"


def topic_key_for(
    project_id: str, scope_channel: str, memory_type: str, title: str
) -> str:
    return (
        f"{TOPIC_PREFIX}/{validate_project_id(project_id)}/{scope_channel}"
        f"/{memory_type}/{slugify(title)}"
    )


@dataclass
class Memory:
    memory_id: str
    project_id: str
    agent_id: str
    agent_type: str
    memory_type: str
    title: str
    body: str
    timestamp: str
    repository_identity: dict
    scope: str
    status: str = "active"
    workspace_id: Optional[str] = None
    branch: Optional[str] = None
    commit_sha: Optional[str] = None
    confidence: Optional[float] = None
    supersedes: Optional[str] = None
    superseded_by: Optional[str] = None
    source_tool: str = "relinkra"
    dedup_key: str = ""
    scope_channel: str = ""
    topic_key: str = ""
    code_refs: list = field(default_factory=list)

    def to_envelope(self) -> dict:
        env: dict[str, Any] = {
            "v": ENVELOPE_VERSION,
            "memory_id": self.memory_id,
            "project_id": self.project_id,
            "workspace_id": self.workspace_id,
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "memory_type": self.memory_type,
            "scope": self.scope,
            "scope_channel": self.scope_channel,
            "topic_key": self.topic_key,
            "title": self.title,
            "body": self.body,
            "timestamp": self.timestamp,
            "repository_identity": self.repository_identity,
            "branch": self.branch,
            "commit_sha": self.commit_sha,
            "status": self.status,
            "confidence": self.confidence,
            "supersedes": self.supersedes,
            "source_tool": self.source_tool,
            "dedup_key": self.dedup_key,
            "code_refs": list(self.code_refs or []),
        }
        return env

    def envelope_json(self) -> str:
        """Compact single-line JSON envelope for storage."""
        return json.dumps(
            self.to_envelope(), separators=(",", ":"), ensure_ascii=False
        )

    def to_dict(self) -> dict:
        d = self.to_envelope()
        d.pop("v", None)
        if self.superseded_by is not None:
            d["superseded_by"] = self.superseded_by
        return d

    @staticmethod
    def from_envelope(data: Mapping) -> "Memory":
        if not isinstance(data, Mapping):
            raise MemoryValidationError("envelope must be a JSON object")
        if data.get("v") != ENVELOPE_VERSION:
            raise MemoryValidationError("unsupported envelope version")
        for required in (
            "memory_id",
            "project_id",
            "memory_type",
            "title",
            "timestamp",
            "repository_identity",
            "scope",
        ):
            if required not in data or data[required] in (None, ""):
                raise MemoryValidationError(
                    f"envelope missing required field: {required}"
                )
        confidence = data.get("confidence")
        return Memory(
            memory_id=str(data["memory_id"]),
            project_id=validate_project_id(str(data["project_id"])),
            workspace_id=(
                str(data["workspace_id"]) if data.get("workspace_id") else None
            ),
            agent_id=str(data.get("agent_id") or ""),
            agent_type=str(data.get("agent_type") or ""),
            memory_type=str(data["memory_type"]),
            title=str(data["title"]),
            body=str(data.get("body") or ""),
            timestamp=str(data["timestamp"]),
            repository_identity=validate_repository_identity(
                data["repository_identity"]
            ),
            scope=normalize_scope(str(data["scope"])),
            status=str(data.get("status") or "active"),
            branch=data.get("branch"),
            commit_sha=data.get("commit_sha"),
            confidence=float(confidence) if confidence is not None else None,
            supersedes=data.get("supersedes"),
            source_tool=str(data.get("source_tool") or "relinkra"),
            dedup_key=str(data.get("dedup_key") or ""),
            scope_channel=str(data.get("scope_channel") or ""),
            topic_key=str(data.get("topic_key") or ""),
            code_refs=validate_code_refs(
                data.get("code_refs"),
                project_id=validate_project_id(str(data["project_id"])),
            ),
        )


@dataclass
class QueryResult:
    memories: list = field(default_factory=list)
    skipped_malformed: int = 0

    def to_dict(self) -> dict:
        return {
            "memories": [m.to_dict() for m in self.memories],
            "count": len(self.memories),
            "skipped_malformed": self.skipped_malformed,
        }


# ---------------------------------------------------------------------------
# Service: policy over a MemoryStore
# ---------------------------------------------------------------------------


class MemoryService:
    """Enforces the R1C shared-memory policy over a raw MemoryStore.

    The store only knows how to persist and search raw records
    (title/content/type/project/scope/topic). All scoping, lifecycle,
    dedup, and redaction policy lives here.
    """

    def __init__(
        self,
        store: Any,
        clock: Callable[[], str] = _utcnow,
        id_generator: Callable[[], str] = new_memory_id,
    ):
        self.store = store
        self._clock = clock
        self._id_gen = id_generator

    # -- save -------------------------------------------------------------

    def save(
        self,
        *,
        project_id: str,
        memory_type: str,
        title: str,
        body: str,
        repository_identity: Any,
        scope: str = "project_shared",
        workspace_id: Optional[str] = None,
        agent_id: str = "",
        agent_type: str = "",
        branch: Optional[str] = None,
        commit_sha: Optional[str] = None,
        confidence: Optional[float] = None,
        source_tool: str = "relinkra",
        status: str = "active",
        supersedes: Optional[str] = None,
        code_refs: Optional[list] = None,
    ) -> tuple[Memory, bool, list[str]]:
        """Save a memory. Returns (memory, deduplicated, superseded_ids).

        Order of operations: validate -> redact -> dedup -> supersede
        same-topic active -> persist. ``code_refs`` (R1D) are validated
        through CodeReference and bound to this memory's project; they
        do NOT participate in the dedup key.
        """
        project_id = validate_project_id(project_id)
        scope = normalize_scope(scope)
        storage_type_for(memory_type)
        if status not in STATUSES:
            raise MemoryValidationError(f"unsupported status: {status!r}")
        repo = validate_repository_identity(repository_identity)
        refs = validate_code_refs(code_refs, project_id=project_id)
        if workspace_id is not None:
            workspace_id = validate_workspace_id(workspace_id)
        if not (title or "").strip():
            raise MemoryValidationError("title must be non-empty")
        if confidence is not None:
            confidence = float(confidence)
            if not 0.0 <= confidence <= 1.0:
                raise MemoryValidationError("confidence must be in [0.0, 1.0]")

        title = redact_text(title.strip())
        body = redact_text(body or "")
        channel = scope_channel_for(scope, workspace_id, agent_type)
        dedup_key = compute_dedup_key(
            project_id, scope, memory_type, title, body
        )

        if status == "active" and not supersedes:
            # Explicit supersession bypasses dedup: the new record must be
            # written even if its content duplicates an existing memory,
            # otherwise the supersede target would never be linked.
            existing = self._find_duplicate(project_id, channel, dedup_key)
            if existing is not None:
                return existing, True, []

        topic_key = topic_key_for(project_id, channel, memory_type, title)
        superseded_ids: list[str] = []
        if status == "active" and supersedes is None:
            prior = self._find_active_by_topic(project_id, topic_key)
            if prior is not None:
                supersedes = prior.memory_id
        if supersedes:
            superseded_ids.append(supersedes)

        memory = Memory(
            memory_id=self._id_gen(),
            project_id=project_id,
            workspace_id=workspace_id,
            agent_id=agent_id or "",
            agent_type=agent_type or "",
            memory_type=memory_type,
            title=title,
            body=body,
            timestamp=self._clock(),
            repository_identity=repo,
            scope=scope,
            status=status,
            branch=branch,
            commit_sha=commit_sha,
            confidence=confidence,
            supersedes=supersedes,
            source_tool=source_tool,
            dedup_key=dedup_key,
            scope_channel=channel,
            topic_key=topic_key,
            code_refs=refs,
        )
        self.store.save_record(
            title=title,
            content=memory.envelope_json(),
            storage_type=STORAGE_TYPE_MAP[memory_type],
            project=project_id,
            scope=ENGRAM_SCOPE,
            topic_key=topic_key,
        )
        return memory, False, superseded_ids

    def supersede(
        self,
        *,
        memory_id: str,
        project_id: str,
        title: Optional[str] = None,
        body: Optional[str] = None,
        obsolete: bool = False,
        agent_id: str = "",
        source_tool: str = "relinkra",
        code_refs: Optional[list] = None,
    ) -> tuple[Memory, list[str]]:
        """Supersede an existing memory with new content, or obsolete it.

        History is never deleted: the old record stays in the store and is
        excluded from default retrieval by policy. Code refs carry over
        from the target unless ``code_refs`` is given explicitly.
        """
        project_id = validate_project_id(project_id)
        target = self._find_by_id(project_id, memory_id)
        if target is None:
            raise MemoryNotFoundError(f"unknown memory_id: {memory_id}")
        refs = target.code_refs if code_refs is None else code_refs
        if obsolete:
            memory, _, superseded = self.save(
                project_id=project_id,
                memory_type=target.memory_type,
                title=target.title,
                body="",
                repository_identity=target.repository_identity,
                scope=target.scope,
                workspace_id=target.workspace_id,
                agent_id=agent_id or target.agent_id,
                agent_type=target.agent_type,
                branch=target.branch,
                commit_sha=target.commit_sha,
                source_tool=source_tool,
                status="obsolete",
                supersedes=target.memory_id,
                code_refs=refs,
            )
            return memory, superseded
        if title is None and body is None and code_refs is None:
            raise MemoryValidationError(
                "supersede requires new --title/--content or --obsolete"
            )
        memory, _, superseded = self.save(
            project_id=project_id,
            memory_type=target.memory_type,
            title=title if title is not None else target.title,
            body=body if body is not None else target.body,
            repository_identity=target.repository_identity,
            scope=target.scope,
            workspace_id=target.workspace_id,
            agent_id=agent_id or target.agent_id,
            agent_type=target.agent_type,
            branch=target.branch,
            commit_sha=target.commit_sha,
            confidence=target.confidence,
            source_tool=source_tool,
            status="active",
            supersedes=target.memory_id,
            code_refs=refs,
        )
        return memory, superseded

    # -- query ------------------------------------------------------------

    def query(
        self,
        *,
        project_id: str,
        scope: str = "project_shared",
        workspace_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        text: Optional[str] = None,
        memory_type: Optional[str] = None,
        include_history: bool = False,
        limit: int = 50,
    ) -> QueryResult:
        """Scope-policy query. project_id is mandatory — no cross-project
        leakage.

        - project_shared  -> only the shared channel
        - workspace_local -> shared channel + that workspace's channel
        - agent_private   -> ONLY the requested agent_type's channel
        """
        project_id = validate_project_id(project_id)
        scope = normalize_scope(scope)
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
        channels = self._visible_channels(scope, workspace_id, agent_type)

        search_text = (text or "").strip() or ENVELOPE_VERSION
        # Request a fixed, sufficiently large store page independent of the
        # user limit; filtering below must not starve visible results.
        records = self.store.search_records(
            query=search_text,
            project=project_id,
            limit=STORE_PAGE_LIMIT,
        )
        memories, skipped = self._parse_envelopes(records, project_id)
        visible = [m for m in memories if m.scope_channel in channels]
        if memory_type:
            storage_type_for(memory_type)
            visible = [m for m in visible if m.memory_type == memory_type]
        visible.sort(key=lambda m: (m.timestamp, m.memory_id))
        visible = self._apply_lifecycle(visible, include_history)
        if not include_history:
            visible = visible[-limit:]
        return QueryResult(memories=visible, skipped_malformed=skipped)

    def get(
        self, *, project_id: str, memory_id: str
    ) -> Optional[Memory]:
        project_id = validate_project_id(project_id)
        return self._find_by_id(project_id, memory_id)

    # -- internals --------------------------------------------------------

    def _visible_channels(
        self,
        scope: str,
        workspace_id: Optional[str],
        agent_type: Optional[str],
    ) -> set:
        if scope == "project_shared":
            return {"shared"}
        if scope == "workspace_local":
            if not workspace_id:
                raise MemoryValidationError(
                    "workspace query requires workspace_id"
                )
            return {"shared", scope_channel_for(scope, workspace_id)}
        if not agent_type or not str(agent_type).strip():
            raise MemoryValidationError(
                "agent_private query requires a matching agent_type"
            )
        return {scope_channel_for(scope, agent_type=agent_type)}

    def _parse_envelopes(
        self, records: list, project_id: str
    ) -> tuple[list[Memory], int]:
        memories: list[Memory] = []
        skipped = 0
        for record in records:
            try:
                data = json.loads(record.content)
                memory = Memory.from_envelope(data)
            except (ValueError, TypeError, MemoryValidationError):
                skipped += 1
                continue
            if memory.project_id != project_id:
                continue
            memories.append(memory)
        return memories, skipped

    def _apply_lifecycle(
        self, memories: list[Memory], include_history: bool
    ) -> list[Memory]:
        if include_history:
            superseded_ids = {
                m.supersedes for m in memories if m.supersedes
            }
            for m in memories:
                if m.memory_id in superseded_ids:
                    m.superseded_by = next(
                        (
                            x.memory_id
                            for x in memories
                            if x.supersedes == m.memory_id
                        ),
                        None,
                    )
            return memories
        superseded_ids = {m.supersedes for m in memories if m.supersedes}
        obsolete_topics: set[str] = set()
        by_topic: dict[str, list[Memory]] = {}
        for m in memories:
            by_topic.setdefault(m.topic_key, []).append(m)
        for topic, group in by_topic.items():
            head = max(group, key=lambda m: (m.timestamp, m.memory_id))
            for m in group:
                if m.memory_id != head.memory_id:
                    superseded_ids.add(m.memory_id)
            if head.status == "obsolete":
                obsolete_topics.add(topic)
        return [
            m
            for m in memories
            if m.status == "active"
            and m.memory_id not in superseded_ids
            and m.topic_key not in obsolete_topics
        ]

    def _search_project(self, project_id: str, text: str) -> list[Memory]:
        records = self.store.search_records(
            query=text, project=project_id, limit=STORE_PAGE_LIMIT
        )
        memories, _ = self._parse_envelopes(records, project_id)
        return memories

    def _find_duplicate(
        self, project_id: str, channel: str, dedup_key: str
    ) -> Optional[Memory]:
        for m in self._search_project(project_id, dedup_key):
            if (
                m.dedup_key == dedup_key
                and m.scope_channel == channel
                and m.status == "active"
            ):
                return m
        return None

    def _find_active_by_topic(
        self, project_id: str, topic_key: str
    ) -> Optional[Memory]:
        candidates = [
            m
            for m in self._search_project(project_id, ENVELOPE_VERSION)
            if m.topic_key == topic_key and m.status == "active"
        ]
        if not candidates:
            return None
        active = self._apply_lifecycle(candidates, include_history=False)
        if not active:
            return None
        return max(active, key=lambda m: (m.timestamp, m.memory_id))

    def _find_by_id(self, project_id: str, memory_id: str) -> Optional[Memory]:
        for m in self._search_project(project_id, ENVELOPE_VERSION):
            if m.memory_id == memory_id:
                return m
        return None
