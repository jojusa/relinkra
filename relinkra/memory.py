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

# memory_id is ``mem_`` + secrets.token_hex(8), i.e. 16 hex characters —
# NOT the 32 used by ref_/pkt_/hof_ ids. The upper bound leaves room for
# the generator to widen without invalidating stored handoffs.
MEMORY_ID_RE = re.compile(r"^mem_[0-9a-f]{16,64}$")

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

_PRIVATE_KEY_HEADER = r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
_PRIVATE_KEY_TRAILER = r"-----END [A-Z0-9 ]*PRIVATE KEY-----"
_BEGIN_PRIVATE_KEY_RE = re.compile(_PRIVATE_KEY_HEADER)
_PRIVATE_KEY_RE = re.compile(
    _PRIVATE_KEY_HEADER + r".*?" + _PRIVATE_KEY_TRAILER,
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

# M6: explicit ASCII scheme/domain alphabets for the anchored URL scan. The
# sets mirror the regex character classes exactly (``[A-Za-z]`` start, then
# ``[A-Za-z0-9+.-]``); membership tests in a frozenset are O(1).
_URL_SCHEME_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+.-"
)
_URL_SCHEME_START_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)


def _redact_private_key_blocks(text: str) -> str:
    """Redact PEM private-key blocks in linear time (M6).

    Byte-identical to ``_PRIVATE_KEY_RE.sub(_REDACTED, text)``, but bounded:
    ``re.sub`` re-attempts the pattern at every ``-----BEGIN`` marker, and
    each attempt without a following ``-----END`` lazily expands to the end
    of the text before failing, so K markers cost O(K * N). Anchoring the
    scan makes the total work O(N):

    - candidates are visited left to right with ``str.find`` over the
      ``-----BEGIN`` literal;
    - a candidate whose header does not match costs only its own bounded
      header scan (the ``[A-Z0-9 ]*`` runs between markers are disjoint);
    - the first candidate whose full match fails proves that no matching
      ``-----END`` header exists after it, so every later candidate must
      fail too and the scan stops — at most one failed expansion ever runs;
    - successful expansions stay inside the replaced span, and the scan
      resumes after it, exactly like ``re.sub``.

    A match is only skipped when the regex itself cannot match there, so no
    truncation, early slicing, or length cap is involved.
    """
    if "-----BEGIN" not in text or "-----END" not in text:
        return text
    pos = 0  # last emitted index (flush origin)
    scan = 0  # search cursor, may skip candidates ahead of pos
    parts = None
    while True:
        begin = text.find("-----BEGIN", scan)
        if begin < 0:
            break
        if _BEGIN_PRIVATE_KEY_RE.match(text, begin) is None:
            scan = begin + 1
            continue
        match = _PRIVATE_KEY_RE.match(text, begin)
        if match is None:
            break
        if parts is None:
            parts = []
        parts.append(text[pos:match.start()])
        parts.append(_REDACTED)
        pos = match.end()
        scan = pos
    if parts is None:
        return text
    parts.append(text[pos:])
    return "".join(parts)


def _redact_url_passwords(text: str) -> str:
    """Redact URL userinfo passwords in linear time (M6).

    Byte-identical to
    ``_URL_PASSWORD_RE.sub(lambda m: f"{m.group(1)}...{_REDACTED}@", text)``,
    but bounded: the pattern starts with an unbounded greedy scheme class
    and is not anchored by a literal, so ``re.sub`` retries it at every
    character of a long unbroken ``[A-Za-z0-9+.-]`` run, and each retry
    scans to the end of the run before failing — O(N^2) for a single huge
    word, hash, base64 blob, or marker repetition.

    A match must contain ``://``, and its scheme is exactly the maximal
    run of scheme characters immediately before that ``://``; the pattern
    can only match starting at the first ASCII letter of that run (every
    later start shares the identical suffix after ``://``, so if the first
    fails they all fail). Anchoring the scan to ``str.find("://")`` and
    that first letter therefore visits each candidate exactly once and
    costs O(N) overall: the runs before successive ``://`` occurrences are
    disjoint because ``:`` is not a scheme character.

    No truncation, early slicing, or length cap is involved: the result is
    identical to the regex pass for every input, including schemes of any
    length.
    """
    pos = 0  # last emitted index (flush origin)
    scan = 0  # search cursor, may skip candidates ahead of pos
    parts = None
    while True:
        stop = text.find("://", scan)
        if stop < 0:
            break
        # Walk back over the scheme run, remembering the leftmost letter.
        anchor = -1
        index = stop
        while index > 0:
            char = text[index - 1]
            if char not in _URL_SCHEME_CHARS:
                break
            index -= 1
            if char in _URL_SCHEME_START_CHARS:
                anchor = index
        match = None
        if anchor >= 0:
            match = _URL_PASSWORD_RE.match(text, anchor)
        if match is None:
            scan = stop + 1
            continue
        if parts is None:
            parts = []
        parts.append(text[pos:match.start()])
        parts.append(f"{match.group(1)}{match.group(2)}:{_REDACTED}@")
        pos = match.end()
        scan = pos
    if parts is None:
        return text
    parts.append(text[pos:])
    return "".join(parts)


def redact_text(text: str) -> str:
    """Best-effort secret redaction applied before persistence.

    Handles bearer tokens, common API-key prefixes, passwords in URLs,
    PEM private key blocks, and generic ``token=`` / ``api_key=`` /
    ``password=`` style key-values. This is defense in depth, not a
    guarantee: do not put secrets in memories.

    M6: every pass runs in time linear in the input length. The PEM-block
    and URL-credential passes are anchored scans (see the helpers above)
    rather than backtracking ``re.sub`` passes, so an arbitrarily large
    attacker-controlled title cannot make redaction superlinear. Output is
    byte-identical to the historical regex passes: no truncation, no early
    slicing, no reduced redaction coverage.
    """
    if not isinstance(text, str) or not text:
        return text
    out = _redact_private_key_blocks(text)
    out = _redact_url_passwords(out)
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
# Title normalization (RIC-03: title structural-injection defense)
# ---------------------------------------------------------------------------


def normalize_title(title: Any) -> str:
    """Flatten an untrusted memory title to a single logical line.

    RIC-03: a memory title is DATA, never packet structure. A title that
    contains a line break would start a new Markdown line inside a
    rendered ContextPacket and counterfeit packet-level headings, fences,
    list items, or metadata lines. Unicode ``\\s`` matches every
    separator ``str.splitlines`` treats as a break (LF, CRLF, CR, NEL,
    LINE/PARAGRAPH SEPARATOR, and the C0 file/ group/record/unit
    separators), so collapsing whitespace runs to one space makes a title
    physically unable to leave its own line while preserving ordinary
    wording and punctuation.

    Renderers must still apply this defensively at render time: memories
    saved before this policy may hold legacy multiline titles and stored
    memory history is never rewritten.

    Deliberately NOT a length cap: existing save validation rejects
    invalid titles rather than truncating them, and a single-line title
    cannot create packet structure at any length.
    """
    text = title if isinstance(title, str) else str(title)
    return re.sub(r"\s+", " ", text).strip()


# ---------------------------------------------------------------------------
# memory_id presentation (M5B: id structural-injection defense)
# ---------------------------------------------------------------------------


def display_memory_id(memory_id: Any) -> str:
    """Render-safe single-line presentation of a stored memory_id.

    M5B: a memory_id is source-authoritative IDENTITY, and it is never
    rewritten: ``Memory.from_envelope`` deliberately accepts non-canonical
    raw/legacy ids, ``get``/history/supersede keep addressing the exact
    stored value, and this helper is NOT applied to any stored or
    serialized field.  But when an id is rendered into ContextPacket
    Markdown it is DATA, not structure: any line separator inside the id
    would start a new column-0 Markdown line and counterfeit packet-level
    headings, sibling list items, fenced blocks, metadata lines, or fake
    provenance sections.

    The defense is render-time only and purely structural: Unicode
    ``\\s`` covers every separator ``str.splitlines`` treats as a break
    (LF, CRLF, CR, NEL, LINE/PARAGRAPH SEPARATOR, and the C0 file/group/
    record/unit separators), so collapsing whitespace runs to one space
    and stripping the edges makes the rendered form physically unable to
    leave its own line.  Canonical ``mem_`` ids — and every other
    already-single-line id — pass through byte-identical; a hostile id is
    neutralized in place without being transformed into a different valid
    id, and a safe rendered form never claims the underlying id is
    canonical.

    The same flattening is applied at render time to composite evidence
    tokens that EMBED a memory_id (``section:<id>:<occurrence>`` refs and
    contradiction subjects), so an embedded hostile id cannot break out
    through the explainability rendering either.  Non-string values keep
    the exact text the renderer would have produced before (``str()``).
    """
    text = memory_id if isinstance(memory_id, str) else str(memory_id)
    return re.sub(r"\s+", " ", text).strip()


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


def physical_topic_key_for(logical_topic_key: str, memory_id: str) -> str:
    """Derive an immutable Engram storage key for one logical memory.

    Engram treats ``topic_key`` as an upsert key.  Relinkra keeps the
    logical topic in the envelope for lifecycle policy, but appends the
    generated memory id to the backend key so every new write gets its own
    physical observation.  The id is generated before persistence and is
    therefore stable for retries of the same in-memory save transaction.
    """
    if not logical_topic_key or not memory_id:
        raise MemoryValidationError("logical_topic_key and memory_id are required")
    return f"{logical_topic_key}/memory/{memory_id}"


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
        # TSC-02: an accepted envelope must carry a KNOWN logical memory
        # type and status. Only Relinkra writes ``rlkmem1`` envelopes, so
        # these narrow a forged/unknown record out without any legacy-data
        # compatibility cost. ``memory_id`` is deliberately NOT shape-
        # checked here: legacy observations with non-canonical ids stay
        # readable (pinned by the non-canonical-id compatibility test),
        # and ``get()`` already validates the REQUESTED id shape.
        memory_type = str(data["memory_type"])
        storage_type_for(memory_type)
        status = str(data.get("status") or "active")
        if status not in STATUSES:
            raise MemoryValidationError(f"unsupported memory status: {status!r}")
        confidence = data.get("confidence")
        return Memory(
            memory_id=str(data["memory_id"]),
            project_id=validate_project_id(str(data["project_id"])),
            workspace_id=(
                str(data["workspace_id"]) if data.get("workspace_id") else None
            ),
            agent_id=str(data.get("agent_id") or ""),
            agent_type=str(data.get("agent_type") or ""),
            memory_type=memory_type,
            title=str(data["title"]),
            body=str(data.get("body") or ""),
            timestamp=str(data["timestamp"]),
            repository_identity=validate_repository_identity(
                data["repository_identity"]
            ),
            scope=normalize_scope(str(data["scope"])),
            status=status,
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
    #: Records the transport itself flagged as cut off (CLI display
    #: truncation). Counted separately so a degraded read channel is
    #: reported honestly instead of inflating the malformed counter.
    skipped_truncated: int = 0
    #: Additive retrieval accounting.  The adapter sets these when a capped
    #: backend page was observed; exact memory_get remains independent.
    backend_window_complete: bool = True
    backend_limit: Optional[int] = None
    retrieval_scope: str = "backend_window"
    retrieval_complete: bool = True
    #: Machine-readable details explaining an incomplete or reconciled
    #: retrieval.  Adapters may leave these empty for ordinary backend pages.
    retrieval_diagnostic: Any = None
    retrieval_diagnostics: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "memories": [m.to_dict() for m in self.memories],
            "count": len(self.memories),
            "skipped_malformed": self.skipped_malformed,
            "skipped_truncated": self.skipped_truncated,
            "backend_window_complete": self.backend_window_complete,
            "backend_limit": self.backend_limit,
            "retrieval_scope": self.retrieval_scope,
            "retrieval_complete": self.retrieval_complete,
            "retrieval_diagnostic": self.retrieval_diagnostic,
            "retrieval_diagnostics": list(self.retrieval_diagnostics),
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

        # RIC-03: a title is single-line data. Normalize before redaction
        # so multi-line secret patterns still match as continuous text.
        title = redact_text(normalize_title(title))
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
        if supersedes:
            # Explicit supersession normally bypasses content dedup so a
            # replacement can intentionally reuse an existing body.  A
            # retried identical supersede is the one exception: return the
            # already-written replacement instead of creating a second link.
            retry = self._find_supersede_retry(
                project_id,
                channel,
                memory_type,
                topic_key,
                dedup_key,
                supersedes,
                status,
            )
            if retry is not None:
                return retry, True, []
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
            topic_key=physical_topic_key_for(topic_key, memory.memory_id),
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
        include_handoff_mirrors: bool = True,
        limit: int = 50,
    ) -> QueryResult:
        """Scope-policy query. project_id is mandatory — no cross-project
        leakage.

        - project_shared  -> only the shared channel
        - workspace_local -> shared channel + that workspace's channel
        - agent_private   -> ONLY the requested agent_type's channel

        Results are a deterministic total order for identical inputs:
        ascending ``(timestamp, memory_id)`` — the id breaks timestamp
        ties — sliced to the newest ``limit`` records after lifecycle
        filtering. The backend candidate window is retrieved first, then
        visibility/type/lifecycle policy is applied, and only then is the
        caller limit cut. Engram 1.20.0 has no usable cursor/offset and caps
        search responses at 20; the adapter uses its complete export path when
        that cap is reached. If export is unavailable, the additive retrieval
        metadata marks the result partial instead of implying that omitted
        matches do not exist.

        ``include_handoff_mirrors=False`` hides handoff-type mirror
        records from the result (handoff state is authoritative through
        the handoff service, which queries this layer with the mirror
        included). Literal flag: ``False`` combined with
        ``memory_type="handoff"`` yields an empty result.
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
        needs_head_validation = not include_history and bool((text or "").strip())
        head_records = None
        head_retrieval = {}
        if needs_head_validation:
            # Fetch lifecycle heads before the caller's text query so the
            # backend-facing query remains the requested/narrow predicate.
            head_records = self.store.search_records(
                query=ENVELOPE_VERSION,
                project=project_id,
                limit=STORE_PAGE_LIMIT,
            )
            head_retrieval = getattr(self.store, "last_search_metadata", {}) or {}
        # Request a fixed, sufficiently large store page independent of the
        # user limit; filtering below must not starve visible results.
        records = self.store.search_records(
            query=search_text,
            project=project_id,
            limit=STORE_PAGE_LIMIT,
        )
        retrieval = getattr(self.store, "last_search_metadata", {}) or {}
        memories, skipped_malformed, skipped_truncated = self._parse_envelopes(
            records, project_id
        )
        visible = [m for m in memories if m.scope_channel in channels]
        if memory_type:
            storage_type_for(memory_type)
            visible = [m for m in visible if m.memory_type == memory_type]
        if not include_handoff_mirrors:
            visible = [m for m in visible if m.memory_type != "handoff"]
        if (
            not include_history
            and not needs_head_validation
            and not bool(retrieval.get("retrieval_complete", True))
        ):
            # The match-all candidate page is itself the head view in this
            # mode; a partial page cannot safely establish current state.
            visible = []
        # A text-narrow current query cannot decide lifecycle from its
        # candidate page alone: a successor may not contain the searched
        # text. Resolve all candidate logical heads in one bounded retrieval
        # before returning any current result. If that head view is partial,
        # fail closed rather than presenting a possibly superseded memory as
        # current. Historical queries intentionally retain their existing
        # candidate-window semantics and exact gets remain addressable.
        if needs_head_validation and visible:
            head_memories, head_malformed, head_truncated = self._parse_envelopes(
                head_records or [], project_id
            )
            retrieval_complete = bool(
                retrieval.get("retrieval_complete", True)
            ) and bool(head_retrieval.get("retrieval_complete", True))
            if not retrieval_complete:
                visible = []
            else:
                head_visible = [
                    m for m in head_memories if m.scope_channel in channels
                ]
                if memory_type:
                    head_visible = [m for m in head_visible if m.memory_type == memory_type]
                if not include_handoff_mirrors:
                    head_visible = [m for m in head_visible if m.memory_type != "handoff"]
                active_ids = {
                    m.memory_id
                    for m in self._apply_lifecycle(head_visible, include_history=False)
                }
                visible = [m for m in visible if m.memory_id in active_ids]
            retrieval = {
                **retrieval,
                "retrieval_complete": retrieval_complete,
                "backend_window_complete": bool(
                    retrieval.get("backend_window_complete", True)
                ) and bool(head_retrieval.get("backend_window_complete", True)),
            }
            # Head validation is an internal lifecycle check. Its malformed
            # rows must not be double-counted in the caller-facing search
            # diagnostics, which describe the requested text retrieval.
        visible.sort(key=lambda m: (m.timestamp, m.memory_id))
        visible = self._apply_lifecycle(visible, include_history)
        if not include_history:
            visible = visible[-limit:]
        return QueryResult(
            memories=visible,
            skipped_malformed=skipped_malformed,
            skipped_truncated=skipped_truncated,
            backend_window_complete=bool(
                retrieval.get("backend_window_complete", True)
            ),
            backend_limit=retrieval.get("backend_limit"),
            retrieval_scope=str(
                retrieval.get("retrieval_scope", "backend_window")
            ),
            retrieval_complete=bool(retrieval.get("retrieval_complete", True)),
            retrieval_diagnostic=retrieval.get("retrieval_diagnostic"),
            retrieval_diagnostics=(
                list(retrieval.get("retrieval_diagnostics", []))
                if isinstance(retrieval.get("retrieval_diagnostics", []), list)
                else [retrieval.get("retrieval_diagnostics")]
            ),
        )

    def get(
        self,
        *,
        project_id: str,
        memory_id: str,
        diagnostics: Optional[dict] = None,
    ) -> Optional[Memory]:
        """Exact lookup by memory_id within one project. No fuzzy fallback.

        The id is queried against the store directly first: the stored
        envelope always contains the id, so a targeted search reaches the
        record without depending on the record being inside the match-all
        page window — a busy project pushes older records out of that
        fixed page, which would report a false ``not_found``. The
        standard match-all page runs as a fallback for stores whose
        search tokenization does not surface the raw id (and for ids
        outside the canonical ``mem_`` shape). Only an exact id match is
        ever returned; lifecycle status does not hide a record here
        (superseded history stays addressable); cross-project records
        are dropped by policy.

        When ``diagnostics`` is a dict it is filled with honest skip
        counters so a caller can tell clean absence from a page the
        transport could not read whole.
        """
        project_id = validate_project_id(project_id)
        memory_id = (memory_id or "").strip()
        if diagnostics is not None:
            diagnostics.clear()
        if not memory_id:
            return None
        queries = []
        if MEMORY_ID_RE.match(memory_id):
            queries.append(memory_id)
        queries.append(ENVELOPE_VERSION)
        found: Optional[Memory] = None
        skipped_truncated = 0
        skipped_malformed = 0
        for query in queries:
            records = self.store.search_records(
                query=query, project=project_id, limit=STORE_PAGE_LIMIT
            )
            memories, malformed, truncated = self._parse_envelopes(
                records, project_id
            )
            skipped_malformed += malformed
            skipped_truncated += truncated
            for memory in memories:
                if memory.memory_id == memory_id:
                    found = memory
                    break
            if found is not None:
                break
        if diagnostics is not None:
            diagnostics["skipped_malformed"] = skipped_malformed
            diagnostics["skipped_truncated"] = skipped_truncated
        return found

    def visible_channels(
        self,
        scope: str,
        workspace_id: Optional[str] = None,
        agent_type: Optional[str] = None,
    ) -> set:
        """Scope-policy channel visibility for one query context."""
        return self._visible_channels(
            normalize_scope(scope), workspace_id, agent_type
        )

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
    ) -> tuple[list[Memory], int, int]:
        """Parse raw records into memories plus two honest skip counters.

        ``skipped_malformed`` counts data that is broken on its own
        terms; ``skipped_truncated`` counts records the transport itself
        flagged as cut off. Cross-project records are dropped silently —
        that is policy, not corruption.
        """
        memories: list[Memory] = []
        skipped_malformed = 0
        skipped_truncated = 0
        for record in records:
            try:
                data = json.loads(record.content)
                memory = Memory.from_envelope(data)
            except (ValueError, TypeError, MemoryValidationError):
                if getattr(record, "truncated", False):
                    skipped_truncated += 1
                else:
                    skipped_malformed += 1
                continue
            if memory.project_id != project_id:
                continue
            memories.append(memory)
        return memories, skipped_malformed, skipped_truncated

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
        memories, _, _ = self._parse_envelopes(records, project_id)
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

    def _find_supersede_retry(
        self,
        project_id: str,
        channel: str,
        memory_type: str,
        topic_key: str,
        dedup_key: str,
        supersedes: str,
        status: str,
    ) -> Optional[Memory]:
        """Find an exact replacement already persisted for a retry.

        This deliberately matches the explicit target plus the complete
        logical identity, rather than applying ordinary content dedup.  Thus
        explicit supersession still writes when the target or replacement
        differs, while an identical retry is idempotent.
        """
        candidates = self._search_project(project_id, ENVELOPE_VERSION)
        matches = [
            m
            for m in candidates
            if m.scope_channel == channel
            and m.memory_type == memory_type
            and m.topic_key == topic_key
            and m.dedup_key == dedup_key
            and m.supersedes == supersedes
            and m.status == status
        ]
        if not matches:
            return None
        return max(matches, key=lambda m: (m.timestamp, m.memory_id))

    def _find_by_id(self, project_id: str, memory_id: str) -> Optional[Memory]:
        # Same exact lookup as get(): the targeted id query keeps
        # supersede targets reachable on projects larger than one store
        # page, where a match-all scan would report a false unknown id.
        return self.get(project_id=project_id, memory_id=memory_id)
