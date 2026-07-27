"""Read-only git intelligence (R2): data models, subprocess runner, pure parsers.

Batch B1 scope: foundation only (limits, typed errors, data models,
``_GitRunner``, pure ``-z`` parsers). The collection service lands in B2.

Read-only guarantee: ``_GitRunner`` spawns ONLY the allowlisted verbs in
``READ_ONLY_VERBS`` via argv arrays — no shell, explicit cwd, explicit
timeout, UTF-8 decoding. Any other verb raises before spawn, so mutating
git commands are unreachable from every public API.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from relinkra.memory import redact_text, sanitize_error
from relinkra.code_reference import normalize_repo_path

# ---------------------------------------------------------------------------
# Centralized limits (design §1)
# ---------------------------------------------------------------------------

GIT_TIMEOUT_SECONDS = 5
GIT_MAX_COMMITS = 100
GIT_DEFAULT_COMMITS = 10
GIT_TOP_COCHANGE = 10
GIT_COCHANGE_SCAN = 100
GIT_CHANGED_PATHS_PER_COMMIT = 50
GIT_SNIPPET_MAX_CHARS = 400
GIT_FILE_HISTORY_MAX = 100

_SHORT_SHA_LEN = 7
_HEX_SHA_LEN = 40

# The ONLY git verbs this module may ever spawn (read-only guarantee).
# rev-list is deliberately excluded: v1 computes no ahead/behind and needs
# no root-commit listing, so the allowlist stays minimal.
READ_ONLY_VERBS = frozenset({"status", "log", "diff", "rev-parse", "show"})

# ---------------------------------------------------------------------------
# Typed errors — messages are always sanitized (no secrets leak to callers)
# ---------------------------------------------------------------------------


class GitError(Exception):
    """Base for all git intelligence errors. Message is sanitized."""

    def __init__(self, message: str = "") -> None:
        super().__init__(sanitize_error(str(message)))


class GitUnavailable(GitError):
    """git binary missing (FileNotFoundError) or invocation timed out."""


class NotGitRepository(GitError):
    """Path is not inside a git working tree (rev-parse probe failed)."""


class GitCommandError(GitError):
    """A spawned git command failed, or a verb was rejected pre-spawn."""

    def __init__(
        self,
        message: str = "",
        *,
        verb: Optional[str] = None,
        returncode: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        self.verb = verb
        self.returncode = returncode


class GitParseError(GitError):
    """git output could not be parsed into typed facts."""


# ---------------------------------------------------------------------------
# Data models (frozen; to_dict/from_dict on all serialized ones)
# ---------------------------------------------------------------------------


class GitFileChangeState(str, Enum):
    UNCHANGED = "unchanged"
    STAGED = "staged"
    UNSTAGED = "unstaged"
    UNTRACKED = "untracked"
    CONFLICTED = "conflicted"


def _str_tuple(value: Any) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    raise TypeError(f"expected a list/tuple of strings, got {type(value).__name__}")


@dataclass(frozen=True)
class GitCapabilities:
    """Detection facts. ``repository_root`` is service-side ONLY: it is never
    serialized into portable output (local diagnostics channel exclusively)."""

    git_available: bool
    git_version: Optional[str]
    repository_detected: bool
    is_bare: bool
    head_available: bool
    repository_root: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "git_available": self.git_available,
            "git_version": self.git_version,
            "repository_detected": self.repository_detected,
            "is_bare": self.is_bare,
            "head_available": self.head_available,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GitCapabilities":
        return cls(
            git_available=bool(data.get("git_available", False)),
            git_version=data.get("git_version"),
            repository_detected=bool(data.get("repository_detected", False)),
            is_bare=bool(data.get("is_bare", False)),
            head_available=bool(data.get("head_available", False)),
        )


@dataclass(frozen=True)
class GitStatusEntry:
    """One porcelain v1 record. ``old_path`` is the rename/copy source."""

    path: str
    index_status: str
    worktree_status: str
    old_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "index_status": self.index_status,
            "worktree_status": self.worktree_status,
            "old_path": self.old_path,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GitStatusEntry":
        return cls(
            path=str(data["path"]),
            index_status=str(data["index_status"]),
            worktree_status=str(data["worktree_status"]),
            old_path=data.get("old_path"),
        )


@dataclass(frozen=True)
class GitWorkingTree:
    clean: bool
    staged: Tuple[str, ...]
    unstaged: Tuple[str, ...]
    untracked: Tuple[str, ...]
    deleted: Tuple[str, ...]
    conflicted: Tuple[str, ...]
    renamed: Tuple[Tuple[str, str], ...]  # (old, new) pairs

    def to_dict(self) -> Dict[str, Any]:
        return {
            "clean": self.clean,
            "staged": list(self.staged),
            "unstaged": list(self.unstaged),
            "untracked": list(self.untracked),
            "deleted": list(self.deleted),
            "conflicted": list(self.conflicted),
            "renamed": [[old, new] for old, new in self.renamed],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GitWorkingTree":
        return cls(
            clean=bool(data.get("clean", False)),
            staged=_str_tuple(data.get("staged")),
            unstaged=_str_tuple(data.get("unstaged")),
            untracked=_str_tuple(data.get("untracked")),
            deleted=_str_tuple(data.get("deleted")),
            conflicted=_str_tuple(data.get("conflicted")),
            renamed=tuple(
                (str(pair[0]), str(pair[1])) for pair in data.get("renamed", ())
            ),
        )


@dataclass(frozen=True)
class GitHeadFacts:
    """HEAD identity. author_name only — email is NEVER emitted."""

    head_sha: str
    short_head_sha: str
    branch: Optional[str]
    detached: bool
    committed_at: str  # ISO 8601 UTC
    author_name: str
    subject: str  # redacted at parse boundary
    parents: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "head_sha": self.head_sha,
            "short_head_sha": self.short_head_sha,
            "branch": self.branch,
            "detached": self.detached,
            "committed_at": self.committed_at,
            "author_name": self.author_name,
            "subject": self.subject,
            "parents": list(self.parents),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GitHeadFacts":
        return cls(
            head_sha=str(data["head_sha"]),
            short_head_sha=str(data["short_head_sha"]),
            branch=data.get("branch"),
            detached=bool(data.get("detached", False)),
            committed_at=str(data["committed_at"]),
            author_name=str(data["author_name"]),
            subject=str(data["subject"]),
            parents=_str_tuple(data.get("parents")),
        )


@dataclass(frozen=True)
class GitRepositoryState:
    """ahead/behind are reserved and always None in v1 (no network)."""

    head_sha: Optional[str]
    short_head_sha: Optional[str]
    branch: Optional[str]
    detached: bool
    clean: bool
    staged_count: int
    unstaged_count: int
    untracked_count: int
    conflicted_count: int
    ahead: Optional[int] = None
    behind: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "head_sha": self.head_sha,
            "short_head_sha": self.short_head_sha,
            "branch": self.branch,
            "detached": self.detached,
            "clean": self.clean,
            "counts": {
                "staged": self.staged_count,
                "unstaged": self.unstaged_count,
                "untracked": self.untracked_count,
                "conflicted": self.conflicted_count,
            },
            "ahead": self.ahead,
            "behind": self.behind,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GitRepositoryState":
        counts = data.get("counts") or {}
        return cls(
            head_sha=data.get("head_sha"),
            short_head_sha=data.get("short_head_sha"),
            branch=data.get("branch"),
            detached=bool(data.get("detached", False)),
            clean=bool(data.get("clean", False)),
            staged_count=int(counts.get("staged", 0)),
            unstaged_count=int(counts.get("unstaged", 0)),
            untracked_count=int(counts.get("untracked", 0)),
            conflicted_count=int(counts.get("conflicted", 0)),
            ahead=data.get("ahead"),
            behind=data.get("behind"),
        )


@dataclass(frozen=True)
class GitDiffFact:
    path: str
    status: str  # added | modified | deleted | renamed
    staged: bool
    insertions: int
    deletions: int
    binary: bool
    old_path: Optional[str] = None
    snippet: Optional[str] = None  # opt-in only, bounded, redacted

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "status": self.status,
            "staged": self.staged,
            "insertions": self.insertions,
            "deletions": self.deletions,
            "binary": self.binary,
            "old_path": self.old_path,
            "snippet": self.snippet,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GitDiffFact":
        return cls(
            path=str(data["path"]),
            status=str(data["status"]),
            staged=bool(data.get("staged", False)),
            insertions=int(data.get("insertions", 0)),
            deletions=int(data.get("deletions", 0)),
            binary=bool(data.get("binary", False)),
            old_path=data.get("old_path"),
            snippet=data.get("snippet"),
        )


@dataclass(frozen=True)
class GitCommitFact:
    """Commit fact. Bodies are never collected."""

    sha: str
    short_sha: str
    committed_at: str  # ISO 8601 UTC
    author_name: str
    subject: str  # redacted at parse boundary
    parents: Tuple[str, ...]
    changed_paths: Tuple[str, ...]  # bounded by GIT_CHANGED_PATHS_PER_COMMIT

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sha": self.sha,
            "short_sha": self.short_sha,
            "committed_at": self.committed_at,
            "author_name": self.author_name,
            "subject": self.subject,
            "parents": list(self.parents),
            "changed_paths": list(self.changed_paths),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GitCommitFact":
        return cls(
            sha=str(data["sha"]),
            short_sha=str(data["short_sha"]),
            committed_at=str(data["committed_at"]),
            author_name=str(data["author_name"]),
            subject=str(data["subject"]),
            parents=_str_tuple(data.get("parents")),
            changed_paths=_str_tuple(data.get("changed_paths")),
        )


@dataclass(frozen=True)
class GitCoChangeFact:
    path: str
    shared_commit_count: int
    sampled_commit_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "shared_commit_count": self.shared_commit_count,
            "sampled_commit_count": self.sampled_commit_count,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GitCoChangeFact":
        return cls(
            path=str(data["path"]),
            shared_commit_count=int(data["shared_commit_count"]),
            sampled_commit_count=int(data["sampled_commit_count"]),
        )


# ---------------------------------------------------------------------------
# Internal parser record types (not serialized into packets)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NumstatEntry:
    path: str
    insertions: int
    deletions: int
    binary: bool
    old_path: Optional[str] = None


@dataclass(frozen=True)
class NameStatusEntry:
    path: str
    status: str  # added | modified | deleted | renamed
    old_path: Optional[str] = None


# ---------------------------------------------------------------------------
# Subprocess runner (adapter: argv array, no shell, explicit cwd/timeout, UTF-8)
# ---------------------------------------------------------------------------


class _GitRunner:
    """Spawn allowlisted read-only git verbs and return stdout.

    Mutating verbs are rejected BEFORE spawn, so they are unreachable from
    any public API. Degradation is typed: FileNotFoundError/TimeoutExpired
    -> GitUnavailable; rc != 0 on a rev-parse repo probe -> NotGitRepository;
    any other rc != 0 -> GitCommandError with a sanitized stderr message.
    """

    def __init__(self, executable: str = "git", timeout: int = GIT_TIMEOUT_SECONDS) -> None:
        self.executable = executable
        self.timeout = timeout

    def probe_version(self) -> str:
        """Return the installed git version string.

        Spawns exactly ``[git, --version]`` — a global no-op flag, NOT a
        repository verb, so the READ_ONLY_VERBS allowlist (which restricts
        repository commands) is untouched. There is no allowlisted verb
        that reports the version (``rev-parse --version`` merely echoes
        the flag), so this is the only safe probe.
        """
        try:
            result = subprocess.run(
                [self.executable, "--version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise GitUnavailable(
                f"git executable not found: {self.executable}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise GitUnavailable(
                f"git --version timed out after {self.timeout}s"
            ) from exc
        except OSError as exc:
            raise GitUnavailable(
                f"git --version failed to spawn: {exc.strerror or type(exc).__name__}"
            ) from exc
        if result.returncode != 0:
            raise GitUnavailable("git --version failed; binary unusable")
        out = result.stdout.strip()
        prefix = "git version "
        return out[len(prefix):] if out.startswith(prefix) else out

    def run(self, cwd, *argv: str) -> str:
        if not argv:
            raise GitCommandError("no git verb provided", verb=None, returncode=None)
        verb = argv[0]
        if verb not in READ_ONLY_VERBS:
            raise GitCommandError(
                f"git verb not allowed (read-only guarantee): {verb}",
                verb=verb,
                returncode=None,
            )
        try:
            result = subprocess.run(
                [self.executable, *argv],
                cwd=str(cwd),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise GitUnavailable(
                f"git executable not found: {self.executable}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise GitUnavailable(
                f"git {verb} timed out after {self.timeout}s"
            ) from exc
        except OSError as exc:
            raise GitUnavailable(
                f"git {verb} failed to spawn: {exc.strerror or type(exc).__name__}"
            ) from exc
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            if verb == "rev-parse":
                raise NotGitRepository(
                    stderr or f"not a git repository: {cwd}"
                )
            raise GitCommandError(
                stderr or f"git {verb} failed with code {result.returncode}",
                verb=verb,
                returncode=result.returncode,
            )
        return result.stdout


# ---------------------------------------------------------------------------
# Pure parsers (no subprocess — unit-tested with canned -z text)
#
# Wire formats (all NUL-delimited, matching git -z output):
#   porcelain v1 -z : "XY <path>\0" records; rename/copy is "XY <new>\0<old>\0"
#   log -z          : per commit: sha, committed_at, author_name, subject,
#                     parents (space-separated), then changed paths, and the
#                     record is terminated by one empty field
#   numstat -z      : "add\tdel\t<path>\0"; rename: "add\tdel\t\0<old>\0<new>\0";
#                     binary files use "-" counts
#   name-status -z  : "<code>\0<path>\0"; rename/copy: "<code><score>\0<old>\0<new>\0"
# Free text (subjects) is redacted at the parse boundary.
# ---------------------------------------------------------------------------


def _validate_sha(sha: str) -> str:
    if (
        not isinstance(sha, str)
        or len(sha) != _HEX_SHA_LEN
        or any(ch not in "0123456789abcdefABCDEF" for ch in sha)
    ):
        raise GitParseError(f"malformed commit sha: {sha!r}")
    return sha


def parse_porcelain_z(text: str) -> List[GitStatusEntry]:
    """Parse ``status --porcelain=v1 -z`` output into status entries."""
    if not isinstance(text, str):
        raise GitParseError("porcelain input must be text")
    entries: List[GitStatusEntry] = []
    tokens = text.split("\0")
    i = 0
    n = len(tokens)
    while i < n:
        token = tokens[i]
        i += 1
        if token == "":
            continue
        if len(token) < 4 or token[2] != " ":
            raise GitParseError(f"malformed porcelain v1 -z record: {token!r}")
        index_status, worktree_status, path = token[0], token[1], token[3:]
        old_path: Optional[str] = None
        if index_status in "RC" or worktree_status in "RC":
            if i >= n or tokens[i] == "":
                raise GitParseError("rename/copy record missing source path")
            old_path = tokens[i]
            i += 1
        entries.append(
            GitStatusEntry(
                path=path,
                index_status=index_status,
                worktree_status=worktree_status,
                old_path=old_path,
            )
        )
    return entries


def _parse_commit_record(tokens: List[str], i: int) -> Tuple[GitCommitFact, int]:
    n = len(tokens)
    if i + 5 > n:
        raise GitParseError("truncated log record header")
    sha, committed_at, author_name, subject, parents_raw = tokens[i : i + 5]
    i += 5
    _validate_sha(sha)
    if not committed_at:
        raise GitParseError("log record missing committed_at")
    # Real `log -z --name-only` output glues the FIRST changed path to the
    # parents field with "\n" (the message->names separator survives -z).
    # Split it back out; paths after the first are clean NUL-separated.
    parents_field, sep, first_path = parents_raw.partition("\n")
    paths: List[str] = []
    if sep and first_path:
        paths.append(first_path)
    while i < n and tokens[i] != "":
        if len(paths) < GIT_CHANGED_PATHS_PER_COMMIT:
            paths.append(tokens[i])
        i += 1
    if i < n and tokens[i] == "":
        i += 1  # consume record terminator
    return (
        GitCommitFact(
            sha=sha,
            short_sha=sha[:_SHORT_SHA_LEN],
            committed_at=committed_at,
            author_name=author_name,
            subject=redact_text(subject),
            parents=tuple(p for p in parents_field.split(" ") if p),
            changed_paths=tuple(paths),
        ),
        i,
    )


def parse_log_z(text: str) -> List[GitCommitFact]:
    """Parse ``log -z`` records into commit facts (newest-first preserved)."""
    if not isinstance(text, str):
        raise GitParseError("log input must be text")
    commits: List[GitCommitFact] = []
    tokens = text.split("\0")
    i = 0
    n = len(tokens)
    while i < n:
        if tokens[i] == "":
            i += 1
            continue
        commit, i = _parse_commit_record(tokens, i)
        commits.append(commit)
    return commits


def parse_head_fields(text: str) -> GitHeadFacts:
    """Parse a single HEAD field record (sha, committed_at, author_name,
    subject, parents). branch/detached are resolved service-side."""
    if not isinstance(text, str):
        raise GitParseError("HEAD input must be text")
    tokens = text.split("\0")
    if tokens and tokens[-1] == "":
        tokens.pop()  # single optional record terminator
    if len(tokens) != 5:
        raise GitParseError(
            f"HEAD record must have exactly 5 fields, got {len(tokens)}"
        )
    sha, committed_at, author_name, subject, parents = tokens
    _validate_sha(sha)
    if not committed_at:
        raise GitParseError("HEAD record missing committed_at")
    return GitHeadFacts(
        head_sha=sha,
        short_head_sha=sha[:_SHORT_SHA_LEN],
        branch=None,
        detached=False,
        committed_at=committed_at,
        author_name=author_name,
        subject=redact_text(subject),
        parents=tuple(p for p in parents.split(" ") if p),
    )


def _parse_count(raw: str) -> Tuple[int, bool]:
    if raw == "-":
        return 0, True
    try:
        return int(raw), False
    except ValueError as exc:
        raise GitParseError(f"malformed numstat count: {raw!r}") from exc


def parse_numstat_z(text: str) -> List[NumstatEntry]:
    """Parse ``diff --numstat -z`` output.

    Normal record: ``add\\tdel\\t<path>\\0``. Rename: the header path field is
    empty (``add\\tdel\\t\\0``) and the next two tokens are old then new path.
    Binary files report ``-`` counts and yield zero insertions/deletions.
    """
    if not isinstance(text, str):
        raise GitParseError("numstat input must be text")
    entries: List[NumstatEntry] = []
    tokens = text.split("\0")
    i = 0
    n = len(tokens)
    while i < n:
        header = tokens[i]
        i += 1
        if header == "":
            continue
        parts = header.split("\t")
        if len(parts) != 3:
            raise GitParseError(f"malformed numstat header: {header!r}")
        insertions, binary_add = _parse_count(parts[0])
        deletions, binary_del = _parse_count(parts[1])
        old_path: Optional[str] = None
        if parts[2] == "":
            # rename/copy: old path then new path follow as separate tokens
            if i + 1 >= n or tokens[i] == "" or tokens[i + 1] == "":
                raise GitParseError("numstat rename record missing paths")
            old_path, path = tokens[i], tokens[i + 1]
            i += 2
        else:
            path = parts[2]
        entries.append(
            NumstatEntry(
                path=path,
                insertions=insertions,
                deletions=deletions,
                binary=binary_add or binary_del,
                old_path=old_path,
            )
        )
    return entries


_NAME_STATUS_MAP = {
    "A": "added",
    "M": "modified",
    "T": "modified",
    "D": "deleted",
    "R": "renamed",
    "C": "renamed",
}


def parse_name_status_z(text: str) -> List[NameStatusEntry]:
    """Parse ``diff --name-status -z`` output.

    Normal record: ``<code>\\0<path>\\0``. Rename/copy records carry a score
    suffix (``R100``) and two path tokens: old then new.
    """
    if not isinstance(text, str):
        raise GitParseError("name-status input must be text")
    entries: List[NameStatusEntry] = []
    tokens = text.split("\0")
    i = 0
    n = len(tokens)
    while i < n:
        code = tokens[i]
        i += 1
        if code == "":
            continue
        letter = code[0]
        status = _NAME_STATUS_MAP.get(letter)
        if status is None or (letter in "RC" and not code[1:].isdigit()):
            raise GitParseError(f"unsupported name-status code: {code!r}")
        if letter in "RC":
            if i + 1 >= n or tokens[i] == "" or tokens[i + 1] == "":
                raise GitParseError("rename/copy record missing paths")
            old_path, path = tokens[i], tokens[i + 1]
            i += 2
        else:
            if i >= n or tokens[i] == "":
                raise GitParseError(f"name-status record missing path: {code!r}")
            old_path, path = None, tokens[i]
            i += 1
        entries.append(NameStatusEntry(path=path, status=status, old_path=old_path))
    return entries


# ---------------------------------------------------------------------------
# Service (Batch B2): typed collection with graceful degradation
#
# Every collect_* method catches its own section's typed errors and returns
# (partial facts, warnings) instead of raising — composition never crashes
# on git failure. Only programmer errors propagate (allowlist violations,
# hostile repo-relative paths rejected by normalize_repo_path).
# ---------------------------------------------------------------------------

# Warning codes (design §2/§6) — the builder maps these to PacketWarnings.
WARN_GIT_UNAVAILABLE = "git_unavailable"
WARN_GIT_NOT_REPOSITORY = "git_not_repository"
WARN_GIT_COMMAND_FAILED = "git_command_failed"
WARN_GIT_PARSE_FAILED = "git_parse_failed"

# Pinned log wire format (B1 contract): 5 NUL-separated header fields,
# then changed paths, record terminated by an empty field.
_LOG_FORMAT = "%H%x00%cI%x00%an%x00%s%x00%P"


@dataclass(frozen=True)
class GitWarning:
    """One degraded-section warning. ``message`` is always sanitized."""

    code: str
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return {"code": self.code, "message": self.message}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GitWarning":
        return cls(code=str(data["code"]), message=str(data["message"]))


def _degrade_warning(exc: GitError) -> GitWarning:
    if isinstance(exc, GitUnavailable):
        code = WARN_GIT_UNAVAILABLE
    elif isinstance(exc, NotGitRepository):
        code = WARN_GIT_NOT_REPOSITORY
    elif isinstance(exc, GitParseError):
        code = WARN_GIT_PARSE_FAILED
    else:
        code = WARN_GIT_COMMAND_FAILED
    return GitWarning(code, str(exc))


def _parse_log_name_only_z(text: str) -> List[Tuple[str, Tuple[str, ...]]]:
    """Parse ``log -z --pretty=format:%H --name-only`` into (sha, paths).

    Wire layout: the first changed path is glued to the %H field with
    ``\\n`` (the message->names separator survives -z); later paths are
    clean NUL-separated tokens; records are separated by an empty field.
    A pathological path that is exactly 40 hex chars would be misread as
    a record start — accepted v1 limitation (absurdly rare).
    """
    if not isinstance(text, str):
        raise GitParseError("log name-only input must be text")
    records: List[Tuple[str, Tuple[str, ...]]] = []
    sha: Optional[str] = None
    paths: List[str] = []

    def flush() -> None:
        if sha is not None:
            records.append((sha, tuple(paths)))

    for token in text.split("\0"):
        if token == "":
            continue
        head, sep, tail = token.partition("\n")
        if len(head) == _HEX_SHA_LEN and all(
            ch in "0123456789abcdefABCDEF" for ch in head
        ):
            flush()
            sha = head
            paths = []
            if sep and tail:
                paths.append(tail)
        else:
            if sha is None:
                raise GitParseError("log name-only record missing commit sha")
            paths.append(token)
    flush()
    return records


def _clamp_limit(limit: int, maximum: int) -> int:
    try:
        value = int(limit)
    except (TypeError, ValueError):
        raise GitCommandError(f"invalid git limit: {limit!r}")
    return max(1, min(value, maximum))


# Porcelain v1 unmerged (conflict) XY pairs.
_CONFLICT_CODES = frozenset({"DD", "AU", "UD", "UA", "DU", "AA", "UU"})


def _classify_working_tree(entries: List[GitStatusEntry]) -> GitWorkingTree:
    """Classify porcelain entries into disjoint change buckets.

    Conflicted paths land ONLY in ``conflicted``; renames land in
    ``renamed`` (old, new) plus the new path in staged/unstaged; deletions
    land ONLY in ``deleted`` regardless of column.
    """
    staged: List[str] = []
    unstaged: List[str] = []
    untracked: List[str] = []
    deleted: List[str] = []
    conflicted: List[str] = []
    renamed: List[Tuple[str, str]] = []
    for entry in entries:
        code = entry.index_status + entry.worktree_status
        if code in _CONFLICT_CODES or "U" in code:
            conflicted.append(entry.path)
            continue
        if code == "??":
            untracked.append(entry.path)
            continue
        if entry.index_status in "RC" and entry.old_path is not None:
            renamed.append((entry.old_path, entry.path))
            staged.append(entry.path)
        elif entry.worktree_status in "RC" and entry.old_path is not None:
            renamed.append((entry.old_path, entry.path))
            unstaged.append(entry.path)
        if entry.index_status == "D" or entry.worktree_status == "D":
            deleted.append(entry.path)
            continue
        if entry.index_status in "AMT":
            staged.append(entry.path)
        if entry.worktree_status in "AMT":
            unstaged.append(entry.path)
    clean = not (staged or unstaged or untracked or deleted or conflicted or renamed)
    return GitWorkingTree(
        clean=clean,
        staged=tuple(staged),
        unstaged=tuple(unstaged),
        untracked=tuple(untracked),
        deleted=tuple(deleted),
        conflicted=tuple(conflicted),
        renamed=tuple(renamed),
    )


class GitIntelligenceService:
    """Read-only git fact collection with typed graceful degradation."""

    def __init__(self, runner: Optional[_GitRunner] = None) -> None:
        self._runner = runner if runner is not None else _GitRunner()

    # -- capabilities ---------------------------------------------------

    def collect_capabilities(self, path) -> Tuple[GitCapabilities, List[GitWarning]]:
        cwd = str(path)
        try:
            version = self._runner.probe_version()
        except GitUnavailable as exc:
            return (
                GitCapabilities(
                    git_available=False,
                    git_version=None,
                    repository_detected=False,
                    is_bare=False,
                    head_available=False,
                    repository_root=None,
                ),
                [_degrade_warning(exc)],
            )
        try:
            bare_out = self._runner.run(cwd, "rev-parse", "--is-bare-repository")
        except GitUnavailable as exc:
            return (
                GitCapabilities(False, None, False, False, False, None),
                [_degrade_warning(exc)],
            )
        except NotGitRepository as exc:
            return (
                GitCapabilities(True, version, False, False, False, None),
                [_degrade_warning(exc)],
            )
        warnings: List[GitWarning] = []
        is_bare = bare_out.strip() == "true"
        root: Optional[str] = None
        try:
            if is_bare:
                root = self._runner.run(cwd, "rev-parse", "--absolute-git-dir").strip()
            else:
                root = self._runner.run(cwd, "rev-parse", "--show-toplevel").strip()
        except GitError as exc:
            warnings.append(_degrade_warning(exc))
        head_available = False
        try:
            self._runner.run(cwd, "rev-parse", "--verify", "HEAD")
            head_available = True
        except GitError:
            head_available = False  # unborn HEAD (or unverifiable ref)
        return (
            GitCapabilities(
                git_available=True,
                git_version=version,
                repository_detected=True,
                is_bare=is_bare,
                head_available=head_available,
                repository_root=root,
            ),
            warnings,
        )

    def _ensure_repository(self, cwd: str) -> None:
        """Cheap typed repo probe: raises NotGitRepository for non-repos so
        every section degrades with the correct warning code (a failing
        status/log/diff would otherwise surface as git_command_failed)."""
        self._runner.run(cwd, "rev-parse", "--is-bare-repository")

    # -- working tree ----------------------------------------------------

    def collect_working_tree(self, path) -> Tuple[Optional[GitWorkingTree], List[GitWarning]]:
        cwd = str(path)
        try:
            self._ensure_repository(cwd)
            out = self._runner.run(cwd, "status", "--porcelain=v1", "-z")
            return _classify_working_tree(parse_porcelain_z(out)), []
        except GitError as exc:
            return None, [_degrade_warning(exc)]

    # -- repository state --------------------------------------------------

    def collect_repository_state(
        self, path
    ) -> Tuple[Optional[GitRepositoryState], List[GitWarning]]:
        cwd = str(path)
        caps, warnings = self.collect_capabilities(cwd)
        if not caps.git_available or not caps.repository_detected:
            return None, warnings
        head_sha: Optional[str] = None
        short_head_sha: Optional[str] = None
        branch: Optional[str] = None
        detached = False
        if caps.head_available:
            try:
                head_sha = self._runner.run(cwd, "rev-parse", "--verify", "HEAD").strip()
                short_head_sha = head_sha[:_SHORT_SHA_LEN]
                branch, detached = self._resolve_branch(cwd)
            except GitError as exc:
                warnings.append(_degrade_warning(exc))
                head_sha = short_head_sha = None
        clean = True
        staged_count = unstaged_count = untracked_count = conflicted_count = 0
        if not caps.is_bare:
            tree, tree_warnings = self.collect_working_tree(cwd)
            warnings.extend(tree_warnings)
            if tree is not None:
                clean = tree.clean
                staged_count = len(tree.staged)
                unstaged_count = len(tree.unstaged)
                untracked_count = len(tree.untracked)
                conflicted_count = len(tree.conflicted)
        return (
            GitRepositoryState(
                head_sha=head_sha,
                short_head_sha=short_head_sha,
                branch=branch,
                detached=detached,
                clean=clean,
                staged_count=staged_count,
                unstaged_count=unstaged_count,
                untracked_count=untracked_count,
                conflicted_count=conflicted_count,
            ),
            warnings,
        )

    def _resolve_branch(self, cwd: str) -> Tuple[Optional[str], bool]:
        """(branch, detached) via rev-parse --abbrev-ref HEAD.

        Detached HEAD prints ``HEAD``; unborn HEAD fails rev-parse and is
        reported as (None, False).
        """
        try:
            name = self._runner.run(cwd, "rev-parse", "--abbrev-ref", "HEAD").strip()
        except GitError:
            return None, False
        if name == "HEAD":
            return None, True
        return name, False

    # -- HEAD facts --------------------------------------------------------

    def collect_head_facts(self, path) -> Tuple[Optional[GitHeadFacts], List[GitWarning]]:
        cwd = str(path)
        try:
            self._ensure_repository(cwd)
            out = self._runner.run(
                cwd, "log", "-z", "-1", f"--pretty=format:{_LOG_FORMAT}", "--name-only"
            )
            commits = parse_log_z(out)
        except GitError as exc:
            return None, [_degrade_warning(exc)]
        if not commits:
            return None, [GitWarning(WARN_GIT_PARSE_FAILED, "empty HEAD log record")]
        head = commits[0]
        branch, detached = self._resolve_branch(cwd)
        return (
            GitHeadFacts(
                head_sha=head.sha,
                short_head_sha=head.short_sha,
                branch=branch,
                detached=detached,
                committed_at=head.committed_at,
                author_name=head.author_name,
                subject=head.subject,
                parents=head.parents,
            ),
            [],
        )

    # -- diff facts ---------------------------------------------------------

    def collect_diff(
        self, path, include_snippets: bool = False
    ) -> Tuple[List[GitDiffFact], List[GitWarning]]:
        """Staged facts first, then unstaged; both in git's path order.

        Snippets are ABSENT unless ``include_snippets`` is True, and are
        always redacted and hard-bounded to GIT_SNIPPET_MAX_CHARS.
        """
        cwd = str(path)
        try:
            self._ensure_repository(cwd)
            facts = self._diff_side(cwd, cached=True, include_snippets=include_snippets)
            facts += self._diff_side(cwd, cached=False, include_snippets=include_snippets)
            return facts, []
        except GitError as exc:
            return [], [_degrade_warning(exc)]

    def _diff_side(
        self, cwd: str, *, cached: bool, include_snippets: bool
    ) -> List[GitDiffFact]:
        side = ["--cached"] if cached else []
        numstat = parse_numstat_z(
            self._runner.run(cwd, "diff", "--numstat", "-z", *side)
        )
        statuses = {
            entry.path: entry
            for entry in parse_name_status_z(
                self._runner.run(cwd, "diff", "--name-status", "-z", *side)
            )
        }
        facts: List[GitDiffFact] = []
        for entry in numstat:
            status_entry = statuses.get(entry.path)
            old_path = entry.old_path or (
                status_entry.old_path if status_entry else None
            )
            snippet: Optional[str] = None
            if include_snippets and not entry.binary:
                raw = self._runner.run(
                    cwd, "diff", "--unified=0", *side, "--", entry.path
                )
                snippet = redact_text(raw)[:GIT_SNIPPET_MAX_CHARS]
            facts.append(
                GitDiffFact(
                    path=entry.path,
                    status=status_entry.status if status_entry else "modified",
                    staged=cached,
                    insertions=entry.insertions,
                    deletions=entry.deletions,
                    binary=entry.binary,
                    old_path=old_path,
                    snippet=snippet,
                )
            )
        return facts

    # -- current change state --------------------------------------------

    def collect_current_change_state(
        self, path, file_path: str
    ) -> Tuple[Optional[GitFileChangeState], List[GitWarning]]:
        rel = normalize_repo_path(file_path)  # hostile paths: programmer error
        cwd = str(path)
        try:
            self._ensure_repository(cwd)
            out = self._runner.run(
                cwd, "status", "--porcelain=v1", "-z", "--", rel
            )
            entries = parse_porcelain_z(out)
        except GitError as exc:
            return None, [_degrade_warning(exc)]
        if not entries:
            return GitFileChangeState.UNCHANGED, []
        entry = entries[0]
        code = entry.index_status + entry.worktree_status
        if code in _CONFLICT_CODES or "U" in code:
            return GitFileChangeState.CONFLICTED, []
        if code == "??":
            return GitFileChangeState.UNTRACKED, []
        if entry.index_status != " ":
            return GitFileChangeState.STAGED, []
        return GitFileChangeState.UNSTAGED, []

    # -- co-change ---------------------------------------------------------

    def collect_cochange(
        self, path, anchor_path: str
    ) -> Tuple[List[GitCoChangeFact], List[GitWarning]]:
        """Co-changed paths over the last GIT_COCHANGE_SCAN commits.

        Single ``git log -z --name-only`` scan (no pathspec). "Co-changed"
        only — no causality claim. Rename-blind by design (v1 limitation):
        pre/post-rename paths are distinct entries.
        """
        rel = normalize_repo_path(anchor_path)  # hostile paths: programmer error
        cwd = str(path)
        try:
            self._ensure_repository(cwd)
            out = self._runner.run(
                cwd,
                "log",
                "-z",
                f"--max-count={GIT_COCHANGE_SCAN}",
                "--pretty=format:%H",
                "--name-only",
            )
            records = _parse_log_name_only_z(out)
        except GitError as exc:
            return [], [_degrade_warning(exc)]
        anchor_records = [paths for _, paths in records if rel in paths]
        sampled = len(anchor_records)
        shared: Dict[str, int] = {}
        for paths in anchor_records:
            for candidate in set(paths):
                if candidate != rel:
                    shared[candidate] = shared.get(candidate, 0) + 1
        facts = [
            GitCoChangeFact(
                path=candidate,
                shared_commit_count=count,
                sampled_commit_count=sampled,
            )
            for candidate, count in shared.items()
            if count >= 1
        ]
        facts.sort(key=lambda f: (-f.shared_commit_count, f.path))
        return facts[:GIT_TOP_COCHANGE], []
    # -- recent commits & file history --------------------------------------

    def _collect_log(
        self, cwd: str, *extra_args: str
    ) -> Tuple[List[GitCommitFact], List[GitWarning]]:
        try:
            self._ensure_repository(cwd)
            out = self._runner.run(cwd, "log", "-z", *extra_args)
            return parse_log_z(out), []
        except GitError as exc:
            return [], [_degrade_warning(exc)]

    def collect_recent_commits(
        self, path, limit: int = GIT_DEFAULT_COMMITS
    ) -> Tuple[List[GitCommitFact], List[GitWarning]]:
        """Newest-first commit facts; bodies are never collected."""
        limit = _clamp_limit(limit, GIT_MAX_COMMITS)
        return self._collect_log(
            str(path),
            f"--max-count={limit}",
            f"--pretty=format:{_LOG_FORMAT}",
            "--name-only",
        )

    def collect_file_history(
        self, path, file_path: str, limit: Optional[int] = None
    ) -> Tuple[List[GitCommitFact], List[GitWarning]]:
        """Commits touching ``file_path`` newest-first, rename-following
        (``--follow``) so pre-rename commits are included where feasible."""
        rel = normalize_repo_path(file_path)  # hostile paths: programmer error
        limit = _clamp_limit(
            GIT_DEFAULT_COMMITS if limit is None else limit, GIT_FILE_HISTORY_MAX
        )
        return self._collect_log(
            str(path),
            f"--max-count={limit}",
            f"--pretty=format:{_LOG_FORMAT}",
            "--follow",
            "--name-only",
            "--",
            rel,
        )


# ---------------------------------------------------------------------------
# Module-level convenience functions — delegate to a shared default service
# ---------------------------------------------------------------------------

_default_service: Optional[GitIntelligenceService] = None


def _get_default_service() -> GitIntelligenceService:
    global _default_service
    if _default_service is None:
        _default_service = GitIntelligenceService()
    return _default_service


def collect_capabilities(path):
    return _get_default_service().collect_capabilities(path)


def collect_repository_state(path):
    return _get_default_service().collect_repository_state(path)


def collect_head_facts(path):
    return _get_default_service().collect_head_facts(path)


def collect_working_tree(path):
    return _get_default_service().collect_working_tree(path)


def collect_diff(path, include_snippets: bool = False):
    return _get_default_service().collect_diff(path, include_snippets=include_snippets)


def collect_recent_commits(path, limit: int = GIT_DEFAULT_COMMITS):
    return _get_default_service().collect_recent_commits(path, limit=limit)


def collect_file_history(path, file_path: str, limit: Optional[int] = None):
    return _get_default_service().collect_file_history(path, file_path, limit=limit)


def collect_current_change_state(path, file_path: str):
    return _get_default_service().collect_current_change_state(path, file_path)


def collect_cochange(path, anchor_path: str):
    return _get_default_service().collect_cochange(path, anchor_path)
