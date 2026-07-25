"""Logical project identity model and normalization for Relinkra.

Relinkra layers a portable logical identity on top of path-derived CBM
identity. A LogicalProject is anchored to a RepositoryIdentity:

- remote:      canonicalized git remote URL, trust=strong
- explicit:    user-supplied canonical value, trust=strong
- local_root:  root commit SHA(s) of HEAD history, trust=weak

HEAD SHA is metadata only and is NEVER part of identity. Scheme
differences (https vs ssh) converge when host+path match; forks differ
by path and never merge.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Mapping, Optional

PROJECT_ID_PREFIX = "rlk_"
WORKSPACE_ID_PREFIX = "ws_"
_PROJECT_NAMESPACE = b"relinkra/project/v1\x00"
_WORKSPACE_NAMESPACE = b"relinkra/workspace/v1\x00"

CASE_INSENSITIVE_HOSTS = frozenset(
    {
        "github.com",
        "www.github.com",
        "gitlab.com",
        "www.gitlab.com",
        "bitbucket.org",
        "www.bitbucket.org",
    }
)

_HTTPS_SCHEMES = {"http", "https", "git+https"}
_SSH_SCHEMES = {"ssh", "git", "git+ssh"}
_KNOWN_SCHEMES = _HTTPS_SCHEMES | _SSH_SCHEMES
_DEFAULT_PORTS = {"https": 443, "ssh": 22}

_SCP_LIKE = re.compile(r"^(?P<userinfo>[^@/:]+)@(?P<host>[^/:\s]+):(?P<path>.+)$")

_CREDENTIALED_AUTHORITY_RE = re.compile(
    r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)[^/\s]+@"
)
_SCP_USERINFO_RE = re.compile(r"^[^/\s]+@")
_QUERY_FRAGMENT_RE = re.compile(r"[?#]")
_DRIVE_LIKE_RE = re.compile(r"^[A-Za-z]:[\\/]")


def redact_url(url: str) -> str:
    """Return a credential-free rendering of a URL for error messages.

    Strips ALL userinfo (``user[:password]@``) from both ``scheme://`` and
    scp-like forms (including ``user:pass@host:path``), drops any query
    string or fragment (which may carry tokens), and falls back to a
    generic placeholder if any ``@`` survives redaction, so raw
    credentialed URLs are never echoed to logs, stderr, or exception text.
    """
    if not isinstance(url, str):
        return "<unprintable remote URL>"
    redacted = _CREDENTIALED_AUTHORITY_RE.sub(r"\g<scheme>", url)
    if "://" not in redacted:
        redacted = _SCP_USERINFO_RE.sub("", redacted, count=1)
    redacted = _QUERY_FRAGMENT_RE.split(redacted, maxsplit=1)[0]
    if "@" in redacted:
        return "<redacted remote URL>"
    return redacted


def _has_forbidden_chars(text: str, extra: str = "") -> bool:
    """True when text holds whitespace, control chars, or chars in ``extra``."""
    for ch in text:
        if ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F or ch in extra:
            return True
    return False


class IdentityError(ValueError):
    """Raised when an identity value is malformed or ambiguous at build time."""


class AmbiguousIdentityError(Exception):
    """Raised when a weak identity matches an existing project without consent."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class RepositoryIdentity:
    kind: str  # "remote" | "explicit" | "local_root"
    value: str  # canonical string, credential-free
    trust: str  # "strong" | "weak"
    credentials_removed: bool = False
    original_scheme: Optional[str] = None  # "https" | "ssh" for remote kind

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(data: Mapping) -> "RepositoryIdentity":
        return RepositoryIdentity(
            kind=str(data["kind"]),
            value=str(data["value"]),
            trust=str(data["trust"]),
            credentials_removed=bool(data.get("credentials_removed", False)),
            original_scheme=data.get("original_scheme"),
        )


@dataclass(frozen=True)
class LogicalProject:
    project_id: str
    display_name: str
    repository_identity: RepositoryIdentity
    created_at: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["repository_identity"] = self.repository_identity.to_dict()
        return d

    @staticmethod
    def from_dict(data: Mapping) -> "LogicalProject":
        return LogicalProject(
            project_id=str(data["project_id"]),
            display_name=str(data["display_name"]),
            repository_identity=RepositoryIdentity.from_dict(data["repository_identity"]),
            created_at=str(data["created_at"]),
        )


@dataclass
class Workspace:
    workspace_id: str
    project_id: str
    absolute_path: str
    canonical_path: str
    os: str  # os family: windows | linux | darwin | ...
    git: dict = field(default_factory=dict)  # {"branch": str, "head_sha": str} — metadata only
    cbm: Optional[dict] = None  # path-derived CBM identity record, unchanged
    agent: Optional[str] = None  # optional agent context string only
    registered_at: str = ""
    last_seen_at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(data: Mapping) -> "Workspace":
        return Workspace(
            workspace_id=str(data["workspace_id"]),
            project_id=str(data["project_id"]),
            absolute_path=str(data["absolute_path"]),
            canonical_path=str(data["canonical_path"]),
            os=str(data["os"]),
            git=dict(data.get("git") or {}),
            cbm=data.get("cbm"),
            agent=data.get("agent"),
            registered_at=str(data.get("registered_at", "")),
            last_seen_at=str(data.get("last_seen_at", "")),
        )


def normalize_remote_url(url: str) -> RepositoryIdentity:
    """Canonicalize a git remote URL into a strong RepositoryIdentity.

    Supported forms (and generic-host equivalents):
      https://github.com/org/repo.git
      git@github.com:org/repo.git
      ssh://git@github.com/org/repo.git

    Userinfo/credentials are ALWAYS stripped (never persisted in value).
    Canonical value: ``remote://git/<host>/<path>`` — https and ssh converge
    when host+path match.
    """
    if not isinstance(url, str):
        raise ValueError("remote URL must be a string")
    raw = url.strip()
    if not raw:
        raise ValueError("empty remote URL")

    credentials_removed = False
    port: Optional[int] = None

    if "://" in raw:
        scheme, rest = raw.split("://", 1)
        scheme = scheme.lower()
        if scheme not in _KNOWN_SCHEMES:
            raise ValueError(f"unsupported remote URL scheme: {scheme!r}")
        norm_scheme = "https" if scheme in _HTTPS_SCHEMES else "ssh"
        if "/" in rest:
            authority, path = rest.split("/", 1)
        else:
            authority, path = rest, ""
        if "@" in authority:
            credentials_removed = True
            authority = authority.rsplit("@", 1)[1]
        if ":" in authority:
            host_part, _, port_part = authority.rpartition(":")
            if port_part.isdigit():
                host, port = host_part, int(port_part)
            else:
                raise ValueError(
                    f"remote URL has a non-numeric port: {redact_url(url)!r}"
                )
        else:
            host = authority
        host = host.lower()
        if port == _DEFAULT_PORTS.get(norm_scheme):
            port = None
    else:
        m = _SCP_LIKE.match(raw)
        if not m:
            raise ValueError(f"malformed remote URL: {redact_url(url)!r}")
        credentials_removed = True  # scp-like always carries userinfo (user@)
        norm_scheme = "ssh"
        host = m.group("host").lower()
        path = m.group("path")

    path = re.sub(r"/+", "/", path).strip("/")
    if path.lower().endswith(".git"):
        path = path[:-4]
    path = path.rstrip("/")

    if not host:
        raise ValueError(
            f"remote URL has no host after stripping userinfo: {redact_url(url)!r}"
        )
    if not path:
        raise ValueError(
            f"remote URL has no path after normalization: {redact_url(url)!r}"
        )
    if "@" in host or "@" in path:
        raise ValueError(
            f"remote URL still contains credentials: {redact_url(url)!r}"
        )
    if _has_forbidden_chars(host, extra="?#"):
        raise ValueError(
            "remote URL host contains whitespace, control, or forbidden "
            f"characters: {redact_url(url)!r}"
        )
    if _has_forbidden_chars(path, extra="?#"):
        raise ValueError(
            "remote URL path contains whitespace, control, or forbidden "
            f"characters (query/fragment not allowed): {redact_url(url)!r}"
        )

    if host in CASE_INSENSITIVE_HOSTS:
        path = path.lower()

    hostport = f"{host}:{port}" if port is not None else host
    value = f"remote://git/{hostport}/{path}"
    return RepositoryIdentity(
        kind="remote",
        value=value,
        trust="strong",
        credentials_removed=credentials_removed,
        original_scheme=norm_scheme,
    )


def choose_remote(remotes: Mapping[str, str]) -> tuple[str, str]:
    """Pick a remote by priority: origin > upstream > lexicographically first.

    Fork safety: a fork's origin and the original's upstream differ in path
    (and possibly host), so they never merge.
    """
    if not remotes:
        raise ValueError("no remotes to choose from")
    for preferred in ("origin", "upstream"):
        if preferred in remotes:
            return preferred, remotes[preferred]
    name = sorted(remotes)[0]
    return name, remotes[name]


def local_root_identity(root_shas: Iterable[str]) -> RepositoryIdentity:
    """Weak identity from the root commit(s) of HEAD history.

    Portable across clones of the same history; not path-derived.
    """
    roots = sorted(s.strip().lower() for s in root_shas if s and s.strip())
    if not roots:
        raise ValueError("no root commit SHA provided")
    for sha in roots:
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha):
            raise ValueError(f"invalid root commit SHA: {sha!r}")
    return RepositoryIdentity(
        kind="local_root",
        value="local-root://" + ",".join(roots),
        trust="weak",
        credentials_removed=False,
    )


def explicit_identity(value: str) -> RepositoryIdentity:
    """Strong user-supplied identity. Stored as ``explicit://<value>``."""
    v = (value or "").strip()
    if not v:
        raise ValueError("empty explicit identity value")
    if "@" in v or "://" in v or any(c.isspace() for c in v):
        raise ValueError(f"invalid explicit identity value: {value!r}")
    return RepositoryIdentity(
        kind="explicit",
        value=f"explicit://{v}",
        trust="strong",
        credentials_removed=False,
    )


def derive_project_id(canonical_identity_value: str) -> str:
    """Deterministic project id: rlk_ + 32 hex of SHA-256(ns + value).

    Not path-derived, stable across branches/commits, filename/DB safe,
    LLM-independent.
    """
    digest = hashlib.sha256(
        _PROJECT_NAMESPACE + canonical_identity_value.encode("utf-8")
    ).hexdigest()
    return PROJECT_ID_PREFIX + digest[:32]


def derive_workspace_id(project_id: str, canonical_path: str, os_family: str) -> str:
    """ws_ + 32 hex of SHA-256(ns + project_id + path + os_family)."""
    payload = (
        _WORKSPACE_NAMESPACE
        + project_id.encode("utf-8")
        + b"\x00"
        + canonical_path.encode("utf-8")
        + b"\x00"
        + os_family.encode("utf-8")
    )
    return WORKSPACE_ID_PREFIX + hashlib.sha256(payload).hexdigest()[:32]


def normalize_os_family(name: str) -> str:
    n = (name or "").strip().lower()
    if n.startswith(("win", "cygwin", "msys", "mingw")):
        return "windows"
    if n in ("darwin", "mac", "macos", "osx", "macosx"):
        return "darwin"
    if n.startswith("linux"):
        return "linux"
    return n


def canonicalize_path(path: str) -> str:
    """Absolute, symlink-resolved, case-normalized (per-OS) path.

    ``os.path.realpath`` resolves symlinks and ``..`` segments so the same
    repository reached through a symlink canonicalizes to the same workspace.
    """
    return os.path.normcase(os.path.realpath(path))


class GitError(Exception):
    pass


def _git(path: str, *args: str) -> str:
    try:
        r = subprocess.run(
            ["git", "-C", str(path), *args],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitError("git executable not found") from exc
    if r.returncode != 0:
        raise GitError(r.stderr.strip() or f"git {' '.join(args)} failed")
    return r.stdout.strip()


def git_remotes(path: str) -> dict[str, str]:
    out = _git(path, "remote", "-v")
    remotes: dict[str, str] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == "(fetch)":
            remotes[parts[0]] = parts[1]
    return remotes


def git_head_sha(path: str) -> str:
    return _git(path, "rev-parse", "HEAD")


def git_branch(path: str) -> str:
    branch = _git(path, "rev-parse", "--abbrev-ref", "HEAD")
    return "" if branch == "HEAD" else branch


def git_root_commits(path: str) -> list[str]:
    out = _git(path, "rev-list", "--max-parents=0", "HEAD")
    return sorted(line.strip().lower() for line in out.splitlines() if line.strip())


def _is_local_remote_reference(url: str, base: Optional[str] = None) -> bool:
    """True when a configured remote points at the local filesystem.

    Local references (``file://`` URLs, drive-letter/absolute/relative
    paths, or paths that exist relative to the repository) are not usable
    remote identifiers and fall back to weak local_root identity. Anything
    else that failed URL normalization (e.g. ``github.com/org/repo`` or an
    unsupported scheme) is a malformed network remote and must NOT fall
    back silently.
    """
    lowered = url.strip().lower()
    if lowered.startswith("file://"):
        return True
    if "://" in url:
        return False
    if _SCP_LIKE.match(url):
        return False
    stripped = url.strip()
    if stripped.startswith((".", "/", "\\", "~")) or _DRIVE_LIKE_RE.match(stripped):
        return True
    candidate = (
        stripped
        if os.path.isabs(stripped)
        else os.path.join(base or os.getcwd(), stripped)
    )
    return os.path.exists(candidate)


def discover_repository_identity(path: str, remote_url: Optional[str] = None) -> RepositoryIdentity:
    """Remote (strong) if usable, else local_root (weak) from root commits.

    Local filesystem remotes (e.g. a clone's origin pointing at another
    local path) are not usable remote identifiers and fall back to
    local_root. A malformed or unsupported *network* remote instead raises
    a sanitized (credential-free) ValueError: silently falling back to a
    weak identity would misidentify the repository.
    """
    url = remote_url
    if url is None:
        remotes = git_remotes(path)
        if remotes:
            _, url = choose_remote(remotes)
    if url is not None:
        try:
            return normalize_remote_url(url)
        except ValueError as exc:
            if _is_local_remote_reference(url, base=path):
                pass
            else:
                raise ValueError(
                    "configured remote is malformed or unsupported: "
                    f"{redact_url(url)!r}"
                ) from exc
    return local_root_identity(git_root_commits(path))
