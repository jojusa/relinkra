"""Relinkra portable code reference model (R1D).

A CodeReference is the stable, workspace-independent identity of a file
or symbol inside a logical project. It layers over CBM
(codebase-memory-mcp) node identity WITHOUT adopting it:

- CBM ``qualified_name`` is path-derived: it embeds the CBM project
  slug, which comes from the absolute workspace path. Relinkra stores
  the PROJECT-RELATIVE semantic qualified name; ``cbm_project_name``
  is kept only as workspace-local resolution metadata.
- SQLite row ids are never used. Identity is content-hashed from
  semantic fields only.
- CBM exposes no language field; language is derived from the file
  extension.
- Absolute paths are rejected as portable identity. Line numbers and
  commit SHAs are drift-detecting metadata, never identity.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Mapping, Optional

CODE_REF_ID_PREFIX = "ref_"
CODE_REF_ID_RE = re.compile(r"^ref_[0-9a-f]{32}$")
_CODE_REF_NAMESPACE = b"relinkra/code-ref/v1\x00"

REFERENCE_KINDS = ("file", "symbol")

PROJECT_ID_RE = re.compile(r"^rlk_[0-9a-f]{32}$")
WORKSPACE_ID_RE = re.compile(r"^ws_[0-9a-f]{32}$")

_DRIVE_ABS_RE = re.compile(r"^[A-Za-z]:[\\/]")
_COMMIT_RE = re.compile(r"^[0-9a-f]{7,64}$")
_LANGUAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+#.\-]*$")
# scp-like git references (git@host:org/repo) must never be stored as a
# repo-relative path; npm-style scoped dirs (@types/node) stay legal.
_SCP_LIKE_RE = re.compile(r"^[^/\s]+@[^/\s]+:")

_LANGUAGE_BY_EXT = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".php": "php",
    ".rb": "ruby",
    ".pl": "perl",
    ".pm": "perl",
    ".swift": "swift",
    ".m": "objective-c",
    ".scala": "scala",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ps1": "powershell",
    ".md": "markdown",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".xml": "xml",
    ".sql": "sql",
    ".html": "html",
    ".css": "css",
    ".lua": "lua",
    ".r": "r",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".hs": "haskell",
    ".fs": "fsharp",
    ".fsx": "fsharp",
    ".dart": "dart",
    ".zig": "zig",
}


class CodeRefError(Exception):
    """Base error for code reference failures."""


class CodeRefValidationError(CodeRefError, ValueError):
    """Raised when a code reference fails validation."""


def _has_control_chars(text: str) -> bool:
    return any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text)


def _redact(text: str) -> str:
    # Lazy import: memory.py imports this module at top level.
    from .memory import redact_text

    return redact_text(text)


def validate_ref_project_id(project_id: str) -> str:
    pid = (project_id or "").strip()
    if not PROJECT_ID_RE.match(pid):
        raise CodeRefValidationError(
            "project_id must be a valid R1B rlk_ id (never a filesystem "
            "path, CBM name, branch, or HEAD SHA)"
        )
    return pid


def validate_ref_workspace_id(workspace_id: str) -> str:
    wid = (workspace_id or "").strip()
    if not WORKSPACE_ID_RE.match(wid):
        raise CodeRefValidationError("workspace_id must be a valid R1B ws_ id")
    return wid


def normalize_repo_path(path: str) -> str:
    """Normalize a repo-relative path to portable POSIX form.

    Backslashes become forward slashes, redundant ``.``/empty segments
    collapse. Absolute paths (POSIX root, drive-letter, UNC), parent
    traversal (``..``), control characters, and URL-like values
    (``scheme://``, scp-like git references) are REJECTED: an absolute
    path is workspace-local metadata, not portable identity.
    """
    if not isinstance(path, str):
        raise CodeRefValidationError("file_path must be a string")
    raw = path.strip()
    if not raw:
        raise CodeRefValidationError("file_path must be non-empty")
    if _has_control_chars(raw):
        raise CodeRefValidationError("file_path contains control characters")
    if _DRIVE_ABS_RE.match(raw):
        raise CodeRefValidationError(
            "file_path must be repo-relative; drive-absolute paths are not "
            "portable identity"
        )
    if raw.startswith(("/", "\\")):
        raise CodeRefValidationError(
            "file_path must be repo-relative; absolute/UNC paths are not "
            "portable identity"
        )
    if "://" in raw:
        raise CodeRefValidationError("file_path must not be a URL")
    if _SCP_LIKE_RE.match(raw):
        raise CodeRefValidationError(
            "file_path must not be a scp-like repository reference"
        )
    segments = []
    for segment in raw.replace("\\", "/").split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            raise CodeRefValidationError(
                "file_path must not contain parent traversal (..)"
            )
        segments.append(segment)
    if not segments:
        raise CodeRefValidationError("file_path must name a file inside the repo")
    return "/".join(segments)


def derive_language(file_path: str) -> Optional[str]:
    """Derive the language from the file extension (CBM has no such field)."""
    name = (file_path or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
    if "." not in name:
        return None
    ext = "." + name.rsplit(".", 1)[-1]
    return _LANGUAGE_BY_EXT.get(ext)


def compute_code_reference_id(
    project_id: str,
    reference_kind: str,
    file_path: str,
    qualified_name: str = "",
) -> str:
    """ref_ + first 32 hex of sha256(ns + project + kind + path + qn).

    Only semantic, workspace-independent fields participate: workspace_id,
    cbm_project_name, line numbers, and commit_sha are deliberately
    excluded so the same semantic ref hashes identically across
    workspaces and across different CBM project names.
    """
    payload = (
        _CODE_REF_NAMESPACE
        + project_id.encode("utf-8")
        + b"\x00"
        + reference_kind.encode("utf-8")
        + b"\x00"
        + file_path.encode("utf-8")
        + b"\x00"
        + (qualified_name or "").encode("utf-8")
    )
    return CODE_REF_ID_PREFIX + hashlib.sha256(payload).hexdigest()[:32]


def _clean_optional_text(
    value: Optional[str], field_name: str, redact: bool = True
) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise CodeRefValidationError(f"{field_name} must be a string")
    v = value.strip()
    if not v:
        return None
    if _has_control_chars(v):
        raise CodeRefValidationError(
            f"{field_name} contains control characters"
        )
    return _redact(v) if redact else v


def _clean_cbm_project_name(value: Optional[str]) -> Optional[str]:
    v = _clean_optional_text(value, "cbm_project_name", redact=False)
    if v is None:
        return None
    if any(ch in v for ch in "/\\:@"):
        raise CodeRefValidationError(
            "cbm_project_name must be a CBM slug, not a path or URL"
        )
    if any(ch.isspace() for ch in v):
        raise CodeRefValidationError("cbm_project_name must not contain spaces")
    return v


def _validate_ref_repository_identity(identity: Any) -> Optional[dict]:
    if identity is None:
        return None
    from .memory import MemoryValidationError, validate_repository_identity

    try:
        return validate_repository_identity(identity)
    except MemoryValidationError as exc:
        raise CodeRefValidationError(str(exc)) from exc


@dataclass
class CodeReference:
    """Portable identity of a file or symbol within a logical project.

    ``reference_kind`` is ``file`` or ``symbol``. A file ref needs only
    ``file_path``; a symbol ref additionally requires ``symbol_name``
    and/or ``qualified_name`` (project-relative, WITHOUT the CBM
    project slug). ``start_line``/``end_line``, ``commit_sha``,
    ``workspace_id``, and ``cbm_project_name`` are metadata: they never
    participate in ``code_reference_id``.
    """

    project_id: str
    reference_kind: str
    file_path: str
    workspace_id: Optional[str] = None
    symbol_name: Optional[str] = None
    qualified_name: Optional[str] = None
    symbol_kind: Optional[str] = None
    language: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    cbm_project_name: Optional[str] = None
    commit_sha: Optional[str] = None
    repository_identity: Optional[dict] = None

    def __post_init__(self) -> None:
        self.project_id = validate_ref_project_id(self.project_id)
        if self.workspace_id is not None:
            self.workspace_id = validate_ref_workspace_id(self.workspace_id)
        kind = (self.reference_kind or "").strip().lower()
        if kind not in REFERENCE_KINDS:
            raise CodeRefValidationError(
                f"reference_kind must be one of {REFERENCE_KINDS}: "
                f"{self.reference_kind!r}"
            )
        self.reference_kind = kind
        self.file_path = normalize_repo_path(self.file_path)

        self.symbol_name = _clean_optional_text(self.symbol_name, "symbol_name")
        self.symbol_kind = _clean_optional_text(self.symbol_kind, "symbol_kind")
        self.qualified_name = self._clean_qualified_name(self.qualified_name)
        self.cbm_project_name = _clean_cbm_project_name(self.cbm_project_name)
        if (
            self.cbm_project_name
            and self.qualified_name
            and (
                self.qualified_name == self.cbm_project_name
                or self.qualified_name.startswith(self.cbm_project_name + ".")
            )
        ):
            raise CodeRefValidationError(
                "qualified_name must be project-relative: strip the CBM "
                "project slug before building a CodeReference"
            )
        if self.reference_kind == "symbol" and not (
            self.symbol_name or self.qualified_name
        ):
            raise CodeRefValidationError(
                "symbol references require symbol_name and/or qualified_name"
            )

        if self.language is None:
            self.language = derive_language(self.file_path)
        else:
            lang = str(self.language).strip().lower()
            if not _LANGUAGE_RE.match(lang):
                raise CodeRefValidationError(
                    f"language is not a plausible language tag: {self.language!r}"
                )
            self.language = lang

        self.start_line = self._clean_line(self.start_line, "start_line")
        self.end_line = self._clean_line(self.end_line, "end_line")
        if (
            self.start_line is not None
            and self.end_line is not None
            and self.end_line < self.start_line
        ):
            raise CodeRefValidationError("end_line must be >= start_line")

        if self.commit_sha is not None:
            sha = str(self.commit_sha).strip().lower()
            if not _COMMIT_RE.match(sha):
                raise CodeRefValidationError(
                    "commit_sha must be 7-64 hex characters (metadata only, "
                    "never identity)"
                )
            self.commit_sha = sha

        self.repository_identity = _validate_ref_repository_identity(
            self.repository_identity
        )

    @staticmethod
    def _clean_line(value: Any, field_name: str) -> Optional[int]:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            try:
                value = int(str(value).strip())
            except (TypeError, ValueError) as exc:
                raise CodeRefValidationError(
                    f"{field_name} must be a positive integer"
                ) from exc
        if value < 1:
            raise CodeRefValidationError(f"{field_name} must be >= 1")
        return value

    @staticmethod
    def _clean_qualified_name(value: Optional[str]) -> Optional[str]:
        v = _clean_optional_text(value, "qualified_name")
        if v is None:
            return None
        if "\\" in v or "/" in v or "://" in v:
            raise CodeRefValidationError(
                "qualified_name must be a semantic dotted name, not a path "
                "or URL"
            )
        return v

    @property
    def code_reference_id(self) -> str:
        return compute_code_reference_id(
            self.project_id,
            self.reference_kind,
            self.file_path,
            self.qualified_name or "",
        )

    def to_dict(self) -> dict:
        return {
            "code_reference_id": self.code_reference_id,
            "project_id": self.project_id,
            "workspace_id": self.workspace_id,
            "reference_kind": self.reference_kind,
            "file_path": self.file_path,
            "symbol_name": self.symbol_name,
            "qualified_name": self.qualified_name,
            "symbol_kind": self.symbol_kind,
            "language": self.language,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "cbm_project_name": self.cbm_project_name,
            "commit_sha": self.commit_sha,
            "repository_identity": self.repository_identity,
        }

    @staticmethod
    def from_dict(data: Mapping) -> "CodeReference":
        if not isinstance(data, Mapping):
            raise CodeRefValidationError("code reference must be a mapping")
        for required in ("project_id", "reference_kind", "file_path"):
            if data.get(required) in (None, ""):
                raise CodeRefValidationError(
                    f"code reference missing required field: {required}"
                )
        return CodeReference(
            project_id=str(data["project_id"]),
            workspace_id=(
                str(data["workspace_id"]) if data.get("workspace_id") else None
            ),
            reference_kind=str(data["reference_kind"]),
            file_path=str(data["file_path"]),
            symbol_name=data.get("symbol_name"),
            qualified_name=data.get("qualified_name"),
            symbol_kind=data.get("symbol_kind"),
            language=data.get("language"),
            start_line=data.get("start_line"),
            end_line=data.get("end_line"),
            cbm_project_name=data.get("cbm_project_name"),
            commit_sha=data.get("commit_sha"),
            repository_identity=data.get("repository_identity"),
        )
