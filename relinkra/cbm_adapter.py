"""Minimal external CBM (codebase-memory-mcp) CLI adapter (R1D).

Relinkra talks to CBM ONLY through its external CLI:

    codebase-memory-mcp cli search_graph --project <slug> --query <q>
    codebase-memory-mcp cli get_code_snippet --project <slug> --qualified-name <qn>

Hard boundaries:

- subprocess with an argv LIST, never a shell; CBM_CACHE_DIR passed via
  env; UTF-8 decoding; bounded by a timeout.
- JSON is parsed from stdout tolerantly (CBM emits ``level=info ...``
  log lines around the payload).
- No graph mutation, no direct SQLite access, no C headers, no Cypher
  reimplementation, no SQLite row ids.
- Only stable external symbol fields are consumed: ``label``, ``name``,
  ``qualified_name``, repo-relative ``file_path``, ``start_line`` /
  ``end_line``. CBM ``qualified_name`` embeds the path-derived project
  slug; the adapter strips it so Relinkra stores project-relative
  identity. ``get_code_snippet`` may return an ABSOLUTE ``file_path``;
  it is normalized against ``workspace_root``. Source contents are
  NEVER persisted.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from typing import List, Optional

from .code_reference import CodeReference, derive_language
from .memory import sanitize_error

DEFAULT_CBM_TIMEOUT = 30.0
CBM_CACHE_DIR_ENV = "CBM_CACHE_DIR"

# CBM placeholder paths that are not repo files (project root node,
# external/stdlib symbols like <python-builtins>).
_NON_REPO_PATHS = frozenset({"{}", ""})


class CBMAdapterError(Exception):
    """Raised when the CBM CLI fails or returns an unusable payload."""


def strip_project_slug(qualified_name: str, cbm_project_name: str) -> str:
    """Remove the path-derived CBM project slug prefix from a qn.

    ``C-Desarrollos-repo.src.calc.add`` with slug ``C-Desarrollos-repo``
    becomes ``src.calc.add``. Without a slug the qn is returned
    unchanged.
    """
    qn = (qualified_name or "").strip()
    slug = (cbm_project_name or "").strip()
    if slug and qn.startswith(slug + "."):
        return qn[len(slug) + 1 :]
    if slug and qn == slug:
        return ""
    return qn


def parse_cli_json(stdout: str) -> object:
    """Parse the first JSON payload from CBM stdout, tolerating log lines."""
    decoder = json.JSONDecoder()
    for line in (stdout or "").splitlines():
        stripped = line.strip()
        if not stripped.startswith(("{", "[")):
            continue
        try:
            payload, _ = decoder.raw_decode(stripped)
        except ValueError:
            continue
        return payload
    raise CBMAdapterError("cbm returned no JSON payload on stdout")


def _int_or_none(value) -> Optional[int]:
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 1 else None


def _is_absolute(path: str) -> bool:
    return bool(re.match(r"^[A-Za-z]:/", path)) or path.startswith("/")


def _casefold_path(path: str) -> str:
    """Case/separator-insensitive comparison key for absolute paths.

    ``os.path.normcase`` lowercases on Windows (case-insensitive FS)
    and is the identity on POSIX (case-sensitive FS), so relativization
    follows the platform semantics. Length is preserved, so a match on
    the key safely slices the original path.
    """
    return os.path.normcase(path.replace("\\", "/")).replace("\\", "/")


class CBMCLIAdapter:
    """Duck-typed CBM adapter over the external codebase-memory-mcp CLI.

    Parameters are explicit and local: the CBM binary path, the CBM
    cache directory (forwarded as CBM_CACHE_DIR), the workspace-local
    ``cbm_project_name`` slug, and an optional ``workspace_root`` used
    to relativize absolute paths returned by get_code_snippet. Nothing
    here reads or mutates global agent/Engram/OpenCode configuration.
    """

    def __init__(
        self,
        cbm_bin: str,
        cache_dir: Optional[str] = None,
        cbm_project_name: Optional[str] = None,
        workspace_root: Optional[str] = None,
        timeout: float = DEFAULT_CBM_TIMEOUT,
    ):
        if not cbm_bin or not str(cbm_bin).strip():
            raise CBMAdapterError("an explicit cbm binary path is required")
        self.cbm_bin = str(cbm_bin)
        self.cache_dir = str(cache_dir) if cache_dir else None
        self.cbm_project_name = (
            str(cbm_project_name).strip() if cbm_project_name else None
        )
        self.workspace_root = (
            os.path.abspath(str(workspace_root)).replace("\\", "/").rstrip("/")
            if workspace_root
            else None
        )
        self.timeout = float(timeout)

    # -- subprocess ---------------------------------------------------

    def _run(self, tool: str, flags: List[str]) -> object:
        argv = [self.cbm_bin, "cli", tool, *flags]
        env = dict(os.environ)
        if self.cache_dir:
            env[CBM_CACHE_DIR_ENV] = self.cache_dir
        try:
            result = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=self.timeout,
                env=env,
                shell=False,
            )
        except FileNotFoundError as exc:
            raise CBMAdapterError(
                f"cbm executable not found: {self.cbm_bin}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise CBMAdapterError(f"cbm {tool} timed out") from exc
        if result.returncode != 0:
            detail = sanitize_error((result.stderr or result.stdout or "").strip())
            raise CBMAdapterError(f"cbm {tool} failed: {detail}")
        return parse_cli_json(result.stdout or "")

    def _project(self, project: Optional[str]) -> str:
        slug = (project or self.cbm_project_name or "").strip()
        if not slug:
            raise CBMAdapterError(
                "a cbm_project_name is required (adapter default or per-call)"
            )
        return slug

    # -- capabilities -------------------------------------------------

    def search_symbols(
        self,
        *,
        query: Optional[str] = None,
        qualified_name: Optional[str] = None,
        file_path: Optional[str] = None,
        project: Optional[str] = None,
        limit: int = 50,
    ) -> List[dict]:
        """Symbol search. Returns normalized candidate dicts.

        Candidates carry only stable external fields plus the derived
        project-relative qn; external/stdlib placeholder nodes are
        dropped. Never raises on a CBM-level error payload — an
        unindexed project simply yields no candidates. The resolved
        project slug (adapter default or per-call) is stripped from
        every qualified_name and recorded as ``cbm_project_name``.
        """
        slug = self._project(project)
        flags = ["--project", slug, "--limit", str(int(limit))]
        if qualified_name:
            flags += ["--qn-pattern", qualified_name]
        elif query:
            flags += ["--query", query]
        if file_path:
            # CBM --file-pattern is a path filter, not a regex: anchoring and
            # escaping it ("^src/cal\.py$") silently matches zero rows. Pass
            # the repository-relative path verbatim.
            flags += ["--file-pattern", file_path]
        payload = self._run("search_graph", flags)
        if not isinstance(payload, dict) or payload.get("error"):
            return []
        results = payload.get("results")
        if not isinstance(results, list):
            return []
        candidates = []
        for node in results:
            if isinstance(node, dict):
                candidate = self._normalize_node(node, cbm_project_name=slug)
                if candidate is not None:
                    candidates.append(candidate)
        return candidates

    def get_snippet(
        self, qualified_name: str, *, project: Optional[str] = None
    ) -> Optional[dict]:
        """Exact lookup by FULL CBM qualified_name (slug included).

        Returns a normalized candidate dict, or None when CBM reports
        an error / no such symbol. Source contents are discarded. The
        resolved project slug (adapter default or per-call) drives the
        qn normalization.
        """
        slug = self._project(project)
        payload = self._run(
            "get_code_snippet",
            ["--project", slug, "--qualified-name", qualified_name],
        )
        if not isinstance(payload, dict) or payload.get("error"):
            return None
        return self._normalize_node(payload, cbm_project_name=slug)

    # -- normalization --------------------------------------------------

    def _normalize_node(
        self, node: dict, *, cbm_project_name: Optional[str] = None
    ) -> Optional[dict]:
        """Normalize one CBM node against the resolved project slug.

        ``cbm_project_name`` is the project context for THIS call
        (per-call override or adapter default, resolved by the caller);
        it is stripped from the qualified_name and recorded on the
        candidate so downstream identity never embeds the CBM slug.
        """
        file_path = self._normalize_file_path(node.get("file_path"))
        if not file_path or file_path in _NON_REPO_PATHS or file_path.startswith("<"):
            return None
        qn = str(node.get("qualified_name") or "").strip()
        slug = (cbm_project_name or self.cbm_project_name or "").strip()
        return {
            "name": node.get("name"),
            "qualified_name": qn,
            "relative_qualified_name": strip_project_slug(qn, slug),
            "label": node.get("label"),
            "file_path": file_path,
            "start_line": _int_or_none(node.get("start_line")),
            "end_line": _int_or_none(node.get("end_line")),
            "cbm_project_name": slug or None,
        }

    def _normalize_file_path(self, value) -> str:
        path = str(value or "").strip().replace("\\", "/")
        if not path or path in _NON_REPO_PATHS:
            return ""
        if _is_absolute(path):
            root = self.workspace_root or ""
            if root:
                # Case-insensitive on Windows (normcase), case-sensitive
                # on POSIX: drive-letter/casing drift must not leave a
                # workspace-local absolute path in a portable candidate.
                path_key = _casefold_path(path)
                root_key = _casefold_path(root)
                if path_key.startswith(root_key + "/"):
                    path = path[len(root) + 1 :]
                elif path_key == root_key:
                    path = ""
            # Otherwise left absolute: CodeReference validation rejects
            # it, which is the correct failure for an unknown root.
        return path

    def to_code_reference(
        self,
        candidate: dict,
        *,
        project_id: str,
        workspace_id: Optional[str] = None,
        reference_kind: Optional[str] = None,
        cbm_project_name: Optional[str] = None,
    ) -> CodeReference:
        """Convert a normalized candidate into a portable CodeReference.

        ``cbm_project_name`` optionally supplies the resolved project
        context for this conversion; otherwise the candidate's recorded
        slug (set during normalization) and finally the adapter default
        are used. It is metadata only — never part of the hashed
        identity.
        """
        rel_qn = (candidate.get("relative_qualified_name") or "").strip() or None
        kind = reference_kind or ("symbol" if rel_qn or candidate.get("name") else "file")
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
            cbm_project_name=cbm_project_name
            or candidate.get("cbm_project_name")
            or self.cbm_project_name,
        )
