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

import hashlib
import hmac
import json
import os
import re
import subprocess
from typing import Dict, List, Optional

from .code_reference import CodeReference, derive_language
from .identity import GitError, git_head_sha
from .memory import sanitize_error

DEFAULT_CBM_TIMEOUT = 30.0
CBM_CACHE_DIR_ENV = "CBM_CACHE_DIR"
# Keep the parser from accepting arbitrarily large child output.  The
# subprocess API still buffers the completed process before this guard can
# run; this is intentionally the smallest safe boundary without introducing
# a platform-specific streaming reader.
MAX_CHILD_OUTPUT_BYTES = 1024 * 1024

# CBM placeholder paths that are not repo files (project root node,
# external/stdlib symbols like <python-builtins>).
_NON_REPO_PATHS = frozenset({"{}", ""})
_GRAPH_REVISION_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")

ARCHITECTURE_DEFAULT_LIMIT = 5
ARCHITECTURE_MAX_LIMIT = 12
ARCHITECTURE_MAX_FIELD_CHARS = 256
ARCHITECTURE_MAX_PAYLOAD_BYTES = 16 * 1024
TRACE_DEFAULT_DEPTH = 2
TRACE_MAX_DEPTH = 3
TRACE_DEFAULT_LIMIT = 20
TRACE_MAX_LIMIT = 50
TRACE_MAX_FIELD_CHARS = 256
TRACE_MAX_PAYLOAD_BYTES = 24 * 1024
TRACE_DIRECTIONS = frozenset(("inbound", "outbound", "both"))

# VIS-2 bounded graph-explorer bounds: search and per-side relationship
# caps share one hard maximum, and depth reuses the TRACE_MAX_DEPTH
# ceiling. The node caps are frontend enforcement values the API reports
# but never enforces per request.
GRAPH_SEARCH_DEFAULT_LIMIT = 20
GRAPH_SEARCH_MAX_LIMIT = 20
GRAPH_RELATION_DEFAULT_LIMIT = 20
GRAPH_RELATION_MAX_LIMIT = 20
GRAPH_DEFAULT_DEPTH = 1
GRAPH_MAX_DEPTH = 3
GRAPH_NODE_LOOKUP_LIMIT = 50
GRAPH_NODE_MAX_PAYLOAD_BYTES = 32 * 1024


class CBMAdapterError(Exception):
    """Raised when the CBM CLI fails or returns an unusable payload."""


class CBMProjectNotIndexedError(CBMAdapterError):
    """Raised when a WORKING CBM backend reports the project as absent.

    Distinguishable from outages so callers can classify INDEX_MISSING
    (an honest missing state) instead of UNAVAILABLE. Following the
    anchored "symbol not found" precedent: only the exact CBM error
    phrase maps here; any other failure stays an outage-class
    ``CBMAdapterError``.
    """


class CBMNodeNotFoundError(CBMAdapterError):
    """Raised when a WORKING CBM backend reports the traced symbol absent.

    Distinguishable from outages so the graph explorer can classify an
    honest 404 (the symbol is no longer resolvable) instead of a backend
    failure. Only the anchored CBM "function not found" envelope maps
    here; any other trace failure stays an outage-class
    ``CBMAdapterError``.
    """


# CBM's stable error phrase for an absent/unindexed project, embedded in
# a JSON error envelope on stderr (exit 1) or a structured payload. The
# stderr match is ANCHORED: _run shapes failures as "cbm <tool> failed:
# <sanitized stderr>" and the envelope is the whole leading stderr when
# CBM emits it, so the envelope must start the failure detail — an
# outage whose stderr merely embeds the phrase mid-text stays
# outage-class (mirroring the "symbol not found" precedent).
_PROJECT_NOT_INDEXED_RE = re.compile(
    r'^cbm [a-z_]+ failed: \{"error"\s*:\s*"project not found or not indexed"',
    re.IGNORECASE,
)

# CBM 0.9.0 exits 1 with the same anchored shape for a trace_path lookup
# miss. Only the envelope at the START of the failure detail maps to
# ``CBMNodeNotFoundError``; an outage whose stderr merely mentions the
# phrase later stays an outage-class error. Real stderr prefixes the
# envelope with CBM's own ``level=info`` log lines (proven against the
# certified binary), so whole leading log lines are tolerated before the
# envelope while any other leading text still means outage.
_TRACE_NOT_FOUND_RE = re.compile(
    r'^cbm trace_path failed: (?:level=[^\n]*\n)*'
    r'\{\s*"error"\s*:\s*"function not found"',
    re.IGNORECASE,
)


def _verify_binary_sha256(cbm_bin: str, expected_sha256: Optional[str]) -> None:
    """Re-check a trust-gated executable immediately before running it."""
    if not expected_sha256:
        return
    digest = hashlib.sha256()
    try:
        with open(cbm_bin, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
    except OSError as exc:
        raise CBMAdapterError(
            "cbm executable changed or disappeared since trust verification"
        ) from exc
    if not hmac.compare_digest(digest.hexdigest(), expected_sha256):
        raise CBMAdapterError(
            "cbm executable hash changed since trust verification; refusing to execute"
        )


def strip_project_slug(qualified_name: str, cbm_project_name: str) -> str:
    """Remove the path-derived CBM project slug prefix from a qn.

    ``C-Users-dev-repo.src.calc.add`` with slug ``C-Users-dev-repo``
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
            payload, end = decoder.raw_decode(stripped)
        except (ValueError, RecursionError):
            continue
        if stripped[end:].strip():
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


_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[/\\]")


def _is_absolute_any_syntax(path: str) -> bool:
    """Absolute under EITHER platform syntax: POSIX root, drive-letter, UNC.

    A path that is absolute only under FOREIGN platform semantics must
    keep its identity verbatim: passing it through host-native
    ``os.path.abspath()`` prepends the current working directory and
    FABRICATES a host-local path that never existed (R5C: on POSIX,
    ``abspath("C:/work/ws-a")`` yields ``"<cwd>/C:/work/ws-a"``).
    """
    return bool(_WINDOWS_DRIVE_RE.match(path)) or path.startswith(("/", "\\\\"))


def _normalize_workspace_root(raw: str) -> str:
    """Portable workspace-root identity: forward slashes, no trailing slash.

    Host-relative paths resolve against the cwd (callers pass absolute
    roots; the relative case exists for tests). Foreign-absolute paths are
    preserved VERBATIM — this value is a portable workspace IDENTITY used
    for string-prefix relativization and safe.directory binding, never a
    host-local IO path.
    """
    text = str(raw).strip().replace("\\", "/").rstrip("/")
    if not text:
        return ""
    if _is_absolute_any_syntax(text):
        return text
    return os.path.abspath(text).replace("\\", "/").rstrip("/")


def _root_comparison_key(path: str) -> str:
    """Case/separator-insensitive root key WITHOUT host re-absolutization.

    ``os.path.normcase`` lowercases on Windows (case-insensitive FS) and
    is the identity on POSIX (case-sensitive FS), so comparison follows
    platform semantics for both operands symmetrically.
    """
    return os.path.normcase(str(path).strip().replace("\\", "/").rstrip("/"))


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
        expected_sha256: Optional[str] = None,
    ):
        if not cbm_bin or not str(cbm_bin).strip():
            raise CBMAdapterError("an explicit cbm binary path is required")
        self.cbm_bin = str(cbm_bin)
        self.cache_dir = str(cache_dir) if cache_dir else None
        self.cbm_project_name = (
            str(cbm_project_name).strip() if cbm_project_name else None
        )
        self.workspace_root = (
            _normalize_workspace_root(str(workspace_root)) or None
            if workspace_root
            else None
        )
        self.timeout = float(timeout)
        self.expected_sha256 = (
            str(expected_sha256).strip().lower() if expected_sha256 else None
        )

    # -- subprocess ---------------------------------------------------

    def _child_environment(self) -> dict:
        """Return only the environment CBM needs for a local executable."""
        env = {
            "PATH": os.environ.get("PATH", ""),
            "SystemRoot": os.environ.get("SystemRoot", ""),
            "WINDIR": os.environ.get("WINDIR", ""),
            "LC_ALL": "C.UTF-8",
            "LANG": "C.UTF-8",
        }
        # The audit/test runner may inject Git's safe.directory exception via
        # GIT_CONFIG_* environment variables. Preserve the security boundary
        # without inheriting the whole host environment: CBM must be able to
        # ask Git about the server-owned workspace even when its owner differs
        # from the sandbox identity.
        if self.workspace_root:
            env.update(
                {
                    "GIT_CONFIG_COUNT": "1",
                    "GIT_CONFIG_KEY_0": "safe.directory",
                    "GIT_CONFIG_VALUE_0": self.workspace_root,
                }
            )
        return env

    def _verify_binary(self) -> None:
        """Re-check a trust-gated production binary immediately before exec."""
        _verify_binary_sha256(self.cbm_bin, self.expected_sha256)

    @staticmethod
    def _output_size(value) -> int:
        if value is None:
            return 0
        if isinstance(value, bytes):
            return len(value)
        return len(str(value).encode("utf-8", errors="replace"))

    def _check_child_output(self, tool: str, result) -> None:
        for stream_name in ("stdout", "stderr"):
            size = self._output_size(getattr(result, stream_name, None))
            if size > MAX_CHILD_OUTPUT_BYTES:
                raise CBMAdapterError(
                    f"cbm {tool} {stream_name} exceeded the {MAX_CHILD_OUTPUT_BYTES}-byte output limit"
                )

    def _run(self, tool: str, flags: List[str]) -> object:
        self._verify_binary()
        argv = [self.cbm_bin, "cli", tool, *flags]
        env = self._child_environment()
        if self.cache_dir:
            env[CBM_CACHE_DIR_ENV] = self.cache_dir
        try:
            result = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
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
        except OSError as exc:
            raise CBMAdapterError(f"cbm {tool} could not be executed") from exc
        self._check_child_output(tool, result)
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
        if not isinstance(payload, dict):
            raise CBMAdapterError("cbm search_graph returned a non-object payload")
        if "error" in payload:
            raise CBMAdapterError("cbm search_graph returned an error payload")
        results = payload.get("results")
        if not isinstance(results, list):
            raise CBMAdapterError("cbm search_graph returned malformed results")
        candidates = []
        for node in results:
            if not isinstance(node, dict):
                raise CBMAdapterError("cbm search_graph returned a malformed result")
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

        Contract note (certified CBM 0.9.0): a MISSING symbol is not a
        JSON error payload — the CLI exits 1 with ``symbol not found``
        at the START of stderr. That is a lookup miss, not a backend
        outage, so it maps to None here. The match is anchored to the
        start of the failure detail: an outage whose stderr merely
        CONTAINS the phrase (e.g. "fatal: symbol not found table …
        index corrupted") still raises CBMAdapterError and degrades as
        an outage upstream.
        """
        slug = self._project(project)
        try:
            payload = self._run(
                "get_code_snippet",
                ["--project", slug, "--qualified-name", qualified_name],
            )
        except CBMAdapterError as exc:
            # _run shapes failures as "cbm <tool> failed: <sanitized
            # stderr>", so "failed: symbol not found" can only be the
            # not-found class emitted at the start of stderr — never a
            # wrapped outage that happens to embed the phrase later.
            if re.search(r"failed:\s*symbol not found", str(exc), re.IGNORECASE):
                return None
            raise
        if not isinstance(payload, dict):
            raise CBMAdapterError("cbm get_code_snippet returned a non-object payload")
        if "error" in payload:
            # Historical CBM fixtures encode a missing exact symbol as a
            # structured error, while certified 0.9.0 uses stderr. Preserve
            # that explicit miss contract, but never swallow arbitrary
            # backend errors as a lookup miss.
            error = str(payload.get("error") or "").strip()
            if re.match(r"^symbol not found(?:\\b|$)", error, re.IGNORECASE):
                return None
            raise CBMAdapterError("cbm get_code_snippet returned an error payload")
        candidate = self._normalize_node(payload, cbm_project_name=slug)
        if candidate is None:
            raise CBMAdapterError("cbm get_code_snippet returned a malformed node")
        return candidate

    # -- introspection -------------------------------------------------

    def probe_version(self) -> str:
        """Run ``--version`` and return the raw version line.

        Capability negotiation starts here: doctor/pin-policy classify
        the parsed version instead of assuming one. Raises
        CBMAdapterError when the binary cannot run.
        """
        self._verify_binary()
        try:
            result = subprocess.run(
                [self.cbm_bin, "--version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=self.timeout,
                env=self._child_environment(),
                shell=False,
            )
        except FileNotFoundError as exc:
            raise CBMAdapterError(
                f"cbm executable not found: {self.cbm_bin}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise CBMAdapterError("cbm --version timed out") from exc
        self._check_child_output("--version", result)
        if result.returncode != 0:
            detail = sanitize_error((result.stderr or result.stdout or "").strip())
            raise CBMAdapterError(f"cbm --version failed: {detail}")
        return (result.stdout or "").strip()

    def list_projects(self) -> List[dict]:
        """Indexed projects known to this cache (``cli list_projects``)."""
        payload = self._run("list_projects", [])
        if not isinstance(payload, dict):
            raise CBMAdapterError("cbm list_projects returned a non-object payload")
        if "error" in payload:
            raise CBMAdapterError("cbm list_projects returned an error payload")
        projects = payload.get("projects")
        if not isinstance(projects, list):
            raise CBMAdapterError("cbm list_projects returned malformed projects")
        if any(not isinstance(project, dict) for project in projects):
            raise CBMAdapterError("cbm list_projects returned a malformed project")
        return projects

    def index_status(self, project: Optional[str] = None) -> dict:
        """Index freshness/root facts for one project (``cli index_status``).

        Contract note (certified CBM 0.9.0): ``git.head_sha`` here is
        LIVE-DERIVED from the repository HEAD at query time, NOT the
        index-time head — it is never freshness evidence. Use it for
        ready/missing state, stats, and the live-accurate ``root_path``
        binding; use ``graph_index_head()`` for freshness. Raises
        ``CBMProjectNotIndexedError`` for the not-indexed error envelope
        and ``CBMAdapterError`` for outages and malformed payloads.
        """
        slug = self._project(project)
        payload = self._run_or_classify("index_status", ["--project", slug])
        if not isinstance(payload, dict):
            raise CBMAdapterError("cbm index_status returned a non-object payload")
        return payload

    def _classify_structured_error(self, tool: str, payload: object) -> None:
        """Raise for an error envelope, mapping the not-indexed phrase."""
        if isinstance(payload, dict) and "error" in payload:
            error = str(payload.get("error") or "").strip()
            if error.lower() == "project not found or not indexed":
                raise CBMProjectNotIndexedError(
                    f"cbm {tool} reported the project as not indexed"
                )
            raise CBMAdapterError(f"cbm {tool} returned an error payload")

    def _run_or_classify(self, tool: str, flags: List[str]) -> object:
        """``_run`` with the not-indexed error envelope classified."""
        try:
            payload = self._run(tool, flags)
        except CBMAdapterError as exc:
            # _run shapes failures as "cbm <tool> failed: <sanitized
            # stderr>"; the not-indexed JSON envelope is the only phrase
            # mapped to a miss-class error, mirroring the anchored
            # "symbol not found" precedent in get_snippet.
            if _PROJECT_NOT_INDEXED_RE.search(str(exc)):
                raise CBMProjectNotIndexedError(
                    f"cbm {tool} reported the project as not indexed"
                ) from exc
            raise
        self._classify_structured_error(tool, payload)
        return payload

    def graph_index_head(self, project: Optional[str] = None) -> Optional[str]:
        """Return the STORED index-time Branch head sha (``cli query_graph``).

        This is the authoritative stored freshness anchor: the graph's
        Branch node keeps the head captured at index time, unlike
        ``index_status`` whose head is re-derived live. Returns None
        when the indexed graph has no Branch node. Raises
        ``CBMProjectNotIndexedError`` for the not-indexed error envelope
        and ``CBMAdapterError`` for outages, malformed payloads, or a
        stored head that is not a 7-64 hex sha.
        """
        slug = self._project(project)
        payload = self._run_or_classify(
            "query_graph",
            [
                "--project",
                slug,
                "--query",
                "MATCH (n:Branch) RETURN n.head_sha AS h LIMIT 1",
            ],
        )
        if not isinstance(payload, dict):
            raise CBMAdapterError("cbm query_graph returned a non-object payload")
        rows = payload.get("rows")
        if not isinstance(rows, list):
            raise CBMAdapterError("cbm query_graph returned malformed rows")
        if not rows:
            return None
        row = rows[0]
        if not isinstance(row, list) or not row:
            raise CBMAdapterError("cbm query_graph returned a malformed row")
        head = row[0]
        if head is None:
            return None
        head = str(head).strip()
        if not head:
            raise CBMAdapterError("cbm query_graph returned an empty head sha")
        if not _GRAPH_REVISION_RE.fullmatch(head):
            raise CBMAdapterError("cbm query_graph returned a non-hex head sha")
        return head

    def detect_changes(self, project: Optional[str] = None) -> dict:
        """Uncommitted worktree drift vs the indexed graph (``cli detect_changes``).

        Returns ``{"changed_count": int, "changed_files": [unique
        sorted POSIX paths]}`` — CBM may emit duplicate paths, which are
        deduped here; non-string entries are dropped, never stringified.
        ``changed_count`` is CBM's raw count (it counts duplicates);
        committed changes with a clean worktree report clean. Raises
        ``CBMProjectNotIndexedError`` for the not-indexed error envelope
        and ``CBMAdapterError`` for outages and malformed payloads.
        """
        slug = self._project(project)
        payload = self._run_or_classify(
            "detect_changes", ["--project", slug]
        )
        if not isinstance(payload, dict):
            raise CBMAdapterError("cbm detect_changes returned a non-object payload")
        count = payload.get("changed_count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise CBMAdapterError(
                "cbm detect_changes returned a malformed changed_count"
            )
        raw_files = payload.get("changed_files")
        if not isinstance(raw_files, list):
            raise CBMAdapterError("cbm detect_changes returned malformed changed_files")
        files = sorted(
            {
                path.strip().replace("\\", "/")
                for path in raw_files
                if isinstance(path, str) and path.strip()
            }
        )
        return {"changed_count": count, "changed_files": files}

    def architecture_orientation(
        self,
        *,
        project: Optional[str] = None,
        path: Optional[str] = None,
        limit: int = ARCHITECTURE_DEFAULT_LIMIT,
    ) -> dict:
        """Return a compact, stable subset of CBM 0.9.0 architecture data.

        The certified tool accepts ``aspects=['overview']`` and returns a
        large object.  Relinkra deliberately consumes only aggregate counts,
        packages, languages, layers, boundaries, hotspots, and a few cluster
        representatives.  Raw qualified names and the CBM project slug do
        not cross this boundary.
        """
        slug = self._project(project)
        limit = self._bounded_limit(limit, ARCHITECTURE_MAX_LIMIT, "limit")
        flags = ["--project", slug, "--aspects", "overview"]
        if path:
            flags += ["--path", str(path).strip()]
        payload = self._run_or_classify("get_architecture", flags)
        if not isinstance(payload, dict):
            raise CBMAdapterError(
                "cbm get_architecture returned a non-object payload"
            )
        result = self._normalize_architecture(payload, limit)
        self._ensure_payload_bound(
            result, ARCHITECTURE_MAX_PAYLOAD_BYTES, "architecture"
        )
        return result

    def trace_relationships(
        self,
        *,
        function_name: str,
        project: Optional[str] = None,
        direction: str = "both",
        max_hops: int = TRACE_DEFAULT_DEPTH,
        limit: int = TRACE_DEFAULT_LIMIT,
        include_tests: bool = False,
    ) -> dict:
        """Return bounded caller/dependency relationships from ``trace_path``.

        CBM 0.9.0 returns ``callers`` and ``callees`` arrays whose entries
        contain only ``name``, ``qualified_name`` and ``hop`` for call traces.
        The adapter strips the path-derived slug, sorts deterministically,
        caps the result, and states explicitly that an empty graph result is
        not proof of absence. Test-code relationships are excluded from the
        graph by default (``--include-tests false``); ``include_tests``
        lifts that boundary for inbound questions whose callers live in
        test files.
        """
        slug = self._project(project)
        function_name = str(function_name or "").strip()
        if not function_name:
            raise CBMAdapterError("a function_name is required")
        direction = str(direction or "both").strip().lower()
        if direction not in TRACE_DIRECTIONS:
            raise CBMAdapterError(
                "trace direction must be inbound, outbound, or both"
            )
        if not isinstance(include_tests, bool):
            raise CBMAdapterError("include_tests must be a boolean")
        max_hops = self._bounded_limit(
            max_hops, TRACE_MAX_DEPTH, "max_hops", minimum=1
        )
        limit = self._bounded_limit(limit, TRACE_MAX_LIMIT, "limit")
        flags = [
            "--project", slug,
            "--function-name", function_name,
            "--direction", direction,
            "--depth", str(max_hops),
            "--mode", "calls",
            "--include-tests", "true" if include_tests else "false",
        ]
        payload = self._run_or_classify("trace_path", flags)
        if not isinstance(payload, dict):
            raise CBMAdapterError(
                "cbm trace_path returned a non-object payload"
            )
        if not payload:
            raise CBMAdapterError("cbm trace_path returned an empty payload")
        target = self._required_text(payload, "function", "trace_path")
        if target != function_name:
            raise CBMAdapterError(
                "cbm trace_path returned a mismatched function"
            )
        returned_direction = self._required_text(
            payload, "direction", "trace_path"
        ).lower()
        returned_mode = self._required_text(payload, "mode", "trace_path").lower()
        if returned_direction != direction or returned_mode != "calls":
            raise CBMAdapterError(
                "cbm trace_path returned an unexpected direction or mode"
            )
        relationships = []
        if direction in ("inbound", "both"):
            relationships.extend(
                self._normalize_trace_entries(
                    payload, "callers", "caller", slug, max_hops
                )
            )
        if direction in ("outbound", "both"):
            relationships.extend(
                self._normalize_trace_entries(
                    payload, "callees", "dependency", slug, max_hops
                )
            )
        relationships.sort(
            key=lambda item: (
                item["hop"], item["relationship"],
                item["qualified_name"], item["name"],
            )
        )
        truncated = len(relationships) > limit
        relationships = relationships[:limit]
        tests_note = (
            "Test-code relationships are included."
            if include_tests
            else "Test-code relationships are excluded by default; a "
            "caller living in a test file is invisible until "
            "include_tests is set."
        )
        result = {
            "target": self._bounded_text(
                strip_project_slug(target, slug), TRACE_MAX_FIELD_CHARS
            ),
            "direction": direction,
            "max_hops": max_hops,
            "relationships": relationships,
            "coverage": {
                "complete": False,
                "truncated": truncated,
                "returned": len(relationships),
                "requested_limit": limit,
                "requested_depth": max_hops,
                "include_tests": include_tests,
                "qualification": (
                    "No relationships were found in the current indexed "
                    "graph; this does not prove that none exist. "
                    + tests_note
                    + " Verify important claims against current source."
                    if not relationships
                    else "The bounded graph result may be incomplete. "
                    + tests_note
                    + " Native file and symbol exploration remains "
                    "available."
                ),
            },
        }
        self._ensure_payload_bound(result, TRACE_MAX_PAYLOAD_BYTES, "trace")
        return result

    def search_graph_page(
        self,
        *,
        query: Optional[str] = None,
        file_path: Optional[str] = None,
        project: Optional[str] = None,
        limit: int = GRAPH_SEARCH_DEFAULT_LIMIT,
    ) -> dict:
        """One bounded search_graph page: rich nodes plus coverage counts.

        Exactly one of ``query`` (bm25 symbol search) or ``file_path``
        (path-substring file search) is required. ``total`` is CBM's
        authoritative full match count and ``has_more`` its truncation
        evidence; both are preserved verbatim (or None when absent or
        malformed) because the viewer reports them as coverage facts.
        Candidates that cannot be focal-traced (empty project-relative
        qn) are dropped.
        """
        if bool(query) == bool(file_path):
            raise CBMAdapterError(
                "exactly one of query or file_path is required"
            )
        slug = self._project(project)
        limit = self._bounded_limit(limit, GRAPH_SEARCH_MAX_LIMIT, "limit")
        flags = ["--project", slug, "--limit", str(limit)]
        if query:
            flags += ["--query", str(query)]
        else:
            flags += ["--file-pattern", str(file_path)]
        payload = self._run_or_classify("search_graph", flags)
        if not isinstance(payload, dict):
            raise CBMAdapterError(
                "cbm search_graph returned a non-object payload"
            )
        if "error" in payload:
            raise CBMAdapterError("cbm search_graph returned an error payload")
        raw_results = payload.get("results")
        if not isinstance(raw_results, list):
            raise CBMAdapterError("cbm search_graph returned malformed results")
        candidates = []
        for node in raw_results:
            if not isinstance(node, dict):
                raise CBMAdapterError(
                    "cbm search_graph returned a malformed result"
                )
            candidate = self._normalize_node(node, cbm_project_name=slug)
            if candidate is None:
                continue
            if not (candidate.get("relative_qualified_name") or "").strip():
                # No project-relative qn means the node cannot be the
                # focal target of a later trace; never offer it.
                continue
            candidates.append(candidate)
        raw_total = payload.get("total")
        total = (
            raw_total
            if isinstance(raw_total, int)
            and not isinstance(raw_total, bool)
            and raw_total >= 0
            else None
        )
        raw_has_more = payload.get("has_more")
        has_more = raw_has_more if isinstance(raw_has_more, bool) else None
        return {"results": candidates, "total": total, "has_more": has_more}

    def graph_neighborhood(
        self,
        *,
        qualified_name: str,
        project: Optional[str] = None,
        depth: int = GRAPH_DEFAULT_DEPTH,
        include_tests: bool = True,
        inbound_limit: int = GRAPH_RELATION_DEFAULT_LIMIT,
        outbound_limit: int = GRAPH_RELATION_DEFAULT_LIMIT,
    ) -> dict:
        """One bounded both-direction call trace around a relative qn.

        ``qualified_name`` is the PROJECT-RELATIVE semantic qn; the full
        CBM qn is reconstructed with the resolved slug because the
        certified CLI only resolves the full form in ``trace_path``.
        Exactly one ``trace_path`` call returns both sides. CBM reports
        no relationship total, so coverage always states that the result
        may be incomplete and is not proof of absence.
        """
        relative_qn = str(qualified_name or "").strip()
        if not relative_qn:
            raise CBMAdapterError("a qualified_name is required")
        slug = self._project(project)
        depth = self._bounded_limit(
            depth, GRAPH_MAX_DEPTH, "depth", minimum=1
        )
        inbound_limit = self._bounded_limit(
            inbound_limit, GRAPH_RELATION_MAX_LIMIT, "inbound_limit"
        )
        outbound_limit = self._bounded_limit(
            outbound_limit, GRAPH_RELATION_MAX_LIMIT, "outbound_limit"
        )
        if not isinstance(include_tests, bool):
            raise CBMAdapterError("include_tests must be a boolean")
        full_qn = f"{slug}.{relative_qn}"
        flags = [
            "--project", slug,
            "--function-name", full_qn,
            "--direction", "both",
            "--depth", str(depth),
            "--mode", "calls",
            "--include-tests", "true" if include_tests else "false",
        ]
        try:
            payload = self._run_or_classify("trace_path", flags)
        except CBMAdapterError as exc:
            if _TRACE_NOT_FOUND_RE.search(str(exc)):
                raise CBMNodeNotFoundError(
                    "cbm trace_path reported the symbol as not found"
                ) from exc
            raise
        if not isinstance(payload, dict):
            raise CBMAdapterError(
                "cbm trace_path returned a non-object payload"
            )
        if not payload:
            raise CBMAdapterError("cbm trace_path returned an empty payload")
        target = self._required_text(payload, "function", "trace_path")
        if target != full_qn:
            raise CBMAdapterError(
                "cbm trace_path returned a mismatched function"
            )
        returned_direction = self._required_text(
            payload, "direction", "trace_path"
        ).lower()
        returned_mode = self._required_text(payload, "mode", "trace_path").lower()
        if returned_direction != "both" or returned_mode != "calls":
            raise CBMAdapterError(
                "cbm trace_path returned an unexpected direction or mode"
            )
        inbound = self._normalize_trace_entries(
            payload, "callers", "caller", slug, depth
        )
        outbound = self._normalize_trace_entries(
            payload, "callees", "dependency", slug, depth
        )
        for item in inbound:
            item["direction"] = "inbound"
        for item in outbound:
            item["direction"] = "outbound"
        inbound.sort(
            key=lambda item: (
                item["hop"], item["relationship"],
                item["qualified_name"], item["name"],
            )
        )
        outbound.sort(
            key=lambda item: (
                item["hop"], item["relationship"],
                item["qualified_name"], item["name"],
            )
        )
        inbound_truncated = len(inbound) > inbound_limit
        outbound_truncated = len(outbound) > outbound_limit
        inbound = inbound[:inbound_limit]
        outbound = outbound[:outbound_limit]
        tests_note = (
            "Test-code relationships are included."
            if include_tests
            else "Test-code relationships are excluded; a relationship "
            "living in a test file is invisible here."
        )
        result = {
            "target": self._bounded_text(
                strip_project_slug(target, slug), TRACE_MAX_FIELD_CHARS
            ),
            "depth": depth,
            "include_tests": include_tests,
            "inbound": inbound,
            "outbound": outbound,
            "coverage": {
                "depth": depth,
                "include_tests": include_tests,
                "inbound": {
                    "returned": len(inbound),
                    "limit": inbound_limit,
                    "truncated": inbound_truncated,
                    "total": None,
                },
                "outbound": {
                    "returned": len(outbound),
                    "limit": outbound_limit,
                    "truncated": outbound_truncated,
                    "total": None,
                },
                "complete": False,
                "qualification": (
                    "The backend reports no relationship total, so this "
                    "bounded result may be incomplete and is not proof of "
                    "absence. " + tests_note + " Verify important claims "
                    "against current source."
                ),
            },
        }
        self._ensure_payload_bound(
            result, GRAPH_NODE_MAX_PAYLOAD_BYTES, "graph"
        )
        return result

    def graph_node_lookup(
        self,
        relative_qualified_name: str,
        *,
        project: Optional[str] = None,
        limit: int = GRAPH_NODE_LOOKUP_LIMIT,
    ) -> Optional[dict]:
        """Exact-match node lookup by PROJECT-RELATIVE qualified name.

        ``--qn-pattern`` is a pattern filter, so CBM may return
        overmatches. Only a candidate whose stripped
        ``relative_qualified_name`` equals the requested qn exactly is
        returned; no exact match is None, never a best-effort guess.
        """
        relative_qn = str(relative_qualified_name or "").strip()
        if not relative_qn:
            raise CBMAdapterError("a qualified_name is required")
        slug = self._project(project)
        limit = self._bounded_limit(limit, GRAPH_NODE_LOOKUP_LIMIT, "limit")
        payload = self._run_or_classify(
            "search_graph",
            [
                "--project", slug,
                "--qn-pattern", relative_qn,
                "--limit", str(limit),
            ],
        )
        if not isinstance(payload, dict):
            raise CBMAdapterError(
                "cbm search_graph returned a non-object payload"
            )
        if "error" in payload:
            raise CBMAdapterError("cbm search_graph returned an error payload")
        results = payload.get("results")
        if not isinstance(results, list):
            raise CBMAdapterError("cbm search_graph returned malformed results")
        for node in results:
            if not isinstance(node, dict):
                raise CBMAdapterError(
                    "cbm search_graph returned a malformed result"
                )
            candidate = self._normalize_node(node, cbm_project_name=slug)
            if candidate is None:
                continue
            if (
                candidate.get("relative_qualified_name") or ""
            ).strip() == relative_qn:
                return candidate
        return None

    @staticmethod
    def _bounded_limit(value, maximum: int, name: str, minimum: int = 1) -> int:
        if isinstance(value, bool):
            raise CBMAdapterError(f"{name} must be an integer")
        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise CBMAdapterError(f"{name} must be an integer") from exc
        if parsed < minimum or parsed > maximum:
            raise CBMAdapterError(
                f"{name} must be between {minimum} and {maximum}"
            )
        return parsed

    @classmethod
    def _required_text(cls, payload: dict, key: str, tool: str) -> str:
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            raise CBMAdapterError(
                f"cbm {tool} returned malformed {key}"
            )
        return value.strip()

    @classmethod
    def _bounded_text(cls, value: str, maximum: int) -> str:
        if len(value) <= maximum:
            return value
        return value[: maximum - 3].rstrip() + "..."

    @staticmethod
    def _ensure_payload_bound(payload: dict, maximum: int, label: str) -> None:
        encoded = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        if len(encoded) > maximum:
            raise CBMAdapterError(
                f"cbm {label} evidence exceeded the {maximum}-byte output limit"
            )

    @staticmethod
    def _records(payload: dict, key: str, tool: str) -> List[dict]:
        if key not in payload:
            raise CBMAdapterError(f"cbm {tool} returned missing {key}")
        value = payload[key]
        if not isinstance(value, list):
            raise CBMAdapterError(
                f"cbm {tool} returned malformed {key}"
            )
        if any(not isinstance(item, dict) for item in value):
            raise CBMAdapterError(
                f"cbm {tool} returned malformed {key} entry"
            )
        return value

    def _normalize_architecture(self, payload: dict, limit: int) -> dict:
        if not payload:
            raise CBMAdapterError("cbm get_architecture returned an empty payload")
        project = self._required_text(payload, "project", "get_architecture")
        del project  # Validate the stable identity, but never expose the slug.
        aggregate = {}
        for key in ("total_nodes", "total_edges"):
            value = payload.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise CBMAdapterError(
                    f"cbm get_architecture returned malformed {key}"
                )
            aggregate[key] = value

        languages = []
        for item in self._records(payload, "languages", "get_architecture"):
            language = self._required_text(item, "language", "get_architecture")
            count = item.get("file_count")
            if not language or not isinstance(count, int) or isinstance(count, bool):
                raise CBMAdapterError(
                    "cbm get_architecture returned malformed language"
                )
            if count < 0:
                raise CBMAdapterError(
                    "cbm get_architecture returned malformed language"
                )
            languages.append({
                "language": self._bounded_text(language, ARCHITECTURE_MAX_FIELD_CHARS),
                "file_count": count,
            })
        languages.sort(key=lambda item: (item["language"].casefold(), item["language"]))

        packages = []
        for item in self._records(payload, "packages", "get_architecture"):
            name = self._required_text(item, "name", "get_architecture")
            count = item.get("node_count")
            if not name or not isinstance(count, int) or isinstance(count, bool):
                raise CBMAdapterError(
                    "cbm get_architecture returned malformed package"
                )
            if count < 0:
                raise CBMAdapterError(
                    "cbm get_architecture returned malformed package"
                )
            packages.append({
                "name": self._bounded_text(name, ARCHITECTURE_MAX_FIELD_CHARS),
                "node_count": count,
            })
        packages.sort(key=lambda item: (item["name"].casefold(), item["name"]))

        layers = []
        for item in self._records(payload, "layers", "get_architecture"):
            layer = self._required_text(item, "layer", "get_architecture")
            name = item.get("name")
            reason = item.get("reason")
            if not isinstance(name, str) or not isinstance(reason, str):
                raise CBMAdapterError(
                    "cbm get_architecture returned malformed layer"
                )
            name = name.strip()
            reason = reason.strip()
            if not layer:
                raise CBMAdapterError(
                    "cbm get_architecture returned malformed layer"
                )
            layers.append({
                "name": self._bounded_text(name, ARCHITECTURE_MAX_FIELD_CHARS),
                "layer": self._bounded_text(layer, ARCHITECTURE_MAX_FIELD_CHARS),
                "reason": self._bounded_text(reason, ARCHITECTURE_MAX_FIELD_CHARS),
            })
        layers.sort(key=lambda item: (item["layer"].casefold(), item["name"].casefold()))

        boundaries = []
        for item in self._records(payload, "boundaries", "get_architecture"):
            source = self._required_text(item, "from", "get_architecture")
            target = self._required_text(item, "to", "get_architecture")
            count = item.get("call_count")
            if not source or not target or not isinstance(count, int) or isinstance(count, bool):
                raise CBMAdapterError(
                    "cbm get_architecture returned malformed boundary"
                )
            if count < 0:
                raise CBMAdapterError(
                    "cbm get_architecture returned malformed boundary"
                )
            boundaries.append({
                "from": self._bounded_text(source, ARCHITECTURE_MAX_FIELD_CHARS),
                "to": self._bounded_text(target, ARCHITECTURE_MAX_FIELD_CHARS),
                "call_count": count,
            })
        boundaries.sort(key=lambda item: (item["from"].casefold(), item["to"].casefold()))

        hotspots = []
        for item in self._records(payload, "hotspots", "get_architecture"):
            name = self._required_text(item, "name", "get_architecture")
            qualified_name = self._required_text(
                item, "qualified_name", "get_architecture"
            )
            fan_in = item.get("fan_in")
            if not name or not isinstance(fan_in, int) or isinstance(fan_in, bool):
                raise CBMAdapterError(
                    "cbm get_architecture returned malformed hotspot"
                )
            if fan_in < 0:
                raise CBMAdapterError(
                    "cbm get_architecture returned malformed hotspot"
                )
            hotspots.append({
                "name": self._bounded_text(name, ARCHITECTURE_MAX_FIELD_CHARS),
                "fan_in": fan_in,
            })
        hotspots.sort(key=lambda item: (-item["fan_in"], item["name"].casefold(), item["name"]))

        clusters = []
        for item in self._records(payload, "clusters", "get_architecture"):
            label = self._required_text(item, "label", "get_architecture")
            members = item.get("members")
            top_nodes = item.get("top_nodes")
            if (
                not isinstance(members, int)
                or isinstance(members, bool)
                or members < 0
                or not isinstance(top_nodes, list)
            ):
                raise CBMAdapterError(
                    "cbm get_architecture returned malformed cluster"
                )
            if any(not isinstance(n, str) for n in top_nodes):
                raise CBMAdapterError(
                    "cbm get_architecture returned malformed cluster nodes"
                )
            clusters.append({
                "label": self._bounded_text(label, ARCHITECTURE_MAX_FIELD_CHARS),
                "members": members,
                "top_nodes": [
                    self._bounded_text(n.strip(), ARCHITECTURE_MAX_FIELD_CHARS)
                    for n in sorted({n.strip() for n in top_nodes if n.strip()})[:3]
                ],
            })
        clusters.sort(key=lambda item: (-item["members"], item["label"].casefold()))

        aggregate.update({
            "languages": languages[:limit],
            "packages": packages[:limit],
            "layers": layers[:limit],
            "boundaries": boundaries[:limit],
            "hotspots": hotspots[:limit],
            "clusters": clusters[: min(3, limit)],
        })
        return aggregate

    def _normalize_trace_entries(
        self,
        payload: dict,
        key: str,
        relationship: str,
        slug: str,
        max_hops: int,
    ) -> List[dict]:
        if key not in payload:
            raise CBMAdapterError(f"cbm trace_path returned missing {key}")
        value = payload[key]
        if not isinstance(value, list):
            raise CBMAdapterError(f"cbm trace_path returned malformed {key}")
        normalized: Dict[tuple, dict] = {}
        for item in value:
            if not isinstance(item, dict):
                raise CBMAdapterError(
                    f"cbm trace_path returned malformed {key} entry"
                )
            qn = self._required_text(item, "qualified_name", "trace_path")
            name = self._required_text(item, "name", "trace_path")
            hop = item.get("hop")
            if (
                not qn
                or not isinstance(hop, int)
                or isinstance(hop, bool)
                or hop < 1
                or hop > max_hops
            ):
                raise CBMAdapterError(
                    f"cbm trace_path returned malformed {key} entry"
                )
            relative_qn = strip_project_slug(qn, slug)
            if not relative_qn:
                raise CBMAdapterError(
                    f"cbm trace_path returned malformed {key} entry"
                )
            display_name = self._bounded_text(name, TRACE_MAX_FIELD_CHARS)
            record = {
                "relationship": relationship,
                "name": display_name,
                "qualified_name": self._bounded_text(
                    relative_qn, TRACE_MAX_FIELD_CHARS
                ),
                "hop": hop,
            }
            # The authoritative test marker is preserved ONLY when CBM
            # says True: an absent key means UNKNOWN, never False.
            if item.get("is_test") is True:
                record["is_test"] = True
            normalized[(relationship, relative_qn, hop)] = record
        return list(normalized.values())

    def code_evidence_authority(self) -> dict:
        """Return the portable graph attestation used by read-side evidence.

        Freshness (R5E.2A) is computed from REAL stored signals only:

        - the graph's STORED index-time Branch head (``graph_index_head``),
          compared against the workspace git HEAD — committed drift;
        - ``detect_changes`` — uncommitted worktree drift.

        ``index_status`` contributes only the live-accurate workspace
        root binding (and ready/missing state); its ``git.head_sha`` is
        live-derived and is NEVER freshness evidence. No cache path,
        project slug, host configuration, or raw status payload crosses
        this boundary. Stage detail strings are diagnostic surface
        only — portable packets strip them via
        ``linkage._portable_cbm_authority``.
        """
        portable_index = {"git": {}}

        def warn(detail: str) -> dict:
            return {
                "index_status": portable_index,
                "trust_stages": [
                    {"name": "CBM graph", "status": "WARN", "detail": detail}
                ],
            }

        try:
            status = self.index_status()
        except CBMProjectNotIndexedError:
            return warn("index missing for the recorded project")
        raw_root = status.get("root_path")
        if not (
            isinstance(raw_root, str)
            and raw_root.strip()
            and self.workspace_root
        ):
            return warn("graph state is missing a valid workspace root")
        status_root = _root_comparison_key(_normalize_workspace_root(raw_root))
        workspace_root = _root_comparison_key(self.workspace_root)
        if status_root != workspace_root:
            return warn("the indexed graph belongs to a different workspace root")

        try:
            stored_head = self.graph_index_head()
        except CBMProjectNotIndexedError:
            return warn("index missing for the recorded project")
        if not stored_head:
            return warn("graph state is missing a stored index HEAD")
        portable_index["git"]["head_sha"] = stored_head

        try:
            current_head = git_head_sha(self.workspace_root)
        except (GitError, ValueError):
            current_head = None
        if not (isinstance(current_head, str) and current_head.strip()):
            return warn("workspace HEAD could not be verified")
        if stored_head != current_head:
            return warn(
                f"stale index: graph at {stored_head[:8]}, workspace at "
                f"{current_head[:8]}"
            )

        try:
            changes = self.detect_changes()
        except CBMProjectNotIndexedError:
            return warn("index missing for the recorded project")
        changed_count = changes.get("changed_count")
        if (
            isinstance(changed_count, bool)
            or not isinstance(changed_count, int)
            or changed_count < 0
        ):
            return warn("graph state is missing valid change detection")
        if changed_count > 0:
            return warn(
                f"worktree has {changed_count} changed file(s) since the "
                "graph was indexed"
            )

        return {
            "index_status": portable_index,
            "trust_stages": [
                {
                    "name": "CBM graph",
                    "status": "PASS",
                    "detail": "graph matches this workspace and HEAD",
                }
            ],
        }

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
        candidate = {
            "name": node.get("name"),
            "qualified_name": qn,
            "relative_qualified_name": strip_project_slug(qn, slug),
            "label": node.get("label"),
            "file_path": file_path,
            "start_line": _int_or_none(node.get("start_line")),
            "end_line": _int_or_none(node.get("end_line")),
            "cbm_project_name": slug or None,
        }
        # Rich file/qn-search fields are preserved additively and only
        # when well-typed: a missing or malformed field stays absent
        # instead of becoming a None-valued key, so a query-mode node
        # keeps exactly its historical key set. Never copied: docstring,
        # signature, rank, last_modified, and the internal fp/sp/bt rows.
        for flag in ("is_test", "is_exported", "is_entry_point"):
            value = node.get(flag)
            if isinstance(value, bool):
                candidate[flag] = value
        for count in ("in_degree", "out_degree", "complexity", "lines"):
            value = node.get(count)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                candidate[count] = value
        return candidate

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
