"""Indexing orchestration for the Relinkra-managed CBM cache (R5E.2B).

Scope: INDEXING ORCHESTRATION ONLY. This module drives a full
``codebase-memory-mcp cli index_repository`` run into the
workspace-managed cache, registers the workspace-to-CBM mapping in the
Relinkra registry, classifies index freshness from real stored signals,
and recovers from the known CBM 0.9.0 modify-only re-index quirk.

Boundaries:

- ``CBMCLIAdapter`` stays the QUERY/READ-ONLY surface. This module
  orchestrates the index command and reads freshness through the
  adapter's stored-head and change-detection probes — nothing else.
- No source mutation: the only filesystem writes are derived,
  rebuildable cache data (the project ``.db`` and its ``-wal``/``-shm``
  companions) plus the Relinkra registry record describing the mapping.
- CBM is invoked ONLY with flags syntax; raw-JSON positional arguments
  crash the CBM 0.9.0 worker.
- The cache is derived data: deleting it costs nothing but a re-index.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .cbm import cbm_db_path, workspace_cbm_record
from .cbm_adapter import (
    CBMAdapterError,
    CBMCLIAdapter,
    CBMProjectNotIndexedError,
    parse_cli_json,
)
from .cbm_support import (
    CERTIFIED_CBM_BINARIES,
    _sha256_file,
    absolutize_against_root,
    platform_tag,
)
from .identity import (
    AmbiguousIdentityError,
    GitError,
    derive_project_id,
    discover_repository_identity,
    git_branch,
    git_head_sha,
)
from .memory import sanitize_error
from .registry import Registry, RegistryError


class IndexSetupError(Exception):
    """Raised when indexing orchestration cannot proceed or has failed."""


class MalformedIndexResponseError(IndexSetupError):
    """Raised when the index CLI answered with an unusable payload.

    Distinguishes contract violations (missing/invalid fields in an
    otherwise successful response) from execution failures, which raise
    plain ``IndexSetupError``.
    """


class StaleAfterRefreshError(IndexSetupError):
    """Raised when the index is still stale after a full reindex plus
    exactly one quirk-recovery attempt. Further deletions/reindexes are
    a human decision, never an automated retry loop.
    """


#: Index freshness states (R5E.2B). The four graded states carry real
#: drift flags; the four degenerate ones carry None flags because the
#: drift is not knowable in that state.
READY = "READY"
STALE_COMMITTED = "STALE_COMMITTED"
STALE_WORKTREE = "STALE_WORKTREE"
STALE_BOTH = "STALE_BOTH"
MISSING = "MISSING"
UNAVAILABLE = "UNAVAILABLE"
UNSUPPORTED = "UNSUPPORTED"
UNKNOWN = "UNKNOWN"
#: The resolved binary exists on a certified platform but does NOT hash
#: to the certified pin. Provenance-before-execution: the state is
#: reported WITHOUT running the binary (R5E.2B trust-gate correction).
UNTRUSTED = "UNTRUSTED"

#: Default bound for one full index run (a hung indexer must never hang
#: the orchestrator).
DEFAULT_INDEX_TIMEOUT = 600.0

#: Bound on the sanitized stderr tail embedded in failure errors.
ERROR_TAIL_CHARS = 400

#: The only cache filenames quirk recovery may ever delete: the project
#: database and its SQLite write-ahead/share-memory companions.
_QUIRK_SUFFIXES = (".db", ".db-wal", ".db-shm")


# ---------------------------------------------------------------------------
# Workspace resolution
# ---------------------------------------------------------------------------


def _workspace_root(start: Optional[str] = None) -> Optional[Path]:
    """Walk upward for a ``.git`` entry (mirrors product_cli._repo_root).

    Accepts a ``.git`` FILE as well as a directory so worktrees and
    submodules resolve, and stops at the filesystem root on every
    platform via the parent-is-self test.
    """
    current = Path(start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def resolve_workspace(path: Optional[str] = None) -> Tuple[str, str]:
    """Resolve the workspace root and its logical project id.

    Walks up from ``path`` (or the cwd) to the enclosing git root,
    discovers the repository identity exactly like the register CLI,
    and derives the ``rlk_...`` project id from it.

    Raises ``IndexSetupError`` — with an actionable message — when the
    path is not inside a git repository, or the repository has no
    commits / unusable remotes so identity cannot be derived.
    """
    root = _workspace_root(path)
    if root is None:
        raise IndexSetupError(
            "not a git repository: no .git entry found at or above the "
            "given path; run from inside the repository checkout or pass "
            "an explicit repository path"
        )
    try:
        identity = discover_repository_identity(str(root))
    except GitError as exc:
        raise IndexSetupError(
            "repository identity could not be derived from git "
            f"(an initial commit is required before indexing): {exc}"
        ) from exc
    except ValueError as exc:
        raise IndexSetupError(f"repository identity is unusable: {exc}") from exc
    return str(root), derive_project_id(identity.value)


# ---------------------------------------------------------------------------
# Cache planning
# ---------------------------------------------------------------------------


def plan_cache(root: str) -> Tuple[Path, str]:
    """Return ``(absolute cache Path, registry record string)``.

    The absolute path is ``<root>/.codebase-memory/cache``. Nothing is
    created here — creation belongs to the index run itself. The record
    string is the workspace-relative value stored in the registry's CBM
    record and re-resolved through containment checks on read.
    """
    cache_dir = Path(os.path.abspath(str(root))) / ".codebase-memory" / "cache"
    return cache_dir, ".codebase-memory/cache"


def gitignore_check(root: str) -> Dict[str, bool]:
    """Report whether the managed cache looks git-ignored (READ-ONLY).

    True when the root ``.gitignore`` OR ``.git/info/exclude`` contains
    a line whose stripped content equals ``.codebase-memory/`` or
    ``.codebase-memory`` or starts with ``.codebase-memory``.

    Simple-match limits (deliberate): this is a heuristic for humans,
    not a gitignore engine. It checks only the ROOT ignore files (not
    nested .gitignore files), ignores negation (``!``) patterns and
    anchored/negated interplay, does not evaluate git attributes, and
    never invokes git. A False answer is therefore "not known to be
    ignored", not a guarantee. This function NEVER writes: both files
    are only read.
    """
    base = Path(root)
    candidates = (
        base / ".gitignore",
        base / ".git" / "info" / "exclude",
    )
    for candidate in candidates:
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for raw_line in text.splitlines():
            entry = raw_line.strip()
            if not entry or entry.startswith("#"):
                continue
            if (
                entry == ".codebase-memory/"
                or entry == ".codebase-memory"
                or entry.startswith(".codebase-memory")
            ):
                return {"ignored": True}
    return {"ignored": False}


# ---------------------------------------------------------------------------
# Index execution
# ---------------------------------------------------------------------------


def _index_child_environment(root: str, cache_dir: str) -> Dict[str, str]:
    """Minimal child env for the indexer (mirrors CBMCLIAdapter._run).

    Only what a local executable needs, plus ``CBM_CACHE_DIR`` placing
    the cache inside the workspace, plus the same bounded Git
    safe.directory exception the adapter grants so CBM can ask Git
    about the workspace it is indexing. The host environment is never
    inherited wholesale.
    """
    env = {
        "PATH": os.environ.get("PATH", ""),
        "SystemRoot": os.environ.get("SystemRoot", ""),
        "WINDIR": os.environ.get("WINDIR", ""),
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        "CBM_CACHE_DIR": str(cache_dir),
    }
    if root:
        env.update(
            {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "safe.directory",
                "GIT_CONFIG_VALUE_0": str(root),
            }
        )
    return env


def _int_or_default(value) -> int:
    """Coerce a payload count to int when present; default 0, never raise."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return 0
    return 0


def run_index(
    binary: str,
    root: str,
    cache_dir: str,
    mode: str = "fast",
    timeout: float = DEFAULT_INDEX_TIMEOUT,
) -> Dict:
    """Run one full ``cli index_repository`` pass (flags syntax only).

    Returns ``{"project_name": str, "nodes": int, "edges": int,
    "raw_status": str}``. Failure mapping:

    - non-zero exit or an ``{"error": ...}`` envelope →
      ``IndexSetupError`` with a sanitized (secret-free, bounded)
      stderr/payload tail;
    - payload not an object, ``status`` not ``"indexed"``, or a
      missing/empty ``project`` → ``MalformedIndexResponseError``
      naming the offending field;
    - timeout → ``IndexSetupError`` containing "timed out".

    ``nodes``/``edges`` default to 0 when absent and never crash on
    non-int values. CBM is invoked ONLY with ``--flag value`` pairs —
    a raw-JSON positional crashes the CBM 0.9.0 worker.
    """
    argv = [
        str(binary),
        "cli",
        "index_repository",
        "--repo-path",
        str(root),
        "--mode",
        str(mode),
    ]
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=float(timeout),
            env=_index_child_environment(root, cache_dir),
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise IndexSetupError(
            f"cbm index_repository timed out after {float(timeout):g}s"
        ) from exc
    except FileNotFoundError as exc:
        raise IndexSetupError(f"cbm executable not found: {binary}") from exc
    except OSError as exc:
        raise IndexSetupError(
            f"cbm index_repository could not be executed: {exc}"
        ) from exc
    if result.returncode != 0:
        detail = sanitize_error((result.stderr or result.stdout or "").strip())
        raise IndexSetupError(
            f"cbm index_repository failed: {detail[-ERROR_TAIL_CHARS:]}"
        )
    try:
        payload = parse_cli_json(result.stdout or "")
    except CBMAdapterError as exc:
        raise MalformedIndexResponseError(
            f"cbm index_repository returned no JSON object on stdout ({exc})"
        ) from exc
    if not isinstance(payload, dict):
        raise MalformedIndexResponseError(
            "cbm index_repository returned a non-object payload"
        )
    if "error" in payload:
        detail = sanitize_error(str(payload.get("error") or ""))[:200]
        raise IndexSetupError(f"cbm index_repository reported an error: {detail}")
    status = payload.get("status")
    if status != "indexed":
        raise MalformedIndexResponseError(
            f"cbm index_repository status field was not 'indexed': {status!r}"
        )
    project = payload.get("project")
    if not isinstance(project, str) or not project.strip():
        raise MalformedIndexResponseError(
            "cbm index_repository response is missing a non-empty 'project' field"
        )
    return {
        "project_name": project,
        "nodes": _int_or_default(payload.get("nodes")),
        "edges": _int_or_default(payload.get("edges")),
        "raw_status": str(status),
    }


# ---------------------------------------------------------------------------
# Mapping registration
# ---------------------------------------------------------------------------


def register_mapping(
    registry_path: str,
    root: str,
    project_name: str,
    cache_dir_rel: str,
    version: Optional[str],
    sha256: Optional[str],
) -> Dict:
    """Register (or idempotently refresh) the workspace-to-CBM mapping.

    Mirrors the register CLI: discovers the repository identity, records
    branch/head git facts, and stores the CBM record built by
    ``workspace_cbm_record`` (project slug + workspace-relative
    cache_dir + binary version/sha256 provenance).

    Idempotency (verified against registry.py): re-registering the SAME
    canonical path resolves to the SAME workspace_id and only refreshes
    ``last_seen_at`` plus the supplied ``git``/``cbm`` metadata — no
    duplicate project or workspace is created, so re-index + re-register
    is always safe. ``RegistryError``/``AmbiguousIdentityError`` are
    wrapped as typed ``IndexSetupError``. Returns the existing/updated
    workspace dict.
    """
    try:
        repository_identity = discover_repository_identity(str(root))
        git_info = {
            "branch": git_branch(str(root)),
            "head_sha": git_head_sha(str(root)),
        }
    except (GitError, ValueError) as exc:
        raise IndexSetupError(
            f"workspace git facts could not be read for registration: {exc}"
        ) from exc
    cbm_record = workspace_cbm_record(
        str(project_name),
        str(cache_dir_rel),
        version=version,
        sha256=sha256,
    ).to_dict()
    try:
        registry = Registry(str(registry_path))
        workspace = registry.register_workspace(
            str(root),
            repository_identity,
            git=git_info,
            cbm=cbm_record,
        )
    except AmbiguousIdentityError as exc:
        raise IndexSetupError(
            "weak repository identity matches an existing project and "
            f"needs explicit merge confirmation: {exc}"
        ) from exc
    except (RegistryError, ValueError) as exc:
        raise IndexSetupError(f"registry registration failed: {exc}") from exc
    return workspace.to_dict()


# ---------------------------------------------------------------------------
# Freshness classification (read-only)
# ---------------------------------------------------------------------------


def _freshness_result(
    state: str,
    committed: Optional[bool] = None,
    worktree: Optional[bool] = None,
) -> Dict:
    return {"state": state, "committed_drift": committed, "worktree_drift": worktree}


def _record_field(record, key: str) -> str:
    if not isinstance(record, dict):
        return ""
    value = record.get(key)
    return value.strip() if isinstance(value, str) else ""


def freshness_state(
    binary: Optional[str],
    root: str,
    record: Optional[dict],
    *,
    timeout: Optional[float] = None,
) -> Dict:
    """Classify index freshness from real stored signals (READ-ONLY).

    Returns ``{"state": str, "committed_drift": bool|None,
    "worktree_drift": bool|None}`` with the module-level state constants.
    Decision order:

    - no resolvable binary → ``UNAVAILABLE`` (flags None);
    - platform without certified CBM provenance (cbm_support tag/map)
      → ``UNSUPPORTED`` (flags None);
    - binary that does not hash to the certified pin → ``UNTRUSTED``
      (flags None) — reported WITHOUT executing the binary
      (provenance-before-execution);
    - malformed record, cache_dir outside the managed subtree, or a
      missing project ``.db`` file → ``UNKNOWN`` / ``MISSING``;
    - committed drift: stored ``graph_index_head()`` vs
      ``git_head_sha(root)`` (the stored Branch head is the only
      freshness anchor — ``index_status``'s head is live-derived);
    - worktree drift: ``detect_changes()`` ``changed_count > 0``;
    - both clean → ``READY``; combinations → ``STALE_COMMITTED`` /
      ``STALE_WORKTREE`` / ``STALE_BOTH``;
    - any ``CBMAdapterError`` (outage/malformed payload) or GitError →
      ``UNKNOWN`` — never ``READY``. A graph with no stored Branch head
      is also ``UNKNOWN``: freshness cannot be verified.

    ``CBMProjectNotIndexedError`` from any probe is an honest
    ``MISSING``.
    """
    if not binary or not str(binary).strip():
        return _freshness_result(UNAVAILABLE)
    tag = platform_tag()
    if tag not in CERTIFIED_CBM_BINARIES:
        return _freshness_result(UNSUPPORTED)
    expected = CERTIFIED_CBM_BINARIES.get(tag) or {}
    expected_sha = str(expected.get("sha256") or "").lower()
    actual_sha = (_sha256_file(str(binary)) or "").lower()
    if not expected_sha or actual_sha != expected_sha:
        # Provenance-before-execution (R5E.2B trust-gate correction):
        # the binary is NEVER probed when it does not hash to the
        # certified pin, wherever it was resolved from (env, managed
        # dir, or PATH).
        return _freshness_result(UNTRUSTED)
    project_name = _record_field(record, "project_name")
    raw_cache = _record_field(record, "cache_dir")
    if not project_name or not raw_cache:
        return _freshness_result(UNKNOWN)
    try:
        cache_dir = absolutize_against_root(str(root), raw_cache)
    except ValueError:
        return _freshness_result(UNKNOWN)
    if not os.path.isfile(cbm_db_path(cache_dir, project_name)):
        return _freshness_result(MISSING)
    adapter_kwargs = {"expected_sha256": expected_sha}
    if timeout is not None:
        adapter_kwargs["timeout"] = timeout
    try:
        adapter = CBMCLIAdapter(
            cbm_bin=str(binary),
            cache_dir=cache_dir,
            cbm_project_name=project_name,
            workspace_root=str(root),
            **adapter_kwargs,
        )
    except CBMAdapterError:
        return _freshness_result(UNKNOWN)
    try:
        stored = adapter.graph_index_head()
    except CBMProjectNotIndexedError:
        return _freshness_result(MISSING)
    except CBMAdapterError:
        return _freshness_result(UNKNOWN)
    if not stored:
        return _freshness_result(UNKNOWN)
    try:
        current = git_head_sha(str(root))
    except (GitError, ValueError):
        return _freshness_result(UNKNOWN)
    committed_drift = stored != current
    try:
        changes = adapter.detect_changes()
    except CBMProjectNotIndexedError:
        return _freshness_result(MISSING)
    except CBMAdapterError:
        return _freshness_result(UNKNOWN)
    count = changes.get("changed_count")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        return _freshness_result(UNKNOWN)
    worktree_drift = count > 0
    if committed_drift and worktree_drift:
        return _freshness_result(STALE_BOTH, committed_drift, worktree_drift)
    if committed_drift:
        return _freshness_result(STALE_COMMITTED, committed_drift, worktree_drift)
    if worktree_drift:
        return _freshness_result(STALE_WORKTREE, committed_drift, worktree_drift)
    return _freshness_result(READY, committed_drift, worktree_drift)


# ---------------------------------------------------------------------------
# Refresh with quirk recovery
# ---------------------------------------------------------------------------


def _quirk_delete_targets(cache_dir: str, project_name) -> List[str]:
    """The ONLY paths quirk recovery may delete, asserted by construction.

    Strictly ``<cache_dir>/<project_name>.db`` plus its ``-wal`` and
    ``-shm`` companions. The project name must be a safe slug (no
    separators, no ``.``/``..``), and every resolved target must have
    the resolved cache dir as its parent and a name that is the project
    name plus a known suffix — otherwise ``IndexSetupError`` is raised
    and nothing is touched. Defense in depth: the path-assert holds
    even if slug validation were ever bypassed.
    """
    name = project_name if isinstance(project_name, str) else ""
    if (
        not name.strip()
        or name in {".", ".."}
        or os.path.basename(name) != name
        or "/" in name
        or "\\" in name
    ):
        raise IndexSetupError(
            "cbm project name is not a safe cache slug; refusing cache cleanup"
        )
    cache_real = os.path.realpath(os.path.abspath(str(cache_dir)))
    targets: List[str] = []
    for suffix in _QUIRK_SUFFIXES:
        candidate = os.path.realpath(os.path.join(cache_real, name + suffix))
        if os.path.dirname(candidate) != cache_real:
            raise IndexSetupError(
                "quirk recovery target escapes the cache directory; refusing"
            )
        base = os.path.basename(candidate)
        if not (base.startswith(name) and base.endswith(suffix)):
            raise IndexSetupError(
                "quirk recovery target has an unexpected name; refusing"
            )
        targets.append(candidate)
    return targets


def _delete_quirk_targets(targets: List[str]) -> None:
    """Delete exactly the asserted candidate files, nothing else."""
    for target in targets:
        if os.path.exists(target) and not os.path.isfile(target):
            raise IndexSetupError(
                "quirk recovery target is not a regular file; refusing "
                f"to delete: {os.path.basename(target)}"
            )
    for target in targets:
        if os.path.exists(target):
            os.remove(target)


def _refresh_head_matches(
    binary: str,
    root: str,
    cache_dir: str,
    project_name: str,
    expected_sha256: Optional[str] = None,
) -> bool:
    """True when the STORED graph head equals the workspace HEAD."""
    adapter = CBMCLIAdapter(
        cbm_bin=str(binary),
        cache_dir=str(cache_dir),
        cbm_project_name=str(project_name),
        workspace_root=str(root),
        expected_sha256=expected_sha256,
    )
    try:
        stored = adapter.graph_index_head()
    except CBMAdapterError as exc:
        raise IndexSetupError(
            f"index refresh could not be verified: {sanitize_error(str(exc))}"
        ) from exc
    try:
        current = git_head_sha(str(root))
    except (GitError, ValueError) as exc:
        raise IndexSetupError(
            f"workspace HEAD could not be read after indexing: {exc}"
        ) from exc
    return bool(stored) and stored == current


def refresh_with_quirk_recovery(
    binary: str,
    root: str,
    cache_dir: str,
    project_name: str,
    mode: str = "fast",
    expected_sha256: Optional[str] = None,
) -> Dict:
    """Full reindex, then recover once from the CBM 0.9.0 modify-only quirk.

    CBM 0.9.0 keeps the stored index-time Branch head when a re-index
    only modifies an existing project, leaving the graph honestly stale
    even after a successful run. Flow:

    1. full reindex (``run_index``);
    2. verify the stored graph head now equals the workspace HEAD —
       match → ``{"quirk_recovery_used": False, "result": ...}``;
    3. on mismatch (known quirk): delete STRICTLY
       ``<cache_dir>/<project_name>.db`` plus its ``-wal``/``-shm``
       companions (path-asserted; ``IndexSetupError`` and no deletion
       otherwise) — nothing else in the cache is touched;
    4. reindex ONCE more and recheck;
    5. still stale → ``StaleAfterRefreshError``. Never more than one
       recovery attempt.
    """
    result = run_index(binary, root, cache_dir, mode=mode)
    if _refresh_head_matches(
        binary, root, cache_dir, project_name, expected_sha256
    ):
        return {"quirk_recovery_used": False, "result": result}
    targets = _quirk_delete_targets(cache_dir, project_name)
    _delete_quirk_targets(targets)
    result = run_index(binary, root, cache_dir, mode=mode)
    if not _refresh_head_matches(
        binary, root, cache_dir, project_name, expected_sha256
    ):
        raise StaleAfterRefreshError(
            "index is still stale after a full reindex and one quirk "
            f"recovery for project {project_name}; the cache may need "
            "manual inspection"
        )
    return {"quirk_recovery_used": True, "result": result}
