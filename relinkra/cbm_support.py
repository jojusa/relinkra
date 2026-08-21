"""CBM version/pin policy for the certified private backend (R4C.1A).

Relinkra certifies EXACT CBM releases against the adapter contract; it
never follows ``latest`` blindly. This module is the single importable
source of truth for:

- the certified CBM version and its per-platform binary provenance
  (SHA-256 verified at acquisition time against the release checksums
  and the GitHub release metadata);
- the supported version range the adapter can talk to;
- the adapter contract version (the CLI flags + JSON shapes
  ``CBMCLIAdapter`` depends on);
- version classification (certified / supported / unsupported);
- binary resolution for diagnostics: explicit env, then the per-user
  Relinkra-managed certified binary (R5H.1), then the workspace-managed
  location, then PATH — never an agent configuration.

The human-readable policy (upgrade detection, rollback, fixture
strategy) lives in ``docs/cbm-backend.md``.
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
from dataclasses import dataclass
from typing import List, Mapping, Optional, Tuple

from .cbm import cbm_db_path
from .cbm_adapter import (
    CBMAdapterError,
    CBMCLIAdapter,
    CBMProjectNotIndexedError,
)
from .identity import GitError, git_head_sha
from .memory import sanitize_error

#: Exact CBM release certified as Relinkra's private backend in R4C.1A.
CERTIFIED_CBM_VERSION = "0.9.0"

#: Inclusive lower / exclusive upper bounds the adapter contract is
#: verified against. Anything outside fails honestly (unsupported).
SUPPORTED_CBM_MIN = (0, 9, 0)
SUPPORTED_CBM_MAX_EXCLUSIVE = (0, 10, 0)

#: The CLI contract the adapter speaks: ``cli search_graph`` /
#: ``cli get_code_snippet`` with flag arguments, JSON payloads on
#: stdout, diagnostics on stderr, CBM_CACHE_DIR for cache placement.
CBM_ADAPTER_CONTRACT = "cbm-cli/v1"

#: Provenance of the certified release binaries, keyed by platform tag.
#: Values are the SHA-256 of the UNPACKED executable, verified against
#: the upstream release's published verification table (and the zip
#: against checksums.txt + the GitHub asset digest) at certification
#: time. Binaries are NEVER committed; this map lets doctor detect a
#: swapped or corrupted managed binary.
CERTIFIED_CBM_BINARIES = {
    "windows-amd64": {
        "version": "0.9.0",
        "sha256": "9a205fa5ae759fbc866bfe1554f0c05a303be9ae6e0a00f94d875dc0c25e0680",
        "release_zip_sha256": "92f96896f952e539f0d6cb34d7892a25064b677ccbf808b8f8310ad897e86f2c",
        "release_url": (
            "https://github.com/DeusData/codebase-memory-mcp/releases/tag/v0.9.0"
        ),
    },
}

#: Version classification outcomes.
VERSION_CERTIFIED = "certified"
VERSION_SUPPORTED = "supported"
VERSION_UNSUPPORTED = "unsupported"
VERSION_UNKNOWN = "unknown"

_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_NAMED_VERSION_RE = re.compile(r"codebase-memory-mcp\s+(\d+)\.(\d+)\.(\d+)")

#: Workspace-relative, Relinkra-managed location for the isolated CBM
#: binary. Git-ignored (``.codebase-memory/``); never an agent config.
MANAGED_CBM_BIN_DIR = os.path.join(".codebase-memory", "bin")

_CBM_EXE_NAMES = ("codebase-memory-mcp.exe", "codebase-memory-mcp")


def _selected_version_match(text: str):
    """Return the version token selected by the documented precedence rule."""
    named = _NAMED_VERSION_RE.search(text or "")
    return named or (list(_VERSION_RE.finditer(text or "")) or [None])[-1]


def parse_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Extract an ``(major, minor, patch)`` tuple from tool output.

    The triple printed after the program name wins; otherwise the LAST
    dotted triple is used, so a prefixed toolchain version ("go1.22.3 …
    codebase-memory-mcp 0.9.0") cannot shadow the tool's own version.
    """
    match = _selected_version_match(text)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def classify_version(version: Optional[str]) -> str:
    """Classify a CBM version string against the pin policy.

    ``certified`` is the exact pinned release; ``supported`` is inside
    the verified range but not certified (upgrade candidate — adopt only
    after re-certification); ``unsupported`` fails honestly;
    ``unknown`` means the version could not be determined at all.
    """
    parsed = parse_version(version or "")
    if parsed is None:
        return VERSION_UNKNOWN
    # ``parse_version`` intentionally remains tuple-compatible for callers,
    # but certification also requires the selected release to be a complete,
    # stable token.  Without this check ``0.9.0foo`` would be certified just
    # because its leading tuple happens to match the pin.
    selected = _selected_version_match(version or "")
    suffix = (version or "")[selected.end():] if selected is not None else ""
    is_stable = not suffix or not re.match(r"[0-9A-Za-z.+_-]", suffix)
    if parsed == parse_version(CERTIFIED_CBM_VERSION) and is_stable:
        return VERSION_CERTIFIED
    if SUPPORTED_CBM_MIN <= parsed < SUPPORTED_CBM_MAX_EXCLUSIVE:
        return VERSION_SUPPORTED
    return VERSION_UNSUPPORTED


def managed_binary_candidates(root: str) -> List[str]:
    """Workspace-managed binary paths, most specific first."""
    return [
        os.path.join(root, MANAGED_CBM_BIN_DIR, name) for name in _CBM_EXE_NAMES
    ]


def relinkra_data_root(environ: Optional[Mapping[str, str]] = None) -> str:
    """Per-user data root for Relinkra-managed, cross-workspace state.

    ``RELINKRA_DATA_ROOT`` overrides everything (an advanced/testing
    seam; normal users never set it). Windows: ``~/.local/relinkra``
    (the established pilot convention, kept uniform across platforms);
    elsewhere: ``$XDG_DATA_HOME/relinkra`` or ``~/.local/share/relinkra``.
    """
    env = environ if environ is not None else os.environ
    override = (env.get("RELINKRA_DATA_ROOT") or "").strip()
    if override:
        return override
    home = os.path.expanduser("~")
    if platform.system().lower() == "windows":
        return os.path.join(home, ".local", "relinkra")
    xdg = (env.get("XDG_DATA_HOME") or "").strip()
    base = xdg if xdg else os.path.join(home, ".local", "share")
    return os.path.join(base, "relinkra")


def managed_cbm_binary_path(
    version: str,
    tag: str,
    data_root: Optional[str] = None,
) -> str:
    """Per-user managed binary path for a certified (version, tag) pair.

    ``<data_root>/backends/cbm/<version>/codebase-memory-mcp[.exe]`` —
    versioned and deterministic, outside any project repository, shared
    across projects and agent hosts. ``data_root`` defaults to
    :func:`relinkra_data_root`.
    """
    root = data_root if data_root is not None else relinkra_data_root()
    name = (
        "codebase-memory-mcp.exe" if tag.startswith("windows") else "codebase-memory-mcp"
    )
    return os.path.join(root, "backends", "cbm", version, name)


def resolve_cbm_binary(
    root: Optional[str] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> Optional[str]:
    """Resolve the CBM executable without touching agent configuration.

    Order: ``RELINKRA_CBM_BIN`` env (verbatim operator override, not
    validated at resolution time), then the per-user Relinkra-managed
    certified binary (R5H.1), then the workspace-managed
    ``.codebase-memory/bin`` location, then PATH. Returns None when
    nothing is found.
    """
    env = environ if environ is not None else os.environ
    explicit = (env.get("RELINKRA_CBM_BIN") or "").strip()
    if explicit:
        return explicit
    tag = platform_tag()
    if tag in CERTIFIED_CBM_BINARIES:
        # Only the certified version's managed path is ever auto-
        # discovered; runtime trust is still SHA-256-gated downstream.
        managed = managed_cbm_binary_path(
            CERTIFIED_CBM_VERSION, tag, data_root=relinkra_data_root(env)
        )
        if os.path.isfile(managed):
            return managed
    if root:
        for candidate in managed_binary_candidates(root):
            if os.path.isfile(candidate):
                return candidate
    found = shutil.which("codebase-memory-mcp")
    if found:
        return found
    return None


# ---------------------------------------------------------------------------
# Trust ladder evaluation (R4C.1A)
#
# Probe orchestration for doctor lives HERE — product_cli only renders the
# verdicts as Checks. Stage discipline:
#
# - PROVENANCE BEFORE EXECUTION: the binary is hashed before it is ever
#   run; a provenance mismatch stops the ladder instead of executing an
#   unverified binary in the control that exists to distrust it.
# - Per-stage isolation: one stage's failure never discards the verdicts
#   already produced, and unexpected payload shapes degrade that stage to
#   an honest "unknown" rather than crashing the ladder.
# - Failure is never mislabelled: a backend that cannot answer is
#   "unknown — backend not reachable", NOT "index missing". Re-indexing
#   is only prescribed when a WORKING backend reports the index absent.
# ---------------------------------------------------------------------------

#: Stage verdict kinds (product_cli maps these to its PASS/WARN display).
STAGE_PASS = "pass"
STAGE_WARN = "warn"

#: Doctor probes use a shorter timeout than the default adapter timeout:
#: diagnostics stay bounded even against a hung indexer.
DOCTOR_PROBE_TIMEOUT = 10.0


@dataclass(frozen=True)
class TrustStage:
    """One trust-ladder verdict. ``detail``/``action`` are pre-sanitized
    and carry no absolute machine paths (the payload is audited)."""

    name: str
    status: str
    detail: str = ""
    action: str = ""


def platform_tag() -> str:
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
    system = platform.system().lower()
    os_name = {"windows": "windows", "darwin": "darwin", "linux": "linux"}.get(
        system, system
    )
    return f"{os_name}-{arch}"


def _sha256_file(path: str) -> Optional[str]:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def absolutize_against_root(root: str, value: str) -> str:
    """Resolve a CBM cache path inside the managed workspace cache tree."""
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("CBM cache_dir cannot be empty")
    workspace = os.path.realpath(os.path.abspath(str(root)))
    cache_root = os.path.realpath(
        os.path.join(workspace, ".codebase-memory", "cache")
    )
    candidate = os.path.realpath(
        raw if os.path.isabs(raw) else os.path.join(workspace, raw)
    )
    try:
        common = os.path.commonpath([cache_root, candidate])
    except ValueError as exc:
        raise ValueError(
            "CBM cache_dir must be inside the workspace .codebase-memory/cache subtree"
        ) from exc
    if os.path.normcase(common) != os.path.normcase(cache_root):
        raise ValueError(
            "CBM cache_dir must be inside the workspace .codebase-memory/cache subtree"
        )
    return candidate


def _clean_detail(text: str, limit: int = 160) -> str:
    """Bound and de-control tool output before it reaches a report."""
    cleaned = re.sub(r"[\x00-\x1f\x7f]+", " ", str(text or "")).strip()
    return cleaned[:limit]


def evaluate_cbm_trust(
    root: str,
    record: Optional[dict],
    binary: Optional[str],
    *,
    adapter_factory=None,
) -> List[TrustStage]:
    """Run the CBM trust ladder and return one verdict per stage reached.

    ``record`` is the registry's workspace CBM identity (or None);
    ``binary`` the resolved executable path (or None). Stages stop early
    only when continuing would require trusting something already
    distrusted (no binary, failed provenance) or when a stage's own
    precondition is genuinely absent (no recorded project, index
    confirmed missing by a WORKING backend).
    """
    if record is None and binary is None:
        return []
    if binary is None:
        missing_detail = (
            "no CBM executable resolved (RELINKRA_CBM_BIN, the per-user "
            "Relinkra-managed location, the workspace "
            ".codebase-memory/bin location, or PATH)"
        )
        if platform_tag() in CERTIFIED_CBM_BINARIES:
            return [
                TrustStage(
                    "CBM binary",
                    STAGE_WARN,
                    missing_detail,
                    "Run 'relinkra cbm setup' to install the certified "
                    "binary into the Relinkra-managed location.",
                )
            ]
        return [
            TrustStage(
                "CBM binary",
                STAGE_WARN,
                f"{missing_detail}; no certified release exists for "
                f"platform {platform_tag()}",
                "CBM is optional — everything else keeps working. See "
                "docs/cbm-backend.md for platform support.",
            )
        ]
    stages: List[TrustStage] = [TrustStage("CBM binary", STAGE_PASS, "executable resolved")]

    # -- provenance (BEFORE any execution) ---------------------------------
    tag = platform_tag()
    expected = CERTIFIED_CBM_BINARIES.get(tag)
    if expected is None:
        stages.append(
            TrustStage(
                "CBM provenance",
                STAGE_WARN,
                f"no certified provenance recorded for platform {tag}",
            )
        )
        return stages
    else:
        actual = _sha256_file(binary)
        if actual and actual.lower() == expected["sha256"].lower():
            stages.append(
                TrustStage("CBM provenance", STAGE_PASS, f"matches certified {tag} binary")
            )
        else:
            stages.append(
                TrustStage(
                    "CBM provenance",
                    STAGE_WARN,
                    f"hash does not match the certified {tag} binary; "
                    "refusing to execute an unverified binary",
                    "Re-acquire the certified release with checksum "
                    "verification (see docs/cbm-backend.md).",
                )
            )
            return stages

    project_name = ((record or {}).get("project_name") or "").strip() or None
    raw_cache = ((record or {}).get("cache_dir") or "").strip()
    if record is not None and not raw_cache:
        stages.append(
            TrustStage(
                "CBM cache",
                STAGE_WARN,
                "no cache_dir is recorded for the configured CBM project",
                "Register a workspace-managed .codebase-memory/cache path before using CBM.",
            )
        )
        return stages
    try:
        cache_dir = absolutize_against_root(root, raw_cache) if raw_cache else None
    except ValueError:
        stages.append(
            TrustStage(
                "CBM cache",
                STAGE_WARN,
                "configured cache_dir escapes the workspace-managed cache subtree",
                "Set cache_dir to .codebase-memory/cache or a descendant and re-run doctor.",
            )
        )
        return stages
    if record is not None:
        stages.append(TrustStage("CBM cache", STAGE_PASS, "managed cache path recorded"))
    try:
        adapter = (adapter_factory or CBMCLIAdapter)(
            cbm_bin=binary,
            cache_dir=cache_dir,
            cbm_project_name=project_name,
            workspace_root=root,
            timeout=DOCTOR_PROBE_TIMEOUT,
            expected_sha256=expected["sha256"],
        )
    except CBMAdapterError as exc:
        stages.append(TrustStage("CBM version", STAGE_WARN, sanitize_error(str(exc))))
        return stages

    # -- version ------------------------------------------------------------
    try:
        raw_version = adapter.probe_version()
        classification = classify_version(raw_version)
        parsed = parse_version(raw_version)
        shown = (
            ".".join(str(part) for part in parsed)
            if parsed
            else _clean_detail(raw_version, 80)
        )
        if classification == VERSION_CERTIFIED:
            stages.append(
                TrustStage(
                    "CBM version",
                    STAGE_PASS,
                    f"{shown} (certified; contract {CBM_ADAPTER_CONTRACT})",
                )
            )
        elif classification == VERSION_SUPPORTED:
            stages.append(
                TrustStage(
                    "CBM version",
                    STAGE_WARN,
                    f"{shown} is inside the supported range but is not the "
                    f"certified {CERTIFIED_CBM_VERSION}",
                    "Adopt newer versions only after re-certification; "
                    "roll back to the certified release for certified "
                    "behavior.",
                )
            )
        elif classification == VERSION_UNSUPPORTED:
            stages.append(
                TrustStage(
                    "CBM version",
                    STAGE_WARN,
                    f"{shown} is outside the supported range; the adapter "
                    "contract is not verified against it",
                    "Install the certified release (see docs/cbm-backend.md).",
                )
            )
        else:
            stages.append(
                TrustStage("CBM version", STAGE_WARN, "version could not be determined")
            )
    except CBMAdapterError as exc:
        stages.append(
            TrustStage(
                "CBM version",
                STAGE_WARN,
                f"binary is not runnable: {sanitize_error(str(exc))}",
            )
        )
        return stages

    # Supported, unsupported, and unknown versions are never trusted to
    # answer index or query calls. Only the exact stable pin may advance.
    if classification != VERSION_CERTIFIED:
        return stages

    # -- index ----------------------------------------------------------------
    if record is None or not project_name:
        stages.append(
            TrustStage(
                "CBM index",
                STAGE_WARN,
                "no CBM project identity is recorded for this workspace",
                "Register the workspace-to-CBM mapping through 'relinkra "
                "register' (relinkra.cli) after indexing.",
            )
        )
        return stages
    if (
        project_name in {".", ".."}
        or os.path.basename(project_name) != project_name
        or "/" in project_name
        or "\\" in project_name
    ):
        stages.append(
            TrustStage(
                "CBM index",
                STAGE_WARN,
                "recorded CBM project identity is not a safe slug",
                "Re-register the workspace with the CBM path-derived project slug.",
            )
        )
        return stages
    db_exists = bool(cache_dir) and os.path.isfile(
        cbm_db_path(cache_dir, project_name)
    )
    try:
        projects = adapter.list_projects()
        if not isinstance(projects, list):
            raise CBMAdapterError("list_projects returned a non-list payload")
    except CBMAdapterError as exc:
        # A backend that cannot answer says NOTHING about the index:
        # report unknown, never prescribe a re-index of a healthy graph.
        stages.append(
            TrustStage(
                "CBM index",
                STAGE_WARN,
                f"index state unknown — backend not reachable: "
                f"{sanitize_error(str(exc))}",
            )
        )
        return stages
    project_listed = any(
        isinstance(p, dict) and p.get("name") == project_name for p in projects
    )
    if not (db_exists and project_listed):
        stages.append(
            TrustStage(
                "CBM index",
                STAGE_WARN,
                "index missing for the recorded project",
                "Index this workspace with 'codebase-memory-mcp cli "
                "index_repository' into the Relinkra-managed cache.",
            )
        )
        return stages
    stages.append(TrustStage("CBM index", STAGE_PASS, "index present for the recorded project"))

    # -- graph binding & freshness ---------------------------------------------
    try:
        status = adapter.index_status()
        if not isinstance(status, dict):
            raise CBMAdapterError("index_status returned a non-object payload")
    except CBMAdapterError as exc:
        stages.append(
            TrustStage(
                "CBM graph",
                STAGE_WARN,
                f"graph state unknown — backend not reachable: "
                f"{sanitize_error(str(exc))}",
            )
        )
        return stages
    raw_status_root = status.get("root_path")
    if not isinstance(raw_status_root, str) or not raw_status_root.strip():
        stages.append(
            TrustStage(
                "CBM graph",
                STAGE_WARN,
                "graph state is missing a valid workspace root",
                "Re-index THIS workspace into the managed cache.",
            )
        )
        return stages
    status_root = os.path.normcase(os.path.normpath(raw_status_root))
    workspace = os.path.normcase(os.path.normpath(root))
    if status_root != workspace:
        stages.append(
            TrustStage(
                "CBM graph",
                STAGE_WARN,
                "the indexed graph belongs to a different workspace root",
                "Re-index THIS workspace into the managed cache.",
            )
        )
        return stages
    # Structural validation only: this head is LIVE-derived by CBM and
    # is never freshness evidence; freshness compares the STORED Branch
    # head below plus change detection for worktree drift (R5E.2A).
    git_facts = status.get("git")
    if not isinstance(git_facts, dict):
        stages.append(
            TrustStage(
                "CBM graph",
                STAGE_WARN,
                "graph state is missing valid git metadata",
                "Re-index to record this workspace HEAD.",
            )
        )
        return stages
    graph_head = git_facts.get("head_sha")
    if not isinstance(graph_head, str) or not graph_head.strip():
        stages.append(
            TrustStage(
                "CBM graph",
                STAGE_WARN,
                "graph state is missing a valid HEAD",
                "Re-index to record this workspace HEAD.",
            )
        )
        return stages
    try:
        workspace_head = git_head_sha(root)
    except (GitError, ValueError):
        workspace_head = None
    if not isinstance(workspace_head, str) or not workspace_head.strip():
        stages.append(
            TrustStage(
                "CBM graph",
                STAGE_WARN,
                "workspace HEAD could not be verified",
                "Restore Git metadata before using the CBM graph.",
            )
        )
        return stages
    # Committed drift: the STORED index-time Branch head vs the current
    # workspace HEAD (index_status head_sha is live-derived and would
    # always match a clean worktree — the R5E.1 false-fresh bug).
    try:
        stored_head = adapter.graph_index_head()
    except CBMProjectNotIndexedError:
        stages.append(
            TrustStage(
                "CBM graph",
                STAGE_WARN,
                "index missing for the recorded project",
                "Index this workspace with 'codebase-memory-mcp cli "
                "index_repository' into the Relinkra-managed cache.",
            )
        )
        return stages
    except CBMAdapterError as exc:
        stages.append(
            TrustStage(
                "CBM graph",
                STAGE_WARN,
                f"graph state unknown — backend not reachable: "
                f"{sanitize_error(str(exc))}",
            )
        )
        return stages
    if not stored_head:
        stages.append(
            TrustStage(
                "CBM graph",
                STAGE_WARN,
                "graph state is missing a stored index HEAD",
                "Re-index to record this workspace HEAD.",
            )
        )
        return stages
    if stored_head != workspace_head:
        stages.append(
            TrustStage(
                "CBM graph",
                STAGE_WARN,
                f"stale index: graph at {stored_head[:8]}, workspace at "
                f"{workspace_head[:8]}",
                "Re-index to refresh the graph for the current HEAD. "
                "(if the WARN persists after re-indexing, delete the "
                "project .db in the managed cache and re-index — CBM "
                "0.9.0 keeps the stored HEAD for modify-only "
                "re-indexes)",
            )
        )
        return stages
    # Uncommitted drift: detect_changes reports worktree changes the
    # stored graph cannot know about even when HEADs match.
    try:
        changes = adapter.detect_changes()
    except CBMProjectNotIndexedError:
        stages.append(
            TrustStage(
                "CBM graph",
                STAGE_WARN,
                "index missing for the recorded project",
                "Index this workspace with 'codebase-memory-mcp cli "
                "index_repository' into the Relinkra-managed cache.",
            )
        )
        return stages
    except CBMAdapterError as exc:
        stages.append(
            TrustStage(
                "CBM graph",
                STAGE_WARN,
                f"graph state unknown — backend not reachable: "
                f"{sanitize_error(str(exc))}",
            )
        )
        return stages
    changed_count = changes.get("changed_count")
    if (
        isinstance(changed_count, bool)
        or not isinstance(changed_count, int)
        or changed_count < 0
    ):
        stages.append(
            TrustStage(
                "CBM graph",
                STAGE_WARN,
                "graph state is missing valid change detection",
                "Re-index to refresh the graph for this workspace.",
            )
        )
        return stages
    if changed_count > 0:
        stages.append(
            TrustStage(
                "CBM graph",
                STAGE_WARN,
                f"worktree has {changed_count} changed file(s) since the "
                "graph was indexed",
                "Re-index to refresh the graph for the current worktree.",
            )
        )
        return stages
    stages.append(TrustStage("CBM graph", STAGE_PASS, "graph matches this workspace and HEAD"))

    # -- real query ---------------------------------------------------------------
    try:
        adapter.search_symbols(query="relinkra_doctor_probe", limit=1)
        stages.append(TrustStage("CBM query", STAGE_PASS, "real query callable"))
    except CBMAdapterError as exc:
        stages.append(
            TrustStage(
                "CBM query",
                STAGE_WARN,
                f"configured but not callable: {sanitize_error(str(exc))}",
                "Health may report CBM configured; it is not usable until "
                "a real query succeeds.",
            )
        )
    return stages


_REQUIRED_TRUST_STAGES = frozenset(
    {"CBM binary", "CBM provenance", "CBM cache", "CBM version", "CBM index", "CBM graph", "CBM query"}
)

# Staleness-drift WARN details (R5E.2A): committed drift (stored index
# head vs workspace HEAD) and uncommitted worktree drift. Matched by
# stable prefix + shape, never full f-string equality. Policy
# (docs/freshness-explainability.md): stale graph evidence is SERVED
# marked stale, so these two WARNs — and only these — do not fail
# adapter certification; every structural graph WARN (different
# workspace root, missing stored index HEAD, unreachable backend,
# missing index) still fails.
_STALE_INDEX_DETAIL_RE = re.compile(r"^stale index: graph at ")
_WORKTREE_DRIFT_DETAIL_RE = re.compile(
    r"^worktree has \d+ changed file\(s\) since the graph was indexed"
)


def _is_staleness_warn(stage: TrustStage) -> bool:
    """True only when a stage WARN is pure freshness drift (R5E.2A)."""
    if stage.name != "CBM graph" or stage.status != STAGE_WARN:
        return False
    return bool(
        _STALE_INDEX_DETAIL_RE.match(stage.detail)
        or _WORKTREE_DRIFT_DETAIL_RE.match(stage.detail)
    )


def certify_configured_adapter(
    root: str,
    record: Optional[dict],
    binary: Optional[str],
    *,
    adapter_factory=None,
):
    """Return an adapter only after the complete CBM trust ladder passes.

    Configuration-created adapters must never get a weaker path than
    doctor. Explicitly injected adapters remain a test seam and
    deliberately bypass this constructor.

    R5E.2A policy exception: freshness drift is NOT a structural
    failure. A dirty worktree or commits-since-index is a normal dev
    state, the per-packet ``code_evidence_authority`` marks the evidence
    stale, and doctor still shows the WARN — so the two staleness-drift
    graph WARNs are tolerated here instead of silently disabling the
    adapter. Structural WARNs still raise.
    """
    if not isinstance(root, str) or not root.strip():
        raise CBMAdapterError("workspace root is required for CBM trust verification")

    constructed = []
    factory = adapter_factory or CBMCLIAdapter

    def capture_adapter(**kwargs):
        adapter = factory(**kwargs)
        constructed.append(adapter)
        return adapter

    stages = evaluate_cbm_trust(
        root,
        record,
        binary,
        adapter_factory=capture_adapter,
    )
    by_name = {stage.name: stage for stage in stages}
    deficient = {
        name
        for name in _REQUIRED_TRUST_STAGES
        if name not in by_name or by_name[name].status != STAGE_PASS
    }
    if not deficient:
        return constructed[-1]
    # The stale-graph drift WARN honestly stops the ladder before the
    # query probe (doctor never queries a distrusted graph), so the
    # drift path can only be deficient in "CBM graph" plus the
    # "CBM query" stage it skipped — nothing else.
    graph = by_name.get("CBM graph")
    query = by_name.get("CBM query")
    if (
        graph is not None
        and _is_staleness_warn(graph)
        and deficient <= {"CBM graph", "CBM query"}
        and (query is None or query.status == STAGE_PASS)
    ):
        return constructed[-1]

    failure = next((stage for stage in stages if stage.status != STAGE_PASS), None)
    detail = failure.detail if failure is not None else "CBM trust ladder did not complete"
    raise CBMAdapterError(sanitize_error(detail) or "CBM trust verification failed")
