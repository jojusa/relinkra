"""Relinkra product CLI — init, status, doctor, project (R4A).

The user-facing front door. "Powerful inside, simple outside": a
developer should be able to run ``relinkra init`` and ``relinkra status``
without knowing what CBM, Engram, a logical project id, or MCP even are.

This layer owns PRESENTATION and nothing else. Identity resolution lives
in R1B (``identity``/``registry``), component probing lives in the R3
application services (``app_service.health``), git facts live in R2, and
portability rules live in ``handoff.scrub_absolute_paths``. The CLI
sequences those and renders them; it re-implements none of them.

Distinct from ``relinkra.cli``, which is the R1B admin tool
(``register``/``list``/``show``) and stays as-is.

Exit codes are a deterministic contract, uniform across commands:

    0  the command ran and the outcome is good
       (status/init: degraded components still exit 0 — degraded is a
       state to report, not a command failure; cbm status: every honest
       optional state — READY/MISSING/STALE/UNAVAILABLE/UNSUPPORTED/
       UNKNOWN — exits 0)
    1  the command itself failed (not a git repo, unreadable registry,
       invalid arguments) or the requested cbm action failed
       (unavailable/unsupported/unverified backend, index or refresh
       error, mapping failure)
    2  the command ran, but the outcome needs a human decision
       (init: ambiguous identity; doctor: at least one FAIL; cbm: the
       workspace itself is unusable — not a git repository, no usable
       identity, or an unreadable registry)
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import platform
import shutil
import sys
import tempfile
from dataclasses import dataclass
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__, backend_policy, cbm_acquire, cbm_indexing, cbm_support
from .app_service import (
    CONTRACT_VERSION,
    RelinkraServices,
    ServiceConfig,
    ServiceError,
    sanitize_wire_text,
)
from .backend_detection import assess_workspace
from .cbm_adapter import CBMAdapterError, CBMCLIAdapter
from .connectors import resolve_launch
from .handoff import contains_absolute_path
from .host_discovery import DiscoveryEnvironment
from .identity import (
    AmbiguousIdentityError,
    GitError,
    canonicalize_path,
    discover_repository_identity,
    git_branch,
    git_head_sha,
)
from .registry import Registry, RegistryError
from .workspace_resolution import discover_git_root

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_ACTION_REQUIRED = 2

#: Workspace-local state directory. Holds the registry and this
#: workspace's config. Machine-specific by nature — not for committing.
CONFIG_DIR = ".relinkra"
CONFIG_FILE = "config.json"
REGISTRY_FILE = "registry.json"
CONFIG_VERSION = 1

#: The oldest interpreter the codebase is known to run on.
MIN_PYTHON = (3, 9)

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"

_BUILD_PROVENANCE_STATEMENT = (
    "Source commit and archive SHA-256 are intentionally external "
    "release-report evidence; runtime metadata does not claim either."
)


def _distribution_shape(distribution: Any) -> Optional[str]:
    """Return the importlib.metadata shape for a distribution."""
    for entry in distribution.files or ():
        parts = Path(str(entry)).parts
        if any(part.endswith(".dist-info") for part in parts):
            return "dist-info"
        if any(part.endswith(".egg-info") for part in parts):
            return "egg-info"

    # ``files`` may be unavailable for an unusual distribution. The path is
    # still importlib.metadata-owned; use it only as a shape fallback.
    metadata_path = getattr(distribution, "_path", None)
    if metadata_path is not None:
        name = Path(str(metadata_path)).name
        if name.endswith(".dist-info"):
            return "dist-info"
        if name.endswith(".egg-info"):
            return "egg-info"
    return None


def _distribution_matches_imported_package(distribution: Any) -> bool:
    """Avoid reporting unrelated installed metadata for a source import."""
    locate_file = getattr(distribution, "locate_file", None)
    if not callable(locate_file):
        return False
    try:
        distribution_root = Path(locate_file("")).resolve()
        imported_root = Path(__file__).resolve().parent.parent
    except (OSError, TypeError, ValueError):
        return False
    return distribution_root == imported_root


def _runtime_version_metadata() -> Tuple[str, Optional[str], Optional[bool]]:
    """Read wheel metadata without consulting Git or the current directory."""
    try:
        distribution = importlib_metadata.distribution("relinkra")
    except importlib_metadata.PackageNotFoundError:
        return "source", None, None

    if (
        _distribution_shape(distribution) != "dist-info"
        or not _distribution_matches_imported_package(distribution)
    ):
        return "source", None, None

    metadata_version = str(distribution.version)
    return "installed", metadata_version, metadata_version == __version__


@dataclass
class Check:
    """One diagnostic result, renderable as text or JSON."""

    name: str
    status: str
    detail: str = ""
    action: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            # Detail and action are free text that may quote an
            # underlying error, so both go through the wire sanitizer.
            "detail": sanitize_wire_text(self.detail),
            "action": sanitize_wire_text(self.action),
        }


@dataclass
class WorkspaceConfig:
    """Minimal workspace-local config written by ``init``.

    Deliberately tiny. It PINS what init resolved so later commands are
    deterministic and fast, rather than re-deriving identity (and
    re-risking ambiguity) on every invocation.

    It stores no absolute paths, no credentials, and no environment
    values — only opaque ids and versions. Tool locations are resolved
    from PATH/environment at runtime instead of being frozen here, which
    is what keeps the file portable and free of machine-specific data.
    """

    project_id: str = ""
    workspace_id: str = ""
    initialized_at: str = ""
    relinkra_version: str = __version__
    config_version: int = CONFIG_VERSION
    #: Explicit opt-in to the advanced topology where a direct CBM server
    #: is exposed alongside Relinkra. NOTHING writes this today — no
    #: command sets it and ``init`` never emits it — so it can only become
    #: true by a deliberate hand edit. Read here so the diagnostics can
    #: report a chosen mixture as ``explicitly_allowed_advanced`` instead
    #: of accusing the user of an accident.
    advanced_direct_cbm: bool = False

    def to_dict(self) -> dict:
        data = {
            "config_version": self.config_version,
            "project_id": self.project_id,
            "workspace_id": self.workspace_id,
            "initialized_at": self.initialized_at,
            "relinkra_version": self.relinkra_version,
        }
        # Emitted only when set. A re-init must not erase a hand-made
        # opt-in, and a workspace that never made one must not grow a key
        # implying the choice was ever offered.
        if self.advanced_direct_cbm:
            data["advanced_direct_cbm"] = True
        return data

    @staticmethod
    def load(root: Path) -> Optional["WorkspaceConfig"]:
        """Read the config, treating anything unusable as absent.

        The guard covers CONSTRUCTION as well as parsing. A file can be
        perfectly valid JSON and still be unusable — ``"config_version":
        "abc"`` parses fine and then explodes in ``int()``. Since
        ``resolve()`` calls this before its own error handling, an escape
        here would crash every command, including ``doctor``, whose whole
        job is to diagnose a broken workspace without falling over.
        """
        path = config_path(root)
        try:
            if not path.exists():
                return None
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return None
            return WorkspaceConfig(
                project_id=str(data.get("project_id") or ""),
                workspace_id=str(data.get("workspace_id") or ""),
                initialized_at=str(data.get("initialized_at") or ""),
                relinkra_version=str(data.get("relinkra_version") or ""),
                config_version=int(data.get("config_version") or 0),
                advanced_direct_cbm=bool(data.get("advanced_direct_cbm")),
            )
        except (OSError, ValueError, TypeError):
            return None

    def save(self, root: Path) -> None:
        """Write the config atomically.

        Same discipline the registry already uses one file away: write a
        temp file, fsync, then os.replace. Without it a crash or two
        racing inits can leave a truncated config, which load() then
        reports as "not initialized" — silently discarding a completed
        initialization. Raises OSError; callers surface it as a typed
        failure.
        """
        directory = config_dir(root)
        directory.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"
        handle, temp_name = tempfile.mkstemp(
            dir=str(directory), prefix=".config-", suffix=".tmp"
        )
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, config_path(root))
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(temp_name)
            raise


def config_dir(root: Path) -> Path:
    return Path(root) / CONFIG_DIR


def config_path(root: Path) -> Path:
    return config_dir(root) / CONFIG_FILE


def registry_path(root: Path) -> Path:
    """The workspace registry file, under the CANONICAL local root.

    ``os.path.realpath`` collapses OS alias forms of the same directory —
    a Windows 8.3 short path (``RUNNER~1``) or a symlinked prefix — so the
    SAME logical registry yields ONE stable string. The launch contract
    serializes this path (``--registry``); an alias-variant string would
    make a healthy registration look out of date (R5C, reproduced on
    windows-latest where TEMP is an 8.3 alias). realpath preserves the
    filesystem's own casing, so canonical paths are unchanged byte-for-byte.
    Relative roots stay verbatim joins — callers resolving a real
    repository always pass an absolute root.
    """
    base = Path(root)
    if base.is_absolute():
        base = Path(os.path.realpath(str(base)))
    return config_dir(base) / REGISTRY_FILE


# ---------------------------------------------------------------------------
# Environment resolution
# ---------------------------------------------------------------------------


def _repo_root(start: Optional[str] = None) -> Optional[Path]:
    """Compatibility wrapper around the shared Git-root resolver."""
    return discover_git_root(start)


def _workspace_cbm_record(
    root: Path,
    config: Optional[WorkspaceConfig],
    registry_file: Optional[Path] = None,
) -> Optional[dict]:
    """The CBM identity record the registry holds for this workspace.

    Read through the existing registry contract; anything unusable is
    treated as absent (doctor must run on broken workspaces).
    """
    if config is None or not config.workspace_id:
        return None
    try:
        registry = Registry(str(registry_file or registry_path(root)))
    except RegistryError:
        return None
    workspace = registry.get_workspace(config.workspace_id)
    if workspace is None or not workspace.cbm:
        return None
    record = workspace.cbm
    return record if isinstance(record, dict) else None


def _services(root: Path, config: Optional[WorkspaceConfig]) -> RelinkraServices:
    """Build the R3 service facade for this workspace.

    The CLI never probes engines itself; it constructs the same services
    the MCP server uses and reads their health. CBM wiring is resolved
    from the registry's workspace record plus the binary locations
    Relinkra manages (env, the isolated workspace location, PATH) —
    never from agent configuration.
    """
    cbm_record = _workspace_cbm_record(root, config)
    cbm_bin = cbm_support.resolve_cbm_binary(str(root))
    cbm_cache_dir = None
    cbm_project_name = None
    if cbm_record:
        raw_project_name = cbm_record.get("project_name")
        cbm_project_name = (
            raw_project_name.strip()
            if isinstance(raw_project_name, str) and raw_project_name.strip()
            else None
        )
        raw_cache_value = cbm_record.get("cache_dir")
        raw_cache = raw_cache_value.strip() if isinstance(raw_cache_value, str) else ""
        if raw_cache:
            try:
                cbm_cache_dir = cbm_support.absolutize_against_root(
                    str(root), raw_cache
                )
            except ValueError:
                # Trust evaluation reports the invalid record explicitly;
                # services must never pass the escaping value to CBM.
                cbm_bin = None
    return RelinkraServices(
        config=ServiceConfig(
            workspace_root=str(root),
            registry_path=str(registry_path(root)),
            default_project_id=(config.project_id if config else None) or None,
            default_workspace_id=(config.workspace_id if config else None) or None,
            cbm_bin=cbm_bin,
            cbm_cache_dir=cbm_cache_dir,
            cbm_project_name=cbm_project_name,
        )
    )


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def check_runtime() -> Check:
    current = sys.version_info[:3]
    label = ".".join(str(part) for part in current)
    if current[:2] < MIN_PYTHON:
        return Check(
            "Python",
            FAIL,
            f"{label} is older than the minimum supported {MIN_PYTHON[0]}.{MIN_PYTHON[1]}",
            f"Upgrade to Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer.",
        )
    return Check("Python", PASS, f"{label} on {platform.system() or 'unknown'}")


def check_git_executable() -> Check:
    if shutil.which("git") is None:
        return Check(
            "Git executable",
            FAIL,
            "git was not found on PATH",
            "Install git and make sure it is on your PATH.",
        )
    return Check("Git executable", PASS, "found on PATH")


def check_repository(root: Optional[Path]) -> Check:
    if root is None:
        return Check(
            "Git repository",
            FAIL,
            "the current directory is not inside a git repository",
            "Run this from inside a git repository, or run 'git init' first.",
        )
    return Check("Git repository", PASS, "detected")


def check_config(root: Path, config: Optional[WorkspaceConfig]) -> Check:
    if config is None:
        return Check(
            "Relinkra config",
            WARN,
            "this workspace is not initialized yet",
            "Run 'relinkra init'.",
        )
    if config.config_version != CONFIG_VERSION:
        return Check(
            "Relinkra config",
            WARN,
            f"config version {config.config_version} differs from the "
            f"expected {CONFIG_VERSION}",
            "Run 'relinkra init' to refresh it.",
        )
    if not config.project_id or not config.workspace_id:
        return Check(
            "Relinkra config",
            WARN,
            "config is missing a project or workspace id",
            "Run 'relinkra init' to repair it.",
        )
    return Check("Relinkra config", PASS, "present and readable")


def check_registry(root: Path) -> Check:
    path = registry_path(root)
    if not path.exists():
        return Check(
            "Registry",
            WARN,
            "no registry yet",
            "Run 'relinkra init'.",
        )
    try:
        Registry(str(path))
    except (RegistryError, OSError, ValueError) as exc:
        # OSError matters as much as RegistryError here: a
        # permission-denied registry is exactly the situation doctor
        # exists to diagnose, and must not crash it.
        return Check(
            "Registry",
            FAIL,
            sanitize_wire_text(str(exc)),
            "Registry file is unreadable or invalid. Back it up and run "
            "'relinkra init' to recreate it.",
        )
    return Check("Registry", PASS, "readable and valid")


def _component_check(
    name: str, probe: dict, action: str, prefer_detail: bool = False
) -> Check:
    if probe.get("available"):
        # A healthy engine that has something to say stays audible: the
        # Engram probe reports memory-read integrity (skipped counters,
        # read path) while green, so operators see it without a failure.
        if prefer_detail and (probe.get("detail") or "").strip():
            return Check(name, PASS, probe["detail"])
        detail = "available"
        if not probe.get("checked", True):
            detail = "configured (not liveness-checked)"
        return Check(name, PASS, detail)
    return Check(name, WARN, probe.get("detail") or "unavailable", action)


def _cbm_missing_component_action() -> str:
    """Next-step text for an absent CBM backend, platform-aware.

    Certified platforms get the actionable managed-acquisition command;
    uncertified ones stay honest about the missing release.
    """
    if cbm_support.platform_tag() in cbm_support.CERTIFIED_CBM_BINARIES:
        return (
            "Optional. Run 'relinkra cbm setup' to install the certified "
            "code-index binary; everything else works without it."
        )
    return (
        "Optional. No certified code-index release exists for platform "
        f"{cbm_support.platform_tag()}; everything else works without it."
    )


def component_checks(health: dict) -> List[Check]:
    """Turn the R3 health report into CLI checks.

    A missing engine is a WARN, never a FAIL: Relinkra is designed to
    degrade, so an absent CBM or Engram means reduced capability, not a
    broken installation.
    """
    components = health.get("components") or {}
    return [
        _component_check(
            "Engram",
            components.get("engram") or {},
            "Install Engram and ensure 'engram' is on your PATH. "
            "Memory and handoffs stay unavailable until then.",
            # The engram probe's detail carries memory integrity info
            # even when green; surface it instead of a bare "available".
            prefer_detail=True,
        ),
        _component_check(
            "CBM",
            components.get("cbm") or {},
            _cbm_missing_component_action(),
        ),
        _component_check(
            "Git intelligence",
            components.get("git") or {},
            "Ensure this workspace is a git repository with at least one "
            "commit.",
        ),
    ]


def _platform_tag() -> str:  # kept as a thin alias for backward compatibility
    return cbm_support.platform_tag()


def cbm_trust_checks(
    root: Path,
    config: Optional[WorkspaceConfig],
) -> List[Check]:
    """Render the CBM trust ladder as doctor checks.

    All probing and policy live in ``cbm_support.evaluate_cbm_trust``
    (provenance-before-execution, per-stage isolation); this layer only
    maps verdicts to presentation.
    """
    record = _workspace_cbm_record(root, config)
    binary = cbm_support.resolve_cbm_binary(str(root))
    status_of = {cbm_support.STAGE_PASS: PASS, cbm_support.STAGE_WARN: WARN}
    return [
        Check(stage.name, status_of.get(stage.status, WARN), stage.detail, stage.action)
        for stage in cbm_support.evaluate_cbm_trust(str(root), record, binary)
    ]


_REQUIRED_CBM_TRUST_STAGES = frozenset(
    {"CBM provenance", "CBM version", "CBM index", "CBM graph", "CBM query"}
)


def _cbm_trust_is_complete(checks: List[Check]) -> bool:
    by_name = {check.name: check for check in checks}
    return _REQUIRED_CBM_TRUST_STAGES.issubset(by_name) and all(
        by_name[name].status == PASS for name in _REQUIRED_CBM_TRUST_STAGES
    )


def _enable_trusted_cbm_service(services: RelinkraServices) -> None:
    """Replace a configured production adapter with a hash-pinned one."""
    adapter = getattr(services, "cbm_adapter", None)
    if not isinstance(adapter, cbm_support.CBMCLIAdapter):
        return
    expected = cbm_support.CERTIFIED_CBM_BINARIES.get(cbm_support.platform_tag())
    if not expected:
        raise cbm_support.CBMAdapterError("no certified CBM provenance for this platform")
    services.cbm_adapter = cbm_support.CBMCLIAdapter(
        cbm_bin=adapter.cbm_bin,
        cache_dir=adapter.cache_dir,
        cbm_project_name=adapter.cbm_project_name,
        workspace_root=services.config.workspace_root,
        timeout=adapter.timeout,
        expected_sha256=expected["sha256"],
    )


def _cbm_index_freshness_checks(
    root: Path, config: Optional[WorkspaceConfig], trust_checks: List[Check]
) -> List[Check]:
    """One doctor line mapping managed-index freshness to the next action.

    Rendered only when the registry holds a CBM record for this
    workspace, and only after the trust ladder proved binary
    provenance: the freshness probes execute the binary, so they follow
    the same provenance-before-execution rule as every other CBM call.
    """
    try:
        record = _cbm_record_for_root(root, config)
    except (RegistryError, OSError, ValueError):
        # check_registry already reports a broken registry honestly.
        return []
    if record is None:
        return []
    by_name = {check.name: check for check in trust_checks}
    provenance = by_name.get("CBM provenance")
    if provenance is None or provenance.status != PASS:
        return []
    try:
        freshness = cbm_indexing.freshness_state(
            cbm_support.resolve_cbm_binary(str(root)),
            str(root),
            record,
            timeout=cbm_support.DOCTOR_PROBE_TIMEOUT,
        )
    except Exception as exc:  # diagnostics must never crash on a probe
        return [
            Check(
                "CBM index freshness",
                WARN,
                f"could not be classified: {sanitize_wire_text(str(exc))}",
                "Run 'relinkra cbm status' for detail.",
            )
        ]
    state = _cbm_display_state(freshness["state"])
    if state == "READY":
        return [Check("CBM index freshness", PASS, "managed index is fresh")]
    if state == cbm_indexing.MISSING:
        return [
            Check(
                "CBM index freshness",
                WARN,
                "managed index is missing",
                "Run 'relinkra cbm index'.",
            )
        ]
    if state == "STALE":
        return [
            Check(
                "CBM index freshness",
                WARN,
                "managed index is stale (graph drift)",
                "Run 'relinkra cbm refresh'.",
            )
        ]
    return [
        Check(
            "CBM index freshness",
            WARN,
            "managed index freshness is unknown",
            "See docs/cbm-backend.md.",
        )
    ]


def check_mcp(services: Optional[RelinkraServices], health: Optional[dict]) -> Check:
    """Can an agent actually connect and get context right now?"""
    if services is None or health is None:
        return Check(
            "MCP",
            WARN,
            "not constructable until the workspace is initialized",
            "Run 'relinkra init'.",
        )
    capabilities = health.get("capabilities") or {}
    if not capabilities.get("context_packets"):
        return Check(
            "MCP",
            FAIL,
            "the context service is not available",
            "Run 'relinkra doctor' for component detail.",
        )
    degraded = [
        name
        for name in ("memory_read", "handoffs", "git_intelligence")
        if not capabilities.get(name)
    ]
    if degraded:
        return Check(
            "MCP",
            WARN,
            "ready with reduced capability: " + ", ".join(sorted(degraded)),
            "Run 'relinkra doctor' to see which component is missing.",
        )
    return Check("MCP", PASS, "ready")


# ---------------------------------------------------------------------------
# Routing and trust diagnostics (R4C.0)
# ---------------------------------------------------------------------------

#: Which ownership states are a good outcome. Everything absent from
#: these sets is a WARN — including every ``unknown`` and ``unverified``
#: state, which is the rule that keeps "we did not look" from rendering
#: as "we checked and it is fine".
_HEALTHY_CBM_OWNERSHIP = frozenset(
    {backend_policy.CBM_RELINKRA_PRIVATE, backend_policy.CBM_UNAVAILABLE}
)
_HEALTHY_ENGRAM_OWNERSHIP = frozenset(
    {
        backend_policy.ENGRAM_RELINKRA_MANAGED,
        backend_policy.ENGRAM_GENTLEMAN_MANAGED,
        backend_policy.ENGRAM_SHARED_SEPARATED,
        backend_policy.ENGRAM_UNAVAILABLE,
    }
)

_CBM_OWNERSHIP_DETAIL = {
    backend_policy.CBM_RELINKRA_PRIVATE: "private Relinkra backend",
    backend_policy.CBM_UNAVAILABLE: (
        "no CBM backend configured and none exposed directly"
    ),
    backend_policy.CBM_DIRECTLY_EXPOSED: (
        "a direct CBM server is registered; direct calls bypass Relinkra "
        "relevance, budgeting, memory integration, Git intelligence, handoffs "
        "and metrics"
    ),
    backend_policy.CBM_EXPLICITLY_ALLOWED_ADVANCED: (
        "direct CBM exposure is allowed explicitly for this workspace"
    ),
    backend_policy.CBM_UNKNOWN: "ownership could not be determined",
}

_ENGRAM_OWNERSHIP_DETAIL = {
    backend_policy.ENGRAM_RELINKRA_MANAGED: "reached through Relinkra only",
    backend_policy.ENGRAM_GENTLEMAN_MANAGED: (
        "a Gentleman-attributed registration; SDD workflow state is its own"
    ),
    backend_policy.ENGRAM_SHARED_SEPARATED: (
        "shared with Gentleman under separated contracts"
    ),
    backend_policy.ENGRAM_DIRECT_UNCLASSIFIED: (
        "a direct Engram registration was found that could not be attributed "
        "to Gentleman or to Relinkra"
    ),
    backend_policy.ENGRAM_UNAVAILABLE: "no memory backend detected",
    backend_policy.ENGRAM_UNKNOWN: "ownership could not be determined",
}

_ROUTE_DETAIL = {
    backend_policy.ROUTE_MANAGED: "managed through Relinkra",
    backend_policy.ROUTE_MIXED: (
        "direct backend exposure detected alongside Relinkra"
    ),
    backend_policy.ROUTE_BYPASSED: (
        "a private backend is exposed directly and Relinkra is not registered"
    ),
    backend_policy.ROUTE_DEGRADED: (
        "Relinkra owns the route but cannot fully serve it"
    ),
    backend_policy.ROUTE_UNVERIFIED: (
        "no observed evidence that project context flows through Relinkra"
    ),
}

_TRUST_DETAIL = {
    backend_policy.TRUST_HIGH: "high",
    backend_policy.TRUST_DEGRADED: (
        "degraded — some context reaches the agent outside Relinkra's "
        "budgeting and attribution"
    ),
    backend_policy.TRUST_UNRELIABLE: (
        "unreliable — direct backend calls bypass Relinkra budgeting and "
        "attribution"
    ),
    backend_policy.TRUST_UNVERIFIED: (
        "unverified — no route has been observed to attribute against"
    ),
}

#: Every non-high trust state names something the user can actually do.
#: A warning with no action is a warning people learn to scroll past.
_TRUST_ACTION = {
    backend_policy.TRUST_DEGRADED: (
        "Some context reaches the agent outside Relinkra. Route project "
        "context and memory through Relinkra before treating token or "
        "duration numbers as attributable."
    ),
    backend_policy.TRUST_UNRELIABLE: (
        "Direct backend calls bypass Relinkra budgeting and attribution. "
        "Disable the direct entry for this host, or treat every metric as "
        "a lower bound."
    ),
    backend_policy.TRUST_UNVERIFIED: (
        "Register Relinkra with a host and start it. Until a route has been "
        "observed, no metric can be attributed to any component."
    ),
}


def routing_checks(assessment) -> List[Check]:
    """Render one routing assessment as the compatibility section.

    Every check here is PASS or WARN, never FAIL. A user who deliberately
    exposes CBM has a working machine and a topology Relinkra disagrees
    with; failing their ``doctor`` over it would turn a policy opinion
    into a broken exit code. What Relinkra will not do is call it healthy.
    """
    checks = [
        Check(
            "Context routing",
            PASS if assessment.context_route == backend_policy.ROUTE_MANAGED else WARN,
            _ROUTE_DETAIL.get(assessment.context_route, assessment.context_route),
            assessment.route_remediation,
        ),
        Check(
            "CBM ownership",
            PASS if assessment.cbm_ownership in _HEALTHY_CBM_OWNERSHIP else WARN,
            _CBM_OWNERSHIP_DETAIL.get(
                assessment.cbm_ownership, assessment.cbm_ownership
            ),
            _ownership_action(assessment, assessment.cbm_ownership),
        ),
        Check(
            "Engram ownership",
            PASS if assessment.engram_ownership in _HEALTHY_ENGRAM_OWNERSHIP else WARN,
            _ENGRAM_OWNERSHIP_DETAIL.get(
                assessment.engram_ownership, assessment.engram_ownership
            ),
            (
                backend_policy.REMEDIATION_UNCLASSIFIED_ENGRAM
                if assessment.engram_ownership
                == backend_policy.ENGRAM_DIRECT_UNCLASSIFIED
                else _ownership_action(assessment, assessment.engram_ownership)
            ),
        ),
        Check(
            "Duplicate read/write risk",
            PASS if assessment.duplicate_risk == backend_policy.DUPLICATE_NONE else WARN,
            _duplicate_detail(assessment),
            _duplicate_action(assessment),
        ),
        Check(
            "Metrics trust",
            PASS if assessment.metrics_trust == backend_policy.TRUST_HIGH else WARN,
            _TRUST_DETAIL.get(assessment.metrics_trust, assessment.metrics_trust),
            _TRUST_ACTION.get(assessment.metrics_trust, ""),
        ),
        _ladder_check(assessment.ladder),
    ]
    host_verification = getattr(assessment, "host_verification", ()) or ()
    if host_verification:
        checks.append(_host_verification_check(host_verification))
    return checks


def _host_verification_check(host_verification) -> Check:
    """One row summarising per-host evidence, never collapsing hosts.

    Each apply-capable host's local operational evidence is assessed
    independently; the row is PASS only when EVERY host holds valid
    local evidence, and the detail names each host's own status so one
    host's proof can never read as another's.
    """
    if all(row.get("locally_verified") for row in host_verification):
        return Check(
            "Host verification",
            PASS,
            "every apply-capable host holds valid local operational evidence; "
            "not independently attested",
        )
    detail = "; ".join(
        f"{row.get('connector_id', '?')}: {row.get('verification_status', 'absent')}"
        for row in host_verification
    )
    return Check(
        "Host verification",
        WARN,
        f"local host evidence per host — {detail}",
        "Run the host, then record evidence with 'relinkra connect verify "
        "<agent> --proof <file>'. Configuration presence is never treated "
        "as host proof.",
    )


#: The two ways an ownership axis lands on ``unknown``, and what to do
#: about each. Without this, a conflicting registration produced a WARN
#: reading "ownership could not be determined" with no action at all —
#: the assessment knew why, and the operator was never told.
_UNKNOWN_OWNERSHIP_ACTION_CONFLICT = (
    "At least one MCP registration's name disagrees with what it launches, "
    "so ownership was not inferred from the name. Check that entry's command "
    "against its name; nothing was changed."
)
_UNKNOWN_OWNERSHIP_ACTION_UNROUTED = (
    "The backend is reachable but Relinkra is not registered with any host, "
    "so nothing observable owns it. Register Relinkra to bring it under the "
    "managed route."
)
_UNKNOWN_OWNERSHIP_ACTION_UNREADABLE = (
    "An authoritative MCP scope could not be read, so ownership cannot be "
    "determined. Repair or remove the unreadable configuration file; nothing "
    "was changed."
)


def _ownership_action(assessment, state: str) -> str:
    """What to do about an ownership state that is not a clean PASS.

    Only ``unknown`` needs disambiguating: it is reached either from a
    conflicting detection or from Relinkra being absent, and those call
    for opposite actions. ``directly_exposed`` already has the route's
    own remediation.
    """
    if assessment.bypass_detected:
        return backend_policy.REMEDIATION_MIXED
    if state not in (backend_policy.CBM_UNKNOWN, backend_policy.ENGRAM_UNKNOWN):
        return ""
    conflicting = any("disagrees" in note for note in assessment.notes)
    if conflicting:
        return _UNKNOWN_OWNERSHIP_ACTION_CONFLICT
    unreadable = any("could not be read" in note for note in assessment.notes)
    if unreadable:
        return _UNKNOWN_OWNERSHIP_ACTION_UNREADABLE
    return _UNKNOWN_OWNERSHIP_ACTION_UNROUTED


def _duplicate_detail(assessment) -> str:
    """Name the risk level and the kinds that reached it."""
    worst = assessment.duplicate_risk
    kinds = sorted(
        {
            finding.kind
            for finding in assessment.duplicate_findings
            if finding.risk == worst
        }
    )
    if worst == backend_policy.DUPLICATE_NONE:
        return "no duplicate retrieval or duplicate write path detected"
    return f"{worst}: " + ", ".join(kinds)


def _duplicate_action(assessment) -> str:
    """What to do about the worst duplication risk found.

    ``unverified`` gets its own wording rather than the route's, because
    the honest answer there is not "fix something" — it is "Relinkra
    cannot see this from here", and pretending otherwise would send
    someone looking for a problem that may not exist.
    """
    worst = assessment.duplicate_risk
    if worst == backend_policy.DUPLICATE_NONE:
        return ""
    if worst == backend_policy.DUPLICATE_UNVERIFIED:
        return (
            "Some duplication happens entirely outside Relinkra's process and "
            "cannot be observed from here. Route project memory and handoffs "
            "through Relinkra so its own side stays single-sourced."
        )
    return assessment.route_remediation or backend_policy.REMEDIATION_MIXED


def _ladder_check(ladder) -> Check:
    """One check for the whole integration-trust ladder.

    Reported as a single row with the unproven rungs named, rather than
    twelve rows: the useful question is "how far does the evidence
    actually go", and a wall of WARNs answers it worse than one line that
    says where the evidence stops.
    """
    # Keyed off all_proven rather than "no unproven stages", because an
    # EMPTY ladder has no unproven stages and has also proven nothing.
    # The two readings differ on exactly one input, and that input is the
    # one a failed assessment produces.
    if ladder.all_proven:
        return Check(
            "Integration trust",
            PASS,
            "every stage from configuration to real host launch is proven",
        )
    unproven = ladder.unproven()
    if not ladder.stages:
        return Check(
            "Integration trust",
            WARN,
            "no integration evidence was gathered",
            "Run 'relinkra connect routing' for detail.",
        )
    names = ", ".join(stage.stage for stage in unproven)
    return Check(
        "Integration trust",
        WARN,
        f"{len(ladder.stages) - len(unproven)}/{len(ladder.stages)} stages "
        f"proven; not proven: {names}",
        "Configuration presence is never treated as readiness. Register "
        "Relinkra with a host, start it, and re-run 'relinkra doctor'.",
    )


def assess_routing_for(
    root: Optional[Path], resolved: "Resolved", *, health: Optional[dict] = None
):
    """Build the routing assessment for a workspace. Read-only.

    Returns ``None`` when there is no repository to assess, so the caller
    can omit the section rather than render a verdict about nothing.

    ``health`` lets the caller supply a TRUSTED deep health report (one
    computed only after the CBM trust ladder completed); without it the
    shallow report on ``resolved`` is used, which honestly marks an
    unprobed CBM as degraded.
    """
    if root is None:
        return None
    from .connector_apply import launch_fingerprint

    env = DiscoveryEnvironment.current(workspace_root=root)
    launch = resolve_launch(root, registry_path(root))
    return assess_workspace(
        env,
        health=health if health is not None else resolved.health,
        launch_resolved=bool(launch.resolved),
        advanced_cbm_allowed=bool(
            resolved.config is not None and resolved.config.advanced_direct_cbm
        ),
        verification_fingerprint=launch_fingerprint(launch),
    )


def check_portable_output(payload: Any) -> Check:
    """Self-audit: nothing the CLI prints may carry a machine path.

    Cheap and worth doing, because this is precisely the guarantee a
    user cannot verify for themselves.
    """
    leaked = [
        value
        for value in _strings(payload)
        if contains_absolute_path(value)
    ]
    if leaked:
        return Check(
            "Portable output",
            FAIL,
            f"{len(leaked)} field(s) contain an absolute path",
            "This is a Relinkra bug — please report it.",
        )
    return Check("Portable output", PASS, "no absolute paths in output")


def _strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


# ---------------------------------------------------------------------------
# Shared resolution
# ---------------------------------------------------------------------------


@dataclass
class Resolved:
    """Everything the read-only commands need, gathered once."""

    root: Optional[Path]
    config: Optional[WorkspaceConfig] = None
    services: Optional[RelinkraServices] = None
    health: Optional[dict] = None
    project: Optional[dict] = None
    error: str = ""


def resolve(start: Optional[str] = None) -> Resolved:
    """Locate the workspace and probe it. Never raises for a bad state."""
    root = _repo_root(start)
    if root is None:
        return Resolved(root=None, error="not inside a git repository")
    config = WorkspaceConfig.load(root)
    resolved = Resolved(root=root, config=config)
    try:
        resolved.services = _services(root, config)
        resolved.health = resolved.services.health()
    except Exception as exc:  # a broken engine must not crash the CLI
        resolved.error = sanitize_wire_text(str(exc))
        return resolved
    try:
        resolved.project = resolved.services.project_resolve()
    except Exception:
        # Broad on purpose. project_resolve() shells out to git through
        # identity.py, which only converts FileNotFoundError into a typed
        # GitError — a PermissionError or other OSError from a
        # non-executable git or an AV/sandbox interception would escape
        # as-is and reach the user as a raw traceback. An unresolved
        # project is a reportable state, never a crash.
        resolved.project = None
    return resolved


def _git_facts(root: Path) -> dict:
    """Branch/HEAD via the R1B helpers. Degrades to empty on failure."""
    facts: Dict[str, Any] = {}
    try:
        facts["branch"] = git_branch(str(root))
    except (GitError, ValueError):
        facts["branch"] = None
    try:
        facts["head_sha"] = git_head_sha(str(root))
    except (GitError, ValueError):
        facts["head_sha"] = None
    facts["detached"] = facts.get("branch") in (None, "", "HEAD")
    return facts


def check_registered_revision(project: Optional[dict]) -> Optional[Check]:
    """Report registry-vs-live revision drift without failing doctor."""
    if not project:
        return None
    # Keep test doubles and older service implementations compatible: this
    # diagnostic only applies when project resolution supplies the additive
    # freshness contract.
    if "freshness" not in project:
        return None
    freshness = project.get("freshness") or {}
    state = freshness.get("state")
    if state == "fresh":
        return Check(
            "Registered revision",
            PASS,
            "registered workspace snapshot matches current Git revision",
        )
    if state == "unknown":
        return Check(
            "Registered revision",
            WARN,
            "current Git revision is unavailable; integrated/control-plane "
            "trust is degraded",
            "Restore Git access and run 'relinkra doctor' again.",
        )
    return Check(
        "Registered revision",
        WARN,
        "registered snapshot differs from the current repository revision; "
        "integrated/control-plane trust is degraded",
        "Run 'relinkra cbm index' to refresh the workspace registration, then "
        "run 'relinkra doctor' again.",
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_STATUS_GLYPH = {PASS: "OK", WARN: "WARN", FAIL: "FAIL"}


def _emit(payload: Any, as_json: bool, text: str) -> None:
    """Render one command result as either JSON or text.

    Both forms come from the same payload, so the two can never drift.
    """
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(text)


#: Minimum label column. Real width is computed from the longest label
#: in the block, so a long name like "Git intelligence" can never run
#: into its value.
_MIN_LABEL_WIDTH = 15
_LABEL_GAP = 2


def _row(label: str, value: str, width: int = _MIN_LABEL_WIDTH) -> str:
    return f"{label:<{width}}{value}"


def _aligned(pairs: List[tuple]) -> List[str]:
    """Render label/value rows on a column wide enough for every label."""
    if not pairs:
        return []
    width = max(
        _MIN_LABEL_WIDTH,
        max(len(str(label)) for label, _ in pairs) + _LABEL_GAP,
    )
    return [_row(str(label), str(value), width) for label, value in pairs]


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def _validated_pin(registry, existing, identity):
    """Reuse the pinned project ONLY if it still describes this repository.

    Returns ``(project_id_or_None, identity_changed)``.

    ``.relinkra/config.json`` can outlive the repository it describes: the
    directory gets repurposed, ``.git`` is replaced with an unrelated
    remote, and the config survives because it is gitignored so nothing
    cleans it up. ``Registry.register_workspace`` accepts a ``project_id``
    override *by design*, without matching it against the supplied
    identity — so handing it a stale pin would file a completely different
    codebase under the previous project, silently sharing that project's
    memory and handoffs with an unrelated repository.

    The registry cannot catch this (the override is the caller's
    assertion), so the validation belongs here, at the point where the
    assertion is made.
    """
    if existing is None or not existing.project_id:
        return None, False
    project = registry.projects.get(existing.project_id)
    if project is None:
        # Pin points at a project this registry does not know. Re-derive
        # from the identity instead of asserting something unverifiable.
        return None, False
    if project.repository_identity.value != identity.value:
        return None, True
    return existing.project_id, False


def cmd_init(args) -> int:
    """Initialize this workspace. Idempotent and non-destructive.

    Touches nothing outside ``.relinkra/``: no git history, no staging,
    no commits, no Engram writes, no daemons.
    """
    root = _repo_root(args.path)
    if root is None:
        _fail(
            "Not inside a git repository.",
            "Run 'relinkra init' from inside a git repository, or run "
            "'git init' first.",
        )
        return EXIT_ERROR

    try:
        identity = discover_repository_identity(str(root))
    except (GitError, ValueError) as exc:
        _fail(
            f"Could not resolve a project identity: {sanitize_wire_text(str(exc))}",
            "Ensure the repository has a remote or at least one commit.",
        )
        return EXIT_ERROR

    git_facts = _git_facts(root)
    existing = WorkspaceConfig.load(root)

    try:
        registry = Registry(str(registry_path(root)))
    except (RegistryError, OSError, ValueError) as exc:
        _fail(
            f"Could not read the Relinkra registry: {sanitize_wire_text(str(exc))}",
            "Check that .relinkra/ exists and is readable.",
        )
        return EXIT_ERROR

    pinned_project_id, identity_changed = _validated_pin(
        registry, existing, identity
    )

    try:
        workspace = registry.register_workspace(
            str(root),
            identity,
            git={
                "branch": git_facts.get("branch"),
                "head_sha": git_facts.get("head_sha"),
            },
            # Only a VALIDATED re-init of the same repository is a
            # refresh. Without a validated pin this is an ordinary
            # first registration, ambiguity guard and all.
            allow_weak_merge=pinned_project_id is not None,
            project_id=pinned_project_id,
        )
    except AmbiguousIdentityError as exc:
        _fail(
            f"Ambiguous project identity: {sanitize_wire_text(str(exc))}",
            "This repository has no remote, so Relinkra cannot tell it "
            "apart from an existing project. Add a git remote, or re-run "
            "with an explicit project to confirm the merge.",
        )
        return EXIT_ACTION_REQUIRED
    except (RegistryError, OSError, ValueError) as exc:
        # OSError is the point of this handler: the registry write goes
        # through a lock file and an atomic temp-file rename, so a
        # permission-denied or full disk arrives as OSError, not
        # RegistryError.
        _fail(
            f"Could not write the Relinkra registry: {sanitize_wire_text(str(exc))}",
            "Check that .relinkra/ is writable.",
        )
        return EXIT_ERROR

    # A changed identity means this is a different project, so the old
    # initialization time no longer describes it.
    reuse_timestamp = (
        existing is not None
        and bool(existing.initialized_at)
        and not identity_changed
    )
    config = WorkspaceConfig(
        project_id=workspace.project_id,
        workspace_id=workspace.workspace_id,
        initialized_at=(
            existing.initialized_at if reuse_timestamp else workspace.registered_at
        ),
        relinkra_version=__version__,
        # Carried across a refresh. An identity change means a different
        # repository, and a topology choice made for the previous one says
        # nothing about this one.
        advanced_direct_cbm=bool(
            existing is not None
            and not identity_changed
            and existing.advanced_direct_cbm
        ),
    )
    try:
        config.save(root)
    except OSError as exc:
        _fail(
            f"Could not write the Relinkra config: {sanitize_wire_text(str(exc))}",
            "Check that .relinkra/ is writable and is a directory.",
        )
        return EXIT_ERROR

    checks = _readiness_checks(root)
    payload = {
        "initialized": True,
        "already_initialized": existing is not None and not identity_changed,
        "identity_changed": identity_changed,
        "project_id": workspace.project_id,
        "workspace_id": workspace.workspace_id,
        "repository_identity": identity.to_dict(),
        "checks": [check.to_dict() for check in checks],
    }
    _emit(
        payload,
        args.json,
        _render_init(workspace, checks, existing, identity_changed),
    )
    return EXIT_OK


def _readiness_checks(root: Path) -> List[Check]:
    """Can an agent use this workspace right now? Re-probed post-write.

    Deliberately probed AFTER registration so the answer reflects the
    state init just created, not the state it found.
    """
    resolved = resolve(str(root))
    return [
        check_git_executable(),
        check_repository(root),
        *component_checks(resolved.health or {}),
        check_mcp(resolved.services, resolved.health),
    ]


def _render_init(
    workspace, checks: List[Check], existing, identity_changed: bool
) -> str:
    if identity_changed:
        headline = "Relinkra re-initialized for a different repository."
    elif existing is not None:
        headline = "Relinkra already initialized (refreshed)."
    else:
        headline = "Relinkra initialized."

    lines = ["", headline, ""]
    if identity_changed:
        # Say what actually changed and what it means for the user's
        # data. Switching projects silently would be the worst outcome.
        lines.extend(
            [
                "This workspace was previously initialized for a different",
                "repository. Relinkra resolved a new project identity, so",
                "the previous project's memory and handoffs are NOT shared",
                "with this one.",
                "",
            ]
        )
    lines.extend(
        _aligned(
            [
                ("Project", workspace.project_id),
                ("Workspace", workspace.workspace_id),
            ]
        )
    )
    lines.append("")
    lines.extend(
        _aligned([(c.name, _STATUS_GLYPH[c.status]) for c in checks])
    )
    lines.append("")
    lines.append("Next: run 'relinkra status' or 'relinkra doctor'.")
    return "\n".join(lines)


def cmd_status(args) -> int:
    """Concise operational summary. Degraded state still exits 0."""
    resolved = resolve(args.path)
    if resolved.root is None:
        _fail(
            "Not inside a git repository.",
            "Run 'relinkra status' from inside a git repository.",
        )
        return EXIT_ERROR
    if resolved.config is None:
        _fail(
            "This workspace is not initialized.",
            "Run 'relinkra init' first.",
        )
        return EXIT_ERROR
    if resolved.error:
        _fail(
            f"Could not read workspace state: {resolved.error}",
            "Run 'relinkra doctor' for detail.",
        )
        return EXIT_ERROR

    health = resolved.health or {}
    capabilities = health.get("capabilities") or {}
    checks = [
        check_repository(resolved.root),
        *component_checks(health),
        check_mcp(resolved.services, health),
    ]
    by_name = {check.name: check for check in checks}

    payload = {
        "project_id": resolved.config.project_id,
        "workspace_id": resolved.config.workspace_id,
        "status": health.get("status", "unknown"),
        "components": {
            check.name: check.status for check in checks
        },
        "capabilities": {
            "memory": bool(capabilities.get("memory_read")),
            "handoffs": bool(capabilities.get("handoffs")),
            "context": bool(capabilities.get("context_packets")),
        },
        "degraded": sorted(health.get("degraded") or []),
    }

    def glyph(name: str) -> str:
        check = by_name.get(name)
        return _STATUS_GLYPH[check.status] if check else "UNKNOWN"

    def availability(flag: Any) -> str:
        return "AVAILABLE" if flag else "UNAVAILABLE"

    lines = ["", "Relinkra", ""]
    lines.extend(
        _aligned(
            [
                ("Project", resolved.config.project_id),
                ("Workspace", resolved.config.workspace_id),
                ("Git", glyph("Git repository")),
                ("Engram", glyph("Engram")),
                ("CBM", glyph("CBM")),
                ("MCP", glyph("MCP")),
                ("Memory", availability(capabilities.get("memory_read"))),
                ("Handoffs", availability(capabilities.get("handoffs"))),
            ]
        )
    )
    lines.append("")
    _emit(payload, args.json, "\n".join(lines))
    return EXIT_OK


def cmd_doctor(args) -> int:
    """Deep diagnostics with actionable remediation.

    Exit 2 when any check FAILs. A WARN is a reduced-capability state,
    not a failure, so it does not change the exit code.
    """
    resolved = resolve(args.path)
    checks: List[Check] = [
        check_runtime(),
        check_git_executable(),
        check_repository(resolved.root),
    ]
    # Set only when services came up: the trusted deep health doctor
    # earned through the CBM trust ladder, else the shallow report.
    health: Optional[dict] = None

    if resolved.root is not None:
        checks.append(check_config(resolved.root, resolved.config))
        checks.append(check_registry(resolved.root))
        revision_check = check_registered_revision(resolved.project)
        if revision_check is not None:
            checks.append(revision_check)
        if resolved.error:
            checks.append(
                Check(
                    "Services",
                    FAIL,
                    resolved.error,
                    "Relinkra could not construct its services. Re-run "
                    "'relinkra init'.",
                )
            )
        else:
            # Trust MUST be established before any deep health/query call.
            # A shallow health result is safe for incomplete or distrusted
            # CBM because it performs no subprocess execution.
            trust_checks: List[Check] = []
            try:
                trust_checks = cbm_trust_checks(resolved.root, resolved.config)
            except Exception as exc:  # the ladder must never crash doctor
                trust_checks.append(
                    Check(
                        "CBM trust",
                        WARN,
                        f"trust ladder could not run: {sanitize_wire_text(str(exc))}",
                    )
                )
            checks.extend(trust_checks)
            checks.extend(
                _cbm_index_freshness_checks(
                    resolved.root, resolved.config, trust_checks
                )
            )

            health = resolved.health or {}
            cbm_adapter = getattr(resolved.services, "cbm_adapter", None)
            if (
                _cbm_trust_is_complete(trust_checks)
                and resolved.services is not None
                and cbm_adapter is not None
            ):
                try:
                    _enable_trusted_cbm_service(resolved.services)
                    health = resolved.services.health(deep=True)
                except Exception:
                    # Keep the shallow/current report when the trusted
                    # production adapter cannot be rebuilt or probed.
                    health = resolved.health or {}
            checks.extend(component_checks(health))
            checks.append(check_mcp(resolved.services, resolved.health))
            checks.append(
                Check("Project identity", PASS, "resolved")
                if resolved.project
                else Check(
                    "Project identity",
                    WARN,
                    "no registered project resolved",
                    "Run 'relinkra init'.",
                )
            )

    payload: Dict[str, Any] = {
        "relinkra_version": __version__,
        "contract_version": CONTRACT_VERSION,
        "checks": [check.to_dict() for check in checks],
    }
    if resolved.project:
        payload["revision"] = {
            key: resolved.project.get(key)
            for key in (
                "registered_head_sha",
                "current_revision",
                "revision_source",
                "freshness",
                "relation",
                "revision_distance",
            )
        }

    # The compatibility and routing section. Built from the same
    # assessment 'connect routing' renders, so the two commands cannot
    # describe one machine two ways. A discovery failure degrades the
    # section to a warning rather than taking down the whole diagnostic —
    # doctor's job is to run when things are broken.
    assessment = None
    if resolved.root is not None:
        try:
            # The trusted deep health (when the CBM trust ladder earned
            # it) is the honest input here: routing must not call a
            # backend "degraded" that doctor itself just proved callable.
            assessment = assess_routing_for(resolved.root, resolved, health=health)
        except Exception as exc:  # discovery must never crash diagnostics
            assessment = None
            checks.append(
                Check(
                    "Context routing",
                    WARN,
                    f"routing could not be assessed: {sanitize_wire_text(str(exc))}",
                    "Run 'relinkra connect routing' for detail.",
                )
            )
        if assessment is not None:
            try:
                checks.extend(routing_checks(assessment))
                payload["routing"] = assessment.to_dict()
            except Exception as exc:
                # Rendering the section is as much a place to fail as
                # building it, and a doctor that dies while formatting
                # its own diagnosis is worse than one that omits a row.
                assessment = None
                checks.append(
                    Check(
                        "Context routing",
                        WARN,
                        f"routing could not be rendered: {sanitize_wire_text(str(exc))}",
                        "Run 'relinkra connect routing' for detail.",
                    )
                )
        payload["agent_instructions"] = backend_policy.agent_instruction_document()
    # Audit the payload we are about to print, then report the result
    # alongside it.
    portable = check_portable_output(payload)
    checks.append(portable)
    payload["checks"] = [check.to_dict() for check in checks]

    counts = {
        PASS: sum(1 for c in checks if c.status == PASS),
        WARN: sum(1 for c in checks if c.status == WARN),
        FAIL: sum(1 for c in checks if c.status == FAIL),
    }
    payload["summary"] = {key.lower(): value for key, value in counts.items()}
    payload["ok"] = counts[FAIL] == 0

    lines = ["", "Relinkra doctor", ""]
    for check in checks:
        lines.append(f"{check.status:<5}{check.name}")
        if check.detail:
            lines.append(f"      {sanitize_wire_text(check.detail)}")
        if check.action and check.status != PASS:
            lines.append(f"      Suggested action: {sanitize_wire_text(check.action)}")
    # Assessment notes explain WHY a routing state landed where it did —
    # a conflicting registration, an unrecognised server left alone, a
    # legacy config location. The JSON payload has carried them all
    # along; without this block the text reader, who is most of the
    # readers, saw the verdict and none of the reasoning.
    if assessment is not None and assessment.notes:
        lines.append("")
        lines.append("Routing notes")
        for note in assessment.notes:
            lines.append(f"      {sanitize_wire_text(note)}")
    lines.append("")
    lines.append(
        f"{counts[PASS]} passed, {counts[WARN]} warning(s), {counts[FAIL]} failed"
    )
    lines.append("")
    _emit(payload, args.json, "\n".join(lines))
    return EXIT_ACTION_REQUIRED if counts[FAIL] else EXIT_OK


def cmd_project(args) -> int:
    """Show the logical project and workspace identity."""
    resolved = resolve(args.path)
    if resolved.root is None:
        _fail(
            "Not inside a git repository.",
            "Run 'relinkra project' from inside a git repository.",
        )
        return EXIT_ERROR
    if resolved.config is None:
        _fail(
            "This workspace is not initialized.",
            "Run 'relinkra init' first.",
        )
        return EXIT_ERROR
    if resolved.error:
        # Same guard as status. Without it a broken registry still
        # produces exit 0 and prints ids from the stale config, which
        # reads as a healthy workspace when it is not.
        _fail(
            f"Could not read workspace state: {resolved.error}",
            "Run 'relinkra doctor' for detail.",
        )
        return EXIT_ERROR

    git_facts = _git_facts(resolved.root)
    identity = (resolved.project or {}).get("repository_identity") or {}
    workspace_facts = (resolved.project or {}).get("workspace") or {}

    payload = {
        "project_id": resolved.config.project_id,
        "workspace_id": resolved.config.workspace_id,
        "display_name": (resolved.project or {}).get("display_name"),
        "repository_identity": {
            "kind": identity.get("kind"),
            "value": identity.get("value"),
            "trust": identity.get("trust"),
        },
        "os_family": workspace_facts.get("os_family"),
        "branch": git_facts.get("branch"),
        "head_sha": git_facts.get("head_sha"),
        "registered_head_sha": (resolved.project or {}).get("registered_head_sha"),
        "head_sha_semantics": "current_revision",
        "current_revision": (resolved.project or {}).get("current_revision"),
        "revision_source": (resolved.project or {}).get("revision_source"),
        "freshness": (resolved.project or {}).get("freshness"),
        "relation": (resolved.project or {}).get("relation"),
        "revision_distance": (resolved.project or {}).get("revision_distance"),
        "detached": git_facts.get("detached"),
    }

    rows = [
        ("Project", payload["project_id"]),
        ("Workspace", payload["workspace_id"]),
    ]
    if payload["display_name"]:
        rows.append(("Name", payload["display_name"]))
    if identity.get("value"):
        rows.append(
            (
                "Repository",
                f"{identity.get('value')} ({identity.get('kind')}, "
                f"{identity.get('trust')})",
            )
        )
    rows.append(("Branch", payload["branch"] or "(detached)"))
    rows.append(("Registered HEAD", payload["registered_head_sha"] or "(unknown)"))
    rows.append(("Current revision", payload["current_revision"] or "(unknown)"))
    if payload["detached"]:
        rows.append(("Detached", "yes"))
    lines = ["", *_aligned(rows), ""]
    _emit(payload, args.json, "\n".join(lines))
    return EXIT_OK


# ---------------------------------------------------------------------------
# CBM index lifecycle (R5E.2B): status / index / refresh
# ---------------------------------------------------------------------------

#: Third line shown instead of a Next action when the optional backend
#: is honestly absent — the message that keeps an optional component
#: from reading like a broken one.
_CBM_OPTIONAL_BACKEND_LINE = (
    "Optional backend unavailable; native agent tools remain available."
)

#: Pointer to the acquisition command for the two action commands.
_CBM_ACQUISITION_POINTER = (
    "Run 'relinkra cbm setup' to install the certified binary into the "
    "Relinkra-managed location (see docs/cbm-backend.md)."
)

#: Display-space Next action per state. READY and the degenerate
#: UNAVAILABLE/UNSUPPORTED states intentionally map to None (READY has
#: nothing to do next; the unavailable/unsupported states print the
#: optional-backend line instead of a Next).
_CBM_NEXT_ACTION = {
    "MISSING": "relinkra cbm index",
    "STALE": "relinkra cbm refresh",
    # UNKNOWN with an existing record is usually a partial/kill-damaged
    # cache: refresh owns the verified heal path (db delete + reindex).
    "UNKNOWN": "relinkra cbm refresh",
}

#: Next action when the only drift is uncommitted worktree changes.
#: Real CBM 0.9.0 change detection reads the git worktree itself
#: (proven by the R5E.2B real-binary cycle: even a full cache wipe and
#: reindex leaves a modified file flagged), so no reindex can clear
#: that drift — only committing can.
_CBM_COMMIT_THEN_REFRESH = "commit your changes, then run 'relinkra cbm refresh'"


def _cbm_display_state(state: str) -> str:
    """Collapse the graded freshness states into the three user-facing
    words. The drift detail stays available in --json."""
    if state in (
        cbm_indexing.STALE_COMMITTED,
        cbm_indexing.STALE_WORKTREE,
        cbm_indexing.STALE_BOTH,
    ):
        return "STALE"
    return state


def _cbm_next_action(display: str, freshness: dict) -> Optional[str]:
    """The honest Next for a display state (None when there is none)."""
    if display == "STALE" and freshness.get("committed_drift") is not True:
        return _CBM_COMMIT_THEN_REFRESH
    return _CBM_NEXT_ACTION.get(display)


def _cbm_record_for_root(
    root: Path, config: Optional[WorkspaceConfig]
) -> Optional[dict]:
    """The CBM record for this workspace, by pinned id or canonical path.

    ``relinkra cbm index`` registers the workspace even before
    ``relinkra init`` pins ids in a config, so when the config lookup
    has nothing the registry is scanned for the workspace whose
    canonical path is this root. A registry that cannot be READ
    propagates ``RegistryError``/``OSError`` — callers that promised
    honest errors for a broken registry must be able to tell it apart
    from the honest "no record yet" None.
    """
    record = _workspace_cbm_record(root, config)
    if record is not None:
        return record
    registry = Registry(str(registry_path(root)))
    canonical = canonicalize_path(str(root))
    for workspace in registry.workspaces.values():
        if workspace.canonical_path == canonical and workspace.cbm:
            candidate = workspace.cbm
            return candidate if isinstance(candidate, dict) else None
    return None


def _cbm_availability(root: str) -> Tuple[str, Optional[str]]:
    """``(AVAILABLE|UNTRUSTED|UNAVAILABLE|UNSUPPORTED, binary)`` for line one."""
    binary = cbm_support.resolve_cbm_binary(root)
    if not binary:
        return cbm_indexing.UNAVAILABLE, None
    if cbm_support.platform_tag() not in cbm_support.CERTIFIED_CBM_BINARIES:
        return cbm_indexing.UNSUPPORTED, binary
    expected = cbm_support.CERTIFIED_CBM_BINARIES.get(cbm_support.platform_tag())
    actual = cbm_support._sha256_file(binary)
    if (
        not expected
        or not actual
        or actual.lower() != str(expected.get("sha256") or "").lower()
    ):
        return cbm_indexing.UNTRUSTED, binary
    return "AVAILABLE", binary


def _cbm_freshness_snapshot(
    root: str, record: Optional[dict]
) -> Tuple[str, Optional[str], dict]:
    """``(availability, binary, freshness result)`` with the CLI's
    honest absent-record mapping.

    No registry record means Relinkra never indexed this workspace, so
    with a usable backend the managed index simply does not exist yet:
    that is MISSING, not UNKNOWN. UNKNOWN stays reserved for a record
    that exists but cannot be verified.
    """
    availability, binary = _cbm_availability(root)
    if availability == cbm_indexing.UNTRUSTED:
        return availability, binary, {
            "state": cbm_indexing.UNTRUSTED,
            "committed_drift": None,
            "worktree_drift": None,
        }
    if record is None and availability == "AVAILABLE":
        return availability, binary, {
            "state": cbm_indexing.MISSING,
            "committed_drift": None,
            "worktree_drift": None,
        }
    return (
        availability,
        binary,
        cbm_indexing.freshness_state(binary, root, record),
    )


def _cbm_action_gate(root: str) -> Tuple[Optional[str], Optional[dict], Optional[str]]:
    """Shared binary/trust gate for ``cbm index`` and ``cbm refresh``.

    Mirrors the provenance stage of ``cbm_support.evaluate_cbm_trust``:
    the platform tag must have certified provenance and the actual
    binary must hash to it BEFORE anything is executed. Returns
    ``(binary, certified_entry, sha256)`` on success; on refusal the
    honest message has already been printed and the binary is None.
    """
    availability, binary = _cbm_availability(root)
    if availability == cbm_indexing.UNAVAILABLE:
        print(f"CBM: {availability}")
        if cbm_support.platform_tag() in cbm_support.CERTIFIED_CBM_BINARIES:
            print(_CBM_ACQUISITION_POINTER)
        else:
            # No certified release for this platform: setup cannot help,
            # so the honest message is the optional-backend one.
            print(_CBM_OPTIONAL_BACKEND_LINE)
        return None, None, None
    if availability == cbm_indexing.UNSUPPORTED:
        print(
            f"CBM: {availability} — no certified binary provenance for "
            f"platform {cbm_support.platform_tag()}"
        )
        print(_CBM_OPTIONAL_BACKEND_LINE)
        return None, None, None
    if availability == cbm_indexing.UNTRUSTED:
        _fail(
            "refusing to execute an unverified binary",
            "Re-acquire the certified release with checksum verification "
            "(see docs/cbm-backend.md).",
        )
        return None, None, None
    expected = cbm_support.CERTIFIED_CBM_BINARIES.get(cbm_support.platform_tag())
    sha256 = cbm_support._sha256_file(binary)
    if (
        not expected
        or not sha256
        or sha256.lower() != str(expected.get("sha256") or "").lower()
    ):
        _fail(
            "refusing to execute an unverified binary",
            "Re-acquire the certified release with checksum verification "
            "(see docs/cbm-backend.md).",
        )
        return None, None, None
    return binary, expected, sha256


def _cbm_resolve_or_report(
    path: Optional[str], command: str
) -> Optional[Tuple[str, str]]:
    """Shared workspace resolution for the cbm family.

    Returns ``(root, project_id)`` or None after printing the honest
    workspace-level failure (exit 2 territory: a human must fix the
    repository before the optional CBM workflow can mean anything).
    """
    try:
        return cbm_indexing.resolve_workspace(path)
    except cbm_indexing.IndexSetupError as exc:
        _fail(
            sanitize_wire_text(str(exc)),
            f"Run 'relinkra cbm {command}' from inside a git repository "
            "with at least one commit.",
        )
        return None


def _cbm_record_or_report(root: str) -> Optional[Tuple[Optional[dict], bool]]:
    """Load the workspace CBM record honestly.

    Returns ``(record, ok)``: ``ok`` is False only for a registry that
    could not be READ (already reported), which callers must not treat
    as the honest "no record yet".
    """
    try:
        return _cbm_record_for_root(Path(root), WorkspaceConfig.load(Path(root))), True
    except (RegistryError, OSError, ValueError) as exc:
        _fail(
            f"Could not read the Relinkra registry: "
            f"{sanitize_wire_text(str(exc))}",
            "Run 'relinkra doctor' to diagnose the registry.",
        )
        return None, False


def cmd_cbm_status(args) -> int:
    """Report managed CBM index freshness in three lines.

    Every honest state exits 0; exit 2 is reserved for workspace-level
    failures (not a usable git repository, unreadable registry).
    """
    resolved = _cbm_resolve_or_report(args.path, "status")
    if resolved is None:
        return EXIT_ACTION_REQUIRED
    root, project_id = resolved
    record, ok = _cbm_record_or_report(root)
    if not ok:
        return EXIT_ACTION_REQUIRED
    availability, _binary, freshness = _cbm_freshness_snapshot(root, record)
    display = _cbm_display_state(freshness["state"])
    next_action = _cbm_next_action(display, freshness)
    lines = ["", f"CBM: {availability}", f"Index: {display}"]
    if freshness["state"] == cbm_indexing.UNTRUSTED:
        # Provenance-before-execution: the binary was never run; the
        # backend is effectively unusable until re-acquired.
        lines = [
            "",
            "CBM: UNAVAILABLE",
            "refusing to execute an unverified binary",
            "Next: see docs/cbm-backend.md",
            "",
        ]
        payload = {
            "status": "UNAVAILABLE",
            "project_id": project_id,
            "cbm": "untrusted",
            "freshness": {
                "committed_drift": freshness["committed_drift"],
                "worktree_drift": freshness["worktree_drift"],
            },
            "next_action": "see docs/cbm-backend.md",
        }
        _emit(payload, args.json, "\n".join(lines))
        return EXIT_OK
    if availability == cbm_indexing.UNAVAILABLE and (
        cbm_support.platform_tag() in cbm_support.CERTIFIED_CBM_BINARIES
    ):
        # Certified platform with no binary: setup is the honest fix.
        next_action = "relinkra cbm setup"
        lines.append(f"Next: {next_action}")
        lines.append(_CBM_OPTIONAL_BACKEND_LINE)
    elif availability in (cbm_indexing.UNAVAILABLE, cbm_indexing.UNSUPPORTED):
        lines.append(_CBM_OPTIONAL_BACKEND_LINE)
    elif next_action:
        lines.append(f"Next: {next_action}")
    lines.append("")
    payload = {
        "status": display,
        "project_id": project_id,
        "cbm": availability.lower(),
        "freshness": {
            "committed_drift": freshness["committed_drift"],
            "worktree_drift": freshness["worktree_drift"],
        },
        "next_action": next_action,
    }
    _emit(payload, args.json, "\n".join(lines))
    return EXIT_OK


def cmd_cbm_setup(args) -> int:
    """Install the certified CBM binary into the Relinkra-managed location.

    Exit 0 for INSTALLED and ALREADY_INSTALLED; exit 1 for NOT_CERTIFIED
    (no certified release for this platform) and FAILED (acquisition or
    verification error) — an honest nonzero, never a silent unverified
    fallback.
    """
    result = cbm_acquire.setup_cbm(from_file=args.from_file)
    payload = result.to_dict()
    if result.status in (
        cbm_acquire.STATUS_INSTALLED,
        cbm_acquire.STATUS_ALREADY_INSTALLED,
    ):
        headline = (
            "CBM: ALREADY_INSTALLED"
            if result.status == cbm_acquire.STATUS_ALREADY_INSTALLED
            else "CBM: INSTALLED"
        )
        lines = [
            "",
            headline,
            f"Managed binary: {result.managed_path}",
            f"Version: {cbm_support.CERTIFIED_CBM_VERSION} "
            f"({cbm_support.platform_tag()})",
            "SHA-256: verified against the certified pin",
            "",
            "Next: relinkra cbm index",
            "",
        ]
        _emit(payload, args.json, "\n".join(lines))
        return EXIT_OK
    if result.status == cbm_acquire.STATUS_NOT_CERTIFIED:
        lines = [
            "",
            f"CBM: NOT_CERTIFIED — {result.detail}",
            _CBM_OPTIONAL_BACKEND_LINE,
            "",
        ]
        _emit(payload, args.json, "\n".join(lines))
        return EXIT_ERROR
    if args.json:
        # Machine-readable failure: the payload carries error/detail so
        # callers get the same verdict they get on stdout for every
        # other setup outcome.
        _emit(payload, True, "")
    else:
        _fail(
            result.error or "CBM setup failed",
            result.detail or "See docs/cbm-backend.md (Acquisition).",
        )
    return EXIT_ERROR


def cmd_cbm_index(args) -> int:
    """Build the managed index and register the workspace mapping.

    Exit 1 whenever the action failed (no/unsupported/unverified
    backend, index error, mapping failure); exit 0 with the honestly
    verified post-index state.
    """
    resolved = _cbm_resolve_or_report(args.path, "index")
    if resolved is None:
        return EXIT_ACTION_REQUIRED
    root, project_id = resolved
    binary, expected, sha256 = _cbm_action_gate(root)
    if binary is None:
        return EXIT_ERROR
    cache_dir, cache_rel = cbm_indexing.plan_cache(root)
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _fail(
            f"Could not create the managed cache directory: "
            f"{sanitize_wire_text(str(exc))}",
            "Check that the workspace is writable.",
        )
        return EXIT_ERROR
    gitignore_warning = not cbm_indexing.gitignore_check(root).get("ignored")
    try:
        result = cbm_indexing.run_index(
            binary,
            root,
            str(cache_dir),
            mode=args.mode,
            expected_sha256=sha256,
        )
    except cbm_indexing.IndexSetupError as exc:
        _fail(
            f"CBM index failed: {sanitize_wire_text(str(exc))}",
            "See docs/cbm-backend.md for the certified setup.",
        )
        return EXIT_ERROR
    # Provenance already pinned this exact binary by hash, so a failed
    # version probe degrades to the certified version string — never to
    # a guess about an unverified executable.
    version = str(expected.get("version") or "")
    try:
        probed = CBMCLIAdapter(
            cbm_bin=binary,
            workspace_root=root,
            expected_sha256=sha256,
        ).probe_version()
        parsed = cbm_support.parse_version(probed)
        if parsed:
            version = ".".join(str(part) for part in parsed)
    except CBMAdapterError:
        pass
    try:
        workspace = cbm_indexing.register_mapping(
            str(registry_path(Path(root))),
            root,
            result["project_name"],
            cache_rel,
            version,
            sha256,
        )
    except cbm_indexing.IndexSetupError as exc:
        _fail(
            "index succeeded but mapping failed; rerun 'relinkra cbm index' "
            f"(safe): {sanitize_wire_text(str(exc))}",
            "The index data itself is intact; only the registry mapping "
            "is missing.",
        )
        return EXIT_ERROR
    record = workspace.get("cbm") if isinstance(workspace, dict) else None
    freshness = cbm_indexing.freshness_state(
        binary, root, record if isinstance(record, dict) else None
    )
    display = _cbm_display_state(freshness["state"])
    payload = {
        "action_performed": "index",
        "status": display,
        "project_id": project_id,
        "nodes": result["nodes"],
        "edges": result["edges"],
        "quirk_recovery_used": False,
        "gitignore_warning": gitignore_warning,
    }
    lines = ["", "CBM: AVAILABLE", f"Index: {display}"]
    if display == "READY":
        lines[2] = f"Index: READY ({result['nodes']} nodes, {result['edges']} edges)"
    else:
        next_action = _cbm_next_action(display, freshness)
        if next_action:
            payload["next_action"] = next_action
            lines.append(f"Next: {next_action}")
    lines.append("")
    if gitignore_warning and not args.json:
        print(
            "WARN: .codebase-memory/ is not git-ignored; add it to "
            ".gitignore — otherwise CBM reports the index permanently "
            "STALE."
        )
    _emit(payload, args.json, "\n".join(lines))
    return EXIT_OK


def cmd_cbm_refresh(args) -> int:
    """Refresh a stale managed index (idempotent when already fresh).

    Exit 1 when the precondition or the refresh itself failed; exit 0
    for the READY no-op and a verified refresh.
    """
    resolved = _cbm_resolve_or_report(args.path, "refresh")
    if resolved is None:
        return EXIT_ACTION_REQUIRED
    root, project_id = resolved
    record, ok = _cbm_record_or_report(root)
    if not ok:
        return EXIT_ACTION_REQUIRED
    availability, _binary, freshness = _cbm_freshness_snapshot(root, record)
    display = _cbm_display_state(freshness["state"])
    if display == cbm_indexing.MISSING:
        print(f"CBM: {availability}")
        print("Index: MISSING — run 'relinkra cbm index' first")
        return EXIT_ERROR
    if freshness["state"] == cbm_indexing.UNTRUSTED:
        # Provenance-before-execution: refuse before ANY binary exec
        # (the snapshot itself refused to probe the unverified binary).
        _fail(
            "refusing to execute an unverified binary",
            "Re-acquire the certified release with checksum verification "
            "(see docs/cbm-backend.md).",
        )
        return EXIT_ERROR
    if display == "READY":
        payload = {
            "action_performed": "none",
            "status": "READY",
            "project_id": project_id,
            "quirk_recovery_used": False,
        }
        _emit(
            payload,
            args.json,
            "\n".join(
                ["", f"CBM: {availability}", "Index: READY (already fresh)", ""]
            ),
        )
        return EXIT_OK
    if availability != "AVAILABLE":
        _cbm_action_gate(root)  # prints the honest refusal
        return EXIT_ERROR
    project_name = str((record or {}).get("project_name") or "").strip()
    raw_cache = str((record or {}).get("cache_dir") or "").strip()
    if not project_name or not raw_cache:
        _fail(
            "the registered CBM mapping is unusable; re-run "
            "'relinkra cbm index' to rebuild it",
            "See docs/cbm-backend.md for the mapping contract.",
        )
        return EXIT_ERROR
    binary, _expected, refresh_sha256 = _cbm_action_gate(root)
    if binary is None:
        return EXIT_ERROR
    try:
        cache_dir = cbm_support.absolutize_against_root(root, raw_cache)
    except ValueError as exc:
        _fail(
            f"The registered CBM cache path is invalid: "
            f"{sanitize_wire_text(str(exc))}",
            "Re-run 'relinkra cbm index' to rebuild the mapping.",
        )
        return EXIT_ERROR
    try:
        outcome = cbm_indexing.refresh_with_quirk_recovery(
            binary,
            root,
            cache_dir,
            project_name,
            mode=args.mode,
            expected_sha256=refresh_sha256,
        )
    except cbm_indexing.StaleAfterRefreshError as exc:
        _fail(
            sanitize_wire_text(str(exc)),
            "The managed cache may need manual inspection; see "
            "docs/cbm-backend.md.",
        )
        return EXIT_ERROR
    except cbm_indexing.IndexSetupError as exc:
        _fail(
            f"CBM refresh failed: {sanitize_wire_text(str(exc))}",
            "See docs/cbm-backend.md for the certified setup.",
        )
        return EXIT_ERROR
    recovery_used = bool(outcome.get("quirk_recovery_used"))
    result = outcome.get("result") or {}
    freshness = cbm_indexing.freshness_state(binary, root, record)
    display = _cbm_display_state(freshness["state"])
    if display == "STALE" and freshness.get("committed_drift") is not True:
        # Real CBM 0.9.0 semantics (R5E.2B real-binary proof): change
        # detection reads the git worktree itself, so uncommitted edits
        # stay drift no matter how often the graph is reindexed. The
        # refresh just captured the current content into the graph;
        # READY returns once the changes are committed and refreshed.
        payload = {
            "action_performed": "refresh",
            "status": "STALE",
            "project_id": project_id,
            "nodes": result.get("nodes"),
            "edges": result.get("edges"),
            "quirk_recovery_used": recovery_used,
            "freshness": {
                "committed_drift": freshness["committed_drift"],
                "worktree_drift": freshness["worktree_drift"],
            },
            "next_action": _CBM_COMMIT_THEN_REFRESH,
        }
        _emit(
            payload,
            args.json,
            "\n".join(
                [
                    "",
                    "CBM: AVAILABLE",
                    "Index: STALE — uncommitted changes keep the index flagged",
                    f"Next: {_CBM_COMMIT_THEN_REFRESH}",
                    "",
                ]
            ),
        )
        return EXIT_OK
    if display != "READY":
        print("CBM: AVAILABLE")
        print(f"Index: {display} — refresh did not reach READY")
        return EXIT_ERROR
    payload = {
        "action_performed": "refresh",
        "status": "READY",
        "project_id": project_id,
        "nodes": result.get("nodes"),
        "edges": result.get("edges"),
        "quirk_recovery_used": recovery_used,
    }
    _emit(
        payload,
        args.json,
        "\n".join(["", "CBM: AVAILABLE", "Index: READY (refreshed)", ""]),
    )
    return EXIT_OK


def cmd_version(args) -> int:
    """Show the Relinkra version and basic compatibility information.

    Deliberately path-free: a version answer must never leak local
    directories into bug reports or screenshots.
    """
    install_mode, metadata_version, metadata_consistent = (
        _runtime_version_metadata()
    )
    payload = {
        "relinkra_version": __version__,
        "contract_version": CONTRACT_VERSION,
        "python_version": platform.python_version(),
        "min_python_version": ".".join(str(part) for part in MIN_PYTHON),
        "install_mode": install_mode,
        "installed_metadata_version": metadata_version,
        "metadata_version_consistent": metadata_consistent,
        "build_provenance": {
            "source_commit": None,
            "artifact_sha256": None,
            "statement": _BUILD_PROVENANCE_STATEMENT,
        },
    }
    text = (
        f"relinkra {payload['relinkra_version']}\n"
        f"python {payload['python_version']} "
        f"(minimum {payload['min_python_version']}) "
        f"· contract {payload['contract_version']} "
        f"· {payload['install_mode']}"
    )
    _emit(payload, args.json, text)
    return EXIT_OK


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _fail(message: str, action: str = "") -> None:
    print(f"Error: {message}", file=sys.stderr)
    if action:
        print(f"Suggested action: {action}", file=sys.stderr)


class _Parser(argparse.ArgumentParser):
    """ArgumentParser that honours this CLI's exit-code contract.

    argparse exits 2 on a usage error, but here 2 means "ran, needs a
    human decision" (ambiguous identity, doctor FAIL). A bad flag is a
    command failure, which this contract defines as 1 — so a script
    branching on 2 is never confused by a typo.
    """

    def error(self, message: str):
        self.print_usage(sys.stderr)
        print(f"Error: {message}", file=sys.stderr)
        raise SystemExit(EXIT_ERROR)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="relinkra",
        description="Relinkra — one codebase, one memory, any agent.",
    )
    parser.add_argument(
        "--version", action="version", version=f"relinkra {__version__}"
    )
    sub = parser.add_subparsers(dest="command")

    for name, handler, help_text in (
        ("init", cmd_init, "initialize Relinkra for this repository"),
        ("status", cmd_status, "show a concise operational summary"),
        ("doctor", cmd_doctor, "run deep diagnostics with suggested fixes"),
        ("project", cmd_project, "show the logical project identity"),
    ):
        command = sub.add_parser(name, help=help_text)
        command.add_argument(
            "--path",
            default=None,
            help="workspace directory (defaults to the current directory)",
        )
        command.add_argument(
            "--json", action="store_true", help="emit machine-readable JSON"
        )
        command.set_defaults(func=handler)

    # The cbm family (R5E.2B): one nested subcommand set so the
    # optional-backend lifecycle verbs read as one workflow. R5H.1 adds
    # `setup`: managed acquisition of the certified binary.
    cbm_cmd = sub.add_parser(
        "cbm",
        help="manage the optional CBM code index (setup/status/index/refresh)",
    )
    cbm_sub = cbm_cmd.add_subparsers(dest="cbm_command", required=True)
    for name, handler, help_text in (
        ("status", cmd_cbm_status, "show managed CBM index freshness"),
        ("index", cmd_cbm_index, "build the managed CBM index and register it"),
        ("refresh", cmd_cbm_refresh, "refresh a stale managed CBM index"),
    ):
        cbm_command = cbm_sub.add_parser(name, help=help_text)
        cbm_command.add_argument(
            "--path",
            default=None,
            help="workspace directory (defaults to the current directory)",
        )
        cbm_command.add_argument(
            "--json", action="store_true", help="emit machine-readable JSON"
        )
        if name in ("index", "refresh"):
            # Only 'fast' is supported today; advertising more would
            # promise an indexing mode the backend never verifies.
            cbm_command.add_argument(
                "--mode",
                choices=["fast"],
                default="fast",
                help="indexing mode (only 'fast' is supported)",
            )
        cbm_command.set_defaults(func=handler)

    # setup is user-level, not workspace-level: it takes no --path.
    setup_command = cbm_sub.add_parser(
        "setup",
        help="install the certified CBM binary (Relinkra-managed location)",
    )
    setup_command.add_argument(
        "--from-file",
        dest="from_file",
        default=None,
        metavar="PATH",
        help="install from a local release archive or executable "
        "(offline path; verified with the same pinned checksums)",
    )
    setup_command.add_argument(
        "--json", action="store_true", help="emit machine-readable JSON"
    )
    setup_command.set_defaults(func=cmd_cbm_setup)

    # Version takes no --path: it answers about the tool, not a workspace.
    version_cmd = sub.add_parser(
        "version", help="show version and compatibility information"
    )
    version_cmd.add_argument(
        "--json", action="store_true", help="emit machine-readable JSON"
    )
    version_cmd.set_defaults(func=cmd_version)

    # Imported here, not at module scope: connect_cli imports this
    # module for the exit-code contract and the shared renderers, so a
    # top-level import in either direction would be circular.
    from .connect_cli import register as register_connect

    register_connect(sub)

    return parser


def _use_utf8(*streams) -> None:
    """Force UTF-8 output so piped text does not mojibake.

    A console attached directly gets UTF-8 already, but redirecting to a
    pipe or file falls back to the locale codec (cp1252 on Windows),
    which mangles non-ASCII in help text, project names, and branches.
    errors="replace" keeps an exotic branch name from crashing the CLI.
    """
    for stream in streams:
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


def main(argv: Optional[List[str]] = None) -> int:
    # Before parse_args so --help and argparse errors are UTF-8 too.
    _use_utf8(sys.stdout, sys.stderr)
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return EXIT_ERROR
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return EXIT_ERROR
    except BrokenPipeError:
        return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
