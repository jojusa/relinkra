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
       state to report, not a command failure)
    1  the command itself failed (not a git repo, unreadable registry,
       invalid arguments)
    2  the command ran, but the outcome needs a human decision
       (init: ambiguous identity; doctor: at least one FAIL)
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
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from .app_service import (
    CONTRACT_VERSION,
    RelinkraServices,
    ServiceConfig,
    ServiceError,
    sanitize_wire_text,
)
from .handoff import contains_absolute_path
from .identity import (
    AmbiguousIdentityError,
    GitError,
    discover_repository_identity,
    git_branch,
    git_head_sha,
)
from .registry import Registry, RegistryError

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

    def to_dict(self) -> dict:
        return {
            "config_version": self.config_version,
            "project_id": self.project_id,
            "workspace_id": self.workspace_id,
            "initialized_at": self.initialized_at,
            "relinkra_version": self.relinkra_version,
        }

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
    return config_dir(root) / REGISTRY_FILE


# ---------------------------------------------------------------------------
# Environment resolution
# ---------------------------------------------------------------------------


def _repo_root(start: Optional[str] = None) -> Optional[Path]:
    """Walk upward for a .git entry. pathlib only — no separator literals.

    Accepts a .git FILE as well as a directory so worktrees and
    submodules resolve, and stops at the filesystem root on every
    platform via the parent-is-self test.
    """
    current = Path(start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def _services(root: Path, config: Optional[WorkspaceConfig]) -> RelinkraServices:
    """Build the R3 service facade for this workspace.

    The CLI never probes engines itself; it constructs the same services
    the MCP server uses and reads their health.
    """
    return RelinkraServices(
        config=ServiceConfig(
            workspace_root=str(root),
            registry_path=str(registry_path(root)),
            default_project_id=(config.project_id if config else None) or None,
            default_workspace_id=(config.workspace_id if config else None) or None,
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


def _component_check(name: str, probe: dict, action: str) -> Check:
    if probe.get("available"):
        detail = "available"
        if not probe.get("checked", True):
            detail = "configured (not liveness-checked)"
        return Check(name, PASS, detail)
    return Check(name, WARN, probe.get("detail") or "unavailable", action)


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
        ),
        _component_check(
            "CBM",
            components.get("cbm") or {},
            "Optional. Configure a code-index binary to enable symbol "
            "resolution; everything else works without it.",
        ),
        _component_check(
            "Git intelligence",
            components.get("git") or {},
            "Ensure this workspace is a git repository with at least one "
            "commit.",
        ),
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

    if resolved.root is not None:
        checks.append(check_config(resolved.root, resolved.config))
        checks.append(check_registry(resolved.root))
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
            checks.extend(component_checks(resolved.health or {}))
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
    rows.append(("HEAD", payload["head_sha"] or "(unknown)"))
    if payload["detached"]:
        rows.append(("Detached", "yes"))
    lines = ["", *_aligned(rows), ""]
    _emit(payload, args.json, "\n".join(lines))
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
    sub = parser.add_subparsers(dest="command", required=True)

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
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return EXIT_ERROR
    except BrokenPipeError:
        return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
