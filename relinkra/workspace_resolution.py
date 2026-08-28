"""Deterministic repository-root and MCP runtime path resolution.

The MCP process may be launched from a nested checkout directory or from a
host that has no repository context at all.  This module keeps that startup
binding separate from presentation-layer commands so every caller uses the
same Git-root and canonical-path rules without creating or modifying state.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Union

from .identity import canonicalize_path

PathLike = Union[str, os.PathLike]


@dataclass(frozen=True)
class WorkspaceResolution:
    """Result of resolving the server's workspace root."""

    root: Optional[str]
    source: str
    error: str = ""


def discover_git_root(start: Optional[PathLike] = None) -> Optional[Path]:
    """Return the enclosing Git root, or ``None``.

    A ``.git`` directory and a ``.git`` file are both valid Git workspaces;
    the latter is how linked worktrees identify their administrative
    directory.  The walk is read-only and terminates at the filesystem root
    through ``Path.parents``.
    """

    try:
        current = Path(start if start is not None else os.getcwd()).resolve()
    except (OSError, RuntimeError, TypeError, ValueError):
        return None

    for candidate in (current, *current.parents):
        try:
            if (candidate / ".git").exists():
                # Keep the resolved spelling here for compatibility with
                # host-specific path keys. The MCP binding below applies
                # canonicalize_path before exposing the root to services.
                return candidate
        except (OSError, RuntimeError, TypeError, ValueError):
            continue
    return None


def resolve_workspace_root(
    explicit: Optional[PathLike] = None,
    *,
    environ: Optional[Mapping[str, str]] = None,
    cwd: Optional[PathLike] = None,
) -> WorkspaceResolution:
    """Resolve workspace precedence without falling back after a choice.

    Precedence is explicit value, ``RELINKRA_WORKSPACE_ROOT``, then the
    process working directory.  An explicitly supplied but invalid value is
    an unresolved binding, not permission to guess from another source.
    """

    env = os.environ if environ is None else environ
    if explicit is not None:
        raw = str(explicit)
        source = "explicit"
    elif "RELINKRA_WORKSPACE_ROOT" in env:
        raw = str(env.get("RELINKRA_WORKSPACE_ROOT") or "")
        source = "environment"
    else:
        raw = str(cwd if cwd is not None else os.getcwd())
        source = "cwd"

    if not raw.strip():
        return WorkspaceResolution(
            root=None,
            source=source,
            error=f"{source} workspace root is empty",
        )

    root = discover_git_root(raw)
    if root is None:
        if source == "cwd":
            error = "the current working directory is not inside a Git repository"
        else:
            error = f"the {source} workspace root is not inside a Git repository"
        return WorkspaceResolution(root=None, source=source, error=error)
    return WorkspaceResolution(
        root=canonicalize_path(str(root)), source=source
    )


def resolve_registry_path(
    explicit: Optional[PathLike] = None,
    workspace_root: Optional[PathLike] = None,
    *,
    environ: Optional[Mapping[str, str]] = None,
    cwd: Optional[PathLike] = None,
) -> Optional[str]:
    """Resolve the registry path using explicit/env/root-derived precedence.

    Relative explicit and environment paths retain normal CLI semantics and
    are interpreted from the process CWD.  Only the omitted default is
    rooted at the already-resolved workspace, so a nested launch cannot read
    a different CWD-relative registry by accident.  This function never
    creates directories or files.
    """

    env = os.environ if environ is None else environ
    if explicit is not None:
        raw = str(explicit)
    elif "RELINKRA_REGISTRY" in env:
        raw = str(env.get("RELINKRA_REGISTRY") or "")
    else:
        if workspace_root is None:
            return None
        root = canonicalize_path(str(workspace_root))
        return os.path.join(root, ".relinkra", "registry.json")

    if not raw.strip():
        return None
    base = str(cwd if cwd is not None else os.getcwd())
    candidate = raw if os.path.isabs(raw) else os.path.join(base, raw)
    return canonicalize_path(candidate)
