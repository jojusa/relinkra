"""Shared effective project identity resolution (VIS-4).

One resolver owns the pre-migration identity contract every read surface
follows. It answers a single question: which identity governs this
workspace right now?

- A **valid persisted registration** for the current workspace is the
  EFFECTIVE identity, even when the current Git remote derives a stronger
  identity than the one that was registered (the legacy local-root case).
- The current Git-derived identity is always a live CANDIDATE, disclosed
  alongside the registered one.
- When they differ, the identity state is explicitly
  ``migration_available`` and the recommended explicit transition is
  ``relinkra init``. Nothing is aliased, replaced, or relabeled
  automatically, and historical evidence stays bound to the identity it
  was recorded under.

The resolver is deliberately read-only: it loads the registry, derives
the live identity, and returns a path-free value object. No registry,
config, memory, handoff, metrics, or CBM state is ever mutated here.

A registration is valid for a workspace only when the registry record
exists AND its canonical path is the workspace's own canonical path. A
pinned config pointing at a record that belongs to another path (a copied
``.relinkra``, a repurposed checkout) is a caller assertion, not an
attestation: it can never become effective.

Registration validity is re-derived, not trusted from the stored shape:
the record's project must exist, both stored paths must canonicalize to
the workspace's own canonical path, the stored OS family must be this
host's, and the stored ``workspace_id`` must equal the id re-derived from
``(project_id, canonical path, OS family)`` with the existing canonical
derivation. A copied, hand-edited, or half-pinned record fails closed.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Optional

from .identity import (
    GitError,
    RepositoryIdentity,
    Workspace,
    canonicalize_path,
    derive_project_id,
    derive_workspace_id,
    discover_repository_identity,
    normalize_os_family,
)
from .registry import Registry, RegistryError

#: Registered identity exists and matches (or cannot be contradicted by) the
#: live derivation. Normal healthy state.
IDENTITY_STATE_REGISTERED = "registered"

#: A valid registration exists and the live derivation differs: the
#: registered identity stays effective and the live identity is a candidate.
IDENTITY_STATE_MIGRATION_AVAILABLE = "migration_available"

#: No valid registration matches this workspace; the live derivation is the
#: best available identity but nothing is registered for it.
IDENTITY_STATE_UNREGISTERED = "unregistered"

#: Neither a valid registration nor a live derivation resolved (the
#: registration lookup is ambiguous or the record fails integrity
#: re-derivation). Fail closed.
IDENTITY_STATE_UNKNOWN = "unknown"

#: The explicit transition. Path-free on purpose: advice is portable, and
#: the caller already knows the workspace it asked about.
MIGRATION_ACTION = "relinkra init"

_REGISTRATION_NONE = "none"
_REGISTRATION_REGISTERED = "registered"
_REGISTRATION_AMBIGUOUS = "ambiguous"
_REGISTRATION_INVALID = "invalid"


@dataclass(frozen=True)
class EffectiveIdentity:
    """Path-free identity resolution result for one workspace."""

    registered_project_id: Optional[str] = None
    registered_workspace_id: Optional[str] = None
    live_project_id: Optional[str] = None
    live_workspace_id: Optional[str] = None
    effective_project_id: Optional[str] = None
    effective_workspace_id: Optional[str] = None
    identity_state: str = IDENTITY_STATE_UNKNOWN
    migration_available: bool = False
    recommended_action: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "registered_project_id": self.registered_project_id,
            "registered_workspace_id": self.registered_workspace_id,
            "live_project_id": self.live_project_id,
            "live_workspace_id": self.live_workspace_id,
            "effective_project_id": self.effective_project_id,
            "effective_workspace_id": self.effective_workspace_id,
            "identity_state": self.identity_state,
            "migration_available": self.migration_available,
            "recommended_action": self.recommended_action,
        }


def _load_registry(
    registry: Optional[Registry], registry_path: Optional[str]
) -> Optional[Registry]:
    """Load the registry for read-only resolution; unusable means absent."""
    if registry is not None:
        return registry
    if not registry_path:
        return None
    try:
        return Registry(str(registry_path))
    except (RegistryError, OSError, ValueError):
        return None


def _registration_is_intact(
    registry: Registry, workspace: Workspace, canonical: str, os_family: str
) -> bool:
    """Re-derive a record's identity from authoritative current facts.

    A persisted record is trustworthy only when every part of its identity
    is reproducible right here, right now: the project must exist, both
    stored paths must canonicalize to this workspace's own canonical path,
    the stored OS family (part of workspace identity) must be this host's,
    and the stored ``workspace_id`` must equal the id re-derived from
    ``(project_id, canonical path, OS family)`` with the existing
    derivation. Copied, malformed, or half-pinned records fail closed.

    Returns a boolean only: no path or record value is ever returned, so
    nothing here can surface an absolute path.

    The caller's ``workspace_id`` pin is never continuity proof on its own;
    it is only ever compared against a record this function has accepted.
    """
    if registry.projects.get(workspace.project_id) is None:
        return False
    try:
        if canonicalize_path(workspace.canonical_path) != canonical:
            return False
        if canonicalize_path(workspace.absolute_path) != canonical:
            return False
    except (OSError, ValueError):
        return False
    if normalize_os_family(workspace.os) != os_family:
        return False
    try:
        expected_workspace_id = derive_workspace_id(
            workspace.project_id, canonical, os_family
        )
    except (TypeError, ValueError):
        return False
    return workspace.workspace_id == expected_workspace_id


def _registration_for_workspace(
    registry: Optional[Registry],
    canonical: str,
    os_family: str,
    pinned_project_id: Optional[str],
    pinned_workspace_id: Optional[str],
) -> tuple[Optional[str], Optional[str], str]:
    """Resolve ``(project_id, workspace_id, status)`` for one canonical path.

    A pinned config pair is honored only when the registry actually holds
    that workspace for this exact canonical path AND the record passes
    integrity re-derivation. Otherwise the registry's own path lookup
    decides; more than one match is ambiguous and fails closed rather than
    guessing. A half-pinned pair (exactly one id) is an inconsistent
    caller state and fails closed without ever falling back to path trust.
    """
    if registry is None:
        return None, None, _REGISTRATION_NONE
    if pinned_project_id or pinned_workspace_id:
        if not (pinned_project_id and pinned_workspace_id):
            return None, None, _REGISTRATION_INVALID
        workspace = registry.workspaces.get(pinned_workspace_id)
        if (
            workspace is not None
            and workspace.project_id == pinned_project_id
            and _registration_is_intact(registry, workspace, canonical, os_family)
        ):
            return pinned_project_id, pinned_workspace_id, _REGISTRATION_REGISTERED
    matches = registry.find_workspaces_by_canonical_path(canonical)
    if len(matches) == 1:
        workspace = matches[0]
        if not _registration_is_intact(registry, workspace, canonical, os_family):
            return None, None, _REGISTRATION_INVALID
        return workspace.project_id, workspace.workspace_id, _REGISTRATION_REGISTERED
    if len(matches) > 1:
        return None, None, _REGISTRATION_AMBIGUOUS
    return None, None, _REGISTRATION_NONE


def _live_identity(workspace_root: str) -> Optional[RepositoryIdentity]:
    try:
        return discover_repository_identity(workspace_root)
    except (GitError, ValueError, OSError):
        return None


def resolve_effective_identity(
    workspace_root: str,
    *,
    registry: Optional[Registry] = None,
    registry_path: Optional[str] = None,
    registered_project_id: Optional[str] = None,
    registered_workspace_id: Optional[str] = None,
) -> EffectiveIdentity:
    """Resolve the effective identity of one workspace. Read-only.

    ``registered_project_id``/``registered_workspace_id`` are the ids a
    caller already pinned for this checkout (``.relinkra/config.json``);
    they are validated against the registry, never trusted on their own.
    """
    canonical = canonicalize_path(workspace_root)
    os_family = normalize_os_family(sys.platform)
    loaded = _load_registry(registry, registry_path)
    reg_pid, reg_wid, reg_status = _registration_for_workspace(
        loaded,
        canonical,
        os_family,
        registered_project_id,
        registered_workspace_id,
    )
    live = _live_identity(workspace_root)
    live_pid = derive_project_id(live.value) if live is not None else None
    live_wid = (
        derive_workspace_id(live_pid, canonical, os_family)
        if live_pid
        else None
    )

    if reg_status == _REGISTRATION_REGISTERED:
        if live_pid is not None and live_pid != reg_pid:
            return EffectiveIdentity(
                registered_project_id=reg_pid,
                registered_workspace_id=reg_wid,
                live_project_id=live_pid,
                live_workspace_id=live_wid,
                effective_project_id=reg_pid,
                effective_workspace_id=reg_wid,
                identity_state=IDENTITY_STATE_MIGRATION_AVAILABLE,
                migration_available=True,
                recommended_action=MIGRATION_ACTION,
            )
        return EffectiveIdentity(
            registered_project_id=reg_pid,
            registered_workspace_id=reg_wid,
            live_project_id=live_pid,
            live_workspace_id=live_wid,
            effective_project_id=reg_pid,
            effective_workspace_id=reg_wid,
            identity_state=IDENTITY_STATE_REGISTERED,
        )

    if reg_status in (_REGISTRATION_AMBIGUOUS, _REGISTRATION_INVALID):
        return EffectiveIdentity(
            live_project_id=live_pid,
            live_workspace_id=live_wid,
            identity_state=IDENTITY_STATE_UNKNOWN,
        )

    if live_pid is not None:
        # No valid registration: the live derivation is the only identity,
        # but it has no registered workspace binding, so no effective
        # workspace id may be claimed.
        return EffectiveIdentity(
            live_project_id=live_pid,
            live_workspace_id=live_wid,
            effective_project_id=live_pid,
            identity_state=IDENTITY_STATE_UNREGISTERED,
            recommended_action=MIGRATION_ACTION,
        )

    return EffectiveIdentity()
