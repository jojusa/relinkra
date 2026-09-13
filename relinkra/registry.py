"""Persistent registry for Relinkra logical projects and workspaces.

JSON file, schema_version=1. Atomic writes (temp file + fsync + os.replace).
Strict validation on load — malformed or credential-containing records are
rejected with RegistryError. No server, no dependencies.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import re
import tempfile
import time
from typing import Optional, Tuple

from .identity import (
    AmbiguousIdentityError,
    LogicalProject,
    RepositoryIdentity,
    Workspace,
    canonicalize_path,
    derive_project_id,
    derive_workspace_id,
    normalize_os_family,
    _utcnow,
)

SCHEMA_VERSION = 1
DEFAULT_REGISTRY_PATH = os.path.join(".relinkra", "registry.json")

_PROJECT_ID_RE = re.compile(r"^rlk_[0-9a-f]{32}$")
_WORKSPACE_ID_RE = re.compile(r"^ws_[0-9a-f]{32}$")
_REMOTE_VALUE_RE = re.compile(r"^remote://git/[^/@\s?#]+/[^\s?#]+$")
_LOCAL_ROOT_VALUE_RE = re.compile(
    r"^local-root://(?:[0-9a-f]{40}|[0-9a-f]{64})(,(?:[0-9a-f]{40}|[0-9a-f]{64}))*$"
)
_EXPLICIT_VALUE_RE = re.compile(r"^explicit://[^@\s]+$")
_CREDENTIAL_RE = re.compile(r"://[^/]*@|://.*:.*@")


class RegistryError(Exception):
    """Raised when the registry file is malformed or fails validation."""


#: Poll interval for a bounded (``timeout``) lock wait. Short enough
#: that a writer waits at most this long past the moment the holder
#: releases; long enough to stay invisible next to any real critical
#: section.
_LOCK_POLL_SECONDS = 0.05

#: Errnos that mean "someone else holds the lock" — retryable under a
#: bounded wait. Anything else means the platform cannot lock this file
#: at all, which is the historical proceed-unlocked case. Built
#: defensively: not every platform defines every errno name.
_LOCK_BUSY_ERRNOS = frozenset(
    value
    for value in (
        errno.EACCES,
        errno.EAGAIN,
        errno.EWOULDBLOCK,
        getattr(errno, "EDEADLK", None),
        getattr(errno, "EDEADLOCK", None),
    )
    if value is not None
)

#: Sentinel returned by a failed non-blocking attempt when the lock is
#: merely held elsewhere — distinct from "this platform cannot lock".
_LOCK_BUSY = "busy"


def _try_lock_once(fh) -> Optional[str]:
    """One non-blocking acquisition attempt.

    Returns the platform primitive name whose lock is HELD, ``None``
    when the platform cannot lock this file at all, or the
    :data:`_LOCK_BUSY` sentinel when another holder keeps the lock.
    """
    try:
        import msvcrt

        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        return "msvcrt"
    except ImportError:
        pass
    except OSError as exc:
        return _LOCK_BUSY if exc.errno in _LOCK_BUSY_ERRNOS else None
    try:
        import fcntl

        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return "fcntl"
    except ImportError:
        return None
    except OSError as exc:
        return _LOCK_BUSY if exc.errno in _LOCK_BUSY_ERRNOS else None


def _acquire_lock_handle(fh, timeout: Optional[float]) -> Tuple[Optional[str], bool]:
    """Take the advisory lock on an open lock-file handle.

    Returns ``(locker, timed_out)``. ``locker`` names the platform
    primitive whose lock is HELD (``"msvcrt"``/``"fcntl"``), or None
    when locking is unavailable or failed — the historical best-effort
    case, in which the critical section proceeds unlocked. ``timed_out``
    is True ONLY when a bounded wait (``timeout``) expired with the lock
    still held elsewhere: the one outcome a bounded caller must treat as
    "skip the critical section" rather than proceed unlocked.
    """
    if timeout is None:
        try:
            import msvcrt

            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
            return "msvcrt", False
        except ImportError:
            try:
                import fcntl

                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                return "fcntl", False
            except (ImportError, OSError):
                return None, False
        except OSError:
            return None, False
    deadline = time.monotonic() + max(0.0, float(timeout))
    while True:
        outcome = _try_lock_once(fh)
        if outcome is not _LOCK_BUSY:
            return outcome, False
        if time.monotonic() >= deadline:
            return None, True
        time.sleep(_LOCK_POLL_SECONDS)


@contextlib.contextmanager
def _interprocess_lock(registry_path: str, *, timeout: Optional[float] = None):
    """Best-effort cross-platform advisory lock for registry mutation.

    Uses a lock file (``<registry>.lock``) alongside the registry:
    ``msvcrt.locking`` on Windows, ``fcntl.flock`` on POSIX. Best-effort:
    if the platform locking primitive is unavailable or fails, the
    critical section proceeds unlocked rather than failing the operation.
    A lock held by a process that dies is released by the OS, and an
    abandoned lock FILE is inert, so nothing here can wedge permanently.

    With ``timeout=None`` (the default) acquisition blocks; the context
    manager yields True. With a ``timeout``, acquisition is a bounded
    non-blocking wait: the manager yields True when the critical section
    may proceed — the lock is held, or the platform cannot lock at all
    (proceed unlocked, as always) — and False only when the bounded wait
    expired with the lock still held elsewhere. A caller that requires
    mutual exclusion must then SKIP its critical section (conservative
    degradation) instead of racing unlocked.
    """
    registry_path = os.fspath(registry_path)
    lock_path = registry_path + ".lock"
    directory = os.path.dirname(os.path.abspath(registry_path))
    os.makedirs(directory, exist_ok=True)
    fh = open(lock_path, "a+b")
    locker = None
    try:
        locker, timed_out = _acquire_lock_handle(fh, timeout)
        try:
            yield not timed_out
        finally:
            try:
                if locker == "msvcrt":
                    import msvcrt

                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                elif locker == "fcntl":
                    import fcntl

                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
    finally:
        fh.close()


#: Public alias. The same advisory-lock discipline guards connector
#: config writes (R4B ``safe_write``); exporting the one implementation
#: keeps a second, subtly different copy from appearing there.
interprocess_lock = _interprocess_lock


def sanitize_remote_for_storage(identity: RepositoryIdentity) -> RepositoryIdentity:
    """Assert an identity carries no credentials before persisting it.

    The error is deliberately generic: the offending value may itself be
    the credential, so it is never interpolated into the message.
    """
    if identity.kind == "remote":
        if "@" in identity.value or _CREDENTIAL_RE.search(identity.value):
            raise ValueError(
                "refusing to store remote identity containing credentials "
                f"(kind={identity.kind})"
            )
    return identity


def _validate_identity(raw: object) -> None:
    if not isinstance(raw, dict):
        raise RegistryError("repository_identity must be an object")
    kind = raw.get("kind")
    value = raw.get("value")
    trust = raw.get("trust")
    if kind not in ("remote", "explicit", "local_root"):
        raise RegistryError(f"unsupported identity kind: {kind!r}")
    if not isinstance(value, str) or not value:
        raise RegistryError("identity value must be a non-empty string")
    if trust not in ("strong", "weak"):
        raise RegistryError(f"unsupported identity trust: {trust!r}")
    if "@" in value or _CREDENTIAL_RE.search(value):
        raise RegistryError(f"stored identity contains credentials (kind={kind})")
    patterns = {
        "remote": _REMOTE_VALUE_RE,
        "explicit": _EXPLICIT_VALUE_RE,
        "local_root": _LOCAL_ROOT_VALUE_RE,
    }
    if not patterns[kind].match(value):
        raise RegistryError(f"malformed {kind} identity value")


def _validate_project(raw: object) -> None:
    if not isinstance(raw, dict):
        raise RegistryError("project record must be an object")
    for field_name in ("project_id", "display_name", "repository_identity", "created_at"):
        if field_name not in raw:
            raise RegistryError(f"project missing required field: {field_name}")
    if not _PROJECT_ID_RE.match(str(raw["project_id"])):
        raise RegistryError(f"malformed project_id: {raw['project_id']!r}")
    _validate_identity(raw["repository_identity"])


def _validate_workspace(raw: object) -> None:
    if not isinstance(raw, dict):
        raise RegistryError("workspace record must be an object")
    for field_name in (
        "workspace_id",
        "project_id",
        "absolute_path",
        "canonical_path",
        "os",
        "registered_at",
        "last_seen_at",
    ):
        if field_name not in raw:
            raise RegistryError(f"workspace missing required field: {field_name}")
    if not _WORKSPACE_ID_RE.match(str(raw["workspace_id"])):
        raise RegistryError(f"malformed workspace_id: {raw['workspace_id']!r}")
    if not _PROJECT_ID_RE.match(str(raw["project_id"])):
        raise RegistryError(f"malformed project_id in workspace: {raw['project_id']!r}")
    if "git" in raw and raw["git"] is not None and not isinstance(raw["git"], dict):
        raise RegistryError("workspace git field must be an object")
    if "cbm" in raw and raw["cbm"] is not None and not isinstance(raw["cbm"], dict):
        raise RegistryError("workspace cbm field must be an object")


def _validate_document(data: object) -> None:
    if not isinstance(data, dict):
        raise RegistryError("registry root must be an object")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise RegistryError(f"unsupported schema_version: {data.get('schema_version')!r}")
    for key in ("projects", "workspaces"):
        if not isinstance(data.get(key), dict):
            raise RegistryError(f"registry {key} must be an object")
    for pid, project in data["projects"].items():
        if not isinstance(project, dict) or pid != project.get("project_id"):
            raise RegistryError(f"project key/id mismatch: {pid!r}")
        _validate_project(project)
    for wid, workspace in data["workspaces"].items():
        if not isinstance(workspace, dict) or wid != workspace.get("workspace_id"):
            raise RegistryError(f"workspace key/id mismatch: {wid!r}")
        _validate_workspace(workspace)
        if workspace["project_id"] not in data["projects"]:
            raise RegistryError(
                f"workspace {wid!r} references unknown project {workspace['project_id']!r}"
            )


class Registry:
    def __init__(self, path: str = DEFAULT_REGISTRY_PATH):
        self.path = str(path)
        self.projects: dict[str, LogicalProject] = {}
        self.workspaces: dict[str, Workspace] = {}
        if os.path.exists(self.path):
            self.load()

    def load(self) -> None:
        with _interprocess_lock(self.path):
            self._load_unlocked()

    def _load_unlocked(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise RegistryError(f"registry is not valid JSON: {exc}") from exc
        _validate_document(data)
        self.projects = {
            pid: LogicalProject.from_dict(p) for pid, p in data["projects"].items()
        }
        self.workspaces = {
            wid: Workspace.from_dict(w) for wid, w in data["workspaces"].items()
        }

    def save(self) -> None:
        with _interprocess_lock(self.path):
            self._save_unlocked()

    def _save_unlocked(self) -> None:
        data = {
            "schema_version": SCHEMA_VERSION,
            "projects": {pid: p.to_dict() for pid, p in sorted(self.projects.items())},
            "workspaces": {wid: w.to_dict() for wid, w in sorted(self.workspaces.items())},
        }
        payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=".registry-", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, self.path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        try:
            dir_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass  # best-effort directory fsync (unsupported on some platforms)

    def find_project_by_identity(self, identity: RepositoryIdentity) -> Optional[LogicalProject]:
        for project in self.projects.values():
            if project.repository_identity.value == identity.value:
                return project
        return None

    def register_workspace(
        self,
        absolute_path: str,
        repository_identity: RepositoryIdentity,
        display_name: Optional[str] = None,
        os_family: Optional[str] = None,
        git: Optional[dict] = None,
        cbm: Optional[dict] = None,
        agent: Optional[str] = None,
        allow_weak_merge: bool = False,
        project_id: Optional[str] = None,
    ) -> Workspace:
        """Register (or refresh) a workspace under a logical project.

        Resolution order: project -> canonical path -> workspace_id. If the
        resolved workspace already exists, this is an idempotent
        re-registration and only ``last_seen_at`` (plus any supplied
        metadata) is refreshed — no ambiguity is raised, even for weak
        identities.         Ambiguity is raised only when a *new* workspace would
        be created from a weak (local_root) identity that matches an
        existing project and neither ``allow_weak_merge`` nor an explicit
        ``project_id`` confirms the merge. Strong identities (remote,
        explicit) merge freely.

        The whole read-modify-write cycle runs under the inter-process
        lock: the current registry file is reloaded from disk while
        holding the lock, then mutated, then saved — so concurrent or
        stale Registry instances never lose each other's registrations.
        """
        sanitize_remote_for_storage(repository_identity)
        if project_id is not None and not _PROJECT_ID_RE.match(project_id):
            raise RegistryError("malformed project_id override")

        with _interprocess_lock(self.path):
            if os.path.exists(self.path):
                self._load_unlocked()
            return self._register_workspace_unlocked(
                absolute_path,
                repository_identity,
                display_name=display_name,
                os_family=os_family,
                git=git,
                cbm=cbm,
                agent=agent,
                allow_weak_merge=allow_weak_merge,
                project_id=project_id,
            )

    def _register_workspace_unlocked(
        self,
        absolute_path: str,
        repository_identity: RepositoryIdentity,
        display_name: Optional[str] = None,
        os_family: Optional[str] = None,
        git: Optional[dict] = None,
        cbm: Optional[dict] = None,
        agent: Optional[str] = None,
        allow_weak_merge: bool = False,
        project_id: Optional[str] = None,
    ) -> Workspace:
        existing = self.find_project_by_identity(repository_identity)
        now = _utcnow()

        if project_id is not None and project_id in self.projects:
            project = self.projects[project_id]
        elif existing is not None:
            project = existing
        else:
            pid = project_id or derive_project_id(repository_identity.value)
            project = self.projects.get(pid)
            if project is None:
                project = LogicalProject(
                    project_id=pid,
                    display_name=display_name
                    or os.path.basename(os.path.abspath(absolute_path)),
                    repository_identity=repository_identity,
                    created_at=now,
                )

        canonical_path = canonicalize_path(absolute_path)
        family = normalize_os_family(os_family or os.sys.platform)
        workspace_id = derive_workspace_id(project.project_id, canonical_path, family)
        workspace = self.workspaces.get(workspace_id)

        if (
            workspace is None
            and existing is not None
            and repository_identity.trust == "weak"
            and not allow_weak_merge
            and project_id is None
        ):
            raise AmbiguousIdentityError(
                "weak local_root identity matches existing project "
                f"{existing.project_id}; pass allow_weak_merge=True or an "
                "explicit project_id to confirm the merge"
            )

        if project.project_id not in self.projects:
            self.projects[project.project_id] = project

        if workspace is None:
            workspace = Workspace(
                workspace_id=workspace_id,
                project_id=project.project_id,
                absolute_path=os.path.abspath(absolute_path),
                canonical_path=canonical_path,
                os=family,
                git=dict(git or {}),
                cbm=cbm,
                agent=agent,
                registered_at=now,
                last_seen_at=now,
            )
            self.workspaces[workspace_id] = workspace
        else:
            workspace.last_seen_at = now
            if git is not None:
                workspace.git = dict(git)
            if cbm is not None:
                workspace.cbm = cbm
            if agent is not None:
                workspace.agent = agent

        self._save_unlocked()
        return workspace

    def list_projects(self) -> list[dict]:
        return [p.to_dict() for _, p in sorted(self.projects.items())]

    def list_workspaces(self) -> list[dict]:
        return [w.to_dict() for _, w in sorted(self.workspaces.items())]

    def get_workspace(self, workspace_id: str) -> Optional[Workspace]:
        return self.workspaces.get(workspace_id)

    def find_workspaces_by_canonical_path(self, path: str) -> list[Workspace]:
        """Return every workspace registered for one canonical root.

        The caller owns ambiguity handling. Keeping this as a collection
        lookup is deliberate: auto-binding must never silently choose the
        first record when malformed or legacy registries contain duplicates.
        """
        canonical = canonicalize_path(path)
        return [
            workspace
            for workspace in self.workspaces.values()
            if canonicalize_path(workspace.canonical_path) == canonical
        ]
