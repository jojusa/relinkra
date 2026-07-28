"""Bounded, read-only discovery of installed agent hosts (R4B).

Finding a host's configuration is where a tool like this normally starts
misbehaving: it walks the user's profile looking for anything that smells
like a config, and ends up reading files it was never invited to read.
This module does the opposite. Every candidate location is DECLARED, the
set is finite and per-connector, and nothing is ever globbed or walked.

Two properties are worth calling out.

LOCATION RESOLUTION IS PURE. Turning an environment into a list of
candidate paths involves no filesystem access and no ``os.path``. It uses
``PureWindowsPath``/``PurePosixPath`` chosen from the environment's own
``system``, so Windows path semantics can be asserted while running on
Linux and vice versa. Only :func:`probe` touches the disk, and only ever
with the real current environment.

ABSENCE IS NOT PROOF. A host is reported ``not_installed`` only when
NONE of its declared locations exist AND its executable is not on PATH.
One missing conventional file means nothing — plenty of people keep their
config somewhere else, or have the tool installed and never configured.
"""

from __future__ import annotations

import os
import platform
import shutil
from dataclasses import dataclass, field
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from typing import Callable, Mapping, Optional, Sequence, Tuple

from .connector import (
    PATH_MACHINE_LOCAL,
    PATH_WORKSPACE_LOCAL,
    SCOPE_USER,
    SCOPE_WORKSPACE,
    ConfigLocation,
)

SYSTEM_WINDOWS = "Windows"
SYSTEM_LINUX = "Linux"
SYSTEM_DARWIN = "Darwin"


def path_flavour(system: str):
    """The pure path class matching a platform's semantics."""
    return PureWindowsPath if system == SYSTEM_WINDOWS else PurePosixPath


def _is_absolute_for(system: str, value: str) -> bool:
    """Whether an environment-supplied directory is safely usable.

    A relative ``XDG_CONFIG_HOME`` or ``CODEX_HOME`` would resolve
    against the process's current directory, which for an MCP host is
    arbitrary — so Relinkra would end up probing, and later planning to
    write, a path chosen by wherever the user happened to be standing.
    Only absolute values are accepted; anything else falls back to the
    documented default.
    """
    if not value or not value.strip():
        return False
    return path_flavour(system)(value).is_absolute()


@dataclass(frozen=True)
class DiscoveryEnvironment:
    """Everything discovery is allowed to know about the machine.

    Injected rather than read ambiently so tests can describe a Windows
    machine, a Linux machine with XDG set, or a machine with no HOME at
    all, without any of those being true of the host running the tests.
    """

    system: str
    home: Optional[PurePath]
    env: Mapping[str, str] = field(default_factory=dict)
    workspace_root: Optional[PurePath] = None
    which: Callable[[str], Optional[str]] = shutil.which

    @classmethod
    def current(cls, workspace_root=None) -> "DiscoveryEnvironment":
        system = platform.system() or SYSTEM_LINUX
        try:
            home: Optional[PurePath] = Path.home()
        except (RuntimeError, OSError):
            # A service account with no resolvable home. Discovery must
            # still run and report honestly rather than raise.
            home = None
        return cls(
            system=system,
            home=home,
            env=dict(os.environ),
            workspace_root=Path(workspace_root) if workspace_root else None,
            which=shutil.which,
        )

    @property
    def is_windows(self) -> bool:
        return self.system == SYSTEM_WINDOWS

    def _join(self, base: Optional[PurePath], *parts: str) -> Optional[PurePath]:
        if base is None:
            return None
        return path_flavour(self.system)(base).joinpath(*parts)

    def home_path(self, *parts: str) -> Optional[PurePath]:
        return self._join(self.home, *parts)

    def config_home(self, *parts: str) -> Optional[PurePath]:
        """``$XDG_CONFIG_HOME`` if usable, else ``~/.config``.

        XDG is honoured on Windows too, and not as a courtesy: several
        cross-platform agent CLIs (OpenCode among them) place their
        config under ``~/.config`` on Windows as well, so a
        POSIX-only reading of the spec would miss the real file.
        """
        raw = self.env.get("XDG_CONFIG_HOME", "")
        if _is_absolute_for(self.system, raw):
            return self._join(path_flavour(self.system)(raw), *parts)
        return self.home_path(".config", *parts)

    def app_data(self, *parts: str) -> Optional[PurePath]:
        """``%APPDATA%`` on Windows, ``None`` elsewhere."""
        if not self.is_windows:
            return None
        raw = self.env.get("APPDATA", "")
        if not _is_absolute_for(self.system, raw):
            return None
        return self._join(path_flavour(self.system)(raw), *parts)

    def env_dir(self, name: str, *parts: str) -> Optional[PurePath]:
        """A directory named by an environment variable, if absolute."""
        raw = self.env.get(name, "")
        if not _is_absolute_for(self.system, raw):
            return None
        return self._join(path_flavour(self.system)(raw), *parts)

    def workspace_path(self, *parts: str) -> Optional[PurePath]:
        return self._join(self.workspace_root, *parts)


@dataclass(frozen=True)
class LocationSpec:
    """A declared candidate configuration file.

    ``build`` maps an environment to a path or ``None`` — ``None`` means
    "this location does not apply here" (``%APPDATA%`` on Linux), which
    is a different statement from "this location is missing".
    """

    location_id: str
    scope: str
    config_format: str
    display_hint: str
    build: Callable[[DiscoveryEnvironment], Optional[PurePath]]

    @property
    def classification(self) -> str:
        return (
            PATH_WORKSPACE_LOCAL
            if self.scope == SCOPE_WORKSPACE
            else PATH_MACHINE_LOCAL
        )


def resolve_locations(
    specs: Sequence[LocationSpec], env: DiscoveryEnvironment
) -> Tuple[Tuple[LocationSpec, Optional[PurePath]], ...]:
    """Map declared specs onto paths. Pure — no filesystem access."""
    return tuple((spec, spec.build(env)) for spec in specs)


def probe(
    specs: Sequence[LocationSpec], env: DiscoveryEnvironment
) -> Tuple[ConfigLocation, ...]:
    """Resolve and stat every candidate, tolerating every failure.

    A location that cannot be stat'ed is reported unreadable rather than
    raising: a permission-denied config is a state ``inspect`` exists to
    describe, and one unreadable candidate must not hide the others.
    """
    results = []
    for spec, pure in resolve_locations(specs, env):
        if pure is None:
            continue
        exists = False
        readable = True
        size: Optional[int] = None
        concrete = Path(str(pure))
        try:
            stat = concrete.stat()
            exists = concrete.is_file()
            size = int(stat.st_size)
            readable = os.access(str(concrete), os.R_OK)
        except OSError as exc:
            # A missing file is the ordinary case and stays "readable" —
            # there is simply nothing there. A denied one is a state the
            # user needs to see, so it is reported unreadable.
            exists = False
            readable = not isinstance(exc, PermissionError)
        results.append(
            ConfigLocation(
                location_id=spec.location_id,
                scope=spec.scope,
                classification=spec.classification,
                config_format=spec.config_format,
                display_hint=spec.display_hint,
                path=concrete,
                exists=exists,
                readable=readable,
                size_bytes=size if exists else None,
            )
        )
    return tuple(results)


def find_executable(
    env: DiscoveryEnvironment, names: Sequence[str]
) -> Optional[str]:
    """First of ``names`` found on PATH, or ``None``.

    Used ONLY as evidence that a host is installed. The result is never
    executed and never becomes part of a launch contract — Relinkra does
    not start the user's agent, it configures it.
    """
    for name in names:
        try:
            found = env.which(name)
        except (OSError, ValueError):
            found = None
        if found:
            return found
    return None


def active_location(locations: Sequence[ConfigLocation]) -> Optional[ConfigLocation]:
    """The first present-or-indeterminate candidate, in declared order.

    Declaration order IS the precedence, so the connector that declares
    the locations decides which config wins — not the order the
    filesystem happens to return.

    An UNREADABLE candidate counts as active even though ``exists`` is
    false for it. A denied ``stat`` cannot tell presence from absence, so
    skipping it would report the host as not installed while its config
    sits right there behind a permissions problem — sending the user off
    to reinstall instead of to ``chmod``.
    """
    for location in locations:
        if location.exists or not location.readable:
            return location
    return None


__all__ = [
    "SYSTEM_DARWIN",
    "SYSTEM_LINUX",
    "SYSTEM_WINDOWS",
    "DiscoveryEnvironment",
    "LocationSpec",
    "active_location",
    "find_executable",
    "path_flavour",
    "probe",
    "resolve_locations",
    "SCOPE_USER",
    "SCOPE_WORKSPACE",
]
