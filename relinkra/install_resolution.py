"""Which Relinkra is running, and how is it reached (M7).

This module answers four questions about THIS interpreter, read-only:

  * does the imported ``relinkra`` package live inside the interpreter's
    own library directories, or is it a checkout sitting on ``sys.path``?
  * does a ``relinkra`` distribution metadata directory exist for this
    interpreter, and does it describe the code that actually imported?
  * is the ``relinkra`` console script present for this interpreter, and
    does ``PATH`` resolve it into one of that interpreter's own script
    directories?
  * is ``PYTHONPATH`` (or the working directory) what made the import
    resolve where it did?

Honesty rules this module holds to:

  * ``site-packages`` is NOT evidence of PyPI. A wheel built locally and
    a wheel fetched from an index are indistinguishable from here, so
    nothing below ever claims an index origin. The vocabulary is
    installed distribution / source checkout / editable installation /
    ambiguous origin.
  * Distribution metadata alone never proves the imported code belongs to
    it. The import location and the metadata location are compared
    before anything is said about them.
  * An editable installation is claimed only when its own PEP 610
    ``direct_url.json`` says ``dir_info.editable`` is true AND names the
    absolute local target it configures. Without that evidence the state
    is reported as a plain source checkout, because that is all the
    local filesystem can prove.
  * The editable target is the CONFIGURED target, never proof of what
    imported. The imported package root must sit at or below the named
    target before this module attributes the running code to the
    editable install; when the target is elsewhere, the state is a
    source checkout carrying the explicit ``editable_target_mismatch``
    condition. Claiming a healthy editable installation there would
    invent provenance the evidence does not support.
  * Every filesystem probe is bounded to a fixed list of interpreter
    library directories. No parent directory is ever walked, no
    recursive scan is performed, and no Git command is invoked.
  * Nothing is mutated. No PATH, no PYTHONPATH, no shell profile, no
    environment variable, no package, and no process.

Two projections, and the difference matters:

  * :meth:`InstallResolution.to_dict` is PORTABLE. It carries only
    classification tokens, booleans, versions and basenames, so it can
    join ``doctor --json`` without violating that payload's documented
    "no machine-local paths" guarantee.
  * :meth:`InstallResolution.local_paths` is MACHINE-LOCAL and is
    therefore only ever rendered when the operator explicitly asks for
    it (``relinkra version --paths``). Paths are bounded in count and
    length; the environment itself is never dumped.
"""

from __future__ import annotations

import importlib.metadata as importlib_metadata
import json
import os
import shutil
import sys
import sysconfig
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from .safe_write import SafeWriteError, read_bounded_text

# -- execution-mode vocabulary ---------------------------------------------

#: The imported package sits inside one of this interpreter's library
#: directories. Says nothing about where the distribution came from.
RUNNING_INSTALLED = "installed_distribution"
#: The imported package sits outside every library directory, which means
#: ``sys.path`` was pointed at a checkout.
RUNNING_SOURCE = "source_checkout"
#: A source checkout whose metadata declares an editable install, and
#: whose package root sits inside the target that metadata names.
RUNNING_EDITABLE = "editable_installation"
#: The import location could not be established at all.
RUNNING_AMBIGUOUS = "ambiguous"

#: ``PATH`` resolves the console script into one of this interpreter's
#: own script directories.
CLI_RESOLVED = "resolved"
#: ``PATH`` resolves it somewhere else entirely.
CLI_RESOLVED_ELSEWHERE = "resolved_elsewhere"
#: The script file exists for this interpreter but no ``PATH`` entry
#: reaches its directory.
CLI_PRESENT_NOT_ON_PATH = "present_not_on_path"
#: Neither resolution nor the expected script file was found.
CLI_ABSENT = "absent"
#: The interpreter reported no script directory, so nothing is claimed.
CLI_UNKNOWN = "unknown"

#: Condition tokens. Doctor turns these into one actionable line, and they
#: are the only machine-readable trigger vocabulary the module exposes.
CONDITION_CLI_NOT_ON_PATH = "console_script_not_on_path"
CONDITION_CLI_ELSEWHERE = "console_script_elsewhere"
CONDITION_CLI_MISSING = "console_script_missing"
CONDITION_SHADOWED = "source_shadows_installed"
#: An editable install is declared, but the imported package root is not
#: at or below the target that editable metadata names. The metadata
#: proves the configured target, not the import origin.
CONDITION_EDITABLE_MISMATCH = "editable_target_mismatch"
CONDITION_AMBIGUOUS = "origin_ambiguous"

#: Display order for conditions, lowest index wins the single "next
#: action" slot. Deterministic by construction: the tuple is a constant.
_CONDITION_PRIORITY = (
    CONDITION_CLI_NOT_ON_PATH,
    CONDITION_CLI_ELSEWHERE,
    CONDITION_CLI_MISSING,
    CONDITION_SHADOWED,
    CONDITION_EDITABLE_MISMATCH,
    CONDITION_AMBIGUOUS,
)

#: The front-door console script, named once.
CONSOLE_SCRIPT = "relinkra"

#: Splinter names a console script can carry on Windows, where pip writes
#: a ``.exe`` launcher, plus the bare POSIX name.
_SCRIPT_CANDIDATES = (
    CONSOLE_SCRIPT,
    CONSOLE_SCRIPT + ".exe",
    CONSOLE_SCRIPT + ".cmd",
    CONSOLE_SCRIPT + ".bat",
)

#: Distinguishes "not supplied, read the live process" from an explicit
#: ``None``. "This interpreter discloses no script directory" is itself a
#: meaningful state that the classifier reports as unknown, so a test must
#: be able to inject it rather than silently inheriting the live machine.
_UNSET = object()

#: Metadata shapes an installed distribution can present locally.
SHAPE_DIST_INFO = "dist-info"
SHAPE_EGG_INFO = "egg-info"

# -- bounds -----------------------------------------------------------------
# Diagnostics must stay cheap: every number below caps work the module can
# do, so a pathological environment degrades into a coarser answer rather
# than into a slow command.

#: Library directories probed. Four are expected (purelib/platlib for the
#: interpreter scheme and for the user scheme).
MAX_LIB_DIRS = 8
#: Metadata directories examined per library directory.
MAX_METADATA_PER_DIR = 4
#: Editable targets compared against the imported package root.
MAX_EDITABLE_TARGETS = 8
#: ``PYTHONPATH`` entries resolved.
MAX_PYTHONPATH_ENTRIES = 64
#: ``PATH`` entries scanned.
MAX_PATH_ENTRIES = 256
#: Bytes read from a PEP 610 ``direct_url.json``.
MAX_DIRECT_URL_BYTES = 65536
#: Machine-local paths reported by :meth:`InstallResolution.local_paths`.
MAX_LOCAL_PATHS = 8
#: Characters kept per machine-local path.
MAX_LOCAL_PATH_CHARS = 512


# ---------------------------------------------------------------------------
# Small path helpers
# ---------------------------------------------------------------------------


def _basename(value: Optional[str]) -> Optional[str]:
    """Last segment of a path, treating BOTH separators as separators.

    ``PurePath`` of the local flavour is wrong here: a Windows path is
    routinely seen on a POSIX interpreter in tests and in the other
    direction on a mapped drive, and the answer must not depend on which
    flavour happens to be running.
    """
    if not value:
        return None
    text = str(value).replace("\\", "/").rstrip("/")
    if not text:
        return None
    return text.rsplit("/", 1)[-1] or None


def _dirname(value: Optional[str]) -> Optional[str]:
    """Directory part of a path, for both separator flavours."""
    if not value:
        return None
    text = str(value).replace("\\", "/")
    if "/" not in text:
        return None
    head = text.rsplit("/", 1)[0]
    return head or None


def _key(value: Any) -> str:
    """Comparison key: separators and case folded the way the OS folds.

    Used only for equality, never for display, so a path is never echoed
    back in a form that differs from what the caller supplied.
    """
    if value is None:
        return ""
    try:
        text = os.path.normcase(os.path.normpath(str(value)))
    except (TypeError, ValueError):
        return ""
    return text.rstrip("\\/") or text


def _resolved(value: Any) -> Optional[str]:
    """Absolute form of a path, or None when it cannot be established."""
    if not value:
        return None
    try:
        return str(Path(str(value)).resolve())
    except (OSError, TypeError, ValueError):
        return None


def _dedupe(values: Sequence[Optional[str]], limit: int) -> Tuple[str, ...]:
    """Resolved, non-empty values with duplicates folded, capped."""
    seen: List[str] = []
    keys = set()
    for value in values:
        resolved = _resolved(value)
        if not resolved:
            continue
        folded = _key(resolved)
        if not folded or folded in keys:
            continue
        keys.add(folded)
        seen.append(resolved)
        if len(seen) >= limit:
            break
    return tuple(seen)


def _same(left: Optional[str], right: Optional[str]) -> bool:
    left_key, right_key = _key(left), _key(right)
    return bool(left_key) and left_key == right_key


def _unique_paths(values: Sequence[Optional[str]], limit: int) -> Tuple[str, ...]:
    """Non-empty values with duplicates folded, capped.

    Purely lexical, like every comparison built on :func:`_key`: the
    values are already resolved when they arrive, so nothing here reads
    the filesystem.
    """
    seen: List[str] = []
    keys = set()
    for value in values:
        if not value:
            continue
        folded = _key(value)
        if not folded or folded in keys:
            continue
        keys.add(folded)
        seen.append(value)
        if len(seen) >= limit:
            break
    return tuple(seen)


def _within(imported: Optional[str], target: Optional[str]) -> bool:
    """Whether an imported package root sits at or below a target path.

    This is the comparison that keeps PEP 610 metadata in its lane: the
    metadata names the checkout an editable install CONFIGURES, and only
    an imported root inside that checkout can be attributed to it.

    Case folding and separator handling come from :func:`_key`, so a
    Windows comparison folds case the way the OS does while POSIX keeps
    it, exactly like the other path comparisons in this module. The
    target is compared with its separator attached, so a sibling
    directory that merely shares a prefix (``relinkra-b`` against
    ``relinkra``) is never mistaken for a child.
    """
    imported_key, target_key = _key(imported), _key(target)
    if not imported_key or not target_key:
        return False
    if imported_key == target_key:
        return True
    prefix = target_key.rstrip("\\/")
    if not prefix:
        # The target is a filesystem root, which contains every
        # absolute path by definition.
        return True
    return any(
        imported_key.startswith(prefix + separator)
        for separator in ("\\", "/")
    )


# ---------------------------------------------------------------------------
# Gathered facts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LibMetadata:
    """One ``relinkra`` metadata directory owned by a library directory."""

    lib_dir: str
    kind: str
    editable: bool = False
    #: Resolved local target a PROMOTABLE PEP 610 editable claim names.
    #: Only ever set together with ``editable``: a document that says
    #: editable without a usable absolute target proves nothing this
    #: module can compare, so it is not promoted to an editable claim.
    editable_target: Optional[str] = None
    #: Version read from this metadata directory, not from any other one.
    version: Optional[str] = None
    #: The metadata directory itself, when it was located on disk.
    metadata_dir: Optional[str] = None


@dataclass(frozen=True)
class InstallEvidence:
    """Facts about this interpreter, gathered or injected.

    Every field is a plain value so a test can assemble the exact state it
    wants to classify instead of depending on the developer machine.
    """

    imported_root: Optional[str] = None
    interpreter: Optional[str] = None
    interpreter_version: str = ""
    prefix: Optional[str] = None
    base_prefix: Optional[str] = None
    lib_dirs: Tuple[str, ...] = ()
    scripts_dir: Optional[str] = None
    user_scripts_dir: Optional[str] = None
    cwd: Optional[str] = None
    pythonpath: Optional[str] = None
    path_value: Optional[str] = None
    resolved_cli: Optional[str] = None
    expected_script_present: bool = False
    #: Whether the package root carries project-level checkout evidence.
    #: Two bounded probes at exactly one directory — never a walk, and
    #: never treated as proof that the checkout is a Relinkra repository.
    checkout_evidence: bool = False
    #: Metadata directory found by ``importlib.metadata``, if any.
    distribution: Optional[LibMetadata] = None
    distribution_version: Optional[str] = None
    distribution_matches_imported: bool = False
    #: Metadata directories found in this interpreter's library dirs.
    lib_metadata: Tuple[LibMetadata, ...] = ()


def _local_target_from_url(url: Any) -> Optional[str]:
    """Absolute local path named by a PEP 610 ``url``, or ``None``.

    Only ``file:`` URLs and bare absolute paths are accepted; a remote or
    version-control URL, a relative path, or anything that does not yield
    an absolute local directory is not authority this module can compare,
    so it returns ``None`` rather than a guess. Percent escapes are
    decoded and the leading slash a Windows drive URL carries is removed,
    so the value can be compared on any host without touching the disk.
    """
    if not isinstance(url, str):
        return None
    text = url.strip()
    if not text:
        return None
    if text.lower().startswith("file:"):
        try:
            parts = urllib.parse.urlsplit(text)
        except ValueError:
            return None
        path = urllib.parse.unquote(parts.path or "")
        host = parts.netloc
        if host and host.lower() != "localhost":
            # A network share: file://server/share/x.
            path = "//" + host + path
    else:
        # ``urlsplit`` would read a bare Windows drive path ("C:/x") as a
        # one-letter scheme, so only text with an explicit "scheme://" is
        # rejected here; everything else is treated as a plain path.
        if "://" in text:
            return None
        path = urllib.parse.unquote(text)
    # A Windows drive URL carries a leading slash: /C:/work -> C:/work.
    if len(path) >= 3 and path[0] == "/" and path[1].isalpha() and path[2] == ":":
        path = path[1:]
    if path.startswith(("/", "\\")):
        return path or None
    # A drive-absolute Windows path ("C:/x", "C:\\x") is local too; a
    # relative path is not, because there is no trustworthy base to
    # resolve it against.
    if (
        len(path) >= 3
        and path[0].isalpha()
        and path[1] == ":"
        and path[2] in ("/", "\\")
    ):
        return path
    return None


def _parse_direct_url(raw: Any) -> Tuple[bool, Optional[str]]:
    """Editable claim and local target from a PEP 610 document.

    Absent, unreadable, oversized, malformed, or target-less all mean "no
    evidence", which is reported as plain source rather than promoted to
    a claim. ``dir_info.editable`` alone is not enough: PEP 610 requires
    an absolute local ``url``, and without the named target the claim can
    never be compared against what actually imported.
    """
    if not isinstance(raw, str) or len(raw) > MAX_DIRECT_URL_BYTES:
        return False, None
    try:
        document = json.loads(raw)
    except (ValueError, TypeError):
        return False, None
    if not isinstance(document, dict):
        return False, None
    dir_info = document.get("dir_info")
    if not isinstance(dir_info, dict) or dir_info.get("editable") is not True:
        return False, None
    target = _local_target_from_url(document.get("url"))
    if target is None:
        return False, None
    return True, target


def _resolved_editable_evidence(raw: Any) -> Tuple[bool, Optional[str]]:
    """Editable claim plus the RESOLVED target it configures.

    Resolution happens once, where the rest of the evidence is gathered,
    so classification stays a pure string comparison over resolved paths
    — exactly like the imported root it is compared against.
    """
    editable, target = _parse_direct_url(raw)
    if not editable:
        return False, None
    resolved = _resolved(target) if target else None
    return (True, resolved) if resolved else (False, None)


def _read_direct_url_evidence(metadata_dir: Path) -> Tuple[bool, Optional[str]]:
    """Read a metadata directory's ``direct_url.json``, bounded."""
    try:
        raw = read_bounded_text(
            metadata_dir / "direct_url.json", max_bytes=MAX_DIRECT_URL_BYTES
        )
    except (OSError, SafeWriteError, ValueError):
        return False, None
    return _resolved_editable_evidence(raw)


#: Metadata files that carry the version, one per shape.
_METADATA_FILES = {
    SHAPE_DIST_INFO: "METADATA",
    SHAPE_EGG_INFO: "PKG-INFO",
}

#: Bytes read when extracting a version from a metadata directory.
MAX_METADATA_BYTES = 65536
#: Characters kept from a version string.
MAX_VERSION_CHARS = 64


def read_metadata_version(
    metadata_dir: Optional[str], kind: str
) -> Optional[str]:
    """The version a metadata directory declares, read bounded.

    Only the RFC 822 header block is consulted and parsing stops at the
    first blank line, so a large description body is never read into
    memory. Every failure — missing, unreadable, oversized, malformed —
    returns ``None`` rather than a guess.
    """
    if not metadata_dir:
        return None
    filename = _METADATA_FILES.get(kind)
    if not filename:
        return None
    try:
        raw = read_bounded_text(
            Path(metadata_dir) / filename, max_bytes=MAX_METADATA_BYTES
        )
    except (OSError, SafeWriteError, ValueError):
        return None
    for line in raw.splitlines():
        if not line.strip():
            break
        if line.startswith("Version:"):
            value = line[len("Version:") :].strip()
            return value[:MAX_VERSION_CHARS] or None
    return None


def _metadata_shape(document: Any) -> Optional[str]:
    """Distribution shape, read the same way the version command reads it."""
    for entry in getattr(document, "files", None) or ():
        parts = Path(str(entry)).parts
        if any(part.endswith(".dist-info") for part in parts):
            return SHAPE_DIST_INFO
        if any(part.endswith(".egg-info") for part in parts):
            return SHAPE_EGG_INFO
    metadata_path = getattr(document, "_path", None)
    if metadata_path is not None:
        name = Path(str(metadata_path)).name
        if name.endswith(".dist-info"):
            return SHAPE_DIST_INFO
        if name.endswith(".egg-info"):
            return SHAPE_EGG_INFO
    return None


def _probe_lib_metadata(lib_dirs: Sequence[str]) -> Tuple[LibMetadata, ...]:
    """Metadata directories for ``relinkra`` inside known library dirs.

    Bounded on both axes: a fixed list of directories and a fixed number
    of matches per directory. A directory that cannot be listed or that
    holds nothing is simply not evidence.
    """
    found: List[LibMetadata] = []
    for lib_dir in lib_dirs[:MAX_LIB_DIRS]:
        base = Path(lib_dir)
        try:
            if not base.is_dir():
                continue
        except OSError:
            continue
        matches: List[Tuple[str, Path]] = []
        for pattern, kind in (
            ("relinkra-*.dist-info", SHAPE_DIST_INFO),
            ("relinkra.egg-info", SHAPE_EGG_INFO),
            ("relinkra-*.egg-info", SHAPE_EGG_INFO),
        ):
            try:
                for entry in sorted(base.glob(pattern)):
                    matches.append((kind, entry))
            except OSError:
                continue
        for kind, entry in matches[:MAX_METADATA_PER_DIR]:
            editable = False
            editable_target: Optional[str] = None
            if kind == SHAPE_DIST_INFO:
                editable, editable_target = _read_direct_url_evidence(entry)
            metadata_dir = _resolved(entry)
            found.append(
                LibMetadata(
                    lib_dir=lib_dir,
                    kind=kind,
                    editable=editable,
                    editable_target=editable_target,
                    version=read_metadata_version(metadata_dir, kind),
                    metadata_dir=metadata_dir,
                )
            )
    return tuple(found)


def _expected_script_present(scripts_dir: Optional[str]) -> bool:
    """Whether a console-script launcher exists in this interpreter's dir."""
    if not scripts_dir:
        return False
    base = Path(scripts_dir)
    for name in _SCRIPT_CANDIDATES:
        try:
            if (base / name).is_file():
                return True
        except OSError:
            continue
    return False


#: Files that mark a project root. Presence is reported as evidence, not
#: as provenance: a directory holding a ``pyproject.toml`` is a project,
#: and proving anything more would need the Git commands and recursive
#: scans this module deliberately refuses to run.
_CHECKOUT_MARKERS = ("pyproject.toml", "setup.py", "setup.cfg")


def _checkout_evidence(imported_root: Optional[str]) -> bool:
    """Bounded project-root probe: at most three ``is_file`` calls."""
    if not imported_root:
        return False
    base = Path(imported_root)
    for name in _CHECKOUT_MARKERS:
        try:
            if (base / name).is_file():
                return True
        except OSError:
            continue
    return False


def _interpreter_lib_dirs() -> Tuple[str, ...]:
    """Library directories that belong to THIS interpreter.

    The default scheme plus the user scheme, because a ``pip install
    --user`` distribution is legitimately this interpreter's. Anything
    else on ``sys.path`` is not consulted.
    """
    candidates: List[Optional[str]] = []
    try:
        paths = sysconfig.get_paths()
    except (OSError, ValueError, KeyError):
        paths = {}
    candidates.extend([paths.get("purelib"), paths.get("platlib")])
    scheme = "nt_user" if os.name == "nt" else "posix_user"
    try:
        user_paths = sysconfig.get_paths(scheme=scheme)
    except (OSError, ValueError, KeyError):
        user_paths = {}
    candidates.extend(
        [user_paths.get("purelib"), user_paths.get("platlib")]
    )
    return _dedupe(candidates, MAX_LIB_DIRS)


def _interpreter_scripts_dir(user: bool = False) -> Optional[str]:
    scheme = ("nt_user" if os.name == "nt" else "posix_user") if user else None
    try:
        paths = (
            sysconfig.get_paths(scheme=scheme)
            if scheme
            else sysconfig.get_paths()
        )
    except (OSError, ValueError, KeyError):
        return None
    return paths.get("scripts") or None


def _distribution_document(
    lookup: Callable[[str], Any]
) -> Tuple[Optional[Any], Optional[str]]:
    """The ``importlib.metadata`` record for ``relinkra``, if it exists."""
    try:
        return lookup("relinkra"), None
    except Exception as exc:  # PackageNotFoundError and any lookup failure
        return None, type(exc).__name__


def _read_distribution_version(document: Any) -> Optional[str]:
    version = getattr(document, "version", None)
    return str(version) if version is not None else None


def _direct_url_evidence(document: Any) -> Tuple[bool, Optional[str]]:
    """Editable evidence carried by the distribution object itself."""
    reader = getattr(document, "read_text", None)
    if not callable(reader):
        return False, None
    try:
        raw = reader("direct_url.json")
    except Exception:
        return False, None
    return _resolved_editable_evidence(raw)


def gather_install_evidence(
    *,
    imported_file: Optional[str] = None,
    interpreter: Optional[str] = None,
    interpreter_version: Optional[str] = None,
    environ: Optional[Mapping[str, str]] = None,
    lib_dirs: Optional[Sequence[str]] = None,
    scripts_dir: Any = _UNSET,
    user_scripts_dir: Any = _UNSET,
    cwd: Optional[str] = None,
    which: Optional[Callable[[str], Optional[str]]] = None,
    distribution_lookup: Optional[Callable[[str], Any]] = None,
    lib_metadata: Optional[Sequence[LibMetadata]] = None,
    expected_script_present: Optional[bool] = None,
    checkout_evidence: Optional[bool] = None,
) -> InstallEvidence:
    """Read the live process. Every input is injectable for tests."""
    env: Mapping[str, str] = os.environ if environ is None else environ
    resolver = shutil.which if which is None else which

    if imported_file is None:
        # This module lives inside the package, so its own resolved parent
        # is the package root without importing the package to ask.
        imported_root = _resolved(Path(__file__).resolve().parent.parent)
    else:
        # An injected value names a module FILE inside the package, exactly
        # like the live one, so the package root is two levels up either
        # way. Reading it as a root would silently misclassify every test.
        imported_root = _resolved(Path(str(imported_file)).parent.parent)

    resolved_lib_dirs = (
        _dedupe(lib_dirs, MAX_LIB_DIRS)
        if lib_dirs is not None
        else _interpreter_lib_dirs()
    )
    resolved_scripts = (
        _interpreter_scripts_dir()
        if scripts_dir is _UNSET
        else (_resolved(scripts_dir) if scripts_dir else None)
    )
    resolved_user_scripts = (
        _interpreter_scripts_dir(user=True)
        if user_scripts_dir is _UNSET
        else (_resolved(user_scripts_dir) if user_scripts_dir else None)
    )

    try:
        resolved_cwd = _resolved(cwd) if cwd else _resolved(os.getcwd())
    except OSError:
        resolved_cwd = None

    try:
        resolved_cli = resolver(CONSOLE_SCRIPT)
    except Exception:
        resolved_cli = None
    resolved_cli = _resolved(resolved_cli) if resolved_cli else None

    lookup = (
        importlib_metadata.distribution
        if distribution_lookup is None
        else distribution_lookup
    )
    document, _ = _distribution_document(lookup)

    distribution: Optional[LibMetadata] = None
    distribution_version: Optional[str] = None
    distribution_matches_imported = False
    if document is not None:
        distribution_version = _read_distribution_version(document)
        shape = _metadata_shape(document)
        metadata_root: Optional[str] = None
        locate = getattr(document, "locate_file", None)
        if callable(locate):
            try:
                metadata_root = _resolved(locate(""))
            except (OSError, TypeError, ValueError):
                metadata_root = None
        if shape is not None:
            editable, editable_target = _direct_url_evidence(document)
            distribution = LibMetadata(
                lib_dir=metadata_root or "",
                kind=shape,
                editable=editable,
                editable_target=editable_target,
                version=_read_distribution_version(document),
                metadata_dir=_resolved(getattr(document, "_path", None)),
            )
        distribution_matches_imported = bool(
            metadata_root
            and imported_root
            and _same(metadata_root, imported_root)
        )

    version = interpreter_version
    if version is None:
        version = ".".join(str(part) for part in sys.version_info[:3])

    return InstallEvidence(
        imported_root=imported_root,
        interpreter=(
            _resolved(sys.executable) if interpreter is None else _resolved(interpreter)
        ),
        interpreter_version=version,
        prefix=_resolved(sys.prefix),
        base_prefix=_resolved(sys.base_prefix),
        lib_dirs=resolved_lib_dirs,
        scripts_dir=resolved_scripts,
        user_scripts_dir=resolved_user_scripts,
        cwd=resolved_cwd,
        pythonpath=env.get("PYTHONPATH"),
        path_value=env.get("PATH"),
        resolved_cli=resolved_cli,
        expected_script_present=(
            _expected_script_present(resolved_scripts)
            if expected_script_present is None
            else bool(expected_script_present)
        ),
        checkout_evidence=(
            _checkout_evidence(imported_root)
            if checkout_evidence is None
            else bool(checkout_evidence)
        ),
        distribution=distribution,
        distribution_version=distribution_version,
        distribution_matches_imported=distribution_matches_imported,
        lib_metadata=(
            _probe_lib_metadata(resolved_lib_dirs)
            if lib_metadata is None
            else tuple(lib_metadata[: MAX_LIB_DIRS * MAX_METADATA_PER_DIR])
        ),
    )


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InstallResolution:
    """The classified answer, plus the evidence it was classified from.

    ``to_dict`` is the portable projection; ``local_paths`` is the
    machine-local one. Only the second may carry absolute paths.
    """

    running_from: str
    interpreter_name: Optional[str]
    interpreter_version: str
    in_virtualenv: bool
    virtualenv_name: Optional[str]
    distribution_version: Optional[str]
    distribution_shape: Optional[str]
    #: Version declared by the metadata found in this interpreter's own
    #: library directories. This is the installed distribution's version,
    #: and it is reported separately from the importlib-visible record
    #: because that record can belong to a checkout instead.
    installed_distribution_version: Optional[str]
    installed_distribution_shape: Optional[str]
    distribution_matches_imported: bool
    installed_for_interpreter: bool
    editable_evidence: bool
    checkout_evidence: bool
    cli_status: str
    console_script: str
    scripts_dir_exists: bool
    scripts_dir_on_path: bool
    scripts_dir_name: Optional[str]
    pythonpath_set: bool
    pythonpath_contributes_imported: bool
    working_directory_is_package_root: bool
    conditions: Tuple[str, ...] = ()
    evidence: Optional[InstallEvidence] = field(
        default=None, compare=False, repr=False
    )

    @property
    def shadowed(self) -> bool:
        """True when a checkout won the import race against an install."""
        return CONDITION_SHADOWED in self.conditions

    @property
    def primary_condition(self) -> Optional[str]:
        """Highest-priority condition, or None when nothing is wrong."""
        for condition in _CONDITION_PRIORITY:
            if condition in self.conditions:
                return condition
        return None

    def to_dict(self) -> dict:
        """Portable projection: no machine-local path can appear here."""
        return {
            "running_from": self.running_from,
            "interpreter": {
                "name": self.interpreter_name,
                "version": self.interpreter_version,
                "in_virtualenv": self.in_virtualenv,
                "virtualenv_name": self.virtualenv_name,
            },
            "distribution": {
                "visible": self.distribution_version is not None
                or self.distribution_shape is not None,
                "version": self.distribution_version,
                "shape": self.distribution_shape,
                "matches_imported_package": self.distribution_matches_imported,
                "installed_for_interpreter": self.installed_for_interpreter,
                "installed_version": self.installed_distribution_version,
                "installed_shape": self.installed_distribution_shape,
                "editable_evidence": self.editable_evidence,
                "checkout_evidence": self.checkout_evidence,
            },
            "console_script": {
                "name": self.console_script,
                "status": self.cli_status,
                "scripts_dir_name": self.scripts_dir_name,
                "scripts_dir_exists": self.scripts_dir_exists,
                "scripts_dir_on_path": self.scripts_dir_on_path,
            },
            "pythonpath": {
                "set": self.pythonpath_set,
                "contributes_imported_package": (
                    self.pythonpath_contributes_imported
                ),
            },
            "working_directory_is_package_root": (
                self.working_directory_is_package_root
            ),
            "conditions": list(self.conditions),
        }

    def local_paths(self) -> Dict[str, Any]:
        """Machine-local projection, rendered only on explicit request.

        Bounded twice over: a fixed number of entries and a fixed length
        per entry. The environment is never dumped wholesale — only the
        two path lists this diagnostic actually reasons about.
        """
        evidence = self.evidence or InstallEvidence()
        pythonpath: List[str] = []
        for entry in _pythonpath_entries(evidence.pythonpath):
            text = str(entry)
            if len(text) > MAX_LOCAL_PATH_CHARS:
                text = text[:MAX_LOCAL_PATH_CHARS]
            pythonpath.append(text)
            if len(pythonpath) >= MAX_LOCAL_PATHS:
                break
        # The metadata directory itself is more actionable than the library
        # directory that contains it, so it wins when both are known.
        metadata = evidence.distribution
        distribution_metadata = None
        if metadata is not None:
            distribution_metadata = metadata.metadata_dir or metadata.lib_dir
        return {
            "interpreter": evidence.interpreter,
            "package_origin": evidence.imported_root,
            "distribution_metadata": distribution_metadata,
            "expected_scripts_dir": evidence.scripts_dir,
            "expected_scripts_dir_exists": self.scripts_dir_exists,
            "resolved_console_script": evidence.resolved_cli,
            "pythonpath": pythonpath,
        }


def _pythonpath_entries(raw: Optional[str]) -> List[str]:
    """Bounded, non-empty ``PYTHONPATH`` entries."""
    if not raw:
        return []
    entries = [entry for entry in raw.split(os.pathsep) if entry.strip()]
    return entries[:MAX_PYTHONPATH_ENTRIES]


def _path_contains(raw: Optional[str], target: Optional[str]) -> bool:
    """Whether a ``PATH``-shaped value reaches ``target``'s directory."""
    if not raw or not target:
        return False
    target_key = _key(target)
    if not target_key:
        return False
    for index, entry in enumerate(raw.split(os.pathsep)):
        if index >= MAX_PATH_ENTRIES:
            break
        if not entry.strip():
            continue
        if _key(_resolved(entry)) == target_key:
            return True
    return False


def classify_install(evidence: InstallEvidence) -> InstallResolution:
    """Classify gathered evidence. Pure, deterministic, never raises."""
    lib_keys = {_key(directory) for directory in evidence.lib_dirs}
    lib_keys.discard("")
    imported_key = _key(evidence.imported_root)
    imported_in_lib = bool(imported_key) and imported_key in lib_keys

    # An editable claim and the target it names travel together: the
    # claim is only promotable when the document names an absolute local
    # target, because that target is the only thing the claim can be
    # honestly compared against.
    editable_entries = [
        entry
        for entry in evidence.lib_metadata
        if entry.editable and entry.editable_target
    ]
    if (
        evidence.distribution is not None
        and evidence.distribution.editable
        and evidence.distribution.editable_target
    ):
        editable_entries.append(evidence.distribution)
    editable_targets = _unique_paths(
        [entry.editable_target for entry in editable_entries],
        MAX_EDITABLE_TARGETS,
    )
    editable = bool(editable_targets)
    installed = bool(evidence.lib_metadata)

    # PEP 610 proves the CONFIGURED editable target; it says nothing
    # about where the import resolved. The imported package root must sit
    # at or below the named target before this execution can be called
    # that editable installation.
    editable_matches_import = bool(imported_key) and any(
        _within(evidence.imported_root, target) for target in editable_targets
    )

    if not imported_key:
        # No import location at all: nothing can be said about the code.
        running_from = RUNNING_AMBIGUOUS
    elif imported_in_lib:
        running_from = RUNNING_INSTALLED
    elif not lib_keys:
        # The interpreter reported no library directory, so a location
        # outside one cannot be told apart from an install. Saying
        # "source checkout" here would be a guess, and this module does
        # not guess.
        running_from = RUNNING_AMBIGUOUS
    elif editable and editable_matches_import:
        running_from = RUNNING_EDITABLE
    else:
        running_from = RUNNING_SOURCE

    consistent_dirs = [
        value
        for value in (evidence.scripts_dir, evidence.user_scripts_dir)
        if value
    ]
    resolved_dir = _dirname(evidence.resolved_cli)
    if evidence.resolved_cli:
        if not consistent_dirs:
            cli_status = CLI_UNKNOWN
        elif any(_same(resolved_dir, value) for value in consistent_dirs):
            cli_status = CLI_RESOLVED
        else:
            cli_status = CLI_RESOLVED_ELSEWHERE
    elif evidence.expected_script_present:
        cli_status = CLI_PRESENT_NOT_ON_PATH
    elif evidence.scripts_dir:
        cli_status = CLI_ABSENT
    else:
        cli_status = CLI_UNKNOWN

    conditions: List[str] = []
    if running_from == RUNNING_AMBIGUOUS:
        conditions.append(CONDITION_AMBIGUOUS)

    # A checkout winning the import race against a separate installed
    # distribution is the state that makes "am I testing the installed
    # artifact?" unanswerable. A MATCHING editable install is not that
    # state: its metadata describes this very checkout, so imports are
    # correct. An editable install whose target is not what imported is a
    # different and sharper failure of the same kind, and gets its own
    # condition below instead of being folded into this one.
    if (
        running_from == RUNNING_SOURCE
        and installed
        and not editable
        and not imported_in_lib
    ):
        conditions.append(CONDITION_SHADOWED)

    # Editable metadata names a target; the imported package root is not
    # at or below it. The configured editable install is not the code
    # that is running, and saying otherwise would invent provenance.
    if (
        running_from == RUNNING_SOURCE
        and editable
        and not editable_matches_import
    ):
        conditions.append(CONDITION_EDITABLE_MISMATCH)

    if installed:
        if cli_status == CLI_PRESENT_NOT_ON_PATH:
            conditions.append(CONDITION_CLI_NOT_ON_PATH)
        elif cli_status == CLI_RESOLVED_ELSEWHERE:
            conditions.append(CONDITION_CLI_ELSEWHERE)
        elif cli_status == CLI_ABSENT:
            conditions.append(CONDITION_CLI_MISSING)
    elif cli_status == CLI_RESOLVED_ELSEWHERE:
        conditions.append(CONDITION_CLI_ELSEWHERE)

    pythonpath_contributes = bool(imported_key) and any(
        _same(_resolved(entry), evidence.imported_root)
        for entry in _pythonpath_entries(evidence.pythonpath)
    )

    # A virtual environment is proven by the interpreter disagreeing with
    # its own base prefix, never inferred from a directory name.
    in_virtualenv = bool(
        evidence.prefix
        and evidence.base_prefix
        and not _same(evidence.prefix, evidence.base_prefix)
    )

    installed_entry = evidence.lib_metadata[0] if evidence.lib_metadata else None

    return InstallResolution(
        running_from=running_from,
        interpreter_name=_basename(evidence.interpreter),
        interpreter_version=evidence.interpreter_version,
        in_virtualenv=in_virtualenv,
        virtualenv_name=_basename(evidence.prefix) if in_virtualenv else None,
        distribution_version=evidence.distribution_version,
        distribution_shape=(
            evidence.distribution.kind
            if evidence.distribution is not None
            else None
        ),
        installed_distribution_version=(
            installed_entry.version if installed_entry is not None else None
        ),
        installed_distribution_shape=(
            installed_entry.kind if installed_entry is not None else None
        ),
        distribution_matches_imported=evidence.distribution_matches_imported,
        installed_for_interpreter=installed,
        editable_evidence=editable,
        checkout_evidence=evidence.checkout_evidence,
        cli_status=cli_status,
        console_script=CONSOLE_SCRIPT,
        scripts_dir_exists=bool(
            evidence.scripts_dir and _is_dir(evidence.scripts_dir)
        ),
        scripts_dir_on_path=_path_contains(
            evidence.path_value, evidence.scripts_dir
        ),
        scripts_dir_name=_basename(evidence.scripts_dir),
        pythonpath_set=bool(evidence.pythonpath),
        pythonpath_contributes_imported=pythonpath_contributes,
        working_directory_is_package_root=_same(
            evidence.cwd, evidence.imported_root
        ),
        # Sorted into the fixed priority order, so the tuple is stable
        # across platforms and across dictionary iteration order.
        conditions=tuple(
            sorted(
                set(conditions),
                key=lambda item: _CONDITION_PRIORITY.index(item),
            )
        ),
        evidence=evidence,
    )


def _is_dir(value: Optional[str]) -> bool:
    if not value:
        return False
    try:
        return Path(value).is_dir()
    except OSError:
        return False


def resolve_install(**kwargs: Any) -> InstallResolution:
    """Gather and classify in one step."""
    return classify_install(gather_install_evidence(**kwargs))
