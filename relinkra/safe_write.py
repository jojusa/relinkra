"""Backup, atomic write and rollback primitives for connector writes (R4B).

Relinkra edits files it does not own. A host's ``settings.json`` may hold
years of a developer's configuration, so the only acceptable failure mode
for a connector write is "nothing changed". Everything here exists to
make that the ONLY failure mode:

    lock -> precondition digest -> pre-validate -> backup
         -> same-directory temp -> fsync -> atomic replace
         -> post-validate -> rollback on failure

Three choices are worth stating up front, because each answers a specific
way this goes wrong in the field.

SAME-DIRECTORY TEMP. ``os.replace`` is atomic only within a filesystem.
Writing the temp file to the system temp directory and moving it across a
mount would silently degrade to copy-then-delete, which is exactly the
non-atomic behaviour being avoided.

POST-WRITE VALIDATION. Validating the in-memory string is not enough. The
bytes that matter are the bytes on disk, and encoding, truncation and a
full disk all show up only after the write. So the file is read back and
re-validated, and a failure restores the backup.

REFUSING SYMLINKS. ``os.replace`` onto a symlink replaces the LINK, not
its target — silently detaching a config the user deliberately linked
into place. There is no safe generic recovery, so the write is refused
with a typed error instead.

This module performs no host-specific reasoning and knows nothing about
MCP. It is the mechanical layer under ``config_merge`` and the connectors.

BOUNDED CONCURRENCY CONTRACT. Relinkra uses optimistic digests, same-directory
atomic filesystem primitives and terminal/post-write safety gates. It detects
and refuses meaningful state changes before commit and never reports success
when post-write safety validation detects authority divergence. It does not
claim a serializable transaction across independent files against arbitrary
non-cooperating writers; the remaining risk is limited to syscall-sized races
that the platform cannot compare-and-swap portably.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Union

from .registry import interprocess_lock

#: Hard ceiling for any configuration file Relinkra reads. A host config
#: is kilobytes; anything past this is a mistake, a log file pointed at
#: the wrong place, or an attempt to make Relinkra allocate a gigabyte
#: from a path it was told to inspect. Refusing is cheaper than parsing.
MAX_CONFIG_BYTES = 1_048_576

#: Suffix for backups. Deliberately explicit: a user finding this file
#: months later should be able to tell who wrote it and why.
BACKUP_SUFFIX = ".relinkra-backup"

#: Upper bound on collision-avoiding backup attempts. Past this the
#: directory is not in a state anyone should keep writing into.
MAX_BACKUP_ATTEMPTS = 100

#: Mode for files Relinkra CREATES. Host configs routinely carry API
#: tokens, so a new one is owner-only. An EXISTING file keeps its own
#: mode — tightening someone's deliberate permissions is its own bug.
NEW_FILE_MODE = 0o600


class SafeWriteError(Exception):
    """Base error for the safe-write primitives."""


class ConfigTooLargeError(SafeWriteError):
    """Raised when a config exceeds :data:`MAX_CONFIG_BYTES`."""


class UnsafeTargetError(SafeWriteError):
    """Raised when the target is not a plain file we may replace."""


class PreconditionError(SafeWriteError):
    """Raised when the target changed since it was inspected."""


class _ExpectedAbsent:
    """Identity-only marker for an inspected target that did not exist."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "EXPECTED_ABSENT"


# None intentionally remains the generic caller's no-precondition mode.
# Connector apply uses this distinct value when its current snapshot proves
# that the target was absent.
EXPECTED_ABSENT = _ExpectedAbsent()


class ContentValidationError(SafeWriteError):
    """Raised when content fails validation.

    ``rolled_back`` distinguishes the two very different situations this
    covers: rejected before anything was touched, or written, found bad,
    and restored. The caller's message to the user differs completely.
    """

    def __init__(self, message: str, *, rolled_back: bool = False):
        super().__init__(message)
        self.rolled_back = rolled_back


@dataclass
class _PreparedWrite:
    """A complete same-directory payload waiting for its terminal commit."""

    target: Path
    temp: Path


def _discard_prepared(prepared: Optional[_PreparedWrite]) -> None:
    if prepared is None:
        return
    with contextlib.suppress(OSError):
        os.unlink(str(prepared.temp))


@dataclass(frozen=True)
class WriteReceipt:
    """What a completed write actually did.

    ``backup_path`` is machine-local and is never rendered into portable
    output; callers report ``backup_created`` instead.
    """

    target: Path
    backup_path: Optional[Path]
    digest_before: Optional[str]
    digest_after: str
    created: bool
    backup_digest: Optional[str] = None

    @property
    def backup_created(self) -> bool:
        return self.backup_path is not None

    def to_dict(self) -> dict:
        return {
            "created": self.created,
            "backup_created": self.backup_created,
            "digest_before": self.digest_before,
            "digest_after": self.digest_after,
            "backup_digest": self.backup_digest,
        }


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def digest_bytes(data: bytes) -> str:
    """Hash exact configuration bytes for security-sensitive gates."""
    return hashlib.sha256(data).hexdigest()


def digest_text(text: str) -> str:
    """Content digest API retained for decoded UTF-8 configuration text."""
    return digest_bytes(text.encode("utf-8"))


def read_bounded_text(
    path, *, max_bytes: int = MAX_CONFIG_BYTES, encoding: str = "utf-8"
) -> str:
    """Read a config file, refusing anything oversized.

    The size is checked twice. ``stat`` is the cheap rejection, but it is
    also a TOCTOU read: the file can grow between the check and the read,
    and on some virtual filesystems it reports zero regardless. So the
    read itself asks for one byte more than the limit and rejects when it
    gets it — that second check is the one that actually holds.
    """
    target = Path(path)
    try:
        size = target.stat().st_size
    except OSError as exc:
        raise SafeWriteError(f"cannot stat configuration file: {exc}") from exc
    if size > max_bytes:
        raise ConfigTooLargeError(
            f"configuration file is {size} bytes, over the {max_bytes} byte limit"
        )
    with open(target, "rb") as handle:
        raw = handle.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ConfigTooLargeError(
            f"configuration file exceeds the {max_bytes} byte limit"
        )
    return raw.decode(encoding, errors="strict")


def detect_newline(text: str) -> str:
    """Return the dominant line ending, defaulting to ``\\n``.

    Rewriting a CRLF file with LF endings turns a one-line change into a
    whole-file diff in the user's own version control. Cheap to preserve,
    expensive to ignore.
    """
    if "\r\n" in text:
        return "\r\n"
    if "\n" in text:
        return "\n"
    return "\n"


# ---------------------------------------------------------------------------
# Target checks
# ---------------------------------------------------------------------------


def _require_host_absolute(target: Path) -> None:
    """Fail closed when a write target is not absolute on THIS host.

    A candidate built with foreign-platform semantics — a Windows-flavour
    ``\\tmp\\...`` string on POSIX, or a drive-less ``/tmp/...`` path on
    Windows — converts to a RELATIVE host path, which resolves against
    the process working directory: the write lands wherever the process
    happens to stand (R5C: a Windows-flavour fixture path was written
    into the repository working tree on a Linux runner). Relinkra only
    ever writes declared, absolute host targets.
    """
    if not target.is_absolute():
        raise UnsafeTargetError(
            "write target is not an absolute host path; refusing to "
            "resolve a write against the process working directory"
        )


def assert_writable_target(path) -> None:
    """Refuse anything that is not an absent file or a plain file.

    Covers symlinks and reparse points (``is_symlink`` is true for a
    Windows junction/symlink too), directories, and device/FIFO entries.
    ``os.replace`` onto any of those either destroys the indirection or
    fails in a way that is hard to unwind.
    """
    target = Path(path)
    _require_host_absolute(target)
    if target.is_symlink():
        raise UnsafeTargetError(
            "refusing to write through a symlink or reparse point"
        )
    if target.exists() and not target.is_file():
        raise UnsafeTargetError("target exists and is not a regular file")
    parent = target.parent
    if parent.exists() and not parent.is_dir():
        raise UnsafeTargetError("target parent exists and is not a directory")


# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------


def next_backup_path(path, *, attempts: int = MAX_BACKUP_ATTEMPTS) -> Path:
    """Pick a backup name that does not exist yet.

    The first backup is ``<name><BACKUP_SUFFIX>``; later ones append
    ``-1``, ``-2``. Never reuses a name, because the second failed write
    of a session would otherwise overwrite the only copy of the user's
    original file.
    """
    target = Path(path)
    base = target.with_name(target.name + BACKUP_SUFFIX)
    if not base.exists():
        return base
    for index in range(1, attempts):
        candidate = target.with_name(f"{target.name}{BACKUP_SUFFIX}-{index}")
        if not candidate.exists():
            return candidate
    raise SafeWriteError(
        f"could not find a free backup name after {attempts} attempts"
    )


def create_backup(path) -> Optional[Path]:
    """Copy the target aside, preserving its mode. ``None`` if absent.

    ``copy2`` rather than ``copy`` so permissions and timestamps survive;
    a backup the user cannot read is not a backup. The copy is fsynced,
    because a backup still in the page cache does not survive the crash
    it exists to protect against.
    """
    target = Path(path)
    if not target.exists():
        return None
    destination = next_backup_path(target)
    shutil.copy2(str(target), str(destination))
    _fsync_file(destination)
    return destination


def _fsync_file(path) -> None:
    try:
        handle = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(handle)
    except OSError:
        pass  # not supported on every filesystem; best effort
    finally:
        os.close(handle)


def _fsync_dir(path) -> None:
    """Best effort. Windows cannot open a directory this way at all."""
    try:
        handle = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(handle)
    except OSError:
        pass
    finally:
        os.close(handle)


# ---------------------------------------------------------------------------
# Atomic write
# ---------------------------------------------------------------------------


def prepare_atomic_write(path, text: str, *, mode: Optional[int] = None) -> _PreparedWrite:
    """Prepare all payload bytes before a terminal safety/commit gate."""
    target = Path(path)
    _require_host_absolute(target)
    directory = target.parent
    directory.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(
        dir=str(directory), prefix=".relinkra-", suffix=".tmp"
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        with contextlib.suppress(OSError, NotImplementedError):
            os.chmod(temp_name, NEW_FILE_MODE if mode is None else mode)
        return _PreparedWrite(target=target, temp=Path(temp_name))
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp_name)
        raise


def commit_prepared_write(
    prepared: _PreparedWrite, *, conditional_create: bool = False
) -> None:
    """Commit a prepared payload with no-expensive-work terminal semantics.

    Conditional creation uses a same-directory hard link.  Link creation is
    atomic and fails when the destination already exists on the supported
    Windows/Linux/macOS filesystems; it is never weakened to ``replace``.
    """
    target = prepared.target
    temp = prepared.temp
    try:
        if conditional_create:
            try:
                os.link(str(temp), str(target))
            except FileExistsError as exc:
                raise PreconditionError(
                    "configuration was created immediately before replacement; re-run the plan"
                ) from exc
            except OSError as exc:
                if exc.errno == errno.EEXIST:
                    raise PreconditionError(
                        "configuration was created immediately before replacement; re-run the plan"
                    ) from exc
                raise SafeWriteError(
                    "the filesystem cannot enforce an atomic expected-absence create"
                ) from exc
            with contextlib.suppress(OSError):
                os.unlink(str(temp))
        else:
            os.replace(str(temp), str(target))
        _fsync_dir(target.parent)
    finally:
        with contextlib.suppress(OSError):
            os.unlink(str(temp))


def atomic_write_text(path, text: str, *, mode: Optional[int] = None, _prepare_only: bool = False):
    """Prepare and atomically replace ``path`` with ``text``."""
    prepared = prepare_atomic_write(path, text, mode=mode)
    if _prepare_only:
        return prepared
    try:
        commit_prepared_write(prepared)
    except BaseException:
        _discard_prepared(prepared)
        raise


def _current_mode(path) -> Optional[int]:
    try:
        return os.stat(str(path)).st_mode & 0o777
    except OSError:
        return None


def _target_identity(path) -> Optional[tuple]:
    """Stable-enough identity for the final in-lock replacement gate."""
    try:
        info = os.lstat(str(path))
    except OSError:
        return None
    return (
        getattr(info, "st_dev", None),
        getattr(info, "st_ino", None),
        getattr(info, "st_file_attributes", None),
    )


def safe_replace(
    path,
    text: str,
    *,
    validator: Optional[Callable[[str], None]] = None,
    expected_digest: Optional[Union[str, _ExpectedAbsent]] = None,
    backup: bool = True,
    before_replace_hook: Optional[Callable[[Path], None]] = None,
    terminal_validator: Optional[Callable[[Path], None]] = None,
    after_terminal_gate_hook: Optional[Callable[[Path], None]] = None,
    post_validator: Optional[Callable[[str], None]] = None,
) -> WriteReceipt:
    """Replace a config file's contents, or leave it exactly as it was.

    ``expected_digest`` closes the gap between inspection and write: a
    plan is built from the file as it was READ, and the user may edit it
    in their editor while deciding. Writing the merged result then would
    silently discard their edit, so a changed digest aborts instead.

    ``expected_digest=None`` intentionally disables this generic precondition.
    The ``EXPECTED_ABSENT`` sentinel instead requires the target to remain
    absent at both the initial and final write gates.

    On post-write validation failure the backup is restored and
    :class:`ContentValidationError` is raised with ``rolled_back=True``.
    """
    target = Path(path)
    assert_writable_target(target)

    # One lock for the whole read-modify-write, matching the registry's
    # discipline. Without it, two `connect` runs can both read the same
    # config, both merge, and the later write erases the earlier one.
    with interprocess_lock(str(target)):
        existed = target.is_file()
        original: Optional[str] = None
        digest_before: Optional[str] = None
        if existed:
            original = read_bounded_text(target)
            digest_before = digest_text(original)
        original_identity = _target_identity(target) if existed else None
        if expected_digest is EXPECTED_ABSENT and existed:
            raise PreconditionError(
                "configuration was created since it was inspected; re-run the plan"
            )
        if (
            expected_digest is not None
            and expected_digest is not EXPECTED_ABSENT
            and digest_before != expected_digest
        ):
            raise PreconditionError(
                "configuration changed since it was inspected; re-run the plan"
            )

        if validator is not None:
            try:
                validator(text)
            except Exception as exc:
                raise ContentValidationError(
                    f"refusing to write invalid content: {exc}", rolled_back=False
                ) from exc

        backup_path = create_backup(target) if (backup and existed) else None
        try:
            # Bind the backup's exact bytes while the transaction lock is
            # still held. The caller must never hash this provenance after
            # safe_replace returns, when an external writer can race it.
            backup_digest = (
                digest_bytes(backup_path.read_bytes())
                if backup_path is not None
                else None
            )
        except BaseException:
            _discard_backup(backup_path)
            raise
        mode = _current_mode(target) if existed else None

        prepared: Optional[_PreparedWrite] = None
        try:
            # All expensive payload preparation happens before the terminal
            # authority/target gate. The final gate is intentionally followed
            # only by a commit primitive and deterministic test hook.
            prepared = atomic_write_text(target, text, mode=mode, _prepare_only=True)
            assert_writable_target(target)
            if before_replace_hook is not None:
                before_replace_hook(target)
            if terminal_validator is not None:
                terminal_validator(target)
            assert_writable_target(target)
            if expected_digest is EXPECTED_ABSENT:
                if target.is_file():
                    raise PreconditionError(
                        "configuration was created immediately before replacement; re-run the plan"
                    )
            elif expected_digest is not None:
                if not target.is_file():
                    raise PreconditionError(
                        "configuration was deleted immediately before replacement; re-run the plan"
                    )
                current_before_replace = read_bounded_text(target)
                if digest_text(current_before_replace) != expected_digest:
                    raise PreconditionError(
                        "configuration changed immediately before replacement; re-run the plan"
                    )
            if original_identity is not None and _target_identity(target) != original_identity:
                raise PreconditionError(
                    "configuration target identity changed immediately before replacement; re-run the plan"
                )
            if after_terminal_gate_hook is not None:
                after_terminal_gate_hook(target)
            commit_prepared_write(
                prepared, conditional_create=expected_digest is EXPECTED_ABSENT
            )
            prepared = None
        except BaseException:
            _discard_prepared(prepared)
            # No target replacement occurred on a precondition failure, so
            # the backup is redundant noise and must not become a recovery
            # point for a write that was refused.
            _discard_backup(backup_path)
            raise
        candidate_digest: Optional[str] = None
        candidate_identity: Optional[tuple] = None
        try:
            written = read_bounded_text(target)
            candidate_digest = digest_text(written)
            candidate_identity = _target_identity(target)
            if validator is not None:
                validator(written)
            if post_validator is not None:
                post_validator(written)
            digest_after = candidate_digest
        except Exception as exc:
            restored = _restore(
                backup_path,
                target,
                existed=existed,
                original=original,
                mode=mode,
                expected_current_digest=candidate_digest,
                expected_current_identity=candidate_identity,
                expected_backup_digest=backup_digest,
            )
            raise ContentValidationError(
                f"post-write validation failed: {exc}", rolled_back=restored
            ) from exc

        return WriteReceipt(
            target=target,
            backup_path=backup_path,
            digest_before=digest_before,
            digest_after=digest_after,
            created=not existed,
            backup_digest=backup_digest,
        )


def _discard_backup(backup_path: Optional[Path]) -> None:
    if backup_path is None:
        return
    with contextlib.suppress(OSError):
        os.unlink(str(backup_path))


def _prepare_atomic_copy(source: Path, target: Path) -> _PreparedWrite:
    """Prepare a backup payload before rollback's terminal target gate."""
    directory = target.parent
    handle, temp_name = tempfile.mkstemp(
        dir=str(directory), prefix=".relinkra-restore-", suffix=".tmp"
    )
    try:
        with os.fdopen(handle, "wb") as stream:
            with open(str(source), "rb") as reader:
                shutil.copyfileobj(reader, stream)
            stream.flush()
            os.fsync(stream.fileno())
        with contextlib.suppress(OSError, NotImplementedError):
            shutil.copymode(str(source), temp_name)
        return _PreparedWrite(target=target, temp=Path(temp_name))
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp_name)
        raise


def _restore(
    backup_path: Optional[Path],
    target: Path,
    *,
    existed: bool,
    original: Optional[str],
    mode: Optional[int],
    expected_current_digest: Optional[str],
    expected_current_identity: Optional[tuple],
    expected_backup_digest: Optional[str],
) -> bool:
    """Restore only while the target still contains Relinkra's candidate.

    Preparation is deliberately completed before the final candidate gate.
    If an external writer changed the post-write target, rollback refuses and
    leaves that newer evidence in place instead of overwriting it.
    """
    expected_original_digest = digest_text(original) if original is not None else None

    def _matches_original() -> bool:
        if not existed:
            return not target.exists()
        if expected_original_digest is None:
            return False
        try:
            return digest_text(read_bounded_text(target)) == expected_original_digest
        except (OSError, SafeWriteError):
            return False

    def _candidate_still_present() -> bool:
        if expected_current_digest is None:
            return False
        try:
            if digest_text(read_bounded_text(target)) != expected_current_digest:
                return False
            if (
                expected_current_identity is not None
                and _target_identity(target) != expected_current_identity
            ):
                return False
            return True
        except (OSError, SafeWriteError):
            return False

    prepared: Optional[_PreparedWrite] = None
    try:
        if backup_path is not None and backup_path.exists():
            backup_bytes = backup_path.read_bytes()
            if expected_backup_digest and digest_bytes(backup_bytes) != expected_backup_digest:
                return False
            prepared = _prepare_atomic_copy(backup_path, target)
        elif original is not None:
            prepared = prepare_atomic_write(target, original, mode=mode)

        if not _candidate_still_present():
            return False
        if prepared is not None:
            commit_prepared_write(prepared)
            prepared = None
        else:
            # The original state was absence. The candidate gate above is
            # the only authorization for this unlink.
            os.unlink(str(target))
        return _matches_original()
    except (OSError, SafeWriteError):
        return False
    finally:
        _discard_prepared(prepared)
