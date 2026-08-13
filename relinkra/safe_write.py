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
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

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


class ContentValidationError(SafeWriteError):
    """Raised when content fails validation.

    ``rolled_back`` distinguishes the two very different situations this
    covers: rejected before anything was touched, or written, found bad,
    and restored. The caller's message to the user differs completely.
    """

    def __init__(self, message: str, *, rolled_back: bool = False):
        super().__init__(message)
        self.rolled_back = rolled_back


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


def atomic_write_text(path, text: str, *, mode: Optional[int] = None) -> None:
    """Write ``text`` to ``path`` atomically, in the same directory.

    ``newline=""`` keeps Python's universal-newline translation out of
    the way: the caller already decided the line endings (see
    :func:`detect_newline`), and a second translation on Windows would
    turn a deliberate ``\\r\\n`` into ``\\r\\r\\n``.
    """
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
        os.replace(temp_name, str(target))
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp_name)
        raise
    _fsync_dir(directory)


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
    expected_digest: Optional[str] = None,
    backup: bool = True,
    before_replace_hook: Optional[Callable[[Path], None]] = None,
) -> WriteReceipt:
    """Replace a config file's contents, or leave it exactly as it was.

    ``expected_digest`` closes the gap between inspection and write: a
    plan is built from the file as it was READ, and the user may edit it
    in their editor while deciding. Writing the merged result then would
    silently discard their edit, so a changed digest aborts instead.

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
        if expected_digest is not None and digest_before != expected_digest:
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

        try:
            # Re-checked at the LAST possible moment. The check before
            # the lock is a cheap early rejection, but it runs several
            # I/O steps before the replace — long enough for the target
            # to be swapped for a symlink in between, which is exactly
            # the substitution the check exists to refuse. Inside the
            # try so a refusal here also discards the backup.
            assert_writable_target(target)
            # Deterministic test hook: callers can model an external edit
            # between backup creation and the last gate without relying on
            # timing. It runs before the final identity/digest check.
            if before_replace_hook is not None:
                before_replace_hook(target)
            assert_writable_target(target)
            if expected_digest is not None:
                current_before_replace = read_bounded_text(target)
                if digest_text(current_before_replace) != expected_digest:
                    raise PreconditionError(
                        "configuration changed immediately before replacement; re-run the plan"
                    )
            if original_identity is not None and _target_identity(target) != original_identity:
                raise PreconditionError(
                    "configuration target identity changed immediately before replacement; re-run the plan"
                )
            atomic_write_text(target, text, mode=mode)
        except BaseException:
            # Nothing was replaced (atomic_write_text either replaced or
            # raised before replacing), so the backup is redundant noise.
            _discard_backup(backup_path)
            raise

        try:
            written = read_bounded_text(target)
            if validator is not None:
                validator(written)
            digest_after = digest_text(written)
        except Exception as exc:
            restored = _restore(
                backup_path,
                target,
                existed=existed,
                original=original,
                mode=mode,
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


def _atomic_copy(source: Path, target: Path) -> None:
    """Replace ``target`` with ``source``'s bytes, atomically.

    Rollback has to be at least as safe as the write it undoes. A plain
    ``copy2`` onto the live file is a chunked read/write: interrupt it
    and the target is neither the original nor the new content — exactly
    the torn state the forward path uses a temp file to avoid. So the
    restore takes the same route.
    """
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
        os.replace(temp_name, str(target))
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp_name)
        raise
    _fsync_dir(directory)


def _restore(
    backup_path: Optional[Path],
    target: Path,
    *,
    existed: bool,
    original: Optional[str],
    mode: Optional[int],
) -> bool:
    """Put the target back. Returns whether the original state is restored.

    Three recovery routes, in order of fidelity:

    1. a backup file, copied back atomically;
    2. the original text, which ``safe_replace`` already read to compute
       the precondition digest — this is what covers ``backup=False``,
       where there is no backup file but the original content is still
       known, and without it that combination would leave the rejected
       content on disk;
    3. deletion, when the file did not exist before — then the correct
       original state is ABSENT, not a half-valid file.
    """
    expected_digest = digest_text(original) if original is not None else None

    def _matches_original() -> bool:
        if not existed:
            return not target.exists()
        if expected_digest is None:
            return False
        try:
            return digest_text(read_bounded_text(target)) == expected_digest
        except (OSError, SafeWriteError):
            return False

    try:
        if backup_path is not None and backup_path.exists():
            _atomic_copy(backup_path, target)
            if _matches_original():
                return True
        if original is not None:
            atomic_write_text(target, original, mode=mode)
            return _matches_original()
        if not existed:
            with contextlib.suppress(OSError):
                os.unlink(str(target))
            return _matches_original()
    except OSError:
        return False
    return False
