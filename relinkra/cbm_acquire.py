"""Relinkra-managed CBM acquisition (R5H.1).

``relinkra cbm setup`` installs the CERTIFIED codebase-memory-mcp release
into the per-user, Relinkra-managed location so normal users never
configure a binary path:

    <data_root>/backends/cbm/<version>/codebase-memory-mcp[.exe]

Invariants (provenance BEFORE execution is the product-wide rule; this
module never weakens it):

- Only the pinned release is ever acquired: the asset URL is derived
  deterministically from the certified tag and platform, never from a
  floating ``latest``.
- A downloaded (or ``--from-file``) archive is SHA-256 verified against
  the pinned release digest BEFORE it is opened; the extracted
  executable is SHA-256 verified against the pinned binary digest
  BEFORE it is ever executed.
- The version probe is the only execution here, and it runs only after
  both digests match; the parsed version must classify as certified.
- Activation is atomic: the new binary is staged in a sibling temp
  directory on the same filesystem, fully verified, and only then moved
  into place under an interprocess lock. A pre-existing installation —
  even a corrupt one — is replaced only after the new binary is fully
  verified, and is left untouched on any failure (the runtime SHA gate
  keeps refusing it either way).
- Runtime trust never depends on the provenance record written here;
  the SHA-256 gates in ``cbm_support``/``cbm_adapter`` stay
  authoritative. The record is audit evidence for doctor and forensics.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from typing import Callable, Mapping, Optional, Tuple

from . import cbm_support
from .identity import _utcnow
from .memory import sanitize_error
from .registry import interprocess_lock

#: Setup outcomes (product_cli maps these to exit codes and copy).
STATUS_INSTALLED = "INSTALLED"
STATUS_ALREADY_INSTALLED = "ALREADY_INSTALLED"
STATUS_NOT_CERTIFIED = "NOT_CERTIFIED"
STATUS_FAILED = "FAILED"

#: Bounded network and probe budgets: acquisition must never hang a CLI.
DOWNLOAD_TIMEOUT = 120.0
PROBE_TIMEOUT = 15.0

#: A release archive is tens of megabytes; anything past this cap is not
#: the asset we pinned and is refused instead of buffered forever.
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024

#: Provenance evidence written next to the installed binary. Read by
#: doctor/audits; never consulted for trust decisions.
PROVENANCE_FILE = "relinkra-cbm-provenance.json"


class CBMAcquireError(Exception):
    """Honest, actionable acquisition failure (never a silent fallback)."""


@dataclass(frozen=True)
class CBMSetupResult:
    """Structured outcome of :func:`setup_cbm`."""

    status: str
    managed_path: Optional[str] = None
    detail: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "managed_path": self.managed_path,
            "detail": self.detail,
            "error": self.error,
        }


def release_asset_url(record: Mapping[str, str], tag: str) -> str:
    """Derive the official asset URL from the pinned release tag.

    Deterministic from ``record['release_url']`` (the tag page) and the
    upstream asset naming convention — never a floating ``latest``.
    """
    repo, separator, tag_ref = record["release_url"].rpartition("/releases/tag/")
    if not separator or not repo or not tag_ref:
        raise CBMAcquireError("certified record carries no parseable release tag URL")
    return f"{repo}/releases/download/{tag_ref}/codebase-memory-mcp-{tag}.zip"


def _default_downloader(url: str, destination: str) -> None:
    """Stream ``url`` into ``destination`` (a temp path we chose)."""
    request = urllib.request.Request(
        url, headers={"User-Agent": "relinkra-cbm-setup"}
    )
    try:
        with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT) as response:
            total = 0
            with open(destination, "wb") as handle:
                while True:
                    chunk = response.read(1 << 20)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_ARCHIVE_BYTES:
                        raise CBMAcquireError(
                            "download exceeds the maximum archive size"
                        )
                    handle.write(chunk)
    except CBMAcquireError:
        raise
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise CBMAcquireError(
            f"could not download the certified release: {exc}"
        ) from exc


def _default_runner(executable: str) -> str:
    """The version probe: ``[exe, --version]``, the adapter's own probe."""
    try:
        result = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=PROBE_TIMEOUT,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CBMAcquireError("version probe timed out") from exc
    except OSError as exc:
        raise CBMAcquireError(f"version probe could not run: {exc}") from exc
    if result.returncode != 0:
        raise CBMAcquireError("version probe exited non-zero")
    return f"{result.stdout or ''}\n{result.stderr or ''}"


def _sha256_path(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _installed_binary_valid(
    target: str, expected_sha256: str, runner: Callable[[str], str]
) -> bool:
    """True only when the managed binary hashes to the pin AND probes
    certified. The probe executes the binary immediately after its hash
    matched — the same provenance-before-execution order every other
    Relinkra execution path follows."""
    if not os.path.isfile(target):
        return False
    actual = cbm_support._sha256_file(target)
    if not actual or actual.lower() != expected_sha256.lower():
        return False
    try:
        output = runner(target)
    except Exception:
        return False
    return cbm_support.classify_version(output) == cbm_support.VERSION_CERTIFIED


def _member_is_safe(name: str) -> bool:
    """Reject absolute paths and ``..`` traversal in archive members.

    The destination is always a path WE chose, so a hostile name could
    never redirect the write — but a malicious archive is refused on
    sight rather than sanitized into compliance.
    """
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        return False
    return ".." not in normalized.split("/")


def _member_basename(name: str) -> str:
    return name.replace("\\", "/").rsplit("/", 1)[-1]


def _extract_certified_exe(
    archive_path: str, exe_name: str, staging_exe: str
) -> None:
    """Extract ONLY the expected executable member into the staging path.

    The archive digest has already been verified before this is called.
    Member names are never trusted as destinations: the member is
    selected by basename equality and written to ``staging_exe``.
    """
    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = [
                info
                for info in archive.infolist()
                if not info.is_dir() and _member_basename(info.filename) == exe_name
            ]
            for info in members:
                if not _member_is_safe(info.filename):
                    raise CBMAcquireError(
                        "archive contains an unsafe member path; refusing to extract"
                    )
            if not members:
                raise CBMAcquireError(
                    f"archive contains no '{exe_name}' member"
                )
            if len(members) > 1:
                raise CBMAcquireError(
                    f"archive contains multiple '{exe_name}' members; refusing to guess"
                )
            with archive.open(members[0]) as source:
                with open(staging_exe, "wb") as destination:
                    shutil.copyfileobj(source, destination, 1 << 20)
    except zipfile.BadZipFile as exc:
        raise CBMAcquireError("release archive is not a valid zip") from exc


def _stage_from_local_file(
    from_file: str, exe_name: str, staging_exe: str, expected: Mapping[str, str]
) -> Tuple[Optional[str], str]:
    """Offline path: stage a local release archive or bare executable.

    Same verification semantics as the download path: the archive digest
    is checked BEFORE it is opened, a bare executable's digest BEFORE it
    is copied. Returns ``(archive_sha256_or_None, source_label)``.
    """
    source = os.path.abspath(os.path.expanduser(from_file))
    if not os.path.isfile(source):
        raise CBMAcquireError(f"--from-file source not found: {from_file}")
    file_sha = _sha256_path(source)
    # The digest ALONE decides what the file is; the zip sniffer only
    # confirms structure afterwards, so nothing parses the file before
    # its bytes have matched a certified pin.
    if file_sha.lower() == str(expected.get("release_zip_sha256") or "").lower():
        if not zipfile.is_zipfile(source):
            raise CBMAcquireError(
                "archive matches the certified release digest but is not "
                "a readable zip"
            )
        _extract_certified_exe(source, exe_name, staging_exe)
        return file_sha, f"file:{source}"
    if file_sha.lower() == str(expected.get("sha256") or "").lower():
        shutil.copyfile(source, staging_exe)
        return None, f"file:{source}"
    raise CBMAcquireError(
        "--from-file hash matches neither the certified release archive "
        "nor the certified executable pin"
    )


def _write_provenance(
    version_dir: str,
    *,
    version: str,
    tag: str,
    expected_sha256: str,
    actual_sha256: str,
    archive_sha256: Optional[str],
    source: str,
    installed_path: str,
) -> None:
    record = {
        "product": "relinkra",
        "backend": "codebase-memory-mcp",
        "version": version,
        "platform_tag": tag,
        "expected_sha256": expected_sha256,
        "actual_sha256": actual_sha256,
        "archive_sha256": archive_sha256,
        "source": source,
        "installed_path": installed_path,
        "installed_at": _utcnow(),
    }
    provenance_path = os.path.join(version_dir, PROVENANCE_FILE)
    with open(provenance_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def _activate(
    staging_version_dir: str,
    backends_dir: str,
    version: str,
    target: str,
    expected_sha256: str,
    runner: Callable[[str], str],
) -> str:
    """Move the fully verified staging directory into place, atomically.

    Serialized by an interprocess lock on ``<backends>/cbm/.setup.lock``:
    concurrent setups line up, and the loser re-checks idempotency after
    acquiring the lock. A pre-existing version directory is renamed aside
    and restored if the activation move itself fails.
    """
    final_version_dir = os.path.join(backends_dir, version)
    with interprocess_lock(os.path.join(backends_dir, ".setup")):
        if _installed_binary_valid(target, expected_sha256, runner):
            return STATUS_ALREADY_INSTALLED
        backup = None
        if os.path.lexists(final_version_dir):
            for attempt in range(100):
                candidate = f"{final_version_dir}.setup-old-{os.getpid()}-{attempt}"
                if not os.path.lexists(candidate):
                    backup = candidate
                    break
            if backup is None:
                raise CBMAcquireError("could not set aside the existing installation")
            os.replace(final_version_dir, backup)
        try:
            os.replace(staging_version_dir, final_version_dir)
        except OSError as exc:
            if backup is not None:
                try:
                    os.replace(backup, final_version_dir)
                except OSError:
                    pass
            raise CBMAcquireError(
                f"could not activate the staged binary: {exc}"
            ) from exc
        if backup is not None:
            shutil.rmtree(backup, ignore_errors=True)
    return STATUS_INSTALLED


def setup_cbm(
    *,
    from_file: Optional[str] = None,
    data_root: Optional[str] = None,
    environ: Optional[Mapping[str, str]] = None,
    downloader: Optional[Callable[[str, str], None]] = None,
    runner: Optional[Callable[[str], str]] = None,
) -> CBMSetupResult:
    """Install the certified CBM binary into the Relinkra-managed location.

    Idempotent: an already-installed, fully verified binary is reported
    as ``ALREADY_INSTALLED`` without touching the network. ``from_file``
    is the documented offline path (a local release archive or bare
    executable, verified with the same pinned digests). ``downloader``
    and ``runner`` are test seams; the defaults stream the official
    asset with urllib and probe the binary with subprocess.
    """
    env = environ if environ is not None else os.environ
    run = runner or _default_runner
    tag = cbm_support.platform_tag()
    record = cbm_support.CERTIFIED_CBM_BINARIES.get(tag)
    if record is None:
        certified = ", ".join(sorted(cbm_support.CERTIFIED_CBM_BINARIES)) or "none"
        return CBMSetupResult(
            status=STATUS_NOT_CERTIFIED,
            detail=(
                f"no certified CBM release for platform {tag}; Relinkra "
                f"auto-installs only platforms with certified provenance "
                f"(currently: {certified})"
            ),
        )
    version = cbm_support.CERTIFIED_CBM_VERSION
    root_dir = data_root or cbm_support.relinkra_data_root(env)
    target = cbm_support.managed_cbm_binary_path(version, tag, data_root=root_dir)
    expected_exe_sha = str(record["sha256"])

    # Idempotency FIRST: never download what is already installed and
    # verified. A present-but-invalid binary falls through to reacquire;
    # it is replaced only after the new one is fully verified.
    if _installed_binary_valid(target, expected_exe_sha, run):
        return CBMSetupResult(
            status=STATUS_ALREADY_INSTALLED,
            managed_path=target,
            detail=f"certified {version} binary already installed and verified",
        )
    try:
        return _install(
            tag=tag,
            record=record,
            version=version,
            root_dir=root_dir,
            target=target,
            from_file=from_file,
            downloader=downloader or _default_downloader,
            runner=run,
        )
    except CBMAcquireError as exc:
        return CBMSetupResult(
            status=STATUS_FAILED,
            error=sanitize_error(str(exc)),
            detail=(
                "No existing installation was modified. Check the source "
                "(network or --from-file) and retry; see docs/cbm-backend.md."
            ),
        )
    except Exception as exc:  # never leak a traceback through the product surface
        return CBMSetupResult(
            status=STATUS_FAILED,
            error=sanitize_error(str(exc)) or "CBM setup failed",
            detail="No existing installation was modified; see docs/cbm-backend.md.",
        )


def _install(
    *,
    tag: str,
    record: Mapping[str, str],
    version: str,
    root_dir: str,
    target: str,
    from_file: Optional[str],
    downloader: Callable[[str, str], None],
    runner: Callable[[str], str],
) -> CBMSetupResult:
    expected_exe_sha = str(record["sha256"])
    backends_dir = os.path.join(root_dir, "backends", "cbm")
    os.makedirs(backends_dir, exist_ok=True)
    # Same filesystem as the target, so the final os.replace is atomic.
    staging = tempfile.mkdtemp(
        prefix=f".setup-tmp-{os.getpid()}-", dir=backends_dir
    )
    try:
        exe_name = os.path.basename(target)
        staging_version_dir = os.path.join(staging, version)
        os.makedirs(staging_version_dir)
        staging_exe = os.path.join(staging_version_dir, exe_name)

        if from_file:
            archive_sha, source_label = _stage_from_local_file(
                from_file, exe_name, staging_exe, record
            )
        else:
            source_label = release_asset_url(record, tag)
            archive_path = os.path.join(staging, "release.zip")
            downloader(source_label, archive_path)
            archive_sha = _sha256_path(archive_path)
            # Verify the archive BEFORE opening it: an unverified zip is
            # never parsed.
            expected_zip = str(record.get("release_zip_sha256") or "").lower()
            if archive_sha.lower() != expected_zip:
                raise CBMAcquireError(
                    "downloaded archive hash does not match the certified "
                    "release pin; refusing to open it"
                )
            _extract_certified_exe(archive_path, exe_name, staging_exe)

        actual_exe_sha = _sha256_path(staging_exe)
        if actual_exe_sha.lower() != expected_exe_sha.lower():
            raise CBMAcquireError(
                "extracted executable hash does not match the certified "
                "binary pin; refusing to install"
            )
        if os.name == "posix":
            os.chmod(staging_exe, 0o755)

        # The ONLY execution in acquisition, and only after every digest
        # matched: the staged binary must probe as the certified version.
        probe_output = runner(staging_exe)
        if cbm_support.classify_version(probe_output) != cbm_support.VERSION_CERTIFIED:
            raise CBMAcquireError(
                "staged binary does not probe as the certified "
                f"{version} release; refusing to install"
            )

        _write_provenance(
            staging_version_dir,
            version=version,
            tag=tag,
            expected_sha256=expected_exe_sha,
            actual_sha256=actual_exe_sha,
            archive_sha256=archive_sha,
            source=source_label,
            installed_path=target,
        )
        status = _activate(
            staging_version_dir, backends_dir, version, target, expected_exe_sha, runner
        )
        detail = (
            f"certified {version} binary already installed and verified"
            if status == STATUS_ALREADY_INSTALLED
            else f"certified {version} binary installed and SHA-256 verified"
        )
        return CBMSetupResult(status=status, managed_path=target, detail=detail)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
