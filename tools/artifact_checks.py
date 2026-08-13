"""Artifact content contract enforcement for Relinkra distributions (R5B).

Importable and runnable as a CLI. Verifies that a built wheel or sdist
contains exactly what the packaging contract allows — the ``relinkra``
package plus its dist-info metadata, nothing else — and none of the
state, junk, or secret-shaped paths that must never ship.

CLI:

    python tools/artifact_checks.py <artifact> [<artifact>...]

Prints one JSON object per artifact plus a summary; exits 1 when any
artifact reports problems. JSON output is portable: paths are reported
as basenames only.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import sys
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import relinkra

#: Path segments forbidden in ANY distribution artifact.
_FORBIDDEN_SEGMENTS = {
    "tests",
    "tools",
    ".windsurf",
    ".relinkra",
    ".codebase-memory",
    ".upstream",
    ".github",
    ".git",
    "build",
    "dist",
    "__pycache__",
}

#: Segments additionally allowed in an sdist (sources legitimately ship
#: the test suite and the generated egg-info).
_SDIST_ALLOWED_SEGMENTS = {"tests", "tools"}

#: Traversal markers are forbidden even when they do not escape the archive
#: root after normalization.
_TRAVERSAL_SEGMENTS = {".", ".."}

#: Secret-shaped basenames that must never ship.
_SECRET_EXACT = {".env"}
_SECRET_GLOBS = ("*.pem", "*.key", "id_rsa*", "*.p12", "*.pfx")

_ENTRY_POINTS = (
    "relinkra = relinkra.product_cli:main",
    "relinkra-mcp = relinkra.mcp_cli:main",
)


@dataclass
class ArtifactReport:
    """The verdict for one inspected artifact."""

    path: str
    kind: str
    sha256: str
    entries: int = 0
    problems: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems

    def to_dict(self) -> dict:
        return {
            "path": os.path.basename(self.path),
            "kind": self.kind,
            "sha256": self.sha256,
            "entries": self.entries,
            "ok": self.ok,
            "problems": list(self.problems),
        }


def sha256_file(path) -> str:
    """The hex SHA-256 of a file's bytes."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _segments(member: str) -> List[str]:
    return [part for part in member.replace("\\", "/").split("/") if part]


def _forbidden_problems(
    names, *, allowed_segments=frozenset()
) -> List[str]:
    """Flag forbidden segments, bytecode, backups and secret-shaped names."""
    problems: List[str] = []
    forbidden = _FORBIDDEN_SEGMENTS - set(allowed_segments)
    for name in names:
        segments = _segments(name)
        basename = segments[-1] if segments else ""
        for segment in segments:
            if segment in _TRAVERSAL_SEGMENTS:
                problems.append(
                    f"path traversal segment {segment!r} in {name!r}"
                )
                break
            if segment in forbidden:
                problems.append(f"forbidden path segment {segment!r} in {name!r}")
                break
        if name.endswith(".pyc"):
            problems.append(f"bytecode member {name!r}")
        if ".relinkra-backup" in name or fnmatch.fnmatch(
            basename, "*.relinkra-backup*"
        ):
            problems.append(f"backup artifact member {name!r}")
        if basename in _SECRET_EXACT or any(
            fnmatch.fnmatch(basename, pattern) for pattern in _SECRET_GLOBS
        ):
            problems.append(f"secret-shaped member {name!r}")
    return problems


def _parse_wheel_filename(filename: str):
    """(distribution, version) from a wheel filename, or None."""
    if not filename.endswith(".whl"):
        return None
    parts = filename[: -len(".whl")].split("-")
    if len(parts) < 2:
        return None
    return parts[0], parts[1]


def _parse_sdist_filename(filename: str) -> Optional[str]:
    """The version from a ``relinkra-<version>.tar.gz`` filename, or None."""
    if not filename.endswith(".tar.gz"):
        return None
    stem = filename[: -len(".tar.gz")]
    prefix = "relinkra-"
    if not stem.startswith(prefix):
        return None
    return stem[len(prefix):]


def expected_artifact_filename(kind: str) -> str:
    """Return the one Relinkra artifact filename expected for ``kind``."""
    version = relinkra.__version__
    if kind == "wheel":
        return f"relinkra-{version}-py3-none-any.whl"
    if kind == "sdist":
        return f"relinkra-{version}.tar.gz"
    raise ValueError(f"unknown artifact kind: {kind!r}")


def _artifact_candidates(directory: Path, kind: str) -> List[Path]:
    suffix = ".whl" if kind == "wheel" else ".tar.gz"
    return sorted(
        path for path in directory.rglob(f"*{suffix}") if path.is_file()
    )


def _validate_artifact_identity(path: Path, kind: str) -> None:
    expected = expected_artifact_filename(kind)
    if path.name != expected:
        raise ValueError(
            f"expected {kind} filename {expected!r}, found {path.name!r}"
        )


def _manifest_digest(manifest: Path, basename: str) -> str:
    matches = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        digest, recorded_name = parts
        if recorded_name.lstrip(" *") == basename:
            matches.append(digest)
    if len(matches) != 1:
        raise ValueError(
            f"checksum manifest must contain exactly one entry for "
            f"{basename!r}; found {len(matches)}"
        )
    digest = matches[0]
    if len(digest) != 64:
        raise ValueError(f"invalid SHA256 digest for {basename!r}")
    try:
        int(digest, 16)
    except ValueError as exc:
        raise ValueError(f"invalid SHA256 digest for {basename!r}") from exc
    return digest.lower()


def select_exact_artifact(directory, kind: str, checksum_manifest=None) -> Path:
    """Select one recursively discovered, identity-checked build artifact.

    A download directory must contain exactly one wheel or sdist candidate.
    When supplied, the build job's SHA256SUMS.txt is also authoritative for
    the selected basename and digest.
    """
    directory = Path(directory)
    if kind not in ("wheel", "sdist"):
        raise ValueError(f"unknown artifact kind: {kind!r}")
    if not directory.is_dir():
        raise ValueError(f"artifact directory does not exist: {directory}")
    candidates = _artifact_candidates(directory, kind)
    if len(candidates) != 1:
        names = ", ".join(str(path) for path in candidates) or "none"
        raise ValueError(
            f"expected exactly one {kind} under {directory}; "
            f"found {len(candidates)}: {names}"
        )
    selected = candidates[0]
    _validate_artifact_identity(selected, kind)
    if checksum_manifest is not None:
        manifest = Path(checksum_manifest)
        if not manifest.is_file():
            raise ValueError(f"checksum manifest does not exist: {manifest}")
        expected_digest = _manifest_digest(manifest, selected.name)
        actual_digest = sha256_file(selected)
        if actual_digest != expected_digest:
            raise ValueError(
                f"SHA256 mismatch for {selected.name!r}: "
                f"expected {expected_digest}, got {actual_digest}"
            )
    return selected


def inspect_wheel(path) -> ArtifactReport:
    """Enforce the wheel content contract."""
    path = str(path)
    report = ArtifactReport(path=path, kind="wheel", sha256=sha256_file(path))
    expected_version = relinkra.__version__

    parsed = _parse_wheel_filename(os.path.basename(path))
    if parsed is None:
        report.problems.append("filename is not a parseable wheel name")
        dist_name, dist_version = "", ""
    else:
        dist_name, dist_version = parsed
        if dist_name != "relinkra":
            report.problems.append(f"wheel distribution name is {dist_name!r}")
        if dist_version != expected_version:
            report.problems.append(
                f"wheel version {dist_version!r} != relinkra.__version__ "
                f"{expected_version!r}"
            )

    dist_info = f"relinkra-{dist_version or expected_version}.dist-info"
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            report.entries = len(names)

            for name in names:
                top = _segments(name)[0] if _segments(name) else ""
                if top not in ("relinkra", dist_info):
                    report.problems.append(
                        f"member outside relinkra/ and {dist_info}/: {name!r}"
                    )

            if not any(
                len(_segments(name)) > 1
                and _segments(name)[0] == "relinkra"
                for name in names
            ):
                report.problems.append(
                    "wheel missing relinkra package member (metadata-only wheel)"
                )

            report.problems.extend(_forbidden_problems(names))

            def _read(member: str) -> Optional[str]:
                try:
                    with archive.open(member) as handle:
                        return handle.read().decode("utf-8", "replace")
                except KeyError:
                    return None

            entry_points = _read(f"{dist_info}/entry_points.txt")
            if entry_points is None:
                report.problems.append("missing dist-info entry_points.txt")
            else:
                for expected in _ENTRY_POINTS:
                    if expected not in entry_points:
                        report.problems.append(
                            f"entry_points.txt missing {expected!r}"
                        )

            metadata = _read(f"{dist_info}/METADATA")
            if metadata is None:
                report.problems.append("missing dist-info METADATA")
            else:
                meta_name = meta_version = None
                for line in metadata.splitlines():
                    if line.startswith("Name:"):
                        meta_name = line.split(":", 1)[1].strip()
                    elif line.startswith("Version:"):
                        meta_version = line.split(":", 1)[1].strip()
                    elif not line.strip():
                        break
                if meta_name != "relinkra":
                    report.problems.append(
                        f"METADATA Name is {meta_name!r}, expected 'relinkra'"
                    )
                if meta_version != expected_version:
                    report.problems.append(
                        f"METADATA Version {meta_version!r} != "
                        f"{expected_version!r}"
                    )

            if f"{dist_info}/RECORD" not in names:
                report.problems.append("missing dist-info RECORD")
    except zipfile.BadZipFile as exc:
        report.problems.append(f"not a readable zip archive: {exc}")

    return report


def inspect_sdist(path) -> ArtifactReport:
    """Enforce the sdist content contract."""
    path = str(path)
    report = ArtifactReport(path=path, kind="sdist", sha256=sha256_file(path))
    expected_version = relinkra.__version__

    version = _parse_sdist_filename(os.path.basename(path))
    if version is None:
        report.problems.append("filename is not relinkra-<version>.tar.gz")
    elif version != expected_version:
        report.problems.append(
            f"sdist version {version!r} != relinkra.__version__ "
            f"{expected_version!r}"
        )

    try:
        with tarfile.open(path, "r:gz") as archive:
            names = archive.getnames()
            report.entries = len(names)

            suffixes = {"/".join(_segments(name)) for name in names}
            if not any(s.endswith("pyproject.toml") for s in suffixes):
                report.problems.append("sdist missing pyproject.toml")
            if not any(s.endswith("README.md") for s in suffixes):
                report.problems.append("sdist missing README.md")
            if not any(s.endswith("relinkra/__init__.py") for s in suffixes):
                report.problems.append("sdist missing relinkra/__init__.py")

            report.problems.extend(
                _forbidden_problems(names, allowed_segments=_SDIST_ALLOWED_SEGMENTS)
            )
    except (tarfile.TarError, OSError) as exc:
        report.problems.append(f"not a readable tar.gz archive: {exc}")

    return report


def inspect_artifact(path) -> ArtifactReport:
    """Dispatch to the wheel or sdist inspector by extension."""
    name = os.path.basename(str(path))
    if name.endswith(".whl"):
        return inspect_wheel(path)
    if name.endswith(".tar.gz"):
        return inspect_sdist(path)
    report = ArtifactReport(path=str(path), kind="unknown", sha256=sha256_file(path))
    report.problems.append(f"unrecognized artifact extension: {name!r}")
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="artifact_checks",
        description=__doc__,
    )
    parser.add_argument("artifacts", nargs="*", help="wheel or sdist paths")
    parser.add_argument(
        "--select",
        choices=("wheel", "sdist"),
        help="select exactly one downloaded artifact of this kind",
    )
    parser.add_argument(
        "--artifact-dir",
        help="directory searched recursively with --select",
    )
    parser.add_argument(
        "--checksum-manifest",
        help="SHA256SUMS.txt from the build job, required by --select in CI",
    )
    args = parser.parse_args(argv)

    if args.select:
        if args.artifacts or not args.artifact_dir:
            parser.error("--select requires --artifact-dir and no artifacts")
        try:
            selected = select_exact_artifact(
                args.artifact_dir, args.select, args.checksum_manifest
            )
        except ValueError as exc:
            parser.error(str(exc))
        print(selected.resolve())
        return 0
    if not args.artifacts:
        parser.error("provide artifacts to inspect or use --select")

    reports = []
    for artifact in args.artifacts:
        report = inspect_artifact(artifact)
        reports.append(report)
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))

    failing = [report for report in reports if not report.ok]
    summary = {
        "artifacts": len(reports),
        "ok": len(reports) - len(failing),
        "failed": len(failing),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
