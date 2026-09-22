"""Strict action pin policy (M8) for workflow ``uses:`` references.

Every external ``uses:`` reference in a workflow must be pinned to a full
40-character lowercase commit SHA. The ``# vX.Y.Z`` version comment is
informational only; the SHA is authoritative. Local references (``./...``,
a local action or a local reusable workflow) are exempt. ``docker://``
container references are pinned by digest instead of by commit SHA, so
they are exempt only when they carry ``@sha256:<64 lowercase hex>``.

This module is stdlib-only. It is shared by ``tests/test_ci_hygiene.py``
(the policy test) and ``tools/release_check.py`` (the SECURITY gate
evidence scan).

The scanner fails closed: a ``uses:`` key whose value is not on the same
line (a bare ``uses:`` or ``- uses:``) is reported as a violation, because
a multi-line value cannot be verified by the bounded line scanner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional, Sequence, Tuple, Union

#: A block scalar header: ``key: |``, ``- key: >-``, ``key: |2 # note``.
_BLOCK_SCALAR_START = re.compile(
    r"^\s*(?:-\s+)?[A-Za-z0-9_.-]+:\s*[|>][+-]?\d*\s*(?:#.*)?$"
)

#: A real ``uses:`` key. Anchored so ``uses:`` embedded in a quoted string
#: or in ``run:`` script text is never mistaken for a workflow key.
_USES_KEY = re.compile(r"^\s*(?:-\s+)?uses:\s*(.+?)\s*$")

#: A ``uses:`` key with no inline value; a multi-line value would follow
#: on a more-indented line, which the bounded scanner cannot verify.
_USES_EMPTY = re.compile(r"^\s*(?:-\s+)?uses:\s*$")

#: A digest-pinned container reference: any image plus a full sha256 digest.
_DOCKER_DIGEST = re.compile(r".+@sha256:[0-9a-f]{64}")

#: The same digest shape in any case, used only to explain the uppercase
#: canonical-format rejection.
_DOCKER_DIGEST_ANY_CASE = re.compile(r".+@sha256:[0-9A-Fa-f]{64}")

#: The canonical commit pin: exactly 40 lowercase hex characters.
_FULL_SHA = re.compile(r"[0-9a-f]{40}")

#: Same shape in any case, used only to explain the uppercase rejection.
_ANY_CASE_SHA = re.compile(r"[0-9A-Fa-f]{40}")

_LOCAL_PREFIX = "./"
_CONTAINER_PREFIX = "docker://"


@dataclass(frozen=True)
class UsesViolation:
    """One unpinned or malformed ``uses:`` reference."""

    path: str
    line: int
    uses: str
    problem: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.uses} -> {self.problem}"


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _strip_value(raw: str) -> str:
    """Unquote a YAML scalar and drop its inline comment, if any."""
    value = raw.strip()
    if value[:1] in ("'", '"'):
        quote = value[0]
        end = value.find(quote, 1)
        if end != -1:
            return value[1:end]
        return value[1:]
    cut = value.find(" #")
    if cut != -1:
        value = value[:cut]
    return value.strip()


def iter_uses(text: str) -> Iterator[Tuple[int, str]]:
    """Yield ``(line_number, value)`` for real ``uses:`` keys, 1-based.

    Blank lines and full-line comments are skipped. Content inside block
    scalars (``run: |`` bodies and similar) is skipped by indentation:
    while inside a block scalar only more-indented lines are ignored, and
    normal processing resumes at the first line whose indent is not
    greater than the block scalar header's indent. A ``uses:`` key with no
    inline value yields an empty value so the policy fails closed.
    """
    block_indent: Optional[int] = None
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        indent = _indent(line)
        if block_indent is not None:
            if indent > block_indent:
                continue
            block_indent = None
        if line.lstrip().startswith("#"):
            continue
        if _BLOCK_SCALAR_START.match(line):
            block_indent = indent
            continue
        if _USES_EMPTY.match(line):
            yield number, ""
            continue
        match = _USES_KEY.match(line)
        if match:
            yield number, _strip_value(match.group(1))


def check_uses_reference(value: str) -> Optional[str]:
    """Return a problem string for an unpinned reference, else ``None``."""
    if value == "":
        return (
            "empty uses reference: the ref must be on the same line as "
            "uses: so it can be verified (multi-line values are "
            "unverifiable and rejected)"
        )
    if value.startswith(_LOCAL_PREFIX):
        if ".." in value[len(_LOCAL_PREFIX):].split("/"):
            return (
                f"{value!r}: local references must resolve inside the "
                "repository (no '..' segments)"
            )
        return None
    # Container references are pinned by digest, not by commit SHA: image
    # tags are mutable, so only docker://IMAGE@sha256:<64 lowercase hex>
    # is accepted.
    if value.startswith(_CONTAINER_PREFIX):
        image = value[len(_CONTAINER_PREFIX):]
        if _DOCKER_DIGEST.fullmatch(image):
            return None
        if _DOCKER_DIGEST_ANY_CASE.fullmatch(image):
            return (
                f"{value!r}: uppercase hex is deliberately rejected; use "
                "the canonical docker://IMAGE@sha256:<64 lowercase hex> "
                "digest"
            )
        return (
            f"{value!r}: container references must be digest-pinned as "
            "docker://IMAGE@sha256:<64 lowercase hex>"
        )
    if "@" not in value:
        return (
            f"{value!r}: missing @REF; external actions and reusable "
            "workflows must be pinned to a full 40-char lowercase commit "
            "SHA"
        )
    repo_path, _, ref = value.rpartition("@")
    parts = repo_path.split("/")
    if len(parts) < 2 or not all(parts):
        return (
            f"{value!r}: not an owner/repo reference, so it cannot be "
            "pinned to a commit SHA"
        )
    if any(part in (".", "..") for part in parts):
        return (
            f"{value!r}: path segments '.' and '..' are not valid in an "
            "owner/repo reference"
        )
    if _FULL_SHA.fullmatch(ref):
        return None
    if _ANY_CASE_SHA.fullmatch(ref):
        return (
            f"{value!r}: uppercase hex is deliberately rejected; use the "
            "canonical 40-char lowercase commit SHA"
        )
    return (
        f"{value!r}: ref {ref!r} is not a full 40-char lowercase commit "
        "SHA; mutable tags and branches (v4, main, master, v1.2.3) are "
        "rejected"
    )


def scan_text(text: str, path: str = "<memory>") -> List[UsesViolation]:
    """Scan workflow text and return every pin-policy violation."""
    violations: List[UsesViolation] = []
    for number, value in iter_uses(text):
        problem = check_uses_reference(value)
        if problem is not None:
            violations.append(
                UsesViolation(
                    path=path, line=number, uses=value, problem=problem
                )
            )
    return violations


def scan_file(path: Union[str, Path]) -> List[UsesViolation]:
    """Scan one UTF-8 workflow file; ``path`` may be str or ``Path``."""
    resolved = Path(path)
    return scan_text(
        resolved.read_text(encoding="utf-8"), path=str(resolved)
    )


def scan_workflows_dir(
    directory: Union[str, Path],
) -> List[UsesViolation]:
    """Scan every ``*.yml`` / ``*.yaml`` file in a directory, sorted."""
    root = Path(directory)
    paths = sorted([*root.glob("*.yml"), *root.glob("*.yaml")])
    violations: List[UsesViolation] = []
    for path in paths:
        violations.extend(scan_file(path))
    return violations


def format_violations(violations: Sequence[UsesViolation]) -> str:
    """Render violations one per line for assertion messages."""
    return "\n".join(str(violation) for violation in violations)
