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

The scanner fails closed. It does not implement all of YAML, but it
recognizes the executable ``uses:`` key forms a workflow may carry --
block mappings, flow mappings, flow sequences of mappings, quoted keys,
optional whitespace before the colon, and explicit ``?`` keys -- and it
reports any ``uses`` construct it cannot classify on one line as a
violation instead of silently skipping it. Text inside comments, quoted
strings, and block scalars belonging to other keys (``run: |`` bodies)
is never a reference.

A value is accepted only when its COMPLETE semantic scalar is a valid
pin. Quoted scalars are decoded in full (single-quote doubling and the
double-quote escape table); a closing quote followed by significant
content, an unclosed scalar, a block-scalar or nested-collection value,
a flow value without a closing delimiter, and a plain scalar that may
continue on a more-indented line are all rejected as unverifiable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Tuple, Union

#: The canonical commit pin: exactly 40 lowercase hex characters.
_FULL_SHA = re.compile(r"[0-9a-f]{40}")

#: Same shape in any case, used only to explain the uppercase rejection.
_ANY_CASE_SHA = re.compile(r"[0-9A-Fa-f]{40}")

#: A digest-pinned container reference: any image plus a full sha256 digest.
_DOCKER_DIGEST = re.compile(r".+@sha256:[0-9a-f]{64}")

#: The same digest shape in any case, used only to explain the uppercase
#: canonical-format rejection.
_DOCKER_DIGEST_ANY_CASE = re.compile(r".+@sha256:[0-9A-Fa-f]{64}")

#: A block-scalar header value: ``|``, ``|-``, ``>2``, ``|+``.
_BLOCK_HEADER = re.compile(r"[|>][+-]?\d*$")

_LOCAL_PREFIX = "./"
_CONTAINER_PREFIX = "docker://"

#: One-character double-quoted YAML escape sequences (the hexadecimal
#: escapes are decoded separately). This is the YAML 1.2 escape table.
_SIMPLE_ESCAPES: Dict[str, str] = {
    "0": "\0",
    "a": "\a",
    "b": "\b",
    "t": "\t",
    "n": "\n",
    "v": "\v",
    "f": "\f",
    "r": "\r",
    "e": "\x1b",
    '"': '"',
    "/": "/",
    "\\": "\\",
    "N": "\x85",
    "_": "\xa0",
    "L": "\u2028",
    "P": "\u2029",
}

#: Characters that end a bare (unquoted) key or scalar token.
_BARE_STOP = frozenset(" \t:,{}[]")


@dataclass(frozen=True)
class UsesViolation:
    """One unpinned or malformed ``uses:`` reference."""

    path: str
    line: int
    uses: str
    problem: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.uses} -> {self.problem}"


@dataclass(frozen=True)
class _KeyToken:
    """One parsed key token: exact text when decodable, else ambiguous."""

    raw: str
    decoded: Optional[str]
    start: int
    end: int


@dataclass(frozen=True)
class _LineFinding:
    """One ``uses`` value found on a line, with its verification state."""

    line: int
    key_col: int
    value: str
    block_plain: bool


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _read_quoted(text: str, start: int) -> Tuple[Optional[str], int]:
    """Read a quoted scalar at ``text[start]``; return ``(raw, end)``.

    ``raw`` includes the surrounding quotes. ``(None, len(text))`` means
    the scalar does not close on this line, so nothing after it can be
    classified safely.
    """
    quote = text[start]
    index = start + 1
    while index < len(text):
        char = text[index]
        if quote == '"' and char == "\\":
            index += 2
            continue
        if char == quote:
            if (
                quote == "'"
                and index + 1 < len(text)
                and text[index + 1] == "'"
            ):
                index += 2
                continue
            return text[start : index + 1], index + 1
        index += 1
    return None, len(text)


def _decode_quoted(raw: str) -> Optional[str]:
    """Decode a complete quoted scalar; ``None`` when not decodable.

    Single quotes decode ``''`` to ``'``. Double quotes decode the YAML
    1.2 escape table. An unknown or malformed escape returns ``None``:
    the caller then fails closed instead of guessing.
    """
    if len(raw) < 2 or raw[0] not in "\"'":
        return None
    quote = raw[0]
    inner = raw[1:-1]
    if quote == "'":
        return inner.replace("''", "'")
    decoded: List[str] = []
    index = 0
    while index < len(inner):
        char = inner[index]
        if char != "\\":
            decoded.append(char)
            index += 1
            continue
        if index + 1 >= len(inner):
            return None
        escape = inner[index + 1]
        if escape in ("x", "u", "U"):
            width = {"x": 2, "u": 4, "U": 8}[escape]
            digits = inner[index + 2 : index + 2 + width]
            if len(digits) != width or any(
                digit not in "0123456789abcdefABCDEF" for digit in digits
            ):
                return None
            codepoint = int(digits, 16)
            if codepoint > 0x10FFFF:
                return None
            decoded.append(chr(codepoint))
            index += 2 + width
            continue
        replacement = _SIMPLE_ESCAPES.get(escape)
        if replacement is None:
            return None
        decoded.append(replacement)
        index += 2
    return "".join(decoded)


def _could_decode_to_uses(raw: str) -> bool:
    """Whether an undecodable quoted key could decode to ``uses``.

    Undecodable escapes are invalid YAML, but the check stays
    conservative: every escape is treated as a wildcard character and
    the literal characters are matched against ``uses`` position by
    position, so an escape-hidden ``uses`` key still fails closed.
    """
    if len(raw) < 2:
        return False
    inner = raw[1:-1]
    units: List[Optional[str]] = []
    index = 0
    while index < len(inner):
        char = inner[index]
        if char != "\\":
            units.append(char)
            index += 1
            continue
        if index + 1 >= len(inner):
            units.append(None)
            index += 1
            continue
        escape = inner[index + 1]
        if escape in ("x", "u", "U"):
            width = {"x": 2, "u": 4, "U": 8}[escape]
            units.append(None)
            index += 2 + width
        else:
            units.append(None)
            index += 2
    target = "uses"
    if len(units) != len(target):
        return False
    return all(
        unit is None or unit == expected
        for unit, expected in zip(units, target)
    )


def _read_key_token(text: str, start: int) -> Optional[_KeyToken]:
    """Parse the key token starting at ``text[start]``, if any.

    A quoted token decodes through the bounded YAML decoder; an unclosed
    quote makes the rest of the line unclassifiable and yields ``None``.
    A bare token ends at whitespace or a YAML indicator character.
    """
    if start >= len(text):
        return None
    char = text[start]
    if char in "\"'":
        raw, end = _read_quoted(text, start)
        if raw is None:
            return None
        return _KeyToken(raw, _decode_quoted(raw), start, end)
    end = start
    while end < len(text) and text[end] not in _BARE_STOP:
        end += 1
    if end == start:
        return None
    token = text[start:end]
    return _KeyToken(token, token, start, end)


def _strip_plain_comment(text: str) -> str:
    """Cut an unquoted scalar at its first `` #`` comment marker."""
    cut = text.find(" #")
    if cut != -1:
        text = text[:cut]
    return text.strip()


def _flow_plain_end(text: str, start: int) -> Tuple[int, bool]:
    """End of a flow plain scalar; return ``(end, closed)``.

    ``closed`` is True only when a top-level ``,``/``}``/``]`` delimiter
    ends the scalar. Running into the end of the line or a comment is not
    closing: the scalar may continue on the next line, so the caller
    fails closed.
    """
    index = start
    while index < len(text):
        char = text[index]
        if char in ",}]":
            return index, True
        if char == "#" and (
            index == start or text[index - 1] in " \t"
        ):
            return index, False
        index += 1
    return len(text), False


def _quoted_value(text: str, start: int, in_flow: bool) -> Optional[str]:
    """Decode a quoted ``uses`` value; ``None`` means fail closed."""
    raw, end = _read_quoted(text, start)
    if raw is None:
        return None
    decoded = _decode_quoted(raw)
    if decoded is None:
        return None
    remainder = text[end:]
    index = 0
    while index < len(remainder) and remainder[index] in " \t":
        index += 1
    if index >= len(remainder):
        return decoded
    if remainder[index] == "#":
        return decoded
    if in_flow and remainder[index] in ",}]":
        return decoded
    return None


def _plain_value(text: str, start: int, in_flow: bool) -> Optional[str]:
    """Extract a plain ``uses`` value; ``None`` means fail closed."""
    if in_flow:
        end, closed = _flow_plain_end(text, start)
        if not closed:
            return None
        value = text[start:end].strip()
    else:
        value = _strip_plain_comment(text[start:])
    return value or None


def _extract_value(text: str, start: int, in_flow: bool) -> Tuple[str, bool]:
    """Return ``(value, block_plain)`` for the value at ``text[start]``.

    An empty string means the construct is unverifiable and must fail
    closed. ``block_plain`` marks a clean block-context plain scalar,
    which may still continue on a more-indented line.
    """
    index = start
    while index < len(text) and text[index] in " \t":
        index += 1
    if index >= len(text) or text[index] == "#":
        return "", False
    char = text[index]
    if char in "|>":
        # A block scalar indicator, or a scalar starting with an
        # indicator character: not verifiable on this line.
        return "", False
    if char in "{[":
        # A nested flow collection as the value: unverifiable.
        return "", False
    if char in "\"'":
        decoded = _quoted_value(text, index, in_flow)
        if decoded is None:
            return "", False
        return decoded, False
    value = _plain_value(text, index, in_flow)
    if value is None:
        return "", False
    return value, not in_flow


def _scan_line(text: str, line_number: int) -> List[_LineFinding]:
    """Find every ``uses`` key on one line, quote- and comment-aware.

    Key positions are the start of the line and the positions right after
    a flow indicator (``{``, ``[``, ``,``), an explicit-key ``?``, or a
    sequence ``-``. Everything else is scalar content and cannot open a
    key, so ``run: echo uses:checkout`` and quoted text are inert.
    """
    findings: List[_LineFinding] = []
    index = 0
    at_key = True
    in_flow = False
    explicit_key = False
    while index < len(text):
        while index < len(text) and text[index] in " \t":
            index += 1
        if index >= len(text):
            break
        char = text[index]
        if char == "#":
            break
        if char in "{[,":
            at_key = True
            in_flow = True
            explicit_key = False
            index += 1
            continue
        if char == "?":
            at_key = True
            explicit_key = True
            index += 1
            continue
        if char in "}]":
            at_key = False
            explicit_key = False
            index += 1
            continue
        if (
            char == "-"
            and at_key
            and (index + 1 >= len(text) or text[index + 1] in " \t")
        ):
            at_key = True
            in_flow = False
            explicit_key = False
            index += 1
            continue
        token = _read_key_token(text, index)
        if token is None:
            break
        probe = token.end
        while probe < len(text) and text[probe] in " \t":
            probe += 1
        has_colon = probe < len(text) and text[probe] == ":"
        if at_key:
            key_is_uses = token.decoded == "uses"
            key_maybe_uses = (
                token.decoded is None and _could_decode_to_uses(token.raw)
            )
            if (key_is_uses or key_maybe_uses) and (has_colon or explicit_key):
                if has_colon:
                    value, block_plain = _extract_value(
                        text, probe + 1, in_flow
                    )
                else:
                    # An explicit ``? uses`` key without an inline value:
                    # the value is on another line, so it cannot be
                    # verified and must fail closed.
                    value, block_plain = "", False
                findings.append(
                    _LineFinding(
                        line=line_number,
                        key_col=token.start,
                        value=value,
                        block_plain=block_plain,
                    )
                )
        index = probe + 1 if has_colon else token.end
        at_key = False
        explicit_key = False
    return findings


def _block_header_key(text: str) -> Optional[_KeyToken]:
    """Return the key token when ``text`` is a block-scalar header line."""
    index = _indent(text)
    if text[index:].startswith("- "):
        index += 2
        while index < len(text) and text[index] in " \t":
            index += 1
    token = _read_key_token(text, index)
    if token is None:
        return None
    probe = token.end
    while probe < len(text) and text[probe] in " \t":
        probe += 1
    if probe >= len(text) or text[probe] != ":":
        return None
    value = _strip_plain_comment(text[probe + 1 :])
    if not _BLOCK_HEADER.fullmatch(value):
        return None
    return token


def _continues(lines: Sequence[str], index: int, key_col: int) -> bool:
    """Whether a plain scalar at ``key_col`` continues on a later line."""
    for later in lines[index + 1 :]:
        if not later.strip() or later.lstrip().startswith("#"):
            continue
        return _indent(later) > key_col
    return False


def iter_uses(text: str) -> Iterator[Tuple[int, str]]:
    """Yield ``(line_number, value)`` for real ``uses:`` keys, 1-based.

    Blank lines and full-line comments are skipped. Content inside block
    scalars (``run: |`` bodies and similar) is skipped by indentation:
    while inside a block scalar only more-indented lines are ignored, and
    normal processing resumes at the first line whose indent is not
    greater than the block scalar header's indent. A ``uses`` key whose
    value is not safely verifiable on one line yields an empty value so
    the policy fails closed.
    """
    lines = text.splitlines()
    block_indent: Optional[int] = None
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        indent = _indent(line)
        if block_indent is not None:
            if indent > block_indent:
                continue
            block_indent = None
        if line.lstrip().startswith("#"):
            continue
        header = _block_header_key(line)
        if header is not None:
            if header.decoded == "uses" or (
                header.decoded is None
                and _could_decode_to_uses(header.raw)
            ):
                yield index + 1, ""
            block_indent = indent
            continue
        for finding in _scan_line(line, index + 1):
            value = finding.value
            if (
                value
                and finding.block_plain
                and _continues(lines, index, finding.key_col)
            ):
                # The semantic scalar continues on a more-indented line;
                # the single-line prefix is not the complete value.
                value = ""
            yield index + 1, value


def check_uses_reference(value: str) -> Optional[str]:
    """Return a problem string for an unpinned reference, else ``None``."""
    if value == "":
        return (
            "unverifiable uses reference: the ref must be a complete "
            "single-line scalar after uses: (empty, block-scalar, "
            "multi-line, and ambiguous values are rejected)"
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


def workflow_files(directory: Union[str, Path]) -> List[Path]:
    """Every ``*.yml`` / ``*.yaml`` workflow file in a directory, sorted.

    This is the single workflow-enumeration rule: tests, the pin policy,
    and the release SECURITY scan all discover the same files.
    """
    root = Path(directory)
    if not root.is_dir():
        return []
    return sorted([*root.glob("*.yml"), *root.glob("*.yaml")])


def scan_workflows_dir(
    directory: Union[str, Path],
) -> List[UsesViolation]:
    """Scan every ``*.yml`` / ``*.yaml`` file in a directory, sorted."""
    violations: List[UsesViolation] = []
    for path in workflow_files(directory):
        violations.extend(scan_file(path))
    return violations


def format_violations(violations: Sequence[UsesViolation]) -> str:
    """Render violations one per line for assertion messages."""
    return "\n".join(str(violation) for violation in violations)
