"""Scoped, comment-preserving TOML editing for connector writes (R4C.1D).

Codex stores MCP registrations as ``[mcp_servers.<name>]`` tables in a
TOML document the user also edits by hand. A whole-document TOML writer
would reorder keys, normalize quoting and drop every comment — the same
whole-file diff the JSON merge was built to avoid. The official
``codex mcp add`` (codex-cli 0.146.0) is not acceptable either: it
preserves top-level comments but drops comments adjacent to the
``mcp_servers`` region it rewrites and normalizes CRLF to LF globally.
No comment-preserving TOML library is available to a stdlib-only project
supporting Python 3.9, so this module performs a SCOPED TEXTUAL edit
instead:

    * parsing and validation always go through ``tomllib`` — never a
      regex or a hand-rolled parser;
    * the text AROUND the managed member's table is preserved
      byte-for-byte: other tables, unknown fields, comments, ordering,
      quoting style, line endings and the UTF-8 BOM;
    * the managed member's own region is re-rendered deterministically.
      Comments INSIDE that region are dropped on update — the region is
      Relinkra-managed — except the trailing run of comment/blank lines
      between the region's last content line and the next table header,
      which may document the FOLLOWING table and is therefore kept.

The house rule is fail-closed. Dotted-key or inline member forms,
duplicate definitions, non-contiguous member subtables, values this
renderer cannot express, and any disagreement between the textual edit
and the ``tomllib`` parse all raise a typed error instead of producing
a "probably right" rewrite.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .config_merge import MalformedConfigError, MergeError, apply_member
from .safe_write import detect_newline

__all__ = [
    "TomlEditError",
    "TomlConflictError",
    "TomlParserUnavailableError",
    "parse_toml_document",
    "serialize_member_toml",
    "toml_parser_available",
    "validate_toml_text",
]


class TomlEditError(MergeError):
    """Base error for scoped TOML edits that cannot be done safely."""


class TomlParserUnavailableError(TomlEditError):
    """Raised when ``tomllib`` is missing (Python older than 3.11)."""


class TomlConflictError(TomlEditError):
    """Raised when the member's textual representation is not ours to edit.

    Dotted-key or inline-table member forms, array-of-tables members and
    non-contiguous member subtables all land here: the file is valid
    TOML, but rewriting it textually would guess at the user's intent.
    """


# ---------------------------------------------------------------------------
# Parsing and validation
# ---------------------------------------------------------------------------


def toml_parser_available() -> bool:
    """Whether this interpreter can parse TOML at all (Python 3.11+)."""
    try:
        import tomllib  # noqa: F401
    except ImportError:
        return False
    return True


def parse_toml_document(text: str) -> Dict[str, Any]:
    """Parse a host TOML config, insisting on a table at the root.

    An empty or whitespace-only file is an empty document, mirroring the
    JSON reader: several hosts create the file before writing into it. A
    UTF-8 BOM is tolerated — Windows-authored configs carry one — and is
    the caller's problem to preserve on write.
    """
    if text is None or not text.strip():
        return {}
    if text.startswith("\ufeff"):
        text = text[1:]
    try:
        import tomllib
    except ImportError as exc:
        raise TomlParserUnavailableError(
            "reading TOML requires Python 3.11 or newer (tomllib); the "
            "registration state cannot be determined on this interpreter"
        ) from exc
    try:
        document = tomllib.loads(text)
    except ValueError as exc:
        raise MalformedConfigError(
            f"configuration is not valid TOML: {exc}"
        ) from exc
    except RecursionError as exc:
        raise MalformedConfigError(
            "configuration is nested too deeply to parse safely"
        ) from exc
    if not isinstance(document, dict):
        raise MalformedConfigError("configuration root must be a TOML table")
    return document


def validate_toml_text(text: str) -> None:
    """Validator for :func:`safe_write.safe_replace` on TOML targets."""
    parse_toml_document(text)


# ---------------------------------------------------------------------------
# Rendering TOML values
# ---------------------------------------------------------------------------

_BARE_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _render_basic_string(value: str) -> str:
    """Render a TOML basic string. JSON string escaping is valid TOML.

    ``json.dumps`` escapes every control character TOML forbids EXCEPT
    DEL (0x7F), which is escaped here explicitly. Non-ASCII text stays
    literal: TOML documents are UTF-8.
    """
    rendered = json.dumps(value, ensure_ascii=False)
    return rendered.replace("\x7f", "\\u007F")


def _render_key(key: Any) -> str:
    if not isinstance(key, str) or not key:
        raise TomlEditError(
            f"cannot render a TOML key from {key!r}; refusing to rewrite"
        )
    if _BARE_KEY_RE.match(key):
        return key
    return _render_basic_string(key)


def _render_value(value: Any) -> str:
    """Render one TOML value. Fail-closed on anything outside the scope.

    Scalars, arrays of scalars and inline tables of renderable values are
    the whole vocabulary. Datetimes (``tomllib`` produces them) and
    nested arrays are refused: reformatting a user's temporal value is a
    rewrite this module does not attempt.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return _render_basic_string(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value):
            return "nan"
        if math.isinf(value):
            return "inf" if value > 0 else "-inf"
        return repr(value)
    if isinstance(value, (list, tuple)):
        items = []
        for item in value:
            if isinstance(item, (list, tuple, Mapping)):
                raise TomlEditError(
                    "the managed entry holds a nested array or table inside "
                    "an array; refusing to rewrite what cannot be rendered "
                    "safely"
                )
            items.append(_render_value(item))
        return "[" + ", ".join(items) + "]"
    if isinstance(value, Mapping):
        pairs = ", ".join(
            f"{_render_key(key)} = {_render_value(item)}"
            for key, item in value.items()
        )
        return "{" + pairs + "}"
    raise TomlEditError(
        f"the managed entry holds a value of type {type(value).__name__} "
        "that cannot be rendered safely; refusing to rewrite it"
    )


def _render_table(
    target_path: Sequence[str], entry: Mapping[str, Any], newline: str
) -> List[str]:
    """The lines of one explicit table: header plus one line per key."""
    header = "[" + ".".join(_render_key(key) for key in target_path) + "]"
    lines = [header]
    for key, value in entry.items():
        lines.append(f"{_render_key(key)} = {_render_value(value)}")
    return lines


# ---------------------------------------------------------------------------
# Textual scanning
# ---------------------------------------------------------------------------


def _skip_ws(text: str, pos: int) -> int:
    while pos < len(text) and text[pos] in " \t":
        pos += 1
    return pos


def _scan_key_segment(text: str, pos: int) -> Tuple[Optional[str], int]:
    """One dotted-key segment: bare, basic-quoted or literal-quoted."""
    if pos >= len(text):
        return None, pos
    if text[pos] == '"':
        cursor = pos + 1
        while cursor < len(text):
            if text[cursor] == "\\":
                cursor += 2
                continue
            if text[cursor] == '"':
                token = text[pos:cursor + 1]
                try:
                    decoded = json.loads(token)
                except ValueError:
                    return None, pos
                if not isinstance(decoded, str):
                    return None, pos
                return decoded, cursor + 1
            cursor += 1
        return None, pos
    if text[pos] == "'":
        end = text.find("'", pos + 1)
        if end == -1:
            return None, pos
        return text[pos + 1:end], end + 1
    match = re.match(r"[A-Za-z0-9_-]+", text[pos:])
    if match is None:
        return None, pos
    return match.group(0), pos + len(match.group(0))


def _scan_header(text: str) -> Optional[Tuple[Tuple[str, ...], bool]]:
    """Parse a stripped line as a table header.

    Returns ``(key_path, is_array)`` or ``None`` when the line is not a
    well-formed header. The document has already been accepted by
    ``tomllib`` before this scanner runs, so a header-shaped line this
    scanner cannot read is a reason to refuse, never to guess.
    """
    if not text.startswith("["):
        return None
    is_array = text.startswith("[[")
    pos = 2 if is_array else 1
    segments: List[str] = []
    while True:
        pos = _skip_ws(text, pos)
        segment, pos = _scan_key_segment(text, pos)
        if segment is None:
            return None
        segments.append(segment)
        pos = _skip_ws(text, pos)
        if pos < len(text) and text[pos] == ".":
            pos += 1
            continue
        break
    closer = "]]" if is_array else "]"
    if not text.startswith(closer, pos):
        return None
    rest = text[pos + len(closer):].strip()
    if rest and not rest.startswith("#"):
        return None
    return tuple(segments), is_array


def _update_string_state(line: str, delimiter: Optional[str]) -> Optional[str]:
    """Track multi-line string state across one line.

    Only triple-quoted strings span lines. Single-line strings on the
    line are consumed first so a triple-quote-looking sequence inside
    one is never mistaken for a delimiter. Heuristic by design; the
    semantic re-parse of the candidate is the check that actually holds.
    """
    cursor = 0
    while cursor < len(line):
        if delimiter is not None:
            end = line.find(delimiter, cursor)
            if end == -1:
                return delimiter
            if delimiter == '"""':
                # Backslash parity decides whether the quote run is
                # escaped: an ODD run of preceding backslashes escapes
                # the first quote (\"), an EVEN run is escaped pairs
                # (\\) and the delimiter really closes the string.
                backslashes = 0
                index = end - 1
                while index >= 0 and line[index] == "\\":
                    backslashes += 1
                    index -= 1
                if backslashes % 2 == 1:
                    cursor = end + 1
                    continue
            return _update_string_state(line[end + 3:], None)
        char = line[cursor]
        if line.startswith('"""', cursor):
            delimiter = '"""'
            cursor += 3
            continue
        if line.startswith("'''", cursor):
            delimiter = "'''"
            cursor += 3
            continue
        if char == '"':
            cursor += 1
            while cursor < len(line):
                if line[cursor] == "\\":
                    cursor += 2
                    continue
                if line[cursor] == '"':
                    break
                cursor += 1
            cursor += 1
            continue
        if char == "'":
            end = line.find("'", cursor + 1)
            cursor = len(line) if end == -1 else end + 1
            continue
        if char == "#":
            return delimiter
        cursor += 1
    return delimiter


#: Line classes for the scoped edit.
_LINE_CONTENT = "content"
_LINE_COMMENT = "comment"
_LINE_BLANK = "blank"


class _ScannedLine:
    __slots__ = ("kind", "header")

    def __init__(self, kind: str, header: Optional[Tuple[Tuple[str, ...], bool]]):
        self.kind = kind
        self.header = header


def _scan_lines(lines: Sequence[str]) -> List[_ScannedLine]:
    """Classify every line, locating table headers outside strings."""
    scanned: List[_ScannedLine] = []
    delimiter: Optional[str] = None
    for raw_line in lines:
        line = raw_line.rstrip("\r\n")
        if delimiter is not None:
            delimiter = _update_string_state(line, delimiter)
            scanned.append(_ScannedLine(_LINE_CONTENT, None))
            continue
        stripped = line.strip()
        if not stripped:
            scanned.append(_ScannedLine(_LINE_BLANK, None))
            continue
        if stripped.startswith("#"):
            scanned.append(_ScannedLine(_LINE_COMMENT, None))
            continue
        if stripped.startswith("["):
            header = _scan_header(stripped)
            if header is None:
                raise TomlEditError(
                    f"a table header could not be scanned safely: {stripped!r}; "
                    "refusing to edit around it"
                )
            scanned.append(_ScannedLine(_LINE_CONTENT, header))
            continue
        delimiter = _update_string_state(line, None)
        scanned.append(_ScannedLine(_LINE_CONTENT, None))
    return scanned


# ---------------------------------------------------------------------------
# The scoped edit
# ---------------------------------------------------------------------------


def _resolve(document: Mapping[str, Any], path: Sequence[str]) -> Any:
    node: Any = document
    for key in path:
        if not isinstance(node, Mapping):
            return None
        node = node.get(key)
    return node


def serialize_member_toml(
    original_text: str,
    container_path: Sequence[str],
    member_name: str,
    entry: Mapping[str, Any],
) -> str:
    """Set one container member in TOML text, preserving everything else.

    ``container_path`` plus ``member_name`` names one explicit table,
    e.g. ``("mcp_servers",)`` + ``"relinkra"`` edits exactly the
    ``[mcp_servers.relinkra]`` table. When that table exists, its byte
    extent — header through the line before the next UNRELATED table
    header — is replaced and the rest of the document is preserved
    byte-for-byte. When it does not exist, a new table is appended at
    end of file, which is valid TOML wherever the super-table lives.

    Raises :class:`TomlConflictError` for member representations that
    are not an explicit managed table (dotted keys, inline tables,
    arrays of tables, non-contiguous subtables), and
    :class:`TomlEditError` when the textual edit and the ``tomllib``
    parse disagree. Nothing is ever silently rewritten.
    """
    if not isinstance(entry, Mapping):
        raise TomlEditError("the member entry must be a mapping")
    newline = detect_newline(original_text)
    bom = original_text.startswith("\ufeff")
    body = original_text[1:] if bom else original_text
    target_path = tuple(container_path) + (member_name,)

    document = parse_toml_document(body)
    container = _resolve(document, container_path)
    member = container.get(member_name) if isinstance(container, Mapping) else None

    lines = body.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    scanned = _scan_lines(lines)
    headers = [
        (index, scanned[index].header)
        for index in range(len(lines))
        if scanned[index].header is not None
    ]

    def extends_target(path: Tuple[str, ...]) -> bool:
        return len(path) > len(target_path) and path[: len(target_path)] == target_path

    block = newline.join(_render_table(target_path, entry, newline))
    trailing = newline if (not body or body.endswith("\n")) else ""

    if member is None:
        # ADD: no explicit table may exist for the member or its subtree,
        # and every ancestor must be header-defined (or implicit) rather
        # than defined by dotted keys — otherwise appending an explicit
        # table would be a TOML redefinition.
        for index, (path, _is_array) in headers:
            if path == target_path or extends_target(path):
                raise TomlEditError(
                    "a table header for the member exists but the parse "
                    "shows no member; textual anchoring disagrees with "
                    "tomllib, refusing to edit"
                )
        for depth in range(1, len(target_path)):
            prefix = target_path[:depth]
            if _resolve(document, prefix) is None:
                continue
            header_defined = any(
                path == prefix or path[:depth] == prefix
                for _, (path, _is_array) in headers
            )
            if not header_defined:
                raise TomlConflictError(
                    f"'{'.'.join(prefix)}' is defined by dotted or inline "
                    "keys, so an explicit member table cannot be appended "
                    "without redefining it; rewrite that section as explicit "
                    "tables by hand"
                )
        if not body:
            candidate_body = block + newline
        elif body.endswith("\n"):
            candidate_body = body + block + newline
        else:
            candidate_body = body + newline + block
    else:
        if not isinstance(member, Mapping):
            raise TomlConflictError(
                f"the member '{member_name}' is a {type(member).__name__}, "
                "not a table; Relinkra never rewrites a representation it "
                "does not manage"
            )
        matching = [
            (index, is_array)
            for index, (path, is_array) in headers
            if path == target_path
        ]
        if any(is_array for _, is_array in matching):
            raise TomlConflictError(
                f"the member '{member_name}' is declared as an array of "
                "tables; refusing to edit it"
            )
        member_headers = [index for index, _ in matching]
        if not member_headers:
            raise TomlConflictError(
                f"the member '{member_name}' is defined by dotted keys or an "
                "inline table, not by an explicit "
                f"'[{'.'.join(target_path)}]' table; Relinkra never rewrites "
                "a representation it did not create"
            )
        header_line = member_headers[0]

        # The member region runs from its header to the line before the
        # next UNRELATED header. Subtable headers belonging to the member
        # ([mcp_servers.relinkra.env]) stay inside the region, but only
        # when contiguous — one appearing after another table's header
        # makes the layout ambiguous and is refused.
        region_end_line = len(lines)
        region_closed = False
        for index, (path, _is_array) in headers:
            if index <= header_line:
                continue
            if extends_target(path):
                if region_closed:
                    raise TomlConflictError(
                        f"a subtable of '{member_name}' is separated from "
                        "its table by another table; the layout is ambiguous "
                        "and is never rewritten"
                    )
                continue
            if not region_closed:
                region_end_line = index
                region_closed = True

        # The replace extent ends after the region's last CONTENT line.
        # Trailing comment/blank lines may document the next table and
        # are preserved byte-for-byte.
        extent_end_line = header_line + 1
        for index in range(header_line, region_end_line):
            if scanned[index].kind == _LINE_CONTENT:
                extent_end_line = index + 1
        at_eof = region_end_line == len(lines) and extent_end_line == len(lines)
        block_text = block + ("" if at_eof and not trailing else newline)
        candidate_body = (
            body[: offsets[header_line]] + block_text + body[offsets[extent_end_line]:]
        )

    candidate = ("\ufeff" if bom else "") + candidate_body

    # Defense in depth: the candidate must parse, and its semantics must
    # be exactly the original document with the member set — every other
    # table, key and value identical. A mismatch means the textual edit
    # corrupted something the parse can still see, and the whole write
    # is refused.
    candidate_document = parse_toml_document(candidate_body)
    expected_document = apply_member(document, container_path, member_name, entry)
    if candidate_document != expected_document:
        raise TomlEditError(
            "the textual TOML edit disagreed with the tomllib parse; "
            "refusing to write a configuration that cannot be proven "
            "equivalent to a structured merge"
        )
    return candidate
