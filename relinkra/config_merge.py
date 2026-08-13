"""Non-destructive structured merge for host configuration files (R4B).

A connector's job is to add ONE member to someone else's configuration
and change nothing else. This module is that operation, isolated from any
host knowledge so it can be reasoned about and tested on its own.

The core decision is deliberately four-valued rather than boolean:

    add       the member is absent
    no_op     a Relinkra-managed member is already correct
    update    a Relinkra-managed member is stale
    conflict  a member of that name exists and is NOT ours

``conflict`` is the value that matters. A user may already run their own
server called ``relinkra``; overwriting it would be silent data loss, so
the merge refuses and reports instead. Ownership is never assumed from
the name alone — see :func:`decide_member`.

Unknown members and unknown fields survive untouched. When a managed
entry is updated, the existing entry is used as the base and the desired
fields are overlaid, so a user's own additions to our entry (``disabled``,
a host-specific flag Relinkra has never heard of) are preserved rather
than reset on the next run.

Serialization preserves the document's own indentation and line endings
and does NOT sort keys. Sorting would reorder the user's entire file and
turn a one-member addition into a whole-file diff in their VCS.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Tuple

from .connector import MARKER_KEY, MARKER_VALUE

#: The four possible outcomes of merging one member.
ACTION_ADD = "add"
ACTION_UPDATE = "update"
ACTION_NO_OP = "no_op"
ACTION_CONFLICT = "conflict"
ACTIONS = frozenset({ACTION_ADD, ACTION_UPDATE, ACTION_NO_OP, ACTION_CONFLICT})

DEFAULT_INDENT = 2

_INDENT_RE = re.compile(r"^(\t+|[ ]+)(?=\S)", re.MULTILINE)


class MergeError(Exception):
    """Base error for configuration merging."""


class MalformedConfigError(MergeError):
    """Raised when a configuration file is not parseable."""


class UnsupportedShapeError(MergeError):
    """Raised when a document or container is not the expected type.

    Distinct from :class:`MalformedConfigError`: the file parsed fine,
    it just is not shaped the way this host's format requires. The user
    action differs — repair the JSON versus look at what that key holds.
    """


@dataclass(frozen=True)
class MergeDecision:
    """What merging one member would do, and why.

    Carries the resulting ``member`` value so the caller can render a
    plan and, later, apply exactly what was planned rather than
    recomputing it and risking a different answer.
    """

    action: str
    reason: str = ""
    member: Optional[Any] = None
    containers_created: Tuple[str, ...] = field(default_factory=tuple)
    existing_kind: str = ""

    @property
    def changes_anything(self) -> bool:
        return self.action in (ACTION_ADD, ACTION_UPDATE)

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "reason": self.reason,
            "containers_created": list(self.containers_created),
            "existing_kind": self.existing_kind,
        }


# ---------------------------------------------------------------------------
# Parsing and serialization
# ---------------------------------------------------------------------------

#: Bound on container nesting in a host configuration. Real host configs
#: nest a handful of levels; 64 is generous headroom. The JSON/TOML
#: parser's own recursion ceiling is PLATFORM-DEPENDENT (C stack size),
#: so "too deep" must be an explicit, deterministic verdict rather than
#: whatever the local parser happens to survive (R5C: a 20000-deep
#: document parsed successfully on the Linux/macOS runners while the
#: Windows interpreter raised RecursionError for the same bytes).
MAX_CONFIG_DEPTH = 64


def exceeds_config_depth(value, limit: int = MAX_CONFIG_DEPTH) -> bool:
    """Iterative nesting-depth check — no recursion, parser-independent."""
    stack = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > limit:
            return True
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, (list, tuple)):
            stack.extend((item, depth + 1) for item in current)
    return False


def parse_json_document(text: str) -> Dict[str, Any]:
    """Parse a host config, insisting on a JSON object at the root.

    An empty or whitespace-only file is treated as an empty object. That
    is not leniency for its own sake: several hosts create the file
    before writing anything into it, and refusing to merge into a
    zero-byte config would block a perfectly ordinary first run.
    """
    if text is None or not text.strip():
        return {}
    # A UTF-8 BOM is legal in files these hosts write on Windows and is
    # not legal JSON; stripping it here keeps a Windows-authored config
    # from being reported as malformed.
    if text.startswith("﻿"):
        text = text[1:]
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise MalformedConfigError(f"configuration is not valid JSON: {exc}") from exc
    except RecursionError as exc:
        # RecursionError is NOT a ValueError, so without this it escapes
        # every caller and reaches the user as a raw traceback. It takes
        # about 40 KB of nested brackets to trigger — far under the size
        # ceiling, so the byte limit does not cover this. A document too
        # deep to parse is a malformed document, and saying so is what
        # keeps one broken host config from crashing the whole command.
        raise MalformedConfigError(
            "configuration is nested too deeply to parse safely"
        ) from exc
    if not isinstance(data, dict):
        raise UnsupportedShapeError(
            f"configuration root must be an object, found {type(data).__name__}"
        )
    if exceeds_config_depth(data):
        raise MalformedConfigError(
            "configuration is nested too deeply to parse safely"
        )
    return data


def detect_indent(text: str) -> Any:
    """Return the document's own indentation unit for round-tripping.

    Returns an int for spaces and the literal ``"\\t"`` for tabs, which is
    what ``json.dumps`` accepts for each. Falls back to the default for
    an empty or single-line document, where there is nothing to detect.
    """
    if not text:
        return DEFAULT_INDENT
    match = _INDENT_RE.search(text)
    if match is None:
        return DEFAULT_INDENT
    unit = match.group(1)
    if unit.startswith("\t"):
        return "\t"
    return len(unit)


def serialize_json_document(
    document: Mapping[str, Any],
    *,
    indent: Any = DEFAULT_INDENT,
    newline: str = "\n",
    trailing_newline: bool = True,
) -> str:
    """Render a document deterministically without reordering it.

    ``sort_keys`` is intentionally NOT used. Key order in the output is
    the document's own insertion order, so every member the user already
    had stays exactly where they left it and the diff is the one member
    Relinkra actually added.
    """
    text = json.dumps(document, indent=indent, ensure_ascii=False)
    if trailing_newline:
        text += "\n"
    if newline != "\n":
        text = text.replace("\n", newline)
    return text


# ---------------------------------------------------------------------------
# Ownership
# ---------------------------------------------------------------------------


def has_marker(entry: Any) -> bool:
    """True when an entry carries the explicit Relinkra ownership marker."""
    return isinstance(entry, Mapping) and entry.get(MARKER_KEY) == MARKER_VALUE


def stamp_marker(entry: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a copy of ``entry`` carrying the ownership marker."""
    stamped = dict(entry)
    stamped[MARKER_KEY] = MARKER_VALUE
    return stamped


def ownership_test(
    structural: Callable[[Any], bool], *, marker_allowed: bool
) -> Callable[[Any], bool]:
    """Build the ownership predicate for one host format.

    The marker is only consulted for hosts that are known to tolerate
    unknown members; for everything else ownership is decided purely
    structurally, from whether the entry actually launches Relinkra.
    Adding a marker to a host that validates its schema strictly would
    break the very config we are trying to extend, so the capability is
    opt-in per connector rather than global.
    """

    def is_managed(entry: Any) -> bool:
        if marker_allowed and has_marker(entry):
            return True
        return bool(structural(entry))

    return is_managed


# ---------------------------------------------------------------------------
# Merge decision
# ---------------------------------------------------------------------------


def _walk(document: Mapping[str, Any], path: Sequence[str]):
    """Resolve a container path, reporting which levels are missing.

    Returns ``(container_or_None, created_levels)``. Raises when an
    existing level is present but is not an object — guessing that a list
    "probably means" a mapping is exactly the shape guessing this engine
    refuses to do.
    """
    node: Any = document
    created = []
    for index, key in enumerate(path):
        if not isinstance(node, Mapping):
            raise UnsupportedShapeError(
                f"cannot descend into {'.'.join(path[:index]) or 'root'}: "
                f"expected an object, found {type(node).__name__}"
            )
        if key not in node or node.get(key) is None:
            created = list(path[index:])
            return None, tuple(created)
        node = node[key]
    if not isinstance(node, Mapping):
        raise UnsupportedShapeError(
            f"{'.'.join(path)} must be an object, found {type(node).__name__}"
        )
    return node, tuple(created)


def merge_entry(existing: Any, desired: Mapping[str, Any]) -> Dict[str, Any]:
    """Overlay the desired fields onto an existing managed entry.

    Existing-first so fields Relinkra does not manage survive. A host may
    add its own bookkeeping to the entry, or the user may add a flag —
    resetting those on every run would make ``connect`` quietly
    destructive in the one place it is supposed to be idempotent.

    The environment mapping merges KEY-WISE with the same precedence:
    an operator's own variables (``DEBUG=1``) survive, and only the
    Relinkra-managed keys (``PYTHONPATH``) are refreshed. A whole-object
    overlay would silently delete the operator's keys on every update.
    """
    if not isinstance(existing, Mapping):
        return dict(desired)
    merged = dict(existing)
    for key, value in desired.items():
        if (
            key in ("env", "environment")
            and isinstance(value, Mapping)
            and isinstance(merged.get(key), Mapping)
        ):
            combined = dict(merged[key])
            combined.update(value)
            merged[key] = combined
        else:
            merged[key] = value
    return merged


def decide_member(
    document: Mapping[str, Any],
    container_path: Sequence[str],
    member_name: str,
    desired: Mapping[str, Any],
    *,
    is_managed: Callable[[Any], bool],
) -> MergeDecision:
    """Decide what merging ``member_name`` into ``container_path`` would do.

    Pure: reads the document and returns a decision. Nothing is mutated
    here, which is what lets ``plan`` be run repeatedly and compared.
    """
    if not isinstance(desired, Mapping):
        raise UnsupportedShapeError("desired member must be an object")

    container, created = _walk(document, container_path)
    if container is None:
        return MergeDecision(
            action=ACTION_ADD,
            reason="configuration container does not exist yet",
            member=dict(desired),
            containers_created=created,
        )

    if member_name not in container:
        return MergeDecision(
            action=ACTION_ADD,
            reason="no entry with this name exists",
            member=dict(desired),
        )

    existing = container[member_name]
    kind = type(existing).__name__
    if not is_managed(existing):
        return MergeDecision(
            action=ACTION_CONFLICT,
            reason=(
                f"an entry named {member_name!r} already exists and was not "
                "created by Relinkra"
            ),
            member=None,
            existing_kind=kind,
        )

    merged = merge_entry(existing, desired)
    if merged == existing:
        return MergeDecision(
            action=ACTION_NO_OP,
            reason="the existing Relinkra entry is already correct",
            member=merged,
            existing_kind=kind,
        )
    return MergeDecision(
        action=ACTION_UPDATE,
        reason="the existing Relinkra entry is out of date",
        member=merged,
        existing_kind=kind,
    )


def apply_member(
    document: Mapping[str, Any],
    container_path: Sequence[str],
    member_name: str,
    member: Mapping[str, Any],
) -> Dict[str, Any]:
    """Return a NEW document with ``member`` set, leaving the input alone.

    Deep-copied rather than mutated in place so a failed write cannot
    leave the caller holding a half-modified document that it might then
    serialize somewhere else.
    """
    result = copy.deepcopy(dict(document))
    node: Any = result
    for key in container_path:
        child = node.get(key)
        if child is None:
            child = {}
            node[key] = child
        elif not isinstance(child, dict):
            raise UnsupportedShapeError(
                f"{key!r} must be an object, found {type(child).__name__}"
            )
        node = child
    node[member_name] = copy.deepcopy(dict(member))
    return result


def validate_json_text(text: str) -> None:
    """Validator for :func:`safe_write.safe_replace`.

    Re-parses what is about to be (or has just been) written. Trivial,
    and it is the check that catches a truncated write before the user's
    host does.
    """
    parse_json_document(text)
