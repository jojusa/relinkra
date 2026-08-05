"""Per-format parse/validate/serialize adapters for connector writes (R4C.1D).

The apply/rollback engine in :mod:`relinkra.connector_apply` is
host-agnostic; the only format-specific seam is the trio of operations
declared here. Keying that seam off ``spec.config_format`` — rather than
special-casing formats inside the engine — keeps every safety property
(digest gates, semantic re-validation, decision reuse) identical across
formats.

The JSON adapter wraps :mod:`relinkra.config_merge` EXACTLY as the
engine used it before this seam existed: same indent/newline detection,
same ``apply_member`` + ``serialize_json_document`` rendering, so the
Claude and OpenCode write paths stay byte-identical. The TOML adapter
delegates to the scoped textual editor in :mod:`relinkra.toml_edit`,
which preserves everything outside the managed table byte-for-byte.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Sequence

from .config_merge import (
    apply_member,
    detect_indent,
    parse_json_document,
    serialize_json_document,
    validate_json_text,
)
from .connector import FORMAT_JSON, FORMAT_TOML
from .safe_write import detect_newline
from .toml_edit import (
    parse_toml_document,
    serialize_member_toml,
    toml_parser_available,
    validate_toml_text,
)

__all__ = ["FormatAdapter", "adapter_for"]


@dataclass(frozen=True)
class FormatAdapter:
    """The three format-specific operations the write engine needs.

    ``serialize_member`` renders the full candidate document text from
    the original file text (raw bytes decoded, line endings intact), the
    parsed document, and the member the merge decision produced. It is
    the only operation allowed to differ in STRATEGY between formats —
    whole-document rendering for JSON, scoped textual edit for TOML —
    because both must satisfy the same contract: the result parses and
    is semantically the original document with the member set.
    """

    config_format: str
    parse: Callable[[str], Mapping[str, Any]]
    validate: Callable[[str], None]
    serialize_member: Callable[
        [str, Mapping[str, Any], Sequence[str], str, Mapping[str, Any]], str
    ]
    #: Whether this interpreter can parse the format at all. Rollback
    #: consults this BEFORE restoring bytes: a parser-less interpreter
    #: cannot re-validate the restore, so it must refuse cleanly instead.
    parser_available: Callable[[], bool] = lambda: True


def _serialize_member_json(
    original_text: str,
    document: Mapping[str, Any],
    container_path: Sequence[str],
    member_name: str,
    entry: Mapping[str, Any],
) -> str:
    """Whole-document JSON rendering, byte-identical to the pre-adapter path.

    Indent and newline detection look at the raw text — the same string
    the engine read from disk — so an existing file's own formatting
    convention is the one the rewrite keeps.
    """
    merged = apply_member(document, container_path, member_name, entry)
    return serialize_json_document(
        merged,
        indent=detect_indent(original_text),
        newline=detect_newline(original_text),
        trailing_newline=(not original_text) or original_text.endswith("\n"),
    )


def _serialize_member_toml(
    original_text: str,
    document: Mapping[str, Any],
    container_path: Sequence[str],
    member_name: str,
    entry: Mapping[str, Any],
) -> str:
    # The parsed document is intentionally NOT passed through: the TOML
    # editor re-parses the original text itself so the textual edit and
    # the semantic check are anchored to the same bytes.
    return serialize_member_toml(original_text, container_path, member_name, entry)


_JSON_ADAPTER = FormatAdapter(
    config_format=FORMAT_JSON,
    parse=parse_json_document,
    validate=validate_json_text,
    serialize_member=_serialize_member_json,
)

_TOML_ADAPTER = FormatAdapter(
    config_format=FORMAT_TOML,
    parse=parse_toml_document,
    validate=validate_toml_text,
    serialize_member=_serialize_member_toml,
    parser_available=toml_parser_available,
)

_ADAPTERS = {
    FORMAT_JSON: _JSON_ADAPTER,
    FORMAT_TOML: _TOML_ADAPTER,
}


def adapter_for(config_format: str) -> Optional[FormatAdapter]:
    """The adapter for one declared format, or ``None`` when unsupported."""
    return _ADAPTERS.get(config_format)
