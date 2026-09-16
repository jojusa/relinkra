"""Bounded read-only graph explorer for the Relinkra viewer (VIS-2).

Pure request validation and response shaping: this module performs no
HTTP, constructs no adapter, executes no backend, and persists nothing.
The viewer passes ``urllib.parse.parse_qs`` output (``keep_blank_values``
enabled) and an already-gated adapter; every response is a deterministic,
path-free payload bounded to the documented viewer contract.

Honesty rules that are intentional and tested:

- the backend reports no relationship total, so coverage always states
  that a bounded graph result is not proof of absence;
- ``is_test`` is only ever True when CBM said so: absence is UNKNOWN,
  never False;
- absolute paths (any platform syntax) never cross this boundary;
- no raw source, docstring, signature, or CBM-internal field is copied.
"""

from __future__ import annotations

from typing import Mapping, Optional, Sequence, Tuple

from .cbm_adapter import (
    CBMAdapterError,
    CBMNodeNotFoundError,
    CBMProjectNotIndexedError,
    GRAPH_RELATION_DEFAULT_LIMIT,
    _is_absolute_any_syntax,
)
from .code_reference import CodeRefError, CodeReference, derive_language

#: Informational contract id reported by every graph payload.
VIEWER_CONTRACT = "relinkra.viewer/v1"

#: Accepted search kinds.
GRAPH_SEARCH_KINDS = ("symbol", "file")

#: Request bounds (mirrors the adapter's hard maximums).
GRAPH_SEARCH_DEFAULT_LIMIT = 20
GRAPH_SEARCH_MAX_LIMIT = 20
GRAPH_QUERY_MAX_CHARS = 200
GRAPH_KEY_MAX_CHARS = 300
GRAPH_DEFAULT_DEPTH = 1

#: Frontend graph node caps reported as coverage facts, never enforced
#: per request by this API.
GRAPH_INITIAL_NODE_CAP = 50
GRAPH_EXPANDED_NODE_CAP = 100

_SEARCH_ERROR_MESSAGE = "The CBM graph query failed."
_INDEX_MISSING_MESSAGE = "The CBM index is missing for this workspace."


class GraphAPIError(Exception):
    """A bounded graph request failure with an HTTP status and a code.

    ``to_dict`` is the only shape that ever crosses the viewer boundary:
    a stable machine code, a short sanitized message, and an optional
    next action. Never a traceback, never raw backend output.
    """

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        next_action: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status = int(status)
        self.code = str(code)
        self.message = str(message)
        self.next_action = next_action

    def to_dict(self) -> dict:
        return {
            "error": self.code,
            "message": self.message,
            "next_action": self.next_action,
        }


# -- request parsing ---------------------------------------------------------


def _first_param(
    params: Mapping[str, Sequence[str]], name: str
) -> Optional[str]:
    """The FIRST value deterministically, or None when absent/blank."""
    values = params.get(name)
    if not values:
        return None
    value = values[0]
    return value if isinstance(value, str) else str(value)


def parse_search_params(
    params: Mapping[str, Sequence[str]],
) -> Tuple[str, str, int]:
    """Validate and bound the ``/api/graph/search`` query parameters.

    Returns ``(query, kind, limit)``. Missing or blank ``q``, an
    over-long query, an unknown ``kind``, and an out-of-range ``limit``
    are 400-class rejections with stable codes.
    """
    raw_query = _first_param(params, "q")
    query = (raw_query or "").strip()
    if not query:
        raise GraphAPIError(
            400, "missing_query", "a non-empty q parameter is required"
        )
    if len(query) > GRAPH_QUERY_MAX_CHARS:
        raise GraphAPIError(
            400, "query_too_long", "q must be at most 200 characters"
        )
    raw_kind = _first_param(params, "kind")
    kind = (raw_kind or "").strip() or "symbol"
    if kind not in GRAPH_SEARCH_KINDS:
        raise GraphAPIError(
            400, "invalid_kind", "kind must be symbol or file"
        )
    raw_limit = _first_param(params, "limit")
    limit = GRAPH_SEARCH_DEFAULT_LIMIT
    if raw_limit is not None:
        try:
            limit = int(raw_limit.strip(), 10)
        except ValueError as exc:
            raise GraphAPIError(
                400,
                "invalid_limit",
                "limit must be an integer between 1 and 20",
            ) from exc
        if limit < 1 or limit > GRAPH_SEARCH_MAX_LIMIT:
            raise GraphAPIError(
                400,
                "invalid_limit",
                "limit must be an integer between 1 and 20",
            )
    return query, kind, limit


def parse_node_params(params: Mapping[str, Sequence[str]]) -> str:
    """Validate and bound the ``/api/graph/node`` query parameters.

    Returns the requested project-relative ``key``. Missing or blank
    keys, over-long keys, keys with control characters, and
    absolute-path shapes are 400-class rejections with stable codes: a
    qualified name is a semantic dotted identity, never a path.
    """
    raw_key = _first_param(params, "key")
    key = (raw_key or "").strip()
    if not key:
        raise GraphAPIError(
            400, "missing_key", "a non-empty key parameter is required"
        )
    if len(key) > GRAPH_KEY_MAX_CHARS:
        raise GraphAPIError(
            400, "key_too_long", "key must be at most 300 characters"
        )
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in key):
        raise GraphAPIError(
            400, "invalid_key", "key contains control characters"
        )
    if _is_absolute_any_syntax(key):
        raise GraphAPIError(
            400,
            "invalid_key",
            "key must be a project-relative qualified name",
        )
    return key


# -- response helpers --------------------------------------------------------


def _optional_text(value) -> Optional[str]:
    return value if isinstance(value, str) else None


def _optional_int(value) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _optional_bool(value) -> Optional[bool]:
    return value if isinstance(value, bool) else None


def _repo_relative_or_none(value) -> Optional[str]:
    """A repo-relative POSIX-ish path, or None for absolute/blank input.

    Absolute under ANY platform syntax is rejected: a foreign-syntax
    absolute path is workspace-local metadata, never portable evidence.
    """
    if not isinstance(value, str):
        return None
    path = value.strip()
    if not path or _is_absolute_any_syntax(path):
        return None
    return path


def _search_node_record(node: dict):
    """One uniform search-result record, or None when the node is unsafe.

    A record is unrepresentable when its project-relative qn is missing
    or has an absolute-path shape: such a node could not be focal-traced
    and its key must never cross the boundary.
    """
    raw_key = node.get("relative_qualified_name")
    key = raw_key.strip() if isinstance(raw_key, str) else ""
    if not key or _is_absolute_any_syntax(key):
        return None
    return {
        "key": key,
        "name": _optional_text(node.get("name")),
        "qualified_name": key,
        "file_path": _repo_relative_or_none(node.get("file_path")),
        "label": _optional_text(node.get("label")),
        "start_line": _optional_int(node.get("start_line")),
        "end_line": _optional_int(node.get("end_line")),
        "in_degree": _optional_int(node.get("in_degree")),
        "out_degree": _optional_int(node.get("out_degree")),
        "complexity": _optional_int(node.get("complexity")),
        "lines": _optional_int(node.get("lines")),
        "is_test": _optional_bool(node.get("is_test")),
        "is_exported": _optional_bool(node.get("is_exported")),
        "is_entry_point": _optional_bool(node.get("is_entry_point")),
    }


def _search_coverage(returned: int, limit: int, total, has_more) -> dict:
    """Search coverage that never claims more than CBM established.

    ``complete`` requires the backend's own no-more signal AND a total
    consistent with what was actually returned; when results were
    dropped before shaping (e.g. an unrepresentable key) the notice
    reports the gap instead of claiming completeness.
    """
    truncated = has_more is True or (
        total is not None and total > returned
    )
    complete = has_more is False and (total is None or total <= returned)
    if total is not None and total > returned:
        notice = f"Showing {returned} of {total} matches."
    elif has_more is True:
        notice = f"Showing the first {returned} matches; more exist."
    elif has_more is False:
        notice = (
            f"All {returned} matches shown." if returned > 0 else "No matches."
        )
    else:
        notice = (
            f"Showing up to {returned} matches; the backend reports no "
            "match total, so more may exist."
        )
    return {
        "returned": returned,
        "limit": limit,
        "total": total,
        "truncated": truncated,
        "complete": complete,
        "notice": notice,
    }


def _relationship_records(entries) -> list:
    """Uniform relationship records, dropping unsafe or qn-less entries."""
    records = []
    for item in entries:
        if not isinstance(item, dict):
            continue
        raw_qn = item.get("qualified_name")
        if not isinstance(raw_qn, str) or not raw_qn.strip():
            continue
        qn = raw_qn.strip()
        if _is_absolute_any_syntax(qn):
            continue
        records.append({
            "key": qn,
            "name": _optional_text(item.get("name")),
            "qualified_name": qn,
            "hop": _optional_int(item.get("hop")),
            "relationship": _optional_text(item.get("relationship")),
            "direction": _optional_text(item.get("direction")),
            "is_test": _optional_bool(item.get("is_test")),
        })
    return records


def _side_entries(result, side: str) -> list:
    if not isinstance(result, dict):
        return []
    entries = result.get(side)
    return entries if isinstance(entries, list) else []


def _node_side_coverage(adapter_coverage, side: str, records: list) -> dict:
    """Mirror one adapter coverage side and add the honest notice."""
    raw = None
    if isinstance(adapter_coverage, dict):
        candidate = adapter_coverage.get(side)
        if isinstance(candidate, dict):
            raw = candidate
    if raw is None:
        raw = {}
    returned = _optional_int(raw.get("returned"))
    if returned is None or returned < 0:
        returned = len(records)
    limit = _optional_int(raw.get("limit"))
    if limit is None or limit < 1:
        limit = GRAPH_RELATION_DEFAULT_LIMIT
    truncated = raw.get("truncated") is True
    if truncated:
        notice = (
            f"Showing {returned} of up to {limit} {side} relationships; "
            "no authoritative total exists, so more may exist."
        )
    else:
        notice = (
            f"Showing {returned} {side} relationships; no authoritative "
            "total exists, so more may exist."
        )
    return {
        "returned": returned,
        "limit": limit,
        "truncated": truncated,
        "total": None,
        "notice": notice,
    }


def _node_coverage(result, inbound: list, outbound: list, depth: int) -> dict:
    adapter_coverage = None
    if isinstance(result, dict):
        candidate = result.get("coverage")
        if isinstance(candidate, dict):
            adapter_coverage = candidate
    return {
        "depth": depth,
        "include_tests": True,
        "inbound": _node_side_coverage(
            adapter_coverage, "inbound", inbound
        ),
        "outbound": _node_side_coverage(
            adapter_coverage, "outbound", outbound
        ),
        "complete": False,
        "node_caps": {
            "initial": GRAPH_INITIAL_NODE_CAP,
            "expanded": GRAPH_EXPANDED_NODE_CAP,
        },
        "notice": (
            "The bounded graph result may be incomplete. CBM reports no "
            "relationship total, and test-code relationships are included; "
            "nodes marked TEST are identified by CBM. Verify important "
            "claims against current source."
        ),
    }


def _focal_record(
    key: str,
    enriched,
    *,
    project_id: str,
    workspace_id: Optional[str],
) -> dict:
    """The focal node record, enriched best-effort, never invented."""
    name = None
    file_path = None
    label = None
    start_line = end_line = None
    in_degree = out_degree = complexity = lines = None
    is_test = is_exported = is_entry_point = None
    if isinstance(enriched, dict):
        name = _optional_text(enriched.get("name"))
        file_path = _repo_relative_or_none(enriched.get("file_path"))
        label = _optional_text(enriched.get("label"))
        start_line = _optional_int(enriched.get("start_line"))
        end_line = _optional_int(enriched.get("end_line"))
        in_degree = _optional_int(enriched.get("in_degree"))
        out_degree = _optional_int(enriched.get("out_degree"))
        complexity = _optional_int(enriched.get("complexity"))
        lines = _optional_int(enriched.get("lines"))
        is_test = _optional_bool(enriched.get("is_test"))
        is_exported = _optional_bool(enriched.get("is_exported"))
        is_entry_point = _optional_bool(enriched.get("is_entry_point"))
    if not name:
        name = key.rsplit(".", 1)[-1] if key else key
    reference = None
    if file_path is not None:
        try:
            reference = CodeReference(
                project_id=project_id,
                workspace_id=workspace_id,
                reference_kind="symbol",
                file_path=file_path,
                symbol_name=name,
                qualified_name=key,
                symbol_kind=label,
                language=derive_language(file_path),
                start_line=start_line,
                end_line=end_line,
            ).to_dict()
        except CodeRefError:
            reference = None
    return {
        "key": key,
        "name": name,
        "qualified_name": key,
        "file_path": file_path,
        "label": label,
        "start_line": start_line,
        "end_line": end_line,
        "in_degree": in_degree,
        "out_degree": out_degree,
        "complexity": complexity,
        "lines": lines,
        "is_test": is_test,
        "is_exported": is_exported,
        "is_entry_point": is_entry_point,
        "reference": reference,
    }


# -- payloads ----------------------------------------------------------------


def search_payload(kind: str, query: str, limit: int, adapter) -> dict:
    """Shape one bounded search page into the viewer's uniform contract."""
    if kind not in GRAPH_SEARCH_KINDS:
        raise GraphAPIError(
            400, "invalid_kind", "kind must be symbol or file"
        )
    try:
        if kind == "file":
            page = adapter.search_graph_page(file_path=query, limit=limit)
        else:
            page = adapter.search_graph_page(query=query, limit=limit)
    except CBMProjectNotIndexedError as exc:
        raise GraphAPIError(
            409,
            "index_missing",
            _INDEX_MISSING_MESSAGE,
            next_action="relinkra cbm index",
        ) from exc
    except CBMAdapterError as exc:
        raise GraphAPIError(
            502,
            "graph_query_failed",
            _SEARCH_ERROR_MESSAGE,
            next_action=None,
        ) from exc
    raw_results = page.get("results") if isinstance(page, dict) else None
    if not isinstance(raw_results, list):
        raw_results = []
    results = []
    for node in raw_results:
        if not isinstance(node, dict):
            continue
        record = _search_node_record(node)
        if record is not None:
            results.append(record)
    total = page.get("total") if isinstance(page, dict) else None
    total = _optional_int(total)
    if total is not None and total < 0:
        total = None
    has_more = page.get("has_more") if isinstance(page, dict) else None
    has_more = _optional_bool(has_more)
    return {
        "viewer_contract": VIEWER_CONTRACT,
        "kind": kind,
        "query": query,
        "results": results,
        "coverage": _search_coverage(len(results), limit, total, has_more),
    }


def node_payload(
    key: str,
    adapter,
    *,
    project_id: str,
    workspace_id: Optional[str] = None,
    depth: int = GRAPH_DEFAULT_DEPTH,
) -> dict:
    """Shape one bounded focal node neighborhood into the viewer contract.

    The neighborhood call is the only failure surface: a symbol the
    working backend can no longer resolve is a 404-class
    ``symbol_not_found``. The lookup that enriches the focal record is
    best-effort — it degrades to a minimal focal record instead of
    failing an otherwise successful request.
    """
    try:
        result = adapter.graph_neighborhood(
            qualified_name=key, depth=depth, include_tests=True
        )
    except CBMNodeNotFoundError as exc:
        raise GraphAPIError(
            404,
            "symbol_not_found",
            "The symbol is no longer resolvable in the indexed graph.",
            next_action="relinkra cbm refresh",
        ) from exc
    except CBMProjectNotIndexedError as exc:
        # The index disappearing between the gate and the trace is the
        # same honest state as the search route: 409, not an outage.
        raise GraphAPIError(
            409,
            "index_missing",
            _INDEX_MISSING_MESSAGE,
            next_action="relinkra cbm index",
        ) from exc
    except CBMAdapterError as exc:
        raise GraphAPIError(
            502,
            "graph_query_failed",
            _SEARCH_ERROR_MESSAGE,
            next_action=None,
        ) from exc
    try:
        enriched = adapter.graph_node_lookup(key)
    except CBMAdapterError:
        # The neighborhood already succeeded; an enrichment miss must
        # never fail the request.
        enriched = None
    if enriched is not None and not isinstance(enriched, dict):
        enriched = None
    inbound = _relationship_records(_side_entries(result, "inbound"))
    outbound = _relationship_records(_side_entries(result, "outbound"))
    return {
        "viewer_contract": VIEWER_CONTRACT,
        "focal": _focal_record(
            key,
            enriched,
            project_id=project_id,
            workspace_id=workspace_id,
        ),
        "inbound": inbound,
        "outbound": outbound,
        "coverage": _node_coverage(result, inbound, outbound, depth),
    }
