"""VIS-2 viewer graph request validation and response shaping tests.

Pure unit tests: every adapter is a local fake, so no CBM binary, server,
or connection is involved. The payload key sets and coverage notice
strings pinned here are the viewer contract the frontend consumes.
"""

from __future__ import annotations

import json
import unittest

from relinkra import viewer_graph
from relinkra.cbm_adapter import (
    CBMAdapterError,
    CBMNodeNotFoundError,
    CBMProjectNotIndexedError,
)
from relinkra.code_reference import CODE_REF_ID_RE

SLUG = "C-Desarrollos-relinkra-ws"
PID = "rlk_" + "a" * 32
WID = "ws_" + "b" * 32
KEY = "relinkra.cbm_adapter.CBMCLIAdapter"

SEARCH_KEYS = {
    "key",
    "name",
    "qualified_name",
    "file_path",
    "label",
    "start_line",
    "end_line",
    "in_degree",
    "out_degree",
    "complexity",
    "lines",
    "is_test",
    "is_exported",
    "is_entry_point",
}

FOCAL_KEYS = SEARCH_KEYS | {"reference"}

RELATIONSHIP_KEYS = {
    "key",
    "name",
    "qualified_name",
    "hop",
    "relationship",
    "direction",
    "is_test",
}


def _candidate(**overrides):
    candidate = {
        "name": "func",
        "qualified_name": f"{SLUG}.relinkra.x.func",
        "relative_qualified_name": "relinkra.x.func",
        "label": "Function",
        "file_path": "relinkra/x.py",
        "start_line": 3,
        "end_line": 9,
        "is_test": True,
        "is_exported": False,
        "is_entry_point": True,
        "in_degree": 2,
        "out_degree": 4,
        "complexity": 7,
        "lines": 12,
        "cbm_project_name": SLUG,
        "docstring": "raw source text",
        "fp": "internal",
    }
    candidate.update(overrides)
    return candidate


def _neighborhood(**overrides):
    payload = {
        "target": "relinkra.x.func",
        "depth": 1,
        "include_tests": True,
        "inbound": [
            {
                "relationship": "caller",
                "name": "caller",
                "qualified_name": "relinkra.a.caller",
                "hop": 1,
                "direction": "inbound",
                "is_test": True,
            }
        ],
        "outbound": [
            {
                "relationship": "dependency",
                "name": "dep",
                "qualified_name": "relinkra.b.dep",
                "hop": 1,
                "direction": "outbound",
            }
        ],
        "coverage": {
            "depth": 1,
            "include_tests": True,
            "inbound": {
                "returned": 1,
                "limit": 20,
                "truncated": False,
                "total": None,
            },
            "outbound": {
                "returned": 1,
                "limit": 20,
                "truncated": False,
                "total": None,
            },
            "complete": False,
        },
    }
    payload.update(overrides)
    return payload


class FakeSearchAdapter:
    def __init__(self, page=None, error=None):
        self.calls = []
        self.page = page if page is not None else {
            "results": [],
            "total": 0,
            "has_more": False,
        }
        self.error = error

    def search_graph_page(self, *, query=None, file_path=None, limit=20):
        self.calls.append(
            {"query": query, "file_path": file_path, "limit": limit}
        )
        if self.error is not None:
            raise self.error
        return self.page


class FakeNodeAdapter:
    def __init__(
        self,
        neighborhood=None,
        lookup=None,
        neighborhood_error=None,
        lookup_error=None,
    ):
        self.neighborhood_calls = []
        self.lookup_calls = []
        self.neighborhood = (
            neighborhood if neighborhood is not None else _neighborhood()
        )
        self.lookup = lookup
        self.neighborhood_error = neighborhood_error
        self.lookup_error = lookup_error

    def graph_neighborhood(
        self,
        *,
        qualified_name,
        depth=1,
        include_tests=True,
        inbound_limit=20,
        outbound_limit=20,
    ):
        self.neighborhood_calls.append(
            {
                "qualified_name": qualified_name,
                "depth": depth,
                "include_tests": include_tests,
            }
        )
        if self.neighborhood_error is not None:
            raise self.neighborhood_error
        return self.neighborhood

    def graph_node_lookup(self, relative_qualified_name, *, project=None, limit=50):
        self.lookup_calls.append(relative_qualified_name)
        if self.lookup_error is not None:
            raise self.lookup_error
        return self.lookup


class ParseSearchParamsTests(unittest.TestCase):
    def assert_rejection(self, params, code, message):
        with self.assertRaises(viewer_graph.GraphAPIError) as ctx:
            viewer_graph.parse_search_params(params)
        error = ctx.exception
        self.assertEqual(error.status, 400)
        self.assertEqual(error.code, code)
        self.assertEqual(error.message, message)
        self.assertIsNone(error.next_action)
        self.assertEqual(
            error.to_dict(),
            {"error": code, "message": message, "next_action": None},
        )

    def test_missing_and_blank_queries_are_rejected(self):
        for params in ({}, {"q": [""]}, {"q": ["   "]}):
            with self.subTest(params=params):
                self.assert_rejection(
                    params,
                    "missing_query",
                    "a non-empty q parameter is required",
                )

    def test_query_length_boundary(self):
        query, _, _ = viewer_graph.parse_search_params({"q": ["x" * 200]})
        self.assertEqual(len(query), 200)
        self.assert_rejection(
            {"q": ["x" * 201]},
            "query_too_long",
            "q must be at most 200 characters",
        )

    def test_kind_defaults_to_symbol_and_validates(self):
        _, kind, _ = viewer_graph.parse_search_params({"q": ["x"]})
        self.assertEqual(kind, "symbol")
        _, kind, _ = viewer_graph.parse_search_params(
            {"q": ["x"], "kind": ["file"]}
        )
        self.assertEqual(kind, "file")
        self.assert_rejection(
            {"q": ["x"], "kind": ["caller"]},
            "invalid_kind",
            "kind must be symbol or file",
        )

    def test_limit_defaults_and_validates(self):
        _, _, limit = viewer_graph.parse_search_params({"q": ["x"]})
        self.assertEqual(limit, 20)
        for value, expected in (("1", 1), ("20", 20)):
            _, _, limit = viewer_graph.parse_search_params(
                {"q": ["x"], "limit": [value]}
            )
            self.assertEqual(limit, expected)
        for value in ("0", "21", "abc", "1.5", ""):
            with self.subTest(limit=value):
                self.assert_rejection(
                    {"q": ["x"], "limit": [value]},
                    "invalid_limit",
                    "limit must be an integer between 1 and 20",
                )

    def test_first_repeated_value_wins(self):
        query, kind, limit = viewer_graph.parse_search_params(
            {
                "q": ["first", "second"],
                "kind": ["file", "symbol"],
                "limit": ["5", "9"],
            }
        )
        self.assertEqual(query, "first")
        self.assertEqual(kind, "file")
        self.assertEqual(limit, 5)

    def test_query_is_stripped(self):
        query, _, _ = viewer_graph.parse_search_params({"q": ["  widget  "]})
        self.assertEqual(query, "widget")


class ParseNodeParamsTests(unittest.TestCase):
    def assert_rejection(self, params, code, message):
        with self.assertRaises(viewer_graph.GraphAPIError) as ctx:
            viewer_graph.parse_node_params(params)
        error = ctx.exception
        self.assertEqual(error.status, 400)
        self.assertEqual(error.code, code)
        self.assertEqual(error.message, message)

    def test_missing_and_blank_keys_are_rejected(self):
        for params in ({}, {"key": [""]}, {"key": ["   "]}):
            with self.subTest(params=params):
                self.assert_rejection(
                    params,
                    "missing_key",
                    "a non-empty key parameter is required",
                )

    def test_key_length_boundary(self):
        self.assertEqual(
            viewer_graph.parse_node_params({"key": ["k" * 300]}), "k" * 300
        )
        self.assert_rejection(
            {"key": ["k" * 301]},
            "key_too_long",
            "key must be at most 300 characters",
        )

    def test_control_characters_are_rejected(self):
        for key in ("bad\u0001key", "bad\x7fkey", "a\tb"):
            with self.subTest(key=key):
                self.assert_rejection(
                    {"key": [key]},
                    "invalid_key",
                    "key contains control characters",
                )

    def test_absolute_path_shapes_are_rejected_as_keys(self):
        for key in ("C:/secret/x.py", "D:\\secret\\x.py", "/etc/passwd", "\\\\srv\\share"):
            with self.subTest(key=key):
                self.assert_rejection(
                    {"key": [key]},
                    "invalid_key",
                    "key must be a project-relative qualified name",
                )

    def test_first_repeated_value_wins(self):
        self.assertEqual(
            viewer_graph.parse_node_params({"key": ["a.b", "c.d"]}), "a.b"
        )


class SearchPayloadTests(unittest.TestCase):
    def test_result_records_have_exactly_the_uniform_keys(self):
        adapter = FakeSearchAdapter(
            page={"results": [_candidate()], "total": 1, "has_more": False}
        )
        payload = viewer_graph.search_payload("symbol", "func", 5, adapter)
        self.assertEqual(
            set(payload), {"viewer_contract", "kind", "query", "results", "coverage"}
        )
        self.assertEqual(payload["viewer_contract"], "relinkra.viewer/v1")
        record = payload["results"][0]
        self.assertEqual(set(record), SEARCH_KEYS)
        self.assertEqual(record["key"], "relinkra.x.func")
        self.assertEqual(record["qualified_name"], "relinkra.x.func")
        self.assertEqual(record["name"], "func")
        self.assertEqual(record["file_path"], "relinkra/x.py")
        self.assertEqual(record["label"], "Function")
        self.assertEqual(record["start_line"], 3)
        self.assertEqual(record["end_line"], 9)
        self.assertEqual(record["in_degree"], 2)
        self.assertEqual(record["out_degree"], 4)
        self.assertEqual(record["complexity"], 7)
        self.assertEqual(record["lines"], 12)
        self.assertIs(record["is_test"], True)
        self.assertIs(record["is_exported"], False)
        self.assertIs(record["is_entry_point"], True)
        self.assertNotIn("docstring", record)
        self.assertNotIn("fp", record)

    def test_missing_optionals_become_none(self):
        adapter = FakeSearchAdapter(
            page={
                "results": [{"relative_qualified_name": "a.b"}],
                "total": 1,
                "has_more": False,
            }
        )
        record = viewer_graph.search_payload("symbol", "b", 5, adapter)[
            "results"
        ][0]
        self.assertEqual(set(record), SEARCH_KEYS)
        for key in SEARCH_KEYS - {"key", "qualified_name"}:
            self.assertIsNone(record[key], key)

    def test_absolute_file_paths_are_dropped_under_any_syntax(self):
        for path in ("C:/work/x.py", "D:\\work\\x.py", "/work/x.py", "\\\\srv\\x.py"):
            with self.subTest(path=path):
                adapter = FakeSearchAdapter(
                    page={
                        "results": [
                            _candidate(relative_qualified_name="a.b", file_path=path)
                        ],
                        "total": 1,
                        "has_more": False,
                    }
                )
                record = viewer_graph.search_payload(
                    "symbol", "b", 5, adapter
                )["results"][0]
                self.assertIsNone(record["file_path"])

    def test_absolute_qualified_names_are_excluded_and_reported(self):
        adapter = FakeSearchAdapter(
            page={
                "results": [
                    _candidate(relative_qualified_name="C:/secret/x.py"),
                    _candidate(relative_qualified_name="relinkra.x.func"),
                ],
                "total": 2,
                "has_more": False,
            }
        )
        payload = viewer_graph.search_payload("symbol", "func", 20, adapter)
        self.assertEqual(
            [record["key"] for record in payload["results"]],
            ["relinkra.x.func"],
        )
        coverage = payload["coverage"]
        self.assertEqual(coverage["returned"], 1)
        self.assertEqual(coverage["notice"], "Showing 1 of 2 matches.")
        self.assertIs(coverage["complete"], False)
        self.assertNotIn("secret", json.dumps(payload, sort_keys=True))

    def test_kind_routes_to_the_matching_adapter_call(self):
        adapter = FakeSearchAdapter()
        viewer_graph.search_payload("file", "relinkra/viewer", 7, adapter)
        self.assertEqual(
            adapter.calls[0], {"query": None, "file_path": "relinkra/viewer", "limit": 7}
        )
        viewer_graph.search_payload("symbol", "widget", 3, adapter)
        self.assertEqual(
            adapter.calls[1], {"query": "widget", "file_path": None, "limit": 3}
        )

    def test_unknown_kind_is_rejected(self):
        with self.assertRaises(viewer_graph.GraphAPIError) as ctx:
            viewer_graph.search_payload("caller", "x", 5, FakeSearchAdapter())
        self.assertEqual(ctx.exception.status, 400)
        self.assertEqual(ctx.exception.code, "invalid_kind")

    def test_coverage_notices_for_the_four_count_states(self):
        cases = (
            (True, 5, "Showing 1 of 5 matches."),
            (True, None, "Showing the first 1 matches; more exist."),
            # has_more False with a larger authoritative total means
            # results were dropped before shaping: the notice reports the
            # gap instead of claiming completeness.
            (False, 3, "Showing 1 of 3 matches."),
            (None, None, "Showing up to 1 matches; the backend reports no match total, so more may exist."),
        )
        for has_more, total, notice in cases:
            with self.subTest(has_more=has_more, total=total):
                adapter = FakeSearchAdapter(
                    page={
                        "results": [_candidate()],
                        "total": total,
                        "has_more": has_more,
                    }
                )
                coverage = viewer_graph.search_payload(
                    "symbol", "func", 20, adapter
                )["coverage"]
                self.assertEqual(coverage["notice"], notice)
                self.assertEqual(coverage["returned"], 1)
                self.assertEqual(coverage["limit"], 20)
                self.assertEqual(coverage["total"], total)

    def test_empty_coverage_never_claims_absence_without_a_total(self):
        cases = (
            (False, 0, "No matches."),
            (False, 2, "Showing 0 of 2 matches."),
            (
                None,
                None,
                "Showing up to 0 matches; the backend reports no match "
                "total, so more may exist.",
            ),
        )
        for has_more, total, notice in cases:
            with self.subTest(has_more=has_more, total=total):
                adapter = FakeSearchAdapter(
                    page={"results": [], "total": total, "has_more": has_more}
                )
                coverage = viewer_graph.search_payload(
                    "symbol", "func", 20, adapter
                )["coverage"]
                self.assertEqual(coverage["notice"], notice)
                self.assertEqual(coverage["returned"], 0)

    def test_truncated_and_complete_truth_table(self):
        cases = (
            (False, 1, False, True),
            # Dropped-but-unreported results keep complete False.
            (False, 3, True, False),
            (True, 5, True, False),
            (True, None, True, False),
            (None, None, False, False),
            (False, 5, True, False),
            (False, 0, False, True),
        )
        for has_more, total, truncated, complete in cases:
            with self.subTest(has_more=has_more, total=total):
                adapter = FakeSearchAdapter(
                    page={
                        "results": [_candidate()],
                        "total": total,
                        "has_more": has_more,
                    }
                )
                coverage = viewer_graph.search_payload(
                    "symbol", "func", 20, adapter
                )["coverage"]
                self.assertIs(coverage["truncated"], truncated)
                self.assertIs(coverage["complete"], complete)

    def test_not_indexed_maps_to_409(self):
        adapter = FakeSearchAdapter(error=CBMProjectNotIndexedError("absent"))
        with self.assertRaises(viewer_graph.GraphAPIError) as ctx:
            viewer_graph.search_payload("symbol", "x", 5, adapter)
        error = ctx.exception
        self.assertEqual(error.status, 409)
        self.assertEqual(error.code, "index_missing")
        self.assertEqual(
            error.message, "The CBM index is missing for this workspace."
        )
        self.assertEqual(error.next_action, "relinkra cbm index")

    def test_adapter_failure_maps_to_502(self):
        adapter = FakeSearchAdapter(
            error=CBMAdapterError("raw backend detail C:\\secret")
        )
        with self.assertRaises(viewer_graph.GraphAPIError) as ctx:
            viewer_graph.search_payload("symbol", "x", 5, adapter)
        error = ctx.exception
        self.assertEqual(error.status, 502)
        self.assertEqual(error.code, "graph_query_failed")
        self.assertEqual(error.message, "The CBM graph query failed.")
        self.assertIsNone(error.next_action)
        self.assertNotIn("secret", error.message)

    def test_serialization_is_deterministic(self):
        def build():
            adapter = FakeSearchAdapter(
                page={"results": [_candidate()], "total": 2, "has_more": True}
            )
            return viewer_graph.search_payload("symbol", "func", 5, adapter)

        self.assertEqual(
            json.dumps(build(), sort_keys=True),
            json.dumps(build(), sort_keys=True),
        )


class NodePayloadTests(unittest.TestCase):
    def test_focal_enrichment_and_reference(self):
        adapter = FakeNodeAdapter(lookup=_candidate())
        payload = viewer_graph.node_payload(
            KEY, adapter, project_id=PID, workspace_id=WID
        )
        self.assertEqual(
            set(payload),
            {"viewer_contract", "focal", "inbound", "outbound", "coverage"},
        )
        focal = payload["focal"]
        self.assertEqual(set(focal), FOCAL_KEYS)
        self.assertEqual(focal["key"], KEY)
        self.assertEqual(focal["qualified_name"], KEY)
        self.assertEqual(focal["name"], "func")
        self.assertEqual(focal["file_path"], "relinkra/x.py")
        self.assertEqual(focal["label"], "Function")
        self.assertEqual(focal["start_line"], 3)
        self.assertEqual(focal["in_degree"], 2)
        self.assertIs(focal["is_test"], True)
        reference = focal["reference"]
        self.assertIsNotNone(reference)
        self.assertRegex(reference["code_reference_id"], r"^ref_[0-9a-f]{32}$")
        self.assertTrue(CODE_REF_ID_RE.fullmatch(reference["code_reference_id"]))
        self.assertEqual(reference["project_id"], PID)
        self.assertEqual(reference["workspace_id"], WID)
        self.assertEqual(reference["reference_kind"], "symbol")
        self.assertEqual(reference["file_path"], "relinkra/x.py")
        self.assertEqual(reference["qualified_name"], KEY)
        self.assertEqual(reference["language"], "python")

    def test_enrichment_failure_degrades_to_a_minimal_focal(self):
        adapter = FakeNodeAdapter(
            lookup_error=CBMAdapterError("lookup exploded")
        )
        payload = viewer_graph.node_payload(
            KEY, adapter, project_id=PID, workspace_id=WID
        )
        focal = payload["focal"]
        self.assertEqual(focal["name"], "CBMCLIAdapter")
        self.assertEqual(focal["key"], KEY)
        self.assertIsNone(focal["reference"])
        for key in FOCAL_KEYS - {"key", "name", "qualified_name"}:
            self.assertIsNone(focal[key], key)

    def test_missing_enrichment_degrades_to_a_minimal_focal(self):
        adapter = FakeNodeAdapter(lookup=None)
        focal = viewer_graph.node_payload(
            KEY, adapter, project_id=PID
        )["focal"]
        self.assertEqual(focal["name"], "CBMCLIAdapter")
        self.assertIsNone(focal["reference"])

    def test_absolute_enriched_path_yields_no_reference(self):
        adapter = FakeNodeAdapter(
            lookup=_candidate(file_path="C:/work/relinkra/x.py")
        )
        focal = viewer_graph.node_payload(
            KEY, adapter, project_id=PID
        )["focal"]
        self.assertIsNone(focal["file_path"])
        self.assertIsNone(focal["reference"])

    def test_neighborhood_is_called_with_bounded_defaults(self):
        adapter = FakeNodeAdapter(lookup=None)
        viewer_graph.node_payload(KEY, adapter, project_id=PID)
        self.assertEqual(
            adapter.neighborhood_calls,
            [{"qualified_name": KEY, "depth": 1, "include_tests": True}],
        )
        self.assertEqual(adapter.lookup_calls, [KEY])

    def test_relationship_records_are_uniform(self):
        payload = viewer_graph.node_payload(
            KEY, FakeNodeAdapter(lookup=None), project_id=PID
        )
        self.assertEqual(set(payload["inbound"][0]), RELATIONSHIP_KEYS)
        self.assertEqual(set(payload["outbound"][0]), RELATIONSHIP_KEYS)
        inbound = payload["inbound"][0]
        self.assertEqual(inbound["key"], "relinkra.a.caller")
        self.assertEqual(inbound["qualified_name"], "relinkra.a.caller")
        self.assertEqual(inbound["hop"], 1)
        self.assertEqual(inbound["relationship"], "caller")
        self.assertEqual(inbound["direction"], "inbound")
        self.assertIs(inbound["is_test"], True)
        self.assertIsNone(payload["outbound"][0]["is_test"])

    def test_absolute_relationship_qns_are_skipped(self):
        neighborhood = _neighborhood()
        neighborhood["inbound"] = neighborhood["inbound"] + [
            {
                "relationship": "caller",
                "name": "leak",
                "qualified_name": "C:/secret/x.py",
                "hop": 1,
                "direction": "inbound",
            }
        ]
        payload = viewer_graph.node_payload(
            KEY, FakeNodeAdapter(neighborhood=neighborhood, lookup=None),
            project_id=PID,
        )
        self.assertEqual(
            [item["key"] for item in payload["inbound"]],
            ["relinkra.a.caller"],
        )
        self.assertNotIn("secret", json.dumps(payload, sort_keys=True))

    def test_per_side_coverage_notices(self):
        neighborhood = _neighborhood()
        neighborhood["coverage"]["inbound"] = {
            "returned": 20,
            "limit": 20,
            "truncated": True,
            "total": None,
        }
        payload = viewer_graph.node_payload(
            KEY, FakeNodeAdapter(neighborhood=neighborhood, lookup=None),
            project_id=PID,
        )
        coverage = payload["coverage"]
        self.assertEqual(
            coverage["inbound"]["notice"],
            "Showing 20 of up to 20 inbound relationships; no authoritative "
            "total exists, so more may exist.",
        )
        self.assertEqual(
            coverage["outbound"]["notice"],
            "Showing 1 outbound relationships; no authoritative total "
            "exists, so more may exist.",
        )
        self.assertIs(coverage["inbound"]["truncated"], True)
        self.assertIs(coverage["outbound"]["truncated"], False)
        self.assertIsNone(coverage["inbound"]["total"])

    def test_coverage_reports_caps_and_an_honest_overall_notice(self):
        coverage = viewer_graph.node_payload(
            KEY, FakeNodeAdapter(lookup=None), project_id=PID
        )["coverage"]
        self.assertEqual(coverage["depth"], 1)
        self.assertIs(coverage["include_tests"], True)
        self.assertEqual(coverage["node_caps"], {"initial": 50, "expanded": 100})
        self.assertIs(coverage["complete"], False)
        self.assertEqual(
            coverage["notice"],
            "The bounded graph result may be incomplete. CBM reports no "
            "relationship total, and test-code relationships are included; "
            "nodes marked TEST are identified by CBM. Verify important "
            "claims against current source.",
        )

    def test_symbol_not_found_maps_to_404(self):
        adapter = FakeNodeAdapter(
            neighborhood_error=CBMNodeNotFoundError("gone")
        )
        with self.assertRaises(viewer_graph.GraphAPIError) as ctx:
            viewer_graph.node_payload(KEY, adapter, project_id=PID)
        error = ctx.exception
        self.assertEqual(error.status, 404)
        self.assertEqual(error.code, "symbol_not_found")
        self.assertEqual(
            error.message,
            "The symbol is no longer resolvable in the indexed graph.",
        )
        self.assertEqual(error.next_action, "relinkra cbm refresh")

    def test_not_indexed_maps_to_409_not_an_outage(self):
        adapter = FakeNodeAdapter(
            neighborhood_error=CBMProjectNotIndexedError("absent")
        )
        with self.assertRaises(viewer_graph.GraphAPIError) as ctx:
            viewer_graph.node_payload(KEY, adapter, project_id=PID)
        error = ctx.exception
        self.assertEqual(error.status, 409)
        self.assertEqual(error.code, "index_missing")
        self.assertEqual(error.next_action, "relinkra cbm index")

    def test_backend_failure_maps_to_502(self):
        adapter = FakeNodeAdapter(
            neighborhood_error=CBMAdapterError("raw backend detail")
        )
        with self.assertRaises(viewer_graph.GraphAPIError) as ctx:
            viewer_graph.node_payload(KEY, adapter, project_id=PID)
        self.assertEqual(ctx.exception.status, 502)
        self.assertEqual(ctx.exception.code, "graph_query_failed")

    def test_payload_never_contains_raw_source_fields(self):
        adapter = FakeNodeAdapter(lookup=_candidate())
        payload = viewer_graph.node_payload(
            KEY, adapter, project_id=PID, workspace_id=WID
        )
        text = json.dumps(payload, sort_keys=True)
        self.assertNotIn("docstring", text)
        self.assertNotIn("raw source text", text)
        self.assertNotIn(SLUG, text)


if __name__ == "__main__":
    unittest.main()
