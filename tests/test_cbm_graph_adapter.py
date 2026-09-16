"""VIS-2 bounded graph-explorer adapter tests.

Hermetic: every CBM subprocess is mocked, so no real binary, cache, or
network is touched. These tests pin the certified 0.9.0 shapes the
adapter builds against: rich search rows, the both-direction trace
split, the exact-match node lookup, and the additive normalization of
the rich search fields.
"""

from __future__ import annotations

import json
import subprocess
import unittest
from unittest import mock

from relinkra.cbm_adapter import (
    CBMAdapterError,
    CBMNodeNotFoundError,
    CBMProjectNotIndexedError,
    CBMCLIAdapter,
    GRAPH_NODE_MAX_PAYLOAD_BYTES,
    _TRACE_NOT_FOUND_RE,
)

SLUG = "C-Desarrollos-relinkra-ws"
REL = "relinkra.cbm_adapter.CBMCLIAdapter"
FULL = f"{SLUG}.{REL}"

BASE_NODE_KEYS = {
    "name",
    "qualified_name",
    "relative_qualified_name",
    "label",
    "file_path",
    "start_line",
    "end_line",
    "cbm_project_name",
}

RICH_NODE_KEYS = {"is_test", "in_degree", "out_degree", "complexity", "lines",
                  "is_exported", "is_entry_point"}


def _completed(rc=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(
        args=["cbm"], returncode=rc, stdout=stdout, stderr=stderr
    )


def _search_payload(*nodes, total=None, has_more=False):
    return json.dumps(
        {
            "total": total if total is not None else len(nodes),
            "results": list(nodes),
            "has_more": has_more,
        }
    )


def _node(qn_suffix, file_path, name=None, label="Function", start=10, end=20):
    return {
        "name": name or qn_suffix.rsplit(".", 1)[-1],
        "qualified_name": f"{SLUG}.{qn_suffix}",
        "label": label,
        "file_path": file_path,
        "start_line": start,
        "end_line": end,
    }


def _rich_node(qn_suffix, file_path=None, **fields):
    node = _node(qn_suffix, file_path or f"relinkra/{qn_suffix.replace('.', '/')}.py")
    node.update(fields)
    return node


def _adapter(**overrides):
    defaults = dict(
        cbm_bin="cbm.exe",
        cache_dir="cache",
        cbm_project_name=SLUG,
        workspace_root="C:/Desarrollos/relinkra",
    )
    defaults.update(overrides)
    return CBMCLIAdapter(**defaults)


def _trace_payload(**overrides):
    payload = {
        "function": FULL,
        "direction": "both",
        "mode": "calls",
        "callers": [
            {
                "name": "Caller",
                "qualified_name": f"{SLUG}.src.a.caller",
                "hop": 1,
            }
        ],
        "callees": [
            {
                "name": "Callee",
                "qualified_name": f"{SLUG}.src.b.callee",
                "hop": 1,
            }
        ],
    }
    payload.update(overrides)
    return payload


class GraphSearchPageTests(unittest.TestCase):
    def test_symbol_search_normalizes_results_and_flags(self):
        node = _rich_node(
            "relinkra.x.func",
            is_test=True,
            is_exported=False,
            is_entry_point=True,
            in_degree=3,
            out_degree=4,
            complexity=7,
            lines=12,
        )
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(
                stdout=_search_payload(node, total=4, has_more=True)
            ),
        ) as run:
            page = _adapter().search_graph_page(query="func", limit=7)
        argv = run.call_args[0][0]
        self.assertEqual(
            argv,
            [
                "cbm.exe",
                "cli",
                "search_graph",
                "--project",
                SLUG,
                "--limit",
                "7",
                "--query",
                "func",
            ],
        )
        self.assertIs(run.call_args.kwargs["shell"], False)
        self.assertEqual(page["total"], 4)
        self.assertIs(page["has_more"], True)
        candidate = page["results"][0]
        self.assertEqual(candidate["relative_qualified_name"], "relinkra.x.func")
        self.assertEqual(candidate["is_test"], True)
        self.assertEqual(candidate["is_exported"], False)
        self.assertEqual(candidate["is_entry_point"], True)
        self.assertEqual(candidate["in_degree"], 3)
        self.assertEqual(candidate["out_degree"], 4)
        self.assertEqual(candidate["complexity"], 7)
        self.assertEqual(candidate["lines"], 12)

    def test_file_search_uses_the_path_filter_without_query(self):
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(stdout=_search_payload()),
        ) as run:
            page = _adapter().search_graph_page(file_path="relinkra/viewer")
        argv = run.call_args[0][0]
        self.assertEqual(
            argv,
            [
                "cbm.exe",
                "cli",
                "search_graph",
                "--project",
                SLUG,
                "--limit",
                "20",
                "--file-pattern",
                "relinkra/viewer",
            ],
        )
        self.assertNotIn("--query", argv)
        self.assertEqual(page["results"], [])

    def test_limits_outside_1_to_20_are_rejected_without_execution(self):
        for value in (0, 21, True, "junk"):
            with self.subTest(limit=value):
                with mock.patch(
                    "relinkra.cbm_adapter.subprocess.run"
                ) as run:
                    with self.assertRaises(CBMAdapterError):
                        _adapter().search_graph_page(query="x", limit=value)
                run.assert_not_called()

    def test_exactly_one_of_query_or_file_path_is_required(self):
        with mock.patch("relinkra.cbm_adapter.subprocess.run") as run:
            with self.assertRaises(CBMAdapterError):
                _adapter().search_graph_page()
            with self.assertRaises(CBMAdapterError):
                _adapter().search_graph_page(query="a", file_path="b")
        run.assert_not_called()

    def test_missing_counts_degrade_to_none(self):
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(
                stdout=json.dumps({"results": [_node("a.b", "a/b.py")]})
            ),
        ):
            page = _adapter().search_graph_page(query="b")
        self.assertIsNone(page["total"])
        self.assertIsNone(page["has_more"])

    def test_malformed_counts_degrade_to_none(self):
        payload = json.dumps(
            {
                "total": "5",
                "has_more": "yes",
                "results": [_node("a.b", "a/b.py")],
            }
        )
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(stdout=payload),
        ):
            page = _adapter().search_graph_page(query="b")
        self.assertIsNone(page["total"])
        self.assertIsNone(page["has_more"])

    def test_negative_total_degrades_to_none(self):
        payload = json.dumps(
            {"total": -1, "has_more": True, "results": []}
        )
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(stdout=payload),
        ):
            page = _adapter().search_graph_page(query="b")
        self.assertIsNone(page["total"])
        self.assertIs(page["has_more"], True)

    def test_malformed_results_are_rejected(self):
        for payload in (
            json.dumps({"results": "nope"}),
            json.dumps({"results": [1]}),
            json.dumps([1, 2]),
            json.dumps({"error": "boom", "results": []}),
        ):
            with self.subTest(payload=payload):
                with mock.patch(
                    "relinkra.cbm_adapter.subprocess.run",
                    return_value=_completed(stdout=payload),
                ):
                    with self.assertRaises(CBMAdapterError):
                        _adapter().search_graph_page(query="x")

    def test_not_indexed_envelope_is_classified(self):
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(
                rc=1, stderr='{"error":"project not found or not indexed"}'
            ),
        ):
            with self.assertRaises(CBMProjectNotIndexedError):
                _adapter().search_graph_page(query="x")

    def test_results_without_relative_qn_are_excluded(self):
        nodes = [
            {"name": "proj", "qualified_name": SLUG, "file_path": "relinkra/x.py"},
            {"name": "empty", "qualified_name": "", "file_path": "relinkra/y.py"},
        ]
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(stdout=_search_payload(*nodes)),
        ):
            page = _adapter().search_graph_page(query="x")
        self.assertEqual(page["results"], [])

    def test_project_relative_identity_never_embeds_the_slug(self):
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(
                stdout=_search_payload(_rich_node("relinkra.x.func"))
            ),
        ):
            page = _adapter().search_graph_page(query="func")
        candidate = page["results"][0]
        self.assertEqual(candidate["relative_qualified_name"], "relinkra.x.func")
        self.assertFalse(
            candidate["relative_qualified_name"].startswith(SLUG)
        )
        # The slug survives ONLY as the recorded resolution metadata the
        # historical normalizer has always carried; the viewer never
        # copies it into a payload.
        self.assertEqual(candidate["cbm_project_name"], SLUG)

    def test_absolute_paths_are_relativized_only_under_the_workspace_root(self):
        inside = _node("relinkra.x.func", "C:/Desarrollos/relinkra/relinkra/x.py")
        foreign = _node("relinkra.y.other", "D:/foreign/other.py")
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(stdout=_search_payload(inside, foreign)),
        ):
            page = _adapter().search_graph_page(query="x")
        by_name = {item["name"]: item for item in page["results"]}
        self.assertEqual(by_name["func"]["file_path"], "relinkra/x.py")
        # A foreign-syntax absolute path is NOT silently rewritten: the
        # adapter keeps it as-is and the viewer API filters it later.
        self.assertEqual(by_name["other"]["file_path"], "D:/foreign/other.py")

    def test_metacharacter_query_stays_one_argv_element(self):
        hostile = "x; rm -rf / $(boom) `id`"
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(stdout=_search_payload()),
        ) as run:
            _adapter().search_graph_page(query=hostile)
        argv = run.call_args[0][0]
        self.assertEqual(argv[argv.index("--query") + 1], hostile)
        self.assertIsInstance(argv, list)
        self.assertIs(run.call_args.kwargs["shell"], False)


class GraphNeighborhoodTests(unittest.TestCase):
    def test_neighborhood_uses_one_exact_trace_invocation(self):
        adapter = _adapter()
        with mock.patch.object(
            adapter, "_run_or_classify", return_value=_trace_payload()
        ) as run:
            adapter.graph_neighborhood(qualified_name=REL)
        run.assert_called_once_with(
            "trace_path",
            [
                "--project", SLUG,
                "--function-name", FULL,
                "--direction", "both",
                "--depth", "1",
                "--mode", "calls",
                "--include-tests", "true",
            ],
        )

    def test_inbound_outbound_split_carries_direction_labels(self):
        adapter = _adapter()
        with mock.patch.object(
            adapter, "_run_or_classify", return_value=_trace_payload()
        ):
            result = adapter.graph_neighborhood(qualified_name=REL)
        self.assertEqual(result["target"], REL)
        self.assertEqual(result["inbound"][0]["relationship"], "caller")
        self.assertEqual(result["inbound"][0]["direction"], "inbound")
        self.assertEqual(result["outbound"][0]["relationship"], "dependency")
        self.assertEqual(result["outbound"][0]["direction"], "outbound")
        self.assertEqual(result["coverage"]["inbound"]["total"], None)
        self.assertEqual(result["coverage"]["outbound"]["total"], None)
        self.assertIs(result["coverage"]["complete"], False)

    def test_per_side_caps_truncate_at_twenty(self):
        callers = [
            {"name": f"C{i}", "qualified_name": f"{SLUG}.src.c{i}", "hop": 1}
            for i in range(21)
        ]
        callees = [
            {"name": f"D{i}", "qualified_name": f"{SLUG}.src.d{i}", "hop": 1}
            for i in range(21)
        ]
        adapter = _adapter()
        with mock.patch.object(
            adapter,
            "_run_or_classify",
            return_value=_trace_payload(callers=callers, callees=callees),
        ):
            result = adapter.graph_neighborhood(qualified_name=REL)
        self.assertEqual(len(result["inbound"]), 20)
        self.assertEqual(len(result["outbound"]), 20)
        self.assertIs(result["coverage"]["inbound"]["truncated"], True)
        self.assertIs(result["coverage"]["outbound"]["truncated"], True)
        self.assertEqual(result["coverage"]["inbound"]["limit"], 20)

    def test_is_test_is_preserved_only_when_true(self):
        callers = [
            {
                "name": "T",
                "qualified_name": f"{SLUG}.tests.test_t",
                "hop": 1,
                "is_test": True,
            },
            {
                "name": "F",
                "qualified_name": f"{SLUG}.src.f",
                "hop": 1,
                "is_test": False,
            },
            {"name": "U", "qualified_name": f"{SLUG}.src.u", "hop": 1},
        ]
        adapter = _adapter()
        with mock.patch.object(
            adapter,
            "_run_or_classify",
            return_value=_trace_payload(callers=callers),
        ):
            result = adapter.graph_neighborhood(qualified_name=REL)
        by_name = {item["name"]: item for item in result["inbound"]}
        self.assertIs(by_name["T"]["is_test"], True)
        self.assertNotIn("is_test", by_name["F"])
        self.assertNotIn("is_test", by_name["U"])

    def test_invalid_hops_are_rejected(self):
        for hop in (0, 4):
            with self.subTest(hop=hop):
                adapter = _adapter()
                callers = [
                    {
                        "name": "X",
                        "qualified_name": f"{SLUG}.src.x",
                        "hop": hop,
                    }
                ]
                with mock.patch.object(
                    adapter,
                    "_run_or_classify",
                    return_value=_trace_payload(callers=callers),
                ):
                    with self.assertRaises(CBMAdapterError):
                        adapter.graph_neighborhood(
                            qualified_name=REL, depth=3
                        )

    def test_mismatched_function_direction_or_mode_is_rejected(self):
        variants = (
            {"function": "other.Target.run"},
            {"direction": "inbound"},
            {"mode": "types"},
        )
        for overrides in variants:
            with self.subTest(overrides=overrides):
                adapter = _adapter()
                with mock.patch.object(
                    adapter,
                    "_run_or_classify",
                    return_value=_trace_payload(**overrides),
                ):
                    with self.assertRaises(CBMAdapterError):
                        adapter.graph_neighborhood(qualified_name=REL)

    def test_function_not_found_envelope_maps_to_node_not_found(self):
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(
                rc=1,
                stderr=(
                    '{"error":"function not found","function_name":"x",'
                    '"hint":"refresh the index"}'
                ),
            ),
        ):
            with self.assertRaises(CBMNodeNotFoundError) as ctx:
                _adapter().graph_neighborhood(qualified_name=REL)
        self.assertIsInstance(ctx.exception, CBMAdapterError)

    def test_real_stderr_with_leading_log_line_maps_to_node_not_found(self):
        # Certified-binary proof: a trace miss writes its log line FIRST
        # and the JSON envelope on the second stderr line. The anchored
        # classification must survive that real shape, or a lookup miss
        # degrades into a 502 outage in the viewer.
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(
                rc=1,
                stderr=(
                    "level=info msg=mem.init budget_mb=24198 "
                    "total_ram_mb=48397\n"
                    '{"error":"function not found","function_name":"x",'
                    '"hint":"refresh the index"}\n'
                ),
            ),
        ):
            with self.assertRaises(CBMNodeNotFoundError):
                _adapter().graph_neighborhood(qualified_name=REL)

    def test_leading_non_log_text_still_stays_an_outage(self):
        # Only whole leading LOG lines are tolerated: arbitrary leading
        # text before the envelope must remain outage-class.
        message = (
            'cbm trace_path failed: fatal: worker crashed\n'
            '{"error":"function not found","function_name":"x"}'
        )
        self.assertIsNone(_TRACE_NOT_FOUND_RE.search(message))

    def test_mid_text_function_not_found_stays_an_outage(self):
        message = (
            "cbm trace_path failed: fatal: function not found while "
            "reading a corrupted index"
        )
        self.assertIsNone(_TRACE_NOT_FOUND_RE.search(message))
        adapter = _adapter()
        with mock.patch.object(
            adapter, "_run_or_classify", side_effect=CBMAdapterError(message)
        ):
            with self.assertRaises(CBMAdapterError) as ctx:
                adapter.graph_neighborhood(qualified_name=REL)
        self.assertNotIsInstance(ctx.exception, CBMNodeNotFoundError)

    def test_depth_bounds_are_one_to_three(self):
        for depth in (0, 4):
            with self.subTest(depth=depth):
                adapter = _adapter()
                with mock.patch.object(
                    adapter, "_run_or_classify", return_value=_trace_payload()
                ) as run:
                    with self.assertRaises(CBMAdapterError):
                        adapter.graph_neighborhood(
                            qualified_name=REL, depth=depth
                        )
                run.assert_not_called()

    def test_depth_accepts_numeric_strings(self):
        adapter = _adapter()
        payload = _trace_payload(
            callers=[
                {"name": "C", "qualified_name": f"{SLUG}.src.c", "hop": 2}
            ]
        )
        with mock.patch.object(
            adapter, "_run_or_classify", return_value=payload
        ) as run:
            result = adapter.graph_neighborhood(
                qualified_name=REL, depth="2", include_tests=False
            )
        flags = run.call_args[0][1]
        self.assertEqual(flags[flags.index("--depth") + 1], "2")
        self.assertEqual(flags[flags.index("--include-tests") + 1], "false")
        self.assertIs(result["include_tests"], False)

    def test_include_tests_must_be_a_boolean(self):
        with mock.patch("relinkra.cbm_adapter.subprocess.run") as run:
            with self.assertRaises(CBMAdapterError):
                _adapter().graph_neighborhood(
                    qualified_name=REL, include_tests="true"
                )
        run.assert_not_called()

    def test_empty_qualified_name_is_rejected(self):
        with mock.patch("relinkra.cbm_adapter.subprocess.run") as run:
            with self.assertRaises(CBMAdapterError):
                _adapter().graph_neighborhood(qualified_name="  ")
        run.assert_not_called()

    def test_missing_side_array_is_rejected(self):
        payload = _trace_payload()
        del payload["callees"]
        adapter = _adapter()
        with mock.patch.object(
            adapter, "_run_or_classify", return_value=payload
        ):
            with self.assertRaises(CBMAdapterError):
                adapter.graph_neighborhood(qualified_name=REL)

    def test_payload_stays_within_the_graph_bound_and_is_bound_checked(self):
        adapter = _adapter()
        with mock.patch.object(
            adapter, "_run_or_classify", return_value=_trace_payload()
        ), mock.patch.object(adapter, "_ensure_payload_bound") as bound:
            result = adapter.graph_neighborhood(qualified_name=REL)
        self.assertEqual(bound.call_args[0][1], GRAPH_NODE_MAX_PAYLOAD_BYTES)
        self.assertEqual(bound.call_args[0][2], "graph")
        self.assertLessEqual(
            len(json.dumps(result).encode("utf-8")),
            GRAPH_NODE_MAX_PAYLOAD_BYTES,
        )
        self.assertNotIn(SLUG, json.dumps(result))


class GraphNodeLookupTests(unittest.TestCase):
    def test_exact_match_wins_over_pattern_overmatches(self):
        overmatch = _node("relinkra.x.func_extra", "relinkra/x.py")
        exact = _node("relinkra.x.func", "relinkra/x.py")
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(stdout=_search_payload(overmatch, exact)),
        ):
            candidate = _adapter().graph_node_lookup("relinkra.x.func")
        self.assertEqual(candidate["relative_qualified_name"], "relinkra.x.func")

    def test_overmatches_only_yield_none(self):
        overmatch = _node("relinkra.x.func_extra", "relinkra/x.py")
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(stdout=_search_payload(overmatch)),
        ):
            self.assertIsNone(
                _adapter().graph_node_lookup("relinkra.x.func")
            )

    def test_lookup_flags_are_exact(self):
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=_completed(stdout=_search_payload()),
        ) as run:
            _adapter().graph_node_lookup(REL)
        self.assertEqual(
            run.call_args[0][0],
            [
                "cbm.exe",
                "cli",
                "search_graph",
                "--project",
                SLUG,
                "--qn-pattern",
                REL,
                "--limit",
                "50",
            ],
        )

    def test_malformed_payloads_are_rejected(self):
        for payload in (
            json.dumps([1, 2]),
            json.dumps({"results": "nope"}),
            json.dumps({"results": [1]}),
            json.dumps({"error": "boom", "results": []}),
        ):
            with self.subTest(payload=payload):
                with mock.patch(
                    "relinkra.cbm_adapter.subprocess.run",
                    return_value=_completed(stdout=payload),
                ):
                    with self.assertRaises(CBMAdapterError):
                        _adapter().graph_node_lookup(REL)

    def test_empty_relative_qn_is_rejected(self):
        with mock.patch("relinkra.cbm_adapter.subprocess.run") as run:
            with self.assertRaises(CBMAdapterError):
                _adapter().graph_node_lookup("")
        run.assert_not_called()


class NormalizeNodeTests(unittest.TestCase):
    def adapter(self):
        return _adapter()

    def test_query_mode_node_keeps_exactly_its_old_key_set(self):
        candidate = self.adapter()._normalize_node(
            _node("relinkra.x.func", "relinkra/x.py"), cbm_project_name=SLUG
        )
        self.assertEqual(set(candidate), BASE_NODE_KEYS)

    def test_file_mode_node_gains_the_rich_fields(self):
        node = _rich_node(
            "relinkra.x.func",
            is_test=True,
            is_exported=False,
            is_entry_point=True,
            in_degree=1,
            out_degree=2,
            complexity=3,
            lines=4,
        )
        candidate = self.adapter()._normalize_node(node, cbm_project_name=SLUG)
        self.assertEqual(set(candidate), BASE_NODE_KEYS | RICH_NODE_KEYS)
        self.assertIs(candidate["is_test"], True)
        self.assertIs(candidate["is_exported"], False)
        self.assertIs(candidate["is_entry_point"], True)
        self.assertEqual(candidate["in_degree"], 1)
        self.assertEqual(candidate["out_degree"], 2)
        self.assertEqual(candidate["complexity"], 3)
        self.assertEqual(candidate["lines"], 4)

    def test_non_boolean_flags_are_omitted(self):
        node = _rich_node(
            "relinkra.x.func", is_test=1, is_exported="yes", is_entry_point=None
        )
        candidate = self.adapter()._normalize_node(node, cbm_project_name=SLUG)
        for flag in ("is_test", "is_exported", "is_entry_point"):
            self.assertNotIn(flag, candidate)

    def test_bool_is_not_an_int_count_and_negatives_are_omitted(self):
        node = _rich_node(
            "relinkra.x.func",
            in_degree=True,
            out_degree=-1,
            complexity="4",
            lines=0,
        )
        candidate = self.adapter()._normalize_node(node, cbm_project_name=SLUG)
        self.assertNotIn("in_degree", candidate)
        self.assertNotIn("out_degree", candidate)
        self.assertNotIn("complexity", candidate)
        self.assertEqual(candidate["lines"], 0)

    def test_internal_and_raw_fields_are_never_copied(self):
        node = _rich_node(
            "relinkra.x.func",
            docstring="raw source text",
            signature="def func() -> None",
            rank=0.5,
            last_modified="2026-01-01",
            fp="internal",
            sp="internal",
            bt="internal",
        )
        candidate = self.adapter()._normalize_node(node, cbm_project_name=SLUG)
        for key in (
            "docstring",
            "signature",
            "rank",
            "last_modified",
            "fp",
            "sp",
            "bt",
        ):
            self.assertNotIn(key, candidate)


if __name__ == "__main__":
    unittest.main()
