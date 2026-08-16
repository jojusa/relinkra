"""Focused R5E.2D tests for bounded CBM structural evidence."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from relinkra.cbm_adapter import (
    ARCHITECTURE_MAX_PAYLOAD_BYTES,
    CBMAdapterError,
    CBMCLIAdapter,
    TRACE_MAX_PAYLOAD_BYTES,
)
from relinkra.context_budget import ContextBudget, apply_budget
from relinkra.context_packet import ContextPacket, PacketItem, Provenance
from relinkra.context_builder import ContextBuilder
from relinkra.linkage import LinkageService
from test_context_packet import Env, node


SLUG = "C-Desarrollos-relinkra-ws"
TARGET = f"{SLUG}.src.service.Target.run"


def architecture_payload():
    return {
        "project": SLUG,
        "total_nodes": 10,
        "total_edges": 20,
        "node_labels": [
            {"label": "Method", "count": 4},
            {"label": "Function", "count": 6},
        ],
        "edge_types": [{"type": "CALLS", "count": 20}],
        "entry_points": [
            {"name": "run", "qualified_name": TARGET, "file": "src/service.py"}
        ],
        "routes": [],
        "languages": [{"language": "Python", "file_count": 2}],
        "packages": [{"name": "api", "node_count": 10}],
        "layers": [{"name": "api", "layer": "entry", "reason": "route"}],
        "boundaries": [{"from": "api", "to": "shared", "call_count": 2}],
        "hotspots": [
            {"name": "run", "qualified_name": TARGET, "fan_in": 3}
        ],
        "clusters": [
            {
                "id": 1,
                "label": "api",
                "members": 4,
                "cohesion": 0.9,
                "top_nodes": ["run", "run", "Target"],
                "packages": ["api"],
                "edge_types": ["CALLS"],
            }
        ],
    }


def trace_payload(**overrides):
    payload = {
        "function": TARGET,
        "direction": "inbound",
        "mode": "calls",
        "callers": [
            {"name": "Bob", "qualified_name": f"{SLUG}.src.bob.Bob", "hop": 1},
            {"name": "Zed", "qualified_name": f"{SLUG}.src.zed.Zed", "hop": 2},
            {"name": "Ada", "qualified_name": f"{SLUG}.src.ada.Ada", "hop": 1},
        ],
    }
    payload.update(overrides)
    return payload


class AdapterStructuralTests(unittest.TestCase):
    def adapter(self):
        return CBMCLIAdapter(
            "cbm.exe",
            cache_dir="cache",
            cbm_project_name=SLUG,
            workspace_root="C:/repo",
        )

    def test_architecture_invocation_is_compact_and_deterministic(self):
        adapter = self.adapter()
        with mock.patch.object(
            adapter, "_run_or_classify", return_value=architecture_payload()
        ) as run:
            first = adapter.architecture_orientation(path="src", limit=1)
            second = adapter.architecture_orientation(path="src", limit=1)

        self.assertEqual(first, second)
        run.assert_called_with(
            "get_architecture",
            ["--project", SLUG, "--aspects", "overview", "--path", "src"],
        )
        self.assertEqual(len(first["languages"]), 1)
        self.assertEqual(len(first["clusters"]), 1)
        self.assertNotIn(SLUG, json.dumps(first))
        self.assertNotIn("node_labels", first)
        self.assertNotIn("edge_types", first)
        self.assertLessEqual(
            len(json.dumps(first).encode()), ARCHITECTURE_MAX_PAYLOAD_BYTES
        )

    def test_architecture_rejects_missing_stable_fields(self):
        adapter = self.adapter()
        with mock.patch.object(adapter, "_run_or_classify", return_value={}):
            with self.assertRaises(CBMAdapterError):
                adapter.architecture_orientation()

    def test_trace_invocation_is_bounded_sorted_and_qualified(self):
        adapter = self.adapter()
        with mock.patch.object(
            adapter, "_run_or_classify", return_value=trace_payload()
        ) as run:
            result = adapter.trace_relationships(
                function_name=TARGET,
                direction="inbound",
                max_hops=2,
                limit=2,
            )

        run.assert_called_once_with(
            "trace_path",
            [
                "--project", SLUG,
                "--function-name", TARGET,
                "--direction", "inbound",
                "--depth", "2",
                "--mode", "calls",
                "--include-tests", "false",
            ],
        )
        self.assertEqual([item["name"] for item in result["relationships"]], ["Ada", "Bob"])
        self.assertTrue(result["coverage"]["truncated"])
        self.assertNotIn(SLUG, json.dumps(result))
        self.assertLessEqual(
            len(json.dumps(result).encode()), TRACE_MAX_PAYLOAD_BYTES
        )

    def test_trace_empty_result_is_not_a_negative_claim(self):
        adapter = self.adapter()
        payload = trace_payload(callers=[])
        with mock.patch.object(adapter, "_run_or_classify", return_value=payload):
            result = adapter.trace_relationships(
                function_name=TARGET, direction="inbound"
            )
        self.assertEqual(result["relationships"], [])
        self.assertIn("does not prove", result["coverage"]["qualification"])

    def test_trace_outbound_maps_callees_to_dependencies(self):
        adapter = self.adapter()
        payload = {
            "function": TARGET,
            "direction": "outbound",
            "mode": "calls",
            "callees": [
                {
                    "name": "Repo",
                    "qualified_name": f"{SLUG}.src.repo.Repo",
                    "hop": 1,
                }
            ],
        }
        with mock.patch.object(adapter, "_run_or_classify", return_value=payload):
            result = adapter.trace_relationships(
                function_name=TARGET, direction="outbound"
            )
        self.assertEqual(result["relationships"][0]["relationship"], "dependency")

    def test_trace_rejects_missing_requested_array(self):
        adapter = self.adapter()
        payload = trace_payload()
        del payload["callers"]
        with mock.patch.object(adapter, "_run_or_classify", return_value=payload):
            with self.assertRaises(CBMAdapterError):
                adapter.trace_relationships(
                    function_name=TARGET, direction="inbound"
                )

    def test_trace_rejects_hop_beyond_requested_bound(self):
        adapter = self.adapter()
        payload = trace_payload(
            callers=[
                {
                    "name": "TooFar",
                    "qualified_name": f"{SLUG}.src.too_far.TooFar",
                    "hop": 3,
                }
            ]
        )
        with mock.patch.object(adapter, "_run_or_classify", return_value=payload):
            with self.assertRaises(CBMAdapterError):
                adapter.trace_relationships(
                    function_name=TARGET, direction="inbound", max_hops=2
                )

    def test_trace_rejects_mismatched_target(self):
        adapter = self.adapter()
        payload = trace_payload(function="another.Target.run")
        with mock.patch.object(adapter, "_run_or_classify", return_value=payload):
            with self.assertRaises(CBMAdapterError):
                adapter.trace_relationships(
                    function_name=TARGET, direction="inbound"
                )


class StructuralFallbackTests(unittest.TestCase):
    class FakeCBM:
        def __init__(self, nodes=()):
            self.nodes = list(nodes)
            self.trace_calls = []

        def code_evidence_authority(self):
            return {
                "index_status": {"git": {"head_sha": "a" * 40}},
                "trust_stages": [{"name": "CBM graph", "status": "PASS"}],
            }

        def search_symbols(self, **kwargs):
            return self.nodes

        def get_snippet(self, qualified_name):
            return next(
                (item for item in self.nodes if item["qualified_name"] == qualified_name),
                None,
            )

        def architecture_orientation(self, **kwargs):
            return {"total_nodes": 1, "total_edges": 0, "hotspots": []}

        def trace_relationships(self, **kwargs):
            self.trace_calls.append(kwargs)
            return {
                "target": "src.service.Target.run",
                "direction": kwargs["direction"],
                "max_hops": kwargs["max_hops"],
                "relationships": [],
                "coverage": {
                    "complete": False,
                    "qualification": "does not prove that none exist",
                },
            }

    def test_ambiguous_symbol_never_triggers_traversal(self):
        fake = self.FakeCBM(
            [
                node("Target", "src.one.Target", "src/one.py"),
                node("Target", "src.two.Target", "src/two.py"),
            ]
        )
        env = Env(cbm=fake)
        self.addCleanup(env.cleanup)
        packet = env.builder().build(
            env.request(symbol="Target", task="find callers")
        )
        self.assertEqual(fake.trace_calls, [])
        self.assertTrue(any(w.code == "ambiguous_code_reference" for w in packet.warnings))

    def test_stale_authority_is_qualified_not_fresh(self):
        class Stale(self.FakeCBM):
            def code_evidence_authority(self):
                return {
                    "index_status": {"git": {"head_sha": "a" * 40}},
                    "trust_stages": [
                        {
                            "name": "CBM graph",
                            "status": "WARN",
                            "detail": "stale index",
                        }
                    ],
                }

        result = LinkageService(None, Stale()).architecture_orientation()
        self.assertEqual(result["freshness"]["state"], "stale")


class BudgetStructuralTests(unittest.TestCase):
    def item(self, kind, payload):
        return PacketItem(
            data={"evidence_kind": kind, **payload},
            provenance=Provenance(source="cbm", why_included="test"),
        )

    def test_structural_fact_is_shed_before_direct_code_fact(self):
        packet = ContextPacket(
            packet_id="pkt_test",
            created_at="2026-01-01T00:00:00+00:00",
            mode="task",
            project_id="rlk_" + "a" * 32,
            project_facts={"registered": True},
            code_facts=[
                self.item("direct", {"name": "focus"}),
                self.item("architecture_fact", {"blob": "x" * 4000}),
            ],
        )
        result = apply_budget(
            packet,
            ContextBudget(max_estimated_tokens=400, max_characters=5000),
        )
        kinds = [item.data.get("evidence_kind") for item in result.packet.code_facts]
        self.assertNotIn("architecture_fact", kinds)
        self.assertIn("direct", kinds)
