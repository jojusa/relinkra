"""R6K regression tests: exact final-packet token accounting.

The R6K contract: when Relinkra reports a cpt1 token total for a
ContextPacket (``packet_status.token_accounting.total_estimated_tokens``,
``budget_report.final_usage.estimated_tokens``, or
``diagnostics.budget.final_estimated_tokens``), the reported number must
describe the FINAL delivered packet — including the serialized
``packet_status`` block itself — under the declared accounting basis
(``serialized_compact_json``: the packet's full ``to_json()`` form; the
portable emission is a documented projection of it, so reported totals
are always >= cpt1 over the portable document).

The oracle in this module is deliberately independent of the builder's
intermediate counters: it re-serializes the final packet with a plain
``json.dumps`` and applies ceil(chars / chars_per_token) directly, so a
field appended after accounting cannot pass. When the self-referential
block cannot converge (proved possible at exact digit boundaries), the
settle ships the deterministic conservative state: at most one token
OVER the actual count, never under.
"""

from __future__ import annotations

import json
import math
import unittest

from relinkra.app_service import CONTRACT_VERSION, RelinkraServices, ServiceConfig
from relinkra.context_budget import (
    apply_budget,
    estimate_tokens,
    resolve_budget,
    settle_delivered_status,
)
from relinkra.explainability import attach_budget
from relinkra.salience import (
    build_status,
    settle_packet_status,
    shrink_status,
)
from test_context_budget import memory_item, make_packet, rich_packet
from test_context_packet import fixed_clock
from test_r6c import TASK, DogfoodEnv, build_ranked_packet

CPT = 3.0


def oracle_tokens(packet_dict) -> int:
    """Independent cpt1 recomputation over a final packet representation.

    Plain json.dumps + ceil — shares no code with the accounting path.
    """
    payload = json.dumps(
        packet_dict, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False,
    )
    return math.ceil(len(payload) / CPT) if payload else 0


def oracle_packet_chars(packet) -> int:
    """Chars of the packet's full canonical serialization."""
    return len(json.dumps(
        packet.to_dict(), sort_keys=True, separators=(",", ":"),
        ensure_ascii=False,
    ))


def budgeted_service_replay(packet, budget):
    """The exact post-ladder sequence app_service runs for a budgeted
    context_get: ladder -> attach_budget -> settle -> reconcile."""
    result = apply_budget(packet, budget)
    final = result.packet
    attach_budget(final, result.decisions)
    settle_delivered_status(packet, final, result.decisions, budget)
    result.reconcile_final_packet(final)
    return result, final


def make_service(env):
    config = ServiceConfig(
        default_project_id=env.project_id,
        default_workspace_id=env.workspace_id,
        workspace_root=env.ws_dir,
        registry_path=env.registry_path,
    )
    return RelinkraServices(
        config=config, store=env.store, cbm_adapter=env.cbm,
        registry=env.registry, clock=fixed_clock,
    )


def seeded_env():
    env = DogfoodEnv()
    env.seed()
    return env


def explainable_rich_packet(snippets=True):
    """rich_packet carrying R4D sidecars, so post-ladder budget
    treatments (attach_budget) have bytes to add."""
    packet = rich_packet()
    if not snippets:
        for fact in packet.code_facts:
            fact.data.pop("snippet", None)
            fact.data.pop("snippet_truncated", None)
    for item in packet.memories + packet.handoffs:
        item.explain = {"freshness": {"state": "fresh",
                                      "reason_code": "ok"}}
    return packet


def assert_honest(self, packet):
    """The status block's total describes the exact final bytes, or —
    only where no self-consistent state exists (proved digit-boundary
    cycles) — over-counts by exactly one token."""
    reported = packet.packet_status["token_accounting"][
        "total_estimated_tokens"
    ]
    actual = oracle_tokens(packet.to_dict())
    self.assertIn(
        reported - actual, (0, 1),
        f"reported {reported} vs actual {actual}: "
        "must be exact or conservative (+1), never stale/under",
    )


class UnbudgetedOracleTests(unittest.TestCase):
    """Primary release blocker: the unbudgeted path must measure the
    packet AFTER packet_status is settled onto it."""

    def setUp(self):
        self.env = seeded_env()
        self.addCleanup(self.env.cleanup)

    def test_settle_makes_reported_equal_actual(self):
        packet = self.env.builder().build(
            self.env.request(include_explain=True)
        )
        self.assertFalse(packet.packet_status)
        settle_packet_status(packet)
        self.assertIn("token_accounting", packet.packet_status)
        # exact: the block re-measures to itself over the final bytes
        self.assertEqual(
            packet.packet_status["token_accounting"][
                "total_estimated_tokens"
            ],
            oracle_tokens(packet.to_dict()),
        )

    def test_oracle_detects_the_release_defect_pattern(self):
        """The old measure-then-attach pattern must stay detectable: the
        oracle flags it, proving the oracle is not tautological."""
        packet = rich_packet()
        packet.explainability = {"notices": []}
        stale = build_status(packet)  # measures WITHOUT the block
        packet.packet_status = stale
        reported = stale["token_accounting"]["total_estimated_tokens"]
        self.assertLess(reported, oracle_tokens(packet.to_dict()))

    def test_service_surface_unbudgeted_projection_bound(self):
        services = make_service(self.env)
        payload = services.context_get(task=TASK)
        delivered = payload["packet"]
        status = delivered["packet_status"]
        self.assertIn("token_accounting", status)
        reported = status["token_accounting"]["total_estimated_tokens"]
        # the portable document is the documented projection of the
        # measured basis: the reported total bounds it from above
        self.assertGreaterEqual(reported, oracle_tokens(delivered))
        self.assertEqual(
            status["token_accounting"]["estimation_version"], "cpt1")
        self.assertEqual(
            status["token_accounting"]["accounting_basis"],
            "serialized_compact_json")


class BudgetedOracleTests(unittest.TestCase):
    """Hard budget stays certified; the embedded accounting must now
    describe the exact delivered bytes (or over-count conservatively)."""

    def setUp(self):
        self.env = seeded_env()
        self.addCleanup(self.env.cleanup)

    def test_post_attach_accounting_matches_final_packet(self):
        packet, _ranked = build_ranked_packet(self.env)
        result, final = budgeted_service_replay(
            packet, resolve_budget(max_tokens=6000)
        )
        self.assertTrue(result.satisfied)
        reported = final.packet_status["token_accounting"][
            "total_estimated_tokens"
        ]
        actual = oracle_tokens(final.to_dict())
        self.assertIn(reported - actual, (0, 1))
        # the REPORT is measured over the exact final bytes — always exact
        self.assertEqual(result.final_usage.estimated_tokens, actual)
        # self-referential diagnostics totals describe the final bytes
        diag = final.diagnostics["budget"]
        self.assertEqual(diag["final_total_chars"],
                         oracle_packet_chars(final))
        self.assertEqual(diag["final_estimated_tokens"], actual)
        # hard budget preserved on the actual final bytes
        self.assertLessEqual(actual, 6000)

    def test_ladder_only_settlement_is_exact(self):
        """Without post-ladder mutation the ladder's own settle converges
        to the exact final bytes."""
        packet, ranked = build_ranked_packet(self.env)
        result = apply_budget(packet, resolve_budget(max_tokens=8000),
                              relevance=ranked)
        self.assertTrue(result.satisfied)
        assert_honest(self, result.packet)

    def test_budget_report_usage_is_exact(self):
        packet = explainable_rich_packet()
        result, final = budgeted_service_replay(
            packet, resolve_budget(max_tokens=6000)
        )
        self.assertTrue(result.satisfied)
        self.assertEqual(
            result.final_usage.estimated_tokens,
            oracle_tokens(final.to_dict()),
        )


class StatusModeAccountingTests(unittest.TestCase):
    """Section 9: all four status modes account AFTER final settlement."""

    def test_mode_a_complete_packet(self):
        env = seeded_env()
        self.addCleanup(env.cleanup)
        packet, ranked = build_ranked_packet(env)
        result = apply_budget(packet, resolve_budget(max_tokens=24000),
                              relevance=ranked)
        self.assertTrue(result.satisfied)
        status = result.packet.packet_status
        self.assertTrue(status["packet_complete"])
        self.assertFalse(status["budget_exhausted"])
        self.assertEqual(status["omitted_sections"], [])
        assert_honest(self, result.packet)

    def test_mode_b_truncation_only(self):
        packet = explainable_rich_packet(snippets=True)
        result, final = budgeted_service_replay(
            packet, resolve_budget(max_tokens=6500)
        )
        self.assertTrue(result.satisfied)
        diag = final.diagnostics["budget"]
        self.assertTrue(diag["truncated_source_ids"])
        self.assertEqual(diag["omitted_source_ids"], [])
        self.assertFalse(final.packet_status["packet_complete"])
        assert_honest(self, final)

    def test_mode_c_omission_only(self):
        packet = explainable_rich_packet(snippets=False)
        result, final = budgeted_service_replay(
            packet, resolve_budget(max_tokens=4800)
        )
        self.assertTrue(result.satisfied)
        diag = final.diagnostics["budget"]
        self.assertFalse(diag["truncated_source_ids"])
        self.assertTrue(diag["omitted_source_ids"])
        self.assertFalse(final.packet_status["packet_complete"])
        assert_honest(self, final)

    def test_mode_d_truncation_and_omission(self):
        packet = explainable_rich_packet(snippets=True)
        result, final = budgeted_service_replay(
            packet, resolve_budget(max_tokens=4400)
        )
        self.assertTrue(result.satisfied)
        diag = final.diagnostics["budget"]
        self.assertTrue(diag["truncated_source_ids"])
        self.assertTrue(diag["omitted_source_ids"])
        assert_honest(self, final)


class ExtremePressureAccountingTests(unittest.TestCase):
    """Section 9: under extreme pressure the block may shrink along its
    fixed order; a shrunk block must stay shrunk after the post-attach
    settle, the self-referential diagnostics totals must still describe
    the final bytes, and the hard budget must hold."""

    def test_shrunk_block_stays_shrunk_after_post_attach_settle(self):
        env = seeded_env()
        self.addCleanup(env.cleanup)
        packet, ranked = build_ranked_packet(env)
        budget = resolve_budget(max_tokens=8000)
        result = apply_budget(packet, budget, relevance=ranked)
        self.assertTrue(result.satisfied)
        final = result.packet
        # force the accepted extreme-pressure form: shrink along the
        # fixed order until the self-referential totals are gone
        status = final.packet_status
        while "token_accounting" in status:
            status = shrink_status(status)
        final.packet_status = status
        attach_budget(final, result.decisions)
        settle_delivered_status(packet, final, result.decisions, budget)
        result.reconcile_final_packet(final)
        self.assertTrue(result.satisfied)
        # the shrink decision is preserved: no accounting re-attached
        self.assertNotIn("token_accounting", final.packet_status)
        # the diagnostics totals still describe the exact final bytes
        self.assertEqual(final.diagnostics["budget"]["final_total_chars"],
                         oracle_packet_chars(final))
        self.assertLessEqual(oracle_tokens(final.to_dict()),
                             budget.max_estimated_tokens)

    def test_shrink_order_drops_token_accounting_first(self):
        status = {
            "version": "salience-v1",
            "token_accounting": {"total_estimated_tokens": 42},
            "recommended_next": ["memory_search(project_id='x')"],
            "salience": {"must_keep": 1, "high_salience": 0,
                         "optional": 0},
            "context_sufficiency": {"orientation": "partial"},
        }
        shrunk = shrink_status(status)
        self.assertNotIn("token_accounting", shrunk)
        self.assertIn("recommended_next", shrunk)

    def test_minimum_useful_and_recommended_guidance_stay_honest(self):
        env = seeded_env()
        self.addCleanup(env.cleanup)
        packet, ranked = build_ranked_packet(env)
        result = apply_budget(packet, resolve_budget(max_tokens=8000),
                              relevance=ranked)
        self.assertTrue(result.satisfied)
        # guidance is a cpt1 estimate over a reconstructed skeleton, not
        # a claim about the delivered packet: present and positive
        self.assertGreater(result.minimum_useful_tokens, 0)
        self.assertGreater(result.recommended_max_tokens, 0)


class DigitTransitionAccountingTests(unittest.TestCase):
    """Section 14: self-reported numeric fields change serialized length
    at digit transitions (99->100, 999->1000). Sweeps around the
    boundary must ship honest accounting at EVERY step."""

    def test_sweep_across_999_1000_transition(self):
        # calibrate a small packet so its serialized length crosses the
        # 999->1000 token transition (2997 chars at cpt1=3.0)
        def build(pad):
            packet = make_packet(
                memories=[memory_item("mem_x", "decision", "x" * pad)]
            )
            packet.explainability = {"notices": []}
            settle_packet_status(packet)
            return packet

        base_len = oracle_packet_chars(build(0))
        target = 2997
        widths = set()
        for pad in range(target - base_len - 15, target - base_len + 15):
            if pad < 0:
                continue
            packet = build(pad)
            reported = packet.packet_status["token_accounting"][
                "total_estimated_tokens"
            ]
            actual = oracle_tokens(packet.to_dict())
            self.assertIn(reported - actual, (0, 1))
            widths.add(len(str(reported)))
        # the sweep actually crossed the digit transition
        self.assertEqual(widths, {3, 4})

    def test_sweep_around_char_boundaries_stays_honest(self):
        # sweep fine-grained padding over a rich packet: dozens of ceil
        # boundaries crossed, every shipped total exact or +1
        for pad in range(0, 24):
            packet = explainable_rich_packet()
            packet.memories[0].data["body"] = "d" * (900 + pad)
            result = apply_budget(packet, resolve_budget(max_tokens=8000))
            self.assertTrue(result.satisfied)
            assert_honest(self, result.packet)

    def test_repeated_settle_is_idempotent(self):
        packet = rich_packet()
        packet.explainability = {"notices": []}
        settle_packet_status(packet)
        once = json.dumps(packet.packet_status, sort_keys=True)
        settle_packet_status(packet)
        twice = json.dumps(packet.packet_status, sort_keys=True)
        self.assertEqual(once, twice)


class ServiceDeterminismTests(unittest.TestCase):
    """Section 10: logically identical final packets account identically
    (fixed clock; report_id/created_at residuals are out of scope)."""

    def test_repeated_unbudgeted_runs_match(self):
        env = seeded_env()
        self.addCleanup(env.cleanup)
        services = make_service(env)
        first = services.context_get(task=TASK)
        second = services.context_get(task=TASK)
        self.assertEqual(
            json.dumps(first["packet"], sort_keys=True),
            json.dumps(second["packet"], sort_keys=True),
        )

    def test_repeated_budgeted_runs_match(self):
        env = seeded_env()
        self.addCleanup(env.cleanup)
        services = make_service(env)
        first = services.context_get(task=TASK, max_tokens=6000)
        second = services.context_get(task=TASK, max_tokens=6000)
        self.assertEqual(
            json.dumps(first["packet"], sort_keys=True),
            json.dumps(second["packet"], sort_keys=True),
        )
        self.assertEqual(
            first["budget_report"]["final_usage"]["estimated_tokens"],
            second["budget_report"]["final_usage"]["estimated_tokens"],
        )


class BreakdownCoherenceTests(unittest.TestCase):
    """Section 11: the accounting breakdown stays internally coherent."""

    def test_breakdown_fields_are_coherent(self):
        packet = rich_packet()
        packet.explainability = {"notices": []}
        settle_packet_status(packet)
        accounting = packet.packet_status["token_accounting"]
        total = accounting["total_estimated_tokens"]
        useful = accounting["useful_payload_tokens"]
        metadata = accounting["metadata_tokens"]
        self.assertGreater(total, 0)
        self.assertGreater(useful, 0)
        self.assertGreaterEqual(metadata, 0)
        # cpt1 over the same char counts: a ceil boundary may differ by 1
        self.assertLessEqual(abs(useful + metadata - total), 1)
        self.assertEqual(
            accounting["compression_ratio"], round(useful / total, 4))
        # no suppressed duplicates in this fixture: honest nulls
        self.assertIsNone(accounting["duplicate_tokens_estimated"])
        self.assertEqual(accounting["duplicate_items_suppressed"], 0)


class UnbudgetedMatrixTests(unittest.TestCase):
    """Section 14 matrix: unbudgeted simple/rich packets, active
    handoff, pending, memory facts, code facts, populated status."""

    def test_unbudgeted_simple_packet_accounts_exact(self):
        env = seeded_env()
        self.addCleanup(env.cleanup)
        packet = env.builder().build(
            env.request(include_git=False, include_explain=True)
        )
        settle_packet_status(packet)
        assert_honest(self, packet)
        self.assertTrue(packet.packet_status)

    def test_unbudgeted_rich_packet_content_matrix(self):
        env = seeded_env()
        self.addCleanup(env.cleanup)
        packet = env.builder().build(
            env.request(task=TASK, symbol="src.budget.applyBudget",
                        include_explain=True)
        )
        settle_packet_status(packet)
        # the content matrix is present in the final packet
        self.assertTrue(packet.handoffs)
        self.assertTrue(packet.pending)
        self.assertTrue(packet.memories)
        self.assertTrue(packet.code_references or packet.code_facts)
        status = packet.packet_status
        self.assertTrue(status.get("salience"))
        self.assertGreater(status["salience"]["must_keep"], 0)
        assert_honest(self, packet)


class McpV1CompatibilityTests(unittest.TestCase):
    """Section 17: relinkra.mcp/v1 surface stays additive."""

    def test_contract_version_unchanged(self):
        self.assertEqual(CONTRACT_VERSION, "relinkra.mcp/v1")

    def test_context_get_response_keys_unchanged(self):
        env = seeded_env()
        self.addCleanup(env.cleanup)
        services = make_service(env)
        payload = services.context_get(task=TASK)
        for key in ("packet_version", "packet_id", "project_id", "packet"):
            self.assertIn(key, payload)
        packet = payload["packet"]
        for key in ("packet_version", "packet_id", "created_at", "mode",
                    "project_id", "memories", "handoffs", "warnings",
                    "provenance", "diagnostics", "packet_status"):
            self.assertIn(key, packet)


if __name__ == "__main__":
    unittest.main()
