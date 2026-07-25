"""Offline deterministic tests for the R1F Context Budget Accountant.

No subprocess, no network, no real Engram/CBM: handcrafted packets with
controlled sizes plus the R1E Env/FakeCBMAdapter/fixed_clock fixtures.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import time
import unittest

from relinkra import context_cli
from relinkra.context_budget import (
    BUDGET_PROFILES,
    DEFAULT_CHARS_PER_TOKEN,
    ESTIMATION_METHOD,
    ESTIMATION_VERSION,
    IMPORTANT_MEMORY_TYPES,
    SNIPPET_LADDER_CAP,
    TRUNCATION_MARKER,
    BudgetValidationError,
    ContextBudget,
    apply_budget,
    classify_memory_type,
    estimate_tokens,
    prepare_budgeted_packet,
    resolve_budget,
)
from relinkra.context_packet import (
    PACKET_VERSION,
    ContextPacket,
    PacketItem,
    PacketWarning,
    Provenance,
    compute_packet_id,
)
from test_context_packet import (
    FIXED_NOW,
    PID,
    Env,
    FakeCBMAdapter,
    fixed_clock,
    node,
)

SLUG = "C-Desarrollos-relinkra-ws"


def compact(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def memory_item(mid, mtype, body, title=None, agent=None):
    data = {
        "memory_id": mid,
        "project_id": PID,
        "memory_type": mtype,
        "title": title or f"title {mid}",
        "body": body,
        "scope_channel": "shared",
    }
    return PacketItem(
        data=data,
        provenance=Provenance(
            source="engram",
            why_included="budget fixture",
            memory_id=mid,
            agent_type=agent,
        ),
    )


def fact_item(ref, snippet=None, name=None, path="src/mod.py"):
    data = {
        "code_reference_id": ref,
        "file_path": path,
        "qualified_name": name or f"src.mod.{ref.replace('ref_', 'fn')}",
        "symbol_name": "fn",
        "symbol_kind": "function",
        "language": "python",
        "start_line": 1,
        "end_line": 5,
        "resolution_state": "resolved",
    }
    if snippet is not None:
        data["snippet"] = snippet
        data["snippet_truncated"] = False
    return PacketItem(
        data=data,
        provenance=Provenance(
            source="cbm",
            why_included="budget fixture",
            code_reference_id=ref,
        ),
    )


def ref_item(rid):
    return PacketItem(
        data={
            "reference": {"reference_kind": "file", "file_path": "src/m.py"},
            "resolution_state": "resolved",
            "note": None,
        },
        provenance=Provenance(
            source="cbm",
            why_included="budget fixture",
            code_reference_id=rid,
        ),
    )


def make_packet(*, memories=(), facts=(), refs=(), pending=(), handoffs=(),
                warnings=(), task="budget fixture task"):
    return ContextPacket(
        packet_id=compute_packet_id(project_id=PID, mode="project"),
        created_at=FIXED_NOW,
        mode="project",
        project_id=PID,
        requesting_agent="opencode",
        task=task,
        project_facts={"registered": True, "display_name": "fixture"},
        memories=list(memories),
        code_references=list(refs),
        code_facts=list(facts),
        pending=list(pending),
        handoffs=list(handoffs),
        warnings=list(warnings),
        provenance={
            "builder": "relinkra.context_builder",
            "packet_version": PACKET_VERSION,
            "sources": ["engram", "relinkra"],
        },
        diagnostics={"mode": "project"},
    )


def rich_packet():
    """One deterministic fixture packet, big enough to exceed `small`."""
    return make_packet(
        memories=[
            memory_item("mem_dec", "decision", "d" * 900),
            memory_item("mem_con", "constraint", "c" * 900),
            memory_item("mem_arc", "architecture", "a" * 900),
            memory_item("mem_bug", "bug", "b" * 900),
            memory_item("mem_dis1", "discovery", "x" * 1200),
            memory_item("mem_dis2", "discovery", "y" * 1200),
            memory_item("mem_ver", "verification", "v" * 1000),
            memory_item("mem_res", "task_result", "t" * 1000),
        ],
        facts=[
            fact_item("ref_focus", snippet="s" * 2000, name="src.mod.focus"),
            fact_item("ref_extra1", snippet="e" * 1500, name="src.mod.extra1"),
            fact_item("ref_extra2", snippet="g" * 800, name="src.mod.extra2"),
        ],
        refs=[ref_item("ref_focus")],
        pending=[memory_item("mem_pen", "pending", "p" * 700)],
        handoffs=[memory_item("mem_han", "handoff", "h" * 700)],
        warnings=[PacketWarning("stale_code_reference", "drifted")],
    )


def included_tokens(packet, budget):
    """Estimated tokens of the all-included working packet under budget."""
    working = prepare_budgeted_packet(packet, budget)
    return estimate_tokens(working.to_json(), budget.chars_per_token)


def budget_with_over(packet, over, reserve_tokens=0, start=10 ** 9):
    """max_estimated_tokens so the full packet exceeds budget-reserve by
    exactly ``over`` tokens (fixed-point over diagnostics digit width)."""
    max_tokens = start
    for _ in range(8):
        budget = ContextBudget(
            max_estimated_tokens=max_tokens, reserve_tokens=reserve_tokens
        )
        size = included_tokens(packet, budget)
        candidate = size + reserve_tokens - over
        if candidate == max_tokens:
            break
        max_tokens = candidate
    return max_tokens


def decisions_by_id(result):
    return {d.source_id: d for d in result.decisions}


class EstimatorTests(unittest.TestCase):
    def test_empty_string_is_zero(self):
        self.assertEqual(estimate_tokens(""), 0)

    def test_ascii(self):
        self.assertEqual(estimate_tokens("abcdef"), 2)  # ceil(6/3)

    def test_ceil_behavior(self):
        self.assertEqual(estimate_tokens("abcd"), 2)  # ceil(4/3)
        self.assertEqual(estimate_tokens("abc"), 1)

    def test_unicode_spanish_accents_count_code_points(self):
        self.assertEqual(estimate_tokens("árbol"), 2)  # 5 code points

    def test_unicode_multilingual_and_emoji(self):
        self.assertEqual(estimate_tokens("日本語テキスト"), 3)  # 7 code points
        self.assertEqual(estimate_tokens("🚀🚀🚀"), 1)  # 3 code points

    def test_custom_ratio(self):
        self.assertEqual(estimate_tokens("abcdef", chars_per_token=1.0), 6)
        self.assertEqual(estimate_tokens("abcdef", chars_per_token=2.0), 3)

    def test_invalid_ratio_rejected(self):
        for bad in (0, -1.0, float("inf"), float("nan")):
            with self.assertRaises(BudgetValidationError):
                estimate_tokens("x", chars_per_token=bad)


class AccountingTests(unittest.TestCase):
    def test_empty_body_item_still_costs(self):
        item = memory_item("mem_empty", "decision", "")
        packet = make_packet(memories=[item])
        budget = ContextBudget(max_estimated_tokens=10 ** 9)
        result = apply_budget(packet, budget)
        decision = decisions_by_id(result)["mem_empty"]
        self.assertGreater(decision.original_chars, 0)
        self.assertGreater(decision.original_estimated_tokens, 0)

    def test_item_cost_includes_provenance_and_metadata(self):
        item = memory_item("mem_meta", "decision", "body")
        packet = make_packet(memories=[item])
        budget = ContextBudget(max_estimated_tokens=10 ** 9)
        result = apply_budget(packet, budget)
        decision = decisions_by_id(result)["mem_meta"]
        self.assertEqual(decision.original_chars, len(compact(item.to_dict())))
        self.assertGreater(decision.original_chars, len("body"))


class BudgetValidationTests(unittest.TestCase):
    def test_zero_or_negative_max_tokens(self):
        for bad in (0, -5):
            with self.assertRaises(BudgetValidationError):
                ContextBudget(max_estimated_tokens=bad)

    def test_negative_reserve(self):
        with self.assertRaises(BudgetValidationError):
            ContextBudget(max_estimated_tokens=10, reserve_tokens=-1)

    def test_non_finite_or_non_positive_ratio(self):
        for bad in (0.0, -2.0, float("inf"), float("nan")):
            with self.assertRaises(BudgetValidationError):
                ContextBudget(max_estimated_tokens=10, chars_per_token=bad)

    def test_invalid_max_characters(self):
        for bad in (0, -3):
            with self.assertRaises(BudgetValidationError):
                ContextBudget(max_estimated_tokens=10, max_characters=bad)

    def test_validation_error_is_value_error(self):
        with self.assertRaises(ValueError):
            ContextBudget(max_estimated_tokens=0)


class ProfileTests(unittest.TestCase):
    def test_profile_values(self):
        self.assertEqual(
            BUDGET_PROFILES, {"small": 2000, "medium": 8000, "large": 24000}
        )

    def test_resolve_profiles(self):
        for name, tokens in BUDGET_PROFILES.items():
            budget = resolve_budget(profile=name)
            self.assertEqual(budget.max_estimated_tokens, tokens)

    def test_explicit_max_tokens_wins_over_profile(self):
        budget = resolve_budget(profile="large", max_tokens=1234)
        self.assertEqual(budget.max_estimated_tokens, 1234)

    def test_neither_profile_nor_max_tokens(self):
        with self.assertRaises(BudgetValidationError):
            resolve_budget()

    def test_unknown_profile(self):
        with self.assertRaises(BudgetValidationError):
            resolve_budget(profile="huge")

    def test_reserve_default_formula(self):
        self.assertEqual(resolve_budget(profile="small").reserve_tokens, 100)
        self.assertEqual(resolve_budget(profile="medium").reserve_tokens, 400)
        self.assertEqual(resolve_budget(profile="large").reserve_tokens, 1200)
        self.assertEqual(resolve_budget(max_tokens=100).reserve_tokens, 64)

    def test_explicit_reserve_honored(self):
        budget = resolve_budget(profile="small", reserve_tokens=7)
        self.assertEqual(budget.reserve_tokens, 7)


class ClassificationTests(unittest.TestCase):
    def test_important_types(self):
        for mtype in ("constraint", "decision", "architecture", "bug"):
            self.assertEqual(classify_memory_type(mtype), "important")
        self.assertIn("bug", IMPORTANT_MEMORY_TYPES)

    def test_optional_types(self):
        for mtype in ("discovery", "verification", "task_result"):
            self.assertEqual(classify_memory_type(mtype), "optional")

    def test_unknown_type_is_optional(self):
        self.assertEqual(classify_memory_type("whatever"), "optional")
        self.assertEqual(classify_memory_type(None), "optional")


class LadderOrderTests(unittest.TestCase):
    def test_step1_only_truncates_one_snippet(self):
        packet = make_packet(
            memories=[memory_item("mem_a", "decision", "d" * 100)],
            facts=[fact_item("ref_f", snippet="s" * 2000)],
        )
        max_tokens = budget_with_over(packet, over=10)
        result = apply_budget(
            packet, ContextBudget(max_estimated_tokens=max_tokens)
        )
        self.assertTrue(result.satisfied)
        by_id = decisions_by_id(result)
        self.assertEqual(by_id["snippet:ref_f"].action, "truncated")
        self.assertEqual(by_id["snippet:ref_f"].reason, "snippet_budget_ladder")
        self.assertEqual(by_id["ref_f"].action, "included")
        self.assertEqual(by_id["mem_a"].action, "included")

    def test_step1_exhausts_before_step2(self):
        packet = make_packet(
            memories=[memory_item("mem_a", "decision", "d" * 100)],
            facts=[
                fact_item("ref_a", snippet="s" * 2000),
                fact_item("ref_b", snippet="t" * 2000),
            ],
        )
        # over by slightly more than BOTH truncations save (~1050 tokens):
        # step 1 must exhaust every snippet before step 2 removes one
        max_tokens = budget_with_over(packet, over=1100)
        result = apply_budget(
            packet, ContextBudget(max_estimated_tokens=max_tokens)
        )
        self.assertTrue(result.satisfied)
        actions = [d.action for d in result.decisions]
        by_id = decisions_by_id(result)
        self.assertEqual(by_id["snippet:ref_a"].action, "reference_only")
        self.assertEqual(by_id["snippet:ref_b"].action, "truncated")
        self.assertNotIn("omitted", actions)  # never reached step 3+

    def test_step3_omits_optional_memories_from_end(self):
        packet = make_packet(
            memories=[
                memory_item("mem_imp", "decision", "d" * 100),
                memory_item("mem_opt1", "discovery", "x" * 1500),
                memory_item("mem_opt2", "verification", "y" * 1500),
            ],
        )
        max_tokens = budget_with_over(packet, over=20)
        result = apply_budget(
            packet, ContextBudget(max_estimated_tokens=max_tokens)
        )
        self.assertTrue(result.satisfied)
        by_id = decisions_by_id(result)
        self.assertEqual(by_id["mem_opt2"].action, "omitted")
        self.assertEqual(
            by_id["mem_opt2"].reason, "optional_section_budget_exhausted"
        )
        self.assertEqual(by_id["mem_opt1"].action, "included")
        self.assertEqual(by_id["mem_imp"].action, "included")

    def test_step4_omits_extra_code_facts_keeps_first(self):
        packet = make_packet(
            memories=[memory_item("mem_a", "decision", "d" * 100)],
            facts=[
                fact_item("ref_focus", name="src.mod." + "f" * 1500),
                fact_item("ref_extra", name="src.mod." + "g" * 1500),
            ],
        )
        max_tokens = budget_with_over(packet, over=20)
        result = apply_budget(
            packet, ContextBudget(max_estimated_tokens=max_tokens)
        )
        self.assertTrue(result.satisfied)
        by_id = decisions_by_id(result)
        self.assertEqual(by_id["ref_extra"].action, "omitted")
        self.assertEqual(
            by_id["ref_extra"].reason, "optional_section_budget_exhausted"
        )
        self.assertEqual(by_id["ref_focus"].action, "included")
        self.assertEqual(
            [f.data["code_reference_id"] for f in result.packet.code_facts],
            ["ref_focus"],
        )

    def test_step5_omits_important_items_from_end(self):
        packet = make_packet(
            memories=[
                memory_item("mem_imp1", "decision", "d" * 1500),
                memory_item("mem_imp2", "bug", "b" * 1500),
            ],
            pending=[memory_item("mem_pen", "pending", "p" * 1500)],
        )
        max_tokens = budget_with_over(packet, over=20)
        result = apply_budget(
            packet, ContextBudget(max_estimated_tokens=max_tokens)
        )
        self.assertTrue(result.satisfied)
        by_id = decisions_by_id(result)
        self.assertEqual(by_id["mem_imp2"].action, "omitted")
        self.assertEqual(
            by_id["mem_imp2"].reason, "important_section_budget_exhausted"
        )
        self.assertEqual(by_id["mem_imp1"].action, "included")
        self.assertEqual(by_id["mem_pen"].action, "included")


class SnippetTruncationTests(unittest.TestCase):
    def test_marker_flag_and_sizes(self):
        snippet = "s" * 2000
        packet = make_packet(facts=[fact_item("ref_f", snippet=snippet)])
        max_tokens = budget_with_over(packet, over=10)
        result = apply_budget(
            packet, ContextBudget(max_estimated_tokens=max_tokens)
        )
        fact = result.packet.code_facts[0].data
        self.assertTrue(fact["snippet_truncated"])
        self.assertTrue(fact["snippet"].endswith(TRUNCATION_MARKER))
        self.assertEqual(
            len(fact["snippet"]), SNIPPET_LADDER_CAP + len(TRUNCATION_MARKER)
        )
        self.assertEqual(fact["code_reference_id"], "ref_f")
        decision = decisions_by_id(result)["snippet:ref_f"]
        self.assertEqual(decision.original_chars, 2000)
        self.assertEqual(decision.final_chars, len(fact["snippet"]))

    def test_short_snippets_are_skipped_by_step1(self):
        packet = make_packet(
            facts=[fact_item("ref_f", snippet="s" * SNIPPET_LADDER_CAP)],
            memories=[memory_item("mem_o", "discovery", "x" * 1500)],
        )
        max_tokens = budget_with_over(packet, over=20)
        result = apply_budget(
            packet, ContextBudget(max_estimated_tokens=max_tokens)
        )
        fact = result.packet.code_facts[0].data
        # step 1 skipped (snippet <= cap); step 2 drops it entirely
        self.assertNotIn("snippet", fact)
        by_id = decisions_by_id(result)
        self.assertEqual(by_id["snippet:ref_f"].action, "reference_only")


class ReferenceOnlyTests(unittest.TestCase):
    def test_snippet_removed_metadata_intact(self):
        packet = make_packet(
            facts=[fact_item("ref_f", snippet="s" * 2000)],
            memories=[memory_item("mem_o", "discovery", "x" * 3000)],
        )
        # force past step 1+2 but keep the optional memory affordable
        max_tokens = budget_with_over(packet, over=700)
        result = apply_budget(
            packet, ContextBudget(max_estimated_tokens=max_tokens)
        )
        self.assertTrue(result.satisfied)
        fact = result.packet.code_facts[0].data
        self.assertNotIn("snippet", fact)
        self.assertNotIn("snippet_truncated", fact)
        for key in ("code_reference_id", "file_path", "qualified_name",
                    "symbol_name", "symbol_kind", "language", "start_line",
                    "end_line", "resolution_state"):
            self.assertIn(key, fact)
        self.assertEqual(
            decisions_by_id(result)["snippet:ref_f"].action, "reference_only"
        )


class MemoryIntegrityTests(unittest.TestCase):
    def test_memories_are_whole_in_or_whole_out(self):
        packet = rich_packet()
        original_bodies = {
            item.data["memory_id"]: item.data["body"]
            for item in packet.memories + packet.pending + packet.handoffs
        }
        for over in (50, 800, 2500, 6000):
            max_tokens = budget_with_over(packet, over=over)
            result = apply_budget(
                packet, ContextBudget(max_estimated_tokens=max_tokens)
            )
            survivors = (
                result.packet.memories + result.packet.pending
                + result.packet.handoffs
            )
            for item in survivors:
                self.assertEqual(
                    item.data["body"], original_bodies[item.data["memory_id"]]
                )

    def test_survivors_preserve_ids_types_and_provenance(self):
        packet = rich_packet()
        max_tokens = budget_with_over(packet, over=1000)
        result = apply_budget(
            packet, ContextBudget(max_estimated_tokens=max_tokens)
        )
        for item in result.packet.memories:
            self.assertTrue(item.data["memory_id"].startswith("mem_"))
            self.assertIn("memory_type", item.data)
            self.assertEqual(item.provenance.source, "engram")
            self.assertEqual(item.provenance.memory_id, item.data["memory_id"])
        for fact in result.packet.code_facts:
            self.assertIn("code_reference_id", fact.data)
            self.assertEqual(fact.provenance.source, "cbm")


class IncludedDecisionsTests(unittest.TestCase):
    def test_every_survivor_has_an_included_decision(self):
        packet = rich_packet()
        max_tokens = budget_with_over(packet, over=300)
        result = apply_budget(
            packet, ContextBudget(max_estimated_tokens=max_tokens)
        )
        survivor_ids = {
            item.provenance.memory_id
            for item in (
                result.packet.memories + result.packet.pending
                + result.packet.handoffs
            )
        } | {
            item.data["code_reference_id"] for item in result.packet.code_facts
        } | {
            item.provenance.code_reference_id
            for item in result.packet.code_references
        }
        by_id = decisions_by_id(result)
        for source_id in survivor_ids:
            self.assertEqual(by_id[source_id].action, "included")
            self.assertEqual(by_id[source_id].reason, "within_budget")

    def test_essential_structural_decision_always_present(self):
        packet = rich_packet()
        budget = ContextBudget(max_estimated_tokens=10 ** 9)
        result = apply_budget(packet, budget)
        essential = result.decisions[0]
        self.assertEqual(essential.source_id, "essential")
        self.assertEqual(essential.section, "essential")
        self.assertEqual(essential.action, "included")
        self.assertGreater(essential.original_chars, 0)

    def test_audit_covers_every_original_unit_when_nothing_is_cut(self):
        packet = rich_packet()
        budget = ContextBudget(max_estimated_tokens=10 ** 9)
        result = apply_budget(packet, budget)
        # essential + 8 memories + 1 ref + 3 facts + 3 snippets + 1 pending
        # + 1 handoff = 18
        self.assertEqual(len(result.decisions), 18)
        self.assertTrue(
            all(d.action == "included" for d in result.decisions)
        )
        self.assertEqual(result.final_usage.included_count, 17)


class HardGuaranteeTests(unittest.TestCase):
    def assert_guarantee(self, packet, budget):
        result = apply_budget(packet, budget)
        if result.status == "OK":
            payload = result.packet.to_json()
            self.assertLessEqual(
                estimate_tokens(payload, budget.chars_per_token),
                budget.max_estimated_tokens,
            )
            if budget.max_characters is not None:
                self.assertLessEqual(len(payload), budget.max_characters)
        return result

    def test_budget_sweep(self):
        packet = rich_packet()
        budgets = [
            resolve_budget(profile="large"),
            resolve_budget(profile="medium"),
            resolve_budget(profile="small"),
            ContextBudget(max_estimated_tokens=budget_with_over(packet, 0)),
            ContextBudget(max_estimated_tokens=10),
        ]
        results = [self.assert_guarantee(packet, b) for b in budgets]
        self.assertEqual(results[-1].status, "BUDGET_UNSATISFIABLE")
        self.assertTrue(all(r.satisfied for r in results[:4]))

    def test_exact_fit_boundary(self):
        packet = rich_packet()
        exact = budget_with_over(packet, over=0)
        budget = ContextBudget(max_estimated_tokens=exact)
        result = self.assert_guarantee(packet, budget)
        self.assertEqual(result.status, "OK")
        self.assertTrue(
            all(d.action == "included" for d in result.decisions)
        )
        one_below = ContextBudget(max_estimated_tokens=exact - 1)
        result2 = self.assert_guarantee(packet, one_below)
        self.assertTrue(
            any(d.action != "included" for d in result2.decisions)
        )

    def test_budget_larger_than_packet(self):
        packet = rich_packet()
        budget = ContextBudget(max_estimated_tokens=10 ** 9)
        result = self.assert_guarantee(packet, budget)
        self.assertEqual(result.status, "OK")
        self.assertEqual(result.final_usage.omitted_count, 0)
        self.assertEqual(result.final_usage.truncated_count, 0)

    def test_max_characters_enforced(self):
        packet = rich_packet()
        full_chars = len(
            prepare_budgeted_packet(
                packet, ContextBudget(max_estimated_tokens=10 ** 9)
            ).to_json()
        )
        budget = ContextBudget(
            max_estimated_tokens=10 ** 9, max_characters=full_chars - 500
        )
        result = self.assert_guarantee(packet, budget)
        self.assertTrue(
            any(d.action != "included" for d in result.decisions)
        )


class UnsatisfiableTests(unittest.TestCase):
    def test_tiny_budget_is_typed_result_not_exception(self):
        packet = rich_packet()
        result = apply_budget(packet, resolve_budget(max_tokens=1))
        self.assertEqual(result.status, "BUDGET_UNSATISFIABLE")
        self.assertIsNone(result.packet)
        self.assertFalse(result.satisfied)
        self.assertTrue(result.decisions)  # decisions retained
        json.loads(result.to_json())  # report still serializes

    def test_essential_alone_exceeding_budget_is_unsatisfiable(self):
        packet = make_packet(task="t" * 5000)
        result = apply_budget(packet, ContextBudget(max_estimated_tokens=50))
        self.assertEqual(result.status, "BUDGET_UNSATISFIABLE")
        self.assertIsNone(result.packet)


class DeterminismTests(unittest.TestCase):
    def test_same_packet_twice_byte_identical_report(self):
        a = rich_packet()
        b = rich_packet()
        budget = resolve_budget(profile="small")
        ra = apply_budget(a, budget)
        rb = apply_budget(b, budget)
        self.assertEqual(ra.to_json(), rb.to_json())
        self.assertEqual(ra.report_id, rb.report_id)

    def test_repeated_application_identical(self):
        packet = rich_packet()
        budget = resolve_budget(profile="small")
        reports = {apply_budget(packet, budget).to_json() for _ in range(3)}
        self.assertEqual(len(reports), 1)

    def test_report_id_format_and_sensitivity(self):
        packet = rich_packet()
        result = apply_budget(packet, resolve_budget(profile="small"))
        self.assertRegex(result.report_id, r"^bgr_[0-9a-f]{32}$")
        other = apply_budget(packet, resolve_budget(profile="medium"))
        self.assertNotEqual(result.report_id, other.report_id)


class ImmutabilityTests(unittest.TestCase):
    def test_original_packet_never_mutated(self):
        packet = rich_packet()
        before = packet.to_json()
        result = apply_budget(packet, resolve_budget(profile="small"))
        self.assertEqual(packet.to_json(), before)
        self.assertNotIn("budget", packet.diagnostics)
        self.assertTrue(result.packet.diagnostics["budget"]["budgeted"])

    def test_budgeted_packet_keeps_original_packet_id(self):
        packet = rich_packet()
        result = apply_budget(packet, resolve_budget(profile="small"))
        self.assertEqual(result.packet.packet_id, packet.packet_id)
        self.assertEqual(result.original_packet_id, packet.packet_id)


class BuilderFixtureTests(unittest.TestCase):
    """Integration over the R1E builder fixtures (Env/FakeCBMAdapter)."""

    def setUp(self):
        self.nodes = [
            node("add", "src.calc.add", "src/calc.py", start=1, end=40),
        ]
        self.env = Env(cbm=FakeCBMAdapter(self.nodes))
        self.addCleanup(self.env.cleanup)
        src = os.path.join(self.env.ws_dir, "src")
        os.makedirs(src, exist_ok=True)
        with open(os.path.join(src, "calc.py"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(f"line_{i:02d} " + "x" * 50 for i in range(40)))

    def build_symbol_packet(self):
        return self.env.builder().build(
            self.env.request(symbol="src.calc.add")
        )

    def test_warnings_survive_smallest_ok_budget_byte_identical(self):
        stale_ref = {
            "reference_kind": "symbol",
            "project_id": self.env.project_id,
            "file_path": "src/calc.py",
            "symbol_name": "add",
            "qualified_name": "src.calc.add",
            "start_line": 999,
            "cbm_project_name": SLUG,
        }
        env = Env(
            cbm=FakeCBMAdapter(
                [node("add", "src.calc.add", "src/calc.py", start=2, end=3)]
            )
        )
        self.addCleanup(env.cleanup)
        packet = env.builder().build(
            env.request(symbol=json.dumps(stale_ref))
        )
        packet.warnings.append(
            PacketWarning("cbm_unavailable", "synthetic second warning")
        )
        codes = [w.code for w in packet.warnings]
        self.assertIn("stale_code_reference", codes)
        self.assertIn("cbm_unavailable", codes)
        # bisect the smallest OK budget (reserve 0)
        lo, hi = 1, estimate_tokens(packet.to_json()) + 500
        while lo < hi:
            mid = (lo + hi) // 2
            res = apply_budget(packet, ContextBudget(max_estimated_tokens=mid))
            if res.satisfied:
                hi = mid
            else:
                lo = mid + 1
        result = apply_budget(packet, ContextBudget(max_estimated_tokens=lo))
        self.assertEqual(result.status, "OK")
        self.assertEqual(
            [w.to_dict() for w in result.packet.warnings],
            [w.to_dict() for w in packet.warnings],
        )

    def test_budget_layer_adds_no_new_warnings(self):
        packet = self.build_symbol_packet()
        result = apply_budget(packet, resolve_budget(profile="small"))
        self.assertEqual(
            [w.to_dict() for w in result.packet.warnings],
            [w.to_dict() for w in packet.warnings],
        )

    def test_cross_agent_removal_depends_on_position_not_agent(self):
        env = Env(seed=False)
        self.addCleanup(env.cleanup)
        first = env.save(
            memory_type="discovery", title="Note from opencode",
            body="o" * 1500, agent_type="opencode",
        )
        second = env.save(
            memory_type="discovery", title="Note from codex",
            body="c" * 1500, agent_type="codex",
        )
        packet = env.builder().build(env.request())
        order = [item.data["memory_id"] for item in packet.memories]
        self.assertEqual(set(order), {first.memory_id, second.memory_id})
        last_id = order[-1]
        max_tokens = budget_with_over(packet, over=20)
        result = apply_budget(
            packet, ContextBudget(max_estimated_tokens=max_tokens)
        )
        by_id = decisions_by_id(result)
        self.assertEqual(by_id[last_id].action, "omitted")
        survivor_id = order[0]
        self.assertEqual(by_id[survivor_id].action, "included")
        survivor = result.packet.memories[0]
        self.assertEqual(survivor.provenance.agent_type,
                         packet.memories[0].provenance.agent_type)
        self.assertIn(survivor.provenance.agent_type, ("opencode", "codex"))

    def test_workspace_local_other_workspace_never_leaks(self):
        packet = self.env.builder().build(
            self.env.request(workspace_id=self.env.workspace_id)
        )
        result = apply_budget(packet, resolve_budget(profile="small"))
        text = result.to_json()
        self.assertNotIn("Other workspace note", text)
        for decision in result.decisions:
            item = [
                i for i in packet.memories
                if i.provenance.memory_id == decision.source_id
            ]
            if item:
                self.assertNotEqual(
                    item[0].data["title"], "Other workspace note"
                )

    def test_secrets_never_appear_in_budgeted_output_or_report(self):
        env = Env(seed=False)
        self.addCleanup(env.cleanup)
        secret = "ghp_abcdefghij1234567890"
        env.save(
            memory_type="decision", title="Leaked token",
            body=f"deploy token {secret} end",
        )
        packet = env.builder().build(env.request())
        result = apply_budget(packet, resolve_budget(profile="small"))
        self.assertNotIn(secret, result.packet.to_json())
        self.assertNotIn(secret, result.to_json())
        self.assertIn("[REDACTED]", result.packet.to_json())

    def test_no_absolute_workspace_paths_in_outputs(self):
        packet = self.build_symbol_packet()
        result = apply_budget(packet, resolve_budget(profile="small"))
        self.assertNotIn(self.env.ws_dir, result.packet.to_json())
        self.assertNotIn(self.env.ws_dir, result.to_json())

    def test_builder_packet_reduction_is_real(self):
        packet = self.build_symbol_packet()
        self.assertGreater(
            estimate_tokens(packet.to_json()),
            BUDGET_PROFILES["small"],
        )
        result = apply_budget(packet, resolve_budget(profile="small"))
        self.assertEqual(result.status, "OK")
        self.assertLessEqual(
            result.final_usage.estimated_tokens,
            BUDGET_PROFILES["small"] - result.budget.reserve_tokens,
        )
        self.assertGreater(result.final_usage.omitted_count, 0)

    def test_builder_composition_diagnostics_preserved_verbatim(self):
        packet = self.build_symbol_packet()
        original = copy.deepcopy(packet.diagnostics)
        self.assertIn("counts", original)  # real R1E composition data
        result = apply_budget(packet, resolve_budget(profile="small"))
        self.assertEqual(result.packet.diagnostics["composition"], original)
        self.assertEqual(packet.diagnostics, original)
        diag = result.packet.diagnostics["budget"]
        self.assertEqual(
            diag["included_source_ids"], packet_source_ids(result.packet)
        )


class RenderingTests(unittest.TestCase):
    def test_budgeted_packet_json_and_markdown(self):
        packet = make_packet(
            facts=[fact_item("ref_f", snippet="s" * 2000,
                             name="src.calc.add")],
        )
        max_tokens = budget_with_over(packet, over=10)
        result = apply_budget(
            packet, ContextBudget(max_estimated_tokens=max_tokens)
        )
        parsed = json.loads(result.packet.to_json())
        self.assertEqual(parsed["packet_id"], packet.packet_id)
        markdown = result.packet.to_markdown()
        self.assertIn("# RELINKRA CONTEXT", markdown)
        self.assertIn(TRUNCATION_MARKER.strip(), markdown)
        self.assertNotIn("budget_unsatisfiable", markdown)

    def test_report_json_carries_estimation_identity(self):
        packet = rich_packet()
        result = apply_budget(packet, resolve_budget(profile="small"))
        parsed = json.loads(result.to_json(pretty=True))
        self.assertEqual(parsed["estimation_method"], ESTIMATION_METHOD)
        self.assertEqual(parsed["estimation_version"], ESTIMATION_VERSION)
        self.assertEqual(parsed["budget"]["estimation_method"], "chars-per-token")


class CLITests(unittest.TestCase):
    def setUp(self):
        class FatEnv(Env):
            def seed_memories(self):
                self.save(memory_type="decision", title="Decision fat",
                          body="d" * 900)
                self.save(memory_type="constraint", title="Constraint fat",
                          body="c" * 900)
                self.save(memory_type="architecture", title="Arch fat",
                          body="a" * 900)
                self.save(memory_type="bug", title="Bug fat", body="b" * 900)
                self.save(memory_type="discovery", title="Discovery one",
                          body="x" * 1500)
                self.save(memory_type="discovery", title="Discovery two",
                          body="y" * 1500)
                self.save(memory_type="verification", title="Verification fat",
                          body="v" * 1200)
                self.save(memory_type="task_result", title="Task result fat",
                          body="t" * 1200)
                self.save(memory_type="pending", title="Pending fat",
                          body="p" * 700)
                self.save(memory_type="handoff", title="Handoff fat",
                          body="h" * 700)

        self.env = FatEnv()
        self.addCleanup(self.env.cleanup)

    def run_cli(self, argv, **kwargs):
        kwargs.setdefault("store", self.env.store)
        kwargs.setdefault("clock", fixed_clock)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = context_cli.main(argv, **kwargs)
        return code, out.getvalue(), err.getvalue()

    def base_argv(self, *extra):
        return [
            "--project-id", self.env.project_id,
            "--registry", self.env.registry_path,
            *extra,
        ]

    def test_no_budget_flags_byte_identical_regression(self):
        packet = self.env.builder().build(self.env.request())
        code, out, err = self.run_cli(self.base_argv())
        self.assertEqual(code, 0, err)
        self.assertEqual(out, packet.to_json() + "\n")
        self.assertEqual(err, "")

    def test_budget_small_produces_smaller_output(self):
        code_full, out_full, _ = self.run_cli(self.base_argv())
        code, out, err = self.run_cli(self.base_argv("--budget", "small"))
        self.assertEqual(code_full, 0)
        self.assertEqual(code, 0, err)
        self.assertLess(len(out), len(out_full))
        packet = json.loads(out)
        self.assertTrue(packet["diagnostics"]["budget"]["budgeted"])
        self.assertEqual(err, "")

    def test_max_tokens_overrides_profile(self):
        code, out, err = self.run_cli(
            self.base_argv("--budget", "large", "--max-tokens", "3000",
                           "--budget-report")
        )
        self.assertEqual(code, 0, err)
        report = json.loads(err)
        self.assertEqual(report["budget"]["max_estimated_tokens"], 3000)

    def test_budget_report_goes_to_stderr(self):
        code, out, err = self.run_cli(
            self.base_argv("--budget", "small", "--budget-report")
        )
        self.assertEqual(code, 0, err)
        report = json.loads(err)
        self.assertTrue(report["report_id"].startswith("bgr_"))
        self.assertEqual(report["status"], "OK")
        self.assertTrue(report["decisions"])
        packet = json.loads(out)  # stdout stays the packet
        self.assertEqual(packet["packet_version"], PACKET_VERSION)

    def test_unsatisfiable_exit_1_with_stderr_json(self):
        code, out, err = self.run_cli(self.base_argv("--max-tokens", "1"))
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        error = json.loads(err)
        self.assertEqual(error["error"], "budget_unsatisfiable")

    def test_budget_report_requires_a_budget(self):
        code, out, err = self.run_cli(self.base_argv("--budget-report"))
        self.assertEqual(code, 1)
        self.assertIn("error", json.loads(err))

    def test_invalid_max_tokens_exit_1(self):
        code, out, err = self.run_cli(self.base_argv("--max-tokens", "0"))
        self.assertEqual(code, 1)
        self.assertIn("error", json.loads(err))

    def test_markdown_with_budget(self):
        env = Env(
            cbm=FakeCBMAdapter(
                [node("add", "src.calc.add", "src/calc.py", start=1, end=40)]
            )
        )
        self.addCleanup(env.cleanup)
        src = os.path.join(env.ws_dir, "src")
        os.makedirs(src, exist_ok=True)
        with open(os.path.join(src, "calc.py"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(f"line_{i:02d} " + "x" * 50 for i in range(40)))
        out, err = io.StringIO(), io.StringIO()
        argv = [
            "--project-id", env.project_id,
            "--registry", env.registry_path,
            "--symbol", "src.calc.add",
            "--budget", "small",
            "--format", "markdown",
        ]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = context_cli.main(
                argv, store=env.store, cbm_adapter=env.cbm, clock=fixed_clock
            )
        self.assertEqual(code, 0, err.getvalue())
        self.assertIn("# RELINKRA CONTEXT", out.getvalue())


class PerformanceTests(unittest.TestCase):
    def test_budgeting_large_fixture_is_fast(self):
        packet = rich_packet()
        budget = resolve_budget(profile="small")
        apply_budget(packet, budget)  # warmup
        start = time.perf_counter()
        for _ in range(20):
            apply_budget(packet, budget)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 5.0)


ITEM_SECTION_ORDER = ("memories", "code_references", "code_facts",
                      "pending", "handoffs")


def packet_source_ids(packet):
    """Surviving source ids in packet order (mirrors the budget spec)."""
    ids = []
    for section in ITEM_SECTION_ORDER:
        for item in getattr(packet, section):
            if section in ("code_references", "code_facts"):
                ids.append(
                    item.provenance.code_reference_id
                    or item.data.get("code_reference_id")
                    or ""
                )
            else:
                ids.append(item.provenance.memory_id or "")
    return ids


class FinalDiagnosticsTests(unittest.TestCase):
    """FIX A: diagnostics['budget'] describes the FINAL packet exactly;
    diagnostics['composition'] preserves the original R1E dict verbatim."""

    def test_budget_diagnostics_match_final_packet_after_trimming(self):
        packet = rich_packet()
        budget = resolve_budget(profile="small")
        result = apply_budget(packet, budget)
        self.assertEqual(result.status, "OK")
        final = result.packet
        diag = final.diagnostics["budget"]
        self.assertTrue(diag["budgeted"])
        self.assertEqual(diag["max_estimated_tokens"], BUDGET_PROFILES["small"])
        self.assertIn("reserve_tokens", diag)
        self.assertEqual(diag["estimation_method"], ESTIMATION_METHOD)
        self.assertEqual(diag["estimation_version"], ESTIMATION_VERSION)
        self.assertTrue(diag["satisfied"])
        # counts computed from the ACTUAL final packet
        self.assertEqual(
            diag["final_counts"],
            {
                "memories": len(final.memories),
                "code_references": len(final.code_references),
                "code_facts": len(final.code_facts),
                "pending": len(final.pending),
                "handoffs": len(final.handoffs),
                "warnings": len(final.warnings),
            },
        )
        # id lists match the ACTUAL final packet / audit trail exactly
        self.assertEqual(diag["included_source_ids"], packet_source_ids(final))
        self.assertEqual(
            diag["omitted_source_ids"],
            [
                d.source_id
                for d in result.decisions
                if d.action == "omitted"
                and d.section != "essential"
                and not d.source_id.startswith("snippet:")
            ],
        )
        self.assertEqual(
            diag["truncated_source_ids"],
            [
                d.source_id[len("snippet:"):]
                for d in result.decisions
                if d.source_id.startswith("snippet:")
                and d.action in ("truncated", "reference_only")
            ],
        )
        self.assertTrue(diag["omitted_source_ids"])  # trimming happened
        # totals describe the exact shipped payload
        self.assertEqual(diag["final_total_chars"], len(final.to_json()))
        self.assertEqual(
            diag["final_estimated_tokens"],
            estimate_tokens(final.to_json(), budget.chars_per_token),
        )

    def test_composition_diagnostics_preserved_verbatim(self):
        packet = rich_packet()
        original = copy.deepcopy(packet.diagnostics)
        result = apply_budget(packet, resolve_budget(profile="small"))
        self.assertEqual(result.packet.diagnostics["composition"], original)
        self.assertEqual(
            set(result.packet.diagnostics), {"composition", "budget"}
        )
        self.assertEqual(packet.diagnostics, original)  # input untouched

    def test_untrimmed_packet_stats(self):
        packet = rich_packet()
        budget = ContextBudget(max_estimated_tokens=10 ** 9)
        result = apply_budget(packet, budget)
        diag = result.packet.diagnostics["budget"]
        self.assertEqual(diag["omitted_source_ids"], [])
        self.assertEqual(diag["truncated_source_ids"], [])
        self.assertEqual(diag["included_source_ids"], packet_source_ids(packet))
        self.assertEqual(diag["final_counts"]["memories"], len(packet.memories))
        self.assertTrue(diag["satisfied"])
        self.assertEqual(
            diag["final_total_chars"], len(result.packet.to_json())
        )


class SnippetTypeValidationTests(unittest.TestCase):
    """FIX B: malformed typed packets are REJECTED at the boundary."""

    def packet_with_snippet(self, snippet, present=True):
        item = fact_item("ref_b")
        item.data.pop("snippet", None)
        item.data.pop("snippet_truncated", None)
        if present:
            item.data["snippet"] = snippet
        return make_packet(facts=[item])

    def big_budget(self):
        return ContextBudget(max_estimated_tokens=10 ** 9)

    def test_none_snippet_is_safe_and_treated_as_no_snippet(self):
        packet = self.packet_with_snippet(None)
        result = apply_budget(packet, self.big_budget())
        self.assertTrue(result.satisfied)
        self.assertFalse(
            any(d.source_id.startswith("snippet:") for d in result.decisions)
        )

    def test_absent_snippet_key_is_safe(self):
        packet = self.packet_with_snippet(None, present=False)
        result = apply_budget(packet, self.big_budget())
        self.assertTrue(result.satisfied)
        self.assertFalse(
            any(d.source_id.startswith("snippet:") for d in result.decisions)
        )

    def test_non_string_snippets_rejected(self):
        for bad in (123, 4.5, True, ["x"], {"code": "s3cr3t"}):
            packet = self.packet_with_snippet(bad)
            with self.assertRaises(BudgetValidationError) as ctx:
                apply_budget(packet, self.big_budget())
            message = str(ctx.exception)
            self.assertIn("code_facts[0]", message)
            self.assertIn(type(bad).__name__, message)

    def test_validation_error_is_value_error(self):
        packet = self.packet_with_snippet(123)
        with self.assertRaises(ValueError):
            apply_budget(packet, self.big_budget())

    def test_error_message_never_contains_snippet_value(self):
        packet = self.packet_with_snippet({"token": "ghp_secretmarker123"})
        with self.assertRaises(BudgetValidationError) as ctx:
            apply_budget(packet, self.big_budget())
        self.assertNotIn("ghp_secretmarker123", str(ctx.exception))

    def test_prepare_budgeted_packet_also_validates(self):
        packet = self.packet_with_snippet(["not", "a", "string"])
        with self.assertRaises(BudgetValidationError):
            prepare_budgeted_packet(packet, self.big_budget())

    def test_normal_string_snippet_accepted(self):
        packet = self.packet_with_snippet("print('hi')")
        result = apply_budget(packet, self.big_budget())
        self.assertTrue(result.satisfied)
        self.assertTrue(
            any(d.source_id == "snippet:ref_b" for d in result.decisions)
        )


class AuditCollisionTests(unittest.TestCase):
    """FIX D: duplicated/empty source ids never collapse audit entries."""

    def test_duplicate_ids_same_section_get_own_decisions(self):
        packet = make_packet(
            memories=[
                memory_item("mem_keep", "decision", "d" * 100),
                memory_item("mem_dup", "discovery", "x" * 1500),
                memory_item("mem_dup", "discovery", "y" * 1500),
            ]
        )
        max_tokens = budget_with_over(packet, over=20)
        result = apply_budget(
            packet, ContextBudget(max_estimated_tokens=max_tokens)
        )
        self.assertTrue(result.satisfied)
        dups = [
            d
            for d in result.decisions
            if d.source_id == "mem_dup" and d.section == "memories"
        ]
        self.assertEqual(len(dups), 2)
        self.assertEqual(dups[0].action, "included")
        self.assertEqual(dups[1].action, "omitted")  # END omitted first
        self.assertEqual(
            dups[1].reason, "optional_section_budget_exhausted"
        )
        survivors = [
            m
            for m in result.packet.memories
            if m.provenance.memory_id == "mem_dup"
        ]
        self.assertEqual(len(survivors), 1)
        self.assertEqual(survivors[0].data["body"], "x" * 1500)

    def test_duplicate_ids_across_sections_are_independent(self):
        packet = make_packet(
            memories=[memory_item("mem_x", "discovery", "x" * 1500)],
            pending=[memory_item("mem_x", "pending", "p" * 100)],
        )
        max_tokens = budget_with_over(packet, over=20)
        result = apply_budget(
            packet, ContextBudget(max_estimated_tokens=max_tokens)
        )
        self.assertTrue(result.satisfied)
        mem = [
            d
            for d in result.decisions
            if d.source_id == "mem_x" and d.section == "memories"
        ]
        pen = [
            d
            for d in result.decisions
            if d.source_id == "mem_x" and d.section == "pending"
        ]
        self.assertEqual(len(mem), 1)
        self.assertEqual(len(pen), 1)
        self.assertEqual(mem[0].action, "omitted")
        self.assertEqual(pen[0].action, "included")

    def test_empty_source_ids_each_get_own_decision(self):
        packet = make_packet(
            memories=[
                memory_item("", "discovery", "x" * 900),
                memory_item("", "discovery", "y" * 900),
                memory_item("", "discovery", "z" * 900),
            ]
        )
        max_tokens = budget_with_over(packet, over=500)
        result = apply_budget(
            packet, ContextBudget(max_estimated_tokens=max_tokens)
        )
        self.assertTrue(result.satisfied)
        empties = [
            d
            for d in result.decisions
            if d.source_id == "" and d.section == "memories"
        ]
        self.assertEqual(len(empties), 3)
        self.assertEqual(empties[0].action, "included")
        self.assertEqual(empties[1].action, "omitted")
        self.assertEqual(empties[2].action, "omitted")

    def test_repeated_builds_with_collisions_are_byte_identical(self):
        def build():
            return make_packet(
                memories=[
                    memory_item("mem_dup", "discovery", "x" * 1500),
                    memory_item("mem_dup", "discovery", "y" * 1500),
                    memory_item("", "verification", "v" * 1200),
                ]
            )

        budget = resolve_budget(profile="small")
        first = apply_budget(build(), budget)
        second = apply_budget(build(), budget)
        self.assertEqual(first.to_json(), second.to_json())
        self.assertEqual(first.report_id, second.report_id)
        again = {apply_budget(build(), budget).to_json() for _ in range(3)}
        self.assertEqual(len(again), 1)

    def test_every_item_gets_exactly_one_decision_with_collisions(self):
        packet = make_packet(
            memories=[
                memory_item("mem_dup", "decision", "d" * 900),
                memory_item("mem_dup", "discovery", "x" * 1500),
                memory_item("", "verification", "v" * 1200),
            ],
            facts=[
                fact_item("ref_dup", snippet="s" * 2000),
                fact_item("ref_dup", snippet="t" * 2000,
                          name="src.mod.other"),
            ],
            pending=[memory_item("", "pending", "p" * 700)],
        )
        max_tokens = budget_with_over(packet, over=600)
        result = apply_budget(
            packet, ContextBudget(max_estimated_tokens=max_tokens)
        )
        total_items = sum(
            len(getattr(packet, section)) for section in ITEM_SECTION_ORDER
        )
        snippet_count = sum(
            1
            for fact in packet.code_facts
            if isinstance(fact.data.get("snippet"), str)
        )
        self.assertEqual(
            len(result.decisions), 1 + total_items + snippet_count
        )
        dup_facts = [
            d
            for d in result.decisions
            if d.source_id == "ref_dup" and d.section == "code_facts"
        ]
        self.assertEqual(len(dup_facts), 2)
        dup_snippets = [
            d
            for d in result.decisions
            if d.source_id == "snippet:ref_dup"
        ]
        self.assertEqual(len(dup_snippets), 2)


class CLIUnsatisfiableContractTests(unittest.TestCase):
    """FIX C: exactly ONE JSON document per stream on unsatisfiable."""

    def setUp(self):
        class FatEnv(Env):
            def seed_memories(self):
                self.save(memory_type="decision", title="Decision fat",
                          body="d" * 900)
                self.save(memory_type="constraint", title="Constraint fat",
                          body="c" * 900)
                self.save(memory_type="architecture", title="Arch fat",
                          body="a" * 900)
                self.save(memory_type="bug", title="Bug fat", body="b" * 900)
                self.save(memory_type="discovery", title="Discovery one",
                          body="x" * 1500)
                self.save(memory_type="discovery", title="Discovery two",
                          body="y" * 1500)
                self.save(memory_type="verification", title="Verification fat",
                          body="v" * 1200)
                self.save(memory_type="task_result", title="Task result fat",
                          body="t" * 1200)
                self.save(memory_type="pending", title="Pending fat",
                          body="p" * 700)
                self.save(memory_type="handoff", title="Handoff fat",
                          body="h" * 700)

        self.env = FatEnv()
        self.addCleanup(self.env.cleanup)

    def run_cli(self, argv, **kwargs):
        kwargs.setdefault("store", self.env.store)
        kwargs.setdefault("clock", fixed_clock)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = context_cli.main(argv, **kwargs)
        return code, out.getvalue(), err.getvalue()

    def base_argv(self, *extra):
        return [
            "--project-id", self.env.project_id,
            "--registry", self.env.registry_path,
            *extra,
        ]

    def assert_single_error_doc(self, err, expect_report):
        # json.loads rejects concatenated documents ("Extra data"), so a
        # successful parse of the whole stream proves exactly ONE document.
        doc = json.loads(err)
        self.assertEqual(doc["error"], "budget_unsatisfiable")
        self.assertTrue(doc["packet_id"].startswith("pkt_"))
        self.assertEqual(doc["max_estimated_tokens"], 1)
        self.assertNotIn("Traceback", err)
        if expect_report:
            report = doc["budget_report"]
            self.assertEqual(report["status"], "BUDGET_UNSATISFIABLE")
            self.assertTrue(report["report_id"].startswith("bgr_"))
            self.assertTrue(report["decisions"])
        else:
            self.assertNotIn("budget_report", doc)

    def test_json_unsatisfiable_without_report(self):
        code, out, err = self.run_cli(
            self.base_argv("--format", "json", "--max-tokens", "1")
        )
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assert_single_error_doc(err, expect_report=False)

    def test_unsatisfiable_with_report(self):
        code, out, err = self.run_cli(
            self.base_argv("--max-tokens", "1", "--budget-report")
        )
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assert_single_error_doc(err, expect_report=True)

    def test_json_unsatisfiable_with_report(self):
        code, out, err = self.run_cli(
            self.base_argv(
                "--format", "json", "--max-tokens", "1", "--budget-report"
            )
        )
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assert_single_error_doc(err, expect_report=True)

    def test_markdown_unsatisfiable_with_report(self):
        code, out, err = self.run_cli(
            self.base_argv(
                "--format", "markdown", "--max-tokens", "1",
                "--budget-report",
            )
        )
        self.assertEqual(code, 1)
        self.assertEqual(out, "")  # no markdown on unsatisfiable
        self.assert_single_error_doc(err, expect_report=True)


if __name__ == "__main__":
    unittest.main()
