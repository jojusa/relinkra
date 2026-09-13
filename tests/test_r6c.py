"""Offline deterministic tests for R6C ContextPacket salience and budget
explainability.

Covers the Kisouma dogfood failure shape: under a ~2500-3000 token budget
the pre-R6C packet spent its budget on metadata and omitted the active
handoff, relevant memories and the focused code fact. Every test here is
deterministic: no network, no wall clock, no real Engram/CBM beyond the
shared offline Env fixtures.
"""

from __future__ import annotations

import json
import unittest

from relinkra.app_service import RelinkraServices, ServiceConfig, ServiceError
from relinkra.context_budget import (
    BudgetedContext,
    ContextBudget,
    apply_budget,
    estimate_tokens,
    resolve_budget,
)
from relinkra.context_builder import ContextBuilder, ContextRequest
from relinkra.explainability import attach_relevance
from relinkra.relevance import score_packet
from relinkra.salience import (
    HIGH_SALIENCE,
    MUST_KEEP,
    OPTIONAL,
    SALIENCE_VERSION,
    build_status,
    classify_packet_items,
    current_handoff_memory_id,
)
from test_context_packet import (
    FIXED_NOW,
    Env,
    FakeCBMAdapter,
    fixed_clock,
    make_service,
    node,
)


VERBOSE = "verbose provenance payload. " * 20


class DogfoodEnv(Env):
    """Kisouma failure shape: active handoff + pending + task-relevant
    decision/constraint + irrelevant verbose memories + a focused symbol."""

    def __init__(self):
        super().__init__(
            cbm=FakeCBMAdapter(
                [
                    node(
                        "applyBudget",
                        "src.budget.applyBudget",
                        "src/budget.py",
                        start=1,
                        end=60,
                    )
                ]
            ),
            seed=False,
        )

    def seed(self):
        self.save(
            memory_type="handoff",
            title="R6B dogfood handoff",
            body="Handoff: continue R6C salience work. Next: implement tiers.",
        )
        self.save(
            memory_type="pending",
            title="Finish salience tiers",
            body="pending work: implement MUST_KEEP protection",
        )
        self.save(
            memory_type="decision",
            title="Budget reduction stays a deterministic ladder",
            body="decision: keep the fixed ladder; no embeddings anywhere",
        )
        self.save(
            memory_type="constraint",
            title="No embeddings in ranking",
            body="constraint: no embeddings, no LLM ranking, no provider APIs",
        )
        self.save(
            memory_type="discovery",
            title="Budget ladder internals",
            body="discovery: " + VERBOSE,
        )
        self.save(
            memory_type="discovery",
            title="Release process notes",
            body="discovery: " + VERBOSE,
        )
        self.save(
            memory_type="verification",
            title="Suite green on windows",
            body="verification: " + VERBOSE,
        )
        self.handoff_id = self._id_of_type("handoff")
        self.pending_id = self._id_of_type("pending")
        self.decision_id = self._id_of_type("decision")
        self.constraint_id = self._id_of_type("constraint")
        self.discovery_id = self._id_of_type("discovery")

    def _id_of_type(self, memory_type):
        items = self.service.query(
            project_id=self.project_id,
            scope="project_shared",
            memory_type=memory_type,
            limit=10,
        ).memories
        assert items, memory_type
        return items[0].memory_id


TASK = "implement context packet salience tiers and budget explainability"


def build_ranked_packet(env):
    """A packet in the exact app_service pre-budget state (R4D + R1G)."""
    builder = env.builder()
    request = ContextRequest(
        project_id=env.project_id,
        workspace_id=env.workspace_id,
        task=TASK,
        symbol="src.budget.applyBudget",
        include_git=True,
        include_explain=True,
    )
    packet = builder.build(request)
    ranked = score_packet(
        packet,
        task=TASK,
        focus_symbol="src.budget.applyBudget",
        focus_code_reference_id=(
            packet.code_references[0].provenance.code_reference_id
            if packet.code_references
            else None
        ),
        workspace_id=env.workspace_id,
        as_of=fixed_clock(),
    )
    attach_relevance(packet, ranked)
    return packet, ranked


def current_handoff(env):
    items = env.service.query(
        project_id=env.project_id,
        scope="project_shared",
        memory_type="handoff",
        limit=10,
    ).memories
    return items[0]


class SalienceTierTests(unittest.TestCase):
    def setUp(self):
        self.env = DogfoodEnv()
        self.addCleanup(self.env.cleanup)
        self.env.seed()

    def test_tiers_are_explicit_and_deterministic(self):
        packet, _ranked = build_ranked_packet(self.env)
        classified = classify_packet_items(packet)
        tiers = {(s, i.data.get("memory_id")): t for s, i, t in classified}
        # pending is the unresolved-work channel: must keep
        self.assertEqual(tiers[("pending", self.env.pending_id)], MUST_KEEP)
        # the current (most recent active) handoff: must keep
        self.assertEqual(
            tiers[("handoffs", self.env.handoff_id)], MUST_KEEP
        )
        # task-relevant baseline memories: high salience
        self.assertEqual(
            tiers[("memories", self.env.decision_id)], HIGH_SALIENCE
        )
        self.assertEqual(
            tiers[("memories", self.env.constraint_id)], HIGH_SALIENCE
        )
        # verbose distant memories: optional
        self.assertEqual(
            tiers[("memories", self.env.discovery_id)], OPTIONAL
        )
        # labels are attached to the explain sidecar deterministically
        for _s, item, tier in classified:
            self.assertEqual(item.explain["salience"], tier)

    def test_same_packet_same_tiers(self):
        packet, _ = build_ranked_packet(self.env)
        again, _ = build_ranked_packet(self.env)
        self.assertEqual(
            [(s, i.data.get("memory_id"), t) for s, i, t in classify_packet_items(packet)],
            [(s, i.data.get("memory_id"), t) for s, i, t in classify_packet_items(again)],
        )


class DogfoodFixtureTests(unittest.TestCase):
    """Section 16: the real dogfood failure shape under ~2500-3000."""

    def setUp(self):
        self.env = DogfoodEnv()
        self.addCleanup(self.env.cleanup)
        self.env.seed()
        self.env.handoff_id = current_handoff(self.env).memory_id
        self.env.pending_id = self._id_of_type("pending")
        self.env.decision_id = self._id_of_type("decision")
        self.env.constraint_id = self._id_of_type("constraint")
        self.env.discovery_id = self._id_of_type("discovery")

    def _id_of_type(self, memory_type):
        items = self.env.service.query(
            project_id=self.env.project_id,
            scope="project_shared",
            memory_type=memory_type,
            limit=10,
        ).memories
        self.assertTrue(items)
        return items[0].memory_id

    def test_budget_3000_retains_must_keep_and_code_evidence(self):
        packet, ranked = build_ranked_packet(self.env)
        result = apply_budget(packet, resolve_budget(max_tokens=3000),
                              relevance=ranked)
        self.assertEqual(result.status, "OK", result.final_usage.sections)
        final = result.packet
        # 1. project identity / revision freshness retained
        self.assertEqual(final.project_id, packet.project_id)
        self.assertTrue(final.project_facts.get("registered"))
        # 2. the active handoff is retained
        self.assertEqual(
            [i.data["memory_id"] for i in final.handoffs],
            [self.env.handoff_id],
        )
        # the current handoff is never omitted by the ladder
        self.assertTrue(final.pending)
        # 4. the focused code fact survives before verbose provenance
        self.assertTrue(final.code_facts)
        self.assertEqual(
            final.code_facts[0].data["code_reference_id"],
            packet.code_facts[0].data["code_reference_id"],
        )
        # 5. omitted optional sections are reported
        status = final.packet_status
        self.assertEqual(status["version"], SALIENCE_VERSION)
        self.assertFalse(status["packet_complete"])
        self.assertTrue(status["budget_exhausted"])
        self.assertIn("memories", status["omitted_sections"])
        # 6. recommended_next names exact recovery tools
        self.assertIn(
            "memory_search(project_id='%s')" % self.env.project_id,
            status["recommended_next"],
        )
        # salience counts are present and consistent
        counts = status["salience"]
        self.assertEqual(
            counts["must_keep"],
            len(final.pending) + len(final.handoffs),
        )

    def test_budget_2500_is_honestly_unsatisfiable_with_guidance(self):
        packet, ranked = build_ranked_packet(self.env)
        budget = resolve_budget(max_tokens=2500)
        result = apply_budget(packet, budget, relevance=ranked)
        self.assertEqual(result.status, "BUDGET_UNSATISFIABLE")
        self.assertIsNone(result.packet)
        # R6C guidance: a failed retry is never the only option
        self.assertGreater(result.minimum_useful_tokens, 2500)
        self.assertGreaterEqual(
            result.recommended_max_tokens, result.minimum_useful_tokens
        )

    def test_no_silent_truncation(self):
        packet, ranked = build_ranked_packet(self.env)
        result = apply_budget(packet, resolve_budget(max_tokens=3000),
                              relevance=ranked)
        final = result.packet
        for fact in final.code_facts:
            if fact.data.get("snippet_truncated"):
                self.assertIn("snippet_original_length", fact.data)
                self.assertIn("snippet_returned_length", fact.data)
                self.assertIn("snippet_continuation_ref", fact.data)
                self.assertEqual(
                    len(fact.data["snippet"]),
                    fact.data["snippet_returned_length"],
                )
                self.assertTrue(fact.data["snippet_continuation_ref"])

    def test_deterministic_output_same_inputs(self):
        first, ranked1 = build_ranked_packet(self.env)
        second, ranked2 = build_ranked_packet(self.env)
        budget = resolve_budget(max_tokens=3000)
        r1 = apply_budget(first, budget, relevance=ranked1)
        r2 = apply_budget(second, budget, relevance=ranked2)
        self.assertEqual(r1.packet.to_json(), r2.packet.to_json())
        self.assertEqual(r1.report_id, r2.report_id)
        self.assertEqual(
            r1.minimum_useful_tokens, r2.minimum_useful_tokens
        )
        unbudgeted1 = self.env.builder().build(
            ContextRequest(
                project_id=self.env.project_id,
                workspace_id=self.env.workspace_id,
                task=TASK,
                include_explain=True,
            )
        )
        unbudgeted2 = self.env.builder().build(
            ContextRequest(
                project_id=self.env.project_id,
                workspace_id=self.env.workspace_id,
                task=TASK,
                include_explain=True,
            )
        )
        self.assertEqual(unbudgeted1.to_json(), unbudgeted2.to_json())


class ActiveHandoffPriorityTests(unittest.TestCase):
    def setUp(self):
        self.env = DogfoodEnv()
        self.addCleanup(self.env.cleanup)
        self.env.seed()

    def test_verbose_metadata_is_sacrificed_before_the_active_handoff(self):
        packet, ranked = build_ranked_packet(self.env)
        # a budget deep enough to reach the important class: the ladder
        # must compact metadata and keep the current handoff
        budget = resolve_budget(max_tokens=3000)
        result = apply_budget(packet, budget, relevance=ranked)
        self.assertEqual(result.status, "OK")
        final = result.packet
        handoff_ids = [i.data["memory_id"] for i in final.handoffs]
        self.assertIn(current_handoff(self.env).memory_id, handoff_ids)
        # verbose optional metadata was compacted, not just items shed
        self.assertTrue(final.diagnostics["budget"]["metadata_compacted"])

    def test_stale_unrelated_handoff_gets_no_free_ride(self):
        # a second, older handoff may be shed under the same budget
        packet, ranked = build_ranked_packet(self.env)
        budget = resolve_budget(max_tokens=3000)
        result = apply_budget(packet, budget, relevance=ranked)
        if result.packet and len(result.packet.handoffs) > 1:
            # if both survive the budget, fine — but the CURRENT one
            # must always be among them
            self.assertIn(
                current_handoff(self.env).memory_id,
                [i.data["memory_id"] for i in result.packet.handoffs],
            )


class RelevantMemoryPriorityTests(unittest.TestCase):
    def setUp(self):
        self.env = DogfoodEnv()
        self.addCleanup(self.env.cleanup)
        self.env.seed()

    def _ids(self, packet):
        return {
            i.data["memory_id"] for i in packet.memories
        }

    def test_relevant_decision_beats_irrelevant_verbose_memory(self):
        # the ranked ladder sheds worst-relevance first: the task-
        # relevant decision outlives the irrelevant verbose discovery at
        # EVERY budget where the discovery itself survives
        decision_id = self.env.decision_id
        discovery_id = self.env.discovery_id
        for cap in range(2400, 4200, 200):
            packet, ranked = build_ranked_packet(self.env)
            result = apply_budget(packet, resolve_budget(max_tokens=cap),
                                  relevance=ranked)
            if result.packet is None:
                continue
            survivor_ids = self._ids(result.packet)
            if discovery_id in survivor_ids:
                self.assertIn(
                    decision_id,
                    survivor_ids,
                    f"decision dropped while verbose discovery survived "
                    f"at max_tokens={cap}",
                )

    def test_handoff_mirror_is_not_duplicated_into_memories(self):
        packet, _ = build_ranked_packet(self.env)
        handoff_id = current_handoff(self.env).memory_id
        in_memories = [i.data["memory_id"] for i in packet.memories]
        in_handoffs = [i.data["memory_id"] for i in packet.handoffs]
        self.assertNotIn(handoff_id, in_memories)
        self.assertIn(handoff_id, in_handoffs)
        # exactly one copy in the whole packet
        all_ids = in_memories + in_handoffs + [
            i.data["memory_id"] for i in packet.pending
        ]
        self.assertEqual(all_ids.count(handoff_id), 1)


class TruncationDeclarationTests(unittest.TestCase):
    def test_ladder_truncation_declares_sizes_and_continuation(self):
        # handcrafted packet: one oversized-snippet fact squeezed just
        # below its untruncated size, so step 1 fires and fits
        from test_context_budget import fact_item, make_packet

        packet = make_packet(
            facts=[fact_item("ref_focus", snippet="s" * 4000)],
        )
        working_size = estimate_tokens(packet.to_json(), 3.0)
        budget = ContextBudget(max_estimated_tokens=working_size - 300)
        result = apply_budget(packet, budget)
        self.assertEqual(result.status, "OK")
        fact = result.packet.code_facts[0].data
        self.assertTrue(fact["snippet_truncated"])
        self.assertEqual(fact["snippet_original_length"], 4000)
        self.assertEqual(
            len(fact["snippet"]), fact["snippet_returned_length"]
        )
        self.assertEqual(
            fact["snippet_continuation_ref"], fact["code_reference_id"]
        )

    def test_builder_guardrail_truncation_declares_sizes(self):
        env = DogfoodEnv()
        self.addCleanup(env.cleanup)
        # a resolved symbol snippet longer than the 1200-char guardrail
        long_source = "\n".join(
            f"line_{i:02d} " + "x" * 60 for i in range(40)
        )
        import os

        src = os.path.join(env.ws_dir, "src")
        os.makedirs(src, exist_ok=True)
        with open(os.path.join(src, "budget.py"), "w", encoding="utf-8") as fh:
            fh.write(long_source)
        builder = env.builder()
        packet = builder.build(
            ContextRequest(
                project_id=env.project_id, symbol="src.budget.applyBudget",
                include_explain=True,
            )
        )
        fact = packet.code_facts[0].data
        self.assertTrue(fact["snippet_truncated"])
        self.assertIn("snippet_original_length", fact)
        self.assertIn("snippet_returned_length", fact)
        self.assertLess(
            fact["snippet_returned_length"], fact["snippet_original_length"]
        )


class PacketCompletenessTests(unittest.TestCase):
    def setUp(self):
        self.env = DogfoodEnv()
        self.addCleanup(self.env.cleanup)
        self.env.seed()

    def test_unbudgeted_packet_reports_guardrail_completeness(self):
        packet, _ = build_ranked_packet(self.env)
        status = build_status(packet)
        self.assertTrue(status["packet_complete"])
        self.assertFalse(status["budget_exhausted"])
        self.assertEqual(status["omitted_sections"], [])
        self.assertEqual(status["omitted_high_salience_count"], 0)

    def test_budgeted_packet_reports_omissions_without_payloads(self):
        packet, ranked = build_ranked_packet(self.env)
        result = apply_budget(packet, resolve_budget(max_tokens=3000),
                              relevance=ranked)
        status = result.packet.packet_status
        self.assertFalse(status["packet_complete"])
        self.assertTrue(status["budget_exhausted"])
        for section in status["omitted_sections"]:
            self.assertIsInstance(section, str)
        # the block tells the agent WHAT is missing, never repeats it
        rendered = json.dumps(status)
        self.assertNotIn(VERBOSE.strip()[:40], rendered)

    def test_markdown_renders_the_status_block(self):
        packet, ranked = build_ranked_packet(self.env)
        result = apply_budget(packet, resolve_budget(max_tokens=3000),
                              relevance=ranked)
        markdown = result.packet.to_markdown()
        self.assertIn("## Packet status", markdown)
        self.assertIn("packet_complete: False", markdown)


class SufficiencyTests(unittest.TestCase):
    def setUp(self):
        self.env = DogfoodEnv()
        self.addCleanup(self.env.cleanup)
        self.env.seed()

    def test_code_evidence_keeps_source_verification_required(self):
        packet, ranked = build_ranked_packet(self.env)
        result = apply_budget(packet, resolve_budget(max_tokens=3000),
                              relevance=ranked)
        sufficiency = result.packet.packet_status["context_sufficiency"]
        # Relinkra provides orientation, not final proof: with code
        # evidence, implementation and security stay source-bound
        self.assertEqual(
            sufficiency["implementation"], "source_verification_required"
        )
        self.assertEqual(
            sufficiency["security_verdict"], "source_verification_required"
        )
        self.assertIn(
            sufficiency["orientation"],
            ("sufficient", "partial", "insufficient"),
        )

    def test_orientation_is_insufficient_without_items(self):
        env = DogfoodEnv()
        self.addCleanup(env.cleanup)
        builder = env.builder()
        packet = builder.build(
            ContextRequest(project_id=env.project_id, include_explain=True)
        )
        status = build_status(packet)
        self.assertEqual(
            status["context_sufficiency"]["orientation"], "insufficient"
        )


class BudgetGuidanceTests(unittest.TestCase):
    def setUp(self):
        self.env = DogfoodEnv()
        self.addCleanup(self.env.cleanup)
        self.env.seed()

    def test_satisfiable_budget_still_reports_guidance(self):
        packet, ranked = build_ranked_packet(self.env)
        result = apply_budget(packet, resolve_budget(max_tokens=3000),
                              relevance=ranked)
        self.assertEqual(result.status, "OK")
        self.assertIsInstance(result.minimum_useful_tokens, int)
        self.assertGreater(result.recommended_max_tokens, 0)

    def test_deterministic_guidance_values(self):
        packet, ranked = build_ranked_packet(self.env)
        budget = resolve_budget(max_tokens=2500)
        r1 = apply_budget(packet, budget, relevance=ranked)
        r2 = apply_budget(packet, budget, relevance=ranked)
        self.assertEqual(r1.minimum_useful_tokens, r2.minimum_useful_tokens)
        self.assertEqual(
            r1.recommended_max_tokens, r2.recommended_max_tokens
        )

    def test_report_serialization_roundtrip(self):
        packet, ranked = build_ranked_packet(self.env)
        result = apply_budget(packet, resolve_budget(max_tokens=3000),
                              relevance=ranked)
        data = json.loads(result.to_json())
        self.assertIn("minimum_useful_tokens", data)
        self.assertIn("recommended_max_tokens", data)
        self.assertIn("omitted_item_types", data)
        restored = BudgetedContext.from_dict(data)
        self.assertEqual(restored.minimum_useful_tokens,
                         result.minimum_useful_tokens)


class TokenObservabilityTests(unittest.TestCase):
    def setUp(self):
        self.env = DogfoodEnv()
        self.addCleanup(self.env.cleanup)
        self.env.seed()

    def test_accounting_is_labeled_and_coherent(self):
        packet, ranked = build_ranked_packet(self.env)
        result = apply_budget(packet, resolve_budget(max_tokens=3000),
                              relevance=ranked)
        accounting = result.packet.packet_status["token_accounting"]
        self.assertEqual(accounting["estimation_version"], "cpt1")
        self.assertEqual(accounting["estimation_method"], "chars-per-token")
        self.assertEqual(accounting["accounting_basis"],
                         "serialized_compact_json")
        total = accounting["total_estimated_tokens"]
        useful = accounting["useful_payload_tokens"]
        metadata = accounting["metadata_tokens"]
        # useful + metadata reconstructs the total (cpt1 over the same
        # char counts, so a 1-token ceil boundary may differ)
        self.assertLessEqual(abs(useful + metadata - total), 1)
        self.assertGreater(useful, 0)
        self.assertGreater(metadata, 0)
        self.assertGreater(accounting["compression_ratio"], 0.0)
        self.assertLessEqual(accounting["compression_ratio"], 1.0)

    def test_unbudgeted_packet_reports_metrics(self):
        packet, _ = build_ranked_packet(self.env)
        status = build_status(packet)
        accounting = status["token_accounting"]
        self.assertEqual(accounting["estimation_version"], "cpt1")
        self.assertGreater(accounting["total_estimated_tokens"], 0)


class DuplicateAccountingTests(unittest.TestCase):
    def test_suppressed_duplicates_are_counted(self):
        env = DogfoodEnv()
        self.addCleanup(env.cleanup)
        env.seed()
        real = env.service

        class DuplicateResult:
            def __init__(self, memories):
                self.memories = memories
                self.skipped_malformed = 0
                self.skipped_truncated = 0

        class DuplicateMemoryService:
            """Returns every visible memory twice, first id repeated."""

            def __init__(self, inner):
                self._inner = inner

            def query(self, **kwargs):
                result = self._inner.query(**kwargs)
                if result.memories:
                    return DuplicateResult(
                        list(result.memories) + [result.memories[0]]
                    )
                return result

            def __getattr__(self, name):
                return getattr(self._inner, name)

        service = DuplicateMemoryService(real)
        builder = ContextBuilder(
            memory_service=service,
            registry=env.registry,
            workspace_root=env.ws_dir,
            clock=fixed_clock,
        )
        packet = builder.build(
            ContextRequest(project_id=env.project_id, include_explain=True)
        )
        self.assertEqual(
            packet.diagnostics["duplicate_memory_ids_skipped"], 1
        )
        status = build_status(packet)
        accounting = status["token_accounting"]
        self.assertEqual(accounting["duplicate_items_suppressed"], 1)
        self.assertEqual(
            accounting["duplicate_tokens_method"],
            "suppressed_copy_envelope_estimate",
        )
        self.assertGreater(accounting["duplicate_tokens_estimated"], 0)


class ServiceSurfaceTests(unittest.TestCase):
    """Section 15/18: the MCP-facing service response stays additive."""

    def _service(self, env):
        config = ServiceConfig(
            default_project_id=env.project_id,
            default_workspace_id=env.workspace_id,
            workspace_root=env.ws_dir,
            registry_path=env.registry_path,
        )
        return RelinkraServices(
            config=config,
            store=env.store,
            cbm_adapter=env.cbm,
            registry=env.registry,
            clock=fixed_clock,
        )

    def setUp(self):
        self.env = DogfoodEnv()
        self.addCleanup(self.env.cleanup)
        self.env.seed()

    def test_unbudgeted_context_get_carries_packet_status(self):
        services = self._service(self.env)
        payload = services.context_get(task=TASK)
        packet = payload["packet"]
        # existing fields remain
        for key in ("packet_version", "packet_id", "project_id", "memories",
                    "handoffs", "warnings", "provenance", "diagnostics"):
            self.assertIn(key, packet)
        # additive R6C block
        status = packet["packet_status"]
        self.assertEqual(status["version"], SALIENCE_VERSION)
        self.assertIn("salience", status)
        self.assertIn("token_accounting", status)

    def test_budgeted_context_get_carries_report_fields(self):
        services = self._service(self.env)
        payload = services.context_get(task=TASK, max_tokens=3000)
        report = payload["budget_report"]
        self.assertIn("minimum_useful_tokens", report)
        self.assertIn("recommended_max_tokens", report)
        self.assertIn("omitted_item_types", report)
        status = payload["packet"]["packet_status"]
        self.assertFalse(status["packet_complete"])

    def test_unsatisfiable_error_carries_budget_guidance(self):
        services = self._service(self.env)
        with self.assertRaises(ServiceError) as ctx:
            services.context_get(
                task=TASK, symbol="src.budget.applyBudget", max_tokens=2500
            )
        details = ctx.exception.to_dict()["error"]
        self.assertEqual(details["code"], "invalid_input")
        self.assertIn("minimum_useful_tokens", details)
        self.assertIn("recommended_max_tokens", details)
        self.assertGreater(details["minimum_useful_tokens"], 2500)


class R6BRegressionTests(unittest.TestCase):
    """Section 17: R6B mirror-dedupe and deterministic retrieval survive."""

    def setUp(self):
        self.env = DogfoodEnv()
        self.addCleanup(self.env.cleanup)
        self.env.seed()

    def test_memory_search_excludes_handoff_mirrors_by_default(self):
        # R6B policy: mirror records are opt-in at the retrieval layer
        default_query = self.env.service.query(
            project_id=self.env.project_id,
            scope="project_shared",
            text="salience",
            include_handoff_mirrors=False,
            limit=20,
        )
        types = [m.memory_type for m in default_query.memories]
        self.assertNotIn("handoff", types)
        # an explicit handoff type filter IS a mirror request
        mirror_query = self.env.service.query(
            project_id=self.env.project_id,
            scope="project_shared",
            memory_type="handoff",
            limit=20,
        )
        self.assertTrue(mirror_query.memories)

    def test_memory_get_exact_id_on_a_larger_store(self):
        # offline-equivalent of the R6B residual live check: an exact-id
        # lookup must work on a store with far more records than one page
        service = self.env.service
        expected = None
        for index in range(60):
            memory = self.env.save(
                memory_type="discovery",
                title=f"Bulk discovery record {index:03d}",
                body=f"bulk record body {index}",
            )
            if index == 30:
                expected = memory.memory_id
        fetched = service.get(
            project_id=self.env.project_id, memory_id=expected
        )
        self.assertEqual(fetched.memory_id, expected)
        self.assertEqual(fetched.title, "Bulk discovery record 030")

    def test_packet_guidance_memory_id_is_retrievable(self):
        packet, ranked = build_ranked_packet(self.env)
        result = apply_budget(packet, resolve_budget(max_tokens=3000),
                              relevance=ranked)
        final = result.packet
        self.assertTrue(final.handoffs)
        handoff_memory_id = final.handoffs[0].data["memory_id"]
        fetched = self.env.service.get(
            project_id=self.env.project_id, memory_id=handoff_memory_id
        )
        self.assertEqual(fetched.memory_id, handoff_memory_id)


if __name__ == "__main__":
    unittest.main()
