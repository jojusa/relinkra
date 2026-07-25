"""Offline deterministic tests for R1G Deterministic Relevance Scoring.

No subprocess, no network, no real Engram/CBM: handcrafted packets with
controlled signals plus the R1E Env/FakeCBMAdapter/fixed_clock fixtures
and the R1F fixture helpers.
"""

from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import os
import unittest

from relinkra import context_cli
from relinkra.code_reference import CodeReference
from relinkra.context_budget import (
    BudgetValidationError,
    ContextBudget,
    apply_budget,
    resolve_budget,
)
from relinkra.context_packet import (
    ContextPacket,
    PacketItem,
    PacketWarning,
    Provenance,
)
from relinkra.relevance import (
    DEFAULT_WEIGHTS,
    RELEVANCE_VERSION,
    SIGNAL_ORDER,
    RelevanceValidationError,
    RelevanceWeights,
    score_packet,
    tokenize,
)
from test_context_budget import (
    budget_with_over,
    decisions_by_id,
    fact_item,
    make_packet,
    memory_item,
    ref_item,
    rich_packet,
)
from test_context_packet import (
    FIXED_NOW,
    PID,
    WID_UNKNOWN,
    Env,
    FakeCBMAdapter,
    fixed_clock,
    node,
)

AS_OF = FIXED_NOW  # 2026-02-01T00:00:00+00:00
WS_A = "ws_" + "a" * 32


def mem(mid, mtype, title=None, body="", ts=None, agent=None,
        scope="shared", link=None, code_refs=None):
    data = {
        "memory_id": mid,
        "project_id": PID,
        "memory_type": mtype,
        "title": title if title is not None else f"title {mid}",
        "body": body,
        "scope_channel": scope,
    }
    if ts is not None:
        data["timestamp"] = ts
    if code_refs is not None:
        data["code_refs"] = code_refs
    return PacketItem(
        data=data,
        provenance=Provenance(
            source="engram",
            why_included="relevance fixture",
            memory_id=mid,
            agent_type=agent,
            code_reference_id=link,
        ),
    )


def score(packet, **kwargs):
    kwargs.setdefault("as_of", AS_OF)
    return score_packet(packet, **kwargs)


def only_score(ranked, section, sid, occurrence=0):
    found = ranked.score_for(section, sid, occurrence)
    if found is None:
        raise AssertionError(f"no score for {section}/{sid}/{occurrence}")
    return found


def sig(score_obj, name):
    return dict(score_obj.signals)[name]


class TokenizerTests(unittest.TestCase):
    def test_camel_case(self):
        self.assertEqual(tokenize("generateOnly"), ("generate", "only"))

    def test_acronym_run(self):
        self.assertEqual(
            tokenize("XMLHttpRequest"), ("xml", "http", "request")
        )

    def test_snake_case(self):
        self.assertEqual(tokenize("apply_budget"), ("apply", "budget"))

    def test_kebab_case(self):
        self.assertEqual(tokenize("context-budget"), ("context", "budget"))

    def test_dotted_symbol(self):
        self.assertEqual(
            tokenize("src.invoice.generate"), ("src", "invoice", "generate")
        )

    def test_spanish_accent_folds(self):
        self.assertEqual(tokenize("árbol"), ("arbol",))

    def test_casefold_and_accents(self):
        self.assertEqual(tokenize("ÁRBOL Grándé"), ("arbol", "grande"))

    def test_english_sentence(self):
        self.assertEqual(
            tokenize("Fix the parser bug"),
            ("fix", "the", "parser", "bug"),
        )

    def test_dedupe_preserves_first_occurrence(self):
        self.assertEqual(tokenize("bug bug fix bug"), ("bug", "fix"))

    def test_min_length_two(self):
        self.assertEqual(tokenize("a b ab cd e"), ("ab", "cd"))

    def test_punctuation_collapses_and_empty(self):
        self.assertEqual(tokenize("...,,, ;;"), ())
        self.assertEqual(tokenize(""), ())
        self.assertEqual(tokenize(None), ())

    def test_letter_digit_boundaries_not_split(self):
        self.assertEqual(tokenize("r1g utf8"), ("r1g", "utf8"))


class WeightsTests(unittest.TestCase):
    def test_version_exposed(self):
        self.assertEqual(RELEVANCE_VERSION, "relevance-v1")

    def test_default_weights_central(self):
        w = DEFAULT_WEIGHTS
        self.assertEqual(w.direct_code_link, 40)
        self.assertEqual(w.symbol_match, 35)
        self.assertEqual(w.file_match, 25)
        self.assertEqual(w.workspace_match, 5)
        self.assertEqual(w.resolution_resolved, 4)
        self.assertEqual(w.resolution_stale, -8)
        self.assertEqual(w.resolution_ambiguous, -6)
        self.assertEqual(w.resolution_missing, -10)
        self.assertEqual(w.keyword_title_each, 6)
        self.assertEqual(w.keyword_title_cap, 18)
        self.assertEqual(w.keyword_code_each, 5)
        self.assertEqual(w.keyword_code_cap, 15)
        self.assertEqual(w.keyword_body_each, 2)
        self.assertEqual(w.keyword_body_cap, 10)

    def test_weights_frozen_and_unknown_type_zero(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            DEFAULT_WEIGHTS.direct_code_link = 1
        self.assertEqual(DEFAULT_WEIGHTS.memory_type_points("nope"), 0)
        self.assertEqual(DEFAULT_WEIGHTS.memory_type_points(None), 0)


class SignalTests(unittest.TestCase):
    def test_direct_code_link(self):
        packet = make_packet(
            memories=[mem("mem_l", "discovery", link="ref_focus")]
        )
        ranked = score(packet, focus_code_reference_id="ref_focus")
        self.assertEqual(
            sig(only_score(ranked, "memories", "mem_l"), "direct_code_link"),
            40,
        )
        ranked_off = score(packet)
        self.assertEqual(
            sig(
                only_score(ranked_off, "memories", "mem_l"),
                "direct_code_link",
            ),
            0,
        )

    def test_direct_code_link_via_code_refs(self):
        # production-shaped linkage: code_refs entries, no provenance id
        packet = make_packet(memories=[
            mem("mem_refs", "discovery",
                code_refs=[{"code_reference_id": "ref_focus"},
                           "junk-entry",
                           {"code_reference_id": 7},
                           {"no_id": True}]),
        ])
        ranked = score(packet, focus_code_reference_id="ref_focus")
        self.assertEqual(
            sig(only_score(ranked, "memories", "mem_refs"),
                "direct_code_link"),
            40,
        )
        # +40 fires ONCE even when several refs point at the focus
        packet_multi = make_packet(memories=[
            mem("mem_multi", "discovery",
                code_refs=[{"code_reference_id": "ref_focus"},
                           {"code_reference_id": "ref_focus"},
                           {"code_reference_id": "ref_other"}]),
        ])
        entry = only_score(
            score(packet_multi, focus_code_reference_id="ref_focus"),
            "memories", "mem_multi",
        )
        self.assertEqual(sig(entry, "direct_code_link"), 40)
        self.assertEqual(entry.total, 40 + 6)  # link + discovery type

    def test_direct_code_link_fires_on_builder_packet(self):
        # production wiring: REAL ContextBuilder packet, memory linked
        # via memory.code_refs (provenance.code_reference_id stays None)
        env = Env(cbm=FakeCBMAdapter(
            [node("add", "src.calc.add", "src/calc.py", start=1, end=3)]
        ))
        self.addCleanup(env.cleanup)
        ref = CodeReference(
            project_id=env.project_id,
            reference_kind="symbol",
            file_path="src/calc.py",
            symbol_name="add",
            qualified_name="src.calc.add",
        )
        saved = env.save(memory_type="decision", title="Add stays pure",
                         body="d", code_refs=[ref.to_dict()])
        packet = env.builder().build(env.request(symbol="src.calc.add"))
        focus_id = packet.code_references[0].provenance.code_reference_id
        self.assertEqual(focus_id, ref.code_reference_id)
        linked = [i for i in packet.memories
                  if i.provenance.memory_id == saved.memory_id]
        self.assertEqual(len(linked), 1)
        self.assertIsNone(linked[0].provenance.code_reference_id)
        ranked = score(packet, focus_code_reference_id=focus_id)  # CLI path
        entry = only_score(ranked, "memories", saved.memory_id)
        self.assertEqual(sig(entry, "direct_code_link"), 40)

    def test_symbol_match_qualified_and_plain(self):
        packet = make_packet(
            facts=[fact_item("ref_x", name="src.calc.add")]
        )
        ranked = score(packet, focus_symbol="src.calc.add")
        self.assertEqual(
            sig(only_score(ranked, "code_facts", "ref_x"), "symbol_match"),
            35,
        )
        ranked_plain = score(packet, focus_symbol="fn")
        self.assertEqual(
            sig(
                only_score(ranked_plain, "code_facts", "ref_x"),
                "symbol_match",
            ),
            35,
        )
        ranked_off = score(packet, focus_symbol="other.symbol")
        self.assertEqual(
            sig(
                only_score(ranked_off, "code_facts", "ref_x"), "symbol_match"
            ),
            0,
        )

    def test_file_match(self):
        packet = make_packet(facts=[fact_item("ref_x", path="src/calc.py")])
        ranked = score(packet, focus_file="src/calc.py")
        self.assertEqual(
            sig(only_score(ranked, "code_facts", "ref_x"), "file_match"), 25
        )
        ranked_off = score(packet, focus_file="src/other.py")
        self.assertEqual(
            sig(only_score(ranked_off, "code_facts", "ref_x"), "file_match"),
            0,
        )

    def test_memory_type_points(self):
        expected = {
            "constraint": 20, "decision": 18, "bug": 15, "handoff": 15,
            "pending": 14, "architecture": 12, "discovery": 6,
            "verification": 4, "task_result": 2,
        }
        for mtype, points in expected.items():
            packet = make_packet(memories=[mem("mem_t", mtype)])
            ranked = score(packet)
            self.assertEqual(
                sig(only_score(ranked, "memories", "mem_t"), "memory_type"),
                points,
                mtype,
            )

    def test_unknown_memory_type_zero(self):
        packet = make_packet(memories=[mem("mem_u", "whatever")])
        ranked = score(packet)
        self.assertEqual(
            sig(only_score(ranked, "memories", "mem_u"), "memory_type"), 0
        )

    def test_keyword_title_overlap(self):
        packet = make_packet(
            memories=[mem("mem_k", "discovery", title="Fix parser bug")]
        )
        ranked = score(packet, task="fix parser")
        self.assertEqual(
            sig(
                only_score(ranked, "memories", "mem_k"),
                "task_keyword_overlap",
            ),
            12,  # fix + parser, 6 each
        )

    def test_keyword_title_cap(self):
        packet = make_packet(
            memories=[
                mem("mem_k", "discovery", title="alpha bravo charlie delta")
            ]
        )
        ranked = score(packet, task="alpha bravo charlie delta")
        self.assertEqual(
            sig(
                only_score(ranked, "memories", "mem_k"),
                "task_keyword_overlap",
            ),
            18,  # 4 * 6 = 24 capped at 18
        )

    def test_keyword_code_tokens_and_cap(self):
        packet = make_packet(
            facts=[fact_item("ref_x", path="src/invoice/generate.py")]
        )
        ranked = score(packet, task="invoice generate")
        self.assertEqual(
            sig(
                only_score(ranked, "code_facts", "ref_x"),
                "task_keyword_overlap",
            ),
            10,  # invoice + generate, 5 each
        )
        packet2 = make_packet(
            facts=[fact_item("ref_y", name="src.invoice.generate.main")]
        )
        ranked2 = score(packet2, task="src invoice generate main")
        # code tokens: src/invoice/generate/main from qualified_name plus
        # src/mod/py from the default file path: 6+ distinct hits, capped
        self.assertEqual(
            sig(
                only_score(ranked2, "code_facts", "ref_y"),
                "task_keyword_overlap",
            ),
            15,
        )

    def test_keyword_body_cap_and_no_spam(self):
        packet = make_packet(
            memories=[
                mem(
                    "mem_k", "discovery", title="plain",
                    body="alpha bravo charlie delta echo foxtrot",
                )
            ]
        )
        ranked = score(packet, task="alpha bravo charlie delta echo foxtrot")
        self.assertEqual(
            sig(
                only_score(ranked, "memories", "mem_k"),
                "task_keyword_overlap",
            ),
            10,  # 6 * 2 = 12 capped at 10
        )
        spam = make_packet(
            memories=[mem("mem_s", "discovery", title="plain",
                          body="bug bug bug bug bug")]
        )
        ranked_spam = score(spam, task="bug")
        self.assertEqual(
            sig(
                only_score(ranked_spam, "memories", "mem_s"),
                "task_keyword_overlap",
            ),
            2,  # set-based: repetition never inflates
        )

    def test_keyword_title_and_body_buckets_both_count(self):
        packet = make_packet(
            memories=[mem("mem_k", "discovery", title="parser",
                          body="parser again")]
        )
        ranked = score(packet, task="parser")
        self.assertEqual(
            sig(
                only_score(ranked, "memories", "mem_k"),
                "task_keyword_overlap",
            ),
            8,  # 6 (title bucket) + 2 (body bucket)
        )

    def test_recency_buckets(self):
        cases = [
            ("2026-01-31T12:00:00+00:00", 8),   # 0.5 day
            ("2026-01-31T00:00:00+00:00", 8),   # exactly 1 day
            ("2026-01-28T00:00:00+00:00", 6),   # 4 days
            ("2026-01-25T00:00:00+00:00", 6),   # exactly 7 days
            ("2026-01-10T00:00:00+00:00", 4),   # 22 days
            ("2025-12-01T00:00:00+00:00", 2),   # 62 days
            ("2025-01-01T00:00:00+00:00", 0),   # older than 90 days
        ]
        for ts, points in cases:
            packet = make_packet(memories=[mem("mem_r", "discovery", ts=ts)])
            ranked = score(packet)
            self.assertEqual(
                sig(only_score(ranked, "memories", "mem_r"), "recency"),
                points,
                ts,
            )

    def test_recency_missing_or_unparseable_is_zero(self):
        for ts in (None, "not-a-date"):
            packet = make_packet(memories=[mem("mem_r", "discovery", ts=ts)])
            ranked = score(packet)
            self.assertEqual(
                sig(only_score(ranked, "memories", "mem_r"), "recency"), 0
            )

    def test_recency_boundaries_and_future(self):
        cases = [
            ("2026-01-02T00:00:00+00:00", 4),   # exactly 30 days
            ("2025-11-03T00:00:00+00:00", 2),   # exactly 90 days
            ("2025-11-02T23:59:59+00:00", 0),   # just past 90 days
            ("2026-02-02T00:00:00+00:00", 8),   # future: freshest bucket
        ]
        for ts, points in cases:
            packet = make_packet(memories=[mem("mem_b", "discovery", ts=ts)])
            ranked = score(packet)
            self.assertEqual(
                sig(only_score(ranked, "memories", "mem_b"), "recency"),
                points,
                ts,
            )

    def test_workspace_match(self):
        packet = make_packet(
            memories=[mem("mem_w", "discovery", scope=f"ws/{WS_A}")]
        )
        ranked = score(packet, workspace_id=WS_A)
        self.assertEqual(
            sig(only_score(ranked, "memories", "mem_w"), "workspace_match"),
            5,
        )
        other = score(packet, workspace_id="ws_" + "b" * 32)
        self.assertEqual(
            sig(only_score(other, "memories", "mem_w"), "workspace_match"),
            0,
        )
        none_ws = score(packet)
        self.assertEqual(
            sig(only_score(none_ws, "memories", "mem_w"), "workspace_match"),
            0,
        )

    def test_resolution_points_on_code_candidates(self):
        cases = [("resolved", 4), ("stale", -8), ("ambiguous", -6),
                 ("missing", -10), (None, 0)]
        for state, points in cases:
            item = fact_item("ref_x")
            if state is None:
                item.data.pop("resolution_state", None)
                item.provenance.resolution_state = None
            else:
                item.data["resolution_state"] = state
            packet = make_packet(facts=[item])
            ranked = score(packet)
            self.assertEqual(
                sig(only_score(ranked, "code_facts", "ref_x"), "resolution"),
                points,
                state,
            )

    def test_memories_never_get_resolution_penalty(self):
        packet = make_packet(
            memories=[mem("mem_h", "bug", link="ref_gone",
                          ts="2026-01-31T12:00:00+00:00")],
            facts=[fact_item("ref_gone")],
        )
        packet.code_facts[0].data["resolution_state"] = "missing"
        ranked = score(packet, task="title", focus_code_reference_id="ref_gone")
        memory_score = only_score(ranked, "memories", "mem_h")
        self.assertEqual(sig(memory_score, "resolution"), 0)
        self.assertEqual(sig(memory_score, "direct_code_link"), 40)
        self.assertEqual(sig(memory_score, "memory_type"), 15)
        self.assertEqual(sig(memory_score, "recency"), 8)
        fact_score = only_score(ranked, "code_facts", "ref_gone")
        self.assertEqual(sig(fact_score, "resolution"), -10)


class ExplainabilityTests(unittest.TestCase):
    def test_signals_sum_to_total_everywhere(self):
        packet = rich_packet()
        ranked = score(packet, task="budget fixture",
                       focus_code_reference_id="ref_focus")
        for section, scores in ranked.scores.items():
            for entry in scores:
                self.assertEqual(
                    sum(points for _, points in entry.signals),
                    entry.total,
                    f"{section}/{entry.source_id}",
                )

    def test_signal_order_is_fixed(self):
        packet = rich_packet()
        ranked = score(packet)
        for scores in ranked.scores.values():
            for entry in scores:
                self.assertEqual(
                    tuple(name for name, _ in entry.signals), SIGNAL_ORDER
                )

    def test_zero_point_signals_omitted_by_default(self):
        packet = make_packet(memories=[mem("mem_z", "discovery")])
        ranked = score(packet)
        entry = only_score(ranked, "memories", "mem_z")
        rendered = entry.to_dict()
        self.assertEqual(
            [s["name"] for s in rendered["signals"]], ["memory_type"]
        )
        full = entry.to_dict(include_zero=True)
        self.assertEqual(len(full["signals"]), len(SIGNAL_ORDER))

    def test_total_may_go_negative(self):
        item = fact_item("ref_x")
        item.data["resolution_state"] = "stale"
        packet = make_packet(facts=[item])
        ranked = score(packet)  # no focus, no task: only the penalty
        entry = only_score(ranked, "code_facts", "ref_x")
        self.assertEqual(entry.total, -8)


class FairnessTests(unittest.TestCase):
    def test_equal_quality_agents_score_equal_both_directions(self):
        def build(first_agent, second_agent):
            return make_packet(memories=[
                mem("mem_a1", "discovery", title="shared note",
                    body="same body", agent=first_agent),
                mem("mem_b2", "discovery", title="shared note",
                    body="same body", agent=second_agent),
            ])

        for first, second in (("opencode", "codex"), ("codex", "opencode")):
            ranked = score(build(first, second))
            a = only_score(ranked, "memories", "mem_a1")
            b = only_score(ranked, "memories", "mem_b2")
            self.assertEqual(a.total, b.total)
            self.assertEqual(a.signals, b.signals)
        # the tie is broken by source_id, never by agent identity
        ordered = [s.source_id for s in ranked.scores["memories"]]
        self.assertEqual(ordered, ["mem_a1", "mem_b2"])

    def test_relevance_difference_decides_not_agent(self):
        def build(kw_agent, plain_agent):
            return make_packet(memories=[
                mem("mem_kw", "discovery", title="parser fix",
                    agent=kw_agent),
                mem("mem_plain", "discovery", title="unrelated stuff",
                    agent=plain_agent),
            ])

        for kw_agent, plain_agent in (("codex", "opencode"),
                                      ("opencode", "codex")):
            ranked = score(build(kw_agent, plain_agent), task="parser")
            best = ranked.scores["memories"][0]
            self.assertEqual(best.source_id, "mem_kw", kw_agent)
            self.assertGreater(
                only_score(ranked, "memories", "mem_kw").total,
                only_score(ranked, "memories", "mem_plain").total,
            )


class PortabilityTests(unittest.TestCase):
    def test_same_semantic_reference_scores_identical_across_workspaces(self):
        def build_ref(workspace_id, slug):
            return CodeReference(
                project_id=PID,
                workspace_id=workspace_id,
                reference_kind="symbol",
                file_path="src/calc.py",
                symbol_name="add",
                qualified_name="src.calc.add",
                cbm_project_name=slug,
            )

        ref_a = build_ref("ws_" + "1" * 32, "slug-a")
        ref_b = build_ref("ws_" + "2" * 32, "slug-b")
        self.assertEqual(ref_a.code_reference_id, ref_b.code_reference_id)

        def item_for(ref):
            return PacketItem(
                data={
                    "reference": ref.to_dict(),
                    "resolution_state": "resolved",
                    "note": None,
                },
                provenance=Provenance(
                    source="cbm",
                    why_included="portability fixture",
                    code_reference_id=ref.code_reference_id,
                ),
            )

        totals = []
        for ref in (ref_a, ref_b):
            packet = make_packet(refs=[item_for(ref)])
            ranked = score(packet, focus_symbol="src.calc.add")
            totals.append(
                only_score(
                    ranked, "code_references", ref.code_reference_id
                ).total
            )
        self.assertEqual(totals[0], totals[1])
        self.assertEqual(totals[0], 35 + 4)  # symbol_match + resolved

    def test_workspace_fixture_packets_score_equal(self):
        # the same semantic candidate built under two workspaces keeps an
        # identical explanation (ids and points, never workspace metadata)
        explanations = []
        for slug_ws in (("slug-one", "ws_" + "1" * 32),
                        ("slug-two", "ws_" + "2" * 32)):
            slug, ws = slug_ws
            ref = CodeReference(
                project_id=PID, workspace_id=ws, reference_kind="file",
                file_path="src/calc.py", cbm_project_name=slug,
            )
            packet = make_packet(refs=[PacketItem(
                data={"reference": ref.to_dict(),
                      "resolution_state": "resolved", "note": None},
                provenance=Provenance(
                    source="cbm", why_included="fixture",
                    code_reference_id=ref.code_reference_id),
            )])
            ranked = score(packet, focus_file="src/calc.py")
            entry = only_score(
                ranked, "code_references", ref.code_reference_id
            )
            explanations.append(entry.to_dict())
        self.assertEqual(explanations[0], explanations[1])


class TieBreakTests(unittest.TestCase):
    def test_total_descending(self):
        packet = make_packet(memories=[
            mem("mem_old", "discovery", ts="2025-01-01T00:00:00+00:00"),
            mem("mem_new", "discovery", ts="2026-01-31T12:00:00+00:00"),
        ])
        ranked = score(packet)
        self.assertEqual(
            [s.source_id for s in ranked.scores["memories"]],
            ["mem_new", "mem_old"],
        )

    def test_type_rank_breaks_equal_totals(self):
        # constraint 20 == bug 15 + workspace 5; constraint wins the tie
        packet = make_packet(memories=[
            mem("mem_bug", "bug", scope=f"ws/{WS_A}"),
            mem("mem_con", "constraint"),
        ])
        ranked = score(packet, workspace_id=WS_A)
        self.assertEqual(
            only_score(ranked, "memories", "mem_bug").total, 20
        )
        self.assertEqual(
            only_score(ranked, "memories", "mem_con").total, 20
        )
        self.assertEqual(
            [s.source_id for s in ranked.scores["memories"]],
            ["mem_con", "mem_bug"],
        )

    def test_timestamp_desc_missing_last(self):
        weights = RelevanceWeights(
            recency_day=0, recency_week=0, recency_month=0, recency_quarter=0
        )
        packet = make_packet(memories=[
            mem("mem_none", "discovery"),
            mem("mem_old", "discovery", ts="2026-01-15T00:00:00+00:00"),
            mem("mem_new", "discovery", ts="2026-01-31T00:00:00+00:00"),
        ])
        ranked = score(packet, weights=weights)
        totals = {s.source_id: s.total for s in ranked.scores["memories"]}
        self.assertEqual(len(set(totals.values())), 1)  # perfect tie
        self.assertEqual(
            [s.source_id for s in ranked.scores["memories"]],
            ["mem_new", "mem_old", "mem_none"],
        )

    def test_timestamp_tie_break_is_chronological_across_offsets(self):
        # '2026-01-15T10:00:00-05:00' is 15:00Z, NEWER than 12:00Z even
        # though it sorts earlier lexicographically
        weights = RelevanceWeights(
            recency_day=0, recency_week=0, recency_month=0, recency_quarter=0
        )
        packet = make_packet(memories=[
            mem("mem_utc", "discovery", ts="2026-01-15T12:00:00+00:00"),
            mem("mem_off", "discovery", ts="2026-01-15T10:00:00-05:00"),
        ])
        ranked = score(packet, weights=weights)
        self.assertEqual(
            [s.source_id for s in ranked.scores["memories"]],
            ["mem_off", "mem_utc"],
        )

    def test_z_suffix_timestamps_parse(self):
        weights = RelevanceWeights(
            recency_day=0, recency_week=0, recency_month=0, recency_quarter=0
        )
        packet = make_packet(memories=[
            mem("mem_none", "discovery"),
            mem("mem_old", "discovery", ts="2026-01-15T00:00:00+00:00"),
            mem("mem_zed", "discovery", ts="2026-01-31T00:00:00Z"),
        ])
        ranked = score(packet, weights=weights)
        self.assertEqual(
            [s.source_id for s in ranked.scores["memories"]],
            ["mem_zed", "mem_old", "mem_none"],
        )
        # 'Z' also earns recency points (it parses, not missing)
        fresh = make_packet(memories=[
            mem("mem_zr", "discovery", ts="2026-01-31T12:00:00Z")
        ])
        self.assertEqual(
            sig(only_score(score(fresh), "memories", "mem_zr"), "recency"), 8
        )

    def test_unparseable_timestamp_sorts_last(self):
        weights = RelevanceWeights(
            recency_day=0, recency_week=0, recency_month=0, recency_quarter=0
        )
        packet = make_packet(memories=[
            mem("mem_bad", "discovery", ts="not-a-date"),
            mem("mem_valid", "discovery", ts="2026-01-15T00:00:00+00:00"),
        ])
        ranked = score(packet, weights=weights)
        self.assertEqual(
            [s.source_id for s in ranked.scores["memories"]],
            ["mem_valid", "mem_bad"],
        )

    def test_source_id_breaks_full_ties(self):
        weights = RelevanceWeights(
            recency_day=0, recency_week=0, recency_month=0, recency_quarter=0
        )
        packet = make_packet(memories=[
            mem("mem_zzz", "discovery", title="same", body="same"),
            mem("mem_aaa", "discovery", title="same", body="same"),
        ])
        ranked = score(packet, weights=weights)
        self.assertEqual(
            [s.source_id for s in ranked.scores["memories"]],
            ["mem_aaa", "mem_zzz"],
        )


class TasklessTests(unittest.TestCase):
    def test_task_none_zeroes_only_the_keyword_signal(self):
        packet = make_packet(memories=[
            mem("mem_a", "constraint", title="fix parser"),
            mem("mem_b", "discovery", title="fix parser"),
        ])
        ranked = score(packet)  # task=None
        for sid in ("mem_a", "mem_b"):
            entry = only_score(ranked, "memories", sid)
            self.assertEqual(sig(entry, "task_keyword_overlap"), 0)
        # everything else still differentiates: never all-equal
        self.assertGreater(
            only_score(ranked, "memories", "mem_a").total,
            only_score(ranked, "memories", "mem_b").total,
        )

    def test_as_of_is_required(self):
        packet = make_packet(memories=[mem("mem_a", "discovery")])
        with self.assertRaises(TypeError):
            score_packet(packet)  # missing required as_of
        with self.assertRaises(RelevanceValidationError):
            score_packet(packet, as_of=None)
        with self.assertRaises(RelevanceValidationError):
            score_packet(packet, as_of="not-a-date")


class HistoricalMemoryTests(unittest.TestCase):
    def test_memory_linked_to_missing_code_keeps_value(self):
        packet = make_packet(
            memories=[mem(
                "mem_hist", "decision",
                title="parser design", link="ref_gone",
                ts="2026-01-31T12:00:00+00:00",
            )],
            refs=[ref_item("ref_gone")],
        )
        packet.code_references[0].data["resolution_state"] = "missing"
        ranked = score(packet, focus_code_reference_id="ref_gone")
        entry = only_score(ranked, "memories", "mem_hist")
        self.assertEqual(sig(entry, "resolution"), 0)  # no penalty
        self.assertEqual(entry.total, 40 + 18 + 8)  # link + type + recency

    def test_stale_code_fact_penalized_but_linked_memory_not(self):
        fact = fact_item("ref_x")
        fact.data["resolution_state"] = "stale"
        packet = make_packet(
            memories=[mem("mem_h", "bug", link="ref_x")],
            facts=[fact],
        )
        ranked = score(packet, focus_code_reference_id="ref_x")
        self.assertEqual(
            only_score(ranked, "code_facts", "ref_x").total, -8
        )
        self.assertEqual(
            only_score(ranked, "memories", "mem_h").total, 40 + 15
        )


class BudgetIntegrationTests(unittest.TestCase):
    def test_relevance_none_is_byte_identical_to_r1f(self):
        packet = rich_packet()
        budget = resolve_budget(profile="small")
        plain = apply_budget(packet, budget)
        explicit_none = apply_budget(packet, budget, relevance=None)
        self.assertEqual(plain.packet.to_json(),
                         explicit_none.packet.to_json())
        self.assertEqual([d.to_dict() for d in plain.decisions],
                         [d.to_dict() for d in explicit_none.decisions])
        self.assertEqual(plain.report_id, explicit_none.report_id)
        self.assertIsNone(plain.to_dict()["relevance_version"])
        # fixed from-end R1F semantics still hold: last optional memory
        by_id = decisions_by_id(plain)
        self.assertEqual(by_id["mem_res"].action, "omitted")
        self.assertEqual(by_id["mem_dec"].action, "included")

    def test_mismatched_ranking_rejected(self):
        packet = rich_packet()
        other = make_packet()
        other.packet_id = "pkt_" + "0" * 32
        ranked = score(other)
        with self.assertRaises(BudgetValidationError):
            apply_budget(packet, resolve_budget(profile="small"),
                         relevance=ranked)

    def test_same_packet_id_different_contents_rejected(self):
        # packet ids are content-insensitive: same id, different scored
        # sections must still be rejected via the packet fingerprint
        packet_a = make_packet(memories=[mem("mem_a", "discovery")])
        packet_b = make_packet(memories=[mem("mem_b", "constraint")])
        self.assertEqual(packet_a.packet_id, packet_b.packet_id)
        ranked = score(packet_a)
        with self.assertRaises(BudgetValidationError):
            apply_budget(packet_b, resolve_budget(profile="small"),
                         relevance=ranked)
        # control: the ranking DOES apply to the packet it was built from
        ok = apply_budget(packet_a, resolve_budget(profile="small"),
                          relevance=ranked)
        self.assertEqual(ok.to_dict()["relevance_version"],
                         RELEVANCE_VERSION)

    def test_ladder_removes_low_score_first_within_class(self):
        packet = make_packet(memories=[
            mem("mem_low", "discovery", body="x" * 1500),
            mem("mem_high", "discovery", body="y" * 1500, link="ref_focus",
                ts="2026-01-31T12:00:00+00:00"),
        ])
        max_tokens = budget_with_over(packet, over=20)
        budget = ContextBudget(max_estimated_tokens=max_tokens)
        fixed = apply_budget(packet, budget)
        self.assertEqual(decisions_by_id(fixed)["mem_high"].action, "omitted")
        self.assertEqual(decisions_by_id(fixed)["mem_low"].action, "included")
        ranked = score(packet, focus_code_reference_id="ref_focus")
        guided = apply_budget(packet, budget, relevance=ranked)
        self.assertEqual(decisions_by_id(guided)["mem_low"].action, "omitted")
        self.assertEqual(
            decisions_by_id(guided)["mem_high"].action, "included"
        )
        self.assertEqual(guided.to_dict()["relevance_version"],
                         RELEVANCE_VERSION)

    def test_occurrence_keying_aligns_with_audit_under_ranking(self):
        packet = make_packet(memories=[
            mem("mem_dup", "discovery", body="z" * 1500, title="plain"),
            mem("mem_dup", "discovery", body="alpha " + "a" * 1494,
                title="alpha focus"),
        ])
        max_tokens = budget_with_over(packet, over=20)
        budget = ContextBudget(max_estimated_tokens=max_tokens)
        ranked = score(packet, task="alpha")
        result = apply_budget(packet, budget, relevance=ranked)
        self.assertTrue(result.satisfied)
        dups = [d for d in result.decisions
                if d.source_id == "mem_dup" and d.section == "memories"]
        self.assertEqual(len(dups), 2)
        # occurrence 0 (low relevance) omitted, occurrence 1 kept
        self.assertEqual(dups[0].action, "omitted")
        self.assertEqual(dups[1].action, "included")
        survivors = [m for m in result.packet.memories
                     if m.provenance.memory_id == "mem_dup"]
        self.assertEqual(len(survivors), 1)
        self.assertIn("alpha", survivors[0].data["body"])

    def test_class_order_beats_score_and_essential_is_untouchable(self):
        # a HIGH-score optional discovery is omitted before a LOW-score
        # important decision; warnings and identity survive byte-identical
        packet = make_packet(
            memories=[
                mem("mem_dec", "decision", body="d" * 900),
                mem("mem_hot", "discovery", body="x" * 1500,
                    link="ref_focus", ts="2026-01-31T12:00:00+00:00",
                    scope=f"ws/{WS_A}"),
            ],
            warnings=[PacketWarning("stale_code_reference", "drifted")],
        )
        ranked = score(packet, focus_code_reference_id="ref_focus",
                       workspace_id=WS_A)
        hot = only_score(ranked, "memories", "mem_hot")
        dec = only_score(ranked, "memories", "mem_dec")
        self.assertGreater(hot.total, dec.total)
        max_tokens = budget_with_over(packet, over=20)
        result = apply_budget(
            packet, ContextBudget(max_estimated_tokens=max_tokens),
            relevance=ranked,
        )
        self.assertTrue(result.satisfied)
        by_id = decisions_by_id(result)
        self.assertEqual(by_id["mem_hot"].action, "omitted")
        self.assertEqual(by_id["mem_dec"].action, "included")
        self.assertEqual(
            [w.to_dict() for w in result.packet.warnings],
            [w.to_dict() for w in packet.warnings],
        )
        self.assertEqual(result.packet.packet_id, packet.packet_id)
        self.assertEqual(result.packet.project_id, packet.project_id)

    def test_hard_guarantee_holds_with_relevance(self):
        packet = rich_packet()
        ranked = score(packet, focus_code_reference_id="ref_focus")
        budgets = [
            resolve_budget(profile="large"),
            resolve_budget(profile="medium"),
            resolve_budget(profile="small"),
            ContextBudget(max_estimated_tokens=budget_with_over(packet, 0)),
            ContextBudget(max_estimated_tokens=10),
        ]
        results = [apply_budget(packet, b, relevance=ranked)
                   for b in budgets]
        for budget, result in zip(budgets, results):
            if result.status == "OK":
                payload = result.packet.to_json()
                from relinkra.context_budget import estimate_tokens
                self.assertLessEqual(
                    estimate_tokens(payload, budget.chars_per_token),
                    budget.max_estimated_tokens,
                )
        self.assertEqual(results[-1].status, "BUDGET_UNSATISFIABLE")
        self.assertIsNone(results[-1].packet)
        self.assertTrue(results[-1].decisions)  # audit retained

    def test_policy_isolation_other_workspace_never_scored(self):
        env = Env(seed=False)
        self.addCleanup(env.cleanup)
        local = env.save(memory_type="discovery", title="Local ws note",
                         body="x", scope="workspace_local",
                         workspace_id=env.workspace_id)
        other = env.save(memory_type="discovery", title="Other ws note",
                         body="y", scope="workspace_local",
                         workspace_id=WID_UNKNOWN)
        packet = env.builder().build(
            env.request(workspace_id=env.workspace_id)
        )
        ranked = score(packet, workspace_id=env.workspace_id)
        report = ranked.to_json()
        self.assertIn(local.memory_id, report)
        self.assertNotIn(other.memory_id, report)
        entry = only_score(ranked, "memories", local.memory_id)
        self.assertEqual(sig(entry, "workspace_match"), 5)
        result = apply_budget(packet, resolve_budget(profile="small"),
                              relevance=ranked)
        self.assertNotIn(other.memory_id, result.to_json())

    def test_relevance_with_room_to_spare_includes_everything(self):
        packet = rich_packet()
        ranked = score(packet)
        result = apply_budget(
            packet, ContextBudget(max_estimated_tokens=10 ** 9),
            relevance=ranked,
        )
        self.assertTrue(result.satisfied)
        self.assertTrue(all(d.action == "included" for d in result.decisions))
        self.assertEqual(result.to_dict()["relevance_version"],
                         RELEVANCE_VERSION)


class FixedVsRankedTests(unittest.TestCase):
    """Phase 17 fixture: an OLD discovery directly linked to the focused
    symbol vs a NEWER unrelated discovery; the budget forces one out."""

    def fixture(self):
        packet = make_packet(
            memories=[
                mem("mem_newer", "discovery", body="n" * 1500,
                    ts="2026-01-31T12:00:00+00:00"),
                mem("mem_linked", "discovery", body="o" * 1500,
                    ts="2025-01-01T00:00:00+00:00", link="ref_focus"),
            ],
            refs=[ref_item("ref_focus")],
        )
        max_tokens = budget_with_over(packet, over=20)
        return packet, ContextBudget(max_estimated_tokens=max_tokens)

    def test_fixed_order_keeps_the_positioned_one(self):
        packet, budget = self.fixture()
        result = apply_budget(packet, budget)  # plain R1F: from the END
        by_id = decisions_by_id(result)
        self.assertEqual(by_id["mem_linked"].action, "omitted")
        self.assertEqual(by_id["mem_newer"].action, "included")

    def test_ranked_order_keeps_the_linked_one(self):
        packet, budget = self.fixture()
        ranked = score(packet, focus_code_reference_id="ref_focus")
        linked = only_score(ranked, "memories", "mem_linked")
        newer = only_score(ranked, "memories", "mem_newer")
        self.assertEqual(linked.total, 40 + 6)   # direct link + type
        self.assertEqual(newer.total, 6 + 8)     # type + recency
        result = apply_budget(packet, budget, relevance=ranked)
        by_id = decisions_by_id(result)
        self.assertEqual(by_id["mem_linked"].action, "included")
        self.assertEqual(by_id["mem_newer"].action, "omitted")
        survivors = [m.provenance.memory_id for m in result.packet.memories]
        self.assertEqual(survivors, ["mem_linked"])


class DeterminismTests(unittest.TestCase):
    def test_score_packet_byte_identical_x3(self):
        packet = rich_packet()
        outputs = {
            score(packet, task="budget fixture",
                  focus_code_reference_id="ref_focus").to_json()
            for _ in range(3)
        }
        self.assertEqual(len(outputs), 1)

    def test_guided_budget_byte_identical(self):
        packet = rich_packet()
        budget = resolve_budget(profile="small")
        ranked = score(packet, focus_code_reference_id="ref_focus")
        first = apply_budget(packet, budget, relevance=ranked)
        second = apply_budget(packet, budget,
                              relevance=score(
                                  packet,
                                  focus_code_reference_id="ref_focus"))
        self.assertEqual(first.to_json(), second.to_json())
        self.assertEqual(first.report_id, second.report_id)


class CLITests(unittest.TestCase):
    def setUp(self):
        class FatEnv(Env):
            def seed_memories(self):
                self.save(memory_type="decision", title="Decision fat",
                          body="d" * 900)
                self.save(memory_type="constraint", title="Constraint fat",
                          body="c" * 900)
                self.save(memory_type="discovery", title="Discovery one",
                          body="x" * 1500)
                self.save(memory_type="discovery", title="Discovery two",
                          body="y" * 1500)
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

    def test_no_flags_byte_identical_regression(self):
        packet = self.env.builder().build(self.env.request())
        code, out, err = self.run_cli(self.base_argv())
        self.assertEqual(code, 0, err)
        self.assertEqual(out, packet.to_json() + "\n")
        self.assertEqual(err, "")

    def test_relevance_only_annotates_diagnostics(self):
        code, out, err = self.run_cli(self.base_argv("--relevance"))
        self.assertEqual(code, 0, err)
        self.assertEqual(err, "")
        packet = json.loads(out)
        relevance = packet["diagnostics"]["relevance"]
        self.assertTrue(relevance["ranked"])
        self.assertEqual(relevance["relevance_version"], RELEVANCE_VERSION)
        self.assertEqual(relevance["as_of"], FIXED_NOW)
        self.assertGreater(relevance["counts"]["memories"], 0)

    def test_relevance_report_goes_to_stderr(self):
        code, out, err = self.run_cli(
            self.base_argv("--relevance", "--relevance-report")
        )
        self.assertEqual(code, 0, err)
        report = json.loads(err)
        self.assertEqual(report["relevance_version"], RELEVANCE_VERSION)
        self.assertTrue(report["scores"]["memories"])
        packet = json.loads(out)  # stdout stays the packet
        self.assertIn("relevance", packet["diagnostics"])

    def test_relevance_with_budget_and_both_reports(self):
        code, out, err = self.run_cli(
            self.base_argv("--relevance", "--budget", "small",
                           "--budget-report", "--relevance-report")
        )
        self.assertEqual(code, 0, err)
        combined = json.loads(err)  # ONE document carrying both reports
        self.assertIn("budget_report", combined)
        self.assertIn("relevance_report", combined)
        self.assertEqual(combined["budget_report"]["relevance_version"],
                         RELEVANCE_VERSION)
        packet = json.loads(out)
        self.assertTrue(packet["diagnostics"]["budget"]["budgeted"])

    def test_relevance_report_requires_relevance(self):
        code, out, err = self.run_cli(self.base_argv("--relevance-report"))
        self.assertEqual(code, 1)
        self.assertIn("error", json.loads(err))

    def test_unsatisfiable_embeds_relevance_report(self):
        code, out, err = self.run_cli(
            self.base_argv("--relevance", "--relevance-report",
                           "--max-tokens", "1")
        )
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        error = json.loads(err)
        self.assertEqual(error["error"], "budget_unsatisfiable")
        self.assertEqual(error["relevance_report"]["relevance_version"],
                         RELEVANCE_VERSION)


class SecurityTests(unittest.TestCase):
    def test_score_report_has_ids_and_points_not_bodies(self):
        packet = make_packet(memories=[
            mem("mem_sec", "discovery", title="TITLEMARKER",
                body="BODYMARKER " + "x" * 100),
        ])
        report = score(packet, task="bodymarker").to_json()
        self.assertNotIn("BODYMARKER", report)
        self.assertNotIn("TITLEMARKER", report)
        self.assertIn("mem_sec", report)
        self.assertIn('"total"', report)

    def test_no_absolute_paths_in_score_report(self):
        env = Env(cbm=FakeCBMAdapter(
            [node("add", "src.calc.add", "src/calc.py", start=1, end=40)]
        ))
        self.addCleanup(env.cleanup)
        packet = env.builder().build(env.request(symbol="src.calc.add"))
        report = score(packet, focus_symbol="src.calc.add").to_json()
        self.assertNotIn(env.ws_dir, report)

    def test_redacted_content_never_echoed_in_score_report(self):
        env = Env(seed=False)
        self.addCleanup(env.cleanup)
        secret = "ghp_abcdefghij1234567890"
        saved = env.save(memory_type="decision", title="Leaked token",
                         body=f"deploy token {secret} end")
        packet = env.builder().build(env.request())
        report = score(packet).to_json()
        self.assertNotIn(secret, report)
        self.assertIn(saved.memory_id, report)


if __name__ == "__main__":
    unittest.main()
