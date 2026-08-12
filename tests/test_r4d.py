"""Discriminating R4D freshness, contradiction and explainability tests."""

from __future__ import annotations

import json
import unittest
from dataclasses import dataclass

from relinkra.context_packet import strip_portable_cbm_labels
from relinkra.context_packet import ContextPacket, PacketItem, Provenance
from relinkra.contradictions import (
    ContradictionType,
    EvidenceFact,
    detect_contradictions,
)
from relinkra.explainability import (
    annotate_packet,
    attach_budget,
    attach_relevance,
    explanation_document,
    human_summary,
)
from relinkra.freshness import (
    FreshnessContext,
    FreshnessState,
    RevisionRelation,
    RevisionRelationState,
    evaluate_freshness,
)
from relinkra.git_intelligence import (
    GitCapabilities,
    GitHeadFacts,
    GitIntelligenceService,
    GitRepositoryState,
    GitWorkingTree,
)
from relinkra.linkage import _portable_cbm_authority

try:
    from tests.test_context_packet import Env, FakeCBMAdapter, SLUG, node
except ImportError:  # pragma: no cover - discover vs module invocation
    from test_context_packet import Env, FakeCBMAdapter, SLUG, node


NOW = "2026-08-11T12:00:00+00:00"
CURRENT = "b" * 40
OLD = "a" * 40
FUTURE = "c" * 40
PROJECT = "rlk_" + "1" * 32


def context(**kwargs):
    values = {
        "as_of": NOW,
        "project_id": PROJECT,
        "current_revision": CURRENT,
        "dirty": False,
    }
    values.update(kwargs)
    return FreshnessContext(**values)


def relation(state, distance=None, **kwargs):
    return lambda _old, _current: RevisionRelation(
        state, distance=distance, **kwargs
    )


class AttestedCBMAdapter(FakeCBMAdapter):
    """CBM fake whose authority payload crosses the real linkage boundary."""

    def __init__(self, authority):
        super().__init__([node("fn", "src.mod.fn", "src/mod.py")])
        self.authority = authority

    def code_evidence_authority(self):
        return self.authority


class CurrentGitService:
    """Small builder-boundary fake; CBM integration remains otherwise real."""

    def collect_capabilities(self, _root):
        return GitCapabilities(True, "2.55.0", True, False, True, None), []

    def collect_repository_state(self, _root, capabilities=None):
        del capabilities
        return (
            GitRepositoryState(
                head_sha=CURRENT,
                short_head_sha=CURRENT[:7],
                branch="main",
                detached=False,
                clean=True,
                staged_count=0,
                unstaged_count=0,
                untracked_count=0,
                conflicted_count=0,
            ),
            [],
        )

    def collect_head_facts(self, _root, state=None):
        del state
        return (
            GitHeadFacts(
                head_sha=CURRENT,
                short_head_sha=CURRENT[:7],
                branch="main",
                detached=False,
                committed_at=NOW,
                author_name="Ada",
                subject="current",
                parents=(),
            ),
            [],
        )

    def collect_working_tree(self, _root):
        return GitWorkingTree(True, (), (), (), (), (), ()), []

    def collect_recent_commits(self, _root, limit=10):
        del limit
        return [], []

    def collect_current_change_state(self, _root, _file_path):
        return None, []

    def collect_file_history(self, _root, _file_path, limit=None):
        del limit
        return [], []

    def collect_diff(self, _root, include_snippets=False):
        del include_snippets
        return [], []

    def collect_cochange(self, _root, _anchor_path):
        return [], []


class BuilderCBMAuthorityIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.env = None

    def tearDown(self):
        if self.env is not None:
            self.env.cleanup()

    @staticmethod
    def _git():
        return CurrentGitService()

    def _build(self, authority):
        adapter = AttestedCBMAdapter(authority)
        self.env = Env(cbm=adapter, seed=False)
        return self.env.builder(git_service=self._git()).build(
            self.env.request(
                workspace_id=self.env.workspace_id,
                symbol="fn",
                include_git=True,
                include_explain=True,
            )
        )

    @staticmethod
    def _authority(revision, *, status="PASS", **extra):
        authority = {
            "index_status": {"git": {"head_sha": revision}},
            "trust_stages": [{"name": "CBM graph", "status": status}],
        }
        authority.update(extra)
        return authority

    def test_current_native_graph_reaches_reference_and_fact_freshness(self):
        packet = self._build(self._authority(CURRENT))
        for item in packet.code_references + packet.code_facts:
            self.assertEqual(item.data["index_status"]["git"]["head_sha"], CURRENT)
            self.assertEqual(
                item.data["trust_stages"],
                [{"name": "CBM graph", "status": "PASS"}],
            )
            self.assertEqual(item.explain["freshness"]["state"], "fresh")
            self.assertEqual(item.explain["freshness"]["reason_code"], "same_revision")

    def test_stale_native_graph_reaches_reference_and_fact_freshness(self):
        packet = self._build(self._authority(OLD))
        for item in packet.code_references + packet.code_facts:
            self.assertEqual(item.explain["freshness"]["state"], "stale")
            self.assertEqual(
                item.explain["freshness"]["reason_code"],
                "cbm_graph_revision_mismatch",
            )

    def test_revision_without_native_trust_attestation_remains_unknown(self):
        packet = self._build(
            {"index_status": {"git": {"head_sha": CURRENT}}}
        )
        for item in packet.code_references + packet.code_facts:
            self.assertEqual(item.explain["freshness"]["state"], "unknown")
            self.assertEqual(
                item.explain["freshness"]["reason_code"],
                "cbm_graph_trust_unverified",
            )

    def test_conflicting_duplicate_cbm_graph_stages_never_project_as_pass(self):
        # Mutation guard: restoring first-PASS projection would make this
        # current graph incorrectly fresh.
        projected = _portable_cbm_authority(
            self._authority(
                CURRENT,
                trust_stages=[
                    {"name": "CBM graph", "status": "PASS"},
                    {"name": "CBM graph", "status": "WARN"},
                ],
            )
        )
        self.assertEqual(
            projected["trust_stages"],
            [{"name": "CBM graph", "status": "WARN"}],
        )
        result = evaluate_freshness("cbm", projected, context())
        self.assertIs(result.state, FreshnessState.UNKNOWN)
        self.assertNotEqual(result.state, FreshnessState.FRESH)
        direct = evaluate_freshness(
            "cbm",
            self._authority(
                CURRENT,
                trust_stages=[
                    {"name": "CBM graph", "status": "PASS"},
                    {"name": "CBM graph", "status": "WARN"},
                ],
            ),
            context(),
        )
        self.assertIs(direct.state, FreshnessState.UNKNOWN)
        self.assertNotEqual(direct.state, FreshnessState.FRESH)

    def test_authority_projection_keeps_private_cbm_state_out_of_portable_output(self):
        private_root = "C:/Users/private/work/repo"
        secret = "token-super-secret"
        host = "private-host.internal"
        packet = self._build(
            self._authority(
                CURRENT,
                index_status={
                    "root_path": private_root,
                    "git": {"head_sha": CURRENT},
                    "credentials": {"token": secret},
                },
                trust_stages=[
                    {
                        "name": "CBM graph",
                        "status": "PASS",
                        "detail": f"{host} {private_root} {secret}",
                    }
                ],
                cbm_project_name=SLUG,
                host_config={"host": host},
            )
        )
        portable = strip_portable_cbm_labels(packet.to_portable_dict())
        rendered = json.dumps(portable, sort_keys=True)
        for private in (private_root, secret, host, SLUG):
            self.assertNotIn(private, rendered)
        for item in packet.code_references + packet.code_facts:
            self.assertEqual(
                set(item.data).intersection(
                    {"root_path", "credentials", "cbm_project_name", "host_config"}
                ),
                set(),
            )


class FreshnessPolicyTests(unittest.TestCase):
    def test_current_code_revision_is_fresh(self):
        result = evaluate_freshness(
            "code", {"source_revision": CURRENT}, context()
        )
        self.assertEqual(result.state, FreshnessState.FRESH)
        self.assertEqual(result.reason_code, "same_revision")
        self.assertEqual(result.revision_distance, 0)

    def test_case_normalized_abbreviated_revision_is_fresh(self):
        result = evaluate_freshness(
            "code", {"source_revision": CURRENT[:12].upper()}, context()
        )
        self.assertEqual(result.state, FreshnessState.FRESH)
        self.assertEqual(result.reason_code, "same_revision")
        self.assertEqual(result.source_revision, CURRENT[:12])

    def test_resolver_confirmed_same_revision_is_fresh(self):
        result = evaluate_freshness(
            "code",
            {"source_revision": OLD},
            context(),
            relation_resolver=relation(RevisionRelationState.SAME, 0),
        )
        self.assertEqual(result.state, FreshnessState.FRESH)
        self.assertEqual(result.reason_code, "same_revision")
        self.assertEqual(result.relation, "same")

    def test_one_revision_old_code_is_aging(self):
        result = evaluate_freshness(
            "code",
            {"source_revision": OLD},
            context(),
            relation_resolver=relation(RevisionRelationState.ANCESTOR, 1),
        )
        self.assertEqual(result.state, FreshnessState.AGING)
        self.assertEqual(result.reason_code, "revision_behind")

    def test_many_revision_old_code_is_stale(self):
        result = evaluate_freshness(
            "code",
            {"source_revision": OLD},
            context(),
            relation_resolver=relation(RevisionRelationState.ANCESTOR, 9),
        )
        self.assertEqual(result.state, FreshnessState.STALE)
        self.assertEqual(result.revision_distance, 9)

    def test_unknown_revision_never_becomes_fresh(self):
        result = evaluate_freshness("code", {}, context())
        self.assertEqual(result.state, FreshnessState.UNKNOWN)
        self.assertEqual(result.reason_code, "source_revision_missing")

    def test_unknown_evidence_kind_never_inherits_memory_freshness(self):
        result = evaluate_freshness(
            "future_backend", {"timestamp": NOW}, context()
        )
        # Mutation guard: changing the unsupported-kind result to FRESH must fail.
        self.assertIs(result.state, FreshnessState.UNKNOWN)
        self.assertNotEqual(result.state, FreshnessState.FRESH)
        self.assertEqual(result.reason_code, "unsupported_evidence_type")

    def test_dirty_tree_degrades_same_revision_code(self):
        result = evaluate_freshness(
            "code", {"source_revision": CURRENT}, context(dirty=True)
        )
        self.assertEqual(result.state, FreshnessState.AGING)
        self.assertIn("uncommitted", " ".join(result.trust_limitations))

    def test_no_git_is_unknown_for_code(self):
        result = evaluate_freshness(
            "code", {"source_revision": OLD}, context(current_revision=None)
        )
        self.assertEqual(result.state, FreshnessState.UNKNOWN)
        self.assertEqual(result.reason_code, "current_revision_unavailable")

    def test_shallow_git_fails_honestly(self):
        result = evaluate_freshness(
            "code",
            {"source_revision": OLD},
            context(),
            relation_resolver=relation(
                RevisionRelationState.UNAVAILABLE,
                shallow=True,
                reason="shallow",
            ),
        )
        self.assertEqual(result.state, FreshnessState.UNKNOWN)
        self.assertIn("shallow", result.trust_limitations[0])

    def test_revision_resolver_exception_is_sanitized_unknown(self):
        def broken_resolver(_old, _current):
            raise RuntimeError("secret=C:/Users/alice/private-token")

        result = evaluate_freshness(
            "code",
            {"source_revision": OLD},
            context(),
            relation_resolver=broken_resolver,
        )
        rendered = json.dumps(result.to_dict(), sort_keys=True)
        self.assertIs(result.state, FreshnessState.UNKNOWN)
        self.assertEqual(result.reason_code, "revision_relation_unknown")
        self.assertNotIn("private-token", rendered)
        self.assertNotIn("C:/Users", rendered)

    def test_invalid_revision_metadata_is_not_projected(self):
        result = evaluate_freshness(
            "code", {"source_revision": r"C:\\private\\repository"}, context()
        )
        rendered = json.dumps(result.to_dict(), sort_keys=True)
        self.assertEqual(result.state, FreshnessState.UNKNOWN)
        self.assertEqual(result.reason_code, "source_revision_invalid")
        self.assertIsNone(result.source_revision)
        self.assertNotIn("C:\\private\\repository", rendered)

    def test_malformed_explicit_revision_is_unknown_for_all_revision_policies(self):
        # Mutation guard: normalizing malformed metadata to None would let
        # timestamp/current-revision fallback report FRESH.
        cases = {
            "memory": {"source_revision": "not-a-sha", "timestamp": NOW},
            "handoff": {"source_revision": "not-a-sha", "timestamp": NOW},
            "code": {"source_revision": "not-a-sha", "timestamp": NOW},
            "cbm": {
                "source_revision": "not-a-sha",
                "index_status": {"git": {"head_sha": CURRENT}},
                "trust_stages": [{"name": "CBM graph", "status": "PASS"}],
                "timestamp": NOW,
            },
            "git": {"head_sha": "not-a-sha", "timestamp": NOW},
            "connector": self.connector_evidence(
                record={"revision": "not-a-sha", "timestamp": NOW}
            ),
        }
        for evidence_type, evidence in cases.items():
            with self.subTest(evidence_type=evidence_type):
                result = evaluate_freshness(evidence_type, evidence, context())
                self.assertIs(result.state, FreshnessState.UNKNOWN)
                self.assertEqual(result.reason_code, "source_revision_invalid")
                self.assertNotEqual(result.state, FreshnessState.FRESH)

    def test_malformed_cbm_graph_revision_is_unknown_without_fallback(self):
        result = evaluate_freshness(
            "cbm",
            {
                "index_status": {"git": {"head_sha": "not-a-sha"}},
                "trust_stages": [{"name": "CBM graph", "status": "PASS"}],
            },
            context(),
        )
        self.assertIs(result.state, FreshnessState.UNKNOWN)
        self.assertEqual(result.reason_code, "cbm_graph_revision_invalid")

    def test_future_timestamp_is_unknown_even_when_revision_matches(self):
        # Mutation guard: bypassing the future-clock guard would make
        # revision-bound evidence incorrectly fresh.
        future = "2026-08-11T12:00:00.500000+00:00"
        cases = {
            "memory": {"timestamp": future},
            "handoff": {"timestamp": future, "source_revision": CURRENT},
            "code": {"timestamp": future, "source_revision": CURRENT},
            "git": {"timestamp": future, "head_sha": CURRENT},
            "cbm": {
                "timestamp": future,
                "index_status": {"git": {"head_sha": CURRENT}},
                "trust_stages": [{"name": "CBM graph", "status": "PASS"}],
            },
            "connector": self.connector_evidence(
                record={"timestamp": future, "revision": CURRENT}
            ),
        }
        for evidence_type, evidence in cases.items():
            with self.subTest(evidence_type=evidence_type):
                result = evaluate_freshness(evidence_type, evidence, context())
                self.assertIs(result.state, FreshnessState.UNKNOWN)
                self.assertEqual(result.reason_code, "timestamp_from_future")
                self.assertNotEqual(result.state, FreshnessState.FRESH)

    def test_non_cbm_current_revision_freshness_remains_unchanged(self):
        result = evaluate_freshness(
            "code", {"source_revision": CURRENT, "timestamp": NOW}, context()
        )
        self.assertIs(result.state, FreshnessState.FRESH)
        self.assertEqual(result.reason_code, "same_revision")

    def test_detached_head_does_not_invalidate_exact_revision(self):
        # Freshness binds to the commit, not a branch label.
        result = evaluate_freshness(
            "git", {"head_sha": CURRENT, "detached": True}, context()
        )
        self.assertEqual(result.state, FreshnessState.FRESH)

    def test_old_memory_without_revision_is_aging_not_stale(self):
        result = evaluate_freshness(
            "memory", {"timestamp": "2020-01-01T00:00:00+00:00"}, context()
        )
        self.assertEqual(result.state, FreshnessState.AGING)
        self.assertEqual(result.reason_code, "old_without_revision")

    def test_old_memory_with_current_revision_is_fresh(self):
        result = evaluate_freshness(
            "memory",
            {
                "timestamp": "2020-01-01T00:00:00+00:00",
                "commit_sha": CURRENT,
            },
            context(),
        )
        # Revision-bound memory uses code policy even when wall-clock old.
        self.assertEqual(result.state, FreshnessState.FRESH)

    def test_recent_memory_with_stale_revision_is_stale(self):
        result = evaluate_freshness(
            "memory",
            {"timestamp": NOW, "commit_sha": OLD},
            context(),
            relation_resolver=relation(RevisionRelationState.ANCESTOR, 5),
        )
        self.assertEqual(result.state, FreshnessState.STALE)

    def test_current_and_stale_handoff(self):
        current_result = evaluate_freshness(
            "handoff", {"source_revision": CURRENT}, context()
        )
        stale_result = evaluate_freshness(
            "handoff",
            {"source_revision": OLD},
            context(),
            relation_resolver=relation(RevisionRelationState.ANCESTOR, 2),
        )
        self.assertEqual(current_result.state, FreshnessState.FRESH)
        self.assertEqual(stale_result.state, FreshnessState.STALE)
        self.assertTrue(stale_result.recommended_action)

    @staticmethod
    def connector_evidence(**overrides):
        record = {
            "timestamp": "2026-08-11T11:59:30+00:00",
            "ttl_seconds": 60,
            "host": "codex",
            "registration_fingerprint": "1" * 64,
            "revision": CURRENT[:12],
            "stages": {"handshake_succeeded": True},
        }
        record.update(overrides.pop("record", {}))
        evidence = {
            "status": "valid",
            "record": record,
            "connector_id": "codex",
            "current_registration_fingerprint": "1" * 64,
            "stage": "handshake_succeeded",
        }
        evidence.update(overrides)
        return evidence

    def test_connector_adapts_existing_verification_authority(self):
        fresh = evaluate_freshness(
            "connector",
            self.connector_evidence(),
            context(),
        )
        expired_evidence = self.connector_evidence(
            status="expired",
            record={"timestamp": "2026-08-11T11:59:30+00:00"},
        )
        expired = evaluate_freshness("connector", expired_evidence, context())
        self.assertEqual(fresh.state, FreshnessState.FRESH)
        self.assertEqual(fresh.reason_code, "verification_authority_valid")
        self.assertEqual(expired.state, FreshnessState.STALE)

    def test_connector_valid_ttl_cannot_override_fingerprint_or_revision(self):
        fingerprint_mismatch = evaluate_freshness(
            "connector",
            self.connector_evidence(current_registration_fingerprint="2" * 64),
            context(),
        )
        revision_mismatch = evaluate_freshness(
            "connector",
            self.connector_evidence(record={"revision": OLD[:12]}),
            context(),
        )
        self.assertIs(fingerprint_mismatch.state, FreshnessState.STALE)
        self.assertEqual(
            fingerprint_mismatch.reason_code, "verification_stale_fingerprint"
        )
        self.assertIs(revision_mismatch.state, FreshnessState.STALE)
        self.assertEqual(
            revision_mismatch.reason_code, "verification_revision_mismatch"
        )

    def test_connector_ttl_alone_and_unproven_stage_are_not_fresh(self):
        ttl_only = evaluate_freshness(
            "connector",
            {"timestamp": "2026-08-11T11:59:30+00:00", "ttl_seconds": 60},
            context(),
        )
        unproven = evaluate_freshness(
            "connector",
            self.connector_evidence(
                record={"stages": {"handshake_succeeded": False}}
            ),
            context(),
        )
        self.assertIs(ttl_only.state, FreshnessState.UNKNOWN)
        self.assertIs(unproven.state, FreshnessState.UNKNOWN)
        self.assertNotEqual(ttl_only.state, FreshnessState.FRESH)

    def test_cbm_native_graph_revision_mismatch_overrides_copied_revision(self):
        result = evaluate_freshness(
            "cbm",
            {
                "source_revision": CURRENT,
                "index_status": {"git": {"head_sha": OLD}},
                "trust_stages": [
                    {
                        "name": "CBM graph",
                        "status": "WARN",
                        "detail": "stale index",
                    }
                ],
            },
            context(),
        )
        self.assertIs(result.state, FreshnessState.STALE)
        self.assertEqual(result.reason_code, "cbm_graph_revision_mismatch")
        self.assertEqual(result.source_revision, OLD)

    def test_cbm_native_unverified_graph_never_falls_back_to_fresh(self):
        result = evaluate_freshness(
            "cbm",
            {
                "source_revision": CURRENT,
                "trust_stages": [
                    {"name": "CBM graph", "status": "WARN", "detail": "unknown"}
                ],
            },
            context(),
        )
        self.assertIs(result.state, FreshnessState.UNKNOWN)
        self.assertNotEqual(result.state, FreshnessState.FRESH)

    def test_cbm_valid_current_trust_stage_is_fresh(self):
        result = evaluate_freshness(
            "cbm",
            {
                "source_revision": CURRENT,
                "index_status": {"git": {"head_sha": CURRENT}},
                "trust_stages": [{"name": "CBM graph", "status": "PASS"}],
            },
            context(),
        )
        self.assertIs(result.state, FreshnessState.FRESH)
        self.assertEqual(result.reason_code, "same_revision")

    def test_cbm_missing_trust_stages_never_falls_back_to_fresh(self):
        # Mutation guard: removing the required trust-stage check makes this
        # current graph SHA incorrectly return FRESH.
        result = evaluate_freshness(
            "cbm",
            {
                "source_revision": CURRENT,
                "index_status": {"git": {"head_sha": CURRENT}},
            },
            context(),
        )
        self.assertIs(result.state, FreshnessState.UNKNOWN)
        self.assertEqual(result.reason_code, "cbm_graph_trust_missing")
        self.assertNotEqual(result.state, FreshnessState.FRESH)

    def test_cbm_empty_trust_stages_never_falls_back_to_fresh(self):
        result = evaluate_freshness(
            "cbm",
            {
                "source_revision": CURRENT,
                "index_status": {"git": {"head_sha": CURRENT}},
                "trust_stages": [],
            },
            context(),
        )
        self.assertIs(result.state, FreshnessState.UNKNOWN)
        self.assertEqual(result.reason_code, "cbm_graph_trust_missing")
        self.assertNotEqual(result.state, FreshnessState.FRESH)

    def test_cbm_malformed_or_incomplete_trust_stages_fail_honest(self):
        cases = {
            "malformed": {"trust_stages": {"name": "CBM graph", "status": "PASS"}},
            "incomplete": {"trust_stages": [{"name": "CBM graph"}]},
        }
        for label, extra in cases.items():
            with self.subTest(label=label):
                evidence = {
                    "source_revision": CURRENT,
                    "index_status": {"git": {"head_sha": CURRENT}},
                    **extra,
                }
                result = evaluate_freshness("cbm", evidence, context())
                self.assertIs(result.state, FreshnessState.UNKNOWN)
                self.assertNotEqual(result.state, FreshnessState.FRESH)

    def test_non_cbm_same_revision_freshness_is_unaffected_by_cbm_guard(self):
        result = evaluate_freshness(
            "code", {"source_revision": CURRENT}, context()
        )
        self.assertIs(result.state, FreshnessState.FRESH)
        self.assertEqual(result.reason_code, "same_revision")

    def test_cbm_pass_without_native_graph_revision_never_borrows_source_revision(self):
        result = evaluate_freshness(
            "cbm",
            {
                "source_revision": CURRENT,
                "trust_stages": [{"name": "CBM graph", "status": "PASS"}],
            },
            context(),
        )
        self.assertIs(result.state, FreshnessState.UNKNOWN)
        self.assertEqual(result.reason_code, "cbm_graph_revision_missing")
        self.assertIsNone(result.source_revision)

    def test_static_and_registry_are_not_applicable(self):
        for evidence_type in ("static", "registry", "project_identity"):
            with self.subTest(evidence_type=evidence_type):
                result = evaluate_freshness(evidence_type, {}, context())
                self.assertEqual(result.state, FreshnessState.NOT_APPLICABLE)

    def test_project_identity_conflict_is_stale(self):
        result = evaluate_freshness(
            "memory", {"project_id": "rlk_" + "2" * 32}, context()
        )
        self.assertEqual(result.state, FreshnessState.STALE)
        self.assertEqual(result.reason_code, "project_identity_mismatch")

    def test_project_identity_conflict_precedes_static_not_applicable(self):
        result = evaluate_freshness(
            "registry", {"project_id": "rlk_" + "2" * 32}, context()
        )
        self.assertIs(result.state, FreshnessState.STALE)
        self.assertEqual(result.reason_code, "project_identity_mismatch")

    def test_unrelated_and_future_revisions_are_unknown(self):
        unrelated = evaluate_freshness(
            "code", {"source_revision": OLD}, context(),
            relation_resolver=relation(RevisionRelationState.UNRELATED),
        )
        future = evaluate_freshness(
            "code", {"source_revision": FUTURE}, context(),
            relation_resolver=relation(RevisionRelationState.DESCENDANT, 2),
        )
        self.assertEqual(unrelated.state, FreshnessState.UNKNOWN)
        self.assertEqual(future.state, FreshnessState.UNKNOWN)


class FakeRevisionRunner:
    def __init__(self, *, shallow=False, ancestor=True):
        self.shallow = shallow
        self.ancestor = ancestor
        self.calls = []

    def run(self, _cwd, verb, *args, **_kwargs):
        self.calls.append((verb,) + args)
        if verb == "rev-parse" and args == ("--is-bare-repository",):
            return "false\n"
        if verb == "rev-parse" and args == ("--is-shallow-repository",):
            return "true\n" if self.shallow else "false\n"
        if verb == "rev-parse" and args[:1] == ("--verify",):
            return args[1].split("^", 1)[0] + "\n"
        if verb == "log":
            revision_range = args[-1]
            if self.ancestor and revision_range == f"{OLD}..{CURRENT}":
                return CURRENT + "\n"
            return ""
        raise AssertionError((verb, args))


class GitRevisionRelationTests(unittest.TestCase):
    def test_exact_revision_uses_no_history_scan(self):
        runner = FakeRevisionRunner()
        service = GitIntelligenceService(runner=runner)
        result = service.collect_revision_relation(".", CURRENT, CURRENT)
        self.assertEqual(result.state, RevisionRelationState.SAME)
        self.assertFalse(any(call[0] == "log" for call in runner.calls))

    def test_bounded_ancestry_distance(self):
        runner = FakeRevisionRunner()
        result = GitIntelligenceService(runner=runner).collect_revision_relation(
            ".", OLD, CURRENT
        )
        self.assertEqual(result.state, RevisionRelationState.ANCESTOR)
        self.assertEqual(result.distance, 1)
        log_call = next(call for call in runner.calls if call[0] == "log")
        self.assertIn("--max-count=101", log_call)
        self.assertIn("--ancestry-path", log_call)

    def test_shallow_unresolved_relation_is_unavailable(self):
        runner = FakeRevisionRunner(shallow=True, ancestor=False)
        result = GitIntelligenceService(runner=runner).collect_revision_relation(
            ".", OLD, CURRENT
        )
        self.assertEqual(result.state, RevisionRelationState.UNAVAILABLE)
        self.assertTrue(result.shallow)


def fact(
    evidence_id,
    value,
    *,
    domain="memory",
    source="engram",
    subject="entity",
    key="setting",
    observed_at=None,
    revision=None,
):
    return EvidenceFact(
        evidence_id=evidence_id,
        authority_domain=domain,
        source_system=source,
        subject=subject,
        key=key,
        value=value,
        observed_at=observed_at,
        revision=revision if revision is not None else value if key == "revision" else None,
    )


class ContradictionTests(unittest.TestCase):
    def test_same_key_same_value_and_duplicates_do_not_conflict(self):
        facts = [fact("a", 1), fact("b", 1), fact("a", 1)]
        self.assertEqual(detect_contradictions(facts), [])

    def test_same_source_key_different_value(self):
        result = detect_contradictions([fact("a", 1), fact("b", 2)])
        self.assertEqual(result[0].type, ContradictionType.SAME_KEY_DIFFERENT_VALUE)

    def test_different_sources_same_domain_disagree(self):
        result = detect_contradictions(
            [fact("a", 1), fact("b", 2, source="relinkra")]
        )
        self.assertEqual(result[0].type, ContradictionType.SOURCE_DISAGREEMENT)

    def test_newer_status_supersedes_old_without_deleting_it(self):
        result = detect_contradictions(
            [
                fact("old", "open", key="status", observed_at="2026-01-01T00:00:00Z"),
                fact("new", "closed", key="status", observed_at="2026-02-01T00:00:00Z"),
            ]
        )
        self.assertEqual(result[0].type, ContradictionType.TEMPORAL_SUPERSESSION)
        self.assertEqual(result[0].evidence_refs, ("old", "new"))
        self.assertEqual(result[0].newer_evidence_ref, "new")
        self.assertEqual(result[0].newer_value, "closed")
        rendered = result[0].to_dict()
        self.assertEqual(rendered["newer_evidence_ref"], "new")
        self.assertEqual(rendered["newer_value"], "closed")

    def test_equivalent_offset_instants_are_not_temporal_supersession(self):
        result = detect_contradictions(
            [
                fact("utc", "open", key="status", observed_at="2026-01-01T00:00:00Z"),
                fact(
                    "offset",
                    "closed",
                    key="status",
                    observed_at="2025-12-31T19:00:00-05:00",
                ),
            ]
        )

        self.assertEqual(result[0].type, ContradictionType.STATUS_CONFLICT)
        self.assertEqual(result[0].observed_at, ("2026-01-01T00:00:00Z",))

    def test_malformed_status_timestamp_is_non_temporal_but_retained(self):
        result = detect_contradictions(
            [
                fact("a", "open", key="status", observed_at="not-a-timestamp"),
                fact("b", "closed", key="status", observed_at="2026-01-01T00:00:00Z"),
            ]
        )
        contradiction = result[0]
        self.assertEqual(contradiction.type, ContradictionType.STATUS_CONFLICT)
        self.assertNotEqual(
            contradiction.type, ContradictionType.TEMPORAL_SUPERSESSION
        )
        self.assertIn("not-a-timestamp", contradiction.observed_at)
        self.assertEqual(contradiction.evidence_refs, ("a", "b"))

    def test_temporal_supersession_uses_chronology_not_lexical_order(self):
        result = detect_contradictions(
            [
                fact(
                    "lexically-later",
                    "open",
                    key="status",
                    observed_at="2026-01-01T00:30:00+01:00",
                ),
                fact(
                    "chronologically-later",
                    "closed",
                    key="status",
                    observed_at="2025-12-31T23:45:00Z",
                ),
            ]
        )

        contradiction = result[0]
        self.assertEqual(
            contradiction.evidence_refs,
            ("lexically-later", "chronologically-later"),
        )
        self.assertEqual(contradiction.newer_evidence_ref, "chronologically-later")
        self.assertEqual(contradiction.newer_value, "closed")
        self.assertEqual(
            contradiction.observed_at,
            ("2025-12-31T23:30:00Z", "2025-12-31T23:45:00Z"),
        )

    def test_equal_time_status_is_conflict_not_supersession(self):
        result = detect_contradictions(
            [fact("a", "open", key="status"), fact("b", "closed", key="status")]
        )
        self.assertEqual(result[0].type, ContradictionType.STATUS_CONFLICT)

    def test_different_authority_domains_are_not_flattened(self):
        result = detect_contradictions(
            [fact("a", 1, domain="memory"), fact("b", 2, domain="code")]
        )
        self.assertEqual(result, [])

    def test_identity_conflict_crosses_domains(self):
        result = detect_contradictions(
            [
                fact("a", PROJECT, key="project_id", domain="registry"),
                fact("b", "rlk_" + "2" * 32, key="project_id", domain="memory"),
            ]
        )
        self.assertEqual(result[0].type, ContradictionType.IDENTITY_CONFLICT)

    def test_workspace_null_vs_missing_has_no_false_contradiction(self):
        # Missing fields are not emitted as EvidenceFact at all.
        result = detect_contradictions(
            [fact("explicit-null", None, key="workspace_id", domain="handoff")]
        )
        self.assertEqual(result, [])

    def test_revision_conflict_and_current_code_vs_memory(self):
        result = detect_contradictions(
            [
                fact("git", CURRENT, key="revision", domain="git", source="git"),
                fact("memory", OLD, key="revision", domain="memory"),
            ]
        )
        self.assertEqual(result[0].type, ContradictionType.REVISION_MISMATCH)

    def test_equivalent_abbreviated_revisions_do_not_contradict(self):
        result = detect_contradictions(
            [
                fact("git", CURRENT, key="revision", domain="git", source="git"),
                fact(
                    "memory",
                    CURRENT[:12].upper(),
                    key="revision",
                    domain="memory",
                ),
            ]
        )
        self.assertEqual(result, [])

    def test_three_way_disagreement_is_one_grouped_contradiction(self):
        result = detect_contradictions(
            [fact("a", 1), fact("b", 2), fact("c", 3)]
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].values, (1, 2, 3))

    def test_order_and_ids_are_deterministic(self):
        facts = [
            fact("z", 2, subject="b"),
            fact("y", 1, subject="b"),
            fact("b", "off", key="status", subject="a"),
            fact("a", "on", key="status", subject="a"),
        ]
        forward = [item.to_dict() for item in detect_contradictions(facts)]
        reverse = [item.to_dict() for item in detect_contradictions(reversed(facts))]
        self.assertEqual(forward, reverse)
        self.assertEqual([x["subject"] for x in forward], ["a", "b"])

    def test_tied_fact_order_is_deterministic_across_time_and_revision(self):
        tied_cases = {
            "observed_at": [
                fact(
                    "same",
                    1,
                    observed_at="2026-01-02T00:00:00Z",
                    revision="revision",
                ),
                fact(
                    "same",
                    1,
                    observed_at="2026-01-01T00:00:00Z",
                    revision="revision",
                ),
            ],
            "revision": [
                fact(
                    "same",
                    1,
                    observed_at="2026-01-01T00:00:00Z",
                    revision="revision-b",
                ),
                fact(
                    "same",
                    1,
                    observed_at="2026-01-01T00:00:00Z",
                    revision="revision-a",
                ),
            ],
        }

        for tie_breaker, tied_facts in tied_cases.items():
            with self.subTest(tie_breaker=tie_breaker):
                facts = [*tied_facts, fact("other", 2)]
                forward = [item.to_dict() for item in detect_contradictions(facts)]
                reverse = [
                    item.to_dict() for item in detect_contradictions(reversed(facts))
                ]
                self.assertEqual(forward, reverse)


def item(source_id, *, section="memory", revision=None, timestamp=NOW):
    data = {
        "project_id": PROJECT,
        "timestamp": timestamp,
        "title": source_id,
        "memory_id": source_id,
        "memory_type": "decision",
    }
    if revision:
        data["commit_sha"] = revision
    if section == "code":
        data = {
            "code_reference_id": source_id,
            "source_revision": revision,
            "resolution_state": "resolved",
            "index_status": {"git": {"head_sha": revision}},
            "trust_stages": [{"name": "CBM graph", "status": "PASS"}],
        }
    return PacketItem(
        data=data,
        provenance=Provenance(
            source="cbm" if section == "code" else "engram",
            why_included="direct task match",
            memory_id=source_id if section == "memory" else None,
            code_reference_id=source_id if section == "code" else None,
        ),
    )


def packet_fixture():
    return ContextPacket(
        packet_id="pkt_" + "1" * 32,
        created_at=NOW,
        mode="task",
        project_id=PROJECT,
        packet_version="rlkctx2",
        memories=[item("mem_" + "1" * 16, revision=OLD)],
        code_facts=[item("ref_" + "2" * 32, section="code", revision=CURRENT)],
        git_facts=[
            PacketItem(
                data={
                    "kind": "repository_state",
                    "head_sha": CURRENT,
                    "clean": True,
                },
                provenance=Provenance(
                    source="git", why_included="current repository state"
                ),
            )
        ],
    )


@dataclass
class FakeScore:
    value: int

    def to_dict(self):
        return {"total": self.value, "signals": [{"name": "task", "points": self.value}]}


class FakeRanked:
    def score_for(self, section, source_id, occurrence):
        return FakeScore(7) if section == "memories" else None


@dataclass
class FakeDecision:
    section: str
    source_id: str
    action: str
    reason: str


class ExplainabilityIntegrationTests(unittest.TestCase):
    def annotated(self):
        return annotate_packet(
            packet_fixture(),
            as_of=NOW,
            relation_resolver=relation(RevisionRelationState.ANCESTOR, 3),
        )

    def test_why_relevance_freshness_provenance_and_trust_are_joined(self):
        packet = self.annotated()
        attach_relevance(packet, FakeRanked())
        explain = packet.memories[0].explain
        self.assertEqual(
            explain["selection"]["reason_ref"], "provenance.why_included"
        )
        self.assertEqual(
            packet.memories[0].provenance.why_included, "direct task match"
        )
        self.assertEqual(explain["selection"]["relevance"]["total"], 7)
        self.assertEqual(explain["freshness"]["state"], "stale")
        self.assertEqual(packet.memories[0].provenance.source, "engram")
        self.assertIn("evidence_ref", explain["provenance"])
        self.assertTrue(explain["trust"]["advisory_only"])

    def test_contradictions_are_single_copy_with_item_references(self):
        packet = self.annotated()
        self.assertEqual(len(packet.contradictions), 1)
        contradiction_id = packet.contradictions[0]["contradiction_id"]
        self.assertIn(contradiction_id, packet.memories[0].explain["contradictions"])
        self.assertNotIn("explanation", packet.memories[0].explain["contradictions"])

    def test_full_truncated_reference_only_and_omitted_budget_treatments(self):
        packet = self.annotated()
        sid = packet.memories[0].provenance.memory_id
        for action in ("included", "truncated", "reference_only"):
            with self.subTest(action=action):
                clone = ContextPacket.from_dict(packet.to_dict())
                attach_budget(
                    clone,
                    [FakeDecision("memories", sid, action, "bounded_test")],
                )
                self.assertEqual(
                    clone.memories[0].explain["budget"]["treatment"], action
                )
        attach_budget(
            packet,
            [FakeDecision("memories", sid, "omitted", "budget_pressure")],
        )
        self.assertEqual(
            packet.explainability["budget"]["omitted"][0]["treatment"],
            "omitted",
        )
        self.assertEqual(len(packet.contradictions), 1)

    def test_attach_budget_reaccounts_exact_final_cap_for_every_treatment(self):
        sid = packet_fixture().memories[0].provenance.memory_id

        def attached(action, max_characters):
            packet = self.annotated()
            packet.memories[0].data["body"] = "RAW-OMITTED-BODY-DO-NOT-RETAIN"
            if action == "omitted":
                # R1F removes the body before attach_budget; packet-level
                # notices and contradiction refs must still survive.
                packet.memories.clear()
            packet.diagnostics = {
                "budget": {
                    "max_estimated_tokens": 1_000_000,
                    "max_characters": max_characters,
                    "reserve_tokens": 0,
                    "chars_per_token": 3.0,
                    "final_total_chars": 0,
                    "final_estimated_tokens": 0,
                }
            }
            attach_budget(
                packet,
                [FakeDecision("memories", sid, action, "bounded_test")],
            )
            return packet

        for action in ("included", "truncated", "reference_only", "omitted"):
            with self.subTest(action=action):
                probe = attached(action, 1_000_000)
                # Force post-attach compaction rather than merely choosing a
                # comfortably large cap; the final bytes must still fit.
                exact_cap = len(probe.to_json()) - 32
                packet = attached(action, exact_cap)
                payload = packet.to_json()
                self.assertLessEqual(len(payload), exact_cap)
                self.assertEqual(
                    packet.diagnostics["budget"]["final_total_chars"],
                    len(payload),
                )
                self.assertTrue(
                    packet.explainability["budget"]["metadata_accounted"]
                )
                self.assertEqual(len(packet.contradictions), 1)
                notice = packet.explainability["notices"][0]
                self.assertEqual(
                    notice["evidence_ref"],
                    "memories:mem_1111111111111111:0",
                )
                self.assertTrue(notice["recommended_action"])
                if action == "omitted":
                    self.assertNotIn("RAW-OMITTED-BODY-DO-NOT-RETAIN", payload)
                    omitted = packet.explainability["budget"]["omitted"][0]
                    self.assertEqual(omitted["treatment"], "omitted")
                    self.assertIn("evidence_ref", omitted)
                else:
                    self.assertEqual(
                        packet.memories[0].explain["budget"]["treatment"],
                        action,
                    )

    def test_unmeasured_budget_metadata_never_claims_accounting(self):
        packet = self.annotated()
        sid = packet.memories[0].provenance.memory_id
        attach_budget(
            packet,
            [FakeDecision("memories", sid, "included", "bounded_test")],
        )
        self.assertFalse(
            packet.explainability["budget"]["metadata_accounted"]
        )

    def test_real_snippet_decision_overrides_whole_code_fact_inclusion(self):
        sid = packet_fixture().code_facts[0].provenance.code_reference_id
        for action in ("truncated", "reference_only"):
            with self.subTest(action=action):
                packet = self.annotated()
                attach_budget(
                    packet,
                    [
                        FakeDecision(
                            "code_facts", sid, "included", "within_budget"
                        ),
                        FakeDecision(
                            "code_facts",
                            f"snippet:{sid}",
                            action,
                            "snippet_budget_ladder",
                        ),
                    ],
                )
                self.assertEqual(
                    packet.code_facts[0].explain["budget"]["treatment"],
                    action,
                )

    def test_nested_handoff_identity_and_status_are_structured_facts(self):
        handoff_id = "hof_" + "7" * 32

        def handoff(memory_id, project_id, status):
            return PacketItem(
                data={
                    "memory_id": memory_id,
                    "memory_type": "handoff",
                    "timestamp": NOW,
                    "body": json.dumps(
                        {
                            "handoff_id": handoff_id,
                            "project_id": project_id,
                            "workspace_id": "ws_shared",
                            "status": status,
                        }
                    ),
                },
                provenance=Provenance(
                    source="engram",
                    why_included="active handoff",
                    memory_id=memory_id,
                ),
            )

        packet = ContextPacket(
            packet_id="pkt_" + "8" * 32,
            created_at=NOW,
            mode="project",
            project_id=PROJECT,
            handoffs=[
                handoff("mem_" + "8" * 16, PROJECT, "active"),
                handoff("mem_" + "9" * 16, "rlk_" + "2" * 32, "closed"),
            ],
        )
        annotate_packet(packet, as_of=NOW)
        by_type = {item["type"]: item for item in packet.contradictions}
        self.assertEqual(by_type["status_conflict"]["subject"], handoff_id)
        self.assertEqual(
            by_type["identity_conflict"]["subject"], "logical_project"
        )
        self.assertTrue(
            all(
                ref.startswith("handoffs:")
                for ref in by_type["status_conflict"]["evidence_refs"]
            )
        )

    def test_handoff_workspace_absence_null_and_validated_identity_conflicts(self):
        handoff_id = "hof_" + "6" * 32

        def handoff(memory_id, payload):
            return PacketItem(
                data={
                    "memory_id": memory_id,
                    "memory_type": "handoff",
                    "timestamp": NOW,
                    "body": json.dumps(
                        {"handoff_id": handoff_id, **payload},
                        sort_keys=True,
                    ),
                },
                provenance=Provenance(
                    source="engram",
                    why_included="targeted handoff fixture",
                    memory_id=memory_id,
                ),
            )

        missing_and_null = ContextPacket(
            packet_id="pkt_" + "6" * 32,
            created_at=NOW,
            mode="project",
            project_id=PROJECT,
            handoffs=[
                handoff("mem_" + "6" * 16, {"project_id": PROJECT}),
                handoff(
                    "mem_" + "7" * 16,
                    {"project_id": PROJECT, "workspace_id": None},
                ),
            ],
        )
        annotate_packet(missing_and_null, as_of=NOW)
        self.assertFalse(
            any(
                item["key"] in {"workspace_id", "project_id"}
                for item in missing_and_null.contradictions
            )
        )

        other_project = "rlk_" + "2" * 32
        first_workspace = "ws_" + "3" * 32
        second_workspace = "ws_" + "4" * 32
        conflicting = ContextPacket(
            packet_id="pkt_" + "7" * 32,
            created_at=NOW,
            mode="project",
            project_id=PROJECT,
            handoffs=[
                handoff(
                    "mem_" + "8" * 16,
                    {
                        "project_id": PROJECT,
                        "workspace_id": first_workspace,
                    },
                ),
                handoff(
                    "mem_" + "9" * 16,
                    {
                        "project_id": other_project,
                        "workspace_id": second_workspace,
                    },
                ),
            ],
        )
        annotate_packet(conflicting, as_of=NOW)
        identity_conflicts = {
            item["key"]: item
            for item in conflicting.contradictions
            if item["type"] == "identity_conflict"
        }
        self.assertEqual(
            set(identity_conflicts), {"project_id", "workspace_id"}
        )
        self.assertEqual(
            len(identity_conflicts["workspace_id"]["evidence_refs"]), 2
        )
        self.assertEqual(
            identity_conflicts["workspace_id"]["subject"], handoff_id
        )
        self.assertGreaterEqual(
            len(identity_conflicts["project_id"]["evidence_refs"]), 2
        )
        self.assertEqual(
            identity_conflicts["project_id"]["subject"], "logical_project"
        )

    def test_copied_cbm_revision_without_native_graph_is_not_projected(self):
        packet = ContextPacket(
            packet_id="pkt_" + "c" * 32,
            created_at=NOW,
            mode="project",
            project_id=PROJECT,
            code_facts=[
                PacketItem(
                    data={
                        "code_reference_id": "ref_" + "c" * 32,
                        "source_revision": CURRENT,
                        "trust_stages": [
                            {"name": "CBM graph", "status": "PASS"}
                        ],
                    },
                    provenance=Provenance(
                        source="cbm",
                        why_included="unattested native graph",
                        code_reference_id="ref_" + "c" * 32,
                    ),
                )
            ],
            git_facts=[
                PacketItem(
                    data={"kind": "repository_state", "head_sha": CURRENT},
                    provenance=Provenance(
                        source="git", why_included="current repository state"
                    ),
                )
            ],
        )
        annotate_packet(packet, as_of=NOW)
        freshness = packet.code_facts[0].explain["freshness"]
        self.assertEqual(freshness["state"], "unknown")
        self.assertEqual(freshness["reason_code"], "cbm_graph_revision_missing")
        self.assertNotIn("source_revision", freshness)
        self.assertFalse(
            any(
                item["type"] == "revision_mismatch"
                for item in packet.contradictions
            )
        )

    def test_native_cbm_revision_and_trust_remain_in_cbm_authority(self):
        def cbm_fact(ref_id, revision, trust_status):
            return PacketItem(
                data={
                    "code_reference_id": ref_id,
                    # A copied current revision must not override the native
                    # graph's own binding.
                    "source_revision": CURRENT,
                    "index_status": {"git": {"head_sha": revision}},
                    "trust_stages": [
                        {"name": "CBM graph", "status": trust_status}
                    ],
                },
                provenance=Provenance(
                    source="cbm",
                    why_included="native graph evidence",
                    code_reference_id=ref_id,
                ),
            )

        packet = ContextPacket(
            packet_id="pkt_" + "a" * 32,
            created_at=NOW,
            mode="project",
            project_id=PROJECT,
            code_facts=[
                cbm_fact("ref_" + "a" * 32, OLD, "WARN"),
                cbm_fact("ref_" + "b" * 32, CURRENT, "PASS"),
            ],
            git_facts=[
                PacketItem(
                    data={"kind": "repository_state", "head_sha": CURRENT},
                    provenance=Provenance(
                        source="git", why_included="current repository state"
                    ),
                )
            ],
        )
        annotate_packet(packet, as_of=NOW)
        subjects = {item["subject"]: item for item in packet.contradictions}
        self.assertIn("repository", subjects)
        self.assertEqual(subjects["repository"]["type"], "revision_mismatch")
        self.assertIn("cbm_trust:cbm graph", subjects)
        self.assertEqual(
            subjects["cbm_trust:cbm graph"]["source_systems"], ["cbm"]
        )
        self.assertTrue(
            all(
                ref.startswith("code_facts:")
                for ref in subjects["cbm_trust:cbm graph"]["evidence_refs"]
            )
        )

    def test_compact_explain_document_omits_raw_memory_body(self):
        packet = self.annotated()
        packet.memories[0].data["body"] = "private raw body"
        document = explanation_document(packet)
        encoded = json.dumps(document, sort_keys=True)
        self.assertNotIn("private raw body", encoded)
        self.assertIn("selection", encoded)

    def test_json_is_stable_across_repeated_runs(self):
        first = explanation_document(self.annotated())
        second = explanation_document(self.annotated())
        self.assertEqual(
            json.dumps(first, sort_keys=True, separators=(",", ":")),
            json.dumps(second, sort_keys=True, separators=(",", ":")),
        )

    def test_human_output_answers_selection_staleness_conflicts_and_verification(self):
        packet = self.annotated()
        text = human_summary(packet)
        self.assertIn("Why selected", text)
        self.assertIn("stale=1", text)
        self.assertIn("contradictions: 1", text)
        self.assertIn("memories:mem_1111111111111111:0 is stale", text)
        self.assertIn("repository.revision conflicts across sources", text)
        self.assertIn("engram", text)
        self.assertIn("git", text)
        self.assertIn("Recommended action:", text)
        self.assertIn("What to verify", text)
        markdown = packet.to_markdown()
        self.assertIn("memories:mem_1111111111111111:0 is stale", markdown)
        self.assertIn("repository.revision conflicts across sources", markdown)
        self.assertNotIn("] None", markdown)

    def test_legacy_packet_round_trip_without_sidecars_is_unchanged(self):
        packet = ContextPacket(
            packet_id="pkt_" + "3" * 32,
            created_at=NOW,
            mode="project",
            project_id=PROJECT,
            packet_version="rlkctx1",
            memories=[item("mem_" + "4" * 16)],
        )
        raw = packet.to_dict()
        self.assertNotIn("explainability", raw)
        self.assertNotIn("explain", raw["memories"][0])
        self.assertEqual(ContextPacket.from_dict(raw).to_dict(), raw)

    def test_mutation_guards_cover_certainty_authority_order_and_budget(self):
        packet = self.annotated()
        # Inverting equality or changing UNKNOWN to FRESH breaks these.
        self.assertEqual(packet.code_facts[0].explain["freshness"]["state"], "fresh")
        unknown = evaluate_freshness("code", {}, context())
        self.assertNotEqual(unknown.state, FreshnessState.FRESH)
        # Removing domain separation introduces a false conflict.
        self.assertEqual(
            detect_contradictions(
                [fact("m", 1, domain="memory"), fact("c", 2, domain="code")]
            ),
            [],
        )
        # Unstable ordering or omitted metadata breaks these exact assertions.
        self.assertEqual(
            packet.contradictions,
            sorted(
                packet.contradictions,
                key=lambda c: (c["subject"], c["key"], c["type"], c["contradiction_id"]),
            ),
        )
        self.assertIn("budget", packet.memories[0].explain)


if __name__ == "__main__":
    unittest.main()
