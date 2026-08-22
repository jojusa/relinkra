"""R5H.2 contradiction-hardening discriminating tests.

Closes the contradiction-handling evidence gap before 0.1.0: deterministic
synthetic fixtures prove Relinkra preserves provenance, source authority,
freshness, and disagreement instead of silently collapsing conflicting
evidence into one false truth. Scenarios marked *must* verify BOTH the
machine-readable fields (state, reason_code, type, resolution_status,
evidence refs) AND the human/explainability semantics (summary prose,
recommended action, retention of the older record).
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from relinkra.context_builder import ContextBuilder, ContextRequest
from relinkra.context_packet import ContextPacket, PacketItem, Provenance
from relinkra.contradictions import (
    ContradictionType,
    EvidenceFact,
    ResolutionStatus,
    detect_contradictions,
)
from relinkra.engram_adapter import InMemoryStore
from relinkra.explainability import annotate_packet, explanation_document, human_summary
from relinkra.freshness import RevisionRelation, RevisionRelationState
from relinkra.identity import derive_project_id, normalize_remote_url
from relinkra.memory import MemoryService
from relinkra.registry import Registry

try:
    from tests import git_fixtures as gf
except ImportError:  # pragma: no cover - discover vs module invocation
    import git_fixtures as gf


NOW = "2026-08-11T12:00:00+00:00"
CURRENT = "b" * 40
OLD = "a" * 40
PROJECT = "rlk_" + "1" * 32


def relation(state, distance=None):
    return lambda _old, _current: RevisionRelation(state, distance=distance)


def _packet(**sections):
    defaults = {
        "packet_id": "pkt_" + "d" * 32,
        "created_at": NOW,
        "mode": "project",
        "project_id": PROJECT,
    }
    defaults.update(sections)
    return ContextPacket(**defaults)


def mem_item(
    sid,
    *,
    commit_sha=None,
    timestamp=NOW,
    topic_key=None,
    status="active",
    key=None,
    value=None,
):
    data = {
        "project_id": PROJECT,
        "timestamp": timestamp,
        "title": sid,
        "memory_id": sid,
        "memory_type": "decision",
        "status": status,
    }
    if commit_sha:
        data["commit_sha"] = commit_sha
    if topic_key:
        data["topic_key"] = topic_key
    if key is not None:
        data["key"] = key
        data["value"] = value
    return PacketItem(
        data=data,
        provenance=Provenance(
            source="engram",
            why_included="direct task match",
            memory_id=sid,
            topic_key=topic_key,
        ),
    )


def code_item(ref, *, index_head=CURRENT, trust="PASS"):
    return PacketItem(
        data={
            "code_reference_id": ref,
            "source_revision": index_head,
            "resolution_state": "resolved",
            "index_status": {"git": {"head_sha": index_head}},
            "trust_stages": [{"name": "CBM graph", "status": trust}],
        },
        provenance=Provenance(
            source="cbm", why_included="focused code", code_reference_id=ref
        ),
    )


def handoff_item(mem, *, status="active", head_sha=None):
    body = {"handoff_id": "hof_" + "2" * 32, "project_id": PROJECT, "status": status}
    if head_sha:
        body["git_state"] = {"head_sha": head_sha}
    return PacketItem(
        data={
            "memory_id": mem,
            "memory_type": "handoff",
            "timestamp": NOW,
            "body": json.dumps(body, sort_keys=True),
        },
        provenance=Provenance(
            source="engram", why_included="active handoff", memory_id=mem
        ),
    )


def repo_state(head=CURRENT, clean=True):
    return PacketItem(
        data={"kind": "repository_state", "head_sha": head, "clean": clean},
        provenance=Provenance(source="git", why_included="current repository state"),
    )


def head_fact(head=CURRENT):
    return PacketItem(
        data={"kind": "head_facts", "head_sha": head},
        provenance=Provenance(source="git", why_included="git HEAD facts"),
    )


def recent_commit(sha):
    return PacketItem(
        data={
            "kind": "recent_commit",
            "sha": sha,
            "subject": "historical",
            "committed_at": "2024-01-01T00:00:00+00:00",
        },
        provenance=Provenance(source="git", why_included="git recent commit"),
    )


def _annotated(packet):
    annotate_packet(
        packet,
        as_of=NOW,
        relation_resolver=relation(RevisionRelationState.ANCESTOR, 5),
    )
    return packet


class ResolutionStatusPolicyTests(unittest.TestCase):
    def _facts(self, conflict_type):
        if conflict_type == ContradictionType.TEMPORAL_SUPERSESSION:
            return [
                EvidenceFact("a", "d", "s", "x", "status", "open",
                             observed_at="2026-01-01T00:00:00Z"),
                EvidenceFact("b", "d", "s", "x", "status", "closed",
                             observed_at="2026-02-01T00:00:00Z"),
            ]
        if conflict_type == ContradictionType.REVISION_MISMATCH:
            return [
                EvidenceFact("git", "git_code", "git", "repository", "revision",
                             CURRENT, revision=CURRENT),
                EvidenceFact("mem", "engram_memory", "engram", "repository",
                             "revision", OLD, revision=OLD),
            ]
        return [
            EvidenceFact("a", "d", "s", "x", "k", 1),
            EvidenceFact("b", "d", "s", "x", "k", 2),
        ]

    def test_superseded_maps_to_superseded(self):
        result = detect_contradictions(
            self._facts(ContradictionType.TEMPORAL_SUPERSESSION)
        )[0]
        self.assertEqual(result.resolution_status, "superseded")
        self.assertEqual(
            result.to_dict()["resolution_status"], "superseded"
        )

    def test_revision_mismatch_maps_to_current_source_preferred(self):
        result = detect_contradictions(
            self._facts(ContradictionType.REVISION_MISMATCH)
        )[0]
        self.assertEqual(result.type, ContradictionType.REVISION_MISMATCH)
        self.assertEqual(result.resolution_status, "current_source_preferred")

    def test_unstructured_conflicts_remain_unresolved(self):
        result = detect_contradictions(
            self._facts(ContradictionType.SAME_KEY_DIFFERENT_VALUE)
        )[0]
        self.assertEqual(result.resolution_status, "unresolved")
        self.assertIsNone(result.newer_evidence_ref)

    def test_resolution_status_is_an_enum_member(self):
        self.assertEqual(
            {s.value for s in ResolutionStatus},
            {"unresolved", "current_source_preferred", "superseded"},
        )


class MemoryVsCurrentSourceTests(unittest.TestCase):
    def _scenario(self):
        return _annotated(
            _packet(
                memories=[mem_item("mem_" + "1" * 16, commit_sha=OLD)],
                code_facts=[code_item("ref_" + "2" * 32)],
                git_facts=[repo_state(CURRENT)],
            )
        )

    def test_machine_readable_fields(self):
        packet = self._scenario()
        memory = packet.memories[0]
        self.assertEqual(memory.explain["freshness"]["state"], "stale")
        self.assertEqual(memory.explain["freshness"]["reason_code"], "revision_stale")
        self.assertEqual(packet.code_facts[0].explain["freshness"]["state"], "fresh")

        contradictions = packet.contradictions
        self.assertEqual(len(contradictions), 1)
        conflict = contradictions[0]
        self.assertEqual(conflict["type"], "revision_mismatch")
        self.assertEqual(conflict["resolution_status"], "current_source_preferred")
        self.assertIn("engram", conflict["source_systems"])
        self.assertIn("git", conflict["source_systems"])
        self.assertNotIn("values", conflict)
        self.assertNotIn("explanation", conflict)

    def test_memory_is_not_suppressed_or_deleted(self):
        packet = self._scenario()
        self.assertEqual(len(packet.memories), 1)
        self.assertEqual(packet.memories[0].data["commit_sha"], OLD)
        conflict_id = packet.contradictions[0]["contradiction_id"]
        self.assertIn(
            conflict_id, packet.memories[0].explain["contradictions"]
        )

    def test_human_explainability_semantics(self):
        packet = self._scenario()
        text = human_summary(packet)
        self.assertIn("stale=1", text)
        self.assertIn("fresh=2", text)
        self.assertIn("contradictions: 1", text)
        self.assertIn("repository.revision conflicts across sources", text)
        self.assertIn("Recommended action:", text)
        self.assertIn("memories:mem_1111111111111111:0 is stale", text)
        markdown = packet.to_markdown()
        self.assertIn("repository.revision conflicts across sources", markdown)
        self.assertIn("memories:mem_1111111111111111:0 is stale", markdown)


class StaleCbmVsCurrentSourceTests(unittest.TestCase):
    def _scenario(self):
        # CBM graph is bound to OLD while the checkout is at CURRENT.
        return _annotated(
            _packet(
                code_facts=[code_item("ref_" + "3" * 32, index_head=OLD)],
                git_facts=[repo_state(CURRENT)],
            )
        )

    def test_stale_graph_is_advisory_and_qualified(self):
        packet = self._scenario()
        fact = packet.code_facts[0]
        self.assertEqual(fact.explain["freshness"]["state"], "stale")
        self.assertEqual(
            fact.explain["freshness"]["reason_code"],
            "cbm_graph_revision_mismatch",
        )
        self.assertTrue(fact.explain["trust"]["advisory_only"])

    def test_current_source_stays_fresh_and_conflict_is_explicit(self):
        packet = self._scenario()
        self.assertEqual(
            packet.git_facts[0].explain["freshness"]["state"], "fresh"
        )
        conflict = packet.contradictions[0]
        self.assertEqual(conflict["type"], "revision_mismatch")
        self.assertEqual(conflict["resolution_status"], "current_source_preferred")
        text = human_summary(packet)
        self.assertIn("repository.revision conflicts across sources", text)
        self.assertIn("stale=1", text)


class HandoffVsNewerSourceTests(unittest.TestCase):
    def _scenario(self):
        return _annotated(
            _packet(
                handoffs=[handoff_item("mem_" + "5" * 16, head_sha=OLD)],
                git_facts=[repo_state(CURRENT)],
            )
        )

    def test_handoff_is_historical_continuity_not_current_truth(self):
        packet = self._scenario()
        handoff = packet.handoffs[0]
        self.assertEqual(handoff.explain["freshness"]["state"], "stale")
        self.assertEqual(handoff.explain["freshness"]["reason_code"], "revision_stale")
        self.assertEqual(len(packet.handoffs), 1)

        conflict = packet.contradictions[0]
        self.assertEqual(conflict["type"], "revision_mismatch")
        self.assertEqual(conflict["resolution_status"], "current_source_preferred")
        self.assertEqual(
            packet.git_facts[0].explain["freshness"]["state"], "fresh"
        )
        self.assertIn("handoffs:mem_5555555555555555:0", conflict["evidence_refs"])


class MemoryVsMemoryUnresolvedTests(unittest.TestCase):
    def test_unit_level_two_claims_without_authority_stay_unresolved(self):
        result = detect_contradictions(
            [
                EvidenceFact("m1", "engram_memory", "engram", "entity",
                             "status", "active"),
                EvidenceFact("m2", "engram_memory", "engram", "entity",
                             "status", "superseded"),
            ]
        )[0]
        self.assertEqual(result.type, ContradictionType.STATUS_CONFLICT)
        self.assertEqual(result.resolution_status, "unresolved")
        self.assertIsNone(result.newer_evidence_ref)
        self.assertEqual(result.evidence_refs, ("m1", "m2"))

    def test_packet_level_two_memories_same_topic_conflict_is_unresolved(self):
        packet = _annotated(
            _packet(
                memories=[
                    mem_item("mem_" + "a" * 16, topic_key="topic/conn",
                             status="active"),
                    mem_item("mem_" + "b" * 16, topic_key="topic/conn",
                             status="superseded"),
                ],
            )
        )
        conflicts = {c["key"]: c for c in packet.contradictions}
        self.assertIn("status", conflicts)
        self.assertEqual(conflicts["status"]["resolution_status"], "unresolved")
        self.assertEqual(len(conflicts["status"]["evidence_refs"]), 2)
        self.assertEqual(len(packet.memories), 2)  # neither deleted


class HistoricalGitVsDirtyWorktreeTests(unittest.TestCase):
    def _scenario(self):
        return _annotated(
            _packet(
                git_facts=[
                    repo_state(CURRENT, clean=False),
                    head_fact(CURRENT),
                    recent_commit(OLD),
                ],
            )
        )

    def test_historical_commit_is_not_current(self):
        packet = self._scenario()
        states = {
            item.data["kind"]: item.explain["freshness"]["state"]
            for item in packet.git_facts
        }
        self.assertEqual(states["recent_commit"], "stale")
        self.assertEqual(states["head_facts"], "fresh")
        self.assertEqual(states["repository_state"], "fresh")

    def test_dirty_worktree_is_surfaced_as_limitation(self):
        packet = self._scenario()
        notices = packet.explainability.get("notices") or []
        dirty_notices = [
            n for n in notices
            if "uncommitted" in " ".join(n.get("limitations") or [])
        ]
        self.assertTrue(dirty_notices)
        self.assertEqual(dirty_notices[0]["state"], "fresh")
        self.assertTrue(packet.explainability["dirty_worktree"])

    def test_historical_vs_current_is_distinguished_not_collapsed(self):
        packet = self._scenario()
        conflict = packet.contradictions[0]
        self.assertEqual(conflict["type"], "revision_mismatch")
        self.assertEqual(conflict["resolution_status"], "current_source_preferred")
        text = human_summary(packet)
        self.assertIn("repository.revision conflicts across sources", text)


class NonConflictingMultiSourceTests(unittest.TestCase):
    def test_agreement_produces_no_false_contradiction(self):
        packet = _annotated(
            _packet(
                memories=[mem_item("mem_" + "1" * 16, commit_sha=CURRENT)],
                code_facts=[code_item("ref_" + "2" * 32)],
                git_facts=[repo_state(CURRENT)],
            )
        )
        self.assertEqual(packet.contradictions, [])
        for item in packet.memories + packet.code_facts + packet.git_facts:
            self.assertEqual(item.explain["freshness"]["state"], "fresh")
        self.assertIn(
            "No structured conflicts were detected", human_summary(packet)
        )


class RealisticCrossSourceProofTests(unittest.TestCase):
    """Controlled realistic proof (temporary project, real git).

    Seed memory + handoff describing ``legacy_connection()`` bound to the
    legacy commit, then change the source to ``runtime_connection()`` WITHOUT
    rewriting the historical memory/handoff. Assert Relinkra surfaces the
    old evidence as stale/conflicting, keeps it, and reports the current
    checkout — without ever claiming the legacy path is current.
    """

    IDENTITY = normalize_remote_url("https://github.com/org/relinkra-proof")
    REPO = {"kind": "remote", "value": IDENTITY.value, "trust": "strong"}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        repo = os.path.join(self.tmp.name, "repo")
        gf.make_repo(repo)
        self.legacy_sha = gf.commit_file(
            repo, "service.py",
            "def connect():\n    return legacy_connection()\n",
            "use legacy connection",
        )
        # Two further commits so the legacy record is clearly stale (>1 step).
        gf.commit_file(repo, "README.md", "proof\n", "add readme")
        gf.commit_file(
            repo, "service.py",
            "def connect():\n    return runtime_connection()\n",
            "switch to runtime connection",
        )
        self.current_sha = gf.git(repo, "rev-parse", "HEAD")

        self.pid = derive_project_id(self.IDENTITY.value)
        self.registry = Registry(os.path.join(self.tmp.name, "registry.json"))
        self.registry.register_workspace(
            repo,
            self.IDENTITY,
            git={"branch": "main", "head_sha": self.current_sha},
        )

        self.service = MemoryService(
            InMemoryStore(), clock=lambda: NOW
        )
        self.service.save(
            project_id=self.pid,
            memory_type="decision",
            title="Connection path",
            body="service calls legacy_connection()",
            repository_identity=self.REPO,
            commit_sha=self.legacy_sha,
            branch="main",
        )
        self.service.save(
            project_id=self.pid,
            memory_type="handoff",
            title="Legacy connection still unresolved",
            body=json.dumps(
                {
                    "handoff_id": "hof_" + "9" * 32,
                    "project_id": self.pid,
                    "status": "active",
                }
            ),
            repository_identity=self.REPO,
            commit_sha=self.legacy_sha,
            branch="main",
        )
        self.repo = repo

    def test_full_cross_source_behavior(self):
        builder = ContextBuilder(
            memory_service=self.service, registry=self.registry, workspace_root=self.repo
        )
        packet = builder.build(
            ContextRequest(
                project_id=self.pid,
                task="check the connection path",
                include_git=True,
                include_explain=True,
            )
        )

        # 1. Current source (git HEAD at the runtime commit) is current/fresh.
        repo_states = [
            item for item in packet.git_facts
            if item.data.get("kind") == "repository_state"
        ]
        self.assertTrue(repo_states)
        self.assertEqual(repo_states[0].data["head_sha"], self.current_sha)

        # 2. Old memory is retained, marked stale, bound to the legacy commit.
        memory = next(
            m for m in packet.memories
            if m.data.get("title") == "Connection path"
        )
        self.assertEqual(memory.data["commit_sha"], self.legacy_sha)
        self.assertEqual(memory.explain["freshness"]["state"], "stale")

        # 3. Old handoff is retained as historical continuity, not current truth.
        handoff = next(h for h in packet.handoffs if "Legacy connection" in h.data.get("title", ""))
        self.assertEqual(handoff.explain["freshness"]["state"], "stale")

        # 4. Contradiction is explicit and prefers current-source evidence.
        self.assertIn(
            "revision_mismatch",
            {c["type"] for c in packet.contradictions},
        )
        revision = next(
            c for c in packet.contradictions
            if c["type"] == "revision_mismatch"
        )
        self.assertEqual(revision["resolution_status"], "current_source_preferred")
        self.assertIn("engram", revision["source_systems"])
        self.assertIn("git", revision["source_systems"])

        # 5. Nothing claims the legacy path is current; the whole packet is advisory.
        self.assertTrue(packet.explainability["advisory_only"])
        text = human_summary(packet)
        self.assertIn("stale", text)
        self.assertIn("conflicts across sources", text)

        # 6. No destructive memory mutation: the record still reads "active".
        self.assertEqual(memory.data.get("status"), "active")
        self.assertEqual(handoff.data.get("status") or "active", "active")

        # 7. Explainability never re-emits the raw memory body.
        document = explanation_document(packet)
        self.assertNotIn("legacy_connection", json.dumps(document, sort_keys=True))

    def test_memory_service_was_not_rewritten(self):
        # The read pipeline must never rewrite history: the stored record
        # still describes the legacy path, and there is exactly one such record.
        result = self.service.query(project_id=self.pid, memory_type="decision")
        matches = [
            m for m in result.memories if "legacy_connection" in m.body
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].commit_sha, self.legacy_sha)


if __name__ == "__main__":
    unittest.main()