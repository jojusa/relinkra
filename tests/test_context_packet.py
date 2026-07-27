"""Offline deterministic tests for R1E Project Context Packets.

No subprocess, no network, no real Engram/CBM: InMemoryStore, fake CBM
adapters, temp-dir registries and workspace roots, fixed clocks.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from relinkra import context_cli
from relinkra.cbm import workspace_cbm_record
from relinkra.code_reference import CodeReference
from relinkra.context_builder import (
    ContextBuildError,
    ContextBuilder,
    ContextRequest,
    Guardrails,
)
from relinkra.context_packet import (
    ACCEPTED_PACKET_VERSIONS,
    PACKET_VERSION,
    PACKET_VERSION_V1,
    ContextPacket,
    PacketItem,
    PacketValidationError,
    PacketWarning,
    Provenance,
    SOURCES,
    compute_packet_id,
)
from relinkra.engram_adapter import EngramCLIAdapter, InMemoryStore
from relinkra.identity import derive_project_id, normalize_remote_url
from relinkra.memory import MemoryService, MemoryStoreError
from relinkra.registry import Registry

try:
    from tests import git_fixtures as gf
except ImportError:  # pragma: no cover - discover vs module invocation
    import git_fixtures as gf

IDENTITY = normalize_remote_url("https://github.com/org/repo")
PID = derive_project_id(IDENTITY.value)
IDENTITY_B = normalize_remote_url("https://github.com/org/other")
PID_B = derive_project_id(IDENTITY_B.value)
WID_UNKNOWN = "ws_" + "9" * 32

REPO = {"kind": "remote", "value": IDENTITY.value, "trust": "strong"}

FIXED_NOW = "2026-02-01T00:00:00+00:00"


def fixed_clock():
    return FIXED_NOW


class FakeCBMAdapter:
    """Duck-typed CBM adapter with canned normalized candidates."""

    def __init__(self, nodes=(), fail=False):
        self.nodes = list(nodes)
        self.fail = fail

    def get_snippet(self, qualified_name):
        if self.fail:
            raise RuntimeError("cbm down")
        for n in self.nodes:
            if n["qualified_name"] == qualified_name:
                return n
        return None

    def search_symbols(self, *, query=None, qualified_name=None,
                       file_path=None, limit=50):
        if self.fail:
            raise RuntimeError("cbm down")
        results = self.nodes
        if query:
            q = query.lower()
            results = [
                n
                for n in results
                if q in (n["name"] or "").lower()
                or q in (n["relative_qualified_name"] or "").lower()
            ]
        if file_path:
            results = [n for n in results if n["file_path"] == file_path]
        return results


SLUG = "C-Desarrollos-relinkra-ws"


def node(name, rel_qn, path, label="Function", start=None, end=None):
    return {
        "name": name,
        "qualified_name": f"{SLUG}.{rel_qn}" if rel_qn else SLUG,
        "relative_qualified_name": rel_qn,
        "label": label,
        "file_path": path,
        "start_line": start,
        "end_line": end,
        "cbm_project_name": SLUG,
    }


def make_service(store=None):
    store = store or InMemoryStore()
    tick = {"n": 0}

    def clock():
        tick["n"] += 1
        return f"2026-01-01T00:00:{tick['n']:02d}+00:00"

    ids = {"n": 0}

    def id_gen():
        ids["n"] += 1
        return f"mem_{ids['n']:016x}"

    return MemoryService(store, clock=clock, id_generator=id_gen), store


class Env:
    """Registered project + workspace + seeded memory service."""

    def __init__(self, cbm=None, seed=True, workspace_root=None):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        self.ws_dir = os.path.join(root, "ws")
        os.makedirs(self.ws_dir, exist_ok=True)
        self.registry_path = os.path.join(root, "registry.json")
        self.registry = Registry(self.registry_path)
        self.workspace = self.registry.register_workspace(
            self.ws_dir,
            IDENTITY,
            git={"branch": "main", "head_sha": "a" * 40},
            cbm=workspace_cbm_record(SLUG, os.path.join(root, "cbm")).to_dict(),
        )
        self.project_id = self.workspace.project_id
        self.workspace_id = self.workspace.workspace_id
        self.service, self.store = make_service()
        self.cbm = cbm
        self.workspace_root = (
            workspace_root if workspace_root is not None else self.ws_dir
        )
        if seed:
            self.seed_memories()

    def cleanup(self):
        self.tmp.cleanup()

    def save(self, **kwargs):
        kwargs.setdefault("project_id", self.project_id)
        kwargs.setdefault("repository_identity", REPO)
        memory, _, _ = self.service.save(**kwargs)
        return memory

    def seed_memories(self):
        self.save(memory_type="decision", title="Use JWT for auth", body="d")
        self.save(
            memory_type="architecture", title="Hexagonal layout", body="a"
        )
        self.save(
            memory_type="constraint", title="Python stdlib only", body="c"
        )
        self.save(
            memory_type="bug",
            title="Fixed parser off-by-one",
            body="the parser skipped a line",
        )
        self.save(
            memory_type="discovery",
            title="CBM slug is path-derived",
            body="x",
        )
        self.save(memory_type="verification", title="Suite green", body="v")
        self.save(memory_type="task_result", title="Implemented R1D", body="t")
        self.save(memory_type="pending", title="Wire live proof", body="p")
        self.save(memory_type="handoff", title="R1E handoff note", body="h")
        self.save(
            memory_type="discovery",
            title="Workspace A note",
            body="wa",
            scope="workspace_local",
            workspace_id=self.workspace_id,
        )
        self.save(
            memory_type="discovery",
            title="Other workspace note",
            body="wb",
            scope="workspace_local",
            workspace_id=WID_UNKNOWN,
        )
        self.save(
            memory_type="discovery",
            title="Private note",
            body="pa",
            scope="agent_private",
            agent_type="opencode",
        )
        # lifecycle: superseded and obsolete must never surface
        self.save(memory_type="decision", title="Old decision", body="v1")
        self.save(memory_type="decision", title="Old decision", body="v2")
        doomed = self.save(memory_type="bug", title="Doomed bug", body="x")
        self.service.supersede(
            memory_id=doomed.memory_id, project_id=self.project_id,
            obsolete=True,
        )

    def builder(self, **overrides):
        kwargs = {
            "memory_service": self.service,
            "cbm_adapter": self.cbm,
            "registry": self.registry,
            "workspace_root": self.workspace_root,
            "clock": fixed_clock,
        }
        kwargs.update(overrides)
        return ContextBuilder(**kwargs)

    def request(self, **overrides):
        kwargs = {"project_id": self.project_id}
        kwargs.update(overrides)
        return ContextRequest(**kwargs)


def titles(items):
    return [item.data["title"] for item in items]


def warning_codes(packet):
    return [w.code for w in packet.warnings]


class PacketIdTests(unittest.TestCase):
    def test_deterministic_same_inputs(self):
        a = compute_packet_id(
            project_id=PID, mode="task", task="Fix Parser",
            source_ids=("mem_1", "ref_2"),
        )
        b = compute_packet_id(
            project_id=PID, mode="task", task="fix   parser",
            source_ids=("mem_1", "ref_2"),
        )
        self.assertEqual(a, b)

    def test_source_id_order_irrelevant(self):
        a = compute_packet_id(
            project_id=PID, mode="project", source_ids=("b", "a", "c")
        )
        b = compute_packet_id(
            project_id=PID, mode="project", source_ids=("c", "a", "b")
        )
        self.assertEqual(a, b)

    def test_identity_changes_with_inputs(self):
        base = compute_packet_id(project_id=PID, mode="project")
        for kwargs in (
            {"project_id": PID_B},
            {"mode": "task", "task": "x"},
            {"workspace_id": WID_UNKNOWN},
            {"source_ids": ("mem_1",)},
            {"focus": {"reference_kind": "file", "file_path": "a.py"}},
        ):
            merged = {"project_id": PID, "mode": "project"}
            merged.update(kwargs)
            self.assertNotEqual(base, compute_packet_id(**merged))

    def test_format(self):
        pid = compute_packet_id(project_id=PID, mode="project")
        self.assertRegex(pid, r"^pkt_[0-9a-f]{32}$")


class SerializationTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.addCleanup(self.env.cleanup)

    def build(self):
        return self.env.builder().build(self.env.request())

    def test_round_trip(self):
        packet = self.build()
        clone = ContextPacket.from_dict(packet.to_dict())
        self.assertEqual(packet.to_dict(), clone.to_dict())

    def test_json_sorted_and_deterministic(self):
        packet = self.build()
        raw = packet.to_json()
        self.assertEqual(raw, json.dumps(packet.to_dict(), sort_keys=True,
                                         separators=(",", ":"),
                                         ensure_ascii=False))
        parsed = json.loads(raw)
        # git-off builds keep emitting rlkctx1 (byte-compatible); the
        # PACKET_VERSION constant now denotes the LATEST version (rlkctx2).
        self.assertEqual(parsed["packet_version"], PACKET_VERSION_V1)
        self.assertEqual(parsed["packet_id"], packet.packet_id)

    def test_json_round_trip(self):
        packet = self.build()
        clone = ContextPacket.from_dict(json.loads(packet.to_json(pretty=True)))
        self.assertEqual(packet.to_dict(), clone.to_dict())

    def test_markdown_sections(self):
        md = self.build().to_markdown()
        for section in (
            "# RELINKRA CONTEXT",
            "## Project",
            "## Task-Focus",
            "## Active decisions",
            "## Constraints",
            "## Code focus",
            "## Pending-Handoff",
            "## Warnings",
            "## Provenance",
        ):
            self.assertIn(section, md)


class ModeTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.addCleanup(self.env.cleanup)

    def test_project_mode_shared_only(self):
        packet = self.env.builder().build(self.env.request())
        self.assertEqual(packet.mode, "project")
        all_titles = titles(packet.memories) + titles(packet.pending) + titles(
            packet.handoffs
        )
        self.assertIn("Use JWT for auth", all_titles)
        self.assertIn("Python stdlib only", all_titles)
        self.assertNotIn("Workspace A note", all_titles)
        self.assertNotIn("Other workspace note", all_titles)
        self.assertNotIn("Private note", all_titles)

    def test_workspace_mode_includes_matching_workspace(self):
        packet = self.env.builder().build(
            self.env.request(workspace_id=self.env.workspace_id)
        )
        self.assertEqual(packet.mode, "workspace")
        all_titles = titles(packet.memories)
        self.assertIn("Workspace A note", all_titles)
        self.assertNotIn("Other workspace note", all_titles)
        self.assertNotIn("Private note", all_titles)

    def test_agent_private_requires_flag_and_matching_agent(self):
        builder = self.env.builder()
        packet = builder.build(
            self.env.request(requesting_agent="opencode")
        )
        self.assertNotIn("Private note", titles(packet.memories))
        packet = builder.build(
            self.env.request(
                requesting_agent="opencode", include_agent_private=True
            )
        )
        self.assertIn("Private note", titles(packet.memories))
        packet = builder.build(
            self.env.request(
                requesting_agent="codex", include_agent_private=True
            )
        )
        self.assertNotIn("Private note", titles(packet.memories))

    def test_lifecycle_excludes_superseded_and_obsolete(self):
        packet = self.env.builder().build(self.env.request())
        all_titles = titles(packet.memories) + titles(packet.pending)
        self.assertIn("Old decision", all_titles)  # the v2 head only
        decision_items = [
            i for i in packet.memories if i.data["title"] == "Old decision"
        ]
        self.assertEqual(len(decision_items), 1)
        self.assertEqual(decision_items[0].data["body"], "v2")
        self.assertNotIn("Doomed bug", all_titles)

    def test_task_mode_keyword_filter(self):
        packet = self.env.builder().build(
            self.env.request(task="fix the parser crash")
        )
        self.assertEqual(packet.mode, "task")
        memory_titles = titles(packet.memories)
        self.assertIn("Fixed parser off-by-one", memory_titles)
        # non-baseline, non-matching types are filtered out
        self.assertNotIn("CBM slug is path-derived", memory_titles)
        self.assertNotIn("Suite green", memory_titles)
        self.assertNotIn("Implemented R1D", memory_titles)
        # baseline types stay eligible without a keyword match
        self.assertIn("Use JWT for auth", memory_titles)
        # pending/handoff remain first-class
        self.assertEqual(titles(packet.pending), ["Wire live proof"])
        self.assertEqual(titles(packet.handoffs), ["R1E handoff note"])

    def test_task_matching_is_deterministic(self):
        builder = self.env.builder()
        a = builder.build(self.env.request(task="fix the parser crash"))
        b = builder.build(self.env.request(task="  FIX   the parser crash "))
        self.assertEqual(a.packet_id, b.packet_id)

    def test_mode_precedence(self):
        builder = self.env.builder()
        base = dict(
            workspace_id=self.env.workspace_id,
            task="some task text",
            file="src/calc.py",
            symbol="src.calc.add",
        )
        self.assertEqual(builder.build(self.env.request(**base)).mode, "symbol")
        base.pop("symbol")
        self.assertEqual(builder.build(self.env.request(**base)).mode, "file")
        base.pop("file")
        self.assertEqual(builder.build(self.env.request(**base)).mode, "task")
        base.pop("task")
        self.assertEqual(
            builder.build(self.env.request(**base)).mode, "workspace"
        )


class TypePriorityTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.addCleanup(self.env.cleanup)

    def test_priority_order(self):
        packet = self.env.builder().build(self.env.request())
        types = [item.data["memory_type"] for item in packet.memories]
        self.assertEqual(
            types,
            [
                "constraint",
                "decision",
                "decision",
                "architecture",
                "bug",
                "discovery",
                "verification",
                "task_result",
            ],
        )

    def test_pending_and_handoff_first_class(self):
        packet = self.env.builder().build(self.env.request())
        self.assertEqual(titles(packet.pending), ["Wire live proof"])
        self.assertEqual(titles(packet.handoffs), ["R1E handoff note"])
        self.assertNotIn("Wire live proof", titles(packet.memories))
        self.assertNotIn("R1E handoff note", titles(packet.memories))


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.addCleanup(self.env.cleanup)

    def test_memory_provenance_fields(self):
        packet = self.env.builder().build(self.env.request())
        item = packet.memories[0]
        prov = item.provenance
        self.assertEqual(prov.source, "engram")
        self.assertTrue(prov.memory_id.startswith("mem_"))
        self.assertTrue(prov.topic_key.startswith("relinkra/v1/"))
        self.assertTrue(prov.why_included)
        self.assertNotIn("why_included", item.data)

    def test_packet_level_provenance(self):
        packet = self.env.builder().build(self.env.request())
        self.assertIn("registry", packet.provenance["sources"])
        self.assertIn("engram", packet.provenance["sources"])
        self.assertIn("relinkra", packet.provenance["sources"])

    def test_project_facts_from_registry(self):
        packet = self.env.builder().build(
            self.env.request(workspace_id=self.env.workspace_id)
        )
        self.assertEqual(packet.repository_identity["value"], IDENTITY.value)
        ws = packet.project_facts["workspace"]
        self.assertEqual(ws["branch"], "main")
        self.assertEqual(ws["head_sha"], "a" * 40)
        self.assertEqual(ws["cbm_project_name"], SLUG)


class CodeFocusTests(unittest.TestCase):
    def setUp(self):
        self.nodes = [
            node("add", "src.calc.add", "src/calc.py", start=2, end=3),
            node("sub", "src.calc.sub", "src/calc.py", start=5, end=6),
        ]
        self.env = Env(cbm=FakeCBMAdapter(self.nodes))
        self.addCleanup(self.env.cleanup)

    def _write_calc(self, lines):
        src = os.path.join(self.env.ws_dir, "src")
        os.makedirs(src, exist_ok=True)
        with open(os.path.join(src, "calc.py"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))

    def test_file_mode_resolves_and_links(self):
        ref = CodeReference(
            project_id=self.env.project_id,
            reference_kind="file",
            file_path="src/calc.py",
        )
        self.env.save(
            memory_type="bug", title="Calc bug", body="b",
            code_refs=[ref.to_dict()],
        )
        packet = self.env.builder().build(
            self.env.request(file="src/calc.py")
        )
        self.assertEqual(packet.mode, "file")
        self.assertEqual(
            packet.focus,
            {"reference_kind": "file", "file_path": "src/calc.py"},
        )
        self.assertEqual(len(packet.code_references), 1)
        item = packet.code_references[0]
        self.assertEqual(item.data["resolution_state"], "resolved")
        self.assertEqual(item.provenance.source, "cbm")
        self.assertTrue(item.provenance.code_reference_id.startswith("ref_"))
        linked = [i for i in packet.memories if i.data["title"] == "Calc bug"]
        self.assertEqual(len(linked), 1)
        self.assertEqual(
            linked[0].provenance.why_included,
            "directly linked to the focused code",
        )

    def test_symbol_mode_exact_resolution_with_snippet(self):
        self._write_calc(
            ["# header", "def add(a, b):", "    return a + b", "# tail"]
        )
        packet = self.env.builder().build(
            self.env.request(symbol="src.calc.add")
        )
        self.assertEqual(packet.mode, "symbol")
        self.assertEqual(len(packet.code_references), 1)
        self.assertEqual(
            packet.code_references[0].data["resolution_state"], "resolved"
        )
        facts = packet.code_facts
        self.assertEqual(len(facts), 1)
        fact = facts[0].data
        self.assertEqual(fact["qualified_name"], "src.calc.add")
        self.assertEqual(
            fact["snippet"], "def add(a, b):\n    return a + b"
        )
        self.assertFalse(fact["snippet_truncated"])
        self.assertEqual(packet.diagnostics["counts"]["snippets"], 1)

    def test_symbol_mode_json_code_reference(self):
        ref = CodeReference(
            project_id=self.env.project_id,
            reference_kind="symbol",
            file_path="src/calc.py",
            symbol_name="add",
            qualified_name="src.calc.add",
            start_line=2,
            end_line=3,
            cbm_project_name=SLUG,
        )
        packet = self.env.builder().build(
            self.env.request(symbol=json.dumps(ref.to_dict()))
        )
        self.assertEqual(packet.mode, "symbol")
        self.assertEqual(
            packet.code_references[0].data["resolution_state"], "resolved"
        )

    def test_symbol_mode_links_memories(self):
        ref = CodeReference(
            project_id=self.env.project_id,
            reference_kind="symbol",
            file_path="src/calc.py",
            symbol_name="add",
            qualified_name="src.calc.add",
        )
        self.env.save(
            memory_type="decision", title="Add stays pure", body="d",
            code_refs=[ref.to_dict()],
        )
        packet = self.env.builder().build(
            self.env.request(symbol="src.calc.add")
        )
        linked = [
            i for i in packet.memories if i.data["title"] == "Add stays pure"
        ]
        self.assertEqual(len(linked), 1)
        self.assertEqual(
            linked[0].provenance.why_included,
            "directly linked to the focused code",
        )

    def test_stale_warning(self):
        stale_ref = CodeReference(
            project_id=self.env.project_id,
            reference_kind="symbol",
            file_path="src/calc.py",
            symbol_name="add",
            qualified_name="src.calc.add",
            start_line=1,
            cbm_project_name=SLUG,
        )
        packet = self.env.builder().build(
            self.env.request(symbol=json.dumps(stale_ref.to_dict()))
        )
        self.assertIn("stale_code_reference", warning_codes(packet))
        self.assertEqual(
            packet.code_references[0].data["resolution_state"], "stale"
        )

    def test_ambiguous_warning(self):
        env = Env(
            cbm=FakeCBMAdapter(
                [
                    node("add", "src.calc.add", "src/calc.py"),
                    node("add", "src.other.add", "src/other.py"),
                ]
            )
        )
        self.addCleanup(env.cleanup)
        packet = env.builder().build(env.request(symbol="add"))
        self.assertIn("ambiguous_code_reference", warning_codes(packet))
        self.assertEqual(len(packet.code_references), 0)
        self.assertEqual(len(packet.code_facts), 2)

    def test_missing_symbol_warning(self):
        packet = self.env.builder().build(self.env.request(symbol="ghost"))
        self.assertIn("missing_code_reference", warning_codes(packet))
        self.assertEqual(len(packet.code_references), 0)

    def test_cbm_unavailable_warning(self):
        env = Env(cbm=None)
        self.addCleanup(env.cleanup)
        packet = env.builder().build(env.request(file="src/calc.py"))
        self.assertIn("cbm_unavailable", warning_codes(packet))
        self.assertEqual(packet.mode, "file")

    def test_cbm_failure_file_focus_warns_unavailable_not_missing(self):
        env = Env(cbm=FakeCBMAdapter(fail=True))
        self.addCleanup(env.cleanup)
        packet = env.builder().build(env.request(file="src/calc.py"))
        codes = warning_codes(packet)
        self.assertIn("cbm_unavailable", codes)
        self.assertNotIn("missing_code_reference", codes)
        item = packet.code_references[0]
        self.assertEqual(item.data["resolution_state"], "missing")
        self.assertIn("unavailable", item.data["note"])

    def test_cbm_failure_symbol_focus_warns_unavailable_not_missing(self):
        env = Env(cbm=FakeCBMAdapter(fail=True))
        self.addCleanup(env.cleanup)
        packet = env.builder().build(env.request(symbol="add"))
        codes = warning_codes(packet)
        self.assertIn("cbm_unavailable", codes)
        self.assertNotIn("missing_code_reference", codes)
        self.assertEqual(len(packet.code_references), 0)

    def test_cbm_genuine_empty_result_stays_missing(self):
        env = Env(cbm=FakeCBMAdapter([]))
        self.addCleanup(env.cleanup)
        packet = env.builder().build(env.request(file="src/ghost.py"))
        codes = warning_codes(packet)
        self.assertIn("missing_code_reference", codes)
        self.assertNotIn("cbm_unavailable", codes)


class DegradationTests(unittest.TestCase):
    def test_engram_unavailable_partial_packet(self):
        class FailingStore(InMemoryStore):
            def search_records(self, **kwargs):
                raise MemoryStoreError("store exploded token=abc123")

        env = Env()
        self.addCleanup(env.cleanup)
        service, _ = make_service(store=FailingStore())
        builder = env.builder(memory_service=service)
        packet = builder.build(env.request())
        codes = warning_codes(packet)
        self.assertIn("engram_unavailable", codes)
        self.assertEqual(packet.memories, [])
        self.assertEqual(packet.pending, [])
        # redacted error text, never raw secrets
        text = json.dumps(packet.to_dict())
        self.assertNotIn("abc123", text)

    def test_no_memory_service_warns(self):
        env = Env()
        self.addCleanup(env.cleanup)
        packet = env.builder(memory_service=None).build(env.request())
        self.assertIn("engram_unavailable", warning_codes(packet))

    def test_workspace_not_registered_warns(self):
        env = Env()
        self.addCleanup(env.cleanup)
        packet = env.builder().build(env.request(workspace_id=WID_UNKNOWN))
        self.assertIn("workspace_not_registered", warning_codes(packet))
        self.assertEqual(packet.mode, "workspace")

    def test_workspace_mismatch_warns(self):
        env = Env()
        self.addCleanup(env.cleanup)
        other = tempfile.TemporaryDirectory()
        self.addCleanup(other.cleanup)
        builder = env.builder(workspace_root=other.name)
        packet = builder.build(
            env.request(workspace_id=env.workspace_id)
        )
        self.assertIn("workspace_mismatch", warning_codes(packet))


class FatalTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.addCleanup(self.env.cleanup)

    def test_invalid_project_id(self):
        with self.assertRaises(ContextBuildError):
            self.env.builder().build(ContextRequest(project_id="nope"))

    def test_invalid_workspace_id(self):
        with self.assertRaises(ContextBuildError):
            self.env.builder().build(
                self.env.request(workspace_id="not-a-ws")
            )

    def test_project_not_in_registry(self):
        with self.assertRaises(ContextBuildError) as ctx:
            self.env.builder().build(ContextRequest(project_id=PID_B))
        self.assertEqual(ctx.exception.exit_code, 2)

    def test_workspace_of_other_project(self):
        other_dir = tempfile.TemporaryDirectory()
        self.addCleanup(other_dir.cleanup)
        other_ws = self.env.registry.register_workspace(
            os.path.join(other_dir.name, "ws2"), IDENTITY_B,
            allow_weak_merge=True,
        )
        with self.assertRaises(ContextBuildError) as ctx:
            self.env.builder().build(
                self.env.request(workspace_id=other_ws.workspace_id)
            )
        self.assertEqual(ctx.exception.exit_code, 2)

    def test_absolute_file_rejected(self):
        with self.assertRaises(ContextBuildError):
            self.env.builder().build(self.env.request(file="/abs/path.py"))

    def test_symbol_ref_of_other_project(self):
        ref = CodeReference(
            project_id=PID_B,
            reference_kind="symbol",
            file_path="src/calc.py",
            symbol_name="add",
        )
        with self.assertRaises(ContextBuildError) as ctx:
            self.env.builder().build(
                self.env.request(symbol=json.dumps(ref.to_dict()))
            )
        self.assertEqual(ctx.exception.exit_code, 2)


class GuardrailTests(unittest.TestCase):
    def test_max_memories_and_omission(self):
        env = Env(seed=False)
        self.addCleanup(env.cleanup)
        for i in range(15):
            env.save(
                memory_type="discovery", title=f"Discovery {i:02d}", body="x"
            )
        packet = env.builder().build(env.request())
        self.assertEqual(len(packet.memories), 12)
        self.assertEqual(packet.diagnostics["omitted"]["memories"], 3)
        self.assertIn("items_omitted", warning_codes(packet))

    def test_max_pending_and_handoffs(self):
        env = Env(seed=False)
        self.addCleanup(env.cleanup)
        for i in range(6):
            env.save(memory_type="pending", title=f"Pending {i}", body="x")
        for i in range(4):
            env.save(memory_type="handoff", title=f"Handoff {i}", body="x")
        packet = env.builder().build(env.request())
        self.assertEqual(len(packet.pending), 5)
        self.assertEqual(len(packet.handoffs), 3)
        self.assertEqual(packet.diagnostics["omitted"]["pending"], 1)
        self.assertEqual(packet.diagnostics["omitted"]["handoffs"], 1)

    def test_max_warnings(self):
        env = Env(seed=False, cbm=None)
        self.addCleanup(env.cleanup)
        builder = env.builder(
            guardrails=Guardrails(max_warnings=2),
            memory_service=None,
            workspace_root=None,
        )
        packet = builder.build(
            env.request(workspace_id=WID_UNKNOWN, file="src/calc.py")
        )
        self.assertEqual(len(packet.warnings), 2)
        self.assertEqual(packet.diagnostics["omitted"]["warnings"], 1)

    def test_items_omitted_survives_warning_truncation(self):
        env = Env(seed=False, cbm=None)
        self.addCleanup(env.cleanup)
        for i in range(15):
            env.save(
                memory_type="discovery", title=f"Discovery {i:02d}", body="x"
            )
        builder = env.builder(guardrails=Guardrails(max_warnings=1))
        packet = builder.build(
            env.request(workspace_id=WID_UNKNOWN, file="src/calc.py")
        )
        codes = warning_codes(packet)
        self.assertIn("items_omitted", codes)
        self.assertEqual(codes, ["items_omitted"])
        self.assertEqual(packet.diagnostics["omitted"]["memories"], 3)
        self.assertGreater(packet.diagnostics["omitted"]["warnings"], 0)

    def test_content_truncated_survives_warning_truncation(self):
        nodes = [node("add", "src.calc.add", "src/calc.py", start=1, end=1)]
        env = Env(seed=False, cbm=FakeCBMAdapter(nodes))
        self.addCleanup(env.cleanup)
        src = os.path.join(env.ws_dir, "src")
        os.makedirs(src, exist_ok=True)
        with open(os.path.join(src, "calc.py"), "w", encoding="utf-8") as fh:
            fh.write("x" * 5000)
        builder = env.builder(
            guardrails=Guardrails(max_warnings=1, max_snippet_chars=100)
        )
        packet = builder.build(
            env.request(workspace_id=WID_UNKNOWN, symbol="src.calc.add")
        )
        codes = warning_codes(packet)
        self.assertIn("content_truncated", codes)
        self.assertEqual(codes, ["content_truncated"])
        self.assertGreater(packet.diagnostics["omitted"]["warnings"], 0)

    def test_snippet_truncation(self):
        nodes = [node("add", "src.calc.add", "src/calc.py", start=1, end=1)]
        env = Env(cbm=FakeCBMAdapter(nodes))
        self.addCleanup(env.cleanup)
        src = os.path.join(env.ws_dir, "src")
        os.makedirs(src, exist_ok=True)
        with open(os.path.join(src, "calc.py"), "w", encoding="utf-8") as fh:
            fh.write("x" * 5000)
        builder = env.builder(guardrails=Guardrails(max_snippet_chars=1200))
        packet = builder.build(env.request(symbol="src.calc.add"))
        fact = packet.code_facts[0].data
        self.assertEqual(len(fact["snippet"]), 1200)
        self.assertTrue(fact["snippet_truncated"])
        self.assertEqual(packet.diagnostics["truncated_snippets"], 1)
        self.assertIn("content_truncated", warning_codes(packet))

    def test_snippets_disabled_by_guardrail(self):
        nodes = [node("add", "src.calc.add", "src/calc.py", start=1, end=1)]
        env = Env(cbm=FakeCBMAdapter(nodes))
        self.addCleanup(env.cleanup)
        src = os.path.join(env.ws_dir, "src")
        os.makedirs(src, exist_ok=True)
        with open(os.path.join(src, "calc.py"), "w", encoding="utf-8") as fh:
            fh.write("def add(): pass")
        builder = env.builder(guardrails=Guardrails(max_snippets=0))
        packet = builder.build(env.request(symbol="src.calc.add"))
        self.assertNotIn("snippet", packet.code_facts[0].data)


class DeterminismTests(unittest.TestCase):
    def test_repeated_generation_same_packet_id(self):
        env = Env()
        self.addCleanup(env.cleanup)
        calls = {"n": 0}

        def ticking_clock():
            calls["n"] += 1
            return f"2026-03-01T00:00:{calls['n']:02d}+00:00"

        builder = env.builder(clock=ticking_clock)
        request = env.request(
            workspace_id=env.workspace_id, task="fix the parser crash"
        )
        a = builder.build(request)
        b = builder.build(request)
        self.assertNotEqual(a.created_at, b.created_at)
        self.assertEqual(a.packet_id, b.packet_id)
        da, db = a.to_dict(), b.to_dict()
        da.pop("created_at")
        db.pop("created_at")
        self.assertEqual(da, db)

    def test_selected_source_ids_sorted(self):
        env = Env()
        self.addCleanup(env.cleanup)
        packet = env.builder().build(env.request())
        ids = packet.diagnostics["selected_source_ids"]
        self.assertEqual(ids, sorted(ids))
        self.assertTrue(ids)


class EngramAliasTests(unittest.TestCase):
    def test_alias_rewrites_cli_search_project(self):
        adapter = EngramCLIAdapter(
            engram_bin="engram", http_url="", project_alias="relinkra"
        )
        with mock.patch.object(
            adapter, "_run", return_value="No memories found"
        ) as run:
            adapter.search_records(query="x", project=PID, limit=5)
        argv = run.call_args[0][0]
        self.assertIn("--project", argv)
        self.assertEqual(argv[argv.index("--project") + 1], "relinkra")

    def test_alias_rewrites_http_search_project(self):
        adapter = EngramCLIAdapter(project_alias="relinkra")
        with mock.patch.object(
            adapter, "_http_search", return_value=[]
        ) as http:
            adapter.search_records(query="x", project=PID)
        self.assertEqual(http.call_args[0][1], "relinkra")

    def test_no_alias_keeps_logical_project(self):
        adapter = EngramCLIAdapter(engram_bin="engram", http_url="")
        with mock.patch.object(
            adapter, "_run", return_value="No memories found"
        ) as run:
            adapter.search_records(query="x", project=PID)
        argv = run.call_args[0][0]
        self.assertEqual(argv[argv.index("--project") + 1], PID)

    def test_alias_preserves_policy_filtering(self):
        class AliasedStore(InMemoryStore):
            """Physical rows live under the alias; reads map to it."""

            def save_record(self, *, title, content, storage_type, project,
                            scope, topic_key):
                return super().save_record(
                    title=title, content=content, storage_type=storage_type,
                    project="relinkra", scope=scope, topic_key=topic_key,
                )

            def search_records(self, *, query, project=None, storage_type=None,
                               limit=50):
                return super().search_records(
                    query=query, project="relinkra",
                    storage_type=storage_type, limit=limit,
                )

        store = AliasedStore()
        service, _ = make_service(store=store)
        service.save(
            project_id=PID, memory_type="decision", title="Mine", body="x",
            repository_identity=REPO,
        )
        service.save(
            project_id=PID_B, memory_type="decision", title="Theirs", body="x",
            repository_identity=REPO,
        )
        # physical records live under the alias project
        self.assertTrue(all(r.project == "relinkra" for r in store._records))
        result = service.query(project_id=PID)
        titles_ = [m.title for m in result.memories]
        self.assertIn("Mine", titles_)
        self.assertNotIn("Theirs", titles_)


class CLITests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.addCleanup(self.env.cleanup)

    def run_cli(self, argv, **kwargs):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = context_cli.main(argv, **kwargs)
        return code, out.getvalue(), err.getvalue()

    def test_json_output(self):
        code, out, err = self.run_cli(
            [
                "--project-id", self.env.project_id,
                "--registry", self.env.registry_path,
            ],
            store=self.env.store, clock=fixed_clock,
        )
        self.assertEqual(code, 0, err)
        packet = json.loads(out)
        self.assertEqual(packet["mode"], "project")
        self.assertEqual(packet["project_id"], self.env.project_id)
        self.assertEqual(err, "")

    def test_markdown_output(self):
        code, out, err = self.run_cli(
            [
                "--project-id", self.env.project_id,
                "--registry", self.env.registry_path,
                "--format", "markdown",
            ],
            store=self.env.store, clock=fixed_clock,
        )
        self.assertEqual(code, 0, err)
        self.assertIn("# RELINKRA CONTEXT", out)

    def test_pretty_json_is_sorted(self):
        code, out, err = self.run_cli(
            [
                "--project-id", self.env.project_id,
                "--registry", self.env.registry_path, "--pretty",
            ],
            store=self.env.store, clock=fixed_clock,
        )
        self.assertEqual(code, 0, err)
        packet = json.loads(out)
        self.assertEqual(packet["packet_version"], PACKET_VERSION_V1)

    def test_invalid_input_exit_1(self):
        code, out, err = self.run_cli(
            ["--project-id", "nope", "--registry", "/nonexistent/reg.json"],
            store=self.env.store, clock=fixed_clock,
        )
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error", json.loads(err))

    def test_project_mismatch_exit_2(self):
        code, out, err = self.run_cli(
            [
                "--project-id", PID_B,
                "--registry", self.env.registry_path,
            ],
            store=self.env.store, clock=fixed_clock,
        )
        self.assertEqual(code, 2)
        self.assertIn("error", json.loads(err))

    def test_cli_matches_builder_packet_id(self):
        builder_packet = self.env.builder().build(
            self.env.request(task="fix the parser crash")
        )
        code, out, err = self.run_cli(
            [
                "--project-id", self.env.project_id,
                "--registry", self.env.registry_path,
                "--task", "fix the parser crash",
            ],
            store=self.env.store, clock=fixed_clock,
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["packet_id"], builder_packet.packet_id)


class PortableCacheDirTests(unittest.TestCase):
    """Portable packets never leak ABSOLUTE CBM cache paths: they are
    dropped from project_facts and exposed only under
    diagnostics["local"] (a machine-local channel)."""

    def build_with_cache_dir(self, cache_dir):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        ws_dir = os.path.join(tmp.name, "ws")
        os.makedirs(ws_dir, exist_ok=True)
        registry = Registry(os.path.join(tmp.name, "registry.json"))
        workspace = registry.register_workspace(
            ws_dir,
            IDENTITY,
            git={"branch": "main", "head_sha": "a" * 40},
            cbm=workspace_cbm_record(SLUG, cache_dir).to_dict(),
        )
        service, _ = make_service()
        builder = ContextBuilder(
            memory_service=service,
            cbm_adapter=None,
            registry=registry,
            workspace_root=ws_dir,
            clock=fixed_clock,
        )
        return builder.build(
            ContextRequest(
                project_id=workspace.project_id,
                workspace_id=workspace.workspace_id,
            )
        )

    def assert_portable(self, packet, cache_dir):
        facts_json = json.dumps(packet.project_facts, sort_keys=True)
        self.assertNotIn(cache_dir, facts_json)
        self.assertNotIn("cbm_cache_dir", packet.project_facts["workspace"])
        self.assertNotIn(cache_dir, packet.to_markdown())
        self.assertEqual(
            packet.diagnostics["local"]["cbm_cache_dir"], cache_dir
        )
        self.assertEqual(
            packet.project_facts["workspace"]["cbm_project_name"], SLUG
        )
        parsed = json.loads(packet.to_json())
        self.assertNotIn("cbm_cache_dir", parsed["project_facts"]["workspace"])
        self.assertEqual(
            parsed["diagnostics"]["local"]["cbm_cache_dir"], cache_dir
        )

    def test_windows_absolute_cache_dir(self):
        packet = self.build_with_cache_dir(r"C:\Users\u\cbm")
        self.assert_portable(packet, "C:\\Users\\u\\cbm")

    def test_posix_absolute_cache_dir(self):
        packet = self.build_with_cache_dir("/home/u/.cache/cbm")
        self.assert_portable(packet, "/home/u/.cache/cbm")

    def test_windows_unc_cache_dir(self):
        packet = self.build_with_cache_dir(r"\\server\share\cbm")
        self.assert_portable(packet, r"\\server\share\cbm")

    def test_relative_cache_dir_stays_in_project_facts(self):
        packet = self.build_with_cache_dir("relative/cbm")
        self.assertEqual(
            packet.project_facts["workspace"]["cbm_cache_dir"],
            "relative/cbm",
        )
        self.assertNotIn("local", packet.diagnostics)


class PortableLocalDiagnosticsTests(unittest.TestCase):
    """Portable output strips the machine-local diagnostics channel so
    absolute repository roots or infrastructure paths never leave the
    local machine."""

    def packet_with_local_root(self, root):
        return ContextPacket(
            packet_id=compute_packet_id(project_id=PID, mode="project"),
            created_at=FIXED_NOW,
            mode="project",
            project_id=PID,
            diagnostics={
                "local": {"git_repository_root": root},
                "counts": {"memories": 0},
            },
        )

    def _assert_portable_strips_root(self, root):
        packet = self.packet_with_local_root(root)
        portable = packet.to_portable_dict()
        portable_json = packet.to_portable_json()
        # Default serialization keeps the channel for local tooling.
        self.assertIn("local", packet.to_dict()["diagnostics"])
        self.assertEqual(packet.diagnostics["local"]["git_repository_root"], root)
        # Portable serialization drops it.
        self.assertNotIn("local", portable.get("diagnostics", {}))
        self.assertNotIn(root, portable_json)
        self.assertNotIn("git_repository_root", portable_json)

    def test_portable_json_strips_windows_root(self):
        self._assert_portable_strips_root(r"C:\Users\dev\relinkra")

    def test_portable_json_strips_posix_root(self):
        self._assert_portable_strips_root("/home/dev/relinkra")

    def test_portable_json_strips_unc_root(self):
        self._assert_portable_strips_root(r"\\server\share\relinkra")

    def test_portable_json_without_local_diagnostics_is_identical(self):
        packet = ContextPacket(
            packet_id=compute_packet_id(project_id=PID, mode="project"),
            created_at=FIXED_NOW,
            mode="project",
            project_id=PID,
            diagnostics={"counts": {"memories": 0}},
        )
        self.assertEqual(packet.to_dict(), packet.to_portable_dict())
        self.assertEqual(packet.to_json(), packet.to_portable_json())

    def test_portable_dict_strips_local_nested_under_composition(self):
        """Budget composition may nest the original diagnostics; portable
        output must strip ``local`` at every level."""
        packet = ContextPacket(
            packet_id=compute_packet_id(project_id=PID, mode="project"),
            created_at=FIXED_NOW,
            mode="project",
            project_id=PID,
            diagnostics={
                "composition": {
                    "local": {"git_repository_root": "/home/dev/relinkra"},
                    "budget": {"status": "ok"},
                },
                "counts": {"memories": 0},
            },
        )
        portable = packet.to_portable_dict()
        self.assertNotIn("local", portable.get("diagnostics", {}))
        self.assertNotIn(
            "local", portable["diagnostics"].get("composition", {})
        )
        self.assertNotIn("/home/dev/relinkra", packet.to_portable_json())
        self.assertEqual(
            portable["diagnostics"]["composition"]["budget"],
            {"status": "ok"},
        )


class GitPacketTests(unittest.TestCase):
    """rlkctx2 optional git_facts section (R2 Git Intelligence, B3)."""

    def git_item(self, kind="repository_state", **data):
        payload = {"kind": kind}
        payload.update(data)
        return PacketItem(
            data=payload,
            provenance=Provenance(source="git", why_included="git fixture"),
        )

    def make_packet(self, *, packet_version=PACKET_VERSION, git_facts=()):
        return ContextPacket(
            packet_id=compute_packet_id(project_id=PID, mode="project"),
            created_at=FIXED_NOW,
            mode="project",
            project_id=PID,
            packet_version=packet_version,
            git_facts=list(git_facts),
        )

    def test_version_constants(self):
        self.assertEqual(PACKET_VERSION, "rlkctx2")
        self.assertEqual(PACKET_VERSION_V1, "rlkctx1")
        self.assertEqual(ACCEPTED_PACKET_VERSIONS, ("rlkctx1", "rlkctx2"))
        self.assertIn("git", SOURCES)

    def test_rlkctx2_to_dict_emits_git_facts(self):
        packet = self.make_packet(
            git_facts=[self.git_item(head_sha="a" * 40, branch="main")]
        )
        raw = packet.to_dict()
        self.assertEqual(raw["packet_version"], "rlkctx2")
        self.assertEqual(len(raw["git_facts"]), 1)
        entry = raw["git_facts"][0]
        self.assertEqual(entry["data"]["kind"], "repository_state")
        self.assertEqual(entry["data"]["branch"], "main")
        self.assertEqual(entry["provenance"]["source"], "git")

    def test_rlkctx1_to_dict_omits_git_facts_key(self):
        # Even when git facts are attached, an rlkctx1 packet never
        # serializes the section (byte-compatible git-off output).
        packet = self.make_packet(
            packet_version=PACKET_VERSION_V1,
            git_facts=[self.git_item()],
        )
        self.assertNotIn("git_facts", packet.to_dict())

    def test_rlkctx2_without_facts_emits_empty_section(self):
        packet = self.make_packet()
        self.assertEqual(packet.to_dict()["git_facts"], [])

    def test_from_dict_accepts_rlkctx1_missing_section(self):
        packet = self.make_packet(packet_version=PACKET_VERSION_V1)
        clone = ContextPacket.from_dict(packet.to_dict())
        self.assertEqual(clone.packet_version, "rlkctx1")
        self.assertEqual(clone.git_facts, [])
        self.assertEqual(clone.to_dict(), packet.to_dict())

    def test_from_dict_rlkctx2_round_trip(self):
        packet = self.make_packet(
            git_facts=[
                self.git_item(),
                self.git_item("co_change", path="src/b.py",
                              shared_commit_count=3),
            ]
        )
        clone = ContextPacket.from_dict(packet.to_dict())
        self.assertEqual(clone.to_dict(), packet.to_dict())
        kinds = [item.data["kind"] for item in clone.git_facts]
        self.assertEqual(kinds, ["repository_state", "co_change"])

    def test_from_dict_rejects_unknown_version(self):
        raw = self.make_packet().to_dict()
        raw["packet_version"] = "rlkctx3"
        with self.assertRaises(PacketValidationError):
            ContextPacket.from_dict(raw)


class ContextCliGitFlagTests(unittest.TestCase):
    """context_cli --git / --git-history-limit (R2 Git Intelligence, B4 4.2)."""

    def setUp(self):
        self.env = Env()
        self.addCleanup(self.env.cleanup)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = gf.make_repo(os.path.join(self.tmp.name, "repo"))
        gf.scenario_abcd(self.repo)

    def run_cli(self, argv, **kwargs):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = context_cli.main(argv, **kwargs)
        return code, out.getvalue(), err.getvalue()

    def base_argv(self):
        return [
            "--project-id", self.env.project_id,
            "--registry", self.env.registry_path,
        ]

    def test_git_flag_emits_rlkctx2_with_git_facts(self):
        code, out, err = self.run_cli(
            self.base_argv() + ["--workspace-root", self.repo, "--git"],
            store=self.env.store, clock=fixed_clock,
        )
        self.assertEqual(code, 0, err)
        packet = json.loads(out)
        self.assertEqual(packet["packet_version"], PACKET_VERSION)
        kinds = [item["data"]["kind"] for item in packet["git_facts"]]
        self.assertIn("repository_state", kinds)
        self.assertIn("head_facts", kinds)
        for item in packet["git_facts"]:
            self.assertEqual(item["provenance"]["source"], "git")
        # absolute repo root is local-diagnostics only; it must not leak
        # into the portable JSON/Markdown emitted by the CLI.
        self.assertNotIn(self.repo, json.dumps(packet["git_facts"]))
        self.assertNotIn("git_repository_root", out)
        self.assertNotIn("local", packet.get("diagnostics", {}))

    def test_git_off_default_byte_identical(self):
        argv = self.base_argv()
        code_a, out_a, err_a = self.run_cli(
            argv, store=self.env.store, clock=fixed_clock
        )
        code_b, out_b, err_b = self.run_cli(
            argv + ["--workspace-root", self.repo],
            store=self.env.store, clock=fixed_clock,
        )
        self.assertEqual(code_a, 0, err_a)
        self.assertEqual(code_b, 0, err_b)
        packet = json.loads(out_b)
        self.assertEqual(packet["packet_version"], PACKET_VERSION_V1)
        self.assertNotIn("git_facts", packet)
        # --workspace-root alone changes nothing when --git is absent
        self.assertEqual(out_a, out_b)
        self.assertEqual(err_a, err_b)

    def test_git_history_limit_maps_to_recent_commits(self):
        argv = self.base_argv() + [
            "--workspace-root", self.repo,
            "--task", "investigate alpha",
            "--git",
        ]
        code, out, err = self.run_cli(
            argv + ["--git-history-limit", "2"],
            store=self.env.store, clock=fixed_clock,
        )
        self.assertEqual(code, 0, err)
        packet = json.loads(out)
        recent = [
            item for item in packet["git_facts"]
            if item["data"]["kind"] == "recent_commit"
        ]
        self.assertEqual(len(recent), 2)
        self.assertEqual(recent[0]["data"]["subject"], "D")

        code, out, err = self.run_cli(
            argv, store=self.env.store, clock=fixed_clock
        )
        self.assertEqual(code, 0, err)
        packet = json.loads(out)
        recent = [
            item for item in packet["git_facts"]
            if item["data"]["kind"] == "recent_commit"
        ]
        self.assertEqual(len(recent), 4)  # default 10, repo has 4 commits


if __name__ == "__main__":
    unittest.main()
