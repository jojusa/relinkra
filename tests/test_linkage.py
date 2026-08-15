"""Offline deterministic tests for R1D linkage: resolution + queries.

The CBM adapter is faked/mocked throughout; no subprocess, no network,
no real CBM index. Adapter subprocess tests mock subprocess.run.
"""

from __future__ import annotations

import json
import os
import subprocess
import unittest
from unittest import mock

from relinkra.cbm_adapter import (
    CBMAdapterError,
    CBMCLIAdapter,
    parse_cli_json,
    strip_project_slug,
)
from relinkra.code_reference import CodeReference, compute_code_reference_id
from relinkra.engram_adapter import InMemoryStore
from relinkra.linkage import (
    AMBIGUOUS,
    MISSING,
    RESOLVED,
    STALE,
    LinkageService,
    candidate_to_reference,
)
from relinkra.memory import (
    MemoryNotFoundError,
    MemoryService,
    MemoryValidationError,
)

PID = "rlk_" + "a" * 32
PID_B = "rlk_" + "b" * 32
WID_A = "ws_" + "1" * 32
WID_B = "ws_" + "2" * 32

SLUG_A = "C-Desarrollos-relinkra-.relinkra-r1a-fixture-a"
SLUG_B = "C-Desarrollos-relinkra-.relinkra-r1a-fixture-b"

REPO = {
    "kind": "remote",
    "value": "remote://git/github.com/org/repo",
    "trust": "strong",
}


def node(name, rel_qn, label, path, slug=SLUG_A, start=None, end=None):
    return {
        "name": name,
        "qualified_name": f"{slug}.{rel_qn}" if rel_qn else slug,
        "relative_qualified_name": rel_qn,
        "label": label,
        "file_path": path,
        "start_line": start,
        "end_line": end,
        "cbm_project_name": slug,
    }


class FakeCBMAdapter:
    """Duck-typed CBM adapter with canned normalized candidates."""

    def __init__(self, nodes=()):
        self.nodes = list(nodes)
        self.snippet_calls = []
        self.search_calls = []

    def get_snippet(self, qualified_name):
        self.snippet_calls.append(qualified_name)
        for n in self.nodes:
            if n["qualified_name"] == qualified_name:
                return n
        return None

    def search_symbols(self, *, query=None, qualified_name=None,
                       file_path=None, limit=50):
        self.search_calls.append(
            {"query": query, "qualified_name": qualified_name,
             "file_path": file_path}
        )
        results = self.nodes
        if query:
            q = query.lower()
            results = [
                n
                for n in results
                if q in (n["name"] or "").lower()
                or q in (n["relative_qualified_name"] or "").lower()
            ]
        if qualified_name:
            results = [
                n
                for n in results
                if n["qualified_name"] == qualified_name
                or n["relative_qualified_name"] == qualified_name
            ]
        if file_path:
            results = [n for n in results if n["file_path"] == file_path]
        return results


def make_memory_service():
    store = InMemoryStore()
    tick = {"n": 0}

    def clock():
        tick["n"] += 1
        return f"2026-01-01T00:00:{tick['n']:02d}+00:00"

    ids = {"n": 0}

    def id_gen():
        ids["n"] += 1
        return f"mem_{ids['n']:016x}"

    return MemoryService(store, clock=clock, id_generator=id_gen), store


def save_with_refs(service, refs, **kw):
    defaults = dict(
        project_id=PID,
        memory_type="decision",
        title="T",
        body="B",
        repository_identity=REPO,
        scope="project_shared",
        code_refs=refs,
    )
    defaults.update(kw)
    return service.save(**defaults)


def ref_dict(**over):
    defaults = dict(
        project_id=PID,
        reference_kind="symbol",
        file_path="src/calculator.py",
        symbol_name="add",
        qualified_name="src.calculator.add",
        symbol_kind="Function",
    )
    defaults.update(over)
    return CodeReference(**defaults).to_dict()


class TestResolution(unittest.TestCase):
    def test_exact_qualified_name_resolves(self):
        cbm = FakeCBMAdapter(
            [node("add", "src.calculator.add", "Function",
                  "src/calculator.py", start=1, end=2)]
        )
        linkage = LinkageService(make_memory_service()[0], cbm_adapter=cbm)
        stored = ref_dict(cbm_project_name=SLUG_A, start_line=1, end_line=2)
        result = linkage.resolve_reference(stored)
        self.assertEqual(result.state, RESOLVED)
        self.assertEqual(cbm.snippet_calls, [f"{SLUG_A}.src.calculator.add"])
        self.assertEqual(result.candidate["qualified_name"], "src.calculator.add")
        self.assertEqual(result.candidate["file_path"], "src/calculator.py")

    def test_unique_search_resolves(self):
        cbm = FakeCBMAdapter(
            [node("add", "src.calculator.add", "Function", "src/calculator.py")]
        )
        linkage = LinkageService(make_memory_service()[0], cbm_adapter=cbm)
        stored = ref_dict(qualified_name=None)  # short-name-only ref
        result = linkage.resolve_reference(stored)
        self.assertEqual(result.state, RESOLVED)
        self.assertEqual(cbm.snippet_calls, [])  # no exact lookup possible
        self.assertEqual(result.candidate["symbol_name"], "add")

    def test_short_name_ambiguity_returns_candidates(self):
        cbm = FakeCBMAdapter(
            [
                node("process", "module_a.process", "Function", "module_a.py"),
                node("process", "module_b.process", "Function", "module_b.py"),
            ]
        )
        linkage = LinkageService(make_memory_service()[0], cbm_adapter=cbm)
        stored = ref_dict(
            file_path="module_a.py", symbol_name="process", qualified_name=None
        )
        result = linkage.resolve_reference(stored)
        self.assertEqual(result.state, AMBIGUOUS)
        self.assertEqual(len(result.candidates), 2)
        self.assertEqual(
            sorted(c["qualified_name"] for c in result.candidates),
            ["module_a.process", "module_b.process"],
        )
        self.assertIsNone(result.candidate)
        # Historical ref is returned verbatim, never silently narrowed.
        self.assertEqual(result.reference, stored)

    def test_missing_preserves_historical_ref(self):
        cbm = FakeCBMAdapter([])  # symbol deleted from the index
        linkage = LinkageService(make_memory_service()[0], cbm_adapter=cbm)
        stored = ref_dict(cbm_project_name=SLUG_A)
        result = linkage.resolve_reference(stored)
        self.assertEqual(result.state, MISSING)
        self.assertEqual(result.reference, stored)
        self.assertIsNone(result.candidate)

    def test_stale_on_file_drift(self):
        cbm = FakeCBMAdapter(
            [node("add", "src.calculator.add", "Function",
                  "src/moved/calculator.py", start=1, end=2)]
        )
        linkage = LinkageService(make_memory_service()[0], cbm_adapter=cbm)
        stored = ref_dict(cbm_project_name=SLUG_A, start_line=1, end_line=2)
        result = linkage.resolve_reference(stored)
        self.assertEqual(result.state, STALE)
        self.assertIn("file_path drifted", result.note)
        self.assertEqual(result.reference, stored)  # history not rewritten

    def test_stale_on_line_drift(self):
        cbm = FakeCBMAdapter(
            [node("add", "src.calculator.add", "Function",
                  "src/calculator.py", start=10, end=12)]
        )
        linkage = LinkageService(make_memory_service()[0], cbm_adapter=cbm)
        stored = ref_dict(cbm_project_name=SLUG_A, start_line=1, end_line=2)
        result = linkage.resolve_reference(stored)
        self.assertEqual(result.state, STALE)
        self.assertIn("start_line drifted", result.note)

    def test_stale_when_symbol_moved_via_search_fallback(self):
        # Exact qn lookup misses (symbol moved); short-name search finds
        # exactly one candidate under a new qn -> stale, not missing.
        cbm = FakeCBMAdapter(
            [node("add", "src.calc.add", "Function", "src/calc.py")]
        )
        linkage = LinkageService(make_memory_service()[0], cbm_adapter=cbm)
        stored = ref_dict(cbm_project_name=SLUG_A)
        result = linkage.resolve_reference(stored)
        self.assertEqual(result.state, STALE)
        self.assertIn("drifted", result.note)

    def test_full_identity_match_narrows_search(self):
        # Two candidates but one matches the stored file+qn exactly.
        cbm = FakeCBMAdapter(
            [
                node("process", "module_a.process", "Function", "module_a.py"),
                node("process", "module_b.process", "Function", "module_b.py"),
            ]
        )
        linkage = LinkageService(make_memory_service()[0], cbm_adapter=cbm)
        stored = ref_dict(
            file_path="module_a.py",
            symbol_name="process",
            qualified_name="module_a.process",
            cbm_project_name=None,  # forces search path (no exact lookup)
        )
        result = linkage.resolve_reference(stored)
        self.assertEqual(result.state, RESOLVED)
        self.assertEqual(result.candidate["qualified_name"], "module_a.process")

    def test_file_ref_resolution(self):
        cbm = FakeCBMAdapter(
            [
                node("add", "src.calculator.add", "Function", "src/calculator.py"),
                node("sub", "src.calculator.sub", "Function", "src/calculator.py"),
            ]
        )
        linkage = LinkageService(make_memory_service()[0], cbm_adapter=cbm)
        stored = ref_dict(
            reference_kind="file", symbol_name=None, qualified_name=None
        )
        result = linkage.resolve_reference(stored)
        self.assertEqual(result.state, RESOLVED)
        self.assertIn("2 symbol(s)", result.note)
        missing = linkage.resolve_reference(
            ref_dict(
                reference_kind="file",
                file_path="src/absent.py",
                symbol_name=None,
                qualified_name=None,
            )
        )
        self.assertEqual(missing.state, MISSING)

    def test_no_adapter_reports_missing_with_note(self):
        linkage = LinkageService(make_memory_service()[0], cbm_adapter=None)
        result = linkage.resolve_reference(ref_dict())
        self.assertEqual(result.state, MISSING)
        self.assertIn("no CBM adapter", result.note)

    def test_adapter_errors_propagate_as_cbm_adapter_error(self):
        class BoomAdapter:
            def get_snippet(self, qn):
                raise RuntimeError("cbm exploded token=abc123")

            def search_symbols(self, **kw):
                raise RuntimeError("cbm exploded token=abc123")

        linkage = LinkageService(
            make_memory_service()[0], cbm_adapter=BoomAdapter()
        )
        with self.assertRaises(CBMAdapterError) as ctx:
            linkage.resolve_reference(ref_dict(cbm_project_name=SLUG_A))
        self.assertNotIn("abc123", str(ctx.exception))

    def test_adapter_errors_propagate_for_file_refs(self):
        class BoomAdapter:
            def get_snippet(self, qn):
                raise RuntimeError("cbm exploded")

            def search_symbols(self, **kw):
                raise RuntimeError("cbm exploded")

        linkage = LinkageService(
            make_memory_service()[0], cbm_adapter=BoomAdapter()
        )
        file_ref = ref_dict(
            reference_kind="file",
            symbol_name=None,
            qualified_name=None,
            symbol_kind=None,
        )
        with self.assertRaises(CBMAdapterError):
            linkage.resolve_reference(file_ref)

    def test_typed_adapter_error_propagates_unwrapped(self):
        class TypedBoomAdapter:
            def get_snippet(self, qn):
                raise CBMAdapterError("cbm timed out")

            def search_symbols(self, **kw):
                raise CBMAdapterError("cbm timed out")

        linkage = LinkageService(
            make_memory_service()[0], cbm_adapter=TypedBoomAdapter()
        )
        with self.assertRaises(CBMAdapterError) as ctx:
            linkage.resolve_reference(ref_dict(cbm_project_name=SLUG_A))
        self.assertIn("timed out", str(ctx.exception))

    def test_genuine_empty_result_stays_missing(self):
        linkage = LinkageService(
            make_memory_service()[0], cbm_adapter=FakeCBMAdapter()
        )
        result = linkage.resolve_reference(ref_dict(cbm_project_name=SLUG_A))
        self.assertEqual(result.state, MISSING)


class TestMemoryToCode(unittest.TestCase):
    def setUp(self):
        self.service, self.store = make_memory_service()

    def test_refs_returned_with_resolution_state(self):
        cbm = FakeCBMAdapter(
            [
                node("add", "src.calculator.add", "Function",
                     "src/calculator.py", start=1, end=2),
            ]
        )
        linkage = LinkageService(self.service, cbm_adapter=cbm)
        refs = [
            ref_dict(cbm_project_name=SLUG_A, start_line=1, end_line=2),
            ref_dict(
                file_path="module_a.py",
                symbol_name="process",
                qualified_name="module_a.process",
                cbm_project_name=SLUG_A,
            ),
        ]
        memory, _, _ = save_with_refs(self.service, refs)
        out = linkage.memory_to_code(
            project_id=PID, memory_id=memory.memory_id
        )
        self.assertEqual(out["memory"]["memory_id"], memory.memory_id)
        states = [r["state"] for r in out["references"]]
        self.assertEqual(states, [RESOLVED, MISSING])

    def test_malformed_stored_ref_is_preserved_and_marked(self):
        memory, _, _ = save_with_refs(self.service, [ref_dict()])
        memory.code_refs = [{"project_id": "not-a-project"}]
        linkage = LinkageService(self.service, cbm_adapter=FakeCBMAdapter())
        with mock.patch.object(self.service, "get", return_value=memory):
            out = linkage.memory_to_code(
                project_id=PID, memory_id=memory.memory_id
            )
        self.assertEqual(out["references"][0]["state"], MISSING)
        self.assertIn("malformed", out["references"][0]["note"])

    def test_unknown_memory_raises(self):
        linkage = LinkageService(self.service, cbm_adapter=FakeCBMAdapter())
        with self.assertRaises(MemoryNotFoundError):
            linkage.memory_to_code(project_id=PID, memory_id="mem_nope")


class TestCodeToMemory(unittest.TestCase):
    def setUp(self):
        self.service, self.store = make_memory_service()
        self.linkage = LinkageService(self.service)  # no adapter needed
        self.calc_ref = ref_dict()
        self.proc_ref = ref_dict(
            file_path="module_a.py",
            symbol_name="process",
            qualified_name="module_a.process",
        )

    def test_match_by_reference_id(self):
        memory, _, _ = save_with_refs(self.service, [self.calc_ref])
        save_with_refs(self.service, [self.proc_ref], title="Other", body="O")
        matches = self.linkage.code_to_memory(
            project_id=PID, reference=self.calc_ref
        )
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["memory"]["memory_id"], memory.memory_id)
        self.assertEqual(matches[0]["matched_refs"], [self.calc_ref])

    def test_match_by_file_only_link(self):
        file_ref = ref_dict(
            reference_kind="file", symbol_name=None, qualified_name=None
        )
        save_with_refs(self.service, [file_ref])
        matches = self.linkage.code_to_memory(
            project_id=PID, file_path="src/calculator.py"
        )
        self.assertEqual(len(matches), 1)
        backslash = self.linkage.code_to_memory(
            project_id=PID, file_path=r"src\calculator.py"
        )
        self.assertEqual(len(backslash), 1)

    def test_match_by_short_symbol_name(self):
        save_with_refs(self.service, [self.proc_ref])
        matches = self.linkage.code_to_memory(project_id=PID, symbol="process")
        self.assertEqual(len(matches), 1)
        self.assertEqual(
            matches[0]["matched_refs"][0]["qualified_name"], "module_a.process"
        )
        self.assertEqual(
            self.linkage.code_to_memory(project_id=PID, symbol="absent"), []
        )

    def test_symbol_and_file_combine_as_and(self):
        save_with_refs(self.service, [self.proc_ref])
        self.assertEqual(
            self.linkage.code_to_memory(
                project_id=PID, file_path="module_a.py", symbol="process"
            ),
            self.linkage.code_to_memory(project_id=PID, symbol="process"),
        )
        self.assertEqual(
            self.linkage.code_to_memory(
                project_id=PID, file_path="module_b.py", symbol="process"
            ),
            [],
        )

    def test_requires_a_target(self):
        with self.assertRaises(MemoryValidationError):
            self.linkage.code_to_memory(project_id=PID)

    def test_scope_policy_enforced(self):
        save_with_refs(self.service, [self.calc_ref], title="Shared", body="s")
        save_with_refs(
            self.service,
            [self.calc_ref],
            title="WS1",
            body="w1",
            scope="workspace_local",
            workspace_id=WID_A,
        )
        save_with_refs(
            self.service,
            [self.calc_ref],
            title="WS2",
            body="w2",
            scope="workspace_local",
            workspace_id=WID_B,
        )
        save_with_refs(
            self.service,
            [self.calc_ref],
            title="OC",
            body="p",
            scope="agent_private",
            agent_type="opencode",
        )

        def titles(matches):
            return sorted(m["memory"]["title"] for m in matches)

        self.assertEqual(
            titles(self.linkage.code_to_memory(
                project_id=PID, file_path="src/calculator.py"
            )),
            ["Shared"],
        )
        self.assertEqual(
            titles(self.linkage.code_to_memory(
                project_id=PID,
                file_path="src/calculator.py",
                scope="workspace_local",
                workspace_id=WID_A,
            )),
            ["Shared", "WS1"],
        )
        self.assertEqual(
            titles(self.linkage.code_to_memory(
                project_id=PID,
                file_path="src/calculator.py",
                scope="agent_private",
                agent_type="opencode",
            )),
            ["OC"],
        )
        self.assertEqual(
            titles(self.linkage.code_to_memory(
                project_id=PID,
                file_path="src/calculator.py",
                scope="agent_private",
                agent_type="codex",
            )),
            [],
        )

    def test_superseded_excluded_by_default(self):
        first, _, _ = save_with_refs(
            self.service, [self.calc_ref], title="Plan", body="v1"
        )
        save_with_refs(self.service, [self.calc_ref], title="Plan", body="v2")
        matches = self.linkage.code_to_memory(
            project_id=PID, file_path="src/calculator.py"
        )
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["memory"]["body"], "v2")
        history = self.linkage.code_to_memory(
            project_id=PID,
            file_path="src/calculator.py",
            include_history=True,
        )
        self.assertEqual(len(history), 2)
        self.assertIn(
            first.memory_id, {m["memory"]["memory_id"] for m in history}
        )

    def test_cross_project_isolation(self):
        save_with_refs(self.service, [self.calc_ref])
        save_with_refs(
            self.service,
            [ref_dict(project_id=PID_B)],
            project_id=PID_B,
            title="Other",
            body="o",
        )
        matches = self.linkage.code_to_memory(
            project_id=PID_B, file_path="src/calculator.py"
        )
        self.assertEqual([m["memory"]["title"] for m in matches], ["Other"])
        matches_a = self.linkage.code_to_memory(
            project_id=PID, file_path="src/calculator.py"
        )
        self.assertEqual(len(matches_a), 1)
        with self.assertRaises(MemoryValidationError):
            self.linkage.code_to_memory(
                project_id=PID, reference=ref_dict(project_id=PID_B)
            )


class TestCandidateConversion(unittest.TestCase):
    def test_candidate_to_reference_strips_slug_and_derives_language(self):
        candidate = node(
            "add", "src.calculator.add", "Function", "src/calculator.py",
            start=1, end=2,
        )
        ref = candidate_to_reference(candidate, project_id=PID)
        self.assertEqual(ref.qualified_name, "src.calculator.add")
        self.assertEqual(ref.language, "python")
        self.assertEqual(ref.symbol_kind, "Function")
        self.assertEqual(ref.cbm_project_name, SLUG_A)

    def test_strip_project_slug(self):
        self.assertEqual(
            strip_project_slug(f"{SLUG_A}.src.calc.add", SLUG_A), "src.calc.add"
        )
        self.assertEqual(strip_project_slug("src.calc.add", SLUG_A), "src.calc.add")
        self.assertEqual(strip_project_slug("src.calc.add", ""), "src.calc.add")


class FakeCompleted:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


SEARCH_STDOUT = (
    "level=info msg=mem.init budget_mb=24198 total_ram_mb=48397\n"
    '{"total":1,"search_mode":"bm25","results":[{"name":"add",'
    f'"qualified_name":"{SLUG_A}.src.calculator.add","label":"Function",'
    '"file_path":"src/calculator.py","in_degree":5,"out_degree":0}],'
    '"has_more":false}\n'
)

SNIPPET_STDOUT = (
    "level=info msg=mem.init budget_mb=24198 total_ram_mb=48397\n"
    '{"name":"add",'
    f'"qualified_name":"{SLUG_A}.src.calculator.add","label":"Function",'
    '"file_path":"C:/work/ws-a/src/calculator.py","start_line":1,'
    '"end_line":2,"source":"def add(a, b):\\n    return a + b\\n"}\n'
)


class TestCBMCLIAdapter(unittest.TestCase):
    def make_adapter(self, **kw):
        defaults = dict(
            cbm_bin="cbm.exe",
            cache_dir=r"C:\cache\cbm",
            cbm_project_name=SLUG_A,
            workspace_root=r"C:\work\ws-a",
        )
        defaults.update(kw)
        return CBMCLIAdapter(**defaults)

    def test_parse_cli_json_tolerates_log_lines(self):
        payload = parse_cli_json(SEARCH_STDOUT)
        self.assertEqual(payload["total"], 1)
        with self.assertRaises(CBMAdapterError):
            parse_cli_json("level=info only logs\nno json here")

    def test_search_invocation_shape_and_env(self):
        adapter = self.make_adapter()
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=FakeCompleted(stdout=SEARCH_STDOUT),
        ) as run:
            candidates = adapter.search_symbols(query="add")
        argv = run.call_args[0][0]
        self.assertIsInstance(argv, list)  # argv list, never a shell string
        self.assertEqual(argv[:3], ["cbm.exe", "cli", "search_graph"])
        self.assertIn("--project", argv)
        self.assertIn(SLUG_A, argv)
        self.assertIn("--query", argv)
        self.assertIn("add", argv)
        kwargs = run.call_args[1]
        self.assertEqual(kwargs["env"]["CBM_CACHE_DIR"], r"C:\cache\cbm")
        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["encoding"], "utf-8")
        self.assertGreater(kwargs["timeout"], 0)
        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertEqual(candidate["relative_qualified_name"], "src.calculator.add")
        self.assertEqual(candidate["cbm_project_name"], SLUG_A)
        self.assertNotIn("source", candidate)

    def test_search_file_pattern_is_passed_verbatim(self):
        adapter = self.make_adapter()
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=FakeCompleted(stdout=SEARCH_STDOUT),
        ) as run:
            adapter.search_symbols(file_path="src/cal.py")
        argv = run.call_args[0][0]
        idx = argv.index("--file-pattern")
        # CBM treats --file-pattern as a path filter, not a regex.
        self.assertEqual(argv[idx + 1], "src/cal.py")

    def test_snippet_normalizes_absolute_path_and_drops_source(self):
        adapter = self.make_adapter()
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=FakeCompleted(stdout=SNIPPET_STDOUT),
        ):
            candidate = adapter.get_snippet(f"{SLUG_A}.src.calculator.add")
        self.assertEqual(candidate["file_path"], "src/calculator.py")
        self.assertEqual(candidate["start_line"], 1)
        self.assertNotIn("source", candidate)
        ref = adapter.to_code_reference(candidate, project_id=PID)
        self.assertEqual(ref.qualified_name, "src.calculator.add")
        self.assertEqual(ref.language, "python")

    def test_snippet_error_payload_returns_none(self):
        adapter = self.make_adapter()
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=FakeCompleted(stdout='{"error":"symbol not found"}'),
        ):
            self.assertIsNone(adapter.get_snippet(f"{SLUG_A}.gone"))

    def test_non_repo_nodes_filtered(self):
        stdout = (
            '{"results":['
            f'{{"name":"{SLUG_A}","qualified_name":"{SLUG_A}","label":"Project","file_path":"{{}}"}},'
            '{"name":"append","qualified_name":"builtins.list.append",'
            '"label":"Method","file_path":"<python-builtins>"},'
            f'{{"name":"add","qualified_name":"{SLUG_A}.src.calculator.add",'
            '"label":"Function","file_path":"src/calculator.py"}]}'
        )
        adapter = self.make_adapter()
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=FakeCompleted(stdout=stdout),
        ):
            candidates = adapter.search_symbols(query="x")
        self.assertEqual([c["name"] for c in candidates], ["add"])

    def test_nonzero_exit_raises_sanitized(self):
        adapter = self.make_adapter()
        secret = "hunter2"
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=FakeCompleted(
                stderr=f"boom https://u:{secret}@h/x token={secret}",
                returncode=1,
            ),
        ):
            with self.assertRaises(CBMAdapterError) as ctx:
                adapter.search_symbols(query="x")
        self.assertNotIn(secret, str(ctx.exception))

    def test_missing_binary_and_timeout(self):
        adapter = self.make_adapter(cbm_bin="cbm-does-not-exist-xyz")
        with self.assertRaises(CBMAdapterError):
            adapter.search_symbols(query="x")
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="cbm", timeout=1),
        ):
            with self.assertRaises(CBMAdapterError):
                self.make_adapter().search_symbols(query="x")

    def test_requires_binary_and_project(self):
        with self.assertRaises(CBMAdapterError):
            CBMCLIAdapter(cbm_bin="")
        adapter = self.make_adapter(cbm_project_name=None)
        with self.assertRaises(CBMAdapterError):
            adapter.search_symbols(query="x")

    def test_per_call_project_normalization_matches_default(self):
        default_adapter = self.make_adapter()  # default cbm_project_name
        per_call_adapter = self.make_adapter(cbm_project_name=None)
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=FakeCompleted(stdout=SEARCH_STDOUT),
        ):
            from_default = default_adapter.search_symbols(query="add")
            from_per_call = per_call_adapter.search_symbols(
                query="add", project=SLUG_A
            )
        self.assertEqual(
            from_per_call[0]["relative_qualified_name"], "src.calculator.add"
        )
        self.assertEqual(from_per_call[0]["cbm_project_name"], SLUG_A)
        ref_default = default_adapter.to_code_reference(
            from_default[0], project_id=PID
        )
        ref_per_call = per_call_adapter.to_code_reference(
            from_per_call[0], project_id=PID
        )
        self.assertEqual(
            ref_default.code_reference_id, ref_per_call.code_reference_id
        )
        self.assertEqual(ref_per_call.qualified_name, "src.calculator.add")
        self.assertNotIn(SLUG_A, ref_per_call.qualified_name)
        # The CBM slug never participates in the hashed identity.
        self.assertEqual(
            ref_per_call.code_reference_id,
            compute_code_reference_id(
                PID, "symbol", "src/calculator.py", "src.calculator.add"
            ),
        )

    def test_per_call_project_snippet_normalization(self):
        adapter = self.make_adapter(cbm_project_name=None)
        with mock.patch(
            "relinkra.cbm_adapter.subprocess.run",
            return_value=FakeCompleted(stdout=SNIPPET_STDOUT),
        ) as run:
            candidate = adapter.get_snippet(
                f"{SLUG_A}.src.calculator.add", project=SLUG_A
            )
        argv = run.call_args[0][0]
        self.assertIn(SLUG_A, argv)
        self.assertEqual(candidate["file_path"], "src/calculator.py")
        self.assertEqual(
            candidate["relative_qualified_name"], "src.calculator.add"
        )
        self.assertEqual(candidate["cbm_project_name"], SLUG_A)
        ref = adapter.to_code_reference(candidate, project_id=PID)
        self.assertEqual(ref.qualified_name, "src.calculator.add")
        self.assertEqual(ref.cbm_project_name, SLUG_A)
        self.assertEqual(
            ref.code_reference_id,
            compute_code_reference_id(
                PID, "symbol", "src/calculator.py", "src.calculator.add"
            ),
        )

    def test_code_evidence_authority_projects_only_graph_head_and_trust(self):
        adapter = self.make_adapter()
        head = "a" * 40
        with mock.patch.object(
            adapter,
            "index_status",
            return_value={
                "root_path": r"C:\work\ws-a",
                "git": {"head_sha": head},
                "credentials": {"token": "secret"},
                "host_config": {"host": "private.internal"},
            },
        ), mock.patch.object(
            adapter, "graph_index_head", return_value=head
        ), mock.patch.object(
            adapter,
            "detect_changes",
            return_value={"changed_count": 0, "changed_files": []},
        ), mock.patch("relinkra.cbm_adapter.git_head_sha", return_value=head):
            authority = adapter.code_evidence_authority()
        self.assertEqual(authority["index_status"], {"git": {"head_sha": head}})
        self.assertEqual(authority["trust_stages"][0]["name"], "CBM graph")
        self.assertEqual(authority["trust_stages"][0]["status"], "PASS")
        rendered = json.dumps(authority, sort_keys=True)
        self.assertNotIn("root_path", rendered)
        self.assertNotIn("secret", rendered)
        self.assertNotIn("private.internal", rendered)

    def test_code_evidence_authority_warns_when_graph_cannot_be_attested(self):
        adapter = self.make_adapter()
        head = "a" * 40
        with mock.patch.object(
            adapter,
            "index_status",
            return_value={
                "root_path": r"D:\other\repo",
                "git": {"head_sha": head},
            },
        ), mock.patch.object(adapter, "graph_index_head") as stored, mock.patch(
            "relinkra.cbm_adapter.git_head_sha"
        ) as git_head:
            authority = adapter.code_evidence_authority()
        self.assertEqual(
            authority["trust_stages"],
            [{"name": "CBM graph", "status": "WARN", "detail": "the indexed graph belongs to a different workspace root"}],
        )
        stored.assert_not_called()
        git_head.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows normcase semantics")
    def test_windows_drive_casing_relativized(self):
        adapter = self.make_adapter(workspace_root=r"C:\work\ws-a")
        self.assertEqual(
            adapter._normalize_file_path(r"c:\work\ws-a\src\calculator.py"),
            "src/calculator.py",
        )
        self.assertEqual(
            adapter._normalize_file_path("c:/WORK/WS-A/src/calculator.py"),
            "src/calculator.py",
        )

    def test_relative_workspace_root_is_absolutized(self):
        rel = os.path.join("tmp", "ws-a")
        adapter = self.make_adapter(workspace_root=rel)
        expected_root = os.path.abspath(rel).replace("\\", "/").rstrip("/")
        self.assertEqual(adapter.workspace_root, expected_root)
        self.assertEqual(
            adapter._normalize_file_path(expected_root + "/src/calculator.py"),
            "src/calculator.py",
        )

    def test_case_insensitive_relativization_portable(self):
        # Simulate Windows normcase on any platform: differing drive and
        # directory casing must still relativize against workspace_root.
        adapter = self.make_adapter(workspace_root="C:/work/ws-a")
        with mock.patch("os.path.normcase", lambda p: p.lower()):
            self.assertEqual(
                adapter._normalize_file_path("c:/Work/WS-A/src/calculator.py"),
                "src/calculator.py",
            )
            self.assertEqual(
                adapter._normalize_file_path(r"c:\work\ws-a\src\calc.py"),
                "src/calc.py",
            )
        # A genuinely different root must stay absolute (rejected later).
        self.assertEqual(
            adapter._normalize_file_path("D:/other/src/calculator.py"),
            "D:/other/src/calculator.py",
        )


class TestInvalidCandidateSurfacing(unittest.TestCase):
    def test_invalid_candidates_surfaced_not_silently_missing(self):
        cbm = FakeCBMAdapter(
            [node("add", "src.calculator.add", "Function", "/outside/root.py")]
        )
        linkage = LinkageService(make_memory_service()[0], cbm_adapter=cbm)
        stored = ref_dict(cbm_project_name=SLUG_A)
        result = linkage.resolve_reference(stored)
        self.assertEqual(result.state, MISSING)
        self.assertEqual(len(result.invalid_candidates), 1)
        self.assertIn("invalid candidate", result.note)
        payload = result.to_dict()
        self.assertEqual(
            payload["invalid_candidates"][0]["file_path"], "/outside/root.py"
        )
        self.assertTrue(payload["invalid_candidates"][0]["error"])
        # Historical ref is still preserved verbatim.
        self.assertEqual(result.reference, stored)

    def test_invalid_candidates_surfaced_alongside_valid(self):
        cbm = FakeCBMAdapter(
            [
                node("process", "module_a.process", "Function", "module_a.py"),
                node(
                    "process",
                    "module_b.process",
                    "Function",
                    "C:/elsewhere/module_b.py",
                ),
            ]
        )
        linkage = LinkageService(make_memory_service()[0], cbm_adapter=cbm)
        stored = ref_dict(
            file_path="module_a.py", symbol_name="process", qualified_name=None
        )
        result = linkage.resolve_reference(stored)
        self.assertEqual(result.state, RESOLVED)
        self.assertEqual(len(result.invalid_candidates), 1)
        self.assertIn("invalid candidate", result.note)
        self.assertEqual(
            result.invalid_candidates[0]["file_path"],
            "C:/elsewhere/module_b.py",
        )

    def test_valid_only_resolution_has_no_invalid_candidates(self):
        cbm = FakeCBMAdapter(
            [node("add", "src.calculator.add", "Function",
                  "src/calculator.py", start=1, end=2)]
        )
        linkage = LinkageService(make_memory_service()[0], cbm_adapter=cbm)
        stored = ref_dict(cbm_project_name=SLUG_A, start_line=1, end_line=2)
        result = linkage.resolve_reference(stored)
        self.assertEqual(result.state, RESOLVED)
        self.assertEqual(result.invalid_candidates, [])
        self.assertNotIn("invalid", result.note)


if __name__ == "__main__":
    unittest.main()
