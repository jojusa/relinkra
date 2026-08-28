"""R5I.2A — project auto-resolution when ``project_id`` is omitted.

Pins the fix for the measured R5I.1 adoption friction: agents naturally
call ``context_get`` / ``memory_search`` / ``code_architecture`` without
``project_id`` and the 0.1.0 surface answered every such call with a
typed-but-unrecoverable error, which MCP hosts render as empty output.

The contract under test:

- omitted ``project_id`` + valid bound workspace -> deterministic
  auto-resolution from the bound workspace context;
- explicit ``project_id`` -> honored verbatim, never replaced;
- unresolvable or ambiguous workspace -> fail-closed typed error whose
  message names the remedy (never an empty or opaque failure);
- auto-resolution can never leak another project's identity.

Identity discovery runs REAL git against temporary repositories through
the same production path ``relinkra connect`` registers with; the MCP
wire is exercised through ``MCPServer.handle_line`` with an in-memory
store, a duck-typed git service, and a frozen clock.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import unittest
from copy import copy

from relinkra.app_service import RelinkraServices, ServiceConfig
from relinkra.engram_adapter import InMemoryStore
from relinkra.identity import (
    LogicalProject,
    discover_repository_identity,
)
from relinkra.mcp_server import TOOLS, MCPServer
from relinkra.registry import Registry

try:
    from tests import git_fixtures as gf
except ImportError:  # pragma: no cover - discover vs module invocation
    import git_fixtures as gf

from test_mcp_server import RecordingGitService

REMOTE_A = "https://github.com/org/repo-a.git"
REMOTE_B = "https://github.com/org/repo-b.git"
REMOTE_C = "https://github.com/org/repo-c.git"

FIXED_NOW = "2026-02-01T00:00:00+00:00"

#: A well-formed but unregistered project id (test C).
PID_UNREGISTERED = "rlk_" + "f" * 32


def build_repo(base: str, name: str, remote: str) -> str:
    repo = gf.make_repo(os.path.join(base, name))
    gf.commit_file(repo, "README.md", f"# {name}\n", "init")
    gf.git(repo, "remote", "add", "origin", remote)
    return repo


class WorkspaceCase(unittest.TestCase):
    """Two registered repos; the server is bound to repo-a.

    Mirrors the canonical connector launch exactly: workspace root +
    registry are configured, but NO default_project_id exists.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = self.tmp.name
        self.repo_a = build_repo(base, "repo-a", REMOTE_A)
        self.repo_b = build_repo(base, "repo-b", REMOTE_B)
        self.registry_path = os.path.join(base, "registry.json")
        registry = Registry(self.registry_path)
        ws_a = registry.register_workspace(
            self.repo_a, discover_repository_identity(self.repo_a)
        )
        registry.register_workspace(
            self.repo_b, discover_repository_identity(self.repo_b)
        )
        # Reload from disk so services see only persisted state.
        self.registry = Registry(self.registry_path)
        self.project_id_a = ws_a.project_id
        self.workspace_id_a = ws_a.workspace_id
        self.project_id_b = next(
            pid for pid in self.registry.projects if pid != self.project_id_a
        )
        self.services = self._services_for(workspace_root=self.repo_a)
        self.server = MCPServer(self.services)

    def _services_for(
        self,
        *,
        workspace_root=None,
        registry="default",
        registry_path=None,
        store=None,
    ) -> RelinkraServices:
        return RelinkraServices(
            config=ServiceConfig(
                workspace_root=workspace_root,
                registry_path=(
                    registry_path
                    if registry_path is not None
                    else self.registry_path
                ),
                # No default_project_id: the canonical connector shape.
            ),
            store=store if store is not None else InMemoryStore(),
            registry=self.registry if registry == "default" else registry,
            git_service=RecordingGitService(),
            clock=lambda: FIXED_NOW,
        )

    # -- helpers ----------------------------------------------------------

    def seed_memory(self, project_id: str, title: str):
        identity = self.registry.projects[project_id].repository_identity.to_dict()
        memory, _, _ = self.services.memories.save(
            project_id=project_id,
            repository_identity=identity,
            memory_type="decision",
            title=title,
            body="b",
        )
        return memory

    def call_raw(self, name: str, arguments: dict, server=None):
        """One full wire round-trip through a raw JSON line."""
        line = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )
        response = (server or self.server).handle_line(line)
        self.assertIsNotNone(response)
        return response["result"]

    def ok(self, name: str, **arguments):
        result = self.call_raw(name, arguments)
        self.assertFalse(
            result["isError"],
            f"{name} failed: {result['content'][0]['text']}",
        )
        return result["structuredContent"]

    def err(self, name: str, **arguments):
        result = self.call_raw(name, arguments)
        self.assertTrue(result["isError"], f"{name} unexpectedly succeeded")
        # The empty-error regression: the text content itself must carry
        # the actionable diagnostic, not just structuredContent.
        self.assertGreater(
            len(result["content"][0]["text"]),
            40,
            "error text must be non-trivially actionable",
        )
        return result["structuredContent"]["error"]


class PublicSurfaceTests(unittest.TestCase):
    """G/H — tool count and namespace hygiene stay frozen."""

    def test_public_tool_count_is_eleven(self):
        self.assertEqual(len(TOOLS), 11)

    def test_no_tool_name_double_prefixes_the_server_namespace(self):
        for tool in TOOLS:
            self.assertRegex(tool["name"], re.compile(r"^[a-zA-Z0-9_-]{1,64}$"))
            self.assertFalse(
                tool["name"].startswith("relinkra_"),
                f"{tool['name']} would double-prefix under host namespacing",
            )

    def test_project_id_schema_documents_auto_resolution(self):
        description = next(
            t for t in TOOLS if t["name"] == "context_get"
        )["inputSchema"]["properties"]["project_id"]["description"]
        self.assertIn("auto", description.lower())


class AutoResolutionTests(WorkspaceCase):
    """A — omitted project_id over a valid bound workspace resolves."""

    def test_project_resolve_auto_resolves_exact_canonical_workspace(self):
        payload = self.ok("project_resolve")
        self.assertEqual(payload["project_id"], self.project_id_a)
        self.assertEqual(payload["workspace_id"], self.workspace_id_a)
        self.assertEqual(
            payload["workspace"]["workspace_id"], self.workspace_id_a
        )

    def test_r5i1_shape_no_project_id_context_get_auto_resolves(self):
        payload = self.ok("context_get", task="probe")
        self.assertEqual(payload["packet"]["project_id"], self.project_id_a)

    def test_r5i1_shape_memory_search_scopes_to_bound_workspace(self):
        self.seed_memory(self.project_id_a, "Auto resolution probe")
        payload = self.ok("memory_search", query="Auto resolution probe")
        self.assertEqual(payload["project_id"], self.project_id_a)
        titles = [m["title"] for m in payload["memories"]]
        self.assertIn("Auto resolution probe", titles)

    def test_r5i1_shape_no_args_code_architecture_executes(self):
        payload = self.ok("code_architecture")
        self.assertEqual(payload["project_id"], self.project_id_a)
        self.assertIn("freshness", payload)

    def test_no_project_id_git_context_labels_resolved_project(self):
        payload = self.ok("git_context")
        self.assertEqual(payload["project_id"], self.project_id_a)

    def test_no_project_id_handoff_get_lists_resolved_project(self):
        payload = self.ok("handoff_get")
        self.assertEqual(payload["project_id"], self.project_id_a)

    def test_configured_default_wins_over_auto_resolution(self):
        services = RelinkraServices(
            config=ServiceConfig(
                workspace_root=self.repo_a,
                registry_path=self.registry_path,
                default_project_id=self.project_id_b,
            ),
            store=InMemoryStore(),
            registry=self.registry,
            git_service=RecordingGitService(),
            clock=lambda: FIXED_NOW,
        )
        server = MCPServer(services)
        result = self.call_raw("context_get", {"task": "probe"}, server=server)
        self.assertFalse(result["isError"])
        packet = result["structuredContent"]["packet"]
        self.assertEqual(packet["project_id"], self.project_id_b)


class ExplicitProjectIdTests(WorkspaceCase):
    """B/C — explicit ids keep their exact pre-auto-resolution semantics."""

    def test_explicit_valid_project_id_is_honored(self):
        self.seed_memory(self.project_id_b, "Explicit probe")
        payload = self.ok(
            "memory_search",
            project_id=self.project_id_b,
            query="Explicit probe",
        )
        self.assertEqual(payload["project_id"], self.project_id_b)
        titles = [m["title"] for m in payload["memories"]]
        self.assertIn("Explicit probe", titles)

    def test_explicit_unregistered_project_id_is_not_replaced(self):
        error = self.err(
            "memory_save",
            project_id=PID_UNREGISTERED,
            memory_type="decision",
            title="t",
            body="b",
        )
        self.assertEqual(error["code"], "not_found")
        self.assertIn(PID_UNREGISTERED, error["message"])

    def test_explicit_other_registered_project_is_not_swapped(self):
        """An explicit id scopes to THAT project, never the bound one."""
        payload = self.ok(
            "memory_search", project_id=self.project_id_b, query="anything"
        )
        self.assertEqual(payload["project_id"], self.project_id_b)
        self.assertNotEqual(payload["project_id"], self.project_id_a)


class FailClosedTests(WorkspaceCase):
    """D/E — unresolved or ambiguous workspaces fail closed, actionably."""

    def test_unregistered_workspace_structured_error(self):
        repo_c = build_repo(self.tmp.name, "repo-c", REMOTE_C)
        stale_path = os.path.join(self.tmp.name, "stale.json")
        stale_registry = Registry(stale_path)
        stale_registry.register_workspace(
            self.repo_b, discover_repository_identity(self.repo_b)
        )
        services = self._services_for(
            workspace_root=repo_c,
            registry=stale_registry,
            registry_path=stale_path,
        )
        result = self.call_raw("memory_search", {"query": "probe"}, server=MCPServer(services))
        self.assertTrue(result["isError"])
        text = result["content"][0]["text"]
        self.assertIn("auto-resolve", text)
        self.assertIn("project_resolve", text)
        self.assertNotIn(self.project_id_b, text)
        error = result["structuredContent"]["error"]
        self.assertEqual(error["code"], "not_found")

    def test_ambiguous_identity_fails_closed_without_guessing(self):
        clone = LogicalProject(
            project_id=PID_UNREGISTERED,
            display_name="degenerate duplicate",
            repository_identity=self.registry.projects[
                self.project_id_a
            ].repository_identity,
            created_at=FIXED_NOW,
        )
        self.services.registry.projects[clone.project_id] = clone
        error = self.err("context_get", task="probe")
        self.assertEqual(error["code"], "not_found")
        self.assertIn("2 registered projects", error["message"])
        self.assertNotIn(self.project_id_a, error["message"])
        self.assertNotIn(PID_UNREGISTERED, error["message"])

    def test_ambiguous_canonical_workspace_fails_closed(self):
        duplicate = copy(self.registry.workspaces[self.workspace_id_a])
        duplicate.workspace_id = "ws_" + "e" * 32
        self.services.registry.workspaces[duplicate.workspace_id] = duplicate
        error = self.err("project_resolve")
        self.assertEqual(error["code"], "not_found")
        self.assertIn("multiple registered workspaces", error["message"])

    def test_missing_workspace_root_fails_closed_actionably(self):
        services = self._services_for(workspace_root=None)
        with self.assertRaises(Exception) as ctx:
            services.memory_search(query="x")
        self.assertEqual(ctx.exception.code, "not_found")  # type: ignore[attr-defined]
        self.assertIn("--workspace-root", str(ctx.exception))

    def test_corrupt_registry_fails_closed_with_detail(self):
        bad_path = os.path.join(self.tmp.name, "bad-registry.json")
        with open(bad_path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        services = self._services_for(
            workspace_root=self.repo_a, registry=None, registry_path=bad_path
        )
        with self.assertRaises(Exception) as ctx:
            services.memory_search(query="x")
        self.assertEqual(ctx.exception.code, "not_found")  # type: ignore[attr-defined]
        self.assertIn("registry is unavailable", str(ctx.exception))

    def test_non_git_workspace_fails_closed_with_reason(self):
        plain_dir = os.path.join(self.tmp.name, "plain")
        os.makedirs(plain_dir, exist_ok=True)
        empty_path = os.path.join(self.tmp.name, "empty.json")
        empty_registry = Registry(empty_path)  # exists but has no projects
        services = self._services_for(
            workspace_root=plain_dir,
            registry=empty_registry,
            registry_path=empty_path,
        )
        with self.assertRaises(Exception) as ctx:
            services.memory_search(query="x")
        self.assertEqual(ctx.exception.code, "not_found")  # type: ignore[attr-defined]
        self.assertIn("discovery failed", str(ctx.exception))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
