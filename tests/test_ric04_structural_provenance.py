"""RIC-04 — structural code evidence is bound to the effective project.

Permanent regression for the Daybreak finding: a service bound to project
A's code backend must never return that backend's structural evidence
labeled with a caller-selected project B. Caller-supplied ``project_id``
values are requests, not provenance; the verified effective project of the
bound workspace owns the evidence identity.

The tests drive the real MCP wire (``MCPServer.handle_line``) and the real
service methods, using temporary git repositories registered through the
production registry path and one fake adapter that physically serves
project A. Expected project ids are always derived from the registry, never
from the response under test.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from relinkra.app_service import RelinkraServices, ServiceConfig
from relinkra.cbm import workspace_cbm_record
from relinkra.effective_identity import (
    IDENTITY_STATE_MIGRATION_AVAILABLE,
    resolve_effective_identity,
)
from relinkra.engram_adapter import InMemoryStore
from relinkra.identity import derive_project_id, discover_repository_identity
from relinkra.mcp_server import MCPServer
from relinkra.registry import Registry

try:
    from tests import git_fixtures as gf
except ImportError:  # pragma: no cover - discover vs module invocation
    import git_fixtures as gf

from test_mcp_server import RecordingGitService

REMOTE_A = "https://github.com/org/ric04-repo-a.git"
REMOTE_B = "https://github.com/org/ric04-repo-b.git"
REMOTE_DRIFT = "https://github.com/org/ric04-drift.git"

FIXED_NOW = "2026-02-01T00:00:00+00:00"

#: The CBM path-derived slug recorded for the bound workspace, and the
#: qualified name the fake adapter physically serves.
SLUG_A = "C-Desarrollos-ric04-repo-a"
TARGET = f"{SLUG_A}.src.service.Target.run"

WARN_UNVERIFIED = "project_binding_unverified"


class ProjectAAdapter:
    """One startup-bound adapter physically serving project A's index."""

    def __init__(self, slug=SLUG_A):
        self.cbm_project_name = slug
        self.calls = []

    def code_evidence_authority(self):
        self.calls.append("code_evidence_authority")
        return {
            "index_status": {"git": {"head_sha": "a" * 40}},
            "trust_stages": [{"name": "CBM graph", "status": "PASS"}],
        }

    def architecture_orientation(self, **kwargs):
        self.calls.append(("architecture_orientation", kwargs))
        # The real adapter normalizes evidence to project-relative
        # qualified names; the fake mirrors that contract.
        return {
            "total_nodes": 3,
            "total_edges": 2,
            "hotspots": [
                {"name": "run", "qualified_name": "src.service.Target.run", "fan_in": 1}
            ],
        }

    def search_symbols(self, **kwargs):
        self.calls.append(("search_symbols", kwargs))
        return [
            {
                "name": "Target",
                "qualified_name": TARGET,
                "relative_qualified_name": "src.service.Target.run",
                "label": "Method",
                "file_path": "src/service.py",
                "start_line": 1,
                "end_line": 2,
                "cbm_project_name": SLUG_A,
            }
        ]

    def get_snippet(self, qualified_name, **kwargs):
        self.calls.append(("get_snippet", qualified_name))
        return None

    def trace_relationships(self, **kwargs):
        self.calls.append(("trace_relationships", kwargs))
        return {
            "target": "src.service.Target.run",
            "direction": kwargs.get("direction", "inbound"),
            "max_hops": kwargs.get("max_hops", 2),
            "relationships": [
                {
                    "name": "Caller",
                    "qualified_name": "src.caller.Caller.run",
                    "relationship": "caller",
                    "hop": 1,
                }
            ],
            "coverage": {
                "complete": False,
                "qualification": "does not prove that none exist",
            },
        }

    def queried(self, operation: str) -> bool:
        return any(
            isinstance(call, tuple) and call[0] == operation
            for call in self.calls
        )


def _build_repo(base: str, name: str, remote: str) -> str:
    repo = gf.make_repo(os.path.join(base, name))
    gf.commit_file(repo, "README.md", f"# {name}\n", "init")
    gf.git(repo, "remote", "add", "origin", remote)
    return repo


class StructuralProvenanceCase(unittest.TestCase):
    """Server bound to repo-a; project B is registered but not bound."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = self.tmp.name
        self.repo_a = _build_repo(base, "ric04-repo-a", REMOTE_A)
        self.repo_b = _build_repo(base, "ric04-repo-b", REMOTE_B)
        self.registry_path = os.path.join(base, "registry.json")
        registry = Registry(self.registry_path)
        ws_a = registry.register_workspace(
            self.repo_a,
            discover_repository_identity(self.repo_a),
            cbm=workspace_cbm_record(
                SLUG_A, os.path.join(base, "cbm-a")
            ).to_dict(),
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
        self.adapter = ProjectAAdapter()
        self.services = self._services_for(self.repo_a)
        self.server = MCPServer(self.services)

    def _services_for(
        self,
        workspace_root,
        *,
        registry="default",
        registry_path=None,
        adapter="default",
        cbm=True,
    ) -> RelinkraServices:
        return RelinkraServices(
            config=ServiceConfig(
                workspace_root=workspace_root,
                registry_path=(
                    registry_path
                    if registry_path is not None
                    else self.registry_path
                ),
            ),
            store=InMemoryStore(),
            cbm_adapter=(
                self.adapter
                if adapter == "default"
                else adapter
            ) if cbm else None,
            registry=self.registry if registry == "default" else registry,
            git_service=RecordingGitService(),
            clock=lambda: FIXED_NOW,
        )

    # -- wire helpers -----------------------------------------------------

    def call_raw(self, name: str, arguments: dict, server=None):
        line = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 11,
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
        return result["structuredContent"]["error"]


class ImplicitAndExplicitBindingTests(StructuralProvenanceCase):
    """A/B/F/G/H/I/L — one bound project: query it implicitly or explicitly."""

    def test_a_implicit_architecture_uses_effective_project(self):
        self.adapter.calls.clear()
        payload = self.ok("code_architecture")
        self.assertEqual(payload["project_id"], self.project_id_a)
        self.assertTrue(self.adapter.queried("architecture_orientation"))
        self.assertTrue(payload["available"])

    def test_b_explicit_effective_project_is_accepted(self):
        payload = self.ok("code_architecture", project_id=self.project_id_a)
        self.assertEqual(payload["project_id"], self.project_id_a)
        self.assertTrue(payload["available"])

    def test_f_code_resolve_reference_binds_effective_project(self):
        payload = self.ok(
            "code_resolve",
            project_id=self.project_id_a,
            symbol="Target",
        )
        self.assertEqual(payload["project_id"], self.project_id_a)
        refs = payload.get("code_references") or []
        self.assertTrue(refs)
        self.assertEqual(
            refs[0]["data"]["reference"]["project_id"], self.project_id_a
        )
        self.assertNotEqual(
            refs[0]["data"]["reference"]["project_id"], self.project_id_b
        )

    def test_g_context_packet_structural_fact_binds_effective_project(self):
        payload = self.ok(
            "context_get",
            project_id=self.project_id_a,
            task="architecture overview",
        )
        facts = payload["packet"]["code_facts"]
        structural = [
            fact
            for fact in facts
            if (fact.get("data") or {}).get("evidence_kind")
            == "architecture_fact"
        ]
        self.assertTrue(structural, "no structural fact was produced")
        for fact in structural:
            self.assertEqual(fact["data"]["project_id"], self.project_id_a)

    def test_h_architecture_evidence_binds_effective_project(self):
        self.adapter.calls.clear()
        payload = self.ok(
            "code_architecture",
            project_id=self.project_id_a,
            path="src",
        )
        self.assertEqual(payload["project_id"], self.project_id_a)
        self.assertTrue(payload["available"])
        self.assertEqual(
            payload["evidence"]["hotspots"][0]["qualified_name"],
            "src.service.Target.run",
        )
        rendered = json.dumps(payload)
        self.assertNotIn(SLUG_A, rendered)

    def test_i_relationships_evidence_binds_effective_project(self):
        self.adapter.calls.clear()
        payload = self.ok(
            "code_relationships",
            project_id=self.project_id_a,
            symbol="src.service.Target.run",
            direction="inbound",
        )
        self.assertEqual(payload["project_id"], self.project_id_a)
        self.assertTrue(payload["available"])
        self.assertTrue(self.adapter.queried("trace_relationships"))
        self.assertEqual(
            payload["evidence"]["relationships"][0]["relationship"], "caller"
        )

    def test_l_single_project_happy_path_is_unchanged(self):
        # Auto-resolution, explicit id, and the full structural triad keep
        # working for the one bound project.
        self.assertEqual(
            self.ok("code_architecture")["project_id"], self.project_id_a
        )
        self.assertEqual(
            self.ok(
                "code_relationships",
                symbol="src.service.Target.run",
            )["project_id"],
            self.project_id_a,
        )
        self.assertEqual(
            self.ok("code_resolve", symbol="Target")["project_id"],
            self.project_id_a,
        )
        packet = self.ok("context_get", task="probe")["packet"]
        self.assertEqual(packet["project_id"], self.project_id_a)
        # Memory scoping by an explicit foreign registered id remains the
        # documented intentional behavior; only CBM evidence is bound.
        memories = self.ok(
            "memory_search", project_id=self.project_id_b, query="probe"
        )
        self.assertEqual(memories["project_id"], self.project_id_b)


class ForeignProjectRejectionTests(StructuralProvenanceCase):
    """C/D/F/G/H/I — a bound adapter never relabels its evidence as B."""

    def test_c_explicit_foreign_architecture_is_rejected(self):
        self.adapter.calls.clear()
        error = self.err("code_architecture", project_id=self.project_id_b)
        self.assertEqual(error["code"], "project_mismatch")
        self.assertIn(self.project_id_b, error["message"])
        self.assertIn(self.project_id_a, error["message"])
        self.assertFalse(self.adapter.queried("architecture_orientation"))

    def test_c_explicit_foreign_relationships_is_rejected(self):
        self.adapter.calls.clear()
        error = self.err(
            "code_relationships",
            project_id=self.project_id_b,
            symbol="src.service.Target.run",
        )
        self.assertEqual(error["code"], "project_mismatch")
        self.assertFalse(self.adapter.queried("trace_relationships"))

    def test_f_explicit_foreign_code_resolve_is_rejected(self):
        self.adapter.calls.clear()
        error = self.err(
            "code_resolve", project_id=self.project_id_b, symbol="Target"
        )
        self.assertEqual(error["code"], "project_mismatch")
        self.assertFalse(self.adapter.queried("search_symbols"))

    def test_explicit_foreign_context_get_is_rejected(self):
        error = self.err(
            "context_get",
            project_id=self.project_id_b,
            task="architecture overview",
        )
        self.assertEqual(error["code"], "project_mismatch")
        self.assertIn(self.project_id_a, error["message"])

    def test_direct_service_call_foreign_project_is_rejected(self):
        from relinkra.app_service import ServiceError

        with self.assertRaises(ServiceError) as ctx:
            self.services.code_architecture(project_id=self.project_id_b)
        self.assertEqual(ctx.exception.code, "project_mismatch")

    def test_no_response_can_claim_foreign_structural_evidence(self):
        # Every code-bearing route answers with a typed rejection and no
        # evidence payload; the foreign label may only appear inside the
        # diagnostic message that explains the mismatch.
        for tool, arguments in (
            ("code_architecture", {}),
            ("code_relationships", {"symbol": "src.service.Target.run"}),
            ("code_resolve", {"symbol": "Target"}),
            ("context_get", {"task": "architecture overview"}),
        ):
            result = self.call_raw(
                tool, {"project_id": self.project_id_b, **arguments}
            )
            self.assertTrue(result["isError"], tool)
            self.assertEqual(
                result["structuredContent"]["error"]["code"],
                "project_mismatch",
                tool,
            )
            body = json.dumps(result["structuredContent"])
            for marker in ("code_references", "code_facts", "evidence_kind"):
                self.assertNotIn(marker, body, f"{tool} carried {marker}")


class MigrationCandidateTests(StructuralProvenanceCase):
    """D/E — the registered identity stays authoritative under drift."""

    def setUp(self):
        super().setUp()
        self.repo_d = gf.make_repo(os.path.join(self.tmp.name, "ric04-drift"))
        gf.commit_file(self.repo_d, "README.md", "# drift\n", "init")
        registry = Registry(self.registry_path)
        ws_d = registry.register_workspace(
            self.repo_d, discover_repository_identity(self.repo_d)
        )
        # The remote appears afterwards: the live derivation drifts.
        gf.git(self.repo_d, "remote", "add", "origin", REMOTE_DRIFT)
        self.registry = Registry(self.registry_path)
        self.project_id_d = ws_d.project_id
        self.workspace_id_d = ws_d.workspace_id
        self.live_project_id_d = derive_project_id(
            discover_repository_identity(self.repo_d).value
        )
        self.adapter = ProjectAAdapter()
        self.services = self._services_for(self.repo_d)
        self.server = MCPServer(self.services)
        identity = resolve_effective_identity(
            self.repo_d, registry=self.registry
        )
        self.assertEqual(
            identity.identity_state, IDENTITY_STATE_MIGRATION_AVAILABLE
        )
        self.assertNotEqual(self.live_project_id_d, self.project_id_d)

    def test_e_migration_available_keeps_registered_identity(self):
        payload = self.ok("code_architecture")
        self.assertEqual(payload["project_id"], self.project_id_d)
        self.assertNotEqual(payload["project_id"], self.live_project_id_d)

    def test_d_live_candidate_is_rejected_as_authority(self):
        error = self.err(
            "code_architecture", project_id=self.live_project_id_d
        )
        self.assertEqual(error["code"], "project_mismatch")
        self.assertIn(self.live_project_id_d, error["message"])
        self.assertIn(self.project_id_d, error["message"])
        self.assertIn("candidate", error["message"])

    def test_explicit_registered_identity_is_accepted_under_drift(self):
        payload = self.ok(
            "code_architecture", project_id=self.project_id_d
        )
        self.assertEqual(payload["project_id"], self.project_id_d)


class BindingUnavailableTests(StructuralProvenanceCase):
    """F/J/K — no verifiable binding: disclose, never fabricate."""

    def test_j_unverified_binding_discloses_instead_of_claiming(self):
        services = RelinkraServices(
            config=ServiceConfig(
                workspace_root=self.repo_a,
                registry_path=os.path.join(
                    self.tmp.name, "no-such-registry.json"
                ),
            ),
            store=InMemoryStore(),
            cbm_adapter=ProjectAAdapter(),
            git_service=RecordingGitService(),
            clock=lambda: FIXED_NOW,
        )
        server = MCPServer(services)
        result = self.call_raw(
            "code_architecture",
            {"project_id": self.project_id_a},
            server=server,
        )
        self.assertFalse(result["isError"])
        body = result["structuredContent"]
        codes = [warning["code"] for warning in body["warnings"]]
        self.assertIn(WARN_UNVERIFIED, codes)
        # The evidence label is the requested one and is explicitly
        # disclosed as unverified rather than presented as attestation.
        self.assertEqual(body["project_id"], self.project_id_a)

    def test_j_packet_with_cbm_evidence_discloses_unverified_binding(self):
        services = RelinkraServices(
            config=ServiceConfig(
                workspace_root=self.repo_a,
                registry_path=os.path.join(
                    self.tmp.name, "no-such-registry.json"
                ),
            ),
            store=InMemoryStore(),
            cbm_adapter=ProjectAAdapter(),
            git_service=RecordingGitService(),
            clock=lambda: FIXED_NOW,
        )
        server = MCPServer(services)
        result = self.call_raw(
            "context_get",
            {
                "project_id": self.project_id_a,
                "task": "architecture overview",
            },
            server=server,
        )
        self.assertFalse(result["isError"])
        packet = result["structuredContent"]["packet"]
        codes = [warning["code"] for warning in packet["warnings"]]
        self.assertIn(WARN_UNVERIFIED, codes)

    def test_j_adapter_not_bound_to_recorded_index_is_rejected(self):
        foreign = ProjectAAdapter(slug="C-Desarrollos-some-other-index")
        services = self._services_for(self.repo_a, adapter=foreign)
        server = MCPServer(services)
        result = self.call_raw(
            "code_architecture",
            {"project_id": self.project_id_a},
            server=server,
        )
        self.assertTrue(result["isError"])
        self.assertEqual(
            result["structuredContent"]["error"]["code"], "project_mismatch"
        )

    def test_k_unregistered_workspace_fails_closed(self):
        repo_c = _build_repo(self.tmp.name, "ric04-repo-c", REMOTE_B)
        services = self._services_for(
            repo_c,
            registry_path=self.registry_path,
        )
        # Implicit resolution keeps the existing fail-closed contract: an
        # unregistered workspace never auto-resolves another project.
        with self.assertRaises(Exception) as ctx:
            services.code_architecture()
        self.assertEqual(ctx.exception.code, "not_found")  # type: ignore[attr-defined]
        # An explicit id cannot be verified either; the response discloses
        # that the label is unverified instead of attributing evidence.
        payload = services.code_architecture(project_id=self.project_id_a)
        codes = [warning["code"] for warning in payload["warnings"]]
        self.assertIn(WARN_UNVERIFIED, codes)

    def test_configured_default_foreign_project_is_rejected(self):
        # A server configured with --project-id B while bound to project A's
        # workspace must not relabel A's evidence as B.
        services = RelinkraServices(
            config=ServiceConfig(
                workspace_root=self.repo_a,
                registry_path=self.registry_path,
                default_project_id=self.project_id_b,
            ),
            store=InMemoryStore(),
            cbm_adapter=ProjectAAdapter(),
            registry=self.registry,
            git_service=RecordingGitService(),
            clock=lambda: FIXED_NOW,
        )
        server = MCPServer(services)
        result = self.call_raw("code_architecture", {}, server=server)
        self.assertTrue(result["isError"])
        self.assertEqual(
            result["structuredContent"]["error"]["code"], "project_mismatch"
        )

    def test_copied_registration_fails_closed_for_structural_evidence(self):
        # A record that fails integrity re-derivation is never an
        # attestation: the structural surfaces fail closed rather than
        # attribute evidence to a registration that cannot be trusted.
        self.services.registry.workspaces[
            self.workspace_id_a
        ].workspace_id = "ws_" + "e" * 32
        error = self.err("code_architecture", project_id=self.project_id_a)
        self.assertEqual(error["code"], "not_found")
        self.assertIn("integrity", error["message"])

    def test_malformed_project_id_is_rejected_when_binding_verified(self):
        error = self.err("code_architecture", project_id="not-a-project")
        self.assertEqual(error["code"], "project_mismatch")
        self.assertIn("not-a-project", error["message"])

    def test_f_absent_adapter_keeps_degraded_contract(self):
        services = self._services_for(self.repo_a, cbm=False)
        payload = services.code_architecture(
            project_id=self.project_id_a
        )
        self.assertEqual(payload["project_id"], self.project_id_a)
        self.assertFalse(payload["available"])
        self.assertIsNone(payload["evidence"])


class ExactRic04RegressionTests(StructuralProvenanceCase):
    """Section-16 regression: the historical primitive is closed.

    This is the exact Daybreak flow: an A-bound adapter, a caller-selected
    registered project B, and every structural route on the real MCP wire.
    On BASE every route returned A's evidence labeled B; after the fix every
    route is a typed rejection and the foreign label never appears.
    """

    def test_historical_reproduction_is_closed_on_every_route(self):
        for tool, arguments in (
            ("code_architecture", {}),
            ("code_relationships", {"symbol": "src.service.Target.run"}),
            ("code_resolve", {"symbol": "Target"}),
            ("context_get", {"task": "architecture overview"}),
        ):
            self.adapter.calls.clear()
            result = self.call_raw(
                tool, {"project_id": self.project_id_b, **arguments}
            )
            self.assertTrue(
                result["isError"],
                f"{tool} returned evidence for a foreign project",
            )
            error = result["structuredContent"]["error"]
            self.assertEqual(error["code"], "project_mismatch")
            # The rejection names the mismatch but returns no evidence:
            # A's data can never be presented under B's label.
            self.assertIn(self.project_id_b, error["message"])
            self.assertIn(self.project_id_a, error["message"])
            self.assertNotIn("evidence_kind", json.dumps(result["structuredContent"]))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
