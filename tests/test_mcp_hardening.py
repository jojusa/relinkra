"""R3.2 production-hardening regression tests for the MCP surface.

Offline and deterministic. Covers the areas R3 left unproven for
long-running real-agent usage: JSON-RPC contract edges, recovery after a
component comes back, concurrent handoff idempotency, reachability of
handoffs past one store page, a systematic portable-wire audit of all
nine tools, and capability honesty.

Live process lifecycle (disconnect, EOF, broken pipe, restart) is proven
against real subprocesses in test_mcp_proof.py.

Relationship to test_mcp_server.py: that file proves the R3 surface
exists and behaves; this one sweeps the edges a long-lived host will hit.
Where the two touch the same rule, this file parametrises it across many
values (every id type, every bad `jsonrpc` value, every non-object
params shape) while the R3 file asserts the single representative case.
The overlap on those representative values is deliberate — dropping them
here would leave arbitrary holes in the sweeps.
"""

from __future__ import annotations

import json
import os
import threading
import time
import unittest

from relinkra.app_service import (
    RelinkraServices,
    ServiceConfig,
    ServiceError,
    ServiceWarning,
    sanitize_wire_text,
)
from relinkra.handoff import (
    HANDOFF_VERSION,
    HandoffService,
    contains_absolute_path,
)
from relinkra.mcp_server import (
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    TOOLS,
    MCPServer,
)
from relinkra.memory import STORE_PAGE_LIMIT, MemoryStoreError
from test_context_packet import FIXED_NOW, Env
from test_mcp_server import RecordingGitService


class FlipStore:
    """An in-memory store whose availability can be toggled at runtime.

    Wraps the real InMemoryStore so that "recovered" genuinely means the
    same data is readable again, not that a fresh empty store appeared.
    """

    def __init__(self, inner, available=True):
        self.inner = inner
        self.available = available
        self.calls = 0

    def _guard(self):
        self.calls += 1
        if not self.available:
            raise MemoryStoreError("engram executable not found: engram")

    def save_record(self, **kwargs):
        self._guard()
        return self.inner.save_record(**kwargs)

    def search_records(self, **kwargs):
        self._guard()
        return self.inner.search_records(**kwargs)


class HardeningTestCase(unittest.TestCase):
    """A live in-process MCP server over a registered project."""

    workspace_root = None

    def setUp(self):
        self.env = Env(seed=True)
        self.addCleanup(self.env.cleanup)
        self.git = RecordingGitService()
        self.store = FlipStore(self.env.store)
        self.services = RelinkraServices(
            config=ServiceConfig(
                registry_path=self.env.registry_path,
                default_project_id=self.env.project_id,
                default_workspace_id=self.env.workspace_id,
                workspace_root=self.workspace_root,
            ),
            store=self.store,
            registry=self.env.registry,
            git_service=self.git,
            clock=lambda: FIXED_NOW,
        )
        self.server = MCPServer(self.services)

    def rpc(self, message):
        return self.server.handle_message(message)

    def call(self, name, **arguments):
        return self.rpc(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )["result"]

    def ok(self, name, **arguments):
        result = self.call(name, **arguments)
        self.assertFalse(
            result["isError"], result["content"][0]["text"]
        )
        return result["structuredContent"]


class JsonRpcContractTests(HardeningTestCase):
    """Edges a long-running host will eventually exercise."""

    def test_request_id_is_preserved_verbatim(self):
        for message_id in (1, 0, -7, "abc", "id-with-dash", 2**53):
            response = self.rpc(
                {"jsonrpc": "2.0", "id": message_id, "method": "ping"}
            )
            self.assertEqual(response["id"], message_id)
            self.assertIsInstance(
                response["id"], type(message_id), f"id type changed: {message_id!r}"
            )

    def test_explicit_null_id_is_a_request_not_a_notification(self):
        """`"id": null` is present, so it must be answered."""
        response = self.rpc({"jsonrpc": "2.0", "id": None, "method": "ping"})
        self.assertIsNotNone(response)
        self.assertIsNone(response["id"])
        self.assertEqual(response["result"], {})

    def test_absent_id_is_a_notification(self):
        self.assertIsNone(self.rpc({"jsonrpc": "2.0", "method": "ping"}))

    def test_notification_of_unknown_method_is_silent(self):
        self.assertIsNone(
            self.rpc({"jsonrpc": "2.0", "method": "totally/unknown"})
        )

    def test_duplicate_request_ids_are_each_answered(self):
        """The server is stateless per message; it must not dedupe ids."""
        first = self.rpc({"jsonrpc": "2.0", "id": 42, "method": "ping"})
        second = self.rpc({"jsonrpc": "2.0", "id": 42, "method": "ping"})
        self.assertEqual(first, second)
        self.assertEqual(second["id"], 42)

    def test_unknown_method_is_a_protocol_error(self):
        response = self.rpc(
            {"jsonrpc": "2.0", "id": 5, "method": "tools/destroy"}
        )
        self.assertEqual(response["error"]["code"], METHOD_NOT_FOUND)
        self.assertNotIn("result", response)

    def test_wrong_jsonrpc_version_is_rejected(self):
        for version in ("1.0", 2.0, None, ""):
            response = self.server.handle_line(
                json.dumps({"jsonrpc": version, "id": 1, "method": "ping"})
            )
            self.assertEqual(response["error"]["code"], INVALID_REQUEST)

    def test_malformed_params_are_rejected(self):
        for params in ([1, 2], "string", 7, True):
            response = self.server.handle_line(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "ping",
                        "params": params,
                    }
                )
            )
            self.assertEqual(response["error"]["code"], INVALID_PARAMS)

    def test_tool_failure_is_a_result_not_a_protocol_error(self):
        """Structured tool errors and protocol errors are different."""
        response = self.rpc(
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {
                    "name": "relinkra_handoff_get",
                    "arguments": {"handoff_id": "hof_" + "0" * 32},
                },
            }
        )
        self.assertIn("result", response)
        self.assertNotIn("error", response)
        self.assertTrue(response["result"]["isError"])
        self.assertEqual(
            response["result"]["structuredContent"]["error"]["code"],
            "not_found",
        )

    def test_bad_arguments_are_a_protocol_error(self):
        response = self.rpc(
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {
                    "name": "relinkra_handoff_get",
                    "arguments": {"nope": 1},
                },
            }
        )
        self.assertIn("error", response)
        self.assertNotIn("result", response)

    def test_serialization_is_deterministic(self):
        first = self.server.handle_line(
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        )
        second = self.server.handle_line(
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_one_bad_request_does_not_corrupt_the_next(self):
        self.server.handle_line("{not json")
        self.rpc({"jsonrpc": "2.0", "id": 1, "method": "no/such"})
        self.rpc(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "relinkra_health", "arguments": {"x": 1}},
            }
        )
        # Still healthy afterwards.
        recovered = self.ok("relinkra_health")
        self.assertIn("contract_version", recovered)

    def test_parse_error_carries_null_id(self):
        response = self.server.handle_line("{{{")
        self.assertEqual(response["error"]["code"], PARSE_ERROR)
        self.assertIsNone(response["id"])


class PortableWireAuditTests(HardeningTestCase):
    """Systematically scan every tool response for machine-local leakage."""

    workspace_root = "."

    def _forbidden_values(self):
        home = os.path.expanduser("~")
        values = {
            "repository absolute path": os.path.abspath(self.env.ws_dir),
            "temp root": os.path.abspath(self.env.tmp.name),
            "home directory": home,
            "registry path": os.path.abspath(self.env.registry_path),
        }
        for env_name in ("PATH", "USERPROFILE", "HOME", "APPDATA"):
            raw = os.environ.get(env_name)
            if raw and len(raw) > 12:
                values[f"env:{env_name}"] = raw
        return {k: v for k, v in values.items() if v}

    def _all_tool_outputs(self):
        """Invoke all nine tools and return {tool_name: response}."""
        handoff = self.ok(
            "relinkra_handoff_create",
            source_agent="opencode",
            target_agent="claude",
            task="audit the wire",
            include_git_state=True,
        )["handoff"]
        self.ok(
            "relinkra_memory_save",
            memory_type="decision",
            title="audit decision",
            body="body",
        )
        outputs = {
            "relinkra_project_resolve": self.ok("relinkra_project_resolve"),
            "relinkra_context_get": self.ok(
                "relinkra_context_get", task="audit the wire"
            ),
            "relinkra_memory_search": self.ok(
                "relinkra_memory_search", limit=50
            ),
            "relinkra_memory_save": self.ok(
                "relinkra_memory_save",
                memory_type="discovery",
                title="audit discovery",
                body="body",
            ),
            "relinkra_code_resolve": self.ok(
                "relinkra_code_resolve", file="src/audit.py"
            ),
            "relinkra_git_context": self.ok("relinkra_git_context"),
            "relinkra_handoff_create": self.ok(
                "relinkra_handoff_create",
                source_agent="claude",
                task="second audit handoff",
            ),
            "relinkra_handoff_get": self.ok(
                "relinkra_handoff_get", handoff_id=handoff["handoff_id"]
            ),
            "relinkra_health": self.ok("relinkra_health"),
        }
        return outputs

    def test_every_tool_covered_by_the_audit(self):
        self.assertEqual(
            set(self._all_tool_outputs()),
            {tool["name"] for tool in TOOLS},
            "the audit must cover the whole tool surface",
        )

    def test_no_machine_local_value_reaches_the_wire(self):
        forbidden = self._forbidden_values()
        self.assertTrue(forbidden, "audit needs at least one forbidden value")
        for tool, payload in self._all_tool_outputs().items():
            blob = json.dumps(payload)
            for label, value in forbidden.items():
                self.assertNotIn(
                    value,
                    blob,
                    f"{tool} leaked {label}",
                )
                # Windows paths survive JSON as escaped backslashes too.
                self.assertNotIn(
                    value.replace("\\", "\\\\"),
                    blob,
                    f"{tool} leaked {label} (escaped form)",
                )

    def test_no_executable_or_store_path_reaches_the_wire(self):
        markers = (
            "engram.exe",
            "python.exe",
            "site-packages",
            ".engram",
            "engram.db",
            ".codebase-memory",
            "cbm-cache",
        )
        for tool, payload in self._all_tool_outputs().items():
            blob = json.dumps(payload).lower()
            for marker in markers:
                self.assertNotIn(
                    marker, blob, f"{tool} leaked path marker {marker!r}"
                )

    def test_no_credential_pattern_reaches_the_wire(self):
        secrets = (
            "sk-live-0123456789abcdef",
            "ghp_0123456789abcdefghij",
            "Bearer abcdef0123456789",
        )
        payload = self.ok(
            "relinkra_handoff_create",
            source_agent="opencode",
            task=f"rotate {secrets[1]}",
            summary=f"used {secrets[0]} and {secrets[2]}",
        )
        blob = json.dumps(payload)
        for secret in secrets:
            self.assertNotIn(secret, blob)

    def test_repo_relative_paths_and_opaque_ids_survive(self):
        """Scrubbing must not destroy the useful parts of the payload."""
        payload = self.ok("relinkra_code_resolve", file="src/audit.py")
        self.assertIn("src/audit.py", json.dumps(payload))
        resolved = self.ok("relinkra_project_resolve")
        self.assertTrue(resolved["project_id"].startswith("rlk_"))
        self.assertTrue(resolved["workspace_id"].startswith("ws_"))


class RealAdapterWireAuditTests(unittest.TestCase):
    """Audit the wire using the REAL adapters, not in-memory fakes.

    PortableWireAuditTests injects a fake store, which means the
    EngramCLIAdapter construction is skipped entirely and its error
    strings are never produced. That makes its executable/DB-path marker
    assertions unfalsifiable on their own. These tests drive the actual
    adapter failure paths, where the leak-prone strings really come from.
    """

    #: Every absolute-path shape a misconfigured binary can take. The
    #: root-relative Windows form is the one os.path.join(os.sep, ...)
    #: produces and the one a drive-letter-only detector misses.
    BOGUS_ENGRAM = "/opt/relinkra-private/bin/engram-binary"
    BOGUS_ENGRAM_WIN = "D:\\relinkra-private\\bin\\engram.exe"
    BOGUS_ENGRAM_ROOTED = "\\opt\\relinkra-private\\bin\\engram-binary"
    BOGUS_ENGRAM_UNC = "\\\\fileserver\\tools\\engram.exe"

    def setUp(self):
        self.env = Env(seed=False)
        self.addCleanup(self.env.cleanup)

    def _services(self, **overrides):
        config = dict(
            registry_path=self.env.registry_path,
            default_project_id=self.env.project_id,
            default_workspace_id=self.env.workspace_id,
        )
        config.update(overrides)
        # NOTE: no `store=` — this builds a real EngramCLIAdapter.
        return RelinkraServices(config=ServiceConfig(**config))

    def _health(self, **overrides):
        return MCPServer(self._services(**overrides)).handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "relinkra_health", "arguments": {}},
            }
        )["result"]["structuredContent"]

    def test_missing_engram_binary_path_never_reaches_the_wire(self):
        """The adapter's own error embeds the configured binary path."""
        for bogus in (
            self.BOGUS_ENGRAM,
            self.BOGUS_ENGRAM_WIN,
            self.BOGUS_ENGRAM_ROOTED,
            self.BOGUS_ENGRAM_UNC,
        ):
            health = self._health(engram_bin=bogus)
            detail = health["components"]["engram"]["detail"]
            self.assertFalse(
                health["components"]["engram"]["available"],
                "a bogus binary should probe as unavailable",
            )
            self.assertFalse(
                contains_absolute_path(detail),
                f"absolute engram path leaked: {detail!r}",
            )
            blob = json.dumps(health)
            self.assertNotIn(bogus, blob)
            self.assertNotIn(bogus.replace("\\", "\\\\"), blob)

    def test_health_detail_still_explains_the_failure(self):
        """Scrubbing must not reduce the detail to noise."""
        health = self._health(engram_bin=self.BOGUS_ENGRAM)
        detail = health["components"]["engram"]["detail"].lower()
        self.assertIn("engram", detail)
        self.assertTrue(detail.strip())

    def test_unreadable_registry_path_never_reaches_the_wire(self):
        """A RegistryError embeds the registry file path."""
        broken = os.path.join(self.env.tmp.name, "broken-registry.json")
        with open(broken, "w", encoding="utf-8") as handle:
            handle.write("{ not valid json")
        health = self._health(registry_path=broken)
        blob = json.dumps(health)
        self.assertNotIn(broken, blob)
        self.assertNotIn(broken.replace("\\", "\\\\"), blob)
        detail = health["components"]["registry"]["detail"]
        self.assertFalse(
            contains_absolute_path(detail),
            f"absolute registry path leaked: {detail!r}",
        )

    def test_typed_service_errors_are_path_scrubbed(self):
        """ServiceError messages travel to the agent verbatim."""
        error = ServiceError(
            "invalid_input",
            f"failed reading {self.BOGUS_ENGRAM_WIN} and /etc/relinkra/secrets.conf",
        )
        self.assertFalse(contains_absolute_path(error.message))
        self.assertNotIn("secrets.conf", error.message)

    def test_service_warnings_are_path_scrubbed(self):
        warning = ServiceWarning(
            "git_unavailable", f"cannot run git in {self.BOGUS_ENGRAM_WIN}"
        )
        self.assertFalse(contains_absolute_path(warning.to_dict()["message"]))

    def test_wire_sanitizer_removes_secrets_and_paths_together(self):
        cleaned = sanitize_wire_text(
            "token Bearer sk-live-0123456789abcdef at C:\\Users\\me\\keys"
        )
        self.assertNotIn("sk-live-0123456789abcdef", cleaned)
        self.assertFalse(contains_absolute_path(cleaned))


class CapabilityHonestyTests(HardeningTestCase):
    workspace_root = "."

    def test_capabilities_track_real_component_state(self):
        healthy = self.ok("relinkra_health")
        self.assertTrue(healthy["capabilities"]["memory_write"])
        self.assertTrue(healthy["capabilities"]["handoffs"])
        self.assertTrue(healthy["capabilities"]["git_intelligence"])

        self.store.available = False
        degraded = self.ok("relinkra_health")
        self.assertFalse(
            degraded["capabilities"]["handoffs"],
            "handoffs advertised while the memory store is down",
        )
        self.assertFalse(degraded["capabilities"]["memory_write"])
        # Git is independent and must stay advertised.
        self.assertTrue(degraded["capabilities"]["git_intelligence"])

    def test_advertised_handoff_capability_is_executable(self):
        """If health says handoffs work, creating one must succeed."""
        health = self.ok("relinkra_health")
        self.assertTrue(health["capabilities"]["handoffs"])
        created = self.call(
            "relinkra_handoff_create",
            source_agent="opencode",
            task="capability honesty",
        )
        self.assertFalse(created["isError"])

    def test_withdrawn_capability_matches_real_failure(self):
        self.store.available = False
        health = self.ok("relinkra_health")
        self.assertFalse(health["capabilities"]["handoffs"])
        attempted = self.call(
            "relinkra_handoff_create",
            source_agent="opencode",
            task="should fail",
        )
        self.assertTrue(attempted["isError"])

    def test_absent_component_is_a_known_negative_not_unchecked(self):
        """"Not configured" is a fact, not an unverified guess."""
        health = self.ok("relinkra_health")
        self.assertFalse(health["capabilities"]["code_resolution"])
        self.assertTrue(health["components"]["cbm"]["checked"])
        self.assertNotIn("code_resolution", health["capabilities_unchecked"])

    def test_configured_but_unprobed_component_is_named_unchecked(self):
        """A configured CBM is not advertised as callable.

        Liveness-probing the code indexer on every health call would be
        too expensive, so the capability is reported as unavailable,
        checked=False, and listed as unchecked rather than implying
        verification.
        """
        self.services.cbm_adapter = object()
        health = self.ok("relinkra_health")
        self.assertFalse(health["capabilities"]["code_resolution"])
        self.assertFalse(health["components"]["cbm"]["checked"])
        self.assertIn("code_resolution", health["capabilities_unchecked"])
        # Liveness-probed components are never listed as unchecked.
        self.assertNotIn("memory_write", health["capabilities_unchecked"])
        self.assertNotIn("git_intelligence", health["capabilities_unchecked"])

    def test_unchecked_capability_still_degrades_safely_when_called(self):
        """"Unchecked" must mean unverified, never unsafe.

        A capability advertised without a liveness probe can turn out to
        be broken at call time. That must surface as a typed tool error,
        not a crash or a leaked traceback.
        """
        self.services.cbm_adapter = object()  # configured but unusable
        result = self.call("relinkra_code_resolve", file="src/audit.py")
        payload = result["structuredContent"]
        if result["isError"]:
            self.assertIn(
                payload["error"]["code"],
                {"invalid_input", "internal_error", "unavailable"},
            )
            self.assertNotIn("Traceback", json.dumps(payload))
        else:
            self.assertIn("code_references", payload)

    def test_permanent_absences_are_not_degradations(self):
        health = self.ok("relinkra_health")
        self.assertFalse(health["capabilities"]["agent_private_access"])
        self.assertFalse(health["capabilities"]["git_write"])
        self.assertNotIn(
            "agent_private_access", health["capabilities_unchecked"]
        )


class DegradedRecoveryTests(HardeningTestCase):
    """Failure is proven in R3; here we prove RECOVERY without a restart."""

    workspace_root = "."

    def test_memory_store_recovers_in_the_same_process(self):
        self.store.available = False
        down = self.call("relinkra_memory_search")
        self.assertTrue(down["isError"])
        self.assertEqual(
            down["structuredContent"]["error"]["code"], "unavailable"
        )

        self.store.available = True
        recovered = self.ok("relinkra_memory_search", limit=50)
        self.assertGreater(recovered["count"], 0)

    def test_health_tracks_the_component_back_to_ok(self):
        self.store.available = False
        self.assertIn("engram", self.ok("relinkra_health")["degraded"])
        self.store.available = True
        self.assertNotIn("engram", self.ok("relinkra_health")["degraded"])

    def test_data_written_before_an_outage_is_still_there_after(self):
        created = self.ok(
            "relinkra_handoff_create",
            source_agent="opencode",
            task="survives an outage",
        )["handoff"]

        self.store.available = False
        self.assertTrue(self.call("relinkra_handoff_get")["isError"])

        self.store.available = True
        fetched = self.ok(
            "relinkra_handoff_get", handoff_id=created["handoff_id"]
        )["handoff"]
        self.assertEqual(fetched["handoff_id"], created["handoff_id"])

    def test_git_recovers_in_the_same_process(self):
        self.git.fail = True
        down = self.ok("relinkra_git_context")
        self.assertFalse(down["available"])
        self.assertTrue(down["warnings"])

        self.git.fail = False
        recovered = self.ok("relinkra_git_context")
        self.assertTrue(recovered["available"])
        self.assertEqual(recovered["repository_state"]["branch"], "main")

    def test_git_outage_never_blocks_memory_tools(self):
        self.git.fail = True
        self.assertFalse(self.call("relinkra_memory_search")["isError"])
        self.assertFalse(
            self.call(
                "relinkra_handoff_create",
                source_agent="opencode",
                task="git is down",
            )["isError"]
        )

    def test_recovery_needs_no_new_server_object(self):
        """The same MCPServer instance serves before, during, and after."""
        server_id = id(self.server)
        self.store.available = False
        self.call("relinkra_memory_search")
        self.store.available = True
        self.ok("relinkra_memory_search")
        self.assertEqual(id(self.server), server_id)


class WindowWideningStore:
    """Forces the unlocked check-then-act window in save() to interleave.

    ``MemoryService.save`` reads (dedup check) and then writes, with no
    lock between. Against the in-memory store that window is a handful of
    bytecodes — shorter than CPython's GIL switch interval — so racing
    threads almost never interleave and a concurrency test would pass on
    scheduling luck rather than on any proven property.

    Sleeping inside the read parks every racing thread in the check at
    once, so they all observe "no duplicate" and all proceed to write.
    That is the WORST case a real, I/O-bound store can produce, and it is
    what the invariants below are asserted against.
    """

    def __init__(self, inner, delay=0.05):
        self.inner = inner
        self.delay = delay

    def save_record(self, **kwargs):
        return self.inner.save_record(**kwargs)

    def search_records(self, **kwargs):
        records = self.inner.search_records(**kwargs)
        time.sleep(self.delay)
        return records


class HandoffConcurrencyTests(unittest.TestCase):
    """Near-simultaneous identical handoffs must stay idempotent.

    Scope, stated precisely: identity is a content hash, so it cannot
    depend on timing at all — that is proven unconditionally. Dedup
    collapsing the replays is a property of R1C's unlocked check-then-act
    and therefore holds only when the window is narrow; the widened-window
    tests below assert what survives when it is not.
    """

    def setUp(self):
        self.env = Env(seed=False)
        self.addCleanup(self.env.cleanup)
        self.repo = self.env.registry.projects[
            self.env.project_id
        ].repository_identity.to_dict()
        self._tick = 0
        self._lock = threading.Lock()

    def _clock(self):
        with self._lock:
            self._tick += 1
            return f"2026-02-01T00:00:{self._tick:02d}+00:00"

    def _race(self, agents):
        barrier = threading.Barrier(len(agents))
        results = []
        errors = []
        results_lock = threading.Lock()

        def worker(agent):
            service = HandoffService(self.env.service, clock=self._clock)
            try:
                barrier.wait(timeout=30)
                handoff, deduplicated, _ = service.create(
                    project_id=self.env.project_id,
                    source_agent=agent,
                    task="Concurrent identical handoff",
                    summary="same logical content",
                    repository_identity=self.repo,
                )
            except Exception as exc:  # surface, never swallow
                with results_lock:
                    errors.append(exc)
                return
            with results_lock:
                results.append((agent, handoff, deduplicated))

        # daemon=True so a deadlock in the code under test fails this
        # test instead of wedging the whole unittest process at exit.
        threads = [
            threading.Thread(target=worker, args=(agent,), daemon=True)
            for agent in agents
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        stuck = [thread for thread in threads if thread.is_alive()]
        self.assertEqual(stuck, [], "concurrent create deadlocked")
        self.assertEqual(errors, [], f"concurrent create raised: {errors}")
        return results

    def test_identical_concurrent_handoffs_share_one_identity(self):
        results = self._race(["opencode"] * 4)
        self.assertEqual(len(results), 4)
        ids = {handoff.handoff_id for _, handoff, _ in results}
        self.assertEqual(
            len(ids), 1, "identical content produced divergent ids"
        )

    def test_identical_concurrent_handoffs_do_not_corrupt_history(self):
        self._race(["opencode"] * 4)
        service = HandoffService(self.env.service, clock=self._clock)
        history = service.list(
            project_id=self.env.project_id, include_history=True
        )
        active = service.list(project_id=self.env.project_id)
        self.assertEqual(
            len(active), 1, "a concurrent replay forked the active view"
        )
        # Every stored record is the same logical handoff, and each one
        # parses — no torn or orphaned entries.
        self.assertEqual(
            len({h.handoff_id for h in history}),
            1,
            "history contains more than one logical handoff",
        )

    def test_concurrent_result_is_reachable_by_id(self):
        results = self._race(["opencode"] * 4)
        handoff_id = results[0][1].handoff_id
        service = HandoffService(self.env.service, clock=self._clock)
        self.assertIsNotNone(
            service.get(
                project_id=self.env.project_id, handoff_id=handoff_id
            )
        )

    def test_narrow_window_collapses_to_one_fresh_write(self):
        """With the default (narrow) window, R1C dedup collapses replays.

        This is the common case, not a guarantee: see the widened-window
        tests below for what holds when the race is genuinely open.
        """
        results = self._race(["opencode"] * 4)
        fresh = [d for _, _, d in results if not d]
        self.assertEqual(
            len(fresh), 1, f"expected one fresh write, got {len(fresh)}"
        )

    # -- widened window: the race is real, not scheduling luck ------------

    def _widen(self):
        self.env.service.store = WindowWideningStore(self.env.store)

    def test_identity_never_forks_even_when_the_race_is_open(self):
        """The property that does NOT depend on locking or timing."""
        self._widen()
        results = self._race(["opencode"] * 4)
        ids = {handoff.handoff_id for _, handoff, _ in results}
        self.assertEqual(
            len(ids),
            1,
            "content-hashed identity diverged under a real race",
        )

    def test_open_race_may_duplicate_records_but_not_corrupt_history(self):
        """Worst case is a redundant record, never a forked history."""
        self._widen()
        self._race(["opencode"] * 4)
        service = HandoffService(self.env.service, clock=self._clock)
        history = service.list(
            project_id=self.env.project_id, include_history=True
        )
        self.assertTrue(history, "the race lost every record")
        # However many physical records the open window produced, they
        # are all the SAME logical handoff and all parse cleanly.
        self.assertEqual(
            len({h.handoff_id for h in history}),
            1,
            "history forked into multiple logical handoffs",
        )
        # And the active view still resolves to a single handoff.
        active = service.list(project_id=self.env.project_id)
        self.assertEqual(len(active), 1)

    def test_open_race_result_is_still_reachable_by_id(self):
        self._widen()
        results = self._race(["opencode"] * 4)
        handoff_id = results[0][1].handoff_id
        service = HandoffService(self.env.service, clock=self._clock)
        self.assertIsNotNone(
            service.get(
                project_id=self.env.project_id, handoff_id=handoff_id
            )
        )

    def test_no_agent_identity_favoritism(self):
        """Different labels are different content, and that is all.

        The outcome must depend on handoff CONTENT, never on which agent
        label happened to race first.
        """
        results = self._race(["opencode", "claude", "codex", "windsurf"])
        ids = {agent: handoff.handoff_id for agent, handoff, _ in results}
        self.assertEqual(
            len(set(ids.values())), 4, "distinct agents collapsed to one id"
        )
        service = HandoffService(self.env.service, clock=self._clock)
        for agent, handoff_id in ids.items():
            fetched = service.get(
                project_id=self.env.project_id, handoff_id=handoff_id
            )
            self.assertIsNotNone(fetched, f"{agent} handoff was lost")
            self.assertEqual(fetched.source_agent, agent)


class HandoffStoreBoundaryTests(unittest.TestCase):
    """Old handoffs must stay reachable past one store page."""

    def setUp(self):
        self.env = Env(seed=False)
        self.addCleanup(self.env.cleanup)
        self.repo = self.env.registry.projects[
            self.env.project_id
        ].repository_identity.to_dict()
        self.service = HandoffService(self.env.service, clock=lambda: FIXED_NOW)

    def _create(self, task, **extra):
        handoff, _, _ = self.service.create(
            project_id=self.env.project_id,
            source_agent="opencode",
            task=task,
            repository_identity=self.repo,
            **extra,
        )
        return handoff

    def test_get_reaches_a_handoff_past_the_store_page(self):
        oldest = self._create("the very first handoff")
        for index in range(STORE_PAGE_LIMIT + 40):
            self._create(f"filler handoff {index}")
        found = self.service.get(
            project_id=self.env.project_id, handoff_id=oldest.handoff_id
        )
        self.assertIsNotNone(
            found, "oldest handoff fell off the store page"
        )
        self.assertEqual(found.handoff_id, oldest.handoff_id)

    def test_supersedes_validation_works_past_the_store_page(self):
        oldest = self._create("supersede me later")
        for index in range(STORE_PAGE_LIMIT + 40):
            self._create(f"filler handoff {index}")
        successor = self._create(
            "supersede me later",
            summary="the replacement",
            supersedes=oldest.handoff_id,
        )
        self.assertEqual(successor.supersedes, oldest.handoff_id)

    def test_list_is_bounded_and_deterministic(self):
        for index in range(40):
            self._create(f"listed handoff {index}")
        first = self.service.list(project_id=self.env.project_id, limit=10)
        second = self.service.list(project_id=self.env.project_id, limit=10)
        self.assertEqual(len(first), 10)
        self.assertEqual(
            [h.handoff_id for h in first], [h.handoff_id for h in second]
        )

    def test_listing_never_scans_the_whole_store_unbounded(self):
        """The store page is a hard ceiling, by design, not an accident."""
        for index in range(30):
            self._create(f"bounded handoff {index}")
        captured = {}
        original = self.env.service.store.search_records

        def spy(**kwargs):
            captured["limit"] = kwargs.get("limit")
            return original(**kwargs)

        self.env.service.store.search_records = spy
        self.addCleanup(
            setattr, self.env.service.store, "search_records", original
        )
        self.service.list(
            project_id=self.env.project_id, include_history=True
        )
        self.assertIsNotNone(captured.get("limit"))
        self.assertLessEqual(captured["limit"], STORE_PAGE_LIMIT)

    def test_handoff_query_is_narrowed_to_handoff_records(self):
        """list() must not spend its page on unrelated memory types."""
        self._create("a real handoff")
        for index in range(50):
            self.env.save(
                memory_type="discovery",
                title=f"unrelated discovery {index}",
                body="noise",
            )
        captured = {}
        original = self.env.service.store.search_records

        def spy(**kwargs):
            captured["query"] = kwargs.get("query")
            return original(**kwargs)

        self.env.service.store.search_records = spy
        self.addCleanup(
            setattr, self.env.service.store, "search_records", original
        )
        self.service.list(project_id=self.env.project_id)
        self.assertEqual(captured.get("query"), HANDOFF_VERSION)


if __name__ == "__main__":
    unittest.main()
