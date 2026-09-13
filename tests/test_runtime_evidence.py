"""R6D tests — self-observed runtime evidence and the doctor trust UX.

Two halves, matching the two halves of the feature.

RUNTIME EVIDENCE. The MCP server records minimal, bounded, host-scoped,
revision-bound evidence of what it directly observed (server start,
handshake, tools/list, successful tool calls). The tests prove the store
stays compact and honest: no failed calls recorded, no host attribution
without identity, no growth beyond the latest-evidence shape.

DOCTOR TRUST UX. Doctor consumes that evidence conservatively: only the
stages Relinkra actually watched are advanced, current-revision evidence
is distinguished from historical evidence, one host's activity never
marks another host observed, PENDING (not yet exercised) is visibly
distinct from WARN (actually degraded), the default output is compact
with ONE next action, and --verbose keeps the deep report.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from relinkra import backend_policy, connect_cli, product_cli
from relinkra.backend_policy import STAGE_HANDOFF_ROUND_TRIP, STAGE_PROVEN
from relinkra.connector_apply import launch_fingerprint
from relinkra.connectors import resolve_launch
from relinkra.connect_verification import build_proof_from_payload, record_verification
from relinkra.host_discovery import (
    SYSTEM_LINUX,
    SYSTEM_WINDOWS,
    DiscoveryEnvironment,
)
from relinkra.identity import explicit_identity
from relinkra.mcp_server import MCPServer
from relinkra.product_cli import FAIL, PASS, PENDING, WARN, main
from relinkra.registry import Registry
from relinkra.runtime_evidence import (
    EVENT_CONTEXT_GET_CALLED,
    EVENT_INITIALIZE_OBSERVED,
    EVENT_MCP_SERVER_STARTED,
    EVENT_PROJECT_RESOLVE_CALLED,
    EVENT_TOOLS_LIST_OBSERVED,
    EVENT_TOOL_INVOKED,
    HOST_UNKNOWN,
    EvidenceRecorder,
    build_evidence_recorder,
    evidence_path,
    host_evidence_path,
    load_store,
    resolve_host_id,
    runtime_stage_claims,
    summarize_runtime_evidence,
)

from test_mcp_server import RecordingGitService
from test_context_packet import FIXED_NOW, Env


def _git(repo: Path, *argv: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *argv],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _real_git_repo(base: Path) -> Path:
    """A real repository with one commit, so revisions bind evidence."""
    repo = base / "repo"
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "fixture@example.com")
    _git(repo, "config", "user.name", "Fixture")
    (repo / "README.md").write_text("fixture\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "fixture revision A")
    return repo


class EvidenceStoreTests(unittest.TestCase):
    """The store itself: bounded, honest, self-healing."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="relinkra-r6d-store-")
        self.addCleanup(self._temp.cleanup)
        self.ws = Path(self._temp.name) / "ws"
        self.ws.mkdir()
        (self.ws / ".git").mkdir()

    def test_record_writes_bounded_latest_evidence(self):
        recorder = EvidenceRecorder(str(self.ws), "codex", revision="a" * 40)
        self.assertTrue(recorder.record(EVENT_MCP_SERVER_STARTED))
        self.assertTrue(
            recorder.record(
                EVENT_INITIALIZE_OBSERVED,
                {"protocol_negotiated": "2025-06-18", "protocol_agreed": True},
            )
        )
        path = host_evidence_path(str(self.ws), "codex")
        self.assertTrue(path.startswith(str(self.ws / ".relinkra")))
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        codex = data["events"]
        self.assertEqual(data["host_id"], "codex")
        self.assertIn(EVENT_MCP_SERVER_STARTED, codex)
        self.assertEqual(codex[EVENT_MCP_SERVER_STARTED]["count"], 1)
        self.assertEqual(codex[EVENT_MCP_SERVER_STARTED]["revision"], "a" * 12)
        self.assertTrue(codex[EVENT_INITIALIZE_OBSERVED]["detail"]["protocol_agreed"])

        # Latest-evidence, not a log: a second observation updates the
        # same entry and bumps the counter instead of growing the file.
        self.assertTrue(recorder.record(EVENT_MCP_SERVER_STARTED))
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self.assertEqual(
            data["events"][EVENT_MCP_SERVER_STARTED]["count"], 2
        )
        self.assertEqual(len(data["events"]), 2)
        # Each host owns exactly one file; no shared file is written.
        self.assertFalse(
            Path(evidence_path(str(self.ws))).exists(),
            "the legacy single-file store must not be written anymore",
        )

    def test_unknown_events_and_details_are_dropped(self):
        recorder = EvidenceRecorder(str(self.ws), "codex", revision="a" * 40)
        self.assertFalse(recorder.record("prompt_text_logged"))
        self.assertTrue(
            recorder.record(
                EVENT_TOOL_INVOKED,
                {"tool": "context_get", "body": "x" * 500},
            )
        )
        data = json.loads(
            Path(host_evidence_path(str(self.ws), "codex")).read_text(
                encoding="utf-8"
            )
        )
        detail = data["events"][EVENT_TOOL_INVOKED]["detail"]
        self.assertEqual(detail["tool"], "context_get")
        self.assertLessEqual(len(detail["body"]), 128)

    def test_unidentified_launcher_lands_in_host_unknown(self):
        recorder = EvidenceRecorder(str(self.ws), "", revision="a" * 40)
        recorder.record(EVENT_MCP_SERVER_STARTED)
        data = json.loads(
            Path(host_evidence_path(str(self.ws), HOST_UNKNOWN)).read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(data["host_id"], HOST_UNKNOWN)
        self.assertFalse(
            Path(host_evidence_path(str(self.ws), "codex")).exists()
        )

    def test_unrecognized_host_id_is_not_trusted(self):
        self.assertEqual(resolve_host_id("codex"), "codex")
        self.assertEqual(resolve_host_id("CODEX"), "codex")
        self.assertEqual(resolve_host_id("not-a-host"), "")
        self.assertEqual(resolve_host_id(None), "")
        recorder = EvidenceRecorder(str(self.ws), "invented-host", revision="a" * 40)
        recorder.record(EVENT_MCP_SERVER_STARTED)
        data = json.loads(
            Path(host_evidence_path(str(self.ws), HOST_UNKNOWN)).read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(data["host_id"], HOST_UNKNOWN)
        # No file is ever named after an unvalidated host.
        self.assertFalse(
            (self.ws / ".relinkra" / "runtime-evidence" / "invented-host.json")
            .exists()
        )

    def test_corrupt_host_file_is_rebuilt_not_propagated(self):
        path = Path(host_evidence_path(str(self.ws), "codex"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json", encoding="utf-8")
        recorder = EvidenceRecorder(str(self.ws), "codex", revision="a" * 40)
        self.assertTrue(recorder.record(EVENT_MCP_SERVER_STARTED))
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn(EVENT_MCP_SERVER_STARTED, data["events"])

    def test_summary_flags_corrupt_host_file_as_invalid(self):
        path = Path(host_evidence_path(str(self.ws), "codex"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json", encoding="utf-8")
        summary = summarize_runtime_evidence(str(self.ws), "a" * 12)
        self.assertTrue(summary["invalid"])
        self.assertFalse(summary["present"])

    def test_recording_never_raises_on_unwritable_workspace(self):
        # A file where the state directory should be makes every write
        # fail; the recorder must swallow that, not disturb serving.
        blocker = self.ws / ".relinkra"
        blocker.write_text("not a directory", encoding="utf-8")
        recorder = EvidenceRecorder(str(self.ws), "codex", revision="a" * 40)
        self.assertFalse(recorder.record(EVENT_MCP_SERVER_STARTED))

    def test_build_recorder_without_workspace_is_none(self):
        self.assertIsNone(build_evidence_recorder(None, "codex"))


class EvidenceMcpPathTests(unittest.TestCase):
    """Evidence is recorded from the real MCP path, and only on success."""

    def setUp(self):
        self.env = Env(seed=False)
        self.addCleanup(self.env.cleanup)
        self.recorder = EvidenceRecorder(
            self.env.ws_dir,
            "codex",
            clock=lambda: FIXED_NOW,
            revision="a" * 40,
        )
        self.services = self._services()
        self.server = MCPServer(self.services, evidence_recorder=self.recorder)

    def _services(self):
        from relinkra.app_service import RelinkraServices, ServiceConfig

        return RelinkraServices(
            config=ServiceConfig(
                registry_path=self.env.registry_path,
                default_project_id=self.env.project_id,
                default_workspace_id=self.env.workspace_id,
                workspace_root=self.env.ws_dir,
            ),
            store=self.env.store,
            registry=self.env.registry,
            git_service=RecordingGitService(),
            clock=lambda: FIXED_NOW,
        )

    def _store(self):
        return load_store(self.env.ws_dir)["hosts"]["codex"]["events"]

    def rpc(self, method, params=None):
        message = {"jsonrpc": "2.0", "id": 1, "method": method}
        if params is not None:
            message["params"] = params
        return self.server.handle_message(message)

    def call(self, name, **arguments):
        return self.rpc(
            "tools/call", {"name": name, "arguments": arguments}
        )["result"]

    def test_handshake_and_tools_list_are_recorded(self):
        self.rpc(
            "initialize",
            {"protocolVersion": "2025-06-18", "capabilities": {}},
        )
        self.rpc("tools/list")
        events = self._store()
        self.assertIn(EVENT_INITIALIZE_OBSERVED, events)
        self.assertTrue(events[EVENT_INITIALIZE_OBSERVED]["detail"]["protocol_agreed"])
        self.assertIn(EVENT_TOOLS_LIST_OBSERVED, events)

    def test_disagreeing_protocol_is_recorded_as_not_agreed(self):
        self.rpc("initialize", {"protocolVersion": "1999-01-01"})
        detail = self._store()[EVENT_INITIALIZE_OBSERVED]["detail"]
        self.assertFalse(detail["protocol_agreed"])

    def test_successful_route_calls_are_recorded(self):
        self.call("project_resolve")
        self.call("context_get", task="evidence fixture")
        events = self._store()
        self.assertIn(EVENT_TOOL_INVOKED, events)
        self.assertEqual(events[EVENT_TOOL_INVOKED]["detail"]["tool"], "context_get")
        self.assertIn(EVENT_PROJECT_RESOLVE_CALLED, events)
        self.assertIn(EVENT_CONTEXT_GET_CALLED, events)

    def test_failed_tool_call_records_nothing(self):
        result = self.call(
            "memory_get", memory_id="mem_x", project_id="rlk_unknown_project"
        )
        self.assertTrue(result["isError"])
        # Nothing recorded at all: the call never served its route.
        self.assertIsNone(load_store(self.env.ws_dir))

    def test_serve_records_server_start(self):
        stdout = io.StringIO()
        self.server.serve(io.StringIO(""), stdout)
        self.assertIn(EVENT_MCP_SERVER_STARTED, self._store())

    def test_server_without_recorder_records_nothing(self):
        bare = MCPServer(self._services())
        bare.handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        )
        self.assertIsNone(load_store(self.env.ws_dir))


class DogfoodCase(unittest.TestCase):
    """A real git repository, discovery monkeypatched, CLI driven directly."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="relinkra-r6d-doctor-")
        self.addCleanup(self._temp.cleanup)
        base = Path(self._temp.name)
        self.home = base / "home"
        self.home.mkdir()
        self.repo = _real_git_repo(base)
        self.root = self.repo.resolve()

        outer = self

        def fake_current(workspace_root=None):
            return DiscoveryEnvironment(
                system=SYSTEM_WINDOWS if os.name == "nt" else SYSTEM_LINUX,
                home=outer.home,
                env={},
                workspace_root=Path(workspace_root) if workspace_root else None,
                which=lambda name: None,
            )

        fixture = type(
            "FixtureDiscoveryEnvironment", (), {"current": staticmethod(fake_current)}
        )
        for module in (connect_cli, product_cli):
            original = module.DiscoveryEnvironment
            module.DiscoveryEnvironment = fixture
            self.addCleanup(setattr, module, "DiscoveryEnvironment", original)

    def run_cli(self, *argv, as_json=False):
        args = [*argv, "--path", str(self.repo)]
        if as_json:
            args.append("--json")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(args)
        return code, out.getvalue(), err.getvalue()

    def doctor_json(self):
        code, out, err = self.run_cli("doctor", as_json=True)
        self.assertEqual(code, product_cli.EXIT_OK, err)
        return json.loads(out)

    def doctor_checks(self):
        payload = self.doctor_json()
        return payload, {check["name"]: check for check in payload["checks"]}

    def agent_row(self, payload, agent):
        return next(row for row in payload["agents"] if row["agent"] == agent)

    def record(self, host_id, events):
        """Simulate the MCP server observing a sequence of events."""
        revision = None
        try:
            from relinkra.identity import git_head_sha

            revision = git_head_sha(str(self.root))
        except Exception:
            revision = ""
        recorder = EvidenceRecorder(
            str(self.root), host_id, revision=revision
        )
        for event, detail in events:
            recorder.record(event, detail)
        return recorder

    def codex_session_events(self):
        """initialize -> tools/list -> project_resolve -> context_get."""
        return [
            (EVENT_MCP_SERVER_STARTED, None),
            (
                EVENT_INITIALIZE_OBSERVED,
                {
                    "protocol_requested": "2025-06-18",
                    "protocol_negotiated": "2025-06-18",
                    "protocol_agreed": True,
                },
            ),
            (EVENT_TOOLS_LIST_OBSERVED, None),
            (EVENT_TOOL_INVOKED, {"tool": "project_resolve"}),
            (EVENT_PROJECT_RESOLVE_CALLED, None),
            (EVENT_TOOL_INVOKED, {"tool": "context_get"}),
            (EVENT_CONTEXT_GET_CALLED, None),
        ]


class DoctorDogfoodTests(DogfoodCase):
    """The R6D dogfood fixture: activity, not operator proofs, advances
    doctor."""

    def test_fresh_workspace_shows_pending_runtime(self):
        payload, checks = self.doctor_checks()
        self.assertEqual(self.agent_row(payload, "codex")["runtime"], "pending")
        self.assertEqual(checks["Context routing"]["status"], PENDING)
        self.assertEqual(checks["Integration trust"]["status"], PENDING)
        self.assertEqual(checks["Host verification"]["status"], PENDING)
        self.assertEqual(checks["Runtime evidence"]["status"], PENDING)
        self.assertIn(
            "no observed evidence", checks["Context routing"]["detail"]
        )

    def test_mcp_activity_advances_the_proven_stages(self):
        self.record("codex", self.codex_session_events())
        payload, checks = self.doctor_checks()
        self.assertEqual(self.agent_row(payload, "codex")["runtime"], "observed")
        # Every other host stays pending — Codex activity is not theirs.
        for other in ("claude", "opencode", "zcode", "devin-desktop"):
            self.assertEqual(self.agent_row(payload, other)["runtime"], "pending")

        self.assertEqual(checks["Context routing"]["status"], PASS)
        self.assertIn("self-observed", checks["Context routing"]["detail"])
        self.assertEqual(checks["Runtime evidence"]["status"], PASS)
        self.assertEqual(checks["Host verification"]["status"], PENDING)

        ladder = payload["routing"]["trust_ladder"]["stages"]
        proven = {
            stage["stage"] for stage in ladder if stage["state"] == STAGE_PROVEN
        }
        for stage in (
            "protocol_compatible",
            "handshake_verified",
            "tools_visible",
            "required_tools_callable",
            "real_host_launch_proven",
        ):
            self.assertIn(stage, proven)
        # One context_get does not make metrics attributable.
        self.assertNotIn("metrics_trustworthy", proven)
        # One session without a handoff read-back does not prove the trip.
        self.assertNotIn("handoff_round_trip_verified", proven)

    def checks_after_activity(self):
        return self.doctor_checks()

    def test_integration_trust_count_advances_without_proofs(self):
        before = self._proven_count(self.doctor_json())
        self.record("codex", self.codex_session_events())
        after = self._proven_count(self.doctor_json())
        self.assertGreater(after, before)
        self.assertLess(after, 12)

    @staticmethod
    def _proven_count(payload):
        stages = payload["routing"]["trust_ladder"]["stages"]
        return sum(1 for stage in stages if stage["state"] == STAGE_PROVEN)

    def test_handoff_round_trip_needs_both_halves(self):
        half = [
            (EVENT_MCP_SERVER_STARTED, None),
            (EVENT_TOOL_INVOKED, {"tool": "handoff_create"}),
            ("handoff_create_called", None),
        ]
        self.record("codex", half)
        ladder = self.doctor_json()["routing"]["trust_ladder"]["stages"]
        stage = next(
            entry for entry in ladder if entry["stage"] == STAGE_HANDOFF_ROUND_TRIP
        )
        self.assertNotEqual(stage["state"], STAGE_PROVEN)

        self.record("codex", half + [
            (EVENT_TOOL_INVOKED, {"tool": "handoff_get"}),
            ("handoff_get_called", None),
        ])
        ladder = self.doctor_json()["routing"]["trust_ladder"]["stages"]
        stage = next(
            entry for entry in ladder if entry["stage"] == STAGE_HANDOFF_ROUND_TRIP
        )
        self.assertEqual(stage["state"], STAGE_PROVEN)
        # Truthful wording: no handoff-id correlation is persisted, so
        # the claim says the routes were served, not that one write was
        # matched to a read-back of that same write.
        self.assertIn("read served", stage["evidence"].lower())
        self.assertNotIn("read-back", stage["evidence"].lower())

    def test_operator_proof_is_visible_as_the_stronger_class(self):
        self.record("codex", self.codex_session_events())
        self._record_operator_proof()
        payload, checks = self.doctor_checks()
        self.assertEqual(self.agent_row(payload, "codex")["runtime"], "attested")
        self.assertEqual(checks["Host verification"]["status"], PENDING)
        self.assertIn("codex: valid", checks["Host verification"]["detail"])

    def _record_operator_proof(self):
        registry_file = self.root / ".relinkra" / "registry.json"
        from relinkra.identity import git_head_sha

        workspace = Registry(str(registry_file)).register_workspace(
            str(self.root),
            explicit_identity("fixture"),
            git={"branch": "main", "head_sha": git_head_sha(str(self.root))},
        )
        from relinkra.product_cli import WorkspaceConfig

        WorkspaceConfig(
            project_id=workspace.project_id,
            workspace_id=workspace.workspace_id,
        ).save(self.repo)
        launch = resolve_launch(self.root, registry_file)
        proof = {
            "workspace_id": None,
            "stages": {
                "host_launched": True,
                "handshake_succeeded": True,
                "tools_visible": True,
                "tools_callable": True,
                "handoff_roundtrip": True,
            },
            "tools_visible": ["context_get"],
            "tools_invoked": ["context_get"],
            "handoff_ok": True,
        }
        record = build_proof_from_payload(
            "codex", proof, root=self.root, fingerprint=launch_fingerprint(launch)
        )
        record_verification(self.root, record)


class StaleEvidenceTests(DogfoodCase):
    """Evidence observed on revision A must not prove revision B routes."""

    def test_older_revision_evidence_stays_historical(self):
        self.record("codex", self.codex_session_events())
        _git(self.repo, "config", "user.email", "fixture@example.com")
        _git(self.repo, "config", "user.name", "Fixture")
        (self.repo / "CHANGELOG.md").write_text("b\n", encoding="utf-8")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-q", "-m", "fixture revision B")

        payload, checks = self.doctor_checks()
        # The host DID launch Relinkra before — that much stays true.
        self.assertIn(
            self.agent_row(payload, "codex")["runtime"], ("stale", "observed")
        )
        runtime = payload["routing"]["runtime_evidence"]["hosts"]["codex"]
        self.assertEqual(runtime["revision_relation"], "older")
        self.assertEqual(runtime["state"], "stale")

        # But nothing about the CURRENT revision's routing is claimed.
        self.assertEqual(checks["Context routing"]["status"], PENDING)
        ladder = payload["routing"]["trust_ladder"]["stages"]
        by_stage = {stage["stage"]: stage for stage in ladder}
        self.assertNotEqual(
            by_stage["handshake_verified"]["state"], STAGE_PROVEN
        )
        self.assertNotEqual(
            by_stage["required_tools_callable"]["state"], STAGE_PROVEN
        )
        self.assertEqual(
            by_stage["real_host_launch_proven"]["state"], STAGE_PROVEN
        )
        # Historical evidence is kept, not erased.
        self.assertTrue(
            Path(host_evidence_path(str(self.root), "codex")).exists()
        )


class MultiHostIsolationTests(DogfoodCase):
    """Host attribution is per host; unknown launchers stay unknown."""

    def test_codex_activity_never_marks_other_hosts_observed(self):
        self.record("codex", self.codex_session_events())
        payload, _ = self.doctor_checks()
        self.assertEqual(self.agent_row(payload, "codex")["runtime"], "observed")
        for other in ("claude", "opencode", "devin-desktop", "zcode"):
            self.assertEqual(self.agent_row(payload, other)["runtime"], "pending")

    def test_unknown_launcher_is_not_attributed_to_any_host(self):
        self.record("", self.codex_session_events())
        payload, checks = self.doctor_checks()
        for agent in ("codex", "claude", "opencode", "devin-desktop", "zcode"):
            self.assertEqual(self.agent_row(payload, agent)["runtime"], "pending")
        unknown = self.agent_row(payload, "unknown host")
        self.assertEqual(unknown["runtime"], "observed")
        self.assertEqual(unknown["config"], "-")
        # The workspace-level ladder may still know a route was served;
        # it never claims to know WHICH host served it.
        self.assertEqual(checks["Runtime evidence"]["status"], PASS)
        self.assertIn("unknown host", checks["Runtime evidence"]["detail"])


class DoctorDisplayTests(DogfoodCase):
    """PENDING vs WARN, compact default, verbose flag, one next action."""

    def test_pending_is_distinct_from_warn(self):
        _, checks = self.doctor_checks()
        # Not yet exercised: PENDING.
        self.assertEqual(checks["Context routing"]["status"], PENDING)
        self.assertEqual(checks["Metrics trust"]["status"], PENDING)
        self.assertEqual(checks["Integration trust"]["status"], PENDING)
        # Actually degraded/anomalous: WARN.
        self.assertEqual(checks["Engram ownership"]["status"], WARN)
        self.assertEqual(checks["Duplicate read/write risk"]["status"], WARN)

    def test_compact_is_the_default_and_verbose_keeps_depth(self):
        code, compact, _ = self.run_cli("doctor")
        self.assertEqual(code, product_cli.EXIT_OK)
        self.assertIn("Core", compact)
        self.assertIn("Agents", compact)
        self.assertIn("Integration", compact)
        self.assertIn("Next:", compact)
        self.assertNotIn("Suggested action:", compact)

        code, verbose, _ = self.run_cli("doctor", "--verbose")
        self.assertEqual(code, product_cli.EXIT_OK)
        self.assertIn("Suggested action:", verbose)
        self.assertIn("passed, ", verbose)
        self.assertIn(" pending, ", verbose)

    def test_compact_has_exactly_one_next_action(self):
        _, compact, _ = self.run_cli("doctor")
        next_lines = [
            line for line in compact.splitlines() if line.startswith("Next:")
        ]
        self.assertEqual(len(next_lines), 1)

    def test_next_action_priority_fail_then_warn_then_pending(self):
        from types import SimpleNamespace

        assessment = SimpleNamespace(
            runtime_evidence={"hosts": {}},
            host_verification=(),
            ladder=None,
        )
        failing = product_cli.Check("Blocking", FAIL, "broken", "Fix the blocker.")
        warning = product_cli.Check("Weak", WARN, "degraded", "Fix the degraded thing.")
        self.assertEqual(
            product_cli._compact_next_action([failing, warning], assessment),
            "Fix the blocker.",
        )
        self.assertEqual(
            product_cli._compact_next_action([warning], assessment),
            "Fix the degraded thing.",
        )

    def test_next_action_targets_configured_host_with_pending_runtime(self):
        from types import SimpleNamespace

        assessment = SimpleNamespace(
            runtime_evidence={"hosts": {}},
            host_verification=(
                {"connector_id": "codex", "managed_registration": True},
            ),
            ladder=None,
        )
        action = product_cli._compact_next_action([], assessment)
        self.assertIn("codex", action.lower())
        self.assertIn("start", action.lower())

    def test_next_action_names_host_identity_when_evidence_is_unattributed(self):
        from types import SimpleNamespace

        assessment = SimpleNamespace(
            runtime_evidence={
                "hosts": {"host_unknown": {"state": "observed"}},
            },
            host_verification=(),
            ladder=None,
        )
        action = product_cli._compact_next_action([], assessment)
        self.assertIn("RELINKRA_HOST_ID", action)

    def test_next_action_suggests_handoff_round_trip_when_hosts_observed(self):
        from types import SimpleNamespace

        assessment = SimpleNamespace(
            runtime_evidence={
                "hosts": {"codex": {"state": "observed"}},
            },
            host_verification=(),
            ladder=SimpleNamespace(
                by_stage=lambda: {
                    backend_policy.STAGE_HANDOFF_ROUND_TRIP: SimpleNamespace(
                        proven=False
                    )
                }
            ),
        )
        action = product_cli._compact_next_action([], assessment)
        self.assertIn("handoff", action.lower())

    def test_json_payload_stays_stable_and_additive(self):
        payload = self.doctor_json()
        for key in ("relinkra_version", "contract_version", "checks", "summary"):
            self.assertIn(key, payload)
        self.assertIn("pending", payload["summary"])
        self.assertIn("pass", payload["summary"])
        self.assertIn("warn", payload["summary"])
        self.assertIn("fail", payload["summary"])
        self.assertIn("next_action", payload)
        self.assertIn("agents", payload)
        # statuses in the wire payload use the four display states
        statuses = {check["status"] for check in payload["checks"]}
        self.assertTrue(statuses <= {PASS, PENDING, WARN, FAIL}, statuses)


class HostIdChannelTests(unittest.TestCase):
    """The RELINKRA_HOST_ID launch channel resolves through mcp_cli."""

    def test_mcp_cli_wires_host_identity_from_environment(self):
        import relinkra.mcp_cli as mcp_cli

        self.assertEqual(mcp_cli._env("HOST_ID", "codex"), "codex")

    def test_env_var_name_is_stable(self):
        from relinkra.runtime_evidence import HOST_ID_ENV

        self.assertEqual(HOST_ID_ENV, "RELINKRA_HOST_ID")


class MultiHostEvidenceFileTests(unittest.TestCase):
    """R6E — one bounded evidence file per host.

    The pre-R6E store was one shared JSON file updated by
    read-modify-write: concurrent Codex and OpenCode writers could
    interleave and silently drop one host's bucket. With one file per
    host there is no shared write target, so concurrent hosts cannot
    lose each other's evidence. These tests prove that deterministically.
    """

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="relinkra-r6e-multihost-")
        self.addCleanup(self._temp.cleanup)
        self.base = Path(self._temp.name)

    def _fresh_ws(self) -> Path:
        ws = self.base / f"ws-{time.monotonic_ns()}"
        ws.mkdir(parents=True)
        (ws / ".git").mkdir()
        return ws

    def test_concurrent_host_writers_keep_both_buckets(self):
        """Two threads (Codex + OpenCode) recording past a shared
        barrier, repeated: both buckets must survive fully."""
        rounds_count = 25
        for _ in range(5):
            ws = self._fresh_ws()
            barrier = threading.Barrier(2)

            def write(host: str) -> None:
                recorder = EvidenceRecorder(str(ws), host, revision="a" * 40)
                barrier.wait(timeout=30)
                for _ in range(rounds_count):
                    self.assertTrue(recorder.record(EVENT_MCP_SERVER_STARTED))

            threads = [
                threading.Thread(target=write, args=(host,))
                for host in ("codex", "opencode")
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=60)
            summary = summarize_runtime_evidence(str(ws), "a" * 12)
            for host in ("codex", "opencode"):
                self.assertIn(host, summary["hosts"], f"{host} bucket lost")
                bucket = summary["hosts"][host]["events"]
                self.assertIn(EVENT_MCP_SERVER_STARTED, bucket)
                self.assertEqual(
                    bucket[EVENT_MCP_SERVER_STARTED]["count"],
                    rounds_count,
                    f"{host} lost updates to its own file",
                )
            self.assertFalse(summary["invalid"])
            self.assertFalse(
                Path(evidence_path(str(ws))).exists(),
                "no shared single file may be written",
            )

    def test_concurrent_processes_keep_both_buckets(self):
        """The same guarantee across real OS processes — the shape of
        the failure the single shared file actually had."""
        ws = self._fresh_ws()
        script = (
            "import sys\n"
            "from relinkra.runtime_evidence import EvidenceRecorder,"
            " EVENT_MCP_SERVER_STARTED\n"
            "recorder = EvidenceRecorder(sys.argv[1], sys.argv[2],"
            " revision='a' * 40)\n"
            "for _ in range(15):\n"
            "    recorder.record(EVENT_MCP_SERVER_STARTED)\n"
        )
        processes = [
            subprocess.Popen(
                [sys.executable, "-c", script, str(ws), host],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            for host in ("codex", "opencode")
        ]
        for process in processes:
            _, stderr = process.communicate(timeout=120)
            self.assertEqual(process.returncode, 0, stderr)
        summary = summarize_runtime_evidence(str(ws), "a" * 12)
        for host in ("codex", "opencode"):
            self.assertIn(host, summary["hosts"])
            bucket = summary["hosts"][host]["events"]
            self.assertEqual(
                bucket[EVENT_MCP_SERVER_STARTED]["count"], 15
            )
            self.assertEqual(
                bucket[EVENT_MCP_SERVER_STARTED]["revision"], "a" * 12
            )

    def test_legacy_single_file_evidence_remains_readable(self):
        """Evidence written by the 0.1.3 layout stays visible, and new
        evidence lands in the per-host layout beside it."""
        ws = self._fresh_ws()
        legacy_dir = ws / ".relinkra"
        legacy_dir.mkdir()
        legacy = {
            "schema_version": "relinkra.runtime-evidence/v1",
            "updated_at": "2026-01-01T00:00:00+00:00",
            "hosts": {
                "codex": {
                    "events": {
                        EVENT_MCP_SERVER_STARTED: {
                            "observed_at": "2026-01-01T00:00:00+00:00",
                            "revision": "a" * 12,
                            "count": 3,
                        }
                    }
                },
                "opencode": {
                    "events": {
                        EVENT_MCP_SERVER_STARTED: {
                            "observed_at": "2026-01-01T00:00:00+00:00",
                            "revision": "a" * 12,
                            "count": 2,
                        }
                    }
                },
            },
        }
        (legacy_dir / "runtime-evidence.json").write_text(
            json.dumps(legacy), encoding="utf-8"
        )
        recorder = EvidenceRecorder(str(ws), "zcode", revision="a" * 40)
        self.assertTrue(recorder.record(EVENT_MCP_SERVER_STARTED))
        summary = summarize_runtime_evidence(str(ws), "a" * 12)
        self.assertTrue(summary["present"])
        self.assertFalse(summary["invalid"])
        self.assertEqual(
            summary["hosts"]["codex"]["events"][EVENT_MCP_SERVER_STARTED]["count"], 3
        )
        self.assertEqual(
            summary["hosts"]["opencode"]["events"][EVENT_MCP_SERVER_STARTED]["count"], 2
        )
        self.assertIn("zcode", summary["hosts"])
        # The legacy file is read, never rewritten.
        self.assertEqual(
            json.loads((legacy_dir / "runtime-evidence.json").read_text(
                encoding="utf-8"
            )),
            legacy,
        )
        store = load_store(str(ws))
        self.assertEqual(set(store["hosts"]), {"codex", "opencode", "zcode"})

    def test_per_host_file_wins_over_legacy_bucket(self):
        ws = self._fresh_ws()
        legacy_dir = ws / ".relinkra"
        legacy_dir.mkdir()
        legacy = {
            "schema_version": "relinkra.runtime-evidence/v1",
            "updated_at": "2026-01-01T00:00:00+00:00",
            "hosts": {
                "codex": {
                    "events": {
                        EVENT_MCP_SERVER_STARTED: {
                            "observed_at": "2026-01-01T00:00:00+00:00",
                            "revision": "b" * 12,
                            "count": 9,
                        }
                    }
                }
            },
        }
        (legacy_dir / "runtime-evidence.json").write_text(
            json.dumps(legacy), encoding="utf-8"
        )
        recorder = EvidenceRecorder(str(ws), "codex", revision="a" * 40)
        recorder.record(EVENT_MCP_SERVER_STARTED)
        summary = summarize_runtime_evidence(str(ws), "a" * 12)
        entry = summary["hosts"]["codex"]["events"][EVENT_MCP_SERVER_STARTED]
        self.assertEqual(entry["revision"], "a" * 12)
        self.assertEqual(entry["count"], 1)

    def test_one_hosts_corrupt_file_does_not_block_the_other(self):
        ws = self._fresh_ws()
        evidence_dir = ws / ".relinkra" / "runtime-evidence"
        evidence_dir.mkdir(parents=True)
        (evidence_dir / "codex.json").write_text("{not json", encoding="utf-8")
        recorder = EvidenceRecorder(str(ws), "opencode", revision="a" * 40)
        self.assertTrue(recorder.record(EVENT_MCP_SERVER_STARTED))
        summary = summarize_runtime_evidence(str(ws), "a" * 12)
        self.assertIn("opencode", summary["hosts"])
        self.assertNotIn("codex", summary["hosts"])
        self.assertTrue(summary["invalid"])

    def test_host_file_named_for_another_host_is_not_reattributed(self):
        ws = self._fresh_ws()
        evidence_dir = ws / ".relinkra" / "runtime-evidence"
        evidence_dir.mkdir(parents=True)
        payload = {
            "schema_version": "relinkra.runtime-evidence/v1",
            "host_id": "zcode",
            "updated_at": "2026-01-01T00:00:00+00:00",
            "events": {
                EVENT_MCP_SERVER_STARTED: {
                    "observed_at": "2026-01-01T00:00:00+00:00",
                    "revision": "a" * 12,
                    "count": 1,
                }
            },
        }
        (evidence_dir / "codex.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )
        summary = summarize_runtime_evidence(str(ws), "a" * 12)
        self.assertFalse(summary["present"])
        self.assertTrue(summary["invalid"], "a mislabelled file is anomalous state")


class UnknownRevisionTests(unittest.TestCase):
    """R6E — an unreadable current revision yields ``unknown``, never
    ``stale``. "Stale" would assert the evidence is historical, which is
    exactly the fact nobody was able to establish."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="relinkra-r6e-unknown-")
        self.addCleanup(self._temp.cleanup)
        self.ws = Path(self._temp.name) / "ws"
        self.ws.mkdir()
        (self.ws / ".git").mkdir()
        recorder = EvidenceRecorder(str(self.ws), "codex", revision="a" * 40)
        recorder.record(EVENT_MCP_SERVER_STARTED)
        recorder.record(
            EVENT_INITIALIZE_OBSERVED,
            {"protocol_negotiated": "2025-06-18", "protocol_agreed": True},
        )
        recorder.record(EVENT_TOOLS_LIST_OBSERVED)

    def test_summary_state_is_unknown_not_stale(self):
        summary = summarize_runtime_evidence(str(self.ws), "")
        codex = summary["hosts"]["codex"]
        self.assertEqual(codex["state"], "unknown")
        self.assertEqual(codex["revision_relation"], "unknown")
        self.assertTrue(codex["events"], "the evidence itself is kept")

    def test_unknown_revision_proves_no_current_revision_stages(self):
        summary = summarize_runtime_evidence(str(self.ws), "")
        claims = runtime_stage_claims(summary, "")
        # A launch is a fact about the host's history and survives.
        self.assertIn("server_started", claims)
        for stage in ("handshake", "protocol_agreed", "tools_visible"):
            self.assertNotIn(stage, claims)

    def test_doctor_reports_unknown_runtime_not_stale(self):
        from unittest import mock

        from relinkra.identity import GitError

        # Drive the real doctor against a real repository whose HEAD
        # cannot be read, with evidence recorded beforehand.
        self._temp2 = tempfile.TemporaryDirectory(prefix="relinkra-r6e-doctor-")
        self.addCleanup(self._temp2.cleanup)
        base = Path(self._temp2.name)
        self.repo = _real_git_repo(base)
        self.root = self.repo.resolve()
        revision = None
        try:
            from relinkra.identity import git_head_sha as _sha

            revision = _sha(str(self.root))
        except Exception:
            revision = ""
        recorder = EvidenceRecorder(str(self.root), "codex", revision=revision)
        recorder.record(EVENT_MCP_SERVER_STARTED)
        recorder.record(EVENT_INITIALIZE_OBSERVED, {"protocol_agreed": True})

        home = base / "home"
        home.mkdir()

        def fake_current(workspace_root=None):
            return DiscoveryEnvironment(
                system=SYSTEM_WINDOWS if os.name == "nt" else SYSTEM_LINUX,
                home=home,
                env={},
                workspace_root=Path(workspace_root) if workspace_root else None,
                which=lambda name: None,
            )

        fixture = type(
            "FixtureDiscoveryEnvironment", (),
            {"current": staticmethod(fake_current)},
        )
        for module in (connect_cli, product_cli):
            original = module.DiscoveryEnvironment
            module.DiscoveryEnvironment = fixture
            self.addCleanup(setattr, module, "DiscoveryEnvironment", original)

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with mock.patch(
                "relinkra.product_cli.git_head_sha",
                side_effect=GitError("head unreadable"),
            ):
                code = main(["doctor", "--path", str(self.repo), "--json"])
        self.assertEqual(code, product_cli.EXIT_OK, err.getvalue())
        payload = json.loads(out.getvalue())
        row = next(a for a in payload["agents"] if a["agent"] == "codex")
        self.assertEqual(row["runtime"], "unknown")


class WorktreeHygieneTests(unittest.TestCase):
    """R6E — runtime evidence must never dirty a linked worktree.

    A linked worktree's ``.git`` is a FILE naming its administrative
    directory; the repository-local exclude lives in the COMMON ``.git``
    directory, and only writing there keeps ``git status`` clean.
    """

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="relinkra-r6e-worktree-")
        self.addCleanup(self._temp.cleanup)
        self.base = Path(self._temp.name)
        self.repo = _real_git_repo(self.base)

    def test_linked_worktree_evidence_keeps_status_clean(self):
        worktree = self.base / "wt"
        _git(self.repo, "worktree", "add", str(worktree.resolve()), "-b", "wt-branch")
        git_file = worktree / ".git"
        self.assertTrue(git_file.is_file(), "fixture must be a linked worktree")
        (worktree / "tracked.txt").write_text("tracked\n", encoding="utf-8")
        _git(worktree, "add", ".")
        _git(worktree, "commit", "-q", "-m", "worktree revision")

        recorder = EvidenceRecorder(str(worktree.resolve()), "codex", revision="a" * 40)
        self.assertTrue(recorder.record(EVENT_MCP_SERVER_STARTED))

        # The evidence file exists inside the worktree...
        self.assertTrue(
            Path(host_evidence_path(str(worktree.resolve()), "codex")).exists()
        )
        # ...the exclude went to the COMMON directory...
        common_exclude = self.repo / ".git" / "info" / "exclude"
        self.assertIn(".relinkra/", common_exclude.read_text(encoding="utf-8"))
        # ...no tracked .gitignore was created or edited...
        self.assertFalse((worktree / ".gitignore").exists())
        self.assertFalse((self.repo / ".gitignore").exists())
        # ...and BOTH worktrees report a clean status.
        self.assertEqual(_git(worktree, "status", "--porcelain"), "")
        self.assertEqual(_git(self.repo, "status", "--porcelain"), "")

    def test_worktree_exclude_is_idempotent_and_preserves_comments(self):
        worktree = self.base / "wt"
        _git(self.repo, "worktree", "add", str(worktree.resolve()), "-b", "wt-branch-2")
        recorder = EvidenceRecorder(str(worktree.resolve()), "codex", revision="a" * 40)
        recorder.record(EVENT_MCP_SERVER_STARTED)
        recorder._exclude_checked = False
        recorder.record(EVENT_TOOL_INVOKED, {"tool": "context_get"})
        exclude_path = self.repo / ".git" / "info" / "exclude"
        content = exclude_path.read_text(encoding="utf-8")
        self.assertEqual(content.count(".relinkra/"), 1)
        self.assertIn("# git ls-files", content, "git's own comments survive")

    def test_normal_repo_evidence_keeps_status_clean(self):
        recorder = EvidenceRecorder(str(self.repo.resolve()), "opencode", revision="a" * 40)
        self.assertTrue(recorder.record(EVENT_MCP_SERVER_STARTED))
        self.assertEqual(_git(self.repo, "status", "--porcelain"), "")
        exclude_path = self.repo / ".git" / "info" / "exclude"
        self.assertIn(".relinkra/", exclude_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
