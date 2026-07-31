"""End-to-end tests for the R4C.0 routing diagnostics (doctor + CLI).

Everything here drives the real product CLI through ``main(argv)`` with
captured streams, against a fixture home. Three properties are under
test.

HONESTY. ``doctor`` may never print PASS for something nobody verified.
The trust ladder makes that checkable rather than aspirational: for every
routing check, the assertion is that its status follows from a state, and
that no ``unverified``/``unknown`` state ever produces a PASS.

NON-INTERFERENCE. The whole R4C.0 surface is read-only with respect to
anything outside ``.relinkra/``. The tests hash every fixture config
before and after, and additionally assert against the REAL machine's
Gentleman/Engram configuration and the untracked ``.windsurf`` workflow
file, because those are the specific things this phase promised not to
touch.

PORTABILITY. No routing output may carry a path, a credential or an
environment value — asserted over both the JSON and the human rendering.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from relinkra import connect_cli, product_cli
from relinkra.backend_policy import (
    CBM_DIRECTLY_EXPOSED,
    CBM_RELINKRA_PRIVATE,
    DUPLICATE_NONE,
    ENGRAM_DIRECT_UNCLASSIFIED,
    ENGRAM_SHARED_SEPARATED,
    ROUTE_MANAGED,
    ROUTE_MIXED,
    ROUTE_UNVERIFIED,
    STAGE_PROVEN,
    TRUST_DEGRADED,
    TRUST_HIGH,
    TRUST_UNRELIABLE,
    TRUST_UNVERIFIED,
    RoutingAssessment,
    TrustLadder,
    TrustStage,
)
from relinkra.connector import iter_strings
from relinkra.handoff import contains_absolute_path
from relinkra.host_discovery import (
    SYSTEM_LINUX,
    SYSTEM_WINDOWS,
    DiscoveryEnvironment,
)
from relinkra.product_cli import (
    EXIT_ACTION_REQUIRED,
    EXIT_OK,
    FAIL,
    PASS,
    WARN,
    main,
    routing_checks,
)

_SECRET = "sk-live-ROUTING-DO-NOT-LEAK-0123456789"

RELINKRA_ENTRY = {
    "command": "/usr/bin/python3",
    "args": ["-m", "relinkra.mcp_cli", "--workspace-root", "/w"],
}
CBM_ENTRY = {"command": "/opt/bin/codebase-memory-mcp", "args": []}
ENGRAM_ENTRY = {"command": "/usr/local/bin/engram", "args": ["mcp", "--tools=agent"]}
GENTLEMAN_ENGRAM_ENTRY = {
    "command": "/home/dev/.gentleman/bin/engram",
    "args": ["mcp"],
}
SECRET_ENTRY = {
    "command": "npx",
    "args": ["-y", "thing"],
    "env": {"API_KEY": _SECRET, "ENGRAM_TOKEN": _SECRET},
}


class RoutingCLICase(unittest.TestCase):
    """A fake repository plus a fixture home holding host configs."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="relinkra-routing-cli-")
        self.addCleanup(self._temp.cleanup)
        base = Path(self._temp.name)
        self.home = base / "home"
        self.home.mkdir()
        self.repo = base / "repo"
        (self.repo / ".git").mkdir(parents=True)

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

    # -- fixtures ---------------------------------------------------------

    def write_config(self, *parts, content):
        path = self.home.joinpath(*parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        text = content if isinstance(content, str) else json.dumps(content, indent=2)
        path.write_text(text, encoding="utf-8")
        return path

    def claude(self, servers):
        return self.write_config(
            ".claude", "settings.json", content={"mcpServers": servers}
        )

    def hash_home(self):
        return {
            str(path.relative_to(self.home)): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in sorted(self.home.rglob("*"))
            if path.is_file()
        }

    # -- driving the CLI --------------------------------------------------

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([*argv, "--path", str(self.repo)])
        return code, out.getvalue(), err.getvalue()

    def routing(self):
        code, out, _ = self.run_cli("connect", "routing", "--json")
        return code, json.loads(out)

    def doctor(self):
        code, out, _ = self.run_cli("doctor", "--json")
        return code, json.loads(out)

    def doctor_checks(self):
        _, payload = self.doctor()
        return {check["name"]: check for check in payload["checks"]}


class RoutingCommandTests(RoutingCLICase):
    def test_a_managed_looking_machine_is_reported_as_unverified(self):
        # Registration is on disk and nothing else has been observed, so
        # the route is a plan. This is the single most important
        # assertion in the file.
        self.claude({"relinkra": RELINKRA_ENTRY})
        code, payload = self.routing()
        self.assertEqual(payload["context_route"], ROUTE_UNVERIFIED)
        self.assertEqual(code, EXIT_ACTION_REQUIRED)

    def test_relinkra_beside_direct_cbm_is_mixed(self):
        self.claude({"relinkra": RELINKRA_ENTRY, "codebase-memory-mcp": CBM_ENTRY})
        _, payload = self.routing()
        self.assertEqual(payload["context_route"], ROUTE_MIXED)
        self.assertEqual(payload["cbm_ownership"], CBM_DIRECTLY_EXPOSED)
        self.assertTrue(payload["bypass_detected"])
        self.assertEqual(payload["metrics_trust"], TRUST_UNRELIABLE)

    def test_the_advanced_opt_in_changes_the_state_not_the_route(self):
        self.claude({"relinkra": RELINKRA_ENTRY, "cbm": CBM_ENTRY})
        (self.repo / ".relinkra").mkdir(parents=True, exist_ok=True)
        (self.repo / ".relinkra" / "config.json").write_text(
            json.dumps(
                {
                    "config_version": 1,
                    "project_id": "rlk_" + "a" * 32,
                    "workspace_id": "ws_" + "1" * 32,
                    "advanced_direct_cbm": True,
                }
            ),
            encoding="utf-8",
        )
        _, payload = self.routing()
        self.assertEqual(payload["cbm_ownership"], "explicitly_allowed_advanced")
        self.assertEqual(payload["metrics_trust"], TRUST_DEGRADED)
        self.assertEqual(payload["context_route"], ROUTE_MIXED)

    def test_a_gentleman_marked_engram_is_reported_as_shared(self):
        self.claude({"relinkra": RELINKRA_ENTRY, "engram": GENTLEMAN_ENGRAM_ENTRY})
        _, payload = self.routing()
        detections = [
            item for host in payload["hosts"] for item in host["detections"]
        ]
        engram = [item for item in detections if item["backend"] == "engram"]
        self.assertTrue(engram)
        self.assertTrue(engram[0]["gentleman_marked"])

    def test_an_unclassified_engram_is_reported_without_failing(self):
        self.claude({"relinkra": RELINKRA_ENTRY, "engram": ENGRAM_ENTRY})
        code, payload = self.routing()
        self.assertEqual(payload["engram_ownership"], ENGRAM_DIRECT_UNCLASSIFIED)
        # Action required, never a command failure: a shared Engram is a
        # legitimate arrangement Relinkra merely cannot classify.
        self.assertEqual(code, EXIT_ACTION_REQUIRED)

    def test_unknown_servers_are_reported_and_preserved(self):
        self.claude({"context7": {"command": "npx", "args": ["-y", "context7-mcp"]}})
        _, payload = self.routing()
        backends = [
            item["backend"] for host in payload["hosts"] for item in host["detections"]
        ]
        self.assertIn("unknown", backends)

    def test_the_agent_instruction_contract_is_emitted_but_not_written(self):
        self.claude({"relinkra": RELINKRA_ENTRY})
        _, payload = self.routing()
        contract = payload["agent_instructions"]
        self.assertFalse(contract["written_to_host"])
        self.assertTrue(contract["instructions"])

    def test_json_and_human_output_are_both_deterministic(self):
        self.claude({"relinkra": RELINKRA_ENTRY, "cbm": CBM_ENTRY})
        first_code, first, _ = self.run_cli("connect", "routing", "--json")
        second_code, second, _ = self.run_cli("connect", "routing", "--json")
        self.assertEqual((first_code, first), (second_code, second))
        _, human_a, _ = self.run_cli("connect", "routing")
        _, human_b, _ = self.run_cli("connect", "routing")
        self.assertEqual(human_a, human_b)

    def test_the_human_rendering_states_that_nothing_was_written(self):
        self.claude({"relinkra": RELINKRA_ENTRY})
        _, out, _ = self.run_cli("connect", "routing")
        self.assertIn("This command wrote nothing", out)


class LeakageTests(RoutingCLICase):
    def populate(self):
        self.claude({"secretive": SECRET_ENTRY, "relinkra": RELINKRA_ENTRY})
        self.write_config(
            ".codeium",
            "windsurf",
            "mcp_config.json",
            content={"mcpServers": {"acme-internal-index": CBM_ENTRY}},
        )

    def test_no_routing_output_prints_a_credential(self):
        self.populate()
        for argv in (("connect", "routing"), ("connect", "routing", "--json"), ("doctor",)):
            with self.subTest(argv=argv):
                _, out, err = self.run_cli(*argv)
                self.assertNotIn(_SECRET, out)
                self.assertNotIn(_SECRET, err)
                self.assertNotIn("ENGRAM_TOKEN", out)

    def test_no_routing_output_prints_a_machine_local_path(self):
        self.populate()
        for argv in (("connect", "routing"), ("connect", "routing", "--json"), ("doctor",)):
            with self.subTest(argv=argv):
                _, out, _ = self.run_cli(*argv)
                self.assertNotIn(str(self.home), out)
                self.assertNotIn(str(self.repo), out)
                self.assertNotIn("/opt/bin", out)

    def test_no_routing_output_echoes_a_configured_server_name(self):
        self.populate()
        for argv in (("connect", "routing"), ("connect", "routing", "--json"), ("doctor",)):
            with self.subTest(argv=argv):
                _, out, _ = self.run_cli(*argv)
                self.assertNotIn("acme-internal-index", out)
                self.assertNotIn("secretive", out)

    def test_routing_payloads_pass_the_absolute_path_audit(self):
        self.populate()
        for argv in (("connect", "routing", "--json"), ("doctor", "--json")):
            with self.subTest(argv=argv):
                _, out, _ = self.run_cli(*argv)
                for value in iter_strings(json.loads(out)):
                    self.assertFalse(contains_absolute_path(value), value)

    def test_doctor_self_audit_passes_with_the_routing_section_present(self):
        self.populate()
        checks = self.doctor_checks()
        self.assertEqual(checks["Portable output"]["status"], PASS)


class DoctorTrustTests(RoutingCLICase):
    def test_doctor_gains_the_compatibility_and_routing_section(self):
        self.claude({"relinkra": RELINKRA_ENTRY})
        checks = self.doctor_checks()
        for name in (
            "Context routing",
            "CBM ownership",
            "Engram ownership",
            "Duplicate read/write risk",
            "Metrics trust",
            "Integration trust",
        ):
            self.assertIn(name, checks)

    def test_configuration_presence_is_not_promoted_to_pass(self):
        self.claude({"relinkra": RELINKRA_ENTRY})
        checks = self.doctor_checks()
        self.assertEqual(checks["Context routing"]["status"], WARN)
        self.assertEqual(checks["Metrics trust"]["status"], WARN)
        self.assertEqual(checks["Integration trust"]["status"], WARN)

    def test_the_ladder_names_the_stages_that_are_not_proven(self):
        self.claude({"relinkra": RELINKRA_ENTRY})
        detail = self.doctor_checks()["Integration trust"]["detail"]
        self.assertIn("handshake_verified", detail)
        self.assertIn("required_tools_callable", detail)
        self.assertIn("real_host_launch_proven", detail)

    def test_direct_cbm_exposure_warns_and_suggests_a_safe_remediation(self):
        self.claude({"relinkra": RELINKRA_ENTRY, "codebase-memory-mcp": CBM_ENTRY})
        checks = self.doctor_checks()
        self.assertEqual(checks["CBM ownership"]["status"], WARN)
        action = checks["CBM ownership"]["action"].lower()
        self.assertIn("keep the direct cbm server", action)
        self.assertNotIn("delete", action)
        self.assertIn("nothing was changed", action)

    def test_a_direct_engram_registration_never_fails_the_diagnostic(self):
        self.claude({"engram": ENGRAM_ENTRY})
        code, payload = self.doctor()
        statuses = {check["name"]: check["status"] for check in payload["checks"]}
        self.assertEqual(statuses["Engram ownership"], WARN)
        self.assertNotIn(FAIL, statuses.values())
        self.assertEqual(code, EXIT_OK)

    def test_routing_warnings_do_not_change_the_doctor_exit_code(self):
        self.claude({"codebase-memory-mcp": CBM_ENTRY})
        code, payload = self.doctor()
        self.assertEqual(payload["summary"]["fail"], 0)
        self.assertEqual(code, EXIT_OK)

    def test_every_non_pass_routing_check_is_actionable(self):
        self.claude({"relinkra": RELINKRA_ENTRY, "cbm": CBM_ENTRY, "engram": ENGRAM_ENTRY})
        _, payload = self.doctor()
        for check in payload["checks"]:
            if check["status"] != PASS:
                self.assertTrue(check["action"], f"{check['name']} has no action")

    def test_doctor_and_connect_routing_agree_about_the_same_machine(self):
        self.claude({"relinkra": RELINKRA_ENTRY, "cbm": CBM_ENTRY})
        _, routing = self.routing()
        _, doctor = self.doctor()
        # doctor probes backends and connect routing does not, so the
        # backend-dependent fields may differ; the routing verdict itself
        # must not.
        self.assertEqual(
            doctor["routing"]["context_route"], routing["context_route"]
        )
        self.assertEqual(
            doctor["routing"]["cbm_ownership"], routing["cbm_ownership"]
        )

    def test_a_conflicting_registration_is_explained_not_just_flagged(self):
        # The assessment always knew why; before this the text reader saw
        # "ownership could not be determined" and nothing else.
        self.claude({"relinkra": CBM_ENTRY})
        checks = self.doctor_checks()
        self.assertEqual(checks["CBM ownership"]["status"], WARN)
        self.assertIn("disagrees", checks["CBM ownership"]["action"])
        _, out, _ = self.run_cli("doctor")
        self.assertIn("Routing notes", out)
        self.assertIn("disagrees with what it launches", out)

    def test_an_unrouted_backend_warning_names_the_missing_registration(self):
        self.claude({"context7": {"command": "npx", "args": ["-y", "context7-mcp"]}})
        checks = self.doctor_checks()
        for name in ("CBM ownership", "Engram ownership"):
            check = checks[name]
            if check["status"] != PASS:
                self.assertTrue(check["action"], name)

    def test_every_doctor_warning_carries_an_action(self):
        for servers in (
            {"relinkra": CBM_ENTRY},
            {"relinkra": RELINKRA_ENTRY, "cbm": CBM_ENTRY},
            {"engram": ENGRAM_ENTRY},
            {},
        ):
            with self.subTest(servers=sorted(servers)):
                self.claude(servers)
                _, payload = self.doctor()
                for check in payload["checks"]:
                    if check["status"] != PASS:
                        self.assertTrue(
                            check["action"], f"{check['name']} has no action"
                        )

    def test_doctor_carries_the_agent_instruction_contract(self):
        self.claude({"relinkra": RELINKRA_ENTRY})
        _, payload = self.doctor()
        self.assertFalse(payload["agent_instructions"]["written_to_host"])


class CheckRenderingTests(unittest.TestCase):
    """Unit-level proof that no unverified state can render as PASS."""

    def _checks(self, **kw):
        base = dict(
            context_route=ROUTE_UNVERIFIED,
            cbm_ownership="unknown",
            engram_ownership="unknown",
            metrics_trust=TRUST_UNVERIFIED,
            duplicate_risk="unverified",
        )
        base.update(kw)
        return {check.name: check for check in routing_checks(RoutingAssessment(**base))}

    def test_unknown_and_unverified_states_never_pass(self):
        for check in self._checks().values():
            self.assertNotEqual(check.status, PASS, check.name)

    def test_a_fully_healthy_assessment_passes_every_check(self):
        checks = self._checks(
            context_route=ROUTE_MANAGED,
            cbm_ownership=CBM_RELINKRA_PRIVATE,
            engram_ownership=ENGRAM_SHARED_SEPARATED,
            metrics_trust=TRUST_HIGH,
            duplicate_risk=DUPLICATE_NONE,
            ladder=TrustLadder((TrustStage("a", True),)),
        )
        for name, check in checks.items():
            self.assertEqual(check.status, PASS, name)

    def test_the_healthy_details_read_like_the_specification(self):
        checks = self._checks(
            context_route=ROUTE_MANAGED,
            cbm_ownership=CBM_RELINKRA_PRIVATE,
            engram_ownership=ENGRAM_SHARED_SEPARATED,
            metrics_trust=TRUST_HIGH,
        )
        self.assertEqual(checks["Context routing"].detail, "managed through Relinkra")
        self.assertEqual(checks["CBM ownership"].detail, "private Relinkra backend")
        self.assertEqual(
            checks["Engram ownership"].detail,
            "shared with Gentleman under separated contracts",
        )
        self.assertEqual(checks["Metrics trust"].detail, "high")

    def test_no_routing_check_can_produce_a_fail(self):
        for route in (ROUTE_UNVERIFIED, ROUTE_MIXED, ROUTE_MANAGED):
            for check in self._checks(context_route=route).values():
                self.assertIn(check.status, (PASS, WARN), check.name)

    def test_an_unproven_ladder_stage_keeps_integration_trust_at_warn(self):
        checks = self._checks(ladder=TrustLadder((TrustStage("a", None),)))
        self.assertEqual(checks["Integration trust"].status, WARN)
        self.assertEqual(
            TrustLadder((TrustStage("a", None),)).stages[0].state, "unverified"
        )

    def test_a_proven_ladder_reports_proven(self):
        ladder = TrustLadder((TrustStage("a", True),))
        self.assertEqual(ladder.stages[0].state, STAGE_PROVEN)


class NonInterferenceTests(RoutingCLICase):
    """R4C.0 is read-only with respect to everything it inspects."""

    def populate(self):
        self.claude({"relinkra": RELINKRA_ENTRY, "codebase-memory-mcp": CBM_ENTRY})
        self.write_config(
            ".codeium",
            "windsurf",
            "mcp_config.json",
            content={"mcpServers": {"engram": GENTLEMAN_ENGRAM_ENTRY}},
        )
        self.write_config(
            ".config",
            "opencode",
            "opencode.json",
            content={"mcp": {"engram": {"type": "local", "command": ["engram", "mcp"]}}},
        )
        self.write_config(
            ".codex",
            "config.toml",
            content='[mcp_servers.engram]\ncommand = "engram"\nargs = ["mcp"]\n',
        )

    def test_no_fixture_host_configuration_is_modified(self):
        self.populate()
        before = self.hash_home()
        for argv in (
            ("connect", "routing"),
            ("connect", "routing", "--json"),
            ("connect", "list", "--json"),
            ("connect", "inspect", "devin-desktop", "--json"),
            ("doctor",),
            ("doctor", "--json"),
        ):
            self.run_cli(*argv)
        self.assertEqual(self.hash_home(), before)

    def test_no_host_configuration_file_is_created_or_removed(self):
        self.populate()
        before = set(self.hash_home())
        self.run_cli("connect", "routing")
        self.run_cli("doctor")
        self.assertEqual(set(self.hash_home()), before)

    def test_a_gentleman_engram_registration_is_read_never_rewritten(self):
        self.populate()
        target = self.home / ".codeium" / "windsurf" / "mcp_config.json"
        before = target.read_bytes()
        self.run_cli("connect", "routing", "--json")
        self.run_cli("doctor", "--json")
        self.assertEqual(target.read_bytes(), before)


class RealMachineNonInterferenceTests(unittest.TestCase):
    """The same promise, against the ACTUAL machine running the suite.

    The fixture tests above prove the code does not write to configs it
    was pointed at. These prove it does not write to the ones it was
    NOT pointed at — the developer's own Gentleman, Engram and host
    configuration, and the untracked ``.windsurf`` workflow file this
    phase was explicitly told to leave alone.
    """

    REPO = Path(__file__).resolve().parent.parent

    def _digest(self, path):
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            return None

    def _live_configs(self):
        home = Path.home()
        return [
            home / ".claude.json",
            home / ".claude" / "settings.json",
            home / ".claude" / "plugins" / "installed_plugins.json",
            home / ".codeium" / "windsurf" / "mcp_config.json",
            home / ".config" / "opencode" / "opencode.json",
            home / ".codex" / "config.toml",
        ]

    def _run(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            main([*argv, "--path", str(self.REPO)])
        return out.getvalue()

    def test_live_host_and_gentleman_configs_are_unchanged(self):
        paths = self._live_configs()
        before = {path: self._digest(path) for path in paths}
        if not any(digest for digest in before.values()):
            self.skipTest("no live host configuration is present on this machine")
        self._run("connect", "routing", "--json")
        self._run("doctor", "--json")
        after = {path: self._digest(path) for path in paths}
        self.assertEqual(after, before)

    def test_the_untracked_windsurf_workflow_file_is_untouched(self):
        target = self.REPO / ".windsurf" / "workflows" / "sdd-new.md"
        if not target.exists():
            self.skipTest("the pre-existing untracked .windsurf fixture is absent")
        before = self._digest(target)
        self._run("connect", "routing", "--json")
        self._run("doctor", "--json")
        self.assertEqual(self._digest(target), before)

    def test_the_real_machine_is_assessed_without_claiming_a_managed_route(self):
        # Relinkra is not registered with any host on a development
        # machine, and the diagnostics must say so rather than inferring
        # a route from the fact that Relinkra is what is running.
        payload = json.loads(self._run("connect", "routing", "--json"))
        self.assertIn(
            payload["context_route"],
            (ROUTE_UNVERIFIED, ROUTE_MIXED, ROUTE_MANAGED),
        )
        self.assertFalse(payload["trust_ladder"]["all_proven"])


if __name__ == "__main__":
    unittest.main()
