"""Tests for the connector registry, launch contract and plan engine (R4B).

Host configurations are built as fixtures inside a temporary home, so the
suite exercises the real discovery and planning path without touching any
configuration on the machine running it.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path, PurePosixPath, PureWindowsPath
from unittest import mock

from relinkra.config_merge import (
    apply_member,
    parse_json_document,
    serialize_json_document,
)
from relinkra.connector import (
    CONTRACT_VERSION,
    DISCOVERY_CONFIG_MALFORMED,
    DISCOVERY_CONFIG_MISSING,
    DISCOVERY_CONFIG_UNSUPPORTED,
    DISCOVERY_DISCOVERED,
    DISCOVERY_NOT_INSTALLED,
    DISTRIBUTION_CONSOLE_SCRIPT,
    DISTRIBUTION_INSTALLED_MODULE,
    DISTRIBUTION_SOURCE_CHECKOUT,
    DISTRIBUTION_UNRESOLVED,
    MANAGED_SERVER_NAME,
    OP_ADD_OBJECT_MEMBER,
    OP_BACKUP_FILE,
    OP_CREATE_FILE,
    OP_NO_OP,
    OP_REPLACE_MANAGED_MEMBER,
    OP_REQUEST_RESTART,
    OP_VALIDATE_JSON,
    OPERATIONS,
    PLAN_BLOCKED,
    PLAN_READY,
    PLAN_UNAVAILABLE,
    REGISTRATION_ABSENT,
    REGISTRATION_ALREADY_CONNECTED,
    REGISTRATION_CONFLICT,
    REGISTRATION_NEEDS_UPDATE,
    SUPPORT_STATUSES,
    SUPPORT_UNSUPPORTED,
    DISCOVERY_STATUSES,
    LaunchContract,
    UnknownConnectorError,
    iter_strings,
)
from relinkra import connectors as relinkra_connectors
from relinkra.connectors import (
    CLAUDE,
    CODEX,
    CONNECTORS,
    CONSOLE_SCRIPT,
    DEVIN_CLOUD,
    GENERIC,
    OPENCODE,
    SERVER_MODULE,
    DEVIN_DESKTOP,
    build_plan,
    build_report,
    check_registration,
    claude_project_key,
    connector_ids,
    container_label,
    entry_tokens,
    inspect_connector,
    launch_contract_document,
    launches_relinkra,
    resolve_connector,
    resolve_launch,
    server_module_importable,
)
from relinkra.handoff import contains_absolute_path
from relinkra.host_discovery import SYSTEM_LINUX, SYSTEM_WINDOWS, DiscoveryEnvironment
from relinkra.safe_write import MAX_CONFIG_BYTES
from relinkra.toml_edit import toml_parser_available

_REQUIRES_TOMLLIB = "codex TOML parsing requires tomllib (Python 3.11+)"

WORKSPACE = "/srv/code/repo" if os.name != "nt" else r"D:\code\repo"

LAUNCH = LaunchContract(
    command="/usr/bin/python3",
    args=("-m", SERVER_MODULE, "--workspace-root", WORKSPACE, "--registry", "reg.json"),
    env={},
    distribution=DISTRIBUTION_INSTALLED_MODULE,
    resolved=True,
)

SOURCE_LAUNCH = LaunchContract(
    command="/usr/bin/python3",
    args=("-m", SERVER_MODULE, "--workspace-root", WORKSPACE),
    env={"PYTHONPATH": "/srv/code/repo"},
    distribution=DISTRIBUTION_SOURCE_CHECKOUT,
    resolved=True,
    warnings=("running from a source checkout",),
)


class RegistryTests(unittest.TestCase):
    def test_every_expected_connector_is_registered(self):
        self.assertEqual(
            connector_ids(),
            ["generic", "claude", "opencode", "codex", "devin-desktop", "devin-cloud"],
        )

    def test_ids_and_aliases_are_globally_unique(self):
        names = [name for spec in CONNECTORS for name in spec.all_names]
        self.assertEqual(len(names), len(set(names)))

    def test_resolution_by_id_and_alias(self):
        for name, expected in (
            ("claude", "claude"),
            ("claude-code", "claude"),
            ("claudecode", "claude"),
            ("opencode", "opencode"),
            ("open-code", "opencode"),
            ("codex", "codex"),
            ("openai-codex", "codex"),
            ("windsurf", "devin-desktop"),
            ("codeium", "devin-desktop"),
            ("windsurf-next", "devin-desktop"),
            ("devin-desktop", "devin-desktop"),
            ("devin-cloud", "devin-cloud"),
            ("generic", "generic"),
            ("mcp", "generic"),
            ("stdio", "generic"),
        ):
            with self.subTest(name=name):
                self.assertEqual(resolve_connector(name).connector_id, expected)

    def test_resolution_is_case_and_space_insensitive(self):
        self.assertEqual(resolve_connector("  Claude-Code  ").connector_id, "claude")

    def test_unknown_connector_lists_the_known_ones(self):
        with self.assertRaises(UnknownConnectorError) as caught:
            resolve_connector("emacs")
        self.assertIn("claude", str(caught.exception))

    def test_empty_name_is_rejected(self):
        for name in ("", "   ", None):
            with self.subTest(name=name):
                with self.assertRaises(UnknownConnectorError):
                    resolve_connector(name)

    def test_declared_states_are_from_the_closed_vocabularies(self):
        for spec in CONNECTORS:
            with self.subTest(connector=spec.connector_id):
                self.assertIn(spec.support_status, SUPPORT_STATUSES)

    def test_devin_is_not_advertised_as_supported(self):
        self.assertEqual(DEVIN_CLOUD.support_status, SUPPORT_UNSUPPORTED)
        self.assertFalse(DEVIN_CLOUD.format_verified)
        self.assertEqual(DEVIN_CLOUD.locations, ())

    def test_only_claude_opencode_codex_and_devin_desktop_may_write_in_this_phase(self):
        # R4C.1B opened the write path for Claude Code; R4C.1C extended
        # it to OpenCode; R4C.1D extended it to Codex via a scoped
        # textual TOML editor; R4C.1E Gate B extended it to Devin
        # Desktop after Gate B1 proved the mirror semantics. Every other
        # connector keeps the structural guarantee behind "live host
        # configs unmodified".
        writable = {"claude", "opencode", "codex", "devin-desktop"}
        for spec in CONNECTORS:
            with self.subTest(connector=spec.connector_id):
                if spec.connector_id in writable:
                    self.assertTrue(spec.apply_available)
                    self.assertFalse(spec.apply_unavailable_reason)
                else:
                    self.assertFalse(spec.apply_available)
                    self.assertTrue(spec.apply_unavailable_reason)

    def test_no_connector_claims_a_proven_host_launch(self):
        for spec in CONNECTORS:
            with self.subTest(connector=spec.connector_id):
                self.assertFalse(spec.real_host_launch_proven)

    def test_verified_formats_declare_their_evidence(self):
        for spec in CONNECTORS:
            with self.subTest(connector=spec.connector_id):
                if spec.format_verified:
                    self.assertTrue(spec.format_evidence)

    def test_hosts_with_locations_declare_a_restart_instruction(self):
        for spec in CONNECTORS:
            with self.subTest(connector=spec.connector_id):
                if spec.locations:
                    self.assertTrue(spec.restart_instruction)

    def test_marker_stays_opt_in(self):
        # No host has been shown to keep unknown members across a
        # rewrite, so nothing may stamp one yet.
        for spec in CONNECTORS:
            with self.subTest(connector=spec.connector_id):
                self.assertFalse(spec.marker_allowed)


class LaunchContractTests(unittest.TestCase):
    def test_console_script_wins_when_present(self):
        launch = resolve_launch(
            ".", "reg.json", which=lambda name: "/opt/bin/" + name
        )
        self.assertEqual(launch.distribution, DISTRIBUTION_CONSOLE_SCRIPT)
        self.assertEqual(launch.command, "/opt/bin/" + CONSOLE_SCRIPT)
        self.assertNotIn("-m", launch.args)
        self.assertEqual(launch.env, {})

    def test_source_checkout_requires_pythonpath(self):
        launch = resolve_launch(
            ".", "reg.json", which=lambda name: None, force_source_checkout=True
        )
        self.assertEqual(launch.distribution, DISTRIBUTION_SOURCE_CHECKOUT)
        self.assertEqual(launch.env_keys, ["PYTHONPATH"])
        self.assertTrue(any("PYTHONPATH" in w for w in launch.warnings))

    def test_installed_module_needs_no_environment(self):
        launch = resolve_launch(
            ".", "reg.json", which=lambda name: None, force_source_checkout=False
        )
        self.assertEqual(launch.distribution, DISTRIBUTION_INSTALLED_MODULE)
        self.assertEqual(launch.env_keys, [])

    def test_module_invocation_is_structured(self):
        launch = resolve_launch(
            ".", "reg.json", which=lambda name: None, force_source_checkout=False
        )
        self.assertEqual(launch.args[0], "-m")
        self.assertEqual(launch.args[1], SERVER_MODULE)
        self.assertIn("--workspace-root", launch.args)
        self.assertIn("--registry", launch.args)

    def test_arguments_are_never_joined_into_a_shell_string(self):
        with tempfile.TemporaryDirectory(prefix="rel kra space&") as workspace:
            launch = resolve_launch(
                workspace, "reg.json", which=lambda name: None,
                force_source_checkout=False,
            )
            index = launch.args.index("--workspace-root")
            # The awkward directory arrives as exactly ONE argument.
            self.assertEqual(
                Path(launch.args[index + 1]).resolve(), Path(workspace).resolve()
            )

    def test_unresolvable_interpreter_is_reported_not_guessed(self):
        original = sys.executable
        try:
            sys.executable = ""
            launch = resolve_launch(".", "reg.json", which=lambda name: None)
        finally:
            sys.executable = original
        self.assertEqual(launch.distribution, DISTRIBUTION_UNRESOLVED)
        self.assertFalse(launch.resolved)
        self.assertEqual(launch.command, "")
        self.assertTrue(launch.warnings)

    def test_interpreter_falls_back_to_path(self):
        original = sys.executable
        try:
            sys.executable = ""
            launch = resolve_launch(
                ".",
                "reg.json",
                which=lambda name: "/usr/bin/python3" if name == "python3" else None,
                force_source_checkout=False,
            )
        finally:
            sys.executable = original
        self.assertEqual(launch.command, "/usr/bin/python3")

    def test_portable_rendering_hides_every_machine_local_value(self):
        launch = SOURCE_LAUNCH
        payload = launch.to_dict()
        self.assertEqual(payload["command"], "<interpreter>")
        self.assertNotIn("env", payload)
        self.assertEqual(payload["env_keys"], ["PYTHONPATH"])
        self.assertNotIn("<path>", "".join(payload["args"][:2]))
        for value in payload["args"]:
            self.assertFalse(contains_absolute_path(value), value)

    def test_portable_rendering_preserves_arity_and_order(self):
        payload = SOURCE_LAUNCH.to_dict()
        self.assertEqual(len(payload["args"]), len(SOURCE_LAUNCH.args))
        self.assertEqual(payload["args"][0], "-m")
        self.assertEqual(payload["args"][1], SERVER_MODULE)
        self.assertEqual(payload["args"][2], "--workspace-root")
        self.assertEqual(payload["args"][3], "<path>")

    def test_machine_rendering_keeps_the_real_values(self):
        payload = SOURCE_LAUNCH.to_machine_dict()
        self.assertEqual(payload["command"], "/usr/bin/python3")
        self.assertEqual(payload["env"], {"PYTHONPATH": "/srv/code/repo"})

    def test_contract_document_is_portable_and_deterministic(self):
        document = launch_contract_document(SOURCE_LAUNCH)
        self.assertEqual(document["contract_version"], CONTRACT_VERSION)
        self.assertEqual(document["server_name"], MANAGED_SERVER_NAME)
        rendered = json.dumps(document, sort_keys=True)
        self.assertEqual(rendered, json.dumps(launch_contract_document(SOURCE_LAUNCH), sort_keys=True))
        for value in iter_strings(document):
            self.assertFalse(contains_absolute_path(value), value)

    def test_server_module_is_importable_here(self):
        self.assertTrue(server_module_importable())


class OwnershipTests(unittest.TestCase):
    def test_entry_tokens_handles_both_command_shapes(self):
        self.assertEqual(
            entry_tokens({"command": "python", "args": ["-m", "x"]}),
            ("python", "-m", "x"),
        )
        self.assertEqual(
            entry_tokens({"command": ["python", "-m", "x"]}), ("python", "-m", "x")
        )
        self.assertEqual(entry_tokens({"url": "https://example.invalid"}), ())
        self.assertEqual(entry_tokens("nonsense"), ())

    def test_windows_paths_split_on_posix_and_vice_versa(self):
        self.assertTrue(
            launches_relinkra({"command": r"C:\tools\relinkra-mcp.exe", "args": []})
        )
        self.assertTrue(
            launches_relinkra({"command": "/opt/tools/relinkra-mcp", "args": []})
        )
        self.assertTrue(
            launches_relinkra(
                {
                    "command": r"C:\Python311\PYTHON.EXE",
                    "args": ["-m", SERVER_MODULE],
                }
            )
        )
        self.assertTrue(
            launches_relinkra(
                {
                    "command": r".\venv\Scripts\python3.12.exe",
                    "args": ["-m", SERVER_MODULE],
                }
            )
        )
        self.assertTrue(
            launches_relinkra({"command": "RELINKRA-MCP.EXE", "args": []})
        )

    def test_module_ownership_requires_a_python_module_launch_slot(self):
        self.assertTrue(
            launches_relinkra({"command": "python", "args": ["-m", SERVER_MODULE]})
        )
        for entry in (
            {"command": "node", "args": ["-m", SERVER_MODULE]},
            {"command": "python", "args": ["wrapper.py", "-m", SERVER_MODULE]},
            {"command": "python", "args": ["-m", "relinkra.other"]},
            {"command": "python", "args": [SERVER_MODULE]},
            {"command": "python", "args": [SERVER_MODULE, "-m"]},
            {"command": "python", "args": ["--", "-m", SERVER_MODULE]},
        ):
            with self.subTest(entry=entry):
                self.assertFalse(launches_relinkra(entry))

    def test_similar_but_different_command_is_not_ours(self):
        self.assertFalse(
            launches_relinkra({"command": "python", "args": ["-m", "relinkra.other"]})
        )
        self.assertFalse(
            launches_relinkra({"command": "relinkra-mcp-proxy", "args": []})
        )


class HostFixtureCase(unittest.TestCase):
    """A temporary home holding whatever host configs a test needs."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="relinkra-hosts-")
        self.addCleanup(self._temp.cleanup)
        self.home = Path(self._temp.name) / "home"
        self.home.mkdir()
        self.workspace = Path(self._temp.name) / "repo"
        self.workspace.mkdir()
        self.installed = set()

    def env(self, **kwargs):
        defaults = dict(
            system=SYSTEM_WINDOWS if os.name == "nt" else SYSTEM_LINUX,
            home=self.home,
            env={},
            workspace_root=self.workspace,
            which=lambda name: "/usr/bin/" + name if name in self.installed else None,
        )
        defaults.update(kwargs)
        return DiscoveryEnvironment(**defaults)

    def write_config(self, *parts, content):
        path = self.home.joinpath(*parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        text = content if isinstance(content, str) else json.dumps(content, indent=2)
        path.write_text(text, encoding="utf-8")
        return path

    def claude_container_path(self):
        """The LOCAL-scope container for this fixture's workspace."""
        return ("projects", claude_project_key(self.workspace), "mcpServers")

    def claude_config(self, content):
        """Write the Claude state file (~/.claude.json).

        A dict of exactly ``{"mcpServers": ...}`` is wrapped into the
        LOCAL-scope shape Claude Code 2.1+ actually reads —
        ``projects[<project-key>].mcpServers`` — alongside an unknown
        top-level member and a sibling project, so every consumer is
        exercised against the real file shape. Anything else (raw JSON
        text, other shapes) is written verbatim.
        """
        if isinstance(content, dict) and set(content) == {"mcpServers"}:
            content = {
                "numStartups": 7,
                "projects": {
                    claude_project_key(self.workspace): {
                        "mcpServers": content["mcpServers"],
                        "allowedTools": ["mcp__other__list"],
                    },
                    "/other/project": {
                        "mcpServers": {
                            "sibling": {"command": "npx", "args": ["-y", "sib"]}
                        }
                    },
                },
                "theme": "dark",
            }
        return self.write_config(".claude.json", content=content)

    def legacy_settings_config(self, content):
        """The legacy ~/.claude/settings.json — discovery-only in 2.1+."""
        return self.write_config(".claude", "settings.json", content=content)

    def inspect(self, spec, **kwargs):
        return inspect_connector(spec, self.env(**kwargs))

    def plan(self, spec, launch=LAUNCH, **kwargs):
        return build_plan(spec, self.inspect(spec, **kwargs), launch)


class DiscoveryStateTests(HostFixtureCase):
    def test_absent_everything_is_not_installed(self):
        inspection = self.inspect(CLAUDE)
        self.assertEqual(inspection.discovery_status, DISCOVERY_NOT_INSTALLED)
        self.assertEqual(inspection.registration_state, REGISTRATION_ABSENT)

    def test_executable_without_config_is_config_missing(self):
        # Absence of one conventional file is not proof of absence.
        self.installed.add("claude")
        inspection = self.inspect(CLAUDE)
        self.assertEqual(inspection.discovery_status, DISCOVERY_CONFIG_MISSING)

    def test_config_without_executable_is_still_discovered(self):
        self.claude_config({"mcpServers": {}})
        inspection = self.inspect(CLAUDE)
        self.assertEqual(inspection.discovery_status, DISCOVERY_DISCOVERED)

    def test_malformed_config_is_its_own_state(self):
        self.claude_config("{ not json")
        inspection = self.inspect(CLAUDE)
        self.assertEqual(inspection.discovery_status, DISCOVERY_CONFIG_MALFORMED)
        self.assertTrue(any(w.code == "config_malformed" for w in inspection.warnings))

    @unittest.skipUnless(toml_parser_available(), _REQUIRES_TOMLLIB)
    def test_deep_toml_recursion_is_reported_malformed_without_raising(self):
        nested = "value = " + ("{a = " * 500) + "0" + ("}" * 500) + "\n"
        self.write_config(".codex", "config.toml", content=nested)
        inspection = self.inspect(CODEX)
        self.assertEqual(inspection.discovery_status, DISCOVERY_CONFIG_MALFORMED)
        self.assertTrue(any(w.code == "config_malformed" for w in inspection.warnings))
        plan = self.plan(CODEX)
        self.assertEqual(plan.status, PLAN_UNAVAILABLE)

    def test_opencode_permission_denied_stays_unverified(self):
        real_stat = Path.stat

        def deny_opencode_config(path, *args, **kwargs):
            if str(path).replace("\\", "/").endswith(
                "/.config/opencode/opencode.json"
            ):
                raise PermissionError("permission denied")
            return real_stat(path, *args, **kwargs)

        with mock.patch("relinkra.host_discovery.Path.stat", deny_opencode_config):
            inspection = self.inspect(OPENCODE)
        self.assertEqual(inspection.discovery_status, DISCOVERY_CONFIG_UNSUPPORTED)
        self.assertIsNone(inspection.document)
        self.assertTrue(any(w.code == "config_unreadable" for w in inspection.warnings))

    def test_unsupported_root_shape_is_its_own_state(self):
        self.claude_config("[1, 2, 3]")
        inspection = self.inspect(CLAUDE)
        self.assertEqual(inspection.discovery_status, DISCOVERY_CONFIG_UNSUPPORTED)

    def test_unsupported_container_shape_is_reported(self):
        self.claude_config({"mcpServers": ["a", "b"]})
        inspection = self.inspect(CLAUDE)
        self.assertEqual(inspection.discovery_status, DISCOVERY_CONFIG_UNSUPPORTED)

    def test_oversized_config_is_refused(self):
        self.claude_config("x" * (MAX_CONFIG_BYTES + 1024))
        inspection = self.inspect(CLAUDE)
        self.assertEqual(inspection.discovery_status, DISCOVERY_CONFIG_UNSUPPORTED)
        self.assertTrue(any(w.code == "config_too_large" for w in inspection.warnings))

    def test_correct_registration_is_detected(self):
        self.claude_config(
            {"mcpServers": {MANAGED_SERVER_NAME: {"command": "py", "args": ["-m", SERVER_MODULE]}}}
        )
        inspection = self.inspect(CLAUDE)
        self.assertEqual(inspection.registration_state, REGISTRATION_ALREADY_CONNECTED)

    def test_foreign_entry_of_the_same_name_is_a_conflict(self):
        self.claude_config(
            {"mcpServers": {MANAGED_SERVER_NAME: {"command": "node", "args": ["s.js"]}}}
        )
        inspection = self.inspect(CLAUDE)
        self.assertEqual(inspection.registration_state, REGISTRATION_CONFLICT)

    def test_unrelated_entries_do_not_look_like_a_registration(self):
        self.claude_config(
            {"mcpServers": {"context7": {"command": "npx", "args": ["-y", "c7"]}}}
        )
        inspection = self.inspect(CLAUDE)
        self.assertEqual(inspection.discovery_status, DISCOVERY_DISCOVERED)
        self.assertEqual(inspection.registration_state, REGISTRATION_ABSENT)

    def test_declared_discovery_states_are_from_the_closed_vocabulary(self):
        self.claude_config({"mcpServers": {}})
        for spec in CONNECTORS:
            with self.subTest(connector=spec.connector_id):
                self.assertIn(self.inspect(spec).discovery_status, DISCOVERY_STATUSES)

    def test_discovery_never_writes(self):
        self.claude_config({"mcpServers": {}})
        before = _snapshot(self.home)
        self.inspect(CLAUDE)
        self.assertEqual(_snapshot(self.home), before)


def _snapshot(root: Path):
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class PlanTests(HostFixtureCase):
    def ops(self, plan):
        return [operation.op for operation in plan.operations]

    def test_add_into_an_existing_file(self):
        self.claude_config({"mcpServers": {"context7": {"command": "npx", "args": []}}})
        plan = self.plan(CLAUDE)
        self.assertEqual(plan.status, PLAN_READY)
        self.assertEqual(plan.registration_state, REGISTRATION_ABSENT)
        self.assertEqual(
            self.ops(plan),
            [OP_BACKUP_FILE, OP_ADD_OBJECT_MEMBER, OP_VALIDATE_JSON, OP_REQUEST_RESTART],
        )
        self.assertFalse(plan.idempotent)

    def test_add_into_an_absent_file_creates_it(self):
        self.installed.add("claude")
        plan = self.plan(CLAUDE)
        self.assertEqual(plan.status, PLAN_READY)
        self.assertEqual(self.ops(plan)[0], OP_CREATE_FILE)

    def test_correct_registration_plans_a_no_op(self):
        self.claude_config(
            {
                "mcpServers": {
                    MANAGED_SERVER_NAME: {
                        "command": LAUNCH.command,
                        "args": list(LAUNCH.args),
                    }
                }
            }
        )
        plan = self.plan(CLAUDE)
        self.assertEqual(plan.status, PLAN_READY)
        self.assertEqual(plan.registration_state, REGISTRATION_ALREADY_CONNECTED)
        self.assertEqual(self.ops(plan), [OP_NO_OP])
        self.assertTrue(plan.idempotent)

    def test_stale_managed_entry_plans_an_update(self):
        self.claude_config(
            {
                "mcpServers": {
                    MANAGED_SERVER_NAME: {
                        "command": "old-python",
                        "args": ["-m", SERVER_MODULE, "--workspace-root", "/elsewhere"],
                    }
                }
            }
        )
        plan = self.plan(CLAUDE)
        self.assertEqual(plan.status, PLAN_READY)
        self.assertEqual(plan.registration_state, REGISTRATION_NEEDS_UPDATE)
        self.assertIn(OP_REPLACE_MANAGED_MEMBER, self.ops(plan))

    def test_conflicting_entry_blocks_the_plan(self):
        self.claude_config(
            {"mcpServers": {MANAGED_SERVER_NAME: {"command": "node", "args": ["s.js"]}}}
        )
        plan = self.plan(CLAUDE)
        self.assertEqual(plan.status, PLAN_BLOCKED)
        self.assertEqual(plan.registration_state, REGISTRATION_CONFLICT)
        self.assertEqual(plan.operations, [])
        self.assertTrue(plan.conflicts)

    def test_malformed_config_makes_the_plan_unavailable(self):
        self.claude_config("{ broken")
        plan = self.plan(CLAUDE)
        self.assertEqual(plan.status, PLAN_UNAVAILABLE)
        self.assertIn("could not be parsed", plan.unavailable_reason)

    def test_unresolved_launch_makes_the_plan_unavailable(self):
        self.claude_config({"mcpServers": {}})
        plan = self.plan(CLAUDE, launch=LaunchContract(resolved=False))
        self.assertEqual(plan.status, PLAN_UNAVAILABLE)

    def test_generic_connector_has_no_configuration_to_mutate(self):
        plan = self.plan(GENERIC)
        self.assertEqual(plan.status, PLAN_UNAVAILABLE)
        self.assertIn("no configuration file", plan.unavailable_reason)

    def test_unimplemented_connector_is_honest(self):
        plan = self.plan(DEVIN_CLOUD)
        self.assertEqual(plan.status, PLAN_UNAVAILABLE)
        self.assertIn("no local configuration file", plan.unavailable_reason)

    @unittest.skipUnless(toml_parser_available(), _REQUIRES_TOMLLIB)
    def test_codex_plans_against_its_toml_container(self):
        # R4C.1D opened the Codex write path: planning a TOML host goes
        # through the same format-agnostic decision as JSON hosts.
        self.write_config(".codex", "config.toml", content='[mcp_servers.other]\ncommand = "x"\n')
        plan = self.plan(CODEX)
        self.assertEqual(plan.status, PLAN_READY)
        detail = next(
            op.detail for op in plan.operations if op.op == OP_ADD_OBJECT_MEMBER
        )
        self.assertIn("mcp_servers.relinkra", detail)

    def test_opencode_uses_its_own_entry_shape(self):
        self.write_config(
            ".config", "opencode", "opencode.json", content={"mcp": {}}
        )
        plan = self.plan(OPENCODE)
        self.assertEqual(plan.status, PLAN_READY)
        detail = next(
            op.detail for op in plan.operations if op.op == OP_ADD_OBJECT_MEMBER
        )
        self.assertIn("mcp.relinkra", detail)

    def test_devin_desktop_never_plans_against_a_legacy_file(self):
        # R4C.1E Gate A declares the current-product locations. A
        # legacy-only install is read as evidence, but the plan aims at
        # the first declared current-product candidate — a create path,
        # the same contract an absent config gets for any other host.
        self.write_config(
            ".codeium", "windsurf", "mcp_config.json", content={"mcpServers": {}}
        )
        inspection = self.inspect(DEVIN_DESKTOP)
        self.assertEqual(inspection.location.location_id, "windsurf_user_mcp")
        plan = self.plan(DEVIN_DESKTOP)
        self.assertEqual(plan.status, PLAN_READY)
        self.assertEqual(plan.target_ref, "devin-desktop:devin_workspace_local_mcp")
        self.assertEqual(self.ops(plan)[0], OP_CREATE_FILE)

    def test_devin_desktop_plans_against_the_first_current_location(self):
        self.write_config(
            ".config", "devin", "mcp_config.json", content={"mcpServers": {}}
        )
        inspection = self.inspect(DEVIN_DESKTOP)
        self.assertEqual(inspection.location.location_id, "devin_user_config_mcp")
        plan = self.plan(DEVIN_DESKTOP)
        self.assertEqual(plan.status, PLAN_READY)
        self.assertEqual(plan.target_ref, "devin-desktop:devin_user_config_mcp")

    def test_every_operation_declares_conditions_and_rollback(self):
        self.claude_config({"mcpServers": {}})
        for operation in self.plan(CLAUDE).operations:
            with self.subTest(op=operation.op):
                self.assertIn(operation.op, OPERATIONS)
                self.assertTrue(operation.target_ref)
                self.assertTrue(operation.preconditions)
                self.assertTrue(operation.postconditions)
                self.assertTrue(operation.rollback)

    def test_target_ref_is_semantic_never_a_path(self):
        self.claude_config({"mcpServers": {}})
        plan = self.plan(CLAUDE)
        self.assertEqual(plan.target_ref, "claude:claude_user_config")
        self.assertFalse(contains_absolute_path(plan.target_ref))

    def test_plan_output_carries_no_machine_local_value(self):
        self.claude_config({"mcpServers": {}})
        plan = self.plan(CLAUDE, launch=SOURCE_LAUNCH)
        for value in iter_strings(plan.to_dict()):
            self.assertFalse(contains_absolute_path(value), value)

    def test_operation_detail_names_env_keys_never_values(self):
        self.claude_config({"mcpServers": {}})
        plan = self.plan(CLAUDE, launch=SOURCE_LAUNCH)
        detail = next(
            op.detail for op in plan.operations if op.op == OP_ADD_OBJECT_MEMBER
        )
        self.assertIn("PYTHONPATH", detail)
        self.assertNotIn("/srv/code/repo", detail)

    def test_planning_never_writes(self):
        self.claude_config({"mcpServers": {"context7": {"command": "npx", "args": []}}})
        before = _snapshot(self.home)
        self.plan(CLAUDE)
        self.assertEqual(_snapshot(self.home), before)


class IdempotencyTests(HostFixtureCase):
    def test_plan_twice_produces_identical_output(self):
        self.claude_config({"mcpServers": {"context7": {"command": "npx", "args": []}}})
        first = json.dumps(self.plan(CLAUDE).to_dict(), sort_keys=True)
        second = json.dumps(self.plan(CLAUDE).to_dict(), sort_keys=True)
        self.assertEqual(first, second)

    def test_simulated_apply_then_replan_is_a_no_op(self):
        path = self.claude_config(
            {"mcpServers": {"context7": {"command": "npx", "args": ["-y", "c7"]}}}
        )
        entry = CLAUDE.entry_builder(LAUNCH)
        document = parse_json_document(path.read_text(encoding="utf-8"))
        applied = apply_member(
            document, self.claude_container_path(), MANAGED_SERVER_NAME, entry
        )
        path.write_text(serialize_json_document(applied), encoding="utf-8")

        plan = self.plan(CLAUDE)
        self.assertEqual([op.op for op in plan.operations], [OP_NO_OP])
        self.assertTrue(plan.idempotent)
        # The user's own server survived the simulated apply untouched.
        after = parse_json_document(path.read_text(encoding="utf-8"))
        servers = after["projects"][claude_project_key(self.workspace)]["mcpServers"]
        self.assertEqual(servers["context7"], {"command": "npx", "args": ["-y", "c7"]})

    def test_two_independent_planners_agree(self):
        self.claude_config({"mcpServers": {}})
        left = build_plan(CLAUDE, self.inspect(CLAUDE), LAUNCH).to_dict()
        right = build_plan(CLAUDE, self.inspect(CLAUDE), LAUNCH).to_dict()
        self.assertEqual(left, right)


class CheckTests(HostFixtureCase):
    def check(self, spec, launch=LAUNCH):
        return check_registration(spec, self.inspect(spec), launch)

    def test_absent_registration_is_reported(self):
        result = self.check(CLAUDE)
        self.assertFalse(result.valid)
        self.assertIn("no Relinkra registration", result.findings[0])

    def test_conflicting_registration_is_reported(self):
        self.claude_config(
            {"mcpServers": {MANAGED_SERVER_NAME: {"command": "node", "args": ["s.js"]}}}
        )
        result = self.check(CLAUDE)
        self.assertFalse(result.valid)
        self.assertEqual(result.registration_state, REGISTRATION_CONFLICT)

    def test_matching_registration_is_valid(self):
        self.claude_config(
            {
                "mcpServers": {
                    MANAGED_SERVER_NAME: {
                        "command": LAUNCH.command,
                        "args": list(LAUNCH.args),
                    }
                }
            }
        )
        result = self.check(CLAUDE)
        self.assertTrue(result.valid, result.findings)
        self.assertTrue(result.matches_workspace)

    def test_registration_pointing_at_another_workspace_is_flagged(self):
        self.claude_config(
            {
                "mcpServers": {
                    MANAGED_SERVER_NAME: {
                        "command": "py",
                        "args": ["-m", SERVER_MODULE, "--workspace-root", "/elsewhere"],
                    }
                }
            }
        )
        result = self.check(CLAUDE)
        self.assertFalse(result.matches_workspace)
        self.assertFalse(result.valid)

    def test_registration_without_a_workspace_root_is_flagged(self):
        self.claude_config(
            {"mcpServers": {MANAGED_SERVER_NAME: {"command": "py", "args": ["-m", SERVER_MODULE]}}}
        )
        result = self.check(CLAUDE)
        self.assertFalse(result.valid)
        self.assertIn("does not pin a workspace root", " ".join(result.findings))

    def test_source_checkout_without_environment_is_flagged(self):
        self.claude_config(
            {
                "mcpServers": {
                    MANAGED_SERVER_NAME: {
                        "command": "py",
                        "args": list(SOURCE_LAUNCH.args),
                    }
                }
            }
        )
        result = self.check(CLAUDE, launch=SOURCE_LAUNCH)
        self.assertFalse(result.valid)
        self.assertIn("passes no environment", " ".join(result.findings))

    def test_check_output_is_portable(self):
        self.claude_config({"mcpServers": {}})
        for value in iter_strings(self.check(CLAUDE).to_dict()):
            self.assertFalse(contains_absolute_path(value), value)

    def test_check_never_writes(self):
        self.claude_config({"mcpServers": {}})
        before = _snapshot(self.home)
        self.check(CLAUDE)
        self.assertEqual(_snapshot(self.home), before)


class CheckPlanAgreementTests(HostFixtureCase):
    """`check` and `plan` must never disagree about the same file."""

    def test_check_reports_the_staleness_plan_reports(self):
        # The workspace root matches and the environment branch is
        # skipped, so the only signal that this entry is out of date is
        # the command itself — the very thing a token-level check misses.
        self.claude_config(
            {
                "mcpServers": {
                    MANAGED_SERVER_NAME: {
                        "command": "python3.10",
                        "args": list(LAUNCH.args),
                    }
                }
            }
        )
        inspection = self.inspect(CLAUDE)
        plan = build_plan(CLAUDE, inspection, LAUNCH)
        result = check_registration(CLAUDE, inspection, LAUNCH)
        self.assertEqual(plan.registration_state, REGISTRATION_NEEDS_UPDATE)
        self.assertEqual(result.registration_state, REGISTRATION_NEEDS_UPDATE)
        self.assertFalse(result.valid)
        self.assertIn("out of date", " ".join(result.findings))

    def test_a_correct_registration_still_checks_clean(self):
        self.claude_config(
            {
                "mcpServers": {
                    MANAGED_SERVER_NAME: {
                        "command": LAUNCH.command,
                        "args": list(LAUNCH.args),
                    }
                }
            }
        )
        inspection = self.inspect(CLAUDE)
        self.assertEqual(
            [op.op for op in build_plan(CLAUDE, inspection, LAUNCH).operations],
            [OP_NO_OP],
        )
        self.assertTrue(check_registration(CLAUDE, inspection, LAUNCH).valid)

    def test_unknown_state_never_claims_absence(self):
        # Simulates an interpreter without tomllib: the config exists and
        # was not parsed, so nothing is known either way. Claiming "no
        # registration found" would contradict the state field beside it.
        self.write_config(
            ".codex",
            "config.toml",
            content='[mcp_servers.other]\ncommand = "x"\n',
        )
        original = relinkra_connectors._load_toml
        relinkra_connectors._load_toml = lambda text: None
        try:
            inspection = self.inspect(CODEX)
            result = check_registration(CODEX, inspection, LAUNCH)
        finally:
            relinkra_connectors._load_toml = original
        self.assertEqual(result.registration_state, "unknown")
        self.assertFalse(result.valid)
        joined = " ".join(result.findings)
        self.assertNotIn("no Relinkra registration", joined)
        self.assertIn("could not be determined", joined)


class ConcurrentPlanningTests(HostFixtureCase):
    def test_parallel_planners_agree_and_corrupt_nothing(self):
        self.claude_config(
            {"mcpServers": {"context7": {"command": "npx", "args": ["-y", "c7"]}}}
        )
        before = _snapshot(self.home)
        results = []
        errors = []
        lock = threading.Lock()
        barrier = threading.Barrier(6)

        def planner():
            try:
                barrier.wait(timeout=10)
                payload = json.dumps(self.plan(CLAUDE).to_dict(), sort_keys=True)
                with lock:
                    results.append(payload)
            except Exception as exc:  # asserted below
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=planner) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)

        self.assertEqual([type(e).__name__ for e in errors], [])
        self.assertEqual(len(set(results)), 1)
        self.assertEqual(_snapshot(self.home), before)


class CapabilityHonestyTests(HostFixtureCase):
    def test_a_producible_plan_does_not_imply_a_proven_host(self):
        self.claude_config({"mcpServers": {}})
        inspection = self.inspect(CLAUDE)
        plan = build_plan(CLAUDE, inspection, LAUNCH)
        report = build_report(CLAUDE, inspection, LAUNCH)
        self.assertEqual(plan.status, PLAN_READY)
        self.assertFalse(report.capabilities.real_host_launch_proven)

    def test_registration_detected_requires_an_actual_registration(self):
        self.claude_config({"mcpServers": {}})
        report = build_report(CLAUDE, self.inspect(CLAUDE), LAUNCH)
        self.assertFalse(report.capabilities.registration_detected)

        self.claude_config(
            {"mcpServers": {MANAGED_SERVER_NAME: {"command": "py", "args": ["-m", SERVER_MODULE]}}}
        )
        report = build_report(CLAUDE, self.inspect(CLAUDE), LAUNCH)
        self.assertTrue(report.capabilities.registration_detected)

    def test_configuration_validated_requires_a_parsed_document(self):
        self.claude_config("{ broken")
        report = build_report(CLAUDE, self.inspect(CLAUDE), LAUNCH)
        self.assertFalse(report.capabilities.configuration_validated)

    def test_process_contract_follows_the_launch_contract(self):
        self.claude_config({"mcpServers": {}})
        unresolved = build_report(CLAUDE, self.inspect(CLAUDE), LaunchContract())
        self.assertFalse(unresolved.capabilities.mcp_process_contract_validated)
        resolved_report = build_report(CLAUDE, self.inspect(CLAUDE), LAUNCH)
        self.assertTrue(resolved_report.capabilities.mcp_process_contract_validated)

    def test_report_output_is_portable(self):
        self.claude_config({"mcpServers": {}})
        report = build_report(CLAUDE, self.inspect(CLAUDE), SOURCE_LAUNCH)
        for value in iter_strings(report.to_dict()):
            self.assertFalse(contains_absolute_path(value), value)

    def test_registration_planned_reflects_an_actual_plan(self):
        self.claude_config({"mcpServers": {}})
        inspection = self.inspect(CLAUDE)
        without = build_report(CLAUDE, inspection, LAUNCH)
        self.assertFalse(without.capabilities.registration_planned)
        plan = build_plan(CLAUDE, inspection, LAUNCH)
        with_plan = build_report(CLAUDE, inspection, LAUNCH, plan)
        self.assertTrue(with_plan.capabilities.registration_planned)

    def test_registration_planned_is_false_for_an_unavailable_plan(self):
        inspection = self.inspect(DEVIN_CLOUD)
        plan = build_plan(DEVIN_CLOUD, inspection, LAUNCH)
        report = build_report(DEVIN_CLOUD, inspection, LAUNCH, plan)
        self.assertFalse(report.capabilities.registration_planned)

    def test_implementation_exists_is_structural_not_a_name_check(self):
        # GENERIC owns no config file, so this must not be decided by
        # comparing connector_id against a hardcoded "generic".
        generic = build_report(GENERIC, self.inspect(GENERIC), LAUNCH)
        self.assertTrue(generic.capabilities.implementation_exists)
        devin = build_report(DEVIN_CLOUD, self.inspect(DEVIN_CLOUD), LAUNCH)
        self.assertFalse(devin.capabilities.implementation_exists)

    def test_machine_rendering_is_available_but_opt_in(self):
        self.claude_config({"mcpServers": {}})
        report = build_report(CLAUDE, self.inspect(CLAUDE), LAUNCH)
        active = [loc for loc in report.locations if loc.exists][0]
        self.assertNotIn("path", active.to_dict())
        self.assertIn("path", active.to_machine_dict())


class ClaudeProjectKeyTests(unittest.TestCase):
    """The projects[] key normalization, verified against Claude 2.1.220."""

    def test_windows_paths_get_forward_slashes_and_an_uppercase_drive(self):
        self.assertEqual(
            claude_project_key(r"C:\Desarrollos\relinkra"), "C:/Desarrollos/relinkra"
        )
        self.assertEqual(claude_project_key(r"c:\x\y"), "C:/x/y")

    def test_posix_paths_pass_through_unchanged(self):
        self.assertEqual(claude_project_key("/home/user/proj"), "/home/user/proj")

    def test_trailing_separators_are_stripped(self):
        self.assertEqual(claude_project_key("/home/user/proj/"), "/home/user/proj")
        self.assertEqual(claude_project_key("C:/X/y/"), "C:/X/y")

    def test_path_objects_and_strings_agree(self):
        self.assertEqual(claude_project_key(PurePosixPath("/a/b")), "/a/b")
        self.assertEqual(
            claude_project_key(PureWindowsPath(r"D:\code\repo")), "D:/code/repo"
        )


class ClaudeContainerResolutionTests(HostFixtureCase):
    def test_the_container_resolves_to_local_scope_with_a_workspace(self):
        inspection = self.inspect(CLAUDE)
        self.assertEqual(inspection.container_path, self.claude_container_path())

    def test_the_container_falls_back_to_user_scope_without_a_workspace(self):
        inspection = self.inspect(CLAUDE, workspace_root=None)
        self.assertEqual(inspection.container_path, ("mcpServers",))

    def test_container_labels_redact_the_project_key(self):
        label = container_label(self.claude_container_path())
        self.assertEqual(label, "projects.<project>.mcpServers")
        self.assertFalse(contains_absolute_path(label))
        self.assertEqual(container_label(("mcpServers",)), "mcpServers")

    def test_plan_targets_the_state_file_local_scope(self):
        self.claude_config({"mcpServers": {}})
        plan = self.plan(CLAUDE)
        self.assertEqual(plan.target_ref, "claude:claude_user_config")
        detail = next(
            op.detail for op in plan.operations if op.op == OP_ADD_OBJECT_MEMBER
        )
        self.assertIn("projects.<project>.mcpServers.relinkra", detail)

    def test_plan_output_never_carries_the_project_key(self):
        self.claude_config({"mcpServers": {}})
        plan = self.plan(CLAUDE)
        key = claude_project_key(self.workspace)
        for value in iter_strings(plan.to_dict()):
            self.assertNotIn(key, value)
            self.assertFalse(contains_absolute_path(value), value)


class ClaudeLegacyLocationTests(HostFixtureCase):
    """~/.claude/settings.json is discovery-only for Claude Code 2.1+."""

    RELINKRA_ENTRY = {"command": "py", "args": ["-m", SERVER_MODULE]}

    def test_legacy_locations_are_marked_discovery_only(self):
        flags = {loc.location_id: loc.discovery_only for loc in CLAUDE.locations}
        self.assertFalse(flags["claude_user_config"])
        self.assertTrue(flags["claude_user_settings"])
        self.assertTrue(flags["claude_workspace_mcp"])
        self.assertTrue(flags["claude_workspace_settings_local"])

    def test_a_legacy_only_registration_never_becomes_the_active_target(self):
        self.legacy_settings_config(
            {"mcpServers": {MANAGED_SERVER_NAME: self.RELINKRA_ENTRY}}
        )
        inspection = self.inspect(CLAUDE)
        self.assertIsNone(inspection.location)
        self.assertEqual(inspection.registration_state, REGISTRATION_ABSENT)
        self.assertEqual(inspection.discovery_status, DISCOVERY_NOT_INSTALLED)

    def test_a_legacy_entry_does_not_make_check_report_connected(self):
        self.legacy_settings_config(
            {"mcpServers": {MANAGED_SERVER_NAME: self.RELINKRA_ENTRY}}
        )
        self.claude_config({"mcpServers": {}})
        inspection = self.inspect(CLAUDE)
        self.assertEqual(inspection.location.location_id, "claude_user_config")
        result = check_registration(CLAUDE, inspection, LAUNCH)
        self.assertEqual(result.registration_state, REGISTRATION_ABSENT)
        self.assertFalse(result.valid)

    def test_the_state_file_wins_over_the_legacy_file(self):
        self.legacy_settings_config(
            {"mcpServers": {MANAGED_SERVER_NAME: self.RELINKRA_ENTRY}}
        )
        self.claude_config(
            {"mcpServers": {MANAGED_SERVER_NAME: self.RELINKRA_ENTRY}}
        )
        inspection = self.inspect(CLAUDE)
        self.assertEqual(inspection.location.location_id, "claude_user_config")
        self.assertEqual(inspection.registration_state, REGISTRATION_ALREADY_CONNECTED)


if __name__ == "__main__":
    unittest.main()
