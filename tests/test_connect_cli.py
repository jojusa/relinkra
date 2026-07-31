"""Tests for the ``relinkra connect`` CLI surface (R4B).

Every test drives the real product CLI through ``main(argv)`` with
captured streams, so exit codes, stdout and stderr are asserted exactly
as a user experiences them. Host discovery is pointed at a temporary home
containing fixture configs, so nothing on the machine running the suite
is read or written.
"""

from __future__ import annotations

import builtins
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from relinkra import connect_cli
from relinkra.connector import MANAGED_SERVER_NAME, iter_strings
from relinkra.connectors import CLAUDE, SERVER_MODULE, resolve_launch
from relinkra.handoff import contains_absolute_path
from relinkra.host_discovery import (
    SYSTEM_LINUX,
    SYSTEM_WINDOWS,
    DiscoveryEnvironment,
)
from relinkra.product_cli import (
    EXIT_ACTION_REQUIRED,
    EXIT_ERROR,
    EXIT_OK,
    main,
    registry_path,
)

_SECRET = "sk-live-DO-NOT-LEAK-0123456789"


class _ReadOnlyFilesystem:
    """Make every write syscall fail for the duration of a block.

    The strongest available proof that a command is read-only: instead of
    checking afterwards that nothing changed — which only covers the
    paths a test thought to look at — any attempt to create, replace or
    delete ANYTHING raises immediately.
    """

    _WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC

    def __enter__(self):
        self._open = builtins.open
        self._os_open = os.open
        self._replace = os.replace
        self._rename = os.rename
        self._remove = os.remove
        self._unlink = os.unlink
        self._mkdir = os.mkdir
        self._makedirs = os.makedirs
        self._copy2 = shutil.copy2

        def guarded_open(file, mode="r", *args, **kwargs):
            if any(flag in mode for flag in ("w", "a", "x", "+")):
                raise AssertionError(f"write attempted on {file!r} (mode {mode!r})")
            return self._open(file, mode, *args, **kwargs)

        def guarded_os_open(path, flags, *args, **kwargs):
            if flags & self._WRITE_FLAGS:
                raise AssertionError(f"write attempted on {path!r}")
            return self._os_open(path, flags, *args, **kwargs)

        def refuse(name):
            def guard(*args, **kwargs):
                raise AssertionError(f"{name} attempted: {args!r}")

            return guard

        builtins.open = guarded_open
        os.open = guarded_os_open
        os.replace = refuse("os.replace")
        os.rename = refuse("os.rename")
        os.remove = refuse("os.remove")
        os.unlink = refuse("os.unlink")
        os.mkdir = refuse("os.mkdir")
        os.makedirs = refuse("os.makedirs")
        shutil.copy2 = refuse("shutil.copy2")
        return self

    def __exit__(self, *exc):
        builtins.open = self._open
        os.open = self._os_open
        os.replace = self._replace
        os.rename = self._rename
        os.remove = self._remove
        os.unlink = self._unlink
        os.mkdir = self._mkdir
        os.makedirs = self._makedirs
        shutil.copy2 = self._copy2
        return False


class ConnectCLICase(unittest.TestCase):
    """A fake repository plus a temporary home holding host fixtures."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="relinkra-connect-cli-")
        self.addCleanup(self._temp.cleanup)
        base = Path(self._temp.name)
        self.home = base / "home"
        self.home.mkdir()
        self.repo = base / "repo"
        (self.repo / ".git").mkdir(parents=True)
        self.installed = set()

        # Point discovery at the fixture home. Patching the CLI's own
        # constructor keeps the whole command path real — argparse, the
        # renderers, the portability audit — while nothing on the machine
        # running these tests is read.
        outer = self

        def fake_current(workspace_root=None):
            return DiscoveryEnvironment(
                system=SYSTEM_WINDOWS if os.name == "nt" else SYSTEM_LINUX,
                home=outer.home,
                env={},
                workspace_root=Path(workspace_root) if workspace_root else None,
                which=lambda name: (
                    "/usr/bin/" + name if name in outer.installed else None
                ),
            )

        original = connect_cli.DiscoveryEnvironment
        connect_cli.DiscoveryEnvironment = type(
            "FixtureDiscoveryEnvironment", (), {"current": staticmethod(fake_current)}
        )
        self.addCleanup(setattr, connect_cli, "DiscoveryEnvironment", original)

    # -- fixtures ---------------------------------------------------------

    def write_config(self, *parts, content):
        path = self.home.joinpath(*parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        text = content if isinstance(content, str) else json.dumps(content, indent=2)
        path.write_text(text, encoding="utf-8")
        return path

    def claude_config(self, content):
        return self.write_config(".claude", "settings.json", content=content)

    def registered_claude_entry(self):
        """The entry a correct registration for THIS machine would hold.

        Built from the real launch contract rather than hand-written, so
        the "already connected" tests assert against what the planner
        would actually produce instead of a fixture that only resembles
        it.
        """
        launch = resolve_launch(self.repo, registry_path(self.repo))
        return CLAUDE.entry_builder(launch)

    # -- driving the CLI --------------------------------------------------

    def run_cli(self, *argv, path=None):
        out, err = io.StringIO(), io.StringIO()
        args = ["connect", *argv, "--path", str(path or self.repo)]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(args)
        return code, out.getvalue(), err.getvalue()

    def run_json(self, *argv, path=None):
        code, out, err = self.run_cli(*argv, "--json", path=path)
        return code, json.loads(out), err

    def snapshot(self):
        return {
            str(p.relative_to(self.home)): p.read_bytes()
            for p in sorted(self.home.rglob("*"))
            if p.is_file()
        }


class ListTests(ConnectCLICase):
    def test_lists_every_connector(self):
        code, payload, _ = self.run_json("list")
        self.assertEqual(code, EXIT_OK)
        ids = [entry["connector_id"] for entry in payload["connectors"]]
        self.assertEqual(
            ids,
            ["generic", "claude", "opencode", "codex", "devin-desktop", "devin-cloud"],
        )

    def test_reports_that_nothing_is_host_proven(self):
        code, payload, _ = self.run_json("list")
        self.assertFalse(payload["real_host_launch_proven"])
        for entry in payload["connectors"]:
            self.assertFalse(entry["capabilities"]["real_host_launch_proven"])

    def test_human_output_states_the_proof_caveat(self):
        code, out, _ = self.run_cli("list")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("PROVEN", out)
        self.assertIn("No connector has been proven yet", out)

    def test_list_works_outside_a_repository(self):
        outside = Path(self._temp.name) / "not-a-repo"
        outside.mkdir()
        code, _, _ = self.run_cli("list", path=outside)
        self.assertEqual(code, EXIT_OK)

    def test_json_output_is_deterministic(self):
        first = self.run_cli("list", "--json")[1]
        second = self.run_cli("list", "--json")[1]
        self.assertEqual(first, second)


class InspectTests(ConnectCLICase):
    def test_reports_a_discovered_host(self):
        self.claude_config({"mcpServers": {}})
        code, payload, _ = self.run_json("inspect", "claude")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(payload["discovery_status"], "discovered")
        self.assertEqual(payload["registration_state"], "absent")

    def test_reports_a_host_that_is_not_installed(self):
        code, payload, _ = self.run_json("inspect", "windsurf")
        self.assertEqual(payload["discovery_status"], "not_installed")

    def test_reports_a_malformed_configuration(self):
        self.claude_config("{ broken")
        code, payload, _ = self.run_json("inspect", "claude")
        self.assertEqual(payload["discovery_status"], "config_malformed")
        self.assertTrue(payload["warnings"])

    def test_resolves_an_alias(self):
        code, payload, _ = self.run_json("inspect", "claude-code")
        self.assertEqual(payload["connector_id"], "claude")

    def test_unknown_connector_is_a_command_failure(self):
        code, out, err = self.run_cli("inspect", "emacs")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("unknown connector", err)
        self.assertIn("connect list", err)

    def test_locations_are_hints_not_paths_by_default(self):
        self.claude_config({"mcpServers": {}})
        code, payload, _ = self.run_json("inspect", "claude")
        for location in payload["locations"]:
            self.assertNotIn("path", location)
            self.assertFalse(contains_absolute_path(location["display_hint"]))

    def test_reveal_paths_opts_into_machine_local_output(self):
        self.claude_config({"mcpServers": {}})
        code, payload, _ = self.run_json("inspect", "claude", "--reveal-paths")
        self.assertEqual(code, EXIT_OK)
        paths = [location["path"] for location in payload["locations"]]
        self.assertTrue(any(str(self.home) in str(path) for path in paths))

    def test_human_output_never_carries_a_path(self):
        self.claude_config({"mcpServers": {}})
        code, out, _ = self.run_cli("inspect", "claude")
        self.assertEqual(code, EXIT_OK)
        self.assertNotIn(str(self.home), out)


class PlanTests(ConnectCLICase):
    def test_ready_plan_exits_zero(self):
        self.claude_config({"mcpServers": {"context7": {"command": "npx", "args": []}}})
        code, payload, _ = self.run_json("plan", "claude")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(payload["status"], "ready")
        self.assertTrue(payload["dry_run"])
        self.assertFalse(payload["apply_available"])

    def test_conflict_needs_a_human(self):
        self.claude_config(
            {"mcpServers": {MANAGED_SERVER_NAME: {"command": "node", "args": ["s.js"]}}}
        )
        code, payload, _ = self.run_json("plan", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertEqual(payload["status"], "blocked")
        self.assertTrue(payload["conflicts"])

    def test_unavailable_plan_needs_a_human(self):
        code, payload, _ = self.run_json("plan", "codex")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertEqual(payload["status"], "unavailable")

    def test_existing_registration_plans_a_no_op(self):
        self.claude_config(
            {"mcpServers": {MANAGED_SERVER_NAME: self.registered_claude_entry()}}
        )
        code, payload, _ = self.run_json("plan", "claude")
        self.assertEqual([op["op"] for op in payload["operations"]], ["no_op"])
        self.assertTrue(payload["idempotent"])

    def test_dry_run_flag_is_accepted_and_changes_nothing(self):
        self.claude_config({"mcpServers": {}})
        plain = self.run_cli("plan", "claude", "--json")[1]
        dry = self.run_cli("plan", "claude", "--dry-run", "--json")[1]
        self.assertEqual(plain, dry)

    def test_plan_is_deterministic_across_runs(self):
        self.claude_config({"mcpServers": {"other": {"command": "x", "args": []}}})
        first = self.run_cli("plan", "claude", "--json")[1]
        second = self.run_cli("plan", "claude", "--json")[1]
        self.assertEqual(first, second)

    def test_plan_requires_a_repository(self):
        outside = Path(self._temp.name) / "loose"
        outside.mkdir()
        code, _, err = self.run_cli("plan", "claude", path=outside)
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("git repository", err)

    def test_human_output_says_it_wrote_nothing(self):
        self.claude_config({"mcpServers": {}})
        code, out, _ = self.run_cli("plan", "claude")
        self.assertIn("wrote nothing", out)


class CheckTests(ConnectCLICase):
    def test_missing_registration_needs_a_human(self):
        self.claude_config({"mcpServers": {}})
        code, payload, _ = self.run_json("check", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertFalse(payload["valid"])

    def test_matching_registration_is_valid(self):
        self.claude_config(
            {"mcpServers": {MANAGED_SERVER_NAME: self.registered_claude_entry()}}
        )
        code, payload, _ = self.run_json("check", "claude")
        self.assertEqual(code, EXIT_OK)
        self.assertTrue(payload["valid"], payload["findings"])
        self.assertTrue(payload["matches_workspace"])

    def test_conflicting_registration_needs_a_human(self):
        self.claude_config(
            {"mcpServers": {MANAGED_SERVER_NAME: {"command": "node", "args": ["s.js"]}}}
        )
        code, payload, _ = self.run_json("check", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertEqual(payload["registration_state"], "conflict")

    def test_check_requires_a_repository(self):
        outside = Path(self._temp.name) / "loose2"
        outside.mkdir()
        code, _, err = self.run_cli("check", "claude", path=outside)
        self.assertEqual(code, EXIT_ERROR)


class GenericTests(ConnectCLICase):
    def test_emits_the_launch_contract(self):
        code, payload, _ = self.run_json("generic")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(payload["server_name"], MANAGED_SERVER_NAME)
        self.assertEqual(payload["launch"]["transport"], "stdio")
        self.assertEqual(payload["launch"]["module"], SERVER_MODULE)

    def test_portable_output_redacts_machine_local_values(self):
        code, payload, _ = self.run_json("generic")
        self.assertEqual(payload["launch"]["command"], "<interpreter>")
        self.assertNotIn("env", payload["launch"])
        self.assertNotIn("machine_local", payload)
        for value in iter_strings(payload):
            self.assertFalse(contains_absolute_path(value), value)

    def test_reveal_paths_emits_a_runnable_command(self):
        code, payload, _ = self.run_json("generic", "--reveal-paths")
        self.assertEqual(code, EXIT_OK)
        machine = payload["machine_local"]
        self.assertEqual(payload["classification"], "machine_local")
        self.assertTrue(machine["command"])
        self.assertIn(SERVER_MODULE, machine["args"])
        index = machine["args"].index("--workspace-root")
        self.assertEqual(
            Path(machine["args"][index + 1]).resolve(), self.repo.resolve()
        )

    def test_human_output_explains_the_redaction(self):
        code, out, _ = self.run_cli("generic")
        self.assertIn("--reveal-paths", out)
        self.assertNotIn(str(self.repo), out)

    def test_generic_requires_a_repository(self):
        outside = Path(self._temp.name) / "loose3"
        outside.mkdir()
        code, _, err = self.run_cli("generic", path=outside)
        self.assertEqual(code, EXIT_ERROR)

    def test_contract_is_deterministic(self):
        self.assertEqual(
            self.run_cli("generic", "--json")[1], self.run_cli("generic", "--json")[1]
        )


class LeakageTests(ConnectCLICase):
    """No command may print a path, a credential or an environment value."""

    ALL_COMMANDS = (
        ("list",),
        ("inspect", "claude"),
        ("inspect", "opencode"),
        ("inspect", "codex"),
        ("inspect", "devin-desktop"),
        ("inspect", "generic"),
        ("plan", "claude"),
        ("plan", "opencode"),
        ("plan", "codex"),
        ("plan", "devin-desktop"),
        ("check", "claude"),
        ("routing",),
        ("generic",),
    )

    def populate(self):
        self.claude_config(
            {
                "mcpServers": {
                    "secretive": {
                        "command": "npx",
                        "args": ["-y", "thing"],
                        "env": {"API_KEY": _SECRET},
                    }
                }
            }
        )
        self.write_config(
            ".config",
            "opencode",
            "opencode.json",
            content={
                "mcp": {
                    "engram": {
                        "type": "local",
                        "command": ["engram", "mcp"],
                        "environment": {"ENGRAM_TOKEN": _SECRET},
                    }
                }
            },
        )
        self.write_config(
            ".codeium",
            "windsurf",
            "mcp_config.json",
            content={"mcpServers": {"c7": {"command": "npx", "args": ["-y", "c7"]}}},
        )
        self.write_config(
            ".codex",
            "config.toml",
            content=f'[mcp_servers.engram]\ncommand = "engram"\nargs = ["mcp"]\ntoken = "{_SECRET}"\n',
        )

    def test_no_command_prints_a_credential(self):
        self.populate()
        for argv in self.ALL_COMMANDS:
            for extra in ((), ("--json",)):
                with self.subTest(argv=argv, extra=extra):
                    _, out, err = self.run_cli(*argv, *extra)
                    self.assertNotIn(_SECRET, out)
                    self.assertNotIn(_SECRET, err)

    def test_no_command_prints_a_machine_local_path(self):
        self.populate()
        for argv in self.ALL_COMMANDS:
            for extra in ((), ("--json",)):
                with self.subTest(argv=argv, extra=extra):
                    _, out, _ = self.run_cli(*argv, *extra)
                    self.assertNotIn(str(self.home), out)
                    self.assertNotIn(str(self.repo), out)

    def test_no_command_emits_raw_configuration(self):
        self.populate()
        for argv in self.ALL_COMMANDS:
            with self.subTest(argv=argv):
                _, out, _ = self.run_cli(*argv, "--json")
                self.assertNotIn("secretive", out)
                self.assertNotIn("ENGRAM_TOKEN", out)

    def test_json_payloads_pass_the_absolute_path_audit(self):
        self.populate()
        for argv in self.ALL_COMMANDS:
            with self.subTest(argv=argv):
                _, out, _ = self.run_cli(*argv, "--json")
                for value in iter_strings(json.loads(out)):
                    self.assertFalse(contains_absolute_path(value), value)


class MaliciousConfigTests(ConnectCLICase):
    def deeply_nested(self):
        # ~40 KB, well under the size ceiling, so the byte limit does not
        # cover it. Before the fix this reached the user as an unhandled
        # RecursionError traceback.
        return '{"mcpServers":' + "[" * 20000 + "]" * 20000 + "}"

    def test_a_deeply_nested_config_is_reported_not_crashed(self):
        self.claude_config(self.deeply_nested())
        code, payload, _ = self.run_json("inspect", "claude")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(payload["discovery_status"], "config_malformed")

    def test_a_deeply_nested_config_does_not_break_plan(self):
        self.claude_config(self.deeply_nested())
        code, payload, _ = self.run_json("plan", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertEqual(payload["status"], "unavailable")

    def test_one_broken_host_does_not_hide_the_others(self):
        self.claude_config("{ broken")
        self.write_config(
            ".codeium", "windsurf", "mcp_config.json", content={"mcpServers": {}}
        )
        code, payload, _ = self.run_json("list")
        self.assertEqual(code, EXIT_OK)
        states = {
            entry["connector_id"]: entry["discovery_status"]
            for entry in payload["connectors"]
        }
        self.assertEqual(states["claude"], "config_malformed")
        self.assertEqual(states["devin-desktop"], "discovered")


class ReadOnlyTests(ConnectCLICase):
    def test_no_command_performs_any_write_syscall(self):
        self.claude_config({"mcpServers": {"c7": {"command": "npx", "args": []}}})
        self.write_config(
            ".codeium", "windsurf", "mcp_config.json", content={"mcpServers": {}}
        )
        for argv in LeakageTests.ALL_COMMANDS:
            with self.subTest(argv=argv):
                with _ReadOnlyFilesystem():
                    self.run_cli(*argv, "--json")

    def test_fixture_home_is_byte_identical_afterwards(self):
        self.claude_config({"mcpServers": {"c7": {"command": "npx", "args": []}}})
        before = self.snapshot()
        for argv in LeakageTests.ALL_COMMANDS:
            self.run_cli(*argv)
            self.run_cli(*argv, "--json")
        self.assertEqual(self.snapshot(), before)


class ExitCodeContractTests(ConnectCLICase):
    def test_bad_flag_is_a_command_failure_not_an_action_request(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
            io.StringIO()
        ):
            with self.assertRaises(SystemExit) as caught:
                main(["connect", "list", "--nope"])
        self.assertEqual(caught.exception.code, EXIT_ERROR)

    def test_missing_subcommand_is_a_command_failure(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
            io.StringIO()
        ):
            with self.assertRaises(SystemExit) as caught:
                main(["connect"])
        self.assertEqual(caught.exception.code, EXIT_ERROR)

    def test_connect_appears_in_the_top_level_help(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit):
                main(["--help"])
        self.assertIn("connect", out.getvalue())

    def test_r4a_commands_still_work(self):
        # The connect group must not disturb the R4A surface.
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit):
                main(["--version"])
        self.assertIn("relinkra", out.getvalue())


class RepositoryUntouchedTests(unittest.TestCase):
    """The real repository this suite runs in must never be modified."""

    REPO = Path(__file__).resolve().parent.parent

    def digest(self, path: Path):
        return path.read_bytes() if path.is_file() else None

    def test_windsurf_workflow_file_is_untouched(self):
        target = self.REPO / ".windsurf" / "workflows" / "sdd-new.md"
        if not target.is_file():
            self.skipTest("the pre-existing untracked .windsurf fixture is absent")
        before = self.digest(target)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            main(["connect", "list", "--json", "--path", str(self.REPO)])
            main(["connect", "plan", "claude", "--json", "--path", str(self.REPO)])
        self.assertEqual(self.digest(target), before)

    def test_relinkra_workspace_state_is_untouched(self):
        state = self.REPO / ".relinkra"
        before = {
            str(p.relative_to(state)): p.read_bytes()
            for p in sorted(state.rglob("*"))
            if p.is_file()
        } if state.is_dir() else {}
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            main(["connect", "generic", "--json", "--path", str(self.REPO)])
            main(["connect", "check", "claude", "--json", "--path", str(self.REPO)])
        after = {
            str(p.relative_to(state)): p.read_bytes()
            for p in sorted(state.rglob("*"))
            if p.is_file()
        } if state.is_dir() else {}
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
