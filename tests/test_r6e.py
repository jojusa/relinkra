"""R6E tests — multiagent onboarding and routing UX.

CONNECT ALL. ``relinkra connect all`` drives every supported host
through its OWN per-agent pipeline (inspect -> check -> plan ->
preflight -> confirmation -> apply). The tests prove the safety matrix:
already-valid hosts are no-ops, writes need per-host confirmation, a
refused or malformed host fails closed without affecting the others, a
declined host mutates nothing, and repeating the command is idempotent.

COMPACT CHECK. The default ``connect check`` output is concise and
host-local; the global per-host tables live behind ``--verbose`` and in
the JSON payload, which never loses detail.

INSPECT. ``workspace_matches`` is exposed directly, read-only.

ZCODE GENERATED STATE. Healthy generated state (git-ignored, git-clean)
is not a warning; only a real hygiene problem warns.

GUIDANCE. Relinkra-first routing order and Engram coexistence are
surfaced in normal-user connect output without blocking native tools.
"""

from __future__ import annotations

import builtins
import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from relinkra import connect_cli, product_cli
from relinkra.connector import MANAGED_SERVER_NAME
from relinkra.connectors import (
    CLAUDE,
    CODEX,
    DEVIN_DESKTOP,
    OPENCODE,
    ZCODE,
    claude_project_key,
    resolve_host_launch,
)
from relinkra.host_discovery import (
    SYSTEM_LINUX,
    SYSTEM_WINDOWS,
    DiscoveryEnvironment,
)
from relinkra.identity import explicit_identity
from relinkra.product_cli import (
    EXIT_ACTION_REQUIRED,
    EXIT_ERROR,
    EXIT_OK,
    WorkspaceConfig,
    main,
    registry_path,
)
from relinkra.registry import Registry
from relinkra.runtime_evidence import (
    EVENT_INITIALIZE_OBSERVED,
    EVENT_MCP_SERVER_STARTED,
    EVENT_TOOLS_LIST_OBSERVED,
    EvidenceRecorder,
)
from relinkra.toml_edit import serialize_member_toml, toml_parser_available


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
    repo = base / "repo"
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "fixture@example.com")
    _git(repo, "config", "user.name", "Fixture")
    (repo / "README.md").write_text("fixture\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "fixture revision")
    return repo


class ConnectAllCase(unittest.TestCase):
    """A real git repository plus a fixture home; discovery patched.

    The repository is real so the ZCode generated-state probes (git
    check-ignore / git status) behave exactly as they do for a user.
    """

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="relinkra-r6e-connect-all-")
        self.addCleanup(self._temp.cleanup)
        base = Path(self._temp.name)
        self.home = base / "home"
        self.home.mkdir()
        self.repo = _real_git_repo(base)
        self.root = self.repo.resolve()

        workspace = Registry(str(registry_path(self.repo))).register_workspace(
            str(self.repo), explicit_identity("fixture")
        )
        WorkspaceConfig(
            project_id=workspace.project_id,
            workspace_id=workspace.workspace_id,
        ).save(self.repo)

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

    def write_home(self, *parts, content):
        path = self.home.joinpath(*parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        text = content if isinstance(content, str) else json.dumps(content, indent=2)
        path.write_text(text, encoding="utf-8")
        return path

    def launch_for(self, connector_id: str):
        return resolve_host_launch(
            connector_id, self.repo, registry_path(self.repo)
        )

    def registered_entry(self, connector_id: str):
        spec = {
            "claude": CLAUDE,
            "opencode": OPENCODE,
            "codex": CODEX,
            "zcode": ZCODE,
            "devin-desktop": DEVIN_DESKTOP,
        }[connector_id]
        return spec.entry_builder(self.launch_for(connector_id))

    def claude_config(self, servers):
        return self.write_home(
            ".claude.json",
            content={
                "projects": {
                    claude_project_key(self.root): {"mcpServers": servers}
                }
            },
        )

    def opencode_config(self, servers):
        return self.write_home(
            ".config", "opencode", "opencode.json", content={"mcp": servers}
        )

    def codex_config(self, servers):
        if not toml_parser_available():
            self.skipTest("codex TOML I/O requires tomllib (Python 3.11+)")
        entry = self.registered_entry("codex")
        if servers:
            body = serialize_member_toml(
                "", ("mcp_servers",), MANAGED_SERVER_NAME, entry
            )
        else:
            body = ""
        return self.write_home(".codex", "config.toml", content=body)

    def zcode_config(self, servers, cwd=None):
        entry = self.registered_entry("zcode")
        if cwd is not None:
            entry = dict(entry)
            entry["cwd"] = str(cwd)
        content = {"mcp": {"servers": dict(servers)}}
        if servers:
            content["mcp"]["servers"][MANAGED_SERVER_NAME] = entry
        path = self.repo / ".zcode" / "config.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(content, indent=2), encoding="utf-8")
        return path

    def devin_config(self, servers):
        entry = self.registered_entry("devin-desktop")
        content = {"mcpServers": dict(servers)}
        if servers:
            content["mcpServers"][MANAGED_SERVER_NAME] = entry
        path = self.repo / ".devin" / "mcp_config.local.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(content, indent=2), encoding="utf-8")
        return path

    def register_all_hosts(self):
        """Every default target holds a current, valid registration."""
        self.claude_config({MANAGED_SERVER_NAME: self.registered_entry("claude")})
        self.opencode_config({MANAGED_SERVER_NAME: self.registered_entry("opencode")})
        self.codex_config({MANAGED_SERVER_NAME: self.registered_entry("codex")})
        self.zcode_config({MANAGED_SERVER_NAME: self.registered_entry("zcode")})
        self.devin_config({MANAGED_SERVER_NAME: self.registered_entry("devin-desktop")})

    def host_row(self, payload, connector_id):
        return next(
            row for row in payload["hosts"] if row["connector_id"] == connector_id
        )

    def record_evidence(self, connector_id: str):
        """Record a session's evidence bound to the CURRENT revision,
        exactly the way the real MCP server would."""
        from relinkra.identity import git_head_sha

        recorder = EvidenceRecorder(
            str(self.root), connector_id, revision=git_head_sha(str(self.root))
        )
        recorder.record(EVENT_MCP_SERVER_STARTED)
        recorder.record(EVENT_INITIALIZE_OBSERVED, {"protocol_agreed": True})
        recorder.record(EVENT_TOOLS_LIST_OBSERVED)
        return recorder

    def snapshot(self):
        return {
            str(p.relative_to(self.root)): p.read_bytes()
            for p in sorted(self.root.rglob("*"))
            if p.is_file()
        }

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


class ConnectAllSafetyTests(ConnectAllCase):
    """The R6E connect-all safety matrix."""

    def test_all_already_valid_is_a_fully_safe_noop(self):
        self.register_all_hosts()
        before = self.snapshot()
        with mock.patch("builtins.input") as confirm:
            code, payload, _ = self.run_json("all")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertEqual(
            [row["action"] for row in payload["hosts"]],
            ["no-op"] * len(payload["hosts"]),
        )
        for row in payload["hosts"]:
            self.assertEqual(row["classification"], "already_valid")
            self.assertEqual(row["config"], "valid")
            self.assertEqual(row["workspace"], "matches")
        confirm.assert_not_called()
        self.assertEqual(self.snapshot(), before)

    def test_one_absent_host_is_the_only_one_planned_and_applied(self):
        self.register_all_hosts()
        (self.home / ".claude.json").unlink()
        with mock.patch("builtins.input", return_value="y") as confirm:
            code, payload, _ = self.run_json("all")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertEqual(self.host_row(payload, "claude")["action"], "applied")
        for other in ("codex", "opencode", "zcode", "devin-desktop"):
            self.assertEqual(self.host_row(payload, other)["action"], "no-op")
        # Only ONE confirmation was asked, for the ONE host needing it.
        self.assertEqual(confirm.call_count, 1)
        self.assertEqual(payload["written"], ["claude"])
        self.assertTrue((self.home / ".claude.json").exists())

    def test_wrong_workspace_is_detected_safely_before_any_write(self):
        self.register_all_hosts()
        foreign = self.root.parent / "another-workspace"
        # Point ZCode's registration at a different workspace cwd.
        self.zcode_config(
            {MANAGED_SERVER_NAME: self.registered_entry("zcode")}, cwd=foreign
        )
        before = self.snapshot()
        # The host IS write-required, so it asks — and the mocked
        # non-answer declines it without any write.
        with mock.patch("builtins.input") as confirm:
            code, payload, _ = self.run_json("all")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        row = self.host_row(payload, "zcode")
        self.assertEqual(row["workspace"], "differs")
        self.assertEqual(row["classification"], "needs_update")
        self.assertEqual(row["action"], "declined")
        self.assertEqual(self.snapshot(), before)

    def test_direct_cbm_conflict_refuses_that_host_only(self):
        self.register_all_hosts()
        path = self.home / ".claude.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        servers = document["projects"][claude_project_key(self.root)]["mcpServers"]
        servers["memory-helper"] = {"command": "codebase-memory-mcp", "args": []}
        path.write_text(json.dumps(document, indent=2), encoding="utf-8")
        before = self.snapshot()
        with mock.patch("builtins.input") as confirm:
            code, payload, _ = self.run_json("all")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        row = self.host_row(payload, "claude")
        self.assertEqual(row["action"], "refused")
        self.assertIn("direct codebase-memory", row["detail"])
        for other in ("codex", "opencode", "zcode", "devin-desktop"):
            self.assertEqual(self.host_row(payload, other)["action"], "no-op")
        confirm.assert_not_called()
        self.assertEqual(self.snapshot(), before)

    def test_malformed_config_fails_closed_without_affecting_others(self):
        self.register_all_hosts()
        (self.home / ".claude.json").write_text("{ broken", encoding="utf-8")
        before = self.snapshot()
        with mock.patch("builtins.input") as confirm:
            code, payload, _ = self.run_json("all")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        row = self.host_row(payload, "claude")
        self.assertEqual(row["action"], "refused")
        self.assertIn("malformed", json.dumps(row))
        for other in ("codex", "opencode", "zcode", "devin-desktop"):
            self.assertEqual(self.host_row(payload, other)["action"], "no-op")
        confirm.assert_not_called()
        self.assertEqual(self.snapshot(), before)

    def test_declining_one_host_writes_nothing_for_it_and_not_the_others(self):
        self.register_all_hosts()
        (self.home / ".claude.json").unlink()
        (self.home / ".config" / "opencode" / "opencode.json").unlink()
        # Prompts fire in target order: OpenCode first, then Claude.
        with mock.patch(
            "builtins.input", side_effect=["n", "y"]
        ) as confirm:
            code, payload, _ = self.run_json("all")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertEqual(self.host_row(payload, "opencode")["action"], "declined")
        self.assertEqual(self.host_row(payload, "claude")["action"], "applied")
        self.assertEqual(confirm.call_count, 2)
        self.assertFalse(
            (self.home / ".config" / "opencode" / "opencode.json").exists(),
            "a declined host must not be written",
        )
        self.assertTrue((self.home / ".claude.json").exists())

    def test_repeated_connect_all_is_idempotent(self):
        self.register_all_hosts()
        (self.home / ".claude.json").unlink()
        with mock.patch("builtins.input", return_value="y"):
            code, payload, _ = self.run_json("all")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertEqual(self.host_row(payload, "claude")["action"], "applied")
        with mock.patch("builtins.input") as confirm:
            code, payload, _ = self.run_json("all")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertEqual(
            [row["action"] for row in payload["hosts"]],
            ["no-op"] * len(payload["hosts"]),
        )
        confirm.assert_not_called()

    def test_zcode_workspace_local_path_is_preserved(self):
        self.register_all_hosts()
        (self.repo / ".zcode" / "config.json").unlink()
        with mock.patch("builtins.input", return_value="y"):
            code, payload, _ = self.run_json("all")
        self.assertEqual(code, EXIT_OK, payload)
        document = json.loads(
            (self.repo / ".zcode" / "config.json").read_text(encoding="utf-8")
        )
        entry = document["mcp"]["servers"][MANAGED_SERVER_NAME]
        from relinkra.identity import canonicalize_path

        self.assertEqual(
            canonicalize_path(entry["cwd"]), canonicalize_path(str(self.root))
        )
        # Workspace-local only: no global ZCode file is created.
        self.assertFalse((self.home / ".zcode").exists())

    def test_noninteractive_run_declines_every_write(self):
        self.register_all_hosts()
        (self.home / ".claude.json").unlink()
        before = self.snapshot()

        def closed_stdin(*_args, **_kwargs):
            raise EOFError("no interactive user")

        with mock.patch("builtins.input", side_effect=closed_stdin):
            code, payload, _ = self.run_json("all")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertEqual(self.host_row(payload, "claude")["action"], "declined")
        self.assertEqual(payload["written"], [])
        self.assertEqual(self.snapshot(), before)

    def test_host_runtime_states_appear_in_the_table(self):
        self.register_all_hosts()
        self.record_evidence("codex")
        code, payload, _ = self.run_json("all")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(self.host_row(payload, "codex")["runtime"], "observed")
        for other in ("claude", "opencode", "zcode", "devin-desktop"):
            self.assertEqual(self.host_row(payload, other)["runtime"], "pending")

    def test_json_payload_carries_guidance_and_targets(self):
        self.register_all_hosts()
        code, payload, _ = self.run_json("all")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(
            payload["targets"],
            ["codex", "opencode", "claude", "devin-desktop", "zcode"],
        )
        ids = [
            item["id"] for item in payload["agent_instructions"]["instructions"]
        ]
        self.assertIn("relinkra_first_routing", ids)
        self.assertIn("engram_coexistence", ids)

    def test_human_output_shows_the_table_before_the_prompts(self):
        self.register_all_hosts()
        (self.home / ".claude.json").unlink()
        with mock.patch("builtins.input", return_value="y"):
            code, out, _ = self.run_cli("all")
        self.assertEqual(code, EXIT_OK)
        table_position = out.index("Relinkra connect all")
        # The printed half of the confirmation (input()'s own question is
        # not echoed because the test mocks input).
        prompt_position = out.index("Relinkra will update the Claude Code")
        self.assertLess(table_position, prompt_position)
        self.assertIn("Routing guidance (Relinkra-first):", out)
        self.assertIn("apply?", out)
        self.assertIn("applied", out)


class CompactCheckTests(ConnectAllCase):
    """The R6E compact default and the --verbose full report."""

    def test_valid_host_is_concise_and_host_local(self):
        self.claude_config({MANAGED_SERVER_NAME: self.registered_entry("claude")})
        code, out, _ = self.run_cli("check", "claude")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Claude Code\n", out)
        self.assertIn("✓ Config valid", out)
        self.assertIn("✓ Workspace matches", out)
        self.assertIn("○ Runtime pending", out)
        self.assertIn("Next: start/restart Claude Code", out)
        # No global tables in the compact default.
        self.assertNotIn("Per-host verification", out)
        self.assertNotIn("Findings", out)

    def test_observed_runtime_shows_honestly(self):
        self.claude_config({MANAGED_SERVER_NAME: self.registered_entry("claude")})
        self.record_evidence("claude")
        code, out, _ = self.run_cli("check", "claude")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("✓ Runtime observed", out)
        self.assertIn("no action needed", out)

    def test_invalid_host_names_the_finding_and_next_action(self):
        self.claude_config(
            {
                MANAGED_SERVER_NAME: {
                    "command": "node",
                    "args": ["not-relinkra.js"],
                }
            }
        )
        code, out, _ = self.run_cli("check", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("✗ Config needs attention", out)
        self.assertIn("does not launch Relinkra", out)
        self.assertIn("Next: run 'relinkra connect plan claude'", out)

    def test_absent_registration_shows_pending_and_registration_next(self):
        self.claude_config({})
        code, out, _ = self.run_cli("check", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("○ Registration absent", out)
        self.assertIn("Next: run 'relinkra connect claude'", out)

    def test_verbose_keeps_the_full_report(self):
        self.claude_config({MANAGED_SERVER_NAME: self.registered_entry("claude")})
        code, out, _ = self.run_cli("check", "claude", "--verbose")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Per-host verification", out)
        self.assertIn("Verification", out)
        self.assertIn("This command wrote nothing.", out)

    def test_json_payload_keeps_full_detail_in_compact_mode(self):
        self.claude_config({MANAGED_SERVER_NAME: self.registered_entry("claude")})
        code, payload, _ = self.run_json("check", "claude")
        self.assertEqual(code, EXIT_OK)
        self.assertTrue(payload["valid"])
        self.assertTrue(payload["matches_workspace"])
        self.assertIn("host_verification_sections", payload)
        self.assertIn("verification", payload)
        self.assertIn("runtime", payload)
        self.assertEqual(payload["runtime"]["state"], "pending")


class InspectWorkspaceMatchTests(ConnectAllCase):
    """``inspect`` answers the workspace question directly, read-only."""

    def test_registered_host_reports_matches(self):
        self.claude_config({MANAGED_SERVER_NAME: self.registered_entry("claude")})
        code, payload, _ = self.run_json("inspect", "claude")
        self.assertEqual(code, EXIT_OK)
        self.assertTrue(payload["workspace_matches"])
        code, out, _ = self.run_cli("inspect", "claude")
        self.assertIn("Workspace      matches", out)

    def test_foreign_workspace_reports_differs(self):
        foreign = self.root.parent / "not-this-workspace"
        self.zcode_config(
            {MANAGED_SERVER_NAME: self.registered_entry("zcode")}, cwd=foreign
        )
        code, payload, _ = self.run_json("inspect", "zcode")
        self.assertEqual(code, EXIT_OK)
        self.assertIs(payload["workspace_matches"], False)
        code, out, _ = self.run_cli("inspect", "zcode")
        self.assertIn("differs", out)

    def test_absent_registration_reports_unknown_without_a_row(self):
        self.claude_config({})
        code, payload, _ = self.run_json("inspect", "claude")
        self.assertEqual(code, EXIT_OK)
        self.assertIsNone(payload["workspace_matches"])


class ZcodeGeneratedStateTests(ConnectAllCase):
    """Healthy generated state is a PASS, not a generic warning."""

    def _ignore_zcode(self):
        exclude = self.repo / ".git" / "info" / "exclude"
        content = exclude.read_text(encoding="utf-8")
        exclude.write_text(content + "\n.zcode/\n", encoding="utf-8")

    def test_healthy_generated_state_is_not_a_warning(self):
        self._ignore_zcode()
        path = self.repo / ".zcode" / "config.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")
        (self.repo / ".zcode" / "config.json.lock").write_text(
            "host-owned", encoding="utf-8"
        )
        code, payload, _ = self.run_json("inspect", "zcode")
        self.assertEqual(code, EXIT_OK)
        state = payload["zcode_generated_state"]
        self.assertEqual(state["status"], "healthy")
        self.assertTrue(state["config_ignored"])
        self.assertTrue(state["lock_ignored"])
        self.assertFalse(state["git_dirty"])
        self.assertNotIn("zcode_lock_present", payload["warnings"])
        self.assertNotIn("zcode_workspace_state", payload["warnings"])

        code, out, _ = self.run_cli("check", "zcode")
        self.assertIn("✓ Generated state Git-clean", out)
        self.assertNotIn("zcode_generated_state_git_dirty", out)

    def test_unhygienic_generated_state_warns_precisely(self):
        path = self.repo / ".zcode" / "config.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")
        code, payload, _ = self.run_json("inspect", "zcode")
        self.assertEqual(code, EXIT_OK)
        state = payload["zcode_generated_state"]
        self.assertEqual(state["status"], "unhygienic")
        self.assertIs(state["config_ignored"], False)
        codes = {warning["code"] for warning in payload["warnings"]}
        self.assertIn("zcode_generated_state_git_dirty", codes)
        code, out, _ = self.run_cli("check", "zcode")
        self.assertIn("✗ Generated state shows in Git", out)

    def test_absent_generated_state_says_nothing(self):
        code, payload, _ = self.run_json("inspect", "zcode")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(payload["zcode_generated_state"]["status"], "absent")
        codes = {warning["code"] for warning in payload["warnings"]}
        self.assertNotIn("zcode_generated_state_git_dirty", codes)
        self.assertNotIn("zcode_lock_present", codes)


class DiscoveryWordingTests(ConnectAllCase):
    """A missing executable is stated plainly, without the contradiction."""

    def test_inspect_says_the_host_is_absent_but_config_preparable(self):
        self.zcode_config({})
        code, payload, _ = self.run_json("inspect", "zcode")
        self.assertEqual(code, EXIT_OK)
        messages = {
            warning["message"]: warning["code"]
            for warning in payload["warnings"]
        }
        self.assertIn(connect_cli.HOST_NOT_DETECTED_NOTE, messages)
        code, out, _ = self.run_cli("inspect", "zcode")
        self.assertIn("Host executable not detected.", out)
        self.assertIn("Workspace configuration can still be prepared.", out)


class GuidanceSurfaceTests(ConnectAllCase):
    """Relinkra-first routing and Engram coexistence, in normal output."""

    def test_connect_list_carries_the_guidance_footer(self):
        code, out, _ = self.run_cli("list")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Routing guidance (Relinkra-first):", out)
        self.assertIn("project_resolve", out)
        self.assertIn("source code and git are authoritative", out)
        self.assertIn("do not duplicate", out)
        self.assertIn("Gentleman/SDD", out)

    def test_connect_list_json_carries_the_instructions(self):
        code, payload, _ = self.run_json("list")
        self.assertEqual(code, EXIT_OK)
        ids = [
            item["id"] for item in payload["agent_instructions"]["instructions"]
        ]
        self.assertEqual(
            ids, ["when_relinkra_helps", "relinkra_first_routing", "engram_coexistence"]
        )


if __name__ == "__main__":
    unittest.main()
