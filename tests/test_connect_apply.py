"""Tests for the connector apply/rollback/verify workflow (R4C.1B).

Every test drives either the real CLI through ``main(argv)`` or the real
engine against a fixture home plus a fake repository, with host discovery
monkeypatched the same way ``tests.test_connect_cli`` does. Nothing on
the machine running the suite is read or written, and every write the
engine performs is asserted against byte-level before/after state.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from relinkra import connect_cli, connector_apply, product_cli
from relinkra import connectors as relinkra_connectors
from relinkra import safe_write as relinkra_safe_write
from relinkra.backend_detection import build_trust_ladder, survey_hosts
from relinkra.backend_policy import (
    ROUTE_UNVERIFIED,
    STAGE_CONFIGURATION_PRESENT,
    STAGE_HANDSHAKE_VERIFIED,
    STAGE_HANDOFF_ROUND_TRIP,
    STAGE_MCP_CONTRACT_CONFIGURED,
    STAGE_REAL_HOST_LAUNCH,
    STAGE_REGISTRATION_DETECTED,
    STAGE_REQUIRED_TOOLS_CALLABLE,
    STAGE_TOOLS_VISIBLE,
    STAGE_UNVERIFIED,
    TRUST_UNVERIFIED,
)
from relinkra.connect_verification import (
    STATUS_ABSENT,
    STATUS_EXPIRED,
    STATUS_INVALID,
    STATUS_STALE_FINGERPRINT,
    STATUS_VALID,
    ProofError,
    assess_verification,
    build_proof_from_payload,
)
from relinkra.connector import MANAGED_SERVER_NAME, iter_strings
from relinkra.connector_apply import (
    apply_connector,
    classify_server_entry,
    entries_equivalent,
    launch_fingerprint,
    rollback_connector,
)
from relinkra.connectors import (
    CLAUDE,
    SERVER_MODULE,
    claude_project_key,
    resolve_launch,
)
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
from relinkra.safe_write import (
    ContentValidationError,
    PreconditionError,
    digest_text,
    read_bounded_text,
    safe_replace,
)

_SECRET = "sk-live-APPLY-DO-NOT-LEAK-0123456789"


class ConnectApplyCase(unittest.TestCase):
    """A fake repository plus a fixture home, discovery monkeypatched."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="relinkra-connect-apply-")
        self.addCleanup(self._temp.cleanup)
        base = Path(self._temp.name)
        self.home = base / "home"
        self.home.mkdir()
        self.repo = base / "repo"
        (self.repo / ".git").mkdir(parents=True)
        # The CLI resolves the workspace root before use; the fixture key
        # must be computed from exactly that resolved form.
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

    # -- fixtures ---------------------------------------------------------

    def env(self):
        return DiscoveryEnvironment(
            system=SYSTEM_WINDOWS if os.name == "nt" else SYSTEM_LINUX,
            home=self.home,
            env={},
            workspace_root=self.root,
            which=lambda name: None,
        )

    def write_config(self, *parts, content):
        path = self.home.joinpath(*parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        text = content if isinstance(content, str) else json.dumps(content, indent=2)
        # Bytes, not write_text: newline translation would rewrite the
        # exact fixture bytes the formatting-preservation tests assert on.
        path.write_bytes(text.encode("utf-8"))
        return path

    def claude_key(self):
        """The projects[] key Claude Code derives for this workspace."""
        return claude_project_key(self.root)

    def claude_config(self, servers, **extra_top_level):
        """Write the Claude state file (~/.claude.json) in its real shape.

        ``servers`` becomes ``projects[<project-key>].mcpServers``,
        surrounded by ~50 unknown top-level members and a sibling
        project with its own servers, so every mutation assertion also
        proves those survive. A raw string is written verbatim (for
        malformed and formatting fixtures).
        """
        if isinstance(servers, str):
            return self.write_config(".claude.json", content=servers)
        # Tolerate the pre-correction call shape: a bare {"mcpServers": X}
        # dict means X is the server map, not a nested member.
        if set(servers) == {"mcpServers"}:
            servers = servers["mcpServers"]
        document = {
            f"unknown_top_level_{index:02d}": {"n": index} for index in range(50)
        }
        document["projects"] = {
            "C:/other/project": {
                "mcpServers": {"sibling": {"command": "npx", "args": ["-y", "sib"]}}
            },
            self.claude_key(): {
                "mcpServers": servers,
                "hasTrustDialogAccepted": True,
            },
        }
        document.update(extra_top_level)
        return self.write_config(".claude.json", content=document)

    def mcp_servers(self, document):
        """The LOCAL-scope server map of this fixture's workspace."""
        return document["projects"][self.claude_key()]["mcpServers"]

    def claude_path(self):
        return self.home / ".claude.json"

    def registered_claude_entry(self):
        launch = resolve_launch(self.repo, registry_path(self.repo))
        return CLAUDE.entry_builder(launch)

    def launch(self):
        return resolve_launch(self.repo, registry_path(self.repo))

    def snapshot(self, root):
        return {
            str(p.relative_to(root)): p.read_bytes()
            for p in sorted(root.rglob("*"))
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

    def valid_proof(self):
        return {
            "stages": {
                "host_launched": True,
                "handshake_succeeded": True,
                "tools_visible": True,
                "tools_callable": True,
                "handoff_roundtrip": True,
            },
            "tools_visible": ["context_packet", "memory_search"],
            "tools_invoked": ["context_packet"],
            "handoff_ok": True,
        }

    def write_proof(self, payload):
        path = Path(self._temp.name) / "proof.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path


class ApplyBasicsTests(ConnectApplyCase):
    def test_existing_empty_object_config_gains_the_entry_with_a_backup(self):
        path = self.claude_config({"mcpServers": {}})
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["change_required"])
        self.assertTrue(payload["backup_created"])
        self.assertTrue(payload["write_succeeded"])
        self.assertTrue(payload["validation_succeeded"])
        self.assertTrue(payload["registration_matches_expected"])
        self.assertEqual(payload["verification_stage"], "config_applied_host_unverified")
        self.assertFalse(payload["real_host_verified"])
        self.assertTrue(payload["host_restart_required"])
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn(MANAGED_SERVER_NAME, self.mcp_servers(document))
        # Unknown state-file members and sibling projects are untouched.
        self.assertEqual(document["unknown_top_level_00"], {"n": 0})
        self.assertEqual(
            document["projects"]["C:/other/project"]["mcpServers"]["sibling"],
            {"command": "npx", "args": ["-y", "sib"]},
        )
        backup = path.with_name(path.name + ".relinkra-backup")
        self.assertEqual(backup.read_bytes(), before)

    def test_a_missing_config_file_is_created_without_a_backup(self):
        code, payload, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertFalse(payload["backup_created"])
        self.assertTrue(payload["write_succeeded"])
        document = json.loads(self.claude_path().read_text(encoding="utf-8"))
        self.assertIn(MANAGED_SERVER_NAME, self.mcp_servers(document))

    def test_unrelated_entries_survive_byte_for_byte_semantically(self):
        context7 = {
            "command": "npx",
            "args": ["-y", "@upstash/context7-mcp"],
            "env": {"CONTEXT7_API_KEY": "abc", "OTHER": {"nested": [1, 2, 3]}},
        }
        path = self.claude_config({"mcpServers": {"context7": context7}})
        code, _, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK)
        document = json.loads(path.read_text(encoding="utf-8"))
        # Full deep equality of the unrelated subtree, not key presence.
        self.assertEqual(self.mcp_servers(document)["context7"], context7)

    def test_unknown_top_level_fields_survive(self):
        path = self.claude_config(
            {"mcpServers": {}},
            permissions={"allow": ["Bash(git:*)"], "deny": []},
            theme="dark",
            model="opus",
        )
        code, _, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK)
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(document["permissions"], {"allow": ["Bash(git:*)"], "deny": []})
        self.assertEqual(document["theme"], "dark")
        self.assertEqual(document["model"], "opus")
        # The ~50 fixture unknowns survive too.
        self.assertEqual(document["unknown_top_level_49"], {"n": 49})

    def test_document_formatting_is_preserved(self):
        # CRLF line endings and tab indentation survive the rewrite.
        key = self.claude_key()
        text = (
            '{\r\n\t"projects": {\r\n\t\t"'
            + key
            + '": {"mcpServers": {}}\r\n\t}\r\n}\r\n'
        )
        path = self.write_config(".claude.json", content=text)
        code, _, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK)
        written = path.read_bytes().decode("utf-8")
        self.assertIn("\r\n", written)
        self.assertNotIn("\r\r\n", written)
        self.assertIn('\t"projects"', written)

    def test_equivalent_registration_is_an_idempotent_no_op(self):
        path = self.claude_config(
            {"mcpServers": {MANAGED_SERVER_NAME: self.registered_claude_entry()}}
        )
        before = path.read_bytes()
        code, payload, out_err = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertFalse(payload["change_required"])
        self.assertFalse(payload["write_attempted"])
        self.assertFalse(payload["backup_created"])
        self.assertTrue(payload["registration_matches_expected"])
        self.assertEqual(path.read_bytes(), before)
        _, out, _ = self.run_cli("apply", "claude")
        self.assertIn("No change required", out)

    def test_a_second_apply_is_deterministic(self):
        self.claude_config({"mcpServers": {}})
        self.run_cli("apply", "claude", "--json")
        digest_after_first = digest_text(read_bounded_text(self.claude_path()))
        second = self.run_cli("apply", "claude", "--json")[1]
        digest_after_second = digest_text(read_bounded_text(self.claude_path()))
        self.assertEqual(digest_after_first, digest_after_second)
        second_payload = json.loads(second)
        self.assertEqual(second_payload["digest_after"], digest_after_second)
        self.assertFalse(second_payload["change_required"])


class ClaudeStateFileApplyTests(ConnectApplyCase):
    """Apply against the real Claude Code 2.1+ LOCAL-scope shape."""

    def test_apply_creates_the_project_container_when_absent(self):
        sibling = {
            "mcpServers": {"sibling": {"command": "npx", "args": ["-y", "sib"]}}
        }
        path = self.write_config(
            ".claude.json",
            content={
                "numStartups": 12,
                "projects": {"C:/other/project": sibling},
                "theme": "dark",
            },
        )
        code, payload, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK, payload)
        after = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn(MANAGED_SERVER_NAME, self.mcp_servers(after))
        # Sibling projects and unknown top-level members survive deeply.
        self.assertEqual(after["projects"]["C:/other/project"], sibling)
        self.assertEqual(after["numStartups"], 12)
        self.assertEqual(after["theme"], "dark")
        # The new project container was appended, not reordered into place.
        self.assertEqual(
            list(after["projects"].keys()), ["C:/other/project", self.claude_key()]
        )

    def test_a_legacy_settings_json_registration_is_inert(self):
        legacy = self.write_config(
            ".claude",
            "settings.json",
            content={
                "mcpServers": {
                    MANAGED_SERVER_NAME: {"command": "py", "args": ["-m", SERVER_MODULE]}
                }
            },
        )
        legacy_before = legacy.read_bytes()
        self.claude_config({"mcpServers": {}})
        code, payload, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK, payload)
        # The apply target is the state file; the legacy file is untouched.
        self.assertEqual(payload["config_path"], "~/.claude.json")
        self.assertEqual(legacy.read_bytes(), legacy_before)
        # And check validates the state-file registration, not the legacy one.
        code, check_payload, _ = self.run_json("check", "claude")
        self.assertEqual(code, EXIT_OK, check_payload["findings"])
        self.assertTrue(check_payload["valid"])

    def test_a_legacy_only_registration_applies_to_the_state_file(self):
        legacy = self.write_config(
            ".claude",
            "settings.json",
            content={
                "mcpServers": {
                    MANAGED_SERVER_NAME: {"command": "py", "args": ["-m", SERVER_MODULE]}
                }
            },
        )
        legacy_before = legacy.read_bytes()
        # No ~/.claude.json at all: apply creates it, in LOCAL scope.
        code, payload, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertEqual(legacy.read_bytes(), legacy_before)
        after = json.loads(self.claude_path().read_text(encoding="utf-8"))
        self.assertIn(MANAGED_SERVER_NAME, self.mcp_servers(after))

    def test_large_document_round_trip_preserves_order_and_subtrees(self):
        path = self.claude_config(
            {"mcpServers": {"context7": {"command": "npx", "args": ["-y", "c7"]}}}
        )
        before = json.loads(path.read_text(encoding="utf-8"))
        before_keys = list(before.keys())
        code, _, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK)
        after = json.loads(path.read_text(encoding="utf-8"))
        # Top-level key order is the document's own, not a reserialized one.
        self.assertEqual(list(after.keys()), before_keys)
        for key in before_keys:
            if key == "projects":
                continue
            self.assertEqual(after[key], before[key], key)
        # Sibling project subtree: full deep equality, order included.
        self.assertEqual(
            after["projects"]["C:/other/project"], before["projects"]["C:/other/project"]
        )
        self.assertEqual(list(after["projects"].keys()), list(before["projects"].keys()))
        # The managed project kept its unknown members too.
        self.assertTrue(after["projects"][self.claude_key()]["hasTrustDialogAccepted"])


class ApplyRefusalTests(ConnectApplyCase):
    def assert_untouched(self, path, before):
        self.assertEqual(path.read_bytes(), before)
        backups = list(path.parent.glob(path.name + ".relinkra-backup*"))
        self.assertEqual(backups, [])

    def test_a_conflicting_unmanaged_entry_is_refused(self):
        path = self.claude_config(
            {"mcpServers": {MANAGED_SERVER_NAME: {"command": "node", "args": ["s.js"]}}}
        )
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertTrue(payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assert_untouched(path, before)

    def test_direct_cbm_exposure_is_refused_with_a_cbm_reason(self):
        path = self.claude_config(
            {
                "mcpServers": {
                    "codebase-memory-mcp": {
                        "command": "/opt/bin/codebase-memory-mcp",
                        "args": [],
                    }
                }
            }
        )
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("CBM", payload["refusal_reason"])
        self.assertIn("codebase-memory", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertTrue(
            any("direct_cbm_exposure" in warning for warning in payload["warnings"])
        )
        self.assert_untouched(path, before)

    def test_malformed_json_is_refused_without_a_backup(self):
        path = self.claude_config("{ broken")
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("config_malformed", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertFalse(payload["backup_created"])
        self.assert_untouched(path, before)

    def test_an_unreadable_target_is_refused(self):
        path = self.claude_config({"mcpServers": {}})
        before = path.read_bytes()
        with mock.patch(
            "relinkra.connectors.read_bounded_text",
            side_effect=PermissionError("denied"),
        ):
            code, payload, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertTrue(payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assert_untouched(path, before)

    def test_a_symlink_target_is_refused(self):
        path = self.claude_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        real_file = self.home / "real-settings.json"
        real_file.write_text('{"mcpServers": {}}', encoding="utf-8")
        try:
            os.symlink(str(real_file), str(path))
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable on this platform: {exc}")
        before = real_file.read_bytes()
        code, payload, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("symlink", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertEqual(real_file.read_bytes(), before)
        self.assertTrue(path.is_symlink())

    def test_other_connectors_still_refuse_writes(self):
        # R4C.1C opened the write path for OpenCode; codex and
        # devin-desktop stay read-only.
        self.write_config(
            ".config", "opencode", "opencode.json", content={"mcp": {}}
        )
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["write_succeeded"])
        for agent in ("codex", "devin-desktop"):
            code, payload, _ = self.run_json("apply", agent)
            self.assertEqual(code, EXIT_ACTION_REQUIRED, agent)
            self.assertTrue(payload["refusal_reason"], agent)
            self.assertFalse(payload["write_attempted"], agent)


class ApplyFailureSemanticsTests(ConnectApplyCase):
    def test_an_atomic_write_failure_keeps_the_original_and_no_backup(self):
        path = self.claude_config({"mcpServers": {}})
        before = path.read_bytes()
        with mock.patch(
            "relinkra.safe_write.atomic_write_text",
            side_effect=OSError("simulated disk failure"),
        ):
            code, payload, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_ERROR)
        self.assertTrue(payload["write_attempted"])
        self.assertFalse(payload["write_succeeded"])
        self.assertTrue(payload["error"])
        self.assertEqual(path.read_bytes(), before)
        # safe_write discards the redundant backup when nothing replaced.
        backups = list(path.parent.glob(path.name + ".relinkra-backup*"))
        self.assertEqual(backups, [])

    def test_a_post_write_validation_failure_rolls_back_automatically(self):
        path = self.claude_config({"mcpServers": {"c7": {"command": "npx", "args": []}}})
        before = path.read_bytes()
        real_validator = connector_apply.validate_json_text
        calls = []

        def flaky_validator(text):
            calls.append(1)
            if len(calls) > 1:
                raise ValueError("simulated post-write validation failure")
            return real_validator(text)

        with mock.patch.object(
            connector_apply, "validate_json_text", side_effect=flaky_validator
        ):
            code, payload, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_ERROR)
        self.assertTrue(payload["write_attempted"])
        self.assertFalse(payload["write_succeeded"])
        self.assertFalse(payload["validation_succeeded"])
        self.assertTrue(payload["rollback_attempted"])
        self.assertTrue(payload["rollback_succeeded"])
        self.assertEqual(path.read_bytes(), before)

    def test_a_concurrent_edit_aborts_the_write(self):
        path = self.claude_config({"mcpServers": {}})
        external = json.dumps({"mcpServers": {}, "external_edit": True}, indent=2)
        real_inspect = connector_apply.inspect_connector

        def inspecting_then_editing(spec, env):
            inspection = real_inspect(spec, env)
            # The user edits the file between inspection and write.
            path.write_text(external, encoding="utf-8")
            return inspection

        with mock.patch.object(
            connector_apply, "inspect_connector", side_effect=inspecting_then_editing
        ):
            code, payload, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("changed since it was inspected", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertEqual(path.read_text(encoding="utf-8"), external)


class RollbackTests(ConnectApplyCase):
    def test_rollback_restores_the_exact_pre_apply_bytes(self):
        path = self.claude_config(
            {"c7": {"command": "npx", "args": []}}, theme="dark"
        )
        before = path.read_bytes()
        before_digest = digest_text(read_bounded_text(path))
        code, _, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK)
        code, payload, _ = self.run_json("rollback", "claude")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["rollback_attempted"])
        self.assertTrue(payload["rollback_succeeded"])
        self.assertTrue(payload["validation_succeeded"])
        self.assertFalse(payload["registration_present"])
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(payload["digest_after"], before_digest)
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertNotIn(MANAGED_SERVER_NAME, self.mcp_servers(document))
        self.assertEqual(
            self.mcp_servers(document)["c7"], {"command": "npx", "args": []}
        )

    def test_rollback_removes_a_file_the_apply_created(self):
        code, _, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK)
        self.assertTrue(self.claude_path().is_file())
        code, payload, _ = self.run_json("rollback", "claude")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["rollback_succeeded"])
        self.assertFalse(self.claude_path().exists())

    def test_rollback_refuses_external_edits_made_after_the_apply(self):
        path = self.claude_config({"mcpServers": {}})
        code, _, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK)
        edited = json.loads(path.read_text(encoding="utf-8"))
        edited["external_edit"] = True
        path.write_text(json.dumps(edited, indent=2), encoding="utf-8")
        kept = path.read_bytes()
        code, payload, _ = self.run_json("rollback", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("external edits", payload["refusal_reason"])
        self.assertFalse(payload["rollback_succeeded"])
        # The external edit survives; rollback never overwrites it.
        self.assertEqual(path.read_bytes(), kept)

    def test_rollback_without_any_prior_apply_is_refused(self):
        self.claude_config({"mcpServers": {}})
        code, payload, _ = self.run_json("rollback", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("no machine receipt and no backup", payload["refusal_reason"])

    def test_rollback_falls_back_to_newest_backup_without_a_receipt(self):
        path = self.claude_config({"mcpServers": {"c7": {"command": "npx", "args": []}}})
        before = path.read_bytes()
        code, _, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK)
        # Remove the receipt: rollback must fall back to backup discovery.
        receipt = self.repo / ".relinkra" / "connect-apply" / "claude.json"
        receipt.unlink()
        code, payload, _ = self.run_json("rollback", "claude")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["rollback_succeeded"])
        self.assertEqual(path.read_bytes(), before)


class PortabilityAndSecretsTests(ConnectApplyCase):
    def populate_secret(self):
        return self.claude_config(
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

    def test_no_apply_rollback_or_check_output_carries_a_path(self):
        self.populate_secret()
        for argv in (
            ("apply", "claude"),
            ("check", "claude"),
            ("rollback", "claude"),
        ):
            for extra in ((), ("--json",)):
                with self.subTest(argv=argv, extra=extra):
                    code, out, err = self.run_cli(*argv, *extra)
                    self.assertNotIn(str(self.home), out)
                    self.assertNotIn(str(self.repo), out)
                    self.assertNotIn(str(self.home), err)
                    if "--json" in extra:
                        for value in iter_strings(json.loads(out)):
                            self.assertFalse(contains_absolute_path(value), value)

    def test_no_output_ever_carries_a_secret_value(self):
        path = self.populate_secret()
        for argv in (
            ("apply", "claude"),
            ("check", "claude"),
            ("rollback", "claude"),
            ("plan", "claude"),
        ):
            for extra in ((), ("--json",)):
                with self.subTest(argv=argv, extra=extra):
                    _, out, err = self.run_cli(*argv, *extra)
                    self.assertNotIn(_SECRET, out)
                    self.assertNotIn(_SECRET, err)
        # The secret survived every mutation of the file, untouched.
        self.assertIn(_SECRET, path.read_text(encoding="utf-8"))

    def test_apply_success_never_claims_readiness(self):
        self.claude_config({"mcpServers": {}})
        code, out, _ = self.run_cli("apply", "claude")
        self.assertEqual(code, EXIT_OK)
        self.assertNotRegex(out, r"(?i)\bready\b")
        self.assertIn("restart", out.lower())
        self.assertIn("NOT occurred", out)

    def test_reveal_paths_opts_into_machine_local_output(self):
        self.claude_config({"mcpServers": {}})
        code, payload, _ = self.run_json("apply", "claude", "--reveal-paths")
        self.assertEqual(code, EXIT_OK)
        self.assertIn(str(self.home), payload["real_config_path"])
        code, out, _ = self.run_cli("apply", "claude", "--reveal-paths")
        self.assertEqual(code, EXIT_OK)


class NonInterferenceTests(ConnectApplyCase):
    def test_other_hosts_and_the_repo_survive_an_apply(self):
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
        self.write_config(
            ".codeium",
            "windsurf",
            "mcp_config.json",
            content={"mcpServers": {"c7": {"command": "npx", "args": ["-y", "c7"]}}},
        )
        self.claude_config({"mcpServers": {}})
        home_before = self.snapshot(self.home)
        repo_before = set(self.snapshot(self.repo))

        code, _, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK)

        home_after = self.snapshot(self.home)
        changed = {
            name
            for name in set(home_before) | set(home_after)
            if home_before.get(name) != home_after.get(name)
        }
        claude_prefix = ".claude.json"
        for name in changed:
            self.assertTrue(
                name == claude_prefix or name.startswith(claude_prefix + "."),
                f"unexpected write outside the claude target: {name}",
            )
        for name in (str(Path(".config") / "opencode" / "opencode.json"),
                     str(Path(".codex") / "config.toml"),
                     str(Path(".codeium") / "windsurf" / "mcp_config.json")):
            self.assertEqual(home_before.get(name), home_after.get(name), name)

        repo_after = self.snapshot(self.repo)
        new_in_repo = set(repo_after) - repo_before
        self.assertTrue(new_in_repo, "the machine receipt was not recorded")
        for name in new_in_repo:
            self.assertTrue(
                name.startswith(".relinkra" + os.sep)
                or name.startswith(".relinkra/"),
                f"unexpected write inside the repository: {name}",
            )


class ClassificationTests(unittest.TestCase):
    def test_an_entry_named_relinkra_launching_something_else_is_foreign(self):
        entry = {"command": "node", "args": ["server.js"]}
        self.assertEqual(classify_server_entry(entry), "foreign")

    def test_an_entry_with_any_name_launching_relinkra_is_relinkra(self):
        entry = {"command": "/usr/bin/python3", "args": ["-m", SERVER_MODULE]}
        self.assertEqual(classify_server_entry(entry), "relinkra")

    def test_cbm_is_classified_by_launch_target_never_by_name(self):
        for entry in (
            {"command": "/opt/bin/codebase-memory-mcp", "args": []},
            {"command": "cbm", "args": ["serve"]},
            {"command": "python", "args": ["-m", "codebase_memory_mcp"]},
            {"command": "npx", "args": ["-y", "codebase-memory-mcp@1.2.3"]},
        ):
            with self.subTest(entry=entry):
                self.assertEqual(classify_server_entry(entry), "cbm")

    def test_a_mixed_relinkra_and_cbm_launch_is_classified_as_cbm(self):
        entry = {
            "command": "python",
            "args": ["-m", SERVER_MODULE, "codebase-memory-mcp"],
        }
        self.assertEqual(classify_server_entry(entry), "cbm")

    def test_entries_equivalent_is_exact_for_workspace_and_interpreter(self):
        # Equivalence drives no-op vs UPDATE decisions, so it is EXACT:
        # an entry pinned to a different workspace, interpreter or env
        # value is NOT equivalent (it must be updated, not silently
        # accepted). Tolerant STRUCTURAL classification lives in
        # launches_relinkra and is tested separately above.
        left = {
            "command": "/usr/bin/python3",
            "args": ["-m", SERVER_MODULE, "--workspace-root", "/a/repo"],
            "env": {"PYTHONPATH": "/a/repo"},
        }
        self.assertTrue(entries_equivalent(left, dict(left)))
        cross_workspace = {
            "command": "/usr/bin/python3",
            "args": ["-m", SERVER_MODULE, "--workspace-root", "/b/other"],
            "env": {"PYTHONPATH": "/b/other"},
        }
        self.assertFalse(entries_equivalent(left, cross_workspace))
        other_interpreter = dict(left, command="C:\\Python\\python.exe")
        self.assertFalse(entries_equivalent(left, other_interpreter))

    def test_entries_equivalent_notices_env_key_differences(self):
        left = {"command": "python", "args": ["-m", SERVER_MODULE]}
        right = dict(left, env={"PYTHONPATH": "/a/repo"})
        self.assertFalse(entries_equivalent(left, right))

    def test_entries_equivalent_notices_argument_differences(self):
        left = {"command": "python", "args": ["-m", SERVER_MODULE, "--verbose"]}
        right = {"command": "python", "args": ["-m", SERVER_MODULE]}
        self.assertFalse(entries_equivalent(left, right))


class VerificationStoreTests(ConnectApplyCase):
    def record_proof(self):
        proof_path = self.write_proof(self.valid_proof())
        code, out, err = self.run_cli(
            "verify", "claude", "--proof", str(proof_path), "--json"
        )
        self.assertEqual(code, EXIT_OK, err)
        return out

    def test_absent_evidence_is_reported_as_absent(self):
        status, record, reasons = assess_verification(
            self.repo, "claude", launch_fingerprint(self.launch())
        )
        self.assertEqual(status, STATUS_ABSENT)
        self.assertIsNone(record)
        self.assertTrue(reasons)

    def test_a_recorded_proof_assesses_as_valid(self):
        self.record_proof()
        status, record, _ = assess_verification(
            self.repo, "claude", launch_fingerprint(self.launch())
        )
        self.assertEqual(status, STATUS_VALID)
        self.assertIsNotNone(record)
        self.assertTrue(record.stages["handshake_succeeded"])
        self.assertEqual(record.tools_visible, ("context_packet", "memory_search"))

    def test_a_fingerprint_change_invalidates_the_evidence(self):
        self.record_proof()
        status, record, reasons = assess_verification(
            self.repo, "claude", "0" * 64
        )
        self.assertEqual(status, STATUS_STALE_FINGERPRINT)
        self.assertIsNotNone(record)
        self.assertTrue(any("launch contract" in reason for reason in reasons))

    def test_old_evidence_expires(self):
        proof = self.valid_proof()
        self.record_proof()
        store = self.repo / ".relinkra" / "connect-verification" / "claude.json"
        data = json.loads(store.read_text(encoding="utf-8"))
        data["timestamp"] = "2001-01-01T00:00:00+00:00"
        store.write_text(json.dumps(data, indent=2), encoding="utf-8")
        status, _, reasons = assess_verification(
            self.repo, "claude", launch_fingerprint(self.launch())
        )
        self.assertEqual(status, STATUS_EXPIRED)
        self.assertTrue(reasons)

    def test_verification_records_are_portable(self):
        out = self.record_proof()
        for value in iter_strings(json.loads(out)):
            self.assertFalse(contains_absolute_path(value), value)
        self.assertNotIn(str(self.repo), out)
        self.assertNotIn(str(self.home), out)


class VerifyCommandTests(ConnectApplyCase):
    def run_verify(self, payload):
        proof_path = self.write_proof(payload)
        return self.run_cli("verify", "claude", "--proof", str(proof_path))

    def test_a_valid_proof_is_recorded_with_its_invalidation_policy(self):
        code, out, _ = self.run_verify(self.valid_proof())
        self.assertEqual(code, EXIT_OK)
        self.assertIn("86400", out)
        self.assertIn("fingerprint", out)
        self.assertIn("handshake_succeeded", out)

    def test_a_proof_missing_required_stages_is_rejected(self):
        proof = self.valid_proof()
        del proof["stages"]["handshake_succeeded"]
        code, _, err = self.run_verify(proof)
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("handshake_succeeded", err)

    def test_a_proof_with_absolute_paths_is_rejected(self):
        proof = self.valid_proof()
        proof["tools_visible"] = [str(self.home / "tool")]
        code, _, err = self.run_verify(proof)
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("machine-local path", err)

    def test_a_proof_with_credential_keys_is_rejected(self):
        for key in ("api_token", "oauth_secret", "password", "key"):
            with self.subTest(key=key):
                proof = self.valid_proof()
                proof[key] = "value"
                code, _, err = self.run_verify(proof)
                self.assertEqual(code, EXIT_ACTION_REQUIRED)
                self.assertIn("credential-shaped", err)

    def test_a_proof_with_unknown_stages_is_rejected(self):
        proof = self.valid_proof()
        proof["stages"]["telepathy_confirmed"] = True
        code, _, err = self.run_verify(proof)
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("unknown stage", err)

    def test_a_malformed_proof_file_is_rejected(self):
        proof_path = Path(self._temp.name) / "proof.json"
        proof_path.write_text("{ not json", encoding="utf-8")
        code, _, _ = self.run_cli("verify", "claude", "--proof", str(proof_path))
        self.assertEqual(code, EXIT_ACTION_REQUIRED)

    def test_an_unknown_host_proof_is_rejected_by_the_builder(self):
        with self.assertRaises(ProofError):
            build_proof_from_payload(
                "emacs", self.valid_proof(), root=self.repo, fingerprint="x"
            )

    def test_verify_writes_nothing_on_rejection(self):
        proof = self.valid_proof()
        del proof["stages"]["host_launched"]
        code, _, _ = self.run_verify(proof)
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        store = self.repo / ".relinkra" / "connect-verification" / "claude.json"
        self.assertFalse(store.exists())


class CheckVerificationSectionTests(ConnectApplyCase):
    def test_check_reports_absent_host_evidence_without_failing(self):
        self.claude_config(
            {"mcpServers": {MANAGED_SERVER_NAME: self.registered_claude_entry()}}
        )
        code, payload, _ = self.run_json("check", "claude")
        self.assertEqual(code, EXIT_OK)
        self.assertTrue(payload["valid"])
        verification = payload["verification"]
        self.assertEqual(verification["status"], STATUS_ABSENT)
        self.assertFalse(verification["fully_verified"])

    def test_config_invalid_still_exits_two_with_evidence_absent(self):
        self.claude_config({"mcpServers": {}})
        code, payload, _ = self.run_json("check", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertEqual(payload["verification"]["status"], STATUS_ABSENT)

    def test_a_recorded_proof_is_local_evidence_not_independent_attestation(self):
        self.claude_config(
            {"mcpServers": {MANAGED_SERVER_NAME: self.registered_claude_entry()}}
        )
        proof_path = self.write_proof(self.valid_proof())
        code, _, _ = self.run_cli("verify", "claude", "--proof", str(proof_path))
        self.assertEqual(code, EXIT_OK)
        code, payload, _ = self.run_json("check", "claude")
        self.assertEqual(code, EXIT_OK)
        verification = payload["verification"]
        self.assertEqual(verification["status"], STATUS_VALID)
        self.assertTrue(verification["locally_verified"])
        self.assertFalse(verification["fully_verified"])
        self.assertFalse(verification["independently_attested"])
        self.assertTrue(verification["record"]["stages"]["host_launched"])

    def test_check_human_output_states_the_host_caveat(self):
        self.claude_config(
            {"mcpServers": {MANAGED_SERVER_NAME: self.registered_claude_entry()}}
        )
        code, out, _ = self.run_cli("check", "claude")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Verification", out)
        self.assertIn("absent", out)
        self.assertIn("connect verify", out)


class TrustLadderEvidenceTests(ConnectApplyCase):
    def ladder(self, fingerprint):
        env = self.env()
        hosts = survey_hosts(env)
        return build_trust_ladder(
            hosts,
            launch_resolved=True,
            relinkra_registered=True,
            route=ROUTE_UNVERIFIED,
            metrics_trust=TRUST_UNVERIFIED,
            bypass_detected=False,
            handoffs_available=None,
            tools_declared=9,
            real_host_launch_proven=False,
            workspace_root=self.repo,
            verification_fingerprint=fingerprint,
        )

    HOST_STAGES = (
        STAGE_HANDSHAKE_VERIFIED,
        STAGE_TOOLS_VISIBLE,
        STAGE_REQUIRED_TOOLS_CALLABLE,
        STAGE_HANDOFF_ROUND_TRIP,
        STAGE_REAL_HOST_LAUNCH,
    )

    def test_applied_config_without_evidence_keeps_host_stages_unverified(self):
        self.claude_config({"mcpServers": {}})
        code, _, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK)
        stages = self.ladder(launch_fingerprint(self.launch())).by_stage()
        # Config-side rungs keep their structural behaviour.
        self.assertTrue(stages[STAGE_CONFIGURATION_PRESENT].proven)
        self.assertTrue(stages[STAGE_REGISTRATION_DETECTED].proven)
        self.assertTrue(stages[STAGE_MCP_CONTRACT_CONFIGURED].proven)
        # Host-side rungs are unverified until a host proves itself.
        for stage in self.HOST_STAGES:
            with self.subTest(stage=stage):
                self.assertEqual(stages[stage].state, STAGE_UNVERIFIED)
                self.assertIn("no local host evidence", stages[stage].evidence)

    def test_a_valid_proof_promotes_the_host_stages(self):
        self.claude_config({"mcpServers": {}})
        code, _, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK)
        proof_path = self.write_proof(self.valid_proof())
        code, _, _ = self.run_cli("verify", "claude", "--proof", str(proof_path))
        self.assertEqual(code, EXIT_OK)
        ladder = self.ladder(launch_fingerprint(self.launch()))
        stages = ladder.by_stage()
        for stage in self.HOST_STAGES:
            with self.subTest(stage=stage):
                self.assertTrue(stages[stage].proven)
                self.assertIn("valid local host evidence", stages[stage].evidence)
        # The route is still not fully proven: protocol compatibility,
        # context routing and the rest have no evidence either way.
        self.assertFalse(ladder.all_proven)

    def test_a_fingerprint_change_returns_the_host_stages_to_unverified(self):
        self.claude_config({"mcpServers": {}})
        code, _, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK)
        proof_path = self.write_proof(self.valid_proof())
        code, _, _ = self.run_cli("verify", "claude", "--proof", str(proof_path))
        self.assertEqual(code, EXIT_OK)
        stages = self.ladder("f" * 64).by_stage()
        for stage in self.HOST_STAGES:
            with self.subTest(stage=stage):
                self.assertEqual(stages[stage].state, STAGE_UNVERIFIED)
                self.assertIn("stale", stages[stage].evidence)

    def test_doctor_reflects_bounded_local_evidence(self):
        self.claude_config({"mcpServers": {}})
        code, _, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["doctor", "--json", "--path", str(self.repo)])
        self.assertIn(code, (EXIT_OK, EXIT_ACTION_REQUIRED))
        payload = json.loads(out.getvalue())
        ladder_stages = {
            stage["stage"]: stage
            for stage in payload["routing"]["trust_ladder"]["stages"]
        }
        self.assertEqual(
            ladder_stages[STAGE_HANDSHAKE_VERIFIED]["state"], "unverified"
        )
        self.assertFalse(payload["routing"]["trust_ladder"]["all_proven"])

        proof_path = self.write_proof(self.valid_proof())
        code, _, _ = self.run_cli("verify", "claude", "--proof", str(proof_path))
        self.assertEqual(code, EXIT_OK)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            main(["doctor", "--json", "--path", str(self.repo)])
        payload = json.loads(out.getvalue())
        ladder_stages = {
            stage["stage"]: stage
            for stage in payload["routing"]["trust_ladder"]["stages"]
        }
        self.assertEqual(ladder_stages[STAGE_HANDSHAKE_VERIFIED]["state"], "proven")
        self.assertIn(
            "valid local host evidence",
            ladder_stages[STAGE_HANDSHAKE_VERIFIED]["evidence"],
        )
        self.assertFalse(payload["routing"]["trust_ladder"]["all_proven"])


class EngineDirectTests(ConnectApplyCase):
    def test_apply_engine_reports_a_machine_receipt(self):
        self.claude_config({"mcpServers": {}})
        result = apply_connector(CLAUDE, self.launch(), self.env())
        self.assertTrue(result.ok)
        receipt_path = self.repo / ".relinkra" / "connect-apply" / "claude.json"
        self.assertTrue(receipt_path.is_file())
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(receipt["host"], "claude")
        self.assertEqual(receipt["launch_fingerprint"], result.launch_fingerprint)
        self.assertEqual(receipt["digest_after"], result.digest_after)
        self.assertTrue(receipt["backup_path"])
        self.assertEqual(receipt["workspace_root"], str(self.repo.resolve()))

    def test_a_receipt_failure_degrades_to_a_warning_not_a_failure(self):
        self.claude_config({"mcpServers": {}})
        with mock.patch.object(
            connector_apply,
            "_persist_receipt",
            side_effect=lambda result, *, backup_path: result.warnings.__add__(
                ("receipt skipped (test)",)
            ),
        ):
            result = apply_connector(CLAUDE, self.launch(), self.env())
        self.assertTrue(result.ok)

    def test_the_result_portable_dict_never_carries_machine_values(self):
        self.claude_config({"mcpServers": {}})
        result = apply_connector(CLAUDE, self.launch(), self.env())
        for value in iter_strings(result.to_dict()):
            self.assertFalse(contains_absolute_path(value), value)
        machine = result.to_machine_dict()
        self.assertIn(str(self.home), machine["real_config_path"])


class RollbackHardeningTests(ConnectApplyCase):
    """Mutation-killing tests for the rollback safety gates (4R findings)."""

    def _apply(self):
        code, payload, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK, payload)

    def _receipt_path(self):
        return self.repo / ".relinkra" / "connect-apply" / "claude.json"

    def _rewrite_receipt(self, mutate):
        receipt = self._receipt_path()
        data = json.loads(receipt.read_text(encoding="utf-8"))
        mutate(data)
        receipt.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def test_rollback_refuses_when_the_recorded_backup_is_missing(self):
        self.claude_config({"mcpServers": {}})
        self._apply()
        backup = self.claude_path().with_name(".claude.json.relinkra-backup")
        self.assertTrue(backup.is_file())
        backup.unlink()
        kept = self.claude_path().read_bytes()
        code, payload, _ = self.run_json("rollback", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("no longer exists", payload["refusal_reason"])
        self.assertFalse(payload["rollback_succeeded"])
        self.assertEqual(self.claude_path().read_bytes(), kept)

    def test_rollback_refuses_a_backup_that_fails_the_receipt_digest(self):
        self.claude_config({"mcpServers": {}})
        self._apply()
        backup = self.claude_path().with_name(".claude.json.relinkra-backup")
        backup.write_bytes(b'{"mcpServers": {}, "tampered": true}')
        kept = self.claude_path().read_bytes()
        code, payload, _ = self.run_json("rollback", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("backup digest", payload["refusal_reason"])
        self.assertEqual(self.claude_path().read_bytes(), kept)

    def test_rollback_fails_closed_on_an_incomplete_receipt(self):
        self.claude_config({"mcpServers": {}})
        self._apply()
        self._rewrite_receipt(lambda data: data.update({"digest_after": ""}))
        kept = self.claude_path().read_bytes()
        code, payload, _ = self.run_json("rollback", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("incomplete", payload["refusal_reason"])
        self.assertEqual(self.claude_path().read_bytes(), kept)

    def test_rollback_refuses_a_receipt_target_outside_known_locations(self):
        self.claude_config({"mcpServers": {}})
        self._apply()
        outside = Path(self._temp.name) / "elsewhere.json"
        outside.write_text("{}", encoding="utf-8")
        self._rewrite_receipt(
            lambda data: data.update({"target_path": str(outside)})
        )
        code, payload, _ = self.run_json("rollback", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("known locations", payload["refusal_reason"])
        self.assertEqual(outside.read_text(encoding="utf-8"), "{}")

    def test_rollback_rechecks_the_digest_inside_the_lock(self):
        self.claude_config({"mcpServers": {}})
        self._apply()
        original_lock = connector_apply.interprocess_lock
        claude_path = self.claude_path()

        def hostile_lock(target):
            context = original_lock(target)

            class _Context:
                def __enter__(self):
                    context.__enter__()
                    # The host rewrites its own state file mid-restore.
                    document = json.loads(claude_path.read_text(encoding="utf-8"))
                    document["host_write"] = True
                    claude_path.write_text(
                        json.dumps(document, indent=2), encoding="utf-8"
                    )
                    return context

                def __exit__(self, *args):
                    return context.__exit__(*args)

            return _Context()

        with mock.patch.object(connector_apply, "interprocess_lock", hostile_lock):
            code, payload, _ = self.run_json("rollback", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("external edits", payload["refusal_reason"])
        self.assertFalse(payload["rollback_succeeded"])
        # The mid-restore host write survives; it is never overwritten.
        current = json.loads(claude_path.read_text(encoding="utf-8"))
        self.assertTrue(current.get("host_write"))

    def test_rollback_post_restore_digest_mismatch_is_a_failure(self):
        self.claude_config({"mcpServers": {}})
        self._apply()
        self._rewrite_receipt(lambda data: data.update({"digest_before": "0" * 64}))
        code, payload, _ = self.run_json("rollback", "claude")
        self.assertNotEqual(code, EXIT_OK)
        self.assertFalse(payload["rollback_succeeded"])
        self.assertIn(
            "does not match the recorded pre-apply digest", payload["error"]
        )

    def test_rollback_without_receipt_picks_the_highest_suffix_backup(self):
        path = self.claude_config({"mcpServers": {}})
        first_bytes = path.read_bytes()
        self._apply()  # base backup (suffix index 0) holds first_bytes
        newer = self.claude_path().with_name(".claude.json.relinkra-backup-1")
        newer_content = (
            json.dumps({"mcpServers": {}, "newer_state": True}, indent=2) + "\n"
        )
        newer.write_bytes(newer_content.encode("utf-8"))
        self._receipt_path().unlink()
        code, payload, _ = self.run_json("rollback", "claude")
        self.assertEqual(code, EXIT_OK, payload)
        # Highest suffix == newest; a min() mutant would restore first_bytes.
        self.assertEqual(
            self.claude_path().read_bytes(), newer_content.encode("utf-8")
        )
        self.assertNotEqual(first_bytes, newer_content.encode("utf-8"))


class NoOpVerificationTests(ConnectApplyCase):
    def test_noop_with_operator_env_keys_verifies_truthfully(self):
        desired = self.registered_claude_entry()
        entry = dict(desired)
        entry["env"] = dict(desired.get("env", {}), DEBUG="1")
        self.claude_config({"mcpServers": {MANAGED_SERVER_NAME: entry}})
        code, payload, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertFalse(payload["change_required"])
        self.assertTrue(payload["registration_matches_expected"])
        self.assertTrue(payload["validation_succeeded"])
        self.assertEqual(
            payload["verification_stage"], "config_applied_host_unverified"
        )
        document = json.loads(self.claude_path().read_text(encoding="utf-8"))
        self.assertEqual(
            self.mcp_servers(document)[MANAGED_SERVER_NAME]["env"].get("DEBUG"),
            "1",
        )

    def test_update_preserves_operator_env_keys(self):
        desired = self.registered_claude_entry()
        stale = dict(
            desired,
            args=["-m", SERVER_MODULE, "--workspace-root", "/old/path"],
        )
        stale["env"] = dict(desired.get("env", {}), DEBUG="1")
        self.claude_config({"mcpServers": {MANAGED_SERVER_NAME: stale}})
        code, payload, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["change_required"])
        document = json.loads(self.claude_path().read_text(encoding="utf-8"))
        env = self.mcp_servers(document)[MANAGED_SERVER_NAME]["env"]
        self.assertEqual(env.get("DEBUG"), "1")
        for key, value in desired.get("env", {}).items():
            self.assertEqual(env.get(key), value)


class ApplyPreservationHardeningTests(ConnectApplyCase):
    def test_non_ascii_content_survives_the_round_trip(self):
        self.claude_config(
            {"mcpServers": {"c7": {"command": "npx", "args": ["ñandú", "日本語"]}}}
        )
        code, _, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK)
        raw = self.claude_path().read_text(encoding="utf-8")
        # ensure_ascii=False keeps the operator's text readable as UTF-8.
        self.assertIn("ñandú", raw)
        document = json.loads(raw)
        self.assertEqual(
            self.mcp_servers(document)["c7"]["args"], ["ñandú", "日本語"]
        )

    def test_a_file_without_trailing_newline_stays_without_one(self):
        self.write_config(
            ".claude.json",
            content=json.dumps({"projects": {}}, indent=2),
        )
        self.assertFalse(self.claude_path().read_bytes().endswith(b"\n"))
        code, _, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK)
        self.assertFalse(self.claude_path().read_bytes().endswith(b"\n"))


class VerificationPrecedenceTests(ConnectApplyCase):
    def test_stale_fingerprint_wins_over_expired(self):
        proof_path = self.write_proof(self.valid_proof())
        code, _, err = self.run_cli(
            "verify", "claude", "--proof", str(proof_path), "--json"
        )
        self.assertEqual(code, EXIT_OK, err)
        store = self.repo / ".relinkra" / "connect-verification" / "claude.json"
        data = json.loads(store.read_text(encoding="utf-8"))
        data["timestamp"] = "2001-01-01T00:00:00+00:00"
        store.write_text(json.dumps(data, indent=2), encoding="utf-8")
        # Both expired AND fingerprint-mismatched: stale_fingerprint is
        # the precedence-pinned answer, not whichever check runs first.
        status, _, _ = assess_verification(self.repo, "claude", "0" * 64)
        self.assertEqual(status, STATUS_STALE_FINGERPRINT)


class ProofIngestionHardeningTests(ConnectApplyCase):
    def test_a_deeply_nested_proof_is_refused_without_a_traceback(self):
        proof_path = Path(self._temp.name) / "deep-proof.json"
        proof_path.write_text("[" * 5000 + "1" + "]" * 5000, encoding="utf-8")
        code, out, err = self.run_cli(
            "verify", "claude", "--proof", str(proof_path)
        )
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertNotIn("Traceback", out + err)
        store = self.repo / ".relinkra" / "connect-verification" / "claude.json"
        self.assertFalse(store.exists())

    def test_tool_names_with_control_characters_are_rejected(self):
        proof = self.valid_proof()
        proof["tools_visible"] = ["context_packet\x1b[31m"]
        code, _, err = self.run_cli(
            "verify", "claude", "--proof", str(self.write_proof(proof))
        )
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("control character", err)


class CriticalClosureMutationTests(ConnectApplyCase):
    """Discriminating probes for the critical closure, not happy-path counts."""

    def _recorded_store(self):
        self.claude_config({"mcpServers": {MANAGED_SERVER_NAME: self.registered_claude_entry()}})
        self.assertEqual(self.run_cli("verify", "claude", "--proof", str(self.write_proof(self.valid_proof())))[0], EXIT_OK)
        return self.repo / ".relinkra" / "connect-verification" / "claude.json"

    def test_forged_all_true_empty_tools_wrong_scope_and_source_never_becomes_valid(self):
        store = self._recorded_store()
        data = json.loads(store.read_text(encoding="utf-8"))
        data["workspace_root"] = str(self.home / "other-workspace")
        data["source"] = "forged"
        data["tools_visible"] = []
        data["tools_invoked"] = []
        data["stages"] = {stage: True for stage in (
            "config_detected", "config_applied", "config_valid", "protocol_compatible",
            "host_launched", "handshake_succeeded", "tools_visible", "tools_callable",
            "context_roundtrip", "handoff_roundtrip",
        )}
        store.write_text(json.dumps(data), encoding="utf-8")
        status, _, reasons = assess_verification(self.repo, "claude", data["registration_fingerprint"])
        self.assertNotEqual(status, STATUS_VALID)
        self.assertTrue(reasons or status == STATUS_ABSENT)
        code, payload, _ = self.run_json("check", "claude")
        self.assertEqual(code, EXIT_OK)
        self.assertFalse(payload["verification"]["fully_verified"])
        self.assertFalse(payload["verification"]["independently_attested"])
        routing_code, routing_payload, _ = self.run_json("routing")
        self.assertNotEqual(routing_code, EXIT_OK)
        self.assertNotEqual(routing_payload["context_route"], "managed")

    def test_future_timestamp_is_rejected(self):
        store = self._recorded_store()
        data = json.loads(store.read_text(encoding="utf-8"))
        data["timestamp"] = "2999-01-01T00:00:00+00:00"
        store.write_text(json.dumps(data), encoding="utf-8")
        status, _, reasons = assess_verification(self.repo, "claude", data["registration_fingerprint"])
        self.assertEqual(status, STATUS_INVALID)
        self.assertTrue(any("future" in reason for reason in reasons))

    def test_duplicate_and_nonfinite_proof_fail_closed(self):
        store = self._recorded_store()
        store.write_text('{"schema_version":"relinkra.connect-verification/v1","schema_version":"relinkra.connect-verification/v1"}', encoding="utf-8")
        status, _, _ = assess_verification(self.repo, "claude", "0" * 64)
        self.assertEqual(status, STATUS_ABSENT)
        store.write_text("{" + "\"schema_version\":NaN}", encoding="utf-8")
        status, _, _ = assess_verification(self.repo, "claude", "0" * 64)
        self.assertEqual(status, STATUS_ABSENT)

    def test_oversized_proof_fails_closed(self):
        store = self._recorded_store()
        store.write_text("{" + "\"x\":\"" + ("a" * 70000) + "\"}", encoding="utf-8")
        status, _, _ = assess_verification(self.repo, "claude", "0" * 64)
        self.assertEqual(status, STATUS_ABSENT)

    def test_semantic_post_write_failure_restores_exact_original_and_keeps_no_receipt(self):
        self.claude_config({"mcpServers": {}})
        original = self.claude_path().read_bytes()
        real_decide = connector_apply.decide_member
        calls = {"count": 0}

        def fail_after_write(*args, **kwargs):
            calls["count"] += 1
            if calls["count"] >= 3:
                raise connector_apply.MergeError("synthetic semantic failure")
            return real_decide(*args, **kwargs)

        with mock.patch.object(connector_apply, "decide_member", side_effect=fail_after_write):
            result = apply_connector(CLAUDE, self.launch(), self.env())
        self.assertTrue(result.rollback_attempted)
        self.assertTrue(result.rollback_succeeded)
        self.assertFalse(result.ok)
        self.assertEqual(self.claude_path().read_bytes(), original)
        self.assertFalse((self.repo / ".relinkra" / "connect-apply" / "claude.json").exists())

    def test_safe_replace_final_digest_gate_catches_deterministic_external_edit(self):
        path = self.repo / "race.json"
        path.write_text('{"before":true}\n', encoding="utf-8")
        original = path.read_bytes()

        def external_edit(target):
            target.write_text('{"external":true}\n', encoding="utf-8")

        with self.assertRaises(PreconditionError):
            safe_replace(
                path,
                '{"after":true}\n',
                expected_digest=digest_text(read_bounded_text(path)),
                before_replace_hook=external_edit,
            )
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"external": True})

    def test_receipt_external_backup_path_is_rejected_without_touching_target(self):
        self.claude_config({"mcpServers": {}})
        self.assertEqual(self.run_json("apply", "claude")[0], EXIT_OK)
        receipt = self.repo / ".relinkra" / "connect-apply" / "claude.json"
        data = json.loads(receipt.read_text(encoding="utf-8"))
        outside = self.home / "foreign-backup.json"
        outside.write_text("{\"foreign\":true}\n", encoding="utf-8")
        data["backup_path"] = str(outside)
        receipt.write_text(json.dumps(data), encoding="utf-8")
        kept = self.claude_path().read_bytes()
        code, payload, _ = self.run_json("rollback", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("backup", payload["refusal_reason"])
        self.assertEqual(self.claude_path().read_bytes(), kept)
        self.assertEqual(outside.read_text(encoding="utf-8"), '{"foreign":true}\n')

    def test_receipt_relative_backup_traversal_is_rejected(self):
        self.claude_config({"mcpServers": {}})
        self.assertEqual(self.run_json("apply", "claude")[0], EXIT_OK)
        receipt = self.repo / ".relinkra" / "connect-apply" / "claude.json"
        data = json.loads(receipt.read_text(encoding="utf-8"))
        data["backup_path"] = "..\\claude.json.relinkra-backup"
        receipt.write_text(json.dumps(data), encoding="utf-8")
        kept = self.claude_path().read_bytes()
        code, payload, _ = self.run_json("rollback", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("backup", payload["refusal_reason"])
        self.assertEqual(self.claude_path().read_bytes(), kept)

    def test_receipt_symlink_backup_is_rejected(self):
        self.claude_config({"mcpServers": {}})
        self.assertEqual(self.run_json("apply", "claude")[0], EXIT_OK)
        backup = self.claude_path().with_name(".claude.json.relinkra-backup")
        foreign = self.home / "foreign-backup.json"
        foreign.write_text('{"foreign":true}\n', encoding="utf-8")
        backup_bytes = backup.read_bytes()
        backup.unlink()
        try:
            os.symlink(str(foreign), str(backup))
        except (OSError, NotImplementedError) as exc:
            backup.write_bytes(backup_bytes)
            self.skipTest(f"symlink creation unavailable: {exc}")
        kept = self.claude_path().read_bytes()
        code, payload, _ = self.run_json("rollback", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("backup", payload["refusal_reason"])
        self.assertEqual(self.claude_path().read_bytes(), kept)

    def test_backup_edit_between_precheck_and_locked_restore_is_rejected(self):
        self.claude_config({"mcpServers": {}})
        self.assertEqual(self.run_json("apply", "claude")[0], EXIT_OK)
        backup = self.claude_path().with_name(".claude.json.relinkra-backup")
        kept = self.claude_path().read_bytes()
        original_lock = connector_apply.interprocess_lock

        def hostile_lock(target):
            context = original_lock(target)

            class _Context:
                def __enter__(self_inner):
                    value = context.__enter__()
                    backup.write_bytes(b'{"tampered":true}\n')
                    return value

                def __exit__(self_inner, *args):
                    return context.__exit__(*args)

            return _Context()

        with mock.patch.object(connector_apply, "interprocess_lock", hostile_lock):
            code, payload, _ = self.run_json("rollback", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("changed before restore", payload["refusal_reason"])
        self.assertEqual(self.claude_path().read_bytes(), kept)

    def test_unsupported_connector_rollback_is_refused_before_discovery(self):
        result = rollback_connector(
            relinkra_connectors.CODEX,
            self.env(),
            workspace_root=self.repo,
        )
        self.assertTrue(result.refused)
        self.assertFalse(result.rollback_attempted)

    def test_opencode_rollback_is_supported_and_reaches_the_receipt_gate(self):
        # R4C.1C: rollback is no longer refused as unsupported; with no
        # prior apply it reaches the ordinary receipt/backup gate instead.
        result = rollback_connector(
            relinkra_connectors.OPENCODE,
            self.env(),
            workspace_root=self.repo,
        )
        self.assertTrue(result.refused)
        self.assertIn("no machine receipt and no backup", result.refusal_reason)

    def test_top_level_direct_cbm_is_detected_even_when_project_scope_is_selected(self):
        document = {
            "mcpServers": {"friendly": {"command": "codebase-memory-mcp", "args": []}},
            "projects": {claude_project_key(self.repo): {"mcpServers": {}}},
        }
        self.assertGreater(
            connector_apply._direct_cbm_entries(
                document,
                ("projects", claude_project_key(self.repo), "mcpServers"),
                relinkra_connectors.CLAUDE.inherited_container_paths,
            ),
            0,
        )

    def test_present_unreadable_workspace_mcp_scope_does_not_claim_clean_apply(self):
        self.claude_config({"mcpServers": {}})
        (self.repo / ".mcp.json").mkdir()
        code, payload, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("authoritative project MCP scope", payload["refusal_reason"])

    def test_workspace_mcp_scope_direct_cbm_is_refused_even_when_json_is_valid(self):
        self.claude_config({"mcpServers": {}})
        (self.repo / ".mcp.json").write_text(
            json.dumps(
                {"mcpServers": {"friendly-name": {"command": "codebase-memory-mcp"}}}
            ),
            encoding="utf-8",
        )
        code, payload, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("direct codebase-memory", payload["refusal_reason"])


if __name__ == "__main__":
    unittest.main()
