"""Tests for the Codex connector write path (R4C.1D).

Mirrors ``tests.test_connect_apply_opencode``: every test drives either
the real CLI through ``main(argv)`` or the real engine against a fixture
home plus a fake repository, with host discovery monkeypatched the same
way. The Codex fixture writes REAL TOML — comments, inline comments,
unknown top-level fields, unknown tables, arrays of tables, single- and
double-quoted strings and escaped Windows paths — because the write
strategy is a scoped textual editor and every mutation assertion also
proves the untouched regions survive byte-for-byte.

Each protection test is discriminating: removing the protection (the
direct-CBM gate, the dotted-key refusal, backup confinement, semantic
rollback, the external-edit digest gate, idempotence, newline/BOM
preservation, forged-proof rejection or portable redaction) makes THAT
test fail.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from relinkra import connect_cli, connector_apply, product_cli
from relinkra import connectors as relinkra_connectors
from relinkra import toml_edit
from relinkra.connect_verification import (
    STATUS_ABSENT,
    STATUS_EXPIRED,
    STATUS_INVALID,
    STATUS_STALE_FINGERPRINT,
    STATUS_VALID,
    assess_verification,
)
from relinkra.connector import MANAGED_SERVER_NAME, iter_strings
from relinkra.connector_apply import (
    apply_connector,
    launch_fingerprint,
    rollback_connector,
)
from relinkra.connectors import (
    CLAUDE,
    CODEX,
    OPENCODE,
    SERVER_MODULE,
    claude_project_key,
    entry_tokens,
    launches_relinkra,
    resolve_host_launch,
    resolve_launch,
)
from relinkra.handoff import contains_absolute_path
from relinkra.freshness import (
    FreshnessContext,
    FreshnessState,
    evaluate_freshness,
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
    WARN,
    WorkspaceConfig,
    main,
    registry_path,
)
from relinkra.registry import Registry
from relinkra.safe_write import digest_text
from relinkra.toml_edit import serialize_member_toml

_SECRET = "sk-live-CODEX-DO-NOT-LEAK-0123456789"

_ENGRAM_TABLE = '[mcp_servers.engram]\ncommand = "engram"\nargs = ["mcp"]\n'


def setUpModule():
    """Codex TOML I/O is fail-closed without tomllib (Python 3.11+).

    Every test in this module drives the real apply/rollback/check path,
    which honestly REFUSES on a tomllib-less interpreter — including the
    tests that mock parser absence, since their fixtures still apply for
    real first. On 3.9/3.10 the suite would only re-prove the refusal
    contract that ``tests.test_platform_honesty`` already covers, so skip
    the module instead of repeating it.
    """
    if not toml_edit.toml_parser_available():
        raise unittest.SkipTest("codex TOML I/O requires tomllib (Python 3.11+)")


class ConnectApplyCodexCase(unittest.TestCase):
    """A fake repository plus a fixture home, discovery monkeypatched."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="relinkra-connect-apply-cx-")
        self.addCleanup(self._temp.cleanup)
        base = Path(self._temp.name)
        self.home = base / "home"
        self.home.mkdir()
        self.repo = base / "repo"
        (self.repo / ".git").mkdir(parents=True)
        self.root = self.repo.resolve()
        workspace = Registry(str(registry_path(self.repo))).register_workspace(
            str(self.repo), explicit_identity("fixture")
        )
        WorkspaceConfig(
            project_id=workspace.project_id,
            workspace_id=workspace.workspace_id,
        ).save(self.repo)
        self.workspace_id = workspace.workspace_id

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
        path.write_bytes(text.encode("utf-8"))
        return path

    def codex_config(self, content):
        """Write the user-scope Codex config as RAW TOML bytes."""
        return self.write_config(".codex", "config.toml", content=content)

    def codex_path(self):
        return self.home / ".codex" / "config.toml"

    def backup_path(self):
        return self.codex_path().with_name("config.toml.relinkra-backup")

    def receipt_path(self):
        return self.repo / ".relinkra" / "connect-apply" / "codex.json"

    def verification_store(self):
        return self.repo / ".relinkra" / "connect-verification" / "codex.json"

    def launch(self):
        return resolve_host_launch("codex", self.repo, registry_path(self.repo))

    def pinned_launch(self):
        return resolve_launch(self.repo, registry_path(self.repo))

    def foreign_pinned_launch(self):
        foreign_root = self.root.parent / "other-workspace"
        return resolve_launch(foreign_root, registry_path(foreign_root))

    def registered_codex_entry(self):
        return CODEX.entry_builder(self.launch())

    def registered_toml(self, entry=None):
        """The managed table rendered exactly as an apply would render it."""
        return serialize_member_toml(
            "",
            ("mcp_servers",),
            MANAGED_SERVER_NAME,
            entry if entry is not None else self.registered_codex_entry(),
        )

    def claude_config(self, servers):
        document = {
            "projects": {
                claude_project_key(self.root): {"mcpServers": servers}
            }
        }
        return self.write_config(".claude.json", content=document)

    def opencode_config(self, servers):
        return self.write_config(
            ".config", "opencode", "opencode.json", content={"mcp": servers}
        )

    def snapshot(self, root):
        return {
            str(p.relative_to(root)): p.read_bytes()
            for p in sorted(root.rglob("*"))
            if p.is_file()
        }

    def assert_untouched(self, path, before):
        self.assertEqual(path.read_bytes(), before)
        backups = list(path.parent.glob(path.name + ".relinkra-backup*"))
        self.assertEqual(backups, [])

    def parsed(self, path):
        import tomllib

        return tomllib.loads(path.read_text(encoding="utf-8"))

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

    def run_doctor(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["doctor", "--json", "--path", str(self.repo)])
        self.assertIn(code, (EXIT_OK, EXIT_ACTION_REQUIRED))
        return json.loads(out.getvalue())

    def valid_proof(self):
        return {
            # The completed Codex host invocation did not establish
            # workspace-local identity, so null is the honest value.
            "workspace_id": None,
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

    def record_codex_proof(self):
        proof_path = self.write_proof(self.valid_proof())
        code, _, err = self.run_cli(
            "verify", "codex", "--proof", str(proof_path), "--json"
        )
        self.assertEqual(code, EXIT_OK, err)


class CodexApplyBasicsTests(ConnectApplyCodexCase):
    def test_empty_config_gains_the_entry_with_a_backup(self):
        path = self.codex_config("")
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["change_required"])
        self.assertTrue(payload["backup_created"])
        self.assertTrue(payload["write_succeeded"])
        self.assertTrue(payload["validation_succeeded"])
        self.assertEqual(payload["verification_stage"], "config_applied_host_unverified")
        self.assertFalse(payload["real_host_verified"])
        self.assertEqual(payload["config_path"], "~/.codex/config.toml")
        document = self.parsed(path)
        entry = document["mcp_servers"][MANAGED_SERVER_NAME]
        self.assertEqual(entry["command"], self.registered_codex_entry()["command"])
        self.assertIsInstance(entry["args"], list)
        self.assertTrue(launches_relinkra(entry))
        self.assertTrue(self.backup_path().is_file())

    def test_a_missing_config_is_created_and_rollback_removes_it(self):
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(self.codex_path().is_file())
        entry = self.parsed(self.codex_path())["mcp_servers"][MANAGED_SERVER_NAME]
        self.assertTrue(launches_relinkra(entry))
        code, payload, _ = self.run_json("rollback", "codex")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["rollback_succeeded"])
        self.assertFalse(self.codex_path().exists())

    def test_existing_comments_and_inline_comments_survive(self):
        original = (
            "# Codex configuration — hand-maintained\n"
            'model = "gpt-5" # inline comment on an unknown field\n'
            "\n"
            "[mcp_servers.engram] # inline comment on a table header\n"
            'command = "engram" # inline comment on a key\n'
            'args = ["mcp"]\n'
            "\n"
            "# trailing comment block\n"
        )
        path = self.codex_config(original)
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_OK, payload)
        after = path.read_bytes()
        self.assertTrue(after.startswith(original.encode("utf-8")))
        document = self.parsed(path)
        self.assertEqual(document["model"], "gpt-5")
        self.assertIn(MANAGED_SERVER_NAME, document["mcp_servers"])

    def test_unknown_tables_and_arrays_of_tables_survive(self):
        original = (
            'unknown_top = "keep me"\n'
            "\n"
            "[profiles.work]\n"
            'model = "gpt-5"\n'
            "\n"
            "[[history.entries]]\n"
            'id = 1\n'
            "\n"
            "[[history.entries]]\n"
            'id = 2\n'
            "\n"
            + _ENGRAM_TABLE
        )
        path = self.codex_config(original)
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(path.read_bytes().startswith(original.encode("utf-8")))
        document = self.parsed(path)
        self.assertEqual(document["profiles"]["work"]["model"], "gpt-5")
        self.assertEqual(document["history"]["entries"], [{"id": 1}, {"id": 2}])
        self.assertEqual(
            document["mcp_servers"]["engram"], {"command": "engram", "args": ["mcp"]}
        )

    def test_string_styles_and_escaped_windows_paths_survive(self):
        original = (
            "[mcp_servers.engram]\n"
            "command = 'C:\\tools\\engram.exe'\n"
            'args = ["mcp"]\n'
            "\n"
            "[mcp_servers.toolbox]\n"
            'command = "C:\\\\tools\\\\toolbox.exe"\n'
            'args = ["run", "--home", "C:\\\\Users\\\\dev"]\n'
        )
        path = self.codex_config(original)
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(path.read_bytes().startswith(original.encode("utf-8")))
        document = self.parsed(path)
        self.assertEqual(document["mcp_servers"]["engram"]["command"], "C:\\tools\\engram.exe")
        self.assertEqual(
            document["mcp_servers"]["toolbox"]["command"], "C:\\tools\\toolbox.exe"
        )

    def test_a_registration_for_another_workspace_is_updated_not_corrupted(self):
        desired = self.registered_codex_entry()
        stale = CODEX.entry_builder(self.foreign_pinned_launch())
        original = (
            "# header comment\n"
            + self.registered_toml(stale)
            + "\n# between comment\n"
            + _ENGRAM_TABLE
            + "# tail comment\n"
        )
        path = self.codex_config(original)
        code, payload, _ = self.run_json("apply", "codex")
        # The engine must not silently accept a foreign-workspace entry
        # as equivalent (a no-op), nor refuse it as a conflict: it is a
        # managed entry pinned elsewhere, so it is UPDATED in place.
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["change_required"])
        self.assertTrue(payload["write_succeeded"])
        document = self.parsed(path)
        entry = document["mcp_servers"][MANAGED_SERVER_NAME]
        self.assertTrue(launches_relinkra(entry))
        self.assertEqual(entry, desired)
        tokens = entry_tokens(entry)
        self.assertNotIn("--workspace-root", tokens)
        self.assertNotIn("--registry", tokens)
        self.assertTrue(payload["registration_matches_expected"])
        # Everything outside the managed region survived byte-for-byte.
        after = path.read_text(encoding="utf-8")
        self.assertTrue(after.startswith("# header comment\n"))
        suffix = "\n# between comment\n" + _ENGRAM_TABLE + "# tail comment\n"
        self.assertTrue(after.endswith(suffix))

    def test_crlf_config_stays_crlf(self):
        original = (
            "[mcp_servers.engram]\r\n"
            'command = "engram"\r\n'
            'args = ["mcp"]\r\n'
        )
        path = self.codex_config(original)
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_OK, payload)
        after = path.read_bytes()
        self.assertTrue(after.startswith(original.encode("utf-8")))
        # No lone LF anywhere: every newline is CRLF, including the
        # appended managed table.
        self.assertNotIn(b"\n", after.replace(b"\r\n", b""))
        self.assertIn(b"[mcp_servers.relinkra]\r\n", after)

    def test_lf_config_stays_lf(self):
        path = self.codex_config(_ENGRAM_TABLE)
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_OK, payload)
        after = path.read_bytes()
        self.assertNotIn(b"\r", after)
        self.assertTrue(after.startswith(_ENGRAM_TABLE.encode("utf-8")))

    def test_a_utf8_bom_is_preserved(self):
        original = "\ufeff" + _ENGRAM_TABLE
        path = self.codex_config(original)
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_OK, payload)
        after = path.read_bytes()
        self.assertTrue(after.startswith(b"\xef\xbb\xbf"))
        self.assertTrue(after.startswith(original.encode("utf-8")))


class CodexIdempotenceTests(ConnectApplyCodexCase):
    def test_an_equivalent_registration_is_a_semantic_no_op(self):
        path = self.codex_config(_ENGRAM_TABLE + self.registered_toml())
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertFalse(payload["change_required"])
        self.assertFalse(payload["backup_created"])
        self.assertFalse(payload["write_attempted"])
        self.assertTrue(payload["registration_matches_expected"])
        self.assertTrue(payload["validation_succeeded"])
        self.assertEqual(path.read_bytes(), before)
        # A second apply is also a byte-identical no-op.
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertFalse(payload["change_required"])
        self.assertEqual(path.read_bytes(), before)

    def test_a_second_apply_after_a_write_keeps_the_receipt_and_digest_stable(self):
        path = self.codex_config(_ENGRAM_TABLE)
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["write_succeeded"])
        receipt_before = self.receipt_path().read_bytes()
        digest_after = payload["digest_after"]
        written = path.read_bytes()
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertFalse(payload["change_required"])
        self.assertEqual(payload["digest_after"], digest_after)
        self.assertEqual(self.receipt_path().read_bytes(), receipt_before)
        self.assertEqual(path.read_bytes(), written)
        backups = sorted(
            self.codex_path().parent.glob("config.toml.relinkra-backup*")
        )
        self.assertEqual([p.name for p in backups], ["config.toml.relinkra-backup"])


class CodexRefusalTests(ConnectApplyCodexCase):
    def test_a_conflicting_unmanaged_entry_is_refused(self):
        original = (
            "[mcp_servers.relinkra]\n"
            'command = "node"\n'
            'args = ["server.js"]\n'
        )
        path = self.codex_config(original)
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertTrue(payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assert_untouched(path, before)
        # The foreign entry is never overwritten or removed.
        document = self.parsed(path)
        self.assertEqual(
            document["mcp_servers"][MANAGED_SERVER_NAME],
            {"command": "node", "args": ["server.js"]},
        )

    def test_dotted_key_member_form_is_refused(self):
        # A Relinkra-launching entry in dotted-key form parses as managed,
        # so the merge decision is UPDATE — but the scoped editor never
        # rewrites a representation that is not an explicit table.
        original = (
            'mcp_servers.relinkra = { command = "python", '
            f'args = ["-m", "{SERVER_MODULE}"] }}\n'
        )
        path = self.codex_config(original)
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("dotted keys or an inline table", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assert_untouched(path, before)

    def test_inline_table_member_form_is_refused(self):
        original = (
            '[mcp_servers]\n'
            'relinkra = { command = "python", '
            f'args = ["-m", "{SERVER_MODULE}"] }}\n'
        )
        path = self.codex_config(original)
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("dotted keys or an inline table", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assert_untouched(path, before)

    def test_malformed_toml_is_refused_without_a_backup(self):
        path = self.codex_config("[mcp_servers.relinkra\ncommand = ")
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("config_malformed", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertFalse(payload["backup_created"])
        self.assert_untouched(path, before)

    def test_duplicate_tables_are_refused(self):
        original = (
            "[mcp_servers.relinkra]\n"
            'command = "a"\n'
            "\n"
            "[mcp_servers.relinkra]\n"
            'command = "b"\n'
        )
        path = self.codex_config(original)
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("config_malformed", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assert_untouched(path, before)

    def test_duplicate_keys_are_refused(self):
        original = (
            "[mcp_servers.engram]\n"
            'command = "a"\n'
            'command = "b"\n'
        )
        path = self.codex_config(original)
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("config_malformed", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assert_untouched(path, before)

    def test_an_unreadable_target_is_refused_without_crashing(self):
        path = self.codex_config(_ENGRAM_TABLE)
        before = path.read_bytes()
        with mock.patch(
            "relinkra.connectors.read_bounded_text",
            side_effect=PermissionError("denied"),
        ):
            code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertTrue(payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertFalse(payload["real_host_verified"])
        self.assert_untouched(path, before)
        with mock.patch(
            "relinkra.connectors.read_bounded_text",
            side_effect=PermissionError("denied"),
        ):
            code, payload, _ = self.run_json("check", "codex")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertFalse(payload["valid"])

    def test_a_symlink_target_is_refused(self):
        path = self.codex_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        real_file = self.home / "real-config.toml"
        real_file.write_text(_ENGRAM_TABLE, encoding="utf-8")
        try:
            os.symlink(str(real_file), str(path))
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable on this platform: {exc}")
        before = real_file.read_bytes()
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("symlink", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertEqual(real_file.read_bytes(), before)
        self.assertTrue(path.is_symlink())

    def test_an_unknown_state_on_old_interpreters_refuses_apply(self):
        # Simulates an interpreter without tomllib: the config exists and
        # was not parsed, so nothing is known — and nothing is written.
        path = self.codex_config(_ENGRAM_TABLE)
        before = path.read_bytes()
        original = relinkra_connectors._load_toml
        relinkra_connectors._load_toml = lambda text: None
        try:
            code, payload, _ = self.run_json("apply", "codex")
        finally:
            relinkra_connectors._load_toml = original
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("3.11", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assert_untouched(path, before)


class CodexDirectCbmGateTests(ConnectApplyCodexCase):
    def test_direct_cbm_under_a_friendly_name_blocks_the_apply(self):
        original = (
            "[mcp_servers.memory-helper]\n"
            'command = "python"\n'
            'args = ["-m", "codebase_memory_mcp"]\n'
        )
        path = self.codex_config(original)
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("CBM", payload["refusal_reason"])
        self.assertIn("codebase-memory", payload["refusal_reason"])
        self.assertIn(
            "Remove the direct codebase-memory registration", " ".join(payload["actions"])
        )
        self.assertFalse(payload["write_attempted"])
        self.assertTrue(
            any("direct_cbm_exposure" in warning for warning in payload["warnings"])
        )
        self.assert_untouched(path, before)
        # The CBM entry is never removed automatically.
        document = self.parsed(path)
        self.assertEqual(
            document["mcp_servers"]["memory-helper"],
            {"command": "python", "args": ["-m", "codebase_memory_mcp"]},
        )

    def test_a_mixed_relinkra_and_cbm_launch_is_refused_before_write(self):
        original = (
            "[mcp_servers.hybrid]\n"
            'command = "python"\n'
            f'args = ["-m", "{SERVER_MODULE}", "codebase-memory-mcp"]\n'
        )
        path = self.codex_config(original)
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("direct codebase-memory", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertEqual(path.read_bytes(), before)


class CodexBackupConfinementTests(ConnectApplyCodexCase):
    def test_the_backup_holds_the_exact_original_bytes_as_a_managed_sibling(self):
        original = "# hand-maintained\n" + _ENGRAM_TABLE
        path = self.codex_config(original)
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_OK, payload)
        backup = self.backup_path()
        self.assertTrue(backup.is_file())
        self.assertEqual(backup.parent, path.parent)
        self.assertEqual(backup.read_bytes(), before)
        self.assertEqual(
            payload["backup_digest"],
            digest_text(before.decode("utf-8")),
        )
        self.assertEqual(payload["backup_ref"], backup.name)

    def test_a_semantic_post_write_failure_rolls_back_the_exact_bytes(self):
        original = "# hand-maintained\n" + _ENGRAM_TABLE
        path = self.codex_config(original)
        before = path.read_bytes()
        real_decide = connector_apply.decide_member
        calls = {"count": 0}

        def fail_after_write(*args, **kwargs):
            calls["count"] += 1
            if calls["count"] >= 3:
                raise connector_apply.MergeError("synthetic semantic failure")
            return real_decide(*args, **kwargs)

        with mock.patch.object(
            connector_apply, "decide_member", side_effect=fail_after_write
        ):
            result = apply_connector(CODEX, self.launch(), self.env())
        self.assertTrue(result.rollback_attempted)
        self.assertTrue(result.rollback_succeeded)
        self.assertFalse(result.ok)
        self.assertEqual(path.read_bytes(), before)
        self.assertFalse(self.receipt_path().exists())

    def test_a_post_write_validation_failure_restores_the_original(self):
        original = _ENGRAM_TABLE
        path = self.codex_config(original)
        before = path.read_bytes()
        real_adapter = connector_apply.adapter_for(CODEX.config_format)
        real_validate = real_adapter.validate
        calls = []

        def flaky_validator(text):
            calls.append(1)
            if len(calls) > 1:
                raise ValueError("simulated post-write validation failure")
            return real_validate(text)

        flaky_adapter = replace(real_adapter, validate=flaky_validator)
        with mock.patch.object(
            connector_apply, "adapter_for", return_value=flaky_adapter
        ):
            code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_ERROR)
        self.assertTrue(payload["write_attempted"])
        self.assertFalse(payload["write_succeeded"])
        self.assertTrue(payload["rollback_attempted"])
        self.assertTrue(payload["rollback_succeeded"])
        self.assertEqual(path.read_bytes(), before)


class CodexRollbackGateTests(ConnectApplyCodexCase):
    def test_rollback_restores_the_exact_pre_apply_bytes(self):
        original = "# hand-maintained\n" + _ENGRAM_TABLE
        path = self.codex_config(original)
        before = path.read_bytes()
        code, _, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_OK)
        code, payload, _ = self.run_json("rollback", "codex")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["rollback_succeeded"])
        self.assertTrue(payload["validation_succeeded"])
        self.assertFalse(payload["registration_present"])
        self.assertEqual(path.read_bytes(), before)

    def test_rollback_refuses_external_edits_made_after_the_apply(self):
        path = self.codex_config(_ENGRAM_TABLE)
        self.assertEqual(self.run_json("apply", "codex")[0], EXIT_OK)
        with open(path, "a", encoding="utf-8", newline="") as handle:
            handle.write('external_edit = true\n')
        kept = path.read_bytes()
        code, payload, _ = self.run_json("rollback", "codex")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("external edits", payload["refusal_reason"])
        self.assertFalse(payload["rollback_succeeded"])
        self.assertEqual(path.read_bytes(), kept)

    def test_backup_tampering_is_refused_at_rollback(self):
        path = self.codex_config(_ENGRAM_TABLE)
        self.assertEqual(self.run_json("apply", "codex")[0], EXIT_OK)
        self.backup_path().write_bytes(b"[mcp_servers.tampered]\ncommand = \"x\"\n")
        kept = path.read_bytes()
        code, payload, _ = self.run_json("rollback", "codex")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("backup digest", payload["refusal_reason"])
        self.assertEqual(path.read_bytes(), kept)

    def test_rollback_without_any_prior_apply_is_refused(self):
        self.codex_config(_ENGRAM_TABLE)
        result = rollback_connector(CODEX, self.env(), workspace_root=self.repo)
        self.assertTrue(result.refused)
        self.assertIn("no machine receipt", result.refusal_reason)

    def test_crlf_rollback_restores_the_exact_crlf_bytes(self):
        # The receipt's backup digest must hash the same byte
        # representation the rollback gates hash; a mismatch reads every
        # CRLF backup as "tampered" and bricks rollback.
        original = (
            "# hand-maintained\r\n"
            "[mcp_servers.engram]\r\n"
            'command = "engram"\r\n'
            'args = ["mcp"]\r\n'
        )
        path = self.codex_config(original)
        before = path.read_bytes()
        code, _, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_OK)
        code, payload, _ = self.run_json("rollback", "codex")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["rollback_succeeded"])
        self.assertEqual(path.read_bytes(), before)
        self.assertNotIn(b"\n", path.read_bytes().replace(b"\r\n", b""))

    def test_rollback_refuses_line_ending_only_external_edits(self):
        original = (
            "# hand-maintained\r\n"
            "[mcp_servers.engram]\r\n"
            'command = "engram"\r\n'
            'args = ["mcp"]\r\n'
        )
        path = self.codex_config(original)
        self.assertEqual(self.run_json("apply", "codex")[0], EXIT_OK)
        path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n"))
        kept = path.read_bytes()
        code, payload, _ = self.run_json("rollback", "codex")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("external edits", payload["refusal_reason"])
        self.assertFalse(payload["rollback_succeeded"])
        self.assertEqual(path.read_bytes(), kept)

    def test_crlf_backup_tampering_still_refuses(self):
        original = "[mcp_servers.engram]\r\n" 'command = "engram"\r\n'
        path = self.codex_config(original)
        self.assertEqual(self.run_json("apply", "codex")[0], EXIT_OK)
        self.backup_path().write_bytes(b"[mcp_servers.tampered]\r\ncommand = \"x\"\r\n")
        kept = path.read_bytes()
        code, payload, _ = self.run_json("rollback", "codex")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("backup digest", payload["refusal_reason"])
        self.assertEqual(path.read_bytes(), kept)

    def test_rollback_without_a_toml_parser_refuses_before_touching(self):
        # A tomllib-less interpreter (3.9/3.10) cannot re-validate the
        # restored bytes, so rollback must refuse cleanly BEFORE any
        # restore is attempted.
        path = self.codex_config(_ENGRAM_TABLE)
        self.assertEqual(self.run_json("apply", "codex")[0], EXIT_OK)
        kept = path.read_bytes()
        real_adapter = connector_apply.adapter_for(CODEX.config_format)
        unavailable = replace(real_adapter, parser_available=lambda: False)
        with mock.patch.object(
            connector_apply, "adapter_for", return_value=unavailable
        ):
            code, payload, _ = self.run_json("rollback", "codex")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("3.11", payload["refusal_reason"])
        self.assertFalse(payload["rollback_succeeded"])
        self.assertFalse(payload["error"])
        self.assertEqual(path.read_bytes(), kept)

    def test_no_receipt_rollback_with_malformed_config_is_a_designed_refusal(self):
        # No receipt, a backup sibling present, and a current config that
        # does not parse: provenance cannot be established, and the
        # answer must be the designed refusal — not a bare error.
        path = self.codex_config("[mcp_servers.relinkra\ncommand = ")
        before = path.read_bytes()
        self.backup_path().write_bytes(_ENGRAM_TABLE.encode("utf-8"))
        result = rollback_connector(CODEX, self.env(), workspace_root=self.repo)
        self.assertTrue(result.refused)
        self.assertIn("no machine receipt", result.refusal_reason)
        self.assertFalse(result.error)
        self.assertEqual(path.read_bytes(), before)


class CodexScopedEditorRobustnessTests(ConnectApplyCodexCase):
    """The textual scanner and the tomllib parse must never disagree.

    The equality check in ``toml_edit.serialize_member_toml`` (candidate
    re-parse compared against the structured merge) is the safety net:
    any scanning mistake must surface as a refusal, never as a write.
    """

    def parity_fixture(self):
        # A managed table holding a multiline basic string whose closing
        # delimiter is preceded by an EVEN number of backslashes: per
        # TOML escaping the pairs collapse and the string really closes.
        # TOML text: note = """first line\nsecond \\"""
        return (
            "[mcp_servers.relinkra]\n"
            'command = "python"\n'
            f'args = ["-m", "{SERVER_MODULE}", "--workspace-root", "/old"]\n'
            'note = """first line\n'
            'second \\\\"""\n'
            "[mcp_servers.engram]\n"
            'command = "engram"\n'
            'args = ["mcp"]\n'
        )

    def test_even_backslash_parity_before_a_closing_triple_quote_is_handled(self):
        # Regression for the parity fix: the old heuristic treated ANY
        # backslash before a closing triple-quote as escaping it, which
        # swallowed the following table header into the string.
        path = self.codex_config(self.parity_fixture())
        code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["write_succeeded"])
        after = path.read_bytes()
        suffix = (
            "[mcp_servers.engram]\n"
            'command = "engram"\n'
            'args = ["mcp"]\n'
        ).encode("utf-8")
        self.assertTrue(after.endswith(suffix))
        document = self.parsed(path)
        entry = document["mcp_servers"][MANAGED_SERVER_NAME]
        self.assertEqual(entry["note"], "first line\nsecond " + chr(92))
        desired = self.registered_codex_entry()
        self.assertEqual(entry["command"], desired["command"])
        self.assertEqual(entry["args"], desired["args"])
        tokens = entry_tokens(entry)
        self.assertNotIn("--workspace-root", tokens)
        self.assertNotIn("--registry", tokens)

    def test_a_scanner_parse_disagreement_refuses_the_write(self):
        # Discriminating for the candidate-reparse equality check: force
        # a scanner fault (the pre-fix parity heuristic) and the same
        # fixture must be REFUSED byte-untouched. Neutralizing the
        # equality check lets the corrupted write through and fails here.
        path = self.codex_config(self.parity_fixture())
        before = path.read_bytes()
        real_string_state = toml_edit._update_string_state

        def faulty_string_state(line, delimiter):
            # Pre-fix fault: ANY backslash before a closing triple-quote
            # counts as an escape, ignoring parity.
            if delimiter == '"""':
                end = line.find('"""')
                if end != -1 and line[end - 1:end] == chr(92):
                    return '"""'
            return real_string_state(line, delimiter)

        with mock.patch.object(
            toml_edit, "_update_string_state", faulty_string_state
        ):
            code, payload, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("tomllib parse", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assert_untouched(path, before)


class CodexVerifyTests(ConnectApplyCodexCase):
    def registered_config(self):
        return self.codex_config(_ENGRAM_TABLE + self.registered_toml())

    def test_a_valid_proof_is_recorded_and_assessed_valid(self):
        self.registered_config()
        self.record_codex_proof()
        stored = json.loads(self.verification_store().read_text(encoding="utf-8"))
        self.assertIn("workspace_id", stored)
        self.assertIsNone(stored["workspace_id"])
        status, record, _ = assess_verification(
            self.repo, "codex", launch_fingerprint(self.launch())
        )
        self.assertEqual(status, STATUS_VALID)
        self.assertIsNotNone(record)
        code, payload, _ = self.run_json("check", "codex")
        self.assertEqual(code, EXIT_OK)
        verification = payload["verification"]
        self.assertEqual(verification["status"], STATUS_VALID)
        self.assertTrue(verification["locally_verified"])
        self.assertFalse(verification["independently_attested"])

    def test_r4d_adapts_native_verification_assessments_without_a_second_ttl(self):
        self.registered_config()
        self.record_codex_proof()
        store = self.verification_store()
        baseline = json.loads(store.read_text(encoding="utf-8"))
        observed = datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc)
        revision = "a" * 40
        current = "b" * 40
        baseline.update(
            {
                "timestamp": observed.isoformat(),
                "ttl_seconds": 60,
                "revision": revision,
            }
        )
        fingerprint = baseline["registration_fingerprint"]

        def assessment(data, *, now, current_revision, current_fingerprint=None):
            store.write_text(json.dumps(data, indent=2), encoding="utf-8")
            with mock.patch(
                "relinkra.connect_verification._utc_now", return_value=now
            ), mock.patch(
                "relinkra.connect_verification._revision_for",
                return_value=current_revision,
            ):
                return connect_cli._verification_section(
                    self.repo,
                    "codex",
                    current_fingerprint or fingerprint,
                )

        def adapt(native, *, as_of=observed, current_revision=revision):
            return evaluate_freshness(
                "connector",
                native,
                FreshnessContext(
                    as_of=as_of.isoformat(),
                    project_id=baseline["project_id"],
                    current_revision=current_revision,
                ),
            )

        def assert_result(native, status, state, reason, **context):
            self.assertEqual(native["status"], status)
            result = adapt(native, **context)
            self.assertIs(result.state, state)
            self.assertEqual(result.reason_code, reason)
            return result

        native_valid = assessment(
            baseline,
            now=observed + timedelta(seconds=30),
            current_revision=revision,
        )
        # R4D does not create a second TTL authority: even an as_of clock
        # beyond the record lifetime cannot contradict a native VALID result.
        valid = assert_result(
            native_valid,
            STATUS_VALID,
            FreshnessState.FRESH,
            "verification_authority_valid",
            as_of=observed + timedelta(seconds=120),
        )
        self.assertEqual(valid.ttl_seconds, 60)
        self.assertEqual(valid.age_seconds, 120)

        native_expired = assessment(
            baseline,
            now=observed + timedelta(seconds=61),
            current_revision=revision,
        )
        native_fingerprint_mismatch = assessment(
            baseline,
            now=observed + timedelta(seconds=30),
            current_revision=revision,
            current_fingerprint="0" * 64,
        )
        native_revision_mismatch = assessment(
            baseline,
            now=observed + timedelta(seconds=30),
            current_revision=current,
        )
        native_cases = (
            (
                "expired",
                native_expired,
                STATUS_EXPIRED,
                "verification_expired",
                {},
            ),
            (
                "fingerprint mismatch",
                native_fingerprint_mismatch,
                STATUS_STALE_FINGERPRINT,
                "verification_stale_fingerprint",
                {},
            ),
            (
                "revision mismatch",
                native_revision_mismatch,
                STATUS_INVALID,
                "verification_revision_mismatch",
                {"current_revision": current},
            ),
        )
        for label, native, status, reason, context_override in native_cases:
            with self.subTest(label=label):
                assert_result(
                    native,
                    status,
                    FreshnessState.STALE,
                    reason,
                    **context_override,
                )
        self.assertTrue(
            any(
                "different Git revision" in reason
                for reason in native_revision_mismatch["reasons"]
            )
        )

        failed_record = dict(baseline)
        failed_record.update(
            {
                "stages": {
                    stage: False for stage in baseline["stages"]
                },
                "tools_visible": [],
                "tools_invoked": [],
                "handoff_ok": False,
            }
        )
        native_failed_stage = assessment(
            failed_record,
            now=observed + timedelta(seconds=30),
            current_revision=revision,
        )
        assert_result(
            native_failed_stage,
            STATUS_VALID,
            FreshnessState.UNKNOWN,
            "verification_stage_unproven",
        )
        self.assertFalse(native_failed_stage["locally_verified"])

        store.unlink()
        with mock.patch(
            "relinkra.connect_verification._utc_now",
            return_value=observed + timedelta(seconds=30),
        ):
            native_unavailable = connect_cli._verification_section(
                self.repo, "codex", fingerprint
            )
        assert_result(
            native_unavailable,
            STATUS_ABSENT,
            FreshnessState.UNKNOWN,
            "verification_unavailable",
        )

    def test_a_forged_record_naming_another_host_is_rejected(self):
        self.registered_config()
        self.record_codex_proof()
        store = self.verification_store()
        data = json.loads(store.read_text(encoding="utf-8"))
        data["host"] = "claude"
        store.write_text(json.dumps(data, indent=2), encoding="utf-8")
        status, _, reasons = assess_verification(
            self.repo, "codex", launch_fingerprint(self.launch())
        )
        self.assertEqual(status, STATUS_INVALID)
        self.assertTrue(any("different host" in reason for reason in reasons))

    def test_a_fingerprint_mismatch_is_stale_not_valid(self):
        self.registered_config()
        self.record_codex_proof()
        status, _, reasons = assess_verification(self.repo, "codex", "0" * 64)
        self.assertEqual(status, STATUS_STALE_FINGERPRINT)
        self.assertTrue(any("launch contract" in reason for reason in reasons))

    def test_a_future_timestamp_is_rejected(self):
        self.registered_config()
        self.record_codex_proof()
        store = self.verification_store()
        data = json.loads(store.read_text(encoding="utf-8"))
        data["timestamp"] = "2999-01-01T00:00:00+00:00"
        store.write_text(json.dumps(data, indent=2), encoding="utf-8")
        status, _, reasons = assess_verification(
            self.repo, "codex", data["registration_fingerprint"]
        )
        self.assertEqual(status, STATUS_INVALID)
        self.assertTrue(any("future" in reason for reason in reasons))

    def test_an_expired_proof_is_reported_honestly(self):
        self.registered_config()
        self.record_codex_proof()
        store = self.verification_store()
        data = json.loads(store.read_text(encoding="utf-8"))
        data["timestamp"] = "2001-01-01T00:00:00+00:00"
        store.write_text(json.dumps(data, indent=2), encoding="utf-8")
        status, _, _ = assess_verification(
            self.repo, "codex", launch_fingerprint(self.launch())
        )
        self.assertEqual(status, STATUS_EXPIRED)
        code, payload, _ = self.run_json("check", "codex")
        verification = payload["verification"]
        self.assertEqual(verification["status"], STATUS_EXPIRED)
        self.assertFalse(verification["locally_verified"])

    def test_a_legacy_v1_record_is_rejected_without_migration(self):
        self.registered_config()
        self.record_codex_proof()
        store = self.verification_store()
        data = json.loads(store.read_text(encoding="utf-8"))
        data["schema_version"] = "relinkra.connect-verification/v1"
        data.pop("workspace_id")
        store.write_text(json.dumps(data, indent=2), encoding="utf-8")
        status, record, reasons = assess_verification(
            self.repo, "codex", launch_fingerprint(self.launch())
        )
        self.assertEqual(status, STATUS_ABSENT)
        self.assertIsNone(record)
        self.assertTrue(reasons)


class CodexPortabilityTests(ConnectApplyCodexCase):
    def populate_secret(self):
        return self.codex_config(
            "[mcp_servers.engram]\n"
            'command = "engram"\n'
            'args = ["mcp"]\n'
            f'env = {{ ENGRAM_TOKEN = "{_SECRET}" }}\n'
        )

    def test_no_apply_check_or_verify_output_carries_a_path(self):
        self.populate_secret()
        proof_path = self.write_proof(self.valid_proof())
        for argv in (
            ("apply", "codex"),
            ("check", "codex"),
            ("verify", "codex", "--proof", str(proof_path)),
            ("rollback", "codex"),
            ("plan", "codex"),
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

    def test_no_output_ever_carries_an_environment_value(self):
        path = self.populate_secret()
        proof_path = self.write_proof(self.valid_proof())
        for argv in (
            ("apply", "codex"),
            ("check", "codex"),
            ("verify", "codex", "--proof", str(proof_path)),
            ("rollback", "codex"),
            ("plan", "codex"),
        ):
            for extra in ((), ("--json",)):
                with self.subTest(argv=argv, extra=extra):
                    _, out, err = self.run_cli(*argv, *extra)
                    self.assertNotIn(_SECRET, out)
                    self.assertNotIn(_SECRET, err)
                    self.assertNotIn(_SECRET.split("-", 1)[-1], out)
        # The secret survived every mutation of the file, untouched.
        self.assertIn(_SECRET, path.read_text(encoding="utf-8"))

    def test_reveal_paths_opts_into_machine_local_output(self):
        self.codex_config(_ENGRAM_TABLE)
        code, payload, _ = self.run_json("apply", "codex", "--reveal-paths")
        self.assertEqual(code, EXIT_OK)
        self.assertIn(str(self.home), payload["real_config_path"])


class CodexNonInterferenceTests(ConnectApplyCodexCase):
    def populate_other_hosts(self):
        self.claude_config({"c7": {"command": "npx", "args": ["-y", "c7"]}})
        self.opencode_config(
            {"engram": {"type": "local", "command": ["engram", "mcp"]}}
        )
        self.write_config(
            ".codeium",
            "windsurf",
            "mcp_config.json",
            content={
                "mcpServers": {
                    "engram": {"command": "/home/dev/.gentleman/bin/engram", "args": ["mcp"]}
                }
            },
        )

    def test_codex_commands_never_touch_other_host_configs(self):
        self.populate_other_hosts()
        self.codex_config(_ENGRAM_TABLE)
        home_before = self.snapshot(self.home)
        repo_before = set(self.snapshot(self.repo))
        proof_path = self.write_proof(self.valid_proof())

        self.assertEqual(self.run_json("apply", "codex")[0], EXIT_OK)
        self.assertEqual(self.run_json("check", "codex")[0], EXIT_OK)
        self.assertEqual(
            self.run_cli("verify", "codex", "--proof", str(proof_path))[0],
            EXIT_OK,
        )

        home_after = self.snapshot(self.home)
        changed = {
            name
            for name in set(home_before) | set(home_after)
            if home_before.get(name) != home_after.get(name)
        }
        codex_prefix = str(Path(".codex") / "config.toml")
        for name in changed:
            self.assertTrue(
                name == codex_prefix or name.startswith(codex_prefix + "."),
                f"unexpected write outside the codex target: {name}",
            )
        for name in (
            ".claude.json",
            str(Path(".config") / "opencode" / "opencode.json"),
            str(Path(".codeium") / "windsurf" / "mcp_config.json"),
        ):
            self.assertEqual(home_before.get(name), home_after.get(name), name)

        new_in_repo = set(self.snapshot(self.repo)) - repo_before
        self.assertTrue(new_in_repo, "the machine receipt was not recorded")
        for name in new_in_repo:
            self.assertTrue(
                name.startswith(".relinkra" + os.sep) or name.startswith(".relinkra/"),
                f"unexpected write inside the repository: {name}",
            )

    def test_other_host_applies_do_not_touch_the_codex_config(self):
        self.populate_other_hosts()
        codex = self.codex_config(_ENGRAM_TABLE)
        before = codex.read_bytes()
        code, _, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK)
        code, _, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(codex.read_bytes(), before)


class CodexDoctorPerHostTests(ConnectApplyCodexCase):
    def test_doctor_preserves_null_workspace_identity_as_local_operational(self):
        self.codex_config(_ENGRAM_TABLE)
        self.record_codex_proof()
        # The doctor route currently reaches its launch seam through the
        # generic resolver; bind that seam to the approved Codex contract so
        # this fixture exercises host-neutral verification rather than a
        # pinned compatibility fingerprint.
        with mock.patch.object(product_cli, "resolve_launch", return_value=self.launch()):
            payload = self.run_doctor()
        rows = {
            row["connector_id"]: row
            for row in payload["routing"]["host_verification"]
        }
        codex = rows["codex"]
        self.assertEqual(codex["verification_status"], STATUS_VALID)
        self.assertTrue(codex["locally_verified"])
        self.assertFalse(codex["independently_attested"])

    def test_doctor_shows_codex_verification_independently(self):
        self.claude_config({MANAGED_SERVER_NAME: CLAUDE.entry_builder(self.pinned_launch())})
        self.opencode_config({})
        self.codex_config(_ENGRAM_TABLE)
        code, _, _ = self.run_json("apply", "codex")
        self.assertEqual(code, EXIT_OK)
        # Claude holds valid local evidence; Codex holds none.
        proof_path = self.write_proof(self.valid_proof())
        code, _, _ = self.run_cli("verify", "claude", "--proof", str(proof_path))
        self.assertEqual(code, EXIT_OK)

        payload = self.run_doctor()
        rows = {
            row["connector_id"]: row
            for row in payload["routing"]["host_verification"]
        }
        self.assertIn("codex", rows)
        self.assertIn("claude", rows)
        self.assertIn("opencode", rows)
        # Codex: applied and managed, but host stages unverified.
        codex = rows["codex"]
        self.assertTrue(codex["config_present"])
        self.assertTrue(codex["managed_registration"])
        self.assertEqual(codex["verification_status"], STATUS_ABSENT)
        self.assertFalse(codex["locally_verified"])
        self.assertFalse(codex["independently_attested"])
        for value in codex["stages"].values():
            self.assertIsNone(value)
        # Claude: proven by its own evidence, never degraded by Codex.
        claude = rows["claude"]
        self.assertEqual(claude["verification_status"], STATUS_VALID)
        self.assertTrue(claude["locally_verified"])

        checks = {check["name"]: check for check in payload["checks"]}
        self.assertEqual(checks["Host verification"]["status"], WARN)


if __name__ == "__main__":
    unittest.main()
