"""Tests for the OpenCode connector write path (R4C.1C).

Mirrors ``tests.test_connect_apply``: every test drives either the real
CLI through ``main(argv)`` or the real engine against a fixture home
plus a fake repository, with host discovery monkeypatched the same way.
The OpenCode fixture writes the REAL configuration shape observed on a
development machine — top-level ``$schema``/``agent``/``default_agent``/
``permission``/``share`` keys plus unknown members, and an ``mcp``
container mixing remote (URL) and local entries — so every mutation
assertion also proves those survive.

Each protection test is written to be discriminating: removing the
protection (the direct-CBM gate, backup confinement, semantic rollback,
the external-edit digest gate, idempotence, forged-proof rejection or
portable redaction) makes THAT test fail.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from relinkra import connect_cli, connector_apply, product_cli
from relinkra import connectors as relinkra_connectors
from relinkra.backend_policy import (
    STAGE_HANDSHAKE_VERIFIED,
    STAGE_REAL_HOST_LAUNCH,
)
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
    OPENCODE,
    SERVER_MODULE,
    claude_project_key,
    entry_tokens,
    launches_relinkra,
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
    WARN,
    main,
    registry_path,
)
from relinkra.safe_write import digest_text, read_bounded_text

_SECRET = "sk-live-OPENCODE-DO-NOT-LEAK-0123456789"

_REMOTE_ENTRY = {"type": "remote", "url": "https://example.invalid/mcp"}
_ENGRAM_ENTRY = {"type": "local", "command": ["engram", "mcp", "--tools=agent"]}


class ConnectApplyOpenCodeCase(unittest.TestCase):
    """A fake repository plus a fixture home, discovery monkeypatched."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="relinkra-connect-apply-oc-")
        self.addCleanup(self._temp.cleanup)
        base = Path(self._temp.name)
        self.home = base / "home"
        self.home.mkdir()
        self.repo = base / "repo"
        (self.repo / ".git").mkdir(parents=True)
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
        path.write_bytes(text.encode("utf-8"))
        return path

    def opencode_config(self, servers=None, **extra_top_level):
        """Write the user-scope OpenCode config in its real observed shape.

        ``servers`` becomes the ``mcp`` container, surrounded by the
        top-level keys the real file carries (``$schema``, ``agent``,
        ``default_agent``, ``permission``, ``share``) and dozens of
        unknown top-level members with nested subtrees, so every
        mutation assertion also proves those survive. A raw string is
        written verbatim (for malformed and formatting fixtures).
        """
        if isinstance(servers, str):
            return self.write_config(
                ".config", "opencode", "opencode.json", content=servers
            )
        # Tolerate the whole-document call shape: a bare {"mcp": X} dict
        # means X is the server map, not a nested member.
        if servers is not None and set(servers) == {"mcp"}:
            servers = servers["mcp"]
        document = {
            "$schema": "https://example.invalid/opencode-schema.json",
            "agent": {"default": {"model": "test-model", "tools": {"bash": True}}},
            "default_agent": "default",
            "permission": {"bash": {"*": "ask"}, "edit": "allow"},
            "share": "disabled",
        }
        for index in range(30):
            document[f"unknown_top_level_{index:02d}"] = {
                "n": index,
                "nested": {"flag": index % 2 == 0, "label": f"member-{index}"},
            }
        document["mcp"] = dict(servers or {})
        document.update(extra_top_level)
        return self.write_config(".config", "opencode", "opencode.json", content=document)

    def claude_config(self, servers):
        document = {
            "projects": {
                claude_project_key(self.root): {"mcpServers": servers}
            }
        }
        return self.write_config(".claude.json", content=document)

    def mcp_container(self, document):
        return document["mcp"]

    def opencode_path(self):
        return self.home / ".config" / "opencode" / "opencode.json"

    def backup_path(self):
        return self.opencode_path().with_name("opencode.json.relinkra-backup")

    def receipt_path(self):
        return self.repo / ".relinkra" / "connect-apply" / "opencode.json"

    def verification_store(self):
        return self.repo / ".relinkra" / "connect-verification" / "opencode.json"

    def registered_opencode_entry(self):
        return OPENCODE.entry_builder(self.launch())

    def registered_claude_entry(self):
        return CLAUDE.entry_builder(self.launch())

    def launch(self):
        return resolve_launch(self.repo, registry_path(self.repo))

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

    def record_opencode_proof(self):
        proof_path = self.write_proof(self.valid_proof())
        code, _, err = self.run_cli(
            "verify", "opencode", "--proof", str(proof_path), "--json"
        )
        self.assertEqual(code, EXIT_OK, err)


class OpenCodeApplyBasicsTests(ConnectApplyOpenCodeCase):
    def test_appdata_candidate_is_scanned_but_never_selected_for_apply(self):
        appdata = self.home / "AppData" / "Roaming" / "opencode" / "opencode.json"
        appdata.parent.mkdir(parents=True, exist_ok=True)
        appdata.write_text(
            json.dumps({"mcp": {"legacy": dict(_ENGRAM_ENTRY)}}),
            encoding="utf-8",
        )
        before = appdata.read_bytes()

        locations = []
        for location in OPENCODE.locations:
            if location.location_id == "opencode_user_appdata":
                location = replace(location, build=lambda env, path=appdata: path)
            locations.append(location)
        spec = replace(OPENCODE, locations=tuple(locations))
        env = self.env()
        inspection = relinkra_connectors.inspect_connector(spec, env)
        self.assertIsNone(inspection.location)

        result = apply_connector(spec, self.launch(), env)
        self.assertFalse(result.refused, result.refusal_reason)
        self.assertTrue(result.write_succeeded)
        self.assertTrue(self.opencode_path().is_file())
        self.assertEqual(appdata.read_bytes(), before)

    def test_empty_object_config_gains_the_entry_with_a_backup(self):
        path = self.opencode_config("{}")
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["change_required"])
        self.assertTrue(payload["backup_created"])
        self.assertTrue(payload["write_succeeded"])
        self.assertTrue(payload["validation_succeeded"])
        self.assertEqual(payload["verification_stage"], "config_applied_host_unverified")
        self.assertFalse(payload["real_host_verified"])
        document = json.loads(path.read_text(encoding="utf-8"))
        entry = self.mcp_container(document)[MANAGED_SERVER_NAME]
        self.assertEqual(entry["type"], "local")
        self.assertIsInstance(entry["command"], list)
        self.assertTrue(launches_relinkra(entry))
        self.assertTrue(self.backup_path().is_file())

    def test_empty_mcp_container_gains_the_entry(self):
        path = self.opencode_config({"mcp": {}})
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_OK, payload)
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn(MANAGED_SERVER_NAME, self.mcp_container(document))

    def test_a_mixed_relinkra_and_cbm_launch_is_refused_before_write(self):
        path = self.opencode_config(
            {
                "hybrid": {
                    "type": "local",
                    "command": [
                        "python",
                        "-m",
                        SERVER_MODULE,
                        "codebase-memory-mcp",
                    ],
                }
            }
        )
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("direct codebase-memory", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertEqual(path.read_bytes(), before)

    def test_unrelated_local_and_remote_servers_survive(self):
        path = self.opencode_config(
            {"context7": dict(_REMOTE_ENTRY), "engram": dict(_ENGRAM_ENTRY)}
        )
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_OK, payload)
        document = json.loads(path.read_text(encoding="utf-8"))
        container = self.mcp_container(document)
        self.assertEqual(container["context7"], _REMOTE_ENTRY)
        self.assertEqual(container["engram"], _ENGRAM_ENTRY)
        self.assertIn(MANAGED_SERVER_NAME, container)

    def test_unknown_top_level_and_nested_fields_survive(self):
        path = self.opencode_config({"mcp": {}}, custom_key={"deep": [1, 2, 3]})
        code, _, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_OK)
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(document["$schema"], "https://example.invalid/opencode-schema.json")
        self.assertEqual(document["agent"], {"default": {"model": "test-model", "tools": {"bash": True}}})
        self.assertEqual(document["default_agent"], "default")
        self.assertEqual(document["permission"], {"bash": {"*": "ask"}, "edit": "allow"})
        self.assertEqual(document["share"], "disabled")
        self.assertEqual(document["custom_key"], {"deep": [1, 2, 3]})
        for index in range(30):
            self.assertEqual(
                document[f"unknown_top_level_{index:02d}"],
                {"n": index, "nested": {"flag": index % 2 == 0, "label": f"member-{index}"}},
            )

    def test_a_registration_for_another_workspace_is_updated_not_corrupted(self):
        desired = self.registered_opencode_entry()
        stale = dict(desired)
        stale["command"] = [
            desired["command"][0],
            "-m",
            SERVER_MODULE,
            "--workspace-root",
            "/old/other-workspace",
        ]
        path = self.opencode_config({"mcp": {MANAGED_SERVER_NAME: stale}})
        code, payload, _ = self.run_json("apply", "opencode")
        # The engine must not silently accept a foreign-workspace entry
        # as equivalent (a no-op), nor refuse it as a conflict: it is a
        # managed entry pinned elsewhere, so it is UPDATED in place.
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["change_required"])
        self.assertTrue(payload["write_succeeded"])
        document = json.loads(path.read_text(encoding="utf-8"))
        entry = self.mcp_container(document)[MANAGED_SERVER_NAME]
        self.assertTrue(launches_relinkra(entry))
        tokens = entry_tokens(entry)
        index = tokens.index("--workspace-root")
        self.assertEqual(Path(tokens[index + 1]).resolve(), self.root)
        self.assertNotIn("/old/other-workspace", tokens)
        self.assertTrue(payload["registration_matches_expected"])


class OpenCodeIdempotenceTests(ConnectApplyOpenCodeCase):
    def test_an_equivalent_registration_is_a_semantic_no_op(self):
        path = self.opencode_config(
            {"mcp": {MANAGED_SERVER_NAME: self.registered_opencode_entry()}}
        )
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertFalse(payload["change_required"])
        self.assertFalse(payload["backup_created"])
        self.assertFalse(payload["write_attempted"])
        self.assertTrue(payload["registration_matches_expected"])
        self.assertTrue(payload["validation_succeeded"])
        self.assertEqual(path.read_bytes(), before)
        # A second apply is also a no-op.
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertFalse(payload["change_required"])
        self.assertEqual(path.read_bytes(), before)

    def test_a_second_apply_after_a_write_keeps_the_receipt_and_digest_stable(self):
        self.opencode_config({"mcp": {}})
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["write_succeeded"])
        receipt_before = self.receipt_path().read_bytes()
        digest_after = payload["digest_after"]
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertFalse(payload["change_required"])
        self.assertEqual(payload["digest_after"], digest_after)
        self.assertEqual(self.receipt_path().read_bytes(), receipt_before)
        # No second backup content was produced by the no-op.
        backups = sorted(
            self.opencode_path().parent.glob("opencode.json.relinkra-backup*")
        )
        self.assertEqual([path.name for path in backups], ["opencode.json.relinkra-backup"])

    def test_idempotent_second_apply_says_no_op_in_portable_output(self):
        self.opencode_config({"mcp": {}})
        self.assertEqual(self.run_json("apply", "opencode")[0], EXIT_OK)
        code, out, _ = self.run_cli("apply", "opencode")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("No change required", out)
        self.assertNotIn(str(self.home), out)
        self.assertNotIn(str(self.repo), out)


class OpenCodeRefusalTests(ConnectApplyOpenCodeCase):
    def test_a_conflicting_unmanaged_entry_is_refused(self):
        path = self.opencode_config(
            {
                "mcp": {
                    MANAGED_SERVER_NAME: {
                        "type": "local",
                        "command": ["node", "server.js"],
                    }
                }
            }
        )
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertTrue(payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assert_untouched(path, before)
        # The foreign entry is never overwritten or removed.
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(
            self.mcp_container(document)[MANAGED_SERVER_NAME],
            {"type": "local", "command": ["node", "server.js"]},
        )

    def test_malformed_json_is_refused_without_a_backup(self):
        path = self.opencode_config("{ broken")
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("config_malformed", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertFalse(payload["backup_created"])
        self.assert_untouched(path, before)

    def test_an_unreadable_target_is_refused_without_crashing(self):
        path = self.opencode_config({"mcp": {}})
        before = path.read_bytes()
        with mock.patch(
            "relinkra.connectors.read_bounded_text",
            side_effect=PermissionError("denied"),
        ):
            code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertTrue(payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertFalse(payload["real_host_verified"])
        self.assert_untouched(path, before)
        # Check reports the same unreadable state honestly, no traceback.
        with mock.patch(
            "relinkra.connectors.read_bounded_text",
            side_effect=PermissionError("denied"),
        ):
            code, payload, _ = self.run_json("check", "opencode")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertFalse(payload["valid"])

    def test_a_symlink_target_is_refused(self):
        path = self.opencode_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        real_file = self.home / "real-opencode.json"
        real_file.write_text('{"mcp": {}}', encoding="utf-8")
        try:
            os.symlink(str(real_file), str(path))
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable on this platform: {exc}")
        before = real_file.read_bytes()
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("symlink", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertEqual(real_file.read_bytes(), before)
        self.assertTrue(path.is_symlink())


class OpenCodeDirectCbmGateTests(ConnectApplyOpenCodeCase):
    CBM_LIST_ENTRY = {"type": "local", "command": ["python", "-m", "codebase_memory_mcp"]}

    def test_direct_cbm_under_a_friendly_name_blocks_the_apply(self):
        path = self.opencode_config(
            {"mcp": {"memory-helper": dict(self.CBM_LIST_ENTRY)}}
        )
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("CBM", payload["refusal_reason"])
        self.assertIn("codebase-memory", payload["refusal_reason"])
        self.assertIn("Remove the direct codebase-memory registration", " ".join(payload["actions"]))
        self.assertFalse(payload["write_attempted"])
        self.assertTrue(
            any("direct_cbm_exposure" in warning for warning in payload["warnings"])
        )
        self.assert_untouched(path, before)
        # The CBM entry is never removed automatically.
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(
            self.mcp_container(document)["memory-helper"], self.CBM_LIST_ENTRY
        )

    def test_direct_cbm_in_the_workspace_scope_fails_closed(self):
        path = self.opencode_config({"mcp": {}})
        before = path.read_bytes()
        (self.repo / "opencode.json").write_text(
            json.dumps({"mcp": {"friendly-name": dict(self.CBM_LIST_ENTRY)}}),
            encoding="utf-8",
        )
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("direct codebase-memory", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertEqual(path.read_bytes(), before)
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertNotIn(MANAGED_SERVER_NAME, self.mcp_container(document))

    def test_an_unreadable_workspace_scope_fails_closed(self):
        path = self.opencode_config({"mcp": {}})
        before = path.read_bytes()
        (self.repo / "opencode.json").mkdir()
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("authoritative project MCP scope", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertEqual(path.read_bytes(), before)


class OpenCodeScopePrecedenceTests(ConnectApplyOpenCodeCase):
    def test_the_user_config_wins_over_the_workspace_config(self):
        path = self.opencode_config({"mcp": {}})
        workspace_file = self.repo / "opencode.json"
        workspace_file.write_text(
            json.dumps({"mcp": {"ws-local": {"type": "local", "command": ["ws"]}}}),
            encoding="utf-8",
        )
        workspace_before = workspace_file.read_bytes()
        code, payload, _ = self.run_json("plan", "opencode")
        self.assertEqual(payload["target_ref"], "opencode:opencode_user_config")
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertEqual(payload["config_path"], "~/.config/opencode/opencode.json")
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn(MANAGED_SERVER_NAME, self.mcp_container(document))
        # The workspace-scope file is scanned but never the apply target.
        self.assertEqual(workspace_file.read_bytes(), workspace_before)
        workspace_document = json.loads(workspace_file.read_text(encoding="utf-8"))
        self.assertNotIn(MANAGED_SERVER_NAME, workspace_document["mcp"])
        # Inspect reports both scopes, with the user scope active.
        code, payload, _ = self.run_json("inspect", "opencode")
        self.assertEqual(code, EXIT_OK)
        location_ids = [loc["location_id"] for loc in payload["locations"]]
        self.assertIn("opencode_user_config", location_ids)
        self.assertIn("opencode_workspace", location_ids)
        self.assertEqual(payload["active_location_id"], "opencode_user_config")


class OpenCodeBackupConfinementTests(ConnectApplyOpenCodeCase):
    def test_the_backup_holds_the_exact_original_bytes_as_a_managed_sibling(self):
        path = self.opencode_config({"context7": dict(_REMOTE_ENTRY)})
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "opencode")
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
        path = self.opencode_config({"mcp": {}})
        original = path.read_bytes()
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
            result = apply_connector(OPENCODE, self.launch(), self.env())
        self.assertTrue(result.rollback_attempted)
        self.assertTrue(result.rollback_succeeded)
        self.assertFalse(result.ok)
        self.assertEqual(path.read_bytes(), original)
        self.assertFalse(self.receipt_path().exists())

    def test_a_post_write_validation_failure_restores_the_original(self):
        path = self.opencode_config({"mcp": {"c7": dict(_REMOTE_ENTRY)}})
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
            code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_ERROR)
        self.assertTrue(payload["write_attempted"])
        self.assertFalse(payload["write_succeeded"])
        self.assertTrue(payload["rollback_attempted"])
        self.assertTrue(payload["rollback_succeeded"])
        self.assertEqual(path.read_bytes(), before)

    def test_a_forged_receipt_backup_path_is_rejected_at_rollback(self):
        path = self.opencode_config({"mcp": {}})
        self.assertEqual(self.run_json("apply", "opencode")[0], EXIT_OK)
        receipt = self.receipt_path()
        for forged in (
            str(self.home / "foreign-backup.json"),
            "..\\opencode.json.relinkra-backup",
        ):
            with self.subTest(forged=forged):
                data = json.loads(receipt.read_text(encoding="utf-8"))
                original_backup = data["backup_path"]
                data["backup_path"] = forged
                receipt.write_text(json.dumps(data, indent=2), encoding="utf-8")
                kept = path.read_bytes()
                code, payload, _ = self.run_json("rollback", "opencode")
                self.assertEqual(code, EXIT_ACTION_REQUIRED)
                self.assertIn("backup", payload["refusal_reason"])
                self.assertFalse(payload["rollback_succeeded"])
                self.assertEqual(path.read_bytes(), kept)
                data["backup_path"] = original_backup
                receipt.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def test_backup_tampering_is_refused_at_rollback(self):
        path = self.opencode_config({"mcp": {}})
        self.assertEqual(self.run_json("apply", "opencode")[0], EXIT_OK)
        self.backup_path().write_bytes(b'{"mcp": {}, "tampered": true}')
        kept = path.read_bytes()
        code, payload, _ = self.run_json("rollback", "opencode")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("backup digest", payload["refusal_reason"])
        self.assertEqual(path.read_bytes(), kept)


class OpenCodeRollbackGateTests(ConnectApplyOpenCodeCase):
    def test_rollback_restores_the_exact_pre_apply_bytes(self):
        path = self.opencode_config({"context7": dict(_REMOTE_ENTRY)})
        before = path.read_bytes()
        code, _, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_OK)
        code, payload, _ = self.run_json("rollback", "opencode")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["rollback_succeeded"])
        self.assertTrue(payload["validation_succeeded"])
        self.assertFalse(payload["registration_present"])
        self.assertEqual(path.read_bytes(), before)
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertNotIn(MANAGED_SERVER_NAME, self.mcp_container(document))
        self.assertEqual(self.mcp_container(document)["context7"], _REMOTE_ENTRY)

    def test_rollback_refuses_external_edits_made_after_the_apply(self):
        path = self.opencode_config({"mcp": {}})
        self.assertEqual(self.run_json("apply", "opencode")[0], EXIT_OK)
        edited = json.loads(path.read_text(encoding="utf-8"))
        edited["external_edit"] = True
        path.write_text(json.dumps(edited, indent=2), encoding="utf-8")
        kept = path.read_bytes()
        code, payload, _ = self.run_json("rollback", "opencode")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("external edits", payload["refusal_reason"])
        self.assertFalse(payload["rollback_succeeded"])
        self.assertEqual(path.read_bytes(), kept)

    def test_rollback_rechecks_the_digest_inside_the_lock(self):
        path = self.opencode_config({"mcp": {}})
        self.assertEqual(self.run_json("apply", "opencode")[0], EXIT_OK)
        original_lock = connector_apply.interprocess_lock

        def hostile_lock(target):
            context = original_lock(target)

            class _Context:
                def __enter__(self):
                    context.__enter__()
                    document = json.loads(path.read_text(encoding="utf-8"))
                    document["host_write"] = True
                    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
                    return context

                def __exit__(self, *args):
                    return context.__exit__(*args)

            return _Context()

        with mock.patch.object(connector_apply, "interprocess_lock", hostile_lock):
            code, payload, _ = self.run_json("rollback", "opencode")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("external edits", payload["refusal_reason"])
        self.assertFalse(payload["rollback_succeeded"])
        current = json.loads(path.read_text(encoding="utf-8"))
        self.assertTrue(current.get("host_write"))

    def test_rollback_without_any_prior_apply_is_refused(self):
        self.opencode_config({"mcp": {}})
        result = rollback_connector(OPENCODE, self.env(), workspace_root=self.repo)
        self.assertTrue(result.refused)
        self.assertIn("no machine receipt and no backup", result.refusal_reason)


class OpenCodeVerifyTests(ConnectApplyOpenCodeCase):
    def test_a_valid_proof_is_recorded_and_assessed_valid(self):
        self.opencode_config({"mcp": {MANAGED_SERVER_NAME: self.registered_opencode_entry()}})
        self.record_opencode_proof()
        status, record, _ = assess_verification(
            self.repo, "opencode", launch_fingerprint(self.launch())
        )
        self.assertEqual(status, STATUS_VALID)
        self.assertIsNotNone(record)
        self.assertTrue(record.stages["handshake_succeeded"])
        code, payload, _ = self.run_json("check", "opencode")
        self.assertEqual(code, EXIT_OK)
        verification = payload["verification"]
        self.assertEqual(verification["status"], STATUS_VALID)
        self.assertTrue(verification["locally_verified"])
        self.assertFalse(verification["independently_attested"])
        self.assertEqual(verification["evidence_class"], "local_operational")

    def test_a_forged_record_naming_another_host_is_rejected(self):
        self.opencode_config({"mcp": {MANAGED_SERVER_NAME: self.registered_opencode_entry()}})
        self.record_opencode_proof()
        store = self.verification_store()
        data = json.loads(store.read_text(encoding="utf-8"))
        data["host"] = "claude"
        store.write_text(json.dumps(data, indent=2), encoding="utf-8")
        status, _, reasons = assess_verification(
            self.repo, "opencode", launch_fingerprint(self.launch())
        )
        self.assertEqual(status, STATUS_INVALID)
        self.assertTrue(any("different host" in reason for reason in reasons))

    def test_a_fingerprint_mismatch_is_stale_not_valid(self):
        self.opencode_config({"mcp": {MANAGED_SERVER_NAME: self.registered_opencode_entry()}})
        self.record_opencode_proof()
        status, _, reasons = assess_verification(self.repo, "opencode", "0" * 64)
        self.assertEqual(status, STATUS_STALE_FINGERPRINT)
        self.assertTrue(any("launch contract" in reason for reason in reasons))
        code, payload, _ = self.run_json("check", "opencode")
        verification = payload["verification"]
        # Against the CURRENT contract the record still holds; the stale
        # state only appears once the launch contract actually changes.
        self.assertEqual(verification["status"], STATUS_VALID)
        self.assertFalse(verification["independently_attested"])

    def test_a_future_timestamp_is_rejected(self):
        self.opencode_config({"mcp": {MANAGED_SERVER_NAME: self.registered_opencode_entry()}})
        self.record_opencode_proof()
        store = self.verification_store()
        data = json.loads(store.read_text(encoding="utf-8"))
        data["timestamp"] = "2999-01-01T00:00:00+00:00"
        store.write_text(json.dumps(data, indent=2), encoding="utf-8")
        status, _, reasons = assess_verification(
            self.repo, "opencode", data["registration_fingerprint"]
        )
        self.assertEqual(status, STATUS_INVALID)
        self.assertTrue(any("future" in reason for reason in reasons))

    def test_an_unknown_source_never_becomes_valid(self):
        self.opencode_config({"mcp": {MANAGED_SERVER_NAME: self.registered_opencode_entry()}})
        self.record_opencode_proof()
        store = self.verification_store()
        data = json.loads(store.read_text(encoding="utf-8"))
        data["source"] = "forged"
        store.write_text(json.dumps(data, indent=2), encoding="utf-8")
        status, _, _ = assess_verification(
            self.repo, "opencode", data["registration_fingerprint"]
        )
        self.assertNotEqual(status, STATUS_VALID)
        code, payload, _ = self.run_json("check", "opencode")
        self.assertFalse(payload["verification"]["fully_verified"])
        self.assertFalse(payload["verification"]["independently_attested"])

    def test_a_proof_for_another_host_does_not_verify_opencode(self):
        self.opencode_config({"mcp": {MANAGED_SERVER_NAME: self.registered_opencode_entry()}})
        proof_path = self.write_proof(self.valid_proof())
        code, _, _ = self.run_cli("verify", "claude", "--proof", str(proof_path))
        self.assertEqual(code, EXIT_OK)
        status, record, _ = assess_verification(
            self.repo, "opencode", launch_fingerprint(self.launch())
        )
        self.assertEqual(status, STATUS_ABSENT)
        self.assertIsNone(record)

    def test_an_expired_proof_is_reported_honestly(self):
        self.opencode_config({"mcp": {MANAGED_SERVER_NAME: self.registered_opencode_entry()}})
        self.record_opencode_proof()
        store = self.verification_store()
        data = json.loads(store.read_text(encoding="utf-8"))
        data["timestamp"] = "2001-01-01T00:00:00+00:00"
        store.write_text(json.dumps(data, indent=2), encoding="utf-8")
        status, _, _ = assess_verification(
            self.repo, "opencode", launch_fingerprint(self.launch())
        )
        self.assertEqual(status, STATUS_EXPIRED)
        code, payload, _ = self.run_json("check", "opencode")
        verification = payload["verification"]
        self.assertEqual(verification["status"], STATUS_EXPIRED)
        self.assertFalse(verification["locally_verified"])
        self.assertTrue(any("lifetime" in reason for reason in verification["reasons"]))


class OpenCodePortabilityTests(ConnectApplyOpenCodeCase):
    def populate_secret(self):
        return self.opencode_config(
            {
                "mcp": {
                    "engram": {
                        "type": "local",
                        "command": ["engram", "mcp"],
                        "environment": {"ENGRAM_TOKEN": _SECRET},
                    }
                }
            }
        )

    def test_no_apply_check_or_verify_output_carries_a_path(self):
        self.populate_secret()
        proof_path = self.write_proof(self.valid_proof())
        for argv in (
            ("apply", "opencode"),
            ("check", "opencode"),
            ("verify", "opencode", "--proof", str(proof_path)),
            ("rollback", "opencode"),
            ("plan", "opencode"),
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
            ("apply", "opencode"),
            ("check", "opencode"),
            ("verify", "opencode", "--proof", str(proof_path)),
            ("rollback", "opencode"),
            ("plan", "opencode"),
        ):
            for extra in ((), ("--json",)):
                with self.subTest(argv=argv, extra=extra):
                    _, out, err = self.run_cli(*argv, *extra)
                    self.assertNotIn(_SECRET, out)
                    self.assertNotIn(_SECRET, err)
                    self.assertNotIn(_SECRET.split("-", 1)[-1], out)
        # The secret survived every mutation of the file, untouched.
        self.assertIn(_SECRET, path.read_text(encoding="utf-8"))

    def test_credential_shaped_proof_keys_are_rejected(self):
        self.opencode_config({"mcp": {}})
        for key in ("api_token", "oauth_secret", "password", "key"):
            with self.subTest(key=key):
                proof = self.valid_proof()
                proof[key] = "value"
                code, _, err = self.run_cli(
                    "verify", "opencode", "--proof", str(self.write_proof(proof))
                )
                self.assertEqual(code, EXIT_ACTION_REQUIRED)
                self.assertIn("credential-shaped", err)
        self.assertFalse(self.verification_store().exists())

    def test_a_proof_with_absolute_paths_is_rejected(self):
        self.opencode_config({"mcp": {}})
        proof = self.valid_proof()
        proof["tools_visible"] = [str(self.home / "tool")]
        code, _, err = self.run_cli(
            "verify", "opencode", "--proof", str(self.write_proof(proof))
        )
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("machine-local path", err)
        self.assertFalse(self.verification_store().exists())

    def test_reveal_paths_opts_into_machine_local_output(self):
        self.opencode_config({"mcp": {}})
        code, payload, _ = self.run_json("apply", "opencode", "--reveal-paths")
        self.assertEqual(code, EXIT_OK)
        self.assertIn(str(self.home), payload["real_config_path"])


class OpenCodeNonInterferenceTests(ConnectApplyOpenCodeCase):
    def populate_other_hosts(self):
        self.claude_config({"c7": {"command": "npx", "args": ["-y", "c7"]}})
        self.write_config(
            ".codex",
            "config.toml",
            content='[mcp_servers.engram]\ncommand = "engram"\nargs = ["mcp"]\n',
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

    def test_opencode_commands_never_touch_other_host_configs(self):
        self.populate_other_hosts()
        self.opencode_config({"mcp": {"engram": dict(_ENGRAM_ENTRY)}})
        home_before = self.snapshot(self.home)
        repo_before = set(self.snapshot(self.repo))
        proof_path = self.write_proof(self.valid_proof())

        self.assertEqual(self.run_json("apply", "opencode")[0], EXIT_OK)
        self.assertEqual(self.run_json("check", "opencode")[0], EXIT_OK)
        self.assertEqual(
            self.run_cli("verify", "opencode", "--proof", str(proof_path))[0],
            EXIT_OK,
        )

        home_after = self.snapshot(self.home)
        changed = {
            name
            for name in set(home_before) | set(home_after)
            if home_before.get(name) != home_after.get(name)
        }
        opencode_prefix = str(Path(".config") / "opencode" / "opencode.json")
        for name in changed:
            self.assertTrue(
                name == opencode_prefix or name.startswith(opencode_prefix + "."),
                f"unexpected write outside the opencode target: {name}",
            )
        for name in (
            ".claude.json",
            str(Path(".codex") / "config.toml"),
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

    def test_a_claude_apply_does_not_touch_the_opencode_config(self):
        self.populate_other_hosts()
        opencode = self.opencode_config({"mcp": {"engram": dict(_ENGRAM_ENTRY)}})
        before = opencode.read_bytes()
        code, _, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(opencode.read_bytes(), before)


class OpenCodeDoctorPerHostTests(ConnectApplyOpenCodeCase):
    def test_doctor_shows_each_hosts_verification_independently(self):
        self.claude_config({MANAGED_SERVER_NAME: self.registered_claude_entry()})
        self.opencode_config({"mcp": {}})
        code, _, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_OK)
        # Claude holds valid local evidence; OpenCode holds none.
        proof_path = self.write_proof(self.valid_proof())
        code, _, _ = self.run_cli("verify", "claude", "--proof", str(proof_path))
        self.assertEqual(code, EXIT_OK)

        payload = self.run_doctor()
        rows = {
            row["connector_id"]: row
            for row in payload["routing"]["host_verification"]
        }
        self.assertIn("claude", rows)
        self.assertIn("opencode", rows)
        # OpenCode: applied and managed, but host stages unverified.
        opencode = rows["opencode"]
        self.assertTrue(opencode["config_present"])
        self.assertTrue(opencode["managed_registration"])
        self.assertEqual(opencode["verification_status"], STATUS_ABSENT)
        self.assertFalse(opencode["locally_verified"])
        self.assertFalse(opencode["independently_attested"])
        self.assertIsNone(opencode["handoff_proven"])
        for value in opencode["stages"].values():
            self.assertIsNone(value)
        # Claude: proven by its own evidence, never degraded by OpenCode.
        claude = rows["claude"]
        self.assertEqual(claude["verification_status"], STATUS_VALID)
        self.assertTrue(claude["locally_verified"])
        self.assertTrue(claude["handoff_proven"])

        checks = {check["name"]: check for check in payload["checks"]}
        self.assertEqual(checks["Host verification"]["status"], WARN)
        ladder_stages = {
            stage["stage"]: stage
            for stage in payload["routing"]["trust_ladder"]["stages"]
        }
        handshake = ladder_stages[STAGE_HANDSHAKE_VERIFIED]
        self.assertEqual(handshake["state"], "proven")
        self.assertIn("valid local host evidence", handshake["evidence"])
        self.assertIn("(claude)", handshake["evidence"])
        self.assertNotIn("(opencode)", handshake["evidence"])
        self.assertEqual(ladder_stages[STAGE_REAL_HOST_LAUNCH]["state"], "proven")

    def test_check_surfaces_per_host_verification_rows(self):
        self.opencode_config({"mcp": {MANAGED_SERVER_NAME: self.registered_opencode_entry()}})
        code, payload, _ = self.run_json("check", "opencode")
        self.assertEqual(code, EXIT_OK)
        hosts = payload["host_verification_sections"]
        self.assertIn("claude", hosts)
        self.assertIn("opencode", hosts)
        for host_id, section in hosts.items():
            with self.subTest(host=host_id):
                self.assertEqual(section["status"], STATUS_ABSENT)
                self.assertFalse(section["locally_verified"])
                self.assertFalse(section["independently_attested"])
                self.assertEqual(section["evidence_class"], "none")
        self.record_opencode_proof()
        code, payload, _ = self.run_json("check", "opencode")
        self.assertEqual(code, EXIT_OK)
        hosts = payload["host_verification_sections"]
        self.assertEqual(hosts["opencode"]["status"], STATUS_VALID)
        self.assertTrue(hosts["opencode"]["locally_verified"])
        self.assertEqual(hosts["opencode"]["evidence_class"], "local_operational")
        self.assertEqual(hosts["claude"]["status"], STATUS_ABSENT)
        self.assertFalse(hosts["claude"]["locally_verified"])
        code, out, _ = self.run_cli("check", "opencode")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Per-host verification", out)
        self.assertIn("opencode", out)
        self.assertIn("claude", out)


class OpenCodeJsoncScopeTests(ConnectApplyOpenCodeCase):
    """OpenCode deep-merges opencode.jsonc after opencode.json (verified
    against upstream ConfigPaths), so a direct-CBM entry living only in a
    ``.jsonc`` file must gate the apply exactly like one in the target."""

    CBM_ENTRY = {"type": "local", "command": ["python", "-m", "codebase_memory_mcp"]}

    def write_user_jsonc(self, content):
        path = self.home / ".config" / "opencode" / "opencode.jsonc"
        path.parent.mkdir(parents=True, exist_ok=True)
        text = content if isinstance(content, str) else json.dumps(content, indent=2)
        path.write_bytes(text.encode("utf-8"))
        return path

    def test_direct_cbm_only_in_the_user_jsonc_blocks_the_apply(self):
        path = self.opencode_config({"mcp": {}})
        json_before = path.read_bytes()
        jsonc = self.write_user_jsonc({"mcp": {"memory-helper": dict(self.CBM_ENTRY)}})
        jsonc_before = jsonc.read_bytes()
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("direct codebase-memory", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertTrue(
            any("direct_cbm_exposure" in warning for warning in payload["warnings"])
        )
        self.assert_untouched(path, json_before)
        self.assertEqual(jsonc.read_bytes(), jsonc_before)
        # The CBM entry is never removed automatically.
        document = json.loads(jsonc.read_text(encoding="utf-8"))
        self.assertEqual(document["mcp"]["memory-helper"], self.CBM_ENTRY)

    def test_direct_cbm_only_in_the_workspace_jsonc_blocks_the_apply(self):
        path = self.opencode_config({"mcp": {}})
        before = path.read_bytes()
        (self.repo / "opencode.jsonc").write_text(
            json.dumps({"mcp": {"friendly-name": dict(self.CBM_ENTRY)}}),
            encoding="utf-8",
        )
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("direct codebase-memory", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertEqual(path.read_bytes(), before)
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertNotIn(MANAGED_SERVER_NAME, self.mcp_container(document))

    def test_a_user_jsonc_with_comments_fails_closed_as_unreadable(self):
        path = self.opencode_config({"mcp": {}})
        before = path.read_bytes()
        jsonc = self.write_user_jsonc('{\n  // a jsonc comment\n  "mcp": {},\n}\n')
        jsonc_before = jsonc.read_bytes()
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("authoritative user MCP scope", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(jsonc.read_bytes(), jsonc_before)

    def test_a_workspace_jsonc_with_comments_fails_closed_as_unreadable(self):
        path = self.opencode_config({"mcp": {}})
        before = path.read_bytes()
        (self.repo / "opencode.jsonc").write_text(
            '{\n  // a jsonc comment\n  "mcp": {}\n}\n', encoding="utf-8"
        )
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("authoritative project MCP scope", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertEqual(path.read_bytes(), before)

    def test_a_clean_jsonc_does_not_block_and_is_never_written(self):
        path = self.opencode_config({"mcp": {}})
        jsonc = self.write_user_jsonc({"mcp": {"engram": dict(_ENGRAM_ENTRY)}})
        jsonc_before = jsonc.read_bytes()
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["write_succeeded"])
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn(MANAGED_SERVER_NAME, self.mcp_container(document))
        self.assertEqual(jsonc.read_bytes(), jsonc_before)

    def test_inspect_reports_the_jsonc_locations(self):
        self.opencode_config({"mcp": {}})
        self.write_user_jsonc({"mcp": {}})
        code, payload, _ = self.run_json("inspect", "opencode")
        self.assertEqual(code, EXIT_OK)
        by_id = {loc["location_id"]: loc for loc in payload["locations"]}
        self.assertIn("opencode_user_config_jsonc", by_id)
        self.assertIn("opencode_workspace_jsonc", by_id)
        self.assertTrue(by_id["opencode_user_config_jsonc"]["exists"])
        # The apply target is still the .json user config.
        self.assertEqual(payload["active_location_id"], "opencode_user_config")


class OpenCodeShadowAndScopeAlignmentTests(ConnectApplyOpenCodeCase):
    """Correction-pass coverage for the OpenCode write path.

    * C-1: an entry under the managed name in ANY merged-in scope shadows
      the registration — apply refuses and check reports the conflict.
    * C-2: a scope without an MCP container registers no servers (clean),
      exactly like the apply scanner.
    * C-5: only the connector's DECLARED inherited containers are scanned;
      an unknown top-level ``mcpServers`` member means nothing to OpenCode.
    * W-1: the ``%APPDATA%`` user config is MCP-authoritative too.
    * W-6: an unreadable-scope refusal names the portable display hint.
    """

    SHADOW_ENTRY = {"type": "local", "command": ["relinkra-old", "mcp"]}
    CBM_ENTRY = {"type": "local", "command": ["python", "-m", "codebase_memory_mcp"]}

    def write_user_jsonc(self, content):
        path = self.home / ".config" / "opencode" / "opencode.jsonc"
        path.parent.mkdir(parents=True, exist_ok=True)
        text = content if isinstance(content, str) else json.dumps(content, indent=2)
        path.write_bytes(text.encode("utf-8"))
        return path

    # -- C-1: shadow entries in merged scopes refuse --------------------

    def test_a_foreign_managed_name_in_the_user_jsonc_refuses_apply(self):
        path = self.opencode_config({"mcp": {}})
        before = path.read_bytes()
        jsonc = self.write_user_jsonc(
            {"mcp": {MANAGED_SERVER_NAME: dict(self.SHADOW_ENTRY)}}
        )
        jsonc_before = jsonc.read_bytes()
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("shadows the managed registration", payload["refusal_reason"])
        self.assertIn("opencode.jsonc", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(jsonc.read_bytes(), jsonc_before)

    def test_a_relinkra_launch_under_the_managed_name_in_jsonc_still_refuses(self):
        # Even an entry that launches Relinkra correctly is a shadow when
        # it lives in a merged-in scope: which entry the host runs is the
        # host's merge rule, and Relinkra never removes another scope's
        # entry to resolve the ambiguity.
        path = self.opencode_config({"mcp": {}})
        before = path.read_bytes()
        self.write_user_jsonc(
            {"mcp": {MANAGED_SERVER_NAME: self.registered_opencode_entry()}}
        )
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("shadows the managed registration", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertEqual(path.read_bytes(), before)

    def test_a_managed_name_in_the_workspace_json_refuses_apply(self):
        path = self.opencode_config({"mcp": {}})
        before = path.read_bytes()
        (self.repo / "opencode.json").write_text(
            json.dumps({"mcp": {MANAGED_SERVER_NAME: dict(self.SHADOW_ENTRY)}}),
            encoding="utf-8",
        )
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("shadows the managed registration", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertEqual(path.read_bytes(), before)

    def test_check_reports_a_jsonc_shadow_as_a_conflict(self):
        self.opencode_config(
            {"mcp": {MANAGED_SERVER_NAME: self.registered_opencode_entry()}}
        )
        self.write_user_jsonc(
            {"mcp": {MANAGED_SERVER_NAME: dict(self.SHADOW_ENTRY)}}
        )
        code, payload, _ = self.run_json("check", "opencode")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertEqual(payload["registration_state"], "conflict")
        self.assertFalse(payload["valid"])
        self.assertTrue(
            any("shadows the managed registration" in f for f in payload["findings"]),
            payload["findings"],
        )
        self.assertTrue(
            any("opencode.jsonc" in f for f in payload["findings"]),
            payload["findings"],
        )

    def test_check_fails_closed_on_an_unreadable_authoritative_jsonc_scope(self):
        self.opencode_config(
            {"mcp": {MANAGED_SERVER_NAME: self.registered_opencode_entry()}}
        )
        self.write_user_jsonc(
            '{\n'
            '  // invalid for the strict authoritative-scope scanner\n'
            '  "mcp": {}\n'
            '}\n'
        )
        code, payload, _ = self.run_json("check", "opencode")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertFalse(payload["valid"])
        self.assertEqual(payload["registration_state"], "unknown")
        self.assertTrue(
            any("could not be read" in finding for finding in payload["findings"]),
            payload["findings"],
        )
        self.assertTrue(
            any("opencode.jsonc" in finding for finding in payload["findings"]),
            payload["findings"],
        )
        for value in iter_strings(payload):
            self.assertFalse(contains_absolute_path(value), value)

    def test_the_target_entry_itself_is_never_reported_as_a_shadow(self):
        self.opencode_config(
            {"mcp": {MANAGED_SERVER_NAME: self.registered_opencode_entry()}}
        )
        code, payload, _ = self.run_json("check", "opencode")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["valid"])
        self.assertFalse(
            any("shadows" in f for f in payload["findings"]), payload["findings"]
        )

    # -- C-2: a scope without an MCP container is clean ------------------

    def test_a_jsonc_without_an_mcp_container_is_clean_not_unreadable(self):
        path = self.opencode_config({"mcp": {}})
        jsonc = self.write_user_jsonc({"theme": "dark", "model": "test"})
        jsonc_before = jsonc.read_bytes()
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["write_succeeded"])
        self.assertEqual(jsonc.read_bytes(), jsonc_before)
        _, routing, _ = self.run_json("routing")
        self.assertFalse(
            any(
                host.get("authoritative_scope_unreadable")
                for host in routing["hosts"]
            ),
            routing["hosts"],
        )

    # -- C-5: only the declared inherited containers are scanned --------

    def test_an_unknown_top_level_mcp_servers_member_means_nothing_to_opencode(self):
        # OpenCode's container is ``mcp``; a top-level ``mcpServers``
        # member is an unknown field the host never honors. It must NOT
        # trip the direct-CBM gate (no blanket top-level scan) and it
        # must survive the rewrite intact.
        path = self.opencode_config(
            {"mcp": {}},
            mcpServers={"memory-helper": {"command": "codebase-memory-mcp", "args": []}},
        )
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["write_succeeded"])
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn(MANAGED_SERVER_NAME, self.mcp_container(document))
        self.assertEqual(
            document["mcpServers"],
            {"memory-helper": {"command": "codebase-memory-mcp", "args": []}},
        )

    # -- W-1: the %APPDATA% user config is MCP-authoritative -------------

    def test_direct_cbm_in_the_appdata_config_blocks_the_apply(self):
        self.opencode_config({"mcp": {}})
        appdata = self.home / "AppData" / "Roaming"
        self.write_config(
            "AppData", "Roaming", "opencode", "opencode.json",
            content={"mcp": {"memory-helper": dict(self.CBM_ENTRY)}},
        )
        env = DiscoveryEnvironment(
            system=SYSTEM_WINDOWS,
            home=self.home,
            env={"APPDATA": str(appdata)},
            workspace_root=self.root,
            which=lambda name: None,
        )
        result = apply_connector(OPENCODE, self.launch(), env)
        self.assertTrue(result.refused)
        self.assertIn("direct codebase-memory", result.refusal_reason)
        document = json.loads(self.opencode_path().read_text(encoding="utf-8"))
        self.assertNotIn(MANAGED_SERVER_NAME, self.mcp_container(document))

    # -- W-6: the unreadable refusal names the portable hint -------------

    def test_the_unreadable_scope_refusal_names_the_display_hint(self):
        self.opencode_config({"mcp": {}})
        self.write_user_jsonc('{\n  // comment\n  "mcp": {}\n}\n')
        code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("authoritative user MCP scope", payload["refusal_reason"])
        self.assertIn("opencode.jsonc", payload["refusal_reason"])
        for value in iter_strings(payload):
            self.assertFalse(contains_absolute_path(value), value)

    # -- W-3: the post-write failure wording matches the rollback --------

    def _forcing_content_validation_error(self, rolled_back):
        from relinkra.safe_write import ContentValidationError

        def broken_replace(*_args, **_kwargs):
            raise ContentValidationError(
                "written content failed validation", rolled_back=rolled_back
            )

        return mock.patch.object(
            connector_apply, "safe_replace", side_effect=broken_replace
        )

    def test_a_failed_post_write_validation_without_rollback_says_so(self):
        # Claiming "the original file was restored" when it was NOT would
        # be the worst possible lie at the worst possible moment.
        self.opencode_config({"mcp": {}})
        with self._forcing_content_validation_error(rolled_back=False):
            code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_ERROR)
        actions = " ".join(payload["actions"])
        self.assertIn("could NOT be restored", actions)
        self.assertNotIn("was restored. Re-run", actions)
        self.assertFalse(payload["rollback_succeeded"])

    def test_a_failed_post_write_validation_with_rollback_says_restored(self):
        self.opencode_config({"mcp": {}})
        with self._forcing_content_validation_error(rolled_back=True):
            code, payload, _ = self.run_json("apply", "opencode")
        self.assertEqual(code, EXIT_ERROR)
        actions = " ".join(payload["actions"])
        self.assertIn("was restored", actions)
        self.assertNotIn("could NOT be restored", actions)
        self.assertTrue(payload["rollback_succeeded"])

    # -- W-7: a corrupt evidence store never crashes check ---------------

    def test_an_unassessable_evidence_store_is_reported_as_absent(self):
        self.opencode_config(
            {"mcp": {MANAGED_SERVER_NAME: self.registered_opencode_entry()}}
        )
        with mock.patch.object(
            connect_cli,
            "assess_verification",
            side_effect=RuntimeError("corrupt evidence store"),
        ):
            code, payload, _ = self.run_json("check", "opencode")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertEqual(payload["verification"]["status"], STATUS_ABSENT)
        self.assertTrue(
            any("could not be assessed" in r for r in payload["verification"]["reasons"]),
            payload["verification"]["reasons"],
        )
        for section in payload["host_verification_sections"].values():
            self.assertEqual(section["status"], STATUS_ABSENT)


if __name__ == "__main__":
    unittest.main()
