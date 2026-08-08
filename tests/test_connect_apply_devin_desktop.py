"""Tests for the Devin Desktop connector write path (R4C.1E Gate B).

Gate B opens apply/rollback/verify for devin-desktop after the Gate B1
machine evidence proved the mirror semantics (PROVEN_MULTI_SOURCE):

* the authoritative user-scope write target on Windows is the product's
  own ``%APPDATA%/Devin/mcp_config.json`` — the CLI user scope IS the
  app profile there (``lLr``/``f$`` config base in the shipped bundles);
  on POSIX it is ``~/.config/devin/mcp_config.json``;
* the legacy ``~/.codeium/*/mcp_config.json`` files are watched one-way
  import sources (TrustedOnNonce), evidence-only, never write targets;
* a direct CBM entry in a LEGACY scope is surfaced loudly (check
  warning, apply warning) but never blocks the apply — only
  authoritative-scope CBM blocks.

Every test drives the real CLI through ``main(argv)`` or the real engine
against a fixture home plus a fake repository, with host discovery
monkeypatched exactly like the other per-host apply suites. The
cross-platform tests use the ``~/.config/devin`` user scope; the APPDATA
profile behaviors are Windows-conditional because ``env.app_data``
returns ``None`` elsewhere by design.

Each protection test is written to be discriminating: removing the
protection (the legacy-write guard, the direct-CBM gate, backup
confinement, the external-edit digest gate, idempotence, forged-proof
rejection or portable redaction) makes THAT test fail.
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
    legacy_scope_findings,
    rollback_connector,
)
from relinkra.connectors import (
    CLAUDE,
    DEVIN_DESKTOP,
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
from relinkra.safe_write import digest_text, read_bounded_text

_SECRET = "sk-live-DEVIN-DO-NOT-LEAK-0123456789"

_SYSTEM = SYSTEM_WINDOWS if os.name == "nt" else SYSTEM_LINUX

_CBM_ENTRY = {"command": "python", "args": ["-m", "codebase_memory_mcp"]}
_REMOTE_ENTRY = {"command": "npx", "args": ["-y", "@upstash/context7-mcp"]}
_ENGRAM_ENTRY = {"command": "engram", "args": ["mcp", "--tools=agent"]}


class ConnectApplyDevinDesktopCase(unittest.TestCase):
    """A fake repository plus a fixture home, discovery monkeypatched."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="relinkra-connect-apply-devin-")
        self.addCleanup(self._temp.cleanup)
        base = Path(self._temp.name)
        self.home = base / "home"
        self.home.mkdir()
        self.appdata = base / "appdata"
        self.repo = base / "repo"
        (self.repo / ".git").mkdir(parents=True)
        self.root = self.repo.resolve()
        self.env_vars = {}
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
                system=_SYSTEM,
                home=outer.home,
                env=dict(outer.env_vars),
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
            system=_SYSTEM,
            home=self.home,
            env=dict(self.env_vars),
            workspace_root=self.root,
            which=lambda name: None,
        )

    def write_home(self, *parts, content):
        path = self.home.joinpath(*parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        text = content if isinstance(content, str) else json.dumps(content, indent=2)
        path.write_bytes(text.encode("utf-8"))
        return path

    def write_repo(self, *parts, content):
        path = self.repo.joinpath(*parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        text = content if isinstance(content, str) else json.dumps(content, indent=2)
        path.write_bytes(text.encode("utf-8"))
        return path

    def current_config(self, content):
        """The cross-platform authoritative user scope (POSIX rendering).

        On Windows this still resolves: with no APPDATA fixture written,
        the config-home user scope is the active current-product file.
        """
        return self.write_home(".config", "devin", "mcp_config.json", content=content)

    def current_path(self):
        return self.home / ".config" / "devin" / "mcp_config.json"

    def appdata_config(self, content):
        self.env_vars["APPDATA"] = str(self.appdata)
        path = self.appdata / "Devin" / "mcp_config.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        text = content if isinstance(content, str) else json.dumps(content, indent=2)
        path.write_bytes(text.encode("utf-8"))
        return path

    def legacy_config(self, content):
        return self.write_home(
            ".codeium", "windsurf", "mcp_config.json", content=content
        )

    def legacy_next_config(self, content):
        return self.write_home(
            ".codeium", "windsurf-next", "mcp_config.json", content=content
        )

    def workspace_local_config(self, content):
        return self.write_repo(".devin", "mcp_config.local.json", content=content)

    def workspace_project_config(self, content):
        return self.write_repo(".devin", "mcp_config.json", content=content)

    def backup_path(self):
        return self.current_path().with_name("mcp_config.json.relinkra-backup")

    def receipt_path(self):
        return self.repo / ".relinkra" / "connect-apply" / "devin-desktop.json"

    def verification_store(self):
        return self.repo / ".relinkra" / "connect-verification" / "devin-desktop.json"

    def launch(self):
        return resolve_launch(self.repo, registry_path(self.repo))

    def managed_entry(self):
        return DEVIN_DESKTOP.entry_builder(self.launch())

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
            "workspace_id": self.workspace_id,
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

    def record_devin_proof(self, payload=None):
        proof_path = self.write_proof(payload or self.valid_proof())
        code, _, err = self.run_cli(
            "verify", "devin-desktop", "--proof", str(proof_path), "--json"
        )
        self.assertEqual(code, EXIT_OK, err)

    def assert_semantic_registration(self, path):
        """The written entry IS the launch contract for this workspace."""
        document = json.loads(path.read_text(encoding="utf-8"))
        entry = document["mcpServers"][MANAGED_SERVER_NAME]
        self.assertEqual(entry, self.managed_entry())
        self.assertTrue(launches_relinkra(entry))
        tokens = entry_tokens(entry)
        index = tokens.index("--workspace-root")
        self.assertEqual(Path(tokens[index + 1]).resolve(), self.root)
        self.assertIn("--registry", tokens)
        if self.launch().env:
            self.assertIn("PYTHONPATH", entry.get("env", {}))


class DevinDesktopApplyBasicsTests(ConnectApplyDevinDesktopCase):
    """B4.1/B4.2 — the apply targets the current product, never legacy."""

    def test_apply_targets_the_current_user_scope_and_never_the_legacy_mirror(self):
        # B4.1 (POSIX-portable half): the config-home user scope is the
        # active current-product file; a legacy mirror sits beside it.
        path = self.current_config({"mcpServers": {}})
        legacy = self.legacy_config({"mcpServers": {}})
        legacy_before = legacy.read_bytes()
        original = path.read_bytes()
        code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["change_required"])
        self.assertTrue(payload["backup_created"])
        self.assertTrue(payload["write_succeeded"])
        self.assertTrue(payload["validation_succeeded"])
        self.assertEqual(
            payload["verification_stage"], "config_applied_host_unverified"
        )
        self.assertFalse(payload["real_host_verified"])
        self.assertEqual(payload["config_path"], "~/.config/devin/mcp_config.json")
        # Only the current file changed; the legacy mirror is byte-exact.
        self.assert_semantic_registration(path)
        self.assertEqual(legacy.read_bytes(), legacy_before)
        # The backup holds the exact original bytes.
        backup = self.backup_path()
        self.assertTrue(backup.is_file())
        self.assertEqual(backup.parent, path.parent)
        self.assertEqual(backup.read_bytes(), original)
        self.assertEqual(payload["backup_digest"], digest_text(original.decode("utf-8")))
        self.assertEqual(payload["backup_ref"], backup.name)
        # The machine receipt is persisted under the workspace.
        receipt = json.loads(self.receipt_path().read_text(encoding="utf-8"))
        self.assertEqual(receipt["host"], "devin-desktop")
        self.assertEqual(receipt["digest_before"], digest_text(original.decode("utf-8")))
        self.assertEqual(receipt["schema_version"], "relinkra.connect-apply/v1")

    @unittest.skipUnless(os.name == "nt", "env.app_data is None off Windows")
    def test_apply_targets_the_appdata_profile_and_never_the_legacy_mirror(self):
        # B4.1 (Windows half): %APPDATA%/Devin is the product's own live
        # file and outranks the CLI-documented config-home scope.
        path = self.appdata_config({"mcpServers": {}})
        legacy = self.legacy_config({"mcpServers": {}})
        legacy_before = legacy.read_bytes()
        original = path.read_bytes()
        code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["write_succeeded"])
        self.assertEqual(payload["config_path"], "%APPDATA%/Devin/mcp_config.json")
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn(MANAGED_SERVER_NAME, document["mcpServers"])
        self.assertEqual(legacy.read_bytes(), legacy_before)
        backup = path.with_name("mcp_config.json.relinkra-backup")
        self.assertEqual(backup.read_bytes(), original)
        receipt = json.loads(self.receipt_path().read_text(encoding="utf-8"))
        self.assertEqual(receipt["host"], "devin-desktop")

    @unittest.skipUnless(os.name == "nt", "env.app_data is None off Windows")
    def test_the_appdata_profile_wins_over_the_config_home_scope(self):
        appdata = self.appdata_config({"mcpServers": {}})
        config_home = self.current_config({"mcpServers": {}})
        config_home_before = config_home.read_bytes()
        code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertEqual(payload["config_path"], "%APPDATA%/Devin/mcp_config.json")
        document = json.loads(appdata.read_text(encoding="utf-8"))
        self.assertIn(MANAGED_SERVER_NAME, document["mcpServers"])
        self.assertEqual(config_home.read_bytes(), config_home_before)

    def test_a_divergent_legacy_mirror_is_never_written(self):
        # B4.2: current and legacy hold DIFFERENT content. The apply
        # targets the current file and the legacy divergence is left
        # exactly as it was — Relinkra never reconciles a mirror.
        path = self.current_config({"mcpServers": {}})
        legacy = self.legacy_config(
            {"mcpServers": {"windsurf-era": {"command": "old", "args": []}}}
        )
        legacy_before = legacy.read_bytes()
        code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["write_succeeded"])
        self.assert_semantic_registration(path)
        self.assertEqual(legacy.read_bytes(), legacy_before)
        legacy_document = json.loads(legacy.read_text(encoding="utf-8"))
        self.assertNotIn(MANAGED_SERVER_NAME, legacy_document["mcpServers"])

    def test_equivalent_only_in_legacy_is_created_at_the_current_target(self):
        # B4.6: a perfectly equivalent registration that lives ONLY at
        # the legacy path is not a current-product registration. Check
        # stays invalid (the Gate A legacy finding), and apply creates
        # the registration at the first current-product candidate — the
        # workspace-local scope the plan promises — never the legacy file.
        legacy = self.legacy_config(
            {"mcpServers": {MANAGED_SERVER_NAME: self.managed_entry()}}
        )
        legacy_before = legacy.read_bytes()
        code, check, _ = self.run_json("check", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED, check)
        self.assertFalse(check["valid"])
        self.assertTrue(any("legacy" in f for f in check["findings"]))
        code, plan, _ = self.run_json("plan", "devin-desktop")
        self.assertEqual(plan["target_ref"], "devin-desktop:devin_workspace_local_mcp")
        code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["write_succeeded"])
        created = self.repo / ".devin" / "mcp_config.local.json"
        self.assert_semantic_registration(created)
        self.assertEqual(legacy.read_bytes(), legacy_before)
        self.assertTrue(self.receipt_path().is_file())


class DevinDesktopDirectCbmTests(ConnectApplyDevinDesktopCase):
    """B4.3/B4.4/B4.18 — authoritative CBM blocks; legacy CBM is loud."""

    def test_direct_cbm_in_the_current_scope_refuses_the_apply(self):
        # B4.3: a direct CBM entry in the authoritative apply target
        # refuses the write before anything is touched.
        path = self.current_config({"mcpServers": {"memory-helper": dict(_CBM_ENTRY)}})
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("direct codebase-memory", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertFalse(payload["backup_created"])
        self.assertTrue(
            any("direct_cbm_exposure" in warning for warning in payload["warnings"])
        )
        self.assert_untouched(path, before)
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(document["mcpServers"]["memory-helper"], _CBM_ENTRY)

    def test_direct_cbm_in_a_workspace_authoritative_scope_refuses(self):
        # The workspace scopes are authoritative too: a CBM entry there
        # gates the apply even when the user-scope target is clean.
        path = self.current_config({"mcpServers": {}})
        before = path.read_bytes()
        self.workspace_project_config(
            {"mcpServers": {"friendly-name": dict(_CBM_ENTRY)}}
        )
        code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("direct codebase-memory", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertEqual(path.read_bytes(), before)

    def test_direct_cbm_in_a_legacy_scope_is_surfaced_but_never_blocks(self):
        # B4.4 + B4.18: the legacy file IS imported into the live host
        # registry by the current product, so the finding must be loud —
        # but per the phase contract it does not block the apply, and it
        # does not change check's valid/exit semantics for the current
        # registration. It is surfaced as a WARNING, never as a finding:
        # ``valid`` is defined as "no findings" and a legacy-scope fact
        # must not flip it.
        path = self.current_config({"mcpServers": {}})
        legacy = self.legacy_config({"mcpServers": {"memory-helper": dict(_CBM_ENTRY)}})
        legacy_before = legacy.read_bytes()
        # The generic scanner reports exactly one finding, per scope.
        findings = legacy_scope_findings(DEVIN_DESKTOP, self.env())
        self.assertEqual(len(findings), 1)
        self.assertIn("codebase-memory", findings[0])
        self.assertIn("legacy", findings[0])
        code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["write_succeeded"])
        self.assertTrue(
            any(
                "direct_cbm_exposure" in warning and "legacy" in warning
                for warning in payload["warnings"]
            ),
            payload["warnings"],
        )
        self.assert_semantic_registration(path)
        self.assertEqual(legacy.read_bytes(), legacy_before)
        document = json.loads(legacy.read_text(encoding="utf-8"))
        self.assertEqual(document["mcpServers"]["memory-helper"], _CBM_ENTRY)
        # Check: the current registration is clean, so check stays VALID
        # with exit 0 — and the legacy CBM is right there in the warnings.
        code, check, _ = self.run_json("check", "devin-desktop")
        self.assertEqual(code, EXIT_OK, check)
        self.assertTrue(check["valid"])
        legacy_warnings = [
            warning for warning in check["warnings"]
            if warning["code"] == "legacy_scope"
        ]
        self.assertTrue(legacy_warnings, check["warnings"])
        self.assertTrue(
            any("codebase-memory" in warning["message"] for warning in legacy_warnings)
        )
        self.assertFalse(
            any("codebase-memory" in finding for finding in check["findings"])
        )

    def test_legacy_cbm_findings_cover_both_legacy_scopes(self):
        self.legacy_config({"mcpServers": {"helper": dict(_CBM_ENTRY)}})
        self.legacy_next_config({"mcpServers": {"helper": dict(_CBM_ENTRY)}})
        findings = legacy_scope_findings(DEVIN_DESKTOP, self.env())
        self.assertEqual(len(findings), 2)

    def test_a_connector_without_legacy_locations_gets_no_findings(self):
        self.assertEqual(CLAUDE.legacy_location_ids, ())
        self.assertEqual(legacy_scope_findings(CLAUDE, self.env()), ())

    def test_an_unreadable_legacy_scope_fails_closed_as_a_finding(self):
        legacy = self.legacy_config("{ broken")
        before = legacy.read_bytes()
        findings = legacy_scope_findings(DEVIN_DESKTOP, self.env())
        self.assertEqual(len(findings), 1)
        self.assertIn("could not be read", findings[0])
        # It is a finding, never a crash and never a write blocker.
        self.current_config({"mcpServers": {}})
        code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["write_succeeded"])
        self.assertEqual(legacy.read_bytes(), before)

    def test_a_stat_denied_legacy_scope_is_a_finding_never_absent(self):
        # Path.exists() suppresses a denied stat and reads as "absent";
        # the scan must still refuse to claim the legacy scopes are
        # clean. Mutation-style probe: deny stat on the legacy file.
        legacy = self.legacy_config({"mcpServers": {}})
        before = legacy.read_bytes()
        real_stat = Path.stat

        def deny(path, *args, **kwargs):
            if Path(str(path)) == legacy:
                raise PermissionError("permission denied")
            return real_stat(path, *args, **kwargs)

        with mock.patch("relinkra.connector_apply.Path.stat", deny):
            findings = legacy_scope_findings(DEVIN_DESKTOP, self.env())
        self.assertEqual(len(findings), 1)
        self.assertIn("could not be read", findings[0])
        self.assertEqual(legacy.read_bytes(), before)

    def test_a_stat_denied_non_active_authoritative_scope_fails_closed(self):
        target = self.workspace_local_config({"mcpServers": {}})
        denied = self.current_config({"mcpServers": {"memory-helper": dict(_CBM_ENTRY)}})
        before = target.read_bytes()
        real_stat = Path.stat
        real_exists = Path.exists

        def deny_stat(path, *args, **kwargs):
            if Path(str(path)) == denied:
                raise PermissionError("permission denied")
            return real_stat(path, *args, **kwargs)

        def deny_exists(path):
            if Path(str(path)) == denied:
                return False
            return real_exists(path)

        with mock.patch.object(Path, "stat", deny_stat), mock.patch.object(
            Path, "exists", deny_exists
        ):
            code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("could not be read", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertEqual(target.read_bytes(), before)


class DevinDesktopIdempotenceTests(ConnectApplyDevinDesktopCase):
    """B4.5/B4.11 — an equivalent registration is a byte-exact no-op."""

    def test_an_equivalent_registration_is_a_semantic_no_op(self):
        path = self.current_config(
            {"mcpServers": {MANAGED_SERVER_NAME: self.managed_entry()}}
        )
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertFalse(payload["change_required"])
        self.assertFalse(payload["backup_created"])
        self.assertFalse(payload["write_attempted"])
        self.assertTrue(payload["registration_matches_expected"])
        self.assertTrue(payload["validation_succeeded"])
        self.assertEqual(
            payload["verification_stage"], "config_applied_host_unverified"
        )
        self.assertEqual(path.read_bytes(), before)
        # A second apply is also a no-op, byte-level.
        code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertFalse(payload["change_required"])
        self.assertEqual(path.read_bytes(), before)
        _, out, _ = self.run_cli("apply", "devin-desktop")
        self.assertIn("No change required", out)

    def test_a_second_apply_after_a_write_keeps_the_file_and_receipt_stable(self):
        path = self.current_config({"mcpServers": {}})
        code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["write_succeeded"])
        written = path.read_bytes()
        receipt_before = self.receipt_path().read_bytes()
        code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertFalse(payload["change_required"])
        self.assertEqual(path.read_bytes(), written)
        self.assertEqual(self.receipt_path().read_bytes(), receipt_before)
        backups = sorted(
            self.current_path().parent.glob("mcp_config.json.relinkra-backup*")
        )
        self.assertEqual(
            [backup.name for backup in backups], ["mcp_config.json.relinkra-backup"]
        )


class DevinDesktopRefusalTests(ConnectApplyDevinDesktopCase):
    """B4.7 — unmanaged conflicts and unsafe states refuse before writing."""

    def test_an_unmanaged_lookalike_under_the_managed_name_is_refused(self):
        path = self.current_config(
            {"mcpServers": {MANAGED_SERVER_NAME: {"command": "node", "args": ["server.js"]}}}
        )
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertTrue(payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assert_untouched(path, before)
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(
            document["mcpServers"][MANAGED_SERVER_NAME],
            {"command": "node", "args": ["server.js"]},
        )

    def test_a_managed_name_in_another_authoritative_scope_shadows(self):
        # The workspace-local scope wins the active slot; an entry under
        # the managed name in the user scope shadows it at runtime.
        path = self.workspace_local_config({"mcpServers": {}})
        before = path.read_bytes()
        self.current_config(
            {"mcpServers": {MANAGED_SERVER_NAME: self.managed_entry()}}
        )
        code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("shadows", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertEqual(path.read_bytes(), before)

    def test_malformed_json_is_refused_without_a_backup(self):
        path = self.current_config("{ broken")
        before = path.read_bytes()
        code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("config_malformed", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertFalse(payload["backup_created"])
        self.assert_untouched(path, before)

    def test_a_symlink_target_is_refused(self):
        path = self.current_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        real_file = self.home / "real-devin.json"
        real_file.write_text('{"mcpServers": {}}', encoding="utf-8")
        try:
            os.symlink(str(real_file), str(path))
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable on this platform: {exc}")
        before = real_file.read_bytes()
        code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("symlink", payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertEqual(real_file.read_bytes(), before)
        self.assertTrue(path.is_symlink())

    def test_devin_cloud_apply_is_refused_and_never_writes(self):
        # B4.17: the hosted connector has no local file to mutate.
        home_before = self.snapshot(self.home)
        code, payload, _ = self.run_json("apply", "devin-cloud")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertTrue(payload["refusal_reason"])
        self.assertFalse(payload["write_attempted"])
        self.assertEqual(self.snapshot(self.home), home_before)


class DevinDesktopPreservationTests(ConnectApplyDevinDesktopCase):
    """B4.8 — unrelated members and formatting conventions survive."""

    def test_unknown_top_level_and_unrelated_servers_survive(self):
        path = self.current_config(
            {
                "mcpServers": {
                    "context7": dict(_REMOTE_ENTRY),
                    "engram": dict(_ENGRAM_ENTRY),
                },
                "theme": "dark",
                "telemetry": {"enabled": False, "level": 2},
            }
        )
        code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_OK, payload)
        document = json.loads(path.read_text(encoding="utf-8"))
        container = document["mcpServers"]
        self.assertEqual(container["context7"], _REMOTE_ENTRY)
        self.assertEqual(container["engram"], _ENGRAM_ENTRY)
        self.assertIn(MANAGED_SERVER_NAME, container)
        self.assertEqual(document["theme"], "dark")
        self.assertEqual(document["telemetry"], {"enabled": False, "level": 2})

    def test_document_formatting_is_preserved(self):
        # CRLF line endings and tab indentation survive the rewrite, as
        # the JSON adapter re-serializes with the detected conventions.
        text = '{\r\n\t"mcpServers": {},\r\n\t"theme": "dark"\r\n}\r\n'
        path = self.current_config(text)
        code, _, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_OK)
        written = path.read_bytes().decode("utf-8")
        self.assertIn("\r\n", written)
        self.assertNotIn("\r\r\n", written)
        self.assertIn('\t"mcpServers"', written)
        self.assertIn('\t"theme": "dark"', written)


class DevinDesktopRollbackTests(ConnectApplyDevinDesktopCase):
    """B4.9/B4.10/B4.12/B4.13 — the rollback contract, byte-exact."""

    def test_rollback_restores_the_exact_pre_apply_bytes(self):
        path = self.current_config({"mcpServers": {"context7": dict(_REMOTE_ENTRY)}})
        before = path.read_bytes()
        code, _, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_OK)
        code, payload, _ = self.run_json("rollback", "devin-desktop")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["rollback_succeeded"])
        self.assertTrue(payload["validation_succeeded"])
        self.assertFalse(payload["registration_present"])
        self.assertEqual(path.read_bytes(), before)
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertNotIn(MANAGED_SERVER_NAME, document["mcpServers"])
        self.assertEqual(document["mcpServers"]["context7"], _REMOTE_ENTRY)

    def test_rollback_after_a_create_unlinks_the_created_file(self):
        # Created-file case: nothing existed before the apply, so the
        # plan targets the first current-product candidate (the
        # workspace-local scope), and the honest restore removes exactly
        # the file Relinkra created.
        created = self.repo / ".devin" / "mcp_config.local.json"
        self.assertFalse(created.exists())
        code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(created.is_file())
        code, payload, _ = self.run_json("rollback", "devin-desktop")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["rollback_succeeded"])
        self.assertTrue(payload["validation_succeeded"])
        self.assertFalse(created.exists())

    def test_backup_tampering_is_refused_at_rollback(self):
        path = self.current_config({"mcpServers": {}})
        self.assertEqual(self.run_json("apply", "devin-desktop")[0], EXIT_OK)
        self.backup_path().write_bytes(b'{"mcpServers": {}, "tampered": true}')
        kept = path.read_bytes()
        code, payload, _ = self.run_json("rollback", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("backup digest", payload["refusal_reason"])
        self.assertEqual(path.read_bytes(), kept)

    def test_rollback_refuses_external_edits_made_after_the_apply(self):
        path = self.current_config({"mcpServers": {}})
        self.assertEqual(self.run_json("apply", "devin-desktop")[0], EXIT_OK)
        edited = json.loads(path.read_text(encoding="utf-8"))
        edited["external_edit"] = True
        path.write_text(json.dumps(edited, indent=2), encoding="utf-8")
        kept = path.read_bytes()
        code, payload, _ = self.run_json("rollback", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("external edits", payload["refusal_reason"])
        self.assertFalse(payload["rollback_succeeded"])
        self.assertEqual(path.read_bytes(), kept)

    def test_rollback_rechecks_the_digest_inside_the_lock(self):
        path = self.current_config({"mcpServers": {}})
        self.assertEqual(self.run_json("apply", "devin-desktop")[0], EXIT_OK)
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
            code, payload, _ = self.run_json("rollback", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("external edits", payload["refusal_reason"])
        self.assertFalse(payload["rollback_succeeded"])
        current = json.loads(path.read_text(encoding="utf-8"))
        self.assertTrue(current.get("host_write"))

    def test_rollback_without_any_prior_apply_is_refused(self):
        self.current_config({"mcpServers": {}})
        result = rollback_connector(DEVIN_DESKTOP, self.env(), workspace_root=self.repo)
        self.assertTrue(result.refused)
        self.assertIn("no machine receipt", result.refusal_reason)

    def test_a_receipt_with_a_tampered_host_is_refused(self):
        path = self.current_config({"mcpServers": {}})
        self.assertEqual(self.run_json("apply", "devin-desktop")[0], EXIT_OK)
        data = json.loads(self.receipt_path().read_text(encoding="utf-8"))
        data["host"] = "claude"
        self.receipt_path().write_text(json.dumps(data, indent=2), encoding="utf-8")
        kept = path.read_bytes()
        code, payload, _ = self.run_json("rollback", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("malformed or unsupported", payload["refusal_reason"])
        self.assertEqual(path.read_bytes(), kept)

    def test_a_receipt_from_another_workspace_is_refused(self):
        path = self.current_config({"mcpServers": {}})
        self.assertEqual(self.run_json("apply", "devin-desktop")[0], EXIT_OK)
        data = json.loads(self.receipt_path().read_text(encoding="utf-8"))
        data["workspace_root"] = str(Path(self._temp.name) / "other-workspace")
        self.receipt_path().write_text(json.dumps(data, indent=2), encoding="utf-8")
        kept = path.read_bytes()
        code, payload, _ = self.run_json("rollback", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("belongs to another workspace", payload["refusal_reason"])
        self.assertEqual(path.read_bytes(), kept)


class DevinDesktopAliasRoutingTests(ConnectApplyDevinDesktopCase):
    """B4.16 — old names route to the canonical connector and receipt."""

    def test_apply_via_the_windsurf_and_codeium_aliases_is_identical(self):
        effects = []
        for alias in ("windsurf", "codeium"):
            with self.subTest(alias=alias):
                path = self.current_config({"mcpServers": {}})
                code, payload, _ = self.run_json("apply", alias)
                self.assertEqual(code, EXIT_OK, payload)
                self.assertEqual(payload["host"], "devin-desktop")
                self.assertTrue(payload["write_succeeded"])
                effects.append(path.read_bytes())
                receipt = json.loads(
                    self.receipt_path().read_text(encoding="utf-8")
                )
                self.assertEqual(receipt["host"], "devin-desktop")
                code, payload, _ = self.run_json("rollback", alias)
                self.assertEqual(code, EXIT_OK, payload)
                path.unlink()
        self.assertEqual(effects[0], effects[1])


class DevinDesktopVerifyTests(ConnectApplyDevinDesktopCase):
    """B4.14/B4.15 — the host-evidence contract for devin-desktop."""

    def registered_config(self):
        return self.current_config(
            {"mcpServers": {MANAGED_SERVER_NAME: self.managed_entry()}}
        )

    def test_a_valid_proof_is_recorded_with_the_workspace_id(self):
        self.registered_config()
        self.record_devin_proof()
        stored = json.loads(self.verification_store().read_text(encoding="utf-8"))
        self.assertEqual(stored["workspace_id"], self.workspace_id)
        status, record, _ = assess_verification(
            self.repo, "devin-desktop", launch_fingerprint(self.launch())
        )
        self.assertEqual(status, STATUS_VALID)
        self.assertIsNotNone(record)
        code, payload, _ = self.run_json("check", "devin-desktop")
        self.assertEqual(code, EXIT_OK)
        verification = payload["verification"]
        self.assertEqual(verification["status"], STATUS_VALID)
        self.assertTrue(verification["locally_verified"])
        self.assertFalse(verification["independently_attested"])

    def test_an_explicit_null_workspace_id_is_stored_as_null(self):
        # The codex contract: an explicit JSON null is a deliberate
        # "no workspace identity" statement and round-trips as None.
        self.registered_config()
        proof = self.valid_proof()
        proof["workspace_id"] = None
        self.record_devin_proof(proof)
        stored = json.loads(self.verification_store().read_text(encoding="utf-8"))
        self.assertIn("workspace_id", stored)
        self.assertIsNone(stored["workspace_id"])
        status, record, _ = assess_verification(
            self.repo, "devin-desktop", launch_fingerprint(self.launch())
        )
        self.assertEqual(status, STATUS_VALID)
        self.assertIsNotNone(record)

    def test_a_fingerprint_mismatch_is_stale_not_valid(self):
        self.registered_config()
        self.record_devin_proof()
        status, _, reasons = assess_verification(
            self.repo, "devin-desktop", "0" * 64
        )
        self.assertEqual(status, STATUS_STALE_FINGERPRINT)
        self.assertTrue(any("launch contract" in reason for reason in reasons))

    def test_an_expired_proof_is_reported_honestly(self):
        self.registered_config()
        self.record_devin_proof()
        store = self.verification_store()
        data = json.loads(store.read_text(encoding="utf-8"))
        data["timestamp"] = "2001-01-01T00:00:00+00:00"
        store.write_text(json.dumps(data, indent=2), encoding="utf-8")
        status, _, _ = assess_verification(
            self.repo, "devin-desktop", launch_fingerprint(self.launch())
        )
        self.assertEqual(status, STATUS_EXPIRED)
        code, payload, _ = self.run_json("check", "devin-desktop")
        verification = payload["verification"]
        self.assertEqual(verification["status"], STATUS_EXPIRED)
        self.assertFalse(verification["locally_verified"])

    def test_a_forged_record_naming_another_host_is_rejected(self):
        self.registered_config()
        self.record_devin_proof()
        store = self.verification_store()
        data = json.loads(store.read_text(encoding="utf-8"))
        data["host"] = "claude"
        store.write_text(json.dumps(data, indent=2), encoding="utf-8")
        status, _, reasons = assess_verification(
            self.repo, "devin-desktop", launch_fingerprint(self.launch())
        )
        self.assertEqual(status, STATUS_INVALID)
        self.assertTrue(any("different host" in reason for reason in reasons))

    def test_a_proof_with_absolute_paths_is_rejected(self):
        self.registered_config()
        proof = self.valid_proof()
        proof["tools_visible"] = [str(self.home / "tool")]
        code, _, err = self.run_cli(
            "verify", "devin-desktop", "--proof", str(self.write_proof(proof))
        )
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("machine-local path", err)
        self.assertFalse(self.verification_store().exists())

    def test_credential_shaped_proof_keys_are_rejected(self):
        self.registered_config()
        for key in ("api_token", "oauth_secret", "password", "key"):
            with self.subTest(key=key):
                proof = self.valid_proof()
                proof[key] = "value"
                code, _, err = self.run_cli(
                    "verify",
                    "devin-desktop",
                    "--proof",
                    str(self.write_proof(proof)),
                )
                self.assertEqual(code, EXIT_ACTION_REQUIRED)
                self.assertIn("credential-shaped", err)
        self.assertFalse(self.verification_store().exists())


class DevinDesktopPortabilityTests(ConnectApplyDevinDesktopCase):
    """B4.19 — portable output and secret redaction on every surface."""

    def populate_secret(self):
        return self.current_config(
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

    def test_no_apply_check_or_verify_output_carries_a_path(self):
        self.populate_secret()
        proof_path = self.write_proof(self.valid_proof())
        for argv in (
            ("apply", "devin-desktop"),
            ("check", "devin-desktop"),
            ("verify", "devin-desktop", "--proof", str(proof_path)),
            ("rollback", "devin-desktop"),
            ("plan", "devin-desktop"),
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
            ("apply", "devin-desktop"),
            ("check", "devin-desktop"),
            ("verify", "devin-desktop", "--proof", str(proof_path)),
            ("rollback", "devin-desktop"),
            ("plan", "devin-desktop"),
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
        self.current_config({"mcpServers": {}})
        code, payload, _ = self.run_json("apply", "devin-desktop", "--reveal-paths")
        self.assertEqual(code, EXIT_OK)
        self.assertIn(str(self.home), payload["real_config_path"])


class DevinDesktopNonInterferenceTests(ConnectApplyDevinDesktopCase):
    """B4.20 — a devin apply never touches another host's config."""

    def populate_other_hosts(self):
        self.write_home(
            ".claude.json",
            content={
                "projects": {
                    str(self.root).replace("/", "\\")
                    if os.name == "nt"
                    else str(self.root): {"mcpServers": {"c7": {"command": "npx", "args": []}}}
                }
            },
        )
        self.write_home(
            ".config", "opencode", "opencode.json",
            content={"mcp": {"engram": {"type": "local", "command": ["engram", "mcp"]}}},
        )
        self.write_home(
            ".codex",
            "config.toml",
            content='[mcp_servers.engram]\ncommand = "engram"\nargs = ["mcp"]\n',
        )

    def test_devin_commands_never_touch_other_host_configs(self):
        self.populate_other_hosts()
        self.current_config({"mcpServers": {"engram": dict(_ENGRAM_ENTRY)}})
        self.legacy_config({"mcpServers": {"windsurf-era": {"command": "old", "args": []}}})
        home_before = self.snapshot(self.home)
        repo_before = set(self.snapshot(self.repo))
        proof_path = self.write_proof(self.valid_proof())

        self.assertEqual(self.run_json("apply", "devin-desktop")[0], EXIT_OK)
        self.assertEqual(self.run_json("check", "devin-desktop")[0], EXIT_OK)
        self.assertEqual(
            self.run_cli("verify", "devin-desktop", "--proof", str(proof_path))[0],
            EXIT_OK,
        )

        home_after = self.snapshot(self.home)
        changed = {
            name
            for name in set(home_before) | set(home_after)
            if home_before.get(name) != home_after.get(name)
        }
        devin_prefix = str(Path(".config") / "devin" / "mcp_config.json")
        for name in changed:
            self.assertTrue(
                name == devin_prefix or name.startswith(devin_prefix + "."),
                f"unexpected write outside the devin-desktop target: {name}",
            )
        for name in (
            ".claude.json",
            str(Path(".config") / "opencode" / "opencode.json"),
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

    def test_a_claude_apply_does_not_touch_the_devin_configs(self):
        self.populate_other_hosts()
        current = self.current_config({"mcpServers": {"engram": dict(_ENGRAM_ENTRY)}})
        legacy = self.legacy_config({"mcpServers": {}})
        current_before = current.read_bytes()
        legacy_before = legacy.read_bytes()
        code, _, _ = self.run_json("apply", "claude")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(current.read_bytes(), current_before)
        self.assertEqual(legacy.read_bytes(), legacy_before)


class DevinDesktopDoctorTests(ConnectApplyDevinDesktopCase):
    """B4.21 — the host-verification gate lists devin-desktop, evidence absent."""

    def test_doctor_lists_devin_desktop_with_absent_evidence_never_ready(self):
        self.current_config({"mcpServers": {}})
        code, _, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_OK)
        payload = self.run_doctor()
        rows = {
            row["connector_id"]: row
            for row in payload["routing"]["host_verification"]
        }
        self.assertIn("devin-desktop", rows)
        row = rows["devin-desktop"]
        self.assertTrue(row["config_present"])
        self.assertTrue(row["managed_registration"])
        self.assertEqual(row["verification_status"], STATUS_ABSENT)
        self.assertFalse(row["locally_verified"])
        self.assertFalse(row["independently_attested"])
        for value in row["stages"].values():
            self.assertIsNone(value)
        checks = {check["name"]: check for check in payload["checks"]}
        self.assertEqual(checks["Host verification"]["status"], WARN)
        self.assertIn("devin-desktop: absent", checks["Host verification"]["detail"])

    def test_check_surfaces_devin_desktop_in_the_per_host_rows(self):
        self.current_config({"mcpServers": {MANAGED_SERVER_NAME: self.managed_entry()}})
        code, payload, _ = self.run_json("check", "devin-desktop")
        self.assertEqual(code, EXIT_OK)
        hosts = payload["host_verification_sections"]
        self.assertIn("devin-desktop", hosts)
        section = hosts["devin-desktop"]
        self.assertEqual(section["status"], STATUS_ABSENT)
        self.assertFalse(section["locally_verified"])
        self.assertFalse(section["independently_attested"])
        self.assertEqual(section["evidence_class"], "none")
        self.record_devin_proof()
        code, payload, _ = self.run_json("check", "devin-desktop")
        self.assertEqual(code, EXIT_OK)
        section = payload["host_verification_sections"]["devin-desktop"]
        self.assertEqual(section["status"], STATUS_VALID)
        self.assertTrue(section["locally_verified"])
        self.assertEqual(section["evidence_class"], "local_operational")


if __name__ == "__main__":
    unittest.main()
