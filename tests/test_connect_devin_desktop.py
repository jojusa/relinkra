"""Tests for the Devin Desktop connector discovery contract (R4C.1E).

Gate A opened READ-ONLY readiness for the current product: the connector
now declares the CLI-documented workspace scopes (``.devin/``), the
observed Windows app profile and the CLI-documented user config home,
ahead of the two legacy Windsurf/Codeium files. Gate B opened the write
path after Gate B1 machine evidence proved the mirror semantics
(PROVEN_MULTI_SOURCE): the authoritative user-scope write target on
Windows is the product's own ``%APPDATA%/Devin/mcp_config.json`` (= the
CLI user scope), and the legacy paths are watched one-way import
sources, evidence-only and never write targets.

Every test drives the real CLI through ``main(argv)`` or the real
engine against a fixture home plus a fake repository, with host
discovery monkeypatched the same way the other per-host suites do.
Nothing on the machine running the suite is read or written. APPDATA
cases are Windows-conditional because ``env.app_data`` returns ``None``
elsewhere by design.
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

from relinkra import connect_cli, product_cli
from relinkra.backend_detection import (
    NAMING_CURRENT,
    NAMING_LEGACY,
    survey_hosts,
)
from relinkra.connector import MANAGED_SERVER_NAME, iter_strings
from relinkra.connector_apply import classify_server_entry
from relinkra.connectors import (
    DEVIN_DESKTOP,
    SERVER_MODULE,
    build_plan,
    inspect_connector,
    is_managed_entry,
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

_SECRET = "sk-live-DEVIN-DO-NOT-LEAK-0123456789"

_SYSTEM = SYSTEM_WINDOWS if os.name == "nt" else SYSTEM_LINUX


class DevinDesktopCase(unittest.TestCase):
    """A fake repository plus a fixture home, discovery monkeypatched."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="relinkra-connect-devin-")
        self.addCleanup(self._temp.cleanup)
        base = Path(self._temp.name)
        self.home = base / "home"
        self.home.mkdir()
        self.appdata = base / "appdata"
        self.repo = base / "repo"
        (self.repo / ".git").mkdir(parents=True)
        self.root = self.repo.resolve()
        self.installed = set()
        self.env_vars = {}
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
                system=_SYSTEM,
                home=outer.home,
                env=dict(outer.env_vars),
                workspace_root=Path(workspace_root) if workspace_root else None,
                which=lambda name: (
                    "/usr/bin/" + name if name in outer.installed else None
                ),
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
            which=lambda name: "/usr/bin/" + name if name in self.installed else None,
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

    def legacy_config(self, content):
        return self.write_home(
            ".codeium", "windsurf", "mcp_config.json", content=content
        )

    def legacy_next_config(self, content):
        return self.write_home(
            ".codeium", "windsurf-next", "mcp_config.json", content=content
        )

    def appdata_config(self, content):
        self.env_vars["APPDATA"] = str(self.appdata)
        path = self.appdata / "Devin" / "mcp_config.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        text = content if isinstance(content, str) else json.dumps(content, indent=2)
        path.write_bytes(text.encode("utf-8"))
        return path

    def config_home_config(self, content):
        return self.write_home(
            ".config", "devin", "mcp_config.json", content=content
        )

    def workspace_local_config(self, content):
        return self.write_repo(".devin", "mcp_config.local.json", content=content)

    def workspace_project_config(self, content):
        return self.write_repo(".devin", "mcp_config.json", content=content)

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

    def naming(self):
        hosts = {host.connector_id: host for host in survey_hosts(self.env())}
        return hosts["devin-desktop"].naming

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


class DiscoveryContractTests(DevinDesktopCase):
    def test_no_installation_reports_not_installed(self):
        code, payload, _ = self.run_json("inspect", "devin-desktop")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(payload["discovery_status"], "not_installed")
        self.assertEqual(payload["registration_state"], "absent")

    def test_executable_without_config_reports_config_missing(self):
        self.installed.add("devin")
        code, payload, _ = self.run_json("inspect", "devin-desktop")
        self.assertEqual(payload["discovery_status"], "config_missing")

    @unittest.skipUnless(os.name == "nt", "env.app_data is None off Windows")
    def test_current_product_only_targets_the_app_profile(self):
        self.appdata_config({"mcpServers": {}})
        code, payload, _ = self.run_json("inspect", "devin-desktop")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(payload["discovery_status"], "discovered")
        self.assertEqual(payload["active_location_id"], "devin_user_appdata_mcp")
        self.assertEqual(payload["display_name"], "Devin Desktop")
        self.assertEqual(self.naming(), NAMING_CURRENT)

    def test_current_product_only_targets_the_config_home_user_scope(self):
        self.config_home_config({"mcpServers": {}})
        code, payload, _ = self.run_json("inspect", "devin-desktop")
        self.assertEqual(payload["discovery_status"], "discovered")
        self.assertEqual(payload["active_location_id"], "devin_user_config_mcp")
        self.assertEqual(payload["display_name"], "Devin Desktop")
        self.assertEqual(self.naming(), NAMING_CURRENT)

    def test_legacy_windsurf_only_is_read_as_legacy_never_as_current(self):
        self.legacy_config({"mcpServers": {}})
        code, payload, _ = self.run_json("inspect", "devin-desktop")
        self.assertEqual(payload["discovery_status"], "discovered")
        self.assertEqual(payload["active_location_id"], "windsurf_user_mcp")
        self.assertEqual(self.naming(), NAMING_LEGACY)
        code, plan, _ = self.run_json("plan", "devin-desktop")
        self.assertNotIn("windsurf", plan["target_ref"])
        self.assertEqual(plan["target_ref"], "devin-desktop:devin_workspace_local_mcp")
        self.assertTrue(plan["apply_available"])

    def test_legacy_windsurf_next_only_is_read_as_legacy(self):
        self.legacy_next_config({"mcpServers": {}})
        code, payload, _ = self.run_json("inspect", "devin-desktop")
        self.assertEqual(payload["active_location_id"], "windsurf_next_mcp")
        self.assertEqual(self.naming(), NAMING_LEGACY)
        _, plan, _ = self.run_json("plan", "devin-desktop")
        self.assertNotIn("windsurf", plan["target_ref"])

    def test_current_and_legacy_present_prefers_the_current_product(self):
        self.config_home_config({"mcpServers": {}})
        legacy = self.legacy_config({"mcpServers": {}})
        before = legacy.read_bytes()
        code, payload, _ = self.run_json("inspect", "devin-desktop")
        self.assertEqual(payload["active_location_id"], "devin_user_config_mcp")
        self.assertEqual(self.naming(), NAMING_CURRENT)
        _, listing, _ = self.run_json("list")
        entry = next(
            item
            for item in listing["connectors"]
            if item["connector_id"] == "devin-desktop"
        )
        self.assertFalse(entry["capabilities"]["real_host_launch_proven"])
        _, plan, _ = self.run_json("plan", "devin-desktop")
        self.assertTrue(plan["apply_available"])
        self.assertEqual(legacy.read_bytes(), before)

    def test_stale_legacy_without_executable_is_never_ready(self):
        self.legacy_config({"mcpServers": {}})
        _, payload, _ = self.run_json("check", "devin-desktop")
        self.assertEqual(payload["registration_state"], "absent")
        self.assertFalse(payload["valid"])
        # Gate B: devin-desktop is apply-capable, so it gets its own
        # verification row — with evidence ABSENT, never inferred.
        section = payload["host_verification_sections"]["devin-desktop"]
        self.assertEqual(section["status"], "absent")
        self.assertFalse(section["locally_verified"])
        doctor = self.run_doctor()
        verification = next(
            (c for c in doctor["checks"] if c["name"] == "Host verification"), None
        )
        if verification is not None:
            self.assertIn("devin-desktop: absent", verification["detail"])
            self.assertEqual(verification["status"], WARN)


class PrecedenceTests(DevinDesktopCase):
    def test_workspace_local_shadows_workspace_project(self):
        self.workspace_project_config({"mcpServers": {"project": {"command": "p", "args": []}}})
        self.workspace_local_config({"mcpServers": {}})
        _, payload, _ = self.run_json("inspect", "devin-desktop")
        self.assertEqual(payload["active_location_id"], "devin_workspace_local_mcp")

    def test_workspace_project_shadows_the_user_scope(self):
        self.config_home_config({"mcpServers": {}})
        self.workspace_project_config({"mcpServers": {}})
        _, payload, _ = self.run_json("inspect", "devin-desktop")
        self.assertEqual(payload["active_location_id"], "devin_workspace_project_mcp")

    def test_workspace_scope_shadows_both_user_scopes(self):
        self.config_home_config({"mcpServers": {}})
        self.workspace_local_config({"mcpServers": {}})
        _, payload, _ = self.run_json("inspect", "devin-desktop")
        self.assertEqual(payload["active_location_id"], "devin_workspace_local_mcp")

    def test_another_workspaces_config_does_not_count_for_this_one(self):
        foreign = Path(self._temp.name) / "other-workspace"
        target = foreign / ".devin" / "mcp_config.json"
        target.parent.mkdir(parents=True)
        target.write_text('{"mcpServers": {}}', encoding="utf-8")
        _, payload, _ = self.run_json("inspect", "devin-desktop")
        self.assertEqual(payload["discovery_status"], "not_installed")


class AuthoritativeScopeTests(DevinDesktopCase):
    def test_a_managed_name_in_another_authoritative_scope_shadows(self):
        self.workspace_project_config({"mcpServers": {}})
        self.config_home_config(
            {"mcpServers": {MANAGED_SERVER_NAME: self.managed_entry()}}
        )
        code, payload, _ = self.run_json("check", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertEqual(payload["registration_state"], "conflict")
        self.assertTrue(any("shadows" in f for f in payload["findings"]))

    def test_an_unreadable_active_scope_fails_closed_never_absent(self):
        target = self.config_home_config({"mcpServers": {}})
        real_stat = Path.stat

        def deny(path, *args, **kwargs):
            if Path(str(path)) == target:
                raise PermissionError("permission denied")
            return real_stat(path, *args, **kwargs)

        with mock.patch("relinkra.host_discovery.Path.stat", deny):
            _, payload, _ = self.run_json("inspect", "devin-desktop")
            self.assertEqual(payload["discovery_status"], "config_unsupported")
            _, check, _ = self.run_json("check", "devin-desktop")
        self.assertEqual(check["registration_state"], "unknown")
        self.assertNotEqual(check["registration_state"], "absent")
        self.assertFalse(check["valid"])

    def test_an_unreadable_non_active_authoritative_scope_is_not_clean(self):
        # The workspace project scope wins the active slot and parses;
        # the user scope behind it is malformed. The fail-closed scan
        # must refuse to call the authoritative scopes clean.
        self.workspace_project_config({"mcpServers": {}})
        self.config_home_config("{ broken")
        code, payload, _ = self.run_json("check", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertEqual(payload["registration_state"], "unknown")
        self.assertTrue(
            any("authoritative" in f for f in payload["findings"]),
            payload["findings"],
        )


class ConfigShapeTests(DevinDesktopCase):
    def test_malformed_json_in_the_active_target_is_reported_not_crashed(self):
        self.config_home_config("{ broken")
        code, payload, _ = self.run_json("inspect", "devin-desktop")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(payload["discovery_status"], "config_malformed")
        self.assertTrue(payload["warnings"])
        code, check, _ = self.run_json("check", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertEqual(check["registration_state"], "unknown")

    def test_unknown_fields_are_tolerated_and_preserved(self):
        path = self.config_home_config(
            {
                "mcpServers": {
                    "context7": {
                        "command": "npx",
                        "args": ["-y", "c7"],
                        "unknownFlag": True,
                    }
                },
                "theme": "dark",
                "telemetry": {"enabled": False},
            }
        )
        before = path.read_bytes()
        _, payload, _ = self.run_json("inspect", "devin-desktop")
        self.assertEqual(payload["discovery_status"], "discovered")
        self.assertEqual(payload["registration_state"], "absent")
        self.run_json("plan", "devin-desktop")
        self.run_json("check", "devin-desktop")
        self.assertEqual(path.read_bytes(), before)


class RegistrationClassificationTests(DevinDesktopCase):
    def test_unrelated_servers_are_foreign_never_relinkra(self):
        self.config_home_config(
            {
                "mcpServers": {
                    "context7": {"command": "npx", "args": ["-y", "c7"]},
                    "engram": {"command": "engram", "args": ["mcp"]},
                }
            }
        )
        _, payload, _ = self.run_json("inspect", "devin-desktop")
        self.assertEqual(payload["registration_state"], "absent")
        hosts = {host.connector_id: host for host in survey_hosts(self.env())}
        backends = {item.backend for item in hosts["devin-desktop"].detections}
        self.assertNotIn("relinkra", backends)
        self.assertNotIn("cbm", backends)
        self.assertIn("engram", backends)

    def test_an_equivalent_entry_is_already_connected_for_this_workspace(self):
        self.config_home_config(
            {"mcpServers": {MANAGED_SERVER_NAME: self.managed_entry()}}
        )
        code, payload, _ = self.run_json("check", "devin-desktop")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertEqual(payload["registration_state"], "already_connected")
        self.assertTrue(payload["valid"])
        self.assertTrue(payload["matches_workspace"])

    def test_an_entry_for_another_workspace_does_not_match_this_one(self):
        entry = self.managed_entry()
        index = entry["args"].index("--workspace-root")
        entry["args"][index + 1] = str(Path(self._temp.name) / "elsewhere")
        self.config_home_config({"mcpServers": {MANAGED_SERVER_NAME: entry}})
        code, payload, _ = self.run_json("check", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertFalse(payload["matches_workspace"])
        self.assertFalse(payload["valid"])

    def test_unmanaged_lookalikes_are_conflicts_never_equivalent(self):
        lookalikes = {
            "wrong_module": {"command": "python", "args": ["-m", "relinkra.other"]},
            "wrapper_form": {
                "command": "python",
                "args": ["wrapper.py", "-m", SERVER_MODULE],
            },
            "module_slot_without_python": {
                "command": "node",
                "args": ["-m", SERVER_MODULE],
            },
            "missing_module_flag": {"command": "python", "args": [SERVER_MODULE]},
            "duplicated_module_flag": {
                "command": "python",
                "args": ["-m", SERVER_MODULE, "-m", SERVER_MODULE],
            },
            "module_in_a_shell_string": {
                "command": f"python -m {SERVER_MODULE}",
                "args": [],
            },
        }
        for name, entry in lookalikes.items():
            with self.subTest(shape=name):
                self.assertFalse(launches_relinkra(entry), name)
                self.config_home_config(
                    {"mcpServers": {MANAGED_SERVER_NAME: entry}}
                )
                _, payload, _ = self.run_json("check", "devin-desktop")
                self.assertEqual(payload["registration_state"], "conflict", name)
                self.assertNotEqual(
                    payload["registration_state"], "already_connected", name
                )
                (self.home / ".config" / "devin" / "mcp_config.json").unlink()

    def test_managed_but_diverging_entries_are_updates_never_equivalent(self):
        variants = {}
        wrong_registry = self.managed_entry()
        index = wrong_registry["args"].index("--registry")
        wrong_registry["args"][index + 1] = "wrong-registry.json"
        variants["wrong_registry"] = wrong_registry
        reordered = self.managed_entry()
        args = list(reordered["args"])
        root_at = args.index("--workspace-root")
        reg_at = args.index("--registry")
        reordered["args"] = (
            args[:root_at]
            + args[reg_at : reg_at + 2]
            + args[root_at : root_at + 2]
            + args[reg_at + 2 :]
        )
        variants["reordered_flags"] = reordered
        for name, entry in variants.items():
            with self.subTest(shape=name):
                self.assertTrue(is_managed_entry(entry), name)
                self.config_home_config(
                    {"mcpServers": {MANAGED_SERVER_NAME: entry}}
                )
                _, payload, _ = self.run_json("check", "devin-desktop")
                self.assertEqual(
                    payload["registration_state"], "needs_update", name
                )
                (self.home / ".config" / "devin" / "mcp_config.json").unlink()

    def test_windows_case_and_slash_variance_still_launches_relinkra(self):
        entry = {
            "command": r"C:\Python311\PYTHON.EXE",
            "args": ["-m", SERVER_MODULE, "--workspace-root", r"D:\Code\Repo"],
        }
        self.assertTrue(launches_relinkra(entry))
        self.assertTrue(is_managed_entry(entry))

    def test_direct_cbm_under_a_friendly_name_fails_closed(self):
        path = self.config_home_config(
            {
                "mcpServers": {
                    MANAGED_SERVER_NAME: {
                        "command": "python",
                        "args": ["-m", "codebase_memory_mcp"],
                    }
                }
            }
        )
        before = path.read_bytes()
        _, payload, _ = self.run_json("check", "devin-desktop")
        self.assertEqual(payload["registration_state"], "conflict")
        hosts = {host.connector_id: host for host in survey_hosts(self.env())}
        backends = {item.backend for item in hosts["devin-desktop"].detections}
        self.assertIn("cbm", backends)
        # Detected and reported, never auto-removed or rewritten.
        self.assertEqual(path.read_bytes(), before)

    def test_mixed_relinkra_and_cbm_tokens_classify_as_cbm(self):
        entry = {
            "command": "python",
            "args": ["-m", SERVER_MODULE, "codebase-memory-mcp"],
        }
        self.assertEqual(classify_server_entry(entry), "cbm")
        self.assertFalse(is_managed_entry(entry))
        self.config_home_config({"mcpServers": {MANAGED_SERVER_NAME: entry}})
        _, payload, _ = self.run_json("check", "devin-desktop")
        self.assertEqual(payload["registration_state"], "conflict")

    def test_current_looking_content_at_a_legacy_path_is_still_legacy(self):
        # Mutant probe: an identity swap. The content is a perfectly
        # current, equivalent registration — but it sits ONLY at the
        # legacy path, so the naming classification must stay legacy and
        # the plan must keep aiming at a current-product location.
        self.legacy_config({"mcpServers": {MANAGED_SERVER_NAME: self.managed_entry()}})
        self.assertEqual(self.naming(), NAMING_LEGACY)
        _, plan, _ = self.run_json("plan", "devin-desktop")
        self.assertNotIn("windsurf", plan["target_ref"])
        self.assertEqual(plan["target_ref"], "devin-desktop:devin_workspace_local_mcp")
        # The plan/check contract must agree: plan refuses the legacy
        # path as a target, so check must refuse to call the same file a
        # valid registration. ``registration_state`` stays truthful about
        # what the file contains; the legacy finding is what invalidates
        # it and forces a human decision.
        code, check, _ = self.run_json("check", "devin-desktop")
        self.assertEqual(code, EXIT_ACTION_REQUIRED, check)
        self.assertFalse(check["valid"])
        self.assertTrue(check["matches_workspace"])
        self.assertTrue(
            any("legacy" in f for f in check["findings"]), check["findings"]
        )


class SurfaceContractTests(DevinDesktopCase):
    def test_every_alias_resolves_to_the_canonical_connector(self):
        self.config_home_config({"mcpServers": {}})
        payloads = {}
        for name in ("devin-desktop", "windsurf", "codeium", "windsurf-next"):
            code, payload, _ = self.run_json("inspect", name)
            self.assertEqual(code, EXIT_OK, name)
            self.assertEqual(payload["connector_id"], "devin-desktop", name)
            self.assertEqual(payload["display_name"], "Devin Desktop", name)
            payloads[name] = payload
        self.assertEqual(payloads["windsurf"], payloads["devin-desktop"])
        self.assertEqual(payloads["codeium"], payloads["devin-desktop"])

    def test_bare_devin_is_an_error_not_a_guess(self):
        code, _, err = self.run_cli("inspect", "devin")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("devin-desktop", err)
        self.assertIn("devin-cloud", err)

    def test_alias_invocation_never_mislabels_the_product_as_windsurf(self):
        self.config_home_config({"mcpServers": {}})
        _, out, _ = self.run_cli("inspect", "windsurf")
        self.assertIn("Devin Desktop", out)
        _, listing, _ = self.run_json("list")
        entry = next(
            item
            for item in listing["connectors"]
            if item["connector_id"] == "devin-desktop"
        )
        self.assertEqual(entry["display_name"], "Devin Desktop")

    def test_devin_desktop_is_in_the_apply_capable_gate_with_absent_evidence(self):
        # Gate B: the connector is apply-capable, so check and doctor
        # list it in the host-verification gate — with evidence ABSENT
        # (WARN, never FAIL or READY) until a real host proof exists.
        self.config_home_config(
            {"mcpServers": {MANAGED_SERVER_NAME: self.managed_entry()}}
        )
        _, payload, _ = self.run_json("check", "devin-desktop")
        section = payload["host_verification_sections"]["devin-desktop"]
        self.assertEqual(section["status"], "absent")
        self.assertFalse(section["locally_verified"])
        self.assertFalse(section["independently_attested"])
        doctor = self.run_doctor()
        verification = next(
            (c for c in doctor["checks"] if c["name"] == "Host verification"), None
        )
        self.assertIsNotNone(verification)
        self.assertEqual(verification["status"], WARN)
        self.assertIn("devin-desktop: absent", verification["detail"])

    def test_apply_is_open_since_gate_b_and_writes_the_current_target(self):
        path = self.config_home_config({"mcpServers": {}})
        code, payload, _ = self.run_json("apply", "devin-desktop")
        self.assertEqual(code, EXIT_OK, payload)
        self.assertTrue(payload["write_succeeded"])
        self.assertEqual(payload["verification_stage"], "config_applied_host_unverified")
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn(MANAGED_SERVER_NAME, document["mcpServers"])

    def test_output_is_portable_and_secret_free(self):
        self.config_home_config(
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
        for argv in (
            ("inspect", "devin-desktop"),
            ("plan", "devin-desktop"),
            ("check", "devin-desktop"),
        ):
            for extra in ((), ("--json",)):
                with self.subTest(argv=argv, extra=extra):
                    code, out, err = self.run_cli(*argv, *extra)
                    self.assertNotEqual(code, EXIT_ERROR, (argv, extra, err))
                    self.assertNotIn(_SECRET, out)
                    self.assertNotIn(_SECRET, err)
                    self.assertNotIn(str(self.home), out)
                    self.assertNotIn(str(self.repo), out)
                    if extra:
                        for value in iter_strings(json.loads(out)):
                            self.assertFalse(contains_absolute_path(value), value)


class NonInterferenceTests(DevinDesktopCase):
    COMMANDS = (
        ("list",),
        ("inspect", "devin-desktop"),
        ("inspect", "windsurf"),
        ("plan", "devin-desktop"),
        ("check", "devin-desktop"),
        ("routing",),
    )

    def test_no_command_writes_to_any_host_config(self):
        self.config_home_config({"mcpServers": {"c7": {"command": "npx", "args": []}}})
        self.legacy_config({"mcpServers": {"engram": {"command": "engram", "args": []}}})
        self.workspace_project_config({"mcpServers": {}})
        before = self.snapshot(self.home)
        repo_files = self.snapshot(self.repo)
        for argv in self.COMMANDS:
            with self.subTest(argv=argv):
                self.run_cli(*argv)
                self.run_cli(*argv, "--json")
        self.run_doctor()
        self.assertEqual(self.snapshot(self.home), before)
        created = set(self.snapshot(self.repo)) - set(repo_files)
        self.assertFalse(
            [name for name in created if ".devin" in name],
            created,
        )

    def test_the_dot_windsurf_workflow_dir_is_never_a_config_candidate(self):
        target = self.repo / ".windsurf" / "workflows" / "sdd-new.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("# operator owned\n", encoding="utf-8")
        before = target.read_bytes()
        for location in DEVIN_DESKTOP.locations:
            self.assertNotIn(".windsurf", location.display_hint)
        self.run_json("list")
        _, payload, _ = self.run_json("inspect", "devin-desktop")
        self.assertEqual(payload["discovery_status"], "not_installed")
        self.assertEqual(target.read_bytes(), before)

    def test_the_connector_contract_outside_locations_is_unchanged(self):
        self.assertEqual(DEVIN_DESKTOP.connector_id, "devin-desktop")
        self.assertEqual(DEVIN_DESKTOP.host_type, "editor")
        self.assertEqual(DEVIN_DESKTOP.container_path, ("mcpServers",))
        self.assertEqual(
            DEVIN_DESKTOP.aliases, ("windsurf", "codeium", "windsurf-next")
        )
        self.assertTrue(DEVIN_DESKTOP.apply_available)
        self.assertEqual(
            DEVIN_DESKTOP.legacy_location_ids,
            ("windsurf_user_mcp", "windsurf_next_mcp"),
        )
        ids = [location.location_id for location in DEVIN_DESKTOP.locations]
        self.assertEqual(
            ids,
            [
                "devin_workspace_local_mcp",
                "devin_workspace_project_mcp",
                "devin_user_appdata_mcp",
                "devin_user_config_mcp",
                "windsurf_user_mcp",
                "windsurf_next_mcp",
            ],
        )
        flags = {loc.location_id: loc for loc in DEVIN_DESKTOP.locations}
        for location_id in ids[:4]:
            with self.subTest(location=location_id):
                self.assertTrue(flags[location_id].mcp_authoritative)
                self.assertFalse(flags[location_id].discovery_only)
        for location_id in ids[4:]:
            with self.subTest(location=location_id):
                self.assertFalse(flags[location_id].mcp_authoritative)
                self.assertFalse(flags[location_id].discovery_only)


if __name__ == "__main__":
    unittest.main()
