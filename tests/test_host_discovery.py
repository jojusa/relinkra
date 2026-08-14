"""Tests for bounded, read-only host discovery (R4B).

Location resolution is a pure function of an injected environment, so
Windows and POSIX semantics are both asserted here regardless of which
platform runs the suite. Only the probing tests touch a filesystem, and
they use a temporary directory.
"""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path, PurePosixPath, PureWindowsPath

from relinkra.connector import (
    PATH_MACHINE_LOCAL,
    PATH_WORKSPACE_LOCAL,
    SCOPE_USER,
    SCOPE_WORKSPACE,
    FORMAT_JSON,
)
from relinkra.connectors import CLAUDE, CODEX, DEVIN_DESKTOP, OPENCODE
from relinkra.host_discovery import (
    SYSTEM_DARWIN,
    SYSTEM_LINUX,
    SYSTEM_WINDOWS,
    DiscoveryEnvironment,
    LocationSpec,
    active_location,
    find_executable,
    path_flavour,
    probe,
    resolve_locations,
)


def windows_env(**kwargs) -> DiscoveryEnvironment:
    defaults = dict(
        system=SYSTEM_WINDOWS,
        home=PureWindowsPath(r"C:\Users\dev"),
        env={"APPDATA": r"C:\Users\dev\AppData\Roaming"},
        workspace_root=PureWindowsPath(r"D:\code\repo"),
        which=lambda name: None,
    )
    defaults.update(kwargs)
    return DiscoveryEnvironment(**defaults)


def posix_env(**kwargs) -> DiscoveryEnvironment:
    defaults = dict(
        system=SYSTEM_LINUX,
        home=PurePosixPath("/home/dev"),
        env={},
        workspace_root=PurePosixPath("/srv/code/repo"),
        which=lambda name: None,
    )
    defaults.update(kwargs)
    return DiscoveryEnvironment(**defaults)


def resolved(spec_tuple, env):
    return {spec.location_id: path for spec, path in resolve_locations(spec_tuple, env)}


class FlavourTests(unittest.TestCase):
    def test_flavour_follows_the_declared_system(self):
        self.assertTrue(path_flavour(SYSTEM_WINDOWS)("C:/x").is_absolute())
        self.assertFalse(path_flavour(SYSTEM_LINUX)("C:/x").is_absolute())
        self.assertTrue(path_flavour(SYSTEM_DARWIN)("/x/y").is_absolute())


class EnvironmentTests(unittest.TestCase):
    def test_windows_paths_use_backslashes(self):
        env = windows_env()
        self.assertEqual(
            str(env.home_path(".claude", "settings.json")),
            r"C:\Users\dev\.claude\settings.json",
        )

    def test_posix_paths_use_forward_slashes(self):
        env = posix_env()
        self.assertEqual(
            str(env.home_path(".claude", "settings.json")),
            "/home/dev/.claude/settings.json",
        )

    def test_xdg_config_home_is_honoured_when_absolute(self):
        env = posix_env(env={"XDG_CONFIG_HOME": "/custom/cfg"})
        self.assertEqual(str(env.config_home("opencode")), "/custom/cfg/opencode")

    def test_relative_xdg_config_home_is_ignored(self):
        # A relative value would resolve against whatever directory the
        # host happened to start Relinkra in.
        env = posix_env(env={"XDG_CONFIG_HOME": "relative/cfg"})
        self.assertEqual(str(env.config_home("opencode")), "/home/dev/.config/opencode")

    def test_empty_xdg_config_home_is_ignored(self):
        env = posix_env(env={"XDG_CONFIG_HOME": "   "})
        self.assertEqual(str(env.config_home("opencode")), "/home/dev/.config/opencode")

    def test_xdg_is_honoured_on_windows_too(self):
        # Real cross-platform agent CLIs place their config under
        # ~/.config on Windows as well.
        env = windows_env()
        self.assertEqual(
            str(env.config_home("opencode", "opencode.json")),
            r"C:\Users\dev\.config\opencode\opencode.json",
        )

    def test_appdata_is_windows_only(self):
        self.assertEqual(
            str(windows_env().app_data("opencode")),
            r"C:\Users\dev\AppData\Roaming\opencode",
        )
        self.assertIsNone(posix_env(env={"APPDATA": "/x"}).app_data("opencode"))

    def test_appdata_missing_from_environment(self):
        self.assertIsNone(windows_env(env={}).app_data("opencode"))

    def test_env_dir_requires_an_absolute_value(self):
        self.assertEqual(
            str(posix_env(env={"CODEX_HOME": "/opt/codex"}).env_dir("CODEX_HOME", "c.toml")),
            "/opt/codex/c.toml",
        )
        self.assertIsNone(
            posix_env(env={"CODEX_HOME": "codex"}).env_dir("CODEX_HOME", "c.toml")
        )
        self.assertIsNone(posix_env().env_dir("CODEX_HOME", "c.toml"))

    def test_absent_home_yields_no_user_paths(self):
        env = posix_env(home=None)
        self.assertIsNone(env.home_path(".claude"))
        self.assertIsNone(env.config_home("opencode"))

    def test_absent_workspace_yields_no_workspace_paths(self):
        self.assertIsNone(posix_env(workspace_root=None).workspace_path("opencode.json"))

    def test_current_reads_the_real_machine(self):
        env = DiscoveryEnvironment.current()
        self.assertIn(env.system, {SYSTEM_WINDOWS, SYSTEM_LINUX, SYSTEM_DARWIN})
        self.assertIsInstance(env.env, dict)


class ConnectorLocationTests(unittest.TestCase):
    def test_claude_windows_locations(self):
        paths = resolved(CLAUDE.locations, windows_env())
        self.assertEqual(
            str(paths["claude_user_settings"]),
            r"C:\Users\dev\.claude\settings.json",
        )
        self.assertEqual(str(paths["claude_user_config"]), r"C:\Users\dev\.claude.json")
        self.assertEqual(str(paths["claude_workspace_mcp"]), r"D:\code\repo\.mcp.json")

    def test_claude_posix_locations(self):
        paths = resolved(CLAUDE.locations, posix_env())
        self.assertEqual(
            str(paths["claude_user_settings"]), "/home/dev/.claude/settings.json"
        )
        self.assertEqual(
            str(paths["claude_workspace_settings_local"]),
            "/srv/code/repo/.claude/settings.local.json",
        )

    def test_opencode_appdata_location_only_exists_on_windows(self):
        self.assertIn("opencode_user_appdata", resolved(OPENCODE.locations, windows_env()))
        posix = resolved(OPENCODE.locations, posix_env())
        self.assertIsNone(posix["opencode_user_appdata"])

    def test_opencode_jsonc_siblings_resolve_beside_their_json_files(self):
        paths = resolved(OPENCODE.locations, posix_env())
        self.assertEqual(
            str(paths["opencode_user_config_jsonc"]),
            "/home/dev/.config/opencode/opencode.jsonc",
        )
        self.assertEqual(
            str(paths["opencode_workspace_jsonc"]),
            "/srv/code/repo/opencode.jsonc",
        )
        # Both are discovery-only authoritative scopes: scanned for direct
        # CBM, never the apply target, which stays the .json user config.
        flags = {loc.location_id: loc for loc in OPENCODE.locations}
        for location_id in ("opencode_user_config_jsonc", "opencode_workspace_jsonc"):
            with self.subTest(location=location_id):
                self.assertTrue(flags[location_id].discovery_only)
                self.assertTrue(flags[location_id].mcp_authoritative)
        self.assertTrue(flags["opencode_user_appdata"].discovery_only)
        self.assertTrue(flags["opencode_user_appdata"].mcp_authoritative)
        self.assertFalse(flags["opencode_user_config"].discovery_only)
        self.assertFalse(flags["opencode_user_config"].mcp_authoritative)

    def test_codex_home_override_wins(self):
        paths = resolved(CODEX.locations, posix_env(env={"CODEX_HOME": "/opt/codex"}))
        self.assertEqual(str(paths["codex_user_config"]), "/opt/codex/config.toml")

    def test_codex_falls_back_to_the_conventional_location(self):
        paths = resolved(CODEX.locations, posix_env())
        self.assertEqual(str(paths["codex_user_config"]), "/home/dev/.codex/config.toml")

    def test_windsurf_locations(self):
        paths = resolved(DEVIN_DESKTOP.locations, posix_env())
        self.assertEqual(
            str(paths["windsurf_user_mcp"]),
            "/home/dev/.codeium/windsurf/mcp_config.json",
        )
        self.assertEqual(
            str(paths["windsurf_next_mcp"]),
            "/home/dev/.codeium/windsurf-next/mcp_config.json",
        )

    def test_every_location_id_is_unique_across_connectors(self):
        seen = []
        for spec in (CLAUDE, OPENCODE, CODEX, DEVIN_DESKTOP):
            seen.extend(location.location_id for location in spec.locations)
        self.assertEqual(len(seen), len(set(seen)))

    def test_location_sets_are_bounded(self):
        # Discovery must never turn into a scan of the user's profile.
        for spec in (CLAUDE, OPENCODE, CODEX, DEVIN_DESKTOP):
            with self.subTest(connector=spec.connector_id):
                self.assertLessEqual(len(spec.locations), 6)

    def test_scope_drives_classification(self):
        for spec in (CLAUDE, OPENCODE, CODEX, DEVIN_DESKTOP):
            for location in spec.locations:
                with self.subTest(location=location.location_id):
                    expected = (
                        PATH_WORKSPACE_LOCAL
                        if location.scope == SCOPE_WORKSPACE
                        else PATH_MACHINE_LOCAL
                    )
                    self.assertEqual(location.classification, expected)


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="relinkra-discovery-")
        self.addCleanup(self._temp.cleanup)
        self.home = Path(self._temp.name)
        self.env = DiscoveryEnvironment(
            system=SYSTEM_LINUX if Path("/").exists() else SYSTEM_WINDOWS,
            home=self.home,
            env={},
            workspace_root=None,
            which=lambda name: None,
        )

    def spec(self, name="probe_target", *parts):
        return LocationSpec(
            location_id=name,
            scope=SCOPE_USER,
            config_format=FORMAT_JSON,
            display_hint="~/probe.json",
            build=lambda env, parts=parts or ("probe.json",): env.home_path(*parts),
        )

    def test_absent_file_is_reported_absent_but_readable(self):
        (location,) = probe((self.spec(),), self.env)
        self.assertFalse(location.exists)
        self.assertTrue(location.readable)
        self.assertIsNone(location.size_bytes)

    def test_present_file_reports_its_size(self):
        (self.home / "probe.json").write_text("{}", encoding="utf-8")
        (location,) = probe((self.spec(),), self.env)
        self.assertTrue(location.exists)
        self.assertEqual(location.size_bytes, 2)

    def test_directory_at_the_location_is_not_a_config(self):
        (self.home / "probe.json").mkdir()
        (location,) = probe((self.spec(),), self.env)
        self.assertFalse(location.exists)

    def test_inapplicable_locations_are_omitted(self):
        never = LocationSpec(
            location_id="never",
            scope=SCOPE_USER,
            config_format=FORMAT_JSON,
            display_hint="(n/a)",
            build=lambda env: None,
        )
        self.assertEqual(probe((never,), self.env), ())

    def test_probed_location_never_renders_its_path(self):
        (self.home / "probe.json").write_text("{}", encoding="utf-8")
        (location,) = probe((self.spec(),), self.env)
        payload = location.to_dict()
        self.assertNotIn("path", payload)
        self.assertEqual(payload["display_hint"], "~/probe.json")
        self.assertIn("path", location.to_machine_dict())

    def test_active_location_follows_declaration_order(self):
        (self.home / "second.json").write_text("{}", encoding="utf-8")
        specs = (
            self.spec("first", "first.json"),
            self.spec("second", "second.json"),
        )
        locations = probe(specs, self.env)
        self.assertEqual(active_location(locations).location_id, "second")

    def test_active_location_prefers_the_earlier_declaration(self):
        (self.home / "first.json").write_text("{}", encoding="utf-8")
        (self.home / "second.json").write_text("{}", encoding="utf-8")
        specs = (
            self.spec("first", "first.json"),
            self.spec("second", "second.json"),
        )
        self.assertEqual(active_location(probe(specs, self.env)).location_id, "first")

    def test_denied_stat_reports_the_location_unreadable(self):
        target = self.home / "probe.json"
        target.write_text("{}", encoding="utf-8")
        real_stat = Path.stat

        def denying_stat(self, *args, **kwargs):
            if self.name == "probe.json":
                raise PermissionError(13, "denied")
            return real_stat(self, *args, **kwargs)

        Path.stat = denying_stat
        try:
            (location,) = probe((self.spec(),), self.env)
        finally:
            Path.stat = real_stat
        self.assertFalse(location.exists)
        self.assertFalse(location.readable)

    def test_an_unreadable_candidate_still_becomes_active(self):
        # Otherwise a permissions problem is reported as "host not
        # installed", sending the user to reinstall instead of to chmod.
        (self.home / "second.json").write_text("{}", encoding="utf-8")
        real_stat = Path.stat

        def denying_stat(self, *args, **kwargs):
            if self.name == "first.json":
                raise PermissionError(13, "denied")
            return real_stat(self, *args, **kwargs)

        specs = (self.spec("first", "first.json"), self.spec("second", "second.json"))
        Path.stat = denying_stat
        try:
            locations = probe(specs, self.env)
        finally:
            Path.stat = real_stat
        self.assertEqual(active_location(locations).location_id, "first")

    def test_opencode_appdata_candidate_is_scanned_but_never_active(self):
        appdata = next(
            location
            for location in OPENCODE.locations
            if location.location_id == "opencode_user_appdata"
        )
        appdata = replace(
            appdata,
            build=lambda env: env.home_path("appdata-opencode.json"),
        )
        (self.home / "appdata-opencode.json").write_text("{}", encoding="utf-8")
        user = next(
            location
            for location in OPENCODE.locations
            if location.location_id == "opencode_user_config"
        )
        locations = probe((user, appdata), self.env)
        self.assertTrue(locations[1].exists)
        self.assertTrue(locations[1].discovery_only)
        self.assertIsNone(active_location(locations))

    def test_active_location_is_none_when_nothing_exists(self):
        self.assertIsNone(active_location(probe((self.spec(),), self.env)))


class ExecutableTests(unittest.TestCase):
    def test_first_match_wins(self):
        env = posix_env(which=lambda name: "/usr/bin/" + name if name == "b" else None)
        self.assertEqual(find_executable(env, ("a", "b", "c")), "/usr/bin/b")

    def test_no_match_returns_none(self):
        self.assertIsNone(find_executable(posix_env(), ("a", "b")))

    def test_empty_name_list_returns_none(self):
        self.assertIsNone(find_executable(posix_env(), ()))

    def test_a_raising_which_does_not_escape(self):
        def broken(name):
            raise OSError("PATH is unreadable")

        self.assertIsNone(find_executable(posix_env(which=broken), ("a",)))


if __name__ == "__main__":
    unittest.main()
