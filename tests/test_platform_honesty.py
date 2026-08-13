"""Platform-honesty guards (R5B).

Proves, against the REAL implementation, that Relinkra never claims
certification it does not hold: non-Windows CBM platforms stop at a WARN
before execution, the MCP surface exposes no direct CBM tools, the
unsupported connector declares nothing, and a tomllib-less interpreter
fails honestly instead of guessing TOML state.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path, PurePath

from relinkra import cbm_support, connectors, mcp_server, toml_edit
from relinkra.connector import (
    REGISTRATION_UNKNOWN,
    SUPPORT_EXPERIMENTAL,
    SUPPORT_SUPPORTED,
    SUPPORT_UNSUPPORTED,
)
from relinkra.host_discovery import (
    SYSTEM_LINUX,
    SYSTEM_WINDOWS,
    DiscoveryEnvironment,
)

NON_WINDOWS_TAGS = ("linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64")

EXPECTED_MCP_TOOLS = {
    "relinkra_project_resolve",
    "relinkra_context_get",
    "relinkra_memory_search",
    "relinkra_memory_save",
    "relinkra_code_resolve",
    "relinkra_git_context",
    "relinkra_handoff_create",
    "relinkra_handoff_get",
}


class NonWindowsCbmTrustTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.root = self._temp.name
        self.binary = os.path.join(self.root, "fake-cbm")
        with open(self.binary, "wb") as handle:
            handle.write(b"not a certified cbm binary\n")

    def test_non_windows_platforms_have_no_certified_provenance(self):
        for tag in NON_WINDOWS_TAGS:
            self.assertNotIn(tag, cbm_support.CERTIFIED_CBM_BINARIES)

    def test_trust_ladder_warns_and_never_executes(self):
        for tag in NON_WINDOWS_TAGS:
            with self.subTest(platform=tag):
                original = cbm_support.platform_tag
                cbm_support.platform_tag = lambda: tag
                calls = []

                def spy_factory(**kwargs):
                    calls.append(kwargs)
                    raise AssertionError(
                        "adapter factory must not be called without provenance"
                    )

                try:
                    stages = cbm_support.evaluate_cbm_trust(
                        self.root, None, self.binary, adapter_factory=spy_factory
                    )
                finally:
                    cbm_support.platform_tag = original

                self.assertEqual(calls, [])
                by_name = {stage.name: stage for stage in stages}
                self.assertEqual(
                    by_name["CBM provenance"].status, cbm_support.STAGE_WARN
                )
                self.assertIn(tag, by_name["CBM provenance"].detail)
                detail = by_name["CBM provenance"].detail
                self.assertNotIn(
                    "matches certified", detail,
                    "provenance must never certify a non-Windows binary",
                )
                # The ladder stops BEFORE any execution stage.
                for execution_stage in (
                    "CBM version",
                    "CBM index",
                    "CBM graph",
                    "CBM query",
                ):
                    self.assertNotIn(execution_stage, by_name)


class WindowsPinGuardTests(unittest.TestCase):
    def test_windows_amd64_certified_entry_is_pinned(self):
        entry = cbm_support.CERTIFIED_CBM_BINARIES.get("windows-amd64")
        self.assertIsNotNone(entry, "the windows-amd64 pin must exist")
        self.assertEqual(entry["version"], cbm_support.CERTIFIED_CBM_VERSION)
        sha = entry["sha256"]
        self.assertEqual(len(sha), 64)
        int(sha, 16)
        zip_sha = entry["release_zip_sha256"]
        self.assertEqual(len(zip_sha), 64)
        int(zip_sha, 16)
        self.assertTrue(entry["release_url"].startswith("https://"))


class McpSurfaceHonestyTests(unittest.TestCase):
    def test_tool_roster_is_the_documented_surface(self):
        # The 8 domain tools plus relinkra_health (a diagnostics endpoint,
        # not a CBM tool); anything beyond that set is a surface change
        # this guard exists to catch.
        names = {tool["name"] for tool in mcp_server.TOOLS}
        self.assertEqual(names, EXPECTED_MCP_TOOLS | {"relinkra_health"})

    def test_no_tool_exposes_cbm_directly(self):
        for tool in mcp_server.TOOLS:
            name = tool["name"].lower()
            self.assertNotIn("cbm", name)
            self.assertNotIn("codebase", name)


class ConnectorHonestyTests(unittest.TestCase):
    def test_devin_cloud_is_unsupported_and_declares_no_locations(self):
        self.assertIs(connectors.DEVIN_CLOUD.support_status, SUPPORT_UNSUPPORTED)
        self.assertEqual(connectors.DEVIN_CLOUD.locations, ())
        self.assertFalse(connectors.DEVIN_CLOUD.apply_available)
        self.assertFalse(connectors.DEVIN_CLOUD.format_verified)

    def test_support_vocabulary_has_no_runtime_certified_state(self):
        allowed = {SUPPORT_SUPPORTED, SUPPORT_EXPERIMENTAL, SUPPORT_UNSUPPORTED}
        for spec in connectors.CONNECTORS:
            self.assertIn(spec.support_status, allowed, spec.connector_id)


class TomllibHonestyTests(unittest.TestCase):
    """A tomllib-less interpreter (3.9/3.10) fails honestly, never guesses."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.home = Path(self._temp.name) / "home"
        (self.home / ".codex").mkdir(parents=True)
        (self.home / ".codex" / "config.toml").write_text(
            '[mcp_servers.other]\ncommand = "x"\n', encoding="utf-8"
        )
        self._had_tomllib = sys.modules.get("tomllib", False)
        sys.modules["tomllib"] = None  # import now raises ImportError
        self.addCleanup(self._restore_tomllib)

    def _restore_tomllib(self):
        if self._had_tomllib is False:
            sys.modules.pop("tomllib", None)
        else:
            sys.modules["tomllib"] = self._had_tomllib

    def test_load_toml_returns_none(self):
        self.assertIsNone(connectors._load_toml('[a]\nb = 1\n'))

    def test_toml_edit_raises_the_fail_honest_sentinel(self):
        with self.assertRaises(toml_edit.TomlParserUnavailableError):
            toml_edit.parse_toml_document('[a]\nb = 1\n')

    def test_codex_inspection_reports_unknown_not_absent(self):
        env = DiscoveryEnvironment(
            system=SYSTEM_WINDOWS if os.name == "nt" else SYSTEM_LINUX,
            home=PurePath(self.home),
            env={},
            workspace_root=None,
            which=lambda name: None,
        )
        result = connectors.inspect_connector(connectors.CODEX, env)
        self.assertEqual(result.registration_state, REGISTRATION_UNKNOWN)
        codes = [warning.code for warning in result.warnings]
        self.assertIn("toml_parser_unavailable", codes)


class TomlDepthHonestyTests(unittest.TestCase):
    """The too-deep verdict is deterministic, not parser-stack luck (R5C)."""

    def test_deeply_nested_toml_is_malformed_on_every_platform(self):
        try:
            import tomllib  # noqa: F401
        except ImportError:
            self.skipTest("tomllib unavailable on this interpreter")
        # 200 nested tables: a parser with a generous C stack may SURVIVE
        # this (the Linux/macOS runners did for JSON); the verdict must be
        # MalformedConfigError everywhere via the explicit depth guard.
        payload = "".join(f"[{'a.' * i}a]\n" for i in range(1, 201))
        with self.assertRaises(toml_edit.MalformedConfigError):
            toml_edit.parse_toml_document(payload)


if __name__ == "__main__":
    unittest.main()
