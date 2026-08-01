"""Tests for relinkra.mcp_cli server-side CBM wiring resolution.

The MCP entry point must wire CBM exactly like the product CLI: explicit
flags/environment win, otherwise the registry's workspace record plus
the Relinkra-managed binary locations — never agent configuration.
Identity defaults (--project-id/--workspace-id) stay untouched.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from relinkra.identity import RepositoryIdentity
from relinkra.mcp_cli import _resolve_cbm_wiring
from relinkra.registry import Registry

REALISTIC_RECORD = {
    "binary": {"sha256": "0" * 64, "version": "0.9.0"},
    "cache_dir": os.path.join(".codebase-memory", "cache"),
    "project_name": "C-Desarrollos-example-example",
}


class CbmWiringCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="relinkra-mcpcli-")
        self.root = Path(self._tmp.name)
        (self.root / ".relinkra").mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def _write_workspace(self, cbm_record=None):
        registry = Registry(str(self.root / ".relinkra" / "registry.json"))
        workspace = registry.register_workspace(
            str(self.root),
            RepositoryIdentity(
                kind="remote", value="remote://git/example/x", trust="strong"
            ),
            cbm=cbm_record,
        )
        # The pinned config carries the id the registry assigned, exactly
        # like `relinkra init` writes it.
        (self.root / ".relinkra" / "config.json").write_text(
            json.dumps(
                {
                    "config_version": 1,
                    "project_id": workspace.project_id,
                    "workspace_id": workspace.workspace_id,
                }
            ),
            encoding="utf-8",
        )
        return workspace

    def test_no_workspace_root_is_passthrough(self):
        self.assertEqual(
            _resolve_cbm_wiring(None, "bin", "cache", "name"),
            ("bin", "cache", "name"),
        )

    def test_explicit_flags_win_over_record(self):
        self._write_workspace(dict(REALISTIC_RECORD))
        result = _resolve_cbm_wiring(str(self.root), "bin", "cache", "name")
        self.assertEqual(result, ("bin", "cache", "name"))

    def test_record_supplies_project_name_and_cache_dir(self):
        self._write_workspace(dict(REALISTIC_RECORD))
        _bin, cache_dir, project_name = _resolve_cbm_wiring(
            str(self.root), None, None, None
        )
        self.assertEqual(project_name, REALISTIC_RECORD["project_name"])
        expected = os.path.realpath(
            os.path.join(str(self.root), ".codebase-memory", "cache")
        )
        self.assertEqual(cache_dir, expected)

    def test_escaping_cache_dir_disables_resolved_cbm_only(self):
        record = dict(REALISTIC_RECORD)
        record["cache_dir"] = os.path.join("..", "outside")
        self._write_workspace(record)
        # A RESOLVED binary came from the same untrusted source family as
        # the hostile record, so the escape disables CBM outright...
        cbm_bin, cache_dir, _name = _resolve_cbm_wiring(
            str(self.root), None, None, None
        )
        self.assertIsNone(cbm_bin)
        self.assertIsNone(cache_dir)
        # ...but an EXPLICIT flag never came from the record and wins.
        cbm_bin, cache_dir, _name = _resolve_cbm_wiring(
            str(self.root), "explicit-bin", None, None
        )
        self.assertEqual(cbm_bin, "explicit-bin")
        self.assertIsNone(cache_dir)

    def test_absent_record_keeps_managed_binary_resolution(self):
        self._write_workspace(cbm_record=None)
        managed = self.root / ".codebase-memory" / "bin"
        managed.mkdir(parents=True)
        exe = managed / "codebase-memory-mcp.exe"
        exe.write_bytes(b"fake")
        cbm_bin, cache_dir, project_name = _resolve_cbm_wiring(
            str(self.root), None, None, None
        )
        self.assertEqual(cbm_bin, str(exe))
        self.assertIsNone(cache_dir)
        self.assertIsNone(project_name)

    def test_missing_workspace_config_leaves_record_unused(self):
        # No config.json: there is no pinned workspace id, so the record
        # lookup is skipped but managed binary resolution still applies.
        cbm_bin, cache_dir, project_name = _resolve_cbm_wiring(
            str(self.root), None, None, None
        )
        self.assertIsNone(cache_dir)
        self.assertIsNone(project_name)


if __name__ == "__main__":
    unittest.main()
