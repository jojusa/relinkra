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
from unittest import mock

from relinkra import cbm_support
from relinkra.identity import RepositoryIdentity, canonicalize_path
from relinkra.mcp_cli import (
    _resolve_cbm_wiring,
    build_parser,
    build_services,
)
from relinkra.registry import Registry
from relinkra.workspace_resolution import (
    resolve_registry_path,
    resolve_workspace_root,
)

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
        # Isolate the per-user managed location: a real binary installed
        # by `relinkra cbm setup` on this machine would otherwise win the
        # documented discovery order and make the test machine-dependent.
        isolated_root = self.root / "isolated-data-root"
        isolated_root.mkdir()
        with mock.patch.object(
            cbm_support,
            "relinkra_data_root",
            lambda environ=None: str(isolated_root),
        ):
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


class RuntimeBindingResolutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="relinkra-binding-")
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.explicit = base / "explicit"
        self.env_root = base / "environment"
        self.cwd_root = base / "cwd"
        for root in (self.explicit, self.env_root, self.cwd_root):
            (root / ".git").mkdir(parents=True)

    def test_workspace_precedence_is_explicit_then_environment_then_cwd(self):
        nested = self.explicit / "src" / "deep"
        nested.mkdir(parents=True)
        result = resolve_workspace_root(
            str(nested),
            environ={"RELINKRA_WORKSPACE_ROOT": str(self.env_root)},
            cwd=str(self.cwd_root),
        )
        self.assertEqual(result.root, canonicalize_path(str(self.explicit)))
        self.assertEqual(result.source, "explicit")

        result = resolve_workspace_root(
            None,
            environ={"RELINKRA_WORKSPACE_ROOT": str(self.env_root)},
            cwd=str(self.cwd_root),
        )
        self.assertEqual(result.root, canonicalize_path(str(self.env_root)))
        self.assertEqual(result.source, "environment")

        result = resolve_workspace_root(None, environ={}, cwd=str(self.cwd_root))
        self.assertEqual(result.root, canonicalize_path(str(self.cwd_root)))
        self.assertEqual(result.source, "cwd")

    def test_git_file_and_outside_git_are_fail_closed(self):
        worktree = Path(self.tmp.name) / "worktree"
        (worktree / ".git").parent.mkdir(parents=True)
        (worktree / ".git").write_text(
            "gitdir: /shared/main/.git/worktrees/worktree\n",
            encoding="utf-8",
        )
        nested = worktree / "src"
        nested.mkdir()
        result = resolve_workspace_root(None, environ={}, cwd=str(nested))
        self.assertEqual(result.root, canonicalize_path(str(worktree)))

        outside = Path(self.tmp.name) / "outside"
        outside.mkdir()
        result = resolve_workspace_root(None, environ={}, cwd=str(outside))
        self.assertIsNone(result.root)
        self.assertEqual(result.source, "cwd")
        self.assertIn("git", result.error.lower())

        invalid_explicit = Path(self.tmp.name) / "not-a-repository"
        result = resolve_workspace_root(
            str(invalid_explicit),
            environ={"RELINKRA_WORKSPACE_ROOT": str(self.cwd_root)},
            cwd=str(self.cwd_root),
        )
        self.assertIsNone(result.root)
        self.assertEqual(result.source, "explicit")
        self.assertIn("workspace root", result.error.lower())

    def test_registry_precedence_and_root_relative_default(self):
        explicit = Path(self.tmp.name) / "explicit-registry.json"
        env = Path(self.tmp.name) / "environment-registry.json"
        cwd = Path(self.tmp.name) / "unrelated-cwd"
        cwd.mkdir()

        self.assertEqual(
            resolve_registry_path(
                str(explicit),
                str(self.explicit),
                environ={"RELINKRA_REGISTRY": str(env)},
                cwd=str(cwd),
            ),
            canonicalize_path(str(explicit)),
        )
        self.assertEqual(
            resolve_registry_path(
                None,
                str(self.explicit),
                environ={"RELINKRA_REGISTRY": str(env)},
                cwd=str(cwd),
            ),
            canonicalize_path(str(env)),
        )
        self.assertEqual(
            resolve_registry_path(
                None, str(self.explicit), environ={}, cwd=str(cwd)
            ),
            os.path.join(
                canonicalize_path(str(self.explicit)),
                ".relinkra",
                "registry.json",
            ),
        )
        self.assertIsNone(resolve_registry_path(None, None, environ={}, cwd=str(cwd)))

    def test_build_services_uses_resolved_root_and_registry(self):
        nested = self.explicit / "src"
        nested.mkdir()
        args = build_parser().parse_args(["--workspace-root", str(nested)])
        with mock.patch.object(
            __import__("relinkra.mcp_cli", fromlist=["_resolve_cbm_wiring"]),
            "_resolve_cbm_wiring",
            return_value=(None, None, None),
        ):
            services = build_services(args)
        self.assertEqual(
            services.config.workspace_root, canonicalize_path(str(self.explicit))
        )
        self.assertEqual(
            services.config.registry_path,
            os.path.join(
                canonicalize_path(str(self.explicit)),
                ".relinkra",
                "registry.json",
            ),
        )

    def test_outside_git_keeps_server_binding_unresolved_without_creating_state(self):
        outside = Path(self.tmp.name) / "outside-server"
        outside.mkdir()
        args = build_parser().parse_args([])
        module = __import__("relinkra.mcp_cli", fromlist=["_resolve_cbm_wiring"])
        with mock.patch.object(
            module, "_resolve_cbm_wiring", return_value=(None, None, None)
        ):
            services = build_services(args, environ={}, cwd=str(outside))
        self.assertIsNone(services.config.workspace_root)
        self.assertIsNone(services.config.registry_path)
        self.assertTrue(services.config.workspace_resolution_error)
        self.assertFalse((outside / ".relinkra").exists())

if __name__ == "__main__":
    unittest.main()
