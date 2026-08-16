"""R5E.2B PART B — mocked product-CLI coverage for the cbm family.

Drives ``relinkra cbm status/index/refresh`` through
``product_cli.main`` against a real temp git repository, with every CBM
seam mocked: binary resolution, platform provenance, the index run,
mapping registration, and freshness classification. The real-binary
cycle proof lives in ``tests/test_cbm_indexing.py`` (gated).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:  # discovery (`-s tests`) puts tests/ on sys.path; direct runs may not
    import git_fixtures
except ImportError:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import git_fixtures

from relinkra import cbm_indexing, cbm_support, product_cli
from relinkra.product_cli import EXIT_ACTION_REQUIRED, EXIT_ERROR, EXIT_OK

BIN = "C:/fake/codebase-memory-mcp.exe"
PROJECT = "C-fixture-repo"
CERTIFIED = cbm_support.CERTIFIED_CBM_BINARIES["windows-amd64"]
CERTIFIED_SHA = CERTIFIED["sha256"]
BAD_SHA = "ff" * 32

READY = {"state": "READY", "committed_drift": False, "worktree_drift": False}
STALE_WORKTREE = {
    "state": "STALE_WORKTREE",
    "committed_drift": False,
    "worktree_drift": True,
}
UNKNOWN = {"state": "UNKNOWN", "committed_drift": None, "worktree_drift": None}


class CBMCLITestCase(unittest.TestCase):
    """A real temp git repo; the CLI's CBM seams fully mocked."""

    def setUp(self):
        if shutil.which("git") is None:
            self.skipTest("git is required for the cbm CLI tests")
        tmp = tempfile.mkdtemp(prefix="rlk-cbm-cli-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.repo = git_fixtures.make_repo(os.path.join(tmp, "repo"))
        git_fixtures.commit_file(self.repo, "README.md", "hello\n", "initial")

    def run_cli(self, *argv, path=None):
        """Invoke the CLI, returning (exit_code, stdout, stderr)."""
        args = list(argv)
        if path is not False:
            args += ["--path", str(path or self.repo)]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = product_cli.main(args)
            except SystemExit as exc:  # argparse usage errors exit 1
                code = int(exc.code)
        return code, out.getvalue(), err.getvalue()

    def happy_gate_patches(self, binary=BIN, sha=CERTIFIED_SHA):
        """Patches that make the binary resolve, the platform certified
        (windows-amd64, regardless of host), and the hash match."""
        return [
            mock.patch.object(
                product_cli.cbm_support,
                "resolve_cbm_binary",
                lambda root=None, environ=None: binary,
            ),
            mock.patch.object(
                product_cli.cbm_support, "platform_tag", lambda: "windows-amd64"
            ),
            mock.patch.object(
                product_cli.cbm_indexing, "platform_tag", lambda: "windows-amd64"
            ),
            mock.patch.object(
                product_cli.cbm_support, "_sha256_file", lambda path: sha
            ),
        ]

    def register_record(self):
        """Create a real registry record (pure registry + git, no CBM)."""
        cbm_indexing.register_mapping(
            str(product_cli.registry_path(Path(self.repo))),
            self.repo,
            PROJECT,
            ".codebase-memory/cache",
            "0.9.0",
            CERTIFIED_SHA,
        )


class CbmStatusTests(CBMCLITestCase):
    def test_missing_when_never_indexed_human_and_json(self):
        freshness = mock.Mock()
        with contextlib.ExitStack() as stack:
            for patch in self.happy_gate_patches():
                stack.enter_context(patch)
            stack.enter_context(
                mock.patch.object(cbm_indexing, "freshness_state", freshness)
            )
            code, out, err = self.run_cli("cbm", "status")
            self.assertEqual(code, EXIT_OK, err)
            self.assertIn("CBM: AVAILABLE", out)
            self.assertIn("Index: MISSING", out)
            self.assertIn("Next: relinkra cbm index", out)
            # No record means the backend is never probed: the state is
            # derived without executing anything.
            freshness.assert_not_called()
            code, out, _ = self.run_cli("cbm", "status", "--json")
            self.assertEqual(code, EXIT_OK)
        payload = json.loads(out)
        self.assertEqual(
            set(payload),
            {"status", "project_id", "cbm", "freshness", "next_action"},
        )
        self.assertEqual(payload["status"], "MISSING")
        self.assertTrue(payload["project_id"].startswith("rlk_"))
        self.assertEqual(payload["cbm"], "available")
        self.assertIsNone(payload["freshness"]["committed_drift"])
        self.assertIsNone(payload["freshness"]["worktree_drift"])
        self.assertEqual(payload["next_action"], "relinkra cbm index")

    def test_untrusted_candidate_without_record_is_not_available(self):
        freshness = mock.Mock()
        with contextlib.ExitStack() as stack:
            for patch in self.happy_gate_patches(sha=BAD_SHA):
                stack.enter_context(patch)
            stack.enter_context(
                mock.patch.object(cbm_indexing, "freshness_state", freshness)
            )
            code, out, err = self.run_cli("cbm", "status")
            self.assertEqual(code, EXIT_OK, err)
            self.assertIn("CBM: UNAVAILABLE", out)
            self.assertNotIn("CBM: AVAILABLE", out)
            self.assertIn("unverified binary", out)
            freshness.assert_not_called()
            code, out, err = self.run_cli("cbm", "status", "--json")
            self.assertEqual(code, EXIT_OK, err)
        payload = json.loads(out)
        self.assertEqual(payload["status"], "UNAVAILABLE")
        self.assertEqual(payload["cbm"], "untrusted")

    def test_ready_omits_next_line(self):
        with contextlib.ExitStack() as stack:
            for patch in self.happy_gate_patches():
                stack.enter_context(patch)
            self.register_record()
            stack.enter_context(
                mock.patch.object(cbm_indexing, "freshness_state", mock.Mock(return_value=dict(READY)))
            )
            code, out, err = self.run_cli("cbm", "status")
        self.assertEqual(code, EXIT_OK, err)
        self.assertIn("Index: READY", out)
        self.assertNotIn("Next:", out)

    def test_stale_maps_to_refresh_human_and_json(self):
        stale_committed = {
            "state": "STALE_COMMITTED",
            "committed_drift": True,
            "worktree_drift": False,
        }
        with contextlib.ExitStack() as stack:
            for patch in self.happy_gate_patches():
                stack.enter_context(patch)
            self.register_record()
            # Worktree-only drift: no reindex can clear it (CBM reads
            # the git worktree), so Next says commit first.
            stack.enter_context(
                mock.patch.object(cbm_indexing, "freshness_state", mock.Mock(return_value=dict(STALE_WORKTREE)))
            )
            code, out, err = self.run_cli("cbm", "status")
            self.assertEqual(code, EXIT_OK, err)
            self.assertIn("Index: STALE", out)
            self.assertIn("commit your changes, then run 'relinkra cbm refresh'", out)
            # Committed-only drift: refresh is exactly the right action.
            stack.enter_context(
                mock.patch.object(cbm_indexing, "freshness_state", mock.Mock(return_value=dict(stale_committed)))
            )
            code, out, err = self.run_cli("cbm", "status")
            self.assertEqual(code, EXIT_OK, err)
            self.assertIn("Next: relinkra cbm refresh", out)
            code, out, _ = self.run_cli("cbm", "status", "--json")
            self.assertEqual(code, EXIT_OK)
        payload = json.loads(out)
        self.assertEqual(payload["status"], "STALE")
        self.assertTrue(payload["freshness"]["committed_drift"])
        self.assertFalse(payload["freshness"]["worktree_drift"])
        self.assertEqual(payload["next_action"], "relinkra cbm refresh")

    def test_unavailable_prints_optional_backend_line(self):
        freshness = mock.Mock(
            return_value={
                "state": cbm_indexing.UNAVAILABLE,
                "committed_drift": None,
                "worktree_drift": None,
            }
        )
        with mock.patch.object(
            product_cli.cbm_support,
            "resolve_cbm_binary",
            lambda root=None, environ=None: None,
        ), mock.patch.object(cbm_indexing, "freshness_state", freshness):
            code, out, err = self.run_cli("cbm", "status")
        self.assertEqual(code, EXIT_OK, err)
        self.assertIn("CBM: UNAVAILABLE", out)
        self.assertIn("Index: UNAVAILABLE", out)
        self.assertIn(
            "Optional backend unavailable; native agent tools remain "
            "available.",
            out,
        )
        self.assertNotIn("Next:", out)
        freshness.assert_called_once()  # still consulted, honestly reports UNAVAILABLE

    def test_untrusted_binary_refuses_without_executing(self):
        freshness = mock.Mock(
            return_value={
                "state": cbm_indexing.UNTRUSTED,
                "committed_drift": None,
                "worktree_drift": None,
            }
        )
        with mock.patch.object(cbm_indexing, "freshness_state", freshness):
            code, out, err = self.run_cli("cbm", "status")
            self.assertEqual(code, EXIT_OK, err)
            self.assertIn("refusing to execute an unverified binary", out)
            code, out, err = self.run_cli("cbm", "status", "--json")
        self.assertEqual(code, EXIT_OK, err)
        payload = json.loads(out)
        self.assertEqual(payload["cbm"], "untrusted")
        self.assertEqual(payload["status"], "UNAVAILABLE")
        self.assertEqual(payload["next_action"], "see docs/cbm-backend.md")

    def test_unsupported_platform_is_honest(self):
        with contextlib.ExitStack() as stack:
            for patch in self.happy_gate_patches():
                stack.enter_context(patch)
            for module in (product_cli.cbm_support, product_cli.cbm_indexing):
                stack.enter_context(
                    mock.patch.object(module, "platform_tag", lambda: "linux-amd64")
                )
            code, out, err = self.run_cli("cbm", "status")
        self.assertEqual(code, EXIT_OK, err)
        self.assertIn("CBM: UNSUPPORTED", out)
        self.assertIn("Index: UNSUPPORTED", out)
        self.assertIn("Optional backend unavailable", out)
        self.assertNotIn("Next:", out)

    def test_unknown_points_to_docs(self):
        with contextlib.ExitStack() as stack:
            for patch in self.happy_gate_patches():
                stack.enter_context(patch)
            self.register_record()
            stack.enter_context(
                mock.patch.object(cbm_indexing, "freshness_state", mock.Mock(return_value=dict(UNKNOWN)))
            )
            code, out, err = self.run_cli("cbm", "status")
        self.assertEqual(code, EXIT_OK, err)
        self.assertIn("Index: UNKNOWN", out)
        self.assertIn("Next: relinkra cbm refresh", out)

    def test_non_git_workspace_exits_two(self):
        plain = tempfile.mkdtemp(prefix="rlk-cbm-plain-")
        self.addCleanup(shutil.rmtree, plain, ignore_errors=True)
        code, out, err = self.run_cli("cbm", "status", path=plain)
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("Error:", err)

    def test_corrupt_registry_exits_two(self):
        registry = product_cli.registry_path(Path(self.repo))
        registry.parent.mkdir(parents=True, exist_ok=True)
        registry.write_text("not json{", encoding="utf-8")
        with contextlib.ExitStack() as stack:
            for patch in self.happy_gate_patches():
                stack.enter_context(patch)
            code, out, err = self.run_cli("cbm", "status")
        self.assertEqual(code, EXIT_ACTION_REQUIRED, out)
        self.assertIn("registry", err.lower())


class CbmIndexTests(CBMCLITestCase):
    def test_trusted_candidate_swapped_after_resolution_refuses_index_execution(self):
        tmp_binary = Path(self.repo) / "cbm-test.exe"
        tmp_binary.write_bytes(b"trusted-at-resolution")
        real_verify = cbm_indexing._verify_binary_sha256

        def swap_then_verify(path, digest):
            Path(path).write_bytes(b"replaced-before-exec")
            return real_verify(path, digest)

        with contextlib.ExitStack() as stack:
            for patch in self.happy_gate_patches(binary=str(tmp_binary)):
                stack.enter_context(patch)
            stack.enter_context(
                mock.patch.object(
                    cbm_indexing,
                    "_verify_binary_sha256",
                    side_effect=swap_then_verify,
                )
            )
            process = stack.enter_context(
                mock.patch.object(
                    cbm_indexing.subprocess, "run", wraps=subprocess.run
                )
            )
            code, out, err = self.run_cli("cbm", "index")
        self.assertEqual(code, EXIT_ERROR, f"out={out!r} err={err!r}")
        self.assertIn("hash changed", err)
        self.assertFalse(
            any(
                call.args
                and call.args[0]
                and str(call.args[0][0]) == str(tmp_binary)
                for call in process.call_args_list
            )
        )

    def test_no_binary_exits_one_with_docs_pointer(self):
        run_index = mock.Mock()
        with mock.patch.object(
            product_cli.cbm_support,
            "resolve_cbm_binary",
            lambda root=None, environ=None: None,
        ), mock.patch.object(cbm_indexing, "run_index", run_index):
            code, out, err = self.run_cli("cbm", "index")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("CBM: UNAVAILABLE", out)
        self.assertIn("docs/cbm-backend.md", out)
        run_index.assert_not_called()

    def test_trust_gate_refuses_mismatched_hash_before_exec(self):
        run_index = mock.Mock()
        with contextlib.ExitStack() as stack:
            for patch in self.happy_gate_patches(sha=BAD_SHA):
                stack.enter_context(patch)
            stack.enter_context(mock.patch.object(cbm_indexing, "run_index", run_index))
            code, out, err = self.run_cli("cbm", "index")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("refusing to execute an unverified binary", err)
        run_index.assert_not_called()

    def test_index_success_registers_mapping_and_reports_ready(self):
        register = mock.Mock(
            return_value={
                "workspace_id": "ws_" + "0" * 32,
                "cbm": {"project_name": PROJECT, "cache_dir": ".codebase-memory/cache"},
            }
        )
        run_index = mock.Mock(
            return_value={
                "project_name": PROJECT,
                "nodes": 12,
                "edges": 30,
                "raw_status": "indexed",
            }
        )

        class _Probe:
            def __init__(self, **kwargs):
                pass

            def probe_version(self):
                return "codebase-memory-mcp 0.9.0"

        with contextlib.ExitStack() as stack:
            for patch in self.happy_gate_patches():
                stack.enter_context(patch)
            stack.enter_context(mock.patch.object(cbm_indexing, "run_index", run_index))
            stack.enter_context(
                mock.patch.object(cbm_indexing, "register_mapping", register)
            )
            stack.enter_context(
                mock.patch.object(cbm_indexing, "freshness_state", mock.Mock(return_value=dict(READY)))
            )
            stack.enter_context(mock.patch.object(product_cli, "CBMCLIAdapter", _Probe))
            code, out, err = self.run_cli("cbm", "index")
            self.assertEqual(code, EXIT_OK, err)
            self.assertIn("Index: READY (12 nodes, 30 edges)", out)
            # The slug never reaches human output.
            self.assertNotIn(PROJECT, out)
            self.assertIn(
                "WARN: .codebase-memory/ is not git-ignored", out
            )
            code, out, _ = self.run_cli("cbm", "index", "--json")
            self.assertEqual(code, EXIT_OK)
        payload = json.loads(out)
        self.assertEqual(
            payload,
            {
                "action_performed": "index",
                "status": "READY",
                "project_id": payload["project_id"],
                "nodes": 12,
                "edges": 30,
                "quirk_recovery_used": False,
                "gitignore_warning": True,
            },
        )
        self.assertTrue(payload["project_id"].startswith("rlk_"))
        self.assertEqual(run_index.call_args.kwargs["expected_sha256"], CERTIFIED_SHA)
        self.assertEqual(
            register.call_args.args,
            (
                str(product_cli.registry_path(Path(self.repo))),
                self.repo,
                PROJECT,
                ".codebase-memory/cache",
                "0.9.0",
                CERTIFIED_SHA,
            ),
        )
        cache_dir = Path(self.repo) / ".codebase-memory" / "cache"
        self.assertTrue(cache_dir.is_dir())

    def test_index_mapping_failure_is_partial_state_honest(self):
        with contextlib.ExitStack() as stack:
            for patch in self.happy_gate_patches():
                stack.enter_context(patch)
            stack.enter_context(
                mock.patch.object(
                    cbm_indexing,
                    "run_index",
                    mock.Mock(
                        return_value={
                            "project_name": PROJECT,
                            "nodes": 3,
                            "edges": 4,
                            "raw_status": "indexed",
                        }
                    ),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    cbm_indexing,
                    "register_mapping",
                    mock.Mock(side_effect=cbm_indexing.IndexSetupError("boom")),
                )
            )
            code, out, err = self.run_cli("cbm", "index")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("index succeeded but mapping failed", err)
        self.assertIn("relinkra cbm index' (safe)", err)

    def test_index_run_failure_exits_one_without_registering(self):
        register = mock.Mock()
        with contextlib.ExitStack() as stack:
            for patch in self.happy_gate_patches():
                stack.enter_context(patch)
            stack.enter_context(
                mock.patch.object(
                    cbm_indexing,
                    "run_index",
                    mock.Mock(
                        side_effect=cbm_indexing.IndexSetupError(
                            "cbm index_repository failed: nope"
                        )
                    ),
                )
            )
            stack.enter_context(
                mock.patch.object(cbm_indexing, "register_mapping", register)
            )
            code, out, err = self.run_cli("cbm", "index")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("CBM index failed", err)
        register.assert_not_called()


class CbmRefreshTests(CBMCLITestCase):
    def test_missing_record_tells_to_index_first(self):
        refresh = mock.Mock()
        with contextlib.ExitStack() as stack:
            for patch in self.happy_gate_patches():
                stack.enter_context(patch)
            stack.enter_context(
                mock.patch.object(
                    cbm_indexing, "refresh_with_quirk_recovery", refresh
                )
            )
            code, out, err = self.run_cli("cbm", "refresh")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("CBM: AVAILABLE", out)
        self.assertIn("Index: MISSING — run 'relinkra cbm index' first", out)
        refresh.assert_not_called()

    def test_ready_is_an_idempotent_noop(self):
        refresh = mock.Mock()
        with contextlib.ExitStack() as stack:
            for patch in self.happy_gate_patches():
                stack.enter_context(patch)
            self.register_record()
            stack.enter_context(
                mock.patch.object(cbm_indexing, "freshness_state", mock.Mock(return_value=dict(READY)))
            )
            stack.enter_context(
                mock.patch.object(cbm_indexing, "refresh_with_quirk_recovery", refresh)
            )
            code, out, err = self.run_cli("cbm", "refresh")
            self.assertEqual(code, EXIT_OK, err)
            self.assertIn("Index: READY (already fresh)", out)
            code, out, _ = self.run_cli("cbm", "refresh", "--json")
            self.assertEqual(code, EXIT_OK)
        payload = json.loads(out)
        self.assertEqual(payload["action_performed"], "none")
        self.assertEqual(payload["status"], "READY")
        self.assertFalse(payload["quirk_recovery_used"])
        refresh.assert_not_called()

    def test_stale_refreshes_with_quirk_recovery(self):
        cache_abs = cbm_support.absolutize_against_root(
            self.repo, ".codebase-memory/cache"
        )
        refresh = mock.Mock(
            return_value={
                "quirk_recovery_used": True,
                "result": {
                    "project_name": PROJECT,
                    "nodes": 5,
                    "edges": 9,
                    "raw_status": "indexed",
                },
            }
        )
        with contextlib.ExitStack() as stack:
            for patch in self.happy_gate_patches():
                stack.enter_context(patch)
            self.register_record()
            stack.enter_context(
                mock.patch.object(
                    cbm_indexing,
                    "freshness_state",
                    mock.Mock(
                        side_effect=[dict(STALE_WORKTREE), dict(READY)] * 2
                    ),
                )
            )
            stack.enter_context(
                mock.patch.object(cbm_indexing, "refresh_with_quirk_recovery", refresh)
            )
            code, out, err = self.run_cli("cbm", "refresh")
            self.assertEqual(code, EXIT_OK, err)
            self.assertIn("Index: READY (refreshed)", out)
            code, out, _ = self.run_cli("cbm", "refresh", "--json")
            self.assertEqual(code, EXIT_OK)
        payload = json.loads(out)
        self.assertEqual(payload["action_performed"], "refresh")
        self.assertTrue(payload["quirk_recovery_used"])
        self.assertEqual(payload["nodes"], 5)
        self.assertEqual(refresh.call_args.args, (BIN, self.repo, cache_abs, PROJECT))
        self.assertEqual(
            refresh.call_args.kwargs,
            {"mode": "fast", "expected_sha256": CERTIFIED_SHA},
        )

    def test_untrusted_binary_refuses_before_any_exec(self):
        refresh = mock.Mock()
        with contextlib.ExitStack() as stack:
            for patch in self.happy_gate_patches():
                stack.enter_context(patch)
            self.register_record()
            stack.enter_context(
                mock.patch.object(
                    cbm_indexing,
                    "freshness_state",
                    mock.Mock(
                        return_value={
                            "state": cbm_indexing.UNTRUSTED,
                            "committed_drift": None,
                            "worktree_drift": None,
                        }
                    ),
                )
            )
            stack.enter_context(
                mock.patch.object(cbm_indexing, "refresh_with_quirk_recovery", refresh)
            )
            code, out, err = self.run_cli("cbm", "refresh")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("refusing to execute an unverified binary", err)
        refresh.assert_not_called()

    def test_worktree_drift_after_refresh_stays_honest_stale(self):
        """Real CBM 0.9.0 semantics: change detection reads the git
        worktree, so a refresh cannot clear uncommitted drift. The
        refresh reindexes (content captured) and exits 0 with the
        honest STALE state and the commit guidance — never a destructive
        cache rebuild that cannot help."""
        run_index = mock.Mock()
        still_stale = {
            "state": "STALE_WORKTREE",
            "committed_drift": False,
            "worktree_drift": True,
        }
        with contextlib.ExitStack() as stack:
            for patch in self.happy_gate_patches():
                stack.enter_context(patch)
            self.register_record()
            stack.enter_context(
                mock.patch.object(
                    cbm_indexing,
                    "freshness_state",
                    mock.Mock(side_effect=[dict(STALE_WORKTREE), dict(still_stale)]),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    cbm_indexing,
                    "refresh_with_quirk_recovery",
                    mock.Mock(
                        return_value={
                            "quirk_recovery_used": False,
                            "result": {
                                "project_name": PROJECT,
                                "nodes": 7,
                                "edges": 11,
                                "raw_status": "indexed",
                            },
                        },
                    ),
                )
            )
            stack.enter_context(mock.patch.object(cbm_indexing, "run_index", run_index))
            code, out, err = self.run_cli("cbm", "refresh", "--json")
        self.assertEqual(code, EXIT_OK, err)
        payload = json.loads(out)
        self.assertEqual(payload["action_performed"], "refresh")
        self.assertEqual(payload["status"], "STALE")
        self.assertEqual(payload["nodes"], 7)
        self.assertFalse(payload["quirk_recovery_used"])
        self.assertTrue(payload["freshness"]["worktree_drift"])
        self.assertIn("commit your changes", payload["next_action"])
        # The CLI itself never re-runs or rebuilds the index: the
        # pinned refresh owns the reindex.
        run_index.assert_not_called()

    def test_stale_after_recovery_exits_one(self):
        with contextlib.ExitStack() as stack:
            for patch in self.happy_gate_patches():
                stack.enter_context(patch)
            self.register_record()
            stack.enter_context(
                mock.patch.object(
                    cbm_indexing,
                    "freshness_state",
                    mock.Mock(return_value=dict(STALE_WORKTREE)),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    cbm_indexing,
                    "refresh_with_quirk_recovery",
                    mock.Mock(
                        side_effect=cbm_indexing.StaleAfterRefreshError(
                            "still stale after one quirk recovery"
                        )
                    ),
                )
            )
            code, out, err = self.run_cli("cbm", "refresh")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("still stale", err)

    def test_unsupported_mode_is_rejected(self):
        code, out, err = self.run_cli("cbm", "refresh", "--mode", "full")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("invalid choice", err)


if __name__ == "__main__":
    unittest.main()
