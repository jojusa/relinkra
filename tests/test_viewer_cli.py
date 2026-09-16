"""CLI and status-payload tests for ``relinkra cbm open`` (VIS-1).

Every CBM seam is mocked: binary resolution, platform provenance, the
freshness classifier, and the adapter class. Servers are real loopback
sockets and are always closed; ``viewer.run_forever`` is faked wherever
the CLI would otherwise block, so the suite can never hang.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.request
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
from relinkra.handoff import contains_absolute_path
from relinkra.identity import git_head_sha, normalize_os_family
from relinkra.product_cli import EXIT_ERROR, EXIT_OK

BIN = "C:/fake/codebase-memory-mcp.exe"
PROJECT = "C-fixture-repo"
CERTIFIED = cbm_support.CERTIFIED_CBM_BINARIES["windows-amd64"]
CERTIFIED_SHA = CERTIFIED["sha256"]
BAD_SHA = "ff" * 32
STORED_HEAD = "a" * 40
LIVE_HEAD = "b" * 40

READY = {"state": "READY", "committed_drift": False, "worktree_drift": False}


class _FakeAdapter:
    """Recording stand-in for CBMCLIAdapter bound to the stored graph."""

    instances = []
    stored_head = STORED_HEAD
    nodes = 12
    edges = 30

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.graph_index_head_calls = 0
        self.index_status_calls = 0
        self.architecture_calls = 0
        _FakeAdapter.instances.append(self)

    @classmethod
    def reset(cls):
        cls.instances = []
        cls.stored_head = STORED_HEAD
        cls.nodes = 12
        cls.edges = 30

    def graph_index_head(self, project=None):
        self.graph_index_head_calls += 1
        return self.stored_head

    def index_status(self):
        """Live-derived head that must NEVER reach the payload."""
        self.index_status_calls += 1
        return {"git": {"head_sha": LIVE_HEAD}}

    def architecture_orientation(self, *, project=None, path=None, limit=5):
        self.architecture_calls += 1
        return {"total_nodes": self.nodes, "total_edges": self.edges}


def _walk_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _walk_strings(item)


class ViewerCLITestCase(unittest.TestCase):
    """A real temp git repo; the CLI's CBM seams fully mocked."""

    def setUp(self):
        _FakeAdapter.reset()
        if shutil.which("git") is None:
            self.skipTest("git is required for the cbm open CLI tests")
        tmp = tempfile.mkdtemp(prefix="rlk-viewer-cli-")
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

    def availability_patches(self, binary=BIN, sha=CERTIFIED_SHA):
        """Make the binary resolve on a certified platform with a pinned hash."""
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

    def write_managed_db(self):
        """The project .db file the stored-graph gates require."""
        cache = Path(self.repo) / ".codebase-memory" / "cache"
        cache.mkdir(parents=True, exist_ok=True)
        (cache / (PROJECT + ".db")).write_bytes(b"")
        return cache


class CbmOpenHelpTests(ViewerCLITestCase):
    def test_open_is_registered_in_the_cbm_family(self):
        code, out, err = self.run_cli("cbm", "--help", path=False)
        self.assertEqual(code, EXIT_OK, err)
        self.assertIn("open", out)
        self.assertIn("usage", out)

    def test_open_help_lists_its_options(self):
        code, out, err = self.run_cli("cbm", "open", "--help", path=False)
        self.assertEqual(code, EXIT_OK, err)
        self.assertIn("cbm open", out)
        for option in ("--path", "--port", "--no-open", "--json"):
            self.assertIn(option, out)
        self.assertNotIn("--host", out)

    def test_invalid_ports_are_usage_errors(self):
        for value in ("-1", "65536", "abc"):
            with self.subTest(port=value):
                code, out, err = self.run_cli("cbm", "open", "--port", value, path=False)
                self.assertEqual(code, EXIT_ERROR)
                self.assertIn("Error", err)
                self.assertIn("65535", err)


class CbmOpenServerTests(ViewerCLITestCase):
    def test_occupied_port_exits_one_with_a_next_step(self):
        blocker = product_cli.viewer.create_server(lambda: {}, port=0)
        self.addCleanup(blocker.server_close)
        port = blocker.server_address[1]
        with mock.patch.object(product_cli.viewer, "run_forever", mock.Mock()):
            code, out, err = self.run_cli(
                "cbm", "open", "--port", str(port), "--no-open", "--json"
            )
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("already in use", err)
        self.assertIn("--port", err)

    def test_no_open_flag_skips_the_browser(self):
        open_browser = mock.Mock(return_value=True)
        run_forever = mock.Mock()
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(product_cli.viewer, "open_browser", open_browser)
            )
            stack.enter_context(
                mock.patch.object(product_cli.viewer, "run_forever", run_forever)
            )
            code, out, err = self.run_cli("cbm", "open", "--no-open")
        self.assertEqual(code, EXIT_OK, err)
        open_browser.assert_not_called()
        run_forever.assert_called_once()
        self.assertIn("Relinkra Viewer", out)
        self.assertIn("http://127.0.0.1:", out)
        self.assertIn("Press Ctrl+C to stop.", out)

    def test_default_mode_opens_the_browser_after_the_server_listens(self):
        real_create = product_cli.viewer.create_server
        created = []
        calls = []

        def tracking_create(provider, *, port=0, host=product_cli.viewer.VIEWER_HOST):
            server = real_create(provider, port=port, host=host)
            created.append(server)
            self.addCleanup(server.server_close)
            return server

        def probe_then_record(url):
            # The spy proves the socket is LISTENING AND SERVING before the
            # browser launch is recorded: it performs a real HTTP request.
            server = created[0]
            thread = threading.Thread(
                target=server.serve_forever,
                kwargs={"poll_interval": 0.05},
                daemon=True,
            )
            thread.start()
            try:
                with urllib.request.urlopen(url + "/", timeout=10) as response:
                    self.assertEqual(response.status, 200)
                    self.assertIn(b"Relinkra Viewer", response.read())
            finally:
                server.shutdown()
                thread.join(10.0)
            calls.append(url)
            return True

        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(product_cli.viewer, "create_server", tracking_create)
            )
            stack.enter_context(
                mock.patch.object(product_cli.viewer, "open_browser", probe_then_record)
            )
            stack.enter_context(
                mock.patch.object(product_cli.viewer, "run_forever", mock.Mock())
            )
            code, out, err = self.run_cli("cbm", "open")
        self.assertEqual(code, EXIT_OK, err)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0], f"http://127.0.0.1:{created[0].server_address[1]}")

    def test_failed_browser_launch_keeps_the_server_alive(self):
        run_forever = mock.Mock()
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    product_cli.viewer, "open_browser", mock.Mock(return_value=False)
                )
            )
            stack.enter_context(
                mock.patch.object(product_cli.viewer, "run_forever", run_forever)
            )
            code, out, err = self.run_cli("cbm", "open")
        self.assertEqual(code, EXIT_OK, err)
        run_forever.assert_called_once()
        self.assertIn("Could not open a browser automatically", err)
        self.assertIn("http://127.0.0.1:", err)

    def test_json_emits_only_the_startup_object(self):
        real_create = product_cli.viewer.create_server
        created = []

        def tracking_create(provider, *, port=0, host=product_cli.viewer.VIEWER_HOST):
            server = real_create(provider, port=port, host=host)
            created.append(server)
            self.addCleanup(server.server_close)
            return server

        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(product_cli.viewer, "create_server", tracking_create)
            )
            stack.enter_context(
                mock.patch.object(product_cli.viewer, "run_forever", mock.Mock())
            )
            code, out, err = self.run_cli("cbm", "open", "--no-open", "--json")
        self.assertEqual(code, EXIT_OK, err)
        payload = json.loads(out)
        self.assertEqual(set(payload), {"host", "port", "url"})
        self.assertEqual(payload["host"], "127.0.0.1")
        self.assertEqual(payload["port"], created[0].server_address[1])
        self.assertEqual(payload["url"], f"http://127.0.0.1:{payload['port']}")
        self.assertNotIn("Relinkra Viewer", out)


class ViewerStatusPayloadTests(ViewerCLITestCase):
    def build_payload(self, *, patch_freshness=None, adapter=True):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        for patch in self.availability_patches():
            stack.enter_context(patch)
        if patch_freshness is not None:
            stack.enter_context(
                mock.patch.object(
                    cbm_indexing,
                    "freshness_state",
                    mock.Mock(return_value=dict(patch_freshness)),
                )
            )
        if adapter:
            stack.enter_context(
                mock.patch.object(product_cli, "CBMCLIAdapter", _FakeAdapter)
            )
        return product_cli._viewer_status_payload(self.repo, "rlk_fixture")

    def test_ready_reports_stored_revision_counts_and_no_next_action(self):
        self.register_record()
        self.write_managed_db()
        head = git_head_sha(str(self.repo))
        _FakeAdapter.stored_head = head
        payload = self.build_payload(patch_freshness=READY)

        self.assertEqual(payload["cbm"]["availability"], "AVAILABLE")
        self.assertEqual(payload["cbm"]["state"], "READY")
        self.assertFalse(payload["cbm"]["committed_drift"])
        self.assertFalse(payload["cbm"]["worktree_drift"])
        self.assertEqual(payload["cbm"]["nodes"], 12)
        self.assertEqual(payload["cbm"]["edges"], 30)
        self.assertIsNone(payload["cbm"]["next_action"])

        self.assertEqual(payload["project"], {"project_id": "rlk_fixture"})
        self.assertEqual(payload["revision"]["current"], head)
        self.assertEqual(payload["revision"]["indexed"], head)
        self.assertEqual(payload["revision"]["indexed_source"], "stored_branch")

        self.assertEqual(
            payload["viewer"],
            {
                "contract": "relinkra.viewer/v1",
                "host": "127.0.0.1",
                "read_only": True,
            },
        )
        self.assertFalse(payload["workspace"]["initialized"])
        self.assertTrue(str(payload["workspace"]["workspace_id"]).startswith("ws_"))
        self.assertEqual(payload["workspace"]["branch"], "main")
        self.assertEqual(
            payload["workspace"]["os_family"], normalize_os_family(sys.platform)
        )

        # The stored Branch probe is the ONLY revision source.
        self.assertTrue(_FakeAdapter.instances)
        for adapter in _FakeAdapter.instances:
            self.assertEqual(adapter.index_status_calls, 0)
        self.assertGreater(
            sum(
                adapter.graph_index_head_calls
                for adapter in _FakeAdapter.instances
            ),
            0,
        )
        self.assertNotIn(LIVE_HEAD, json.dumps(payload, sort_keys=True))

    def test_stale_committed_maps_to_refresh(self):
        self.register_record()
        self.write_managed_db()
        freshness = {
            "state": "STALE_COMMITTED",
            "committed_drift": True,
            "worktree_drift": False,
        }
        payload = self.build_payload(patch_freshness=freshness)
        self.assertEqual(payload["cbm"]["state"], "STALE")
        self.assertTrue(payload["cbm"]["committed_drift"])
        self.assertFalse(payload["cbm"]["worktree_drift"])
        self.assertEqual(payload["cbm"]["next_action"], "relinkra cbm refresh")

    def test_stale_worktree_maps_to_commit_then_refresh(self):
        self.register_record()
        self.write_managed_db()
        freshness = {
            "state": "STALE_WORKTREE",
            "committed_drift": False,
            "worktree_drift": True,
        }
        payload = self.build_payload(patch_freshness=freshness)
        self.assertEqual(payload["cbm"]["state"], "STALE")
        self.assertEqual(
            payload["cbm"]["next_action"], product_cli._CBM_COMMIT_THEN_REFRESH
        )

    def test_missing_record_reports_missing_without_touching_the_backend(self):
        payload = self.build_payload()
        self.assertEqual(payload["cbm"]["availability"], "AVAILABLE")
        self.assertEqual(payload["cbm"]["state"], "MISSING")
        self.assertIsNone(payload["cbm"]["committed_drift"])
        self.assertIsNone(payload["cbm"]["worktree_drift"])
        self.assertIsNone(payload["cbm"]["nodes"])
        self.assertIsNone(payload["cbm"]["edges"])
        self.assertIsNone(payload["revision"]["indexed"])
        self.assertEqual(payload["cbm"]["next_action"], "relinkra cbm index")
        self.assertEqual(_FakeAdapter.instances, [])

    def test_unavailable_reports_setup_and_never_constructs_an_adapter(self):
        _FakeAdapter.reset()
        unavail = {
            "state": cbm_indexing.UNAVAILABLE,
            "committed_drift": None,
            "worktree_drift": None,
        }
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    product_cli.cbm_support,
                    "resolve_cbm_binary",
                    lambda root=None, environ=None: None,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    cbm_indexing,
                    "freshness_state",
                    mock.Mock(return_value=dict(unavail)),
                )
            )
            stack.enter_context(
                mock.patch.object(product_cli, "CBMCLIAdapter", _FakeAdapter)
            )
            payload = product_cli._viewer_status_payload(self.repo, "rlk_fixture")
        self.assertEqual(payload["cbm"]["availability"], "UNAVAILABLE")
        self.assertEqual(payload["cbm"]["state"], "UNAVAILABLE")
        self.assertEqual(payload["cbm"]["next_action"], "relinkra cbm setup")
        self.assertIsNone(payload["revision"]["indexed"])
        self.assertIsNone(payload["cbm"]["nodes"])
        self.assertEqual(_FakeAdapter.instances, [])

    def test_unsupported_reports_setup_and_never_constructs_an_adapter(self):
        _FakeAdapter.reset()
        unsupported = {
            "state": cbm_indexing.UNSUPPORTED,
            "committed_drift": None,
            "worktree_drift": None,
        }
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    product_cli.cbm_support,
                    "resolve_cbm_binary",
                    lambda root=None, environ=None: BIN,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    product_cli.cbm_support, "platform_tag", lambda: "linux-amd64"
                )
            )
            stack.enter_context(
                mock.patch.object(
                    cbm_indexing,
                    "freshness_state",
                    mock.Mock(return_value=dict(unsupported)),
                )
            )
            stack.enter_context(
                mock.patch.object(product_cli, "CBMCLIAdapter", _FakeAdapter)
            )
            payload = product_cli._viewer_status_payload(self.repo, "rlk_fixture")
        self.assertEqual(payload["cbm"]["availability"], "UNSUPPORTED")
        self.assertEqual(payload["cbm"]["state"], "UNSUPPORTED")
        self.assertEqual(payload["cbm"]["next_action"], "relinkra cbm setup")
        self.assertIsNone(payload["revision"]["indexed"])
        self.assertEqual(_FakeAdapter.instances, [])

    def test_untrusted_reports_setup_and_never_executes(self):
        _FakeAdapter.reset()
        self.register_record()
        self.write_managed_db()
        with contextlib.ExitStack() as stack:
            for patch in self.availability_patches(sha=BAD_SHA):
                stack.enter_context(patch)
            stack.enter_context(
                mock.patch.object(product_cli, "CBMCLIAdapter", _FakeAdapter)
            )
            payload = product_cli._viewer_status_payload(self.repo, "rlk_fixture")
        self.assertEqual(payload["cbm"]["availability"], "UNTRUSTED")
        self.assertEqual(payload["cbm"]["state"], "UNTRUSTED")
        self.assertEqual(payload["cbm"]["next_action"], "relinkra cbm setup")
        self.assertIsNone(payload["revision"]["indexed"])
        self.assertIsNone(payload["cbm"]["nodes"])
        self.assertEqual(_FakeAdapter.instances, [])

    def test_uninitialized_workspace_is_reported_honestly(self):
        with mock.patch.object(
            product_cli.cbm_support,
            "resolve_cbm_binary",
            lambda root=None, environ=None: None,
        ):
            payload = product_cli._viewer_status_payload(self.repo, "rlk_fixture")
        self.assertFalse(payload["workspace"]["initialized"])
        self.assertIsNone(payload["workspace"]["workspace_id"])

    def test_indexed_revision_never_comes_from_the_live_status(self):
        self.register_record()
        self.write_managed_db()
        _FakeAdapter.stored_head = STORED_HEAD
        payload = self.build_payload(patch_freshness=READY)
        self.assertEqual(payload["revision"]["indexed"], STORED_HEAD)
        for adapter in _FakeAdapter.instances:
            self.assertEqual(adapter.index_status_calls, 0)
        self.assertNotIn(LIVE_HEAD, json.dumps(payload, indent=2, sort_keys=True))

    def test_payload_is_byte_identical_across_builds(self):
        self.register_record()
        self.write_managed_db()
        first = self.build_payload(patch_freshness=READY)
        second = self.build_payload(patch_freshness=READY)
        self.assertEqual(
            json.dumps(first, indent=2, sort_keys=True),
            json.dumps(second, indent=2, sort_keys=True),
        )

    def test_payload_is_path_free_and_hygienic(self):
        self.register_record()
        self.write_managed_db()
        payload = self.build_payload(patch_freshness=READY)
        text = json.dumps(payload, indent=2, sort_keys=True)

        self.assertNotIn(str(Path(self.repo)), text)
        self.assertNotIn(str(Path(self.repo).resolve()), text)
        self.assertNotIn(os.path.expanduser("~"), text)
        for marker in (
            ".codebase-memory",
            "codebase-memory-mcp",
            "cache",
            "bin",
            BIN,
            "\\",
        ):
            self.assertNotIn(marker, text)

        for value in _walk_strings(payload):
            self.assertFalse(contains_absolute_path(value), value)
            self.assertNotIn("\\", value)


if __name__ == "__main__":
    unittest.main()