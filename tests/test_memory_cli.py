"""Tests for the memory CLI and the Engram CLI adapter (mocked subprocess)."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import urllib.error
from unittest import mock

from relinkra import memory_cli
from relinkra.engram_adapter import (
    DEFAULT_ENGRAM_URL,
    EngramCLIAdapter,
    InMemoryStore,
    _close_all_loopbacks,
    parse_save_output,
    parse_search_output,
)
from relinkra.identity import explicit_identity
from relinkra.memory import MemoryStoreError
from relinkra.registry import Registry

PID = "rlk_" + "a1b2c3d4" * 4
WID = "ws_" + "1" * 32
REPO_VALUE = "explicit://cli-test-project"


def _cleanup_tmp_dir(tmp) -> None:
    """Remove a scratch dir, tolerating Windows handle-release races.

    Right after a killed ``engram`` child exits, Windows (and the
    occasional AV scanner) can still hold one of its SQLite files for a
    moment, making rmtree fail with "directory not empty". Retry
    briefly; a PERSISTENT lock still raises, which is exactly the
    process-leak signal this suite must keep visible.
    """
    last_error = None
    for _ in range(8):
        try:
            tmp.cleanup()
            return
        except OSError as exc:
            last_error = exc
            time.sleep(0.5)
    raise last_error

SAMPLE_SEARCH = """Found 2 memories:

[1] #42 (decision) — Chose Engram
    {{"v":"rlkmem1","memory_id":"mem_aaa","project_id":"{pid}","title":"Chose Engram"}}
    2026-07-24 10:00:00 | project: {pid} | scope: project

[2] #43 (manual) — Truncated one
    {{"v":"rlkmem1","memory_id":"mem_bbb","body":"xxxxxxxxxxxxxxxxxxxxxxxx...
    2026-07-24 10:01:00 | project: {pid} | scope: project
""".format(pid=PID)


def run_cli(argv, store=None):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = memory_cli.main(argv, store=store)
    return code, out.getvalue(), err.getvalue()


def cli_save(store, **over):
    argv = [
        "save",
        "--project-id",
        PID,
        "--repository-identity",
        REPO_VALUE,
        "--memory-type",
        "decision",
        "--title",
        over.pop("title", "T"),
        "--content",
        over.pop("content", "B"),
    ]
    for key, value in over.items():
        argv += ["--" + key.replace("_", "-"), str(value)]
    return run_cli(argv, store=store)


class TestParseSearchOutput(unittest.TestCase):
    def test_parses_blocks(self):
        records = parse_search_output(SAMPLE_SEARCH)
        self.assertEqual(len(records), 2)
        first = records[0]
        self.assertEqual(first.record_id, "42")
        self.assertEqual(first.storage_type, "decision")
        self.assertEqual(first.title, "Chose Engram")
        self.assertEqual(first.project, PID)
        self.assertEqual(first.scope, "project")
        self.assertEqual(first.timestamp, "2026-07-24 10:00:00")
        envelope = json.loads(first.content)
        self.assertEqual(envelope["memory_id"], "mem_aaa")

    def test_truncated_content_reconstructed_but_not_valid_json(self):
        records = parse_search_output(SAMPLE_SEARCH)
        truncated = records[1]
        self.assertTrue(truncated.content.endswith("..."))
        # Transport honesty: the parser flags cut-off content so the
        # policy layer can account for it separately from malformed data.
        self.assertTrue(truncated.truncated)
        with self.assertRaises(json.JSONDecodeError):
            json.loads(truncated.content)

    def test_empty_and_no_match(self):
        self.assertEqual(parse_search_output(""), [])
        self.assertEqual(parse_search_output('No memories found for: "x"'), [])

    def test_parse_save_output(self):
        self.assertEqual(
            parse_save_output('Memory saved: #7 "T" (decision)'), "7"
        )
        self.assertEqual(parse_save_output("unexpected"), "")


class FakeCompleted:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class TestEngramCLIAdapter(unittest.TestCase):
    def make_adapter(self, **kw):
        kw.setdefault("http_url", "")  # force CLI path in these tests
        return EngramCLIAdapter(**kw)

    def test_save_invokes_engram_with_topic(self):
        adapter = self.make_adapter()
        with mock.patch(
            "relinkra.engram_adapter.subprocess.run",
            return_value=FakeCompleted(stdout='Memory saved: #9 "T" (decision)'),
        ) as run:
            record_id = adapter.save_record(
                title="T",
                content='{"v":"rlkmem1"}',
                storage_type="decision",
                project=PID,
                scope="project",
                topic_key=f"relinkra/v1/{PID}/shared/decision/t",
            )
        self.assertEqual(record_id, "9")
        argv = run.call_args[0][0]
        self.assertEqual(argv[:3], ["engram", "save", "T"])
        self.assertIn("--topic", argv)
        self.assertIn("--project", argv)
        self.assertIn(PID, argv)

    def test_search_parses_output_and_passes_filters(self):
        adapter = self.make_adapter()
        with mock.patch(
            "relinkra.engram_adapter.subprocess.run",
            return_value=FakeCompleted(stdout=SAMPLE_SEARCH),
        ) as run:
            records = adapter.search_records(
                query="rlkmem1", project=PID, limit=25
            )
        self.assertEqual(len(records), 2)
        argv = run.call_args[0][0]
        self.assertEqual(argv[:2], ["engram", "search"])
        self.assertIn("--project", argv)
        self.assertIn("--limit", argv)

    def test_search_no_match_returns_empty(self):
        adapter = self.make_adapter()
        with mock.patch(
            "relinkra.engram_adapter.subprocess.run",
            return_value=FakeCompleted(stdout='No memories found for: "zz"'),
        ):
            self.assertEqual(adapter.search_records(query="zz"), [])

    def test_nonzero_exit_raises_sanitized(self):
        adapter = self.make_adapter()
        secret = "hunter2"
        with mock.patch(
            "relinkra.engram_adapter.subprocess.run",
            return_value=FakeCompleted(
                stderr=f"boom https://u:{secret}@h/x token={secret}", returncode=1
            ),
        ):
            with self.assertRaises(MemoryStoreError) as ctx:
                adapter.search_records(query="x")
        self.assertNotIn(secret, str(ctx.exception))

    def test_missing_binary_raises(self):
        adapter = self.make_adapter(engram_bin="engram-does-not-exist-xyz")
        with self.assertRaises(MemoryStoreError):
            adapter.search_records(query="x")

    def test_timeout_raises(self):
        adapter = self.make_adapter(timeout=0.001)
        with mock.patch(
            "relinkra.engram_adapter.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="engram", timeout=0.001),
        ):
            with self.assertRaises(MemoryStoreError):
                adapter.search_records(query="x")


class FakeHTTPResponse:
    def __init__(self, payload):
        self._body = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def http_payload(**over):
    item = {
        "id": 42,
        "type": "decision",
        "title": "Chose Engram",
        "content": json.dumps(
            {"v": "rlkmem1", "memory_id": "mem_aaa", "project_id": PID}
        ),
        "project": PID,
        "scope": "project",
        "timestamp": "2026-07-24 10:00:00",
    }
    item.update(over)
    return [item]


class TestEngramHTTPReadPath(unittest.TestCase):
    """HTTP read path: full content, no server required (mocked urllib)."""

    def adapter(self, **kw):
        kw.setdefault("http_url", "http://127.0.0.1:7437")
        return EngramCLIAdapter(**kw)

    def test_http_returns_full_untruncated_content(self):
        long_body = "x" * 1200  # far beyond the ~300 char CLI truncation
        envelope = json.dumps(
            {"v": "rlkmem1", "memory_id": "mem_big", "project_id": PID,
             "body": long_body}
        )
        payload = http_payload(content=envelope)
        with mock.patch(
            "relinkra.engram_adapter.urllib.request.urlopen",
            return_value=FakeHTTPResponse(payload),
        ) as urlopen, mock.patch(
            "relinkra.engram_adapter.subprocess.run"
        ) as run:
            records = self.adapter().search_records(query="rlkmem1", project=PID)
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.record_id, "42")
        self.assertEqual(record.storage_type, "decision")
        self.assertEqual(record.content, envelope)
        self.assertFalse(record.content.endswith("..."))
        self.assertEqual(json.loads(record.content)["body"], long_body)
        run.assert_not_called()
        url = urlopen.call_args[0][0]
        self.assertIn("/search?", url)
        self.assertIn("q=rlkmem1", url)
        self.assertIn(f"project={PID}", url)

    def test_http_applies_storage_type_filter_client_side(self):
        payload = http_payload() + http_payload(
            id=43, type="manual", title="Other"
        )
        with mock.patch(
            "relinkra.engram_adapter.urllib.request.urlopen",
            return_value=FakeHTTPResponse(payload),
        ):
            records = self.adapter().search_records(
                query="rlkmem1", project=PID, storage_type="decision"
            )
        self.assertEqual([r.title for r in records], ["Chose Engram"])

    def test_http_applies_limit_client_side(self):
        payload = [http_payload(id=i, title=f"T{i}")[0] for i in range(5)]
        with mock.patch(
            "relinkra.engram_adapter.urllib.request.urlopen",
            return_value=FakeHTTPResponse(payload),
        ):
            records = self.adapter().search_records(query="x", limit=2)
        self.assertEqual(len(records), 2)

    def test_http_down_falls_back_to_cli(self):
        with mock.patch(
            "relinkra.engram_adapter.urllib.request.urlopen",
            side_effect=urllib.error.URLError("connection refused"),
        ), mock.patch(
            "relinkra.engram_adapter.subprocess.run",
            return_value=FakeCompleted(stdout=SAMPLE_SEARCH),
        ) as run:
            records = self.adapter().search_records(query="rlkmem1", project=PID)
        self.assertEqual(len(records), 2)
        run.assert_called_once()

    def test_http_bad_payload_falls_back_to_cli(self):
        class BadResponse(FakeHTTPResponse):
            def read(self):
                return b"not json{"

        with mock.patch(
            "relinkra.engram_adapter.urllib.request.urlopen",
            return_value=BadResponse(None),
        ), mock.patch(
            "relinkra.engram_adapter.subprocess.run",
            return_value=FakeCompleted(stdout=SAMPLE_SEARCH),
        ) as run:
            records = self.adapter().search_records(query="rlkmem1", project=PID)
        self.assertEqual(len(records), 2)
        run.assert_called_once()

    def test_http_non_list_payload_falls_back_to_cli(self):
        with mock.patch(
            "relinkra.engram_adapter.urllib.request.urlopen",
            return_value=FakeHTTPResponse({"error": "nope"}),
        ), mock.patch(
            "relinkra.engram_adapter.subprocess.run",
            return_value=FakeCompleted(stdout=SAMPLE_SEARCH),
        ) as run:
            records = self.adapter().search_records(query="rlkmem1", project=PID)
        self.assertEqual(len(records), 2)
        run.assert_called_once()

    def test_http_disabled_goes_straight_to_cli(self):
        with mock.patch(
            "relinkra.engram_adapter.urllib.request.urlopen"
        ) as urlopen, mock.patch(
            "relinkra.engram_adapter.subprocess.run",
            return_value=FakeCompleted(stdout=SAMPLE_SEARCH),
        ):
            records = self.adapter(http_url="").search_records(
                query="rlkmem1", project=PID
            )
        self.assertEqual(len(records), 2)
        urlopen.assert_not_called()

    def test_http_url_resolution(self):
        self.assertEqual(
            EngramCLIAdapter(http_url="http://x:1/").http_url, "http://x:1"
        )
        with mock.patch.dict(os.environ, {"ENGRAM_URL": "http://y:2"}):
            self.assertEqual(EngramCLIAdapter().http_url, "http://y:2")
            self.assertEqual(EngramCLIAdapter(http_url="").http_url, "")
        with mock.patch.dict(
            os.environ,
            {"ENGRAM_DATA_DIR": "C:/isolated-engram"},
            clear=True,
        ):
            self.assertEqual(EngramCLIAdapter().http_url, "")
        with mock.patch.dict(
            os.environ,
            {
                "ENGRAM_DATA_DIR": "C:/isolated-engram",
                "ENGRAM_URL": "http://explicit:7437",
            },
            clear=True,
        ):
            self.assertEqual(EngramCLIAdapter().http_url, "http://explicit:7437")
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ENGRAM_URL", None)
            self.assertEqual(EngramCLIAdapter().http_url, DEFAULT_ENGRAM_URL)


class TestMemoryCLI(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryStore()

    def test_save_outputs_json(self):
        code, out, err = run_cli(
            [
                "save",
                "--project-id", PID,
                "--repository-identity", REPO_VALUE,
                "--memory-type", "bug",
                "--title", "Login crashes",
                "--content", "Null deref on empty password",
                "--scope", "project_shared",
                "--agent-type", "opencode",
                "--source-tool", "opencode",
            ],
            store=self.store,
        )
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertFalse(payload["deduplicated"])
        memory = payload["memory"]
        self.assertEqual(memory["project_id"], PID)
        self.assertEqual(memory["memory_type"], "bug")
        self.assertEqual(memory["scope"], "project_shared")
        self.assertEqual(
            memory["topic_key"],
            f"relinkra/v1/{PID}/shared/bug/login-crashes",
        )
        stored = self.store.saved_args[0]
        self.assertEqual(stored["storage_type"], "bugfix")
        self.assertEqual(stored["scope"], "project")

    def test_save_requires_project_binding(self):
        code, out, err = run_cli(
            ["save", "--memory-type", "bug", "--title", "T", "--content", "B"],
            store=self.store,
        )
        self.assertEqual(code, 1)
        self.assertIn("error", json.loads(err))

    def test_save_rejects_bad_project_id(self):
        code, _, err = run_cli(
            [
                "save",
                "--project-id", r"C:\Desarrollos\relinkra",
                "--repository-identity", REPO_VALUE,
                "--memory-type", "bug",
                "--title", "T",
                "--content", "B",
            ],
            store=self.store,
        )
        self.assertEqual(code, 1)
        self.assertIn("error", json.loads(err))

    def test_save_redacts_secrets(self):
        secret = "sk-" + "z" * 30
        code, out, _ = cli_save(self.store, title="Leak", content=f"key {secret}")
        self.assertEqual(code, 0)
        self.assertNotIn(secret, self.store.saved_args[0]["content"])
        self.assertNotIn(secret, out)

    def test_query_roundtrip(self):
        cli_save(self.store, title="Shared one", content="alpha")
        cli_save(
            self.store,
            title="WS note",
            content="beta",
            scope="workspace_local",
            workspace_id=WID,
        )
        code, out, _ = run_cli(
            ["query", "--project-id", PID, "--scope", "project_shared"],
            store=self.store,
        )
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["memories"][0]["title"], "Shared one")

        code, out, _ = run_cli(
            [
                "query",
                "--project-id", PID,
                "--scope", "workspace_local",
                "--workspace-id", WID,
            ],
            store=self.store,
        )
        payload = json.loads(out)
        self.assertEqual(payload["count"], 2)

    def test_query_requires_project_id(self):
        parser = memory_cli.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["query"])

    def test_supersede_roundtrip(self):
        code, out, _ = cli_save(self.store, title="Doc", content="old")
        memory_id = json.loads(out)["memory"]["memory_id"]
        code, out, err = run_cli(
            [
                "supersede",
                memory_id,
                "--project-id", PID,
                "--content", "new",
            ],
            store=self.store,
        )
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["superseded"], [memory_id])
        self.assertEqual(payload["memory"]["body"], "new")

    def test_supersede_obsolete(self):
        code, out, _ = cli_save(self.store, title="Stale", content="old")
        memory_id = json.loads(out)["memory"]["memory_id"]
        code, out, _ = run_cli(
            ["supersede", memory_id, "--project-id", PID, "--obsolete"],
            store=self.store,
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["memory"]["status"], "obsolete")

    def test_supersede_unknown_exits_2(self):
        code, _, err = run_cli(
            ["supersede", "mem_missing", "--project-id", PID, "--obsolete"],
            store=self.store,
        )
        self.assertEqual(code, 2)
        self.assertIn("error", json.loads(err))


CALC_REF_JSON = json.dumps(
    {
        "project_id": PID,
        "reference_kind": "symbol",
        "file_path": "src/calculator.py",
        "symbol_name": "add",
        "qualified_name": "src.calculator.add",
        "symbol_kind": "Function",
    }
)


class TestMemoryCLICodeLinks(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryStore()

    def test_save_with_code_ref(self):
        code, out, err = cli_save(self.store, code_ref=CALC_REF_JSON)
        self.assertEqual(code, 0, err)
        memory = json.loads(out)["memory"]
        self.assertEqual(len(memory["code_refs"]), 1)
        ref = memory["code_refs"][0]
        self.assertEqual(ref["qualified_name"], "src.calculator.add")
        self.assertTrue(ref["code_reference_id"].startswith("ref_"))
        self.assertEqual(ref["language"], "python")

    def test_save_rejects_bad_code_ref_json(self):
        code, _, err = cli_save(self.store, code_ref="{not json")
        self.assertEqual(code, 1)
        self.assertIn("error", json.loads(err))

    def test_save_rejects_invalid_code_ref(self):
        bad = json.dumps(
            {
                "project_id": PID,
                "reference_kind": "symbol",
                "file_path": "../escape.py",
                "symbol_name": "x",
            }
        )
        code, _, err = cli_save(self.store, code_ref=bad)
        self.assertEqual(code, 1)
        self.assertIn("error", json.loads(err))

    def test_query_code_file_finds_linked_memory(self):
        cli_save(self.store, title="Linked", content="L", code_ref=CALC_REF_JSON)
        cli_save(self.store, title="Unlinked", content="U")
        code, out, err = run_cli(
            [
                "query",
                "--project-id", PID,
                "--code-file", "src/calculator.py",
            ],
            store=self.store,
        )
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["matches"][0]["memory"]["title"], "Linked")

    def test_query_code_symbol_finds_linked_memory(self):
        cli_save(self.store, title="Linked", content="L", code_ref=CALC_REF_JSON)
        code, out, _ = run_cli(
            ["query", "--project-id", PID, "--code-symbol", "add"],
            store=self.store,
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["count"], 1)
        code, out, _ = run_cli(
            ["query", "--project-id", PID, "--code-symbol", "absent"],
            store=self.store,
        )
        self.assertEqual(json.loads(out)["count"], 0)

    def test_query_code_file_respects_scope(self):
        cli_save(
            self.store,
            title="WS note",
            content="W",
            scope="workspace_local",
            workspace_id=WID,
            code_ref=CALC_REF_JSON,
        )
        code, out, _ = run_cli(
            ["query", "--project-id", PID, "--code-file", "src/calculator.py"],
            store=self.store,
        )
        self.assertEqual(json.loads(out)["count"], 0)
        code, out, _ = run_cli(
            [
                "query",
                "--project-id", PID,
                "--scope", "workspace_local",
                "--workspace-id", WID,
                "--code-file", "src/calculator.py",
            ],
            store=self.store,
        )
        self.assertEqual(json.loads(out)["count"], 1)


class TestRegistryResolution(unittest.TestCase):
    def test_save_resolves_project_and_workspace_by_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry_path = os.path.join(tmp, "registry.json")
            repo_dir = os.path.join(tmp, "repo")
            os.makedirs(repo_dir)
            registry = Registry(registry_path)
            workspace = registry.register_workspace(
                repo_dir, explicit_identity("cli-test-project")
            )
            store = InMemoryStore()
            code, out, err = run_cli(
                [
                    "save",
                    "--path", repo_dir,
                    "--registry", registry_path,
                    "--memory-type", "discovery",
                    "--title", "Found thing",
                    "--content", "details",
                ],
                store=store,
            )
            self.assertEqual(code, 0, err)
            memory = json.loads(out)["memory"]
            self.assertEqual(memory["project_id"], workspace.project_id)
            self.assertEqual(memory["workspace_id"], workspace.workspace_id)
            self.assertEqual(
                memory["repository_identity"]["value"], REPO_VALUE
            )
            self.assertEqual(
                store.saved_args[0]["project"], workspace.project_id
            )

    def test_save_unregistered_path_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry_path = os.path.join(tmp, "registry.json")
            Registry(registry_path).save()
            code, _, err = run_cli(
                [
                    "save",
                    "--path", tmp,
                    "--registry", registry_path,
                    "--memory-type", "bug",
                    "--title", "T",
                    "--content", "B",
                ],
                store=InMemoryStore(),
            )
            self.assertEqual(code, 2)
            self.assertIn("error", json.loads(err))

    def test_project_id_mismatch_with_registry_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry_path = os.path.join(tmp, "registry.json")
            repo_dir = os.path.join(tmp, "repo")
            os.makedirs(repo_dir)
            registry = Registry(registry_path)
            registry.register_workspace(repo_dir, explicit_identity("p"))
            code, _, err = run_cli(
                [
                    "save",
                    "--path", repo_dir,
                    "--registry", registry_path,
                    "--project-id", PID,
                    "--memory-type", "bug",
                    "--title", "T",
                    "--content", "B",
                ],
                store=InMemoryStore(),
            )
            self.assertEqual(code, 1)
            self.assertIn("error", json.loads(err))


@unittest.skipUnless(
    os.environ.get("RELINKRA_ENGRAM_INTEGRATION"),
    "real Engram integration (set RELINKRA_ENGRAM_INTEGRATION=1)",
)
class TestEngramIntegration(unittest.TestCase):
    """Opt-in roundtrip against the real engram binary, fully isolated.

    ENGRAM_DATA_DIR points at a TemporaryDirectory for the subprocess
    environment, so the global ~/.engram/engram.db is never touched and
    the global :7437 server is never required or consulted.

    Two read-path scenarios are pinned:

    - With only ENGRAM_DATA_DIR isolation (ENGRAM_URL absent), the
      adapter's loopback server engages over that same data dir, so the
      saved memory round-trips with FULL content: found by the query,
      skipped_malformed == 0.
    - With ENGRAM_URL="" (hard-off), reads degrade to the CLI text
      output; the truncated envelope cannot parse, so it is reported as
      skipped_truncated >= 1 while skipped_malformed stays 0 — transport
      loss counted honestly, not as corruption. The tests assert both
      that writes landed in the scratch dir and that the global DB mtime
      did not change.
    """

    GLOBAL_DB = os.path.join(os.path.expanduser("~"), ".engram", "engram.db")

    def setUp(self):
        if shutil.which("engram") is None:
            self.skipTest("engram binary not available on PATH")
        self._scratch = tempfile.TemporaryDirectory()
        self.addCleanup(_cleanup_tmp_dir, self._scratch)
        self.addCleanup(_close_all_loopbacks)
        env_patch = mock.patch.dict(
            os.environ, {"ENGRAM_DATA_DIR": self._scratch.name}
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        # ENGRAM_URL must be absent for the loopback tier to engage;
        # restore whatever the outer environment had afterwards.
        self._saved_engram_url = os.environ.pop("ENGRAM_URL", None)
        self.addCleanup(self._restore_engram_url)
        self._global_mtime_before = self._global_db_mtime()

    def _restore_engram_url(self):
        if self._saved_engram_url is None:
            os.environ.pop("ENGRAM_URL", None)
        else:
            os.environ["ENGRAM_URL"] = self._saved_engram_url

    @classmethod
    def _global_db_mtime(cls):
        if os.path.exists(cls.GLOBAL_DB):
            return os.path.getmtime(cls.GLOBAL_DB)
        return None

    def _assert_writes_stayed_local(self):
        self.assertTrue(
            os.path.exists(os.path.join(self._scratch.name, "engram.db")),
            "writes must land in the scratch ENGRAM_DATA_DIR",
        )
        self.assertEqual(
            self._global_db_mtime(),
            self._global_mtime_before,
            "global ~/.engram/engram.db must not be modified",
        )

    def test_roundtrip_with_loopback_read_path(self):
        # No explicit http_url + isolated data dir -> loopback engages.
        store = EngramCLIAdapter()
        self.assertTrue(store.allow_loopback)
        code, out, err = cli_save(store, title="Integration probe", content="body")
        self.assertEqual(code, 0, err)
        saved = json.loads(out)["memory"]
        pid = saved["project_id"]
        records = store.search_records(query="rlkmem1", project=pid, limit=25)
        self.assertEqual(store.read_mode, "loopback")
        match = next(
            (r for r in records if r.title == "Integration probe"), None
        )
        self.assertIsNotNone(
            match, "saved memory must be findable via engram search"
        )
        # Full-fidelity proof: the record handed back parses completely.
        self.assertFalse(match.content.endswith("..."))
        self.assertEqual(json.loads(match.content)["v"], "rlkmem1")
        code, out, _ = run_cli(
            ["query", "--project-id", pid, "--scope", "project_shared"],
            store=store,
        )
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertIn(
            "Integration probe",
            [m["title"] for m in payload["memories"]],
        )
        self.assertEqual(payload["skipped_malformed"], 0)
        self.assertEqual(payload.get("skipped_truncated"), 0)
        self._assert_writes_stayed_local()

    def test_roundtrip_hard_off_degrades_honestly(self):
        env_patch = mock.patch.dict(os.environ, {"ENGRAM_URL": ""})
        env_patch.start()
        self.addCleanup(env_patch.stop)
        store = EngramCLIAdapter(http_url="")
        self.assertFalse(store.allow_loopback)
        code, out, err = cli_save(store, title="Integration probe", content="body")
        self.assertEqual(code, 0, err)
        pid = json.loads(out)["memory"]["project_id"]
        code, out, _ = run_cli(
            ["query", "--project-id", pid, "--scope", "project_shared"],
            store=store,
        )
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertNotIn(
            "Integration probe",
            [m["title"] for m in payload["memories"]],
        )
        # Transport loss counted honestly: truncated, not malformed.
        self.assertGreaterEqual(payload["skipped_truncated"], 1)
        self.assertEqual(payload["skipped_malformed"], 0)
        self._assert_writes_stayed_local()


if __name__ == "__main__":
    unittest.main()
