"""R5E.2B PART A — indexing orchestration tests (mocked, no real CBM binary).

Covers relinkra/cbm_indexing.py: workspace resolution, cache planning,
gitignore heuristics, the index CLI wrapper (flags-only argv), idempotent
mapping registration, freshness classification, and quirk recovery. CBM
is mocked at the subprocess/adapter seams; the real-binary CLI proof is
PART B.
"""

from __future__ import annotations

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

from relinkra import cbm_indexing
from relinkra.cbm_adapter import CBMAdapterError, CBMProjectNotIndexedError
from relinkra.cbm_indexing import (
    MalformedIndexResponseError,
    StaleAfterRefreshError,
    IndexSetupError,
)
from relinkra.cbm_support import absolutize_against_root
from relinkra.identity import GitError
from relinkra.registry import Registry

BIN = "C:/fake/codebase-memory-mcp.exe"
HEAD = "a" * 40
OLD_HEAD = "b" * 40
PROJECT = "C-proj"


class TempCase(unittest.TestCase):
    def make_temp_dir(self) -> str:
        path = tempfile.mkdtemp(prefix="rlk-cbm-idx-")
        self.addCleanup(shutil.rmtree, path, ignore_errors=True)
        return path


def _forbidden_adapter(**kwargs):
    raise AssertionError("CBMCLIAdapter must not be constructed on this path")


class FakeAdapter:
    """Stateful read-only adapter double.

    ``heads`` is consumed left to right; the last value repeats, so
    [OLD, NEW] models the quirk (stale before recovery, fresh after)
    and [OLD] models permanently stale.
    """

    def __init__(self, heads, changed_count=0, head_error=None, changes_error=None):
        self._heads = list(heads)
        self.changed_count = changed_count
        self.head_error = head_error
        self.changes_error = changes_error
        self.head_calls = 0
        self.changes_calls = 0

    def graph_index_head(self):
        self.head_calls += 1
        if self.head_error is not None:
            raise self.head_error
        if len(self._heads) > 1:
            return self._heads.pop(0)
        return self._heads[0]

    def detect_changes(self):
        self.changes_calls += 1
        if self.changes_error is not None:
            raise self.changes_error
        return {"changed_count": self.changed_count, "changed_files": []}


def _adapter_factory(fake, captured=None):
    def factory(**kwargs):
        if captured is not None:
            captured.update(kwargs)
        return fake

    return factory


class TestResolveWorkspace(TempCase):
    def test_resolves_root_and_project_id(self):
        tmp = self.make_temp_dir()
        repo = git_fixtures.make_repo(os.path.join(tmp, "repo"))
        git_fixtures.commit_file(repo, "README.md", "hello\n", "initial")
        root, project_id = cbm_indexing.resolve_workspace(repo)
        self.assertEqual(os.path.realpath(root), os.path.realpath(repo))
        self.assertRegex(project_id, r"^rlk_[0-9a-f]{32}$")

    def test_resolves_from_nested_subdirectory_by_walking_up(self):
        tmp = self.make_temp_dir()
        repo = git_fixtures.make_repo(os.path.join(tmp, "repo"))
        git_fixtures.commit_file(repo, "README.md", "hello\n", "initial")
        nested = os.path.join(repo, "pkg", "deep")
        os.makedirs(nested)
        root, _ = cbm_indexing.resolve_workspace(nested)
        self.assertEqual(os.path.realpath(root), os.path.realpath(repo))

    def test_non_git_path_raises_typed_error(self):
        plain = self.make_temp_dir()
        with self.assertRaises(IndexSetupError) as ctx:
            cbm_indexing.resolve_workspace(plain)
        self.assertIn("git", str(ctx.exception).lower())

    def test_repo_without_commits_raises_typed_error(self):
        tmp = self.make_temp_dir()
        repo = git_fixtures.make_repo(os.path.join(tmp, "empty"))
        with self.assertRaises(IndexSetupError):
            cbm_indexing.resolve_workspace(repo)


class TestPlanCache(TempCase):
    def test_cache_path_shape_and_record_string(self):
        tmp = self.make_temp_dir()
        cache_dir, record = cbm_indexing.plan_cache(tmp)
        self.assertIsInstance(cache_dir, Path)
        self.assertTrue(cache_dir.is_absolute())
        self.assertEqual(cache_dir, Path(tmp) / ".codebase-memory" / "cache")
        self.assertEqual(record, ".codebase-memory/cache")

    def test_does_not_create_anything(self):
        tmp = self.make_temp_dir()
        cbm_indexing.plan_cache(tmp)
        self.assertFalse((Path(tmp) / ".codebase-memory").exists())


class TestGitignoreCheck(TempCase):
    IGNORE_FORMS = (
        ".codebase-memory/",
        ".codebase-memory",
        ".codebase-memory/cache",
    )

    def test_three_ignore_line_forms_are_detected(self):
        for entry in self.IGNORE_FORMS:
            with self.subTest(entry=entry):
                tmp = self.make_temp_dir()
                Path(tmp, ".gitignore").write_text("*.pyc\nbuild/\n", encoding="utf-8")
                with Path(tmp, ".gitignore").open("a", encoding="utf-8") as fh:
                    fh.write(f"{entry}\n")
                self.assertEqual(cbm_indexing.gitignore_check(tmp), {"ignored": True})

    def test_not_ignored_without_matching_line(self):
        tmp = self.make_temp_dir()
        Path(tmp, ".gitignore").write_text("*.pyc\nbuild/\n", encoding="utf-8")
        self.assertEqual(cbm_indexing.gitignore_check(tmp), {"ignored": False})

    def test_not_ignored_when_no_ignore_files_exist(self):
        tmp = self.make_temp_dir()
        self.assertEqual(cbm_indexing.gitignore_check(tmp), {"ignored": False})
        self.assertFalse((Path(tmp) / ".gitignore").exists())

    def test_git_info_exclude_is_honored(self):
        tmp = self.make_temp_dir()
        exclude = Path(tmp, ".git", "info", "exclude")
        exclude.parent.mkdir(parents=True)
        exclude.write_text(".codebase-memory/\n", encoding="utf-8")
        self.assertEqual(cbm_indexing.gitignore_check(tmp), {"ignored": True})

    def test_is_strictly_read_only(self):
        tmp = self.make_temp_dir()
        gitignore = Path(tmp, ".gitignore")
        gitignore.write_text("target/\n.codebase-memory/\n", encoding="utf-8")
        exclude = Path(tmp, ".git", "info", "exclude")
        exclude.parent.mkdir(parents=True)
        exclude.write_text("notes/\n", encoding="utf-8")
        before_gitignore = gitignore.read_bytes()
        before_exclude = exclude.read_bytes()
        cbm_indexing.gitignore_check(tmp)
        cbm_indexing.gitignore_check(self.make_temp_dir())
        self.assertEqual(gitignore.read_bytes(), before_gitignore)
        self.assertEqual(exclude.read_bytes(), before_exclude)
        self.assertEqual(
            sorted(os.listdir(Path(tmp, ".git", "info"))), ["exclude"]
        )


def _completed(rc=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(
        args=["cbm"], returncode=rc, stdout=stdout, stderr=stderr
    )


class TestRunIndex(TempCase):
    SUCCESS_STDOUT = (
        'level=info msg="scanning repository" repo=.\n'
        'level=info msg="building graph" mode=fast\n'
        '{"project": "C-tmp-repo", "status": "indexed", "nodes": 12, "edges": 30}\n'
    )

    def _run(self, **kwargs):
        tmp = self.make_temp_dir()
        defaults = dict(
            binary=BIN,
            root=tmp,
            cache_dir=os.path.join(tmp, ".codebase-memory", "cache"),
            mode="fast",
        )
        defaults.update(kwargs)
        return cbm_indexing.run_index(**defaults)

    def test_success_parses_json_after_log_lines(self):
        tmp = self.make_temp_dir()
        cache = os.path.join(tmp, ".codebase-memory", "cache")
        with mock.patch("relinkra.cbm_indexing.subprocess.run") as run:
            run.return_value = _completed(stdout=self.SUCCESS_STDOUT)
            result = cbm_indexing.run_index(BIN, tmp, cache)
        self.assertEqual(
            result,
            {
                "project_name": "C-tmp-repo",
                "nodes": 12,
                "edges": 30,
                "raw_status": "indexed",
            },
        )
        argv = run.call_args.args[0]
        # Flags syntax ONLY: tool name at its fixed position, then --flag
        # value pairs; a raw-JSON positional would crash CBM 0.9.0.
        self.assertEqual(argv[0], BIN)
        self.assertEqual(argv[1], "cli")
        self.assertEqual(argv[2], "index_repository")
        self.assertEqual(argv[3], "--repo-path")
        self.assertEqual(argv[4], str(tmp))
        self.assertEqual(argv[5], "--mode")
        self.assertEqual(argv[6], "fast")
        self.assertEqual(len(argv), 7)
        self.assertFalse(
            any(arg.startswith(("{", "[")) for arg in argv),
            f"raw-JSON positional leaked into argv: {argv}",
        )
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(kwargs["timeout"], 600.0)
        self.assertEqual(kwargs["env"]["CBM_CACHE_DIR"], str(cache))
        self.assertLessEqual(
            set(kwargs["env"]),
            {
                "PATH",
                "SystemRoot",
                "WINDIR",
                "LC_ALL",
                "LANG",
                "CBM_CACHE_DIR",
                "GIT_CONFIG_COUNT",
                "GIT_CONFIG_KEY_0",
                "GIT_CONFIG_VALUE_0",
            },
        )

    def test_missing_project_field_is_malformed(self):
        with mock.patch("relinkra.cbm_indexing.subprocess.run") as run:
            run.return_value = _completed(
                stdout='{"status": "indexed", "nodes": 3, "edges": 4}\n'
            )
            with self.assertRaises(MalformedIndexResponseError) as ctx:
                self._run()
        self.assertIn("project", str(ctx.exception))

    def test_status_not_indexed_is_malformed(self):
        with mock.patch("relinkra.cbm_indexing.subprocess.run") as run:
            run.return_value = _completed(
                stdout='{"project": "p", "status": "partial"}\n'
            )
            with self.assertRaises(MalformedIndexResponseError) as ctx:
                self._run()
        self.assertIn("status", str(ctx.exception))

    def test_error_envelope_is_index_setup_error(self):
        with mock.patch("relinkra.cbm_indexing.subprocess.run") as run:
            run.return_value = _completed(
                stdout='{"error": "repository path is not a git repository"}\n'
            )
            with self.assertRaises(IndexSetupError) as ctx:
                self._run()
        self.assertIn("not a git repository", str(ctx.exception))
        self.assertNotIsInstance(ctx.exception, MalformedIndexResponseError)

    def test_nonzero_exit_sanitizes_stderr_tail(self):
        stderr = (
            "fatal: remote https://user:hunter2@example.invalid/x.git "
            'unreachable\n{"error": "index_repository crashed"}'
        )
        with mock.patch("relinkra.cbm_indexing.subprocess.run") as run:
            run.return_value = _completed(rc=1, stderr=stderr)
            with self.assertRaises(IndexSetupError) as ctx:
                self._run()
        message = str(ctx.exception)
        self.assertIn("index_repository crashed", message)
        self.assertNotIn("hunter2", message)
        self.assertNotIsInstance(ctx.exception, MalformedIndexResponseError)

    def test_timeout_is_typed_error(self):
        with mock.patch("relinkra.cbm_indexing.subprocess.run") as run:
            run.side_effect = subprocess.TimeoutExpired(cmd="cbm", timeout=600)
            with self.assertRaises(IndexSetupError) as ctx:
                self._run(timeout=7.5)
        self.assertIn("timed out", str(ctx.exception))

    def test_nodes_edges_default_to_zero_and_coerce(self):
        with mock.patch("relinkra.cbm_indexing.subprocess.run") as run:
            run.return_value = _completed(
                stdout='{"project": "p", "status": "indexed", "nodes": "42"}\n'
            )
            result = self._run()
        self.assertEqual(result["nodes"], 42)
        self.assertEqual(result["edges"], 0)

    def test_missing_binary_is_typed_error(self):
        with mock.patch("relinkra.cbm_indexing.subprocess.run") as run:
            run.side_effect = FileNotFoundError("nope")
            with self.assertRaises(IndexSetupError):
                self._run()


class TestRegisterMapping(TempCase):
    def _repo(self) -> str:
        tmp = self.make_temp_dir()
        repo = git_fixtures.make_repo(os.path.join(tmp, "repo"))
        git_fixtures.commit_file(repo, "README.md", "hello\n", "initial")
        return repo

    def test_registers_workspace_with_cbm_record(self):
        tmp = self.make_temp_dir()
        repo = self._repo()
        registry_path = os.path.join(tmp, "registry.json")
        workspace = cbm_indexing.register_mapping(
            registry_path, repo, PROJECT, ".codebase-memory/cache", "0.9.0", "ab" * 32
        )
        record = workspace["cbm"]
        self.assertEqual(record["project_name"], PROJECT)
        self.assertEqual(record["cache_dir"], ".codebase-memory/cache")
        self.assertTrue(record["db_path"].endswith(f"{PROJECT}.db"))
        self.assertEqual(record["binary"]["version"], "0.9.0")
        self.assertEqual(record["binary"]["sha256"], "ab" * 32)
        head = git_fixtures.git(repo, "rev-parse", "HEAD")
        self.assertEqual(workspace["git"]["head_sha"], head)
        self.assertTrue(workspace["git"]["branch"])

    def test_re_register_is_idempotent_and_updates_record(self):
        tmp = self.make_temp_dir()
        repo = self._repo()
        registry_path = os.path.join(tmp, "registry.json")
        cbm_indexing.register_mapping(
            registry_path, repo, PROJECT, ".codebase-memory/cache", "0.9.0", "ab" * 32
        )
        workspace = cbm_indexing.register_mapping(
            registry_path, repo, PROJECT, ".codebase-memory/cache", "0.9.0", "cd" * 32
        )
        self.assertEqual(workspace["cbm"]["binary"]["sha256"], "cd" * 32)
        registry = Registry(registry_path)
        self.assertEqual(len(registry.projects), 1)
        self.assertEqual(len(registry.workspaces), 1)
        [stored] = registry.list_workspaces()
        self.assertEqual(stored["cbm"]["binary"]["sha256"], "cd" * 32)
        self.assertEqual(stored["cbm"]["project_name"], PROJECT)

    def test_registry_failure_is_wrapped_as_typed_error(self):
        tmp = self.make_temp_dir()
        repo = self._repo()
        registry_path = os.path.join(tmp, "registry.json")
        Path(registry_path).write_text("not json{", encoding="utf-8")
        with self.assertRaises(IndexSetupError) as ctx:
            cbm_indexing.register_mapping(
                registry_path, repo, PROJECT, ".codebase-memory/cache", None, None
            )
        self.assertIn("registry", str(ctx.exception).lower())


class TestFreshnessState(TempCase):
    RECORD = {"project_name": PROJECT, "cache_dir": ".codebase-memory/cache"}

    #: A trusted-platform fixture so the provenance gate (R5E.2B trust
    #: correction) passes and the freshness probes run against the fake
    #: adapter, exactly like a certified binary on a real platform.
    TRUSTED_SHA = "a" * 64

    def setUp(self):
        super().setUp()
        patches = (
            mock.patch.object(
                cbm_indexing,
                "CERTIFIED_CBM_BINARIES",
                {"test-amd64": {"sha256": self.TRUSTED_SHA}},
            ),
            mock.patch.object(cbm_indexing, "platform_tag", lambda: "test-amd64"),
            mock.patch.object(
                cbm_indexing, "_sha256_file", lambda path: self.TRUSTED_SHA
            ),
        )
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_untrusted_binary_is_untrusted_without_probing(self):
        root = self._root_with_db()
        with mock.patch.object(
            cbm_indexing, "_sha256_file", lambda path: "b" * 64
        ), mock.patch.object(cbm_indexing, "CBMCLIAdapter", _forbidden_adapter):
            state = cbm_indexing.freshness_state(BIN, root, self.RECORD)
        self.assertEqual(
            state,
            {
                "state": "UNTRUSTED",
                "committed_drift": None,
                "worktree_drift": None,
            },
        )

    def _root_with_db(self) -> str:
        root = self.make_temp_dir()
        cache = absolutize_against_root(root, ".codebase-memory/cache")
        os.makedirs(cache)
        Path(cache, f"{PROJECT}.db").write_bytes(b"sqlite")
        return root

    def test_no_binary_is_unavailable_without_touching_the_adapter(self):
        root = self.make_temp_dir()
        with mock.patch.object(
            cbm_indexing, "CBMCLIAdapter", _forbidden_adapter
        ):
            for binary in (None, "", "  "):
                with self.subTest(binary=binary):
                    self.assertEqual(
                        cbm_indexing.freshness_state(binary, root, self.RECORD),
                        {"state": "UNAVAILABLE", "committed_drift": None, "worktree_drift": None},
                    )

    def test_platform_without_certified_provenance_is_unsupported(self):
        root = self._root_with_db()
        with mock.patch.object(
            cbm_indexing, "CERTIFIED_CBM_BINARIES", {"otherplatform-amd64": {}}
        ), mock.patch.object(cbm_indexing, "CBMCLIAdapter", _forbidden_adapter):
            state = cbm_indexing.freshness_state(BIN, root, self.RECORD)
        self.assertEqual(state["state"], "UNSUPPORTED")
        self.assertIsNone(state["committed_drift"])
        self.assertIsNone(state["worktree_drift"])

    def test_missing_db_file_is_missing_without_probing_the_backend(self):
        root = self.make_temp_dir()
        with mock.patch.object(
            cbm_indexing, "CBMCLIAdapter", _forbidden_adapter
        ):
            state = cbm_indexing.freshness_state(BIN, root, self.RECORD)
        self.assertEqual(state["state"], "MISSING")
        self.assertIsNone(state["committed_drift"])
        self.assertIsNone(state["worktree_drift"])

    def test_stored_head_match_and_clean_worktree_is_ready(self):
        root = self._root_with_db()
        cache = absolutize_against_root(root, ".codebase-memory/cache")
        fake = FakeAdapter(heads=[HEAD], changed_count=0)
        captured = {}
        with mock.patch.object(
            cbm_indexing, "CBMCLIAdapter", _adapter_factory(fake, captured)
        ), mock.patch.object(cbm_indexing, "git_head_sha", lambda r: HEAD):
            state = cbm_indexing.freshness_state(BIN, root, self.RECORD)
        self.assertEqual(
            state,
            {"state": "READY", "committed_drift": False, "worktree_drift": False},
        )
        self.assertEqual(captured["cbm_bin"], BIN)
        self.assertEqual(captured["cbm_project_name"], PROJECT)
        self.assertEqual(captured["cache_dir"], cache)
        self.assertEqual(captured["workspace_root"], root)

    def test_stored_head_mismatch_is_stale_committed(self):
        root = self._root_with_db()
        fake = FakeAdapter(heads=[OLD_HEAD], changed_count=0)
        with mock.patch.object(
            cbm_indexing, "CBMCLIAdapter", _adapter_factory(fake)
        ), mock.patch.object(cbm_indexing, "git_head_sha", lambda r: HEAD):
            state = cbm_indexing.freshness_state(BIN, root, self.RECORD)
        self.assertEqual(state["state"], "STALE_COMMITTED")
        self.assertTrue(state["committed_drift"])
        self.assertFalse(state["worktree_drift"])

    def test_changed_files_is_stale_worktree(self):
        root = self._root_with_db()
        fake = FakeAdapter(heads=[HEAD], changed_count=3)
        with mock.patch.object(
            cbm_indexing, "CBMCLIAdapter", _adapter_factory(fake)
        ), mock.patch.object(cbm_indexing, "git_head_sha", lambda r: HEAD):
            state = cbm_indexing.freshness_state(BIN, root, self.RECORD)
        self.assertEqual(state["state"], "STALE_WORKTREE")
        self.assertFalse(state["committed_drift"])
        self.assertTrue(state["worktree_drift"])

    def test_both_drifts_is_stale_both(self):
        root = self._root_with_db()
        fake = FakeAdapter(heads=[OLD_HEAD], changed_count=1)
        with mock.patch.object(
            cbm_indexing, "CBMCLIAdapter", _adapter_factory(fake)
        ), mock.patch.object(cbm_indexing, "git_head_sha", lambda r: HEAD):
            state = cbm_indexing.freshness_state(BIN, root, self.RECORD)
        self.assertEqual(state["state"], "STALE_BOTH")
        self.assertTrue(state["committed_drift"])
        self.assertTrue(state["worktree_drift"])

    def test_adapter_outage_is_unknown_never_ready(self):
        root = self._root_with_db()
        fake = FakeAdapter(
            heads=[HEAD], head_error=CBMAdapterError("cbm query_graph failed: outage")
        )
        with mock.patch.object(
            cbm_indexing, "CBMCLIAdapter", _adapter_factory(fake)
        ), mock.patch.object(cbm_indexing, "git_head_sha", lambda r: HEAD):
            state = cbm_indexing.freshness_state(BIN, root, self.RECORD)
        self.assertEqual(
            state,
            {"state": "UNKNOWN", "committed_drift": None, "worktree_drift": None},
        )

    def test_not_indexed_probe_with_db_present_is_missing(self):
        root = self._root_with_db()
        fake = FakeAdapter(
            heads=[],
            head_error=CBMProjectNotIndexedError("project not found or not indexed"),
        )
        with mock.patch.object(
            cbm_indexing, "CBMCLIAdapter", _adapter_factory(fake)
        ):
            state = cbm_indexing.freshness_state(BIN, root, self.RECORD)
        self.assertEqual(state["state"], "MISSING")
        self.assertIsNone(state["committed_drift"])

    def test_no_stored_branch_head_is_unknown(self):
        root = self._root_with_db()
        fake = FakeAdapter(heads=[None])
        with mock.patch.object(
            cbm_indexing, "CBMCLIAdapter", _adapter_factory(fake)
        ), mock.patch.object(cbm_indexing, "git_head_sha", lambda r: HEAD):
            state = cbm_indexing.freshness_state(BIN, root, self.RECORD)
        self.assertEqual(state["state"], "UNKNOWN")

    def test_git_error_is_unknown(self):
        root = self._root_with_db()
        fake = FakeAdapter(heads=[HEAD])
        def _boom(_root):
            raise GitError("git rev-parse HEAD failed")

        with mock.patch.object(
            cbm_indexing, "CBMCLIAdapter", _adapter_factory(fake)
        ), mock.patch.object(cbm_indexing, "git_head_sha", _boom):
            state = cbm_indexing.freshness_state(BIN, root, self.RECORD)
        self.assertEqual(
            state,
            {"state": "UNKNOWN", "committed_drift": None, "worktree_drift": None},
        )

    def test_malformed_record_is_unknown(self):
        root = self._root_with_db()
        for record in (None, {}, {"project_name": PROJECT}, {"cache_dir": "c"}):
            with self.subTest(record=record):
                self.assertEqual(
                    cbm_indexing.freshness_state(BIN, root, record)["state"],
                    "UNKNOWN",
                )

    def test_cache_dir_outside_managed_subtree_is_unknown(self):
        root = self._root_with_db()
        record = {"project_name": PROJECT, "cache_dir": "../escape"}
        self.assertEqual(
            cbm_indexing.freshness_state(BIN, root, record)["state"], "UNKNOWN"
        )


class TestRefreshWithQuirkRecovery(TempCase):
    RESULT = {
        "project_name": PROJECT,
        "nodes": 5,
        "edges": 9,
        "raw_status": "indexed",
    }

    def _cache_with(self, *names) -> tuple:
        tmp = self.make_temp_dir()
        cache = os.path.join(tmp, ".codebase-memory", "cache")
        os.makedirs(cache)
        for name in names:
            Path(cache, name).write_bytes(name.encode("utf-8"))
        return tmp, cache

    def test_happy_path_needs_no_recovery(self):
        tmp, cache = self._cache_with(f"{PROJECT}.db")
        fake = FakeAdapter(heads=[HEAD])
        run_mock = mock.Mock(return_value=dict(self.RESULT))
        with mock.patch.object(
            cbm_indexing, "CBMCLIAdapter", _adapter_factory(fake)
        ), mock.patch.object(cbm_indexing, "git_head_sha", lambda r: HEAD), mock.patch.object(
            cbm_indexing, "run_index", run_mock
        ):
            out = cbm_indexing.refresh_with_quirk_recovery(BIN, tmp, cache, PROJECT)
        self.assertFalse(out["quirk_recovery_used"])
        self.assertEqual(out["result"], self.RESULT)
        run_mock.assert_called_once()
        self.assertEqual(run_mock.call_args.args, (BIN, tmp, cache))
        self.assertEqual(fake.head_calls, 1)
        self.assertTrue(os.path.isfile(os.path.join(cache, f"{PROJECT}.db")))

    def test_quirk_recovery_deletes_only_db_and_companions(self):
        names = (
            f"{PROJECT}.db",
            f"{PROJECT}.db-wal",
            f"{PROJECT}.db-shm",
            "sentinel.txt",
            "Other.db",
            f"{PROJECT}-notes.txt",
        )
        tmp, cache = self._cache_with(*names)
        fake = FakeAdapter(heads=[OLD_HEAD, HEAD])
        run_mock = mock.Mock(return_value=dict(self.RESULT))
        with mock.patch.object(
            cbm_indexing, "CBMCLIAdapter", _adapter_factory(fake)
        ), mock.patch.object(cbm_indexing, "git_head_sha", lambda r: HEAD), mock.patch.object(
            cbm_indexing, "run_index", run_mock
        ):
            out = cbm_indexing.refresh_with_quirk_recovery(BIN, tmp, cache, PROJECT)
        self.assertTrue(out["quirk_recovery_used"])
        self.assertEqual(out["result"], self.RESULT)
        self.assertEqual(run_mock.call_count, 2)
        self.assertEqual(fake.head_calls, 2)
        # Exactly the three candidates were deleted; everything else —
        # including another project's db and a same-prefix file — survives.
        self.assertEqual(
            set(os.listdir(cache)),
            {"sentinel.txt", "Other.db", f"{PROJECT}-notes.txt"},
        )

    def test_still_stale_after_one_recovery_raises(self):
        tmp, cache = self._cache_with(
            f"{PROJECT}.db", f"{PROJECT}.db-wal", f"{PROJECT}.db-shm", "sentinel.txt"
        )
        fake = FakeAdapter(heads=[OLD_HEAD])
        run_mock = mock.Mock(return_value=dict(self.RESULT))
        with mock.patch.object(
            cbm_indexing, "CBMCLIAdapter", _adapter_factory(fake)
        ), mock.patch.object(cbm_indexing, "git_head_sha", lambda r: HEAD), mock.patch.object(
            cbm_indexing, "run_index", run_mock
        ):
            with self.assertRaises(StaleAfterRefreshError):
                cbm_indexing.refresh_with_quirk_recovery(BIN, tmp, cache, PROJECT)
        # Never more than one recovery: one initial index + one retry.
        self.assertEqual(run_mock.call_count, 2)
        self.assertEqual(fake.head_calls, 2)
        self.assertEqual(set(os.listdir(cache)), {"sentinel.txt"})

    def test_unsafe_project_name_refuses_and_deletes_nothing(self):
        for bad in ("nested/" + PROJECT, "..\\" + PROJECT, "..", "."):
            with self.subTest(project_name=bad):
                tmp, cache = self._cache_with("sentinel.txt", "keep.db")
                fake = FakeAdapter(heads=[OLD_HEAD, HEAD])
                run_mock = mock.Mock(return_value=dict(self.RESULT))
                with mock.patch.object(
                    cbm_indexing, "CBMCLIAdapter", _adapter_factory(fake)
                ), mock.patch.object(
                    cbm_indexing, "git_head_sha", lambda r: HEAD
                ), mock.patch.object(cbm_indexing, "run_index", run_mock):
                    with self.assertRaises(IndexSetupError) as ctx:
                        cbm_indexing.refresh_with_quirk_recovery(
                            BIN, tmp, cache, bad
                        )
                self.assertNotIsInstance(ctx.exception, StaleAfterRefreshError)
                self.assertEqual(run_mock.call_count, 1)
                self.assertEqual(set(os.listdir(cache)), {"sentinel.txt", "keep.db"})


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Real certified binary through the product CLI (gated, R5E.2B PART B)
# ---------------------------------------------------------------------------

import contextlib  # noqa: E402
import io  # noqa: E402
import json  # noqa: E402

from relinkra import product_cli  # noqa: E402


def _real_cbm_bin():
    """The main repo's managed certified binary (mirrors test_cbm_backend)."""
    candidate = REPO_ROOT / ".codebase-memory" / "bin" / "codebase-memory-mcp.exe"
    if candidate.is_file():
        return str(candidate)
    return os.environ.get("RELINKRA_CBM_BIN")


@unittest.skipUnless(
    _real_cbm_bin() and shutil.which("git"),
    "real CBM binary and git required",
)
class TestRealBinaryIndexingCycle(unittest.TestCase):
    """R5E.2B real-binary proof: the FULL user cycle through the product
    CLI surface on a throwaway git repo — status(MISSING) → index(READY)
    → status(READY) → worktree drift → status(STALE) → refresh(READY) →
    committed drift → status(STALE) → refresh(READY, quirk path allowed)
    → delete the project db → status(MISSING) — with the tracked tree
    verified unchanged except the deliberate, committed drift."""

    def setUp(self):
        work = tempfile.mkdtemp(prefix="rlk-r5e2b-cli-")
        self.addCleanup(shutil.rmtree, work, ignore_errors=True)
        repo = os.path.join(work, "repo")
        os.makedirs(repo)
        git_fixtures.make_repo(repo)
        # The documented setup: the derived cache and the local registry
        # are git-ignored. This matters beyond hygiene — CBM's real
        # detect_changes counts an untracked .codebase-memory/ as a
        # worktree change, so an un-ignored cache can never reach READY.
        git_fixtures.commit_files(
            repo,
            {
                ".gitignore": ".codebase-memory/\n.relinkra/\n",
                "calc.py": "def add(a, b):\n    return a + b\n",
                "util.py": "def label(text):\n    return text.strip()\n",
            },
            "initial",
        )
        self.repo = repo
        # The temp workspace has no managed .codebase-memory/bin of its
        # own, so feed the CLI's resolver the MAIN repo's certified
        # binary explicitly and restore the environment afterwards.
        self._previous_env = os.environ.get("RELINKRA_CBM_BIN")
        os.environ["RELINKRA_CBM_BIN"] = _real_cbm_bin()

        def _restore_env():
            if self._previous_env is None:
                os.environ.pop("RELINKRA_CBM_BIN", None)
            else:
                os.environ["RELINKRA_CBM_BIN"] = self._previous_env

        self.addCleanup(_restore_env)

    def _cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = product_cli.main(["cbm", *argv, "--path", self.repo])
        return code, out.getvalue(), err.getvalue()

    def test_full_cli_cycle(self):
        # 1. Never indexed: honest MISSING, exit 0, next action offered.
        code, out, err = self._cli("status")
        self.assertEqual(code, 0, err)
        self.assertIn("CBM: AVAILABLE", out)
        self.assertIn("Index: MISSING", out)
        self.assertIn("Next: relinkra cbm index", out)

        # 2. Index: READY with real counts, mapping registered, no slug
        #    in human output. The ignored cache means no WARN line (the
        #    un-ignored WARN branch is pinned by the mocked CLI tests).
        code, out, err = self._cli("index")
        self.assertEqual(code, 0, err)
        self.assertIn("Index: READY (", out)
        self.assertIn("nodes", out)
        self.assertNotIn("WARN:", out)
        registry_file = product_cli.registry_path(Path(self.repo))
        self.assertTrue(registry_file.is_file())
        registry = json.loads(registry_file.read_text(encoding="utf-8"))
        [workspace] = registry["workspaces"].values()
        slug = workspace["cbm"]["project_name"]
        self.assertEqual(workspace["cbm"]["cache_dir"], ".codebase-memory/cache")
        self.assertNotIn(slug, out)
        self.assertEqual(
            (Path(self.repo) / ".gitignore").read_text(encoding="utf-8"),
            ".codebase-memory/\n.relinkra/\n",
        )

        # 3. Status now sees the registered, fresh index.
        code, out, err = self._cli("status")
        self.assertEqual(code, 0, err)
        self.assertIn("Index: READY", out)
        self.assertNotIn("Next:", out)

        # 4. Uncommitted worktree drift → honest STALE, exit 0. Real CBM
        #    semantics: detect_changes reads the git worktree, so Next
        #    says commit first (no reindex can clear this drift).
        with open(os.path.join(self.repo, "util.py"), "a", encoding="utf-8") as fh:
            fh.write("def extra(text):\n    return text + \"!\"\n")
        code, out, err = self._cli("status")
        self.assertEqual(code, 0, err)
        self.assertIn("Index: STALE", out)
        self.assertIn("commit your changes", out)

        # 5. Refresh reindexes the current content into the graph but
        #    cannot clear uncommitted drift — exit 0 with the honest
        #    STALE state (proved on the real binary: even a full cache
        #    wipe leaves a modified file flagged until it is committed).
        code, out, err = self._cli("refresh")
        self.assertEqual(code, 0, err)
        self.assertIn("Index: STALE — uncommitted changes", out)
        self.assertIn("commit your changes", out)

        # 6. Committing converts the drift to committed drift; the
        #    worktree is clean again.
        git_fixtures.git(self.repo, "add", "util.py")
        git_fixtures.git(self.repo, "commit", "-qm", "drift")
        code, out, err = self._cli("status")
        self.assertEqual(code, 0, err)
        self.assertIn("Index: STALE", out)
        self.assertIn("Next: relinkra cbm refresh", out)

        # 7. Refresh clears committed drift — the pinned quirk recovery
        #    may or may not trigger (CBM 0.9.0 modify-only reindex
        #    keeps the stored head); either path must land on READY.
        code, out, err = self._cli("refresh")
        self.assertEqual(code, 0, err)
        self.assertIn("Index: READY (refreshed)", out)

        # 8. Deleting the derived db is an honest MISSING, never a lie.
        cache_dir = Path(self.repo) / ".codebase-memory" / "cache"
        for name in (f"{slug}.db", f"{slug}.db-wal", f"{slug}.db-shm"):
            target = cache_dir / name
            if target.exists():
                target.unlink()
        code, out, err = self._cli("status")
        self.assertEqual(code, 0, err)
        self.assertIn("Index: MISSING", out)

        # 9. The tracked tree is exactly the deliberate, committed
        #    drift; both managed directories stay ignored and nothing
        #    else in the tracked tree was touched.
        porcelain = git_fixtures.git(self.repo, "status", "--porcelain")
        self.assertEqual(porcelain.strip(), "")
