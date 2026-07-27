"""GitIntelligenceService tests for relinkra.git_intelligence (R2, B2).

Service-level tests exercise the real git binary against temp-repo fixtures
(tests/git_fixtures.py) — fully offline. subprocess-level spies are used
only where the behavior under test is the command surface itself
(allowlist, single-call co-change, limit clamping).
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime
from unittest import mock

import relinkra.git_intelligence as gi
from relinkra.git_intelligence import (
    GIT_COCHANGE_SCAN,
    GIT_FILE_HISTORY_MAX,
    GIT_MAX_COMMITS,
    GIT_SNIPPET_MAX_CHARS,
    GitFileChangeState,
    GitIntelligenceService,
)

try:  # discovery (`-s tests`) puts tests/ on sys.path; package form does not
    from tests import git_fixtures as gf
except ModuleNotFoundError:  # pragma: no cover - import-mode fallback
    import git_fixtures as gf


def _tmp_dir(test: unittest.TestCase) -> str:
    path = tempfile.mkdtemp(prefix="relinkra-git-svc-")
    test.addCleanup(lambda: __import__("shutil").rmtree(path, ignore_errors=True))
    return path


def _warning_codes(warnings) -> list:
    return [w.code for w in warnings]


class CapabilitiesTests(unittest.TestCase):
    """2.1: collect_capabilities + degraded matrix."""

    def setUp(self):
        self.service = GitIntelligenceService()

    def test_normal_repo_all_fields_populated(self):
        repo = gf.make_repo(os.path.join(_tmp_dir(self), "repo"))
        gf.commit_file(repo, "alpha.py", "alpha\n", "add alpha")
        caps, warnings = self.service.collect_capabilities(repo)
        self.assertTrue(caps.git_available)
        self.assertIsNotNone(caps.git_version)
        self.assertRegex(caps.git_version, r"^\d+\.\d+")
        self.assertTrue(caps.repository_detected)
        self.assertEqual(
            os.path.normpath(caps.repository_root), os.path.normpath(repo)
        )
        self.assertFalse(caps.is_bare)
        self.assertTrue(caps.head_available)
        self.assertEqual(warnings, [])

    def test_no_binary_via_path_patch(self):
        repo = gf.make_repo(os.path.join(_tmp_dir(self), "repo"))
        gf.commit_file(repo, "alpha.py", "alpha\n", "add alpha")
        empty_path = _tmp_dir(self)
        with mock.patch.dict(os.environ, {"PATH": empty_path}):
            caps, warnings = self.service.collect_capabilities(repo)
        self.assertFalse(caps.git_available)
        self.assertIsNone(caps.git_version)
        self.assertFalse(caps.repository_detected)
        self.assertIsNone(caps.repository_root)
        self.assertIn("git_unavailable", _warning_codes(warnings))

    def test_non_repo_directory(self):
        plain = _tmp_dir(self)
        caps, warnings = self.service.collect_capabilities(plain)
        self.assertTrue(caps.git_available)
        self.assertFalse(caps.repository_detected)
        self.assertIsNone(caps.repository_root)
        self.assertFalse(caps.head_available)
        self.assertIn("git_not_repository", _warning_codes(warnings))

    def test_unborn_head(self):
        repo = gf.make_repo(os.path.join(_tmp_dir(self), "repo"))
        caps, warnings = self.service.collect_capabilities(repo)
        self.assertTrue(caps.repository_detected)
        self.assertFalse(caps.head_available)
        self.assertEqual(warnings, [])

    def test_detached_head_still_available(self):
        repo = gf.make_repo(os.path.join(_tmp_dir(self), "repo"))
        sha = gf.commit_file(repo, "alpha.py", "alpha\n", "add alpha")
        gf.git(repo, "checkout", "-q", "--detach", sha)
        caps, warnings = self.service.collect_capabilities(repo)
        self.assertTrue(caps.repository_detected)
        self.assertTrue(caps.head_available)
        self.assertEqual(warnings, [])

    def test_bare_repo_detected(self):
        base = _tmp_dir(self)
        src = gf.make_repo(os.path.join(base, "src"))
        gf.commit_file(src, "alpha.py", "alpha\n", "add alpha")
        bare = gf.bare_fixture(src, os.path.join(base, "bare.git"))
        caps, warnings = self.service.collect_capabilities(bare)
        self.assertTrue(caps.repository_detected)
        self.assertTrue(caps.is_bare)
        self.assertTrue(caps.head_available)
        self.assertEqual(warnings, [])

    def test_nested_cwd_resolves_root(self):
        repo = gf.make_repo(os.path.join(_tmp_dir(self), "repo"))
        gf.commit_file(repo, "sub/dir/alpha.py", "alpha\n", "add alpha")
        nested = os.path.join(repo, "sub", "dir")
        caps, _ = self.service.collect_capabilities(nested)
        self.assertTrue(caps.repository_detected)
        self.assertEqual(
            os.path.normpath(caps.repository_root), os.path.normpath(repo)
        )

    def test_repository_root_never_serialized(self):
        repo = gf.make_repo(os.path.join(_tmp_dir(self), "repo"))
        gf.commit_file(repo, "alpha.py", "alpha\n", "add alpha")
        caps, _ = self.service.collect_capabilities(repo)
        self.assertNotIn("repository_root", caps.to_dict())


class WorkingTreeTests(unittest.TestCase):
    """2.2: collect_working_tree classification."""

    def setUp(self):
        self.service = GitIntelligenceService()
        self.repo = gf.make_repo(os.path.join(_tmp_dir(self), "repo"))

    def test_clean_repo(self):
        gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        tree, warnings = self.service.collect_working_tree(self.repo)
        self.assertTrue(tree.clean)
        for bucket in (
            tree.staged, tree.unstaged, tree.untracked,
            tree.deleted, tree.conflicted, tree.renamed,
        ):
            self.assertEqual(bucket, ())
        self.assertEqual(warnings, [])

    def test_staged_new_file(self):
        gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        gf._write_file(self.repo, "beta.py", "beta\n")
        gf.git(self.repo, "add", "--", "beta.py")
        tree, _ = self.service.collect_working_tree(self.repo)
        self.assertFalse(tree.clean)
        self.assertEqual(tree.staged, ("beta.py",))
        self.assertEqual(tree.unstaged, ())
        self.assertEqual(tree.untracked, ())

    def test_unstaged_modification(self):
        gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        gf._write_file(self.repo, "alpha.py", "alpha changed\n")
        tree, _ = self.service.collect_working_tree(self.repo)
        self.assertEqual(tree.unstaged, ("alpha.py",))
        self.assertEqual(tree.staged, ())

    def test_untracked_file(self):
        gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        gf._write_file(self.repo, "new file.py", "new\n")
        tree, _ = self.service.collect_working_tree(self.repo)
        self.assertEqual(tree.untracked, ("new file.py",))

    def test_deleted_file_worktree(self):
        gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        os.remove(os.path.join(self.repo, "alpha.py"))
        tree, _ = self.service.collect_working_tree(self.repo)
        self.assertEqual(tree.deleted, ("alpha.py",))
        self.assertEqual(tree.staged, ())

    def test_deleted_file_staged(self):
        gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        gf.git(self.repo, "rm", "-q", "--", "alpha.py")
        tree, _ = self.service.collect_working_tree(self.repo)
        self.assertEqual(tree.deleted, ("alpha.py",))

    def test_renamed_file(self):
        gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        gf.git(self.repo, "mv", "alpha.py", "delta.py")
        tree, _ = self.service.collect_working_tree(self.repo)
        self.assertEqual(tree.renamed, (("alpha.py", "delta.py"),))
        self.assertIn("delta.py", tree.staged)

    def test_conflicted_file(self):
        gf.conflict_fixture(self.repo)
        tree, _ = self.service.collect_working_tree(self.repo)
        self.assertEqual(tree.conflicted, ("alpha.py",))
        self.assertFalse(tree.clean)

    def test_unicode_and_space_paths_classified(self):
        gf.commit_file(self.repo, "seed.py", "seed\n", "seed")
        gf._write_file(self.repo, "a b/ñ.txt", "unicode\n")
        gf.git(self.repo, "add", "--", "a b/ñ.txt")
        tree, _ = self.service.collect_working_tree(self.repo)
        self.assertEqual(tree.staged, ("a b/ñ.txt",))

    def test_non_repo_returns_none_with_warning(self):
        tree, warnings = self.service.collect_working_tree(_tmp_dir(self))
        self.assertIsNone(tree)
        self.assertIn("git_not_repository", _warning_codes(warnings))


class RepositoryStateTests(unittest.TestCase):
    """2.2: collect_repository_state aggregate view."""

    def setUp(self):
        self.service = GitIntelligenceService()
        self.repo = gf.make_repo(os.path.join(_tmp_dir(self), "repo"))

    def test_clean_repo_state(self):
        sha = gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        state, warnings = self.service.collect_repository_state(self.repo)
        self.assertEqual(state.head_sha, sha)
        self.assertEqual(state.short_head_sha, sha[:7])
        self.assertEqual(state.branch, "main")
        self.assertFalse(state.detached)
        self.assertTrue(state.clean)
        self.assertEqual(
            state.to_dict()["counts"],
            {"staged": 0, "unstaged": 0, "untracked": 0, "conflicted": 0},
        )
        self.assertEqual(warnings, [])

    def test_ahead_behind_always_none_in_v1(self):
        gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        state, _ = self.service.collect_repository_state(self.repo)
        self.assertIsNone(state.ahead)
        self.assertIsNone(state.behind)

    def test_dirty_counts(self):
        gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        gf.commit_file(self.repo, "keep.py", "keep\n", "add keep")
        gf._write_file(self.repo, "staged.py", "staged\n")
        gf.git(self.repo, "add", "--", "staged.py")
        gf._write_file(self.repo, "alpha.py", "alpha changed\n")
        gf._write_file(self.repo, "untracked.py", "untracked\n")
        state, _ = self.service.collect_repository_state(self.repo)
        self.assertFalse(state.clean)
        self.assertEqual(state.staged_count, 1)
        self.assertEqual(state.unstaged_count, 1)
        self.assertEqual(state.untracked_count, 1)
        self.assertEqual(state.conflicted_count, 0)

    def test_conflicted_count(self):
        gf.conflict_fixture(self.repo)
        state, _ = self.service.collect_repository_state(self.repo)
        self.assertEqual(state.conflicted_count, 1)
        self.assertFalse(state.clean)

    def test_detached_state(self):
        sha = gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        gf.git(self.repo, "checkout", "-q", "--detach", sha)
        state, _ = self.service.collect_repository_state(self.repo)
        self.assertTrue(state.detached)
        self.assertIsNone(state.branch)
        self.assertEqual(state.head_sha, sha)

    def test_unborn_head_state(self):
        state, _ = self.service.collect_repository_state(self.repo)
        self.assertIsNone(state.head_sha)
        self.assertIsNone(state.branch)
        self.assertFalse(state.detached)
        self.assertTrue(state.clean)

    def test_bare_repo_state_skips_working_tree(self):
        base = _tmp_dir(self)
        src = gf.make_repo(os.path.join(base, "src"))
        gf.commit_file(src, "alpha.py", "alpha\n", "add alpha")
        bare = gf.bare_fixture(src, os.path.join(base, "bare.git"))
        state, warnings = self.service.collect_repository_state(bare)
        self.assertIsNotNone(state.head_sha)
        self.assertEqual(state.branch, "main")
        self.assertTrue(state.clean)
        self.assertEqual(warnings, [])

    def test_non_repo_returns_none_with_warning(self):
        state, warnings = self.service.collect_repository_state(_tmp_dir(self))
        self.assertIsNone(state)
        self.assertIn("git_not_repository", _warning_codes(warnings))


class HeadFactsTests(unittest.TestCase):
    """2.3: collect_head_facts — author_name only, redacted subject, ISO time."""

    def setUp(self):
        self.service = GitIntelligenceService()
        self.repo = gf.make_repo(os.path.join(_tmp_dir(self), "repo"))

    def test_root_commit_facts(self):
        sha = gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        head, warnings = self.service.collect_head_facts(self.repo)
        self.assertEqual(head.head_sha, sha)
        self.assertEqual(head.short_head_sha, sha[:7])
        self.assertEqual(head.branch, "main")
        self.assertFalse(head.detached)
        self.assertEqual(
            datetime.fromisoformat(head.committed_at),
            datetime.fromisoformat(gf.FIXED_COMMITTER_DATE),
        )
        self.assertEqual(head.author_name, gf.GIT_TEST_USER_NAME)
        self.assertEqual(head.subject, "add alpha")
        self.assertEqual(head.parents, ())
        self.assertEqual(warnings, [])

    def test_second_commit_parents(self):
        first = gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        second = gf.commit_file(self.repo, "beta.py", "beta\n", "add beta")
        head, _ = self.service.collect_head_facts(self.repo)
        self.assertEqual(head.head_sha, second)
        self.assertEqual(head.parents, (first,))

    def test_no_author_email_anywhere(self):
        gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        head, _ = self.service.collect_head_facts(self.repo)
        serialized = json.dumps(head.to_dict(), sort_keys=True)
        self.assertNotIn("email", serialized)
        self.assertNotIn(gf.GIT_TEST_USER_EMAIL, serialized)
        self.assertNotIn("@", serialized)

    def test_subject_with_token_is_redacted(self):
        gf.commit_file(
            self.repo, "alpha.py", "alpha\n", "leak ghp_abcdefghijklmnopqrstuvwxyz0123456789"
        )
        head, _ = self.service.collect_head_facts(self.repo)
        self.assertNotIn("ghp_", head.subject)
        self.assertIn("[REDACTED]", head.subject)

    def test_detached_head(self):
        sha = gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        gf.git(self.repo, "checkout", "-q", "--detach", sha)
        head, _ = self.service.collect_head_facts(self.repo)
        self.assertTrue(head.detached)
        self.assertIsNone(head.branch)
        self.assertEqual(head.head_sha, sha)

    def test_unborn_head_returns_none_with_warning(self):
        head, warnings = self.service.collect_head_facts(self.repo)
        self.assertIsNone(head)
        self.assertIn("git_command_failed", _warning_codes(warnings))

    def test_non_repo_returns_none_with_warning(self):
        head, warnings = self.service.collect_head_facts(_tmp_dir(self))
        self.assertIsNone(head)
        self.assertIn("git_not_repository", _warning_codes(warnings))


class DiffFactsTests(unittest.TestCase):
    """2.4: collect_diff — staged vs unstaged, numstat, binary, snippets."""

    def setUp(self):
        self.service = GitIntelligenceService()
        self.repo = gf.make_repo(os.path.join(_tmp_dir(self), "repo"))

    def test_unstaged_modification(self):
        gf.commit_file(self.repo, "alpha.py", "line1\nline2\n", "add alpha")
        gf._write_file(self.repo, "alpha.py", "line1\nline2 changed\nline3\n")
        facts, warnings = self.service.collect_diff(self.repo)
        self.assertEqual(len(facts), 1)
        fact = facts[0]
        self.assertEqual(fact.path, "alpha.py")
        self.assertEqual(fact.status, "modified")
        self.assertFalse(fact.staged)
        self.assertEqual((fact.insertions, fact.deletions), (2, 1))
        self.assertFalse(fact.binary)
        self.assertIsNone(fact.old_path)
        self.assertIsNone(fact.snippet)
        self.assertEqual(warnings, [])

    def test_staged_modification(self):
        gf.commit_file(self.repo, "alpha.py", "line1\n", "add alpha")
        gf._write_file(self.repo, "alpha.py", "line1\nline2\n")
        gf.git(self.repo, "add", "--", "alpha.py")
        facts, _ = self.service.collect_diff(self.repo)
        self.assertEqual(len(facts), 1)
        self.assertTrue(facts[0].staged)
        self.assertEqual(facts[0].status, "modified")
        self.assertEqual((facts[0].insertions, facts[0].deletions), (1, 0))

    def test_staged_and_unstaged_are_separate_facts(self):
        gf.commit_file(self.repo, "alpha.py", "base\n", "add alpha")
        gf._write_file(self.repo, "alpha.py", "base\nstaged\n")
        gf.git(self.repo, "add", "--", "alpha.py")
        gf._write_file(self.repo, "alpha.py", "base\nstaged\nunstaged\n")
        facts, _ = self.service.collect_diff(self.repo)
        by_staged = {f.staged: f for f in facts}
        self.assertEqual(set(by_staged), {True, False})
        self.assertEqual(by_staged[True].insertions, 1)
        self.assertEqual(by_staged[False].insertions, 1)

    def test_added_file_status(self):
        gf.commit_file(self.repo, "seed.py", "seed\n", "seed")
        gf._write_file(self.repo, "beta.py", "beta\n")
        gf.git(self.repo, "add", "--", "beta.py")
        facts, _ = self.service.collect_diff(self.repo)
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0].status, "added")
        self.assertTrue(facts[0].staged)

    def test_deleted_file_status(self):
        gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        gf.git(self.repo, "rm", "-q", "--", "alpha.py")
        facts, _ = self.service.collect_diff(self.repo)
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0].status, "deleted")
        self.assertEqual(facts[0].deletions, 1)

    def test_renamed_file_status_and_old_path(self):
        gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        gf.git(self.repo, "mv", "alpha.py", "delta.py")
        facts, _ = self.service.collect_diff(self.repo)
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0].status, "renamed")
        self.assertEqual(facts[0].path, "delta.py")
        self.assertEqual(facts[0].old_path, "alpha.py")

    def test_binary_file_flag_and_zero_counts(self):
        gf.commit_file(self.repo, "seed.py", "seed\n", "seed")
        blob = os.path.join(self.repo, "blob.bin")
        with open(blob, "wb") as fh:
            fh.write(b"\x00\x01\x02\x03")
        gf.git(self.repo, "add", "--", "blob.bin")
        gf.git(self.repo, "commit", "-q", "-m", "add blob")
        with open(blob, "wb") as fh:
            fh.write(b"\x00\x01\x02\x03\x04\x05")
        facts, _ = self.service.collect_diff(self.repo)
        self.assertEqual(len(facts), 1)
        self.assertTrue(facts[0].binary)
        self.assertEqual((facts[0].insertions, facts[0].deletions), (0, 0))

    def test_snippets_absent_by_default(self):
        gf.commit_file(self.repo, "alpha.py", "line1\n", "add alpha")
        gf._write_file(self.repo, "alpha.py", "line1\nline2\n")
        facts, _ = self.service.collect_diff(self.repo)
        self.assertEqual(len(facts), 1)
        self.assertIsNone(facts[0].snippet)
        self.assertNotIn("snippet_text", json.dumps(facts[0].to_dict()))

    def test_snippets_opt_in_bounded_and_redacted(self):
        secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
        gf.commit_file(self.repo, "alpha.py", "line1\n", "add alpha")
        gf._write_file(self.repo, "alpha.py", f"line1\ntoken = {secret}\n")
        facts, _ = self.service.collect_diff(self.repo, include_snippets=True)
        self.assertEqual(len(facts), 1)
        snippet = facts[0].snippet
        self.assertIsNotNone(snippet)
        self.assertLessEqual(len(snippet), GIT_SNIPPET_MAX_CHARS)
        self.assertNotIn(secret, snippet)
        self.assertIn("[REDACTED]", snippet)

    def test_snippet_hard_bound(self):
        long_line = "x" * 2000
        gf.commit_file(self.repo, "alpha.py", "line1\n", "add alpha")
        gf._write_file(self.repo, "alpha.py", f"line1\n{long_line}\n")
        facts, _ = self.service.collect_diff(self.repo, include_snippets=True)
        self.assertEqual(len(facts[0].snippet), GIT_SNIPPET_MAX_CHARS)

    def test_non_repo_returns_empty_with_warning(self):
        facts, warnings = self.service.collect_diff(_tmp_dir(self))
        self.assertEqual(facts, [])
        self.assertIn("git_not_repository", _warning_codes(warnings))


class RecentCommitsTests(unittest.TestCase):
    """2.5: collect_recent_commits — limits, order, no bodies, real wire."""

    def setUp(self):
        self.service = GitIntelligenceService()
        self.repo = gf.make_repo(os.path.join(_tmp_dir(self), "repo"))

    def test_abcd_newest_first_with_fields(self):
        shas = gf.scenario_abcd(self.repo)
        commits, warnings = self.service.collect_recent_commits(self.repo)
        self.assertEqual([c.subject for c in commits], ["D", "C", "B", "A"])
        self.assertEqual([c.sha for c in commits], [shas[k] for k in "DCBA"])
        head = commits[0]
        self.assertEqual(head.short_sha, shas["D"][:7])
        self.assertEqual(head.author_name, gf.GIT_TEST_USER_NAME)
        self.assertEqual(head.parents, (shas["C"],))
        self.assertEqual(head.changed_paths, ("alpha.py",))
        self.assertEqual(warnings, [])

    def test_root_commit_parents_and_paths_not_glued(self):
        # Real `log -z --name-only` output glues the first changed path to
        # the %P field with "\n"; the parser must split them cleanly.
        shas = gf.scenario_abcd(self.repo)
        commits, _ = self.service.collect_recent_commits(self.repo)
        root = commits[-1]
        self.assertEqual(root.sha, shas["A"])
        self.assertEqual(root.parents, ())
        self.assertEqual(root.changed_paths, ("alpha.py",))
        multi = commits[2]  # B touched alpha.py + beta.py
        self.assertEqual(multi.parents, (shas["A"],))
        self.assertEqual(set(multi.changed_paths), {"alpha.py", "beta.py"})
        self.assertEqual(
            [p for c in commits for p in c.parents],
            [p for c in commits for p in c.parents if "\n" not in p],
        )

    def test_default_limit_is_ten(self):
        for day in range(1, 13):
            gf.commit_file(
                self.repo,
                f"file{day:02d}.py",
                f"content {day}\n",
                f"commit {day}",
                author_date=f"2024-02-{day:02d}T00:00:00+00:00",
                committer_date=f"2024-02-{day:02d}T00:00:00+00:00",
            )
        commits, _ = self.service.collect_recent_commits(self.repo)
        self.assertEqual(len(commits), 10)
        self.assertEqual(commits[0].subject, "commit 12")
        self.assertEqual(commits[-1].subject, "commit 3")

    def test_explicit_limit(self):
        gf.scenario_abcd(self.repo)
        commits, _ = self.service.collect_recent_commits(self.repo, limit=2)
        self.assertEqual([c.subject for c in commits], ["D", "C"])

    def test_limit_clamped_to_max(self):
        gf.scenario_abcd(self.repo)
        seen = []
        real_run = self.service._runner.run

        def spy(cwd, *argv):
            seen.append(argv)
            return real_run(cwd, *argv)

        with mock.patch.object(self.service._runner, "run", side_effect=spy):
            commits, _ = self.service.collect_recent_commits(self.repo, limit=500)
        self.assertEqual(len(commits), 4)
        log_calls = [a for a in seen if a[0] == "log"]
        self.assertTrue(any(f"--max-count={GIT_MAX_COMMITS}" in a for a in log_calls))

    def test_no_bodies_anywhere(self):
        gf.commit_file(self.repo, "alpha.py", "alpha\n", "subject only")
        commits, _ = self.service.collect_recent_commits(self.repo)
        serialized = json.dumps([c.to_dict() for c in commits], sort_keys=True)
        self.assertNotIn("body", serialized)

    def test_changed_paths_bounded(self):
        files = {f"f{i:03d}.py": f"c{i}\n" for i in range(60)}
        gf.commit_files(self.repo, files, "sixty files")
        commits, _ = self.service.collect_recent_commits(self.repo)
        self.assertEqual(len(commits[0].changed_paths), 50)

    def test_unborn_head_returns_empty_with_warning(self):
        commits, warnings = self.service.collect_recent_commits(self.repo)
        self.assertEqual(commits, [])
        self.assertIn("git_command_failed", _warning_codes(warnings))

    def test_non_repo_returns_empty_with_warning(self):
        commits, warnings = self.service.collect_recent_commits(_tmp_dir(self))
        self.assertEqual(commits, [])
        self.assertIn("git_not_repository", _warning_codes(warnings))


class FileHistoryTests(unittest.TestCase):
    """2.5: collect_file_history — --follow pre-rename commits, bounded."""

    def setUp(self):
        self.service = GitIntelligenceService()
        self.repo = gf.make_repo(os.path.join(_tmp_dir(self), "repo"))

    def test_follow_includes_pre_rename_commits(self):
        shas = gf.rename_fixture(self.repo)
        commits, warnings = self.service.collect_file_history(self.repo, "delta.py")
        self.assertEqual([c.sha for c in commits], [shas["after"], shas["before"]])
        self.assertEqual(commits[0].subject, "rename alpha to delta")
        self.assertEqual(warnings, [])

    def test_history_of_never_renamed_file(self):
        shas = gf.scenario_abcd(self.repo)
        commits, _ = self.service.collect_file_history(self.repo, "beta.py")
        self.assertEqual([c.sha for c in commits], [shas["C"], shas["B"]])

    def test_limit_respected(self):
        shas = gf.rename_fixture(self.repo)
        commits, _ = self.service.collect_file_history(self.repo, "delta.py", limit=1)
        self.assertEqual([c.sha for c in commits], [shas["after"]])

    def test_limit_clamped_to_file_history_max(self):
        gf.scenario_abcd(self.repo)
        seen = []
        real_run = self.service._runner.run

        def spy(cwd, *argv):
            seen.append(argv)
            return real_run(cwd, *argv)

        with mock.patch.object(self.service._runner, "run", side_effect=spy):
            self.service.collect_file_history(self.repo, "alpha.py", limit=9999)
        log_calls = [a for a in seen if a[0] == "log"]
        self.assertTrue(
            any(f"--max-count={GIT_FILE_HISTORY_MAX}" in a for a in log_calls)
        )
        self.assertTrue(any("--follow" in a for a in log_calls))

    def test_hostile_paths_rejected(self):
        gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        from relinkra.code_reference import CodeRefValidationError

        for bad in ("../outside.py", "sub/../../escape.py", "/abs/path.py", "C:\\abs.py"):
            with self.subTest(path=bad), self.assertRaises(CodeRefValidationError):
                self.service.collect_file_history(self.repo, bad)

    def test_unknown_path_returns_empty_without_warning(self):
        gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        commits, warnings = self.service.collect_file_history(self.repo, "ghost.py")
        self.assertEqual(commits, [])
        self.assertEqual(warnings, [])

    def test_non_repo_returns_empty_with_warning(self):
        commits, warnings = self.service.collect_file_history(
            _tmp_dir(self), "alpha.py"
        )
        self.assertEqual(commits, [])
        self.assertIn("git_not_repository", _warning_codes(warnings))


class CurrentChangeStateTests(unittest.TestCase):
    """2.6: collect_current_change_state — all five states."""

    def setUp(self):
        self.service = GitIntelligenceService()
        self.repo = gf.make_repo(os.path.join(_tmp_dir(self), "repo"))

    def test_unchanged(self):
        gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        state, warnings = self.service.collect_current_change_state(
            self.repo, "alpha.py"
        )
        self.assertEqual(state, GitFileChangeState.UNCHANGED)
        self.assertEqual(warnings, [])

    def test_staged(self):
        gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        gf._write_file(self.repo, "beta.py", "beta\n")
        gf.git(self.repo, "add", "--", "beta.py")
        state, _ = self.service.collect_current_change_state(self.repo, "beta.py")
        self.assertEqual(state, GitFileChangeState.STAGED)

    def test_unstaged(self):
        gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        gf._write_file(self.repo, "alpha.py", "alpha changed\n")
        state, _ = self.service.collect_current_change_state(self.repo, "alpha.py")
        self.assertEqual(state, GitFileChangeState.UNSTAGED)

    def test_untracked(self):
        gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        gf._write_file(self.repo, "loose.py", "loose\n")
        state, _ = self.service.collect_current_change_state(self.repo, "loose.py")
        self.assertEqual(state, GitFileChangeState.UNTRACKED)

    def test_conflicted(self):
        gf.conflict_fixture(self.repo)
        state, _ = self.service.collect_current_change_state(self.repo, "alpha.py")
        self.assertEqual(state, GitFileChangeState.CONFLICTED)

    def test_state_serializes_lowercase(self):
        gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        state, _ = self.service.collect_current_change_state(self.repo, "alpha.py")
        self.assertEqual(json.dumps(state), '"unchanged"')

    def test_hostile_path_rejected(self):
        gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        from relinkra.code_reference import CodeRefValidationError

        with self.assertRaises(CodeRefValidationError):
            self.service.collect_current_change_state(self.repo, "../x.py")

    def test_non_repo_returns_none_with_warning(self):
        state, warnings = self.service.collect_current_change_state(
            _tmp_dir(self), "alpha.py"
        )
        self.assertIsNone(state)
        self.assertIn("git_not_repository", _warning_codes(warnings))


class CoChangeTests(unittest.TestCase):
    """2.6: collect_cochange — single scan, counts, order, bounds."""

    def setUp(self):
        self.service = GitIntelligenceService()
        self.repo = gf.make_repo(os.path.join(_tmp_dir(self), "repo"))

    def test_abcd_counts_and_anchor_excluded(self):
        gf.scenario_abcd(self.repo)
        facts, warnings = self.service.collect_cochange(self.repo, "alpha.py")
        self.assertEqual(len(facts), 1)
        fact = facts[0]
        self.assertEqual(fact.path, "beta.py")
        self.assertEqual(fact.shared_commit_count, 1)
        self.assertEqual(fact.sampled_commit_count, 3)
        self.assertNotIn("alpha.py", [f.path for f in facts])
        self.assertEqual(warnings, [])

    def test_ordering_count_desc_then_path_asc(self):
        gf.commit_files(
            self.repo, {"a.py": "a\n", "zz.py": "z\n"}, "a+zz",
            author_date="2024-03-01T00:00:00+00:00",
            committer_date="2024-03-01T00:00:00+00:00",
        )
        gf.commit_files(
            self.repo, {"a.py": "a2\n", "mm.py": "m\n"}, "a+mm",
            author_date="2024-03-02T00:00:00+00:00",
            committer_date="2024-03-02T00:00:00+00:00",
        )
        gf.commit_files(
            self.repo, {"a.py": "a3\n", "mm.py": "m2\n", "zz.py": "z2\n"}, "a+mm+zz",
            author_date="2024-03-03T00:00:00+00:00",
            committer_date="2024-03-03T00:00:00+00:00",
        )
        facts, _ = self.service.collect_cochange(self.repo, "a.py")
        # mm.py shares 2 commits, zz.py shares 2 -> count DESC, path ASC
        self.assertEqual([f.path for f in facts], ["mm.py", "zz.py"])
        self.assertEqual(facts[0].shared_commit_count, 2)
        self.assertEqual(facts[0].sampled_commit_count, 3)
        self.assertEqual(facts[1].shared_commit_count, 2)

    def test_tie_breaks_by_path_asc(self):
        gf.scenario_abcd(self.repo)
        facts, _ = self.service.collect_cochange(self.repo, "beta.py")
        self.assertEqual([f.path for f in facts], ["alpha.py", "gamma.py"])
        self.assertTrue(all(f.shared_commit_count == 1 for f in facts))
        self.assertTrue(all(f.sampled_commit_count == 2 for f in facts))

    def test_min_shared_count_is_one(self):
        gf.scenario_abcd(self.repo)
        facts, _ = self.service.collect_cochange(self.repo, "alpha.py")
        self.assertTrue(all(f.shared_commit_count >= 1 for f in facts))
        self.assertNotIn("gamma.py", [f.path for f in facts])

    def test_top_ten_bound(self):
        files = {"anchor.py": "a\n"}
        for i in range(15):
            files[f"other{i:02d}.py"] = f"c{i}\n"
        gf.commit_files(self.repo, files, "big commit")
        facts, _ = self.service.collect_cochange(self.repo, "anchor.py")
        self.assertEqual(len(facts), 10)
        self.assertTrue(all(f.shared_commit_count == 1 for f in facts))
        self.assertEqual([f.path for f in facts], sorted(f.path for f in facts))

    def test_single_log_call(self):
        gf.scenario_abcd(self.repo)
        seen = []
        real_run = self.service._runner.run

        def spy(cwd, *argv):
            seen.append(argv)
            return real_run(cwd, *argv)

        with mock.patch.object(self.service._runner, "run", side_effect=spy):
            self.service.collect_cochange(self.repo, "alpha.py")
        log_calls = [a for a in seen if a[0] == "log"]
        self.assertEqual(len(log_calls), 1)
        self.assertIn(f"--max-count={GIT_COCHANGE_SCAN}", log_calls[0])
        self.assertIn("--name-only", log_calls[0])

    def test_anchor_without_commits_returns_empty(self):
        gf.scenario_abcd(self.repo)
        facts, warnings = self.service.collect_cochange(self.repo, "ghost.py")
        self.assertEqual(facts, [])
        self.assertEqual(warnings, [])

    def test_hostile_anchor_rejected(self):
        gf.commit_file(self.repo, "alpha.py", "alpha\n", "add alpha")
        from relinkra.code_reference import CodeRefValidationError

        with self.assertRaises(CodeRefValidationError):
            self.service.collect_cochange(self.repo, "../x.py")

    def test_non_repo_returns_empty_with_warning(self):
        facts, warnings = self.service.collect_cochange(_tmp_dir(self), "alpha.py")
        self.assertEqual(facts, [])
        self.assertIn("git_not_repository", _warning_codes(warnings))


def _freeze(value) -> str:
    def default(o):
        if hasattr(o, "to_dict"):
            return o.to_dict()
        return str(o)

    return json.dumps(value, sort_keys=True, default=default)


def _collect_everything(service, repo):
    return {
        "capabilities": service.collect_capabilities(repo),
        "repository_state": service.collect_repository_state(repo),
        "head_facts": service.collect_head_facts(repo),
        "working_tree": service.collect_working_tree(repo),
        "diff": service.collect_diff(repo),
        "diff_snippets": service.collect_diff(repo, include_snippets=True),
        "recent_commits": service.collect_recent_commits(repo),
        "file_history": service.collect_file_history(repo, "alpha.py"),
        "change_state": service.collect_current_change_state(repo, "alpha.py"),
        "cochange": service.collect_cochange(repo, "alpha.py"),
    }


def _dirty_abcd_repo(test: unittest.TestCase) -> str:
    repo = gf.make_repo(os.path.join(_tmp_dir(test), "repo"))
    gf.scenario_abcd(repo)
    gf._write_file(repo, "staged.py", "staged\n")
    gf.git(repo, "add", "--", "staged.py")
    gf._write_file(repo, "alpha.py", "alpha dirty\n")
    gf._write_file(repo, "untracked.py", "untracked\n")
    return repo


class DeterminismTests(unittest.TestCase):
    """2.7: identical repo state -> byte-identical output."""

    def test_double_run_byte_identical(self):
        repo = _dirty_abcd_repo(self)
        service = GitIntelligenceService()
        first = _freeze(_collect_everything(service, repo))
        second = _freeze(_collect_everything(service, repo))
        self.assertEqual(first, second)


class NoPersistSpyTests(unittest.TestCase):
    """2.7: no MemoryService/Engram adapter method on any collect path."""

    def test_no_memory_or_engram_writes(self):
        from relinkra.engram_adapter import EngramCLIAdapter
        from relinkra.memory import MemoryService

        repo = _dirty_abcd_repo(self)
        service = GitIntelligenceService()
        with mock.patch.object(MemoryService, "save") as mem_save, mock.patch.object(
            MemoryService, "supersede"
        ) as mem_supersede, mock.patch.object(
            MemoryService, "query"
        ) as mem_query, mock.patch.object(
            MemoryService, "get"
        ) as mem_get, mock.patch.object(
            EngramCLIAdapter, "save_record"
        ) as eng_save, mock.patch.object(
            EngramCLIAdapter, "search_records"
        ) as eng_search:
            _collect_everything(service, repo)
        for spy in (
            mem_save, mem_supersede, mem_query, mem_get, eng_save, eng_search,
        ):
            spy.assert_not_called()


class CommandSurfaceTests(unittest.TestCase):
    """2.7: every spawned command is an allowlisted read-only verb (or the
    global no-op ``--version`` flag, which is not a repository verb)."""

    def test_only_allowlisted_verbs_spawned(self):
        repo = _dirty_abcd_repo(self)
        service = GitIntelligenceService()
        with mock.patch.object(
            gi.subprocess, "run", wraps=gi.subprocess.run
        ) as run:
            _collect_everything(service, repo)
        self.assertGreater(run.call_count, 0)
        for call in run.call_args_list:
            argv = call.args[0]
            verb = argv[1]
            self.assertTrue(
                verb in gi.READ_ONLY_VERBS or verb == "--version",
                f"non-allowlisted command spawned: {argv!r}",
            )


class ModuleConvenienceTests(unittest.TestCase):
    """Module-level functions delegate to a default service."""

    def test_module_level_collect_capabilities(self):
        repo = gf.make_repo(os.path.join(_tmp_dir(self), "repo"))
        gf.commit_file(repo, "alpha.py", "alpha\n", "add alpha")
        caps, warnings = gi.collect_capabilities(repo)
        self.assertTrue(caps.repository_detected)
        self.assertTrue(caps.head_available)
        self.assertEqual(warnings, [])

    def test_module_level_collect_cochange(self):
        repo = gf.make_repo(os.path.join(_tmp_dir(self), "repo"))
        gf.scenario_abcd(repo)
        facts, _ = gi.collect_cochange(repo, "alpha.py")
        self.assertEqual([f.path for f in facts], ["beta.py"])
