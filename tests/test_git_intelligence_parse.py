"""Parser and fixture tests for relinkra.git_intelligence (R2 Git Intelligence).

Fixture tests exercise the real git binary in temp repos; parser tests are
pure (canned `-z` text in, typed facts out) and fully offline.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from datetime import datetime

try:  # discovery (`-s tests`) puts tests/ on sys.path; package form does not
    from tests import git_fixtures as gf
except ModuleNotFoundError:  # pragma: no cover - import-mode fallback
    import git_fixtures as gf

from relinkra.git_intelligence import (
    GIT_CHANGED_PATHS_PER_COMMIT,
    GitParseError,
    parse_log_z,
    parse_name_status_z,
    parse_numstat_z,
    parse_porcelain_z,
)

_SHA_A = "a" * 40
_SHA_B = "b" * 40


class PorcelainZTests(unittest.TestCase):
    """status --porcelain=v1 -z: NUL-delimited, XY + space + path records."""

    def test_staged_unstaged_untracked_classes(self):
        text = "M  staged.py\x00 M unstaged.py\x00?? new file.py\x00"
        entries = parse_porcelain_z(text)
        self.assertEqual(len(entries), 3)
        self.assertEqual(entries[0].path, "staged.py")
        self.assertEqual((entries[0].index_status, entries[0].worktree_status), ("M", " "))
        self.assertEqual(entries[1].path, "unstaged.py")
        self.assertEqual((entries[1].index_status, entries[1].worktree_status), (" ", "M"))
        self.assertEqual(entries[2].path, "new file.py")
        self.assertEqual((entries[2].index_status, entries[2].worktree_status), ("?", "?"))
        self.assertIsNone(entries[2].old_path)

    def test_unicode_and_nested_paths_preserved(self):
        text = "A  a b/ñ.txt\x00A  deep/nested/dir/file.py\x00"
        entries = parse_porcelain_z(text)
        self.assertEqual([e.path for e in entries], ["a b/ñ.txt", "deep/nested/dir/file.py"])

    def test_rename_records_new_path_then_old_path(self):
        # porcelain v1 -z: "R  <new>\x00<old>\x00" (order reversed vs non-z).
        text = "R  c.txt\x00a b/ñ.txt\x00"
        entries = parse_porcelain_z(text)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].path, "c.txt")
        self.assertEqual(entries[0].old_path, "a b/ñ.txt")
        self.assertEqual(entries[0].index_status, "R")

    def test_conflict_codes_preserved(self):
        text = "UU both.py\x00AA added.py\x00DD deleted.py\x00"
        entries = parse_porcelain_z(text)
        self.assertEqual(
            [(e.path, e.index_status, e.worktree_status) for e in entries],
            [("both.py", "U", "U"), ("added.py", "A", "A"), ("deleted.py", "D", "D")],
        )

    def test_empty_input_yields_no_entries(self):
        self.assertEqual(parse_porcelain_z(""), [])
        self.assertEqual(parse_porcelain_z("\x00"), [])

    def test_malformed_record_raises(self):
        with self.assertRaises(GitParseError):
            parse_porcelain_z("garbage-without-status-columns\x00")

    def test_rename_missing_source_raises(self):
        with self.assertRaises(GitParseError):
            parse_porcelain_z("R  new.py\x00")


class LogZTests(unittest.TestCase):
    """log -z records: sha, committed_at, author_name, subject, parents,
    then changed paths, terminated by an empty field."""

    def test_single_commit_full_fields(self):
        text = f"{_SHA_A}\x002024-01-01T00:00:00Z\x00Ada\x00initial\x00\x00alpha.py\x00\x00"
        commits = parse_log_z(text)
        self.assertEqual(len(commits), 1)
        commit = commits[0]
        self.assertEqual(commit.sha, _SHA_A)
        self.assertEqual(commit.short_sha, "a" * 7)
        self.assertEqual(commit.committed_at, "2024-01-01T00:00:00Z")
        self.assertEqual(commit.author_name, "Ada")
        self.assertEqual(commit.subject, "initial")
        self.assertEqual(commit.parents, ())
        self.assertEqual(commit.changed_paths, ("alpha.py",))

    def test_multiple_commits_preserve_order_and_parents(self):
        text = (
            f"{_SHA_B}\x002024-01-02T00:00:00Z\x00Bob\x00second\x00{_SHA_A}\x00beta.py\x00gamma.py\x00\x00"
            f"{_SHA_A}\x002024-01-01T00:00:00Z\x00Ada\x00first\x00\x00alpha.py\x00\x00"
        )
        commits = parse_log_z(text)
        self.assertEqual([c.sha for c in commits], [_SHA_B, _SHA_A])
        self.assertEqual(commits[0].parents, (_SHA_A,))
        self.assertEqual(commits[0].changed_paths, ("beta.py", "gamma.py"))
        self.assertEqual(commits[1].changed_paths, ("alpha.py",))

    def test_changed_paths_bounded_per_commit(self):
        paths = [f"file{i:03d}.py" for i in range(GIT_CHANGED_PATHS_PER_COMMIT + 10)]
        text = f"{_SHA_A}\x002024-01-01T00:00:00Z\x00Ada\x00big\x00\x00" + "\x00".join(paths) + "\x00\x00"
        commits = parse_log_z(text)
        self.assertEqual(len(commits[0].changed_paths), GIT_CHANGED_PATHS_PER_COMMIT)
        self.assertEqual(commits[0].changed_paths[0], "file000.py")

    def test_secret_in_subject_is_redacted(self):
        token = "ghp_" + "x9Y8z7" * 6
        text = f"{_SHA_A}\x002024-01-01T00:00:00Z\x00Ada\x00deploy {token} now\x00\x00\x00"
        commits = parse_log_z(text)
        self.assertNotIn(token, commits[0].subject)
        self.assertIn("[REDACTED]", commits[0].subject)

    def test_invalid_sha_raises(self):
        with self.assertRaises(GitParseError):
            parse_log_z("not-a-sha\x002024-01-01T00:00:00Z\x00Ada\x00s\x00\x00\x00")

    def test_truncated_header_raises(self):
        with self.assertRaises(GitParseError):
            parse_log_z(f"{_SHA_A}\x002024-01-01T00:00:00Z\x00")


class NumstatZTests(unittest.TestCase):
    """diff --numstat -z: "add\\tdel\\tpath\\x00"; rename: "add\\tdel\\t\\x00old\\x00new\\x00"."""

    def test_normal_entries(self):
        text = "3\t1\talpha.py\x0010\t0\tdeep/beta.py\x00"
        entries = parse_numstat_z(text)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].path, "alpha.py")
        self.assertEqual((entries[0].insertions, entries[0].deletions), (3, 1))
        self.assertFalse(entries[0].binary)
        self.assertIsNone(entries[0].old_path)
        self.assertEqual(entries[1].path, "deep/beta.py")

    def test_binary_dash_counts(self):
        text = "-\t-\timage.png\x00"
        entries = parse_numstat_z(text)
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0].binary)
        self.assertEqual((entries[0].insertions, entries[0].deletions), (0, 0))

    def test_rename_entry_old_then_new(self):
        text = "1\t0\t\x00a b/old.py\x00new.py\x00"
        entries = parse_numstat_z(text)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].path, "new.py")
        self.assertEqual(entries[0].old_path, "a b/old.py")
        self.assertEqual((entries[0].insertions, entries[0].deletions), (1, 0))

    def test_malformed_counts_raise(self):
        with self.assertRaises(GitParseError):
            parse_numstat_z("x\ty\tfile.py\x00")

    def test_missing_tab_fields_raise(self):
        with self.assertRaises(GitParseError):
            parse_numstat_z("no-tabs-here\x00")


class NameStatusZTests(unittest.TestCase):
    """diff --name-status -z: "M\\x00path\\x00"; rename: "R100\\x00old\\x00new\\x00"."""

    def test_modified_added_deleted_mapping(self):
        # name-status -z: single-letter code token, then path token.
        text = "M\x00a.py\x00A\x00b.py\x00D\x00c.py\x00"
        entries = parse_name_status_z(text)
        self.assertEqual(
            [(e.path, e.status) for e in entries],
            [("a.py", "modified"), ("b.py", "added"), ("c.py", "deleted")],
        )

    def test_rename_with_score_old_then_new(self):
        text = "R100\x00old name.py\x00new.py\x00"
        entries = parse_name_status_z(text)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].status, "renamed")
        self.assertEqual(entries[0].path, "new.py")
        self.assertEqual(entries[0].old_path, "old name.py")

    def test_unknown_code_raises(self):
        with self.assertRaises(GitParseError):
            parse_name_status_z("Z\x00a.py\x00")

    def test_rename_missing_paths_raise(self):
        with self.assertRaises(GitParseError):
            parse_name_status_z("R100\x00only-old.py\x00")


@unittest.skipUnless(shutil.which("git"), "git binary required for fixture tests")
class GitFixturesTests(unittest.TestCase):
    """tests/git_fixtures.py shared temp-repo helper (task 1.1)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="relinkra-gf-")
        self.repo = gf.make_repo(os.path.join(self._tmp.name, "repo"))

    def tearDown(self):
        self._tmp.cleanup()

    def test_make_repo_initializes_main_branch(self):
        self.assertEqual(
            gf.git(self.repo, "symbolic-ref", "HEAD"), "refs/heads/main"
        )

    def test_commit_file_pins_identity_and_dates(self):
        sha = gf.commit_file(self.repo, "x.txt", "hello\n", "first")
        self.assertEqual(gf.git(self.repo, "rev-parse", "HEAD"), sha)
        self.assertEqual(
            gf.git(self.repo, "log", "-1", "--pretty=%an"), gf.GIT_TEST_USER_NAME
        )
        self.assertEqual(
            gf.git(self.repo, "log", "-1", "--pretty=%ae"), gf.GIT_TEST_USER_EMAIL
        )
        # git may render UTC as "+00:00" or "Z"; compare instants, not text.
        self.assertEqual(
            datetime.fromisoformat(gf.git(self.repo, "log", "-1", "--pretty=%aI")),
            datetime.fromisoformat(gf.FIXED_AUTHOR_DATE),
        )
        self.assertEqual(
            datetime.fromisoformat(gf.git(self.repo, "log", "-1", "--pretty=%cI")),
            datetime.fromisoformat(gf.FIXED_COMMITTER_DATE),
        )

    def test_scenario_abcd_commit_shape(self):
        shas = gf.scenario_abcd(self.repo)
        self.assertEqual(set(shas), {"A", "B", "C", "D"})
        self.assertEqual(len(set(shas.values())), 4)
        self.assertEqual(gf.git(self.repo, "rev-list", "--count", "HEAD"), "4")
        # Design scenario: A:alpha; B:alpha+beta; C:beta+gamma; D:alpha.
        for name in ("alpha.py", "beta.py", "gamma.py"):
            self.assertTrue(os.path.isfile(os.path.join(self.repo, name)), name)
        touched = gf.git(
            self.repo, "log", "--pretty=format:--%s", "--name-only"
        )
        self.assertEqual(touched.count("--A"), 1)
        # alpha.py appears in commits A, B and D (3 touches).
        self.assertEqual(touched.count("alpha.py"), 3)
        # beta.py appears in commits B and C (2 touches).
        self.assertEqual(touched.count("beta.py"), 2)
        # gamma.py appears only in commit C.
        self.assertEqual(touched.count("gamma.py"), 1)

    def test_rename_fixture(self):
        shas = gf.rename_fixture(self.repo)
        self.assertNotEqual(shas["before"], shas["after"])
        self.assertFalse(os.path.exists(os.path.join(self.repo, "alpha.py")))
        self.assertTrue(os.path.isfile(os.path.join(self.repo, "delta.py")))
        history = gf.git(
            self.repo, "log", "--follow", "--pretty=%H", "--", "delta.py"
        ).splitlines()
        self.assertIn(shas["before"], history)
        self.assertIn(shas["after"], history)

    def test_unicode_fixture(self):
        gf.unicode_fixture(self.repo)
        path = os.path.join(self.repo, "a b", "ñ.txt")
        self.assertTrue(os.path.isfile(path))
        self.assertEqual(gf.git(self.repo, "status", "--porcelain"), "")

    def test_conflict_fixture(self):
        gf.conflict_fixture(self.repo)
        status = gf.git(self.repo, "status", "--porcelain")
        self.assertIn("UU alpha.py", status.splitlines())


if __name__ == "__main__":
    unittest.main()
