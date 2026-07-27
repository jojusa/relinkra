"""Data model tests for relinkra.git_intelligence (R2 Git Intelligence, B1).

Covers: frozen dataclasses, to_dict/from_dict round-trips, lowercase enum
values, GIT_* limit constants, and the privacy rule that repository_root is
NEVER serialized into portable output.
"""

from __future__ import annotations

import dataclasses
import json
import unittest

from relinkra.git_intelligence import (
    GIT_CHANGED_PATHS_PER_COMMIT,
    GIT_COCHANGE_SCAN,
    GIT_DEFAULT_COMMITS,
    GIT_FILE_HISTORY_MAX,
    GIT_MAX_COMMITS,
    GIT_SNIPPET_MAX_CHARS,
    GIT_TIMEOUT_SECONDS,
    GIT_TOP_COCHANGE,
    GitCapabilities,
    GitCoChangeFact,
    GitCommitFact,
    GitDiffFact,
    GitFileChangeState,
    GitHeadFacts,
    GitRepositoryState,
    GitStatusEntry,
    GitWorkingTree,
)


class GitLimitConstantsTests(unittest.TestCase):
    def test_limit_values_match_design(self):
        self.assertEqual(GIT_TIMEOUT_SECONDS, 5)
        self.assertEqual(GIT_MAX_COMMITS, 100)
        self.assertEqual(GIT_DEFAULT_COMMITS, 10)
        self.assertEqual(GIT_TOP_COCHANGE, 10)
        self.assertEqual(GIT_COCHANGE_SCAN, 100)
        self.assertEqual(GIT_CHANGED_PATHS_PER_COMMIT, 50)
        self.assertEqual(GIT_SNIPPET_MAX_CHARS, 400)
        self.assertEqual(GIT_FILE_HISTORY_MAX, 100)


class GitFileChangeStateTests(unittest.TestCase):
    def test_values_are_lowercase(self):
        self.assertEqual(
            {state.value for state in GitFileChangeState},
            {"unchanged", "staged", "unstaged", "untracked", "conflicted"},
        )

    def test_str_enum_serializes_as_value(self):
        self.assertEqual(json.dumps(GitFileChangeState.STAGED), '"staged"')


class FrozenModelTests(unittest.TestCase):
    def test_models_are_frozen(self):
        cases = [
            GitCapabilities(
                git_available=True,
                git_version="2.46.0",
                repository_detected=True,
                is_bare=False,
                head_available=True,
            ),
            GitStatusEntry(path="a.py", index_status="M", worktree_status=" "),
            GitWorkingTree(
                clean=True,
                staged=(),
                unstaged=(),
                untracked=(),
                deleted=(),
                conflicted=(),
                renamed=(),
            ),
            GitHeadFacts(
                head_sha="a" * 40,
                short_head_sha="a" * 7,
                branch="main",
                detached=False,
                committed_at="2024-01-01T00:00:00Z",
                author_name="Ada",
                subject="init",
                parents=(),
            ),
            GitRepositoryState(
                head_sha="a" * 40,
                short_head_sha="a" * 7,
                branch="main",
                detached=False,
                clean=True,
                staged_count=0,
                unstaged_count=0,
                untracked_count=0,
                conflicted_count=0,
            ),
            GitDiffFact(
                path="a.py",
                status="modified",
                staged=False,
                insertions=1,
                deletions=2,
                binary=False,
            ),
            GitCommitFact(
                sha="b" * 40,
                short_sha="b" * 7,
                committed_at="2024-01-01T00:00:00Z",
                author_name="Ada",
                subject="change",
                parents=("a" * 40,),
                changed_paths=("a.py",),
            ),
            GitCoChangeFact(path="b.py", shared_commit_count=2, sampled_commit_count=3),
        ]
        for obj in cases:
            with self.subTest(model=type(obj).__name__):
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    obj.path = "mutated"  # type: ignore[attr-defined]


class RoundTripTests(unittest.TestCase):
    def _round_trip(self, obj):
        restored = type(obj).from_dict(obj.to_dict())
        self.assertEqual(restored, obj)
        # JSON-serializable (portable output) and stable key order irrelevant.
        json.dumps(obj.to_dict(), sort_keys=True)
        return restored

    def test_status_entry_round_trip_with_rename(self):
        self._round_trip(
            GitStatusEntry(
                path="c.txt", index_status="R", worktree_status=" ", old_path="a b/ñ.txt"
            )
        )

    def test_status_entry_round_trip_without_rename(self):
        obj = self._round_trip(
            GitStatusEntry(path="n/d.py", index_status=" ", worktree_status="M")
        )
        self.assertIsNone(obj.old_path)

    def test_working_tree_round_trip(self):
        obj = self._round_trip(
            GitWorkingTree(
                clean=False,
                staged=("a.py",),
                unstaged=("b.py",),
                untracked=("c.py",),
                deleted=("d.py",),
                conflicted=("e.py",),
                renamed=(("old.py", "new.py"),),
            )
        )
        self.assertIsInstance(obj.staged, tuple)
        self.assertIsInstance(obj.renamed, tuple)
        self.assertIsInstance(obj.renamed[0], tuple)

    def test_working_tree_clean_empty(self):
        self._round_trip(
            GitWorkingTree(
                clean=True,
                staged=(),
                unstaged=(),
                untracked=(),
                deleted=(),
                conflicted=(),
                renamed=(),
            )
        )

    def test_head_facts_round_trip_detached(self):
        obj = self._round_trip(
            GitHeadFacts(
                head_sha="f" * 40,
                short_head_sha="f" * 7,
                branch=None,
                detached=True,
                committed_at="2024-01-02T03:04:05Z",
                author_name="Grace",
                subject="detach",
                parents=("e" * 40, "d" * 40),
            )
        )
        self.assertIsNone(obj.branch)
        self.assertTrue(obj.detached)
        self.assertIsInstance(obj.parents, tuple)

    def test_head_facts_has_no_author_email_field(self):
        data = GitHeadFacts(
            head_sha="f" * 40,
            short_head_sha="f" * 7,
            branch="main",
            detached=False,
            committed_at="2024-01-02T03:04:05Z",
            author_name="Grace",
            subject="s",
            parents=(),
        ).to_dict()
        self.assertNotIn("email", json.dumps(data).lower())
        self.assertIn("author_name", data)

    def test_repository_state_round_trip_with_counts(self):
        obj = self._round_trip(
            GitRepositoryState(
                head_sha="a" * 40,
                short_head_sha="a" * 7,
                branch="main",
                detached=False,
                clean=False,
                staged_count=1,
                unstaged_count=2,
                untracked_count=3,
                conflicted_count=1,
            )
        )
        data = obj.to_dict()
        self.assertEqual(
            data["counts"],
            {"staged": 1, "unstaged": 2, "untracked": 3, "conflicted": 1},
        )
        # v1: ahead/behind always None (no network), fields reserved.
        self.assertIsNone(data["ahead"])
        self.assertIsNone(data["behind"])

    def test_repository_state_unborn_head(self):
        obj = self._round_trip(
            GitRepositoryState(
                head_sha=None,
                short_head_sha=None,
                branch="main",
                detached=False,
                clean=False,
                staged_count=0,
                unstaged_count=1,
                untracked_count=0,
                conflicted_count=0,
            )
        )
        self.assertIsNone(obj.head_sha)

    def test_diff_fact_round_trip_rename_binary(self):
        obj = self._round_trip(
            GitDiffFact(
                path="new.bin",
                status="renamed",
                staged=True,
                insertions=0,
                deletions=0,
                binary=True,
                old_path="old.bin",
                snippet=None,
            )
        )
        self.assertTrue(obj.binary)
        self.assertIsNone(obj.snippet)

    def test_diff_fact_round_trip_with_snippet(self):
        self._round_trip(
            GitDiffFact(
                path="a.py",
                status="modified",
                staged=False,
                insertions=3,
                deletions=1,
                binary=False,
                snippet="+line",
            )
        )

    def test_commit_fact_round_trip(self):
        obj = self._round_trip(
            GitCommitFact(
                sha="c" * 40,
                short_sha="c" * 7,
                committed_at="2024-01-03T00:00:00Z",
                author_name="Linus",
                subject="subject",
                parents=("b" * 40,),
                changed_paths=("x.py", "y.py"),
            )
        )
        self.assertIsInstance(obj.parents, tuple)
        self.assertIsInstance(obj.changed_paths, tuple)

    def test_cochange_fact_round_trip(self):
        self._round_trip(
            GitCoChangeFact(path="b.py", shared_commit_count=3, sampled_commit_count=4)
        )


class CapabilitiesPrivacyTests(unittest.TestCase):
    def test_repository_root_never_serialized(self):
        caps = GitCapabilities(
            git_available=True,
            git_version="2.46.0",
            repository_detected=True,
            is_bare=False,
            head_available=True,
            repository_root="C:/secret/absolute/path",
        )
        data = caps.to_dict()
        self.assertNotIn("repository_root", data)
        self.assertNotIn("C:/secret/absolute/path", json.dumps(data))

    def test_capabilities_round_trip_without_root(self):
        caps = GitCapabilities(
            git_available=False,
            git_version=None,
            repository_detected=False,
            is_bare=False,
            head_available=False,
        )
        restored = GitCapabilities.from_dict(caps.to_dict())
        self.assertEqual(restored.git_available, False)
        self.assertIsNone(restored.git_version)
        self.assertIsNone(restored.repository_root)


if __name__ == "__main__":
    unittest.main()
