"""Tests for relinkra.git_cli (R2 Git Intelligence V1, task 4.1).

Integration tests run the CLI against real temp git repos
(tests/git_fixtures.py) — fully offline. Degradation paths inject a
service whose runner points at a missing binary, or an exploding fake.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest

from relinkra import git_cli
from relinkra.git_intelligence import GitIntelligenceService, _GitRunner

try:
    from tests import git_fixtures as gf
except ImportError:  # pragma: no cover - discover vs module invocation
    import git_fixtures as gf


def run_cli(argv, **kwargs):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = git_cli.main(argv, **kwargs)
    return code, out.getvalue(), err.getvalue()


def assert_sorted_pretty_json(testcase, raw):
    parsed = json.loads(raw)
    testcase.assertEqual(raw, json.dumps(parsed, indent=2, sort_keys=True) + "\n")
    return parsed


class RepoCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = gf.make_repo(os.path.join(self.tmp.name, "repo"))

    def commit_abcd(self):
        return gf.scenario_abcd(self.repo)


class StatusTests(RepoCase):
    def test_status_happy_path_exit_0_sorted_json(self):
        self.commit_abcd()
        code, out, err = run_cli(["status", "--path", self.repo])
        self.assertEqual(code, 0, err)
        self.assertEqual(err, "")
        parsed = assert_sorted_pretty_json(self, out)
        self.assertEqual(
            set(parsed),
            {"capabilities", "head", "repository_state", "warnings", "working_tree"},
        )
        caps = parsed["capabilities"]
        self.assertTrue(caps["git_available"])
        self.assertTrue(caps["repository_detected"])
        self.assertNotIn("repository_root", caps)
        state = parsed["repository_state"]
        self.assertEqual(state["branch"], "main")
        self.assertTrue(state["clean"])
        self.assertIsNone(state["ahead"])
        self.assertIsNone(state["behind"])
        head = parsed["head"]
        self.assertEqual(head["subject"], "D")
        self.assertEqual(head["branch"], "main")
        self.assertEqual(parsed["warnings"], [])

    def test_status_emits_author_name_only_no_email(self):
        self.commit_abcd()
        code, out, err = run_cli(["status", "--path", self.repo])
        self.assertEqual(code, 0, err)
        parsed = json.loads(out)
        self.assertEqual(parsed["head"]["author_name"], gf.GIT_TEST_USER_NAME)
        self.assertNotIn(gf.GIT_TEST_USER_EMAIL, out)
        self.assertNotIn("@", out)

    def test_status_never_emits_absolute_repo_path(self):
        self.commit_abcd()
        code, out, err = run_cli(["status", "--path", self.repo])
        self.assertEqual(code, 0, err)
        self.assertNotIn(self.repo, out)
        self.assertNotIn(os.path.normpath(self.repo), out)
        self.assertNotIn(self.tmp.name, out)

    def test_status_non_repo_exit_1_redacted_stderr(self):
        plain = os.path.join(self.tmp.name, "plain")
        os.makedirs(plain)
        code, out, err = run_cli(["status", "--path", plain])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        error = json.loads(err)
        self.assertIn("error", error)
        self.assertTrue(error["error"])

    def test_status_git_unavailable_exit_1(self):
        service = GitIntelligenceService(
            runner=_GitRunner(executable="relinkra-no-such-git-binary")
        )
        code, out, err = run_cli(
            ["status", "--path", self.repo], git_service=service
        )
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error", json.loads(err))


class HistoryTests(RepoCase):
    def test_history_happy_path_newest_first(self):
        shas = self.commit_abcd()
        code, out, err = run_cli(
            ["history", "--file", "alpha.py", "--path", self.repo]
        )
        self.assertEqual(code, 0, err)
        parsed = assert_sorted_pretty_json(self, out)
        self.assertEqual(parsed["file"], "alpha.py")
        commits = parsed["commits"]
        self.assertEqual([c["subject"] for c in commits], ["D", "B", "A"])
        self.assertEqual([c["sha"] for c in commits], [shas["D"], shas["B"], shas["A"]])
        for commit in commits:
            self.assertEqual(commit["author_name"], gf.GIT_TEST_USER_NAME)
            self.assertIn("alpha.py", commit["changed_paths"])
            self.assertNotIn("body", commit)
        self.assertNotIn("@", out)

    def test_history_limit(self):
        self.commit_abcd()
        code, out, err = run_cli(
            ["history", "--file", "alpha.py", "--limit", "2", "--path", self.repo]
        )
        self.assertEqual(code, 0, err)
        commits = json.loads(out)["commits"]
        self.assertEqual(len(commits), 2)
        self.assertEqual(commits[0]["subject"], "D")

    def test_history_redacts_secret_in_subject(self):
        gf.commit_file(
            self.repo, "a.py", "x\n", "token ghp_abcdef1234567890abcd leak"
        )
        code, out, err = run_cli(
            ["history", "--file", "a.py", "--path", self.repo]
        )
        self.assertEqual(code, 0, err)
        self.assertNotIn("ghp_abcdef1234567890abcd", out)
        self.assertIn("[REDACTED]", out)

    def test_history_hostile_path_exit_1(self):
        self.commit_abcd()
        for hostile in ("../outside.py", "/absolute/path.py"):
            code, out, err = run_cli(
                ["history", "--file", hostile, "--path", self.repo]
            )
            self.assertEqual(code, 1, hostile)
            self.assertEqual(out, "")
            self.assertIn("error", json.loads(err))

    def test_history_non_repo_exit_1(self):
        plain = os.path.join(self.tmp.name, "plain")
        os.makedirs(plain)
        code, out, err = run_cli(
            ["history", "--file", "a.py", "--path", plain]
        )
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error", json.loads(err))


class CoChangeTests(RepoCase):
    def test_cochange_happy_path_counts_and_order(self):
        self.commit_abcd()
        code, out, err = run_cli(
            ["cochange", "--file", "alpha.py", "--path", self.repo]
        )
        self.assertEqual(code, 0, err)
        parsed = assert_sorted_pretty_json(self, out)
        self.assertEqual(parsed["anchor"], "alpha.py")
        entries = {e["path"]: e for e in parsed["co_changed"]}
        self.assertIn("beta.py", entries)
        self.assertEqual(entries["beta.py"]["shared_commit_count"], 1)
        self.assertEqual(entries["beta.py"]["sampled_commit_count"], 3)
        self.assertNotIn("alpha.py", entries)

    def test_cochange_limit(self):
        self.commit_abcd()
        code, out, err = run_cli(
            ["cochange", "--file", "alpha.py", "--limit", "1", "--path", self.repo]
        )
        self.assertEqual(code, 0, err)
        parsed = json.loads(out)
        self.assertEqual(len(parsed["co_changed"]), 1)
        self.assertEqual(parsed["co_changed"][0]["path"], "beta.py")

    def test_cochange_hostile_path_exit_1(self):
        self.commit_abcd()
        code, out, err = run_cli(
            ["cochange", "--file", "..", "--path", self.repo]
        )
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error", json.loads(err))


class ExitCodeTests(RepoCase):
    def test_usage_error_exit_1(self):
        for argv in (["bogus-subcommand"], ["history", "--path", self.repo]):
            code, out, err = run_cli(argv)
            self.assertEqual(code, 1, argv)
            self.assertEqual(out, "")
            self.assertIn("error", json.loads(err))

    def test_internal_error_exit_2_redacted(self):
        class ExplodingService:
            def collect_capabilities(self, path):
                raise RuntimeError("boom ghp_internaltoken9999999")

        code, out, err = run_cli(
            ["status", "--path", self.repo], git_service=ExplodingService()
        )
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("error", json.loads(err))
        self.assertNotIn("ghp_internaltoken9999999", err)


class DocsTests(unittest.TestCase):
    """Task 4.3: docs/git-intelligence.md contains the four required blocks."""

    def test_docs_contains_all_four_required_blocks(self):
        docs_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "docs",
            "git-intelligence.md",
        )
        with open(docs_path, encoding="utf-8") as fh:
            text = fh.read().lower()
        for marker in (
            "model split",          # CBM / Engram / Git / Relinkra combines
            "stable vs volatile",   # stable vs volatile facts, no auto-persist
            "read-only guarantee",  # verb allowlist, argv, timeout, redaction
            "limitations",          # bounded scans, rename-blind co-change, ...
        ):
            self.assertIn(marker, text)


if __name__ == "__main__":
    unittest.main()
