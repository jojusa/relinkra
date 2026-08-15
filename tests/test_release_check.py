"""Tests for tools/release_check.py CLI behavior (R5B/R5C).

Fast, collector-only invocations: no --run-regression, no
--run-packaging. The R5C --require-sha binding is asserted exhaustively;
the pre-R5C shallow-merge behavior without --require-sha is pinned as
unchanged.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import release_check

SHA = "d818b8c20d38557ab6624a9a3e4fe66a11532261"
OTHER_SHA = "5cfbc37e0000000000000000000000000000dead"


class RequireShaTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.evidence_path = Path(self._tmp.name) / "evidence.json"

    def _write_evidence(self, data):
        self.evidence_path.write_text(
            json.dumps(data), encoding="utf-8"
        )

    def _run(self, argv):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr):
            code = release_check.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def _good_evidence(self):
        return {
            "meta": {"sha": SHA, "run_id": "31760708465",
                     "source": "github-actions"},
            "ci": {"workflows_present": True, "remote_runs_passed": True},
        }

    def test_matching_sha_proceeds_and_merges(self):
        self._write_evidence(self._good_evidence())
        code, stdout, _ = self._run(
            ["--evidence", str(self.evidence_path),
             "--require-sha", SHA, "--json"]
        )
        self.assertEqual(code, 0)
        report = json.loads(stdout)
        ci_gate = next(g for g in report["gates"] if g["name"] == "CI")
        self.assertEqual(ci_gate["status"], "PASS")

    def test_mismatching_sha_exits_2(self):
        self._write_evidence(self._good_evidence())
        code, _, stderr = self._run(
            ["--evidence", str(self.evidence_path),
             "--require-sha", OTHER_SHA]
        )
        self.assertEqual(code, 2)
        self.assertIn("evidence sha validation failed", stderr)

    def test_evidence_without_meta_exits_2(self):
        evidence = self._good_evidence()
        del evidence["meta"]
        self._write_evidence(evidence)
        code, _, stderr = self._run(
            ["--evidence", str(self.evidence_path), "--require-sha", SHA]
        )
        self.assertEqual(code, 2)
        self.assertIn("evidence sha validation failed", stderr)

    def test_meta_with_empty_sha_exits_2(self):
        evidence = self._good_evidence()
        evidence["meta"]["sha"] = ""
        self._write_evidence(evidence)
        code, _, stderr = self._run(
            ["--evidence", str(self.evidence_path), "--require-sha", SHA]
        )
        self.assertEqual(code, 2)
        self.assertIn("evidence sha validation failed", stderr)

    def test_require_sha_without_evidence_exits_2(self):
        code, _, stderr = self._run(["--require-sha", SHA])
        self.assertEqual(code, 2)
        self.assertIn("evidence sha validation failed", stderr)

    def test_evidence_without_require_sha_keeps_shallow_merge(self):
        # Pre-R5C behavior is unchanged: no meta is required and the
        # external mapping still wins per key.
        self._write_evidence(
            {"ci": {"workflows_present": True, "remote_runs_passed": True}}
        )
        code, stdout, _ = self._run(
            ["--evidence", str(self.evidence_path), "--json"]
        )
        self.assertEqual(code, 0)
        report = json.loads(stdout)
        ci_gate = next(g for g in report["gates"] if g["name"] == "CI")
        self.assertEqual(ci_gate["status"], "PASS")

    def test_validation_happens_before_gate_evaluation(self):
        # A mismatch must exit 2, not 0-with-a-report: no JSON report may
        # be printed when the binding fails.
        self._write_evidence(self._good_evidence())
        code, stdout, _ = self._run(
            ["--evidence", str(self.evidence_path),
             "--require-sha", OTHER_SHA, "--json"]
        )
        self.assertEqual(code, 2)
        self.assertEqual(stdout.strip(), "")


class RequireShaFormatTests(unittest.TestCase):
    """The --require-sha value itself: malformed values exit 2 BEFORE any
    collector runs (R5D.2 hardening)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.evidence_path = Path(self._tmp.name) / "evidence.json"
        self.evidence_path.write_text(
            json.dumps({"meta": {"sha": SHA, "run_id": "31760708465",
                                 "source": "github-actions"}}),
            encoding="utf-8",
        )

    def _run(self, argv):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr):
            code = release_check.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def _assert_rejected(self, sha):
        code, stdout, stderr = self._run(
            ["--evidence", str(self.evidence_path), "--require-sha", sha]
        )
        self.assertEqual(code, 2)
        self.assertIn("evidence sha validation failed", stderr)
        self.assertIn("40 lowercase hex", stderr)
        self.assertEqual(stdout.strip(), "")

    def test_empty_sha_rejected(self):
        self._assert_rejected("")

    def test_whitespace_sha_rejected(self):
        self._assert_rejected("   ")

    def test_39_char_sha_rejected(self):
        self._assert_rejected(SHA[:-1])

    def test_uppercase_sha_rejected(self):
        self._assert_rejected(SHA.upper())

    def test_valid_sha_accepted(self):
        code, _, _ = self._run(
            ["--evidence", str(self.evidence_path), "--require-sha", SHA]
        )
        self.assertEqual(code, 0)

    def test_absent_flag_compatibility(self):
        # Without --require-sha nothing changes: the same evidence merges
        # with no sha binding at all.
        code, _, stderr = self._run(
            ["--evidence", str(self.evidence_path)]
        )
        self.assertEqual(code, 0, stderr)

    def test_validation_runs_before_packaging_build(self):
        # --require-sha bad + --run-packaging must exit 2 without paying
        # for a build: no collector may run at all.
        calls = []
        original = release_check.collect_local_evidence
        release_check.collect_local_evidence = lambda **kwargs: (
            calls.append(kwargs) or original(**kwargs)
        )
        try:
            code, _, stderr = self._run(
                ["--evidence", str(self.evidence_path),
                 "--require-sha", "not-a-sha", "--run-packaging"]
            )
        finally:
            release_check.collect_local_evidence = original
        self.assertEqual(code, 2)
        self.assertIn("evidence sha validation failed", stderr)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
