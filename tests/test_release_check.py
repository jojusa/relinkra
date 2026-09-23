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

from tools import release_check, release_gates

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
            "installed": {
                "cli": True,
                "mcp": True,
                "details": [
                    "wheel exact-artifact CLI/MCP E2E retained",
                    "sdist exact-artifact CLI/MCP E2E retained",
                ],
            },
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
        installed_gate = next(
            g for g in report["gates"] if g["name"] == "INSTALLED_CLI_MCP"
        )
        self.assertEqual(installed_gate["status"], "PASS")

    def test_external_installed_cli_failure_is_blocked(self):
        evidence = self._good_evidence()
        evidence["installed"]["cli"] = False
        self._write_evidence(evidence)
        code, stdout, _ = self._run(
            ["--evidence", str(self.evidence_path), "--json"]
        )
        self.assertEqual(code, 0)
        report = json.loads(stdout)
        installed_gate = next(
            g for g in report["gates"] if g["name"] == "INSTALLED_CLI_MCP"
        )
        self.assertEqual(installed_gate["status"], "BLOCKED")
        self.assertFalse(report["safe_for_public_release"])

    def test_external_installed_mcp_failure_is_blocked(self):
        evidence = self._good_evidence()
        evidence["installed"]["mcp"] = False
        self._write_evidence(evidence)
        code, stdout, _ = self._run(
            ["--evidence", str(self.evidence_path), "--json"]
        )
        self.assertEqual(code, 0)
        report = json.loads(stdout)
        installed_gate = next(
            g for g in report["gates"] if g["name"] == "INSTALLED_CLI_MCP"
        )
        self.assertEqual(installed_gate["status"], "BLOCKED")
        self.assertFalse(report["safe_for_public_release"])

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


class ReportTextTests(unittest.TestCase):
    def test_text_surfaces_pending_external_certification_fields(self):
        report = release_gates.evaluate_gates({})
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            release_check._print_text(
                report,
                {
                    "metadata": {"version": "0.1.0"},
                    "workspace": {"git_clean": True},
                },
            )

        text = stdout.getvalue()
        self.assertIn(
            "public_release_external_certification_status: PENDING", text
        )
        self.assertIn(
            "pending_public_release_external_certification: LINUX=PARTIAL",
            text,
        )
        self.assertIn("INSTALLED_CLI_MCP: PARTIAL", text)


class WorkflowDiscoveryTests(unittest.TestCase):
    """The release SECURITY scan must cover *.yml and *.yaml workflows.

    Discovery is shared with the pin policy (ci_pin_policy.workflow_files);
    a mutable ref in either extension must block the SECURITY gate, not
    only the one the release check used to glob for.
    """

    PINNED = "3d3c42e5aac5ba805825da76410c181273ba90b1"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="relinkra-wf-")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.workflows = self.root / ".github" / "workflows"
        self.workflows.mkdir(parents=True)
        original = release_check.REPO_ROOT
        release_check.REPO_ROOT = self.root
        self.addCleanup(setattr, release_check, "REPO_ROOT", original)

    def _write_workflow(self, name, *step_lines):
        body = "".join(f"{line}\n" for line in step_lines)
        (self.workflows / name).write_text(
            "name: fixture\n"
            "on: push\n"
            "permissions:\n"
            "  contents: read\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            f"{body}",
            encoding="utf-8",
        )

    def _security(self):
        return release_check.collect_ci_and_security()["security"]

    def _gate(self, security):
        report = release_gates.evaluate_gates({"security": security})
        return next(gate for gate in report.gates if gate.name == "SECURITY")

    def test_mutable_ref_in_yaml_blocks_the_security_gate(self):
        self._write_workflow("evil.yaml", "      - uses: actions/checkout@v7")
        security = self._security()
        self.assertFalse(security["actions_pinned"])
        self.assertEqual(self._gate(security).status.value, "BLOCKED")

    def test_flow_style_mutable_ref_in_yml_blocks_the_security_gate(self):
        self._write_workflow(
            "evil.yml", "      - { uses: actions/checkout@v7 }"
        )
        security = self._security()
        self.assertFalse(security["actions_pinned"])
        self.assertEqual(self._gate(security).status.value, "BLOCKED")

    def test_pinned_ref_in_yaml_passes(self):
        self._write_workflow(
            "good.yaml", f"      - uses: actions/checkout@{self.PINNED}"
        )
        security = self._security()
        self.assertTrue(security["actions_pinned"])
        self.assertEqual(self._gate(security).status.value, "PASS")

    def test_yaml_only_directory_is_discovered(self):
        self._write_workflow(
            "only.yaml", f"      - uses: actions/checkout@{self.PINNED}"
        )
        evidence = release_check.collect_ci_and_security()
        self.assertTrue(evidence["ci"]["workflows_present"])
        self.assertTrue(evidence["security"]["actions_pinned"])

    def test_pinned_yml_does_not_mask_a_mutable_yaml(self):
        self._write_workflow(
            "good.yml", f"      - uses: actions/checkout@{self.PINNED}"
        )
        self._write_workflow("evil.yaml", "      - uses: actions/checkout@v7")
        security = self._security()
        self.assertFalse(security["actions_pinned"])
        self.assertEqual(self._gate(security).status.value, "BLOCKED")


if __name__ == "__main__":
    unittest.main()
