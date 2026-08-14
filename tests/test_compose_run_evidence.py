"""Tests for tools/compose_run_evidence.py — evidence composer (R5C)."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import compose_run_evidence

SHA = "d818b8c20d38557ab6624a9a3e4fe66a11532261"
OTHER_SHA = "5cfbc37e0000000000000000000000000000dead"
RUN_ID = "31760708465"


def _fragment(platform, sha=SHA, run_id=RUN_ID, passed=True,
              tests=100, failures=0, errors=0, resource_warnings=0,
              where="ci full-regression test"):
    return {
        "meta": {"sha": sha, "run_id": run_id,
                 "job": "full-regression", "os": f"{platform}-latest"},
        "platform": platform,
        "regression": {
            "passed": passed,
            "tests": tests,
            "failures": failures,
            "errors": errors,
            "resource_warnings": resource_warnings,
            "where": where,
        },
    }


class ComposeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name) / "run-evidence"
        self.dir.mkdir()
        self.out = Path(self._tmp.name) / "composed.json"

    def _write(self, name, data):
        path = self.dir / name
        if isinstance(data, str):
            path.write_text(data, encoding="utf-8")
        else:
            path.write_text(
                json.dumps(data, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        return path

    def _write_three(self, **overrides):
        counts = {"linux": (101, 0, 0, 0), "windows": (102, 0, 0, 0),
                  "macos": (103, 0, 0, 0)}
        for platform, (tests, failures, errors, warnings_) in counts.items():
            self._write(
                f"run-evidence-{platform}.json",
                _fragment(platform, tests=tests, failures=failures,
                          errors=errors, resource_warnings=warnings_,
                          **overrides),
            )

    def _argv(self, upstream=("fast=success", "core=success",
                              "full-regression=success")):
        argv = [
            "--evidence-dir", str(self.dir),
            "--require-sha", SHA,
            "--run-id", RUN_ID,
            "--out", str(self.out),
        ]
        for entry in upstream:
            argv.extend(["--upstream", entry])
        return argv

    def _compose(self, **kwargs):
        return compose_run_evidence.main(self._argv(**kwargs))

    def _load(self):
        return json.loads(self.out.read_text(encoding="utf-8"))

    # -- happy path ----------------------------------------------------

    def test_happy_path_schema_and_aggregate_sums(self):
        self._write_three()
        self.assertEqual(self._compose(), 0)
        composed = self._load()
        self.assertEqual(set(composed), {"meta", "platforms", "regression", "ci"})
        self.assertEqual(
            composed["meta"],
            {"sha": SHA, "run_id": RUN_ID, "source": "github-actions"},
        )
        self.assertEqual(
            composed["platforms"],
            {"linux": "pass", "windows": "pass", "macos": "pass"},
        )
        regression = composed["regression"]
        # Aggregate semantics: tests is the SUM of executions across
        # cells (101+102+103), per-cell canonical counts live in cells.
        self.assertEqual(regression["tests"], 306)
        self.assertEqual(regression["failures"], 0)
        self.assertEqual(regression["errors"], 0)
        self.assertEqual(regression["resource_warnings"], 0)
        self.assertIs(regression["passed"], True)
        self.assertEqual(regression["where"], "CI full-regression matrix")
        self.assertEqual(
            set(regression["cells"]), {"linux", "windows", "macos"}
        )
        self.assertEqual(regression["cells"]["linux"]["tests"], 101)
        self.assertEqual(regression["cells"]["macos"]["tests"], 103)
        self.assertEqual(
            set(regression["cells"]["windows"]),
            {"tests", "failures", "errors", "resource_warnings", "where"},
        )
        self.assertEqual(
            composed["ci"],
            {"workflows_present": True, "remote_runs_passed": True},
        )

    def test_comma_separated_upstream_accepted(self):
        self._write_three()
        code = self._compose(
            upstream=("fast=success,core=success,full-regression=success",)
        )
        self.assertEqual(code, 0)
        self.assertIs(self._load()["ci"]["remote_runs_passed"], True)

    def test_deterministic_output_bytes(self):
        self._write_three()
        self.assertEqual(self._compose(), 0)
        second = Path(self._tmp.name) / "second.json"
        argv = self._argv()
        argv[argv.index("--out") + 1] = str(second)
        self.assertEqual(compose_run_evidence.main(argv), 0)
        self.assertEqual(self.out.read_bytes(), second.read_bytes())
        self.assertTrue(self.out.read_bytes().endswith(b"\n"))
        self.assertNotIn(b"\r", self.out.read_bytes())

    # -- hard failures (exit 2, no output) ------------------------------

    def test_duplicate_platform_rejected(self):
        self._write("a.json", _fragment("linux"))
        nested = self.dir / "nested"
        nested.mkdir()
        (nested / "b.json").write_text(
            json.dumps(_fragment("linux")), encoding="utf-8"
        )
        self.assertEqual(self._compose(), 2)
        self.assertFalse(self.out.exists())

    def test_mixed_shas_rejected(self):
        self._write("linux.json", _fragment("linux", sha=SHA))
        self._write("windows.json", _fragment("windows", sha=OTHER_SHA))
        self.assertEqual(self._compose(), 2)

    def test_wrong_sha_vs_require_rejected(self):
        self._write("linux.json", _fragment("linux", sha=OTHER_SHA))
        self.assertEqual(self._compose(), 2)

    def test_cross_run_id_rejected(self):
        self._write("linux.json", _fragment("linux", run_id="999"))
        self.assertEqual(self._compose(), 2)

    def test_malformed_run_id_rejected(self):
        self._write("linux.json", _fragment("linux", run_id="12ab"))
        self.assertEqual(self._compose(), 2)

    def test_malformed_json_rejected(self):
        self._write("broken.json", "{not json")
        self.assertEqual(self._compose(), 2)

    def test_non_object_fragment_rejected(self):
        self._write("list.json", "[1, 2]")
        self.assertEqual(self._compose(), 2)

    def test_missing_meta_rejected(self):
        fragment = _fragment("linux")
        del fragment["meta"]
        self._write("linux.json", fragment)
        self.assertEqual(self._compose(), 2)

    def test_unexpected_platform_rejected(self):
        self._write("plan9.json", _fragment("plan9"))
        self.assertEqual(self._compose(), 2)

    def test_missing_required_upstream_rejected(self):
        self._write_three()
        self.assertEqual(
            self._compose(upstream=("fast=success", "core=success")), 2
        )

    def test_unknown_upstream_result_rejected(self):
        self._write_three()
        self.assertEqual(
            self._compose(upstream=("fast=success", "core=success",
                                    "full-regression=green")),
            2,
        )

    def test_missing_platform_with_all_success_upstream_hard_fails(self):
        self._write("linux.json", _fragment("linux"))
        self._write("macos.json", _fragment("macos"))
        # All upstreams succeeded but the windows fragment is absent:
        # anomalous — a succeeded cell MUST have produced evidence.
        self.assertEqual(self._compose(), 2)
        self.assertFalse(self.out.exists())

    # -- degraded / honest-not-green paths ------------------------------

    def test_missing_platform_with_failed_upstream_composes_degraded(self):
        self._write("linux.json", _fragment("linux"))
        self._write("macos.json", _fragment("macos"))
        code = self._compose(upstream=("fast=success", "core=success",
                                       "full-regression=failure"))
        self.assertEqual(code, 0)
        composed = self._load()
        self.assertNotIn("windows", composed["platforms"])
        self.assertEqual(
            composed["platforms"], {"linux": "pass", "macos": "pass"}
        )
        self.assertNotIn("windows", composed["regression"]["cells"])
        self.assertIs(composed["regression"]["passed"], False)
        self.assertIs(composed["ci"]["remote_runs_passed"], False)

    def test_failed_matrix_dependency_marks_remote_false(self):
        self._write_three()
        code = self._compose(upstream=("fast=failure", "core=success",
                                       "full-regression=success"))
        self.assertEqual(code, 0)
        composed = self._load()
        self.assertEqual(
            composed["platforms"]["linux"], "pass"
        )
        self.assertIs(composed["ci"]["remote_runs_passed"], False)
        self.assertIs(composed["regression"]["passed"], True)

    def test_cancelled_upstream_marks_remote_false(self):
        self._write_three()
        code = self._compose(upstream=("fast=success", "core=cancelled",
                                       "full-regression=success"))
        self.assertEqual(code, 0)
        self.assertIs(self._load()["ci"]["remote_runs_passed"], False)

    def test_failed_fragment_marks_platform_fail_and_remote_false(self):
        self._write("linux.json", _fragment("linux"))
        self._write("macos.json", _fragment("macos"))
        self._write(
            "windows.json",
            _fragment("windows", passed=False, failures=4),
        )
        self.assertEqual(self._compose(), 0)
        composed = self._load()
        self.assertEqual(composed["platforms"]["windows"], "fail")
        self.assertEqual(composed["regression"]["failures"], 4)
        self.assertIs(composed["regression"]["passed"], False)
        self.assertIs(composed["ci"]["remote_runs_passed"], False)


if __name__ == "__main__":
    unittest.main()
