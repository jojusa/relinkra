"""Tests for tools/emit_run_evidence.py — run-scoped fragments (R5C)."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import emit_run_evidence

SHA = "d818b8c20d38557ab6624a9a3e4fe66a11532261"
RUN_ID = "31760708465"


def _argv(out, platform="linux", **overrides):
    argv = [
        "--platform", platform,
        "--job", "full-regression",
        "--sha", SHA,
        "--run-id", RUN_ID,
        "--out", str(out),
        "--tests", "2061",
        "--failures", "0",
        "--errors", "0",
        "--resource-warnings", "0",
    ]
    for key, value in overrides.items():
        name = "--" + key.replace("_", "-")
        if value is None:
            argv = [
                item
                for index, item in enumerate(argv)
                if item != name and (index == 0 or argv[index - 1] != name)
            ]
        else:
            argv.extend([name, str(value)])
    return argv


class ExplicitCountsTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.out = Path(self._tmp.name) / "fragment.json"

    def _run(self, **overrides):
        return emit_run_evidence.main(_argv(self.out, **overrides))

    def _load(self):
        return json.loads(self.out.read_text(encoding="utf-8"))

    def test_valid_fragment_for_every_platform(self):
        for platform in ("windows", "linux", "macos"):
            with self.subTest(platform=platform):
                out = Path(self._tmp.name) / f"{platform}.json"
                code = emit_run_evidence.main(_argv(out, platform=platform))
                self.assertEqual(code, 0)
                fragment = json.loads(out.read_text(encoding="utf-8"))
                self.assertEqual(set(fragment), {"meta", "platform", "regression"})
                self.assertEqual(
                    set(fragment["meta"]), {"sha", "run_id", "job", "os"}
                )
                self.assertEqual(fragment["meta"]["sha"], SHA)
                self.assertEqual(fragment["meta"]["run_id"], RUN_ID)
                self.assertEqual(fragment["meta"]["job"], "full-regression")
                self.assertEqual(fragment["meta"]["os"], platform)
                self.assertEqual(fragment["platform"], platform)
                self.assertEqual(
                    set(fragment["regression"]),
                    {"passed", "tests", "failures", "errors",
                     "resource_warnings", "where"},
                )
                self.assertIs(fragment["regression"]["passed"], True)
                self.assertEqual(fragment["regression"]["tests"], 2061)

    def test_runner_os_label_overrides_meta_os(self):
        code = self._run(runner_os="windows-latest")
        self.assertEqual(code, 0)
        fragment = self._load()
        self.assertEqual(fragment["meta"]["os"], "windows-latest")
        self.assertEqual(fragment["platform"], "linux")

    def test_missing_sha_rejected(self):
        code = emit_run_evidence.main(_argv(self.out, sha=None))
        self.assertEqual(code, 2)
        self.assertFalse(self.out.exists())

    def test_empty_sha_rejected(self):
        self.assertEqual(self._run(sha=""), 2)

    def test_non_hex_sha_rejected(self):
        bad = "g" + SHA[1:]
        self.assertEqual(self._run(sha=bad), 2)

    def test_wrong_length_sha_rejected(self):
        self.assertEqual(self._run(sha=SHA[:-1]), 2)

    def test_uppercase_sha_rejected(self):
        self.assertEqual(self._run(sha=SHA.upper()), 2)

    def test_empty_run_id_rejected(self):
        self.assertEqual(self._run(run_id=""), 2)

    def test_non_digit_run_id_rejected(self):
        self.assertEqual(self._run(run_id="3176abc"), 2)

    def test_negative_count_rejected(self):
        self.assertEqual(self._run(tests="-1"), 2)
        self.assertFalse(self.out.exists())

    def test_non_integer_count_rejected(self):
        self.assertEqual(self._run(tests="3.5"), 2)
        self.assertEqual(self._run(failures="many"), 2)

    def test_passed_true_with_failures_rejected(self):
        code = self._run(failures="1", passed="true")
        self.assertEqual(code, 2)
        self.assertFalse(self.out.exists())

    def test_passed_true_with_resource_warnings_rejected(self):
        self.assertEqual(
            self._run(**{"resource-warnings": "2", "passed": "true"}), 2
        )

    def test_passed_derived_true_when_green(self):
        code = self._run()
        self.assertEqual(code, 0)
        self.assertIs(self._load()["regression"]["passed"], True)

    def test_passed_derived_false_when_failures_present(self):
        code = self._run(failures="3")
        self.assertEqual(code, 0)
        self.assertIs(self._load()["regression"]["passed"], False)

    def test_zero_tests_never_infers_pass(self):
        # Explicit zeros with tests=0: nothing ran, so nothing is green.
        code = self._run(tests="0")
        self.assertEqual(code, 0)
        fragment = self._load()
        self.assertEqual(fragment["regression"]["tests"], 0)
        self.assertIs(fragment["regression"]["passed"], False)

    def test_deterministic_output_bytes(self):
        first = Path(self._tmp.name) / "first.json"
        second = Path(self._tmp.name) / "second.json"
        self.assertEqual(emit_run_evidence.main(_argv(first)), 0)
        self.assertEqual(emit_run_evidence.main(_argv(second)), 0)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertTrue(first.read_bytes().endswith(b"\n"))
        self.assertNotIn(b"\r", first.read_bytes())

    def test_mixed_modes_rejected(self):
        code = emit_run_evidence.main(
            _argv(self.out) + ["--run-regression"]
        )
        self.assertEqual(code, 2)

    def test_no_input_mode_rejected(self):
        argv = _argv(self.out)
        for name in ("--tests", "--failures", "--errors",
                     "--resource-warnings"):
            index = argv.index(name)
            del argv[index:index + 2]
        self.assertEqual(emit_run_evidence.main(argv), 2)


if __name__ == "__main__":
    unittest.main()
