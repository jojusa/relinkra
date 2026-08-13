"""Tests for tools/run_core_tests.py — the canonical core CI runner (R5B)."""

from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import run_core_tests


class ExcludedContractTests(unittest.TestCase):
    def test_excluded_is_exactly_the_two_e2e_suites(self):
        self.assertEqual(
            set(run_core_tests.EXCLUDED),
            {"test_install_e2e.py", "test_sdist_install_e2e.py"},
        )

    def test_every_exclusion_has_a_reason(self):
        for name, reason in run_core_tests.EXCLUDED.items():
            self.assertIsInstance(reason, str)
            self.assertTrue(reason.strip(), f"{name} has an empty reason")


class InventoryTests(unittest.TestCase):
    def test_inventory_covers_every_test_file_exactly_once(self):
        included, excluded = run_core_tests.inventory()
        included_names = {path.name for path in included}
        excluded_names = {path.name for path in excluded}

        self.assertFalse(included_names & excluded_names)
        on_disk = {
            path.name
            for path in (REPO_ROOT / "tests").glob("test_*.py")
        }
        self.assertEqual(on_disk, included_names | excluded_names)

    def test_e2e_files_are_excluded_everything_else_included(self):
        included, excluded = run_core_tests.inventory()
        excluded_names = {path.name for path in excluded}
        included_names = {path.name for path in included}
        self.assertEqual(excluded_names, set(run_core_tests.EXCLUDED))
        self.assertIn("test_product_cli.py", included_names)
        self.assertIn("test_packaging.py", included_names)


class BuildSuiteTests(unittest.TestCase):
    def test_build_suite_loads_only_included_files(self):
        with tempfile.TemporaryDirectory(prefix="relinkra-coretests-") as tmp:
            fixture = Path(tmp)
            (fixture / "test_alpha.py").write_text(
                "import unittest\n"
                "class AlphaTests(unittest.TestCase):\n"
                "    def test_ok(self):\n"
                "        self.assertTrue(True)\n",
                encoding="utf-8",
            )
            (fixture / "test_beta.py").write_text(
                "import unittest\n"
                "class BetaTests(unittest.TestCase):\n"
                "    def test_ok(self):\n"
                "        self.assertEqual(1, 1)\n",
                encoding="utf-8",
            )
            # Named like an E2E exclusion; must NOT be loaded.
            (fixture / "test_install_e2e.py").write_text(
                "import unittest\n"
                "class ShouldNotRun(unittest.TestCase):\n"
                "    def test_no(self):\n"
                "        self.fail('excluded file was loaded')\n",
                encoding="utf-8",
            )
            included, excluded = run_core_tests.discover_test_files(fixture)
            self.assertEqual(
                [path.name for path in included],
                ["test_alpha.py", "test_beta.py"],
            )
            self.assertEqual(
                [path.name for path in excluded], ["test_install_e2e.py"]
            )
            suite = run_core_tests.build_suite(included)
            self.assertEqual(suite.countTestCases(), 2)
            stream = io.StringIO()
            result = unittest.TextTestRunner(stream=stream).run(suite)
            self.assertTrue(result.wasSuccessful(), stream.getvalue())


class ListModeTests(unittest.TestCase):
    def test_list_mode_exits_zero_and_mentions_known_files(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = run_core_tests.main(["--list"])
        self.assertEqual(code, 0)
        text = out.getvalue()
        self.assertIn("test_product_cli.py", text)
        self.assertIn("EXCLUDED", text)


if __name__ == "__main__":
    unittest.main()
