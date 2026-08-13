"""Canonical bounded core test runner for CI version/platform cells (R5B).

Runs the full unit/integration suite EXCEPT the slow venv/pip end-to-end
packaging suites, which are executed in the dedicated packaging CI jobs.
The exclusion list is explicit and small; every other ``tests/test_*.py``
file discovered on disk is included automatically, so a newly added test
file can never be silently skipped by CI.

Usage (from the repository root):

    python -W error::ResourceWarning tools/run_core_tests.py [--list]
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
import unittest
from pathlib import Path
from typing import List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = REPO_ROOT / "tests"

#: Files excluded from the core cell, with the reason each lives in a
#: dedicated CI job instead. Keep this list exactly these two entries;
#: tests/test_tools_core_runner.py guards the contract.
EXCLUDED = {
    "test_install_e2e.py": (
        "slow venv/pip end-to-end suite; executed in the dedicated "
        "packaging CI job"
    ),
    "test_sdist_install_e2e.py": (
        "slow venv/pip end-to-end suite (sdist variant); executed in the "
        "dedicated packaging CI job"
    ),
}


def discover_test_files(tests_dir) -> Tuple[List[Path], List[Path]]:
    """Split ``test_*.py`` files under ``tests_dir`` into (included, excluded).

    Discovery is filename-based and total: any file not explicitly in
    :data:`EXCLUDED` is included. Both lists are sorted for determinism.
    """
    directory = Path(tests_dir)
    included: List[Path] = []
    excluded: List[Path] = []
    for path in sorted(directory.glob("test_*.py")):
        if path.name in EXCLUDED:
            excluded.append(path)
        else:
            included.append(path)
    return included, excluded


def inventory(tests_dir=None) -> Tuple[List[Path], List[Path]]:
    """The (included, excluded) inventory for the repository test suite."""
    return discover_test_files(tests_dir or TESTS_DIR)


def _load_module_from_path(path: Path) -> object:
    """Load a test module from its file path, regardless of sys.path."""
    module_name = f"relinkra_coretests_{path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load test module from {path}")
    module = importlib.util.module_from_spec(spec)
    # Registered before execution so dataclasses and future-annotation
    # resolution inside the module can find it.
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


def build_suite(files) -> unittest.TestSuite:
    """Build a TestSuite from an iterable of test file paths."""
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite()
    for path in files:
        module = _load_module_from_path(Path(path))
        suite.addTests(loader.loadTestsFromModule(module))
    return suite


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="run_core_tests",
        description=__doc__,
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="list the test files that would run, then exit 0",
    )
    args = parser.parse_args(argv)

    # Mirror ``unittest discover -s tests`` path semantics: the repository
    # root resolves ``import relinkra`` to the checkout, and the tests
    # directory resolves bare sibling imports such as
    # ``from test_context_packet import ...`` or ``import git_fixtures``
    # (tests/ has no __init__.py, exactly like discover's top-level dir).
    for path in (str(TESTS_DIR), str(REPO_ROOT)):
        if path not in sys.path:
            sys.path.insert(0, path)

    included, excluded = inventory()

    if args.list:
        for path in included:
            print(path.name)
        for path in excluded:
            print(f"{path.name}  # EXCLUDED: {EXCLUDED[path.name]}")
        return 0

    suite = build_suite(included)
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
