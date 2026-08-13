"""Packaging contract tests (R5A).

Unit-level only: no venv, no network, no wheel build. These guard the
declared packaging metadata in pyproject.toml (single-source version,
console entry points, explicit flat-layout package list), the .gitignore
coverage for Relinkra state, and the ``version`` command's path-free
output contract. The clean-install proof lives in
tests/test_install_e2e.py.
"""

from __future__ import annotations

import ast
import contextlib
import importlib
import io
import json
import re
import unittest
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python 3.9/3.10: the package floor is 3.9
    tomllib = None

import relinkra
from relinkra import product_cli

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
GITIGNORE = REPO_ROOT / ".gitignore"

VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")


def load_pyproject() -> dict:
    with PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)


def run_cli(argv):
    """Invoke the product CLI, returning (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = product_cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class PyprojectTests(unittest.TestCase):
    """The declared packaging metadata in pyproject.toml."""

    @classmethod
    def setUpClass(cls):
        if tomllib is None:
            raise unittest.SkipTest("tomllib requires Python 3.11+")
        cls.data = load_pyproject()

    def test_pyproject_parses_and_names_the_project(self):
        self.assertEqual(self.data["project"]["name"], "relinkra")

    def test_requires_python_minimum(self):
        self.assertEqual(self.data["project"]["requires-python"], ">=3.9")

    def test_build_backend_is_setuptools(self):
        self.assertEqual(
            self.data["build-system"]["build-backend"],
            "setuptools.build_meta",
        )
        requires = self.data["build-system"]["requires"]
        self.assertTrue(
            any(req.split(";")[0].strip().startswith("setuptools") for req in requires),
            f"build requires must include setuptools, got {requires}",
        )

    def test_version_is_dynamic_and_single_sourced(self):
        dynamic = self.data["tool"]["setuptools"]["dynamic"]["version"]
        self.assertEqual(dynamic, {"attr": "relinkra.__version__"})
        self.assertRegex(relinkra.__version__, VERSION_PATTERN)

    def test_project_table_never_hardcodes_version(self):
        # Mutation guard: the version must stay dynamic, read from
        # relinkra/__init__.py — never duplicated as a literal here.
        self.assertNotIn("version", self.data["project"])
        self.assertIn("version", self.data["project"]["dynamic"])

    def test_console_scripts_point_at_existing_mains(self):
        scripts = self.data["project"]["scripts"]
        self.assertEqual(
            scripts,
            {
                "relinkra": "relinkra.product_cli:main",
                "relinkra-mcp": "relinkra.mcp_cli:main",
            },
        )
        # Mutation guard: a renamed or removed entry point target fails
        # here instead of shipping a broken console script.
        for target in scripts.values():
            module_name, func_name = target.split(":")
            module = importlib.import_module(module_name)
            self.assertTrue(
                callable(getattr(module, func_name, None)),
                f"{target} is not callable",
            )

    def test_only_the_relinkra_package_is_shipped(self):
        packages = self.data["tool"]["setuptools"]["packages"]
        self.assertEqual(packages, ["relinkra"])
        self.assertNotIn("tests", packages)


class GitignoreTests(unittest.TestCase):
    def test_relinkra_state_and_build_junk_are_ignored(self):
        lines = GITIGNORE.read_text(encoding="utf-8").splitlines()
        for pattern in (
            ".relinkra/",
            ".codebase-memory/",
            "*.relinkra-backup*",
            "__pycache__/",
        ):
            self.assertIn(pattern, lines)


class VersionCommandTests(unittest.TestCase):
    """The ``version`` subcommand and the ``--version`` argparse flag."""

    EXPECTED_KEYS = {
        "relinkra_version",
        "contract_version",
        "python_version",
        "min_python_version",
        "install_mode",
    }

    def assert_no_local_paths(self, text: str) -> None:
        """A version answer must never leak local directories."""
        self.assertNotIn(str(REPO_ROOT), text)
        self.assertNotIn("C:\\", text)

    def test_version_text_is_path_free(self):
        code, out, err = run_cli(["version"])
        self.assertEqual(code, 0, err)
        first_line = out.splitlines()[0]
        self.assertEqual(first_line, f"relinkra {relinkra.__version__}")
        self.assert_no_local_paths(out)

    def test_version_json_payload_is_exact(self):
        code, out, err = run_cli(["version", "--json"])
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(set(payload), self.EXPECTED_KEYS)
        self.assertEqual(payload["relinkra_version"], relinkra.__version__)
        self.assert_no_local_paths(out)

    def test_dash_dash_version_flag_exits_zero(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as raised:
                product_cli.main(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(
            out.getvalue().strip(), f"relinkra {relinkra.__version__}"
        )


class TestPythonFloorContract(unittest.TestCase):
    """The Python 3.9 production floor: no construct in relinkra/ may
    require a newer interpreter at import or runtime.

    - no match statements (3.10+ syntax);
    - tomllib (3.11+) only ever imported inside try/except ImportError;
    - PEP 604 unions (``X | Y``, 3.10+) never evaluated at runtime on
      3.9: allowed in annotations ONLY when the module has
      ``from __future__ import annotations`` (making them lazy strings)
      or the annotation is itself a string literal.
    """

    MODULES = sorted((REPO_ROOT / "relinkra").glob("*.py"))

    def _trees(self):
        return {
            path.name: ast.parse(path.read_text(encoding="utf-8"))
            for path in self.MODULES
        }

    @staticmethod
    def _has_future_annotations(tree) -> bool:
        for node in tree.body:
            if (
                isinstance(node, ast.ImportFrom)
                and node.module == "__future__"
                and any(alias.name == "annotations" for alias in node.names)
            ):
                return True
        return False

    def test_no_match_statements(self):
        for name, tree in self._trees().items():
            offenders = [
                type(node).__name__
                for node in ast.walk(tree)
                if type(node).__name__.startswith("Match")
            ]
            self.assertEqual(offenders, [], f"{name}: {offenders}")

    def test_tomllib_imports_are_guarded(self):
        for name, tree in self._trees().items():
            parents = {}
            for node in ast.walk(tree):
                for child in ast.iter_child_nodes(node):
                    parents[child] = node
            for node in ast.walk(tree):
                imports_tomllib = (
                    isinstance(node, ast.Import)
                    and any(a.name == "tomllib" for a in node.names)
                ) or (
                    isinstance(node, ast.ImportFrom)
                    and node.module == "tomllib"
                )
                if not imports_tomllib:
                    continue
                guarded = False
                cursor = node
                while cursor in parents:
                    cursor = parents[cursor]
                    if isinstance(cursor, ast.Try) and any(
                        _handler_catches_import_error(handler)
                        for handler in cursor.handlers
                    ):
                        guarded = True
                        break
                self.assertTrue(
                    guarded,
                    f"{name}:line {node.lineno} imports tomllib unguarded",
                )

    def test_no_runtime_pep604_unions(self):
        for name, tree in self._trees().items():
            if self._has_future_annotations(tree):
                continue
            annotations = []
            for node in ast.walk(tree):
                if isinstance(node, ast.AnnAssign) and node.annotation:
                    annotations.append(node.annotation)
                elif isinstance(node, ast.arg) and node.annotation:
                    annotations.append(node.annotation)
                elif isinstance(node, ast.FunctionDef) and node.returns:
                    annotations.append(node.returns)
                elif isinstance(node, ast.AsyncFunctionDef) and node.returns:
                    annotations.append(node.returns)
            for annotation in annotations:
                for inner in ast.walk(annotation):
                    if isinstance(inner, ast.Constant):
                        continue  # string annotation: never evaluated
                    if isinstance(inner, ast.BinOp) and isinstance(
                        inner.op, ast.BitOr
                    ):
                        self.fail(
                            f"{name}:line {inner.lineno} evaluates a PEP 604 "
                            f"union without 'from __future__ import annotations'"
                        )


def _handler_catches_import_error(handler) -> bool:
    target = handler.type
    if target is None:
        return True  # bare except
    names = []
    if isinstance(target, ast.Name):
        names = [target.id]
    elif isinstance(target, ast.Tuple):
        names = [elt.id for elt in target.elts if isinstance(elt, ast.Name)]
    return "ImportError" in names or "Exception" in names


if __name__ == "__main__":
    unittest.main()
