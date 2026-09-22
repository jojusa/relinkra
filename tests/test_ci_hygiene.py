"""CI / workflow hygiene audits (R5B Batch 2).

Static, stdlib-only audits over the repository's own CI surface:

- every skip in the test suite carries an explicit reason;
- no developer-machine absolute path leaks into committed files;
- every subprocess / urlopen call site in product code is bounded by a
  timeout (known debt is allowlisted explicitly, never silently);
- the GitHub workflows obey the security contract (minimal permissions,
  no untrusted triggers, pinned actions, no secrets) and the structural
  contract the jobs were designed around;
- the core-runner inventory and the workflow python floor stay honest.

These audits parse text and ASTs only; they mutate nothing and read
nothing outside the repository checkout.
"""

from __future__ import annotations

import ast
import re
import sys
import unittest
from pathlib import Path
from typing import List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import ci_pin_policy, run_core_tests

TESTS_DIR = REPO_ROOT / "tests"
TOOLS_DIR = REPO_ROOT / "tools"
PRODUCT_DIR = REPO_ROOT / "relinkra"
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

REQUIRED_WORKFLOWS = ("ci.yml", "packaging.yml", "release-dry-run.yml")


def _read(path: Path) -> str:
    """Read a repository text file (Path.read_text closes the file)."""
    return path.read_text(encoding="utf-8")


def _parse(path: Path) -> ast.Module:
    return ast.parse(_read(path), filename=str(path))


# ---------------------------------------------------------------------------
# (a) Skip reason audit
# ---------------------------------------------------------------------------

#: Skip-style calls and the positional index of their reason argument.
_SKIP_REASON_INDEX = {
    "skip": 0,
    "skipIf": 1,
    "skipUnless": 1,
    "skipTest": 0,
    "SkipTest": 0,
}


def _call_short_name(func: ast.expr) -> Optional[str]:
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _reason_expression_ok(arg: ast.expr) -> bool:
    """A reason argument counts when it is present and not statically
    empty. F-strings, concatenations and names are dynamic but a reason
    was clearly supplied; only a constant can be proven empty."""
    if isinstance(arg, ast.Constant):
        return isinstance(arg.value, str) and bool(arg.value.strip())
    return True


def _skip_call_has_reason(node: ast.Call, index: int) -> bool:
    if len(node.args) > index:
        return _reason_expression_ok(node.args[index])
    for keyword in node.keywords:
        if keyword.arg == "reason":
            return _reason_expression_ok(keyword.value)
    return False


def _skip_violations(path: Path) -> List[str]:
    """file:line entries for skip calls/decorators without a reason."""
    violations: List[str] = []
    tree = _parse(path)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_short_name(node.func)
            if name in _SKIP_REASON_INDEX:
                if not _skip_call_has_reason(node, _SKIP_REASON_INDEX[name]):
                    violations.append(
                        f"{path.name}:{node.lineno}: {name}() has no reason"
                    )
        elif isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            for decorator in node.decorator_list:
                # A bare @skip (never called) cannot carry a reason.
                if not isinstance(decorator, ast.Call):
                    name = _call_short_name(decorator)
                    if name in ("skip", "skipIf", "skipUnless"):
                        violations.append(
                            f"{path.name}:{decorator.lineno}: "
                            f"@{name} used without a call, so without a reason"
                        )
    return violations


class SkipReasonAudit(unittest.TestCase):
    def test_every_skip_carries_a_reason(self):
        violations: List[str] = []
        test_files = sorted(TESTS_DIR.glob("test_*.py"))
        self.assertTrue(test_files, "no test files discovered")
        for path in test_files:
            violations.extend(_skip_violations(path))
        self.assertEqual(
            violations,
            [],
            "skips without an explicit reason:\n" + "\n".join(violations),
        )


# ---------------------------------------------------------------------------
# (b) Developer path audit
# ---------------------------------------------------------------------------

_HOME_PATH = re.compile(
    r"(?:C:\\Users\\|C:/Users/|/Users/|/home/)([^\\\s/\"'`)\]}|+(]+)"
)

#: Usernames that are generic fixtures or documented placeholders, not a
#: developer's real account. ``runner`` is the GitHub-hosted default;
#: the short names are synthetic identities used across the test suite's
#: path-redaction fixtures. Anything else after a home-directory prefix
#: is treated as a leaked developer-machine path.
_GENERIC_USERNAMES = frozenset(
    {
        "runner",
        "u",
        "me",
        "alice",
        "bob",
        "dev",
        "devin",
        "user",
        "users",
        "example",
        "private",
        "youruser",
        "your-user",
        "username",
        "someone",
        "owner",
        "test",
        "tester",
    }
)


def _developer_path_hits(path: Path) -> List[str]:
    hits: List[str] = []
    for lineno, line in enumerate(_read(path).splitlines(), 1):
        for match in _HOME_PATH.finditer(line):
            name = match.group(1).rstrip(".,;:\"'").lower()
            if name not in _GENERIC_USERNAMES:
                hits.append(f"{path.name}:{lineno}: {match.group(0)}")
    return hits


class DeveloperPathAudit(unittest.TestCase):
    def _targets(self) -> List[Path]:
        targets: List[Path] = []
        targets.extend(sorted(TESTS_DIR.glob("*.py")))
        targets.extend(sorted(TOOLS_DIR.glob("*.py")))
        targets.extend(sorted(WORKFLOWS_DIR.glob("*.yml")))
        return targets

    def test_no_developer_absolute_paths(self):
        hits: List[str] = []
        for path in self._targets():
            hits.extend(_developer_path_hits(path))
        self.assertEqual(
            hits,
            [],
            "possible developer-machine paths:\n" + "\n".join(hits),
        )


# ---------------------------------------------------------------------------
# (c) Timeout audit on product code
# ---------------------------------------------------------------------------

#: Known product-code debt allowlist. Key: (file, function, call).
#:
#: Currently EMPTY: the one recorded debt (identity.py::_git missing
#: ``timeout=``) was fixed in R5B by bounding the call with GIT_TIMEOUT and
#: converting TimeoutExpired to GitError (covered by test_identity.py).
#:
#: The audit asserts EXACT equality with this set: any NEW subprocess or
#: urlopen call site without a timeout fails the suite. Never silence a new
#: violation by editing this set — bound the call instead.
_KNOWN_TIMEOUT_DEBT = frozenset()


class _TimeoutVisitor(ast.NodeVisitor):
    """Collect subprocess/urlopen call sites missing a timeout keyword."""

    def __init__(self) -> None:
        self.stack: List[str] = []
        self.violations: Set[Tuple[str, str, str]] = set()

    @property
    def enclosing(self) -> str:
        return self.stack[-1] if self.stack else "<module>"

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        kind = self._bounded_kind(node.func)
        if kind is not None and not any(
            keyword.arg == "timeout" for keyword in node.keywords
        ):
            self.violations.add((self.filename, self.enclosing, kind))
        self.generic_visit(node)

    @staticmethod
    def _bounded_kind(func: ast.expr) -> Optional[str]:
        if isinstance(func, ast.Attribute):
            if func.attr == "communicate":
                return ".communicate()"
            if (
                func.attr == "run"
                and isinstance(func.value, ast.Name)
                and func.value.id == "subprocess"
            ):
                return "subprocess.run"
            if func.attr == "urlopen":
                return "urlopen"
        elif isinstance(func, ast.Name):
            if func.id == "urlopen":
                return "urlopen"
        return None


class TimeoutAudit(unittest.TestCase):
    def test_product_network_and_subprocess_calls_are_bounded(self):
        violations: Set[Tuple[str, str, str]] = set()
        for path in sorted(PRODUCT_DIR.glob("*.py")):
            visitor = _TimeoutVisitor()
            visitor.filename = path.name
            visitor.visit(_parse(path))
            violations |= visitor.violations
        self.assertEqual(
            violations,
            set(_KNOWN_TIMEOUT_DEBT),
            "timeout violations differ from the known-debt allowlist;\n"
            "new violations (fix them, never edit the allowlist): "
            + repr(sorted(violations - _KNOWN_TIMEOUT_DEBT))
            + "\nstale entries (the debt was paid; remove them): "
            + repr(sorted(_KNOWN_TIMEOUT_DEBT - violations)),
        )


# ---------------------------------------------------------------------------
# (d) Workflow security audit
# ---------------------------------------------------------------------------

_TOP_PERMISSIONS = re.compile(r"^permissions:\n((?:^ +.*\n?)+)", re.MULTILINE)


class WorkflowSecurityAudit(unittest.TestCase):
    def _workflow_texts(self):
        self.assertTrue(
            WORKFLOWS_DIR.is_dir(), ".github/workflows/ does not exist"
        )
        texts = {}
        for name in REQUIRED_WORKFLOWS:
            path = WORKFLOWS_DIR / name
            self.assertTrue(path.is_file(), f"missing workflow: {name}")
            texts[name] = _read(path)
        return texts

    def test_required_workflows_exist(self):
        self._workflow_texts()

    def test_minimal_top_level_permissions(self):
        for name, text in self._workflow_texts().items():
            with self.subTest(workflow=name):
                top = _TOP_PERMISSIONS.search(text)
                self.assertIsNotNone(
                    top, f"{name}: no top-level permissions block"
                )
                self.assertRegex(
                    top.group(1),
                    r"(?m)^\s+contents:\s*read\s*$",
                    f"{name}: permissions must be exactly contents: read",
                )

    def test_no_untrusted_triggers_or_error_tolerance(self):
        for name, text in self._workflow_texts().items():
            with self.subTest(workflow=name):
                self.assertNotIn("pull_request_target", text)
                self.assertNotIn("continue-on-error: true", text)

    def test_actions_are_pinned(self):
        # Strict M8 policy: every external uses: reference must carry a
        # full 40-char lowercase commit SHA (the version comment is
        # informational). ci_pin_policy owns the rule.
        for name in REQUIRED_WORKFLOWS:
            with self.subTest(workflow=name):
                violations = ci_pin_policy.scan_file(WORKFLOWS_DIR / name)
                self.assertEqual(
                    violations,
                    [],
                    ci_pin_policy.format_violations(violations),
                )

    def test_no_secrets_references(self):
        # These workflows need no secrets at all; the string must be absent.
        for name, text in self._workflow_texts().items():
            with self.subTest(workflow=name):
                self.assertNotIn("secrets.", text)

    def test_yaml_uses_spaces_only(self):
        for name, text in self._workflow_texts().items():
            with self.subTest(workflow=name):
                self.assertNotIn("\t", text, f"{name}: tab character")
                self.assertNotIn("\r", text, f"{name}: CRLF line ending")


# ---------------------------------------------------------------------------
# (d2) Strict action pin policy (M8)
# ---------------------------------------------------------------------------


class ActionPinPolicyAudit(unittest.TestCase):
    """Unit cases for the strict pin policy in tools/ci_pin_policy.py.

    Every external ``uses:`` reference must carry a full 40-char lowercase
    commit SHA; the ``# vX.Y.Z`` version comment is informational only.
    """

    SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"

    def _scan_value(self, value: str):
        return ci_pin_policy.scan_text(
            f"      - uses: {value}\n", path="x.yml"
        )

    def _assert_rejected(self, value: str) -> None:
        violations = self._scan_value(value)
        self.assertTrue(
            violations, f"expected at least one violation for {value!r}"
        )

    def _assert_accepted(self, value: str) -> None:
        violations = self._scan_value(value)
        self.assertEqual(
            violations, [], ci_pin_policy.format_violations(violations)
        )

    def test_mutable_refs_are_rejected(self):
        for value in (
            "actions/checkout@v4",
            "owner/action@main",
            "owner/action@master",
            "owner/action@v1.2.3",
        ):
            with self.subTest(uses=value):
                self._assert_rejected(value)

    def test_malformed_commit_lengths_are_rejected(self):
        for length in (7, 32, 39, 41):
            with self.subTest(length=length):
                self._assert_rejected(f"owner/action@{'a' * length}")

    def test_non_hex_and_uppercase_shas_are_rejected(self):
        self._assert_rejected(f"owner/action@{'z' * 40}")
        uppercase = self._scan_value(f"owner/action@{self.SHA.upper()}")
        self.assertEqual(len(uppercase), 1)
        self.assertIn("uppercase", uppercase[0].problem)

    def test_ref_less_and_container_refs_are_rejected(self):
        self._assert_rejected("actions/checkout")
        self._assert_rejected("docker://alpine:latest")
        self._assert_rejected("docker://alpine@sha256:abc")

    def test_dot_segments_in_remote_refs_are_rejected(self):
        for value in (
            f"owner/../evil@{self.SHA}",
            f"../evil@{self.SHA}",
            f"owner/./x@{self.SHA}",
        ):
            with self.subTest(uses=value):
                self._assert_rejected(value)

    def test_parent_segments_in_local_refs_are_rejected(self):
        for value in ("./../evil", "./a/../b"):
            with self.subTest(uses=value):
                self._assert_rejected(value)

    def test_uppercase_digest_is_rejected_canonically(self):
        violations = self._scan_value(
            f"docker://alpine@sha256:{'C' * 64}"
        )
        self.assertEqual(len(violations), 1)
        self.assertIn("uppercase", violations[0].problem)

    def test_valueless_uses_key_fails_closed(self):
        # A multi-line value is unverifiable by the bounded scanner, so
        # the valueless form must be reported instead of silently skipped.
        violations = ci_pin_policy.scan_text(
            "      - uses:\n        actions/checkout@v4\n", path="x.yml"
        )
        self.assertTrue(
            violations, "a valueless uses: key must not evade the scanner"
        )
        self.assertEqual(violations[0].path, "x.yml")
        self.assertEqual(violations[0].line, 1)
        self.assertEqual(violations[0].uses, "")

    def test_regression_accepted_refs_stay_accepted(self):
        for value in (
            "./local/action",
            "./.github/workflows/foo.yml",
            f"owner/repo/sub/path@{self.SHA}",
            f"actions/checkout@{self.SHA} # v7.0.1",
        ):
            with self.subTest(uses=value):
                self._assert_accepted(value)

    def test_pinned_local_and_digest_refs_are_accepted(self):
        for value in (
            f"actions/checkout@{self.SHA} # v7.0.1",
            f"owner/repo/sub/path@{'b' * 40}",
            "./local/action",
            "./.github/workflows/foo.yml",
            f"docker://alpine@sha256:{'c' * 64}",
            f'"actions/checkout@{self.SHA}"',
        ):
            with self.subTest(uses=value):
                self._assert_accepted(value)

    def test_scanner_ignores_comments_and_block_scalar_text(self):
        text = (
            "# - uses: actions/checkout@v4\n"
            "      - name: step\n"
            "        run: |\n"
            "          uses: owner/action@main\n"
            "          # - uses: owner/action@v1\n"
            '        shell: echo "uses: owner/action@main"\n'
        )
        violations = ci_pin_policy.scan_text(text, path="x.yml")
        self.assertEqual(
            violations, [], ci_pin_policy.format_violations(violations)
        )

    def test_real_uses_after_a_block_scalar_is_detected_once(self):
        text = (
            "      - name: step\n"
            "        run: |\n"
            "          uses: owner/action@main\n"
            "      - uses: owner/action@main\n"
        )
        violations = ci_pin_policy.scan_text(text, path="x.yml")
        self.assertEqual(
            len(violations),
            1,
            ci_pin_policy.format_violations(violations),
        )
        self.assertEqual(violations[0].path, "x.yml")
        self.assertEqual(violations[0].line, 4)
        self.assertEqual(violations[0].uses, "owner/action@main")

    def test_inline_comment_does_not_excuse_a_mutable_ref(self):
        violations = self._scan_value(
            "actions/checkout@v4 # deliberately mutable"
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].uses, "actions/checkout@v4")

    def test_violation_string_is_readable(self):
        violations = self._scan_value("actions/checkout@v4")
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            str(violations[0]),
            f"x.yml:1: actions/checkout@v4 -> {violations[0].problem}",
        )

    def test_repository_workflows_are_fully_pinned(self):
        violations = ci_pin_policy.scan_workflows_dir(WORKFLOWS_DIR)
        self.assertEqual(
            violations, [], ci_pin_policy.format_violations(violations)
        )
        scanned = sum(
            sum(
                1
                for _ in ci_pin_policy.iter_uses(
                    _read(WORKFLOWS_DIR / name)
                )
            )
            for name in REQUIRED_WORKFLOWS
        )
        self.assertGreaterEqual(
            scanned, 20, "too few uses: references scanned; vacuous pass risk"
        )


# ---------------------------------------------------------------------------
# (e) Workflow structural contract
# ---------------------------------------------------------------------------


class WorkflowContractAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.texts = {
            name: _read(WORKFLOWS_DIR / name) for name in REQUIRED_WORKFLOWS
        }

    def test_ci_job_ids_and_commands(self):
        ci = self.texts["ci.yml"]
        for job_id in ("fast", "core", "full-regression", "release-readiness"):
            self.assertIn(f"\n  {job_id}:\n", ci, f"ci.yml missing job {job_id}")
        # R5C: the full-regression job runs the canonical suite through
        # the run-scoped evidence emitter, which promotes ResourceWarning
        # to error in-process (mirroring release_check.run_regression);
        # the raw `unittest discover` command no longer lives in ci.yml.
        self.assertIn("tools/emit_run_evidence.py --run-regression", ci)
        self.assertIn("tools/run_core_tests.py", ci)

    def test_ci_matrix_covers_floor_to_current(self):
        ci = self.texts["ci.yml"]
        for version in ("3.9", "3.10", "3.11", "3.12", "3.13", "3.14"):
            self.assertIn(f'"{version}"', ci, f"ci.yml missing python {version}")
        for runner in ("ubuntu-latest", "windows-latest", "macos-latest"):
            self.assertIn(runner, ci)

    def test_core_smoke_bootstraps_a_committed_repo(self):
        # `relinkra init` FAILs HONESTLY on a repository with zero commits
        # (no resolvable project identity). The core smoke must therefore
        # create a deterministic initial commit — with a disposable local
        # Git identity, never the runner's global config — BEFORE invoking
        # `relinkra init`, or every core matrix cell fails before the core
        # suite ever runs (R5C remote evidence, run 31719355467).
        ci = self.texts["ci.yml"]
        match = re.search(
            r"(?ms)^      - name: Installed CLI smoke\n(?P<body>.*?)(?=^      - name: |\Z)",
            ci,
        )
        self.assertIsNotNone(match, "ci.yml missing the Installed CLI smoke step")
        body = match.group("body")
        for token, after in (
            ("git config user.email", None),
            ("git config user.name", None),
            ("git commit", "git config user.name"),
            ("relinkra init --json", "git commit"),
        ):
            self.assertIn(token, body, f"smoke step missing {token!r}")
            if after is not None:
                self.assertLess(
                    body.index(after),
                    body.index(token),
                    f"smoke step: {token!r} must come after {after!r}",
                )

    def test_packaging_contract(self):
        packaging = self.texts["packaging.yml"]
        for job_id in ("build", "wheel-install", "sdist-install"):
            self.assertIn(
                f"\n  {job_id}:\n", packaging, f"packaging.yml missing {job_id}"
        )
        for token in (
            "tools/artifact_checks.py",
            "RELINKRA_E2E_ARTIFACT",
            "test_install_e2e.py",
            "test_sdist_install_e2e.py",
            "if-no-files-found: error",
        ):
            self.assertIn(token, packaging, f"packaging.yml missing {token}")
        self.assertIn(
            '- { os: ubuntu-latest, python: "3.9" }',
            packaging,
            "packaging.yml missing the bounded sdist Python 3.9 cell",
        )
        self.assertEqual(
            packaging.count('- { os: ubuntu-latest, python: "3.9" }'),
            2,
            "the wheel and sdist jobs must each contain one Ubuntu Python 3.9 cell",
        )

    def test_packaging_artifact_steps_fail_closed_and_select_recursively(self):
        packaging = self.texts["packaging.yml"]

        def step_body(name):
            match = re.search(
                rf"(?ms)^      - name: {re.escape(name)}\n"
                rf"(?P<body>.*?)(?=^      - name: |\Z)",
                packaging,
            )
            self.assertIsNotNone(match, f"packaging.yml missing {name}")
            return match.group("body")

        inspect = step_body("Inspect artifacts")
        self.assertIn("set -euo pipefail", inspect)
        self.assertIn("tools/artifact_checks.py", inspect)

        for name, kind in (
            ("Select the downloaded wheel", "wheel"),
            ("Select the downloaded sdist", "sdist"),
        ):
            with self.subTest(step=name):
                body = step_body(name)
                self.assertIn("set -euo pipefail", body)
                self.assertIn(
                    f"tools/artifact_checks.py --select {kind}", body
                )
                self.assertIn("--artifact-dir artifacts", body)
                self.assertIn(
                    "--checksum-manifest artifacts/SHA256SUMS.txt", body
                )
                self.assertNotIn("glob.glob", body)

    def test_dry_run_cannot_publish(self):
        dry_run = self.texts["release-dry-run.yml"]
        self.assertIn("workflow_dispatch", dry_run)
        # Manual trigger only: no push / pull_request triggers.
        self.assertNotIn("push:", dry_run)
        self.assertNotIn("pull_request:", dry_run)
        # Anti-accidental-release guard: no upload tooling vocabulary at
        # all, not even in comments.
        lowered = dry_run.lower()
        for token in ("pypi", "twine", "publish"):
            self.assertNotIn(token, lowered, f"release-dry-run.yml mentions {token}")

    def test_dry_run_summary_uses_computed_report(self):
        dry_run = self.texts["release-dry-run.yml"]
        summary = dry_run.split(
            "- name: Append the RC gate summary", 1
        )[1]
        self.assertIn("rc-report.json", summary)
        self.assertIn("python -m json.tool rc-report.json", summary)
        self.assertNotIn("python tools/release_check.py", summary)


# ---------------------------------------------------------------------------
# (f) Run-scoped remote evidence contract (R5C)
# ---------------------------------------------------------------------------


class RunScopedEvidenceAudit(unittest.TestCase):
    """The ci.yml wiring for SHA-bound, ephemeral, run-scoped evidence."""

    @classmethod
    def setUpClass(cls):
        cls.ci = _read(WORKFLOWS_DIR / "ci.yml")

    def _job_body(self, job_id):
        match = re.search(
            rf"(?ms)^  {re.escape(job_id)}:\n(?P<body>.*?)(?=^  \S|\Z)",
            self.ci,
        )
        self.assertIsNotNone(match, f"ci.yml missing job {job_id}")
        return match.group("body")

    def test_release_readiness_runs_always(self):
        body = self._job_body("release-readiness")
        self.assertIn("if: always()", body)

    def test_run_evidence_fragments_downloaded_unmerged(self):
        body = self._job_body("release-readiness")
        self.assertIn("actions/download-artifact@", body)
        self.assertIn("pattern: run-evidence-*", body)
        # No merge-multiple: duplicate platform fragments must stay
        # detectable by the composer.
        self.assertNotIn("merge-multiple: true", body)

    def test_report_is_bound_to_the_run_commit(self):
        body = self._job_body("release-readiness")
        self.assertIn("--require-sha", body)
        self.assertIn("github.sha", body)
        self.assertIn("--run-id", body)
        self.assertIn("github.run_id", body)

    def test_composer_receives_all_upstream_results(self):
        body = self._job_body("release-readiness")
        for token in ("needs.fast.result", "needs.core.result",
                      "needs.full-regression.result"):
            self.assertIn(token, body, f"compose step missing {token}")

    def test_run_evidence_artifacts_are_ephemeral(self):
        body = self._job_body("full-regression")
        match = re.search(
            r"(?ms)^      - uses: actions/upload-artifact@[^\n]*\n"
            r"(?P<body>.*?)(?=^      - |\Z)",
            body,
        )
        self.assertIsNotNone(
            match, "full-regression missing the evidence upload step"
        )
        upload = match.group("body")
        self.assertIn("retention-days: 1", upload)
        self.assertIn("if-no-files-found: error", upload)
        self.assertIn("if: always()", upload)

    def test_release_report_upload_runs_always(self):
        body = self._job_body("release-readiness")
        match = re.search(
            r"(?ms)^      - uses: actions/upload-artifact@[^\n]*\n"
            r"(?P<body>.*?)(?=^      - |\Z|\Z)",
            body,
        )
        self.assertIsNotNone(
            match, "release-readiness missing the report upload step"
        )
        self.assertIn("if: always()", match.group("body"))
        self.assertIn("name: release-report", match.group("body"))

    def test_no_untrusted_triggers_or_continue_on_error(self):
        self.assertNotIn("pull_request_target", self.ci)
        self.assertNotIn("continue-on-error", self.ci)


# ---------------------------------------------------------------------------
# (g) Core runner coverage
# ---------------------------------------------------------------------------


class CoreRunnerCoverage(unittest.TestCase):
    def test_inventory_is_total_and_exclusions_are_exact(self):
        included, excluded = run_core_tests.inventory()
        included_names = {path.name for path in included}
        excluded_names = {path.name for path in excluded}
        on_disk = {path.name for path in TESTS_DIR.glob("test_*.py")}
        self.assertFalse(included_names & excluded_names)
        self.assertEqual(on_disk, included_names | excluded_names)
        self.assertEqual(
            excluded_names,
            {"test_install_e2e.py", "test_sdist_install_e2e.py"},
        )

    def test_ci_and_packaging_together_cover_every_suite(self):
        # The core-runner exclusion cannot silently strand a suite: the
        # core job runs the runner, and the packaging workflow runs both
        # excluded E2E files explicitly.
        ci = _read(WORKFLOWS_DIR / "ci.yml")
        packaging = _read(WORKFLOWS_DIR / "packaging.yml")
        self.assertIn("tools/run_core_tests.py", ci)
        for e2e_file in ("test_install_e2e.py", "test_sdist_install_e2e.py"):
            self.assertIn(e2e_file, packaging)


# ---------------------------------------------------------------------------
# (h) Workflow python floor
# ---------------------------------------------------------------------------

_OLDER_THAN_FLOOR = re.compile(r"(?<![\d.])3\.[0-8](?![\d.])")


class WorkflowPythonFloor(unittest.TestCase):
    def test_floor_and_current_stable_only(self):
        for name in ("ci.yml", "packaging.yml"):
            text = _read(WORKFLOWS_DIR / name)
            with self.subTest(workflow=name):
                self.assertIn('"3.9"', text, f"{name}: python floor 3.9 missing")
                self.assertIn('"3.14"', text, f"{name}: python 3.14 missing")
                self.assertIsNone(
                    _OLDER_THAN_FLOOR.search(text),
                    f"{name}: references a python older than the 3.9 floor",
                )


if __name__ == "__main__":
    unittest.main()
