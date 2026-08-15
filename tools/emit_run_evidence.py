"""Run-scoped regression evidence emitter (R5C).

Emits ONE deterministic JSON evidence fragment for ONE full-regression
matrix cell. Every fragment is bound to the exact commit (``--sha``) and
workflow run (``--run-id``) that produced it, so composed CI evidence can
never silently mix commits or runs. Fragments are ephemeral CI artifacts
(uploaded with ``retention-days: 1``); they are never committed.

Two mutually exclusive evidence-input modes (exactly one required):

1. Explicit counts: ``--tests``, ``--failures``, ``--errors`` and
   ``--resource-warnings`` (all non-negative integers), with an optional
   ``--passed true|false``. When ``--passed`` is omitted it is derived as
   ``tests > 0 and failures == errors == resource_warnings == 0``.
   ``--passed true`` is rejected when any of failures / errors /
   resource-warnings is non-zero, and when ``--tests`` is 0 (a run that
   executed nothing is never green).
2. ``--run-regression``: runs the full test suite in-process, mirroring
   ``tools/release_check.py::run_regression`` (unittest discovery over
   ``tests/`` with ResourceWarning promoted to error; ResourceWarnings are
   counted by scanning ``result.errors`` tracebacks). The captured runner
   output is mirrored to stderr so CI logs keep it.

PASS is never inferred from missing data: ``tests == 0`` derives to
``passed=false``, and malformed input exits non-zero without writing a
fragment.

Fragment schema (keys sorted, two-space indent, trailing newline, no
timestamps — the output is byte-deterministic for identical inputs)::

    {"meta": {"sha": ..., "run_id": ..., "job": ..., "os": ...},
     "platform": "windows|linux|macos",
     "regression": {"passed": bool, "tests": int, "failures": int,
                    "errors": int, "resource_warnings": int, "where": str}}

``meta.os`` is the runner label given via ``--runner-os`` (e.g.
``windows-latest``), or the platform label when absent.

Exit codes: 0 fragment written (in ``--run-regression`` mode: the suite
passed), 1 the suite failed in ``--run-regression`` mode (the fragment is
still written — a ``passed=false`` fragment is evidence, not noise),
2 malformed input (no fragment written).
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
import unittest
import warnings
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
# Mirror tools/release_check.py: invoked as ``python tools/emit_run_evidence.py``
# the script directory (tools/) is sys.path[0] and the repo root is absent, so
# test modules that import relinkra before their own sys.path bootstrap would
# fail discovery. Put the repo root on sys.path before ``--run-regression``
# discovery, exactly like run_regression does.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

#: Canonical platform labels shared with tools/compose_run_evidence.py.
PLATFORMS = ("windows", "linux", "macos")

_SHA_RE = re.compile(r"[0-9a-f]{40}")
_RUN_ID_RE = re.compile(r"[0-9]+")


class UsageError(Exception):
    """Malformed CLI input; maps to exit code 2 without SystemExit."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # noqa: D102 - argparse hook
        raise UsageError(message)


def _sha(value: str) -> str:
    if not _SHA_RE.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "sha must be exactly 40 lowercase hex characters"
        )
    return value


def _run_id(value: str) -> str:
    if not value.isascii() or not _RUN_ID_RE.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "run_id must be non-empty ASCII digits"
        )
    return value


def _count(value: str) -> int:
    try:
        number = int(value, 10)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"count must be an integer, got {value!r}"
        )
    if number < 0:
        raise argparse.ArgumentTypeError(
            f"count must be non-negative, got {value!r}"
        )
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="emit_run_evidence",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--platform", choices=PLATFORMS, required=True,
                        help="canonical platform label of this matrix cell")
    parser.add_argument("--job", required=True,
                        help="job name that produced this fragment")
    parser.add_argument("--sha", type=_sha, required=True,
                        help="40-hex commit the evidence is bound to")
    parser.add_argument("--run-id", type=_run_id, required=True,
                        help="workflow run id (ASCII digits)")
    parser.add_argument("--runner-os", default=None,
                        help="runner label (e.g. windows-latest); defaults "
                        "to --platform")
    parser.add_argument("--where", default=None,
                        help="human locator; defaults to "
                        "'ci full-regression <runner-os-or-platform>'")
    parser.add_argument("--out", required=True,
                        help="fragment file to write")
    parser.add_argument("--tests", type=_count, default=None)
    parser.add_argument("--failures", type=_count, default=None)
    parser.add_argument("--errors", type=_count, default=None)
    parser.add_argument("--resource-warnings", type=_count, default=None)
    parser.add_argument("--passed", choices=("true", "false"), default=None,
                        help="explicit verdict; derived from the counts "
                        "when omitted")
    parser.add_argument("--run-regression", action="store_true",
                        help="run the full suite in-process instead of "
                        "taking explicit counts (minutes)")
    return parser


def run_regression_suite() -> Dict[str, Any]:
    """Run the full test suite in-process; ResourceWarning is an error.

    Mirrors ``tools/release_check.py::run_regression`` and mirrors the
    captured runner output to stderr so CI logs keep it.

    TIMEBOX: the full suite; this takes minutes.
    """
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=1)
    with warnings.catch_warnings():
        warnings.simplefilter("error", ResourceWarning)
        result = runner.run(suite)
    sys.stderr.write(stream.getvalue())
    resource_warnings = sum(
        1 for _test, tb in result.errors if "ResourceWarning" in tb
    )
    return {
        "passed": result.wasSuccessful(),
        "tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "resource_warnings": resource_warnings,
    }


def build_fragment(
    *,
    platform: str,
    sha: str,
    run_id: str,
    job: str,
    os_label: str,
    passed: bool,
    tests: int,
    failures: int,
    errors: int,
    resource_warnings: int,
    where: str,
) -> Dict[str, Any]:
    """Assemble the deterministic fragment mapping."""
    return {
        "meta": {"sha": sha, "run_id": run_id, "job": job, "os": os_label},
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


def _resolve_counts(args: argparse.Namespace) -> Tuple[Dict[str, Any], bool]:
    """Return (regression counts, suite_ok) from exactly one input mode."""
    count_args = (args.tests, args.failures, args.errors,
                  args.resource_warnings)
    if args.run_regression:
        if any(value is not None for value in count_args):
            raise UsageError(
                "--run-regression cannot be combined with explicit counts"
            )
        if args.passed is not None:
            raise UsageError(
                "--run-regression cannot be combined with --passed"
            )
        counts = run_regression_suite()
        return counts, counts["passed"]
    if any(value is None for value in count_args):
        raise UsageError(
            "explicit mode requires --tests, --failures, --errors and "
            "--resource-warnings (or use --run-regression)"
        )
    tests, failures, errors, resource_warnings = count_args
    if args.passed is None:
        # Never infer PASS from nothing: an empty run is not green.
        passed = (
            tests > 0
            and failures == 0
            and errors == 0
            and resource_warnings == 0
        )
    else:
        passed = args.passed == "true"
        if passed and (failures or errors or resource_warnings):
            raise UsageError(
                "--passed true is incompatible with non-zero "
                "failures/errors/resource-warnings"
            )
        if passed and tests == 0:
            # Zero-test false green: a real regression run always
            # executes tests; passed=true with tests=0 is anomalous,
            # never evidence of success.
            raise UsageError(
                "--passed true requires --tests >= 1 (a run that "
                "executed nothing is not green)"
            )
    counts = {
        "passed": passed,
        "tests": tests,
        "failures": failures,
        "errors": errors,
        "resource_warnings": resource_warnings,
    }
    return counts, True


def write_fragment(path: str, fragment: Dict[str, Any]) -> None:
    """Write deterministic JSON: sorted keys, LF endings, one trailing
    newline (newline='' keeps write untranslated on Windows)."""
    text = json.dumps(fragment, indent=2, sort_keys=True) + "\n"
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(text)


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        if not args.job.strip():
            raise UsageError("--job must be non-empty")
        os_label = args.runner_os or args.platform
        where = args.where or f"ci full-regression {os_label}"
        counts, suite_ok = _resolve_counts(args)
        fragment = build_fragment(
            platform=args.platform,
            sha=args.sha,
            run_id=args.run_id,
            job=args.job,
            os_label=os_label,
            where=where,
            **counts,
        )
        write_fragment(args.out, fragment)
    except UsageError as exc:
        print(f"emit_run_evidence: error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"emit_run_evidence: error: cannot write fragment: {exc}",
              file=sys.stderr)
        return 2
    return 0 if suite_ok else 1


if __name__ == "__main__":
    sys.exit(main())
