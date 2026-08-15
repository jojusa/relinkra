"""Run-scoped evidence composer (R5C).

Composes the per-cell fragments emitted by ``tools/emit_run_evidence.py``
(one per full-regression matrix cell, downloaded unmerged as ephemeral CI
artifacts) into a single evidence mapping consumable by
``tools/release_check.py --evidence``.

Trust contract — the composer FAILS CLOSED (exit 2, no output file) on:

- a fragment that is not a JSON object, is malformed, or lacks ``meta``;
- any fragment whose ``meta.sha`` is missing, empty, or different from
  ``--require-sha`` (stale or cross-commit evidence; this also makes
  mixed-SHA fragment sets impossible);
- any fragment whose ``meta.run_id`` is missing, malformed (non ASCII
  digits), or different from ``--run-id`` (cross-run evidence);
- a fragment with a platform outside windows/linux/macos, or duplicate
  fragments for the same platform (never silently take the first);
- a fragment claiming ``passed=true`` with ``tests <= 0`` (zero-test
  false green — a run that executed nothing is never green);
- a missing platform fragment while the ``full-regression`` upstream
  succeeded — anomalous: when every cell succeeded the evidence MUST
  exist;
- unknown upstream result values or missing required upstreams
  (``fast``, ``core``, ``full-regression``).

Degraded-report rule (exit 0, compose anyway): a platform fragment is
missing AND the ``full-regression`` upstream did not succeed (failure /
cancelled / skipped). The platform key is then omitted — the gate model
honestly yields PARTIAL for it — and ``ci.remote_runs_passed`` is false.

``ci.remote_runs_passed`` is true ONLY when ``fast``, ``core`` and
``full-regression`` are ALL exactly ``success`` AND every present
fragment passed. Anything else — cancelled, failure, skipped, missing —
is false. Nothing unexpected is ever converted into PASS.

AGGREGATE SEMANTICS (fixed decision): ``regression.tests`` is the
AGGREGATE number of test executions across all present matrix cells
(e.g. 2061*3 = 6183 when every cell ran the full suite);
``failures``/``errors``/``resource_warnings`` are likewise sums. The
per-cell canonical counts live in ``regression.cells``.
``regression.passed`` requires at least one cell, every present cell
passed, and no degraded (missing) cell.

Composed output (deterministic: sorted keys, LF endings, trailing
newline, no timestamps)::

    {"meta": {"sha": ..., "run_id": ..., "source": "github-actions"},
     "platforms": {"linux": "pass"|"fail", ...},
     "regression": {"passed": bool, "tests": <sum>, "failures": <sum>,
                    "errors": <sum>, "resource_warnings": <sum>,
                    "where": "CI full-regression matrix",
                    "cells": {<platform>: {"tests": n, "failures": n,
                              "errors": n, "resource_warnings": n,
                              "where": str}}},
     "ci": {"workflows_present": true, "remote_runs_passed": bool}}

Exit codes: 0 composed (possibly degraded), 2 hard validation failure.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

#: Canonical platform labels, shared with tools/emit_run_evidence.py.
EXPECTED_PLATFORMS = ("windows", "linux", "macos")

#: Upstream jobs whose results gate remote_runs_passed.
REQUIRED_UPSTREAMS = ("fast", "core", "full-regression")

#: GitHub Actions job-result vocabulary; anything else is rejected.
KNOWN_RESULTS = ("success", "failure", "cancelled", "skipped")

_SHA_RE = re.compile(r"[0-9a-f]{40}")
_RUN_ID_RE = re.compile(r"[0-9]+")


class ComposeError(Exception):
    """Hard validation failure; maps to exit code 2 without SystemExit."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # noqa: D102 - argparse hook
        raise ComposeError(message)


def _sha(value: str) -> str:
    if not _SHA_RE.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "require-sha must be exactly 40 lowercase hex characters"
        )
    return value


def _run_id(value: str) -> str:
    if not value.isascii() or not _RUN_ID_RE.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "run-id must be non-empty ASCII digits"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="compose_run_evidence",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--evidence-dir", required=True,
                        help="directory scanned recursively for *.json "
                        "fragments")
    parser.add_argument("--require-sha", type=_sha, required=True,
                        help="40-hex commit every fragment must be bound to")
    parser.add_argument("--run-id", type=_run_id, required=True,
                        help="workflow run id every fragment must belong to")
    parser.add_argument("--upstream", action="append", default=[],
                        metavar="NAME=RESULT",
                        help="upstream job result; repeatable or "
                        "comma-separated. Required: fast, core, "
                        "full-regression")
    parser.add_argument("--out", required=True,
                        help="composed evidence file to write")
    return parser


def parse_upstreams(values: List[str]) -> Dict[str, str]:
    """Parse repeatable/comma-separated NAME=RESULT pairs."""
    upstream: Dict[str, str] = {}
    for value in values:
        for pair in value.split(","):
            pair = pair.strip()
            if not pair:
                continue
            if "=" not in pair:
                raise ComposeError(
                    f"malformed --upstream entry {pair!r} (want NAME=RESULT)"
                )
            name, result = (part.strip() for part in pair.split("=", 1))
            if result not in KNOWN_RESULTS:
                raise ComposeError(
                    f"unknown upstream result {result!r} for {name!r} "
                    f"(known: {', '.join(KNOWN_RESULTS)})"
                )
            if name in upstream:
                raise ComposeError(f"duplicate --upstream entry {name!r}")
            upstream[name] = result
    missing = [name for name in REQUIRED_UPSTREAMS if name not in upstream]
    if missing:
        raise ComposeError(
            f"missing required upstream results: {', '.join(missing)}"
        )
    return upstream


def _validate_fragment(path: Path, data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        raise ComposeError(
            f"fragment {path}: top level must be a JSON object"
        )
    meta = data.get("meta")
    if not isinstance(meta, dict):
        raise ComposeError(f"fragment {path}: missing meta object")
    platform = data.get("platform")
    if platform not in EXPECTED_PLATFORMS:
        raise ComposeError(
            f"fragment {path}: unexpected platform {platform!r}"
        )
    regression = data.get("regression")
    if not isinstance(regression, dict):
        raise ComposeError(f"fragment {path}: missing regression object")
    if not isinstance(regression.get("passed"), bool):
        raise ComposeError(
            f"fragment {path}: regression.passed must be a boolean"
        )
    for key in ("tests", "failures", "errors", "resource_warnings"):
        value = regression.get(key)
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
        ):
            raise ComposeError(
                f"fragment {path}: regression.{key} must be a "
                f"non-negative integer"
            )
    if regression["passed"] and regression["tests"] <= 0:
        # Zero-test false green: the composer is the trust boundary, so
        # an anomalous "passed with no tests executed" fragment is
        # rejected here even if an emitter let it through.
        raise ComposeError(
            f"fragment {path}: regression.passed=true requires "
            f"tests >= 1 (a run that executed nothing is not green)"
        )
    return data


def load_fragments(
    evidence_dir: str, require_sha: str, run_id: str
) -> Dict[str, Dict[str, Any]]:
    """Load, validate and index fragments by platform."""
    root = Path(evidence_dir)
    fragments: Dict[str, Dict[str, Any]] = {}
    for path in sorted(root.rglob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise ComposeError(f"fragment {path}: not valid JSON ({exc})")
        data = _validate_fragment(path, data)
        meta = data["meta"]
        sha = meta.get("sha")
        if not isinstance(sha, str) or not sha:
            raise ComposeError(
                f"fragment {path}: meta.sha is missing or empty"
            )
        if sha != require_sha:
            raise ComposeError(
                f"fragment {path}: sha {sha} does not match the required "
                f"{require_sha} (stale or cross-commit evidence)"
            )
        frag_run_id = meta.get("run_id")
        if (
            not isinstance(frag_run_id, str)
            or not frag_run_id.isascii()
            or not _RUN_ID_RE.fullmatch(frag_run_id)
        ):
            raise ComposeError(
                f"fragment {path}: meta.run_id is missing or malformed"
            )
        if frag_run_id != run_id:
            raise ComposeError(
                f"fragment {path}: run_id {frag_run_id} does not match "
                f"the required {run_id} (cross-run evidence)"
            )
        platform = data["platform"]
        if platform in fragments:
            raise ComposeError(
                f"duplicate platform fragment for {platform!r}: {path} "
                f"conflicts with another fragment"
            )
        fragments[platform] = data
    return fragments


def compose(
    fragments: Dict[str, Dict[str, Any]],
    upstream: Dict[str, str],
    *,
    sha: str,
    run_id: str,
) -> Dict[str, Any]:
    """Compose validated fragments into the release_check evidence map."""
    missing = [
        platform
        for platform in EXPECTED_PLATFORMS
        if platform not in fragments
    ]
    if missing and upstream["full-regression"] == "success":
        raise ComposeError(
            f"missing platform fragments {missing} although the "
            f"full-regression upstream succeeded — anomalous; evidence "
            f"must exist when the cell succeeded"
        )
    platforms: Dict[str, str] = {}
    cells: Dict[str, Dict[str, Any]] = {}
    for platform in EXPECTED_PLATFORMS:
        fragment = fragments.get(platform)
        if fragment is None:
            continue
        regression = fragment["regression"]
        platforms[platform] = "pass" if regression["passed"] else "fail"
        cells[platform] = {
            "tests": regression["tests"],
            "failures": regression["failures"],
            "errors": regression["errors"],
            "resource_warnings": regression["resource_warnings"],
            "where": str(regression.get("where") or ""),
        }
    upstream_green = all(
        upstream[name] == "success" for name in REQUIRED_UPSTREAMS
    )
    all_cells_passed = all(
        value == "pass" for value in platforms.values()
    )
    regression_passed = bool(cells) and not missing and all_cells_passed
    remote_runs_passed = upstream_green and all_cells_passed and not missing
    return {
        "meta": {
            "sha": sha,
            "run_id": run_id,
            "source": "github-actions",
        },
        "platforms": platforms,
        "regression": {
            "passed": regression_passed,
            "tests": sum(cell["tests"] for cell in cells.values()),
            "failures": sum(cell["failures"] for cell in cells.values()),
            "errors": sum(cell["errors"] for cell in cells.values()),
            "resource_warnings": sum(
                cell["resource_warnings"] for cell in cells.values()
            ),
            "where": "CI full-regression matrix",
            "cells": cells,
        },
        "ci": {
            "workflows_present": True,
            "remote_runs_passed": remote_runs_passed,
        },
    }


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        upstream = parse_upstreams(args.upstream)
        fragments = load_fragments(
            args.evidence_dir, args.require_sha, args.run_id
        )
        composed = compose(
            fragments, upstream, sha=args.require_sha, run_id=args.run_id
        )
        text = json.dumps(composed, indent=2, sort_keys=True) + "\n"
        with open(args.out, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
    except ComposeError as exc:
        print(f"compose_run_evidence: error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(
            f"compose_run_evidence: error: cannot write output: {exc}",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
