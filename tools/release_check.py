"""Bounded release-check CLI (R5B.22).

Runs LOCAL evidence collectors without service calls or git mutation,
evaluates the release gates from tools/release_gates.py, and prints a text
summary or a JSON report. The opt-in packaging collector may acquire build
dependencies; every such subprocess is explicitly time-bounded.

    python tools/release_check.py [--json] [--evidence file.json]
                                  [--run-regression] [--run-packaging]
                                  [--require {merge,rc,public}]

--run-regression executes the full test suite in-process with
ResourceWarning promoted to error; TIMEBOX: this runs ~2000 tests and
takes minutes. --run-packaging builds the wheel and sdist into a temp
dir and enforces the artifact content contract.

Exit codes: 0 when the report was computed (even with PARTIAL/BLOCKED
gates), 1 when --require fails, 2 when a collector crashes.
"""

from __future__ import annotations

import argparse
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from tools import artifact_checks, release_gates
except ImportError:  # pragma: no cover - direct script invocation
    import artifact_checks
    import release_gates

import relinkra
from relinkra.cbm_support import CERTIFIED_CBM_BINARIES

GIT_TIMEOUT = 30
BUILD_TIMEOUT = 300

_PLATFORM_KEYS = {"windows": "windows", "linux": "linux", "darwin": "macos"}


# ---------------------------------------------------------------------------
# Local collectors
# ---------------------------------------------------------------------------


def collect_git_status() -> Dict[str, Any]:
    """Read-only ``git status --porcelain``; the .windsurf/ line is ignored."""
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True,
        text=True,
        timeout=GIT_TIMEOUT,
        cwd=str(REPO_ROOT),
    )
    if result.returncode != 0:
        raise RuntimeError(f"git status failed: {result.stderr.strip()[-200:]}")
    dirty = [
        line
        for line in result.stdout.splitlines()
        if line.strip() and not line.startswith("?? .windsurf/")
    ]
    return {"git_clean": not dirty, "dirty_entries": dirty}


def collect_metadata() -> Dict[str, Any]:
    """Version single-sourcing, checked without tomllib (3.9 floor)."""
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    dynamic_attr = re.search(
        r'version\s*=\s*\{\s*attr\s*=\s*"relinkra\.__version__"\s*\}', text
    )
    name_ok = re.search(r'^\s*name\s*=\s*"relinkra"', text, re.MULTILINE)
    init_text = (REPO_ROOT / "relinkra" / "__init__.py").read_text(
        encoding="utf-8"
    )
    literal = re.search(r'__version__\s*=\s*"([^"]+)"', init_text)
    version = literal.group(1) if literal else ""
    consistent = bool(
        dynamic_attr and name_ok and version == relinkra.__version__
    )
    return {
        "version": relinkra.__version__,
        "version_consistent": consistent,
    }


def collect_legal() -> Dict[str, Any]:
    return {
        "license_present": (REPO_ROOT / "LICENSE").is_file(),
        "notice_complete": None,
    }


def collect_docs() -> Dict[str, Any]:
    readme_path = REPO_ROOT / "README.md"
    readme = (
        readme_path.read_text(encoding="utf-8").lower()
        if readme_path.is_file()
        else ""
    )
    return {
        "release_doc": (REPO_ROOT / "docs" / "release.md").is_file(),
        "readme_sections": "python 3.9" in readme and "certified" in readme,
        "installation_doc": (
            REPO_ROOT / "docs" / "installation.md"
        ).is_file(),
    }


def _scan_workflow_security(workflows: List[Path]) -> Dict[str, bool]:
    """Static workflow hygiene scan: minimal permissions, no untrusted
    triggers, actions pinned to a major tag or a full commit SHA."""
    minimal_permissions = True
    no_untrusted_triggers = True
    actions_pinned = True
    for path in workflows:
        text = path.read_text(encoding="utf-8")
        if "pull_request_target" in text:
            no_untrusted_triggers = False
        top = re.search(r"^permissions:\n((?:^[ \t]+.*\n?)+)", text, re.MULTILINE)
        if top is None or not re.search(
            r"^\s+contents:\s*read\s*$", top.group(1), re.MULTILINE
        ):
            minimal_permissions = False
        for match in re.finditer(r"uses:\s*([^\s]+)@([^\s]+)", text):
            ref = match.group(2)
            pinned = re.fullmatch(r"v\d+(\.\d+)*", ref) or re.fullmatch(
                r"[0-9a-f]{40}", ref
            )
            if not pinned:
                actions_pinned = False
    return {
        "workflows_minimal_permissions": minimal_permissions,
        "no_untrusted_triggers": no_untrusted_triggers,
        "actions_pinned": actions_pinned,
    }


def collect_ci_and_security() -> Dict[str, Any]:
    workflows_dir = REPO_ROOT / ".github" / "workflows"
    workflows = sorted(workflows_dir.glob("*.yml")) if workflows_dir.is_dir() else []
    present = bool(workflows)
    ci = {"workflows_present": present, "remote_runs_passed": None}
    if present:
        security = _scan_workflow_security(workflows)
    else:
        security = {
            "workflows_minimal_permissions": False,
            "no_untrusted_triggers": False,
            "actions_pinned": False,
        }
    return {"ci": ci, "security": security}


def collect_cbm() -> Dict[str, Any]:
    certified = sorted(CERTIFIED_CBM_BINARIES.keys())
    notes: List[str] = []
    others = [
        tag
        for tag in ("linux-amd64", "darwin-amd64")
        if tag not in CERTIFIED_CBM_BINARIES
    ]
    if others:
        notes.append("Linux/macOS CBM not certified "
                     "(honest degradation verified)")
    return {"certified_platforms": certified, "notes": notes}


def collect_hosts() -> Dict[str, Any]:
    """Host certification is accepted via --evidence only; the local
    collector does not harvest certification records, so this is honestly
    PARTIAL until CI or the caller supplies the evidence."""
    return {
        "certified_hosts": [],
        "regenerated_in_ci": False,
        "notes": [
            "host certification not collected locally; supply it via "
            "--evidence"
        ],
    }


# ---------------------------------------------------------------------------
# Expensive collectors (opt-in)
# ---------------------------------------------------------------------------


def run_regression() -> Dict[str, Any]:
    """Run the full test suite in-process; ResourceWarning is an error.

    TIMEBOX: ~2000 tests; this takes minutes.
    """
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=1)
    with warnings.catch_warnings():
        warnings.simplefilter("error", ResourceWarning)
        result = runner.run(suite)
    resource_warnings = sum(
        1 for _test, tb in result.errors if "ResourceWarning" in tb
    )
    return {
        "passed": result.wasSuccessful(),
        "tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "resource_warnings": resource_warnings,
        "where": "local release_check --run-regression",
    }


def _build_wheel(outdir: Path) -> Path:
    base_cmd = [
        sys.executable,
        "-m",
        "pip",
        "wheel",
        str(REPO_ROOT),
        "--no-deps",
        "-w",
        str(outdir),
    ]
    result = subprocess.run(
        base_cmd + ["--no-build-isolation"],
        capture_output=True,
        text=True,
        timeout=BUILD_TIMEOUT,
        cwd=str(REPO_ROOT),
    )
    if result.returncode != 0:
        result = subprocess.run(
            base_cmd,
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT,
            cwd=str(REPO_ROOT),
        )
    if result.returncode != 0:
        raise RuntimeError(
            f"wheel build failed: {result.stderr.strip()[-300:]}"
        )
    wheels = list(outdir.glob("relinkra-*.whl"))
    if not wheels:
        raise RuntimeError("wheel build produced no relinkra wheel")
    return wheels[0]


def _build_sdist(outdir: Path) -> Path:
    """Build the sdist: setuptools PEP 517 hook when setuptools is
    importable, otherwise an ephemeral build venv (needs network),
    mirroring the fallback chain proven in tests/test_artifact_contents.py.
    """
    errors: List[str] = []
    if importlib.util.find_spec("setuptools") is not None:
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; from setuptools import build_meta; "
                "build_meta.build_sdist(sys.argv[1])",
                str(outdir),
            ],
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT,
            cwd=str(REPO_ROOT),
        )
        if result.returncode != 0:
            errors.append(f"setuptools hook: {result.stderr.strip()[-300:]}")
    else:
        errors.append("setuptools hook: setuptools not importable")

    if not any(outdir.glob("relinkra-*.tar.gz")):
        venv_dir = outdir / "sdist-buildenv"
        venv = subprocess.run(
            [sys.executable, "-m", "venv", str(venv_dir)],
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT,
        )
        if venv.returncode != 0:
            errors.append(f"build venv: {venv.stderr.strip()[-300:]}")
        else:
            python = venv_dir / ("Scripts" if sys.platform == "win32" else "bin") / (
                "python.exe" if sys.platform == "win32" else "python"
            )
            bootstrap = subprocess.run(
                [str(python), "-m", "pip", "install", "--quiet", "build", "setuptools"],
                capture_output=True,
                text=True,
                timeout=BUILD_TIMEOUT,
            )
            if bootstrap.returncode != 0:
                errors.append(
                    f"build venv bootstrap: {bootstrap.stderr.strip()[-300:]}"
                )
            else:
                result = subprocess.run(
                    [
                        str(python),
                        "-m",
                        "build",
                        "--sdist",
                        "--no-isolation",
                        "--outdir",
                        str(outdir),
                        str(REPO_ROOT),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=BUILD_TIMEOUT,
                    cwd=str(REPO_ROOT),
                )
                if result.returncode != 0:
                    errors.append(
                        f"build venv build: {result.stderr.strip()[-300:]}"
                    )

    sdists = [
        path
        for path in outdir.glob("relinkra-*.tar.gz")
        if "sdist-buildenv" not in str(path)
    ]
    if not sdists:
        raise RuntimeError("sdist build failed: " + "; ".join(errors))
    return sdists[0]


def run_packaging() -> Dict[str, Any]:
    """Build wheel + sdist into a temp dir and enforce the contract."""
    with tempfile.TemporaryDirectory(prefix="relinkra-release-") as tmp:
        outdir = Path(tmp)
        wheel = _build_wheel(outdir)
        sdist = _build_sdist(outdir)
        wheel_report = artifact_checks.inspect_wheel(wheel)
        sdist_report = artifact_checks.inspect_sdist(sdist)
    details = [
        f"wheel {os.path.basename(str(wheel))} sha256={wheel_report.sha256}",
        f"sdist {os.path.basename(str(sdist))} sha256={sdist_report.sha256}",
    ]
    details.extend(f"wheel: {p}" for p in wheel_report.problems)
    details.extend(f"sdist: {p}" for p in sdist_report.problems)
    return {
        "wheel_ok": wheel_report.ok,
        "sdist_ok": sdist_report.ok,
        "details": details,
    }


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def collect_local_evidence(
    *, regression: bool, packaging: bool
) -> Dict[str, Any]:
    evidence: Dict[str, Any] = {}
    evidence["workspace"] = collect_git_status()
    evidence["metadata"] = collect_metadata()
    evidence["legal"] = collect_legal()
    evidence["docs"] = collect_docs()
    evidence.update(collect_ci_and_security())
    evidence["cbm"] = collect_cbm()
    evidence["hosts"] = collect_hosts()
    if regression:
        evidence["regression"] = run_regression()
        platform_key = _PLATFORM_KEYS.get(sys.platform)
        if platform_key:
            evidence["platforms"] = {
                platform_key: (
                    "pass" if evidence["regression"]["passed"] else "fail"
                )
            }
    if packaging:
        evidence["packaging"] = run_packaging()
    return evidence


def merge_evidence(
    local: Dict[str, Any], external_path: Optional[str]
) -> Dict[str, Any]:
    """Merge an external evidence JSON object; external wins per key."""
    if not external_path:
        return local
    with open(external_path, "r", encoding="utf-8") as handle:
        external = json.load(handle)
    if not isinstance(external, dict):
        raise ValueError("external evidence must be a JSON object")
    merged = dict(local)
    merged.update(external)
    return merged


def _print_text(report: "release_gates.ReleaseReport", evidence: Dict[str, Any]) -> None:
    workspace = evidence.get("workspace") or {}
    metadata = evidence.get("metadata") or {}
    print(f"relinkra release check — version {metadata.get('version', '?')}")
    print(f"workspace git clean: {workspace.get('git_clean', '?')}")
    for gate in report.gates:
        print(f"{gate.name}: {gate.status.value}")
        for blocker in gate.blockers:
            print(f"  blocker: {blocker}")
        for note in gate.notes:
            print(f"  note: {note}")
    print(f"overall: {report.overall.value}")
    print(f"safe_to_merge: {report.safe_to_merge}")
    print(f"safe_to_tag_rc: {report.safe_to_tag_rc}")
    print(f"safe_for_public_release: {report.safe_for_public_release}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="release_check",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--json", action="store_true",
                        help="print the ReleaseReport as JSON")
    parser.add_argument("--evidence", metavar="FILE.json",
                        help="external evidence mapping (wins per key)")
    parser.add_argument("--run-regression", action="store_true",
                        help="run the full test suite in-process (minutes)")
    parser.add_argument("--run-packaging", action="store_true",
                        help="build wheel+sdist and enforce the contract")
    parser.add_argument("--require", choices=("merge", "rc", "public"),
                        help="exit 1 unless the given safety holds")
    args = parser.parse_args(argv)

    try:
        evidence = collect_local_evidence(
            regression=args.run_regression, packaging=args.run_packaging
        )
        evidence = merge_evidence(evidence, args.evidence)
    except Exception as exc:
        print(f"release_check collector error: {exc}", file=sys.stderr)
        return 2

    report = release_gates.evaluate_gates(evidence)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        _print_text(report, evidence)

    if args.require:
        ok = {
            "merge": report.safe_to_merge,
            "rc": report.safe_to_tag_rc,
            "public": report.safe_for_public_release,
        }[args.require]
        if not ok:
            print(f"--require {args.require}: NOT satisfied", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
