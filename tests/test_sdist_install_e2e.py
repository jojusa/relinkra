"""Sdist-install end-to-end tests (R5A closure).

Same clean-install contract as tests/test_install_e2e.py, but the artifact
under test is the SDIST (.tar.gz), not the wheel and not the source
checkout. Installing from the sdist is the path a source-distribution
consumer actually takes, so the isolation guarantees (no source-tree
fallback, sandboxed home, idempotent init, bounded doctor, MCP handshake)
must hold for it independently.

The sdist build is best-effort and offline-tolerant locally: it tries, in
order, the ``build`` frontend, setuptools' PEP 517 hook directly, and an
ephemeral build venv (needs network); if none works the class skips with the
reason only when ``RELINKRA_E2E_ARTIFACT`` is absent. Packaging CI treats
that infrastructure failure as an error.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

try:
    from tests import test_install_e2e as _e2e
except ImportError:  # pragma: no cover - discover vs module invocation
    import test_install_e2e as _e2e

REPO_ROOT = _e2e.REPO_ROOT
TIMEOUT = _e2e.TIMEOUT
_tail = _e2e._tail


def _have(module: str) -> bool:
    return importlib.util.find_spec(module) is not None


def _build_sdist_with(python: str, outdir: Path) -> subprocess.CompletedProcess:
    """Build the sdist without build isolation using the given interpreter.

    ``--no-isolation`` keeps the build offline whenever the interpreter
    already has setuptools; the caller guarantees a frontend is present.
    """
    return subprocess.run(
        [
            python,
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
        timeout=TIMEOUT,
        cwd=str(REPO_ROOT),
    )


class SdistInstallTests(_e2e.CleanInstallTests):
    """The wheel E2E contract, installed FROM THE SDIST."""

    @classmethod
    def build_artifact(cls, artifact_dir: Path) -> Path:
        errors = []

        if _have("build") and _have("setuptools"):
            result = _build_sdist_with(sys.executable, artifact_dir)
            if result.returncode != 0:
                errors.append(f"build frontend: {_tail(result.stderr)}")
        else:
            errors.append("build frontend: not importable in test interpreter")

        if not any(artifact_dir.glob("relinkra-*.tar.gz")) and _have("setuptools"):
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import sys; from setuptools import build_meta; "
                    "build_meta.build_sdist(sys.argv[1])",
                    str(artifact_dir),
                ],
                capture_output=True,
                text=True,
                timeout=TIMEOUT,
                cwd=str(REPO_ROOT),
            )
            if result.returncode != 0:
                errors.append(f"setuptools hook: {_tail(result.stderr)}")
        elif not _have("setuptools"):
            errors.append("setuptools hook: setuptools not importable")

        if not any(artifact_dir.glob("relinkra-*.tar.gz")):
            # Last resort: an ephemeral venv with the build frontend. Needs
            # network for pip; any failure here skips the whole class.
            venv_dir = cls.base / "sdist-buildenv"
            venv = subprocess.run(
                [sys.executable, "-m", "venv", str(venv_dir)],
                capture_output=True,
                text=True,
                timeout=TIMEOUT,
            )
            if venv.returncode != 0:
                errors.append(f"build venv: {_tail(venv.stderr)}")
            else:
                python = venv_dir / ("Scripts" if sys.platform == "win32" else "bin") / (
                    "python.exe" if sys.platform == "win32" else "python"
                )
                bootstrap = subprocess.run(
                    [str(python), "-m", "pip", "install", "--quiet", "build", "setuptools"],
                    capture_output=True,
                    text=True,
                    timeout=TIMEOUT,
                )
                if bootstrap.returncode != 0:
                    errors.append(f"build venv bootstrap: {_tail(bootstrap.stderr)}")
                else:
                    result = _build_sdist_with(str(python), artifact_dir)
                    if result.returncode != 0:
                        errors.append(f"build venv build: {_tail(result.stderr)}")

        sdists = list(artifact_dir.glob("relinkra-*.tar.gz"))
        if not sdists:
            _e2e._raise_infrastructure_failure(
                "sdist build unavailable: " + "; ".join(errors)
            )
        return sdists[0]


if __name__ == "__main__":
    unittest.main()
