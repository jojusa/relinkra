"""Artifact content contract tests (R5B).

Group A builds the real wheel and sdist and enforces the shipping
contract against them (skipped with an explicit reason only when the
build backend is unavailable). Group B crafts synthetic archives and
proves the inspector catches every forbidden shape — without any build.
"""

from __future__ import annotations

import importlib.util
import io
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

import relinkra

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import artifact_checks

TIMEOUT = 300
VERSION = relinkra.__version__
DIST_INFO = f"relinkra-{VERSION}.dist-info"


def _tail(text: str, limit: int = 400) -> str:
    return text.strip()[-limit:]


def _build_sdist(outdir: Path, scratch: Path) -> Path:
    """Build the sdist: setuptools PEP 517 hook first, then an ephemeral
    build venv (needs network), mirroring tests/test_sdist_install_e2e.py.
    """
    errors = []
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
            timeout=TIMEOUT,
            cwd=str(REPO_ROOT),
        )
        if result.returncode != 0:
            errors.append(f"setuptools hook: {_tail(result.stderr)}")
    else:
        errors.append("setuptools hook: setuptools not importable")

    if not any(outdir.glob("relinkra-*.tar.gz")):
        venv_dir = scratch / "sdist-buildenv"
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
                    timeout=TIMEOUT,
                    cwd=str(REPO_ROOT),
                )
                if result.returncode != 0:
                    errors.append(f"build venv build: {_tail(result.stderr)}")

    sdists = list(outdir.glob("relinkra-*.tar.gz"))
    if not sdists:
        raise unittest.SkipTest("sdist build unavailable: " + "; ".join(errors))
    return sdists[0]


class RealBuildContractTests(unittest.TestCase):
    """The real wheel and sdist satisfy the content contract."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        outdir = Path(cls.tmp.name)

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
            timeout=TIMEOUT,
            cwd=str(REPO_ROOT),
        )
        if result.returncode != 0:
            result = subprocess.run(
                base_cmd,
                capture_output=True,
                text=True,
                timeout=TIMEOUT,
                cwd=str(REPO_ROOT),
            )
        if result.returncode != 0:
            raise unittest.SkipTest(
                f"wheel build unavailable (backend missing?): "
                f"{_tail(result.stderr)}"
            )
        wheels = list(outdir.glob("relinkra-*.whl"))
        if not wheels:
            raise unittest.SkipTest("wheel build produced no relinkra wheel")
        cls.wheel = wheels[0]

        cls.sdist = _build_sdist(outdir, outdir / "scratch")

    def test_wheel_satisfies_the_contract(self):
        report = artifact_checks.inspect_wheel(self.wheel)
        self.assertEqual(report.problems, [], report.problems)
        self.assertTrue(report.ok)
        self.assertEqual(report.kind, "wheel")

    def test_wheel_size_is_sane(self):
        report = artifact_checks.inspect_wheel(self.wheel)
        self.assertGreater(report.entries, 0)
        self.assertLess(report.entries, 200)

    def test_sha256_format_is_stable(self):
        for path in (self.wheel, self.sdist):
            digest = artifact_checks.sha256_file(path)
            self.assertEqual(len(digest), 64)
            int(digest, 16)

    def test_sdist_satisfies_the_contract(self):
        report = artifact_checks.inspect_sdist(self.sdist)
        self.assertEqual(report.problems, [], report.problems)
        self.assertTrue(report.ok)
        self.assertEqual(report.kind, "sdist")

    def test_inspect_artifact_dispatches_by_extension(self):
        self.assertEqual(
            artifact_checks.inspect_artifact(self.wheel).kind, "wheel"
        )
        self.assertEqual(
            artifact_checks.inspect_artifact(self.sdist).kind, "sdist"
        )


class SyntheticArtifactCase(unittest.TestCase):
    """Hermetic mutation proofs over crafted archives (no build)."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.dir = Path(self._temp.name)

    # -- fixture builders ---------------------------------------------------

    def make_wheel(self, members, name=None):
        """A zip with a wheel filename; members maps arcname -> bytes/str."""
        filename = name or f"relinkra-{VERSION}-py3-none-any.whl"
        path = self.dir / filename
        with zipfile.ZipFile(path, "w") as archive:
            for arcname, content in members.items():
                data = content.encode("utf-8") if isinstance(content, str) else content
                archive.writestr(arcname, data)
        return path

    def valid_wheel_members(self):
        return {
            "relinkra/__init__.py": "__version__ = %r\n" % VERSION,
            f"{DIST_INFO}/METADATA": (
                f"Metadata-Version: 2.1\nName: relinkra\nVersion: {VERSION}\n"
            ),
            f"{DIST_INFO}/RECORD": "",
            f"{DIST_INFO}/entry_points.txt": (
                "[console_scripts]\n"
                "relinkra = relinkra.product_cli:main\n"
                "relinkra-mcp = relinkra.mcp_cli:main\n"
            ),
        }

    def make_sdist(self, members, name=None):
        filename = name or f"relinkra-{VERSION}.tar.gz"
        path = self.dir / filename
        with tarfile.open(path, "w:gz") as archive:
            for arcname, content in members.items():
                data = content.encode("utf-8") if isinstance(content, str) else content
                info = tarfile.TarInfo(arcname)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return path

    def valid_sdist_members(self):
        root = f"relinkra-{VERSION}"
        return {
            f"{root}/pyproject.toml": "[project]\nname = 'relinkra'\n",
            f"{root}/README.md": "# relinkra\n",
            f"{root}/relinkra/__init__.py": "",
        }

    # -- wheel mutations ------------------------------------------------------

    def test_wheel_missing_entry_points_is_flagged(self):
        members = self.valid_wheel_members()
        del members[f"{DIST_INFO}/entry_points.txt"]
        report = artifact_checks.inspect_wheel(self.make_wheel(members))
        self.assertFalse(report.ok)
        self.assertTrue(
            any("entry_points" in problem for problem in report.problems),
            report.problems,
        )

    def test_metadata_only_wheel_is_flagged(self):
        members = self.valid_wheel_members()
        del members["relinkra/__init__.py"]
        report = artifact_checks.inspect_wheel(self.make_wheel(members))
        self.assertFalse(report.ok)
        self.assertTrue(
            any("metadata-only wheel" in problem for problem in report.problems),
            report.problems,
        )

    def test_wheel_containing_tests_is_flagged(self):
        members = self.valid_wheel_members()
        members["relinkra/tests/test_x.py"] = ""
        report = artifact_checks.inspect_wheel(self.make_wheel(members))
        self.assertTrue(report.problems)

    def test_wheel_containing_windsurf_state_is_flagged(self):
        members = self.valid_wheel_members()
        members[".windsurf/workflows/x.md"] = ""
        report = artifact_checks.inspect_wheel(self.make_wheel(members))
        self.assertTrue(report.problems)

    def test_wheel_containing_relinkra_state_is_flagged(self):
        members = self.valid_wheel_members()
        members[".relinkra/config.json"] = "{}"
        report = artifact_checks.inspect_wheel(self.make_wheel(members))
        self.assertTrue(report.problems)

    def test_wheel_with_wrong_metadata_version_is_flagged(self):
        members = self.valid_wheel_members()
        members[f"{DIST_INFO}/METADATA"] = (
            "Metadata-Version: 2.1\nName: relinkra\nVersion: 9.9.9\n"
        )
        report = artifact_checks.inspect_wheel(self.make_wheel(members))
        self.assertTrue(
            any("METADATA" in problem for problem in report.problems),
            report.problems,
        )

    def test_wheel_containing_secrets_is_flagged(self):
        for secret in (".env", "secret.pem", "id_rsa", "cert.p12"):
            members = self.valid_wheel_members()
            members[f"relinkra/{secret}"] = ""
            report = artifact_checks.inspect_wheel(self.make_wheel(members))
            self.assertTrue(
                report.problems, f"{secret} was not flagged"
            )

    # -- sdist mutations ------------------------------------------------------

    def test_sdist_containing_windsurf_state_is_flagged(self):
        members = self.valid_sdist_members()
        members[f"relinkra-{VERSION}/.windsurf/x"] = ""
        report = artifact_checks.inspect_sdist(self.make_sdist(members))
        self.assertTrue(report.problems)

    def test_sdist_allows_tests_and_egg_info(self):
        members = self.valid_sdist_members()
        root = f"relinkra-{VERSION}"
        members[f"{root}/tests/test_product_cli.py"] = ""
        members[f"{root}/relinkra.egg-info/PKG-INFO"] = ""
        report = artifact_checks.inspect_sdist(self.make_sdist(members))
        flagged = [
            problem
            for problem in report.problems
            if "tests" in problem or "egg-info" in problem
        ]
        self.assertEqual(flagged, [], report.problems)

    def test_traversal_and_sdist_dist_poison_are_flagged(self):
        wheel_members = self.valid_wheel_members()
        wheel_members["relinkra/./module.py"] = ""
        wheel_report = artifact_checks.inspect_wheel(
            self.make_wheel(wheel_members)
        )
        self.assertFalse(wheel_report.ok)
        self.assertTrue(
            any("path traversal segment '.'" in problem
                for problem in wheel_report.problems),
            wheel_report.problems,
        )

        root = f"relinkra-{VERSION}"
        for poison in (f"{root}/../outside.txt", f"{root}/dist/poison.txt"):
            with self.subTest(poison=poison):
                members = self.valid_sdist_members()
                members[poison] = ""
                report = artifact_checks.inspect_sdist(self.make_sdist(members))
                self.assertFalse(report.ok)
                if ".." in poison:
                    self.assertTrue(
                        any("path traversal segment '..'" in problem
                            for problem in report.problems),
                        report.problems,
                    )
                else:
                    self.assertTrue(
                        any("forbidden path segment 'dist'" in problem
                            for problem in report.problems),
                        report.problems,
                    )

    # -- report semantics -------------------------------------------------------

    def test_ok_is_exactly_no_problems(self):
        good = artifact_checks.inspect_wheel(
            self.make_wheel(self.valid_wheel_members())
        )
        self.assertTrue(good.ok)
        self.assertEqual(good.problems, [])
        bad = artifact_checks.inspect_wheel(
            self.make_wheel({"junk.txt": ""})
        )
        self.assertFalse(bad.ok)
        self.assertTrue(bad.problems)


class ExactArtifactSelectionTests(unittest.TestCase):
    """The downloaded-artifact selector fails closed before E2E install."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.dir = Path(self._temp.name)

    def _artifact(self, relative: str, content: bytes = b"artifact") -> Path:
        path = self.dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def _manifest_for(self, artifact: Path, digest=None) -> Path:
        manifest = self.dir / "SHA256SUMS.txt"
        manifest.write_text(
            f"{digest or artifact_checks.sha256_file(artifact)}  "
            f"{artifact.name}\n",
            encoding="utf-8",
        )
        return manifest

    def test_selects_single_expected_wheel(self):
        artifact = self._artifact(
            "dist/" + artifact_checks.expected_artifact_filename("wheel")
        )
        selected = artifact_checks.select_exact_artifact(
            self.dir, "wheel", self._manifest_for(artifact)
        )
        self.assertEqual(selected, artifact)

    def test_selects_single_expected_sdist(self):
        artifact = self._artifact(
            "dist/" + artifact_checks.expected_artifact_filename("sdist")
        )
        selected = artifact_checks.select_exact_artifact(
            self.dir, "sdist", self._manifest_for(artifact)
        )
        self.assertEqual(selected, artifact)

    def test_selector_rejects_duplicate_wheels(self):
        name = artifact_checks.expected_artifact_filename("wheel")
        self._artifact("first/" + name)
        self._artifact("second/" + name)
        with self.assertRaisesRegex(ValueError, "exactly one wheel"):
            artifact_checks.select_exact_artifact(self.dir, "wheel")

    def test_selector_rejects_duplicate_sdists(self):
        name = artifact_checks.expected_artifact_filename("sdist")
        self._artifact("first/" + name)
        self._artifact("second/" + name)
        with self.assertRaisesRegex(ValueError, "exactly one sdist"):
            artifact_checks.select_exact_artifact(self.dir, "sdist")

    def test_selector_rejects_checksum_mismatch(self):
        artifact = self._artifact(
            "dist/" + artifact_checks.expected_artifact_filename("wheel")
        )
        manifest = self._manifest_for(artifact, "0" * 64)
        with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
            artifact_checks.select_exact_artifact(self.dir, "wheel", manifest)

    def test_selector_rejects_wrong_version_or_renamed_artifact(self):
        cases = (
            ("relinkra-9.9.9-py3-none-any.whl", "wheel"),
            ("renamed.whl", "wheel"),
            ("relinkra-9.9.9.tar.gz", "sdist"),
            ("renamed.tar.gz", "sdist"),
        )
        for name, kind in cases:
            with self.subTest(name=name):
                case_dir = self.dir / name.replace(".", "_")
                case_dir.mkdir()
                self._artifact(str(case_dir.relative_to(self.dir) / name))
                with self.assertRaisesRegex(ValueError, "expected .* filename"):
                    artifact_checks.select_exact_artifact(case_dir, kind)


if __name__ == "__main__":
    unittest.main()
