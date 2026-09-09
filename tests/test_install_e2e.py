"""Clean-install end-to-end tests (R5A).

Builds the distribution artifact once (a wheel here; the sdist variant in
tests/test_sdist_install_e2e.py subclasses this and overrides the build),
installs it into an isolated venv, and then drives
the INSTALLED console scripts from directories outside the source checkout
with sanitized environments. Proves the package stands on its own: no
reliance on the source tree, no reads or writes of the developer's real
home or host configs, honest degradation, and idempotent init.

Offline-tolerant locally: any infrastructure failure (no git, venv creation,
wheel build, pip install) skips with the reason when
``RELINKRA_E2E_ARTIFACT`` is absent. Packaging CI treats those failures as
errors when the variable is set.

Test methods are named test_step_* so alphabetical execution matches the
documented install sequence; later steps skip with a pointer to the step
that failed rather than cascading errors.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    from tests import git_fixtures as gf
except ImportError:  # pragma: no cover - discover vs module invocation
    import git_fixtures as gf

REPO_ROOT = Path(__file__).resolve().parents[1]
TIMEOUT = 300
IS_NT = os.name == "nt"

#: When set to an existing artifact path, the suites install THAT artifact
#: instead of building one (CI reuses a certified build across cells).
ENV_ARTIFACT = "RELINKRA_E2E_ARTIFACT"
RELEASE_VERSION = "0.1.2"

# Variables the sandbox environment keeps from the real one so git and the
# interpreter still resolve; everything home- or config-related is replaced.
SANDBOX_KEPT = (
    "PATH",
    "PATHEXT",
    "COMSPEC",
    "SystemRoot",
    "SystemDrive",
    "ProgramData",
    "windir",
    "TEMP",
    "TMP",
    "USERNAME",
    "OS",
)


def _norm(path) -> str:
    return os.path.normcase(os.path.realpath(str(path)))


def _is_within(path, root) -> bool:
    child, parent = _norm(path), _norm(root)
    return child == parent or child.startswith(parent + os.sep)


def _tree(root: Path) -> set:
    return {str(p.relative_to(root)) for p in root.rglob("*")}


def _tail(text: str, limit: int = 400) -> str:
    return text.strip()[-limit:]


def _raise_infrastructure_failure(reason: str) -> None:
    """Skip offline-only failures locally; fail strict artifact runs."""
    if os.environ.get(ENV_ARTIFACT):
        raise RuntimeError("strict artifact E2E failure: " + reason)
    raise unittest.SkipTest(reason)


class CleanInstallTests(unittest.TestCase):
    #: Path to the distribution artifact (wheel or sdist) pip installs.
    artifact = None
    venv_dir = None
    venv_python = None
    install_error = None

    @classmethod
    def build_artifact(cls, artifact_dir: Path) -> Path:
        """Build the wheel; subclasses override to build another artifact."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                str(REPO_ROOT),
                "--no-deps",
                "-w",
                str(artifact_dir),
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            cwd=str(cls.base),
        )
        if result.returncode != 0:
            _raise_infrastructure_failure(
                f"wheel build failed (network needed for build "
                f"dependencies?): {_tail(result.stderr)}"
            )
        wheels = list(artifact_dir.glob("relinkra-*.whl"))
        if not wheels:
            _raise_infrastructure_failure(
                f"wheel build produced no relinkra wheel in {artifact_dir}"
            )
        return wheels[0]

    @classmethod
    def resolve_artifact(cls, artifact_dir: Path) -> Path:
        """The artifact under test: RELINKRA_E2E_ARTIFACT when set to an
        existing file, otherwise a fresh build."""
        provided = os.environ.get(ENV_ARTIFACT)
        if provided:
            path = Path(provided)
            if path.is_file():
                return path
            _raise_infrastructure_failure(
                f"configured artifact does not exist: {path}"
            )
        return cls.build_artifact(artifact_dir)

    @classmethod
    def setUpClass(cls):
        if shutil.which("git") is None:
            _raise_infrastructure_failure("git binary not available")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.base = Path(cls.tmp.name)
        cls.sandbox_home = cls.base / "sandbox-home"
        cls.sandbox_home.mkdir()

        artifact_dir = cls.base / "artifact"
        artifact_dir.mkdir()
        cls.artifact = cls.resolve_artifact(artifact_dir)

    # -- shared helpers ----------------------------------------------------

    @classmethod
    def _scripts_dir(cls) -> Path:
        return cls.venv_dir / ("Scripts" if IS_NT else "bin")

    @classmethod
    def _script(cls, name: str) -> Path:
        return cls._scripts_dir() / (name + (".exe" if IS_NT else ""))

    @classmethod
    def _clean_env(cls) -> dict:
        """Real environment minus anything that could redirect imports."""
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        env.pop("PYTHONHOME", None)
        return env

    @classmethod
    def _sandbox_env(cls) -> dict:
        """Home and host-config locations redirected to an empty directory.

        Nothing the installed CLI reads or writes can land in the
        developer's real home, APPDATA, XDG or Codex config.
        """
        env = {
            key: os.environ[key] for key in SANDBOX_KEPT if key in os.environ
        }
        home = str(cls.sandbox_home)
        env["HOME"] = home
        env["XDG_CONFIG_HOME"] = home
        env["CODEX_HOME"] = home
        if IS_NT:
            env["USERPROFILE"] = home
            env["APPDATA"] = home
        return env

    @classmethod
    def _fresh_dir(cls, name: str) -> Path:
        path = cls.base / name
        path.mkdir(exist_ok=True)
        return path

    def _installed(self) -> None:
        """Skip unless the venv exists and the artifact is installed."""
        cls = type(self)
        if cls.venv_python is None:
            _raise_infrastructure_failure(
                "venv unavailable (see test_step_a_create_venv)"
            )
        if cls.install_error is not None:
            _raise_infrastructure_failure(
                f"artifact not installed (see test_step_b_install_artifact): "
                f"{cls.install_error}"
            )

    def _work_repo(self) -> Path:
        """The initialized temp repo, created by step g if absent."""
        cls = type(self)
        repo = cls.base / "work-repo"
        if not (repo / ".relinkra" / "config.json").exists():
            gf.make_repo(repo)
            gf.git(repo, "remote", "add", "origin",
                   "https://github.com/org/e2e.git")
            gf.commit_file(repo, "README.md", "# e2e\n", "seed")
            result = subprocess.run(
                [str(cls._script("relinkra")), "init", "--json"],
                capture_output=True,
                text=True,
                timeout=TIMEOUT,
                cwd=str(repo),
                env=cls._sandbox_env(),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
        return repo

    # -- install sequence --------------------------------------------------

    def test_step_a_create_venv(self):
        cls = type(self)
        venv_dir = cls.base / "venv"
        result = subprocess.run(
            [sys.executable, "-m", "venv", str(venv_dir)],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
        )
        if result.returncode != 0:
            _raise_infrastructure_failure(
                f"venv creation failed: {_tail(result.stderr)}"
            )
        python = venv_dir / ("Scripts" if IS_NT else "bin") / (
            "python.exe" if IS_NT else "python"
        )
        if not python.exists():
            _raise_infrastructure_failure(f"venv python not found at {python}")
        cls.venv_dir = venv_dir
        cls.venv_python = python

    def test_step_b_install_artifact(self):
        cls = type(self)
        if cls.venv_python is None:
            _raise_infrastructure_failure(
                "venv unavailable (see test_step_a_create_venv)"
            )
        result = subprocess.run(
            [
                str(cls.venv_python),
                "-m",
                "pip",
                "install",
                "--no-cache-dir",
                str(cls.artifact),
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            cwd=str(cls.base),
            env=cls._clean_env(),
        )
        if result.returncode != 0:
            cls.install_error = _tail(result.stderr)
            _raise_infrastructure_failure(
                f"pip install failed (offline?): {cls.install_error}"
            )
        for name in ("relinkra", "relinkra-mcp"):
            script = cls._script(name)
            self.assertTrue(script.exists(), f"missing console script {script}")

    def test_step_c_version_flag_runs_outside_the_repo(self):
        self._installed()
        cls = type(self)
        result = subprocess.run(
            [str(cls._script("relinkra")), "--version"],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            cwd=str(cls._fresh_dir("cwd-c")),
            env=cls._clean_env(),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f"relinkra {RELEASE_VERSION}\n")

    def test_step_d_version_json_reports_installed(self):
        self._installed()
        cls = type(self)
        result = subprocess.run(
            [str(cls._script("relinkra")), "version", "--json"],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            cwd=str(cls._fresh_dir("cwd-d")),
            env=cls._clean_env(),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["relinkra_version"], RELEASE_VERSION)
        self.assertEqual(payload["install_mode"], "installed")
        self.assertEqual(payload["installed_metadata_version"], RELEASE_VERSION)
        self.assertTrue(payload["metadata_version_consistent"])
        self.assertIsNone(payload["build_provenance"]["source_commit"])
        self.assertIsNone(payload["build_provenance"]["artifact_sha256"])
        self.assertNotIn(str(REPO_ROOT), result.stdout)

    def test_step_e_help_lists_all_commands(self):
        self._installed()
        cls = type(self)
        result = subprocess.run(
            [str(cls._script("relinkra")), "--help"],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            cwd=str(cls._fresh_dir("cwd-e")),
            env=cls._clean_env(),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for command in (
            "init", "status", "doctor", "project", "cbm", "connect", "version"
        ):
            self.assertIn(command, result.stdout)

    def test_step_e_mcp_help_flag_runs_installed_entry_point(self):
        self._installed()
        cls = type(self)
        result = subprocess.run(
            [str(cls._script("relinkra-mcp")), "--help"],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            cwd=str(cls._fresh_dir("cwd-e-mcp")),
            env=cls._clean_env(),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage: relinkra-mcp", result.stdout)
        self.assertIn("--workspace-root", result.stdout)

    def test_step_f_import_resolves_inside_the_venv_not_the_checkout(self):
        self._installed()
        cls = type(self)
        code = "import relinkra; print(relinkra.__file__)"
        result = subprocess.run(
            [str(cls.venv_python), "-c", code],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            cwd=str(cls._fresh_dir("cwd-f")),
            env=cls._clean_env(),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        imported = result.stdout.strip()
        self.assertTrue(
            _is_within(imported, cls.venv_dir),
            f"relinkra imported from {imported}, outside the venv",
        )
        self.assertFalse(
            _is_within(imported, REPO_ROOT),
            f"relinkra imported from the source checkout: {imported}",
        )
        # Mutation-style companion: the very same import with the checkout
        # as cwd MUST resolve to the checkout — otherwise the assertions
        # above cannot discriminate a leaking import path.
        companion = subprocess.run(
            [str(cls.venv_python), "-c", code],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            cwd=str(REPO_ROOT),
            env=cls._clean_env(),
        )
        self.assertEqual(companion.returncode, 0, companion.stderr)
        self.assertTrue(
            _is_within(companion.stdout.strip(), REPO_ROOT),
            "companion import did not resolve to the checkout; "
            "the source-tree independence assertion is vacuous",
        )

    def test_step_g_init_is_idempotent_in_a_fresh_repo(self):
        self._installed()
        cls = type(self)
        repo = cls.base / "work-repo"
        gf.make_repo(repo)
        gf.git(repo, "remote", "add", "origin",
               "https://github.com/org/e2e.git")
        gf.commit_file(repo, "README.md", "# e2e\n", "seed")
        script = str(cls._script("relinkra"))

        first = subprocess.run(
            [script, "init", "--json"],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            cwd=str(repo),
            env=cls._sandbox_env(),
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        payload_first = json.loads(first.stdout)
        self.assertTrue(payload_first["initialized"])
        self.assertFalse(payload_first["already_initialized"])
        self.assertTrue((repo / ".relinkra" / "config.json").exists())
        self.assertTrue((repo / ".relinkra" / "registry.json").exists())

        second = subprocess.run(
            [script, "init", "--json"],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            cwd=str(repo),
            env=cls._sandbox_env(),
        )
        self.assertEqual(second.returncode, 0, second.stderr)
        payload_second = json.loads(second.stdout)
        self.assertTrue(payload_second["already_initialized"])
        self.assertEqual(
            payload_first["project_id"], payload_second["project_id"]
        )

    def test_step_h_doctor_json_in_sandboxed_environment(self):
        self._installed()
        cls = type(self)
        repo = self._work_repo()
        result = subprocess.run(
            [str(cls._script("relinkra")), "doctor", "--json"],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            cwd=str(repo),
            env=cls._sandbox_env(),
        )
        self.assertIn(result.returncode, (0, 2), result.stderr)
        payload = json.loads(result.stdout)
        checks = payload["checks"]
        self.assertTrue(checks, "doctor reported no checks")
        counts = {"PASS": 0, "WARN": 0, "FAIL": 0}
        for check in checks:
            for key in ("name", "status", "detail"):
                self.assertIn(key, check)
            self.assertIn(check["status"], counts)
            counts[check["status"]] += 1
        summary = payload["summary"]
        self.assertEqual(summary["pass"], counts["PASS"])
        self.assertEqual(summary["warn"], counts["WARN"])
        self.assertEqual(summary["fail"], counts["FAIL"])

    def test_step_i_connect_check_is_read_only(self):
        self._installed()
        cls = type(self)
        repo = self._work_repo()
        env = cls._sandbox_env()
        before = _tree(cls.sandbox_home)
        result = subprocess.run(
            [str(cls._script("relinkra")), "connect", "check", "codex", "--json"],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            cwd=str(repo),
            env=env,
        )
        self.assertIn(result.returncode, (0, 1, 2), result.stderr)
        after = _tree(cls.sandbox_home)
        self.assertEqual(
            before,
            after,
            f"connect check wrote into the sandbox home: {after - before}",
        )

    def test_step_j_import_surface(self):
        self._installed()
        cls = type(self)
        modules = (
            "relinkra.product_cli",
            "relinkra.mcp_cli",
            "relinkra.registry",
            "relinkra.identity",
            "relinkra.connectors",
        )
        result = subprocess.run(
            [str(cls.venv_python), "-c", "; ".join(f"import {m}" for m in modules)],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            cwd=str(cls._fresh_dir("cwd-j")),
            env=cls._clean_env(),
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_step_k_uninstall_and_reinstall(self):
        self._installed()
        cls = type(self)
        uninstall = subprocess.run(
            [str(cls.venv_python), "-m", "pip", "uninstall", "-y", "relinkra"],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            cwd=str(cls.base),
            env=cls._clean_env(),
        )
        self.assertEqual(uninstall.returncode, 0, uninstall.stderr)
        self.assertFalse(
            cls._script("relinkra").exists(),
            "console script survived pip uninstall",
        )
        reinstall = subprocess.run(
            [
                str(cls.venv_python),
                "-m",
                "pip",
                "install",
                "--no-cache-dir",
                str(cls.artifact),
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            cwd=str(cls.base),
            env=cls._clean_env(),
        )
        self.assertEqual(reinstall.returncode, 0, reinstall.stderr)
        version = subprocess.run(
            [str(cls._script("relinkra")), "--version"],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            cwd=str(cls._fresh_dir("cwd-k")),
            env=cls._clean_env(),
        )
        self.assertEqual(version.returncode, 0, version.stderr)
        self.assertTrue(
            version.stdout.startswith(f"relinkra {RELEASE_VERSION}"),
            version.stdout,
        )

    def test_step_l_mcp_entry_point_launches_relinkra_surface(self):
        """The installed MCP script must reach Relinkra, not a backend."""
        self._installed()
        cls = type(self)
        repo = self._work_repo()
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "r5a-install-test", "version": "1"},
            },
        }
        result = subprocess.run(
            [
                str(cls._script("relinkra-mcp")),
                "--workspace-root",
                str(repo),
                "--registry",
                str(repo / ".relinkra" / "registry.json"),
            ],
            input=json.dumps(request) + "\n",
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            cwd=str(repo),
            env=cls._sandbox_env(),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        response = json.loads(result.stdout)
        self.assertEqual(response["result"]["serverInfo"]["name"], "relinkra")


class ArtifactResolutionTests(unittest.TestCase):
    """Hermetic proof of the RELINKRA_E2E_ARTIFACT resolution contract."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.dir = Path(self._temp.name)
        self._saved_env = os.environ.pop(ENV_ARTIFACT, None)
        self.addCleanup(self._restore_env)
        self._saved_build = CleanInstallTests.__dict__["build_artifact"]
        self.addCleanup(
            setattr, CleanInstallTests, "build_artifact", self._saved_build
        )

    def _restore_env(self):
        if self._saved_env is None:
            os.environ.pop(ENV_ARTIFACT, None)
        else:
            os.environ[ENV_ARTIFACT] = self._saved_env

    def _stub_build(self, marker: Path):
        @classmethod
        def fake_build(cls, artifact_dir):
            return marker

        CleanInstallTests.build_artifact = fake_build

    def test_env_provided_artifact_wins(self):
        provided = self.dir / "provided.whl"
        provided.write_bytes(b"fake")
        built = self.dir / "built.whl"
        self._stub_build(built)
        os.environ[ENV_ARTIFACT] = str(provided)
        self.assertEqual(
            CleanInstallTests.resolve_artifact(self.dir), provided
        )

    def test_built_artifact_is_used_otherwise(self):
        built = self.dir / "built.whl"
        self._stub_build(built)
        # Env var absent.
        self.assertEqual(CleanInstallTests.resolve_artifact(self.dir), built)
        # A configured but missing artifact is a strict CI infrastructure
        # failure, not an invitation to rebuild a different artifact.
        os.environ[ENV_ARTIFACT] = str(self.dir / "missing.whl")
        with self.assertRaisesRegex(RuntimeError, "strict artifact E2E failure"):
            CleanInstallTests.resolve_artifact(self.dir)


if __name__ == "__main__":
    unittest.main()
