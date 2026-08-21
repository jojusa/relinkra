"""R5H.1 — managed CBM acquisition (``relinkra cbm setup``), hermetic tests.

No network is ever touched: the ``downloader`` seam is always a fake, and
the certified pin is replaced with a test pin built from fake exe bytes
(the real SHA-256 of those bytes; the release zip is built in-memory).
That keeps the full pipeline — archive digest, extraction, exe digest,
version probe, atomic activation, provenance record — on real code paths
while staying offline and platform-neutral (the fake tag ``linux-amd64``
gives the extensionless exe name on every host).
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:  # discovery (`-s tests`) puts tests/ on sys.path; direct runs may not
    import git_fixtures
except ImportError:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import git_fixtures

from relinkra import cbm_acquire, cbm_indexing, cbm_support, product_cli
from relinkra.product_cli import EXIT_ERROR, EXIT_OK

FAKE_TAG = "linux-amd64"
FAKE_EXE_NAME = "codebase-memory-mcp"
FAKE_EXE = b"fake-certified-cbm-executable"
FAKE_VERSION_OUTPUT = "codebase-memory-mcp 0.9.0"


def _build_zip(member_name: str, content: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(member_name, content)
    return buffer.getvalue()


def _pin(exe_bytes: bytes = FAKE_EXE, zip_bytes: bytes = b"") -> dict:
    return {
        "version": cbm_support.CERTIFIED_CBM_VERSION,
        "sha256": hashlib.sha256(exe_bytes).hexdigest(),
        "release_zip_sha256": hashlib.sha256(zip_bytes).hexdigest(),
        "release_url": "https://example.invalid/cbm/releases/tag/v0.9.0",
    }


class ManagedPathTests(unittest.TestCase):
    def test_managed_binary_path_template(self):
        root = os.path.join("D:", os.sep, "data") if os.name == "nt" else "/data"
        self.assertEqual(
            cbm_support.managed_cbm_binary_path("0.9.0", "linux-amd64", data_root=root),
            os.path.join(root, "backends", "cbm", "0.9.0", "codebase-memory-mcp"),
        )
        self.assertEqual(
            cbm_support.managed_cbm_binary_path("0.9.0", "windows-amd64", data_root=root),
            os.path.join(root, "backends", "cbm", "0.9.0", "codebase-memory-mcp.exe"),
        )

    def test_data_root_env_override_wins(self):
        self.assertEqual(
            cbm_support.relinkra_data_root(environ={"RELINKRA_DATA_ROOT": "/x"}), "/x"
        )

    def test_data_root_windows_default(self):
        home = os.path.expanduser("~")
        with mock.patch("relinkra.cbm_support.platform.system", return_value="Windows"):
            self.assertEqual(
                cbm_support.relinkra_data_root(environ={}),
                os.path.join(home, ".local", "relinkra"),
            )

    def test_data_root_posix_xdg_and_default(self):
        home = os.path.expanduser("~")
        with mock.patch("relinkra.cbm_support.platform.system", return_value="Linux"):
            self.assertEqual(
                cbm_support.relinkra_data_root(environ={"XDG_DATA_HOME": "/xdg"}),
                os.path.join("/xdg", "relinkra"),
            )
            self.assertEqual(
                cbm_support.relinkra_data_root(environ={}),
                os.path.join(home, ".local", "share", "relinkra"),
            )


class SetupTests(unittest.TestCase):
    """setup_cbm against a tmp RELINKRA_DATA_ROOT with a fake certified pin."""

    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="rlk-cbm-setup-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.data_root = os.path.join(tmp, "data-root")
        self.zip_bytes = _build_zip(FAKE_EXE_NAME, FAKE_EXE)
        pin = _pin(zip_bytes=self.zip_bytes)
        patch_tag = mock.patch.object(cbm_support, "platform_tag", lambda: FAKE_TAG)
        patch_pin = mock.patch.dict(
            cbm_support.CERTIFIED_CBM_BINARIES, {FAKE_TAG: pin}
        )
        patch_tag.start()
        patch_pin.start()
        self.addCleanup(patch_pin.stop)
        self.addCleanup(patch_tag.stop)
        self.runner = mock.Mock(return_value=FAKE_VERSION_OUTPUT)
        self.download_calls = []

    @property
    def target(self) -> str:
        return cbm_support.managed_cbm_binary_path(
            cbm_support.CERTIFIED_CBM_VERSION, FAKE_TAG, data_root=self.data_root
        )

    def _downloader(self, content=None):
        def download(url, destination):
            self.download_calls.append(url)
            Path(destination).write_bytes(
                self.zip_bytes if content is None else content
            )

        return download

    def _backends_dir(self) -> Path:
        return Path(self.data_root) / "backends" / "cbm"

    def _assert_no_staging_leftovers(self):
        backends = self._backends_dir()
        if not backends.is_dir():
            return
        leftovers = [
            entry.name
            for entry in backends.iterdir()
            if entry.name.startswith(".setup-tmp") or ".setup-old-" in entry.name
        ]
        self.assertEqual(leftovers, [])

    def _write_from_file_zip(self, content=None) -> str:
        source = Path(self.data_root).parent / "release.zip"
        source.write_bytes(self.zip_bytes if content is None else content)
        return str(source)

    # -- happy paths ---------------------------------------------------

    def test_first_install_from_file_zip(self):
        result = cbm_acquire.setup_cbm(
            from_file=self._write_from_file_zip(),
            data_root=self.data_root,
            runner=self.runner,
        )
        self.assertEqual(result.status, cbm_acquire.STATUS_INSTALLED, result.error)
        self.assertEqual(result.managed_path, self.target)
        self.assertEqual(Path(self.target).read_bytes(), FAKE_EXE)
        self.runner.assert_called_once()
        provenance = json.loads(
            (Path(self.target).parent / cbm_acquire.PROVENANCE_FILE).read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(provenance["version"], cbm_support.CERTIFIED_CBM_VERSION)
        self.assertEqual(provenance["platform_tag"], FAKE_TAG)
        self.assertEqual(
            provenance["expected_sha256"], provenance["actual_sha256"]
        )
        self.assertEqual(
            provenance["archive_sha256"], hashlib.sha256(self.zip_bytes).hexdigest()
        )
        self.assertTrue(provenance["source"].startswith("file:"))
        self.assertTrue(provenance["installed_at"])
        self._assert_no_staging_leftovers()

    def test_first_install_via_downloader_derives_pinned_url(self):
        result = cbm_acquire.setup_cbm(
            data_root=self.data_root,
            downloader=self._downloader(),
            runner=self.runner,
        )
        self.assertEqual(result.status, cbm_acquire.STATUS_INSTALLED, result.error)
        self.assertEqual(len(self.download_calls), 1)
        self.assertEqual(
            self.download_calls[0],
            "https://example.invalid/cbm/releases/download/"
            "v0.9.0/codebase-memory-mcp-linux-amd64.zip",
        )
        provenance = json.loads(
            (Path(self.target).parent / cbm_acquire.PROVENANCE_FILE).read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(provenance["source"], self.download_calls[0])

    def test_from_file_bare_executable(self):
        source = Path(self.data_root).parent / "cbm-local"
        source.write_bytes(FAKE_EXE)
        result = cbm_acquire.setup_cbm(
            from_file=str(source), data_root=self.data_root, runner=self.runner
        )
        self.assertEqual(result.status, cbm_acquire.STATUS_INSTALLED, result.error)
        self.assertEqual(Path(self.target).read_bytes(), FAKE_EXE)

    def test_idempotent_second_run_never_downloads(self):
        first = cbm_acquire.setup_cbm(
            data_root=self.data_root,
            downloader=self._downloader(),
            runner=self.runner,
        )
        self.assertEqual(first.status, cbm_acquire.STATUS_INSTALLED, first.error)
        self.download_calls.clear()
        second = cbm_acquire.setup_cbm(
            data_root=self.data_root,
            downloader=self._downloader(),
            runner=self.runner,
        )
        self.assertEqual(second.status, cbm_acquire.STATUS_ALREADY_INSTALLED)
        self.assertEqual(second.managed_path, self.target)
        self.assertEqual(self.download_calls, [])

    # -- verification failures ------------------------------------------

    def test_archive_sha_mismatch_fails_without_activating(self):
        result = cbm_acquire.setup_cbm(
            data_root=self.data_root,
            downloader=self._downloader(content=b"corrupted-archive"),
            runner=self.runner,
        )
        self.assertEqual(result.status, cbm_acquire.STATUS_FAILED)
        self.assertIn("archive", result.error)
        self.assertFalse(os.path.exists(self.target))
        self.runner.assert_not_called()
        self._assert_no_staging_leftovers()

    def test_exe_sha_mismatch_inside_valid_zip_fails(self):
        wrong_zip = _build_zip(FAKE_EXE_NAME, b"not-the-certified-exe")
        with mock.patch.dict(
            cbm_support.CERTIFIED_CBM_BINARIES,
            {FAKE_TAG: _pin(zip_bytes=wrong_zip)},
        ):
            result = cbm_acquire.setup_cbm(
                data_root=self.data_root,
                downloader=self._downloader(content=wrong_zip),
                runner=self.runner,
            )
        self.assertEqual(result.status, cbm_acquire.STATUS_FAILED)
        self.assertIn("executable", result.error)
        self.assertFalse(os.path.exists(self.target))
        self.runner.assert_not_called()
        self._assert_no_staging_leftovers()

    def test_unsafe_archive_member_is_refused(self):
        evil_zip = _build_zip(f"../{FAKE_EXE_NAME}", FAKE_EXE)
        with mock.patch.dict(
            cbm_support.CERTIFIED_CBM_BINARIES, {FAKE_TAG: _pin(zip_bytes=evil_zip)}
        ):
            result = cbm_acquire.setup_cbm(
                data_root=self.data_root,
                downloader=self._downloader(content=evil_zip),
                runner=self.runner,
            )
        self.assertEqual(result.status, cbm_acquire.STATUS_FAILED)
        self.assertFalse(os.path.exists(self.target))
        self._assert_no_staging_leftovers()

    def test_version_mismatch_fails_without_activating(self):
        self.runner.return_value = "codebase-memory-mcp 0.8.0"
        result = cbm_acquire.setup_cbm(
            data_root=self.data_root,
            downloader=self._downloader(),
            runner=self.runner,
        )
        self.assertEqual(result.status, cbm_acquire.STATUS_FAILED)
        self.assertIn("certified", result.error)
        self.assertFalse(os.path.exists(self.target))
        self._assert_no_staging_leftovers()

    def test_unsupported_platform_is_not_certified_and_never_downloads(self):
        with mock.patch.object(cbm_support, "platform_tag", lambda: "darwin-arm64"):
            result = cbm_acquire.setup_cbm(
                data_root=self.data_root,
                downloader=self._downloader(),
                runner=self.runner,
            )
        self.assertEqual(result.status, cbm_acquire.STATUS_NOT_CERTIFIED)
        self.assertIn("darwin-arm64", result.detail)
        self.assertEqual(self.download_calls, [])
        self.runner.assert_not_called()

    # -- pre-existing installation discipline ----------------------------

    def test_corrupt_install_replaced_only_after_full_verification(self):
        target = Path(self.target)
        target.parent.mkdir(parents=True)
        target.write_bytes(b"corrupt")
        result = cbm_acquire.setup_cbm(
            data_root=self.data_root,
            downloader=self._downloader(),
            runner=self.runner,
        )
        self.assertEqual(result.status, cbm_acquire.STATUS_INSTALLED, result.error)
        self.assertEqual(target.read_bytes(), FAKE_EXE)

    def test_failed_reacquire_leaves_existing_install_untouched(self):
        target = Path(self.target)
        target.parent.mkdir(parents=True)
        target.write_bytes(b"corrupt")
        self.runner.return_value = "codebase-memory-mcp 0.8.0"
        result = cbm_acquire.setup_cbm(
            data_root=self.data_root,
            downloader=self._downloader(),
            runner=self.runner,
        )
        self.assertEqual(result.status, cbm_acquire.STATUS_FAILED)
        # The pre-existing (corrupt) binary is left exactly as found; the
        # runtime SHA gate keeps refusing it.
        self.assertEqual(target.read_bytes(), b"corrupt")
        self._assert_no_staging_leftovers()

    def test_downloader_error_cleans_staging(self):
        def broken(url, destination):
            raise cbm_acquire.CBMAcquireError("offline")

        result = cbm_acquire.setup_cbm(
            data_root=self.data_root, downloader=broken, runner=self.runner
        )
        self.assertEqual(result.status, cbm_acquire.STATUS_FAILED)
        self.assertIn("offline", result.error)
        self._assert_no_staging_leftovers()


class CbmSetupCliTests(unittest.TestCase):
    """The ``relinkra cbm setup`` command surface (acquisition mocked)."""

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = product_cli.main(list(argv))
            except SystemExit as exc:  # argparse usage errors exit 1
                code = int(exc.code)
        return code, out.getvalue(), err.getvalue()

    def _result(self, status, **kwargs):
        return cbm_acquire.CBMSetupResult(status=status, **kwargs)

    def test_setup_installed_human_output(self):
        result = self._result(
            cbm_acquire.STATUS_INSTALLED, managed_path="C:/managed/cbm.exe"
        )
        with mock.patch.object(
            product_cli.cbm_acquire, "setup_cbm", return_value=result
        ) as setup:
            code, out, err = self.run_cli("cbm", "setup")
        self.assertEqual(code, EXIT_OK, err)
        setup.assert_called_once_with(from_file=None)
        self.assertIn("CBM: INSTALLED", out)
        self.assertIn("C:/managed/cbm.exe", out)
        self.assertIn("SHA-256", out)
        self.assertIn("Next: relinkra cbm index", out)

    def test_setup_from_file_is_passed_through(self):
        result = self._result(
            cbm_acquire.STATUS_INSTALLED, managed_path="/managed/cbm"
        )
        with mock.patch.object(
            product_cli.cbm_acquire, "setup_cbm", return_value=result
        ) as setup:
            code, out, err = self.run_cli("cbm", "setup", "--from-file", "x.zip")
        self.assertEqual(code, EXIT_OK, err)
        setup.assert_called_once_with(from_file="x.zip")

    def test_setup_already_installed_exits_zero(self):
        result = self._result(
            cbm_acquire.STATUS_ALREADY_INSTALLED, managed_path="/managed/cbm"
        )
        with mock.patch.object(
            product_cli.cbm_acquire, "setup_cbm", return_value=result
        ):
            code, out, err = self.run_cli("cbm", "setup", "--json")
        self.assertEqual(code, EXIT_OK, err)
        payload = json.loads(out)
        self.assertEqual(payload["status"], "ALREADY_INSTALLED")
        self.assertEqual(payload["managed_path"], "/managed/cbm")

    def test_setup_not_certified_exits_nonzero_honestly(self):
        result = self._result(
            cbm_acquire.STATUS_NOT_CERTIFIED,
            detail="no certified CBM release for platform linux-amd64",
        )
        with mock.patch.object(
            product_cli.cbm_acquire, "setup_cbm", return_value=result
        ):
            code, out, err = self.run_cli("cbm", "setup")
            self.assertEqual(code, EXIT_ERROR)
            self.assertIn("NOT_CERTIFIED", out)
            self.assertIn("linux-amd64", out)
            self.assertIn("Optional backend unavailable", out)
            code, out, err = self.run_cli("cbm", "setup", "--json")
        self.assertEqual(code, EXIT_ERROR)
        self.assertEqual(json.loads(out)["status"], "NOT_CERTIFIED")

    def test_setup_failure_exits_nonzero(self):
        result = self._result(
            cbm_acquire.STATUS_FAILED,
            error="downloaded archive hash does not match",
            detail="No existing installation was modified.",
        )
        with mock.patch.object(
            product_cli.cbm_acquire, "setup_cbm", return_value=result
        ):
            code, out, err = self.run_cli("cbm", "setup")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("Error:", err)
        self.assertIn("archive hash", err)

    def test_setup_failure_json_still_emits_payload(self):
        """--json must stay machine-readable even for FAILED setups."""
        result = self._result(
            cbm_acquire.STATUS_FAILED,
            error="downloaded archive hash does not match",
            detail="No existing installation was modified.",
        )
        with mock.patch.object(
            product_cli.cbm_acquire, "setup_cbm", return_value=result
        ):
            code, out, err = self.run_cli("cbm", "setup", "--json")
        self.assertEqual(code, EXIT_ERROR)
        payload = json.loads(out)
        self.assertEqual(payload["status"], "FAILED")
        self.assertIn("archive hash", payload["error"])


class CbmStatusManagedDiscoveryTests(unittest.TestCase):
    """CLI-level proof: a managed per-user binary is discovered without
    RELINKRA_CBM_BIN ever being set."""

    def setUp(self):
        if shutil.which("git") is None:
            self.skipTest("git is required for the cbm CLI tests")
        tmp = tempfile.mkdtemp(prefix="rlk-cbm-setup-cli-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.repo = git_fixtures.make_repo(os.path.join(tmp, "repo"))
        git_fixtures.commit_file(self.repo, "README.md", "hello\n", "initial")
        self.data_root = os.path.join(tmp, "data-root")

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = product_cli.main(list(argv))
            except SystemExit as exc:
                code = int(exc.code)
        return code, out.getvalue(), err.getvalue()

    def test_status_discovers_managed_binary_without_env_override(self):
        target = Path(
            cbm_support.managed_cbm_binary_path(
                cbm_support.CERTIFIED_CBM_VERSION, FAKE_TAG, data_root=self.data_root
            )
        )
        target.parent.mkdir(parents=True)
        target.write_bytes(FAKE_EXE)
        with mock.patch.dict(
            os.environ, {"RELINKRA_DATA_ROOT": self.data_root}
        ), mock.patch.dict(
            cbm_support.CERTIFIED_CBM_BINARIES, {FAKE_TAG: _pin()}
        ), mock.patch.object(
            cbm_support, "platform_tag", lambda: FAKE_TAG
        ), mock.patch.object(
            cbm_indexing, "platform_tag", lambda: FAKE_TAG
        ):
            os.environ.pop("RELINKRA_CBM_BIN", None)  # restored by patch.dict
            code, out, err = self.run_cli("cbm", "status", "--path", self.repo)
        self.assertEqual(code, EXIT_OK, err)
        # AVAILABLE + never indexed => the managed binary was found and
        # hash-verified, and the honest next step is indexing.
        self.assertIn("CBM: AVAILABLE", out)
        self.assertIn("Index: MISSING", out)
        self.assertIn("Next: relinkra cbm index", out)


class ConnectorIndependenceTests(unittest.TestCase):
    """Generated host configs must never embed a CBM path or env var."""

    def test_host_entries_carry_no_cbm_path_or_env(self):
        from relinkra import connectors

        launch = connectors.resolve_launch("C:/ws", "C:/ws/.relinkra/registry.json")
        self.assertTrue(launch.resolved, launch.warnings)
        checked = 0
        for connector_id in (
            "opencode",
            "claude",
            "codex",
            "devin-desktop",
        ):
            spec = connectors.resolve_connector(connector_id)
            if spec.entry_builder is None:
                continue
            entry = spec.entry_builder(launch)
            rendered = json.dumps(entry)
            with self.subTest(connector=connector_id):
                self.assertNotIn("RELINKRA_CBM_BIN", rendered)
                self.assertNotIn("codebase-memory", rendered.lower())
            checked += 1
        self.assertEqual(checked, 4)


if __name__ == "__main__":
    unittest.main()
