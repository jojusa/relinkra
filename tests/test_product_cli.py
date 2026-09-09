"""Tests for the R4A product CLI: init, status, doctor, project.

Every test runs against a real temporary git repository and drives the
CLI through ``main(argv)`` with captured streams, so exit codes, stdout,
and stderr are all asserted as a user would experience them.

Engine availability is controlled by monkeypatching the CLI's own
service constructor, which keeps these tests offline and deterministic
without reaching into Engram or CBM.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from relinkra import product_cli
from relinkra.product_cli import (
    EXIT_ACTION_REQUIRED,
    EXIT_ERROR,
    EXIT_OK,
    FAIL,
    PASS,
    WARN,
    WorkspaceConfig,
)

_HAS_GIT = shutil.which("git") is not None


def _git(cwd, *args):
    subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    )


class FakeProbeServices:
    """Stand-in for RelinkraServices with controllable component health.

    Only the two methods the CLI actually calls are implemented, so a
    drift in either signature shows up here as a failure rather than
    being silently absorbed.
    """

    def __init__(self, engram=True, cbm=False, git=True, project=True):
        self._engram = engram
        self._cbm = cbm
        self._git = git
        self._project = project

    def health(self):
        degraded = [
            name
            for name, ok in (
                ("engram", self._engram),
                ("cbm", self._cbm),
                ("git", self._git),
            )
            if not ok
        ]
        return {
            "status": "degraded" if degraded else "ok",
            "components": {
                "engram": {
                    "available": self._engram,
                    "checked": True,
                    "detail": "" if self._engram else "engram not found",
                },
                "cbm": {
                    "available": self._cbm,
                    "checked": not self._cbm,
                    "detail": "" if self._cbm else "no CBM adapter configured",
                },
                "git": {
                    "available": self._git,
                    "checked": True,
                    "detail": "" if self._git else "git unavailable",
                },
                "registry": {"available": True, "checked": True, "detail": ""},
            },
            "degraded": degraded,
            "capabilities": {
                "context_packets": True,
                "memory_read": self._engram,
                "memory_write": self._engram,
                "handoffs": self._engram,
                "code_resolution": self._cbm,
                "git_intelligence": self._git,
            },
            "capabilities_unchecked": [] if self._cbm else ["code_resolution"],
        }

    def project_resolve(self):
        if not self._project:
            from relinkra.app_service import ERR_NOT_FOUND, ServiceError

            raise ServiceError(ERR_NOT_FOUND, "no registered project")
        return {
            "project_id": "rlk_" + "0" * 32,
            "display_name": "demo",
            "repository_identity": {
                "kind": "remote",
                "value": "remote://git/github.com/org/demo",
                "trust": "strong",
            },
            "workspace": {"os_family": "linux"},
        }


class CLITestCase(unittest.TestCase):
    """A real temp git repo with the CLI wired to fake engines."""

    engram = True
    cbm = False
    git_component = True

    def setUp(self):
        if not _HAS_GIT:
            self.skipTest("git is required for the product CLI tests")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "repo"
        self.root.mkdir(parents=True)
        _git(self.root, "init", "-q")
        _git(self.root, "config", "user.email", "cli@relinkra.test")
        _git(self.root, "config", "user.name", "Relinkra CLI")
        _git(self.root, "remote", "add", "origin",
             "https://github.com/org/demo.git")
        (self.root / "README.md").write_text("# demo\n", encoding="utf-8")
        _git(self.root, "add", "README.md")
        _git(self.root, "commit", "-q", "-m", "seed")

        original = product_cli._services

        def fake_services(root, config):
            return FakeProbeServices(
                engram=self.engram, cbm=self.cbm, git=self.git_component
            )

        product_cli._services = fake_services
        self.addCleanup(setattr, product_cli, "_services", original)

    def run_cli(self, *argv, path=None):
        """Invoke the CLI, returning (exit_code, stdout, stderr)."""
        args = list(argv)
        if path is not False:
            args += ["--path", str(path or self.root)]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = product_cli.main(args)
        return code, out.getvalue(), err.getvalue()

    def init(self, *extra):
        code, out, err = self.run_cli("init", *extra)
        self.assertEqual(code, EXIT_OK, err)
        return out


class InitTests(CLITestCase):
    def test_init_succeeds_and_reports_identity(self):
        out = self.init()
        self.assertIn("Relinkra initialized", out)
        self.assertIn("Project", out)
        self.assertIn("rlk_", out)
        self.assertIn("ws_", out)

    def test_init_writes_only_inside_the_config_dir(self):
        before = {p.name for p in self.root.iterdir()}
        self.init()
        after = {p.name for p in self.root.iterdir()}
        self.assertEqual(after - before, {product_cli.CONFIG_DIR})

    def test_init_creates_config_and_registry(self):
        self.init()
        self.assertTrue(product_cli.config_path(self.root).exists())
        self.assertTrue(product_cli.registry_path(self.root).exists())

    def test_init_is_idempotent(self):
        first = self.init()
        config_a = WorkspaceConfig.load(self.root)
        second = self.init()
        config_b = WorkspaceConfig.load(self.root)

        self.assertIn("Relinkra initialized", first)
        self.assertIn("already initialized", second)
        self.assertEqual(config_a.project_id, config_b.project_id)
        self.assertEqual(config_a.workspace_id, config_b.workspace_id)
        # The original initialization time is preserved, not rewritten.
        self.assertEqual(config_a.initialized_at, config_b.initialized_at)

    def test_repeated_init_creates_no_duplicate_identities(self):
        for _ in range(4):
            self.init()
        registry = json.loads(
            product_cli.registry_path(self.root).read_text(encoding="utf-8")
        )
        self.assertEqual(len(registry["projects"]), 1)
        self.assertEqual(len(registry["workspaces"]), 1)

    def test_init_outside_a_git_repository_fails(self):
        plain = Path(self.tmp.name) / "plain"
        plain.mkdir()
        code, out, err = self.run_cli("init", path=plain)
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("not inside a git repository", err.lower())
        self.assertIn("Suggested action", err)
        self.assertFalse((plain / product_cli.CONFIG_DIR).exists())

    def test_init_never_touches_git_state(self):
        head_before = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.root,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        self.init()
        head_after = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.root,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain"], cwd=self.root,
            capture_output=True, text=True, check=True,
        ).stdout
        self.assertEqual(head_before, head_after)
        # .relinkra/ is the only new entry and nothing was staged.
        self.assertNotIn("A  ", status)
        self.assertNotIn("M  ", status)

    def test_init_json_output(self):
        code, out, err = self.run_cli("init", "--json")
        self.assertEqual(code, EXIT_OK, err)
        payload = json.loads(out)
        self.assertTrue(payload["initialized"])
        self.assertFalse(payload["already_initialized"])
        self.assertTrue(payload["project_id"].startswith("rlk_"))
        self.assertTrue(payload["workspace_id"].startswith("ws_"))

    def test_init_json_marks_reinitialization(self):
        self.init()
        code, out, _ = self.run_cli("init", "--json")
        self.assertEqual(code, EXIT_OK)
        self.assertTrue(json.loads(out)["already_initialized"])


class IdentityPinTests(CLITestCase):
    """A stale config must never attach a different repo to a project.

    `.relinkra/config.json` is gitignored, so it routinely outlives the
    repository it describes. Reusing its project_id unconditionally would
    file an unrelated codebase under the previous project and silently
    share that project's memory and handoffs.
    """

    def _project_id(self):
        return WorkspaceConfig.load(self.root).project_id

    def _repoint(self, url):
        _git(self.root, "remote", "set-url", "origin", url)

    def test_repurposed_directory_gets_a_new_project(self):
        self.init()
        before = self._project_id()
        self._repoint("https://github.com/other-org/beta.git")
        self.init()
        after = self._project_id()
        self.assertNotEqual(
            before, after, "an unrelated repository inherited the old project"
        )

    def test_repurposed_directory_is_reported_not_silent(self):
        self.init()
        self._repoint("https://github.com/other-org/beta.git")
        code, out, err = self.run_cli("init")
        self.assertEqual(code, EXIT_OK, err)
        self.assertIn("different repository", out)
        self.assertIn("NOT shared", out)

    def test_identity_change_is_flagged_in_json(self):
        self.init()
        self._repoint("https://github.com/other-org/beta.git")
        payload = json.loads(self.run_cli("init", "--json")[1])
        self.assertTrue(payload["identity_changed"])
        self.assertFalse(payload["already_initialized"])

    def test_both_projects_survive_in_the_registry(self):
        self.init()
        first = self._project_id()
        self._repoint("https://github.com/other-org/beta.git")
        self.init()
        second = self._project_id()
        registry = json.loads(
            product_cli.registry_path(self.root).read_text(encoding="utf-8")
        )
        self.assertEqual(len(registry["projects"]), 2)
        identities = {
            pid: proj["repository_identity"]["value"]
            for pid, proj in registry["projects"].items()
        }
        self.assertNotEqual(identities[first], identities[second])

    def test_identity_change_adopts_the_new_workspace_timestamp(self):
        """A different project must not inherit the old init time.

        Asserted against the registry rather than by comparing the two
        strings: the clock has second precision, so two inits in the same
        second are legitimately equal and would make a difference-based
        assertion pass or fail on timing rather than on behaviour.
        """
        self.init()
        self._repoint("https://github.com/other-org/beta.git")
        self.init()

        config = WorkspaceConfig.load(self.root)
        registry = json.loads(
            product_cli.registry_path(self.root).read_text(encoding="utf-8")
        )
        workspace = registry["workspaces"][config.workspace_id]
        self.assertEqual(
            config.initialized_at,
            workspace["registered_at"],
            "the new project kept a timestamp from the previous one",
        )

    def test_unchanged_identity_is_still_a_plain_refresh(self):
        """The fix must not break ordinary idempotency."""
        self.init()
        payload = json.loads(self.run_cli("init", "--json")[1])
        self.assertFalse(payload["identity_changed"])
        self.assertTrue(payload["already_initialized"])

    def test_pin_to_an_unknown_project_is_rederived(self):
        """A config pointing outside the registry is not trusted."""
        self.init()
        path = product_cli.config_path(self.root)
        data = json.loads(path.read_text(encoding="utf-8"))
        data["project_id"] = "rlk_" + "9" * 32
        path.write_text(json.dumps(data), encoding="utf-8")
        code, _, err = self.run_cli("init")
        self.assertEqual(code, EXIT_OK, err)
        self.assertNotEqual(
            WorkspaceConfig.load(self.root).project_id, "rlk_" + "9" * 32
        )


class RegistryFailureTests(CLITestCase):
    def test_unreadable_registry_is_a_clean_doctor_failure(self):
        """A permission/IO error must not crash doctor."""
        self.init()
        path = product_cli.registry_path(self.root)
        path.unlink()
        # A directory where a file is expected raises OSError on read,
        # portably across Windows and POSIX.
        path.mkdir()
        code, out, _ = self.run_cli("doctor")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("Registry", out)
        self.assertIn(FAIL, out)

    def test_unreadable_registry_is_a_clean_init_failure(self):
        self.init()
        path = product_cli.registry_path(self.root)
        path.unlink()
        path.mkdir()
        code, _, err = self.run_cli("init")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("registry", err.lower())
        self.assertIn("Suggested action", err)


class BrokenStateTests(CLITestCase):
    """No command may crash on a broken workspace.

    `doctor` especially: it exists to diagnose exactly these states, so a
    traceback there is the worst possible outcome.
    """

    def _write_config(self, data):
        product_cli.config_dir(self.root).mkdir(parents=True, exist_ok=True)
        product_cli.config_path(self.root).write_text(
            json.dumps(data), encoding="utf-8"
        )

    def test_non_numeric_config_version_does_not_crash(self):
        """Valid JSON that is still unusable must be treated as absent."""
        self._write_config({"config_version": "abc", "project_id": "rlk_x"})
        self.assertIsNone(WorkspaceConfig.load(self.root))
        for argv, expected in (
            (("doctor",), EXIT_OK),
            (("status",), EXIT_ERROR),
            (("project",), EXIT_ERROR),
        ):
            code, _, _ = self.run_cli(*argv)
            self.assertEqual(code, expected, argv)

    def test_odd_config_shapes_do_not_crash(self):
        for data in (
            {"config_version": None, "project_id": []},
            {"config_version": [1], "project_id": "rlk_x"},
            {"config_version": {"a": 1}},
            {"project_id": 12345},
        ):
            self._write_config(data)
            code, _, _ = self.run_cli("doctor")
            self.assertEqual(code, EXIT_OK, data)

    def test_config_that_is_a_list_is_treated_as_absent(self):
        product_cli.config_dir(self.root).mkdir(parents=True, exist_ok=True)
        product_cli.config_path(self.root).write_text("[1,2]", encoding="utf-8")
        self.assertIsNone(WorkspaceConfig.load(self.root))
        self.assertEqual(self.run_cli("doctor")[0], EXIT_OK)

    def test_unwritable_config_is_a_clean_init_failure(self):
        """A directory where config.json belongs must not crash init."""
        product_cli.config_dir(self.root).mkdir(parents=True, exist_ok=True)
        product_cli.config_path(self.root).mkdir()
        code, _, err = self.run_cli("init")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("config", err.lower())
        self.assertIn("Suggested action", err)

    def test_atomic_save_leaves_no_temporary_file(self):
        self.init()
        leftovers = [
            entry.name
            for entry in product_cli.config_dir(self.root).iterdir()
            if entry.name.endswith(".tmp")
        ]
        self.assertEqual(leftovers, [])

    def test_config_survives_a_repeated_save(self):
        self.init()
        for _ in range(5):
            WorkspaceConfig.load(self.root).save(self.root)
        reloaded = WorkspaceConfig.load(self.root)
        self.assertIsNotNone(reloaded)
        self.assertTrue(reloaded.project_id.startswith("rlk_"))


class RealServiceFailureTests(CLITestCase):
    """Failures that only the REAL services can surface.

    CLITestCase swaps in FakeProbeServices, which never opens the
    registry — so a registry fault is invisible through it. These tests
    restore the genuine constructor, which is the only way to prove the
    commands react to an engine-level failure at all.
    """

    def setUp(self):
        super().setUp()
        product_cli._services = self._real_services

    @staticmethod
    def _real_services(root, config):
        from relinkra.app_service import RelinkraServices, ServiceConfig

        return RelinkraServices(
            config=ServiceConfig(
                workspace_root=str(root),
                registry_path=str(product_cli.registry_path(root)),
                default_project_id=(config.project_id if config else None) or None,
            )
        )

    def _break_registry(self):
        path = product_cli.registry_path(self.root)
        path.unlink()
        path.mkdir()

    def test_project_fails_when_the_registry_is_unreadable(self):
        """project must not report identity it could not verify."""
        self.init()
        self._break_registry()
        code, out, err = self.run_cli("project")
        self.assertEqual(code, EXIT_ERROR)
        self.assertNotIn("rlk_", out)
        self.assertIn("Suggested action", err)

    def test_status_fails_when_the_registry_is_unreadable(self):
        self.init()
        self._break_registry()
        code, out, err = self.run_cli("status")
        self.assertEqual(code, EXIT_ERROR)
        self.assertNotIn("rlk_", out)

    def test_doctor_still_reports_on_an_unreadable_registry(self):
        """doctor diagnoses rather than fails to start."""
        self.init()
        self._break_registry()
        code, out, _ = self.run_cli("doctor")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("Registry", out)
        self.assertIn(FAIL, out)

    def test_broken_registry_error_leaks_no_path(self):
        self.init()
        self._break_registry()
        for argv in (("status",), ("project",), ("doctor",)):
            _, out, err = self.run_cli(*argv)
            self.assertNotIn(str(self.root), out + err)


class StatusTests(CLITestCase):
    def test_status_requires_init(self):
        code, out, err = self.run_cli("status")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("not initialized", err)
        self.assertIn("relinkra init", err)

    def test_status_reports_the_expected_rows(self):
        self.init()
        code, out, err = self.run_cli("status")
        self.assertEqual(code, EXIT_OK, err)
        for label in (
            "Project", "Workspace", "Git", "Engram", "CBM", "MCP",
            "Memory", "Handoffs",
        ):
            self.assertIn(label, out)

    def test_status_is_deterministic(self):
        self.init()
        first = self.run_cli("status")[1]
        second = self.run_cli("status")[1]
        self.assertEqual(first, second)

    def test_status_exits_zero_when_degraded(self):
        """Degraded is a state to report, not a command failure."""
        self.engram = False
        self.cbm = False
        self.init()
        code, out, err = self.run_cli("status")
        self.assertEqual(code, EXIT_OK, err)
        self.assertIn("UNAVAILABLE", out)

    def test_status_json(self):
        self.init()
        code, out, _ = self.run_cli("status", "--json")
        self.assertEqual(code, EXIT_OK)
        payload = json.loads(out)
        self.assertTrue(payload["project_id"].startswith("rlk_"))
        self.assertIn("components", payload)
        self.assertIn("capabilities", payload)

    def test_status_json_reflects_degraded_engram(self):
        self.engram = False
        self.init()
        payload = json.loads(self.run_cli("status", "--json")[1])
        self.assertFalse(payload["capabilities"]["memory"])
        self.assertFalse(payload["capabilities"]["handoffs"])
        self.assertIn("engram", payload["degraded"])


class DoctorTests(CLITestCase):
    def test_doctor_all_green_exits_zero(self):
        self.cbm = True
        self.init()
        code, out, err = self.run_cli("doctor")
        self.assertEqual(code, EXIT_OK, err)
        self.assertIn("Relinkra doctor", out)
        self.assertIn(PASS, out)
        self.assertIn("0 failed", out)

    def test_doctor_warns_before_init(self):
        code, out, _ = self.run_cli("doctor")
        self.assertEqual(code, EXIT_OK)
        self.assertIn(WARN, out)
        self.assertIn("relinkra init", out)

    def test_doctor_warns_on_missing_engram(self):
        self.engram = False
        self.init()
        code, out, _ = self.run_cli("doctor")
        self.assertEqual(code, EXIT_OK)
        self.assertIn(WARN, out)
        self.assertIn("Engram", out)
        self.assertIn("Suggested action", out)

    def test_doctor_missing_cbm_recommends_setup_on_certified_platform(self):
        """A fresh user (no CBM anywhere) must get the actionable command."""
        self.init()
        with mock.patch.object(
            product_cli.cbm_support, "platform_tag", return_value="windows-amd64"
        ):
            code, out, _ = self.run_cli("doctor")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("relinkra cbm setup", out)

    def test_doctor_missing_cbm_on_uncertified_platform_is_honest(self):
        self.init()
        with mock.patch.object(
            product_cli.cbm_support, "platform_tag", return_value="linux-amd64"
        ):
            code, out, _ = self.run_cli("doctor")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("No certified code-index release", out)
        self.assertNotIn("relinkra cbm setup", out)

    def test_doctor_fails_outside_a_repository(self):
        plain = Path(self.tmp.name) / "plain"
        plain.mkdir()
        code, out, _ = self.run_cli("doctor", path=plain)
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn(FAIL, out)
        self.assertIn("Git repository", out)

    def test_doctor_fails_on_a_corrupt_registry(self):
        self.init()
        product_cli.registry_path(self.root).write_text(
            "{ not valid json", encoding="utf-8"
        )
        code, out, _ = self.run_cli("doctor")
        self.assertEqual(code, EXIT_ACTION_REQUIRED)
        self.assertIn("Registry", out)
        self.assertIn(FAIL, out)

    def test_doctor_every_non_pass_check_is_actionable(self):
        self.engram = False
        code, out, _ = self.run_cli("doctor", "--json")
        payload = json.loads(out)
        for check in payload["checks"]:
            if check["status"] != PASS:
                self.assertTrue(
                    check["action"],
                    f"{check['name']} is {check['status']} with no action",
                )

    def test_doctor_json_summary_matches_checks(self):
        self.init()
        payload = json.loads(self.run_cli("doctor", "--json")[1])
        counts = {PASS: 0, WARN: 0, FAIL: 0}
        for check in payload["checks"]:
            counts[check["status"]] += 1
        self.assertEqual(payload["summary"]["pass"], counts[PASS])
        self.assertEqual(payload["summary"]["warn"], counts[WARN])
        self.assertEqual(payload["summary"]["fail"], counts[FAIL])
        self.assertEqual(payload["ok"], counts[FAIL] == 0)

    def test_doctor_self_audits_its_own_output(self):
        self.init()
        payload = json.loads(self.run_cli("doctor", "--json")[1])
        portable = [
            c for c in payload["checks"] if c["name"] == "Portable output"
        ]
        self.assertEqual(len(portable), 1)
        self.assertEqual(portable[0]["status"], PASS)

    def test_doctor_is_deterministic(self):
        self.init()
        self.assertEqual(
            self.run_cli("doctor")[1], self.run_cli("doctor")[1]
        )


class ProjectTests(CLITestCase):
    def test_project_requires_init(self):
        code, _, err = self.run_cli("project")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("not initialized", err)

    def test_project_reports_logical_identity(self):
        self.init()
        code, out, err = self.run_cli("project")
        self.assertEqual(code, EXIT_OK, err)
        self.assertIn("rlk_", out)
        self.assertIn("ws_", out)
        self.assertIn("Branch", out)
        self.assertIn("HEAD", out)

    def test_project_json(self):
        self.init()
        payload = json.loads(self.run_cli("project", "--json")[1])
        self.assertTrue(payload["project_id"].startswith("rlk_"))
        self.assertTrue(payload["workspace_id"].startswith("ws_"))
        self.assertEqual(len(payload["head_sha"]), 40)
        self.assertIn("detached", payload)
        self.assertIn("branch", payload)

    def test_project_reports_detached_head(self):
        self.init()
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.root,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        _git(self.root, "checkout", "-q", head)
        payload = json.loads(self.run_cli("project", "--json")[1])
        self.assertTrue(payload["detached"])

    def test_project_outside_a_repository_fails(self):
        plain = Path(self.tmp.name) / "plain"
        plain.mkdir()
        code, _, err = self.run_cli("project", path=plain)
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("not inside a git repository", err.lower())


class PortableOutputTests(CLITestCase):
    """No command may print a machine-local path."""

    def _forbidden(self):
        values = [str(self.root), str(self.root.resolve()), str(self.tmp.name)]
        home = os.path.expanduser("~")
        if home and len(home) > 6:
            values.append(home)
        return values

    def test_no_command_leaks_an_absolute_path(self):
        self.init()
        for argv in (
            ("init",), ("status",), ("doctor",), ("project",),
            ("init", "--json"), ("status", "--json"),
            ("doctor", "--json"), ("project", "--json"),
        ):
            _, out, err = self.run_cli(*argv)
            blob = out + err
            for value in self._forbidden():
                self.assertNotIn(
                    value, blob, f"{argv} leaked {value!r}"
                )

    def test_failure_messages_leak_no_path(self):
        plain = Path(self.tmp.name) / "plain"
        plain.mkdir()
        for argv in (("status",), ("project",), ("init",)):
            _, out, err = self.run_cli(*argv, path=plain)
            for value in self._forbidden():
                self.assertNotIn(value, out + err)

    def test_corrupt_registry_error_leaks_no_path(self):
        self.init()
        product_cli.registry_path(self.root).write_text(
            "{ bad", encoding="utf-8"
        )
        _, out, err = self.run_cli("doctor")
        for value in self._forbidden():
            self.assertNotIn(value, out + err)


class RenderingTests(CLITestCase):
    """Label columns must survive a label longer than the default width."""

    def test_long_labels_never_collide_with_their_value(self):
        rows = product_cli._aligned(
            [("Git intelligence", "OK"), ("MCP", "OK")]
        )
        for row in rows:
            label, _, value = row.partition("  ")
            self.assertTrue(
                row.startswith(label) and value.strip(),
                f"label and value collided: {row!r}",
            )
        self.assertTrue(all(row.rstrip().endswith("OK") for row in rows))
        # Every row shares one column, so values line up.
        starts = {row.index("OK") for row in rows}
        self.assertEqual(len(starts), 1)

    def test_init_output_has_no_collided_rows(self):
        out = self.init()
        for line in out.splitlines():
            for glyph in ("OK", "WARN", "FAIL"):
                if line.rstrip().endswith(glyph) and line.startswith(" ") is False:
                    label = line[: -len(glyph)]
                    self.assertTrue(
                        label.endswith(" "),
                        f"label ran into its value: {line!r}",
                    )

    def test_short_labels_still_use_the_minimum_width(self):
        rows = product_cli._aligned([("Git", "OK")])
        self.assertEqual(rows[0].index("OK"), product_cli._MIN_LABEL_WIDTH)


class ConfigTests(CLITestCase):
    def test_config_stores_no_absolute_path(self):
        self.init()
        raw = product_cli.config_path(self.root).read_text(encoding="utf-8")
        from relinkra.handoff import contains_absolute_path

        for value in json.loads(raw).values():
            if isinstance(value, str):
                self.assertFalse(contains_absolute_path(value))
        self.assertNotIn(str(self.root), raw)

    def test_config_round_trips(self):
        self.init()
        loaded = WorkspaceConfig.load(self.root)
        self.assertEqual(loaded.config_version, product_cli.CONFIG_VERSION)
        self.assertTrue(loaded.project_id.startswith("rlk_"))

    def test_unreadable_config_is_treated_as_absent(self):
        self.init()
        product_cli.config_path(self.root).write_text("{ bad", encoding="utf-8")
        self.assertIsNone(WorkspaceConfig.load(self.root))
        # And the CLI reports it as uninitialized rather than crashing.
        code, _, err = self.run_cli("status")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("not initialized", err)

    def test_stale_config_version_warns(self):
        self.init()
        path = product_cli.config_path(self.root)
        data = json.loads(path.read_text(encoding="utf-8"))
        data["config_version"] = 999
        path.write_text(json.dumps(data), encoding="utf-8")
        code, out, _ = self.run_cli("doctor")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Relinkra config", out)
        self.assertIn(WARN, out)


class CrossPlatformTests(unittest.TestCase):
    """Path semantics must not assume one operating system."""

    def test_config_paths_use_pathlib_not_separators(self):
        root = Path("some") / "workspace"
        self.assertEqual(
            product_cli.config_path(root),
            root / product_cli.CONFIG_DIR / product_cli.CONFIG_FILE,
        )
        self.assertEqual(
            product_cli.registry_path(root),
            root / product_cli.CONFIG_DIR / product_cli.REGISTRY_FILE,
        )

    def test_config_paths_render_with_the_native_separator(self):
        rendered = str(product_cli.config_path(Path("a") / "b"))
        self.assertIn(os.sep, rendered)
        self.assertTrue(rendered.endswith(product_cli.CONFIG_FILE))

    @unittest.skipUnless(_HAS_GIT, "git is required")
    def test_repo_root_walks_up_from_a_subdirectory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            nested = root / "src" / "deep" / "deeper"
            nested.mkdir(parents=True)
            _git(root, "init", "-q")
            found = product_cli._repo_root(str(nested))
            self.assertIsNotNone(found)
            self.assertEqual(found.resolve(), root.resolve())

    def test_repo_root_never_invents_a_root(self):
        """A temp dir may itself sit inside a checkout on some machines.

        So assert CONSISTENCY rather than None: a nested directory with
        no .git of its own must resolve to exactly what its parent
        resolves to. That holds whether or not an outer repository
        exists, and unlike an `if result is not None` guard it always
        executes a real assertion.
        """
        with tempfile.TemporaryDirectory() as tmp:
            outer = product_cli._repo_root(tmp)
            nested = Path(tmp) / "a" / "b" / "c"
            nested.mkdir(parents=True)
            self.assertEqual(product_cli._repo_root(str(nested)), outer)

    def test_repo_root_terminates_at_the_filesystem_root(self):
        """The upward walk must stop, on any platform."""
        anchor = Path(Path.cwd().anchor or os.sep)
        result = product_cli._repo_root(str(anchor))
        self.assertTrue(result is None or (result / ".git").exists())

    #: Every literal form a path separator can take in source. Checking
    #: only the double-quoted variants would let `'/'` or "\\" through.
    SEPARATOR_LITERALS = ('"/"', "'/'", '"\\\\"', "'\\\\'")

    def test_no_hardcoded_separators_in_the_module(self):
        source = Path(product_cli.__file__).read_text(encoding="utf-8")
        for number, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith('"'):
                continue
            for literal in self.SEPARATOR_LITERALS:
                self.assertNotIn(
                    literal,
                    stripped,
                    f"hardcoded separator {literal} at line {number}: {line}",
                )

    def test_the_separator_check_can_actually_fail(self):
        """Guard against the guard silently matching nothing."""
        for literal in self.SEPARATOR_LITERALS:
            sample = f"parts = value.split({literal})"
            self.assertIn(
                literal, sample, f"{literal!r} would never be detected"
            )


class TopLevelCliTests(unittest.TestCase):
    """Direct regressions for root argparse behavior."""

    @staticmethod
    def run_cli(argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = product_cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_version_flag_exits_zero_with_canonical_version(self):
        out, err = io.StringIO(), io.StringIO()
        with self.assertRaises(SystemExit) as caught:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                product_cli.main(["--version"])
        self.assertEqual(caught.exception.code, EXIT_OK)
        self.assertEqual(
            out.getvalue(), f"relinkra {product_cli.__version__}\n"
        )
        self.assertEqual(err.getvalue(), "")

    def test_help_flag_exits_zero_with_usage_and_commands(self):
        out, err = io.StringIO(), io.StringIO()
        with self.assertRaises(SystemExit) as caught:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                product_cli.main(["--help"])
        self.assertEqual(caught.exception.code, EXIT_OK)
        self.assertIn("usage: relinkra", out.getvalue())
        for command in ("init", "status", "doctor", "project", "cbm", "connect"):
            self.assertIn(command, out.getvalue())
        self.assertEqual(err.getvalue(), "")

    def test_bare_invocation_prints_help_and_returns_error(self):
        code, out, err = self.run_cli([])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("usage: relinkra", out)
        self.assertIn("init", out)
        self.assertEqual(err, "")

    def test_existing_version_command_dispatches(self):
        code, out, err = self.run_cli(["version"])
        self.assertEqual(code, EXIT_OK)
        self.assertTrue(out.startswith(f"relinkra {product_cli.__version__}\n"))
        self.assertEqual(err, "")

    def test_version_json_reports_external_provenance_boundary(self):
        code, out, err = self.run_cli(["version", "--json"])
        self.assertEqual(code, EXIT_OK, err)
        payload = json.loads(out)
        self.assertEqual(payload["relinkra_version"], "0.1.2")
        self.assertEqual(payload["install_mode"], "source")
        self.assertIsNone(payload["installed_metadata_version"])
        self.assertIsNone(payload["metadata_version_consistent"])
        provenance = payload["build_provenance"]
        self.assertIsNone(provenance["source_commit"])
        self.assertIsNone(provenance["artifact_sha256"])
        self.assertIn("external release-report evidence", provenance["statement"])
        self.assertNotIn(str(Path(__file__).resolve().parents[1]), out)

    def test_invalid_command_exits_one_with_argparse_error(self):
        out, err = io.StringIO(), io.StringIO()
        with self.assertRaises(SystemExit) as caught:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                product_cli.main(["not-a-command"])
        self.assertEqual(caught.exception.code, EXIT_ERROR)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("usage: relinkra", err.getvalue())
        self.assertIn("invalid choice", err.getvalue())


class ExitCodeContractTests(CLITestCase):
    """The documented exit-code contract, asserted end to end."""

    def test_success_is_zero(self):
        self.init()
        for argv in (("status",), ("project",), ("doctor",)):
            self.assertEqual(self.run_cli(*argv)[0], EXIT_OK, argv)

    def test_command_failure_is_one(self):
        plain = Path(self.tmp.name) / "plain"
        plain.mkdir()
        for argv in (("init",), ("status",), ("project",)):
            self.assertEqual(
                self.run_cli(*argv, path=plain)[0], EXIT_ERROR, argv
            )

    def test_doctor_failure_is_two(self):
        plain = Path(self.tmp.name) / "plain"
        plain.mkdir()
        self.assertEqual(
            self.run_cli("doctor", path=plain)[0], EXIT_ACTION_REQUIRED
        )

    def test_degraded_components_never_change_the_exit_code(self):
        self.engram = False
        self.cbm = False
        self.git_component = False
        self.init()
        self.assertEqual(self.run_cli("status")[0], EXIT_OK)
        self.assertEqual(self.run_cli("doctor")[0], EXIT_OK)
        self.assertEqual(self.run_cli("project")[0], EXIT_OK)

    def test_usage_errors_exit_one_not_two(self):
        """A typo must not look like 'needs a human decision' (2)."""
        for argv in (["nonsense"], ["status", "--bogus"], ["--bad"]):
            with self.assertRaises(SystemExit) as caught:
                with contextlib.redirect_stderr(io.StringIO()):
                    with contextlib.redirect_stdout(io.StringIO()):
                        product_cli.main(argv)
            self.assertEqual(
                caught.exception.code, EXIT_ERROR, f"argv={argv}"
            )

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = product_cli.main([])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("usage: relinkra", out.getvalue())
        self.assertEqual(err.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
