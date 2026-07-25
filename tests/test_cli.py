"""CLI end-to-end tests for Relinkra (register/list/show)."""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest

from relinkra.cli import main
from relinkra.identity import derive_project_id, normalize_remote_url


def _git(path, *args):
    r = subprocess.run(
        ["git", "-C", str(path), *args], capture_output=True, text=True, check=False
    )
    if r.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {r.stderr}")
    return r.stdout.strip()


def _init_repo(path):
    os.makedirs(path, exist_ok=True)
    _git(path, "init", "-q", "-b", "main")
    with open(os.path.join(path, "file.txt"), "w", encoding="utf-8") as fh:
        fh.write(f"content of {path}\n")
    _git(path, "add", ".")
    _git(
        path,
        "-c",
        "user.email=test@example.com",
        "-c",
        "user.name=Test",
        "commit",
        "-q",
        "-m",
        "initial",
    )


def _run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.registry = os.path.join(self.root, "registry.json")

    def test_register_list_show_roundtrip(self):
        repo = os.path.join(self.root, "solo")
        _init_repo(repo)

        code, out, err = _run_cli("register", repo, "--registry", self.registry)
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertIn("project", payload)
        self.assertIn("workspace", payload)
        workspace_id = payload["workspace"]["workspace_id"]
        project_id = payload["project"]["project_id"]
        self.assertEqual(payload["workspace"]["project_id"], project_id)

        code, out, err = _run_cli("list", "--registry", self.registry)
        self.assertEqual(code, 0, err)
        listed = json.loads(out)
        self.assertEqual([p["project_id"] for p in listed["projects"]], [project_id])
        self.assertEqual(
            [w["workspace_id"] for w in listed["workspaces"]], [workspace_id]
        )

        code, out, err = _run_cli("show", workspace_id, "--registry", self.registry)
        self.assertEqual(code, 0, err)
        shown = json.loads(out)
        self.assertEqual(shown["workspace"]["workspace_id"], workspace_id)
        self.assertEqual(shown["project"]["project_id"], project_id)

    def test_show_unknown_workspace_fails(self):
        code, out, err = _run_cli(
            "show", "ws_" + "0" * 32, "--registry", self.registry
        )
        self.assertEqual(code, 1)
        self.assertIn("unknown workspace_id", err)

    def test_ambiguous_weak_merge_exits_2(self):
        repo_a = os.path.join(self.root, "a")
        _init_repo(repo_a)
        repo_b = os.path.join(self.root, "b")
        _git(self.root, "clone", "-q", repo_a, repo_b)

        code, out, err = _run_cli("register", repo_a, "--registry", self.registry)
        self.assertEqual(code, 0, err)
        code, out, err = _run_cli("register", repo_b, "--registry", self.registry)
        self.assertEqual(code, 2)
        self.assertIn("weak local_root identity", err)
        code, out, err = _run_cli(
            "register", repo_b, "--registry", self.registry, "--allow-weak-merge"
        )
        self.assertEqual(code, 0, err)

    def test_remote_url_override_strong_identity(self):
        repo = os.path.join(self.root, "no-remote")
        _init_repo(repo)
        code, out, err = _run_cli(
            "register",
            repo,
            "--registry",
            self.registry,
            "--remote-url",
            "https://github.com/org/example.git",
        )
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        identity = payload["project"]["repository_identity"]
        self.assertEqual(identity["kind"], "remote")
        self.assertEqual(identity["trust"], "strong")
        self.assertEqual(
            identity["value"], "remote://git/github.com/org/example"
        )

    def test_stderr_is_credential_free_on_error(self):
        secret = "s3cr3t-t0k3n"
        repo = os.path.join(self.root, "solo")
        _init_repo(repo)
        code, out, err = _run_cli(
            "register",
            repo,
            "--registry",
            self.registry,
            "--remote-url",
            f"https://user:{secret}@github.com:abc/org/repo",
        )
        self.assertEqual(code, 1)
        self.assertNotIn(secret, err)
        self.assertNotIn(secret, out)
        self.assertNotIn("user:", err)

    def _write_credentialed_registry(self, secret):
        identity = normalize_remote_url("https://github.com/org/repo.git")
        pid = derive_project_id(identity.value)
        doc = {
            "schema_version": 1,
            "projects": {
                pid: {
                    "project_id": pid,
                    "display_name": "repo",
                    "repository_identity": {
                        **identity.to_dict(),
                        "value": f"remote://git/user:{secret}@github.com/org/repo",
                    },
                    "created_at": "2026-07-24T00:00:00+00:00",
                }
            },
            "workspaces": {},
        }
        with open(self.registry, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)

    def test_credentialed_registry_file_fails_json_without_secret(self):
        secret = "s3cr3t-t0k3n"
        repo = os.path.join(self.root, "solo")
        _init_repo(repo)
        self._write_credentialed_registry(secret)

        for argv in (
            ("list", "--registry", self.registry),
            ("register", repo, "--registry", self.registry),
            ("show", "ws_" + "0" * 32, "--registry", self.registry),
        ):
            with self.subTest(argv=argv):
                code, out, err = _run_cli(*argv)
                self.assertEqual(code, 1)
                self.assertNotIn(secret, err)
                self.assertNotIn(secret, out)
                self.assertNotIn("Traceback", err)
                payload = json.loads(err)  # error must be JSON, not a traceback
                self.assertIn("error", payload)

    def test_malformed_remote_url_override_exits_1(self):
        repo = os.path.join(self.root, "solo")
        _init_repo(repo)
        code, out, err = _run_cli(
            "register",
            repo,
            "--registry",
            self.registry,
            "--remote-url",
            "github.com/org/repo",
        )
        self.assertEqual(code, 1)
        self.assertIn("malformed or unsupported", err)

    def test_weak_reregistration_is_idempotent(self):
        repo = os.path.join(self.root, "solo")
        _init_repo(repo)
        code, out, err = _run_cli("register", repo, "--registry", self.registry)
        self.assertEqual(code, 0, err)
        first = json.loads(out)["workspace"]
        code, out, err = _run_cli("register", repo, "--registry", self.registry)
        self.assertEqual(code, 0, err)
        second = json.loads(out)["workspace"]
        self.assertEqual(first["workspace_id"], second["workspace_id"])
        self.assertEqual(first["project_id"], second["project_id"])

        code, out, err = _run_cli("list", "--registry", self.registry)
        self.assertEqual(code, 0, err)
        listed = json.loads(out)
        self.assertEqual(len(listed["projects"]), 1)
        self.assertEqual(len(listed["workspaces"]), 1)


if __name__ == "__main__":
    unittest.main()
