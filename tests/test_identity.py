"""Deterministic, offline tests for Relinkra R1B logical project identity."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest

from relinkra.cbm import workspace_cbm_record
from relinkra import identity as identity_module
from relinkra.identity import (
    AmbiguousIdentityError,
    RepositoryIdentity,
    canonicalize_path,
    choose_remote,
    derive_project_id,
    derive_workspace_id,
    discover_repository_identity,
    git_root_commits,
    local_root_identity,
    normalize_remote_url,
    redact_url,
)
from relinkra.registry import Registry, RegistryError
from unittest import mock


class GitSubprocessBoundTests(unittest.TestCase):
    """identity._git must bound every git subprocess (R5B.18): a hung git
    child degrades to GitError instead of hanging the caller."""

    def test_timeout_is_passed_to_subprocess(self):
        with mock.patch.object(
            identity_module.subprocess, "run"
        ) as run_mock:
            run_mock.return_value = subprocess.CompletedProcess(
                args=["git"], returncode=0, stdout="ok\n", stderr=""
            )
            identity_module._git("repo", "rev-parse", "HEAD")
        _, kwargs = run_mock.call_args
        self.assertEqual(kwargs.get("timeout"), identity_module.GIT_TIMEOUT)

    def test_timeout_expired_becomes_git_error(self):
        with mock.patch.object(
            identity_module.subprocess, "run"
        ) as run_mock:
            run_mock.side_effect = subprocess.TimeoutExpired(
                cmd=["git"], timeout=identity_module.GIT_TIMEOUT
            )
            with self.assertRaises(identity_module.GitError) as ctx:
                identity_module._git("repo", "rev-parse", "HEAD")
        self.assertIn("timed out", str(ctx.exception))


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


class NormalizeRemoteUrlTests(unittest.TestCase):
    def test_https_normalization(self):
        ident = normalize_remote_url("https://github.com/org/repo.git")
        self.assertEqual(ident.value, "remote://git/github.com/org/repo")
        self.assertEqual(ident.kind, "remote")
        self.assertEqual(ident.trust, "strong")
        self.assertFalse(ident.credentials_removed)
        self.assertEqual(ident.original_scheme, "https")

    def test_ssh_git_at_normalization(self):
        ident = normalize_remote_url("git@github.com:org/repo.git")
        self.assertEqual(ident.value, "remote://git/github.com/org/repo")
        self.assertTrue(ident.credentials_removed)
        self.assertEqual(ident.original_scheme, "ssh")

    def test_ssh_scheme_normalization(self):
        ident = normalize_remote_url("ssh://git@github.com/org/repo.git")
        self.assertEqual(ident.value, "remote://git/github.com/org/repo")
        self.assertTrue(ident.credentials_removed)
        self.assertEqual(ident.original_scheme, "ssh")

    def test_dotgit_suffix_optional(self):
        with_git = normalize_remote_url("https://github.com/org/repo.git")
        without_git = normalize_remote_url("https://github.com/org/repo")
        self.assertEqual(with_git.value, without_git.value)

    def test_https_and_ssh_converge(self):
        https = normalize_remote_url("https://github.com/org/repo.git")
        ssh = normalize_remote_url("git@github.com:org/repo.git")
        self.assertEqual(https.value, ssh.value)
        self.assertEqual(
            derive_project_id(https.value), derive_project_id(ssh.value)
        )

    def test_gitlab_equivalent(self):
        https = normalize_remote_url("https://gitlab.com/group/sub/repo.git")
        ssh = normalize_remote_url("git@gitlab.com:group/sub/repo.git")
        self.assertEqual(https.value, "remote://git/gitlab.com/group/sub/repo")
        self.assertEqual(https.value, ssh.value)

    def test_generic_host_preserves_path_case(self):
        ident = normalize_remote_url("https://git.example.com/Org/Repo.git")
        self.assertEqual(ident.value, "remote://git/git.example.com/Org/Repo")

    def test_known_host_lowercases_path(self):
        ident = normalize_remote_url("https://github.com/Org/Repo.git")
        self.assertEqual(ident.value, "remote://git/github.com/org/repo")

    def test_default_ports_removed(self):
        ident = normalize_remote_url("https://github.com:443/org/repo.git")
        self.assertEqual(ident.value, "remote://git/github.com/org/repo")
        ident_ssh = normalize_remote_url("ssh://git@github.com:22/org/repo.git")
        self.assertEqual(ident_ssh.value, "remote://git/github.com/org/repo")
        custom = normalize_remote_url("https://git.example.com:8443/org/repo.git")
        self.assertEqual(custom.value, "remote://git/git.example.com:8443/org/repo")

    def test_credential_stripping(self):
        ident = normalize_remote_url("https://user:token@example.com/org/repo.git")
        self.assertEqual(ident.value, "remote://git/example.com/org/repo")
        self.assertTrue(ident.credentials_removed)
        self.assertNotIn("token", ident.value)
        self.assertNotIn("user", ident.value)
        self.assertNotIn("@", ident.value)

    def test_malformed_remotes_rejected(self):
        for bad in (
            "",
            "   ",
            "https://",
            "https://github.com",
            "https://github.com/",
            "git@github.com",
            "ftp://github.com/org/repo.git",
            "not-a-url",
        ):
            with self.assertRaises(ValueError, msg=bad):
                normalize_remote_url(bad)

    def test_non_numeric_port_rejected(self):
        for bad in (
            "https://github.com:abc/org/repo",
            "https://user:secret@github.com:abc/org/repo",
            "ssh://git@github.com:twentytwo/org/repo.git",
        ):
            with self.assertRaises(ValueError, msg=bad):
                normalize_remote_url(bad)

    def test_error_messages_never_echo_credentials(self):
        secret = "s3cr3t-t0k3n"
        cases = (
            f"https://user:{secret}@github.com:abc/org/repo",  # bad port
            f"https://user:{secret}@",  # no host after userinfo
            f"https://user:{secret}@github.com",  # no path
        )
        for bad in cases:
            with self.assertRaises(ValueError, msg=bad) as ctx:
                normalize_remote_url(bad)
            message = str(ctx.exception)
            self.assertNotIn(secret, message)
            self.assertNotIn("user:", message)
            self.assertNotIn("@", message)

    def test_redact_url_helper(self):
        self.assertEqual(
            redact_url("https://user:token@github.com/org/repo.git"),
            "https://github.com/org/repo.git",
        )
        self.assertEqual(
            redact_url("git@github.com:org/repo.git"),
            "github.com:org/repo.git",
        )
        self.assertEqual(
            redact_url("https://github.com/org/repo.git"),
            "https://github.com/org/repo.git",
        )

    def test_redact_url_redacts_all_userinfo_forms(self):
        secret = "s3cr3t-t0k3n"
        cases = (
            f"https://user:{secret}@github.com/org/repo.git",
            f"http://user:{secret}@github.com/org/repo.git",
            f"ssh://user:{secret}@github.com/org/repo.git",
            f"git+ssh://user:{secret}@github.com/org/repo.git",
            f"user:{secret}@github.com:org/repo",  # scp-like with password
            f"{secret}@github.com:org/repo",  # scp-like, token as user
            f"https://user:p@{secret}@github.com/org/repo",  # @ inside userinfo
        )
        for raw in cases:
            with self.subTest(raw=raw):
                redacted = redact_url(raw)
                self.assertNotIn(secret, redacted)
                self.assertNotIn("@", redacted)

    def test_redact_url_scp_like_userinfo_with_password(self):
        self.assertEqual(
            redact_url("user:pass@github.com:org/repo"),
            "github.com:org/repo",
        )

    def test_redact_url_strips_query_and_fragment(self):
        secret = "s3cr3t-t0k3n"
        for raw in (
            f"https://github.com/org/repo?access_token={secret}",
            f"https://user:{secret}@github.com/org/repo?access_token={secret}",
            f"git@github.com:org/repo#{secret}",
        ):
            with self.subTest(raw=raw):
                self.assertNotIn(secret, redact_url(raw))

    def test_redact_url_never_returns_unredacted_at(self):
        # Inputs whose userinfo cannot be parsed must not come back unchanged.
        for raw in ("foo bar@baz", "/path/only@weird", "@github.com:org/repo"):
            with self.subTest(raw=raw):
                redacted = redact_url(raw)
                self.assertNotIn("@", redacted)
                self.assertNotEqual(redacted, raw)

    def test_redact_url_non_string(self):
        self.assertEqual(redact_url(None), "<unprintable remote URL>")

    def test_whitespace_and_control_chars_rejected(self):
        for bad in (
            "https://github.com/org/re po.git",
            "https://github.com/org/re\tpo.git",
            "https://github.com/org/re\npo.git",
            "https://git hub.com/org/repo.git",
            "https://github.com/org/re\x01po.git",
            "https://github.com/org/re\x7fpo.git",
            "git@github.com:org/re po",
            "git@github.com:org/re\x0bpo",
        ):
            with self.assertRaises(ValueError, msg=bad):
                normalize_remote_url(bad)

    def test_query_and_fragment_rejected_without_leaking_token(self):
        secret = "s3cr3t-t0k3n"
        for bad in (
            f"https://github.com/org/repo?access_token={secret}",
            f"https://user:{secret}@github.com/org/repo?access_token={secret}",
            f"git@github.com:org/repo?token={secret}",
            f"https://github.com/org/repo#{secret}",
        ):
            with self.assertRaises(ValueError, msg=bad) as ctx:
                normalize_remote_url(bad)
            self.assertNotIn(secret, str(ctx.exception))

    def test_normalized_values_match_registry_load_regex(self):
        # Every value normalize_remote_url can emit must survive a registry
        # save/load round-trip (load-time validation must never reject it).
        urls = (
            "https://github.com/org/repo.git",
            "git@github.com:org/repo.git",
            "ssh://git@github.com:2222/org/repo.git",
            "https://git.example.com:8443/Org/Repo.git",
            "https://user:token@gitlab.com/group/sub/repo.git",
        )
        with tempfile.TemporaryDirectory() as tmp:
            registry_path = os.path.join(tmp, "registry.json")
            registry = Registry(registry_path)
            for i, url in enumerate(urls):
                identity = normalize_remote_url(url)
                registry.register_workspace(
                    os.path.join(tmp, f"ws{i}"), identity
                )
            reloaded = Registry(registry_path)
            distinct = {normalize_remote_url(u).value for u in urls}
            self.assertEqual(len(reloaded.projects), len(distinct))

    def test_choose_remote_priority(self):
        remotes = {"upstream": "https://github.com/org/repo.git", "origin": "git@github.com:me/repo.git"}
        name, _ = choose_remote(remotes)
        self.assertEqual(name, "origin")
        name, _ = choose_remote({"upstream": "u", "zzz": "z"})
        self.assertEqual(name, "upstream")
        name, _ = choose_remote({"beta": "b", "alpha": "a"})
        self.assertEqual(name, "alpha")


class ProjectIdTests(unittest.TestCase):
    def test_fork_vs_upstream_distinct(self):
        fork = normalize_remote_url("git@github.com:me/repo.git")
        upstream = normalize_remote_url("git@github.com:org/repo.git")
        self.assertNotEqual(fork.value, upstream.value)
        self.assertNotEqual(
            derive_project_id(fork.value), derive_project_id(upstream.value)
        )

    def test_project_id_format_and_stability(self):
        pid = derive_project_id("remote://git/github.com/org/repo")
        self.assertRegex(pid, r"^rlk_[0-9a-f]{32}$")
        self.assertEqual(pid, derive_project_id("remote://git/github.com/org/repo"))


class LocalRepoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.registry_path = os.path.join(self.root, "registry.json")

    def _register(self, registry, path, **kwargs):
        identity = discover_repository_identity(path)
        return identity, registry.register_workspace(path, identity, **kwargs)

    def test_local_only_repo_uses_root_commit_and_weak_trust(self):
        repo = os.path.join(self.root, "solo")
        _init_repo(repo)
        identity = discover_repository_identity(repo)
        self.assertEqual(identity.kind, "local_root")
        self.assertEqual(identity.trust, "weak")
        expected_root = _git(repo, "rev-list", "--max-parents=0", "HEAD")
        self.assertEqual(identity.value, f"local-root://{expected_root}")

    def test_fixture_ab_convergence(self):
        repo_a = os.path.join(self.root, "fixture-a")
        _init_repo(repo_a)
        repo_b = os.path.join(self.root, "fixture-b")
        _git(self.root, "clone", "-q", repo_a, repo_b)

        registry = Registry(self.registry_path)
        ident_a, ws_a = self._register(
            registry, repo_a, cbm=workspace_cbm_record(
                "proj-fixture-a", self.root, version="0.9.0"
            ).to_dict(),
        )
        ident_b, ws_b = self._register(
            registry, repo_b, allow_weak_merge=True,
            cbm=workspace_cbm_record("proj-fixture-b", self.root).to_dict(),
        )
        self.assertEqual(ident_a.kind, "local_root")  # clone origin is a local path
        self.assertEqual(ident_a.value, ident_b.value)
        self.assertEqual(ws_a.project_id, ws_b.project_id)
        self.assertNotEqual(ws_a.workspace_id, ws_b.workspace_id)
        self.assertEqual(len(registry.projects), 1)
        self.assertEqual(len(registry.workspaces), 2)
        # CBM path-derived identities stay distinct and unchanged
        self.assertNotEqual(ws_a.cbm["project_name"], ws_b.cbm["project_name"])
        self.assertNotEqual(ws_a.cbm["db_path"], ws_b.cbm["db_path"])

    def test_weak_merge_requires_flag(self):
        repo_a = os.path.join(self.root, "a")
        _init_repo(repo_a)
        repo_b = os.path.join(self.root, "b")
        _git(self.root, "clone", "-q", repo_a, repo_b)
        registry = Registry(self.registry_path)
        self._register(registry, repo_a)
        identity_b = discover_repository_identity(repo_b)
        with self.assertRaises(AmbiguousIdentityError):
            registry.register_workspace(repo_b, identity_b)

    def test_unrelated_same_dirname_no_collision(self):
        parent1 = os.path.join(self.root, "parent1", "repo")
        parent2 = os.path.join(self.root, "parent2", "repo")
        _init_repo(parent1)
        _init_repo(parent2)
        registry = Registry(self.registry_path)
        _, ws1 = self._register(registry, parent1)
        _, ws2 = self._register(registry, parent2, allow_weak_merge=True)
        self.assertNotEqual(ws1.project_id, ws2.project_id)
        self.assertNotEqual(ws1.workspace_id, ws2.workspace_id)
        self.assertEqual(len(registry.projects), 2)

    def test_same_head_sha_is_not_identity(self):
        fake_head = "f" * 40
        root_a, root_b = "a" * 40, "b" * 40
        ident_a = local_root_identity([root_a])
        ident_b = local_root_identity([root_b])
        registry = Registry(self.registry_path)
        ws_a = registry.register_workspace(
            os.path.join(self.root, "one"), ident_a,
            git={"branch": "main", "head_sha": fake_head},
        )
        ws_b = registry.register_workspace(
            os.path.join(self.root, "two"), ident_b,
            git={"branch": "main", "head_sha": fake_head},
        )
        self.assertNotEqual(ws_a.project_id, ws_b.project_id)
        self.assertEqual(ws_a.git["head_sha"], ws_b.git["head_sha"])
        self.assertNotIn(fake_head, ident_a.value)
        self.assertNotIn(fake_head, ident_b.value)

    def test_two_unrelated_local_no_remote_distinct(self):
        repo_a = os.path.join(self.root, "local-a")
        repo_b = os.path.join(self.root, "local-b")
        _init_repo(repo_a)
        _init_repo(repo_b)
        registry = Registry(self.registry_path)
        _, ws_a = self._register(registry, repo_a)
        _, ws_b = self._register(registry, repo_b, allow_weak_merge=True)
        self.assertNotEqual(ws_a.project_id, ws_b.project_id)

    def test_worktree_same_project_different_workspace(self):
        repo = os.path.join(self.root, "main-repo")
        _init_repo(repo)
        worktree = os.path.join(self.root, "wt-repo")
        _git(repo, "worktree", "add", "-q", "--detach", worktree)
        registry = Registry(self.registry_path)
        _, ws_main = self._register(registry, repo)
        _, ws_wt = self._register(registry, worktree, allow_weak_merge=True)
        self.assertEqual(ws_main.project_id, ws_wt.project_id)
        self.assertNotEqual(ws_main.workspace_id, ws_wt.workspace_id)

    def test_cross_platform_path_independence(self):
        identity = normalize_remote_url("https://github.com/org/example.git")
        pid = derive_project_id(identity.value)
        ws_win = derive_workspace_id(pid, r"c:\desarrollos\example", "windows")
        ws_linux = derive_workspace_id(pid, "/home/devin/example", "linux")
        self.assertNotEqual(ws_win, ws_linux)

        registry = Registry(self.registry_path)
        ws = registry.register_workspace(
            self.root, identity, os_family="Linux"
        )
        self.assertEqual(ws.project_id, pid)
        self.assertEqual(ws.os, "linux")


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.registry_path = os.path.join(self.root, "sub", "registry.json")

    def _write_registry(self):
        registry = Registry(self.registry_path)
        identity = normalize_remote_url("git@github.com:org/repo.git")
        registry.register_workspace(
            os.path.join(self.root, "ws1"), identity,
            git={"branch": "main", "head_sha": "c" * 40},
            cbm=workspace_cbm_record("proj", self.root, version="0.9.0", sha256="d" * 64).to_dict(),
        )
        return registry

    def test_persistence_reload(self):
        registry = self._write_registry()
        reloaded = Registry(self.registry_path)
        self.assertEqual(
            [p.to_dict() for p in reloaded.projects.values()],
            [p.to_dict() for p in registry.projects.values()],
        )
        self.assertEqual(
            [w.to_dict() for w in reloaded.workspaces.values()],
            [w.to_dict() for w in registry.workspaces.values()],
        )

    def test_atomic_write_leaves_valid_json_and_no_temp_files(self):
        self._write_registry()
        with open(self.registry_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["schema_version"], 1)
        leftovers = [
            f
            for f in os.listdir(os.path.dirname(self.registry_path))
            if f not in ("registry.json", "registry.json.lock")
        ]
        self.assertEqual(leftovers, [])

    def _load_raw(self, data):
        os.makedirs(os.path.dirname(self.registry_path), exist_ok=True)
        with open(self.registry_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        return Registry(self.registry_path)

    def _valid_doc(self):
        identity = normalize_remote_url("https://github.com/org/repo.git")
        pid = derive_project_id(identity.value)
        return {
            "schema_version": 1,
            "projects": {
                pid: {
                    "project_id": pid,
                    "display_name": "repo",
                    "repository_identity": identity.to_dict(),
                    "created_at": "2026-07-24T00:00:00+00:00",
                }
            },
            "workspaces": {},
        }

    def test_registry_rejects_malformed(self):
        with self.assertRaises(RegistryError):
            self._load_raw({"schema_version": 2, "projects": {}, "workspaces": {}})
        with self.assertRaises(RegistryError):
            self._load_raw({"schema_version": 1, "projects": [], "workspaces": {}})
        bad = self._valid_doc()
        proj = next(iter(bad["projects"].values()))
        proj["project_id"] = "not-a-valid-id"
        with self.assertRaises(RegistryError):
            self._load_raw(bad)
        bad = self._valid_doc()
        proj = next(iter(bad["projects"].values()))
        del proj["display_name"]
        with self.assertRaises(RegistryError):
            self._load_raw(bad)
        os.makedirs(os.path.dirname(self.registry_path), exist_ok=True)
        with open(self.registry_path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        with self.assertRaises(RegistryError):
            Registry(self.registry_path)

    def test_registry_rejects_credential_containing_stored_json(self):
        bad = self._valid_doc()
        proj = next(iter(bad["projects"].values()))
        proj["repository_identity"]["value"] = "remote://git/user:token@github.com/org/repo"
        with self.assertRaises(RegistryError):
            self._load_raw(bad)

        bad = self._valid_doc()
        proj = next(iter(bad["projects"].values()))
        proj["repository_identity"]["value"] = "remote://git/github.com/org/repo@evil"
        with self.assertRaises(RegistryError):
            self._load_raw(bad)

    def test_registry_error_messages_do_not_echo_stored_values(self):
        secret = "s3cr3t-t0k3n"
        bad = self._valid_doc()
        proj = next(iter(bad["projects"].values()))
        proj["repository_identity"]["value"] = (
            f"remote://git/user:{secret}@github.com/org/repo"
        )
        with self.assertRaises(RegistryError) as ctx:
            self._load_raw(bad)
        message = str(ctx.exception)
        self.assertNotIn(secret, message)
        self.assertNotIn("user:", message)
        self.assertNotIn("@", message)

        bad = self._valid_doc()
        proj = next(iter(bad["projects"].values()))
        proj["repository_identity"]["value"] = (
            f"remote://git/github.com/org/repo?access_token={secret}"
        )
        with self.assertRaises(RegistryError) as ctx:
            self._load_raw(bad)
        self.assertNotIn(secret, str(ctx.exception))

    def test_sanitize_remote_for_storage_error_is_credential_free(self):
        secret = "s3cr3t-t0k3n"
        identity = RepositoryIdentity(
            kind="remote",
            value=f"remote://git/user:{secret}@github.com/org/repo",
            trust="strong",
        )
        registry = Registry(self.registry_path)
        with self.assertRaises(ValueError) as ctx:
            registry.register_workspace(
                os.path.join(self.root, "ws"), identity
            )
        message = str(ctx.exception)
        self.assertNotIn(secret, message)
        self.assertNotIn("user:", message)
        self.assertNotIn("@", message)


class Sha256RootIdentityTests(unittest.TestCase):
    def test_sha1_and_sha256_roots_accepted(self):
        sha1 = "a" * 40
        sha256 = "b" * 64
        ident1 = local_root_identity([sha1])
        self.assertEqual(ident1.value, f"local-root://{sha1}")
        ident2 = local_root_identity([sha256])
        self.assertEqual(ident2.value, f"local-root://{sha256}")

    def test_invalid_sha_lengths_rejected(self):
        for bad in ("a" * 39, "a" * 41, "a" * 63, "a" * 65, "g" * 40, "Z" * 64):
            with self.assertRaises(ValueError, msg=bad):
                local_root_identity([bad])

    def test_registry_validates_sha256_local_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry = Registry(os.path.join(tmp, "registry.json"))
            ws = registry.register_workspace(
                os.path.join(tmp, "ws"), local_root_identity(["c" * 64])
            )
            reloaded = Registry(os.path.join(tmp, "registry.json"))
            self.assertEqual(
                reloaded.workspaces[ws.workspace_id].project_id, ws.project_id
            )


class CanonicalizePathTests(unittest.TestCase):
    def test_symlink_resolves_to_same_canonical_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = os.path.join(tmp, "real-repo")
            os.makedirs(real)
            link = os.path.join(tmp, "link-repo")
            try:
                os.symlink(real, link, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            self.assertEqual(canonicalize_path(link), canonicalize_path(real))

    def test_dotdot_and_case_normalization(self):
        with tempfile.TemporaryDirectory() as tmp:
            sub = os.path.join(tmp, "sub")
            os.makedirs(sub)
            self.assertEqual(
                canonicalize_path(os.path.join(sub, "..")), canonicalize_path(tmp)
            )


class DiscoverMalformedRemoteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.repo = os.path.join(self.root, "repo")
        _init_repo(self.repo)

    def test_schemeless_host_path_remote_raises(self):
        _git(self.repo, "remote", "add", "origin", "github.com/org/repo")
        with self.assertRaises(ValueError) as ctx:
            discover_repository_identity(self.repo)
        self.assertIn("malformed or unsupported", str(ctx.exception))

    def test_unsupported_scheme_remote_raises(self):
        _git(self.repo, "remote", "add", "origin", "ftp://github.com/org/repo.git")
        with self.assertRaises(ValueError) as ctx:
            discover_repository_identity(self.repo)
        self.assertIn("malformed or unsupported", str(ctx.exception))

    def test_malformed_remote_error_is_credential_free(self):
        secret = "s3cr3t-t0k3n"
        with self.assertRaises(ValueError) as ctx:
            discover_repository_identity(
                self.repo, remote_url=f"https://user:{secret}@github.com:abc/org/repo"
            )
        message = str(ctx.exception)
        self.assertNotIn(secret, message)
        self.assertNotIn("@", message)

    def test_file_scheme_remote_falls_back_to_local_root(self):
        other = os.path.join(self.root, "other")
        _init_repo(other)
        _git(self.repo, "remote", "add", "origin", f"file://{other}")
        identity = discover_repository_identity(self.repo)
        self.assertEqual(identity.kind, "local_root")
        self.assertEqual(identity.trust, "weak")

    def test_local_path_remote_falls_back_to_local_root(self):
        other = os.path.join(self.root, "other")
        _init_repo(other)
        _git(self.repo, "remote", "add", "origin", other)
        identity = discover_repository_identity(self.repo)
        self.assertEqual(identity.kind, "local_root")

    def test_remote_url_override_malformed_raises(self):
        with self.assertRaises(ValueError):
            discover_repository_identity(self.repo, remote_url="github.com/org/repo")


class WeakReregistrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.registry_path = os.path.join(self.root, "registry.json")

    def test_same_weak_workspace_reregisters_without_ambiguity(self):
        repo = os.path.join(self.root, "solo")
        _init_repo(repo)
        identity = discover_repository_identity(repo)
        self.assertEqual(identity.trust, "weak")

        registry = Registry(self.registry_path)
        ws_first = registry.register_workspace(repo, identity)

        stale = "2000-01-01T00:00:00+00:00"
        registry.workspaces[ws_first.workspace_id].last_seen_at = stale

        ws_second = registry.register_workspace(repo, identity)
        self.assertEqual(ws_second.workspace_id, ws_first.workspace_id)
        self.assertEqual(ws_second.project_id, ws_first.project_id)
        self.assertNotEqual(ws_second.last_seen_at, stale)
        self.assertEqual(len(registry.projects), 1)
        self.assertEqual(len(registry.workspaces), 1)

    def test_different_weak_workspace_still_requires_consent(self):
        repo_a = os.path.join(self.root, "a")
        _init_repo(repo_a)
        repo_b = os.path.join(self.root, "b")
        _git(self.root, "clone", "-q", repo_a, repo_b)
        registry = Registry(self.registry_path)
        registry.register_workspace(repo_a, discover_repository_identity(repo_a))
        with self.assertRaises(AmbiguousIdentityError):
            registry.register_workspace(repo_b, discover_repository_identity(repo_b))

    def test_symlinked_path_is_same_workspace(self):
        repo = os.path.join(self.root, "real")
        _init_repo(repo)
        link = os.path.join(self.root, "link")
        try:
            os.symlink(repo, link, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        identity = discover_repository_identity(repo)
        registry = Registry(self.registry_path)
        ws_real = registry.register_workspace(repo, identity)
        ws_link = registry.register_workspace(link, identity)
        self.assertEqual(ws_real.workspace_id, ws_link.workspace_id)
        self.assertEqual(len(registry.workspaces), 1)


class RegistryLockTests(unittest.TestCase):
    def test_register_creates_lock_file_alongside_registry(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry_path = os.path.join(tmp, "registry.json")
            registry = Registry(registry_path)
            identity = normalize_remote_url("https://github.com/org/repo.git")
            registry.register_workspace(os.path.join(tmp, "ws"), identity)
            self.assertTrue(os.path.exists(registry_path + ".lock"))
            with open(registry_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["schema_version"], 1)


class StaleRegistryInstanceTests(unittest.TestCase):
    def test_two_stale_instances_both_registrations_survive(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry_path = os.path.join(tmp, "registry.json")
            # Both instances are constructed before either saves: each holds
            # a stale (empty) in-memory view of the registry.
            reg_a = Registry(registry_path)
            reg_b = Registry(registry_path)
            ident_a = normalize_remote_url("https://github.com/org/repo-a.git")
            ident_b = normalize_remote_url("https://github.com/org/repo-b.git")

            ws_a = reg_a.register_workspace(os.path.join(tmp, "a"), ident_a)
            ws_b = reg_b.register_workspace(os.path.join(tmp, "b"), ident_b)

            reloaded = Registry(registry_path)
            self.assertIn(ws_a.workspace_id, reloaded.workspaces)
            self.assertIn(ws_b.workspace_id, reloaded.workspaces)
            self.assertEqual(len(reloaded.projects), 2)
            self.assertEqual(len(reloaded.workspaces), 2)
            # reg_b must have merged reg_a's on-disk state, not clobbered it.
            self.assertIn(ws_a.workspace_id, reg_b.workspaces)

    def test_stale_instance_reregisters_existing_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry_path = os.path.join(tmp, "registry.json")
            identity = normalize_remote_url("https://github.com/org/repo.git")
            path = os.path.join(tmp, "ws")
            reg_a = Registry(registry_path)
            stale = Registry(registry_path)  # constructed before reg_a saves

            ws_first = reg_a.register_workspace(path, identity)
            ws_second = stale.register_workspace(path, identity)

            self.assertEqual(ws_second.workspace_id, ws_first.workspace_id)
            reloaded = Registry(registry_path)
            self.assertEqual(len(reloaded.projects), 1)
            self.assertEqual(len(reloaded.workspaces), 1)


if __name__ == "__main__":
    unittest.main()
