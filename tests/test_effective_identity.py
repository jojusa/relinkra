"""VIS-4-FIX-2 — effective legacy identity tests.

The pre-migration contract under test:

- a valid persisted registration for the current workspace is the
  EFFECTIVE identity, even when a stronger current Git derivation exists;
- the stronger derivation is disclosed as a live CANDIDATE;
- a mismatch exposes ``migration_available`` and the explicit
  ``relinkra init`` transition — nothing is aliased, replaced, or
  relabeled automatically;
- viewer status, doctor, metrics currentness, and context CLI validation
  all follow the one shared resolver;
- copied state, changed remotes, forks, and hand overrides never inherit
  another project's trust or produce a false CURRENT.

Fixtures are deterministic temp repositories with pinned commits and
dates (``git_fixtures``). CBM seams are mocked; no backend is executed.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.request
from copy import copy
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:  # discovery (`-s tests`) puts tests/ on sys.path; direct runs may not
    from tests import git_fixtures as gf
    from tests.test_product_cli import FakeProbeServices
except ImportError:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import git_fixtures as gf
    from test_product_cli import FakeProbeServices

from relinkra import context_cli, context_metrics, effective_identity, product_cli
from relinkra.engram_adapter import InMemoryStore
from relinkra.identity import (
    canonicalize_path,
    derive_project_id,
    derive_workspace_id,
    discover_repository_identity,
    git_head_sha,
    normalize_os_family,
    normalize_remote_url,
)
from relinkra.product_cli import WorkspaceConfig
from relinkra.registry import Registry

REMOTE = "https://github.com/org/legacy-repo.git"
REMOTE_CHANGED = "https://github.com/org/changed-repo.git"
REMOTE_OTHER = "https://github.com/other/unrelated-repo.git"
OLD_REVISION = "a" * 40


def live_project_id(path: str, remote: str | None = None) -> str:
    return derive_project_id(discover_repository_identity(str(path), remote).value)


class IdentityCase(unittest.TestCase):
    """Deterministic temp repositories and registration helpers."""

    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="rlk-effective-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.tmp = tmp

    # -- fixtures ---------------------------------------------------------

    def make_repo(self, name: str = "repo", *, remote: str | None = None) -> str:
        repo = gf.make_repo(os.path.join(self.tmp, name))
        gf.commit_file(repo, "README.md", f"# {name}\n", "init")
        if remote:
            gf.git(repo, "remote", "add", "origin", remote)
        return repo

    def register(self, repo: str) -> object:
        """Register the workspace as-is and pin it in the workspace config."""
        workspace = Registry(str(self.registry_path(repo))).register_workspace(
            repo, discover_repository_identity(repo)
        )
        self.write_config(repo, workspace.project_id, workspace.workspace_id)
        return workspace

    def legacy_repo(
        self, name: str = "legacy", *, remote: str = REMOTE
    ) -> tuple[str, object]:
        """Registered weak (local_root), then a strong remote appears."""
        repo = self.make_repo(name)
        workspace = self.register(repo)
        gf.git(repo, "remote", "add", "origin", remote)
        return repo, workspace

    def write_config(self, repo: str, project_id: str, workspace_id: str) -> None:
        WorkspaceConfig(
            project_id=project_id,
            workspace_id=workspace_id,
            initialized_at="2024-01-01T00:00:00+00:00",
        ).save(Path(repo))

    @staticmethod
    def registry_path(repo: str) -> Path:
        return product_cli.registry_path(Path(repo))

    # -- resolution helpers ------------------------------------------------

    def resolve(self, repo: str, registry=None):
        config = WorkspaceConfig.load(Path(repo))
        return effective_identity.resolve_effective_identity(
            repo,
            registry=registry,
            registry_path=(
                None if registry is not None else str(self.registry_path(repo))
            ),
            registered_project_id=(config.project_id if config else None) or None,
            registered_workspace_id=(config.workspace_id if config else None) or None,
        )

    @contextlib.contextmanager
    def fake_services(self, **kwargs):
        original = product_cli._services
        product_cli._services = lambda root, config: FakeProbeServices(**kwargs)
        try:
            yield
        finally:
            product_cli._services = original

    def run_cli(self, *argv) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = product_cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def viewer_status(self, repo: str) -> dict:
        with mock.patch.object(
            product_cli.cbm_support,
            "resolve_cbm_binary",
            lambda root=None, environ=None: None,
        ):
            return product_cli._viewer_status_payload(repo)

    def observation(self, project_id, workspace_id, revision, packet_id="pkt_x"):
        return context_metrics.extract_context_observation(
            {
                "packet_id": packet_id,
                "created_at": "2026-01-01T00:00:00+00:00",
                "project_id": project_id,
                "workspace_id": workspace_id,
                "project_facts": {"workspace": {"current_revision": revision}},
                "packet_status": {
                    "token_accounting": {
                        "total_estimated_tokens": 10,
                        "useful_payload_tokens": 8,
                        "metadata_tokens": 2,
                        "estimation_version": "cpt1.v1",
                        "accounting_basis": "utf8_envelope",
                    }
                },
            }
        )

    def snapshot_state(self, repo: str) -> dict:
        state = {}
        for name in ("registry.json", "config.json"):
            path = self.registry_path(repo).parent / name
            state[name] = path.read_bytes() if path.exists() else None
        return state


class ResolverTests(IdentityCase):
    """The shared resolver semantics, without any CLI or viewer."""

    def test_legacy_registered_identity_stays_effective(self):
        repo, workspace = self.legacy_repo()
        resolved = self.resolve(repo)

        self.assertEqual(resolved.registered_project_id, workspace.project_id)
        self.assertEqual(resolved.registered_workspace_id, workspace.workspace_id)
        self.assertEqual(resolved.live_project_id, live_project_id(repo))
        self.assertNotEqual(resolved.live_project_id, resolved.registered_project_id)
        self.assertEqual(resolved.effective_project_id, workspace.project_id)
        self.assertEqual(resolved.effective_workspace_id, workspace.workspace_id)
        self.assertEqual(
            resolved.identity_state,
            effective_identity.IDENTITY_STATE_MIGRATION_AVAILABLE,
        )
        self.assertTrue(resolved.migration_available)
        self.assertEqual(resolved.recommended_action, "relinkra init")

    def test_modern_strong_remote_registration_is_aligned(self):
        repo = self.make_repo("modern", remote=REMOTE)
        workspace = self.register(repo)
        resolved = self.resolve(repo)

        self.assertEqual(resolved.registered_project_id, workspace.project_id)
        self.assertEqual(resolved.live_project_id, workspace.project_id)
        self.assertEqual(resolved.effective_project_id, workspace.project_id)
        self.assertEqual(resolved.effective_workspace_id, workspace.workspace_id)
        self.assertEqual(
            resolved.identity_state, effective_identity.IDENTITY_STATE_REGISTERED
        )
        self.assertFalse(resolved.migration_available)
        self.assertIsNone(resolved.recommended_action)

    def test_no_registration_is_unregistered_and_never_invents_workspace(self):
        repo = self.make_repo("fresh", remote=REMOTE)
        resolved = self.resolve(repo)

        self.assertIsNone(resolved.registered_project_id)
        self.assertIsNone(resolved.registered_workspace_id)
        self.assertEqual(resolved.live_project_id, live_project_id(repo))
        self.assertEqual(resolved.effective_project_id, resolved.live_project_id)
        self.assertIsNone(resolved.effective_workspace_id)
        self.assertEqual(
            resolved.identity_state, effective_identity.IDENTITY_STATE_UNREGISTERED
        )
        self.assertFalse(resolved.migration_available)
        self.assertEqual(resolved.recommended_action, "relinkra init")

    def test_unresolvable_identity_is_unknown(self):
        resolved = effective_identity.resolve_effective_identity(
            os.path.join(self.tmp, "missing-directory")
        )
        self.assertEqual(
            resolved.identity_state, effective_identity.IDENTITY_STATE_UNKNOWN
        )
        self.assertIsNone(resolved.effective_project_id)

    def test_ambiguous_registrations_fail_closed(self):
        repo = self.make_repo("ambiguous", remote=REMOTE)
        workspace = self.register(repo)
        # Without a config pin to disambiguate, two workspace records for
        # the same canonical path are an unresolvable registration.
        (self.registry_path(repo).parent / "config.json").unlink()
        duplicate = Registry(str(self.registry_path(repo)))
        twin = copy(duplicate.workspaces[workspace.workspace_id])
        twin.workspace_id = "ws_" + "e" * 32
        duplicate.workspaces[twin.workspace_id] = twin
        duplicate.save()

        resolved = self.resolve(repo)
        self.assertIsNone(resolved.registered_project_id)
        self.assertIsNone(resolved.effective_project_id)
        self.assertEqual(
            resolved.identity_state, effective_identity.IDENTITY_STATE_UNKNOWN
        )

    def test_resolution_is_read_only(self):
        repo, _workspace = self.legacy_repo()
        before = self.snapshot_state(repo)
        self.resolve(repo)
        self.resolve(repo)
        self.assertEqual(self.snapshot_state(repo), before)

    def test_config_pin_to_another_workspace_is_not_an_attestation(self):
        """A caller assertion (hand override) is never an attestation."""
        repo1, workspace1 = self.legacy_repo("donor")
        repo2 = self.make_repo("override", remote=REMOTE_OTHER)
        self.write_config(repo2, workspace1.project_id, workspace1.workspace_id)

        resolved = self.resolve(repo2)
        self.assertIsNone(resolved.registered_project_id)
        self.assertEqual(
            resolved.identity_state, effective_identity.IDENTITY_STATE_UNREGISTERED
        )
        self.assertNotEqual(resolved.effective_project_id, workspace1.project_id)
        self.assertEqual(resolved.effective_project_id, live_project_id(repo2))

    def test_changed_remote_keeps_the_registered_identity_effective(self):
        repo, workspace = self.legacy_repo(remote=REMOTE)
        gf.git(repo, "remote", "set-url", "origin", REMOTE_CHANGED)

        resolved = self.resolve(repo)
        expected_live = derive_project_id(normalize_remote_url(REMOTE_CHANGED).value)
        self.assertEqual(resolved.registered_project_id, workspace.project_id)
        self.assertEqual(resolved.live_project_id, expected_live)
        self.assertEqual(resolved.effective_project_id, workspace.project_id)
        self.assertTrue(resolved.migration_available)

    def test_fork_like_second_checkout_never_inherits(self):
        repo, workspace = self.legacy_repo(remote=REMOTE)
        fork = os.path.join(self.tmp, "fork")
        gf.git(self.tmp, "clone", "-q", repo, fork)
        gf.git(fork, "remote", "set-url", "origin", REMOTE_OTHER)

        resolved = self.resolve(fork)
        self.assertIsNone(resolved.registered_project_id)
        self.assertNotEqual(resolved.effective_project_id, workspace.project_id)
        self.assertEqual(resolved.effective_project_id, live_project_id(fork))

    def test_same_remote_other_workspace_keeps_project_semantics(self):
        repo_a = self.make_repo("workspace-a", remote=REMOTE)
        repo_b = self.make_repo("workspace-b", remote=REMOTE)
        shared = Registry(os.path.join(self.tmp, "shared-registry.json"))
        ws_a = shared.register_workspace(repo_a, discover_repository_identity(repo_a))
        ws_b = shared.register_workspace(repo_b, discover_repository_identity(repo_b))

        self.assertEqual(ws_a.project_id, ws_b.project_id)
        self.assertNotEqual(ws_a.workspace_id, ws_b.workspace_id)

        resolved = self.resolve(repo_b, registry=shared)
        self.assertEqual(resolved.identity_state, "registered")
        self.assertEqual(resolved.effective_project_id, ws_a.project_id)
        self.assertEqual(resolved.effective_workspace_id, ws_b.workspace_id)
        self.assertEqual(
            resolved.effective_workspace_id, resolved.registered_workspace_id
        )

    def test_copied_state_registers_nothing_for_the_new_path(self):
        repo1, workspace1 = self.legacy_repo("origin-repo")
        repo2 = self.make_repo("unrelated", remote=REMOTE_OTHER)
        shutil.copytree(
            str(self.registry_path(repo1).parent),
            str(self.registry_path(repo2).parent),
        )

        resolved = self.resolve(repo2)
        self.assertIsNone(resolved.registered_project_id)
        self.assertEqual(
            resolved.identity_state, effective_identity.IDENTITY_STATE_UNREGISTERED
        )
        self.assertEqual(resolved.effective_project_id, live_project_id(repo2))
        self.assertNotEqual(resolved.effective_project_id, workspace1.project_id)

    def test_live_workspace_candidate_is_path_bound(self):
        repo, workspace = self.legacy_repo()
        resolved = self.resolve(repo)
        expected = derive_workspace_id(
            resolved.live_project_id,
            canonicalize_path(repo),
            normalize_os_family(sys.platform),
        )
        self.assertEqual(resolved.live_workspace_id, expected)
        self.assertNotEqual(resolved.live_workspace_id, workspace.workspace_id)


class ViewerStatusTests(IdentityCase):
    """Viewer status exposes effective/registered/live/migration truth."""

    def test_legacy_workspace_reports_the_registered_project_as_effective(self):
        repo, workspace = self.legacy_repo()
        payload = self.viewer_status(repo)
        project = payload["project"]

        self.assertEqual(project["project_id"], workspace.project_id)
        self.assertEqual(project["registered_project_id"], workspace.project_id)
        self.assertEqual(project["live_project_id"], live_project_id(repo))
        self.assertEqual(
            project["identity_state"], effective_identity.IDENTITY_STATE_MIGRATION_AVAILABLE
        )
        self.assertTrue(project["migration_available"])
        self.assertEqual(project["recommended_action"], "relinkra init")

        self.assertEqual(payload["workspace"]["workspace_id"], workspace.workspace_id)
        self.assertEqual(
            payload["workspace"]["registered_workspace_id"], workspace.workspace_id
        )
        self.assertEqual(
            payload["workspace"]["live_workspace_id"],
            derive_workspace_id(
                project["live_project_id"],
                canonicalize_path(repo),
                normalize_os_family(sys.platform),
            ),
        )

    def test_viewer_status_is_path_free(self):
        repo, _workspace = self.legacy_repo()
        text = json.dumps(self.viewer_status(repo), indent=2, sort_keys=True)
        self.assertNotIn(repo, text)
        self.assertNotIn(os.path.expanduser("~"), text)
        self.assertNotIn("\\", text)

    def test_modern_workspace_has_no_migration_warning(self):
        repo = self.make_repo("modern-viewer", remote=REMOTE)
        workspace = self.register(repo)
        payload = self.viewer_status(repo)
        project = payload["project"]

        self.assertEqual(project["project_id"], workspace.project_id)
        self.assertEqual(project["registered_project_id"], workspace.project_id)
        self.assertEqual(project["live_project_id"], workspace.project_id)
        self.assertEqual(project["identity_state"], "registered")
        self.assertFalse(project["migration_available"])
        self.assertIsNone(project["recommended_action"])
        self.assertTrue(payload["workspace"]["initialized"])


class DoctorTests(IdentityCase):
    """Doctor follows the same semantics and mutates nothing."""

    def test_doctor_discloses_the_candidate_without_mutating_state(self):
        repo, workspace = self.legacy_repo()
        before = self.snapshot_state(repo)

        with self.fake_services(engram=False, cbm=False, project=True):
            code, out, err = self.run_cli("doctor", "--path", repo, "--json")
        self.assertEqual(code, 0, err)
        payload = json.loads(out)

        identity = payload["identity"]
        self.assertEqual(identity["registered_project_id"], workspace.project_id)
        self.assertEqual(identity["live_project_id"], live_project_id(repo))
        self.assertEqual(identity["effective_project_id"], workspace.project_id)
        self.assertEqual(identity["identity_state"], "migration_available")
        self.assertTrue(identity["migration_available"])
        self.assertEqual(identity["recommended_action"], "relinkra init")

        row = next(
            check for check in payload["checks"] if check["name"] == "Project identity"
        )
        self.assertEqual(row["status"], "WARN")
        self.assertIn(workspace.project_id, row["detail"])
        self.assertIn("is effective", row["detail"])
        self.assertIn("migration candidate", row["detail"])
        self.assertIn("relinkra init", row["action"])

        self.assertEqual(self.snapshot_state(repo), before)

    def test_doctor_reports_a_modern_project_as_aligned(self):
        repo = self.make_repo("modern-doctor", remote=REMOTE)
        with self.fake_services(engram=False, cbm=False, project=True):
            self.run_cli("init", "--path", repo)
            code, out, err = self.run_cli("doctor", "--path", repo, "--json")
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["identity"]["identity_state"], "registered")
        self.assertFalse(payload["identity"]["migration_available"])
        row = next(
            check for check in payload["checks"] if check["name"] == "Project identity"
        )
        self.assertEqual(row["status"], "PASS")


class MetricsCurrentnessTests(IdentityCase):
    """CURRENT is only reachable through the effective identity."""

    def test_fresh_registered_observation_is_current(self):
        repo, workspace = self.legacy_repo()
        head = git_head_sha(repo)
        context_metrics.append_observation(
            repo,
            self.observation(workspace.project_id, workspace.workspace_id, head),
        )
        payload = product_cli._viewer_metrics_current_payload(repo)
        self.assertEqual(payload["currentness"], "current")

    def test_live_candidate_observation_is_foreign(self):
        repo, workspace = self.legacy_repo()
        head = git_head_sha(repo)
        live_pid = live_project_id(repo)
        live_wid = derive_workspace_id(
            live_pid, canonicalize_path(repo), normalize_os_family(sys.platform)
        )
        context_metrics.append_observation(
            repo, self.observation(live_pid, live_wid, head)
        )
        payload = product_cli._viewer_metrics_current_payload(repo)
        self.assertEqual(payload["currentness"], "foreign")
        self.assertNotEqual(payload["currentness"], "current")

    def test_history_classifies_each_row_without_relabeling(self):
        repo, workspace = self.legacy_repo()
        head = git_head_sha(repo)
        live_pid = live_project_id(repo)
        live_wid = derive_workspace_id(
            live_pid, canonicalize_path(repo), normalize_os_family(sys.platform)
        )
        context_metrics.append_observation(
            repo,
            self.observation(live_pid, live_wid, head, packet_id="pkt_live"),
        )
        context_metrics.append_observation(
            repo,
            self.observation(
                workspace.project_id, workspace.workspace_id, head,
                packet_id="pkt_current",
            ),
        )
        context_metrics.append_observation(
            repo,
            self.observation(
                workspace.project_id, workspace.workspace_id, OLD_REVISION,
                packet_id="pkt_stale",
            ),
        )
        rows = {
            row["packet_id"]: row
            for row in product_cli._viewer_metrics_history_payload(repo)["history"]
        }
        self.assertEqual(rows["pkt_live"]["currentness"], "foreign")
        self.assertEqual(rows["pkt_current"]["currentness"], "current")
        self.assertEqual(rows["pkt_stale"]["currentness"], "stale")

    def test_unresolved_identity_observation_is_unknown(self):
        repo = self.make_repo("unknown-identity", remote=REMOTE)
        context_metrics.append_observation(
            repo, self.observation(None, None, git_head_sha(repo))
        )
        payload = product_cli._viewer_metrics_current_payload(repo)
        self.assertEqual(payload["currentness"], "unknown")

    def test_copied_state_never_becomes_current(self):
        repo1, workspace1 = self.legacy_repo("copied-source")
        repo2 = self.make_repo("copied-target", remote=REMOTE_OTHER)
        shutil.copytree(
            str(self.registry_path(repo1).parent),
            str(self.registry_path(repo2).parent),
        )
        context_metrics.append_observation(
            repo2,
            self.observation(
                workspace1.project_id,
                workspace1.workspace_id,
                git_head_sha(repo2),
            ),
        )
        payload = product_cli._viewer_metrics_current_payload(repo2)
        self.assertEqual(payload["currentness"], "foreign")

    def test_fresh_context_cli_packet_becomes_current(self):
        """End-to-end: a legitimate packet from the legacy workspace is CURRENT."""
        repo, workspace = self.legacy_repo()
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = context_cli.main(
                [
                    "--project-id",
                    workspace.project_id,
                    "--workspace-id",
                    workspace.workspace_id,
                    "--registry",
                    str(self.registry_path(repo)),
                    "--workspace-root",
                    repo,
                    "--explain",
                    "--git",
                ],
                store=InMemoryStore(),
            )
        self.assertEqual(code, 0, err.getvalue())
        payload = product_cli._viewer_metrics_current_payload(repo)
        self.assertEqual(payload["currentness"], "current")
        self.assertEqual(
            payload["observation"]["identity"]["project_id"],
            workspace.project_id,
        )


class ViewerRouteTests(IdentityCase):
    """The real loopback status/metrics routes serve effective identity."""

    def test_status_and_metrics_routes_serve_effective_identity(self):
        repo, workspace = self.legacy_repo()
        head = git_head_sha(repo)
        context_metrics.append_observation(
            repo,
            self.observation(workspace.project_id, workspace.workspace_id, head),
        )
        served = {}

        def probe_real_routes(server):
            """Serve the real loopback socket, query it, then stop it.

            ``cmd_cbm_open`` owns the server and closes it after
            ``run_forever`` returns, so the probe must happen here.
            """
            thread = threading.Thread(
                target=server.serve_forever,
                kwargs={"poll_interval": 0.05},
                daemon=True,
            )
            thread.start()
            base = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                with urllib.request.urlopen(
                    base + "/api/status", timeout=15
                ) as response:
                    served["status"] = json.loads(response.read())
                with urllib.request.urlopen(
                    base + "/api/metrics/current", timeout=15
                ) as response:
                    served["metrics"] = json.loads(response.read())
            finally:
                server.shutdown()
                thread.join(10)

        with mock.patch.object(
            product_cli.viewer, "run_forever", probe_real_routes
        ), mock.patch.object(
            product_cli.cbm_support,
            "resolve_cbm_binary",
            lambda root=None, environ=None: None,
        ):
            code, _out, err = self.run_cli(
                "cbm", "open", "--path", repo, "--no-open", "--json"
            )
        self.assertEqual(code, 0, err)

        project = served["status"]["project"]
        self.assertEqual(project["project_id"], workspace.project_id)
        self.assertEqual(project["registered_project_id"], workspace.project_id)
        self.assertEqual(project["live_project_id"], live_project_id(repo))
        self.assertEqual(project["identity_state"], "migration_available")
        self.assertTrue(project["migration_available"])
        self.assertEqual(project["recommended_action"], "relinkra init")
        self.assertEqual(served["metrics"]["currentness"], "current")


class ContextCliValidationTests(IdentityCase):
    """Registry validation is preserved: registered accepted, candidate not."""

    def run_context(self, args) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = context_cli.main(args, store=InMemoryStore())
        return code, out.getvalue(), err.getvalue()

    def test_registered_effective_identity_is_accepted(self):
        repo, workspace = self.legacy_repo()
        code, out, err = self.run_context(
            [
                "--project-id",
                workspace.project_id,
                "--workspace-id",
                workspace.workspace_id,
                "--registry",
                str(self.registry_path(repo)),
            ]
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["project_id"], workspace.project_id)

    def test_unregistered_live_candidate_is_rejected(self):
        repo, _workspace = self.legacy_repo()
        code, _out, err = self.run_context(
            [
                "--project-id",
                live_project_id(repo),
                "--registry",
                str(self.registry_path(repo)),
            ]
        )
        self.assertEqual(code, 2)
        self.assertIn("not registered", err)


class RegistrationIntegrityTests(IdentityCase):
    """A persisted registration is re-derived, never trusted from its shape.

    Copied, malformed, and half-pinned records fail closed: they can never
    become the effective identity, and a workspace_id pin alone is never
    continuity proof.
    """

    def tamper_workspace(self, repo: str, mutate) -> None:
        """Mutate the registry record for ``repo`` and persist the tamper."""
        registry = Registry(str(self.registry_path(repo)))
        (workspace_id, workspace), = registry.workspaces.items()
        mutate(workspace)
        if workspace.workspace_id != workspace_id:
            del registry.workspaces[workspace_id]
            registry.workspaces[workspace.workspace_id] = workspace
        registry.save()

    def assert_failed_closed(self, resolved) -> None:
        self.assertIsNone(resolved.registered_project_id)
        self.assertIsNone(resolved.registered_workspace_id)
        self.assertIsNone(resolved.effective_project_id)
        self.assertIsNone(resolved.effective_workspace_id)
        self.assertEqual(
            resolved.identity_state, effective_identity.IDENTITY_STATE_UNKNOWN
        )
        self.assertFalse(resolved.migration_available)

    def test_workspace_id_must_re_derive_from_project_path_and_os(self):
        repo, _workspace = self.legacy_repo("rederive")
        self.tamper_workspace(
            repo, lambda ws: setattr(ws, "workspace_id", "ws_" + "d" * 32)
        )
        self.assert_failed_closed(self.resolve(repo))

    def test_workspace_id_re_derivation_fails_closed_without_a_pin(self):
        repo, _workspace = self.legacy_repo("rederive-nopin")
        self.tamper_workspace(
            repo, lambda ws: setattr(ws, "workspace_id", "ws_" + "e" * 32)
        )
        (self.registry_path(repo).parent / "config.json").unlink()
        self.assert_failed_closed(self.resolve(repo))

    def test_absolute_path_inconsistent_with_canonical_path_fails_closed(self):
        repo, _workspace = self.legacy_repo("bad-absolute")
        self.tamper_workspace(
            repo,
            lambda ws: setattr(
                ws, "absolute_path", os.path.join(self.tmp, "somewhere-else")
            ),
        )
        self.assert_failed_closed(self.resolve(repo))

    def test_canonical_path_of_another_directory_fails_closed(self):
        repo, _workspace = self.legacy_repo("bad-canonical")
        elsewhere = os.path.join(self.tmp, "other-directory")
        os.makedirs(elsewhere, exist_ok=True)
        self.tamper_workspace(
            repo,
            lambda ws: setattr(ws, "canonical_path", canonicalize_path(elsewhere)),
        )
        resolved = self.resolve(repo)
        self.assertIsNone(resolved.registered_project_id)
        self.assertIsNone(resolved.registered_workspace_id)
        self.assertIsNone(resolved.effective_workspace_id)
        self.assertEqual(
            resolved.identity_state, effective_identity.IDENTITY_STATE_UNREGISTERED
        )

    def test_os_family_mismatch_fails_closed(self):
        repo, _workspace = self.legacy_repo("os-mismatch")
        current = normalize_os_family(sys.platform)
        foreign = "linux" if current != "linux" else "windows"
        self.tamper_workspace(repo, lambda ws: setattr(ws, "os", foreign))
        self.assert_failed_closed(self.resolve(repo))

    def test_half_pinned_config_fails_closed(self):
        repo, workspace = self.legacy_repo("half-pin")
        self.write_config(repo, workspace.project_id, "")
        self.assert_failed_closed(self.resolve(repo))

    def test_copied_state_is_never_effective(self):
        repo1, workspace1 = self.legacy_repo("integrity-copy-source")
        repo2 = self.make_repo("integrity-copy-target", remote=REMOTE_OTHER)
        shutil.copytree(
            str(self.registry_path(repo1).parent),
            str(self.registry_path(repo2).parent),
        )
        resolved = self.resolve(repo2)
        self.assertIsNone(resolved.registered_project_id)
        self.assertNotEqual(resolved.effective_project_id, workspace1.project_id)
        self.assertNotEqual(resolved.effective_workspace_id, workspace1.workspace_id)
        self.assertEqual(resolved.effective_project_id, live_project_id(repo2))

    def test_valid_registration_still_resolves_after_integrity_checks(self):
        repo = self.make_repo("integrity-modern", remote=REMOTE)
        workspace = self.register(repo)
        resolved = self.resolve(repo)
        self.assertEqual(resolved.registered_project_id, workspace.project_id)
        self.assertEqual(resolved.registered_workspace_id, workspace.workspace_id)
        self.assertEqual(resolved.effective_project_id, workspace.project_id)
        self.assertEqual(resolved.effective_workspace_id, workspace.workspace_id)
        self.assertEqual(
            resolved.identity_state, effective_identity.IDENTITY_STATE_REGISTERED
        )


class PrivacyCanaryTests(IdentityCase):
    """A credential-bearing input never leaks into user-facing payloads.

    Canary: a real credentialed remote URL on the workspace, plus its raw
    components. Viewer status/metrics payloads and doctor JSON must not
    carry credentials, the raw remote URL, local-root canonical identity,
    absolute paths, or registry internals. Project IDs remain allowed.
    """

    CANARY_USER = "secret-canary"
    CANARY_TOKEN = "ghp_canary_token_do_not_leak"
    CREDENTIAL_REMOTE = (
        f"https://{CANARY_USER}:{CANARY_TOKEN}@github.com/org/private-repo.git"
    )
    #: Registry internals that must never cross a user-facing boundary.
    INTERNAL_KEYS = (
        "canonical_path",
        "absolute_path",
        "repository_identity",
        "last_seen_at",
        "registered_at",
    )
    IDENTITY_VALUES = ("remote://", "local-root://", "explicit://")

    def assert_no_credential(self, text: str) -> None:
        for canary in (self.CANARY_USER, self.CANARY_TOKEN, self.CREDENTIAL_REMOTE):
            self.assertNotIn(canary, text)

    def assert_no_private_leak(self, text: str, repo: str) -> None:
        self.assert_no_credential(text)
        self.assertNotIn(str(Path(repo)), text)
        self.assertNotIn(str(Path(repo).resolve()), text)
        self.assertNotIn(os.path.expanduser("~"), text)
        for value in self.IDENTITY_VALUES:
            self.assertNotIn(value, text)
        for key in self.INTERNAL_KEYS:
            self.assertNotIn(key, text)

    def doctor_payload(self, repo: str) -> dict:
        with self.fake_services(engram=False, cbm=False, project=True):
            code, out, err = self.run_cli("doctor", "--path", repo, "--json")
        self.assertEqual(code, 0, err)
        return json.loads(out)

    def test_credentialed_remote_never_reaches_viewer_or_doctor(self):
        repo = self.make_repo("canary-remote", remote=self.CREDENTIAL_REMOTE)
        workspace = self.register(repo)
        head = git_head_sha(repo)
        context_metrics.append_observation(
            repo,
            self.observation(workspace.project_id, workspace.workspace_id, head),
        )

        # Storage hygiene: the credential never lands in Relinkra state.
        # (The registry legitimately stores canonical paths; credentials
        # never, under any field.)
        registry_text = self.registry_path(repo).read_text(encoding="utf-8")
        config_text = (
            self.registry_path(repo).parent / "config.json"
        ).read_text(encoding="utf-8")
        for text in (registry_text, config_text):
            self.assert_no_credential(text)

        resolved = self.resolve(repo)
        self.assertEqual(resolved.identity_state, "registered")
        self.assert_no_private_leak(
            json.dumps(resolved.to_dict(), sort_keys=True), repo
        )

        status_text = json.dumps(self.viewer_status(repo), sort_keys=True)
        self.assert_no_private_leak(status_text, repo)
        self.assertIn(workspace.project_id, status_text)

        self.assert_no_private_leak(
            json.dumps(self.doctor_payload(repo), sort_keys=True), repo
        )
        self.assert_no_private_leak(
            json.dumps(
                product_cli._viewer_metrics_current_payload(repo), sort_keys=True
            ),
            repo,
        )
        self.assert_no_private_leak(
            json.dumps(
                product_cli._viewer_metrics_history_payload(repo), sort_keys=True
            ),
            repo,
        )

    def test_credential_input_is_sanitized_at_the_source(self):
        repo = self.make_repo("canary-input")
        discovered = discover_repository_identity(repo, self.CREDENTIAL_REMOTE)
        self.assertEqual(discovered.kind, "remote")
        self.assertTrue(discovered.credentials_removed)
        self.assertNotIn(self.CANARY_USER, discovered.value)
        self.assertNotIn(self.CANARY_TOKEN, discovered.value)

    def test_local_root_identity_is_not_disclosed(self):
        repo = self.make_repo("canary-weak")
        workspace = self.register(repo)
        identity = discover_repository_identity(repo)
        self.assertTrue(identity.value.startswith("local-root://"))
        context_metrics.append_observation(
            repo, self.observation(workspace.project_id, workspace.workspace_id, git_head_sha(repo))
        )
        for text in (
            json.dumps(self.viewer_status(repo), sort_keys=True),
            json.dumps(self.doctor_payload(repo), sort_keys=True),
            json.dumps(
                product_cli._viewer_metrics_current_payload(repo), sort_keys=True
            ),
        ):
            self.assert_no_private_leak(text, repo)


if __name__ == "__main__":
    unittest.main()
