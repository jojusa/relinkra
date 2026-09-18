"""RIC-01/RIC-01B runtime evidence trust-boundary regressions."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from relinkra.backend_detection import build_trust_ladder
from relinkra.backend_policy import (
    ROUTE_MANAGED,
    STAGE_PROVEN,
    STAGE_REAL_HOST_LAUNCH,
    TRUST_UNVERIFIED,
)
from relinkra.identity import discover_repository_identity, git_head_sha
from relinkra.product_cli import WorkspaceConfig, registry_path
from relinkra.registry import Registry
from relinkra.runtime_evidence import (
    EVENT_MCP_SERVER_STARTED,
    EvidenceRecorder,
    host_evidence_path,
    revision_relation,
    runtime_stage_claims,
    summarize_runtime_evidence,
)


class _RIC01Fixture(unittest.TestCase):
    """Real git repositories, real registration, real evidence files.

    No trust decision is mocked: the tests exercise the shipped
    ``summarize_runtime_evidence``/``runtime_stage_claims`` pair and the
    real ``build_trust_ladder`` against disposable local projects.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="relinkra-ric01-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self._repo("repo")
        self.workspace = self._register(self.repo)
        self.revision = git_head_sha(str(self.repo))

    def _repo(self, name: str) -> Path:
        repo = self.root / name
        repo.mkdir()
        self._git(repo, "init", "-q")
        self._git(repo, "config", "user.email", "ric01@example.invalid")
        self._git(repo, "config", "user.name", "RIC-01")
        (repo / "README.md").write_text(name + "\n", encoding="utf-8")
        self._git(repo, "add", ".")
        self._git(repo, "commit", "-qm", "fixture")
        return repo

    @staticmethod
    def _git(repo: Path, *args: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        return result.stdout.strip()

    @staticmethod
    def _register(repo: Path):
        registry = Registry(str(registry_path(repo)))
        workspace = registry.register_workspace(
            str(repo), discover_repository_identity(str(repo))
        )
        WorkspaceConfig(
            project_id=workspace.project_id,
            workspace_id=workspace.workspace_id,
        ).save(repo)
        return workspace


class RIC01RuntimeEvidenceTests(_RIC01Fixture):
    """Evidence is current only when identity and complete HEAD both agree."""

    def test_exact_full_head_is_current_and_stamped_without_truncation(self):
        recorder = EvidenceRecorder(str(self.repo), "codex", revision=self.revision)
        self.assertTrue(recorder.record(EVENT_MCP_SERVER_STARTED))
        summary = summarize_runtime_evidence(str(self.repo), self.revision)
        host = summary["hosts"]["codex"]
        self.assertEqual(host["state"], "observed")
        self.assertEqual(host["revision_relation"], "current")
        self.assertEqual(host["revision"], self.revision)
        self.assertIn("server_started", runtime_stage_claims(summary))
        raw = json.loads(
            Path(host_evidence_path(str(self.repo), "codex")).read_text()
        )
        self.assertEqual(raw["events"][EVENT_MCP_SERVER_STARTED]["revision"], self.revision)
        self.assertEqual(
            raw["events"][EVENT_MCP_SERVER_STARTED]["project_id"],
            self.workspace.project_id,
        )

    def test_prefix_collision_and_legacy_short_revision_are_not_current(self):
        collision = self.revision[:12] + "0" * 28
        self.assertNotEqual(collision, self.revision)
        self.assertEqual(revision_relation(collision, self.revision), "older")
        self.assertEqual(revision_relation(self.revision[:12], self.revision), "unknown")
        recorder = EvidenceRecorder(str(self.repo), "codex", revision=self.revision[:12])
        self.assertTrue(recorder.record(EVENT_MCP_SERVER_STARTED))
        summary = summarize_runtime_evidence(str(self.repo), self.revision)
        self.assertNotIn("server_started", runtime_stage_claims(summary))
        self.assertEqual(summary["hosts"]["codex"]["revision"], self.revision[:12])

    def test_stale_complete_revision_remains_diagnostic_only(self):
        recorder = EvidenceRecorder(str(self.repo), "codex", revision="a" * 40)
        self.assertTrue(recorder.record(EVENT_MCP_SERVER_STARTED))
        summary = summarize_runtime_evidence(str(self.repo), self.revision)
        self.assertEqual(summary["hosts"]["codex"]["state"], "stale")
        self.assertNotIn("server_started", runtime_stage_claims(summary))

    def test_explicit_raw_ids_cannot_override_effective_resolution(self):
        unregistered = self._repo("unregistered")
        summary = summarize_runtime_evidence(
            str(unregistered),
            git_head_sha(str(unregistered)),
            current_project_id=self.workspace.project_id,
            current_workspace_id=self.workspace.workspace_id,
        )
        self.assertEqual(summary["current_project_id"], "")
        self.assertEqual(summary["current_workspace_id"], "")

    def test_copied_config_registry_and_evidence_are_not_relabelled(self):
        # Seed the source before copying all state, matching the Daybreak
        # repro: the destination receives config, registry, and evidence.
        recorder = EvidenceRecorder(str(self.repo), "codex", revision=self.revision)
        self.assertTrue(recorder.record(EVENT_MCP_SERVER_STARTED))
        unrelated = self._repo("unrelated")
        shutil.copytree(self.repo / ".relinkra", unrelated / ".relinkra")
        summary = summarize_runtime_evidence(
            str(unrelated), git_head_sha(str(unrelated))
        )
        self.assertNotEqual(summary["identity_state"], "effective")
        self.assertNotIn("server_started", runtime_stage_claims(summary))
        self.assertNotEqual(summary["hosts"]["codex"]["state"], "observed")

    def test_malformed_config_makes_current_identity_unknown(self):
        config = self.repo / ".relinkra" / "config.json"
        config.write_text("{malformed", encoding="utf-8")
        recorder = EvidenceRecorder(str(self.repo), "codex", revision=self.revision)
        self.assertTrue(recorder.record(EVENT_MCP_SERVER_STARTED))
        summary = summarize_runtime_evidence(str(self.repo), self.revision)
        self.assertEqual(summary["identity_state"], "unknown")
        self.assertNotIn("server_started", runtime_stage_claims(summary))


class RIC01BBackendDetectionTests(_RIC01Fixture):
    """RIC-01B: historical evidence attests only the certified identity.

    The exact Daybreak BACKEND_DETECTION reproduction lives here: copied
    runtime evidence must not prove ``STAGE_REAL_HOST_LAUNCH`` in the
    destination workspace, while the same-identity historical diagnostic
    keeps working. Observation is not attestation.
    """

    def _record_launch(self, repo: Path, revision: str) -> Path:
        recorder = EvidenceRecorder(str(repo), "codex", revision=revision)
        self.assertTrue(recorder.record(EVENT_MCP_SERVER_STARTED))
        return Path(host_evidence_path(str(repo), "codex"))

    @staticmethod
    def _copy_evidence(source: Path, dest: Path) -> Path:
        target = Path(host_evidence_path(str(dest), "codex"))
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        return target

    @staticmethod
    def _tamper_identity(evidence: Path, **fields: str) -> None:
        data = json.loads(evidence.read_text(encoding="utf-8"))
        event = data["events"][EVENT_MCP_SERVER_STARTED]
        event.update({key: value for key, value in fields.items() if value})
        evidence.write_text(json.dumps(data), encoding="utf-8")

    def _summary(self, repo: Path) -> dict:
        return summarize_runtime_evidence(str(repo), git_head_sha(str(repo)))

    def _launch_stage(self, repo: Path, summary: dict):
        ladder = build_trust_ladder(
            [],
            launch_resolved=True,
            relinkra_registered=True,
            route=ROUTE_MANAGED,
            metrics_trust=TRUST_UNVERIFIED,
            bypass_detected=False,
            handoffs_available=None,
            tools_declared=0,
            real_host_launch_proven=False,
            workspace_root=str(repo),
            current_revision=git_head_sha(str(repo)),
            runtime_evidence=summary,
        )
        return ladder.by_stage()[STAGE_REAL_HOST_LAUNCH]

    def _assert_not_attested(self, repo: Path, summary: dict) -> None:
        claims = runtime_stage_claims(summary)
        self.assertNotIn("server_started", claims)
        self.assertNotIn("server_started_historical", claims)
        stage = self._launch_stage(repo, summary)
        self.assertNotEqual(
            stage.state,
            STAGE_PROVEN,
            "copied/unresolved evidence must not prove the launch rung",
        )

    def test_copied_runtime_evidence_does_not_attest(self):
        evidence = self._record_launch(self.repo, self.revision)
        unrelated = self._repo("unrelated-evidence")
        self._copy_evidence(evidence, unrelated)
        summary = self._summary(unrelated)
        self.assertNotEqual(summary["identity_state"], "effective")
        self.assertTrue(summary["identity_resolution_attempted"])
        self._assert_not_attested(unrelated, summary)

    def test_copied_config_and_evidence_does_not_attest(self):
        evidence = self._record_launch(self.repo, self.revision)
        unrelated = self._repo("unrelated-config")
        (unrelated / ".relinkra").mkdir()
        shutil.copy2(
            self.repo / ".relinkra" / "config.json",
            unrelated / ".relinkra" / "config.json",
        )
        self._copy_evidence(evidence, unrelated)
        summary = self._summary(unrelated)
        self._assert_not_attested(unrelated, summary)

    def test_copied_full_state_does_not_attest(self):
        # The exact Daybreak BACKEND_DETECTION reproduction: a complete
        # ``.relinkra`` copy into an unrelated workspace. It fails on the
        # RIC-01B base revision (3ad912fd) and passes once historical
        # evidence is gated on the certified effective identity.
        evidence = self._record_launch(self.repo, self.revision)
        unrelated = self._repo("unrelated-full")
        shutil.copytree(self.repo / ".relinkra", unrelated / ".relinkra")
        summary = self._summary(unrelated)
        self.assertNotEqual(summary["identity_state"], "effective")
        self.assertEqual(summary["hosts"]["codex"]["state"], "unknown")
        self.assertTrue(summary["hosts"]["codex"]["events"], "evidence stays readable")
        self._assert_not_attested(unrelated, summary)

    def test_unresolved_identity_historical_evidence_is_diagnostic_only(self):
        unrelated = self._repo("unregistered")
        recorder = EvidenceRecorder(str(unrelated), "codex", revision="a" * 40)
        self.assertTrue(recorder.record(EVENT_MCP_SERVER_STARTED))
        summary = self._summary(unrelated)
        self.assertTrue(summary["identity_resolution_attempted"])
        self.assertEqual(summary["current_project_id"], "")
        self.assertEqual(summary["current_workspace_id"], "")
        self.assertEqual(summary["hosts"]["codex"]["state"], "unknown")
        self._assert_not_attested(unrelated, summary)

    def test_foreign_project_evidence_does_not_attest(self):
        registered = self._repo("registered-foreign-project")
        self._register(registered)
        evidence = self._record_launch(self.repo, self.revision)
        target = self._copy_evidence(evidence, registered)
        self._tamper_identity(target, project_id="rlk_" + "f" * 32)
        summary = self._summary(registered)
        self.assertEqual(summary["hosts"]["codex"]["state"], "foreign")
        self._assert_not_attested(registered, summary)

    def test_foreign_workspace_evidence_does_not_attest(self):
        registered = self._repo("registered-foreign-workspace")
        self._register(registered)
        evidence = self._record_launch(self.repo, self.revision)
        target = self._copy_evidence(evidence, registered)
        self._tamper_identity(target, workspace_id="ws_" + "f" * 32)
        summary = self._summary(registered)
        self.assertEqual(summary["hosts"]["codex"]["state"], "foreign")
        self._assert_not_attested(registered, summary)

    def test_same_identity_older_revision_stays_historical(self):
        recorder = EvidenceRecorder(str(self.repo), "codex", revision="a" * 40)
        self.assertTrue(recorder.record(EVENT_MCP_SERVER_STARTED))
        summary = summarize_runtime_evidence(str(self.repo), self.revision)
        claims = runtime_stage_claims(summary)
        self.assertNotIn("server_started", claims)
        self.assertIn("server_started_historical", claims)
        # The certified identity keeps its historical launch diagnostic.
        stage = self._launch_stage(self.repo, summary)
        self.assertEqual(stage.state, STAGE_PROVEN)
        self.assertIn("historical", stage.evidence)

    def test_legacy_short_revision_stays_historical_not_current(self):
        recorder = EvidenceRecorder(
            str(self.repo), "codex", revision=self.revision[:12]
        )
        self.assertTrue(recorder.record(EVENT_MCP_SERVER_STARTED))
        summary = summarize_runtime_evidence(str(self.repo), self.revision)
        self.assertEqual(summary["hosts"]["codex"]["revision"], self.revision[:12])
        claims = runtime_stage_claims(summary)
        self.assertNotIn("server_started", claims)
        self.assertIn("server_started_historical", claims)

    def test_exact_current_identity_and_revision_still_prove_launch(self):
        recorder = EvidenceRecorder(str(self.repo), "codex", revision=self.revision)
        self.assertTrue(recorder.record(EVENT_MCP_SERVER_STARTED))
        summary = summarize_runtime_evidence(str(self.repo), self.revision)
        claims = runtime_stage_claims(summary)
        self.assertIn("server_started", claims)
        self.assertNotIn("server_started_historical", claims)
        stage = self._launch_stage(self.repo, summary)
        self.assertEqual(stage.state, STAGE_PROVEN)
        self.assertIn("current revision", stage.evidence)


if __name__ == "__main__":
    unittest.main()
