"""RIC-01 runtime evidence trust-boundary regressions."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

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


class RIC01RuntimeEvidenceTests(unittest.TestCase):
    """Evidence is current only when identity and complete HEAD both agree."""

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


if __name__ == "__main__":
    unittest.main()
