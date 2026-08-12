"""Real-repository integration tests for R4D revision freshness.

These tests keep repository creation outside the production adapter, then
exercise the same read-only ``GitIntelligenceService`` and freshness resolver
used by context-building surfaces.  Mocking is limited to failure/timeout
injection and command-boundary inspection.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import relinkra.git_intelligence as gi
from relinkra.freshness import (
    FreshnessContext,
    FreshnessState,
    RevisionRelationState,
    evaluate_freshness,
)
from relinkra.git_intelligence import GitCommandError, GitIntelligenceService

try:  # discovery and package invocation use different import roots
    from tests import git_fixtures as gf
except ModuleNotFoundError:  # pragma: no cover - import-mode fallback
    import git_fixtures as gf


NOW = "2026-08-11T00:00:00+00:00"


def _tmp_dir(test: unittest.TestCase) -> str:
    path = tempfile.mkdtemp(prefix="relinkra-r4d-git-")
    test.addCleanup(lambda: shutil.rmtree(path, ignore_errors=True))
    return path


class R4DGitIntegrationTests(unittest.TestCase):
    def _repo(self) -> str:
        return gf.make_repo(os.path.join(_tmp_dir(self), "repo"))

    def _context(self, service: GitIntelligenceService, repo: str):
        state, warnings = service.collect_repository_state(repo)
        self.assertEqual(warnings, [])
        self.assertIsNotNone(state)
        return FreshnessContext(
            as_of=NOW,
            project_id="project",
            current_revision=state.head_sha,
            dirty=not state.clean,
        ), state

    def _freshness(
        self,
        service: GitIntelligenceService,
        repo: str,
        source_revision: str,
        *,
        max_distance: int = 100,
    ):
        context, state = self._context(service, repo)
        result = evaluate_freshness(
            "code",
            {"source_revision": source_revision},
            context,
            relation_resolver=lambda evidence, current: (
                service.collect_revision_relation(
                    repo, evidence, current, max_distance=max_distance
                )
            ),
        )
        return result, state

    def test_dirty_tree_makes_exact_revision_aging(self):
        repo = self._repo()
        head = gf.commit_file(repo, "alpha.py", "clean\n", "base")
        gf._write_file(repo, "alpha.py", "dirty\n")

        result, state = self._freshness(GitIntelligenceService(), repo, head)

        self.assertFalse(state.clean)
        self.assertEqual(result.state, FreshnessState.AGING)
        self.assertEqual(result.reason_code, "dirty_worktree_uncertainty")

    def test_non_repository_and_missing_git_degrade_to_unknown(self):
        plain = _tmp_dir(self)
        current = "a" * 40
        evidence = "b" * 40

        for service in (
            GitIntelligenceService(),
            GitIntelligenceService(
                runner=gi._GitRunner(
                    executable=os.path.join(plain, "missing-git-binary")
                )
            ),
        ):
            with self.subTest(executable=service._runner.executable):
                relation = service.collect_revision_relation(
                    plain, evidence, current
                )
                result = evaluate_freshness(
                    "code",
                    {"source_revision": evidence},
                    FreshnessContext(as_of=NOW, current_revision=current),
                    relation_resolver=lambda _e, _c, value=relation: value,
                )
                self.assertEqual(
                    relation.state, RevisionRelationState.UNAVAILABLE
                )
                self.assertEqual(result.state, FreshnessState.UNKNOWN)
                self.assertEqual(
                    result.reason_code, "revision_relation_unknown"
                )

    def test_detached_head_keeps_exact_revision_fresh(self):
        repo = self._repo()
        head = gf.commit_file(repo, "alpha.py", "alpha\n", "base")
        gf.git(repo, "checkout", "-q", "--detach", head)

        result, state = self._freshness(GitIntelligenceService(), repo, head)

        self.assertTrue(state.detached)
        self.assertIsNone(state.branch)
        self.assertEqual(result.state, FreshnessState.FRESH)
        self.assertEqual(result.reason_code, "same_revision")

    def test_one_old_revision_is_aging(self):
        repo = self._repo()
        old = gf.commit_file(repo, "alpha.py", "one\n", "one")
        current = gf.commit_file(repo, "alpha.py", "two\n", "two")
        service = GitIntelligenceService()

        relation = service.collect_revision_relation(repo, old, current)
        result, _state = self._freshness(service, repo, old)

        self.assertEqual(relation.state, RevisionRelationState.ANCESTOR)
        self.assertEqual(relation.distance, 1)
        self.assertTrue(relation.bounded)
        self.assertEqual(result.state, FreshnessState.AGING)
        self.assertEqual(result.revision_distance, 1)

    def test_many_old_revision_uses_bounded_timeout_protected_history(self):
        repo = self._repo()
        revisions = [
            gf.commit_file(repo, "alpha.py", "0\n", "commit 0")
        ]
        for index in range(1, 6):
            revisions.append(
                gf.commit_file(
                    repo, "alpha.py", f"{index}\n", f"commit {index}"
                )
            )
        service = GitIntelligenceService()

        with mock.patch.object(
            gi.subprocess, "run", wraps=gi.subprocess.run
        ) as run:
            relation = service.collect_revision_relation(
                repo, revisions[0], revisions[-1], max_distance=2
            )

        log_calls = [
            call
            for call in run.call_args_list
            if len(call.args[0]) > 1 and call.args[0][1] == "log"
        ]
        self.assertEqual(len(log_calls), 1)
        self.assertIn("--max-count=3", log_calls[0].args[0])
        self.assertEqual(log_calls[0].kwargs["timeout"], gi.GIT_TIMEOUT_SECONDS)
        self.assertEqual(relation.state, RevisionRelationState.ANCESTOR)
        self.assertEqual(relation.distance, 3)
        self.assertFalse(relation.bounded)

        result, _state = self._freshness(
            service, repo, revisions[0], max_distance=2
        )
        self.assertEqual(result.state, FreshnessState.STALE)

    def test_unrelated_revision_is_unknown(self):
        repo = self._repo()
        main = gf.commit_file(repo, "main.py", "main\n", "main")
        gf.git(repo, "checkout", "-q", "--orphan", "unrelated")
        gf.git(repo, "rm", "-q", "-f", "-r", "--", ".")
        unrelated = gf.commit_file(repo, "side.py", "side\n", "side")
        service = GitIntelligenceService()

        relation = service.collect_revision_relation(repo, main, unrelated)
        result, _state = self._freshness(service, repo, main)

        self.assertEqual(relation.state, RevisionRelationState.UNRELATED)
        self.assertEqual(result.state, FreshnessState.UNKNOWN)
        self.assertEqual(result.reason_code, "revision_relation_unknown")

    def test_descendant_revision_is_unknown(self):
        repo = self._repo()
        old = gf.commit_file(repo, "alpha.py", "old\n", "old")
        future = gf.commit_file(repo, "alpha.py", "future\n", "future")
        service = GitIntelligenceService()
        relation = service.collect_revision_relation(repo, future, old)

        result = evaluate_freshness(
            "code",
            {"source_revision": future},
            FreshnessContext(as_of=NOW, current_revision=old, dirty=False),
            relation_resolver=lambda _e, _c: relation,
        )

        self.assertEqual(relation.state, RevisionRelationState.DESCENDANT)
        self.assertEqual(relation.distance, 1)
        self.assertEqual(result.state, FreshnessState.UNKNOWN)
        self.assertEqual(result.reason_code, "revision_from_future")

    def test_shallow_missing_revision_is_marked_shallow_and_unknown(self):
        base = _tmp_dir(self)
        source = gf.make_repo(os.path.join(base, "source"))
        old = gf.commit_file(source, "alpha.py", "old\n", "old")
        gf.commit_file(source, "alpha.py", "middle\n", "middle")
        current = gf.commit_file(source, "alpha.py", "current\n", "current")
        shallow = os.path.join(base, "shallow")
        clone = gf.git(
            source,
            "clone",
            "-q",
            "--depth",
            "1",
            "--no-local",
            source,
            shallow,
            check=False,
        )
        if clone.returncode != 0:
            self.skipTest("local shallow clone is not supported by this Git")
        if gf.git(shallow, "rev-parse", "--is-shallow-repository") != "true":
            self.skipTest("Git did not create a shallow repository")
        service = GitIntelligenceService()

        relation = service.collect_revision_relation(shallow, old, current)
        result, _state = self._freshness(service, shallow, old)

        self.assertEqual(relation.state, RevisionRelationState.UNAVAILABLE)
        self.assertTrue(relation.shallow)
        self.assertEqual(result.state, FreshnessState.UNKNOWN)
        self.assertIn("shallow", " ".join(result.trust_limitations))

    def test_rename_and_delete_history_keep_revision_freshness(self):
        rename_repo = self._repo()
        renamed = gf.rename_fixture(rename_repo)
        rename_service = GitIntelligenceService()
        rename_history, rename_warnings = rename_service.collect_file_history(
            rename_repo, "delta.py"
        )
        rename_result, _state = self._freshness(
            rename_service, rename_repo, renamed["before"]
        )

        self.assertEqual(rename_warnings, [])
        self.assertEqual(
            [commit.sha for commit in rename_history],
            [renamed["after"], renamed["before"]],
        )
        self.assertEqual(rename_result.state, FreshnessState.AGING)

        delete_repo = self._repo()
        before_delete = gf.commit_file(
            delete_repo, "alpha.py", "alpha\n", "add alpha"
        )
        gf.git(delete_repo, "rm", "-q", "--", "alpha.py")
        gf.git(delete_repo, "commit", "-q", "-m", "delete alpha")
        after_delete = gf.git(delete_repo, "rev-parse", "HEAD")
        delete_service = GitIntelligenceService()
        delete_history, delete_warnings = delete_service.collect_file_history(
            delete_repo, "alpha.py"
        )
        delete_relation = delete_service.collect_revision_relation(
            delete_repo, before_delete, after_delete
        )
        delete_result, _state = self._freshness(
            delete_service, delete_repo, before_delete
        )

        self.assertEqual(delete_warnings, [])
        self.assertEqual(
            [commit.sha for commit in delete_history],
            [after_delete, before_delete],
        )
        self.assertEqual(
            delete_relation.state, RevisionRelationState.ANCESTOR
        )
        self.assertEqual(delete_result.state, FreshnessState.AGING)

    def test_history_command_failure_and_timeout_degrade_to_unknown(self):
        repo = self._repo()
        old = gf.commit_file(repo, "alpha.py", "old\n", "old")
        current = gf.commit_file(repo, "alpha.py", "current\n", "current")

        for failure in ("command", "timeout"):
            service = GitIntelligenceService()
            real_run = service._runner.run

            def failing_run(cwd, verb, *args, **kwargs):
                if verb == "log":
                    if failure == "timeout":
                        raise gi.GitUnavailable("git log timed out after 5s")
                    raise GitCommandError(
                        "forced log failure", verb="log", returncode=128
                    )
                return real_run(cwd, verb, *args, **kwargs)

            with self.subTest(failure=failure), mock.patch.object(
                service._runner, "run", side_effect=failing_run
            ):
                relation = service.collect_revision_relation(
                    repo, old, current
                )
                result, _state = self._freshness(service, repo, old)
                self.assertEqual(
                    relation.state, RevisionRelationState.UNAVAILABLE
                )
                self.assertEqual(result.state, FreshnessState.UNKNOWN)

    def test_linked_worktree_has_independent_dirty_freshness(self):
        base = _tmp_dir(self)
        repo = gf.make_repo(os.path.join(base, "repo"))
        head = gf.commit_file(repo, "alpha.py", "clean\n", "base")
        worktree = os.path.join(base, "linked")
        created = gf.git(
            repo,
            "worktree",
            "add",
            "-q",
            "--detach",
            worktree,
            head,
            check=False,
        )
        if created.returncode != 0:
            self.skipTest("linked worktrees are not supported by this Git")
        gf._write_file(worktree, "alpha.py", "dirty linked worktree\n")
        service = GitIntelligenceService()

        result, linked_state = self._freshness(service, worktree, head)
        root_state, root_warnings = service.collect_repository_state(repo)

        self.assertEqual(root_warnings, [])
        self.assertTrue(linked_state.detached)
        self.assertFalse(linked_state.clean)
        self.assertTrue(root_state.clean)
        self.assertEqual(result.state, FreshnessState.AGING)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
