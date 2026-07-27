"""Offline deterministic tests for ContextBuilder git integration (R2, B3).

No subprocess, no network: a duck-typed FakeGitService returns canned
GitIntelligenceService facts/warnings so builder mode mapping, guardrail
caps, degradation warnings and portability rules are exercised without a
real git binary.
"""

from __future__ import annotations

import json
import unittest

from relinkra.context_builder import (
    ContextBuilder,
    Guardrails,
)
from relinkra.context_packet import (
    PACKET_VERSION,
    PACKET_VERSION_V1,
)
from relinkra.git_intelligence import (
    WARN_GIT_NOT_REPOSITORY,
    GitCapabilities,
    GitCoChangeFact,
    GitCommitFact,
    GitDiffFact,
    GitFileChangeState,
    GitHeadFacts,
    GitRepositoryState,
    GitWarning,
    GitWorkingTree,
)
from test_context_packet import (
    FIXED_NOW,
    Env,
    FakeCBMAdapter,
    node,
)

SHA_A = "a" * 40
SHA_B = "b" * 40
GIT_ROOT = "C:\\fake\\repo"


def commit(sha, subject, paths=()):
    return GitCommitFact(
        sha=sha,
        short_sha=sha[:7],
        committed_at=FIXED_NOW,
        author_name="Ada",
        subject=subject,
        parents=(SHA_B,),
        changed_paths=tuple(paths),
    )


class FakeGitService:
    """Duck-typed GitIntelligenceService with canned facts + call log."""

    def __init__(self, **overrides):
        self.calls = []
        self._facts = {
            "capabilities": (
                GitCapabilities(
                    git_available=True,
                    git_version="2.55.0",
                    repository_detected=True,
                    is_bare=False,
                    head_available=True,
                    repository_root=GIT_ROOT,
                ),
                [],
            ),
            "repository_state": (
                GitRepositoryState(
                    head_sha=SHA_A,
                    short_head_sha=SHA_A[:7],
                    branch="main",
                    detached=False,
                    clean=False,
                    staged_count=1,
                    unstaged_count=0,
                    untracked_count=0,
                    conflicted_count=0,
                ),
                [],
            ),
            "head_facts": (
                GitHeadFacts(
                    head_sha=SHA_A,
                    short_head_sha=SHA_A[:7],
                    branch="main",
                    detached=False,
                    committed_at=FIXED_NOW,
                    author_name="Ada",
                    subject="canned head",
                    parents=(SHA_B,),
                ),
                [],
            ),
            "working_tree": (
                GitWorkingTree(
                    clean=False,
                    staged=("src/staged.py",),
                    unstaged=("src/unstaged.py",),
                    untracked=(),
                    deleted=(),
                    conflicted=(),
                    renamed=(),
                ),
                [],
            ),
            "recent_commits": ([commit(SHA_A, "recent one", ("src/a.py",))], []),
            "file_history": ([commit(SHA_B, "history hit", ("src/f.py",))], []),
            "current_change_state": (GitFileChangeState.UNSTAGED, []),
            "cochange": ([GitCoChangeFact("src/co.py", 3, 4)], []),
            "diff": (
                [
                    GitDiffFact("src/other.py", "modified", False, 5, 2, False),
                    GitDiffFact("src/f.py", "modified", False, 2, 1, False),
                ],
                [],
            ),
        }
        for key, value in overrides.items():
            self._facts[key] = value

    def _record(self, name, *args, **kwargs):
        self.calls.append((name, args, kwargs))
        return self._facts[name]

    def collect_capabilities(self, path):
        return self._record("capabilities", path)

    def collect_repository_state(self, path, capabilities=None):
        return self._record("repository_state", path)

    def collect_head_facts(self, path, state=None):
        return self._record("head_facts", path)

    def collect_working_tree(self, path):
        return self._record("working_tree", path)

    def collect_recent_commits(self, path, limit=10):
        return self._record("recent_commits", path, limit=limit)

    def collect_file_history(self, path, file_path, limit=None):
        return self._record(
            "file_history", path, file_path, limit=limit
        )

    def collect_current_change_state(self, path, file_path):
        return self._record("current_change_state", path, file_path)

    def collect_cochange(self, path, anchor_path):
        return self._record("cochange", path, anchor_path)

    def collect_diff(self, path, include_snippets=False):
        return self._record("diff", path, include_snippets=include_snippets)


def kinds(packet):
    return [item.data["kind"] for item in packet.git_facts]


class BuilderGitTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.addCleanup(self.env.cleanup)
        self.git = FakeGitService()

    def build(self, git=None, **request_overrides):
        service = self.git if git is None else git
        builder = self.env.builder(git_service=service)
        request = self.env.request(**request_overrides)
        return builder.build(request)

    def git_request(self, **overrides):
        overrides.setdefault("include_git", True)
        overrides.setdefault("workspace_id", self.env.workspace_id)
        return overrides

    # -- opt-in / byte-compatible git-off --------------------------------

    def test_git_off_never_touches_service_and_stays_rlkctx1(self):
        packet = self.build()  # include_git defaults to False
        self.assertEqual(packet.packet_version, PACKET_VERSION_V1)
        self.assertNotIn("git_facts", packet.to_dict())
        self.assertEqual(self.git.calls, [])
        self.assertNotIn("git_facts", packet.diagnostics["counts"])

    def test_git_on_emits_rlkctx2_with_git_provenance(self):
        packet = self.build(**self.git_request())
        self.assertEqual(packet.packet_version, PACKET_VERSION)
        self.assertTrue(packet.git_facts)
        for item in packet.git_facts:
            self.assertEqual(item.provenance.source, "git")
            self.assertTrue(item.provenance.why_included)

    def test_packet_id_identical_with_and_without_git(self):
        without = self.build(workspace_id=self.env.workspace_id)
        with_git = self.build(**self.git_request())
        self.assertEqual(without.packet_id, with_git.packet_id)

    # -- mode mapping -----------------------------------------------------

    def test_project_mode_collects_state_and_head_only(self):
        packet = self.build(**self.git_request(workspace_id=None))
        self.assertEqual(
            kinds(packet), ["repository_state", "head_facts"]
        )

    def test_workspace_mode_adds_working_tree_and_recent_commits(self):
        packet = self.build(**self.git_request())
        self.assertEqual(
            kinds(packet),
            [
                "repository_state",
                "head_facts",
                "working_tree_change",
                "working_tree_change",
                "recent_commit",
            ],
        )
        states = [
            item.data["state"]
            for item in packet.git_facts
            if item.data["kind"] == "working_tree_change"
        ]
        self.assertEqual(states, ["staged", "unstaged"])

    def test_file_mode_adds_focused_file_kinds(self):
        packet = self.build(**self.git_request(file="src/f.py"))
        self.assertEqual(
            kinds(packet),
            [
                "repository_state",
                "head_facts",
                "working_tree_change",
                "working_tree_change",
                "recent_commit",
                "current_change_state",
                "file_history",
                "diff_fact",
                "diff_fact",
                "co_change",
            ],
        )
        anchored = {
            item.data["kind"]: item.provenance.code_reference_id
            for item in packet.git_facts
            if item.data["kind"]
            in ("current_change_state", "file_history", "co_change")
        }
        self.assertTrue(all(anchored.values()))
        state = next(
            item.data
            for item in packet.git_facts
            if item.data["kind"] == "current_change_state"
        )
        self.assertEqual(
            state, {
                "kind": "current_change_state",
                "file_path": "src/f.py",
                "state": "unstaged",
            }
        )
        history = next(
            item.data
            for item in packet.git_facts
            if item.data["kind"] == "file_history"
        )
        self.assertEqual(history["file_path"], "src/f.py")
        self.assertEqual(len(history["commits"]), 1)

    def test_diff_facts_focused_file_first(self):
        packet = self.build(**self.git_request(file="src/f.py"))
        diffs = [
            item.data["path"]
            for item in packet.git_facts
            if item.data["kind"] == "diff_fact"
        ]
        self.assertEqual(diffs, ["src/f.py", "src/other.py"])

    def test_symbol_mode_anchors_at_file_level(self):
        env = Env(cbm=FakeCBMAdapter([node("fn", "mod.fn", "src/mod.py")]))
        self.addCleanup(env.cleanup)
        git = FakeGitService()
        packet = env.builder(git_service=git).build(
            env.request(
                include_git=True,
                workspace_id=env.workspace_id,
                symbol="fn",
            )
        )
        self.assertIn("current_change_state", kinds(packet))
        self.assertIn("file_history", kinds(packet))
        # File-level anchoring: the anchor path is the resolved symbol's
        # file, never a line range.
        anchored = [
            item
            for item in packet.git_facts
            if item.data["kind"] == "file_history"
        ]
        self.assertEqual(anchored[0].data["file_path"], "src/mod.py")
        self.assertTrue(anchored[0].provenance.code_reference_id)

    def test_task_mode_is_workspace_set_only(self):
        packet = self.build(
            **self.git_request(task="fix the parser crash")
        )
        self.assertNotIn("current_change_state", kinds(packet))
        self.assertNotIn("file_history", kinds(packet))
        self.assertNotIn("co_change", kinds(packet))
        self.assertIn("repository_state", kinds(packet))
        self.assertIn("recent_commit", kinds(packet))

    # -- degradation ------------------------------------------------------

    def test_non_repo_degrades_to_warning_and_valid_empty_packet(self):
        git = FakeGitService(
            capabilities=(
                GitCapabilities(True, "2.55.0", False, False, False, None),
                [GitWarning(WARN_GIT_NOT_REPOSITORY, "not a git repository")],
            )
        )
        packet = self.build(git=git, **self.git_request())
        self.assertEqual(packet.packet_version, PACKET_VERSION)
        self.assertEqual(packet.git_facts, [])
        codes = [w.code for w in packet.warnings]
        self.assertIn(WARN_GIT_NOT_REPOSITORY, codes)
        # Only capabilities probed: no section collection after the
        # not-a-repository verdict.
        called = {name for name, _, _ in git.calls}
        self.assertEqual(called, {"capabilities"})

    def test_repository_root_only_in_local_diagnostics(self):
        packet = self.build(**self.git_request())
        local = packet.diagnostics.get("local") or {}
        self.assertEqual(local.get("git_repository_root"), GIT_ROOT)
        portable = dict(packet.to_dict())
        portable.pop("diagnostics")
        self.assertNotIn(GIT_ROOT, json.dumps(portable, ensure_ascii=False))

    def test_no_workspace_root_skips_git_silently(self):
        env = Env(workspace_root=None)
        self.addCleanup(env.cleanup)
        git = FakeGitService()
        packet = env.builder(git_service=git, workspace_root=None).build(
            env.request(include_git=True)
        )
        self.assertEqual(packet.git_facts, [])
        self.assertEqual(git.calls, [])
        git_warnings = [
            w for w in packet.warnings if w.code.startswith("git_")
        ]
        self.assertEqual(git_warnings, [])

    # -- guardrails ---------------------------------------------------------

    def test_total_git_fact_cap_and_omission_reporting(self):
        builder = self.env.builder(
            git_service=self.git,
            guardrails=Guardrails(max_git_facts=2),
        )
        packet = builder.build(self.env.request(**self.git_request()))
        self.assertEqual(len(packet.git_facts), 2)
        self.assertEqual(
            kinds(packet), ["repository_state", "head_facts"]
        )
        self.assertEqual(packet.diagnostics["omitted"]["git_facts"], 3)
        codes = [w.code for w in packet.warnings]
        self.assertIn("items_omitted", codes)

    def dirty_git(self):
        """Fake service whose candidate facts overflow the 24-fact cap:
        20 working-tree entries + 4 commits of bulk vs 7 essentials /
        focused-file facts (31 candidates in total)."""
        tree = GitWorkingTree(
            clean=False,
            staged=tuple(f"src/s{i:02d}.py" for i in range(20)),
            unstaged=(),
            untracked=(),
            deleted=(),
            conflicted=(),
            renamed=(),
        )
        commits = [
            commit(f"{i:040x}", f"bulk commit {i}", (f"src/c{i}.py",))
            for i in range(4)
        ]
        return FakeGitService(
            working_tree=(tree, []),
            recent_commits=(commits, []),
        )

    def test_cap_sheds_bulk_kinds_before_focused_file_kinds(self):
        packet = self.build(
            git=self.dirty_git(), **self.git_request(file="src/f.py")
        )
        # Essentials and every focused-file kind survive the cap even
        # though bulk kinds were appended first.
        self.assertEqual(
            kinds(packet),
            ["repository_state", "head_facts"]
            + ["working_tree_change"] * 17
            + [
                "current_change_state",
                "file_history",
                "diff_fact",
                "diff_fact",
                "co_change",
            ],
        )
        # Bulk kinds fill only the slots left by priority kinds, in
        # original append order.
        paths = [
            item.data["path"]
            for item in packet.git_facts
            if item.data["kind"] == "working_tree_change"
        ]
        self.assertEqual(paths, [f"src/s{i:02d}.py" for i in range(17)])
        # Omission reporting stays exact: 31 candidates - 24 kept.
        self.assertEqual(packet.diagnostics["omitted"]["git_facts"], 7)

    def test_cap_shedding_is_deterministic_across_builds(self):
        first = self.build(
            git=self.dirty_git(), **self.git_request(file="src/f.py")
        )
        second = self.build(
            git=self.dirty_git(), **self.git_request(file="src/f.py")
        )
        self.assertEqual(
            [item.data for item in first.git_facts],
            [item.data for item in second.git_facts],
        )

    def test_diff_cap_and_cochange_cap(self):
        git = FakeGitService(
            diff=(
                [
                    GitDiffFact(f"src/d{i}.py", "modified", False, 1, 1, False)
                    for i in range(12)
                ],
                [],
            ),
            cochange=(
                [GitCoChangeFact(f"src/c{i}.py", 1, 5) for i in range(12)],
                [],
            ),
        )
        builder = self.env.builder(
            git_service=git,
            guardrails=Guardrails(max_git_facts=100),
        )
        packet = builder.build(
            self.env.request(**self.git_request(file="src/f.py"))
        )
        diffs = [
            item for item in packet.git_facts
            if item.data["kind"] == "diff_fact"
        ]
        cochanges = [
            item for item in packet.git_facts
            if item.data["kind"] == "co_change"
        ]
        self.assertEqual(len(diffs), 8)
        self.assertEqual(len(cochanges), 10)

    def test_git_history_limit_passed_to_service(self):
        self.build(**self.git_request(git_history_limit=3))
        recent = [
            kwargs
            for name, _, kwargs in self.git.calls
            if name == "recent_commits"
        ]
        history = [
            kwargs
            for name, _, kwargs in self.git.calls
            if name == "file_history"
        ]
        self.assertEqual(recent, [{"limit": 3}])
        # No file anchor in workspace mode: no history call at all.
        self.assertEqual(history, [])

    def test_conflicted_paths_warn_and_keep_other_sections(self):
        git = FakeGitService(
            working_tree=(
                GitWorkingTree(
                    clean=False,
                    staged=(),
                    unstaged=(),
                    untracked=(),
                    deleted=(),
                    conflicted=("src/clash.py",),
                    renamed=(),
                ),
                [],
            )
        )
        packet = self.build(git=git, **self.git_request())
        conflict_items = [
            item.data
            for item in packet.git_facts
            if item.data["kind"] == "working_tree_change"
        ]
        self.assertEqual(
            conflict_items,
            [
                {
                    "kind": "working_tree_change",
                    "path": "src/clash.py",
                    "state": "conflicted",
                    "old_path": None,
                }
            ],
        )
        codes = [w.code for w in packet.warnings]
        self.assertIn("git_conflicts", codes)
        # Other sections survive the conflict state.
        self.assertIn("repository_state", kinds(packet))
        self.assertIn("head_facts", kinds(packet))

    def test_git_facts_count_in_diagnostics(self):
        packet = self.build(**self.git_request())
        self.assertEqual(
            packet.diagnostics["counts"]["git_facts"],
            len(packet.git_facts),
        )


if __name__ == "__main__":
    unittest.main()
