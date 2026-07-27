"""R2 Git Intelligence V1 — Batch B5 proof suite (tasks 5.1–5.3).

Three handoff-mandated proofs against the SHIPPED implementation:

5.1 PERF: full collect benchmark (capabilities + repository_state +
   head_facts + recent_commits + file_history + cochange) against the
   REAL relinkra repository, with a generous wall-time budget and the
   measured timings printed for the final report.
5.2 REAL-REPO READ-ONLY: collect_file_history("relinkra/relevance.py")
   includes f54aac2b; ``git status --porcelain`` and HEAD are captured
   before and after every collect in this module and asserted identical
   (zero mutation). The guard lives in setUpModule/tearDownModule so it
   spans ALL real-repo collects in the module; plain subprocess is used
   ONLY for this guard — collects go through GitIntelligenceService.
5.3 AGENT-VALUE: deterministic abcd fixture proving quality-first
   selection — under a constrained budget IMPORTANT git facts survive
   while OPTIONAL git facts are shed first, and under relevance-v1-git1
   the candidate linked to focus-touching history outranks unrelated
   history.

Real-repo proofs skip gracefully when the repository or the proof commit
is unavailable, keeping the suite portable.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _TESTS_DIR not in sys.path:
    # Allow both `python -m unittest discover -s tests` and
    # `python -m unittest tests.test_git_proofs` invocation styles.
    sys.path.insert(0, _TESTS_DIR)

from test_context_budget import budget_with_over
from test_context_packet import FIXED_NOW, Env

try:
    from tests import git_fixtures as gf
except ImportError:  # pragma: no cover - discover vs module invocation
    import git_fixtures as gf

from relinkra.code_reference import CodeReference
from relinkra.context_budget import (
    DEFAULT_CHARS_PER_TOKEN,
    ContextBudget,
    _item_chars,
    _tokens_for_chars,
    apply_budget,
    classify_git_fact,
    classify_memory_type,
)
from relinkra.context_packet import PacketItem, Provenance
from relinkra.git_intelligence import GitIntelligenceService
from relinkra.relevance import (
    DEFAULT_WEIGHTS,
    GIT1_WEIGHTS,
    RELEVANCE_VERSION,
    RELEVANCE_VERSION_GIT1,
    score_packet,
)

REPO_ROOT = os.path.dirname(_TESTS_DIR)
GIT_BIN = gf.GIT_BIN
PROOF_COMMIT_PREFIX = "f54aac2b"
PROOF_COMMIT_SUBJECT = "feat(relevance): add deterministic relevance scoring v1"
PROOF_FILE = "relinkra/relevance.py"

GIT_SIGNAL_NAMES = (
    "focused_file_changed",
    "commit_touches_focused_file",
    "recent_commit",
    "cochange_with_focus",
    "task_keyword_match",
)

IMPORTANT_GIT_KINDS = (
    "repository_state",
    "head_facts",
    "working_tree_change",
    "recent_commit",
    "current_change_state",
    "file_history",
)
OPTIONAL_GIT_KINDS = ("diff_fact", "co_change")


def _git_guard(*args):
    """Plain-subprocess read-only probe used ONLY for the mutation guard.

    Returns stripped stdout, or None when the command fails (repo or git
    unavailable) so callers can skip gracefully.
    """
    if GIT_BIN is None:
        return None
    result = subprocess.run(
        [GIT_BIN, "-C", REPO_ROOT, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _probe_repo():
    """(HEAD sha, porcelain) snapshot, or None when the repo is unusable."""
    if not os.path.isdir(os.path.join(REPO_ROOT, ".git")):
        return None
    head = _git_guard("rev-parse", "HEAD")
    porcelain = _git_guard("status", "--porcelain")
    if head is None or porcelain is None:
        return None
    return {"head": head, "porcelain": porcelain}


# Captured at import (collection) time: the true BEFORE state for every
# real-repo collect in this module.
_REPO_BEFORE = _probe_repo()

_PROOF_SHA = (
    _git_guard("rev-parse", "--verify", "-q", f"{PROOF_COMMIT_PREFIX}^{{commit}}")
    if _REPO_BEFORE is not None
    else None
)

REPO_AVAILABLE = _REPO_BEFORE is not None
PROOF_COMMIT_AVAILABLE = _PROOF_SHA is not None


def tearDownModule():
    """Zero-mutation guard: HEAD and porcelain identical after ALL collects."""
    if _REPO_BEFORE is None:
        return
    after = _probe_repo()
    if after is None:
        raise AssertionError("mutation guard: repo became unreadable")
    porcelain_identical = after["porcelain"] == _REPO_BEFORE["porcelain"]
    head_identical = after["head"] == _REPO_BEFORE["head"]
    print(
        "[git-proof] read-only guard: HEAD "
        f"{_REPO_BEFORE['head'][:12]} -> {after['head'][:12]} "
        f"(identical={head_identical}) | porcelain before/after "
        f"identical={porcelain_identical}"
    )
    if not head_identical:
        raise AssertionError(
            "git collects mutated HEAD: "
            f"{_REPO_BEFORE['head']} -> {after['head']}"
        )
    if not porcelain_identical:
        raise AssertionError(
            "git collects mutated the working tree.\n"
            f"--- porcelain BEFORE ---\n{_REPO_BEFORE['porcelain']}\n"
            f"--- porcelain AFTER ---\n{after['porcelain']}"
        )


@unittest.skipUnless(REPO_AVAILABLE, "real relinkra git repository unavailable")
class PerfBenchmarkTests(unittest.TestCase):
    """5.1 — full collect wall-time benchmark on the real relinkra repo."""

    TOTAL_BUDGET_SECONDS = 5.0
    PER_OP_BUDGET_SECONDS = 2.5

    def test_full_collect_wall_time_budget(self):
        service = GitIntelligenceService()
        timings = {}

        def timed(name, collect):
            start = time.perf_counter()
            facts, warnings = collect()
            timings[name] = time.perf_counter() - start
            # A degraded collect times the wrong (trivial) path: fail loudly.
            self.assertEqual([], warnings, f"{name} degraded: {warnings}")
            return facts

        total_start = time.perf_counter()
        caps = timed("capabilities", lambda: service.collect_capabilities(REPO_ROOT))
        state = timed(
            "repository_state", lambda: service.collect_repository_state(REPO_ROOT)
        )
        head = timed("head_facts", lambda: service.collect_head_facts(REPO_ROOT))
        recent = timed(
            "recent_commits", lambda: service.collect_recent_commits(REPO_ROOT)
        )
        history = timed(
            "file_history",
            lambda: service.collect_file_history(REPO_ROOT, PROOF_FILE),
        )
        cochange = timed(
            "cochange",
            lambda: service.collect_cochange(REPO_ROOT, PROOF_FILE),
        )
        total = time.perf_counter() - total_start

        print(
            "[git-perf] "
            + " ".join(f"{name}={secs * 1000:.1f}ms" for name, secs in timings.items())
            + f" total={total * 1000:.1f}ms "
            f"(budget: per-op < {self.PER_OP_BUDGET_SECONDS * 1000:.0f}ms, "
            f"total < {self.TOTAL_BUDGET_SECONDS * 1000:.0f}ms)"
        )

        # The benchmark must have timed REAL collections, not degradation.
        self.assertTrue(caps.git_available)
        self.assertTrue(caps.repository_detected)
        self.assertIsNotNone(state)
        self.assertIsNotNone(head)
        self.assertTrue(recent)
        self.assertTrue(history)
        self.assertIsInstance(cochange, list)

        for name, seconds in timings.items():
            self.assertLess(seconds, self.PER_OP_BUDGET_SECONDS, name)
        self.assertLess(total, self.TOTAL_BUDGET_SECONDS)


@unittest.skipUnless(
    PROOF_COMMIT_AVAILABLE, f"relinkra repo @ {PROOF_COMMIT_PREFIX} unavailable"
)
class RealRepoReadOnlyProofTests(unittest.TestCase):
    """5.2 — real-repo content proof; zero mutation is guarded module-wide."""

    def test_file_history_contains_proof_commit(self):
        service = GitIntelligenceService()
        commits, warnings = service.collect_file_history(
            REPO_ROOT, PROOF_FILE, limit=100
        )
        self.assertEqual([], warnings)
        shas = [commit.sha for commit in commits]
        print(
            f"[git-proof] collect_file_history({PROOF_FILE!r}) commits: "
            + str([(c.short_sha, c.subject) for c in commits])
        )
        self.assertIn(_PROOF_SHA, shas)
        proof = commits[shas.index(_PROOF_SHA)]
        self.assertEqual(PROOF_COMMIT_SUBJECT, proof.subject)
        self.assertIn(PROOF_FILE, proof.changed_paths)

    def test_head_facts_match_mutation_guard(self):
        service = GitIntelligenceService()
        head, warnings = service.collect_head_facts(REPO_ROOT)
        self.assertEqual([], warnings)
        self.assertIsNotNone(head)
        # The service sees the same HEAD the porcelain guard captured.
        self.assertEqual(_REPO_BEFORE["head"], head.head_sha)
        self.assertEqual("master", head.branch)
        self.assertFalse(head.detached)
        self.assertNotIn("@", head.author_name)  # email never emitted


class AgentValueQualityProofTests(unittest.TestCase):
    """5.3 — quality-first selection: IMPORTANT git facts survive a
    constrained budget while OPTIONAL git facts are shed first, and
    relevance-v1-git1 lifts the candidate linked to focus-touching
    history above unrelated history."""

    def setUp(self):
        self.env = Env()
        self.addCleanup(self.env.cleanup)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = gf.make_repo(os.path.join(self.tmp.name, "repo"))
        self.shas = gf.scenario_abcd(self.repo)
        # Dirty alpha.py (unstaged) so the focused file has a live change
        # state and a real diff fact.
        with open(
            os.path.join(self.repo, "alpha.py"), "a", encoding="utf-8", newline="\n"
        ) as fh:
            fh.write("alpha uncommitted\n")
        builder = self.env.builder(workspace_root=self.repo)  # real git service
        self.packet = builder.build(
            self.env.request(
                task="fix regression in alpha",
                file="alpha.py",
                include_git=True,
            )
        )

    def kinds(self, packet):
        return [item.data["kind"] for item in packet.git_facts]

    def test_constrained_budget_keeps_important_git_sheds_optional_first(self):
        packet = self.packet
        original_kinds = self.kinds(packet)
        # Fixture sanity: both policy classes are present in the packet.
        for kind in IMPORTANT_GIT_KINDS + OPTIONAL_GIT_KINDS:
            self.assertIn(kind, original_kinds)
        state = next(
            item for item in packet.git_facts
            if item.data["kind"] == "current_change_state"
        )
        self.assertEqual("alpha.py", state.data["file_path"])
        self.assertEqual("unstaged", state.data["state"])

        # Constrained budget: exceed it by exactly the OPTIONAL mass
        # (optional memories + optional git facts, measured with the
        # accountant's own functions) minus one token, so the ladder must
        # shed every optional item but never needs to touch important ones.
        optional_tokens = sum(
            _tokens_for_chars(_item_chars(item), DEFAULT_CHARS_PER_TOKEN)
            for item in packet.memories
            if classify_memory_type(item.data.get("memory_type")) == "optional"
        )
        optional_tokens += sum(
            _tokens_for_chars(_item_chars(item), DEFAULT_CHARS_PER_TOKEN)
            for item in packet.git_facts
            if classify_git_fact(item.data.get("kind")) == "optional"
        )
        budget = ContextBudget(
            max_estimated_tokens=budget_with_over(
                packet, max(1, optional_tokens - 1)
            )
        )
        result = apply_budget(packet, budget)

        self.assertEqual("OK", result.status)
        self.assertTrue(result.satisfied)
        # Hard guarantee: the shipped payload respects the budget.
        self.assertLessEqual(
            result.final_usage.estimated_tokens, budget.max_estimated_tokens
        )

        surviving = self.kinds(result.packet)
        # IMPORTANT git facts SURVIVE: repo state, focused file change
        # state, and the relevant commits/history touching the focus.
        self.assertEqual(sorted(set(IMPORTANT_GIT_KINDS)), sorted(set(surviving)))
        # OPTIONAL git facts are shed FIRST (before any important item).
        for kind in OPTIONAL_GIT_KINDS:
            self.assertNotIn(kind, surviving)
        omitted_git = [
            d for d in result.decisions
            if d.section == "git_facts" and d.action == "omitted"
        ]
        self.assertEqual(2, len(omitted_git))
        for decision in omitted_git:
            self.assertEqual(
                "optional_section_budget_exhausted", decision.reason
            )
        # Important memories survive too; pending/handoffs (step-5 classes)
        # are never reached by the ladder.
        surviving_types = {
            item.data["memory_type"] for item in result.packet.memories
        }
        self.assertTrue(
            {"constraint", "decision", "architecture", "bug"} <= surviving_types
        )
        self.assertEqual(1, len(result.packet.pending))
        self.assertEqual(1, len(result.packet.handoffs))

        # The surviving git facts are the ones that matter for the task:
        # the focused file's change state, its history, and a recent
        # commit touching it.
        history = next(
            item for item in result.packet.git_facts
            if item.data["kind"] == "file_history"
        )
        self.assertEqual("alpha.py", history.data["file_path"])
        self.assertEqual(
            [self.shas["D"], self.shas["B"], self.shas["A"]],
            [c["sha"] for c in history.data["commits"]],
        )
        touching = [
            item for item in result.packet.git_facts
            if item.data["kind"] == "recent_commit"
            and "alpha.py" in (item.data.get("changed_paths") or [])
        ]
        self.assertTrue(touching)
        kept_state = next(
            item for item in result.packet.git_facts
            if item.data["kind"] == "current_change_state"
        )
        self.assertEqual("unstaged", kept_state.data["state"])

        # The input packet is never mutated by the accountant.
        self.assertEqual(original_kinds, self.kinds(packet))

        print(
            f"[git-proof] agent-value budget: max={budget.max_estimated_tokens} "
            f"tokens | shed first: {sorted(set(OPTIONAL_GIT_KINDS))} "
            f"(+ optional memories) | surviving git kinds: {surviving}"
        )

    def test_git1_lifts_focus_linked_candidate_above_unrelated_history(self):
        packet = self.packet
        alpha_item = packet.code_references[0]
        alpha_id = alpha_item.provenance.code_reference_id
        # An unrelated code candidate: gamma.py exists in history but is
        # untouched by the focus-linked commits' co-change and is not the
        # focus. It mirrors the builder's code_reference item shape.
        gamma_ref = CodeReference(
            project_id=self.env.project_id,
            workspace_id=None,
            reference_kind="file",
            file_path="gamma.py",
        )
        packet.code_references.append(
            PacketItem(
                data={
                    "reference": gamma_ref.to_dict(),
                    "resolution_state": alpha_item.data["resolution_state"],
                    "note": None,
                },
                provenance=Provenance(
                    source=alpha_item.provenance.source,
                    why_included="unrelated file candidate (proof fixture)",
                    code_reference_id=gamma_ref.code_reference_id,
                    resolution_state=alpha_item.provenance.resolution_state,
                ),
            )
        )

        scored = dict(
            task="fix regression in alpha",
            focus_file="alpha.py",
            as_of=FIXED_NOW,
        )
        ranked = score_packet(packet, weights=GIT1_WEIGHTS, **scored)
        self.assertEqual(RELEVANCE_VERSION_GIT1, ranked.relevance_version)

        alpha = ranked.score_for("code_references", alpha_id, 0)
        gamma = ranked.score_for("code_references", gamma_ref.code_reference_id, 0)
        alpha_signals = dict(alpha.signals)
        # The commit touching the focused file (+ its live change state)
        # lifts the focused candidate: exactly the designed git boost.
        self.assertEqual(10, alpha_signals["focused_file_changed"])
        self.assertEqual(8, alpha_signals["commit_touches_focused_file"])
        self.assertEqual(0, alpha_signals["recent_commit"])
        self.assertEqual(0, alpha_signals["cochange_with_focus"])
        self.assertEqual(0, alpha_signals["task_keyword_match"])
        git_boost = sum(alpha_signals[name] for name in GIT_SIGNAL_NAMES)
        self.assertEqual(18, git_boost)
        # Unrelated history earns NOTHING from git.
        gamma_signals = dict(gamma.signals)
        for name in GIT_SIGNAL_NAMES:
            self.assertEqual(0, gamma_signals[name], name)
        # ... so the focus-linked candidate outranks it.
        self.assertGreater(alpha.total, gamma.total)
        self.assertEqual(
            alpha_id, ranked.scores["code_references"][0].source_id
        )
        # Non-code candidates (memories/pending/handoffs) are never
        # modulated by these git signals.
        for section in ("memories", "pending", "handoffs"):
            for entry in ranked.scores[section]:
                signals = dict(entry.signals)
                for name in GIT_SIGNAL_NAMES:
                    self.assertEqual(
                        0, signals[name], f"{section}/{entry.source_id}/{name}"
                    )

        # Same packet, git weights disabled: the lift disappears (and the
        # report degrades to plain relevance-v1) — the +18 is provably
        # attributable to git facts, not to focus matching alone.
        baseline = score_packet(packet, weights=DEFAULT_WEIGHTS, **scored)
        self.assertEqual(RELEVANCE_VERSION, baseline.relevance_version)
        base_alpha = baseline.score_for("code_references", alpha_id, 0)
        base_gamma = baseline.score_for(
            "code_references", gamma_ref.code_reference_id, 0
        )
        self.assertEqual(18, alpha.total - base_alpha.total)
        self.assertEqual(0, gamma.total - base_gamma.total)

        print(
            "[git-proof] agent-value relevance: alpha.py candidate "
            f"total={alpha.total} (relevance-v1 {base_alpha.total}, "
            f"+{alpha.total - base_alpha.total} git) outranks gamma.py "
            f"total={gamma.total} (relevance-v1 {base_gamma.total}, "
            f"+{gamma.total - base_gamma.total} git)"
        )


if __name__ == "__main__":
    unittest.main()
