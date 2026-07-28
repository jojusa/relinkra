"""Deterministic tests for the R3 cross-agent Handoff model and service.

Offline: memories go through the in-memory R1C store, so identity,
redaction, dedup, supersession, and policy isolation are all exercised
without Engram, CBM, or git.
"""

from __future__ import annotations

import json
import unittest

from relinkra.handoff import (
    HANDOFF_ID_RE,
    HANDOFF_VERSION,
    GitStateRef,
    Handoff,
    HandoffService,
    HandoffValidationError,
    build_handoff,
    contains_absolute_path,
    handoff_title,
)
from test_context_packet import FIXED_NOW, Env


def _service(env):
    return HandoffService(env.service, clock=lambda: FIXED_NOW)


def _base(env, **overrides):
    kwargs = dict(
        project_id=env.project_id,
        source_agent="opencode",
        task="Implement the MCP surface",
        created_at=FIXED_NOW,
    )
    kwargs.update(overrides)
    return build_handoff(**kwargs)


class HandoffIdentityTests(unittest.TestCase):
    def setUp(self):
        self.env = Env(seed=False)
        self.addCleanup(self.env.cleanup)

    def test_id_shape(self):
        handoff = _base(self.env)
        self.assertTrue(HANDOFF_ID_RE.match(handoff.handoff_id))
        self.assertEqual(handoff.handoff_version, HANDOFF_VERSION)

    def test_id_is_deterministic_across_builds(self):
        a = _base(self.env)
        b = _base(self.env)
        self.assertEqual(a.handoff_id, b.handoff_id)

    def test_created_at_never_participates_in_identity(self):
        a = _base(self.env, created_at="2020-01-01T00:00:00+00:00")
        b = _base(self.env, created_at="2031-12-31T23:59:59+00:00")
        self.assertEqual(a.handoff_id, b.handoff_id)

    def test_reference_order_never_participates_in_identity(self):
        ids = ["mem_" + "a" * 32, "mem_" + "b" * 32]
        a = _base(self.env, related_memory_ids=ids)
        b = _base(self.env, related_memory_ids=list(reversed(ids)))
        self.assertEqual(a.handoff_id, b.handoff_id)
        self.assertEqual(a.related_memory_ids, b.related_memory_ids)

    def test_content_change_changes_identity(self):
        a = _base(self.env)
        b = _base(self.env, summary="now with a summary")
        self.assertNotEqual(a.handoff_id, b.handoff_id)

    def test_source_agent_changes_identity_but_not_authority(self):
        a = _base(self.env, source_agent="opencode")
        b = _base(self.env, source_agent="claude")
        self.assertNotEqual(a.handoff_id, b.handoff_id)
        # Recorded as data; it is not a scope, channel, or agent_type.
        self.assertEqual(a.source_agent, "opencode")

    def test_supersedes_participates_in_identity(self):
        prior = _base(self.env)
        a = _base(self.env, summary="second")
        b = _base(self.env, summary="second", supersedes=prior.handoff_id)
        self.assertNotEqual(a.handoff_id, b.handoff_id)

    def test_title_is_unique_per_handoff(self):
        """Distinct handoffs must not collapse onto one R1C topic_key."""
        a = _base(self.env, summary="one")
        b = _base(self.env, summary="two")
        self.assertNotEqual(handoff_title(a), handoff_title(b))
        self.assertIn("implement", handoff_title(a))


class HandoffValidationTests(unittest.TestCase):
    def setUp(self):
        self.env = Env(seed=False)
        self.addCleanup(self.env.cleanup)

    def test_task_is_required(self):
        with self.assertRaises(HandoffValidationError):
            _base(self.env, task="   ")

    def test_source_agent_is_required(self):
        with self.assertRaises(HandoffValidationError):
            _base(self.env, source_agent="")

    def test_target_agent_is_optional(self):
        handoff = _base(self.env)
        self.assertIsNone(handoff.target_agent)

    def test_malformed_memory_id_is_rejected(self):
        with self.assertRaises(HandoffValidationError):
            _base(self.env, related_memory_ids=["not-a-memory-id"])

    def test_malformed_packet_id_is_rejected(self):
        with self.assertRaises(HandoffValidationError):
            _base(self.env, context_packet_id="pkt_nope")

    def test_malformed_supersedes_is_rejected(self):
        with self.assertRaises(HandoffValidationError):
            _base(self.env, supersedes="hof_short")

    def test_scalar_where_list_expected_is_rejected(self):
        with self.assertRaises(HandoffValidationError):
            _base(self.env, completed_work="not a list")

    def test_control_characters_are_stripped(self):
        handoff = _base(self.env, summary="clean\x00\x07text")
        self.assertEqual(handoff.summary, "cleantext")

    def test_long_fields_are_bounded(self):
        handoff = _base(self.env, summary="x" * 9000)
        self.assertLessEqual(len(handoff.summary), 2000)

    def test_list_length_is_bounded(self):
        handoff = _base(self.env, pending_work=[f"item {i}" for i in range(100)])
        self.assertLessEqual(len(handoff.pending_work), 20)

    def test_secrets_are_redacted_before_hashing(self):
        secret = "Authorization: Bearer sk-abcdef0123456789abcdef"
        handoff = _base(self.env, summary=secret)
        self.assertNotIn("sk-abcdef0123456789abcdef", handoff.summary)
        self.assertNotIn("sk-abcdef0123456789abcdef", handoff.to_json())
        # The stored bytes and the identity must agree: rebuilding from
        # the redacted text yields the same id.
        again = _base(self.env, summary=handoff.summary)
        self.assertEqual(handoff.handoff_id, again.handoff_id)

    def test_agent_labels_are_sanitized_like_any_free_text(self):
        """An agent label is caller-supplied, not a trusted enum."""
        handoff = _base(
            self.env,
            source_agent="opencode /home/me/secrets",
            target_agent="claude C:\\Users\\me\\key",
        )
        self.assertFalse(contains_absolute_path(handoff.source_agent))
        self.assertFalse(contains_absolute_path(handoff.target_agent))
        self.assertNotIn("secrets", handoff.source_agent)

    def test_round_trip_through_dict(self):
        handoff = _base(self.env, summary="s", decisions=["d1"])
        restored = Handoff.from_dict(json.loads(handoff.to_json()))
        self.assertEqual(restored.handoff_id, handoff.handoff_id)
        self.assertEqual(restored.decisions, ["d1"])

    def test_unknown_version_is_rejected(self):
        data = json.loads(_base(self.env).to_json())
        data["handoff_version"] = "rlkho999"
        with self.assertRaises(HandoffValidationError):
            Handoff.from_dict(data)


class GitStateRefTests(unittest.TestCase):
    def test_defaults_are_empty(self):
        state = GitStateRef()
        self.assertIsNone(state.head_sha)
        self.assertEqual(state.to_dict()["counts"]["staged"], 0)

    def test_non_sha_head_is_rejected(self):
        with self.assertRaises(HandoffValidationError):
            GitStateRef.from_dict({"head_sha": "../../etc/passwd"})

    def test_projection_from_repository_state(self):
        class FakeState:
            branch = "main"
            head_sha = "a" * 40
            short_head_sha = "a" * 7
            detached = False
            clean = False
            staged_count = 2
            unstaged_count = 1
            untracked_count = 0
            conflicted_count = 0

        state = GitStateRef.from_repository_state(FakeState())
        self.assertEqual(state.branch, "main")
        self.assertEqual(state.staged_count, 2)
        # No paths, no remotes, no author email travel with a handoff.
        self.assertNotIn("repository_root", state.to_dict())

    def test_projection_sanitizes_branch_like_from_dict(self):
        """Both construction paths must scrub identically."""

        class HostileState:
            branch = "wip/C:\\Users\\me\\repo\x07"
            head_sha = "b" * 40
            short_head_sha = "b" * 7
            detached = False
            clean = True
            staged_count = 0
            unstaged_count = 0
            untracked_count = 0
            conflicted_count = 0

        projected = GitStateRef.from_repository_state(HostileState())
        self.assertFalse(contains_absolute_path(projected.branch))
        self.assertNotIn("\x07", projected.branch)
        parsed = GitStateRef.from_dict({"branch": HostileState.branch})
        self.assertEqual(projected.branch, parsed.branch)


class AbsolutePathDetectionTests(unittest.TestCase):
    def test_detects_windows_and_posix(self):
        self.assertTrue(contains_absolute_path("C:\\Users\\me\\repo"))
        self.assertTrue(contains_absolute_path("see /home/me/repo"))
        self.assertTrue(contains_absolute_path("\\\\server\\share"))

    def test_ignores_relative(self):
        self.assertFalse(contains_absolute_path("src/relinkra/mcp_server.py"))
        self.assertFalse(contains_absolute_path(""))


class HandoffServiceTests(unittest.TestCase):
    def setUp(self):
        self.env = Env(seed=False)
        self.addCleanup(self.env.cleanup)
        self.service = _service(self.env)

    def _create(self, **overrides):
        kwargs = dict(
            project_id=self.env.project_id,
            source_agent="opencode",
            task="Implement the MCP surface",
            repository_identity=_repo(self.env),
        )
        kwargs.update(overrides)
        return self.service.create(**kwargs)

    def test_create_then_get_round_trip(self):
        handoff, deduplicated, warnings = self._create(
            target_agent="claude", summary="scaffolded"
        )
        self.assertFalse(deduplicated)
        self.assertEqual(warnings, [])
        fetched = self.service.get(
            project_id=self.env.project_id, handoff_id=handoff.handoff_id
        )
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.handoff_id, handoff.handoff_id)
        self.assertEqual(fetched.target_agent, "claude")

    def test_persisted_as_shared_handoff_memory(self):
        handoff, _, _ = self._create()
        memory = self.env.service.get(
            project_id=self.env.project_id, memory_id=handoff.memory_id
        )
        self.assertEqual(memory.memory_type, "handoff")
        self.assertEqual(memory.scope, "project_shared")
        self.assertEqual(memory.scope_channel, "shared")
        # source_agent must never become an authority signal.
        self.assertEqual(memory.agent_type, "")

    def test_duplicate_handoff_is_deduplicated(self):
        first, first_dedup, _ = self._create(summary="same")
        second, second_dedup, _ = self._create(summary="same")
        self.assertFalse(first_dedup)
        self.assertTrue(second_dedup)
        self.assertEqual(first.handoff_id, second.handoff_id)
        listed = self.service.list(project_id=self.env.project_id)
        self.assertEqual(len(listed), 1)

    def test_duplicate_is_deduplicated_under_a_moving_clock(self):
        """The frozen-clock case is the easy one; reality moves.

        created_at must not reach the R1C dedup key, or a replayed
        handoff writes a second record that supersedes the first and
        reports deduplicated=False forever.
        """
        ticks = {"n": 0}

        def clock():
            ticks["n"] += 1
            return f"2026-02-01T00:00:{ticks['n']:02d}+00:00"

        service = HandoffService(self.env.service, clock=clock)
        args = dict(
            project_id=self.env.project_id,
            source_agent="opencode",
            task="Replayed after a transient failure",
            repository_identity=_repo(self.env),
            summary="identical content",
        )
        first, first_dedup, _ = service.create(**args)
        second, second_dedup, _ = service.create(**args)
        third, third_dedup, _ = service.create(**args)

        self.assertFalse(first_dedup)
        self.assertTrue(second_dedup)
        self.assertTrue(third_dedup)
        self.assertEqual(first.handoff_id, second.handoff_id)
        self.assertEqual(first.handoff_id, third.handoff_id)
        self.assertEqual(first.memory_id, second.memory_id)
        # One record, not a supersession chain.
        history = service.list(
            project_id=self.env.project_id, include_history=True
        )
        self.assertEqual(
            [h.handoff_id for h in history], [first.handoff_id]
        )

    def test_created_at_round_trips_from_the_envelope(self):
        service = HandoffService(
            self.env.service, clock=lambda: "2026-03-04T05:06:07+00:00"
        )
        created, _, _ = service.create(
            project_id=self.env.project_id,
            source_agent="opencode",
            task="Timestamped work",
            repository_identity=_repo(self.env),
        )
        fetched = service.get(
            project_id=self.env.project_id, handoff_id=created.handoff_id
        )
        self.assertTrue(fetched.created_at)
        # The body itself carries no wall clock.
        self.assertNotIn("created_at", created.to_storage_dict())

    def test_distinct_handoffs_both_survive(self):
        a, _, _ = self._create(summary="first")
        b, _, _ = self._create(summary="second")
        self.assertNotEqual(a.handoff_id, b.handoff_id)
        listed = {h.handoff_id for h in self.service.list(
            project_id=self.env.project_id
        )}
        self.assertEqual(listed, {a.handoff_id, b.handoff_id})

    def test_supersede_retains_history(self):
        first, _, _ = self._create(summary="first")
        second, _, _ = self._create(
            summary="second", supersedes=first.handoff_id
        )
        self.assertEqual(second.supersedes, first.handoff_id)
        # The prior handoff is still addressable: nothing is rewritten.
        prior = self.service.get(
            project_id=self.env.project_id, handoff_id=first.handoff_id
        )
        self.assertIsNotNone(prior)
        self.assertEqual(prior.handoff_id, first.handoff_id)

    def test_supersede_unknown_handoff_is_rejected(self):
        with self.assertRaises(HandoffValidationError):
            self._create(supersedes="hof_" + "0" * 32)

    def test_agent_private_reference_is_dropped_with_warning(self):
        private = self.env.save(
            memory_type="discovery",
            title="private note",
            body="secret-ish",
            scope="agent_private",
            agent_type="claude",
        )
        handoff, _, warnings = self._create(
            related_memory_ids=[private.memory_id]
        )
        self.assertEqual(handoff.related_memory_ids, [])
        self.assertTrue(
            any("agent_private" in w for w in warnings), warnings
        )
        self.assertNotIn(private.memory_id, handoff.to_json())

    def test_shared_reference_is_kept(self):
        shared = self.env.save(
            memory_type="decision", title="use stdlib only", body="d"
        )
        handoff, _, warnings = self._create(
            related_memory_ids=[shared.memory_id]
        )
        self.assertEqual(handoff.related_memory_ids, [shared.memory_id])
        self.assertEqual(warnings, [])

    def test_unknown_reference_is_dropped_with_warning(self):
        handoff, _, warnings = self._create(
            related_memory_ids=["mem_" + "f" * 32]
        )
        self.assertEqual(handoff.related_memory_ids, [])
        self.assertTrue(any("unknown" in w for w in warnings), warnings)

    def test_list_filters_by_target_agent(self):
        self._create(target_agent="claude", summary="for claude")
        self._create(target_agent="codex", summary="for codex")
        for_claude = self.service.list(
            project_id=self.env.project_id, target_agent="claude"
        )
        self.assertEqual(len(for_claude), 1)
        self.assertEqual(for_claude[0].target_agent, "claude")

    def test_get_survives_a_busy_project(self):
        """R1C fetches a fixed store page across ALL memory types.

        A handoff buried under a page of unrelated memories must still be
        reachable by id, or supersede targets start vanishing.
        """
        handoff, _, _ = self._create(summary="buried treasure")
        for index in range(260):
            self.env.save(
                memory_type="discovery",
                title=f"noise discovery {index}",
                body=f"unrelated body {index}",
            )
        found = self.service.get(
            project_id=self.env.project_id, handoff_id=handoff.handoff_id
        )
        self.assertIsNotNone(found, "handoff fell off the store page")
        self.assertEqual(found.handoff_id, handoff.handoff_id)
        # And it can still be superseded, which needs the same lookup.
        successor, _, _ = self._create(
            summary="replaces the buried one", supersedes=handoff.handoff_id
        )
        self.assertEqual(successor.supersedes, handoff.handoff_id)

    def test_malformed_stored_payload_is_skipped(self):
        self._create(summary="good")
        # A corrupt handoff record must not take down the listing.
        self.env.save(
            memory_type="handoff", title="corrupt handoff", body="{not json"
        )
        listed = self.service.list(project_id=self.env.project_id)
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0].summary, "good")


class CrossAgentHandoffTests(unittest.TestCase):
    """The R3 headline behaviour: agent A writes, agent B reads."""

    def setUp(self):
        self.env = Env(seed=False)
        self.addCleanup(self.env.cleanup)

    def test_opencode_to_claude(self):
        producer = HandoffService(self.env.service, clock=lambda: FIXED_NOW)
        created, _, _ = producer.create(
            project_id=self.env.project_id,
            source_agent="opencode",
            target_agent="claude",
            task="Port the parser",
            repository_identity=_repo(self.env),
            completed_work=["tokenizer done"],
            pending_work=["error recovery"],
            decisions=["keep the stdlib-only rule"],
        )
        # A completely separate service instance, as a different agent.
        consumer = HandoffService(self.env.service, clock=lambda: FIXED_NOW)
        fetched = consumer.get(
            project_id=self.env.project_id, handoff_id=created.handoff_id
        )
        self.assertEqual(fetched.source_agent, "opencode")
        self.assertEqual(fetched.target_agent, "claude")
        self.assertEqual(fetched.pending_work, ["error recovery"])

    def test_claude_to_codex(self):
        producer = HandoffService(self.env.service, clock=lambda: FIXED_NOW)
        created, _, _ = producer.create(
            project_id=self.env.project_id,
            source_agent="claude",
            target_agent="codex",
            task="Write the integration tests",
            repository_identity=_repo(self.env),
            warnings=["the fixture clock is frozen"],
        )
        consumer = HandoffService(self.env.service, clock=lambda: FIXED_NOW)
        inbox = consumer.list(
            project_id=self.env.project_id, target_agent="codex"
        )
        self.assertEqual(len(inbox), 1)
        self.assertEqual(inbox[0].handoff_id, created.handoff_id)
        self.assertEqual(inbox[0].source_agent, "claude")

    def test_target_agent_is_intent_not_access_control(self):
        producer = HandoffService(self.env.service, clock=lambda: FIXED_NOW)
        created, _, _ = producer.create(
            project_id=self.env.project_id,
            source_agent="opencode",
            target_agent="claude",
            task="Only for claude",
            repository_identity=_repo(self.env),
        )
        # Every agent on the project can read a PROJECT_SHARED handoff.
        # Filtering by target is a convenience, never a permission.
        other = HandoffService(self.env.service, clock=lambda: FIXED_NOW)
        self.assertIsNotNone(
            other.get(
                project_id=self.env.project_id, handoff_id=created.handoff_id
            )
        )


class CrossWorkspacePortabilityTests(unittest.TestCase):
    def setUp(self):
        self.env = Env(seed=False)
        self.addCleanup(self.env.cleanup)

    def test_same_handoff_id_across_workspaces(self):
        """Identity is logical: it must not encode a machine path."""
        a = build_handoff(
            project_id=self.env.project_id,
            source_agent="opencode",
            task="shared task",
            created_at=FIXED_NOW,
        )
        b = build_handoff(
            project_id=self.env.project_id,
            source_agent="opencode",
            task="shared task",
            created_at="2030-05-05T05:05:05+00:00",
        )
        self.assertEqual(a.handoff_id, b.handoff_id)

    def test_portable_payload_carries_no_absolute_path(self):
        service = HandoffService(self.env.service, clock=lambda: FIXED_NOW)
        handoff, _, _ = service.create(
            project_id=self.env.project_id,
            source_agent="opencode",
            task="Work in C:\\Users\\me\\repo and /home/me/repo",
            summary="built at C:\\build\\out",
            repository_identity=_repo(self.env),
        )
        payload = handoff.to_portable_dict()
        for value in _strings(payload):
            self.assertFalse(
                contains_absolute_path(value),
                f"absolute path leaked into portable output: {value!r}",
            )


def _repo(env):
    return env.registry.projects[env.project_id].repository_identity.to_dict()


def _strings(value):
    """Yield every string in a nested structure."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


if __name__ == "__main__":
    unittest.main()
