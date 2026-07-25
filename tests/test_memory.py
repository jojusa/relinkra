"""Offline deterministic tests for the R1C memory policy layer."""

from __future__ import annotations

import json
import unittest

from relinkra.engram_adapter import InMemoryStore, StoredRecord
from relinkra.memory import (
    ENVELOPE_VERSION,
    Memory,
    MemoryNotFoundError,
    MemoryService,
    MemoryValidationError,
    compute_dedup_key,
    normalize_for_dedup,
    redact_text,
    sanitize_error,
    scope_channel_for,
    storage_type_for,
    topic_key_for,
    validate_project_id,
    validate_repository_identity,
)

PID_A = "rlk_" + "a" * 32
PID_B = "rlk_" + "b" * 32
WID_1 = "ws_" + "1" * 32
WID_2 = "ws_" + "2" * 32

REPO = {
    "kind": "remote",
    "value": "remote://git/github.com/org/repo",
    "trust": "strong",
}


def make_service(store=None):
    store = store or InMemoryStore()
    tick = {"n": 0}

    def clock():
        tick["n"] += 1
        return f"2026-01-01T00:00:{tick['n']:02d}+00:00"

    ids = {"n": 0}

    def id_gen():
        ids["n"] += 1
        return f"mem_{ids['n']:016x}"

    return MemoryService(store, clock=clock, id_generator=id_gen), store


def save_shared(service, title="T", body="B", **kw):
    defaults = dict(
        project_id=PID_A,
        memory_type="decision",
        title=title,
        body=body,
        repository_identity=REPO,
        scope="project_shared",
    )
    defaults.update(kw)
    return service.save(**defaults)


class TestTypeMapping(unittest.TestCase):
    def test_all_memory_types_map(self):
        expected = {
            "decision": "decision",
            "discovery": "discovery",
            "architecture": "architecture",
            "bug": "bugfix",
            "constraint": "config",
            "task_result": "manual",
            "verification": "manual",
            "pending": "manual",
            "handoff": "manual",
        }
        for logical, storage in expected.items():
            self.assertEqual(storage_type_for(logical), storage)

    def test_unknown_type_rejected(self):
        with self.assertRaises(MemoryValidationError):
            storage_type_for("nope")


class TestProjectBinding(unittest.TestCase):
    def test_valid_project_id(self):
        self.assertEqual(validate_project_id(PID_A), PID_A)

    def test_rejects_filesystem_path(self):
        for bad in (
            r"C:\Desarrollos\relinkra",
            "/home/user/repo",
            "main",
            "e" * 40,
            "relinkra",
            "rlk_short",
            "rlk_" + "A" * 32,
        ):
            with self.assertRaises(MemoryValidationError, msg=bad):
                validate_project_id(bad)

    def test_repository_identity_validation(self):
        repo = validate_repository_identity(REPO)
        self.assertEqual(repo["kind"], "remote")
        with self.assertRaises(MemoryValidationError):
            validate_repository_identity(
                {"kind": "remote", "value": r"C:\path\repo", "trust": "strong"}
            )
        with self.assertRaises(MemoryValidationError):
            validate_repository_identity(
                {
                    "kind": "remote",
                    "value": "remote://git/user@github.com/org/repo",
                    "trust": "strong",
                }
            )
        with self.assertRaises(MemoryValidationError):
            validate_repository_identity({"kind": "nope", "value": "x", "trust": "strong"})

    def test_save_rejects_path_project(self):
        service, _ = make_service()
        with self.assertRaises(MemoryValidationError):
            save_shared(service, project_id=r"C:\Desarrollos\relinkra")


class TestEnvelopeSerialization(unittest.TestCase):
    def test_round_trip(self):
        service, _ = make_service()
        memory, _, _ = save_shared(
            service,
            title="Chose Engram",
            body="Shared backend",
            branch="main",
            commit_sha="abc123",
            confidence=0.9,
            agent_id="agent-1",
            agent_type="opencode",
            source_tool="opencode",
        )
        line = memory.envelope_json()
        self.assertNotIn("\n", line)
        restored = Memory.from_envelope(json.loads(line))
        self.assertEqual(restored.memory_id, memory.memory_id)
        self.assertEqual(restored.project_id, PID_A)
        self.assertEqual(restored.repository_identity, REPO)
        self.assertEqual(restored.branch, "main")
        self.assertEqual(restored.commit_sha, "abc123")
        self.assertEqual(restored.source_tool, "opencode")
        self.assertEqual(restored.memory_type, "decision")
        self.assertAlmostEqual(restored.confidence, 0.9)

    def test_envelope_has_marker_and_topic(self):
        service, store = make_service()
        save_shared(service, title="Marker Check")
        stored = store.saved_args[0]
        env = json.loads(stored["content"])
        self.assertEqual(env["v"], ENVELOPE_VERSION)
        self.assertEqual(stored["project"], PID_A)
        self.assertEqual(stored["scope"], "project")
        self.assertEqual(stored["storage_type"], "decision")
        self.assertEqual(
            stored["topic_key"],
            f"relinkra/v1/{PID_A}/shared/decision/marker-check",
        )

    def test_from_envelope_rejects_malformed(self):
        with self.assertRaises(MemoryValidationError):
            Memory.from_envelope({"v": "other", "memory_id": "x"})
        with self.assertRaises(MemoryValidationError):
            Memory.from_envelope({"v": ENVELOPE_VERSION, "memory_id": "x"})


class TestScopeChannels(unittest.TestCase):
    def test_channels(self):
        self.assertEqual(scope_channel_for("project_shared"), "shared")
        self.assertEqual(
            scope_channel_for("workspace_local", workspace_id=WID_1),
            f"ws/{WID_1}",
        )
        self.assertEqual(
            scope_channel_for("agent_private", agent_type="OpenCode"),
            "agent/opencode",
        )

    def test_workspace_scope_requires_workspace_id(self):
        with self.assertRaises(MemoryValidationError):
            scope_channel_for("workspace_local")

    def test_agent_scope_requires_agent_type(self):
        with self.assertRaises(MemoryValidationError):
            scope_channel_for("agent_private")

    def test_topic_key_per_scope(self):
        self.assertEqual(
            topic_key_for(PID_A, "shared", "bug", "Fix login!"),
            f"relinkra/v1/{PID_A}/shared/bug/fix-login",
        )
        self.assertEqual(
            topic_key_for(PID_A, f"ws/{WID_1}", "pending", "Todo"),
            f"relinkra/v1/{PID_A}/ws/{WID_1}/pending/todo",
        )


class TestRetrievalPolicy(unittest.TestCase):
    def setUp(self):
        self.service, self.store = make_service()
        save_shared(self.service, title="Shared fact", body="s1")
        save_shared(
            self.service,
            title="WS1 note",
            body="w1",
            scope="workspace_local",
            workspace_id=WID_1,
        )
        save_shared(
            self.service,
            title="WS2 note",
            body="w2",
            scope="workspace_local",
            workspace_id=WID_2,
        )
        save_shared(
            self.service,
            title="OC private",
            body="p1",
            scope="agent_private",
            agent_type="opencode",
        )
        save_shared(
            self.service,
            title="Codex private",
            body="p2",
            scope="agent_private",
            agent_type="codex",
        )
        save_shared(self.service, title="Other project", body="x", project_id=PID_B)

    def titles(self, result):
        return sorted(m.title for m in result.memories)

    def test_shared_query_returns_only_shared(self):
        result = self.service.query(project_id=PID_A, scope="project_shared")
        self.assertEqual(self.titles(result), ["Shared fact"])

    def test_workspace_query_returns_shared_plus_own_workspace(self):
        result = self.service.query(
            project_id=PID_A, scope="workspace_local", workspace_id=WID_1
        )
        self.assertEqual(self.titles(result), ["Shared fact", "WS1 note"])

    def test_workspace_query_requires_workspace_id(self):
        with self.assertRaises(MemoryValidationError):
            self.service.query(project_id=PID_A, scope="workspace_local")

    def test_agent_private_only_matching_agent(self):
        result = self.service.query(
            project_id=PID_A, scope="agent_private", agent_type="opencode"
        )
        self.assertEqual(self.titles(result), ["OC private"])

    def test_agent_private_requires_agent_type(self):
        with self.assertRaises(MemoryValidationError):
            self.service.query(project_id=PID_A, scope="agent_private")

    def test_cross_project_isolation(self):
        result = self.service.query(project_id=PID_B, scope="project_shared")
        self.assertEqual(self.titles(result), ["Other project"])
        result = self.service.query(
            project_id=PID_B, scope="agent_private", agent_type="opencode"
        )
        self.assertEqual(self.titles(result), [])

    def test_project_id_mandatory(self):
        with self.assertRaises(MemoryValidationError):
            self.service.query(project_id="", scope="project_shared")

    def test_memory_type_filter(self):
        save_shared(self.service, title="A bug", body="b", memory_type="bug")
        result = self.service.query(
            project_id=PID_A, scope="project_shared", memory_type="bug"
        )
        self.assertEqual(self.titles(result), ["A bug"])

    def test_text_search(self):
        result = self.service.query(
            project_id=PID_A, scope="project_shared", text="Shared"
        )
        self.assertEqual(self.titles(result), ["Shared fact"])


class TestLifecycle(unittest.TestCase):
    def test_same_topic_save_supersedes_prior(self):
        service, _ = make_service()
        first, _, _ = save_shared(service, title="Plan", body="v1")
        second, _, superseded = save_shared(service, title="Plan", body="v2")
        self.assertEqual(superseded, [first.memory_id])
        self.assertEqual(second.supersedes, first.memory_id)

        result = service.query(project_id=PID_A, scope="project_shared")
        self.assertEqual([m.body for m in result.memories], ["v2"])

        history = service.query(
            project_id=PID_A, scope="project_shared", include_history=True
        )
        self.assertEqual(sorted(m.body for m in history.memories), ["v1", "v2"])
        old = next(m for m in history.memories if m.body == "v1")
        self.assertEqual(old.superseded_by, second.memory_id)

    def test_history_never_deleted(self):
        service, store = make_service()
        save_shared(service, title="Plan", body="v1")
        save_shared(service, title="Plan", body="v2")
        self.assertEqual(len(store.saved_args), 2)

    def test_supersede_command_replaces(self):
        service, _ = make_service()
        first, _, _ = save_shared(service, title="Doc", body="old")
        replacement, superseded = service.supersede(
            memory_id=first.memory_id,
            project_id=PID_A,
            title="Doc",
            body="new",
        )
        self.assertEqual(superseded, [first.memory_id])
        result = service.query(project_id=PID_A, scope="project_shared")
        self.assertEqual([m.body for m in result.memories], ["new"])
        self.assertEqual(replacement.supersedes, first.memory_id)

    def test_supersede_obsolete_tombstone(self):
        service, _ = make_service()
        first, _, _ = save_shared(service, title="Stale", body="old")
        tombstone, superseded = service.supersede(
            memory_id=first.memory_id, project_id=PID_A, obsolete=True
        )
        self.assertEqual(tombstone.status, "obsolete")
        self.assertEqual(superseded, [first.memory_id])
        result = service.query(project_id=PID_A, scope="project_shared")
        self.assertEqual(result.memories, [])
        history = service.query(
            project_id=PID_A, scope="project_shared", include_history=True
        )
        self.assertEqual(len(history.memories), 2)

    def test_supersede_unknown_memory(self):
        service, _ = make_service()
        with self.assertRaises(MemoryNotFoundError):
            service.supersede(
                memory_id="mem_missing", project_id=PID_A, body="x"
            )

    def test_supersede_requires_content_or_obsolete(self):
        service, _ = make_service()
        first, _, _ = save_shared(service, title="Doc", body="old")
        with self.assertRaises(MemoryValidationError):
            service.supersede(memory_id=first.memory_id, project_id=PID_A)


class TestDedup(unittest.TestCase):
    def test_explicit_supersedes_bypasses_dedup(self):
        # Regression: save A old, save C new, supersede A with C's
        # title/body. Without the fix, dedup would early-return C and A
        # would never be linked or excluded.
        service, store = make_service()
        a, _, _ = save_shared(service, title="Old", body="old body")
        c, _, _ = save_shared(service, title="New", body="new body")
        replacement, superseded = service.supersede(
            memory_id=a.memory_id, project_id=PID_A, title="New", body="new body"
        )
        self.assertEqual(superseded, [a.memory_id])
        self.assertNotEqual(replacement.memory_id, c.memory_id)
        self.assertEqual(replacement.supersedes, a.memory_id)
        self.assertEqual(len(store.saved_args), 3)

        result = service.query(project_id=PID_A, scope="project_shared")
        self.assertNotIn(a.memory_id, [m.memory_id for m in result.memories])

        history = service.query(
            project_id=PID_A, scope="project_shared", include_history=True
        )
        old = next(m for m in history.memories if m.memory_id == a.memory_id)
        self.assertEqual(old.superseded_by, replacement.memory_id)

    def test_identical_save_returns_existing(self):
        service, store = make_service()
        first, dedup1, _ = save_shared(service, title="Fact", body="Body")
        second, dedup2, _ = save_shared(service, title="Fact", body="Body")
        self.assertFalse(dedup1)
        self.assertTrue(dedup2)
        self.assertEqual(first.memory_id, second.memory_id)
        self.assertEqual(len(store.saved_args), 1)

    def test_normalization_dedups(self):
        service, store = make_service()
        save_shared(service, title="  FACT!! ", body="Body   with\n space")
        _, dedup, _ = save_shared(service, title="fact", body="body with space")
        self.assertTrue(dedup)
        self.assertEqual(len(store.saved_args), 1)

    def test_different_scope_not_deduped(self):
        service, store = make_service()
        save_shared(service, title="Fact", body="Body")
        _, dedup, _ = save_shared(
            service,
            title="Fact",
            body="Body",
            scope="workspace_local",
            workspace_id=WID_1,
        )
        self.assertFalse(dedup)
        self.assertEqual(len(store.saved_args), 2)

    def test_different_agent_private_not_deduped(self):
        service, store = make_service()
        save_shared(
            service, title="Fact", body="Body",
            scope="agent_private", agent_type="opencode",
        )
        _, dedup, _ = save_shared(
            service, title="Fact", body="Body",
            scope="agent_private", agent_type="codex",
        )
        self.assertFalse(dedup)
        self.assertEqual(len(store.saved_args), 2)

    def test_dedup_key_deterministic(self):
        k1 = compute_dedup_key(PID_A, "project_shared", "decision", "T!", "B")
        k2 = compute_dedup_key(PID_A, "project_shared", "decision", "t", "b")
        self.assertEqual(k1, k2)
        self.assertEqual(normalize_for_dedup("  Hi,  THERE! "), "hi, there")


class TestRedaction(unittest.TestCase):
    def test_bearer_token(self):
        out = redact_text("use Bearer abcdef123456.token-here please")
        self.assertNotIn("abcdef123456", out)
        self.assertIn("Bearer [REDACTED]", out)

    def test_api_key_prefixes(self):
        for token in (
            "sk-" + "a" * 30,
            "sk_live_" + "b" * 20,
            "ghp_" + "c" * 30,
            "github_pat_" + "d" * 30,
            "glpat-" + "e" * 20,
            "AKIA" + "F" * 16,
            "xoxb-" + "1" * 12,
        ):
            self.assertNotIn(token, redact_text(f"key={token}"))

    def test_jwt(self):
        jwt = "eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 8
        self.assertNotIn(jwt, redact_text(jwt))

    def test_password_in_url(self):
        out = redact_text("clone https://user:hunter2@github.com/org/repo.git")
        self.assertNotIn("hunter2", out)
        self.assertIn("https://user:[REDACTED]@github.com", out)

    def test_private_key_block(self):
        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIBlah\n-----END RSA PRIVATE KEY-----"
        )
        out = redact_text(f"before {pem} after")
        self.assertNotIn("MIIBlah", out)
        self.assertEqual(out, "before [REDACTED] after")

    def test_generic_key_values(self):
        for kv in (
            "token=abc123",
            "api_key: abc123",
            'password="abc 123"',
            "API_KEY='abc123'",
        ):
            out = redact_text(kv)
            self.assertNotIn("abc123", out)
            self.assertIn("[REDACTED]", out)

    def test_redaction_applied_before_persistence(self):
        service, store = make_service()
        secret = "sk-" + "z" * 30
        save_shared(service, title="Leak?", body=f"key is {secret}")
        env = store.saved_args[0]["content"]
        self.assertNotIn(secret, env)
        self.assertNotIn(secret, store.saved_args[0]["title"])

    def test_errors_do_not_echo_secrets(self):
        secret = "hunter2"
        msg = sanitize_error(f"failed on https://u:{secret}@h/x with token={secret}")
        self.assertNotIn(secret, msg)


class TestQueryStorePaging(unittest.TestCase):
    class SpyStore(InMemoryStore):
        def __init__(self):
            super().__init__()
            self.requested_limits = []

        def search_records(self, *, query, project=None, storage_type=None, limit=50):
            self.requested_limits.append(limit)
            return super().search_records(
                query=query, project=project, storage_type=storage_type, limit=limit
            )

    def test_store_page_is_fixed_and_independent_of_user_limit(self):
        service, store = make_service(store=self.SpyStore())
        save_shared(service, title="One", body="1")
        save_shared(service, title="Two", body="2")
        save_shared(service, title="Three", body="3")
        result = service.query(project_id=PID_A, scope="project_shared", limit=2)
        self.assertEqual(len(result.memories), 2)
        self.assertEqual([m.title for m in result.memories], ["Two", "Three"])
        self.assertIn(200, store.requested_limits)
        self.assertNotIn(2, store.requested_limits)

    def test_filtering_happens_before_user_limit(self):
        # Newer records in a non-visible channel must not starve visible
        # results when the user limit is small.
        service, store = make_service(store=self.SpyStore())
        save_shared(service, title="Shared keep", body="s")
        for i in range(5):
            save_shared(
                service,
                title=f"WS noise {i}",
                body="n",
                scope="workspace_local",
                workspace_id=WID_1,
            )
        result = service.query(project_id=PID_A, scope="project_shared", limit=1)
        self.assertEqual([m.title for m in result.memories], ["Shared keep"])

    def test_nonpositive_limit_rejected(self):
        service, _ = make_service()
        for bad in (0, -1, -50):
            with self.assertRaises(MemoryValidationError, msg=str(bad)):
                service.query(project_id=PID_A, scope="project_shared", limit=bad)


class TestMalformedStoredEnvelopes(unittest.TestCase):
    def test_garbage_records_skipped_and_counted(self):
        service, store = make_service()
        save_shared(service, title="Good", body="ok")
        store._records.append(
            StoredRecord(
                record_id="99",
                storage_type="manual",
                title=ENVELOPE_VERSION,
                content="not json at all " + ENVELOPE_VERSION,
                project=PID_A,
                scope="project",
                timestamp="2026-01-01 00:00:00",
            )
        )
        store._records.append(
            StoredRecord(
                record_id="100",
                storage_type="manual",
                title=ENVELOPE_VERSION,
                content=json.dumps({"v": ENVELOPE_VERSION, "incomplete": True}),
                project=PID_A,
                scope="project",
                timestamp="2026-01-01 00:00:01",
            )
        )
        result = service.query(project_id=PID_A, scope="project_shared")
        self.assertEqual([m.title for m in result.memories], ["Good"])
        self.assertEqual(result.skipped_malformed, 2)


if __name__ == "__main__":
    unittest.main()
