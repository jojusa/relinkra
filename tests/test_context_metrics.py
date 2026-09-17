"""Permanent VIS-3 tests for extraction and the bounded local store."""

from __future__ import annotations

import json
import http.client
import shutil
import threading
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from relinkra import context_metrics
from relinkra import viewer


def packet(*, revision: str = "a" * 40, retrieval=True) -> dict:
    diagnostics = {
        "budget": {"truncated_source_ids": ["snippet:ref"]},
        "counts": {"snippets": 3},
    }
    if retrieval is not None:
        diagnostics["retrieval_complete"] = retrieval
    if retrieval is True:
        diagnostics["retrieval_diagnostic"] = {"code": "complete_export"}
        diagnostics["retrieval_scope"] = "complete_export"
    elif retrieval is False:
        diagnostics["retrieval_scopes"] = ["partial"]
    return {
        "packet_id": "pkt_demo",
        "created_at": "2026-01-01T00:00:00+00:00",
        "project_id": "rlk_demo",
        "workspace_id": "ws_demo",
        "task": "DO_NOT_PERSIST_PROMPT",
        "project_facts": {"workspace": {"current_revision": revision}},
        "memories": [{"body": "DO_NOT_PERSIST_MEMORY"}],
        "code_references": [{"file_path": "DO_NOT_PERSIST_PATH"}],
        "code_facts": [{"data": {"snippet": "DO_NOT_PERSIST_SNIPPET"}}],
        "handoffs": [{"body": "DO_NOT_PERSIST_HANDOFF"}],
        "pending": [{"body": "DO_NOT_PERSIST_PENDING"}],
        "git_facts": [{"subject": "fact"}],
        "packet_status": {
            "token_accounting": {
                "total_estimated_tokens": 101,
                "useful_payload_tokens": 77,
                "metadata_tokens": 24,
                "estimation_version": "cpt1.v1",
                "accounting_basis": "utf8_envelope",
            },
            "packet_complete": False,
            "budget_exhausted": True,
            "omitted_sections": ["memories", "handoffs"],
            "omitted_high_salience_count": 2,
            "context_sufficiency": {
                "orientation": "partial",
                "implementation": "source_verification_required",
            },
        },
        "diagnostics": diagnostics,
    }


class ExtractionTests(unittest.TestCase):
    def test_final_settled_values_and_counts_are_projected_without_bodies(self):
        observation = context_metrics.extract_context_observation(packet())
        self.assertEqual(observation["schema_version"], 1)
        self.assertEqual(observation["accounting"]["final_cpt1"], 101)
        self.assertEqual(observation["accounting"]["useful_cpt1"], 77)
        self.assertEqual(observation["accounting"]["metadata_cpt1"], 24)
        self.assertEqual(observation["composition"]["memory_facts"], 1)
        self.assertEqual(observation["composition"]["code_references"], 1)
        self.assertEqual(observation["composition"]["code_facts"], 1)
        self.assertEqual(observation["composition"]["handoffs"], 1)
        self.assertEqual(observation["composition"]["pending"], 1)
        self.assertEqual(observation["composition"]["git_facts"], 1)
        self.assertFalse(observation["quality"]["packet_complete"])
        self.assertTrue(observation["quality"]["budget_exhausted"])
        self.assertEqual(observation["quality"]["omitted_high_salience"], 2)
        self.assertTrue(observation["quality"]["truncated"])
        self.assertEqual(observation["retrieval"]["complete"], True)
        rendered = json.dumps(observation)
        for canary in (
            "DO_NOT_PERSIST_PROMPT", "DO_NOT_PERSIST_MEMORY", "DO_NOT_PERSIST_PATH",
            "DO_NOT_PERSIST_SNIPPET", "DO_NOT_PERSIST_HANDOFF",
        ):
            self.assertNotIn(canary, rendered)

    def test_retrieval_unknown_is_not_coerced_to_false(self):
        observation = context_metrics.extract_context_observation(packet(retrieval=None))
        self.assertIsNone(observation["retrieval"]["complete"])

    def test_retrieval_false_is_preserved(self):
        observation = context_metrics.extract_context_observation(packet(retrieval=False))
        self.assertFalse(observation["retrieval"]["complete"])


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.root = Path.cwd() / (".vis3-metrics-test-" + uuid.uuid4().hex)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def append(self, index: int, *, bucket: str = "host_unknown"):
        value = context_metrics.extract_context_observation(
            {**packet(), "packet_id": "pkt_" + str(index),
             "created_at": (datetime(2026, 1, 1, tzinfo=timezone.utc)
                            + timedelta(minutes=index)).isoformat()}
        )
        return context_metrics.append_observation(str(self.root), value, bucket=bucket)

    def test_bounded_retention_and_current_selection(self):
        for index in range(105):
            self.assertTrue(self.append(index))
        path = context_metrics.metrics_path(str(self.root), "host_unknown")
        self.assertLessEqual(path.stat().st_size, context_metrics.MAX_STORE_BYTES)
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(len(data["observations"]), 100)
        self.assertEqual(data["observations"][0]["packet_id"], "pkt_5")
        loaded, status = context_metrics.load_observations_with_status(str(self.root))
        self.assertEqual(status, "ok")
        self.assertEqual(len(loaded), 100)
        current = context_metrics.metrics_payload(
            str(self.root), project_id="rlk_demo", workspace_id="ws_demo",
            revision="a" * 40,
        )
        self.assertEqual(current["currentness"], "current")
        self.assertEqual(current["observation"]["packet_id"], "pkt_104")

    def test_same_bucket_concurrent_writers_leave_valid_json(self):
        results = []
        threads = [threading.Thread(target=lambda i=i: results.append(self.append(i))) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        path = context_metrics.metrics_path(str(self.root), "host_unknown")
        self.assertTrue(path.is_file())
        self.assertTrue(all(results))
        self.assertIsInstance(json.loads(path.read_text(encoding="utf-8")), dict)

    def test_corrupt_store_is_degraded_and_does_not_fabricate_history(self):
        path = context_metrics.metrics_path(str(self.root), "host_unknown")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not-json", encoding="utf-8")
        payload = context_metrics.metrics_payload(
            str(self.root), project_id="rlk_demo", workspace_id="ws_demo",
            revision="a" * 40,
        )
        self.assertTrue(payload["no_data"])
        self.assertEqual(payload["storage"], "degraded")

    def test_write_failure_is_non_blocking(self):
        with mock.patch.object(context_metrics, "atomic_write_text", side_effect=OSError("disk")):
            self.assertFalse(self.append(1))


class MetricsRouteTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.server = viewer.create_server(
            lambda: {},
            metrics_current_provider=lambda params: {
                "schema_version": 1, "currentness": "current",
                "observation": {"accounting": {"final_cpt1": 4}},
                "no_data": False,
            },
            metrics_history_provider=lambda params: {
                "schema_version": 1, "history": [], "count": 0,
                "no_data": True, "storage": "absent",
            },
            port=0,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(5)
        self.server.server_close()

    def request(self, method, path):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        try:
            connection.request(method, path)
            response = connection.getresponse()
            raw = response.read()
            try:
                payload = json.loads(raw or b"{}")
            except (TypeError, ValueError):
                payload = raw
            return response.status, payload
        finally:
            connection.close()

    def test_current_and_history_are_read_only_json_routes(self):
        status, current = self.request("GET", "/api/metrics/current")
        self.assertEqual(status, 200)
        self.assertEqual(current["observation"]["accounting"]["final_cpt1"], 4)
        status, history = self.request("GET", "/api/metrics/history?limit=1000")
        self.assertEqual(status, 200)
        self.assertEqual(history["count"], 0)
        status, _ = self.request("POST", "/api/metrics/current")
        self.assertEqual(status, 405)

    def test_absent_metrics_provider_is_structured_no_data(self):
        server = viewer.create_server(lambda: {}, port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        connection = None
        try:
            connection = http.client.HTTPConnection(*server.server_address, timeout=5)
            connection.request("GET", "/api/metrics/current")
            response = connection.getresponse()
            payload = json.loads(response.read())
            self.assertEqual(response.status, 200)
            self.assertTrue(payload["no_data"])
            self.assertEqual(payload["storage"], "unavailable")
        finally:
            if connection is not None:
                connection.close()
            server.shutdown()
            thread.join(5)
            server.server_close()


class ExactRevisionCurrentnessTests(unittest.TestCase):
    """CURRENT requires exact full revision equality (no 12-char prefixes).

    A stored abbreviation (legacy rows) or a same-prefix/different-tail
    revision is never CURRENT; legacy rows are left untouched and classify
    conservatively as STALE.
    """

    HEAD = "0123456789abcdef0123456789abcdef01234567"
    SHORT = HEAD[:12]

    def observation(self, revision):
        return context_metrics.extract_context_observation(
            {
                "packet_id": "pkt_revision",
                "created_at": "2026-01-01T00:00:00+00:00",
                "project_id": "rlk_revision",
                "workspace_id": "ws_revision",
                "project_facts": {"workspace": {"current_revision": revision}},
                "packet_status": {
                    "token_accounting": {
                        "total_estimated_tokens": 5,
                        "useful_payload_tokens": 4,
                        "metadata_tokens": 1,
                        "estimation_version": "cpt1.v1",
                        "accounting_basis": "utf8_envelope",
                    }
                },
            }
        )

    def classify(self, observed_revision, current_revision=HEAD):
        return context_metrics.classify_currentness(
            self.observation(observed_revision),
            project_id="rlk_revision",
            workspace_id="ws_revision",
            revision=current_revision,
        )

    def test_exact_full_revision_equality_is_current(self):
        self.assertEqual(self.classify(self.HEAD), "current")

    def test_twelve_char_prefix_collision_is_not_current(self):
        collision = self.SHORT + "0" * (len(self.HEAD) - len(self.SHORT))
        self.assertEqual(collision[:12], self.HEAD[:12])
        self.assertNotEqual(collision, self.HEAD)
        self.assertEqual(self.classify(collision), "stale")

    def test_legacy_short_revision_is_conservatively_stale(self):
        self.assertEqual(self.classify(self.SHORT), "stale")

    def test_legacy_short_row_is_never_rewritten(self):
        root = Path.cwd() / (".vis3-exact-revision-" + uuid.uuid4().hex)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        observation = self.observation(self.SHORT)
        self.assertEqual(observation["identity"]["revision"], self.SHORT)
        self.assertTrue(context_metrics.append_observation(str(root), observation))
        loaded = context_metrics.load_observations(str(root))
        self.assertEqual(loaded[-1]["identity"]["revision"], self.SHORT)
        payload = context_metrics.metrics_payload(
            str(root),
            project_id="rlk_revision",
            workspace_id="ws_revision",
            revision=self.HEAD,
        )
        self.assertEqual(payload["currentness"], "stale")

    def test_full_snapshot_revision_is_not_truncated_on_store(self):
        observation = self.observation(self.HEAD)
        self.assertEqual(observation["identity"]["revision"], self.HEAD)


if __name__ == "__main__":
    unittest.main()
