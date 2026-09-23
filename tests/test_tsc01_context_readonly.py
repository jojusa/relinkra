"""TSC-01 — context_get read-only semantics vs observability writes.

Permanent matrix for the 0.1.5 hardening unit (base 7b344ce):

- A successful ``context_get`` never modifies authoritative state: the
  registry file stays byte-identical, the in-memory memory store does
  not change, and nothing outside ``.relinkra/`` appears in the
  workspace.
- The call DOES persist bounded local observability where expected:
  one allow-listed metrics observation under
  ``.relinkra/metrics/context/`` and runtime-evidence events under
  ``.relinkra/runtime-evidence/`` (recorded only on success).
- Neither store carries the task text (prompt) passed to the call nor
  seeded memory titles/bodies: read-only means "no authoritative
  mutation", and the observability side channel stays content-free.

The ``readOnlyHint: True`` annotation on ``context_get`` itself is
pinned by ``test_mcp_server.test_annotations_truthfully_mark_read_only_tools``;
this file pins the behavioral contract behind that hint. See
``docs/mcp-surface.md`` ("Read-only semantics") for the documented
contract.
"""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from relinkra.app_service import RelinkraServices, ServiceConfig
from relinkra.mcp_server import MCPServer
from relinkra.runtime_evidence import (
    EVENT_CONTEXT_GET_CALLED,
    EVENT_TOOL_INVOKED,
    EvidenceRecorder,
    host_evidence_path,
)

from test_context_packet import Env
from test_mcp_server import RecordingGitService

#: Distinctive prompt text: must never reach either observability store.
TASK_SENTINEL = "TSC01-TASK-SENTINEL-DO-NOT-PERSIST"
#: Seeded by ``Env.seed_memories`` — must never reach the metrics store.
SEEDED_TITLE = "Use JWT for auth"
SEEDED_BODY = "the parser skipped a line"


def _file_digest(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _store_digest(store) -> str:
    """Stable digest of the whole in-memory store (append-only)."""
    blob = json.dumps(vars(store), sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class ContextGetReadOnlyContractTests(unittest.TestCase):
    """The TSC-01 contract, exercised through the real MCP dispatch path."""

    def setUp(self):
        self.env = Env(seed=True)
        self.addCleanup(self.env.cleanup)
        self.recorder = EvidenceRecorder(
            self.env.ws_dir, "codex", revision="a" * 40
        )
        self.services = RelinkraServices(
            config=ServiceConfig(
                registry_path=self.env.registry_path,
                default_project_id=self.env.project_id,
                default_workspace_id=self.env.workspace_id,
                workspace_root=self.env.ws_dir,
            ),
            store=self.env.store,
            registry=self.env.registry,
            git_service=RecordingGitService(),
        )
        self.server = MCPServer(
            self.services, evidence_recorder=self.recorder
        )
        self.registry_before = _file_digest(self.env.registry_path)
        self.memory_before = _store_digest(self.env.store)
        response = self.server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "context_get",
                    "arguments": {"task": TASK_SENTINEL},
                },
            }
        )
        self.assertIn("result", response)
        self.result = response["result"]
        self.assertNotEqual(self.result.get("isError"), True)

    def test_authoritative_state_is_unchanged(self):
        # Registry (identity authority) is byte-identical after the call.
        self.assertEqual(
            _file_digest(self.env.registry_path), self.registry_before
        )
        # Memory store (append-only) did not change: no save, no supersede.
        self.assertEqual(_store_digest(self.env.store), self.memory_before)
        # Nothing outside .relinkra/ appeared in the workspace.
        stray = [
            p
            for p in Path(self.env.ws_dir).rglob("*")
            if p.is_file() and ".relinkra" not in p.parts
        ]
        self.assertEqual(stray, [])

    def test_observability_is_persisted_where_expected(self):
        metrics_dir = (
            Path(self.env.ws_dir) / ".relinkra" / "metrics" / "context"
        )
        metric_files = sorted(metrics_dir.glob("*.json"))
        self.assertTrue(
            metric_files, "context_get must append a metrics observation"
        )
        rows = []
        for path in metric_files:
            data = json.loads(path.read_text(encoding="utf-8"))
            rows.extend(data.get("observations") or [])
        self.assertGreaterEqual(len(rows), 1)

        evidence = json.loads(
            Path(host_evidence_path(self.env.ws_dir, "codex")).read_text(
                encoding="utf-8"
            )
        )
        events = evidence["events"]
        self.assertIn(EVENT_CONTEXT_GET_CALLED, events)
        self.assertGreaterEqual(
            events[EVENT_CONTEXT_GET_CALLED]["count"], 1
        )
        self.assertIn(EVENT_TOOL_INVOKED, events)
        self.assertEqual(
            events[EVENT_TOOL_INVOKED]["detail"]["tool"], "context_get"
        )

    def test_observability_stores_exclude_task_and_memory_content(self):
        json_blobs = [
            p.read_text(encoding="utf-8")
            for p in (Path(self.env.ws_dir) / ".relinkra").rglob("*.json")
        ]
        self.assertTrue(json_blobs, "observability stores must exist")
        blob = "\n".join(json_blobs)
        self.assertNotIn(TASK_SENTINEL, blob)
        self.assertNotIn(SEEDED_TITLE, blob)
        self.assertNotIn(SEEDED_BODY, blob)


if __name__ == "__main__":
    unittest.main()
