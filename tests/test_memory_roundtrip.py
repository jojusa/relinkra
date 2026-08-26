"""R5J.2 — memory round-trip integrity against the real Engram store.

Pins the contract that a memory written through Relinkra comes back
whole, and that whatever the transport loses is counted honestly:

- Full-fidelity round-trip: with an isolated ``ENGRAM_DATA_DIR`` (and no
  external ``ENGRAM_URL``), the adapter's loopback server serves the
  same data dir, so envelopes read back complete — zero skips anywhere.
- HTTP control path: an explicitly configured endpoint behaves
  identically (read_mode == "http").
- Degraded honesty: hard-off mode (``http_url=""``) degrades to the CLI
  text output; cut-off envelopes surface as ``skipped_truncated``, never
  inflating ``skipped_malformed``.
- Fail-safe parsing: external garbage rows stay skipped as malformed
  while valid memories remain retrievable.
- Project isolation, multi-type provenance, and offline accounting are
  exercised against the real store or deterministic fakes respectively.

Integration classes skip gracefully when the ``engram`` binary is
absent. Every store is ISOLATED: scratch ``ENGRAM_DATA_DIR``, one
TemporaryDirectory per class, processes and files cleaned up via
``addCleanup``.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

from relinkra.app_service import RelinkraServices, ServiceConfig
from relinkra.context_builder import ContextBuilder, ContextRequest
from relinkra.engram_adapter import (
    EngramCLIAdapter,
    StoredRecord,
    _LOOPBACK_SERVERS,
    _close_all_loopbacks,
    _shared_loopback,
    parse_search_output,
)
from relinkra.identity import explicit_identity
from relinkra.memory import MemoryService
from relinkra.registry import Registry

_ENGRAM_BIN = shutil.which("engram")

FIXED_NOW = "2026-08-26T00:00:00+00:00"

PID_A = "rlk_" + "b0c0ffee" * 4
PID_B = "rlk_" + "c0ffee00" * 4
IDENTITY_A = {"kind": "explicit", "value": "explicit://roundtrip-a", "trust": "strong"}
IDENTITY_B = {"kind": "explicit", "value": "explicit://roundtrip-b", "trust": "strong"}

READY_TIMEOUT_SECONDS = 20.0


def _cleanup_tmp_dir(tmp: tempfile.TemporaryDirectory) -> None:
    """Remove a scratch dir, tolerating Windows handle-release races.

    Right after a killed ``engram`` child exits, Windows (and the
    occasional AV scanner) can still hold one of its SQLite files for a
    moment, making ``rmtree`` fail with "directory not empty". Retry
    briefly; a PERSISTENT lock still raises — that is exactly the
    process-leak signal this suite must keep visible.
    """
    last_error: OSError | None = None
    for attempt in range(8):
        try:
            tmp.cleanup()
            return
        except OSError as exc:
            last_error = exc
            time.sleep(0.5)
    raise last_error


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _spawn_engram_server(engram_bin: str, data_dir: str, port: int):
    """Start ``engram serve`` over an isolated data dir; return the child."""
    env = dict(os.environ)
    env["ENGRAM_DATA_DIR"] = data_dir
    popen_kwargs = {}
    create_no_window = getattr(subprocess, "CREATE_NO_WINDOW", None)
    if create_no_window is not None:
        popen_kwargs["creationflags"] = create_no_window
    return subprocess.Popen(
        [engram_bin, "serve", str(port)],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **popen_kwargs,
    )


def _stop_engram_server(process) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def _wait_until_ready(url: str, process) -> bool:
    deadline = time.monotonic() + READY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(url, timeout=1.0) as response:
                if response.status == 200:
                    return True
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    return False


class _IsolatedStoreCase(unittest.TestCase):
    """Shared plumbing: one scratch ENGRAM_DATA_DIR + registry per class."""

    @classmethod
    def setUpClass(cls):
        if _ENGRAM_BIN is None:
            raise unittest.SkipTest("engram binary not available on PATH")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(_cleanup_tmp_dir, cls.tmp)
        cls.addClassCleanup(_close_all_loopbacks)
        cls.data_dir = os.path.join(cls.tmp.name, "engram")
        os.makedirs(cls.data_dir, exist_ok=True)
        cls.registry_path = os.path.join(cls.tmp.name, "registry.json")
        cls._saved_env = {
            key: os.environ.get(key) for key in ("ENGRAM_DATA_DIR", "ENGRAM_URL")
        }
        os.environ["ENGRAM_DATA_DIR"] = cls.data_dir
        os.environ.pop("ENGRAM_URL", None)
        cls.addClassCleanup(cls._restore_env)

    @classmethod
    def tearDownClass(cls):
        # Kill loopback children eagerly so they never outlive the class.
        _close_all_loopbacks()

    @classmethod
    def _restore_env(cls):
        for key, value in cls._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    @classmethod
    def make_store(cls, **overrides) -> EngramCLIAdapter:
        overrides.setdefault("engram_bin", _ENGRAM_BIN)
        return EngramCLIAdapter(**overrides)

    @classmethod
    def make_services(cls, store, project_ids=(("a", IDENTITY_A),)):
        """Services bound to a registry holding the given explicit projects."""
        registry = Registry(cls.registry_path)
        ids = {}
        for suffix, identity in project_ids:
            directory = os.path.join(cls.tmp.name, f"repo-{suffix}")
            os.makedirs(directory, exist_ok=True)
            workspace = registry.register_workspace(directory, explicit_identity(identity["value"].split("://", 1)[1]))
            ids[suffix] = workspace.project_id
        services = RelinkraServices(
            config=ServiceConfig(registry_path=cls.registry_path),
            store=store,
            registry=registry,
            clock=lambda: FIXED_NOW,
        )
        return services, ids


@unittest.skipUnless(_ENGRAM_BIN, "engram is required for roundtrip proof")
class TestR5J1ExactRegression(_IsolatedStoreCase):
    """The measured defect, pinned green: isolation now reads whole.

    R5J.1 reproduced: CLI-only reads turned every saved envelope into a
    skipped_malformed casualty. With the loopback tier engaging over the
    isolated data dir, the same flow must round-trip perfectly.
    """

    TITLE = "Roundtrip regression probe"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.store = cls.make_store()
        cls.services, cls.ids = cls.make_services(cls.store)
        cls.project_id = cls.ids["a"]

    def test_r5j1_saved_memory_roundtrips_without_any_skips(self):
        saved = self.services.memory_save(
            project_id=self.project_id,
            memory_type="decision",
            title=self.TITLE,
            body="root-cause regression envelope for R5J.1/R5J.2",
            confidence=0.87,
        )
        self.assertEqual(saved["project_id"], self.project_id)
        self.assertTrue(saved["memory_id"])

        # Direct interop: the RAW engram CLI finds the row under this
        # project — Relinkra wrote something the store itself can find.
        raw = subprocess.run(
            [
                _ENGRAM_BIN, "search", "regression",
                "--project", self.project_id, "--limit", "25",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        records = parse_search_output(raw.stdout)
        self.assertTrue(
            any(r.title == self.TITLE for r in records),
            f"raw engram search missed the saved row: {raw.stdout!r}",
        )

        # The physical row is a complete rlkmem1 envelope. Completeness
        # is proven against the store's own HTTP channel (the raw CLI
        # TEXT output truncates display at ~300 chars BY DESIGN of
        # engram; that is the transport limitation this change routes
        # around, not a property of the stored data).
        loopback = _shared_loopback(_ENGRAM_BIN, self.data_dir)
        self.assertIsNotNone(loopback)
        self.assertTrue(loopback.base_url)
        with urllib.request.urlopen(
            f"{loopback.base_url}/search?q=regression&limit=10", timeout=5
        ) as response:
            rows = json.loads(response.read().decode("utf-8"))
        row = next(r for r in rows if r.get("title") == self.TITLE)
        envelope = json.loads(row["content"])
        self.assertEqual(envelope["v"], "rlkmem1")
        self.assertEqual(envelope["memory_id"], saved["memory_id"])

        # Through the policy layer: found, fully accounted.
        search = self.services.memory_search(
            project_id=self.project_id, query="regression probe"
        )
        self.assertEqual(search["count"], 1)
        self.assertEqual(search["skipped_malformed"], 0)
        self.assertEqual(search["skipped_truncated"], 0)
        self.assertEqual(
            [m["title"] for m in search["memories"]], [self.TITLE]
        )

        packet = self.services.context_get(
            project_id=self.project_id,
            task=f"{self.TITLE} integrity",
            include_git=False,
        )["packet"]
        # Portable packet shape: each entry nests the memory under
        # "data" (plus "explain"/"provenance" siblings).
        self.assertTrue(
            any(m["data"]["title"] == self.TITLE for m in packet["memories"]),
            "context_get packet must contain the saved memory",
        )
        self.assertEqual(packet["diagnostics"]["skipped_malformed"], 0)
        self.assertEqual(packet["diagnostics"]["skipped_truncated"], 0)


@unittest.skipUnless(_ENGRAM_BIN, "engram is required for roundtrip proof")
class TestHTTPControlPath(_IsolatedStoreCase):
    """Explicitly configured HTTP endpoint: identical round-trip, tier 1."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.port = _free_port()
        cls.url = f"http://127.0.0.1:{cls.port}"
        cls.server_process = _spawn_engram_server(
            _ENGRAM_BIN, cls.data_dir, cls.port
        )
        cls.addClassCleanup(_stop_engram_server, cls.server_process)
        if not _wait_until_ready(
            f"{cls.url}/search?q=e&limit=1", cls.server_process
        ):
            raise unittest.SkipTest("isolated Engram server did not become ready")
        cls.store = cls.make_store(http_url=cls.url)
        cls.services, cls.ids = cls.make_services(cls.store)
        cls.project_id = cls.ids["a"]

    def test_roundtrip_reports_http_read_mode(self):
        self.services.memory_save(
            project_id=self.project_id,
            memory_type="discovery",
            title="HTTP control probe",
            body="round trip through the explicitly configured endpoint",
        )
        search = self.services.memory_search(
            project_id=self.project_id, query="control probe"
        )
        self.assertEqual(search["count"], 1)
        self.assertEqual(search["skipped_malformed"], 0)
        self.assertEqual(search["skipped_truncated"], 0)
        self.assertEqual(self.store.read_mode, "http")


@unittest.skipUnless(_ENGRAM_BIN, "engram is required for roundtrip proof")
class TestDegradedHonesty(_IsolatedStoreCase):
    """Hard-off adapter: transport loss counted honestly, not as corruption."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.store = cls.make_store(http_url="")
        cls.services, cls.ids = cls.make_services(cls.store)
        cls.project_id = cls.ids["a"]

    def test_hard_off_query_counts_truncated_not_malformed(self):
        saved = self.services.memory_save(
            project_id=self.project_id,
            memory_type="decision",
            title="Honesty degradation probe",
            body="written fine; unreadable through the truncated CLI text path",
        )
        self.assertTrue(saved["memory_id"])
        self.assertFalse(self.store.allow_loopback)

        search = self.services.memory_search(
            project_id=self.project_id, query="honesty"
        )
        self.assertEqual(
            [m["title"] for m in search["memories"]],
            [],
            "hard-off transport cannot deliver the memory",
        )
        self.assertEqual(search["skipped_truncated"], 1)
        self.assertEqual(search["skipped_malformed"], 0)


@unittest.skipUnless(_ENGRAM_BIN, "engram is required for roundtrip proof")
class TestMalformedStaysFailsafe(_IsolatedStoreCase):
    """External garbage rows never break retrieval of valid memories.

    Reads run through the full-fidelity tiers on purpose: the valid
    envelope must be DELIVERED while the garbage row — which the same
    page hands back, FTS matching its injected token — lands in the
    parser and is counted as malformed.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.store = cls.make_store()
        cls.services, cls.ids = cls.make_services(cls.store)
        cls.project_id = cls.ids["a"]

    def test_garbage_row_is_skipped_and_valid_memory_survives(self):
        self.services.memory_save(
            project_id=self.project_id,
            memory_type="decision",
            title="Failsafe survivor",
            body="valid memory beside a corrupted row",
        )
        # Inject garbage EXACTLY like a foreign tool would: raw CLI save,
        # non-JSON content that still carries the FTS token queries use.
        injected = subprocess.run(
            [
                _ENGRAM_BIN, "save", "junk-title",
                "rlkmem1 not-json{{{ broken envelope fragment",
                "--type", "manual",
                "--project", self.project_id,
                "--scope", "project",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        self.assertEqual(injected.returncode, 0, injected.stderr)

        search = self.services.memory_search(
            project_id=self.project_id, query="rlkmem1"
        )
        self.assertEqual(
            [m["title"] for m in search["memories"]], ["Failsafe survivor"]
        )
        self.assertGreaterEqual(search["skipped_malformed"], 1)
        self.assertEqual(search["skipped_truncated"], 0)

        packet = self.services.context_get(
            project_id=self.project_id,
            task="failsafe survivor retrieval",
            include_git=False,
        )["packet"]
        titles = [m["data"]["title"] for m in packet["memories"]]
        self.assertIn("Failsafe survivor", titles)
        self.assertNotIn("junk-title", titles)


@unittest.skipUnless(_ENGRAM_BIN, "engram is required for roundtrip proof")
class TestProjectIsolationReal(_IsolatedStoreCase):
    """Two projects, one physical store: zero leakage, explicit ids kept."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.store = cls.make_store()
        cls.services, cls.ids = cls.make_services(
            cls.store,
            project_ids=(("a", IDENTITY_A), ("b", IDENTITY_B)),
        )

    def test_memory_saved_in_a_never_leaks_into_b(self):
        saved = self.services.memory_save(
            project_id=self.ids["a"],
            memory_type="decision",
            title="Island memory",
            body="belongs to project A only",
        )
        self.assertEqual(saved["project_id"], self.ids["a"])

        search_b = self.services.memory_search(
            project_id=self.ids["b"], query="island"
        )
        # Explicit project_id is honored verbatim — never swapped for
        # another registered project by auto-resolution.
        self.assertEqual(search_b["project_id"], self.ids["b"])
        self.assertEqual(search_b["count"], 0)
        self.assertEqual(search_b["memories"], [])

        search_a = self.services.memory_search(
            project_id=self.ids["a"], query="island"
        )
        self.assertEqual(search_a["count"], 1)


@unittest.skipUnless(_ENGRAM_BIN, "engram is required for roundtrip proof")
class TestMultiTypeAndProvenance(_IsolatedStoreCase):
    """Multiple memory types round-trip with provenance intact."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.store = cls.make_store()
        cls.services, cls.ids = cls.make_services(cls.store)
        cls.project_id = cls.ids["a"]
        cls.confidences = {
            "decision": 0.5,
            "bug": 0.75,
            "discovery": 0.9,
        }
        for memory_type, confidence in cls.confidences.items():
            cls.services.memory_save(
                project_id=cls.project_id,
                memory_type=memory_type,
                title=f"Provenance {memory_type}",
                body=f"provenance survival check for {memory_type}",
                confidence=confidence,
            )

    def test_each_type_filters_and_carries_provenance(self):
        for memory_type, confidence in self.confidences.items():
            search = self.services.memory_search(
                project_id=self.project_id,
                query="provenance",
                memory_type=memory_type,
            )
            self.assertEqual(search["count"], 1, memory_type)
            memory = search["memories"][0]
            self.assertEqual(memory["memory_type"], memory_type)
            self.assertEqual(memory["source_tool"], "relinkra")
            self.assertTrue(memory["timestamp"])
            self.assertAlmostEqual(memory["confidence"], confidence)
            self.assertEqual(
                memory["repository_identity"]["kind"], IDENTITY_A["kind"]
            )
            self.assertEqual(
                memory["repository_identity"]["value"], IDENTITY_A["value"]
            )


class _ScriptedStore:
    """Offline store handing back a fixed record page."""

    def __init__(self, records):
        self._records = list(records)

    def save_record(self, **kwargs) -> str:
        return "1"

    def search_records(self, *, query, project=None, storage_type=None, limit=50):
        return list(self._records)


class TestAccountingOffline(unittest.TestCase):
    """Counter semantics over deterministic fakes — no server involved."""

    PID = "rlk_" + "a11ce5ed" * 4
    IDENTITY = {
        "kind": "explicit",
        "value": "explicit://accounting-offline",
        "trust": "strong",
    }

    def setUp(self):
        # A valid envelope produced by the real policy layer.
        seed_service = MemoryService(_ScriptedStore([]))
        memory, _, _ = seed_service.save(
            project_id=self.PID,
            memory_type="decision",
            title="Coincidental dots",
            body="valid envelope that merely looks suspicious",
            repository_identity=self.IDENTITY,
        )
        self.good_title = memory.title
        self.good_content = memory.envelope_json()

    def _records(self):
        return [
            # Parses fine; a conservative truncation flag is IGNORED on
            # success (the flag describes the transport's best guess).
            StoredRecord(
                record_id="1",
                storage_type="manual",
                title=self.good_title,
                content=self.good_content,
                project=self.PID,
                scope="project",
                timestamp="2026-08-26 00:00:01",
                truncated=True,
            ),
            # Genuinely broken data, no flag -> malformed.
            StoredRecord(
                record_id="2",
                storage_type="manual",
                title="garbage",
                content="not json {{{",
                project=self.PID,
                scope="project",
                timestamp="2026-08-26 00:00:02",
                truncated=False,
            ),
            # Cut off by the transport (flagged) -> truncated counter.
            StoredRecord(
                record_id="3",
                storage_type="manual",
                title="cut",
                content='{"v":"rlkmem1","memory_id":"mem_x',
                project=self.PID,
                scope="project",
                timestamp="2026-08-26 00:00:03",
                truncated=True,
            ),
        ]

    def test_counters_aggregate_in_query_result(self):
        service = MemoryService(_ScriptedStore(self._records()))
        result = service.query(project_id=self.PID, scope="project_shared")
        self.assertEqual([m.title for m in result.memories], [self.good_title])
        self.assertEqual(result.skipped_malformed, 1)
        self.assertEqual(result.skipped_truncated, 1)
        payload = result.to_dict()
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["skipped_malformed"], 1)
        self.assertEqual(payload["skipped_truncated"], 1)

    def test_counters_surface_in_context_builder_diagnostics(self):
        service = MemoryService(_ScriptedStore(self._records()))
        builder = ContextBuilder(memory_service=service)
        packet = builder.build(
            ContextRequest(
                project_id=self.PID,
                task="coincidental dots accounting",
                include_agent_private=False,
                include_git=False,
            )
        )
        self.assertEqual(packet.diagnostics["skipped_malformed"], 1)
        self.assertEqual(packet.diagnostics["skipped_truncated"], 1)


class _NeverSpawnCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if _ENGRAM_BIN is None:
            raise unittest.SkipTest("engram binary not available on PATH")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(_cleanup_tmp_dir, cls.tmp)
        cls.addClassCleanup(_close_all_loopbacks)

    @property
    def data_dir(self):
        return os.path.join(self.tmp.name, f"engram-{id(self)}")


@unittest.skipUnless(_ENGRAM_BIN, "engram is required for the lifecycle proof")
class TestLoopbackLifecycle(_NeverSpawnCase):
    """Hard-off never spawns; allow-loopback shares one child; clean exit."""

    def test_hard_off_adapter_never_spawns_a_server(self):
        recorded = mock.MagicMock(side_effect=AssertionError("spawn attempted"))
        with mock.patch(
            "relinkra.engram_adapter.subprocess.Popen", recorded
        ), mock.patch.object(
            EngramCLIAdapter,
            "_run",
            return_value='No memories found for: "x"',
        ):
            adapter = EngramCLIAdapter(engram_bin=_ENGRAM_BIN, http_url="")
            self.assertFalse(adapter.allow_loopback)
            records = adapter.search_records(
                query="x", project=PID_A, limit=5
            )
        self.assertEqual(records, [])
        recorded.assert_not_called()

    def test_shared_loopback_spawns_once_and_closes_cleanly(self):
        data_dir = self.data_dir
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ["ENGRAM_DATA_DIR"] = data_dir
        os.environ.pop("ENGRAM_URL", None)

        first = EngramCLIAdapter(engram_bin=_ENGRAM_BIN)
        second = EngramCLIAdapter(engram_bin=_ENGRAM_BIN)
        self.assertTrue(first.allow_loopback)
        self.assertEqual(first.search_records(query="rlkmem1"), [])
        self.assertEqual(second.search_records(query="rlkmem1"), [])
        for adapter in (first, second):
            self.assertEqual(adapter.read_mode, "loopback")

        server = _LOOPBACK_SERVERS.get((_ENGRAM_BIN, data_dir))
        self.assertIsNotNone(server)
        self.assertIs(_shared_loopback(_ENGRAM_BIN, data_dir), server)
        self.assertIsNotNone(server.base_url)

        server.close()
        server.close()  # idempotent
        self.assertIsNotNone(server._process)
        self.assertIsNotNone(server._process.poll(), "child must be gone")

        _close_all_loopbacks()
        self.assertEqual(_LOOPBACK_SERVERS, {})


if __name__ == "__main__":
    unittest.main()
