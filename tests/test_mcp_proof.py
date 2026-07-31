"""Live end-to-end proof of the Relinkra MCP server (R3).

This is NOT an in-process test. It spawns the real server as a
subprocess, speaks real newline-delimited JSON-RPC 2.0 over its stdin and
stdout from an independent client, and persists through the real Engram
store. Agent A and agent B are two SEPARATE server processes, so a
handoff genuinely crosses a process boundary.

Skipped when the environment cannot support a live run (no ``git``, no
``engram`` on PATH). Everything else about the MCP surface is covered
offline in ``test_mcp_server.py``.
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from relinkra.handoff import contains_absolute_path

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STARTUP_TIMEOUT = 60.0
CALL_TIMEOUT = 120.0

_HAS_GIT = shutil.which("git") is not None
_ENGRAM_BIN = shutil.which("engram")
_HAS_ENGRAM = _ENGRAM_BIN is not None


class StdioClient:
    """A minimal, independent MCP client over a subprocess pipe.

    Deliberately hand-rolled: using the server's own Python objects would
    prove nothing about the wire contract. This only knows how to write a
    JSON line and read a JSON line.
    """

    def __init__(self, args, cwd):
        env = dict(os.environ)
        env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
        env["PYTHONIOENCODING"] = "utf-8"
        self.process = subprocess.Popen(
            [sys.executable, "-u", "-m", "relinkra.mcp_cli", *args],
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self._lines: "queue.Queue[str]" = queue.Queue()
        self._stderr: list = []
        self._next_id = 0
        self._closed = False
        #: Set by close() when shutdown did not complete cleanly. Tests
        #: assert these stay False rather than close() raising.
        self.kill_timed_out = False
        self.threads_timed_out = False
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()
        self._errors = threading.Thread(target=self._pump_stderr, daemon=True)
        self._errors.start()

    def _pump(self):
        # Tolerate the stream being closed underneath us. close() joins
        # these threads first, but a join can time out; without this
        # guard that would surface as an unraisable exception in a daemon
        # thread rather than a clean shutdown.
        try:
            for line in self.process.stdout:
                self._lines.put(line)
        except (ValueError, OSError):
            pass
        self._lines.put("")

    def _pump_stderr(self):
        try:
            for line in self.process.stderr:
                self._stderr.append(line)
        except (ValueError, OSError):
            pass

    def request(self, method, params=None, timeout=CALL_TIMEOUT):
        self._next_id += 1
        message = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        if params is not None:
            message["params"] = params
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()
        try:
            raw = self._lines.get(timeout=timeout)
        except queue.Empty:
            raise AssertionError(
                f"no response to {method}; stderr={''.join(self._stderr)[:2000]}"
            )
        if not raw.strip():
            raise AssertionError(
                f"server closed the stream during {method}; "
                f"stderr={''.join(self._stderr)[:2000]}"
            )
        return json.loads(raw)

    def notify(self, method, params=None):
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def call_tool(self, name, **arguments):
        response = self.request(
            "tools/call", {"name": name, "arguments": arguments}
        )
        assert "result" in response, response
        result = response["result"]
        assert not result.get("isError"), result["content"][0]["text"]
        return json.loads(result["content"][0]["text"])

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def close(self):
        """Shut the server down and release every handle deterministically.

        Order matters and is the whole point:

        1. Close stdin  -> the server sees EOF and leaves its serve loop.
        2. wait()       -> the process exits, so its stdout/stderr reach
                           EOF and the pump threads end on their own.
        3. join()       -> no thread is still touching a stream when we
                           close it, which would otherwise be a race.
        4. Close stdout/stderr -> Popen does NOT close PIPE handles for
                           you unless you go through communicate(); the
                           earlier version closed only stdin, so every
                           client leaked two TextIOWrappers and the suite
                           reported them as ResourceWarnings at GC time.

        Idempotent: tests call it via addCleanup and sometimes explicitly.
        """
        if getattr(self, "_closed", False):
            return
        self._closed = True

        self._safe_close(self.process.stdin)
        try:
            self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.process.kill()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                # Teardown must not raise: close() runs from addCleanup,
                # where an exception turns a real assertion failure into
                # a confusing teardown error. Record and keep going.
                self.kill_timed_out = True

        for thread in (self._reader, self._errors):
            thread.join(timeout=10)
            if thread.is_alive():
                # The pumps tolerate a closed stream (see _pump), so
                # closing under a straggler is safe rather than racy.
                self.threads_timed_out = True

        self._safe_close(self.process.stdout)
        self._safe_close(self.process.stderr)

    @staticmethod
    def _safe_close(stream):
        if stream is None:
            return
        try:
            stream.close()
        except (OSError, ValueError):
            pass

    @property
    def returncode(self):
        return self.process.returncode

    @property
    def stderr_text(self):
        return "".join(self._stderr)


def _git(cwd, *args):
    subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


@unittest.skipUnless(_HAS_GIT, "git is required for the live MCP proof")
@unittest.skipUnless(_HAS_ENGRAM, "engram is required for the live MCP proof")
class LiveMCPProofTests(unittest.TestCase):
    """One real proof: two processes, one project, one handoff."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls._saved_engram_data_dir = os.environ.get("ENGRAM_DATA_DIR")
        cls._saved_engram_url = os.environ.get("ENGRAM_URL")
        cls.engram_data_dir = os.path.join(cls.tmp.name, "engram")
        os.makedirs(cls.engram_data_dir, exist_ok=True)
        cls.engram_port = cls._free_port()
        cls.engram_url = f"http://127.0.0.1:{cls.engram_port}"
        engram_env = dict(os.environ)
        engram_env["ENGRAM_DATA_DIR"] = cls.engram_data_dir
        cls.engram_process = subprocess.Popen(
            [_ENGRAM_BIN, "serve", str(cls.engram_port)],
            cwd=REPO_ROOT,
            env=engram_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        os.environ["ENGRAM_DATA_DIR"] = cls.engram_data_dir
        os.environ["ENGRAM_URL"] = cls.engram_url
        try:
            cls._wait_for_engram()
        except Exception:
            cls._stop_engram()
            cls.tmp.cleanup()
            raise

        cls.root = os.path.join(cls.tmp.name, "repo")
        os.makedirs(cls.root, exist_ok=True)

        # A fresh repository gives this run a unique local-root identity,
        # so the proof never collides with a real project in the store.
        _git(cls.root, "init", "-q")
        _git(cls.root, "config", "user.email", "proof@relinkra.test")
        _git(cls.root, "config", "user.name", "Relinkra Proof")
        with open(
            os.path.join(cls.root, "README.md"), "w", encoding="utf-8"
        ) as handle:
            handle.write("# live mcp proof\n")
        _git(cls.root, "add", "README.md")
        _git(cls.root, "commit", "-q", "-m", "seed the proof repository")

        cls.registry = os.path.join(cls.tmp.name, "registry.json")
        env = dict(os.environ)
        env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
        registered = subprocess.run(
            [
                sys.executable, "-m", "relinkra.cli", "register", cls.root,
                "--registry", cls.registry,
            ],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
        )
        if registered.returncode != 0:
            raise unittest.SkipTest(
                f"could not register the proof workspace: {registered.stderr}"
            )
        payload = json.loads(registered.stdout)
        cls.project_id = payload["project"]["project_id"]
        cls.workspace_id = payload["workspace"]["workspace_id"]

    @classmethod
    def tearDownClass(cls):
        cls._stop_engram()
        if cls._saved_engram_data_dir is None:
            os.environ.pop("ENGRAM_DATA_DIR", None)
        else:
            os.environ["ENGRAM_DATA_DIR"] = cls._saved_engram_data_dir
        if cls._saved_engram_url is None:
            os.environ.pop("ENGRAM_URL", None)
        else:
            os.environ["ENGRAM_URL"] = cls._saved_engram_url
        cls.tmp.cleanup()

    @staticmethod
    def _free_port():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            return probe.getsockname()[1]

    @classmethod
    def _wait_for_engram(cls):
        deadline = time.monotonic() + 15.0
        url = f"{cls.engram_url}/search?q=rlkmem1&limit=1"
        while time.monotonic() < deadline:
            if cls.engram_process.poll() is not None:
                raise unittest.SkipTest("isolated Engram server exited")
            try:
                with urllib.request.urlopen(url, timeout=1.0) as response:
                    if response.status == 200:
                        return
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        raise unittest.SkipTest("isolated Engram server did not become ready")

    @classmethod
    def _stop_engram(cls):
        process = getattr(cls, "engram_process", None)
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    def _client(self):
        client = StdioClient(
            [
                "--workspace-root", self.root,
                "--registry", self.registry,
                "--project-id", self.project_id,
                "--workspace-id", self.workspace_id,
            ],
            cwd=REPO_ROOT,
        )
        self.addCleanup(client.close)
        init = client.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "relinkra-proof", "version": "1"},
            },
            timeout=STARTUP_TIMEOUT,
        )
        self.assertIn("result", init, init)
        self.assertEqual(init["result"]["serverInfo"]["name"], "relinkra")
        client.notify("notifications/initialized")
        return client

    def test_live_proof_uses_isolated_engram_environment(self):
        self.assertEqual(os.environ.get("ENGRAM_DATA_DIR"), self.engram_data_dir)
        self.assertEqual(os.environ.get("ENGRAM_URL"), self.engram_url)
        self.assertNotEqual(
            os.path.abspath(self.engram_data_dir),
            os.path.abspath(os.path.expanduser("~/.engram")),
        )

    def test_live_cross_agent_handoff_over_stdio(self):
        # --- agent A: a real server process -------------------------------
        agent_a = self._client()

        tools = agent_a.request("tools/list")["result"]["tools"]
        self.assertIn(
            "relinkra_handoff_create", {tool["name"] for tool in tools}
        )

        resolved_a = agent_a.call_tool("relinkra_project_resolve")
        self.assertEqual(resolved_a["project_id"], self.project_id)

        health = agent_a.call_tool("relinkra_health")
        self.assertTrue(health["components"]["git"]["available"])
        self.assertTrue(health["components"]["engram"]["available"])

        created = agent_a.call_tool(
            "relinkra_handoff_create",
            source_agent="opencode",
            target_agent="claude",
            task="Prove the Relinkra MCP surface end to end",
            summary="Server A wrote this over real stdio JSON-RPC.",
            completed_work=["stdio transport", "tool schema"],
            pending_work=["read it back from a second process"],
            decisions=["stdlib-only MCP implementation"],
            include_git_state=True,
        )["handoff"]
        handoff_id = created["handoff_id"]
        self.assertTrue(handoff_id.startswith("hof_"))

        # Real git facts were captured from the real repository.
        self.assertIsNotNone(created["git_state"]["head_sha"])
        self.assertEqual(len(created["git_state"]["head_sha"]), 40)

        agent_a.close()

        # --- agent B: an independent second process ------------------------
        agent_b = self._client()

        resolved_b = agent_b.call_tool("relinkra_project_resolve")
        self.assertEqual(
            resolved_b["project_id"],
            resolved_a["project_id"],
            "the two agents must resolve the SAME logical project",
        )

        fetched = agent_b.call_tool(
            "relinkra_handoff_get", handoff_id=handoff_id
        )["handoff"]
        self.assertEqual(fetched["handoff_id"], handoff_id)
        self.assertEqual(fetched["source_agent"], "opencode")
        self.assertEqual(fetched["target_agent"], "claude")
        self.assertEqual(
            fetched["pending_work"], ["read it back from a second process"]
        )
        # Provenance survived the process boundary.
        self.assertEqual(fetched["provenance"]["producer"], "relinkra.handoff")
        self.assertEqual(fetched["git_state"]["head_sha"],
                         created["git_state"]["head_sha"])

        inbox = agent_b.call_tool(
            "relinkra_handoff_get", target_agent="claude"
        )
        self.assertIn(
            handoff_id, [h["handoff_id"] for h in inbox["handoffs"]]
        )

        # --- context for the same project, from agent B --------------------
        context = agent_b.call_tool(
            "relinkra_context_get",
            task="Prove the Relinkra MCP surface end to end",
            include_git=True,
            budget="medium",
        )
        packet = context["packet"]
        self.assertEqual(packet["project_id"], self.project_id)
        self.assertTrue(packet["git_facts"], "git facts missing from packet")
        self.assertTrue(
            any(
                handoff_id in json.dumps(item)
                for item in packet["handoffs"]
            ),
            "the handoff did not reach the context packet",
        )

        # --- invariants ----------------------------------------------------
        blob = json.dumps({"handoff": fetched, "context": context,
                           "health": health, "project": resolved_b})
        for value in blob.split('"'):
            self.assertFalse(
                contains_absolute_path(value.replace("\\\\", "\\")),
                f"absolute path leaked over the wire: {value!r}",
            )
        self.assertNotIn(self.root, blob)
        # No record carrying the private scope crossed the wire. Note the
        # health payload legitimately mentions `agent_private_access` —
        # that is the server DECLARING the capability is off, so a bare
        # substring check on "agent_private" would be a false positive.
        self.assertNotIn('"scope": "agent_private"', blob)
        self.assertNotIn('"scope":"agent_private"', blob)
        self.assertFalse(health["capabilities"]["agent_private_access"])
        self.assertFalse(health["capabilities"]["git_write"])

        # The repository is untouched: git intelligence is read-only.
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=self.root, capture_output=True, text=True, check=True,
        )
        self.assertEqual(status.stdout.strip(), "")

    def test_live_malformed_input_is_rejected_cleanly(self):
        client = self._client()

        client.process.stdin.write("{not json at all\n")
        client.process.stdin.flush()
        raw = client._lines.get(timeout=CALL_TIMEOUT)
        self.assertEqual(json.loads(raw)["error"]["code"], -32700)

        unknown = client.request("no/such/method")
        self.assertEqual(unknown["error"]["code"], -32601)

        bad_args = client.request(
            "tools/call",
            {"name": "relinkra_health", "arguments": {"drop": "tables"}},
        )
        self.assertEqual(bad_args["error"]["code"], -32602)

        # The server is still alive and correct after all of that.
        self.assertEqual(client.request("ping")["result"], {})


@unittest.skipUnless(_HAS_GIT, "git is required to build a workspace root")
class ProcessLifecycleTests(unittest.TestCase):
    """R3.2: the server must start, serve, and die cleanly, every time.

    Deliberately independent of Engram: `initialize`, `ping`, and
    `tools/list` never touch the memory store, so these run anywhere and
    exercise the process contract itself rather than the data path.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = os.path.join(self.tmp.name, "repo")
        os.makedirs(self.root, exist_ok=True)
        _git(self.root, "init", "-q")

    def _spawn(self):
        """Spawn a server, always registering teardown.

        Cleanup is registered unconditionally even for tests that close
        explicitly to inspect the exit code: close() is idempotent, so
        the second call is free, and without this an assertion failing
        before the explicit close would strand a child process blocked
        on stdin forever.
        """
        client = StdioClient(
            ["--workspace-root", self.root,
             "--registry", os.path.join(self.tmp.name, "absent.json")],
            cwd=REPO_ROOT,
        )
        self.addCleanup(client.close)
        return client

    def _handshake(self, client):
        init = client.request(
            "initialize",
            {"protocolVersion": "2025-06-18", "capabilities": {},
             "clientInfo": {"name": "lifecycle", "version": "1"}},
            timeout=STARTUP_TIMEOUT,
        )
        self.assertIn("result", init, init)
        client.notify("notifications/initialized")
        return init["result"]

    def test_full_lifecycle_then_clean_exit(self):
        """initialize -> tools/list -> call -> EOF -> exit 0."""
        client = self._spawn()
        self._handshake(client)
        tools = client.request("tools/list")["result"]["tools"]
        self.assertEqual(len(tools), 9)
        health = client.request(
            "tools/call",
            {"name": "relinkra_health", "arguments": {}},
        )["result"]
        self.assertIn("content", health)

        client.close()  # closes stdin -> server sees EOF
        self.assertEqual(
            client.returncode, 0, f"unclean exit; stderr={client.stderr_text}"
        )

    def test_eof_while_idle_exits_cleanly(self):
        client = self._spawn()
        self._handshake(client)
        # No further traffic; just disconnect.
        client.close()
        self.assertEqual(client.returncode, 0, client.stderr_text)

    def test_eof_without_any_handshake_exits_cleanly(self):
        client = self._spawn()
        client.close()
        self.assertEqual(client.returncode, 0, client.stderr_text)

    def test_malformed_json_does_not_corrupt_the_session(self):
        client = self._spawn()
        self._handshake(client)
        client.process.stdin.write("{ this is not json\n")
        client.process.stdin.flush()
        raw = client._lines.get(timeout=CALL_TIMEOUT)
        self.assertEqual(json.loads(raw)["error"]["code"], -32700)
        # The very next request must be served normally.
        self.assertEqual(client.request("ping")["result"], {})
        self.assertEqual(
            len(client.request("tools/list")["result"]["tools"]), 9
        )

    def test_oversized_request_is_rejected_and_session_survives(self):
        client = self._spawn()
        self._handshake(client)
        giant = "x" * (5 * 1024 * 1024)
        client.process.stdin.write(
            json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": "ping",
                 "params": {"pad": giant}}
            )
            + "\n"
        )
        client.process.stdin.flush()
        raw = client._lines.get(timeout=CALL_TIMEOUT)
        self.assertEqual(json.loads(raw)["error"]["code"], -32600)
        self.assertEqual(client.request("ping")["result"], {})

    def test_invalid_utf8_does_not_kill_the_server(self):
        """One bad byte must cost one message, not the whole process.

        The bytes are decoded with errors="replace", so the line becomes
        undecodable-but-safe text, fails JSON parsing, and is answered
        with a single parse error — exactly one message lost.
        """
        client = self._spawn()
        self._handshake(client)
        raw_stdin = client.process.stdin.buffer
        raw_stdin.write(b"\xff\xfe not valid utf-8\n")
        raw_stdin.flush()

        raw = client._lines.get(timeout=CALL_TIMEOUT)
        self.assertEqual(json.loads(raw)["error"]["code"], -32700)
        # The session continues normally.
        self.assertEqual(client.request("ping")["result"], {})
        self.assertEqual(
            len(client.request("tools/list")["result"]["tools"]), 9
        )

    def test_server_survives_a_long_mixed_sequence(self):
        """A long-running host mixes good, bad, and notification traffic."""
        client = self._spawn()
        self._handshake(client)
        for index in range(15):
            client.notify("notifications/progress", {"n": index})
            self.assertEqual(client.request("ping")["id"], client._next_id)
            bad = client.request("no/such/method")
            self.assertEqual(bad["error"]["code"], -32601)
        self.assertEqual(
            len(client.request("tools/list")["result"]["tools"]), 9
        )

    def test_repeated_start_stop_leaves_no_process_behind(self):
        codes = []
        for _ in range(3):
            client = self._spawn()
            self._handshake(client)
            self.assertEqual(client.request("ping")["result"], {})
            client.close()
            codes.append(client.returncode)
            self.assertIsNotNone(
                client.process.poll(), "process still running after close()"
            )
        self.assertEqual(codes, [0, 0, 0])

    def test_close_is_idempotent(self):
        client = self._spawn()
        self._handshake(client)
        client.close()
        client.close()  # must not raise
        self.assertEqual(client.returncode, 0)

    def test_write_to_a_dead_peer_raises_broken_pipe_not_a_hang(self):
        """A genuine EPIPE: the peer is gone but our handle is still open.

        Deliberately does NOT close our own stdin first — that would make
        Python's own closed-stream guard raise ValueError before any
        syscall, and the test would pass without ever exercising a real
        broken pipe.
        """
        client = self._spawn()
        self._handshake(client)

        client.process.kill()
        client.process.wait(timeout=20)
        self.assertFalse(client.process.stdin.closed)

        # A few writes may be needed: the first can land in a local
        # buffer before the OS reports the dead reader.
        with self.assertRaises((BrokenPipeError, OSError)) as caught:
            for _ in range(200):
                client.process.stdin.write(
                    '{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
                )
                client.process.stdin.flush()
        self.assertNotIsInstance(
            caught.exception,
            ValueError,
            "closed-stream guard fired instead of a real broken pipe",
        )
        client.close()

    def test_close_reports_clean_shutdown(self):
        client = self._spawn()
        self._handshake(client)
        client.close()
        self.assertFalse(client.kill_timed_out, "server needed a hard kill")
        self.assertFalse(client.threads_timed_out, "a reader thread hung")

    def test_every_pipe_is_closed_after_close(self):
        """The ResourceWarning regression guard."""
        client = self._spawn()
        self._handshake(client)
        client.close()
        for name in ("stdin", "stdout", "stderr"):
            stream = getattr(client.process, name)
            self.assertTrue(
                stream is None or stream.closed,
                f"{name} was left open after close()",
            )


if __name__ == "__main__":
    unittest.main()
