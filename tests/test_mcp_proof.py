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
import subprocess
import sys
import tempfile
import threading
import unittest

from relinkra.handoff import contains_absolute_path

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STARTUP_TIMEOUT = 60.0
CALL_TIMEOUT = 120.0

_HAS_GIT = shutil.which("git") is not None
_HAS_ENGRAM = shutil.which("engram") is not None


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
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()
        self._errors = threading.Thread(target=self._pump_stderr, daemon=True)
        self._errors.start()

    def _pump(self):
        for line in self.process.stdout:
            self._lines.put(line)
        self._lines.put("")

    def _pump_stderr(self):
        for line in self.process.stderr:
            self._stderr.append(line)

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

    def close(self):
        try:
            self.process.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)

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
        cls.tmp.cleanup()

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


if __name__ == "__main__":
    unittest.main()
