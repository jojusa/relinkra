"""TSC-02 — Engram loopback transport bounds and provenance hardening.

Permanent matrix for the 0.1.5 hardening unit (base 0ac3252a):

- A normal bounded response is accepted; a moderate response near the
  chosen bound is accepted whole.
- An oversized response — advertised by ``Content-Length`` or actually
  sent with a missing/lying header — is refused before it can be
  materialized or parsed; partial JSON is never accepted.
- The endpoint policy accepts loopback forms only (``127.0.0.1``,
  ``::1``, ``localhost``) and refuses non-loopback, credentialed,
  malformed, and unsupported-scheme URLs WITHOUT sending a request.
- Redirects are refused, so no response can move the transport off the
  validated destination.
- Transport reachability is never provenance: a reachable endpoint
  serving a forged/foreign/malformed envelope delivers nothing through
  the R1C policy layer.
- Pagination (cap recovery via complete export), exact ``memory_get``,
  history/supersede semantics, and managed ``ENGRAM_DATA_DIR`` loopback
  mode keep working.

Every server in this file is a disposable loopback HTTP server and every
adapter is isolated from any real Engram store (``allow_loopback``
disabled plus a mocked CLI tier, except the managed-mode test which uses
a scratch ``ENGRAM_DATA_DIR`` and cleans its child process up). Nothing
here contacts an external host, port 7437, or a real user store.
"""

from __future__ import annotations

import http.server
import json
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

from relinkra.engram_adapter import EngramCLIAdapter
from relinkra.memory import MemoryService

# The transport-policy names below exist only from TSC-02 onward. They are
# imported defensively so this file can also be executed against the BASE
# commit (git-archive extraction) to prove the exact regressions FAIL
# before the fix. On BASE the fallbacks make the policy-only tests fail
# loudly, which is the honest signal for a missing feature.
try:  # pragma: no cover - the import succeeds on the fixed tree
    from relinkra.engram_adapter import (  # noqa: F401
        ENGRAM_HTTP_MAX_RESPONSE_BYTES,
        EngramResponseTooLargeError,
        validate_engram_endpoint,
    )
except ImportError:  # pragma: no cover - BASE-only execution path
    ENGRAM_HTTP_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
    EngramResponseTooLargeError = None
    validate_engram_endpoint = None

_ENGRAM_BIN = shutil.which("engram")

PID_A = "rlk_" + "a" * 32
PID_B = "rlk_" + "b" * 32
WID_A = "ws_" + "a" * 32
WID_B = "ws_" + "b" * 32
REPO_IDENTITY = {
    "kind": "explicit",
    "value": "explicit://tsc02-transport",
    "trust": "strong",
}
OVERSIZED_SENTINEL = "TSC02-OVERSIZED-PAYLOAD-SENTINEL"
MODERATE_BODY_BYTES = 2 * 1024 * 1024


def envelope(
    memory_id: str,
    project_id: str,
    *,
    title: str = "tsc02 memory",
    body: str = "tsc02 body",
    memory_type: str = "decision",
    status: str = "active",
    scope_channel="shared",
    topic_key=None,
    timestamp: str = "2026-09-20T00:00:00+00:00",
    supersedes=None,
) -> dict:
    """One canonical ``rlkmem1`` envelope for transport-level fixtures."""
    data = {
        "v": "rlkmem1",
        "memory_id": memory_id,
        "project_id": project_id,
        "memory_type": memory_type,
        "title": title,
        "body": body,
        "timestamp": timestamp,
        "repository_identity": REPO_IDENTITY,
        "scope": "project_shared",
        "topic_key": topic_key
        or f"relinkra/v1/{project_id}/shared/{memory_type}/tsc02",
        "status": status,
    }
    if scope_channel is not None:
        data["scope_channel"] = scope_channel
    if supersedes:
        data["supersedes"] = supersedes
    return data


def record(
    memory_id: str,
    project_id: str,
    *,
    timestamp: str = "2026-09-20 00:00:00",
    **envelope_kwargs,
) -> dict:
    """One HTTP-API record wrapping an envelope, as ``GET /search`` returns."""
    env = envelope(memory_id, project_id, **envelope_kwargs)
    return {
        "id": memory_id,
        "type": "decision",
        "title": env["title"],
        "content": json.dumps(env),
        "project": project_id,
        "scope": "project",
        "timestamp": timestamp,
    }


class _LoopbackFixture:
    """Disposable loopback HTTP server with a per-request responder.

    HTTP/1.0 on purpose: a response without ``Content-Length`` is
    close-delimited, which is exactly the "no declared length" case the
    transport bound must survive. Threads are daemons and the socket is
    closed deterministically on exit.
    """

    def __init__(self, responder, host: str = "127.0.0.1"):
        fixture = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def do_GET(self):  # noqa: N802
                fixture.requests.append(self.path)
                try:
                    responder(self)
                except OSError:
                    # The client may refuse an oversized response and hang
                    # up while the body is still being written; that is the
                    # behavior under test, not a fixture failure.
                    pass

            def handle_one_request(self):
                try:
                    super().handle_one_request()
                except OSError:
                    self.close_connection = True

            def log_message(self, *args):  # silence fixture chatter
                pass

        self.host = host
        self._httpd = http.server.ThreadingHTTPServer((host, 0), _Handler)
        self._httpd.daemon_threads = True
        self.port = self._httpd.server_address[1]
        self.requests: list = []
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            kwargs={"poll_interval": 0.02},
            daemon=True,
        )

    @property
    def url(self) -> str:
        literal = self.host if ":" not in self.host else f"[{self.host}]"
        return f"http://{literal}:{self.port}"

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(5)
        return False


def _send_bytes(handler, payload: bytes, content_length="auto", status=200):
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    if content_length == "auto":
        handler.send_header("Content-Length", str(len(payload)))
    elif content_length is not None:
        handler.send_header("Content-Length", str(content_length))
    handler.end_headers()
    handler.wfile.write(payload)


def _send_json(handler, payload, content_length="auto", status=200):
    _send_bytes(
        handler, json.dumps(payload).encode("utf-8"), content_length, status
    )


def _isolated_adapter(base_url: str, **kwargs) -> EngramCLIAdapter:
    """An adapter that can only reach the disposable fixture.

    ``allow_loopback`` is disabled so a refused or failed HTTP tier can
    never spawn ``engram serve`` over a real data directory; the CLI tier
    is mocked per test (see :func:`_cli_returns_nothing`).
    """
    adapter = EngramCLIAdapter(http_url=base_url, http_timeout=5.0, **kwargs)
    adapter.allow_loopback = False
    return adapter


def _cli_returns_nothing():
    return mock.patch(
        "relinkra.engram_adapter.subprocess.run",
        return_value=mock.Mock(
            returncode=0, stdout="No memories found", stderr=""
        ),
    )


def _diagnostic_codes(adapter) -> list:
    return [
        item.get("code")
        for item in adapter.last_search_metadata.get(
            "retrieval_diagnostics", []
        )
        if isinstance(item, dict)
    ]


class _HeaderOnlyResponse:
    """A response that must be refused from its Content-Length alone."""

    status = 200

    def __init__(self, declared: int):
        self.headers = {"Content-Length": str(declared)}
        self.read_calls = 0

    def read(self, *args):
        self.read_calls += 1
        raise AssertionError("an oversized body must never be read")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _LyingLengthResponse:
    """A client stack that ignores the requested read size."""

    status = 200

    def __init__(self, body: bytes, declared: str = "10"):
        self._body = body
        self.headers = {"Content-Length": declared}
        self.read_args: list = []

    def read(self, *args):
        self.read_args.append(args)
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestResponseSizeBound(unittest.TestCase):
    """Matrix A–D: one bounded response; oversized is refused, never partial."""

    def test_documented_bound_is_one_mebibyte_page_scale_constant(self):
        self.assertEqual(ENGRAM_HTTP_MAX_RESPONSE_BYTES, 8 * 1024 * 1024)

    def test_normal_bounded_response_is_accepted(self):
        target = "mem_" + "1" * 16
        payload = [record(target, PID_A, title="tsc02 normal")]
        with _LoopbackFixture(lambda h: _send_json(h, payload)) as server:
            adapter = _isolated_adapter(server.url)
            with _cli_returns_nothing():
                result = MemoryService(adapter).query(
                    project_id=PID_A, text="rlkmem1", limit=10
                )
        self.assertEqual([m.memory_id for m in result.memories], [target])
        self.assertEqual(adapter.read_mode, "http")
        self.assertEqual(result.skipped_malformed, 0)
        self.assertEqual(result.skipped_truncated, 0)

    def test_moderate_response_near_the_bound_is_accepted_whole(self):
        target = "mem_" + "2" * 16
        body = "m" * MODERATE_BODY_BYTES
        payload = [record(target, PID_A, body=body, title="tsc02 moderate")]
        with _LoopbackFixture(lambda h: _send_json(h, payload)) as server:
            adapter = _isolated_adapter(server.url)
            with _cli_returns_nothing():
                result = MemoryService(adapter).query(
                    project_id=PID_A, text="rlkmem1", limit=10
                )
        self.assertEqual(len(result.memories), 1)
        self.assertEqual(len(result.memories[0].body), MODERATE_BODY_BYTES)
        self.assertEqual(adapter.read_mode, "http")

    def test_content_length_over_limit_is_refused_before_the_body_is_read(self):
        response = _HeaderOnlyResponse(ENGRAM_HTTP_MAX_RESPONSE_BYTES + 1)
        adapter = _isolated_adapter("http://127.0.0.1:9")
        with mock.patch(
            "relinkra.engram_adapter._engram_http_open", return_value=response
        ), _cli_returns_nothing():
            records = adapter.search_records(query="rlkmem1", project=PID_A)
        self.assertEqual(records, [])
        self.assertEqual(response.read_calls, 0, "body must not be read")
        self.assertEqual(adapter.read_mode, "cli")
        self.assertIn("engram_response_rejected", _diagnostic_codes(adapter))

    def test_oversized_body_raises_the_typed_transport_error(self):
        from relinkra.engram_adapter import _read_bounded_response_body

        response = _LyingLengthResponse(
            b"x" * (ENGRAM_HTTP_MAX_RESPONSE_BYTES + 1)
        )
        with self.assertRaises(EngramResponseTooLargeError):
            _read_bounded_response_body(response)

    def test_absent_content_length_oversized_body_is_refused(self):
        oversized = OVERSIZED_SENTINEL + "x" * (
            ENGRAM_HTTP_MAX_RESPONSE_BYTES + 1024
        )
        payload = [record("mem_" + "3" * 16, PID_A, body=oversized)]
        with _LoopbackFixture(
            lambda h: _send_json(h, payload, content_length=None)
        ) as server:
            adapter = _isolated_adapter(server.url)
            with _cli_returns_nothing():
                result = MemoryService(adapter).query(
                    project_id=PID_A, text="rlkmem1", limit=10
                )
        self.assertEqual(result.memories, [])
        self.assertNotEqual(adapter.read_mode, "http")
        self.assertIn("engram_response_rejected", _diagnostic_codes(adapter))
        # No raw response content may leak into diagnostics.
        rendered = json.dumps(adapter.last_search_metadata)
        self.assertNotIn(OVERSIZED_SENTINEL, rendered)

    def test_lying_small_content_length_is_refused_by_the_actual_read_bound(self):
        oversized = json.dumps(
            [
                record(
                    "mem_" + "4" * 16,
                    PID_A,
                    body=OVERSIZED_SENTINEL
                    + "y" * (ENGRAM_HTTP_MAX_RESPONSE_BYTES + 64),
                )
            ]
        ).encode("utf-8")
        response = _LyingLengthResponse(oversized, declared="10")
        adapter = _isolated_adapter("http://127.0.0.1:9")
        with mock.patch(
            "relinkra.engram_adapter._engram_http_open", return_value=response
        ), _cli_returns_nothing():
            records = adapter.search_records(query="rlkmem1", project=PID_A)
        self.assertEqual(records, [])
        self.assertEqual(
            response.read_args,
            [(ENGRAM_HTTP_MAX_RESPONSE_BYTES + 1,)],
            "the read itself must be capped at MAX + 1 bytes",
        )
        self.assertEqual(adapter.read_mode, "cli")
        self.assertIn("engram_response_rejected", _diagnostic_codes(adapter))
        self.assertNotIn(
            OVERSIZED_SENTINEL, json.dumps(adapter.last_search_metadata)
        )

    def test_lying_small_content_length_real_http_is_refused(self):
        oversized = json.dumps(
            [record("mem_" + "5" * 16, PID_A, body="z" * 4096)]
        ).encode("utf-8")
        with _LoopbackFixture(
            lambda h: _send_bytes(h, oversized, content_length=16)
        ) as server:
            adapter = _isolated_adapter(server.url)
            with _cli_returns_nothing():
                result = MemoryService(adapter).query(
                    project_id=PID_A, text="rlkmem1", limit=10
                )
        self.assertEqual(result.memories, [])
        self.assertNotEqual(adapter.read_mode, "http")


class TestEndpointPolicy(unittest.TestCase):
    """Matrix H–K: local-only endpoint forms; refused URLs never contacted."""

    def test_accepted_loopback_forms(self):
        self.assertIsNotNone(validate_engram_endpoint)
        for value in (
            "http://127.0.0.1:7437",
            "http://127.0.0.1",
            "http://localhost:7437",
            "http://LOCALHOST:7437",
            "http://[::1]:7437",
            "http://127.0.0.1:7437/",
        ):
            with self.subTest(endpoint=value):
                self.assertIsNone(validate_engram_endpoint(value))

    def test_refused_forms_and_reasons(self):
        self.assertIsNotNone(validate_engram_endpoint)
        cases = (
            ("http://192.0.2.10:7437", "non-loopback host"),
            ("http://engram.example.com:7437", "non-loopback host"),
            ("http://127.0.0.1.example.com:7437", "non-loopback host"),
            ("http://localhost.example.com:7437", "non-loopback host"),
            ("http://user:pass@127.0.0.1:7437", "credential-bearing endpoint"),
            ("http://user@127.0.0.1:7437", "credential-bearing endpoint"),
            ("ftp://127.0.0.1:7437", "unsupported scheme"),
            ("https://127.0.0.1:7437", "unsupported scheme"),
            ("file:///tmp/engram", "unsupported scheme"),
            ("127.0.0.1:7437", "unsupported scheme"),
            ("http://", "missing host"),
            ("http://[::1", "malformed endpoint"),
            ("http://127.0.0.1:notaport", "malformed endpoint"),
            ("http://127.0.0.1:7437?token=1", "endpoint carries query or fragment"),
            ("http://127.0.0.1:7437#frag", "endpoint carries query or fragment"),
        )
        for value, reason in cases:
            with self.subTest(endpoint=value):
                self.assertEqual(validate_engram_endpoint(value), reason)

    def test_non_loopback_endpoint_is_never_contacted(self):
        for value in (
            "http://192.0.2.10:7437",
            "http://engram.example.com:7437",
            "http://127.0.0.1.example.com:7437",
        ):
            with self.subTest(endpoint=value):
                adapter = _isolated_adapter(value)
                with mock.patch(
                    "relinkra.engram_adapter._engram_http_open"
                ) as open_http, _cli_returns_nothing():
                    records = adapter.search_records(
                        query="rlkmem1", project=PID_A
                    )
                open_http.assert_not_called()
                self.assertEqual(records, [])
                self.assertEqual(adapter.read_mode, "cli")
                self.assertIn(
                    {"code": "engram_endpoint_rejected", "reason": "non-loopback host"},
                    adapter.last_search_metadata["retrieval_diagnostics"],
                )

    def test_credential_bearing_url_is_refused_without_leaking_credentials(self):
        secret_url = "http://operator:s3cr3t@127.0.0.1:7437"
        adapter = _isolated_adapter(secret_url)
        with mock.patch(
            "relinkra.engram_adapter._engram_http_open"
        ) as open_http, _cli_returns_nothing():
            adapter.search_records(query="rlkmem1", project=PID_A)
        open_http.assert_not_called()
        rendered = json.dumps(adapter.last_search_metadata, sort_keys=True)
        self.assertIn("engram_endpoint_rejected", rendered)
        self.assertNotIn("s3cr3t", rendered)
        self.assertNotIn("operator", rendered)
        self.assertNotIn(secret_url, rendered)

    def test_unsupported_scheme_is_never_contacted(self):
        adapter = _isolated_adapter("ftp://127.0.0.1:7437")
        with mock.patch(
            "relinkra.engram_adapter._engram_http_open"
        ) as open_http, _cli_returns_nothing():
            adapter.search_records(query="rlkmem1", project=PID_A)
        open_http.assert_not_called()
        self.assertEqual(adapter.read_mode, "cli")

    def test_localhost_endpoint_reaches_a_real_loopback_server(self):
        payload = [record("mem_" + "6" * 16, PID_A, title="tsc02 localhost")]
        try:
            server = _LoopbackFixture(lambda h: _send_json(h, payload), host="localhost")
        except OSError as exc:  # pragma: no cover - unusual hosts file
            self.skipTest(f"cannot bind localhost: {exc}")
        with server:
            adapter = _isolated_adapter(server.url)
            with _cli_returns_nothing():
                result = MemoryService(adapter).query(
                    project_id=PID_A, text="rlkmem1", limit=10
                )
        self.assertEqual(len(result.memories), 1)
        self.assertEqual(adapter.read_mode, "http")

    def test_ipv6_loopback_endpoint_reaches_a_real_server(self):
        if not socket.has_ipv6:
            self.skipTest("IPv6 unavailable on this host")
        payload = [record("mem_" + "7" * 16, PID_A, title="tsc02 ipv6")]
        try:
            server = _LoopbackFixture(lambda h: _send_json(h, payload), host="::1")
        except OSError as exc:
            self.skipTest(f"cannot bind IPv6 loopback: {exc}")
        with server:
            adapter = _isolated_adapter(server.url)
            with _cli_returns_nothing():
                result = MemoryService(adapter).query(
                    project_id=PID_A, text="rlkmem1", limit=10
                )
        self.assertEqual(len(result.memories), 1)
        self.assertEqual(adapter.read_mode, "http")


class TestRedirectPolicy(unittest.TestCase):
    """Matrix L: a redirect can never move the transport off-policy."""

    def test_redirect_target_is_never_contacted(self):
        target_payload = [record("mem_" + "8" * 16, PID_A, title="redirected")]
        with _LoopbackFixture(lambda h: _send_json(h, target_payload)) as target:

            def redirect(handler):
                handler.send_response(302)
                handler.send_header(
                    "Location", target.url + "/search?q=rlkmem1"
                )
                handler.send_header("Content-Length", "0")
                handler.end_headers()

            with _LoopbackFixture(redirect) as source:
                adapter = _isolated_adapter(source.url)
                with _cli_returns_nothing():
                    result = MemoryService(adapter).query(
                        project_id=PID_A, text="rlkmem1", limit=10
                    )
        self.assertEqual(target.requests, [], "redirect target was contacted")
        self.assertEqual(result.memories, [])
        self.assertNotEqual(adapter.read_mode, "http")

    def test_redirect_to_non_loopback_cannot_bypass_the_policy(self):
        def redirect(handler):
            handler.send_response(302)
            handler.send_header(
                "Location", "http://192.0.2.10:7437/search?q=rlkmem1"
            )
            handler.send_header("Content-Length", "0")
            handler.end_headers()

        with _LoopbackFixture(redirect) as source:
            adapter = _isolated_adapter(source.url)
            with _cli_returns_nothing():
                records = adapter.search_records(query="rlkmem1", project=PID_A)
        self.assertEqual(records, [])
        self.assertNotEqual(adapter.read_mode, "http")


class TestProvenanceAndEnvelopeValidation(unittest.TestCase):
    """Matrix E–G: reachability is transport; only policy validates content."""

    def test_reachable_endpoint_with_wrong_project_envelope_delivers_nothing(self):
        payload = [record("mem_" + "9" * 16, PID_B, title="foreign project")]
        with _LoopbackFixture(lambda h: _send_json(h, payload)) as server:
            adapter = _isolated_adapter(server.url)
            with _cli_returns_nothing():
                result = MemoryService(adapter).query(
                    project_id=PID_A, text="rlkmem1", limit=10
                )
        self.assertEqual(result.memories, [])
        # The transport WAS reachable; that is exactly the point.
        self.assertEqual(adapter.read_mode, "http")
        # A cross-project record is policy-dropped, not counted as corruption.
        self.assertEqual(result.skipped_malformed, 0)

    def test_same_project_envelope_is_delivered(self):
        target = "mem_" + "a" * 16
        payload = [record(target, PID_A, title="own project")]
        with _LoopbackFixture(lambda h: _send_json(h, payload)) as server:
            adapter = _isolated_adapter(server.url)
            with _cli_returns_nothing():
                result = MemoryService(adapter).query(
                    project_id=PID_A, text="rlkmem1", limit=10
                )
        self.assertEqual([m.memory_id for m in result.memories], [target])
        self.assertEqual(adapter.read_mode, "http")

    def test_transport_metadata_never_claims_verified_provenance(self):
        payload = [record("mem_" + "b" * 16, PID_A)]
        with _LoopbackFixture(lambda h: _send_json(h, payload)) as server:
            adapter = _isolated_adapter(server.url)
            with _cli_returns_nothing():
                adapter.search_records(query="rlkmem1", project=PID_A)
        self.assertIn(adapter.read_mode, {"http", "loopback", "cli"})
        self.assertFalse(
            {"verified", "trusted", "authenticated", "provenance"}
            & set(adapter.last_search_metadata),
            "transport metadata must not assert content provenance",
        )

    def test_malformed_json_is_refused_whole(self):
        with _LoopbackFixture(
            lambda h: _send_bytes(h, b'[{"id": 1, "content": "rlkmem1')
        ) as server:
            adapter = _isolated_adapter(server.url)
            with _cli_returns_nothing():
                result = MemoryService(adapter).query(
                    project_id=PID_A, text="rlkmem1", limit=10
                )
        self.assertEqual(result.memories, [])
        self.assertNotEqual(adapter.read_mode, "http")

    def test_wrong_top_level_shape_is_refused(self):
        for payload in ({"error": "nope"}, "just a string", 7):
            with self.subTest(payload=payload):
                with _LoopbackFixture(
                    lambda h, payload=payload: _send_json(h, payload)
                ) as server:
                    adapter = _isolated_adapter(server.url)
                    with _cli_returns_nothing():
                        result = MemoryService(adapter).query(
                            project_id=PID_A, text="rlkmem1", limit=10
                        )
                self.assertEqual(result.memories, [])
                self.assertNotEqual(adapter.read_mode, "http")

    def test_unknown_memory_type_is_skipped_as_malformed(self):
        payload = [
            record("mem_" + "c" * 16, PID_A, memory_type="not-a-real-type")
        ]
        with _LoopbackFixture(lambda h: _send_json(h, payload)) as server:
            adapter = _isolated_adapter(server.url)
            with _cli_returns_nothing():
                result = MemoryService(adapter).query(
                    project_id=PID_A, text="rlkmem1", limit=10
                )
        self.assertEqual(result.memories, [])
        self.assertEqual(result.skipped_malformed, 1)

    def test_unknown_status_is_skipped_as_malformed(self):
        payload = [record("mem_" + "d" * 16, PID_A, status="not-a-status")]
        with _LoopbackFixture(lambda h: _send_json(h, payload)) as server:
            adapter = _isolated_adapter(server.url)
            with _cli_returns_nothing():
                result = MemoryService(adapter).query(
                    project_id=PID_A, text="rlkmem1", limit=10
                )
        self.assertEqual(result.memories, [])
        self.assertEqual(result.skipped_malformed, 1)

    def test_missing_scope_channel_is_never_delivered(self):
        payload = [record("mem_" + "e" * 16, PID_A, scope_channel=None)]
        with _LoopbackFixture(lambda h: _send_json(h, payload)) as server:
            adapter = _isolated_adapter(server.url)
            with _cli_returns_nothing():
                result = MemoryService(adapter).query(
                    project_id=PID_A, text="rlkmem1", limit=10
                )
        self.assertEqual(result.memories, [])
        self.assertEqual(result.skipped_malformed, 0)

    def test_foreign_workspace_channel_is_not_delivered_to_another_workspace(self):
        foreign = "mem_" + "f" * 16
        own = "mem_" + "1" * 16
        payload = [
            record(foreign, PID_A, scope_channel=f"ws/{WID_B}"),
            record(own, PID_A, scope_channel=f"ws/{WID_A}"),
        ]
        with _LoopbackFixture(lambda h: _send_json(h, payload)) as server:
            adapter = _isolated_adapter(server.url)
            with _cli_returns_nothing():
                result = MemoryService(adapter).query(
                    project_id=PID_A,
                    scope="workspace_local",
                    workspace_id=WID_A,
                    text="rlkmem1",
                    limit=10,
                )
        self.assertEqual([m.memory_id for m in result.memories], [own])

    def test_malformed_requested_id_never_fuzzy_matches(self):
        payload = [record("mem_" + "2" * 16, PID_A)]
        with _LoopbackFixture(lambda h: _send_json(h, payload)) as server:
            adapter = _isolated_adapter(server.url)
            with _cli_returns_nothing():
                service = MemoryService(adapter)
                self.assertIsNone(
                    service.get(
                        project_id=PID_A, memory_id="legacy-style-id"
                    )
                )
                self.assertIsNone(
                    service.get(project_id=PID_A, memory_id="mem_" + "3" * 16)
                )


class TestPaginationExactGetAndHistory(unittest.TestCase):
    """Matrix M–O: bounded responses keep complete retrieval semantics."""

    def test_capped_http_page_recovers_complete_export(self):
        def row_topic(index: int) -> str:
            return f"relinkra/v1/{PID_A}/shared/decision/tsc02page-{index}"

        page = [
            record(
                f"mem_{index:016x}",
                PID_A,
                title=f"tsc02page row {index}",
                topic_key=row_topic(index),
            )
            for index in range(20)
        ]
        export_observations = []
        for index in range(25):
            memory_id = f"mem_{index:016x}"
            env = envelope(
                memory_id,
                PID_A,
                title=f"tsc02page row {index}",
                topic_key=row_topic(index),
            )
            export_observations.append(
                {
                    "id": memory_id,
                    "project": PID_A,
                    "type": "decision",
                    "title": env["title"],
                    "content": json.dumps(env),
                    "scope": "project",
                    "timestamp": "2026-09-20 00:00:00",
                    "topic_key": env["topic_key"],
                }
            )

        def fake_run(command, **_kwargs):
            if len(command) > 1 and command[1] == "export":
                with open(command[2], "w", encoding="utf-8") as handle:
                    json.dump({"observations": export_observations}, handle)
            return mock.Mock(returncode=0, stdout="Exported", stderr="")

        with _LoopbackFixture(lambda h: _send_json(h, page)) as server:
            adapter = _isolated_adapter(server.url)
            with mock.patch(
                "relinkra.engram_adapter.subprocess.run", side_effect=fake_run
            ):
                result = MemoryService(adapter).query(
                    project_id=PID_A, text="tsc02page", limit=50
                )
        self.assertEqual(len(result.memories), 25)
        self.assertEqual(result.retrieval_scope, "complete_export")
        self.assertFalse(result.backend_window_complete)

    def test_exact_memory_get_unchanged(self):
        target = "mem_" + "4" * 16
        foreign = "mem_" + "5" * 16
        payload = [
            record(target, PID_A, title="exact get target"),
            record(foreign, PID_B, title="foreign id"),
        ]
        with _LoopbackFixture(lambda h: _send_json(h, payload)) as server:
            adapter = _isolated_adapter(server.url)
            with _cli_returns_nothing():
                service = MemoryService(adapter)
                fetched = service.get(project_id=PID_A, memory_id=target)
                missing = service.get(project_id=PID_A, memory_id=foreign)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.memory_id, target)
        self.assertIsNone(missing)

    def test_history_and_supersede_semantics_unchanged(self):
        topic = f"relinkra/v1/{PID_A}/shared/decision/tsc02-history"
        old = "mem_" + "6" * 16
        new = "mem_" + "7" * 16
        payload = [
            record(
                old,
                PID_A,
                title="tsc02 history v1",
                topic_key=topic,
                timestamp="2026-09-19T00:00:00+00:00",
            ),
            record(
                new,
                PID_A,
                title="tsc02 history v2",
                topic_key=topic,
                supersedes=old,
                timestamp="2026-09-20T00:00:00+00:00",
            ),
        ]
        with _LoopbackFixture(lambda h: _send_json(h, payload)) as server:
            adapter = _isolated_adapter(server.url)
            with _cli_returns_nothing():
                service = MemoryService(adapter)
                current = service.query(
                    project_id=PID_A, text="rlkmem1", limit=10
                )
                history = service.query(
                    project_id=PID_A,
                    text="rlkmem1",
                    include_history=True,
                    limit=10,
                )
        self.assertEqual([m.memory_id for m in current.memories], [new])
        self.assertEqual(
            sorted(m.memory_id for m in history.memories), sorted([old, new])
        )
        superseded = next(m for m in history.memories if m.memory_id == old)
        self.assertEqual(superseded.superseded_by, new)


class TestManagedDataDirMode(unittest.TestCase):
    """Matrix P: managed ENGRAM_DATA_DIR mode is unchanged."""

    def test_data_dir_isolation_disables_external_http(self):
        with mock.patch.dict(
            os.environ, {"ENGRAM_DATA_DIR": "C:/tsc02-isolated"}, clear=True
        ):
            adapter = EngramCLIAdapter()
        self.assertEqual(adapter.http_url, "")
        self.assertTrue(adapter.allow_loopback)
        adapter.allow_loopback = False
        with mock.patch(
            "relinkra.engram_adapter._engram_http_open"
        ) as open_http, _cli_returns_nothing():
            records = adapter.search_records(query="rlkmem1", project=PID_A)
        open_http.assert_not_called()
        self.assertEqual(records, [])

    @unittest.skipUnless(_ENGRAM_BIN, "engram binary not available on PATH")
    def test_managed_loopback_roundtrip_uses_a_policy_accepted_endpoint(self):
        from relinkra.engram_adapter import _close_all_loopbacks, _shared_loopback

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(_cleanup_tmp_dir, tmp)
        self.addCleanup(_close_all_loopbacks)
        data_dir = os.path.join(tmp.name, "engram")
        os.makedirs(data_dir, exist_ok=True)
        env_patch = mock.patch.dict(
            os.environ, {"ENGRAM_DATA_DIR": data_dir}
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        saved_url = os.environ.pop("ENGRAM_URL", None)
        self.addCleanup(_restore_engram_url, saved_url)
        global_db = os.path.join(
            os.path.expanduser("~"), ".engram", "engram.db"
        )
        before = os.path.getmtime(global_db) if os.path.exists(global_db) else None

        store = EngramCLIAdapter()
        self.assertTrue(store.allow_loopback)
        store.save_record(
            title="tsc02 managed probe",
            content="tsc02 managed body",
            storage_type="manual",
            project=PID_A,
            scope="project",
            topic_key="tsc02/managed",
        )
        records = store.search_records(query="tsc02", project=PID_A, limit=10)
        self.assertEqual(store.read_mode, "loopback")
        self.assertTrue(
            any(r.title == "tsc02 managed probe" for r in records),
            "managed loopback read lost the saved record",
        )
        loopback = _shared_loopback(store.engram_bin, data_dir)
        self.assertIsNotNone(loopback)
        self.assertIsNotNone(validate_engram_endpoint)
        self.assertIsNone(
            validate_engram_endpoint(loopback.base_url),
            "Relinkra's generated loopback endpoint must pass the policy",
        )
        after = os.path.getmtime(global_db) if os.path.exists(global_db) else None
        self.assertEqual(before, after, "global Engram store was touched")


def _cleanup_tmp_dir(tmp: tempfile.TemporaryDirectory) -> None:
    """Remove a scratch dir, tolerating Windows handle-release races."""
    last_error: OSError | None = None
    for _ in range(8):
        try:
            tmp.cleanup()
            return
        except OSError as exc:
            last_error = exc
            time.sleep(0.5)
    raise last_error


def _restore_engram_url(saved: str | None) -> None:
    if saved is None:
        os.environ.pop("ENGRAM_URL", None)
    else:
        os.environ["ENGRAM_URL"] = saved


class TestTransportFailureDegradation(unittest.TestCase):
    """Error statuses degrade like any transport failure, without leaks."""

    def test_error_status_degrades_to_the_next_tier(self):
        def error(handler):
            _send_bytes(handler, b"", status=500)

        with _LoopbackFixture(error) as server:
            adapter = _isolated_adapter(server.url)
            with _cli_returns_nothing():
                result = MemoryService(adapter).query(
                    project_id=PID_A, text="rlkmem1", limit=10
                )
        self.assertEqual(result.memories, [])
        self.assertEqual(adapter.read_mode, "cli")


class TestTSC02ExactRegression(unittest.TestCase):
    """Exact regressions: FAIL on BASE 0ac3252a, PASS after the fix."""

    def test_exact_tsc02_oversized_http_response_is_not_accepted(self):
        """BASE read the whole body unbounded and accepted it.

        The response carries valid JSON with no Content-Length, so the
        ONLY thing that can refuse it is Relinkra's own transport bound —
        this exercises the real HTTP response path, not a constant.
        """
        oversized = OVERSIZED_SENTINEL + "q" * (
            ENGRAM_HTTP_MAX_RESPONSE_BYTES + 1024
        )
        payload = [record("mem_" + "8" * 16, PID_A, body=oversized)]
        with _LoopbackFixture(
            lambda h: _send_json(h, payload, content_length=None)
        ) as server:
            adapter = _isolated_adapter(server.url)
            with _cli_returns_nothing():
                result = MemoryService(adapter).query(
                    project_id=PID_A, text="rlkmem1", limit=10
                )
        self.assertEqual(
            result.memories,
            [],
            "an oversized HTTP response must never be accepted",
        )
        self.assertNotEqual(
            adapter.read_mode,
            "http",
            "an oversized response must degrade, not serve",
        )

    def test_exact_tsc02_redirect_is_not_followed(self):
        """BASE followed the 302 and served the target's payload."""
        target_payload = [record("mem_" + "9" * 16, PID_A, title="redirected")]
        with _LoopbackFixture(lambda h: _send_json(h, target_payload)) as target:

            def redirect(handler):
                handler.send_response(302)
                handler.send_header(
                    "Location", target.url + "/search?q=rlkmem1"
                )
                handler.send_header("Content-Length", "0")
                handler.end_headers()

            with _LoopbackFixture(redirect) as source:
                adapter = _isolated_adapter(source.url)
                with _cli_returns_nothing():
                    result = MemoryService(adapter).query(
                        project_id=PID_A, text="rlkmem1", limit=10
                    )
        self.assertEqual(target.requests, [], "redirect target was contacted")
        self.assertEqual(result.memories, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
