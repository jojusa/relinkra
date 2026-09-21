"""Viewer concurrency bound tests (M4 / TSC-03).

The local viewer stays thread-per-request (``ThreadingMixIn``), but routes
whose providers can launch CBM subprocesses (status, graph search, graph
node) run under one small bounded gate: at most
``viewer.MAX_EXPENSIVE_REQUESTS`` expensive requests are in flight at once
and the excess is rejected fail-fast with a deterministic 429 BEFORE any
provider runs. Static assets and the local-only metrics routes stay
outside the gate so the shell remains responsive under saturation.

Everything here is hermetic: a real loopback socket, fake providers, no
CBM, no external network. Every server, serving thread, client thread,
and HTTP connection is closed in cleanup so the suite stays
``-W error::ResourceWarning`` clean.
"""

from __future__ import annotations

import http.client
import json
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from relinkra import cbm_adapter, viewer, viewer_graph

#: The configured bound, or None on a base without the gate. The TSC-03
#: regression test must FAIL there (unbounded provider concurrency); the
#: remaining gate-semantics tests skip, because they test the fix itself.
BOUND = getattr(viewer, "MAX_EXPENSIVE_REQUESTS", None)

#: Safety net for any provider wait so a wedged test can never hang.
WAIT_DEADLINE = 15.0

needs_gate = unittest.skipIf(BOUND is None, "viewer concurrency gate absent")


class ConcurrencyMeter:
    """Thread-safe in-flight counter with a high-water mark."""

    def __init__(self):
        self._lock = threading.Lock()
        self.current = 0
        self.maximum = 0
        self.calls = 0

    def enter(self):
        with self._lock:
            self.current += 1
            self.calls += 1
            self.maximum = max(self.maximum, self.current)

    def exit(self):
        with self._lock:
            self.current -= 1


def wait_for(predicate, timeout=WAIT_DEADLINE, interval=0.01):
    """Poll ``predicate`` until true or the deadline passes."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


class ViewerConcurrencyCase(unittest.TestCase):
    """Shared helpers: servers and clients that are always cleaned up."""

    def make_server(self, provider=None, **providers):
        server = viewer.create_server(
            provider if provider is not None else (lambda: {"status": "ok"}),
            port=0,
            **providers,
        )
        self.addCleanup(server.server_close)
        return server

    def serve_in_background(self, server):
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.02},
            daemon=True,
        )
        thread.start()
        self.addCleanup(thread.join, 10.0)
        self.addCleanup(server.shutdown)
        return thread

    def serve(self, provider=None, **providers):
        server = self.make_server(provider, **providers)
        self.serve_in_background(server)
        return server

    def request(self, server, path, method="GET", headers=None):
        """One HTTP exchange, always closing the connection."""
        connection = http.client.HTTPConnection(
            server.server_address[0], server.server_address[1], timeout=15
        )
        try:
            connection.request(method, path, headers=headers or {})
            response = connection.getresponse()
            data = response.read()
            header_map = {
                name.lower(): value for name, value in response.getheaders()
            }
            return response.status, header_map, data
        finally:
            connection.close()

    def request_without_host(self, server, path):
        """One HTTP/1.0-style exchange with NO Host header at all."""
        connection = http.client.HTTPConnection(
            server.server_address[0], server.server_address[1], timeout=15
        )
        try:
            connection.putrequest("GET", path, skip_host=True)
            connection.endheaders()
            response = connection.getresponse()
            data = response.read()
            return response.status, data
        finally:
            connection.close()

    def burst(self, server, path, count):
        """Fire ``count`` concurrent requests; return (status, headers, body)s."""
        with ThreadPoolExecutor(max_workers=count) as pool:
            futures = [
                pool.submit(self.request, server, path) for _ in range(count)
            ]
            return [future.result() for future in futures]


class GateShapeTests(unittest.TestCase):
    """The bound is one small explicit constant over exactly the expensive
    routes; cheap local routes stay outside it."""

    @needs_gate
    def test_bound_is_a_small_fixed_constant(self):
        self.assertIsInstance(BOUND, int)
        self.assertEqual(BOUND, 4)

    @needs_gate
    def test_exactly_the_expensive_routes_are_gated(self):
        self.assertEqual(
            viewer._GATED_PATHS,
            frozenset(
                {
                    viewer.STATUS_PATH,
                    viewer.GRAPH_SEARCH_PATH,
                    viewer.GRAPH_NODE_PATH,
                }
            ),
        )
        for cheap in (
            "/",
            "/app.js",
            "/styles.css",
            viewer.METRICS_CURRENT_PATH,
            viewer.METRICS_HISTORY_PATH,
        ):
            self.assertNotIn(cheap, viewer._GATED_PATHS)

    @needs_gate
    def test_overload_contract_is_pinned(self):
        self.assertEqual(viewer.OVERLOAD_STATUS, 429)

    @needs_gate
    def test_each_server_instance_owns_an_independent_bounded_gate(self):
        first = viewer.create_server(lambda: {}, port=0)
        self.addCleanup(first.server_close)
        second = viewer.create_server(lambda: {}, port=0)
        self.addCleanup(second.server_close)
        self.assertIsNot(first.expensive_gate, second.expensive_gate)
        # The gate is bounded at exactly MAX_EXPENSIVE_REQUESTS permits.
        acquired = 0
        while first.expensive_gate.acquire(blocking=False):
            acquired += 1
            self.assertLessEqual(acquired, BOUND)
        self.assertEqual(acquired, BOUND)
        for _ in range(acquired):
            first.expensive_gate.release()


class Tsc03RegressionTests(ViewerConcurrencyCase):
    """TSC-03 exact regression over the real viewer HTTP/provider path.

    On base (e04059b2) there is no gate: every concurrent request runs the
    provider, so the observed provider concurrency far exceeds the
    candidate bound and no request is ever rejected — this test FAILS
    there. With the gate, concurrency is capped and the excess is a
    deterministic 429.
    """

    def test_concurrent_expensive_work_is_bounded(self):
        bound = BOUND or 0
        meter = ConcurrencyMeter()

        def provider(params):
            meter.enter()
            try:
                time.sleep(0.6)
                return 200, {"ok": True}
            finally:
                meter.exit()

        server = self.serve(graph_search_provider=provider)
        results = self.burst(server, "/api/graph/search?q=x", 16)
        statuses = [status for status, _, _ in results]
        # A 200 implies a provider run; a 429 must never have run it.
        self.assertEqual(meter.calls, statuses.count(200))
        self.assertTrue(
            0 < meter.maximum <= bound,
            f"provider concurrency {meter.maximum} exceeds the "
            f"viewer bound {bound}",
        )
        self.assertIn(429, statuses)


@needs_gate
class CapacityBoundTests(ViewerConcurrencyCase):
    """The gate admits at most BOUND expensive requests and never lets a
    rejected request touch the provider."""

    def blocking_provider(self, meter, release):
        def provider(params):
            meter.enter()
            try:
                release.wait(WAIT_DEADLINE)
                return 200, {"ok": True}
            finally:
                meter.exit()

        return provider

    def test_up_to_the_limit_all_requests_execute(self):
        meter = ConcurrencyMeter()

        def provider(params):
            meter.enter()
            try:
                time.sleep(0.5)
                return 200, {"ok": True}
            finally:
                meter.exit()

        server = self.serve(graph_search_provider=provider)
        results = self.burst(server, "/api/graph/search?q=x", BOUND)
        self.assertEqual([status for status, _, _ in results], [200] * BOUND)
        self.assertEqual(meter.maximum, BOUND)
        self.assertEqual(meter.calls, BOUND)

    def test_excess_requests_are_rejected_fail_fast(self):
        meter = ConcurrencyMeter()
        release = threading.Event()
        server = self.serve(
            graph_search_provider=self.blocking_provider(meter, release)
        )
        with ThreadPoolExecutor(max_workers=BOUND + 3) as pool:
            holders = [
                pool.submit(self.request, server, "/api/graph/search?q=hold")
                for _ in range(BOUND)
            ]
            self.assertTrue(wait_for(lambda: meter.current == BOUND))
            # All slots are held: excess requests fail fast, in order.
            extras = [
                pool.submit(self.request, server, "/api/graph/search?q=x")
                for _ in range(3)
            ]
            extra_statuses = [future.result()[0] for future in extras]
            self.assertEqual(extra_statuses, [429, 429, 429])
            release.set()
            held_statuses = [future.result()[0] for future in holders]
        self.assertEqual(held_statuses, [200] * BOUND)

    def test_rejected_request_never_calls_the_provider(self):
        meter = ConcurrencyMeter()
        release = threading.Event()
        server = self.serve(
            graph_search_provider=self.blocking_provider(meter, release)
        )
        with ThreadPoolExecutor(max_workers=BOUND + 2) as pool:
            holders = [
                pool.submit(self.request, server, "/api/graph/search?q=hold")
                for _ in range(BOUND)
            ]
            self.assertTrue(wait_for(lambda: meter.current == BOUND))
            for _ in range(2):
                status, _, _ = self.request(server, "/api/graph/node?key=a.b")
                self.assertEqual(status, 429)
            # Only the admitted BOUND requests ever ran a provider, even
            # though the rejections targeted the OTHER gated route.
            self.assertEqual(meter.calls, BOUND)
            release.set()
            for future in holders:
                self.assertEqual(future.result()[0], 200)

    def test_capacity_recovers_after_success(self):
        meter = ConcurrencyMeter()

        def provider(params):
            meter.enter()
            try:
                time.sleep(0.3)
                return 200, {"ok": True}
            finally:
                meter.exit()

        server = self.serve(graph_search_provider=provider)
        self.burst(server, "/api/graph/search?q=x", BOUND * 2)
        # After the burst the full capacity is available again: a fresh
        # burst of exactly BOUND all execute and overlap fully.
        meter.maximum = 0
        second = self.burst(server, "/api/graph/search?q=y", BOUND)
        self.assertEqual([status for status, _, _ in second], [200] * BOUND)
        self.assertEqual(meter.maximum, BOUND)

    def test_capacity_recovers_after_provider_exception(self):
        meter = ConcurrencyMeter()

        def provider(params):
            meter.enter()
            try:
                raise RuntimeError("secret provider detail")
            finally:
                meter.exit()

        server = self.serve(graph_search_provider=provider)
        results = self.burst(server, "/api/graph/search?q=x", BOUND)
        for status, _, body in results:
            self.assertEqual(status, 500)
            self.assertEqual(json.loads(body), {"error": "graph unavailable"})
        # No leaked slot: the next request is served (and fails the same
        # sanitized way), never a 429.
        status, _, _ = self.request(server, "/api/graph/search?q=x")
        self.assertEqual(status, 500)
        self.assertEqual(meter.calls, BOUND + 1)
        self.assertEqual(meter.current, 0)

    def test_capacity_recovers_after_provider_timeout(self):
        meter = ConcurrencyMeter()

        def provider(params):
            meter.enter()
            try:
                # The provider's own internal deadline fires; from the
                # viewer's perspective this is an ordinary provider error.
                time.sleep(0.05)
                raise TimeoutError("provider deadline exceeded")
            finally:
                meter.exit()

        server = self.serve(graph_search_provider=provider)
        results = self.burst(server, "/api/graph/search?q=x", BOUND)
        self.assertEqual([status for status, _, _ in results], [500] * BOUND)
        status, _, _ = self.request(server, "/api/graph/search?q=x")
        self.assertEqual(status, 500)
        self.assertEqual(meter.current, 0)


    def test_client_disconnect_still_releases_capacity(self):
        meter = ConcurrencyMeter()

        def provider(params):
            meter.enter()
            try:
                time.sleep(0.4)
                return 200, {"ok": True}
            finally:
                meter.exit()

        server = self.serve(graph_search_provider=provider)

        def abandoned_request():
            connection = http.client.HTTPConnection(
                server.server_address[0], server.server_address[1], timeout=15
            )
            try:
                connection.request("GET", "/api/graph/search?q=x")
                # Never read the response: the client goes away mid-flight.
            finally:
                connection.close()

        threads = [
            threading.Thread(target=abandoned_request, daemon=True)
            for _ in range(BOUND)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10.0)
        self.assertTrue(wait_for(lambda: meter.current == 0))
        # Every slot came back despite the handler's write failing.
        status, _, _ = self.request(server, "/api/graph/search?q=x")
        self.assertEqual(status, 200)
        self.assertEqual(meter.calls, BOUND + 1)


@needs_gate
class CheapRouteAvailabilityTests(ViewerConcurrencyCase):
    """Static assets and local metrics stay responsive under saturation."""

    def test_cheap_routes_bypass_the_gate(self):
        meter = ConcurrencyMeter()
        release = threading.Event()

        def provider(params):
            meter.enter()
            try:
                release.wait(WAIT_DEADLINE)
                return 200, {"ok": True}
            finally:
                meter.exit()

        server = self.serve(
            graph_search_provider=provider, graph_node_provider=provider
        )
        with ThreadPoolExecutor(max_workers=BOUND + 1) as pool:
            holders = [
                pool.submit(self.request, server, "/api/graph/search?q=hold")
                for _ in range(BOUND)
            ]
            self.assertTrue(wait_for(lambda: meter.current == BOUND))
            # Cheap surfaces are unaffected by the exhausted gate.
            status, _, body = self.request(server, "/")
            self.assertEqual(status, 200)
            self.assertIn(b"Relinkra Viewer", body)
            for asset in ("/app.js", "/styles.css"):
                status, _, _ = self.request(server, asset)
                self.assertEqual(status, 200)
            for metrics in (
                viewer.METRICS_CURRENT_PATH,
                viewer.METRICS_HISTORY_PATH,
            ):
                status, _, body = self.request(server, metrics)
                self.assertEqual(status, 200)
                self.assertTrue(json.loads(body)["no_data"])
            # ...while one more expensive request is still rejected.
            status, _, _ = self.request(server, "/api/graph/search?q=x")
            self.assertEqual(status, 429)
            release.set()
            for future in holders:
                self.assertEqual(future.result()[0], 200)

    def test_status_route_shares_the_gate(self):
        meter = ConcurrencyMeter()
        release = threading.Event()

        def status_provider():
            meter.enter()
            try:
                release.wait(WAIT_DEADLINE)
                return {"status": "ok"}
            finally:
                meter.exit()

        server = self.serve(status_provider)
        with ThreadPoolExecutor(max_workers=BOUND + 1) as pool:
            holders = [
                pool.submit(self.request, server, "/api/status")
                for _ in range(BOUND)
            ]
            self.assertTrue(wait_for(lambda: meter.current == BOUND))
            extra = pool.submit(self.request, server, "/api/status")
            self.assertEqual(extra.result()[0], 429)
            self.assertEqual(meter.calls, BOUND)
            release.set()
            for future in holders:
                self.assertEqual(future.result()[0], 200)



@needs_gate
class OverloadResponseTests(ViewerConcurrencyCase):
    """The overload response is deterministic, sanitized, and CORS-free."""

    def _blocking(self, meter, release):
        def provider(params):
            meter.enter()
            try:
                release.wait(WAIT_DEADLINE)
                return 200, {"ok": True}
            finally:
                meter.exit()

        return provider

    def test_overload_response_contract(self):
        meter = ConcurrencyMeter()
        release = threading.Event()
        self.addCleanup(release.set)
        server = self.serve(
            graph_search_provider=self._blocking(meter, release)
        )
        pool = ThreadPoolExecutor(max_workers=BOUND + 1)
        self.addCleanup(pool.shutdown, True)
        holders = [
            pool.submit(self.request, server, "/api/graph/search?q=hold")
            for _ in range(BOUND)
        ]
        self.assertTrue(wait_for(lambda: meter.current == BOUND))
        status, headers, body = self.request(server, "/api/graph/search?q=x")
        self.assertEqual(status, viewer.OVERLOAD_STATUS)
        self.assertEqual(status, 429)
        self.assertEqual(
            headers["content-type"], "application/json; charset=utf-8"
        )
        self.assertEqual(headers["connection"], "close")
        self.assertEqual(headers["retry-after"], "1")
        self.assertNotIn("access-control-allow-origin", headers)
        payload = json.loads(body)
        self.assertEqual(payload["error"], "viewer_busy")
        self.assertIn("message", payload)
        # No raw traceback, no internal detail, no path leakage.
        self.assertNotIn(b"Traceback", body)
        self.assertNotIn(b"C:\\", body)
        self.assertNotIn(b"/home/", body)
        # Identical shape on every gated route.
        status, _, node_body = self.request(server, "/api/graph/node?key=a.b")
        self.assertEqual(status, 429)
        self.assertEqual(json.loads(node_body), payload)
        status, _, status_body = self.request(server, "/api/status")
        self.assertEqual(status, 429)
        self.assertEqual(json.loads(status_body), payload)
        # The held requests still complete once released.
        release.set()
        for future in holders:
            self.assertEqual(future.result()[0], 200)


@needs_gate
class HostValidationTests(ViewerConcurrencyCase):
    """Bounded Host policy: loopback authorities only, no foreign names.

    The viewer binds loopback only; a request whose Host names a foreign
    authority (the DNS-rebinding shape) is rejected before any routing or
    provider work. HTTP/1.0 clients without a Host header stay accepted:
    command-line tools legitimately omit it and no browser does.
    """

    def test_loopback_host_authorities_are_accepted(self):
        server = self.serve(
            graph_search_provider=lambda params: (200, {"ok": True})
        )
        port = server.server_address[1]
        for host in (
            f"127.0.0.1:{port}",
            f"localhost:{port}",
            f"[::1]:{port}",
            "127.0.0.1",
            "localhost",
            f"LOCALHOST:{port}",
        ):
            with self.subTest(host=host):
                status, _, _ = self.request(
                    server, "/", headers={"Host": host}
                )
                self.assertEqual(status, 200)
        # The port is not re-validated: only the authority NAME matters.
        status, _, _ = self.request(
            server, "/", headers={"Host": "127.0.0.1:1"}
        )
        self.assertEqual(status, 200)
        # HTTP/1.0-style request with no Host header at all.
        status, _ = self.request_without_host(server, "/")
        self.assertEqual(status, 200)

    def test_foreign_host_is_rejected_before_any_work(self):
        meter = ConcurrencyMeter()

        def provider(params):
            meter.enter()
            meter.exit()
            return 200, {"ok": True}

        server = self.serve(graph_search_provider=provider)
        port = server.server_address[1]
        for host in (
            "foreign.example",
            f"attacker.invalid:{port}",
            "127.0.0.1.evil.com",
            "localhost.evil.com",
        ):
            with self.subTest(host=host):
                status, headers, body = self.request(
                    server, "/api/graph/search?q=x", headers={"Host": host}
                )
                self.assertEqual(status, 400)
                self.assertEqual(body, b"Bad request")
                self.assertNotIn(host.encode("utf-8"), body)
                self.assertNotIn("access-control-allow-origin", headers)
        # No provider ever ran for a foreign Host.
        self.assertEqual(meter.calls, 0)
        # Static routes are equally refused for a foreign Host.
        status, _, _ = self.request(
            server, "/", headers={"Host": "foreign.example"}
        )
        self.assertEqual(status, 400)



class GraphCapsPreservedTests(ViewerConcurrencyCase):
    """M4 must not weaken the existing graph/query bounds."""

    def test_graph_bound_constants_are_unchanged(self):
        self.assertEqual(viewer_graph.GRAPH_SEARCH_DEFAULT_LIMIT, 20)
        self.assertEqual(viewer_graph.GRAPH_SEARCH_MAX_LIMIT, 20)
        self.assertEqual(viewer_graph.GRAPH_QUERY_MAX_CHARS, 200)
        self.assertEqual(viewer_graph.GRAPH_KEY_MAX_CHARS, 300)
        self.assertEqual(viewer_graph.GRAPH_DEFAULT_DEPTH, 1)
        self.assertEqual(viewer_graph.GRAPH_INITIAL_NODE_CAP, 50)
        self.assertEqual(viewer_graph.GRAPH_EXPANDED_NODE_CAP, 100)
        self.assertEqual(cbm_adapter.GRAPH_SEARCH_MAX_LIMIT, 20)
        self.assertEqual(cbm_adapter.GRAPH_RELATION_MAX_LIMIT, 20)
        self.assertEqual(cbm_adapter.GRAPH_MAX_DEPTH, 3)
        self.assertEqual(cbm_adapter.GRAPH_NODE_LOOKUP_LIMIT, 50)

    def test_extreme_or_malformed_limits_stay_bounded_over_http(self):
        def provider(params):
            try:
                query, kind, limit = viewer_graph.parse_search_params(params)
            except viewer_graph.GraphAPIError as exc:
                return exc.status, exc.to_dict()
            return 200, {"limit": limit}

        server = self.serve(graph_search_provider=provider)
        for raw in ("999999", "0", "-5", "abc", "1e9"):
            with self.subTest(limit=raw):
                status, _, body = self.request(
                    server, f"/api/graph/search?q=x&limit={raw}"
                )
                self.assertEqual(status, 400)
                self.assertEqual(json.loads(body)["error"], "invalid_limit")
        status, _, body = self.request(server, "/api/graph/search?q=x")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["limit"], 20)
        status, _, body = self.request(
            server, "/api/graph/search?q=x&limit=20"
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["limit"], 20)


@needs_gate
class BoundedStressTests(ViewerConcurrencyCase):
    """A bounded stress probe: 32 concurrent mixed expensive requests."""

    def test_stress_burst_never_exceeds_the_bound_and_server_survives(self):
        meter = ConcurrencyMeter()

        def provider(params):
            meter.enter()
            try:
                time.sleep(0.05)
                return 200, {"ok": True}
            finally:
                meter.exit()

        server = self.serve(
            graph_search_provider=provider, graph_node_provider=provider
        )
        paths = ["/api/graph/search?q=s", "/api/graph/node?key=mod.fn"] * 16
        with ThreadPoolExecutor(max_workers=32) as pool:
            results = list(pool.map(lambda p: self.request(server, p), paths))
        statuses = [status for status, _, _ in results]
        self.assertLessEqual(meter.maximum, BOUND)
        self.assertGreater(meter.maximum, 1)
        for status in statuses:
            self.assertIn(status, (200, 429))
        self.assertEqual(meter.calls, statuses.count(200))
        self.assertGreater(statuses.count(429), 0)
        # The server survives a saturated burst without corruption.
        status, _, body = self.request(server, "/")
        self.assertEqual(status, 200)
        self.assertIn(b"Relinkra Viewer", body)
        status, _, _ = self.request(server, "/api/graph/search?q=after")
        self.assertEqual(status, 200)


@needs_gate
class ShutdownTests(ViewerConcurrencyCase):
    """Bounded concurrency must not break shutdown semantics."""

    def test_shutdown_with_in_flight_bounded_work_is_clean(self):
        meter = ConcurrencyMeter()
        release = threading.Event()

        def provider(params):
            meter.enter()
            try:
                release.wait(WAIT_DEADLINE)
                return 200, {"ok": True}
            finally:
                meter.exit()

        server = self.make_server(graph_search_provider=provider)
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.02},
            daemon=True,
        )
        thread.start()
        pool = ThreadPoolExecutor(max_workers=BOUND)
        self.addCleanup(pool.shutdown, True)
        futures = [
            pool.submit(self.request, server, "/api/graph/search?q=x")
            for _ in range(BOUND)
        ]
        self.assertTrue(wait_for(lambda: meter.current == BOUND))
        # Stop accepting and release the port while bounded work is
        # in flight; the in-flight requests then finish predictably.
        server.shutdown()
        thread.join(10.0)
        self.assertFalse(thread.is_alive())
        server.server_close()
        release.set()
        statuses = [future.result()[0] for future in futures]
        self.assertEqual(statuses, [200] * BOUND)
        self.assertTrue(wait_for(lambda: meter.current == 0))
        # The port was released: a fresh server binds it immediately.
        port = server.server_address[1]
        second = viewer.create_server(lambda: {"status": "ok"}, port=port)
        second.server_close()


if __name__ == "__main__":
    unittest.main()

