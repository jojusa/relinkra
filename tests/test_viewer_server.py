"""Loopback HTTP contract tests for the Relinkra viewer (VIS-1).

Everything here is hermetic: a real loopback socket, a fake status
provider, and no CBM, no external network. Every server, serving thread,
and HTTP connection is closed in cleanup so the suite stays
``-W error::ResourceWarning`` clean.
"""

from __future__ import annotations

import http.client
import importlib.resources
import json
import threading
import unittest
from unittest import mock

from relinkra import viewer


class ViewerServerCase(unittest.TestCase):
    """Shared helpers: servers that are always stopped and closed."""

    def make_server(self, provider=None, *, port=0, host=viewer.VIEWER_HOST, **providers):
        server = viewer.create_server(
            provider if provider is not None else (lambda: {"status": "ok"}),
            port=port,
            host=host,
            **providers,
        )
        self.addCleanup(server.server_close)
        return server

    def serve_in_background(self, server):
        """Run serve_forever off-thread; cleanup stops it before closing."""
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.05},
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

    def request(self, server, method, path, body=None):
        """One HTTP exchange, always closing the connection."""
        connection = http.client.HTTPConnection(
            server.server_address[0], server.server_address[1], timeout=10
        )
        try:
            connection.request(method, path, body=body)
            response = connection.getresponse()
            data = response.read()
            headers = {
                name.lower(): value for name, value in response.getheaders()
            }
            return response.status, headers, data
        finally:
            connection.close()

    def assert_contract_headers(self, headers):
        self.assertEqual(headers.get("connection"), "close")
        self.assertEqual(headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(headers.get("cache-control"), "no-store")
        self.assertIn("content-length", headers)
        self.assertNotIn("access-control-allow-origin", headers)


class ContractConstantTests(unittest.TestCase):
    def test_loopback_host_and_contract_id_are_pinned(self):
        self.assertEqual(viewer.VIEWER_HOST, "127.0.0.1")
        self.assertEqual(viewer.VIEWER_CONTRACT, "relinkra.viewer/v1")


class StaticRouteTests(ViewerServerCase):
    def test_index_is_served_as_html(self):
        server = self.serve()
        status, headers, body = self.request(server, "GET", "/")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "text/html; charset=utf-8")
        self.assertIn(b"Relinkra Viewer", body)
        self.assertIn(b"read-only", body)
        self.assert_contract_headers(headers)

    def test_app_js_is_served_with_a_javascript_type(self):
        server = self.serve()
        status, headers, body = self.request(server, "GET", "/app.js")
        self.assertEqual(status, 200)
        self.assertEqual(
            headers["content-type"], "application/javascript; charset=utf-8"
        )
        self.assertIn(b"use strict", body)
        self.assert_contract_headers(headers)

    def test_styles_css_is_served_with_a_css_type(self):
        server = self.serve()
        status, headers, body = self.request(server, "GET", "/styles.css")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "text/css; charset=utf-8")
        self.assertIn(b"body", body)
        self.assert_contract_headers(headers)

    def test_viewer_placeholders_are_in_the_shell(self):
        server = self.serve()
        _, _, body = self.request(server, "GET", "/")
        html = body.decode("utf-8")
        self.assertIn("No ContextPacket metrics recorded yet", html)
        # VIS-2 replaced the graph placeholder with the real explorer
        # skeleton: the search form ships, the placeholder string is gone.
        self.assertNotIn("Graph explorer will load here", html)
        self.assertIn('id="graph-search-form"', html)
        self.assertIn('id="graph-query"', html)

    def test_query_strings_are_ignored(self):
        server = self.serve()
        for path in ("/api/status?probe=1", "/app.js?v=1", "/?tab=status"):
            with self.subTest(path=path):
                status, _, _ = self.request(server, "GET", path)
                self.assertEqual(status, 200)

    def test_missing_asset_is_a_bare_500(self):
        server = self.serve()
        with mock.patch.object(viewer, "_read_asset", return_value=None):
            status, headers, body = self.request(server, "GET", "/")
        self.assertEqual(status, 500)
        self.assertEqual(headers["content-type"], "text/plain; charset=utf-8")
        self.assertNotIn(b"Traceback", body)
        self.assertNotIn(b"index.html", body)

    def test_assets_are_reachable_as_package_resources(self):
        for name in ("index.html", "app.js", "styles.css"):
            with self.subTest(asset=name):
                resource = importlib.resources.files("relinkra").joinpath(
                    "viewer", name
                )
                self.assertTrue(resource.is_file(), name)


class StatusRouteTests(ViewerServerCase):
    def test_status_echoes_the_provider_payload_exactly(self):
        payload = {
            "cbm": {"state": "MISSING", "nodes": None},
            "project": {"project_id": "rlk_demo"},
        }
        server = self.serve(lambda: payload)
        status, headers, body = self.request(server, "GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/json; charset=utf-8")
        echoed = json.loads(body)
        self.assertEqual(echoed, payload)
        self.assertIn("cbm", echoed)
        self.assert_contract_headers(headers)

    def test_status_provider_is_called_fresh_per_request(self):
        calls = []

        def provider():
            calls.append(1)
            return {"call": len(calls)}

        server = self.serve(provider)
        first = json.loads(self.request(server, "GET", "/api/status")[2])
        second = json.loads(self.request(server, "GET", "/api/status")[2])
        self.assertEqual(first, {"call": 1})
        self.assertEqual(second, {"call": 2})

    def test_provider_failure_is_a_bare_500_and_server_survives(self):
        def broken():
            raise RuntimeError("boom")

        server = self.serve(broken)
        status, headers, body = self.request(server, "GET", "/api/status")
        self.assertEqual(status, 500)
        self.assertEqual(headers["content-type"], "application/json; charset=utf-8")
        self.assertEqual(json.loads(body), {"error": "status unavailable"})
        self.assertNotIn(b"Traceback", body)
        self.assertNotIn(b"boom", body)
        self.assert_contract_headers(headers)

        status, _, body = self.request(server, "GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"Relinkra Viewer", body)


class RejectedRouteTests(ViewerServerCase):
    UNKNOWN_ROUTES = (
        "/nope",
        "/api",
        "/api/status/extra",
        "/viewer/index.html",
        "/index.html",
        "/static/app.js",
    )

    TRAVERSAL_ROUTES = (
        "/../pyproject.toml",
        "/%2e%2e/pyproject.toml",
        "/viewer/../../pyproject.toml",
        "/C:/Windows/win.ini",
        "/..%2fpyproject.toml",
        "/Sub/../../relinkra/viewer/index.html",
        "/..\\pyproject.toml",
        "/%2e%2e%2f%2e%2e%2fpyproject.toml",
        "/index.html%00",
    )

    def test_unknown_routes_are_plain_404(self):
        server = self.serve()
        for path in self.UNKNOWN_ROUTES:
            with self.subTest(path=path):
                status, headers, body = self.request(server, "GET", path)
                self.assertEqual(status, 404)
                self.assertEqual(
                    headers["content-type"], "text/plain; charset=utf-8"
                )
                self.assert_contract_headers(headers)
                self.assertNotIn(path.encode("utf-8"), body)

    def test_traversal_attempts_are_404_without_file_content(self):
        server = self.serve()
        for path in self.TRAVERSAL_ROUTES:
            with self.subTest(path=path):
                status, _, body = self.request(server, "GET", path)
                self.assertEqual(status, 404)
                self.assertNotIn(b"[project]", body)
                self.assertNotIn(b"setuptools", body)
                self.assertNotIn(b"pyproject", body)
                self.assertNotIn(b"win.ini", body)


class MethodTests(ViewerServerCase):
    def test_non_get_methods_are_405_with_allow_and_no_cors(self):
        server = self.serve()
        for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            with self.subTest(method=method):
                status, headers, _ = self.request(server, method, "/")
                self.assertEqual(status, 405)
                self.assertEqual(headers.get("allow"), "GET, HEAD")
                self.assertNotIn("access-control-allow-origin", headers)

    def test_head_returns_headers_without_a_body(self):
        server = self.serve()
        get_status, get_headers, get_body = self.request(server, "GET", "/")
        head_status, head_headers, head_body = self.request(server, "HEAD", "/")
        self.assertEqual(get_status, 200)
        self.assertEqual(head_status, 200)
        self.assertEqual(head_body, b"")
        self.assertGreater(len(get_body), 0)
        self.assertEqual(
            head_headers.get("content-length"), get_headers.get("content-length")
        )
        self.assertEqual(
            head_headers.get("content-type"), get_headers.get("content-type")
        )


class BindingTests(ViewerServerCase):
    def test_default_binding_is_loopback(self):
        server = self.make_server()
        self.assertEqual(server.server_address[0], "127.0.0.1")

    def test_explicit_loopback_host_is_honored(self):
        server = self.make_server(host="127.0.0.1")
        self.assertEqual(server.server_address[0], "127.0.0.1")

    def test_zero_port_asks_the_os_for_a_port(self):
        server = self.make_server(port=0)
        self.assertGreater(server.server_address[1], 0)

    def test_explicit_port_is_honored_and_released_on_close(self):
        first = self.make_server(port=0)
        port = first.server_address[1]
        first.server_close()
        second = self.make_server(port=port)
        self.assertEqual(second.server_address[1], port)

    def test_occupied_port_raises_oserror(self):
        first = self.make_server(port=0)
        port = first.server_address[1]
        with self.assertRaises(OSError):
            viewer.create_server(lambda: {}, port=port)


class LifecycleTests(ViewerServerCase):
    def test_run_forever_returns_on_keyboard_interrupt(self):
        server = self.make_server()
        with mock.patch.object(server, "serve_forever", side_effect=KeyboardInterrupt):
            viewer.run_forever(server)

    def test_run_forever_uses_a_short_poll_interval(self):
        server = self.make_server()
        serve_forever = mock.Mock()
        with mock.patch.object(server, "serve_forever", serve_forever):
            viewer.run_forever(server)
        serve_forever.assert_called_once_with(poll_interval=0.2)

    def test_open_browser_reports_the_webbrowser_verdict(self):
        with mock.patch.object(viewer.webbrowser, "open", return_value=True) as opener:
            self.assertTrue(viewer.open_browser("http://127.0.0.1:1"))
        opener.assert_called_once_with("http://127.0.0.1:1", new=2)

    def test_open_browser_never_raises(self):
        with mock.patch.object(
            viewer.webbrowser, "open", side_effect=RuntimeError("no browser")
        ):
            self.assertFalse(viewer.open_browser("http://127.0.0.1:1"))


class GraphRouteTests(ViewerServerCase):
    """VIS-2 graph routes: parsed params, fixed failures, exact matching."""

    def test_realistic_node_payload_round_trips_through_the_server(self):
        key = "relinkra.cbm_adapter.strip_project_slug"
        payload = {
            "viewer_contract": "relinkra.viewer/v1",
            "focal": {
                "key": key,
                "name": "strip_project_slug",
                "qualified_name": key,
                "file_path": "relinkra/cbm_adapter.py",
                "label": "Function",
                "start_line": 112,
                "end_line": 125,
                "in_degree": 5,
                "out_degree": 1,
                "complexity": 2,
                "lines": 14,
                "is_test": None,
                "is_exported": True,
                "is_entry_point": False,
                "reference": {
                    "code_reference_id": "ref_" + "a" * 32,
                    "project_id": "rlk_" + "b" * 32,
                    "workspace_id": "ws_" + "c" * 32,
                    "reference_kind": "symbol",
                    "file_path": "relinkra/cbm_adapter.py",
                    "symbol_name": "strip_project_slug",
                    "qualified_name": key,
                    "symbol_kind": "Function",
                    "language": "python",
                    "start_line": 112,
                    "end_line": 125,
                    "cbm_project_name": "C-Desarrollos-relinkra",
                    "commit_sha": None,
                    "repository_identity": None,
                },
            },
            "inbound": [
                {
                    "key": "relinkra.cbm_adapter.CBMCLIAdapter",
                    "name": "CBMCLIAdapter",
                    "qualified_name": "relinkra.cbm_adapter.CBMCLIAdapter",
                    "hop": 1,
                    "relationship": "caller",
                    "direction": "inbound",
                    "is_test": None,
                }
            ],
            "outbound": [
                {
                    "key": "relinkra.identity.git_head_sha",
                    "name": "git_head_sha",
                    "qualified_name": "relinkra.identity.git_head_sha",
                    "hop": 1,
                    "relationship": "dependency",
                    "direction": "outbound",
                    "is_test": None,
                }
            ],
            "coverage": {
                "depth": 1,
                "include_tests": True,
                "inbound": {
                    "returned": 1,
                    "limit": 20,
                    "truncated": False,
                    "total": None,
                    "notice": "Showing 1 inbound relationships; no "
                    "authoritative total exists, so more may exist.",
                },
                "outbound": {
                    "returned": 1,
                    "limit": 20,
                    "truncated": False,
                    "total": None,
                    "notice": "Showing 1 outbound relationships; no "
                    "authoritative total exists, so more may exist.",
                },
                "complete": False,
                "node_caps": {"initial": 50, "expanded": 100},
                "notice": "The bounded graph result may be incomplete. CBM "
                "reports no relationship total, and test-code relationships "
                "are included; nodes marked TEST are identified by CBM. "
                "Verify important claims against current source.",
            },
        }
        server = self.serve(graph_node_provider=lambda params: (200, payload))
        status, headers, body = self.request(
            server, "GET", "/api/graph/node?key=" + key
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/json; charset=utf-8")
        self.assertEqual(json.loads(body), payload)
        self.assertEqual(
            body.decode("utf-8"),
            json.dumps(payload, indent=2, sort_keys=True),
        )
        self.assert_contract_headers(headers)

    def test_search_provider_receives_parsed_params_fresh_per_request(self):
        calls = []

        def provider(params):
            calls.append(params)
            return 200, {"call": len(calls)}

        server = self.serve(graph_search_provider=provider)
        first = json.loads(
            self.request(
                server, "GET", "/api/graph/search?q=x&kind=symbol&limit=5"
            )[2]
        )
        second = json.loads(
            self.request(
                server, "GET", "/api/graph/search?q=x&kind=symbol&limit=5"
            )[2]
        )
        self.assertEqual(first, {"call": 1})
        self.assertEqual(second, {"call": 2})
        self.assertEqual(
            calls[0], {"q": ["x"], "kind": ["symbol"], "limit": ["5"]}
        )
        self.assertEqual(
            calls[1], {"q": ["x"], "kind": ["symbol"], "limit": ["5"]}
        )

    def test_node_provider_receives_parsed_params(self):
        calls = []

        def provider(params):
            calls.append(params)
            return 200, {"focal": None}

        server = self.serve(graph_node_provider=provider)
        status, headers, body = self.request(
            server, "GET", "/api/graph/node?key=relinkra.cbm_adapter"
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            calls, [{"key": ["relinkra.cbm_adapter"]}]
        )
        self.assertEqual(json.loads(body), {"focal": None})
        self.assertEqual(headers["content-type"], "application/json; charset=utf-8")
        self.assert_contract_headers(headers)

    def test_graph_payload_echoes_exactly(self):
        payload = {
            "viewer_contract": "relinkra.viewer/v1",
            "coverage": {"returned": 0, "complete": False},
        }
        server = self.serve(
            graph_search_provider=lambda params: (200, payload),
            graph_node_provider=lambda params: (400, {"error": "missing_key"}),
        )
        status, headers, body = self.request(
            server, "GET", "/api/graph/search?q=x"
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), payload)
        self.assertEqual(headers["content-type"], "application/json; charset=utf-8")
        self.assert_contract_headers(headers)

        status, headers, body = self.request(server, "GET", "/api/graph/node")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body), {"error": "missing_key"})
        self.assert_contract_headers(headers)

    def test_absent_provider_is_a_fixed_503(self):
        server = self.serve()
        for path in ("/api/graph/search?q=x", "/api/graph/node?key=a"):
            with self.subTest(path=path):
                status, headers, body = self.request(server, "GET", path)
                self.assertEqual(status, 503)
                self.assertEqual(
                    headers["content-type"], "application/json; charset=utf-8"
                )
                self.assertEqual(json.loads(body), {"error": "graph unavailable"})
                self.assert_contract_headers(headers)

    def test_provider_failure_is_a_bare_500_and_server_survives(self):
        class Boom(Exception):
            pass

        def broken(params):
            raise Boom("secret detail")

        server = self.serve(graph_search_provider=broken)
        status, headers, body = self.request(
            server, "GET", "/api/graph/search?q=x"
        )
        self.assertEqual(status, 500)
        self.assertEqual(json.loads(body), {"error": "graph unavailable"})
        self.assertNotIn(b"Traceback", body)
        self.assertNotIn(b"secret detail", body)
        self.assert_contract_headers(headers)

        status, _, body = self.request(server, "GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"Relinkra Viewer", body)

    def test_malformed_provider_returns_are_500(self):
        malformed = (
            {"status": 200},
            None,
            "not a tuple",
            (None, {"error": "x"}),
            (True, {"error": "x"}),
            ("200", {"error": "x"}),
            (200, object()),
        )
        for result in malformed:
            with self.subTest(result=result):
                server = self.serve(
                    graph_search_provider=lambda params, r=result: r
                )
                status, _, body = self.request(
                    server, "GET", "/api/graph/search?q=x"
                )
                self.assertEqual(status, 500)
                self.assertEqual(
                    json.loads(body), {"error": "graph unavailable"}
                )

    def test_unknown_graph_shapes_stay_plain_404(self):
        server = self.serve()
        for path in (
            "/api/graph",
            "/api/graph/",
            "/api/graph/search/extra",
            "/api/graph/node/extra",
            "/api/graph/search/../node",
        ):
            with self.subTest(path=path):
                status, headers, body = self.request(server, "GET", path)
                self.assertEqual(status, 404)
                self.assertEqual(
                    headers["content-type"], "text/plain; charset=utf-8"
                )
                self.assert_contract_headers(headers)
                self.assertNotIn(path.encode("utf-8"), body)

    def test_graph_methods_are_405_with_allow_and_no_cors(self):
        server = self.serve(
            graph_search_provider=lambda params: (200, {"ok": True})
        )
        for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            with self.subTest(method=method):
                status, headers, _ = self.request(
                    server, method, "/api/graph/search"
                )
                self.assertEqual(status, 405)
                self.assertEqual(headers.get("allow"), "GET, HEAD")
                self.assertNotIn("access-control-allow-origin", headers)

    def test_graph_head_returns_headers_without_a_body(self):
        server = self.serve(
            graph_search_provider=lambda params: (200, {"ok": True})
        )
        get_status, get_headers, get_body = self.request(
            server, "GET", "/api/graph/search?q=x"
        )
        head_status, head_headers, head_body = self.request(
            server, "HEAD", "/api/graph/search?q=x"
        )
        self.assertEqual(get_status, 200)
        self.assertEqual(head_status, 200)
        self.assertEqual(head_body, b"")
        self.assertGreater(len(get_body), 0)
        self.assertEqual(
            head_headers.get("content-length"), get_headers.get("content-length")
        )
        self.assertEqual(
            head_headers.get("content-type"), get_headers.get("content-type")
        )

    def test_query_strings_do_not_leak_into_responses(self):
        server = self.serve(
            graph_search_provider=lambda params: (200, {"searched": True})
        )
        hostile = "%3Cscript%3Ealert(1)%3C%2Fscript%3E"
        status, _, body = self.request(
            server, "GET", f"/api/graph/search?q={hostile}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"searched": True})
        self.assertNotIn(b"script", body.lower())
        self.assertNotIn(hostile.encode("utf-8"), body)


if __name__ == "__main__":
    unittest.main()