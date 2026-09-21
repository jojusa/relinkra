"""Relinkra-owned read-only local viewer (VIS-1/VIS-2).

A minimal loopback HTTP server that serves the packaged viewer shell
(``relinkra/viewer/``) plus JSON routes whose payloads callers supply:
one status route, two bounded graph-explorer routes (search and node), and
two read-only metrics routes (current and history). This module knows
nothing about CBM, Engram, or the graph: it
sequences no workflow, executes no backend, reads no database, and
persists nothing.

Boundaries that are intentional and tested:

- the socket binds ONLY to the requested host (``127.0.0.1`` by default),
  never to a wildcard address;
- URLs never map to filesystem paths. Every route is an exact-match
  constant and unknown paths (including traversal shapes) are a plain
  404 with no path echo and no file content;
- only ``GET`` and ``HEAD`` are served; everything else is 405 with
  ``Allow: GET, HEAD``;
- payloads are produced fresh per request by the caller's providers; a
  raising or malformed provider becomes a fixed 500 JSON body, never a
  traceback, and never kills the server; a graph route without a
  provider is a fixed 503.
- expensive work is bounded (M4/TSC-03): routes whose providers can
  launch CBM subprocesses (status, graph search, graph node) share one
  small concurrency gate (``MAX_EXPENSIVE_REQUESTS``). The excess is a
  fixed 429 ``viewer_busy`` response emitted BEFORE any provider runs,
  so one local client cannot amplify into unbounded concurrent
  provider/subprocess work. Static assets and the local-only metrics
  routes stay outside the gate.
- the Host header must name a loopback authority (``127.0.0.1``,
  ``localhost``, ``::1``) when present; a foreign authority name (the
  DNS-rebinding shape) is a plain 400 before any routing or provider
  work. An absent Host (HTTP/1.0-style clients) stays accepted.

There is no daemon mode, no PID file, no persistence, no service
registration, and no CORS surface.
"""

from __future__ import annotations

import http.server
import importlib.resources
import inspect
import json
import os
import socketserver
import threading
import urllib.parse
import webbrowser
from typing import Any, Callable, Dict, Optional, Tuple

#: The only interface the viewer ever binds. There is no host option in
#: the CLI, and no caller passes anything else.
VIEWER_HOST = "127.0.0.1"

#: Informational contract id reported by the status payload and the UI.
VIEWER_CONTRACT = "relinkra.viewer/v1"

#: Package directory holding the plain-file assets (no ``__init__.py``:
#: it is package DATA, not a subpackage).
ASSET_DIR = "viewer"

_HTML = "text/html; charset=utf-8"
_JAVASCRIPT = "application/javascript; charset=utf-8"
_CSS = "text/css; charset=utf-8"
_JSON = "application/json; charset=utf-8"
_TEXT = "text/plain; charset=utf-8"

#: Exact-match URL whitelist: route -> (asset name, content type).
_ROUTES = {
    "/": ("index.html", _HTML),
    "/app.js": ("app.js", _JAVASCRIPT),
    "/styles.css": ("styles.css", _CSS),
}

#: Exact-match status route (kept separate: its body is not an asset).
STATUS_PATH = "/api/status"

#: Exact-match graph-explorer routes (bodies come from caller providers).
GRAPH_SEARCH_PATH = "/api/graph/search"
GRAPH_NODE_PATH = "/api/graph/node"

# Exact-match metrics routes. Providers own identity resolution and storage;
# this transport remains a path-free read-only shell.
METRICS_CURRENT_PATH = "/api/metrics/current"
METRICS_HISTORY_PATH = "/api/metrics/history"

#: Fixed, non-sensitive failure body for a status provider that raises.
_STATUS_ERROR = {"error": "status unavailable"}

#: Fixed, non-sensitive failure body for an absent/failing graph provider.
_GRAPH_ERROR = {"error": "graph unavailable"}
_METRICS_ERROR = {"error": "metrics unavailable"}

#: Upper bound on concurrent requests that may run EXPENSIVE provider
#: work (M4/TSC-03). The graph routes and the status route can each
#: launch one or two CBM subprocesses per request, so this gate also
#: bounds aggregate subprocess amplification to at most
#: ``2 * MAX_EXPENSIVE_REQUESTS`` children in flight. Small and fixed on
#: purpose: the viewer is a local single-user tool, not a shared server.
MAX_EXPENSIVE_REQUESTS = 4

#: Exact-match routes whose providers may launch provider/CBM
#: subprocesses: the VIS-2 graph queries, and the status route (it probes
#: the stored graph through the adapter when CBM is available). These
#: run under the concurrency gate. Static assets and the metrics routes
#: are cheap local reads and deliberately stay outside it.
_GATED_PATHS = frozenset({STATUS_PATH, GRAPH_SEARCH_PATH, GRAPH_NODE_PATH})

#: Deterministic overload contract: an excess expensive request is
#: rejected fail-fast with this fixed JSON body — never queued, never a
#: traceback, never a provider call.
OVERLOAD_STATUS = 429
_OVERLOAD_ERROR = {
    "error": "viewer_busy",
    "message": "The viewer is busy with other requests; retry shortly.",
}
_OVERLOAD_BODY = json.dumps(_OVERLOAD_ERROR, indent=2, sort_keys=True).encode(
    "utf-8"
)

#: Hostnames the loopback viewer accepts in a Host header.
_LOOPBACK_HOSTNAMES = frozenset({"127.0.0.1", "localhost", "::1"})


def _loopback_host_allowed(header_value: Optional[str]) -> bool:
    """True when the Host header names a loopback authority, or is absent.

    The socket binds loopback only; this check refuses requests naming a
    foreign authority (the DNS-rebinding shape) while keeping normal
    browser and command-line use untouched. Only the hostname is compared
    — the port is whatever this socket actually bound. HTTP/1.0 clients
    may omit Host entirely; browsers always send it, and a browser driven
    at the viewer through a rebound foreign name is exactly the case this
    refuses.
    """
    if header_value is None:
        return True
    authority = header_value.strip()
    if not authority:
        return True
    if authority.startswith("["):
        end = authority.find("]")
        if end == -1:
            return False
        hostname = authority[1:end]
    else:
        hostname = authority.split(":", 1)[0]
    return hostname.lower() in _LOOPBACK_HOSTNAMES

_ASSET_CACHE: Dict[str, Optional[bytes]] = {}


def _read_asset(name: str) -> Optional[bytes]:
    """Read one packaged viewer asset, or None when it is missing.

    ``name`` is always a module-owned constant from :data:`_ROUTES`, so no
    request can steer this at an arbitrary file. Assets are read from the
    package through :mod:`importlib.resources`, which works from a wheel.
    """
    if name not in _ASSET_CACHE:
        try:
            _ASSET_CACHE[name] = (
                importlib.resources.files("relinkra")
                .joinpath(ASSET_DIR, name)
                .read_bytes()
            )
        except (OSError, ValueError):
            _ASSET_CACHE[name] = None
    return _ASSET_CACHE[name]


class _ViewerRequestHandler(http.server.BaseHTTPRequestHandler):
    """Request handler for the fixed viewer route whitelist.

    ``protocol_version`` is HTTP/1.0 so every connection closes after one
    response, which keeps shutdown and tests deterministic.
    """

    protocol_version = "HTTP/1.0"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Silence request logging: the viewer must not chatter on stdout."""
        return

    # -- response helpers ------------------------------------------------

    def _respond(
        self,
        status: int,
        content_type: str,
        body: bytes,
        extra_headers: Tuple[Tuple[str, str], ...] = (),
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        for name, value in extra_headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _path_only(self) -> str:
        """The decoded path component; query strings are ignored."""
        return urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)

    # -- routing ---------------------------------------------------------

    def _serve(self) -> None:
        if not _loopback_host_allowed(self.headers.get("Host")):
            # A foreign authority name (the DNS-rebinding shape) is
            # refused before any routing or provider work; nothing about
            # the request is echoed back.
            self._respond(400, _TEXT, b"Bad request")
            return
        path = self._path_only()
        route = _ROUTES.get(path)
        if route is not None:
            asset_name, content_type = route
            data = _read_asset(asset_name)
            if data is None:
                self._respond(500, _TEXT, b"viewer asset unavailable")
                return
            self._respond(200, content_type, data)
            return
        if path in _GATED_PATHS:
            self._serve_gated(path)
            return
        if path in (METRICS_CURRENT_PATH, METRICS_HISTORY_PATH):
            self._serve_metrics(path)
            return
        self._respond(404, _TEXT, b"Not found")

    def _serve_gated(self, path: str) -> None:
        """Serve one expensive route under the server's concurrency gate.

        Fail-fast: when every slot is held, the request is rejected with
        the fixed 429 body BEFORE the provider is invoked — no provider
        call, no subprocess, no queue. A held slot is released in
        ``finally``, so success, a provider failure, and a client
        disconnect mid-response all restore capacity.
        """
        gate = getattr(self.server, "expensive_gate", None)
        if gate is None:
            # Defensive: a handler attached to a server that never ran
            # ViewerServer.__init__ keeps the historical behavior rather
            # than crashing the connection.
            self._serve_expensive(path)
            return
        if not gate.acquire(blocking=False):
            self._respond(
                OVERLOAD_STATUS,
                _JSON,
                _OVERLOAD_BODY,
                extra_headers=(("Retry-After", "1"),),
            )
            return
        try:
            self._serve_expensive(path)
        finally:
            gate.release()

    def _serve_expensive(self, path: str) -> None:
        """Dispatch one admitted expensive route to its provider."""
        if path == STATUS_PATH:
            self._serve_status()
            return
        self._serve_graph(path)

    def _serve_status(self) -> None:
        provider: Optional[Callable[[], Any]] = getattr(
            self.server, "status_provider", None
        )
        try:
            payload = provider() if provider is not None else None
            body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        except Exception:
            body = json.dumps(
                dict(_STATUS_ERROR), indent=2, sort_keys=True
            ).encode("utf-8")
            self._respond(500, _JSON, body)
            return
        self._respond(200, _JSON, body)

    def _serve_graph(self, path: str) -> None:
        """Serve one graph route from the caller's provider.

        The provider receives the parsed query mapping (blank values
        kept) and must return ``(status, payload)``. Absent, raising, or
        malformed providers never escape: they become fixed JSON bodies
        and the server keeps serving.
        """
        attribute = (
            "graph_search_provider"
            if path == GRAPH_SEARCH_PATH
            else "graph_node_provider"
        )
        provider: Optional[Callable[[Dict[str, Any]], Any]] = getattr(
            self.server, attribute, None
        )
        error_body = json.dumps(
            dict(_GRAPH_ERROR), indent=2, sort_keys=True
        ).encode("utf-8")
        if provider is None:
            self._respond(503, _JSON, error_body)
            return
        params = urllib.parse.parse_qs(
            urllib.parse.urlsplit(self.path).query, keep_blank_values=True
        )
        try:
            result = provider(params)
            status, payload = result
            if isinstance(status, bool) or not isinstance(status, int):
                raise ValueError("graph provider returned an invalid status")
            body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        except Exception:
            self._respond(500, _JSON, error_body)
            return
        self._respond(status, _JSON, body)

    def _serve_metrics(self, path: str) -> None:
        attribute = (
            "metrics_current_provider"
            if path == METRICS_CURRENT_PATH
            else "metrics_history_provider"
        )
        provider: Optional[Callable[..., Any]] = getattr(self.server, attribute, None)
        is_history = path == METRICS_HISTORY_PATH
        empty = (
            {"schema_version": 1, "history": [], "count": 0,
             "no_data": True, "storage": "unavailable"}
            if is_history
            else {"schema_version": 1, "currentness": "unknown",
                  "observation": None, "no_data": True,
                  "storage": "unavailable"}
        )
        if provider is None:
            body = json.dumps(empty, indent=2, sort_keys=True).encode("utf-8")
            self._respond(200, _JSON, body)
            return
        try:
            params = urllib.parse.parse_qs(
                urllib.parse.urlsplit(self.path).query, keep_blank_values=True
            )
            try:
                signature = inspect.signature(provider)
                accepts_params = any(
                    parameter.kind in (inspect.Parameter.POSITIONAL_ONLY,
                                       inspect.Parameter.POSITIONAL_OR_KEYWORD,
                                       inspect.Parameter.VAR_POSITIONAL)
                    for parameter in signature.parameters.values()
                )
            except (TypeError, ValueError):
                accepts_params = False
            payload = provider(params) if accepts_params else provider()
            if not isinstance(payload, dict):
                raise ValueError("metrics provider returned a non-object")
            body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        except Exception:
            body = json.dumps(_METRICS_ERROR, indent=2, sort_keys=True).encode("utf-8")
            self._respond(500, _JSON, body)
            return
        self._respond(200, _JSON, body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib method name
        self._serve()

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib method name
        self._serve()

    def _method_not_allowed(self) -> None:
        self._respond(
            405,
            _TEXT,
            b"Method not allowed",
            extra_headers=(("Allow", "GET, HEAD"),),
        )

    def do_POST(self) -> None:  # noqa: N802 - stdlib method name
        self._method_not_allowed()

    def do_PUT(self) -> None:  # noqa: N802 - stdlib method name
        self._method_not_allowed()

    def do_PATCH(self) -> None:  # noqa: N802 - stdlib method name
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802 - stdlib method name
        self._method_not_allowed()

    def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib method name
        self._method_not_allowed()


class ViewerServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Threaded loopback server for the read-only viewer.

    ``allow_reuse_address`` is disabled on Windows so an occupied port
    fails to bind loudly instead of silently stealing the address; on
    POSIX it stays enabled for the usual rebind robustness after
    shutdown.

    Thread-per-request stays, but expensive provider work is bounded:
    ``expensive_gate`` admits at most ``MAX_EXPENSIVE_REQUESTS``
    concurrent requests on the gated routes (M4/TSC-03). The semaphore is
    per instance so independent servers never share capacity, and bounded
    so an over-release bug raises instead of silently inflating it.
    """

    daemon_threads = True
    allow_reuse_address = os.name != "nt"
    protocol_version = "HTTP/1.0"

    def __init__(
        self,
        server_address: Tuple[str, int],
        RequestHandlerClass: type = _ViewerRequestHandler,
        status_provider: Optional[Callable[[], Any]] = None,
        graph_search_provider: Optional[Callable[[Dict[str, Any]], Any]] = None,
        graph_node_provider: Optional[Callable[[Dict[str, Any]], Any]] = None,
        metrics_current_provider: Optional[Callable[[], Any]] = None,
        metrics_history_provider: Optional[Callable[[], Any]] = None,
    ) -> None:
        self.status_provider = status_provider
        self.graph_search_provider = graph_search_provider
        self.graph_node_provider = graph_node_provider
        self.metrics_current_provider = metrics_current_provider
        self.metrics_history_provider = metrics_history_provider
        self.expensive_gate = threading.BoundedSemaphore(MAX_EXPENSIVE_REQUESTS)
        super().__init__(server_address, RequestHandlerClass)


def create_server(
    status_provider: Optional[Callable[[], Any]],
    *,
    graph_search_provider: Optional[Callable[[Dict[str, Any]], Any]] = None,
    graph_node_provider: Optional[Callable[[Dict[str, Any]], Any]] = None,
    metrics_current_provider: Optional[Callable[[], Any]] = None,
    metrics_history_provider: Optional[Callable[[], Any]] = None,
    port: int = 0,
    host: str = VIEWER_HOST,
) -> ViewerServer:
    """Create (bind + listen) the viewer server.

    ``port=0`` asks the OS for a free port; ``server_address[1]`` then
    carries the chosen port. The socket binds only to ``host``, which
    defaults to the loopback interface; there is no wildcard option.
    ``graph_search_provider`` / ``graph_node_provider`` receive the
    parsed query mapping (``urllib.parse.parse_qs``, blank values kept)
    and must return ``(status, payload)``.
    """
    return ViewerServer(
        (str(host), int(port)),
        _ViewerRequestHandler,
        status_provider,
        graph_search_provider,
        graph_node_provider,
        metrics_current_provider,
        metrics_history_provider,
    )


def run_forever(server: ViewerServer) -> None:
    """Serve until Ctrl+C, then return with the server still open.

    Closing belongs to the caller (``server.server_close()``), so normal
    and interrupted exits share one shutdown path.
    """
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        return


def open_browser(url: str) -> bool:
    """Best-effort browser launch; never raises.

    A ``False`` verdict means the caller keeps the server alive and
    reports the URL instead of terminating.
    """
    try:
        return bool(webbrowser.open(url, new=2))
    except Exception:
        return False
