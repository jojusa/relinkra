"""Relinkra-owned read-only local viewer (VIS-1/VIS-2).

A minimal loopback HTTP server that serves the packaged viewer shell
(``relinkra/viewer/``) plus JSON routes whose payloads callers supply:
one status route and two bounded graph-explorer routes (search and
node). This module knows nothing about CBM, Engram, or the graph: it
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

There is no daemon mode, no PID file, no persistence, no service
registration, and no CORS surface.
"""

from __future__ import annotations

import http.server
import importlib.resources
import json
import os
import socketserver
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

#: Fixed, non-sensitive failure body for a status provider that raises.
_STATUS_ERROR = {"error": "status unavailable"}

#: Fixed, non-sensitive failure body for an absent/failing graph provider.
_GRAPH_ERROR = {"error": "graph unavailable"}

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
        if path == STATUS_PATH:
            self._serve_status()
            return
        if path in (GRAPH_SEARCH_PATH, GRAPH_NODE_PATH):
            self._serve_graph(path)
            return
        self._respond(404, _TEXT, b"Not found")

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
    ) -> None:
        self.status_provider = status_provider
        self.graph_search_provider = graph_search_provider
        self.graph_node_provider = graph_node_provider
        super().__init__(server_address, RequestHandlerClass)


def create_server(
    status_provider: Optional[Callable[[], Any]],
    *,
    graph_search_provider: Optional[Callable[[Dict[str, Any]], Any]] = None,
    graph_node_provider: Optional[Callable[[Dict[str, Any]], Any]] = None,
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