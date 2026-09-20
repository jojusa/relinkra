"""Storage adapters for the Relinkra memory layer.

``MemoryStore`` is the raw persistence protocol: save/search of opaque
records (title, content, type, project, scope, topic_key). All R1C policy
lives in ``relinkra.memory``; adapters know nothing about envelopes.

``EngramCLIAdapter`` writes through the ``engram save`` CLI — never
direct SQLite — so OpenCode (``engram mcp --tools=agent`` + HTTP :7437)
and Codex (``engram mcp``) share the same physical database without a
second permanent memory DB. Reads follow a three-tier path: the
configured Engram HTTP API first (``GET /search`` returns FULL
untruncated content; the CLI text output truncates at ~300 chars), then
a self-hosted loopback server over the SAME data directory the CLI
writes to, and only then the ``engram search`` CLI text output. The
loopback makes full-fidelity reads unconditional whenever the engram
binary exists; when HTTP is explicitly disabled the CLI fallback still
works, and records it could not read whole are flagged ``truncated``
so the policy layer can account for them honestly.

Transport hardening (TSC-02): the HTTP tiers are LOCAL-ONLY. Every
request goes through a redirect-refusing opener, the configured endpoint
must be an accepted loopback form (:func:`validate_engram_endpoint`),
and one response body is size-bounded
(``ENGRAM_HTTP_MAX_RESPONSE_BYTES``) so no endpoint can make Relinkra
allocate unbounded memory. Reachability is a transport observation,
never content provenance: a memory is trusted only after the R1C policy
layer re-validates its envelope (version, memory type, status, project
id, scope channel, repository identity, code refs). No cryptographic
authentication exists between Relinkra and Engram, and none is claimed.

``InMemoryStore`` is a deterministic offline store for tests.
"""

from __future__ import annotations

import atexit
import json
import os
import re
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Protocol, Tuple

from .memory import MemoryStoreError, sanitize_error

ENGRAM_BIN = "engram"
DEFAULT_ENGRAM_URL = "http://127.0.0.1:7437"
ENGRAM_URL_ENV = "ENGRAM_URL"
ENGRAM_DATA_DIR_ENV = "ENGRAM_DATA_DIR"
# Engram 1.20.0 currently caps every search response at 20 rows.  The
# HTTP/loopback API does not expose a cursor or total, and the CLI exposes no
# offset/page flag, so this is a detection threshold rather than a requested
# Relinkra result limit.  When the threshold is reached we use the existing
# complete `engram export` primitive instead of pretending the capped page is
# complete.
ENGRAM_SEARCH_CAP = 20

#: Hard byte bound on ONE Engram HTTP response body (TSC-02). Engram's HTTP
#: API answers with a JSON array capped at 20 rows (see ENGRAM_SEARCH_CAP),
#: so legitimate pages sit orders of magnitude below this bound, while an
#: unbounded ``resp.read()`` lets a broken or hostile endpoint make Relinkra
#: allocate arbitrarily much memory. ``Content-Length`` is checked first when
#: present, and the body read itself is capped at ``MAX + 1`` bytes so a
#: missing or lying header cannot smuggle an oversized body past the bound.
#: The bound applies per RESPONSE, never to the logical total across
#: legitimate pagination.
ENGRAM_HTTP_MAX_RESPONSE_BYTES = 8 * 1024 * 1024

#: Hosts the Engram HTTP transport accepts. Engram is a LOCAL shared
#: backend (docs/release.md, docs/memory-policy.md): the only documented
#: network forms are the loopback default and Relinkra's own ephemeral
#: loopback server. Public hosts, arbitrary remote hosts, and names that
#: could resolve off-box are refused before any request is sent; the
#: adapter then degrades to its loopback/CLI tiers.
_ENGRAM_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

#: Schemes the Engram HTTP transport supports. Engram serves plain HTTP;
#: everything else (https, ftp, file, ...) is refused as unsupported.
_ENGRAM_ALLOWED_SCHEMES = frozenset({"http"})


@dataclass
class StoredRecord:
    """One raw record as returned by a store search."""

    record_id: str
    storage_type: str
    title: str
    content: str
    project: str
    scope: str
    timestamp: str
    #: Transport-honesty heuristic for the CLI text path: ``engram
    #: search`` cuts long content with a trailing ``...``, so CLI-parsed
    #: content ending in ``...`` is flagged as possibly truncated. The
    #: flag only matters for records that FAIL envelope parsing — those
    #: count as ``skipped_truncated`` (transport loss) instead of
    #: ``skipped_malformed`` (corruption). Records that parse
    #: successfully are delivered regardless of the flag, and the full-
    #: fidelity tiers (HTTP/loopback) never set it.
    truncated: bool = False


class MemoryStore(Protocol):
    def save_record(
        self,
        *,
        title: str,
        content: str,
        storage_type: str,
        project: str,
        scope: str,
        topic_key: str,
    ) -> str:
        """Persist a record; returns the store-native record id."""
        ...

    def search_records(
        self,
        *,
        query: str,
        project: Optional[str] = None,
        storage_type: Optional[str] = None,
        limit: int = 50,
    ) -> List[StoredRecord]:
        """Full-text search over records, newest first."""
        ...


# ---------------------------------------------------------------------------
# Engram CLI output parsing
# ---------------------------------------------------------------------------
#
# engram search emits blocks like:
#
#   Found 2 memories:
#
#   [1] #54 (decision) — Some title
#       {"v":"rlkmem1",...}
#       2026-05-31 00:29:02 | project: rlk_... | scope: project
#
# Long content is truncated by the CLI at ~300 chars with a trailing
# "..."; such blocks no longer parse as JSON envelopes. The parser marks
# them ``truncated=True`` so the policy layer can account for the
# transport loss separately (``skipped_truncated``) instead of inflating
# the malformed counter. "No memories found for:" means zero results.
# subprocess is decoded as UTF-8 explicitly: the block header uses an
# em-dash and the Windows locale codec (cp1252) would otherwise mangle
# it and silently break parsing.

_BLOCK_HEADER_RE = re.compile(
    r"^\[(?P<idx>\d+)\]\s+#(?P<rid>\d+)\s+\((?P<rtype>[^)]+)\)"
    r"\s+[\u2014-]\s+(?P<title>.*)$"
)
_BLOCK_META_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
    r"\s+\|\s+project:\s+(?P<project>.*?)\s+\|\s+scope:\s+(?P<scope>\S+)\s*$"
)
_SAVE_RESULT_RE = re.compile(r"#(\d+)")


def parse_search_output(output: str) -> List[StoredRecord]:
    """Parse ``engram search`` text output into raw records.

    Tolerant of truncated content, blank lines, and preamble. Content
    lines are the 4-space-indented lines between the header and the
    trailing metadata line; they are rejoined to reconstruct the original
    single-line JSON envelope.
    """
    records: List[StoredRecord] = []
    current: Optional[dict] = None
    for line in (output or "").splitlines():
        header = _BLOCK_HEADER_RE.match(line)
        if header:
            if current is not None:
                records.append(_finalize_record(current))
            current = {
                "record_id": header.group("rid"),
                "storage_type": header.group("rtype").strip(),
                "title": header.group("title").strip(),
                "content_lines": [],
                "project": "",
                "scope": "",
                "timestamp": "",
            }
            continue
        if current is None:
            continue
        if not line.startswith("    "):
            continue
        body = line[4:]
        meta = _BLOCK_META_RE.match(body)
        if meta:
            current["timestamp"] = meta.group("ts")
            current["project"] = meta.group("project")
            current["scope"] = meta.group("scope")
            records.append(_finalize_record(current))
            current = None
        else:
            current["content_lines"].append(body)
    if current is not None:
        records.append(_finalize_record(current))
    return records


def _finalize_record(raw: dict) -> StoredRecord:
    content = "\n".join(raw["content_lines"])
    return StoredRecord(
        record_id=raw["record_id"],
        storage_type=raw["storage_type"],
        title=raw["title"],
        content=content,
        project=raw["project"],
        scope=raw["scope"],
        timestamp=raw["timestamp"],
        # The CLI display cuts long content and appends "..."; say so on
        # the record instead of leaving downstream parsers to guess why
        # an envelope fails to parse.
        truncated=content.endswith("..."),
    )


def parse_save_output(output: str) -> str:
    """Extract the observation id from ``engram save`` output."""
    match = _SAVE_RESULT_RE.search(output or "")
    return match.group(1) if match else ""


# ---------------------------------------------------------------------------
# Loopback read server
# ---------------------------------------------------------------------------


def _free_tcp_port() -> int:
    """Ask the OS for a free loopback port (bind, read, release)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class _LoopbackServer:
    """Ephemeral ``engram serve`` bound to the CLI's own data directory.

    The docs declare HTTP the authoritative read path ("GET /search
    returns FULL untruncated content"); this makes that true
    unconditionally. When no external endpoint is configured or
    reachable, the adapter starts its own short-lived server over the
    SAME ``ENGRAM_DATA_DIR`` the CLI writes to, so reads get full
    fidelity instead of the CLI text output's ~300-char truncation.

    Lifecycle contract:

    - Start is LAZY; failures (missing binary, repeated bind or
      readiness failures) are absorbed into ``_failed`` — nothing here
      ever raises to a caller. A child that dies AFTER a healthy start
      is restarted on the next ``ensure_ready`` instead of letting a
      long-lived host (MCP server) silently lose the lossless tier for
      the rest of its life.
    - ``close()`` is idempotent and runs a terminate -> wait -> kill
      ladder; instances are shared per (binary, data dir) through
      :func:`_shared_loopback` so several adapters reuse one child.
    - Startup is serialized by a module lock and FAILED instances stay
      cached, so concurrent searches can never double-spawn and a
      broken ``engram serve`` is probed at most once per process.
    """

    READY_TIMEOUT_SECONDS = 10.0
    #: The free-port probe and the child's bind race each other, and
    #: Windows excludes some ephemeral port ranges entirely; retry a
    #: few times so one transient collision cannot permanently degrade
    #: the lossless read path.
    MAX_START_ATTEMPTS = 3

    def __init__(self, engram_bin: str, data_dir: str):
        self._engram_bin = engram_bin
        self._data_dir = data_dir
        self.base_url: Optional[str] = None
        self._failed = False
        self._process: Optional[subprocess.Popen] = None

    def ensure_ready(self) -> bool:
        """Lazily start once; True when the endpoint is usable."""
        if self.base_url is not None:
            if self._child_alive():
                return True
            # Healthy start earlier, child gone since: fall through and
            # try to start again rather than degrading forever.
            self.base_url = None
        if not self._failed:
            try:
                self._start()
            except Exception:
                # Any unexpected failure degrades to the CLI text path;
                # a read accelerator must never break a search.
                self._shutdown_child()
                self._failed = True
        return self.base_url is not None

    def _child_alive(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def _start(self) -> None:
        for _ in range(self.MAX_START_ATTEMPTS):
            port = _free_tcp_port()
            env = {**os.environ, ENGRAM_DATA_DIR_ENV: self._data_dir}
            popen_kwargs = {}
            # Keep console-less Windows hosts from flashing a window.
            create_no_window = getattr(subprocess, "CREATE_NO_WINDOW", None)
            if create_no_window is not None:
                popen_kwargs["creationflags"] = create_no_window
            self._process = subprocess.Popen(
                [self._engram_bin, "serve", str(port)],
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                **popen_kwargs,
            )
            if self._wait_until_ready(port):
                self.base_url = f"http://127.0.0.1:{port}"
                return
            self._shutdown_child()
        self._failed = True

    def _wait_until_ready(self, port: int) -> bool:
        process = self._process
        if process is None:  # pragma: no cover - defensive
            return False
        url = f"http://127.0.0.1:{port}/search?q=e&limit=1"
        deadline = time.monotonic() + self.READY_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return False
            try:
                with _engram_http_open(url, timeout=1.0) as response:
                    if response.status == 200:
                        return True
            except urllib.error.HTTPError as exc:
                _close_http_error(exc)
                time.sleep(0.1)
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        return False

    def _shutdown_child(self) -> None:
        process = self._process
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
                pass  # reap at exit rather than block the caller forever

    def close(self) -> None:
        """Terminate the child; safe to call any number of times."""
        self._shutdown_child()


#: One shared loopback per (binary, data dir) per process: adapters built
#: against the same isolated store must reuse a single ephemeral server
#: instead of racing ports or leaking children. FAILED instances stay in
#: the registry too, so a broken ``engram serve`` is probed once per
#: process, not on every search.
_LOOPBACK_SERVERS: Dict[Tuple[str, str], _LoopbackServer] = {}

#: Serializes loopback creation and startup: concurrent first searches
#: must spawn at most ONE child per (binary, data dir), never racing
#: duplicates whose loser would leak.
_LOOPBACK_LOCK = threading.Lock()


def _shared_loopback(engram_bin: str, data_dir: str) -> Optional[_LoopbackServer]:
    """Return the healthy shared loopback for this binary/data-dir pair.

    Creates it on first use and starts it lazily. Returns None when the
    tier is unusable (binary cannot serve); callers then degrade to the
    CLI text path without any error.
    """
    key = (engram_bin, data_dir)
    with _LOOPBACK_LOCK:
        server = _LOOPBACK_SERVERS.get(key)
        if server is None:
            server = _LoopbackServer(engram_bin, data_dir)
            _LOOPBACK_SERVERS[key] = server
        if server.ensure_ready():
            return server
        return None


def _close_all_loopbacks() -> None:
    """Shut every loopback child down and empty the registry."""
    with _LOOPBACK_LOCK:
        servers = list(_LOOPBACK_SERVERS.values())
        _LOOPBACK_SERVERS.clear()
    for server in servers:
        server.close()


atexit.register(_close_all_loopbacks)


def _deterministic_newest_first(
    records: List[StoredRecord],
) -> List[StoredRecord]:
    """Order a store page deterministically, newest first.

    The backend's result order is incidental: FTS ranking for HTTP
    reads, output order for CLI reads. The MemoryStore protocol promises
    newest-first pages, so the adapter enforces that contract itself
    instead of trusting the read tier — sorting by (timestamp,
    record_id) makes identical inputs produce identical page order and
    keeps the page cut deterministic regardless of which tier served
    the read.
    """
    return sorted(
        records, key=lambda r: (r.timestamp, r.record_id), reverse=True
    )


def _fts_tokens(query: str) -> List[str]:
    """Split a query the way Engram's default ``unicode61`` tokenizer does.

    ``unicode61`` treats punctuation (including ``_``) as a token boundary,
    folds case, and removes diacritics.  Quoting each resulting token before
    passing it to FTS5 makes operators such as ``OR`` ordinary terms and
    prevents user input from changing the MATCH expression.
    """
    tokens: List[str] = []
    current: List[str] = []
    for char in query or "":
        if char.isalnum():
            current.append(char)
        elif current:
            tokens.append("".join(current))
            current = []
    if current:
        tokens.append("".join(current))
    return tokens


def _fts_match_query(query: str) -> Optional[str]:
    """Build Engram's safe, whitespace-term-AND FTS5 MATCH expression.

    Engram wraps each whitespace-delimited term as an FTS phrase.  Therefore
    punctuation *inside* a term remains significant as an adjacency phrase
    (``foo-bar``), while punctuation-only terms are discarded.  ``None``
    means an actually empty query (match all); an empty string means a
    nonblank query with no searchable terms (match none).
    """
    raw_query = query or ""
    if not raw_query.strip():
        return None
    terms = []
    for term in raw_query.split():
        if not _fts_tokens(term):
            continue
        # Keep punctuation in the phrase so foo-bar requires adjacent foo,
        # bar tokens, matching the backend's whitespace-term normalization.
        terms.append('"' + term.replace('"', '""') + '"')
    return " AND ".join(terms)


def _export_query_matches(
    query: str,
    title: str,
    content: str,
    tool_name: str = "",
    storage_type: str = "",
    project: str = "",
    topic_key: str = "",
) -> bool:
    """Apply Engram's complete-export FTS predicate to one record.

    This compatibility helper intentionally uses the same six columns as
    Engram 1.20's ``observations_fts`` table.  The export path batches rows in
    one ephemeral database; keeping this helper separate also makes the
    predicate easy to regression-test directly.
    """
    match_query = _fts_match_query(query)
    if match_query is None:
        return True
    if not match_query:
        return False
    try:
        connection = sqlite3.connect(":memory:")
        try:
            connection.execute(
                "CREATE VIRTUAL TABLE observations_fts USING fts5("
                "title, content, tool_name, type, project, topic_key, "
                "tokenize='unicode61')"
            )
            connection.execute(
                "INSERT INTO observations_fts "
                "(title, content, tool_name, type, project, topic_key) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (title, content, tool_name, storage_type, project, topic_key),
            )
            return connection.execute(
                "SELECT 1 FROM observations_fts "
                "WHERE observations_fts MATCH ? LIMIT 1",
                (match_query,),
            ).fetchone() is not None
        finally:
            connection.close()
    except Exception:
        # The batched export path turns this into an honest incomplete read;
        # this helper has no metadata channel and therefore fails closed.
        return False


# ---------------------------------------------------------------------------
# Engram HTTP transport policy (TSC-02)
# ---------------------------------------------------------------------------


class EngramResponseTooLargeError(Exception):
    """One Engram HTTP response exceeded the transport byte bound.

    Raised instead of returning a sentinel so the caller can record an
    explicit, content-free diagnostic while every other transport failure
    keeps its existing silent-fallback semantics.
    """


def validate_engram_endpoint(url: str) -> Optional[str]:
    """Return a rejection reason for an Engram HTTP base URL, else ``None``.

    Engram is a local shared backend: Relinkra talks to it over loopback
    (``127.0.0.1``, ``::1``, ``localhost``) or its own ephemeral loopback
    server, and nothing in the product documents a remote endpoint. This
    validator therefore accepts ONLY the supported local forms and refuses
    everything a configured ``ENGRAM_URL`` could smuggle in:

    - non-loopback hosts (public or arbitrary remote, including lookalike
      names such as ``127.0.0.1.example.com``),
    - credential-bearing URLs (``user[:password]@`` userinfo),
    - unsupported or malformed schemes, missing hosts, malformed ports,
      whitespace/control characters, and query/fragment suffixes.

    Validation is by literal host identity, never by DNS resolution: a
    name that is not one of the loopback literals is refused outright, so
    there is no validate-then-resolve window a hostile resolver could win.
    The rejection reason is a fixed, credential-free phrase; the URL
    itself is never echoed.
    """
    candidate = (url or "").strip()
    if not candidate:
        return "empty endpoint"
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in candidate):
        return "malformed endpoint"
    try:
        parts = urllib.parse.urlsplit(candidate)
        host = parts.hostname
        parts.port  # raises ValueError on a malformed/out-of-range port
    except ValueError:
        return "malformed endpoint"
    if parts.scheme.lower() not in _ENGRAM_ALLOWED_SCHEMES:
        return "unsupported scheme"
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        return "credential-bearing endpoint"
    if parts.query or parts.fragment:
        return "endpoint carries query or fragment"
    if not host:
        return "missing host"
    if host.lower() not in _ENGRAM_LOOPBACK_HOSTS:
        return "non-loopback host"
    return None


def _read_bounded_response_body(
    response, max_bytes: int = ENGRAM_HTTP_MAX_RESPONSE_BYTES
) -> bytes:
    """Read one HTTP response body without materializing more than
    ``max_bytes`` bytes.

    Two independent guards, because neither alone is sufficient:

    1. A ``Content-Length`` header that parses to an integer larger than
       ``max_bytes`` refuses the response BEFORE any body byte is read —
       no allocation and no wait for a body already known to be
       oversized.
    2. The body read itself is capped at ``max_bytes + 1`` bytes. A
       missing header, a chunked body, or a header that lies small cannot
       exceed the bound: the extra sentinel byte proves overflow and the
       whole response is refused. Partial JSON is never handed to the
       parser, and there is no fallback to an unbounded read.

    Raises :class:`EngramResponseTooLargeError` for an oversized response;
    a body that is not bytes raises ``ValueError``. ``urllib`` does not
    transparently decompress, so the bound applies to exactly the bytes
    Relinkra materializes.
    """
    declared = None
    headers = getattr(response, "headers", None)
    if headers is not None:
        try:
            declared = headers.get("Content-Length")
        except Exception:  # pragma: no cover - defensive header access
            declared = None
    if declared is not None:
        try:
            declared_bytes = int(str(declared).strip())
        except (TypeError, ValueError):
            declared_bytes = None
        if declared_bytes is not None and declared_bytes > max_bytes:
            raise EngramResponseTooLargeError(
                "engram HTTP response declares an oversized body"
            )
    body = response.read(max_bytes + 1)
    if not isinstance(body, (bytes, bytearray)):
        raise ValueError("engram HTTP response body is not bytes")
    if len(body) > max_bytes:
        raise EngramResponseTooLargeError(
            "engram HTTP response body exceeds the transport bound"
        )
    return bytes(body)


class _EngramNoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse every HTTP redirect on the Engram transport.

    Engram answers one local JSON API and never legitimately redirects.
    Following one would let the response decide where Relinkra sends the
    next request — exactly how a loopback endpoint could bypass the
    loopback-only endpoint policy. The refusal surfaces as an ordinary
    transport failure and degrades to the next read tier; redirect
    support is deliberately NOT added.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Close the redirect response before refusing it: its body is
        # never read (it could be unbounded) and the socket is released
        # deterministically instead of at GC time. A plain URLError is
        # raised instead of HTTPError so no response wrapper survives the
        # refusal.
        if fp is not None:
            try:
                fp.close()
            except OSError:
                pass
        raise urllib.error.URLError(
            f"engram transport refuses HTTP redirects ({code})"
        )


#: One process-wide opener for every Engram HTTP request (configured
#: endpoint and internal loopback alike): redirects are refused so no
#: response can move the transport off the validated destination.
_ENGRAM_OPENER = urllib.request.build_opener(_EngramNoRedirectHandler())


def _engram_http_open(url: str, timeout: float):
    """Open an Engram HTTP request with redirects disabled."""
    return _ENGRAM_OPENER.open(url, timeout=timeout)


def _close_http_error(exc: urllib.error.HTTPError) -> None:
    """Release an HTTPError response wrapper instead of leaking it to GC.

    An error-status response never contributes data; closing it here keeps
    the transport deterministic (and warning-free under
    ``-W error::ResourceWarning``) instead of leaving the socket to the
    garbage collector.
    """
    try:
        exc.close()
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Engram CLI adapter
# ---------------------------------------------------------------------------


class EngramCLIAdapter:
    """MemoryStore backed by Engram (HTTP/loopback reads, CLI fallback).

    Writes always go through ``engram save``. Reads follow a three-tier
    path: the configured Engram HTTP API first (``GET
    /search?q=...&project=...`` returns FULL untruncated content, unlike
    the CLI text output which truncates at ~300 chars), then a
    self-hosted loopback server over the SAME data directory the CLI
    writes to, and only then ``engram search``. The loopback restores
    full-fidelity reads whenever the engram binary exists; records the
    CLI path could not hand back whole carry ``truncated=True`` so the
    policy layer counts the transport loss honestly.

    The HTTP base URL comes from explicit ``http_url`` first, then the
    ``ENGRAM_URL`` env var. When a non-empty ``ENGRAM_DATA_DIR`` is set
    without an explicit URL, external HTTP is disabled so an isolated
    CLI process cannot silently read the default shared server (the
    loopback still serves THAT data dir). Otherwise the default is
    ``http://127.0.0.1:7437``. Pass ``http_url=""`` (or set
    ``ENGRAM_URL=""``) for hard-off semantics: no external endpoint AND
    no loopback, CLI-only reads with honest truncation accounting.

    ``project_alias`` (optional) rewrites ONLY the physical project filter
    of store queries: searches are sent to Engram under the alias (e.g.
    ``relinkra``) instead of the logical ``rlk_`` id, because some MCP
    front-ends reject unknown ``rlk_`` projects. Writes are unaffected.
    Isolation is preserved: the R1C policy layer always re-filters parsed
    envelopes by the logical ``project_id``, so an aliased search can
    never leak another project's memories into a query result.

    TSC-02: the HTTP transport is local-only. A configured endpoint that
    is not an accepted loopback form is never contacted (the search
    degrades to the loopback/CLI tiers and records an
    ``engram_endpoint_rejected`` retrieval diagnostic), redirects are
    refused, and every response body is size-bounded. ``read_mode``
    reports the OBSERVED transport (http/loopback/cli) — it is not an
    authenticated provenance claim.
    """

    def __init__(
        self,
        engram_bin: str = ENGRAM_BIN,
        timeout: float = 30.0,
        http_url: Optional[str] = None,
        http_timeout: float = 2.0,
        project_alias: Optional[str] = None,
    ):
        self.engram_bin = engram_bin
        self.timeout = timeout
        # An EXPLICIT falsy URL (argument or env) means hard-off: user
        # intent to keep every read on the CLI path, loopback included.
        self._http_explicitly_disabled = (
            (http_url is not None and not http_url)
            or (
                ENGRAM_URL_ENV in os.environ
                and os.environ[ENGRAM_URL_ENV].strip() == ""
            )
        )
        self.allow_loopback = not self._http_explicitly_disabled
        #: How the last search actually read data:
        #: "http" | "loopback" | "cli" | "unknown" (never searched).
        self.read_mode: str = "unknown"
        #: Additive retrieval accounting for callers that need to distinguish
        #: a complete backend page from a complete-store export or an honest
        #: partial fallback.  The list-returning MemoryStore protocol stays
        #: backwards compatible; MemoryService reads this side channel.
        self.last_search_metadata: dict = {
            "backend_window_complete": True,
            "backend_limit": None,
            "retrieval_scope": "backend_window",
            "retrieval_complete": True,
            "retrieval_diagnostic": None,
            "retrieval_diagnostics": [],
        }
        if http_url is None:
            if ENGRAM_URL_ENV in os.environ:
                http_url = os.environ[ENGRAM_URL_ENV]
            elif os.environ.get(ENGRAM_DATA_DIR_ENV):
                http_url = ""
            else:
                http_url = DEFAULT_ENGRAM_URL
        self.http_url = (http_url or "").rstrip("/")
        self.http_timeout = http_timeout
        self.project_alias = (project_alias or "").strip() or None

    def _run(self, args: List[str]) -> str:
        try:
            result = subprocess.run(
                [self.engram_bin, *args],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=self.timeout,
            )
        except FileNotFoundError as exc:
            raise MemoryStoreError(
                f"engram executable not found: {self.engram_bin}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise MemoryStoreError("engram command timed out") from exc
        if result.returncode != 0:
            detail = sanitize_error((result.stderr or result.stdout or "").strip())
            raise MemoryStoreError(f"engram {' '.join(args[:1])} failed: {detail}")
        return result.stdout or ""

    def save_record(
        self,
        *,
        title: str,
        content: str,
        storage_type: str,
        project: str,
        scope: str,
        topic_key: str,
    ) -> str:
        args = [
            "save",
            title,
            content,
            "--type",
            storage_type,
            "--project",
            project,
            "--scope",
            scope,
        ]
        if topic_key:
            args += ["--topic", topic_key]
        return parse_save_output(self._run(args))

    def search_records(
        self,
        *,
        query: str,
        project: Optional[str] = None,
        storage_type: Optional[str] = None,
        limit: int = 50,
    ) -> List[StoredRecord]:
        limit = max(1, int(limit))
        self.last_search_metadata = {
            "backend_window_complete": True,
            "backend_limit": None,
            "retrieval_scope": "backend_window",
            "retrieval_complete": True,
            "retrieval_diagnostic": None,
            "retrieval_diagnostics": [],
        }
        # project_alias rewrites the PHYSICAL store filter only; the R1C
        # policy layer still filters parsed envelopes by the logical
        # project_id, so cross-project isolation is preserved.
        physical_project = self.project_alias or project
        http_records = self._http_search(query, physical_project, limit)
        if http_records is not None:
            self.read_mode = "http"
            records = self._recover_capped_window(
                http_records, query, physical_project, storage_type
            )
            return self._filtered(records, storage_type, limit)
        if self.allow_loopback:
            data_dir = os.environ.get(ENGRAM_DATA_DIR_ENV) or str(
                Path.home() / ".engram"
            )
            loopback = _shared_loopback(self.engram_bin, data_dir)
            if loopback is not None and loopback.base_url:
                loopback_records = self._http_search(
                    query, physical_project, limit, base_url=loopback.base_url
                )
                if loopback_records is not None:
                    self.read_mode = "loopback"
                    records = self._recover_capped_window(
                        loopback_records,
                        query,
                        physical_project,
                        storage_type,
                    )
                    return self._filtered(records, storage_type, limit)
        self.read_mode = "cli"
        args = ["search", query, "--limit", str(limit)]
        if physical_project:
            args += ["--project", physical_project]
        if storage_type:
            args += ["--type", storage_type]
        output = self._run(args)
        if "No memories found" in output:
            return []
        records = parse_search_output(output)
        records = self._recover_capped_window(
            records, query, physical_project, storage_type
        )
        # The CLI backend already applied its own limit to its own
        # (incidental) ordering; re-ordering the parsed page is the only
        # deterministic part left in Relinkra's hands when export recovery is
        # unavailable.  Type filtering remains client-side for the recovered
        # complete path so all tiers have the same pipeline.
        return self._filtered(records, storage_type, limit)

    def _recover_capped_window(
        self,
        records: List[StoredRecord],
        query: str,
        project: Optional[str],
        storage_type: Optional[str],
    ) -> List[StoredRecord]:
        """Recover a capped backend page through Engram's complete export.

        Engram 1.20.0 returns exactly 20 rows for a matching search even when
        Relinkra asks for 200, and it ignores offset/page/cursor parameters.
        Once that cap is reached, the page cannot prove that its newest rows
        are the newest rows in the store.  ``engram export`` is an existing
        supported read primitive that returns all observations, so use it only
        at the cap and filter the exported records locally before they enter
        the ordering/policy pipeline.  If export is unavailable, preserve the
        backend page but expose an explicit incomplete retrieval scope.
        """
        if len(records) < ENGRAM_SEARCH_CAP:
            return records
        exported = self._export_search(
            query, project, storage_type, authoritative_records=records
        )
        if exported is not None:
            # _export_search may have had to reconcile records from the
            # authoritative capped page.  Preserve that diagnostic rather
            # than claiming a complete export when its matcher disagreed.
            self.last_search_metadata.update(
                {
                    "backend_window_complete": False,
                    "backend_limit": ENGRAM_SEARCH_CAP,
                    "retrieval_scope": "complete_export",
                    "retrieval_complete": self.last_search_metadata.get(
                        "retrieval_complete", True
                    ),
                }
            )
            return exported
        self.last_search_metadata = {
            "backend_window_complete": False,
            "backend_limit": ENGRAM_SEARCH_CAP,
            "retrieval_scope": "partial",
            "retrieval_complete": False,
            "retrieval_diagnostic": self.last_search_metadata.get(
                "retrieval_diagnostic"
            )
            or "complete_export_unavailable",
            "retrieval_diagnostics": self.last_search_metadata.get(
                "retrieval_diagnostics", []
            ),
        }
        return records

    def _export_search(
        self,
        query: str,
        project: Optional[str],
        storage_type: Optional[str],
        authoritative_records: Optional[List[StoredRecord]] = None,
    ) -> Optional[List[StoredRecord]]:
        """Read and filter the complete Engram JSON export, if available.

        Export is deliberately invoked only after the 20-row cap is observed;
        ordinary small searches stay on the fast HTTP/loopback/CLI path.  The
        temporary file is outside the repository and is removed immediately.
        Project/type/query filtering happens before deterministic ordering so
        foreign or private observations never influence result ranking.
        """
        fd, path = tempfile.mkstemp(
            prefix="relinkra-engram-export-", suffix=".json"
        )
        os.close(fd)
        try:
            self._run(["export", path])
            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (MemoryStoreError, OSError, TypeError, ValueError):
            self._set_retrieval_diagnostic("complete_export_unavailable")
            return None
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

        observations = payload.get("observations") if isinstance(payload, dict) else None
        if not isinstance(observations, list):
            self._set_retrieval_diagnostic("complete_export_malformed")
            return None

        candidates: List[Tuple[StoredRecord, Tuple[str, ...]]] = []
        for item in observations:
            if not isinstance(item, dict):
                self._set_retrieval_diagnostic("complete_export_malformed")
                return None
            # Deleted observations are not search results.  Engram's export
            # schema has used both a timestamp and a boolean marker across
            # versions; accept either without assuming a migration shape.
            if item.get("deleted_at") or item.get("deleted"):
                continue
            item_project = str(item.get("project") or "")
            if project and item_project != project:
                continue
            item_type = str(item.get("type") or item.get("storage_type") or "")
            if storage_type and item_type != storage_type:
                continue
            title = str(item.get("title") or "")
            content = str(item.get("content") or "")
            record = StoredRecord(
                record_id=str(item.get("id") or item.get("sync_id") or ""),
                storage_type=item_type,
                title=title,
                content=content,
                project=item_project,
                scope=str(item.get("scope") or ""),
                timestamp=str(
                    item.get("timestamp")
                    or item.get("created_at")
                    or item.get("updated_at")
                    or ""
                ),
            )
            candidates.append(
                (
                    record,
                    (
                        title,
                        content,
                        str(item.get("tool_name") or item.get("source_tool") or ""),
                        item_type,
                        item_project,
                        str(item.get("topic_key") or ""),
                    ),
                )
            )

        records = self._fts_filter_export(candidates, query)
        if records is None:
            self._set_retrieval_diagnostic("fts_unavailable")
            return None

        # The backend page is authoritative for every ID it returned.  An
        # export may be stale, use a different id field, or expose a tokenizer
        # mismatch.  Never silently drop those page records: union them and
        # downgrade completeness so callers know the export was reconciled.
        exported_ids = {record.record_id for record in records if record.record_id}
        missing = [
            record
            for record in (authoritative_records or [])
            if record.record_id and record.record_id not in exported_ids
        ]
        if missing:
            records.extend(missing)
            self.last_search_metadata["retrieval_complete"] = False
            self._set_retrieval_diagnostic(
                {
                    "code": "backend_page_reconciled",
                    "missing_backend_ids": [r.record_id for r in missing],
                }
            )
        return records

    def _set_retrieval_diagnostic(self, diagnostic) -> None:
        """Add an explicit, machine-readable retrieval honesty diagnostic."""
        diagnostics = self.last_search_metadata.setdefault(
            "retrieval_diagnostics", []
        )
        if diagnostic not in diagnostics:
            diagnostics.append(diagnostic)
        if self.last_search_metadata.get("retrieval_diagnostic") is None:
            self.last_search_metadata["retrieval_diagnostic"] = diagnostic

    @staticmethod
    def _fts_filter_export(
        candidates: List[Tuple[StoredRecord, Tuple[str, ...]]], query: str
    ) -> Optional[List[StoredRecord]]:
        """Filter export rows with a temporary Engram-compatible FTS5 table."""
        match_query = _fts_match_query(query)
        if match_query is None:
            return [record for record, _fields in candidates]
        if not match_query:
            return []
        try:
            connection = sqlite3.connect(":memory:")
            try:
                connection.execute(
                    "CREATE VIRTUAL TABLE observations_fts USING fts5("
                    "title, content, tool_name, type, project, topic_key, "
                    "tokenize='unicode61')"
                )
                connection.executemany(
                    "INSERT INTO observations_fts "
                    "(title, content, tool_name, type, project, topic_key) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (fields for _record, fields in candidates),
                )
                rows = connection.execute(
                    "SELECT rowid FROM observations_fts "
                    "WHERE observations_fts MATCH ?",
                    (match_query,),
                ).fetchall()
                return [candidates[int(row[0]) - 1][0] for row in rows]
            finally:
                connection.close()
        except Exception:
            return None

    @staticmethod
    def _filtered(
        records: List[StoredRecord], storage_type: Optional[str], limit: int
    ) -> List[StoredRecord]:
        """Deterministic page cut for full-content reads: newest-first
        order first, then the type filter, then the limit cut."""
        records = _deterministic_newest_first(records)
        if storage_type:
            records = [r for r in records if r.storage_type == storage_type]
        return records[:limit]

    # -- HTTP read path ---------------------------------------------------

    def _http_search(
        self,
        query: str,
        project: Optional[str],
        limit: int,
        base_url: Optional[str] = None,
    ) -> Optional[List[StoredRecord]]:
        """Search via an Engram HTTP API; None signals fallback.

        Serves both read tiers with identical logic and timeouts: the
        configured endpoint (default ``base_url``) or a loopback server
        over the CLI's own data dir. Returns full untruncated records.

        TSC-02: the endpoint must be an accepted LOCAL form before a
        request is sent, redirects are refused by the shared opener, and
        the response body is size-bounded. Any failure — endpoint
        refused, server down, timeout, redirect, oversized body, bad
        payload — returns None so the caller falls back; HTTP is
        strictly an optional read accelerator over the same physical
        backend.
        """
        base = (base_url if base_url is not None else self.http_url).rstrip("/")
        if not base:
            return None
        rejection = validate_engram_endpoint(base)
        if rejection is not None:
            # Never contact a refused endpoint: the reason is a fixed,
            # credential-free phrase and the URL itself is not echoed.
            self._set_retrieval_diagnostic(
                {"code": "engram_endpoint_rejected", "reason": rejection}
            )
            return None
        params = {"q": query, "limit": str(limit)}
        if project:
            params["project"] = project
        url = f"{base}/search?{urllib.parse.urlencode(params)}"
        try:
            with _engram_http_open(url, timeout=self.http_timeout) as resp:
                try:
                    body = _read_bounded_response_body(resp)
                except EngramResponseTooLargeError:
                    self._set_retrieval_diagnostic(
                        {
                            "code": "engram_response_rejected",
                            "reason": "oversized_response",
                            "max_bytes": ENGRAM_HTTP_MAX_RESPONSE_BYTES,
                        }
                    )
                    return None
                payload = json.loads(body.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            _close_http_error(exc)
            return None
        except (OSError, ValueError, urllib.error.URLError):
            return None
        # Engram marshals an EMPTY result set as JSON null (a nil list).
        # That is an authoritative "no matches", NOT a transport failure:
        # treating it as one would bounce every empty search into the
        # lossy CLI tier and misreport the read path. Any other non-list
        # payload still signals fallback.
        if payload is None:
            return []
        if not isinstance(payload, list):
            return None
        try:
            return [self._record_from_http(item) for item in payload]
        except (AttributeError, TypeError):
            return None

    @staticmethod
    def _record_from_http(item: dict) -> StoredRecord:
        return StoredRecord(
            record_id=str(item.get("id", "")),
            storage_type=str(item.get("type") or item.get("storage_type") or ""),
            title=str(item.get("title") or ""),
            content=str(item.get("content") or ""),
            project=str(item.get("project") or ""),
            scope=str(item.get("scope") or ""),
            timestamp=str(item.get("timestamp") or item.get("created_at") or ""),
        )


# ---------------------------------------------------------------------------
# Deterministic offline store
# ---------------------------------------------------------------------------


class InMemoryStore:
    """Deterministic in-process store for offline tests.

    Token-AND matching over title+content (rough Engram FTS analogue),
    newest-first ordering, monotonically increasing ids.
    """

    def __init__(self):
        self._records: List[StoredRecord] = []
        self._next_id = 1
        self.saved_args: List[dict] = []
        self.last_search_metadata = {
            "backend_window_complete": True,
            "backend_limit": None,
            "retrieval_scope": "in_memory_complete",
            "retrieval_complete": True,
        }

    def save_record(
        self,
        *,
        title: str,
        content: str,
        storage_type: str,
        project: str,
        scope: str,
        topic_key: str,
    ) -> str:
        record = StoredRecord(
            record_id=str(self._next_id),
            storage_type=storage_type,
            title=title,
            content=content,
            project=project,
            scope=scope,
            timestamp=f"2026-01-01 00:00:{self._next_id:02d}",
        )
        self._next_id += 1
        self._records.append(record)
        # Keep the historical test/debug view logical even though the
        # service now passes an immutable physical topic to real adapters.
        # The in-memory store is append-only and has no backend upsert, so
        # exposing both values preserves callers that asserted the old
        # logical ``saved_args[...]["topic_key"]`` contract.
        logical_topic_key = topic_key
        try:
            envelope = json.loads(content)
            logical_topic_key = str(envelope.get("topic_key") or topic_key)
        except (TypeError, ValueError):
            pass
        self.saved_args.append(
            {
                "title": title,
                "content": content,
                "storage_type": storage_type,
                "project": project,
                "scope": scope,
                "topic_key": logical_topic_key,
                "physical_topic_key": topic_key,
            }
        )
        return record.record_id

    def search_records(
        self,
        *,
        query: str,
        project: Optional[str] = None,
        storage_type: Optional[str] = None,
        limit: int = 50,
    ) -> List[StoredRecord]:
        tokens = [t.lower() for t in (query or "").split() if t.strip()]
        matches = []
        for record in self._records:
            if project and record.project != project:
                continue
            if storage_type and record.storage_type != storage_type:
                continue
            haystack = f"{record.title}\n{record.content}".lower()
            if all(token in haystack for token in tokens):
                matches.append(record)
        matches.reverse()
        return matches[: max(1, int(limit))]


def dumps_record(record: StoredRecord) -> str:
    """Debug helper: render a StoredRecord as one JSON line."""
    return json.dumps(record.__dict__, sort_keys=True)
