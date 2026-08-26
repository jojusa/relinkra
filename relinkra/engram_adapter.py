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

``InMemoryStore`` is a deterministic offline store for tests.
"""

from __future__ import annotations

import atexit
import json
import os
import re
import socket
import subprocess
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
                with urllib.request.urlopen(url, timeout=1.0) as response:
                    if response.status == 200:
                        return True
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
        # project_alias rewrites the PHYSICAL store filter only; the R1C
        # policy layer still filters parsed envelopes by the logical
        # project_id, so cross-project isolation is preserved.
        physical_project = self.project_alias or project
        http_records = self._http_search(query, physical_project, limit)
        if http_records is not None:
            self.read_mode = "http"
            return self._filtered(http_records, storage_type, limit)
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
                    return self._filtered(loopback_records, storage_type, limit)
        self.read_mode = "cli"
        args = ["search", query, "--limit", str(limit)]
        if physical_project:
            args += ["--project", physical_project]
        if storage_type:
            args += ["--type", storage_type]
        output = self._run(args)
        if "No memories found" in output:
            return []
        return parse_search_output(output)

    @staticmethod
    def _filtered(
        records: List[StoredRecord], storage_type: Optional[str], limit: int
    ) -> List[StoredRecord]:
        """Client-side type filter + page cut for full-content reads."""
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
        Any failure (server down, timeout, bad payload) returns None so
        the caller falls back — HTTP is strictly an optional read
        accelerator over the same physical backend.
        """
        base = (base_url if base_url is not None else self.http_url).rstrip("/")
        if not base:
            return None
        params = {"q": query, "limit": str(limit)}
        if project:
            params["project"] = project
        url = f"{base}/search?{urllib.parse.urlencode(params)}"
        try:
            with urllib.request.urlopen(url, timeout=self.http_timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
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
        self.saved_args.append(
            {
                "title": title,
                "content": content,
                "storage_type": storage_type,
                "project": project,
                "scope": scope,
                "topic_key": topic_key,
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
