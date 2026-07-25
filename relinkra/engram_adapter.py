"""Storage adapters for the Relinkra memory layer.

``MemoryStore`` is the raw persistence protocol: save/search of opaque
records (title, content, type, project, scope, topic_key). All R1C policy
lives in ``relinkra.memory``; adapters know nothing about envelopes.

``EngramCLIAdapter`` writes through the ``engram save`` CLI — never
direct SQLite — so OpenCode (``engram mcp --tools=agent`` + HTTP :7437)
and Codex (``engram mcp``) share the same physical database without a
second permanent memory DB. Reads try the local Engram HTTP API first
(``GET /search`` returns FULL untruncated content; the CLI truncates at
~300 chars) and fall back to the ``engram search`` CLI when HTTP is
unavailable. HTTP is an optional read path on the same physical
backend; the CLI remains the write path and the read fallback.

``InMemoryStore`` is a deterministic offline store for tests.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import List, Optional, Protocol

from .memory import MemoryStoreError, sanitize_error

ENGRAM_BIN = "engram"
DEFAULT_ENGRAM_URL = "http://127.0.0.1:7437"
ENGRAM_URL_ENV = "ENGRAM_URL"


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
# "..."; such blocks no longer parse as JSON envelopes and are skipped by
# the policy layer (counted as malformed). "No memories found for:" means
# zero results. subprocess is decoded as UTF-8 explicitly: the block
# header uses an em-dash and the Windows locale codec (cp1252) would
# otherwise mangle it and silently break parsing.

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
    return StoredRecord(
        record_id=raw["record_id"],
        storage_type=raw["storage_type"],
        title=raw["title"],
        content="\n".join(raw["content_lines"]),
        project=raw["project"],
        scope=raw["scope"],
        timestamp=raw["timestamp"],
    )


def parse_save_output(output: str) -> str:
    """Extract the observation id from ``engram save`` output."""
    match = _SAVE_RESULT_RE.search(output or "")
    return match.group(1) if match else ""


# ---------------------------------------------------------------------------
# Engram CLI adapter
# ---------------------------------------------------------------------------


class EngramCLIAdapter:
    """MemoryStore backed by Engram (HTTP read path + CLI write/fallback).

    Writes always go through ``engram save``. Reads try the local Engram
    HTTP API first (``GET /search?q=...&project=...`` returns FULL
    untruncated content, unlike the CLI text output which truncates at
    ~300 chars and breaks envelope parsing). If HTTP is unavailable the
    adapter falls back to ``engram search``.

    The HTTP base URL comes from ``http_url``, else the ``ENGRAM_URL``
    env var, else ``http://127.0.0.1:7437``. Pass ``http_url=""`` (or set
    ``ENGRAM_URL=""``) to disable HTTP and force the CLI path.

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
        if http_url is None:
            http_url = os.environ.get(ENGRAM_URL_ENV, DEFAULT_ENGRAM_URL)
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
            if storage_type:
                http_records = [
                    r for r in http_records if r.storage_type == storage_type
                ]
            return http_records[:limit]
        args = ["search", query, "--limit", str(limit)]
        if physical_project:
            args += ["--project", physical_project]
        if storage_type:
            args += ["--type", storage_type]
        output = self._run(args)
        if "No memories found" in output:
            return []
        return parse_search_output(output)

    # -- HTTP read path ---------------------------------------------------

    def _http_search(
        self, query: str, project: Optional[str], limit: int
    ) -> Optional[List[StoredRecord]]:
        """Search via the local Engram HTTP API; None signals fallback.

        Returns full untruncated records. Any failure (server down,
        timeout, bad payload) returns None so the caller falls back to
        the CLI — HTTP is strictly an optional read accelerator over the
        same physical backend.
        """
        if not self.http_url:
            return None
        params = {"q": query, "limit": str(limit)}
        if project:
            params["project"] = project
        url = f"{self.http_url}/search?{urllib.parse.urlencode(params)}"
        try:
            with urllib.request.urlopen(url, timeout=self.http_timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (OSError, ValueError, urllib.error.URLError):
            return None
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
