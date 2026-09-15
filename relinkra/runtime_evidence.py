"""Runtime evidence — what the Relinkra MCP server observed about itself (R6D).

A fresh host session used to leave no trace: the MCP server kept no state,
so ``doctor`` could only report "no observed evidence" for activity
Relinkra itself had just served. This module persists the smallest honest
record of that activity so self-observed trust can survive the session.

Deliberate limits, in order of importance:

    local-only        the store lives in this workspace's ``.relinkra/``
                      directory, which git already ignores.
    self-observed     every record here was produced by the MCP server
                      while serving. It proves Relinkra ran and which
                      routes it served — nothing more. Operator-supplied
                      proofs stay in ``connect-verification/`` and remain
                      the stronger evidence class.
    host-scoped       records are attributed to the host that launched the
                      server when that host identifies itself through
                      ``RELINKRA_HOST_ID``; anything else lands in a
                      separate ``host_unknown`` bucket and is never
                      attributed to a named host.
    one file per host each host bucket is its own bounded file under
                      ``.relinkra/runtime-evidence/<host>.json``. A writer
                      never reads or rewrites another host's file, so two
                      hosts recording concurrently cannot lose each
                      other's evidence the way a single shared file's
                      read-modify-write cycle could (R6E).
    lock-guarded      two processes of the SAME host share one file and
                      one read-modify-write cycle, so every writer takes
                      a bounded per-host interprocess lock around it
                      (R6F). Concurrent same-host sessions therefore
                      preserve every distinct event and never decrease a
                      counter; the one honest cost of the bound is that
                      a writer locked out past its timeout skips its
                      write — conservative under-reporting, never trust
                      inflation, never blocked serving. Same-event
                      ordering is latest-timestamp-wins-by-lock-order,
                      not a global event log.
    revision-bound    each record carries the workspace revision it was
                      observed on, so doctor can tell current-revision
                      evidence from historical evidence. When the current
                      revision cannot be read at all, the relation is
                      ``unknown`` — never ``stale``, which would claim a
                      fact nobody established.
    non-secret        event names, timestamps, counters, protocol
                      versions and ids. No prompt text, no bodies, no
                      paths beyond the ids Relinkra already pins.
    compact           latest evidence per (host, event) plus a counter —
                      never a log. No file can grow with usage.

The pre-R6E single-file layout (``.relinkra/runtime-evidence.json``) is
still READ and merged into every summary, so evidence written by 0.1.3
and early R6D builds remains visible. That legacy file is never written
again; there is no migration step.
"""

from __future__ import annotations

import json
import hashlib
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from .safe_write import SafeWriteError, atomic_write_text, read_bounded_text
from .registry import interprocess_lock

SCHEMA_VERSION = "relinkra.runtime-evidence/v1"

#: Where the store lives, relative to the workspace root. Covered by the
#: existing ``.relinkra/`` git-ignore rule, like the registry and the
#: operator-proof store.
CONFIG_DIR = ".relinkra"

#: Directory holding one bounded evidence file per host.
EVIDENCE_DIRNAME = "runtime-evidence"

#: The pre-R6E single-file store. Read for compatibility; never written.
LEGACY_FILENAME = "runtime-evidence.json"

#: Reading is bounded like every other persisted state read; no file is
#: larger than this in practice.
MAX_FILE_BYTES = 256 * 1024
MAX_HOSTS = 32
MAX_DETAIL_CHARS = 128
MAX_COUNT = 1_000_000_000

#: Bucket key for activity whose launcher never identified itself. Not a
#: connector id (those never contain underscores), so it cannot collide.
HOST_UNKNOWN = "host_unknown"

#: Launch-time host identity channel. A connector configuration (or an
#: operator) may export this to the MCP server process; the value must be
#: a registered connector id or it is ignored rather than guessed with.
HOST_ID_ENV = "RELINKRA_HOST_ID"

#: Evidence source recorded on every entry. The store has exactly one
#: source by construction — records the MCP server wrote about itself.
SOURCE_SELF_OBSERVED = "self_observed"

EVENT_MCP_SERVER_STARTED = "mcp_server_started"
EVENT_INITIALIZE_OBSERVED = "initialize_observed"
EVENT_TOOLS_LIST_OBSERVED = "tools_list_observed"
EVENT_TOOL_INVOKED = "tool_invoked"
EVENT_PROJECT_RESOLVE_CALLED = "project_resolve_called"
EVENT_CONTEXT_GET_CALLED = "context_get_called"
EVENT_HANDOFF_CREATE_CALLED = "handoff_create_called"
EVENT_HANDOFF_GET_CALLED = "handoff_get_called"
EVENT_MEMORY_ACTIVITY = "memory_activity"
EVENT_CBM_ACTIVITY = "cbm_activity"

#: The closed set of events the recorder accepts. Evidence for anything
#: else is dropped rather than stored.
EVENTS: tuple = (
    EVENT_MCP_SERVER_STARTED,
    EVENT_INITIALIZE_OBSERVED,
    EVENT_TOOLS_LIST_OBSERVED,
    EVENT_TOOL_INVOKED,
    EVENT_PROJECT_RESOLVE_CALLED,
    EVENT_CONTEXT_GET_CALLED,
    EVENT_HANDOFF_CREATE_CALLED,
    EVENT_HANDOFF_GET_CALLED,
    EVENT_MEMORY_ACTIVITY,
    EVENT_CBM_ACTIVITY,
)

#: Revision shorthand length, matching the operator-proof store so the
#: two evidence classes can be compared like for like.
REVISION_LENGTH = 12

#: Bound on waiting for another same-host process's evidence critical
#: section (per-host lock around the read-modify-write, and the
#: ``info/exclude`` append). Evidence must never block MCP serving: a
#: writer that times out skips its write — conservative under-reporting
#: — instead of racing unlocked and resurrecting the lost-update race
#: the lock exists to close. OS-level locks are released automatically
#: when a holder dies, so an abandoned writer cannot wedge this.
EVIDENCE_LOCK_TIMEOUT_SECONDS = 5.0

# Handoff identifiers are correlation material, not evidence payload.  Keep
# only a bounded one-way digest so runtime state cannot disclose the id (or
# anything reachable through it) while still allowing a create/get pair to
# be matched.
HANDOFF_FINGERPRINT_LENGTH = 16
HANDOFF_FINGERPRINT_KEY = "handoff_id_fingerprint"
MAX_HANDOFF_FINGERPRINTS = 32


def handoff_id_fingerprint(handoff_id: Optional[str]) -> str:
    """Return a bounded, one-way correlation token for a handoff id."""
    if not isinstance(handoff_id, str) or not handoff_id.strip():
        return ""
    digest = hashlib.sha256(
        b"relinkra/runtime-evidence/handoff/v1\x00"
        + handoff_id.strip().encode("utf-8", "ignore")
    ).hexdigest()
    return digest[:HANDOFF_FINGERPRINT_LENGTH]


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def short_revision(revision: Optional[str]) -> str:
    """Normalize a revision to the bounded shorthand used in evidence."""
    if not isinstance(revision, str):
        return ""
    return revision.strip().lower()[:REVISION_LENGTH]


def revision_relation(evidence_revision: str, current_revision: str) -> str:
    """Classify one evidence revision against the workspace's current one.

    ``current``  — observed on the revision doctor is looking at; strong
                   enough to prove current-revision routing stages.
    ``older``    — real historical evidence, useful for "this host has
                   launched Relinkra before", never for current routing.
    ``unknown``  — neither side can be established: the evidence carries
                   no revision, or the current one could not be read. No
                   current-revision claim is made from it, and it is
                   never reported as ``stale`` — "stale" asserts the
                   evidence is historical, which is exactly the fact
                   nobody was able to establish (R6E).
    """
    evidence_revision = short_revision(evidence_revision)
    current_revision = short_revision(current_revision)
    if not evidence_revision:
        return "unknown"
    if not current_revision:
        return "unknown"
    if evidence_revision == current_revision:
        return "current"
    return "older"


def identity_relation(
    evidence: Mapping[str, Any],
    current_project_id: str = "",
    current_workspace_id: str = "",
) -> str:
    """Classify immutable project/workspace binding for one event.

    Missing pins are legacy/unbound, never inferred from the current cwd.
    Any mismatch is foreign (not merely stale). A current claim requires
    both ids and both exact matches.
    """
    project = str(evidence.get("project_id") or "").strip()
    workspace = str(evidence.get("workspace_id") or "").strip()
    current_project_id = str(current_project_id or "").strip()
    current_workspace_id = str(current_workspace_id or "").strip()
    if not project or not workspace:
        return "unbound"
    if not current_project_id or not current_workspace_id:
        return "unknown"
    if project != current_project_id or workspace != current_workspace_id:
        return "foreign"
    return "current"


def resolve_host_id(raw: Optional[str]) -> str:
    """Validate a launch-time host identity, or return '' (unknown).

    The value must name a registered connector. Anything else — empty,
    unknown, an agent's self-declared label — becomes unknown: guessing a
    host from a string nobody vouched for is exactly what this channel
    must not do.
    """
    if not raw:
        return ""
    candidate = str(raw).strip().lower()
    if not candidate:
        return ""
    try:
        from .connectors import CONNECTORS
    except ImportError:  # pragma: no cover - the module ships in-package
        return ""
    for spec in CONNECTORS:
        if spec.connector_id == candidate:
            return candidate
    return ""


def _validated_bucket_name(name: str) -> bool:
    """True when ``name`` may own an evidence bucket: a registered
    connector id, or the dedicated unknown bucket."""
    return name == HOST_UNKNOWN or resolve_host_id(name) == name


def evidence_path(workspace_root: str) -> str:
    """The pre-R6E single-file store. Read for compatibility only."""
    return os.path.join(str(workspace_root), CONFIG_DIR, LEGACY_FILENAME)


def host_evidence_dir(workspace_root: str) -> str:
    """The directory holding one evidence file per host."""
    return os.path.join(str(workspace_root), CONFIG_DIR, EVIDENCE_DIRNAME)


def host_evidence_path(workspace_root: str, host_id: str) -> str:
    """The evidence file ONE host owns. Writers never touch another's."""
    bucket = host_id if _validated_bucket_name(host_id) else HOST_UNKNOWN
    return os.path.join(host_evidence_dir(workspace_root), f"{bucket}.json")


def _empty_host_file(host_id: str) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "host_id": host_id,
        "updated_at": "",
        "events": {},
    }


def _empty_store() -> dict:
    return {"schema_version": SCHEMA_VERSION, "updated_at": "", "hosts": {}}


def normalize_store(data: Any) -> dict:
    """Coerce a loaded whole-store (legacy shape) to the bounded,
    whitelisted shape.

    Unknown hosts, unknown events, oversized details and non-conforming
    values are dropped rather than preserved: the store can only ever
    contain what this module writes. A structurally corrupt file yields
    an empty store — evidence that cannot be read is evidence that does
    not exist.
    """
    if not isinstance(data, dict):
        return _empty_store()
    hosts_raw = data.get("hosts")
    hosts: Dict[str, Any] = {}
    if isinstance(hosts_raw, dict):
        for host_id, bucket in hosts_raw.items():
            if not isinstance(host_id, str) or not host_id:
                continue
            if not _validated_bucket_name(host_id):
                continue
            if len(hosts) >= MAX_HOSTS:
                break
            hosts[host_id] = _normalize_bucket(bucket)
    normalized = _empty_store()
    normalized["hosts"] = hosts
    updated = data.get("updated_at")
    if isinstance(updated, str):
        normalized["updated_at"] = updated[:MAX_DETAIL_CHARS]
    return normalized


def _normalize_bucket(bucket: Any) -> dict:
    events: Dict[str, Any] = {}
    normalized: Dict[str, Any] = {"events": events}
    if isinstance(bucket, dict):
        events_raw = bucket.get("events")
        if isinstance(events_raw, dict):
            for event, entry in events_raw.items():
                if event not in EVENTS:
                    continue
                events[event] = _normalize_entry(entry)
        for key in ("project_id", "workspace_id"):
            value = bucket.get(key)
            if isinstance(value, str) and value:
                normalized[key] = value[:MAX_DETAIL_CHARS]
    return normalized


def _normalize_entry(entry: Any) -> dict:
    if not isinstance(entry, dict):
        return {}
    normalized: Dict[str, Any] = {}
    observed_at = entry.get("observed_at")
    if isinstance(observed_at, str):
        normalized["observed_at"] = observed_at[:MAX_DETAIL_CHARS]
    normalized["revision"] = short_revision(entry.get("revision"))
    try:
        count = int(entry.get("count", 1))
    except (TypeError, ValueError):
        count = 1
    normalized["count"] = max(1, min(count, MAX_COUNT))
    detail = entry.get("detail")
    if isinstance(detail, dict):
        clean: Dict[str, Any] = {}
        for key, value in detail.items():
            if not isinstance(key, str) or not key:
                continue
            if key in ("handoff_id", "id"):
                # A handoff id in a pre-R6I file is not trusted and must not
                # be carried forward in clear text.
                continue
            if key == HANDOFF_FINGERPRINT_KEY:
                if isinstance(value, str) and value:
                    clean[key] = [value[:HANDOFF_FINGERPRINT_LENGTH]]
                elif isinstance(value, list):
                    clean[key] = [
                        item[:HANDOFF_FINGERPRINT_LENGTH]
                        for item in value
                        if isinstance(item, str) and item
                    ][:MAX_HANDOFF_FINGERPRINTS]
                continue
            if isinstance(value, bool):
                clean[key[:MAX_DETAIL_CHARS]] = value
            elif isinstance(value, str):
                clean[key[:MAX_DETAIL_CHARS]] = value[:MAX_DETAIL_CHARS]
        if clean:
            normalized["detail"] = clean
    # Identity is attached to every new entry.  Missing values are retained
    # as absent so legacy evidence remains readable but is never eligible for
    # identity-bound claims.
    for key in ("project_id", "workspace_id"):
        value = entry.get(key)
        if isinstance(value, str) and value:
            normalized[key] = value[:MAX_DETAIL_CHARS]
    host_id = entry.get("host_id")
    if isinstance(host_id, str) and host_id:
        normalized["host_id"] = host_id[:MAX_DETAIL_CHARS]
    return normalized


# Per-host file status codes, for callers that must distinguish "no
# evidence" from "evidence exists but cannot be used".
HOST_FILE_ABSENT = "absent"
HOST_FILE_OK = "ok"
HOST_FILE_INVALID = "invalid"


def read_host_file(
    workspace_root: Optional[str], host_id: str
) -> Tuple[str, dict]:
    """Read ONE host's evidence file.

    Returns ``(status, bucket)``. The bucket is the whitelisted
    ``{"events": ..., "project_id": ..., "workspace_id": ...}`` shape
    the aggregate summaries attach under the host's name; it is empty
    for every status other than ``ok``. The bucket key is the FILE's
    name — a file whose embedded ``host_id`` disagrees with its own
    filename is anomalous state, reported invalid rather than
    attributed anywhere.

    A file for an name that cannot own a bucket is not Relinkra state
    at all and is ignored entirely.
    """
    if not workspace_root or not _validated_bucket_name(host_id):
        return HOST_FILE_ABSENT, {}
    path = host_evidence_path(workspace_root, host_id)
    try:
        text = read_bounded_text(path, max_bytes=MAX_FILE_BYTES)
    except (OSError, ValueError, SafeWriteError):
        return HOST_FILE_ABSENT, {}
    try:
        data = json.loads(text)
    except ValueError:
        # Exists but unreadable: an anomaly the summaries surface.
        return HOST_FILE_INVALID, {}
    if not isinstance(data, dict):
        return HOST_FILE_INVALID, {}
    embedded = data.get("host_id")
    if isinstance(embedded, str) and embedded and embedded != host_id:
        # The file says it belongs to another host. Never re-attribute
        # it; the filename is the only identity anyone can rely on.
        return HOST_FILE_INVALID, {}
    bucket = _normalize_bucket(data)
    for key in ("project_id", "workspace_id"):
        value = data.get(key)
        if isinstance(value, str) and value:
            bucket[key] = value[:MAX_DETAIL_CHARS]
    updated = data.get("updated_at")
    if isinstance(updated, str):
        bucket["updated_at"] = updated[:MAX_DETAIL_CHARS]
    return HOST_FILE_OK, bucket


def host_file_invalid(workspace_root: Optional[str], host_id: str) -> bool:
    """True when this host's file exists but cannot be used."""
    status, _ = read_host_file(workspace_root, host_id)
    return status == HOST_FILE_INVALID


def _legacy_store_invalid(workspace_root: Optional[str]) -> bool:
    """True when the legacy single-file store exists but cannot parse."""
    if not workspace_root:
        return False
    try:
        text = read_bounded_text(
            evidence_path(workspace_root), max_bytes=MAX_FILE_BYTES
        )
    except (OSError, ValueError, SafeWriteError):
        return False
    try:
        json.loads(text)
    except ValueError:
        return True
    return False


def _known_host_files(workspace_root: Optional[str]) -> Tuple[str, ...]:
    """The host names present in the per-host directory, capped and
    sorted for determinism."""
    if not workspace_root:
        return ()
    directory = host_evidence_dir(workspace_root)
    try:
        entries = os.listdir(directory)
    except OSError:
        return ()
    names = []
    for entry in entries:
        if not entry.endswith(".json"):
            continue
        name = entry[: -len(".json")]
        if not isinstance(name, str) or not name:
            continue
        if not _validated_bucket_name(name):
            continue
        names.append(name)
    return tuple(sorted(names)[:MAX_HOSTS])


def _ignores_relinkra(text: str) -> bool:
    """True when an ignore file already covers the .relinkra/ directory."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped in (".relinkra/", ".relinkra"):
            return True
    return False


def _sanitize_detail(
    detail: Optional[Mapping[str, Any]], event: Optional[str] = None
) -> Dict[str, Any]:
    if not detail:
        return {}
    clean: Dict[str, Any] = {}
    for key, value in detail.items():
        if not isinstance(key, str) or not key:
            continue
        # Never persist the handoff id itself.  It is only accepted on the
        # two handoff route events and reduced to a non-reversible token.
        if event in (EVENT_HANDOFF_CREATE_CALLED, EVENT_HANDOFF_GET_CALLED):
            if key in ("handoff_id", "id", "handoff_ids"):
                raw_values = value if isinstance(value, (list, tuple)) else [value]
                fingerprints = [
                    handoff_id_fingerprint(item)
                    for item in raw_values
                ]
                fingerprints = [item for item in fingerprints if item]
                if fingerprints:
                    clean[HANDOFF_FINGERPRINT_KEY] = fingerprints[
                        :MAX_HANDOFF_FINGERPRINTS
                    ]
                continue
            if key == HANDOFF_FINGERPRINT_KEY and isinstance(value, str):
                clean[key] = [value[:HANDOFF_FINGERPRINT_LENGTH]]
                continue
            if key == HANDOFF_FINGERPRINT_KEY and isinstance(value, (list, tuple)):
                clean[key] = [
                    item[:HANDOFF_FINGERPRINT_LENGTH]
                    for item in value
                    if isinstance(item, str) and item
                ][:MAX_HANDOFF_FINGERPRINTS]
                continue
        if isinstance(value, bool):
            clean[key[:MAX_DETAIL_CHARS]] = value
        elif isinstance(value, str):
            clean[key[:MAX_DETAIL_CHARS]] = value[:MAX_DETAIL_CHARS]
    return clean


def load_store(workspace_root: Optional[str]) -> Optional[dict]:
    """Read and normalize the aggregate store; None when there is none.

    The aggregate merges the per-host files with the legacy single-file
    store, so evidence written before the per-host layout remains
    visible. A per-host file wins over a same-named legacy bucket: the
    newer, file-per-host evidence is the live record. Writers never
    produce this shape — they write one host file each — so reading is
    the only place the two layouts meet.
    """
    if not workspace_root:
        return None
    hosts: Dict[str, Any] = {}
    any_evidence = False
    latest_at = ""
    # Legacy single-file store: read-only compatibility.
    legacy_text = None
    try:
        legacy_text = read_bounded_text(
            evidence_path(workspace_root), max_bytes=MAX_FILE_BYTES
        )
        any_evidence = True
    except (OSError, ValueError, SafeWriteError):
        legacy_text = None
    if legacy_text is not None:
        try:
            data = json.loads(legacy_text)
        except ValueError:
            data = None
        if data is not None:
            normalized = normalize_store(data)
            for host_id, bucket in normalized["hosts"].items():
                hosts[host_id] = bucket
            updated = normalized.get("updated_at") or ""
            if updated > latest_at:
                latest_at = updated
    for name in _known_host_files(workspace_root):
        status, bucket = read_host_file(workspace_root, name)
        if status == HOST_FILE_OK:
            any_evidence = True
            hosts[name] = bucket
            bucket_updated = bucket.get("updated_at") or ""
            if bucket_updated > latest_at:
                latest_at = bucket_updated
    if not any_evidence and not hosts:
        return None
    store = _empty_store()
    store["hosts"] = hosts
    store["updated_at"] = latest_at
    return store


class EvidenceRecorder:
    """Best-effort writer of self-observed runtime evidence.

    Recording must never disturb serving: every failure — unreadable
    path, full disk, hostile state file — is swallowed after one
    best-effort write. The worst outcome is missing evidence, which is
    exactly what doctor rendered before this module existed.

    Each recorder owns exactly ONE file — its host's. It never reads or
    rewrites another host's bucket, so concurrent hosts (Codex and
    OpenCode recording at the same time, for instance) cannot lose each
    other's evidence: there is no shared read-modify-write cycle to
    interleave. Two processes of the SAME host DO share one file and one
    read-modify-write cycle, so the recorder takes a bounded per-host
    interprocess lock around it (R6F): the loser of a lock race skips
    its write — evidence stays honest but may under-report — rather
    than serving block or stale derived state clobber fresh events. The
    lock is local-only, lives beside the host file, is never rendered
    as evidence, and dies with its holding process.
    """

    def __init__(
        self,
        workspace_root: Optional[str],
        host_id: str,
        *,
        clock: Optional[Callable[[], str]] = None,
        revision: Optional[str] = None,
        lock_timeout: Optional[float] = EVIDENCE_LOCK_TIMEOUT_SECONDS,
        project_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ):
        self.workspace_root = str(workspace_root) if workspace_root else None
        self.host_id = resolve_host_id(host_id)
        self._clock = clock or _utc_now
        self._revision = short_revision(revision)
        self._lock_timeout = lock_timeout
        self._explicit_pin = {
            key: value[:MAX_DETAIL_CHARS]
            for key, value in (
                ("project_id", project_id),
                ("workspace_id", workspace_id),
            )
            if isinstance(value, str) and value.strip()
        }
        self._pin: Optional[Dict[str, str]] = None
        self._pin_loaded = False
        self._exclude_checked = False

    @property
    def bucket_id(self) -> str:
        return self.host_id or HOST_UNKNOWN

    def _workspace_pin(self) -> Dict[str, str]:
        """Best-effort project/workspace ids from the workspace pin.

        Read once per process. The pin is advisory context attached to
        each entry so doctor can notice evidence written under a
        different registration; a missing pin omits the ids rather than
        inventing them.
        """
        if self._pin_loaded:
            return self._pin or {}
        self._pin_loaded = True
        if self._explicit_pin:
            self._pin = dict(self._explicit_pin)
            return self._pin
        if not self.workspace_root:
            return {}
        try:
            from .product_cli import WorkspaceConfig

            config = WorkspaceConfig.load(self.workspace_root)
        except Exception:
            return {}
        if config is None:
            return {}
        self._pin = {}
        if isinstance(config.project_id, str) and config.project_id:
            self._pin["project_id"] = config.project_id[:MAX_DETAIL_CHARS]
        if isinstance(config.workspace_id, str) and config.workspace_id:
            self._pin["workspace_id"] = config.workspace_id[:MAX_DETAIL_CHARS]
        return self._pin

    def record(self, event: str, detail: Optional[Mapping[str, Any]] = None) -> bool:
        """Record one observation. Returns False when nothing was stored."""
        try:
            return self._record(event, detail)
        except Exception:
            # Serving continues without evidence. Never let a state-file
            # problem surface as an MCP error.
            return False

    def _record(self, event: str, detail) -> bool:
        if event not in EVENTS or not self.workspace_root:
            return False
        self._ensure_git_excluded()
        path = host_evidence_path(self.workspace_root, self.bucket_id)
        with interprocess_lock(path, timeout=self._lock_timeout) as acquired:
            if not acquired:
                # Another same-host writer held the lock past the bound.
                # Skipping loses this event (conservative under-reporting)
                # but never blocks serving, and never resurrects the
                # lost-update race the per-host lock exists to close.
                return False
            return self._record_locked(event, detail, path)

    def _record_locked(self, event: str, detail, path: str) -> bool:
        """The read-modify-write critical section.

        Every writer to THIS host's file takes the SAME per-host
        interprocess lock, so two same-host processes can no longer
        interleave read-modify-write and lose each other's events
        (R6F). Cross-host writers use different files and never meet.
        """
        try:
            text = read_bounded_text(path, max_bytes=MAX_FILE_BYTES)
            data = json.loads(text)
        except (OSError, ValueError, SafeWriteError):
            # Absent or corrupt: rebuild from a clean skeleton rather
            # than propagating whatever damaged state was found.
            data = _empty_host_file(self.bucket_id)
        data = _normalize_host_file(data, self.bucket_id)
        if data is None:
            data = _empty_host_file(self.bucket_id)

        events = data["events"]
        entry = events.get(event) if isinstance(events.get(event), dict) else {}
        entry["observed_at"] = self._clock()
        entry["revision"] = self._revision
        entry["host_id"] = self.bucket_id
        try:
            entry["count"] = max(1, min(int(entry.get("count", 0)) + 1, MAX_COUNT))
        except (TypeError, ValueError):
            entry["count"] = 1
        clean_detail = _sanitize_detail(detail, event)
        if event in (EVENT_HANDOFF_CREATE_CALLED, EVENT_HANDOFF_GET_CALLED):
            previous = (entry.get("detail") or {}).get(HANDOFF_FINGERPRINT_KEY, [])
            if isinstance(previous, str):
                previous = [previous]
            current = clean_detail.get(HANDOFF_FINGERPRINT_KEY, [])
            if isinstance(current, str):
                current = [current]
            merged = []
            for fingerprint in list(previous or []) + list(current or []):
                if (
                    isinstance(fingerprint, str)
                    and fingerprint
                    and fingerprint not in merged
                ):
                    merged.append(fingerprint[:HANDOFF_FINGERPRINT_LENGTH])
            if merged:
                clean_detail[HANDOFF_FINGERPRINT_KEY] = merged[
                    -MAX_HANDOFF_FINGERPRINTS:
                ]
        if clean_detail:
            entry["detail"] = clean_detail
        else:
            entry.pop("detail", None)
        events[event] = entry

        # Bind the observation itself, not merely its containing host file.
        # A file can outlive a workspace re-registration and different events
        # can have been written before/after that change.
        for key, value in self._workspace_pin().items():
            entry[key] = value
        for key in ("project_id", "workspace_id"):
            if key not in self._workspace_pin():
                entry.pop(key, None)

        data["updated_at"] = self._clock()
        for key, value in self._workspace_pin().items():
            data[key] = value

        payload = json.dumps(data, ensure_ascii=False, sort_keys=True, indent=1)
        atomic_write_text(path, payload)
        return True

    def _ensure_git_excluded(self) -> None:
        """Keep ``.relinkra/`` out of the host repository's git status.

        Runtime evidence is machine-local state, like the registry. The
        workspace may not git-ignore that directory, and an untracked
        state file showing up as ``?? .relinkra/`` in every ``git
        status`` would be exactly the dirt Relinkra must not create. The
        exclusion goes into ``.git/info/exclude`` — repository-local,
        never a tracked file, never pushed. Best effort only: any
        failure leaves git status as it was, and recording proceeds.

        Linked worktrees are handled through the COMMON directory: a
        ``.git`` FILE names the worktree's administrative directory,
        whose ``commondir`` file names the shared ``.git``. The exclude
        belongs there — it applies to every worktree, and writing
        anywhere else would leave the worktree's status dirty (R6E).

        The check-then-append cycle is guarded by the same interprocess
        lock discipline as the evidence store (R6F): two first-time
        startups could otherwise both observe the rule absent and both
        append it. The lock is taken on the exclude file's own
        ``<exclude>.lock`` sibling — inside the git directory, invisible
        to git status, shared by every worktree of the repository. A
        writer that cannot take it within the bound skips the append:
        the rule arrives on a later startup, and no duplicate is
        created.
        """
        if self._exclude_checked:
            return
        self._exclude_checked = True
        root = self.workspace_root
        common_dir = _git_common_dir(root)
        if not common_dir:
            return  # not a repository we can describe: leave alone
        info_dir = os.path.join(common_dir, "info")
        exclude_path = os.path.join(info_dir, "exclude")
        try:
            with interprocess_lock(
                exclude_path, timeout=self._lock_timeout
            ) as acquired:
                if not acquired:
                    # Another startup is mid-append. Skipping leaves the
                    # rule for a later startup; appending unlocked could
                    # duplicate it.
                    return
                existing = ""
                if os.path.isfile(exclude_path):
                    with open(
                        exclude_path, "r", encoding="utf-8", errors="replace"
                    ) as h:
                        existing = h.read()
                    if _ignores_relinkra(existing):
                        return
                # A tracked .gitignore covering the directory makes the
                # exclude entry redundant. The worktree's own .gitignore
                # is the one that governs what its status shows.
                gitignore_path = os.path.join(root, ".gitignore")
                if os.path.isfile(gitignore_path):
                    with open(
                        gitignore_path, "r", encoding="utf-8", errors="replace"
                    ) as h:
                        if _ignores_relinkra(h.read()):
                            return
                os.makedirs(info_dir, exist_ok=True)
                with open(exclude_path, "a", encoding="utf-8") as h:
                    if existing and not existing.endswith("\n"):
                        h.write("\n")
                    h.write(".relinkra/\n")
        except OSError:
            return


def _git_common_dir(root: Optional[str]) -> Optional[str]:
    """The repository-local directory holding ``info/exclude``.

    Three layouts, resolved without spawning git:

    ``.git/``      a normal repository — the ``.git`` directory itself.
    ``.git`` file  a linked worktree — the file names the worktree's
                   administrative directory (``gitdir:``), and that
                   directory's ``commondir`` file names the shared
                   ``.git``. Relative pointers are resolved against the
                   directory that contains them.
    none           not a repository root this module describes.

    ``None`` means "cannot tell"; callers treat that as leave-alone.
    """
    if not root:
        return None
    git_path = os.path.join(str(root), ".git")
    try:
        if os.path.isdir(git_path):
            return git_path
        if not os.path.isfile(git_path):
            return None
        with open(git_path, "r", encoding="utf-8", errors="replace") as h:
            first = h.readline().strip()
        if not first.lower().startswith("gitdir:"):
            return None
        gitdir = first[len("gitdir:"):].strip()
        if not gitdir:
            return None
        if not os.path.isabs(gitdir):
            gitdir = os.path.normpath(os.path.join(str(root), gitdir))
        if not os.path.isdir(gitdir):
            return None
        commondir_path = os.path.join(gitdir, "commondir")
        if not os.path.isfile(commondir_path):
            # A standalone .git file pointing at a full repository
            # directory (some submodule layouts): the gitdir itself is
            # the common dir when it holds an info/ directory.
            if os.path.isdir(os.path.join(gitdir, "info")):
                return gitdir
            return None
        with open(commondir_path, "r", encoding="utf-8", errors="replace") as h:
            common = h.readline().strip()
        if not common:
            return None
        if not os.path.isabs(common):
            common = os.path.normpath(os.path.join(gitdir, common))
        if not os.path.isdir(common):
            return None
        return common
    except OSError:
        return None


def _normalize_host_file(data: Any, host_id: str) -> Optional[dict]:
    """Coerce one host's file to the bounded, whitelisted shape.

    Returns None for anything structurally unusable — the caller
    rebuilds from a clean skeleton rather than propagating damaged
    state. The embedded ``host_id``, when present, must agree with the
    file's own name.
    """
    if not isinstance(data, dict):
        return None
    embedded = data.get("host_id")
    if isinstance(embedded, str) and embedded and embedded != host_id:
        return None
    normalized = _empty_host_file(host_id)
    events_raw = data.get("events")
    if isinstance(events_raw, dict):
        for event, entry in events_raw.items():
            if event not in EVENTS:
                continue
            normalized["events"][event] = _normalize_entry(entry)
    updated = data.get("updated_at")
    if isinstance(updated, str):
        normalized["updated_at"] = updated[:MAX_DETAIL_CHARS]
    for key in ("project_id", "workspace_id"):
        value = data.get(key)
        if isinstance(value, str) and value:
            normalized[key] = value[:MAX_DETAIL_CHARS]
    return normalized


def build_evidence_recorder(
    workspace_root: Optional[str],
    host_id: Optional[str],
    *,
    revision: Optional[str] = None,
    project_id: Optional[str] = None,
    workspace_id: Optional[str] = None,
) -> Optional[EvidenceRecorder]:
    """Recorder for an MCP server process, or None without a workspace.

    Without a workspace there is nowhere honest to scope the evidence,
    so nothing is recorded — a global launch outside any repository
    cannot be attributed to a project by any reader.
    """
    if not workspace_root:
        return None
    resolved_revision = revision
    if resolved_revision is None:
        try:
            from .identity import git_head_sha

            resolved_revision = git_head_sha(str(workspace_root))
        except Exception:
            resolved_revision = ""
    return EvidenceRecorder(
        workspace_root,
        host_id or "",
        revision=resolved_revision,
        project_id=project_id,
        workspace_id=workspace_id,
    )


# ---------------------------------------------------------------------------
# Doctor-facing summary
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HostRuntime:
    """One host bucket's self-observed evidence, classified for doctor."""

    host_id: str
    state: str  # "observed" | "stale" | "foreign" | "unbound" | "unknown" | "pending"
    revision_relation: str  # "current" | "older" | "unknown" | ""
    identity_relation: str  # "current" | "foreign" | "unbound" | "unknown" | ""
    last_observed_at: str
    revision: str
    events: Mapping[str, dict] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "host_id": self.host_id,
            "state": self.state,
            "revision_relation": self.revision_relation,
            "identity_relation": self.identity_relation,
            "last_observed_at": self.last_observed_at,
            "revision": self.revision,
            "events": dict(self.events),
            "source": SOURCE_SELF_OBSERVED,
        }


def _host_state(
    entries: Mapping[str, dict],
    current_revision: str,
    current_project_id: str = "",
    current_workspace_id: str = "",
) -> HostRuntime:
    """Classify one bucket.

    Current-revision evidence dominates and is ``observed``. When the
    current revision cannot be read (or an entry carries no revision),
    the relation is ``unknown`` — evidence exists, but nothing can be
    claimed about the current revision, and calling it ``stale`` would
    assert a historical fact nobody established. Real historical
    evidence (a readable revision that simply is not this one) stays
    ``stale``: visible as history, never promoted.
    """
    if not entries:
        return HostRuntime(
            host_id="", state="pending", revision_relation="",
            identity_relation="", last_observed_at="", revision="", events={},
        )
    latest_at = ""
    latest_revision = ""
    seen_current = False
    seen_unknown = False
    seen_foreign = False
    seen_unbound = False
    seen_identity_unknown = False
    seen_current_identity = False
    identity_required = bool(current_project_id or current_workspace_id)
    for entry in entries.values():
        observed_at = str(entry.get("observed_at") or "")
        if observed_at > latest_at:
            latest_at = observed_at
            latest_revision = short_revision(entry.get("revision"))
        relation = revision_relation(entry.get("revision"), current_revision)
        binding = identity_relation(entry, current_project_id, current_workspace_id)
        if binding == "unbound" and not identity_required:
            # Compatibility for pre-init diagnostics: without any current
            # project/workspace pin there is no identity to compare. This
            # mode never applies once a workspace pin is available.
            binding = "current"
        if binding == "current":
            seen_current_identity = True
        elif binding == "foreign":
            seen_foreign = True
        elif binding == "unbound":
            seen_unbound = True
        elif binding == "unknown":
            seen_identity_unknown = True
        if relation == "current" and binding == "current":
            seen_current = True
        elif relation == "unknown" and binding == "current":
            seen_unknown = True
    if seen_current:
        state, relation = "observed", "current"
    elif seen_foreign:
        state, relation = "foreign", "foreign"
    elif seen_unbound:
        state, relation = "unbound", "unbound"
    elif seen_identity_unknown:
        state, relation = "unknown", "unknown"
    elif seen_unknown:
        state, relation = "unknown", "unknown"
    else:
        state, relation = "stale", "older"
    return HostRuntime(
        host_id="",
        state=state,
        revision_relation=relation,
        identity_relation=(
            "current" if seen_current_identity else
            "foreign" if seen_foreign else
            "unbound" if seen_unbound else
            "unknown" if seen_identity_unknown else ""
        ),
        last_observed_at=latest_at,
        revision=latest_revision,
        events=dict(entries),
    )


def summarize_runtime_evidence(
    workspace_root: Optional[str],
    current_revision: str = "",
    *,
    current_project_id: str = "",
    current_workspace_id: str = "",
) -> dict:
    """Everything doctor needs about self-observed evidence, read-only.

    The result is plain data (dicts of primitives) so it can ride inside
    the routing assessment payload unchanged.
    """
    if workspace_root and not (current_project_id and current_workspace_id):
        try:
            from .product_cli import WorkspaceConfig

            config = WorkspaceConfig.load(workspace_root)
            if config is not None:
                current_project_id = str(config.project_id or "")
                current_workspace_id = str(config.workspace_id or "")
        except Exception:
            pass
    invalid = _store_invalid(workspace_root)
    loaded = load_store(workspace_root)
    if loaded is None:
        # Absent is the quiet case; a file that exists but cannot be
        # parsed is an anomaly doctor should name.
        return {
            "present": False,
            "invalid": invalid,
            "current_project_id": current_project_id,
            "current_workspace_id": current_workspace_id,
            "hosts": {},
        }
    hosts: Dict[str, dict] = {}
    for host_id, bucket in loaded.get("hosts", {}).items():
        entries = bucket.get("events") or {}
        runtime = _host_state(
            entries,
            current_revision,
            current_project_id,
            current_workspace_id,
        )
        summary = runtime.to_dict()
        summary["host_id"] = host_id
        for key in ("project_id", "workspace_id"):
            value = bucket.get(key)
            if isinstance(value, str) and value:
                summary[key] = value
        hosts[host_id] = summary
    return {
        "present": bool(hosts),
        "invalid": invalid,
        "current_revision": short_revision(current_revision),
        "current_project_id": current_project_id,
        "current_workspace_id": current_workspace_id,
        "hosts": hosts,
    }


def _store_invalid(workspace_root: Optional[str]) -> bool:
    """True when evidence state exists but cannot be used (anomalous).

    Covers the legacy single-file store and every per-host file: any
    existing evidence file that cannot be parsed, or that names a
    different host than its own file, makes the store anomalous.
    """
    if not workspace_root:
        return False
    if _legacy_store_invalid(workspace_root):
        return True
    for name in _known_host_files(workspace_root):
        if host_file_invalid(workspace_root, name):
            return True
    return False


def _event_on_current_revision(entries: Mapping[str, dict], current_revision: str) -> bool:
    return any(
        revision_relation(entry.get("revision"), current_revision) == "current"
        for entry in entries.values()
        if isinstance(entry, dict)
    )


def _event_any_revision(entries: Mapping[str, dict]) -> bool:
    return bool(entries)


def runtime_stage_claims(
    summary: dict,
    current_revision: str = "",
    *,
    current_project_id: str = "",
    current_workspace_id: str = "",
) -> dict:
    """Map only correctly-bound current runtime evidence onto trust stages."""
    summary = summary or {}
    if not current_revision:
        current_revision = str(summary.get("current_revision") or "")
    current_project_id = str(
        current_project_id or summary.get("current_project_id") or ""
    )
    current_workspace_id = str(
        current_workspace_id or summary.get("current_workspace_id") or ""
    )
    identity_required = bool(current_project_id or current_workspace_id)
    hosts = summary.get("hosts") or {}
    claims: Dict[str, Any] = {}

    def entries_for(event: str, *, current_only: bool = True):
        found = []
        for host_id, bucket in sorted(hosts.items()):
            entry = ((bucket or {}).get("events") or {}).get(event) or {}
            if not isinstance(entry, dict):
                continue
            binding = identity_relation(
                entry, current_project_id, current_workspace_id
            )
            if binding == "unbound" and not identity_required:
                binding = "current"
            relation = revision_relation(entry.get("revision"), current_revision)
            if current_only and (binding != "current" or relation != "current"):
                continue
            found.append((host_id, entry, binding, relation))
        return sorted(found, key=lambda item: (str(item[1].get("observed_at") or ""), item[0]))

    def label(host_id: str) -> str:
        return host_id if host_id != HOST_UNKNOWN else "host identity unknown"

    started = []
    for host_id, bucket in sorted(hosts.items()):
        entry = ((bucket or {}).get("events") or {}).get(EVENT_MCP_SERVER_STARTED) or {}
        if isinstance(entry, dict) and entry:
            binding = identity_relation(entry, current_project_id, current_workspace_id)
            if binding == "unbound" and not identity_required:
                binding = "current"
            relation = revision_relation(entry.get("revision"), current_revision)
            if binding == "current":
                started.append((host_id, entry, relation))
    if started:
        host_id, entry, relation = sorted(
            started, key=lambda item: (str(item[1].get("observed_at") or ""), item[0])
        )[-1]
        relation_note = "on the current revision" if relation == "current" else f"on revision {entry.get('revision') or 'unknown'}"
        claims["server_started"] = (
            True,
            f"self-observed Relinkra server start ({label(host_id)}, {relation_note}, "
            f"{entry.get('observed_at') or 'time unknown'})",
        )

    handshake = entries_for(EVENT_INITIALIZE_OBSERVED)
    if handshake:
        host_id, entry, _, _ = handshake[-1]
        claims["handshake"] = (
            True,
            f"self-observed initialize handshake ({label(host_id)}, revision {entry.get('revision') or 'unknown'})",
        )
        detail = entry.get("detail") or {}
        if detail.get("protocol_agreed") is True:
            claims["protocol_agreed"] = (
                True,
                f"self-observed handshake agreed protocol version {detail.get('protocol_negotiated') or 'unknown'} ({label(host_id)})",
            )

    for event, key, text in (
        (EVENT_TOOLS_LIST_OBSERVED, "tools_visible", "tools/list served to a connected host"),
        (EVENT_TOOL_INVOKED, "tool_invoked", "successful tool call"),
    ):
        seen = entries_for(event)
        if seen:
            host_id, entry, _, _ = seen[-1]
            suffix = ""
            if event == EVENT_TOOL_INVOKED:
                suffix = f" {(entry.get('detail') or {}).get('tool') or 'a tool'}"
            claims[key] = (
                True,
                f"self-observed {text}{suffix} ({label(host_id)}, revision {entry.get('revision') or 'unknown'})",
            )

    for event, key in (
        (EVENT_PROJECT_RESOLVE_CALLED, "project_resolve"),
        (EVENT_CONTEXT_GET_CALLED, "context_get"),
        (EVENT_HANDOFF_CREATE_CALLED, "handoff_create"),
        (EVENT_HANDOFF_GET_CALLED, "handoff_get"),
    ):
        seen = entries_for(event)
        if seen:
            host_id, entry, _, _ = seen[-1]
            claims[key] = (
                True,
                f"self-observed {event.replace('_', ' ')} ({label(host_id)}, revision {entry.get('revision') or 'unknown'})",
            )

    creates = entries_for(EVENT_HANDOFF_CREATE_CALLED)
    gets = entries_for(EVENT_HANDOFF_GET_CALLED)
    def fingerprints(entry: Mapping[str, Any]):
        raw = ((entry.get("detail") or {}).get(HANDOFF_FINGERPRINT_KEY) or [])
        if isinstance(raw, str):
            raw = [raw]
        return raw if isinstance(raw, (list, tuple)) else []

    created_ids = {
        fingerprint
        for _, entry, _, _ in creates
        for fingerprint in fingerprints(entry)
    }
    retrieved_ids = {
        fingerprint
        for _, entry, _, _ in gets
        for fingerprint in fingerprints(entry)
    }
    if created_ids & retrieved_ids:
        claims["handoff_round_trip"] = (
            True,
            "self-observed correlated handoff create/read for the same handoff under the current project/workspace and revision",
        )
    return claims


def handoff_round_trip_observed(summary: dict, current_revision: str = "") -> bool:
    """True when both handoff route halves (write and read) were
    self-observed on the current revision. One create alone never
    proves even that; no self-observed claim proves an actual
    correlated round trip — that is operator-proof territory."""
    claims = runtime_stage_claims(summary, current_revision)
    trip = claims.get("handoff_round_trip")
    return bool(trip and trip[0])
