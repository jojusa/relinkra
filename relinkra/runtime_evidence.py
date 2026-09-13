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
    revision-bound    each record carries the workspace revision it was
                      observed on, so doctor can tell current-revision
                      evidence from historical evidence.
    non-secret        event names, timestamps, counters, protocol
                      versions and ids. No prompt text, no bodies, no
                      paths beyond the ids Relinkra already pins.
    compact           latest evidence per (host, event) plus a counter —
                      never a log. The file cannot grow with usage.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, Optional

from .safe_write import SafeWriteError, atomic_write_text, read_bounded_text

SCHEMA_VERSION = "relinkra.runtime-evidence/v1"

#: Where the store lives, relative to the workspace root. Covered by the
#: existing ``.relinkra/`` git-ignore rule, like the registry and the
#: operator-proof store.
CONFIG_DIR = ".relinkra"
STORE_FILENAME = "runtime-evidence.json"

#: Reading is bounded like every other persisted state read; the store is
#: far smaller than this in practice.
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
    ``unknown``  — the evidence carries no revision (or the current one
                   could not be read), so no current-revision claim is
                   made from it.
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


def evidence_path(workspace_root: str) -> str:
    return os.path.join(str(workspace_root), CONFIG_DIR, STORE_FILENAME)


def _empty_store() -> dict:
    return {"schema_version": SCHEMA_VERSION, "updated_at": "", "hosts": {}}


def normalize_store(data: Any) -> dict:
    """Coerce a loaded store to the bounded, whitelisted shape.

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
            if host_id != HOST_UNKNOWN and resolve_host_id(host_id) != host_id:
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
    if isinstance(bucket, dict):
        events_raw = bucket.get("events")
        if isinstance(events_raw, dict):
            for event, entry in events_raw.items():
                if event not in EVENTS:
                    continue
                events[event] = _normalize_entry(entry)
    return {"events": events}


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
            if isinstance(value, bool):
                clean[key[:MAX_DETAIL_CHARS]] = value
            elif isinstance(value, str):
                clean[key[:MAX_DETAIL_CHARS]] = value[:MAX_DETAIL_CHARS]
        if clean:
            normalized["detail"] = clean
    return normalized


def load_store(workspace_root: Optional[str]) -> Optional[dict]:
    """Read and normalize the store; None when there is none."""
    if not workspace_root:
        return None
    try:
        text = read_bounded_text(
            evidence_path(workspace_root), max_bytes=MAX_FILE_BYTES
        )
    except (OSError, ValueError, SafeWriteError):
        return None
    try:
        data = json.loads(text)
    except ValueError:
        # Corrupt state is treated as absent by the recorder (which
        # rebuilds it) and flagged as invalid by doctor.
        return None
    return normalize_store(data)


def _ignores_relinkra(text: str) -> bool:
    """True when an ignore file already covers the .relinkra/ directory."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped in (".relinkra/", ".relinkra"):
            return True
    return False


def _sanitize_detail(detail: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    if not detail:
        return {}
    clean: Dict[str, Any] = {}
    for key, value in detail.items():
        if not isinstance(key, str) or not key:
            continue
        if isinstance(value, bool):
            clean[key[:MAX_DETAIL_CHARS]] = value
        elif isinstance(value, str):
            clean[key[:MAX_DETAIL_CHARS]] = value[:MAX_DETAIL_CHARS]
    return clean


class EvidenceRecorder:
    """Best-effort writer of self-observed runtime evidence.

    Recording must never disturb serving: every failure — unreadable
    path, full disk, hostile state file — is swallowed after one
    best-effort write. The worst outcome is missing evidence, which is
    exactly what doctor rendered before this module existed.
    """

    def __init__(
        self,
        workspace_root: Optional[str],
        host_id: str,
        *,
        clock: Optional[Callable[[], str]] = None,
        revision: Optional[str] = None,
    ):
        self.workspace_root = str(workspace_root) if workspace_root else None
        self.host_id = resolve_host_id(host_id)
        self._clock = clock or _utc_now
        self._revision = short_revision(revision)
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
        path = evidence_path(self.workspace_root)
        try:
            text = read_bounded_text(path, max_bytes=MAX_FILE_BYTES)
            data = json.loads(text)
        except (OSError, ValueError, SafeWriteError):
            # Absent or corrupt: rebuild from a clean skeleton rather
            # than propagating whatever damaged state was found.
            data = _empty_store()
        data = normalize_store(data)

        bucket = data["hosts"].setdefault(self.bucket_id, {"events": {}})
        events = bucket.setdefault("events", {})
        entry = events.get(event) if isinstance(events.get(event), dict) else {}
        entry["observed_at"] = self._clock()
        entry["revision"] = self._revision
        try:
            entry["count"] = max(1, min(int(entry.get("count", 0)) + 1, MAX_COUNT))
        except (TypeError, ValueError):
            entry["count"] = 1
        clean_detail = _sanitize_detail(detail)
        if clean_detail:
            entry["detail"] = clean_detail
        else:
            entry.pop("detail", None)
        events[event] = entry

        for key, value in self._workspace_pin().items():
            bucket[key] = value
        data["updated_at"] = self._clock()

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
        """
        if self._exclude_checked:
            return
        self._exclude_checked = True
        root = self.workspace_root
        git_path = os.path.join(root, ".git")
        if not os.path.isdir(git_path):
            return  # worktree (.git file) or not a repo root: leave alone
        info_dir = os.path.join(git_path, "info")
        exclude_path = os.path.join(info_dir, "exclude")
        try:
            existing = ""
            if os.path.isfile(exclude_path):
                with open(exclude_path, "r", encoding="utf-8", errors="replace") as h:
                    existing = h.read()
                if _ignores_relinkra(existing):
                    return
            # A tracked .gitignore covering the directory makes the
            # exclude entry redundant.
            gitignore_path = os.path.join(root, ".gitignore")
            if os.path.isfile(gitignore_path):
                with open(gitignore_path, "r", encoding="utf-8", errors="replace") as h:
                    if _ignores_relinkra(h.read()):
                        return
            os.makedirs(info_dir, exist_ok=True)
            with open(exclude_path, "a", encoding="utf-8") as h:
                if existing and not existing.endswith("\n"):
                    h.write("\n")
                h.write(".relinkra/\n")
        except OSError:
            return


def build_evidence_recorder(
    workspace_root: Optional[str],
    host_id: Optional[str],
    *,
    revision: Optional[str] = None,
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
    )


# ---------------------------------------------------------------------------
# Doctor-facing summary
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HostRuntime:
    """One host bucket's self-observed evidence, classified for doctor."""

    host_id: str
    state: str  # "observed" | "stale" | "pending"
    revision_relation: str  # "current" | "older" | "unknown" | ""
    last_observed_at: str
    revision: str
    events: Mapping[str, dict] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "host_id": self.host_id,
            "state": self.state,
            "revision_relation": self.revision_relation,
            "last_observed_at": self.last_observed_at,
            "revision": self.revision,
            "events": dict(self.events),
            "source": SOURCE_SELF_OBSERVED,
        }


def _host_state(entries: Mapping[str, dict], current_revision: str) -> HostRuntime:
    """Classify one bucket. Current-revision evidence dominates; older
    evidence stays visible as historical, never promoted."""
    if not entries:
        return HostRuntime(
            host_id="", state="pending", revision_relation="",
            last_observed_at="", revision="", events={},
        )
    latest_at = ""
    latest_relation = "older"
    seen_current = False
    seen_unknown = False
    latest_revision = ""
    for entry in entries.values():
        observed_at = str(entry.get("observed_at") or "")
        if observed_at > latest_at:
            latest_at = observed_at
            latest_revision = short_revision(entry.get("revision"))
        relation = revision_relation(entry.get("revision"), current_revision)
        if relation == "current":
            seen_current = True
        elif relation == "unknown":
            seen_unknown = True
    if seen_current:
        latest_relation = "current"
    elif seen_unknown:
        latest_relation = "unknown"
    return HostRuntime(
        host_id="",
        state="observed" if seen_current else "stale",
        revision_relation=latest_relation,
        last_observed_at=latest_at,
        revision=latest_revision,
        events=dict(entries),
    )


def summarize_runtime_evidence(
    workspace_root: Optional[str], current_revision: str = ""
) -> dict:
    """Everything doctor needs about self-observed evidence, read-only.

    The result is plain data (dicts of primitives) so it can ride inside
    the routing assessment payload unchanged.
    """
    loaded = load_store(workspace_root)
    if loaded is None:
        # Absent is the quiet case; a file that exists but cannot be
        # parsed is an anomaly doctor should name.
        return {
            "present": False,
            "invalid": _store_invalid(workspace_root),
            "hosts": {},
        }
    hosts: Dict[str, dict] = {}
    for host_id, bucket in loaded.get("hosts", {}).items():
        entries = bucket.get("events") or {}
        runtime = _host_state(entries, current_revision)
        summary = runtime.to_dict()
        summary["host_id"] = host_id
        for key in ("project_id", "workspace_id"):
            value = bucket.get(key)
            if isinstance(value, str) and value:
                summary[key] = value
        hosts[host_id] = summary
    return {
        "present": bool(hosts),
        "invalid": _store_invalid(workspace_root),
        "current_revision": short_revision(current_revision),
        "hosts": hosts,
    }


def _store_invalid(workspace_root: Optional[str]) -> bool:
    """True when a store exists but cannot be parsed (anomalous state)."""
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


def _event_on_current_revision(entries: Mapping[str, dict], current_revision: str) -> bool:
    return any(
        revision_relation(entry.get("revision"), current_revision) == "current"
        for entry in entries.values()
        if isinstance(entry, dict)
    )


def _event_any_revision(entries: Mapping[str, dict]) -> bool:
    return bool(entries)


def runtime_stage_claims(summary: dict, current_revision: str = "") -> dict:
    """Map self-observed evidence onto the trust ladder's host-side rungs.

    ``current_revision`` binds the "current" classification; when empty,
    the revision recorded in the summary itself is used, so a summary
    produced by :func:`summarize_runtime_evidence` is self-contained.
    The result is ``{claim: (achieved, evidence)}`` where ``achieved`` is
    True only for what was directly observed on the current revision. The
    one deliberate exception is the server-start claim: a launch is a
    fact about the host's history, so historical evidence still proves
    it — with the revision relation named in the evidence string.

    Claims from the ``host_unknown`` bucket are included here: the ladder
    speaks for the workspace, and "some process launched Relinkra and
    served a route" is true even when the launcher never identified
    itself. Per-host attribution (the agents table) never reads unknown
    evidence into a named host.
    """
    if not current_revision:
        current_revision = str((summary or {}).get("current_revision") or "")
    hosts = (summary or {}).get("hosts") or {}
    claims: Dict[str, Any] = {}

    def _buckets() -> "list[tuple[str, Mapping[str, dict]]]":
        return [
            (host_id, (bucket or {}).get("events") or {})
            for host_id, bucket in sorted(hosts.items())
        ]

    def _claim(key: str, achieved: bool, evidence: str) -> None:
        if achieved:
            claims[key] = (True, evidence)

    def _label(host_id: str) -> str:
        return host_id if host_id != HOST_UNKNOWN else "host identity unknown"

    started = [
        (_label(host_id), bucket.get(EVENT_MCP_SERVER_STARTED) or {})
        for host_id, bucket in _buckets()
    ]
    started = [(label, entry) for label, entry in started if entry]
    if started:
        label, entry = started[0]
        relation = revision_relation(entry.get("revision"), current_revision)
        relation_note = (
            f"on revision {entry.get('revision') or 'unknown'}"
            if relation != "current"
            else "on the current revision"
        )
        _claim(
            "server_started",
            True,
            f"self-observed Relinkra server start ({label}, {relation_note}, "
            f"{entry.get('observed_at') or 'time unknown'})",
        )

    initialize = [
        (_label(host_id), bucket.get(EVENT_INITIALIZE_OBSERVED) or {})
        for host_id, bucket in _buckets()
    ]
    initialize = [(label, entry) for label, entry in initialize if entry]
    if initialize:
        label, entry = initialize[0]
        detail = entry.get("detail") or {}
        if _event_on_current_revision({EVENT_INITIALIZE_OBSERVED: entry}, current_revision):
            _claim(
                "handshake",
                True,
                f"self-observed initialize handshake ({label}, revision "
                f"{entry.get('revision') or 'unknown'}, {entry.get('observed_at') or 'time unknown'})",
            )
            if detail.get("protocol_agreed") is True:
                _claim(
                    "protocol_agreed",
                    True,
                    "self-observed handshake agreed protocol version "
                    f"{detail.get('protocol_negotiated') or 'unknown'} ({label})",
                )

    tools_list = [
        (_label(host_id), bucket.get(EVENT_TOOLS_LIST_OBSERVED) or {})
        for host_id, bucket in _buckets()
    ]
    tools_list = [(label, entry) for label, entry in tools_list if entry]
    if tools_list:
        label, entry = tools_list[0]
        if _event_on_current_revision({EVENT_TOOLS_LIST_OBSERVED: entry}, current_revision):
            _claim(
                "tools_visible",
                True,
                f"self-observed tools/list served to a connected host ({label}, "
                f"revision {entry.get('revision') or 'unknown'})",
            )

    invoked = [
        (_label(host_id), bucket.get(EVENT_TOOL_INVOKED) or {})
        for host_id, bucket in _buckets()
    ]
    invoked = [(label, entry) for label, entry in invoked if entry]
    if invoked:
        label, entry = invoked[0]
        if _event_on_current_revision({EVENT_TOOL_INVOKED: entry}, current_revision):
            tool = (entry.get("detail") or {}).get("tool") or "a tool"
            _claim(
                "tool_invoked",
                True,
                f"self-observed successful tool call ({tool}, {label}, "
                f"revision {entry.get('revision') or 'unknown'})",
            )

    for event, key in (
        (EVENT_PROJECT_RESOLVE_CALLED, "project_resolve"),
        (EVENT_CONTEXT_GET_CALLED, "context_get"),
        (EVENT_HANDOFF_CREATE_CALLED, "handoff_create"),
        (EVENT_HANDOFF_GET_CALLED, "handoff_get"),
    ):
        seen = [
            (_label(host_id), bucket.get(event) or {})
            for host_id, bucket in _buckets()
        ]
        seen = [(label, entry) for label, entry in seen if entry]
        if seen:
            label, entry = seen[0]
            if _event_on_current_revision({event: entry}, current_revision):
                _claim(
                    key,
                    True,
                    f"self-observed {event.replace('_', ' ')} ({label}, "
                    f"revision {entry.get('revision') or 'unknown'})",
                )

    # A handoff round trip needs BOTH halves observed on the current
    # revision. One create alone is a write nobody read back.
    create = claims.get("handoff_create")
    fetch = claims.get("handoff_get")
    if create and create[0] and fetch and fetch[0]:
        claims["handoff_round_trip"] = (
            True,
            f"self-observed handoff write and read-back; {create[1]}; {fetch[1]}",
        )

    return claims


def handoff_round_trip_observed(summary: dict, current_revision: str = "") -> bool:
    """True when both halves of a handoff round trip were self-observed
    on the current revision. One create alone never proves the trip."""
    claims = runtime_stage_claims(summary, current_revision)
    trip = claims.get("handoff_round_trip")
    return bool(trip and trip[0])
