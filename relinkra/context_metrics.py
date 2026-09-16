"""Bounded, privacy-safe observations of final ContextPackets (VIS-3).

The store is intentionally separate from :mod:`metrics_model`, which describes
future ecosystem telemetry. These observations contain only facts Relinkra
can measure at the final ContextPacket delivery boundary.
"""

from __future__ import annotations

import copy
import json
import math
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Mapping, Optional, Tuple

from .registry import interprocess_lock
from .runtime_evidence import HOST_UNKNOWN, resolve_host_id, short_revision
from .safe_write import atomic_write_text, read_bounded_text

SCHEMA_VERSION = 1
MAX_OBSERVATIONS = 100
DEFAULT_HISTORY_LIMIT = 20
MAX_HISTORY_LIMIT = 100
MAX_STORE_BYTES = 256 * 1024
LOCK_TIMEOUT_SECONDS = 0.5
_BUCKET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_SECTION_NAMES = {
    "memories", "pending", "handoffs", "code_references", "code_facts",
    "git_facts", "warnings", "contradictions", "snippets",
}
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_VALUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$")
_REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{3,63}$")
_SUFFICIENCY_VALUES = {
    "sufficient", "partial", "insufficient", "source_verification_required",
    "unknown",
}
_SALIENCE_TIERS = ("must_keep", "high_salience", "optional")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def host_bucket(host_id: Optional[str] = None) -> str:
    """Return only a registered coarse host bucket, never arbitrary input."""
    raw = host_id if host_id is not None else os.environ.get("RELINKRA_HOST_ID")
    resolved = resolve_host_id(raw)
    if resolved and _BUCKET_RE.fullmatch(resolved):
        return resolved
    return HOST_UNKNOWN


def metrics_context_dir(workspace_root: str) -> Path:
    # safe_write's atomic primitive intentionally accepts only absolute host
    # targets; workspace configuration normally is absolute, but normalizing
    # here keeps this best-effort side channel safe for direct callers too.
    return Path(str(workspace_root)).expanduser().absolute() / ".relinkra" / "metrics" / "context"


def metrics_path(workspace_root: str, bucket: Optional[str] = None) -> Path:
    return metrics_context_dir(workspace_root) / f"{host_bucket(bucket)}.json"


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _tri(value: Any) -> Optional[bool]:
    return value if isinstance(value, bool) else None


def _safe_string_list(value: Any, allowed: Optional[set] = None) -> list:
    if not isinstance(value, list):
        return []
    result = []
    for item in value:
        if not isinstance(item, str):
            continue
        item = item.strip()
        if item and (allowed is None or item in allowed):
            result.append(item)
    return sorted(set(result))


def _number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if value < 0:
        return None
    return value


def _safe_id(value: Any) -> Optional[str]:
    if isinstance(value, str) and _ID_RE.fullmatch(value.strip()):
        return value.strip()
    return None


def _safe_revision(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    normalized = short_revision(value)
    return normalized if _REVISION_RE.fullmatch(normalized) else None


def _safe_enum(value: Any, allowed: set) -> Optional[str]:
    if isinstance(value, str) and value in allowed:
        return value
    return None


def _safe_count(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return min(value, 2_147_483_647)


def _sanitize_observation(value: Mapping[str, Any], bucket: str) -> dict:
    """Allow-list every persisted value; never trust a caller's nested data."""
    identity_raw = _mapping(value.get("identity"))
    accounting_raw = _mapping(value.get("accounting"))
    composition_raw = _mapping(value.get("composition"))
    quality_raw = _mapping(value.get("quality"))
    retrieval_raw = _mapping(value.get("retrieval"))
    identity = {
        "project_id": _safe_id(identity_raw.get("project_id")),
        "workspace_id": _safe_id(identity_raw.get("workspace_id")),
        "revision": _safe_revision(identity_raw.get("revision")),
    }
    accounting = {
        "final_cpt1": _number(accounting_raw.get("final_cpt1")),
        "useful_cpt1": _number(accounting_raw.get("useful_cpt1")),
        "metadata_cpt1": _number(accounting_raw.get("metadata_cpt1")),
        "estimation_version": _safe_value(accounting_raw.get("estimation_version")),
        "accounting_basis": _safe_value(accounting_raw.get("accounting_basis")),
    }
    composition = {}
    for key in (
        "memory_facts", "code_references", "code_facts", "handoffs", "pending",
        "git_facts", "warnings", "snippets",
    ):
        composition[key] = _safe_count(composition_raw.get(key))
    salience_raw = _mapping(composition_raw.get("salience"))
    composition["salience"] = {
        key: _safe_count(salience_raw.get(key))
        for key in _SALIENCE_TIERS
    }
    omitted_raw = quality_raw.get("omitted_sections")
    omitted = (
        _safe_string_list(omitted_raw, _SECTION_NAMES)
        if isinstance(omitted_raw, list) else None
    )
    sufficiency_raw = quality_raw.get("context_sufficiency")
    sufficiency = None
    if isinstance(sufficiency_raw, Mapping):
        sufficiency = {
            str(key): str(val)
            for key, val in sorted(sufficiency_raw.items(), key=lambda pair: str(pair[0]))
            if isinstance(key, str) and _SAFE_VALUE_RE.fullmatch(key)
            and isinstance(val, str) and val in _SUFFICIENCY_VALUES
        }
    scopes = [
        item for item in _safe_string_list(retrieval_raw.get("scope"))
        if _SAFE_VALUE_RE.fullmatch(item)
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "observed_at": _bounded_timestamp(value.get("observed_at")),
        "packet_id": _safe_id(value.get("packet_id")),
        "host_bucket": bucket,
        "identity": identity,
        "accounting": accounting,
        "composition": composition,
        "quality": {
            "packet_complete": _tri(quality_raw.get("packet_complete")),
            "budget_exhausted": _tri(quality_raw.get("budget_exhausted")),
            "omitted_sections": omitted,
            "omitted_sections_count": len(omitted) if omitted is not None else None,
            "omitted_high_salience": _safe_count(quality_raw.get("omitted_high_salience")),
            "context_sufficiency": sufficiency,
            "truncated": _tri(quality_raw.get("truncated")),
        },
        "retrieval": {
            "complete": _tri(retrieval_raw.get("complete")),
            "scope": sorted(set(scopes)),
        },
    }


def _safe_value(value: Any) -> Optional[str]:
    if isinstance(value, str) and _SAFE_VALUE_RE.fullmatch(value.strip()):
        return value.strip()
    return None


def _bounded_timestamp(value: Any) -> str:
    if isinstance(value, str) and value and len(value) <= 80 and "\x00" not in value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.isoformat()
        except (TypeError, ValueError, OverflowError):
            pass
    return _now()


def extract_context_observation(
    packet: Any,
    *,
    observed_at: Optional[str] = None,
    revision: Optional[str] = None,
    bucket: Optional[str] = None,
) -> dict:
    """Project a *final* packet without recomputing accounting or copying data."""
    raw = packet.to_dict() if hasattr(packet, "to_dict") else packet
    raw = _mapping(raw)
    status = _mapping(raw.get("packet_status"))
    diagnostics = _mapping(raw.get("diagnostics"))
    accounting = _mapping(status.get("token_accounting"))
    facts = _mapping(raw.get("project_facts"))
    workspace = _mapping(facts.get("workspace"))

    project_id = _safe_id(raw.get("project_id"))
    workspace_id = _safe_id(raw.get("workspace_id"))
    if not workspace_id:
        workspace_id = _safe_id(workspace.get("workspace_id"))
    raw_revision = revision
    if not isinstance(raw_revision, str) or not raw_revision.strip():
        raw_revision = workspace.get("current_revision")
    if not isinstance(raw_revision, str) or not raw_revision.strip():
        raw_revision = workspace.get("head_sha")
    revision_value = _safe_revision(raw_revision) or ""

    composition = {
        "memory_facts": len(raw.get("memories") or []) if isinstance(raw.get("memories"), list) else 0,
        "code_references": len(raw.get("code_references") or []) if isinstance(raw.get("code_references"), list) else 0,
        "code_facts": len(raw.get("code_facts") or []) if isinstance(raw.get("code_facts"), list) else 0,
        "handoffs": len(raw.get("handoffs") or []) if isinstance(raw.get("handoffs"), list) else 0,
        "pending": len(raw.get("pending") or []) if isinstance(raw.get("pending"), list) else 0,
        "git_facts": len(raw.get("git_facts") or []) if isinstance(raw.get("git_facts"), list) else 0,
        "warnings": len(raw.get("warnings") or []) if isinstance(raw.get("warnings"), list) else 0,
    }
    salience_raw = _mapping(status.get("salience"))
    composition["salience"] = {
        key: _safe_count(salience_raw.get(key))
        for key in _SALIENCE_TIERS
    }
    diag_counts = _mapping(diagnostics.get("counts"))
    composition["snippets"] = _safe_count(diag_counts.get("snippets")) or 0

    budget = _mapping(diagnostics.get("budget"))
    truncation_evidence = "budget" in diagnostics or "truncated_snippets" in diagnostics
    truncated = bool(budget.get("truncated_source_ids")) or bool(diagnostics.get("truncated_snippets"))
    for fact in raw.get("code_facts") or []:
        if isinstance(fact, Mapping) and isinstance(fact.get("data"), Mapping) and fact["data"].get("snippet_truncated") is True:
            truncated = True
            truncation_evidence = True
            break
    if not truncation_evidence:
        truncated = False if status.get("packet_complete") is True else None
    omitted_raw = status.get("omitted_sections")
    omitted_sections = (
        _safe_string_list(omitted_raw, _SECTION_NAMES)
        if isinstance(omitted_raw, list) else None
    )
    omitted_high = status.get("omitted_high_salience_count")
    if isinstance(omitted_high, bool) or not isinstance(omitted_high, int):
        omitted_high = None
    sufficiency = status.get("context_sufficiency")
    if isinstance(sufficiency, Mapping):
        sufficiency = {
            str(k): str(v)[:80]
            for k, v in sufficiency.items()
            if isinstance(k, str) and _SAFE_VALUE_RE.fullmatch(k)
            and isinstance(v, str) and v in _SUFFICIENCY_VALUES
        }
    else:
        sufficiency = None

    retrieval_value = diagnostics.get("retrieval_complete")
    retrieval_evidence = any(
        key in diagnostics
        for key in ("retrieval_scope", "retrieval_scopes", "retrieval_diagnostic", "retrieval_diagnostics")
    )
    retrieval_complete = (
        retrieval_value
        if isinstance(retrieval_value, bool) and retrieval_evidence
        else None
    )
    scopes = [
        item for item in _safe_string_list(diagnostics.get("retrieval_scopes"))
        if _SAFE_VALUE_RE.fullmatch(item)
    ]
    if isinstance(diagnostics.get("retrieval_scope"), str):
        scopes.extend(
            item for item in _safe_string_list([diagnostics.get("retrieval_scope")])
            if _SAFE_VALUE_RE.fullmatch(item)
        )

    observation = {
        "schema_version": SCHEMA_VERSION,
        "observed_at": _bounded_timestamp(observed_at or raw.get("created_at")),
        "packet_id": _safe_id(raw.get("packet_id")),
        "host_bucket": host_bucket(bucket),
        "identity": {
            "project_id": project_id,
            "workspace_id": workspace_id,
            "revision": revision_value or None,
        },
        "accounting": {
            "final_cpt1": _number(accounting.get("total_estimated_tokens")),
            "useful_cpt1": _number(accounting.get("useful_payload_tokens")),
            "metadata_cpt1": _number(accounting.get("metadata_tokens")),
            "estimation_version": _safe_value(accounting.get("estimation_version")),
            "accounting_basis": _safe_value(accounting.get("accounting_basis")),
        },
        "composition": composition,
        "quality": {
            "packet_complete": _tri(status.get("packet_complete")),
            "budget_exhausted": _tri(status.get("budget_exhausted")),
            "omitted_sections": omitted_sections,
            "omitted_sections_count": len(omitted_sections) if omitted_sections is not None else None,
            "omitted_high_salience": omitted_high,
            "context_sufficiency": sufficiency,
            "truncated": truncated,
        },
        "retrieval": {
            "complete": retrieval_complete,
            "scope": sorted(set(scopes)),
        },
    }
    return _sanitize_observation(observation, host_bucket(bucket))


def _empty(bucket: str) -> dict:
    return {"schema_version": SCHEMA_VERSION, "host_bucket": bucket, "observations": []}


def _load_file(path: Path, bucket: str) -> Tuple[str, dict]:
    if not path.exists():
        return "absent", _empty(bucket)
    try:
        text = read_bounded_text(path, max_bytes=MAX_STORE_BYTES)
    except OSError:
        return ("absent" if not path.exists() else "unreadable"), _empty(bucket)
    except Exception:
        return "invalid", _empty(bucket)
    try:
        data = json.loads(text)
    except (ValueError, TypeError, UnicodeError):
        return "invalid", _empty(bucket)
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION or data.get("host_bucket") not in (None, bucket):
        return "invalid", _empty(bucket)
    records = data.get("observations")
    if not isinstance(records, list):
        return "invalid", _empty(bucket)
    clean = []
    degraded = False
    for record in records:
        if not isinstance(record, Mapping):
            degraded = True
            continue
        try:
            clean.append(_sanitize_observation(record, bucket))
        except Exception:
            degraded = True
            continue
    clean = clean[-MAX_OBSERVATIONS:]
    result = _empty(bucket)
    result["observations"] = clean
    return ("degraded" if degraded else "ok"), result


def _normalize_observation(value: Mapping[str, Any], bucket: str) -> dict:
    """Keep append's public seam privacy-safe even with caller-supplied data."""
    return _sanitize_observation(value, bucket)


def append_observation(
    workspace_root: Optional[str], observation: Mapping[str, Any], *, bucket: Optional[str] = None
) -> bool:
    """Append one observation using a bounded per-bucket atomic transaction."""
    if not workspace_root or not isinstance(observation, Mapping):
        return False
    selected_bucket = host_bucket(bucket)
    path = metrics_path(str(workspace_root), selected_bucket)
    try:
        with interprocess_lock(str(path), timeout=LOCK_TIMEOUT_SECONDS) as acquired:
            if not acquired:
                return False
            state, store = _load_file(path, selected_bucket)
            if state not in ("absent", "ok", "degraded"):
                return False
            records = list(store["observations"])
            records.append(_normalize_observation(observation, selected_bucket))
            records = records[-MAX_OBSERVATIONS:]
            while records:
                candidate = {"schema_version": SCHEMA_VERSION, "host_bucket": selected_bucket, "observations": records}
                encoded = json.dumps(candidate, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
                if len(encoded.encode("utf-8")) <= MAX_STORE_BYTES:
                    break
                records.pop(0)
            if not records:
                return False
            candidate = {"schema_version": SCHEMA_VERSION, "host_bucket": selected_bucket, "observations": records}
            encoded = json.dumps(candidate, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
            path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(path, encoded)
            return True
    except Exception:
        return False


def record_context_observation(
    workspace_root: Optional[str], packet: Any, *, bucket: Optional[str] = None
) -> bool:
    try:
        observation = extract_context_observation(packet, bucket=bucket)
        accounting = observation.get("accounting") or {}
        # A legacy packet without settled CPT1 accounting is not a measured
        # observation.  Do not write a row of fabricated zero/unknown data.
        if not any(
            accounting.get(key) is not None
            for key in ("final_cpt1", "useful_cpt1", "metadata_cpt1")
        ):
            return False
        return append_observation(workspace_root, observation, bucket=bucket)
    except Exception:
        return False


def load_observations_with_status(workspace_root: Optional[str]) -> Tuple[List[dict], str]:
    if not workspace_root:
        return [], "unavailable"
    directory = metrics_context_dir(str(workspace_root))
    try:
        names = sorted(
            n for n in os.listdir(directory)
            if n.endswith(".json") and _BUCKET_RE.fullmatch(n[:-5]) and host_bucket(n[:-5]) == n[:-5]
        )[:64]
    except FileNotFoundError:
        return [], "absent"
    except OSError:
        return [], "unavailable"
    observations: List[dict] = []
    degraded = False
    for name in names:
        state, store = _load_file(directory / name, name[:-5])
        if state in ("ok", "degraded"):
            observations.extend(store["observations"])
        if state == "degraded":
            degraded = True
        elif state not in ("absent", "ok"):
            degraded = True
    # The array order is the append order protected by the per-bucket lock.
    # Do not re-sort by wall-clock timestamps: clock skew or a caller-supplied
    # fixture must not make an older append appear to be the latest delivery.
    return observations[-MAX_OBSERVATIONS:], ("degraded" if degraded else "ok")


def load_observations(workspace_root: Optional[str]) -> List[dict]:
    return load_observations_with_status(workspace_root)[0]


def classify_currentness(
    observation: Mapping[str, Any], *, project_id: Optional[str] = None,
    workspace_id: Optional[str] = None, revision: Optional[str] = None
) -> str:
    identity = _mapping(observation.get("identity"))
    if not identity.get("project_id") or not identity.get("workspace_id"):
        return "unknown"
    # A mismatch in EITHER settled identity is foreign on its own: an
    # observation from another project must never be excused by an
    # unresolved effective workspace (and vice versa).
    if project_id and identity.get("project_id") != project_id:
        return "foreign"
    if workspace_id and identity.get("workspace_id") != workspace_id:
        return "foreign"
    if not project_id or not workspace_id or not revision:
        return "unknown"
    observed_revision = _safe_revision(identity.get("revision")) or ""
    current_revision = _safe_revision(revision) or ""
    return "current" if observed_revision and current_revision and observed_revision == current_revision else ("stale" if observed_revision and current_revision else "unknown")


def _age_seconds(timestamp: Any) -> Optional[float]:
    if not isinstance(timestamp, str) or not timestamp:
        return None
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0.0, (datetime.now(timezone.utc) - parsed).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return None


def metrics_payload(
    workspace_root: Optional[str], *, project_id: Optional[str] = None,
    workspace_id: Optional[str] = None, revision: Optional[str] = None,
    history: bool = False, limit: Optional[int] = None
) -> dict:
    records, storage = load_observations_with_status(workspace_root)
    decorated = []
    for record in records:
        item = copy.deepcopy(record)
        item["currentness"] = classify_currentness(item, project_id=project_id, workspace_id=workspace_id, revision=revision)
        item["age_seconds"] = _age_seconds(item.get("observed_at"))
        decorated.append(item)
    if history:
        try:
            requested = DEFAULT_HISTORY_LIMIT if limit is None else int(limit)
        except (TypeError, ValueError):
            requested = DEFAULT_HISTORY_LIMIT
        requested = max(1, min(requested, MAX_HISTORY_LIMIT))
        rows = list(reversed(decorated[-requested:]))
        return {"schema_version": SCHEMA_VERSION, "history": rows, "count": len(rows), "no_data": not bool(rows), "storage": storage}
    if not decorated:
        return {"schema_version": SCHEMA_VERSION, "currentness": "unknown", "observation": None, "no_data": True, "storage": storage}
    current = [item for item in decorated if item.get("currentness") == "current"]
    selected = (current or decorated)[-1]
    return {"schema_version": SCHEMA_VERSION, "currentness": selected.get("currentness", "unknown"), "observation": selected, "no_data": False, "storage": storage}


extract_metrics = extract_context_observation
append = append_observation
load = load_observations
