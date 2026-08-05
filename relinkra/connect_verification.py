"""Persisted host-verification evidence for connector apply (R4C.1B).

A written configuration proves a file was edited. It says nothing about
the host actually launching Relinkra, completing a handshake, exposing
the tools or round-tripping a handoff — those happen in ANOTHER process,
which Relinkra cannot observe. What it can do is record an operator's
machine-readable proof that they happened, and then treat that record as
evidence with an expiry date and an invalidation rule.

Two rules shape this module.

EVIDENCE IS TYPED, STAGED AND PERISHABLE. A :class:`VerificationRecord`
names each stage separately, carries the launch-contract fingerprint it
was proven against, and dies of old age after ``ttl_seconds``. A record
that outlives the contract it proved is not "still true" — it is
``stale_fingerprint``, and the trust ladder falls back to UNVERIFIED.

PROOFS ARE SANITIZED BY REFUSAL. The proof payload is operator-supplied
JSON read from a file. Anything carrying an absolute path, a key that
names a secret, an unknown host or a malformed shape is rejected whole
rather than partially trusted, because a proof store that accepts
tainted input becomes a way to launder machine-local data into CLI
output.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Mapping, Optional, Sequence, Tuple

from .connector import iter_strings
from .connectors import resolve_connector
from .handoff import contains_absolute_path
from .identity import canonicalize_path, derive_workspace_id, normalize_os_family
from .registry import Registry, RegistryError, _WORKSPACE_ID_RE
from .safe_write import SafeWriteError, atomic_write_text, read_bounded_text
from .connector import UnknownConnectorError

#: Bumped when the shape of a stored verification record changes.
VERIFICATION_VERSION = "relinkra.connect-verification/v2"

# The verification file is operator-supplied local evidence, not an
# attestation channel.  Keep its grammar deliberately small and bounded so
# possession of the file cannot turn arbitrary JSON into route trust.
MAX_RECORD_BYTES = 64 * 1024
MAX_STRING_LENGTH = 512
MAX_TOOL_COUNT = 128
MAX_TOOL_NAME_LENGTH = 128
MAX_STAGE_COUNT = 10
MAX_JSON_DEPTH = 8
MAX_FUTURE_SKEW_SECONDS = 300
MAX_TTL_SECONDS = 7 * 86400

#: Default lifetime of a proof. A day is long enough to survive a work
#: session and short enough that last month's handshake cannot pass for
#: today's.
DEFAULT_TTL_SECONDS = 86400

#: Where records live, relative to the workspace root. Already covered
#: by the ``.relinkra/`` git-ignore rule.
STORE_DIRNAME = "connect-verification"

#: The staged claims a proof can make, in trust order. Config-side
#: stages are facts Relinkra establishes itself; host-side stages only
#: ever become true through an operator proof.
CONFIG_DETECTED = "config_detected"
CONFIG_APPLIED = "config_applied"
CONFIG_VALID = "config_valid"
PROTOCOL_COMPATIBLE = "protocol_compatible"
HOST_LAUNCHED = "host_launched"
HANDSHAKE_SUCCEEDED = "handshake_succeeded"
TOOLS_VISIBLE = "tools_visible"
TOOLS_CALLABLE = "tools_callable"
CONTEXT_ROUNDTRIP = "context_roundtrip"
HANDOFF_ROUNDTRIP = "handoff_roundtrip"

VERIFICATION_STAGES: Tuple[str, ...] = (
    CONFIG_DETECTED,
    CONFIG_APPLIED,
    CONFIG_VALID,
    PROTOCOL_COMPATIBLE,
    HOST_LAUNCHED,
    HANDSHAKE_SUCCEEDED,
    TOOLS_VISIBLE,
    TOOLS_CALLABLE,
    CONTEXT_ROUNDTRIP,
    HANDOFF_ROUNDTRIP,
)

#: Stages a host-side proof MUST speak to. A proof that omits them is
#: not evidence about them, and partial evidence rendered as complete
#: is how "verified" starts meaning nothing.
REQUIRED_PROOF_STAGES: Tuple[str, ...] = (
    HOST_LAUNCHED,
    HANDSHAKE_SUCCEEDED,
    TOOLS_VISIBLE,
    TOOLS_CALLABLE,
    HANDOFF_ROUNDTRIP,
)

#: Where the record came from. Today there is exactly one source: an
#: operator who ran the real host and produced a machine-readable proof.
SOURCE_OPERATOR_PROOF = "operator-proof"

#: assess_verification outcomes.
STATUS_ABSENT = "absent"
STATUS_STALE_FINGERPRINT = "stale_fingerprint"
STATUS_EXPIRED = "expired"
STATUS_INVALID = "invalid"
STATUS_VALID = "valid"
ASSESS_STATUSES = frozenset(
    {STATUS_ABSENT, STATUS_STALE_FINGERPRINT, STATUS_EXPIRED, STATUS_INVALID, STATUS_VALID}
)

#: Key fragments a proof payload may not contain. A proof is a statement
#: about stages, tools and round trips; anything shaped like a credential
#: does not belong in it, so the whole payload is refused.
_SECRET_KEY_PARTS = frozenset(
    {"token", "secret", "password", "passwd", "oauth", "apikey", "api_key"}
)
_KEY_SPLIT_RE = re.compile(r"[^a-z0-9]+")
_CREDENTIAL_VALUE_RE = re.compile(
    r"(?i)(?:^|[^a-z0-9])(?:"
    r"bearer\s+[a-z0-9._~+/\-]{6,}"
    r"|sk[-_](?:live|test)[-_][a-z0-9_-]{4,}"
    r"|sk-[a-z0-9]{20,}"
    r"|xox[baprs]-[a-z0-9-]{10,}"
    r"|gh[pousr]_[a-z0-9]{20,}"
    r"|github_pat_[a-z0-9_]{20,}"
    r"|glpat-[a-z0-9_-]{15,}"
    r"|akia[0-9a-z]{16}"
    r"|aiza[0-9a-z_-]{35}"
    r"|hf_[a-z0-9]{20,}"
    r")(?:$|[^a-z0-9])"
)
_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")

_STORAGE_KEYS = frozenset(
    {
        "schema_version", "host", "timestamp", "registration_fingerprint",
        "revision", "project_id", "stages", "tools_visible", "tools_invoked",
        "handoff_ok", "ttl_seconds", "source", "workspace_root",
        "workspace_id", "evidence_class", "independently_attested",
    }
)
_PORTABLE_KEYS = _STORAGE_KEYS - {"workspace_root"}


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProofError([f"duplicate JSON key: {key!r}"])
        result[key] = value
    return result


def _reject_nonfinite(value):
    raise ProofError([f"non-finite JSON number is not allowed: {value!r}"])


def _json_depth(value, depth=0):
    if depth > MAX_JSON_DEPTH:
        raise ProofError([f"verification evidence exceeds the {MAX_JSON_DEPTH}-level nesting limit"])
    if isinstance(value, Mapping):
        for key, item in value.items():
            _json_depth(key, depth + 1)
            _json_depth(item, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _json_depth(item, depth + 1)


def _bounded_text(value, field_name, *, allow_empty=True):
    if not isinstance(value, str):
        raise ProofError([f"{field_name} must be a string"])
    if not allow_empty and not value:
        raise ProofError([f"{field_name} must not be empty"])
    if len(value) > MAX_STRING_LENGTH:
        raise ProofError([f"{field_name} exceeds the {MAX_STRING_LENGTH}-character limit"])
    if _has_control_chars(value):
        raise ProofError([f"{field_name} contains control character(s)"])
    return value


def parse_proof_json(text: str):
    """Parse an operator proof with the same strict grammar as storage.

    CLI input is untrusted before :func:`build_proof_from_payload` sees it:
    duplicate keys, non-finite numbers and excessive nesting must fail at the
    boundary rather than being silently normalized by ``json.loads``.
    """
    if text.startswith("\ufeff"):
        text = text[1:]
    try:
        payload = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except ProofError:
        raise
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProofError([f"proof JSON is malformed: {exc}"]) from exc
    _json_depth(payload)
    return payload


class ProofError(ValueError):
    """Raised when an operator proof cannot be accepted.

    Carries every reason found, not just the first, so the operator can
    fix the payload in one pass instead of discovering problems one
    rejection at a time.
    """

    def __init__(self, reasons: Sequence[str]):
        self.reasons = tuple(reasons)
        super().__init__("; ".join(self.reasons))


@dataclass(frozen=True)
class VerificationRecord:
    """One persisted proof that a host-side stage was observed.

    ``workspace_root`` is machine-local: it is needed to detect a record
    being replayed against a different workspace, and it is exactly what
    :meth:`to_dict` must never emit. ``workspace_id`` is portable opaque
    identity; when non-null it must be backed by the current registry entry.
    The portable rendering carries stages, tool names and timestamps — facts
    a reader can act on — and nothing that locates the machine.
    """

    host: str
    timestamp: str
    registration_fingerprint: str
    stages: Mapping[str, bool] = field(default_factory=dict)
    tools_visible: Sequence[str] = field(default_factory=tuple)
    tools_invoked: Sequence[str] = field(default_factory=tuple)
    handoff_ok: bool = False
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    source: str = SOURCE_OPERATOR_PROOF
    workspace_root: str = ""
    workspace_id: Optional[str] = None
    project_id: str = ""
    revision: str = ""
    schema_version: str = VERIFICATION_VERSION

    def to_dict(self) -> dict:
        """Portable rendering: no paths, no secrets, no machine values."""
        return {
            "schema_version": self.schema_version,
            "host": self.host,
            "timestamp": self.timestamp,
            "registration_fingerprint": self.registration_fingerprint,
            "revision": self.revision,
            "project_id": self.project_id,
            "stages": {key: bool(value) for key, value in sorted(self.stages.items())},
            "tools_visible": list(self.tools_visible),
            "tools_invoked": list(self.tools_invoked),
            "handoff_ok": self.handoff_ok,
            "ttl_seconds": self.ttl_seconds,
            "source": self.source,
            "workspace_id": self.workspace_id,
            "evidence_class": "local_operational",
            "independently_attested": False,
        }

    def to_storage_dict(self) -> dict:
        """Machine-local rendering for the on-disk record only."""
        data = self.to_dict()
        data["workspace_root"] = self.workspace_root
        return data

    @staticmethod
    def from_storage_dict(data: Mapping[str, object]) -> "VerificationRecord":
        if not isinstance(data, Mapping):
            raise ProofError(["verification evidence must be a JSON object"])
        unknown = sorted(set(data) - _STORAGE_KEYS)
        missing = sorted(_STORAGE_KEYS - set(data))
        if unknown:
            raise ProofError(["unknown verification field(s): " + ", ".join(map(str, unknown))])
        if missing:
            raise ProofError(["missing verification field(s): " + ", ".join(missing)])
        if data.get("schema_version") != VERIFICATION_VERSION:
            raise ProofError([f"unsupported verification schema: {data.get('schema_version')!r}"])
        stages = data.get("stages")
        if not isinstance(stages, Mapping):
            raise ProofError(["verification stages must be an object"])
        if len(stages) > MAX_STAGE_COUNT:
            raise ProofError(["verification contains too many stages"])
        for key, value in stages.items():
            if not isinstance(key, str) or key not in VERIFICATION_STAGES:
                raise ProofError([f"unknown verification stage: {key!r}"])
            if not isinstance(value, bool):
                raise ProofError([f"verification stage {key!r} must be boolean"])
        visible = data.get("tools_visible")
        invoked = data.get("tools_invoked")
        if not isinstance(visible, list) or not isinstance(invoked, list):
            raise ProofError(["verification tool lists must be arrays"])
        if len(visible) > MAX_TOOL_COUNT or len(invoked) > MAX_TOOL_COUNT:
            raise ProofError(["verification tool list is too large"])
        for field_name, values in (("tools_visible", visible), ("tools_invoked", invoked)):
            for item in values:
                _bounded_text(item, f"{field_name} item", allow_empty=False)
                if contains_absolute_path(item):
                    raise ProofError([f"{field_name} contains a machine-local path"])
        if not isinstance(data.get("handoff_ok"), bool):
            raise ProofError(["handoff_ok must be boolean"])
        ttl = data.get("ttl_seconds")
        if isinstance(ttl, bool) or not isinstance(ttl, int) or not (1 <= ttl <= MAX_TTL_SECONDS):
            raise ProofError([f"ttl_seconds must be an integer from 1 to {MAX_TTL_SECONDS}"])
        for field_name in (
            "host", "timestamp", "registration_fingerprint", "revision",
            "project_id", "source", "workspace_root",
        ):
            _bounded_text(
                data.get(field_name),
                field_name,
                allow_empty=field_name in {"revision", "project_id"},
            )
            if field_name != "workspace_root" and contains_absolute_path(data[field_name]):
                raise ProofError([f"{field_name} contains a machine-local path"])
        workspace_id = data.get("workspace_id")
        if workspace_id is not None:
            if not isinstance(workspace_id, str) or not _WORKSPACE_ID_RE.fullmatch(workspace_id):
                raise ProofError([
                    "workspace_id must be null or match ^ws_[0-9a-f]{32}$"
                ])
        if data.get("source") != SOURCE_OPERATOR_PROOF:
            raise ProofError(["source must be 'operator-proof'"])
        if data.get("evidence_class") != "local_operational":
            raise ProofError(["evidence_class must be 'local_operational'"])
        if data.get("independently_attested") is not False:
            raise ProofError(["persisted verification cannot claim independent attestation"])
        if not _SHA_RE.fullmatch(data.get("registration_fingerprint", "")):
            raise ProofError(["registration_fingerprint must be a hexadecimal digest"])
        revision = data.get("revision", "")
        if revision and not _SHA_RE.fullmatch(revision):
            raise ProofError(["revision must be a hexadecimal Git revision"])
        return VerificationRecord(
            host=data["host"],
            timestamp=data["timestamp"],
            registration_fingerprint=data["registration_fingerprint"],
            stages=dict(stages),
            tools_visible=tuple(visible),
            tools_invoked=tuple(invoked),
            handoff_ok=data["handoff_ok"],
            ttl_seconds=ttl,
            source=data["source"],
            workspace_root=data["workspace_root"],
            workspace_id=workspace_id,
            project_id=data["project_id"],
            revision=revision,
            schema_version=data["schema_version"],
        )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _store_dir(root) -> Path:
    return Path(root) / ".relinkra" / STORE_DIRNAME


def _record_path(root, host: str) -> Path:
    return _store_dir(root) / f"{host}.json"


def record_verification(root, record: VerificationRecord) -> Path:
    """Persist the record as the single latest one for its host.

    One record per host, overwritten: verification evidence is a "latest
    known proof", not a log, and keeping history would invite a reader
    to treat an old proof as current.
    """
    # Re-validate even records constructed by an in-process caller.  The CLI
    # is not the only possible writer, and a dataclass instance can otherwise
    # bypass the JSON boundary's schema, timestamp and stage checks.
    validated = VerificationRecord.from_storage_dict(record.to_storage_dict())
    reasons = _record_validation_reasons(
        validated,
        root=root,
        host=validated.host,
        current_fingerprint=validated.registration_fingerprint,
    )
    if reasons:
        raise ProofError(reasons)
    path = _record_path(root, validated.host)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(validated.to_storage_dict(), indent=2, sort_keys=True) + "\n"
    atomic_write_text(path, payload)
    return path


def load_verification(root, host: str) -> Optional[VerificationRecord]:
    """Read the latest record for a host. ``None`` when absent/unusable.

    A corrupt record is treated as absent rather than trusted or fatal:
    the honest state for unreadable evidence is "no evidence".
    """
    path = _record_path(root, host)
    try:
        if not path.is_file():
            return None
        data = json.loads(
            read_bounded_text(path, max_bytes=MAX_RECORD_BYTES),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
        _json_depth(data)
        if not isinstance(data, Mapping):
            return None
        return VerificationRecord.from_storage_dict(data)
    except (OSError, ValueError, SafeWriteError, RecursionError, TypeError):
        return None


def _record_validation_reasons(
    record: VerificationRecord, *, root, host: str, current_fingerprint: str
) -> Tuple[str, ...]:
    """Validate stored evidence against the current local identity."""
    reasons = []
    try:
        expected_host = resolve_connector(host).connector_id
    except UnknownConnectorError:
        expected_host = host
    if record.host != expected_host:
        reasons.append("the recorded proof names a different host")
    if record.workspace_root != str(Path(root).resolve()):
        reasons.append("the recorded proof belongs to a different workspace")
    if record.workspace_id is not None:
        expected_workspace_id = _workspace_id_for(root)
        if expected_workspace_id is None:
            reasons.append(
                "the recorded proof carries a workspace_id that cannot be "
                "validated against the registry-backed current workspace"
            )
        elif record.workspace_id != expected_workspace_id:
            reasons.append(
                "the recorded proof belongs to a different workspace identity"
            )
    current_project = _project_id_for(root)
    if current_project and record.project_id != current_project:
        reasons.append("the recorded proof belongs to a different project")
    if current_fingerprint and record.registration_fingerprint != current_fingerprint:
        reasons.append(
            "the recorded proof was made against a different launch contract; "
            "the registration changed, so the proof no longer applies"
        )
    current_revision = _revision_for(root)
    if current_revision and record.revision != current_revision:
        reasons.append("the recorded proof is for a different Git revision")

    try:
        proven_at = datetime.fromisoformat(record.timestamp)
        if proven_at.tzinfo is None:
            reasons.append("the recorded proof timestamp has no timezone")
        else:
            age = (_utc_now() - proven_at).total_seconds()
            if age < -MAX_FUTURE_SKEW_SECONDS:
                reasons.append("the recorded proof timestamp is materially in the future")
            elif age > record.ttl_seconds:
                reasons.append(
                    f"the recorded proof is older than its {record.ttl_seconds}s lifetime"
                )
    except (TypeError, ValueError):
        reasons.append("the recorded proof carries an unreadable timestamp")

    stages = record.stages
    prerequisites = {
        HANDSHAKE_SUCCEEDED: HOST_LAUNCHED,
        TOOLS_VISIBLE: HANDSHAKE_SUCCEEDED,
        TOOLS_CALLABLE: TOOLS_VISIBLE,
        CONTEXT_ROUNDTRIP: TOOLS_CALLABLE,
        HANDOFF_ROUNDTRIP: TOOLS_CALLABLE,
    }
    for stage, prerequisite in prerequisites.items():
        if stages.get(stage) is True and stages.get(prerequisite) is not True:
            reasons.append(f"stage {stage} skips prerequisite {prerequisite}")
    if stages.get(TOOLS_VISIBLE) is True and not record.tools_visible:
        reasons.append("tools_visible is true but the visible tool list is empty")
    if stages.get(TOOLS_CALLABLE) is True:
        if not record.tools_invoked:
            reasons.append("tools_callable is true but no tool invocation is recorded")
        if not set(record.tools_invoked).issubset(set(record.tools_visible)):
            reasons.append("invoked tools must be a subset of visible tools")
    if stages.get(HANDOFF_ROUNDTRIP) is True and not record.handoff_ok:
        reasons.append("handoff_roundtrip is true but handoff_ok is false")
    return tuple(dict.fromkeys(reasons))


def assess_verification(
    root, host: str, current_fingerprint: str
) -> Tuple[str, Optional[VerificationRecord], Tuple[str, ...]]:
    """Judge the persisted evidence against the CURRENT launch contract.

    Four answers, never a bare boolean: there is no evidence, the
    evidence was proven against a different contract, the evidence is
    too old, or the evidence currently holds. Every non-valid answer
    names why, so a renderer never has to invent the reason.
    """
    record = load_verification(root, host)
    if record is None:
        return (
            STATUS_ABSENT,
            None,
            ("no local host evidence has been recorded for this host",),
        )
    reasons = _record_validation_reasons(
        record, root=root, host=host, current_fingerprint=current_fingerprint
    )
    if reasons:
        if any("launch contract" in reason for reason in reasons):
            status = STATUS_STALE_FINGERPRINT
        elif any("lifetime" in reason for reason in reasons):
            status = STATUS_EXPIRED
        else:
            status = STATUS_INVALID
        return status, record, reasons
    return (STATUS_VALID, record, ())


def _secret_shaped_key(key: object) -> bool:
    """Whether a payload key names something credential-shaped."""
    lowered = str(key).lower()
    if lowered in ("key", "keys"):
        return True
    parts = set(part for part in _KEY_SPLIT_RE.split(lowered) if part)
    return bool(parts & _SECRET_KEY_PARTS)


def _credential_shaped_value(value: str) -> bool:
    """Whether a tool-name value resembles a portable credential."""
    return bool(_CREDENTIAL_VALUE_RE.search(value))


def _walk_keys(value):
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield key
            yield from _walk_keys(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _walk_keys(item)


def _revision_for(root) -> str:
    """Short git HEAD, best effort. Empty when git cannot answer."""
    try:
        from .identity import git_head_sha

        return git_head_sha(str(root))[:12]
    except Exception:
        return ""


def _project_id_for(root) -> str:
    """The pinned project id, best effort. Empty when uninitialized."""
    try:
        from .product_cli import WorkspaceConfig

        config = WorkspaceConfig.load(Path(root))
        return config.project_id if config else ""
    except Exception:
        return ""


def _workspace_id_for(root) -> Optional[str]:
    """Return the registry-backed identity expected for ``root``.

    A workspace id in ``.relinkra/config.json`` is only a pin. It becomes
    usable verification context after the registry proves that the pin names
    the current canonical path, project and OS-derived workspace id.
    """
    try:
        from .product_cli import WorkspaceConfig, registry_path

        config = WorkspaceConfig.load(Path(root))
        if config is None or not config.project_id or not config.workspace_id:
            return None
        if not _WORKSPACE_ID_RE.fullmatch(config.workspace_id):
            return None
        registry = Registry(str(registry_path(Path(root))))
        workspace = registry.get_workspace(config.workspace_id)
        if workspace is None or workspace.project_id != config.project_id:
            return None
        canonical_root = canonicalize_path(str(root))
        os_family = normalize_os_family(sys.platform)
        if workspace.canonical_path != canonical_root or workspace.os != os_family:
            return None
        expected = derive_workspace_id(
            workspace.project_id, canonical_root, os_family
        )
        if workspace.workspace_id != config.workspace_id or workspace.workspace_id != expected:
            return None
        return expected
    except (OSError, RegistryError, TypeError, ValueError):
        return None


def _has_control_chars(text: str) -> bool:
    return any(ord(char) < 0x20 or ord(char) == 0x7F for char in text)


def build_proof_from_payload(
    host: str, payload, *, root, fingerprint: str
) -> VerificationRecord:
    """Validate an operator proof and turn it into a record.

    The payload is a statement FROM the real host's operator, in this
    shape::

        {
          "stages": {"host_launched": true, "handshake_succeeded": true,
                     "tools_visible": true, "tools_callable": true,
                     "handoff_roundtrip": true},
          "tools_visible": ["context_packet", ...],
          "tools_invoked": ["context_packet", ...],
          "handoff_ok": true,
          "workspace_id": "ws_..." or null
        }

    Anything else — unknown hosts, unknown stages, missing required
    stages, absolute paths, credential-shaped keys — is refused whole.
    """
    reasons = []

    try:
        spec = resolve_connector(host)
    except UnknownConnectorError:
        raise ProofError([f"unknown host {host!r}; proofs are accepted only "
                          "for registered connectors"])
    canonical_host = spec.connector_id

    if not isinstance(payload, Mapping):
        raise ProofError(["the proof payload must be a JSON object"])
    _json_depth(payload)
    allowed_payload_keys = {
        "stages", "tools_visible", "tools_invoked", "handoff_ok", "workspace_id"
    }
    unknown_payload = sorted(set(payload) - allowed_payload_keys)
    if unknown_payload:
        reasons.append(
            "unknown proof field(s): " + ", ".join(map(str, unknown_payload))
        )

    stages = payload.get("stages")
    if not isinstance(stages, Mapping):
        reasons.append("'stages' must be an object mapping stage names to booleans")
        stages = {}
    else:
        unknown = sorted(set(str(key) for key in stages) - set(VERIFICATION_STAGES))
        if unknown:
            reasons.append("unknown stage(s): " + ", ".join(unknown))
        missing = [stage for stage in REQUIRED_PROOF_STAGES if stage not in stages]
        if missing:
            reasons.append("missing required stage(s): " + ", ".join(missing))
        non_bool = sorted(
            str(key) for key, value in stages.items() if not isinstance(value, bool)
        )
        if non_bool:
            reasons.append(
                "stage value(s) must be booleans: " + ", ".join(non_bool)
            )

    for key in ("tools_visible", "tools_invoked"):
        value = payload.get(key)
        if not isinstance(value, (list, tuple)) or not all(
            isinstance(item, str) for item in value
        ):
            reasons.append(f"'{key}' must be a list of tool names")
        elif any(_has_control_chars(item) for item in value):
            # Evidence gets pasted, shared and rendered on terminals;
            # control characters turn a name into an escape sequence.
            reasons.append(f"'{key}' contains control character(s)")
        elif any(_credential_shaped_value(item) for item in value):
            reasons.append(f"'{key}' contains credential-shaped value(s)")
        elif len(value) > MAX_TOOL_COUNT:
            reasons.append(f"'{key}' exceeds the tool-count limit")
        elif any(len(item) > MAX_TOOL_NAME_LENGTH for item in value):
            reasons.append(f"'{key}' contains an overlong tool name")

    if not isinstance(payload.get("handoff_ok"), bool):
        reasons.append("'handoff_ok' must be a boolean")

    if "workspace_id" not in payload:
        reasons.append("missing proof field: workspace_id")
    else:
        workspace_id = payload.get("workspace_id")
        if workspace_id is not None:
            if not isinstance(workspace_id, str) or not _WORKSPACE_ID_RE.fullmatch(workspace_id):
                reasons.append(
                    "'workspace_id' must be null or match ^ws_[0-9a-f]{32}$"
                )
            else:
                expected_workspace_id = _workspace_id_for(root)
                if expected_workspace_id is None:
                    reasons.append(
                        "'workspace_id' cannot be validated against the "
                        "registry-backed current workspace"
                    )
                elif workspace_id != expected_workspace_id:
                    reasons.append(
                        "'workspace_id' does not match the current workspace identity"
                    )

    if isinstance(stages, Mapping):
        prerequisites = {
            HANDSHAKE_SUCCEEDED: HOST_LAUNCHED,
            TOOLS_VISIBLE: HANDSHAKE_SUCCEEDED,
            TOOLS_CALLABLE: TOOLS_VISIBLE,
            CONTEXT_ROUNDTRIP: TOOLS_CALLABLE,
            HANDOFF_ROUNDTRIP: TOOLS_CALLABLE,
        }
        for stage, prerequisite in prerequisites.items():
            if stages.get(stage) is True and stages.get(prerequisite) is not True:
                reasons.append(f"stage {stage} skips prerequisite {prerequisite}")
        visible = payload.get("tools_visible")
        invoked = payload.get("tools_invoked")
        if stages.get(TOOLS_VISIBLE) is True and not visible:
            reasons.append("tools_visible is true but the visible tool list is empty")
        if stages.get(TOOLS_CALLABLE) is True:
            if not invoked:
                reasons.append("tools_callable is true but no tool invocation is recorded")
            elif isinstance(visible, (list, tuple)) and not set(invoked).issubset(set(visible)):
                reasons.append("invoked tools must be a subset of visible tools")
        if stages.get(HANDOFF_ROUNDTRIP) is True and payload.get("handoff_ok") is not True:
            reasons.append("handoff_roundtrip is true but handoff_ok is false")

    leaked_paths = [
        value for value in iter_strings(payload) if contains_absolute_path(value)
    ]
    if leaked_paths:
        reasons.append(
            f"the proof contains {len(leaked_paths)} machine-local path(s); "
            "proofs are portable statements, not machine dumps"
        )

    secret_keys = sorted(
        {str(key) for key in _walk_keys(payload) if _secret_shaped_key(key)}
    )
    if secret_keys:
        reasons.append(
            "the proof contains credential-shaped key(s): " + ", ".join(secret_keys)
        )

    if reasons:
        raise ProofError(reasons)

    return VerificationRecord(
        host=canonical_host,
        timestamp=_utc_now().isoformat(),
        registration_fingerprint=fingerprint,
        stages={str(key): bool(value) for key, value in stages.items()},
        tools_visible=tuple(str(item) for item in payload.get("tools_visible") or ()),
        tools_invoked=tuple(str(item) for item in payload.get("tools_invoked") or ()),
        handoff_ok=bool(payload.get("handoff_ok")),
        workspace_root=str(Path(root).resolve()),
        workspace_id=payload.get("workspace_id"),
        project_id=_project_id_for(root),
        revision=_revision_for(root),
    )


__all__ = [
    "ASSESS_STATUSES",
    "CONFIG_APPLIED",
    "CONFIG_DETECTED",
    "CONFIG_VALID",
    "CONTEXT_ROUNDTRIP",
    "DEFAULT_TTL_SECONDS",
    "HANDOFF_ROUNDTRIP",
    "HANDSHAKE_SUCCEEDED",
    "HOST_LAUNCHED",
    "PROTOCOL_COMPATIBLE",
    "ProofError",
    "REQUIRED_PROOF_STAGES",
    "SOURCE_OPERATOR_PROOF",
    "STATUS_ABSENT",
    "STATUS_EXPIRED",
    "STATUS_INVALID",
    "STATUS_STALE_FINGERPRINT",
    "STATUS_VALID",
    "STORE_DIRNAME",
    "TOOLS_CALLABLE",
    "TOOLS_VISIBLE",
    "VERIFICATION_STAGES",
    "VERIFICATION_VERSION",
    "VerificationRecord",
    "assess_verification",
    "build_proof_from_payload",
    "parse_proof_json",
    "load_verification",
    "record_verification",
]
