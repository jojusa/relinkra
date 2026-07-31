"""Relinkra's side of a shared memory backend (R4C.0).

Engram is shared with Gentleman on purpose, and Gentleman was there
first. Everything in this module solves the coexistence problem from
RELINKRA'S SIDE ONLY: nothing here reads, rewrites, migrates or
reinterprets a record Relinkra did not write, and nothing here touches a
Gentleman installation, configuration, workflow or receipt.

Three mechanisms, one rule each.

OWNERSHIP IS DECIDED BY THE ENVELOPE, NOT BY THE STORE. A record belongs
to Relinkra when it carries the ``rlkmem1`` envelope and nothing else
qualifies. A Gentleman record sitting in the same project is
:data:`OWNER_EXTERNAL` — visible as a fact, never parsed as native
memory, never selected into a context packet. ``MemoryService`` already
enforces this by construction (``Memory.from_envelope`` rejects any other
version); :func:`classify_record` gives that guarantee a name so it can
be asserted directly instead of inferred from a parser's failure mode.

A REFERENCE IS NOT A COPY. When a Gentleman event matters to Relinkra —
a review receipt worth linking to a task result — Relinkra stores an
:class:`ExternalReference`: ``source_system``, ``external_id``, and a
capped summary. Never the payload. Copying the receipt would create a
second authority for a record Gentleman owns, which is the exact failure
:data:`OWNERSHIP_MATRIX` exists to prevent, so the matrix is consulted at
save time rather than left as documentation.

DUPLICATE WORK IS OBSERVED WHERE IT IS OBSERVABLE. :class:`ObservingStore`
wraps a memory store and counts identical reads and writes inside one
operation. It is a decorator: ``MemoryService`` is unchanged, every write
still goes through it, and with no wrapper installed nothing behaves
differently. What happens inside Gentleman's own process stays
unverified — this module observes Relinkra, not its neighbour.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .backend_policy import OWNERSHIP_MATRIX, RECORD_FULL, RECORD_NONE
from .memory import ENVELOPE_VERSION, MemoryValidationError

#: Bumped when the external-reference body contract changes.
REFERENCE_VERSION = "relinkra.external-ref/v1"

OWNER_RELINKRA = "relinkra"
OWNER_EXTERNAL = "external"
OWNER_UNKNOWN = "unknown"
OWNERS = frozenset({OWNER_RELINKRA, OWNER_EXTERNAL, OWNER_UNKNOWN})

#: Systems Relinkra knows how to REFER to. Recognising a name grants no
#: access and implies no integration — it only makes the provenance of a
#: reference legible instead of anonymous.
SOURCE_GENTLEMAN = "gentleman"
SOURCE_UNSPECIFIED = "external"
KNOWN_SOURCE_SYSTEMS = frozenset({SOURCE_GENTLEMAN, SOURCE_UNSPECIFIED})

#: Hard cap on a reference summary. Small on purpose: the moment a
#: "summary" can hold a review, the reference has become a copy and the
#: single-authority rule is gone.
MAX_SUMMARY_CHARS = 400

#: Hard cap on an external id. Long enough for a lineage or receipt id,
#: short enough that a payload cannot be smuggled through it.
MAX_EXTERNAL_ID_CHARS = 200


# ---------------------------------------------------------------------------
# Record ownership
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RecordOwnership:
    """Who owns one stored record, and why that was concluded."""

    owner: str
    envelope_version: Optional[str] = None
    reason: str = ""

    @property
    def relinkra_native(self) -> bool:
        return self.owner == OWNER_RELINKRA

    def to_dict(self) -> dict:
        return {
            "owner": self.owner,
            "envelope_version": self.envelope_version,
            "reason": self.reason,
            "relinkra_native": self.relinkra_native,
        }


def classify_record(content: Any) -> RecordOwnership:
    """Decide whether a stored record is Relinkra's, from its content.

    Positive identification only. A record qualifies when it parses as a
    JSON object AND declares ``v == "rlkmem1"``; everything else is
    external. There is deliberately no heuristic — no "looks like ours",
    no key-shape guessing — because the cost of a false positive is
    Relinkra serving a Gentleman workflow record to an agent as project
    memory.
    """
    if isinstance(content, Mapping):
        data: Any = content
    else:
        try:
            data = json.loads(content)
        except (TypeError, ValueError):
            return RecordOwnership(
                OWNER_EXTERNAL, None, "record content is not a JSON object"
            )
    if not isinstance(data, Mapping):
        return RecordOwnership(
            OWNER_EXTERNAL, None, "record content is not a JSON object"
        )
    version = data.get("v")
    if version == ENVELOPE_VERSION:
        return RecordOwnership(
            OWNER_RELINKRA, ENVELOPE_VERSION, "carries the Relinkra envelope"
        )
    if version is None:
        return RecordOwnership(
            OWNER_EXTERNAL, None, "no Relinkra envelope version present"
        )
    return RecordOwnership(
        OWNER_EXTERNAL,
        str(version),
        "envelope version is not Relinkra's",
    )


def is_relinkra_owned(content: Any) -> bool:
    """Convenience predicate over :func:`classify_record`."""
    return classify_record(content).relinkra_native


def partition_records(records: Any) -> Tuple[List[Any], List[Any]]:
    """Split store records into (relinkra_owned, external).

    Both halves are returned because both matter: the first is what
    Relinkra may interpret, and the second is what it must leave exactly
    as it found it. Counting the second is how ``doctor`` can say "this
    project also holds records Relinkra does not own" without implying it
    did anything to them.
    """
    owned: List[Any] = []
    external: List[Any] = []
    for record in records or ():
        content = getattr(record, "content", record)
        (owned if is_relinkra_owned(content) else external).append(record)
    return owned, external


# ---------------------------------------------------------------------------
# External references
# ---------------------------------------------------------------------------

#: Which shared domain each reference kind belongs to. The domain — not
#: the kind — decides whether Relinkra may store anything at all, so this
#: map is the join between a caller's vocabulary and the authority matrix.
REFERENCE_KIND_DOMAIN: Dict[str, str] = {
    "review_receipt": "gentleman_reviews_and_receipts",
    "review_finding": "gentleman_reviews_and_receipts",
    "sdd_phase": "sdd_workflow_state",
    "workflow_checkpoint": "gentleman_workflow_checkpoints",
    "external_artifact": "gentleman_specific_artifacts",
}

#: How an allowed reference is typed as Relinkra memory. Only kinds the
#: matrix permits appear here.
REFERENCE_KIND_MEMORY_TYPE: Dict[str, str] = {
    "review_receipt": "verification",
    "review_finding": "verification",
}


class ExternalReferenceError(MemoryValidationError):
    """Raised when a reference would exceed what Relinkra may store."""


@dataclass(frozen=True)
class ExternalReference:
    """A pointer to a record another system owns.

    Deliberately anaemic. It carries enough to FIND the original
    (``source_system`` plus ``external_id``) and enough to decide whether
    fetching it is worth doing (``summary``), and nothing else. If a
    caller wants the content, the answer is to ask the owning system —
    that is what having an authority means.
    """

    source_system: str
    external_id: str
    kind: str
    summary: str = ""
    reference_version: str = REFERENCE_VERSION

    def to_body(self) -> str:
        """The compact JSON body stored inside the Relinkra envelope."""
        return json.dumps(
            {
                "ref": self.reference_version,
                "source_system": self.source_system,
                "external_id": self.external_id,
                "kind": self.kind,
                "summary": self.summary,
            },
            separators=(",", ":"),
            ensure_ascii=False,
            sort_keys=True,
        )

    def to_dict(self) -> dict:
        return {
            "reference_version": self.reference_version,
            "source_system": self.source_system,
            "external_id": self.external_id,
            "kind": self.kind,
            "summary": self.summary,
        }

    @property
    def domain(self) -> Optional[str]:
        return REFERENCE_KIND_DOMAIN.get(self.kind)


def _matrix_allowance(domain: str) -> str:
    for rule in OWNERSHIP_MATRIX:
        if rule.domain == domain:
            return rule.relinkra_stores
    return RECORD_NONE


def build_external_reference(
    *,
    source_system: str,
    external_id: str,
    kind: str,
    summary: str = "",
) -> ExternalReference:
    """Validate and build a reference, refusing anything copy-shaped.

    Every rejection below has the same root cause: a reference that grows
    into a copy stops being a reference. An over-long summary is the
    obvious version; a kind whose domain the matrix says Relinkra stores
    NOTHING for is the subtle one, and it is refused even when the caller
    only wants to store a pointer — Gentleman's SDD phase state is
    Gentleman's, including the fact that it exists.
    """
    system = (source_system or "").strip().lower()
    if system not in KNOWN_SOURCE_SYSTEMS:
        raise ExternalReferenceError(
            f"unsupported source_system: {source_system!r}; known: "
            + ", ".join(sorted(KNOWN_SOURCE_SYSTEMS))
        )
    identifier = (external_id or "").strip()
    if not identifier:
        raise ExternalReferenceError("external_id must be non-empty")
    if len(identifier) > MAX_EXTERNAL_ID_CHARS:
        raise ExternalReferenceError(
            f"external_id exceeds {MAX_EXTERNAL_ID_CHARS} characters"
        )
    domain = REFERENCE_KIND_DOMAIN.get(kind)
    if domain is None:
        raise ExternalReferenceError(
            f"unsupported reference kind: {kind!r}; known: "
            + ", ".join(sorted(REFERENCE_KIND_DOMAIN))
        )
    allowance = _matrix_allowance(domain)
    if allowance == RECORD_NONE:
        raise ExternalReferenceError(
            f"the ownership matrix gives Relinkra no record for '{domain}'; "
            "that domain belongs entirely to its authority."
        )
    if allowance == RECORD_FULL:
        raise ExternalReferenceError(
            f"'{domain}' is Relinkra-owned; store it as native memory, not "
            "as an external reference."
        )
    text = (summary or "").strip()
    if len(text) > MAX_SUMMARY_CHARS:
        raise ExternalReferenceError(
            f"summary exceeds {MAX_SUMMARY_CHARS} characters; store a "
            "reference, not a copy of the record."
        )
    return ExternalReference(
        source_system=system,
        external_id=identifier,
        kind=kind,
        summary=text,
    )


def save_external_reference(
    service: Any,
    *,
    project_id: str,
    repository_identity: Any,
    reference: ExternalReference,
    title: str = "",
    workspace_id: Optional[str] = None,
    agent_id: str = "",
    agent_type: str = "",
    scope: str = "project_shared",
) -> tuple:
    """Persist a reference THROUGH ``MemoryService``. Returns its result.

    Routed through the service rather than the store on purpose: scoping,
    redaction, dedup, supersession and the envelope are policy, and a
    reference that skipped them would be a second, weaker write path into
    the same backend.
    """
    memory_type = REFERENCE_KIND_MEMORY_TYPE.get(reference.kind)
    if memory_type is None:
        raise ExternalReferenceError(
            f"reference kind {reference.kind!r} has no Relinkra memory type"
        )
    heading = (title or "").strip() or (
        f"{reference.source_system} {reference.kind} {reference.external_id}"
    )
    return service.save(
        project_id=project_id,
        memory_type=memory_type,
        title=heading,
        body=reference.to_body(),
        repository_identity=repository_identity,
        scope=scope,
        workspace_id=workspace_id,
        agent_id=agent_id,
        agent_type=agent_type,
        source_tool="relinkra",
    )


def read_external_reference(body: Any) -> Optional[ExternalReference]:
    """Parse a reference back out of a memory body, or ``None``.

    ``None`` rather than an exception: most memory bodies are ordinary
    prose, and "this is not a reference" is a normal answer to a question
    a caller is allowed to ask about any record.
    """
    try:
        data = json.loads(body) if not isinstance(body, Mapping) else body
    except (TypeError, ValueError):
        return None
    if not isinstance(data, Mapping) or data.get("ref") != REFERENCE_VERSION:
        return None
    kind = str(data.get("kind") or "")
    if kind not in REFERENCE_KIND_DOMAIN:
        return None
    return ExternalReference(
        source_system=str(data.get("source_system") or SOURCE_UNSPECIFIED),
        external_id=str(data.get("external_id") or ""),
        kind=kind,
        summary=str(data.get("summary") or ""),
    )


# ---------------------------------------------------------------------------
# Duplicate read/write observation
# ---------------------------------------------------------------------------

OP_READ = "read"
OP_WRITE = "write"


@dataclass(frozen=True)
class DuplicateOperation:
    """One backend call Relinkra made more than once in an operation."""

    operation: str
    fingerprint: str
    count: int

    def to_dict(self) -> dict:
        return {
            "operation": self.operation,
            "fingerprint": self.fingerprint,
            "count": self.count,
        }


@dataclass
class OperationLedger:
    """Counts identical backend calls within one logical operation.

    Fingerprints are STRUCTURAL — the query text, project and limit for a
    read; the topic key, type and content digest for a write — so two
    calls collide only when they would return or persist the same thing.
    """

    reads: Dict[str, int] = field(default_factory=dict)
    writes: Dict[str, int] = field(default_factory=dict)

    def record(self, operation: str, fingerprint: str) -> None:
        bucket = self.reads if operation == OP_READ else self.writes
        bucket[fingerprint] = bucket.get(fingerprint, 0) + 1

    def reset(self) -> None:
        self.reads.clear()
        self.writes.clear()

    @property
    def read_calls(self) -> int:
        return sum(self.reads.values())

    @property
    def write_calls(self) -> int:
        return sum(self.writes.values())

    def duplicates(self) -> Tuple[DuplicateOperation, ...]:
        found = [
            DuplicateOperation(OP_READ, key, count)
            for key, count in sorted(self.reads.items())
            if count > 1
        ]
        found.extend(
            DuplicateOperation(OP_WRITE, key, count)
            for key, count in sorted(self.writes.items())
            if count > 1
        )
        return tuple(found)

    @property
    def duplicate_reads_avoidable(self) -> int:
        """Calls that would disappear if identical reads were reused."""
        return sum(count - 1 for count in self.reads.values() if count > 1)

    def to_dict(self) -> dict:
        return {
            "read_calls": self.read_calls,
            "write_calls": self.write_calls,
            "distinct_reads": len(self.reads),
            "distinct_writes": len(self.writes),
            "duplicate_reads_avoidable": self.duplicate_reads_avoidable,
            "duplicates": [item.to_dict() for item in self.duplicates()],
        }


def _digest(value: str) -> str:
    """Short, stable fingerprint of a content string.

    Hashed rather than stored: a fingerprint is compared, never read, and
    a raw memory body in a diagnostic ledger is a leak waiting for
    someone to print it.
    """
    import hashlib

    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


class ObservingStore:
    """A memory store decorator that records what Relinkra asked for.

    Transparent by construction: every method delegates, return values
    pass through untouched, and exceptions propagate. Installing it
    changes what Relinkra KNOWS about its own behaviour and nothing about
    that behaviour — which is the only way an observer is allowed to
    exist in a write path.

    Deliberately not a cache. Suppressing a repeated read would change
    ``MemoryService`` semantics (a second read after a save must see the
    save), and R4C.0 is a measurement phase, not an optimisation one.
    """

    def __init__(self, store: Any, ledger: Optional[OperationLedger] = None):
        self._store = store
        self.ledger = ledger if ledger is not None else OperationLedger()

    def __getattr__(self, name: str) -> Any:
        # Anything this decorator does not intercept belongs to the
        # wrapped store, unchanged.
        return getattr(self._store, name)

    def search_records(self, **kwargs: Any) -> Any:
        fingerprint = "|".join(
            (
                str(kwargs.get("query") or ""),
                str(kwargs.get("project") or ""),
                str(kwargs.get("storage_type") or ""),
                str(kwargs.get("limit") or ""),
            )
        )
        self.ledger.record(OP_READ, fingerprint)
        return self._store.search_records(**kwargs)

    def save_record(self, **kwargs: Any) -> Any:
        fingerprint = "|".join(
            (
                str(kwargs.get("project") or ""),
                str(kwargs.get("topic_key") or ""),
                str(kwargs.get("storage_type") or ""),
                _digest(str(kwargs.get("content") or "")),
            )
        )
        self.ledger.record(OP_WRITE, fingerprint)
        return self._store.save_record(**kwargs)


__all__ = [
    "KNOWN_SOURCE_SYSTEMS",
    "MAX_EXTERNAL_ID_CHARS",
    "MAX_SUMMARY_CHARS",
    "OP_READ",
    "OP_WRITE",
    "OWNERS",
    "OWNER_EXTERNAL",
    "OWNER_RELINKRA",
    "OWNER_UNKNOWN",
    "REFERENCE_KIND_DOMAIN",
    "REFERENCE_KIND_MEMORY_TYPE",
    "REFERENCE_VERSION",
    "SOURCE_GENTLEMAN",
    "SOURCE_UNSPECIFIED",
    "DuplicateOperation",
    "ExternalReference",
    "ExternalReferenceError",
    "ObservingStore",
    "OperationLedger",
    "RecordOwnership",
    "build_external_reference",
    "classify_record",
    "is_relinkra_owned",
    "partition_records",
    "read_external_reference",
    "save_external_reference",
]
