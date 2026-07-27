"""Relinkra deterministic Project Context Packet model (R1E).

A ContextPacket is the minimal, deterministic bundle of project context an
agent needs to start work: logical identity, baseline active
decisions/constraints, code focus, pending/handoff state, and warnings.
It is POWERFUL INSIDE (explicit provenance and why-included per item) and
SIMPLE OUTSIDE (one JSON document or one Markdown brief).

Hard rules:

- DATA is separate from PROVENANCE. Every item is ``{"data": ...,
  "provenance": {...}}``; ``why_included`` never lives inside the data.
- packet_id is a content hash over identity inputs plus the SORTED
  selected source ids. ``created_at`` is NEVER part of identity:
  identical inputs and selected sources yield an identical packet_id.
- No embeddings, no LLM ranking, no token budgets. Selection is a
  deterministic keyword filter plus fixed structural guardrails.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, List, Mapping, Optional

PACKET_VERSION = "rlkctx2"
PACKET_VERSION_V1 = "rlkctx1"
ACCEPTED_PACKET_VERSIONS = (PACKET_VERSION_V1, PACKET_VERSION)
PACKET_ID_PREFIX = "pkt_"
PACKET_ID_RE = re.compile(r"^pkt_[0-9a-f]{32}$")
_PACKET_NAMESPACE = b"relinkra/context-packet/v1\x00"

MODES = ("project", "workspace", "task", "file", "symbol")
# Highest first: a more specific focus always wins over a broader one.
MODE_PRECEDENCE = ("symbol", "file", "task", "workspace", "project")

SOURCES = ("registry", "engram", "cbm", "relinkra", "git")

PROJECT_ID_RE = re.compile(r"^rlk_[0-9a-f]{32}$")
WORKSPACE_ID_RE = re.compile(r"^ws_[0-9a-f]{32}$")


class PacketError(Exception):
    """Base error for context packet failures."""


class PacketValidationError(PacketError, ValueError):
    """Raised when packet input or model data is invalid."""


def normalize_task_text(text: Optional[str]) -> str:
    """Lowercase, collapse whitespace. Used for identity and matching."""
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def normalize_focus(focus: Optional[Mapping]) -> str:
    """Canonical rendering of the focus block for the identity hash."""
    if not focus:
        return ""
    return json.dumps(
        dict(focus), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def compute_packet_id(
    *,
    project_id: str,
    mode: str,
    workspace_id: Optional[str] = None,
    task: Optional[str] = None,
    focus: Optional[Mapping] = None,
    source_ids: tuple = (),
    packet_version: str = PACKET_VERSION,
) -> str:
    """pkt_ + first 32 hex of sha256(ns + identity fields + sorted sources).

    Fields are NUL-separated to prevent field-boundary ambiguity. Source
    ids (memory_id / code_reference_id / CBM candidate ids) are sorted so
    selection ORDER never affects identity. ``created_at`` and warning or
    diagnostic content deliberately do NOT participate.
    """
    payload = (
        _PACKET_NAMESPACE
        + str(packet_version).encode("utf-8")
        + b"\x00"
        + str(project_id).encode("utf-8")
        + b"\x00"
        + str(workspace_id or "").encode("utf-8")
        + b"\x00"
        + str(mode).encode("utf-8")
        + b"\x00"
        + normalize_task_text(task).encode("utf-8")
        + b"\x00"
        + normalize_focus(focus).encode("utf-8")
        + b"\x00"
        + "\n".join(sorted(str(s) for s in source_ids)).encode("utf-8")
    )
    return PACKET_ID_PREFIX + hashlib.sha256(payload).hexdigest()[:32]


@dataclass
class Provenance:
    """Why and from where an item entered the packet.

    ``source`` is one of registry | engram | cbm | relinkra. All other
    fields are optional identifiers of the upstream artifact. This block
    is metadata: it never mutates the item data it travels with.
    """

    source: str
    why_included: str
    memory_id: Optional[str] = None
    agent_type: Optional[str] = None
    topic_key: Optional[str] = None
    code_reference_id: Optional[str] = None
    workspace_id: Optional[str] = None
    cbm_project_name: Optional[str] = None
    resolution_state: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "why_included": self.why_included,
            "memory_id": self.memory_id,
            "agent_type": self.agent_type,
            "topic_key": self.topic_key,
            "code_reference_id": self.code_reference_id,
            "workspace_id": self.workspace_id,
            "cbm_project_name": self.cbm_project_name,
            "resolution_state": self.resolution_state,
        }

    @staticmethod
    def from_dict(data: Mapping) -> "Provenance":
        return Provenance(
            source=str(data.get("source") or "relinkra"),
            why_included=str(data.get("why_included") or ""),
            memory_id=data.get("memory_id"),
            agent_type=data.get("agent_type"),
            topic_key=data.get("topic_key"),
            code_reference_id=data.get("code_reference_id"),
            workspace_id=data.get("workspace_id"),
            cbm_project_name=data.get("cbm_project_name"),
            resolution_state=data.get("resolution_state"),
        )


@dataclass
class PacketItem:
    """One packet entry: opaque DATA plus its PROVENANCE."""

    data: dict
    provenance: Provenance

    def to_dict(self) -> dict:
        return {"data": self.data, "provenance": self.provenance.to_dict()}

    @staticmethod
    def from_dict(raw: Mapping) -> "PacketItem":
        return PacketItem(
            data=dict(raw.get("data") or {}),
            provenance=Provenance.from_dict(raw.get("provenance") or {}),
        )


@dataclass
class PacketWarning:
    """A non-fatal degradation. Partial packet + warning beats no packet."""

    code: str
    message: str

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message}

    @staticmethod
    def from_dict(raw: Mapping) -> "PacketWarning":
        return PacketWarning(
            code=str(raw.get("code") or "unknown"),
            message=str(raw.get("message") or ""),
        )


@dataclass
class ContextPacket:
    """The R1E Project Context Packet.

    Item lists (``memories``, ``code_references``, ``code_facts``,
    ``pending``, ``handoffs``) hold PacketItem entries. ``provenance`` at
    packet level describes the packet itself (builder, sources used);
    per-item provenance travels with each item.
    """

    packet_id: str
    created_at: str
    mode: str
    project_id: str
    packet_version: str = PACKET_VERSION
    workspace_id: Optional[str] = None
    repository_identity: Optional[dict] = None
    requesting_agent: str = ""
    task: Optional[str] = None
    focus: Optional[dict] = None
    project_facts: dict = field(default_factory=dict)
    memories: List[PacketItem] = field(default_factory=list)
    code_references: List[PacketItem] = field(default_factory=list)
    code_facts: List[PacketItem] = field(default_factory=list)
    pending: List[PacketItem] = field(default_factory=list)
    handoffs: List[PacketItem] = field(default_factory=list)
    git_facts: List[PacketItem] = field(default_factory=list)
    warnings: List[PacketWarning] = field(default_factory=list)
    provenance: dict = field(default_factory=dict)
    diagnostics: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        data = {
            "packet_version": self.packet_version,
            "packet_id": self.packet_id,
            "created_at": self.created_at,
            "mode": self.mode,
            "project_id": self.project_id,
            "workspace_id": self.workspace_id,
            "repository_identity": self.repository_identity,
            "requesting_agent": self.requesting_agent,
            "task": self.task,
            "focus": self.focus,
            "project_facts": self.project_facts,
            "memories": [item.to_dict() for item in self.memories],
            "code_references": [item.to_dict() for item in self.code_references],
            "code_facts": [item.to_dict() for item in self.code_facts],
            "pending": [item.to_dict() for item in self.pending],
            "handoffs": [item.to_dict() for item in self.handoffs],
            "warnings": [w.to_dict() for w in self.warnings],
            "provenance": self.provenance,
            "diagnostics": self.diagnostics,
        }
        # The git_facts section is emitted ONLY by rlkctx2 packets; rlkctx1
        # output never carries the key (byte-compatible git-off behavior).
        if self.packet_version == PACKET_VERSION:
            data["git_facts"] = [item.to_dict() for item in self.git_facts]
        return data

    @staticmethod
    def from_dict(data: Mapping) -> "ContextPacket":
        if not isinstance(data, Mapping):
            raise PacketValidationError("packet must be a JSON object")
        for required in ("packet_id", "created_at", "mode", "project_id"):
            if data.get(required) in (None, ""):
                raise PacketValidationError(
                    f"packet missing required field: {required}"
                )
        if str(data.get("packet_version") or "") not in ACCEPTED_PACKET_VERSIONS:
            raise PacketValidationError("unsupported packet_version")
        return ContextPacket(
            packet_version=str(data["packet_version"]),
            packet_id=str(data["packet_id"]),
            created_at=str(data["created_at"]),
            mode=str(data["mode"]),
            project_id=str(data["project_id"]),
            workspace_id=data.get("workspace_id"),
            repository_identity=data.get("repository_identity"),
            requesting_agent=str(data.get("requesting_agent") or ""),
            task=data.get("task"),
            focus=data.get("focus"),
            project_facts=dict(data.get("project_facts") or {}),
            memories=[PacketItem.from_dict(i) for i in data.get("memories") or []],
            code_references=[
                PacketItem.from_dict(i) for i in data.get("code_references") or []
            ],
            code_facts=[
                PacketItem.from_dict(i) for i in data.get("code_facts") or []
            ],
            pending=[PacketItem.from_dict(i) for i in data.get("pending") or []],
            handoffs=[
                PacketItem.from_dict(i) for i in data.get("handoffs") or []
            ],
            git_facts=[
                PacketItem.from_dict(i) for i in data.get("git_facts") or []
            ],
            warnings=[
                PacketWarning.from_dict(w) for w in data.get("warnings") or []
            ],
            provenance=dict(data.get("provenance") or {}),
            diagnostics=dict(data.get("diagnostics") or {}),
        )

    def to_json(self, *, pretty: bool = False) -> str:
        """Deterministic JSON: keys always sorted."""
        if pretty:
            return json.dumps(
                self.to_dict(), indent=2, sort_keys=True, ensure_ascii=False
            )
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        )

    def to_markdown(self) -> str:
        """Concise human brief with the fixed R1E section layout."""
        lines: List[str] = []
        lines.append("# RELINKRA CONTEXT")
        lines.append("")
        lines.append(f"- packet_id: {self.packet_id}")
        lines.append(f"- mode: {self.mode}")
        lines.append(f"- created_at: {self.created_at}")
        lines.append("")

        lines.append("## Project")
        lines.append("")
        lines.append(f"- project_id: {self.project_id}")
        if self.workspace_id:
            lines.append(f"- workspace_id: {self.workspace_id}")
        if self.repository_identity:
            ident = self.repository_identity
            lines.append(
                f"- repository: {ident.get('value')} "
                f"({ident.get('kind')}, {ident.get('trust')})"
            )
        name = self.project_facts.get("display_name")
        if name:
            lines.append(f"- display_name: {name}")
        ws = self.project_facts.get("workspace") or {}
        if ws:
            bits = [f"workspace {ws.get('workspace_id')}"]
            if ws.get("branch"):
                bits.append(f"branch={ws['branch']}")
            if ws.get("head_sha"):
                bits.append(f"head={ws['head_sha']}")
            if ws.get("cbm_project_name"):
                bits.append(f"cbm={ws['cbm_project_name']}")
            lines.append("- " + " ".join(bits))
        other = [
            item
            for item in self.memories
            if item.data.get("memory_type")
            not in ("decision", "architecture", "constraint")
        ]
        if other:
            lines.append("- other active memories:")
            for item in other:
                lines.append(
                    f"  - [{item.data.get('memory_type')}] "
                    f"{item.data.get('title')} ({item.data.get('memory_id')})"
                )
        lines.append("")

        lines.append("## Task-Focus")
        lines.append("")
        if self.task:
            lines.append(f"- task: {self.task}")
        if self.focus:
            lines.append(
                f"- focus: {json.dumps(self.focus, sort_keys=True, ensure_ascii=False)}"
            )
        if not self.task and not self.focus:
            lines.append("- (none)")
        lines.append("")

        decisions = [
            item
            for item in self.memories
            if item.data.get("memory_type") in ("decision", "architecture")
        ]
        lines.append("## Active decisions")
        lines.append("")
        if decisions:
            for item in decisions:
                lines.append(
                    f"- [{item.data.get('memory_type')}] "
                    f"{item.data.get('title')} ({item.data.get('memory_id')})"
                )
        else:
            lines.append("- (none)")
        lines.append("")

        constraints = [
            item
            for item in self.memories
            if item.data.get("memory_type") == "constraint"
        ]
        lines.append("## Constraints")
        lines.append("")
        if constraints:
            for item in constraints:
                lines.append(
                    f"- {item.data.get('title')} ({item.data.get('memory_id')})"
                )
        else:
            lines.append("- (none)")
        lines.append("")

        lines.append("## Code focus")
        lines.append("")
        if self.code_references:
            for item in self.code_references:
                ref = item.data.get("reference") or {}
                label = ref.get("qualified_name") or ref.get("file_path")
                lines.append(
                    f"- {item.provenance.code_reference_id} "
                    f"{ref.get('reference_kind')} {label} "
                    f"({item.data.get('resolution_state') or 'unresolved'})"
                )
        if self.code_facts:
            for item in self.code_facts:
                fact = item.data
                label = fact.get("qualified_name") or fact.get("file_path")
                lines.append(
                    f"- fact {fact.get('code_reference_id')}: {label} "
                    f"lines {fact.get('start_line')}-{fact.get('end_line')}"
                )
                snippet = fact.get("snippet")
                if snippet:
                    indented = "\n".join(
                        f"    {line}" for line in snippet.splitlines()
                    )
                    lines.append(f"  ```\n{indented}\n  ```")
        if not self.code_references and not self.code_facts:
            lines.append("- (none)")
        lines.append("")

        lines.append("## Pending-Handoff")
        lines.append("")
        if self.pending:
            for item in self.pending:
                lines.append(
                    f"- [pending] {item.data.get('title')} "
                    f"({item.data.get('memory_id')})"
                )
        if self.handoffs:
            for item in self.handoffs:
                lines.append(
                    f"- [handoff] {item.data.get('title')} "
                    f"({item.data.get('memory_id')})"
                )
        if not self.pending and not self.handoffs:
            lines.append("- (none)")
        lines.append("")

        lines.append("## Warnings")
        lines.append("")
        if self.warnings:
            for warning in self.warnings:
                lines.append(f"- [{warning.code}] {warning.message}")
        else:
            lines.append("- (none)")
        lines.append("")

        lines.append("## Provenance")
        lines.append("")
        sources = self.provenance.get("sources") or []
        lines.append(
            f"- builder: {self.provenance.get('builder', 'relinkra')} "
            f"sources: {', '.join(sources) if sources else 'none'}"
        )
        for item in (
            self.memories
            + self.pending
            + self.handoffs
            + self.code_references
            + self.code_facts
        ):
            prov = item.provenance
            key = prov.memory_id or prov.code_reference_id or "item"
            lines.append(
                f"- {key}: source={prov.source} why={prov.why_included}"
            )
        lines.append("")
        return "\n".join(lines)
