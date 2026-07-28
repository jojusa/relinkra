"""Relinkra MCP server — stdio JSON-RPC 2.0 transport (R3).

A THIN adapter. Every handler does exactly four things:

    validate input -> call one application service -> serialize typed
    output -> map typed errors

No business logic lives here. Composition, policy, budgeting, relevance,
and git intelligence all stay in ``relinkra.app_service`` and the R1/R2
modules beneath it.

Transport is MCP stdio: newline-delimited JSON-RPC 2.0 over stdin/stdout,
UTF-8, one message per line. No HTTP, no third-party dependency — the
whole Relinkra codebase is standard library only and this layer does not
change that.

Tool naming: the surface is ``relinkra_<domain>_<verb>`` (underscores,
not dots). Hosts namespace an MCP tool as ``mcp__<server>__<tool>`` and
the resulting identifier must match ``^[a-zA-Z0-9_-]{1,64}$``; a dotted
name like ``relinkra.project.resolve`` would not survive that mapping on
Claude-family clients. The dotted names remain the documented logical
contract and are reported by ``relinkra_health``.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Callable, Dict, List, Optional

from . import __version__
from .app_service import (
    CONTRACT_VERSION,
    ERR_INTERNAL,
    ERR_INVALID_INPUT,
    RelinkraServices,
    ServiceError,
)

SERVER_NAME = "relinkra"

#: Protocol revisions this server speaks. Negotiation echoes the client's
#: version when we support it, otherwise we answer with our preferred one.
SUPPORTED_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18")
PREFERRED_PROTOCOL_VERSION = "2025-06-18"

# JSON-RPC 2.0 reserved codes.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

_MAX_LINE_BYTES = 4 * 1024 * 1024


def _string(desc: str, **extra) -> dict:
    schema = {"type": "string", "description": desc}
    schema.update(extra)
    return schema


def _string_array(desc: str) -> dict:
    return {
        "type": "array",
        "description": desc,
        "items": {"type": "string"},
    }


_PROJECT_ID = _string(
    "Logical Relinkra project id (rlk_...). Omit to use the server default."
)
_WORKSPACE_ID = _string(
    "Workspace id (ws_...). Omit to use the server default."
)


TOOLS: List[dict] = [
    {
        "name": "relinkra_project_resolve",
        "logical_name": "relinkra.project.resolve",
        "description": (
            "Resolve the logical Relinkra project identity for this server, "
            "including repository identity and the active workspace. Call "
            "this first: every other tool is scoped to a project_id."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_id": _PROJECT_ID,
                "workspace_id": _WORKSPACE_ID,
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "relinkra_context_get",
        "logical_name": "relinkra.context.get",
        "description": (
            "Get a deterministic Project Context Packet: logical identity, "
            "active shared memories, memory-code links, code facts, git "
            "intelligence, pending work, and relevant handoffs — ranked by "
            "relevance and bounded by a token budget. This is the main "
            "entry point for starting work on a project."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_id": _PROJECT_ID,
                "workspace_id": _WORKSPACE_ID,
                "task": _string("What you are about to work on."),
                "file": _string("Repo-relative POSIX path to focus on."),
                "symbol": _string("Qualified symbol name to focus on."),
                "requesting_agent": _string(
                    "Calling agent label. Recorded as provenance only; it "
                    "never affects ranking or visibility."
                ),
                "include_git": {
                    "type": "boolean",
                    "description": "Include read-only git facts (default true).",
                },
                "budget": _string(
                    "Fixed budget profile.", enum=["small", "medium", "large"]
                ),
                "max_tokens": {
                    "type": "integer",
                    "description": "Explicit token cap; wins over budget.",
                    "minimum": 1,
                },
                "rank": {
                    "type": "boolean",
                    "description": "Apply relevance ranking (default true).",
                },
                "format": _string(
                    "Output shape.", enum=["json", "markdown"]
                ),
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "relinkra_memory_search",
        "logical_name": "relinkra.memory.search",
        "description": (
            "Search shared project memory (decisions, constraints, "
            "discoveries, bugs, pending work, handoffs). Agent-private "
            "memory is never returned through this surface."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_id": _PROJECT_ID,
                "workspace_id": _WORKSPACE_ID,
                "query": _string("Free-text filter."),
                "memory_type": _string(
                    "Restrict to one memory type.",
                    enum=[
                        "decision",
                        "discovery",
                        "constraint",
                        "bug",
                        "architecture",
                        "task_result",
                        "verification",
                        "pending",
                        "handoff",
                    ],
                ),
                "include_history": {
                    "type": "boolean",
                    "description": "Include superseded records.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results (1-100).",
                    "minimum": 1,
                    "maximum": 100,
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "relinkra_memory_save",
        "logical_name": "relinkra.memory.save",
        "description": (
            "Save a project memory (decision, constraint, discovery, bug, "
            "architecture note, pending work). Deduplicated and "
            "superseded automatically by the Relinkra memory policy."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_id": _PROJECT_ID,
                "workspace_id": _WORKSPACE_ID,
                "memory_type": _string(
                    "Kind of memory.",
                    enum=[
                        "decision",
                        "discovery",
                        "constraint",
                        "bug",
                        "architecture",
                        "task_result",
                        "verification",
                        "pending",
                    ],
                ),
                "title": _string("Short title. Required."),
                "body": _string("Full content."),
                "scope": _string(
                    "Visibility. agent_private is rejected here.",
                    enum=["project_shared", "workspace_local"],
                ),
                "agent_id": _string("Optional calling agent instance id."),
                "confidence": {
                    "type": "number",
                    "description": "Confidence in [0.0, 1.0].",
                    "minimum": 0.0,
                    "maximum": 1.0,
                },
            },
            "required": ["memory_type", "title"],
            "additionalProperties": False,
        },
    },
    {
        "name": "relinkra_code_resolve",
        "logical_name": "relinkra.code.resolve",
        "description": (
            "Resolve a file or symbol to a portable code reference plus any "
            "memories linked to it. Degrades to an unresolved reference "
            "with a warning when the code index is unavailable."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_id": _PROJECT_ID,
                "workspace_id": _WORKSPACE_ID,
                "file": _string("Repo-relative POSIX path."),
                "symbol": _string("Qualified symbol name."),
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "relinkra_git_context",
        "logical_name": "relinkra.git.context",
        "description": (
            "Read-only git intelligence for the configured workspace: "
            "repository state, HEAD facts, recent commits, working diff, "
            "and optional per-file history. Never mutates the repository."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_id": _PROJECT_ID,
                "file": _string("Repo-relative path for file history."),
                "history_limit": {
                    "type": "integer",
                    "description": "Max commits (1-100).",
                    "minimum": 1,
                    "maximum": 100,
                },
                "include_diff": {
                    "type": "boolean",
                    "description": "Include working-tree diff facts.",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "relinkra_handoff_create",
        "logical_name": "relinkra.handoff.create",
        "description": (
            "Record a cross-agent handoff: what the task was, what is done, "
            "what is pending, decisions, warnings, and the git state. "
            "Shared with every agent on the project and readable by name "
            "from any other agent or workspace."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_id": _PROJECT_ID,
                "workspace_id": _WORKSPACE_ID,
                "source_agent": _string(
                    "Agent producing the handoff, e.g. 'opencode'. Data "
                    "only: it confers no authority and never affects "
                    "ranking."
                ),
                "target_agent": _string(
                    "Intended recipient, e.g. 'claude'. Optional."
                ),
                "task": _string("What the work was. Required."),
                "summary": _string("Narrative summary of the state."),
                "completed_work": _string_array("What is finished."),
                "pending_work": _string_array("What remains."),
                "decisions": _string_array("Decisions taken."),
                "warnings": _string_array("Risks the next agent must know."),
                "related_memory_ids": _string_array(
                    "Memory ids (mem_...) to attach. Agent-private ids are "
                    "dropped with a warning."
                ),
                "related_code_reference_ids": _string_array(
                    "Code reference ids (ref_...) to attach."
                ),
                "context_packet_id": _string(
                    "Context packet (pkt_...) this handoff was built from."
                ),
                "supersedes": _string(
                    "Handoff id (hof_...) this one replaces. The prior "
                    "handoff is retained, never rewritten."
                ),
                "include_git_state": {
                    "type": "boolean",
                    "description": "Capture git state (default true).",
                },
            },
            "required": ["source_agent", "task"],
            "additionalProperties": False,
        },
    },
    {
        "name": "relinkra_handoff_get",
        "logical_name": "relinkra.handoff.get",
        "description": (
            "Fetch one handoff by id, or list the most recent handoffs for "
            "the project. Use target_agent to find work left for you."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_id": _PROJECT_ID,
                "workspace_id": _WORKSPACE_ID,
                "handoff_id": _string("Specific handoff id (hof_...)."),
                "target_agent": _string("Filter by intended recipient."),
                "include_history": {
                    "type": "boolean",
                    "description": "Include superseded handoffs.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results (1-50).",
                    "minimum": 1,
                    "maximum": 50,
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "relinkra_health",
        "logical_name": "relinkra.health",
        "description": (
            "Report Relinkra version and schema contract, project "
            "resolution status, availability of Engram / code index / git, "
            "degraded components, and supported capabilities."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
]

TOOLS_BY_NAME = {tool["name"]: tool for tool in TOOLS}


class ProtocolError(Exception):
    """A JSON-RPC level failure (bad envelope, unknown method, bad params)."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def validate_arguments(schema: dict, arguments: Any) -> dict:
    """Validate tool arguments against the declared subset of JSON Schema.

    Deliberately strict and deliberately small: it enforces object shape,
    required keys, unknown-key rejection, primitive types, enums, numeric
    bounds, and array-of-string element types. Anything a tool accepts
    must be declarable here — that keeps malformed or hostile input from
    reaching an application service at all.
    """
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        raise ProtocolError(INVALID_PARAMS, "arguments must be an object")

    properties = schema.get("properties") or {}
    if not schema.get("additionalProperties", True):
        unknown = sorted(set(arguments) - set(properties))
        if unknown:
            raise ProtocolError(
                INVALID_PARAMS,
                f"unknown argument(s): {', '.join(unknown)}",
            )

    for key in schema.get("required") or []:
        if arguments.get(key) in (None, ""):
            raise ProtocolError(INVALID_PARAMS, f"missing required argument: {key}")

    cleaned: Dict[str, Any] = {}
    for key, value in arguments.items():
        spec = properties.get(key)
        if spec is None or value is None:
            if value is not None:
                cleaned[key] = value
            continue
        cleaned[key] = _validate_value(key, spec, value)
    return cleaned


def _validate_value(key: str, spec: dict, value: Any) -> Any:
    expected = spec.get("type")
    if expected == "string":
        if not isinstance(value, str):
            raise ProtocolError(INVALID_PARAMS, f"{key} must be a string")
        choices = spec.get("enum")
        if choices and value not in choices:
            raise ProtocolError(
                INVALID_PARAMS,
                f"{key} must be one of: {', '.join(choices)}",
            )
        return value
    if expected == "boolean":
        if not isinstance(value, bool):
            raise ProtocolError(INVALID_PARAMS, f"{key} must be a boolean")
        return value
    if expected == "integer":
        # bool is a subclass of int; a boolean here is a client bug.
        if isinstance(value, bool) or not isinstance(value, int):
            raise ProtocolError(INVALID_PARAMS, f"{key} must be an integer")
        return _check_bounds(key, spec, value)
    if expected == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ProtocolError(INVALID_PARAMS, f"{key} must be a number")
        return _check_bounds(key, spec, value)
    if expected == "array":
        if not isinstance(value, list):
            raise ProtocolError(INVALID_PARAMS, f"{key} must be an array")
        item_type = (spec.get("items") or {}).get("type")
        if item_type == "string":
            for entry in value:
                if not isinstance(entry, str):
                    raise ProtocolError(
                        INVALID_PARAMS, f"{key} must contain only strings"
                    )
        return value
    if expected == "object":
        if not isinstance(value, dict):
            raise ProtocolError(INVALID_PARAMS, f"{key} must be an object")
        return value
    return value


def _check_bounds(key: str, spec: dict, value: Any) -> Any:
    minimum = spec.get("minimum")
    maximum = spec.get("maximum")
    if minimum is not None and value < minimum:
        raise ProtocolError(INVALID_PARAMS, f"{key} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ProtocolError(INVALID_PARAMS, f"{key} must be <= {maximum}")
    return value


class MCPServer:
    """MCP stdio server bound to one RelinkraServices facade."""

    def __init__(self, services: RelinkraServices):
        self.services = services
        self.protocol_version = PREFERRED_PROTOCOL_VERSION
        self.initialized = False
        self._handlers: Dict[str, Callable[[dict], dict]] = {
            "initialize": self._handle_initialize,
            "ping": lambda params: {},
            "tools/list": self._handle_tools_list,
            "tools/call": self._handle_tools_call,
        }
        self._tool_dispatch: Dict[str, Callable[..., dict]] = {
            "relinkra_project_resolve": self.services.project_resolve,
            "relinkra_context_get": self.services.context_get,
            "relinkra_memory_search": self.services.memory_search,
            "relinkra_memory_save": self.services.memory_save,
            "relinkra_code_resolve": self.services.code_resolve,
            "relinkra_git_context": self.services.git_context,
            "relinkra_handoff_create": self.services.handoff_create,
            "relinkra_handoff_get": self.services.handoff_get,
            "relinkra_health": lambda: self.services.health(),
        }

    # -- protocol ---------------------------------------------------------

    def _handle_initialize(self, params: dict) -> dict:
        requested = str((params or {}).get("protocolVersion") or "")
        if requested in SUPPORTED_PROTOCOL_VERSIONS:
            self.protocol_version = requested
        else:
            self.protocol_version = PREFERRED_PROTOCOL_VERSION
        self.initialized = True
        return {
            "protocolVersion": self.protocol_version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {
                "name": SERVER_NAME,
                "version": __version__,
                "contractVersion": CONTRACT_VERSION,
            },
        }

    def _handle_tools_list(self, params: dict) -> dict:
        return {
            "tools": [
                {
                    "name": tool["name"],
                    "description": tool["description"],
                    "inputSchema": tool["inputSchema"],
                }
                for tool in TOOLS
            ]
        }

    def _handle_tools_call(self, params: dict) -> dict:
        params = params or {}
        name = params.get("name")
        if not isinstance(name, str) or not name:
            raise ProtocolError(INVALID_PARAMS, "tools/call requires a name")
        tool = TOOLS_BY_NAME.get(name)
        if tool is None:
            raise ProtocolError(INVALID_PARAMS, f"unknown tool: {name}")

        arguments = validate_arguments(tool["inputSchema"], params.get("arguments"))
        handler = self._tool_dispatch[name]

        try:
            payload = handler(**arguments)
        except ServiceError as exc:
            # A tool-level failure is a RESULT with isError, not a
            # protocol error: the call reached the tool and the tool
            # answered. Protocol errors are reserved for envelope faults.
            return self._tool_result(exc.to_dict(), is_error=True)
        except (TypeError, ValueError) as exc:
            return self._tool_result(
                ServiceError(ERR_INVALID_INPUT, str(exc)).to_dict(),
                is_error=True,
            )
        except Exception as exc:  # never leak a traceback to the client
            return self._tool_result(
                ServiceError(ERR_INTERNAL, str(exc)).to_dict(), is_error=True
            )
        return self._tool_result(payload, is_error=False)

    @staticmethod
    def _tool_result(payload: Any, *, is_error: bool) -> dict:
        text = json.dumps(
            payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        )
        result = {
            "content": [{"type": "text", "text": text}],
            "isError": is_error,
        }
        if isinstance(payload, dict):
            # structuredContent is honoured by newer clients; older ones
            # ignore the unknown key and read `content` instead.
            result["structuredContent"] = payload
        return result

    # -- dispatch ---------------------------------------------------------

    def handle_message(self, message: Any) -> Optional[dict]:
        """Handle one decoded JSON-RPC message.

        Returns the response object, or None for notifications (which by
        JSON-RPC definition must not be answered).
        """
        if isinstance(message, list):
            raise ProtocolError(
                INVALID_REQUEST, "batch requests are not supported"
            )
        if not isinstance(message, dict):
            raise ProtocolError(INVALID_REQUEST, "message must be an object")
        if message.get("jsonrpc") != "2.0":
            raise ProtocolError(INVALID_REQUEST, "jsonrpc must be '2.0'")

        method = message.get("method")
        message_id = message.get("id")
        is_notification = "id" not in message

        if not isinstance(method, str) or not method:
            if is_notification:
                return None
            raise ProtocolError(INVALID_REQUEST, "method must be a string")

        if is_notification:
            # Notifications are fire-and-forget. Unknown ones are ignored
            # by design so a newer client cannot break an older server.
            return None

        handler = self._handlers.get(method)
        if handler is None:
            return _error_response(
                message_id, METHOD_NOT_FOUND, f"unknown method: {method}"
            )

        params = message.get("params")
        if params is not None and not isinstance(params, dict):
            return _error_response(
                message_id, INVALID_PARAMS, "params must be an object"
            )

        try:
            result = handler(params or {})
        except ProtocolError as exc:
            return _error_response(message_id, exc.code, exc.message)
        except Exception as exc:
            return _error_response(message_id, INTERNAL_ERROR, str(exc))
        return {"jsonrpc": "2.0", "id": message_id, "result": result}

    def handle_line(self, line: str) -> Optional[dict]:
        """Decode and handle one newline-delimited JSON-RPC message."""
        try:
            message = json.loads(line)
        except ValueError:
            return _error_response(None, PARSE_ERROR, "invalid JSON")
        try:
            return self.handle_message(message)
        except ProtocolError as exc:
            message_id = message.get("id") if isinstance(message, dict) else None
            return _error_response(message_id, exc.code, exc.message)

    def serve(self, stdin=None, stdout=None) -> int:
        """Run the stdio loop until EOF.

        Reads with an explicit readline rather than iterating the stream
        so a decode failure on one line can be answered and stepped over.
        Iteration would raise out of the loop entirely, killing the
        server for every in-flight call because of one bad byte.

        Known bound: the size guard rejects an oversized message but
        cannot stop the runtime buffering it first, since a line is only
        delimited by its newline. Acceptable here — the stdio peer is the
        local host process that launched this server, so an unterminated
        line is a denial of service against itself, not a trust boundary.
        """
        stdin = stdin if stdin is not None else sys.stdin
        stdout = stdout if stdout is not None else sys.stdout
        while True:
            try:
                raw = stdin.readline()
            except UnicodeDecodeError:
                self._write(
                    stdout,
                    _error_response(
                        None, PARSE_ERROR, "message was not valid UTF-8"
                    ),
                )
                continue
            if not raw:
                return 0
            line = raw.strip()
            if not line:
                continue
            if len(line.encode("utf-8", "ignore")) > _MAX_LINE_BYTES:
                response = _error_response(
                    None, INVALID_REQUEST, "message exceeds size limit"
                )
            else:
                response = self.handle_line(line)
            if response is None:
                continue
            self._write(stdout, response)

    @staticmethod
    def _write(stdout, response: dict) -> None:
        stdout.write(
            json.dumps(response, ensure_ascii=False, separators=(",", ":"))
            + "\n"
        )
        stdout.flush()


def _error_response(message_id: Any, code: int, message: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "error": {"code": code, "message": message},
    }
