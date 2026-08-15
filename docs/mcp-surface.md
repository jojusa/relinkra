# MCP Surface (R3)

R3 turns Relinkra into the **agent-facing control plane**. An agent
connects to one MCP server and asks for project-aware context; Relinkra
sequences Engram, CBM, and git behind that single contract.

```
AGENT (Claude Code / OpenCode / Codex / …)
  |
  |  MCP stdio, newline-delimited JSON-RPC 2.0
  v
RELINKRA MCP  (relinkra/mcp_server.py)
  |           validate -> call ONE application service -> serialize -> map errors
  v
APPLICATION SERVICES  (relinkra/app_service.py)
  |
  +-- Codebase Memory MCP   (code index)
  +-- Engram                (persistent memory)
  +-- Git                   (read-only facts)
```

Agents do **not** connect to CBM or Engram directly for anything
Relinkra exposes. Relinkra owns logical project identity, memory policy,
memory↔code linkage, context packets, budgeting, relevance, git
intelligence, and handoffs. CBM, Engram, and git stay engines.

## Layering rules

Two rules keep the layering honest, and both are enforced by tests:

- **No business logic in MCP handlers.** A handler validates its
  arguments, calls exactly one application service, serializes the typed
  result, and maps typed errors. Nothing else.
- **No duplicated R1E/R1F/R1G logic in the service layer.**
  `context_get` runs the *same* build → relevance → budget → portable
  pipeline the R1E CLI runs. `code_resolve` reuses the R1E code-focus
  path rather than re-deriving symbol lookup. Duplicating either would
  let the two paths drift.

R3 is **purely additive**: it introduced four new modules and modified no
existing R1/R2 file.

## Transport

**stdio, JSON-RPC 2.0, newline-delimited, UTF-8, one message per line.**

No HTTP. The whole codebase is standard library only and R3 does not
change that — the JSON-RPC framing is implemented directly rather than
pulling in an SDK.

Implemented methods:

| Method | Behaviour |
|--------|-----------|
| `initialize` | Negotiates the protocol version and reports `serverInfo` (incl. `contractVersion`) |
| `notifications/initialized` | Accepted, no response (JSON-RPC notification) |
| `ping` | Liveness, returns `{}` |
| `tools/list` | The nine tools with their JSON Schemas |
| `tools/call` | Dispatch to one application service |

Protocol versions supported: `2024-11-05`, `2025-03-26`, `2025-06-18`.
The server echoes the client's version when it recognises it, otherwise
answers with its preferred one. Unknown *notifications* are ignored by
design, so a newer client cannot break an older server. Batch requests
are rejected.

**Error mapping is deliberate.** A failure *inside* a tool is a
`tools/call` **result** with `isError: true` and a typed
`{code, message}` body — the call reached the tool and the tool
answered. JSON-RPC error responses are reserved for envelope faults
(parse error, unknown method, bad params). Typed error codes:
`invalid_input`, `not_found`, `project_mismatch`, `unavailable`,
`internal_error`.

`stdout` carries protocol frames and nothing else; every diagnostic goes
to `stderr`. On Windows both streams are reconfigured to UTF-8 with `\n`
framing, because the default text mode would emit `\r\n` and some clients
reject that as a malformed frame.

## Tool naming

The surface is `relinkra_<domain>_<verb>` — **underscores, not dots.**

Hosts namespace an MCP tool as `mcp__<server>__<tool>`, and the resulting
identifier must match `^[a-zA-Z0-9_-]{1,64}$`. A dotted logical name like
`relinkra.project.resolve` would become
`mcp__relinkra__relinkra.project.resolve`, which fails that pattern on
Claude-family clients. The dotted names remain the documented logical
contract and are carried in the tool table below; a test asserts every
wire name survives host namespacing within the 64-character limit.

## Tool contract

| Wire name | Logical name | Purpose |
|-----------|--------------|---------|
| `relinkra_project_resolve` | `relinkra.project.resolve` | Resolve logical project identity + active workspace |
| `relinkra_context_get` | `relinkra.context.get` | One deterministic Project Context Packet |
| `relinkra_memory_search` | `relinkra.memory.search` | Search shared project memory |
| `relinkra_memory_save` | `relinkra.memory.save` | Save a memory under R1C policy |
| `relinkra_code_resolve` | `relinkra.code.resolve` | Resolve file/symbol → portable code reference |
| `relinkra_git_context` | `relinkra.git.context` | Read-only git facts |
| `relinkra_handoff_create` | `relinkra.handoff.create` | Record a cross-agent handoff |
| `relinkra_handoff_get` | `relinkra.handoff.get` | Fetch one handoff, or list recent ones |
| `relinkra_health` | `relinkra.health` | Contract, engine availability, degraded components |

Every tool declares a JSON Schema with `additionalProperties: false`.
Validation is strict and server-side: object shape, required keys,
unknown-key rejection, primitive types, enums, numeric bounds, and
array-element types. Anything a tool accepts must be declarable in that
subset — which is what keeps malformed or hostile input from reaching an
application service at all.

### Argument conventions

- `project_id` / `workspace_id` are optional on every tool; they fall
  back to the server's configured defaults.
- **Paths are server-owned.** `--workspace-root` is set at startup and is
  never taken from a tool argument, so an agent cannot point Relinkra at
  an arbitrary directory. `file` arguments are repo-relative POSIX paths
  interpreted *within* that root.
- `requesting_agent` and `source_agent` are recorded as provenance data
  only. They never affect ranking, scope, or visibility.

## Context integration

`relinkra_context_get` composes from logical identity, active shared
memories, memory↔code links, CBM facts, git intelligence, pending work,
and relevant handoffs — then passes through **relevance → budget →
portable serialization**, preserving the existing ordering invariants.

The existing read tools also return additive R4D explanation fields. Context
items carry `explain`, packets carry `contradictions` and `explainability`,
and memory, code, Git, and handoff reads carry compact freshness sidecars.
No tool name or input schema changed, and clients may ignore these new output
fields. See [Freshness, contradictions, and explainability](freshness-explainability.md)
for the exact states, fields, authority boundaries, and privacy guarantees.

Handoffs are *not* special-cased. A handoff is persisted as a
`handoff`-type memory, so R1E's existing memory selection picks it up
into the packet's first-class `handoffs` section automatically.

The relevance diagnostic is annotated **after** budgeting, because
`apply_budget` rebuilds the packet and an annotation written earlier
would be dropped from the packet actually returned. The budget report is
returned with its embedded packet stripped — the response already carries
that packet once, and shipping it twice would be self-defeating on a
surface whose whole purpose is respecting a token budget.

## Degraded mode

R3 preserves the R1E philosophy: **a partial result plus a typed warning
beats no result**, and one failing subsystem never breaks an unrelated
tool.

| Failure | Behaviour |
|---------|-----------|
| Engram down | `project_resolve`, `git_context`, `health` still answer. `memory_search` returns a typed `unavailable` error. |
| CBM absent | Memory and git tools unaffected; `code_resolve` degrades to an unresolved reference plus a warning. |
| Git unavailable | Code/memory context still usable; `git_context` reports `available: false` with warnings; `handoff_create` still succeeds with an empty `git_state`. |
| Registry missing | `health` reports `registry` degraded; writes fail typed (`not_found`) because a write needs a registered identity. |
| No workspace root | Only git degrades. |

`health` is the tool an operator reaches for when things are *already*
broken, so it never fails itself — a project-resolution error is reported
as a degraded component rather than raised.

**Recovery needs no restart.** Components are probed per `health` call
and every tool resolves its engine at call time, so a component that
comes back is usable on the very next request from the same process.

## Capability honesty

`health.capabilities` describes what the server can execute **right
now**, not what it implements in principle. Anything requiring a working
memory write path (`memory_read`, `memory_write`, `handoffs`) is reported
against Engram's real, liveness-probed availability — advertising
`handoffs` while Engram is down would be a claim an agent only discovers
by failing. `context_packets` stays available because it degrades to a
partial packet plus warnings rather than failing.

`agent_private_access` and `git_write` are permanent, deliberate
absences, not degradations.

`capabilities_unchecked` names any capability whose backing component was
**not** liveness-probed on this call, so a caller can tell "verified
working" from "configured, unverified". Today that is `code_resolution`
when a CBM binary is configured: probing the code indexer on every status
request would be too expensive, so it is advertised and labelled rather
than silently implying verification. A component known to be absent is a
checked negative, not an unchecked one.

## Security properties

Re-proven by tests in this delta:

- No credentials in output. Free text is pushed through the R1C redactor
  **before** the handoff id is computed, so stored bytes and identity can
  never disagree.
- No absolute machine paths in portable output. `health` reports
  `workspace_root_configured` as a boolean, never the path.
  `project_resolve` projects `Workspace` field-by-field, because that
  object also carries `absolute_path` / `canonical_path`.
- **Every free-text field the service layer emits** — typed error
  messages, warnings, and component probe details — goes through
  `sanitize_wire_text`, which redacts secrets *and* replaces machine-local
  absolute paths. This matters because the text reaching an agent is
  often an underlying error that embeds a path: a missing binary produces
  `engram executable not found: <path>`, and a broken registry produces
  the registry's own path. Redaction alone does not remove paths, so both
  filters are applied.
- `AGENT_PRIVATE` is unreachable: never returned by search, never in a
  context packet, not writable through the surface, and dropped (with a
  warning) if referenced from a handoff. This matters because
  `MemoryService.get()` resolves by id *without* applying a scope filter.
- No cross-project or cross-workspace leakage.
- Git stays read-only; the engine exposes only `collect_*` operations.
- Input is validated before dispatch; no `shell=True` anywhere; shell
  metacharacters are inert data.

## Running the server

```bash
python -m relinkra.mcp_cli \
  --workspace-root . \
  --registry .relinkra/registry.json \
  --project-id rlk_... \
  --workspace-id ws_...
```

Every flag also reads a `RELINKRA_`-prefixed environment variable
(`RELINKRA_WORKSPACE_ROOT`, `RELINKRA_REGISTRY`, `RELINKRA_PROJECT_ID`,
`RELINKRA_CBM_BIN`, …).

## Agent connection examples

The same stdio contract serves every host. Devin Desktop (formerly
Windsurf) already uses it — R4C.1E recorded a real Cascade launch — and
any other MCP-speaking host can use it unchanged; there is no
agent-specific logic in the core.

**Claude Code** (`.mcp.json` / `claude mcp add`):

```json
{
  "mcpServers": {
    "relinkra": {
      "command": "python",
      "args": ["-m", "relinkra.mcp_cli", "--workspace-root", "."],
      "env": { "RELINKRA_REGISTRY": ".relinkra/registry.json" }
    }
  }
}
```

Tools then appear as `mcp__relinkra__relinkra_context_get`, etc.

**OpenCode** (`opencode.json`):

```json
{
  "mcp": {
    "relinkra": {
      "type": "local",
      "command": ["python", "-m", "relinkra.mcp_cli", "--workspace-root", "."],
      "enabled": true
    }
  }
}
```

**Codex** (`~/.codex/config.toml`):

```toml
[mcp_servers.relinkra]
command = "python"
args = ["-m", "relinkra.mcp_cli", "--workspace-root", "."]
```

A minimal hand-rolled client is also enough — write one JSON object per
line to stdin and read one per line from stdout. `tests/test_mcp_proof.py`
does exactly that against two real server processes.

## Proof

`tests/test_mcp_proof.py` is a live end-to-end proof, not an in-process
test: it spawns the real server as a subprocess, speaks real JSON-RPC
over the pipe from an independent client, and persists through the real
Engram store. Agent A and agent B are two **separate** processes, so a
handoff genuinely crosses a process boundary. It skips when `git` or
`engram` is unavailable.
