# Project Context Packet (R1E)

A **ContextPacket** is the minimal, deterministic bundle of project context
an agent needs to start work on a Relinkra logical project. It composes the
R1B identity registry, the R1C shared-memory policy, and the R1D memory↔code
linkage into ONE auditable document.

Powerful inside, simple outside:

- **Inside**: every item carries explicit provenance — where it came from
  (`registry` | `engram` | `cbm` | `relinkra`) and *why it was included*.
  DATA is always separate from PROVENANCE (`{"data": ..., "provenance": ...}`).
- **Outside**: one deterministic JSON document, or one concise Markdown
  brief. Nothing else to learn.

```
 ContextRequest (project/workspace/task/file/symbol)
        │
        ▼
 ┌──────────────────────┐   active-only query    ┌───────────────────┐
 │ ContextBuilder       │ ─────────────────────► │ MemoryService R1C │
 │  mode precedence     │                        │  scope channels   │
 │  keyword filter      │   resolve + link       │  lifecycle        │
 │  type priority       │ ─────────────────────► │ LinkageService R1D│
 │  guardrails          │                        │  CBM resolution   │
 └──────────┬───────────┘                        └───────────────────┘
            │ registry facts
            ▼
     ContextPacket ──► JSON (sort_keys) │ Markdown brief
     pkt_<sha256:32>  data + provenance + warnings + diagnostics
```

## What the packet IS / is NOT

- It IS a **composition** of already-policy-filtered facts, with fixed
  structural limits. It is NOT a relevance engine.
- **No embeddings. No LLM ranking. Composition itself is budget-free.**
  Selection is:
  scope policy → type priority → (task mode only) a deterministic keyword
  filter (tokens of length ≥ 4, substring match on title+body) → guardrail
  caps. Same inputs always select the same items. Optional token budgets
  exist as a separate post-composition layer — see
  [Context Budget Accountant (R1F)](context-budget.md).
- It is NOT a graph walk. Code focus resolves ONE reference and its
  directly linked memories. No recursion, no full-file ingestion.

## Deterministic identity

`packet_id` = `pkt_` + first 32 hex of
`sha256("relinkra/context-packet/v1\0" + packet_version + project_id
+ workspace_id + mode + normalized task + normalized focus
+ sorted selected source ids)`.

- Source ids are `memory_id` / `code_reference_id` values, **sorted**, so
  selection order never changes identity.
- `created_at`, warnings, and diagnostics are NOT part of identity.
- Identical inputs + identical selected sources ⇒ identical `packet_id`,
  across machines and across runs.

## Modes and precedence

`symbol` > `file` > `task` > `workspace` > `project`

| mode | input | focus |
|---|---|---|
| project | `--project-id` only | baseline shared context |
| workspace | `+ --workspace-id` | + workspace channel memories |
| task | `+ --task text` | + keyword filter on non-baseline types |
| file | `--file src/x.py` | + file resolution, linked memories |
| symbol | `--symbol qn` (or CodeReference JSON) | + symbol resolution, bounded snippet |

## What is included

- **Identity**: `project_id`, optional `workspace_id`, repository identity,
  workspace/branch/HEAD/CBM metadata from the R1B Registry when available.

### Portable vs local paths

Portable packet output (JSON `project_facts`, Markdown) never contains
absolute machine infrastructure paths. An ABSOLUTE CBM cache dir (Windows
drive/UNC or POSIX `/...`) is dropped from
`project_facts.workspace.cbm_cache_dir` (a relative value, if ever
recorded, is kept; `cbm_project_name` and the rest of the workspace
metadata always survive). The absolute value is exposed ONLY under
`diagnostics["local"].cbm_cache_dir` — a machine-local diagnostic
channel that must NOT be shipped as portable context. Markdown never
renders diagnostics, so `diagnostics["local"]` can never leak into a
brief.
- **Baseline active memories**: handoff, pending, constraint, decision,
  architecture first; then bug, discovery, verification, task_result —
  ordered by that type priority, then timestamp desc, then `memory_id` asc.
- **Pending and handoff are first-class sections**, active only.
- **Code focus** (file/symbol modes): the focused reference with its R1D
  resolution state, minimal CBM facts, directly linked active memories,
  and an optional bounded snippet for an exactly resolved symbol.

## What is excluded

- Superseded, obsolete, and history memories. Always.
- Other workspaces' workspace-local memories; other agents' private
  memories (`agent_private` is read ONLY with `--include-agent-private`
  AND a matching `--requesting-agent`).
- Anything beyond the guardrails (reported, not silent).
- Recursive CBM graph walks, full file contents, SQLite row ids.

## Guardrails (structural limits, NOT token budgets)

| limit | default |
|---|---|
| max_memories | 12 |
| max_code_refs | 8 |
| max_snippets | 2 |
| max_snippet_chars | 1200 |
| max_pending | 5 |
| max_handoffs | 3 |
| max_warnings | 10 |

Omitted and truncated counts are reported in `diagnostics.omitted` /
`diagnostics.truncated_snippets` and surfaced as `items_omitted` /
`content_truncated` warnings. When `max_warnings` is exceeded, ordinary
warnings are truncated first: `items_omitted` / `content_truncated`
warnings are appended after truncation with deterministic priority and
are never silently dropped.

## Warnings vs fatal

Prefer a **partial packet with warnings** over no packet:

- `stale_code_reference`, `missing_code_reference`,
  `ambiguous_code_reference`
- `cbm_unavailable` (no adapter configured, or a configured adapter
  that FAILED — an outage is never reported as `missing_code_reference`),
  `engram_unavailable`
- `workspace_mismatch`, `workspace_not_registered`
- `items_omitted`, `content_truncated`

Fatal (`ContextBuildError`, no packet) only for invalid input
(malformed ids, absolute file paths) or project mismatch (unknown project,
workspace/symbol ref bound to a different project).

## CLI

```
python -m relinkra.context_cli --project-id rlk_... \
    [--workspace-id ws_...] [--task "..."] [--file src/x.py] [--symbol qn] \
    [--registry .relinkra/registry.json] [--engram-bin engram] \
    [--engram-project-alias relinkra] \
    [--cbm-bin codebase-memory-mcp] [--cbm-cache-dir D] [--cbm-project-name S] \
    [--workspace-root R] [--requesting-agent opencode] [--include-agent-private] \
    [--format json|markdown] [--pretty]
```

JSON (or Markdown) goes to stdout only; errors are redacted JSON on stderr
with exit 1 (invalid input) or 2 (project mismatch).

### Examples

```
# baseline project packet
python -m relinkra.context_cli --project-id rlk_... --pretty

# task-focused packet
python -m relinkra.context_cli --project-id rlk_... --task "fix the parser"

# symbol-focused packet with live CBM resolution
python -m relinkra.context_cli --project-id rlk_... --symbol src.calc.add \
    --cbm-bin codebase-memory-mcp --cbm-project-name <slug> \
    --workspace-root . --format markdown
```

## Engram project alias

Some MCP front-ends (observed: OpenCode) reject unknown `rlk_` Engram
projects during R1C/R1D live proofs. `EngramCLIAdapter(project_alias=...)`
rewrites ONLY the physical project filter of store *queries* (HTTP and CLI
read paths) to the alias (e.g. `relinkra`). Writes are unaffected, and
isolation is preserved: the R1C `MemoryService` always re-filters parsed
envelopes by the logical `project_id`, so an aliased search can never leak
another project's memories into a result.
