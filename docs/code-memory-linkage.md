# Code ↔ Memory Linkage (R1D)

Relinkra links logical memories (R1C) to code symbols through a portable
`CodeReference` identity, resolved lazily against CBM (codebase-memory-mcp).

```
        save --code-ref                query --code-file/--code-symbol
                │                                   │
                ▼                                   ▼
┌──────────────────────────────┐   code→memory   ┌──────────────────────┐
│ Memory (rlkmem1 envelope)    │ ◄────────────── │ LinkageService       │
│   code_refs: [CodeReference] │ ──────────────► │  memory→code + state │
└──────────────────────────────┘   resolution    └──────────┬───────────┘
                │ code_reference_id (content hash)          │
                ▼                                           ▼
┌──────────────────────────────┐                ┌──────────────────────┐
│ CodeReference (portable id)  │                │ CBMCLIAdapter        │
│  project_id rlk_ + kind +    │                │  subprocess argv list│
│  repo-relative POSIX path +  │                │  CBM_CACHE_DIR env   │
│  project-relative qn         │                │  no shell / timeout  │
└──────────────────────────────┘                └──────────┬───────────┘
                                                           │ cli search_graph /
                                                           │ cli get_code_snippet
                                                           ▼
                                              ┌──────────────────────┐
                                              │ codebase-memory-mcp  │
                                              │ (path-derived graph, │
                                              │  workspace-local)    │
                                              └──────────────────────┘
```

## Identity model (non-negotiable statements)

- **CBM node identity is NOT Relinkra identity.** CBM `qualified_name`
  embeds the path-derived project slug (e.g.
  `C-Desarrollos-relinkra-.relinkra-r1a-fixture-a.src.calculator.add`).
  Relinkra stores only the project-relative semantic qn
  (`src.calculator.add`); the slug is kept as `cbm_project_name`,
  workspace-local resolution metadata.
- **Different CBM project names can map to the same Relinkra ref.**
  Two workspaces (fixtures A/B) indexing the same repo under different
  slugs produce the SAME `code_reference_id` for the same repo-relative
  file/symbol.
- **An absolute path is not portable identity.** `file_path` is always
  repo-relative POSIX. Absolute paths, drive letters, UNC, `..`
  traversal, control chars, and URL/scp-like values are rejected. CBM
  `get_code_snippet` may return an absolute `file_path`; the adapter
  normalizes it against `workspace_root` before validation.
- **Line numbers are metadata, never identity.** `start_line`/`end_line`
  (and `commit_sha`) are excluded from `code_reference_id`; drift
  between the stored hint and the live index yields the `stale` state.
- **Historical refs survive symbol deletion.** Resolution never rewrites
  a stored reference. A deleted symbol resolves to `missing` with the
  historical ref preserved verbatim.
- **Never SQLite row ids.** `code_reference_id` is
  `ref_` + first 32 hex of `sha256("relinkra/code-ref/v1\0" + project_id
  + "\0" + reference_kind + "\0" + file_path + "\0" + qualified_name)`.
  (Fields are `\0`-separated to prevent field-boundary ambiguity.)
- **CBM has no language field.** `language` is derived from the file
  extension at construction time.

## CodeReference

| field | role | in identity? |
|---|---|---|
| `project_id` (`rlk_`) | logical project binding (R1B) | yes |
| `reference_kind` | `file` \| `symbol` | yes |
| `file_path` | repo-relative POSIX path | yes |
| `qualified_name` | project-relative semantic qn (no CBM slug) | yes |
| `symbol_name`, `symbol_kind` | display/label metadata | no |
| `language` | derived from extension | no |
| `start_line`/`end_line` | drift-detecting metadata | no |
| `workspace_id` (`ws_`) | provenance | no |
| `cbm_project_name` | workspace-local CBM slug | no |
| `commit_sha` | provenance | no |
| `repository_identity` | R1B identity mapping | no |

File refs require only `file_path`; symbol refs require `symbol_name`
and/or `qualified_name`.

## Memory integration

`Memory.code_refs` is a list of validated CodeReference dicts, stored in
the `rlkmem1` envelope. Pre-R1D envelopes parse with `code_refs == []`.
Refs must match the memory's `project_id`. Save/query/supersede/dedup
semantics are unchanged; refs do not participate in the dedup key, and
supersede carries refs over unless replaced explicitly.

## Resolution states

`LinkageService.resolve_reference` returns a typed result:

- `resolved` — exact (`cbm_project_name + "." + qualified_name`) or
  unique-search candidate, metadata consistent with the stored hint.
- `ambiguous` — multiple live candidates (e.g. short name `process`
  matching `module_a.process` and `module_b.process`). All candidates
  are returned; the service NEVER silently chooses.
- `missing` — no live candidate. The historical ref is preserved.
- `stale` — a candidate resolved but file/line metadata drifted from
  the stored hint. The stored ref is still not rewritten.

Without a CBM adapter, refs report `missing` with an explanatory note.

## Queries

- **memory → code**: `memory_to_code(project_id, memory_id)` returns the
  memory plus each stored ref with its resolution state.
- **code → memory**: `code_to_memory(project_id, reference=... |
  file_path=... | symbol=..., scope, workspace_id, agent_type,
  include_history)` returns active memories directly linked to the
  target, enforcing the R1C scope/workspace/agent_private/lifecycle
  policy. Superseded/obsolete memories are excluded by default.
  File-only links are supported.

CLI:

```
python -m relinkra.memory_cli save ... --code-ref '{"project_id":"rlk_...","reference_kind":"symbol","file_path":"src/calculator.py","symbol_name":"add","qualified_name":"src.calculator.add"}'
python -m relinkra.memory_cli query --project-id rlk_... --code-file src/calculator.py
python -m relinkra.memory_cli query --project-id rlk_... --code-symbol add
```

## CBM adapter boundaries

`CBMCLIAdapter` is a minimal external CLI adapter: explicit binary path,
`CBM_CACHE_DIR` via env, argv list (no shell), UTF-8, timeout, tolerant
JSON parsing (CBM emits `level=info ...` log lines). It consumes only
stable external symbol fields (`label`, `name`, `qualified_name`,
`file_path`, `start_line`/`end_line`). No graph mutation, no direct
SQLite, no Cypher reimplementation. Source contents returned by
`get_code_snippet` are discarded and never persisted.

## Security

Refs cannot persist credentialed repo URLs (userinfo rejected at both
the path and repository-identity layers), absolute/secret paths,
traversal, env secrets (symbol fields pass through the R1C redactor),
raw CBM cache paths (absolute → rejected), or source contents.
Separators normalize cross-platform (`\` → `/`) before hashing.
