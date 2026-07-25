# Relinkra Shared Memory Policy (R1C)

R1C layers a **logical shared-memory policy** on top of a single physical
Engram database. OpenCode (`engram mcp --tools=agent` + HTTP :7437) and
Codex (`engram mcp`) already share that backend; Relinkra adds the rules
that decide *who sees what* — without creating a second memory DB and
without touching global agent configuration.

## BACKEND SHARED != EVERY MEMORY SHARED

Sharing one physical database does **not** mean every memory is visible to
everyone. The backend is a warehouse; the policy is the set of keys. A
memory only becomes visible to a caller when the caller's query scope
matches the memory's scope channel:

```
                    ONE physical Engram DB
   (shared by OpenCode via MCP+HTTP :7437 and Codex via MCP)
                              |
        Relinkra R1C policy layer (relinkra.memory.MemoryService)
                              |
   +--------------------------+-----------------------------+
   |                          |                             |
 project_shared          workspace_local              agent_private
 channel: "shared"       channel: "ws/<ws_id>"        channel: "agent/<type>"
   |                          |                             |
 visible to ANY query    visible to workspace         visible ONLY to
 in the same project     queries from THAT ws_<id>    queries with the SAME
                         (plus everything shared)     agent_type (never shared,
                                                      never other agents)
```

Isolation is **policy-enforced, not physical**. There are no separate
Engram namespaces per scope; separation comes from the scope channel
encoded in every memory's `topic_key` and content envelope, checked on
every query. Cross-project leakage is prevented structurally: every query
requires a `project_id` (`rlk_…`) and results are filtered to it.

## Logical model vs storage

The logical model (`relinkra/memory.py`) is independent of storage
(`relinkra/engram_adapter.py`).

**Memory types** (logical) map conservatively onto Engram storage types;
the relinkra `memory_type` is always preserved inside the envelope:

| logical      | Engram `type` |
| ------------ | ------------- |
| decision     | decision      |
| discovery    | discovery     |
| architecture | architecture  |
| bug          | bugfix        |
| constraint   | config        |
| task_result  | manual        |
| verification | manual        |
| pending      | manual        |
| handoff      | manual        |

**Memory fields**: `memory_id` (`mem_…`), `project_id` (`rlk_…`, R1B),
optional `workspace_id` (`ws_…`), `agent_id`, `agent_type`, `memory_type`,
`title`, `body`, `timestamp` (UTC), `repository_identity` (R1B record),
optional `branch`, optional `commit_sha`, `scope`, `status`
(`active|superseded|obsolete`), optional `confidence`, optional
`supersedes` / `superseded_by`, `source_tool`. Fields Engram cannot
represent natively live in the envelope — nothing is required that the
store cannot carry.

## Engram representation

| Engram field | Relinkra value |
| ------------ | -------------- |
| `project`    | the R1B `project_id` (`rlk_…`) — never a path/CBM name |
| `scope`      | always `project` |
| `type`       | mapped storage type (table above) |
| `topic_key`  | `relinkra/v1/{project_id}/{scope_channel}/{memory_type}/{slug}` |
| `title`      | human title (may carry a nonce for proofs) |
| `content`    | compact single-line JSON envelope (`"v":"rlkmem1"`, all fields) |

`scope_channel` is `shared`, `ws/{workspace_id}`, or `agent/{agent_type}`.

## Project binding

Every memory is bound to a valid R1B `rlk_` project id **and** a canonical
`repository_identity` (remote / explicit / local_root). Binding to a
filesystem path, CBM project name, branch, or HEAD SHA alone is rejected.
The CLI can resolve `project_id` / `workspace_id` / `repository_identity`
from the R1B Registry via `--path`; otherwise pass `--project-id` and
`--repository-identity` explicitly.

## Retrieval policy

- `project_shared` query → only the `shared` channel.
- `workspace_local` query (requires `workspace_id`) → `shared` + that
  workspace's `ws/<id>` channel.
- `agent_private` query (requires `agent_type`) → **only** that agent
  type's channel. Nothing else: not shared, not other agents.
- `project_id` is mandatory on every query; records from other projects
  are filtered out even if the store returns them.

## Lifecycle and supersession

History is never deleted. Saving an `active` memory whose `topic_key`
already has an active record automatically supersedes the prior one (the
new envelope carries `supersedes: <old memory_id>`). Default retrieval
returns only `active` records and excludes superseded ones; pass
`--include-history` to see everything (with `superseded_by` resolved).
`supersede` replaces a memory's content, or `--obsolete` writes a
tombstone that hides the whole topic by default.

Caveat: Engram treats `topic_key` as an upsert key for its own latest-
observation reuse. Relinkra does not rely on Engram's upsert semantics —
supersession is computed from envelopes at query time — but operators
should know the two mechanisms coexist.

## Deduplication

Deterministic and conservative — no embeddings, no LLM. Text is
normalized (lowercase, whitespace collapsed, punctuation stripped at the
edges) and the key is:

```
dedup_key = sha256(project_id + scope + memory_type
                   + normalized(title) + normalized(body))
```

computed over **redacted** text. On save, if an identical active memory
already exists in the same scope channel, the existing memory is returned
(`"deduplicated": true`) and nothing is written — **unless** an explicit
`supersedes` target was provided: explicit supersession always writes a
new record so the target is linked and excluded from default retrieval.
Limitations: only exact post-normalization duplicates are caught;
paraphrases, reordering, and semantic similarity are not.

## Redaction (defense in depth)

Before persistence, titles and bodies pass through `redact_text`:
bearer tokens, common API-key prefixes (`sk-…`, `sk_live_…`, `ghp_…`,
`github_pat_…`, `glpat-…`, `AKIA…`, `AIza…`, `xox?-…`, `hf_…`, JWTs),
passwords in URLs, PEM private-key blocks, and generic
`token=` / `api_key=` / `password=` key-values (reusing
`identity.redact_url` semantics for credentialed URLs). Error messages
never echo user content without redaction. This is **not perfect** — do
not put secrets in memories.

## Adapter

`MemoryStore` is a minimal protocol (`save_record` / `search_records`).
`EngramCLIAdapter` implements it against the shared Engram backend —
**no direct SQLite** — so both agents keep using the same physical DB.
`InMemoryStore` is a deterministic offline store for tests.

### Read path: HTTP first, CLI fallback (truncation resolved)

`engram search` truncates content display at ~300 chars with a trailing
`...`. A spec-compliant envelope is larger than that, so through the CLI
text output the truncated envelope cannot be parsed as JSON and is
skipped (counted in `skipped_malformed`). Resolution: reads try the
local **Engram HTTP API** first, an *optional read path on the same
physical backend*:

- Base URL: `ENGRAM_URL` env var, default `http://127.0.0.1:7437`
  (set `ENGRAM_URL=""` to disable HTTP entirely).
- `GET /search?q=<query>&project=<project>` returns a JSON array with
  **full untruncated `content`**; `GET /observations/{id}` returns a
  full record. Both are read-only and safe.
- Short timeout (2s). Any failure — server down, timeout, malformed
  payload — falls back transparently to the `engram search` CLI.
- `--type` filtering and the store page limit are applied client-side
  on HTTP results.

**Writes always go through the `engram save` CLI**; the CLI is also the
read fallback. Limitation: when the HTTP server is not running, the CLI
truncation caveat above still applies to full-fidelity retrieval (save,
project binding, and FTS discoverability are unaffected). Query paging
is fixed: the store is always asked for a page of 200 records and
channel/type/lifecycle filtering plus the user `--limit` are applied
afterwards, so filtering can never starve visible results.

All policy behavior is fully validated offline via mocked subprocess
and mocked `urllib`; no server is required for the normal test suite.

## CLI

```
python -m relinkra.memory_cli save \
    [--project-id rlk_... | --path PATH [--registry FILE]] \
    [--repository-identity VALUE] [--workspace-id ws_...] \
    --memory-type TYPE --title T --content C \
    [--scope project_shared|workspace_local|agent_private] \
    [--agent-id ID] [--agent-type TYPE] [--branch B] [--commit-sha SHA] \
    [--confidence 0.0-1.0] [--source-tool NAME]

python -m relinkra.memory_cli query --project-id rlk_... \
    [--scope SCOPE] [--workspace-id ws_...] [--agent-type TYPE] \
    [--text Q] [--memory-type TYPE] [--include-history] [--limit N]

python -m relinkra.memory_cli supersede MEMORY_ID --project-id rlk_... \
    [--title T] [--content C] | --obsolete
```

JSON output only. Exit codes: `0` ok, `1` validation/usage error, `2` not
found (unregistered path, unknown memory_id), `3` store failure. stderr
is redacted.

## Tests

```
python -m unittest discover -s tests -v
```

All unit tests are deterministic and offline (`InMemoryStore` + mocked
subprocess + mocked `urllib` for the HTTP read path — no server needed).
Real-Engram integration is marked separately and skipped by default; run
it with `RELINKRA_ENGRAM_INTEGRATION=1`.
