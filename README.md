# Relinkra

**Potente por dentro. Simple por fuera.**

Relinkra is an orchestration and context layer for AI coding agents. It
gives every connected agent one shared project route — stable project
identity, persistent memory, cross-agent handoffs, read-only Git facts, an
optional code graph, and bounded context packets — through a single MCP
server, while the agent stays in control of search, reasoning, editing,
and validation.

> Relinkra optimiza el camino hacia la información; no restringe la
> capacidad del agente de buscar, razonar, editar o validar por sí mismo.

## Why Relinkra

Every agent session starts by rediscovering the same project facts. With
several agents — or several sessions of one agent — that rediscovery
repeats and the agents drift apart.

- **Reduces rediscovery.** Project identity, prior decisions, active
  handoffs, and code-graph facts are resolved once and served to every
  connected agent.
- **Improves continuity.** Deterministic memory and cross-agent handoffs
  let a fresh session — or a different agent — pick up where the last one
  stopped.
- **Improves useful information per token.** Context packets are
  salience-ranked and budgeted; token optimization removes redundancy,
  never evidence.

Three principles run through everything:

- **Relinkra-first.** The shared route is the normal path to project
  context.
- **Source-authoritative.** Current source always wins; Relinkra evidence
  is advisory.
- **Expand-on-demand.** Start with the short answer; every read exposes
  where to dig deeper.

Relinkra never disables native file access, search, or source inspection,
and never requires Relinkra-only reasoning. There is no universal or
quantitative token-saving guarantee; local or simple tasks can carry
overhead (see [Performance and scope](#performance-and-scope)).

## Release status

Relinkra **0.1.4** is the current stable release. Install it with
`pip install relinkra`; maintainers and testers can also exercise it from
a source checkout (see [Contributing](CONTRIBUTING.md)).

Requirements: Python 3.9 or newer and Git. Zero runtime dependencies.
Released under the [MIT License](LICENSE). The project is hosted at
[github.com/jojusa/relinkra](https://github.com/jojusa/relinkra).

## Level A — Quick start

Six commands take a project from zero to connected and verified:

```bash
pip install relinkra

cd my-project
relinkra init          # register this workspace (idempotent)
relinkra cbm setup     # optional: install the code-graph backend
relinkra cbm index     # build the code graph
relinkra connect all   # connect every supported agent host
relinkra doctor        # confirm everything is healthy
```

What each step gives you:

1. **`relinkra init`** detects the repository, resolves a stable logical
   project identity (`rlk_...` / `ws_...`), and writes local state under
   `.relinkra/`. It is per workspace and safe to run again.
2. **`relinkra cbm setup` and `relinkra cbm index`** install the optional
   Codebase Memory (CBM) backend and build the structural code graph your
   agents query for architecture orientation and caller/dependency
   relationships. Skip them if you do not want the code graph — memory,
   handoffs, and context packets still work.
3. **`relinkra connect all`** walks every supported host (`codex`,
   `opencode`, `claude`, `devin-desktop`, `zcode`) through its own
   inspect → plan → confirm → apply pipeline, with per-host backup and
   rollback. Already-valid hosts are safe no-ops; every write asks first.
4. **Restart each configured host**, then **`relinkra doctor`** answers:
   is Relinkra healthy, which agents are configured, which were actually
   observed running, what is still pending, and what to do next.

Connecting one agent instead of all of them:

```bash
relinkra connect codex
```

The normal front door inspects and plans first, asks for confirmation
before a write, and then uses the existing backup, validation, rollback,
and restart guidance. If a write is required, Relinkra:

- shows the planned change;
- asks for confirmation;
- creates a backup;
- preserves unrelated configuration;
- validates the result;
- keeps rollback available;
- tells you when the host must be restarted or reloaded.

If the registration is already valid for the workspace it is a verified
no-op. Configuration presence is never proof that the host launched
Relinkra.

After connecting, just use your agent. It can call the Relinkra MCP tools
(`project_resolve`, `context_get`, `memory_save`, `memory_search`,
`memory_get`, `handoff_create`, `handoff_get`, `code_resolve`,
`code_architecture`, `code_relationships`, `git_context`, `health`) to
share memory, hand work across agents, and fetch bounded, budgeted project
context. See [Memory, handoffs, and context surfaces](#memory-handoffs-and-context-surfaces).

## Level B — Advanced and safe control

When you need to inspect or control one stage, the same pipeline is
available step by step:

```bash
relinkra connect list
relinkra connect inspect <agent>
relinkra connect check <agent>
relinkra connect plan <agent> --dry-run
relinkra connect apply <agent>
relinkra connect rollback <agent>
relinkra connect verify <agent> --proof <proof-file>
```

`inspect`, `check`, and `plan` are read-only. `apply` writes only after
the existing safety gates; restart the host, then run `check` and
`verify`. `relinkra connect rollback <agent>` restores a supported backup.
The `relinkra connect generic` route is available for generic
configuration work; `devin-cloud` is unsupported.

Configuration verification and host-side proof are separate:

```bash
relinkra connect check <agent>
relinkra connect verify <agent> --proof <proof-file>
```

`check` verifies the configuration. After the host is restarted or
reloaded, `verify` records proof that the real host launched Relinkra.

## What Relinkra provides

- **Orchestration and context:** a shared project route for code references,
  memory, handoffs, Git facts, and bounded context packets.
- **CBM integration:** optional structural code intelligence, such as graph
  indexing and bounded relationships, behind Relinkra's MCP server.
- **Host configuration:** inspect, plan, apply, rollback, and verify supported
  agent-host configuration without replacing the host's native tools.
- **Honest degradation:** missing CBM or Engram is reported as unavailable or
  optional; the core workflow remains usable.

Relinkra does **not** replace an agent's native file search, reasoning, editing,
testing, or validation. It does not make stale context authoritative, require
CBM or Engram for every task, or register CBM directly with an agent.

## Agent hosts

The following connector IDs have configuration support. Every one is
**experimental**: configuration and format support are distinct from proof
that the real host launches Relinkra end to end.

| Connector | Configuration target | Reload after `connect apply` |
|---|---|---|
| `codex` | Global user `~/.codex/config.toml` | Restart the Codex CLI. |
| `opencode` | User `~/.config/opencode/opencode.json`; JSONC and workspace alternatives may also be recognized. | Restart OpenCode. |
| `claude` | User `~/.claude.json`, project-scoped under `projects[<project>].mcpServers`. | Restart Claude, then run `/mcp`. |
| `zcode` | Workspace-local `.zcode/config.json`. | Restart ZCode. |
| `devin-desktop` | User `%APPDATA%/Devin/mcp_config.json`; workspace-local files are also recognized. | Reload the Cascade/MCP panel. |

For any host, inspect before changing it and verify after restarting:

```bash
relinkra connect inspect <agent>
relinkra connect check <agent>
relinkra connect verify <agent> --proof <proof-file>
```

## Multiagent onboarding and routing

### Connect all

`relinkra connect all` walks every default target — `codex`, `opencode`,
`claude`, `devin-desktop`, `zcode` — through its OWN per-agent pipeline:
inspect, check, plan, preflight, confirmation, apply, and restart guidance.
It is a driver over the per-agent safety, never a weaker batch path:

- already-valid hosts are safe no-ops;
- every write asks per host (`apply?`); declining one host writes nothing
  for it and does not affect the others;
- a refused or malformed host fails closed and is reported, without
  marking the others successful;
- each apply owns its own backup and rollback; there is no cross-host
  rollback;
- non-interactive runs (nobody to answer the confirmation) decline every
  write; there is deliberately no consent flag that bypasses the
  per-host confirmation.

The summary table reports each host's config state, workspace match,
runtime evidence, and outcome. Repeating `connect all` is idempotent.

### Compact check

`relinkra connect check <agent>` is concise and host-local by default:

```
Codex CLI
✓ Config valid
✓ Workspace matches
○ Runtime pending

Next: start/restart Codex CLI
```

Use `--verbose` for the full report (findings, persisted verification
evidence, and the per-host sections). The JSON payload always carries the
full detail.

### Inspect workspace match

`relinkra connect inspect <agent>` exposes `workspace_matches`
(`true`, `false`, or unknown) directly, so you do not need inspect plus
check to learn whether a registration points at the current workspace.

### Host runtime states

Runtime evidence is displayed with honest categories: `attested` (an
operator-recorded proof), `observed` (self-observed on the current
revision), `stale` (explicitly historical), `unknown` (evidence exists
but the current revision could not be read to classify it), and
`pending` (nothing observed yet). Self-observed evidence is never
displayed as externally attested, and one host's evidence is never
attributed to another host. When the current Git revision cannot be
read, the relation is `unknown`, never `stale`.

Evidence storage is one bounded file per host
(`.relinkra/runtime-evidence/<host>.json`), so concurrent hosts cannot
lose each other's evidence, and the pre-R6E single-file store remains
readable. No migration is required. Concurrent processes of the same
host serialize their writes with a bounded per-host lock; a writer that
cannot take the lock in time skips its record (conservative
under-reporting) rather than blocking MCP serving.

### ZCode generated state

`connect check zcode` and `connect inspect zcode` classify ZCode's
workspace-local generated state (`.zcode/config.json` and
`.zcode/config.json.lock`). When both files are git-ignored and Git is
clean, the state is reported as healthy (PASS) instead of a generic
warning. Only a real hygiene problem — generated state showing in Git
status — warns. Relinkra never deletes the lock file and never edits
`.gitignore`.

### Relinkra-first routing and Engram coexistence

`connect list` and `connect all` surface the routing guidance:

- **Order:** `project_resolve` → active handoff / `context_get` → memory
  if needed → CBM code relationships → native source/search as needed.
  Relinkra-first, source-authoritative, expand-on-demand; native tools
  are never blocked.
- **Engram:** use Relinkra first for normal project context and do not
  duplicate the same retrieval through direct Engram. Direct Engram
  remains fully available for Gentleman/SDD state, explicitly
  Engram-only workflows, and information Relinkra does not expose.

## Memory, handoffs, and context surfaces

These are the agent-facing surfaces served by the Relinkra MCP server.
Full contracts live in [the MCP surface](docs/mcp-surface.md), [memory
policy](docs/memory-policy.md), [handoff lifecycle](docs/handoff-lifecycle.md),
and [context budget](docs/context-budget.md).

**Deterministic memory.** `memory_search` returns results in a stable,
deterministic order (oldest first, `memory_id` tiebreak) — the same
query always returns the same results. `memory_get(memory_id)` fetches
exactly one record by id: a deterministic exact lookup with no fuzzy
fallback (`found=false` when absent). Same id, same record, every time.

**Handoffs and memory mirrors.** A handoff is mirrored into memory, and
duplicate handoffs on the same topic are deduplicated (superseding the
older record). Because the mirrors would bury real memories,
`memory_search` excludes handoff mirror records by default. To retrieve
handoffs:

- `handoff_get` — authoritative for handoff workflow state;
- `memory_get(memory_id)` — expand any handoff mirror id you already have;
- `memory_search(..., include_handoffs=true)` — opt back into mirrors;
- `memory_search(..., memory_type="handoff")` — mirrors auto-included.

**Code relationships include tests on demand.** `code_relationships`
excludes test code by default; pass `include_tests=true` when callers
living in test files matter.

**Bounded, honest context packets.** `context_get` composes the packet,
then ranks every item into salience tiers and applies a deterministic
reduction ladder under a token budget:

- `must_keep` items (identity, warnings, the current handoff, pending
  work) are never omitted; `optional` items (payload-heavy, redundant, or
  reconstructable metadata) are sacrificed first.
- Nothing disappears silently. The packet's `packet_status` block tells
  the agent the truth: `packet_complete` (or not), `budget_exhausted`,
  `omitted_sections`, `recommended_next` (deterministic recovery hints
  naming real MCP tools), and a conservative `context_sufficiency` that
  flags when code claims still require source verification.
- Snippet truncation is explicit (`snippet_truncated`, original and
  returned lengths, a continuation reference) and recorded in
  `truncated_source_ids`.
- Token accounting uses the `cpt1` estimation method and is reported
  with the packet, so an agent can see how its budget was spent. The
  reported figures are final-packet cpt1 tokens over the exact delivered
  serialization (an approximation, not an exact provider tokenizer
  count).
- When a budget cannot hold the must-keep skeleton, the error carries
  budget guidance (`minimum_useful_tokens`, `recommended_max_tokens`) —
  never a bare retry.

## Doctor: what healthy means

`relinkra doctor` is compact by default and reads like a status board:
core groups (Git, project identity, registered revision, CBM, Engram),
an agent table (config state vs runtime observation — never merged into
one column), and one suggested next action. It answers, without flags:

- Is Relinkra healthy? (`PASS` / `WARN` / `FAIL` / `PENDING` counts)
- Which agents are configured? (per-host config column)
- Which agents were actually observed? (per-host runtime column, from
  persisted evidence the MCP server records while serving)
- What is pending? (`PENDING` — not yet proven, not wrong)
- What is actually wrong? (`WARN` / `FAIL` with reasons)
- What should I do next? (one concrete next action)

`PENDING` and `WARN` are different judgments: `PENDING` means "no proof
yet", `WARN` means "a real condition worth attention". A missing optional
backend is `WARN`, never `FAIL`; `FAIL` is reserved for "this cannot
work" (no git, no repository, a corrupt registry). Use
`relinkra doctor --verbose` for the full per-check diagnostics; the
compact view is a projection of the same payload, never a second
opinion.

Doctor's runtime-evidence column is fed automatically: the MCP server
records self-observed evidence (server start, client handshake, tool
activity) to `.relinkra/runtime-evidence/<host>.json` while serving —
no manual proof file required. Self-observed evidence remains distinct
from the stronger external `connect verify` proof.

## Revision and generated-state hygiene

Relinkra keeps the registered workspace snapshot separate from live Git. In
MCP and context packet output, legacy `workspace.head_sha` means the
registered snapshot; use `registered_head_sha` for that value and
`current_revision` for the live checkout. `freshness`, `relation`, and
`revision_distance` explain whether they agree. If Git cannot be read, the
state is explicitly unknown/degraded.

`.zcode/config.json` is workspace-local host configuration. A
`.zcode/config.json.lock` is ZCode-owned generated state: Relinkra detects and
reports it but never deletes it. Relinkra does not silently edit `.gitignore`;
review Git ownership/ignore policy explicitly before committing workspace
state (see [ZCode generated state](#zcode-generated-state) for the
healthy/unhygienic classification). `.relinkra/`, `.codebase-memory/`, and
`*.relinkra-backup*` remain local state; runtime evidence lives under
`.relinkra/runtime-evidence/` and never dirties a linked worktree's Git
status. Engram remains an independent optional coexistence path.

## Project-local state

Relinkra state is intentionally local and should not be committed:

- `.relinkra/` contains opaque project/workspace IDs, version data, and a
  registry. The registry can contain machine-specific paths.
- `.codebase-memory/` contains optional CBM binaries, caches, and indexes.
- `*.relinkra-backup*` contains host-configuration safety backups.

These paths are gitignored. `relinkra init` does not stage, commit, or modify
Git history, and does not write agent configuration. Keep the generated state
private to the workspace; do not add it to a pull request.

## Optional backends

### Codebase Memory (CBM)

CBM is an external, optional structural code-intelligence backend. The
certified managed binary is Windows-amd64/Windows-focused. Linux and macOS
have CI coverage but no certified CBM binary; Relinkra reports that limitation
and continues without CBM.

The lifecycle is:

```bash
relinkra cbm setup
relinkra cbm status
relinkra cbm index
relinkra cbm refresh
relinkra cbm open
```

`setup` also accepts `--from-file PATH` and `--json`; `index` and `refresh`
accept `--path`, `--json`, and `--mode fast`.

`open` starts the Relinkra-owned viewer for this workspace:

- **Loopback-only.** It binds `127.0.0.1` and nothing else; there is no
  `--host` option.
- **Read-only and local-only.** It serves a static shell, one JSON status
  route built from the same honest CBM facts as `cbm status`, and two bounded
  graph routes. The Graph tab searches symbols and files (default limit 20)
  and draws a bounded focal graph (depth 1; up to 20 inbound and 20 outbound
  relationships), marking test relationships only when CBM identifies them
  (`is_test` is never inferred). Node expansion is explicit and bounded: up to
  50 nodes initially and 100 after expansion, always reporting what was
  trimmed instead of dropping it silently. Coverage, truncation, and stale or
  missing-index indicators are shown, so a bounded graph result never claims
  to be complete. The Metrics tab shows bounded, local observations from
  final ContextPackets (CPT1 accounting and quality/composition signals).
  CPT1 is Relinkra's deterministic accounting metric, not provider/model
  billing tokens. Metrics are observability only: they do not claim model
  token usage or savings. The local store retains bounded counts, flags and
  accounting only — never prompts, memory bodies, source snippets, task text
  or handoff bodies — and records stay under `.relinkra/` rather than being
  sent to a host.
- **Bounded concurrency.** Routes that can launch CBM work (the status route
  and the two graph routes) share one small concurrency gate (at most 4
  expensive requests in flight). Under a burst, excess requests fail fast with
  a deterministic `429 viewer_busy` JSON response (`Retry-After: 1`) instead
  of piling up provider subprocesses; static assets and the metrics routes
  are unaffected. A request whose `Host` header names a non-loopback
  authority is refused (`400`) before any work. There is no authentication:
  the viewer is loopback-only and makes no public-server claim.
- **No automatic lifecycle.** Opening the viewer never indexes or refreshes;
  stale or missing indexes are reported with the exact command to run.
- **Options.** `--path`, `--port PORT` (default `0`: the OS picks a free
  port), `--no-open` (do not launch the default browser), and `--json`
  (print only the startup object: `host`, `port`, `url`). Stop it with
  Ctrl+C.

`status` distinguishes missing, ready, stale, unavailable, unsupported, and
unknown states, reporting index freshness as drift against the registered
revision (`STALE_COMMITTED`, `STALE_WORKTREE`, `STALE_BOTH`) with a next
action. A successful `cbm index` or `refresh` reports only reliable fields:
`nodes`, `edges`, the workspace `revision`, freshness drift flags, and
measured `elapsed_seconds`. CBM remains behind Relinkra; agents should not
install or register it directly. Upstream CBM's own web server is not used,
bundled, or documented as a supported surface.

See [CBM backend](docs/cbm-backend.md) for certified acquisition, cache
behavior, and limitations.

### Engram

Engram is an external, optional persisted-memory backend. Relinkra does not
remove or restrict Engram capabilities, and direct Engram can coexist when
another workflow requires it. For agent-neutral project memory and handoffs,
the normal route should be Relinkra. If Engram is absent, Relinkra reports
memory and handoffs as unavailable instead of pretending they are working.

## Performance and scope

Relinkra's value is meaningful in controlled, cross-module and context-heavy
benchmarks where repeated repository orientation is expensive. There is no
universal token-saving guarantee. Local or simple tasks can incur overhead
from initialization, health checks, or optional backend inspection. The next
validation step is Kisouma dogfood.

## Platform and release truth

- Version **0.1.4** is the current stable release.
- Windows is certified for the product. Linux and macOS have CI coverage, but
  exact-SHA/product certification language remains limited to the evidence
  available for each platform.
- CBM managed certification is Windows-focused; Linux/macOS degrade honestly.
- The connector hosts above are experimental; configuration support is not a
  claim of real-host launch certification.

## Learn more

- [Installation](docs/installation.md) — public install and first run.
- [Product CLI](docs/cli.md) — command behavior and exit codes.
- [Connectors](docs/connectors.md) — host configuration details.
- [CBM backend](docs/cbm-backend.md) — optional code-graph lifecycle.
- [MCP surface](docs/mcp-surface.md) — the agent-facing tool contract.
- [Context budget](docs/context-budget.md) — salience, truncation truth,
  and budget guidance.
- [Memory policy](docs/memory-policy.md) — what is remembered and how.
- [Handoff lifecycle](docs/handoff-lifecycle.md) — cross-agent handoffs.
- [Freshness and explainability](docs/freshness-explainability.md) — how
  Relinkra qualifies context and conflicts.
- [Release verification](docs/release.md) — maintainer evidence and
  certification boundaries.
- [Contributing](CONTRIBUTING.md) — maintainer-only source setup.
- [Security](SECURITY.md) — supported versions and vulnerability reporting.
