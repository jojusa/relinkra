# Relinkra

**Potente por dentro. Simple por fuera.**

Relinkra is an orchestration and context layer for AI coding agents. It
optimizes the path to project information while leaving the agent in control
of search, reasoning, editing, and validation.

> Relinkra optimiza el camino hacia la información; no restringe la capacidad del agente de buscar, razonar, editar o validar por sí mismo.

## Start here

This checkout is the 0.1.3 release-preparation candidate. It is not yet
published; the last public PyPI package is 0.1.2. Use the normal install path
for the published package, or the maintainer source checkout when exercising
this candidate.

### 1. Install

Requirements: Python 3.9 or newer and Git.

```bash
pip install relinkra
```

Relinkra has zero runtime dependencies and is released under the [MIT
License](LICENSE). The project is hosted at
[github.com/jojusa/relinkra](https://github.com/jojusa/relinkra).

### 2. Add Relinkra to a project

Run this inside an existing Git repository with at least one commit:

```bash
relinkra version
relinkra init
relinkra status
```

`init` is per repository/workspace and idempotent. It writes
`.relinkra/config.json` and `.relinkra/registry.json`, then reuses that local
identity on later commands.

### Level A — Quick Start: connect one agent (0.1.3 release-preparation candidate)

Replace `<agent>` with `codex`, `opencode`, `zcode`, `claude`, or
`devin-desktop`:

```bash
relinkra doctor
relinkra connect codex
```

The normal front door performs inspection and planning, asks for confirmation
before a write, and then uses the existing backup, validation, rollback, and
restart guidance. If the registration is already valid for the workspace it
is a verified no-op. Configuration presence is never proof that the host
launched Relinkra.

Supported front-door targets are `codex`, `opencode`, `claude`,
`devin-desktop`, and `zcode`. To connect every supported host in one
command, use `relinkra connect all` (see [Multiagent onboarding and
routing](#multiagent-onboarding-and-routing-r6e) below). This front door
is part of the 0.1.3 release-preparation candidate and is not yet
published. The last public 0.1.2 package does not expose it; use a source
checkout to exercise this candidate.

### Level B — Safe Advanced Connector Workflow (last-published 0.1.2)

Use these last-published 0.1.2 advanced commands when you need to inspect or
control one stage:

```bash
relinkra connect list
relinkra connect inspect <agent>
relinkra connect check <agent>
relinkra connect plan <agent> --dry-run
relinkra connect apply <agent>
relinkra connect rollback <agent>
relinkra connect verify <agent> --proof <proof-file>
```

`inspect`, `check`, and `plan` are read-only. `apply` writes only after the
existing safety gates; restart the host, then run `check` and `verify`.

### 4. Build the optional code graph

Codebase Memory (CBM) is optional. Relinkra owns the normal route; agents do
not add CBM directly to their configuration.

```bash
relinkra cbm setup
relinkra cbm status
relinkra cbm index
```

Use `relinkra cbm refresh` after the index becomes stale. `setup` also accepts
`--from-file PATH` and `--json`; `index` and `refresh` accept `--path`,
`--json`, and `--mode fast`.

### 5. Verify

Configuration verification and host-side proof are separate:

```bash
relinkra connect check <agent>
relinkra connect verify <agent> --proof <proof-file>
```

`check` verifies the configuration. After the host is restarted or reloaded,
`verify` records proof that the real host launched Relinkra.

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

The following connector IDs have configuration support in the 0.1.3
release-preparation candidate. Every one is **experimental**: configuration
and format support are distinct from proof that the real host launches Relinkra
end to end.

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

`relinkra connect rollback <agent>` restores a supported backup. The
`relinkra connect generic` route is available for generic configuration work.
`devin-cloud` is unsupported.

## Multiagent onboarding and routing (R6E)

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
readable. No migration is required.

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
state (see [ZCode generated state](#zcode-generated-state) for the R6E
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
```

`status` distinguishes missing, ready, stale, unavailable, unsupported, and
unknown states. CBM remains behind Relinkra; agents should not install or
register it directly.

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

## Relinkra 0.1.3 release-preparation candidate

The 0.1.3 changes described here are in the release-preparation candidate and
are not a claim that 0.1.3 has been published. The CBM lifecycle is `relinkra cbm setup`,
`relinkra cbm index`, `relinkra cbm status`, and `relinkra cbm refresh`; stale
registration guidance uses the real route `relinkra cbm index`.

## Platform and release truth

- Version **0.1.3** is the release-preparation candidate; 0.1.2 remains the
  last public PyPI release until publication.
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
- [Freshness and explainability](docs/freshness-explainability.md) — how
  Relinkra qualifies context and conflicts.
- [Release verification](docs/release.md) — maintainer evidence and
  certification boundaries.
- [Contributing](CONTRIBUTING.md) — maintainer-only source setup.
- [Security](SECURITY.md) — supported versions and vulnerability reporting.
