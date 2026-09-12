# Relinkra

**Potente por dentro. Simple por fuera.**

Relinkra is an orchestration and context layer for AI coding agents. It
optimizes the path to project information while leaving the agent in control
of search, reasoning, editing, and validation.

> Relinkra optimiza el camino hacia la información; no restringe la capacidad del agente de buscar, razonar, editar o validar por sí mismo.

## Start here

**Current stable release: 0.1.3 — available on PyPI.**

The normal installation path is:

```bash
pip install relinkra
```

If you already have Relinkra installed:

```bash
pip install --upgrade relinkra
```

### 1. Install

Requirements: Python 3.9 or newer and Git.

```bash
pip install relinkra
```

Relinkra has zero runtime dependencies and is released under the [MIT
License](LICENSE). The project is hosted at
[github.com/jojusa/relinkra](https://github.com/jojusa/relinkra).

### 2. Add Relinkra to a project

Run Relinkra inside an existing Git repository with at least one commit:

```bash
cd my-project

relinkra version
relinkra init
relinkra status
```

`relinkra init` is per repository/workspace and idempotent. It creates the local Relinkra project/workspace identity and reuses it on later commands.

Relinkra writes local state under:

- `.relinkra/config.json`
- `.relinkra/registry.json`

These files are local workspace state and should not be committed.

### Level A — Quick Start: connect one agent

Replace `<agent>` with `codex`, `opencode`, `claude`, `devin-desktop`, or `zcode`.

```bash
relinkra connect codex
relinkra doctor
```

The normal front door safely inspects the existing host configuration, validates the workspace binding, and checks the required safety conditions before deciding whether any change is needed.

If a write is required, Relinkra:

- shows the planned change;
- asks for confirmation;
- creates a backup;
- preserves unrelated configuration;
- validates the result;
- keeps rollback available;
- tells you when the host must be restarted or reloaded.

If the agent is already correctly connected to this workspace, the command completes as a safe no-op.

Configuration presence is never treated as proof that the real host has launched Relinkra. After restarting or reloading the agent, use the verification workflow described below when you need host-side proof.

Supported front-door targets are:

- `codex`
- `opencode`
- `claude`
- `devin-desktop`
- `zcode`

There is currently no `relinkra connect all`; connect each agent individually.

### Level B — Safe Advanced Connector Workflow

Use the advanced connector commands when you need to inspect or control each stage explicitly:

```bash
relinkra connect list
relinkra connect inspect <agent>
relinkra connect check <agent>
relinkra connect plan <agent> --dry-run
relinkra connect apply <agent>
relinkra connect rollback <agent>
relinkra connect verify <agent> --proof <proof-file>
```

`inspect`, `check`, and `plan` are read-only.

`apply` uses Relinkra's safety gates, backup, validation, concurrency protection, and rollback mechanisms before modifying supported host configuration.

After applying a configuration change, restart or reload the host when requested, then use:

```bash
relinkra connect check <agent>
relinkra connect verify <agent> --proof <proof-file>
```

Configuration presence is not treated as proof that the real host launched Relinkra.

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

Relinkra 0.1.3 provides experimental configuration support for the following agent hosts.

Configuration support is distinct from proof that the real host launched Relinkra end to end.

| Connector | Configuration target | Reload after configuration |
|---|---|---|
| `codex` | Global user `~/.codex/config.toml` | Restart the Codex CLI. |
| `opencode` | User `~/.config/opencode/opencode.json`; JSONC and workspace alternatives may also be recognized. | Restart OpenCode. |
| `claude` | User `~/.claude.json`, project-scoped under `projects[<project>].mcpServers`. | Restart Claude, then run `/mcp`. |
| `zcode` | Workspace-local `.zcode/config.json`. | Restart ZCode. |
| `devin-desktop` | User `%APPDATA%/Devin/mcp_config.json`; workspace-local files are also recognized. | Reload the Cascade/MCP panel. |

For normal setup, use the simplified front door:

```bash
relinkra connect <agent>
```

For advanced inspection and verification:

```bash
relinkra connect inspect <agent>
relinkra connect check <agent>
relinkra connect verify <agent> --proof <proof-file>
```

`relinkra connect rollback <agent>` restores a supported Relinkra backup when available.

The `relinkra connect generic` route is available for generic configuration work.

`devin-cloud` is unsupported.

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
state. `.relinkra/`, `.codebase-memory/`, and `*.relinkra-backup*` remain local
state. Engram remains an independent optional coexistence path.

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

## Platform and release truth

- Version **0.1.3** is the current stable public release on PyPI.
- Install with `pip install relinkra`.
- Upgrade with `pip install --upgrade relinkra`.
- Windows is the currently certified product environment.
- Linux and macOS are covered by CI, while platform-specific certification remains limited to the evidence available for each environment.
- Managed CBM binary certification is Windows-focused; Linux and macOS degrade honestly when a certified CBM backend is unavailable.
- Agent-host connectors are experimental: configuration support is not the same as real-host launch certification.
- Relinkra does not claim universal token savings; production dogfooding is used to validate value on real projects.

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
