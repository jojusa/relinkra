# Install Relinkra

Relinkra gives coding agents an orchestration and context layer without
replacing their native tools. The current release-preparation candidate is
**0.1.4**; it is not yet published, and **0.1.2** remains the last public
package until publication.

## Quick path

Requirements: Python 3.9 or newer and Git.

```bash
pip install relinkra
```

From inside an existing Git repository with at least one commit, the normal
journey is:

```bash
relinkra version
relinkra init
relinkra cbm setup
relinkra cbm index
relinkra connect all
relinkra doctor
```

`cbm setup` and `cbm index` are optional (they build the code graph);
everything else works without them. To connect one agent instead of all of
them, replace `relinkra connect all` with a single front door such as
`relinkra connect codex`. Restart or reload each configured host, then use
configuration verification and host-side proof as separate steps:

```bash
relinkra connect check <agent>
relinkra connect verify <agent> --proof <proof-file>
```

`check` validates configuration. `verify` is for proof that the real host
launched Relinkra after its restart or reload.

## Requirements

| Requirement | Purpose |
|---|---|
| Python 3.9+ | Runs Relinkra. |
| Git | Required by `init` and workspace operations. |
| Engram | Optional external persisted memory and handoffs. |
| CBM | Optional external structural code intelligence. |

Relinkra has zero runtime dependencies. Missing optional backends are reported
honestly and do not prevent the core workflow from running.

## What `init` does

`relinkra init` is per repository/workspace. It requires a Git repository with
at least one commit and is safe to run again.

It writes only:

- `.relinkra/config.json` — opaque project/workspace IDs and version data.
- `.relinkra/registry.json` — the local registry, which may contain
  machine-specific paths.

Both files are under the gitignored `.relinkra/` directory. Re-running `init`
is idempotent: it preserves the existing identity when the repository is the
same and reports a changed identity when the directory now contains a
different repository.

`init` does not stage or commit files, modify Git history, write an agent-host
configuration, start a daemon, or configure CBM directly.

## Connect an agent

Relinkra can inspect, plan, apply, rollback, and check supported host
configuration:

```bash
relinkra connect inspect <agent>
relinkra connect check <agent>
relinkra connect plan <agent>
relinkra connect apply <agent>
relinkra connect rollback <agent>
```

All supported connector IDs are experimental. Configuration/format support is
not the same as real-host launch certification.

| Connector | Configuration target | Restart or reload |
|---|---|---|
| `codex` | Global user `~/.codex/config.toml` | Restart the Codex CLI. |
| `opencode` | User `~/.config/opencode/opencode.json`; JSONC and workspace alternatives may also be recognized. | Restart OpenCode. |
| `claude` | User `~/.claude.json`, project-scoped under `projects[<project>].mcpServers`. | Restart Claude, then run `/mcp`. |
| `zcode` | Workspace-local `.zcode/config.json`. | Restart ZCode. |
| `devin-desktop` | User `%APPDATA%/Devin/mcp_config.json`; workspace-local files are also recognized. | Reload the Cascade/MCP panel. |

`devin-cloud` is unsupported. `relinkra connect generic` is available for
generic configuration work.

## Optional CBM lifecycle

CBM is optional and stays behind Relinkra. Agents do not add CBM directly to
their configuration.

```bash
relinkra cbm setup
relinkra cbm status
relinkra cbm index
relinkra cbm refresh
```

`setup` accepts `--from-file PATH` and `--json`. `index` and `refresh` accept
`--path`, `--json`, and `--mode fast`.

The managed/certified CBM binary is Windows-amd64/Windows-focused. Linux and
macOS have CI coverage but no certified CBM binary; Relinkra reports the
limitation and continues without CBM. See [CBM backend](cbm-backend.md) for
trust, cache, and freshness details.

## Engram

Engram is an external, optional persisted-memory backend. Relinkra does not
remove Engram capabilities, and direct Engram can coexist when another
workflow requires it. Agent-neutral project memory and handoffs should
normally route through Relinkra. Without Engram, memory and handoffs report as
unavailable rather than being treated as silently successful.

## Maintainer-only source checkout

Most users should install from PyPI with `pip install relinkra`. A source
checkout is for Relinkra maintainers, contributors, and release verification
only:

```bash
git clone https://github.com/jojusa/relinkra.git
cd relinkra
python -m pip install -e .
```

Maintainers can also install a locally built wheel or sdist when verifying a
release artifact. Those paths are not the normal public installation route.
See [Contributing](../CONTRIBUTING.md) and [Release verification](release.md).

## Upgrade and uninstall

```bash
pip install --upgrade relinkra
pip uninstall relinkra
```

Uninstalling the package leaves project state and safety backups in place:

- `.relinkra/` — project identity, registry, and runtime evidence.
- `.codebase-memory/` — optional CBM binaries, caches, and indexes.
- `.zcode/config.json` and `.zcode/config.json.lock` — ZCode-owned
  workspace state.
- `*.relinkra-backup*` — host-configuration backups.

Remove them manually only when you intentionally want to discard local
state or backups.

### Git ignore policy, truthfully

Each path has a different owner and a different ignore story. Relinkra
never edits a tracked `.gitignore` and never deletes host-owned files:

| Path | Owner | Git state |
| --- | --- | --- |
| `.relinkra/` | Relinkra-managed local state | Ignored. Relinkra appends a `.relinkra/` rule to `.git/info/exclude` (repository-local, never committed, applies to every linked worktree) — and only if the tracked `.gitignore` does not already cover it. If that write could not happen, the directory shows as untracked (`?? .relinkra/`). |
| `.codebase-memory/` | Relinkra-managed derived CBM state (optional backend) | Not ignored automatically. `relinkra cbm index` warns while it is untracked and never edits `.gitignore`; add the rule yourself if you want it out of `git status`. |
| `.zcode/config.json`, `.zcode/config.json.lock` | ZCode-owned generated state | Depends on your ignore policy. `relinkra connect zcode` reports the real state — ignored, visible/untracked, or tracked unexpectedly — without changing anything. |
| `*.relinkra-backup*` | Your host-config backups, written by `connect apply` | Not ignored automatically, and they live next to your host's config files (often outside any repository). Delete them once you are satisfied, or add your own ignore rule. |

A dirty `git status` is only attributed to Relinkra or ZCode when the
dirty paths are actually local state owned by one of them; unrelated
changes are never reported as theirs.

## Next step

For command behavior and exit codes, see [Product CLI](cli.md). For host
configuration details, see [Connectors](connectors.md).
