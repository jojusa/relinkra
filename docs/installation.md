# Install Relinkra

Relinkra is a Python package. Installing it gives you two commands —
`relinkra` (the operator front door) and `relinkra-mcp` (the endpoint
agents connect to) — that work from any directory, against any git
repository.

## Quick path

1. Check requirements: Python 3.9 or newer, and Git.
2. From a clone of this repository: `pip install .`
3. Inside your project's git repository: `relinkra init`
4. Confirm everything works: `relinkra doctor`
5. Connect your agent: `relinkra connect plan <host>` then
   `relinkra connect apply <host>`

## Requirements

| Requirement | Needed for |
|---|---|
| Python 3.9+ | Running Relinkra at all (`python --version` to check) |
| Git | `init`, `doctor`, and every workspace command |
| Engram (optional) | Persistent memory and handoffs; absent = honest degraded mode |
| CBM 0.9.0 (optional) | Code intelligence (symbol resolution); absent = honest degraded mode |

The core product runs on Python 3.9+. Codex TOML configuration management
(`connect` discovery/apply/rollback for Codex) additionally requires Python
3.11+, because that is when the standard-library `tomllib` parser became
available; on Python 3.9/3.10 Relinkra reports that connector capability as
unsupported rather than failing the rest of the product.

## Install

From a clone of the repository:

```
pip install .
```

For development on Relinkra itself, use an editable install so source
edits take effect immediately:

```
pip install -e .
```

Both commands install the same two entry points:

| Command | Purpose |
|---|---|
| `relinkra` | Operator CLI: `init`, `status`, `doctor`, `project`, `version`, `connect` |
| `relinkra-mcp` | The MCP server endpoint that agent hosts launch |

Check the install from any directory:

```
relinkra --version
relinkra version
```

`relinkra version` also reports the Python it runs on, the minimum
supported Python, and whether it is running from an installed package or
a source checkout.

Maintainers verifying a source checkout for release (rather than a
normal install) can additionally run the bounded release check —
`python tools/release_check.py --json` from the repository root — and
read the gate semantics in [Release verification](release.md).

## First run

Run this sequence inside your project's git repository:

1. `relinkra init` — detects the repository, resolves its logical project
   identity, and registers this workspace.
2. `relinkra doctor` — deep diagnostics. Fix anything marked FAIL;
   WARN entries are optional components you can enable later.
3. `relinkra connect check <host>` — see the current registration state
   for your agent host (`codex`, `claude`, `opencode`, `devin-desktop`).
4. `relinkra connect plan <host>` — preview exactly what would change.
   Read-only, writes nothing.
5. `relinkra connect apply <host>` — write the host configuration. A
   timestamped backup (`*.relinkra-backup*`) is created first.
6. `relinkra connect verify <host> --proof <file>` — record proof that
   the real host served Relinkra, then use the agent.

### What `init` does — and never does

`init` writes exactly two files, both under `.relinkra/` in the
repository: `config.json` (the pinned identity) and `registry.json`
(the local registry). That directory is gitignored.

It is **idempotent**: re-running preserves the project id, workspace id,
and the original initialization timestamp, and reports
"already initialized".

It **never** modifies git history, stages or commits anything, writes to
agent host configurations, or starts background processes.

## Optional components

### Codebase Memory (CBM)

CBM provides code intelligence (symbol-level resolution). It is optional:
without it, everything else works and `doctor` reports a WARN with an
explanation.

- **Certified version: 0.9.0** (supported range: 0.9.x, up to but not
  including 0.10.0).
- **Discovery order:** the `RELINKRA_CBM_BIN` environment variable, then
  a workspace-managed `.codebase-memory/bin/` directory, then `PATH`.
- **Platform note:** the certified binary currently ships for
  windows-amd64 only. On macOS and Linux this is a known limitation —
  `doctor` explains the state and everything else remains usable. See
  [Release verification](release.md) for what "certified" means and how
  CI and platform status are tracked.

### Engram

Engram provides persistent memory and handoffs. It is optional: Relinkra
works without it and says so honestly — memory read/write and handoffs
report as unavailable, and commands still exit 0. To enable full memory
read/write and handoffs, install Engram and make sure the `engram`
executable is on `PATH`. `ENGRAM_URL` may provide the HTTP read path, but
it does not replace the CLI write path.

## Upgrade and uninstall

| Task | Command / action |
|---|---|
| Upgrade | `pip install --upgrade .` from the updated clone (or reinstall) |
| Uninstall the package | `pip uninstall relinkra` |
| Remove project state | Delete `.relinkra/` inside the repository |
| Remove host-config backups | Delete the `*.relinkra-backup*` files next to each host config |

`pip uninstall relinkra` removes only the installed package and its
console scripts. It deliberately leaves behind:

- `.relinkra/` — your project's identity, registry, and verification
  records. Deleting it means the next `init` re-derives the project
  identity from scratch.
- `*.relinkra-backup*` — safety backups of agent host configurations
  taken before each `connect apply`. Keep them until you are sure you
  will not need to roll back.

Both are inert files; nothing runs or phones home if you leave them.

## Offline behavior

- **Installing** needs network access only so pip can fetch build
  dependencies (setuptools). With a warm pip cache, even that works
  offline.
- **Everything after install** — `init`, `doctor`, `status`, `project`,
  `connect`, git intelligence — works fully offline. Optional components
  (Engram, CBM) are local tools, not network services.

## Platform notes

| Platform | Notes |
|---|---|
| Windows | Console scripts land in the environment's `Scripts\` directory. If `relinkra` is not found after install, see [Troubleshooting](troubleshooting.md). |
| macOS / Linux | Console scripts land in the environment's `bin/` directory. |
| Virtual environments | Activate the environment first, then `pip install .`; the commands are available while it is active. |
| Source checkout | Without installing, `python -m relinkra.product_cli` from the checkout is equivalent to `relinkra`. |

## Next step

Run `relinkra doctor` inside your project. If anything reports FAIL or
an unexpected WARN, continue to [Troubleshooting](troubleshooting.md).
For the full command reference, see the [Product CLI](cli.md) guide.
