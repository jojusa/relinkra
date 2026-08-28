# Relinkra

Relinkra gives AI coding agents shared code intelligence, persistent memory, and optimized context: one codebase, one shared context, many agents. Every connected agent sees the same project memory, handoffs, and code references instead of re-discovering the repository alone. Relinkra optimizes the path to information; it does not restrict the agent's ability to search, reason, edit, or validate by itself.

## Quick Start

Requirements: Python 3.9+ and Git. Everything below works without any optional component.

**Windows (PowerShell)**

```powershell
git clone https://github.com/jojusa/relinkra.git
cd relinkra
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install .
```

If PowerShell blocks `Activate.ps1` ("running scripts is disabled"), run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or use `cmd` with `.venv\Scripts\activate.bat`.

**Linux / macOS**

```bash
git clone https://github.com/jojusa/relinkra.git
cd relinkra
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
pip install .
```

`pip install .` is the user install. If you want to hack on Relinkra itself, use the editable install instead: `pip install -e .`.

Normal flow: **install → `relinkra init` → `relinkra connect <host>`**. The
concrete host-binding command is the explicit `apply` subcommand:
`relinkra connect apply <host>`.

Then, inside the Git repository you want your agents to share:

```bash
relinkra --version   # confirms the install
relinkra init        # registers this project and workspace
```

Connect the host you use:

```text
relinkra connect apply opencode
relinkra connect apply codex
relinkra connect apply zcode
relinkra doctor                    # deep diagnostics with suggested fixes
```

OpenCode and Codex receive global, bare `relinkra-mcp` entries. Their MCP
process derives the active Git root from its process CWD, so the same global
registration can serve different repositories. ZCode receives a workspace-
local `.zcode/config.json` entry with an absolute repository-root `cwd`.

Optionally install the CBM code-intelligence backend — recommended for
architecture and relationship intelligence; everything works without it:

```text
relinkra cbm setup     # downloads and checksum-verifies the certified binary
relinkra cbm index
relinkra cbm status
relinkra cbm refresh
```

CBM remains optional; native agent tools continue to work without it.

For other supported hosts, run `relinkra connect list`. Inspect or validate a
registration without changing it:

```bash
relinkra connect inspect claude   # read-only: what Relinkra sees
relinkra connect apply claude     # writes the host config, with a backup
relinkra connect check claude     # validates configuration, not host runtime
```

Restart the host so it can reread the configuration and launch Relinkra as its
MCP (Model Context Protocol) server. `connect apply` and `connect check` do not
prove that a real host launched the server; record that separately only when
you have host-side evidence with `relinkra connect verify <host> --proof <file>`.

Once the connector is configured, ask normal project questions. You should
not normally need to say "use Relinkra": the MCP server advertises when its
shared context, memory, architecture, relationship, Git, or bounded-packet
tools can reduce redundant exploration. It does not force those tools for
trivial work, replace native tools, or make stale context authoritative.

## What just happened?

- `relinkra init` registered a portable identity for your repository and this workspace, under `.relinkra/` — nothing else was touched.
- `connect apply` added one MCP server entry named `relinkra` to the selected host configuration, after creating a timestamped backup (`*.relinkra-backup*`) where that host uses a writable config target.
- OpenCode and Codex were configured as global bare launches; ZCode was configured only in the repository's `.zcode/config.json` with an absolute `cwd`.
- Your agent can now request shared project context — memory, code references, handoffs — through Relinkra instead of starting from zero.
- Optional backends (Engram for memory, CBM for code intelligence) were detected if present; any absent one is reported, not hidden.
- Your agent's native tools are untouched; Relinkra adds a server, it does not replace anything.

## How do I know it worked?

Run `relinkra doctor`, then `relinkra connect check <agent>`.

Healthy means: no FAIL entries in `doctor` (WARN entries are typically optional components in degraded mode — safe to ignore for now), and `check` reports the registration as valid. This confirms configuration only; host runtime proof is a separate `connect verify` concern.

## If something fails

- **Python too old** — Relinkra requires Python 3.9+; check with `python --version`. See [Installation](docs/installation.md).
- **Commands not found** — the virtual environment is not activated (or the console scripts directory is not on `PATH`). See [Troubleshooting](docs/troubleshooting.md).
- **`init` refuses** — you are not inside a git repository. Run it from your project root. See [Installation](docs/installation.md).
- **Outside Git or before `init`** — binding fails closed and does not create `.relinkra`; run `git init` for a new repository, then `relinkra init` before connecting a host.
- **`doctor` reports a degraded backend** — an optional component is missing; the core still works. See [Troubleshooting](docs/troubleshooting.md).
- **Host connector not detected** — the agent's config was not found; `connect inspect <agent>` shows what Relinkra probed. See [Connectors](docs/connectors.md).
- **CBM unavailable or not certified on this platform** — code intelligence is unavailable; everything else works. See [CBM backend](docs/cbm-backend.md).
- **Engram unavailable** — memory and handoffs report as unavailable; commands still succeed. See [Installation](docs/installation.md).

Direct Engram use remains independently available; host binding does not depend
on it and does not require direct CBM configuration.

## Conflicting and stale context

Relinkra combines evidence from source, Git, CBM graphs, memory, and handoffs.
When those sources disagree it does not silently collapse them into one truth:
older evidence stays visible and is marked stale/historical, current-source
evidence is presented as current for current-code claims, and unresolvable
conflicts are surfaced as unresolved rather than guessed away. See
[Freshness, contradictions, and explainability](docs/freshness-explainability.md).

## Optional external integrations

Both are third-party projects, installed and managed independently. Neither is bundled with Relinkra, and neither is required for the quick start.

- **Codebase Memory (CBM)** — code intelligence backend maintained by [DeusData](https://github.com/DeusData/codebase-memory-mcp) (MIT license). Certified with the real binary on Windows; on Linux/macOS it is NOT certified, and Relinkra keeps working without it. Manage its index with `relinkra cbm status/index/refresh` — see [CBM backend](docs/cbm-backend.md).
- **Engram** — persistent memory backend maintained by Gentleman Programming (MIT license). External and optional; without it, memory and handoffs report as unavailable and commands still exit successfully.

## Current state

- Python 3.9 through 3.14 CI-verified (Windows and Linux; macOS CI covers 3.11+), with zero runtime dependencies.
- Core and full test suites CI-verified on Windows, Linux, and macOS.
- Remote full regression, packaging, and installed-MCP evidence: PASS (see [Release verification](docs/release.md)).
- CBM: real-binary verified on Windows; Linux/macOS are not certified (honest degradation).
- Agent hosts Claude, OpenCode, Codex, and Devin Desktop: real-host verified as historical local evidence, not regenerated by CI. Devin Cloud is unsupported (roadmap).

## License

Relinkra is released under the [MIT License](LICENSE).

## Learn more

- [Installation](docs/installation.md) — install, upgrade, and uninstall.
- [Connectors](docs/connectors.md) — how agent hosts are connected.
- [Product CLI](docs/cli.md) — the full command reference.
- [Freshness, contradictions, and explainability](docs/freshness-explainability.md) — why context was shown and whether it is current.
- [Release verification](docs/release.md) — CI, verification levels, and release gates (maintainer-facing).
- [Contributing](CONTRIBUTING.md) — set up a development checkout and run the tests.
- [Security](SECURITY.md) — supported versions and how to report a vulnerability.
