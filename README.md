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

Then, inside the git repository you want your agents to share:

```bash
relinkra --version   # confirms the install
relinkra init        # registers this project and workspace
relinkra doctor      # deep diagnostics with suggested fixes
```

Connect your agent host (example: `claude`; run `relinkra connect list` to see every supported host):

```bash
relinkra connect inspect claude   # read-only: what Relinkra sees
relinkra connect apply claude     # writes the host config, with a backup
relinkra connect check claude     # confirms the registration is valid
```

Restart the agent, and it launches Relinkra as its MCP (Model Context Protocol) server. Optionally, once you have used it from the real host, record the proof with `relinkra connect verify claude --proof <file>`.

## What just happened?

- `relinkra init` registered a portable identity for your repository and this workspace, under `.relinkra/` — nothing else was touched.
- `connect apply` added one MCP server entry named `relinkra` to your agent's config, after creating a timestamped backup (`*.relinkra-backup*`).
- Your agent can now request shared project context — memory, code references, handoffs — through Relinkra instead of starting from zero.
- Optional backends (Engram for memory, CBM for code intelligence) were detected if present; any absent one is reported, not hidden.
- Your agent's native tools are untouched; Relinkra adds a server, it does not replace anything.

## How do I know it worked?

Run `relinkra doctor`, then `relinkra connect check <agent>`.

Healthy means: no FAIL entries in `doctor` (WARN entries are typically optional components in degraded mode — safe to ignore for now), and `check` reports the registration as valid. If both hold, your agent is connected.

## If something fails

- **Python too old** — Relinkra requires Python 3.9+; check with `python --version`. See [Installation](docs/installation.md).
- **Commands not found** — the virtual environment is not activated (or the console scripts directory is not on `PATH`). See [Troubleshooting](docs/troubleshooting.md).
- **`init` refuses** — you are not inside a git repository. Run it from your project root. See [Installation](docs/installation.md).
- **`doctor` reports a degraded backend** — an optional component is missing; the core still works. See [Troubleshooting](docs/troubleshooting.md).
- **Host connector not detected** — the agent's config was not found; `connect inspect <agent>` shows what Relinkra probed. See [Connectors](docs/connectors.md).
- **CBM unavailable or not certified on this platform** — code intelligence is unavailable; everything else works. See [CBM backend](docs/cbm-backend.md).
- **Engram unavailable** — memory and handoffs report as unavailable; commands still succeed. See [Installation](docs/installation.md).

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
