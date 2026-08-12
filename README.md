# Relinkra

**One codebase. One memory. Any agent.**

Shared code intelligence, persistent memory and optimized context for AI coding agents.

Relinkra is being built on top of open-source components including Codebase Memory MCP and Engram, adding shared multi-agent memory, Git intelligence, handoffs and token-aware context orchestration.

## Quick Start

1. **Requirements** — Python 3.9+ and Git. Optional: Engram for persistent memory, Codebase Memory (CBM) 0.9.0 for code intelligence. Relinkra runs without them and reports the degradation honestly.
2. **Install** — from a clone: `pip install .` (use `pip install -e .` for development). This provides the `relinkra` and `relinkra-mcp` commands.
3. **Initialize** — inside a git repository: `relinkra init`.
4. **Diagnose** — `relinkra doctor`. A WARN means degraded but usable; only FAIL blocks.
5. **Connect an agent** — `relinkra connect check codex` → `relinkra connect plan codex` → `relinkra connect apply codex`. `check` and `plan` are read-only; `apply` writes the host config with a backup.
6. **Verify** — record proof from the real host with `relinkra connect verify codex --proof <file>`, then use the agent.

See [Installation](docs/installation.md) for the full picture and [Troubleshooting](docs/troubleshooting.md) when something goes wrong.

## Start here

- [Installation](docs/installation.md) — install, upgrade, and uninstall.
- [Troubleshooting](docs/troubleshooting.md) — common symptoms and safe fixes.
- [Product CLI](docs/cli.md) — initialize and inspect a workspace.
- [Project Context Packet](docs/context-packet.md) — the portable context contract.
- [Freshness, contradictions, and explainability](docs/freshness-explainability.md) — understand why evidence was shown and whether it is current.
- [MCP surface](docs/mcp-surface.md) — connect an agent to Relinkra.
