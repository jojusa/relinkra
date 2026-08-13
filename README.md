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

## Platform & certification status

- **Core** — works on Python 3.9+ (zero runtime dependencies). Verified locally (~2010 tests, 0 failures); CI workflows are provided and **READY_TO_RUN**, first remote run pending — nothing is CI-certified yet.
- **Codebase Memory (CBM)** — certified on Windows amd64 v0.9.0 only; on Linux/macOS it degrades honestly and everything else works.
- **Agent hosts** (Claude, OpenCode, Codex, Devin Desktop) — experimental; real-host certified locally as historical evidence, not regenerated per CI run. Devin Cloud is on the roadmap, not supported.
- **Releases** — see [Release verification](docs/release.md) for CI, verification levels, release gates, and what still blocks a public release.

## License

No LICENSE file yet — all rights reserved. This is a public-release blocker; see [docs/release.md](docs/release.md) for the legal readiness state.

## Start here

- [Installation](docs/installation.md) — install, upgrade, and uninstall.
- [Troubleshooting](docs/troubleshooting.md) — common symptoms and safe fixes.
- [Release verification](docs/release.md) — CI, verification levels, and release gates (maintainer-facing).
- [Product CLI](docs/cli.md) — initialize and inspect a workspace.
- [Project Context Packet](docs/context-packet.md) — the portable context contract.
- [Freshness, contradictions, and explainability](docs/freshness-explainability.md) — understand why evidence was shown and whether it is current.
- [MCP surface](docs/mcp-surface.md) — connect an agent to Relinkra.
