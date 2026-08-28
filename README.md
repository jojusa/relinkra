# Relinkra

## What Relinkra does

Relinkra gives AI coding agents shared code intelligence, persistent memory, and optimized context: one codebase, one shared context, many agents. Every connected agent sees the same project memory, handoffs, and code references instead of re-discovering the repository alone. Relinkra optimizes the path to information; it does not restrict the agent's ability to search, reason, edit, or validate by itself.

## Quick start

Requirements: Python 3.9+ and Git. The quick start does not require any optional component.

### Install

The normal installation path after publication is:

```bash
python -m pip install relinkra
```

The literal `pip install relinkra` command is the equivalent user-facing
contract. Relinkra is not being published to PyPI in this checkpoint, so this
is the post-publication path rather than a claim of current public availability.

For local validation or unreleased development only, install a built artifact
or a source checkout:

```bash
# Install a locally built wheel or sdist
python -m pip install path/to/relinkra-<version>-py3-none-any.whl

# Or install from an unreleased source checkout
git clone https://github.com/jojusa/relinkra.git
cd relinkra
python -m pip install .
```

Use `python -m pip install -e .` only when actively developing Relinkra. The
source-checkout paths are not the normal user installation.

### Initialize

From inside the Git repository you want your agents to share:

```bash
relinkra --version
relinkra init
```

### Connect an agent

Run the supported command sequence for the host you use:

```bash
relinkra doctor
relinkra connect check <host>
relinkra connect plan <host>
relinkra connect apply <host>
```

Supported hosts include `claude`, `opencode`, `codex`, `zcode`, and
`devin-desktop`. OpenCode and Codex receive global, bare `relinkra-mcp`
registrations; Codex uses `args = []`. ZCode receives a workspace-local
configuration with the repository-root `cwd`.

For the complete host list, run `relinkra connect list`. `connect check` is
read-only, `connect plan` previews changes, and `connect apply` writes the
configuration after creating a backup where supported.

### Verify

Restart the host so it can reread its configuration and launch Relinkra as its
MCP (Model Context Protocol) server. Then record host-side proof:

```bash
relinkra connect verify <host> --proof <proof-file>
```

`connect apply` and `connect check` validate configuration only; they do not
prove that a real host launched the server.

### Use

Once the connector is configured, ask normal project questions. You should not
normally need to say "use Relinkra": the MCP server advertises when its shared
context, memory, architecture, relationship, Git, or bounded-packet tools can
reduce redundant exploration. It does not force those tools for trivial work,
replace native tools, or make stale context authoritative.

## What just happened?

- `relinkra init` registered a portable identity for your repository and this workspace under `.relinkra/` — nothing else was touched.
- `connect apply` added one MCP server entry named `relinkra` to the selected host configuration, after creating a timestamped backup where that host uses a writable config target.
- Your agent can now request shared project context — memory, code references, and handoffs — through Relinkra instead of starting from zero.
- Optional integrations are not required; their absence is reported honestly, and your agent's native tools remain untouched.

## How do I know it worked?

Run `relinkra doctor`, then `relinkra connect check <agent>`. After applying the
configuration and restarting the host, use
`relinkra connect verify <agent> --proof <proof-file>` when host-side evidence
is required.

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

Both are third-party projects, installed and managed independently. Neither is bundled with Relinkra, and neither is required for the quick start. Direct CBM setup is optional advanced/local configuration, not part of the normal public installation path.

- **Codebase Memory (CBM)** — code intelligence backend maintained by [DeusData](https://github.com/DeusData/codebase-memory-mcp) (MIT license). Certified with the real binary on Windows; on Linux/macOS it is NOT certified, and Relinkra keeps working without it. Manage its index with `relinkra cbm status/index/refresh` — see [CBM backend](docs/cbm-backend.md).
- **Engram** — persistent memory backend maintained by Gentleman Programming (MIT license). External and optional; without it, memory and handoffs report as unavailable and commands still exit successfully.

## Current state

- Python 3.9 through 3.14 is covered by the repository's CI matrix, with zero runtime dependencies.
- Exact release-HEAD evidence for full regression, packaging, and installed-MCP behavior must be regenerated before public publication; older remote evidence is historical (see [Release verification](docs/release.md)).
- CBM: real-binary verified on Windows; Linux/macOS are not certified (honest degradation).
- Agent hosts Claude, OpenCode, Codex, Devin Desktop, and ZCode: real-host verified as historical local evidence, not regenerated by CI. Devin Cloud is unsupported (roadmap).
- PyPI publication is not performed in this checkpoint; local validation uses built artifacts or a source checkout.

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
