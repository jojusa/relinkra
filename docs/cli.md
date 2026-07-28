# Product CLI (R4A)

The user-facing front door: `init`, `status`, `doctor`, `project`.

**Powerful inside, simple outside.** A developer should get from a fresh
clone to a working Relinkra without knowing what CBM, Engram, a logical
project id, or MCP are. Those words appear in `doctor` output only where
they are the actionable noun — never as prerequisites for using the tool.

```
$ relinkra init
$ relinkra status

Relinkra

Project        rlk_f53fe1e22c1bd57e7f0ca04c1701c33b
Workspace      ws_6dab6756bc40bd1c48c1a55acbe0c437
Git            OK
Engram         OK
CBM            WARN
MCP            OK
Memory         AVAILABLE
Handoffs       AVAILABLE
```

Entry point: `python -m relinkra.product_cli`.

This is distinct from `relinkra.cli`, the R1B admin tool
(`register` / `list` / `show`), which is unchanged.

## Architecture

The CLI owns **presentation and nothing else**:

| Concern | Owner | CLI role |
|---|---|---|
| Logical project identity | R1B `identity` / `registry` | calls `discover_repository_identity`, `register_workspace` |
| Component health | R3 `app_service.health()` | renders the report |
| Git facts | R2 / R1B git helpers | calls `git_branch` / `git_head_sha` |
| Portability rules | `handoff.scrub_absolute_paths` | audits its own output with them |
| Error/warning sanitation | `app_service.sanitize_wire_text` | routes all free text through it |

Nothing here re-derives identity, re-probes engines, or re-parses git.
`status` and `doctor` share one check engine — `doctor` adds runtime and
integrity checks on top of the same `health()` call `status` renders.

The subcommand table in `build_parser` is a plain loop over
`(name, handler, help)`, so `connect`, `context`, `handoff`, and `memory`
slot in later without restructuring.

## Exit codes

One contract, uniform across commands:

| Code | Meaning |
|---|---|
| `0` | The command ran and the outcome is good. **Degraded components still exit 0** — a missing CBM is a state to report, not a command failure. |
| `1` | The command itself failed: not a git repository, unreadable registry, invalid arguments. |
| `2` | The command ran, but the outcome needs a human decision: `init` hit an ambiguous identity, or `doctor` found at least one `FAIL`. |

A `WARN` never changes an exit code. That distinction is the whole point:
scripts can gate on "did this work" without being tripped by optional
components.

## `relinkra init`

Detects the repository, resolves logical identity, registers the
workspace, writes minimal config, then reports readiness.

**Idempotent.** Re-running preserves `project_id`, `workspace_id`, and
the original `initialized_at`; `register_workspace` treats a known
workspace as a refresh rather than a new merge, so no duplicate identity
is ever created. The second run says so explicitly ("already
initialized (refreshed)").

**The pin is validated, not trusted.** `init` reuses the `project_id`
recorded in config only when the registry's identity for that project
still matches the identity freshly discovered from git. That check is
load-bearing: `.relinkra/config.json` is gitignored, so it routinely
outlives the repository it describes — a directory gets repurposed, its
`.git` replaced with an unrelated remote, and the config survives.
`Registry.register_workspace` accepts a `project_id` override *by design*
without matching it against the supplied identity, so an unvalidated pin
would file a completely different codebase under the previous project and
silently share that project's memory and handoffs.

When the identity has changed, `init` resolves a new project, resets the
initialization timestamp, sets `identity_changed` in `--json`, and says
so in plain language rather than switching projects silently:

```
Relinkra re-initialized for a different repository.

This workspace was previously initialized for a different
repository. Relinkra resolved a new project identity, so
the previous project's memory and handoffs are NOT shared
with this one.
```

**Safety — what init does NOT do:** it never modifies git history,
stages, commits, pushes, deletes memory, writes to Engram's database, or
starts a daemon. The only filesystem writes are inside `.relinkra/`,
which a test asserts directly by diffing the workspace before and after.

It does **not** write host-specific MCP config. That is R4B.

## `relinkra status`

Concise, deterministic, one screen. Renders project/workspace identity
plus Git, Engram, CBM, MCP, Memory, and Handoffs.

Degraded output is the interesting case and is still exit 0: components
show `WARN`, capabilities show `UNAVAILABLE`, and the command succeeds.

## `relinkra doctor`

Deep diagnostics as `PASS` / `WARN` / `FAIL`, each with a suggested
action when it is not passing:

```
WARN CBM
      no CBM adapter configured
      Suggested action: Optional. Configure a code-index binary to
      enable symbol resolution; everything else works without it.
```

Checks: Python runtime, git executable, git repository, Relinkra config,
registry integrity, Engram, CBM, git intelligence, MCP constructability,
project identity, and a **portable-output self-audit**.

That last one is unusual and deliberate: `doctor` runs
`contains_absolute_path` over the payload it is about to print and
reports the result as a check. It is the one guarantee a user cannot
verify for themselves, so the tool verifies it in front of them.

A missing engine is `WARN`, not `FAIL` — Relinkra is built to degrade.
`FAIL` is reserved for "this cannot work": no git, no repository, a
corrupt registry.

## `relinkra project`

Logical identity for humans and scripts: project id, workspace id,
display name, repository identity (value/kind/trust), branch, HEAD, and
detached state. No absolute paths.

## `--json`

Every command takes `--json`. Each handler builds one payload dict and
then either renders text from it or dumps it — the two paths never
diverge because there is only one source. Useful for scripting and for
the R4B connectors.

## Configuration

One file, `.relinkra/config.json`, alongside the registry:

```json
{
  "config_version": 1,
  "project_id": "rlk_...",
  "workspace_id": "ws_...",
  "initialized_at": "...",
  "relinkra_version": "0.1.0"
}
```

**Workspace-local, not for committing.** `.relinkra/` holds the registry
too, and the registry necessarily records this machine's absolute paths.

The config file itself stores **no absolute paths, no credentials, no
environment values** — only opaque ids and versions, asserted by test.
Tool locations are resolved from PATH/environment at runtime rather than
frozen here, which is what keeps the file free of machine-specific data.

Its job is to *pin* what `init` resolved so later commands are
deterministic and cannot re-trip identity ambiguity. It does not
duplicate the registry; it points into it.

A corrupt or unreadable config is treated as absent — the CLI reports
"not initialized" and tells you to run `init`, rather than crashing.

## Cross-platform

Windows, Linux, and macOS are all supported.

- All paths are `pathlib`; no separator literals, enforced by a test that
  greps the module source.
- `_repo_root` walks upward via `Path.parents` (terminates at the
  filesystem root on every platform) and accepts a `.git` **file** as
  well as a directory, so worktrees and submodules resolve.
- Executables are found with `shutil.which`, never a hardcoded path.
- No PowerShell, no `cmd.exe`, no POSIX shell assumptions; no `shell=True`.
- stdout/stderr are reconfigured to UTF-8 with `errors="replace"` before
  argparse runs, so piped output does not mojibake under a locale codec
  (cp1252 on Windows) and an exotic branch name cannot crash the CLI.
