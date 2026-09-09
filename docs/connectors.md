# Connectors (R5K.1 / R4B)

Relinkra runs as an MCP server. A *connector* is what gets a host — Claude
Code, OpenCode, Codex, Devin Desktop (formerly Windsurf), or anything else that speaks MCP — to launch
that server for this workspace.

The user-facing shape is meant to stay this small:

```
relinkra connect list
relinkra connect inspect claude
relinkra connect plan claude
relinkra connect apply claude
relinkra connect check claude
relinkra connect routing
relinkra connect generic
```

Powerful inside, simple outside. Everything below is the "inside".

> **Status.** Claude Code (R4C.1B), OpenCode (R4C.1C), Codex (R4C.1D), Devin
> Desktop (R4C.1E), and ZCode (R5K.1) have gated write paths (`connect apply`
> / `rollback` / `verify`). Historical/local Devin Desktop evidence exists, but
> the published 0.1.2 CLI currently reports `real_host_launch_proven=false` for
> Devin Desktop and overall. Actual host proof is separate and must be recorded
> through the published verify flow. See [Capability honesty](#capability-honesty).

---

## Connector lifecycle

Every connector mutation follows one fixed sequence. Read-only commands stop
partway through it.

```
discover → inspect → plan → validate plan → dry-run
         → backup → atomic merge → validate result → rollback on failure
```

| Stage | Owner | Implemented | Reachable from the CLI |
| --- | --- | --- | --- |
| discover | `host_discovery.probe` | yes | `connect list`, `connect inspect` |
| inspect | `connectors.inspect_connector` | yes | `connect inspect`, `connect check` |
| plan | `connectors.build_plan` | yes | `connect plan` |
| validate plan | `config_merge.decide_member` | yes | `connect plan` |
| dry-run | planning *is* the dry run | yes | `connect plan --dry-run` |
| backup | `safe_write.create_backup` | yes | `connect apply` (claude, opencode, codex, zcode, devin-desktop) |
| atomic merge | `safe_write.safe_replace` | yes | `connect apply` (claude, opencode, codex, zcode, devin-desktop) |
| validate result | `config_formats.adapter_for(...).validate` | yes | `connect apply` (claude, opencode, codex, zcode, devin-desktop) |
| rollback | `safe_write.safe_replace` | yes | `connect rollback` (claude, opencode, codex, zcode, devin-desktop) |

The last four rows are wired only for the connectors whose write gate is
open; every other connector still stops at `plan` — see
[Apply and host proof are separate](#apply-and-host-proof-are-separate).

---

## Module map

| Module | Responsibility |
| --- | --- |
| `relinkra/connector.py` | Domain vocabulary: states, launch contract, plan, capability matrix. No I/O. |
| `relinkra/workspace_resolution.py` | Central MCP startup resolver for explicit/env/CWD workspace roots and root-derived registries; read-only and fail-closed. |
| `relinkra/host_discovery.py` | Bounded, declared candidate locations; pure path resolution; probing. |
| `relinkra/config_merge.py` | Non-destructive structured merge and deterministic serialization. |
| `relinkra/config_formats.py` | Per-format adapter seam (parse / validate / serialize_member) keyed off `spec.config_format`; JSON and TOML adapters. |
| `relinkra/toml_edit.py` | Scoped, comment-preserving textual TOML editor (Codex); tomllib parsing plus byte-exact region replacement, fail-closed. |
| `relinkra/safe_write.py` | Backup, atomic write, rollback, size bounds, advisory locking. |
| `relinkra/connectors.py` | The registry: per-host declarations, launch resolution, plan building. |
| `relinkra/connect_cli.py` | Command dispatch, exit codes, the portability audit. |
| `relinkra/connect_render.py` | Human-readable rendering. Pure functions. |
| `relinkra/backend_policy.py` | R4C.0 ownership, routing and trust vocabulary. Pure domain, no I/O. |
| `relinkra/backend_detection.py` | R4C.0 structural classification of MCP registrations; routing assessment. |

`connect routing` reports which backends each host actually reaches and
whether project context flows through Relinkra. It is configuration-only
— no backend is probed and no process is spawned. See
[context-control-plane.md](context-control-plane.md) for the policy it
applies.

---

## Generic MCP contract

`relinkra connect generic` emits the compatibility, workspace-pinned way to
start the server over stdio. Host-specific `connect apply <host>` uses the
R5K.1 binding policy described below instead of copying those explicit paths
into every host registration.

Resolution order:

1. **console script** — `relinkra-mcp` on `PATH`, if Relinkra is installed as a
   package. Cleanest contract: no interpreter, no `PYTHONPATH`.
2. **installed module** — the current interpreter plus `-m relinkra.mcp_cli`,
   when the package resolves from the interpreter's own library directories.
3. **source checkout** — same, plus a required `PYTHONPATH`. This is what a
   working copy of the repository gets, and the contract says so out loud.
4. **unresolved** — no interpreter could be found. Reported, never guessed.

The contract is always **structured**: a `command` string and a separate `args`
list. It is never assembled into a single shell string, so a workspace path
containing a space, an `&` or a quote is inert data. No `shell=True`, anywhere.

### Portable vs machine-local output

| | Default | `--reveal-paths` |
| --- | --- | --- |
| `command` | `<interpreter>` | the real executable |
| path-shaped `args` | `<path>` | the real value |
| environment | key names only | names and values |

Argument **arity and order** survive redaction, so the shape of the invocation
is still reviewable without disclosing where anything lives. Every payload
rendered without `--reveal-paths` is audited for absolute paths immediately
before printing; a leak fails the command rather than reaching the terminal.

## R5K.1 host-neutral HYBRID binding

The normal flow is:

```text
install Relinkra → relinkra init → relinkra connect apply <host>
```

Run `relinkra init` from the target Git repository before applying a host
connector. It records the workspace-local Relinkra state under `.relinkra/`.
The host connector then writes only the host configuration it owns; it does not
start the host or claim that the host launched the MCP server.

| Host | Registration scope | Binding written by Relinkra |
| --- | --- | --- |
| OpenCode | Global user config | Bare `relinkra-mcp` launch with no `--workspace-root`, `--registry`, or config `cwd`; the MCP process derives the active Git root from its process CWD. |
| Codex | Global user config | Same bare launch contract as OpenCode; the process CWD determines the active Git root. |
| ZCode | Workspace-local `.zcode/config.json` | `mcp.servers.relinkra` stdio entry with an absolute canonical repository-root `cwd`. |

For OpenCode and Codex, a single global registration is intentionally
repository-neutral. When the host starts the MCP process from a nested project
directory, Relinkra walks upward to the enclosing Git root; `.git` directories
and linked-worktree `.git` files are supported. The default registry is then
`<resolved-root>/.relinkra/registry.json`.

ZCode is intentionally not global: only `<workspace>/.zcode/config.json` is
read or written, and its entry carries the absolute resolved Git root so a
nested launch does not change the binding.

### Compatibility options

The explicit `--workspace-root`, `--registry`, `--project-id`, and
`--workspace-id` options remain supported for compatibility and controlled
manual launches. `RELINKRA_*` environment variables remain supported as well.
The older `connect generic` contract continues to emit explicit workspace and
registry arguments; it is not the host-neutral OpenCode/Codex registration.

### Fail-closed states

Root and registry resolution is read-only. Outside a Git repository, or before
`relinkra init` has registered the workspace, automatic binding fails closed:
it does not guess another repository and does not create `.relinkra`. Corrupt,
missing, or ambiguous registry state is also reported as an actionable failure.
MCP liveness methods such as `initialize`, `ping`, `tools/list`, and `health`
may still be available without a project binding; project-scoped operations do
not invent one.

Engram remains an independent optional path. Host binding does not require
Engram, and these connector instructions do not configure a direct CBM server.

---

## Support and proof matrix

Verified formats were read out of a real local configuration on a development
machine — not from documentation.

| Connector | Support | Format verified | Evidence | Plan | Apply | Host launch proven |
| --- | --- | --- | --- | --- | --- | --- |
| `generic` | supported | yes | Relinkra's own stdio entry point | n/a | n/a | **no** |
| `claude` | experimental | yes | `mcpServers` with `{command, args}` | yes | yes (R4C.1B) | **no** |
| `opencode` | experimental | yes | `mcp` with `{type: local, command: [...]}` | yes | yes (R4C.1C) | **no** |
| `codex` | experimental | yes | `[mcp_servers.<name>]` TOML tables | yes | yes (R4C.1D) | **no** |
| `zcode` | experimental | yes | workspace-local `mcp.servers` with `{type, command, args, cwd, enabled}` | yes | yes (R5K.1) | **no** |
| `devin-desktop` | experimental | yes (current Devin file) | `mcpServers` with `{command, args}` | yes | **yes (R4C.1E write path)** | **no (published CLI)** |
| `devin-cloud` | unsupported | no | — | no | no | no |

Codex writes use a **scoped textual TOML editor**: only the byte extent of the
`[mcp_servers.relinkra]` table is replaced (or appended at end of file), while
every other table, comment, quoting style, line ending and the UTF-8 BOM is
preserved byte-for-byte. Parsing and post-write validation always go through
`tomllib`, and the candidate text is re-parsed and compared against the
structured merge before any write is accepted. This strategy was chosen over
the official `codex mcp add` (codex-cli 0.146.0), which drops comments
adjacent to the `mcp_servers` region it rewrites and normalizes CRLF to LF
globally; no comment-preserving TOML library is available to a stdlib-only
project. Dotted-key or inline-table representations of the managed member
(`mcp_servers.relinkra = {...}`) are **refused**, never rewritten. Reading and
writing require `tomllib` (Python 3.11+); on older interpreters the
registration state is reported `unknown` and writes refuse, rather than
guessing from a regex.

### Devin Desktop

The primary connector is `devin-desktop`. The compatibility aliases
`windsurf`, `codeium`, and `windsurf-next` resolve to that same canonical
connector; they do not create separate proof identities or writable targets.
Bare `devin` remains ambiguous with the distinct, unsupported `devin-cloud`
connector. Devin Cloud is outside the scope of R4C.1E.

R4C.1E recorded historical/local Devin Desktop/Cascade evidence, including the
expected eleven-tool Relinkra roster, six successful tool calls, project
binding, handoff retrieval, and an explicit null `workspace_id`. Preserve that
record as historical/local evidence only: it is not current host certification.
The published 0.1.2 CLI reports `real_host_launch_proven=false` for Devin
Desktop and overall. Actual host proof is separate and must be recorded after
the host launch with the published flow, for example:
`relinkra connect verify devin-desktop --proof <proof-file>`.

When only a legacy file is discoverable, read-only inspection may display that
file as the observed evidence location. This is not the writable target:
planning and apply resolve the first current Devin location instead. The
distinction is intentional and preserves legacy evidence without enabling a
legacy write.

### Verification evidence schema

Persisted connector proof uses `relinkra.connect-verification/v2`. The version
bump is intentional: `workspace_id` is now a required storage field, so the
exact record shape changed.

| Field | Rule |
| --- | --- |
| `workspace_id` | Always serialized; either JSON `null` or a registry-backed `ws_` id matching `^ws_[0-9a-f]{32}$` and the current workspace. |
| `null` | Valid local-operational evidence that makes no workspace-local identity claim; it is not independent attestation. The completed Codex proof uses this value. |
| v1 record | Legacy and fail-closed. It is not migrated, rewritten or trusted. |

Host isolation, workspace-root binding and the existing local-operational trust
semantics remain unchanged. Missing, malformed, copied or mismatched workspace
identity evidence is unusable rather than partially trusted.

### Config locations

Each connector declares a finite, ordered list. For connectors other than
Claude, declaration order is precedence: the first candidate that **exists**
becomes the active config. Claude is the explicit exception in the published
CLI: project-scoped `~/.claude.json` is the active/apply target, while
`~/.claude/settings.json` is legacy/discovery-only. Nothing is globbed and no
directory is walked.

| Connector | Candidates |
| --- | --- |
| `claude` | `~/.claude.json` (project-scoped active/apply target), `~/.claude/settings.json` (legacy/discovery-only), `<workspace>/.mcp.json`, `<workspace>/.claude/settings.local.json` |
| `opencode` | `$XDG_CONFIG_HOME/opencode/opencode.json` (default `~/.config/...`) — the only apply target, plus `opencode.jsonc` siblings at user and workspace scope and `%APPDATA%/opencode/opencode.json`, `<workspace>/opencode.json` (discoverable and scanned for direct CBM, never the apply target) |
| `codex` | `$CODEX_HOME/config.toml` (default `~/.codex/config.toml`) |
| `zcode` | `<workspace>/.zcode/config.json` only |
| `devin-desktop` | `.devin/mcp_config.local.json` → `.devin/mcp_config.json` → `%APPDATA%/Devin/mcp_config.json` → `~/.config/devin/mcp_config.json`; legacy `~/.codeium/windsurf/mcp_config.json` and `~/.codeium/windsurf-next/mcp_config.json` are discovery/import evidence only and are never preferred write targets |

A host is reported `not_installed` only when **none** of its candidates exist
**and** its executable is not on `PATH`. One missing conventional file proves
nothing.

---

## Discovery states

Four failure shapes are kept distinct because each calls for a different user
action:

| State | Meaning | What the user does |
| --- | --- | --- |
| `discovered` | config found and parsed | nothing |
| `not_installed` | no config, no executable | install the host |
| `config_missing` | executable present, no config | run the host once |
| `config_malformed` | config exists, does not parse | repair the file |
| `config_unsupported` | parses, wrong shape / too large / unreadable | look at what that key holds |
| `unverified` | Relinkra cannot speak for this host | nothing available |

A candidate whose `stat` is denied counts as the **active** location even
though it does not report as existing. A denied `stat` cannot tell presence
from absence, and skipping it would report the host as not installed while its
config sits right there behind a permissions problem — sending the user to
reinstall instead of to `chmod`.

---

## Ownership and conflicts

Relinkra registers under the server name `relinkra`. A name alone never confers
ownership — the name is exactly what a coincidental user entry would share.

Ownership is decided **structurally**: an entry is Relinkra's if its command
tokens name `relinkra.mcp_cli` or the `relinkra-mcp` console script. Both
command shapes are understood (`{command: str, args: [...]}` and
`{command: [prog, ...]}`), and path separators are handled for both platforms so
a config written on Windows is read correctly on POSIX.

| Situation | Decision | Effect |
| --- | --- | --- |
| no entry of that name | `add` | plan creates it |
| our entry, already correct | `no_op` | plan is idempotent |
| our entry, stale | `update` | plan refreshes it |
| someone else's entry of that name | **`conflict`** | plan is `blocked`, nothing is overwritten |

An explicit ownership marker (`x-relinkra`) is supported by the engine but
enabled for no host: adding an unknown member to a config whose validation
behaviour is unverified could break the very file Relinkra is extending. It
stays opt-in per connector.

### Cross-scope protection during apply

Hosts merge MCP scopes beside (or after) the apply target: OpenCode deep-merges
`opencode.jsonc` after `opencode.json`, and both its `%APPDATA%` user config and
the workspace pair register servers too. Two protections follow from that.

- **Shadow refusal.** An entry named `relinkra` in ANY scope the host loads —
  whatever it launches — shadows the managed registration: which entry runs is
  the host's merge rule, not Relinkra's. `apply` refuses and names the scope's
  portable display hint; `check` reports the same fact as a `conflict`. Relinkra
  never removes or overwrites another scope's entry to resolve the ambiguity.
  The apply target's own entry is never a shadow: it is what Relinkra manages.
- **Fail-closed scope scanning.** Every authoritative scope is scanned for
  direct codebase-memory registration before any write. The semantics are
  identical between the apply gate and the routing survey: a scope that exists
  but has no MCP container (or a non-mapping container) registers no servers and
  is *clean*; a scope that cannot be read, parsed or walked — including a
  `.jsonc` file using comments or trailing commas, which the strict parser
  rejects — is *unreadable* and fails closed, never reported as clean.

Only scopes the connector declares are scanned. OpenCode's container is `mcp`;
a stray top-level `mcpServers` member is an unknown field the host never honors,
so it neither trips the gate nor is touched by the rewrite. Claude Code is the
opposite case: its top-level `mcpServers` IS inherited beside the targeted
project scope, so the connector declares it as an inherited container and the
gate scans both.

### What survives a merge

- Every unrelated member, byte-for-byte where the structured representation
  allows it.
- Key order — the document is never sorted, so a one-member addition stays a
  one-member diff.
- Indentation and line endings, detected from the file itself.
- **Unknown fields on our own entry.** An update overlays the desired fields
  onto the existing entry rather than replacing it, so a user's `disabled` flag
  or a host's bookkeeping is not reset on the next run.

Nothing is guessed. A container that is a list where an object is expected is a
typed refusal, not an assumption.

---

## Plan model

A plan is deterministic and side-effect free. Two builds from the same inputs
produce equal dictionaries — that is what makes `connect plan` safe to run
repeatedly and what the idempotency proof compares.

Operations: `no_op`, `backup_file`, `create_file`, `add_object_member`,
`replace_managed_member`, `validate_json`, `request_restart`. The
`validate_json` token predates the format-adapter seam and is format-generic:
it means "re-parse the written file with the host format's parser" (TOML for
Codex).

Every operation carries preconditions, postconditions and rollback information
as **data**, because the process that plans is not the process that would
apply. The executor re-checks them at write time; that re-check is what closes
the gap between the two.

Targets are named semantically (`claude:claude_user_settings`), never by path,
so a plan means the same thing on every machine and can be diffed across them.

Plan status is three-valued:

- `ready` — the merge is computable and safe.
- `blocked` — a conflict. A person must decide.
- `unavailable` — no plan could be built (unverified format, unparseable
  config, unresolved launch contract, unsupported format).

`apply_available` is a **separate** field. A `ready` plan with
`apply_available: false` is expected only for connectors whose write path is
still closed; Claude Code, OpenCode and Codex currently expose apply.

`connect check` decides staleness with the **same** `decide_member` engine that
`build_plan` uses. Answering that question a second way is exactly how a `check`
ends up calling a registration valid that `plan`, reading the same file, reports
as needing an update. `check` also distinguishes *unknown* from *absent*: when
the config could not be parsed — on an interpreter without `tomllib`, say — it
says so rather than claiming no registration exists.

---

## Backup, atomic write and rollback

The only acceptable failure mode for a connector write is "nothing changed".

- **Backup before mutation**, with collision-safe naming
  (`config.json.relinkra-backup`, then `-1`, `-2`). A name is never reused, so
  a second failed write cannot overwrite the only copy of the original.
- **Same-directory temp file.** `os.replace` is atomic only within a
  filesystem; a cross-mount move would silently degrade to copy-then-delete.
- **fsync** on the temp file, on backups, and best-effort on the directory.
- **Atomic replace**, then **re-read and re-validate what landed on disk** —
  the in-memory string being valid says nothing about truncation, encoding, or
  a full disk.
- **Automatic rollback**, by the most faithful route available: the backup file
  (copied back through the same temp-and-replace sequence as the forward write,
  never a chunked `copy2` onto the live file), else the original text — which
  `safe_replace` already read to compute the precondition digest, and which is
  what covers `backup=False` — else deletion, when the file did not exist before
  and the correct original state is *absent*.
- **Temp cleanup on every path**, success or failure.
- **Permissions**: new files are `0o600`; an existing file keeps its own mode.
  Relinkra never widens permissions.
- **Advisory locking** around the whole read-modify-write, reusing the
  registry's existing cross-platform lock rather than introducing a second one.
  Best-effort by design (matching the registry): if the platform primitive is
  unavailable the critical section proceeds unlocked rather than failing.
- **The symlink refusal is re-asserted immediately before the replace**, not
  only on entry. The early check runs several I/O steps before the write —
  long enough for the target to be swapped for a symlink in between, which is
  exactly the substitution the check exists to refuse.

Precondition digests close the plan/apply gap: a plan is built from the config
as it was *read*, and a user may edit it while deciding. A changed digest
aborts the write instead of silently discarding their edit.

---

## Security boundaries

| Risk | Mitigation |
| --- | --- |
| Command injection | Structured `command` + `args`; never joined into a string. |
| Shell invocation | No `shell=True`, no `eval`/`exec`, no shell string assembled anywhere. |
| Path traversal | Candidate locations are declared constants joined onto a resolved base. |
| Environment-supplied directories | `XDG_CONFIG_HOME` / `CODEX_HOME` are honoured only when **absolute**; a relative value would resolve against an arbitrary working directory. |
| Symlink / reparse point | Writes through a symlink are refused with a typed error — `os.replace` would silently detach the link. |
| TOCTOU | Size is checked at `stat` **and** at read; content digests gate the write; the read-modify-write runs under one lock. |
| Oversized config | Hard `MAX_CONFIG_BYTES` ceiling with a typed failure. |
| Malicious JSON shapes | Non-object roots and non-object containers are typed refusals, never coerced. |
| Credential leakage | No configuration is echoed. Only key *names* and structural counts are rendered. |
| Environment-value leakage | `env_keys` in portable output; values only under `--reveal-paths`. |
| Absolute-path leakage | Every non-revealed payload is audited before printing; a leak fails the command. |
| Destructive merge | Foreign entries of the same name are a hard conflict. Unrelated members are never touched. |
| Unbounded scanning | No globbing, no directory walking, no reading outside declared candidates. |
| Deeply nested JSON | `RecursionError` is caught at the parse boundary and reported as a malformed configuration. ~40 KB of brackets is under the size ceiling, so the byte limit alone does not cover this. |

The host executable is looked up **only as evidence of installation**. Relinkra
never runs it. Relinkra configures agents; it does not start them.

---

## Capability honesty

`connect list` and `connect inspect` report seven independent facts. Read them
left to right — a later one is never implied by an earlier one.

| Capability | Means |
| --- | --- |
| `implementation_exists` | Relinkra has a connector for this host. |
| `configuration_format_verified` | The shape was read from a real config, not assumed. |
| `registration_detected` | A Relinkra entry is present right now. |
| `registration_planned` | A `ready` mutation plan was produced. `connect list` and `connect inspect` plan as well as inspect, so this is a live fact rather than a field that can only ever be false. |
| `configuration_validated` | The host's config parsed cleanly. |
| `mcp_process_contract_validated` | The launch contract resolves and the server module imports. |
| `real_host_launch_proven` | **A real host actually started this server.** |

The published 0.1.2 CLI currently reports the last one as `false` for Devin
Desktop and overall. Historical/local R4C.1E Cascade evidence (see [Devin
Desktop](#devin-desktop)) is not current certification. The value cannot be
set by planning: producing a plan proves a file could be edited, not that a
host started the server afterwards. Actual host proof is separate and must be
recorded after the real launch through the published verify flow,
`relinkra connect verify <host> --proof <proof-file>`.

### Apply and host proof are separate

Claude Code and OpenCode have gated `connect apply` paths. A successful apply
proves only that the configuration was safely edited; `real_host_launch_proven`
still requires a real host launch and remains a separate claim.

---

## Cross-platform design

Windows, Linux and macOS are all first-class.

- `pathlib` throughout; no separator literals, no hardcoded slashes.
- Location resolution is a **pure function** of an injected environment and uses
  `PureWindowsPath` / `PurePosixPath` chosen from that environment's declared
  system — so Windows semantics are asserted while running on Linux and vice
  versa.
- `%APPDATA%` is Windows-only and resolves to nothing elsewhere. `XDG_CONFIG_HOME`
  is honoured on **every** platform, because real cross-platform agent CLIs use
  `~/.config` on Windows too.
- No `python` vs `python3` assumption: `sys.executable` first, then `python3`,
  then `python`.
- No dependency on PowerShell, `cmd` or a POSIX shell.
- POSIX file modes are applied where they mean something and ignored where they
  do not; directory `fsync` is best-effort because Windows cannot do it.

**Still requiring CI certification on real machines:** POSIX permission
assertions and symlink refusal are skipped on Windows and vice versa; the
`%APPDATA%` and `$XDG_CONFIG_HOME` branches are asserted through injected
environments rather than on real Linux and macOS hosts. The published 0.1.2
CLI currently records no certified real-host launch for Devin Desktop or
overall. The R4C.1E Cascade record is historical/local evidence only; actual
host proof remains separate and must be recorded through
`relinkra connect verify <host> --proof <proof-file>`.

### Windows, paths, and console scripts

The installed `relinkra` and `relinkra-mcp` console scripts live in the
environment's `Scripts` directory, which must be on `PATH`. If the scripts are
not available, use `python -m relinkra.product_cli` or
`python -m relinkra.mcp_cli` from the active environment. Launch commands keep
the executable and argument list separate, so Windows paths containing spaces,
`&`, or quotes are passed as data rather than through a shell.

Relinkra configures its product and MCP streams for UTF-8; the MCP stream uses
newline-delimited JSON-RPC framing and sends diagnostics to `stderr`. These
settings avoid Windows console encoding and `CRLF` framing surprises.

---

## Adding a future connector

Append one `ConnectorSpec` to `CONNECTORS` in `relinkra/connectors.py`:

```python
NEWHOST = ConnectorSpec(
    connector_id="newhost",
    display_name="New Host",
    host_type="cli_agent",
    aliases=("nh",),
    support_status=SUPPORT_EXPERIMENTAL,
    executables=("newhost",),
    locations=_newhost_locations(),   # declared LocationSpec tuple
    container_path=("mcpServers",),
    config_format=FORMAT_JSON,
    entry_builder=_string_command_entry,
    format_verified=False,            # until read from a real config
    apply_available=False,            # until the write path is implemented and validated
    apply_unavailable_reason="...",
    restart_instruction="...",
)
```

Nothing in the CLI enumerates connector ids, so no dispatch code changes.

Rules for the new spec:

1. `format_verified` stays `False` until the shape is read out of a real
   configuration file. Documentation is not evidence.
2. `apply_available` stays `False` until the write path is implemented and
   validated; host launch proof is tracked separately.
3. `marker_allowed` stays `False` until that host is shown to preserve unknown
   members across a rewrite.
4. Location `display_hint` is a declared template (`~/.foo/config.json`), never
   derived from a resolved path.
5. If the entry shape is neither of the two verified ones, add an entry builder
   and an ownership matcher rather than bending an existing one.

---

## Next: R4C real-host proof

Required before any connector may claim `real_host_launch_proven`:

1. Apply a `connect plan` by hand to one real host.
2. Start that host and confirm it launches `relinkra.mcp_cli` over stdio.
3. Confirm the MCP handshake and at least one tool call succeed.
4. Confirm unrelated MCP servers in the same config still work.
5. Record the proof with the published flow:
   `relinkra connect verify <host> --proof <proof-file>`.
6. Only then set `real_host_launch_proven=True` for that connector, and only
   for that one.

Enabling `apply_available` does not establish `real_host_launch_proven`; keep
the write-path capability and host-launch proof as separate claims.
