# CBM as Relinkra's code-intelligence backend

Codebase Memory (CBM, `codebase-memory-mcp`) is a third-party, optional
backend maintained by [DeusData](https://github.com/DeusData/codebase-memory-mcp)
under the MIT license. It is not bundled with Relinkra.

The supported topology is:

```
agent -> Relinkra MCP -> CBM CLI
                     \-> Engram
                     \-> Git
```

Agents do not talk to CBM directly. Relinkra owns the normal route, and CBM is
never added directly to Claude, OpenCode, Codex, ZCode, Devin Desktop, or any
other agent configuration.

## Public lifecycle

CBM is optional. Without it, Relinkra continues with native Git and agent
capabilities and reports the missing backend honestly.

### 1. Set up the optional binary

```bash
relinkra cbm setup
```

Setup downloads the certified release for a certified platform, verifies the
archive and executable against pinned SHA-256 digests, probes the version, and
installs it in a per-user Relinkra-managed location. It is idempotent.

For an offline local asset:

```bash
relinkra cbm setup --from-file PATH
relinkra cbm setup --json
```

`setup` refuses to download or execute a release with no certified platform
record. It also refuses a checksum or version mismatch before activation.

### 2. Inspect backend and index state

```bash
relinkra cbm status
```

The status command distinguishes `MISSING`, `READY`, and `STALE` index states,
plus honest backend states such as `UNAVAILABLE`, `UNSUPPORTED`, and `UNKNOWN`.
An honest degraded state is not silently treated as a usable index.

### 3. Build or refresh the graph

When status is `MISSING`:

```bash
relinkra cbm index
relinkra cbm index --path PATH --json --mode fast
```

`cbm index` builds the workspace index under
`.codebase-memory/cache/` and registers the workspace-to-CBM mapping in the
Relinkra registry. It is safe to repeat. This is the public registration route.

When status is `STALE`:

```bash
relinkra cbm refresh
relinkra cbm refresh --path PATH --json --mode fast
```

`refresh` reindexes the workspace. If committed or uncommitted drift prevents
a fresh graph, it reports the stale state instead of claiming success. The
certified CBM 0.9.0 modify-only behavior can require a clean-cache recovery;
Relinkra owns that bounded recovery and removes only the affected project
database and its `-wal`/`-shm` companions.

`--path` selects the repository path for the operation. `--json` emits the
machine-readable result. `--mode fast` selects the supported fast lifecycle
mode for `index` and `refresh`.

## 0.1.2 stale doctor wording

The published 0.1.2 `doctor` output can still mention `relinkra register`.
That wording is stale and should be ignored: the public product does not expose
that command. Use `relinkra cbm index`, which owns workspace registration.
This is a non-blocking 0.1.3 UX issue. This documentation does not add a
runtime compatibility command.

## Certified release and platform boundary

| Axis | Value |
|---|---|
| Certified version | **0.9.0** |
| Certified binary | Windows-amd64 / Windows-focused |
| Supported range | `>=0.9.0, <0.10.0`; supported is not the same as certified |
| Upstream | [DeusData/codebase-memory-mcp](https://github.com/DeusData/codebase-memory-mcp) |
| Adapter contract | `cbm-cli/v1` |
| Windows-amd64 executable SHA-256 | `9a205fa5ae759fbc866bfe1554f0c05a303be9ae6e0a00f94d875dc0c25e0680` |
| Windows-amd64 archive SHA-256 | `92f96896f952e539f0d6cb34d7892a25064b677ccbf808b8f8310ad897e86f2c` |

Linux and macOS have CI coverage but no certified CBM binary. On those
platforms `setup` may report `NOT_CERTIFIED`, and `doctor` reports the
limitation; Relinkra continues without CBM. A CI fixture is not CBM
certification.

The managed binary is resolved in this order: `RELINKRA_CBM_BIN`, the
per-user Relinkra-managed location, workspace `.codebase-memory/bin/`, then
`PATH`. Relinkra verifies the certified SHA-256 before executing the binary.

## Files and safety

`.codebase-memory/` contains derived binaries, caches, and index databases. It
is rebuildable and should remain gitignored. If it is not ignored, `cbm index`
prints a warning but does not edit `.gitignore`.

The workspace registry can contain machine-specific paths. Do not commit
`.relinkra/` or `.codebase-memory/`, and do not place CBM configuration in an
agent's own configuration directory.

## Optional structural evidence

When a trusted, fresh graph is available, Relinkra may use bounded structural
results such as architecture orientation and caller/dependency relationships.
These results are advisory, budgeted, and freshness-labelled. An unavailable,
missing, stale, or unverifiable graph is omitted with a warning. Agents can
always continue with native search, symbol navigation, editing, testing, and
validation.

Relinkra does not expose CBM's raw Cypher or graph schema. Upstream install,
update, config, and bare-server modes are not used because they can configure
agents outside Relinkra's ownership boundary.
