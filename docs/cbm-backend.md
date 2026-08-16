# CBM as Relinkra's code-intelligence backend (R4C.1A)

CBM (`codebase-memory-mcp`) is a **third-party, external project**
maintained by DeusData under the MIT license
(https://github.com/DeusData/codebase-memory-mcp). It is **not bundled
with Relinkra**: it is acquired, installed, and managed independently.
Within Relinkra's architecture it acts as a *private backend* — the only
supported topology is:

```
agent -> Relinkra MCP -> CBM (cli) 
                     \-> Engram
                     \-> Git
```

Agents never talk to CBM directly. CBM is **never** registered in Claude,
OpenCode, Codex, Devin Desktop/Windsurf, or any other agent, and no CBM
installer mode that writes agent configuration, hooks, or global instruction
files is ever used. Gentleman/Gentle AI and its Engram integration are out
of scope and stay untouched.

## User workflow

Once the certified binary is in place, the index is a normal part of
working with a repository:

1. `relinkra cbm status` — shows `Index: MISSING`, `READY`, or `STALE`
   (plus the honest backend states `UNAVAILABLE`/`UNSUPPORTED`/
   `UNKNOWN`). If the executable is present but fails the certified
   checksum, status reports it as unavailable rather than usable. Every
   honest state exits 0.
2. `MISSING` → `relinkra cbm index` — builds the index into the
   workspace-managed `.codebase-memory/cache/` and registers the
   workspace-to-CBM mapping in the Relinkra registry (idempotent;
   re-running is always safe).
3. `STALE` → `relinkra cbm refresh` — full reindex with automatic
   recovery from the CBM 0.9.0 modify-only quirk (deleting exactly the
   project `.db` and its `-wal`/`-shm` companions, nothing else). When
   the drift is uncommitted worktree changes, refresh reports the
   honest `STALE` state back: commit first, then refresh.

`.codebase-memory/` (binary, cache, index databases) is derived,
rebuildable local data — normally git-ignored. If it is not, `cbm
index` prints a one-line `WARN` suggesting the ignore entry (it never
edits `.gitignore` itself).

The manual acquisition and `relinkra register` flow below remains the
advanced path for pre-existing setups.

## Certified release

| Axis | Value |
|---|---|
| Certified version | **0.9.0** |
| Upstream | https://github.com/DeusData/codebase-memory-mcp (release `v0.9.0`, published 2026-07-08) |
| Adapter contract | `cbm-cli/v1` (`cli search_graph` / `cli get_code_snippet`, flags; a JSON payload is parsed tolerantly from stdout — informational `level=info` lines can appear on either stream; failures exit non-zero with diagnostics on stderr; `CBM_CACHE_DIR` selects the cache) |
| Supported range | `>=0.9.0, <0.10.0` (inside range but not certified = *upgrade candidate only*) |
| License | MIT (upstream), third-party notices shipped with the archive |
| windows-amd64 exe SHA-256 | `9a205fa5ae759fbc866bfe1554f0c05a303be9ae6e0a00f94d875dc0c25e0680` |
| windows-amd64 zip SHA-256 | `92f96896f952e539f0d6cb34d7892a25064b677ccbf808b8f8310ad897e86f2c` |

The machine-readable pin lives in `relinkra/cbm_support.py`
(`CERTIFIED_CBM_VERSION`, `CERTIFIED_CBM_BINARIES`, supported range,
contract id). Doctor's CBM trust ladder reads it — update both together.

## Acquisition (safe, reproducible)

1. Download the release archive for the platform from the upstream
   `v0.9.0` release (version-pinned URL, never `latest`).
2. Verify the archive SHA-256 against **both** the release `checksums.txt`
   and the GitHub asset digest. Verify the unpacked executable against the
   release's published verification table.
3. Place the executable in the isolated, Relinkra-managed, git-ignored
   location `.codebase-memory/bin/` (per workspace) — never in an agent
   directory, never via `codebase-memory-mcp install` (that mode
   auto-configures agents).
4. Index into the isolated cache `.codebase-memory/cache/` with
   `CBM_CACHE_DIR` — binaries, caches, and index databases are never
   committed.
5. Record the workspace-to-CBM mapping with `relinkra register`
   (`--cbm-project-name --cbm-cache-dir --cbm-version --cbm-sha256`).

Binary resolution order at runtime: `RELINKRA_CBM_BIN` → managed
`.codebase-memory/bin/` → `PATH`.

## Upgrade detection and adoption

- Doctor reports **certified / supported-uncertified / unsupported /
  unknown** per the pin policy; anything not certified is a WARN, not a
  silent accept, and the ladder stops before index/graph/query probing.
- New upstream releases are detected (release listing) but **adopted only
  after certification**: CLI contract probe, adapter compatibility run,
  index + real query proof, and a regression pass — exactly the R4C.1A
  procedure.
- **Rollback**: replace the managed binary with the certified one (hash
  above), re-run `index_repository` if the on-disk index format changed,
  and confirm `doctor` returns to all-PASS on the CBM ladder. Relinkra
  state (registry, config, memories) is unaffected by a CBM swap.
- **Stale artifacts**: doctor flags a stale graph by comparing the
  graph's STORED index-time Branch head (via `cli query_graph`) with
  the workspace HEAD (committed drift), plus `cli detect_changes` for
  uncommitted worktree drift; also an index missing for the recorded
  project, and a binary failing the provenance hash. Relinkra
  determines freshness from these real signals only — `index_status`
  `git.head_sha` is live-derived from the repository at query time and
  alone is NOT freshness evidence.

## Compatibility fixture strategy

Contract fixtures captured from the certified binary (payload shapes for
`search_graph`, `get_code_snippet`, `list_projects`, `index_status`, error
channels and exit codes) are encoded as tests in `tests/test_cbm_backend.py`:

- mocked-subprocess fixtures pin the **historical** and **certified**
  contracts (including logs-before-JSON and the 0.9.0 not-found semantics:
  `search_graph` empty result vs `get_code_snippet` exit 1 + stderr text);
- real-binary tests run only when a CBM executable is resolvable and skip
  otherwise, so CI without CBM stays green while certified machines prove
  the real query path.

## Known contract notes (0.9.0)

### Optional structural evidence

Relinkra can optionally use two read-only CBM 0.9.0 capabilities through its
own high-level surfaces:

- `relinkra_code_architecture` returns a compact orientation with aggregate
  packages, layers, boundaries, hotspots, and language facts.
- `relinkra_code_relationships` returns bounded callers or dependencies for a
  selected symbol.

These results are advisory and are bounded before they enter a ContextPacket.
They carry the same graph freshness authority as focused code evidence. A
stale graph is labelled stale; an unavailable, missing, untrusted, or
unverifiable graph is omitted with a warning. An empty relationship result
means that no relationship was found in the current indexed graph, not that
the repository has no such relationship. Agents can always continue with
native file search, symbol navigation, inspection, editing, testing, and
validation. Relinkra does not expose CBM's raw Cypher or graph schema.

- `--name` for `index_repository` does **not** fully override the derived
  project name - the recorded slug can keep a path-derived prefix (e.g.
  `home-user-projects-myrepo-myrepo`). Relinkra treats the CBM slug as
  opaque, records it unchanged, and strips it from semantic identity in
  the adapter. Discover the real slug from the `index_repository` response
  or `list_projects`; never re-derive it.
- A missing symbol is **not** a JSON error payload: `get_code_snippet`
  exits 1 with `symbol not found` at the START of stderr. The adapter
  maps exactly this anchored form to a lookup miss (None); a failure
  whose stderr merely *contains* the phrase elsewhere (e.g. a wrapped
  "index corrupted" message) stays an outage-class `CBMAdapterError`.
- A missing/unindexed project in `search_graph` exits 1 with a JSON error
  on stderr; the adapter raises and the context pipeline degrades with a
  `cbm_unavailable` warning (honest degradation, not a silent empty).
  The same `{"error":"project not found or not indexed",...}` envelope
  from `query_graph`/`detect_changes` is classified as an honest
  missing index (`CBMProjectNotIndexedError`), never an outage and
  never fresh.
- Freshness signals (0.9.0): `cli query_graph` `MATCH (n:Branch) RETURN
  n.head_sha` returns the graph's STORED index-time head — the
  authoritative anchor. `index_status` `git.head_sha` is LIVE-DERIVED
  from the repository HEAD at query time and is not freshness
  evidence. `cli detect_changes` reports UNCOMMITTED worktree drift
  only (a clean worktree after commits reports clean) and may emit
  duplicate `changed_files` entries; the adapter dedupes them, while
  `changed_count` stays CBM's raw count (duplicates included) — so the
  two values can legitimately differ.
- Re-index quirk (0.9.0): `index_repository` over an existing database
  refreshes the stored Branch head only when NEW files appeared since
  the last index; a modify-only change keeps the old stored head, so
  the freshness check honestly stays stale until a clean-cache
  re-index (delete the project db, then re-index).
- Doctor's ladder verifies provenance (SHA-256) BEFORE executing the
  binary; a mismatch stops the ladder. A backend that cannot answer is
  reported "index/graph state unknown — backend not reachable", never
  "index missing" (re-indexing is only prescribed when a WORKING backend
  confirms absence). Doctor probes use a 10s timeout per stage.
- If `cbm status` reports an unavailable or untrusted executable, re-acquire
  the certified `0.9.0` release and verify its published checksum. Relinkra
  does not run an executable that fails that check.
- Certification requires the exact stable `0.9.0` string; prerelease and
  build variants such as `0.9.0-rc1` and `0.9.0+dirty` are not certified.
- Registry/service `cache_dir` values must resolve inside the workspace's
  `.codebase-memory/cache` subtree. Invalid values produce a warning and are
  never forwarded as `CBM_CACHE_DIR`.
- Child processes receive a minimal environment (`PATH`, Windows system
  roots, and stable locale values), no stdin, and never inherited credentials
  or sentinel variables. Stdout/stderr are rejected above the adapter's hard
  output limit after subprocess capture and before JSON parsing; the current
  standard-library adapter does not claim a streaming memory bound.
- After trust succeeds, production adapters re-check the certified SHA-256
  immediately before each subprocess execution. This narrows replacement
  races but does not claim complete TOCTOU or supply-chain elimination.
- Configuration-created adapters used by Relinkra services and the legacy
  context CLI must pass the complete ladder: binary, provenance, managed
  cache, certified version, present index, workspace/HEAD-bound graph, and a
  real query. Missing graph metadata is WARN/unknown and never advances to a
  query. Explicit adapter injection remains a test seam, not agent wiring.
- Probing has side effects in the managed cache only: CBM may create
  SQLite `-shm`/`-wal` companions next to the index db (WAL-safe,
  git-ignored). Deep health probes are TTL-capped (60s) per services
  instance so agent-triggered `health(deep=true)` cannot spawn unbounded
  subprocesses.
- `install`/`update`/`config`/bare-server modes exist upstream but are
  forbidden here: only `cli` tool invocation and `--version` are used.
