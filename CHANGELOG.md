# Changelog

All notable changes to Relinkra are documented here. The format is a
lightweight take on [Keep a Changelog](https://keepachangelog.com/).

## Unreleased — 0.1.4 fresh-user recertification

Not yet published; no version bump. This section records the 0.1.4 core
surfaces (R6B–R6D) and the documentation finalization (R6G). The R6E and
R6F sections below are part of the same unreleased 0.1.4 pool.

### Added

- `memory_get(memory_id)`: a deterministic exact-record lookup on the MCP
  surface. Same id returns the same logical record; no fuzzy fallback
  (`found=false` when the id does not exist or is outside the caller's
  channels). Handoff mirror records are retrievable here; `handoff_get`
  remains authoritative for handoff workflow state.
- Deterministic memory retrieval: `memory_search` returns a stable total
  order (oldest first, `memory_id` tiebreak) — identical inputs return
  identical results.
- Handoff/memory dedupe: duplicate handoffs on the same topic supersede
  the older mirror record instead of accumulating.
- `include_tests` on `code_relationships`: test-code relationships are
  excluded by default and can be included explicitly when callers living
  in test files matter.
- ContextPacket salience: every packet item carries an agent-visible tier
  (`must_keep` / `high_salience` / `optional`), `must_keep` items (the
  essential frame, the current handoff, pending work) are protected from
  budget omission, and `optional` items are sacrificed first.
- Truncation truth on the packet `packet_status` block:
  `packet_complete`, `budget_exhausted`, `omitted_sections`,
  `omitted_high_salience_count`, `recommended_next` (deterministic
  recovery hints naming real MCP tools), and a conservative
  `context_sufficiency`. Snippet truncation is explicit
  (`snippet_truncated`, original/returned lengths, continuation
  reference) with `truncated_source_ids` in the budget report. Nothing
  disappears silently.
- Budget guidance: `budget_unsatisfiable` errors and budget reports carry
  deterministic `minimum_useful_tokens` (the cpt1 cost of the must-keep
  skeleton) and `recommended_max_tokens` (nothing high-salience omitted) —
  guidance, never a bare retry.
- Token-efficiency observability: `cpt1` char-per-token accounting and
  the `budget_report` (with `useful_payload_tokens`, `metadata_tokens`,
  `compression_ratio`, duplicate suppression counts) are returned with
  `context_get`; unbudgeted agent-facing packets carry the additive
  status block too.
- Automatic runtime evidence: the MCP server self-observes while serving
  (server start, client handshake, `tools/list`, tool invocations, memory
  and CBM activity) and persists the evidence automatically — doctor can
  see a host was real without any manual proof file. Self-observed
  evidence remains distinct from the stronger external `connect verify`
  proof.
- Doctor `PENDING` state: "not yet proven" is reported distinctly from
  `WARN` ("a real condition worth attention"); neither changes the exit
  code — only `FAIL` does.

### Changed

- `memory_search` no longer includes handoff mirror records by default.
  To retrieve handoffs: use `handoff_get` (authoritative), expand a known
  mirror id with `memory_get(id)`, pass `include_handoffs=true`, or
  filter `memory_type="handoff"` (mirrors are auto-included there).
- `relinkra doctor` is compact by default — core groups, one agent row
  per apply-capable host, one suggested next action — with `--verbose`
  for the full per-check diagnostics. Both views render from the same
  payload; the compact view is a projection, never a second opinion.
- README restructured as a public product document: a six-command quick
  start (`init` → `cbm setup` → `cbm index` → `connect all` → `doctor`),
  an explicit two-level split (Level A quick start, Level B advanced
  safe-control commands), and the memory/context surface guide. Relinkra
  remains Relinkra-first, source-authoritative, and expand-on-demand;
  token optimization removes redundancy, never evidence.

### Fixed

- Final-packet token accounting: the `packet_status` cpt1 totals now
  measure the exact delivered packet — the block is settled onto the
  packet before measurement instead of being appended afterwards, so
  unbudgeted packets no longer under-count the bytes they ship. The
  same re-settlement runs after post-ladder metadata attach on budgeted
  packets. At an exact digit boundary no self-consistent state exists;
  the settle then ships the deterministic conservative state (at most
  one token over, never under). These are cpt1 approximations over the
  serialized packet, not exact provider tokenizer counts.

## Unreleased — R6E multiagent UX and routing

Not yet published; no version bump.

### Added

- `relinkra connect all`: a multiagent front door that runs every default
  target (`codex`, `opencode`, `claude`, `devin-desktop`, `zcode`) through
  its own per-agent inspect/check/plan/preflight/confirmation/apply
  pipeline, with a per-host summary table, per-host confirmation, and
  fail-closed behavior for refused or malformed hosts.
- `connect check --verbose` for the full report; the default check output
  is now compact and host-local (config, workspace, generated state,
  runtime evidence, one next action).
- `connect inspect` now exposes `workspace_matches` directly.
- Relinkra-first routing order and Engram coexistence guidance, surfaced
  in `connect list` and `connect all` output and the agent-instruction
  contract.

### Changed

- Runtime evidence moved to one bounded file per host
  (`.relinkra/runtime-evidence/<host>.json`): concurrent hosts can no
  longer lose each other's evidence through a shared-file
  read-modify-write. The pre-R6E single-file store remains readable; no
  migration is required.
- An unreadable current Git revision now reports runtime evidence as
  `unknown`, never `stale`, and proves no current-revision stages.
- Runtime evidence exclude handling covers linked worktrees by writing
  the repository-local exclude into the Git common directory, keeping
  worktree status clean.
- The self-observed handoff claim is worded truthfully as "handoff write
  and read served" — no handoff-id correlation is persisted.
- ZCode generated state (`.zcode/config.json`, `.zcode/config.json.lock`)
  is classified: git-ignored and Git-clean is healthy (no warning);
  generated state showing in Git warns precisely. Relinkra still never
  deletes the lock file or edits `.gitignore`.
- A missing host executable is reported together with the fact that
  workspace configuration can still be prepared, instead of a bare
  not-installed state.

## Unreleased — R6F residual trust and local-state hardening

Not yet published; no version bump.

### Changed

- Runtime-evidence recording takes a bounded per-host interprocess lock
  around the read-modify-write critical section: two concurrent processes
  of the same host can no longer overwrite each other's evidence. A
  writer that cannot take the lock in time skips its record —
  conservative under-reporting, never trust inflation, never blocked MCP
  serving. OS-level locks die with their holding process, so an abandoned
  writer cannot wedge the store.
- Concurrent first-time startups no longer append duplicate `.relinkra/`
  rules to `.git/info/exclude`: the check-then-append cycle runs under
  the same bounded lock discipline (the lock file lives beside the
  exclude file in the git directory and never dirties git status).
- `relinkra cbm index` and a `relinkra cbm refresh` that reaches `READY`
  report a concise successful-index summary: `nodes`, `edges`, the
  workspace `revision`, `freshness` drift flags, and measured
  `elapsed_seconds` (additive JSON fields; a files-indexed figure is not
  reported by the backend and is not invented).

### Documentation

- The ignore-policy guidance now states truthfully, per path
  (`.relinkra/`, `.codebase-memory/`, `.zcode/config.json` + lock,
  `*.relinkra-backup*`), who owns it and whether it is ignored,
  visible/untracked, or tracked unexpectedly — and a dirty `git status`
  is attributed to Relinkra/ZCode only when the dirty paths are theirs.

## 0.1.3 — release-preparation candidate

This candidate is not yet published.

### Changed

- Clarified explicit registered-versus-current revision semantics, including
  `project_resolve` freshness and current-revision reporting.
- Kept `context_get` revision and freshness output consistent.
- Added doctor/trust divergence detection.
- Added the safe `connect <agent>` front door.
- Hardened connector safety.
- Added a bounded optimistic concurrency model.
- Added expected-absence preconditions.
- Revalidated terminal authority before completion.
- Fixed rollback ownership and provenance handling.
- Improved Git/generated-state onboarding.
- Improved the README quick start.

## 0.1.2

First public PyPI release. The published 0.1.2 package artifacts were built
from release source commit `8afd3245347dea9cda93176384421d33fdfd69b3`.
This later documentation-only closure does not change the package artifacts,
their build source, or the public version, and does not republish 0.1.2.

The public release includes the 0.1.1 product baseline, optional CBM and
Engram integrations, host connectors, and the bounded context/freshness
behavior documented below. Windows is certified for the product; Linux/macOS,
CBM breadth, and real-host connector launch coverage retain their stated
evidence boundaries.

Known non-blocking follow-up: some published 0.1.2 doctor wording still
mentions the nonexistent public `relinkra register` command. The public CBM
route is `relinkra cbm index`; the runtime compatibility fix is deferred to
0.1.3.

## 0.1.0

First Relinkra release: shared code intelligence, persistent memory, and
optimized context for AI coding agents — one codebase, one shared context,
many agents. Ships the full content verified across the 0.1.0rc2 candidate
plus the final pre-release work below.

### Added

- MCP stdio server (`relinkra-mcp`) that agent hosts connect to.
- Shared persistent memory and handoffs via the external, optional Engram
  integration (not bundled; degrades honestly when absent).
- Code intelligence via the external, optional CBM backend (not bundled;
  certified with the real binary on Windows), acquired through managed
  discovery: `relinkra cbm setup` installs the checksum-certified backend
  per user, so normal users never configure binary paths.
- Context packets with token budgets, plus freshness and contradiction
  detection.
- Compact architecture orientation and bounded caller/dependency traversal
  for structural evidence.
- User-facing CBM lifecycle (`cbm status`, `cbm index`, `cbm refresh`) with
  trusted automatic registration and provenance checks before every
  executable invocation.
- Git intelligence over the local repository (read-only).
- Host connectors for Claude, OpenCode, Codex, and Devin Desktop, with
  backup, atomic write, and rollback on every mutation.
- CI and packaging evidence gates (`tools/release_check.py` and friends)
  that fail closed: absence of evidence is never PASS.

### Changed

- Contradiction handling hardened with machine-readable resolution status:
  current-source evidence is preferred for current-code claims, stale
  memory stays visible and qualified, and unresolved conflicts remain
  explicitly unresolved instead of being silently collapsed.
- CBM freshness derives from the stored graph head and real source changes;
  provenance checks gate executable invocations, including refresh and
  bounded recovery paths.
- Fresh-user installation diagnostics isolated from developer-environment
  assumptions; cross-platform path equivalence hardened (Windows 8.3
  aliases, macOS `/private` aliases).

### Security & Safety

- No `shell=True` anywhere; launch contracts are structured data.
- Host-config writes are backup-first, atomic, and validated after write.
- Workflow hygiene is enforced: minimal permissions, no untrusted
  triggers, pinned actions.
- Evidence fragments are bound to an exact commit SHA and CI run id.

### Validation and limitations

- Agents retain native file search, inspection, editing, testing, and
  validation tools; Relinkra evidence is advisory and may be incomplete.
- Replicated exploratory testing showed promising reductions in exploration
  on complex cross-module tracing tasks while preserving critical-context
  quality.
- CBM is certified on Windows only; on Linux/macOS it degrades honestly.
- Host real-launch certification is historical local evidence, not
  regenerated by CI.
- Devin Cloud is unsupported (roadmap).

## 0.1.0rc2 — release candidate

This release candidate improves the path from an agent request to compact,
project-aware evidence. It is not the final 0.1.0 release and has not been
published to PyPI.

### Changed

- Corrected CBM freshness derivation from the stored graph head and real
  source changes.
- Added the user-facing `cbm status`, `cbm index`, and `cbm refresh` lifecycle
  with trusted automatic registration.
- Hardened CBM provenance checks before every executable invocation,
  including refresh and bounded recovery paths.
- Added compact architecture orientation and bounded caller/dependency
  traversal for structural evidence.
- Added bounded CBM architecture and relationship evidence to ContextPackets,
  preserving freshness, coverage, relevance, and budget metadata.
- Hardened cross-platform path-equivalence tests for Windows 8.3 aliases and
  macOS `/private` path aliases.

### Validation and limitations

- CBM remains optional and is certified with the real binary on Windows;
  Linux/macOS behavior degrades honestly when the backend is unavailable or
  not certified.
- Agents retain native file search, inspection, editing, testing, and
  validation tools; CBM evidence is advisory and may be incomplete.
