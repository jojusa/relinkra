# Changelog

All notable changes to Relinkra are documented here. The format is a
lightweight take on [Keep a Changelog](https://keepachangelog.com/).

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
