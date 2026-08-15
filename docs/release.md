# Release verification for Relinkra

How a maintainer verifies that a Relinkra release is releasable: what the CI
workflows prove, what they do not, how the eleven release gates read
evidence, and what remains open before a public release. This document
describes the verification work delivered in work units R5B, R5C, and
R5D.

> **Status: CI-VERIFIED.** The CI workflows below have executed remotely
> and are green (remote full regression, packaging, and installed-MCP
> evidence: PASS). Checkable proof: CI run
> [31815886965](https://github.com/jojusa/relinkra/actions/runs/31815886965)
> and Packaging run
> [31815886882](https://github.com/jojusa/relinkra/actions/runs/31815886882),
> both bound to commit `60062ec0`. What remains open is tracked in
> [Remaining evidence debt](#remaining-evidence-debt).

## Scope

R5B delivers release *verification*: local test tooling, an artifact
content contract, an evidence-driven gate model, and three GitHub
workflows that run it all.

R5B is **not** publication. Nothing here uploads to PyPI, creates a
GitHub Release, or pushes a git tag. RC tagging is not approved yet;
publication requires the blockers in
[Remaining evidence debt](#remaining-evidence-debt) to be resolved.

## Verification levels

Every claim about "works on X" carries exactly one of these levels:

| Level | Meaning |
|---|---|
| **IMPLEMENTED** | The code exists and local tests exercise it (fixtures, sandboxes, fakes). |
| **CI-VERIFIED** | A remote GitHub Actions run proves it on a real runner, per OS and Python version. |
| **REAL-HOST-CERTIFIED** | A real machine ran the real integration end-to-end and the result was recorded as evidence. |

**The fixture rule:** a CI fixture or sandbox connector test that passes
is CI-VERIFIED (once CI runs), but it is **never** host or CBM
certification. Real-host certification requires the real binary on the
real host. Do not blur these levels — overstating a level is the exact
failure this document exists to prevent.

## CI map

Three workflows under `.github/workflows/`. Common trust model (enforced
by `tests/test_ci_hygiene.py`): top-level `permissions: contents: read`,
no `pull_request_target`, no secrets, every action pinned to a major tag
(`checkout@v7`, `setup-python@v7`, `upload/download-artifact@v7`), no
`continue-on-error`.

### `ci.yml` — CI

| Job | Runner / Python | What it proves | What it does NOT prove |
|---|---|---|---|
| `fast` | ubuntu / 3.14 | Byte-compiles package + tools; runs the five audit suites (`test_packaging`, `test_tools_core_runner`, `test_release_gates`, `test_platform_honesty`, `test_ci_hygiene`), one run step each so a failure points at its suite. | Runtime behavior on real interpreters/OSes. |
| `core` (matrix) | ubuntu × py3.9–3.14; windows × py3.9 + 3.14; macos × py3.11 + 3.14 | Installs the package (`pip install .`), smokes the installed console scripts from a throwaway directory (`relinkra init`, `relinkra doctor --json`), runs the core suite via `tools/run_core_tests.py`. | The two slow venv E2E suites (packaging workflow covers them); host/CBM certification. |
| `full-regression` (matrix) | ubuntu, windows, macos × py3.14 | Full suite via `tools/emit_run_evidence.py --run-regression` (ResourceWarning promoted to error in-process, mirroring `release_check.run_regression`) — 0 failures, 0 errors, 0 ResourceWarnings required; each cell emits a SHA-bound evidence fragment (`run-evidence-<platform>.json`, uploaded with `if: always()`, `retention-days: 1`). | Anything beyond 3.14; artifact installability. |
| `release-readiness` | ubuntu / 3.14 (`if: always()` after the above) | Downloads the run-evidence fragments unmerged, composes them with `tools/compose_run_evidence.py` (bound to `github.sha`/`github.run_id` + upstream job results), computes the gate report with `release_check.py --evidence composed-evidence.json --require-sha <sha> --run-packaging`, uploads `release-report.json` (`if: always()`), appends a human summary. Asserts no `--require` level. | That any release safety actually holds — it reports, it does not gate. |

### Run-scoped remote evidence (R5C)

Remote evidence is **generated per CI run**, never committed, and never
maintainer-attested:

1. **Emit** — each `full-regression` matrix cell runs
   `tools/emit_run_evidence.py --run-regression`, which executes the full
   suite in-process and writes `run-evidence-<platform>.json`:
   `{"meta": {sha, run_id, job, os}, "platform", "regression": {passed,
   tests, failures, errors, resource_warnings, where}}`. The fragment is
   byte-deterministic (sorted keys, LF endings, no timestamps) and is
   uploaded as an ephemeral artifact (`retention-days: 1`).
2. **Compose** — `release-readiness` downloads every `run-evidence-*`
   artifact **unmerged** (duplicate platform fragments stay detectable)
   and runs `tools/compose_run_evidence.py`, which fails closed (exit 2)
   on malformed fragments, stale/cross-commit sha, cross-run `run_id`,
   duplicate or unexpected platforms, unknown upstream results, or a
   fragment missing although its cell succeeded.
3. **Bind** — `release_check.py --evidence composed-evidence.json
   --require-sha "$GITHUB_SHA"` re-validates `meta.sha` **before**
   evaluating any gate; a mismatch exits 2. The sha is never compared
   against the local git HEAD — the caller supplies the trusted reference
   (`GITHUB_SHA`), so installed-package / off-checkout execution cannot
   fail falsely.

**Aggregate semantics (fixed decision):** the composed
`regression.tests` is the *aggregate* number of test executions across
all matrix cells (the full-suite count multiplied by three when every
cell runs the full suite);
`failures`/`errors`/`resource_warnings` are likewise sums. Per-cell
canonical counts live in `regression.cells`. `regression.passed`
requires at least one cell, every present cell passed, and no degraded
(missing) cell.

**Degraded-report behavior:** if a platform fragment is missing *and*
its upstream did not succeed (failure/cancelled), the composer omits that
platform key — the gate model honestly yields PARTIAL for it — and sets
`ci.remote_runs_passed=false`. A fragment with `passed=false` maps the
platform to `"fail"`. Any cancelled/failure/skipped upstream result also
forces `remote_runs_passed=false`. Nothing unexpected is ever converted
into PASS.

**Honesty notes.** This evidence chain cannot certify CBM on Linux/macOS
(there is no certified binary) and says nothing about real-HOST
certification — those gates keep their own evidence requirements. Remote
generation has happened: the remote CI runs are green and their evidence
is consumed through exactly this chain.

### `packaging.yml` — Packaging

| Job | What it proves | What it does NOT prove |
|---|---|---|
| `build` (ubuntu / 3.14) | `python -m build` produces wheel + sdist; `tools/artifact_checks.py` enforces the content contract; `SHA256SUMS.txt` records digests; artifacts uploaded once. | Installability — that is the point of the downstream jobs. |
| `wheel-install` (matrix) | 6 cells — ubuntu 3.9/3.14, windows 3.9/3.14, macos 3.11/3.14 — each downloads the **exact built wheel** and installs it via `test_install_e2e.py` (`RELINKRA_E2E_ARTIFACT`), sandboxing HOME/USERPROFILE/APPDATA/XDG_CONFIG_HOME/CODEX_HOME and proving source-tree independence. | Anything about other wheels — only this artifact, by design. |
| `sdist-install` (matrix) | 3 cells — ubuntu/windows/macos × py3.14 — pip builds from the **exact built sdist** (PEP 517 isolated) via `test_sdist_install_e2e.py`, proving the sdist is self-sufficient. | Same one-artifact scope as wheel-install. |

### `release-dry-run.yml` — Release Candidate Dry Run

`workflow_dispatch` only. Runs the RC report and builds artifacts on
ubuntu/windows/macos × py3.14. Never publishes, never tags. See
[RC dry-run](#rc-dry-run).

## Python support

- **Floor: Python 3.9.** The core product runs on 3.9+; zero runtime
  dependencies.
- **Matrix: 3.9 through 3.14.** Ubuntu covers the full floor-to-current
  range; Windows covers floor + current (3.9, 3.14); macOS runs 3.11 and
  3.14 — the floor versions are already covered on ubuntu/windows, and
  3.9 on macOS carries an arm64 runner availability risk.
- **Codex TOML connector needs 3.11+** (standard-library `tomllib`). On
  3.9/3.10 the connector reports the capability as unsupported
  (`FAIL_HONEST`); the rest of the product works. The 3.9/3.10 CI cells
  verify this path through the existing suite.

## Platform honesty

**Codebase Memory (CBM)** is a third-party, external backend
([DeusData](https://github.com/DeusData/codebase-memory-mcp), MIT —
never bundled with Relinkra) with a certified, sha256-pinned provenance
of **windows-amd64 v0.9.0 only**. There is no
certified Linux or macOS binary. Off Windows, `relinkra doctor` WARNs
honestly and the integration ladder stops before execution; CI verifies
the absence/degraded behavior — and a CI fixture passing is **not** CBM
certification.

**Host connectors** (Claude, OpenCode, Codex, Devin Desktop) are
real-host certified **locally**, as historical recorded evidence — the
certification is not regenerated per CI run. CI runs fixture/sandbox
connector tests only. **Devin Cloud is UNSUPPORTED** (roadmap).

**Engram** is optional: a third-party project (Gentleman Programming,
MIT), external and never bundled with Relinkra. Relinkra talks to it via
CLI subprocess plus loopback HTTP (127.0.0.1:7437, 2s timeout), with
graceful degradation when absent.

## Release gates

`tools/release_gates.py` maps an evidence mapping to eleven gate
verdicts. Statuses: `PASS`, `PARTIAL`, `BLOCKED`, `NOT_APPLICABLE`.

**The critical semantic: absence of evidence is never PASS.** A gate
with no evidence is PARTIAL (unknown), never green. A gate that cannot
possibly apply is NOT_APPLICABLE, never PASS.

| Gate | Evidence it reads | PASS means |
|---|---|---|
| `TECHNICAL_CORE` | `regression` (passed/tests/failures/errors/resource_warnings) | Full suite passed with 0 failures, 0 errors, 0 ResourceWarnings. |
| `PACKAGING` | `packaging` (wheel_ok/sdist_ok) | Both artifacts satisfy the content contract. |
| `WINDOWS` / `LINUX` / `MACOS` | `platforms.<os>` | Passing regression evidence on that OS. |
| `CBM_CERTIFICATION` | `cbm.certified_platforms` | All desktop platforms certified. Windows-only is PARTIAL; claiming a non-Windows platform without evidence is BLOCKED. |
| `HOST_CERTIFICATION` | `hosts.certified_hosts` + `regenerated_in_ci` | Certified hosts **and** certification regenerated in CI; historical local certification is PARTIAL. |
| `DOCUMENTATION` | `docs` (release_doc, readme_sections, installation_doc) | This document, the README sections, and the installation guide all present. |
| `LEGAL` | `legal.license_present`, `notice_complete` | LICENSE file exists. No LICENSE is BLOCKED — distribution rights undefined. |
| `SECURITY` | Workflow hygiene scan | Minimal permissions, no untrusted triggers, actions pinned. |
| `CI` | `ci.workflows_present`, `remote_runs_passed` | Workflows present **and** remote runs green. Present-but-unrun is PARTIAL (`REMOTE_CI_PENDING`). |

### Rollup decisions

| Safety | Requirements |
|---|---|
| `safe_to_merge` | `TECHNICAL_CORE`, `PACKAGING`, `SECURITY` PASS; `CI` PASS or PARTIAL; no BLOCKED among the four. |
| `safe_to_tag_rc` | `safe_to_merge`, plus `WINDOWS`, `LINUX`, `MACOS`, `CI` all PASS, `DOCUMENTATION` at least PARTIAL. A `LEGAL` BLOCKED is surfaced but tolerated for an internal RC tag; any other BLOCKED vetoes the tag. |
| `safe_for_public_release` | Every gate PASS, except `CBM_CERTIFICATION` and `HOST_CERTIFICATION`, which may be PARTIAL as documented evidence debt. `LEGAL` and `DOCUMENTATION` must be PASS. |

### Reading `release_check.py` output

`tools/release_check.py` collects local evidence (read-only, no service calls,
no git mutation), evaluates the gates, and prints a text summary or JSON
(`--json`). Exit codes: **0** when the report was computed — even with
PARTIAL/BLOCKED gates; **1** when `--require` fails; **2** when a
collector crashes or `--require-sha` validation fails. `--require-sha
SHA` binds `--evidence` to a commit: the external evidence must carry
`meta.sha` equal to `SHA` (non-empty), validated before any gate runs;
without `--evidence` it exits 2. The opt-in `--run-packaging` path may acquire build
dependencies, separately from runtime/offline behavior. An exit 0 therefore means "reported", not "releasable"
— use `--require` to assert a safety.

Current report (collector evidence only): `TECHNICAL_CORE`, `PACKAGING`,
and the platform gates are PARTIAL (no regression/packaging evidence
until `--run-regression`/`--run-packaging` runs); `SECURITY` PASS;
`LEGAL` PASS (LICENSE present, MIT); `CI` PARTIAL (`REMOTE_CI_PENDING`).
Fed with composed run-scoped remote evidence (`--evidence`), the
technical, platform, and `CI` gates evaluate to the remote truth.

## Local verification commands

All commands run from the repository root.

```bash
# Full regression (canonical; the full suite, takes minutes)
python -W error::ResourceWarning -m unittest discover -s tests -q

# Core subset (full suite minus the two venv E2E files; exclusions explicit)
python -W error::ResourceWarning tools/run_core_tests.py
python tools/run_core_tests.py --list   # show included/excluded inventory

# Artifact contract + sha256 (build first, then inspect)
python -m build
python tools/artifact_checks.py dist/*   # bash; on PowerShell pass
# explicit paths — PowerShell does not expand the glob:
# python tools/artifact_checks.py dist/relinkra-0.1.0rc1-py3-none-any.whl dist/relinkra-0.1.0rc1.tar.gz

# Bounded release check (collectors only — fast, read-only)
python tools/release_check.py --json

# Release check with real evidence (regression takes minutes)
python tools/release_check.py --run-regression --run-packaging --json

# Assert a safety level (exit 1 when not satisfied)
python tools/release_check.py --require merge
python tools/release_check.py --evidence external.json --require rc

# Focused E2E: install the exact artifact under test (as packaging.yml does)
# bash:
RELINKRA_E2E_ARTIFACT=/path/to/relinkra-0.1.0rc1-py3-none-any.whl \
  python -W error::ResourceWarning -m unittest discover -s tests -p "test_install_e2e.py" -q
RELINKRA_E2E_ARTIFACT=/path/to/relinkra-0.1.0rc1.tar.gz \
  python -W error::ResourceWarning -m unittest discover -s tests -p "test_sdist_install_e2e.py" -q
# PowerShell equivalents:
# $env:RELINKRA_E2E_ARTIFACT = "C:\path\to\relinkra-0.1.0rc1-py3-none-any.whl"
# python -W error::ResourceWarning -m unittest discover -s tests -p "test_install_e2e.py" -q
# $env:RELINKRA_E2E_ARTIFACT = "C:\path\to\relinkra-0.1.0rc1.tar.gz"
# python -W error::ResourceWarning -m unittest discover -s tests -p "test_sdist_install_e2e.py" -q
```

Without `RELINKRA_E2E_ARTIFACT`, the E2E suites build their own artifact
(with network) inside their venv sandbox. With it, they install exactly
the given wheel or sdist — which is how CI proves the shipped artifact,
never a rebuild.

One environment prerequisite, verified while writing this document:

- **Building artifacts locally** (`python -m build`,
  `release_check.py --run-packaging`) needs the build frontend and
  backend available: `python -m pip install build setuptools`. A bare
  interpreter still builds the wheel through pip's isolated fallback but
  fails the sdist step. CI installs these explicitly; the failure is
  environmental, not a product defect.

The core runner mirrors `unittest discover -s tests` path semantics on its
own: it inserts both the repository root and `tests/` into `sys.path`
before loading test modules, so bare sibling imports between test files
(`from test_context_packet import ...`, `import git_fixtures`) resolve
without any `PYTHONPATH` setup — locally and in CI `core` cells alike.

## RC dry-run

Trigger: GitHub Actions → *Release Candidate Dry Run* → *Run workflow*
(`workflow_dispatch` only). Runs on ubuntu, windows, and macos × py3.14.

Each cell produces an uploaded artifact set `rc-dry-run-<os>` containing
`dist/` (wheel + sdist, inspected by `tools/artifact_checks.py`) and
`rc-report.json` (gate report computed with `--run-regression
--run-packaging`). A human gate summary lands in the step summary.

The dry run **never** asserts `--require public`, **never** uploads
outside CI artifacts, **never** tags, and **never** publishes. It is an
RC realism rehearsal, not a release.

## Versioning policy

- Version 0.1.0rc1 (release candidate for 0.1.0), single-sourced in `relinkra/__init__.py`
  (`__version__`); `pyproject.toml` reads it dynamically
  (`version = { attr = "relinkra.__version__" }`), guarded by
  `tests/test_packaging.py`.
- Pre-1.0 semver: **minor** bumps may add features or break compat;
  **patch** bumps are fixes only.
- The bump happens **only** in a dedicated release commit by the
  maintainer — never mixed into feature work.
- RC naming is `0.1.0rcN`, only if and when tagging is approved. R5B
  does not tag.

## Legal and NOTICE readiness

- **LICENSE present: MIT.** The repository root carries an MIT LICENSE
  file (copyright José Julián Sánchez Rodríguez, 2026), chosen by the
  owner. The `LEGAL` gate passes. The package metadata declares the MIT
  license as a PEP 639 SPDX expression.
- There is no NOTICE/THIRD_PARTY file for Relinkra itself, and none is
  required for the current package contents: the wheel ships only
  `relinkra/**` with no bundled third-party code. Re-evaluate if bundled
  content ever changes.
- The vendored CBM payload under `.codebase-memory/` carries its own
  LICENSE and THIRD_PARTY_NOTICES, but it is **not shipped** in the
  package (the artifact contract forbids it). CBM itself is a
  third-party project (DeusData, MIT), not bundled with Relinkra.
- Engram is likewise a third-party project (Gentleman Programming, MIT),
  external and optional, never bundled.
- The README attributes Codebase Memory MCP and Engram.

## Remaining evidence debt

Pre-existing debt the tooling surfaces honestly rather than hiding:

- ~~**Python 3.9/3.10 machine certification**~~ — **resolved**: verified
  by the remote CI matrix runs.
- ~~**Linux/macOS real-run verification**~~ — **resolved**: the remote
  CI runs are green on Linux and macOS.
- **CBM provenance Windows-amd64 only** — no certified Linux/macOS
  binary; honest degradation is the designed behavior. Open.
- **Host certifications are historical local evidence** — not
  regenerated per CI run. Open.

Public-release blockers (must all clear before publication):

1. ~~**LICENSE absent**~~ — **resolved**: MIT LICENSE present; `LEGAL`
   gate PASS.
2. ~~**Remote CI never run**~~ — **resolved**: remote runs are green on
   all matrix cells; `CI` gate PASS.
3. ~~**py3.9/3.10 and Linux/macOS real-machine evidence**~~ —
   **resolved**: arrived via the remote CI runs; platform gates PASS.
4. **CBM Windows-only provenance** — PARTIAL is tolerated for public
   release as documented debt; PASS requires certified Linux/macOS
   binaries. Open.
5. **Host certification historical** — PARTIAL tolerated for public
   release as documented debt; PASS requires CI regeneration. Open.

## Release checklist ownership

The maintainer owns the release decision; the tooling computes it.

- [ ] Before merging release work: run the full regression locally, then
      `python tools/release_check.py --run-regression --run-packaging
      --require merge`.
- [x] First remote CI run green: verified — remote runs are green on all
      matrix cells and the run-scoped evidence chain (emit → compose →
      bind) is exercised by `release-readiness`.
- [x] LICENSE resolved by the owner: MIT, present at the repository root.
- [ ] Rehearse with the Release Candidate Dry Run workflow, then
      `python tools/release_check.py --evidence <all-evidence.json>
      --require public`.
- [ ] Version bumps only in a dedicated release commit; RC names are
      `0.1.0rcN`; nothing in R5B/R5C/R5D tags or publishes.
