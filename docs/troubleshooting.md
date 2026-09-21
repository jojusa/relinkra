# Troubleshooting Relinkra

Each entry lists a symptom, its likely cause, and the safest fix. Every
fix is non-destructive: nothing here asks you to delete or hand-edit an
agent host's configuration.

First move for almost anything: run `relinkra doctor --json` inside your
project and read the `action` field of every non-PASS check.

## How to read `doctor`

| Status | Meaning | Exit code |
|---|---|---|
| PASS | Working | — |
| WARN | Degraded but usable — an optional component is missing or stale | still `0` |
| FAIL | Must fix — this cannot work (no git, no repository, corrupt registry) | `2` |

A WARN never changes the exit code. Scripts can gate on "did this work"
without being tripped by optional components.

## `relinkra: command not found`

**Symptom:** `relinkra` does not resolve, yet `python -m relinkra.product_cli`
works and the package imports.

**Cause:** the environment you installed into is not active, or its
script directory is not on `PATH`. On Windows the scripts live in
`Scripts\`; on macOS and Linux, in `bin/`.

**Diagnose it, don't guess:** `doctor` reports this as an `Install
resolution` warning naming the condition, and `relinkra version --paths`
prints the exact directory that is missing from `PATH`:

```bash
relinkra version --paths
```

Read `expected_scripts_dir` (where this interpreter's console scripts
belong), `resolved_console_script` (`null` when nothing on `PATH`
resolves), and `interpreter` (the Python that owns them).

**Fix:** add that directory to `PATH` and open a **new terminal** — `PATH`
changes do not reach already-open windows. Activating the virtual
environment you installed into also puts its script directory on `PATH`,
which is usually the cleaner fix. As a fallback from a source checkout,
`python -m relinkra.product_cli` is equivalent to `relinkra`.

Relinkra never edits `PATH` for you. It reports the state and leaves the
change to you.

## Relinkra runs, but under the wrong Python

**Symptom:** `relinkra version` reports a Python you did not expect, or
imports fail.

**Cause:** multiple Pythons on the machine; `pip` and `python` point at
different installations.

**Fix:** install with the interpreter you actually want:
`python -m pip install .`. The `python -m pip` form always targets the
Python that runs it, unlike a bare `pip`. To see which interpreter is
actually in play, `relinkra version --paths` prints `interpreter` — the
exact executable — and `doctor` reports it as the interpreter in the
`Install resolution` row.

## Source-tree import shadowing

**Symptom:** an installed verification reports `install_mode: "source"`,
missing installed metadata, or a version different from the package you just
installed. More generally: you believe you are exercising the installed
artifact, and you are exercising the checkout.

**Cause:** Python imported the checkout before the installed package. This
usually happens when running from the source tree, leaving `PYTHONPATH` set,
or invoking `python -m relinkra.product_cli` while validating an install.
An editable/source distribution is correctly reported as `source`; a wheel
must have nearby `.dist-info` metadata.

**Diagnose it:** `doctor` reports this as an `Install
resolution` warning that says the import resolved to the checkout while an
installed distribution is also visible to the same interpreter. The
`install` section of `doctor --json` says which one it was:

- `running_from` — `installed_distribution`, `source_checkout`,
  `editable_installation`, or `ambiguous`.
- `distribution.installed_for_interpreter` and
  `distribution.installed_version` — the installed copy this interpreter
  can see, if any.
- `pythonpath.set` and `pythonpath.contributes_imported_package` — whether
  `PYTHONPATH` is what decided the import.

An **editable installation** is deliberately not treated as shadowing: its
metadata describes that very checkout, so importing from it is correct.
Relinkra claims an editable install only when the distribution's own PEP
610 `direct_url.json` says so; otherwise the state is reported as a plain
source checkout, because that is all the local filesystem proves.

**Fix:** run the installed console script from an unrelated directory with
`PYTHONPATH` cleared, and verify the JSON fields:

```bash
relinkra version --json
```

For an installed wheel, expect `install_mode: "installed"`,
`installed_metadata_version` equal to `relinkra_version`, and
`metadata_version_consistent: true`. The package location can be checked
without importing from the checkout:

```bash
python -c "import relinkra; print(relinkra.__file__)"
```

Relinkra never clears `PYTHONPATH` for you; it tells you that it is the
cause and leaves the change to you.

Two further limits are worth stating plainly. First, nothing here claims
where a wheel came from: a locally built wheel and one fetched from an
index are indistinguishable from inside the interpreter, so the
diagnostics say *installed distribution* and never "PyPI". Second, a
stale host process can keep serving old code after an install or a source
change — that is a runtime question, not an install-resolution one, and
`doctor`'s runtime-evidence and integration-trust rows are where it
surfaces. Relinkra does not enumerate or kill processes.

The command intentionally does not recover the original archive SHA-256 or
source commit; those are exact-release-head report evidence, not runtime
package metadata.

## Git is not installed

**Symptom:** `doctor` FAILs on the git executable check, or `init`
reports it cannot find git.

**Cause:** no `git` on `PATH`.

**Fix:** install Git, open a new terminal, and re-run `relinkra doctor`.

## Untracked local state in `git status`

**Symptom:** `git status` shows `?? .relinkra/`, `?? .codebase-memory/`,
or `?? .zcode/` as untracked.

**Cause:** each path has a different ignore story. `.relinkra/` is kept
out of status automatically — Relinkra writes the rule to
`.git/info/exclude` (repository-local, never pushed) unless your tracked
`.gitignore` already covers it. `.codebase-memory/` and ZCode-owned
`.zcode/` workspace state are not ignored by Relinkra: it never edits a
tracked `.gitignore` and never deletes host-owned files.

**Fix:** decide the ignore policy yourself. Add the paths you want out
of `git status` to your `.gitignore`, or commit them deliberately if
your team shares that state. `relinkra connect zcode` reports the real
git state of `.zcode/config.json` and its lock (ignored, visible, or
tracked unexpectedly) without changing anything. A dirty `git status`
is blamed on Relinkra or ZCode only when the dirty paths are actually
theirs — unrelated changes are never attributed to them.

## CBM missing or incompatible

**Symptom:** `doctor` WARNs on CBM ("no CBM adapter configured" or an
unsupported version).

**Cause:** Codebase Memory is absent, or its version is outside the
supported range (0.9.x, certified 0.9.0).

**Fix:** this is optional — everything except symbol-level code
resolution works without it. To enable it, run `relinkra cbm setup`
(checksum-verified install of the certified 0.9.0 release into the
per-user Relinkra-managed location). Advanced alternatives: put the
binary on `PATH`, point `RELINKRA_CBM_BIN` at it, or use the
workspace-managed `.codebase-memory/bin/` location. On macOS/Linux, note
that the certified binary currently ships for windows-amd64 only.

## CBM graph is stale

**Symptom:** `doctor` WARNs on the CBM graph stage with `stale index:
graph at …` or `worktree has N changed file(s)…`; packets still carry
CBM code evidence, marked stale.

**Cause:** normal development drifted the indexed graph. `stale index`
means commits landed after the last index (the stored graph HEAD no
longer matches the workspace HEAD); `worktree has N changed file(s)`
means uncommitted edits exist. Evidence is served degraded-but-usable,
never silently dropped.

**Fix:** run `relinkra cbm refresh` — a full reindex with automatic
recovery from the CBM 0.9.0 modify-only quirk (it deletes exactly the
project `.db` under `.codebase-memory/cache/` and reindexes when the
stored HEAD refuses to move). If the WARN says `worktree has N changed
file(s)`, the drift is your uncommitted edits: CBM's change detection
reads the git worktree, so commit (or stash) first and refresh again —
no reindex can clear it. Details: [CBM backend](cbm-backend.md).

## CBM executable is unavailable or untrusted

**Symptom:** `relinkra cbm status` reports CBM as unavailable or refuses to
run an unverified executable.

**Cause:** the resolved CBM executable is missing, unsupported on this
platform, or does not match the certified `0.9.0` release.

**Fix:** re-acquire the certified release, verify its published checksum, and
place it in the documented managed location. CBM is optional; the rest of
Relinkra continues to work without it. Details: [CBM backend](cbm-backend.md).

## Engram missing

**Symptom:** `doctor` or `status` show Engram as unavailable; memory
read/write and handoffs report UNAVAILABLE.

**Cause:** no `engram` executable on `PATH`. `ENGRAM_URL` can provide
the HTTP read path, but it cannot replace the CLI required for memory
writes and handoffs.

**Note:** the HTTP read path is loopback-only. `ENGRAM_URL` must be an
`http://` URL whose host is `127.0.0.1`, `::1`, or `localhost`; any
other value (remote host, credentials in the URL, another scheme) is
refused without sending a request, and the search degrades to the
loopback/CLI tiers with an `engram_endpoint_rejected` diagnostic in
`memory_search` results.

**Fix:** optional — Relinkra degrades honestly and commands still exit 0.
To enable memory, install Engram and ensure `engram` is on `PATH`.

## Registry corruption

**Symptom:** `doctor` FAILs on the registry check.

**Cause:** `.relinkra/registry.json` is unreadable or malformed (a
killed write, a manual edit).

**Fix:** re-run `relinkra init`. If it still fails, remove
`.relinkra/registry.json` and run `relinkra init` again. Warning: this
re-derives the project identity — the registry records this machine's
workspaces, so anything pinned to the old registry is rebuilt fresh.
Never edit the registry by hand.

## Connector check fails / host not installed

**Symptom:** `relinkra connect check <host>` reports the host is absent
or the registration is invalid, and exits `2`.

**Cause:** the agent host is not installed, or it is installed but not
yet registered with Relinkra.

**Fix:** run `relinkra connect plan <host>` to see exactly what would
change, then `relinkra connect apply <host>` to write it (a backup is
created first). If the host itself is missing, install it first.

## Host config permission problem

**Symptom:** `connect apply` fails with a write or permission error.

**Cause:** the host's config file or its directory is not writable by
your user.

**Fix:** check permissions on the host's config directory — do not edit
the file by hand. After fixing permissions, re-run
`relinkra connect apply <host>`. Your previous config is safe: every
apply writes a `*.relinkra-backup*` file (mode `0o600`, owner-only)
before touching anything, and `relinkra connect rollback <host>`
restores it.

## Windows: install succeeded but `relinkra` is not found

**Cause:** the Python `Scripts\` directory is not on `PATH`, or the
terminal predates the `PATH` change. This is the Windows shape of
`relinkra: command not found` above.

**Fix:** close and reopen the terminal first — `PATH` changes do not reach
already-open windows. `relinkra version --paths` prints
`expected_scripts_dir`, which is the directory to add. If it persists,
try the `py` launcher: `py -m pip install .` then check
`py -m relinkra.product_cli --version`. Installing into an activated
virtual environment avoids the system `PATH` question entirely.

When `doctor` reports the script directory as absent from `PATH` while the
file itself exists, the launcher is there and only the `PATH` entry is
missing — reinstalling will not help. Adding the directory is the fix.

## Stale verification proof

**Symptom:** `connect check <host>` reports the host-side verification
as stale or expired.

**Cause:** the launch contract changed since the proof was recorded —
proofs are pinned to the current contract fingerprint, so an upgrade or
config change invalidates them automatically.

**Fix:** produce a fresh proof from the real host and record it again:
`relinkra connect verify <host> --proof <file>`.

## Direct CBM detected

**Symptom:** `doctor`'s routing section reports a direct CBM registration
for this codebase.

**Cause:** the code-index backend was registered directly (outside
Relinkra), so agents can reach it without Relinkra's logical identity,
memory, or routing.

**Fix:** prefer the Relinkra-managed registration —
`relinkra connect plan <host>` shows the managed route. Direct CBM
bypasses the trust ladder and shared memory; the routing section of
`relinkra doctor` explains which backend owns which context.

## Network unavailable

**Symptom:** `pip install .` fails fetching build dependencies.

**Cause:** pip needs network access for the build backend (setuptools)
unless its cache is warm.

**Fix:** retry where network is available, or ensure setuptools is
cached. Everything after installation — `init`, `doctor`, `connect`,
git intelligence — works fully offline.

## Still stuck

Collect `relinkra version --json` and `relinkra doctor --json` (both are
guaranteed free of local paths and credentials) and attach them to your
report. If the problem is how Relinkra is installed or reached, add
`relinkra version --paths` — it is machine-local **because you asked for
it**, so read it before attaching it.
