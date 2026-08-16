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

**Cause:** the environment you installed into is not active, or its
script directory is not on `PATH`.

**Fix:** activate the virtual environment you installed into, then retry.
If you installed without a virtual environment, make sure Python's script
directory is on `PATH` (`Scripts\` on Windows, `bin/` on macOS/Linux).
As a fallback from a source checkout, `python -m relinkra.product_cli`
is equivalent to `relinkra`.

## Relinkra runs, but under the wrong Python

**Symptom:** `relinkra version` reports a Python you did not expect, or
imports fail.

**Cause:** multiple Pythons on the machine; `pip` and `python` point at
different installations.

**Fix:** install with the interpreter you actually want:
`python -m pip install .`. The `python -m pip` form always targets the
Python that runs it, unlike a bare `pip`.

## Git is not installed

**Symptom:** `doctor` FAILs on the git executable check, or `init`
reports it cannot find git.

**Cause:** no `git` on `PATH`.

**Fix:** install Git, open a new terminal, and re-run `relinkra doctor`.

## CBM missing or incompatible

**Symptom:** `doctor` WARNs on CBM ("no CBM adapter configured" or an
unsupported version).

**Cause:** Codebase Memory is absent, or its version is outside the
supported range (0.9.x, certified 0.9.0).

**Fix:** this is optional — everything except symbol-level code
resolution works without it. To enable it, install CBM 0.9.0 and either
put it on `PATH`, point `RELINKRA_CBM_BIN` at the binary, or use the
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

## Engram missing

**Symptom:** `doctor` or `status` show Engram as unavailable; memory
read/write and handoffs report UNAVAILABLE.

**Cause:** no `engram` executable on `PATH`. `ENGRAM_URL` can provide
the HTTP read path, but it cannot replace the CLI required for memory
writes and handoffs.

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
terminal predates the PATH change.

**Fix:** close and reopen the terminal first — PATH changes do not reach
already-open windows. If it persists, try the `py` launcher:
`py -m pip install .` then check `py -m relinkra.product_cli --version`.
Installing into an activated virtual environment avoids the system PATH
question entirely.

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
report.
