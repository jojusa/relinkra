# Relinkra Logical Project Identity (R1B)

Relinkra assigns every workspace a **portable logical project identity** that
survives clones, moves, worktrees, branch switches, and OS differences.

**Relinkra does NOT replace CBM identity.** CBM's identity is path-derived
(e.g. `C-Desarrollos-relinkra-.relinkra-r1a-fixture-a` → one SQLite DB per
path). Relinkra layers a portable logical identity *above* it; each workspace
record carries the CBM path-derived identity **unchanged** alongside the
logical one.

## Architecture

```
                    LogicalProject  (rlk_<sha256-32>)
                   /  project_id, display_name,
                  |   repository_identity, created_at
                  |
        RepositoryIdentity
          kind     = remote | explicit | local_root
          value    = remote://git/<host>/<path>        (strong)
                     explicit://<value>                (strong)
                     local-root://<root_commit_sha>    (weak)
          trust    = strong | weak
          credentials_removed = bool  (userinfo ALWAYS stripped)
                  |
                  | 1 project : N workspaces
                  v
        Workspace  (ws_<sha256-32>)
          absolute_path, canonical_path, os (family),
          git {branch, head_sha}        <- metadata only, NEVER identity
          cbm {project_name, cache_dir, db_path, binary{version, sha256}}
          agent (optional string), registered_at, last_seen_at
                  |
                  v
        Registry (.relinkra/registry.json, schema_version=1)
          atomic write (temp + fsync + os.replace), validated on load
```

## Identity rules

- **Remote (strong).** https/ssh/git@ forms are canonicalized to
  `remote://git/<host>/<path>`: userinfo stripped (never persisted), host
  lowercased, default ports removed (443/22), `.git` suffix and extra slashes
  removed, path lowercased only on known case-insensitive hosts
  (github.com, gitlab.com, bitbucket.org + www). **https and ssh converge
  only when host+path match.** Forks differ by path and never merge.
- **Explicit (strong).** User-supplied canonical value (`explicit://<value>`).
- **Local root (weak).** No usable remote → `local-root://<root_commit_sha>`
  from `git rev-list --max-parents=0 HEAD` (multiple roots sorted, joined
  with `,`). Portable across clones of the same history; not path-derived.
  Local filesystem remotes (a clone's `origin` pointing at another local
  path) are not usable and fall back to local_root.
- **HEAD SHA is metadata only.** It is stored under `workspace.git.head_sha`
  for context but never participates in `project_id` or `workspace_id`.

## Deterministic IDs

- `project_id = rlk_` + SHA-256(`relinkra/project/v1\0` + canonical identity
  value)[:32 hex]. Not path-derived, stable across branches/commits,
  filename/DB safe, LLM-independent.
- `workspace_id = ws_` + SHA-256(`relinkra/workspace/v1\0` + project_id +
  `\0` + canonical_path + `\0` + os_family)[:32 hex]. Same project at a
  different path or OS family ⇒ different workspace.

## Trust assumptions and ambiguous cases

- Strong identities (remote, explicit) merge freely: two paths with the same
  canonical remote are the same logical project.
- **Stale-origin hazard.** Strong merges are only as trustworthy as the
  configured `origin`. If a workspace's `origin` still points at a template,
  a forked-from repo, or a retired project, its workspace will silently
  merge into that *other* logical project. Before registering, verify
  `git remote -v` points at the intended repository; use `--remote-url` (or
  an explicit identity) to override a stale or missing remote, and fix the
  remote in git so future registrations converge correctly.
- **Weak identities never silently merge into *other* workspaces.** If a
  `local_root` identity matches an existing project and the registration
  targets a *different* workspace, `register_workspace` raises
  `AmbiguousIdentityError` unless `allow_weak_merge=True` (explicit
  human/agent consent) or an explicit `project_id` override is given.
  Rationale: a root-commit match proves shared history but not shared
  *intent* (e.g. template forks). Passing `--allow-weak-merge` means "I
  confirm these two checkouts are the same logical project".
- **Re-registration is idempotent.** Re-registering the *same* workspace
  (same project + canonical path + OS family) never raises ambiguity — it
  only refreshes `last_seen_at` and any supplied metadata. Weak-merge
  consent is therefore asked once per distinct workspace, not on every
  registration.
- Canonical paths are resolved with `os.path.realpath`, so the same
  repository reached through a symlink canonicalizes to the same workspace
  instead of becoming a second one.
- Clones of the same local history (R1A fixture-a/fixture-b) converge to one
  project under `allow_weak_merge=True` while keeping **distinct workspaces
  and distinct CBM databases**.
- A repo with no remote is still portable: any clone of its history derives
  the same weak identity.
- A *malformed or unsupported network remote* (e.g. `github.com/org/repo`
  without a scheme, an `ftp://` URL, or a non-numeric port) is a
  configuration error, not a fallback case: discovery raises a sanitized
  `ValueError` instead of silently degrading to weak identity. Only local
  filesystem remotes (plain paths, `file://`) fall back to local_root.
- `local_root` supports both SHA-1 (40 hex) and SHA-256 (64 hex)
  repositories.
- Credentials are never stored nor echoed: normalization strips userinfo,
  all error messages pass through `redact_url`, the CLI redacts stderr
  output, and the registry refuses to load or save any identity value
  containing `@` / `://user:` patterns (`sanitize_remote_for_storage` +
  load validation).

## Registry persistence

JSON, `schema_version=1`, default path `.relinkra/registry.json` (gitignored).
Writes are atomic: temp file in the same directory → flush + fsync →
`os.replace` → best-effort directory fsync. Registry mutation
(`register_workspace` + `save`) and `load` run under a best-effort
cross-platform advisory inter-process lock (`<registry>.lock` alongside the
registry; `msvcrt.locking` on Windows, `fcntl.flock` on POSIX; proceeds
unlocked if the primitive is unavailable). Loads are strictly validated
(schema version, record shapes, id formats, credential patterns) and raise
`RegistryError` on any malformed content. No server, no runtime dependencies
— Python 3.14 stdlib only.

## CLI

```
python -m relinkra.cli register PATH [--registry PATH] [--display-name NAME]
    [--remote-url URL] [--allow-weak-merge]
    [--cbm-project-name NAME --cbm-cache-dir DIR [--cbm-version V] [--cbm-sha256 H]]
python -m relinkra.cli list [--registry PATH]
python -m relinkra.cli show WORKSPACE_ID [--registry PATH]
```

JSON output only; nonzero exit on errors (2 on ambiguous weak merge).
