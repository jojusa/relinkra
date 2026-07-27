# Git Intelligence (R2)

R2 adds **read-only, deterministic git facts** to Relinkra context: what
actually changed in the repository — HEAD, working tree, recent commits,
file history, diffs and co-change — collected offline through a hardened
subprocess boundary and delivered opt-in (`--git`) as an `rlkctx2`
packet section, or directly through `python -m relinkra.git_cli`.

Nothing here mutates your repository, touches the network, or writes to
memory. Git facts complement the existing models; they replace nothing.

## Model split

Three fact sources, three different questions:

| Source | Question it answers | Nature |
|--------|--------------------|--------|
| **CBM** (Codebase Memory MCP) | *What does the code look like?* — structure, symbols, references | Static code shape |
| **Engram** | *What have agents learned?* — decisions, discoveries, conventions, bugs fixed | Curated persistent memory |
| **Git** (this module) | *What actually changed?* — commits, working tree, history, co-change | Factual repository state |

**Relinkra combines** all three into one deterministic ContextPacket:
CBM candidates anchor the code, Engram memories carry the learnings, and
git facts say what is in flux *right now*. Git facts are complementary —
they are never a replacement for code structure (CBM) or for curated
learnings (Engram), and they are scored only as additive relevance
signals, never outweighing direct memory/code linkage.

## Stable vs volatile facts

- **Stable facts**: commit facts (SHA, timestamp, author name, redacted
  subject, parents, changed paths). Once a commit exists, its facts
  never change.
- **Volatile facts**: working-tree state (staged/unstaged/untracked/
  renamed/deleted/conflicted), diffs, current change state. They describe
  a moving target and can be stale one second later.

Because volatile facts expire immediately, **nothing is auto-persisted**:
there is no write path from `git_intelligence`, the context builder, or
any CLI to Engram. A test-level spy proves no `MemoryService`/Engram
adapter method is ever invoked on a collection or composition path.
Persisting a git-derived learning is always an explicit user action
(e.g. you run `memory_cli save` yourself).

## Read-only guarantee

Every git invocation goes through one runner with a hard boundary:

- **Verb allowlist**: only `status`, `log`, `diff`, `rev-parse`, `show`.
  Any other verb (commit, push, fetch, merge, reset, checkout, ...) is
  rejected *before* a process is spawned, so mutating verbs are
  unreachable from every public API.
- **argv arrays, never a shell**: `subprocess.run([...], shell=False)`
  with an explicit `cwd` and a hard **5-second timeout** per command.
- **No remotes, no network**: no fetch/pull/push, no remote APIs
  (GitHub/GitLab), no ahead/behind computation.
- **No `.git` internals access** and **no environment-variable reads**:
  facts come from porcelain output only.
- **Redaction at the parse boundary**: commit subjects and diff snippets
  pass through `redact_text` (tokens, keys, passwords → `[REDACTED]`);
  authors are emitted as **names only, never emails**; the absolute
  repository root is never serialized into portable output (local
  diagnostics channel only).
- **Typed degradation**: every failure (no binary, non-repo, unborn
  HEAD, bare repo, timeout, parse error) becomes partial facts plus a
  warning — context composition never crashes on git failure.

## Limitations

V1 is deliberately small. Know the edges:

- **No remote APIs**: GitHub/GitLab data (PRs, reviews, issues) is out
  of scope; everything comes from the local object database.
- **No mutation**: the CLI and service cannot change your repository,
  index, or config — by construction (allowlist above), not by policy.
- **Bounded scans**: `GIT_MAX_COMMITS=100` recent-commit cap (default
  10), co-change scans at most 100 commits × 50 changed paths each,
  file history bounded at 100, diff snippets opt-in and ≤ 400 chars,
  top-10 co-change entries. Large histories are sampled, not exhausted.
- **No ahead/behind in v1**: the fields exist but are always `null`
  (computing them needs either network or ref negotiation).
- **Co-change is rename-blind**: no `--follow` across renames — the
  pre-rename and post-rename paths are treated as distinct files.
- **File-level anchoring only**: git facts attach to code references at
  file granularity; there is no line-range or per-symbol history.
- **"Co-changed" is not causality**: two files appearing in the same
  commits means exactly that — co-occurrence. Never read it as "changing
  A requires changing B".

## CLI reference

```
python -m relinkra.git_cli status [--path PATH]
python -m relinkra.git_cli history --file src/f.py [--limit N] [--path PATH]
python -m relinkra.git_cli cochange --file src/f.py [--limit N] [--path PATH]
```

Sorted-keys JSON on stdout; exit `0` ok, `1` usage/git errors, `2`
internal errors; failures are a single redacted `{"error": ...}` on
stderr. Context composition opts in via
`python -m relinkra.context_cli ... --git [--git-history-limit N]`;
without `--git` the output is byte-identical to R1E (`rlkctx1`).

See also: [Context Packets](context-packet.md) ·
[Context Budget](context-budget.md) ·
[Relevance Scoring](relevance-scoring.md) ·
[Code–Memory Linkage](code-memory-linkage.md)
