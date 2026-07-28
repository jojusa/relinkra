# Cross-Agent Handoffs (R3)

A **handoff** is the portable, first-class record one agent leaves for
the next: what the task was, what got done, what is still pending, which
decisions were made, and which memories, code references, and git state
they attach to.

It is what makes "one codebase, one memory, any agent" concrete —
OpenCode → Claude, Claude → Codex, and back, without either agent
knowing anything about the other.

## Hard rules

These mirror the R1E packet and R1C memory invariants:

- **Deterministic identity.** `handoff_id` is a content hash over the
  semantic payload. `created_at` and `provenance` never participate, so
  replaying the same handoff yields the same id and the R1C dedup layer
  collapses it instead of writing a second record.
- **Agent-neutral.** `source_agent` is data. It never becomes a scope
  channel, never becomes an `agent_type`, and never feeds relevance
  scoring. `target_agent` may be absent.
- **Portable.** No absolute paths, no credentials. Every free-text field
  is redacted and de-pathed *before* the id is computed, so the stored
  bytes and the identity always agree.
- **Append-only.** A handoff may be superseded by another handoff, which
  is an explicit new record linked via `supersedes`. Nothing is ever
  rewritten in place.

## Model

`handoff_version` is `rlkho1`; ids are `hof_` + 32 hex.

| Field | Notes |
|-------|-------|
| `handoff_id` | Content hash (see below) |
| `project_id` / `workspace_id` | Logical identity; workspace optional |
| `source_agent` | Producer label — data only, no authority |
| `target_agent` | Intended recipient, optional |
| `created_at` | Timestamp — **not** part of identity |
| `task` | What the work was (required) |
| `summary` | Narrative state |
| `completed_work` / `pending_work` | Bounded string lists |
| `decisions` / `warnings` | Bounded string lists |
| `related_memory_ids` | `mem_…`, sorted, policy-filtered |
| `related_code_reference_ids` | `ref_…`, sorted |
| `git_state` | Portable subset: branch, HEAD, dirtiness counts |
| `context_packet_id` | `pkt_…`, optional |
| `supersedes` / `superseded_by` | Lifecycle links |
| `status` | `active` \| `superseded` \| `obsolete` |
| `provenance` | Producer + schema version + scope |
| `memory_id` | Storage bookkeeping |

### What is in the identity hash

Everything semantic, plus `supersedes` — superseding handoff B of A is a
different fact from a standalone B, and both must be able to coexist in
history. Reference lists are **sorted** before hashing, so the order the
caller happened to collect them in cannot change the id.

Excluded: `created_at`, `provenance`, `memory_id`, `status`.

### Guardrails

Structural, not token budgets: a handoff is a summary, not a transcript.
Task 400 chars, summary 2000, list items 400 chars, 20 items per list,
40 related ids. Control characters are stripped; overlong fields are
truncated.

### `git_state` is a deliberate subset

Branch, HEAD sha, detached/clean flags, and staged/unstaged/untracked/
conflicted counts. Never paths, never remotes, never author email.

## Persistence

Handoffs are stored **through the existing Engram adapter and R1C policy
layer** — `HandoffService` owns no storage of its own and nothing touches
Engram SQLite directly.

A handoff is saved as a memory with `memory_type="handoff"` and
`scope="project_shared"`, its JSON payload in the body. Consequences,
all of them intentional:

- Redaction, dedup, supersession, and scope policy are inherited rather
  than reimplemented.
- The R1C dedup key covers normalised title + body, so an identical
  handoff deduplicates automatically.
- R1E's memory selection already routes `handoff`-type memories into the
  packet's first-class `handoffs` section, so handoffs reach context
  without any special-casing.
- `agent_type` is stored **empty**. A non-empty value would be an
  authority signal, and `source_agent` must never be one.

### Why the title embeds a hash slice

R1C derives `topic_key` from the memory title and **auto-supersedes the
previous active memory on the same topic**. Two distinct handoffs
sharing a title would therefore silently rewrite each other — which the
append-only rule forbids.

So the title is `handoff <12 hex of id> <task slug>`: unique by
construction (48 bits of content hash), while leaving the task readable
in Markdown briefs. Explicit supersession still works, because it passes
the prior record id and bypasses dedup.

## Lifecycle

```
create ──> active ──┬──> (identical content re-created) ──> deduplicated
                    │
                    └──> superseded by a NEW handoff (supersedes: hof_…)
                             │
                             └──> prior handoff stays queryable forever
```

- **Create.** Validate → redact → de-path → hash → persist. Returns the
  handoff, a `deduplicated` flag, and any policy warnings.
- **Duplicate.** Same content ⇒ same id ⇒ R1C dedup returns the existing
  record. `deduplicated: true`, nothing new written.
- **Supersede.** Pass `supersedes: hof_…`. The service resolves the prior
  handoff, links the new memory to it, and both remain addressable.
  History is never deleted.
- **Read.** `handoff_get` by id (including superseded ones), or list the
  most recent, optionally filtered by `target_agent`.

`target_agent` is **intent, not access control.** Every handoff here is
already `PROJECT_SHARED` and readable by any agent on the project;
filtering by target is a convenience for "what was left for me", never a
permission.

## Policy isolation

`MemoryService.get()` resolves by id *without* applying a scope filter,
so an `AGENT_PRIVATE` memory is reachable by id. Publishing such an id in
a `PROJECT_SHARED` handoff would leak private context across the agent
boundary.

`HandoffService` therefore resolves every `related_memory_ids` entry and
drops any that is agent-private or unknown, recording a warning instead
of failing the call — a partial handoff plus an explicit warning beats no
handoff. A cross-project payload smuggled into another project's channel
is refused outright rather than surfaced.

## Portability

The same handoff created in two different workspaces (or on two
different operating systems) hashes identically: identity is logical, not
path-derived. Free text is scrubbed of Windows drive paths, UNC shares,
and multi-segment POSIX absolute paths, which are replaced with `<path>`.
Repo-relative paths are left untouched — those are the portable way to
point at code.

The POSIX pattern deliberately requires more than one segment so that
arithmetic like `3 /4` is not mistaken for a path, and the Windows
pattern has a lookbehind so the `e:/` inside `remote://git/…` is not
mistaken for a drive letter.

## Example

```jsonc
// relinkra_handoff_create
{
  "source_agent": "opencode",
  "target_agent": "claude",
  "task": "Port the parser",
  "summary": "Tokenizer is done; error recovery is not started.",
  "completed_work": ["tokenizer", "golden tests"],
  "pending_work": ["error recovery"],
  "decisions": ["keep the stdlib-only rule"],
  "warnings": ["the fixture clock is frozen"],
  "related_memory_ids": ["mem_29b77270973ff375"]
}
```

Any other agent, in any workspace, then reads it back:

```jsonc
// relinkra_handoff_get
{ "target_agent": "claude" }
```
