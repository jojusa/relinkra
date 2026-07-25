# Deterministic Relevance Scoring (R1G)

R1E *gathers* a ContextPacket. R1F controls **how much** of it fits. R1G
controls **which** context is preferred: a deterministic, LLM-free,
embedding-free, offline scorer that ranks every candidate in the packet
with integer points — and can hand that ranking to the budget accountant
so the ladder sheds the *least relevant* context first.

Powerful inside, simple outside:

- **Inside**: every score is an exact integer sum of named signals
  (`direct_code_link +40`, `memory_type(constraint) +20`, ...). Every
  candidate carries its own explanation; nothing is a black box.
- **Outside**: one RankedContext JSON (ids + points, never bodies) plus,
  optionally, a relevance-guided budget pass that produces the same
  bounded ContextPacket shape as plain R1F.

```
 ContextPacket (R1E)              focus: task / file / symbol / ref id
 pkt_<sha256:32>                  workspace_id, as_of (injected)
         │                                │
         ▼                                ▼
 ┌──────────────────────────────────────────────┐
 │ Relevance Scorer (relinkra.relevance)        │
 │  tokenize → signals (integer points) → rank  │
 └───────────────────┬──────────────────────────┘
                     ▼
        RankedContext (relevance-v1)   ── optional ──▶ apply_budget()
        per section, best-first                        relevance-aware ladder
                     ▼
        Bounded best-fit ContextPacket (same packet_id)
```

## What the scorer IS / is NOT

- It IS **lexical**, not semantic: exact id equality, normalized
  path/symbol equality, and set-based keyword overlap over a
  deterministic tokenizer. No embeddings, no vector search, no BM25, no
  graph centrality, no Git-history scoring, no LLM — v1 by design.
- A score is **not a probability** and is **never clamped**: totals may
  go negative (penalty signals) and only mean something *relative* to
  other candidates in the same packet.
- Scores are **derived, never persisted**: nothing is written back to
  Engram, the packet is never mutated, and the score report carries
  ids / points / timestamps only — never raw bodies, never absolute
  paths.
- `as_of` is **required and injected** (the CLI passes its clock): no
  wall-clock, no randomness. Same packet + same inputs ⇒ byte-identical
  RankedContext.

## Quick start

```
# annotate the packet with a relevance block (no budget)
python -m relinkra.context_cli --project-id rlk_... --relevance

# rank, then budget: the ladder drops the least relevant first
python -m relinkra.context_cli --project-id rlk_... --task "fix parser" \
    --relevance --budget small

# full audit: one combined stderr object with both reports
python -m relinkra.context_cli --project-id rlk_... --symbol src.calc.add \
    --relevance --relevance-report --budget small --budget-report
```

`--relevance` alone only annotates `diagnostics["relevance"]` (version,
`as_of`, per-section counts). `--relevance-report` writes the
RankedContext JSON to stderr (requires `--relevance`); with
`--budget-report` too, stderr carries ONE combined object
`{"budget_report": {...}, "relevance_report": {...}}`. With no new
flags, output is byte-identical to R1F.

## A score, explained

A constraint memory directly linked to the focused code, fresh, and
matching the task in title and body:

```json
{
  "source_id": "mem_0042...",
  "section": "memories",
  "total": 82,
  "signals": [
    {"name": "direct_code_link", "points": 40},
    {"name": "memory_type", "points": 20},
    {"name": "task_keyword_overlap", "points": 14},
    {"name": "recency", "points": 8}
  ]
}
```

*scored 82 because*: **+40** its provenance links it to the focused
code reference, **+20** it is a constraint, **+14** two distinct task
tokens hit the title (2 × 6) and one hits the body (1 × 2), **+8** it
is less than a day old. Zero-point signals are omitted from the JSON
but always exist in the fixed-order explanation; `sum(signals) ==
total`, always.

## Signals and weights (v1)

All weights live in `RelevanceWeights` / `DEFAULT_WEIGHTS` — no magic
numbers elsewhere.

| signal | points | rule |
|---|---|---|
| `direct_code_link` | +40 | focused code reference id ∈ memory's linked refs (`provenance.code_reference_id` or any `code_refs[*].code_reference_id`; fires once) |
| `symbol_match` | +35 | candidate `qualified_name` or `symbol_name` == focused symbol (exact, whitespace-normalized) |
| `file_match` | +25 | candidate repo-relative `file_path` == focused file (normalized POSIX) |
| `memory_type` | +20/+18/+15/+15/+14/+12/+6/+4/+2 | constraint / decision / bug / handoff / pending / architecture / discovery / verification / task_result; unknown types 0 |
| `task_keyword_overlap` | title +6 each (cap 18); symbol/file +5 each (cap 15); body +2 each (cap 10) | **set-based**: each distinct shared token scores once per bucket — repeating a keyword never inflates the score |
| `recency` | +8/+6/+4/+2/0 | age at `as_of`: ≤ 1d / ≤ 7d / ≤ 30d / ≤ 90d / older; missing or unparseable timestamp +0 |
| `workspace_match` | +5 | memory `scope_channel` == `ws/<current workspace_id>` |
| `resolution` (code only) | +4 / −8 / −6 / −10 | resolved / stale / ambiguous / missing |

Penalties are part of the explanation (a stale code fact scores
`resolution: −8` openly). Resolution signals apply **only** to
code_references / code_facts: **memories keep their historical value** —
a memory linked to missing code still earns its type, task and recency
points (and the `direct_code_link` bonus), because the knowledge
survives the code. There is deliberately **no signal for the requesting
agent**: provenance is not reputation, so equal-quality memories score
identically whether they came from opencode or codex.

### Recency buckets

| age at `as_of` | points |
|---|---|
| ≤ 1 day | +8 |
| ≤ 7 days | +6 |
| ≤ 30 days | +4 |
| ≤ 90 days | +2 |
| older / missing | 0 |

Timestamps are parsed as ISO-8601 (a trailing `Z` is normalized to
`+00:00`); mixed offsets compare **chronologically**, never
lexicographically. A **future** timestamp clamps into the freshest
(≤ 1 day) bucket; a missing or unparseable timestamp earns 0.

## The tokenizer (deterministic, stdlib only)

`tokenize(text)`: camelCase boundaries split **before** casefold
(`generateOnly` → `generate, only`; acronym runs split too), then
`casefold()` + NFKD with combining marks stripped (accented Spanish is
ASCII-folded: `árbol` → `arbol`), snake_case / kebab-case / dotted
symbols split on their separators, punctuation collapses, tokens
shorter than 2 chars are dropped, duplicates are removed keeping
first-occurrence order. Letter/digit boundaries are not split (`r1g`
stays `r1g`). No stemming, no NLP packages.

## Tie-breaking (exact)

Within each section, best-first order is:

1. `total` **descending**
2. `type_rank` **ascending**: constraint < decision < bug < handoff <
   pending < architecture < discovery < verification < task_result <
   code_reference < code_fact (unknown memory types slot just above
   code references)
3. `timestamp` **descending**, compared chronologically (parsed aware
   datetimes; mixed offsets order correctly) — missing or unparseable
   timestamps last
4. `source_id` **ascending**

No randomness anywhere: repeated scoring of the same packet is
byte-identical. Lookup keys are `(section, source_id,
occurrence_index)` — the same occurrence counting the R1F audit uses —
so a budget decision and a relevance explanation always name the same
candidate, even with duplicated or empty source ids.

## Taskless behavior

`task=None` zeroes **only** the keyword signal; every other signal
(direct links, type, recency, workspace, resolution) still
differentiates, so scores are never all-equal by construction.

## Budget integration (optional pre-budget step)

`apply_budget(packet, budget, relevance=ranked)` keeps the R1F ladder
**structure** exactly — essential class protected, snippet steps 1–2
untouched, class order of steps 3–5 preserved (optional memories, then
extra code facts, then important items) — but the **removal order
inside** steps 3, 4 and 5 becomes ascending relevance (lowest total
first, ties by the chain above, then occurrence index) instead of
strictly-from-end. The hard budget guarantee, the typed
`BUDGET_UNSATISFIABLE` result, policy isolation and the occurrence-
keyed audit are all preserved; the report gains `relevance_version`.
The ranking must belong to the packet: `apply_budget` rejects a
RankedContext whose `original_packet_id` differs **or** whose stored
`packet_fingerprint` (per scored section, the ordered `(source_id,
occurrence_index)` pairs) does not match the packet — packet ids are
content-insensitive, so the fingerprint is what actually proves the
ranking was built from THIS packet.
With `relevance=None` the accountant is byte-identical to plain R1F.

Class still beats score: a high-score optional discovery is omitted
before a low-score important decision, and identity/warnings are never
touched by the ladder. What ranking changes is *which* candidate leaves
first **within** a class. Concretely (Phase 17 fixture): an old
discovery directly linked to the focused symbol (total **46** = 40
direct link + 6 type) sits at the END of the list behind a newer
unrelated discovery (total **14** = 6 type + 8 recency); when the
budget forces one out, plain R1F keeps the positioned (newer) one,
while the relevance-aware ladder keeps the **linked** one.

## Limitations (v1, by design)

- **Lexical, not semantic**: "parser" does not match "parsera" or
  "syntax engine". No embeddings, no synonyms, no stemming.
- Recency is a coarse 4-bucket signal, not a decay function.
- Keyword overlap is set-based with hard caps: it rewards topical
  coverage, never verbosity.
- Scores are per-packet relative integers; they are not comparable
  across packets, projects, or weight versions.
- Non-goals: embeddings / vector search, BM25, graph centrality,
  Git-history scoring, model routing, pricing, prompt injection, and
  writing scores back to Engram.
