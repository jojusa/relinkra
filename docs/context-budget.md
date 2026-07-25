# Context Budget Accountant (R1F)

R1E *gathers* a deterministic ContextPacket. R1F answers the next question:
**given this packet and a fixed context budget, what fits, what must be
reduced or omitted, and why?** It controls how much we can afford to send —
without changing how packets are composed.

Powerful inside, simple outside:

- **Inside**: every byte is accounted (data + provenance + metadata +
  warnings, never just raw bodies) and every reduction is an auditable
  `BudgetDecision` with a machine-stable reason.
- **Outside**: one bounded ContextPacket (same `pkt_` id, same JSON or
  Markdown rendering) plus one deterministic JSON budget report.

```
 ContextPacket (R1E)          ContextBudget (R1F)
 pkt_<sha256:32>              profile small|medium|large or --max-tokens
        │                              │
        ▼                              ▼
 ┌─────────────────────────────────────────────┐
 │ Budget Accountant (relinkra.context_budget) │
 │  estimate (cpt1) → classify → reduce ladder │
 └──────────────────┬──────────────────────────┘
                    ▼
   Bounded ContextPacket  +  Budget Report (bgr_<sha256:32>)
   (same packet_id)          (decisions, usage, status)
```

## What the accountant IS / is NOT

- It IS a **post-composition layer**: composition (R1E) stays budget-free;
  budgeting happens after the packet exists.
- **No embeddings. No LLM ranking. No semantic scoring. No provider APIs.
  No recency/similarity scoring.** Reduction is a fixed ladder over fixed
  section classes. Same packet + same budget ⇒ same decisions and a
  byte-identical report.
- Non-goals (later phases): provider pricing, model routing, exact
  provider tokenizers, semantic relevance.

## Quick start

```
# bounded packet with a fixed profile
python -m relinkra.context_cli --project-id rlk_... --budget small --pretty

# explicit cap (wins over --budget) + audit report on stderr
python -m relinkra.context_cli --project-id rlk_... --task "fix parser" \
    --budget medium --max-tokens 5000 --budget-report
```

stdout is always the (budgeted) packet in the selected `--format`;
`--budget-report` writes the report JSON to stderr. **Each stream carries
at most ONE JSON document.** When the budget cannot be satisfied, stdout
stays empty (both `--format json` and `--format markdown`), stderr gets
exactly one object
`{"error": "budget_unsatisfiable", "packet_id": ..., "max_estimated_tokens": ...}`
— with the full report embedded as `"budget_report": {...}` inside that
same object when `--budget-report` was passed — and the exit code is 1.
With no budget flags, behavior is byte-identical to R1E.

## Budget profiles

| profile | max_estimated_tokens | intended use |
|---|---|---|
| small | 2000 | compact agent handoff |
| medium | 8000 | normal coding task |
| large | 24000 | architecture/debug session |

`--max-tokens N` always overrides the profile. Each budget also reserves
`max(64, ceil(5% of max))` tokens by default: the ladder targets
`budget - reserve`, so the guarantee holds with headroom and content that
only fits inside the reserve is reported unsatisfiable.

## Estimation: cpt1 (a conservative approximation)

- Method `chars-per-token`, version `cpt1`:
  `estimated_tokens = ceil(len(text) / chars_per_token)`, default
  **3.0 chars/token** — deliberately below the common ~4.0 English
  heuristic so code and multilingual text are over- rather than
  under-counted. Empty text costs 0.
- Measured over the **actual serialized payload**: the compact packet
  JSON (same sorted-keys/compact config as the packet itself), so
  provenance, metadata and warnings are always counted.
- `len()` counts Unicode code points: cpt1 may diverge from real provider
  tokenizers (especially CJK/emoji). The method/version fields exist so a
  future exact-tokenizer adapter can replace it without changing policy.

## Fixed section policy

| class | contents | rationale |
|---|---|---|
| ESSENTIAL | project identity/facts, task/focus, ALL warnings, packet provenance | identity and degradation signals must survive any budget |
| IMPORTANT | pending, handoffs, memories of type constraint/decision/architecture/bug, code_references (metadata), code_fact metadata rows | baseline working context |
| OPTIONAL | snippet payloads, memories of type discovery/verification/task_result and any unknown type | payload-heavy, reconstructable |

## The reduction ladder

Applied in exact order while the packet exceeds `budget - reserve`;
each step is exhaustive before the next, with re-estimation after every
mutation, stopping as soon as it fits:

1. **Snippet truncate** — snippets over 400 chars are cut to 400 chars +
   the marker `\n...[truncated by budget]` (`snippet_truncated=True`).
   `action=truncated`, `reason=snippet_budget_ladder`.
2. **Snippet reference-only** — snippet payloads removed entirely; all
   code_fact metadata and `code_reference_id` kept.
   `action=reference_only`, `reason=snippet_budget_ladder`.
3. **Omit optional memories** — whole memories only (bodies are never cut
   mid-sentence), from the END of the list first.
   `reason=optional_section_budget_exhausted`.
4. **Omit optional code facts** — code_facts beyond the FIRST one (the
   direct focus), from the end. `reason=optional_section_budget_exhausted`.
5. **Omit important items** — important memories, then pending, then
   handoffs, then code_references beyond the first; from the end of each
   list. `reason=important_section_budget_exhausted`.
6. Still over ⇒ `status=BUDGET_UNSATISFIABLE`, `packet=None`,
   `satisfied=false`, decisions retained. Never silently exceeded.

**Optional pre-budget ranking (R1G).** `apply_budget(..., relevance=...)`
(or `--relevance` on the CLI) ranks the packet first with the
deterministic scorer from [docs/relevance-scoring.md](relevance-scoring.md).
The ladder STRUCTURE above is unchanged — essential protected, snippet
steps 1–2 untouched, class order of steps 3–5 preserved — but the removal
order *inside* steps 3, 4 and 5 becomes ascending relevance (lowest score
first) instead of strictly-from-end. The hard guarantee, the audit model
and `BUDGET_UNSATISFIABLE` are preserved; the report gains a
`relevance_version` field. With `relevance=None` (the default) behavior
is byte-identical to plain R1F.

Integrity rules: the truncation marker is exact; memory bodies are
whole-in or whole-out; `memory_id`, `memory_type`, provenance and
`code_reference_id` survive every reduction; warnings are never removed
and the budget layer never adds warnings (omissions live in the report
and in `diagnostics["budget"]`, keeping warning bytes identical).

## Hard budget guarantee

When `status=OK`, the estimated tokens of the budgeted packet's compact
JSON are **≤ `max_estimated_tokens`** (and its length ≤ `max_characters`
when set). A final assertion-style check re-verifies this before OK is
returned; if it could not hold, the result is the typed
`BUDGET_UNSATISFIABLE` instead — never an exception, never an overflow.

The original packet is never mutated: survivors are deep-copied into a
new ContextPacket that **keeps the original `packet_id`**. This is safe
because `compute_packet_id` hashes only identity fields and sorted source
ids; diagnostics, warnings and `created_at` never participate in identity.

## Diagnostics: composition vs budget

Diagnostics are split, never falsified:

- `diagnostics["composition"]` — the ORIGINAL R1E composition diagnostics
  (`counts`, `omitted`, `selected_source_ids`, ...), moved verbatim. They
  describe the packet as composed, BEFORE the ladder.
- `diagnostics["budget"]` — describes the FINAL budgeted packet:
  - policy fields: `budgeted: true`, `max_estimated_tokens`,
    `max_characters`, `reserve_tokens`, `chars_per_token`,
    `estimation_method`, `estimation_version`;
  - final state: `final_counts` (per section: memories, code_references,
    code_facts, pending, handoffs, warnings), `included_source_ids`
    (survivors, in packet order), `omitted_source_ids`,
    `truncated_source_ids` (snippets truncated or made reference-only;
    counts and id lists only, never item copies), `final_total_chars`,
    `final_estimated_tokens`, `satisfied`.

The final-state fields are part of the measured payload itself: the
ladder always measures the packet WITH its final diagnostics, so the hard
guarantee covers the exact shipped JSON (`final_total_chars` is
self-referential and resolved by deterministic fixed-point iteration).

## The audit model

Every original content unit (item, snippet payload, plus one `essential`
structural entry) gets exactly one decision — survivors included, so the
audit is complete:

```json
{
  "source_id": "snippet:ref_9f2c...",
  "section": "code_facts",
  "action": "truncated",
  "reason": "snippet_budget_ladder",
  "original_chars": 2000,
  "original_estimated_tokens": 667,
  "final_chars": 425,
  "final_estimated_tokens": 142
}
```

```json
{
  "source_id": "mem_0042...",
  "section": "memories",
  "action": "omitted",
  "reason": "optional_section_budget_exhausted",
  "original_chars": 1350,
  "original_estimated_tokens": 450,
  "final_chars": 0,
  "final_estimated_tokens": 0
}
```

The report (`bgr_<sha256:32>`, content-hashed over original packet id +
budget + one `section:source_id:occurrence` entry per decision) carries
`estimation_method`/`version`, `budget`, `original_usage`, `final_usage`
(totals measure the actual serialized JSON; the per-section breakdown is
the accounting view), `status`, `satisfied`, and all `decisions`. Audit
bookkeeping is keyed internally by `(kind, source_id, occurrence_index)`
— the deterministic 0-based occurrence count of each
`(section, source_id)` pair in packet order — so duplicated or empty
source ids each get their OWN decision instead of collapsing into one.
No timestamps: identical inputs produce a byte-identical report. Markdown
rendering reuses `ContextPacket.to_markdown()` — the truncation marker
shows naturally and no accounting noise is added; accounting lives in the
JSON report only.
