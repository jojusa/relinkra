# Freshness, contradictions, and explainability (R4D)

Relinkra explains **why evidence was shown and what supports its currency**.
It does not certify that a fact is true, silently discard old evidence, or
prevent an agent from inspecting, searching, or verifying the source.

## Quick answers

### Why did Relinkra show me this?

Read the item's existing `provenance.why_included` field. Its `explain`
sidecar points to that reason and, when relevance was requested, includes the
named deterministic score signals. It also records the budget treatment and a
stable `evidence_ref` used by warnings and contradictions.

```json
{
  "selection": {
    "reason_ref": "provenance.why_included",
    "relevance": {"total": 52, "signals": [{"name": "direct_code_link", "points": 40}]}
  },
  "budget": {"treatment": "included", "reason": "within_budget"},
  "provenance": {"evidence_ref": "memories:mem_0042:0"}
}
```

The score is relative ranking evidence, not a probability or a trust grade.
See [Deterministic Relevance Scoring](relevance-scoring.md).

### Can I trust this information is current?

Check `freshness.state`, `reason_code`, and any packet-level notice for the
same `evidence_ref`:

```json
{
  "freshness": {
    "state": "stale",
    "reason_code": "revision_stale",
    "source_revision": "8b2f...",
    "revision_distance": 9,
    "relation": "ancestor"
  }
}
```

This says the evidence describes an older Git commit. The matching notice
contains the limitation and recommended action, such as refreshing the source
or inspecting current code. By contrast, `fresh` with
`reason_code: same_revision` means the evidence is bound to the current commit at the
reported `as_of`; it still does **not** prove correctness, completeness, or
absence of later uncommitted changes.

## Read the freshness state

| State | Meaning |
|---|---|
| `fresh` | The evidence-specific policy has positive current evidence. Read any limitations too. |
| `aging` | The evidence is close to current or old only by an advisory clock. Verify when the fact may have changed. |
| `stale` | Relinkra has positive evidence of a mismatch, older revision, or expired native verification. |
| `unknown` | Required provenance or authority is missing, unavailable, unrelated, shallow, or unverified. Relinkra does not guess. |
| `not_applicable` | The structural fact has no meaningful lifetime. |

Freshness is an observation, not an access-control or execution decision.
Stale and unknown records remain visible, with recommended checks.

## Evidence-specific policy

| Evidence | Policy |
|---|---|
| Code and revision-bound memory/handoff | Same commit is `fresh`; one bounded ancestor step is `aging`; older ancestor evidence is `stale`. A descendant, unrelated commit, failed comparison, or shallow uncertainty is `unknown`. Exact-revision non-Git evidence becomes `aging` when the working tree is dirty. |
| Current Git facts | Bind to the collected HEAD, not a branch label, so detached HEAD can still be `fresh`. A dirty tree is reported as a limitation; unavailable Git is `unknown`. |
| CBM code evidence | Supplied native CBM graph revision and graph trust outrank a copied result revision. A native graph revision mismatch is `stale`; malformed or incomplete supplied native evidence, a missing graph verdict, or a non-PASS verdict is `unknown`. Otherwise the revision policy applies. |
| Connector verification | The connector's native assessment owns expiry, fingerprint, revision, and stage proof. A valid assessment is `fresh`; explicit expiry, fingerprint mismatch, or revision mismatch is `stale`; absent, otherwise invalid, or unproven evidence is `unknown`. TTL is metadata and never proves freshness by itself. |
| Memory without a revision | Up to 30 days is `fresh`; older evidence is `aging`, not automatically invalid. A missing or unusable timestamp is `unknown`. |
| Handoff without a revision | Up to 7 days is `fresh`; older evidence is `aging`. Revision-bound handoffs use the Git policy instead. |
| Registry/project identity | Structural identity is normally `not_applicable`. A logical-project mismatch is `stale` and takes precedence. |

`as_of` is injected into the build, and revision comparison is bounded and
read-only. Resolver failures are sanitized and degrade to `unknown` rather
than leaking an error or manufacturing confidence.

## What contradiction detection covers

Contradictions are deterministic comparisons of **narrowly structured facts**,
not semantic claims extracted from prose. R4D considers:

- logical project, workspace, and repository revision identity;
- `status`, `state`, and `resolution_state`;
- schema-owned handoff identity/lifecycle fields;
- native CBM trust-stage status; and
- records explicitly shaped as `key` plus `value`.

It does not recursively flatten arbitrary JSON bodies, compare free-form
sentences, or infer a giant cross-system graph. Missing and explicit-null
workspace values do not create a false conflict.

Ordinary keys are compared only inside one authority domain. Project,
workspace, repository identity, and revision are the deliberate cross-domain
exceptions. A disagreement produces one stable, grouped `ctr_...` record with
evidence references and a recommended action; raw conflicting values are not
copied into the packet.

For `status`, `state`, and `resolution_state`, distinct valid timestamps can
produce `temporal_supersession`: an informational notice that the newer
same-authority value is preferable for current-status questions. Both records
remain available. Equal or unusable chronology is not treated as
supersession.

## Authority and autonomy boundaries

- Git owns commit relationships; CBM owns its graph/trust verdict; connector
  verification owns its staged proof; memory and handoff services own their
  lifecycle and persistence.
- R4D adapts those authorities. It does not replace them with a second clock,
  mutate source records, or turn a notice into lifecycle supersession.
- `authority_policy` is `domain_scoped_no_global_winner`: contradictions do
  not select or delete a global winner.
- `advisory_only` is always `true`. An agent remains free to inspect code,
  query memory, search history, or verify externally.

## Explainability fields

Each selected packet item can carry:

| Field | What it answers |
|---|---|
| `explain.selection` | Why it was selected and its optional relevance score. |
| `explain.freshness` | State, reason code, and applicable time/revision relation facts. |
| `explain.budget` | `full` before budgeting, then `included`, `truncated`, or `reference_only`, with a reason where space permits. Packet metadata tracks omitted items. |
| `explain.provenance.evidence_ref` | Stable reference used by notices and contradictions. |
| `explain.contradictions` | IDs of packet-level contradiction records involving this item. |
| `explain.trust` | The advisory boundary; detailed limitations are kept in packet notices. |

The packet-level `explainability` block carries the version, `as_of`, current
revision and dirty-worktree state when available, contradiction count,
authority policy, actionable `notices`, and budget-accounting metadata.
Packet-level `contradictions` stores each conflict once; items hold only IDs.

Fields whose evidence is unavailable are omitted rather than filled with
misleading nulls. Under a tight budget, optional detail can also be compacted,
so consumers should key on stable fields such as `state`, `reason_code`,
`evidence_ref`, budget treatment, contradiction IDs, and recommended actions.

## Relevance, budgets, and compaction

The read pipeline is:

1. compose and annotate the packet;
2. optionally attach deterministic relevance signals;
3. apply the existing budget ladder; and
4. re-measure the exact final serialized packet, including R4D metadata.

The relevance score changes removal order only inside an existing budget
class; it does not change freshness or authority. Budget treatment is copied
into each surviving item's sidecar. For omitted items, the packet retains a
compact row with the `evidence_ref`, treatment, and reason when space permits.

If R4D metadata itself creates pressure, compaction is deterministic: detailed
relevance signals shrink first, then optional freshness/chronology detail.
Typed warnings, recommended actions, evidence links, contradiction IDs, and
single-copy contradiction records survive. Omitted raw bodies are never
reintroduced through an explanation. `metadata_accounted: true` means the
final metadata was measured inside the cap. The budget block is absent when no
budget was requested; an unmeasured block never claims `true`. If the final
packet cannot fit, the existing
`budget_unsatisfiable` result is returned instead of exceeding the cap.

See [Context Budget Accountant](context-budget.md) for the reduction ladder.

## CLI: machine and human views

Machine-readable JSON, without raw evidence bodies:

```bash
python -m relinkra.context_cli --project-id rlk_... \
  --workspace-root . --task "fix the parser" --explain --pretty
```

Operator-friendly summary:

```bash
python -m relinkra.context_cli --project-id rlk_... \
  --workspace-root . --task "fix the parser" --explain --format markdown
```

The human view lists selection reasons, freshness warnings, structured
conflicts, and what to verify. `--explain` with `--workspace-root` enables the
read-only Git facts needed for revision comparison. Without a root, Relinkra
preserves the legacy Git-off behavior and reports currency as `unknown` where
revision evidence is required.

`--explain` composes with relevance and budgeting:

```bash
python -m relinkra.context_cli --project-id rlk_... \
  --workspace-root . --task "fix the parser" --explain \
  --relevance --budget medium --budget-report
```

## MCP: additive compatibility

R4D enriches five existing read responses; it adds no tool and changes no
input schema:

| Tool | Additive output |
|---|---|
| `relinkra_context_get` | Per-item `explain`, plus packet `contradictions` and `explainability`. |
| `relinkra_memory_search` | Per-memory `explain` and top-level `explainability`. |
| `relinkra_code_resolve` | Explained code references/facts plus packet-level contradiction metadata. |
| `relinkra_git_context` | A compact `explain` sidecar, including degraded `unknown` results. |
| `relinkra_handoff_get` | A compact `explain` sidecar on each returned handoff, including historical records. |

Clients that ignore unknown output properties continue using the original
payload. Strict output decoders should allow the documented additive fields.
Explanation is read-side only: fetching a historical handoff or memory does
not update, refresh, or otherwise write the stored record.

## Privacy and portability

- CLI explanation JSON contains IDs, policy metadata, and actions, not raw
  memory or handoff bodies.
- Contradiction records omit raw values and repeated prose, preventing an
  omitted or sensitive body from returning through metadata.
- Portable packet serialization still removes machine-local diagnostics and
  absolute infrastructure paths.
- Git/revision failures are sanitized before they become `unknown` sidecars.
- R4D stores no new authority state and performs no read-time persistence.

The underlying packet, memory, handoff, and MCP privacy rules still apply; R4D
is an additive explanation layer, not a parallel data channel.
