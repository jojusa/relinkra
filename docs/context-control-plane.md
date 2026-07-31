# Relinkra as the context control plane

**Status:** R4C.0 — policy, detection and diagnostics implemented.
No live host configuration is modified by anything described here.

Relinkra sits between an agent and the things that know about a project.
CBM knows the code graph. Engram knows what was decided. Git knows what
actually changed. An agent wired directly to those gets three answers and
has to reconcile them itself, without budget, without relevance ranking,
and without anything linking a memory to the line of code it is about.

Relinkra's job is to be the one door.

```
Claude / OpenCode / Codex / Devin Desktop / future agents
                         |
                         | Relinkra MCP
                         v
                    RELINKRA
       identity / context / relevance / budget
       memory-code linkage / Git / handoffs
                         |
              +----------+----------+
              |                     |
           Engram                  CBM
        memory backend        code graph backend
```

The recommended topology:

```
agent     -> Relinkra MCP -> CBM
          -> Relinkra MCP -> Engram
          -> Relinkra MCP -> Git

Gentleman -> Engram  (SDD-specific ownership)
```

This document explains what that means as *policy* — enforceable states a
machine can check — rather than as a diagram.

---

## 1. Why the door matters

Every capability Relinkra adds lives on the path through it:

| Going through Relinkra | Going around it |
| --- | --- |
| Relevance ranking picks what matters for *this* task | You get whatever the backend returned |
| The budgeter sheds context before it costs tokens | Nothing is shed |
| Memories carry code references that survive a refactor | No linkage |
| Git facts join the packet | Separate query, separate reconciliation |
| Handoffs are portable across agents | Not produced |
| Delivery is measured and attributable | Invisible |

None of that is a reason to *forbid* a direct backend call. It is the
reason Relinkra will not describe a machine that makes them as
"managed" — and will not credit itself with savings it did not produce.

---

## 2. Backend ownership model

Five typed axes, all closed enums. They live in
`relinkra/backend_policy.py`; nothing anywhere uses a loose string.

### CBM ownership

CBM is a **private Relinkra backend**. The supported topology is
`agent -> Relinkra -> CBM`.

| State | Meaning |
| --- | --- |
| `relinkra_private` | CBM is reachable only through Relinkra, **and Relinkra is registered with a host**. Healthy. |
| `directly_exposed` | A CBM MCP server is registered with a host. Reported, never removed. |
| `explicitly_allowed_advanced` | The same exposure, opted into deliberately (see §7). |
| `unavailable` | No CBM backend, and none exposed. |
| `unknown` | Detection was conflicting, **or Relinkra is registered nowhere** so nothing observable owns the backend. |

`relinkra_private` renders as a PASS, so it is a claim that requires
Relinkra to actually be in the route. A reachable CBM that nothing
exposes and nothing routes to is `unknown` — otherwise `doctor` would
print a green ownership line beside a warning saying Relinkra has not
been observed serving anything.

### Engram ownership

Engram is **shared on purpose**. Gentleman uses it for SDD workflow
state, and that is legitimate — see §4.

| State | Meaning |
| --- | --- |
| `relinkra_managed` | No direct registration, Relinkra is registered, and it reaches the backend alone. |
| `gentleman_managed` | A Gentleman-attributed registration. |
| `shared_separated` | Both, under separated contracts. **Healthy.** |
| `direct_unclassified` | A direct registration with no ownership marker. Warned, never failed. |
| `unavailable` / `unknown` | No backend / no conclusion (including: Relinkra registered nowhere). |

### Context route

| State | Meaning |
| --- | --- |
| `managed` | Every observed path goes through Relinkra, and Relinkra is more than configured. |
| `mixed` | Relinkra is registered *and* a private backend is exposed beside it. |
| `bypassed` | A private backend is exposed and Relinkra is not there. |
| `degraded` | Relinkra owns the route but cannot fully serve it. |
| `unverified` | Nothing observable supports any of the above. |

### Metrics trust

`high` · `degraded` · `unreliable` · `unverified` — derived from the
route, never asserted independently (§8).

### Duplicate read/write risk

`none` · `possible` · `detected` · `unverified`, tracked separately for
five distinct risks (§5).

---

## 3. CBM policy

**Default:** `agent -> Relinkra -> CBM`. Direct exposure is never healthy
by default.

When a supported host registers both Relinkra and a direct CBM server,
Relinkra:

- does **not** claim a managed route — the route becomes `mixed`;
- marks metrics trust `unreliable` (or `degraded` under an explicit
  opt-in);
- reports duplicate retrieval and budget-bypass risk as `detected`;
- explains that direct CBM calls bypass relevance, budgeting, memory
  integration, Git intelligence, handoffs and metrics;
- suggests a remediation;
- **does not delete, disable or rewrite the user's CBM entry.**

That last point is not a limitation of the current phase — it is the
policy. A tool that silently removes a server someone installed on
purpose has replaced one wrong assumption with a worse one. The
remediation text says so explicitly: *"Nothing was changed — disable or
remove the direct entry yourself if you want the managed route."*

---

## 4. Gentleman and Engram coexistence

Gentleman is an external workflow system, and R4C.0 does not touch it.
Not its installation, not its configuration, not its MCP registrations,
not the Engram configuration it uses, not its SDD commands, workflows,
review agents or receipts, and not a single Engram record it wrote.

Duplicate-write prevention is solved **entirely on Relinkra's side**.

### Ownership authority matrix

Exactly one system stores the full record for each domain. The other
stores a reference or nothing. `duplicate_full_ownership()` asserts this
invariant and the tests call it.

| Domain | Authority | Relinkra stores | Gentleman stores |
| --- | --- | --- | --- |
| SDD workflow state | Gentleman | — | full |
| Gentleman reviews and receipts | Gentleman | reference | full |
| Gentleman workflow checkpoints | Gentleman | — | full |
| Gentleman-specific artifacts | Gentleman | — | full |
| Cross-agent handoffs | Relinkra | full | reference |
| Agent-neutral project memory | Relinkra | full | reference |
| Context packets and selection metadata | Relinkra | full | — |
| Portable memory-code linkage | Relinkra | full | — |
| Git-linked task results | Relinkra | full | reference |
| Relinkra verification summaries | Relinkra | full | — |

### How Relinkra stays on its own side

**Ownership is decided by the envelope.** A record is Relinkra's when it
carries the `rlkmem1` envelope, and by nothing else — no shape matching,
no key-shape heuristic. `MemoryService` already enforces this
structurally (`Memory.from_envelope` rejects any other version);
`memory_ownership.classify_record` gives the guarantee a name so it can
be asserted directly. A Gentleman record in the same project is
`external`: visible as a fact, never parsed as native memory, never
selected into a context packet.

**A reference is not a copy.** When a Gentleman event matters, Relinkra
stores an `ExternalReference` — `source_system`, `external_id`, and a
summary capped at 400 characters. Never the payload. The matrix is
consulted at save time, so a reference to a domain where Relinkra stores
*nothing* (SDD phase state, workflow checkpoints) is refused outright:
the fact that a phase exists is Gentleman's too.

**Every write still goes through `MemoryService`.** References are saved
through the service, not the store, so scoping, redaction, dedup,
supersession and the envelope all apply.

**What happens inside Gentleman is `unverified`.** Not intercepted, not
modified, not guessed.

---

## 5. Duplicate read/write prevention

Five risks, tracked separately because their remediations differ:

| Risk | Observable from |
| --- | --- |
| `duplicate_project_context_retrieval` | host configuration |
| `duplicate_backend_query` | host configuration |
| `duplicate_persisted_memory` | in-process |
| `duplicate_task_result_recording` | in-process |
| `duplicate_token_attribution` | host configuration |

Observability is part of the finding. `outside_process` means Relinkra
cannot see it and never produces a `none` verdict for it — an agent that
reads forty files by hand is doing duplicate work Relinkra has no way to
observe, and pretending otherwise would be the more comfortable lie.

`ObservingStore` wraps a memory store and counts identical reads and
writes inside one operation, fingerprinting reads by
`(query, project, storage_type, limit)` and writes by
`(project, topic_key, storage_type, content-digest)`. It is a decorator:
`MemoryService` is unchanged, and with no wrapper installed nothing
behaves differently. It is deliberately **not** a cache — suppressing a
repeated read would change service semantics, and R4C.0 is a measurement
phase.

### Recommended managed mode

- Relinkra MCP visible to the agent.
- Gentleman tools and workflows remain available.
- Direct CBM MCP hidden or disabled for ordinary project context.
- Direct Engram access limited to Gentleman workflows that require it.
- Project context, memory lookup and handoffs routed through Relinkra.

---

## 6. Connector inspection

`backend_detection.py` classifies each MCP registration by **what it
would execute**, never by what it is called.

Declared markers, each traceable to a real artifact:

| Backend | Markers |
| --- | --- |
| Relinkra | module `relinkra.mcp_cli`; console script `relinkra-mcp` |
| CBM | binary `codebase-memory-mcp` (+ `.exe`); package `codebase-memory-mcp`; module `codebase_memory_mcp` |
| Engram | binary `engram` / `engram-mcp`; module `engram.mcp` |
| Gentleman marker | token `gentleman` / `gentle-ai` in the **launch target** (including as a dotted path segment) |

Confidence is four-valued:

| Evidence | Confidence |
| --- | --- |
| One backend matched by launch tokens, name agrees or is silent | `detected` |
| One matched, name names a *different* backend | `conflicting` |
| More than one backend matched | `conflicting` |
| Nothing matched, tokens present, name names one | `conflicting` |
| Nothing matched, no tokens (remote entry), name names one | `likely` |
| Nothing matched, name silent | `unknown` |

Only `detected` drives a routing conclusion. The fourth row is the one
that matters: tokens matching nothing are positive evidence *against* the
name.

Gentleman attribution follows the same rule as backend identification:
it comes from the launch target, never from the name. A plugin-scoped
server name (`plugin:engram:engram`) is deliberately **not** sufficient —
it says *a* plugin manages the entry, not *which system* does, and
accepting it would turn an unclassified direct Engram server into a
healthy `shared_separated` PASS on the strength of user-authored text.

**Nothing from the file reaches output.** Not paths, not environment
values, and not the configured server name — a name is user-authored text
that can carry a client, a codename or a hostname. Entries are identified
by a synthetic `ref` (`cbm#1`, `unknown#2`), and the diagnostic value the
name carried is preserved as `name_suggests` (which backend it implied)
without the string. Unknown entries are reported and left completely
alone.

---

## 7. Doctor trust model

`relinkra doctor` gained a compatibility and routing section. It
distinguishes twelve stages, and **configuration presence is never
promoted to readiness**:

| Stage | How it can be proven in R4C.0 |
| --- | --- |
| `configuration_present` | a host config was read |
| `relinkra_registration_detected` | a registration launches `relinkra.mcp_cli` |
| `mcp_contract_configured` | the stdio launch contract resolved |
| `protocol_compatible` | **unverified** — needs a handshake |
| `handshake_verified` | **unverified** — needs a host |
| `tools_visible` | declared and importable in-process |
| `required_tools_callable` | **unverified** — needs a tool call from a host |
| `handoff_round_trip_verified` | **unverified** (or *not proven* when the backend is down) |
| `real_host_launch_proven` | **not proven** — no real host has launched this server |
| `context_route_managed` | from the route verdict |
| `backend_bypass_absent` | from the detections |
| `metrics_trustworthy` | from the trust verdict |

A stage with no evidence renders `unverified`, and `unverified` is never
PASS. A fully green ladder is impossible in this phase — `real_host_
launch_proven` requires a real host — which is the intended result.

Healthy output:

```
PASS Context routing
     managed through Relinkra
PASS CBM ownership
     private Relinkra backend
PASS Engram ownership
     shared with Gentleman under separated contracts
PASS Metrics trust
     high
```

Degraded output:

```
WARN Context routing
     direct backend exposure detected alongside Relinkra
WARN Metrics trust
     unreliable — direct backend calls bypass Relinkra budgeting and attribution
     Suggested action: Use Relinkra for project context and keep the direct
     CBM server disabled for this host. ... Nothing was changed.
```

Routing checks are PASS or WARN, **never FAIL**. A user who deliberately
exposes CBM has a working machine and a topology Relinkra disagrees with;
failing their `doctor` over it would turn a policy opinion into a broken
exit code.

`relinkra connect routing` renders the same assessment. It is
configuration-only — no backend probe, no process spawned — so it stays
fast and provably read-only; `doctor` is the deeper one.

### Advanced override policy

`.relinkra/config.json` may carry `"advanced_direct_cbm": true`. Nothing
writes it — no command sets it, `init` never emits it — so it can only
become true by a deliberate hand edit, and `init` preserves it across a
refresh (but not across an identity change). It changes the *state* and
the *trust level*, never the route: a deliberate mixture is still
`mixed`, because the field records a fact, not a preference.

There is deliberately no destructive override command.

---

## 8. Metrics attribution and trust

`metrics_model.py` defines the vocabulary a later telemetry phase will
fill in. Nothing collects anything yet, and that is the point.

**Sources** — `registry`, `engram`, `cbm`, `git`, `relevance`, `budget`,
`handoff`, `deduplication`, `direct_agent_exploration`,
`unknown_external`.

The last two are first-class. Work the agent does on its own is not a
rounding error; if it is not attributable somewhere, it silently inflates
Relinkra's apparent contribution.

**Trust is a property of the record, not of a sample.** A number
collected while an agent was also querying a backend directly is not more
believable because it was measured carefully. The route decides.

**Nothing is fabricated.** Each metric declares whether it is
*instrumentable at all* from inside Relinkra's process. `empty_record()`
produces the complete metric set with every value `None`:
`unavailable` for what Relinkra can never see (total task tokens, files
explored, time to first useful action), `unverified` for what is simply
not instrumented yet. A plausible `0` reads as "this did not happen" and
gets quoted as evidence — so no metric ever gets one it did not earn.

---

## 9. Agent instruction contract

A host-neutral contract, available as structured connector metadata for a
future `relinkra connect <agent>`. **It is not written to any host
configuration in this phase**, and the emitted document says so
(`written_to_host: false`).

- Use Relinkra for project context.
- Use Relinkra for memory search, memory save and handoffs.
- Do not query CBM directly for ordinary project work.
- Use Engram directly only when a Gentleman workflow explicitly requires it.
- Do not query both Relinkra and Engram for the same project-memory need.
- Report degraded Relinkra health rather than silently bypassing it.
- Leave MCP servers you do not recognise alone.

---

## 10. Windsurf → Devin Desktop migration

Windsurf (Codeium) is now Devin Desktop. Hosted Devin is a different
product.

| Connector | Status |
| --- | --- |
| `devin-desktop` | primary local desktop connector. Aliases: `windsurf`, `codeium`, `windsurf-next` |
| `devin-cloud` | hosted/remote. Unsupported, and a **separate** connector |

The old names stay first-class aliases: a rename must not break a working
command for someone with a year of muscle memory.

**Legacy locations remain discoverable.** `~/.codeium/windsurf/
mcp_config.json` and `~/.codeium/windsurf-next/mcp_config.json` are still
read, because a rename does not move anyone's existing file. When the
active configuration sits at one of them, the naming state is reported as
`legacy`.

**The current Devin Desktop format is not claimed as verified.** No
Devin-Desktop-native configuration location has been observed locally, so
none is declared — inventing a path so the table looks complete would
make `inspect` report a missing file at a location that may not exist.
`format_evidence` says this in as many words.

**Bare `devin` resolves to nothing.** It is ambiguous since the rename,
and `resolve_connector("devin")` raises `AmbiguousConnectorError` naming
both. Guessing would either point a desktop user at an unsupported hosted
connector or silently reinterpret an existing script; one retry is
cheaper than a wrong answer. The error subclasses
`UnknownConnectorError`, so R4B callers still catch it.

---

## 11. What this phase does not do

- No live host configuration is modified — Claude, OpenCode, Codex,
  Devin Desktop/Windsurf, Gentleman or otherwise.
- No Engram record is modified, migrated or reinterpreted.
- CBM is never disabled.
- No host is launched, no daemon is created.
- No handshake, tool call or handoff round trip is performed, which is
  precisely why those stages report `unverified`.
