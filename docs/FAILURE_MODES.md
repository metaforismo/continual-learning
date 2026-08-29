# Failure modes and mitigations

The primary design goal is not maximum memory volume. It is preventing accumulated experience from becoming accumulated error.

## Failure taxonomy

| Boundary | Failure | Why naive systems fail | Required control |
|---|---|---|---|
| Capture | Missing evidence | A summary stores the conclusion but not the source span or tool result | Provider-owned artifact plus canonical content-addressed evidence metadata |
| Capture | Memory contamination | An extraction hallucination becomes persistent system state | Quarantine, source-grounded admission, transition verifier |
| Capture | Prompt-injection persistence | Malicious document text is later recalled as an instruction | Taint labels; memory is data by default; instruction authority is separate |
| Capture | Secret retention | Tokens, keys, health, or financial data are stored indefinitely | Data classification, secret scanning, least-retention policy, scoped deletion |
| Write | Blind append | Contradictory values accumulate without state change semantics | Typed claim keys, valid intervals, supersession, dispute, unknown-current |
| Write | Destructive overwrite | New state erases history and the evidence needed to repair it | Append-only audit row; projections, not in-place truth mutation |
| Write | Replay inconsistency | An LLM judge returns a different decision when the same history is replayed | Log judge/model/config/output hash; deterministic operators where possible |
| Write | Concurrent drift | Two writers update the same belief partition and both commit | Compare-and-set revisions or serializable per-key transactions |
| Write | Partial durable publication | Events become visible without their audit/receipt/cursor, or vice versa | One `BEGIN IMMEDIATE` transaction over events, both hash chains, audit, receipt, and cursor CAS |
| Write | Copied verifier result | Accepted-looking JSON is persisted without the verifier runtime that issued it | Exact process-local verifier capability for new commits; durable receipt recovery only for an exact prior request |
| Write | Historical receipt corruption | A healthy tail hides an altered older receipt or audit | Full receipt/audit history verification on startup, new commits, receipt reads, and idempotent recovery |
| Write | SQLite text alias | NUL or malformed UTF-8 bytes decode to an apparently valid JavaScript identity | Reject non-round-trippable text and compare raw SQLite `hex(...)` with canonical UTF-8 |
| Write | Schema weakening | Missing uniqueness or malicious triggers manufacture duplicates or side effects | Exact STRICT column/unique contract and no triggers on canonical tables |
| Write | Admission-policy drift | A lower current append limit invalidates already-authorized history | Separate the current admission limit from the durable protocol hard bound |
| Write | Authority escalation | A model inference is stored as if directly confirmed by a human | Authority cannot exceed cited evidence; explicit admission policy |
| Write | Duplicate evidence inflation | Chunks, retries, mirrors, or summaries of one source are treated as independent confirmations | Digest deduplication plus inherited source-group unions |
| Write | Partial multi-event commit | Early events persist before a later operation fails | Isolated semantic replay and one verified append |
| Write | Stale-base overwrite | A verified proposal commits after another writer changed memory | Base fingerprint compare-and-swap at verification and commit |
| Write | Permissive-policy injection | Untrusted code verifies itself with a caller-chosen weak policy | Trusted frozen `TransitionVerifier` capability owns policy and commit |
| Write | Verifier report replay | An old or supportive artifact is presented as a new independent check | Explicit verifier role, report digest, proposal subject, authority, and host trust boundary |
| Write | Oversized proposal | Huge operations/evidence/check graphs exhaust verification resources | Policy limits plus host-level raw request and parser-depth caps |
| State | Stale-state use | Updated evidence is retrieved but old state still drives action | Write-side adjudication plus constrained current-state projection |
| State | Ghost memory | Old, transition, and current states enter one undifferentiated prompt | Current/historical/transition roles and view-specific assembly |
| State | Implicit invalidation | A change in one slot should invalidate related assumptions | Bounded dependency propagation plus unresolved-state markers |
| State | False certainty | Conflicting evidence is forced into one confident answer | First-class ambiguity and abstention |
| Retrieval | Semantic crowding | Many near-duplicates displace the one target memory | Source-family collapse, diversity, conflict-aware ranking |
| Retrieval | Lexical cue overload | Repeated surface forms dominate sparse search | Repetition caps, temporal/state-aware features, hybrid routing |
| Retrieval | Fan-out explosion | Generic nodes activate thousands of irrelevant neighbors | Degree normalization, inhibition, hop budgets, scope filters |
| Retrieval | Similarity-only miss | Causally or temporally related memories are not textually similar | Learned associations, graph traversal, temporal and entity retrieval |
| Retrieval | Early irreversible compression | An omitted detail can never be recovered | Hierarchical anchors with callback to raw episodes and sources |
| Retrieval | Cross-project bleed | A useful lesson in one repository contaminates an unrelated task | Scope hierarchy and explicit promotion to broader scopes |
| Retrieval | Popularity lock-in | Frequently recalled memories become easier to recall regardless of value | Separate exposure from utility; exploration and counterfactual evaluation |
| Context | Context pollution | Too much relevant-but-noncritical material distracts the model | Hard budget, risk-aware selection, diversity, task-critical reservations |
| Context | Dependency omission | A procedure enters the prompt without its caveats or evidence | Dependency closure and atomic packet groups |
| Context | Order effects | The same packets produce different behavior under different ordering | Stable assembly policy, order randomization evals, position-aware tests |
| Context | Model prior override | The model ignores valid memory that conflicts with parametric knowledge | Explicit state basis, source authority, structured answer policy |
| Decision | Retrieval-use gap | Correct memory is visible but not applied | Separate evidence extraction, state resolution, policy execution, generation |
| Decision | Procedure collision | Multiple individually good skills give incompatible instructions | Applicability router, precedence contracts, conflict detection |
| Decision | High-risk overreach | A weak memory drives destructive external action | Evidence requirement, current verification, approval policy, least authority |
| Outcome | False success | The model declares completion without environmental proof | Scoped outcome events with exact evidence references and verifier-authority floors |
| Outcome | Sparse credit | Final success cannot identify which memory operation helped | Step-level transition rewards and local verifier signals |
| Outcome | Spurious credit | Every retrieved memory is rewarded after success | Usage tracing, ablations, holdouts, causal comparisons |
| Outcome | Self-confirmation loop | The agent writes a belief, retrieves it, acts on it, and treats that as confirmation | Self-derived evidence cannot independently verify itself |
| Consolidation | Lossy drift | Repeated summaries omit details and invent general rules | Raw episodes first-class; selective, versioned consolidation |
| Consolidation | Misclustering | Unrelated episodes are merged into one procedure | Structure-aware clustering and human/testable applicability hypotheses |
| Consolidation | Overgeneralization | A rule loses the conditions under which it worked | Required/forbidden features, counterexamples, per-context outcome stats |
| Consolidation | Narrow-stream overfit | Repetition in one environment is mistaken for a universal law | Cross-context validation and scope-limited procedures |
| Consolidation | Premature promotion | One impressive success becomes a trusted skill | Independent trials, confidence bounds, staged promotion |
| Consolidation | Permanent bad abstraction | A faulty skill remains active after later failures | Versioning, deprecation, rollback, utility decay, evidence reinspection |
| Learning | Catastrophic policy update | A trained memory controller improves one task and damages prior behavior | Replay suites, frozen holdouts, canaries, rollback, retention metrics |
| Learning | Reward hacking | The controller learns to manipulate the verifier or memory budget | Independent verifiers, adversarial evals, immutable outcome evidence |
| Learning | Distribution shift | A policy trained on conversational QA fails on coding or robotics | Substrate/task routing and out-of-distribution evals |
| Learning | Loss of learnability | The system retains old tasks but becomes unable to acquire new ones | Measure next-task learning rate after long update sequences |
| Learning | Model-specific lock-in | Memory only works with the model that produced it | Model-neutral canonical state and adapter-specific projections |
| Forgetting | Deletion masquerading as forgetting | Useful historical evidence is permanently removed to reduce noise | Accessibility suppression distinct from evidence deletion |
| Forgetting | No legal deletion | Derived summaries, indexes, adapters, and caches retain deleted user data | Provenance closure, tombstones, rebuildable indexes, deletion audit |
| Multi-agent | Authority confusion | One subagent's speculation becomes shared organizational truth | Actor identity, trust domains, shared-memory admission policy |
| Multi-agent | Write storms | Many agents race to duplicate or contradict the same state | Idempotency keys, partition concurrency, deduplication, backpressure |
| Operations | Index lag | Retrieval sees an older projection than the canonical ledger | Watermarks, freshness metadata, fallback to authoritative state |
| Operations | Schema drift | Old memory objects become unreadable after upgrades | Versioned event schema, migrations, replay fixtures |
| Operations | Unbounded maintenance | Consolidation cost grows with total history | Incremental partitions, recurrence triggers, bounded candidate regions |
| Operations | Hidden latency tail | Multi-hop retrieval occasionally explodes | Per-stage budgets, cancellation, degraded modes, latency SLOs |

## Intelligent design responses

### Keep two kinds of forgetting

1. **Epistemic retirement**: a claim is no longer authorized as current state.
2. **Access suppression**: a low-utility memory becomes harder to activate.

Neither necessarily deletes the underlying evidence. Privacy deletion is a separate operation with provenance-closure semantics.

### Learn negative knowledge

A useful system must remember not only what worked, but also:

- contraindications;
- failed procedures;
- contexts in which a skill should not activate;
- misleading cues;
- rejected hypotheses;
- unresolved conflicts.

Negative evidence should reduce applicability, not disappear because it has a lower success score.

### Prefer mixtures over universal rewrites

When procedure A works in context X and procedure B works in context Y, the correct result is often:

```text
router(context) -> A or B
```

not a single merged paragraph. This preserves specialization and reduces catastrophic interference between procedures.

### Separate deterministic and learned decisions

Use deterministic code for invariants such as:

- sequence ordering;
- interval containment;
- maximum-version selection when the policy is explicit;
- scope authorization;
- dependency closure;
- budget enforcement;
- evidence independence;
- state-machine transitions.

Use learned models for ambiguous semantic tasks such as candidate extraction, association proposal, or applicability prediction. Learned outputs remain governed by deterministic contracts.

### Preserve unknown-current

When an old state is invalidated but no replacement is known, the current value is not the old value. It is `unknown-current`. This prevents stale defaults from silently surviving an update.

### Make non-use observable

For each activated but unmaterialized memory, record why it was not selected. For each selected memory, record whether the model cited, expanded, or used it. Without negative selection data, the retrieval controller cannot learn intelligently.

## Open problems

The architecture reduces risk but does not solve several research questions:

- reliable implicit invalidation across arbitrary commonsense dependencies;
- causal credit assignment for interacting memories and tools;
- stable learned associations at billion-object scale;
- skill composition without combinatorial conflicts;
- privacy deletion after parametric consolidation;
- controller learning under adversarial and non-stationary feedback;
- proving that bounded-context performance does not decay with lifetime history;
- evaluating continual learnability over realistic month- or year-scale streams.

These remain explicit research targets, not implementation details to hand-wave away.

## Durable delivery failures

| Failure | Required response |
|---|---|
| New consumer silently starts at tail | Default to genesis; require explicit tail bootstrap |
| Backlog exceeds one request budget | Emit several bounded contiguous batches, never truncate |
| Tail advances before retry | Preserve the exact pending batch capability and original canonical range |
| Projection commits but cursor does not | Projection mutation, receipt, and cursor share one SQLite transaction |
| Cursor commits but projection fails | Roll back the entire consumer transaction |
| Projection code changes under one consumer id | Bind a durable configuration digest and reject drift |
| Two consumers address overlapping tables | Register exclusive non-overlapping lowercase object prefixes |
| Callback reads or writes another projection | Enforce the registered namespace on every SQL target/read |
| Callback leaks its transaction object | Revoke the capability before callback-result inspection |
| Callback hides access in joins/subqueries/CTEs | Reject multi-source and nested SQL at the boundary |
| Callback mutates consumer receipts/checkpoints | Re-attest owned state and schema before publication |
| Async callback escapes transaction lifetime | Revoke authority, then reject Promise/thenable results |
| Malformed SQLite text aliases metadata | Verify raw UTF-8 bytes, storage classes, and canonical JSON |
