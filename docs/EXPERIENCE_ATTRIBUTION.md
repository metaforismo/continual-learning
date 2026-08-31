# Verified experience attribution

## Purpose

A persistent agent must not collapse these statements into one claim:

```text
memory M was activated during a successful run
memory M entered bounded context
memory M was consulted
memory M was applied
memory M caused an improvement
```

They require different evidence. `experience-attribution-v1` introduces three process-local issued objects:

```text
VerifiedExperienceTrace
VerifiedMemoryIntervention
MemoryUtilityAssessment
```

The layer is deliberately conservative. Successful co-occurrence is retained as diagnostic correlation, but it never becomes causal credit by itself.

## Trace boundary

`recordExperienceTrace()` snapshots its request once, replays the supplied canonical prefix through `MemoryKernel`, and binds the trace to:

- an exact canonical fingerprint;
- one canonical `outcome.recorded` event;
- scope, task, context, goal, and experimental unit;
- model, tool, harness, and verifier-setup digests;
- exact available evidence references;
- source groups, authorities, content hashes, and evidence roles;
- bounded start and completion times.

A stale fingerprint, unavailable evidence, scope mismatch, forged reference, future completion time, malformed discriminant, sparse array, circular input, duplicate memory ID, or oversized fan-in fails closed.

Trace admission currently replays and fingerprints the full canonical history. That correctness boundary remains `O(N)` and is not a production-scale claim.

## Memory-use funnel

Each memory carries one exact monotonic stage prefix:

```text
activated
activated -> materialized
activated -> materialized -> consulted
activated -> materialized -> consulted -> applied
```

Skipping, reordering, or inventing a later stage is rejected.

- `activated`: the memory entered a candidate or active set.
- `materialized`: it entered bounded model/controller context.
- `consulted`: the model or deterministic controller inspected or cited it.
- `applied`: runtime instrumentation observed it contributing to the executed plan, action, or policy decision.

Every non-applied use requires a bounded `nonUseReason`. This preserves negative selection evidence such as budget exclusion, scope denial, insufficient evidence, ranking loss, or explicit rejection.

Only this combination is eligible for causal credit:

```text
terminalStage = applied
captureMode = runtime-instrumented
```

`host-reconstructed` and `model-reported` traces remain correlation. A model saying “I used memory X” is not runtime proof that X governed an action.

## Evidence and scope

Every use cites exact currently available canonical `EvidenceRef` objects. References are checked for:

- source ID;
- source groups;
- authority;
- content digest;
- runtime-valid roles;
- availability;
- global-or-exact-scope compatibility.

The layer does not reinterpret contextual or supportive evidence as verification authority. Copies and summaries retain their inherited source groups and cannot manufacture independent attribution evidence.

## Process-local issuance

Verified traces, interventions, and assessments are process-local capabilities. A structural clone with identical JSON is rejected when a downstream operation requires an issued object.

This blocks arbitrary plugin/model code from fabricating an accepted-looking attribution object. It is not durable authentication. Restart-safe attribution still requires a future canonical admission protocol with authenticated recorder/controller identities, exact bytes, verifier identity, and trusted host receipts or signatures.

No attribution object in v1 is a canonical memory mutation.

## Exact paired intervention

V1 supports one intervention:

```text
treatment: target memory present and runtime-applied
control:   target memory entirely withheld
```

The target may not appear in control even as merely activated or consulted. Every other memory-use digest must be identical across arms, so hidden differences in materialization or consultation are rejected.

Both arms require:

- runtime-instrumented traces;
- strongly verified `tool`, `test`, or `human` outcomes;
- non-unknown outcomes;
- distinct run IDs;
- distinct canonical outcome events and evidence packets;
- exact equality of scope, task, raw experimental unit, context, goal, model, tools, harness, verifier setup, canonical prefix, and verifier kind.

Treatment and control may share one verifier source family inside a matched pair because they are expected to use the same verification setup. The pair itself is one causal observation.

Outcome contrast is explicit:

```text
success = 1.0
partial = 0.5
failure = 0.0
unknown = ineligible

effect = treatment - control
```

This is a bounded contrast, not a universal utility scale.

## Cross-pair independence

Pair validity and cross-pair independence are separate contracts.

The pair verifier is strict: treatment and control must match on the full execution identity. The assessment then derives a deliberately coarser `experimentalUnitDigest` from:

```text
scope
target memory
raw unit digest
context fingerprint
goal digest
```

This prevents repeated runs of the same task instance from becoming independent votes merely because run IDs, receipts, canonical history, or verification timestamps changed. Reusing the same raw unit in a genuinely different context produces a different identity.

Assessment is deterministic and independent of caller ordering:

1. group comparisons by `experimentalUnitDigest`;
2. if one unit produces positive and negative effects, preserve a unit conflict and count none of those rows as independent votes;
3. otherwise keep at most one same-direction observation per unit, choosing the effect closest to zero and then a digest tie-break;
4. build transitive connected components over overlapping source groups;
5. if one source-family component produces positive and negative effects, preserve a source-family conflict and count none of those rows;
6. otherwise keep at most one conservative observation per source-family component;
7. sort accepted, excluded, and conflicting identities canonically before calculating the assessment digest.

A chain such as `A overlaps B` and `B overlaps C` is one correlated source family even if A and C do not directly overlap. Reversing or permuting input arrays cannot select a more favorable result.

## Correlation is preserved but cannot vote

An assessment reports successful applied traces as diagnostics. These counts do not influence directional causal classification.

```text
memory M appeared in 100 verified successful runs
```

may mean M helped, was irrelevant, appeared only on easy tasks, interacted with another memory, or was repeatedly copied from one origin. Without an accepted paired intervention, `causalBasis = none` and the result remains `insufficient`.

## Utility classifications

Possible classifications are:

```text
supported-positive
supported-negative
mixed
neutral
insufficient
```

The default policy requires:

```text
at least 5 independent pairs
at least 2 contexts
absolute mean effect >= 0.2
directional rate >= 0.6
95% Wilson lower bound >= 0.3
opposite-direction rate <= 0.2
neutral band = +/- 0.1
```

These are conservative engineering defaults, not scientifically universal thresholds.

- `supported-positive`: independent matched interventions consistently improve the bounded outcome.
- `supported-negative`: they consistently degrade it; negative transfer is first-class evidence.
- `mixed`: direction changes across independent contexts, within one unit, or inside one source family.
- `neutral`: enough matched evidence exists but no directional threshold is cleared.
- `insufficient`: too few independent pairs or contexts, regardless of correlated success volume.

Mixed evidence is not majority-voted into a global rule. It signals missing applicability variables.

## No promotion or execution authority

Every trace, intervention, and assessment explicitly carries:

```text
procedurePromotionAuthorized = false
executionAuthorized = false
```

A `supported-positive` assessment is learning evidence only. It is not a procedure, trusted skill, or tool-execution permission.

The intended path is:

```text
verified traces
  -> paired attribution
  -> context-specific utility
  -> held-out applicability hypotheses
  -> evidence-backed procedure candidate
  -> bounded canary
  -> human-reviewed lifecycle
  -> separate harness execution authority
```

## Complexity

```text
record trace:             O(N canonical replay/fingerprint + uses/evidence)
verify one pair:          O(supplied traces + memory uses)
assess P comparisons:     O(P log P + total source-group memberships)
```

Source-family collapse uses disjoint-set components rather than pairwise graph scanning. No latency or production-scale claim is made until machine-readable benchmarks cover increasing lifetime histories, trace counts, evidence fan-in, and assessment streams.

## Security boundary and known limitations

V1 does not provide:

- authenticated recorder or experiment-controller identities;
- remote attestation of instrumentation;
- proof that an `applied` hook measured genuine cognitive influence;
- durable canonical storage of issued capabilities;
- randomized assignment;
- a complete experiment registry preventing selective trial omission;
- carry-over or order-effect control beyond supplied identities;
- hidden-confounder detection;
- protection against a trusted host fabricating canonical evidence/outcomes;
- automatic mutation of retrieval, procedure, or controller state.

Process-local WeakSet issuance is a software capability boundary, not a cryptographic signature or hardware trust guarantee.

## Evaluation gates

Before attribution evidence can feed procedure learning, test:

- exact stage prefixes and mandatory non-use reasons;
- stale fingerprint and unavailable-evidence rejection;
- scope, role, authority, and source-group laundering;
- target leakage into control;
- changes in other memory use, model, tools, harness, verifier, context, goal, environment, or seed;
- copied trace/intervention capabilities;
- duplicate units and direct/transitive source overlap;
- order invariance under reversed and permuted inputs;
- positive, negative, neutral, mixed, and insufficient outcomes;
- repeated nondeterministic units;
- bounded input and adversarial JSON behavior;
- restart behavior after durable attribution exists.

The allowed claim for v1 is narrow:

> Directional memory utility is not assigned from successful co-occurrence. It requires strongly verified, process-issued, matched target-withheld interventions, while conflicting and duplicated evidence remains visible and non-authoritative.

## Next gate

`contextual-applicability-hypotheses-v1` must discover required and forbidden context features from attributed evidence, then validate them on held-out experimental units. Discovery data cannot also prove generalization.
