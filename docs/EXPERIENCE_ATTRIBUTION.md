# Verified experience attribution

## Purpose

A persistent agent must not collapse these statements into one claim:

```text
memory M was activated during a successful run
memory M entered the model context
memory M was inspected
memory M was applied
memory M caused an improvement
```

They require different evidence. `experience-attribution-v1` introduces three process-local issued objects:

```text
VerifiedExperienceTrace
VerifiedMemoryIntervention
MemoryUtilityAssessment
```

The layer is deliberately conservative. A successful trajectory may provide useful correlation, but it does not assign positive causal utility to every memory that happened to be present.

## Trace boundary

`recordExperienceTrace()` snapshots its request once, reconstructs the exact canonical event prefix through `MemoryKernel`, and binds the trace to:

- one canonical fingerprint;
- one canonical `outcome.recorded` event;
- exact scope, task, context, goal, and experimental unit;
- exact model, tool, harness, and verifier-setup digests;
- current available evidence references;
- source groups, authorities, content hashes, and evidence roles;
- bounded start and completion times.

A stale fingerprint, unavailable evidence, scope mismatch, forged reference, future completion time, malformed runtime discriminant, sparse array, circular input, or oversized fan-in fails closed.

Trace recording currently replays and fingerprints the full canonical history. That correctness boundary remains `O(N)` and is not a production-scale claim.

## Memory-use funnel

Each memory has one use record containing an exact monotonic prefix:

```text
activated
activated -> materialized
activated -> materialized -> consulted
activated -> materialized -> consulted -> applied
```

Skipping or reordering a stage is rejected. This prevents a caller from reporting only `applied` while omitting whether the memory was actually selected, materialized, and consulted.

### Activated

The memory entered a candidate or active set.

### Materialized

The memory entered bounded model/controller context.

### Consulted

The model or deterministic controller inspected or cited it.

### Applied

Runtime instrumentation observed the memory contributing to the executed plan, action, or policy decision.

Every non-applied use requires a bounded `nonUseReason`, preserving negative selection evidence such as:

```text
lost ranking competition
out of scope
insufficient evidence
omitted by context budget
consulted but rejected
withheld by experiment
```

Only this combination is eligible for causal credit:

```text
terminalStage = applied
captureMode = runtime-instrumented
```

`host-reconstructed` and `model-reported` traces remain inspectable correlation. A model saying “I used memory X” is not runtime proof that X governed the action.

## Evidence and scope

Every use cites exact currently available canonical `EvidenceRef` objects. References are checked against the evidence projection for:

- source ID;
- source groups;
- authority;
- content digest;
- runtime-valid roles;
- availability;
- global-or-exact-scope compatibility.

The layer does not convert contextual or supportive evidence into verification authority. Copies and summaries retain their inherited source groups and therefore cannot manufacture independent attribution evidence.

## Process-local issuance

Verified traces, interventions, and utility assessments are issued as process-local capabilities. A structural clone with identical JSON is rejected when a downstream operation requires an issued trace or intervention.

This prevents arbitrary plugin/model code from fabricating an accepted-looking attribution object. It is not durable authentication: restart-safe attribution will require a future canonical re-admission protocol with authenticated recorder/controller identity, exact bytes, schema version, verifier identity, and trusted host receipts or signatures.

No attribution object in v1 is a canonical memory mutation.

## Experimental identity

Each trace identifies:

```text
task id
scope
task family
instance digest
environment digest
optional seed
context fingerprint
goal signature
model digest
tool digest
harness digest
verifier-setup digest
canonical fingerprint
```

Treatment and control must match on all of these correctness-relevant fields. Run IDs and outcome events must be distinct.

A verified intervention derives a stronger `experimentalUnitDigest` over the raw unit plus scope, target memory, task, context, goal, runtime, verifier kind, and canonical prefix. Reusing one raw unit object in a different context therefore does not create a false duplicate.

The contract cannot observe hidden variables that the host omitted from those fingerprints. It establishes a mechanically checkable minimum, not universal causal identification.

## Paired intervention

V1 supports one intervention:

```text
treatment: target memory present and runtime-applied
control:   target memory entirely withheld
```

The control may not contain the target even as merely activated or consulted. All other memory-use digests must be identical across arms. This is stricter than comparing only applied-memory sets and avoids hidden differences in materialization or consultation.

Both arms require:

- runtime-instrumented traces;
- strongly verified `tool`, `test`, or `human` outcomes;
- non-unknown outcomes;
- distinct canonical outcome events and evidence packets;
- the same actual verifier kind and verifier-setup digest.

Treatment and control may share one verifier source family inside the pair because matched arms are expected to use the same verification setup. The complete pair becomes one experimental unit. Across utility-assessment pairs, overlapping source groups are not counted as independent evidence.

Outcome contrast is explicit:

```text
success = 1.0
partial = 0.5
failure = 0.0
unknown = ineligible

effect = treatment - control
```

This is a bounded outcome contrast, not a claim that the score is a universal measure of utility.

## Correlation is preserved but cannot vote

An assessment reports successful applied traces as diagnostic correlation. These counts do not influence directional causal classification.

For example:

```text
memory M appeared in 100 verified successful runs
```

may mean M helped, was irrelevant, was selected on easy tasks, interacted with another memory, or was repeatedly summarized from one origin. Without a valid paired intervention the causal basis remains `none` and classification remains `insufficient`.

## Independence and conflicts

Utility assessment is deterministic and independent of caller ordering:

1. group paired comparisons by the full experimental-unit digest;
2. if one unit produces positive and negative directions, preserve an explicit unit conflict and count none of those rows as independent votes;
3. otherwise retain at most one same-direction observation per unit, choosing the effect closest to zero and then a digest tie-break;
4. build transitive connected components over overlapping source groups;
5. if one source-family component produces positive and negative directions, preserve an explicit source-family conflict and count none of those rows as independent votes;
6. otherwise retain at most one conservative observation per source-family component;
7. sort accepted, excluded, and conflicting identities canonically before calculating the assessment digest.

This means reversing input arrays cannot select a more favorable pair. A chain such as `A shares origin with B`, `B shares origin with C` is one correlated source family even when A and C do not directly overlap.

Opposite effects for one unit, one source family, or independent contexts are not majority-voted into a global rule. They produce `mixed`, indicating hidden conditions or missing applicability variables.

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

These are conservative engineering defaults, not scientifically universal thresholds. Policy values are snapshotted and runtime-validated.

### Supported positive

Independent matched interventions consistently improve the bounded outcome score.

### Supported negative

Independent matched interventions consistently degrade the bounded outcome score. This is first-class negative-transfer evidence and should eventually inform suppression, counterexample search, or deprecation.

### Mixed

Direction changes across independent contexts, inside one experimental identity, or inside one source-family component. The correct next step is applicability discovery, not averaging into one global utility.

### Neutral

Enough matched evidence exists, but it does not clear a directional threshold.

### Insufficient

There are too few independent pairs or contexts, even if many successful correlated traces exist.

## No promotion or execution authority

Every trace, intervention, and assessment explicitly carries:

```text
procedurePromotionAuthorized = false
executionAuthorized = false
```

A `supported-positive` assessment is learning evidence only. It is not a procedure, not a trusted skill, and not permission to run tools. The intended future path is:

```text
verified experience traces
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
record trace:              O(N canonical replay/fingerprint + uses/evidence)
verify one intervention:   O(supplied traces + memory uses)
assess P comparisons:      O(P log P + total source-group memberships)
```

The source-family collapse uses disjoint-set components rather than pairwise graph scanning. No latency or production-scale claim is made until machine-readable benchmarks cover increasing lifetime histories, trace counts, evidence fan-in, and repeated assessment streams.

## Security boundary

V1 does not provide:

- authenticated recorder or experiment-controller identities;
- remote attestation of instrumentation;
- proof that an `applied` hook measured genuine cognitive influence;
- durable canonical storage of issued capabilities;
- randomized assignment or prevention of selective experiment creation;
- hidden-confounder detection;
- protection against a trusted host fabricating canonical evidence/outcomes;
- automatic mutation of retrieval, procedure, or controller state.

## Evaluation gates

Before using attribution evidence in procedure learning, evaluate:

- exact stage-prefix validation and non-use reasons;
- stale fingerprint and unavailable-evidence rejection;
- scope and role laundering attempts;
- target leakage into control;
- changes in other memory use, model, tools, harness, verifier, context, goal, environment, or seed;
- copied trace/intervention capabilities;
- duplicate units and direct/transitive source-group overlap;
- order invariance under reversed and permuted input arrays;
- positive, negative, neutral, mixed, and insufficient cases;
- repeated nondeterministic units;
- order/carry-over effects and repeated seeds;
- bounded input and adversarial JSON behavior;
- restart behavior once durable attribution is introduced.

The allowed claim for v1 is narrow:

> Directional memory utility is not assigned from successful co-occurrence. It requires strongly verified, process-issued, matched target-withheld interventions, while conflicting and duplicated evidence remains visible and non-authoritative.
