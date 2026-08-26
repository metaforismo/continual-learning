# Verified experience attribution

## Purpose

A persistent agent must not confuse these statements:

```text
memory M was retrieved during a successful run
memory M was read by the model
memory M affected the chosen action
memory M caused an improvement
```

They are different claims with different evidence requirements.

This layer introduces two process-local, verifier-issued objects:

```text
VerifiedExperienceTrace
VerifiedMemoryIntervention
```

The first records what was exposed, what was actually applied, and which canonical outcome followed. The second represents a strict paired comparison in which the target memory is the only applied-memory difference between treatment and control.

The project deliberately does **not** reward every memory present in a successful trajectory.

## Canonical outcome binding

A trace is admitted only against an exact canonical memory fingerprint and a canonical `outcome.recorded` event.

The trace must agree with that outcome on:

- scope;
- task id;
- context fingerprint;
- completion time;
- verifier kind;
- independent source groups;
- currently available evidence references.

If outcome evidence is later restricted or deleted, a new trace cannot use it as current verified learning evidence.

V1 recomputes the complete canonical fingerprint when recording a trace. This is intentionally conservative and currently `O(N)`.

## Exposure stages

Each memory exposure is classified as one of:

```text
activated
materialized
consulted
applied
```

### `activated`

The memory entered the controller's candidate or active set.

### `materialized`

The memory entered the bounded model context.

### `consulted`

The model or controller inspected or cited it.

### `applied`

Runtime instrumentation observed the memory contributing to the executed plan, action, or policy decision.

Only:

```text
stage = applied
captureMode = runtime-instrumented
```

is eligible for paired credit assignment.

A model saying “I used memory X” is not runtime evidence that X was applied. Model self-reports and human-reviewed traces can remain useful for inspection, but V1 does not treat them as causal credit inputs.

Every non-applied exposure requires a `nonUseReason`. This preserves negative selection data such as:

```text
lost ranking competition
excluded by scope
insufficient evidence
budget omitted
consulted but rejected
withheld by experiment
```

## Evidence and scope

Every exposed memory must cite currently available canonical evidence. Evidence may be global or match the trace scope; narrower evidence cannot silently train a broader scope.

Evidence roles are runtime validated. Packet kinds and exposure stages are also checked at runtime rather than trusting TypeScript types on replayed JSON.

A memory id is unique within one trace. Multiple appearances of the same memory at different stages must be represented by the final measured stage or by a future explicit stage-transition trace, not duplicate entries that inflate exposure counts.

## Process-local issuance

Verified traces and interventions are process-local capabilities. A structural clone with identical fields is rejected by paired verification and utility assessment.

This prevents arbitrary callers from manufacturing apparently verified experience records by copying or editing JSON.

V1 does not yet persist these capability objects as canonical experience events. After restart, durable traces will need a separate re-admission protocol bound to canonical bytes, verifier identity, schema version, and signatures or trusted host receipts.

## Experimental unit

Each trace identifies an experimental unit:

```text
task family
instance digest
environment digest
optional seed
```

Treatment and control must match exactly on:

- scope;
- experimental-unit digest;
- task family;
- context fingerprint;
- goal signature.

This does not prove that every hidden environmental variable is controlled. It establishes a mechanically checkable minimum matching contract.

## Paired memory intervention

V1 supports one intervention:

```text
removed
```

The treatment must have the target memory in the runtime-instrumented `applied` set. The control must not apply it. After sorting the applied-memory sets:

```text
treatment - control = {target memory}
control - treatment = {}
```

Any additional applied-memory difference rejects the comparison.

Both outcomes must be strongly verified by:

```text
tool
test
human
```

`model`, `none`, and `unknown` outcomes are not accepted for paired attribution.

Treatment and control outcome evidence must come from disjoint independent source groups. Two reports derived from the same test run do not form an independent pair.

The effect scale is deliberately small and explicit:

```text
success = 1.0
partial = 0.5
failure = 0.0
unknown = ineligible

effect = treatment score - control score
```

This is an outcome contrast, not a universal causal estimate.

## Why successful correlation is insufficient

The assessment reports `correlatedVerifiedSuccesses`, but those successes do not promote memory utility.

For example:

```text
memory M applied in 100 successful runs
```

may mean:

- M helped;
- M was irrelevant;
- M was always selected on easy tasks;
- another procedure caused success;
- the controller ignored M;
- the same underlying run was summarized repeatedly.

Only admissible paired interventions contribute to V1 directional utility support.

## Independence and deduplication

Utility assessment accepts at most one comparison per experimental-unit digest and excludes comparisons whose verifier source groups overlap a previously accepted pair.

This prevents inflation from:

- rerunning analysis over the same execution;
- mirrored logs;
- summaries of one verifier result;
- multiple comparison objects over one treatment/control unit;
- shared verification origins presented as independent experiments.

Exact trace ids, trace digests, comparison ids, and comparison digests must also be unique within one assessment call.

## Utility assessment

For one memory, V1 reports:

```text
independent paired interventions
excluded correlated pairs
distinct contexts
positive / negative / neutral effects
mean effect
positive and negative directional rates
Wilson lower bounds
correlated verified successes
accepted and excluded comparison ids
promotion blockers
```

Possible statuses are:

```text
insufficient
supported-positive
supported-negative
mixed
neutral
```

The default policy requires:

```text
at least 5 independent pairs
at least 2 contexts
absolute mean effect >= 0.2
directional rate >= 0.6
directional Wilson lower bound >= 0.3
opposite-direction rate <= 0.2
```

These are conservative initial gates, not scientifically universal thresholds.

## Negative utility

The same machinery can establish that a memory is harmful.

```text
treatment with M fails
control without M succeeds
```

Repeated independent negative effects can produce:

```text
supported-negative
```

This evidence should eventually lower applicability, trigger suppression or deprecation, and generate counterexample analysis. V1 only measures and reports the support; it does not automatically mutate retrieval or procedure state.

## Mixed effects

When positive and negative effects both exceed the permitted opposite-direction rate, the result is `mixed` rather than averaging them into a misleading global utility score.

A mixed result is evidence that applicability conditions are incomplete. The correct next action is usually to split contexts or learn a router, not to merge everything into one universal rule.

## Assumptions and open confounding

Even a mechanically valid pair can remain biased by:

- hidden environment differences not represented in the unit digest;
- order and carry-over effects;
- nondeterministic tools;
- model sampling variation;
- interaction between the target memory and unmeasured state;
- interference between runs;
- verifier error;
- selective experiment creation.

V1 therefore calls its output **paired attribution evidence**, not proof of general causality.

Future work should add randomized withholding, crossover designs, repeated seeds, pre-registered units, richer environment manifests, sequential testing, and counterfactual replay.

## Separation from procedure promotion

This layer does not directly promote a memory into a trusted procedure.

The future path is:

```text
verified experience traces
        ↓
paired attribution evidence
        ↓
context-specific utility support
        ↓
applicability and counterexample induction
        ↓
procedure candidate
        ↓
held-out validation and canary
        ↓
trusted procedure
```

Procedure promotion still requires applicability boundaries, independent outcomes, counterexamples, rollback, and negative-transfer evaluation.

## Complexity

```text
record trace canonical replay/fingerprint: O(N)
verify one paired intervention:           O(T + E)
assess P comparisons:                     O(P log P)
```

where `T` is supplied traces and `E` is exposure-set size.

No production-scale performance claim is made.

## Security boundary

The module currently does not provide:

- authenticated recorder or experiment-controller identities;
- digital signatures or remote attestation;
- durable canonical storage of issued trace capabilities;
- sandboxing of runtime instrumentation;
- proof that an instrumentation hook measured true cognitive use rather than superficial access;
- automatic randomized experiment scheduling;
- protection from a trusted host fabricating canonical outcomes and evidence.

## Non-claims

This layer does not prove:

- arbitrary causal identification;
- continual learning;
- infinite context;
- automatic skill acquisition;
- safe online controller updates;
- absence of hidden confounding.

It establishes a narrower invariant:

> Memory utility cannot receive directional support merely from co-occurring with success; it requires independent, strongly verified, process-issued paired interventions whose applied-memory sets differ only by the target memory.
