# Contextual applicability hypotheses

## Purpose

A memory can have supported positive utility without being useful everywhere.

```text
memory M helped on matched task instances
```

does not imply:

```text
apply M to every future task
```

`contextual-applicability-hypotheses-v1` adds the next conservative boundary after verified experience attribution:

```text
paired attributed interventions
        -> pre-trial context features
        -> discovery hypothesis
        -> disjoint held-out validation
        -> validated applicability evidence
```

The output remains learning evidence. It is not a procedure, a promotion decision, or execution authority.

## Objects

The layer emits three process-local issued objects:

```text
VerifiedApplicabilityObservation
ApplicabilityHypothesisCandidate
VerifiedApplicabilityHypothesis
```

A structural clone is rejected wherever an issued capability is required.

## Observation boundary

`verifyApplicabilityObservation()` accepts the same treatment/control traces and intervention request used by the experience-attribution boundary. It internally obtains a new exact `VerifiedMemoryIntervention`, then binds one feature manifest to that causal observation.

The observation records:

- scope and target memory;
- comparison and experimental-unit identities;
- context, goal, and runtime digests;
- effect and source groups;
- normalized context features;
- feature-extraction schema digest;
- feature-set digest;
- feature observation time;
- trial start/completion and intervention record time.

Features must be observed no later than the start of either trial arm:

```text
featureObservedAt <= min(treatment.startedAt, control.startedAt)
```

This blocks outcome leakage such as adding `result:success` or a post-hoc diagnosis after seeing which arm won.

The host remains responsible for the truthfulness and completeness of its feature instrumentation. A schema digest identifies the extractor contract but is not remote attestation.

## Feature contract

V1 features are bounded normalized strings such as:

```text
runtime:node
framework:nextjs
symptom:race
stateful-auth:true
```

Normalization is deterministic and rejects malformed, duplicate, oversized, or empty feature sets.

Within one discovery or validation call:

- one experimental-unit digest must map to one feature-set digest;
- one context fingerprint must map to one feature-set digest;
- every observation must use one exact feature-schema digest.

A caller cannot rerun the same experimental identity and retroactively describe it with a more favorable context manifest.

## Independence before learning

The layer does not count raw observation rows.

Before rule induction or validation, it reuses the public experience-attribution assessment over the exact issued interventions. Therefore:

- duplicate experimental units contribute at most one conservative observation;
- every source-group edge from duplicate units is retained;
- transitive source-family overlap collapses into one observation;
- opposite directions inside one unit or source family remain explicit conflicts;
- caller order cannot choose a more favorable independent subset.

Accepted and excluded observation IDs, comparison IDs, assessment digest, unit digests, and source groups are retained in the candidate or validation result.

## Rule form

V1 deliberately uses an inspectable conjunction:

```text
all requiredFeatures are present
AND
no forbiddenFeatures are present
```

Example:

```text
required:
  runtime:node
  symptom:race

forbidden:
  runtime:python
```

This rule language is intentionally small. It is easier to audit, falsify, and carry into a future procedure candidate than an opaque model score.

## Discovery

`induceApplicabilityHypothesis()` receives an explicit set of discovery observation IDs.

It:

1. validates issued capabilities, scope, memory, time, schema, and manifests;
2. collapses duplicate/correlated evidence through attribution;
3. labels independent effects as positive, negative, or neutral;
4. ignores features without minimum repeated support;
5. ranks candidate literals by positive/counterexample discrimination;
6. greedily adds only deterministic score-improving clauses;
7. penalizes unnecessary complexity;
8. reports discovery metrics and blockers.

High-cardinality features that occur once, such as a unique repository ID, do not become rules merely because they identify one successful case.

Possible discovery states:

```text
candidate
ambiguous
insufficient
```

- `candidate`: discovery gates pass, but generalization is unproven.
- `ambiguous`: identical feature signatures or correlated evidence contain contradictory directions.
- `insufficient`: there are too few independent positives, counterexamples, contexts, or the rule misses discovery thresholds.

## Discovery is not validation

The observations used to construct the rule cannot prove that it generalizes.

Held-out validation rejects reuse of any discovery:

- comparison;
- experimental unit;
- verifier source group;
- feature-extraction schema mismatch.

The discovery candidate retains the complete selected source-group and unit lineage, including evidence excluded as a vote. Hidden correlated rows therefore cannot re-enter validation under another observation ID.

## Held-out validation

`validateApplicabilityHypothesis()` evaluates the unchanged candidate rule against an explicit disjoint validation set.

It does not retrain or edit the rule after seeing held-out outcomes.

Reported metrics include:

```text
precision
recall
specificity
coverage
counterexample activation rate
mean activated effect
positive / negative / neutral counts
distinct contexts
distinct experimental units
contradictory feature signatures
```

Possible states:

```text
validated
rejected
ambiguous
insufficient
```

- `validated`: held-out quantity, diversity, effect, precision, recall, specificity, and counterexample gates pass.
- `rejected`: enough held-out evidence exists, but the rule overgeneralizes or fails an effect/quality threshold.
- `ambiguous`: the same feature signature produces incompatible effects, or attribution reports a unit/source-family conflict.
- `insufficient`: discovery was insufficient or held-out coverage is too small.

A discovery-successful rule that activates harmful held-out cases is rejected rather than preserving its training-set status.

## Metrics semantics

Positive means:

```text
effect > effectThreshold
```

Negative means:

```text
effect < -effectThreshold
```

Everything inside the neutral band is a counterexample for activation precision/specificity. A rule should not activate merely because the memory was non-harmful; it needs evidence of directional utility.

For one rule:

```text
precision = positive activated / all activated
recall = positive activated / all positive
specificity = counterexamples rejected / all counterexamples
counterexampleActivationRate = counterexamples activated / all counterexamples
```

`meanActivatedEffect` uses the original bounded intervention effects, not labels alone.

## No promotion or execution authority

Every observation, candidate, and validation carries:

```text
procedurePromotionAuthorized = false
executionAuthorized = false
```

A validated applicability hypothesis means only:

> Under this bounded feature schema and held-out protocol, the attributed memory effect generalized to the reported contexts with the reported metrics.

It does not establish that the memory is a complete procedure, that every step has evidence, that risks and rollback are specified, or that a harness may execute tools.

The next path is:

```text
validated applicability
    -> step-level evidence-backed procedure candidate
    -> canary plan
    -> complete trial registry
    -> human-reviewed lifecycle
    -> separate harness execution authority
```

## Failure modes and mitigations

### Post-outcome feature leakage

Failure: a successful result is encoded as a context feature.

Mitigation: the feature manifest must be timestamped before both trial arms start.

### Feature-schema drift

Failure: discovery and validation use different extractors or semantics.

Mitigation: one exact feature-schema digest is required across the protocol.

### Retroactive context rewriting

Failure: one unit/context receives different feature descriptions on repeated observations.

Mitigation: unit and context fingerprints must each map to one feature-set digest per call.

### Memorization through unique features

Failure: a rule learns `repo:exact-training-case`.

Mitigation: minimum repeated feature support, bounded candidate features, and complexity penalty.

### Source-family inflation

Failure: copies or duplicate units become independent support.

Mitigation: exact attribution assessment is rerun before discovery and validation, preserving transitive lineage.

### Discovery/validation contamination

Failure: a discovery trial reappears in held-out validation through a new ID.

Mitigation: comparison, unit, source-group, and schema overlap are rejected.

### Majority vote over missing variables

Failure: identical feature signatures produce positive and negative effects, but the majority is accepted.

Mitigation: contradictory signatures produce `ambiguous`, indicating a missing latent feature.

### Silent rule tuning on held-out data

Failure: validation failures are used to edit the same candidate and still reported as held-out success.

Mitigation: the validation API evaluates an immutable issued candidate. A changed rule requires a new discovery candidate and a new held-out set.

### Automatic procedure promotion

Failure: `validated` is interpreted as executable skill authority.

Mitigation: explicit false promotion/execution flags and a separate future procedure boundary.

## Security boundary and limitations

V1 does not provide:

- authenticated or remotely attested feature extractors;
- durable restart-safe observation/candidate capabilities;
- a complete experiment registry preventing selective omission;
- randomized assignment or carry-over control;
- protection against a trusted host fabricating feature manifests or canonical outcomes;
- discovery of arbitrary nonlinear or latent context variables;
- multiple-comparison correction for broad exploratory feature spaces;
- online sequential-testing guarantees;
- automatic privacy classification of feature strings;
- procedure induction, canary execution, lifecycle promotion, or tool authority.

Feature names may themselves reveal sensitive project state. Hosts must keep feature vocabularies within the same scope/privacy boundary as the underlying experiment and avoid embedding secrets or raw personal data in feature strings.

## Evaluation gates

Before applicability evidence feeds procedure induction, test:

- pre-trial feature timing and schema binding;
- malformed/duplicate/oversized features;
- inconsistent unit/context manifests;
- order invariance;
- duplicate units and direct/transitive source overlap;
- opposite directions inside one unit or source family;
- high-cardinality memorization attempts;
- discovery/validation comparison, unit, source, and schema leakage;
- positive held-out generalization;
- overgeneralization rejection;
- neutral and harmful counterexample activation;
- identical-signature ambiguity;
- insufficient discovery and validation sets;
- clone/capability forgery;
- policy bounds and adversarial JSON;
- feature-schema version migration once durable records exist.

The allowed v1 claim is narrow:

> Contextual utility rules are induced only from independent attributed interventions and are considered validated only after disjoint held-out evaluation under one pre-trial feature schema. Validation still grants neither procedure promotion nor execution authority.

## Complexity

For `P` observations and `F` bounded candidate features:

```text
independence collapse: attribution assessment cost
feature statistics:   O(P * F)
greedy induction:     O(maxClauses * F * P)
validation:           O(P * clauses)
```

V1 is designed for bounded experimental datasets, not unrestricted feature mining over lifetime history.

## Next gate

`verified-procedure-candidates-v1` must require:

- validated applicability;
- ordered typed steps;
- exact step-level canonical evidence;
- dependencies and contraindications;
- risk and verification contracts;
- rollback behavior;
- immutable candidate identity;
- `executable = false`.
