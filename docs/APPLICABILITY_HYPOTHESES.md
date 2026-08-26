# Held-out applicability hypotheses

## Purpose

A memory can have positive average utility and still be harmful outside a narrow context.

For example:

```text
procedure P helps Next.js authentication races
procedure P is neutral in a different concurrency model
procedure P is harmful in a stateless unit test
```

A scalar score cannot represent this safely. The system must learn:

```text
when P should activate
when P should not activate
when the available features are insufficient to decide
```

This layer transforms process-issued paired interventions into a **candidate applicability hypothesis**, then tests that candidate on a disjoint held-out set.

It does not create or promote a trusted skill.

## Structured context features

Runtime-instrumented experience traces may carry bounded canonical features such as:

```text
framework:nextjs
runtime:node
symptom:race
repo:showstead
tool:playwright
```

Features are:

- lower-cased and whitespace-trimmed;
- syntax-validated;
- unique and sorted;
- bounded to 64 per trace;
- frozen into the issued trace before paired attribution.

Treatment and control must have exactly the same feature snapshot. A caller cannot add a convenient feature after observing the result.

The feature vocabulary is not automatically trusted ontology. Instrumentation and feature extractors remain host-controlled components that require their own versioning and evaluation.

## Rule language

V1 intentionally uses a small interpretable language:

```text
all required features are present
AND
all forbidden features are absent
```

Example:

```text
required:
  - symptom:race
  - runtime:node

forbidden:
  - test:stateless
```

The rule is inspectable, deterministic, bounded in complexity, and can be rendered without asking an LLM to reinterpret it.

More expressive mixtures, disjunctions, numeric predicates, hierarchies, and learned routers are later work.

## Discovery and validation are separate capabilities

The API is split into two operations:

```text
induceApplicabilityHypothesis(discovery pairs)
        ↓
process-local candidate capability
        ↓
validateApplicabilityHypothesis(candidate, held-out pairs)
```

A structural clone of the candidate is rejected. Validation accepts only the exact process-issued candidate object.

Discovery and validation comparison ids are explicit. The sets must be disjoint not only by id, but also by:

- experimental-unit digest;
- verifier source group.

This blocks a summary, rerun analysis, or duplicate report from appearing once in discovery and again as independent held-out evidence.

## Discovery requirements

The default discovery policy requires:

```text
at least 3 positive paired effects
at least 1 negative or neutral counterexample
at least 2 distinct contexts
at most 6 rule clauses
at most 24 candidate features
minimum discovery recall 0.67
```

A candidate can still be emitted with blockers. Emission means:

> this is a reproducible hypothesis object worth inspecting or gathering more data for

not:

> this rule is valid or safe to activate.

## Deterministic induction

V1 labels effects using paired treatment-control contrasts:

```text
effect > positive threshold   -> positive
effect < -negative threshold  -> negative
otherwise                     -> neutral
```

Positive examples should activate. Negative and neutral examples are counterexamples for applicability.

The learner:

1. computes bounded feature discrimination over discovery examples;
2. considers required and forbidden literals;
3. greedily adds the deterministic literal that improves balanced discovery performance;
4. enforces minimum discovery recall;
5. penalizes rule complexity;
6. stops when no literal produces a real improvement or the clause budget is reached.

The deterministic tie-breaker is stable. Prompt order and hash-map iteration do not choose the rule.

This is a transparent baseline, not a claim that greedy conjunction learning is optimal.

## Contradictory signatures

If the exact same canonical feature signature has both positive and non-positive effects, the features do not explain the observed difference.

```text
same features -> positive
same features -> negative
```

The result remains `ambiguous` rather than forcing a winner through recency or majority vote.

Likely causes include:

- a missing context feature;
- nondeterministic environment behavior;
- hidden interaction with another memory;
- verifier noise;
- carry-over effects;
- an invalid assumption that one deterministic conjunction is sufficient.

## Held-out validation

The validation set is not used to induce literals.

The default validation policy requires:

```text
at least 5 held-out paired examples
at least 2 positive examples
at least 1 negative or neutral counterexample
at least 2 distinct contexts
precision >= 0.8
recall >= 0.6
counterexample activation rate <= 0.2
mean effect among activated examples >= 0.2
```

Possible validation states are:

```text
validated
rejected
ambiguous
insufficient
```

### `validated`

Discovery cleared its gate and all held-out quality thresholds pass.

### `rejected`

Held-out data is sufficient but the rule fails precision, recall, counterexample, or activated-effect thresholds.

### `ambiguous`

Identical feature signatures produce contradictory effects in discovery or validation.

### `insufficient`

Held-out quantity or context coverage is below the declared minimum.

## Overfitting example

Suppose discovery contains only one negative family:

```text
positive: Next.js
negative: FastAPI
```

The learner may infer:

```text
forbidden framework:fastapi
```

Held-out negatives from Django or Flask will then activate incorrectly. The hypothesis is rejected.

This is intentional evidence that discovery did not cover the relevant counterexample space. The fix is more diverse intervention data or a better feature/rule family, not lowering the threshold after seeing the result.

## Metrics

Discovery and validation both report:

```text
positive / negative / neutral counts
activated examples
true and false positive counts
false negative and true negative counts
precision
recall
specificity
counterexample activation rate
mean effect among activated examples
distinct contexts
contradictory feature signatures
```

All metrics are derived from process-issued paired interventions. Unpaired successful runs do not enter this layer.

## Independence boundary

Within discovery and within validation:

- experimental-unit digests must be unique;
- verifier source groups must not overlap.

Across discovery and validation:

- units must not overlap;
- source groups must not overlap.

This is intentionally stricter than ordinary train/test splitting because the cost of false procedural activation can accumulate over years.

## Activation boundary

A `validated` applicability hypothesis is still not authority to execute a procedure.

The later procedure router must also check:

- procedure lifecycle and version;
- current state adjudication;
- evidence availability;
- risk and approval policy;
- conflicts with other procedures;
- tool/environment compatibility;
- rollback and verification contract.

Applicability answers only:

> do the observed structured context features match this held-out-supported hypothesis?

## Process-local issuance

Candidate and validation objects are process-local capabilities. Cloned JSON is rejected.

V1 does not yet persist hypotheses as canonical learning events. A durable version will require:

- schema-versioned canonical bytes;
- exact discovery and validation comparison references;
- controller/feature-extractor versions;
- policy digest;
- authenticated actor or trusted-host receipt;
- revocation and supersession semantics.

## Complexity

For `E` examples and `F` bounded candidate features:

```text
feature preparation:        O(E * F)
greedy induction:           O(maxClauses * F * E)
held-out validation:        O(E * clauses)
```

V1 bounds:

```text
comparisons <= 1,000
features per comparison <= 64
candidate features <= 32
clauses <= 16
```

No million-example or production latency claim is made.

## Security and epistemic boundary

The module does not provide:

- authenticated feature instrumentation;
- causal proof under hidden confounding;
- randomized experiment scheduling;
- automatic discovery of missing variables;
- durable capability recovery after restart;
- safe procedure composition;
- automatic retrieval-policy mutation;
- digital signatures or remote attestation.

An operator able to fabricate the underlying canonical outcomes and paired interventions can fabricate an apparently validated hypothesis.

## Non-claims

This layer does not prove:

- universal applicability;
- arbitrary causal identification;
- automatic skill acquisition;
- continual learning;
- infinite context;
- safe autonomous execution.

It establishes a narrower invariant:

> A memory applicability rule is induced only from independent paired effects and earns `validated` status only on held-out experimental units and verifier origins that meet explicit precision, recall, counterexample, and effect thresholds.
