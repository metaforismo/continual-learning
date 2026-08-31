# Bounded non-executable canary plans

## Purpose

A verified procedure candidate is still review material. It has not been scheduled, executed, or proven safe under live conditions. `bounded-non-executable-canary-plans-v1` introduces a separate planning boundary that answers a narrower question:

> Can an exact treatment/control experiment be specified with a content-addressed population, coherent resource limits, evidence-bound runtime identities, defensive stopping rules, inherited rollback, and independent review while granting no operational authority?

The result may be a `BoundedCanaryPlan` and an advisory `CanaryPlanReview`. Neither object schedules a run or executes a procedure.

## Required upstream capability

Planning requires the exact process-issued `VerifiedProcedureCandidate` capability. Structural JSON copies are rejected before candidate properties are trusted.

The plan binds:

- candidate ID and digest;
- procedure ID and immutable version;
- scope and risk;
- held-out applicability binding;
- procedure verification contract digest;
- procedure rollback contract digest;
- inherited candidate provenance and source groups.

No caller can substitute a broader applicability rule, weaker verification contract, or different rollback contract during canary planning.

Destructive candidates are rejected in v1.

## Content-addressed population manifest

Population entries contain only:

```text
subjectDigest
experimentalUnitDigest
normalized context features
```

Unknown fields are rejected. In particular, callers cannot silently add raw names, email addresses, account IDs, or other direct identifiers to a subject object.

Every subject and experimental unit digest must be unique. Context features must already be normalized, deduplicated lowercase text under the same feature-schema digest used by held-out applicability validation.

The exact validated applicability rule determines eligibility. Inapplicable subjects remain visible as `excluded` rather than disappearing from the manifest.

V1 requires at least four applicable subjects.

## Deterministic treatment/control assignment

For each applicable subject, the plan derives a content address from:

```text
candidate digest
assignment seed digest
subject digest
experimental unit digest
context-feature digest
```

Applicable subjects are sorted by that address and alternated between treatment and control. This makes assignment:

- deterministic;
- independent of caller array order;
- content-addressed;
- guaranteed to produce non-empty treatment and control arms once the minimum population is met.

The plan stores the assignment digest for every subject. It does not reveal or accept raw subject identity.

This is deterministic assignment, not a claim of cryptographically unpredictable randomization. An external experiment controller may require a stronger authenticated randomization protocol later.

## Blast-radius budget

Every plan declares safe-integer bounds for:

```text
subjects
runs
concurrent runs
duration
tool calls
cost in micros
retries per subject
```

The subject limit must equal the exact eligible population size. Run count must be coherent with subjects and retries. Concurrency cannot exceed either subjects or runs.

High-risk plans are additionally constrained to:

```text
at most 8 subjects
exactly 1 concurrent run
at most 1 hour
no retries
```

These are admission ceilings, not runtime enforcement. A later host receipt protocol must prove that the actual execution stayed inside them.

## Runtime identity

The plan binds content digests for:

- scheduler;
- harness;
- observer;
- verifier;
- rollback controller;
- environment.

The identity requires currently available, scope-authorized, non-secret evidence with `tool-verified` authority or stronger and a `verifies` or `constrains` role.

These are evidence-bound identities, not remote attestation. V1 does not prove that the named binaries were installed or invoked.

## Stop conditions

A stop condition declares:

```text
stable ID
category
metric
comparator
finite threshold
observation window in runs
action
canonical evidence
```

Categories are:

```text
quality
cost
safety
security
```

Actions are:

```text
pause
abort
rollback
```

Every plan requires quality and cost conditions. A procedure containing a `mutate` step additionally requires safety and security conditions, and both must trigger rollback.

Conditions are declarative. The library neither observes metrics nor takes actions.

## Abort and inherited rollback

The canary abort contract names evidence-backed instructions and the exact stop-condition IDs that trigger abort or rollback behavior.

Rollback semantics are inherited by digest from the verified procedure candidate. Canary planning cannot quietly replace the candidate's rollback contract.

A mutative canary must include at least one explicit rollback trigger.

## Time, privacy, and scope

The plan names the exact canonical event-history fingerprint used during admission. Every evidence reference must:

1. have existed and been available at the plan's `recordedAt`;
2. remain currently available;
3. remain global or inside the candidate scope;
4. preserve its exact source groups, authority, content digest, and role;
5. avoid secret or `secret-detected` material.

This preserves transaction-time evidence while applying the current privacy overlay.

## Independent review

A plan begins with:

```text
reviewStatus = pending-independent-review
```

Review requires another process-issued capability. The reviewer cannot be the plan author. Review evidence must be `tool-verified` or stronger, carry the `verifies` role, and come from source groups disjoint from both candidate provenance and plan-construction provenance.

Decisions are:

```text
approve
request-changes
reject
```

An approval produces only:

```text
recommendation = ready-for-host-scheduling
```

It does not authorize host scheduling. Non-approval decisions require explicit findings.

One reviewer may issue only one immutable review for one exact plan digest. Conflicting retries fail closed.

## Identity and idempotency

The guarded API binds both:

```text
plan ID
candidate digest + population manifest digest
```

Both registries are preflighted before mutation. A conflict on candidate/population identity therefore cannot reserve a fresh plan ID and poison a later valid request.

Review IDs and plan/reviewer identities follow the same atomic pattern.

Exact retries return the original capability.

## Authority boundary

Every plan contains literal values:

```text
status = plan
reviewStatus = pending-independent-review
executable = false
hostSchedulingAuthorized = false
procedurePromotionAuthorized = false
executionAuthorized = false
```

Every review contains:

```text
reviewComplete = true
executable = false
hostSchedulingAuthorized = false
procedurePromotionAuthorized = false
executionAuthorized = false
```

This tranche imports no process, filesystem, network, shell, scheduler, or tool-execution primitive.

The intended progression is:

```text
verified attribution
  -> held-out applicability
  -> verified procedure candidate
  -> bounded canary plan
  -> independent advisory review
  -> separate authenticated host scheduling capability
  -> bounded execution receipts
  -> monitoring, stop, rollback, and outcome receipts
  -> lifecycle governance
```

No arrow is implicit.

## Complexity and bounds

Planning is bounded by explicit limits on canonical input size, event count, subjects, features, evidence, stop conditions, findings, and numeric budgets.

Canonical history replay remains `O(N)` in the supplied lifetime history. Population normalization and assignment are `O(S log S)`. These are correctness properties, not production-latency claims.

## Known limitations

V1 does not provide:

- authenticated or unpredictable random assignment;
- durable cryptographic authentication of process-local capabilities;
- remote attestation of scheduler, harness, observer, verifier, or rollback controller;
- runtime enforcement of blast-radius budgets;
- metric collection or stop-condition evaluation;
- scheduling, execution, abort, or rollback;
- proof that treatment and control were actually run as declared;
- sequential-testing correction or a complete omission-resistant experiment registry;
- outcome aggregation or procedure lifecycle promotion.

Those belong to the receipt and trusted-host boundary that follows.

## Evaluation gates

Before plans can feed a host scheduler, test at least:

- cloned and forged candidate/plan/review capabilities;
- stale canonical history and current privacy changes;
- secret, weak, contradictory, or cross-scope evidence;
- raw subject identity fields and duplicate units;
- caller-order invariance;
- empty treatment/control arms and too-small populations;
- incoherent run, retry, concurrency, duration, tool, and cost limits;
- high-risk and destructive bypasses;
- missing quality/cost conditions;
- missing safety/security rollback conditions for mutation;
- same-author and source-family-correlated reviews;
- partial registry-poisoning attempts;
- sparse, circular, oversized, and non-canonical input;
- every authority field remaining false.

## Next gate

`canonical-canary-receipts-v1` should admit authenticated host-issued receipts for assignment, bounded execution, observations, stop-condition evaluation, rollback, and verified outcomes. Receipt admission must prove exact plan binding and preserve the separation between learning evidence and host execution authority.
