# Canonical canary host receipts

## Purpose

A reviewed canary plan is still descriptive. It does not prove that a host admitted an assignment, granted execution, ran a subject, observed a metric, stopped on a threshold, rolled back, or verified an outcome.

`canonical-canary-receipts-v1` records those externally performed actions as process-local capabilities backed by canonical evidence:

```text
reviewed plan
  -> host admission receipt
  -> external execution-grant receipt
  -> run start and completion receipts
  -> monotonic monitoring observations
  -> deterministic stop evaluation
  -> rollback receipt when triggered
  -> canonical outcome verification
```

The module validates receipts. It does not create host authority, invoke a scheduler, call a tool, execute a procedure, or perform rollback.

## Ready-plan boundary

Every receipt requires the exact process-issued canary plan and its matching process-issued review. The review decision must be:

```text
ready-for-host-scheduling
```

The plan and review must still carry negative authority flags. A ready recommendation is not treated as scheduling permission.

## Admission receipt

An admission receipt binds:

- one subject digest from the plan population;
- the exact deterministic assignment digest and derived arm;
- plan, review, population, procedure-candidate, and scheduler identities;
- an external host-admission digest;
- currently available canonical evidence from the planned scheduler component source family;
- an admission time after review.

The caller cannot choose treatment or control. The arm is recovered from the plan assignment.

One process-local admission may exist per assignment. Exact retries return the original capability; conflicting IDs or assignment reuse fail atomically.

## Run start receipt

A start receipt requires an admitted assignment plus canonical evidence for:

- an external execution-grant digest;
- a content-addressed runner identity;
- the exact environment digest;
- run ID, subject, arm, and bounded attempt number;
- start time after admission.

The external grant must originate from the planned scheduler component source family. This records that a separate host supplied a grant; `executionAuthorized` remains false because this module did not issue it.

The guarded API enforces, within one process:

- one run ID;
- one run for each `(subject, attempt)` identity;
- the plan's maximum run count;
- the plan's maximum active concurrency.

## Completion receipt

A completion closes one active process-local run and records:

- terminal status;
- duration;
- tool-call count;
- run cost and cumulative plan cost;
- external run-receipt digest;
- canonical evidence linked to the admitted runner source family.

Evidence is retained even when the host exceeded a plan limit. Violations are explicit in `limitBreaches` rather than being rejected and lost:

```text
duration
tool-calls
plan-cost
```

A receipt documents what happened; it does not retroactively make the action compliant.

## Monitoring observations

Each observation binds one metric declared by the plan to:

- a strictly increasing sequence;
- a finite canonical value;
- a non-regressing cumulative sample count;
- a non-regressing observation time;
- the exact planned observer digest and component source family;
- an external observation digest and canonical verifier evidence.

The guarded API maintains the complete admitted prefix for each `(plan, metric)` within the process.

## Stop evaluation

A stop evaluation selects one declared stop condition and the complete process-local observation prefix available for its metric at `evaluatedAt`. Previously admitted observations cannot be omitted or replaced by caller order.

The evaluator uses the latest cumulative sample that satisfies the condition's minimum sample count and applies the plan's exact comparator and threshold. The result is either:

```text
triggered = false, action = continue
```

or the condition's planned stop action.

The evaluation is deterministic and content-addressed. It remains descriptive and grants neither scheduling nor execution authority.

## Rollback receipt

A rollback receipt is accepted only for a triggered `rollback` evaluation. It binds:

- exact evaluation and condition digests;
- the planned rollback-controller digest;
- start, completion, and bounded duration;
- succeeded, partial, or failed outcome;
- an external rollback digest;
- currently available canonical evidence from the rollback-controller source family.

Failed and partial rollback outcomes are retained as first-class evidence.

## Canonical outcome verification

A completion can be bound to one canonical `outcome.recorded` event. The verifier checks:

- exact run ID through `subjectId`;
- exact scope;
- event time after completion and before verification;
- exact planned verifier digest;
- verification evidence present in the canonical outcome event;
- continuity with the planned verifier source family;
- currently available authoritative evidence.

The resulting outcome receipt preserves the canary arm and canonical outcome without promoting the procedure.

## Atomic identity and live bounds

Public registries preflight all identity collisions before mutation. A failed run ID, subject-attempt, completion, metric sequence, evaluation, rollback, or outcome retry cannot partially reserve another key.

The run/concurrency, cumulative-cost, and observation-prefix registries are intentionally process-local. They are useful for one instrumented host process but are not a distributed lock or durable experiment registry.

## Authority invariants

All receipts preserve negative authority:

```text
hostSchedulingAuthorized = false
executionAuthorized = false
procedurePromotionAuthorized = false
```

Some receipts additionally say that an external host action or grant was observed. Observation is not authorization.

## Security and research limitations

V1 does not provide:

- cryptographic signatures from scheduler, runner, observer, verifier, or rollback controller;
- remote attestation;
- a durable cross-process run/concurrency registry;
- distributed uniqueness or exactly-once execution;
- proof that the host did not omit a receipt before it reached this process;
- sequential-testing correction;
- causal or statistical comparison of treatment and control outcomes;
- automatic rollback, quarantine, scheduling, or procedure promotion.

Within one guarded process, stop evaluation prevents omission of already admitted monitoring observations. It cannot detect observations that a trusted host never submitted.

The next gate is `held-out-canary-result-assessment-v1`: require complete assignment/run/outcome coverage or an explicitly stopped experiment, preserve missing and failed receipts, compare treatment and control under a predeclared policy, and keep promotion authority separate.


## Canonical lineage and privacy revalidation

Every receipt replays the supplied canonical history, verifies the exact current fingerprint, proves
that both the plan and independent-review prefixes are ancestors of that history by fingerprint and
event count, and reapplies the current privacy overlay to inherited plan and review evidence.
Receipt-local evidence must also have existed at the declared action time and remain currently
available.

## Environment and canonical outcome role binding

A run start must use the exact environment digest declared by the plan. Canonical outcome
verification requires each supplied verifier binding to appear in the outcome event as the exact
source ID, source groups, authority, content hash, and a `verifies` role. Reusing the same source ID
with a stronger caller-supplied role is rejected.
