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

The module validates receipts. It does not create host authority, invoke a scheduler, call a tool, execute a procedure, or perform rollback. Receipt and nested runner objects reject unknown runtime fields instead of silently ignoring them.
Public capability predicates recognize only receipts returned by the guarded API; an object issued solely by an internal validation core, or a structural clone of a public receipt, is not a public capability.

## Ready-plan boundary

Every receipt requires the exact process-issued canary plan and its matching process-issued review. The review decision must be:

```text
ready-for-host-scheduling
```

The plan and review must still carry negative authority flags. A ready recommendation is not treated as scheduling permission.

Every receipt replays the supplied canonical history, verifies the exact current fingerprint, proves
that both the plan and independent-review prefixes are ancestors of that history by fingerprint and
event count, and reapplies the current privacy overlay to inherited plan and review evidence.
Receipt-local evidence must also have existed at the declared action time and remain currently
available.

An external action digest is not a component identity digest. Admission, grant, completion,
observation, rollback, and verification inputs reject direct reuse of the scheduler, runner,
observer, rollback-controller, or verifier identity digest as the represented external action.

## Admission receipt

An admission receipt binds:

- one subject digest from the plan population;
- the exact deterministic assignment digest and derived arm;
- plan, review, population, procedure-candidate, and scheduler identities;
- an external host-admission digest;
- currently available canonical evidence whose exact host-admission digest comes from the planned scheduler component source family;
- a host-admission digest distinct from the scheduler identity digest;
- an admission time not earlier than the review.

The caller cannot choose treatment or control. The arm is recovered from the plan assignment.

One process-local admission may exist per assignment. Exact retries return the original capability; conflicting IDs or assignment reuse fail atomically.

## Run start receipt

A start receipt requires an admitted assignment plus canonical evidence for:

- an external execution-grant digest;
- a content-addressed runner identity whose exact digest remains in the planned harness source family;
- the exact environment digest;
- run ID, subject, arm, and bounded attempt number;
- a grant digest distinct from the scheduler identity digest;
- start time not earlier than admission.

The exact runner digest must originate from the planned harness component source family, the run must use the exact environment digest declared by the plan, and the exact external-grant digest must originate from the planned scheduler component source family. This records that a separate host supplied a grant; `executionAuthorized` remains false because this module did not issue it.

The guarded API enforces, within one process:

- one run ID;
- one run for each `(subject, attempt)` identity;
- contiguous retry order, where attempt `N` requires completed attempt `N - 1`;
- at most one active run for one subject;
- no retry after a successful subject attempt;
- the plan's maximum run count;
- the plan's maximum active concurrency.

## Completion receipt

A completion closes one active process-local run and records:

- terminal status;
- duration;
- run and cumulative plan tool-call counts;
- run cost and cumulative plan cost;
- external run-receipt digest;
- canonical evidence whose exact external run-receipt digest is linked to the admitted runner source family;
- an external run-receipt digest distinct from the runner identity digest.

Evidence is retained even when the host exceeded a plan limit. Violations are explicit in `limitBreaches` rather than being rejected and lost:

```text
duration
tool-calls
plan-cost
```

A receipt documents what happened; it does not retroactively make the action compliant.

A receipt digest and its source-family continuity must be satisfied by the same evidence binding. A foreign exact digest cannot borrow scheduler, runner, observer, verifier, or rollback-controller identity from an unrelated decoy record.

## Monitoring observations

Each observation binds one metric declared by the plan to:

- a strictly increasing sequence;
- a finite canonical value;
- a non-regressing cumulative sample count;
- a non-regressing observation time;
- the exact planned observer digest, retained directly in the receipt, and its component source family;
- an external observation digest whose exact binding comes from the planned observer source family and differs from the observer identity digest.

The guarded API maintains the complete admitted prefix for each `(plan, metric)` within the process.
Admission fails before one metric exceeds 4,096 observations or 250,000 canonical characters of observation IDs, so every admitted prefix remains representable by the complete-prefix evaluator under the module's canonical input bound.

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
- currently available canonical evidence whose exact external rollback digest comes from the rollback-controller source family;
- an external rollback digest distinct from the rollback-controller identity digest.

Failed and partial rollback outcomes are retained as first-class evidence.

## Canonical outcome verification

A completion can be bound to one canonical `outcome.recorded` event. The verifier checks:

- exact run ID through `subjectId`;
- exact scope, procedure ID, and population manifest context;
- event time not earlier than completion and not later than verification;
- exact planned verifier digest and an external canonical verifier classification (`tool`, `test`, or `human`);
- exact `human-explicit` authority on the external verification digest when the event claims a human verifier;
- every supplied verifier binding present in the canonical outcome event as the exact source ID, source groups, authority, content hash, and a `verifies` role;
- continuity between the exact external verification digest and the planned verifier source family;
- an external verification digest distinct from the verifier identity digest;
- currently available authoritative evidence.

The resulting outcome receipt preserves the canary arm, canonical outcome, and external verifier classification without promoting the procedure.

## Atomic identity and live bounds

Public registries preflight all identity collisions before mutation. A failed run ID, subject-attempt, completion, metric sequence, evaluation, rollback, or outcome retry cannot partially reserve another key.

The run/concurrency, cumulative-cost, cumulative-tool-call, and observation-prefix registries are intentionally process-local. They are useful for one instrumented host process but are not a distributed lock or durable experiment registry.

Exact v1 retries are also bound to the original canonical event snapshot and fingerprint. A caller cannot replay the same logical receipt against a later canonical tail and call it the same receipt; tail-independent durable idempotency remains a later boundary.

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
- tail-independent exact retry after unrelated canonical history has advanced;
- unbounded monitoring histories; v1 rejects additional samples before a complete prefix becomes inevaluable;
- proof that the host did not omit a receipt before it reached this process;
- sequential-testing correction;
- causal or statistical comparison of treatment and control outcomes;
- automatic rollback, quarantine, scheduling, or procedure promotion.

Within one guarded process, stop evaluation prevents omission of already admitted monitoring observations. It cannot detect observations that a trusted host never submitted.

The next gate is `held-out-canary-result-assessment-v1`: require complete assignment/run/outcome coverage or an explicitly stopped experiment, preserve missing and failed receipts, compare treatment and control under a predeclared policy, and keep promotion authority separate.
