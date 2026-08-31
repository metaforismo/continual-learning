# Evaluation and evidence ladder

The project will not use a single recall score as proof of continual learning.

## Stage-decomposed evaluation

Every end-to-end error should be localized to one of these boundaries:

```text
capture -> write/admission -> state projection -> retrieval/activation
        -> selected canonical rehydration -> context compilation
        -> decision/use -> action -> verified outcome
        -> attribution -> applicability -> procedure candidate -> later canary/lifecycle
```

Report both final task accuracy and intermediate diagnostics.

## Evaluation suites

### A. Ledger, evidence, and replay

- deterministic structural and semantic replay from the same event stream;
- content-address verification and duplicate-byte/source-independence attacks;
- provenance DAG order and lineage closure;
- taint, sensitivity, authority, and scope laundering attempts;
- evidence restriction/deletion effects on derived state;
- immutable snapshots;
- duplicate/idempotency handling;
- crash-prefix recovery;
- real process termination after event/audit/receipt/cursor writes but before SQLite commit;
- exact restart idempotency without new mutation authority;
- raw SQLite NUL and malformed UTF-8 aliases in events, receipts, audits, and cursor metadata;
- historical receipt/audit corruption after an otherwise healthy startup;
- schema weakening through missing uniqueness or canonical-table triggers;
- schema migration fixtures;
- concurrent update anomalies.

### B. State correctness

- explicit supersession;
- implicit invalidation;
- current-state queries;
- historical-state queries;
- transaction-time queries;
- premise resistance;
- unresolved and disputed state;
- multi-hop invalidation propagation.

### C. Retrieval and activation

- exact fact recall;
- paraphrased recall;
- associative recall without semantic similarity;
- temporal and causal recall;
- early-versus-late history;
- interference from repetitions and same-slot conflicts;
- exhaustive multi-target retrieval;
- activation precision, recall, and calibration;
- fan-out and latency scaling;
- address-only candidate output without accidental content authority;
- selected canonical evidence and claim rehydration after candidate discovery.

### D. Context compilation

- token-budget compliance;
- source/evidence closure;
- current versus historical authorization;
- ambiguity handling;
- packet ordering sensitivity;
- diversity and redundancy;
- high-risk evidence requirements;
- model-specific prompt-template effects.

### E. Memory transition reliability

- atomic all-or-nothing replay of multi-event proposals;
- stale-base verification and commit races;
- omitted inputs, undeclared used evidence, and invalid ignore reasons;
- corruption of unrelated claim/evidence lifecycle state;
- exact affected-state coverage and before/after assertions;
- assertions that try to hide writes through early world time or old transaction time;
- unsupported additions and authority/scope escalation, including implicit global writes;
- risk under-declaration and cumulative check requirements;
- audit/result/append digest tampering;
- proposer/verifier self-confirmation and copied-result commit attempts;
- semantic report digest, role, subject, and evidence-authority binding;
- prompt-injection persistence, tainted associations/outcomes, and secret capture;
- policy resource-limit bypass and oversized proposal behavior;
- replay inconsistency and unknown future event types;
- duplicate artifacts presented as independent confirmation.

### F. Procedural learning

- same-error recurrence after correction;
- transfer to unseen cases;
- applicability precision and recall;
- contraindication recall;
- cross-context validation;
- full discovery/held-out lineage preservation;
- step-local versus generic evidence laundering;
- dependency, verifier, and checkpoint digest binding;
- verification dependency-closure coverage;
- risk and rollback under-declaration;
- immutable candidate ID/version conflict handling;
- explicit absence of promotion, canary, scheduling, and execution authority;
- procedure collision;
- negative transfer;
- degradation after repeated consolidation.

### G. Continual learning

Use long streams such as:

```text
learn A -> learn B -> ... -> learn Z -> retest A...Z -> learn AA
```

Measure:

- average accuracy;
- backward transfer / forgetting;
- forward transfer;
- next-task learning rate;
- worst-task retention;
- calibration;
- memory/controller growth;
- read, write, context, and training cost;
- rollback recovery.

### H. Portability

- swap the foundation model while retaining canonical memory;
- reconstruct behavior from the same ledger and controller version;
- export, clear, restore, and verify identity/project-state integrity;
- compare adapter-specific context projections.

## Baselines

Each experiment should compare against the smallest credible alternatives:

1. no memory;
2. full context where feasible;
3. recency window;
4. BM25 / sparse retrieval;
5. dense top-k retrieval;
6. flat extracted-memory bank;
7. hierarchical summary retrieval;
8. temporal/graph memory;
9. episodic-only replay;
10. procedure-only consolidation;
11. learned memory manager;
12. oracle evidence and oracle state projections.

A complex architecture is justified only when it beats simpler baselines on quality **and** cost or reliability.

## Core metrics

```text
Recall@k
Precision@k
MRR
state resolution accuracy
premise resistance
historical accuracy
multi-target coverage
context utilization
transition omission/corruption/hallucination
error recurrence rate
applicability precision/recall
procedure step evidence coverage
procedure contraindication coverage
procedure candidate conflict/rejection rate
retention and backward transfer
next-task learning rate
p50/p95/p99 latency
write amplification
model-context tokens per request
storage/index growth
selected-object bucket size
selected-object proof size
compound-read retry rate
full audit and rebuild time
```

## Causal memory utility

A memory should not receive credit merely because it was present in a successful run.

Where affordable, evaluate:

```text
outcome(with selected memory)
outcome(with memory removed)
outcome(with alternative memory)
```

Use paired tasks, deterministic verifiers, and replayable environments. Report confidence intervals and the number of independent source groups.

## Verified procedure-candidate evaluation

Evaluate the candidate boundary independently from applicability discovery and independently from
future canary execution. A correct candidate test does not need to execute any instruction.

### Positive construction

Construct a candidate from a real process-issued validated applicability capability and canonical
evidence. Verify that the resulting object preserves:

- exact discovery and held-out observation, comparison, unit, source-family, metric, and digest lineage;
- required and forbidden feature rules;
- semantic step order and canonicalized unordered sets;
- step-exclusive supportive evidence anchors;
- evidence-bound dependency versions, verifier implementation, and restore checkpoint;
- evidence-backed contraindications;
- risk, verification, and rollback contracts;
- immutable candidate and procedure-version identity;
- `executable = false` and every authority flag set to false.

### Adversarial matrix

Reject or classify explicitly:

- cloned upstream capabilities and stateful property getters;
- stale fingerprints, historical backdating, sparse arrays, circular JSON, and oversized requests;
- unavailable, restricted, deleted, cross-scope, context-only, contradicting, constraints-only, or secret evidence;
- generic evidence copied onto all steps;
- forward step dependencies and a final verifier that omits prior steps;
- dependency/verifier/checkpoint digests without exact digest-matching authoritative evidence;
- a human verifier backed only by policy or tool evidence;
- overlapping success/failure criteria;
- low-risk mutation and disable-only rollback;
- conflicting candidate IDs or immutable procedure versions;
- any implicit promotion, canary planning, host scheduling, or execution authority.

### Determinism and retry

Permute every semantically unordered input collection while retaining exact step order. Candidate
bytes and digest must remain identical. Exact retries must return the same issued capability; a
failed identity/version conflict must not reserve either registry key.

### Allowed claim

Until durable admission and real canary trials exist, the allowed claim is limited to:

> The kernel constructs an immutable, evidence-bound, non-executable procedure candidate from an
> issued held-out applicability result and rejects the documented provenance, identity, risk, and
> authority violations in deterministic tests.

## Verified bounded-canary-plan evaluation

Evaluate planning independently from procedure-candidate construction and independently from future
trial execution. A correct plan test does not schedule a task or invoke a tool.

### Positive construction

From an exact issued procedure candidate and canonical evidence, verify that a plan preserves:

- the exact candidate, applicability, verification, rollback, risk, canonical-prefix, and provenance lineage;
- deterministic non-empty treatment and control assignment for the same normalized population;
- coherent trial, concurrency, subject, wall-clock, token, tool-call, external-action, and cost budgets;
- explicit sandbox, network, and tool policy;
- exact digest-matching verifier evidence for scheduler, harness, observer, verifier, rollback controller, and environment identities;
- quality, cost, safety, and security stopping with complete rollback coverage;
- independent advisory review without scheduling, execution, or promotion authority.

### Adversarial matrix

Reject or classify explicitly:

- cloned candidate or plan capabilities and conflicting process-local IDs;
- stale, truncated, or forked candidate/plan canonical prefixes;
- backdated plans or reviews;
- unavailable, restricted, deleted, cross-scope, or secret inherited/plan/review evidence;
- runtime component digests backed only by unrelated evidence;
- duplicate subjects, raw identity fields, inapplicable populations, or empty trial arms;
- incoherent budgets, high-risk over-allocation, missing safety/security stops, and incomplete rollback coverage;
- destructive candidates, unsafe mutative rollback, reused review source families, and reviewer/author identity reuse;
- any implicit host scheduling, tool execution, or procedure-promotion authority.

### Allowed claim

Until complete hosted trial assessment exists, the allowed planning claim is limited to:

> The kernel constructs and independently reviews an immutable, evidence-bound, bounded,
> non-executable canary plan and rejects the documented lineage, privacy, identity, budget,
> stopping, rollback, and authority violations in deterministic tests.


## Canonical canary host-receipt evaluation

Evaluate the receipt boundary independently from planning and independently from treatment/control
assessment. Tests may simulate external host evidence, but the receipt module must never schedule or
execute the represented action.

### Positive construction

From one exact reviewed plan, verify the complete process-local path:

- deterministic subject admission recovers the plan arm rather than accepting caller choice;
- runner identity is tied to the planned harness family and the external grant to the scheduler family;
- completion closes the active subject slot and retains terminal status, run/cumulative cost, and run/cumulative tool calls;
- observer samples advance monotonically and stop evaluation consumes the complete admitted prefix;
- triggered rollback preserves succeeded, partial, and failed outcomes as evidence;
- canonical outcome verification binds the exact run, procedure, population manifest, verifier class, and exact canonical evidence;
- every result remains immutable, content-addressed, and authority-negative.

### Adversarial matrix

Reject or preserve explicitly:

- split-evidence laundering, where the exact digest and expected source family come from different records;
- planned component identity evidence reused directly as an admission, grant, completion, observation, rollback, or verification action receipt;
- runner identities outside the planned harness lineage;
- stale/forked canonical fingerprints and evidence that was unavailable at action time or is restricted now;
- unknown top-level or nested runner fields carrying authority-like claims;
- duplicate/conflicting admission, run, completion, metric sequence, evaluation, rollback, or outcome identities;
- skipped or overlapping retries, retry after success, concurrency overflow, and cumulative resource overflow;
- omitted admitted monitoring samples, undeclared metrics, regressing sequence/sample/time, and forged observation sets;
- monitoring prefixes admitted beyond the evaluator's count or canonical representation bounds;
- rollback without a triggered rollback condition or with the wrong controller lineage;
- outcome events for another run, procedure, population, time interval, verifier family, model-only verifier class, or a human label without exact human-explicit evidence;
- internal-core receipts and structural clones presented as guarded public capabilities;
- a logical retry presented against a canonical tail different from the original receipt snapshot;
- any implicit scheduling, execution, rollback invocation, or procedure promotion authority.

### Allowed claim

Until a complete durable experiment registry and held-out reducer exist, the allowed claim is:

> The kernel validates evidence-backed, process-local receipts for externally performed canary host
> actions and rejects the documented lineage, identity, retry, meter, monitoring, outcome, and
> authority violations in deterministic tests. It does not execute the canary, prove host
> completeness, or demonstrate a treatment effect.

## Evidence ladder

### Level 0 — specification

Architecture, invariants, threat model, and tests over hand-built cases. No capability claim.

### Level 1 — deterministic kernel

Replay, evidence, bitemporal state, adjudication, transition verification, quarantine, activation, compilation, conservative attribution, held-out applicability, non-executable procedure-candidate and canary-plan, guarded canary-receipt, change-feed delivery, and selected-object-read invariants pass locally and in CI.

Allowed claim: "the kernel enforces these tested contracts."

### Level 2 — controlled synthetic memory

Stress updates, contradictions, poisoning, multi-target recall, selected-object reads, and growth over millions of generated events.

Allowed claim: "the system maintains specified memory properties under controlled workloads."

### Level 3 — established public benchmarks

Evaluate on LongMemEval, LoCoMo, MemoryAgentBench, MINTEval, STALE-like conflict suites, HaluMem-like transition tests, and agentic tasks.

Allowed claim: benchmark-specific results with complete configuration and cost.

### Level 4 — cross-domain procedural learning

Demonstrate lower same-error recurrence and transfer on coding, web, planning, and another non-text-only environment.

Allowed claim: "the agent learns reusable procedures in these evaluated domains."

### Level 5 — long-stream continual learning

A/B evaluation over long non-stationary task streams, including retention and continued learnability.

Allowed claim: "the controller shows continual-learning behavior under this protocol."

### Level 6 — model portability and production scale

Multiple foundation models, billion-scale memory simulation or real workloads, privacy deletion, multi-tenant isolation, failure recovery, and cost SLOs.

Allowed claim: production-readiness only for the verified deployment envelope.

### Level 7 — parametric consolidation

Optional adapter/weight learning with capability-retention, privacy, rollback, and provenance tests.

Allowed claim: in-weight continual learning only if the learned parameters, not hidden retrieval, carry the measured gain.

## Reproducibility rules

Every result must retain:

- exact commit;
- dataset and split hashes;
- model/provider/version;
- prompts and tool schemas;
- controller and index versions;
- event ledger seed;
- budget and latency settings;
- random seeds;
- raw per-case outputs;
- evaluator implementation;
- failures and excluded cases;
- cost accounting.

Do not report a headline number without a machine-readable manifest and a rerunnable command.

## Durable delivery and consumer evaluation

Delivery tests must cover genesis versus explicit-tail bootstrap, multi-batch catch-up, stable batch identity after concurrent appends, persisted checkpoint verification, forged/copy capability rejection, exact pending retry after concurrent tail advancement, reentrancy, configuration drift, namespace overlap/cross-consumer access, leaked-capability revocation, joins/subqueries and SQL escape attempts, parameter bounds, single-read request/binding snapshots, idempotent restart, fault injection, real process crash, consumer-schema tampering, raw SQLite byte corruption, and independent consumer chains.

## Canonical object-read evaluation

The selected-object path must be evaluated separately from candidate retrieval and separately from full forensic audit.

### Correctness parity

For generated and adversarial histories, compare every selected result with deterministic replay of the same canonical prefix:

```text
object-read projection result == canonical replay result
```

Cover:

- current evidence and claims;
- transaction-time `knownAt` versions;
- claim world-time `validAt` views;
- superseded and revoked states;
- evidence available/restricted/deleted transitions;
- exact evidence-reference closure;
- explicit global and project scope combinations.

### Tamper matrix

Mutate independently and coherently:

- canonical state JSON;
- state digest;
- version row digest;
- head digest;
- transaction interval;
- deterministic bucket assignment;
- bucket item count and digest;
- sparse sibling and internal node;
- published root and count;
- cursor digest, batch ID, revision, and configuration digest;
- claim evidence ID, source groups, authority, digest, and roles.

Selected reads and `audit()` must fail closed for every corruption class they claim to detect. Coherent replacement of the whole derived database is outside the v1 internal-root guarantee and must be tested against the future external-commitment boundary rather than misreported as solved.

### Concurrency and snapshot consistency

Exercise canonical and projection advancement between individual operations in:

- bounded address rehydration;
- claim plus supporting-evidence closure;
- repeated current lookups;
- restart and catch-up.

A compound result must contain one exact cursor, consumer revision, batch ID, and configuration digest, or fail closed and require retry.

### Scale protocol

Generate at least the following history sizes when practical:

```text
10k
100k
1M
10M events
```

At each size measure cold and warm:

- one evidence lookup;
- one claim lookup;
- one historical lookup;
- one claim plus all supporting evidence;
- 10 and 100 address rehydration;
- canonical batch catch-up;
- startup verification;
- full audit;
- genesis rebuild;
- selected bucket distribution and worst bucket;
- proof bytes and SQL rows read.

The selected-read benchmark must instrument or wrap the canonical ledger and demonstrate that no lifetime `readRange` calls occur on the normal lookup path. Timing alone is insufficient evidence of bounded behavior.

### Run manifest

Store machine-readable manifests with:

- commit and tree SHA;
- Node and SQLite versions;
- dataset generator and seed;
- exact event count and object/version count;
- bucket bits and configuration digest;
- hardware and operating system;
- cold/warm cache state;
- repetitions and percentiles;
- raw results and failures;
- full audit/rebuild commands;
- canonical range-read counters.

Until this protocol is run beyond small synthetic fixtures, the allowed claim is limited to: "the selected-read implementation avoids lifetime ledger replay in the tested path and enforces the documented integrity contracts."
