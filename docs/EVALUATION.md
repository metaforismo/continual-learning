# Evaluation and evidence ladder

The project will not use a single recall score as proof of continual learning.

## Stage-decomposed evaluation

Every end-to-end error should be localized to one of these boundaries:

```text
capture -> write/admission -> state projection -> retrieval/activation
        -> context compilation -> decision/use -> action -> outcome -> learning update
```

Report both final task accuracy and intermediate diagnostics.

## Evaluation suites

### A. Ledger and replay

- deterministic replay from the same event stream;
- immutable snapshots;
- duplicate/idempotency handling;
- crash-prefix recovery;
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
- fan-out and latency scaling.

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

- omission;
- corruption of unrelated state;
- unsupported additions;
- authority escalation;
- audit erasure;
- replay inconsistency;
- prompt-injection persistence;
- secret retention.

### F. Procedural learning

- same-error recurrence after correction;
- transfer to unseen cases;
- applicability precision and recall;
- contraindication recall;
- cross-context validation;
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
retention and backward transfer
next-task learning rate
p50/p95/p99 latency
write amplification
model-context tokens per request
storage/index growth
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

## Evidence ladder

### Level 0 — specification

Architecture, invariants, threat model, and tests over hand-built cases. No capability claim.

### Level 1 — deterministic kernel

Replay, bitemporal state, quarantine, activation, compilation, and procedure-promotion invariants pass locally and in CI.

Allowed claim: "the kernel enforces these tested contracts."

### Level 2 — controlled synthetic memory

Stress updates, contradictions, poisoning, multi-target recall, and growth over millions of generated events.

Allowed claim: "the system maintains specified memory properties under controlled workloads."

### Level 3 — established public benchmarks

Evaluate on LongMemEval, LoCoMo, MemoryAgentBench, MINTEval, STALE-like conflict suites, HaluMem-like transition tests, and agentic tasks.

Allowed claim: benchmark-specific results with complete configuration and cost.

### Level 4 — cross-domain procedural learning

Demonstrate lower repeat-error rates and transfer on coding, web, planning, and another non-text-only environment.

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
