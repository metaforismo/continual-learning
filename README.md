# Continual Learning

A research-first, model-agnostic continual-learning layer for long-running AI agents.

> Persistent memory is not automatically continual learning.

The project asks a stricter question:

> Can an agent accumulate evidence and experience for months or years, retrieve the right parts under a bounded context budget, revise stale state, learn reusable procedures from verified outcomes, and measurably improve without silently corrupting prior knowledge?

## Why this repository exists

Most agent memory systems are variations of:

```text
conversation -> extraction or summary -> searchable store -> top-k prompt injection
```

That is useful, but it leaves several hard problems unsolved:

- old and new state coexist without reliable adjudication;
- repeated summaries drift away from their source evidence;
- semantically similar memories crowd one another out;
- a hallucinated write becomes a persistent false premise;
- a lesson learned from one case is overgeneralized into a universal rule;
- repeated copies of one trajectory masquerade as independent evidence;
- retrieval success is confused with correct downstream use;
- a growing memory bank eventually overwhelms a flat `MEMORY.md`, a vector index, or the model context;
- "remembering" is reported as "learning" without held-out improvement or retention tests.

This repository starts from correctness contracts rather than a chatbot UI.

## Design thesis

```text
Store experiences exactly.
Learn abstractions slowly.
Retrieve associatively.
Act from adjudicated state.
Keep every learned behavior reversible and testable.
```

The system separates:

```text
canonical experience ledger        immutable evidence
            |
            +--> bitemporal state   what is true now / was true then
            +--> associations       what tends to activate together
            +--> procedures         what may work under explicit conditions
            +--> indexes            how candidates are found efficiently
                                      |
                                      v
                              activated memory
                                      |
                              state adjudicator
                                      |
                              context compiler
                                      |
                              bounded LLM context
                                      |
                              action + verifier
                                      |
                              outcome / learning signal
```

There is **one canonical history and many projections**. Episodes, claims, associations, summaries, and procedures must cite the evidence from which they were derived; they are not independent copies of truth.

## Current implementation

The foundational TypeScript kernel currently includes:

- an append-only, schema-versioned event ledger with structural and semantic replay;
- strict single-read JSON snapshots resistant to mutation and prototype-pollution input;
- a content-addressed evidence metadata plane with provenance DAGs, source independence, sensitivity, taint, and availability state;
- role-aware evidence use: `supports`, `verifies`, `context`, `contradicts`, and `constrains`;
- evidence-backed claims, associations, and verifier-role outcomes with hard scope boundaries;
- write-time claim admission checks and quarantine;
- bitemporal claim projection using world time and transaction time;
- deterministic, domain-specific state policies rather than one global authority ranking;
- explicit `current`, `historical`, `disputed`, `unknown-current`, and `unknown` state;
- premise resistance for requests that presuppose stale state;
- bounded implicit invalidation over a validated dependency DAG;
- transition-aware invalidation that distinguishes a value change from a same-value reaffirmation;
- sparse multi-signal memory activation;
- associative expansion with fan-out inhibition;
- a dependency-, evidence-role-, diversity-, and token-budget-aware context compiler;
- a capability-gated transition verifier with isolated replay, base-fingerprint CAS, exact deltas, input coverage, state assertions, taint/risk gates, and append-only verdict audit;
- a durable SQLite canonical ledger that atomically publishes exact verifier-issued event bytes, event and receipt hash chains, transition audit, idempotency receipt, and a compare-and-swap cursor;
- a verified canonical change feed with safe genesis bootstrap, explicit tail skipping, stable range identities, bounded contiguous batches, and process-local acknowledgement capability;
- a registered durable consumer store that binds configuration, initial completeness, and an exclusive SQL-object prefix, then commits a revocable projection mutation, receipt, and cursor in one hardened SQLite transaction;
- a rebuildable SQLite FTS5 projection that emits addresses only, binds generations to canonical fingerprints and privacy configuration, detects row/manifest corruption, and requires canonical rehydration;
- a checkpointed FTS5 diff publisher with exact-prefix verification, changed-row repair, privacy-filtered reverse dependencies, hash-chained checkpoints, fixed bucket manifests, and cache-independent rehydration;
- procedure promotion gates based on independent evidence, verified outcomes, counterexample search, applicability boundaries, failure rate, and Wilson confidence bounds.

The correctness kernel remains model- and harness-agnostic. The durable SQLite ledger is canonical storage; SQLite FTS5 remains an optional disposable retrieval adapter. No embedding provider, LLM dependency, or DeepSeek Harness coupling defines canonical memory semantics.

## Run locally

Requirements: Node.js 22.16.0+ (`node:sqlite` is currently experimental in Node 22).

```bash
npm install
npm test
```

The test suite currently exercises 219 foundational, state, transition, durable-ledger, change-feed, consumer-transaction, and lexical-projection scenarios.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Evidence model](docs/EVIDENCE_MODEL.md)
- [State adjudication](docs/STATE_ADJUDICATION.md)
- [Transition verification](docs/TRANSITION_VERIFICATION.md)
- [FTS5 lexical projection](docs/FTS5_PROJECTION.md)
- [Checkpointed FTS5 diff publication](docs/INCREMENTAL_FTS5.md)
- [Durable canonical SQLite ledger](docs/DURABLE_CANONICAL_LEDGER.md)
- [Canonical change feed](docs/CANONICAL_CHANGE_FEED.md)
- [Durable consumer checkpoints](docs/DURABLE_CONSUMER_CHECKPOINTS.md)
- [Learning contract](docs/LEARNING_CONTRACT.md)
- [Failure modes and mitigations](docs/FAILURE_MODES.md)
- [Evaluation and evidence ladder](docs/EVALUATION.md)
- [Roadmap](docs/ROADMAP.md)
- [Research basis](docs/RESEARCH_NOTES.md)
- [DeepSeek Harness integration plan](docs/DEEPSEEK_HARNESS.md)
- [Security policy](SECURITY.md)

## What this project does not claim

The repository does **not** currently claim:

- infinite context;
- solved continual learning;
- human-equivalent memory;
- resistance to all memory poisoning;
- improvement from online weight updates;
- production scalability;
- benchmark superiority over existing systems.

Those claims must be earned independently through the evidence ladder.

## Status

Foundational kernel, deterministic state adjudicator, capability-gated transition verifier, crash-safe canonical SQLite ledger, and disposable FTS5 candidate projections with checkpointed changed-row publication. APIs may change while O(k) canonical cursors, authenticated actors, artifact storage, and evaluation boundaries are established.
