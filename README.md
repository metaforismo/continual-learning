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
- an FTS5 canonical change-feed consumer that incrementally maintains lexical documents and reverse dependencies, scrubs restricted evidence and dependent claims, refuses stale canonical tails, and falls back to explicit rebuild when discarded plaintext would be required;
- an authenticated, rebuildable canonical object-read projection with exact evidence/claim lookup, bitemporal versions, current privacy overlays, provenance closure, sparse integrity proofs, current-tail gating, and checkpoint-consistent compound reads without lifetime replay;
- deterministic experience attribution that separates activated, materialized, consulted, and applied memories; binds traces to canonical outcomes and evidence; requires exact target-withheld paired interventions for causal credit; preserves complete source-family lineage across duplicate experimental units; and retains mixed, negative, neutral, and insufficient evidence without granting procedure or execution authority;
- contextual applicability hypotheses that bind schema-versioned features before paired trials begin, reuse attribution's exact unit/source-family collapse, prevent one unit or context fingerprint from being rewritten with a different feature manifest, induce bounded required/forbidden feature rules, and require disjoint held-out validation before reporting contextual generalization;
- provenance-complete verified procedure candidates that preserve discovery and held-out lineage, require ordered typed steps with step-exclusive supportive evidence, bind dependency/verifier/checkpoint digests to authoritative canonical evidence, retain evidence-backed contraindications, enforce risk and rollback contracts, and remain explicitly non-executable;
- bounded non-executable canary plans that preserve exact procedure/applicability lineage, bind deterministic treatment/control assignment and coherent budgets to evidence-backed runtime identities, require safety/security stopping and rollback coverage, support independent advisory review, and never grant host scheduling or execution authority;
- a rebuildable SQLite FTS5 projection that emits addresses only, binds generations to canonical fingerprints and privacy configuration, detects row/manifest corruption, and requires canonical rehydration;
- a checkpointed FTS5 diff publisher with exact-prefix verification, changed-row repair, privacy-filtered reverse dependencies, hash-chained checkpoints, fixed bucket manifests, and cache-independent rehydration;
- procedure promotion gates based on independent evidence, verified outcomes, counterexample search, applicability boundaries, failure rate, and Wilson confidence bounds.

The correctness kernel remains model- and harness-agnostic. The durable SQLite ledger is canonical storage; SQLite FTS5 and the canonical object-read index remain rebuildable derived projections. Experience-attribution and applicability objects are process-local learning evidence in v1, not canonical mutations, procedures, or execution capabilities. No embedding provider, LLM dependency, or DeepSeek Harness coupling defines canonical memory semantics.

## Run locally

Requirements: Node.js 22.16.0+ (`node:sqlite` is currently experimental in Node 22).

```bash
npm install
npm test
```

The test suite currently exercises 312 foundational, state, transition, durable-ledger, change-feed, consumer-transaction, lexical-projection, selected-object-read, experience-attribution, contextual-applicability, verified-procedure-candidate, and bounded-canary-plan scenarios.

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
- [FTS5 canonical change-feed consumer](docs/FTS5_FEED_CONSUMER.md)
- [Canonical object read index](docs/CANONICAL_OBJECT_READ_INDEX.md)
- [Verified experience attribution](docs/EXPERIENCE_ATTRIBUTION.md)
- [Contextual applicability hypotheses](docs/APPLICABILITY_HYPOTHESES.md)
- [Verified procedure candidates](docs/VERIFIED_PROCEDURE_CANDIDATES.md)
- [Bounded non-executable canary plans](docs/BOUNDED_CANARY_PLANS.md)
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
- benchmark superiority over existing systems;
- causal utility from ordinary successful co-occurrence;
- universal applicability from discovery-set fit;
- automatic procedure promotion, canary scheduling, or tool-execution authority.

Those claims must be earned independently through the evidence ladder.

## Status

Foundational kernel, deterministic state adjudicator, capability-gated transition verifier, crash-safe canonical SQLite ledger, verified durable projection delivery, incremental FTS5 candidate discovery, selected canonical object rehydration, conservative paired experience attribution, held-out contextual applicability hypotheses, provenance-complete non-executable procedure candidates, and bounded non-executable canary plans with advisory review. APIs may change while durable authenticated learning records, canonical canary trials and receipts, procedure lifecycle, artifact storage, and longitudinal benchmarks are established.
