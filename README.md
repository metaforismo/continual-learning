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
- procedure promotion gates based on independent evidence, verified outcomes, counterexample search, applicability boundaries, failure rate, and Wilson confidence bounds.

The kernel intentionally has no embedding provider, database, LLM dependency, or DeepSeek Harness coupling yet. Those are replaceable adapters, not correctness primitives.

## Run locally

Requirements: Node.js 22+.

```bash
npm install
npm test
```

The test suite currently exercises 97 foundational, state-adjudication, and transition-verification scenarios.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Evidence model](docs/EVIDENCE_MODEL.md)
- [State adjudication](docs/STATE_ADJUDICATION.md)
- [Transition verification](docs/TRANSITION_VERIFICATION.md)
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

Foundational kernel, deterministic state adjudicator, and in-memory transition verifier. APIs may change while durability, authenticated actors, concurrency, and evaluation boundaries are established.
