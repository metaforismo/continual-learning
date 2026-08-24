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

- an append-only, replayable event ledger;
- strict JSON snapshots so post-write mutation cannot alter history;
- write-time claim admission checks and quarantine;
- bitemporal claim resolution using world time and transaction time;
- explicit supersession, revocation, authority, ambiguity, and provenance;
- sparse multi-signal memory activation;
- associative expansion with fan-out inhibition;
- a dependency-, evidence-, diversity-, and token-budget-aware context compiler;
- procedure promotion gates based on independent evidence, verified outcomes, counterexample search, applicability boundaries, failure rate, and Wilson confidence bounds.

The kernel intentionally has no embedding provider, database, LLM dependency, or DeepSeek Harness coupling yet. Those are replaceable adapters, not correctness primitives.

## Run locally

Requirements: Node.js 22+.

```bash
npm install
npm test
```

The test suite currently exercises 19 foundational invariants.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
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

Foundational kernel. APIs may change while the invariants and evaluation boundary are established.
