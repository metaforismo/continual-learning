# Architecture

## Objective

Build a portable cognitive-memory subsystem that can sit above interchangeable foundation models and below an agent harness.

The system should allow a model with a bounded physical context window to operate over an indefinitely growing history without treating every stored token as prompt text.

```text
history size -> grows
activated state -> sparse and query-dependent
materialized working context -> bounded
```

This is context virtualization, not literal full-attention over an infinite sequence.

## Core principles

### One canonical history, many projections

The append-only experience ledger is authoritative. Every derived object points back to ledger evidence.

Do not maintain five independently editable copies of the same observation in an episode store, knowledge graph, profile, skill file, and summary. That creates update divergence. Instead:

```text
canonical events
    -> episode projection
    -> claim/state projection
    -> association projection
    -> procedure projection
    -> retrieval indexes
```

Indexes and summaries may be rebuilt. Evidence is never destructively rewritten: raw bytes live in a content-addressed provider, while capture metadata and restriction/deletion tombstones remain auditable.

### Evidence before memory

Raw artifacts, observations, messages, tool results, tests, and trajectories enter a separate evidence plane before they may authorize learned state.

```text
artifact bytes -> content address -> evidence metadata -> derived memory object
```

The event log stores digest, provenance, independent source groups, taints, sensitivity, scope, and availability—not arbitrary sensitive bytes. Derived evidence inherits origin groups, taints, authority ceilings, and sensitivity from its parents. This prevents summaries from manufacturing independent confirmation or laundering untrusted/private content.

See [Evidence model](EVIDENCE_MODEL.md).

### Claims, not unqualified facts

Every state claim carries:

- scope;
- subject and predicate;
- value;
- world-valid interval;
- transaction time in the ledger;
- authority and epistemic status;
- confidence;
- source groups and evidence references;
- supersession, dispute, or revocation state.

The system must be able to answer both:

```text
What is true now?
What did the agent know, at time T, about what was true at time V?
```

This requires bitemporal state rather than a flat latest-value cache.

### Retrieval is not authorization

A retrieved memory may be:

- relevant but stale;
- relevant but quarantined;
- relevant but contradicted;
- historically valid but wrong for the current-state view;
- malicious content from an untrusted source;
- a low-confidence inference;
- a procedure whose preconditions are absent.

Activation produces candidates. A state/policy layer decides what may govern action.

### Activation is not context

Let:

```text
M = all addressable memory
A_t = memory activated for the current state
W_t = memory materialized into the model's working context
```

with:

```text
W_t subset A_t subset M
```

`A_t` may contain hundreds or thousands of lightweight ids, scores, and state markers. `W_t` contains only the small evidence packets that fit the context budget. The agent can expand an activated item on demand.

### Consolidation is hypothesis formation

An abstraction is not automatically true because an LLM summarized several episodes.

```text
episodes
  -> candidate regularity
  -> counterexample search
  -> applicability hypothesis
  -> verified trials
  -> validated procedure
  -> trusted skill
```

The source episodes remain intact. Promotion and deprecation are new events; they do not overwrite history.

## Proposed subsystem map

```text
                         agent harness
                              |
                    bounded model request
                              |
                       context compiler
                              |
             +----------------+----------------+
             |                |                |
       state resolver   activation router  procedure router
             |                |                |
             +----------------+----------------+
                              |
                         active memory
                              |
  =================================================================
                              |
                    canonical event ledger
                              |
       +----------------------+----------------------+
       |                      |                      |
 content-addressed       bitemporal claims      associations/outcomes
 evidence metadata
       |                      |                      |
       +---------------+------+----------------------+
                       |
                 procedure hypotheses
                       |
               transition verification
                       |
              learned memory controller
  =================================================================
                       |
                storage and indexes
       hot cache / lexical / vector / graph / archive
```

## Write path

### 1. Capture evidence

Store the original event, tool result, document span, human correction, test result, or environment transition in a provider-owned content-addressed artifact store. Append immutable metadata to the ledger: digest, origin groups, authority, scope, observation time, sensitivity, taints, lineage, and availability.

Raw evidence has exactly one independent source group. Derived evidence inherits the exact union of its parents' groups and cannot reduce inherited taint or sensitivity.

### 2. Extract candidates

A model or deterministic parser may propose claims, associations, outcomes, or procedure evidence.

### 3. Quarantine

Model-generated state is not automatically authoritative. Candidates enter quarantine unless a declared policy permits immediate admission.

### 4. Verify the transition

Check:

- coverage — important source information was not omitted;
- preservation — unrelated valid state was not destroyed;
- faithfulness — additions are supported by cited evidence;
- authority — a derived claim cannot become stronger than its evidence;
- temporal consistency — valid intervals and supersession are coherent;
- independence — duplicate citations do not become multiple votes;
- scope — writes cannot escape their authorized tenant/user/project boundary;
- replay consistency — the decision and judge configuration are logged.

### 5. Commit an event

Accepted operations append a new event. There is no destructive in-place edit of canonical history.

## Read path

### 1. Infer the requested view

Current, historical, hypothetical, audit, or source-verification queries require different policies.

### 2. Route by scope and memory substrate

Search the smallest useful partitions first:

```text
session -> project -> user -> global
```

The router may combine lexical, vector, temporal, entity, causal, and procedural indexes.

### 3. Build a sparse activation frontier

Direct cues activate candidate nodes. Activation may spread over learned associations, with:

- hop decay;
- fan-out normalization;
- scope filters;
- competition and inhibition;
- duplicate/source-family collapse;
- authority and utility signals;
- explicit negative and contraindication edges.

### 4. Adjudicate state

Resolve current versus stale claims before prompt assembly. When no justified winner exists, preserve ambiguity or mark current state unknown instead of inventing certainty.

### 5. Compile the working context

The compiler chooses evidence packets under a hard budget. It must be:

- dependency-aware;
- diversity-seeking;
- risk-aware;
- provenance-preserving;
- model-template-aware;
- able to include multiple procedures and memories together;
- able to leave most activated objects outside the prompt.

### 6. Iterative callback

Retrieval is not a single pre-generation top-k operation. During reasoning, the model or controller may ask to:

```text
expand(memory_id)
neighbors(memory_id)
evidence(memory_id)
history(claim_key)
search(counterexample_query)
```

The new evidence re-enters the same authorization and budget pipeline.

## Learning path

### Outcome capture

An outcome is itself a scoped derived object and must cite captured evidence. A bare agent self-report is not a verified success.

For each use of a memory or procedure, record:

- task and context fingerprint;
- selected memory ids;
- action;
- verifier result and exact evidence references;
- success, failure, partial, or unknown outcome;
- alternative candidates considered;
- latency and token cost.

### Credit assignment

Do not reward every retrieved memory after a successful task. That creates self-reinforcing noise.

Use interventions where possible:

- run with and without the memory;
- compare alternative retrieval sets;
- replay on held-out cases;
- attribute local test/verifier outcomes;
- discount memories that were retrieved but unused;
- separate correlation from causal contribution.

### Procedure learning

A procedure is a typed object, not only a Markdown instruction:

```text
goal signature
preconditions
forbidden conditions
steps or policy reference
supporting episodes
counterexamples
success/failure statistics by context
version and status
activation policy
```

A procedure can coexist with another procedure for a different context. The system should learn a mixture or router rather than forcing a universal rewrite.

### Controller learning

Initially, deterministic rules and transparent scoring control memory operations. Later, a small policy may learn actions such as:

```text
STORE / QUARANTINE / LINK / RETRIEVE / EXPAND
SUPPRESS / SUPERSEDE / CONSOLIDATE / ABSTAIN
```

Controller updates require offline replay, held-out evaluation, canary deployment, and rollback. The controller must never train only on its own unverified memories.

### Optional parametric consolidation

Stable procedures may eventually generate training data for a LoRA, adapter, fast-weight module, or base-model update. This is the slowest layer and must preserve:

- dataset provenance;
- exact model and optimizer state;
- before/after capability evals;
- deletion and privacy semantics;
- reversible routing back to the previous adapter.

## Human-memory inspiration

The design borrows computational principles, not biological claims.

- fast, pattern-separated episodic storage resembles a hippocampal role;
- slow integration across interleaved episodes resembles cortical consolidation;
- cue-driven associative completion motivates sparse recall;
- prefrontal-like selection and inhibition motivates competition after activation;
- replay motivates offline validation across diverse episodes;
- reconsolidation motivates versioned updates after retrieval;
- active forgetting motivates lowering accessibility without erasing evidence.

The Complementary Learning Systems literature is useful because rapid one-shot storage and slow generalization are conflicting optimization goals. They should not be collapsed into one mandatory rewrite loop.

## Scalability plan

### Storage tiers

```text
hot: current task state, validated procedures, recent active claims
warm: indexed episodes, project history, summaries, graph neighborhoods
cold: raw transcripts, documents, artifacts, full trajectories
```

### Bounded request cost

A target read pipeline is:

```text
partition routing
  -> approximate / lexical candidate lookup
  -> 1k-scale candidate set
  -> sparse associative expansion
  -> 100-scale activated state
  -> 10-50 materialized packets
```

No request should scan the entire history or rebuild a global graph.

### Bounded write cost

Raw capture is append-only and cheap. Expensive extraction, association learning, and consolidation should be incremental and partitioned. Background work must be idempotent, checkpointed, and safe to retry.

### Index independence

Indexes are caches over canonical events. They may lag, fail, or be replaced without changing truth. Every retrieval result includes index/version metadata so regressions are diagnosable.

## Invariants implemented now

The current kernel enforces a first subset:

1. event ids are unique, schema-versioned, and sequence/transaction time are monotonic;
2. persisted values are immutable single-read JSON snapshots; dangerous keys remain data rather than mutating prototypes;
3. structural replay is followed by semantic replay through the same public write contract;
4. artifact evidence is content-addressed and the same bytes cannot manufacture a second evidence identity;
5. evidence provenance is a transaction-ordered DAG;
6. derived evidence inherits the exact union of source groups, all taints, an authority ceiling, and the strongest sensitivity of its parents;
7. raw sensitive/secret previews cannot enter the canonical log and their artifacts require provider-managed encryption;
8. claims, associations, and outcomes cite captured, available, exact evidence references;
9. derived objects and procedure evidence cannot cross scopes implicitly; global evidence may narrow into a scoped use;
10. non-policy claims cite evidence and derived claim lineage must already exist;
11. unverified model inference cannot bypass quarantine;
12. evidence restriction blocks later admission and current resolution; deletion is terminal in the kernel;
13. current and historical truth use explicit validity intervals and transaction-time reconstruction;
14. supersession preserves the old claim;
15. unresolved conflicts stay ambiguous unless a declared authority policy applies;
16. activation and model-context materialization are separate;
17. scope authorization is a hard retrieval boundary and out-of-scope associations are not traversed;
18. generic high-fan associations are inhibited;
19. high-risk procedures require evidence packets;
20. packet dependency cycles are contained rather than crashing context assembly;
21. repeated copies of one trajectory or counterexample run do not count as independent learning;
22. unverified successes cannot manufacture procedure confidence;
23. procedure promotion requires cross-context evidence and counterexample search;
24. dependency closures cannot bypass context packet caps.
