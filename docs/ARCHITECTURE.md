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

Indexes and summaries may be rebuilt. Evidence cannot.

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
  bitemporal claims      associations           outcomes
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

Store the original event, tool result, document span, human correction, test result, or environment transition.

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

For each use of a memory or procedure, record:

- task and context fingerprint;
- selected memory ids;
- action;
- verifier result;
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

1. event ids are unique and sequence numbers monotonic;
2. persisted values are immutable JSON snapshots;
3. non-policy claims cite evidence;
4. derived authority cannot exceed source authority;
5. unverified model inference cannot bypass quarantine;
6. current and historical truth use explicit validity intervals;
7. supersession preserves the old claim;
8. unresolved conflicts stay ambiguous unless a declared authority policy applies;
9. activation and materialization are separate;
10. generic high-fan associations are inhibited;
11. high-risk procedures require evidence packets;
12. repeated copies of one trajectory do not count as independent learning;
13. procedure promotion requires cross-context evidence and counterexample search.
