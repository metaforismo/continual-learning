# Security policy

This repository is an early research project and has not yet received a production security audit.

## Threat model

A persistent learning system has a larger blast radius than an ordinary chat session. A single bad write can influence many future actions.

The project treats the following as first-class threats:

- hallucinated or corrupted memory writes;
- prompt injection stored from web pages, documents, tool output, or other agents;
- authority escalation from untrusted evidence to actionable instruction;
- stale state driving high-impact actions;
- cross-user, cross-tenant, or cross-project memory leakage;
- secret and sensitive-data retention;
- duplicated evidence inflating confidence;
- malicious or compromised subagents poisoning shared memory;
- reward hacking and self-confirming learning loops;
- concurrent write anomalies and replay inconsistency;
- consumer bootstrap that silently skips canonical history;
- projection code advancing offsets without the corresponding derived-state mutation;
- configuration drift reusing an old projection checkpoint under new semantics;
- denial of service through write storms, graph fan-out, or oversized evidence;
- incomplete deletion across projections, indexes, caches, exports, and learned parameters.

## Security principles

### Memory is data, not instruction

Retrieved text is untrusted data unless it is a validated procedure with explicit instruction authority. Prompt-looking content inside a source document must not gain control merely because it was remembered.

### Least write authority

Reading memory and proposing memory are separate capabilities. Admission, supersession, scope promotion, shared-memory writes, and deletion require progressively stronger authority.

### Evidence before action

High-risk learned procedures require recoverable evidence and current verification. Claims, associations, and outcomes must cite captured, available evidence with exact digest, authority, source-group, and scope metadata. Sensitive external actions retain harness approval and sandbox policies.

### Raw bytes outside the immutable log

The canonical event ledger stores content addresses, provenance, taints, sensitivity, and availability transitions—not arbitrary sensitive artifact bytes. Sensitive and secret artifacts require provider-managed encryption and cannot carry inline previews. This reduces, but does not by itself complete, deletion obligations across providers, backups, caches, indexes, exports, or learned parameters.

### No provenance laundering

Derived evidence inherits the union of source groups, all taints, the strongest sensitivity, and an authority ceiling from its parents. Summarization cannot silently turn one source into multiple confirmations, external prompt-like text into a trusted instruction, or secret material into ordinary memory.

### Quarantine by default

Model inferences, extracted instructions, and untrusted-source claims do not become authorized state immediately.

### Provenance closure

Every derived object references its source evidence. Security review and deletion must be able to traverse that graph.

### Scope isolation

Every object and index entry belongs to an explicit tenant/user/project/session scope. Broader-scope promotion is a new authorized event, not an implicit side effect of retrieval frequency.


### Verified write capability

Model/plugin code may propose operations but must not hold the canonical kernel or the
`TransitionVerifier` commit capability. A transition is staged on an isolated kernel, bound to an
exact base fingerprint, checked under a trusted frozen policy, and committed only by the same runtime
instance that issued the accepted result. The pure `verifyTransition` function is an evaluator, not a
write authority.

External semantic/security checks must be constructed or authorized by the trusted host. Actor names,
authority labels, SHA-256 digests, and report metadata are not signatures. Until authenticated actors
and attestation exist, arbitrary check objects supplied by the proposing model are untrusted input.

Transition policies cap operation count, scope fan-out, evidence fan-in, checks, state assertions, and
canonical proposal size. Hosts must additionally cap raw request bytes and parser depth before calling
the library.

### Durable canonical publication

New SQLite canonical mutations require the exact cursor issued by the open ledger and the exact accepted result issued by its configured `TransitionVerifier`. Event bytes, event-chain advancement, audit, idempotency receipt, receipt-chain advancement, and cursor metadata are published under one `BEGIN IMMEDIATE` transaction. Exact retries after restart perform complete event/receipt/audit verification before returning the prior receipt.

The durable boundary rejects embedded NULs, ill-formed Unicode, non-canonical SQLite UTF-8 aliases, weakened uniqueness contracts, and triggers on canonical tables. File databases require WAL and `synchronous = FULL`. These controls detect accidental or partial corruption; unkeyed hashes do not authenticate a database operator capable of coherently rewriting the entire history. Deployments handling valuable or personal state still require protected storage, signed checkpoints, authenticated actors, backups, and incident recovery.

### Durable projection consumption

A new projection consumer must register a configuration digest, explicit initial canonical cursor, and
an exclusive non-overlapping lowercase SQL-object prefix. Genesis is the safe default; starting at the
current tail is an explicit history-skipping decision. Canonical batches are bounded and contiguous;
`retry()` preserves the exact outstanding capability and range even when the durable tail advances.

Projection mutation, durable receipt, and consumer cursor are published under one `BEGIN IMMEDIATE`
transaction. The callback is trusted host code, must remain synchronous, and receives a revocable
transaction-scoped capability. It may address only its registered namespace; raw connection access,
other consumer namespaces, joins/subqueries, transaction control, PRAGMAs, catalogs, quoted SQL text,
and `cl_consumer_*` state are forbidden. Parameters are runtime-typed and size-bounded. Consumer
metadata is stored in STRICT tables and checked at the raw SQLite byte boundary. These controls do not
sandbox projection code or provide distributed exactly-once delivery.

The FTS5 feed consumer additionally requires its consumer cursor to equal the durable canonical tail
before current search. Restricted/deleted evidence and dependent claim text are removed transactionally;
restoration that needs discarded plaintext requires a canonical rebuild. The projection database still
contains structural identifiers and provenance metadata and must therefore be protected as sensitive
metadata even when search text has been scrubbed. Selected result buckets are recomputed before
candidate emission, but unkeyed manifests do not authenticate an operator capable of coherently
rewriting the entire projection database.

### Reversible learning

Procedures, controller versions, adapters, and context policies must support suppression and rollback.

## Required controls before handling real personal data

- secret and credential scanning;
- sensitive-attribute classification;
- encryption at rest and in transit;
- access-control, authenticated actor identities, and audit logs;
- tenant isolation tests;
- retention and deletion policy;
- export and provenance inspection;
- prompt-injection/taint and transition-verifier red-team evaluation;
- backup and disaster-recovery process;
- dependency and supply-chain review;
- incident response contacts.

## Reporting a vulnerability

Until a private reporting channel is published, avoid posting exploitable details in a public issue. Contact the repository owner privately through an available verified channel and include reproduction steps, affected commit, and impact.
