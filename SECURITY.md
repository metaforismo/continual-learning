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
- denial of service through write storms, graph fan-out, or oversized evidence;
- incomplete deletion across projections, indexes, caches, exports, and learned parameters.

## Security principles

### Memory is data, not instruction

Retrieved text is untrusted data unless it is a validated procedure with explicit instruction authority. Prompt-looking content inside a source document must not gain control merely because it was remembered.

### Least write authority

Reading memory and proposing memory are separate capabilities. Admission, supersession, scope promotion, shared-memory writes, and deletion require progressively stronger authority.

### Evidence before action

High-risk learned procedures require recoverable evidence and current verification. Sensitive external actions retain harness approval and sandbox policies.

### Quarantine by default

Model inferences, extracted instructions, and untrusted-source claims do not become authorized state immediately.

### Provenance closure

Every derived object references its source evidence. Security review and deletion must be able to traverse that graph.

### Scope isolation

Every object and index entry belongs to an explicit tenant/user/project/session scope. Broader-scope promotion is a new authorized event, not an implicit side effect of retrieval frequency.

### Reversible learning

Procedures, controller versions, adapters, and context policies must support suppression and rollback.

## Required controls before handling real personal data

- secret and credential scanning;
- sensitive-attribute classification;
- encryption at rest and in transit;
- access-control and audit logs;
- tenant isolation tests;
- retention and deletion policy;
- export and provenance inspection;
- prompt-injection/taint evaluation;
- backup and disaster-recovery process;
- dependency and supply-chain review;
- incident response contacts.

## Reporting a vulnerability

Until a private reporting channel is published, avoid posting exploitable details in a public issue. Contact the repository owner privately through an available verified channel and include reproduction steps, affected commit, and impact.
