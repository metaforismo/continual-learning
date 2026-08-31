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
- post-outcome context features leaking treatment success into applicability discovery;
- discovery trials reappearing in held-out validation through copied ids, units, or source families;
- context-feature strings exposing sensitive project, user, or tenant state;
- generic or constraints-only evidence being laundered into step-level procedure support;
- caller-chosen digests masquerading as attested dependency, verifier, or rollback identities;
- a policy/tool artifact masquerading as human verification;
- mutating procedure candidates underdeclaring risk or claiming disable-only rollback;
- evidence-backed procedure candidates being mistaken for scheduling or execution authority;
- canary runtime identities being accepted without exact digest-matching verifier evidence;
- forked candidate or plan lineage being reviewed as current;
- restricted candidate or plan provenance remaining eligible after privacy changes;
- advisory canary review being mistaken for scheduling or execution authority;
- concurrent write anomalies and replay inconsistency;
- consumer bootstrap that silently skips canonical history;
- projection code advancing offsets without the corresponding derived-state mutation;
- configuration drift reusing an old projection checkpoint under new semantics;
- mixed-cursor compound reads during concurrent projection catch-up;
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

Model/plugin code may propose operations but must not hold the canonical kernel or the `TransitionVerifier` commit capability. A transition is staged on an isolated kernel, bound to an exact base fingerprint, checked under a trusted frozen policy, and committed only by the same runtime instance that issued the accepted result. The pure `verifyTransition` function is an evaluator, not a write authority.

External semantic/security checks must be constructed or authorized by the trusted host. Actor names, authority labels, SHA-256 digests, and report metadata are not signatures. Until authenticated actors and attestation exist, arbitrary check objects supplied by the proposing model are untrusted input.

Transition policies cap operation count, scope fan-out, evidence fan-in, checks, state assertions, and canonical proposal size. Hosts must additionally cap raw request bytes and parser depth before calling the library.

### Durable canonical publication

New SQLite canonical mutations require the exact cursor issued by the open ledger and the exact accepted result issued by its configured `TransitionVerifier`. Event bytes, event-chain advancement, audit, idempotency receipt, receipt-chain advancement, and cursor metadata are published under one `BEGIN IMMEDIATE` transaction. Exact retries after restart perform complete event/receipt/audit verification before returning the prior receipt.

The durable boundary rejects embedded NULs, ill-formed Unicode, non-canonical SQLite UTF-8 aliases, weakened uniqueness contracts, and triggers on canonical tables. File databases require WAL and `synchronous = FULL`. These controls detect accidental or partial corruption; unkeyed hashes do not authenticate a database operator capable of coherently rewriting the entire history. Deployments handling valuable or personal state still require protected storage, signed checkpoints, authenticated actors, backups, and incident recovery.

### Durable projection consumption

A new projection consumer must register a configuration digest, explicit initial canonical cursor, and an exclusive non-overlapping lowercase SQL-object prefix. Genesis is the safe default; starting at the current tail is an explicit history-skipping decision. Canonical batches are bounded and contiguous; `retry()` preserves the exact outstanding capability and range even when the durable tail advances.

Projection mutation, durable receipt, and consumer cursor are published under one `BEGIN IMMEDIATE` transaction. The callback is trusted host code, must remain synchronous, and receives a revocable transaction-scoped capability. It may address only its registered namespace; raw connection access, other consumer namespaces, joins/subqueries, transaction control, PRAGMAs, catalogs, quoted SQL text, and `cl_consumer_*` state are forbidden. Parameters are runtime-typed and size-bounded. Consumer metadata is stored in STRICT tables and checked at the raw SQLite byte boundary. These controls do not sandbox projection code or provide distributed exactly-once delivery.

The FTS5 feed consumer additionally requires its consumer cursor to equal the durable canonical tail before current search. Restricted/deleted evidence and dependent claim text are removed transactionally; restoration that needs discarded plaintext requires a canonical rebuild. The projection database still contains structural identifiers and provenance metadata and must therefore be protected as sensitive metadata even when search text has been scrubbed. Selected result buckets are recomputed before candidate emission, but unkeyed manifests do not authenticate an operator capable of coherently rewriting the entire projection database.

The canonical object-read consumer also requires genesis completeness and current-tail equality. It stores canonical evidence and claim metadata, immutable transaction-time versions, evidence references, and bounded previews for evidence whose canonical record permits them. Current restriction or deletion suppresses preview content even in historical reads. Exact lookups verify state, version, head, deterministic bucket, sparse path, roots, checkpoint, and configuration. Compound address reads and claim provenance closure must remain on one cursor/revision/batch/configuration or fail closed. These controls detect partial or incoherent corruption; the sparse roots are stored inside the derived projection and therefore are not an independent trust anchor against a database operator that coherently replaces the entire projection. Such deployments require protected storage and a future separately authenticated commitment.

### Applicability feature boundary

Context features are host-provided metadata, not canonical facts or harmless labels. They may encode repository names, infrastructure, customer state, user attributes, failure symptoms, or other sensitive information. Hosts must keep feature vocabularies inside the same scope and privacy boundary as the attributed experiment and must not place secrets, credentials, raw personal data, or unbounded source text inside feature strings.

The applicability boundary requires one feature-schema digest, timestamps the manifest before either trial arm starts, and rejects inconsistent feature manifests for the same experimental unit or context fingerprint. Discovery and held-out validation cannot reuse comparisons, units, or verifier source groups. These controls reduce post-outcome leakage and evidence duplication; they do not authenticate the feature extractor or stop a trusted host from fabricating a manifest.

Applicability observations, candidates, and validations are process-local capabilities in v1. A validated rule remains non-canonical learning evidence and explicitly carries no procedure-promotion or execution authority. Durable storage, signatures, schema migration, deletion propagation, and authenticated feature instrumentation remain future boundaries.

### Verified procedure-candidate boundary

A verified procedure candidate is still data, not an instruction capability. The boundary accepts
only an exact issued held-out applicability validation, preserves both discovery and validation
lineage, binds to the current canonical fingerprint, and requires every goal and ordered step to
carry positive canonical support. One generic citation cannot serve as the sole evidence anchor for
every step. Context-only, contradicting, constraints-only, cross-scope, unavailable, and secret
evidence cannot be laundered into positive procedure support.

Dependency versions, verifier identities, and restore checkpoints are accepted only when exact
`verifies` evidence has the same content hash as the declared digest and sufficient authority. A
human verifier specifically requires digest-matching `human-explicit` evidence; a system-policy
label does not become human review merely because it ranks highly. Contraindications retain
constraining or verifying evidence as first-class negative knowledge.

Mutating candidates cannot declare low risk and cannot claim that disabling future use reverses an
external change. High and destructive candidates require human verification and review-oriented
failure handling, but even a compliant candidate remains:

```text
status = candidate
executable = false
procedurePromotionAuthorized = false
canaryPlanAuthorized = false
executionAuthorized = false
```

Candidate issuance and ID/version conflict protection are process-local capabilities, not signatures
or durable authorization. The module semantically replays the supplied history and trusts the host
to provide the real canonical prefix and authentic evidence bytes. It does not schedule canaries,
execute instructions, attest tools or humans, or propagate deletion into a durable candidate store.
Those remain separate future boundaries.

### Bounded canary-plan boundary

A bounded canary plan is data, not a scheduling or execution capability. It accepts only an exact
issued procedure candidate, preserves its applicability, verification, rollback, risk, source
identities, and canonical prefix, and rechecks the current privacy state of inherited evidence.
The plan records its own canonical fingerprint and event count so a later review can prove that the
exact planning prefix remains an ancestor of the supplied history rather than accepting a fresh
fingerprint from an unrelated fork.

Population entries are caller-supplied opaque subject digests. The boundary rejects obvious raw
identity fields, duplicates, inapplicable subjects, and empty treatment/control arms, but it does
not prove unlinkability or prevent a trusted caller from encoding identifying data into a digest.
Deployments must construct population manifests inside their tenant and privacy boundary.

Scheduler, harness, observer, verifier, rollback-controller, and environment identities require
separate canonical evidence whose content hash exactly matches each declared digest and whose role
includes `verifies`. This is evidence binding, not remote attestation. The host remains responsible
for authenticating the actual runtime components.

Plans enforce coherent resource budgets, sandbox/network/tool policy, risk-dependent caps,
quality/cost/safety/security stop conditions, and rollback coverage. Destructive candidates are
rejected. Independent review cannot reuse the plan author or inherited source families, and all
candidate and plan evidence is checked again under the current privacy overlay. Even an approved
review remains:

```text
executable = false
hostSchedulingAuthorized = false
procedurePromotionAuthorized = false
executionAuthorized = false
```

This planning boundary does not issue admission, run, monitoring, rollback, or outcome receipts.
Those externally performed actions are admitted only by the separate guarded receipt boundary below;
complete cross-process trial accounting and authenticated monotonic metering remain future work.

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
- applicability-feature schema review and sensitive-feature filtering;
- procedure-candidate provenance, contraindication, risk, rollback, and exact-digest review;
- backup and disaster-recovery process;
- dependency and supply-chain review;
- incident response contacts.

## Reporting a vulnerability

Until a private reporting channel is published, avoid posting exploitable details in a public issue. Contact the repository owner privately through an available verified channel and include reproduction steps, affected commit, and impact.


## Canonical canary receipt boundary

Receipt APIs require exact process-issued plans/reviews and canonical evidence from the planned scheduler, harness-bound runner, observer, verifier, or rollback-controller source family. The binding that carries the exact external receipt or runner digest must itself belong to that source family; unrelated decoy evidence cannot supply identity continuity. An external action digest must also differ from the component identity digest it claims acted, so identity evidence cannot masquerade as an action receipt. A `human` outcome label additionally requires the exact external verification digest to carry `human-explicit` authority. Top-level receipt requests and nested runner identities reject undeclared runtime fields. Process-local registries enforce run IDs, contiguous non-overlapping subject attempts, no retry after success, concurrency, monotonic monitoring, representable complete stop-evaluation prefixes, and atomic retries; they track cumulative cost and tool calls and expose budget breaches without hiding the external action. Observation admission stops before the evaluator's count or canonical-ID bounds are exhausted. Exact retry remains bound to the original canonical snapshot rather than a later tail. Receipts may report that an external host acted or issued a grant; they do not create credentials, schedule work, invoke tools, roll back state, promote a procedure, or set any authority flag to true.
