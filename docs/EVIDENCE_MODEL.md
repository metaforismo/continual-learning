# Evidence model

## Why evidence is a separate plane

A memory system becomes dangerous when a generated sentence such as:

```text
The user prefers X.
```

is stored without preserving where it came from, whether the source is still available, whether it was model-generated, whether it contained prompt injection, or whether five apparent confirmations were merely five copies of the same document.

The foundational kernel therefore separates:

```text
raw artifact bytes                 provider-owned, content-addressed
canonical evidence metadata        append-only event ledger
claims / associations / outcomes   derived objects that cite evidence
indexes / summaries / packets      rebuildable projections
```

A claim is not evidence. A summary is not evidence. A model judgment is not evidence unless the judgment output itself is captured as a source with the correct authority and taint.

## Canonical evidence record

An `EvidenceRecord` contains:

- stable evidence id;
- explicit scope;
- evidence kind;
- one or more independent-origin `sourceGroups`;
- authority;
- world observation time;
- sensitivity classification;
- taints;
- content-addressed artifact reference;
- optional bounded display preview;
- derivation parents;
- labels.

The artifact reference contains a provider URI, SHA-256 digest, byte size, media type, encryption mode, and retention class. The event ledger does **not** store arbitrary raw artifact bytes.

## Source groups and independence

`sourceGroups` represent independent origins, not filenames, chunks, citations, retries, or summaries.

Examples:

```text
one user message split into ten spans       one source group
one test run with many log files             one source group
three independently executed test runs       three source groups
one summary over those three runs             inherits all three groups
```

Derived evidence must carry the exact sorted union of its parents' source groups. It cannot invent a new group and thereby masquerade as fresh confirmation.

The same artifact digest cannot be captured under a second evidence identity. Reuse the existing evidence object or create a genuinely distinct derived artifact with explicit lineage.

## Provenance DAG

Derived evidence may cite only evidence that already exists in the transaction-time prefix. This creates a directed acyclic provenance graph:

```text
raw document
    -> source span
        -> extracted claim candidate

trajectory + test result
    -> verified outcome
        -> procedure evidence
```

The current schema prevents:

- self-derivation;
- references to future or unknown evidence;
- duplicate parent ids;
- implicit cross-scope promotion;
- source-group laundering;
- authority escalation;
- sensitivity downgrade;
- taint removal.

A future explicit declassification/sanitization protocol may relax some inheritance rules, but it must be a separately authorized, audited transition. Ordinary summarization is not declassification.

## Taint is sticky

Taints currently include:

- `untrusted-source`;
- `external-content`;
- `model-generated`;
- `prompt-like`;
- `secret-detected`.

Derived evidence inherits every parent taint. This prevents a model from summarizing malicious or secret-bearing content into an apparently clean instruction.

Taint does not by itself determine relevance. It constrains how evidence may be used. In particular, remembered text remains data; it does not gain instruction authority merely because it was retrieved.

## Sensitivity and raw-byte separation

Sensitivity levels are ordered:

```text
public < internal < personal < sensitive < secret
```

Derived evidence cannot reduce the strongest inherited sensitivity. Sensitive and secret evidence:

- cannot store raw preview text in the canonical event log;
- requires provider-managed encryption;
- remains represented by metadata and digest only.

This separation is necessary because an immutable audit log and a legal deletion requirement conflict if private bytes are embedded directly into every historical event.

## Availability

Evidence has transaction-time availability state:

```text
available <-> restricted -> deleted
```

- `available`: may authorize derived state;
- `restricted`: retained but cannot authorize new admissions or current answers;
- `deleted`: terminal tombstone in the kernel.

A claim whose evidence becomes unavailable automatically stops resolving as authorized current state. A historical `knownAt` query can still reconstruct what the system was allowed to know before the restriction or deletion event.

The kernel's `deleted` state is not proof that provider bytes, backups, vector indexes, caches, exports, or trained parameters were erased. Provenance-closure deletion across those systems remains a later evidence gate.

## Exact references

A derived object references evidence through:

```text
sourceId
sourceGroups
source authority
content digest
```

All fields must exactly match the captured record, and the evidence must currently be available. This blocks forged hashes, forged authority, fabricated independence, and dangling ids.

Claims, associations, and verified outcomes are scoped derived objects. They cannot cite narrower-scope evidence while silently promoting it into a broader scope. Global evidence may be reused in a narrower scope without copying its bytes.

## Outcomes are evidence-backed

An outcome such as `success` is not accepted as a bare self-report. It records:

- scope;
- subject/task/context identity;
- outcome and verifier type;
- exact inherited source groups;
- evidence references.

The claimed verifier must be supported by evidence with sufficient authority. For example, a `human` verdict cannot be backed only by a tool result, and a `test` verdict requires tool-verified evidence or stronger.

This closes an important self-improvement loophole:

```text
agent says it succeeded
    -> stores success
        -> promotes its own procedure
```

The remaining credit-assignment problem—whether a particular memory or procedure *caused* success—is not solved by this contract and requires controlled ablations or local verifiers.

## Replay contract

Every event carries a schema version, contiguous sequence number, monotonic transaction time, actor, and immutable JSON snapshot.

`MemoryKernel.from(events)` performs two layers of replay validation:

1. structural ledger checks;
2. semantic replay through the same public write operations used online.

Therefore a stream that is syntactically valid but cites evidence before capture, crosses scopes, repeats an entity id, or performs an illegal lifecycle transition fails closed.

## Current limitations

The implemented plane is metadata and correctness infrastructure. It does not yet provide:

- an artifact/blob provider;
- digest verification against fetched bytes;
- SQLite durability;
- access-control identities and actor authorization;
- explicit declassification or scope-promotion events;
- provenance-closure deletion across indexes and backups;
- a taint-aware context rendering policy;
- multi-tenant encryption key management;
- signed evidence or remote attestation;
- causal credit assignment.

These are explicit next layers, not properties implied by the current in-memory kernel.
