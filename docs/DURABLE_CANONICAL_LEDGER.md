# Durable canonical SQLite ledger

## Purpose

The in-memory kernel and transition verifier establish semantic and admission contracts. A long-running agent additionally needs a canonical byte store that survives restart and cannot expose a partially published learning transition.

`SqliteCanonicalLedger` persists one accepted append through a single SQLite transaction:

```text
exact canonical event bytes
+ event hash chain
+ transition metadata
+ transition audit record
+ idempotency receipt
+ receipt hash chain
+ canonical cursor metadata
```

Either all of those become visible, or none do.

This is the canonical storage boundary. Unlike FTS5 and future retrieval indexes, it is not a disposable cache.

## Write authority

A new mutation requires two independent process-local capabilities:

1. a cursor issued by the open ledger instance;
2. the exact accepted `TransitionVerificationResult` issued by the configured `TransitionVerifier` instance.

Matching JSON fields are insufficient. A structured clone of either object cannot authorize a new write.

The ledger binds `TransitionVerifier.prototype.commit` at construction, replays the complete durable prefix, asks that exact verifier capability to commit the result, and checks that the returned kernel preserves the prefix and appends exactly the verified events.

```text
model/plugin proposal
        ↓
trusted TransitionVerifier
        ↓ exact accepted result capability
SqliteCanonicalLedger
        ↓ atomic publication
canonical bytes
```

Actor names and verifier metadata remain descriptive strings rather than authenticated identities. Authentication and delegated authorization are later host-level gates.

## Canonical event bytes

Every event is stored as deterministic canonical JSON together with:

```text
sequence
stable event id
schema version
event type
transaction time
actor
event digest
previous chain digest
resulting chain digest
publishing revision
```

For event `i`:

```text
e_i = H(domain, canonical_event_i)
c_i = H(domain, c_(i-1), sequence_i, e_i)
```

Startup, new commits, receipt reads, exact retries, kernel loads, and full audit recompute the relevant bytes and semantic replay through `MemoryKernel.from`.

Sensitive artifact bytes are still not introduced by this layer. Canonical evidence events retain provider-owned content addresses, provenance, taint, sensitivity, and availability metadata rather than arbitrary secret blobs.

## Atomic commit

The write transaction is:

```text
BEGIN IMMEDIATE
    validate exact STRICT schema and connection policy
    resolve exact idempotent retry, if any
    compare process-issued cursor with the locked canonical cursor
    replay and hash the complete stored prefix
    verify the complete receipt/audit history
    commit the exact verifier-issued transition result
    validate the contiguous canonical append
    insert event bytes and advance the event hash chain
    insert transition audit
    insert durable receipt and advance the receipt hash chain
    compare-and-swap canonical cursor metadata
COMMIT
```

Injected failures after every publication boundary roll the complete transaction back. The suite also terminates a separate Node process after cursor mutation but before `COMMIT`; reopening the database observes the old cursor and no event, audit, or receipt from the interrupted publication.

## Cursor capability and restart semantics

A cursor contains:

```text
schema version
revision
event count
last sequence
last transaction time
canonical semantic fingerprint
event-chain head
latest receipt-chain head
```

For a new mutation, the object must be a capability issued by that exact open ledger instance. A plain object or structured clone with matching fields is rejected.

Audit output deliberately returns a descriptive cursor, not a write capability.

An exact idempotent retry is different. The store looks up the durable idempotency key and compares the digest of the complete original request. It then performs a full event, receipt, and audit verification before returning the existing receipt. This permits crash recovery after restart without granting authority for another mutation.

```text
same key + same complete request -> verify history and return existing receipt
same key + different request     -> reject
same result + different key      -> reject
new mutation + copied cursor     -> reject
```

An exact retry after later commits returns the existing receipt together with the current canonical cursor and no repeated append.

## Receipts and audits

A receipt binds:

```text
revision
idempotency key and request digest
exact transition result digest and metadata
audit id and audit digest
base and resulting event-chain heads
append sequence interval and append digest
previous receipt digest
committer label and commit time
```

Receipts form a second hash chain independent from the event chain.

The audit row is canonicalized and bound to the same proposal, result, policy, verifier configuration, risk, fingerprints, finding codes, and receipt digest. Every receipt/audit pair is checked against its exact event range.

The original full request is intentionally not copied into the database. `requestDigest` therefore supports exact retry comparison when the caller resupplies the original request, but storage alone cannot reconstruct that request. This remains an explicit v1 limitation.

## SQLite byte and schema boundary

Node's SQLite text decoder is not treated as an integrity oracle.

The ledger:

- rejects embedded `U+0000` and ill-formed Unicode before publication;
- reads `hex(column)` and verifies exact canonical UTF-8 bytes for event, receipt, audit, and metadata text;
- rejects malformed UTF-8 aliases rather than accepting their replacement-character decoding;
- uses `STRICT` tables;
- validates exact column order, type, nullability, primary keys, and required uniqueness contracts;
- rejects database triggers on canonical tables;
- requires `trusted_schema = OFF`, `foreign_keys = ON`, `synchronous = FULL`, and the configured busy timeout;
- requires persistent WAL mode for file-backed databases.

The runtime validation is still authoritative for semantic constraints. V1 does not claim that every SQL `CHECK` expression is itself schema-attested.

## Fast status, startup recovery, and full audit

`status()` is a bounded operational check. It verifies:

- canonical metadata shape and exact bytes;
- the predecessor anchor of the latest append;
- every event in that bounded append, not only its final row;
- the latest receipt and receipt-chain relation;
- the latest audit and transition binding;
- agreement between the latest receipt and canonical cursor.

`status()` does not scan old history.

Every constructor performs `status()` followed by a full recovery audit. A database with a healthy-looking tail but corrupted historical bytes fails to open.

`audit()` remains deliberately `O(N)` and verifies:

- SQLite's integrity check;
- every canonical event byte and semantic replay;
- the complete event hash chain;
- every receipt byte, digest, predecessor, and append range;
- every audit byte and transition binding;
- event-to-revision attribution;
- final event, receipt, fingerprint, and cursor heads.

A failed audit does not mint a cursor capability.

## Range reads

`readRange(fromSeq, limit)` is bounded and checks:

- exact canonical JSON and raw SQLite bytes;
- row metadata and event digest;
- the immediately preceding chain and transaction-time anchor;
- contiguous sequence and revision boundaries;
- every chain edge inside the returned range;
- expected row count, so a missing row cannot become a silent short read.

This proves local range integrity relative to the stored predecessor. It is not a substitute for an external signed checkpoint or a complete prefix audit.

## Concurrency

SQLite `BEGIN IMMEDIATE` serializes publication. Cursor comparison occurs only after the write lock is held.

```text
writer A and B read revision r
writer A acquires the lock and commits r + 1
writer B later acquires the lock, sees a stale cursor, and fails
```

V1 uses a whole-ledger cursor. Serializable per-belief partitions and distributed writer coordination remain later work.

## Configuration drift

`maxAppendEvents` governs new admissions only. Tightening it after restart does not invalidate older, already-authorized append receipts, provided they remain within the durable schema's hard bound.

Other resource limits may still reject a newly submitted or retried request before publication; hosts should treat operational limit changes as versioned deployment policy.

## Complexity boundary

V1 intentionally prioritizes correctness and recovery evidence over throughput:

```text
new commit prefix replay and rehash: O(N)
new commit receipt/audit verification: O(N)
startup recovery audit:               O(N)
exact idempotent retry verification:  O(N)
receipt read verification:            O(N)
full audit:                            O(N)
range read:                            O(k)
fast status:                           O(latest append)
```

The latest append has a protocol hard bound, so fast status remains bounded. An incremental canonical cursor/change-feed layer is required before normal publication can become `O(k)` in lifetime history.

## Security boundary

This module does not yet provide:

- authenticated actors, verifier identities, or ACL enforcement;
- digital signatures, keyed manifests, remote attestation, or external transparency checkpoints;
- OS-level protection from a process that can rewrite the SQLite file;
- distributed consensus or replication;
- legal deletion across backups, indexes, exports, and learned parameters;
- an artifact provider that verifies referenced source bytes.

An operator able to rewrite every row and recompute every unkeyed digest can forge a coherent alternate history. Signed checkpoints and protected storage are later gates.

## Recovery

A partially present, column-incompatible, uniqueness-weakened, trigger-modified, byte-corrupt, or semantically invalid canonical schema fails closed. The database is never silently reset.

Operational recovery must preserve the original file, diagnose the failure, and restore from a verified backup or external checkpoint. Retrieval caches may be rebuilt; this canonical ledger may not.

## Non-claims

This layer does not prove:

- infinite context;
- continual learning;
- correct causal credit assignment;
- production scalability;
- multi-agent trust;
- authenticated learning.

It establishes a narrower invariant:

> Exact verifier-authorized event bytes, their audit, their receipt, and the resulting canonical cursor become durable as one crash-safe publication.
