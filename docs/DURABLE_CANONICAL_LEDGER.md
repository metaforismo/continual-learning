# Durable canonical SQLite ledger

## Purpose

The in-memory kernel and transition verifier establish semantic and admission contracts, but a long-running agent also needs a crash-safe canonical byte store.

`SqliteCanonicalLedger` persists one accepted append through a single SQLite transaction:

```text
canonical event rows
+ event hash-chain
+ transition audit record
+ idempotency receipt
+ receipt hash-chain
+ canonical cursor metadata
```

Either all of those become visible, or none do.

This module is a storage boundary. It does not independently prove that a caller really is the named actor or that a supplied result digest came from an authentic verifier. The trusted host must connect it to the transition verifier, actor authentication, and authorization policy.

## Canonical event bytes

Every event is stored as deterministic canonical JSON together with:

```text
sequence
event id
recordedAt
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

Startup and full audit recompute the bytes, event digests, chain, metadata, and semantic replay through `MemoryKernel.from`.

Sensitive artifact bytes are still not introduced by this layer. The evidence contract continues to store provider-owned content addresses rather than arbitrary secret blobs in canonical events.

## Atomic commit

A new durable commit requires:

- an exact process-local cursor capability for a new mutation;
- contiguous, monotonic, schema-valid events;
- semantic replay against the complete stored prefix;
- accepted transition metadata;
- a transition audit describing the same proposal, result, policy, verifier, risk, and verdict;
- a unique bounded idempotency key.

The write transaction performs:

```text
BEGIN IMMEDIATE
    verify current cursor / compare-and-swap
    replay and hash the complete prefix
    insert canonical event rows
    insert transition audit
    insert durable receipt
    update canonical cursor metadata
COMMIT
```

Injected failures after any write phase roll the whole transaction back.

## Cursor capability and restart semantics

A cursor contains:

```text
revision
event count
last sequence
last transaction time
event-chain digest
latest receipt digest
```

For a **new** mutation, matching fields are insufficient. The object must be a process-local capability issued by that open ledger instance. This prevents copied JSON from being treated as write authority.

An exact idempotent retry is different. The durable store first looks up the idempotency key and compares the digest of the complete original request. An exact retry may therefore recover its receipt after process restart without regaining authority to submit a different mutation.

```text
same key + same complete request -> return existing receipt
same key + different request     -> reject
new key + copied cursor          -> reject
```

## Receipts and audit records

A receipt binds:

```text
revision
idempotency key and request digest
transition metadata
audit id and audit digest
base and resulting event-chain heads
append sequence interval and append digest
previous receipt digest
committer and commit time
```

Receipts form a second hash chain independent from the event chain.

The audit row is canonicalized and its digest is recomputed whenever the corresponding receipt is read, used for idempotent recovery, checked by fast status, or traversed by full audit.

The original complete request is intentionally not duplicated in the database. Consequently, `requestDigest` is an integrity address for exact idempotency lookup, but cannot be independently reconstructed from storage after the caller discards the original request. This is an explicit v1 limitation.

## Fast status versus full audit

`status()` performs a bounded tail check:

- canonical metadata shape;
- latest event row agrees with the cursor;
- latest receipt agrees with revision and chain head;
- latest audit bytes and digest agree with the receipt.

It does not scan old event rows.

`audit()` is deliberately `O(N)` and verifies:

- every canonical event byte and semantic event stream;
- the complete event hash chain;
- every receipt digest and predecessor;
- every audit byte and transition binding;
- every receipt append range against its event rows;
- event-to-revision attribution;
- append digests;
- final receipt and event-chain heads.

A green fast status is not evidence that historical rows were never modified. Full audit is the forensic boundary.

## Range reads

`readRange(fromSeq, limit)` is bounded and verifies each returned row against:

- canonical JSON;
- row metadata;
- event digest;
- the immediately preceding chain anchor;
- every chain edge inside the returned range.

This proves local range integrity relative to the stored predecessor anchor. It does not replace a complete prefix audit against an external trusted checkpoint.

## Concurrency

SQLite `BEGIN IMMEDIATE` serializes publication. Cursor comparison occurs only after the write lock is held.

Two writers that both read revision `r` cannot both publish revision `r + 1`:

```text
writer A acquires lock and commits
writer B acquires lock and observes stale cursor
writer B fails
```

V1 uses a whole-ledger cursor rather than serializable per-belief partitions.

## Complexity boundary

V1 intentionally favors correctness over throughput:

```text
new commit prefix replay and rehash: O(N)
startup semantic recovery:          O(N)
full audit:                          O(N)
range read:                          O(k)
fast tail status:                    O(1)
exact idempotent receipt lookup:     indexed lookup + bounded verification
```

A later canonical cursor/checkpoint layer may reduce normal append cost to `O(k)` while preserving this durable transaction contract. This implementation does not claim bounded lifetime cost.

## Security boundary

The module currently does not provide:

- authenticated actors or ACL enforcement;
- digital signatures, remote attestation, or keyed database manifests;
- proof that transition metadata was emitted by the claimed verifier;
- OS-level isolation from a process that can modify the SQLite file;
- automatic legal deletion across backups, caches, indexes, and trained parameters;
- distributed consensus or replication.

A database operator able to rewrite every row and recompute every unkeyed digest can forge a coherent history. External signed checkpoints are a later gate.

## Recovery

A partially present durable schema fails closed. Unlike a disposable retrieval cache, the canonical ledger is not silently reset.

Operational recovery must preserve the original database, diagnose the incomplete migration or corruption, and restore from a verified checkpoint or backup.

## Non-claims

This layer does not prove:

- infinite context;
- continual learning;
- correct semantic credit assignment;
- production scalability;
- multi-agent trust;
- authenticated learning.

It establishes a narrower invariant:

> Accepted event bytes, their audit evidence, their receipt, and the resulting canonical cursor become durable as one atomic publication.
