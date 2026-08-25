# Durable canonical ledger

## Purpose

The in-memory kernel can determine whether an event stream is semantically valid, and the transition verifier can determine whether a proposed append is authorized. Neither property alone guarantees that a process crash cannot expose half of a learned transition.

The durable ledger adds this boundary:

```text
accepted process-local transition capability
                    ↓
          BEGIN IMMEDIATE
                    ↓
     exact canonical-base comparison
                    ↓
           canonical event append
                    +
        transition audit receipt
                    +
          revision metadata update
                    ↓
             COMMIT or ROLLBACK
```

Events, receipt, and revision become visible together or not at all.

## Source-of-truth boundary

SQLite stores the canonical append-only event history. Retrieval indexes, materialized projections, summaries, and model-facing context remain derived caches.

The storage layer does not decide that a proposed transition is trustworthy. Its caller must supply the trusted process-local commit capability issued by the transition-verification runtime. The store then verifies that the capability output:

- preserves the exact existing event prefix;
- equals the result's staged append;
- matches the append and after-state fingerprints;
- remains semantically replayable through `MemoryKernel`;
- still targets the exact canonical base held under the SQLite write lock.

An arbitrary in-process caller is still inside the trusted-host boundary. This package is not an operating-system sandbox or an authentication system.

## Schema

### `cl_ledger_meta`

One singleton row records:

```text
schema version
revision
canonical event count
last sequence
last transaction time
canonical full-history fingerprint
event-chain head
transition-receipt count
receipt-chain head
```

`revision` advances once per accepted transition. `event_count` advances once per canonical event.

### `cl_ledger_events`

Each canonical event stores:

```text
sequence and stable event id
schema version, type, transaction time, actor
canonical JSON payload
payload digest
previous event-chain digest
event-chain digest
```

The row columns must agree with the canonical JSON payload. Startup replay checks contiguous sequence, transaction-time monotonicity, payload digest, chain links, semantic replay, full-history fingerprint, and metadata.

### `cl_transition_receipts`

Each committed transition stores:

```text
transition audit record
result digest
canonical audit-record digest
previous receipt digest
receipt-chain digest
```

The receipt preserves the proposal, policy, verifier, risk, verdict, canonical before/after fingerprints, append fingerprint, and finding codes without duplicating the complete historical ledger.

## Atomic commit

`commitVerifiedTransition` acquires a SQLite write reservation with `BEGIN IMMEDIATE` before it reads the revision used for compare-and-swap.

The transaction performs:

1. metadata and integrity validation;
2. idempotency lookup by verification-result digest;
3. exact base-fingerprint comparison;
4. consumption of the trusted transition capability;
5. canonical-prefix and staged-append comparison;
6. event-row insertion and event-chain advancement;
7. receipt insertion and receipt-chain advancement;
8. metadata compare-and-swap;
9. commit.

A fault before commit rolls back all three durable surfaces.

## Idempotent recovery

A caller may lose the response after SQLite committed successfully. Replaying the same verification result finds the existing receipt by `resultDigest`.

When the current canonical fingerprint still equals the result's `afterFingerprint`, the store returns the prior receipt without consuming the transition capability or appending a second copy.

A reused result digest that points at a different canonical state is treated as corruption or conflict, not as a successful retry.

## Concurrency

V1 uses whole-ledger optimistic concurrency:

```text
verify against fingerprint F
            ↓
another writer commits F → G
            ↓
attempt commit against F
            ↓
reject as stale
```

SQLite serializes the write transaction, and the metadata update includes revision and canonical-fingerprint predicates. Two proposals prepared from one prefix cannot both commit.

Per-belief serializable partitions remain a later optimization. Whole-ledger compare-and-swap is deliberately conservative.

## Failure injection

The implementation exposes deterministic test hooks at:

- after `BEGIN IMMEDIATE`;
- after event insertion;
- after receipt insertion;
- after metadata update;
- immediately before commit.

Every injected failure must leave zero partial event, receipt, or revision visibility after reopening the database.

## Hash-chain meaning

The event and receipt chains detect accidental or unsynchronized mutation when metadata is not rewritten consistently. They are integrity addresses, not signatures.

An operator capable of rewriting all rows, metadata, and hashes can manufacture another internally consistent database. Authentication requires keyed MACs or digital signatures, protected keys, and an authenticated actor registry.

## Recovery model

SQLite crash recovery handles incomplete transactions. On open, the library additionally performs:

```text
row-shape validation
canonical JSON validation
payload-digest verification
hash-chain verification
semantic MemoryKernel replay
full-history fingerprint verification
receipt-chain verification
metadata agreement
```

The database fails closed when any check fails. V1 performs full verification and replay; checkpointed verification is future work.

## Current limitations

The durable ledger does not yet provide:

- authenticated actors, ACLs, signatures, or remote attestation;
- encrypted artifact-byte storage or digest verification against provider bytes;
- migration from an existing non-empty in-memory ledger;
- per-belief write partitions;
- incremental semantic checkpoints;
- replication, backup verification, or disaster recovery;
- provenance-closure deletion;
- a guarantee against an operator who can rewrite the entire database coherently;
- model, retrieval, or continual-learning benchmark evidence.

The implemented claim is narrower: accepted canonical appends and their transition receipts can be committed atomically, replayed after reopening, rejected on stale base, and checked for internal integrity under the documented trusted-host boundary.
