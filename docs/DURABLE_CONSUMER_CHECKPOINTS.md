# Durable consumer checkpoints

## Purpose

A verified change feed is not sufficient by itself. A projection can still fail in either of these ways:

```text
projection rows committed, offset not committed
    -> duplicate replay after restart

offset committed, projection rows not committed
    -> canonical events silently skipped
```

`SqliteConsumerCheckpointStore` places the trusted projection mutation, batch receipt, and consumer cursor in one SQLite transaction.

## Authority path

A public structural batch is not enough to enter the store. Application is invoked through:

```text
store.apply(feed, batch, consumerId, trustedCallback)
             │
             └── feed.consume verifies the exact outstanding process-local batch capability
```

A cloned batch with identical fields is rejected before the callback runs.

The projection callback is trusted host/adaptor code. It receives the same `DatabaseSync` connection so it can update consumer-owned tables in the checkpoint transaction. It is not an SQL execution surface for model-generated or otherwise untrusted input.

## Transaction

For a new batch:

```text
BEGIN IMMEDIATE
    validate exact batch structure, cursors, event chain, append digest, and batch id
    compare durable consumer checkpoint with batch.base
    run trusted synchronous projection callback
    append consumer receipt
    publish batch.after as consumer checkpoint
COMMIT
feed advances in memory
```

If the callback or any injected phase fails, SQLite rolls back projection rows, receipt, and checkpoint. The feed retains the same pending batch.

## Crash between store commit and feed acknowledgement

The store transaction can commit immediately before the process crashes, leaving no opportunity to update the feed's in-memory checkpoint.

After restart:

1. open the feed from the older persisted consumer-side cursor;
2. poll the same deterministic canonical batch;
3. call `store.apply` again;
4. the existing receipt is verified;
5. the callback is not rerun;
6. `feed.consume` advances to `batch.after`.

Thus:

```text
same consumer + same batch id + same base/after/append
    -> durable idempotent replay

same batch id + different content
    -> reject
```

This is not a claim of distributed exactly-once delivery. It is atomic/idempotent application under one SQLite authority.

## Consumer checkpoint

Each consumer has an independent checkpoint:

```text
consumer id
revision
canonical read cursor + cursor digest
last batch id
last append digest
latest receipt digest
updatedAt
```

A consumer may begin from any verified feed base, including the current durable tail. The first receipt records that base explicitly.

## Receipt chain

Consumer receipts bind:

```text
consumer id and revision
batch id
base cursor and digest
after cursor and digest
append digest
previous consumer receipt digest
application time
receipt digest
```

Receipts form a per-consumer hash chain. Different consumers do not share revision counters or receipt heads.

The complete batch events are intentionally not duplicated in the consumer store. Therefore the store proves receipt/cursor consistency and relies on the change feed for canonical batch authority. It cannot independently reconstruct the batch id from storage after canonical events are unavailable.

## Synchronous callback boundary

Projection callbacks must be synchronous. Returning a Promise fails and rolls back.

This prevents the transaction from committing its offset before asynchronous work actually completes.

Long-running or networked processing should happen before the transaction and produce a bounded deterministic mutation input. The final SQLite callback should perform only the local publication.

## Fast checkpoint read and full audit

`checkpoint(consumerId)` verifies:

- canonical cursor JSON and digest;
- latest receipt digest;
- batch id and append digest;
- receipt-to-checkpoint after cursor.

`audit(consumerId)` traverses the complete per-consumer receipt chain and checks:

- contiguous revisions;
- predecessor receipt digests;
- base cursor equals prior after cursor;
- monotonic application time;
- final receipt head equals the active checkpoint.

The store does not audit arbitrary projection-owned tables because their schema and semantics belong to the trusted adapter. The callback should maintain its own projection manifest or verification contract.

## Concurrency

`BEGIN IMMEDIATE` serializes consumer publication. The current checkpoint is read only after the write lock is acquired.

Two processes cannot both advance one consumer from the same base. Different consumer ids can maintain independent logical histories, although SQLite still serializes writes at the database level.

## Failure and recovery

A partially present consumer schema fails closed. Durable consumer offsets are not a disposable cache and are never silently reset.

Fault injection covers:

```text
after begin
after projection callback
after receipt
after checkpoint
before commit
```

Every failure must leave both projection state and consumer checkpoint at the prior revision.

## Security boundary

The current module does not provide:

- authentication or ACLs for consumer ids;
- sandboxing of the trusted callback;
- protection from trusted callback code deliberately modifying checkpoint tables;
- digital signatures or keyed receipts;
- distributed leases, consensus, or remote offsets;
- automatic verification of projection-specific derived rows;
- protection against a database operator able to rewrite all rows and recompute unkeyed digests.

## Non-claims

This layer does not prove:

- distributed exactly-once processing;
- infinite context;
- continual learning;
- complete retrieval;
- production-scale fan-out.

It establishes a narrower invariant:

> Under one SQLite transaction authority, a verified canonical batch's trusted projection mutation, receipt, and consumer checkpoint advance together or do not advance at all.
