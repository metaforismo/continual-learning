# Durable consumer checkpoints

## Purpose

A verified feed alone cannot prevent:

```text
projection rows committed, offset missing  -> duplicate replay
projection offset committed, rows missing  -> silent skip
```

`SqliteConsumerCheckpointStore` executes the trusted projection mutation, durable receipt, and
consumer checkpoint on the same SQLite connection and transaction.

## Durable registration

A consumer must be registered before its first batch with:

```text
consumer id
configuration digest
explicit initial canonical cursor
registration time and digest
```

The configuration digest binds projection schema/code version, privacy policy, and interpretation
semantics. Reusing the same consumer id with a different configuration or initial cursor fails.

The initial cursor is the completeness declaration:

- genesis means replay all canonical history;
- a verified tail cursor intentionally skips prior history;
- an arbitrary first batch cannot silently define its own starting point.

Registration is idempotent when configuration and initial cursor are unchanged.

## Authority path

Application enters through:

```text
store.apply(feed, batch, { consumerId, configurationDigest }, callback)
                         │
                         └── feed.consume checks the exact outstanding capability
```

A structural clone cannot invoke the projection callback or advance the checkpoint.

## Atomic transaction

For a new batch:

```text
BEGIN IMMEDIATE
    attest connection and consumer schema
    verify registration and exact batch
    compare batch.base with registration/checkpoint cursor
    issue restricted single-statement projection transaction
    run trusted synchronous projection mutation
    re-attest PRAGMAs, schema, and outer transaction
    append receipt
    publish checkpoint
COMMIT
feed advances in memory
```

Any failure rolls back projection changes, receipt, and checkpoint. The feed retains the same pending
batch.

The callback may create/update projection-owned tables through `run`, and read them through `get`
or `all`. It has no raw `DatabaseSync`. SQL is restricted to one statement and cannot access
`cl_consumer_*`, SQLite catalogs, transaction control, PRAGMAs, attachments, or extension/file helper
functions. Promise/thenable results are rejected.

## Crash and retry

If the process exits before `COMMIT`, SQLite preserves the registration but rolls back projection
rows, receipt, and checkpoint.

If the store commits and the process exits before the feed's in-memory advancement, restart from the
registered/previous cursor and poll the same canonical range. Stable batch identity lets the store
find the existing receipt and advance without rerunning projection code.

```text
same consumer + configuration + canonical range
    -> idempotent receipt replay

same batch id + different durable content/configuration
    -> reject
```

This is not distributed exactly-once processing. It is atomic and idempotent under one SQLite write
authority.

## Receipt and checkpoint

Each receipt binds:

```text
consumer and configuration
initial-cursor digest
revision
batch id and append digest
base/after cursors and digests
previous receipt digest
application time
receipt digest
```

Each checkpoint binds the receipt-chain head and current cursor. Revisions are contiguous and guarded
against safe-integer overflow.

## SQLite integrity boundary

The store requires:

```text
trusted_schema = OFF
foreign_keys = ON
synchronous = FULL
WAL for file-backed databases
STRICT consumer tables
exact table definitions
no unexpected triggers, views, or user indexes
```

Identity/integrity text is validated at the raw SQLite byte boundary with `hex(...)`. Embedded
`U+0000`, ill-formed Unicode, malformed UTF-8 aliases, wrong storage classes, non-canonical cursor
JSON, and digest tampering fail closed.

## Fast read and audit

`checkpoint(consumerId)` verifies registration, cursor, latest receipt, configuration, and the active
receipt/checkpoint relationship.

`audit(consumerId)` traverses the full per-consumer receipt chain and checks:

- durable registration;
- contiguous revisions;
- predecessor receipt digests;
- base cursor equals prior after cursor;
- monotonic application time;
- stable configuration and initial-cursor binding;
- final receipt equals checkpoint head;
- connection and schema invariants.

Projection-owned table semantics remain the adapter's responsibility.

## Security boundary

The callback is trusted host code behind a restricted single-statement SQL surface, not a model-generated SQL surface. This module does not provide
actor authentication, sandboxing, digital signatures, distributed leases, consensus, or protection
against an operator able to rewrite the full database and recompute all unkeyed digests.

## Non-claims

This layer does not prove distributed exactly-once delivery, infinite context, continual learning,
complete retrieval, or production-scale fan-out. It establishes:

> Under one SQLite authority, a registered consumer's projection mutation, durable receipt, and
> canonical cursor advance together or do not advance at all.
