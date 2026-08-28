# Canonical change feed

## Purpose

The durable canonical ledger is the source of truth. A projection should not replay the complete
lifetime history after every new append, and it must never infer canonical truth from its own cache.

`CanonicalChangeFeed` provides a verified pull-based stream over `SqliteCanonicalLedger`:

```text
startup / persisted-checkpoint verification: O(N)
normal bounded poll:                         O(k)
acknowledgement:                             O(1)
```

where `k <= maxBatchEvents`. This optimizes downstream delivery; it does not change the semantic
or durability cost of canonical writes.

## Explicit bootstrap

A feed without a persisted checkpoint starts at **genesis** by default. This is the safe completeness
boundary for a new projection.

Skipping existing history must be explicit:

```ts
CanonicalChangeFeed.open(ledger, { startAt: 'tail' })
```

`checkpoint` and `startAt` are mutually exclusive. A persisted checkpoint is replay-verified against
the exact canonical prefix before use.

## Read cursor

A persistable cursor contains:

```text
schema version
event count
last sequence
last recordedAt
event-chain digest
```

It carries no write authority. Resume verification replays bounded canonical ranges from genesis to
the supplied event count and compares count, sequence, transaction time, and chain digest. Recovery
therefore remains intentionally `O(N)`.

## Bounded polling

`poll()` emits at most `maxBatchEvents` contiguous canonical events. A large backlog is delivered as
several batches:

```text
checkpoint 0, durable tail 700, budget 256
    -> batch 1..256
    -> batch 257..512
    -> batch 513..700
```

A batch contains:

```text
base cursor
after cursor
append interval and digest
canonical frozen events
durable tail observed at issue time
stable batch id
```

The batch id is bound to the canonical range, not to a later durable tail. Reissuing the same range
after the ledger has advanced therefore produces the same id, which makes durable idempotent retry
possible.

A lexical or projection consumer must not interpret a feed batch as authorization to answer a model.
It remains canonical delivery data that downstream state and privacy policies must process.

## Pending capability and reentrancy

Only one batch may be outstanding per feed instance. Repeated `poll()` calls return the same frozen
object until it is acknowledged or retried.

`ack`, `retry`, and `consume` accept only the exact process-local object issued by that feed. A
structured clone with identical fields is not authority.

During `consume`, reentrant calls to `poll`, `ack`, `retry`, or another `consume` fail. This prevents a
projection callback from advancing or clearing the feed while its durable transaction is incomplete.
Async callbacks are rejected.

## Concurrent canonical appends

The ledger may advance after a batch is issued. The issued range remains valid:

```text
consumer at 10
poll 11..12 (tail observed = 12)
ledger advances to 15
ack 11..12
next poll 13..15
```

The informational `durableTailAtIssue` changes, but the identity of 11..12 does not.

## Startup verification modes

### `full-audit` — default

Runs the durable ledger audit before opening. This is the correctness boundary for persisted
checkpoints.

### `tail-only`

Uses the ledger's bounded status surface. It is an explicit operational trade-off and does not prove
historical rows intact.

## Failure handling

The feed fails closed on:

- malformed or non-genesis empty cursors;
- checkpoints ahead of storage;
- same-length cursor conflicts;
- failed prefix replay;
- sequence gaps or transaction-time regression;
- incomplete bounded range reads;
- forged/copy batch acknowledgement;
- reentrant consumer mutation;
- ledger regression behind the checkpoint.

## Complexity boundary

```text
full-audit open:                   O(N)
resume historical checkpoint:     O(N)
poll one bounded batch:           O(k), k <= configured maximum
status / ack / retry:              O(1) relative to history size
```

This v1 does not provide authenticated external checkpoints, distributed leases, remote replication,
or bounded startup recovery.

## Non-claims

This module does not prove infinite context, continual learning, complete retrieval, or production
fan-out. It establishes a narrower invariant:

> After a verified startup boundary, every canonical event after a checkpoint can be delivered in
> stable, bounded, contiguous batches without silent history skipping.
