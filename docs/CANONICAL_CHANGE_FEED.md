# Canonical change feed

## Purpose

The durable canonical ledger provides atomic storage and complete forensic verification, but a projection or agent runtime should not have to replay the complete lifetime history after every new event.

`CanonicalChangeFeed` provides a verified pull-based append stream over `SqliteCanonicalLedger`:

```text
startup / persisted-checkpoint verification: O(N)
normal complete-delta poll:                  O(k)
acknowledgement:                             O(1)
```

where `k` is the number of events committed since the consumer checkpoint.

This layer does **not** make canonical writes or semantic transition verification `O(k)`. It optimizes verified downstream consumption only.

## Read cursor

A persistable read cursor contains:

```text
schema version
event count
last sequence
last recordedAt
event-chain digest
```

It carries no write authority.

When a cursor is supplied after restart, the default startup path:

1. performs the durable ledger's full audit;
2. replays canonical ranges from genesis to the supplied event count;
3. recomputes the event chain;
4. compares count, sequence, transaction time, and chain digest.

The recovery cost is intentionally `O(N)`. A future externally authenticated checkpoint may reduce it.

Omitting a cursor starts the feed at the currently verified durable tail, which is appropriate for a new live consumer that does not need historical backfill.

## Poll, consumer commit, acknowledgement

The feed uses an explicit two-phase consumer protocol:

```text
poll verified batch
      ↓
consumer atomically updates its own projection/checkpoint
      ↓
ack exact process-local batch capability
```

`poll()` does not advance the in-memory consumer checkpoint. Repeated calls while one batch is outstanding return the same object.

`ack()` accepts only the exact frozen batch object issued by that feed instance. A structured clone with identical fields is not authority to advance.

A consumer may call `retry(batch)` to clear the pending capability without advancing. The next poll verifies and issues the delta again.

## Complete-delta rule

A batch always spans the complete difference between the consumer checkpoint and the durable tail observed by that poll.

If the lag exceeds `maxBatchEvents`, the feed fails rather than truncating silently:

```text
lag <= budget  -> read and verify entire delta
lag > budget   -> explicit catch-up/reopen workflow required
```

Because the complete delta is present, the recomputed final chain must equal the durable cursor's chain head.

This v1 design keeps the proof simple. A later chunked catch-up protocol will require authenticated intermediate anchors.

## Concurrent durable appends

The durable ledger may advance after a batch is issued but before it is acknowledged.

Acknowledging the already verified batch remains legal. The following poll then retrieves the next complete delta:

```text
consumer at 10
poll 11..12
ledger advances to 15
ack 11..12
next poll 13..15
```

No event is skipped.

## Startup verification modes

### `full-audit` — default

Traverses canonical events, receipts, audits, event-to-revision attribution, and both hash chains before opening.

This is the correctness boundary for persisted consumer checkpoints.

### `tail-only`

Uses the durable ledger's bounded tail status. It verifies current cursor, latest event, latest receipt, and latest audit, but does not prove that older rows are intact.

This mode is an explicit operational trade-off. It must not be presented as equivalent to full recovery verification.

## Batch contents

A batch contains:

```text
process-local batch id/capability
base read cursor
after read cursor
append sequence interval
append digest
canonical event bytes
```

The event array is a canonical deep-frozen snapshot. A caller cannot mutate it after verification and then acknowledge a different payload.

## Fork and regression handling

The feed fails closed when:

- durable event count regresses below the consumer checkpoint;
- an equal-length durable tail has a different chain digest;
- a persisted checkpoint is ahead of storage;
- a persisted checkpoint fails genesis-to-prefix verification;
- range sequence or transaction time is invalid;
- the complete delta does not reach the durable chain head;
- a forged or out-of-order batch is acknowledged.

## Complexity boundary

```text
open at current tail with full audit: O(N)
resume persisted historical cursor:   O(N)
poll delta within budget:             O(k)
status:                               O(1)
ack/retry:                            O(1)
```

`poll()` currently supports at most 1,000 events per complete delta because the underlying bounded range API has that limit. Large backlog recovery remains a later checkpoint/anchor feature.

## Integration with projections

A projection should persist its own checkpoint in the same transaction as its derived changes:

```text
BEGIN projection transaction
    apply batch events
    update projection rows
    store batch.after cursor
COMMIT
feed.ack(batch)
```

After a crash before `ack`, restart from the projection's persisted cursor and poll the same canonical delta again.

The change feed never turns projection rows into memory truth. Derived indexes still rehydrate and authorize from canonical memory.

## Security boundary

The feed relies on the durable ledger's unkeyed event-chain integrity and process-local batch capabilities. It does not provide:

- external signatures or remote attestation;
- authenticated consumer identities;
- distributed offsets or leases;
- protection against an operator able to rewrite the entire canonical database and recompute every digest;
- automatic semantic transition verification;
- arbitrary chunked catch-up with intermediate trusted anchors.

## Non-claims

This module does not prove:

- infinite context;
- continual learning;
- bounded startup recovery;
- `O(k)` canonical mutation;
- production-scale fan-out to many consumers;
- complete memory retrieval.

It establishes a narrower invariant:

> After a verified startup boundary, a live consumer can receive and acknowledge the exact complete canonical append since its checkpoint with work proportional to that append.
