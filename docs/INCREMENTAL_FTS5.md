# Checkpointed FTS5 diff publication

## Purpose

The rebuildable FTS5 adapter establishes the lexical trust boundary but replaces the complete cache on every publication. `SqliteIncrementalFts5Projection` adds append-bound checkpoints and changed-row publication without changing the central rule:

> Retrieval proposes canonical addresses. Canonical memory alone supplies content, availability, scope, lifecycle, privacy classification, and authority.

The adapter is a disposable cache. Its event digests, checkpoints, reverse dependencies, and manifests are projection metadata—not a second canonical event store.

## Publication model

Each public operation first replays the caller-supplied history once into one immutable canonical snapshot. Fingerprinting, document derivation, prefix verification, search freshness, and rehydration all use that same snapshot.

`update(events)` then:

1. acquires a SQLite `BEGIN IMMEDIATE` write lock;
2. verifies the exact previously checkpointed event prefix;
3. rejects regressions, same-length forks, longer non-prefix histories, configuration drift, malformed checkpoints, stale bucket generations, and unpublished event-digest tails;
4. derives the final privacy-filtered document and dependency projection;
5. compares it with stored rows;
6. leaves exact unchanged document/dependency rows untouched;
7. replaces only appeared, disappeared, changed, or corrupted rows;
8. rewrites the fixed-size bucket metadata;
9. appends only the new canonical event-digest range;
10. publishes the next checkpoint and active metadata in the same transaction.

An unchanged document retains the generation in which its bytes were last published. The generation stored on a document row is therefore **last-modified cache metadata**, not current-state truth. Search candidates carry the active checkpoint generation instead.

A no-op `update()` returns the current checkpoint without publishing another generation. An explicit `rebuild()` republishes the full document/dependency cache and creates a new checkpoint; it is the repair and configuration-migration path.

## Checkpoint contract

Each checkpoint binds:

```text
exact canonical fingerprint
base and resulting event counts
last sequence and transaction time
append sequence interval and append digest
privacy/configuration digest
document/dependency counts
document/dependency root manifests
strictly monotonic publication time
immediate predecessor digest
```

The active metadata row must exactly equal the active checkpoint on every duplicated field. Fast verification also recomputes the active checkpoint digest and the immediate predecessor digest rather than trusting their stored content addresses.

Publication is atomic across:

```text
document rows
FTS shadow rows
privacy-filtered reverse dependencies
bucket manifests
append event digests
checkpoint
active metadata
```

A fault before commit rolls all of them back.

## Integrity layers

### Fast status and search gate

After canonical snapshot preparation, normal status/search verifies a fixed amount of cache metadata:

- exact active metadata/checkpoint agreement;
- active checkpoint digest;
- genesis or immediate-predecessor linkage;
- predecessor digest;
- monotonic checkpoint time;
- configuration and canonical watermark;
- fixed-size document and dependency bucket sets;
- bucket generation equal to the active checkpoint;
- root manifests and aggregate counts.

For each selected search result, the adapter additionally checks the FTS row against the canonical document-cache row and recomputes that row's entry digest before emitting an address.

### Full audit

`audit(events)` is deliberately stronger and remains linear in the stored/canonical projection. It checks:

- every document against the canonical privacy projection;
- every FTS shadow row against the document table;
- SQLite FTS5's internal integrity command;
- every privacy-filtered reverse dependency and bucket assignment;
- every canonical event-prefix digest;
- every checkpoint digest, predecessor edge, event range, append digest, timestamp, and terminal-head relation;
- bucket roots recomputed from canonical documents and dependencies.

A fast status result is not a substitute for forensic audit.

## Privacy

The default plaintext policy indexes only currently available `public` and `internal` evidence. It excludes `personal`, `sensitive`, `secret`, `secret-detected`, unavailable, and otherwise ineligible evidence.

Claims supported by excluded evidence are excluded. Claim values remain omitted unless `indexClaimValues: true` is explicitly supplied, because claims do not yet carry an independent value-sensitivity classification.

The reverse-dependency table follows the same plaintext privacy projection. Changing the privacy configuration changes the configuration digest: `update()` fails closed and requires explicit `rebuild()`.

## Retrieval and rehydration

Search returns only:

```text
canonical id
kind
scope
transaction lifecycle
rank and advisory score
entry digest
canonical fingerprint
active checkpoint generation
```

It never returns indexed text or claim values.

Rehydration snapshots caller-provided candidates once, rejects malformed or duplicate addresses, replays canonical memory, reapplies scope/privacy/availability/lifecycle rules, and recomputes the exact entry digest. It does not read the SQLite cache, so a valid candidate can still be canonically rehydrated after the disposable cache is closed or rebuilt.

A lexical miss remains **not evidence of absence**.

## Recovery and schema handling

The adapter uses strict SQLite tables, `trusted_schema = OFF`, WAL, full synchronous durability, bounded busy timeout, parameterized values, and parser-produced FTS queries.

A partially created or column-incompatible incremental schema is discarded before first use. Explicit rebuild is the recovery path for document, FTS, dependency, bucket, or privacy-configuration repair. A corrupt checkpoint/event-prefix lineage fails closed; the host must discard the disposable database and rebuild it from trusted canonical memory.

## Complexity boundary

The current implementation deliberately does not hide its remaining linear work:

```text
canonical semantic replay:       O(N)
canonical full fingerprint:      O(N)
expected document derivation:    O(N)
row/dependency diff construction: O(N)
SQL writes:                      O(changed rows + fixed buckets + append)
fast cache metadata verification: O(bucket count + selected results)
startup recovery/full audit:      O(N)
```

This tranche reduces write amplification and adds exact append/checkpoint integrity. It does **not** yet provide an O(k) canonical cursor or bounded lifetime cost.

## Non-claims

This layer does not yet provide:

- a durable canonical event-byte store;
- O(k) canonical cursor advancement or append-only projection consumption;
- keyed/authenticated manifests against an operator able to rewrite the whole database coherently;
- proof of FTS shadow-index completeness or zero-result completeness;
- encrypted personal-memory search;
- claim-level value sensitivity;
- vector, temporal, entity, graph, causal, or learned retrieval fusion;
- million-object latency evidence;
- infinite context;
- solved continual learning.
