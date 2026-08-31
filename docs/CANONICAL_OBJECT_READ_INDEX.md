# Canonical object read index

## Status

`canonical-object-read-index-v1` is a derived, rebuildable SQLite projection over the verified canonical change feed. It exists to rehydrate selected evidence and claim identities without replaying the complete lifetime event history for every retrieval hit.

It is **not** a second source of truth. The durable canonical ledger remains authoritative.

```text
canonical SQLite ledger
        |
        v
verified bounded change feed
        |
        v
registered object-read consumer transaction
        |
        +-- object heads
        +-- immutable object versions
        +-- transaction-time intervals
        +-- sparse integrity buckets and nodes
        +-- projection metadata
        +-- durable consumer receipt and cursor
```

Projection mutation, the consumer receipt, and consumer-cursor advancement commit atomically through `SqliteConsumerCheckpointStore`.

## Why it exists

The FTS5 consumer makes candidate discovery incremental, but an FTS hit is only an address. Before this projection, exact canonical rehydration could still require replaying all historical events:

```text
FTS candidate claim/847291
        |
        v
replay N lifetime events
        |
        v
recover one claim and its evidence
```

The object-read index replaces that normal read path with selected lookup:

```text
candidate identity
        |
        v
exact head/version lookup
        |
        v
verify selected bucket and sparse path
        |
        v
apply scope, privacy, and temporal view
        |
        v
return cursor-bound proof
```

Full replay remains available for rebuild and forensic audit.

## Correctness contract

### Genesis completeness

Registration requires the canonical genesis cursor. Tail bootstrap is rejected because a projection that intentionally skipped prior history could not authenticate complete object histories.

### Exact identities

The public API supports exact lookup by:

- evidence ID;
- claim ID.

Unknown current identities return no object only after the corresponding authenticated head bucket has been checked. The implementation does not turn approximate search output into canonical content.

### Bitemporal reads

The index keeps immutable versions with half-open transaction-time intervals:

```text
[recordedAt, knownTo)
```

It exposes separate operations for:

- current object state;
- object state known at transaction time `knownAt`;
- claim applicability at world time `validAt`, evaluated against the version selected at `knownAt`.

Transaction time and world time remain separate. A superseded claim can therefore remain historically retrievable without governing the current view.

### Current privacy overlay

Historical evidence metadata may be selected, but current restriction/deletion still governs content use. If either the selected version or current version is unavailable, the returned evidence view:

- reports the selected and current availability states;
- marks `contentAvailable = false`;
- removes the bounded canonical `preview` field from the returned record.

The projection never reconstructs missing artifact bytes. Raw evidence remains in the provider-owned content-addressed artifact layer.

### Exact provenance closure

`rehydrateClaim()` follows the claim's exact `EvidenceRef` identities. Every selected reference is checked against:

- evidence ID;
- source groups;
- authority;
- artifact content digest.

The result reports whether closure is complete and lists unavailable evidence IDs. Evidence roles remain on the canonical claim references; reading an object does not reinterpret support as verification.

### Scope authorization

Every selected object must belong to an explicitly authorized scope in `scopeChain`. Exact IDs do not bypass scope checks. Callers that need a globally scoped evidence object must authorize `global` explicitly.

### Current-tail gate

Current reads require:

```text
object-read consumer cursor == durable canonical tail observed by the change feed
```

A coherent but lagging projection emits no current object.

### One checkpoint per compound result

The public facade rejects multi-object address rehydration or claim provenance closure if individual lookups cross a consumer checkpoint while the canonical ledger and projection advance concurrently.

Compound results therefore either:

- contain proofs bound to one exact cursor, revision, batch, and configuration; or
- fail closed and require the caller to retry.

## Integrity model

Each immutable object version stores:

- canonical kind and ID;
- canonical event sequence that created the version;
- transaction interval;
- canonical state JSON;
- state digest;
- row digest;
- deterministic bucket assignment.

Each current object head stores:

- exact current version sequence;
- state digest;
- version digest;
- head digest;
- deterministic bucket assignment.

Two sparse authenticated trees are maintained:

```text
head tree       current identity -> current version
version tree    identity + version sequence -> immutable version
```

Non-empty buckets have deterministic manifests. Their leaf digests are folded through sparse internal nodes into published head and version roots. A selected proof contains the target bucket, sibling path, root, canonical cursor, consumer revision, last batch ID, and projection configuration digest.

The normal selected-read path verifies only the relevant bucket and sparse path. `audit()` performs an exhaustive projection scan and verifies:

- every object row and canonical JSON state;
- head-to-version parity;
- complete transaction-interval chains;
- every bucket manifest;
- every sparse node;
- root counts and digests;
- projection metadata against the durable consumer checkpoint;
- the durable consumer receipt chain through the underlying store audit.

## API outline

```ts
const index = new CanonicalObjectReadIndex(store, {
  consumerId: 'projection/object-read/main',
  projectionTablePrefix: 'object_read_main_',
});

index.register(); // genesis only
index.catchUp(feed);

const evidence = index.lookupEvidence(feed, 'evidence/123', {
  scopeChain: ['project/example'],
});

const claimAtTransactionTime = index.lookupClaimKnownAt(feed, 'claim/456', {
  scopeChain: ['project/example'],
  knownAt: 1_780_000_000_000,
});

const claimAtWorldTime = index.lookupClaimValidAt(feed, 'claim/456', {
  scopeChain: ['project/example'],
  knownAt: 1_780_000_000_000,
  validAt: 1_770_000_000_000,
});

const closure = index.rehydrateClaim(feed, 'claim/456', {
  scopeChain: ['project/example', 'global'],
});
```

Every selected result is immutable and includes `proofDigest` plus the exact canonical cursor metadata against which it was produced.

## Complexity boundary

Let:

- `k` be the number of selected objects;
- `B` be the selected authenticated bucket size;
- `D` be sparse-tree depth (`bucketBits`);
- `n` be total projected object versions.

Normal selected lookup is designed around:

```text
O(B + D)
```

per object, plus SQLite index lookup cost. Bounded `k`-object rehydration is approximately:

```text
O(k * (B + D))
```

It does not request lifetime events from the canonical ledger. Projection catch-up is incremental in the canonical batch and objects changed by that batch. Full forensic audit and genesis rebuild remain explicitly `O(n)`.

This is an engineering complexity boundary, not a benchmark claim. Latency and scaling claims require machine-readable benchmark runs at increasing history sizes.

## Failure behavior

The read path fails closed on:

- stale or forked canonical cursors;
- mismatched consumer configuration;
- malformed canonical JSON;
- wrong object kind or identity;
- invalid transaction interval;
- state, version, or head digest mismatch;
- wrong deterministic bucket assignment;
- missing or divergent bucket manifests;
- missing or divergent sparse nodes;
- roots or counts that do not match publication metadata;
- stale retrieval-candidate cursor metadata;
- evidence references that diverge from selected evidence;
- compound reads that cross a projection checkpoint.

A corrupted derived database is dropped and rebuilt from the verified canonical ledger. It must never authorize repair or mutation of canonical history.

## Known limitations

### Projection roots are not yet externally committed

The sparse roots are published atomically inside the derived projection transaction and are bound to its durable consumer checkpoint metadata. They detect accidental, partial, and incoherent corruption.

A party with arbitrary write access to the entire projection database could coherently replace rows, manifests, nodes, and root metadata. This v1 does not pretend that an internally stored root is a hardware-backed or independently authenticated commitment.

A future hardening tranche may bind projection roots to a separate host-authenticated commitment or canonical receipt without promoting the projection itself into canonical truth.

### Historical absence before first capture

The v1 API authenticates current absence through the head tree. A historical query for an identity that exists now but had not yet been captured fails closed rather than claiming an authenticated historical absence. A later version may add explicit non-membership proofs over per-object version ranges.

### No state adjudication inside the index

The object-read index returns canonical object versions. It does not decide which conflicting claim governs action. Callers must still apply evidence availability, policy, deterministic state adjudication, and context-compilation boundaries.

## Evaluation gates

Before treating this path as scalable, benchmark at increasing lifetime histories and record:

- one evidence lookup;
- one claim lookup;
- claim plus evidence closure;
- historical lookup;
- batch catch-up;
- startup verification;
- full audit;
- full rebuild;
- selected bucket size distribution;
- proof size;
- concurrent-advance retry rate.

Run manifests must include commit SHA, Node/SQLite versions, dataset generator version, event counts, bucket configuration, hardware, warm/cold cache state, repetitions, and raw results.

## Next gate

With candidate discovery and selected canonical rehydration separated from lifetime replay, the next research tranche is `experience-attribution-v1`: distinguish memories that were activated, materialized, consulted, and actually applied, then attach conservative utility evidence without confusing ordinary successful trajectories with causal interventions.
