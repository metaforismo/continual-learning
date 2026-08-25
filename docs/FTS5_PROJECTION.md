# FTS5 lexical projection

## Purpose

The FTS5 layer accelerates lexical candidate discovery without becoming a second memory system.

```text
canonical ledger
      ↓ deterministic projection
SQLite FTS5 cache
      ↓ candidate ids + digests only
canonical rehydration
      ↓ authorization / state adjudication
bounded model context
```

The index is disposable. It never authorizes a fact, procedure, outcome, or instruction.

## Trust boundary

A search hit is only an address:

```text
canonical id
kind
scope
rank
projection generation
entry digest
canonical fingerprint
```

It exposes neither indexed text nor claim values. Before a hit may influence a model or action, `rehydrate` verifies the active generation, exact ledger fingerprint, authorized scope, evidence availability, claim lifecycle, privacy policy, and canonical entry digest.

## Watermark, manifest, and generations

Every rebuild stores:

```text
projection schema version
active generation
canonical fingerprint
event count
last event sequence
entry count
full generation manifest digest
rebuild time
```

`status` replays the canonical input and verifies every active row plus the complete manifest. Deleted, inserted, malformed, or modified cache rows therefore fail closed instead of silently changing recall.

This is integrity detection, not authentication. An attacker able to rewrite both the projection and all of its metadata remains outside this cache-level boundary; canonical rehydration and a rebuild are still required.

Rebuild uses a generation swap inside `BEGIN IMMEDIATE`:

1. acquire the SQLite write lock;
2. read the current watermark under that lock;
3. reject an older snapshot or same-length canonical fork;
4. insert the next generation;
5. write its watermark and manifest;
6. retire prior generations;
7. commit.

A failure at any phase rolls the transaction back, leaving the prior generation usable. Reading the watermark after acquiring the write lock prevents concurrent rebuilders from independently choosing the same generation or regressing a newer committed snapshot.

## Plaintext privacy policy

By default, searchable text enters the cache only when every contributing evidence object is currently available and classified `public` or `internal`.

The following remain excluded regardless of a mistaken lower sensitivity classification:

```text
secret-detected evidence
claims derived from secret-detected evidence
evidence-less claim values with no privacy classification
personal / sensitive / secret evidence under the default policy
```

A host may broaden the configured sensitivity list only when encryption, tenancy, access control, deletion, backups, and incident recovery justify copying that data into a search cache.

## Query and scope bounds

Callers never supply raw SQLite `MATCH` syntax. Input is normalized into bounded Unicode word/identifier tokens and compiled into quoted prefix terms. The public path bounds:

- query token count;
- individual token length;
- result count;
- number of authorized scopes;
- scope identifier length.

`global` is never appended implicitly. FTS operators, column filters, and `NEAR` expressions cannot be injected through the query string.

## Candidate-only output

Search returns IDs, scope, lifecycle, score, generation, fingerprint, and entry digest. It deliberately omits:

```text
search_text
claim value
evidence preview
model-ready content
```

The caller must rehydrate from canonical projections. Current search excludes superseded claims; historical search may recover them but still preserves their lifecycle.

## Recovery

The FTS database is not backed up as authoritative memory. Recovery is:

```text
discard projection
replay canonical ledger
rebuild
```

## Current limitations

V1 does not yet provide:

- incremental indexing; it performs full canonical rebuilds;
- a cached/opaque durable-ledger snapshot, so freshness checks currently replay the supplied history;
- encrypted per-user personal-memory indexes;
- BM25 calibration across heterogeneous document classes;
- typo tolerance, stemming, synonyms, or learned query rewriting;
- vector, temporal, graph, or causal candidate fusion;
- distributed replicas, leases, or million-object benchmark evidence;
- protection against an operator who can forge both cache rows and cache metadata.

These are later retrieval gates. None weaken the invariant that index output must be canonically rehydrated and authorized.
