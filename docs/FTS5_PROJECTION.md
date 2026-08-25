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

The index is a disposable projection. It never authorizes a fact, procedure, outcome, or instruction.

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

It does not expose indexed text or a claim value. Before any hit may influence a model or action, `rehydrate` verifies:

- the index watermark still matches the exact canonical ledger fingerprint;
- the candidate belongs to the active generation;
- the requested scope is explicitly authorized;
- the canonical evidence is still available;
- the canonical claim lifecycle is valid for the current/historical view;
- the candidate digest matches a fresh deterministic projection of the canonical object.

The index therefore selects candidates; canonical memory remains the source of content and authority.

## Watermark and generations

Every completed rebuild stores:

```text
projection schema version
active generation
canonical fingerprint
event count
last event sequence
entry count
rebuild time
```

Search fails closed when the watermark is stale. `ensureFresh` may rebuild explicitly; search never silently mixes old index rows with new canonical state.

Rebuild uses a generation swap inside `BEGIN IMMEDIATE`:

1. insert the next generation;
2. write its watermark;
3. retire prior generations;
4. commit.

A failure at any injected phase rolls the transaction back, leaving the old generation and watermark usable.

## Plaintext privacy policy

The default cache indexes searchable text only when every contributing evidence object is:

```text
public or internal
and currently available
```

`personal`, `sensitive`, and `secret` text is excluded from the plaintext FTS database by default. A host may configure a broader set only when its database encryption, tenancy, deletion, backup, and access-control boundary justifies doing so.

Evidence previews are indexed only when canonically present. Claims are indexed only when their evidence is available and all contributing sensitivities are allowed. The first implementation deliberately sacrifices some recall rather than copying private memory into an unencrypted cache.

## Query safety and bounded work

Callers do not provide raw SQLite `MATCH` syntax. Input is normalized into bounded Unicode word/identifier tokens and compiled into quoted prefix terms. The API also bounds:

- query token count;
- individual token length;
- result count;
- active generation.

FTS operators, column filters, and `NEAR` expressions therefore cannot be injected through the public query string.

## Corruption and recovery

Each row contains an entry digest over:

```text
canonical id
kind
scope
lifecycle
canonical source digest
search text
```

Search verifies row self-integrity before emitting a candidate. Rehydration then recomputes the expected entry from canonical state. Corruption or tampering fails closed and the host can rebuild the entire projection.

The FTS database is not backed up as authoritative memory. Recovery is:

```text
discard projection
replay canonical ledger
rebuild
```

## Current limitations

The implementation does not yet provide:

- incremental indexing; v1 rebuilds from the canonical snapshot;
- encrypted per-user personal-memory indexes;
- BM25 calibration across heterogeneous document classes;
- typo tolerance, stemming, synonyms, or learned query rewriting;
- vector, temporal, graph, or causal candidate fusion;
- distributed index replicas or watermark leases;
- benchmark evidence at million- or billion-object scale;
- proof that retrieval quality remains constant as lifetime history grows.

These are later retrieval gates. They do not weaken the invariant that index output must be rehydrated and authorized canonically.
