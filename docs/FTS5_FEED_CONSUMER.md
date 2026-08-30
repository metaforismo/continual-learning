# FTS5 canonical change-feed consumer

## Purpose

`Fts5FeedConsumer` connects the durable canonical event ledger to a disposable SQLite FTS5 candidate index without replaying the entire canonical history for every update.

```text
canonical ledger cursor N
        -> verified bounded batch N+1..M
        -> registered consumer transaction
        -> structural projection + lexical documents
        -> consumer receipt + cursor M
        -> commit
```

The FTS database remains derived state. It may nominate canonical addresses; it never authorizes memory, resolves current truth, or proves absence.

## Correctness boundary

The consumer must be registered from canonical genesis. Tail bootstrap is rejected because an apparently healthy lexical index that silently skipped older history cannot claim complete lexical coverage.

Each batch is an exact process-issued `CanonicalAppendBatch`. The surrounding `SqliteConsumerCheckpointStore` publishes the FTS mutation, durable receipt, and consumer cursor in one SQLite transaction. Failure at any point rolls back all three and leaves the exact batch pending for retry.

The consumer keeps only enough local structure to update the lexical view incrementally:

- evidence availability and support eligibility;
- claim lifecycle and evidence references;
- reverse evidence -> claim dependencies;
- current searchable documents;
- FTS5 shadow rows;
- fixed bucket integrity manifests;
- the consumer configuration and canonical cursor binding.

A clean full rebuild remains the recovery boundary when the incremental state cannot prove a safe transition.

## Privacy behavior

The default plaintext policy indexes only `public` and `internal` available evidence and excludes `secret-detected` sources. Claim text is searchable only while every cited evidence reference remains available and eligible. Claim values remain excluded unless the host explicitly opts in.

When evidence becomes restricted or deleted:

1. its searchable document is removed;
2. its retained search text is cleared;
3. every dependent claim loses searchable text and its FTS document;
4. the same transaction updates manifests, receipt, and consumer cursor.

A later restoration does **not** recreate discarded plaintext from memory. If restoration would require bytes intentionally removed from the projection, the consumer raises `Fts5FeedRebuildRequiredError`; the canonical source must be re-read through the rebuild path.

The projection still retains structural identifiers, scope, source-group metadata, authority, and artifact digests needed to process future canonical events. Treat the projection database as sensitive metadata. Identity-key hashing/minimization beyond the fields already removed in v1 is a separate schema migration and is not claimed here.

## Current-tail requirement

An internally consistent projection may still lag the canonical ledger. `search()` therefore requires the `CanonicalChangeFeed` observing that durable ledger and compares the durable tail with the consumer checkpoint before returning candidates.

```text
consumer cursor != durable canonical tail
        -> no candidates
        -> catch up first
```

This prevents a stale but internally consistent cache from being treated as a current retrieval surface.

## Search output

Search results are addresses only:

```text
canonical id
kind
scope
claim lifecycle hint
rank / advisory score
entry digest
consumer revision
consumer cursor digest
last batch id
configuration digest
```

They do not contain source text, claim values, or model-ready content.

Before use, candidates require canonical rehydration plus the normal scope, availability, state-adjudication, and context-compilation gates.

## Integrity checks

Every document carries a digest over its canonical id, kind, scope, lifecycle, source digest, and search text. The FTS shadow row must match the canonical projection document.

Documents and dependencies are partitioned into fixed hash buckets. Search re-verifies the full bucket for every selected candidate, so a coherent alteration of both a document row and its FTS shadow is still rejected unless the matching manifest is also rewritten. `audit()` recomputes every document, dependency, shadow row, and bucket.

These are corruption-detection controls, not cryptographic authentication of a database administrator capable of coherently rewriting the entire projection and its manifests.

## Incremental semantics

Examples:

```text
evidence.captured
    -> create evidence state
    -> maybe create lexical document

claim.asserted
    -> create claim state
    -> record evidence dependencies
    -> index only if lifecycle + evidence policy permit

evidence restricted/deleted
    -> remove evidence lexical document
    -> scrub all dependent claims

claim admitted/superseded/revoked
    -> update only the affected claim documents
```

The cost of update is therefore driven by the canonical append and its dependency blast radius, rather than total lifetime history.

## Explicit scalability limitation

Safe rehydration currently reconstructs canonical projections from the supplied full event history in order to verify candidate identity, lifecycle, and cursor binding. That path is still `O(N)` in lifetime history. Selected-bucket integrity verification is also proportional to the size of the selected buckets.

The next scaling gate is a canonical object-read index / authenticated object projection that can rehydrate selected evidence and claims without scanning the entire event log. This FTS consumer solves incremental **index maintenance**, not yet billion-event canonical reads.

## Non-claims

This component does not provide:

- canonical truth;
- exhaustive retrieval;
- proof that a lexical miss means absence;
- vector or associative retrieval;
- distributed exactly-once delivery;
- privacy erasure of the canonical ledger;
- solved continual learning or infinite context.
