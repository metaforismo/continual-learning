# FTS5 lexical projection

## Purpose

The FTS5 layer accelerates lexical candidate discovery without becoming a second memory system.

```text
canonical ledger
      ↓ deterministic projection
SQLite FTS5 cache
      ↓ candidate addresses only
canonical rehydration
      ↓ availability / lifecycle / scope / privacy checks
state adjudication
      ↓
bounded model context
```

The index is disposable. It never authorizes a fact, procedure, outcome, or instruction.

A lexical miss is not proof that a memory is absent. FTS is one candidate generator; exhaustive or safety-critical absence claims require an explicit canonical coverage protocol or additional retrievers.

## Trust boundary

A search hit is only an address:

```text
canonical id
kind
scope
transaction lifecycle
rank and advisory score
projection generation
entry digest
canonical fingerprint
```

It exposes neither indexed text nor claim values. Before a hit may influence a model or action, `rehydrate` checks the exact canonical fingerprint, authorized scope, evidence availability, claim lifecycle, plaintext privacy policy, and a freshly recomputed entry digest.

Rank and score describe the cache query that produced a candidate. They are not epistemic authority and must not bypass canonical state adjudication.

## Canonical single-read snapshots

Every public operation first semantically replays the supplied events through `MemoryKernel.from(events)` and then uses that one immutable event snapshot for:

```text
fingerprinting
projection document construction
privacy filtering
rehydration
```

Caller-owned objects and stateful getters therefore cannot present one history to fingerprinting and another history to indexing.

## Watermark, configuration, manifest, and generations

Every rebuild stores:

```text
projection schema version
active generation
canonical fingerprint
event count
last event sequence
entry count
full generation manifest digest
projection configuration digest
rebuild time
```

The configuration digest binds the generation to:

```text
projection schema
tokenizer
allowed plaintext sensitivity levels
claim-value indexing policy
```

A generation built under a permissive policy cannot be silently reopened under a stricter host policy. It becomes stale and must be rebuilt.

`status` verifies every active row and the complete generation manifest. Deleted, inserted, malformed, duplicated, or modified cache rows therefore fail closed instead of silently changing recall.

This is integrity detection, not authentication. An operator able to rewrite both projection rows and all cache metadata remains outside this cache-level boundary. Canonical rehydration is still mandatory.

## Atomic rebuild and fork resistance

Rebuild uses a generation swap inside `BEGIN IMMEDIATE`:

1. acquire the SQLite write lock;
2. read the current watermark under that lock;
3. reject a regressing history;
4. verify that a longer history extends the exact previously projected prefix;
5. reject same-length or longer canonical forks;
6. insert the next generation;
7. write its watermark, configuration digest, and manifest;
8. retire prior generations;
9. commit.

A failure at any injected phase rolls the transaction back, leaving the prior generation usable. Reading and validating the watermark after acquiring the write lock prevents delayed rebuilders from regressing a newer committed projection.

## Consistent search snapshots

A strict search performs, in one SQLite read transaction:

```text
read watermark
    ↓
validate configuration
    ↓
verify active-generation row manifest
    ↓
execute MATCH against that same generation
```

A concurrent rebuild cannot retire the generation between validation and `MATCH` and cause a false empty result.

## Plaintext privacy policy

By default, searchable evidence text enters the cache only when the source is currently available and classified `public` or `internal`.

The following remain excluded:

```text
secret-detected evidence
claims derived from excluded or unavailable evidence
evidence-less claims with no privacy classification
personal / sensitive / secret evidence under the default policy
```

Claim values have no independent sensitivity field yet and are omitted by default. A host must explicitly set:

```ts
indexClaimValues: true
```

before values are copied into plaintext FTS. The option is runtime-validated as a boolean and is included in the configuration digest.

Claim subject, predicate, and tags remain metadata indexed only when every cited source is currently available and permitted by the configured sensitivity policy. A later claim-level privacy classification remains desirable.

A host should broaden plaintext sensitivity levels only when tenancy, filesystem permissions, encryption, deletion, backup handling, and incident response justify the extra copy.

## Query, scope, and candidate bounds

Callers never supply raw SQLite `MATCH` syntax. Input is normalized with deterministic Unicode normalization and lowercasing, tokenized into word/number/identifier terms, and compiled into quoted prefix expressions.

The public path bounds:

- query characters;
- query token count;
- individual token length;
- result count;
- rehydration candidate count;
- number of authorized scopes;
- scope identifier length.

`global` is never appended implicitly. FTS operators, column filters, and `NEAR` expressions cannot be injected through the query string.

## Lifecycle is not world-time truth

The projection includes both `active` and `superseded` claim candidates by default. An optional:

```ts
claimLifecycle: 'active-only'
```

filter narrows the transaction-lifecycle candidate set, but it is not a current-state decision.

Bitemporal current/historical validity, conflicts, invalidation, and `unknown-current` remain the state adjudicator's responsibility.

## Candidate-only output and canonical rehydration

Search deliberately omits:

```text
search_text
claim value
evidence preview
model-ready content
```

Rehydration uses canonical projections rather than the cache. A candidate can therefore still be rehydrated after the disposable database has been closed or rebuilt, provided that:

```text
candidate canonical fingerprint == current canonical fingerprint
candidate scope is authorized
canonical object remains searchable under host privacy policy
fresh canonical entry digest == candidate entry digest
```

Candidates from an older canonical history fail closed.

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
- bounded freshness verification; strict status/search currently scan the active generation;
- an authenticated or keyed manifest;
- proof of completeness for the internal FTS shadow index;
- encrypted per-user personal-memory indexes;
- claim-level sensitivity independent of source evidence;
- BM25 calibration across heterogeneous document classes;
- typo tolerance, stemming, synonyms, or learned query rewriting;
- vector, temporal, graph, causal, or learned candidate fusion;
- distributed replicas, leases, or million-object benchmark evidence;
- proof that a zero-result lexical query means no relevant memory exists.

These are later retrieval gates. None weaken the invariant that index output must be canonically rehydrated and authorized.
