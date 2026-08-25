import { DatabaseSync } from 'node:sqlite';

import { ClaimProjection } from '../claims.js';
import type { ClaimLifecycle, EvidenceRecord, MemoryEvent } from '../domain.js';
import { EvidenceProjection } from '../evidence.js';
import { MemoryKernel } from '../kernel.js';
import { fingerprintMemoryEvents } from '../transitions/verifier.js';
import {
  buildDocuments,
  claimText,
  contentDigest,
  documentDigest,
  evidenceText,
  manifestDigest,
  normalizeClaimLifecycleFilter,
  projectionConfigDigest,
  safeMatchQuery,
  searchableClaim,
  searchableEvidence,
  SHA256_PATTERN,
  snapshotScopeChain,
  type IndexedDocument,
} from './canonical.js';
import {
  FTS5_PROJECTION_SCHEMA_VERSION,
  type Fts5ProjectionDatabase,
  type Fts5ProjectionOptions,
  type Fts5ProjectionSnapshot,
  type Fts5ProjectionStatus,
  type Fts5ProjectionWatermark,
  type Fts5RehydrateOptions,
  type Fts5SearchCandidate,
  type Fts5SearchOptions,
  type RehydratedFts5Candidate,
} from './types.js';

const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;
const MAX_REHYDRATE_CANDIDATES = 100;
const META_ROW_ID = 1;

interface MetaRow {
  readonly schema_version: number;
  readonly active_generation: number;
  readonly event_count: number;
  readonly last_seq: number;
  readonly canonical_fingerprint: string;
  readonly entry_count: number;
  readonly manifest_digest: string;
  readonly config_digest: string;
  readonly rebuilt_at: number;
}

interface SearchRow {
  readonly canonical_id: string;
  readonly kind: string;
  readonly scope: string;
  readonly lifecycle: string;
  readonly source_digest: string;
  readonly entry_digest: string;
  readonly search_text: string;
  readonly generation: number;
  readonly fts_score: number;
}

function snapshot(events: readonly MemoryEvent[]): Fts5ProjectionSnapshot {
  // Canonicalize exactly once. Fingerprinting, projection, and rehydration use the same immutable
  // semantic replay rather than rereading caller-owned objects or stateful getters.
  const canonicalEvents = MemoryKernel.from(events).events();
  return Object.freeze({
    events: canonicalEvents,
    fingerprint: fingerprintMemoryEvents(canonicalEvents),
  });
}

function rowAsMeta(value: unknown): MetaRow | undefined {
  if (value === undefined) return undefined;
  const row = value as Partial<MetaRow>;
  if (
    typeof row.schema_version !== 'number' ||
    !Number.isInteger(row.schema_version) ||
    typeof row.active_generation !== 'number' ||
    !Number.isInteger(row.active_generation) ||
    row.active_generation <= 0 ||
    typeof row.event_count !== 'number' ||
    !Number.isInteger(row.event_count) ||
    row.event_count < 0 ||
    typeof row.last_seq !== 'number' ||
    !Number.isInteger(row.last_seq) ||
    row.last_seq < 0 ||
    typeof row.canonical_fingerprint !== 'string' ||
    typeof row.entry_count !== 'number' ||
    !Number.isInteger(row.entry_count) ||
    row.entry_count < 0 ||
    typeof row.manifest_digest !== 'string' ||
    typeof row.config_digest !== 'string' ||
    typeof row.rebuilt_at !== 'number' ||
    !Number.isInteger(row.rebuilt_at) ||
    row.rebuilt_at < 0
  ) {
    throw new Error('FTS projection metadata is malformed');
  }
  return row as MetaRow;
}

function watermarkFromRow(row: MetaRow): Fts5ProjectionWatermark {
  if (row.schema_version !== FTS5_PROJECTION_SCHEMA_VERSION) {
    throw new Error(`unsupported FTS projection schema version: ${row.schema_version}`);
  }
  if (!SHA256_PATTERN.test(row.canonical_fingerprint)) {
    throw new Error('FTS projection watermark fingerprint is malformed');
  }
  if (!SHA256_PATTERN.test(row.manifest_digest)) {
    throw new Error('FTS projection manifest digest is malformed');
  }
  if (!SHA256_PATTERN.test(row.config_digest)) {
    throw new Error('FTS projection config digest is malformed');
  }
  return Object.freeze({
    schemaVersion: FTS5_PROJECTION_SCHEMA_VERSION,
    generation: row.active_generation,
    eventCount: row.event_count,
    lastSeq: row.last_seq,
    canonicalFingerprint: row.canonical_fingerprint,
    entryCount: row.entry_count,
    manifestDigest: row.manifest_digest,
    configDigest: row.config_digest,
    rebuiltAt: row.rebuilt_at,
  });
}

function snapshotCandidate(candidate: Fts5SearchCandidate): Fts5SearchCandidate {
  const canonicalId = candidate.canonicalId;
  const kind = candidate.kind;
  const scope = candidate.scope;
  const lifecycle = candidate.lifecycle;
  const rank = candidate.rank;
  const score = candidate.score;
  const entryDigest = candidate.entryDigest;
  const canonicalFingerprint = candidate.canonicalFingerprint;
  const generation = candidate.generation;
  return Object.freeze({
    canonicalId,
    kind,
    scope,
    ...(lifecycle === undefined ? {} : { lifecycle }),
    rank,
    score,
    entryDigest,
    canonicalFingerprint,
    generation,
  });
}

/**
 * Rebuildable SQLite FTS5 projection. Search emits addresses only, verifies its generation, and
 * requires canonical rehydration before a hit may affect model context or action.
 */
export class SqliteFts5Projection {
  readonly #db: Fts5ProjectionDatabase;
  readonly #ownsDatabase: boolean;
  readonly #allowedSensitivities: ReadonlySet<EvidenceRecord['sensitivity']>;
  readonly #indexClaimValues: boolean;
  readonly #configDigest: string;
  readonly #faultInjector: Fts5ProjectionOptions['faultInjector'] | undefined;
  #closed = false;

  constructor(
    database: Fts5ProjectionDatabase,
    options: Fts5ProjectionOptions = {},
    ownsDatabase = false,
  ) {
    this.#db = database;
    this.#ownsDatabase = ownsDatabase;

    const suppliedSensitivities = options.searchableSensitivities;
    const sensitivities = Object.freeze([
      ...(suppliedSensitivities ?? ['public', 'internal']),
    ]);
    const indexClaimValues = options.indexClaimValues;
    const busyTimeoutMs = options.busyTimeoutMs;
    const faultInjector = options.faultInjector;

    if (sensitivities.length === 0 || new Set(sensitivities).size !== sensitivities.length) {
      throw new Error('searchableSensitivities must be non-empty and unique');
    }
    for (const sensitivity of sensitivities) {
      if (!['public', 'internal', 'personal', 'sensitive', 'secret'].includes(sensitivity)) {
        throw new Error(`unknown evidence sensitivity: ${String(sensitivity)}`);
      }
    }
    if (indexClaimValues !== undefined && typeof indexClaimValues !== 'boolean') {
      throw new TypeError('indexClaimValues must be boolean');
    }
    if (faultInjector !== undefined && typeof faultInjector !== 'function') {
      throw new TypeError('faultInjector must be a function');
    }

    this.#allowedSensitivities = new Set(sensitivities);
    this.#indexClaimValues = indexClaimValues ?? false;
    this.#configDigest = projectionConfigDigest(sensitivities, this.#indexClaimValues);
    this.#faultInjector = faultInjector;
    this.#initialize(busyTimeoutMs ?? 5_000);
  }

  static open(filename: string, options: Fts5ProjectionOptions = {}): SqliteFts5Projection {
    if (typeof filename !== 'string' || filename.trim().length === 0) {
      throw new Error('FTS projection filename cannot be empty');
    }
    const database = new DatabaseSync(filename) as unknown as Fts5ProjectionDatabase;
    return new SqliteFts5Projection(database, options, true);
  }

  #initialize(busyTimeoutMs: number): void {
    if (!Number.isInteger(busyTimeoutMs) || busyTimeoutMs < 0 || busyTimeoutMs > 60_000) {
      throw new RangeError('busyTimeoutMs must be an integer in [0, 60000]');
    }
    this.#db.exec('PRAGMA trusted_schema = OFF');
    this.#db.exec(`PRAGMA busy_timeout = ${busyTimeoutMs}`);
    this.#db.exec('PRAGMA journal_mode = WAL');
    this.#db.exec('PRAGMA synchronous = FULL');
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS cl_fts_meta (
        singleton INTEGER PRIMARY KEY CHECK (singleton = ${META_ROW_ID}),
        schema_version INTEGER NOT NULL,
        active_generation INTEGER NOT NULL,
        event_count INTEGER NOT NULL,
        last_seq INTEGER NOT NULL,
        canonical_fingerprint TEXT NOT NULL,
        entry_count INTEGER NOT NULL,
        manifest_digest TEXT NOT NULL,
        config_digest TEXT NOT NULL,
        rebuilt_at INTEGER NOT NULL
      ) STRICT;
    `);
    try {
      this.#db.exec(`
        CREATE VIRTUAL TABLE IF NOT EXISTS cl_fts_entries USING fts5(
          canonical_id UNINDEXED,
          kind UNINDEXED,
          scope UNINDEXED,
          lifecycle UNINDEXED,
          source_digest UNINDEXED,
          entry_digest UNINDEXED,
          generation UNINDEXED,
          search_text,
          tokenize = 'unicode61 remove_diacritics 2'
        );
      `);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'unknown SQLite error';
      throw new Error(`SQLite FTS5 is unavailable: ${message}`);
    }
  }

  #assertOpen(): void {
    if (this.#closed) throw new Error('FTS projection is closed');
  }

  #meta(): Fts5ProjectionWatermark | undefined {
    this.#assertOpen();
    const row = rowAsMeta(
      this.#db
        .prepare(
          `SELECT schema_version, active_generation, event_count, last_seq,
                  canonical_fingerprint, entry_count, manifest_digest, config_digest, rebuilt_at
             FROM cl_fts_meta WHERE singleton = ?`,
        )
        .get(META_ROW_ID),
    );
    return row === undefined ? undefined : watermarkFromRow(row);
  }

  watermark(): Fts5ProjectionWatermark | undefined {
    return this.#meta();
  }

  #withReadTransaction<T>(operation: () => T): T {
    this.#assertOpen();
    this.#db.exec('BEGIN');
    try {
      const result = operation();
      this.#db.exec('COMMIT');
      return result;
    } catch (error) {
      try {
        this.#db.exec('ROLLBACK');
      } catch {
        // Preserve the original failure. Reopen/rebuild remains the cache recovery boundary.
      }
      throw error;
    }
  }

  #generationIntegrityFailure(watermark: Fts5ProjectionWatermark): string | undefined {
    const rows = this.#db
      .prepare(`
        SELECT canonical_id, kind, scope, lifecycle, source_digest, entry_digest,
               search_text, CAST(generation AS INTEGER) AS generation, 0 AS fts_score
          FROM cl_fts_entries
         WHERE generation = ?
         ORDER BY kind ASC, canonical_id ASC, rowid ASC
      `)
      .all(watermark.generation) as unknown as readonly SearchRow[];
    if (rows.length !== watermark.entryCount) {
      return `active generation contains ${rows.length} rows; watermark declares ${watermark.entryCount}`;
    }

    const documents: IndexedDocument[] = [];
    const identities = new Set<string>();
    for (const row of rows) {
      if (row.kind !== 'evidence' && row.kind !== 'claim') {
        return `active generation contains unknown document kind ${row.kind}`;
      }
      if (
        typeof row.canonical_id !== 'string' ||
        row.canonical_id.trim().length === 0 ||
        typeof row.scope !== 'string' ||
        row.scope.trim().length === 0 ||
        typeof row.search_text !== 'string' ||
        !Number.isInteger(row.generation) ||
        row.generation !== watermark.generation
      ) {
        return `row ${row.kind}/${String(row.canonical_id)} contains malformed identity or generation metadata`;
      }
      const identity = `${row.kind}\u0000${row.canonical_id}`;
      if (identities.has(identity)) return `active generation repeats ${row.kind}/${row.canonical_id}`;
      identities.add(identity);

      const lifecycle =
        row.kind === 'claim'
          ? row.lifecycle === 'active' || row.lifecycle === 'superseded'
            ? row.lifecycle
            : undefined
          : row.lifecycle === ''
            ? ''
            : undefined;
      if (lifecycle === undefined) return `${row.kind} ${row.canonical_id} has an invalid lifecycle`;
      if (!SHA256_PATTERN.test(row.source_digest) || !SHA256_PATTERN.test(row.entry_digest)) {
        return `row ${row.kind}/${row.canonical_id} contains a malformed digest`;
      }
      const base = Object.freeze({
        canonicalId: row.canonical_id,
        kind: row.kind,
        scope: row.scope,
        lifecycle,
        sourceDigest: row.source_digest,
        searchText: row.search_text,
      });
      if (documentDigest(base) !== row.entry_digest) {
        return `row integrity failed for ${row.kind}/${row.canonical_id}`;
      }
      documents.push(Object.freeze({ ...base, entryDigest: row.entry_digest }));
    }
    return manifestDigest(documents) === watermark.manifestDigest
      ? undefined
      : 'active generation manifest does not match its watermark';
  }

  #statusForSnapshot(current: Fts5ProjectionSnapshot): Fts5ProjectionStatus {
    const watermark = this.#meta();
    if (watermark === undefined) {
      return Object.freeze({
        initialized: false,
        fresh: false,
        canonicalFingerprint: current.fingerprint,
        eventCount: current.events.length,
        reason: 'projection has not been built',
      });
    }
    if (watermark.configDigest !== this.#configDigest) {
      return Object.freeze({
        initialized: true,
        fresh: false,
        watermark,
        canonicalFingerprint: current.fingerprint,
        eventCount: current.events.length,
        reason: 'projection configuration does not match the active host policy',
      });
    }
    const integrityFailure = this.#generationIntegrityFailure(watermark);
    const watermarkFresh =
      watermark.canonicalFingerprint === current.fingerprint &&
      watermark.eventCount === current.events.length &&
      watermark.lastSeq === (current.events.at(-1)?.seq ?? 0);
    const fresh = watermarkFresh && integrityFailure === undefined;
    return Object.freeze({
      initialized: true,
      fresh,
      watermark,
      canonicalFingerprint: current.fingerprint,
      eventCount: current.events.length,
      reason:
        integrityFailure !== undefined
          ? `projection integrity failed: ${integrityFailure}`
          : fresh
            ? 'projection watermark matches canonical memory'
            : 'projection watermark is stale',
    });
  }

  status(events: readonly MemoryEvent[]): Fts5ProjectionStatus {
    const current = snapshot(events);
    return this.#withReadTransaction(() => this.#statusForSnapshot(current));
  }

  rebuild(events: readonly MemoryEvent[], rebuiltAt = Date.now()): Fts5ProjectionWatermark {
    this.#assertOpen();
    if (!Number.isInteger(rebuiltAt) || rebuiltAt < 0) {
      throw new RangeError('rebuiltAt must be a non-negative integer');
    }
    const current = snapshot(events);
    const documents = buildDocuments(
      current.events,
      this.#allowedSensitivities,
      this.#indexClaimValues,
    );
    const nextManifestDigest = manifestDigest(documents);
    const currentLastSeq = current.events.at(-1)?.seq ?? 0;

    this.#db.exec('BEGIN IMMEDIATE');
    try {
      this.#faultInjector?.('after-begin');
      const existing = this.#meta();
      if (
        existing !== undefined &&
        (current.events.length < existing.eventCount || currentLastSeq < existing.lastSeq)
      ) {
        throw new Error('FTS rebuild cannot regress an existing canonical watermark');
      }
      if (
        existing !== undefined &&
        current.events.length === existing.eventCount &&
        currentLastSeq === existing.lastSeq &&
        existing.canonicalFingerprint !== current.fingerprint
      ) {
        throw new Error('FTS rebuild detected a same-length canonical fork');
      }
      if (existing !== undefined && current.events.length > existing.eventCount) {
        const projectedPrefix = current.events.slice(0, existing.eventCount);
        const prefixLastSeq = projectedPrefix.at(-1)?.seq ?? 0;
        const prefixFingerprint = fingerprintMemoryEvents(projectedPrefix);
        if (
          prefixLastSeq !== existing.lastSeq ||
          prefixFingerprint !== existing.canonicalFingerprint
        ) {
          throw new Error('FTS rebuild detected a canonical fork before the new append range');
        }
      }

      const generation = (existing?.generation ?? 0) + 1;
      if (!Number.isSafeInteger(generation) || generation <= 0) {
        throw new Error('FTS projection generation overflow');
      }
      this.#db.prepare('DELETE FROM cl_fts_entries WHERE generation = ?').run(generation);
      this.#faultInjector?.('after-clear-next-generation');

      const insert = this.#db.prepare(`
        INSERT INTO cl_fts_entries(
          canonical_id, kind, scope, lifecycle, source_digest, entry_digest, generation, search_text
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (const document of documents) {
        insert.run(
          document.canonicalId,
          document.kind,
          document.scope,
          document.lifecycle,
          document.sourceDigest,
          document.entryDigest,
          generation,
          document.searchText,
        );
      }
      this.#faultInjector?.('after-insert');

      this.#db
        .prepare(`
          INSERT INTO cl_fts_meta(
            singleton, schema_version, active_generation, event_count, last_seq,
            canonical_fingerprint, entry_count, manifest_digest, config_digest, rebuilt_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(singleton) DO UPDATE SET
            schema_version = excluded.schema_version,
            active_generation = excluded.active_generation,
            event_count = excluded.event_count,
            last_seq = excluded.last_seq,
            canonical_fingerprint = excluded.canonical_fingerprint,
            entry_count = excluded.entry_count,
            manifest_digest = excluded.manifest_digest,
            config_digest = excluded.config_digest,
            rebuilt_at = excluded.rebuilt_at
        `)
        .run(
          META_ROW_ID,
          FTS5_PROJECTION_SCHEMA_VERSION,
          generation,
          current.events.length,
          currentLastSeq,
          current.fingerprint,
          documents.length,
          nextManifestDigest,
          this.#configDigest,
          rebuiltAt,
        );
      this.#faultInjector?.('after-watermark');
      this.#db.prepare('DELETE FROM cl_fts_entries WHERE generation <> ?').run(generation);
      this.#faultInjector?.('after-retire-old-generation');
      this.#faultInjector?.('before-commit');
      this.#db.exec('COMMIT');
    } catch (error) {
      try {
        this.#db.exec('ROLLBACK');
      } catch {
        // Preserve the original failure. Reopen/status checks remain the recovery boundary.
      }
      throw error;
    }

    const watermark = this.#meta();
    if (watermark === undefined) throw new Error('FTS projection rebuild committed without a watermark');
    return watermark;
  }

  ensureFresh(events: readonly MemoryEvent[], rebuiltAt = Date.now()): Fts5ProjectionWatermark {
    const state = this.status(events);
    return state.fresh && state.watermark !== undefined
      ? state.watermark
      : this.rebuild(events, rebuiltAt);
  }

  search(
    events: readonly MemoryEvent[],
    query: string,
    options: Fts5SearchOptions,
  ): readonly Fts5SearchCandidate[] {
    this.#assertOpen();
    const scopeChain = snapshotScopeChain(options.scopeChain);
    const claimLifecycle = normalizeClaimLifecycleFilter(options.claimLifecycle);
    const limit = options.limit ?? DEFAULT_LIMIT;
    if (!Number.isInteger(limit) || limit <= 0 || limit > MAX_LIMIT) {
      throw new RangeError(`FTS result limit must be an integer in [1, ${MAX_LIMIT}]`);
    }
    const match = safeMatchQuery(query, options.maxQueryTokens);
    const current = snapshot(events);

    return this.#withReadTransaction(() => {
      const state = this.#statusForSnapshot(current);
      if (!state.fresh || state.watermark === undefined) {
        throw new Error(`FTS projection is unavailable: ${state.reason}`);
      }
      const watermark = state.watermark;
      const scopePlaceholders = scopeChain.map(() => '?').join(', ');
      const lifecycleClause =
        claimLifecycle === 'active-only'
          ? "AND (kind <> 'claim' OR lifecycle = 'active')"
          : '';
      const rows = this.#db
        .prepare(`
          SELECT canonical_id, kind, scope, lifecycle, source_digest, entry_digest,
                 search_text, CAST(generation AS INTEGER) AS generation,
                 bm25(cl_fts_entries) AS fts_score
            FROM cl_fts_entries
           WHERE cl_fts_entries MATCH ?
             AND generation = ?
             AND scope IN (${scopePlaceholders})
             ${lifecycleClause}
           ORDER BY fts_score ASC, kind ASC, canonical_id ASC
           LIMIT ?
        `)
        .all(match, watermark.generation, ...scopeChain, limit) as unknown as readonly SearchRow[];

      return Object.freeze(
        rows.map((row, index) => {
          if (row.kind !== 'evidence' && row.kind !== 'claim') {
            throw new Error(`FTS projection contains an unknown document kind: ${row.kind}`);
          }
          if (
            typeof row.canonical_id !== 'string' ||
            row.canonical_id.trim().length === 0 ||
            typeof row.scope !== 'string' ||
            row.scope.trim().length === 0 ||
            typeof row.search_text !== 'string' ||
            !Number.isInteger(row.generation) ||
            row.generation !== watermark.generation
          ) {
            throw new Error('FTS projection row contains malformed identity or generation metadata');
          }
          if (!SHA256_PATTERN.test(row.source_digest) || !SHA256_PATTERN.test(row.entry_digest)) {
            throw new Error('FTS projection row contains a malformed digest');
          }
          if (typeof row.fts_score !== 'number' || !Number.isFinite(row.fts_score)) {
            throw new Error('FTS projection returned a malformed BM25 score');
          }
          const lifecycle =
            row.kind === 'claim'
              ? row.lifecycle === 'active' || row.lifecycle === 'superseded'
                ? row.lifecycle
                : undefined
              : row.lifecycle === ''
                ? undefined
                : undefined;
          if (row.kind === 'claim' && lifecycle === undefined) {
            throw new Error(`FTS projection claim ${row.canonical_id} has an invalid lifecycle`);
          }
          if (row.kind === 'evidence' && row.lifecycle !== '') {
            throw new Error(`FTS projection evidence ${row.canonical_id} has an invalid lifecycle`);
          }
          const base = Object.freeze({
            canonicalId: row.canonical_id,
            kind: row.kind,
            scope: row.scope,
            lifecycle: lifecycle ?? ('' as const),
            sourceDigest: row.source_digest,
            searchText: row.search_text,
          });
          if (documentDigest(base) !== row.entry_digest) {
            throw new Error(`FTS projection row integrity failed for ${row.kind}/${row.canonical_id}`);
          }
          return Object.freeze({
            canonicalId: row.canonical_id,
            kind: row.kind,
            scope: row.scope,
            ...(lifecycle === undefined ? {} : { lifecycle }),
            rank: index + 1,
            score: -row.fts_score,
            entryDigest: row.entry_digest,
            canonicalFingerprint: watermark.canonicalFingerprint,
            generation: watermark.generation,
          });
        }),
      );
    });
  }

  rehydrate(
    events: readonly MemoryEvent[],
    candidates: readonly Fts5SearchCandidate[],
    options: Fts5RehydrateOptions,
  ): readonly RehydratedFts5Candidate[] {
    const scopeChain = snapshotScopeChain(options.scopeChain);
    if (!Array.isArray(candidates)) throw new TypeError('FTS candidates must be an array');
    const candidateSnapshot = Object.freeze(Array.from(candidates, snapshotCandidate));
    if (candidateSnapshot.length > MAX_REHYDRATE_CANDIDATES) {
      throw new RangeError(
        `FTS rehydration cannot exceed ${MAX_REHYDRATE_CANDIDATES} candidates`,
      );
    }
    const claimLifecycle = normalizeClaimLifecycleFilter(options.claimLifecycle);
    const current = snapshot(events);
    const allowedScopes = new Set(scopeChain);
    const evidence = EvidenceProjection.from(current.events);
    const claims = ClaimProjection.from(current.events);
    const rehydrated: RehydratedFts5Candidate[] = [];
    const seen = new Set<string>();

    for (const candidate of candidateSnapshot) {
      if (candidate.kind !== 'evidence' && candidate.kind !== 'claim') {
        throw new Error(`FTS candidate has an unknown kind: ${String(candidate.kind)}`);
      }
      if (
        typeof candidate.canonicalId !== 'string' ||
        candidate.canonicalId.trim().length === 0 ||
        typeof candidate.scope !== 'string' ||
        candidate.scope.trim().length === 0 ||
        !Number.isInteger(candidate.generation) ||
        candidate.generation <= 0 ||
        !Number.isInteger(candidate.rank) ||
        candidate.rank <= 0 ||
        typeof candidate.score !== 'number' ||
        !Number.isFinite(candidate.score) ||
        !SHA256_PATTERN.test(candidate.entryDigest) ||
        !SHA256_PATTERN.test(candidate.canonicalFingerprint)
      ) {
        throw new Error('FTS candidate metadata is malformed');
      }
      const identity = `${candidate.kind}\u0000${candidate.canonicalId}`;
      if (seen.has(identity)) {
        throw new Error(`duplicate FTS candidate: ${candidate.kind}/${candidate.canonicalId}`);
      }
      seen.add(identity);
      if (candidate.canonicalFingerprint !== current.fingerprint) {
        throw new Error(`FTS candidate ${candidate.canonicalId} belongs to a stale projection`);
      }
      if (!allowedScopes.has(candidate.scope)) {
        throw new Error(`FTS candidate scope is not authorized: ${candidate.scope}`);
      }

      if (candidate.kind === 'evidence') {
        if (candidate.lifecycle !== undefined) {
          throw new Error(`FTS evidence candidate has an invalid lifecycle: ${candidate.canonicalId}`);
        }
        const projected = evidence.get(candidate.canonicalId);
        if (
          projected === undefined ||
          !searchableEvidence(projected.record, evidence, this.#allowedSensitivities) ||
          projected.record.scope !== candidate.scope
        ) {
          throw new Error(
            `FTS evidence candidate is no longer canonically searchable: ${candidate.canonicalId}`,
          );
        }
        const base = Object.freeze({
          canonicalId: projected.record.id,
          kind: 'evidence' as const,
          scope: projected.record.scope,
          lifecycle: '' as const,
          sourceDigest: projected.record.artifact.digest,
          searchText: evidenceText(projected.record),
        });
        if (documentDigest(base) !== candidate.entryDigest) {
          throw new Error(`FTS evidence candidate digest mismatch: ${candidate.canonicalId}`);
        }
        rehydrated.push(
          Object.freeze({
            candidate: candidate as Fts5SearchCandidate & { readonly kind: 'evidence' },
            record: projected.record,
          }),
        );
        continue;
      }

      const claim = claims.get(candidate.canonicalId);
      const lifecycle = claims.lifecycle(candidate.canonicalId);
      if (
        claim === undefined ||
        !searchableClaim(claim, lifecycle, evidence, this.#allowedSensitivities) ||
        claim.key.scope !== candidate.scope ||
        (claimLifecycle === 'active-only' && lifecycle !== 'active')
      ) {
        throw new Error(
          `FTS claim candidate is no longer canonically searchable: ${candidate.canonicalId}`,
        );
      }
      const base = Object.freeze({
        canonicalId: claim.id,
        kind: 'claim' as const,
        scope: claim.key.scope,
        lifecycle,
        sourceDigest: contentDigest(claim),
        searchText: claimText(claim, this.#indexClaimValues),
      });
      if (documentDigest(base) !== candidate.entryDigest || candidate.lifecycle !== lifecycle) {
        throw new Error(`FTS claim candidate digest mismatch: ${candidate.canonicalId}`);
      }
      rehydrated.push(
        Object.freeze({
          candidate: candidate as Fts5SearchCandidate & { readonly kind: 'claim' },
          record: claim,
          lifecycle,
        }),
      );
    }
    return Object.freeze(rehydrated);
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    if (this.#ownsDatabase) this.#db.close();
  }
}
