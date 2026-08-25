import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

import { ClaimProjection } from '../claims.js';
import type {
  ClaimLifecycle,
  ClaimRecord,
  EvidenceRecord,
  JsonValue,
  MemoryEvent,
} from '../domain.js';
import { EvidenceProjection } from '../evidence.js';
import { fingerprintMemoryEvents } from '../transitions/verifier.js';
import {
  FTS5_PROJECTION_SCHEMA_VERSION,
  type Fts5ProjectionDatabase,
  type Fts5ProjectionDocumentKind,
  type Fts5ProjectionOptions,
  type Fts5ProjectionSnapshot,
  type Fts5ProjectionStatus,
  type Fts5ProjectionView,
  type Fts5ProjectionWatermark,
  type Fts5RehydrateOptions,
  type Fts5SearchCandidate,
  type Fts5SearchOptions,
  type RehydratedFts5Candidate,
} from './types.js';

const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;
const DEFAULT_MAX_QUERY_TOKENS = 16;
const MAX_QUERY_TOKEN_LENGTH = 96;
const META_ROW_ID = 1;

interface IndexedDocument {
  readonly canonicalId: string;
  readonly kind: Fts5ProjectionDocumentKind;
  readonly scope: string;
  readonly lifecycle: '' | Extract<ClaimLifecycle, 'active' | 'superseded'>;
  readonly sourceDigest: string;
  readonly searchText: string;
  readonly entryDigest: string;
}

interface MetaRow {
  readonly schema_version: number;
  readonly active_generation: number;
  readonly event_count: number;
  readonly last_seq: number;
  readonly canonical_fingerprint: string;
  readonly entry_count: number;
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

function canonicalJson(value: unknown, path = '$', ancestors = new WeakSet<object>()): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      throw new TypeError(`${path} must contain only finite JSON numbers`);
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (ancestors.has(value)) throw new TypeError(`${path} cannot contain a circular reference`);
    ancestors.add(value);
    const encoded = value.map((item, index) => canonicalJson(item, `${path}[${index}]`, ancestors));
    ancestors.delete(value);
    return `[${encoded.join(',')}]`;
  }
  if (typeof value === 'object') {
    if (ancestors.has(value)) throw new TypeError(`${path} cannot contain a circular reference`);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(`${path} must be a plain JSON object`);
    }
    ancestors.add(value);
    const objectValue = value as Record<string, unknown>;
    const encoded = Object.keys(objectValue)
      .sort()
      .map((key) => {
        const item = objectValue[key];
        if (item === undefined) throw new TypeError(`${path}.${key} cannot be undefined`);
        return `${JSON.stringify(key)}:${canonicalJson(item, `${path}.${key}`, ancestors)}`;
      });
    ancestors.delete(value);
    return `{${encoded.join(',')}}`;
  }
  throw new TypeError(`${path} contains a non-JSON value`);
}

function digest(value: unknown): string {
  return `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

function assertNonEmptyUnique(values: readonly string[], label: string): void {
  if (values.length === 0) throw new Error(`${label} requires at least one value`);
  if (values.some((value) => value.trim().length === 0)) {
    throw new Error(`${label} cannot contain empty values`);
  }
  if (new Set(values).size !== values.length) {
    throw new Error(`${label} cannot contain duplicates`);
  }
}

function normalizeView(value: Fts5ProjectionView | undefined): Fts5ProjectionView {
  const view = value ?? 'current';
  if (view !== 'current' && view !== 'historical') {
    throw new Error('FTS projection view must be current or historical');
  }
  return view;
}

function safeMatchQuery(query: string, maxTokens: number): string {
  if (!Number.isInteger(maxTokens) || maxTokens <= 0 || maxTokens > 64) {
    throw new RangeError('maxQueryTokens must be an integer in [1, 64]');
  }
  const tokens = [
    ...new Set(query.normalize('NFKC').toLocaleLowerCase().match(/[\p{L}\p{N}_-]+/gu) ?? []),
  ];
  if (tokens.length === 0) throw new Error('FTS query requires at least one searchable token');
  if (tokens.length > maxTokens) {
    throw new RangeError(`FTS query exceeds the ${maxTokens}-token limit`);
  }
  if (tokens.some((token) => token.length > MAX_QUERY_TOKEN_LENGTH)) {
    throw new RangeError(`FTS query token exceeds ${MAX_QUERY_TOKEN_LENGTH} characters`);
  }
  // Tokens are parser-produced rather than caller-provided MATCH syntax. Quoted prefix terms keep
  // names and identifiers useful while preventing operators, column filters, or NEAR injection.
  return tokens.map((token) => `"${token.replaceAll('"', '""')}"*`).join(' AND ');
}

function snapshot(events: readonly MemoryEvent[]): Fts5ProjectionSnapshot {
  const canonicalEvents = Object.freeze([...events]);
  return Object.freeze({
    events: canonicalEvents,
    fingerprint: fingerprintMemoryEvents(canonicalEvents),
  });
}

function claimDigest(claim: ClaimRecord): string {
  return digest(claim);
}

function documentDigest(document: Omit<IndexedDocument, 'entryDigest'>): string {
  return digest(document);
}

function evidenceText(record: EvidenceRecord): string {
  return [record.preview ?? '', record.kind, ...record.labels].filter((item) => item.length > 0).join('\n');
}

function claimText(claim: ClaimRecord): string {
  return [
    claim.key.subject,
    claim.key.predicate,
    ...claim.tags,
    canonicalJson(claim.value as JsonValue),
  ].join('\n');
}

function searchableEvidence(
  record: EvidenceRecord,
  projection: EvidenceProjection,
  allowedSensitivities: ReadonlySet<EvidenceRecord['sensitivity']>,
): boolean {
  return (
    projection.isAvailable(record.id) &&
    record.preview !== undefined &&
    record.preview.length > 0 &&
    allowedSensitivities.has(record.sensitivity)
  );
}

function searchableClaim(
  claim: ClaimRecord,
  lifecycle: ClaimLifecycle | undefined,
  evidence: EvidenceProjection,
  allowedSensitivities: ReadonlySet<EvidenceRecord['sensitivity']>,
): lifecycle is Extract<ClaimLifecycle, 'active' | 'superseded'> {
  if (lifecycle !== 'active' && lifecycle !== 'superseded') return false;
  if (claim.evidence.length === 0) return claim.authority === 'system-policy' && claim.key.scope === 'global';
  return claim.evidence.every((reference) => {
    const projected = evidence.get(reference.sourceId);
    return (
      projected !== undefined &&
      evidence.validatesReference(reference) &&
      allowedSensitivities.has(projected.record.sensitivity)
    );
  });
}

function buildDocuments(
  events: readonly MemoryEvent[],
  allowedSensitivities: ReadonlySet<EvidenceRecord['sensitivity']>,
): readonly IndexedDocument[] {
  const evidence = EvidenceProjection.from(events);
  const claims = ClaimProjection.from(events);
  const documents: IndexedDocument[] = [];

  for (const projected of evidence.all()) {
    const record = projected.record;
    if (!searchableEvidence(record, evidence, allowedSensitivities)) continue;
    const base = Object.freeze({
      canonicalId: record.id,
      kind: 'evidence' as const,
      scope: record.scope,
      lifecycle: '' as const,
      sourceDigest: record.artifact.digest,
      searchText: evidenceText(record),
    });
    documents.push(Object.freeze({ ...base, entryDigest: documentDigest(base) }));
  }

  const seenClaimIds = new Set<string>();
  for (const event of events) {
    if (event.type !== 'claim.asserted') continue;
    const claim = event.data.claim;
    if (seenClaimIds.has(claim.id)) continue;
    seenClaimIds.add(claim.id);
    const lifecycle = claims.lifecycle(claim.id);
    if (!searchableClaim(claim, lifecycle, evidence, allowedSensitivities)) continue;
    const base = Object.freeze({
      canonicalId: claim.id,
      kind: 'claim' as const,
      scope: claim.key.scope,
      lifecycle,
      sourceDigest: claimDigest(claim),
      searchText: claimText(claim),
    });
    documents.push(Object.freeze({ ...base, entryDigest: documentDigest(base) }));
  }

  return Object.freeze(
    documents.sort(
      (left, right) => left.kind.localeCompare(right.kind) || left.canonicalId.localeCompare(right.canonicalId),
    ),
  );
}

function rowAsMeta(value: unknown): MetaRow | undefined {
  if (value === undefined) return undefined;
  const row = value as Partial<MetaRow>;
  if (
    typeof row.schema_version !== 'number' ||
    !Number.isInteger(row.schema_version) ||
    typeof row.active_generation !== 'number' ||
    !Number.isInteger(row.active_generation) ||
    typeof row.event_count !== 'number' ||
    !Number.isInteger(row.event_count) ||
    typeof row.last_seq !== 'number' ||
    !Number.isInteger(row.last_seq) ||
    typeof row.canonical_fingerprint !== 'string' ||
    typeof row.entry_count !== 'number' ||
    !Number.isInteger(row.entry_count) ||
    typeof row.rebuilt_at !== 'number' ||
    !Number.isInteger(row.rebuilt_at)
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
  return Object.freeze({
    schemaVersion: FTS5_PROJECTION_SCHEMA_VERSION,
    generation: row.active_generation,
    eventCount: row.event_count,
    lastSeq: row.last_seq,
    canonicalFingerprint: row.canonical_fingerprint,
    entryCount: row.entry_count,
    rebuiltAt: row.rebuilt_at,
  });
}

/**
 * Rebuildable SQLite FTS5 projection. The canonical ledger remains the only source of truth:
 * search emits ids/digests only, freshness is checked against the exact ledger fingerprint, and
 * every hit must be rehydrated from canonical projections before use.
 */
export class SqliteFts5Projection {
  readonly #db: Fts5ProjectionDatabase;
  readonly #ownsDatabase: boolean;
  readonly #allowedSensitivities: ReadonlySet<EvidenceRecord['sensitivity']>;
  readonly #faultInjector: Fts5ProjectionOptions['faultInjector'] | undefined;
  #closed = false;

  constructor(
    database: Fts5ProjectionDatabase,
    options: Fts5ProjectionOptions = {},
    ownsDatabase = false,
  ) {
    this.#db = database;
    this.#ownsDatabase = ownsDatabase;
    const sensitivities = options.searchableSensitivities ?? ['public', 'internal'];
    if (sensitivities.length === 0 || new Set(sensitivities).size !== sensitivities.length) {
      throw new Error('searchableSensitivities must be non-empty and unique');
    }
    for (const sensitivity of sensitivities) {
      if (!['public', 'internal', 'personal', 'sensitive', 'secret'].includes(sensitivity)) {
        throw new Error(`unknown evidence sensitivity: ${String(sensitivity)}`);
      }
    }
    this.#allowedSensitivities = new Set(sensitivities);
    this.#faultInjector = options.faultInjector;
    this.#initialize(options.busyTimeoutMs ?? 5_000);
  }

  static open(filename: string, options: Fts5ProjectionOptions = {}): SqliteFts5Projection {
    if (filename.trim().length === 0) throw new Error('FTS projection filename cannot be empty');
    const database = new DatabaseSync(filename) as unknown as Fts5ProjectionDatabase;
    return new SqliteFts5Projection(database, options, true);
  }

  #initialize(busyTimeoutMs: number): void {
    if (!Number.isInteger(busyTimeoutMs) || busyTimeoutMs < 0 || busyTimeoutMs > 60_000) {
      throw new RangeError('busyTimeoutMs must be an integer in [0, 60000]');
    }
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
                  canonical_fingerprint, entry_count, rebuilt_at
             FROM cl_fts_meta WHERE singleton = ?`,
        )
        .get(META_ROW_ID),
    );
    return row === undefined ? undefined : watermarkFromRow(row);
  }

  watermark(): Fts5ProjectionWatermark | undefined {
    return this.#meta();
  }

  status(events: readonly MemoryEvent[]): Fts5ProjectionStatus {
    const current = snapshot(events);
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
    const fresh =
      watermark.canonicalFingerprint === current.fingerprint &&
      watermark.eventCount === current.events.length &&
      watermark.lastSeq === (current.events.at(-1)?.seq ?? 0);
    return Object.freeze({
      initialized: true,
      fresh,
      watermark,
      canonicalFingerprint: current.fingerprint,
      eventCount: current.events.length,
      reason: fresh ? 'projection watermark matches canonical memory' : 'projection watermark is stale',
    });
  }

  rebuild(events: readonly MemoryEvent[], rebuiltAt = Date.now()): Fts5ProjectionWatermark {
    this.#assertOpen();
    if (!Number.isInteger(rebuiltAt) || rebuiltAt < 0) {
      throw new RangeError('rebuiltAt must be a non-negative integer epoch millisecond value');
    }
    const current = snapshot(events);
    const documents = buildDocuments(current.events, this.#allowedSensitivities);
    const existing = this.#meta();
    const generation = (existing?.generation ?? 0) + 1;

    this.#db.exec('BEGIN IMMEDIATE');
    try {
      this.#faultInjector?.('after-begin');
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
            canonical_fingerprint, entry_count, rebuilt_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(singleton) DO UPDATE SET
            schema_version = excluded.schema_version,
            active_generation = excluded.active_generation,
            event_count = excluded.event_count,
            last_seq = excluded.last_seq,
            canonical_fingerprint = excluded.canonical_fingerprint,
            entry_count = excluded.entry_count,
            rebuilt_at = excluded.rebuilt_at
        `)
        .run(
          META_ROW_ID,
          FTS5_PROJECTION_SCHEMA_VERSION,
          generation,
          current.events.length,
          current.events.at(-1)?.seq ?? 0,
          current.fingerprint,
          documents.length,
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
    assertNonEmptyUnique(options.scopeChain, 'scopeChain');
    const view = normalizeView(options.view);
    const limit = options.limit ?? DEFAULT_LIMIT;
    if (!Number.isInteger(limit) || limit <= 0 || limit > MAX_LIMIT) {
      throw new RangeError(`FTS result limit must be an integer in [1, ${MAX_LIMIT}]`);
    }
    const match = safeMatchQuery(query, options.maxQueryTokens ?? DEFAULT_MAX_QUERY_TOKENS);
    const state = this.status(events);
    if (!state.fresh || state.watermark === undefined) {
      throw new Error(`FTS projection is stale: ${state.reason}`);
    }
    const watermark = state.watermark;
    const scopePlaceholders = options.scopeChain.map(() => '?').join(', ');
    const lifecycleClause = view === 'current' ? "AND (kind <> 'claim' OR lifecycle = 'active')" : '';
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
      .all(match, watermark.generation, ...options.scopeChain, limit) as unknown as readonly SearchRow[];

    const candidates: Fts5SearchCandidate[] = [];
    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index];
      if (row === undefined) continue;
      if (row.kind !== 'evidence' && row.kind !== 'claim') {
        throw new Error(`FTS projection contains an unknown document kind: ${row.kind}`);
      }
      if (row.generation !== watermark.generation) {
        throw new Error('FTS projection returned a row from an inactive generation');
      }
      if (!SHA256_PATTERN.test(row.source_digest) || !SHA256_PATTERN.test(row.entry_digest)) {
        throw new Error('FTS projection row contains a malformed digest');
      }
      const lifecycle =
        row.kind === 'claim'
          ? row.lifecycle === 'active' || row.lifecycle === 'superseded'
            ? row.lifecycle
            : undefined
          : undefined;
      if (row.kind === 'claim' && lifecycle === undefined) {
        throw new Error(`FTS projection claim ${row.canonical_id} has an invalid lifecycle`);
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
      candidates.push(
        Object.freeze({
          canonicalId: row.canonical_id,
          kind: row.kind,
          scope: row.scope,
          ...(lifecycle === undefined ? {} : { lifecycle }),
          rank: index + 1,
          score: Number.isFinite(row.fts_score) ? -row.fts_score : 0,
          entryDigest: row.entry_digest,
          canonicalFingerprint: watermark.canonicalFingerprint,
          generation: watermark.generation,
        }),
      );
    }
    return Object.freeze(candidates);
  }

  rehydrate(
    events: readonly MemoryEvent[],
    candidates: readonly Fts5SearchCandidate[],
    options: Fts5RehydrateOptions,
  ): readonly RehydratedFts5Candidate[] {
    this.#assertOpen();
    assertNonEmptyUnique(options.scopeChain, 'scopeChain');
    const view = normalizeView(options.view);
    const state = this.status(events);
    if (!state.fresh || state.watermark === undefined) {
      throw new Error(`FTS projection is stale: ${state.reason}`);
    }
    const watermark = state.watermark;
    const allowedScopes = new Set(options.scopeChain);
    const evidence = EvidenceProjection.from(events);
    const claims = ClaimProjection.from(events);
    const rehydrated: RehydratedFts5Candidate[] = [];
    const seen = new Set<string>();

    for (const candidate of candidates) {
      const identity = `${candidate.kind}\u0000${candidate.canonicalId}`;
      if (seen.has(identity)) throw new Error(`duplicate FTS candidate: ${candidate.kind}/${candidate.canonicalId}`);
      seen.add(identity);
      if (
        candidate.canonicalFingerprint !== watermark.canonicalFingerprint ||
        candidate.generation !== watermark.generation
      ) {
        throw new Error(`FTS candidate ${candidate.canonicalId} belongs to a stale projection`);
      }
      if (!allowedScopes.has(candidate.scope)) {
        throw new Error(`FTS candidate scope is not authorized: ${candidate.scope}`);
      }

      if (candidate.kind === 'evidence') {
        const projected = evidence.get(candidate.canonicalId);
        if (
          projected === undefined ||
          !searchableEvidence(projected.record, evidence, this.#allowedSensitivities) ||
          projected.record.scope !== candidate.scope
        ) {
          throw new Error(`FTS evidence candidate is no longer canonically searchable: ${candidate.canonicalId}`);
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
        (view === 'current' && lifecycle !== 'active')
      ) {
        throw new Error(`FTS claim candidate is no longer canonically searchable: ${candidate.canonicalId}`);
      }
      const base = Object.freeze({
        canonicalId: claim.id,
        kind: 'claim' as const,
        scope: claim.key.scope,
        lifecycle,
        sourceDigest: claimDigest(claim),
        searchText: claimText(claim),
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
