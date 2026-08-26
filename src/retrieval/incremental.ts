import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

import { ClaimProjection } from '../claims.js';
import type { ClaimLifecycle, ClaimRecord, EvidenceRecord, MemoryEvent } from '../domain.js';
import { EvidenceProjection } from '../evidence.js';
import { MemoryKernel } from '../kernel.js';
import { fingerprintMemoryEvents } from '../transitions/verifier.js';
import {
  snapshotScopeChain,
  buildDocuments,
  documentDigest,
  normalizeClaimLifecycleFilter,
  safeMatchQuery,
  SHA256_PATTERN,
} from './canonical.js';

const SCHEMA_VERSION = 1;
const DEFAULT_BUCKET_COUNT = 256;
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;
const MAX_CANDIDATES = 100;
const DEFAULT_SENSITIVITIES = Object.freeze(['public', 'internal'] as const);

export type IncrementalProjectionFaultPoint =
  | 'after-begin'
  | 'after-prefix'
  | 'after-documents'
  | 'after-dependencies'
  | 'after-buckets'
  | 'after-checkpoint'
  | 'after-search-verify'
  | 'before-commit';

export interface IncrementalFts5Options {
  readonly database?: string;
  readonly busyTimeoutMs?: number;
  readonly bucketCount?: number;
  readonly searchableSensitivities?: readonly EvidenceRecord['sensitivity'][];
  readonly indexClaimValues?: boolean;
  readonly faultInjector?: (point: IncrementalProjectionFaultPoint) => void;
  /** Test/host clock. Publication remains strictly monotonic even when this clock regresses. */
  readonly clock?: () => number;
}

export interface IncrementalProjectionCheckpoint {
  readonly generation: number;
  readonly previousDigest: string;
  readonly checkpointDigest: string;
  readonly baseEventCount: number;
  readonly eventCount: number;
  readonly appendFromSeq: number;
  readonly appendToSeq: number;
  readonly appendDigest: string;
  readonly canonicalFingerprint: string;
  readonly lastSeq: number;
  readonly lastRecordedAt: number;
  readonly documentCount: number;
  readonly dependencyCount: number;
  readonly documentManifestDigest: string;
  readonly dependencyManifestDigest: string;
  readonly configDigest: string;
  readonly createdAt: number;
}

export interface IncrementalProjectionStatus {
  readonly initialized: boolean;
  readonly fresh: boolean;
  readonly reason: string;
  readonly canonicalFingerprint: string;
  readonly eventCount: number;
  readonly checkpoint?: IncrementalProjectionCheckpoint;
}

export interface IncrementalProjectionAudit {
  readonly ok: boolean;
  readonly errors: readonly string[];
  readonly checkpoint?: IncrementalProjectionCheckpoint;
}

export interface IncrementalSearchOptions {
  readonly scopeChain: readonly string[];
  readonly limit?: number;
  readonly maxQueryTokens?: number;
  readonly claimLifecycle?: 'all' | 'active-only';
}

export interface IncrementalSearchCandidate {
  readonly canonicalId: string;
  readonly kind: 'evidence' | 'claim';
  readonly scope: string;
  readonly lifecycle?: Extract<ClaimLifecycle, 'active' | 'superseded'>;
  readonly rank: number;
  readonly score: number;
  readonly entryDigest: string;
  readonly canonicalFingerprint: string;
  readonly generation: number;
}

export interface IncrementalRehydratedCandidate {
  readonly candidate: IncrementalSearchCandidate;
  readonly evidence?: EvidenceRecord;
  readonly claim?: ClaimRecord;
}

interface CanonicalSnapshot {
  readonly events: readonly MemoryEvent[];
  readonly fingerprint: string;
  readonly eventDigests: readonly EventDigest[];
}

interface EventDigest {
  readonly seq: number;
  readonly eventId: string;
  readonly recordedAt: number;
  readonly digest: string;
}

interface ProjectionDocument {
  readonly canonicalId: string;
  readonly kind: 'evidence' | 'claim';
  readonly scope: string;
  readonly lifecycle?: Extract<ClaimLifecycle, 'active' | 'superseded'>;
  readonly sourceDigest: string;
  readonly searchText: string;
  readonly entryDigest: string;
}

interface Dependency {
  readonly evidenceId: string;
  readonly claimId: string;
}

interface BucketRecord {
  readonly bucket: number;
  readonly itemCount: number;
  readonly digest: string;
}

interface StoredBucketRecord extends BucketRecord {
  readonly generation: number;
}

interface MetaRow {
  readonly schema_version: number;
  readonly config_digest: string;
  readonly generation: number;
  readonly event_count: number;
  readonly last_seq: number;
  readonly last_recorded_at: number;
  readonly canonical_fingerprint: string;
  readonly active_checkpoint_digest: string;
  readonly document_count: number;
  readonly dependency_count: number;
  readonly document_manifest_digest: string;
  readonly dependency_manifest_digest: string;
  readonly updated_at: number;
}

interface CheckpointRow {
  readonly generation: number;
  readonly previous_digest: string;
  readonly checkpoint_digest: string;
  readonly base_event_count: number;
  readonly event_count: number;
  readonly append_from_seq: number;
  readonly append_to_seq: number;
  readonly append_digest: string;
  readonly canonical_fingerprint: string;
  readonly last_seq: number;
  readonly last_recorded_at: number;
  readonly document_count: number;
  readonly dependency_count: number;
  readonly document_manifest_digest: string;
  readonly dependency_manifest_digest: string;
  readonly config_digest: string;
  readonly created_at: number;
}

interface StoredDocumentRow {
  readonly canonical_id: string;
  readonly kind: string;
  readonly scope: string;
  readonly lifecycle: string;
  readonly source_digest: string;
  readonly search_text: string;
  readonly entry_digest: string;
  readonly bucket: number;
  readonly generation: number;
}

interface StoredDependencyRow {
  readonly evidence_id: string;
  readonly claim_id: string;
  readonly bucket: number;
  readonly generation: number;
}

interface StoredFtsRow {
  readonly canonical_id: string;
  readonly kind: string;
  readonly scope: string;
  readonly lifecycle: string;
  readonly entry_digest: string;
  readonly generation: number;
  readonly search_text: string;
}

interface SearchRow {
  readonly canonical_id: string;
  readonly kind: string;
  readonly scope: string;
  readonly lifecycle: string;
  readonly entry_digest: string;
  readonly generation: number;
  readonly search_text: string;
  readonly fts_score: number;
}

function stableJson(value: unknown, path = '$', ancestors = new WeakSet<object>()): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      throw new TypeError(`${path} contains a non-canonical number`);
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (ancestors.has(value)) throw new TypeError(`${path} contains a circular reference`);
    ancestors.add(value);
    const items = value.map((item, index) => stableJson(item, `${path}[${index}]`, ancestors));
    ancestors.delete(value);
    return `[${items.join(',')}]`;
  }
  if (typeof value === 'object') {
    if (ancestors.has(value)) throw new TypeError(`${path} contains a circular reference`);
    ancestors.add(value);
    const objectValue = value as Record<string, unknown>;
    const entries = Object.keys(objectValue)
      .sort()
      .map((key) => {
        const item = objectValue[key];
        if (item === undefined) throw new TypeError(`${path}.${key} cannot be undefined`);
        return `${JSON.stringify(key)}:${stableJson(item, `${path}.${key}`, ancestors)}`;
      });
    ancestors.delete(value);
    return `{${entries.join(',')}}`;
  }
  throw new TypeError(`${path} contains a non-JSON value`);
}

function digest(value: unknown): string {
  return `sha256:${createHash('sha256').update(stableJson(value)).digest('hex')}`;
}

function validateDigest(value: string, label: string): void {
  if (!SHA256_PATTERN.test(value)) throw new Error(`${label} is not a SHA-256 content address`);
}

function snapshot(events: readonly MemoryEvent[]): CanonicalSnapshot {
  const canonicalEvents = MemoryKernel.from(events).events();
  return Object.freeze({
    events: canonicalEvents,
    fingerprint: fingerprintMemoryEvents(canonicalEvents),
    eventDigests: Object.freeze(
      canonicalEvents.map((event) =>
        Object.freeze({
          seq: event.seq,
          eventId: event.id,
          recordedAt: event.recordedAt,
          digest: digest({ domain: 'cl-event-v1', event }),
        }),
      ),
    ),
  });
}

function docKey(kind: ProjectionDocument['kind'], canonicalId: string): string {
  return `${kind}\u0000${canonicalId}`;
}

function normalizeDocument(value: unknown): ProjectionDocument {
  const document = value as Partial<ProjectionDocument>;
  if (document.kind !== 'evidence' && document.kind !== 'claim') {
    throw new Error('canonical document has an unknown kind');
  }
  if (
    typeof document.canonicalId !== 'string' ||
    document.canonicalId.trim().length === 0 ||
    typeof document.scope !== 'string' ||
    document.scope.trim().length === 0 ||
    typeof document.sourceDigest !== 'string' ||
    typeof document.searchText !== 'string'
  ) {
    throw new Error('canonical document has malformed identity, scope, digest, or text');
  }
  validateDigest(document.sourceDigest, 'canonical document source digest');
  const lifecycle =
    document.kind === 'claim'
      ? document.lifecycle === 'active' || document.lifecycle === 'superseded'
        ? document.lifecycle
        : undefined
      : undefined;
  if (document.kind === 'claim' && lifecycle === undefined) {
    throw new Error(`claim document ${document.canonicalId} has an invalid lifecycle`);
  }
  const base = Object.freeze({
    canonicalId: document.canonicalId,
    kind: document.kind,
    scope: document.scope,
    lifecycle: lifecycle ?? ('' as const),
    sourceDigest: document.sourceDigest,
    searchText: document.searchText,
  });
  return Object.freeze({
    canonicalId: base.canonicalId,
    kind: base.kind,
    scope: base.scope,
    ...(lifecycle === undefined ? {} : { lifecycle }),
    sourceDigest: base.sourceDigest,
    searchText: base.searchText,
    entryDigest: documentDigest(base),
  });
}

function documentsFor(
  current: CanonicalSnapshot,
  sensitivities: ReadonlySet<EvidenceRecord['sensitivity']>,
  includeClaimValues: boolean,
): readonly ProjectionDocument[] {
  return Object.freeze(
    (buildDocuments(current.events, sensitivities, includeClaimValues) as readonly unknown[])
      .map(normalizeDocument)
      .sort(
        (left, right) =>
          left.kind.localeCompare(right.kind) || left.canonicalId.localeCompare(right.canonicalId),
      ),
  );
}

function dependenciesFor(
  events: readonly MemoryEvent[],
  documents: readonly ProjectionDocument[],
): readonly Dependency[] {
  const indexedEvidence = new Set(
    documents.filter((item) => item.kind === 'evidence').map((item) => item.canonicalId),
  );
  const indexedClaims = new Set(
    documents.filter((item) => item.kind === 'claim').map((item) => item.canonicalId),
  );
  const claims = new Map<string, ClaimRecord>();
  for (const event of events) {
    if (event.type === 'claim.asserted') claims.set(event.data.claim.id, event.data.claim);
  }
  const dependencies: Dependency[] = [];
  for (const claimId of [...indexedClaims].sort()) {
    const claim = claims.get(claimId);
    if (claim === undefined) throw new Error(`indexed claim ${claimId} is absent from canonical events`);
    for (const reference of claim.evidence) {
      // The plaintext reverse index follows the exact same privacy projection as searchable docs.
      if (indexedEvidence.has(reference.sourceId)) {
        dependencies.push(Object.freeze({ evidenceId: reference.sourceId, claimId }));
      }
    }
  }
  return Object.freeze(
    dependencies.sort(
      (left, right) =>
        left.evidenceId.localeCompare(right.evidenceId) || left.claimId.localeCompare(right.claimId),
    ),
  );
}

function bucketFor(identity: string, bucketCount: number): number {
  const hexadecimal = createHash('sha256').update(identity).digest('hex').slice(0, 12);
  return Number.parseInt(hexadecimal, 16) % bucketCount;
}

function documentBuckets(
  documents: readonly ProjectionDocument[],
  bucketCount: number,
): readonly BucketRecord[] {
  const grouped = Array.from({ length: bucketCount }, () => [] as ProjectionDocument[]);
  for (const document of documents) {
    grouped[bucketFor(docKey(document.kind, document.canonicalId), bucketCount)]?.push(document);
  }
  return Object.freeze(
    grouped.map((items, bucket) => {
      const members = items
        .map((item) => ({ key: docKey(item.kind, item.canonicalId), digest: item.entryDigest }))
        .sort((left, right) => left.key.localeCompare(right.key));
      return Object.freeze({
        bucket,
        itemCount: members.length,
        digest: digest({ domain: 'cl-document-bucket-v1', bucket, members }),
      });
    }),
  );
}

function dependencyBuckets(
  dependencies: readonly Dependency[],
  bucketCount: number,
): readonly BucketRecord[] {
  const grouped = Array.from({ length: bucketCount }, () => [] as Dependency[]);
  for (const dependency of dependencies) {
    const key = `${dependency.evidenceId}\u0000${dependency.claimId}`;
    grouped[bucketFor(key, bucketCount)]?.push(dependency);
  }
  return Object.freeze(
    grouped.map((items, bucket) => {
      const members = items
        .map((item) => `${item.evidenceId}\u0000${item.claimId}`)
        .sort();
      return Object.freeze({
        bucket,
        itemCount: members.length,
        digest: digest({ domain: 'cl-dependency-bucket-v1', bucket, members }),
      });
    }),
  );
}

function rootManifest(domain: string, buckets: readonly BucketRecord[]): string {
  return digest({
    domain,
    buckets: buckets.map((bucket) => ({
      bucket: bucket.bucket,
      itemCount: bucket.itemCount,
      digest: bucket.digest,
    })),
  });
}

function appendDigest(eventDigests: readonly EventDigest[]): string {
  return digest({
    domain: 'cl-incremental-append-v1',
    events: eventDigests.map((event) => ({ seq: event.seq, eventId: event.eventId, digest: event.digest })),
  });
}

function checkpointPayload(
  checkpoint: Omit<IncrementalProjectionCheckpoint, 'checkpointDigest'>,
): unknown {
  return { domain: 'cl-incremental-checkpoint-v1', ...checkpoint };
}

function assertSafeInteger(value: number, label: string, minimum = 0): void {
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new Error(`${label} must be a safe integer >= ${minimum}`);
  }
}

function snapshotCandidate(candidate: IncrementalSearchCandidate): IncrementalSearchCandidate {
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

function checkpointFromRow(row: CheckpointRow): IncrementalProjectionCheckpoint {
  const checkpoint = Object.freeze({
    generation: row.generation,
    previousDigest: row.previous_digest,
    checkpointDigest: row.checkpoint_digest,
    baseEventCount: row.base_event_count,
    eventCount: row.event_count,
    appendFromSeq: row.append_from_seq,
    appendToSeq: row.append_to_seq,
    appendDigest: row.append_digest,
    canonicalFingerprint: row.canonical_fingerprint,
    lastSeq: row.last_seq,
    lastRecordedAt: row.last_recorded_at,
    documentCount: row.document_count,
    dependencyCount: row.dependency_count,
    documentManifestDigest: row.document_manifest_digest,
    dependencyManifestDigest: row.dependency_manifest_digest,
    configDigest: row.config_digest,
    createdAt: row.created_at,
  });
  assertSafeInteger(checkpoint.generation, 'checkpoint generation', 1);
  assertSafeInteger(checkpoint.baseEventCount, 'checkpoint baseEventCount');
  assertSafeInteger(checkpoint.eventCount, 'checkpoint eventCount');
  assertSafeInteger(checkpoint.appendFromSeq, 'checkpoint appendFromSeq', 1);
  assertSafeInteger(checkpoint.appendToSeq, 'checkpoint appendToSeq');
  assertSafeInteger(checkpoint.lastSeq, 'checkpoint lastSeq');
  assertSafeInteger(checkpoint.documentCount, 'checkpoint documentCount');
  assertSafeInteger(checkpoint.dependencyCount, 'checkpoint dependencyCount');
  assertSafeInteger(checkpoint.createdAt, 'checkpoint createdAt');
  if (!Number.isFinite(checkpoint.lastRecordedAt)) {
    throw new Error('checkpoint lastRecordedAt must be finite');
  }
  if (checkpoint.eventCount < checkpoint.baseEventCount) {
    throw new Error('checkpoint eventCount cannot precede baseEventCount');
  }
  if (checkpoint.lastSeq !== checkpoint.eventCount) {
    throw new Error('checkpoint lastSeq must equal eventCount for a contiguous ledger');
  }
  const expectedFrom =
    checkpoint.eventCount === checkpoint.baseEventCount
      ? checkpoint.eventCount + 1
      : checkpoint.baseEventCount + 1;
  if (
    checkpoint.appendFromSeq !== expectedFrom ||
    checkpoint.appendToSeq !== checkpoint.eventCount
  ) {
    throw new Error('checkpoint append sequence range is malformed');
  }
  validateDigest(checkpoint.checkpointDigest, 'checkpoint digest');
  validateDigest(checkpoint.previousDigest, 'checkpoint predecessor digest');
  validateDigest(checkpoint.appendDigest, 'checkpoint append digest');
  validateDigest(checkpoint.canonicalFingerprint, 'checkpoint canonical fingerprint');
  validateDigest(checkpoint.documentManifestDigest, 'checkpoint document manifest');
  validateDigest(checkpoint.dependencyManifestDigest, 'checkpoint dependency manifest');
  validateDigest(checkpoint.configDigest, 'checkpoint config digest');
  return checkpoint;
}

function verifyCheckpointDigest(checkpoint: IncrementalProjectionCheckpoint, label: string): void {
  const { checkpointDigest: _ignored, ...unsigned } = checkpoint;
  if (digest(checkpointPayload(unsigned)) !== checkpoint.checkpointDigest) {
    throw new Error(`${label} digest is invalid`);
  }
}

/**
 * Incremental document publication for the lexical projection.
 *
 * The implementation intentionally keeps canonical replay and fingerprinting on the correctness
 * path. `update()` changes only rows whose canonical projection changed and publishes a hash-chained
 * checkpoint atomically. Startup recovery and full audit are still O(N); no bounded-lifetime claim
 * is implied by this adapter.
 */
export class SqliteIncrementalFts5Projection {
  readonly #db: DatabaseSync;
  readonly #bucketCount: number;
  readonly #sensitivities: ReadonlySet<EvidenceRecord['sensitivity']>;
  readonly #indexClaimValues: boolean;
  readonly #configDigest: string;
  readonly #faultInjector: IncrementalFts5Options['faultInjector'];
  readonly #clock: () => number;
  #closed = false;

  constructor(options: IncrementalFts5Options = {}) {
    const database = options.database;
    const busyTimeoutMs = options.busyTimeoutMs;
    const suppliedBucketCount = options.bucketCount;
    const suppliedSensitivities = options.searchableSensitivities;
    const indexClaimValues = options.indexClaimValues;
    const faultInjector = options.faultInjector;
    const clock = options.clock;

    const bucketCount = suppliedBucketCount ?? DEFAULT_BUCKET_COUNT;
    if (!Number.isInteger(bucketCount) || bucketCount < 16 || bucketCount > 4_096) {
      throw new RangeError('bucketCount must be an integer in [16, 4096]');
    }
    if (indexClaimValues !== undefined && typeof indexClaimValues !== 'boolean') {
      throw new TypeError('indexClaimValues must be boolean');
    }
    const sensitivities = Object.freeze([
      ...(suppliedSensitivities ?? DEFAULT_SENSITIVITIES),
    ]);
    if (sensitivities.length === 0) {
      throw new Error('searchableSensitivities requires at least one value');
    }
    if (new Set(sensitivities).size !== sensitivities.length) {
      throw new Error('searchableSensitivities cannot contain duplicates');
    }
    const allowed = new Set<EvidenceRecord['sensitivity']>();
    for (const sensitivity of sensitivities) {
      if (!['public', 'internal', 'personal', 'sensitive', 'secret'].includes(sensitivity)) {
        throw new Error(`unknown evidence sensitivity: ${String(sensitivity)}`);
      }
      allowed.add(sensitivity);
    }
    if (faultInjector !== undefined && typeof faultInjector !== 'function') {
      throw new TypeError('faultInjector must be a function');
    }
    if (clock !== undefined && typeof clock !== 'function') {
      throw new TypeError('clock must be a function');
    }
    if (database !== undefined && (typeof database !== 'string' || database.trim().length === 0)) {
      throw new TypeError('database must be a non-empty string');
    }

    this.#bucketCount = bucketCount;
    this.#sensitivities = allowed;
    this.#indexClaimValues = indexClaimValues ?? false;
    this.#faultInjector = faultInjector;
    this.#clock = clock ?? Date.now;
    this.#configDigest = digest({
      domain: 'cl-incremental-config-v1',
      schemaVersion: SCHEMA_VERSION,
      bucketCount,
      searchableSensitivities: [...allowed].sort(),
      indexClaimValues: this.#indexClaimValues,
    });
    const timeout = busyTimeoutMs ?? 5_000;
    if (!Number.isInteger(timeout) || timeout < 0 || timeout > 60_000) {
      throw new RangeError('busyTimeoutMs must be an integer in [0, 60000]');
    }
    this.#db = new DatabaseSync(database ?? ':memory:');
    this.#db.exec('PRAGMA trusted_schema = OFF');
    this.#db.exec(`PRAGMA busy_timeout = ${timeout}`);
    this.#db.exec('PRAGMA journal_mode = WAL');
    this.#db.exec('PRAGMA synchronous = FULL');
    this.#db.exec('PRAGMA foreign_keys = ON');
    this.#initializeSchema();
  }

  #assertOpen(): void {
    if (this.#closed) throw new Error('incremental FTS5 projection is closed');
  }

  #inject(point: IncrementalProjectionFaultPoint): void {
    this.#faultInjector?.(point);
  }

  #transaction<T>(mode: 'read' | 'write', operation: () => T): T {
    this.#assertOpen();
    this.#db.exec(mode === 'write' ? 'BEGIN IMMEDIATE' : 'BEGIN');
    try {
      const result = operation();
      this.#db.exec('COMMIT');
      return result;
    } catch (error) {
      try {
        this.#db.exec('ROLLBACK');
      } catch {
        // Preserve the original failure. Reopen/rebuild is the recovery boundary.
      }
      throw error;
    }
  }

  #initializeSchema(): void {
    const expected = new Set([
      'cl_incremental_meta',
      'cl_incremental_event_digests',
      'cl_incremental_documents',
      'cl_incremental_dependencies',
      'cl_incremental_buckets',
      'cl_incremental_checkpoints',
      'cl_incremental_fts',
    ]);
    const existing = this.#db
      .prepare(`SELECT name FROM sqlite_master WHERE name GLOB 'cl_incremental_*'`)
      .all() as unknown as readonly { readonly name: string }[];
    const names = new Set(existing.map((row) => row.name));
    const requiredColumns = new Map<string, readonly string[]>([
      [
        'cl_incremental_meta',
        [
          'id',
          'schema_version',
          'config_digest',
          'generation',
          'event_count',
          'last_seq',
          'last_recorded_at',
          'canonical_fingerprint',
          'active_checkpoint_digest',
          'document_count',
          'dependency_count',
          'document_manifest_digest',
          'dependency_manifest_digest',
          'updated_at',
        ],
      ],
      [
        'cl_incremental_event_digests',
        ['seq', 'event_id', 'recorded_at', 'event_digest'],
      ],
      [
        'cl_incremental_documents',
        [
          'canonical_id',
          'kind',
          'scope',
          'lifecycle',
          'source_digest',
          'search_text',
          'entry_digest',
          'bucket',
          'generation',
        ],
      ],
      [
        'cl_incremental_dependencies',
        ['evidence_id', 'claim_id', 'bucket', 'generation'],
      ],
      [
        'cl_incremental_buckets',
        ['manifest_kind', 'bucket', 'item_count', 'bucket_digest', 'generation'],
      ],
      [
        'cl_incremental_checkpoints',
        [
          'generation',
          'previous_digest',
          'checkpoint_digest',
          'base_event_count',
          'event_count',
          'append_from_seq',
          'append_to_seq',
          'append_digest',
          'canonical_fingerprint',
          'last_seq',
          'last_recorded_at',
          'document_count',
          'dependency_count',
          'document_manifest_digest',
          'dependency_manifest_digest',
          'config_digest',
          'created_at',
        ],
      ],
      [
        'cl_incremental_fts',
        [
          'canonical_id',
          'kind',
          'scope',
          'lifecycle',
          'entry_digest',
          'generation',
          'search_text',
        ],
      ],
    ]);
    const missingTable = names.size > 0 && [...expected].some((name) => !names.has(name));
    const incompatibleTable =
      names.size > 0 &&
      !missingTable &&
      [...requiredColumns].some(([table, columns]) => {
        const rows = this.#db
          .prepare(`PRAGMA table_info(${table})`)
          .all() as unknown as readonly { readonly name: string }[];
        const present = new Set(rows.map((row) => row.name));
        return columns.some((column) => !present.has(column));
      });
    if (missingTable || incompatibleTable) {
      this.#dropSchema();
    }
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS cl_incremental_meta (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        schema_version INTEGER NOT NULL,
        config_digest TEXT NOT NULL,
        generation INTEGER NOT NULL,
        event_count INTEGER NOT NULL,
        last_seq INTEGER NOT NULL,
        last_recorded_at REAL NOT NULL,
        canonical_fingerprint TEXT NOT NULL,
        active_checkpoint_digest TEXT NOT NULL,
        document_count INTEGER NOT NULL,
        dependency_count INTEGER NOT NULL,
        document_manifest_digest TEXT NOT NULL,
        dependency_manifest_digest TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS cl_incremental_event_digests (
        seq INTEGER PRIMARY KEY,
        event_id TEXT NOT NULL UNIQUE,
        recorded_at REAL NOT NULL,
        event_digest TEXT NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS cl_incremental_documents (
        canonical_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        scope TEXT NOT NULL,
        lifecycle TEXT NOT NULL,
        source_digest TEXT NOT NULL,
        search_text TEXT NOT NULL,
        entry_digest TEXT NOT NULL,
        bucket INTEGER NOT NULL,
        generation INTEGER NOT NULL,
        PRIMARY KEY (kind, canonical_id),
        CHECK ((kind = 'evidence' AND lifecycle = '') OR
               (kind = 'claim' AND lifecycle IN ('active', 'superseded'))),
        CHECK (bucket >= 0),
        CHECK (generation > 0)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS cl_incremental_dependencies (
        evidence_id TEXT NOT NULL,
        claim_id TEXT NOT NULL,
        bucket INTEGER NOT NULL,
        generation INTEGER NOT NULL,
        PRIMARY KEY (evidence_id, claim_id),
        CHECK (bucket >= 0),
        CHECK (generation > 0)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS cl_incremental_buckets (
        manifest_kind TEXT NOT NULL,
        bucket INTEGER NOT NULL,
        item_count INTEGER NOT NULL,
        bucket_digest TEXT NOT NULL,
        generation INTEGER NOT NULL,
        PRIMARY KEY (manifest_kind, bucket),
        CHECK (manifest_kind IN ('document', 'dependency')),
        CHECK (bucket >= 0),
        CHECK (item_count >= 0),
        CHECK (generation > 0)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS cl_incremental_checkpoints (
        generation INTEGER PRIMARY KEY,
        previous_digest TEXT NOT NULL,
        checkpoint_digest TEXT NOT NULL UNIQUE,
        base_event_count INTEGER NOT NULL,
        event_count INTEGER NOT NULL,
        append_from_seq INTEGER NOT NULL,
        append_to_seq INTEGER NOT NULL,
        append_digest TEXT NOT NULL,
        canonical_fingerprint TEXT NOT NULL,
        last_seq INTEGER NOT NULL,
        last_recorded_at REAL NOT NULL,
        document_count INTEGER NOT NULL,
        dependency_count INTEGER NOT NULL,
        document_manifest_digest TEXT NOT NULL,
        dependency_manifest_digest TEXT NOT NULL,
        config_digest TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        CHECK (generation > 0),
        CHECK (base_event_count >= 0),
        CHECK (event_count >= base_event_count),
        CHECK (last_seq = event_count),
        CHECK (document_count >= 0),
        CHECK (dependency_count >= 0),
        CHECK (created_at >= 0)
      ) STRICT;
      CREATE VIRTUAL TABLE IF NOT EXISTS cl_incremental_fts USING fts5(
        canonical_id UNINDEXED,
        kind UNINDEXED,
        scope UNINDEXED,
        lifecycle UNINDEXED,
        entry_digest UNINDEXED,
        generation UNINDEXED,
        search_text,
        tokenize = 'unicode61 remove_diacritics 2'
      );
    `);
    const row = this.#meta();
    if (row !== undefined && row.schema_version !== SCHEMA_VERSION) this.#resetSchema();
  }

  #dropSchema(): void {
    this.#db.exec(`
      DROP TABLE IF EXISTS cl_incremental_fts;
      DROP TABLE IF EXISTS cl_incremental_checkpoints;
      DROP TABLE IF EXISTS cl_incremental_buckets;
      DROP TABLE IF EXISTS cl_incremental_dependencies;
      DROP TABLE IF EXISTS cl_incremental_documents;
      DROP TABLE IF EXISTS cl_incremental_event_digests;
      DROP TABLE IF EXISTS cl_incremental_meta;
    `);
  }

  #resetSchema(): void {
    this.#dropSchema();
    this.#initializeSchema();
  }

  #meta(): MetaRow | undefined {
    const value = this.#db.prepare('SELECT * FROM cl_incremental_meta WHERE id = 1').get() as
      | MetaRow
      | undefined;
    if (value === undefined) return undefined;
    if (value.schema_version !== SCHEMA_VERSION) {
      throw new Error(`unsupported incremental projection schema version: ${value.schema_version}`);
    }
    assertSafeInteger(value.generation, 'incremental metadata generation', 1);
    assertSafeInteger(value.event_count, 'incremental metadata event_count');
    assertSafeInteger(value.last_seq, 'incremental metadata last_seq');
    assertSafeInteger(value.document_count, 'incremental metadata document_count');
    assertSafeInteger(value.dependency_count, 'incremental metadata dependency_count');
    assertSafeInteger(value.updated_at, 'incremental metadata updated_at');
    if (!Number.isFinite(value.last_recorded_at)) {
      throw new Error('incremental metadata last_recorded_at must be finite');
    }
    if (value.last_seq !== value.event_count) {
      throw new Error('incremental metadata last_seq must equal event_count');
    }
    for (const [label, candidate] of [
      ['config digest', value.config_digest],
      ['canonical fingerprint', value.canonical_fingerprint],
      ['active checkpoint digest', value.active_checkpoint_digest],
      ['document manifest', value.document_manifest_digest],
      ['dependency manifest', value.dependency_manifest_digest],
    ] as const) {
      validateDigest(candidate, `incremental metadata ${label}`);
    }
    return value;
  }

  #checkpoint(generation: number): IncrementalProjectionCheckpoint | undefined {
    const row = this.#db
      .prepare('SELECT * FROM cl_incremental_checkpoints WHERE generation = ?')
      .get(generation) as CheckpointRow | undefined;
    return row === undefined ? undefined : checkpointFromRow(row);
  }

  #verifyStoredHead(meta: MetaRow): IncrementalProjectionCheckpoint {
    const active = this.#checkpoint(meta.generation);
    if (active === undefined) throw new Error('active incremental checkpoint is missing');
    verifyCheckpointDigest(active, 'active incremental checkpoint');

    if (
      active.generation !== meta.generation ||
      active.configDigest !== meta.config_digest ||
      active.eventCount !== meta.event_count ||
      active.lastSeq !== meta.last_seq ||
      active.lastRecordedAt !== meta.last_recorded_at ||
      active.canonicalFingerprint !== meta.canonical_fingerprint ||
      active.checkpointDigest !== meta.active_checkpoint_digest ||
      active.documentCount !== meta.document_count ||
      active.dependencyCount !== meta.dependency_count ||
      active.documentManifestDigest !== meta.document_manifest_digest ||
      active.dependencyManifestDigest !== meta.dependency_manifest_digest ||
      active.createdAt !== meta.updated_at
    ) {
      throw new Error('incremental metadata diverges from the active checkpoint');
    }

    if (active.generation === 1) {
      const genesis = digest({ domain: 'cl-checkpoint-genesis-v1' });
      if (active.previousDigest !== genesis || active.baseEventCount !== 0) {
        throw new Error('incremental genesis checkpoint is malformed');
      }
      return active;
    }

    const predecessor = this.#checkpoint(active.generation - 1);
    if (predecessor === undefined) {
      throw new Error('active incremental checkpoint predecessor is missing');
    }
    verifyCheckpointDigest(predecessor, 'incremental checkpoint predecessor');
    if (
      active.previousDigest !== predecessor.checkpointDigest ||
      active.baseEventCount !== predecessor.eventCount ||
      active.eventCount < predecessor.eventCount ||
      active.createdAt <= predecessor.createdAt
    ) {
      throw new Error('active incremental checkpoint predecessor is invalid');
    }
    return active;
  }

  #storedDocuments(): readonly StoredDocumentRow[] {
    return this.#db
      .prepare(`SELECT * FROM cl_incremental_documents ORDER BY kind, canonical_id`)
      .all() as unknown as readonly StoredDocumentRow[];
  }

  #storedDependencies(): readonly StoredDependencyRow[] {
    return this.#db
      .prepare(`SELECT * FROM cl_incremental_dependencies ORDER BY evidence_id, claim_id`)
      .all() as unknown as readonly StoredDependencyRow[];
  }

  #storedFtsRows(): readonly StoredFtsRow[] {
    return this.#db
      .prepare(`
        SELECT canonical_id, kind, scope, lifecycle, entry_digest,
               CAST(generation AS INTEGER) AS generation, search_text
          FROM cl_incremental_fts
         ORDER BY kind, canonical_id
      `)
      .all() as unknown as readonly StoredFtsRow[];
  }

  #verifyPrefix(current: CanonicalSnapshot, meta: MetaRow): void {
    if (current.events.length < meta.event_count) {
      throw new Error('canonical history regressed behind the incremental checkpoint');
    }
    const rows = this.#db
      .prepare(`
        SELECT seq, event_id, recorded_at, event_digest
          FROM cl_incremental_event_digests
         WHERE seq <= ?
         ORDER BY seq
      `)
      .all(meta.event_count) as unknown as readonly {
      readonly seq: number;
      readonly event_id: string;
      readonly recorded_at: number;
      readonly event_digest: string;
    }[];
    if (rows.length !== meta.event_count) throw new Error('incremental event-prefix rows are incomplete');
    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index];
      const expected = current.eventDigests[index];
      if (
        row === undefined ||
        expected === undefined ||
        row.seq !== expected.seq ||
        row.event_id !== expected.eventId ||
        row.recorded_at !== expected.recordedAt ||
        row.event_digest !== expected.digest
      ) {
        throw new Error(`canonical history fork detected at sequence ${index + 1}`);
      }
    }
  }

  #writeDocuments(documents: readonly ProjectionDocument[], generation: number): void {
    const expected = new Map(
      documents.map((document) => [docKey(document.kind, document.canonicalId), document]),
    );
    const existingDocuments = new Map(
      this.#storedDocuments().map((row) => [
        docKey(row.kind as ProjectionDocument['kind'], row.canonical_id),
        row,
      ]),
    );
    const existingFts = new Map<string, StoredFtsRow[]>();
    for (const row of this.#storedFtsRows()) {
      const key = docKey(row.kind as ProjectionDocument['kind'], row.canonical_id);
      const rows = existingFts.get(key) ?? [];
      rows.push(row);
      existingFts.set(key, rows);
    }

    const removeDocument = this.#db.prepare(
      'DELETE FROM cl_incremental_documents WHERE kind = ? AND canonical_id = ?',
    );
    const removeFts = this.#db.prepare(
      'DELETE FROM cl_incremental_fts WHERE kind = ? AND canonical_id = ?',
    );
    const insertDocument = this.#db.prepare(`
      INSERT INTO cl_incremental_documents
        (canonical_id, kind, scope, lifecycle, source_digest, search_text, entry_digest, bucket, generation)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const insertFts = this.#db.prepare(`
      INSERT INTO cl_incremental_fts
        (canonical_id, kind, scope, lifecycle, entry_digest, generation, search_text)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    const allKeys = new Set([...existingDocuments.keys(), ...existingFts.keys()]);
    for (const key of allKeys) {
      if (expected.has(key)) continue;
      const documentRow = existingDocuments.get(key);
      const ftsRow = existingFts.get(key)?.[0];
      const kind = documentRow?.kind ?? ftsRow?.kind;
      const canonicalId = documentRow?.canonical_id ?? ftsRow?.canonical_id;
      if (kind !== undefined && canonicalId !== undefined) {
        removeDocument.run(kind, canonicalId);
        removeFts.run(kind, canonicalId);
      }
    }

    for (const [key, document] of expected) {
      const lifecycle = document.lifecycle ?? '';
      const bucket = bucketFor(key, this.#bucketCount);
      const documentRow = existingDocuments.get(key);
      const ftsRows = existingFts.get(key) ?? [];
      const documentMatches =
        documentRow !== undefined &&
        documentRow.kind === document.kind &&
        documentRow.canonical_id === document.canonicalId &&
        documentRow.scope === document.scope &&
        documentRow.lifecycle === lifecycle &&
        documentRow.source_digest === document.sourceDigest &&
        documentRow.search_text === document.searchText &&
        documentRow.entry_digest === document.entryDigest &&
        documentRow.bucket === bucket &&
        Number.isSafeInteger(documentRow.generation) &&
        documentRow.generation > 0 &&
        documentRow.generation <= generation;
      const ftsRow = ftsRows[0];
      const ftsMatches =
        ftsRows.length === 1 &&
        ftsRow !== undefined &&
        ftsRow.kind === document.kind &&
        ftsRow.canonical_id === document.canonicalId &&
        ftsRow.scope === document.scope &&
        ftsRow.lifecycle === lifecycle &&
        ftsRow.entry_digest === document.entryDigest &&
        ftsRow.search_text === document.searchText &&
        documentRow !== undefined &&
        ftsRow.generation === documentRow.generation;

      if (documentMatches && ftsMatches) continue;

      removeDocument.run(document.kind, document.canonicalId);
      removeFts.run(document.kind, document.canonicalId);
      insertDocument.run(
        document.canonicalId,
        document.kind,
        document.scope,
        lifecycle,
        document.sourceDigest,
        document.searchText,
        document.entryDigest,
        bucket,
        generation,
      );
      insertFts.run(
        document.canonicalId,
        document.kind,
        document.scope,
        lifecycle,
        document.entryDigest,
        generation,
        document.searchText,
      );
    }
  }

  #writeDependencies(dependencies: readonly Dependency[], generation: number): void {
    const expected = new Map(
      dependencies.map((item) => [
        `${item.evidenceId}\u0000${item.claimId}`,
        item,
      ]),
    );
    const existing = new Map(
      this.#storedDependencies().map((row) => [
        `${row.evidence_id}\u0000${row.claim_id}`,
        row,
      ]),
    );
    const remove = this.#db.prepare(
      'DELETE FROM cl_incremental_dependencies WHERE evidence_id = ? AND claim_id = ?',
    );
    for (const [key, row] of existing) {
      if (!expected.has(key)) remove.run(row.evidence_id, row.claim_id);
    }
    const insert = this.#db.prepare(`
      INSERT INTO cl_incremental_dependencies (evidence_id, claim_id, bucket, generation)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(evidence_id, claim_id)
      DO UPDATE SET bucket = excluded.bucket, generation = excluded.generation
    `);
    for (const [key, dependency] of expected) {
      const bucket = bucketFor(key, this.#bucketCount);
      const row = existing.get(key);
      if (
        row !== undefined &&
        row.bucket === bucket &&
        Number.isSafeInteger(row.generation) &&
        row.generation > 0 &&
        row.generation <= generation
      ) {
        continue;
      }
      insert.run(dependency.evidenceId, dependency.claimId, bucket, generation);
    }
  }

  #writeBuckets(
    kind: 'document' | 'dependency',
    buckets: readonly BucketRecord[],
    generation: number,
  ): void {
    const statement = this.#db.prepare(`
      INSERT INTO cl_incremental_buckets
        (manifest_kind, bucket, item_count, bucket_digest, generation)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(manifest_kind, bucket)
      DO UPDATE SET item_count = excluded.item_count,
                    bucket_digest = excluded.bucket_digest,
                    generation = excluded.generation
    `);
    for (const bucket of buckets) {
      statement.run(kind, bucket.bucket, bucket.itemCount, bucket.digest, generation);
    }
  }

  #publish(
    current: CanonicalSnapshot,
    documents: readonly ProjectionDocument[],
    dependencies: readonly Dependency[],
    previous: MetaRow | undefined,
  ): IncrementalProjectionCheckpoint {
    const generation = (previous?.generation ?? 0) + 1;
    assertSafeInteger(generation, 'incremental generation', 1);
    const baseEventCount = previous?.event_count ?? 0;
    const appended = current.eventDigests.slice(baseEventCount);
    const documentBucketRows = documentBuckets(documents, this.#bucketCount);
    const dependencyBucketRows = dependencyBuckets(dependencies, this.#bucketCount);
    const documentManifestDigest = rootManifest('cl-document-manifest-v1', documentBucketRows);
    const dependencyManifestDigest = rootManifest('cl-dependency-manifest-v1', dependencyBucketRows);
    const previousUpdatedAt = previous?.updated_at ?? -1;
    if (!Number.isSafeInteger(previousUpdatedAt) || previousUpdatedAt < -1) {
      throw new Error('previous incremental checkpoint time is malformed');
    }
    const observedNow = this.#clock();
    if (!Number.isSafeInteger(observedNow) || observedNow < 0) {
      throw new Error('incremental checkpoint clock must return a non-negative safe integer');
    }
    const createdAt = Math.max(observedNow, previousUpdatedAt + 1);
    assertSafeInteger(createdAt, 'incremental checkpoint publication time');
    const unsigned = Object.freeze({
      generation,
      previousDigest: previous?.active_checkpoint_digest ?? digest({ domain: 'cl-checkpoint-genesis-v1' }),
      baseEventCount,
      eventCount: current.events.length,
      appendFromSeq: appended.at(0)?.seq ?? current.events.length + 1,
      appendToSeq: appended.at(-1)?.seq ?? current.events.length,
      appendDigest: appendDigest(appended),
      canonicalFingerprint: current.fingerprint,
      lastSeq: current.events.at(-1)?.seq ?? 0,
      lastRecordedAt: current.events.at(-1)?.recordedAt ?? 0,
      documentCount: documents.length,
      dependencyCount: dependencies.length,
      documentManifestDigest,
      dependencyManifestDigest,
      configDigest: this.#configDigest,
      createdAt,
    });
    const checkpointDigest = digest(checkpointPayload(unsigned));
    const checkpoint = Object.freeze({ ...unsigned, checkpointDigest });

    this.#writeDocuments(documents, generation);
    this.#inject('after-documents');
    this.#writeDependencies(dependencies, generation);
    this.#inject('after-dependencies');
    this.#writeBuckets('document', documentBucketRows, generation);
    this.#writeBuckets('dependency', dependencyBucketRows, generation);
    this.#inject('after-buckets');

    const unpublishedRows = this.#db
      .prepare('SELECT COUNT(*) AS count FROM cl_incremental_event_digests WHERE seq > ?')
      .get(baseEventCount) as { readonly count: number } | undefined;
    if (
      unpublishedRows === undefined ||
      !Number.isSafeInteger(unpublishedRows.count) ||
      unpublishedRows.count !== 0
    ) {
      throw new Error('incremental event-prefix table contains unpublished tail rows');
    }
    const insertEvent = this.#db.prepare(`
      INSERT INTO cl_incremental_event_digests (seq, event_id, recorded_at, event_digest)
      VALUES (?, ?, ?, ?)
    `);
    for (const event of appended) insertEvent.run(event.seq, event.eventId, event.recordedAt, event.digest);

    this.#db
      .prepare(`
        INSERT INTO cl_incremental_checkpoints
          (generation, previous_digest, checkpoint_digest, base_event_count, event_count,
           append_from_seq, append_to_seq, append_digest, canonical_fingerprint,
           last_seq, last_recorded_at, document_count, dependency_count,
           document_manifest_digest, dependency_manifest_digest, config_digest, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .run(
        checkpoint.generation,
        checkpoint.previousDigest,
        checkpoint.checkpointDigest,
        checkpoint.baseEventCount,
        checkpoint.eventCount,
        checkpoint.appendFromSeq,
        checkpoint.appendToSeq,
        checkpoint.appendDigest,
        checkpoint.canonicalFingerprint,
        checkpoint.lastSeq,
        checkpoint.lastRecordedAt,
        checkpoint.documentCount,
        checkpoint.dependencyCount,
        checkpoint.documentManifestDigest,
        checkpoint.dependencyManifestDigest,
        checkpoint.configDigest,
        checkpoint.createdAt,
      );
    this.#inject('after-checkpoint');
    this.#db
      .prepare(`
        INSERT INTO cl_incremental_meta
          (id, schema_version, config_digest, generation, event_count, last_seq,
           last_recorded_at, canonical_fingerprint, active_checkpoint_digest,
           document_count, dependency_count, document_manifest_digest,
           dependency_manifest_digest, updated_at)
        VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          schema_version = excluded.schema_version,
          config_digest = excluded.config_digest,
          generation = excluded.generation,
          event_count = excluded.event_count,
          last_seq = excluded.last_seq,
          last_recorded_at = excluded.last_recorded_at,
          canonical_fingerprint = excluded.canonical_fingerprint,
          active_checkpoint_digest = excluded.active_checkpoint_digest,
          document_count = excluded.document_count,
          dependency_count = excluded.dependency_count,
          document_manifest_digest = excluded.document_manifest_digest,
          dependency_manifest_digest = excluded.dependency_manifest_digest,
          updated_at = excluded.updated_at
      `)
      .run(
        SCHEMA_VERSION,
        this.#configDigest,
        generation,
        current.events.length,
        current.events.at(-1)?.seq ?? 0,
        current.events.at(-1)?.recordedAt ?? 0,
        current.fingerprint,
        checkpointDigest,
        documents.length,
        dependencies.length,
        documentManifestDigest,
        dependencyManifestDigest,
        createdAt,
      );
    return checkpoint;
  }

  rebuild(events: readonly MemoryEvent[]): IncrementalProjectionCheckpoint {
    const current = snapshot(events);
    const documents = documentsFor(current, this.#sensitivities, this.#indexClaimValues);
    const dependencies = dependenciesFor(current.events, documents);
    return this.#transaction('write', () => {
      this.#inject('after-begin');
      const previous = this.#meta();
      if (previous !== undefined) {
        this.#verifyPrefix(current, previous);
        this.#verifyStoredHead(previous);
      }
      this.#inject('after-prefix');
      this.#db.exec(`
        DELETE FROM cl_incremental_fts;
        DELETE FROM cl_incremental_documents;
        DELETE FROM cl_incremental_dependencies;
        DELETE FROM cl_incremental_buckets;
      `);
      if (previous === undefined) this.#db.exec('DELETE FROM cl_incremental_event_digests');
      const checkpoint = this.#publish(current, documents, dependencies, previous);
      this.#inject('before-commit');
      return checkpoint;
    });
  }

  update(events: readonly MemoryEvent[]): IncrementalProjectionCheckpoint {
    const current = snapshot(events);
    const documents = documentsFor(current, this.#sensitivities, this.#indexClaimValues);
    const dependencies = dependenciesFor(current.events, documents);
    return this.#transaction('write', () => {
      this.#inject('after-begin');
      const previous = this.#meta();
      if (previous === undefined) throw new Error('incremental projection must be rebuilt before update');
      if (previous.config_digest !== this.#configDigest) {
        throw new Error('incremental projection configuration changed; a full rebuild is required');
      }
      this.#verifyPrefix(current, previous);
      const integrity = this.#verifyFast(current);
      this.#inject('after-prefix');
      if (current.events.length === previous.event_count) {
        if (!integrity.fresh || integrity.checkpoint === undefined) {
          throw new Error(`incremental projection is unavailable: ${integrity.reason}`);
        }
        return integrity.checkpoint;
      }
      const checkpoint = this.#publish(current, documents, dependencies, previous);
      this.#inject('before-commit');
      return checkpoint;
    });
  }

  #bucketRows(
    kind: 'document' | 'dependency',
    expectedGeneration: number,
  ): readonly StoredBucketRecord[] {
    const rows = this.#db
      .prepare(`
        SELECT bucket, item_count, bucket_digest, generation
          FROM cl_incremental_buckets
         WHERE manifest_kind = ?
         ORDER BY bucket
      `)
      .all(kind) as unknown as readonly {
      readonly bucket: number;
      readonly item_count: number;
      readonly bucket_digest: string;
      readonly generation: number;
    }[];
    if (rows.length !== this.#bucketCount) {
      throw new Error(`${kind} bucket manifest is incomplete`);
    }
    return Object.freeze(
      rows.map((row, index) => {
        if (
          row.bucket !== index ||
          !Number.isSafeInteger(row.item_count) ||
          row.item_count < 0 ||
          !Number.isSafeInteger(row.generation) ||
          row.generation !== expectedGeneration
        ) {
          throw new Error(`${kind} bucket metadata or generation is malformed`);
        }
        validateDigest(row.bucket_digest, `${kind} bucket digest`);
        return Object.freeze({
          bucket: row.bucket,
          itemCount: row.item_count,
          digest: row.bucket_digest,
          generation: row.generation,
        });
      }),
    );
  }

  #verifyFast(current: CanonicalSnapshot): IncrementalProjectionStatus {
    const meta = this.#meta();
    if (meta === undefined) {
      return Object.freeze({
        initialized: false,
        fresh: false,
        reason: 'incremental projection has not been built',
        canonicalFingerprint: current.fingerprint,
        eventCount: current.events.length,
      });
    }
    const active = this.#verifyStoredHead(meta);
    const documentBuckets = this.#bucketRows('document', active.generation);
    const dependencyBuckets = this.#bucketRows('dependency', active.generation);
    const documentRoot = rootManifest('cl-document-manifest-v1', documentBuckets);
    const dependencyRoot = rootManifest('cl-dependency-manifest-v1', dependencyBuckets);
    if (
      documentRoot !== meta.document_manifest_digest ||
      documentRoot !== active.documentManifestDigest ||
      dependencyRoot !== meta.dependency_manifest_digest ||
      dependencyRoot !== active.dependencyManifestDigest
    ) {
      throw new Error('incremental bucket root does not match checkpoint metadata');
    }
    const documentCount = documentBuckets.reduce((sum, bucket) => sum + bucket.itemCount, 0);
    const dependencyCount = dependencyBuckets.reduce((sum, bucket) => sum + bucket.itemCount, 0);
    if (
      documentCount !== meta.document_count ||
      documentCount !== active.documentCount ||
      dependencyCount !== meta.dependency_count ||
      dependencyCount !== active.dependencyCount
    ) {
      throw new Error('incremental bucket counts do not match checkpoint metadata');
    }
    const fresh =
      meta.config_digest === this.#configDigest &&
      meta.canonical_fingerprint === current.fingerprint &&
      meta.event_count === current.events.length &&
      meta.last_seq === (current.events.at(-1)?.seq ?? 0) &&
      meta.last_recorded_at === (current.events.at(-1)?.recordedAt ?? 0);
    return Object.freeze({
      initialized: true,
      fresh,
      reason: fresh
        ? 'incremental checkpoint matches canonical memory'
        : 'incremental checkpoint is stale or uses a different privacy configuration',
      canonicalFingerprint: current.fingerprint,
      eventCount: current.events.length,
      checkpoint: active,
    });
  }

  status(events: readonly MemoryEvent[]): IncrementalProjectionStatus {
    const current = snapshot(events);
    return this.#transaction('read', () => this.#verifyFast(current));
  }

  search(
    events: readonly MemoryEvent[],
    query: string,
    options: IncrementalSearchOptions,
  ): readonly IncrementalSearchCandidate[] {
    const scopeChain = snapshotScopeChain(options.scopeChain);
    const limit = options.limit ?? DEFAULT_LIMIT;
    if (!Number.isInteger(limit) || limit <= 0 || limit > MAX_LIMIT) {
      throw new RangeError(`incremental FTS result limit must be in [1, ${MAX_LIMIT}]`);
    }
    const match = safeMatchQuery(query, options.maxQueryTokens);
    const lifecycle = normalizeClaimLifecycleFilter(options.claimLifecycle);
    const current = snapshot(events);
    return this.#transaction('read', () => {
      const state = this.#verifyFast(current);
      if (!state.fresh || state.checkpoint === undefined) {
        throw new Error(`incremental projection is unavailable: ${state.reason}`);
      }
      const checkpoint = state.checkpoint;
      this.#inject('after-search-verify');
      const placeholders = scopeChain.map(() => '?').join(', ');
      const lifecycleClause =
        lifecycle === 'active-only' ? "AND (kind <> 'claim' OR lifecycle = 'active')" : '';
      const rows = this.#db
        .prepare(`
          SELECT canonical_id, kind, scope, lifecycle, entry_digest,
                 CAST(generation AS INTEGER) AS generation, search_text,
                 bm25(cl_incremental_fts) AS fts_score
            FROM cl_incremental_fts
           WHERE cl_incremental_fts MATCH ?
             AND scope IN (${placeholders})
             ${lifecycleClause}
           ORDER BY fts_score ASC, kind ASC, canonical_id ASC
           LIMIT ?
        `)
        .all(match, ...scopeChain, limit) as unknown as readonly SearchRow[];
      return Object.freeze(
        rows.map((row, index) => {
          if (row.kind !== 'evidence' && row.kind !== 'claim') {
            throw new Error('incremental FTS row has an unknown kind');
          }
          if (
            typeof row.canonical_id !== 'string' ||
            row.canonical_id.trim().length === 0 ||
            typeof row.scope !== 'string' ||
            row.scope.trim().length === 0 ||
            typeof row.search_text !== 'string' ||
            typeof row.fts_score !== 'number' ||
            !Number.isFinite(row.fts_score)
          ) {
            throw new Error('incremental FTS row has malformed identity, scope, text, or score');
          }
          if (!SHA256_PATTERN.test(row.entry_digest)) {
            throw new Error('incremental FTS row has a malformed entry digest');
          }
          const canonical = this.#db
            .prepare(`
              SELECT scope, lifecycle, source_digest, entry_digest, generation, search_text
                FROM cl_incremental_documents
               WHERE kind = ? AND canonical_id = ?
            `)
            .get(row.kind, row.canonical_id) as
            | {
                readonly scope: string;
                readonly lifecycle: string;
                readonly source_digest: string;
                readonly entry_digest: string;
                readonly generation: number;
                readonly search_text: string;
              }
            | undefined;
          const storedLifecycle =
            canonical === undefined
              ? undefined
              : row.kind === 'claim'
                ? canonical.lifecycle === 'active' || canonical.lifecycle === 'superseded'
                  ? canonical.lifecycle
                  : undefined
                : canonical.lifecycle === ''
                  ? ''
                  : undefined;
          const canonicalBase =
            canonical === undefined || storedLifecycle === undefined
              ? undefined
              : Object.freeze({
                  canonicalId: row.canonical_id,
                  kind: row.kind,
                  scope: canonical.scope,
                  lifecycle: storedLifecycle,
                  sourceDigest: canonical.source_digest,
                  searchText: canonical.search_text,
                });
          if (
            canonical === undefined ||
            canonicalBase === undefined ||
            canonical.scope !== row.scope ||
            canonical.lifecycle !== row.lifecycle ||
            canonical.entry_digest !== row.entry_digest ||
            canonical.search_text !== row.search_text ||
            canonical.generation !== row.generation ||
            documentDigest(canonicalBase) !== canonical.entry_digest ||
            !Number.isSafeInteger(row.generation) ||
            row.generation <= 0 ||
            row.generation > checkpoint.generation
          ) {
            throw new Error(`incremental FTS shadow row diverged for ${row.kind}/${row.canonical_id}`);
          }
          const claimLifecycle =
            row.kind === 'claim'
              ? row.lifecycle === 'active' || row.lifecycle === 'superseded'
                ? row.lifecycle
                : undefined
              : undefined;
          if (row.kind === 'claim' && claimLifecycle === undefined) {
            throw new Error('incremental FTS claim lifecycle is invalid');
          }
          return Object.freeze({
            canonicalId: row.canonical_id,
            kind: row.kind,
            scope: row.scope,
            ...(claimLifecycle === undefined ? {} : { lifecycle: claimLifecycle }),
            rank: index + 1,
            score: -row.fts_score,
            entryDigest: row.entry_digest,
            canonicalFingerprint: checkpoint.canonicalFingerprint,
            generation: checkpoint.generation,
          });
        }),
      );
    });
  }

  rehydrate(
    events: readonly MemoryEvent[],
    candidates: readonly IncrementalSearchCandidate[],
    options: Pick<IncrementalSearchOptions, 'scopeChain' | 'claimLifecycle'>,
  ): readonly IncrementalRehydratedCandidate[] {
    const scopeChain = snapshotScopeChain(options.scopeChain);
    if (!Array.isArray(candidates)) throw new TypeError('incremental candidates must be an array');
    const candidateSnapshot = Object.freeze(Array.from(candidates, snapshotCandidate));
    if (candidateSnapshot.length > MAX_CANDIDATES) {
      throw new RangeError(`incremental rehydration cannot exceed ${MAX_CANDIDATES} candidates`);
    }
    const lifecycle = normalizeClaimLifecycleFilter(options.claimLifecycle);
    const current = snapshot(events);
    const documents = new Map(
      documentsFor(current, this.#sensitivities, this.#indexClaimValues).map((document) => [
        docKey(document.kind, document.canonicalId),
        document,
      ]),
    );
    const allowedScopes = new Set(scopeChain);
    const evidence = EvidenceProjection.from(current.events);
    const claims = ClaimProjection.from(current.events);
    const seen = new Set<string>();
    return Object.freeze(
      candidateSnapshot.map((candidate) => {
        if (candidate.kind !== 'evidence' && candidate.kind !== 'claim') {
          throw new Error(`incremental candidate has an unknown kind: ${String(candidate.kind)}`);
        }
        if (
          typeof candidate.canonicalId !== 'string' ||
          candidate.canonicalId.trim().length === 0 ||
          typeof candidate.scope !== 'string' ||
          candidate.scope.trim().length === 0 ||
          !Number.isSafeInteger(candidate.generation) ||
          candidate.generation <= 0 ||
          !Number.isSafeInteger(candidate.rank) ||
          candidate.rank <= 0 ||
          typeof candidate.score !== 'number' ||
          !Number.isFinite(candidate.score) ||
          !SHA256_PATTERN.test(candidate.entryDigest) ||
          !SHA256_PATTERN.test(candidate.canonicalFingerprint)
        ) {
          throw new Error('incremental candidate metadata is malformed');
        }
        const identity = docKey(candidate.kind, candidate.canonicalId);
        if (seen.has(identity)) {
          throw new Error(`duplicate incremental candidate: ${candidate.kind}/${candidate.canonicalId}`);
        }
        seen.add(identity);
        if (candidate.canonicalFingerprint !== current.fingerprint) {
          throw new Error(`incremental candidate ${candidate.canonicalId} is stale`);
        }
        if (
          (candidate.kind === 'evidence' && candidate.lifecycle !== undefined) ||
          (candidate.kind === 'claim' &&
            candidate.lifecycle !== 'active' &&
            candidate.lifecycle !== 'superseded')
        ) {
          throw new Error(`incremental candidate ${candidate.canonicalId} has invalid lifecycle metadata`);
        }
        if (!allowedScopes.has(candidate.scope)) {
          throw new Error(`incremental candidate scope ${candidate.scope} is not authorized`);
        }
        const document = documents.get(docKey(candidate.kind, candidate.canonicalId));
        if (
          document === undefined ||
          document.scope !== candidate.scope ||
          document.entryDigest !== candidate.entryDigest
        ) {
          throw new Error(`incremental candidate ${candidate.canonicalId} failed canonical rehydration`);
        }
        if (
          candidate.kind === 'claim' &&
          lifecycle === 'active-only' &&
          document.lifecycle !== 'active'
        ) {
          throw new Error(`incremental claim ${candidate.canonicalId} is not active`);
        }
        if (candidate.kind === 'evidence') {
          const projected = evidence.get(candidate.canonicalId);
          if (projected === undefined || projected.availability !== 'available') {
            throw new Error(`incremental evidence ${candidate.canonicalId} is unavailable`);
          }
          return Object.freeze({ candidate, evidence: projected.record });
        }
        const claim = claims.get(candidate.canonicalId);
        const claimLifecycle = claims.lifecycle(candidate.canonicalId);
        if (
          claim === undefined ||
          (claimLifecycle !== 'active' && claimLifecycle !== 'superseded') ||
          claimLifecycle !== document.lifecycle ||
          candidate.lifecycle !== document.lifecycle
        ) {
          throw new Error(`incremental claim ${candidate.canonicalId} has invalid canonical lifecycle`);
        }
        return Object.freeze({ candidate, claim });
      }),
    );
  }

  audit(events: readonly MemoryEvent[]): IncrementalProjectionAudit {
    const current = snapshot(events);
    const expectedDocuments = documentsFor(current, this.#sensitivities, this.#indexClaimValues);
    const expectedDependencies = dependenciesFor(current.events, expectedDocuments);
    return this.#transaction('read', () => {
      const errors: string[] = [];
      let checkpoint: IncrementalProjectionCheckpoint | undefined;
      try {
        const status = this.#verifyFast(current);
        checkpoint = status.checkpoint;
        if (!status.fresh) errors.push(status.reason);
      } catch (error) {
        errors.push(error instanceof Error ? error.message : 'fast integrity verification failed');
      }
      const activeGeneration = checkpoint?.generation;

      const storedDocuments = this.#storedDocuments();
      const storedDocumentMap = new Map(
        storedDocuments.map((row) => [
          docKey(row.kind as ProjectionDocument['kind'], row.canonical_id),
          row,
        ]),
      );
      const expectedDocumentMap = new Map(
        expectedDocuments.map((document) => [docKey(document.kind, document.canonicalId), document]),
      );
      if (storedDocuments.length !== expectedDocuments.length) {
        errors.push('stored document count differs from canonical projection');
      }
      for (const row of storedDocuments) {
        const key = docKey(row.kind as ProjectionDocument['kind'], row.canonical_id);
        const expected = expectedDocumentMap.get(key);
        if (
          expected === undefined ||
          expected.scope !== row.scope ||
          (expected.lifecycle ?? '') !== row.lifecycle ||
          expected.sourceDigest !== row.source_digest ||
          expected.searchText !== row.search_text ||
          expected.entryDigest !== row.entry_digest ||
          row.bucket !== bucketFor(docKey(expected.kind, expected.canonicalId), this.#bucketCount) ||
          !Number.isSafeInteger(row.generation) ||
          row.generation <= 0 ||
          (activeGeneration !== undefined && row.generation > activeGeneration)
        ) {
          errors.push(`stored document diverges from canonical projection: ${row.kind}/${row.canonical_id}`);
        }
      }

      const ftsRows = this.#storedFtsRows();
      const ftsByKey = new Map<string, StoredFtsRow[]>();
      for (const row of ftsRows) {
        const key = docKey(row.kind as ProjectionDocument['kind'], row.canonical_id);
        const rows = ftsByKey.get(key) ?? [];
        rows.push(row);
        ftsByKey.set(key, rows);
      }
      if (ftsRows.length !== storedDocuments.length) {
        errors.push('FTS shadow row count differs from document table');
      }
      for (const [key, rows] of ftsByKey) {
        const stored = storedDocumentMap.get(key);
        const row = rows[0];
        if (
          rows.length !== 1 ||
          stored === undefined ||
          row === undefined ||
          stored.scope !== row.scope ||
          stored.lifecycle !== row.lifecycle ||
          stored.entry_digest !== row.entry_digest ||
          stored.generation !== row.generation ||
          stored.search_text !== row.search_text
        ) {
          errors.push(`FTS shadow row diverges: ${key.replace('\u0000', '/')}`);
        }
      }
      try {
        this.#db.exec("INSERT INTO cl_incremental_fts(cl_incremental_fts) VALUES('integrity-check')");
      } catch (error) {
        errors.push(
          `FTS5 internal integrity check failed: ${
            error instanceof Error ? error.message : 'unknown SQLite error'
          }`,
        );
      }

      const expectedDependencyMap = new Map(
        expectedDependencies.map((item) => [
          `${item.evidenceId}\u0000${item.claimId}`,
          item,
        ]),
      );
      const storedDependencies = this.#storedDependencies();
      if (storedDependencies.length !== expectedDependencies.length) {
        errors.push('reverse dependency count differs from canonical projection');
      }
      for (const row of storedDependencies) {
        const key = `${row.evidence_id}\u0000${row.claim_id}`;
        const expected = expectedDependencyMap.get(key);
        if (
          expected === undefined ||
          row.bucket !== bucketFor(key, this.#bucketCount) ||
          !Number.isSafeInteger(row.generation) ||
          row.generation <= 0 ||
          (activeGeneration !== undefined && row.generation > activeGeneration)
        ) {
          errors.push(`reverse dependency diverges from canonical projection: ${key}`);
        }
      }

      const eventRows = this.#db
        .prepare(`
          SELECT seq, event_id, recorded_at, event_digest
            FROM cl_incremental_event_digests
           ORDER BY seq
        `)
        .all() as unknown as readonly {
        readonly seq: number;
        readonly event_id: string;
        readonly recorded_at: number;
        readonly event_digest: string;
      }[];
      if (eventRows.length !== current.eventDigests.length) {
        errors.push('event-prefix digest row count is incorrect');
      }
      for (let index = 0; index < current.eventDigests.length; index += 1) {
        const expected = current.eventDigests[index];
        const row = eventRows[index];
        if (
          expected === undefined ||
          row === undefined ||
          expected.seq !== row.seq ||
          expected.eventId !== row.event_id ||
          expected.recordedAt !== row.recorded_at ||
          expected.digest !== row.event_digest
        ) {
          errors.push(`event-prefix digest mismatch at sequence ${index + 1}`);
          break;
        }
      }

      const checkpointRows = this.#db
        .prepare(`SELECT * FROM cl_incremental_checkpoints ORDER BY generation`)
        .all() as unknown as readonly CheckpointRow[];
      if (activeGeneration !== undefined && checkpointRows.length !== activeGeneration) {
        errors.push('checkpoint table contains missing or future generations');
      }
      let previousDigest = digest({ domain: 'cl-checkpoint-genesis-v1' });
      let previousCount = 0;
      let previousCreatedAt = -1;
      let latest: IncrementalProjectionCheckpoint | undefined;
      for (let index = 0; index < checkpointRows.length; index += 1) {
        try {
          const item = checkpointFromRow(checkpointRows[index] as CheckpointRow);
          verifyCheckpointDigest(item, `checkpoint ${item.generation}`);
          if (item.generation !== index + 1) {
            errors.push('checkpoint generations are not contiguous');
          }
          if (item.previousDigest !== previousDigest) {
            errors.push(`checkpoint ${item.generation} has an invalid predecessor`);
          }
          if (item.baseEventCount !== previousCount) {
            errors.push(`checkpoint ${item.generation} has an invalid event range`);
          }
          if (item.createdAt <= previousCreatedAt) {
            errors.push(`checkpoint ${item.generation} time is not monotonic`);
          }
          if (item.eventCount > current.eventDigests.length) {
            errors.push(`checkpoint ${item.generation} points beyond canonical memory`);
          } else {
            const expectedAppend = current.eventDigests.slice(
              item.baseEventCount,
              item.eventCount,
            );
            if (appendDigest(expectedAppend) !== item.appendDigest) {
              errors.push(`checkpoint ${item.generation} append digest is invalid`);
            }
            const expectedRecordedAt = current.events.at(item.eventCount - 1)?.recordedAt ?? 0;
            if (item.lastRecordedAt !== expectedRecordedAt) {
              errors.push(`checkpoint ${item.generation} lastRecordedAt is invalid`);
            }
          }
          previousDigest = item.checkpointDigest;
          previousCount = item.eventCount;
          previousCreatedAt = item.createdAt;
          latest = item;
        } catch (error) {
          errors.push(
            error instanceof Error
              ? `checkpoint row ${index + 1} is invalid: ${error.message}`
              : `checkpoint row ${index + 1} is invalid`,
          );
        }
      }
      if (
        checkpoint !== undefined &&
        (latest === undefined || latest.checkpointDigest !== checkpoint.checkpointDigest)
      ) {
        errors.push('active checkpoint is not the terminal checkpoint');
      }
      if (
        latest !== undefined &&
        latest.eventCount === current.events.length &&
        latest.canonicalFingerprint !== current.fingerprint
      ) {
        errors.push('terminal checkpoint canonical fingerprint is invalid');
      }

      const expectedDocumentBuckets = documentBuckets(expectedDocuments, this.#bucketCount);
      const expectedDependencyBuckets = dependencyBuckets(expectedDependencies, this.#bucketCount);
      if (activeGeneration !== undefined) {
        try {
          if (
            rootManifest('cl-document-manifest-v1', expectedDocumentBuckets) !==
            rootManifest(
              'cl-document-manifest-v1',
              this.#bucketRows('document', activeGeneration),
            )
          ) {
            errors.push('document bucket manifest differs from canonical projection');
          }
          if (
            rootManifest('cl-dependency-manifest-v1', expectedDependencyBuckets) !==
            rootManifest(
              'cl-dependency-manifest-v1',
              this.#bucketRows('dependency', activeGeneration),
            )
          ) {
            errors.push('dependency bucket manifest differs from canonical projection');
          }
        } catch (error) {
          errors.push(error instanceof Error ? error.message : 'bucket audit failed');
        }
      }

      return Object.freeze({
        ok: errors.length === 0,
        errors: Object.freeze(errors),
        ...(checkpoint === undefined ? {} : { checkpoint }),
      });
    });
  }

  close(): void {
    if (this.#closed) return;
    this.#db.close();
    this.#closed = true;
  }
}
