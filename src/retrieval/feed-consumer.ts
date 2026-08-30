import type {
  ClaimLifecycle,
  ClaimRecord,
  EvidenceAvailability,
  EvidenceRecord,
  EvidenceRef,
  MemoryEvent,
} from '../domain.js';
import { ClaimProjection } from '../claims.js';
import { EvidenceProjection } from '../evidence.js';
import {
  CanonicalChangeFeed,
  canonicalGenesisCursor,
  canonicalReadCursorDigest,
  canonicalReadCursorForEvents,
  sameCanonicalReadCursor,
  type CanonicalAppendBatch,
  type CanonicalReadCursor,
} from '../durable/change-feed.js';
import {
  SqliteConsumerCheckpointStore,
  type ConsumerBinding,
  type ConsumerProjectionReadTransaction,
  type ConsumerProjectionTransaction,
  type DurableConsumerCheckpoint,
  type DurableConsumerRegistration,
} from '../durable/consumer-store.js';
import {
  buildDocuments,
  canonicalJson,
  claimText,
  contentDigest,
  documentDigest,
  evidenceText,
  normalizeClaimLifecycleFilter,
  safeMatchQuery,
  SHA256_PATTERN,
  snapshotScopeChain,
  type IndexedDocument,
} from './canonical.js';

const FEED_FTS_SCHEMA_VERSION = 1 as const;
const DEFAULT_BUCKET_COUNT = 256;
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;
const MAX_REHYDRATE = 100;
const DEFAULT_SENSITIVITIES = Object.freeze(['public', 'internal'] as const);
const PREFIX_PATTERN = /^[a-z][a-z0-9_]*_$/;
const MAX_PREFIX_BYTES = 96;

export class Fts5FeedRebuildRequiredError extends Error {
  readonly reason: string;
  readonly canonicalId?: string;

  constructor(reason: string, canonicalId?: string) {
    super(canonicalId === undefined ? reason : `${reason}: ${canonicalId}`);
    this.name = 'Fts5FeedRebuildRequiredError';
    this.reason = reason;
    if (canonicalId !== undefined) this.canonicalId = canonicalId;
  }
}

export interface Fts5FeedConsumerOptions {
  readonly consumerId: string;
  readonly projectionTablePrefix: string;
  readonly searchableSensitivities?: readonly EvidenceRecord['sensitivity'][];
  readonly indexClaimValues?: boolean;
  readonly bucketCount?: number;
}

export interface Fts5FeedSearchOptions {
  readonly scopeChain: readonly string[];
  readonly limit?: number;
  readonly maxQueryTokens?: number;
  readonly claimLifecycle?: 'all' | 'active-only';
}

export interface Fts5FeedSearchCandidate {
  readonly canonicalId: string;
  readonly kind: 'evidence' | 'claim';
  readonly scope: string;
  readonly lifecycle?: Extract<ClaimLifecycle, 'active' | 'superseded'>;
  readonly rank: number;
  readonly score: number;
  readonly entryDigest: string;
  readonly consumerRevision: number;
  readonly consumerCursorDigest: string;
  readonly lastBatchId: string;
  readonly configurationDigest: string;
}

export interface Fts5FeedRehydratedCandidate {
  readonly candidate: Fts5FeedSearchCandidate;
  readonly evidence?: EvidenceRecord;
  readonly claim?: ClaimRecord;
}

export interface Fts5FeedStatus {
  readonly initialized: boolean;
  readonly fresh: boolean;
  readonly reason: string;
  readonly registration?: DurableConsumerRegistration;
  readonly checkpoint?: DurableConsumerCheckpoint;
  readonly documentCount: number;
  readonly dependencyCount: number;
}

export interface Fts5FeedAudit {
  readonly ok: boolean;
  readonly errors: readonly string[];
  readonly documentCount: number;
  readonly dependencyCount: number;
}

interface MetaRow {
  readonly schema_version: unknown;
  readonly config_digest: unknown;
  readonly last_batch_id: unknown;
  readonly after_cursor_digest: unknown;
  readonly event_count: unknown;
  readonly document_count: unknown;
  readonly dependency_count: unknown;
  readonly document_manifest_digest: unknown;
  readonly dependency_manifest_digest: unknown;
}

interface EvidenceStateRow {
  readonly evidence_id_json: unknown;
  readonly scope_json: unknown;
  readonly source_groups_json: unknown;
  readonly authority: unknown;
  readonly artifact_digest: unknown;
  readonly availability: unknown;
  readonly support_eligible: unknown;
  readonly search_text: unknown;
}

interface ClaimStateRow {
  readonly claim_id_json: unknown;
  readonly scope_json: unknown;
  readonly lifecycle: unknown;
  readonly source_digest: unknown;
  readonly search_text: unknown;
  readonly evidence_refs_json: unknown;
}

interface DocumentRow {
  readonly canonical_id_json: unknown;
  readonly kind: unknown;
  readonly scope_json: unknown;
  readonly lifecycle: unknown;
  readonly source_digest: unknown;
  readonly search_text: unknown;
  readonly entry_digest: unknown;
  readonly bucket: unknown;
}

interface FtsRow extends DocumentRow {
  readonly fts_score: unknown;
}

interface DependencyRow {
  readonly evidence_id_json: unknown;
  readonly claim_id_json: unknown;
  readonly bucket: unknown;
}

interface BucketRow {
  readonly manifest_kind: unknown;
  readonly bucket: unknown;
  readonly item_count: unknown;
  readonly bucket_digest: unknown;
}

function isWellFormedText(value: string): boolean {
  const candidate = value as string & { isWellFormed?: () => boolean };
  if (typeof candidate.isWellFormed === 'function') return candidate.isWellFormed();
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function safeSearchText(value: string): string | undefined {
  return value.length > 0 && !value.includes('\u0000') && isWellFormedText(value)
    ? value
    : undefined;
}

function encodeString(value: string): string {
  return canonicalJson(value);
}

function decodeString(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new Error(`${label} must be stored as TEXT`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new Error(`${label} is not canonical JSON text`);
  }
  if (typeof parsed !== 'string' || canonicalJson(parsed) !== value) {
    throw new Error(`${label} is not a canonical encoded string`);
  }
  return parsed;
}

function decodeJsonArray<T>(value: unknown, label: string): readonly T[] {
  if (typeof value !== 'string') throw new Error(`${label} must be stored as TEXT`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
  if (!Array.isArray(parsed) || canonicalJson(parsed) !== value) {
    throw new Error(`${label} is not canonical JSON array data`);
  }
  return Object.freeze(parsed as T[]);
}

function assertString(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${label} is malformed`);
}

function assertInteger(value: unknown, label: string, minimum = 0): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    throw new Error(`${label} is malformed`);
  }
}

function assertDigest(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || !SHA256_PATTERN.test(value)) {
    throw new Error(`${label} is malformed`);
  }
}

function assertPrefix(prefix: unknown): asserts prefix is string {
  if (typeof prefix !== 'string' || !PREFIX_PATTERN.test(prefix)) {
    throw new Error('projectionTablePrefix must use lowercase ASCII letters, digits, underscores, and end with underscore');
  }
  if (new TextEncoder().encode(prefix).length > MAX_PREFIX_BYTES) {
    throw new Error(`projectionTablePrefix cannot exceed ${MAX_PREFIX_BYTES} UTF-8 bytes`);
  }
  if (prefix.startsWith('cl_consumer_') || prefix.startsWith('sqlite_')) {
    throw new Error('projectionTablePrefix overlaps a reserved namespace');
  }
}

function bucketFor(identity: string, bucketCount: number): number {
  const digest = contentDigest({ domain: 'cl-fts-feed-bucket-v1', identity });
  return Number.parseInt(digest.slice(7, 19), 16) % bucketCount;
}

function documentBucketDigest(bucket: number, rows: readonly DocumentRow[]): string {
  const members = rows.map((row) => {
    const kind = row.kind;
    if (kind !== 'evidence' && kind !== 'claim') throw new Error('document bucket contains invalid kind');
    const canonicalId = decodeString(row.canonical_id_json, 'document canonical id');
    assertDigest(row.entry_digest, 'document entry digest');
    return Object.freeze({ kind, canonicalId, entryDigest: row.entry_digest });
  });
  return contentDigest({ domain: 'cl-fts-feed-document-bucket-v1', bucket, members });
}

function dependencyBucketDigest(bucket: number, rows: readonly DependencyRow[]): string {
  const members = rows.map((row) => ({
    evidenceId: decodeString(row.evidence_id_json, 'dependency evidence id'),
    claimId: decodeString(row.claim_id_json, 'dependency claim id'),
  }));
  return contentDigest({ domain: 'cl-fts-feed-dependency-bucket-v1', bucket, members });
}

function rootManifest(kind: 'document' | 'dependency', rows: readonly BucketRow[]): string {
  const normalized = rows.map((row, index) => {
    if (row.manifest_kind !== kind) throw new Error(`${kind} bucket manifest has wrong kind`);
    assertInteger(row.bucket, `${kind} bucket`, 0);
    if (row.bucket !== index) throw new Error(`${kind} bucket manifest is not contiguous`);
    assertInteger(row.item_count, `${kind} bucket item count`, 0);
    assertDigest(row.bucket_digest, `${kind} bucket digest`);
    return Object.freeze({ bucket: row.bucket, itemCount: row.item_count, digest: row.bucket_digest });
  });
  return contentDigest({ domain: `cl-fts-feed-${kind}-manifest-v1`, buckets: normalized });
}

function documentFromRow(row: DocumentRow): IndexedDocument {
  const kind = row.kind;
  if (kind !== 'evidence' && kind !== 'claim') throw new Error('projection document kind is invalid');
  const canonicalId = decodeString(row.canonical_id_json, 'document canonical id');
  const scope = decodeString(row.scope_json, 'document scope');
  if (typeof row.search_text !== 'string' || safeSearchText(row.search_text) === undefined) {
    throw new Error(`projection document ${kind}/${canonicalId} contains unsafe search text`);
  }
  assertString(row.source_digest, 'document source digest');
  assertDigest(row.source_digest, 'document source digest');
  assertDigest(row.entry_digest, 'document entry digest');
  assertInteger(row.bucket, 'document bucket', 0);
  const lifecycle =
    kind === 'claim'
      ? row.lifecycle === 'active' || row.lifecycle === 'superseded'
        ? row.lifecycle
        : undefined
      : row.lifecycle === ''
        ? ''
        : undefined;
  if (lifecycle === undefined) throw new Error(`projection document ${kind}/${canonicalId} has invalid lifecycle`);
  const base = Object.freeze({
    canonicalId,
    kind,
    scope,
    lifecycle,
    sourceDigest: row.source_digest,
    searchText: row.search_text,
  });
  if (documentDigest(base) !== row.entry_digest) {
    throw new Error(`projection document integrity failed for ${kind}/${canonicalId}`);
  }
  return Object.freeze({ ...base, entryDigest: row.entry_digest });
}

function sameEvidenceRef(row: EvidenceStateRow, reference: EvidenceRef): boolean {
  if (
    row.availability !== 'available' ||
    row.support_eligible !== 1 ||
    row.authority !== reference.authority ||
    row.artifact_digest !== reference.contentHash
  ) {
    return false;
  }
  return row.source_groups_json === canonicalJson(reference.sourceGroups);
}

export class Fts5FeedConsumer {
  readonly #store: SqliteConsumerCheckpointStore;
  readonly #binding: Readonly<ConsumerBinding>;
  readonly #sensitivities: ReadonlySet<EvidenceRecord['sensitivity']>;
  readonly #indexClaimValues: boolean;
  readonly #bucketCount: number;
  readonly #configDigest: string;
  readonly #prefix: string;

  constructor(store: SqliteConsumerCheckpointStore, options: Fts5FeedConsumerOptions) {
    if (!(store instanceof SqliteConsumerCheckpointStore)) {
      throw new TypeError('Fts5FeedConsumer requires a SqliteConsumerCheckpointStore');
    }
    if (typeof options !== 'object' || options === null) {
      throw new TypeError('Fts5FeedConsumer options are required');
    }
    const consumerId = options.consumerId;
    const prefix = options.projectionTablePrefix;
    if (typeof consumerId !== 'string' || consumerId.trim().length === 0 || consumerId.includes('\u0000')) {
      throw new Error('consumerId must be a non-empty string without U+0000');
    }
    assertPrefix(prefix);
    const sensitivities = Object.freeze([...(options.searchableSensitivities ?? DEFAULT_SENSITIVITIES)]);
    if (sensitivities.length === 0 || new Set(sensitivities).size !== sensitivities.length) {
      throw new Error('searchableSensitivities must be non-empty and unique');
    }
    for (const sensitivity of sensitivities) {
      if (!['public', 'internal', 'personal', 'sensitive', 'secret'].includes(sensitivity)) {
        throw new Error(`unknown evidence sensitivity: ${String(sensitivity)}`);
      }
    }
    if (options.indexClaimValues !== undefined && typeof options.indexClaimValues !== 'boolean') {
      throw new TypeError('indexClaimValues must be boolean');
    }
    const bucketCount = options.bucketCount ?? DEFAULT_BUCKET_COUNT;
    if (!Number.isSafeInteger(bucketCount) || bucketCount < 16 || bucketCount > 4096) {
      throw new RangeError('bucketCount must be an integer in [16, 4096]');
    }
    this.#store = store;
    this.#prefix = prefix;
    this.#sensitivities = new Set(sensitivities);
    this.#indexClaimValues = options.indexClaimValues ?? false;
    this.#bucketCount = bucketCount;
    this.#configDigest = contentDigest({
      domain: 'cl-fts-feed-config-v1',
      schemaVersion: FEED_FTS_SCHEMA_VERSION,
      searchableSensitivities: [...this.#sensitivities].sort(),
      indexClaimValues: this.#indexClaimValues,
      bucketCount,
    });
    this.#binding = Object.freeze({
      consumerId,
      configurationDigest: this.#configDigest,
      projectionTablePrefix: prefix,
    });
  }

  get binding(): Readonly<ConsumerBinding> {
    return this.#binding;
  }

  get configurationDigest(): string {
    return this.#configDigest;
  }

  register(initialCursor: CanonicalReadCursor = canonicalGenesisCursor()): DurableConsumerRegistration {
    if (!sameCanonicalReadCursor(initialCursor, canonicalGenesisCursor())) {
      throw new Fts5FeedRebuildRequiredError(
        'FTS feed consumer v1 requires genesis bootstrap to guarantee complete lexical state',
      );
    }
    return this.#store.register({
      consumerId: this.#binding.consumerId,
      configurationDigest: this.#binding.configurationDigest,
      projectionTablePrefix: this.#binding.projectionTablePrefix,
      initialCursor,
    });
  }

  #tables() {
    const p = this.#prefix;
    return Object.freeze({
      meta: `${p}meta`,
      evidence: `${p}evidence_state`,
      claims: `${p}claim_state`,
      dependencies: `${p}dependencies`,
      documents: `${p}documents`,
      buckets: `${p}buckets`,
      fts: `${p}fts`,
    });
  }

  #ensureSchema(tx: ConsumerProjectionTransaction): void {
    const t = this.#tables();
    tx.run(`CREATE TABLE IF NOT EXISTS ${t.meta} (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL, config_digest TEXT NOT NULL, last_batch_id TEXT NOT NULL, after_cursor_digest TEXT NOT NULL, event_count INTEGER NOT NULL, document_count INTEGER NOT NULL, dependency_count INTEGER NOT NULL, document_manifest_digest TEXT NOT NULL, dependency_manifest_digest TEXT NOT NULL) STRICT`);
    tx.run(`CREATE TABLE IF NOT EXISTS ${t.evidence} (evidence_id_json TEXT PRIMARY KEY, scope_json TEXT NOT NULL, source_groups_json TEXT NOT NULL, authority TEXT NOT NULL, artifact_digest TEXT NOT NULL, availability TEXT NOT NULL, support_eligible INTEGER NOT NULL, search_text TEXT) STRICT`);
    tx.run(`CREATE TABLE IF NOT EXISTS ${t.claims} (claim_id_json TEXT PRIMARY KEY, scope_json TEXT NOT NULL, lifecycle TEXT NOT NULL, source_digest TEXT NOT NULL, search_text TEXT, evidence_refs_json TEXT NOT NULL) STRICT`);
    tx.run(`CREATE TABLE IF NOT EXISTS ${t.dependencies} (evidence_id_json TEXT NOT NULL, claim_id_json TEXT NOT NULL, bucket INTEGER NOT NULL, PRIMARY KEY (evidence_id_json, claim_id_json)) STRICT`);
    tx.run(`CREATE TABLE IF NOT EXISTS ${t.documents} (canonical_id_json TEXT NOT NULL, kind TEXT NOT NULL, scope_json TEXT NOT NULL, lifecycle TEXT NOT NULL, source_digest TEXT NOT NULL, search_text TEXT NOT NULL, entry_digest TEXT NOT NULL, bucket INTEGER NOT NULL, PRIMARY KEY (kind, canonical_id_json)) STRICT`);
    tx.run(`CREATE TABLE IF NOT EXISTS ${t.buckets} (manifest_kind TEXT NOT NULL, bucket INTEGER NOT NULL, item_count INTEGER NOT NULL, bucket_digest TEXT NOT NULL, PRIMARY KEY (manifest_kind, bucket)) STRICT`);
    tx.run(`CREATE VIRTUAL TABLE IF NOT EXISTS ${t.fts} USING fts5(canonical_id_json UNINDEXED, kind UNINDEXED, scope_json UNINDEXED, lifecycle UNINDEXED, source_digest UNINDEXED, entry_digest UNINDEXED, bucket UNINDEXED, search_text)`);
  }

  #initializeEmptyState(tx: ConsumerProjectionTransaction): void {
    const t = this.#tables();
    for (const table of [t.evidence, t.claims, t.dependencies, t.documents, t.buckets, t.fts]) {
      const row = tx.get(`SELECT COUNT(*) AS count FROM ${table}`) as { readonly count: unknown } | undefined;
      if (row === undefined || row.count !== 0) {
        throw new Fts5FeedRebuildRequiredError('FTS feed projection has structural rows without publication metadata');
      }
    }
    for (const kind of ['document', 'dependency'] as const) {
      for (let bucket = 0; bucket < this.#bucketCount; bucket += 1) {
        const domain = kind === 'document' ? 'cl-fts-feed-document-bucket-v1' : 'cl-fts-feed-dependency-bucket-v1';
        const emptyDigest = contentDigest({ domain, bucket, members: [] });
        tx.run(`INSERT INTO ${t.buckets} (manifest_kind, bucket, item_count, bucket_digest) VALUES (?, ?, ?, ?)`, kind, bucket, 0, emptyDigest);
      }
    }
  }

  #evidenceState(tx: ConsumerProjectionTransaction, evidenceId: string): EvidenceStateRow | undefined {
    const t = this.#tables();
    return tx.get(`SELECT evidence_id_json, scope_json, source_groups_json, authority, artifact_digest, availability, support_eligible, search_text FROM ${t.evidence} WHERE evidence_id_json = ?`, encodeString(evidenceId)) as EvidenceStateRow | undefined;
  }

  #claimState(tx: ConsumerProjectionTransaction, claimId: string): ClaimStateRow | undefined {
    const t = this.#tables();
    return tx.get(`SELECT claim_id_json, scope_json, lifecycle, source_digest, search_text, evidence_refs_json FROM ${t.claims} WHERE claim_id_json = ?`, encodeString(claimId)) as ClaimStateRow | undefined;
  }

  #deleteDocument(
    tx: ConsumerProjectionTransaction,
    kind: 'evidence' | 'claim',
    canonicalId: string,
    touched: Set<number>,
  ): void {
    const t = this.#tables();
    const encoded = encodeString(canonicalId);
    const existing = tx.get(`SELECT canonical_id_json, kind, scope_json, lifecycle, source_digest, search_text, entry_digest, bucket FROM ${t.documents} WHERE kind = ? AND canonical_id_json = ?`, kind, encoded) as DocumentRow | undefined;
    if (existing !== undefined) {
      assertInteger(existing.bucket, 'existing document bucket', 0);
      touched.add(existing.bucket);
    }
    tx.run(`DELETE FROM ${t.fts} WHERE kind = ? AND canonical_id_json = ?`, kind, encoded);
    tx.run(`DELETE FROM ${t.documents} WHERE kind = ? AND canonical_id_json = ?`, kind, encoded);
  }

  #upsertDocument(
    tx: ConsumerProjectionTransaction,
    document: IndexedDocument,
    touched: Set<number>,
  ): void {
    const t = this.#tables();
    const encodedId = encodeString(document.canonicalId);
    const encodedScope = encodeString(document.scope);
    const existing = tx.get(`SELECT canonical_id_json, kind, scope_json, lifecycle, source_digest, search_text, entry_digest, bucket FROM ${t.documents} WHERE kind = ? AND canonical_id_json = ?`, document.kind, encodedId) as DocumentRow | undefined;
    if (existing !== undefined) {
      assertInteger(existing.bucket, 'existing document bucket', 0);
      touched.add(existing.bucket);
    }
    const bucket = bucketFor(`${document.kind}\u0000${document.canonicalId}`, this.#bucketCount);
    touched.add(bucket);
    tx.run(`DELETE FROM ${t.fts} WHERE kind = ? AND canonical_id_json = ?`, document.kind, encodedId);
    tx.run(`DELETE FROM ${t.documents} WHERE kind = ? AND canonical_id_json = ?`, document.kind, encodedId);
    tx.run(`INSERT INTO ${t.documents} (canonical_id_json, kind, scope_json, lifecycle, source_digest, search_text, entry_digest, bucket) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, encodedId, document.kind, encodedScope, document.lifecycle, document.sourceDigest, document.searchText, document.entryDigest, bucket);
    tx.run(`INSERT INTO ${t.fts} (canonical_id_json, kind, scope_json, lifecycle, source_digest, entry_digest, bucket, search_text) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, encodedId, document.kind, encodedScope, document.lifecycle, document.sourceDigest, document.entryDigest, bucket, document.searchText);
  }

  #documentForEvidence(row: EvidenceStateRow): IndexedDocument | undefined {
    if (row.availability !== 'available' || row.support_eligible !== 1 || typeof row.search_text !== 'string') {
      return undefined;
    }
    const canonicalId = decodeString(row.evidence_id_json, 'evidence state id');
    const scope = decodeString(row.scope_json, 'evidence state scope');
    assertDigest(row.artifact_digest, 'evidence artifact digest');
    const searchText = safeSearchText(row.search_text);
    if (searchText === undefined) return undefined;
    const base = Object.freeze({
      canonicalId,
      kind: 'evidence' as const,
      scope,
      lifecycle: '' as const,
      sourceDigest: row.artifact_digest,
      searchText,
    });
    return Object.freeze({ ...base, entryDigest: documentDigest(base) });
  }

  #documentForClaim(row: ClaimStateRow): IndexedDocument | undefined {
    if ((row.lifecycle !== 'active' && row.lifecycle !== 'superseded') || typeof row.search_text !== 'string') {
      return undefined;
    }
    const canonicalId = decodeString(row.claim_id_json, 'claim state id');
    const scope = decodeString(row.scope_json, 'claim state scope');
    assertDigest(row.source_digest, 'claim source digest');
    const searchText = safeSearchText(row.search_text);
    if (searchText === undefined) return undefined;
    const base = Object.freeze({
      canonicalId,
      kind: 'claim' as const,
      scope,
      lifecycle: row.lifecycle,
      sourceDigest: row.source_digest,
      searchText,
    });
    return Object.freeze({ ...base, entryDigest: documentDigest(base) });
  }

  #refreshClaimDocument(
    tx: ConsumerProjectionTransaction,
    claimId: string,
    touched: Set<number>,
  ): void {
    const row = this.#claimState(tx, claimId);
    if (row === undefined) throw new Error(`unknown claim state: ${claimId}`);
    const document = this.#documentForClaim(row);
    if (document === undefined) this.#deleteDocument(tx, 'claim', claimId, touched);
    else this.#upsertDocument(tx, document, touched);
  }

  #clearClaimSearchText(
    tx: ConsumerProjectionTransaction,
    claimId: string,
    touched: Set<number>,
  ): void {
    const t = this.#tables();
    const encoded = encodeString(claimId);
    const row = this.#claimState(tx, claimId);
    if (row === undefined) return;
    tx.run(`UPDATE ${t.claims} SET search_text = ? WHERE claim_id_json = ?`, null, encoded);
    this.#deleteDocument(tx, 'claim', claimId, touched);
  }

  #claimSearchTextIfEligible(tx: ConsumerProjectionTransaction, claim: ClaimRecord): string | undefined {
    if (claim.evidence.length === 0) return undefined;
    for (const reference of claim.evidence) {
      const state = this.#evidenceState(tx, reference.sourceId);
      if (state === undefined || !sameEvidenceRef(state, reference)) return undefined;
    }
    return safeSearchText(claimText(claim, this.#indexClaimValues));
  }

  #processEvent(
    tx: ConsumerProjectionTransaction,
    event: MemoryEvent,
    touchedDocuments: Set<number>,
    touchedDependencies: Set<number>,
  ): void {
    const t = this.#tables();
    switch (event.type) {
      case 'evidence.captured': {
        const record = event.data.evidence;
        if (this.#evidenceState(tx, record.id) !== undefined) {
          throw new Error(`duplicate evidence state in FTS feed consumer: ${record.id}`);
        }
        const supportEligible =
          this.#sensitivities.has(record.sensitivity) && !record.taints.includes('secret-detected');
        const searchText =
          supportEligible && record.preview !== undefined
            ? safeSearchText(evidenceText(record))
            : undefined;
        tx.run(`INSERT INTO ${t.evidence} (evidence_id_json, scope_json, source_groups_json, authority, artifact_digest, availability, support_eligible, search_text) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          encodeString(record.id), encodeString(record.scope), canonicalJson(record.sourceGroups), record.authority,
          record.artifact.digest, 'available', supportEligible ? 1 : 0, searchText ?? null);
        const state = this.#evidenceState(tx, record.id);
        if (state === undefined) throw new Error(`failed to persist evidence state: ${record.id}`);
        const document = this.#documentForEvidence(state);
        if (document !== undefined) this.#upsertDocument(tx, document, touchedDocuments);
        return;
      }
      case 'evidence.availability-changed': {
        const state = this.#evidenceState(tx, event.data.evidenceId);
        if (state === undefined) throw new Error(`unknown evidence state: ${event.data.evidenceId}`);
        const previous = state.availability;
        if (previous !== 'available' && event.data.availability === 'available' && state.support_eligible === 1) {
          const dependent = tx.all(`SELECT evidence_id_json, claim_id_json, bucket FROM ${t.dependencies} WHERE evidence_id_json = ? ORDER BY claim_id_json`, encodeString(event.data.evidenceId)) as readonly DependencyRow[];
          if (typeof state.search_text !== 'string' || dependent.length > 0) {
            throw new Fts5FeedRebuildRequiredError(
              'restoring searchable evidence requires a genesis rebuild because plaintext was intentionally discarded',
              event.data.evidenceId,
            );
          }
        }
        tx.run(`UPDATE ${t.evidence} SET availability = ?, search_text = ? WHERE evidence_id_json = ?`, event.data.availability, event.data.availability === 'available' ? state.search_text as string | null : null, encodeString(event.data.evidenceId));
        if (event.data.availability !== 'available') {
          this.#deleteDocument(tx, 'evidence', event.data.evidenceId, touchedDocuments);
          const dependents = tx.all(`SELECT evidence_id_json, claim_id_json, bucket FROM ${t.dependencies} WHERE evidence_id_json = ? ORDER BY claim_id_json`, encodeString(event.data.evidenceId)) as readonly DependencyRow[];
          for (const dependency of dependents) {
            const claimId = decodeString(dependency.claim_id_json, 'dependency claim id');
            this.#clearClaimSearchText(tx, claimId, touchedDocuments);
          }
        }
        return;
      }
      case 'claim.asserted': {
        const claim = event.data.claim;
        if (this.#claimState(tx, claim.id) !== undefined) {
          throw new Error(`duplicate claim state in FTS feed consumer: ${claim.id}`);
        }
        const searchText = this.#claimSearchTextIfEligible(tx, claim);
        tx.run(`INSERT INTO ${t.claims} (claim_id_json, scope_json, lifecycle, source_digest, search_text, evidence_refs_json) VALUES (?, ?, ?, ?, ?, ?)`,
          encodeString(claim.id), encodeString(claim.key.scope), event.data.initialLifecycle,
          contentDigest(claim), searchText ?? null, canonicalJson(claim.evidence));
        for (const reference of claim.evidence) {
          const evidenceEncoded = encodeString(reference.sourceId);
          const claimEncoded = encodeString(claim.id);
          const bucket = bucketFor(`${reference.sourceId}\u0000${claim.id}`, this.#bucketCount);
          tx.run(`INSERT INTO ${t.dependencies} (evidence_id_json, claim_id_json, bucket) VALUES (?, ?, ?)`, evidenceEncoded, claimEncoded, bucket);
          touchedDependencies.add(bucket);
        }
        if (event.data.initialLifecycle === 'active') this.#refreshClaimDocument(tx, claim.id, touchedDocuments);
        return;
      }
      case 'claim.admitted': {
        const row = this.#claimState(tx, event.data.claimId);
        if (row === undefined) throw new Error(`unknown claim state: ${event.data.claimId}`);
        if (row.lifecycle !== 'quarantined') throw new Error(`claim ${event.data.claimId} is not quarantined in FTS state`);
        tx.run(`UPDATE ${t.claims} SET lifecycle = ? WHERE claim_id_json = ?`, 'active', encodeString(event.data.claimId));
        this.#refreshClaimDocument(tx, event.data.claimId, touchedDocuments);
        return;
      }
      case 'claim.superseded': {
        const previous = this.#claimState(tx, event.data.previousClaimId);
        const replacement = this.#claimState(tx, event.data.replacementClaimId);
        if (previous === undefined || replacement === undefined) throw new Error('FTS claim supersession requires both claim states');
        if (previous.lifecycle !== 'active' || replacement.lifecycle !== 'active') throw new Error('FTS claim supersession requires active claims');
        tx.run(`UPDATE ${t.claims} SET lifecycle = ? WHERE claim_id_json = ?`, 'superseded', encodeString(event.data.previousClaimId));
        this.#refreshClaimDocument(tx, event.data.previousClaimId, touchedDocuments);
        this.#refreshClaimDocument(tx, event.data.replacementClaimId, touchedDocuments);
        return;
      }
      case 'claim.revoked': {
        const row = this.#claimState(tx, event.data.claimId);
        if (row === undefined) throw new Error(`unknown claim state: ${event.data.claimId}`);
        tx.run(`UPDATE ${t.claims} SET lifecycle = ?, search_text = ? WHERE claim_id_json = ?`, 'revoked', null, encodeString(event.data.claimId));
        this.#deleteDocument(tx, 'claim', event.data.claimId, touchedDocuments);
        return;
      }
      case 'association.added':
      case 'outcome.recorded':
        return;
    }
  }

  #refreshBucket(
    tx: ConsumerProjectionTransaction,
    kind: 'document' | 'dependency',
    bucket: number,
  ): void {
    const t = this.#tables();
    if (kind === 'document') {
      const rows = tx.all(`SELECT canonical_id_json, kind, scope_json, lifecycle, source_digest, search_text, entry_digest, bucket FROM ${t.documents} WHERE bucket = ? ORDER BY kind, canonical_id_json`, bucket) as readonly DocumentRow[];
      const digest = documentBucketDigest(bucket, rows);
      tx.run(`UPDATE ${t.buckets} SET item_count = ?, bucket_digest = ? WHERE manifest_kind = ? AND bucket = ?`, rows.length, digest, kind, bucket);
    } else {
      const rows = tx.all(`SELECT evidence_id_json, claim_id_json, bucket FROM ${t.dependencies} WHERE bucket = ? ORDER BY evidence_id_json, claim_id_json`, bucket) as readonly DependencyRow[];
      const digest = dependencyBucketDigest(bucket, rows);
      tx.run(`UPDATE ${t.buckets} SET item_count = ?, bucket_digest = ? WHERE manifest_kind = ? AND bucket = ?`, rows.length, digest, kind, bucket);
    }
  }

  #verifyDocumentBucket(tx: ConsumerProjectionReadTransaction, bucket: number): void {
    if (!Number.isSafeInteger(bucket) || bucket < 0 || bucket >= this.#bucketCount) {
      throw new Error('FTS feed document bucket is out of range');
    }
    const t = this.#tables();
    const rows = tx.all(`SELECT canonical_id_json, kind, scope_json, lifecycle, source_digest, search_text, entry_digest, bucket FROM ${t.documents} WHERE bucket = ? ORDER BY kind, canonical_id_json`, bucket) as readonly DocumentRow[];
    const manifest = tx.get(`SELECT manifest_kind, bucket, item_count, bucket_digest FROM ${t.buckets} WHERE manifest_kind = ? AND bucket = ?`, 'document', bucket) as BucketRow | undefined;
    if (manifest === undefined || manifest.manifest_kind !== 'document') {
      throw new Error(`FTS feed document bucket ${bucket} manifest is missing`);
    }
    assertInteger(manifest.bucket, 'FTS feed document bucket', 0);
    assertInteger(manifest.item_count, 'FTS feed document bucket count', 0);
    assertDigest(manifest.bucket_digest, 'FTS feed document bucket digest');
    if (
      manifest.bucket !== bucket ||
      manifest.item_count !== rows.length ||
      manifest.bucket_digest !== documentBucketDigest(bucket, rows)
    ) {
      throw new Error(`FTS feed document bucket ${bucket} failed integrity verification`);
    }
  }

  #bucketRows(tx: ConsumerProjectionReadTransaction, kind: 'document' | 'dependency'): readonly BucketRow[] {
    const t = this.#tables();
    const rows = tx.all(`SELECT manifest_kind, bucket, item_count, bucket_digest FROM ${t.buckets} WHERE manifest_kind = ? ORDER BY bucket`, kind) as readonly BucketRow[];
    if (rows.length !== this.#bucketCount) throw new Error(`${kind} bucket manifest is incomplete`);
    return rows;
  }

  #meta(tx: ConsumerProjectionReadTransaction): MetaRow | undefined {
    const t = this.#tables();
    return tx.get(`SELECT schema_version, config_digest, last_batch_id, after_cursor_digest, event_count, document_count, dependency_count, document_manifest_digest, dependency_manifest_digest FROM ${t.meta} WHERE id = ?`, 1) as MetaRow | undefined;
  }

  #writeMeta(tx: ConsumerProjectionTransaction, batch: CanonicalAppendBatch): void {
    const t = this.#tables();
    const documentBuckets = this.#bucketRows(tx, 'document');
    const dependencyBuckets = this.#bucketRows(tx, 'dependency');
    const documentManifest = rootManifest('document', documentBuckets);
    const dependencyManifest = rootManifest('dependency', dependencyBuckets);
    const documentCount = documentBuckets.reduce((sum, row) => sum + (row.item_count as number), 0);
    const dependencyCount = dependencyBuckets.reduce((sum, row) => sum + (row.item_count as number), 0);
    tx.run(`DELETE FROM ${t.meta} WHERE id = ?`, 1);
    tx.run(`INSERT INTO ${t.meta} (id, schema_version, config_digest, last_batch_id, after_cursor_digest, event_count, document_count, dependency_count, document_manifest_digest, dependency_manifest_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      1, FEED_FTS_SCHEMA_VERSION, this.#configDigest, batch.id, canonicalReadCursorDigest(batch.after),
      batch.after.eventCount, documentCount, dependencyCount, documentManifest, dependencyManifest);
  }

  apply(feed: CanonicalChangeFeed, batch: CanonicalAppendBatch) {
    return this.#store.apply(feed, batch, this.#binding, (tx, authorizedBatch) => {
      this.#ensureSchema(tx);
      const previousMeta = this.#meta(tx);
      if (previousMeta === undefined) this.#initializeEmptyState(tx);
      if (previousMeta !== undefined) {
        assertInteger(previousMeta.schema_version, 'FTS feed schema version', 1);
        if (previousMeta.schema_version !== FEED_FTS_SCHEMA_VERSION) throw new Fts5FeedRebuildRequiredError('FTS feed schema version changed');
        if (previousMeta.config_digest !== this.#configDigest) throw new Fts5FeedRebuildRequiredError('FTS feed configuration changed');
        assertInteger(previousMeta.event_count, 'FTS feed event count', 0);
        if (previousMeta.event_count !== authorizedBatch.base.eventCount) throw new Error('FTS feed metadata does not match the batch base');
      } else if (authorizedBatch.base.eventCount !== 0) {
        throw new Fts5FeedRebuildRequiredError('FTS feed structural state is absent for a non-genesis checkpoint');
      }

      const touchedDocuments = new Set<number>();
      const touchedDependencies = new Set<number>();
      for (const event of authorizedBatch.events) {
        this.#processEvent(tx, event, touchedDocuments, touchedDependencies);
      }
      for (const bucket of touchedDocuments) this.#refreshBucket(tx, 'document', bucket);
      for (const bucket of touchedDependencies) this.#refreshBucket(tx, 'dependency', bucket);
      this.#writeMeta(tx, authorizedBatch);
      return Object.freeze({
        appliedEvents: authorizedBatch.events.length,
        touchedDocumentBuckets: touchedDocuments.size,
        touchedDependencyBuckets: touchedDependencies.size,
      });
    });
  }

  #statusFromRead(
    tx: ConsumerProjectionReadTransaction,
    checkpoint: DurableConsumerCheckpoint,
    registration?: DurableConsumerRegistration,
  ): Fts5FeedStatus {
    const meta = this.#meta(tx);
    if (meta === undefined) {
      return Object.freeze({ initialized: false, fresh: false, reason: 'FTS feed projection has not consumed a batch', checkpoint, documentCount: 0, dependencyCount: 0 });
    }
    assertInteger(meta.schema_version, 'FTS feed schema version', 1);
    assertInteger(meta.event_count, 'FTS feed event count', 0);
    assertInteger(meta.document_count, 'FTS feed document count', 0);
    assertInteger(meta.dependency_count, 'FTS feed dependency count', 0);
    assertString(meta.config_digest, 'FTS feed configuration digest');
    assertString(meta.last_batch_id, 'FTS feed last batch id');
    assertDigest(meta.after_cursor_digest, 'FTS feed cursor digest');
    assertDigest(meta.document_manifest_digest, 'FTS feed document manifest');
    assertDigest(meta.dependency_manifest_digest, 'FTS feed dependency manifest');
    const documentBuckets = this.#bucketRows(tx, 'document');
    const dependencyBuckets = this.#bucketRows(tx, 'dependency');
    const documentManifest = rootManifest('document', documentBuckets);
    const dependencyManifest = rootManifest('dependency', dependencyBuckets);
    const documentCount = documentBuckets.reduce((sum, row) => sum + (row.item_count as number), 0);
    const dependencyCount = dependencyBuckets.reduce((sum, row) => sum + (row.item_count as number), 0);
    const fresh =
      meta.schema_version === FEED_FTS_SCHEMA_VERSION &&
      meta.config_digest === this.#configDigest &&
      meta.last_batch_id === checkpoint.lastBatchId &&
      meta.after_cursor_digest === checkpoint.cursorDigest &&
      meta.event_count === checkpoint.cursor.eventCount &&
      meta.document_count === documentCount &&
      meta.dependency_count === dependencyCount &&
      meta.document_manifest_digest === documentManifest &&
      meta.dependency_manifest_digest === dependencyManifest;
    return Object.freeze({
      initialized: true,
      fresh,
      reason: fresh ? 'FTS feed projection matches the durable consumer checkpoint' : 'FTS feed metadata or manifest does not match the durable consumer checkpoint',
      ...(registration === undefined ? {} : { registration }),
      checkpoint,
      documentCount,
      dependencyCount,
    });
  }

  status(): Fts5FeedStatus {
    const checkpoint = this.#store.checkpoint(this.#binding.consumerId);
    if (checkpoint === undefined) {
      const registration = this.#store.registration(this.#binding.consumerId);
      return Object.freeze({ initialized: false, fresh: false, reason: 'FTS feed consumer has no durable checkpoint', ...(registration === undefined ? {} : { registration }), documentCount: 0, dependencyCount: 0 });
    }
    const registration = this.#store.registration(this.#binding.consumerId);
    return this.#store.readProjection(this.#binding, (tx) => this.#statusFromRead(tx, checkpoint, registration));
  }

  search(
    feed: CanonicalChangeFeed,
    query: string,
    options: Fts5FeedSearchOptions,
  ): readonly Fts5FeedSearchCandidate[] {
    if (!(feed instanceof CanonicalChangeFeed)) {
      throw new TypeError('FTS feed search requires the canonical change feed that observes the durable ledger');
    }
    const scopeChain = snapshotScopeChain(options.scopeChain);
    const limit = options.limit ?? DEFAULT_LIMIT;
    if (!Number.isSafeInteger(limit) || limit <= 0 || limit > MAX_LIMIT) {
      throw new RangeError(`FTS feed result limit must be in [1, ${MAX_LIMIT}]`);
    }
    const match = safeMatchQuery(query, options.maxQueryTokens);
    const lifecycle = normalizeClaimLifecycleFilter(options.claimLifecycle);
    const checkpoint = this.#store.checkpoint(this.#binding.consumerId);
    if (checkpoint === undefined) throw new Error('FTS feed projection has no durable consumer checkpoint');
    const durableTail = feed.status().durableTail;
    if (!sameCanonicalReadCursor(checkpoint.cursor, durableTail)) {
      throw new Error('FTS feed projection is behind the current canonical ledger tail');
    }
    return this.#store.readProjection(this.#binding, (tx) => {
      const status = this.#statusFromRead(tx, checkpoint);
      if (!status.fresh) throw new Error(`FTS feed projection is unavailable: ${status.reason}`);
      const t = this.#tables();
      const placeholders = scopeChain.map(() => '?').join(', ');
      const encodedScopes = scopeChain.map(encodeString);
      const lifecycleClause = lifecycle === 'active-only' ? `AND (kind <> ? OR lifecycle = ?)` : '';
      const parameters: (string | number)[] = [match, ...encodedScopes];
      if (lifecycle === 'active-only') parameters.push('claim', 'active');
      parameters.push(limit + 1);
      const rows = tx.all(`SELECT canonical_id_json, kind, scope_json, lifecycle, source_digest, entry_digest, bucket, search_text, bm25(${t.fts}) AS fts_score FROM ${t.fts} WHERE ${t.fts} MATCH ? AND scope_json IN (${placeholders}) ${lifecycleClause} ORDER BY fts_score ASC, kind ASC, canonical_id_json ASC, rowid ASC LIMIT ?`, ...parameters) as readonly FtsRow[];
      const selectedBuckets = new Set<number>();
      for (const row of rows) {
        assertInteger(row.bucket, 'FTS feed selected document bucket', 0);
        selectedBuckets.add(row.bucket);
      }
      for (const bucket of selectedBuckets) this.#verifyDocumentBucket(tx, bucket);

      const seen = new Set<string>();
      const verified = rows.map((row, index) => {
        const document = documentFromRow(row);
        if (typeof row.fts_score !== 'number' || !Number.isFinite(row.fts_score)) throw new Error('FTS feed returned malformed BM25 score');
        const identity = `${document.kind}\u0000${document.canonicalId}`;
        if (seen.has(identity)) throw new Error(`duplicate FTS feed row: ${document.kind}/${document.canonicalId}`);
        seen.add(identity);
        const canonical = tx.get(`SELECT canonical_id_json, kind, scope_json, lifecycle, source_digest, search_text, entry_digest, bucket FROM ${t.documents} WHERE kind = ? AND canonical_id_json = ?`, document.kind, encodeString(document.canonicalId)) as DocumentRow | undefined;
        if (canonical === undefined) throw new Error(`FTS feed shadow row has no document: ${document.kind}/${document.canonicalId}`);
        const canonicalDocument = documentFromRow(canonical);
        if (canonicalDocument.entryDigest !== document.entryDigest || canonicalDocument.searchText !== document.searchText || canonicalDocument.scope !== document.scope || canonicalDocument.lifecycle !== document.lifecycle) {
          throw new Error(`FTS feed shadow row diverged for ${document.kind}/${document.canonicalId}`);
        }
        return Object.freeze({
          canonicalId: document.canonicalId,
          kind: document.kind,
          scope: document.scope,
          ...(document.kind === 'claim' ? { lifecycle: document.lifecycle as Extract<ClaimLifecycle, 'active' | 'superseded'> } : {}),
          rank: index + 1,
          score: -(row.fts_score as number),
          entryDigest: document.entryDigest,
          consumerRevision: checkpoint.revision,
          consumerCursorDigest: checkpoint.cursorDigest,
          lastBatchId: checkpoint.lastBatchId,
          configurationDigest: checkpoint.configurationDigest,
        });
      });
      return Object.freeze(verified.slice(0, limit));
    });
  }

  rehydrate(
    events: readonly MemoryEvent[],
    candidates: readonly Fts5FeedSearchCandidate[],
    options: Pick<Fts5FeedSearchOptions, 'scopeChain' | 'claimLifecycle'>,
  ): readonly Fts5FeedRehydratedCandidate[] {
    if (!Array.isArray(candidates)) throw new TypeError('FTS feed candidates must be an array');
    if (candidates.length > MAX_REHYDRATE) throw new RangeError(`FTS feed rehydration cannot exceed ${MAX_REHYDRATE} candidates`);
    const snapshot = Object.freeze(Array.from(candidates, (candidate) => Object.freeze({ ...candidate })));
    const scopeChain = snapshotScopeChain(options.scopeChain);
    const allowedScopes = new Set(scopeChain);
    const lifecycleFilter = normalizeClaimLifecycleFilter(options.claimLifecycle);
    const cursor = canonicalReadCursorForEvents(events);
    const cursorDigest = canonicalReadCursorDigest(cursor);
    const documents = new Map(
      buildDocuments(events, this.#sensitivities, this.#indexClaimValues).map((document) => [
        `${document.kind}\u0000${document.canonicalId}`,
        document,
      ]),
    );
    const evidence = EvidenceProjection.from(events);
    const claims = ClaimProjection.from(events);
    const seen = new Set<string>();
    return Object.freeze(snapshot.map((candidate) => {
      if (candidate.kind !== 'evidence' && candidate.kind !== 'claim') throw new Error('FTS feed candidate has invalid kind');
      if (!allowedScopes.has(candidate.scope)) throw new Error(`FTS feed candidate scope is not authorized: ${candidate.scope}`);
      if (candidate.consumerCursorDigest !== cursorDigest) throw new Error(`FTS feed candidate ${candidate.canonicalId} is stale`);
      if (candidate.configurationDigest !== this.#configDigest) throw new Error(`FTS feed candidate ${candidate.canonicalId} uses a different projection policy`);
      const identity = `${candidate.kind}\u0000${candidate.canonicalId}`;
      if (seen.has(identity)) throw new Error(`duplicate FTS feed candidate: ${candidate.kind}/${candidate.canonicalId}`);
      seen.add(identity);
      const document = documents.get(identity);
      if (document === undefined || document.scope !== candidate.scope || document.entryDigest !== candidate.entryDigest) {
        throw new Error(`FTS feed candidate ${candidate.canonicalId} failed canonical rehydration`);
      }
      if (candidate.kind === 'claim') {
        if (candidate.lifecycle !== document.lifecycle) throw new Error(`FTS feed claim ${candidate.canonicalId} lifecycle changed`);
        if (lifecycleFilter === 'active-only' && candidate.lifecycle !== 'active') throw new Error(`FTS feed claim ${candidate.canonicalId} is not active`);
        const claim = claims.get(candidate.canonicalId);
        if (claim === undefined) throw new Error(`FTS feed claim ${candidate.canonicalId} is missing from canonical memory`);
        return Object.freeze({ candidate, claim });
      }
      const projected = evidence.get(candidate.canonicalId);
      if (projected === undefined || !evidence.isAvailable(candidate.canonicalId)) throw new Error(`FTS feed evidence ${candidate.canonicalId} is unavailable`);
      return Object.freeze({ candidate, evidence: projected.record });
    }));
  }

  audit(): Fts5FeedAudit {
    const checkpoint = this.#store.checkpoint(this.#binding.consumerId);
    if (checkpoint === undefined) return Object.freeze({ ok: false, errors: Object.freeze(['FTS feed consumer has no checkpoint']), documentCount: 0, dependencyCount: 0 });
    return this.#store.readProjection(this.#binding, (tx) => {
      const errors: string[] = [];
      const t = this.#tables();
      let documentCount = 0;
      let dependencyCount = 0;
      try {
        const status = this.#statusFromRead(tx, checkpoint);
        if (!status.fresh) errors.push(status.reason);
        const documents = tx.all(`SELECT canonical_id_json, kind, scope_json, lifecycle, source_digest, search_text, entry_digest, bucket FROM ${t.documents} ORDER BY kind, canonical_id_json`) as readonly DocumentRow[];
        documentCount = documents.length;
        const documentMap = new Map<string, IndexedDocument>();
        for (const row of documents) {
          const document = documentFromRow(row);
          const identity = `${document.kind}\u0000${document.canonicalId}`;
          if (documentMap.has(identity)) throw new Error(`duplicate FTS feed document: ${identity}`);
          documentMap.set(identity, document);
        }
        const ftsRows = tx.all(`SELECT canonical_id_json, kind, scope_json, lifecycle, source_digest, entry_digest, bucket, search_text, 0 AS fts_score FROM ${t.fts} ORDER BY kind, canonical_id_json, rowid`) as readonly FtsRow[];
        const seenFts = new Set<string>();
        for (const row of ftsRows) {
          const document = documentFromRow(row);
          const identity = `${document.kind}\u0000${document.canonicalId}`;
          if (seenFts.has(identity)) throw new Error(`duplicate FTS feed shadow row: ${identity}`);
          seenFts.add(identity);
          const canonical = documentMap.get(identity);
          if (canonical === undefined || canonical.entryDigest !== document.entryDigest || canonical.searchText !== document.searchText || canonical.scope !== document.scope || canonical.lifecycle !== document.lifecycle) {
            throw new Error(`FTS feed shadow parity failed for ${identity}`);
          }
        }
        if (seenFts.size !== documentMap.size) throw new Error('FTS feed shadow row count differs from document row count');
        const dependencies = tx.all(`SELECT evidence_id_json, claim_id_json, bucket FROM ${t.dependencies} ORDER BY evidence_id_json, claim_id_json`) as readonly DependencyRow[];
        dependencyCount = dependencies.length;
        for (const row of dependencies) {
          decodeString(row.evidence_id_json, 'dependency evidence id');
          decodeString(row.claim_id_json, 'dependency claim id');
          assertInteger(row.bucket, 'dependency bucket', 0);
        }
        for (let bucket = 0; bucket < this.#bucketCount; bucket += 1) {
          const docs = documents.filter((row) => row.bucket === bucket);
          const deps = dependencies.filter((row) => row.bucket === bucket);
          const docBucket = tx.get(`SELECT manifest_kind, bucket, item_count, bucket_digest FROM ${t.buckets} WHERE manifest_kind = ? AND bucket = ?`, 'document', bucket) as BucketRow | undefined;
          const depBucket = tx.get(`SELECT manifest_kind, bucket, item_count, bucket_digest FROM ${t.buckets} WHERE manifest_kind = ? AND bucket = ?`, 'dependency', bucket) as BucketRow | undefined;
          if (docBucket === undefined || depBucket === undefined) throw new Error(`FTS feed bucket ${bucket} is missing`);
          assertInteger(docBucket.item_count, 'document bucket count', 0);
          assertInteger(depBucket.item_count, 'dependency bucket count', 0);
          if (docBucket.item_count !== docs.length || docBucket.bucket_digest !== documentBucketDigest(bucket, docs)) throw new Error(`FTS feed document bucket ${bucket} failed audit`);
          if (depBucket.item_count !== deps.length || depBucket.bucket_digest !== dependencyBucketDigest(bucket, deps)) throw new Error(`FTS feed dependency bucket ${bucket} failed audit`);
        }
      } catch (error) {
        errors.push(error instanceof Error ? error.message : 'unknown FTS feed audit failure');
      }
      return Object.freeze({ ok: errors.length === 0, errors: Object.freeze(errors), documentCount, dependencyCount });
    });
  }
}
