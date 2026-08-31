import type {
  ClaimRecord,
  EvidenceRecord,
  MemoryEvent,
} from '../domain.js';
import {
  CanonicalChangeFeed,
  canonicalGenesisCursor,
  canonicalReadCursorDigest,
  sameCanonicalReadCursor,
  type CanonicalAppendBatch,
  type CanonicalReadCursor,
} from '../durable/change-feed.js';
import {
  SqliteConsumerCheckpointStore,
  type ConsumerApplyResult,
  type ConsumerBinding,
  type ConsumerProjectionReadTransaction,
  type ConsumerProjectionTransaction,
  type DurableConsumerCheckpoint,
  type DurableConsumerRegistration,
} from '../durable/consumer-store.js';
import { canonicalJson, contentDigest } from './canonical.js';
import {
  CANONICAL_OBJECT_READ_INDEX_SCHEMA_VERSION,
  CanonicalObjectReadIndexIntegrityError,
  CanonicalObjectReadIndexRebuildRequiredError,
  DEFAULT_OBJECT_READ_BUCKET_BITS,
  MAX_OBJECT_READ_BUCKET_BITS,
  MIN_OBJECT_READ_BUCKET_BITS,
  type CanonicalObjectKind,
  type CanonicalObjectReadIndexApplySummary,
  type CanonicalObjectReadIndexCatchUpSummary,
  type CanonicalObjectReadIndexOptions,
  type CanonicalObjectReadIndexStatus,
  type DecodedObjectReadHead,
  type DecodedObjectReadVersion,
  type IndexedCanonicalObjectState,
  type IndexedClaimState,
  type IndexedEvidenceState,
  type ObjectReadBucketRow,
  type ObjectReadContext,
  type ObjectReadHeadRow,
  type ObjectReadMetaRow,
  type ObjectReadNodeRow,
  type ObjectReadTreeKind,
  type ObjectReadTreeValue,
  type ObjectReadVersionRow,
  type VerifiedObjectReadMeta,
} from './object-read-index-contract.js';
import {
  assertDigest,
  assertInteger,
  assertObjectKind,
  assertProjectionPrefix,
  assertTreeKind,
  bucketForObject,
  canonicalClone,
  decodeHeadRow,
  decodeNodeRow,
  decodeString,
  decodeVersionRow,
  deepFreeze,
  encodeString,
  headBucketDigest,
  indexedStateDigest,
  objectHeadDigest,
  objectVersionDigest,
  sparseEmptyDigests,
  sparseInternalDigest,
  sparseLeafDigest,
  versionBucketDigest,
} from './object-read-index-integrity.js';

interface ProjectionTables {
  readonly meta: string;
  readonly heads: string;
  readonly versions: string;
  readonly buckets: string;
  readonly nodes: string;
}

interface EventProjectionDelta {
  readonly changedObjects: number;
  readonly newHeads: number;
  readonly newVersions: number;
}

interface AppendStateResult {
  readonly createdHead: boolean;
}

/**
 * Durable projection and sparse-integrity layer for selected canonical object reads.
 * The public read API is implemented by `CanonicalObjectReadIndex` in the sibling module.
 */
export class CanonicalObjectReadIndexStorage {
  protected readonly _store: SqliteConsumerCheckpointStore;
  protected readonly _binding: Readonly<ConsumerBinding>;
  protected readonly _prefix: string;
  protected readonly _bucketBits: number;
  protected readonly _bucketCount: number;
  protected readonly _configurationDigest: string;
  protected readonly _emptyDigests: Readonly<Record<ObjectReadTreeKind, readonly string[]>>;

  constructor(store: SqliteConsumerCheckpointStore, options: CanonicalObjectReadIndexOptions) {
    if (!(store instanceof SqliteConsumerCheckpointStore)) {
      throw new TypeError('CanonicalObjectReadIndex requires a SqliteConsumerCheckpointStore');
    }
    if (typeof options !== 'object' || options === null) {
      throw new TypeError('CanonicalObjectReadIndex options are required');
    }
    const consumerId = options.consumerId;
    if (
      typeof consumerId !== 'string' ||
      consumerId.trim().length === 0 ||
      consumerId.includes('\u0000')
    ) {
      throw new Error('consumerId must be a non-empty string without U+0000');
    }
    const prefix = options.projectionTablePrefix;
    assertProjectionPrefix(prefix);
    const bucketBits = options.bucketBits ?? DEFAULT_OBJECT_READ_BUCKET_BITS;
    if (
      !Number.isSafeInteger(bucketBits) ||
      bucketBits < MIN_OBJECT_READ_BUCKET_BITS ||
      bucketBits > MAX_OBJECT_READ_BUCKET_BITS
    ) {
      throw new RangeError(
        `bucketBits must be an integer in [${MIN_OBJECT_READ_BUCKET_BITS}, ${MAX_OBJECT_READ_BUCKET_BITS}]`,
      );
    }
    const configurationDigest = contentDigest({
      domain: 'cl-canonical-object-read-index-config-v1',
      schemaVersion: CANONICAL_OBJECT_READ_INDEX_SCHEMA_VERSION,
      bucketBits,
      transactionIntervals: 'recorded-at-half-open-v1',
      privacyView: 'current-availability-overlay-v1',
      sparseIntegrity: 'authenticated-buckets-v1',
    });
    this._store = store;
    this._prefix = prefix;
    this._bucketBits = bucketBits;
    this._bucketCount = 2 ** bucketBits;
    this._configurationDigest = configurationDigest;
    this._binding = Object.freeze({
      consumerId,
      configurationDigest,
      projectionTablePrefix: prefix,
    });
    this._emptyDigests = Object.freeze({
      head: sparseEmptyDigests('head', bucketBits),
      version: sparseEmptyDigests('version', bucketBits),
    });
  }

  get binding(): Readonly<ConsumerBinding> {
    return this._binding;
  }

  get configurationDigest(): string {
    return this._configurationDigest;
  }

  register(initialCursor: CanonicalReadCursor = canonicalGenesisCursor()): DurableConsumerRegistration {
    if (!sameCanonicalReadCursor(initialCursor, canonicalGenesisCursor())) {
      throw new CanonicalObjectReadIndexRebuildRequiredError(
        'canonical object read index requires genesis bootstrap to authenticate complete object history',
      );
    }
    return this._store.register({
      consumerId: this._binding.consumerId,
      configurationDigest: this._binding.configurationDigest,
      projectionTablePrefix: this._binding.projectionTablePrefix,
      initialCursor,
    });
  }

  protected tables(): ProjectionTables {
    const p = this._prefix;
    return Object.freeze({
      meta: `${p}meta`,
      heads: `${p}heads`,
      versions: `${p}versions`,
      buckets: `${p}buckets`,
      nodes: `${p}nodes`,
    });
  }

  protected ensureSchema(tx: ConsumerProjectionTransaction): void {
    const t = this.tables();
    tx.run(`CREATE TABLE IF NOT EXISTS ${t.meta} (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL, config_digest TEXT NOT NULL, last_batch_id TEXT NOT NULL, after_cursor_digest TEXT NOT NULL, event_count INTEGER NOT NULL, head_count INTEGER NOT NULL, version_count INTEGER NOT NULL, head_root_digest TEXT NOT NULL, version_root_digest TEXT NOT NULL) STRICT`);
    tx.run(`CREATE TABLE IF NOT EXISTS ${t.heads} (kind TEXT NOT NULL, object_id_json TEXT NOT NULL, version_seq INTEGER NOT NULL, recorded_at INTEGER NOT NULL, state_digest TEXT NOT NULL, version_digest TEXT NOT NULL, head_digest TEXT NOT NULL, bucket INTEGER NOT NULL, PRIMARY KEY (kind, object_id_json)) STRICT`);
    tx.run(`CREATE TABLE IF NOT EXISTS ${t.versions} (kind TEXT NOT NULL, object_id_json TEXT NOT NULL, version_seq INTEGER NOT NULL, recorded_at INTEGER NOT NULL, known_to INTEGER, state_json TEXT NOT NULL, state_digest TEXT NOT NULL, row_digest TEXT NOT NULL, bucket INTEGER NOT NULL, PRIMARY KEY (kind, object_id_json, version_seq)) STRICT`);
    tx.run(`CREATE TABLE IF NOT EXISTS ${t.buckets} (tree_kind TEXT NOT NULL, bucket INTEGER NOT NULL, item_count INTEGER NOT NULL, bucket_digest TEXT NOT NULL, PRIMARY KEY (tree_kind, bucket)) STRICT`);
    tx.run(`CREATE TABLE IF NOT EXISTS ${t.nodes} (tree_kind TEXT NOT NULL, level INTEGER NOT NULL, prefix INTEGER NOT NULL, item_count INTEGER NOT NULL, node_digest TEXT NOT NULL, PRIMARY KEY (tree_kind, level, prefix)) STRICT`);
  }

  protected initializeEmptyState(tx: ConsumerProjectionTransaction): void {
    const t = this.tables();
    for (const table of [t.heads, t.versions, t.buckets, t.nodes]) {
      const row = tx.get(`SELECT COUNT(*) AS count FROM ${table}`) as
        | { readonly count: unknown }
        | undefined;
      if (row === undefined || row.count !== 0) {
        throw new CanonicalObjectReadIndexRebuildRequiredError(
          'canonical object projection has structural rows without publication metadata',
        );
      }
    }
  }

  protected meta(tx: ConsumerProjectionReadTransaction): ObjectReadMetaRow | undefined {
    const t = this.tables();
    return tx.get(`SELECT schema_version, config_digest, last_batch_id, after_cursor_digest, event_count, head_count, version_count, head_root_digest, version_root_digest FROM ${t.meta} WHERE id = ?`, 1) as ObjectReadMetaRow | undefined;
  }

  protected decodeMeta(row: ObjectReadMetaRow): VerifiedObjectReadMeta {
    assertInteger(row.schema_version, 'object read schema version', 1);
    if (row.schema_version !== CANONICAL_OBJECT_READ_INDEX_SCHEMA_VERSION) {
      throw new CanonicalObjectReadIndexRebuildRequiredError(
        `unsupported canonical object read schema version: ${row.schema_version}`,
      );
    }
    if (typeof row.config_digest !== 'string') {
      throw new CanonicalObjectReadIndexIntegrityError('object read configuration digest is malformed');
    }
    assertDigest(row.config_digest, 'object read configuration digest');
    if (row.config_digest !== this._configurationDigest) {
      throw new CanonicalObjectReadIndexRebuildRequiredError(
        'canonical object read index configuration differs from durable projection state',
      );
    }
    if (typeof row.last_batch_id !== 'string') {
      throw new CanonicalObjectReadIndexIntegrityError('object read last batch id is malformed');
    }
    assertDigest(row.last_batch_id, 'object read last batch id');
    if (typeof row.after_cursor_digest !== 'string') {
      throw new CanonicalObjectReadIndexIntegrityError('object read cursor digest is malformed');
    }
    assertDigest(row.after_cursor_digest, 'object read cursor digest');
    assertInteger(row.event_count, 'object read event count', 0);
    assertInteger(row.head_count, 'object read head count', 0);
    assertInteger(row.version_count, 'object read version count', 0);
    if (typeof row.head_root_digest !== 'string' || typeof row.version_root_digest !== 'string') {
      throw new CanonicalObjectReadIndexIntegrityError('object read root metadata is malformed');
    }
    assertDigest(row.head_root_digest, 'object read head root digest');
    assertDigest(row.version_root_digest, 'object read version root digest');
    return Object.freeze({
      schemaVersion: row.schema_version,
      configDigest: row.config_digest,
      lastBatchId: row.last_batch_id,
      afterCursorDigest: row.after_cursor_digest,
      eventCount: row.event_count,
      headCount: row.head_count,
      versionCount: row.version_count,
      headRootDigest: row.head_root_digest,
      versionRootDigest: row.version_root_digest,
    });
  }

  protected headRow(
    tx: ConsumerProjectionReadTransaction,
    kind: CanonicalObjectKind,
    canonicalId: string,
  ): ObjectReadHeadRow | undefined {
    const t = this.tables();
    return tx.get(`SELECT kind, object_id_json, version_seq, recorded_at, state_digest, version_digest, head_digest, bucket FROM ${t.heads} WHERE kind = ? AND object_id_json = ?`, kind, encodeString(canonicalId)) as ObjectReadHeadRow | undefined;
  }

  protected versionRow(
    tx: ConsumerProjectionReadTransaction,
    kind: CanonicalObjectKind,
    canonicalId: string,
    versionSeq: number,
  ): ObjectReadVersionRow | undefined {
    const t = this.tables();
    return tx.get(`SELECT kind, object_id_json, version_seq, recorded_at, known_to, state_json, state_digest, row_digest, bucket FROM ${t.versions} WHERE kind = ? AND object_id_json = ? AND version_seq = ?`, kind, encodeString(canonicalId), versionSeq) as ObjectReadVersionRow | undefined;
  }

  protected decodeHead(row: ObjectReadHeadRow): DecodedObjectReadHead {
    return decodeHeadRow(row, this._bucketCount);
  }

  protected decodeVersion(row: ObjectReadVersionRow): DecodedObjectReadVersion {
    return decodeVersionRow(row, this._bucketCount);
  }

  protected currentState(
    tx: ConsumerProjectionReadTransaction,
    kind: CanonicalObjectKind,
    canonicalId: string,
  ):
    | {
        readonly head: DecodedObjectReadHead;
        readonly version: DecodedObjectReadVersion;
      }
    | undefined {
    const rawHead = this.headRow(tx, kind, canonicalId);
    if (rawHead === undefined) return undefined;
    const head = this.decodeHead(rawHead);
    const rawVersion = this.versionRow(tx, kind, canonicalId, head.versionSeq);
    if (rawVersion === undefined) {
      throw new CanonicalObjectReadIndexIntegrityError(
        `object head has no current version: ${kind}/${canonicalId}`,
      );
    }
    const version = this.decodeVersion(rawVersion);
    if (
      version.knownTo !== undefined ||
      version.rowDigest !== head.versionDigest ||
      version.stateDigest !== head.stateDigest ||
      version.recordedAt !== head.recordedAt
    ) {
      throw new CanonicalObjectReadIndexIntegrityError(
        `object head and current version diverged: ${kind}/${canonicalId}`,
      );
    }
    return Object.freeze({ head, version });
  }

  protected bucketRow(
    tx: ConsumerProjectionReadTransaction,
    tree: ObjectReadTreeKind,
    bucket: number,
  ): ObjectReadBucketRow | undefined {
    const t = this.tables();
    return tx.get(`SELECT tree_kind, bucket, item_count, bucket_digest FROM ${t.buckets} WHERE tree_kind = ? AND bucket = ?`, tree, bucket) as ObjectReadBucketRow | undefined;
  }

  protected nodeRow(
    tx: ConsumerProjectionReadTransaction,
    tree: ObjectReadTreeKind,
    level: number,
    prefix: number,
  ): ObjectReadNodeRow | undefined {
    const t = this.tables();
    return tx.get(`SELECT tree_kind, level, prefix, item_count, node_digest FROM ${t.nodes} WHERE tree_kind = ? AND level = ? AND prefix = ?`, tree, level, prefix) as ObjectReadNodeRow | undefined;
  }

  protected decodeBucketRow(
    row: ObjectReadBucketRow,
    tree: ObjectReadTreeKind,
    bucket: number,
  ): ObjectReadTreeValue {
    assertTreeKind(row.tree_kind, 'object bucket tree kind');
    assertInteger(row.bucket, 'object bucket number', 0);
    assertInteger(row.item_count, 'object bucket item count', 1);
    if (typeof row.bucket_digest !== 'string') {
      throw new CanonicalObjectReadIndexIntegrityError('object bucket digest is malformed');
    }
    assertDigest(row.bucket_digest, 'object bucket digest');
    if (row.tree_kind !== tree || row.bucket !== bucket || bucket >= this._bucketCount) {
      throw new CanonicalObjectReadIndexIntegrityError('object bucket identity diverged');
    }
    return Object.freeze({ digest: row.bucket_digest, itemCount: row.item_count });
  }

  protected treeValue(
    tx: ConsumerProjectionReadTransaction,
    tree: ObjectReadTreeKind,
    level: number,
    prefix: number,
  ): ObjectReadTreeValue {
    const empty = this._emptyDigests[tree][level];
    if (empty === undefined) throw new Error('sparse tree level is unavailable');
    if (level === 0) {
      const row = this.bucketRow(tx, tree, prefix);
      if (row === undefined) return Object.freeze({ digest: empty, itemCount: 0 });
      const bucket = this.decodeBucketRow(row, tree, prefix);
      return Object.freeze({
        digest: sparseLeafDigest(tree, prefix, bucket.itemCount, bucket.digest),
        itemCount: bucket.itemCount,
      });
    }
    const row = this.nodeRow(tx, tree, level, prefix);
    return row === undefined
      ? Object.freeze({ digest: empty, itemCount: 0 })
      : decodeNodeRow(row, tree, level, prefix);
  }

  protected rootValue(
    tx: ConsumerProjectionReadTransaction,
    tree: ObjectReadTreeKind,
  ): ObjectReadTreeValue {
    return this.treeValue(tx, tree, this._bucketBits, 0);
  }

  protected headRowsForBucket(
    tx: ConsumerProjectionReadTransaction,
    bucket: number,
  ): readonly DecodedObjectReadHead[] {
    const t = this.tables();
    const rows = tx.all(`SELECT kind, object_id_json, version_seq, recorded_at, state_digest, version_digest, head_digest, bucket FROM ${t.heads} WHERE bucket = ? ORDER BY kind, object_id_json`, bucket) as readonly ObjectReadHeadRow[];
    return Object.freeze(rows.map((row) => this.decodeHead(row)));
  }

  protected versionRowsForBucket(
    tx: ConsumerProjectionReadTransaction,
    bucket: number,
  ): readonly DecodedObjectReadVersion[] {
    const t = this.tables();
    const rows = tx.all(`SELECT kind, object_id_json, version_seq, recorded_at, known_to, state_json, state_digest, row_digest, bucket FROM ${t.versions} WHERE bucket = ? ORDER BY kind, object_id_json, version_seq`, bucket) as readonly ObjectReadVersionRow[];
    return Object.freeze(rows.map((row) => this.decodeVersion(row)));
  }

  protected updateSparsePath(
    tx: ConsumerProjectionTransaction,
    tree: ObjectReadTreeKind,
    bucket: number,
  ): void {
    const t = this.tables();
    for (let level = 1; level <= this._bucketBits; level += 1) {
      const parentPrefix = Math.floor(bucket / 2 ** level);
      const left = this.treeValue(tx, tree, level - 1, parentPrefix * 2);
      const right = this.treeValue(tx, tree, level - 1, parentPrefix * 2 + 1);
      const itemCount = left.itemCount + right.itemCount;
      const digest = sparseInternalDigest(tree, level, left.digest, right.digest);
      tx.run(`DELETE FROM ${t.nodes} WHERE tree_kind = ? AND level = ? AND prefix = ?`, tree, level, parentPrefix);
      if (itemCount > 0) {
        tx.run(`INSERT INTO ${t.nodes} (tree_kind, level, prefix, item_count, node_digest) VALUES (?, ?, ?, ?, ?)`, tree, level, parentPrefix, itemCount, digest);
      }
    }
  }

  protected refreshBucket(
    tx: ConsumerProjectionTransaction,
    tree: ObjectReadTreeKind,
    bucket: number,
  ): void {
    if (!Number.isSafeInteger(bucket) || bucket < 0 || bucket >= this._bucketCount) {
      throw new CanonicalObjectReadIndexIntegrityError('touched object bucket is out of range');
    }
    const t = this.tables();
    const rows = tree === 'head'
      ? this.headRowsForBucket(tx, bucket)
      : this.versionRowsForBucket(tx, bucket);
    const digest = tree === 'head'
      ? headBucketDigest(bucket, rows as readonly DecodedObjectReadHead[])
      : versionBucketDigest(bucket, rows as readonly DecodedObjectReadVersion[]);
    tx.run(`DELETE FROM ${t.buckets} WHERE tree_kind = ? AND bucket = ?`, tree, bucket);
    if (rows.length > 0) {
      tx.run(`INSERT INTO ${t.buckets} (tree_kind, bucket, item_count, bucket_digest) VALUES (?, ?, ?, ?)`, tree, bucket, rows.length, digest);
    }
    this.updateSparsePath(tx, tree, bucket);
  }

}
