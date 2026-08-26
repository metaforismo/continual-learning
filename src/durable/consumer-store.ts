import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

import type { MemoryEvent } from '../domain.js';
import {
  CanonicalChangeFeed,
  type CanonicalAppendBatch,
  type CanonicalReadCursor,
} from './change-feed.js';

const CONSUMER_SCHEMA_VERSION = 1 as const;
const MAX_CONSUMER_ID_LENGTH = 256;
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;

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
    const items: string[] = [];
    for (let index = 0; index < value.length; index += 1) {
      if (!(index in value)) throw new TypeError(`${path} contains a sparse array`);
      items.push(stableJson(value[index], `${path}[${index}]`, ancestors));
    }
    ancestors.delete(value);
    return `[${items.join(',')}]`;
  }
  if (typeof value === 'object') {
    if (ancestors.has(value)) throw new TypeError(`${path} contains a circular reference`);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(`${path} must contain only plain JSON objects`);
    }
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

const GENESIS_CHAIN_DIGEST = digest({ domain: 'cl-canonical-event-chain-genesis-v1' });
const GENESIS_RECEIPT_DIGEST = digest({ domain: 'cl-consumer-receipt-chain-genesis-v1' });

function eventDigest(event: MemoryEvent): string {
  return digest({ domain: 'cl-canonical-event-v1', event });
}

function nextChainDigest(previous: string, event: MemoryEvent): string {
  return digest({
    domain: 'cl-canonical-event-chain-v1',
    previous,
    seq: event.seq,
    eventDigest: eventDigest(event),
  });
}

function appendDigest(events: readonly MemoryEvent[]): string {
  return digest({
    domain: 'cl-change-feed-append-v1',
    events: events.map((event) => ({
      seq: event.seq,
      eventId: event.id,
      eventDigest: eventDigest(event),
    })),
  });
}

function assertDigest(value: string, label: string): void {
  if (!SHA256_PATTERN.test(value)) throw new Error(`${label} must be a SHA-256 content address`);
}

function validateCursor(cursor: CanonicalReadCursor): void {
  if (
    cursor.schemaVersion !== 1 ||
    !Number.isInteger(cursor.eventCount) ||
    cursor.eventCount < 0 ||
    !Number.isInteger(cursor.lastSeq) ||
    cursor.lastSeq !== cursor.eventCount ||
    !Number.isInteger(cursor.lastRecordedAt) ||
    cursor.lastRecordedAt < 0 ||
    !SHA256_PATTERN.test(cursor.chainDigest)
  ) {
    throw new Error('consumer cursor is malformed');
  }
  if (
    cursor.eventCount === 0 &&
    (cursor.lastRecordedAt !== 0 || cursor.chainDigest !== GENESIS_CHAIN_DIGEST)
  ) {
    throw new Error('empty consumer cursor does not match canonical genesis');
  }
}

function sameCursor(left: CanonicalReadCursor, right: CanonicalReadCursor): boolean {
  return stableJson(left) === stableJson(right);
}

function cursorDigest(cursor: CanonicalReadCursor): string {
  validateCursor(cursor);
  return digest({ domain: 'cl-consumer-cursor-v1', cursor });
}

function advance(base: CanonicalReadCursor, events: readonly MemoryEvent[]): CanonicalReadCursor {
  let chain = base.chainDigest;
  let expectedSeq = base.lastSeq + 1;
  let recordedAt = base.lastRecordedAt;
  for (const event of events) {
    if (
      event.seq !== expectedSeq ||
      !Number.isFinite(event.recordedAt) ||
      event.recordedAt < recordedAt
    ) {
      throw new Error(`consumer batch is malformed at canonical sequence ${expectedSeq}`);
    }
    chain = nextChainDigest(chain, event);
    recordedAt = event.recordedAt;
    expectedSeq += 1;
  }
  return Object.freeze({
    schemaVersion: 1,
    eventCount: base.eventCount + events.length,
    lastSeq: base.lastSeq + events.length,
    lastRecordedAt: recordedAt,
    chainDigest: chain,
  });
}

function verifyBatch(batch: CanonicalAppendBatch): void {
  if (
    typeof batch !== 'object' ||
    batch === null ||
    batch.schemaVersion !== 1 ||
    typeof batch.id !== 'string' ||
    !SHA256_PATTERN.test(batch.id) ||
    !Array.isArray(batch.events) ||
    batch.events.length === 0 ||
    !Number.isInteger(batch.appendFromSeq) ||
    !Number.isInteger(batch.appendToSeq) ||
    !SHA256_PATTERN.test(batch.appendDigest)
  ) {
    throw new Error('consumer batch shape is invalid');
  }
  validateCursor(batch.base);
  validateCursor(batch.after);
  if (
    batch.appendFromSeq !== batch.base.lastSeq + 1 ||
    batch.appendToSeq !== batch.after.lastSeq ||
    batch.events.length !== batch.after.eventCount - batch.base.eventCount ||
    batch.events[0]?.seq !== batch.appendFromSeq ||
    batch.events.at(-1)?.seq !== batch.appendToSeq
  ) {
    throw new Error('consumer batch sequence interval is invalid');
  }
  const after = advance(batch.base, batch.events);
  if (!sameCursor(after, batch.after)) throw new Error('consumer batch cursor transition is invalid');
  if (appendDigest(batch.events) !== batch.appendDigest) {
    throw new Error('consumer batch append digest is invalid');
  }
  const unsigned = {
    schemaVersion: batch.schemaVersion,
    base: batch.base,
    after: batch.after,
    appendFromSeq: batch.appendFromSeq,
    appendToSeq: batch.appendToSeq,
    appendDigest: batch.appendDigest,
    events: batch.events,
  };
  if (digest({ domain: 'cl-change-feed-batch-v1', batch: unsigned }) !== batch.id) {
    throw new Error('consumer batch id is invalid');
  }
}

export type ConsumerCheckpointFaultPoint =
  | 'after-begin'
  | 'after-callback'
  | 'after-receipt'
  | 'after-checkpoint'
  | 'before-commit';

export interface ConsumerCheckpointStoreOptions {
  readonly database?: string;
  readonly busyTimeoutMs?: number;
  readonly faultInjector?: (point: ConsumerCheckpointFaultPoint) => void;
}

export interface DurableConsumerCheckpoint {
  readonly schemaVersion: typeof CONSUMER_SCHEMA_VERSION;
  readonly consumerId: string;
  readonly revision: number;
  readonly cursor: CanonicalReadCursor;
  readonly cursorDigest: string;
  readonly lastBatchId: string;
  readonly lastAppendDigest: string;
  readonly latestReceiptDigest: string;
  readonly updatedAt: number;
}

export interface DurableConsumerReceipt {
  readonly schemaVersion: typeof CONSUMER_SCHEMA_VERSION;
  readonly consumerId: string;
  readonly revision: number;
  readonly batchId: string;
  readonly base: CanonicalReadCursor;
  readonly baseDigest: string;
  readonly after: CanonicalReadCursor;
  readonly afterDigest: string;
  readonly appendDigest: string;
  readonly previousReceiptDigest: string;
  readonly receiptDigest: string;
  readonly appliedAt: number;
}

export interface ConsumerApplyResult<T> {
  readonly value: T | undefined;
  readonly checkpoint: DurableConsumerCheckpoint;
  readonly receipt: DurableConsumerReceipt;
  readonly idempotentReplay: boolean;
}

export interface ConsumerCheckpointAudit {
  readonly ok: boolean;
  readonly errors: readonly string[];
  readonly checkpoint?: DurableConsumerCheckpoint;
  readonly receiptCount: number;
}

export type TrustedConsumerTransaction<T> = (
  database: DatabaseSync,
  batch: CanonicalAppendBatch,
) => T;

interface CheckpointRow {
  readonly consumer_id: string;
  readonly revision: number;
  readonly cursor_json: string;
  readonly cursor_digest: string;
  readonly last_batch_id: string;
  readonly last_append_digest: string;
  readonly latest_receipt_digest: string;
  readonly updated_at: number;
}

interface ReceiptRow {
  readonly consumer_id: string;
  readonly revision: number;
  readonly batch_id: string;
  readonly base_cursor_json: string;
  readonly base_cursor_digest: string;
  readonly after_cursor_json: string;
  readonly after_cursor_digest: string;
  readonly append_digest: string;
  readonly previous_receipt_digest: string;
  readonly receipt_digest: string;
  readonly applied_at: number;
}

function checkpointFromRow(row: CheckpointRow): DurableConsumerCheckpoint {
  if (
    typeof row.consumer_id !== 'string' ||
    row.consumer_id.trim().length === 0 ||
    !Number.isInteger(row.revision) ||
    row.revision <= 0 ||
    !Number.isInteger(row.updated_at) ||
    row.updated_at <= 0
  ) {
    throw new Error('consumer checkpoint row is malformed');
  }
  const cursor = JSON.parse(row.cursor_json) as CanonicalReadCursor;
  if (stableJson(cursor) !== row.cursor_json) throw new Error('consumer checkpoint cursor is not canonical');
  const computedCursorDigest = cursorDigest(cursor);
  if (computedCursorDigest !== row.cursor_digest) throw new Error('consumer checkpoint cursor digest is invalid');
  for (const [label, value] of [
    ['last batch id', row.last_batch_id],
    ['last append digest', row.last_append_digest],
    ['latest receipt digest', row.latest_receipt_digest],
  ] as const) {
    assertDigest(value, `consumer checkpoint ${label}`);
  }
  return Object.freeze({
    schemaVersion: CONSUMER_SCHEMA_VERSION,
    consumerId: row.consumer_id,
    revision: row.revision,
    cursor,
    cursorDigest: row.cursor_digest,
    lastBatchId: row.last_batch_id,
    lastAppendDigest: row.last_append_digest,
    latestReceiptDigest: row.latest_receipt_digest,
    updatedAt: row.updated_at,
  });
}

function receiptPayload(receipt: Omit<DurableConsumerReceipt, 'receiptDigest'>): unknown {
  return { domain: 'cl-consumer-receipt-v1', ...receipt };
}

function receiptFromRow(row: ReceiptRow): DurableConsumerReceipt {
  if (
    typeof row.consumer_id !== 'string' ||
    row.consumer_id.trim().length === 0 ||
    !Number.isInteger(row.revision) ||
    row.revision <= 0 ||
    !Number.isInteger(row.applied_at) ||
    row.applied_at <= 0
  ) {
    throw new Error('consumer receipt row is malformed');
  }
  const base = JSON.parse(row.base_cursor_json) as CanonicalReadCursor;
  const after = JSON.parse(row.after_cursor_json) as CanonicalReadCursor;
  if (
    stableJson(base) !== row.base_cursor_json ||
    stableJson(after) !== row.after_cursor_json ||
    cursorDigest(base) !== row.base_cursor_digest ||
    cursorDigest(after) !== row.after_cursor_digest
  ) {
    throw new Error(`consumer receipt cursor integrity failed at revision ${row.revision}`);
  }
  for (const [label, value] of [
    ['batch id', row.batch_id],
    ['append digest', row.append_digest],
    ['previous receipt digest', row.previous_receipt_digest],
    ['receipt digest', row.receipt_digest],
  ] as const) {
    assertDigest(value, `consumer receipt ${label}`);
  }
  const receipt = Object.freeze({
    schemaVersion: CONSUMER_SCHEMA_VERSION,
    consumerId: row.consumer_id,
    revision: row.revision,
    batchId: row.batch_id,
    base,
    baseDigest: row.base_cursor_digest,
    after,
    afterDigest: row.after_cursor_digest,
    appendDigest: row.append_digest,
    previousReceiptDigest: row.previous_receipt_digest,
    receiptDigest: row.receipt_digest,
    appliedAt: row.applied_at,
  });
  const { receiptDigest: _ignored, ...unsigned } = receipt;
  if (digest(receiptPayload(unsigned)) !== receipt.receiptDigest) {
    throw new Error(`consumer receipt digest failed at revision ${row.revision}`);
  }
  return receipt;
}

/**
 * Durable consumer offset and receipt store.
 *
 * `apply` is intentionally entered through `CanonicalChangeFeed.consume`, so a forged structural
 * clone cannot run the trusted projection transaction or advance the durable checkpoint.
 */
export class SqliteConsumerCheckpointStore {
  readonly #db: DatabaseSync;
  readonly #faultInjector: ConsumerCheckpointStoreOptions['faultInjector'];
  #closed = false;

  constructor(options: ConsumerCheckpointStoreOptions = {}) {
    const timeout = options.busyTimeoutMs ?? 5_000;
    if (!Number.isInteger(timeout) || timeout < 0 || timeout > 60_000) {
      throw new RangeError('busyTimeoutMs must be an integer in [0, 60000]');
    }
    this.#faultInjector = options.faultInjector;
    this.#db = new DatabaseSync(options.database ?? ':memory:');
    this.#db.exec(`PRAGMA busy_timeout = ${timeout}`);
    this.#initializeSchema();
  }

  #assertOpen(): void {
    if (this.#closed) throw new Error('consumer checkpoint store is closed');
  }

  #inject(point: ConsumerCheckpointFaultPoint): void {
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
        // Preserve the original failure.
      }
      throw error;
    }
  }

  #initializeSchema(): void {
    const expected = new Set(['cl_consumer_meta', 'cl_consumer_checkpoints', 'cl_consumer_receipts']);
    const rows = this.#db
      .prepare(`SELECT name FROM sqlite_master WHERE name LIKE 'cl_consumer_%'`)
      .all() as unknown as readonly { readonly name: string }[];
    const names = new Set(rows.map((row) => row.name));
    if (names.size > 0 && [...expected].some((name) => !names.has(name))) {
      throw new Error('consumer checkpoint schema is partially present; manual recovery is required');
    }
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS cl_consumer_meta (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        schema_version INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS cl_consumer_checkpoints (
        consumer_id TEXT PRIMARY KEY,
        revision INTEGER NOT NULL,
        cursor_json TEXT NOT NULL,
        cursor_digest TEXT NOT NULL,
        last_batch_id TEXT NOT NULL,
        last_append_digest TEXT NOT NULL,
        latest_receipt_digest TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS cl_consumer_receipts (
        consumer_id TEXT NOT NULL,
        revision INTEGER NOT NULL,
        batch_id TEXT NOT NULL,
        base_cursor_json TEXT NOT NULL,
        base_cursor_digest TEXT NOT NULL,
        after_cursor_json TEXT NOT NULL,
        after_cursor_digest TEXT NOT NULL,
        append_digest TEXT NOT NULL,
        previous_receipt_digest TEXT NOT NULL,
        receipt_digest TEXT NOT NULL,
        applied_at INTEGER NOT NULL,
        PRIMARY KEY (consumer_id, revision),
        UNIQUE (consumer_id, batch_id),
        UNIQUE (consumer_id, receipt_digest)
      );
    `);
    const meta = this.#db.prepare('SELECT schema_version FROM cl_consumer_meta WHERE id = 1').get() as
      | { readonly schema_version: number }
      | undefined;
    if (meta === undefined) {
      this.#db
        .prepare('INSERT INTO cl_consumer_meta (id, schema_version) VALUES (1, ?)')
        .run(CONSUMER_SCHEMA_VERSION);
    } else if (meta.schema_version !== CONSUMER_SCHEMA_VERSION) {
      throw new Error(`unsupported consumer checkpoint schema version: ${meta.schema_version}`);
    }
  }

  #validateConsumerId(consumerId: string): void {
    if (
      typeof consumerId !== 'string' ||
      consumerId.trim().length === 0 ||
      consumerId.length > MAX_CONSUMER_ID_LENGTH
    ) {
      throw new Error(`consumerId must be a non-empty string up to ${MAX_CONSUMER_ID_LENGTH} characters`);
    }
  }

  #checkpointRow(consumerId: string): CheckpointRow | undefined {
    return this.#db
      .prepare('SELECT * FROM cl_consumer_checkpoints WHERE consumer_id = ?')
      .get(consumerId) as CheckpointRow | undefined;
  }

  #receiptRow(consumerId: string, batchId: string): ReceiptRow | undefined {
    return this.#db
      .prepare('SELECT * FROM cl_consumer_receipts WHERE consumer_id = ? AND batch_id = ?')
      .get(consumerId, batchId) as ReceiptRow | undefined;
  }

  apply<T>(
    feed: CanonicalChangeFeed,
    batch: CanonicalAppendBatch,
    consumerId: string,
    operation: TrustedConsumerTransaction<T>,
  ): ConsumerApplyResult<T> {
    this.#validateConsumerId(consumerId);
    if (typeof operation !== 'function') throw new TypeError('consumer operation must be a function');
    return feed.consume(batch, (authorizedBatch) =>
      this.#transaction('write', () => {
        this.#inject('after-begin');
        verifyBatch(authorizedBatch);
        const existingReceiptRow = this.#receiptRow(consumerId, authorizedBatch.id);
        if (existingReceiptRow !== undefined) {
          const existingReceipt = receiptFromRow(existingReceiptRow);
          if (
            !sameCursor(existingReceipt.base, authorizedBatch.base) ||
            !sameCursor(existingReceipt.after, authorizedBatch.after) ||
            existingReceipt.appendDigest !== authorizedBatch.appendDigest
          ) {
            throw new Error('consumer batch id already exists with different durable content');
          }
          const checkpointRow = this.#checkpointRow(consumerId);
          if (checkpointRow === undefined) throw new Error('idempotent consumer receipt has no checkpoint');
          const checkpoint = checkpointFromRow(checkpointRow);
          if (
            checkpoint.latestReceiptDigest !== existingReceipt.receiptDigest ||
            !sameCursor(checkpoint.cursor, authorizedBatch.after)
          ) {
            throw new Error('idempotent consumer receipt is not the active checkpoint');
          }
          return Object.freeze({
            value: undefined,
            checkpoint,
            receipt: existingReceipt,
            idempotentReplay: true,
          });
        }

        const currentRow = this.#checkpointRow(consumerId);
        const current = currentRow === undefined ? undefined : checkpointFromRow(currentRow);
        if (current !== undefined && !sameCursor(current.cursor, authorizedBatch.base)) {
          throw new Error('consumer batch base is stale or out of order');
        }

        const value = operation(this.#db, authorizedBatch);
        if (
          value !== null &&
          typeof value === 'object' &&
          typeof (value as { readonly then?: unknown }).then === 'function'
        ) {
          throw new Error('consumer projection transaction must be synchronous');
        }
        this.#inject('after-callback');

        const revision = (current?.revision ?? 0) + 1;
        const appliedAt = Math.max(Date.now(), (current?.updatedAt ?? 0) + 1);
        const unsigned = Object.freeze({
          schemaVersion: CONSUMER_SCHEMA_VERSION,
          consumerId,
          revision,
          batchId: authorizedBatch.id,
          base: authorizedBatch.base,
          baseDigest: cursorDigest(authorizedBatch.base),
          after: authorizedBatch.after,
          afterDigest: cursorDigest(authorizedBatch.after),
          appendDigest: authorizedBatch.appendDigest,
          previousReceiptDigest: current?.latestReceiptDigest ?? GENESIS_RECEIPT_DIGEST,
          appliedAt,
        });
        const receipt = Object.freeze({
          ...unsigned,
          receiptDigest: digest(receiptPayload(unsigned)),
        });
        this.#db
          .prepare(`
            INSERT INTO cl_consumer_receipts
              (consumer_id, revision, batch_id, base_cursor_json, base_cursor_digest,
               after_cursor_json, after_cursor_digest, append_digest,
               previous_receipt_digest, receipt_digest, applied_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `)
          .run(
            consumerId,
            revision,
            receipt.batchId,
            stableJson(receipt.base),
            receipt.baseDigest,
            stableJson(receipt.after),
            receipt.afterDigest,
            receipt.appendDigest,
            receipt.previousReceiptDigest,
            receipt.receiptDigest,
            receipt.appliedAt,
          );
        this.#inject('after-receipt');

        this.#db
          .prepare(`
            INSERT INTO cl_consumer_checkpoints
              (consumer_id, revision, cursor_json, cursor_digest, last_batch_id,
               last_append_digest, latest_receipt_digest, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(consumer_id) DO UPDATE SET
              revision = excluded.revision,
              cursor_json = excluded.cursor_json,
              cursor_digest = excluded.cursor_digest,
              last_batch_id = excluded.last_batch_id,
              last_append_digest = excluded.last_append_digest,
              latest_receipt_digest = excluded.latest_receipt_digest,
              updated_at = excluded.updated_at
          `)
          .run(
            consumerId,
            revision,
            stableJson(receipt.after),
            receipt.afterDigest,
            receipt.batchId,
            receipt.appendDigest,
            receipt.receiptDigest,
            appliedAt,
          );
        this.#inject('after-checkpoint');
        this.#inject('before-commit');
        return Object.freeze({
          value,
          checkpoint: Object.freeze({
            schemaVersion: CONSUMER_SCHEMA_VERSION,
            consumerId,
            revision,
            cursor: receipt.after,
            cursorDigest: receipt.afterDigest,
            lastBatchId: receipt.batchId,
            lastAppendDigest: receipt.appendDigest,
            latestReceiptDigest: receipt.receiptDigest,
            updatedAt: appliedAt,
          }),
          receipt,
          idempotentReplay: false,
        });
      }),
    );
  }

  checkpoint(consumerId: string): DurableConsumerCheckpoint | undefined {
    this.#validateConsumerId(consumerId);
    return this.#transaction('read', () => {
      const row = this.#checkpointRow(consumerId);
      if (row === undefined) return undefined;
      const checkpoint = checkpointFromRow(row);
      const receiptRow = this.#receiptRow(consumerId, checkpoint.lastBatchId);
      if (receiptRow === undefined) throw new Error('consumer checkpoint receipt is missing');
      const receipt = receiptFromRow(receiptRow);
      if (
        receipt.receiptDigest !== checkpoint.latestReceiptDigest ||
        !sameCursor(receipt.after, checkpoint.cursor) ||
        receipt.appendDigest !== checkpoint.lastAppendDigest
      ) {
        throw new Error('consumer checkpoint differs from its latest receipt');
      }
      return checkpoint;
    });
  }

  audit(consumerId: string): ConsumerCheckpointAudit {
    this.#validateConsumerId(consumerId);
    return this.#transaction('read', () => {
      const errors: string[] = [];
      const checkpointRow = this.#checkpointRow(consumerId);
      const checkpoint = checkpointRow === undefined ? undefined : checkpointFromRow(checkpointRow);
      const rows = this.#db
        .prepare('SELECT * FROM cl_consumer_receipts WHERE consumer_id = ? ORDER BY revision')
        .all(consumerId) as unknown as readonly ReceiptRow[];
      let previousReceipt = GENESIS_RECEIPT_DIGEST;
      let previousAfter: CanonicalReadCursor | undefined;
      let previousAppliedAt = -1;
      for (let index = 0; index < rows.length; index += 1) {
        try {
          const receipt = receiptFromRow(rows[index] as ReceiptRow);
          if (
            receipt.revision !== index + 1 ||
            receipt.previousReceiptDigest !== previousReceipt ||
            (previousAfter !== undefined && !sameCursor(receipt.base, previousAfter)) ||
            receipt.appliedAt <= previousAppliedAt
          ) {
            errors.push(`consumer receipt chain mismatch at revision ${receipt.revision}`);
          }
          previousReceipt = receipt.receiptDigest;
          previousAfter = receipt.after;
          previousAppliedAt = receipt.appliedAt;
        } catch (error) {
          errors.push(error instanceof Error ? error.message : `consumer receipt ${index + 1} is invalid`);
        }
      }
      if (checkpoint === undefined) {
        if (rows.length !== 0) errors.push('consumer receipts exist without an active checkpoint');
      } else if (
        checkpoint.revision !== rows.length ||
        checkpoint.latestReceiptDigest !== previousReceipt ||
        previousAfter === undefined ||
        !sameCursor(checkpoint.cursor, previousAfter)
      ) {
        errors.push('consumer checkpoint differs from the receipt-chain head');
      }
      return Object.freeze({
        ok: errors.length === 0,
        errors: Object.freeze(errors),
        ...(checkpoint === undefined ? {} : { checkpoint }),
        receiptCount: rows.length,
      });
    });
  }

  close(): void {
    if (this.#closed) return;
    this.#db.close();
    this.#closed = true;
  }
}
