import { createHash } from 'node:crypto';

import type { MemoryEvent } from '../domain.js';
import {
  SqliteCanonicalLedger,
  type DurableCanonicalCursor,
} from './canonical-ledger.js';

const CHANGE_FEED_SCHEMA_VERSION = 1 as const;
const MAX_BATCH_EVENTS = 1_000;
const DEFAULT_BATCH_EVENTS = 256;
const DEFAULT_VERIFICATION_CHUNK = 1_000;
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

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function canonicalClone<T>(value: T): T {
  return deepFreeze(JSON.parse(stableJson(value)) as T);
}

export interface CanonicalReadCursor {
  readonly schemaVersion: typeof CHANGE_FEED_SCHEMA_VERSION;
  readonly eventCount: number;
  readonly lastSeq: number;
  readonly lastRecordedAt: number;
  readonly chainDigest: string;
}

export interface CanonicalAppendBatch {
  readonly schemaVersion: typeof CHANGE_FEED_SCHEMA_VERSION;
  readonly id: string;
  readonly base: CanonicalReadCursor;
  readonly after: CanonicalReadCursor;
  readonly appendFromSeq: number;
  readonly appendToSeq: number;
  readonly appendDigest: string;
  readonly events: readonly MemoryEvent[];
}

export interface CanonicalChangeFeedOptions {
  /** Persisted read checkpoint. Omission starts at the currently verified tail. */
  readonly checkpoint?: CanonicalReadCursor;
  readonly maxBatchEvents?: number;
  readonly verificationChunkSize?: number;
  /** Full durable audit is the default startup boundary. */
  readonly startupVerification?: 'full-audit' | 'tail-only';
}

export interface CanonicalChangeFeedStatus {
  readonly checkpoint: CanonicalReadCursor;
  readonly pending: boolean;
  readonly lagEvents: number;
  readonly durableTail: CanonicalReadCursor;
}

function cursorFromDurable(cursor: DurableCanonicalCursor): CanonicalReadCursor {
  return Object.freeze({
    schemaVersion: CHANGE_FEED_SCHEMA_VERSION,
    eventCount: cursor.eventCount,
    lastSeq: cursor.lastSeq,
    lastRecordedAt: cursor.lastRecordedAt,
    chainDigest: cursor.chainDigest,
  });
}

function validateReadCursor(cursor: CanonicalReadCursor): void {
  if (
    cursor.schemaVersion !== CHANGE_FEED_SCHEMA_VERSION ||
    !Number.isInteger(cursor.eventCount) ||
    cursor.eventCount < 0 ||
    !Number.isInteger(cursor.lastSeq) ||
    cursor.lastSeq !== cursor.eventCount ||
    !Number.isInteger(cursor.lastRecordedAt) ||
    cursor.lastRecordedAt < 0 ||
    !SHA256_PATTERN.test(cursor.chainDigest)
  ) {
    throw new Error('canonical read cursor is malformed');
  }
  if (
    cursor.eventCount === 0 &&
    (cursor.lastSeq !== 0 ||
      cursor.lastRecordedAt !== 0 ||
      cursor.chainDigest !== GENESIS_CHAIN_DIGEST)
  ) {
    throw new Error('empty canonical read cursor does not match genesis');
  }
}

function sameCursor(left: CanonicalReadCursor, right: CanonicalReadCursor): boolean {
  return (
    left.schemaVersion === right.schemaVersion &&
    left.eventCount === right.eventCount &&
    left.lastSeq === right.lastSeq &&
    left.lastRecordedAt === right.lastRecordedAt &&
    left.chainDigest === right.chainDigest
  );
}

function advanceCursor(
  base: CanonicalReadCursor,
  events: readonly MemoryEvent[],
): CanonicalReadCursor {
  let chain = base.chainDigest;
  let expectedSeq = base.lastSeq + 1;
  let recordedAt = base.lastRecordedAt;
  for (const event of events) {
    if (
      event.seq !== expectedSeq ||
      !Number.isFinite(event.recordedAt) ||
      event.recordedAt < recordedAt
    ) {
      throw new Error(`canonical change-feed append is malformed at sequence ${expectedSeq}`);
    }
    chain = nextChainDigest(chain, event);
    recordedAt = event.recordedAt;
    expectedSeq += 1;
  }
  return Object.freeze({
    schemaVersion: CHANGE_FEED_SCHEMA_VERSION,
    eventCount: base.eventCount + events.length,
    lastSeq: base.lastSeq + events.length,
    lastRecordedAt: recordedAt,
    chainDigest: chain,
  });
}

/**
 * Verified pull-based change feed over `SqliteCanonicalLedger`.
 *
 * Startup/resume verification remains O(N). After that, polling a complete delta is O(k), where k
 * is the number of newly committed events, and acknowledgement is capability-gated and O(1).
 */
export class CanonicalChangeFeed {
  readonly #ledger: SqliteCanonicalLedger;
  readonly #issuedBatches = new WeakSet<object>();
  readonly #maxBatchEvents: number;
  #checkpoint: CanonicalReadCursor;
  #pending: CanonicalAppendBatch | undefined;

  private constructor(
    ledger: SqliteCanonicalLedger,
    checkpoint: CanonicalReadCursor,
    maxBatchEvents: number,
  ) {
    this.#ledger = ledger;
    this.#checkpoint = checkpoint;
    this.#maxBatchEvents = maxBatchEvents;
  }

  static open(
    ledger: SqliteCanonicalLedger,
    options: CanonicalChangeFeedOptions = {},
  ): CanonicalChangeFeed {
    const maxBatchEvents = options.maxBatchEvents ?? DEFAULT_BATCH_EVENTS;
    if (!Number.isInteger(maxBatchEvents) || maxBatchEvents <= 0 || maxBatchEvents > MAX_BATCH_EVENTS) {
      throw new RangeError(`maxBatchEvents must be an integer in [1, ${MAX_BATCH_EVENTS}]`);
    }
    const verificationChunkSize = options.verificationChunkSize ?? DEFAULT_VERIFICATION_CHUNK;
    if (
      !Number.isInteger(verificationChunkSize) ||
      verificationChunkSize <= 0 ||
      verificationChunkSize > MAX_BATCH_EVENTS
    ) {
      throw new RangeError(
        `verificationChunkSize must be an integer in [1, ${MAX_BATCH_EVENTS}]`,
      );
    }
    const startupVerification = options.startupVerification ?? 'full-audit';
    if (startupVerification !== 'full-audit' && startupVerification !== 'tail-only') {
      throw new Error('startupVerification must be full-audit or tail-only');
    }
    if (startupVerification === 'full-audit') {
      const audit = ledger.audit();
      if (!audit.ok) throw new Error(`canonical change feed cannot open: ${audit.errors.join('; ')}`);
    } else {
      const status = ledger.status();
      if (!status.ok) throw new Error(`canonical change feed cannot open: ${status.reason}`);
    }

    const durableTail = cursorFromDurable(ledger.cursor());
    const supplied = options.checkpoint;
    const checkpoint = supplied === undefined
      ? durableTail
      : CanonicalChangeFeed.#verifyPersistedCheckpoint(
          ledger,
          canonicalClone(supplied),
          durableTail,
          verificationChunkSize,
        );
    return new CanonicalChangeFeed(ledger, checkpoint, maxBatchEvents);
  }

  static #verifyPersistedCheckpoint(
    ledger: SqliteCanonicalLedger,
    checkpoint: CanonicalReadCursor,
    durableTail: CanonicalReadCursor,
    chunkSize: number,
  ): CanonicalReadCursor {
    validateReadCursor(checkpoint);
    if (checkpoint.eventCount > durableTail.eventCount) {
      throw new Error('canonical read checkpoint is ahead of the durable ledger');
    }
    if (checkpoint.eventCount === durableTail.eventCount) {
      if (!sameCursor(checkpoint, durableTail)) {
        throw new Error('canonical read checkpoint conflicts with the durable tail');
      }
      return checkpoint;
    }

    let verified = Object.freeze({
      schemaVersion: CHANGE_FEED_SCHEMA_VERSION,
      eventCount: 0,
      lastSeq: 0,
      lastRecordedAt: 0,
      chainDigest: GENESIS_CHAIN_DIGEST,
    }) satisfies CanonicalReadCursor;
    while (verified.eventCount < checkpoint.eventCount) {
      const remaining = checkpoint.eventCount - verified.eventCount;
      const events = ledger.readRange(verified.eventCount + 1, Math.min(chunkSize, remaining));
      if (events.length === 0) throw new Error('durable ledger ended before the persisted checkpoint');
      verified = advanceCursor(verified, events);
    }
    if (!sameCursor(verified, checkpoint)) {
      throw new Error('persisted canonical read checkpoint failed prefix verification');
    }
    return checkpoint;
  }

  checkpoint(): CanonicalReadCursor {
    return canonicalClone(this.#checkpoint);
  }

  status(): CanonicalChangeFeedStatus {
    const durableTail = cursorFromDurable(this.#ledger.cursor());
    if (durableTail.eventCount < this.#checkpoint.eventCount) {
      throw new Error('durable ledger regressed behind the change-feed checkpoint');
    }
    if (
      durableTail.eventCount === this.#checkpoint.eventCount &&
      durableTail.chainDigest !== this.#checkpoint.chainDigest
    ) {
      throw new Error('durable ledger forked at the change-feed checkpoint');
    }
    return Object.freeze({
      checkpoint: this.checkpoint(),
      pending: this.#pending !== undefined,
      lagEvents: durableTail.eventCount - this.#checkpoint.eventCount,
      durableTail,
    });
  }

  poll(): CanonicalAppendBatch | undefined {
    if (this.#pending !== undefined) return this.#pending;
    const durableTail = cursorFromDurable(this.#ledger.cursor());
    if (durableTail.eventCount < this.#checkpoint.eventCount) {
      throw new Error('durable ledger regressed behind the change-feed checkpoint');
    }
    const delta = durableTail.eventCount - this.#checkpoint.eventCount;
    if (delta === 0) {
      if (!sameCursor(durableTail, this.#checkpoint)) {
        throw new Error('durable ledger forked at the change-feed checkpoint');
      }
      return undefined;
    }
    if (delta > this.#maxBatchEvents) {
      throw new Error(
        `canonical change-feed lag ${delta} exceeds maxBatchEvents ${this.#maxBatchEvents}; reopen with a larger bounded budget or use an explicit catch-up workflow`,
      );
    }
    const events = canonicalClone(
      this.#ledger.readRange(this.#checkpoint.eventCount + 1, delta),
    );
    if (events.length !== delta) {
      throw new Error('canonical change feed did not receive the complete durable delta');
    }
    const after = advanceCursor(this.#checkpoint, events);
    if (!sameCursor(after, durableTail)) {
      throw new Error('canonical change-feed delta does not reach the durable cursor');
    }
    const unsigned = Object.freeze({
      schemaVersion: CHANGE_FEED_SCHEMA_VERSION,
      base: this.checkpoint(),
      after,
      appendFromSeq: events[0]?.seq ?? after.lastSeq + 1,
      appendToSeq: events.at(-1)?.seq ?? after.lastSeq,
      appendDigest: appendDigest(events),
      events,
    });
    const batch = Object.freeze({
      ...unsigned,
      id: digest({ domain: 'cl-change-feed-batch-v1', batch: unsigned }),
    });
    this.#issuedBatches.add(batch as object);
    this.#pending = batch;
    return batch;
  }

  ack(batch: CanonicalAppendBatch): CanonicalReadCursor {
    if (
      typeof batch !== 'object' ||
      batch === null ||
      !this.#issuedBatches.has(batch as object) ||
      this.#pending !== batch
    ) {
      throw new Error('change-feed batch is not the outstanding capability issued by this feed');
    }
    if (!sameCursor(batch.base, this.#checkpoint)) {
      throw new Error('change-feed batch base no longer matches the consumer checkpoint');
    }
    this.#checkpoint = batch.after;
    this.#pending = undefined;
    return this.checkpoint();
  }

  retry(batch: CanonicalAppendBatch): void {
    if (
      typeof batch !== 'object' ||
      batch === null ||
      !this.#issuedBatches.has(batch as object) ||
      this.#pending !== batch
    ) {
      throw new Error('change-feed batch is not the outstanding capability issued by this feed');
    }
    this.#pending = undefined;
  }
}
