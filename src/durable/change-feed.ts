import { createHash } from 'node:crypto';

import type { MemoryEvent } from '../domain.js';
import {
  SqliteCanonicalLedger,
  type DurableCanonicalCursor,
} from './canonical-ledger.js';

export const CANONICAL_CHANGE_FEED_SCHEMA_VERSION = 1 as const;
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
  readonly schemaVersion: typeof CANONICAL_CHANGE_FEED_SCHEMA_VERSION;
  readonly eventCount: number;
  readonly lastSeq: number;
  readonly lastRecordedAt: number;
  readonly chainDigest: string;
}

export interface CanonicalAppendBatch {
  readonly schemaVersion: typeof CANONICAL_CHANGE_FEED_SCHEMA_VERSION;
  readonly id: string;
  readonly base: CanonicalReadCursor;
  readonly after: CanonicalReadCursor;
  readonly appendFromSeq: number;
  readonly appendToSeq: number;
  readonly appendDigest: string;
  /** Durable tail observed when this bounded batch was issued. */
  readonly durableTailAtIssue: CanonicalReadCursor;
  readonly events: readonly MemoryEvent[];
}

export interface CanonicalChangeFeedOptions {
  /** Persisted read checkpoint. Mutually exclusive with `startAt`. */
  readonly checkpoint?: CanonicalReadCursor;
  /** Safe default is genesis. Starting at tail must be explicit because it skips prior history. */
  readonly startAt?: 'genesis' | 'tail';
  readonly maxBatchEvents?: number;
  readonly verificationChunkSize?: number;
  /** Full durable audit is the default startup boundary. */
  readonly startupVerification?: 'full-audit' | 'tail-only';
}

export interface CanonicalChangeFeedStatus {
  readonly checkpoint: CanonicalReadCursor;
  readonly pending: boolean;
  readonly consuming: boolean;
  readonly lagEvents: number;
  readonly durableTail: CanonicalReadCursor;
}

function cursorFromDurable(cursor: DurableCanonicalCursor): CanonicalReadCursor {
  return Object.freeze({
    schemaVersion: CANONICAL_CHANGE_FEED_SCHEMA_VERSION,
    eventCount: cursor.eventCount,
    lastSeq: cursor.lastSeq,
    lastRecordedAt: cursor.lastRecordedAt,
    chainDigest: cursor.chainDigest,
  });
}

export function canonicalGenesisCursor(): CanonicalReadCursor {
  return Object.freeze({
    schemaVersion: CANONICAL_CHANGE_FEED_SCHEMA_VERSION,
    eventCount: 0,
    lastSeq: 0,
    lastRecordedAt: 0,
    chainDigest: GENESIS_CHAIN_DIGEST,
  });
}

export function assertCanonicalReadCursor(cursor: CanonicalReadCursor): void {
  if (
    typeof cursor !== 'object' ||
    cursor === null ||
    cursor.schemaVersion !== CANONICAL_CHANGE_FEED_SCHEMA_VERSION ||
    !Number.isSafeInteger(cursor.eventCount) ||
    cursor.eventCount < 0 ||
    !Number.isSafeInteger(cursor.lastSeq) ||
    cursor.lastSeq !== cursor.eventCount ||
    !Number.isSafeInteger(cursor.lastRecordedAt) ||
    cursor.lastRecordedAt < 0 ||
    typeof cursor.chainDigest !== 'string' ||
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

export function sameCanonicalReadCursor(
  left: CanonicalReadCursor,
  right: CanonicalReadCursor,
): boolean {
  return (
    left.schemaVersion === right.schemaVersion &&
    left.eventCount === right.eventCount &&
    left.lastSeq === right.lastSeq &&
    left.lastRecordedAt === right.lastRecordedAt &&
    left.chainDigest === right.chainDigest
  );
}

export function canonicalReadCursorDigest(cursor: CanonicalReadCursor): string {
  assertCanonicalReadCursor(cursor);
  return digest({ domain: 'cl-consumer-cursor-v1', cursor });
}

export function canonicalReadCursorForEvents(
  events: readonly MemoryEvent[],
): CanonicalReadCursor {
  if (!Array.isArray(events)) throw new TypeError('canonical events must be an array');
  const snapshot = canonicalClone(Array.from(events));
  return advanceCursor(canonicalGenesisCursor(), snapshot);
}

function advanceCursor(
  base: CanonicalReadCursor,
  events: readonly MemoryEvent[],
): CanonicalReadCursor {
  assertCanonicalReadCursor(base);
  let chain = base.chainDigest;
  let expectedSeq = base.lastSeq + 1;
  let recordedAt = base.lastRecordedAt;
  for (const event of events) {
    if (
      !Number.isSafeInteger(event.seq) ||
      event.seq !== expectedSeq ||
      !Number.isSafeInteger(event.recordedAt) ||
      event.recordedAt < recordedAt
    ) {
      throw new Error(`canonical change-feed append is malformed at sequence ${expectedSeq}`);
    }
    chain = nextChainDigest(chain, event);
    recordedAt = event.recordedAt;
    expectedSeq += 1;
  }
  return Object.freeze({
    schemaVersion: CANONICAL_CHANGE_FEED_SCHEMA_VERSION,
    eventCount: base.eventCount + events.length,
    lastSeq: base.lastSeq + events.length,
    lastRecordedAt: recordedAt,
    chainDigest: chain,
  });
}

export function verifyCanonicalAppendBatch(batch: CanonicalAppendBatch): void {
  if (
    typeof batch !== 'object' ||
    batch === null ||
    batch.schemaVersion !== CANONICAL_CHANGE_FEED_SCHEMA_VERSION ||
    typeof batch.id !== 'string' ||
    !SHA256_PATTERN.test(batch.id) ||
    !Array.isArray(batch.events) ||
    batch.events.length === 0 ||
    batch.events.length > MAX_BATCH_EVENTS ||
    !Number.isSafeInteger(batch.appendFromSeq) ||
    !Number.isSafeInteger(batch.appendToSeq) ||
    typeof batch.appendDigest !== 'string' ||
    !SHA256_PATTERN.test(batch.appendDigest)
  ) {
    throw new Error('canonical append batch shape is invalid');
  }
  assertCanonicalReadCursor(batch.base);
  assertCanonicalReadCursor(batch.after);
  assertCanonicalReadCursor(batch.durableTailAtIssue);
  if (
    batch.appendFromSeq !== batch.base.lastSeq + 1 ||
    batch.appendToSeq !== batch.after.lastSeq ||
    batch.events.length !== batch.after.eventCount - batch.base.eventCount ||
    batch.events[0]?.seq !== batch.appendFromSeq ||
    batch.events.at(-1)?.seq !== batch.appendToSeq ||
    batch.after.eventCount > batch.durableTailAtIssue.eventCount
  ) {
    throw new Error('canonical append batch sequence interval is invalid');
  }
  const after = advanceCursor(batch.base, batch.events);
  if (!sameCanonicalReadCursor(after, batch.after)) {
    throw new Error('canonical append batch cursor transition is invalid');
  }
  if (appendDigest(batch.events) !== batch.appendDigest) {
    throw new Error('canonical append batch append digest is invalid');
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
    throw new Error('canonical append batch id is invalid');
  }
}

/**
 * Verified pull-based change feed over `SqliteCanonicalLedger`.
 *
 * Startup/resume verification remains O(N). After that, each poll verifies and returns at most
 * `maxBatchEvents`; a lag larger than one batch is consumed through several bounded batches.
 */
export class CanonicalChangeFeed {
  readonly #ledger: SqliteCanonicalLedger;
  readonly #issuedBatches = new WeakSet<object>();
  readonly #maxBatchEvents: number;
  #checkpoint: CanonicalReadCursor;
  #pending: CanonicalAppendBatch | undefined;
  #consuming = false;

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
    if (
      !Number.isSafeInteger(maxBatchEvents) ||
      maxBatchEvents <= 0 ||
      maxBatchEvents > MAX_BATCH_EVENTS
    ) {
      throw new RangeError(`maxBatchEvents must be an integer in [1, ${MAX_BATCH_EVENTS}]`);
    }
    const verificationChunkSize = options.verificationChunkSize ?? DEFAULT_VERIFICATION_CHUNK;
    if (
      !Number.isSafeInteger(verificationChunkSize) ||
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
    if (options.checkpoint !== undefined && options.startAt !== undefined) {
      throw new Error('checkpoint and startAt are mutually exclusive');
    }
    if (options.startAt !== undefined && options.startAt !== 'genesis' && options.startAt !== 'tail') {
      throw new Error('startAt must be genesis or tail');
    }
    if (startupVerification === 'full-audit') {
      const audit = ledger.audit();
      if (!audit.ok) throw new Error(`canonical change feed cannot open: ${audit.errors.join('; ')}`);
    } else {
      const status = ledger.status();
      if (!status.ok) throw new Error(`canonical change feed cannot open: ${status.reason}`);
    }

    const durableTail = cursorFromDurable(ledger.cursor());
    let checkpoint: CanonicalReadCursor;
    if (options.checkpoint !== undefined) {
      checkpoint = CanonicalChangeFeed.#verifyPersistedCheckpoint(
        ledger,
        canonicalClone(options.checkpoint),
        durableTail,
        verificationChunkSize,
      );
    } else if ((options.startAt ?? 'genesis') === 'tail') {
      checkpoint = durableTail;
    } else {
      checkpoint = canonicalGenesisCursor();
    }
    return new CanonicalChangeFeed(ledger, checkpoint, maxBatchEvents);
  }

  static #verifyPersistedCheckpoint(
    ledger: SqliteCanonicalLedger,
    checkpoint: CanonicalReadCursor,
    durableTail: CanonicalReadCursor,
    chunkSize: number,
  ): CanonicalReadCursor {
    assertCanonicalReadCursor(checkpoint);
    if (checkpoint.eventCount > durableTail.eventCount) {
      throw new Error('canonical read checkpoint is ahead of the durable ledger');
    }
    if (checkpoint.eventCount === durableTail.eventCount) {
      if (!sameCanonicalReadCursor(checkpoint, durableTail)) {
        throw new Error('canonical read checkpoint conflicts with the durable tail');
      }
      return checkpoint;
    }

    let verified = canonicalGenesisCursor();
    while (verified.eventCount < checkpoint.eventCount) {
      const remaining = checkpoint.eventCount - verified.eventCount;
      const events = ledger.readRange(verified.eventCount + 1, Math.min(chunkSize, remaining));
      if (events.length === 0) throw new Error('durable ledger ended before the persisted checkpoint');
      verified = advanceCursor(verified, events);
    }
    if (!sameCanonicalReadCursor(verified, checkpoint)) {
      throw new Error('persisted canonical read checkpoint failed prefix verification');
    }
    return checkpoint;
  }

  #assertNotConsuming(action: string): void {
    if (this.#consuming) {
      throw new Error(`change-feed ${action} is not allowed during an active consumer transaction`);
    }
  }

  #assertOutstanding(batch: CanonicalAppendBatch): void {
    if (
      typeof batch !== 'object' ||
      batch === null ||
      !this.#issuedBatches.has(batch as object) ||
      this.#pending !== batch
    ) {
      throw new Error('change-feed batch is not the outstanding capability issued by this feed');
    }
    if (!sameCanonicalReadCursor(batch.base, this.#checkpoint)) {
      throw new Error('change-feed batch base no longer matches the consumer checkpoint');
    }
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
      consuming: this.#consuming,
      lagEvents: durableTail.eventCount - this.#checkpoint.eventCount,
      durableTail,
    });
  }

  poll(): CanonicalAppendBatch | undefined {
    this.#assertNotConsuming('poll');
    if (this.#pending !== undefined) return this.#pending;
    const durableTail = cursorFromDurable(this.#ledger.cursor());
    if (durableTail.eventCount < this.#checkpoint.eventCount) {
      throw new Error('durable ledger regressed behind the change-feed checkpoint');
    }
    const lag = durableTail.eventCount - this.#checkpoint.eventCount;
    if (lag === 0) {
      if (!sameCanonicalReadCursor(durableTail, this.#checkpoint)) {
        throw new Error('durable ledger forked at the change-feed checkpoint');
      }
      return undefined;
    }

    const batchSize = Math.min(lag, this.#maxBatchEvents);
    const events = canonicalClone(
      this.#ledger.readRange(this.#checkpoint.eventCount + 1, batchSize),
    );
    if (events.length !== batchSize) {
      throw new Error('canonical change feed did not receive the complete bounded range');
    }
    const after = advanceCursor(this.#checkpoint, events);
    if (after.eventCount === durableTail.eventCount && !sameCanonicalReadCursor(after, durableTail)) {
      throw new Error('canonical change-feed range does not reach the expected durable cursor');
    }
    const identity = Object.freeze({
      schemaVersion: CANONICAL_CHANGE_FEED_SCHEMA_VERSION,
      base: this.checkpoint(),
      after,
      appendFromSeq: events[0]?.seq ?? after.lastSeq + 1,
      appendToSeq: events.at(-1)?.seq ?? after.lastSeq,
      appendDigest: appendDigest(events),
      events,
    });
    const batch = Object.freeze({
      ...identity,
      durableTailAtIssue: durableTail,
      id: digest({ domain: 'cl-change-feed-batch-v1', batch: identity }),
    });
    verifyCanonicalAppendBatch(batch);
    this.#issuedBatches.add(batch as object);
    this.#pending = batch;
    return batch;
  }

  consume<T>(
    batch: CanonicalAppendBatch,
    operation: (batch: CanonicalAppendBatch) => T,
  ): T {
    if (typeof operation !== 'function') {
      throw new TypeError('change-feed consumer operation must be a function');
    }
    this.#assertNotConsuming('consume');
    this.#assertOutstanding(batch);
    this.#consuming = true;
    try {
      const value = operation(batch);
      if (
        value !== null &&
        typeof value === 'object' &&
        typeof (value as { readonly then?: unknown }).then === 'function'
      ) {
        throw new Error('change-feed consumer operation must be synchronous');
      }
      if (this.#pending !== batch || !sameCanonicalReadCursor(batch.base, this.#checkpoint)) {
        throw new Error('change-feed state changed during consumer operation');
      }
      this.#checkpoint = batch.after;
      this.#pending = undefined;
      this.#issuedBatches.delete(batch as object);
      return value;
    } finally {
      this.#consuming = false;
    }
  }

  ack(batch: CanonicalAppendBatch): CanonicalReadCursor {
    this.#assertNotConsuming('ack');
    this.#assertOutstanding(batch);
    this.#checkpoint = batch.after;
    this.#pending = undefined;
    this.#issuedBatches.delete(batch as object);
    return this.checkpoint();
  }

  retry(batch: CanonicalAppendBatch): CanonicalAppendBatch {
    this.#assertNotConsuming('retry');
    this.#assertOutstanding(batch);
    // A retry is the same delivery attempt, not permission to widen the batch to a newer tail.
    // Keep the exact issued capability pending until it is consumed or acknowledged.
    return batch;
  }
}
