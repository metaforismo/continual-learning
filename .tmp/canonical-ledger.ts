import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

import { EVENT_SCHEMA_VERSION, type MemoryEvent } from '../domain.js';
import { MemoryKernel } from '../kernel.js';

const DURABLE_SCHEMA_VERSION = 1 as const;
const MAX_APPEND_EVENTS = 256;
const MAX_REQUEST_CHARACTERS = 2_000_000;
const MAX_RANGE_EVENTS = 1_000;
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

function cloneJson<T>(value: T): T {
  return JSON.parse(stableJson(value)) as T;
}

function contentDigest(value: unknown): string {
  return `sha256:${createHash('sha256').update(stableJson(value)).digest('hex')}`;
}

const GENESIS_CHAIN_DIGEST = contentDigest({ domain: 'cl-canonical-event-chain-genesis-v1' });
const GENESIS_RECEIPT_DIGEST = contentDigest({ domain: 'cl-canonical-receipt-chain-genesis-v1' });

export type DurableCommitFaultPoint =
  | 'after-begin'
  | 'after-prefix-audit'
  | 'after-events'
  | 'after-audit'
  | 'after-receipt'
  | 'after-cursor'
  | 'before-commit';

export interface DurableCanonicalLedgerOptions {
  readonly database?: string;
  readonly busyTimeoutMs?: number;
  readonly maxAppendEvents?: number;
  readonly maxRequestCharacters?: number;
  readonly faultInjector?: (point: DurableCommitFaultPoint) => void;
}

export interface DurableCanonicalCursor {
  readonly schemaVersion: typeof DURABLE_SCHEMA_VERSION;
  readonly revision: number;
  readonly eventCount: number;
  readonly lastSeq: number;
  readonly lastRecordedAt: number;
  readonly chainDigest: string;
  readonly latestReceiptDigest: string;
}

export interface DurableTransitionMetadata {
  readonly proposalId: string;
  readonly proposalDigest: string;
  readonly resultDigest: string;
  readonly verdict: 'accept';
  readonly actualRisk: 'low' | 'medium' | 'high' | 'destructive';
  readonly policyId: string;
  readonly policyVersion: string;
  readonly policyDigest: string;
  readonly verifierId: string;
  readonly verifierConfigDigest: string;
}

export interface DurableAuditRecord {
  readonly schemaVersion: number;
  readonly id: string;
  readonly seq: number;
  readonly recordedAt: number;
  readonly actor: string;
  readonly proposalId: string;
  readonly proposalDigest: string;
  readonly resultDigest: string;
  readonly verdict: 'accept';
  readonly actualRisk: 'low' | 'medium' | 'high' | 'destructive';
  readonly policyId: string;
  readonly policyVersion: string;
  readonly policyDigest: string;
  readonly verifierId: string;
  readonly verifierConfigDigest: string;
  readonly findingCodes: readonly string[];
  readonly [key: string]: unknown;
}

export interface DurableCommitRequest {
  /** Process-local capability returned by `cursor()` or a prior successful commit. */
  readonly base: DurableCanonicalCursor;
  readonly idempotencyKey: string;
  readonly committedBy: string;
  readonly events: readonly MemoryEvent[];
  readonly transition: DurableTransitionMetadata;
  readonly audit: DurableAuditRecord;
}

interface NormalizedDurableCommitRequest {
  readonly base: DurableCanonicalCursor;
  readonly idempotencyKey: string;
  readonly committedBy: string;
  readonly events: readonly MemoryEvent[];
  readonly transition: DurableTransitionMetadata;
  readonly audit: DurableAuditRecord;
  readonly requestDigest: string;
}

export interface DurableCommitReceipt {
  readonly schemaVersion: typeof DURABLE_SCHEMA_VERSION;
  readonly revision: number;
  readonly idempotencyKey: string;
  readonly requestDigest: string;
  readonly transition: DurableTransitionMetadata;
  readonly auditId: string;
  readonly auditDigest: string;
  readonly baseChainDigest: string;
  readonly afterChainDigest: string;
  readonly appendFromSeq: number;
  readonly appendToSeq: number;
  readonly appendDigest: string;
  readonly previousReceiptDigest: string;
  readonly receiptDigest: string;
  readonly committedBy: string;
  readonly committedAt: number;
}

export interface DurableCommitResult {
  readonly cursor: DurableCanonicalCursor;
  readonly receipt: DurableCommitReceipt;
  readonly idempotentReplay: boolean;
}

export interface DurableLedgerStatus {
  readonly ok: boolean;
  readonly reason: string;
  readonly cursor: DurableCanonicalCursor;
}

export interface DurableLedgerAudit {
  readonly ok: boolean;
  readonly errors: readonly string[];
  readonly cursor: DurableCanonicalCursor;
  readonly receiptCount: number;
}

interface MetaRow {
  readonly schema_version: number;
  readonly revision: number;
  readonly event_count: number;
  readonly last_seq: number;
  readonly last_recorded_at: number;
  readonly chain_digest: string;
  readonly latest_receipt_digest: string;
  readonly updated_at: number;
}

interface EventRow {
  readonly seq: number;
  readonly event_id: string;
  readonly recorded_at: number;
  readonly event_json: string;
  readonly event_digest: string;
  readonly previous_chain_digest: string;
  readonly chain_digest: string;
  readonly revision: number;
}

interface ReceiptRow {
  readonly revision: number;
  readonly idempotency_key: string;
  readonly request_digest: string;
  readonly transition_json: string;
  readonly transition_digest: string;
  readonly audit_id: string;
  readonly audit_digest: string;
  readonly base_chain_digest: string;
  readonly after_chain_digest: string;
  readonly append_from_seq: number;
  readonly append_to_seq: number;
  readonly append_digest: string;
  readonly previous_receipt_digest: string;
  readonly receipt_digest: string;
  readonly committed_by: string;
  readonly committed_at: number;
}

interface AuditRow {
  readonly revision: number;
  readonly audit_id: string;
  readonly audit_json: string;
  readonly audit_digest: string;
  readonly receipt_digest: string;
}

function assertDigest(value: string, label: string): void {
  if (!SHA256_PATTERN.test(value)) throw new Error(`${label} must be a SHA-256 content address`);
}

function eventDigest(event: MemoryEvent): string {
  return contentDigest({ domain: 'cl-canonical-event-v1', event });
}

function nextChainDigest(previous: string, event: MemoryEvent, digest: string): string {
  return contentDigest({
    domain: 'cl-canonical-event-chain-v1',
    previous,
    seq: event.seq,
    eventDigest: digest,
  });
}

function appendDigest(events: readonly MemoryEvent[]): string {
  return contentDigest({
    domain: 'cl-canonical-append-v1',
    events: events.map((event) => ({
      seq: event.seq,
      eventId: event.id,
      eventDigest: eventDigest(event),
    })),
  });
}

function transitionDigest(transition: DurableTransitionMetadata): string {
  return contentDigest({ domain: 'cl-durable-transition-metadata-v1', transition });
}

function auditDigest(audit: DurableAuditRecord): string {
  return contentDigest({ domain: 'cl-durable-transition-audit-v1', audit });
}

function receiptPayload(receipt: Omit<DurableCommitReceipt, 'receiptDigest'>): unknown {
  return { domain: 'cl-durable-receipt-v1', ...receipt };
}

function cursorFromMeta(meta: MetaRow): DurableCanonicalCursor {
  if (
    meta.schema_version !== DURABLE_SCHEMA_VERSION ||
    !Number.isInteger(meta.revision) ||
    meta.revision < 0 ||
    !Number.isInteger(meta.event_count) ||
    meta.event_count < 0 ||
    !Number.isInteger(meta.last_seq) ||
    meta.last_seq < 0 ||
    !Number.isInteger(meta.last_recorded_at) ||
    meta.last_recorded_at < 0 ||
    !Number.isInteger(meta.updated_at) ||
    meta.updated_at < 0 ||
    meta.last_seq !== meta.event_count ||
    meta.revision > meta.event_count
  ) {
    throw new Error('durable canonical metadata is malformed');
  }
  assertDigest(meta.chain_digest, 'canonical chain digest');
  assertDigest(meta.latest_receipt_digest, 'latest receipt digest');
  return Object.freeze({
    schemaVersion: DURABLE_SCHEMA_VERSION,
    revision: meta.revision,
    eventCount: meta.event_count,
    lastSeq: meta.last_seq,
    lastRecordedAt: meta.last_recorded_at,
    chainDigest: meta.chain_digest,
    latestReceiptDigest: meta.latest_receipt_digest,
  });
}

function validateTransition(transition: DurableTransitionMetadata): void {
  for (const [label, value] of [
    ['proposal id', transition.proposalId],
    ['policy id', transition.policyId],
    ['policy version', transition.policyVersion],
    ['verifier id', transition.verifierId],
  ] as const) {
    if (typeof value !== 'string' || value.trim().length === 0) {
      throw new Error(`${label} cannot be empty`);
    }
  }
  for (const [label, value] of [
    ['proposal digest', transition.proposalDigest],
    ['result digest', transition.resultDigest],
    ['policy digest', transition.policyDigest],
    ['verifier config digest', transition.verifierConfigDigest],
  ] as const) {
    assertDigest(value, label);
  }
  if (transition.verdict !== 'accept') throw new Error('only accepted transitions may be persisted');
  if (!['low', 'medium', 'high', 'destructive'].includes(transition.actualRisk)) {
    throw new Error('transition risk is invalid');
  }
}

function validateAudit(audit: DurableAuditRecord, transition: DurableTransitionMetadata): void {
  if (
    !Number.isInteger(audit.schemaVersion) ||
    audit.schemaVersion <= 0 ||
    typeof audit.id !== 'string' ||
    audit.id.trim().length === 0 ||
    !Number.isInteger(audit.seq) ||
    audit.seq <= 0 ||
    !Number.isFinite(audit.recordedAt) ||
    audit.recordedAt < 0 ||
    typeof audit.actor !== 'string' ||
    audit.actor.trim().length === 0
  ) {
    throw new Error('durable transition audit shape is invalid');
  }
  if (
    audit.proposalId !== transition.proposalId ||
    audit.proposalDigest !== transition.proposalDigest ||
    audit.resultDigest !== transition.resultDigest ||
    audit.verdict !== transition.verdict ||
    audit.actualRisk !== transition.actualRisk ||
    audit.policyId !== transition.policyId ||
    audit.policyVersion !== transition.policyVersion ||
    audit.policyDigest !== transition.policyDigest ||
    audit.verifierId !== transition.verifierId ||
    audit.verifierConfigDigest !== transition.verifierConfigDigest
  ) {
    throw new Error('durable audit does not describe the supplied verified transition');
  }
  if (
    !Array.isArray(audit.findingCodes) ||
    audit.findingCodes.some((code) => typeof code !== 'string' || code.trim().length === 0) ||
    new Set(audit.findingCodes).size !== audit.findingCodes.length
  ) {
    throw new Error('durable audit finding codes must be unique non-empty strings');
  }
}

function receiptFromRow(row: ReceiptRow): DurableCommitReceipt {
  for (const [label, value] of [
    ['revision', row.revision],
    ['append start', row.append_from_seq],
    ['append end', row.append_to_seq],
    ['committedAt', row.committed_at],
  ] as const) {
    if (!Number.isInteger(value) || value <= 0) throw new Error(`receipt ${label} is invalid`);
  }
  if (row.append_to_seq < row.append_from_seq) throw new Error('receipt append range is invalid');
  if (
    row.idempotency_key.trim().length === 0 ||
    row.audit_id.trim().length === 0 ||
    row.committed_by.trim().length === 0
  ) {
    throw new Error('receipt identity fields are invalid');
  }
  const transition = JSON.parse(row.transition_json) as DurableTransitionMetadata;
  if (stableJson(transition) !== row.transition_json) {
    throw new Error(`transition JSON is not canonical at revision ${row.revision}`);
  }
  validateTransition(transition);
  const receipt = Object.freeze({
    schemaVersion: DURABLE_SCHEMA_VERSION,
    revision: row.revision,
    idempotencyKey: row.idempotency_key,
    requestDigest: row.request_digest,
    transition,
    auditId: row.audit_id,
    auditDigest: row.audit_digest,
    baseChainDigest: row.base_chain_digest,
    afterChainDigest: row.after_chain_digest,
    appendFromSeq: row.append_from_seq,
    appendToSeq: row.append_to_seq,
    appendDigest: row.append_digest,
    previousReceiptDigest: row.previous_receipt_digest,
    receiptDigest: row.receipt_digest,
    committedBy: row.committed_by,
    committedAt: row.committed_at,
  });
  for (const [label, value] of [
    ['request digest', receipt.requestDigest],
    ['transition digest', row.transition_digest],
    ['audit digest', receipt.auditDigest],
    ['base chain digest', receipt.baseChainDigest],
    ['after chain digest', receipt.afterChainDigest],
    ['append digest', receipt.appendDigest],
    ['previous receipt digest', receipt.previousReceiptDigest],
    ['receipt digest', receipt.receiptDigest],
  ] as const) {
    assertDigest(value, label);
  }
  if (transitionDigest(transition) !== row.transition_digest) {
    throw new Error(`transition metadata digest mismatch at revision ${row.revision}`);
  }
  const { receiptDigest: _ignored, ...unsigned } = receipt;
  if (contentDigest(receiptPayload(unsigned)) !== receipt.receiptDigest) {
    throw new Error(`receipt digest mismatch at revision ${row.revision}`);
  }
  return receipt;
}

/**
 * Durable canonical event-byte store.
 *
 * V1 deliberately replays and re-hashes the complete canonical prefix before every new commit.
 * This makes corruption and semantic drift fail closed, but new-commit cost remains O(N). Exact
 * idempotent retries are resolved from the durable receipt before a process-local cursor capability
 * is required.
 */
export class SqliteCanonicalLedger {
  readonly #db: DatabaseSync;
  readonly #issuedCursors = new WeakSet<object>();
  readonly #maxAppendEvents: number;
  readonly #maxRequestCharacters: number;
  readonly #faultInjector: DurableCanonicalLedgerOptions['faultInjector'];
  #closed = false;

  constructor(options: DurableCanonicalLedgerOptions = {}) {
    const busyTimeoutMs = options.busyTimeoutMs ?? 5_000;
    if (!Number.isInteger(busyTimeoutMs) || busyTimeoutMs < 0 || busyTimeoutMs > 60_000) {
      throw new RangeError('busyTimeoutMs must be an integer in [0, 60000]');
    }
    this.#maxAppendEvents = options.maxAppendEvents ?? MAX_APPEND_EVENTS;
    if (
      !Number.isInteger(this.#maxAppendEvents) ||
      this.#maxAppendEvents <= 0 ||
      this.#maxAppendEvents > 4_096
    ) {
      throw new RangeError('maxAppendEvents must be an integer in [1, 4096]');
    }
    this.#maxRequestCharacters = options.maxRequestCharacters ?? MAX_REQUEST_CHARACTERS;
    if (
      !Number.isInteger(this.#maxRequestCharacters) ||
      this.#maxRequestCharacters < 1_024 ||
      this.#maxRequestCharacters > 20_000_000
    ) {
      throw new RangeError('maxRequestCharacters must be an integer in [1024, 20000000]');
    }
    this.#faultInjector = options.faultInjector;
    this.#db = new DatabaseSync(options.database ?? ':memory:');
    this.#db.exec(`PRAGMA busy_timeout = ${busyTimeoutMs}`);
    this.#db.exec('PRAGMA foreign_keys = ON');
    this.#initializeSchema();
    this.status();
  }

  #assertOpen(): void {
    if (this.#closed) throw new Error('durable canonical ledger is closed');
  }

  #inject(point: DurableCommitFaultPoint): void {
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
    const expected = new Set([
      'cl_canonical_meta',
      'cl_canonical_events',
      'cl_canonical_receipts',
      'cl_canonical_audits',
    ]);
    const rows = this.#db
      .prepare(`SELECT name FROM sqlite_master WHERE name LIKE 'cl_canonical_%'`)
      .all() as unknown as readonly { readonly name: string }[];
    const names = new Set(rows.map((row) => row.name));
    if (names.size > 0 && [...expected].some((name) => !names.has(name))) {
      throw new Error('durable canonical schema is partially present; manual recovery is required');
    }
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS cl_canonical_meta (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        schema_version INTEGER NOT NULL,
        revision INTEGER NOT NULL,
        event_count INTEGER NOT NULL,
        last_seq INTEGER NOT NULL,
        last_recorded_at INTEGER NOT NULL,
        chain_digest TEXT NOT NULL,
        latest_receipt_digest TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS cl_canonical_events (
        seq INTEGER PRIMARY KEY,
        event_id TEXT NOT NULL UNIQUE,
        recorded_at INTEGER NOT NULL,
        event_json TEXT NOT NULL,
        event_digest TEXT NOT NULL,
        previous_chain_digest TEXT NOT NULL,
        chain_digest TEXT NOT NULL UNIQUE,
        revision INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS cl_canonical_receipts (
        revision INTEGER PRIMARY KEY,
        idempotency_key TEXT NOT NULL UNIQUE,
        request_digest TEXT NOT NULL,
        transition_json TEXT NOT NULL,
        transition_digest TEXT NOT NULL,
        audit_id TEXT NOT NULL UNIQUE,
        audit_digest TEXT NOT NULL,
        base_chain_digest TEXT NOT NULL,
        after_chain_digest TEXT NOT NULL,
        append_from_seq INTEGER NOT NULL,
        append_to_seq INTEGER NOT NULL,
        append_digest TEXT NOT NULL,
        previous_receipt_digest TEXT NOT NULL,
        receipt_digest TEXT NOT NULL UNIQUE,
        committed_by TEXT NOT NULL,
        committed_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS cl_canonical_audits (
        revision INTEGER PRIMARY KEY,
        audit_id TEXT NOT NULL UNIQUE,
        audit_json TEXT NOT NULL,
        audit_digest TEXT NOT NULL UNIQUE,
        receipt_digest TEXT NOT NULL UNIQUE
      );
    `);
    const existing = this.#metaOrUndefined();
    if (existing === undefined) {
      this.#db
        .prepare(`
          INSERT INTO cl_canonical_meta
            (id, schema_version, revision, event_count, last_seq, last_recorded_at,
             chain_digest, latest_receipt_digest, updated_at)
          VALUES (1, ?, 0, 0, 0, 0, ?, ?, 0)
        `)
        .run(DURABLE_SCHEMA_VERSION, GENESIS_CHAIN_DIGEST, GENESIS_RECEIPT_DIGEST);
    } else if (existing.schema_version !== DURABLE_SCHEMA_VERSION) {
      throw new Error(`unsupported durable canonical schema version: ${existing.schema_version}`);
    }
  }

  #metaOrUndefined(): MetaRow | undefined {
    return this.#db.prepare('SELECT * FROM cl_canonical_meta WHERE id = 1').get() as
      | MetaRow
      | undefined;
  }

  #meta(): MetaRow {
    const meta = this.#metaOrUndefined();
    if (meta === undefined) throw new Error('durable canonical metadata is missing');
    cursorFromMeta(meta);
    return meta;
  }

  #issueCursor(meta: MetaRow): DurableCanonicalCursor {
    const cursor = cursorFromMeta(meta);
    this.#issuedCursors.add(cursor as object);
    return cursor;
  }

  #assertCursorCapability(cursor: DurableCanonicalCursor): void {
    if (typeof cursor !== 'object' || cursor === null || !this.#issuedCursors.has(cursor as object)) {
      throw new Error('base cursor is not a capability issued by this ledger instance');
    }
  }

  #lastEvent(): EventRow | undefined {
    return this.#db
      .prepare('SELECT * FROM cl_canonical_events ORDER BY seq DESC LIMIT 1')
      .get() as EventRow | undefined;
  }

  #latestReceipt(): ReceiptRow | undefined {
    return this.#db
      .prepare('SELECT * FROM cl_canonical_receipts ORDER BY revision DESC LIMIT 1')
      .get() as ReceiptRow | undefined;
  }

  #auditForRevision(revision: number): AuditRow | undefined {
    return this.#db
      .prepare('SELECT * FROM cl_canonical_audits WHERE revision = ?')
      .get(revision) as AuditRow | undefined;
  }

  #verifiedAudit(row: AuditRow, receipt: DurableCommitReceipt): DurableAuditRecord {
    if (
      row.revision !== receipt.revision ||
      row.audit_id !== receipt.auditId ||
      row.audit_digest !== receipt.auditDigest ||
      row.receipt_digest !== receipt.receiptDigest
    ) {
      throw new Error(`audit/receipt metadata mismatch at revision ${receipt.revision}`);
    }
    const audit = JSON.parse(row.audit_json) as DurableAuditRecord;
    if (stableJson(audit) !== row.audit_json) {
      throw new Error(`audit JSON is not canonical at revision ${receipt.revision}`);
    }
    validateAudit(audit, receipt.transition);
    if (auditDigest(audit) !== receipt.auditDigest) {
      throw new Error(`audit digest mismatch at revision ${receipt.revision}`);
    }
    return audit;
  }

  #loadEventsVerified(meta: MetaRow): readonly MemoryEvent[] {
    const rows = this.#db
      .prepare('SELECT * FROM cl_canonical_events ORDER BY seq')
      .all() as unknown as readonly EventRow[];
    if (rows.length !== meta.event_count) throw new Error('canonical event count differs from metadata');
    const events: MemoryEvent[] = [];
    let previous = GENESIS_CHAIN_DIGEST;
    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index];
      if (
        row === undefined ||
        row.seq !== index + 1 ||
        !Number.isInteger(row.revision) ||
        row.revision <= 0
      ) {
        throw new Error(`canonical event sequence or revision gap at ${index + 1}`);
      }
      const parsed = JSON.parse(row.event_json) as MemoryEvent;
      if (stableJson(parsed) !== row.event_json) {
        throw new Error(`canonical event JSON is not canonical at sequence ${row.seq}`);
      }
      if (
        parsed.seq !== row.seq ||
        parsed.id !== row.event_id ||
        parsed.recordedAt !== row.recorded_at ||
        parsed.schemaVersion !== EVENT_SCHEMA_VERSION
      ) {
        throw new Error(`canonical event row metadata diverges at sequence ${row.seq}`);
      }
      const expectedEventDigest = eventDigest(parsed);
      if (expectedEventDigest !== row.event_digest) {
        throw new Error(`canonical event digest mismatch at sequence ${row.seq}`);
      }
      if (row.previous_chain_digest !== previous) {
        throw new Error(`canonical event predecessor mismatch at sequence ${row.seq}`);
      }
      const expectedChain = nextChainDigest(previous, parsed, expectedEventDigest);
      if (expectedChain !== row.chain_digest) {
        throw new Error(`canonical event chain mismatch at sequence ${row.seq}`);
      }
      previous = row.chain_digest;
      events.push(parsed);
    }
    if (previous !== meta.chain_digest) throw new Error('canonical event chain head differs from metadata');
    if (
      (events.at(-1)?.seq ?? 0) !== meta.last_seq ||
      (events.at(-1)?.recordedAt ?? 0) !== meta.last_recorded_at
    ) {
      throw new Error('canonical event tail differs from metadata');
    }
    return MemoryKernel.from(events).events();
  }

  #requestSnapshot(request: DurableCommitRequest): NormalizedDurableCommitRequest {
    if (
      typeof request !== 'object' ||
      request === null ||
      typeof request.idempotencyKey !== 'string' ||
      typeof request.committedBy !== 'string' ||
      !Array.isArray(request.events) ||
      typeof request.base !== 'object' ||
      request.base === null
    ) {
      throw new TypeError('durable commit request has an invalid runtime shape');
    }
    const base = cloneJson(request.base);
    const events = cloneJson(request.events);
    const transition = cloneJson(request.transition);
    const audit = cloneJson(request.audit);
    const payload = {
      base,
      idempotencyKey: request.idempotencyKey,
      committedBy: request.committedBy,
      events,
      transition,
      audit,
    };
    const canonical = stableJson(payload);
    if (canonical.length > this.#maxRequestCharacters) {
      throw new RangeError('durable commit request exceeds the canonical size budget');
    }
    return Object.freeze({
      ...payload,
      requestDigest: contentDigest({ domain: 'cl-durable-request-v1', payload }),
    });
  }

  #validateRequest(snapshot: NormalizedDurableCommitRequest): void {
    if (
      snapshot.idempotencyKey.trim().length === 0 ||
      snapshot.idempotencyKey.length > 256 ||
      snapshot.committedBy.trim().length === 0 ||
      snapshot.committedBy.length > 256
    ) {
      throw new Error('idempotencyKey and committedBy must be non-empty and bounded');
    }
    if (snapshot.events.length === 0 || snapshot.events.length > this.#maxAppendEvents) {
      throw new RangeError(`durable append requires 1..${this.#maxAppendEvents} events`);
    }
    validateTransition(snapshot.transition);
    validateAudit(snapshot.audit, snapshot.transition);
  }

  #idempotentReceipt(
    key: string,
    requestDigestValue: string,
  ): { readonly receipt: DurableCommitReceipt; readonly meta: MetaRow } | undefined {
    const row = this.#db
      .prepare('SELECT * FROM cl_canonical_receipts WHERE idempotency_key = ?')
      .get(key) as ReceiptRow | undefined;
    if (row === undefined) return undefined;
    if (row.request_digest !== requestDigestValue) {
      throw new Error('idempotency key was already used for a different durable request');
    }
    const receipt = receiptFromRow(row);
    this.#verifiedAudit(
      this.#auditForRevision(receipt.revision) ?? (() => { throw new Error('idempotent receipt audit is missing'); })(),
      receipt,
    );
    const meta = this.#meta();
    if (
      meta.revision < receipt.revision ||
      (meta.revision === receipt.revision && meta.chain_digest !== receipt.afterChainDigest)
    ) {
      throw new Error('idempotent receipt is not represented by the current canonical cursor');
    }
    return Object.freeze({ receipt, meta });
  }

  cursor(): DurableCanonicalCursor {
    return this.#transaction('read', () => this.#issueCursor(this.#meta()));
  }

  status(): DurableLedgerStatus {
    return this.#transaction('read', () => {
      const meta = this.#meta();
      const cursor = this.#issueCursor(meta);
      const last = this.#lastEvent();
      if (meta.event_count === 0) {
        if (
          last !== undefined ||
          meta.chain_digest !== GENESIS_CHAIN_DIGEST ||
          meta.revision !== 0 ||
          meta.latest_receipt_digest !== GENESIS_RECEIPT_DIGEST
        ) {
          throw new Error('empty canonical ledger metadata is inconsistent');
        }
        return Object.freeze({ ok: true, reason: 'empty canonical ledger is initialized', cursor });
      }
      if (
        last === undefined ||
        last.seq !== meta.last_seq ||
        last.recorded_at !== meta.last_recorded_at ||
        last.chain_digest !== meta.chain_digest ||
        last.revision !== meta.revision
      ) {
        throw new Error('canonical tail row differs from metadata');
      }
      const latest = this.#latestReceipt();
      if (latest === undefined || latest.revision !== meta.revision) {
        throw new Error('latest durable receipt differs from canonical revision');
      }
      const receipt = receiptFromRow(latest);
      if (
        receipt.receiptDigest !== meta.latest_receipt_digest ||
        receipt.afterChainDigest !== meta.chain_digest ||
        receipt.appendToSeq !== meta.last_seq
      ) {
        throw new Error('latest durable receipt differs from canonical cursor');
      }
      this.#verifiedAudit(
        this.#auditForRevision(meta.revision) ?? (() => { throw new Error('latest durable audit is missing'); })(),
        receipt,
      );
      return Object.freeze({ ok: true, reason: 'canonical tail, receipt, audit, and cursor agree', cursor });
    });
  }

  commit(request: DurableCommitRequest): DurableCommitResult {
    const snapshot = this.#requestSnapshot(request);
    this.#validateRequest(snapshot);
    return this.#transaction('write', () => {
      this.#inject('after-begin');
      const duplicate = this.#idempotentReceipt(snapshot.idempotencyKey, snapshot.requestDigest);
      if (duplicate !== undefined) {
        return Object.freeze({
          cursor: this.#issueCursor(duplicate.meta),
          receipt: duplicate.receipt,
          idempotentReplay: true,
        });
      }

      this.#assertCursorCapability(request.base);
      const meta = this.#meta();
      if (
        snapshot.base.schemaVersion !== DURABLE_SCHEMA_VERSION ||
        snapshot.base.revision !== meta.revision ||
        snapshot.base.eventCount !== meta.event_count ||
        snapshot.base.lastSeq !== meta.last_seq ||
        snapshot.base.lastRecordedAt !== meta.last_recorded_at ||
        snapshot.base.chainDigest !== meta.chain_digest ||
        snapshot.base.latestReceiptDigest !== meta.latest_receipt_digest
      ) {
        throw new Error('durable commit base cursor is stale');
      }

      const existingEvents = this.#loadEventsVerified(meta);
      this.#inject('after-prefix-audit');
      const first = snapshot.events.at(0);
      const last = snapshot.events.at(-1);
      if (
        first === undefined ||
        last === undefined ||
        first.seq !== meta.last_seq + 1 ||
        last.seq !== meta.last_seq + snapshot.events.length
      ) {
        throw new Error('durable append sequence is not contiguous with the canonical cursor');
      }
      let expectedSeq = meta.last_seq + 1;
      let recordedAt = meta.last_recorded_at;
      const ids = new Set<string>();
      for (const event of snapshot.events) {
        if (
          event.seq !== expectedSeq ||
          event.schemaVersion !== EVENT_SCHEMA_VERSION ||
          typeof event.id !== 'string' ||
          event.id.trim().length === 0 ||
          ids.has(event.id) ||
          !Number.isFinite(event.recordedAt) ||
          event.recordedAt < recordedAt
        ) {
          throw new Error(`durable append event is malformed at sequence ${expectedSeq}`);
        }
        ids.add(event.id);
        expectedSeq += 1;
        recordedAt = event.recordedAt;
      }
      const combined = MemoryKernel.from([...existingEvents, ...snapshot.events]).events();
      if (combined.length !== meta.event_count + snapshot.events.length) {
        throw new Error('durable semantic replay produced an unexpected event count');
      }

      const revision = meta.revision + 1;
      let chain = meta.chain_digest;
      const insertEvent = this.#db.prepare(`
        INSERT INTO cl_canonical_events
          (seq, event_id, recorded_at, event_json, event_digest,
           previous_chain_digest, chain_digest, revision)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (const event of snapshot.events) {
        const serialized = stableJson(event);
        const digestValue = eventDigest(event);
        const next = nextChainDigest(chain, event, digestValue);
        insertEvent.run(
          event.seq,
          event.id,
          event.recordedAt,
          serialized,
          digestValue,
          chain,
          next,
          revision,
        );
        chain = next;
      }
      this.#inject('after-events');

      const transitionDigestValue = transitionDigest(snapshot.transition);
      const auditJson = stableJson(snapshot.audit);
      const auditDigestValue = auditDigest(snapshot.audit);
      const committedAt = Math.max(Date.now(), meta.updated_at + 1, snapshot.audit.recordedAt);
      const appendDigestValue = appendDigest(snapshot.events);
      const unsignedReceipt = Object.freeze({
        schemaVersion: DURABLE_SCHEMA_VERSION,
        revision,
        idempotencyKey: snapshot.idempotencyKey,
        requestDigest: snapshot.requestDigest,
        transition: snapshot.transition,
        auditId: snapshot.audit.id,
        auditDigest: auditDigestValue,
        baseChainDigest: meta.chain_digest,
        afterChainDigest: chain,
        appendFromSeq: first.seq,
        appendToSeq: last.seq,
        appendDigest: appendDigestValue,
        previousReceiptDigest: meta.latest_receipt_digest,
        committedBy: snapshot.committedBy,
        committedAt,
      });
      const receiptDigestValue = contentDigest(receiptPayload(unsignedReceipt));
      const receipt = Object.freeze({ ...unsignedReceipt, receiptDigest: receiptDigestValue });

      this.#db
        .prepare(`
          INSERT INTO cl_canonical_audits
            (revision, audit_id, audit_json, audit_digest, receipt_digest)
          VALUES (?, ?, ?, ?, ?)
        `)
        .run(revision, snapshot.audit.id, auditJson, auditDigestValue, receiptDigestValue);
      this.#inject('after-audit');

      this.#db
        .prepare(`
          INSERT INTO cl_canonical_receipts
            (revision, idempotency_key, request_digest, transition_json, transition_digest,
             audit_id, audit_digest, base_chain_digest, after_chain_digest,
             append_from_seq, append_to_seq, append_digest, previous_receipt_digest,
             receipt_digest, committed_by, committed_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .run(
          revision,
          snapshot.idempotencyKey,
          snapshot.requestDigest,
          stableJson(snapshot.transition),
          transitionDigestValue,
          snapshot.audit.id,
          auditDigestValue,
          meta.chain_digest,
          chain,
          first.seq,
          last.seq,
          appendDigestValue,
          meta.latest_receipt_digest,
          receiptDigestValue,
          snapshot.committedBy,
          committedAt,
        );
      this.#inject('after-receipt');

      this.#db
        .prepare(`
          UPDATE cl_canonical_meta
             SET revision = ?, event_count = ?, last_seq = ?, last_recorded_at = ?,
                 chain_digest = ?, latest_receipt_digest = ?, updated_at = ?
           WHERE id = 1
        `)
        .run(
          revision,
          combined.length,
          last.seq,
          last.recordedAt,
          chain,
          receiptDigestValue,
          committedAt,
        );
      this.#inject('after-cursor');
      this.#inject('before-commit');
      return Object.freeze({
        cursor: this.#issueCursor(this.#meta()),
        receipt,
        idempotentReplay: false,
      });
    });
  }

  readRange(fromSeq: number, limit = MAX_RANGE_EVENTS): readonly MemoryEvent[] {
    if (!Number.isInteger(fromSeq) || fromSeq <= 0) throw new RangeError('fromSeq must be positive');
    if (!Number.isInteger(limit) || limit <= 0 || limit > MAX_RANGE_EVENTS) {
      throw new RangeError(`range limit must be in [1, ${MAX_RANGE_EVENTS}]`);
    }
    return this.#transaction('read', () => {
      let previous = GENESIS_CHAIN_DIGEST;
      if (fromSeq > 1) {
        const anchor = this.#db
          .prepare('SELECT chain_digest FROM cl_canonical_events WHERE seq = ?')
          .get(fromSeq - 1) as { readonly chain_digest: string } | undefined;
        if (anchor === undefined) throw new Error('range predecessor is absent from the canonical ledger');
        assertDigest(anchor.chain_digest, 'range predecessor chain digest');
        previous = anchor.chain_digest;
      }
      const rows = this.#db
        .prepare(`
          SELECT * FROM cl_canonical_events
           WHERE seq >= ?
           ORDER BY seq
           LIMIT ?
        `)
        .all(fromSeq, limit) as unknown as readonly EventRow[];
      const result: MemoryEvent[] = [];
      let expectedSeq = fromSeq;
      for (const row of rows) {
        if (row.seq !== expectedSeq) throw new Error(`canonical range gap at sequence ${expectedSeq}`);
        const event = JSON.parse(row.event_json) as MemoryEvent;
        if (
          stableJson(event) !== row.event_json ||
          event.seq !== row.seq ||
          event.id !== row.event_id ||
          event.recordedAt !== row.recorded_at
        ) {
          throw new Error(`canonical range row metadata diverges at sequence ${row.seq}`);
        }
        const digestValue = eventDigest(event);
        if (digestValue !== row.event_digest || row.previous_chain_digest !== previous) {
          throw new Error(`canonical range digest or predecessor mismatch at sequence ${row.seq}`);
        }
        const chain = nextChainDigest(previous, event, digestValue);
        if (chain !== row.chain_digest) {
          throw new Error(`canonical range chain mismatch at sequence ${row.seq}`);
        }
        previous = chain;
        expectedSeq += 1;
        result.push(event);
      }
      return Object.freeze(result);
    });
  }

  loadKernel(): MemoryKernel {
    return this.#transaction('read', () => MemoryKernel.from(this.#loadEventsVerified(this.#meta())));
  }

  receipt(idempotencyKey: string): DurableCommitReceipt | undefined {
    if (typeof idempotencyKey !== 'string' || idempotencyKey.trim().length === 0) {
      throw new Error('idempotencyKey cannot be empty');
    }
    return this.#transaction('read', () => {
      const row = this.#db
        .prepare('SELECT * FROM cl_canonical_receipts WHERE idempotency_key = ?')
        .get(idempotencyKey) as ReceiptRow | undefined;
      if (row === undefined) return undefined;
      const receipt = receiptFromRow(row);
      this.#verifiedAudit(
        this.#auditForRevision(receipt.revision) ?? (() => { throw new Error('receipt audit is missing'); })(),
        receipt,
      );
      return receipt;
    });
  }

  audit(): DurableLedgerAudit {
    return this.#transaction('read', () => {
      const errors: string[] = [];
      const meta = this.#meta();
      const cursor = this.#issueCursor(meta);
      try {
        this.#loadEventsVerified(meta);
      } catch (error) {
        errors.push(error instanceof Error ? error.message : 'canonical event audit failed');
      }

      const receipts = this.#db
        .prepare('SELECT * FROM cl_canonical_receipts ORDER BY revision')
        .all() as unknown as readonly ReceiptRow[];
      const audits = this.#db
        .prepare('SELECT * FROM cl_canonical_audits ORDER BY revision')
        .all() as unknown as readonly AuditRow[];
      if (receipts.length !== meta.revision || audits.length !== meta.revision) {
        errors.push('receipt or audit count differs from canonical revision');
      }
      let previousReceipt = GENESIS_RECEIPT_DIGEST;
      let previousChain = GENESIS_CHAIN_DIGEST;
      let previousToSeq = 0;
      let previousCommittedAt = -1;
      for (let index = 0; index < receipts.length; index += 1) {
        const row = receipts[index];
        if (row === undefined || row.revision !== index + 1) {
          errors.push(`receipt revision gap at ${index + 1}`);
          continue;
        }
        try {
          const receipt = receiptFromRow(row);
          const audit = audits[index];
          if (audit === undefined) {
            errors.push(`audit is missing at revision ${receipt.revision}`);
          } else {
            this.#verifiedAudit(audit, receipt);
          }
          if (
            receipt.previousReceiptDigest !== previousReceipt ||
            receipt.baseChainDigest !== previousChain ||
            receipt.appendFromSeq !== previousToSeq + 1 ||
            receipt.committedAt <= previousCommittedAt
          ) {
            errors.push(`receipt chain or append range mismatch at revision ${receipt.revision}`);
          }
          const eventRows = this.#db
            .prepare('SELECT * FROM cl_canonical_events WHERE seq BETWEEN ? AND ? ORDER BY seq')
            .all(receipt.appendFromSeq, receipt.appendToSeq) as unknown as readonly EventRow[];
          const events = eventRows.map((event) => JSON.parse(event.event_json) as MemoryEvent);
          if (
            eventRows.length !== receipt.appendToSeq - receipt.appendFromSeq + 1 ||
            eventRows.some((event) => event.revision !== receipt.revision) ||
            appendDigest(events) !== receipt.appendDigest ||
            eventRows.at(-1)?.chain_digest !== receipt.afterChainDigest
          ) {
            errors.push(`receipt event range mismatch at revision ${receipt.revision}`);
          }
          previousReceipt = receipt.receiptDigest;
          previousChain = receipt.afterChainDigest;
          previousToSeq = receipt.appendToSeq;
          previousCommittedAt = receipt.committedAt;
        } catch (error) {
          errors.push(error instanceof Error ? error.message : `receipt audit failed at revision ${row.revision}`);
        }
      }
      if (
        previousReceipt !== meta.latest_receipt_digest ||
        previousChain !== meta.chain_digest ||
        previousToSeq !== meta.last_seq
      ) {
        errors.push('receipt chain head differs from canonical metadata');
      }
      return Object.freeze({
        ok: errors.length === 0,
        errors: Object.freeze(errors),
        cursor,
        receiptCount: receipts.length,
      });
    });
  }

  close(): void {
    if (this.#closed) return;
    this.#db.close();
    this.#closed = true;
  }
}
