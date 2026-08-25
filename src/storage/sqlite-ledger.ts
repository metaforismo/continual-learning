import { DatabaseSync } from 'node:sqlite';

import type { MemoryEvent } from '../domain.js';
import { MemoryKernel } from '../kernel.js';
import {
  TRANSITION_AUDIT_SCHEMA_VERSION,
  type TransitionAuditRecord,
  type TransitionVerificationResult,
} from '../transitions/types.js';
import { fingerprintMemoryEvents } from '../transitions/verifier.js';
import {
  canonicalJson,
  canonicalValuesEqual,
  digestCanonical,
  eventDigest,
  EVENT_CHAIN_GENESIS,
  nextEventChainDigest,
  nextReceiptChainDigest,
  RECEIPT_CHAIN_GENESIS,
  SHA256_CONTENT_ADDRESS,
} from './canonical.js';
import {
  DURABLE_LEDGER_SCHEMA_VERSION,
  type DurableCommitResult,
  type DurableIntegrityReport,
  type DurableLedgerRevision,
  type DurableReceiptEnvelope,
  type DurableTransitionReceipt,
  type SqliteCanonicalLedgerOptions,
  type VerifiedTransitionCommitter,
} from './types.js';

const META_ROW_ID = 1;
const MAX_BUSY_TIMEOUT_MS = 60_000;

interface MetaRow {
  readonly schema_version: number;
  readonly revision: number;
  readonly event_count: number;
  readonly last_seq: number;
  readonly last_recorded_at: number | null;
  readonly canonical_fingerprint: string;
  readonly event_chain_digest: string;
  readonly receipt_count: number;
  readonly last_receipt_digest: string;
}

interface EventRow {
  readonly seq: number;
  readonly id: string;
  readonly schema_version: number;
  readonly type: string;
  readonly recorded_at: number;
  readonly actor: string;
  readonly event_json: string;
  readonly event_digest: string;
  readonly previous_chain_digest: string;
  readonly chain_digest: string;
}

interface ReceiptRow {
  readonly seq: number;
  readonly id: string;
  readonly result_digest: string;
  readonly record_json: string;
  readonly record_digest: string;
  readonly previous_receipt_digest: string;
  readonly receipt_digest: string;
}

function integer(value: unknown, label: string, minimum = 0): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < minimum) {
    throw new Error(`${label} must be an integer >= ${minimum}`);
  }
  return value;
}

function nonEmptyString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function contentAddress(value: unknown, label: string): string {
  const address = nonEmptyString(value, label);
  if (!SHA256_CONTENT_ADDRESS.test(address)) {
    throw new Error(`${label} must be a SHA-256 content address`);
  }
  return address;
}

function statementChanges(result: { readonly changes: number | bigint }): number {
  const changes = typeof result.changes === 'bigint' ? Number(result.changes) : result.changes;
  if (!Number.isSafeInteger(changes)) throw new Error('SQLite returned an unsafe change count');
  return changes;
}

function uniqueSorted(values: readonly string[]): readonly string[] {
  return Object.freeze([...new Set(values)].sort());
}

function validateEnvelope(envelope: DurableReceiptEnvelope): void {
  nonEmptyString(envelope.id, 'receipt id');
  nonEmptyString(envelope.actor, 'receipt actor');
  if (!Number.isFinite(envelope.recordedAt)) {
    throw new Error('receipt recordedAt must be finite');
  }
}

function validateAcceptedResult(result: TransitionVerificationResult): void {
  if (result.verdict !== 'accept') {
    throw new Error(`only accepted transitions may be durably committed; received ${result.verdict}`);
  }
  if (result.stagedAppend === undefined || result.stagedAppend.length === 0) {
    throw new Error('accepted transition requires a non-empty staged append');
  }
  contentAddress(result.proposalDigest, 'proposalDigest');
  contentAddress(result.policyDigest, 'policyDigest');
  contentAddress(result.resultDigest, 'resultDigest');
  contentAddress(result.baseFingerprint, 'baseFingerprint');
  contentAddress(result.afterFingerprint, 'afterFingerprint');
  contentAddress(result.appendFingerprint, 'appendFingerprint');
  contentAddress(result.verifier.configDigest, 'verifier configDigest');
}

function auditRecordFor(
  result: TransitionVerificationResult,
  envelope: DurableReceiptEnvelope,
  seq: number,
): TransitionAuditRecord {
  return Object.freeze({
    schemaVersion: TRANSITION_AUDIT_SCHEMA_VERSION,
    id: envelope.id,
    seq,
    recordedAt: envelope.recordedAt,
    actor: envelope.actor,
    proposalId: result.proposalId,
    proposalDigest: result.proposalDigest,
    resultDigest: result.resultDigest,
    verdict: result.verdict,
    actualRisk: result.actualRisk,
    baseFingerprint: result.baseFingerprint,
    ...(result.afterFingerprint === undefined ? {} : { afterFingerprint: result.afterFingerprint }),
    ...(result.appendFingerprint === undefined
      ? {}
      : { appendFingerprint: result.appendFingerprint }),
    policyId: result.policyId,
    policyVersion: result.policyVersion,
    policyDigest: result.policyDigest,
    verifierId: result.verifier.id,
    verifierConfigDigest: result.verifier.configDigest,
    findingCodes: uniqueSorted(result.findings.map((finding) => finding.code)),
  });
}

/**
 * Durable SQLite source for the canonical event ledger and transition receipts.
 *
 * Every accepted transition is committed under `BEGIN IMMEDIATE`: canonical events, the receipt
 * hash chain, and the revision metadata either become visible together or not at all. The store
 * remains a trusted-host component; it cannot authenticate an arbitrary in-process caller.
 */
export class SqliteCanonicalLedger {
  readonly #db: DatabaseSync;
  readonly #faultInjector: SqliteCanonicalLedgerOptions['faultInjector'];
  #closed = false;

  constructor(location: string, options: SqliteCanonicalLedgerOptions = {}) {
    if (typeof location !== 'string' || location.trim().length === 0) {
      throw new TypeError('SQLite ledger location must be a non-empty string');
    }
    const busyTimeoutMs = options.busyTimeoutMs ?? 5_000;
    if (
      !Number.isInteger(busyTimeoutMs) ||
      busyTimeoutMs < 0 ||
      busyTimeoutMs > MAX_BUSY_TIMEOUT_MS
    ) {
      throw new RangeError(`busyTimeoutMs must be an integer in [0, ${MAX_BUSY_TIMEOUT_MS}]`);
    }

    this.#db = new DatabaseSync(location);
    this.#faultInjector = options.faultInjector;
    this.#db.exec('PRAGMA foreign_keys = ON');
    this.#db.exec(`PRAGMA busy_timeout = ${busyTimeoutMs}`);
    if (location !== ':memory:') {
      this.#db.exec('PRAGMA journal_mode = WAL');
      this.#db.exec('PRAGMA synchronous = FULL');
    }
    this.#initializeSchema();
    const report = this.verifyIntegrity();
    if (!report.ok) {
      throw new Error(`durable ledger integrity failed: ${report.errors.join('; ')}`);
    }
  }

  #assertOpen(): void {
    if (this.#closed) throw new Error('SQLite canonical ledger is closed');
  }

  #initializeSchema(): void {
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS cl_ledger_meta (
        singleton INTEGER PRIMARY KEY CHECK (singleton = ${META_ROW_ID}),
        schema_version INTEGER NOT NULL,
        revision INTEGER NOT NULL CHECK (revision >= 0),
        event_count INTEGER NOT NULL CHECK (event_count >= 0),
        last_seq INTEGER NOT NULL CHECK (last_seq >= 0),
        last_recorded_at INTEGER,
        canonical_fingerprint TEXT NOT NULL,
        event_chain_digest TEXT NOT NULL,
        receipt_count INTEGER NOT NULL CHECK (receipt_count >= 0),
        last_receipt_digest TEXT NOT NULL
      ) STRICT;

      CREATE TABLE IF NOT EXISTS cl_ledger_events (
        seq INTEGER PRIMARY KEY,
        id TEXT NOT NULL UNIQUE,
        schema_version INTEGER NOT NULL,
        type TEXT NOT NULL,
        recorded_at INTEGER NOT NULL,
        actor TEXT NOT NULL,
        event_json TEXT NOT NULL,
        event_digest TEXT NOT NULL,
        previous_chain_digest TEXT NOT NULL,
        chain_digest TEXT NOT NULL UNIQUE
      ) STRICT;

      CREATE TABLE IF NOT EXISTS cl_transition_receipts (
        seq INTEGER PRIMARY KEY,
        id TEXT NOT NULL UNIQUE,
        result_digest TEXT NOT NULL UNIQUE,
        record_json TEXT NOT NULL,
        record_digest TEXT NOT NULL,
        previous_receipt_digest TEXT NOT NULL,
        receipt_digest TEXT NOT NULL UNIQUE
      ) STRICT;
    `);

    const existing = this.#db
      .prepare('SELECT singleton FROM cl_ledger_meta WHERE singleton = ?')
      .get(META_ROW_ID);
    if (existing === undefined) {
      const emptyFingerprint = fingerprintMemoryEvents(Object.freeze([]));
      this.#db
        .prepare(`
          INSERT INTO cl_ledger_meta (
            singleton, schema_version, revision, event_count, last_seq, last_recorded_at,
            canonical_fingerprint, event_chain_digest, receipt_count, last_receipt_digest
          ) VALUES (?, ?, 0, 0, 0, NULL, ?, ?, 0, ?)
        `)
        .run(
          META_ROW_ID,
          DURABLE_LEDGER_SCHEMA_VERSION,
          emptyFingerprint,
          EVENT_CHAIN_GENESIS,
          RECEIPT_CHAIN_GENESIS,
        );
    }
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
        // Preserve the original integrity error.
      }
      throw error;
    }
  }

  #withImmediateTransaction<T>(operation: () => T): T {
    this.#assertOpen();
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      this.#faultInjector?.('after-begin');
      const result = operation();
      this.#faultInjector?.('before-commit');
      this.#db.exec('COMMIT');
      return result;
    } catch (error) {
      try {
        this.#db.exec('ROLLBACK');
      } catch {
        // Preserve the original transition failure.
      }
      throw error;
    }
  }

  #meta(): MetaRow {
    const value = this.#db
      .prepare(`
        SELECT schema_version, revision, event_count, last_seq, last_recorded_at,
               canonical_fingerprint, event_chain_digest, receipt_count, last_receipt_digest
          FROM cl_ledger_meta
         WHERE singleton = ?
      `)
      .get(META_ROW_ID) as Partial<MetaRow> | undefined;
    if (value === undefined) throw new Error('durable ledger metadata is missing');

    const row: MetaRow = {
      schema_version: integer(value.schema_version, 'metadata schema_version', 1),
      revision: integer(value.revision, 'metadata revision'),
      event_count: integer(value.event_count, 'metadata event_count'),
      last_seq: integer(value.last_seq, 'metadata last_seq'),
      last_recorded_at:
        value.last_recorded_at === null
          ? null
          : integer(value.last_recorded_at, 'metadata last_recorded_at'),
      canonical_fingerprint: contentAddress(
        value.canonical_fingerprint,
        'metadata canonical_fingerprint',
      ),
      event_chain_digest: contentAddress(
        value.event_chain_digest,
        'metadata event_chain_digest',
      ),
      receipt_count: integer(value.receipt_count, 'metadata receipt_count'),
      last_receipt_digest: contentAddress(
        value.last_receipt_digest,
        'metadata last_receipt_digest',
      ),
    };
    if (row.schema_version !== DURABLE_LEDGER_SCHEMA_VERSION) {
      throw new Error(`unsupported durable-ledger schema version: ${row.schema_version}`);
    }
    if (row.event_count !== row.last_seq) {
      throw new Error('durable ledger metadata event_count and last_seq diverge');
    }
    if (row.event_count === 0 && row.last_recorded_at !== null) {
      throw new Error('empty durable ledger cannot have last_recorded_at');
    }
    return row;
  }

  #revisionFromMeta(meta: MetaRow): DurableLedgerRevision {
    return Object.freeze({
      schemaVersion: DURABLE_LEDGER_SCHEMA_VERSION,
      revision: meta.revision,
      eventCount: meta.event_count,
      lastSeq: meta.last_seq,
      ...(meta.last_recorded_at === null ? {} : { lastRecordedAt: meta.last_recorded_at }),
      canonicalFingerprint: meta.canonical_fingerprint,
      eventChainDigest: meta.event_chain_digest,
      receiptCount: meta.receipt_count,
      lastReceiptDigest: meta.last_receipt_digest,
    });
  }

  #eventsForMeta(meta: MetaRow): readonly MemoryEvent[] {
    const rows = this.#db
      .prepare(`
        SELECT seq, id, schema_version, type, recorded_at, actor, event_json, event_digest,
               previous_chain_digest, chain_digest
          FROM cl_ledger_events
         ORDER BY seq ASC
      `)
      .all() as unknown as readonly EventRow[];
    if (rows.length !== meta.event_count) {
      throw new Error('durable ledger event row count does not match metadata');
    }

    const events: MemoryEvent[] = [];
    let previousChain = EVENT_CHAIN_GENESIS;
    let previousRecordedAt: number | undefined;
    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index];
      if (row === undefined) throw new Error('durable ledger row iteration failed');
      const expectedSeq = index + 1;
      if (integer(row.seq, 'event row seq', 1) !== expectedSeq) {
        throw new Error(`durable ledger event sequence is not contiguous at ${expectedSeq}`);
      }
      const event = JSON.parse(nonEmptyString(row.event_json, 'event row JSON')) as MemoryEvent;
      if (canonicalJson(event) !== row.event_json) {
        throw new Error(`event ${expectedSeq} is not stored in canonical JSON form`);
      }
      if (
        event.seq !== row.seq ||
        event.id !== row.id ||
        event.schemaVersion !== row.schema_version ||
        event.type !== row.type ||
        event.recordedAt !== row.recorded_at ||
        event.actor !== row.actor
      ) {
        throw new Error(`event ${expectedSeq} columns do not match its canonical payload`);
      }
      if (previousRecordedAt !== undefined && event.recordedAt < previousRecordedAt) {
        throw new Error(`event ${expectedSeq} violates monotonic transaction time`);
      }
      const calculatedEventDigest = eventDigest(event);
      if (contentAddress(row.event_digest, 'event row digest') !== calculatedEventDigest) {
        throw new Error(`event ${expectedSeq} digest mismatch`);
      }
      if (row.previous_chain_digest !== previousChain) {
        throw new Error(`event ${expectedSeq} previous chain digest mismatch`);
      }
      const calculatedChain = nextEventChainDigest(previousChain, event);
      if (row.chain_digest !== calculatedChain) {
        throw new Error(`event ${expectedSeq} chain digest mismatch`);
      }
      previousChain = calculatedChain;
      previousRecordedAt = event.recordedAt;
      events.push(event);
    }

    const normalized = MemoryKernel.from(events).events();
    const fingerprint = fingerprintMemoryEvents(normalized);
    if (fingerprint !== meta.canonical_fingerprint) {
      throw new Error('durable ledger canonical fingerprint does not match event rows');
    }
    if (previousChain !== meta.event_chain_digest) {
      throw new Error('durable ledger event-chain head does not match metadata');
    }
    if ((normalized.at(-1)?.recordedAt ?? undefined) !== (meta.last_recorded_at ?? undefined)) {
      throw new Error('durable ledger last_recorded_at does not match event rows');
    }
    return normalized;
  }

  #receiptFromRow(row: ReceiptRow, expectedSeq: number, previousDigest: string): DurableTransitionReceipt {
    if (integer(row.seq, 'receipt row seq', 1) !== expectedSeq) {
      throw new Error(`transition receipt sequence is not contiguous at ${expectedSeq}`);
    }
    const audit = JSON.parse(nonEmptyString(row.record_json, 'receipt record JSON')) as TransitionAuditRecord;
    if (canonicalJson(audit) !== row.record_json) {
      throw new Error(`transition receipt ${expectedSeq} is not canonical JSON`);
    }
    if (audit.seq !== row.seq || audit.id !== row.id || audit.resultDigest !== row.result_digest) {
      throw new Error(`transition receipt ${expectedSeq} columns do not match its audit payload`);
    }
    if (audit.schemaVersion !== TRANSITION_AUDIT_SCHEMA_VERSION) {
      throw new Error(`transition receipt ${expectedSeq} has an unsupported audit schema`);
    }
    const recordDigest = digestCanonical(audit);
    if (row.record_digest !== recordDigest) {
      throw new Error(`transition receipt ${expectedSeq} record digest mismatch`);
    }
    if (row.previous_receipt_digest !== previousDigest) {
      throw new Error(`transition receipt ${expectedSeq} previous digest mismatch`);
    }
    const receiptDigest = nextReceiptChainDigest(previousDigest, recordDigest);
    if (row.receipt_digest !== receiptDigest) {
      throw new Error(`transition receipt ${expectedSeq} chain digest mismatch`);
    }
    return Object.freeze({
      audit: Object.freeze(audit),
      previousReceiptDigest: previousDigest,
      auditRecordDigest: recordDigest,
      receiptDigest,
    });
  }

  #receiptsForMeta(meta: MetaRow): readonly DurableTransitionReceipt[] {
    const rows = this.#db
      .prepare(`
        SELECT seq, id, result_digest, record_json, record_digest,
               previous_receipt_digest, receipt_digest
          FROM cl_transition_receipts
         ORDER BY seq ASC
      `)
      .all() as unknown as readonly ReceiptRow[];
    if (rows.length !== meta.receipt_count) {
      throw new Error('transition receipt row count does not match metadata');
    }
    const receipts: DurableTransitionReceipt[] = [];
    let previousDigest = RECEIPT_CHAIN_GENESIS;
    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index];
      if (row === undefined) throw new Error('transition receipt row iteration failed');
      const receipt = this.#receiptFromRow(row, index + 1, previousDigest);
      receipts.push(receipt);
      previousDigest = receipt.receiptDigest;
    }
    if (previousDigest !== meta.last_receipt_digest) {
      throw new Error('transition receipt-chain head does not match metadata');
    }
    return Object.freeze(receipts);
  }

  #receiptByResultDigest(
    resultDigest: string,
    meta: MetaRow,
  ): DurableTransitionReceipt | undefined {
    const rows = this.#db
      .prepare(`
        SELECT seq, id, result_digest, record_json, record_digest,
               previous_receipt_digest, receipt_digest
          FROM cl_transition_receipts
         WHERE result_digest = ?
      `)
      .all(resultDigest) as unknown as readonly ReceiptRow[];
    if (rows.length === 0) return undefined;
    if (rows.length !== 1) throw new Error('duplicate durable result digest detected');
    const all = this.#receiptsForMeta(meta);
    return all.find((receipt) => receipt.audit.resultDigest === resultDigest);
  }

  revision(): DurableLedgerRevision {
    return this.#withReadTransaction(() => {
      const meta = this.#meta();
      this.#eventsForMeta(meta);
      this.#receiptsForMeta(meta);
      return this.#revisionFromMeta(meta);
    });
  }

  events(): readonly MemoryEvent[] {
    return this.#withReadTransaction(() => this.#eventsForMeta(this.#meta()));
  }

  receipts(): readonly DurableTransitionReceipt[] {
    return this.#withReadTransaction(() => this.#receiptsForMeta(this.#meta()));
  }

  loadKernel(): MemoryKernel {
    return MemoryKernel.from(this.events());
  }

  verifyIntegrity(): DurableIntegrityReport {
    try {
      const revision = this.#withReadTransaction(() => {
        const meta = this.#meta();
        this.#eventsForMeta(meta);
        this.#receiptsForMeta(meta);
        return this.#revisionFromMeta(meta);
      });
      return Object.freeze({ ok: true, revision, errors: Object.freeze([]) });
    } catch (error) {
      return Object.freeze({
        ok: false,
        errors: Object.freeze([
          error instanceof Error ? error.message : 'unknown durable-ledger integrity failure',
        ]),
      });
    }
  }

  commitVerifiedTransition(
    result: TransitionVerificationResult,
    committer: VerifiedTransitionCommitter,
    envelope: DurableReceiptEnvelope,
  ): DurableCommitResult {
    this.#assertOpen();
    if (typeof committer !== 'function') {
      throw new TypeError('verified transition committer must be a function');
    }
    validateEnvelope(envelope);
    validateAcceptedResult(result);

    return this.#withImmediateTransaction(() => {
      const meta = this.#meta();
      const duplicate = this.#receiptByResultDigest(result.resultDigest, meta);
      if (duplicate !== undefined) {
        if (meta.canonical_fingerprint !== result.afterFingerprint) {
          throw new Error('result digest already exists but canonical memory no longer matches it');
        }
        return Object.freeze({
          idempotent: true,
          revision: this.#revisionFromMeta(meta),
          receipt: duplicate,
          appendedEvents: Object.freeze([]),
        });
      }

      const currentEvents = this.#eventsForMeta(meta);
      if (meta.canonical_fingerprint !== result.baseFingerprint) {
        throw new Error('durable transition base is stale');
      }

      const currentKernel = MemoryKernel.from(currentEvents);
      const committedKernel = committer(currentKernel, result);
      if (!(committedKernel instanceof MemoryKernel)) {
        throw new Error('verified transition committer did not return a MemoryKernel');
      }
      const nextEvents = MemoryKernel.from(committedKernel.events()).events();
      if (nextEvents.length <= currentEvents.length) {
        throw new Error('verified transition did not append any canonical events');
      }
      for (let index = 0; index < currentEvents.length; index += 1) {
        if (!canonicalValuesEqual(currentEvents[index], nextEvents[index])) {
          throw new Error(`verified transition rewrote canonical prefix event ${index + 1}`);
        }
      }

      const append = Object.freeze(nextEvents.slice(currentEvents.length));
      if (!canonicalValuesEqual(append, result.stagedAppend)) {
        throw new Error('verified transition committer output differs from the staged append');
      }
      if (digestCanonical(append) !== result.appendFingerprint) {
        throw new Error('verified transition append fingerprint mismatch');
      }
      const afterFingerprint = fingerprintMemoryEvents(nextEvents);
      if (afterFingerprint !== result.afterFingerprint) {
        throw new Error('verified transition after fingerprint mismatch');
      }

      let chainDigest = meta.event_chain_digest;
      let lastRecordedAt = meta.last_recorded_at ?? undefined;
      const insertEvent = this.#db.prepare(`
        INSERT INTO cl_ledger_events (
          seq, id, schema_version, type, recorded_at, actor, event_json, event_digest,
          previous_chain_digest, chain_digest
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (const event of append) {
        if (event.seq !== meta.last_seq + (event.seq - meta.last_seq)) {
          // The semantic replay below is authoritative; this branch keeps the error local and clear.
        }
        if (event.seq !== meta.last_seq + append.indexOf(event) + 1) {
          throw new Error(`staged append sequence is not contiguous at event ${event.id}`);
        }
        if (lastRecordedAt !== undefined && event.recordedAt < lastRecordedAt) {
          throw new Error(`staged append recordedAt regresses at event ${event.id}`);
        }
        const serialized = canonicalJson(event);
        const digest = eventDigest(event);
        const nextChain = nextEventChainDigest(chainDigest, event);
        insertEvent.run(
          event.seq,
          event.id,
          event.schemaVersion,
          event.type,
          event.recordedAt,
          event.actor,
          serialized,
          digest,
          chainDigest,
          nextChain,
        );
        chainDigest = nextChain;
        lastRecordedAt = event.recordedAt;
      }
      this.#faultInjector?.('after-event-inserts');

      const audit = auditRecordFor(result, envelope, meta.receipt_count + 1);
      const auditJson = canonicalJson(audit);
      const auditRecordDigest = digestCanonical(audit);
      const receiptDigest = nextReceiptChainDigest(meta.last_receipt_digest, auditRecordDigest);
      this.#db
        .prepare(`
          INSERT INTO cl_transition_receipts (
            seq, id, result_digest, record_json, record_digest,
            previous_receipt_digest, receipt_digest
          ) VALUES (?, ?, ?, ?, ?, ?, ?)
        `)
        .run(
          audit.seq,
          audit.id,
          audit.resultDigest,
          auditJson,
          auditRecordDigest,
          meta.last_receipt_digest,
          receiptDigest,
        );
      this.#faultInjector?.('after-receipt-insert');

      const updatedMeta: MetaRow = {
        schema_version: DURABLE_LEDGER_SCHEMA_VERSION,
        revision: meta.revision + 1,
        event_count: nextEvents.length,
        last_seq: nextEvents.at(-1)?.seq ?? 0,
        last_recorded_at: nextEvents.at(-1)?.recordedAt ?? null,
        canonical_fingerprint: afterFingerprint,
        event_chain_digest: chainDigest,
        receipt_count: meta.receipt_count + 1,
        last_receipt_digest: receiptDigest,
      };
      const update = this.#db
        .prepare(`
          UPDATE cl_ledger_meta
             SET schema_version = ?, revision = ?, event_count = ?, last_seq = ?,
                 last_recorded_at = ?, canonical_fingerprint = ?, event_chain_digest = ?,
                 receipt_count = ?, last_receipt_digest = ?
           WHERE singleton = ? AND revision = ? AND canonical_fingerprint = ?
        `)
        .run(
          updatedMeta.schema_version,
          updatedMeta.revision,
          updatedMeta.event_count,
          updatedMeta.last_seq,
          updatedMeta.last_recorded_at,
          updatedMeta.canonical_fingerprint,
          updatedMeta.event_chain_digest,
          updatedMeta.receipt_count,
          updatedMeta.last_receipt_digest,
          META_ROW_ID,
          meta.revision,
          meta.canonical_fingerprint,
        );
      if (statementChanges(update) !== 1) {
        throw new Error('durable ledger compare-and-swap failed');
      }
      this.#faultInjector?.('after-metadata-update');

      const receipt: DurableTransitionReceipt = Object.freeze({
        audit,
        previousReceiptDigest: meta.last_receipt_digest,
        auditRecordDigest,
        receiptDigest,
      });
      return Object.freeze({
        idempotent: false,
        revision: this.#revisionFromMeta(updatedMeta),
        receipt,
        appendedEvents: append,
      });
    });
  }

  close(): void {
    if (this.#closed) return;
    this.#db.close();
    this.#closed = true;
  }
}
