import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

import {
  EVENT_SCHEMA_VERSION,
  type MemoryEvent,
} from '../domain.js';
import { MemoryKernel } from '../kernel.js';
import {
  TRANSITION_AUDIT_SCHEMA_VERSION,
  type TransitionAuditRecord,
  type TransitionRisk,
  type TransitionVerificationResult,
} from '../transitions/types.js';
import {
  fingerprintMemoryEvents,
  TransitionVerifier,
  verifyTransitionResultIntegrity,
} from '../transitions/verifier.js';

const DURABLE_SCHEMA_VERSION = 1 as const;
const META_ROW_ID = 1;
const DEFAULT_MAX_APPEND_EVENTS = 256;
const MAX_DURABLE_APPEND_EVENTS = 4_096;
const MAX_REQUEST_CHARACTERS = 2_000_000;
const MAX_RANGE_EVENTS = 1_000;
const MAX_BUSY_TIMEOUT_MS = 60_000;
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;

const TABLE_META = 'cl_canonical_meta';
const TABLE_EVENTS = 'cl_canonical_events';
const TABLE_RECEIPTS = 'cl_canonical_receipts';
const TABLE_AUDITS = 'cl_canonical_audits';
const EXPECTED_TABLES = Object.freeze([
  TABLE_META,
  TABLE_EVENTS,
  TABLE_RECEIPTS,
  TABLE_AUDITS,
]);

const GENESIS_CHAIN_DIGEST = contentDigest({ domain: 'cl-canonical-event-chain-genesis-v1' });
const GENESIS_RECEIPT_DIGEST = contentDigest({ domain: 'cl-canonical-receipt-chain-genesis-v1' });
const GENESIS_CANONICAL_FINGERPRINT = fingerprintMemoryEvents(Object.freeze([]));

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
  /**
   * Trusted process-local verifier capability. New commits require results issued by this exact
   * verifier instance. Exact idempotent retries may be recovered after restart without it.
   */
  readonly transitionVerifier?: TransitionVerifier;
  readonly faultInjector?: (point: DurableCommitFaultPoint) => void;
}

export interface DurableCanonicalCursor {
  readonly schemaVersion: typeof DURABLE_SCHEMA_VERSION;
  readonly revision: number;
  readonly eventCount: number;
  readonly lastSeq: number;
  readonly lastRecordedAt: number;
  readonly canonicalFingerprint: string;
  readonly chainDigest: string;
  readonly latestReceiptDigest: string;
}

export interface DurableCommitEnvelope {
  readonly idempotencyKey: string;
  readonly auditId: string;
  readonly recordedAt: number;
  readonly actor: string;
  readonly committedBy: string;
}

export interface DurableCommitRequest {
  /** Process-local capability returned by `cursor()` or a prior successful commit. */
  readonly base: DurableCanonicalCursor;
  /** Process-local accepted result issued by the configured `TransitionVerifier`. */
  readonly result: TransitionVerificationResult;
  readonly envelope: DurableCommitEnvelope;
}

export interface DurableTransitionMetadata {
  readonly proposalId: string;
  readonly proposalDigest: string;
  readonly resultDigest: string;
  readonly verdict: 'accept';
  readonly actualRisk: TransitionRisk;
  readonly baseFingerprint: string;
  readonly afterFingerprint: string;
  readonly appendFingerprint: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly policyDigest: string;
  readonly verifierId: string;
  readonly verifierConfigDigest: string;
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
  readonly appendedEvents: readonly MemoryEvent[];
}

export interface DurableLedgerStatus {
  readonly ok: true;
  readonly reason: string;
  readonly cursor: DurableCanonicalCursor;
}

export interface DurableLedgerAudit {
  readonly ok: boolean;
  readonly errors: readonly string[];
  readonly cursor: DurableCanonicalCursor;
  readonly receiptCount: number;
}

interface NormalizedDurableCommitRequest {
  readonly base: DurableCanonicalCursor;
  readonly result: TransitionVerificationResult;
  readonly envelope: DurableCommitEnvelope;
  readonly requestDigest: string;
}

interface CommitCapabilities {
  readonly base: DurableCanonicalCursor;
  readonly result: TransitionVerificationResult;
}

interface MetaRow {
  readonly schema_version: unknown;
  readonly revision: unknown;
  readonly event_count: unknown;
  readonly last_seq: unknown;
  readonly last_recorded_at: unknown;
  readonly canonical_fingerprint: unknown;
  readonly canonical_fingerprint_hex: unknown;
  readonly chain_digest: unknown;
  readonly chain_digest_hex: unknown;
  readonly latest_receipt_digest: unknown;
  readonly latest_receipt_digest_hex: unknown;
  readonly updated_at: unknown;
}

interface EventRow {
  readonly seq: unknown;
  readonly event_id: unknown;
  readonly event_id_hex: unknown;
  readonly schema_version: unknown;
  readonly type: unknown;
  readonly type_hex: unknown;
  readonly recorded_at: unknown;
  readonly actor: unknown;
  readonly actor_hex: unknown;
  readonly event_json: unknown;
  readonly event_json_hex: unknown;
  readonly event_digest: unknown;
  readonly event_digest_hex: unknown;
  readonly previous_chain_digest: unknown;
  readonly previous_chain_digest_hex: unknown;
  readonly chain_digest: unknown;
  readonly chain_digest_hex: unknown;
  readonly revision: unknown;
}

interface ReceiptRow {
  readonly revision: unknown;
  readonly idempotency_key: unknown;
  readonly idempotency_key_hex: unknown;
  readonly request_digest: unknown;
  readonly request_digest_hex: unknown;
  readonly result_digest: unknown;
  readonly result_digest_hex: unknown;
  readonly transition_json: unknown;
  readonly transition_json_hex: unknown;
  readonly transition_digest: unknown;
  readonly transition_digest_hex: unknown;
  readonly audit_id: unknown;
  readonly audit_id_hex: unknown;
  readonly audit_digest: unknown;
  readonly audit_digest_hex: unknown;
  readonly base_chain_digest: unknown;
  readonly base_chain_digest_hex: unknown;
  readonly after_chain_digest: unknown;
  readonly after_chain_digest_hex: unknown;
  readonly append_from_seq: unknown;
  readonly append_to_seq: unknown;
  readonly append_digest: unknown;
  readonly append_digest_hex: unknown;
  readonly previous_receipt_digest: unknown;
  readonly previous_receipt_digest_hex: unknown;
  readonly receipt_digest: unknown;
  readonly receipt_digest_hex: unknown;
  readonly committed_by: unknown;
  readonly committed_by_hex: unknown;
  readonly committed_at: unknown;
}

interface AuditRow {
  readonly revision: unknown;
  readonly audit_id: unknown;
  readonly audit_id_hex: unknown;
  readonly audit_json: unknown;
  readonly audit_json_hex: unknown;
  readonly audit_digest: unknown;
  readonly audit_digest_hex: unknown;
  readonly receipt_digest: unknown;
  readonly receipt_digest_hex: unknown;
}

interface TableColumnRow {
  readonly cid: unknown;
  readonly name: unknown;
  readonly type: unknown;
  readonly notnull: unknown;
  readonly dflt_value: unknown;
  readonly pk: unknown;
  readonly hidden: unknown;
}

interface TableListRow {
  readonly name: unknown;
  readonly type: unknown;
  readonly strict: unknown;
}

interface IndexListRow {
  readonly name: unknown;
  readonly unique: unknown;
  readonly origin: unknown;
  readonly partial: unknown;
}

interface IndexInfoRow {
  readonly seqno: unknown;
  readonly name: unknown;
}

interface ExpectedColumn {
  readonly name: string;
  readonly type: 'INTEGER' | 'TEXT';
  readonly notNull: boolean;
  readonly primaryKey: boolean;
}

const EXPECTED_COLUMNS: Readonly<Record<string, readonly ExpectedColumn[]>> = Object.freeze({
  [TABLE_META]: Object.freeze([
    { name: 'id', type: 'INTEGER', notNull: false, primaryKey: true },
    { name: 'schema_version', type: 'INTEGER', notNull: true, primaryKey: false },
    { name: 'revision', type: 'INTEGER', notNull: true, primaryKey: false },
    { name: 'event_count', type: 'INTEGER', notNull: true, primaryKey: false },
    { name: 'last_seq', type: 'INTEGER', notNull: true, primaryKey: false },
    { name: 'last_recorded_at', type: 'INTEGER', notNull: true, primaryKey: false },
    { name: 'canonical_fingerprint', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'chain_digest', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'latest_receipt_digest', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'updated_at', type: 'INTEGER', notNull: true, primaryKey: false },
  ]),
  [TABLE_EVENTS]: Object.freeze([
    { name: 'seq', type: 'INTEGER', notNull: false, primaryKey: true },
    { name: 'event_id', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'schema_version', type: 'INTEGER', notNull: true, primaryKey: false },
    { name: 'type', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'recorded_at', type: 'INTEGER', notNull: true, primaryKey: false },
    { name: 'actor', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'event_json', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'event_digest', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'previous_chain_digest', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'chain_digest', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'revision', type: 'INTEGER', notNull: true, primaryKey: false },
  ]),
  [TABLE_RECEIPTS]: Object.freeze([
    { name: 'revision', type: 'INTEGER', notNull: false, primaryKey: true },
    { name: 'idempotency_key', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'request_digest', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'result_digest', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'transition_json', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'transition_digest', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'audit_id', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'audit_digest', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'base_chain_digest', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'after_chain_digest', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'append_from_seq', type: 'INTEGER', notNull: true, primaryKey: false },
    { name: 'append_to_seq', type: 'INTEGER', notNull: true, primaryKey: false },
    { name: 'append_digest', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'previous_receipt_digest', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'receipt_digest', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'committed_by', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'committed_at', type: 'INTEGER', notNull: true, primaryKey: false },
  ]),
  [TABLE_AUDITS]: Object.freeze([
    { name: 'revision', type: 'INTEGER', notNull: false, primaryKey: true },
    { name: 'audit_id', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'audit_json', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'audit_digest', type: 'TEXT', notNull: true, primaryKey: false },
    { name: 'receipt_digest', type: 'TEXT', notNull: true, primaryKey: false },
  ]),
}) as Readonly<Record<string, readonly ExpectedColumn[]>>;

const EXPECTED_UNIQUE_COLUMNS: Readonly<Record<string, readonly (readonly string[])[]>> =
  Object.freeze({
    [TABLE_META]: Object.freeze([]),
    [TABLE_EVENTS]: Object.freeze([
      Object.freeze(['event_id']),
      Object.freeze(['chain_digest']),
    ]),
    [TABLE_RECEIPTS]: Object.freeze([
      Object.freeze(['idempotency_key']),
      Object.freeze(['result_digest']),
      Object.freeze(['audit_id']),
      Object.freeze(['receipt_digest']),
    ]),
    [TABLE_AUDITS]: Object.freeze([
      Object.freeze(['audit_id']),
      Object.freeze(['audit_digest']),
      Object.freeze(['receipt_digest']),
    ]),
  }) as Readonly<Record<string, readonly (readonly string[])[]>>;

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

function snapshotJson<T>(value: T): T {
  return JSON.parse(stableJson(value)) as T;
}

function sha256Text(value: string): string {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function canonicalDigest(value: unknown): string {
  return sha256Text(stableJson(value));
}

function contentDigest(value: unknown): string {
  return canonicalDigest(value);
}

function assertDigest(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || !SHA256_PATTERN.test(value)) {
    throw new Error(`${label} must be a SHA-256 content address`);
  }
}

function safeInteger(value: unknown, label: string, minimum = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum) {
    throw new Error(`${label} must be a safe integer >= ${minimum}`);
  }
  return value;
}

function statementChanges(result: unknown): number {
  const value = result as { readonly changes?: number | bigint };
  const rawChanges = value.changes;
  if (rawChanges === undefined) {
    throw new Error('SQLite did not return a change count');
  }
  const changes = typeof rawChanges === 'bigint' ? Number(rawChanges) : rawChanges;
  if (!Number.isSafeInteger(changes) || changes < 0) {
    throw new Error('SQLite returned an unsafe change count');
  }
  return changes;
}

function uniqueSorted(values: readonly string[]): readonly string[] {
  return Object.freeze([...new Set(values)].sort());
}

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      if (index + 1 >= value.length) return false;
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return false;
      index += 1;
      continue;
    }
    if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

function assertSqliteText(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  if (value.includes('\u0000')) throw new Error(`${label} cannot contain U+0000`);
  if (!isWellFormedUnicode(value)) throw new Error(`${label} must be well-formed Unicode`);
}

function assertCanonicalSqliteText(value: string, label: string): void {
  if (value.includes('\u0000')) throw new Error(`${label} cannot contain U+0000`);
  if (!isWellFormedUnicode(value)) throw new Error(`${label} must be well-formed Unicode`);
}

function utf8Hex(value: string): string {
  return [...new TextEncoder().encode(value)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

function hasExactSqliteText(value: unknown, hex: unknown): value is string {
  return typeof value === 'string' && typeof hex === 'string' && utf8Hex(value) === hex;
}

function assertExactSqliteText(value: unknown, hex: unknown, label: string): asserts value is string {
  if (!hasExactSqliteText(value, hex)) {
    throw new Error(`${label} has a non-canonical SQLite text encoding`);
  }
}

function exactSqliteText(value: unknown, hex: unknown, label: string): string {
  assertExactSqliteText(value, hex, label);
  return value;
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

function transitionFromResult(result: TransitionVerificationResult): DurableTransitionMetadata {
  if (
    result.verdict !== 'accept' ||
    result.afterFingerprint === undefined ||
    result.appendFingerprint === undefined
  ) {
    throw new Error('only accepted transition results with exact append fingerprints may persist');
  }
  return Object.freeze({
    proposalId: result.proposalId,
    proposalDigest: result.proposalDigest,
    resultDigest: result.resultDigest,
    verdict: 'accept',
    actualRisk: result.actualRisk,
    baseFingerprint: result.baseFingerprint,
    afterFingerprint: result.afterFingerprint,
    appendFingerprint: result.appendFingerprint,
    policyId: result.policyId,
    policyVersion: result.policyVersion,
    policyDigest: result.policyDigest,
    verifierId: result.verifier.id,
    verifierConfigDigest: result.verifier.configDigest,
  });
}

function validateTransition(transition: DurableTransitionMetadata): void {
  for (const [label, value] of [
    ['proposal id', transition.proposalId],
    ['policy id', transition.policyId],
    ['policy version', transition.policyVersion],
    ['verifier id', transition.verifierId],
  ] as const) {
    assertSqliteText(value, label);
  }
  for (const [label, value] of [
    ['proposal digest', transition.proposalDigest],
    ['result digest', transition.resultDigest],
    ['base fingerprint', transition.baseFingerprint],
    ['after fingerprint', transition.afterFingerprint],
    ['append fingerprint', transition.appendFingerprint],
    ['policy digest', transition.policyDigest],
    ['verifier config digest', transition.verifierConfigDigest],
  ] as const) {
    assertDigest(value, label);
  }
  if (transition.verdict !== 'accept') throw new Error('only accepted transitions may persist');
  if (!['low', 'medium', 'high', 'destructive'].includes(transition.actualRisk)) {
    throw new Error('transition risk is invalid');
  }
}

function transitionDigest(transition: DurableTransitionMetadata): string {
  return contentDigest({ domain: 'cl-durable-transition-metadata-v1', transition });
}

function auditRecordFor(
  result: TransitionVerificationResult,
  envelope: DurableCommitEnvelope,
  revision: number,
): TransitionAuditRecord {
  if (
    result.afterFingerprint === undefined ||
    result.appendFingerprint === undefined ||
    result.verdict !== 'accept'
  ) {
    throw new Error('accepted result is missing durable audit fingerprints');
  }
  return Object.freeze({
    schemaVersion: TRANSITION_AUDIT_SCHEMA_VERSION,
    id: envelope.auditId,
    seq: revision,
    recordedAt: envelope.recordedAt,
    actor: envelope.actor,
    proposalId: result.proposalId,
    proposalDigest: result.proposalDigest,
    resultDigest: result.resultDigest,
    verdict: result.verdict,
    actualRisk: result.actualRisk,
    baseFingerprint: result.baseFingerprint,
    afterFingerprint: result.afterFingerprint,
    appendFingerprint: result.appendFingerprint,
    policyId: result.policyId,
    policyVersion: result.policyVersion,
    policyDigest: result.policyDigest,
    verifierId: result.verifier.id,
    verifierConfigDigest: result.verifier.configDigest,
    findingCodes: uniqueSorted(result.findings.map((finding) => finding.code)),
  });
}

function validateAudit(audit: TransitionAuditRecord, transition: DurableTransitionMetadata): void {
  if (
    audit.schemaVersion !== TRANSITION_AUDIT_SCHEMA_VERSION ||
    !Number.isSafeInteger(audit.seq) ||
    audit.seq <= 0 ||
    !Number.isSafeInteger(audit.recordedAt) ||
    audit.recordedAt < 0
  ) {
    throw new Error('durable transition audit shape is invalid');
  }
  assertSqliteText(audit.id, 'audit id');
  assertSqliteText(audit.actor, 'audit actor');
  if (
    audit.proposalId !== transition.proposalId ||
    audit.proposalDigest !== transition.proposalDigest ||
    audit.resultDigest !== transition.resultDigest ||
    audit.verdict !== transition.verdict ||
    audit.actualRisk !== transition.actualRisk ||
    audit.baseFingerprint !== transition.baseFingerprint ||
    audit.afterFingerprint !== transition.afterFingerprint ||
    audit.appendFingerprint !== transition.appendFingerprint ||
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
    new Set(audit.findingCodes).size !== audit.findingCodes.length ||
    [...audit.findingCodes].sort().some((code, index) => code !== audit.findingCodes[index])
  ) {
    throw new Error('durable audit finding codes must be sorted unique non-empty strings');
  }
}

function auditDigest(audit: TransitionAuditRecord): string {
  return contentDigest({ domain: 'cl-durable-transition-audit-v1', audit });
}

function receiptPayload(receipt: Omit<DurableCommitReceipt, 'receiptDigest'>): unknown {
  return { domain: 'cl-durable-receipt-v1', ...receipt };
}

function cursorFromMeta(meta: MetaRow): DurableCanonicalCursor {
  const schemaVersion = safeInteger(meta.schema_version, 'metadata schema_version', 1);
  const revision = safeInteger(meta.revision, 'metadata revision');
  const eventCount = safeInteger(meta.event_count, 'metadata event_count');
  const lastSeq = safeInteger(meta.last_seq, 'metadata last_seq');
  const lastRecordedAt = safeInteger(meta.last_recorded_at, 'metadata last_recorded_at');
  const updatedAt = safeInteger(meta.updated_at, 'metadata updated_at');
  if (schemaVersion !== DURABLE_SCHEMA_VERSION || lastSeq !== eventCount || revision > eventCount) {
    throw new Error('durable canonical metadata is malformed');
  }
  if (revision === 0 && (eventCount !== 0 || updatedAt !== 0)) {
    throw new Error('empty durable canonical metadata is malformed');
  }
  assertExactSqliteText(
    meta.canonical_fingerprint,
    meta.canonical_fingerprint_hex,
    'canonical fingerprint',
  );
  assertExactSqliteText(meta.chain_digest, meta.chain_digest_hex, 'canonical chain digest');
  assertExactSqliteText(
    meta.latest_receipt_digest,
    meta.latest_receipt_digest_hex,
    'latest receipt digest',
  );
  assertDigest(meta.canonical_fingerprint, 'canonical fingerprint');
  assertDigest(meta.chain_digest, 'canonical chain digest');
  assertDigest(meta.latest_receipt_digest, 'latest receipt digest');
  return Object.freeze({
    schemaVersion: DURABLE_SCHEMA_VERSION,
    revision,
    eventCount,
    lastSeq,
    lastRecordedAt,
    canonicalFingerprint: meta.canonical_fingerprint,
    chainDigest: meta.chain_digest,
    latestReceiptDigest: meta.latest_receipt_digest,
  });
}

function assertEventRowEncoding(row: EventRow, label: string): void {
  assertExactSqliteText(row.event_id, row.event_id_hex, `${label} event id`);
  assertExactSqliteText(row.type, row.type_hex, `${label} event type`);
  assertExactSqliteText(row.actor, row.actor_hex, `${label} actor`);
  assertExactSqliteText(row.event_json, row.event_json_hex, `${label} event JSON`);
  assertExactSqliteText(row.event_digest, row.event_digest_hex, `${label} event digest`);
  assertExactSqliteText(
    row.previous_chain_digest,
    row.previous_chain_digest_hex,
    `${label} previous chain digest`,
  );
  assertExactSqliteText(row.chain_digest, row.chain_digest_hex, `${label} chain digest`);
}

function assertReceiptRowEncoding(row: ReceiptRow, label: string): void {
  for (const [field, value, hex] of [
    ['idempotency key', row.idempotency_key, row.idempotency_key_hex],
    ['request digest', row.request_digest, row.request_digest_hex],
    ['result digest', row.result_digest, row.result_digest_hex],
    ['transition JSON', row.transition_json, row.transition_json_hex],
    ['transition digest', row.transition_digest, row.transition_digest_hex],
    ['audit id', row.audit_id, row.audit_id_hex],
    ['audit digest', row.audit_digest, row.audit_digest_hex],
    ['base chain digest', row.base_chain_digest, row.base_chain_digest_hex],
    ['after chain digest', row.after_chain_digest, row.after_chain_digest_hex],
    ['append digest', row.append_digest, row.append_digest_hex],
    ['previous receipt digest', row.previous_receipt_digest, row.previous_receipt_digest_hex],
    ['receipt digest', row.receipt_digest, row.receipt_digest_hex],
    ['committed by', row.committed_by, row.committed_by_hex],
  ] as const) {
    assertExactSqliteText(value, hex, `${label} ${field}`);
  }
}

function assertAuditRowEncoding(row: AuditRow, label: string): void {
  assertExactSqliteText(row.audit_id, row.audit_id_hex, `${label} audit id`);
  assertExactSqliteText(row.audit_json, row.audit_json_hex, `${label} audit JSON`);
  assertExactSqliteText(row.audit_digest, row.audit_digest_hex, `${label} audit digest`);
  assertExactSqliteText(row.receipt_digest, row.receipt_digest_hex, `${label} receipt digest`);
}

function receiptFromRow(row: ReceiptRow): DurableCommitReceipt {
  const idempotencyKey = exactSqliteText(
    row.idempotency_key,
    row.idempotency_key_hex,
    'durable receipt idempotency key',
  );
  const requestDigest = exactSqliteText(
    row.request_digest,
    row.request_digest_hex,
    'durable receipt request digest',
  );
  const resultDigest = exactSqliteText(
    row.result_digest,
    row.result_digest_hex,
    'durable receipt result digest',
  );
  const transitionJson = exactSqliteText(
    row.transition_json,
    row.transition_json_hex,
    'durable receipt transition JSON',
  );
  const transitionDigestValue = exactSqliteText(
    row.transition_digest,
    row.transition_digest_hex,
    'durable receipt transition digest',
  );
  const auditId = exactSqliteText(row.audit_id, row.audit_id_hex, 'durable receipt audit id');
  const auditDigestValue = exactSqliteText(
    row.audit_digest,
    row.audit_digest_hex,
    'durable receipt audit digest',
  );
  const baseChainDigest = exactSqliteText(
    row.base_chain_digest,
    row.base_chain_digest_hex,
    'durable receipt base chain digest',
  );
  const afterChainDigest = exactSqliteText(
    row.after_chain_digest,
    row.after_chain_digest_hex,
    'durable receipt after chain digest',
  );
  const appendDigestValue = exactSqliteText(
    row.append_digest,
    row.append_digest_hex,
    'durable receipt append digest',
  );
  const previousReceiptDigest = exactSqliteText(
    row.previous_receipt_digest,
    row.previous_receipt_digest_hex,
    'durable receipt previous receipt digest',
  );
  const receiptDigestValue = exactSqliteText(
    row.receipt_digest,
    row.receipt_digest_hex,
    'durable receipt digest',
  );
  const committedBy = exactSqliteText(
    row.committed_by,
    row.committed_by_hex,
    'durable receipt committedBy',
  );

  const revision = safeInteger(row.revision, 'receipt revision', 1);
  const appendFromSeq = safeInteger(row.append_from_seq, 'receipt append start', 1);
  const appendToSeq = safeInteger(row.append_to_seq, 'receipt append end', 1);
  const committedAt = safeInteger(row.committed_at, 'receipt committedAt');
  if (appendToSeq < appendFromSeq) throw new Error('receipt append range is invalid');
  assertSqliteText(idempotencyKey, 'receipt idempotency key');
  assertSqliteText(auditId, 'receipt audit id');
  assertSqliteText(committedBy, 'receipt committedBy');

  const transition = JSON.parse(transitionJson) as DurableTransitionMetadata;
  if (stableJson(transition) !== transitionJson) {
    throw new Error(`transition JSON is not canonical at revision ${revision}`);
  }
  validateTransition(transition);

  const receipt: DurableCommitReceipt = Object.freeze({
    schemaVersion: DURABLE_SCHEMA_VERSION,
    revision,
    idempotencyKey,
    requestDigest,
    transition,
    auditId,
    auditDigest: auditDigestValue,
    baseChainDigest,
    afterChainDigest,
    appendFromSeq,
    appendToSeq,
    appendDigest: appendDigestValue,
    previousReceiptDigest,
    receiptDigest: receiptDigestValue,
    committedBy,
    committedAt,
  });
  for (const [label, value] of [
    ['request digest', requestDigest],
    ['result digest', resultDigest],
    ['transition digest', transitionDigestValue],
    ['audit digest', auditDigestValue],
    ['base chain digest', baseChainDigest],
    ['after chain digest', afterChainDigest],
    ['append digest', appendDigestValue],
    ['previous receipt digest', previousReceiptDigest],
    ['receipt digest', receiptDigestValue],
  ] as const) {
    assertDigest(value, label);
  }
  if (transition.resultDigest !== resultDigest) {
    throw new Error(`receipt result digest mismatch at revision ${revision}`);
  }
  if (transitionDigest(transition) !== transitionDigestValue) {
    throw new Error(`transition metadata digest mismatch at revision ${revision}`);
  }
  const { receiptDigest: _ignored, ...unsigned } = receipt;
  if (contentDigest(receiptPayload(unsigned)) !== receiptDigestValue) {
    throw new Error(`receipt digest mismatch at revision ${revision}`);
  }
  return receipt;
}

/**
 * Durable canonical event-byte store.
 *
 * V1 deliberately replays and re-hashes the complete canonical prefix before every new commit.
 * This makes corruption and semantic drift fail closed, but new-commit cost remains O(N). Exact
 * idempotent retries are resolved from their durable receipt before process-local capability checks.
 */
export class SqliteCanonicalLedger {
  readonly #db: DatabaseSync;
  readonly #issuedCursors = new WeakSet<object>();
  readonly #maxAppendEvents: number;
  readonly #maxRequestCharacters: number;
  readonly #faultInjector: DurableCanonicalLedgerOptions['faultInjector'];
  readonly #commitVerified?: (
    current: MemoryKernel,
    result: TransitionVerificationResult,
  ) => MemoryKernel;
  #closed = false;

  constructor(options: DurableCanonicalLedgerOptions = {}) {
    const busyTimeoutMs = options.busyTimeoutMs ?? 5_000;
    if (
      !Number.isInteger(busyTimeoutMs) ||
      busyTimeoutMs < 0 ||
      busyTimeoutMs > MAX_BUSY_TIMEOUT_MS
    ) {
      throw new RangeError(`busyTimeoutMs must be an integer in [0, ${MAX_BUSY_TIMEOUT_MS}]`);
    }
    this.#maxAppendEvents = options.maxAppendEvents ?? DEFAULT_MAX_APPEND_EVENTS;
    if (
      !Number.isInteger(this.#maxAppendEvents) ||
      this.#maxAppendEvents <= 0 ||
      this.#maxAppendEvents > MAX_DURABLE_APPEND_EVENTS
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
    if (options.transitionVerifier !== undefined) {
      if (!(options.transitionVerifier instanceof TransitionVerifier)) {
        throw new TypeError('transitionVerifier must be a TransitionVerifier instance');
      }
      this.#commitVerified = TransitionVerifier.prototype.commit.bind(options.transitionVerifier);
    }
    this.#faultInjector = options.faultInjector;
    const database = options.database ?? ':memory:';
    if (typeof database !== 'string' || database.trim().length === 0) {
      throw new TypeError('database must be a non-empty SQLite location');
    }
    this.#db = new DatabaseSync(database);
    this.#db.exec('PRAGMA trusted_schema = OFF');
    this.#db.exec('PRAGMA foreign_keys = ON');
    this.#db.exec(`PRAGMA busy_timeout = ${busyTimeoutMs}`);
    this.#db.exec('PRAGMA synchronous = FULL');
    if (database !== ':memory:') {
      const journal = this.#db.prepare('PRAGMA journal_mode = WAL').get() as
        | { readonly journal_mode: unknown }
        | undefined;
      if (journal?.journal_mode !== 'wal') {
        throw new Error('durable canonical file database requires SQLite WAL mode');
      }
    }
    this.#assertConnectionPragmas(busyTimeoutMs);
    this.#initializeSchema();
    this.status();
    const recoveryAudit = this.audit();
    if (!recoveryAudit.ok) {
      throw new Error(`durable canonical recovery audit failed: ${recoveryAudit.errors[0] ?? 'unknown error'}`);
    }
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
        // Preserve the original integrity or publication failure.
      }
      throw error;
    }
  }

  #assertConnectionPragmas(expectedBusyTimeoutMs: number): void {
    const readIntegerPragma = (name: string): number => {
      const row = this.#db.prepare(`PRAGMA ${name}`).get() as Record<string, unknown> | undefined;
      if (row === undefined) throw new Error(`SQLite PRAGMA ${name} returned no value`);
      const value = Object.values(row)[0];
      return safeInteger(value, `SQLite PRAGMA ${name}`);
    };
    if (readIntegerPragma('trusted_schema') !== 0) {
      throw new Error('durable canonical connection requires trusted_schema = OFF');
    }
    if (readIntegerPragma('foreign_keys') !== 1) {
      throw new Error('durable canonical connection requires foreign_keys = ON');
    }
    if (readIntegerPragma('synchronous') !== 2) {
      throw new Error('durable canonical connection requires synchronous = FULL');
    }
    if (readIntegerPragma('busy_timeout') !== expectedBusyTimeoutMs) {
      throw new Error('durable canonical connection busy_timeout differs from configuration');
    }
  }

  #initializeSchema(): void {
    const rows = this.#db
      .prepare(`
        SELECT name, type
          FROM sqlite_master
         WHERE name LIKE 'cl_canonical_%'
         ORDER BY name
      `)
      .all() as unknown as readonly { readonly name: unknown; readonly type: unknown }[];
    const names = new Set<string>();
    for (const row of rows) {
      if (typeof row.name !== 'string' || row.type !== 'table') {
        throw new Error('durable canonical schema contains an unexpected object');
      }
      names.add(row.name);
    }
    if (names.size > 0 && EXPECTED_TABLES.some((name) => !names.has(name))) {
      throw new Error('durable canonical schema is partially present; manual recovery is required');
    }
    if ([...names].some((name) => !EXPECTED_TABLES.includes(name))) {
      throw new Error('durable canonical schema contains an unexpected prefixed table');
    }

    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS ${TABLE_META} (
        id INTEGER PRIMARY KEY CHECK (id = ${META_ROW_ID}),
        schema_version INTEGER NOT NULL CHECK (schema_version = ${DURABLE_SCHEMA_VERSION}),
        revision INTEGER NOT NULL CHECK (revision >= 0),
        event_count INTEGER NOT NULL CHECK (event_count >= 0),
        last_seq INTEGER NOT NULL CHECK (last_seq >= 0),
        last_recorded_at INTEGER NOT NULL CHECK (last_recorded_at >= 0),
        canonical_fingerprint TEXT NOT NULL,
        chain_digest TEXT NOT NULL,
        latest_receipt_digest TEXT NOT NULL,
        updated_at INTEGER NOT NULL CHECK (updated_at >= 0)
      ) STRICT;

      CREATE TABLE IF NOT EXISTS ${TABLE_EVENTS} (
        seq INTEGER PRIMARY KEY CHECK (seq > 0),
        event_id TEXT NOT NULL UNIQUE,
        schema_version INTEGER NOT NULL CHECK (schema_version = ${EVENT_SCHEMA_VERSION}),
        type TEXT NOT NULL,
        recorded_at INTEGER NOT NULL CHECK (recorded_at >= 0),
        actor TEXT NOT NULL,
        event_json TEXT NOT NULL,
        event_digest TEXT NOT NULL,
        previous_chain_digest TEXT NOT NULL,
        chain_digest TEXT NOT NULL UNIQUE,
        revision INTEGER NOT NULL CHECK (revision > 0)
      ) STRICT;

      CREATE TABLE IF NOT EXISTS ${TABLE_RECEIPTS} (
        revision INTEGER PRIMARY KEY CHECK (revision > 0),
        idempotency_key TEXT NOT NULL UNIQUE,
        request_digest TEXT NOT NULL,
        result_digest TEXT NOT NULL UNIQUE,
        transition_json TEXT NOT NULL,
        transition_digest TEXT NOT NULL,
        audit_id TEXT NOT NULL UNIQUE,
        audit_digest TEXT NOT NULL,
        base_chain_digest TEXT NOT NULL,
        after_chain_digest TEXT NOT NULL,
        append_from_seq INTEGER NOT NULL CHECK (append_from_seq > 0),
        append_to_seq INTEGER NOT NULL CHECK (append_to_seq >= append_from_seq),
        append_digest TEXT NOT NULL,
        previous_receipt_digest TEXT NOT NULL,
        receipt_digest TEXT NOT NULL UNIQUE,
        committed_by TEXT NOT NULL,
        committed_at INTEGER NOT NULL CHECK (committed_at >= 0)
      ) STRICT;

      CREATE TABLE IF NOT EXISTS ${TABLE_AUDITS} (
        revision INTEGER PRIMARY KEY CHECK (revision > 0),
        audit_id TEXT NOT NULL UNIQUE,
        audit_json TEXT NOT NULL,
        audit_digest TEXT NOT NULL UNIQUE,
        receipt_digest TEXT NOT NULL UNIQUE
      ) STRICT;
    `);
    this.#assertSchema();

    const existing = this.#metaOrUndefined();
    if (existing === undefined) {
      const inserted = this.#db
        .prepare(`
          INSERT INTO ${TABLE_META}
            (id, schema_version, revision, event_count, last_seq, last_recorded_at,
             canonical_fingerprint, chain_digest, latest_receipt_digest, updated_at)
          VALUES (?, ?, 0, 0, 0, 0, ?, ?, ?, 0)
        `)
        .run(
          META_ROW_ID,
          DURABLE_SCHEMA_VERSION,
          GENESIS_CANONICAL_FINGERPRINT,
          GENESIS_CHAIN_DIGEST,
          GENESIS_RECEIPT_DIGEST,
        );
      if (statementChanges(inserted) !== 1) {
        throw new Error('failed to initialize durable canonical metadata');
      }
    } else {
      cursorFromMeta(existing);
    }
  }

  #assertSchema(): void {
    const tableRows = this.#db.prepare('PRAGMA table_list').all() as unknown as readonly TableListRow[];
    const tableByName = new Map<string, TableListRow>();
    for (const row of tableRows) {
      if (typeof row.name === 'string') tableByName.set(row.name, row);
    }
    for (const table of EXPECTED_TABLES) {
      const tableRow = tableByName.get(table);
      if (tableRow === undefined || tableRow.type !== 'table' || tableRow.strict !== 1) {
        throw new Error(`durable canonical table ${table} must exist as a STRICT table`);
      }
      const columns = this.#db
        .prepare(`PRAGMA table_xinfo('${table}')`)
        .all() as unknown as readonly TableColumnRow[];
      const expected = EXPECTED_COLUMNS[table];
      if (expected === undefined || columns.length !== expected.length) {
        throw new Error(`durable canonical table ${table} has an incompatible column set`);
      }
      for (let index = 0; index < expected.length; index += 1) {
        const actual = columns[index];
        const wanted = expected[index];
        if (
          actual === undefined ||
          wanted === undefined ||
          actual.cid !== index ||
          actual.name !== wanted.name ||
          actual.type !== wanted.type ||
          actual.notnull !== Number(wanted.notNull) ||
          actual.pk !== Number(wanted.primaryKey) ||
          actual.hidden !== 0
        ) {
          throw new Error(`durable canonical table ${table} has an incompatible column at ${index}`);
        }
      }

      const indexRows = this.#db
        .prepare(`PRAGMA index_list('${table}')`)
        .all() as unknown as readonly IndexListRow[];
      const uniqueColumns: string[][] = [];
      for (const indexRow of indexRows) {
        if (indexRow.unique !== 1) continue;
        if (
          typeof indexRow.name !== 'string' ||
          indexRow.origin !== 'u' ||
          indexRow.partial !== 0
        ) {
          throw new Error(`durable canonical table ${table} has an incompatible unique index`);
        }
        const indexColumns = this.#db
          .prepare(`PRAGMA index_info('${indexRow.name.replaceAll("'", "''")}')`)
          .all() as unknown as readonly IndexInfoRow[];
        const names = indexColumns
          .map((row, index) => {
            if (row.seqno !== index || typeof row.name !== 'string') {
              throw new Error(`durable canonical table ${table} has malformed unique-index metadata`);
            }
            return row.name;
          });
        uniqueColumns.push(names);
      }
      const actualUnique = uniqueColumns.map((columnsValue) => stableJson(columnsValue)).sort();
      const expectedUnique = (EXPECTED_UNIQUE_COLUMNS[table] ?? [])
        .map((columnsValue) => stableJson(columnsValue))
        .sort();
      if (stableJson(actualUnique) !== stableJson(expectedUnique)) {
        throw new Error(`durable canonical table ${table} has an incompatible uniqueness contract`);
      }
    }

    const triggers = this.#db
      .prepare(`
        SELECT name, tbl_name
          FROM sqlite_master
         WHERE type = 'trigger'
           AND tbl_name IN (?, ?, ?, ?)
      `)
      .all(...EXPECTED_TABLES) as unknown as readonly {
        readonly name: unknown;
        readonly tbl_name: unknown;
      }[];
    if (triggers.length > 0) {
      throw new Error('durable canonical tables must not have database triggers');
    }
  }

  #metaOrUndefined(): MetaRow | undefined {
    return this.#db
      .prepare(`
        SELECT schema_version, revision, event_count, last_seq, last_recorded_at,
               canonical_fingerprint, hex(canonical_fingerprint) AS canonical_fingerprint_hex,
               chain_digest, hex(chain_digest) AS chain_digest_hex,
               latest_receipt_digest,
               hex(latest_receipt_digest) AS latest_receipt_digest_hex,
               updated_at
          FROM ${TABLE_META}
         WHERE id = ?
      `)
      .get(META_ROW_ID) as MetaRow | undefined;
  }

  #meta(): MetaRow {
    const countRow = this.#db
      .prepare(`SELECT COUNT(*) AS count FROM ${TABLE_META}`)
      .get() as { readonly count: unknown } | undefined;
    if (countRow === undefined || safeInteger(countRow.count, 'metadata row count') !== 1) {
      throw new Error('durable canonical metadata must contain exactly one row');
    }
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

  #eventSelect(where = '', order = ''): string {
    return `
      SELECT seq,
             event_id, hex(event_id) AS event_id_hex,
             schema_version,
             type, hex(type) AS type_hex,
             recorded_at,
             actor, hex(actor) AS actor_hex,
             event_json, hex(event_json) AS event_json_hex,
             event_digest, hex(event_digest) AS event_digest_hex,
             previous_chain_digest,
             hex(previous_chain_digest) AS previous_chain_digest_hex,
             chain_digest, hex(chain_digest) AS chain_digest_hex,
             revision
        FROM ${TABLE_EVENTS}
        ${where}
        ${order}
    `;
  }

  #receiptSelect(where = '', order = ''): string {
    return `
      SELECT revision,
             idempotency_key, hex(idempotency_key) AS idempotency_key_hex,
             request_digest, hex(request_digest) AS request_digest_hex,
             result_digest, hex(result_digest) AS result_digest_hex,
             transition_json, hex(transition_json) AS transition_json_hex,
             transition_digest, hex(transition_digest) AS transition_digest_hex,
             audit_id, hex(audit_id) AS audit_id_hex,
             audit_digest, hex(audit_digest) AS audit_digest_hex,
             base_chain_digest, hex(base_chain_digest) AS base_chain_digest_hex,
             after_chain_digest, hex(after_chain_digest) AS after_chain_digest_hex,
             append_from_seq, append_to_seq,
             append_digest, hex(append_digest) AS append_digest_hex,
             previous_receipt_digest,
             hex(previous_receipt_digest) AS previous_receipt_digest_hex,
             receipt_digest, hex(receipt_digest) AS receipt_digest_hex,
             committed_by, hex(committed_by) AS committed_by_hex,
             committed_at
        FROM ${TABLE_RECEIPTS}
        ${where}
        ${order}
    `;
  }

  #auditSelect(where = '', order = ''): string {
    return `
      SELECT revision,
             audit_id, hex(audit_id) AS audit_id_hex,
             audit_json, hex(audit_json) AS audit_json_hex,
             audit_digest, hex(audit_digest) AS audit_digest_hex,
             receipt_digest, hex(receipt_digest) AS receipt_digest_hex
        FROM ${TABLE_AUDITS}
        ${where}
        ${order}
    `;
  }

  #lastEvent(): EventRow | undefined {
    return this.#db
      .prepare(this.#eventSelect('', 'ORDER BY seq DESC LIMIT 1'))
      .get() as EventRow | undefined;
  }

  #eventAnchor(
    seq: number,
  ): { readonly chainDigest: string; readonly recordedAt: number; readonly revision: number } | undefined {
    const row = this.#db
      .prepare(`
        SELECT chain_digest, hex(chain_digest) AS chain_digest_hex,
               recorded_at, revision
          FROM ${TABLE_EVENTS}
         WHERE seq = ?
      `)
      .get(seq) as
      | {
          readonly chain_digest: unknown;
          readonly chain_digest_hex: unknown;
          readonly recorded_at: unknown;
          readonly revision: unknown;
        }
      | undefined;
    if (row === undefined) return undefined;
    const chainDigest = exactSqliteText(
      row.chain_digest,
      row.chain_digest_hex,
      `canonical event ${seq} anchor chain digest`,
    );
    assertDigest(chainDigest, `canonical event ${seq} anchor chain digest`);
    return Object.freeze({
      chainDigest,
      recordedAt: safeInteger(row.recorded_at, `canonical event ${seq} anchor recordedAt`),
      revision: safeInteger(row.revision, `canonical event ${seq} anchor revision`, 1),
    });
  }

  #latestReceipt(): ReceiptRow | undefined {
    return this.#db
      .prepare(this.#receiptSelect('', 'ORDER BY revision DESC LIMIT 1'))
      .get() as ReceiptRow | undefined;
  }

  #receiptForRevision(revision: number): ReceiptRow | undefined {
    return this.#db
      .prepare(this.#receiptSelect('WHERE revision = ?'))
      .get(revision) as ReceiptRow | undefined;
  }

  #latestAudit(): AuditRow | undefined {
    return this.#db
      .prepare(this.#auditSelect('', 'ORDER BY revision DESC LIMIT 1'))
      .get() as AuditRow | undefined;
  }

  #auditForRevision(revision: number): AuditRow | undefined {
    return this.#db
      .prepare(this.#auditSelect('WHERE revision = ?'))
      .get(revision) as AuditRow | undefined;
  }

  #assertReceiptLinks(receipt: DurableCommitReceipt, cursor: DurableCanonicalCursor): void {
    if (receipt.revision === 1) {
      if (receipt.previousReceiptDigest !== GENESIS_RECEIPT_DIGEST) {
        throw new Error('first durable receipt does not reference the receipt genesis');
      }
    } else {
      const previousRow = this.#receiptForRevision(receipt.revision - 1);
      if (previousRow === undefined) {
        throw new Error(`previous durable receipt is missing at revision ${receipt.revision - 1}`);
      }
      const previousReceipt = receiptFromRow(previousRow);
      if (receipt.previousReceiptDigest !== previousReceipt.receiptDigest) {
        throw new Error(`durable receipt predecessor mismatch at revision ${receipt.revision}`);
      }
    }

    if (receipt.revision < cursor.revision) {
      const nextRow = this.#receiptForRevision(receipt.revision + 1);
      if (nextRow === undefined) {
        throw new Error(`next durable receipt is missing at revision ${receipt.revision + 1}`);
      }
      const nextReceipt = receiptFromRow(nextRow);
      if (nextReceipt.previousReceiptDigest !== receipt.receiptDigest) {
        throw new Error(`durable receipt successor mismatch at revision ${receipt.revision}`);
      }
    } else if (
      receipt.revision !== cursor.revision ||
      receipt.receiptDigest !== cursor.latestReceiptDigest ||
      receipt.afterChainDigest !== cursor.chainDigest ||
      receipt.transition.afterFingerprint !== cursor.canonicalFingerprint
    ) {
      throw new Error('latest durable receipt differs from the canonical cursor');
    }
  }

  #assertReceiptAppend(
    receipt: DurableCommitReceipt,
    cursor: DurableCanonicalCursor,
  ): readonly MemoryEvent[] {
    const expectedCount = receipt.appendToSeq - receipt.appendFromSeq + 1;
    if (expectedCount <= 0 || expectedCount > MAX_DURABLE_APPEND_EVENTS) {
      throw new Error(`durable receipt ${receipt.revision} has an invalid append size`);
    }

    let previousChain = GENESIS_CHAIN_DIGEST;
    let previousRecordedAt = 0;
    let previousRevision = 0;
    if (receipt.appendFromSeq > 1) {
      const anchor = this.#eventAnchor(receipt.appendFromSeq - 1);
      if (anchor === undefined) {
        throw new Error(`durable receipt ${receipt.revision} append predecessor is missing`);
      }
      previousChain = anchor.chainDigest;
      previousRecordedAt = anchor.recordedAt;
      previousRevision = anchor.revision;
    }
    if (receipt.baseChainDigest !== previousChain) {
      throw new Error(`durable receipt ${receipt.revision} base chain mismatch`);
    }

    const rows = this.#db
      .prepare(this.#eventSelect('WHERE seq BETWEEN ? AND ?', 'ORDER BY seq'))
      .all(receipt.appendFromSeq, receipt.appendToSeq) as unknown as readonly EventRow[];
    if (rows.length !== expectedCount) {
      throw new Error(`durable receipt ${receipt.revision} append range is incomplete`);
    }

    const events: MemoryEvent[] = [];
    let expectedSeq = receipt.appendFromSeq;
    for (const row of rows) {
      const verified = this.#verifyEventRow(row, expectedSeq, previousChain, cursor.revision);
      if (verified.revision !== receipt.revision) {
        throw new Error(`durable receipt ${receipt.revision} event attribution mismatch`);
      }
      if (verified.event.recordedAt < previousRecordedAt) {
        throw new Error(`durable receipt ${receipt.revision} transaction time regresses`);
      }
      if (verified.revision < previousRevision || verified.revision > previousRevision + 1) {
        throw new Error(`durable receipt ${receipt.revision} revision boundary is invalid`);
      }
      previousChain = verified.chain;
      previousRecordedAt = verified.event.recordedAt;
      previousRevision = verified.revision;
      expectedSeq += 1;
      events.push(verified.event);
    }

    if (
      previousChain !== receipt.afterChainDigest ||
      appendDigest(events) !== receipt.appendDigest ||
      canonicalDigest(events) !== receipt.transition.appendFingerprint
    ) {
      throw new Error(`durable receipt ${receipt.revision} append integrity mismatch`);
    }
    return Object.freeze(events);
  }

  #assertReceiptHistory(meta: MetaRow, events: readonly MemoryEvent[]): number {
    const cursor = cursorFromMeta(meta);
    const receiptRows = this.#db
      .prepare(this.#receiptSelect('', 'ORDER BY revision'))
      .all() as unknown as readonly ReceiptRow[];
    const auditRows = this.#db
      .prepare(this.#auditSelect('', 'ORDER BY revision'))
      .all() as unknown as readonly AuditRow[];
    if (receiptRows.length !== cursor.revision || auditRows.length !== cursor.revision) {
      throw new Error('receipt or audit count differs from canonical revision');
    }

    let previousReceipt = GENESIS_RECEIPT_DIGEST;
    let previousChain = GENESIS_CHAIN_DIGEST;
    let previousFingerprint = GENESIS_CANONICAL_FINGERPRINT;
    let previousToSeq = 0;
    let previousCommittedAt = -1;
    for (let index = 0; index < receiptRows.length; index += 1) {
      const row = receiptRows[index];
      const auditRow = auditRows[index];
      if (row === undefined || auditRow === undefined) {
        throw new Error(`durable receipt or audit is missing at revision ${index + 1}`);
      }
      const receipt = receiptFromRow(row);
      if (receipt.revision !== index + 1) {
        throw new Error(`durable receipt revision gap at ${index + 1}`);
      }
      this.#verifiedAudit(auditRow, receipt);
      if (
        receipt.previousReceiptDigest !== previousReceipt ||
        receipt.baseChainDigest !== previousChain ||
        receipt.transition.baseFingerprint !== previousFingerprint ||
        receipt.appendFromSeq !== previousToSeq + 1 ||
        receipt.committedAt <= previousCommittedAt
      ) {
        throw new Error(`durable receipt chain mismatch at revision ${receipt.revision}`);
      }
      const range = events.slice(receipt.appendFromSeq - 1, receipt.appendToSeq);
      if (
        range.length !== receipt.appendToSeq - receipt.appendFromSeq + 1 ||
        appendDigest(range) !== receipt.appendDigest ||
        canonicalDigest(range) !== receipt.transition.appendFingerprint
      ) {
        throw new Error(`durable receipt event range mismatch at revision ${receipt.revision}`);
      }
      this.#assertReceiptAppend(receipt, cursor);
      previousReceipt = receipt.receiptDigest;
      previousChain = receipt.afterChainDigest;
      previousFingerprint = receipt.transition.afterFingerprint;
      previousToSeq = receipt.appendToSeq;
      previousCommittedAt = receipt.committedAt;
    }
    if (
      previousReceipt !== cursor.latestReceiptDigest ||
      previousChain !== cursor.chainDigest ||
      previousFingerprint !== cursor.canonicalFingerprint ||
      previousToSeq !== cursor.lastSeq
    ) {
      throw new Error('durable receipt history head differs from canonical metadata');
    }
    return receiptRows.length;
  }

  #verifiedAudit(row: AuditRow, receipt: DurableCommitReceipt): TransitionAuditRecord {
    const auditId = exactSqliteText(
      row.audit_id,
      row.audit_id_hex,
      `durable audit revision ${receipt.revision} audit id`,
    );
    const auditJson = exactSqliteText(
      row.audit_json,
      row.audit_json_hex,
      `durable audit revision ${receipt.revision} audit JSON`,
    );
    const auditDigestValue = exactSqliteText(
      row.audit_digest,
      row.audit_digest_hex,
      `durable audit revision ${receipt.revision} audit digest`,
    );
    const receiptDigestValue = exactSqliteText(
      row.receipt_digest,
      row.receipt_digest_hex,
      `durable audit revision ${receipt.revision} receipt digest`,
    );
    const revision = safeInteger(row.revision, 'audit revision', 1);
    if (
      revision !== receipt.revision ||
      auditId !== receipt.auditId ||
      auditDigestValue !== receipt.auditDigest ||
      receiptDigestValue !== receipt.receiptDigest
    ) {
      throw new Error(`audit/receipt metadata mismatch at revision ${receipt.revision}`);
    }
    const audit = JSON.parse(auditJson) as TransitionAuditRecord;
    if (stableJson(audit) !== auditJson) {
      throw new Error(`audit JSON is not canonical at revision ${receipt.revision}`);
    }
    validateAudit(audit, receipt.transition);
    if (auditDigest(audit) !== receipt.auditDigest) {
      throw new Error(`audit digest mismatch at revision ${receipt.revision}`);
    }
    return audit;
  }

  #verifyEventRow(
    row: EventRow,
    expectedSeq: number,
    previous: string,
    maximumRevision: number,
  ): { readonly event: MemoryEvent; readonly chain: string; readonly revision: number } {
    const eventId = exactSqliteText(
      row.event_id,
      row.event_id_hex,
      `canonical event ${expectedSeq} event id`,
    );
    const eventType = exactSqliteText(
      row.type,
      row.type_hex,
      `canonical event ${expectedSeq} event type`,
    );
    const actor = exactSqliteText(
      row.actor,
      row.actor_hex,
      `canonical event ${expectedSeq} actor`,
    );
    const eventJson = exactSqliteText(
      row.event_json,
      row.event_json_hex,
      `canonical event ${expectedSeq} event JSON`,
    );
    const eventDigestValue = exactSqliteText(
      row.event_digest,
      row.event_digest_hex,
      `canonical event ${expectedSeq} event digest`,
    );
    const previousChainDigest = exactSqliteText(
      row.previous_chain_digest,
      row.previous_chain_digest_hex,
      `canonical event ${expectedSeq} previous chain digest`,
    );
    const chainDigest = exactSqliteText(
      row.chain_digest,
      row.chain_digest_hex,
      `canonical event ${expectedSeq} chain digest`,
    );
    const seq = safeInteger(row.seq, `event ${expectedSeq} seq`, 1);
    const schemaVersion = safeInteger(row.schema_version, `event ${expectedSeq} schema_version`, 1);
    const recordedAt = safeInteger(row.recorded_at, `event ${expectedSeq} recorded_at`);
    const revision = safeInteger(row.revision, `event ${expectedSeq} revision`, 1);
    if (seq !== expectedSeq || schemaVersion !== EVENT_SCHEMA_VERSION || revision > maximumRevision) {
      throw new Error(`canonical event sequence, schema, or revision mismatch at ${expectedSeq}`);
    }
    assertSqliteText(eventId, `event ${expectedSeq} id`);
    assertSqliteText(eventType, `event ${expectedSeq} type`);
    assertSqliteText(actor, `event ${expectedSeq} actor`);
    assertDigest(eventDigestValue, `event ${expectedSeq} digest`);
    assertDigest(previousChainDigest, `event ${expectedSeq} previous chain digest`);
    assertDigest(chainDigest, `event ${expectedSeq} chain digest`);
    const parsed = JSON.parse(eventJson) as MemoryEvent;
    if (stableJson(parsed) !== eventJson) {
      throw new Error(`canonical event JSON is not canonical at sequence ${seq}`);
    }
    if (
      parsed.seq !== seq ||
      parsed.id !== eventId ||
      parsed.type !== eventType ||
      parsed.recordedAt !== recordedAt ||
      parsed.actor !== actor ||
      parsed.schemaVersion !== EVENT_SCHEMA_VERSION
    ) {
      throw new Error(`canonical event row metadata diverges at sequence ${seq}`);
    }
    const expectedEventDigest = eventDigest(parsed);
    if (expectedEventDigest !== eventDigestValue || previousChainDigest !== previous) {
      throw new Error(`canonical event digest or predecessor mismatch at sequence ${seq}`);
    }
    const expectedChain = nextChainDigest(previous, parsed, expectedEventDigest);
    if (expectedChain !== chainDigest) {
      throw new Error(`canonical event chain mismatch at sequence ${seq}`);
    }
    return Object.freeze({ event: parsed, chain: expectedChain, revision });
  }

  #loadEventsVerified(meta: MetaRow): readonly MemoryEvent[] {
    const cursor = cursorFromMeta(meta);
    const rows = this.#db
      .prepare(this.#eventSelect('', 'ORDER BY seq'))
      .all() as unknown as readonly EventRow[];
    if (rows.length !== cursor.eventCount) {
      throw new Error('canonical event count differs from metadata');
    }
    const events: MemoryEvent[] = [];
    let previous = GENESIS_CHAIN_DIGEST;
    let previousRecordedAt = 0;
    let previousRevision = 0;
    for (let index = 0; index < rows.length; index += 1) {
      const verified = this.#verifyEventRow(rows[index] as EventRow, index + 1, previous, cursor.revision);
      if (verified.event.recordedAt < previousRecordedAt) {
        throw new Error(`canonical event transaction time regresses at sequence ${index + 1}`);
      }
      if (verified.revision < previousRevision || verified.revision > previousRevision + 1) {
        throw new Error(`canonical event revision gap at sequence ${index + 1}`);
      }
      previous = verified.chain;
      previousRecordedAt = verified.event.recordedAt;
      previousRevision = verified.revision;
      events.push(verified.event);
    }
    if (previous !== cursor.chainDigest) {
      throw new Error('canonical event chain head differs from metadata');
    }
    if ((rows.length === 0 ? 0 : previousRevision) !== cursor.revision) {
      throw new Error('canonical event revision head differs from metadata');
    }
    if (
      (events.at(-1)?.seq ?? 0) !== cursor.lastSeq ||
      (events.at(-1)?.recordedAt ?? 0) !== cursor.lastRecordedAt
    ) {
      throw new Error('canonical event tail differs from metadata');
    }
    const canonical = MemoryKernel.from(events).events();
    if (fingerprintMemoryEvents(canonical) !== cursor.canonicalFingerprint) {
      throw new Error('canonical semantic fingerprint differs from metadata');
    }
    return canonical;
  }

  #requestSnapshot(request: DurableCommitRequest): {
    readonly snapshot: NormalizedDurableCommitRequest;
    readonly capabilities: CommitCapabilities;
  } {
    if (typeof request !== 'object' || request === null) {
      throw new TypeError('durable commit request has an invalid runtime shape');
    }
    const baseCapability = request.base;
    const resultCapability = request.result;
    const envelopeValue = request.envelope;
    if (
      typeof baseCapability !== 'object' ||
      baseCapability === null ||
      typeof resultCapability !== 'object' ||
      resultCapability === null ||
      typeof envelopeValue !== 'object' ||
      envelopeValue === null
    ) {
      throw new TypeError('durable commit request has an invalid runtime shape');
    }
    const payload = {
      base: snapshotJson(baseCapability),
      result: snapshotJson(resultCapability),
      envelope: snapshotJson(envelopeValue),
    };
    const canonical = stableJson(payload);
    if (canonical.length > this.#maxRequestCharacters) {
      throw new RangeError('durable commit request exceeds the canonical size budget');
    }
    return Object.freeze({
      snapshot: Object.freeze({
        ...payload,
        requestDigest: contentDigest({ domain: 'cl-durable-request-v2', payload }),
      }),
      capabilities: Object.freeze({ base: baseCapability, result: resultCapability }),
    });
  }

  #validateRequest(snapshot: NormalizedDurableCommitRequest): void {
    const envelope = snapshot.envelope;
    assertSqliteText(envelope.idempotencyKey, 'idempotency key');
    assertSqliteText(envelope.auditId, 'audit id');
    assertSqliteText(envelope.actor, 'audit actor');
    assertSqliteText(envelope.committedBy, 'committedBy');
    if (
      envelope.idempotencyKey.length > 256 ||
      envelope.auditId.length > 256 ||
      envelope.actor.length > 256 ||
      envelope.committedBy.length > 256
    ) {
      throw new Error('durable commit identity fields exceed their size budget');
    }
    safeInteger(envelope.recordedAt, 'audit recordedAt');
    if (!verifyTransitionResultIntegrity(snapshot.result)) {
      throw new Error('transition result failed integrity verification');
    }
    if (
      snapshot.result.verdict !== 'accept' ||
      snapshot.result.stagedAppend === undefined ||
      snapshot.result.stagedAppend.length === 0 ||
      snapshot.result.afterFingerprint === undefined ||
      snapshot.result.appendFingerprint === undefined
    ) {
      throw new Error('durable commit requires an accepted transition with a non-empty staged append');
    }
    if (snapshot.result.stagedAppend.length > MAX_DURABLE_APPEND_EVENTS) {
      throw new RangeError(
        `durable append exceeds the ${MAX_DURABLE_APPEND_EVENTS}-event protocol limit`,
      );
    }
    validateTransition(transitionFromResult(snapshot.result));
    assertDigest(snapshot.base.canonicalFingerprint, 'base canonical fingerprint');
    assertDigest(snapshot.base.chainDigest, 'base chain digest');
    assertDigest(snapshot.base.latestReceiptDigest, 'base latest receipt digest');
  }

  #receiptByIdempotencyKey(key: string): ReceiptRow | undefined {
    return this.#db
      .prepare(this.#receiptSelect('WHERE idempotency_key = ?'))
      .get(key) as ReceiptRow | undefined;
  }

  #receiptByResultDigest(resultDigest: string): ReceiptRow | undefined {
    return this.#db
      .prepare(this.#receiptSelect('WHERE result_digest = ?'))
      .get(resultDigest) as ReceiptRow | undefined;
  }

  #idempotentReceipt(
    snapshot: NormalizedDurableCommitRequest,
  ): { readonly receipt: DurableCommitReceipt; readonly meta: MetaRow } | undefined {
    const row = this.#receiptByIdempotencyKey(snapshot.envelope.idempotencyKey);
    if (row === undefined) {
      const resultRow = this.#receiptByResultDigest(snapshot.result.resultDigest);
      if (resultRow !== undefined) {
        throw new Error('transition result was already committed under a different idempotency key');
      }
      return undefined;
    }
    assertReceiptRowEncoding(row, 'idempotent durable receipt');
    if (row.request_digest !== snapshot.requestDigest) {
      throw new Error('idempotency key was already used for a different durable request');
    }
    const receipt = receiptFromRow(row);
    this.#verifiedAudit(
      this.#auditForRevision(receipt.revision) ?? (() => {
        throw new Error('idempotent receipt audit is missing');
      })(),
      receipt,
    );
    const meta = this.#meta();
    const events = this.#loadEventsVerified(meta);
    this.#assertReceiptHistory(meta, events);
    const cursor = cursorFromMeta(meta);
    if (cursor.revision < receipt.revision) {
      throw new Error('idempotent receipt is newer than the current canonical cursor');
    }
    this.#assertReceiptLinks(receipt, cursor);
    this.#assertReceiptAppend(receipt, cursor);
    return Object.freeze({ receipt, meta });
  }

  cursor(): DurableCanonicalCursor {
    return this.status().cursor;
  }

  status(): DurableLedgerStatus {
    return this.#transaction('read', () => {
      this.#assertSchema();
      const meta = this.#meta();
      const cursor = this.#issueCursor(meta);
      const last = this.#lastEvent();
      const latestReceiptRow = this.#latestReceipt();
      const latestAuditRow = this.#latestAudit();
      if (cursor.eventCount === 0) {
        if (
          last !== undefined ||
          latestReceiptRow !== undefined ||
          latestAuditRow !== undefined ||
          cursor.canonicalFingerprint !== GENESIS_CANONICAL_FINGERPRINT ||
          cursor.chainDigest !== GENESIS_CHAIN_DIGEST ||
          cursor.revision !== 0 ||
          cursor.latestReceiptDigest !== GENESIS_RECEIPT_DIGEST
        ) {
          throw new Error('empty canonical ledger metadata is inconsistent');
        }
        return Object.freeze({
          ok: true,
          reason: 'empty canonical ledger is initialized',
          cursor,
        });
      }
      if (last === undefined || latestReceiptRow === undefined || latestAuditRow === undefined) {
        throw new Error('canonical tail, receipt, or audit is missing');
      }
      let previousChain = GENESIS_CHAIN_DIGEST;
      if (cursor.lastSeq > 1) {
        const anchor = this.#eventAnchor(cursor.lastSeq - 1);
        if (anchor === undefined) throw new Error('canonical tail predecessor is missing');
        previousChain = anchor.chainDigest;
      }
      const verifiedLast = this.#verifyEventRow(
        last,
        cursor.lastSeq,
        previousChain,
        cursor.revision,
      );
      if (
        verifiedLast.event.recordedAt !== cursor.lastRecordedAt ||
        verifiedLast.chain !== cursor.chainDigest ||
        verifiedLast.revision !== cursor.revision
      ) {
        throw new Error('canonical tail row differs from metadata');
      }
      const receipt = receiptFromRow(latestReceiptRow);
      if (receipt.appendToSeq !== cursor.lastSeq) {
        throw new Error('latest durable receipt append tail differs from canonical cursor');
      }
      this.#assertReceiptLinks(receipt, cursor);
      this.#assertReceiptAppend(receipt, cursor);
      this.#verifiedAudit(latestAuditRow, receipt);
      return Object.freeze({
        ok: true,
        reason: 'canonical tail, receipt, audit, and cursor agree',
        cursor,
      });
    });
  }

  commit(request: DurableCommitRequest): DurableCommitResult {
    const captured = this.#requestSnapshot(request);
    this.#validateRequest(captured.snapshot);
    return this.#transaction('write', () => {
      this.#inject('after-begin');
      this.#assertSchema();
      const duplicate = this.#idempotentReceipt(captured.snapshot);
      if (duplicate !== undefined) {
        return Object.freeze({
          cursor: this.#issueCursor(duplicate.meta),
          receipt: duplicate.receipt,
          idempotentReplay: true,
          appendedEvents: Object.freeze([]),
        });
      }

      const stagedAppend = captured.snapshot.result.stagedAppend;
      if (stagedAppend === undefined) {
        throw new Error('verified transition lost its staged append after validation');
      }
      if (stagedAppend.length > this.#maxAppendEvents) {
        throw new RangeError(`durable append exceeds the ${this.#maxAppendEvents}-event limit`);
      }

      this.#assertCursorCapability(captured.capabilities.base);
      if (this.#commitVerified === undefined) {
        throw new Error('new durable commits require a configured TransitionVerifier capability');
      }
      const meta = this.#meta();
      const cursor = cursorFromMeta(meta);
      if (
        captured.snapshot.base.schemaVersion !== DURABLE_SCHEMA_VERSION ||
        captured.snapshot.base.revision !== cursor.revision ||
        captured.snapshot.base.eventCount !== cursor.eventCount ||
        captured.snapshot.base.lastSeq !== cursor.lastSeq ||
        captured.snapshot.base.lastRecordedAt !== cursor.lastRecordedAt ||
        captured.snapshot.base.canonicalFingerprint !== cursor.canonicalFingerprint ||
        captured.snapshot.base.chainDigest !== cursor.chainDigest ||
        captured.snapshot.base.latestReceiptDigest !== cursor.latestReceiptDigest
      ) {
        throw new Error('durable commit base cursor is stale');
      }

      const existingEvents = this.#loadEventsVerified(meta);
      this.#assertReceiptHistory(meta, existingEvents);
      this.#inject('after-prefix-audit');
      if (captured.snapshot.result.baseFingerprint !== cursor.canonicalFingerprint) {
        throw new Error('verified transition base differs from the durable canonical cursor');
      }
      const currentKernel = MemoryKernel.from(existingEvents);
      const committedKernel = this.#commitVerified(currentKernel, captured.capabilities.result);
      if (!(committedKernel instanceof MemoryKernel)) {
        throw new Error('trusted transition verifier did not return a MemoryKernel');
      }
      const nextEvents = MemoryKernel.from(committedKernel.events()).events();
      if (nextEvents.length !== existingEvents.length + stagedAppend.length) {
        throw new Error('verified transition produced an unexpected canonical event count');
      }
      for (let index = 0; index < existingEvents.length; index += 1) {
        if (stableJson(existingEvents[index]) !== stableJson(nextEvents[index])) {
          throw new Error(`verified transition rewrote canonical prefix event ${index + 1}`);
        }
      }
      const append = Object.freeze(nextEvents.slice(existingEvents.length));
      if (stableJson(append) !== stableJson(stagedAppend)) {
        throw new Error('verified transition output differs from its staged append');
      }
      if (canonicalDigest(append) !== captured.snapshot.result.appendFingerprint) {
        throw new Error('verified transition append fingerprint mismatch');
      }
      if (fingerprintMemoryEvents(nextEvents) !== captured.snapshot.result.afterFingerprint) {
        throw new Error('verified transition after fingerprint mismatch');
      }

      const first = append.at(0);
      const last = append.at(-1);
      if (
        first === undefined ||
        last === undefined ||
        first.seq !== cursor.lastSeq + 1 ||
        last.seq !== cursor.lastSeq + append.length
      ) {
        throw new Error('durable append sequence is not contiguous with the canonical cursor');
      }
      if (captured.snapshot.envelope.recordedAt < last.recordedAt) {
        throw new Error('durable audit cannot predate the final appended event');
      }
      let expectedSeq = cursor.lastSeq + 1;
      let recordedAt = cursor.lastRecordedAt;
      const newIds = new Set<string>();
      for (const event of append) {
        if (
          event.seq !== expectedSeq ||
          event.schemaVersion !== EVENT_SCHEMA_VERSION ||
          !Number.isSafeInteger(event.recordedAt) ||
          event.recordedAt < recordedAt ||
          newIds.has(event.id)
        ) {
          throw new Error(`durable append event is malformed at sequence ${expectedSeq}`);
        }
        assertSqliteText(event.id, `event ${expectedSeq} id`);
        assertSqliteText(event.type, `event ${expectedSeq} type`);
        assertSqliteText(event.actor, `event ${expectedSeq} actor`);
        const serialized = stableJson(event);
        assertCanonicalSqliteText(serialized, `event ${expectedSeq} JSON`);
        newIds.add(event.id);
        expectedSeq += 1;
        recordedAt = event.recordedAt;
      }

      const revision = cursor.revision + 1;
      let chain = cursor.chainDigest;
      const insertEvent = this.#db.prepare(`
        INSERT INTO ${TABLE_EVENTS}
          (seq, event_id, schema_version, type, recorded_at, actor, event_json, event_digest,
           previous_chain_digest, chain_digest, revision)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (const event of append) {
        const serialized = stableJson(event);
        const digestValue = eventDigest(event);
        const next = nextChainDigest(chain, event, digestValue);
        const inserted = insertEvent.run(
          event.seq,
          event.id,
          event.schemaVersion,
          event.type,
          event.recordedAt,
          event.actor,
          serialized,
          digestValue,
          chain,
          next,
          revision,
        );
        if (statementChanges(inserted) !== 1) {
          throw new Error(`failed to insert canonical event ${event.id}`);
        }
        chain = next;
      }
      this.#inject('after-events');

      const transition = transitionFromResult(captured.snapshot.result);
      const transitionJson = stableJson(transition);
      const transitionDigestValue = transitionDigest(transition);
      const audit = auditRecordFor(captured.snapshot.result, captured.snapshot.envelope, revision);
      validateAudit(audit, transition);
      const auditJson = stableJson(audit);
      const auditDigestValue = auditDigest(audit);
      const committedAt = Math.max(
        Date.now(),
        safeInteger(meta.updated_at, 'metadata updated_at') + 1,
        captured.snapshot.envelope.recordedAt,
      );
      if (!Number.isSafeInteger(committedAt)) throw new Error('durable committedAt is unsafe');
      const appendDigestValue = appendDigest(append);
      const unsignedReceipt = Object.freeze({
        schemaVersion: DURABLE_SCHEMA_VERSION,
        revision,
        idempotencyKey: captured.snapshot.envelope.idempotencyKey,
        requestDigest: captured.snapshot.requestDigest,
        transition,
        auditId: audit.id,
        auditDigest: auditDigestValue,
        baseChainDigest: cursor.chainDigest,
        afterChainDigest: chain,
        appendFromSeq: first.seq,
        appendToSeq: last.seq,
        appendDigest: appendDigestValue,
        previousReceiptDigest: cursor.latestReceiptDigest,
        committedBy: captured.snapshot.envelope.committedBy,
        committedAt,
      });
      const receiptDigestValue = contentDigest(receiptPayload(unsignedReceipt));
      const receipt = Object.freeze({ ...unsignedReceipt, receiptDigest: receiptDigestValue });

      const auditInsert = this.#db
        .prepare(`
          INSERT INTO ${TABLE_AUDITS}
            (revision, audit_id, audit_json, audit_digest, receipt_digest)
          VALUES (?, ?, ?, ?, ?)
        `)
        .run(revision, audit.id, auditJson, auditDigestValue, receiptDigestValue);
      if (statementChanges(auditInsert) !== 1) throw new Error('failed to insert durable audit');
      this.#inject('after-audit');

      const receiptInsert = this.#db
        .prepare(`
          INSERT INTO ${TABLE_RECEIPTS}
            (revision, idempotency_key, request_digest, result_digest,
             transition_json, transition_digest, audit_id, audit_digest,
             base_chain_digest, after_chain_digest, append_from_seq, append_to_seq,
             append_digest, previous_receipt_digest, receipt_digest,
             committed_by, committed_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .run(
          revision,
          receipt.idempotencyKey,
          receipt.requestDigest,
          transition.resultDigest,
          transitionJson,
          transitionDigestValue,
          receipt.auditId,
          receipt.auditDigest,
          receipt.baseChainDigest,
          receipt.afterChainDigest,
          receipt.appendFromSeq,
          receipt.appendToSeq,
          receipt.appendDigest,
          receipt.previousReceiptDigest,
          receipt.receiptDigest,
          receipt.committedBy,
          receipt.committedAt,
        );
      if (statementChanges(receiptInsert) !== 1) throw new Error('failed to insert durable receipt');
      this.#inject('after-receipt');

      const metadataUpdate = this.#db
        .prepare(`
          UPDATE ${TABLE_META}
             SET revision = ?, event_count = ?, last_seq = ?, last_recorded_at = ?,
                 canonical_fingerprint = ?, chain_digest = ?, latest_receipt_digest = ?,
                 updated_at = ?
           WHERE id = ? AND revision = ? AND canonical_fingerprint = ? AND chain_digest = ?
        `)
        .run(
          revision,
          nextEvents.length,
          last.seq,
          last.recordedAt,
          transition.afterFingerprint,
          chain,
          receiptDigestValue,
          committedAt,
          META_ROW_ID,
          cursor.revision,
          cursor.canonicalFingerprint,
          cursor.chainDigest,
        );
      if (statementChanges(metadataUpdate) !== 1) {
        throw new Error('durable canonical compare-and-swap failed');
      }
      this.#inject('after-cursor');
      this.#inject('before-commit');
      return Object.freeze({
        cursor: this.#issueCursor(this.#meta()),
        receipt,
        idempotentReplay: false,
        appendedEvents: append,
      });
    });
  }

  readRange(fromSeq: number, limit = MAX_RANGE_EVENTS): readonly MemoryEvent[] {
    if (!Number.isInteger(fromSeq) || fromSeq <= 0) throw new RangeError('fromSeq must be positive');
    if (!Number.isInteger(limit) || limit <= 0 || limit > MAX_RANGE_EVENTS) {
      throw new RangeError(`range limit must be in [1, ${MAX_RANGE_EVENTS}]`);
    }
    return this.#transaction('read', () => {
      this.#assertSchema();
      const cursor = cursorFromMeta(this.#meta());
      if (fromSeq > cursor.lastSeq) return Object.freeze([]);
      let previous = GENESIS_CHAIN_DIGEST;
      let previousRecordedAt = 0;
      let previousRevision = 0;
      if (fromSeq > 1) {
        const anchor = this.#eventAnchor(fromSeq - 1);
        if (anchor === undefined) throw new Error('range predecessor is absent from the canonical ledger');
        previous = anchor.chainDigest;
        previousRecordedAt = anchor.recordedAt;
        previousRevision = anchor.revision;
      }
      const rows = this.#db
        .prepare(this.#eventSelect('WHERE seq >= ? AND seq <= ?', 'ORDER BY seq LIMIT ?'))
        .all(fromSeq, cursor.lastSeq, limit) as unknown as readonly EventRow[];
      const expectedCount = Math.min(limit, cursor.lastSeq - fromSeq + 1);
      if (rows.length !== expectedCount) {
        throw new Error('canonical range contains a gap or missing row');
      }
      const result: MemoryEvent[] = [];
      let expectedSeq = fromSeq;
      for (const row of rows) {
        const verified = this.#verifyEventRow(row, expectedSeq, previous, cursor.revision);
        if (verified.event.recordedAt < previousRecordedAt) {
          throw new Error(`canonical range transaction time regresses at sequence ${expectedSeq}`);
        }
        if (verified.revision < previousRevision || verified.revision > previousRevision + 1) {
          throw new Error(`canonical range revision gap at sequence ${expectedSeq}`);
        }
        previous = verified.chain;
        previousRecordedAt = verified.event.recordedAt;
        previousRevision = verified.revision;
        expectedSeq += 1;
        result.push(verified.event);
      }
      return Object.freeze(result);
    });
  }

  loadKernel(): MemoryKernel {
    return this.#transaction('read', () => {
      this.#assertSchema();
      const meta = this.#meta();
      const events = this.#loadEventsVerified(meta);
      this.#assertReceiptHistory(meta, events);
      return MemoryKernel.from(events);
    });
  }

  receipt(idempotencyKey: string): DurableCommitReceipt | undefined {
    assertSqliteText(idempotencyKey, 'idempotency key');
    return this.#transaction('read', () => {
      this.#assertSchema();
      const row = this.#receiptByIdempotencyKey(idempotencyKey);
      if (row === undefined) return undefined;
      const receipt = receiptFromRow(row);
      this.#verifiedAudit(
        this.#auditForRevision(receipt.revision) ?? (() => {
          throw new Error('receipt audit is missing');
        })(),
        receipt,
      );
      const meta = this.#meta();
      const events = this.#loadEventsVerified(meta);
      this.#assertReceiptHistory(meta, events);
      const cursor = cursorFromMeta(meta);
      this.#assertReceiptLinks(receipt, cursor);
      this.#assertReceiptAppend(receipt, cursor);
      return receipt;
    });
  }

  audit(): DurableLedgerAudit {
    return this.#transaction('read', () => {
      const errors: string[] = [];
      try {
        this.#assertSchema();
      } catch (error) {
        errors.push(error instanceof Error ? error.message : 'durable schema audit failed');
      }
      const integrityRows = this.#db.prepare('PRAGMA integrity_check').all() as unknown as readonly Record<string, unknown>[];
      for (const row of integrityRows) {
        const value = Object.values(row)[0];
        if (value !== 'ok') errors.push(`SQLite integrity_check: ${String(value)}`);
      }

      const meta = this.#meta();
      // Audit reports must not mint write capabilities, especially when the audit fails.
      const cursor = cursorFromMeta(meta);
      let events: readonly MemoryEvent[] = Object.freeze([]);
      try {
        events = this.#loadEventsVerified(meta);
      } catch (error) {
        errors.push(error instanceof Error ? error.message : 'canonical event audit failed');
      }

      const receiptRows = this.#db
        .prepare(this.#receiptSelect('', 'ORDER BY revision'))
        .all() as unknown as readonly ReceiptRow[];
      const auditRows = this.#db
        .prepare(this.#auditSelect('', 'ORDER BY revision'))
        .all() as unknown as readonly AuditRow[];
      if (receiptRows.length !== cursor.revision || auditRows.length !== cursor.revision) {
        errors.push('receipt or audit count differs from canonical revision');
      }

      let previousReceipt = GENESIS_RECEIPT_DIGEST;
      let previousChain = GENESIS_CHAIN_DIGEST;
      let previousFingerprint = GENESIS_CANONICAL_FINGERPRINT;
      let previousToSeq = 0;
      let previousCommittedAt = -1;
      for (let index = 0; index < receiptRows.length; index += 1) {
        const row = receiptRows[index];
        if (row === undefined) continue;
        try {
          const receipt = receiptFromRow(row);
          if (receipt.revision !== index + 1) {
            errors.push(`receipt revision gap at ${index + 1}`);
          }
          const auditRow = auditRows[index];
          if (auditRow === undefined) {
            errors.push(`audit is missing at revision ${receipt.revision}`);
          } else {
            this.#verifiedAudit(auditRow, receipt);
          }
          if (
            receipt.previousReceiptDigest !== previousReceipt ||
            receipt.baseChainDigest !== previousChain ||
            receipt.transition.baseFingerprint !== previousFingerprint ||
            receipt.appendFromSeq !== previousToSeq + 1 ||
            receipt.committedAt <= previousCommittedAt
          ) {
            errors.push(`receipt chain, fingerprint, or append range mismatch at revision ${receipt.revision}`);
          }
          const range = events.slice(receipt.appendFromSeq - 1, receipt.appendToSeq);
          const eventRows = this.#db
            .prepare(this.#eventSelect('WHERE seq BETWEEN ? AND ?', 'ORDER BY seq'))
            .all(receipt.appendFromSeq, receipt.appendToSeq) as unknown as readonly EventRow[];
          const revisionsMatch = eventRows.every(
            (eventRow, eventIndex) =>
              safeInteger(
                eventRow.revision,
                `receipt ${receipt.revision} event revision ${eventIndex + 1}`,
                1,
              ) === receipt.revision,
          );
          const tailRow = eventRows.at(-1);
          const tailChain =
            tailRow === undefined
              ? undefined
              : exactSqliteText(
                  tailRow.chain_digest,
                  tailRow.chain_digest_hex,
                  `receipt ${receipt.revision} tail chain digest`,
                );
          if (
            range.length !== receipt.appendToSeq - receipt.appendFromSeq + 1 ||
            eventRows.length !== range.length ||
            !revisionsMatch ||
            appendDigest(range) !== receipt.appendDigest ||
            canonicalDigest(range) !== receipt.transition.appendFingerprint ||
            tailChain !== receipt.afterChainDigest
          ) {
            errors.push(`receipt event range mismatch at revision ${receipt.revision}`);
          }
          previousReceipt = receipt.receiptDigest;
          previousChain = receipt.afterChainDigest;
          previousFingerprint = receipt.transition.afterFingerprint;
          previousToSeq = receipt.appendToSeq;
          previousCommittedAt = receipt.committedAt;
        } catch (error) {
          errors.push(
            error instanceof Error
              ? error.message
              : `receipt audit failed at revision ${String(row.revision)}`,
          );
        }
      }
      if (
        previousReceipt !== cursor.latestReceiptDigest ||
        previousChain !== cursor.chainDigest ||
        previousFingerprint !== cursor.canonicalFingerprint ||
        previousToSeq !== cursor.lastSeq
      ) {
        errors.push('receipt chain head differs from canonical metadata');
      }
      return Object.freeze({
        ok: errors.length === 0,
        errors: Object.freeze(errors),
        cursor,
        receiptCount: receiptRows.length,
      });
    });
  }

  close(): void {
    if (this.#closed) return;
    this.#db.close();
    this.#closed = true;
  }
}
