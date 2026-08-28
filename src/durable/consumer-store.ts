import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

import {
  CanonicalChangeFeed,
  assertCanonicalReadCursor,
  canonicalGenesisCursor,
  canonicalReadCursorDigest,
  sameCanonicalReadCursor,
  verifyCanonicalAppendBatch,
  type CanonicalAppendBatch,
  type CanonicalReadCursor,
} from './change-feed.js';

const CONSUMER_SCHEMA_VERSION = 1 as const;
const MAX_CONSUMER_ID_BYTES = 256;
const MAX_BUSY_TIMEOUT_MS = 60_000;
const MAX_PROJECTION_SQL_CHARACTERS = 100_000;
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const GENESIS_RECEIPT_DIGEST = contentDigest({ domain: 'cl-consumer-receipt-chain-genesis-v1' });

const TABLE_META = 'cl_consumer_meta';
const TABLE_REGISTRATIONS = 'cl_consumer_registrations';
const TABLE_CHECKPOINTS = 'cl_consumer_checkpoints';
const TABLE_RECEIPTS = 'cl_consumer_receipts';
const EXPECTED_TABLES = Object.freeze([
  TABLE_META,
  TABLE_REGISTRATIONS,
  TABLE_CHECKPOINTS,
  TABLE_RECEIPTS,
]);


const EXPECTED_TABLE_SQL: Readonly<Record<string, string>> = Object.freeze({
  [TABLE_META]: `
    CREATE TABLE ${TABLE_META} (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      schema_version INTEGER NOT NULL CHECK (schema_version = ${CONSUMER_SCHEMA_VERSION})
    ) STRICT
  `,
  [TABLE_REGISTRATIONS]: `
    CREATE TABLE ${TABLE_REGISTRATIONS} (
      consumer_id TEXT PRIMARY KEY,
      configuration_digest TEXT NOT NULL,
      initial_cursor_json TEXT NOT NULL,
      initial_cursor_digest TEXT NOT NULL,
      registered_at INTEGER NOT NULL CHECK (registered_at > 0),
      registration_digest TEXT NOT NULL UNIQUE
    ) STRICT
  `,
  [TABLE_CHECKPOINTS]: `
    CREATE TABLE ${TABLE_CHECKPOINTS} (
      consumer_id TEXT PRIMARY KEY REFERENCES ${TABLE_REGISTRATIONS}(consumer_id),
      configuration_digest TEXT NOT NULL,
      initial_cursor_digest TEXT NOT NULL,
      revision INTEGER NOT NULL CHECK (revision > 0),
      cursor_json TEXT NOT NULL,
      cursor_digest TEXT NOT NULL,
      last_batch_id TEXT NOT NULL,
      last_append_digest TEXT NOT NULL,
      latest_receipt_digest TEXT NOT NULL,
      updated_at INTEGER NOT NULL CHECK (updated_at > 0)
    ) STRICT
  `,
  [TABLE_RECEIPTS]: `
    CREATE TABLE ${TABLE_RECEIPTS} (
      consumer_id TEXT NOT NULL REFERENCES ${TABLE_REGISTRATIONS}(consumer_id),
      configuration_digest TEXT NOT NULL,
      initial_cursor_digest TEXT NOT NULL,
      revision INTEGER NOT NULL CHECK (revision > 0),
      batch_id TEXT NOT NULL,
      base_cursor_json TEXT NOT NULL,
      base_cursor_digest TEXT NOT NULL,
      after_cursor_json TEXT NOT NULL,
      after_cursor_digest TEXT NOT NULL,
      append_digest TEXT NOT NULL,
      previous_receipt_digest TEXT NOT NULL,
      receipt_digest TEXT NOT NULL UNIQUE,
      applied_at INTEGER NOT NULL CHECK (applied_at > 0),
      PRIMARY KEY (consumer_id, revision),
      UNIQUE (consumer_id, batch_id)
    ) STRICT
  `,
});

function normalizeSql(value: string): string {
  return value.replace(/\s+/g, ' ').trim().toLowerCase();
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

function contentDigest(value: unknown): string {
  return `sha256:${createHash('sha256').update(stableJson(value)).digest('hex')}`;
}

function assertDigest(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || !SHA256_PATTERN.test(value)) {
    throw new Error(`${label} must be a SHA-256 content address`);
  }
}

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function assertSqliteText(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
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

function assertExactSqliteText(
  value: unknown,
  hex: unknown,
  label: string,
): asserts value is string {
  if (!hasExactSqliteText(value, hex)) {
    throw new Error(`${label} has a non-canonical SQLite text encoding`);
  }
}

function assertSafePositiveInteger(value: unknown, label: string): asserts value is number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
}

function assertSqliteInteger(
  value: unknown,
  storageClass: unknown,
  label: string,
  options: { readonly allowZero?: boolean } = {},
): asserts value is number {
  if (
    storageClass !== 'integer' ||
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < (options.allowZero === true ? 0 : 1)
  ) {
    throw new Error(`${label} must be stored as a canonical SQLite integer`);
  }
}

function validateConsumerId(consumerId: unknown): asserts consumerId is string {
  assertSqliteText(consumerId, 'consumerId');
  if (consumerId !== consumerId.trim()) {
    throw new Error('consumerId cannot contain leading or trailing whitespace');
  }
  if (new TextEncoder().encode(consumerId).length > MAX_CONSUMER_ID_BYTES) {
    throw new Error(`consumerId cannot exceed ${MAX_CONSUMER_ID_BYTES} UTF-8 bytes`);
  }
}

function validateConfigurationDigest(value: unknown): asserts value is string {
  assertDigest(value, 'consumer configuration digest');
}

function parseCanonicalCursorJson(value: string, label: string): CanonicalReadCursor {
  let cursor: CanonicalReadCursor;
  try {
    cursor = JSON.parse(value) as CanonicalReadCursor;
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
  if (stableJson(cursor) !== value) throw new Error(`${label} is not canonical JSON`);
  assertCanonicalReadCursor(cursor);
  return Object.freeze(cursor);
}

function registrationPayload(
  registration: Omit<DurableConsumerRegistration, 'registrationDigest'>,
): unknown {
  return { domain: 'cl-consumer-registration-v1', ...registration };
}

function receiptPayload(receipt: Omit<DurableConsumerReceipt, 'receiptDigest'>): unknown {
  return { domain: 'cl-consumer-receipt-v1', ...receipt };
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

export interface ConsumerRegistrationRequest {
  readonly consumerId: string;
  /** Binds projection schema, code/configuration, privacy policy, and rendering semantics. */
  readonly configurationDigest: string;
  /** Explicit completeness boundary. Genesis replays history; a tail cursor intentionally skips it. */
  readonly initialCursor: CanonicalReadCursor;
  readonly registeredAt?: number;
}

export interface ConsumerBinding {
  readonly consumerId: string;
  readonly configurationDigest: string;
}

export interface DurableConsumerRegistration {
  readonly schemaVersion: typeof CONSUMER_SCHEMA_VERSION;
  readonly consumerId: string;
  readonly configurationDigest: string;
  readonly initialCursor: CanonicalReadCursor;
  readonly initialCursorDigest: string;
  readonly registeredAt: number;
  readonly registrationDigest: string;
}

export interface DurableConsumerCheckpoint {
  readonly schemaVersion: typeof CONSUMER_SCHEMA_VERSION;
  readonly consumerId: string;
  readonly configurationDigest: string;
  readonly initialCursorDigest: string;
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
  readonly configurationDigest: string;
  readonly initialCursorDigest: string;
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
  readonly registration?: DurableConsumerRegistration;
  readonly checkpoint?: DurableConsumerCheckpoint;
  readonly receiptCount: number;
}

export type ConsumerSqlParameter = string | number | bigint | null;

export interface ConsumerProjectionTransaction {
  run(sql: string, ...params: readonly ConsumerSqlParameter[]): unknown;
  get(sql: string, ...params: readonly ConsumerSqlParameter[]): unknown;
  all(sql: string, ...params: readonly ConsumerSqlParameter[]): readonly unknown[];
}

export type TrustedConsumerTransaction<T> = (
  transaction: ConsumerProjectionTransaction,
  batch: CanonicalAppendBatch,
) => T;

interface RegistrationRow {
  readonly consumer_id: unknown;
  readonly consumer_id_hex: unknown;
  readonly configuration_digest: unknown;
  readonly configuration_digest_hex: unknown;
  readonly initial_cursor_json: unknown;
  readonly initial_cursor_json_hex: unknown;
  readonly initial_cursor_digest: unknown;
  readonly initial_cursor_digest_hex: unknown;
  readonly registered_at: unknown;
  readonly registered_at_type: unknown;
  readonly registration_digest: unknown;
  readonly registration_digest_hex: unknown;
}

interface CheckpointRow {
  readonly consumer_id: unknown;
  readonly consumer_id_hex: unknown;
  readonly configuration_digest: unknown;
  readonly configuration_digest_hex: unknown;
  readonly initial_cursor_digest: unknown;
  readonly initial_cursor_digest_hex: unknown;
  readonly revision: unknown;
  readonly revision_type: unknown;
  readonly cursor_json: unknown;
  readonly cursor_json_hex: unknown;
  readonly cursor_digest: unknown;
  readonly cursor_digest_hex: unknown;
  readonly last_batch_id: unknown;
  readonly last_batch_id_hex: unknown;
  readonly last_append_digest: unknown;
  readonly last_append_digest_hex: unknown;
  readonly latest_receipt_digest: unknown;
  readonly latest_receipt_digest_hex: unknown;
  readonly updated_at: unknown;
  readonly updated_at_type: unknown;
}

interface ReceiptRow {
  readonly consumer_id: unknown;
  readonly consumer_id_hex: unknown;
  readonly configuration_digest: unknown;
  readonly configuration_digest_hex: unknown;
  readonly initial_cursor_digest: unknown;
  readonly initial_cursor_digest_hex: unknown;
  readonly revision: unknown;
  readonly revision_type: unknown;
  readonly batch_id: unknown;
  readonly batch_id_hex: unknown;
  readonly base_cursor_json: unknown;
  readonly base_cursor_json_hex: unknown;
  readonly base_cursor_digest: unknown;
  readonly base_cursor_digest_hex: unknown;
  readonly after_cursor_json: unknown;
  readonly after_cursor_json_hex: unknown;
  readonly after_cursor_digest: unknown;
  readonly after_cursor_digest_hex: unknown;
  readonly append_digest: unknown;
  readonly append_digest_hex: unknown;
  readonly previous_receipt_digest: unknown;
  readonly previous_receipt_digest_hex: unknown;
  readonly receipt_digest: unknown;
  readonly receipt_digest_hex: unknown;
  readonly applied_at: unknown;
  readonly applied_at_type: unknown;
}

const REGISTRATION_SELECT = `
  SELECT consumer_id,
         hex(consumer_id) AS consumer_id_hex,
         configuration_digest,
         hex(configuration_digest) AS configuration_digest_hex,
         initial_cursor_json,
         hex(initial_cursor_json) AS initial_cursor_json_hex,
         initial_cursor_digest,
         hex(initial_cursor_digest) AS initial_cursor_digest_hex,
         registered_at,
         typeof(registered_at) AS registered_at_type,
         registration_digest,
         hex(registration_digest) AS registration_digest_hex
    FROM ${TABLE_REGISTRATIONS}
`;

const CHECKPOINT_SELECT = `
  SELECT consumer_id,
         hex(consumer_id) AS consumer_id_hex,
         configuration_digest,
         hex(configuration_digest) AS configuration_digest_hex,
         initial_cursor_digest,
         hex(initial_cursor_digest) AS initial_cursor_digest_hex,
         revision,
         typeof(revision) AS revision_type,
         cursor_json,
         hex(cursor_json) AS cursor_json_hex,
         cursor_digest,
         hex(cursor_digest) AS cursor_digest_hex,
         last_batch_id,
         hex(last_batch_id) AS last_batch_id_hex,
         last_append_digest,
         hex(last_append_digest) AS last_append_digest_hex,
         latest_receipt_digest,
         hex(latest_receipt_digest) AS latest_receipt_digest_hex,
         updated_at,
         typeof(updated_at) AS updated_at_type
    FROM ${TABLE_CHECKPOINTS}
`;

const RECEIPT_SELECT = `
  SELECT consumer_id,
         hex(consumer_id) AS consumer_id_hex,
         configuration_digest,
         hex(configuration_digest) AS configuration_digest_hex,
         initial_cursor_digest,
         hex(initial_cursor_digest) AS initial_cursor_digest_hex,
         revision,
         typeof(revision) AS revision_type,
         batch_id,
         hex(batch_id) AS batch_id_hex,
         base_cursor_json,
         hex(base_cursor_json) AS base_cursor_json_hex,
         base_cursor_digest,
         hex(base_cursor_digest) AS base_cursor_digest_hex,
         after_cursor_json,
         hex(after_cursor_json) AS after_cursor_json_hex,
         after_cursor_digest,
         hex(after_cursor_digest) AS after_cursor_digest_hex,
         append_digest,
         hex(append_digest) AS append_digest_hex,
         previous_receipt_digest,
         hex(previous_receipt_digest) AS previous_receipt_digest_hex,
         receipt_digest,
         hex(receipt_digest) AS receipt_digest_hex,
         applied_at,
         typeof(applied_at) AS applied_at_type
    FROM ${TABLE_RECEIPTS}
`;

function registrationFromRow(row: RegistrationRow): DurableConsumerRegistration {
  assertExactSqliteText(row.consumer_id, row.consumer_id_hex, 'consumer registration id');
  assertExactSqliteText(
    row.configuration_digest,
    row.configuration_digest_hex,
    'consumer registration configuration digest',
  );
  assertExactSqliteText(
    row.initial_cursor_json,
    row.initial_cursor_json_hex,
    'consumer registration initial cursor',
  );
  assertExactSqliteText(
    row.initial_cursor_digest,
    row.initial_cursor_digest_hex,
    'consumer registration initial cursor digest',
  );
  assertExactSqliteText(
    row.registration_digest,
    row.registration_digest_hex,
    'consumer registration digest',
  );
  assertSqliteInteger(row.registered_at, row.registered_at_type, 'consumer registeredAt');

  validateConsumerId(row.consumer_id);
  validateConfigurationDigest(row.configuration_digest);
  assertDigest(row.initial_cursor_digest, 'consumer initial cursor digest');
  assertDigest(row.registration_digest, 'consumer registration digest');
  const initialCursor = parseCanonicalCursorJson(
    row.initial_cursor_json,
    'consumer registration initial cursor',
  );
  if (canonicalReadCursorDigest(initialCursor) !== row.initial_cursor_digest) {
    throw new Error('consumer registration initial cursor digest is invalid');
  }
  const unsigned = Object.freeze({
    schemaVersion: CONSUMER_SCHEMA_VERSION,
    consumerId: row.consumer_id,
    configurationDigest: row.configuration_digest,
    initialCursor,
    initialCursorDigest: row.initial_cursor_digest,
    registeredAt: row.registered_at,
  });
  if (contentDigest(registrationPayload(unsigned)) !== row.registration_digest) {
    throw new Error('consumer registration digest is invalid');
  }
  return Object.freeze({ ...unsigned, registrationDigest: row.registration_digest });
}

function checkpointFromRow(row: CheckpointRow): DurableConsumerCheckpoint {
  assertExactSqliteText(row.consumer_id, row.consumer_id_hex, 'consumer checkpoint id');
  const consumerId = row.consumer_id;
  assertExactSqliteText(
    row.configuration_digest,
    row.configuration_digest_hex,
    'consumer checkpoint configuration',
  );
  const configurationDigest = row.configuration_digest;
  assertExactSqliteText(
    row.initial_cursor_digest,
    row.initial_cursor_digest_hex,
    'consumer checkpoint initial cursor',
  );
  const initialCursorDigest = row.initial_cursor_digest;
  assertExactSqliteText(row.cursor_json, row.cursor_json_hex, 'consumer checkpoint cursor');
  const cursorJson = row.cursor_json;
  assertExactSqliteText(
    row.cursor_digest,
    row.cursor_digest_hex,
    'consumer checkpoint cursor digest',
  );
  const storedCursorDigest = row.cursor_digest;
  assertExactSqliteText(row.last_batch_id, row.last_batch_id_hex, 'consumer checkpoint batch id');
  const lastBatchId = row.last_batch_id;
  assertExactSqliteText(
    row.last_append_digest,
    row.last_append_digest_hex,
    'consumer checkpoint append digest',
  );
  const lastAppendDigest = row.last_append_digest;
  assertExactSqliteText(
    row.latest_receipt_digest,
    row.latest_receipt_digest_hex,
    'consumer checkpoint receipt digest',
  );
  const latestReceiptDigest = row.latest_receipt_digest;
  assertSqliteInteger(row.revision, row.revision_type, 'consumer checkpoint revision');
  const revision = row.revision;
  assertSqliteInteger(row.updated_at, row.updated_at_type, 'consumer checkpoint updatedAt');
  const updatedAt = row.updated_at;
  validateConsumerId(consumerId);
  validateConfigurationDigest(configurationDigest);
  for (const [value, label] of [
    [initialCursorDigest, 'consumer checkpoint initial cursor digest'],
    [storedCursorDigest, 'consumer checkpoint cursor digest'],
    [lastBatchId, 'consumer checkpoint batch id'],
    [lastAppendDigest, 'consumer checkpoint append digest'],
    [latestReceiptDigest, 'consumer checkpoint receipt digest'],
  ] as const) {
    assertDigest(value, label);
  }
  const cursor = parseCanonicalCursorJson(cursorJson, 'consumer checkpoint cursor');
  if (canonicalReadCursorDigest(cursor) !== storedCursorDigest) {
    throw new Error('consumer checkpoint cursor digest is invalid');
  }
  return Object.freeze({
    schemaVersion: CONSUMER_SCHEMA_VERSION,
    consumerId,
    configurationDigest,
    initialCursorDigest,
    revision,
    cursor,
    cursorDigest: storedCursorDigest,
    lastBatchId,
    lastAppendDigest,
    latestReceiptDigest,
    updatedAt,
  });
}
function receiptFromRow(row: ReceiptRow): DurableConsumerReceipt {
  assertExactSqliteText(row.consumer_id, row.consumer_id_hex, 'consumer receipt id');
  const consumerId = row.consumer_id;
  assertExactSqliteText(
    row.configuration_digest,
    row.configuration_digest_hex,
    'consumer receipt configuration',
  );
  const configurationDigest = row.configuration_digest;
  assertExactSqliteText(
    row.initial_cursor_digest,
    row.initial_cursor_digest_hex,
    'consumer receipt initial cursor',
  );
  const initialCursorDigest = row.initial_cursor_digest;
  assertExactSqliteText(row.batch_id, row.batch_id_hex, 'consumer receipt batch id');
  const batchId = row.batch_id;
  assertExactSqliteText(row.base_cursor_json, row.base_cursor_json_hex, 'consumer receipt base cursor');
  const baseCursorJson = row.base_cursor_json;
  assertExactSqliteText(
    row.base_cursor_digest,
    row.base_cursor_digest_hex,
    'consumer receipt base digest',
  );
  const baseDigest = row.base_cursor_digest;
  assertExactSqliteText(row.after_cursor_json, row.after_cursor_json_hex, 'consumer receipt after cursor');
  const afterCursorJson = row.after_cursor_json;
  assertExactSqliteText(
    row.after_cursor_digest,
    row.after_cursor_digest_hex,
    'consumer receipt after digest',
  );
  const afterDigest = row.after_cursor_digest;
  assertExactSqliteText(row.append_digest, row.append_digest_hex, 'consumer receipt append digest');
  const appendDigest = row.append_digest;
  assertExactSqliteText(
    row.previous_receipt_digest,
    row.previous_receipt_digest_hex,
    'consumer previous receipt digest',
  );
  const previousReceiptDigest = row.previous_receipt_digest;
  assertExactSqliteText(row.receipt_digest, row.receipt_digest_hex, 'consumer receipt digest');
  const storedReceiptDigest = row.receipt_digest;
  assertSqliteInteger(row.revision, row.revision_type, 'consumer receipt revision');
  const revision = row.revision;
  assertSqliteInteger(row.applied_at, row.applied_at_type, 'consumer receipt appliedAt');
  const appliedAt = row.applied_at;
  validateConsumerId(consumerId);
  validateConfigurationDigest(configurationDigest);
  for (const [value, label] of [
    [initialCursorDigest, 'consumer receipt initial cursor digest'],
    [batchId, 'consumer receipt batch id'],
    [baseDigest, 'consumer receipt base digest'],
    [afterDigest, 'consumer receipt after digest'],
    [appendDigest, 'consumer receipt append digest'],
    [previousReceiptDigest, 'consumer receipt previous digest'],
    [storedReceiptDigest, 'consumer receipt digest'],
  ] as const) {
    assertDigest(value, label);
  }
  const base = parseCanonicalCursorJson(baseCursorJson, 'consumer receipt base cursor');
  const after = parseCanonicalCursorJson(afterCursorJson, 'consumer receipt after cursor');
  if (
    canonicalReadCursorDigest(base) !== baseDigest ||
    canonicalReadCursorDigest(after) !== afterDigest
  ) {
    throw new Error(`consumer receipt cursor integrity failed at revision ${revision}`);
  }
  const unsigned: Omit<DurableConsumerReceipt, 'receiptDigest'> = Object.freeze({
    schemaVersion: CONSUMER_SCHEMA_VERSION,
    consumerId,
    configurationDigest,
    initialCursorDigest,
    revision,
    batchId,
    base,
    baseDigest,
    after,
    afterDigest,
    appendDigest,
    previousReceiptDigest,
    appliedAt,
  });
  if (contentDigest(receiptPayload(unsigned)) !== storedReceiptDigest) {
    throw new Error(`consumer receipt digest failed at revision ${revision}`);
  }
  return Object.freeze({ ...unsigned, receiptDigest: storedReceiptDigest });
}

function validateProjectionSql(sql: unknown, mode: 'run' | 'read'): asserts sql is string {
  if (typeof sql !== 'string' || sql.trim().length === 0) {
    throw new Error('projection SQL must be a non-empty string');
  }
  if (sql.length > MAX_PROJECTION_SQL_CHARACTERS) {
    throw new Error(`projection SQL cannot exceed ${MAX_PROJECTION_SQL_CHARACTERS} characters`);
  }
  if (sql.includes('\u0000') || !isWellFormedUnicode(sql)) {
    throw new Error('projection SQL must be well-formed text without U+0000');
  }
  if (sql.includes('--') || sql.includes('/*') || sql.includes('*/')) {
    throw new Error('projection SQL comments are not allowed; bind data as parameters');
  }
  const trimmed = sql.trim();
  const withoutTrailing = trimmed.endsWith(';') ? trimmed.slice(0, -1).trim() : trimmed;
  if (withoutTrailing.includes(';')) {
    throw new Error('projection SQL must contain exactly one statement');
  }
  const normalized = withoutTrailing.toLowerCase();
  const firstKeyword = normalized.match(/^([a-z]+)/)?.[1] ?? '';
  if (
    new Set([
      'begin',
      'commit',
      'end',
      'rollback',
      'savepoint',
      'release',
      'attach',
      'detach',
      'pragma',
      'vacuum',
      'reindex',
    ]).has(firstKeyword)
  ) {
    throw new Error('projection SQL cannot control transactions, attachments, or connection PRAGMAs');
  }
  if (
    normalized.includes('cl_consumer_') ||
    normalized.includes('pragma_') ||
    /\bsqlite_(master|schema|temp_master|temp_schema|dbpage|dbdata|dbptr)\b/.test(normalized) ||
    /\b(dbstat|load_extension|writefile|readfile|eval)\s*\(/.test(normalized)
  ) {
    throw new Error('projection SQL cannot access consumer-owned or SQLite catalog state');
  }
  if (/^create\s+virtual\s+table\b/.test(normalized) && !/\busing\s+fts5\b/.test(normalized)) {
    throw new Error('projection virtual tables are restricted to the built-in FTS5 module');
  }
  if (mode === 'read' && !/^(select|explain)\b/.test(normalized)) {
    throw new Error('projection read SQL must begin with SELECT or EXPLAIN');
  }
}

function validateSqlParameters(params: readonly ConsumerSqlParameter[]): void {
  for (const value of params) {
    if (typeof value === 'number' && (!Number.isFinite(value) || Object.is(value, -0))) {
      throw new Error('projection SQL parameters must contain canonical finite numbers');
    }
    if (typeof value === 'string' && (value.includes('\u0000') || !isWellFormedUnicode(value))) {
      throw new Error('projection SQL string parameters must be well-formed and cannot contain U+0000');
    }
  }
}

function expectedColumns(): Readonly<
  Record<string, readonly (readonly [string, string, number, number])[]>
> {
  const columns = {
    [TABLE_META]: [
      ['id', 'INTEGER', 0, 1],
      ['schema_version', 'INTEGER', 1, 0],
    ],
    [TABLE_REGISTRATIONS]: [
      ['consumer_id', 'TEXT', 1, 1],
      ['configuration_digest', 'TEXT', 1, 0],
      ['initial_cursor_json', 'TEXT', 1, 0],
      ['initial_cursor_digest', 'TEXT', 1, 0],
      ['registered_at', 'INTEGER', 1, 0],
      ['registration_digest', 'TEXT', 1, 0],
    ],
    [TABLE_CHECKPOINTS]: [
      ['consumer_id', 'TEXT', 1, 1],
      ['configuration_digest', 'TEXT', 1, 0],
      ['initial_cursor_digest', 'TEXT', 1, 0],
      ['revision', 'INTEGER', 1, 0],
      ['cursor_json', 'TEXT', 1, 0],
      ['cursor_digest', 'TEXT', 1, 0],
      ['last_batch_id', 'TEXT', 1, 0],
      ['last_append_digest', 'TEXT', 1, 0],
      ['latest_receipt_digest', 'TEXT', 1, 0],
      ['updated_at', 'INTEGER', 1, 0],
    ],
    [TABLE_RECEIPTS]: [
      ['consumer_id', 'TEXT', 1, 1],
      ['configuration_digest', 'TEXT', 1, 0],
      ['initial_cursor_digest', 'TEXT', 1, 0],
      ['revision', 'INTEGER', 1, 2],
      ['batch_id', 'TEXT', 1, 0],
      ['base_cursor_json', 'TEXT', 1, 0],
      ['base_cursor_digest', 'TEXT', 1, 0],
      ['after_cursor_json', 'TEXT', 1, 0],
      ['after_cursor_digest', 'TEXT', 1, 0],
      ['append_digest', 'TEXT', 1, 0],
      ['previous_receipt_digest', 'TEXT', 1, 0],
      ['receipt_digest', 'TEXT', 1, 0],
      ['applied_at', 'INTEGER', 1, 0],
    ],
  } as const satisfies Readonly<
    Record<string, readonly (readonly [string, string, number, number])[]>
  >;
  return columns;
}
/**
 * Durable projection-consumer registry, receipt chain, and checkpoint store.
 *
 * Projection mutations execute on the same SQLite connection and transaction as the consumer
 * receipt/checkpoint update. The callback is trusted but cannot modify this store's own tables,
 * connection invariants, or schema without causing a rollback.
 */
export class SqliteConsumerCheckpointStore {
  readonly #db: DatabaseSync;
  readonly #faultInjector: ConsumerCheckpointStoreOptions['faultInjector'];
  readonly #fileDatabase: boolean;
  #closed = false;
  #applying = false;

  constructor(options: ConsumerCheckpointStoreOptions = {}) {
    const timeout = options.busyTimeoutMs ?? 5_000;
    if (!Number.isSafeInteger(timeout) || timeout < 0 || timeout > MAX_BUSY_TIMEOUT_MS) {
      throw new RangeError(`busyTimeoutMs must be an integer in [0, ${MAX_BUSY_TIMEOUT_MS}]`);
    }
    this.#faultInjector = options.faultInjector;
    const location = options.database ?? ':memory:';
    this.#fileDatabase = location !== ':memory:';
    this.#db = new DatabaseSync(location);
    this.#db.exec('PRAGMA trusted_schema = OFF');
    this.#db.exec('PRAGMA foreign_keys = ON');
    this.#db.exec(`PRAGMA busy_timeout = ${timeout}`);
    this.#db.exec('PRAGMA synchronous = FULL');
    if (this.#fileDatabase) this.#db.exec('PRAGMA journal_mode = WAL');
    this.#initializeSchema();
    this.#assertConnectionInvariants();
    this.#assertSchema();
  }

  #assertOpen(): void {
    if (this.#closed) throw new Error('consumer checkpoint store is closed');
  }

  #assertNotApplying(action: string): void {
    if (this.#applying) {
      throw new Error(`consumer checkpoint ${action} is not allowed during an active projection transaction`);
    }
  }

  #projectionTransaction(): ConsumerProjectionTransaction {
    const database = this.#db;
    return Object.freeze({
      run(sql: string, ...params: readonly ConsumerSqlParameter[]): unknown {
        validateProjectionSql(sql, 'run');
        validateSqlParameters(params);
        return database.prepare(sql).run(...params);
      },
      get(sql: string, ...params: readonly ConsumerSqlParameter[]): unknown {
        validateProjectionSql(sql, 'read');
        validateSqlParameters(params);
        return database.prepare(sql).get(...params);
      },
      all(sql: string, ...params: readonly ConsumerSqlParameter[]): readonly unknown[] {
        validateProjectionSql(sql, 'read');
        validateSqlParameters(params);
        return database.prepare(sql).all(...params);
      },
    });
  }

  #inject(point: ConsumerCheckpointFaultPoint): void {
    this.#faultInjector?.(point);
  }

  #transaction<T>(mode: 'read' | 'write', operation: () => T): T {
    this.#assertOpen();
    this.#db.exec(mode === 'write' ? 'BEGIN IMMEDIATE' : 'BEGIN');
    try {
      const result = operation();
      if (!this.#db.isTransaction) {
        throw new Error('consumer transaction was ended by the projection callback');
      }
      this.#db.exec('COMMIT');
      return result;
    } catch (error) {
      try {
        if (this.#db.isTransaction) this.#db.exec('ROLLBACK');
      } catch {
        // Preserve the original failure.
      }
      throw error;
    }
  }

  #readIntegerPragma(name: string): number {
    const row = this.#db.prepare(`PRAGMA ${name}`).get() as Record<string, unknown> | undefined;
    const value = row === undefined ? undefined : Object.values(row)[0];
    if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
      throw new Error(`consumer checkpoint PRAGMA ${name} is not a canonical integer`);
    }
    return value;
  }

  #readTextPragma(name: string): string {
    const row = this.#db.prepare(`PRAGMA ${name}`).get() as Record<string, unknown> | undefined;
    const value = row === undefined ? undefined : Object.values(row)[0];
    if (typeof value !== 'string') {
      throw new Error(`consumer checkpoint PRAGMA ${name} is not text`);
    }
    return value.toLowerCase();
  }

  #assertConnectionInvariants(): void {
    if (this.#readIntegerPragma('trusted_schema') !== 0) {
      throw new Error('consumer checkpoint connection requires trusted_schema = OFF');
    }
    if (this.#readIntegerPragma('foreign_keys') !== 1) {
      throw new Error('consumer checkpoint connection requires foreign_keys = ON');
    }
    if (this.#readIntegerPragma('synchronous') !== 2) {
      throw new Error('consumer checkpoint connection requires synchronous = FULL');
    }
    if (this.#fileDatabase && this.#readTextPragma('journal_mode') !== 'wal') {
      throw new Error('file-backed consumer checkpoint store requires WAL journal mode');
    }
  }

  #initializeSchema(): void {
    const existingRows = this.#db
      .prepare(`
        SELECT name
          FROM sqlite_master
         WHERE type = 'table' AND name GLOB 'cl_consumer_*'
         ORDER BY name
      `)
      .all() as unknown as readonly { readonly name: unknown }[];
    const existingNames = existingRows.map((row) => row.name);
    if (
      existingNames.length !== 0 &&
      (existingNames.length !== EXPECTED_TABLES.length ||
        existingNames.some((name, index) => name !== [...EXPECTED_TABLES].sort()[index]))
    ) {
      throw new Error('consumer checkpoint schema is partially present or contains unexpected tables');
    }

    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS ${TABLE_META} (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        schema_version INTEGER NOT NULL CHECK (schema_version = ${CONSUMER_SCHEMA_VERSION})
      ) STRICT;

      CREATE TABLE IF NOT EXISTS ${TABLE_REGISTRATIONS} (
        consumer_id TEXT PRIMARY KEY,
        configuration_digest TEXT NOT NULL,
        initial_cursor_json TEXT NOT NULL,
        initial_cursor_digest TEXT NOT NULL,
        registered_at INTEGER NOT NULL CHECK (registered_at > 0),
        registration_digest TEXT NOT NULL UNIQUE
      ) STRICT;

      CREATE TABLE IF NOT EXISTS ${TABLE_CHECKPOINTS} (
        consumer_id TEXT PRIMARY KEY REFERENCES ${TABLE_REGISTRATIONS}(consumer_id),
        configuration_digest TEXT NOT NULL,
        initial_cursor_digest TEXT NOT NULL,
        revision INTEGER NOT NULL CHECK (revision > 0),
        cursor_json TEXT NOT NULL,
        cursor_digest TEXT NOT NULL,
        last_batch_id TEXT NOT NULL,
        last_append_digest TEXT NOT NULL,
        latest_receipt_digest TEXT NOT NULL,
        updated_at INTEGER NOT NULL CHECK (updated_at > 0)
      ) STRICT;

      CREATE TABLE IF NOT EXISTS ${TABLE_RECEIPTS} (
        consumer_id TEXT NOT NULL REFERENCES ${TABLE_REGISTRATIONS}(consumer_id),
        configuration_digest TEXT NOT NULL,
        initial_cursor_digest TEXT NOT NULL,
        revision INTEGER NOT NULL CHECK (revision > 0),
        batch_id TEXT NOT NULL,
        base_cursor_json TEXT NOT NULL,
        base_cursor_digest TEXT NOT NULL,
        after_cursor_json TEXT NOT NULL,
        after_cursor_digest TEXT NOT NULL,
        append_digest TEXT NOT NULL,
        previous_receipt_digest TEXT NOT NULL,
        receipt_digest TEXT NOT NULL UNIQUE,
        applied_at INTEGER NOT NULL CHECK (applied_at > 0),
        PRIMARY KEY (consumer_id, revision),
        UNIQUE (consumer_id, batch_id)
      ) STRICT;
    `);
    const meta = this.#db
      .prepare(`SELECT schema_version, typeof(schema_version) AS storage_type FROM ${TABLE_META} WHERE id = 1`)
      .get() as { readonly schema_version: unknown; readonly storage_type: unknown } | undefined;
    if (meta === undefined) {
      this.#db
        .prepare(`INSERT INTO ${TABLE_META} (id, schema_version) VALUES (1, ?)`)
        .run(CONSUMER_SCHEMA_VERSION);
    } else if (
      meta.storage_type !== 'integer' ||
      meta.schema_version !== CONSUMER_SCHEMA_VERSION
    ) {
      throw new Error(`unsupported consumer checkpoint schema version: ${String(meta.schema_version)}`);
    }
  }

  #assertSchema(): void {
    const tables = this.#db
      .prepare(`
        SELECT name
          FROM sqlite_master
         WHERE type = 'table' AND name GLOB 'cl_consumer_*'
         ORDER BY name
      `)
      .all() as unknown as readonly { readonly name: unknown }[];
    const actual = tables.map((row) => row.name);
    if (
      actual.length !== EXPECTED_TABLES.length ||
      actual.some((name, index) => name !== [...EXPECTED_TABLES].sort()[index])
    ) {
      throw new Error('consumer checkpoint schema contains missing or unexpected tables');
    }

    const tableDefinitions = this.#db
      .prepare(`
        SELECT name, sql
          FROM sqlite_master
         WHERE type = 'table' AND name GLOB 'cl_consumer_*'
         ORDER BY name
      `)
      .all() as unknown as readonly { readonly name: unknown; readonly sql: unknown }[];
    for (const row of tableDefinitions) {
      if (typeof row.name !== 'string' || typeof row.sql !== 'string') {
        throw new Error('consumer checkpoint table definition is malformed');
      }
      const expectedSql = EXPECTED_TABLE_SQL[row.name];
      if (expectedSql === undefined || normalizeSql(row.sql) !== normalizeSql(expectedSql)) {
        throw new Error(`consumer checkpoint table ${row.name} definition is incompatible`);
      }
    }

    const dangerous = this.#db
      .prepare(`
        SELECT type, name, tbl_name
          FROM sqlite_master
         WHERE (type IN ('trigger', 'view') AND (name GLOB 'cl_consumer_*' OR tbl_name GLOB 'cl_consumer_*'))
            OR (type = 'index' AND tbl_name GLOB 'cl_consumer_*' AND sql IS NOT NULL)
      `)
      .all() as readonly unknown[];
    if (dangerous.length !== 0) {
      throw new Error('consumer checkpoint schema contains unexpected triggers, views, or indexes');
    }

    const expected = expectedColumns();
    for (const table of EXPECTED_TABLES) {
      const list = this.#db
        .prepare('PRAGMA table_list')
        .all() as unknown as readonly Record<string, unknown>[];
      const descriptor = list.find((row) => row['name'] === table);
      if (descriptor?.['strict'] !== 1) {
        throw new Error(`consumer checkpoint table ${table} must be STRICT`);
      }
      const columns = this.#db
        .prepare(`PRAGMA table_info(${table})`)
        .all() as unknown as readonly Record<string, unknown>[];
      const specification = expected[table] ?? [];
      if (columns.length !== specification.length) {
        throw new Error(`consumer checkpoint table ${table} has an unexpected column count`);
      }
      for (let index = 0; index < specification.length; index += 1) {
        const [name, type, notNull, primaryKey] = specification[index] as readonly [
          string,
          string,
          number,
          number,
        ];
        const column = columns[index];
        if (
          column?.['name'] !== name ||
          column['type'] !== type ||
          column['notnull'] !== notNull ||
          column['pk'] !== primaryKey
        ) {
          throw new Error(`consumer checkpoint table ${table} column ${name} is incompatible`);
        }
      }
    }
  }

  #assertOperationalBoundary(): void {
    this.#assertConnectionInvariants();
    this.#assertSchema();
  }

  #registrationRow(consumerId: string): RegistrationRow | undefined {
    return this.#db
      .prepare(`${REGISTRATION_SELECT} WHERE consumer_id = ?`)
      .get(consumerId) as RegistrationRow | undefined;
  }

  #checkpointRow(consumerId: string): CheckpointRow | undefined {
    return this.#db
      .prepare(`${CHECKPOINT_SELECT} WHERE consumer_id = ?`)
      .get(consumerId) as CheckpointRow | undefined;
  }

  #receiptRow(consumerId: string, batchId: string): ReceiptRow | undefined {
    return this.#db
      .prepare(`${RECEIPT_SELECT} WHERE consumer_id = ? AND batch_id = ?`)
      .get(consumerId, batchId) as ReceiptRow | undefined;
  }


  #registrationFor(binding: ConsumerBinding): DurableConsumerRegistration {
    validateConsumerId(binding.consumerId);
    validateConfigurationDigest(binding.configurationDigest);
    const row = this.#registrationRow(binding.consumerId);
    if (row === undefined) throw new Error(`consumer is not registered: ${binding.consumerId}`);
    const registration = registrationFromRow(row);
    if (registration.configurationDigest !== binding.configurationDigest) {
      throw new Error('consumer configuration digest differs from its durable registration');
    }
    return registration;
  }

  register(request: ConsumerRegistrationRequest): DurableConsumerRegistration {
    this.#assertNotApplying('register');
    validateConsumerId(request.consumerId);
    validateConfigurationDigest(request.configurationDigest);
    assertCanonicalReadCursor(request.initialCursor);
    if (request.registeredAt !== undefined) {
      assertSafePositiveInteger(request.registeredAt, 'consumer registeredAt');
    }
    const initialCursor = Object.freeze(
      JSON.parse(stableJson(request.initialCursor)) as CanonicalReadCursor,
    );
    const initialCursorDigest = canonicalReadCursorDigest(initialCursor);

    return this.#transaction('write', () => {
      this.#assertOperationalBoundary();
      const existingRow = this.#registrationRow(request.consumerId);
      if (existingRow !== undefined) {
        const existing = registrationFromRow(existingRow);
        if (
          existing.configurationDigest !== request.configurationDigest ||
          existing.initialCursorDigest !== initialCursorDigest ||
          !sameCanonicalReadCursor(existing.initialCursor, initialCursor) ||
          (request.registeredAt !== undefined && existing.registeredAt !== request.registeredAt)
        ) {
          throw new Error('consumer is already registered with different durable configuration');
        }
        return existing;
      }

      const registeredAt = request.registeredAt ?? Date.now();
      assertSafePositiveInteger(registeredAt, 'consumer registeredAt');
      const unsigned = Object.freeze({
        schemaVersion: CONSUMER_SCHEMA_VERSION,
        consumerId: request.consumerId,
        configurationDigest: request.configurationDigest,
        initialCursor,
        initialCursorDigest,
        registeredAt,
      });
      const registration = Object.freeze({
        ...unsigned,
        registrationDigest: contentDigest(registrationPayload(unsigned)),
      });
      this.#db
        .prepare(`
          INSERT INTO ${TABLE_REGISTRATIONS}
            (consumer_id, configuration_digest, initial_cursor_json,
             initial_cursor_digest, registered_at, registration_digest)
          VALUES (?, ?, ?, ?, ?, ?)
        `)
        .run(
          registration.consumerId,
          registration.configurationDigest,
          stableJson(registration.initialCursor),
          registration.initialCursorDigest,
          registration.registeredAt,
          registration.registrationDigest,
        );
      return registration;
    });
  }

  registration(consumerId: string): DurableConsumerRegistration | undefined {
    this.#assertNotApplying('registration read');
    validateConsumerId(consumerId);
    return this.#transaction('read', () => {
      this.#assertOperationalBoundary();
      const row = this.#registrationRow(consumerId);
      return row === undefined ? undefined : registrationFromRow(row);
    });
  }

  apply<T>(
    feed: CanonicalChangeFeed,
    batch: CanonicalAppendBatch,
    binding: ConsumerBinding,
    operation: TrustedConsumerTransaction<T>,
  ): ConsumerApplyResult<T> {
    this.#assertNotApplying('apply');
    if (typeof operation !== 'function') throw new TypeError('consumer operation must be a function');
    const registration = this.#registrationFor(binding);
    this.#applying = true;
    try {
      return feed.consume(batch, (authorizedBatch) =>
        this.#transaction('write', () => {
        this.#assertOperationalBoundary();
        this.#inject('after-begin');
        verifyCanonicalAppendBatch(authorizedBatch);

        const liveRegistration = this.#registrationFor(binding);
        if (liveRegistration.registrationDigest !== registration.registrationDigest) {
          throw new Error('consumer registration changed before batch application');
        }

        const existingReceiptRow = this.#receiptRow(binding.consumerId, authorizedBatch.id);
        if (existingReceiptRow !== undefined) {
          const existingReceipt = receiptFromRow(existingReceiptRow);
          if (
            existingReceipt.configurationDigest !== binding.configurationDigest ||
            existingReceipt.initialCursorDigest !== registration.initialCursorDigest ||
            !sameCanonicalReadCursor(existingReceipt.base, authorizedBatch.base) ||
            !sameCanonicalReadCursor(existingReceipt.after, authorizedBatch.after) ||
            existingReceipt.appendDigest !== authorizedBatch.appendDigest
          ) {
            throw new Error('consumer batch id already exists with different durable content');
          }
          const checkpointRow = this.#checkpointRow(binding.consumerId);
          if (checkpointRow === undefined) throw new Error('idempotent consumer receipt has no checkpoint');
          const checkpoint = checkpointFromRow(checkpointRow);
          if (
            checkpoint.configurationDigest !== binding.configurationDigest ||
            checkpoint.initialCursorDigest !== registration.initialCursorDigest ||
            checkpoint.latestReceiptDigest !== existingReceipt.receiptDigest ||
            !sameCanonicalReadCursor(checkpoint.cursor, authorizedBatch.after)
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

        const currentRow = this.#checkpointRow(binding.consumerId);
        const current = currentRow === undefined ? undefined : checkpointFromRow(currentRow);
        const expectedBase = current?.cursor ?? registration.initialCursor;
        if (!sameCanonicalReadCursor(expectedBase, authorizedBatch.base)) {
          throw new Error('consumer batch base is stale, incomplete, or out of order');
        }
        if (
          current !== undefined &&
          (current.configurationDigest !== binding.configurationDigest ||
            current.initialCursorDigest !== registration.initialCursorDigest)
        ) {
          throw new Error('consumer checkpoint configuration differs from registration');
        }

        const value = operation(this.#projectionTransaction(), authorizedBatch);
        if (
          value !== null &&
          typeof value === 'object' &&
          typeof (value as { readonly then?: unknown }).then === 'function'
        ) {
          throw new Error('consumer projection transaction must be synchronous');
        }
        if (!this.#db.isTransaction) {
          throw new Error('consumer projection callback ended the outer transaction');
        }
        this.#assertOperationalBoundary();
        this.#inject('after-callback');

        const revision = (current?.revision ?? 0) + 1;
        if (!Number.isSafeInteger(revision) || revision <= 0) {
          throw new Error('consumer checkpoint revision overflow');
        }
        const appliedAt = Math.max(Date.now(), (current?.updatedAt ?? registration.registeredAt) + 1);
        assertSafePositiveInteger(appliedAt, 'consumer appliedAt');
        const unsigned = Object.freeze({
          schemaVersion: CONSUMER_SCHEMA_VERSION,
          consumerId: binding.consumerId,
          configurationDigest: binding.configurationDigest,
          initialCursorDigest: registration.initialCursorDigest,
          revision,
          batchId: authorizedBatch.id,
          base: authorizedBatch.base,
          baseDigest: canonicalReadCursorDigest(authorizedBatch.base),
          after: authorizedBatch.after,
          afterDigest: canonicalReadCursorDigest(authorizedBatch.after),
          appendDigest: authorizedBatch.appendDigest,
          previousReceiptDigest: current?.latestReceiptDigest ?? GENESIS_RECEIPT_DIGEST,
          appliedAt,
        });
        const receipt = Object.freeze({
          ...unsigned,
          receiptDigest: contentDigest(receiptPayload(unsigned)),
        });

        this.#db
          .prepare(`
            INSERT INTO ${TABLE_RECEIPTS}
              (consumer_id, configuration_digest, initial_cursor_digest, revision,
               batch_id, base_cursor_json, base_cursor_digest, after_cursor_json,
               after_cursor_digest, append_digest, previous_receipt_digest,
               receipt_digest, applied_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `)
          .run(
            receipt.consumerId,
            receipt.configurationDigest,
            receipt.initialCursorDigest,
            receipt.revision,
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
            INSERT INTO ${TABLE_CHECKPOINTS}
              (consumer_id, configuration_digest, initial_cursor_digest, revision,
               cursor_json, cursor_digest, last_batch_id, last_append_digest,
               latest_receipt_digest, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(consumer_id) DO UPDATE SET
              configuration_digest = excluded.configuration_digest,
              initial_cursor_digest = excluded.initial_cursor_digest,
              revision = excluded.revision,
              cursor_json = excluded.cursor_json,
              cursor_digest = excluded.cursor_digest,
              last_batch_id = excluded.last_batch_id,
              last_append_digest = excluded.last_append_digest,
              latest_receipt_digest = excluded.latest_receipt_digest,
              updated_at = excluded.updated_at
          `)
          .run(
            receipt.consumerId,
            receipt.configurationDigest,
            receipt.initialCursorDigest,
            receipt.revision,
            stableJson(receipt.after),
            receipt.afterDigest,
            receipt.batchId,
            receipt.appendDigest,
            receipt.receiptDigest,
            receipt.appliedAt,
          );
        this.#inject('after-checkpoint');
        this.#inject('before-commit');

        const checkpoint: DurableConsumerCheckpoint = Object.freeze({
          schemaVersion: CONSUMER_SCHEMA_VERSION,
          consumerId: receipt.consumerId,
          configurationDigest: receipt.configurationDigest,
          initialCursorDigest: receipt.initialCursorDigest,
          revision: receipt.revision,
          cursor: receipt.after,
          cursorDigest: receipt.afterDigest,
          lastBatchId: receipt.batchId,
          lastAppendDigest: receipt.appendDigest,
          latestReceiptDigest: receipt.receiptDigest,
          updatedAt: receipt.appliedAt,
        });
        return Object.freeze({
          value,
          checkpoint,
          receipt,
          idempotentReplay: false,
        });
        }),
      );
    } finally {
      this.#applying = false;
    }
  }

  checkpoint(consumerId: string): DurableConsumerCheckpoint | undefined {
    this.#assertNotApplying('checkpoint read');
    validateConsumerId(consumerId);
    return this.#transaction('read', () => {
      this.#assertOperationalBoundary();
      const registrationRow = this.#registrationRow(consumerId);
      const row = this.#checkpointRow(consumerId);
      if (registrationRow === undefined) {
        const receiptCountRow = this.#db
          .prepare(`SELECT COUNT(*) AS count FROM ${TABLE_RECEIPTS} WHERE consumer_id = ?`)
          .get(consumerId) as { readonly count: unknown };
        if (row !== undefined || receiptCountRow.count !== 0) {
          throw new Error('consumer checkpoint state exists without a durable registration');
        }
        return undefined;
      }
      const registration = registrationFromRow(registrationRow);
      if (row === undefined) return undefined;
      const checkpoint = checkpointFromRow(row);
      if (
        checkpoint.configurationDigest !== registration.configurationDigest ||
        checkpoint.initialCursorDigest !== registration.initialCursorDigest
      ) {
        throw new Error('consumer checkpoint differs from registration');
      }
      const receiptRow = this.#receiptRow(consumerId, checkpoint.lastBatchId);
      if (receiptRow === undefined) throw new Error('consumer checkpoint receipt is missing');
      const receipt = receiptFromRow(receiptRow);
      if (
        receipt.receiptDigest !== checkpoint.latestReceiptDigest ||
        !sameCanonicalReadCursor(receipt.after, checkpoint.cursor) ||
        receipt.appendDigest !== checkpoint.lastAppendDigest ||
        receipt.configurationDigest !== checkpoint.configurationDigest
      ) {
        throw new Error('consumer checkpoint differs from its latest receipt');
      }
      return checkpoint;
    });
  }

  audit(consumerId: string): ConsumerCheckpointAudit {
    this.#assertNotApplying('audit');
    validateConsumerId(consumerId);
    return this.#transaction('read', () => {
      const errors: string[] = [];
      try {
        this.#assertOperationalBoundary();
      } catch (error) {
        errors.push(error instanceof Error ? error.message : 'consumer store boundary is invalid');
      }

      let registration: DurableConsumerRegistration | undefined;
      let checkpoint: DurableConsumerCheckpoint | undefined;
      try {
        const registrationRow = this.#registrationRow(consumerId);
        registration = registrationRow === undefined ? undefined : registrationFromRow(registrationRow);
      } catch (error) {
        errors.push(error instanceof Error ? error.message : 'consumer registration is invalid');
      }
      try {
        const checkpointRow = this.#checkpointRow(consumerId);
        checkpoint = checkpointRow === undefined ? undefined : checkpointFromRow(checkpointRow);
      } catch (error) {
        errors.push(error instanceof Error ? error.message : 'consumer checkpoint is invalid');
      }

      const rows = this.#db
        .prepare(`${RECEIPT_SELECT} WHERE consumer_id = ? ORDER BY revision`)
        .all(consumerId) as unknown as readonly ReceiptRow[];
      let previousReceipt = GENESIS_RECEIPT_DIGEST;
      let previousAfter = registration?.initialCursor;
      let previousAppliedAt = registration?.registeredAt ?? 0;
      for (let index = 0; index < rows.length; index += 1) {
        try {
          const receipt = receiptFromRow(rows[index] as ReceiptRow);
          if (
            receipt.revision !== index + 1 ||
            receipt.previousReceiptDigest !== previousReceipt ||
            previousAfter === undefined ||
            !sameCanonicalReadCursor(receipt.base, previousAfter) ||
            receipt.appliedAt <= previousAppliedAt ||
            registration === undefined ||
            receipt.configurationDigest !== registration.configurationDigest ||
            receipt.initialCursorDigest !== registration.initialCursorDigest
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

      if (registration === undefined) {
        if (rows.length !== 0 || checkpoint !== undefined) {
          errors.push('consumer state exists without a durable registration');
        }
      } else if (checkpoint === undefined) {
        if (rows.length !== 0) errors.push('consumer receipts exist without an active checkpoint');
      } else if (
        checkpoint.configurationDigest !== registration.configurationDigest ||
        checkpoint.initialCursorDigest !== registration.initialCursorDigest ||
        checkpoint.revision !== rows.length ||
        checkpoint.latestReceiptDigest !== previousReceipt ||
        previousAfter === undefined ||
        !sameCanonicalReadCursor(checkpoint.cursor, previousAfter)
      ) {
        errors.push('consumer checkpoint differs from the receipt-chain head');
      }

      return Object.freeze({
        ok: errors.length === 0,
        errors: Object.freeze(errors),
        ...(registration === undefined ? {} : { registration }),
        ...(checkpoint === undefined ? {} : { checkpoint }),
        receiptCount: rows.length,
      });
    });
  }

  close(): void {
    this.#assertNotApplying('close');
    if (this.#closed) return;
    this.#db.close();
    this.#closed = true;
  }
}
