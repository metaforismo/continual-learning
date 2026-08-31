import type {
  ClaimRecord,
  EvidenceRecord,
  EvidenceRef,
} from '../domain.js';
import { canonicalJson, contentDigest, SHA256_PATTERN } from './canonical.js';
import {
  CanonicalObjectReadIndexIntegrityError,
  MAX_OBJECT_READ_ID_CHARACTERS,
  type CanonicalObjectKind,
  type ClaimReadRecord,
  type DecodedObjectReadHead,
  type DecodedObjectReadVersion,
  type EvidenceReadRecord,
  type IndexedCanonicalObjectState,
  type IndexedClaimState,
  type IndexedEvidenceState,
  type ObjectReadHeadRow,
  type ObjectReadNodeRow,
  type ObjectReadTreeKind,
  type ObjectReadTreeValue,
  type ObjectReadVersionRow,
} from './object-read-index-contract.js';

const PREFIX_PATTERN = /^[a-z][a-z0-9_]*_$/;
const MAX_PREFIX_BYTES = 96;

export function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export function canonicalClone<T>(value: T): T {
  return deepFreeze(JSON.parse(canonicalJson(value)) as T);
}

export function assertDigest(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || !SHA256_PATTERN.test(value)) {
    throw new CanonicalObjectReadIndexIntegrityError(`${label} is not a SHA-256 content address`);
  }
}

export function assertInteger(value: unknown, label: string, minimum = 0): asserts value is number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum) {
    throw new CanonicalObjectReadIndexIntegrityError(`${label} is not a safe integer >= ${minimum}`);
  }
}

export function assertNullableInteger(
  value: unknown,
  label: string,
  minimum = 0,
): asserts value is number | null {
  if (value !== null) assertInteger(value, label, minimum);
}

export function assertNonEmptyString(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\u0000')) {
    throw new CanonicalObjectReadIndexIntegrityError(`${label} is malformed`);
  }
}

export function assertObjectKind(
  value: unknown,
  label: string,
): asserts value is CanonicalObjectKind {
  if (value !== 'evidence' && value !== 'claim') {
    throw new CanonicalObjectReadIndexIntegrityError(`${label} is invalid`);
  }
}

export function assertTreeKind(
  value: unknown,
  label: string,
): asserts value is ObjectReadTreeKind {
  if (value !== 'head' && value !== 'version') {
    throw new CanonicalObjectReadIndexIntegrityError(`${label} is invalid`);
  }
}

export function assertObjectId(value: unknown): asserts value is string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new TypeError('canonical object id must be a non-empty string');
  }
  if (value.length > MAX_OBJECT_READ_ID_CHARACTERS) {
    throw new RangeError(
      `canonical object id cannot exceed ${MAX_OBJECT_READ_ID_CHARACTERS} characters`,
    );
  }
  if (value.includes('\u0000')) throw new TypeError('canonical object id cannot contain U+0000');
}

export function assertProjectionPrefix(prefix: unknown): asserts prefix is string {
  if (typeof prefix !== 'string' || !PREFIX_PATTERN.test(prefix)) {
    throw new Error(
      'projectionTablePrefix must use lowercase ASCII letters, digits, underscores, and end with underscore',
    );
  }
  if (new TextEncoder().encode(prefix).length > MAX_PREFIX_BYTES) {
    throw new Error(`projectionTablePrefix cannot exceed ${MAX_PREFIX_BYTES} UTF-8 bytes`);
  }
  if (prefix.startsWith('cl_consumer_') || prefix.startsWith('sqlite_')) {
    throw new Error('projectionTablePrefix overlaps a reserved namespace');
  }
}

export function encodeString(value: string): string {
  return canonicalJson(value);
}

export function decodeString(value: unknown, label: string): string {
  if (typeof value !== 'string') {
    throw new CanonicalObjectReadIndexIntegrityError(`${label} is not stored as TEXT`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new CanonicalObjectReadIndexIntegrityError(`${label} is not canonical JSON text`);
  }
  if (typeof parsed !== 'string' || canonicalJson(parsed) !== value) {
    throw new CanonicalObjectReadIndexIntegrityError(`${label} is not a canonical encoded string`);
  }
  assertObjectId(parsed);
  return parsed;
}

export function parseCanonicalJson(value: unknown, label: string): unknown {
  if (typeof value !== 'string') {
    throw new CanonicalObjectReadIndexIntegrityError(`${label} is not stored as TEXT`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new CanonicalObjectReadIndexIntegrityError(`${label} is not valid JSON`);
  }
  if (canonicalJson(parsed) !== value) {
    throw new CanonicalObjectReadIndexIntegrityError(`${label} is not canonical JSON`);
  }
  return parsed;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function assertStringArray(value: unknown, label: string): asserts value is readonly string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new CanonicalObjectReadIndexIntegrityError(`${label} must be a string array`);
  }
}

function assertEvidenceRecordShape(record: unknown, canonicalId: string): asserts record is EvidenceRecord {
  if (!isRecord(record) || record['id'] !== canonicalId) {
    throw new CanonicalObjectReadIndexIntegrityError('indexed evidence identity diverged');
  }
  assertNonEmptyString(record['scope'], 'indexed evidence scope');
  assertStringArray(record['sourceGroups'], 'indexed evidence source groups');
  assertNonEmptyString(record['authority'], 'indexed evidence authority');
  if (!isRecord(record['artifact'])) {
    throw new CanonicalObjectReadIndexIntegrityError('indexed evidence artifact is malformed');
  }
  assertDigest(record['artifact']['digest'], 'indexed evidence artifact digest');
  assertStringArray(record['taints'], 'indexed evidence taints');
  assertStringArray(record['derivedFrom'], 'indexed evidence derivedFrom');
  assertStringArray(record['labels'], 'indexed evidence labels');
  if (record['preview'] !== undefined && typeof record['preview'] !== 'string') {
    throw new CanonicalObjectReadIndexIntegrityError('indexed evidence preview is malformed');
  }
}

function assertEvidenceRefShape(reference: unknown): asserts reference is EvidenceRef {
  if (!isRecord(reference)) {
    throw new CanonicalObjectReadIndexIntegrityError('indexed claim evidence reference is malformed');
  }
  assertNonEmptyString(reference['sourceId'], 'indexed claim evidence source id');
  assertStringArray(reference['sourceGroups'], 'indexed claim evidence source groups');
  assertNonEmptyString(reference['authority'], 'indexed claim evidence authority');
  assertDigest(reference['contentHash'], 'indexed claim evidence content hash');
  if (reference['roles'] !== undefined) {
    assertStringArray(reference['roles'], 'indexed claim evidence roles');
  }
}

function assertClaimRecordShape(claim: unknown, canonicalId: string): asserts claim is ClaimRecord {
  if (!isRecord(claim) || claim['id'] !== canonicalId) {
    throw new CanonicalObjectReadIndexIntegrityError('indexed claim identity diverged');
  }
  if (!isRecord(claim['key'])) {
    throw new CanonicalObjectReadIndexIntegrityError('indexed claim key is malformed');
  }
  for (const key of ['scope', 'subject', 'predicate'] as const) {
    assertNonEmptyString(claim['key'][key], `indexed claim key ${key}`);
  }
  if (!isRecord(claim['valid'])) {
    throw new CanonicalObjectReadIndexIntegrityError('indexed claim validity is malformed');
  }
  if (typeof claim['valid']['from'] !== 'number' || !Number.isFinite(claim['valid']['from'])) {
    throw new CanonicalObjectReadIndexIntegrityError('indexed claim valid.from is malformed');
  }
  if (
    claim['valid']['to'] !== undefined &&
    (typeof claim['valid']['to'] !== 'number' || !Number.isFinite(claim['valid']['to']))
  ) {
    throw new CanonicalObjectReadIndexIntegrityError('indexed claim valid.to is malformed');
  }
  if (!Array.isArray(claim['evidence'])) {
    throw new CanonicalObjectReadIndexIntegrityError('indexed claim evidence is malformed');
  }
  for (const reference of claim['evidence']) assertEvidenceRefShape(reference);
  assertStringArray(claim['derivedFrom'], 'indexed claim derivedFrom');
  assertStringArray(claim['tags'], 'indexed claim tags');
  if (typeof claim['confidence'] !== 'number' || !Number.isFinite(claim['confidence'])) {
    throw new CanonicalObjectReadIndexIntegrityError('indexed claim confidence is malformed');
  }
}

export function parseIndexedState(
  stateJson: unknown,
  kind: CanonicalObjectKind,
  canonicalId: string,
): IndexedCanonicalObjectState {
  const parsed = parseCanonicalJson(stateJson, 'indexed object state');
  if (!isRecord(parsed) || parsed['kind'] !== kind) {
    throw new CanonicalObjectReadIndexIntegrityError('indexed object state kind diverged');
  }
  if (kind === 'evidence') {
    assertEvidenceRecordShape(parsed['record'], canonicalId);
    if (!['available', 'restricted', 'deleted'].includes(String(parsed['availability']))) {
      throw new CanonicalObjectReadIndexIntegrityError('indexed evidence availability is invalid');
    }
    assertInteger(parsed['capturedSeq'], 'indexed evidence capturedSeq', 1);
    if (parsed['latestAvailabilitySeq'] !== undefined) {
      assertInteger(parsed['latestAvailabilitySeq'], 'indexed evidence availability sequence', 1);
    }
    return deepFreeze(parsed as unknown as IndexedEvidenceState);
  }
  assertClaimRecordShape(parsed['claim'], canonicalId);
  if (!['quarantined', 'active', 'superseded', 'revoked'].includes(String(parsed['lifecycle']))) {
    throw new CanonicalObjectReadIndexIntegrityError('indexed claim lifecycle is invalid');
  }
  assertInteger(parsed['assertedSeq'], 'indexed claim assertedSeq', 1);
  for (const key of ['admittedSeq', 'revokedSeq'] as const) {
    if (parsed[key] !== undefined) assertInteger(parsed[key], `indexed claim ${key}`, 1);
  }
  if (parsed['supersededAt'] !== undefined) {
    if (typeof parsed['supersededAt'] !== 'number' || !Number.isFinite(parsed['supersededAt'])) {
      throw new CanonicalObjectReadIndexIntegrityError('indexed claim supersededAt is invalid');
    }
  }
  if (parsed['supersededBy'] !== undefined) {
    assertNonEmptyString(parsed['supersededBy'], 'indexed claim supersededBy');
  }
  return deepFreeze(parsed as unknown as IndexedClaimState);
}
