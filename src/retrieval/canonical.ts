import { createHash } from 'node:crypto';

import { ClaimProjection } from '../claims.js';
import type {
  ClaimLifecycle,
  ClaimRecord,
  EvidenceRecord,
  JsonValue,
  MemoryEvent,
} from '../domain.js';
import { EvidenceProjection } from '../evidence.js';
import {
  FTS5_PROJECTION_SCHEMA_VERSION,
  type Fts5ClaimLifecycleFilter,
  type Fts5ProjectionDocumentKind,
} from './types.js';

export const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
export const DEFAULT_MAX_QUERY_TOKENS = 16;
export const MAX_QUERY_TOKEN_LENGTH = 96;
export const MAX_QUERY_CHARACTERS = 4_096;
export const MAX_SCOPE_COUNT = 64;
export const MAX_SCOPE_LENGTH = 256;

const FTS5_TOKENIZER = 'unicode61 remove_diacritics 2';

export interface IndexedDocument {
  readonly canonicalId: string;
  readonly kind: Fts5ProjectionDocumentKind;
  readonly scope: string;
  readonly lifecycle: '' | Extract<ClaimLifecycle, 'active' | 'superseded'>;
  readonly sourceDigest: string;
  readonly searchText: string;
  readonly entryDigest: string;
}

export function canonicalJson(
  value: unknown,
  path = '$',
  ancestors = new WeakSet<object>(),
): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      throw new TypeError(`${path} must contain only finite JSON numbers`);
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (ancestors.has(value)) throw new TypeError(`${path} cannot contain a circular reference`);
    ancestors.add(value);
    const encoded: string[] = [];
    for (let index = 0; index < value.length; index += 1) {
      if (!(index in value)) throw new TypeError(`${path} cannot contain a sparse array`);
      encoded.push(canonicalJson(value[index], `${path}[${index}]`, ancestors));
    }
    ancestors.delete(value);
    return `[${encoded.join(',')}]`;
  }
  if (typeof value === 'object') {
    if (ancestors.has(value)) throw new TypeError(`${path} cannot contain a circular reference`);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(`${path} must be a plain JSON object`);
    }
    ancestors.add(value);
    const objectValue = value as Record<string, unknown>;
    const encoded = Object.keys(objectValue)
      .sort()
      .map((key) => {
        const item = objectValue[key];
        if (item === undefined) throw new TypeError(`${path}.${key} cannot be undefined`);
        return `${JSON.stringify(key)}:${canonicalJson(item, `${path}.${key}`, ancestors)}`;
      });
    ancestors.delete(value);
    return `{${encoded.join(',')}}`;
  }
  throw new TypeError(`${path} contains a non-JSON value`);
}

export function contentDigest(value: unknown): string {
  return `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

export function normalizeClaimLifecycleFilter(
  value: Fts5ClaimLifecycleFilter | undefined,
): Fts5ClaimLifecycleFilter {
  const filter = value ?? 'all';
  if (filter !== 'all' && filter !== 'active-only') {
    throw new Error('FTS claimLifecycle must be all or active-only');
  }
  return filter;
}

export function snapshotScopeChain(scopeChain: readonly string[]): readonly string[] {
  if (!Array.isArray(scopeChain)) throw new TypeError('scopeChain must be an array');
  const snapshot = Object.freeze(Array.from(scopeChain));
  if (snapshot.length === 0) throw new Error('scopeChain requires at least one value');
  if (snapshot.length > MAX_SCOPE_COUNT) {
    throw new RangeError(`scopeChain cannot exceed ${MAX_SCOPE_COUNT} values`);
  }
  if (snapshot.some((scope) => typeof scope !== 'string')) {
    throw new TypeError('scopeChain values must be strings');
  }
  if (snapshot.some((scope) => scope.trim().length === 0)) {
    throw new Error('scopeChain cannot contain empty values');
  }
  if (snapshot.some((scope) => scope.length > MAX_SCOPE_LENGTH)) {
    throw new RangeError(`scopeChain values cannot exceed ${MAX_SCOPE_LENGTH} characters`);
  }
  if (new Set(snapshot).size !== snapshot.length) {
    throw new Error('scopeChain cannot contain duplicates');
  }
  return snapshot;
}

export function safeMatchQuery(query: string, maxTokens = DEFAULT_MAX_QUERY_TOKENS): string {
  if (typeof query !== 'string') throw new TypeError('FTS query must be a string');
  if (query.length > MAX_QUERY_CHARACTERS) {
    throw new RangeError(`FTS query cannot exceed ${MAX_QUERY_CHARACTERS} characters`);
  }
  if (!Number.isInteger(maxTokens) || maxTokens <= 0 || maxTokens > 64) {
    throw new RangeError('maxQueryTokens must be an integer in [1, 64]');
  }
  const tokens = [
    ...new Set(query.normalize('NFKC').toLowerCase().match(/[\p{L}\p{N}_-]+/gu) ?? []),
  ];
  if (tokens.length === 0) throw new Error('FTS query requires at least one searchable token');
  if (tokens.length > maxTokens) {
    throw new RangeError(`FTS query exceeds the ${maxTokens}-token limit`);
  }
  if (tokens.some((token) => token.length > MAX_QUERY_TOKEN_LENGTH)) {
    throw new RangeError(`FTS query token exceeds ${MAX_QUERY_TOKEN_LENGTH} characters`);
  }
  // Callers never supply raw MATCH syntax. Parser-produced tokens become quoted prefix terms.
  return tokens.map((token) => `"${token.replaceAll('"', '""')}"*`).join(' AND ');
}

export function evidenceText(record: EvidenceRecord): string {
  return [record.preview ?? '', record.kind, ...record.labels]
    .filter((item) => item.length > 0)
    .join('\n');
}

export function claimText(claim: ClaimRecord, includeValue = false): string {
  return [
    claim.key.subject,
    claim.key.predicate,
    ...claim.tags,
    ...(includeValue ? [canonicalJson(claim.value as JsonValue)] : []),
  ].join('\n');
}

export function documentDigest(document: Omit<IndexedDocument, 'entryDigest'>): string {
  return contentDigest(document);
}

export function manifestDigest(documents: readonly IndexedDocument[]): string {
  return contentDigest(
    documents.map((document) => ({
      canonicalId: document.canonicalId,
      kind: document.kind,
      scope: document.scope,
      lifecycle: document.lifecycle,
      sourceDigest: document.sourceDigest,
      searchText: document.searchText,
      entryDigest: document.entryDigest,
    })),
  );
}

export function projectionConfigDigest(
  sensitivities: readonly EvidenceRecord['sensitivity'][],
  indexClaimValues: boolean,
): string {
  return contentDigest({
    schemaVersion: FTS5_PROJECTION_SCHEMA_VERSION,
    tokenizer: FTS5_TOKENIZER,
    searchableSensitivities: [...sensitivities].sort(),
    indexClaimValues,
  });
}

export function searchableEvidence(
  record: EvidenceRecord,
  projection: EvidenceProjection,
  allowedSensitivities: ReadonlySet<EvidenceRecord['sensitivity']>,
): boolean {
  return (
    projection.isAvailable(record.id) &&
    record.preview !== undefined &&
    record.preview.length > 0 &&
    allowedSensitivities.has(record.sensitivity) &&
    !record.taints.includes('secret-detected')
  );
}

export function searchableClaim(
  claim: ClaimRecord,
  lifecycle: ClaimLifecycle | undefined,
  evidence: EvidenceProjection,
  allowedSensitivities: ReadonlySet<EvidenceRecord['sensitivity']>,
): lifecycle is Extract<ClaimLifecycle, 'active' | 'superseded'> {
  if (lifecycle !== 'active' && lifecycle !== 'superseded') return false;
  // Evidence-less values have no privacy classification. Keep them canonical but out of plaintext.
  if (claim.evidence.length === 0) return false;
  return claim.evidence.every((reference) => {
    const projected = evidence.get(reference.sourceId);
    return (
      projected !== undefined &&
      evidence.validatesReference(reference) &&
      allowedSensitivities.has(projected.record.sensitivity) &&
      !projected.record.taints.includes('secret-detected')
    );
  });
}

export function buildDocuments(
  events: readonly MemoryEvent[],
  allowedSensitivities: ReadonlySet<EvidenceRecord['sensitivity']>,
  includeClaimValues = false,
): readonly IndexedDocument[] {
  const evidence = EvidenceProjection.from(events);
  const claims = ClaimProjection.from(events);
  const documents: IndexedDocument[] = [];

  for (const projected of evidence.all()) {
    const record = projected.record;
    if (!searchableEvidence(record, evidence, allowedSensitivities)) continue;
    const base = Object.freeze({
      canonicalId: record.id,
      kind: 'evidence' as const,
      scope: record.scope,
      lifecycle: '' as const,
      sourceDigest: record.artifact.digest,
      searchText: evidenceText(record),
    });
    documents.push(Object.freeze({ ...base, entryDigest: documentDigest(base) }));
  }

  const seenClaimIds = new Set<string>();
  for (const event of events) {
    if (event.type !== 'claim.asserted') continue;
    const claim = event.data.claim;
    if (seenClaimIds.has(claim.id)) continue;
    seenClaimIds.add(claim.id);
    const lifecycle = claims.lifecycle(claim.id);
    if (!searchableClaim(claim, lifecycle, evidence, allowedSensitivities)) continue;
    const base = Object.freeze({
      canonicalId: claim.id,
      kind: 'claim' as const,
      scope: claim.key.scope,
      lifecycle,
      sourceDigest: contentDigest(claim),
      searchText: claimText(claim, includeClaimValues),
    });
    documents.push(Object.freeze({ ...base, entryDigest: documentDigest(base) }));
  }

  return Object.freeze(
    documents.sort(
      (left, right) =>
        left.kind.localeCompare(right.kind) || left.canonicalId.localeCompare(right.canonicalId),
    ),
  );
}
