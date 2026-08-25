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
import type { Fts5ProjectionDocumentKind, Fts5ProjectionView } from './types.js';

export const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
export const DEFAULT_MAX_QUERY_TOKENS = 16;
export const MAX_QUERY_TOKEN_LENGTH = 96;
export const MAX_SCOPE_COUNT = 64;
export const MAX_SCOPE_LENGTH = 256;

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
    const encoded = value.map((item, index) =>
      canonicalJson(item, `${path}[${index}]`, ancestors),
    );
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

export function normalizeView(value: Fts5ProjectionView | undefined): Fts5ProjectionView {
  const view = value ?? 'current';
  if (view !== 'current' && view !== 'historical') {
    throw new Error('FTS projection view must be current or historical');
  }
  return view;
}

export function assertScopeChain(scopeChain: readonly string[]): void {
  if (scopeChain.length === 0) throw new Error('scopeChain requires at least one value');
  if (scopeChain.length > MAX_SCOPE_COUNT) {
    throw new RangeError(`scopeChain cannot exceed ${MAX_SCOPE_COUNT} values`);
  }
  if (scopeChain.some((scope) => scope.trim().length === 0)) {
    throw new Error('scopeChain cannot contain empty values');
  }
  if (scopeChain.some((scope) => scope.length > MAX_SCOPE_LENGTH)) {
    throw new RangeError(`scopeChain values cannot exceed ${MAX_SCOPE_LENGTH} characters`);
  }
  if (new Set(scopeChain).size !== scopeChain.length) {
    throw new Error('scopeChain cannot contain duplicates');
  }
}

export function safeMatchQuery(query: string, maxTokens = DEFAULT_MAX_QUERY_TOKENS): string {
  if (!Number.isInteger(maxTokens) || maxTokens <= 0 || maxTokens > 64) {
    throw new RangeError('maxQueryTokens must be an integer in [1, 64]');
  }
  const tokens = [
    ...new Set(query.normalize('NFKC').toLocaleLowerCase().match(/[\p{L}\p{N}_-]+/gu) ?? []),
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

export function claimText(claim: ClaimRecord): string {
  return [
    claim.key.subject,
    claim.key.predicate,
    ...claim.tags,
    canonicalJson(claim.value as JsonValue),
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
      searchText: claimText(claim),
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
