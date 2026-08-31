import type { EvidenceRecord, EvidenceRef } from '../domain.js';
import { canonicalJson, contentDigest } from './canonical.js';
import {
  CanonicalObjectReadIndexIntegrityError,
  type CanonicalObjectKind,
  ClaimReadRecord,
  DecodedObjectReadHead,
  DecodedObjectReadVersion,
  EvidenceReadRecord,
  IndexedCanonicalObjectState,
  IndexedClaimState,
  IndexedEvidenceState,
  ObjectReadHeadRow,
  ObjectReadNodeRow,
  ObjectReadTreeKind,
  ObjectReadTreeValue,
  ObjectReadVersionRow,
} from './object-read-index-contract.js';
import {
  assertDigest,
  assertInteger,
  assertNullableInteger,
  assertObjectKind,
  assertTreeKind,
  canonicalClone,
  decodeString,
  deepFreeze,
  parseIndexedState,
} from './object-read-index-validation.js';

export function indexedStateDigest(state: IndexedCanonicalObjectState): string {
  return contentDigest({ domain: 'cl-canonical-object-read-state-v1', state });
}

export function objectVersionDigest(value: {
  readonly kind: CanonicalObjectKind;
  readonly canonicalId: string;
  readonly versionSeq: number;
  readonly recordedAt: number;
  readonly knownTo?: number;
  readonly stateDigest: string;
  readonly bucket: number;
}): string {
  return contentDigest({ domain: 'cl-canonical-object-read-version-row-v1', ...value });
}

export function objectHeadDigest(value: {
  readonly kind: CanonicalObjectKind;
  readonly canonicalId: string;
  readonly versionSeq: number;
  readonly recordedAt: number;
  readonly stateDigest: string;
  readonly versionDigest: string;
  readonly bucket: number;
}): string {
  return contentDigest({ domain: 'cl-canonical-object-read-head-row-v1', ...value });
}

export function bucketForObject(
  tree: ObjectReadTreeKind,
  identity: string,
  bucketCount: number,
): number {
  const digest = contentDigest({ domain: 'cl-canonical-object-read-bucket-key-v1', tree, identity });
  return Number.parseInt(digest.slice(7, 15), 16) % bucketCount;
}

export function headBucketDigest(
  bucket: number,
  rows: readonly DecodedObjectReadHead[],
): string {
  return contentDigest({
    domain: 'cl-canonical-object-read-head-bucket-v1',
    bucket,
    members: rows.map((row) => ({
      kind: row.kind,
      canonicalId: row.canonicalId,
      headDigest: row.headDigest,
    })),
  });
}

export function versionBucketDigest(
  bucket: number,
  rows: readonly DecodedObjectReadVersion[],
): string {
  return contentDigest({
    domain: 'cl-canonical-object-read-version-bucket-v1',
    bucket,
    members: rows.map((row) => ({
      kind: row.kind,
      canonicalId: row.canonicalId,
      versionSeq: row.versionSeq,
      rowDigest: row.rowDigest,
    })),
  });
}

export function sparseLeafDigest(
  tree: ObjectReadTreeKind,
  bucket: number,
  itemCount: number,
  bucketDigest: string,
): string {
  return contentDigest({
    domain: 'cl-canonical-object-read-sparse-leaf-v1',
    tree,
    bucket,
    itemCount,
    bucketDigest,
  });
}

export function sparseInternalDigest(
  tree: ObjectReadTreeKind,
  level: number,
  leftDigest: string,
  rightDigest: string,
): string {
  return contentDigest({
    domain: 'cl-canonical-object-read-sparse-node-v1',
    tree,
    level,
    leftDigest,
    rightDigest,
  });
}

export function sparseEmptyDigests(
  tree: ObjectReadTreeKind,
  bucketBits: number,
): readonly string[] {
  const values = [contentDigest({ domain: 'cl-canonical-object-read-empty-leaf-v1', tree })];
  for (let level = 1; level <= bucketBits; level += 1) {
    const child = values[level - 1];
    if (child === undefined) throw new Error('sparse empty digest invariant failed');
    values.push(sparseInternalDigest(tree, level, child, child));
  }
  return Object.freeze(values);
}

export function decodeHeadRow(
  row: ObjectReadHeadRow,
  bucketCount: number,
): DecodedObjectReadHead {
  assertObjectKind(row.kind, 'object head kind');
  const canonicalId = decodeString(row.object_id_json, 'object head id');
  assertInteger(row.version_seq, 'object head version sequence', 1);
  assertInteger(row.recorded_at, 'object head recordedAt', 0);
  assertDigest(row.state_digest, 'object head state digest');
  assertDigest(row.version_digest, 'object head version digest');
  assertDigest(row.head_digest, 'object head digest');
  assertInteger(row.bucket, 'object head bucket', 0);
  if (row.bucket >= bucketCount) {
    throw new CanonicalObjectReadIndexIntegrityError('object head bucket is out of range');
  }
  const expectedBucket = bucketForObject(
    'head',
    `${row.kind}\u0000${canonicalId}`,
    bucketCount,
  );
  if (row.bucket !== expectedBucket) {
    throw new CanonicalObjectReadIndexIntegrityError('object head bucket assignment diverged');
  }
  const unsigned = Object.freeze({
    kind: row.kind,
    canonicalId,
    versionSeq: row.version_seq,
    recordedAt: row.recorded_at,
    stateDigest: row.state_digest,
    versionDigest: row.version_digest,
    bucket: row.bucket,
  });
  if (objectHeadDigest(unsigned) !== row.head_digest) {
    throw new CanonicalObjectReadIndexIntegrityError(
      `object head integrity failed for ${row.kind}/${canonicalId}`,
    );
  }
  return Object.freeze({ ...unsigned, headDigest: row.head_digest });
}

export function decodeVersionRow(
  row: ObjectReadVersionRow,
  bucketCount: number,
): DecodedObjectReadVersion {
  assertObjectKind(row.kind, 'object version kind');
  const canonicalId = decodeString(row.object_id_json, 'object version id');
  assertInteger(row.version_seq, 'object version sequence', 1);
  assertInteger(row.recorded_at, 'object version recordedAt', 0);
  assertNullableInteger(row.known_to, 'object version knownTo', 0);
  if (row.known_to !== null && row.known_to < row.recorded_at) {
    throw new CanonicalObjectReadIndexIntegrityError('object version interval is inverted');
  }
  assertDigest(row.state_digest, 'object version state digest');
  assertDigest(row.row_digest, 'object version row digest');
  assertInteger(row.bucket, 'object version bucket', 0);
  if (row.bucket >= bucketCount) {
    throw new CanonicalObjectReadIndexIntegrityError('object version bucket is out of range');
  }
  const expectedBucket = bucketForObject(
    'version',
    `${row.kind}\u0000${canonicalId}\u0000${row.version_seq}`,
    bucketCount,
  );
  if (row.bucket !== expectedBucket) {
    throw new CanonicalObjectReadIndexIntegrityError('object version bucket assignment diverged');
  }
  const state = parseIndexedState(row.state_json, row.kind, canonicalId);
  const computedStateDigest = indexedStateDigest(state);
  if (computedStateDigest !== row.state_digest) {
    throw new CanonicalObjectReadIndexIntegrityError(
      `object state integrity failed for ${row.kind}/${canonicalId}`,
    );
  }
  const unsigned = Object.freeze({
    kind: row.kind,
    canonicalId,
    versionSeq: row.version_seq,
    recordedAt: row.recorded_at,
    ...(row.known_to === null ? {} : { knownTo: row.known_to }),
    stateDigest: row.state_digest,
    bucket: row.bucket,
  });
  if (objectVersionDigest(unsigned) !== row.row_digest) {
    throw new CanonicalObjectReadIndexIntegrityError(
      `object version integrity failed for ${row.kind}/${canonicalId}@${row.version_seq}`,
    );
  }
  return Object.freeze({ ...unsigned, state, rowDigest: row.row_digest });
}

export function decodeNodeRow(
  row: ObjectReadNodeRow,
  tree: ObjectReadTreeKind,
  level: number,
  prefix: number,
): ObjectReadTreeValue {
  assertTreeKind(row.tree_kind, 'sparse node tree kind');
  assertInteger(row.level, 'sparse node level', 1);
  assertInteger(row.prefix, 'sparse node prefix', 0);
  assertInteger(row.item_count, 'sparse node item count', 1);
  assertDigest(row.node_digest, 'sparse node digest');
  if (row.tree_kind !== tree || row.level !== level || row.prefix !== prefix) {
    throw new CanonicalObjectReadIndexIntegrityError('sparse node identity diverged');
  }
  return Object.freeze({ digest: row.node_digest, itemCount: row.item_count });
}

export function evidenceReferenceMatches(record: EvidenceRecord, reference: EvidenceRef): boolean {
  return (
    reference.sourceId === record.id &&
    canonicalJson(reference.sourceGroups) === canonicalJson(record.sourceGroups) &&
    reference.authority === record.authority &&
    reference.contentHash === record.artifact.digest
  );
}

export function claimCoversWorldTime(state: IndexedClaimState, validAt: number): boolean {
  if (!Number.isFinite(validAt)) throw new TypeError('validAt must be finite');
  if (state.lifecycle === 'quarantined' || state.lifecycle === 'revoked') return false;
  const explicitTo = state.claim.valid.to;
  const effectiveTo =
    explicitTo === undefined
      ? state.supersededAt
      : state.supersededAt === undefined
        ? explicitTo
        : Math.min(explicitTo, state.supersededAt);
  return (
    validAt >= state.claim.valid.from &&
    (effectiveTo === undefined || validAt < effectiveTo)
  );
}

export function evidenceReadView(
  selected: IndexedEvidenceState,
  current: IndexedEvidenceState,
): EvidenceReadRecord {
  const contentAvailable =
    selected.availability === 'available' && current.availability === 'available';
  const canonicalRecord = canonicalClone(selected.record);
  const record = contentAvailable || canonicalRecord.preview === undefined
    ? canonicalRecord
    : deepFreeze((({ preview: _preview, ...rest }) => rest)(canonicalRecord));
  return deepFreeze({
    kind: 'evidence' as const,
    record,
    availabilityAtSelection: selected.availability,
    currentAvailability: current.availability,
    contentAvailable,
    capturedSeq: selected.capturedSeq,
    ...(selected.latestAvailabilitySeq === undefined
      ? {}
      : { latestAvailabilitySeq: selected.latestAvailabilitySeq }),
  });
}

export function claimReadView(state: IndexedClaimState): ClaimReadRecord {
  return deepFreeze({
    kind: 'claim' as const,
    claim: canonicalClone(state.claim),
    lifecycle: state.lifecycle,
    assertedSeq: state.assertedSeq,
    ...(state.admittedSeq === undefined ? {} : { admittedSeq: state.admittedSeq }),
    ...(state.supersededAt === undefined ? {} : { supersededAt: state.supersededAt }),
    ...(state.supersededBy === undefined ? {} : { supersededBy: state.supersededBy }),
    ...(state.revokedSeq === undefined ? {} : { revokedSeq: state.revokedSeq }),
  });
}

export * from './object-read-index-validation.js';
