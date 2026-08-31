import type {
  ClaimLifecycle,
  ClaimRecord,
  EvidenceAvailability,
  EvidenceRecord,
} from '../domain.js';
import type { CanonicalReadCursor } from '../durable/change-feed.js';
import type {
  DurableConsumerCheckpoint,
  DurableConsumerRegistration,
} from '../durable/consumer-store.js';

export const CANONICAL_OBJECT_READ_INDEX_SCHEMA_VERSION = 1 as const;
export const DEFAULT_OBJECT_READ_BUCKET_BITS = 16;
export const MIN_OBJECT_READ_BUCKET_BITS = 8;
export const MAX_OBJECT_READ_BUCKET_BITS = 20;
export const MAX_OBJECT_READ_LOOKUPS = 100;
export const MAX_OBJECT_READ_ID_CHARACTERS = 4_096;

export type CanonicalObjectKind = 'evidence' | 'claim';
export type ObjectReadTreeKind = 'head' | 'version';
export type ObjectReadMode = 'current' | 'known-at' | 'valid-at';

export class CanonicalObjectReadIndexRebuildRequiredError extends Error {
  readonly reason: string;

  constructor(reason: string) {
    super(reason);
    this.name = 'CanonicalObjectReadIndexRebuildRequiredError';
    this.reason = reason;
  }
}

export class CanonicalObjectReadIndexIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CanonicalObjectReadIndexIntegrityError';
  }
}

export interface CanonicalObjectReadIndexOptions {
  readonly consumerId: string;
  readonly projectionTablePrefix: string;
  /**
   * Number of leading SHA-256 bits used for sparse authenticated buckets.
   * Larger values reduce expected bucket size while increasing proof depth.
   */
  readonly bucketBits?: number;
}

export interface IndexedEvidenceState {
  readonly kind: 'evidence';
  readonly record: EvidenceRecord;
  readonly availability: EvidenceAvailability;
  readonly capturedSeq: number;
  readonly latestAvailabilitySeq?: number;
}

export interface IndexedClaimState {
  readonly kind: 'claim';
  readonly claim: ClaimRecord;
  readonly lifecycle: ClaimLifecycle;
  readonly assertedSeq: number;
  readonly admittedSeq?: number;
  readonly supersededAt?: number;
  readonly supersededBy?: string;
  readonly revokedSeq?: number;
}

export type IndexedCanonicalObjectState = IndexedEvidenceState | IndexedClaimState;

export interface EvidenceReadRecord {
  readonly kind: 'evidence';
  /**
   * Canonical metadata for the selected version. `preview` is removed whenever
   * selected or current availability forbids content use.
   */
  readonly record: EvidenceRecord;
  readonly availabilityAtSelection: EvidenceAvailability;
  readonly currentAvailability: EvidenceAvailability;
  readonly contentAvailable: boolean;
  readonly capturedSeq: number;
  readonly latestAvailabilitySeq?: number;
}

export interface ClaimReadRecord {
  readonly kind: 'claim';
  readonly claim: ClaimRecord;
  readonly lifecycle: ClaimLifecycle;
  readonly assertedSeq: number;
  readonly admittedSeq?: number;
  readonly supersededAt?: number;
  readonly supersededBy?: string;
  readonly revokedSeq?: number;
}

export interface SparseBucketSibling {
  readonly level: number;
  readonly side: 'left' | 'right';
  readonly digest: string;
  readonly itemCount: number;
}

export interface SparseBucketProof {
  readonly tree: ObjectReadTreeKind;
  readonly bucket: number;
  readonly bucketItemCount: number;
  readonly bucketDigest: string;
  readonly siblings: readonly SparseBucketSibling[];
  readonly rootDigest: string;
  readonly rootItemCount: number;
}

export interface SelectedObjectProof<TRecord extends EvidenceReadRecord | ClaimReadRecord> {
  readonly schemaVersion: typeof CANONICAL_OBJECT_READ_INDEX_SCHEMA_VERSION;
  readonly kind: TRecord['kind'];
  readonly canonicalId: string;
  readonly mode: ObjectReadMode;
  readonly knownAt?: number;
  readonly validAt?: number;
  readonly record: TRecord;
  readonly stateDigest: string;
  readonly versionSeq: number;
  readonly recordedAt: number;
  readonly knownTo?: number;
  readonly versionDigest: string;
  readonly headDigest?: string;
  readonly headProof?: SparseBucketProof;
  readonly versionProof: SparseBucketProof;
  readonly canonicalCursor: CanonicalReadCursor;
  readonly canonicalCursorDigest: string;
  readonly consumerRevision: number;
  readonly lastBatchId: string;
  readonly configurationDigest: string;
  readonly proofDigest: string;
}

export type SelectedEvidenceProof = SelectedObjectProof<EvidenceReadRecord>;
export type SelectedClaimProof = SelectedObjectProof<ClaimReadRecord>;
export type AnySelectedObjectProof = SelectedEvidenceProof | SelectedClaimProof;

export interface CanonicalObjectAddress {
  readonly kind: CanonicalObjectKind;
  readonly canonicalId: string;
  /** Optional stale-candidate gate, for example an FTS consumer cursor digest. */
  readonly expectedCursorDigest?: string;
}

export interface CanonicalObjectReadOptions {
  readonly scopeChain: readonly string[];
}

export interface CanonicalObjectKnownAtOptions extends CanonicalObjectReadOptions {
  readonly knownAt: number;
}

export interface CanonicalClaimValidAtOptions extends CanonicalObjectKnownAtOptions {
  readonly validAt: number;
}

export interface RehydratedClaimProof {
  readonly claim: SelectedClaimProof;
  readonly evidence: readonly SelectedEvidenceProof[];
  readonly complete: boolean;
  readonly unavailableEvidenceIds: readonly string[];
  readonly proofDigest: string;
}

export interface CanonicalObjectReadIndexApplySummary {
  readonly appliedEvents: number;
  readonly changedObjects: number;
  readonly touchedHeadBuckets: number;
  readonly touchedVersionBuckets: number;
}

export interface CanonicalObjectReadIndexCatchUpSummary {
  readonly batches: number;
  readonly events: number;
  readonly changedObjects: number;
}

export interface CanonicalObjectReadIndexStatus {
  readonly initialized: boolean;
  readonly fresh: boolean;
  readonly reason: string;
  readonly registration?: DurableConsumerRegistration;
  readonly checkpoint?: DurableConsumerCheckpoint;
  readonly headCount: number;
  readonly versionCount: number;
  readonly headRootDigest?: string;
  readonly versionRootDigest?: string;
}

export interface CanonicalObjectReadIndexAudit {
  readonly ok: boolean;
  readonly errors: readonly string[];
  readonly headCount: number;
  readonly versionCount: number;
}

export interface ObjectReadMetaRow {
  readonly schema_version: unknown;
  readonly config_digest: unknown;
  readonly last_batch_id: unknown;
  readonly after_cursor_digest: unknown;
  readonly event_count: unknown;
  readonly head_count: unknown;
  readonly version_count: unknown;
  readonly head_root_digest: unknown;
  readonly version_root_digest: unknown;
}

export interface ObjectReadHeadRow {
  readonly kind: unknown;
  readonly object_id_json: unknown;
  readonly version_seq: unknown;
  readonly recorded_at: unknown;
  readonly state_digest: unknown;
  readonly version_digest: unknown;
  readonly head_digest: unknown;
  readonly bucket: unknown;
}

export interface ObjectReadVersionRow {
  readonly kind: unknown;
  readonly object_id_json: unknown;
  readonly version_seq: unknown;
  readonly recorded_at: unknown;
  readonly known_to: unknown;
  readonly state_json: unknown;
  readonly state_digest: unknown;
  readonly row_digest: unknown;
  readonly bucket: unknown;
}

export interface ObjectReadBucketRow {
  readonly tree_kind: unknown;
  readonly bucket: unknown;
  readonly item_count: unknown;
  readonly bucket_digest: unknown;
}

export interface ObjectReadNodeRow {
  readonly tree_kind: unknown;
  readonly level: unknown;
  readonly prefix: unknown;
  readonly item_count: unknown;
  readonly node_digest: unknown;
}

export interface DecodedObjectReadHead {
  readonly kind: CanonicalObjectKind;
  readonly canonicalId: string;
  readonly versionSeq: number;
  readonly recordedAt: number;
  readonly stateDigest: string;
  readonly versionDigest: string;
  readonly headDigest: string;
  readonly bucket: number;
}

export interface DecodedObjectReadVersion {
  readonly kind: CanonicalObjectKind;
  readonly canonicalId: string;
  readonly versionSeq: number;
  readonly recordedAt: number;
  readonly knownTo?: number;
  readonly state: IndexedCanonicalObjectState;
  readonly stateDigest: string;
  readonly rowDigest: string;
  readonly bucket: number;
}

export interface VerifiedObjectReadMeta {
  readonly schemaVersion: number;
  readonly configDigest: string;
  readonly lastBatchId: string;
  readonly afterCursorDigest: string;
  readonly eventCount: number;
  readonly headCount: number;
  readonly versionCount: number;
  readonly headRootDigest: string;
  readonly versionRootDigest: string;
}

export interface ObjectReadTreeValue {
  readonly digest: string;
  readonly itemCount: number;
}

export interface ObjectReadContext {
  readonly checkpoint: DurableConsumerCheckpoint;
  readonly meta: VerifiedObjectReadMeta;
}
