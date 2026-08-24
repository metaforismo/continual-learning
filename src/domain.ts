export type JsonPrimitive = string | number | boolean | null;
export type JsonValue =
  | JsonPrimitive
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

export const EVENT_SCHEMA_VERSION = 1 as const;
export type EventSchemaVersion = typeof EVENT_SCHEMA_VERSION;

export type Authority =
  | 'model-inference'
  | 'repeated-observation'
  | 'external-source'
  | 'tool-verified'
  | 'human-explicit'
  | 'system-policy';

export const AUTHORITY_RANK: Readonly<Record<Authority, number>> = Object.freeze({
  'model-inference': 0,
  'repeated-observation': 1,
  'external-source': 2,
  'tool-verified': 3,
  'human-explicit': 4,
  'system-policy': 5,
});

export type EpistemicStatus =
  | 'observed'
  | 'inferred'
  | 'verified'
  | 'disputed'
  | 'unknown';

export type ClaimLifecycle =
  | 'quarantined'
  | 'active'
  | 'superseded'
  | 'revoked';

export interface ValidInterval {
  /** Inclusive Unix epoch milliseconds. */
  readonly from: number;
  /** Exclusive Unix epoch milliseconds. Omission means open-ended. */
  readonly to?: number;
}

export type EvidenceKind =
  | 'user-message'
  | 'assistant-message'
  | 'tool-call'
  | 'tool-result'
  | 'document'
  | 'source-span'
  | 'test-result'
  | 'human-feedback'
  | 'environment-transition'
  | 'trajectory'
  | 'other';

export type EvidenceSensitivity =
  | 'public'
  | 'internal'
  | 'personal'
  | 'sensitive'
  | 'secret';

export type EvidenceTaint =
  | 'untrusted-source'
  | 'external-content'
  | 'model-generated'
  | 'prompt-like'
  | 'secret-detected';

export interface ArtifactRef {
  /** Provider-owned stable location. Raw bytes do not live in the canonical event log. */
  readonly uri: string;
  /** Content address in the form sha256:<64 lowercase hex characters>. */
  readonly digest: string;
  readonly sizeBytes: number;
  readonly mediaType: string;
  readonly encryption: 'none' | 'provider-managed';
  readonly retention: 'durable' | 'reference-only' | 'ephemeral';
}

export interface EvidenceRecord {
  readonly id: string;
  readonly scope: string;
  readonly kind: EvidenceKind;
  /** Independent-origin groups represented by this evidence. Raw evidence has exactly one. */
  readonly sourceGroups: readonly string[];
  readonly authority: Authority;
  /** World time at which the source event or artifact was observed. */
  readonly observedAt: number;
  readonly sensitivity: EvidenceSensitivity;
  readonly taints: readonly EvidenceTaint[];
  readonly artifact: ArtifactRef;
  /** Bounded non-authoritative display aid. Never the canonical source bytes. */
  readonly preview?: string;
  readonly derivedFrom: readonly string[];
  readonly labels: readonly string[];
}

export type EvidenceAvailability = 'available' | 'restricted' | 'deleted';

export interface EvidenceRef {
  readonly sourceId: string;
  /** Exact independent-origin groups inherited from the captured evidence lineage. */
  readonly sourceGroups: readonly string[];
  readonly authority: Authority;
  readonly contentHash: string;
}

export interface ClaimKey {
  /** A stable scope such as global, user/francesco, or project/hephaestus. */
  readonly scope: string;
  readonly subject: string;
  readonly predicate: string;
}

export interface ClaimRecord {
  readonly id: string;
  readonly key: ClaimKey;
  readonly value: JsonValue;
  readonly valid: ValidInterval;
  readonly authority: Authority;
  readonly epistemicStatus: EpistemicStatus;
  readonly confidence: number;
  readonly evidence: readonly EvidenceRef[];
  readonly derivedFrom: readonly string[];
  readonly tags: readonly string[];
}

export interface AssociationRecord {
  readonly id: string;
  readonly scope: string;
  readonly from: string;
  readonly to: string;
  readonly kind:
    | 'semantic'
    | 'temporal'
    | 'causal'
    | 'procedural'
    | 'co-occurrence'
    | 'contradicts'
    | 'supports';
  readonly weight: number;
  readonly evidence: readonly EvidenceRef[];
}

export interface BaseEvent<TType extends string, TData> {
  readonly schemaVersion: EventSchemaVersion;
  readonly id: string;
  readonly seq: number;
  readonly type: TType;
  /** Transaction time: when this event entered the canonical ledger. */
  readonly recordedAt: number;
  readonly actor: string;
  readonly data: TData;
}

export type EvidenceCapturedEvent = BaseEvent<
  'evidence.captured',
  {
    readonly evidence: EvidenceRecord;
  }
>;

export type EvidenceAvailabilityChangedEvent = BaseEvent<
  'evidence.availability-changed',
  {
    readonly evidenceId: string;
    readonly availability: EvidenceAvailability;
    readonly reason: string;
  }
>;

export type ClaimAssertedEvent = BaseEvent<
  'claim.asserted',
  {
    readonly claim: ClaimRecord;
    readonly initialLifecycle: Extract<ClaimLifecycle, 'quarantined' | 'active'>;
  }
>;

export type ClaimAdmittedEvent = BaseEvent<
  'claim.admitted',
  {
    readonly claimId: string;
    readonly reason: string;
  }
>;

export type ClaimSupersededEvent = BaseEvent<
  'claim.superseded',
  {
    readonly previousClaimId: string;
    readonly replacementClaimId: string;
    /** World time at which the replacement became true. */
    readonly effectiveAt: number;
    readonly reason: string;
  }
>;

export type ClaimRevokedEvent = BaseEvent<
  'claim.revoked',
  {
    readonly claimId: string;
    readonly reason: string;
  }
>;

export type AssociationAddedEvent = BaseEvent<
  'association.added',
  {
    readonly association: AssociationRecord;
  }
>;

export type OutcomeRecordedEvent = BaseEvent<
  'outcome.recorded',
  {
    readonly scope: string;
    readonly subjectId: string;
    readonly taskId: string;
    readonly contextFingerprint: string;
    readonly sourceGroups: readonly string[];
    readonly outcome: 'success' | 'failure' | 'partial' | 'unknown';
    readonly verifier: 'none' | 'model' | 'tool' | 'test' | 'human';
    readonly evidence: readonly EvidenceRef[];
    readonly notes?: string;
  }
>;

export type MemoryEvent =
  | EvidenceCapturedEvent
  | EvidenceAvailabilityChangedEvent
  | ClaimAssertedEvent
  | ClaimAdmittedEvent
  | ClaimSupersededEvent
  | ClaimRevokedEvent
  | AssociationAddedEvent
  | OutcomeRecordedEvent;

export type MemoryEventInput = MemoryEvent extends infer TEvent
  ? TEvent extends MemoryEvent
    ? Omit<TEvent, 'seq' | 'schemaVersion'>
    : never
  : never;

export function claimKeyToString(key: ClaimKey): string {
  return `${key.scope}\u0000${key.subject}\u0000${key.predicate}`;
}

export function intervalContains(interval: ValidInterval, instant: number): boolean {
  return instant >= interval.from && (interval.to === undefined || instant < interval.to);
}

export function assertValidInterval(interval: ValidInterval): void {
  if (!Number.isFinite(interval.from)) {
    throw new TypeError('valid.from must be a finite number');
  }
  if (interval.to !== undefined) {
    if (!Number.isFinite(interval.to)) {
      throw new TypeError('valid.to must be a finite number when supplied');
    }
    if (interval.to <= interval.from) {
      throw new RangeError('valid.to must be greater than valid.from');
    }
  }
}
