export type JsonPrimitive = string | number | boolean | null;
export type JsonValue =
  | JsonPrimitive
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

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

export interface EvidenceRef {
  readonly sourceId: string;
  /** Independent evidence should use a distinct sourceGroup. */
  readonly sourceGroup: string;
  readonly authority: Authority;
  readonly contentHash?: string;
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
  readonly id: string;
  readonly seq: number;
  readonly type: TType;
  /** Transaction time: when this event entered the canonical ledger. */
  readonly recordedAt: number;
  readonly actor: string;
  readonly data: TData;
}

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
    readonly subjectId: string;
    readonly taskId: string;
    readonly contextFingerprint: string;
    readonly sourceGroup: string;
    readonly outcome: 'success' | 'failure' | 'partial' | 'unknown';
    readonly verifier: 'none' | 'model' | 'tool' | 'test' | 'human';
    readonly notes?: string;
  }
>;

export type MemoryEvent =
  | ClaimAssertedEvent
  | ClaimAdmittedEvent
  | ClaimSupersededEvent
  | ClaimRevokedEvent
  | AssociationAddedEvent
  | OutcomeRecordedEvent;

export type MemoryEventInput = MemoryEvent extends infer TEvent
  ? TEvent extends MemoryEvent
    ? Omit<TEvent, 'seq'>
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
