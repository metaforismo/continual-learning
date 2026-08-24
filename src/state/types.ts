import type {
  Authority,
  ClaimKey,
  ClaimRecord,
  EvidenceRole,
  JsonValue,
} from '../domain.js';

export type StateView = 'current' | 'historical';

export type StateStatus =
  | 'current'
  | 'historical'
  | 'disputed'
  | 'unknown-current'
  | 'unknown';

export type StateResolutionStrategy =
  | 'require-agreement'
  | 'latest-valid'
  | 'role-authority'
  | 'role-authority-then-latest';

export interface StateEvidenceRolePolicy {
  readonly role: EvidenceRole;
  /** Ordered from most authoritative to least authoritative for this slot and role. */
  readonly authorityPrecedence: readonly Authority[];
  readonly required?: boolean;
}

export interface StateSlotDefinition {
  readonly id: string;
  readonly domain: string;
  readonly key: ClaimKey;
  readonly strategy: StateResolutionStrategy;
  readonly evidencePolicy: readonly StateEvidenceRolePolicy[];
  readonly allowInferred?: boolean;
  readonly minimumConfidence?: number;
}

export interface StateInvalidationRule {
  readonly id: string;
  readonly sourceSlotId: string;
  readonly targetSlotId: string;
  readonly reason: string;
  /** Defaults to true: uncertain newer upstream state blocks stale downstream assumptions. */
  readonly propagateWhenSourceUncertain?: boolean;
}

export interface StateAdjudicationSchema {
  readonly id: string;
  readonly version: string;
  readonly slots: readonly StateSlotDefinition[];
  readonly invalidations?: readonly StateInvalidationRule[];
  readonly maxInvalidationHops?: number;
  readonly maxInvalidatedSlots?: number;
}

export interface StateRequest {
  readonly slotId: string;
  readonly view: StateView;
  /** World time being asked about. */
  readonly validAt: number;
  /** Transaction-time cutoff. Defaults to the complete known ledger. */
  readonly knownAt?: number;
  /** Optional premise embedded in the request that must not be trusted blindly. */
  readonly premise?: JsonValue;
}

export interface StateRoleRank {
  readonly role: EvidenceRole;
  /** Higher is stronger; -1 means no qualifying evidence for the role. */
  readonly rank: number;
  readonly authorities: readonly Authority[];
  readonly sourceIds: readonly string[];
}

export interface StateCandidateEvaluation {
  readonly claim: ClaimRecord;
  readonly eligible: boolean;
  readonly reasons: readonly string[];
  readonly roleRanks: readonly StateRoleRank[];
}

export interface StateValueGroupEvaluation {
  readonly value: JsonValue;
  readonly valueKey: string;
  readonly claimIds: readonly string[];
  readonly eligibleClaimIds: readonly string[];
  readonly eligible: boolean;
  readonly reasons: readonly string[];
  readonly roleRanks: readonly StateRoleRank[];
  readonly newestValidFrom: number;
  readonly highestConfidence: number;
}

export interface StateInvalidation {
  readonly ruleId: string;
  readonly sourceSlotId: string;
  readonly targetSlotId: string;
  readonly effectiveAt: number;
  readonly reason: string;
  readonly path: readonly string[];
  readonly sourceWasUncertain: boolean;
  readonly sourceClaimIds: readonly string[];
  readonly sourceEvidenceSourceIds: readonly string[];
}

export interface PremiseAssessment {
  readonly status: 'accepted' | 'rejected' | 'unsupported';
  readonly reason: string;
  readonly requested?: JsonValue;
  readonly authorized?: JsonValue;
}

export interface StateExplanation {
  readonly schemaId: string;
  readonly schemaVersion: string;
  readonly slotId: string;
  readonly strategy: StateResolutionStrategy;
  readonly reasons: readonly string[];
  readonly candidates: readonly StateCandidateEvaluation[];
  readonly valueGroups: readonly StateValueGroupEvaluation[];
  readonly selectedValueKey?: string;
}

export interface StateDecision {
  readonly slot: StateSlotDefinition;
  readonly request: StateRequest;
  readonly status: StateStatus;
  readonly claim?: ClaimRecord;
  readonly value?: JsonValue;
  readonly candidates: readonly ClaimRecord[];
  readonly invalidations: readonly StateInvalidation[];
  readonly premise: PremiseAssessment;
  readonly explanation: StateExplanation;
}

export interface StateContextPacketOptions {
  readonly id?: string;
  readonly activationScore?: number;
  readonly estimatedTokens?: number;
  readonly mandatory?: boolean;
  readonly risk?: 'low' | 'medium' | 'high';
  readonly topics?: readonly string[];
  readonly dependsOn?: readonly string[];
  /** Map canonical evidence source ids to source packet ids. */
  readonly evidencePacketIdBySourceId?: Readonly<Record<string, string>>;
  readonly enforceEvidenceDependencies?: boolean;
}
