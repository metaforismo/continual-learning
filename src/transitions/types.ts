import type {
  ClaimLifecycle,
  EvidenceAvailability,
  EvidenceRef,
  JsonValue,
  MemoryEvent,
  MemoryEventInput,
} from '../domain.js';
import type {
  StateAdjudicationSchema,
  StateRequest,
  StateStatus,
} from '../state/types.js';

export type TransitionRisk = 'low' | 'medium' | 'high' | 'destructive';
export type TransitionVerdict = 'accept' | 'quarantine' | 'human-review' | 'reject';
export type TransitionStateImpact = 'none' | 'declared' | 'unknown';

export type TransitionExternalCheckKind =
  | 'semantic-coverage'
  | 'semantic-preservation'
  | 'semantic-faithfulness'
  | 'security';

export type TransitionExternalCheckStatus = 'pass' | 'fail' | 'unknown';

export interface TransitionVerifierIdentity {
  readonly id: string;
  readonly actor: string;
  readonly kind: 'deterministic' | 'model' | 'tool' | 'human';
  readonly implementation: string;
  readonly version: string;
  /** Content address of the exact prompt/configuration/policy implementation. */
  readonly configDigest: string;
}

export interface IgnoredTransitionEvidence {
  readonly sourceId: string;
  readonly reason: string;
}

export interface TransitionExternalCheck {
  readonly id: string;
  readonly kind: TransitionExternalCheckKind;
  readonly status: TransitionExternalCheckStatus;
  readonly verifier: TransitionVerifierIdentity;
  readonly subjectIds: readonly string[];
  readonly reportDigest: string;
  /** Evidence that records the verifier result. It must explicitly play the `verifies` role. */
  readonly evidence: readonly EvidenceRef[];
  readonly notes?: string;
}

export interface StateSnapshotExpectation {
  readonly status?: StateStatus;
  readonly value?: JsonValue;
}

export interface TransitionStateExpectation {
  readonly id: string;
  readonly schema: StateAdjudicationSchema;
  readonly request: StateRequest;
  readonly mode: 'assert' | 'preserve' | 'change';
  readonly before?: StateSnapshotExpectation;
  readonly after?: StateSnapshotExpectation;
}

export interface TransitionProposal {
  readonly id: string;
  readonly proposer: string;
  readonly baseFingerprint: string;
  readonly authorizedScopes: readonly string[];
  readonly declaredRisk: TransitionRisk;
  readonly stateImpact: TransitionStateImpact;
  readonly operations: readonly MemoryEventInput[];
  /** Incoming evidence that the proposal was expected to consider. */
  readonly inputEvidenceIds: readonly string[];
  readonly ignoredInputEvidence: readonly IgnoredTransitionEvidence[];
  readonly externalChecks: readonly TransitionExternalCheck[];
  readonly stateExpectations: readonly TransitionStateExpectation[];
  readonly rationale: string;
}

export interface TransitionRequiredChecks {
  readonly low?: readonly TransitionExternalCheckKind[];
  readonly medium?: readonly TransitionExternalCheckKind[];
  readonly high?: readonly TransitionExternalCheckKind[];
  readonly destructive?: readonly TransitionExternalCheckKind[];
}

export interface TransitionVerificationPolicy {
  readonly id: string;
  readonly version: string;
  readonly maxOperations: number;
  readonly maxAuthorizedScopes: number;
  readonly maxInputEvidence: number;
  readonly maxExternalChecks: number;
  readonly maxStateExpectations: number;
  /** Maximum canonical JSON characters after the host-level raw request-size gate. */
  readonly maxProposalCharacters: number;
  readonly allowedEventTypes?: readonly MemoryEvent['type'][];
  readonly requireIndependentVerifier?: boolean;
  readonly requiredExternalChecks?: TransitionRequiredChecks;
  readonly humanReviewAtOrAbove?: TransitionRisk;
  readonly taintedActiveWritesRequireSecurityCheck?: boolean;
}

export type TransitionFindingCategory =
  | 'structure'
  | 'coverage'
  | 'preservation'
  | 'faithfulness'
  | 'authority'
  | 'scope'
  | 'temporal'
  | 'concurrency'
  | 'verification';

export interface TransitionFinding {
  readonly code: string;
  readonly category: TransitionFindingCategory;
  readonly severity: 'info' | 'warning' | 'error';
  readonly message: string;
  readonly objectIds: readonly string[];
}

export interface CreatedEvidenceDelta {
  readonly evidenceId: string;
  readonly availability: EvidenceAvailability;
}

export interface CreatedClaimDelta {
  readonly claimId: string;
  readonly lifecycle: ClaimLifecycle;
}

export interface ClaimLifecycleDelta {
  readonly claimId: string;
  readonly before: ClaimLifecycle;
  readonly after: ClaimLifecycle;
}

export interface EvidenceAvailabilityDelta {
  readonly evidenceId: string;
  readonly before: EvidenceAvailability;
  readonly after: EvidenceAvailability;
}

export interface TransitionDelta {
  readonly appendedEventIds: readonly string[];
  readonly appendedEventTypes: readonly MemoryEvent['type'][];
  readonly createdEvidence: readonly CreatedEvidenceDelta[];
  readonly evidenceAvailabilityChanges: readonly EvidenceAvailabilityDelta[];
  readonly createdClaims: readonly CreatedClaimDelta[];
  readonly claimLifecycleChanges: readonly ClaimLifecycleDelta[];
  readonly createdAssociationIds: readonly string[];
  readonly outcomeEventIds: readonly string[];
  readonly touchedScopes: readonly string[];
}

export interface StateSnapshotObservation {
  readonly status: StateStatus;
  readonly value?: JsonValue;
}

export interface TransitionStateObservation {
  readonly id: string;
  readonly mode: TransitionStateExpectation['mode'];
  readonly passed: boolean;
  readonly before: StateSnapshotObservation;
  readonly after: StateSnapshotObservation;
  readonly reasons: readonly string[];
}

export interface TransitionVerificationResult {
  readonly proposalId: string;
  readonly proposalDigest: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly policyDigest: string;
  readonly verifier: TransitionVerifierIdentity;
  readonly verdict: TransitionVerdict;
  readonly actualRisk: TransitionRisk;
  readonly baseFingerprint: string;
  readonly afterFingerprint?: string;
  readonly appendFingerprint?: string;
  readonly findings: readonly TransitionFinding[];
  readonly delta?: TransitionDelta;
  readonly stateObservations: readonly TransitionStateObservation[];
  readonly externalCheckIds: readonly string[];
  /** Newly staged canonical events only. The historical prefix is never copied into the verdict. */
  readonly stagedAppend?: readonly MemoryEvent[];
  readonly resultDigest: string;
}

export const TRANSITION_AUDIT_SCHEMA_VERSION = 1 as const;

export interface TransitionAuditRecord {
  readonly schemaVersion: typeof TRANSITION_AUDIT_SCHEMA_VERSION;
  readonly id: string;
  readonly seq: number;
  readonly recordedAt: number;
  readonly actor: string;
  readonly proposalId: string;
  readonly proposalDigest: string;
  readonly resultDigest: string;
  readonly verdict: TransitionVerdict;
  readonly actualRisk: TransitionRisk;
  readonly baseFingerprint: string;
  readonly afterFingerprint?: string;
  readonly appendFingerprint?: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly policyDigest: string;
  readonly verifierId: string;
  readonly verifierConfigDigest: string;
  readonly findingCodes: readonly string[];
}
