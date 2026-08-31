import {
  AUTHORITY_RANK,
  evidenceRoles,
  type Authority,
  type EvidenceRef,
  type EvidenceRole,
  type EvidenceSensitivity,
  type EvidenceTaint,
  type MemoryEvent,
} from '../domain.js';
import { EvidenceProjection } from '../evidence.js';
import { MemoryKernel } from '../kernel.js';
import { canonicalJson, contentDigest } from '../retrieval/canonical.js';
import { fingerprintMemoryEvents } from '../transitions/verifier.js';
import {
  isIssuedBoundedCanaryPlan,
  isIssuedCanaryPlanReview,
  type CanaryAssignment,
  type CanaryStopAction,
  type CanaryPlanReview,
  type BoundedCanaryPlan,
  type VerifiedCanaryRuntimeIdentity,
} from './bounded-canary-plans-api.js';
import type { ProcedureEvidenceBinding } from './verified-procedure-candidates-api.js';

export const CANONICAL_CANARY_RECEIPT_SCHEMA_VERSION = 1 as const;

export type CanaryArm = Extract<CanaryAssignment, 'treatment' | 'control'>;

const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const MAX_INPUT_CHARACTERS = 1_000_000;
const MAX_IDENTIFIER_CHARACTERS = 512;
const MAX_TEXT_CHARACTERS = 4_096;
const MAX_EVIDENCE_REFERENCES = 256;
const MAX_OBSERVATIONS_PER_EVALUATION = 4_096;
const TERMINAL_STATUSES = new Set([
  'success',
  'failure',
  'aborted',
  'timed-out',
  'rolled-back',
]);
const ROLLBACK_OUTCOMES = new Set(['succeeded', 'partial', 'failed']);
const COMPARATORS = new Set(['gt', 'gte', 'lt', 'lte', 'eq']);


const issuedAdmissions = new WeakSet<object>();
const issuedStarts = new WeakSet<object>();
const issuedCompletions = new WeakSet<object>();
const issuedObservations = new WeakSet<object>();
const issuedEvaluations = new WeakSet<object>();
const issuedRollbacks = new WeakSet<object>();
const issuedOutcomes = new WeakSet<object>();

export interface CanaryAdmissionReceiptInput {
  readonly id: string;
  readonly subjectDigest: string;
  readonly assignmentDigest: string;
  readonly hostAdmissionDigest: string;
  readonly evidence: readonly EvidenceRef[];
  readonly canonicalFingerprint: string;
  readonly actor: string;
  readonly admittedAt: number;
}

export interface VerifiedCanaryAdmissionReceipt {
  readonly schemaVersion: typeof CANONICAL_CANARY_RECEIPT_SCHEMA_VERSION;
  readonly id: string;
  readonly scope: string;
  readonly planId: string;
  readonly planDigest: string;
  readonly reviewId: string;
  readonly reviewDigest: string;
  readonly procedureCandidateDigest: string;
  readonly subjectDigest: string;
  readonly arm: CanaryArm;
  readonly assignmentDigest: string;
  readonly populationManifestDigest: string;
  readonly runtimeIdentityDigest: string;
  readonly schedulerDigest: string;
  readonly hostAdmissionDigest: string;
  readonly evidence: readonly ProcedureEvidenceBinding[];
  readonly canonicalFingerprint: string;
  readonly actor: string;
  readonly admittedAt: number;
  readonly status: 'admitted';
  readonly externalHostActionObserved: true;
  readonly hostSchedulingAuthorized: false;
  readonly procedurePromotionAuthorized: false;
  readonly executionAuthorized: false;
  readonly receiptDigest: string;
}

export interface CanaryRunnerIdentityInput {
  readonly id: string;
  readonly digest: string;
  readonly evidence: readonly EvidenceRef[];
}

export interface VerifiedCanaryRunnerIdentity
  extends Omit<CanaryRunnerIdentityInput, 'evidence'> {
  readonly evidence: readonly ProcedureEvidenceBinding[];
  readonly identityDigest: string;
}

export interface CanaryRunStartReceiptInput {
  readonly id: string;
  readonly runId: string;
  readonly attempt: number;
  readonly runner: CanaryRunnerIdentityInput;
  readonly environmentDigest: string;
  readonly executionGrantDigest: string;
  readonly grantEvidence: readonly EvidenceRef[];
  readonly canonicalFingerprint: string;
  readonly actor: string;
  readonly startedAt: number;
}

export interface VerifiedCanaryRunStartReceipt {
  readonly schemaVersion: typeof CANONICAL_CANARY_RECEIPT_SCHEMA_VERSION;
  readonly id: string;
  readonly scope: string;
  readonly planId: string;
  readonly planDigest: string;
  readonly reviewDigest: string;
  readonly admissionId: string;
  readonly admissionReceiptDigest: string;
  readonly runId: string;
  readonly subjectDigest: string;
  readonly arm: CanaryArm;
  readonly attempt: number;
  readonly runner: VerifiedCanaryRunnerIdentity;
  readonly environmentDigest: string;
  readonly executionGrantDigest: string;
  readonly grantEvidence: readonly ProcedureEvidenceBinding[];
  readonly canonicalFingerprint: string;
  readonly actor: string;
  readonly startedAt: number;
  readonly status: 'started';
  readonly externalExecutionGrantObserved: true;
  readonly hostSchedulingAuthorized: false;
  readonly procedurePromotionAuthorized: false;
  readonly executionAuthorized: false;
  readonly receiptDigest: string;
}

export type CanaryRunTerminalStatus =
  | 'success'
  | 'failure'
  | 'aborted'
  | 'timed-out'
  | 'rolled-back';

export interface CanaryRunCompletionReceiptInput {
  readonly id: string;
  readonly runId: string;
  readonly terminalStatus: CanaryRunTerminalStatus;
  readonly costMicrounits: number;
  readonly toolCalls: number;
  readonly externalRunReceiptDigest: string;
  readonly evidence: readonly EvidenceRef[];
  readonly canonicalFingerprint: string;
  readonly actor: string;
  readonly completedAt: number;
}

export interface VerifiedCanaryRunCompletionReceipt {
  readonly schemaVersion: typeof CANONICAL_CANARY_RECEIPT_SCHEMA_VERSION;
  readonly id: string;
  readonly scope: string;
  readonly planId: string;
  readonly planDigest: string;
  readonly reviewDigest: string;
  readonly startId: string;
  readonly startReceiptDigest: string;
  readonly runId: string;
  readonly subjectDigest: string;
  readonly arm: CanaryArm;
  readonly attempt: number;
  readonly terminalStatus: CanaryRunTerminalStatus;
  readonly costMicrounits: number;
  readonly cumulativeCostMicrounits: number;
  readonly toolCalls: number;
  readonly durationMs: number;
  readonly limitBreaches: readonly string[];
  readonly externalRunReceiptDigest: string;
  readonly evidence: readonly ProcedureEvidenceBinding[];
  readonly canonicalFingerprint: string;
  readonly actor: string;
  readonly completedAt: number;
  readonly status: 'completed';
  readonly externalHostActionObserved: true;
  readonly hostSchedulingAuthorized: false;
  readonly procedurePromotionAuthorized: false;
  readonly executionAuthorized: false;
  readonly receiptDigest: string;
}

export interface CanaryMonitoringObservationInput {
  readonly id: string;
  readonly metric: string;
  readonly sequence: number;
  readonly value: number;
  readonly sampleCount: number;
  readonly observerDigest: string;
  readonly externalObservationDigest: string;
  readonly evidence: readonly EvidenceRef[];
  readonly canonicalFingerprint: string;
  readonly actor: string;
  readonly observedAt: number;
}

export interface VerifiedCanaryMonitoringObservation {
  readonly schemaVersion: typeof CANONICAL_CANARY_RECEIPT_SCHEMA_VERSION;
  readonly id: string;
  readonly scope: string;
  readonly planId: string;
  readonly planDigest: string;
  readonly reviewDigest: string;
  readonly metric: string;
  readonly sequence: number;
  readonly value: number;
  readonly sampleCount: number;
  readonly observerIdentityDigest: string;
  readonly externalObservationDigest: string;
  readonly evidence: readonly ProcedureEvidenceBinding[];
  readonly canonicalFingerprint: string;
  readonly actor: string;
  readonly observedAt: number;
  readonly status: 'observed';
  readonly hostSchedulingAuthorized: false;
  readonly procedurePromotionAuthorized: false;
  readonly executionAuthorized: false;
  readonly receiptDigest: string;
}

export interface CanaryStopEvaluationInput {
  readonly id: string;
  readonly conditionId: string;
  readonly observationIds: readonly string[];
  readonly canonicalFingerprint: string;
  readonly actor: string;
  readonly evaluatedAt: number;
}

export interface VerifiedCanaryStopEvaluation {
  readonly schemaVersion: typeof CANONICAL_CANARY_RECEIPT_SCHEMA_VERSION;
  readonly id: string;
  readonly scope: string;
  readonly planId: string;
  readonly planDigest: string;
  readonly reviewDigest: string;
  readonly conditionId: string;
  readonly conditionDigest: string;
  readonly metric: string;
  readonly comparator: 'gt' | 'gte' | 'lt' | 'lte' | 'eq';
  readonly threshold: number;
  readonly minimumSamples: number;
  readonly observationIds: readonly string[];
  readonly observationSetDigest: string;
  readonly latestObservationId?: string;
  readonly latestSequence?: number;
  readonly latestValue?: number;
  readonly latestSampleCount?: number;
  readonly triggered: boolean;
  readonly action: CanaryStopAction | 'continue';
  readonly canonicalFingerprint: string;
  readonly actor: string;
  readonly evaluatedAt: number;
  readonly status: 'evaluated';
  readonly hostSchedulingAuthorized: false;
  readonly procedurePromotionAuthorized: false;
  readonly executionAuthorized: false;
  readonly evaluationDigest: string;
}

export type CanaryRollbackOutcome = 'succeeded' | 'partial' | 'failed';

export interface CanaryRollbackReceiptInput {
  readonly id: string;
  readonly evaluationId: string;
  readonly controllerDigest: string;
  readonly externalRollbackDigest: string;
  readonly outcome: CanaryRollbackOutcome;
  readonly evidence: readonly EvidenceRef[];
  readonly canonicalFingerprint: string;
  readonly actor: string;
  readonly startedAt: number;
  readonly completedAt: number;
}

export interface VerifiedCanaryRollbackReceipt {
  readonly schemaVersion: typeof CANONICAL_CANARY_RECEIPT_SCHEMA_VERSION;
  readonly id: string;
  readonly scope: string;
  readonly planId: string;
  readonly planDigest: string;
  readonly reviewDigest: string;
  readonly evaluationId: string;
  readonly evaluationDigest: string;
  readonly conditionId: string;
  readonly controllerDigest: string;
  readonly externalRollbackDigest: string;
  readonly outcome: CanaryRollbackOutcome;
  readonly evidence: readonly ProcedureEvidenceBinding[];
  readonly canonicalFingerprint: string;
  readonly actor: string;
  readonly startedAt: number;
  readonly completedAt: number;
  readonly durationMs: number;
  readonly status: 'rollback-recorded';
  readonly externalHostActionObserved: true;
  readonly hostSchedulingAuthorized: false;
  readonly procedurePromotionAuthorized: false;
  readonly executionAuthorized: false;
  readonly receiptDigest: string;
}

export interface CanaryOutcomeVerificationInput {
  readonly id: string;
  readonly completionId: string;
  readonly outcomeEventId: string;
  readonly verifierDigest: string;
  readonly externalVerificationDigest: string;
  readonly evidence: readonly EvidenceRef[];
  readonly canonicalFingerprint: string;
  readonly actor: string;
  readonly verifiedAt: number;
}

export interface VerifiedCanaryOutcomeReceipt {
  readonly schemaVersion: typeof CANONICAL_CANARY_RECEIPT_SCHEMA_VERSION;
  readonly id: string;
  readonly scope: string;
  readonly planId: string;
  readonly planDigest: string;
  readonly reviewDigest: string;
  readonly completionId: string;
  readonly completionReceiptDigest: string;
  readonly runId: string;
  readonly subjectDigest: string;
  readonly arm: CanaryArm;
  readonly outcomeEventId: string;
  readonly outcome: 'success' | 'partial' | 'failure' | 'unknown';
  readonly verifierDigest: string;
  readonly externalVerificationDigest: string;
  readonly evidence: readonly ProcedureEvidenceBinding[];
  readonly sourceGroups: readonly string[];
  readonly canonicalFingerprint: string;
  readonly actor: string;
  readonly verifiedAt: number;
  readonly status: 'outcome-verified';
  readonly procedurePromotionAuthorized: false;
  readonly hostSchedulingAuthorized: false;
  readonly executionAuthorized: false;
  readonly receiptDigest: string;
}

interface EvidenceContext {
  readonly historical: EvidenceProjection;
  readonly current: EvidenceProjection;
  readonly scope: string;
  totalReferences: number;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as unknown as Record<string, unknown>)) {
      deepFreeze(child);
    }
    Object.freeze(value);
  }
  return value;
}

function canonicalSnapshot<T>(value: T, label: string): T {
  const encoded = canonicalJson(value);
  if (encoded.length > MAX_INPUT_CHARACTERS) {
    throw new RangeError(`${label} cannot exceed ${MAX_INPUT_CHARACTERS} canonical characters`);
  }
  return deepFreeze(JSON.parse(encoded) as T);
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

function assertText(value: unknown, label: string, maximum = MAX_IDENTIFIER_CHARACTERS): asserts value is string {
  if (
    typeof value !== 'string' ||
    value.trim().length === 0 ||
    value.length > maximum ||
    value.includes('\u0000') ||
    !isWellFormedUnicode(value)
  ) {
    throw new Error(`${label} must be non-empty well-formed text within ${maximum} characters`);
  }
}

function assertDigest(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || !SHA256_PATTERN.test(value)) {
    throw new Error(`${label} must be a SHA-256 content address`);
  }
}

function assertSafeInteger(
  value: unknown,
  label: string,
  minimum = 0,
  maximum = Number.MAX_SAFE_INTEGER,
): asserts value is number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw new Error(`${label} must be a safe integer in ${minimum}..${maximum}`);
  }
}

function assertFiniteNumber(value: unknown, label: string): asserts value is number {
  if (typeof value !== 'number' || !Number.isFinite(value) || Object.is(value, -0)) {
    throw new Error(`${label} must be a finite canonical number`);
  }
}

function assertReadyPlan(
  plan: BoundedCanaryPlan,
  review: CanaryPlanReview,
): void {
  if (!isIssuedBoundedCanaryPlan(plan)) {
    throw new Error('canary receipt requires an issued bounded canary plan capability');
  }
  if (!isIssuedCanaryPlanReview(review)) {
    throw new Error('canary receipt requires an issued bounded canary review capability');
  }
  if (review.planId !== plan.id || review.planDigest !== plan.planDigest) {
    throw new Error('canary review does not bind the supplied plan');
  }
  if (
    review.decision !== 'approve' ||
    review.recommendation !== 'ready-for-host-scheduling'
  ) {
    throw new Error('canary host receipts require a ready-for-host-scheduling review');
  }
  if (
    plan.executable !== false ||
    plan.hostSchedulingAuthorized !== false ||
    plan.procedurePromotionAuthorized !== false ||
    plan.executionAuthorized !== false ||
    review.executable !== false ||
    review.hostSchedulingAuthorized !== false ||
    review.procedurePromotionAuthorized !== false ||
    review.executionAuthorized !== false
  ) {
    throw new Error('canary plan or review authority boundary is invalid');
  }
}

function assertCanonicalPrefix(
  events: readonly MemoryEvent[],
  eventCount: number,
  expectedFingerprint: string,
  label: string,
): void {
  if (!Number.isSafeInteger(eventCount) || eventCount < 0 || eventCount > events.length) {
    throw new Error(`${label} canonical event count is outside the supplied history`);
  }
  if (fingerprintMemoryEvents(events.slice(0, eventCount)) !== expectedFingerprint) {
    throw new Error(`${label} canonical prefix is stale, truncated, or forked`);
  }
}

function assertCurrentEvidenceIds(
  sourceIds: readonly string[],
  projection: EvidenceProjection,
  scope: string,
  label: string,
): void {
  for (const sourceId of [...new Set(sourceIds)].sort()) {
    const projected = projection.get(sourceId);
    if (projected === undefined || projected.availability !== 'available') {
      throw new Error(`${label} is not currently available: ${sourceId}`);
    }
    if (projected.record.scope !== 'global' && projected.record.scope !== scope) {
      throw new Error(`${label} crosses scope through ${sourceId}`);
    }
  }
}

function canonicalEvents(
  eventsInput: readonly MemoryEvent[],
  canonicalFingerprint: string,
  plan: BoundedCanaryPlan,
  review: CanaryPlanReview,
): readonly MemoryEvent[] {
  assertDigest(canonicalFingerprint, 'canary receipt canonicalFingerprint');
  const events = MemoryKernel.from(eventsInput).events();
  if (fingerprintMemoryEvents(events) !== canonicalFingerprint) {
    throw new Error('canary receipt canonical fingerprint is stale or forged');
  }
  assertCanonicalPrefix(
    events,
    plan.canonicalEventCount,
    plan.canonicalFingerprint,
    'canary plan',
  );
  assertCanonicalPrefix(
    events,
    review.canonicalEventCount,
    review.canonicalFingerprint,
    'canary review',
  );
  const current = EvidenceProjection.from(events);
  assertCurrentEvidenceIds(
    [
      ...plan.inheritedSourceEvidenceIds,
      ...plan.planSourceEvidenceIds,
      ...review.evidence.map((binding) => binding.sourceId),
    ],
    current,
    plan.scope,
    'canary plan or review evidence',
  );
  return events;
}

function evidenceContext(
  events: readonly MemoryEvent[],
  recordedAt: number,
  scope: string,
): EvidenceContext {
  return {
    historical: EvidenceProjection.from(events, recordedAt),
    current: EvidenceProjection.from(events),
    scope,
    totalReferences: 0,
  };
}

function normalizeEvidence(
  referencesInput: readonly EvidenceRef[],
  context: EvidenceContext,
  label: string,
  requiredRoles: readonly EvidenceRole[],
  exactDigest?: string,
  minimumAuthority: Authority = 'external-source',
): readonly ProcedureEvidenceBinding[] {
  if (
    !Array.isArray(referencesInput) ||
    referencesInput.length === 0 ||
    referencesInput.length > 32
  ) {
    throw new Error(`${label} requires 1..32 evidence references`);
  }
  context.totalReferences += referencesInput.length;
  if (context.totalReferences > MAX_EVIDENCE_REFERENCES) {
    throw new RangeError(`canary receipt cannot exceed ${MAX_EVIDENCE_REFERENCES} evidence references`);
  }
  const seen = new Set<string>();
  const bindings: ProcedureEvidenceBinding[] = [];
  for (const reference of referencesInput) {
    if (typeof reference !== 'object' || reference === null) {
      throw new Error(`${label} contains a malformed evidence reference`);
    }
    assertText(reference.sourceId, `${label} sourceId`);
    if (seen.has(reference.sourceId)) throw new Error(`${label} repeats ${reference.sourceId}`);
    seen.add(reference.sourceId);
    if (!context.historical.validatesReference(reference)) {
      throw new Error(`${label} was unavailable or forged at receipt time: ${reference.sourceId}`);
    }
    if (!context.current.validatesReference(reference)) {
      throw new Error(`${label} is not currently available: ${reference.sourceId}`);
    }
    const projected = context.current.get(reference.sourceId);
    if (projected === undefined) throw new Error(`${label} references unknown evidence`);
    if (projected.record.scope !== 'global' && projected.record.scope !== context.scope) {
      throw new Error(`${label} crosses scope through ${reference.sourceId}`);
    }
    if (projected.record.sensitivity === 'secret' || projected.record.taints.includes('secret-detected')) {
      throw new Error(`${label} cannot use secret evidence`);
    }
    const roles = Object.freeze([...evidenceRoles(reference)].sort()) as readonly EvidenceRole[];
    if (roles.includes('contradicts') || !roles.some((role) => requiredRoles.includes(role))) {
      throw new Error(`${label} lacks the required positive evidence role`);
    }
    if (AUTHORITY_RANK[projected.record.authority] < AUTHORITY_RANK[minimumAuthority]) {
      throw new Error(`${label} lacks ${minimumAuthority} authority or stronger`);
    }
    bindings.push(
      Object.freeze({
        sourceId: projected.record.id,
        sourceGroups: Object.freeze([...projected.record.sourceGroups]),
        authority: projected.record.authority,
        contentHash: projected.record.artifact.digest,
        roles,
        sensitivity: projected.record.sensitivity,
        taints: Object.freeze([...projected.record.taints]),
      }),
    );
  }
  if (exactDigest !== undefined && !bindings.some((binding) => binding.contentHash === exactDigest)) {
    throw new Error(`${label} does not bind the declared receipt digest`);
  }
  return Object.freeze(bindings.sort((left, right) => left.sourceId.localeCompare(right.sourceId)));
}

function normalizeRunner(
  input: CanaryRunnerIdentityInput,
  context: EvidenceContext,
): VerifiedCanaryRunnerIdentity {
  if (typeof input !== 'object' || input === null) throw new Error('canary runner identity must be an object');
  assertText(input.id, 'canary runner id');
  assertDigest(input.digest, 'canary runner digest');
  const evidence = normalizeEvidence(
    input.evidence,
    context,
    'canary runner identity evidence',
    ['verifies'],
    input.digest,
    'tool-verified',
  );
  const unsigned = { id: input.id, digest: input.digest, evidence };
  return Object.freeze({
    ...unsigned,
    identityDigest: contentDigest({ domain: 'cl-canary-runner-identity-v1', identity: unsigned }),
  });
}

function sourceGroups(bindings: readonly ProcedureEvidenceBinding[]): readonly string[] {
  return Object.freeze([...new Set(bindings.flatMap((binding) => binding.sourceGroups))].sort());
}

function requireRuntimeComponentSourceContinuity(
  bindings: readonly ProcedureEvidenceBinding[],
  identity: VerifiedCanaryRuntimeIdentity,
  componentDigest: string,
  label: string,
): void {
  const componentBindings = identity.evidence.filter(
    (binding) => binding.contentHash === componentDigest,
  );
  if (componentBindings.length === 0) {
    throw new Error(`${label} has no planned component evidence`);
  }
  const expected = new Set(componentBindings.flatMap((binding) => binding.sourceGroups));
  if (!bindings.some((binding) => binding.sourceGroups.some((group) => expected.has(group)))) {
    throw new Error(`${label} is not linked to the planned component source family`);
  }
}

function comparatorApplies(
  comparator: 'gt' | 'gte' | 'lt' | 'lte' | 'eq',
  value: number,
  threshold: number,
): boolean {
  if (!COMPARATORS.has(comparator)) throw new Error('canary stop comparator is invalid');
  switch (comparator) {
    case 'gt':
      return value > threshold;
    case 'gte':
      return value >= threshold;
    case 'lt':
      return value < threshold;
    case 'lte':
      return value <= threshold;
    case 'eq':
      return value === threshold;
  }
}

export function createCanaryAdmissionReceipt(
  eventsInput: readonly MemoryEvent[],
  plan: BoundedCanaryPlan,
  review: CanaryPlanReview,
  input: CanaryAdmissionReceiptInput,
): VerifiedCanaryAdmissionReceipt {
  assertReadyPlan(plan, review);
  const request = canonicalSnapshot(input, 'canary admission receipt input');
  assertText(request.id, 'canary admission receipt id');
  assertDigest(request.subjectDigest, 'canary admission subjectDigest');
  assertDigest(request.assignmentDigest, 'canary admission assignmentDigest');
  assertDigest(request.hostAdmissionDigest, 'canary hostAdmissionDigest');
  assertText(request.actor, 'canary admission actor');
  assertSafeInteger(request.admittedAt, 'canary admittedAt', review.recordedAt);
  const assignment = plan.population.subjects.find(
    (candidate) => candidate.subjectDigest === request.subjectDigest,
  );
  if (
    assignment === undefined ||
    !assignment.applicable ||
    (assignment.assignment !== 'treatment' && assignment.assignment !== 'control') ||
    assignment.assignmentDigest !== request.assignmentDigest
  ) {
    throw new Error('canary admission does not match the deterministic plan assignment');
  }
  const arm: CanaryArm = assignment.assignment;
  const events = canonicalEvents(eventsInput, request.canonicalFingerprint, plan, review);
  const context = evidenceContext(events, request.admittedAt, plan.scope);
  const evidence = normalizeEvidence(
    request.evidence,
    context,
    'canary host admission evidence',
    ['verifies'],
    request.hostAdmissionDigest,
    'tool-verified',
  );
  requireRuntimeComponentSourceContinuity(
    evidence,
    plan.runtime,
    plan.runtime.schedulerDigest,
    'canary host admission evidence',
  );
  const unsigned = {
    schemaVersion: CANONICAL_CANARY_RECEIPT_SCHEMA_VERSION,
    id: request.id,
    scope: plan.scope,
    planId: plan.id,
    planDigest: plan.planDigest,
    reviewId: review.id,
    reviewDigest: review.reviewDigest,
    procedureCandidateDigest: plan.candidateDigest,
    subjectDigest: request.subjectDigest,
    arm,
    assignmentDigest: assignment.assignmentDigest,
    populationManifestDigest: plan.population.manifestDigest,
    runtimeIdentityDigest: plan.runtime.identityDigest,
    schedulerDigest: plan.runtime.schedulerDigest,
    hostAdmissionDigest: request.hostAdmissionDigest,
    evidence,
    canonicalFingerprint: request.canonicalFingerprint,
    actor: request.actor,
    admittedAt: request.admittedAt,
    status: 'admitted' as const,
    externalHostActionObserved: true as const,
    hostSchedulingAuthorized: false as const,
    procedurePromotionAuthorized: false as const,
    executionAuthorized: false as const,
  };
  const receipt = canonicalSnapshot<VerifiedCanaryAdmissionReceipt>(
    {
      ...unsigned,
      receiptDigest: contentDigest({ domain: 'cl-canary-admission-receipt-v1', receipt: unsigned }),
    },
    'verified canary admission receipt',
  );
  issuedAdmissions.add(receipt as object);
  return receipt;
}

export function recordCanaryRunStartReceipt(
  eventsInput: readonly MemoryEvent[],
  plan: BoundedCanaryPlan,
  review: CanaryPlanReview,
  admission: VerifiedCanaryAdmissionReceipt,
  input: CanaryRunStartReceiptInput,
): VerifiedCanaryRunStartReceipt {
  assertReadyPlan(plan, review);
  if (!isIssuedCanaryAdmissionReceipt(admission)) {
    throw new Error('canary run start requires an issued admission receipt');
  }
  if (admission.planDigest !== plan.planDigest || admission.reviewDigest !== review.reviewDigest) {
    throw new Error('canary admission receipt belongs to another plan or review');
  }
  const request = canonicalSnapshot(input, 'canary run start receipt input');
  assertText(request.id, 'canary run start receipt id');
  assertText(request.runId, 'canary run id');
  assertSafeInteger(request.attempt, 'canary run attempt', 1, (plan.budget.maxRetriesPerSubject + 1));
  assertDigest(request.environmentDigest, 'canary environmentDigest');
  if (request.environmentDigest !== plan.runtime.environmentDigest) {
    throw new Error('canary run start does not use the planned environment digest');
  }
  assertDigest(request.executionGrantDigest, 'canary executionGrantDigest');
  assertText(request.actor, 'canary run start actor');
  assertSafeInteger(request.startedAt, 'canary startedAt', admission.admittedAt);
  const events = canonicalEvents(eventsInput, request.canonicalFingerprint, plan, review);
  const context = evidenceContext(events, request.startedAt, plan.scope);
  const runner = normalizeRunner(request.runner, context);
  const grantEvidence = normalizeEvidence(
    request.grantEvidence,
    context,
    'canary external execution grant evidence',
    ['verifies'],
    request.executionGrantDigest,
    'tool-verified',
  );
  requireRuntimeComponentSourceContinuity(
    grantEvidence,
    plan.runtime,
    plan.runtime.schedulerDigest,
    'canary execution grant evidence',
  );
  const unsigned = {
    schemaVersion: CANONICAL_CANARY_RECEIPT_SCHEMA_VERSION,
    id: request.id,
    scope: plan.scope,
    planId: plan.id,
    planDigest: plan.planDigest,
    reviewDigest: review.reviewDigest,
    admissionId: admission.id,
    admissionReceiptDigest: admission.receiptDigest,
    runId: request.runId,
    subjectDigest: admission.subjectDigest,
    arm: admission.arm,
    attempt: request.attempt,
    runner,
    environmentDigest: request.environmentDigest,
    executionGrantDigest: request.executionGrantDigest,
    grantEvidence,
    canonicalFingerprint: request.canonicalFingerprint,
    actor: request.actor,
    startedAt: request.startedAt,
    status: 'started' as const,
    externalExecutionGrantObserved: true as const,
    hostSchedulingAuthorized: false as const,
    procedurePromotionAuthorized: false as const,
    executionAuthorized: false as const,
  };
  const receipt = canonicalSnapshot<VerifiedCanaryRunStartReceipt>(
    {
      ...unsigned,
      receiptDigest: contentDigest({ domain: 'cl-canary-run-start-receipt-v1', receipt: unsigned }),
    },
    'verified canary run start receipt',
  );
  issuedStarts.add(receipt as object);
  return receipt;
}

export function recordCanaryRunCompletionReceipt(
  eventsInput: readonly MemoryEvent[],
  plan: BoundedCanaryPlan,
  review: CanaryPlanReview,
  start: VerifiedCanaryRunStartReceipt,
  input: CanaryRunCompletionReceiptInput,
  priorCumulativeCostMicrounits = 0,
): VerifiedCanaryRunCompletionReceipt {
  assertReadyPlan(plan, review);
  if (!isIssuedCanaryRunStartReceipt(start)) {
    throw new Error('canary run completion requires an issued run start receipt');
  }
  if (start.planDigest !== plan.planDigest || start.reviewDigest !== review.reviewDigest) {
    throw new Error('canary run start belongs to another plan or review');
  }
  const request = canonicalSnapshot(input, 'canary run completion receipt input');
  assertText(request.id, 'canary completion receipt id');
  assertText(request.runId, 'canary completion runId');
  if (request.runId !== start.runId) throw new Error('canary completion runId differs from its start receipt');
  if (!TERMINAL_STATUSES.has(request.terminalStatus)) throw new Error('canary terminalStatus is invalid');
  assertSafeInteger(request.costMicrounits, 'canary completion costMicrounits');
  assertSafeInteger(request.toolCalls, 'canary completion toolCalls');
  assertSafeInteger(priorCumulativeCostMicrounits, 'prior cumulative canary cost');
  assertDigest(request.externalRunReceiptDigest, 'canary externalRunReceiptDigest');
  assertText(request.actor, 'canary completion actor');
  assertSafeInteger(request.completedAt, 'canary completedAt', start.startedAt);
  const events = canonicalEvents(eventsInput, request.canonicalFingerprint, plan, review);
  const context = evidenceContext(events, request.completedAt, plan.scope);
  const evidence = normalizeEvidence(
    request.evidence,
    context,
    'canary external run completion evidence',
    ['verifies'],
    request.externalRunReceiptDigest,
    'tool-verified',
  );
  const runnerGroups = new Set(start.runner.evidence.flatMap((binding) => binding.sourceGroups));
  if (!evidence.some((binding) => binding.sourceGroups.some((group) => runnerGroups.has(group)))) {
    throw new Error('canary completion evidence is not linked to the admitted runner source family');
  }
  const durationMs = request.completedAt - start.startedAt;
  const cumulativeCostMicrounits = priorCumulativeCostMicrounits + request.costMicrounits;
  if (!Number.isSafeInteger(cumulativeCostMicrounits)) {
    throw new Error('cumulative canary cost exceeds the safe integer range');
  }
  const limitBreaches: string[] = [];
  if (durationMs > plan.budget.maxDurationMs) limitBreaches.push('duration');
  if (request.toolCalls > plan.budget.maxToolCalls) limitBreaches.push('tool-calls');
  if (cumulativeCostMicrounits > plan.budget.maxCostMicros) limitBreaches.push('plan-cost');
  const unsigned = {
    schemaVersion: CANONICAL_CANARY_RECEIPT_SCHEMA_VERSION,
    id: request.id,
    scope: plan.scope,
    planId: plan.id,
    planDigest: plan.planDigest,
    reviewDigest: review.reviewDigest,
    startId: start.id,
    startReceiptDigest: start.receiptDigest,
    runId: start.runId,
    subjectDigest: start.subjectDigest,
    arm: start.arm,
    attempt: start.attempt,
    terminalStatus: request.terminalStatus,
    costMicrounits: request.costMicrounits,
    cumulativeCostMicrounits,
    toolCalls: request.toolCalls,
    durationMs,
    limitBreaches: Object.freeze(limitBreaches),
    externalRunReceiptDigest: request.externalRunReceiptDigest,
    evidence,
    canonicalFingerprint: request.canonicalFingerprint,
    actor: request.actor,
    completedAt: request.completedAt,
    status: 'completed' as const,
    externalHostActionObserved: true as const,
    hostSchedulingAuthorized: false as const,
    procedurePromotionAuthorized: false as const,
    executionAuthorized: false as const,
  };
  const receipt = canonicalSnapshot<VerifiedCanaryRunCompletionReceipt>(
    {
      ...unsigned,
      receiptDigest: contentDigest({ domain: 'cl-canary-run-completion-receipt-v1', receipt: unsigned }),
    },
    'verified canary run completion receipt',
  );
  issuedCompletions.add(receipt as object);
  return receipt;
}

export function recordCanaryMonitoringObservation(
  eventsInput: readonly MemoryEvent[],
  plan: BoundedCanaryPlan,
  review: CanaryPlanReview,
  input: CanaryMonitoringObservationInput,
): VerifiedCanaryMonitoringObservation {
  assertReadyPlan(plan, review);
  const request = canonicalSnapshot(input, 'canary monitoring observation input');
  assertText(request.id, 'canary observation id');
  assertText(request.metric, 'canary observation metric');
  if (!plan.stopConditions.some((condition) => condition.metric === request.metric)) {
    throw new Error(`canary observation metric is not declared by the plan: ${request.metric}`);
  }
  assertSafeInteger(request.sequence, 'canary observation sequence', 1);
  assertFiniteNumber(request.value, 'canary observation value');
  assertSafeInteger(request.sampleCount, 'canary observation sampleCount', 1, plan.budget.maxRuns);
  assertDigest(request.observerDigest, 'canary observerDigest');
  if (request.observerDigest !== plan.runtime.observerDigest) {
    throw new Error('canary observation does not use the planned observer digest');
  }
  assertDigest(request.externalObservationDigest, 'canary externalObservationDigest');
  assertText(request.actor, 'canary observation actor');
  assertSafeInteger(request.observedAt, 'canary observation observedAt', review.recordedAt);
  const events = canonicalEvents(eventsInput, request.canonicalFingerprint, plan, review);
  const context = evidenceContext(events, request.observedAt, plan.scope);
  const evidence = normalizeEvidence(
    request.evidence,
    context,
    'canary monitoring observation evidence',
    ['verifies'],
    request.externalObservationDigest,
    'tool-verified',
  );
  requireRuntimeComponentSourceContinuity(
    evidence,
    plan.runtime,
    plan.runtime.observerDigest,
    'canary monitoring observation evidence',
  );
  const unsigned = {
    schemaVersion: CANONICAL_CANARY_RECEIPT_SCHEMA_VERSION,
    id: request.id,
    scope: plan.scope,
    planId: plan.id,
    planDigest: plan.planDigest,
    reviewDigest: review.reviewDigest,
    metric: request.metric,
    sequence: request.sequence,
    value: request.value,
    sampleCount: request.sampleCount,
    observerIdentityDigest: plan.runtime.identityDigest,
    externalObservationDigest: request.externalObservationDigest,
    evidence,
    canonicalFingerprint: request.canonicalFingerprint,
    actor: request.actor,
    observedAt: request.observedAt,
    status: 'observed' as const,
    hostSchedulingAuthorized: false as const,
    procedurePromotionAuthorized: false as const,
    executionAuthorized: false as const,
  };
  const receipt = canonicalSnapshot<VerifiedCanaryMonitoringObservation>(
    {
      ...unsigned,
      receiptDigest: contentDigest({ domain: 'cl-canary-monitoring-observation-v1', receipt: unsigned }),
    },
    'verified canary monitoring observation',
  );
  issuedObservations.add(receipt as object);
  return receipt;
}

export function evaluateCanaryStopCondition(
  eventsInput: readonly MemoryEvent[],
  plan: BoundedCanaryPlan,
  review: CanaryPlanReview,
  observationsInput: readonly VerifiedCanaryMonitoringObservation[],
  input: CanaryStopEvaluationInput,
): VerifiedCanaryStopEvaluation {
  assertReadyPlan(plan, review);
  const request = canonicalSnapshot(input, 'canary stop evaluation input');
  assertText(request.id, 'canary stop evaluation id');
  assertText(request.conditionId, 'canary stop condition id');
  assertText(request.actor, 'canary stop evaluation actor');
  assertSafeInteger(request.evaluatedAt, 'canary stop evaluatedAt', review.recordedAt);
  const condition = plan.stopConditions.find((candidate) => candidate.id === request.conditionId);
  if (condition === undefined) throw new Error('canary stop evaluation references an unknown condition');
  if (!Array.isArray(observationsInput) || observationsInput.length > MAX_OBSERVATIONS_PER_EVALUATION) {
    throw new Error(`canary stop evaluation cannot exceed ${MAX_OBSERVATIONS_PER_EVALUATION} observations`);
  }
  const observations = Array.from(observationsInput);
  for (const observation of observations) {
    if (!isIssuedCanaryMonitoringObservation(observation)) {
      throw new Error('canary stop evaluation requires issued monitoring observations');
    }
    if (
      observation.planDigest !== plan.planDigest ||
      observation.reviewDigest !== review.reviewDigest ||
      observation.metric !== condition.metric ||
      observation.observedAt > request.evaluatedAt
    ) {
      throw new Error('canary stop evaluation received an observation outside its plan, metric, or time boundary');
    }
  }
  if (new Set(observations.map((observation) => observation.id)).size !== observations.length) {
    throw new Error('canary stop evaluation cannot repeat observations');
  }
  if (!Array.isArray(request.observationIds) || request.observationIds.length !== observations.length) {
    throw new Error('canary stop evaluation observationIds must cover the supplied observations exactly');
  }
  const sorted = observations.sort(
    (left, right) => left.sequence - right.sequence || left.id.localeCompare(right.id),
  );
  const expectedIds = sorted.map((observation) => observation.id);
  const requestIds = [...request.observationIds].sort();
  if (
    new Set(requestIds).size !== requestIds.length ||
    requestIds.some((id, index) => id !== [...expectedIds].sort()[index])
  ) {
    throw new Error('canary stop evaluation observationIds differ from the supplied observation set');
  }
  for (let index = 1; index < sorted.length; index += 1) {
    const previous = sorted[index - 1];
    const current = sorted[index];
    if (previous === undefined || current === undefined || current.sequence <= previous.sequence) {
      throw new Error('canary stop evaluation observations must have strictly increasing sequences');
    }
  }
  canonicalEvents(eventsInput, request.canonicalFingerprint, plan, review);
  const latest = [...sorted]
    .reverse()
    .find((observation) => observation.sampleCount >= condition.observationWindowRuns);
  const triggered =
    latest !== undefined && comparatorApplies(condition.comparator, latest.value, condition.threshold);
  const observationSetDigest = contentDigest({
    domain: 'cl-canary-stop-observation-set-v1',
    planDigest: plan.planDigest,
    conditionDigest: condition.conditionDigest,
    observations: sorted.map((observation) => observation.receiptDigest),
  });
  const unsigned = {
    schemaVersion: CANONICAL_CANARY_RECEIPT_SCHEMA_VERSION,
    id: request.id,
    scope: plan.scope,
    planId: plan.id,
    planDigest: plan.planDigest,
    reviewDigest: review.reviewDigest,
    conditionId: condition.id,
    conditionDigest: condition.conditionDigest,
    metric: condition.metric,
    comparator: condition.comparator,
    threshold: condition.threshold,
    minimumSamples: condition.observationWindowRuns,
    observationIds: Object.freeze(expectedIds),
    observationSetDigest,
    ...(latest === undefined
      ? {}
      : {
          latestObservationId: latest.id,
          latestSequence: latest.sequence,
          latestValue: latest.value,
          latestSampleCount: latest.sampleCount,
        }),
    triggered,
    action: triggered ? condition.action : ('continue' as const),
    canonicalFingerprint: request.canonicalFingerprint,
    actor: request.actor,
    evaluatedAt: request.evaluatedAt,
    status: 'evaluated' as const,
    hostSchedulingAuthorized: false as const,
    procedurePromotionAuthorized: false as const,
    executionAuthorized: false as const,
  };
  const evaluation = canonicalSnapshot<VerifiedCanaryStopEvaluation>(
    {
      ...unsigned,
      evaluationDigest: contentDigest({ domain: 'cl-canary-stop-evaluation-v1', evaluation: unsigned }),
    },
    'verified canary stop evaluation',
  );
  issuedEvaluations.add(evaluation as object);
  return evaluation;
}

export function recordCanaryRollbackReceipt(
  eventsInput: readonly MemoryEvent[],
  plan: BoundedCanaryPlan,
  review: CanaryPlanReview,
  evaluation: VerifiedCanaryStopEvaluation,
  input: CanaryRollbackReceiptInput,
): VerifiedCanaryRollbackReceipt {
  assertReadyPlan(plan, review);
  if (!isIssuedCanaryStopEvaluation(evaluation)) {
    throw new Error('canary rollback receipt requires an issued stop evaluation');
  }
  if (
    evaluation.planDigest !== plan.planDigest ||
    evaluation.reviewDigest !== review.reviewDigest ||
    !evaluation.triggered ||
    evaluation.action !== 'rollback'
  ) {
    throw new Error('canary rollback receipt requires a triggered stop-and-rollback evaluation');
  }
  const request = canonicalSnapshot(input, 'canary rollback receipt input');
  assertText(request.id, 'canary rollback receipt id');
  assertText(request.evaluationId, 'canary rollback evaluationId');
  if (request.evaluationId !== evaluation.id) throw new Error('canary rollback targets another evaluation');
  assertDigest(request.controllerDigest, 'canary rollback controllerDigest');
  if (request.controllerDigest !== plan.runtime.rollbackControllerDigest) {
    throw new Error('canary rollback does not use the planned rollback controller digest');
  }
  assertDigest(request.externalRollbackDigest, 'canary externalRollbackDigest');
  if (!ROLLBACK_OUTCOMES.has(request.outcome)) throw new Error('canary rollback outcome is invalid');
  assertText(request.actor, 'canary rollback actor');
  assertSafeInteger(request.startedAt, 'canary rollback startedAt', evaluation.evaluatedAt);
  assertSafeInteger(request.completedAt, 'canary rollback completedAt', request.startedAt);
  const durationMs = request.completedAt - request.startedAt;
  if (durationMs > plan.budget.maxDurationMs) {
    throw new Error('canary rollback receipt exceeds the planned maximum rollback duration');
  }
  const events = canonicalEvents(eventsInput, request.canonicalFingerprint, plan, review);
  const context = evidenceContext(events, request.completedAt, plan.scope);
  const evidence = normalizeEvidence(
    request.evidence,
    context,
    'canary rollback execution evidence',
    ['verifies'],
    request.externalRollbackDigest,
    'tool-verified',
  );
  requireRuntimeComponentSourceContinuity(
    evidence,
    plan.runtime,
    plan.runtime.rollbackControllerDigest,
    'canary rollback evidence',
  );
  const unsigned = {
    schemaVersion: CANONICAL_CANARY_RECEIPT_SCHEMA_VERSION,
    id: request.id,
    scope: plan.scope,
    planId: plan.id,
    planDigest: plan.planDigest,
    reviewDigest: review.reviewDigest,
    evaluationId: evaluation.id,
    evaluationDigest: evaluation.evaluationDigest,
    conditionId: evaluation.conditionId,
    controllerDigest: plan.runtime.rollbackControllerDigest,
    externalRollbackDigest: request.externalRollbackDigest,
    outcome: request.outcome,
    evidence,
    canonicalFingerprint: request.canonicalFingerprint,
    actor: request.actor,
    startedAt: request.startedAt,
    completedAt: request.completedAt,
    durationMs,
    status: 'rollback-recorded' as const,
    externalHostActionObserved: true as const,
    hostSchedulingAuthorized: false as const,
    procedurePromotionAuthorized: false as const,
    executionAuthorized: false as const,
  };
  const receipt = canonicalSnapshot<VerifiedCanaryRollbackReceipt>(
    {
      ...unsigned,
      receiptDigest: contentDigest({ domain: 'cl-canary-rollback-receipt-v1', receipt: unsigned }),
    },
    'verified canary rollback receipt',
  );
  issuedRollbacks.add(receipt as object);
  return receipt;
}

export function verifyCanaryOutcomeReceipt(
  eventsInput: readonly MemoryEvent[],
  plan: BoundedCanaryPlan,
  review: CanaryPlanReview,
  completion: VerifiedCanaryRunCompletionReceipt,
  input: CanaryOutcomeVerificationInput,
): VerifiedCanaryOutcomeReceipt {
  assertReadyPlan(plan, review);
  if (!isIssuedCanaryRunCompletionReceipt(completion)) {
    throw new Error('canary outcome verification requires an issued completion receipt');
  }
  if (completion.planDigest !== plan.planDigest || completion.reviewDigest !== review.reviewDigest) {
    throw new Error('canary completion receipt belongs to another plan or review');
  }
  const request = canonicalSnapshot(input, 'canary outcome verification input');
  assertText(request.id, 'canary outcome receipt id');
  assertText(request.completionId, 'canary outcome completionId');
  if (request.completionId !== completion.id) throw new Error('canary outcome targets another completion');
  assertText(request.outcomeEventId, 'canary outcome event id');
  assertDigest(request.verifierDigest, 'canary outcome verifierDigest');
  if (request.verifierDigest !== plan.runtime.verifierDigest) {
    throw new Error('canary outcome does not use the planned verifier digest');
  }
  assertDigest(request.externalVerificationDigest, 'canary externalVerificationDigest');
  assertText(request.actor, 'canary outcome actor');
  assertSafeInteger(request.verifiedAt, 'canary outcome verifiedAt', completion.completedAt);
  const events = canonicalEvents(eventsInput, request.canonicalFingerprint, plan, review);
  const matches = events.filter(
    (event) => event.type === 'outcome.recorded' && event.id === request.outcomeEventId,
  );
  if (matches.length !== 1) throw new Error('canary outcome event is absent or duplicated');
  const event = matches[0];
  if (event === undefined || event.type !== 'outcome.recorded') {
    throw new Error('canary outcome event disappeared after selection');
  }
  if (
    event.data.scope !== plan.scope ||
    event.data.subjectId !== completion.runId ||
    event.recordedAt < completion.completedAt ||
    event.recordedAt > request.verifiedAt
  ) {
    throw new Error('canary outcome event does not bind the completed run, scope, or verification time');
  }
  const context = evidenceContext(events, request.verifiedAt, plan.scope);
  const evidence = normalizeEvidence(
    request.evidence,
    context,
    'canary independent outcome verification evidence',
    ['verifies'],
    request.externalVerificationDigest,
    'tool-verified',
  );
  requireRuntimeComponentSourceContinuity(
    evidence,
    plan.runtime,
    plan.runtime.verifierDigest,
    'canary outcome verification evidence',
  );
  for (const binding of evidence) {
    const exactReference = event.data.evidence.some((reference) => {
      const roles = evidenceRoles(reference);
      return (
        reference.sourceId === binding.sourceId &&
        reference.authority === binding.authority &&
        reference.contentHash === binding.contentHash &&
        reference.sourceGroups.length === binding.sourceGroups.length &&
        reference.sourceGroups.every(
          (sourceGroup, index) => sourceGroup === binding.sourceGroups[index],
        ) &&
        roles.includes('verifies')
      );
    });
    if (!exactReference) {
      throw new Error(
        'canary outcome verification evidence is not an exact verifying reference in the canonical outcome event',
      );
    }
  }
  const verifierGroups = new Set(
    plan.runtime.evidence
      .filter((binding) => binding.contentHash === plan.runtime.verifierDigest)
      .flatMap((binding) => binding.sourceGroups),
  );
  if (!event.data.sourceGroups.some((group) => verifierGroups.has(group))) {
    throw new Error('canary outcome event source groups do not bind the planned verifier family');
  }
  const groups = sourceGroups(evidence);
  const unsigned = {
    schemaVersion: CANONICAL_CANARY_RECEIPT_SCHEMA_VERSION,
    id: request.id,
    scope: plan.scope,
    planId: plan.id,
    planDigest: plan.planDigest,
    reviewDigest: review.reviewDigest,
    completionId: completion.id,
    completionReceiptDigest: completion.receiptDigest,
    runId: completion.runId,
    subjectDigest: completion.subjectDigest,
    arm: completion.arm,
    outcomeEventId: event.id,
    outcome: event.data.outcome,
    verifierDigest: plan.runtime.verifierDigest,
    externalVerificationDigest: request.externalVerificationDigest,
    evidence,
    sourceGroups: groups,
    canonicalFingerprint: request.canonicalFingerprint,
    actor: request.actor,
    verifiedAt: request.verifiedAt,
    status: 'outcome-verified' as const,
    procedurePromotionAuthorized: false as const,
    hostSchedulingAuthorized: false as const,
    executionAuthorized: false as const,
  };
  const receipt = canonicalSnapshot<VerifiedCanaryOutcomeReceipt>(
    {
      ...unsigned,
      receiptDigest: contentDigest({ domain: 'cl-canary-outcome-receipt-v1', receipt: unsigned }),
    },
    'verified canary outcome receipt',
  );
  issuedOutcomes.add(receipt as object);
  return receipt;
}

export function isIssuedCanaryAdmissionReceipt(value: VerifiedCanaryAdmissionReceipt): boolean {
  return typeof value === 'object' && value !== null && issuedAdmissions.has(value as object);
}

export function isIssuedCanaryRunStartReceipt(value: VerifiedCanaryRunStartReceipt): boolean {
  return typeof value === 'object' && value !== null && issuedStarts.has(value as object);
}

export function isIssuedCanaryRunCompletionReceipt(
  value: VerifiedCanaryRunCompletionReceipt,
): boolean {
  return typeof value === 'object' && value !== null && issuedCompletions.has(value as object);
}

export function isIssuedCanaryMonitoringObservation(
  value: VerifiedCanaryMonitoringObservation,
): boolean {
  return typeof value === 'object' && value !== null && issuedObservations.has(value as object);
}

export function isIssuedCanaryStopEvaluation(value: VerifiedCanaryStopEvaluation): boolean {
  return typeof value === 'object' && value !== null && issuedEvaluations.has(value as object);
}

export function isIssuedCanaryRollbackReceipt(value: VerifiedCanaryRollbackReceipt): boolean {
  return typeof value === 'object' && value !== null && issuedRollbacks.has(value as object);
}

export function isIssuedCanaryOutcomeReceipt(value: VerifiedCanaryOutcomeReceipt): boolean {
  return typeof value === 'object' && value !== null && issuedOutcomes.has(value as object);
}
