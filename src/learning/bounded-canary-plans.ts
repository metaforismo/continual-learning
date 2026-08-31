import {
  AUTHORITY_RANK,
  evidenceRoles,
  type Authority,
  type EvidenceRef,
  type EvidenceRole,
  type EvidenceTaint,
  type MemoryEvent,
} from '../domain.js';
import { EvidenceProjection } from '../evidence.js';
import { MemoryKernel } from '../kernel.js';
import { canonicalJson, contentDigest } from '../retrieval/canonical.js';
import { fingerprintMemoryEvents } from '../transitions/verifier.js';
import { applicabilityRuleApplies } from './applicability-hypotheses-api.js';
import {
  isIssuedVerifiedProcedureCandidate,
  type ProcedureEvidenceBinding,
  type VerifiedProcedureCandidate,
} from './verified-procedure-candidates-api.js';

export const BOUNDED_CANARY_PLAN_SCHEMA_VERSION = 1 as const;

const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const MAX_INPUT_CHARACTERS = 1_000_000;
const MAX_IDENTIFIER_CHARACTERS = 512;
const MAX_TEXT_CHARACTERS = 4_096;
const MAX_SUBJECTS = 4_096;
const MIN_ELIGIBLE_SUBJECTS = 4;
const MAX_FEATURES_PER_SUBJECT = 128;
const MAX_STOP_CONDITIONS = 32;
const MAX_EVIDENCE_PER_BINDING = 32;
const MAX_TOTAL_EVIDENCE_REFERENCES = 512;
const MAX_FINDINGS = 64;

const STOP_CATEGORIES = new Set(['quality', 'cost', 'safety', 'security']);
const STOP_COMPARATORS = new Set(['gt', 'gte', 'lt', 'lte', 'eq']);
const STOP_ACTIONS = new Set(['pause', 'abort', 'rollback']);
const REVIEW_DECISIONS = new Set(['approve', 'request-changes', 'reject']);

const issuedPlans = new WeakSet<object>();
const issuedReviews = new WeakSet<object>();

export type CanaryAssignment = 'treatment' | 'control' | 'excluded';
export type CanaryStopCategory = 'quality' | 'cost' | 'safety' | 'security';
export type CanaryStopComparator = 'gt' | 'gte' | 'lt' | 'lte' | 'eq';
export type CanaryStopAction = 'pause' | 'abort' | 'rollback';
export type CanaryReviewDecision = 'approve' | 'request-changes' | 'reject';
export type CanaryReviewRecommendation =
  | 'ready-for-host-scheduling'
  | 'changes-required'
  | 'rejected';

export interface CanarySubjectInput {
  readonly subjectDigest: string;
  readonly experimentalUnitDigest: string;
  readonly contextFeatures: readonly string[];
}

export interface VerifiedCanarySubject {
  readonly subjectDigest: string;
  readonly experimentalUnitDigest: string;
  readonly contextFeatures: readonly string[];
  readonly contextFeatureDigest: string;
  readonly applicable: boolean;
  readonly assignment: CanaryAssignment;
  readonly assignmentDigest: string;
}

export interface CanaryPopulationManifestInput {
  readonly id: string;
  readonly featureSchemaDigest: string;
  readonly subjects: readonly CanarySubjectInput[];
}

export interface VerifiedCanaryPopulationManifest {
  readonly id: string;
  readonly featureSchemaDigest: string;
  readonly subjects: readonly VerifiedCanarySubject[];
  readonly subjectCount: number;
  readonly eligibleCount: number;
  readonly treatmentCount: number;
  readonly controlCount: number;
  readonly excludedCount: number;
  readonly manifestDigest: string;
}

export interface CanaryBudgetInput {
  readonly maxSubjects: number;
  readonly maxRuns: number;
  readonly maxConcurrentRuns: number;
  readonly maxDurationMs: number;
  readonly maxToolCalls: number;
  readonly maxCostMicros: number;
  readonly maxRetriesPerSubject: number;
}

export interface VerifiedCanaryBudget extends CanaryBudgetInput {
  readonly budgetDigest: string;
}

export interface CanaryRuntimeIdentityInput {
  readonly schedulerDigest: string;
  readonly harnessDigest: string;
  readonly observerDigest: string;
  readonly verifierDigest: string;
  readonly rollbackControllerDigest: string;
  readonly environmentDigest: string;
  readonly evidence: readonly EvidenceRef[];
}

export interface VerifiedCanaryRuntimeIdentity
  extends Omit<CanaryRuntimeIdentityInput, 'evidence'> {
  readonly evidence: readonly ProcedureEvidenceBinding[];
  readonly identityDigest: string;
}

export interface CanaryStopConditionInput {
  readonly id: string;
  readonly category: CanaryStopCategory;
  readonly metric: string;
  readonly comparator: CanaryStopComparator;
  readonly threshold: number;
  readonly observationWindowRuns: number;
  readonly action: CanaryStopAction;
  readonly evidence: readonly EvidenceRef[];
}

export interface VerifiedCanaryStopCondition
  extends Omit<CanaryStopConditionInput, 'evidence'> {
  readonly evidence: readonly ProcedureEvidenceBinding[];
  readonly conditionDigest: string;
}

export interface CanaryAbortContractInput {
  readonly instructions: string;
  readonly evidence: readonly EvidenceRef[];
}

export interface VerifiedCanaryAbortContract {
  readonly instructions: string;
  readonly evidence: readonly ProcedureEvidenceBinding[];
  readonly stopConditionIds: readonly string[];
  readonly contractDigest: string;
}

export interface BoundedCanaryPlanInput {
  readonly id: string;
  readonly candidateDigest: string;
  readonly assignmentSeedDigest: string;
  readonly population: CanaryPopulationManifestInput;
  readonly budget: CanaryBudgetInput;
  readonly runtime: CanaryRuntimeIdentityInput;
  readonly stopConditions: readonly CanaryStopConditionInput[];
  readonly abort: CanaryAbortContractInput;
  readonly canonicalFingerprint: string;
  readonly actor: string;
  readonly recordedAt: number;
}

export interface BoundedCanaryPlan {
  readonly schemaVersion: typeof BOUNDED_CANARY_PLAN_SCHEMA_VERSION;
  readonly id: string;
  readonly candidateId: string;
  readonly candidateDigest: string;
  readonly scope: string;
  readonly procedureId: string;
  readonly procedureVersion: string;
  readonly risk: VerifiedProcedureCandidate['risk'];
  readonly assignmentSeedDigest: string;
  readonly population: VerifiedCanaryPopulationManifest;
  readonly budget: VerifiedCanaryBudget;
  readonly runtime: VerifiedCanaryRuntimeIdentity;
  readonly stopConditions: readonly VerifiedCanaryStopCondition[];
  readonly abort: VerifiedCanaryAbortContract;
  readonly inheritedApplicabilityDigest: string;
  readonly inheritedVerificationDigest: string;
  readonly inheritedRollbackDigest: string;
  readonly canonicalFingerprint: string;
  readonly canonicalEventCount: number;
  readonly inheritedSourceEvidenceIds: readonly string[];
  readonly planSourceEvidenceIds: readonly string[];
  readonly inheritedSourceGroups: readonly string[];
  readonly planSourceGroups: readonly string[];
  readonly actor: string;
  readonly recordedAt: number;
  readonly status: 'plan';
  readonly reviewStatus: 'pending-independent-review';
  readonly executable: false;
  readonly hostSchedulingAuthorized: false;
  readonly procedurePromotionAuthorized: false;
  readonly executionAuthorized: false;
  readonly planDigest: string;
}

export interface CanaryPlanReviewInput {
  readonly id: string;
  readonly planId: string;
  readonly decision: CanaryReviewDecision;
  readonly findings: readonly string[];
  readonly evidence: readonly EvidenceRef[];
  readonly canonicalFingerprint: string;
  readonly reviewer: string;
  readonly recordedAt: number;
}

export interface CanaryPlanReview {
  readonly schemaVersion: typeof BOUNDED_CANARY_PLAN_SCHEMA_VERSION;
  readonly id: string;
  readonly planId: string;
  readonly planDigest: string;
  readonly decision: CanaryReviewDecision;
  readonly recommendation: CanaryReviewRecommendation;
  readonly findings: readonly string[];
  readonly evidence: readonly ProcedureEvidenceBinding[];
  readonly reviewSourceGroups: readonly string[];
  readonly canonicalFingerprint: string;
  readonly canonicalEventCount: number;
  readonly reviewer: string;
  readonly recordedAt: number;
  readonly reviewComplete: true;
  readonly executable: false;
  readonly hostSchedulingAuthorized: false;
  readonly procedurePromotionAuthorized: false;
  readonly executionAuthorized: false;
  readonly reviewDigest: string;
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

function assertText(
  value: unknown,
  label: string,
  maximum = MAX_IDENTIFIER_CHARACTERS,
): asserts value is string {
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
  minimum: number,
  maximum: number,
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

function assertExactKeys(
  value: object,
  keys: readonly string[],
  label: string,
): void {
  const expected = [...keys].sort();
  const actual = Object.keys(value).sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} contains an unexpected or missing field`);
  }
}

function normalizeFeatures(
  valuesInput: readonly string[],
  label: string,
): readonly string[] {
  if (
    !Array.isArray(valuesInput) ||
    valuesInput.length === 0 ||
    valuesInput.length > MAX_FEATURES_PER_SUBJECT
  ) {
    throw new Error(`${label} requires 1..${MAX_FEATURES_PER_SUBJECT} features`);
  }
  const values = valuesInput.map((value) => {
    assertText(value, label, MAX_TEXT_CHARACTERS);
    const normalized = value.trim().toLowerCase();
    if (normalized !== value) {
      throw new Error(`${label} must already be normalized lowercase text`);
    }
    return normalized;
  });
  if (new Set(values).size !== values.length) throw new Error(`${label} cannot contain duplicates`);
  return Object.freeze([...values].sort());
}

function normalizeEvidence(
  referencesInput: readonly EvidenceRef[],
  context: EvidenceContext,
  label: string,
  minimumAuthority: Authority = 'external-source',
): readonly ProcedureEvidenceBinding[] {
  if (
    !Array.isArray(referencesInput) ||
    referencesInput.length === 0 ||
    referencesInput.length > MAX_EVIDENCE_PER_BINDING
  ) {
    throw new Error(`${label} requires 1..${MAX_EVIDENCE_PER_BINDING} references`);
  }
  context.totalReferences += referencesInput.length;
  if (context.totalReferences > MAX_TOTAL_EVIDENCE_REFERENCES) {
    throw new RangeError(
      `canary plan cannot exceed ${MAX_TOTAL_EVIDENCE_REFERENCES} evidence references`,
    );
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
      throw new Error(`${label} was unavailable or forged at plan time: ${reference.sourceId}`);
    }
    if (!context.current.validatesReference(reference)) {
      throw new Error(`${label} is not currently available: ${reference.sourceId}`);
    }
    const projected = context.current.get(reference.sourceId);
    if (projected === undefined) throw new Error(`${label} references unknown evidence`);
    if (projected.record.scope !== 'global' && projected.record.scope !== context.scope) {
      throw new Error(`${label} crosses scope through ${reference.sourceId}`);
    }
    if (
      projected.record.sensitivity === 'secret' ||
      projected.record.taints.includes('secret-detected')
    ) {
      throw new Error(`${label} cannot use secret evidence`);
    }
    if (AUTHORITY_RANK[projected.record.authority] < AUTHORITY_RANK[minimumAuthority]) {
      throw new Error(`${label} lacks ${minimumAuthority} authority: ${reference.sourceId}`);
    }
    const roles = Object.freeze([...evidenceRoles(reference)].sort()) as readonly EvidenceRole[];
    if (
      roles.includes('contradicts') ||
      !roles.some((role) => role === 'verifies' || role === 'constrains')
    ) {
      throw new Error(`${label} requires non-contradicting verifies or constrains evidence`);
    }
    bindings.push(
      Object.freeze({
        sourceId: reference.sourceId,
        sourceGroups: Object.freeze([...projected.record.sourceGroups]),
        authority: projected.record.authority,
        contentHash: projected.record.artifact.digest,
        roles,
        sensitivity: projected.record.sensitivity,
        taints: Object.freeze([...projected.record.taints]),
      }),
    );
  }
  return Object.freeze(bindings.sort((left, right) => left.sourceId.localeCompare(right.sourceId)));
}

function uniqueSorted(values: readonly string[]): readonly string[] {
  return Object.freeze([...new Set(values)].sort());
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
  const actualFingerprint = fingerprintMemoryEvents(events.slice(0, eventCount));
  if (actualFingerprint !== expectedFingerprint) {
    throw new Error(`${label} canonical prefix is stale, truncated, or forked`);
  }
}

function assertCurrentEvidenceIds(
  sourceIds: readonly string[],
  projection: EvidenceProjection,
  scope: string,
  label: string,
): void {
  for (const sourceId of uniqueSorted(sourceIds)) {
    const projected = projection.get(sourceId);
    if (projected === undefined || projected.availability !== 'available') {
      throw new Error(`${label} is not currently available: ${sourceId}`);
    }
    if (projected.record.scope !== 'global' && projected.record.scope !== scope) {
      throw new Error(`${label} crosses scope through ${sourceId}`);
    }
  }
}

function requireRuntimeDigestEvidence(
  evidence: readonly ProcedureEvidenceBinding[],
  digest: string,
  component: string,
): void {
  if (
    !evidence.some(
      (binding) =>
        binding.contentHash === digest && binding.roles.includes('verifies'),
    )
  ) {
    throw new Error(
      `canary runtime ${component} digest requires exact verifies evidence`,
    );
  }
}

function normalizeBudget(
  input: CanaryBudgetInput,
  eligibleCount: number,
  risk: VerifiedProcedureCandidate['risk'],
): VerifiedCanaryBudget {
  if (typeof input !== 'object' || input === null) {
    throw new Error('canary budget must be an object');
  }
  assertExactKeys(
    input,
    [
      'maxSubjects',
      'maxRuns',
      'maxConcurrentRuns',
      'maxDurationMs',
      'maxToolCalls',
      'maxCostMicros',
      'maxRetriesPerSubject',
    ],
    'canary budget',
  );
  assertSafeInteger(input.maxSubjects, 'canary maxSubjects', 1, MAX_SUBJECTS);
  assertSafeInteger(input.maxRuns, 'canary maxRuns', 1, 1_000_000);
  assertSafeInteger(input.maxConcurrentRuns, 'canary maxConcurrentRuns', 1, 1_000);
  assertSafeInteger(input.maxDurationMs, 'canary maxDurationMs', 1, 86_400_000);
  assertSafeInteger(input.maxToolCalls, 'canary maxToolCalls', 0, 10_000_000);
  assertSafeInteger(input.maxCostMicros, 'canary maxCostMicros', 0, Number.MAX_SAFE_INTEGER);
  assertSafeInteger(input.maxRetriesPerSubject, 'canary maxRetriesPerSubject', 0, 10);
  if (input.maxSubjects !== eligibleCount) {
    throw new Error('canary maxSubjects must equal the exact eligible population size');
  }
  if (input.maxRuns < eligibleCount || input.maxRuns > eligibleCount * (input.maxRetriesPerSubject + 1)) {
    throw new Error('canary maxRuns is incoherent with subjects and retry budget');
  }
  if (input.maxConcurrentRuns > input.maxRuns || input.maxConcurrentRuns > eligibleCount) {
    throw new Error('canary concurrency exceeds its run or subject budget');
  }
  if (risk === 'high') {
    if (
      input.maxSubjects > 8 ||
      input.maxConcurrentRuns !== 1 ||
      input.maxDurationMs > 3_600_000 ||
      input.maxRetriesPerSubject !== 0
    ) {
      throw new Error('high-risk canaries require at most 8 subjects, one concurrent run, one hour, and no retries');
    }
  }
  const unsigned = {
    maxSubjects: input.maxSubjects,
    maxRuns: input.maxRuns,
    maxConcurrentRuns: input.maxConcurrentRuns,
    maxDurationMs: input.maxDurationMs,
    maxToolCalls: input.maxToolCalls,
    maxCostMicros: input.maxCostMicros,
    maxRetriesPerSubject: input.maxRetriesPerSubject,
  };
  return Object.freeze({
    ...unsigned,
    budgetDigest: contentDigest({ domain: 'cl-canary-budget-v1', budget: unsigned }),
  });
}

function normalizePopulation(
  input: CanaryPopulationManifestInput,
  candidate: VerifiedProcedureCandidate,
  assignmentSeedDigest: string,
): VerifiedCanaryPopulationManifest {
  if (typeof input !== 'object' || input === null) {
    throw new Error('canary population manifest must be an object');
  }
  assertExactKeys(input, ['id', 'featureSchemaDigest', 'subjects'], 'canary population manifest');
  assertText(input.id, 'canary population id');
  assertDigest(input.featureSchemaDigest, 'canary featureSchemaDigest');
  if (input.featureSchemaDigest !== candidate.applicability.featureSchemaDigest) {
    throw new Error('canary feature schema differs from validated applicability');
  }
  if (!Array.isArray(input.subjects) || input.subjects.length > MAX_SUBJECTS) {
    throw new Error(`canary population cannot exceed ${MAX_SUBJECTS} subjects`);
  }
  const seenSubjects = new Set<string>();
  const seenUnits = new Set<string>();
  const normalized = input.subjects.map((subject) => {
    if (typeof subject !== 'object' || subject === null) {
      throw new Error('canary subject must be an object');
    }
    assertExactKeys(
      subject,
      ['subjectDigest', 'experimentalUnitDigest', 'contextFeatures'],
      'canary subject',
    );
    assertDigest(subject.subjectDigest, 'canary subjectDigest');
    assertDigest(subject.experimentalUnitDigest, 'canary experimentalUnitDigest');
    if (seenSubjects.has(subject.subjectDigest)) throw new Error('canary subjects must be unique');
    if (seenUnits.has(subject.experimentalUnitDigest)) {
      throw new Error('canary experimental units must be unique');
    }
    seenSubjects.add(subject.subjectDigest);
    seenUnits.add(subject.experimentalUnitDigest);
    const contextFeatures = normalizeFeatures(subject.contextFeatures, 'canary context feature');
    const contextFeatureDigest = contentDigest({
      domain: 'cl-canary-context-features-v1',
      featureSchemaDigest: input.featureSchemaDigest,
      contextFeatures,
    });
    const applicable = applicabilityRuleApplies(candidate.applicability.rule, contextFeatures);
    const assignmentDigest = contentDigest({
      domain: 'cl-canary-assignment-key-v1',
      candidateDigest: candidate.candidateDigest,
      assignmentSeedDigest,
      subjectDigest: subject.subjectDigest,
      experimentalUnitDigest: subject.experimentalUnitDigest,
      contextFeatureDigest,
    });
    return {
      subjectDigest: subject.subjectDigest,
      experimentalUnitDigest: subject.experimentalUnitDigest,
      contextFeatures,
      contextFeatureDigest,
      applicable,
      assignmentDigest,
    };
  });
  const eligible = normalized
    .filter((subject) => subject.applicable)
    .sort(
      (left, right) =>
        left.assignmentDigest.localeCompare(right.assignmentDigest) ||
        left.subjectDigest.localeCompare(right.subjectDigest),
    );
  if (eligible.length < MIN_ELIGIBLE_SUBJECTS) {
    throw new Error(`canary population requires at least ${MIN_ELIGIBLE_SUBJECTS} applicable subjects`);
  }
  const assignments = new Map<string, CanaryAssignment>();
  for (let index = 0; index < eligible.length; index += 1) {
    const subject = eligible[index];
    if (subject === undefined) continue;
    assignments.set(subject.subjectDigest, index % 2 === 0 ? 'treatment' : 'control');
  }
  const subjects = Object.freeze(
    normalized
      .map((subject) =>
        Object.freeze<VerifiedCanarySubject>({
          ...subject,
          assignment: assignments.get(subject.subjectDigest) ?? 'excluded',
        }),
      )
      .sort((left, right) => left.subjectDigest.localeCompare(right.subjectDigest)),
  );
  const treatmentCount = subjects.filter((subject) => subject.assignment === 'treatment').length;
  const controlCount = subjects.filter((subject) => subject.assignment === 'control').length;
  if (treatmentCount === 0 || controlCount === 0) {
    throw new Error('canary assignment requires non-empty treatment and control arms');
  }
  const unsigned = {
    id: input.id,
    featureSchemaDigest: input.featureSchemaDigest,
    subjects,
    subjectCount: subjects.length,
    eligibleCount: eligible.length,
    treatmentCount,
    controlCount,
    excludedCount: subjects.length - eligible.length,
  };
  return Object.freeze({
    ...unsigned,
    manifestDigest: contentDigest({
      domain: 'cl-canary-population-manifest-v1',
      candidateDigest: candidate.candidateDigest,
      population: unsigned,
    }),
  });
}

function normalizeRuntime(
  input: CanaryRuntimeIdentityInput,
  context: EvidenceContext,
): VerifiedCanaryRuntimeIdentity {
  if (typeof input !== 'object' || input === null) {
    throw new Error('canary runtime identity must be an object');
  }
  assertExactKeys(
    input,
    [
      'schedulerDigest',
      'harnessDigest',
      'observerDigest',
      'verifierDigest',
      'rollbackControllerDigest',
      'environmentDigest',
      'evidence',
    ],
    'canary runtime identity',
  );
  assertDigest(input.schedulerDigest, 'canary schedulerDigest');
  assertDigest(input.harnessDigest, 'canary harnessDigest');
  assertDigest(input.observerDigest, 'canary observerDigest');
  assertDigest(input.verifierDigest, 'canary verifierDigest');
  assertDigest(input.rollbackControllerDigest, 'canary rollbackControllerDigest');
  assertDigest(input.environmentDigest, 'canary environmentDigest');
  const evidence = normalizeEvidence(
    input.evidence,
    context,
    'canary runtime evidence',
    'tool-verified',
  );
  requireRuntimeDigestEvidence(evidence, input.schedulerDigest, 'scheduler');
  requireRuntimeDigestEvidence(evidence, input.harnessDigest, 'harness');
  requireRuntimeDigestEvidence(evidence, input.observerDigest, 'observer');
  requireRuntimeDigestEvidence(evidence, input.verifierDigest, 'verifier');
  requireRuntimeDigestEvidence(
    evidence,
    input.rollbackControllerDigest,
    'rollback controller',
  );
  requireRuntimeDigestEvidence(evidence, input.environmentDigest, 'environment');
  const unsigned = {
    schedulerDigest: input.schedulerDigest,
    harnessDigest: input.harnessDigest,
    observerDigest: input.observerDigest,
    verifierDigest: input.verifierDigest,
    rollbackControllerDigest: input.rollbackControllerDigest,
    environmentDigest: input.environmentDigest,
    evidence,
  };
  return Object.freeze({
    ...unsigned,
    identityDigest: contentDigest({ domain: 'cl-canary-runtime-identity-v1', identity: unsigned }),
  });
}

function normalizeStopConditions(
  inputs: readonly CanaryStopConditionInput[],
  context: EvidenceContext,
  budget: VerifiedCanaryBudget,
  mutative: boolean,
): readonly VerifiedCanaryStopCondition[] {
  if (
    !Array.isArray(inputs) ||
    inputs.length === 0 ||
    inputs.length > MAX_STOP_CONDITIONS
  ) {
    throw new Error(`canary requires 1..${MAX_STOP_CONDITIONS} stop conditions`);
  }
  const ids = new Set<string>();
  const conditions = inputs.map((input) => {
    if (typeof input !== 'object' || input === null) {
      throw new Error('canary stop condition must be an object');
    }
    assertExactKeys(
      input,
      [
        'id',
        'category',
        'metric',
        'comparator',
        'threshold',
        'observationWindowRuns',
        'action',
        'evidence',
      ],
      'canary stop condition',
    );
    assertText(input.id, 'canary stop condition id');
    if (ids.has(input.id)) throw new Error(`duplicate canary stop condition: ${input.id}`);
    ids.add(input.id);
    if (!STOP_CATEGORIES.has(input.category)) throw new Error('canary stop category is invalid');
    assertText(input.metric, 'canary stop metric', MAX_TEXT_CHARACTERS);
    if (!STOP_COMPARATORS.has(input.comparator)) throw new Error('canary stop comparator is invalid');
    if (typeof input.threshold !== 'number' || !Number.isFinite(input.threshold) || Object.is(input.threshold, -0)) {
      throw new Error('canary stop threshold must be a canonical finite number');
    }
    assertSafeInteger(
      input.observationWindowRuns,
      'canary observationWindowRuns',
      1,
      budget.maxRuns,
    );
    if (!STOP_ACTIONS.has(input.action)) throw new Error('canary stop action is invalid');
    if (
      (input.category === 'safety' || input.category === 'security') &&
      input.action !== 'rollback'
    ) {
      throw new Error('safety and security stop conditions must trigger rollback');
    }
    const evidence = normalizeEvidence(
      input.evidence,
      context,
      `canary stop condition ${input.id} evidence`,
    );
    const unsigned = {
      id: input.id,
      category: input.category,
      metric: input.metric,
      comparator: input.comparator,
      threshold: input.threshold,
      observationWindowRuns: input.observationWindowRuns,
      action: input.action,
      evidence,
    };
    return Object.freeze({
      ...unsigned,
      conditionDigest: contentDigest({ domain: 'cl-canary-stop-condition-v1', condition: unsigned }),
    });
  });
  const categories = new Set(conditions.map((condition) => condition.category));
  if (!categories.has('quality') || !categories.has('cost')) {
    throw new Error('canary plans require quality and cost stop conditions');
  }
  if (mutative && (!categories.has('safety') || !categories.has('security'))) {
    throw new Error('mutative canaries require safety and security rollback conditions');
  }
  return Object.freeze(
    conditions.sort((left, right) => left.id.localeCompare(right.id)),
  );
}

function normalizeAbort(
  input: CanaryAbortContractInput,
  context: EvidenceContext,
  stopConditions: readonly VerifiedCanaryStopCondition[],
): VerifiedCanaryAbortContract {
  if (typeof input !== 'object' || input === null) {
    throw new Error('canary abort contract must be an object');
  }
  assertExactKeys(input, ['instructions', 'evidence'], 'canary abort contract');
  assertText(input.instructions, 'canary abort instructions', MAX_TEXT_CHARACTERS);
  const evidence = normalizeEvidence(input.evidence, context, 'canary abort evidence');
  const stopConditionIds = Object.freeze(
    stopConditions
      .filter((condition) => condition.action === 'abort' || condition.action === 'rollback')
      .map((condition) => condition.id)
      .sort(),
  );
  if (stopConditionIds.length === 0) {
    throw new Error('canary abort contract requires at least one abort or rollback trigger');
  }
  const unsigned = { instructions: input.instructions, evidence, stopConditionIds };
  return Object.freeze({
    ...unsigned,
    contractDigest: contentDigest({ domain: 'cl-canary-abort-contract-v1', contract: unsigned }),
  });
}

function aggregateSourceGroups(
  bindings: readonly ProcedureEvidenceBinding[],
): readonly string[] {
  return Object.freeze([...new Set(bindings.flatMap((binding) => binding.sourceGroups))].sort());
}

export function createBoundedCanaryPlan(
  memoryEventsInput: readonly MemoryEvent[],
  candidate: VerifiedProcedureCandidate,
  input: BoundedCanaryPlanInput,
): BoundedCanaryPlan {
  if (!isIssuedVerifiedProcedureCandidate(candidate)) {
    throw new Error('canary planning requires an issued verified procedure candidate');
  }
  if (candidate.risk === 'destructive') {
    throw new Error('destructive procedure candidates are not eligible for v1 canary planning');
  }
  const request = canonicalSnapshot(input, 'bounded canary plan input');
  assertText(request.id, 'canary plan id');
  assertDigest(request.candidateDigest, 'canary candidateDigest');
  if (request.candidateDigest !== candidate.candidateDigest) {
    throw new Error('canary plan candidate digest does not match its capability');
  }
  assertDigest(request.assignmentSeedDigest, 'canary assignmentSeedDigest');
  assertDigest(request.canonicalFingerprint, 'canary canonicalFingerprint');
  assertText(request.actor, 'canary plan actor');
  assertSafeInteger(request.recordedAt, 'canary plan recordedAt', 0, Number.MAX_SAFE_INTEGER);
  if (request.recordedAt < candidate.recordedAt) {
    throw new Error('canary plan cannot predate its procedure candidate');
  }
  const events = MemoryKernel.from(memoryEventsInput).events();
  const latestCanonicalEvent = events.at(-1);
  if (
    latestCanonicalEvent !== undefined &&
    request.recordedAt < latestCanonicalEvent.recordedAt
  ) {
    throw new Error('canary plan cannot be backdated before the canonical tail it fingerprints');
  }
  const canonicalFingerprint = fingerprintMemoryEvents(events);
  if (canonicalFingerprint !== request.canonicalFingerprint) {
    throw new Error('canary canonical fingerprint is stale or forged');
  }
  assertCanonicalPrefix(
    events,
    candidate.canonicalEventCount,
    candidate.canonicalFingerprint,
    'procedure candidate',
  );
  const currentEvidence = EvidenceProjection.from(events);
  assertCurrentEvidenceIds(
    candidate.sourceEvidenceIds,
    currentEvidence,
    candidate.scope,
    'procedure candidate evidence',
  );
  const evidenceContext: EvidenceContext = {
    historical: EvidenceProjection.from(events, request.recordedAt),
    current: currentEvidence,
    scope: candidate.scope,
    totalReferences: 0,
  };
  const population = normalizePopulation(
    request.population,
    candidate,
    request.assignmentSeedDigest,
  );
  const budget = normalizeBudget(request.budget, population.eligibleCount, candidate.risk);
  const runtime = normalizeRuntime(request.runtime, evidenceContext);
  const mutative = candidate.steps.some((step) => step.kind === 'mutate');
  const stopConditions = normalizeStopConditions(
    request.stopConditions,
    evidenceContext,
    budget,
    mutative,
  );
  const abort = normalizeAbort(request.abort, evidenceContext, stopConditions);
  if (mutative && !stopConditions.some((condition) => condition.action === 'rollback')) {
    throw new Error('mutative canaries require an explicit rollback trigger');
  }
  const evidenceBindings = [
    ...runtime.evidence,
    ...stopConditions.flatMap((condition) => condition.evidence),
    ...abort.evidence,
  ];
  const inheritedSourceEvidenceIds = uniqueSorted(candidate.sourceEvidenceIds);
  const planSourceEvidenceIds = uniqueSorted(
    evidenceBindings.map((binding) => binding.sourceId),
  );
  const planSourceGroups = aggregateSourceGroups(evidenceBindings);
  const unsigned = {
    schemaVersion: BOUNDED_CANARY_PLAN_SCHEMA_VERSION,
    id: request.id,
    candidateId: candidate.id,
    candidateDigest: candidate.candidateDigest,
    scope: candidate.scope,
    procedureId: candidate.procedureId,
    procedureVersion: candidate.version,
    risk: candidate.risk,
    assignmentSeedDigest: request.assignmentSeedDigest,
    population,
    budget,
    runtime,
    stopConditions,
    abort,
    inheritedApplicabilityDigest: candidate.applicability.bindingDigest,
    inheritedVerificationDigest: candidate.verification.contractDigest,
    inheritedRollbackDigest: candidate.rollback.contractDigest,
    canonicalFingerprint,
    canonicalEventCount: events.length,
    inheritedSourceEvidenceIds,
    planSourceEvidenceIds,
    inheritedSourceGroups: candidate.sourceGroups,
    planSourceGroups,
    actor: request.actor,
    recordedAt: request.recordedAt,
    status: 'plan' as const,
    reviewStatus: 'pending-independent-review' as const,
    executable: false as const,
    hostSchedulingAuthorized: false as const,
    procedurePromotionAuthorized: false as const,
    executionAuthorized: false as const,
  };
  const plan = canonicalSnapshot<BoundedCanaryPlan>(
    {
      ...unsigned,
      planDigest: contentDigest({ domain: 'cl-bounded-canary-plan-v1', plan: unsigned }),
    },
    'bounded canary plan',
  );
  issuedPlans.add(plan as object);
  return plan;
}

export function reviewBoundedCanaryPlan(
  memoryEventsInput: readonly MemoryEvent[],
  plan: BoundedCanaryPlan,
  input: CanaryPlanReviewInput,
): CanaryPlanReview {
  if (!isIssuedBoundedCanaryPlan(plan)) {
    throw new Error('canary review requires an issued bounded canary plan');
  }
  const request = canonicalSnapshot(input, 'canary plan review input');
  assertText(request.id, 'canary review id');
  assertText(request.planId, 'canary review planId');
  if (request.planId !== plan.id) throw new Error('canary review names a different plan');
  if (!REVIEW_DECISIONS.has(request.decision)) throw new Error('canary review decision is invalid');
  assertText(request.reviewer, 'canary reviewer');
  if (request.reviewer === plan.actor) {
    throw new Error('canary reviewer must be independent from the plan author');
  }
  assertSafeInteger(request.recordedAt, 'canary review recordedAt', 0, Number.MAX_SAFE_INTEGER);
  if (request.recordedAt < plan.recordedAt) throw new Error('canary review cannot predate the plan');
  assertDigest(request.canonicalFingerprint, 'canary review canonicalFingerprint');
  const events = MemoryKernel.from(memoryEventsInput).events();
  const latestCanonicalEvent = events.at(-1);
  if (
    latestCanonicalEvent !== undefined &&
    request.recordedAt < latestCanonicalEvent.recordedAt
  ) {
    throw new Error('canary review cannot be backdated before the canonical tail it fingerprints');
  }
  const canonicalFingerprint = fingerprintMemoryEvents(events);
  if (canonicalFingerprint !== request.canonicalFingerprint) {
    throw new Error('canary review canonical fingerprint is stale or forged');
  }
  assertCanonicalPrefix(
    events,
    plan.canonicalEventCount,
    plan.canonicalFingerprint,
    'canary plan',
  );
  const currentEvidence = EvidenceProjection.from(events);
  assertCurrentEvidenceIds(
    [...plan.inheritedSourceEvidenceIds, ...plan.planSourceEvidenceIds],
    currentEvidence,
    plan.scope,
    'canary plan evidence',
  );
  if (!Array.isArray(request.findings) || request.findings.length > MAX_FINDINGS) {
    throw new Error(`canary review cannot exceed ${MAX_FINDINGS} findings`);
  }
  const findings = request.findings.map((finding) => {
    assertText(finding, 'canary review finding', MAX_TEXT_CHARACTERS);
    return finding;
  });
  if (new Set(findings).size !== findings.length) {
    throw new Error('canary review findings cannot contain duplicates');
  }
  if (request.decision !== 'approve' && findings.length === 0) {
    throw new Error('non-approval canary reviews require at least one finding');
  }
  const evidenceContext: EvidenceContext = {
    historical: EvidenceProjection.from(events, request.recordedAt),
    current: currentEvidence,
    scope: plan.scope,
    totalReferences: 0,
  };
  const evidence = normalizeEvidence(
    request.evidence,
    evidenceContext,
    'canary review evidence',
    'tool-verified',
  );
  if (!evidence.some((binding) => binding.roles.includes('verifies'))) {
    throw new Error('canary review requires verifies evidence');
  }
  const reviewSourceGroups = aggregateSourceGroups(evidence);
  const inherited = new Set([...plan.inheritedSourceGroups, ...plan.planSourceGroups]);
  if (reviewSourceGroups.some((sourceGroup) => inherited.has(sourceGroup))) {
    throw new Error('canary review reuses a source family from candidate or plan construction');
  }
  const recommendation: CanaryReviewRecommendation =
    request.decision === 'approve'
      ? 'ready-for-host-scheduling'
      : request.decision === 'request-changes'
        ? 'changes-required'
        : 'rejected';
  const unsigned = {
    schemaVersion: BOUNDED_CANARY_PLAN_SCHEMA_VERSION,
    id: request.id,
    planId: plan.id,
    planDigest: plan.planDigest,
    decision: request.decision,
    recommendation,
    findings: Object.freeze([...findings]),
    evidence,
    reviewSourceGroups,
    canonicalFingerprint,
    canonicalEventCount: events.length,
    reviewer: request.reviewer,
    recordedAt: request.recordedAt,
    reviewComplete: true as const,
    executable: false as const,
    hostSchedulingAuthorized: false as const,
    procedurePromotionAuthorized: false as const,
    executionAuthorized: false as const,
  };
  const review = canonicalSnapshot<CanaryPlanReview>(
    {
      ...unsigned,
      reviewDigest: contentDigest({ domain: 'cl-canary-plan-review-v1', review: unsigned }),
    },
    'canary plan review',
  );
  issuedReviews.add(review as object);
  return review;
}

export function isIssuedBoundedCanaryPlan(plan: BoundedCanaryPlan): boolean {
  return typeof plan === 'object' && plan !== null && issuedPlans.has(plan as object);
}

export function isIssuedCanaryPlanReview(review: CanaryPlanReview): boolean {
  return typeof review === 'object' && review !== null && issuedReviews.has(review as object);
}
