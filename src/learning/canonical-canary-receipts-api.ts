import type { MemoryEvent } from '../domain.js';
import { canonicalJson } from '../retrieval/canonical.js';
import {
  createCanaryAdmissionReceipt as createCanaryAdmissionReceiptCore,
  evaluateCanaryStopCondition as evaluateCanaryStopConditionCore,
  isIssuedCanaryAdmissionReceipt as isIssuedAdmissionCore,
  isIssuedCanaryMonitoringObservation as isIssuedObservationCore,
  isIssuedCanaryOutcomeReceipt as isIssuedOutcomeCore,
  isIssuedCanaryRollbackReceipt as isIssuedRollbackCore,
  isIssuedCanaryRunCompletionReceipt as isIssuedCompletionCore,
  isIssuedCanaryRunStartReceipt as isIssuedStartCore,
  isIssuedCanaryStopEvaluation as isIssuedEvaluationCore,
  recordCanaryMonitoringObservation as recordCanaryMonitoringObservationCore,
  recordCanaryRollbackReceipt as recordCanaryRollbackReceiptCore,
  recordCanaryRunCompletionReceipt as recordCanaryRunCompletionReceiptCore,
  recordCanaryRunStartReceipt as recordCanaryRunStartReceiptCore,
  verifyCanaryOutcomeReceipt as verifyCanaryOutcomeReceiptCore,
  type CanaryAdmissionReceiptInput,
  type CanaryMonitoringObservationInput,
  type CanaryOutcomeVerificationInput,
  type CanaryRollbackReceiptInput,
  type CanaryRunCompletionReceiptInput,
  type CanaryRunStartReceiptInput,
  type CanaryStopEvaluationInput,
  type VerifiedCanaryAdmissionReceipt,
  type VerifiedCanaryMonitoringObservation,
  type VerifiedCanaryOutcomeReceipt,
  type VerifiedCanaryRollbackReceipt,
  type VerifiedCanaryRunCompletionReceipt,
  type VerifiedCanaryRunStartReceipt,
  type VerifiedCanaryStopEvaluation,
} from './canonical-canary-receipts.js';
import {
  isIssuedBoundedCanaryPlan,
  isIssuedCanaryPlanReview,
  type CanaryPlanReview,
  type BoundedCanaryPlan,
} from './bounded-canary-plans-api.js';

export {
  CANONICAL_CANARY_RECEIPT_SCHEMA_VERSION,
} from './canonical-canary-receipts.js';

export type {
  CanaryAdmissionReceiptInput,
  CanaryMonitoringObservationInput,
  CanaryOutcomeVerifierClass,
  CanaryOutcomeVerificationInput,
  CanaryRollbackOutcome,
  CanaryRollbackReceiptInput,
  CanaryRunnerIdentityInput,
  CanaryRunCompletionReceiptInput,
  CanaryRunStartReceiptInput,
  CanaryRunTerminalStatus,
  CanaryStopEvaluationInput,
  VerifiedCanaryAdmissionReceipt,
  VerifiedCanaryMonitoringObservation,
  VerifiedCanaryOutcomeReceipt,
  VerifiedCanaryRollbackReceipt,
  VerifiedCanaryRunnerIdentity,
  VerifiedCanaryRunCompletionReceipt,
  VerifiedCanaryRunStartReceipt,
  VerifiedCanaryStopEvaluation,
} from './canonical-canary-receipts.js';

const MAX_EVENTS = 10_000_000;
const MAX_INPUT_CHARACTERS = 1_000_000;
const MAX_IDENTITIES = 65_536;
const MAX_OBSERVATIONS_PER_METRIC = 4_096;
const MAX_OBSERVATION_ID_CANONICAL_CHARACTERS = 250_000;

interface IssuedIdentity<T> {
  readonly digest: string;
  readonly value: T;
}

interface PlanRunState {
  readonly startsByRunId: Map<string, VerifiedCanaryRunStartReceipt>;
  readonly startsBySubjectAttempt: Map<string, VerifiedCanaryRunStartReceipt>;
  readonly activeRunIds: Set<string>;
  readonly activeRunBySubjectDigest: Map<string, string>;
  readonly completionsByRunId: Map<string, VerifiedCanaryRunCompletionReceipt>;
  readonly costBeforeCompletionByRunId: Map<string, number>;
  readonly toolCallsBeforeCompletionByRunId: Map<string, number>;
  cumulativeCostMicrounits: number;
  cumulativeToolCalls: number;
}

interface MetricObservationState {
  readonly bySequence: Map<number, VerifiedCanaryMonitoringObservation>;
  readonly byId: Map<string, VerifiedCanaryMonitoringObservation>;
  lastSequence: number;
  lastSampleCount: number;
  lastObservedAt: number;
  observationIdCanonicalCharacters: number;
}

const admissionsById = new Map<string, IssuedIdentity<VerifiedCanaryAdmissionReceipt>>();
const admissionsByAssignment = new Map<
  string,
  IssuedIdentity<VerifiedCanaryAdmissionReceipt>
>();
const startsById = new Map<string, IssuedIdentity<VerifiedCanaryRunStartReceipt>>();
const startsByRunId = new Map<string, IssuedIdentity<VerifiedCanaryRunStartReceipt>>();
const completionsById = new Map<
  string,
  IssuedIdentity<VerifiedCanaryRunCompletionReceipt>
>();
const completionsByRunId = new Map<
  string,
  IssuedIdentity<VerifiedCanaryRunCompletionReceipt>
>();
const observationsById = new Map<
  string,
  IssuedIdentity<VerifiedCanaryMonitoringObservation>
>();
const evaluationsById = new Map<string, IssuedIdentity<VerifiedCanaryStopEvaluation>>();
const evaluationsByConditionSet = new Map<
  string,
  IssuedIdentity<VerifiedCanaryStopEvaluation>
>();
const rollbacksById = new Map<string, IssuedIdentity<VerifiedCanaryRollbackReceipt>>();
const rollbacksByEvaluation = new Map<
  string,
  IssuedIdentity<VerifiedCanaryRollbackReceipt>
>();
const outcomesById = new Map<string, IssuedIdentity<VerifiedCanaryOutcomeReceipt>>();
const outcomesByCompletion = new Map<string, IssuedIdentity<VerifiedCanaryOutcomeReceipt>>();
const runStateByPlan = new Map<string, PlanRunState>();
const observationsByPlanMetric = new Map<string, MetricObservationState>();
const publicAdmissions = new WeakSet<object>();
const publicStarts = new WeakSet<object>();
const publicCompletions = new WeakSet<object>();
const publicObservations = new WeakSet<object>();
const publicEvaluations = new WeakSet<object>();
const publicRollbacks = new WeakSet<object>();
const publicOutcomes = new WeakSet<object>();

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as unknown as Record<string, unknown>)) deepFreeze(child);
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

function snapshotEvents(eventsInput: readonly MemoryEvent[]): readonly MemoryEvent[] {
  if (!Array.isArray(eventsInput)) throw new TypeError('canary receipt events must be an array');
  if (eventsInput.length > MAX_EVENTS) {
    throw new RangeError(`canary receipt events cannot exceed ${MAX_EVENTS} entries`);
  }
  return Object.freeze(Array.from(eventsInput));
}

function snapshotArray<T>(valuesInput: readonly T[], label: string, maximum: number): readonly T[] {
  if (!Array.isArray(valuesInput) || valuesInput.length > maximum) {
    throw new TypeError(`${label} must be an array with at most ${maximum} values`);
  }
  return Object.freeze(Array.from(valuesInput));
}

function assertPublicPlanAndReview(
  plan: BoundedCanaryPlan,
  review: CanaryPlanReview,
): void {
  if (!isIssuedBoundedCanaryPlan(plan)) {
    throw new Error('canonical canary receipt requires an issued plan capability');
  }
  if (!isIssuedCanaryPlanReview(review)) {
    throw new Error('canonical canary receipt requires an issued review capability');
  }
}

function inspectIdentity<T>(
  key: string,
  digest: string,
  registry: Map<string, IssuedIdentity<T>>,
  label: string,
): T | undefined {
  const previous = registry.get(key);
  if (previous !== undefined && previous.digest !== digest) {
    throw new Error(`${label} conflicts with an already issued identity: ${key}`);
  }
  return previous?.value;
}

function assertCapacity<T>(
  registry: Map<string, IssuedIdentity<T>>,
  adding: boolean,
  label: string,
): void {
  if (adding && registry.size >= MAX_IDENTITIES) {
    throw new RangeError(`${label} registry cannot exceed ${MAX_IDENTITIES} identities`);
  }
}

function bindTwo<T>(
  firstKey: string,
  secondKey: string,
  digest: string,
  value: T,
  first: Map<string, IssuedIdentity<T>>,
  second: Map<string, IssuedIdentity<T>>,
  firstLabel: string,
  secondLabel: string,
): T {
  const byFirst = inspectIdentity(firstKey, digest, first, firstLabel);
  const bySecond = inspectIdentity(secondKey, digest, second, secondLabel);
  if (byFirst !== undefined && bySecond !== undefined && byFirst !== bySecond) {
    throw new Error(`${firstLabel} and ${secondLabel} bindings disagree`);
  }
  assertCapacity(first, byFirst === undefined, firstLabel);
  assertCapacity(second, bySecond === undefined, secondLabel);
  const selected = byFirst ?? bySecond ?? value;
  if (byFirst === undefined) first.set(firstKey, Object.freeze({ digest, value: selected }));
  if (bySecond === undefined) second.set(secondKey, Object.freeze({ digest, value: selected }));
  return selected;
}

function planRunState(planDigest: string): PlanRunState {
  const existing = runStateByPlan.get(planDigest);
  if (existing !== undefined) return existing;
  if (runStateByPlan.size >= MAX_IDENTITIES) {
    throw new RangeError(`canary plan run-state registry cannot exceed ${MAX_IDENTITIES} plans`);
  }
  const created: PlanRunState = {
    startsByRunId: new Map(),
    startsBySubjectAttempt: new Map(),
    activeRunIds: new Set(),
    activeRunBySubjectDigest: new Map(),
    completionsByRunId: new Map(),
    costBeforeCompletionByRunId: new Map(),
    toolCallsBeforeCompletionByRunId: new Map(),
    cumulativeCostMicrounits: 0,
    cumulativeToolCalls: 0,
  };
  runStateByPlan.set(planDigest, created);
  return created;
}

function metricState(planDigest: string, metric: string): MetricObservationState {
  const key = `${planDigest}:${metric}`;
  const existing = observationsByPlanMetric.get(key);
  if (existing !== undefined) return existing;
  if (observationsByPlanMetric.size >= MAX_IDENTITIES) {
    throw new RangeError(`canary metric registry cannot exceed ${MAX_IDENTITIES} metrics`);
  }
  const created: MetricObservationState = {
    bySequence: new Map(),
    byId: new Map(),
    lastSequence: 0,
    lastSampleCount: 0,
    lastObservedAt: 0,
    observationIdCanonicalCharacters: 0,
  };
  observationsByPlanMetric.set(key, created);
  return created;
}

/** Record that an external host admitted one deterministic plan assignment. */
export function createCanaryAdmissionReceipt(
  eventsInput: readonly MemoryEvent[],
  plan: BoundedCanaryPlan,
  review: CanaryPlanReview,
  input: CanaryAdmissionReceiptInput,
): VerifiedCanaryAdmissionReceipt {
  assertPublicPlanAndReview(plan, review);
  const events = snapshotEvents(eventsInput);
  const request = canonicalSnapshot(input, 'canary admission receipt input');
  const receipt = createCanaryAdmissionReceiptCore(events, plan, review, request);
  if (!isIssuedAdmissionCore(receipt)) throw new Error('canary admission core did not issue a capability');
  const assignmentKey = `${receipt.planDigest}:${receipt.assignmentDigest}`;
  const selected = bindTwo(
    receipt.id,
    assignmentKey,
    receipt.receiptDigest,
    receipt,
    admissionsById,
    admissionsByAssignment,
    'canary admission id',
    'canary admitted assignment',
  );
  publicAdmissions.add(selected as object);
  return selected;
}

/**
 * Record an externally granted run start while enforcing process-local run, attempt and concurrency
 * bounds. This validates a host grant; it does not manufacture one.
 */
export function recordCanaryRunStartReceipt(
  eventsInput: readonly MemoryEvent[],
  plan: BoundedCanaryPlan,
  review: CanaryPlanReview,
  admission: VerifiedCanaryAdmissionReceipt,
  input: CanaryRunStartReceiptInput,
): VerifiedCanaryRunStartReceipt {
  assertPublicPlanAndReview(plan, review);
  if (
    typeof admission !== 'object' ||
    admission === null ||
    !isIssuedAdmissionCore(admission) ||
    !publicAdmissions.has(admission as object)
  ) {
    throw new Error('canary run start requires a guarded public admission receipt');
  }
  const events = snapshotEvents(eventsInput);
  const request = canonicalSnapshot(input, 'canary run start receipt input');
  const receipt = recordCanaryRunStartReceiptCore(events, plan, review, admission, request);
  if (!isIssuedStartCore(receipt)) throw new Error('canary run start core did not issue a capability');

  const state = planRunState(plan.planDigest);
  const subjectAttemptKey = `${receipt.subjectDigest}:attempt:${receipt.attempt}`;
  const previousId = inspectIdentity(receipt.id, receipt.receiptDigest, startsById, 'canary run start id');
  const previousRun = inspectIdentity(receipt.runId, receipt.receiptDigest, startsByRunId, 'canary run id');
  const previousAttempt = state.startsBySubjectAttempt.get(subjectAttemptKey);
  if (previousAttempt !== undefined && previousAttempt.receiptDigest !== receipt.receiptDigest) {
    throw new Error(`canary subject attempt already has another run: ${subjectAttemptKey}`);
  }
  if (previousId !== undefined || previousRun !== undefined || previousAttempt !== undefined) {
    const selected = previousId ?? previousRun ?? previousAttempt;
    if (selected === undefined || selected.receiptDigest !== receipt.receiptDigest) {
      throw new Error('canary run start retry identities disagree');
    }
    publicStarts.add(selected as object);
    return selected;
  }
  const activeRunId = state.activeRunBySubjectDigest.get(receipt.subjectDigest);
  if (activeRunId !== undefined) {
    throw new Error(
      `canary subject already has an active run: ${receipt.subjectDigest} (${activeRunId})`,
    );
  }
  if (receipt.attempt > 1) {
    const precedingAttemptKey = `${receipt.subjectDigest}:attempt:${receipt.attempt - 1}`;
    const precedingStart = state.startsBySubjectAttempt.get(precedingAttemptKey);
    if (precedingStart === undefined) {
      throw new Error('canary retry requires the immediately preceding subject attempt');
    }
    const precedingCompletion = state.completionsByRunId.get(precedingStart.runId);
    if (precedingCompletion === undefined) {
      throw new Error('canary retry requires a completed preceding subject attempt');
    }
    if (precedingCompletion.terminalStatus === 'success') {
      throw new Error('canary retry cannot follow a successful subject attempt');
    }
  }
  if (state.startsByRunId.size >= plan.budget.maxRuns) {
    throw new Error('canary plan has reached its maximum run count');
  }
  if (state.activeRunIds.size >= plan.budget.maxConcurrentRuns) {
    throw new Error('canary plan has reached its maximum concurrent run count');
  }
  assertCapacity(startsById, true, 'canary run start id');
  assertCapacity(startsByRunId, true, 'canary run id');
  startsById.set(receipt.id, Object.freeze({ digest: receipt.receiptDigest, value: receipt }));
  startsByRunId.set(receipt.runId, Object.freeze({ digest: receipt.receiptDigest, value: receipt }));
  state.startsByRunId.set(receipt.runId, receipt);
  state.startsBySubjectAttempt.set(subjectAttemptKey, receipt);
  state.activeRunIds.add(receipt.runId);
  state.activeRunBySubjectDigest.set(receipt.subjectDigest, receipt.runId);
  publicStarts.add(receipt as object);
  return receipt;
}

/** Record external completion evidence, close one active slot, and retain cumulative cost. */
export function recordCanaryRunCompletionReceipt(
  eventsInput: readonly MemoryEvent[],
  plan: BoundedCanaryPlan,
  review: CanaryPlanReview,
  start: VerifiedCanaryRunStartReceipt,
  input: CanaryRunCompletionReceiptInput,
): VerifiedCanaryRunCompletionReceipt {
  assertPublicPlanAndReview(plan, review);
  if (
    typeof start !== 'object' ||
    start === null ||
    !isIssuedStartCore(start) ||
    !publicStarts.has(start as object)
  ) {
    throw new Error('canary completion requires a guarded public run start receipt');
  }
  const state = planRunState(plan.planDigest);
  if (state.startsByRunId.get(start.runId) !== start) {
    throw new Error('canary completion start is absent from the plan run registry');
  }
  const events = snapshotEvents(eventsInput);
  const request = canonicalSnapshot(input, 'canary run completion receipt input');
  const costBefore =
    state.costBeforeCompletionByRunId.get(start.runId) ?? state.cumulativeCostMicrounits;
  const toolCallsBefore =
    state.toolCallsBeforeCompletionByRunId.get(start.runId) ?? state.cumulativeToolCalls;
  const receipt = recordCanaryRunCompletionReceiptCore(
    events,
    plan,
    review,
    start,
    request,
    costBefore,
    toolCallsBefore,
  );
  if (!isIssuedCompletionCore(receipt)) {
    throw new Error('canary run completion core did not issue a capability');
  }
  const previousId = inspectIdentity(
    receipt.id,
    receipt.receiptDigest,
    completionsById,
    'canary completion id',
  );
  const previousRun = inspectIdentity(
    receipt.runId,
    receipt.receiptDigest,
    completionsByRunId,
    'canary completed run',
  );
  const statePrevious = state.completionsByRunId.get(receipt.runId);
  if (statePrevious !== undefined && statePrevious.receiptDigest !== receipt.receiptDigest) {
    throw new Error('canary run already has another completion receipt');
  }
  if (previousId !== undefined || previousRun !== undefined || statePrevious !== undefined) {
    const selected = previousId ?? previousRun ?? statePrevious;
    if (selected === undefined || selected.receiptDigest !== receipt.receiptDigest) {
      throw new Error('canary completion retry identities disagree');
    }
    publicCompletions.add(selected as object);
    return selected;
  }
  if (!state.activeRunIds.has(start.runId)) {
    throw new Error('canary completion cannot close a run that is not active');
  }
  if (state.activeRunBySubjectDigest.get(start.subjectDigest) !== start.runId) {
    throw new Error('canary completion does not match the subject active-run registry');
  }
  assertCapacity(completionsById, true, 'canary completion id');
  assertCapacity(completionsByRunId, true, 'canary completed run');
  completionsById.set(receipt.id, Object.freeze({ digest: receipt.receiptDigest, value: receipt }));
  completionsByRunId.set(
    receipt.runId,
    Object.freeze({ digest: receipt.receiptDigest, value: receipt }),
  );
  state.costBeforeCompletionByRunId.set(receipt.runId, costBefore);
  state.toolCallsBeforeCompletionByRunId.set(receipt.runId, toolCallsBefore);
  state.cumulativeCostMicrounits = receipt.cumulativeCostMicrounits;
  state.cumulativeToolCalls = receipt.cumulativeToolCalls;
  state.completionsByRunId.set(receipt.runId, receipt);
  state.activeRunIds.delete(receipt.runId);
  state.activeRunBySubjectDigest.delete(receipt.subjectDigest);
  publicCompletions.add(receipt as object);
  return receipt;
}

/** Record one monotonic cumulative observer sample for a metric declared by the plan. */
export function recordCanaryMonitoringObservation(
  eventsInput: readonly MemoryEvent[],
  plan: BoundedCanaryPlan,
  review: CanaryPlanReview,
  input: CanaryMonitoringObservationInput,
): VerifiedCanaryMonitoringObservation {
  assertPublicPlanAndReview(plan, review);
  const events = snapshotEvents(eventsInput);
  const request = canonicalSnapshot(input, 'canary monitoring observation input');
  const receipt = recordCanaryMonitoringObservationCore(events, plan, review, request);
  if (!isIssuedObservationCore(receipt)) {
    throw new Error('canary monitoring core did not issue a capability');
  }
  const state = metricState(plan.planDigest, receipt.metric);
  const previousId = inspectIdentity(
    receipt.id,
    receipt.receiptDigest,
    observationsById,
    'canary monitoring observation id',
  );
  const previousSequence = state.bySequence.get(receipt.sequence);
  if (previousSequence !== undefined && previousSequence.receiptDigest !== receipt.receiptDigest) {
    throw new Error(`canary monitoring sequence already exists: ${receipt.sequence}`);
  }
  if (previousId !== undefined || previousSequence !== undefined) {
    const selected = previousId ?? previousSequence;
    if (selected === undefined || selected.receiptDigest !== receipt.receiptDigest) {
      throw new Error('canary monitoring retry identities disagree');
    }
    publicObservations.add(selected as object);
    return selected;
  }
  const encodedIdCharacters = canonicalJson(receipt.id).length + 1;
  if (
    state.bySequence.size >= MAX_OBSERVATIONS_PER_METRIC ||
    state.observationIdCanonicalCharacters + encodedIdCharacters >
      MAX_OBSERVATION_ID_CANONICAL_CHARACTERS
  ) {
    throw new RangeError(
      'canary monitoring prefix exceeds the complete-evaluation representation bound',
    );
  }
  if (receipt.sequence !== state.lastSequence + 1) {
    throw new Error(`canary monitoring sequence must advance to ${state.lastSequence + 1}`);
  }
  if (receipt.sampleCount < state.lastSampleCount) {
    throw new Error('canary monitoring sampleCount cannot regress');
  }
  if (receipt.observedAt < state.lastObservedAt) {
    throw new Error('canary monitoring observedAt cannot regress');
  }
  assertCapacity(observationsById, true, 'canary monitoring observation id');
  observationsById.set(receipt.id, Object.freeze({ digest: receipt.receiptDigest, value: receipt }));
  state.bySequence.set(receipt.sequence, receipt);
  state.byId.set(receipt.id, receipt);
  state.lastSequence = receipt.sequence;
  state.lastSampleCount = receipt.sampleCount;
  state.lastObservedAt = receipt.observedAt;
  state.observationIdCanonicalCharacters += encodedIdCharacters;
  publicObservations.add(receipt as object);
  return receipt;
}

/**
 * Evaluate one stop condition against the complete process-local observation prefix for that metric.
 * A caller cannot omit a previously admitted sample from the evaluation.
 */
export function evaluateCanaryStopCondition(
  eventsInput: readonly MemoryEvent[],
  plan: BoundedCanaryPlan,
  review: CanaryPlanReview,
  observationsInput: readonly VerifiedCanaryMonitoringObservation[],
  input: CanaryStopEvaluationInput,
): VerifiedCanaryStopEvaluation {
  assertPublicPlanAndReview(plan, review);
  const observations = snapshotArray(observationsInput, 'canary stop observations', 4_096);
  for (const observation of observations) {
    if (
      typeof observation !== 'object' ||
      observation === null ||
      !isIssuedObservationCore(observation) ||
      !publicObservations.has(observation as object)
    ) {
      throw new Error('canary stop evaluation requires guarded public observations');
    }
  }
  const events = snapshotEvents(eventsInput);
  const request = canonicalSnapshot(input, 'canary stop evaluation input');
  const condition = plan.stopConditions.find((candidate) => candidate.id === request.conditionId);
  if (condition === undefined) throw new Error('canary stop evaluation references an unknown condition');
  const state = metricState(plan.planDigest, condition.metric);
  const expected = [...state.bySequence.values()]
    .filter((observation) => observation.observedAt <= request.evaluatedAt)
    .sort((left, right) => left.sequence - right.sequence);
  const suppliedIds = [...observations.map((observation) => observation.id)].sort();
  const expectedIds = expected.map((observation) => observation.id).sort();
  if (
    suppliedIds.length !== expectedIds.length ||
    suppliedIds.some((id, index) => id !== expectedIds[index])
  ) {
    throw new Error('canary stop evaluation omits or invents admitted monitoring observations');
  }
  const evaluation = evaluateCanaryStopConditionCore(events, plan, review, observations, request);
  if (!isIssuedEvaluationCore(evaluation)) {
    throw new Error('canary stop evaluation core did not issue a capability');
  }
  const conditionSetKey = `${evaluation.planDigest}:${evaluation.conditionDigest}:${evaluation.observationSetDigest}`;
  const selected = bindTwo(
    evaluation.id,
    conditionSetKey,
    evaluation.evaluationDigest,
    evaluation,
    evaluationsById,
    evaluationsByConditionSet,
    'canary stop evaluation id',
    'canary condition observation set',
  );
  publicEvaluations.add(selected as object);
  return selected;
}

/** Record external rollback execution after a triggered stop-and-rollback evaluation. */
export function recordCanaryRollbackReceipt(
  eventsInput: readonly MemoryEvent[],
  plan: BoundedCanaryPlan,
  review: CanaryPlanReview,
  evaluation: VerifiedCanaryStopEvaluation,
  input: CanaryRollbackReceiptInput,
): VerifiedCanaryRollbackReceipt {
  assertPublicPlanAndReview(plan, review);
  if (
    typeof evaluation !== 'object' ||
    evaluation === null ||
    !isIssuedEvaluationCore(evaluation) ||
    !publicEvaluations.has(evaluation as object)
  ) {
    throw new Error('canary rollback requires a guarded public stop evaluation');
  }
  const events = snapshotEvents(eventsInput);
  const request = canonicalSnapshot(input, 'canary rollback receipt input');
  const receipt = recordCanaryRollbackReceiptCore(events, plan, review, evaluation, request);
  if (!isIssuedRollbackCore(receipt)) throw new Error('canary rollback core did not issue a capability');
  const selected = bindTwo(
    receipt.id,
    receipt.evaluationDigest,
    receipt.receiptDigest,
    receipt,
    rollbacksById,
    rollbacksByEvaluation,
    'canary rollback receipt id',
    'canary rolled-back evaluation',
  );
  publicRollbacks.add(selected as object);
  return selected;
}

/** Bind a completion to one canonical outcome event and the planned verifier family. */
export function verifyCanaryOutcomeReceipt(
  eventsInput: readonly MemoryEvent[],
  plan: BoundedCanaryPlan,
  review: CanaryPlanReview,
  completion: VerifiedCanaryRunCompletionReceipt,
  input: CanaryOutcomeVerificationInput,
): VerifiedCanaryOutcomeReceipt {
  assertPublicPlanAndReview(plan, review);
  if (
    typeof completion !== 'object' ||
    completion === null ||
    !isIssuedCompletionCore(completion) ||
    !publicCompletions.has(completion as object)
  ) {
    throw new Error('canary outcome verification requires a guarded public completion receipt');
  }
  const events = snapshotEvents(eventsInput);
  const request = canonicalSnapshot(input, 'canary outcome verification input');
  const receipt = verifyCanaryOutcomeReceiptCore(events, plan, review, completion, request);
  if (!isIssuedOutcomeCore(receipt)) throw new Error('canary outcome core did not issue a capability');
  const selected = bindTwo(
    receipt.id,
    receipt.completionReceiptDigest,
    receipt.receiptDigest,
    receipt,
    outcomesById,
    outcomesByCompletion,
    'canary outcome receipt id',
    'canary verified completion',
  );
  publicOutcomes.add(selected as object);
  return selected;
}

export function isIssuedCanaryAdmissionReceipt(
  value: VerifiedCanaryAdmissionReceipt,
): boolean {
  return typeof value === 'object' && value !== null && publicAdmissions.has(value as object);
}

export function isIssuedCanaryRunStartReceipt(
  value: VerifiedCanaryRunStartReceipt,
): boolean {
  return typeof value === 'object' && value !== null && publicStarts.has(value as object);
}

export function isIssuedCanaryRunCompletionReceipt(
  value: VerifiedCanaryRunCompletionReceipt,
): boolean {
  return typeof value === 'object' && value !== null && publicCompletions.has(value as object);
}

export function isIssuedCanaryMonitoringObservation(
  value: VerifiedCanaryMonitoringObservation,
): boolean {
  return typeof value === 'object' && value !== null && publicObservations.has(value as object);
}

export function isIssuedCanaryStopEvaluation(
  value: VerifiedCanaryStopEvaluation,
): boolean {
  return typeof value === 'object' && value !== null && publicEvaluations.has(value as object);
}

export function isIssuedCanaryRollbackReceipt(
  value: VerifiedCanaryRollbackReceipt,
): boolean {
  return typeof value === 'object' && value !== null && publicRollbacks.has(value as object);
}

export function isIssuedCanaryOutcomeReceipt(
  value: VerifiedCanaryOutcomeReceipt,
): boolean {
  return typeof value === 'object' && value !== null && publicOutcomes.has(value as object);
}
