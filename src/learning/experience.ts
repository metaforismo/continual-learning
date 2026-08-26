import { createHash } from 'node:crypto';

import type { MemoryPacketKind } from '../context.js';
import type { EvidenceRole, MemoryEvent } from '../domain.js';
import { EvidenceProjection } from '../evidence.js';
import { MemoryKernel } from '../kernel.js';
import { fingerprintMemoryEvents } from '../transitions/verifier.js';

const EXPERIENCE_SCHEMA_VERSION = 1 as const;
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const EXPOSURE_STAGES = new Set(['activated', 'materialized', 'consulted', 'applied']);
const CAPTURE_MODES = new Set(['runtime-instrumented', 'human-reviewed', 'model-self-report']);
const VERIFIERS = new Set(['none', 'model', 'tool', 'test', 'human']);

function stableJson(value: unknown, path = '$', ancestors = new WeakSet<object>()): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      throw new TypeError(`${path} contains a non-canonical number`);
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (ancestors.has(value)) throw new TypeError(`${path} contains a circular reference`);
    ancestors.add(value);
    const items: string[] = [];
    for (let index = 0; index < value.length; index += 1) {
      if (!(index in value)) throw new TypeError(`${path} contains a sparse array`);
      items.push(stableJson(value[index], `${path}[${index}]`, ancestors));
    }
    ancestors.delete(value);
    return `[${items.join(',')}]`;
  }
  if (typeof value === 'object') {
    if (ancestors.has(value)) throw new TypeError(`${path} contains a circular reference`);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(`${path} must contain only plain JSON objects`);
    }
    ancestors.add(value);
    const objectValue = value as Record<string, unknown>;
    const entries = Object.keys(objectValue)
      .sort()
      .map((key) => {
        const item = objectValue[key];
        if (item === undefined) throw new TypeError(`${path}.${key} cannot be undefined`);
        return `${JSON.stringify(key)}:${stableJson(item, `${path}.${key}`, ancestors)}`;
      });
    ancestors.delete(value);
    return `{${entries.join(',')}}`;
  }
  throw new TypeError(`${path} contains a non-JSON value`);
}

function digest(value: unknown): string {
  return `sha256:${createHash('sha256').update(stableJson(value)).digest('hex')}`;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as unknown as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function canonicalClone<T>(value: T): T {
  return deepFreeze(JSON.parse(stableJson(value)) as T);
}

function assertDigest(value: string, label: string): void {
  if (!SHA256_PATTERN.test(value)) throw new Error(`${label} must be a SHA-256 content address`);
}

function uniqueStrings(values: readonly string[], label: string): readonly string[] {
  if (!Array.isArray(values) || values.some((value) => typeof value !== 'string' || value.trim().length === 0)) {
    throw new Error(`${label} must contain non-empty strings`);
  }
  if (new Set(values).size !== values.length) throw new Error(`${label} cannot contain duplicates`);
  return Object.freeze([...values]);
}

export type ExperienceCaptureMode =
  | 'runtime-instrumented'
  | 'human-reviewed'
  | 'model-self-report';

export type MemoryExposureStage =
  | 'activated'
  | 'materialized'
  | 'consulted'
  | 'applied';

export interface ExperienceUnit {
  readonly taskFamily: string;
  readonly instanceDigest: string;
  readonly environmentDigest: string;
  readonly seed?: string;
}

export interface MemoryExposureInput {
  readonly memoryId: string;
  readonly kind: MemoryPacketKind;
  readonly stage: MemoryExposureStage;
  readonly evidenceSourceIds: readonly string[];
  readonly roles?: readonly EvidenceRole[];
  /** Required when the memory was not applied. */
  readonly nonUseReason?: string;
}

export interface MemoryExposure extends MemoryExposureInput {
  readonly evidenceSourceIds: readonly string[];
  readonly roles: readonly EvidenceRole[];
  readonly creditEligible: boolean;
}

export interface ExperienceTraceInput {
  readonly id: string;
  readonly scope: string;
  readonly runId: string;
  readonly taskId: string;
  readonly contextFingerprint: string;
  readonly goalSignature: string;
  readonly unit: ExperienceUnit;
  readonly startedAt: number;
  readonly completedAt: number;
  readonly captureMode: ExperienceCaptureMode;
  readonly recorder: string;
  readonly canonicalFingerprint: string;
  readonly outcomeEventId: string;
  readonly exposures: readonly MemoryExposureInput[];
}

export interface VerifiedExperienceTrace {
  readonly schemaVersion: typeof EXPERIENCE_SCHEMA_VERSION;
  readonly id: string;
  readonly scope: string;
  readonly runId: string;
  readonly taskId: string;
  readonly contextFingerprint: string;
  readonly goalSignature: string;
  readonly unit: ExperienceUnit;
  readonly unitDigest: string;
  readonly startedAt: number;
  readonly completedAt: number;
  readonly captureMode: ExperienceCaptureMode;
  readonly recorder: string;
  readonly canonicalFingerprint: string;
  readonly outcomeEventId: string;
  readonly outcome: 'success' | 'failure' | 'partial' | 'unknown';
  readonly verifier: 'none' | 'model' | 'tool' | 'test' | 'human';
  readonly outcomeSourceGroups: readonly string[];
  readonly exposures: readonly MemoryExposure[];
  readonly traceDigest: string;
}

export interface MemoryInterventionInput {
  readonly id: string;
  readonly memoryId: string;
  readonly treatmentTraceId: string;
  readonly controlTraceId: string;
  readonly intervention: 'removed';
  readonly actor: string;
  readonly recordedAt: number;
}

export interface VerifiedMemoryIntervention extends MemoryInterventionInput {
  readonly schemaVersion: typeof EXPERIENCE_SCHEMA_VERSION;
  readonly unitDigest: string;
  readonly contextFingerprint: string;
  readonly treatmentOutcome: VerifiedExperienceTrace['outcome'];
  readonly controlOutcome: VerifiedExperienceTrace['outcome'];
  readonly effect: number;
  readonly sourceGroups: readonly string[];
  readonly comparisonDigest: string;
}

export interface MemoryUtilityPolicy {
  readonly minIndependentPairs: number;
  readonly minDistinctContexts: number;
  readonly minMeanAbsoluteEffect: number;
  readonly minDirectionalRate: number;
  readonly minDirectionalWilsonLowerBound: number;
  readonly maxOppositeRate: number;
  readonly neutralThreshold: number;
}

export interface MemoryUtilityAssessment {
  readonly memoryId: string;
  readonly status:
    | 'insufficient'
    | 'supported-positive'
    | 'supported-negative'
    | 'mixed'
    | 'neutral';
  readonly independentPairs: number;
  readonly excludedCorrelatedPairs: number;
  readonly distinctContexts: number;
  readonly positivePairs: number;
  readonly negativePairs: number;
  readonly neutralPairs: number;
  readonly meanEffect: number;
  readonly positiveRate: number;
  readonly negativeRate: number;
  readonly positiveWilsonLowerBound: number;
  readonly negativeWilsonLowerBound: number;
  readonly correlatedVerifiedSuccesses: number;
  readonly comparisonIds: readonly string[];
  readonly excludedComparisonIds: readonly string[];
  readonly blockers: readonly string[];
}

export const DEFAULT_MEMORY_UTILITY_POLICY: Readonly<MemoryUtilityPolicy> = Object.freeze({
  minIndependentPairs: 5,
  minDistinctContexts: 2,
  minMeanAbsoluteEffect: 0.2,
  minDirectionalRate: 0.6,
  minDirectionalWilsonLowerBound: 0.3,
  maxOppositeRate: 0.2,
  neutralThreshold: 0.1,
});

function validateUnit(unit: ExperienceUnit): ExperienceUnit {
  if (
    typeof unit.taskFamily !== 'string' ||
    unit.taskFamily.trim().length === 0 ||
    (unit.seed !== undefined && (typeof unit.seed !== 'string' || unit.seed.trim().length === 0))
  ) {
    throw new Error('experience unit taskFamily and optional seed must be non-empty');
  }
  assertDigest(unit.instanceDigest, 'experience unit instanceDigest');
  assertDigest(unit.environmentDigest, 'experience unit environmentDigest');
  return canonicalClone(unit);
}

function outcomeEvent(
  events: readonly MemoryEvent[],
  eventId: string,
): Extract<MemoryEvent, { type: 'outcome.recorded' }> {
  const event = events.find((candidate) => candidate.id === eventId);
  if (event === undefined || event.type !== 'outcome.recorded') {
    throw new Error(`experience trace outcome event does not exist: ${eventId}`);
  }
  return event;
}

export function recordExperienceTrace(
  memoryEvents: readonly MemoryEvent[],
  input: ExperienceTraceInput,
): VerifiedExperienceTrace {
  const events = MemoryKernel.from(memoryEvents).events();
  const snapshotFingerprint = fingerprintMemoryEvents(events);
  if (input.canonicalFingerprint !== snapshotFingerprint) {
    throw new Error('experience trace canonical fingerprint is stale or forged');
  }
  if (
    typeof input.id !== 'string' ||
    input.id.trim().length === 0 ||
    typeof input.scope !== 'string' ||
    input.scope.trim().length === 0 ||
    typeof input.runId !== 'string' ||
    input.runId.trim().length === 0 ||
    typeof input.taskId !== 'string' ||
    input.taskId.trim().length === 0 ||
    typeof input.contextFingerprint !== 'string' ||
    input.contextFingerprint.trim().length === 0 ||
    typeof input.goalSignature !== 'string' ||
    input.goalSignature.trim().length === 0 ||
    typeof input.recorder !== 'string' ||
    input.recorder.trim().length === 0
  ) {
    throw new Error('experience trace identity, scope, task, goal, context, and recorder are required');
  }
  if (!CAPTURE_MODES.has(input.captureMode)) throw new Error('experience capture mode is invalid');
  if (
    !Number.isFinite(input.startedAt) ||
    !Number.isFinite(input.completedAt) ||
    input.startedAt < 0 ||
    input.completedAt < input.startedAt
  ) {
    throw new Error('experience trace time interval is invalid');
  }
  if (!Array.isArray(input.exposures)) throw new Error('experience exposures must be an array');
  const ids = new Set<string>();
  const evidence = EvidenceProjection.from(events);
  const exposures: MemoryExposure[] = [];
  for (const exposure of input.exposures) {
    if (
      typeof exposure.memoryId !== 'string' ||
      exposure.memoryId.trim().length === 0 ||
      ids.has(exposure.memoryId)
    ) {
      throw new Error('experience memory ids must be non-empty and unique');
    }
    ids.add(exposure.memoryId);
    if (!EXPOSURE_STAGES.has(exposure.stage)) throw new Error('memory exposure stage is invalid');
    const sourceIds = uniqueStrings(exposure.evidenceSourceIds, 'memory exposure evidenceSourceIds');
    if (sourceIds.length === 0) throw new Error('memory exposure requires recoverable evidence');
    for (const sourceId of sourceIds) {
      const projected = evidence.get(sourceId);
      if (projected === undefined || projected.availability !== 'available') {
        throw new Error(`memory exposure evidence is unavailable: ${sourceId}`);
      }
      if (projected.record.scope !== 'global' && projected.record.scope !== input.scope) {
        throw new Error(`memory exposure evidence scope is unauthorized: ${sourceId}`);
      }
    }
    const roles = exposure.roles === undefined
      ? Object.freeze([])
      : uniqueStrings(exposure.roles, 'memory exposure roles') as readonly EvidenceRole[];
    if (
      exposure.stage !== 'applied' &&
      (typeof exposure.nonUseReason !== 'string' || exposure.nonUseReason.trim().length === 0)
    ) {
      throw new Error('non-applied memory exposure requires a nonUseReason');
    }
    exposures.push(
      Object.freeze({
        memoryId: exposure.memoryId,
        kind: exposure.kind,
        stage: exposure.stage,
        evidenceSourceIds: sourceIds,
        roles,
        ...(exposure.nonUseReason === undefined ? {} : { nonUseReason: exposure.nonUseReason }),
        creditEligible:
          exposure.stage === 'applied' && input.captureMode === 'runtime-instrumented',
      }),
    );
  }

  const outcome = outcomeEvent(events, input.outcomeEventId);
  if (
    outcome.data.scope !== input.scope ||
    outcome.data.taskId !== input.taskId ||
    outcome.data.contextFingerprint !== input.contextFingerprint
  ) {
    throw new Error('experience trace does not match its canonical outcome scope/task/context');
  }
  if (!VERIFIERS.has(outcome.data.verifier)) throw new Error('canonical outcome verifier is invalid');
  if (input.completedAt > outcome.recordedAt) {
    throw new Error('experience trace cannot complete after its canonical outcome was recorded');
  }
  if (!outcome.data.evidence.every((reference) => evidence.validatesReference(reference))) {
    throw new Error('experience trace outcome evidence is unavailable or forged');
  }
  const unit = validateUnit(input.unit);
  const unsigned = Object.freeze({
    schemaVersion: EXPERIENCE_SCHEMA_VERSION,
    id: input.id,
    scope: input.scope,
    runId: input.runId,
    taskId: input.taskId,
    contextFingerprint: input.contextFingerprint,
    goalSignature: input.goalSignature,
    unit,
    unitDigest: digest({ domain: 'cl-experience-unit-v1', unit }),
    startedAt: input.startedAt,
    completedAt: input.completedAt,
    captureMode: input.captureMode,
    recorder: input.recorder,
    canonicalFingerprint: input.canonicalFingerprint,
    outcomeEventId: input.outcomeEventId,
    outcome: outcome.data.outcome,
    verifier: outcome.data.verifier,
    outcomeSourceGroups: Object.freeze([...outcome.data.sourceGroups]),
    exposures: Object.freeze(exposures),
  });
  return canonicalClone({
    ...unsigned,
    traceDigest: digest({ domain: 'cl-experience-trace-v1', trace: unsigned }),
  });
}

function appliedMemoryIds(trace: VerifiedExperienceTrace): readonly string[] {
  return Object.freeze(
    trace.exposures
      .filter((exposure) => exposure.stage === 'applied' && exposure.creditEligible)
      .map((exposure) => exposure.memoryId)
      .sort(),
  );
}

function outcomeScore(outcome: VerifiedExperienceTrace['outcome']): number | undefined {
  switch (outcome) {
    case 'success':
      return 1;
    case 'partial':
      return 0.5;
    case 'failure':
      return 0;
    case 'unknown':
      return undefined;
  }
}

function strongOutcome(trace: VerifiedExperienceTrace): boolean {
  return trace.verifier === 'tool' || trace.verifier === 'test' || trace.verifier === 'human';
}

export function verifyMemoryIntervention(
  traces: readonly VerifiedExperienceTrace[],
  input: MemoryInterventionInput,
): VerifiedMemoryIntervention {
  if (
    typeof input.id !== 'string' ||
    input.id.trim().length === 0 ||
    typeof input.memoryId !== 'string' ||
    input.memoryId.trim().length === 0 ||
    typeof input.actor !== 'string' ||
    input.actor.trim().length === 0 ||
    input.intervention !== 'removed' ||
    !Number.isFinite(input.recordedAt) ||
    input.recordedAt < 0
  ) {
    throw new Error('memory intervention identity, actor, kind, and time are invalid');
  }
  if (input.treatmentTraceId === input.controlTraceId) {
    throw new Error('memory intervention requires distinct treatment and control traces');
  }
  const treatment = traces.find((trace) => trace.id === input.treatmentTraceId);
  const control = traces.find((trace) => trace.id === input.controlTraceId);
  if (treatment === undefined || control === undefined) {
    throw new Error('memory intervention references an unknown trace');
  }
  if (treatment.traceDigest === control.traceDigest) {
    throw new Error('memory intervention traces are not independent records');
  }
  if (
    treatment.scope !== control.scope ||
    treatment.unitDigest !== control.unitDigest ||
    treatment.unit.taskFamily !== control.unit.taskFamily ||
    treatment.contextFingerprint !== control.contextFingerprint ||
    treatment.goalSignature !== control.goalSignature
  ) {
    throw new Error('treatment and control are not matched on scope/unit/context/goal');
  }
  if (
    treatment.captureMode !== 'runtime-instrumented' ||
    control.captureMode !== 'runtime-instrumented'
  ) {
    throw new Error('paired memory attribution requires runtime-instrumented traces');
  }
  if (!strongOutcome(treatment) || !strongOutcome(control)) {
    throw new Error('paired memory attribution requires strongly verified outcomes');
  }
  const treatmentScore = outcomeScore(treatment.outcome);
  const controlScore = outcomeScore(control.outcome);
  if (treatmentScore === undefined || controlScore === undefined) {
    throw new Error('paired memory attribution cannot use an unknown outcome');
  }
  const treatmentApplied = appliedMemoryIds(treatment);
  const controlApplied = appliedMemoryIds(control);
  const treatmentOnly = treatmentApplied.filter((memoryId) => !controlApplied.includes(memoryId));
  const controlOnly = controlApplied.filter((memoryId) => !treatmentApplied.includes(memoryId));
  if (
    treatmentOnly.length !== 1 ||
    treatmentOnly[0] !== input.memoryId ||
    controlOnly.length !== 0
  ) {
    throw new Error('paired intervention must differ only by the applied target memory');
  }
  const treatmentGroups = new Set(treatment.outcomeSourceGroups);
  if (control.outcomeSourceGroups.some((group) => treatmentGroups.has(group))) {
    throw new Error('paired outcomes must have independent verifier source groups');
  }
  if (input.recordedAt < Math.max(treatment.completedAt, control.completedAt)) {
    throw new Error('memory intervention cannot be recorded before both traces complete');
  }
  const sourceGroups = Object.freeze(
    [...new Set([...treatment.outcomeSourceGroups, ...control.outcomeSourceGroups])].sort(),
  );
  const unsigned = Object.freeze({
    schemaVersion: EXPERIENCE_SCHEMA_VERSION,
    id: input.id,
    memoryId: input.memoryId,
    treatmentTraceId: input.treatmentTraceId,
    controlTraceId: input.controlTraceId,
    intervention: input.intervention,
    actor: input.actor,
    recordedAt: input.recordedAt,
    unitDigest: treatment.unitDigest,
    contextFingerprint: treatment.contextFingerprint,
    treatmentOutcome: treatment.outcome,
    controlOutcome: control.outcome,
    effect: treatmentScore - controlScore,
    sourceGroups,
  });
  return canonicalClone({
    ...unsigned,
    comparisonDigest: digest({ domain: 'cl-memory-intervention-v1', comparison: unsigned }),
  });
}

function wilsonLowerBound(successes: number, trials: number, z = 1.96): number {
  if (trials <= 0) return 0;
  const proportion = successes / trials;
  const denominator = 1 + (z * z) / trials;
  const centre = proportion + (z * z) / (2 * trials);
  const margin =
    z * Math.sqrt((proportion * (1 - proportion) + (z * z) / (4 * trials)) / trials);
  return Math.max(0, (centre - margin) / denominator);
}

function validatePolicy(policy: MemoryUtilityPolicy): void {
  if (
    !Number.isInteger(policy.minIndependentPairs) ||
    policy.minIndependentPairs <= 0 ||
    !Number.isInteger(policy.minDistinctContexts) ||
    policy.minDistinctContexts <= 0
  ) {
    throw new Error('memory utility pair/context minimums must be positive integers');
  }
  for (const [label, value] of [
    ['minMeanAbsoluteEffect', policy.minMeanAbsoluteEffect],
    ['minDirectionalRate', policy.minDirectionalRate],
    ['minDirectionalWilsonLowerBound', policy.minDirectionalWilsonLowerBound],
    ['maxOppositeRate', policy.maxOppositeRate],
    ['neutralThreshold', policy.neutralThreshold],
  ] as const) {
    if (!Number.isFinite(value) || value < 0 || value > 1) {
      throw new Error(`memory utility ${label} must be in [0, 1]`);
    }
  }
}

export function assessMemoryUtility(
  memoryId: string,
  traces: readonly VerifiedExperienceTrace[],
  comparisons: readonly VerifiedMemoryIntervention[],
  policy: MemoryUtilityPolicy = DEFAULT_MEMORY_UTILITY_POLICY,
): MemoryUtilityAssessment {
  if (typeof memoryId !== 'string' || memoryId.trim().length === 0) {
    throw new Error('memory utility assessment requires a memoryId');
  }
  validatePolicy(policy);
  const candidates = comparisons
    .filter((comparison) => comparison.memoryId === memoryId)
    .sort(
      (left, right) =>
        left.recordedAt - right.recordedAt || left.id.localeCompare(right.id),
    );
  const accepted: VerifiedMemoryIntervention[] = [];
  const excluded: VerifiedMemoryIntervention[] = [];
  const units = new Set<string>();
  const sourceGroups = new Set<string>();
  for (const comparison of candidates) {
    const overlaps = comparison.sourceGroups.some((group) => sourceGroups.has(group));
    if (units.has(comparison.unitDigest) || overlaps) {
      excluded.push(comparison);
      continue;
    }
    units.add(comparison.unitDigest);
    for (const group of comparison.sourceGroups) sourceGroups.add(group);
    accepted.push(comparison);
  }
  const positive = accepted.filter((comparison) => comparison.effect > policy.neutralThreshold);
  const negative = accepted.filter((comparison) => comparison.effect < -policy.neutralThreshold);
  const neutral = accepted.length - positive.length - negative.length;
  const directional = positive.length + negative.length;
  const positiveRate = accepted.length === 0 ? 0 : positive.length / accepted.length;
  const negativeRate = accepted.length === 0 ? 0 : negative.length / accepted.length;
  const meanEffect =
    accepted.length === 0
      ? 0
      : accepted.reduce((sum, comparison) => sum + comparison.effect, 0) / accepted.length;
  const positiveWilson = wilsonLowerBound(positive.length, directional);
  const negativeWilson = wilsonLowerBound(negative.length, directional);
  const distinctContexts = new Set(accepted.map((comparison) => comparison.contextFingerprint)).size;
  const blockers: string[] = [];
  if (accepted.length < policy.minIndependentPairs) {
    blockers.push(`needs ${policy.minIndependentPairs - accepted.length} more independent paired interventions`);
  }
  if (distinctContexts < policy.minDistinctContexts) {
    blockers.push(`needs ${policy.minDistinctContexts - distinctContexts} more contexts`);
  }

  let status: MemoryUtilityAssessment['status'] = 'insufficient';
  if (accepted.length >= policy.minIndependentPairs && distinctContexts >= policy.minDistinctContexts) {
    const positiveSupported =
      meanEffect >= policy.minMeanAbsoluteEffect &&
      positiveRate >= policy.minDirectionalRate &&
      positiveWilson >= policy.minDirectionalWilsonLowerBound &&
      negativeRate <= policy.maxOppositeRate;
    const negativeSupported =
      meanEffect <= -policy.minMeanAbsoluteEffect &&
      negativeRate >= policy.minDirectionalRate &&
      negativeWilson >= policy.minDirectionalWilsonLowerBound &&
      positiveRate <= policy.maxOppositeRate;
    if (positiveSupported) status = 'supported-positive';
    else if (negativeSupported) status = 'supported-negative';
    else if (
      positiveRate > policy.maxOppositeRate &&
      negativeRate > policy.maxOppositeRate
    ) {
      status = 'mixed';
      blockers.push('effect direction changes across matched interventions');
    } else {
      status = 'neutral';
      blockers.push('paired evidence does not clear a directional utility threshold');
    }
  }

  const correlatedVerifiedSuccesses = traces.filter(
    (trace) =>
      trace.outcome === 'success' &&
      strongOutcome(trace) &&
      trace.exposures.some(
        (exposure) =>
          exposure.memoryId === memoryId &&
          exposure.stage === 'applied' &&
          exposure.creditEligible,
      ),
  ).length;

  return Object.freeze({
    memoryId,
    status,
    independentPairs: accepted.length,
    excludedCorrelatedPairs: excluded.length,
    distinctContexts,
    positivePairs: positive.length,
    negativePairs: negative.length,
    neutralPairs: neutral,
    meanEffect,
    positiveRate,
    negativeRate,
    positiveWilsonLowerBound: positiveWilson,
    negativeWilsonLowerBound: negativeWilson,
    correlatedVerifiedSuccesses,
    comparisonIds: Object.freeze(accepted.map((comparison) => comparison.id)),
    excludedComparisonIds: Object.freeze(excluded.map((comparison) => comparison.id)),
    blockers: Object.freeze(blockers),
  });
}
