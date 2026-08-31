import { createHash } from 'node:crypto';

import type { MemoryPacketKind } from '../context.js';
import {
  EVIDENCE_ROLES,
  evidenceRoles,
  isEvidenceRole,
  type Authority,
  type EvidenceRef,
  type EvidenceRole,
  type MemoryEvent,
} from '../domain.js';
import { EvidenceProjection } from '../evidence.js';
import { MemoryKernel } from '../kernel.js';
import { fingerprintMemoryEvents } from '../transitions/verifier.js';

export const EXPERIENCE_ATTRIBUTION_SCHEMA_VERSION = 1 as const;

const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const STAGE_ORDER = Object.freeze([
  'activated',
  'materialized',
  'consulted',
  'applied',
] as const);
const CAPTURE_MODES: ReadonlySet<string> = new Set([
  'runtime-instrumented',
  'host-reconstructed',
  'model-reported',
]);
const STRONG_OUTCOME_VERIFIERS: ReadonlySet<string> = new Set(['tool', 'test', 'human']);
const OUTCOME_VERIFIERS: ReadonlySet<string> = new Set([
  'none',
  'model',
  'tool',
  'test',
  'human',
]);
const MAX_IDENTIFIER_CHARACTERS = 512;
const MAX_REASON_CHARACTERS = 4_096;
const MAX_MEMORY_USES = 256;
const MAX_EVIDENCE_REFERENCES = 64;
const MAX_TRACE_INPUT_CHARACTERS = 1_000_000;
const MAX_ASSESSMENT_TRACES = 4_096;
const MAX_ASSESSMENT_INTERVENTIONS = 4_096;

const issuedExperienceTraces = new WeakSet<object>();
const issuedMemoryInterventions = new WeakSet<object>();
const issuedUtilityAssessments = new WeakSet<object>();

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
    for (const child of Object.values(value as unknown as Record<string, unknown>)) {
      deepFreeze(child);
    }
    Object.freeze(value);
  }
  return value;
}

function canonicalSnapshot<T>(value: T, label: string, maxCharacters = MAX_TRACE_INPUT_CHARACTERS): T {
  const encoded = stableJson(value);
  if (encoded.length > maxCharacters) {
    throw new RangeError(`${label} cannot exceed ${maxCharacters} canonical characters`);
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
  maxCharacters = MAX_IDENTIFIER_CHARACTERS,
): asserts value is string {
  if (
    typeof value !== 'string' ||
    value.trim().length === 0 ||
    value.length > maxCharacters ||
    value.includes('\u0000') ||
    !isWellFormedUnicode(value)
  ) {
    throw new Error(`${label} must be non-empty well-formed text within ${maxCharacters} characters`);
  }
}

function assertDigest(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || !SHA256_PATTERN.test(value)) {
    throw new Error(`${label} must be a SHA-256 content address`);
  }
}

function assertSafeTime(value: unknown, label: string): asserts value is number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
}

function normalizedStrings(values: readonly string[]): readonly string[] {
  return Object.freeze([...new Set(values)].sort());
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) return false;
  return left.every((value, index) => value === right[index]);
}

export type MemoryUseStage = (typeof STAGE_ORDER)[number];

export type MemoryUseCaptureMode =
  | 'runtime-instrumented'
  | 'host-reconstructed'
  | 'model-reported';

export type OutcomeVerifier = 'none' | 'model' | 'tool' | 'test' | 'human';

export interface ExperienceUnit {
  readonly taskFamily: string;
  readonly instanceDigest: string;
  readonly environmentDigest: string;
  readonly seed?: string;
}

export interface AttributionRuntimeIdentity {
  readonly modelDigest: string;
  readonly toolDigest: string;
  readonly harnessDigest: string;
  readonly verifierDigest: string;
}

export interface MemoryUseInput {
  readonly memoryId: string;
  readonly kind: MemoryPacketKind;
  /** Exact monotonic prefix: activated -> materialized -> consulted -> applied. */
  readonly stages: readonly MemoryUseStage[];
  readonly evidence: readonly EvidenceRef[];
  /** Required when the final stage is not `applied`; forbidden when it is applied. */
  readonly nonUseReason?: string;
}

export interface AttributionEvidenceReference {
  readonly sourceId: string;
  readonly sourceGroups: readonly string[];
  readonly authority: Authority;
  readonly contentHash: string;
  readonly roles: readonly EvidenceRole[];
}

export interface VerifiedMemoryUse {
  readonly memoryId: string;
  readonly kind: MemoryPacketKind;
  readonly stages: readonly MemoryUseStage[];
  readonly terminalStage: MemoryUseStage;
  readonly evidence: readonly AttributionEvidenceReference[];
  readonly sourceGroups: readonly string[];
  readonly nonUseReason?: string;
  /** True only for runtime-instrumented use that reached `applied`. */
  readonly causalCreditEligible: boolean;
  readonly useDigest: string;
}

export interface ExperienceTraceInput {
  readonly id: string;
  readonly scope: string;
  readonly runId: string;
  readonly taskId: string;
  readonly contextFingerprint: string;
  readonly goalSignature: string;
  readonly unit: ExperienceUnit;
  readonly runtime: AttributionRuntimeIdentity;
  readonly startedAt: number;
  readonly completedAt: number;
  readonly captureMode: MemoryUseCaptureMode;
  readonly recorder: string;
  readonly canonicalFingerprint: string;
  readonly outcomeEventId: string;
  readonly memoryUses: readonly MemoryUseInput[];
}

export interface VerifiedExperienceTrace {
  readonly schemaVersion: typeof EXPERIENCE_ATTRIBUTION_SCHEMA_VERSION;
  readonly id: string;
  readonly scope: string;
  readonly runId: string;
  readonly taskId: string;
  readonly contextFingerprint: string;
  readonly goalSignature: string;
  readonly goalDigest: string;
  readonly unit: ExperienceUnit;
  readonly unitDigest: string;
  readonly runtime: AttributionRuntimeIdentity;
  readonly runtimeDigest: string;
  readonly startedAt: number;
  readonly completedAt: number;
  readonly captureMode: MemoryUseCaptureMode;
  readonly recorder: string;
  readonly canonicalFingerprint: string;
  readonly outcomeEventId: string;
  readonly outcome: 'success' | 'failure' | 'partial' | 'unknown';
  readonly verifier: OutcomeVerifier;
  readonly outcomeEvidence: readonly AttributionEvidenceReference[];
  readonly outcomeSourceGroups: readonly string[];
  readonly memoryUses: readonly VerifiedMemoryUse[];
  readonly memoryUseSetDigest: string;
  readonly causalOutcomeEligible: boolean;
  readonly procedurePromotionAuthorized: false;
  readonly executionAuthorized: false;
  readonly traceDigest: string;
}

export interface MemoryInterventionInput {
  readonly id: string;
  readonly memoryId: string;
  readonly treatmentTraceId: string;
  readonly controlTraceId: string;
  readonly intervention: 'withheld';
  readonly actor: string;
  readonly recordedAt: number;
}

export interface VerifiedMemoryIntervention {
  readonly schemaVersion: typeof EXPERIENCE_ATTRIBUTION_SCHEMA_VERSION;
  readonly id: string;
  readonly scope: string;
  readonly memoryId: string;
  readonly treatmentTraceId: string;
  readonly controlTraceId: string;
  readonly intervention: 'withheld';
  readonly actor: string;
  readonly recordedAt: number;
  readonly taskId: string;
  readonly unitDigest: string;
  readonly contextFingerprint: string;
  readonly goalDigest: string;
  readonly runtimeDigest: string;
  readonly treatmentOutcome: VerifiedExperienceTrace['outcome'];
  readonly controlOutcome: VerifiedExperienceTrace['outcome'];
  readonly effect: number;
  readonly sourceGroups: readonly string[];
  readonly independenceDigest: string;
  readonly causalEvidence: true;
  readonly procedurePromotionAuthorized: false;
  readonly executionAuthorized: false;
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

export interface MemoryUtilityAssessmentRequest {
  readonly scope: string;
  readonly memoryId: string;
}

export type MemoryUtilityClassification =
  | 'supported-positive'
  | 'supported-negative'
  | 'mixed'
  | 'neutral'
  | 'insufficient';

export interface MemoryUtilityAssessment {
  readonly schemaVersion: typeof EXPERIENCE_ATTRIBUTION_SCHEMA_VERSION;
  readonly scope: string;
  readonly memoryId: string;
  readonly classification: MemoryUtilityClassification;
  readonly causalBasis: 'paired-intervention' | 'none';
  readonly independentPairs: number;
  readonly excludedCorrelatedPairs: number;
  readonly conflictingExperimentalUnits: number;
  readonly distinctContexts: number;
  readonly positivePairs: number;
  readonly negativePairs: number;
  readonly neutralPairs: number;
  readonly meanEffect: number;
  readonly positiveRate: number;
  readonly negativeRate: number;
  readonly positiveWilsonLowerBound: number;
  readonly negativeWilsonLowerBound: number;
  readonly correlatedAppliedSuccesses: number;
  readonly runtimeInstrumentedAppliedSuccesses: number;
  readonly comparisonIds: readonly string[];
  readonly excludedComparisonIds: readonly string[];
  readonly conflictingUnitDigests: readonly string[];
  readonly correlatedTraceIds: readonly string[];
  readonly blockers: readonly string[];
  readonly procedurePromotionAuthorized: false;
  readonly executionAuthorized: false;
  readonly assessmentDigest: string;
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
  if (typeof unit !== 'object' || unit === null) {
    throw new TypeError('experience unit must be an object');
  }
  assertText(unit.taskFamily, 'experience unit taskFamily');
  assertDigest(unit.instanceDigest, 'experience unit instanceDigest');
  assertDigest(unit.environmentDigest, 'experience unit environmentDigest');
  if (unit.seed !== undefined) assertText(unit.seed, 'experience unit seed');
  return canonicalSnapshot(unit, 'experience unit');
}

function validateRuntime(runtime: AttributionRuntimeIdentity): AttributionRuntimeIdentity {
  if (typeof runtime !== 'object' || runtime === null) {
    throw new TypeError('runtime identity must be an object');
  }
  assertDigest(runtime.modelDigest, 'runtime modelDigest');
  assertDigest(runtime.toolDigest, 'runtime toolDigest');
  assertDigest(runtime.harnessDigest, 'runtime harnessDigest');
  assertDigest(runtime.verifierDigest, 'runtime verifierDigest');
  return canonicalSnapshot(runtime, 'runtime identity');
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

function normalizeEvidenceReferences(
  references: readonly EvidenceRef[],
  projection: EvidenceProjection,
  scope: string,
  label: string,
): readonly AttributionEvidenceReference[] {
  if (!Array.isArray(references) || references.length === 0) {
    throw new Error(`${label} requires recoverable evidence`);
  }
  if (references.length > MAX_EVIDENCE_REFERENCES) {
    throw new RangeError(`${label} cannot exceed ${MAX_EVIDENCE_REFERENCES} references`);
  }
  const seen = new Set<string>();
  const normalized: AttributionEvidenceReference[] = [];
  for (const reference of references) {
    if (typeof reference !== 'object' || reference === null) {
      throw new Error(`${label} contains a malformed evidence reference`);
    }
    assertText(reference.sourceId, `${label} sourceId`);
    if (seen.has(reference.sourceId)) {
      throw new Error(`${label} cannot repeat evidence source ${reference.sourceId}`);
    }
    seen.add(reference.sourceId);
    if (!projection.validatesReference(reference)) {
      throw new Error(`${label} contains unavailable or forged evidence: ${reference.sourceId}`);
    }
    const projected = projection.get(reference.sourceId);
    if (projected === undefined) {
      throw new Error(`${label} references unknown evidence: ${reference.sourceId}`);
    }
    if (projected.record.scope !== 'global' && projected.record.scope !== scope) {
      throw new Error(`${label} crosses scope through evidence ${reference.sourceId}`);
    }
    const roles = evidenceRoles(reference);
    if (roles.length === 0 || roles.some((role) => !isEvidenceRole(role))) {
      throw new Error(`${label} contains an invalid evidence role`);
    }
    const orderedRoles = Object.freeze(
      EVIDENCE_ROLES.filter((role) => roles.includes(role)),
    );
    normalized.push(
      Object.freeze({
        sourceId: reference.sourceId,
        sourceGroups: normalizedStrings(reference.sourceGroups),
        authority: reference.authority,
        contentHash: reference.contentHash,
        roles: orderedRoles,
      }),
    );
  }
  return Object.freeze(
    normalized.sort((left, right) => left.sourceId.localeCompare(right.sourceId)),
  );
}

function validateStages(stages: readonly MemoryUseStage[], label: string): readonly MemoryUseStage[] {
  if (!Array.isArray(stages) || stages.length === 0 || stages.length > STAGE_ORDER.length) {
    throw new Error(`${label} requires a non-empty bounded stage sequence`);
  }
  const snapshot = Object.freeze([...stages]);
  for (let index = 0; index < snapshot.length; index += 1) {
    const stage = snapshot[index];
    if (stage !== STAGE_ORDER[index]) {
      throw new Error(`${label} stages must be the exact monotonic exposure prefix`);
    }
  }
  return snapshot;
}

function validateMemoryUse(
  use: MemoryUseInput,
  captureMode: MemoryUseCaptureMode,
  projection: EvidenceProjection,
  scope: string,
): VerifiedMemoryUse {
  if (typeof use !== 'object' || use === null) {
    throw new TypeError('memory use must be an object');
  }
  assertText(use.memoryId, 'memory use memoryId');
  const kinds: ReadonlySet<string> = new Set([
    'state',
    'episode',
    'procedure',
    'source',
    'constraint',
    'summary',
  ]);
  if (!kinds.has(use.kind)) throw new Error(`memory use ${use.memoryId} has an invalid kind`);
  const stages = validateStages(use.stages, `memory use ${use.memoryId}`);
  const terminalStage = stages.at(-1);
  if (terminalStage === undefined) throw new Error('memory use stage invariant failed');
  if (terminalStage === 'applied') {
    if (use.nonUseReason !== undefined) {
      throw new Error(`applied memory ${use.memoryId} cannot carry a nonUseReason`);
    }
  } else {
    assertText(use.nonUseReason, `memory use ${use.memoryId} nonUseReason`, MAX_REASON_CHARACTERS);
  }
  const evidence = normalizeEvidenceReferences(
    use.evidence,
    projection,
    scope,
    `memory use ${use.memoryId}`,
  );
  const sourceGroups = normalizedStrings(evidence.flatMap((reference) => reference.sourceGroups));
  const unsigned = {
    memoryId: use.memoryId,
    kind: use.kind,
    stages,
    terminalStage,
    evidence,
    sourceGroups,
    ...(use.nonUseReason === undefined ? {} : { nonUseReason: use.nonUseReason }),
    causalCreditEligible:
      captureMode === 'runtime-instrumented' && terminalStage === 'applied',
  } as const;
  return canonicalSnapshot(
    {
      ...unsigned,
      useDigest: digest({ domain: 'cl-memory-use-v1', use: unsigned }),
    },
    `memory use ${use.memoryId}`,
  );
}

function isStrongVerifier(verifier: OutcomeVerifier): boolean {
  return STRONG_OUTCOME_VERIFIERS.has(verifier);
}

function assertIssuedTrace(trace: VerifiedExperienceTrace): void {
  if (
    typeof trace !== 'object' ||
    trace === null ||
    !issuedExperienceTraces.has(trace as object)
  ) {
    throw new Error('experience attribution requires an issued experience trace capability');
  }
}

function assertIssuedIntervention(intervention: VerifiedMemoryIntervention): void {
  if (
    typeof intervention !== 'object' ||
    intervention === null ||
    !issuedMemoryInterventions.has(intervention as object)
  ) {
    throw new Error('memory utility requires an issued paired intervention capability');
  }
}

export function recordExperienceTrace(
  memoryEvents: readonly MemoryEvent[],
  input: ExperienceTraceInput,
): VerifiedExperienceTrace {
  const request = canonicalSnapshot(input, 'experience trace input');
  const events = MemoryKernel.from(memoryEvents).events();
  const canonicalFingerprint = fingerprintMemoryEvents(events);
  assertDigest(request.canonicalFingerprint, 'experience trace canonicalFingerprint');
  if (request.canonicalFingerprint !== canonicalFingerprint) {
    throw new Error('experience trace canonical fingerprint is stale or forged');
  }

  assertText(request.id, 'experience trace id');
  assertText(request.scope, 'experience trace scope');
  assertText(request.runId, 'experience trace runId');
  assertText(request.taskId, 'experience trace taskId');
  assertText(request.contextFingerprint, 'experience trace contextFingerprint');
  assertText(request.goalSignature, 'experience trace goalSignature', MAX_REASON_CHARACTERS);
  assertText(request.recorder, 'experience trace recorder');
  assertText(request.outcomeEventId, 'experience trace outcomeEventId');
  if (!CAPTURE_MODES.has(request.captureMode)) {
    throw new Error('experience trace captureMode is invalid');
  }
  assertSafeTime(request.startedAt, 'experience trace startedAt');
  assertSafeTime(request.completedAt, 'experience trace completedAt');
  if (request.completedAt < request.startedAt) {
    throw new Error('experience trace cannot complete before it starts');
  }
  if (!Array.isArray(request.memoryUses) || request.memoryUses.length > MAX_MEMORY_USES) {
    throw new RangeError(`experience trace cannot exceed ${MAX_MEMORY_USES} memory uses`);
  }

  const unit = validateUnit(request.unit);
  const runtime = validateRuntime(request.runtime);
  const projection = EvidenceProjection.from(events);
  const seenMemoryIds = new Set<string>();
  const memoryUses: VerifiedMemoryUse[] = [];
  for (const use of request.memoryUses) {
    if (seenMemoryIds.has(use.memoryId)) {
      throw new Error(`experience trace repeats memory ${use.memoryId}`);
    }
    seenMemoryIds.add(use.memoryId);
    memoryUses.push(validateMemoryUse(use, request.captureMode, projection, request.scope));
  }
  memoryUses.sort((left, right) => left.memoryId.localeCompare(right.memoryId));

  const outcome = outcomeEvent(events, request.outcomeEventId);
  if (
    outcome.data.scope !== request.scope ||
    outcome.data.taskId !== request.taskId ||
    outcome.data.contextFingerprint !== request.contextFingerprint
  ) {
    throw new Error('experience trace does not match its canonical outcome scope/task/context');
  }
  if (!OUTCOME_VERIFIERS.has(outcome.data.verifier)) {
    throw new Error('experience trace canonical outcome verifier is invalid');
  }
  if (request.completedAt > outcome.recordedAt) {
    throw new Error('experience trace cannot complete after its canonical outcome was recorded');
  }
  const outcomeEvidence = normalizeEvidenceReferences(
    outcome.data.evidence,
    projection,
    request.scope,
    'experience trace outcome',
  );
  const outcomeSourceGroups = normalizedStrings(
    outcomeEvidence.flatMap((reference) => reference.sourceGroups),
  );
  if (!sameStrings(outcomeSourceGroups, normalizedStrings(outcome.data.sourceGroups))) {
    throw new Error('experience trace outcome source groups diverge from evidence lineage');
  }

  const verifier = outcome.data.verifier as OutcomeVerifier;
  const unsigned = {
    schemaVersion: EXPERIENCE_ATTRIBUTION_SCHEMA_VERSION,
    id: request.id,
    scope: request.scope,
    runId: request.runId,
    taskId: request.taskId,
    contextFingerprint: request.contextFingerprint,
    goalSignature: request.goalSignature,
    goalDigest: digest({ domain: 'cl-experience-goal-v1', goal: request.goalSignature }),
    unit,
    unitDigest: digest({ domain: 'cl-experience-unit-v1', unit }),
    runtime,
    runtimeDigest: digest({ domain: 'cl-experience-runtime-v1', runtime }),
    startedAt: request.startedAt,
    completedAt: request.completedAt,
    captureMode: request.captureMode,
    recorder: request.recorder,
    canonicalFingerprint: request.canonicalFingerprint,
    outcomeEventId: request.outcomeEventId,
    outcome: outcome.data.outcome,
    verifier,
    outcomeEvidence,
    outcomeSourceGroups,
    memoryUses: Object.freeze(memoryUses),
    memoryUseSetDigest: digest({
      domain: 'cl-memory-use-set-v1',
      uses: memoryUses.map((use) => use.useDigest),
    }),
    causalOutcomeEligible:
      request.captureMode === 'runtime-instrumented' &&
      isStrongVerifier(verifier) &&
      outcome.data.outcome !== 'unknown',
    procedurePromotionAuthorized: false,
    executionAuthorized: false,
  } as const;
  const trace = canonicalSnapshot(
    {
      ...unsigned,
      traceDigest: digest({ domain: 'cl-experience-trace-v1', trace: unsigned }),
    },
    'verified experience trace',
  );
  issuedExperienceTraces.add(trace as object);
  return trace;
}

function memoryUse(trace: VerifiedExperienceTrace, memoryId: string): VerifiedMemoryUse | undefined {
  return trace.memoryUses.find((use) => use.memoryId === memoryId);
}

function otherMemoryUseDigests(
  trace: VerifiedExperienceTrace,
  targetMemoryId: string,
): readonly string[] {
  return Object.freeze(
    trace.memoryUses
      .filter((use) => use.memoryId !== targetMemoryId)
      .map((use) => use.useDigest)
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

export function verifyMemoryIntervention(
  traces: readonly VerifiedExperienceTrace[],
  input: MemoryInterventionInput,
): VerifiedMemoryIntervention {
  if (!Array.isArray(traces) || traces.length === 0 || traces.length > MAX_ASSESSMENT_TRACES) {
    throw new RangeError('paired intervention requires a bounded non-empty trace set');
  }
  for (const trace of traces) assertIssuedTrace(trace);
  const request = canonicalSnapshot(input, 'memory intervention input');
  assertText(request.id, 'memory intervention id');
  assertText(request.memoryId, 'memory intervention memoryId');
  assertText(request.treatmentTraceId, 'memory intervention treatmentTraceId');
  assertText(request.controlTraceId, 'memory intervention controlTraceId');
  assertText(request.actor, 'memory intervention actor');
  assertSafeTime(request.recordedAt, 'memory intervention recordedAt');
  if (request.intervention !== 'withheld') {
    throw new Error('memory intervention must explicitly withhold the target from control');
  }
  if (request.treatmentTraceId === request.controlTraceId) {
    throw new Error('memory intervention requires distinct treatment and control traces');
  }

  const byId = new Map<string, VerifiedExperienceTrace>();
  for (const trace of traces) {
    if (byId.has(trace.id)) throw new Error(`paired intervention repeats trace id ${trace.id}`);
    byId.set(trace.id, trace);
  }
  const treatment = byId.get(request.treatmentTraceId);
  const control = byId.get(request.controlTraceId);
  if (treatment === undefined || control === undefined) {
    throw new Error('memory intervention references an unknown trace');
  }
  if (treatment.traceDigest === control.traceDigest) {
    throw new Error('memory intervention treatment and control are the same trace');
  }
  if (treatment.runId === control.runId) {
    throw new Error('memory intervention treatment and control require distinct run ids');
  }
  if (
    treatment.scope !== control.scope ||
    treatment.taskId !== control.taskId ||
    treatment.unitDigest !== control.unitDigest ||
    treatment.contextFingerprint !== control.contextFingerprint ||
    treatment.goalDigest !== control.goalDigest ||
    treatment.runtimeDigest !== control.runtimeDigest ||
    treatment.canonicalFingerprint !== control.canonicalFingerprint ||
    treatment.verifier !== control.verifier
  ) {
    throw new Error(
      'treatment and control are not matched on scope/task/unit/context/goal/runtime/canonical/verifier identity',
    );
  }
  if (
    treatment.captureMode !== 'runtime-instrumented' ||
    control.captureMode !== 'runtime-instrumented' ||
    !treatment.causalOutcomeEligible ||
    !control.causalOutcomeEligible
  ) {
    throw new Error('paired memory attribution requires runtime-instrumented strongly verified traces');
  }
  if (treatment.outcomeEventId === control.outcomeEventId) {
    throw new Error('paired intervention cannot reuse one canonical outcome event for both arms');
  }
  if (stableJson(treatment.outcomeEvidence) === stableJson(control.outcomeEvidence)) {
    throw new Error('paired intervention cannot reuse one outcome evidence packet for both arms');
  }

  const treatmentTarget = memoryUse(treatment, request.memoryId);
  const controlTarget = memoryUse(control, request.memoryId);
  if (
    treatmentTarget === undefined ||
    treatmentTarget.terminalStage !== 'applied' ||
    !treatmentTarget.causalCreditEligible
  ) {
    throw new Error('treatment must contain an applied runtime-instrumented target memory');
  }
  if (controlTarget !== undefined) {
    throw new Error('control must omit the target memory entirely, not merely decline to apply it');
  }
  if (
    !sameStrings(
      otherMemoryUseDigests(treatment, request.memoryId),
      otherMemoryUseDigests(control, request.memoryId),
    )
  ) {
    throw new Error('paired intervention must differ only by the target memory');
  }

  const treatmentScore = outcomeScore(treatment.outcome);
  const controlScore = outcomeScore(control.outcome);
  if (treatmentScore === undefined || controlScore === undefined) {
    throw new Error('paired memory attribution cannot use an unknown outcome');
  }
  if (request.recordedAt < Math.max(treatment.completedAt, control.completedAt)) {
    throw new Error('memory intervention cannot be recorded before both traces complete');
  }

  const sourceGroups = normalizedStrings([
    ...treatment.outcomeSourceGroups,
    ...control.outcomeSourceGroups,
  ]);
  const unsigned = {
    schemaVersion: EXPERIENCE_ATTRIBUTION_SCHEMA_VERSION,
    id: request.id,
    scope: treatment.scope,
    memoryId: request.memoryId,
    treatmentTraceId: request.treatmentTraceId,
    controlTraceId: request.controlTraceId,
    intervention: request.intervention,
    actor: request.actor,
    recordedAt: request.recordedAt,
    taskId: treatment.taskId,
    unitDigest: treatment.unitDigest,
    contextFingerprint: treatment.contextFingerprint,
    goalDigest: treatment.goalDigest,
    runtimeDigest: treatment.runtimeDigest,
    treatmentOutcome: treatment.outcome,
    controlOutcome: control.outcome,
    effect: treatmentScore - controlScore,
    sourceGroups,
    independenceDigest: digest({
      domain: 'cl-memory-intervention-independence-v1',
      scope: treatment.scope,
      memoryId: request.memoryId,
      unitDigest: treatment.unitDigest,
      sourceGroups,
    }),
    causalEvidence: true,
    procedurePromotionAuthorized: false,
    executionAuthorized: false,
  } as const;
  const comparison = canonicalSnapshot(
    {
      ...unsigned,
      comparisonDigest: digest({
        domain: 'cl-memory-intervention-v1',
        comparison: unsigned,
      }),
    },
    'verified memory intervention',
  );
  issuedMemoryInterventions.add(comparison as object);
  return comparison;
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

function validatePolicy(input: MemoryUtilityPolicy): MemoryUtilityPolicy {
  const policy = canonicalSnapshot(input, 'memory utility policy', 100_000);
  if (
    !Number.isSafeInteger(policy.minIndependentPairs) ||
    policy.minIndependentPairs <= 0 ||
    !Number.isSafeInteger(policy.minDistinctContexts) ||
    policy.minDistinctContexts <= 0
  ) {
    throw new Error('memory utility pair/context minimums must be positive safe integers');
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
  return policy;
}

function effectDirection(effect: number, neutralThreshold: number): -1 | 0 | 1 {
  if (effect > neutralThreshold) return 1;
  if (effect < -neutralThreshold) return -1;
  return 0;
}

export function assessMemoryUtility(
  requestInput: MemoryUtilityAssessmentRequest,
  traces: readonly VerifiedExperienceTrace[],
  interventions: readonly VerifiedMemoryIntervention[],
  policyInput: MemoryUtilityPolicy = DEFAULT_MEMORY_UTILITY_POLICY,
): MemoryUtilityAssessment {
  const request = canonicalSnapshot(requestInput, 'memory utility request', 100_000);
  assertText(request.scope, 'memory utility scope');
  assertText(request.memoryId, 'memory utility memoryId');
  if (!Array.isArray(traces) || traces.length > MAX_ASSESSMENT_TRACES) {
    throw new RangeError(`memory utility cannot inspect more than ${MAX_ASSESSMENT_TRACES} traces`);
  }
  if (!Array.isArray(interventions) || interventions.length > MAX_ASSESSMENT_INTERVENTIONS) {
    throw new RangeError(
      `memory utility cannot inspect more than ${MAX_ASSESSMENT_INTERVENTIONS} interventions`,
    );
  }
  for (const trace of traces) assertIssuedTrace(trace);
  for (const intervention of interventions) assertIssuedIntervention(intervention);
  const policy = validatePolicy(policyInput);

  const traceIds = new Set<string>();
  for (const trace of traces) {
    if (traceIds.has(trace.id)) throw new Error(`memory utility repeats trace id ${trace.id}`);
    traceIds.add(trace.id);
  }
  const interventionIds = new Set<string>();
  for (const intervention of interventions) {
    if (interventionIds.has(intervention.id)) {
      throw new Error(`memory utility repeats intervention id ${intervention.id}`);
    }
    interventionIds.add(intervention.id);
  }

  const candidates = interventions
    .filter(
      (intervention) =>
        intervention.scope === request.scope && intervention.memoryId === request.memoryId,
    )
    .sort(
      (left, right) =>
        left.recordedAt - right.recordedAt || left.id.localeCompare(right.id),
    );

  const byUnit = new Map<string, VerifiedMemoryIntervention[]>();
  for (const candidate of candidates) {
    const group = byUnit.get(candidate.unitDigest) ?? [];
    group.push(candidate);
    byUnit.set(candidate.unitDigest, group);
  }

  const unitDeduplicated: VerifiedMemoryIntervention[] = [];
  const excluded: VerifiedMemoryIntervention[] = [];
  const conflictingUnitDigests: string[] = [];
  for (const [unitDigest, group] of [...byUnit].sort(([left], [right]) => left.localeCompare(right))) {
    const directions = new Set(
      group.map((comparison) => effectDirection(comparison.effect, policy.neutralThreshold)),
    );
    if (directions.has(1) && directions.has(-1)) {
      conflictingUnitDigests.push(unitDigest);
      excluded.push(...group);
      continue;
    }
    const [accepted, ...duplicates] = group;
    if (accepted !== undefined) unitDeduplicated.push(accepted);
    excluded.push(...duplicates);
  }

  const accepted: VerifiedMemoryIntervention[] = [];
  const usedSourceGroups = new Set<string>();
  for (const comparison of unitDeduplicated.sort(
    (left, right) => left.recordedAt - right.recordedAt || left.id.localeCompare(right.id),
  )) {
    if (comparison.sourceGroups.some((group) => usedSourceGroups.has(group))) {
      excluded.push(comparison);
      continue;
    }
    for (const group of comparison.sourceGroups) usedSourceGroups.add(group);
    accepted.push(comparison);
  }

  const positive = accepted.filter(
    (comparison) => comparison.effect > policy.neutralThreshold,
  );
  const negative = accepted.filter(
    (comparison) => comparison.effect < -policy.neutralThreshold,
  );
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
    blockers.push(
      `needs ${policy.minIndependentPairs - accepted.length} more independent paired interventions`,
    );
  }
  if (distinctContexts < policy.minDistinctContexts) {
    blockers.push(`needs ${policy.minDistinctContexts - distinctContexts} more contexts`);
  }
  if (conflictingUnitDigests.length > 0) {
    blockers.push('the same experimental unit produced opposite effect directions');
  }

  let classification: MemoryUtilityClassification = 'insufficient';
  if (conflictingUnitDigests.length > 0) {
    classification = 'mixed';
  } else if (
    accepted.length >= policy.minIndependentPairs &&
    distinctContexts >= policy.minDistinctContexts
  ) {
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
    if (positiveSupported) classification = 'supported-positive';
    else if (negativeSupported) classification = 'supported-negative';
    else if (positive.length > 0 && negative.length > 0) {
      classification = 'mixed';
      blockers.push('effect direction changes across independent matched interventions');
    } else {
      classification = 'neutral';
      blockers.push('paired evidence does not clear a directional utility threshold');
    }
  }

  const correlated = traces
    .filter((trace) => {
      if (trace.scope !== request.scope || trace.outcome !== 'success' || !isStrongVerifier(trace.verifier)) {
        return false;
      }
      const use = memoryUse(trace, request.memoryId);
      return use?.terminalStage === 'applied';
    })
    .sort((left, right) => left.completedAt - right.completedAt || left.id.localeCompare(right.id));
  const runtimeInstrumentedAppliedSuccesses = correlated.filter(
    (trace) => trace.captureMode === 'runtime-instrumented',
  ).length;

  const unsigned = {
    schemaVersion: EXPERIENCE_ATTRIBUTION_SCHEMA_VERSION,
    scope: request.scope,
    memoryId: request.memoryId,
    classification,
    causalBasis: accepted.length > 0 ? ('paired-intervention' as const) : ('none' as const),
    independentPairs: accepted.length,
    excludedCorrelatedPairs: excluded.length,
    conflictingExperimentalUnits: conflictingUnitDigests.length,
    distinctContexts,
    positivePairs: positive.length,
    negativePairs: negative.length,
    neutralPairs: neutral,
    meanEffect,
    positiveRate,
    negativeRate,
    positiveWilsonLowerBound: positiveWilson,
    negativeWilsonLowerBound: negativeWilson,
    correlatedAppliedSuccesses: correlated.length,
    runtimeInstrumentedAppliedSuccesses,
    comparisonIds: Object.freeze(accepted.map((comparison) => comparison.id)),
    excludedComparisonIds: Object.freeze(
      [...new Set(excluded.map((comparison) => comparison.id))].sort(),
    ),
    conflictingUnitDigests: Object.freeze([...conflictingUnitDigests].sort()),
    correlatedTraceIds: Object.freeze(correlated.map((trace) => trace.id)),
    blockers: Object.freeze(blockers),
    procedurePromotionAuthorized: false,
    executionAuthorized: false,
  } as const;
  const assessment = canonicalSnapshot(
    {
      ...unsigned,
      assessmentDigest: digest({ domain: 'cl-memory-utility-assessment-v1', assessment: unsigned }),
    },
    'memory utility assessment',
  );
  issuedUtilityAssessments.add(assessment as object);
  return assessment;
}

export function isIssuedMemoryUtilityAssessment(
  assessment: MemoryUtilityAssessment,
): boolean {
  return (
    typeof assessment === 'object' &&
    assessment !== null &&
    issuedUtilityAssessments.has(assessment as object)
  );
}
