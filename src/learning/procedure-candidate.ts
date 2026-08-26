import { createHash } from 'node:crypto';

import type { Authority, EvidenceSensitivity, EvidenceTaint, MemoryEvent } from '../domain.js';
import { EvidenceProjection } from '../evidence.js';
import { MemoryKernel } from '../kernel.js';
import { fingerprintMemoryEvents } from '../transitions/verifier.js';
import {
  assertIssuedApplicabilityHypothesis,
  type ApplicabilityRule,
  type VerifiedApplicabilityHypothesis,
} from './applicability.js';
import {
  assertIssuedMemoryUtilityAssessment,
  type MemoryUtilityAssessment,
} from './experience.js';

const PROCEDURE_CANDIDATE_SCHEMA_VERSION = 1 as const;
const VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9][a-z0-9.-]{0,63})?$/;
const MAX_STEPS = 64;
const MAX_STEP_CHARACTERS = 2_000;
const MAX_DEPENDENCIES = 64;
const RISK_LEVELS = new Set(['low', 'medium', 'high', 'destructive']);
const VERIFIERS = new Set(['tool', 'test', 'human']);
const FAILURE_ACTIONS = new Set(['disable', 'quarantine', 'human-review']);
const SENSITIVITY_RANK: Readonly<Record<EvidenceSensitivity, number>> = Object.freeze({
  public: 0,
  internal: 1,
  personal: 2,
  sensitive: 3,
  secret: 4,
});

const ISSUED_PROCEDURE_CANDIDATES = new WeakSet<object>();

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

function assertIdentifier(value: string, label: string, maximum = 256): void {
  if (typeof value !== 'string' || value.trim().length === 0 || value.length > maximum) {
    throw new Error(`${label} must be a non-empty string up to ${maximum} characters`);
  }
}

function canonicalStrings(
  values: readonly string[],
  label: string,
  maximum = MAX_DEPENDENCIES,
): readonly string[] {
  if (!Array.isArray(values) || values.length > maximum) {
    throw new Error(`${label} cannot exceed ${maximum} values`);
  }
  for (const value of values) assertIdentifier(value, label);
  if (new Set(values).size !== values.length) throw new Error(`${label} cannot contain duplicates`);
  return Object.freeze([...values].sort());
}

export type ProcedureCandidateRisk = 'low' | 'medium' | 'high' | 'destructive';

export interface ProcedureCandidateStepInput {
  readonly id: string;
  readonly instruction: string;
  readonly evidenceSourceIds: readonly string[];
}

export interface ProcedureCandidateStep {
  readonly id: string;
  readonly instruction: string;
  readonly evidenceSourceIds: readonly string[];
}

export interface ProcedureVerificationContract {
  readonly requiredVerifier: 'tool' | 'test' | 'human';
  readonly timeoutMs: number;
  readonly maxAttempts: number;
  readonly onFailure: 'disable' | 'quarantine' | 'human-review';
  readonly successPredicate: string;
}

export type ProcedureRollbackTarget =
  | { readonly kind: 'disable' }
  | {
      readonly kind: 'procedure-version';
      readonly procedureId: string;
      readonly version: string;
    };

export interface ProcedureCandidateInput {
  readonly id: string;
  readonly procedureId: string;
  readonly version: string;
  readonly memoryId: string;
  readonly scope: string;
  readonly name: string;
  readonly goalSignature: string;
  readonly rationale: string;
  readonly steps: readonly ProcedureCandidateStepInput[];
  readonly toolDependencies?: readonly string[];
  readonly risk: ProcedureCandidateRisk;
  readonly verification: ProcedureVerificationContract;
  readonly rollback: ProcedureRollbackTarget;
  readonly canonicalFingerprint: string;
  readonly actor: string;
  readonly recordedAt: number;
}

export interface VerifiedProcedureCandidate {
  readonly schemaVersion: typeof PROCEDURE_CANDIDATE_SCHEMA_VERSION;
  readonly id: string;
  readonly procedureId: string;
  readonly version: string;
  readonly memoryId: string;
  readonly scope: string;
  readonly name: string;
  readonly goalSignature: string;
  readonly rationale: string;
  readonly steps: readonly ProcedureCandidateStep[];
  readonly toolDependencies: readonly string[];
  readonly risk: ProcedureCandidateRisk;
  readonly verification: ProcedureVerificationContract;
  readonly rollback: ProcedureRollbackTarget;
  readonly applicabilityRule: ApplicabilityRule;
  readonly utilityAssessmentDigest: string;
  readonly applicabilityValidationDigest: string;
  readonly canonicalFingerprint: string;
  readonly sourceEvidenceIds: readonly string[];
  readonly sourceGroups: readonly string[];
  readonly sourceAuthorities: readonly Authority[];
  readonly taints: readonly EvidenceTaint[];
  readonly maximumSensitivity: EvidenceSensitivity;
  readonly actor: string;
  readonly recordedAt: number;
  readonly status: 'candidate';
  readonly executable: false;
  readonly canaryEligible: boolean;
  readonly blockers: readonly string[];
  readonly candidateDigest: string;
}

function validateVerification(contract: ProcedureVerificationContract): ProcedureVerificationContract {
  if (
    typeof contract !== 'object' ||
    contract === null ||
    !VERIFIERS.has(contract.requiredVerifier) ||
    !Number.isInteger(contract.timeoutMs) ||
    contract.timeoutMs <= 0 ||
    contract.timeoutMs > 3_600_000 ||
    !Number.isInteger(contract.maxAttempts) ||
    contract.maxAttempts <= 0 ||
    contract.maxAttempts > 10 ||
    !FAILURE_ACTIONS.has(contract.onFailure)
  ) {
    throw new Error('procedure verification contract is invalid');
  }
  assertIdentifier(contract.successPredicate, 'procedure successPredicate', 512);
  return canonicalClone(contract);
}

function validateRollback(
  rollback: ProcedureRollbackTarget,
  procedureId: string,
  version: string,
): ProcedureRollbackTarget {
  if (typeof rollback !== 'object' || rollback === null) {
    throw new Error('procedure rollback target is invalid');
  }
  if (rollback.kind === 'disable') return Object.freeze({ kind: 'disable' });
  if (rollback.kind !== 'procedure-version') throw new Error('procedure rollback kind is invalid');
  assertIdentifier(rollback.procedureId, 'rollback procedure id');
  if (!VERSION_PATTERN.test(rollback.version)) throw new Error('rollback procedure version is invalid');
  if (rollback.procedureId === procedureId && rollback.version === version) {
    throw new Error('procedure cannot roll back to its own candidate version');
  }
  return canonicalClone(rollback);
}

function strongestSensitivity(values: readonly EvidenceSensitivity[]): EvidenceSensitivity {
  let result: EvidenceSensitivity = 'public';
  for (const value of values) {
    if (SENSITIVITY_RANK[value] > SENSITIVITY_RANK[result]) result = value;
  }
  return result;
}

export function createProcedureCandidate(
  memoryEvents: readonly MemoryEvent[],
  utility: MemoryUtilityAssessment,
  applicability: VerifiedApplicabilityHypothesis,
  input: ProcedureCandidateInput,
): VerifiedProcedureCandidate {
  assertIssuedMemoryUtilityAssessment(utility);
  assertIssuedApplicabilityHypothesis(applicability);
  if (utility.memoryId !== input.memoryId || applicability.memoryId !== input.memoryId) {
    throw new Error('procedure candidate memory id differs from its learning evidence');
  }
  if (utility.status !== 'supported-positive') {
    throw new Error('procedure candidate requires supported-positive utility');
  }
  if (applicability.status !== 'validated') {
    throw new Error('procedure candidate requires a validated applicability hypothesis');
  }

  assertIdentifier(input.id, 'procedure candidate id');
  assertIdentifier(input.procedureId, 'procedure id');
  if (!VERSION_PATTERN.test(input.version)) throw new Error('procedure candidate version is invalid');
  assertIdentifier(input.memoryId, 'procedure memory id');
  assertIdentifier(input.scope, 'procedure scope');
  assertIdentifier(input.name, 'procedure name');
  assertIdentifier(input.goalSignature, 'procedure goalSignature', 512);
  assertIdentifier(input.rationale, 'procedure rationale', 4_096);
  assertIdentifier(input.actor, 'procedure candidate actor');
  if (!RISK_LEVELS.has(input.risk)) throw new Error('procedure candidate risk is invalid');
  if (!Number.isFinite(input.recordedAt) || input.recordedAt < applicability.recordedAt) {
    throw new Error('procedure candidate recordedAt is invalid');
  }
  const events = MemoryKernel.from(memoryEvents).events();
  const canonicalFingerprint = fingerprintMemoryEvents(events);
  if (input.canonicalFingerprint !== canonicalFingerprint) {
    throw new Error('procedure candidate canonical fingerprint is stale or forged');
  }
  if (!Array.isArray(input.steps) || input.steps.length === 0 || input.steps.length > MAX_STEPS) {
    throw new Error(`procedure candidate requires 1..${MAX_STEPS} steps`);
  }

  const evidence = EvidenceProjection.from(events);
  const stepIds = new Set<string>();
  const allEvidenceIds = new Set<string>();
  const evidenceRecords = new Map<string, ReturnType<EvidenceProjection['get']>>();
  const steps: ProcedureCandidateStep[] = [];
  for (const step of input.steps) {
    assertIdentifier(step.id, 'procedure step id');
    if (stepIds.has(step.id)) throw new Error(`duplicate procedure step id: ${step.id}`);
    stepIds.add(step.id);
    assertIdentifier(step.instruction, 'procedure step instruction', MAX_STEP_CHARACTERS);
    const sourceIds = canonicalStrings(step.evidenceSourceIds, `procedure step ${step.id} evidence`, 64);
    if (sourceIds.length === 0) throw new Error(`procedure step ${step.id} requires evidence`);
    for (const sourceId of sourceIds) {
      const projected = evidence.get(sourceId);
      if (projected === undefined || projected.availability !== 'available') {
        throw new Error(`procedure step evidence is unavailable: ${sourceId}`);
      }
      if (projected.record.scope !== 'global' && projected.record.scope !== input.scope) {
        throw new Error(`procedure step evidence scope is unauthorized: ${sourceId}`);
      }
      allEvidenceIds.add(sourceId);
      evidenceRecords.set(sourceId, projected);
    }
    steps.push(
      Object.freeze({
        id: step.id,
        instruction: step.instruction,
        evidenceSourceIds: sourceIds,
      }),
    );
  }

  const sourceEvidenceIds = Object.freeze([...allEvidenceIds].sort());
  const records = sourceEvidenceIds.map((sourceId) => {
    const projected = evidenceRecords.get(sourceId);
    if (projected === undefined) throw new Error(`procedure evidence projection disappeared: ${sourceId}`);
    return projected.record;
  });
  const sourceGroups = Object.freeze([...new Set(records.flatMap((record) => record.sourceGroups))].sort());
  const sourceAuthorities = Object.freeze([...new Set(records.map((record) => record.authority))].sort());
  const taints = Object.freeze([...new Set(records.flatMap((record) => record.taints))].sort()) as readonly EvidenceTaint[];
  const maximumSensitivity = strongestSensitivity(records.map((record) => record.sensitivity));
  const verification = validateVerification(input.verification);
  const rollback = validateRollback(input.rollback, input.procedureId, input.version);
  const toolDependencies = canonicalStrings(input.toolDependencies ?? [], 'procedure toolDependencies');

  const blockers: string[] = [];
  if (sourceGroups.length < 2) {
    blockers.push('procedure steps require evidence from at least two independent source groups before canary');
  }
  if (
    taints.includes('prompt-like') ||
    taints.includes('untrusted-source') ||
    taints.includes('secret-detected')
  ) {
    blockers.push('procedure evidence carries taint that requires an independent security review');
  }
  if (SENSITIVITY_RANK[maximumSensitivity] >= SENSITIVITY_RANK.personal) {
    blockers.push('procedure evidence is personal or more sensitive and cannot enter the default canary path');
  }
  if (sourceAuthorities.every((authority) => authority === 'model-inference')) {
    blockers.push('procedure steps are supported only by model-inference evidence');
  }
  if (input.risk === 'high' || input.risk === 'destructive') {
    if (!sourceAuthorities.includes('human-explicit')) {
      blockers.push(`${input.risk} procedure candidate requires human-explicit source evidence`);
    }
    if (verification.requiredVerifier !== 'human') {
      blockers.push(`${input.risk} procedure candidate requires a human verification contract`);
    }
    if (verification.onFailure !== 'human-review') {
      blockers.push(`${input.risk} procedure candidate failure must route to human review`);
    }
  }
  if (input.risk === 'destructive') {
    blockers.push('destructive procedure candidates are not canary-eligible in v1');
  }

  const unsigned = Object.freeze({
    schemaVersion: PROCEDURE_CANDIDATE_SCHEMA_VERSION,
    id: input.id,
    procedureId: input.procedureId,
    version: input.version,
    memoryId: input.memoryId,
    scope: input.scope,
    name: input.name,
    goalSignature: input.goalSignature,
    rationale: input.rationale,
    steps: Object.freeze(steps),
    toolDependencies,
    risk: input.risk,
    verification,
    rollback,
    applicabilityRule: applicability.rule,
    utilityAssessmentDigest: utility.assessmentDigest,
    applicabilityValidationDigest: applicability.validationDigest,
    canonicalFingerprint,
    sourceEvidenceIds,
    sourceGroups,
    sourceAuthorities,
    taints,
    maximumSensitivity,
    actor: input.actor,
    recordedAt: input.recordedAt,
    status: 'candidate' as const,
    executable: false as const,
    canaryEligible: blockers.length === 0,
    blockers: Object.freeze(blockers),
  });
  const result = canonicalClone({
    ...unsigned,
    candidateDigest: digest({ domain: 'cl-procedure-candidate-v1', candidate: unsigned }),
  });
  ISSUED_PROCEDURE_CANDIDATES.add(result as object);
  return result;
}

export function assertIssuedProcedureCandidate(
  value: unknown,
): asserts value is VerifiedProcedureCandidate {
  if (typeof value !== 'object' || value === null || !ISSUED_PROCEDURE_CANDIDATES.has(value)) {
    throw new Error('operation requires an issued procedure candidate');
  }
}
