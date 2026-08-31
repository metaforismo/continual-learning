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
  isIssuedVerifiedApplicabilityHypothesis,
  type ApplicabilityMetrics,
  type ApplicabilityRule,
  type VerifiedApplicabilityHypothesis,
} from './applicability-hypotheses-api.js';

export const VERIFIED_PROCEDURE_CANDIDATE_SCHEMA_VERSION = 1 as const;

const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9][a-z0-9.-]{0,63})?$/;
const STEP_KINDS = new Set(['inspect', 'decide', 'mutate', 'verify', 'communicate']);
const DEPENDENCY_KINDS = new Set(['tool', 'service', 'procedure', 'policy']);
const RISKS = new Set(['low', 'medium', 'high', 'destructive']);
const VERIFIERS = new Set(['tool', 'test', 'human']);
const FAILURE_ACTIONS = new Set(['disable-candidate', 'quarantine', 'human-review']);
const ROLLBACK_STRATEGIES = new Set(['disable-candidate', 'restore-checkpoint', 'manual']);
const MAX_INPUT_CHARACTERS = 1_000_000;
const MAX_IDENTIFIER_CHARACTERS = 512;
const MAX_TEXT_CHARACTERS = 4_096;
const MAX_VERSION_CHARACTERS = 128;
const MAX_STEPS = 32;
const MAX_DEPENDENCIES = 64;
const MAX_CONTRAINDICATIONS = 32;
const MAX_EVIDENCE_PER_BINDING = 32;
const MAX_TOTAL_EVIDENCE_REFERENCES = 512;
const MAX_CRITERIA = 32;

const SENSITIVITY_RANK: Readonly<Record<EvidenceSensitivity, number>> = Object.freeze({
  public: 0,
  internal: 1,
  personal: 2,
  sensitive: 3,
  secret: 4,
});

const issuedCandidates = new WeakSet<object>();

export type ProcedureStepKind = 'inspect' | 'decide' | 'mutate' | 'verify' | 'communicate';
export type ProcedureDependencyKind = 'tool' | 'service' | 'procedure' | 'policy';
export type ProcedureCandidateRisk = 'low' | 'medium' | 'high' | 'destructive';
export type ProcedureVerifier = 'tool' | 'test' | 'human';
export type ProcedureFailureAction = 'disable-candidate' | 'quarantine' | 'human-review';
export type ProcedureRollbackStrategy = 'disable-candidate' | 'restore-checkpoint' | 'manual';

export interface ProcedureEvidenceBinding {
  readonly sourceId: string;
  readonly sourceGroups: readonly string[];
  readonly authority: Authority;
  readonly contentHash: string;
  readonly roles: readonly EvidenceRole[];
  readonly sensitivity: EvidenceSensitivity;
  readonly taints: readonly EvidenceTaint[];
}

export interface ProcedureStepInput {
  readonly id: string;
  readonly kind: ProcedureStepKind;
  readonly instruction: string;
  readonly expectedOutcome: string;
  readonly dependsOn?: readonly string[];
  readonly evidence: readonly EvidenceRef[];
}

export interface VerifiedProcedureStep {
  readonly id: string;
  readonly kind: ProcedureStepKind;
  readonly instruction: string;
  readonly expectedOutcome: string;
  readonly dependsOn: readonly string[];
  readonly evidence: readonly ProcedureEvidenceBinding[];
  readonly exclusiveEvidenceSourceIds: readonly string[];
  readonly stepDigest: string;
}

export interface ProcedureDependencyInput {
  readonly id: string;
  readonly kind: ProcedureDependencyKind;
  readonly versionDigest: string;
  readonly evidence: readonly EvidenceRef[];
}

export interface VerifiedProcedureDependency {
  readonly id: string;
  readonly kind: ProcedureDependencyKind;
  readonly versionDigest: string;
  readonly evidence: readonly ProcedureEvidenceBinding[];
  readonly dependencyDigest: string;
}

export interface ProcedureContraindicationInput {
  readonly id: string;
  readonly condition: string;
  readonly evidence: readonly EvidenceRef[];
}

export interface VerifiedProcedureContraindication {
  readonly id: string;
  readonly condition: string;
  readonly evidence: readonly ProcedureEvidenceBinding[];
  readonly contraindicationDigest: string;
}

export interface ProcedureVerificationContractInput {
  readonly verificationStepId: string;
  readonly verifier: ProcedureVerifier;
  readonly verifierDigest: string;
  readonly evidence: readonly EvidenceRef[];
  readonly successCriteria: readonly string[];
  readonly failureCriteria: readonly string[];
  readonly timeoutMs: number;
  readonly maxAttempts: number;
  readonly onFailure: ProcedureFailureAction;
}

export interface ProcedureVerificationContract {
  readonly verificationStepId: string;
  readonly verifier: ProcedureVerifier;
  readonly verifierDigest: string;
  readonly evidence: readonly ProcedureEvidenceBinding[];
  readonly successCriteria: readonly string[];
  readonly failureCriteria: readonly string[];
  readonly timeoutMs: number;
  readonly maxAttempts: number;
  readonly onFailure: ProcedureFailureAction;
  readonly contractDigest: string;
}

export interface ProcedureRollbackContractInput {
  readonly strategy: ProcedureRollbackStrategy;
  readonly instructions: string;
  readonly evidence: readonly EvidenceRef[];
  readonly checkpointDigest?: string;
}

export interface ProcedureRollbackContract {
  readonly strategy: ProcedureRollbackStrategy;
  readonly instructions: string;
  readonly evidence: readonly ProcedureEvidenceBinding[];
  readonly checkpointDigest?: string;
  readonly contractDigest: string;
}

export interface VerifiedApplicabilityBinding {
  readonly validationId: string;
  readonly validationDigest: string;
  readonly discoveryCandidateId: string;
  readonly discoveryCandidateDigest: string;
  readonly featureSchemaDigest: string;
  readonly rule: ApplicabilityRule;
  readonly discoveryObservationIds: readonly string[];
  readonly acceptedDiscoveryObservationIds: readonly string[];
  readonly excludedDiscoveryObservationIds: readonly string[];
  readonly discoveryComparisonIds: readonly string[];
  readonly discoveryExperimentalUnitDigests: readonly string[];
  readonly discoverySourceGroups: readonly string[];
  readonly discoveryAssessmentDigest: string;
  readonly discoveryMetrics: ApplicabilityMetrics;
  readonly consideredFeatures: readonly string[];
  readonly validationObservationIds: readonly string[];
  readonly acceptedValidationObservationIds: readonly string[];
  readonly excludedValidationObservationIds: readonly string[];
  readonly validationComparisonIds: readonly string[];
  readonly validationExperimentalUnitDigests: readonly string[];
  readonly validationSourceGroups: readonly string[];
  readonly validationAssessmentDigest: string;
  readonly validationMetrics: ApplicabilityMetrics;
  readonly bindingDigest: string;
}

export interface VerifiedProcedureCandidateInput {
  readonly id: string;
  readonly procedureId: string;
  readonly version: string;
  readonly name: string;
  readonly goalSignature: string;
  readonly goalEvidence: readonly EvidenceRef[];
  readonly rationale: string;
  readonly steps: readonly ProcedureStepInput[];
  readonly dependencies?: readonly ProcedureDependencyInput[];
  readonly contraindications?: readonly ProcedureContraindicationInput[];
  readonly risk: ProcedureCandidateRisk;
  readonly verification: ProcedureVerificationContractInput;
  readonly rollback: ProcedureRollbackContractInput;
  readonly canonicalFingerprint: string;
  readonly actor: string;
  readonly recordedAt: number;
}

export interface VerifiedProcedureCandidate {
  readonly schemaVersion: typeof VERIFIED_PROCEDURE_CANDIDATE_SCHEMA_VERSION;
  readonly id: string;
  readonly procedureId: string;
  readonly version: string;
  readonly scope: string;
  readonly memoryId: string;
  readonly name: string;
  readonly goalSignature: string;
  readonly goalDigest: string;
  readonly goalEvidence: readonly ProcedureEvidenceBinding[];
  readonly rationale: string;
  readonly steps: readonly VerifiedProcedureStep[];
  readonly dependencies: readonly VerifiedProcedureDependency[];
  readonly contraindications: readonly VerifiedProcedureContraindication[];
  readonly risk: ProcedureCandidateRisk;
  readonly verification: ProcedureVerificationContract;
  readonly rollback: ProcedureRollbackContract;
  readonly applicability: VerifiedApplicabilityBinding;
  readonly canonicalFingerprint: string;
  readonly sourceEvidenceIds: readonly string[];
  readonly sourceGroups: readonly string[];
  readonly authorities: readonly Authority[];
  readonly taints: readonly EvidenceTaint[];
  readonly maximumSensitivity: EvidenceSensitivity;
  readonly humanReviewRequired: boolean;
  readonly reviewReasons: readonly string[];
  readonly actor: string;
  readonly recordedAt: number;
  readonly status: 'candidate';
  readonly executable: false;
  readonly procedurePromotionAuthorized: false;
  readonly canaryPlanAuthorized: false;
  readonly executionAuthorized: false;
  readonly candidateDigest: string;
}

interface EvidenceContext {
  readonly historical: EvidenceProjection;
  readonly current: EvidenceProjection;
  readonly scope: string;
  readonly records: Map<string, ProcedureEvidenceBinding>;
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

function normalizeStrings(
  valuesInput: readonly string[],
  label: string,
  maximum: number,
): readonly string[] {
  if (!Array.isArray(valuesInput) || valuesInput.length === 0 || valuesInput.length > maximum) {
    throw new Error(`${label} requires 1..${maximum} values`);
  }
  const values = valuesInput.map((value) => {
    assertText(value, label, MAX_TEXT_CHARACTERS);
    return value;
  });
  if (new Set(values).size !== values.length) throw new Error(`${label} cannot contain duplicates`);
  return Object.freeze([...values].sort());
}

function strongestSensitivity(values: readonly EvidenceSensitivity[]): EvidenceSensitivity {
  let strongest: EvidenceSensitivity = 'public';
  for (const value of values) {
    if (SENSITIVITY_RANK[value] > SENSITIVITY_RANK[strongest]) strongest = value;
  }
  return strongest;
}

function hasPositiveInstructionRole(roles: readonly EvidenceRole[]): boolean {
  return roles.some((role) => role === 'supports' || role === 'verifies' || role === 'constrains');
}

function hasSupportiveRole(roles: readonly EvidenceRole[]): boolean {
  return roles.some((role) => role === 'supports' || role === 'verifies');
}

function normalizeEvidence(
  referencesInput: readonly EvidenceRef[],
  context: EvidenceContext,
  label: string,
  requireVerifies = false,
): readonly ProcedureEvidenceBinding[] {
  if (
    !Array.isArray(referencesInput) ||
    referencesInput.length === 0 ||
    referencesInput.length > MAX_EVIDENCE_PER_BINDING
  ) {
    throw new Error(`${label} requires 1..${MAX_EVIDENCE_PER_BINDING} evidence references`);
  }
  context.totalReferences += referencesInput.length;
  if (context.totalReferences > MAX_TOTAL_EVIDENCE_REFERENCES) {
    throw new RangeError(
      `procedure candidate cannot exceed ${MAX_TOTAL_EVIDENCE_REFERENCES} evidence references`,
    );
  }
  const seen = new Set<string>();
  const bindings: ProcedureEvidenceBinding[] = [];
  for (const reference of referencesInput) {
    if (typeof reference !== 'object' || reference === null) {
      throw new Error(`${label} contains a malformed evidence reference`);
    }
    assertText(reference.sourceId, `${label} sourceId`);
    if (seen.has(reference.sourceId)) {
      throw new Error(`${label} repeats evidence source ${reference.sourceId}`);
    }
    seen.add(reference.sourceId);
    if (!context.historical.validatesReference(reference)) {
      throw new Error(`${label} was unavailable or forged when the candidate was recorded: ${reference.sourceId}`);
    }
    if (!context.current.validatesReference(reference)) {
      throw new Error(`${label} is not currently available: ${reference.sourceId}`);
    }
    const projected = context.current.get(reference.sourceId);
    if (projected === undefined) throw new Error(`${label} references unknown evidence`);
    if (projected.record.scope !== 'global' && projected.record.scope !== context.scope) {
      throw new Error(`${label} crosses scope through evidence ${reference.sourceId}`);
    }
    const roles = Object.freeze([...evidenceRoles(reference)].sort()) as readonly EvidenceRole[];
    if (!hasPositiveInstructionRole(roles) || roles.includes('contradicts')) {
      throw new Error(`${label} cannot use context-only or contradicting evidence`);
    }
    if (projected.record.sensitivity === 'secret' || projected.record.taints.includes('secret-detected')) {
      throw new Error(`${label} cannot derive a procedure candidate from secret evidence`);
    }
    const binding = Object.freeze({
      sourceId: reference.sourceId,
      sourceGroups: Object.freeze([...projected.record.sourceGroups]),
      authority: projected.record.authority,
      contentHash: projected.record.artifact.digest,
      roles,
      sensitivity: projected.record.sensitivity,
      taints: Object.freeze([...projected.record.taints]),
    });
    bindings.push(binding);
    context.records.set(binding.sourceId, binding);
  }
  if (requireVerifies && !bindings.some((binding) => binding.roles.includes('verifies'))) {
    throw new Error(`${label} requires evidence with the verifies role`);
  }
  return Object.freeze(bindings.sort((left, right) => left.sourceId.localeCompare(right.sourceId)));
}

function requireDigestBoundEvidence(
  bindings: readonly ProcedureEvidenceBinding[],
  digest: string,
  label: string,
  minimumAuthority: Authority,
): void {
  if (
    !bindings.some(
      (binding) =>
        binding.contentHash === digest &&
        binding.roles.includes('verifies') &&
        AUTHORITY_RANK[binding.authority] >= AUTHORITY_RANK[minimumAuthority],
    )
  ) {
    throw new Error(
      `${label} requires verifies evidence whose content hash equals the declared digest and whose authority is ${minimumAuthority} or stronger`,
    );
  }
}

function normalizeDependencies(
  dependenciesInput: readonly ProcedureDependencyInput[] | undefined,
  context: EvidenceContext,
): readonly VerifiedProcedureDependency[] {
  const dependencies = dependenciesInput ?? [];
  if (!Array.isArray(dependencies) || dependencies.length > MAX_DEPENDENCIES) {
    throw new Error(`procedure dependencies cannot exceed ${MAX_DEPENDENCIES}`);
  }
  const identities = new Set<string>();
  const normalized: VerifiedProcedureDependency[] = [];
  for (const dependency of dependencies) {
    if (typeof dependency !== 'object' || dependency === null) {
      throw new Error('procedure dependency must be an object');
    }
    assertText(dependency.id, 'procedure dependency id');
    if (!DEPENDENCY_KINDS.has(dependency.kind)) {
      throw new Error('procedure dependency kind is invalid');
    }
    assertDigest(dependency.versionDigest, 'procedure dependency versionDigest');
    const identity = `${dependency.kind}:${dependency.id}`;
    if (identities.has(identity)) throw new Error(`duplicate procedure dependency: ${identity}`);
    identities.add(identity);
    const evidence = normalizeEvidence(
      dependency.evidence,
      context,
      `procedure dependency ${identity} evidence`,
      true,
    );
    requireDigestBoundEvidence(
      evidence,
      dependency.versionDigest,
      `procedure dependency ${identity}`,
      'external-source',
    );
    const unsigned = {
      id: dependency.id,
      kind: dependency.kind,
      versionDigest: dependency.versionDigest,
      evidence,
    };
    normalized.push(
      Object.freeze({
        ...unsigned,
        dependencyDigest: contentDigest({
          domain: 'cl-procedure-dependency-v1',
          dependency: unsigned,
        }),
      }),
    );
  }
  return Object.freeze(
    normalized.sort((left, right) =>
      `${left.kind}:${left.id}`.localeCompare(`${right.kind}:${right.id}`),
    ),
  );
}

function normalizeContraindications(
  contraindicationsInput: readonly ProcedureContraindicationInput[] | undefined,
  context: EvidenceContext,
): readonly VerifiedProcedureContraindication[] {
  const contraindications = contraindicationsInput ?? [];
  if (!Array.isArray(contraindications) || contraindications.length > MAX_CONTRAINDICATIONS) {
    throw new Error(`procedure contraindications cannot exceed ${MAX_CONTRAINDICATIONS}`);
  }
  const ids = new Set<string>();
  const normalized: VerifiedProcedureContraindication[] = [];
  for (const contraindication of contraindications) {
    if (typeof contraindication !== 'object' || contraindication === null) {
      throw new Error('procedure contraindication must be an object');
    }
    assertText(contraindication.id, 'procedure contraindication id');
    if (ids.has(contraindication.id)) {
      throw new Error(`duplicate procedure contraindication: ${contraindication.id}`);
    }
    ids.add(contraindication.id);
    assertText(
      contraindication.condition,
      `procedure contraindication ${contraindication.id} condition`,
      MAX_TEXT_CHARACTERS,
    );
    const evidence = normalizeEvidence(
      contraindication.evidence,
      context,
      `procedure contraindication ${contraindication.id} evidence`,
    );
    if (
      !evidence.some(
        (binding) =>
          (binding.roles.includes('constrains') || binding.roles.includes('verifies')) &&
          AUTHORITY_RANK[binding.authority] >= AUTHORITY_RANK['external-source'],
      )
    ) {
      throw new Error(
        `procedure contraindication ${contraindication.id} requires constrains or verifies evidence with external-source authority or stronger`,
      );
    }
    const unsigned = {
      id: contraindication.id,
      condition: contraindication.condition,
      evidence,
    };
    normalized.push(
      Object.freeze({
        ...unsigned,
        contraindicationDigest: contentDigest({
          domain: 'cl-procedure-contraindication-v1',
          contraindication: unsigned,
        }),
      }),
    );
  }
  return Object.freeze(normalized.sort((left, right) => left.id.localeCompare(right.id)));
}

function normalizeSteps(
  stepsInput: readonly ProcedureStepInput[],
  context: EvidenceContext,
): readonly VerifiedProcedureStep[] {
  if (!Array.isArray(stepsInput) || stepsInput.length < 2 || stepsInput.length > MAX_STEPS) {
    throw new Error(`procedure candidate requires 2..${MAX_STEPS} ordered steps`);
  }
  const seenIds = new Set<string>();
  const provisional: Array<Omit<VerifiedProcedureStep, 'exclusiveEvidenceSourceIds' | 'stepDigest'>> = [];
  for (const step of stepsInput) {
    if (typeof step !== 'object' || step === null) throw new Error('procedure step must be an object');
    assertText(step.id, 'procedure step id');
    if (seenIds.has(step.id)) throw new Error(`duplicate procedure step id: ${step.id}`);
    if (!STEP_KINDS.has(step.kind)) throw new Error(`procedure step kind is invalid: ${String(step.kind)}`);
    assertText(step.instruction, `procedure step ${step.id} instruction`, MAX_TEXT_CHARACTERS);
    assertText(step.expectedOutcome, `procedure step ${step.id} expectedOutcome`, MAX_TEXT_CHARACTERS);
    const dependsOnInput = step.dependsOn ?? [];
    if (!Array.isArray(dependsOnInput) || dependsOnInput.length > MAX_STEPS) {
      throw new Error(`procedure step ${step.id} dependencies are invalid`);
    }
    const dependsOn = dependsOnInput.map((dependencyId) => {
      assertText(dependencyId, `procedure step ${step.id} dependency`);
      return dependencyId;
    });
    if (new Set(dependsOn).size !== dependsOn.length) {
      throw new Error(`procedure step ${step.id} repeats a dependency`);
    }
    for (const dependencyId of dependsOn) {
      if (!seenIds.has(dependencyId)) {
        throw new Error(
          `procedure step ${step.id} must depend only on an earlier step: ${dependencyId}`,
        );
      }
    }
    const evidence = normalizeEvidence(
      step.evidence,
      context,
      `procedure step ${step.id} evidence`,
      step.kind === 'verify',
    );
    if (!evidence.some((binding) => hasSupportiveRole(binding.roles))) {
      throw new Error(`procedure step ${step.id} requires supports or verifies evidence`);
    }
    provisional.push(
      Object.freeze({
        id: step.id,
        kind: step.kind,
        instruction: step.instruction,
        expectedOutcome: step.expectedOutcome,
        dependsOn: Object.freeze([...dependsOn].sort()),
        evidence,
      }),
    );
    seenIds.add(step.id);
  }

  const sourceCounts = new Map<string, number>();
  for (const step of provisional) {
    for (const evidence of step.evidence) {
      sourceCounts.set(evidence.sourceId, (sourceCounts.get(evidence.sourceId) ?? 0) + 1);
    }
  }
  const steps: VerifiedProcedureStep[] = [];
  for (const step of provisional) {
    const exclusiveEvidenceSourceIds = step.evidence
      .filter(
        (evidence) =>
          sourceCounts.get(evidence.sourceId) === 1 &&
          hasSupportiveRole(evidence.roles) &&
          AUTHORITY_RANK[evidence.authority] >= AUTHORITY_RANK['external-source'],
      )
      .map((evidence) => evidence.sourceId)
      .sort();
    if (exclusiveEvidenceSourceIds.length === 0) {
      throw new Error(
        `procedure step ${step.id} requires a step-exclusive evidence anchor with external-source authority or stronger`,
      );
    }
    const unsigned = {
      ...step,
      exclusiveEvidenceSourceIds: Object.freeze(exclusiveEvidenceSourceIds),
    };
    steps.push(
      Object.freeze({
        ...unsigned,
        stepDigest: contentDigest({ domain: 'cl-procedure-step-v1', step: unsigned }),
      }),
    );
  }
  return Object.freeze(steps);
}

function dependencyClosure(
  stepId: string,
  byId: ReadonlyMap<string, VerifiedProcedureStep>,
  result = new Set<string>(),
): ReadonlySet<string> {
  const step = byId.get(stepId);
  if (step === undefined) throw new Error(`unknown procedure step: ${stepId}`);
  for (const dependencyId of step.dependsOn) {
    if (result.has(dependencyId)) continue;
    result.add(dependencyId);
    dependencyClosure(dependencyId, byId, result);
  }
  return result;
}

function normalizeVerification(
  input: ProcedureVerificationContractInput,
  steps: readonly VerifiedProcedureStep[],
  context: EvidenceContext,
): ProcedureVerificationContract {
  if (typeof input !== 'object' || input === null) {
    throw new Error('procedure verification contract must be an object');
  }
  assertText(input.verificationStepId, 'procedure verificationStepId');
  if (!VERIFIERS.has(input.verifier)) throw new Error('procedure verifier is invalid');
  assertDigest(input.verifierDigest, 'procedure verifierDigest');
  const verifierEvidence = normalizeEvidence(
    input.evidence,
    context,
    'procedure verifier evidence',
    true,
  );
  requireDigestBoundEvidence(
    verifierEvidence,
    input.verifierDigest,
    'procedure verifier',
    input.verifier === 'human' ? 'human-explicit' : 'tool-verified',
  );
  if (
    input.verifier === 'human' &&
    !verifierEvidence.some(
      (binding) =>
        binding.contentHash === input.verifierDigest &&
        binding.roles.includes('verifies') &&
        binding.authority === 'human-explicit',
    )
  ) {
    throw new Error('human procedure verifier requires exact human-explicit verifier evidence');
  }
  const successCriteria = normalizeStrings(input.successCriteria, 'procedure success criteria', MAX_CRITERIA);
  const failureCriteria = normalizeStrings(input.failureCriteria, 'procedure failure criteria', MAX_CRITERIA);
  const overlappingCriteria = successCriteria.filter((criterion) =>
    failureCriteria.includes(criterion),
  );
  if (overlappingCriteria.length > 0) {
    throw new Error(
      `procedure success and failure criteria overlap: ${overlappingCriteria.join(', ')}`,
    );
  }
  if (!Number.isSafeInteger(input.timeoutMs) || input.timeoutMs <= 0 || input.timeoutMs > 3_600_000) {
    throw new Error('procedure verification timeoutMs must be in 1..3600000');
  }
  if (!Number.isInteger(input.maxAttempts) || input.maxAttempts <= 0 || input.maxAttempts > 10) {
    throw new Error('procedure verification maxAttempts must be in 1..10');
  }
  if (!FAILURE_ACTIONS.has(input.onFailure)) throw new Error('procedure onFailure is invalid');
  const verificationIndex = steps.findIndex((step) => step.id === input.verificationStepId);
  if (verificationIndex < 0) throw new Error('procedure verificationStepId is unknown');
  const verificationStep = steps[verificationIndex];
  if (verificationStep === undefined || verificationStep.kind !== 'verify') {
    throw new Error('procedure verificationStepId must identify a verify step');
  }
  if (verificationIndex !== steps.length - 1) {
    throw new Error('procedure verification step must be the final ordered step');
  }
  const byId = new Map(steps.map((step) => [step.id, step] as const));
  const closure = dependencyClosure(verificationStep.id, byId);
  const missing = steps
    .slice(0, -1)
    .map((step) => step.id)
    .filter((stepId) => !closure.has(stepId));
  if (missing.length > 0) {
    throw new Error(
      `procedure verification step does not cover every prior step: ${missing.join(', ')}`,
    );
  }
  if (
    !verificationStep.evidence.some(
      (evidence) =>
        evidence.roles.includes('verifies') &&
        AUTHORITY_RANK[evidence.authority] >= AUTHORITY_RANK['tool-verified'],
    )
  ) {
    throw new Error('procedure verification step requires tool-verified or stronger verifier evidence');
  }
  const unsigned = {
    verificationStepId: input.verificationStepId,
    verifier: input.verifier,
    verifierDigest: input.verifierDigest,
    evidence: verifierEvidence,
    successCriteria,
    failureCriteria,
    timeoutMs: input.timeoutMs,
    maxAttempts: input.maxAttempts,
    onFailure: input.onFailure,
  };
  return Object.freeze({
    ...unsigned,
    contractDigest: contentDigest({
      domain: 'cl-procedure-verification-contract-v1',
      contract: unsigned,
    }),
  });
}

function normalizeRollback(
  input: ProcedureRollbackContractInput,
  context: EvidenceContext,
): ProcedureRollbackContract {
  if (typeof input !== 'object' || input === null) {
    throw new Error('procedure rollback contract must be an object');
  }
  if (!ROLLBACK_STRATEGIES.has(input.strategy)) {
    throw new Error('procedure rollback strategy is invalid');
  }
  assertText(input.instructions, 'procedure rollback instructions', MAX_TEXT_CHARACTERS);
  const evidence = normalizeEvidence(input.evidence, context, 'procedure rollback evidence');
  if (
    !evidence.some(
      (binding) =>
        hasSupportiveRole(binding.roles) &&
        AUTHORITY_RANK[binding.authority] >= AUTHORITY_RANK['external-source'],
    )
  ) {
    throw new Error(
      'procedure rollback requires supports or verifies evidence with external-source authority or stronger',
    );
  }
  if (input.strategy === 'restore-checkpoint') {
    assertDigest(input.checkpointDigest, 'procedure rollback checkpointDigest');
    requireDigestBoundEvidence(
      evidence,
      input.checkpointDigest,
      'procedure rollback checkpoint',
      'tool-verified',
    );
  } else if (input.checkpointDigest !== undefined) {
    throw new Error('procedure rollback checkpointDigest is only valid for restore-checkpoint');
  }
  const unsigned = {
    strategy: input.strategy,
    instructions: input.instructions,
    evidence,
    ...(input.checkpointDigest === undefined ? {} : { checkpointDigest: input.checkpointDigest }),
  };
  return Object.freeze({
    ...unsigned,
    contractDigest: contentDigest({
      domain: 'cl-procedure-rollback-contract-v1',
      contract: unsigned,
    }),
  });
}

function applicabilityBinding(
  applicability: VerifiedApplicabilityHypothesis,
): VerifiedApplicabilityBinding {
  const unsigned = {
    validationId: applicability.id,
    validationDigest: applicability.validationDigest,
    discoveryCandidateId: applicability.candidateId,
    discoveryCandidateDigest: applicability.candidateDigest,
    featureSchemaDigest: applicability.featureSchemaDigest,
    rule: applicability.rule,
    discoveryObservationIds: applicability.discoveryObservationIds,
    acceptedDiscoveryObservationIds: applicability.acceptedDiscoveryObservationIds,
    excludedDiscoveryObservationIds: applicability.excludedDiscoveryObservationIds,
    discoveryComparisonIds: applicability.discoveryComparisonIds,
    discoveryExperimentalUnitDigests: applicability.discoveryExperimentalUnitDigests,
    discoverySourceGroups: applicability.discoverySourceGroups,
    discoveryAssessmentDigest: applicability.discoveryAssessmentDigest,
    discoveryMetrics: applicability.discoveryMetrics,
    consideredFeatures: applicability.consideredFeatures,
    validationObservationIds: applicability.validationObservationIds,
    acceptedValidationObservationIds: applicability.acceptedValidationObservationIds,
    excludedValidationObservationIds: applicability.excludedValidationObservationIds,
    validationComparisonIds: applicability.validationComparisonIds,
    validationExperimentalUnitDigests: applicability.validationExperimentalUnitDigests,
    validationSourceGroups: applicability.validationSourceGroups,
    validationAssessmentDigest: applicability.validationAssessmentDigest,
    validationMetrics: applicability.validationMetrics,
  };
  return Object.freeze({
    ...unsigned,
    bindingDigest: contentDigest({
      domain: 'cl-procedure-applicability-binding-v1',
      binding: unsigned,
    }),
  });
}

function reviewReasonsFor(
  bindings: readonly ProcedureEvidenceBinding[],
  risk: ProcedureCandidateRisk,
): readonly string[] {
  const reasons: string[] = [];
  if (
    bindings.some(
      (binding) =>
        binding.taints.includes('prompt-like') || binding.taints.includes('untrusted-source'),
    )
  ) {
    reasons.push('procedure evidence carries prompt-like or untrusted-source taint');
  }
  if (
    bindings.some(
      (binding) => SENSITIVITY_RANK[binding.sensitivity] >= SENSITIVITY_RANK.personal,
    )
  ) {
    reasons.push('procedure evidence is personal or more sensitive');
  }
  if (risk === 'high' || risk === 'destructive') {
    reasons.push(`${risk} procedure candidates require human review before any canary planning`);
  }
  return Object.freeze(reasons);
}

export function createVerifiedProcedureCandidate(
  memoryEventsInput: readonly MemoryEvent[],
  applicability: VerifiedApplicabilityHypothesis,
  input: VerifiedProcedureCandidateInput,
): VerifiedProcedureCandidate {
  if (!isIssuedVerifiedApplicabilityHypothesis(applicability)) {
    throw new Error('procedure candidate requires an issued applicability validation capability');
  }
  if (applicability.status !== 'validated') {
    throw new Error('procedure candidate requires validated applicability');
  }
  if (applicability.blockers.length > 0) {
    throw new Error('validated applicability cannot retain blockers');
  }
  const request = canonicalSnapshot(input, 'verified procedure candidate input');
  assertText(request.id, 'procedure candidate id');
  assertText(request.procedureId, 'procedure id');
  assertText(request.version, 'procedure version', MAX_VERSION_CHARACTERS);
  if (!VERSION_PATTERN.test(request.version)) throw new Error('procedure version is invalid');
  assertText(request.name, 'procedure name');
  assertText(request.goalSignature, 'procedure goalSignature', MAX_TEXT_CHARACTERS);
  assertText(request.rationale, 'procedure rationale', MAX_TEXT_CHARACTERS);
  assertText(request.actor, 'procedure candidate actor');
  assertSafeTime(request.recordedAt, 'procedure candidate recordedAt');
  if (request.recordedAt < applicability.recordedAt) {
    throw new Error('procedure candidate cannot predate applicability validation');
  }
  if (!RISKS.has(request.risk)) throw new Error('procedure candidate risk is invalid');
  assertDigest(request.canonicalFingerprint, 'procedure candidate canonicalFingerprint');

  const events = MemoryKernel.from(memoryEventsInput).events();
  const latestCanonicalEvent = events.at(-1);
  if (
    latestCanonicalEvent !== undefined &&
    request.recordedAt < latestCanonicalEvent.recordedAt
  ) {
    throw new Error(
      'procedure candidate cannot be backdated before the canonical tail it fingerprints',
    );
  }
  const canonicalFingerprint = fingerprintMemoryEvents(events);
  if (request.canonicalFingerprint !== canonicalFingerprint) {
    throw new Error('procedure candidate canonical fingerprint is stale or forged');
  }
  const context: EvidenceContext = {
    historical: EvidenceProjection.from(events, request.recordedAt),
    current: EvidenceProjection.from(events),
    scope: applicability.scope,
    records: new Map(),
    totalReferences: 0,
  };
  const goalEvidence = normalizeEvidence(request.goalEvidence, context, 'procedure goal evidence');
  if (
    !goalEvidence.some(
      (binding) =>
        hasSupportiveRole(binding.roles) &&
        AUTHORITY_RANK[binding.authority] >= AUTHORITY_RANK['external-source'],
    )
  ) {
    throw new Error(
      'procedure goal requires supports or verifies evidence with external-source authority or stronger',
    );
  }
  const steps = normalizeSteps(request.steps, context);
  const dependencies = normalizeDependencies(request.dependencies, context);
  const contraindications = normalizeContraindications(request.contraindications, context);
  const verification = normalizeVerification(request.verification, steps, context);
  const rollback = normalizeRollback(request.rollback, context);
  const mutatesExternalState = steps.some((step) => step.kind === 'mutate');
  if (mutatesExternalState && request.risk === 'low') {
    throw new Error('procedure candidates with mutate steps require medium risk or stronger');
  }
  if (mutatesExternalState && rollback.strategy === 'disable-candidate') {
    throw new Error(
      'procedure candidates with mutate steps require restore-checkpoint or manual rollback',
    );
  }

  if (request.risk === 'high' || request.risk === 'destructive') {
    if (verification.verifier !== 'human' || verification.onFailure !== 'human-review') {
      throw new Error(`${request.risk} procedure requires human verification and failure review`);
    }
    if (rollback.strategy === 'disable-candidate') {
      throw new Error(`${request.risk} procedure requires restore-checkpoint or manual rollback`);
    }
    if (
      ![...context.records.values()].some(
        (binding) => binding.authority === 'human-explicit',
      )
    ) {
      throw new Error(`${request.risk} procedure requires human-explicit supporting evidence`);
    }
  }

  const evidenceBindings = Object.freeze(
    [...context.records.values()].sort((left, right) => left.sourceId.localeCompare(right.sourceId)),
  );
  const sourceEvidenceIds = Object.freeze(evidenceBindings.map((binding) => binding.sourceId));
  const sourceGroups = Object.freeze([
    ...new Set([
      ...evidenceBindings.flatMap((binding) => binding.sourceGroups),
      ...applicability.discoverySourceGroups,
      ...applicability.validationSourceGroups,
    ]),
  ].sort());
  const authorities = Object.freeze([
    ...new Set(evidenceBindings.map((binding) => binding.authority)),
  ].sort()) as readonly Authority[];
  const taints = Object.freeze([
    ...new Set(evidenceBindings.flatMap((binding) => binding.taints)),
  ].sort()) as readonly EvidenceTaint[];
  const maximumSensitivity = strongestSensitivity(
    evidenceBindings.map((binding) => binding.sensitivity),
  );
  const reviewReasons = reviewReasonsFor(evidenceBindings, request.risk);
  const applicabilityBindingValue = applicabilityBinding(applicability);
  const goalDigest = contentDigest({
    domain: 'cl-procedure-goal-v1',
    goalSignature: request.goalSignature,
    evidence: goalEvidence,
  });
  const unsigned = {
    schemaVersion: VERIFIED_PROCEDURE_CANDIDATE_SCHEMA_VERSION,
    id: request.id,
    procedureId: request.procedureId,
    version: request.version,
    scope: applicability.scope,
    memoryId: applicability.memoryId,
    name: request.name,
    goalSignature: request.goalSignature,
    goalDigest,
    goalEvidence,
    rationale: request.rationale,
    steps,
    dependencies,
    contraindications,
    risk: request.risk,
    verification,
    rollback,
    applicability: applicabilityBindingValue,
    canonicalFingerprint,
    sourceEvidenceIds,
    sourceGroups,
    authorities,
    taints,
    maximumSensitivity,
    humanReviewRequired: reviewReasons.length > 0,
    reviewReasons,
    actor: request.actor,
    recordedAt: request.recordedAt,
    status: 'candidate' as const,
    executable: false as const,
    procedurePromotionAuthorized: false as const,
    canaryPlanAuthorized: false as const,
    executionAuthorized: false as const,
  };
  const candidate = canonicalSnapshot<VerifiedProcedureCandidate>(
    {
      ...unsigned,
      candidateDigest: contentDigest({
        domain: 'cl-verified-procedure-candidate-v1',
        candidate: unsigned,
      }),
    },
    'verified procedure candidate',
  );
  issuedCandidates.add(candidate as object);
  return candidate;
}

export function isIssuedVerifiedProcedureCandidate(
  candidate: VerifiedProcedureCandidate,
): boolean {
  return (
    typeof candidate === 'object' &&
    candidate !== null &&
    issuedCandidates.has(candidate as object)
  );
}
