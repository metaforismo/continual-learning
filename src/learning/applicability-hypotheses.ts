import {
  assessMemoryUtility,
  verifyMemoryIntervention,
  type MemoryInterventionInput,
  type MemoryUtilityAssessment,
  type MemoryUtilityPolicy,
  type VerifiedExperienceTrace,
  type VerifiedMemoryIntervention,
} from './experience-attribution-api.js';
import { canonicalJson, contentDigest } from '../retrieval/canonical.js';

export const APPLICABILITY_HYPOTHESES_SCHEMA_VERSION = 1 as const;

const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const FEATURE_PATTERN = /^[a-z0-9][a-z0-9._:/=-]{0,127}$/;
const MAX_IDENTIFIER_CHARACTERS = 512;
const MAX_FEATURES_PER_OBSERVATION = 64;
const MAX_OBSERVATIONS = 4_096;
const MAX_CANDIDATE_FEATURES = 32;
const MAX_INPUT_CHARACTERS = 1_000_000;
const EPSILON = 1e-12;

const issuedObservations = new WeakSet<object>();
const issuedCandidates = new WeakSet<object>();
const issuedValidations = new WeakSet<object>();
const observationInterventions = new WeakMap<object, VerifiedMemoryIntervention>();

export interface ApplicabilityRule {
  readonly requiredFeatures: readonly string[];
  readonly forbiddenFeatures: readonly string[];
}

export interface ApplicabilityObservationInput {
  readonly id: string;
  readonly contextFeatures: readonly string[];
  /** Digest of the host feature-extraction schema/version. */
  readonly featureSchemaDigest: string;
  /** Host-observed feature time; must not be after either trial arm starts. */
  readonly featureObservedAt: number;
  readonly recorder: string;
}

export interface VerifiedApplicabilityObservation {
  readonly schemaVersion: typeof APPLICABILITY_HYPOTHESES_SCHEMA_VERSION;
  readonly id: string;
  readonly scope: string;
  readonly memoryId: string;
  readonly interventionId: string;
  readonly comparisonDigest: string;
  readonly experimentalUnitDigest: string;
  readonly contextFingerprint: string;
  readonly goalDigest: string;
  readonly runtimeDigest: string;
  readonly effect: number;
  readonly sourceGroups: readonly string[];
  readonly contextFeatures: readonly string[];
  readonly featureSchemaDigest: string;
  readonly featureSetDigest: string;
  readonly featureObservedAt: number;
  readonly trialStartedAt: number;
  readonly trialCompletedAt: number;
  readonly recordedAt: number;
  readonly recorder: string;
  readonly causalEvidence: true;
  readonly procedurePromotionAuthorized: false;
  readonly executionAuthorized: false;
  readonly observationDigest: string;
}

export interface ApplicabilityInductionPolicy {
  readonly effectThreshold: number;
  readonly minPositiveExamples: number;
  readonly minCounterexamples: number;
  readonly minDistinctContexts: number;
  readonly minFeatureSupport: number;
  readonly maxClauses: number;
  readonly maxCandidateFeatures: number;
  readonly complexityPenalty: number;
  readonly minDiscoveryPrecision: number;
  readonly minDiscoveryRecall: number;
  readonly maxDiscoveryCounterexampleActivationRate: number;
  readonly minMeanActivatedEffect: number;
}

export interface ApplicabilityValidationPolicy {
  readonly minValidationExamples: number;
  readonly minPositiveExamples: number;
  readonly minCounterexamples: number;
  readonly minDistinctContexts: number;
  readonly minPrecision: number;
  readonly minRecall: number;
  readonly minSpecificity: number;
  readonly maxCounterexampleActivationRate: number;
  readonly minMeanActivatedEffect: number;
}

export interface ApplicabilityMetrics {
  readonly exampleCount: number;
  readonly positiveCount: number;
  readonly negativeCount: number;
  readonly neutralCount: number;
  readonly activatedCount: number;
  readonly truePositive: number;
  readonly falsePositive: number;
  readonly falseNegative: number;
  readonly trueNegative: number;
  readonly precision: number;
  readonly recall: number;
  readonly specificity: number;
  readonly coverage: number;
  readonly counterexampleActivationRate: number;
  readonly meanActivatedEffect: number;
  readonly distinctContexts: number;
  readonly distinctExperimentalUnits: number;
  readonly contradictoryFeatureSignatureDigests: readonly string[];
}

export interface ApplicabilityHypothesisInput {
  readonly id: string;
  readonly scope: string;
  readonly memoryId: string;
  readonly discoveryObservationIds: readonly string[];
  readonly actor: string;
  readonly recordedAt: number;
  readonly policy?: Partial<ApplicabilityInductionPolicy>;
}

export type ApplicabilityHypothesisStatus = 'candidate' | 'ambiguous' | 'insufficient';

export interface ApplicabilityHypothesisCandidate {
  readonly schemaVersion: typeof APPLICABILITY_HYPOTHESES_SCHEMA_VERSION;
  readonly id: string;
  readonly scope: string;
  readonly memoryId: string;
  readonly status: ApplicabilityHypothesisStatus;
  readonly rule: ApplicabilityRule;
  readonly featureSchemaDigest: string;
  readonly discoveryObservationIds: readonly string[];
  readonly acceptedDiscoveryObservationIds: readonly string[];
  readonly excludedDiscoveryObservationIds: readonly string[];
  readonly discoveryComparisonIds: readonly string[];
  readonly discoveryExperimentalUnitDigests: readonly string[];
  readonly discoverySourceGroups: readonly string[];
  readonly discoveryAssessmentDigest: string;
  readonly discoveryMetrics: ApplicabilityMetrics;
  readonly consideredFeatures: readonly string[];
  readonly actor: string;
  readonly recordedAt: number;
  readonly policy: ApplicabilityInductionPolicy;
  readonly blockers: readonly string[];
  readonly procedurePromotionAuthorized: false;
  readonly executionAuthorized: false;
  readonly candidateDigest: string;
}

export interface ApplicabilityValidationInput {
  readonly id: string;
  readonly candidateId: string;
  readonly validationObservationIds: readonly string[];
  readonly actor: string;
  readonly recordedAt: number;
  readonly policy?: Partial<ApplicabilityValidationPolicy>;
}

export type ApplicabilityValidationStatus =
  | 'validated'
  | 'rejected'
  | 'ambiguous'
  | 'insufficient';

export interface VerifiedApplicabilityHypothesis {
  readonly schemaVersion: typeof APPLICABILITY_HYPOTHESES_SCHEMA_VERSION;
  readonly id: string;
  readonly candidateId: string;
  readonly candidateDigest: string;
  readonly scope: string;
  readonly memoryId: string;
  readonly status: ApplicabilityValidationStatus;
  readonly rule: ApplicabilityRule;
  readonly featureSchemaDigest: string;
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
  readonly actor: string;
  readonly recordedAt: number;
  readonly policy: ApplicabilityValidationPolicy;
  readonly blockers: readonly string[];
  readonly procedurePromotionAuthorized: false;
  readonly executionAuthorized: false;
  readonly validationDigest: string;
}

export const DEFAULT_APPLICABILITY_INDUCTION_POLICY: Readonly<ApplicabilityInductionPolicy> =
  Object.freeze({
    effectThreshold: 0.1,
    minPositiveExamples: 3,
    minCounterexamples: 2,
    minDistinctContexts: 2,
    minFeatureSupport: 2,
    maxClauses: 6,
    maxCandidateFeatures: 24,
    complexityPenalty: 0.02,
    minDiscoveryPrecision: 0.7,
    minDiscoveryRecall: 0.67,
    maxDiscoveryCounterexampleActivationRate: 0.3,
    minMeanActivatedEffect: 0.2,
  });

export const DEFAULT_APPLICABILITY_VALIDATION_POLICY: Readonly<ApplicabilityValidationPolicy> =
  Object.freeze({
    minValidationExamples: 6,
    minPositiveExamples: 3,
    minCounterexamples: 2,
    minDistinctContexts: 2,
    minPrecision: 0.8,
    minRecall: 0.6,
    minSpecificity: 0.8,
    maxCounterexampleActivationRate: 0.2,
    minMeanActivatedEffect: 0.2,
  });

type EffectLabel = 'positive' | 'negative' | 'neutral';

interface Example {
  readonly observation: VerifiedApplicabilityObservation;
  readonly features: ReadonlySet<string>;
  readonly label: EffectLabel;
}

interface IndependentObservationSet {
  readonly assessment: MemoryUtilityAssessment;
  readonly accepted: readonly VerifiedApplicabilityObservation[];
  readonly excluded: readonly VerifiedApplicabilityObservation[];
}

interface LiteralCandidate {
  readonly kind: 'required' | 'forbidden';
  readonly feature: string;
  readonly discrimination: number;
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

function canonicalSnapshot<T>(value: T, label: string, maxCharacters = MAX_INPUT_CHARACTERS): T {
  const encoded = canonicalJson(value);
  if (encoded.length > maxCharacters) {
    throw new RangeError(`${label} cannot exceed ${maxCharacters} canonical characters`);
  }
  return deepFreeze(JSON.parse(encoded) as T);
}

function snapshotArray<T>(values: readonly T[], label: string): readonly T[] {
  if (!Array.isArray(values)) throw new TypeError(`${label} must be an array`);
  return Object.freeze(Array.from(values));
}

function assertIdentifier(value: unknown, label: string): asserts value is string {
  if (
    typeof value !== 'string' ||
    value.trim().length === 0 ||
    value.length > MAX_IDENTIFIER_CHARACTERS ||
    value.includes('\u0000')
  ) {
    throw new Error(`${label} must be non-empty bounded text without U+0000`);
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

function assertRate(value: unknown, label: string): asserts value is number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 1) {
    throw new Error(`${label} must be in [0, 1]`);
  }
}

function assertPositiveInteger(value: unknown, label: string): asserts value is number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
}

function normalizeFeatures(featuresInput: readonly string[]): readonly string[] {
  if (
    !Array.isArray(featuresInput) ||
    featuresInput.length === 0 ||
    featuresInput.length > MAX_FEATURES_PER_OBSERVATION
  ) {
    throw new Error(
      `contextFeatures requires 1..${MAX_FEATURES_PER_OBSERVATION} feature values`,
    );
  }
  const features = featuresInput.map((feature) => {
    if (typeof feature !== 'string') throw new Error('context feature must be a string');
    const normalized = feature.trim().toLowerCase();
    if (!FEATURE_PATTERN.test(normalized)) {
      throw new Error(`context feature is invalid: ${feature}`);
    }
    return normalized;
  });
  if (new Set(features).size !== features.length) {
    throw new Error('contextFeatures cannot contain duplicates after normalization');
  }
  return Object.freeze(features.sort());
}

function uniqueSortedIds(values: readonly string[], label: string): readonly string[] {
  if (!Array.isArray(values) || values.length === 0 || values.length > MAX_OBSERVATIONS) {
    throw new Error(`${label} requires 1..${MAX_OBSERVATIONS} ids`);
  }
  for (const value of values) assertIdentifier(value, label);
  if (new Set(values).size !== values.length) throw new Error(`${label} cannot contain duplicates`);
  return Object.freeze([...values].sort());
}

function normalizeInductionPolicy(
  partial: Partial<ApplicabilityInductionPolicy> | undefined,
): ApplicabilityInductionPolicy {
  const policy = canonicalSnapshot(
    { ...DEFAULT_APPLICABILITY_INDUCTION_POLICY, ...(partial ?? {}) },
    'applicability induction policy',
  );
  assertRate(policy.effectThreshold, 'effectThreshold');
  assertPositiveInteger(policy.minPositiveExamples, 'minPositiveExamples');
  assertPositiveInteger(policy.minCounterexamples, 'minCounterexamples');
  assertPositiveInteger(policy.minDistinctContexts, 'minDistinctContexts');
  assertPositiveInteger(policy.minFeatureSupport, 'minFeatureSupport');
  assertPositiveInteger(policy.maxClauses, 'maxClauses');
  assertPositiveInteger(policy.maxCandidateFeatures, 'maxCandidateFeatures');
  if (policy.maxClauses > 16) throw new Error('maxClauses cannot exceed 16');
  if (policy.maxCandidateFeatures > MAX_CANDIDATE_FEATURES) {
    throw new Error(`maxCandidateFeatures cannot exceed ${MAX_CANDIDATE_FEATURES}`);
  }
  assertRate(policy.complexityPenalty, 'complexityPenalty');
  assertRate(policy.minDiscoveryPrecision, 'minDiscoveryPrecision');
  assertRate(policy.minDiscoveryRecall, 'minDiscoveryRecall');
  assertRate(
    policy.maxDiscoveryCounterexampleActivationRate,
    'maxDiscoveryCounterexampleActivationRate',
  );
  assertRate(policy.minMeanActivatedEffect, 'minMeanActivatedEffect');
  return policy;
}

function normalizeValidationPolicy(
  partial: Partial<ApplicabilityValidationPolicy> | undefined,
): ApplicabilityValidationPolicy {
  const policy = canonicalSnapshot(
    { ...DEFAULT_APPLICABILITY_VALIDATION_POLICY, ...(partial ?? {}) },
    'applicability validation policy',
  );
  assertPositiveInteger(policy.minValidationExamples, 'minValidationExamples');
  assertPositiveInteger(policy.minPositiveExamples, 'minPositiveExamples');
  assertPositiveInteger(policy.minCounterexamples, 'minCounterexamples');
  assertPositiveInteger(policy.minDistinctContexts, 'minDistinctContexts');
  assertRate(policy.minPrecision, 'minPrecision');
  assertRate(policy.minRecall, 'minRecall');
  assertRate(policy.minSpecificity, 'minSpecificity');
  assertRate(policy.maxCounterexampleActivationRate, 'maxCounterexampleActivationRate');
  assertRate(policy.minMeanActivatedEffect, 'minMeanActivatedEffect');
  return policy;
}

function assertIssuedObservation(
  observation: unknown,
): asserts observation is VerifiedApplicabilityObservation {
  if (
    typeof observation !== 'object' ||
    observation === null ||
    !issuedObservations.has(observation as object) ||
    !observationInterventions.has(observation as object)
  ) {
    throw new Error('applicability requires an issued observation capability');
  }
}

function selectedObservations(
  observationsInput: readonly VerifiedApplicabilityObservation[],
  idsInput: readonly string[],
  scope: string,
  memoryId: string,
  label: string,
): readonly VerifiedApplicabilityObservation[] {
  const observations = snapshotArray(observationsInput, `${label} observations`);
  const ids = uniqueSortedIds(idsInput, `${label} observation ids`);
  const selected: VerifiedApplicabilityObservation[] = [];
  const comparisonIds = new Set<string>();
  for (const id of ids) {
    const matches = observations.filter((observation) => observation.id === id);
    if (matches.length !== 1) {
      throw new Error(`${label} observation id is absent or duplicated: ${id}`);
    }
    const observation = matches[0];
    if (observation === undefined) throw new Error(`${label} observation disappeared: ${id}`);
    assertIssuedObservation(observation);
    if (observation.scope !== scope || observation.memoryId !== memoryId) {
      throw new Error(`${label} observation crosses scope or memory: ${id}`);
    }
    if (comparisonIds.has(observation.interventionId)) {
      throw new Error(`${label} binds the same intervention more than once`);
    }
    comparisonIds.add(observation.interventionId);
    selected.push(observation);
  }
  return Object.freeze(
    selected.sort((left, right) => left.observationDigest.localeCompare(right.observationDigest)),
  );
}

function independencePolicy(effectThreshold: number): MemoryUtilityPolicy {
  return Object.freeze({
    minIndependentPairs: 1,
    minDistinctContexts: 1,
    minMeanAbsoluteEffect: 0,
    minDirectionalRate: 0,
    minDirectionalWilsonLowerBound: 0,
    maxOppositeRate: 1,
    neutralThreshold: effectThreshold,
  });
}

function independentObservationSet(
  observations: readonly VerifiedApplicabilityObservation[],
  effectThreshold: number,
  scope: string,
  memoryId: string,
): IndependentObservationSet {
  const interventions = observations.map((observation) => {
    const intervention = observationInterventions.get(observation as object);
    if (intervention === undefined) {
      throw new Error('applicability observation lost its intervention capability');
    }
    return intervention;
  });
  const assessment = assessMemoryUtility(
    { scope, memoryId },
    [],
    interventions,
    independencePolicy(effectThreshold),
  );
  const byComparisonId = new Map(
    observations.map((observation) => [observation.interventionId, observation] as const),
  );
  const accepted = assessment.comparisonIds.map((comparisonId) => {
    const observation = byComparisonId.get(comparisonId);
    if (observation === undefined) {
      throw new Error(`assessment returned an unknown comparison: ${comparisonId}`);
    }
    return observation;
  });
  const excluded = assessment.excludedComparisonIds.map((comparisonId) => {
    const observation = byComparisonId.get(comparisonId);
    if (observation === undefined) {
      throw new Error(`assessment excluded an unknown comparison: ${comparisonId}`);
    }
    return observation;
  });
  return Object.freeze({
    assessment,
    accepted: Object.freeze(
      accepted.sort((left, right) => left.observationDigest.localeCompare(right.observationDigest)),
    ),
    excluded: Object.freeze(
      excluded.sort((left, right) => left.observationDigest.localeCompare(right.observationDigest)),
    ),
  });
}

function labelEffect(effect: number, threshold: number): EffectLabel {
  if (effect > threshold) return 'positive';
  if (effect < -threshold) return 'negative';
  return 'neutral';
}

function examplesFor(
  observations: readonly VerifiedApplicabilityObservation[],
  effectThreshold: number,
): readonly Example[] {
  return Object.freeze(
    observations.map((observation) =>
      Object.freeze({
        observation,
        features: new Set(observation.contextFeatures),
        label: labelEffect(observation.effect, effectThreshold),
      }),
    ),
  );
}

function ruleAppliesToSet(rule: ApplicabilityRule, features: ReadonlySet<string>): boolean {
  return (
    rule.requiredFeatures.every((feature) => features.has(feature)) &&
    rule.forbiddenFeatures.every((feature) => !features.has(feature))
  );
}

export function applicabilityRuleApplies(
  ruleInput: ApplicabilityRule,
  contextFeaturesInput: readonly string[],
): boolean {
  const rule = normalizeRule(ruleInput);
  return ruleAppliesToSet(rule, new Set(normalizeFeatures(contextFeaturesInput)));
}

function normalizeRule(ruleInput: ApplicabilityRule): ApplicabilityRule {
  if (typeof ruleInput !== 'object' || ruleInput === null) {
    throw new TypeError('applicability rule must be an object');
  }
  const requiredFeatures = normalizeRuleFeatures(ruleInput.requiredFeatures, 'requiredFeatures');
  const forbiddenFeatures = normalizeRuleFeatures(ruleInput.forbiddenFeatures, 'forbiddenFeatures');
  if (requiredFeatures.some((feature) => forbiddenFeatures.includes(feature))) {
    throw new Error('a context feature cannot be both required and forbidden');
  }
  return Object.freeze({ requiredFeatures, forbiddenFeatures });
}

function normalizeRuleFeatures(features: readonly string[], label: string): readonly string[] {
  if (!Array.isArray(features) || features.length > 16) {
    throw new Error(`${label} must be a bounded feature array`);
  }
  if (features.length === 0) return Object.freeze([]);
  return normalizeFeatures(features);
}

function contradictoryFeatureSignatures(examples: readonly Example[]): readonly string[] {
  const labels = new Map<string, Set<EffectLabel>>();
  for (const example of examples) {
    const digest = contentDigest({
      domain: 'cl-applicability-feature-signature-v1',
      features: example.observation.contextFeatures,
    });
    const current = labels.get(digest) ?? new Set<EffectLabel>();
    current.add(example.label);
    labels.set(digest, current);
  }
  return Object.freeze(
    [...labels.entries()]
      .filter(([, labelsForSignature]) =>
        labelsForSignature.has('positive') &&
        (labelsForSignature.has('negative') || labelsForSignature.has('neutral')),
      )
      .map(([digest]) => digest)
      .sort(),
  );
}

function metrics(rule: ApplicabilityRule, examples: readonly Example[]): ApplicabilityMetrics {
  let positiveCount = 0;
  let negativeCount = 0;
  let neutralCount = 0;
  let activatedCount = 0;
  let truePositive = 0;
  let falsePositive = 0;
  let falseNegative = 0;
  let trueNegative = 0;
  let activatedEffect = 0;
  for (const example of examples) {
    const applies = ruleAppliesToSet(rule, example.features);
    if (example.label === 'positive') positiveCount += 1;
    else if (example.label === 'negative') negativeCount += 1;
    else neutralCount += 1;
    if (applies) {
      activatedCount += 1;
      activatedEffect += example.observation.effect;
      if (example.label === 'positive') truePositive += 1;
      else falsePositive += 1;
    } else if (example.label === 'positive') {
      falseNegative += 1;
    } else {
      trueNegative += 1;
    }
  }
  const counterexampleCount = negativeCount + neutralCount;
  const precision =
    truePositive + falsePositive === 0 ? 0 : truePositive / (truePositive + falsePositive);
  const recall = positiveCount === 0 ? 0 : truePositive / positiveCount;
  const specificity =
    counterexampleCount === 0 ? 0 : trueNegative / counterexampleCount;
  return Object.freeze({
    exampleCount: examples.length,
    positiveCount,
    negativeCount,
    neutralCount,
    activatedCount,
    truePositive,
    falsePositive,
    falseNegative,
    trueNegative,
    precision,
    recall,
    specificity,
    coverage: examples.length === 0 ? 0 : activatedCount / examples.length,
    counterexampleActivationRate:
      counterexampleCount === 0 ? 0 : falsePositive / counterexampleCount,
    meanActivatedEffect: activatedCount === 0 ? 0 : activatedEffect / activatedCount,
    distinctContexts: new Set(
      examples.map((example) => example.observation.contextFingerprint),
    ).size,
    distinctExperimentalUnits: new Set(
      examples.map((example) => example.observation.experimentalUnitDigest),
    ).size,
    contradictoryFeatureSignatureDigests: contradictoryFeatureSignatures(examples),
  });
}

function ruleScore(
  rule: ApplicabilityRule,
  examples: readonly Example[],
  complexityPenalty: number,
): number {
  const result = metrics(rule, examples);
  return (
    (result.precision + result.recall + result.specificity) / 3 -
    complexityPenalty * (rule.requiredFeatures.length + rule.forbiddenFeatures.length)
  );
}

function featureCandidates(
  examples: readonly Example[],
  policy: ApplicabilityInductionPolicy,
): { readonly features: readonly string[]; readonly literals: readonly LiteralCandidate[] } {
  const positives = examples.filter((example) => example.label === 'positive');
  const counterexamples = examples.filter((example) => example.label !== 'positive');
  const allFeatures = new Set(
    examples.flatMap((example) => example.observation.contextFeatures),
  );
  const ranked = [...allFeatures]
    .map((feature) => {
      const positiveSupport = positives.filter((example) => example.features.has(feature)).length;
      const counterexampleSupport = counterexamples.filter((example) =>
        example.features.has(feature),
      ).length;
      const positiveRate = positives.length === 0 ? 0 : positiveSupport / positives.length;
      const counterexampleRate =
        counterexamples.length === 0 ? 0 : counterexampleSupport / counterexamples.length;
      return {
        feature,
        positiveSupport,
        counterexampleSupport,
        discrimination: Math.abs(positiveRate - counterexampleRate),
      };
    })
    .filter(
      (candidate) =>
        candidate.positiveSupport >= policy.minFeatureSupport ||
        candidate.counterexampleSupport >= policy.minFeatureSupport,
    )
    .sort(
      (left, right) =>
        right.discrimination - left.discrimination || left.feature.localeCompare(right.feature),
    )
    .slice(0, policy.maxCandidateFeatures);
  const literals: LiteralCandidate[] = [];
  for (const candidate of ranked) {
    if (candidate.positiveSupport >= policy.minFeatureSupport) {
      literals.push({
        kind: 'required',
        feature: candidate.feature,
        discrimination: candidate.discrimination,
      });
    }
    if (candidate.counterexampleSupport >= policy.minFeatureSupport) {
      literals.push({
        kind: 'forbidden',
        feature: candidate.feature,
        discrimination: candidate.discrimination,
      });
    }
  }
  literals.sort(
    (left, right) =>
      right.discrimination - left.discrimination ||
      `${left.kind}:${left.feature}`.localeCompare(`${right.kind}:${right.feature}`),
  );
  return Object.freeze({
    features: Object.freeze(ranked.map((candidate) => candidate.feature)),
    literals: Object.freeze(literals),
  });
}

function addLiteral(rule: ApplicabilityRule, literal: LiteralCandidate): ApplicabilityRule {
  return Object.freeze({
    requiredFeatures: Object.freeze(
      literal.kind === 'required'
        ? [...rule.requiredFeatures, literal.feature].sort()
        : [...rule.requiredFeatures],
    ),
    forbiddenFeatures: Object.freeze(
      literal.kind === 'forbidden'
        ? [...rule.forbiddenFeatures, literal.feature].sort()
        : [...rule.forbiddenFeatures],
    ),
  });
}

function induceRule(
  examples: readonly Example[],
  policy: ApplicabilityInductionPolicy,
): { readonly rule: ApplicabilityRule; readonly consideredFeatures: readonly string[] } {
  const candidates = featureCandidates(examples, policy);
  let rule: ApplicabilityRule = Object.freeze({
    requiredFeatures: Object.freeze([]),
    forbiddenFeatures: Object.freeze([]),
  });
  let currentScore = ruleScore(rule, examples, policy.complexityPenalty);
  for (let step = 0; step < policy.maxClauses; step += 1) {
    let winner:
      | {
          readonly literal: LiteralCandidate;
          readonly rule: ApplicabilityRule;
          readonly score: number;
          readonly metrics: ApplicabilityMetrics;
        }
      | undefined;
    for (const literal of candidates.literals) {
      if (
        rule.requiredFeatures.includes(literal.feature) ||
        rule.forbiddenFeatures.includes(literal.feature)
      ) {
        continue;
      }
      const nextRule = addLiteral(rule, literal);
      const nextMetrics = metrics(nextRule, examples);
      if (nextMetrics.recall + EPSILON < policy.minDiscoveryRecall) continue;
      const nextScore = ruleScore(nextRule, examples, policy.complexityPenalty);
      const next = { literal, rule: nextRule, score: nextScore, metrics: nextMetrics };
      if (
        winner === undefined ||
        next.score > winner.score + EPSILON ||
        (Math.abs(next.score - winner.score) <= EPSILON &&
          (next.metrics.falsePositive < winner.metrics.falsePositive ||
            (next.metrics.falsePositive === winner.metrics.falsePositive &&
              (next.metrics.falseNegative < winner.metrics.falseNegative ||
                (next.metrics.falseNegative === winner.metrics.falseNegative &&
                  `${next.literal.kind}:${next.literal.feature}`.localeCompare(
                    `${winner.literal.kind}:${winner.literal.feature}`,
                  ) < 0)))))
      ) {
        winner = next;
      }
    }
    if (winner === undefined || winner.score <= currentScore + EPSILON) break;
    rule = winner.rule;
    currentScore = winner.score;
  }
  return Object.freeze({ rule, consideredFeatures: candidates.features });
}

function unionStrings(values: readonly (readonly string[])[]): readonly string[] {
  return Object.freeze([...new Set(values.flat())].sort());
}

function observationIds(observations: readonly VerifiedApplicabilityObservation[]): readonly string[] {
  return Object.freeze(observations.map((observation) => observation.id).sort());
}

function comparisonIds(observations: readonly VerifiedApplicabilityObservation[]): readonly string[] {
  return Object.freeze(observations.map((observation) => observation.interventionId).sort());
}

function unitDigests(observations: readonly VerifiedApplicabilityObservation[]): readonly string[] {
  return Object.freeze(
    [...new Set(observations.map((observation) => observation.experimentalUnitDigest))].sort(),
  );
}

function sourceGroups(observations: readonly VerifiedApplicabilityObservation[]): readonly string[] {
  return unionStrings(observations.map((observation) => observation.sourceGroups));
}

function ensureFeatureSchema(
  observations: readonly VerifiedApplicabilityObservation[],
  expected?: string,
): string {
  const schemas = [...new Set(observations.map((observation) => observation.featureSchemaDigest))];
  if (schemas.length !== 1) {
    throw new Error('applicability observations use different feature schemas');
  }
  const schema = schemas[0];
  if (schema === undefined) throw new Error('applicability observations have no feature schema');
  if (expected !== undefined && schema !== expected) {
    throw new Error('validation feature schema does not match discovery');
  }
  return schema;
}

export function verifyApplicabilityObservation(
  tracesInput: readonly VerifiedExperienceTrace[],
  interventionInput: MemoryInterventionInput,
  observationInput: ApplicabilityObservationInput,
): VerifiedApplicabilityObservation {
  const traces = snapshotArray(tracesInput, 'applicability trial traces');
  const input = canonicalSnapshot(observationInput, 'applicability observation input');
  assertIdentifier(input.id, 'applicability observation id');
  assertIdentifier(input.recorder, 'applicability observation recorder');
  assertDigest(input.featureSchemaDigest, 'applicability featureSchemaDigest');
  assertSafeTime(input.featureObservedAt, 'applicability featureObservedAt');
  const contextFeatures = normalizeFeatures(input.contextFeatures);
  const intervention = verifyMemoryIntervention(traces, interventionInput);
  const treatment = traces.find((trace) => trace.id === intervention.treatmentTraceId);
  const control = traces.find((trace) => trace.id === intervention.controlTraceId);
  if (treatment === undefined || control === undefined) {
    throw new Error('applicability intervention traces disappeared after verification');
  }
  const trialStartedAt = Math.min(treatment.startedAt, control.startedAt);
  const trialCompletedAt = Math.max(treatment.completedAt, control.completedAt);
  if (input.featureObservedAt > trialStartedAt) {
    throw new Error('context features must be observed before both trial arms start');
  }
  const featureSetDigest = contentDigest({
    domain: 'cl-applicability-feature-set-v1',
    featureSchemaDigest: input.featureSchemaDigest,
    contextFeatures,
  });
  const unsigned = {
    schemaVersion: APPLICABILITY_HYPOTHESES_SCHEMA_VERSION,
    id: input.id,
    scope: intervention.scope,
    memoryId: intervention.memoryId,
    interventionId: intervention.id,
    comparisonDigest: intervention.comparisonDigest,
    experimentalUnitDigest: intervention.experimentalUnitDigest,
    contextFingerprint: intervention.contextFingerprint,
    goalDigest: intervention.goalDigest,
    runtimeDigest: intervention.runtimeDigest,
    effect: intervention.effect,
    sourceGroups: intervention.sourceGroups,
    contextFeatures,
    featureSchemaDigest: input.featureSchemaDigest,
    featureSetDigest,
    featureObservedAt: input.featureObservedAt,
    trialStartedAt,
    trialCompletedAt,
    recordedAt: intervention.recordedAt,
    recorder: input.recorder,
    causalEvidence: true as const,
    procedurePromotionAuthorized: false as const,
    executionAuthorized: false as const,
  };
  const observation = canonicalSnapshot<VerifiedApplicabilityObservation>(
    {
      ...unsigned,
      observationDigest: contentDigest({
        domain: 'cl-applicability-observation-v1',
        observation: unsigned,
      }),
    },
    'verified applicability observation',
  );
  issuedObservations.add(observation as object);
  observationInterventions.set(observation as object, intervention);
  return observation;
}

export function induceApplicabilityHypothesis(
  observationsInput: readonly VerifiedApplicabilityObservation[],
  requestInput: ApplicabilityHypothesisInput,
): ApplicabilityHypothesisCandidate {
  const request = canonicalSnapshot(requestInput, 'applicability hypothesis request');
  assertIdentifier(request.id, 'applicability hypothesis id');
  assertIdentifier(request.scope, 'applicability hypothesis scope');
  assertIdentifier(request.memoryId, 'applicability hypothesis memory id');
  assertIdentifier(request.actor, 'applicability hypothesis actor');
  assertSafeTime(request.recordedAt, 'applicability hypothesis recordedAt');
  const policy = normalizeInductionPolicy(request.policy);
  const selected = selectedObservations(
    observationsInput,
    request.discoveryObservationIds,
    request.scope,
    request.memoryId,
    'discovery',
  );
  const latestObservation = Math.max(...selected.map((observation) => observation.recordedAt));
  if (request.recordedAt < latestObservation) {
    throw new Error('applicability hypothesis cannot predate its discovery observations');
  }
  const featureSchemaDigest = ensureFeatureSchema(selected);
  const independent = independentObservationSet(
    selected,
    policy.effectThreshold,
    request.scope,
    request.memoryId,
  );
  const examples = examplesFor(independent.accepted, policy.effectThreshold);
  const induced = induceRule(examples, policy);
  const discoveryMetrics = metrics(induced.rule, examples);
  const blockers: string[] = [];
  if (independent.assessment.conflictingExperimentalUnits > 0) {
    blockers.push('discovery contains opposite directions for one experimental identity');
  }
  if (independent.assessment.conflictingSourceFamilies > 0) {
    blockers.push('discovery contains opposite directions in one source family');
  }
  if (discoveryMetrics.positiveCount < policy.minPositiveExamples) {
    blockers.push(
      `needs ${policy.minPositiveExamples - discoveryMetrics.positiveCount} more positive discovery examples`,
    );
  }
  const counterexamples = discoveryMetrics.negativeCount + discoveryMetrics.neutralCount;
  if (counterexamples < policy.minCounterexamples) {
    blockers.push(`needs ${policy.minCounterexamples - counterexamples} more discovery counterexamples`);
  }
  if (discoveryMetrics.distinctContexts < policy.minDistinctContexts) {
    blockers.push(
      `needs ${policy.minDistinctContexts - discoveryMetrics.distinctContexts} more discovery contexts`,
    );
  }
  if (discoveryMetrics.contradictoryFeatureSignatureDigests.length > 0) {
    blockers.push('identical discovery feature signatures have contradictory effects');
  }
  if (discoveryMetrics.precision + EPSILON < policy.minDiscoveryPrecision) {
    blockers.push(
      `discovery precision ${discoveryMetrics.precision.toFixed(3)} is below ${policy.minDiscoveryPrecision}`,
    );
  }
  if (discoveryMetrics.recall + EPSILON < policy.minDiscoveryRecall) {
    blockers.push(
      `discovery recall ${discoveryMetrics.recall.toFixed(3)} is below ${policy.minDiscoveryRecall}`,
    );
  }
  if (
    discoveryMetrics.counterexampleActivationRate - EPSILON >
    policy.maxDiscoveryCounterexampleActivationRate
  ) {
    blockers.push(
      `discovery counterexample activation rate ${discoveryMetrics.counterexampleActivationRate.toFixed(3)} exceeds ${policy.maxDiscoveryCounterexampleActivationRate}`,
    );
  }
  if (discoveryMetrics.meanActivatedEffect + EPSILON < policy.minMeanActivatedEffect) {
    blockers.push(
      `discovery mean activated effect ${discoveryMetrics.meanActivatedEffect.toFixed(3)} is below ${policy.minMeanActivatedEffect}`,
    );
  }
  const ambiguous =
    independent.assessment.conflictingExperimentalUnits > 0 ||
    independent.assessment.conflictingSourceFamilies > 0 ||
    discoveryMetrics.contradictoryFeatureSignatureDigests.length > 0;
  const status: ApplicabilityHypothesisStatus = ambiguous
    ? 'ambiguous'
    : blockers.length === 0
      ? 'candidate'
      : 'insufficient';
  const unsigned = {
    schemaVersion: APPLICABILITY_HYPOTHESES_SCHEMA_VERSION,
    id: request.id,
    scope: request.scope,
    memoryId: request.memoryId,
    status,
    rule: induced.rule,
    featureSchemaDigest,
    discoveryObservationIds: observationIds(selected),
    acceptedDiscoveryObservationIds: observationIds(independent.accepted),
    excludedDiscoveryObservationIds: observationIds(independent.excluded),
    discoveryComparisonIds: comparisonIds(selected),
    discoveryExperimentalUnitDigests: unitDigests(selected),
    discoverySourceGroups: sourceGroups(selected),
    discoveryAssessmentDigest: independent.assessment.assessmentDigest,
    discoveryMetrics,
    consideredFeatures: induced.consideredFeatures,
    actor: request.actor,
    recordedAt: request.recordedAt,
    policy,
    blockers: Object.freeze(blockers),
    procedurePromotionAuthorized: false as const,
    executionAuthorized: false as const,
  };
  const candidate = canonicalSnapshot<ApplicabilityHypothesisCandidate>(
    {
      ...unsigned,
      candidateDigest: contentDigest({
        domain: 'cl-applicability-hypothesis-v1',
        candidate: unsigned,
      }),
    },
    'applicability hypothesis candidate',
  );
  issuedCandidates.add(candidate as object);
  return candidate;
}

export function validateApplicabilityHypothesis(
  candidate: ApplicabilityHypothesisCandidate,
  observationsInput: readonly VerifiedApplicabilityObservation[],
  requestInput: ApplicabilityValidationInput,
): VerifiedApplicabilityHypothesis {
  if (
    typeof candidate !== 'object' ||
    candidate === null ||
    !issuedCandidates.has(candidate as object)
  ) {
    throw new Error('applicability validation requires an issued hypothesis candidate');
  }
  const request = canonicalSnapshot(requestInput, 'applicability validation request');
  assertIdentifier(request.id, 'applicability validation id');
  assertIdentifier(request.candidateId, 'applicability validation candidate id');
  assertIdentifier(request.actor, 'applicability validation actor');
  assertSafeTime(request.recordedAt, 'applicability validation recordedAt');
  if (request.candidateId !== candidate.id) {
    throw new Error('applicability validation candidate id does not match');
  }
  const policy = normalizeValidationPolicy(request.policy);
  const selected = selectedObservations(
    observationsInput,
    request.validationObservationIds,
    candidate.scope,
    candidate.memoryId,
    'validation',
  );
  const latestObservation = Math.max(...selected.map((observation) => observation.recordedAt));
  if (request.recordedAt < candidate.recordedAt || request.recordedAt < latestObservation) {
    throw new Error('applicability validation time is invalid');
  }
  ensureFeatureSchema(selected, candidate.featureSchemaDigest);
  const discoveryComparisons = new Set(candidate.discoveryComparisonIds);
  const discoveryUnits = new Set(candidate.discoveryExperimentalUnitDigests);
  const discoverySources = new Set(candidate.discoverySourceGroups);
  for (const observation of selected) {
    if (discoveryComparisons.has(observation.interventionId)) {
      throw new Error('validation reuses a discovery comparison');
    }
    if (discoveryUnits.has(observation.experimentalUnitDigest)) {
      throw new Error('validation reuses a discovery experimental unit');
    }
    if (observation.sourceGroups.some((sourceGroup) => discoverySources.has(sourceGroup))) {
      throw new Error('validation reuses a discovery verifier source group');
    }
  }
  const independent = independentObservationSet(
    selected,
    candidate.policy.effectThreshold,
    candidate.scope,
    candidate.memoryId,
  );
  const examples = examplesFor(independent.accepted, candidate.policy.effectThreshold);
  const validationMetrics = metrics(candidate.rule, examples);
  const blockers: string[] = [];
  if (candidate.status !== 'candidate') {
    blockers.push(`discovery candidate status is ${candidate.status}`);
  }
  if (independent.assessment.conflictingExperimentalUnits > 0) {
    blockers.push('validation contains opposite directions for one experimental identity');
  }
  if (independent.assessment.conflictingSourceFamilies > 0) {
    blockers.push('validation contains opposite directions in one source family');
  }
  if (validationMetrics.exampleCount < policy.minValidationExamples) {
    blockers.push(
      `needs ${policy.minValidationExamples - validationMetrics.exampleCount} more validation examples`,
    );
  }
  if (validationMetrics.positiveCount < policy.minPositiveExamples) {
    blockers.push(
      `needs ${policy.minPositiveExamples - validationMetrics.positiveCount} more positive validation examples`,
    );
  }
  const counterexamples = validationMetrics.negativeCount + validationMetrics.neutralCount;
  if (counterexamples < policy.minCounterexamples) {
    blockers.push(`needs ${policy.minCounterexamples - counterexamples} more validation counterexamples`);
  }
  if (validationMetrics.distinctContexts < policy.minDistinctContexts) {
    blockers.push(
      `needs ${policy.minDistinctContexts - validationMetrics.distinctContexts} more validation contexts`,
    );
  }
  if (validationMetrics.contradictoryFeatureSignatureDigests.length > 0) {
    blockers.push('identical validation feature signatures have contradictory effects');
  }
  if (validationMetrics.precision + EPSILON < policy.minPrecision) {
    blockers.push(
      `validation precision ${validationMetrics.precision.toFixed(3)} is below ${policy.minPrecision}`,
    );
  }
  if (validationMetrics.recall + EPSILON < policy.minRecall) {
    blockers.push(
      `validation recall ${validationMetrics.recall.toFixed(3)} is below ${policy.minRecall}`,
    );
  }
  if (validationMetrics.specificity + EPSILON < policy.minSpecificity) {
    blockers.push(
      `validation specificity ${validationMetrics.specificity.toFixed(3)} is below ${policy.minSpecificity}`,
    );
  }
  if (
    validationMetrics.counterexampleActivationRate - EPSILON >
    policy.maxCounterexampleActivationRate
  ) {
    blockers.push(
      `validation counterexample activation rate ${validationMetrics.counterexampleActivationRate.toFixed(3)} exceeds ${policy.maxCounterexampleActivationRate}`,
    );
  }
  if (validationMetrics.meanActivatedEffect + EPSILON < policy.minMeanActivatedEffect) {
    blockers.push(
      `validation mean activated effect ${validationMetrics.meanActivatedEffect.toFixed(3)} is below ${policy.minMeanActivatedEffect}`,
    );
  }
  const ambiguous =
    candidate.status === 'ambiguous' ||
    independent.assessment.conflictingExperimentalUnits > 0 ||
    independent.assessment.conflictingSourceFamilies > 0 ||
    validationMetrics.contradictoryFeatureSignatureDigests.length > 0;
  const insufficient =
    candidate.status === 'insufficient' ||
    validationMetrics.exampleCount < policy.minValidationExamples ||
    validationMetrics.positiveCount < policy.minPositiveExamples ||
    counterexamples < policy.minCounterexamples ||
    validationMetrics.distinctContexts < policy.minDistinctContexts;
  const status: ApplicabilityValidationStatus = ambiguous
    ? 'ambiguous'
    : insufficient
      ? 'insufficient'
      : blockers.length === 0
        ? 'validated'
        : 'rejected';
  const unsigned = {
    schemaVersion: APPLICABILITY_HYPOTHESES_SCHEMA_VERSION,
    id: request.id,
    candidateId: candidate.id,
    candidateDigest: candidate.candidateDigest,
    scope: candidate.scope,
    memoryId: candidate.memoryId,
    status,
    rule: candidate.rule,
    featureSchemaDigest: candidate.featureSchemaDigest,
    discoveryObservationIds: candidate.discoveryObservationIds,
    acceptedDiscoveryObservationIds: candidate.acceptedDiscoveryObservationIds,
    excludedDiscoveryObservationIds: candidate.excludedDiscoveryObservationIds,
    discoveryComparisonIds: candidate.discoveryComparisonIds,
    discoveryExperimentalUnitDigests: candidate.discoveryExperimentalUnitDigests,
    discoverySourceGroups: candidate.discoverySourceGroups,
    discoveryAssessmentDigest: candidate.discoveryAssessmentDigest,
    discoveryMetrics: candidate.discoveryMetrics,
    consideredFeatures: candidate.consideredFeatures,
    validationObservationIds: observationIds(selected),
    acceptedValidationObservationIds: observationIds(independent.accepted),
    excludedValidationObservationIds: observationIds(independent.excluded),
    validationComparisonIds: comparisonIds(selected),
    validationExperimentalUnitDigests: unitDigests(selected),
    validationSourceGroups: sourceGroups(selected),
    validationAssessmentDigest: independent.assessment.assessmentDigest,
    validationMetrics,
    actor: request.actor,
    recordedAt: request.recordedAt,
    policy,
    blockers: Object.freeze(blockers),
    procedurePromotionAuthorized: false as const,
    executionAuthorized: false as const,
  };
  const validation = canonicalSnapshot<VerifiedApplicabilityHypothesis>(
    {
      ...unsigned,
      validationDigest: contentDigest({
        domain: 'cl-applicability-validation-v1',
        validation: unsigned,
      }),
    },
    'verified applicability hypothesis',
  );
  issuedValidations.add(validation as object);
  return validation;
}

export function isIssuedApplicabilityObservation(
  observation: VerifiedApplicabilityObservation,
): boolean {
  return (
    typeof observation === 'object' &&
    observation !== null &&
    issuedObservations.has(observation as object)
  );
}

export function isIssuedApplicabilityHypothesisCandidate(
  candidate: ApplicabilityHypothesisCandidate,
): boolean {
  return (
    typeof candidate === 'object' &&
    candidate !== null &&
    issuedCandidates.has(candidate as object)
  );
}

export function isIssuedVerifiedApplicabilityHypothesis(
  validation: VerifiedApplicabilityHypothesis,
): boolean {
  return (
    typeof validation === 'object' &&
    validation !== null &&
    issuedValidations.has(validation as object)
  );
}
