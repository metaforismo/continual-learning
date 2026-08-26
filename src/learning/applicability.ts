import {
  assertIssuedMemoryIntervention,
  type VerifiedMemoryIntervention,
} from './experience.js';

const APPLICABILITY_SCHEMA_VERSION = 1 as const;
const MAX_COMPARISONS = 1_000;
const MAX_FEATURES_PER_COMPARISON = 64;
const MAX_CANDIDATE_FEATURES = 32;
const FEATURE_PATTERN = /^[a-z0-9][a-z0-9._:/=-]{0,127}$/;

const ISSUED_CANDIDATES = new WeakSet<object>();
const ISSUED_VALIDATIONS = new WeakSet<object>();

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

async function sha256(value: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(stableJson(value));
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return `sha256:${[...new Uint8Array(hash)].map((item) => item.toString(16).padStart(2, '0')).join('')}`;
}

function syncDigest(value: unknown): string {
  // Node is the supported runtime. Keeping the implementation synchronous avoids turning
  // deterministic induction/validation into an asynchronous state machine.
  const requireDigest = (globalThis as unknown as { __clApplicabilityDigest?: (text: string) => string })
    .__clApplicabilityDigest;
  if (requireDigest !== undefined) return requireDigest(stableJson(value));
  throw new Error('applicability digest provider was not installed');
}

export interface ApplicabilityRule {
  readonly requiredFeatures: readonly string[];
  readonly forbiddenFeatures: readonly string[];
}

export interface ApplicabilityInductionPolicy {
  readonly positiveThreshold: number;
  readonly negativeThreshold: number;
  readonly minPositiveExamples: number;
  readonly minCounterexamples: number;
  readonly minDistinctContexts: number;
  readonly maxClauses: number;
  readonly maxCandidateFeatures: number;
  readonly complexityPenalty: number;
  readonly minDiscoveryRecall: number;
}

export interface ApplicabilityValidationPolicy {
  readonly positiveThreshold: number;
  readonly negativeThreshold: number;
  readonly minValidationExamples: number;
  readonly minPositiveExamples: number;
  readonly minCounterexamples: number;
  readonly minDistinctContexts: number;
  readonly minPrecision: number;
  readonly minRecall: number;
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
  readonly counterexampleActivationRate: number;
  readonly meanActivatedEffect: number;
  readonly distinctContexts: number;
  readonly contradictoryFeatureSignatures: readonly string[];
}

export interface ApplicabilityHypothesisInput {
  readonly id: string;
  readonly memoryId: string;
  readonly discoveryComparisonIds: readonly string[];
  readonly actor: string;
  readonly recordedAt: number;
  readonly policy?: Partial<ApplicabilityInductionPolicy>;
}

export interface ApplicabilityHypothesisCandidate {
  readonly schemaVersion: typeof APPLICABILITY_SCHEMA_VERSION;
  readonly id: string;
  readonly memoryId: string;
  readonly rule: ApplicabilityRule;
  readonly discoveryComparisonIds: readonly string[];
  readonly discoveryUnitDigests: readonly string[];
  readonly discoverySourceGroups: readonly string[];
  readonly discoveryMetrics: ApplicabilityMetrics;
  readonly consideredFeatures: readonly string[];
  readonly actor: string;
  readonly recordedAt: number;
  readonly policy: ApplicabilityInductionPolicy;
  readonly blockers: readonly string[];
  readonly candidateDigest: string;
}

export interface ApplicabilityValidationInput {
  readonly id: string;
  readonly candidateId: string;
  readonly validationComparisonIds: readonly string[];
  readonly actor: string;
  readonly recordedAt: number;
  readonly policy?: Partial<ApplicabilityValidationPolicy>;
}

export interface VerifiedApplicabilityHypothesis {
  readonly schemaVersion: typeof APPLICABILITY_SCHEMA_VERSION;
  readonly id: string;
  readonly candidateId: string;
  readonly candidateDigest: string;
  readonly memoryId: string;
  readonly rule: ApplicabilityRule;
  readonly status: 'validated' | 'rejected' | 'ambiguous' | 'insufficient';
  readonly validationComparisonIds: readonly string[];
  readonly validationUnitDigests: readonly string[];
  readonly validationSourceGroups: readonly string[];
  readonly validationMetrics: ApplicabilityMetrics;
  readonly actor: string;
  readonly recordedAt: number;
  readonly policy: ApplicabilityValidationPolicy;
  readonly blockers: readonly string[];
  readonly validationDigest: string;
}

export const DEFAULT_APPLICABILITY_INDUCTION_POLICY: Readonly<ApplicabilityInductionPolicy> = Object.freeze({
  positiveThreshold: 0.1,
  negativeThreshold: 0.1,
  minPositiveExamples: 3,
  minCounterexamples: 1,
  minDistinctContexts: 2,
  maxClauses: 6,
  maxCandidateFeatures: 24,
  complexityPenalty: 0.01,
  minDiscoveryRecall: 0.67,
});

export const DEFAULT_APPLICABILITY_VALIDATION_POLICY: Readonly<ApplicabilityValidationPolicy> = Object.freeze({
  positiveThreshold: 0.1,
  negativeThreshold: 0.1,
  minValidationExamples: 5,
  minPositiveExamples: 2,
  minCounterexamples: 1,
  minDistinctContexts: 2,
  minPrecision: 0.8,
  minRecall: 0.6,
  maxCounterexampleActivationRate: 0.2,
  minMeanActivatedEffect: 0.2,
});

type EffectLabel = 'positive' | 'negative' | 'neutral';

interface Example {
  readonly comparison: VerifiedMemoryIntervention;
  readonly features: readonly string[];
  readonly featureSet: ReadonlySet<string>;
  readonly label: EffectLabel;
}

function assertIdentifier(value: string, label: string): void {
  if (typeof value !== 'string' || value.trim().length === 0 || value.length > 256) {
    throw new Error(`${label} must be a non-empty string up to 256 characters`);
  }
}

function uniqueIds(values: readonly string[], label: string): readonly string[] {
  if (!Array.isArray(values) || values.length === 0 || values.length > MAX_COMPARISONS) {
    throw new Error(`${label} requires 1..${MAX_COMPARISONS} ids`);
  }
  for (const value of values) assertIdentifier(value, label);
  if (new Set(values).size !== values.length) throw new Error(`${label} cannot contain duplicates`);
  return Object.freeze([...values]);
}

function normalizeFeatures(features: readonly string[]): readonly string[] {
  if (!Array.isArray(features) || features.length === 0 || features.length > MAX_FEATURES_PER_COMPARISON) {
    throw new Error(`contextFeatures requires 1..${MAX_FEATURES_PER_COMPARISON} values`);
  }
  const normalized = features.map((feature) => {
    if (typeof feature !== 'string') throw new Error('context feature must be a string');
    const value = feature.trim().toLowerCase();
    if (!FEATURE_PATTERN.test(value)) throw new Error(`context feature is invalid: ${feature}`);
    return value;
  });
  if (new Set(normalized).size !== normalized.length) {
    throw new Error('contextFeatures cannot contain duplicates after normalization');
  }
  return Object.freeze(normalized.sort());
}

function labelEffect(effect: number, positiveThreshold: number, negativeThreshold: number): EffectLabel {
  if (effect > positiveThreshold) return 'positive';
  if (effect < -negativeThreshold) return 'negative';
  return 'neutral';
}

function validateThresholds(positive: number, negative: number): void {
  if (
    !Number.isFinite(positive) ||
    positive < 0 ||
    positive > 1 ||
    !Number.isFinite(negative) ||
    negative < 0 ||
    negative > 1
  ) {
    throw new Error('applicability effect thresholds must be in [0, 1]');
  }
}

function inductionPolicy(
  partial: Partial<ApplicabilityInductionPolicy> | undefined,
): ApplicabilityInductionPolicy {
  const policy = Object.freeze({ ...DEFAULT_APPLICABILITY_INDUCTION_POLICY, ...(partial ?? {}) });
  validateThresholds(policy.positiveThreshold, policy.negativeThreshold);
  for (const [label, value] of [
    ['minPositiveExamples', policy.minPositiveExamples],
    ['minCounterexamples', policy.minCounterexamples],
    ['minDistinctContexts', policy.minDistinctContexts],
    ['maxClauses', policy.maxClauses],
    ['maxCandidateFeatures', policy.maxCandidateFeatures],
  ] as const) {
    if (!Number.isInteger(value) || value <= 0) throw new Error(`${label} must be a positive integer`);
  }
  if (policy.maxClauses > 16) throw new Error('maxClauses cannot exceed 16');
  if (policy.maxCandidateFeatures > MAX_CANDIDATE_FEATURES) {
    throw new Error(`maxCandidateFeatures cannot exceed ${MAX_CANDIDATE_FEATURES}`);
  }
  if (
    !Number.isFinite(policy.complexityPenalty) ||
    policy.complexityPenalty < 0 ||
    policy.complexityPenalty > 1 ||
    !Number.isFinite(policy.minDiscoveryRecall) ||
    policy.minDiscoveryRecall < 0 ||
    policy.minDiscoveryRecall > 1
  ) {
    throw new Error('induction penalty and recall thresholds must be in [0, 1]');
  }
  return policy;
}

function validationPolicy(
  partial: Partial<ApplicabilityValidationPolicy> | undefined,
): ApplicabilityValidationPolicy {
  const policy = Object.freeze({ ...DEFAULT_APPLICABILITY_VALIDATION_POLICY, ...(partial ?? {}) });
  validateThresholds(policy.positiveThreshold, policy.negativeThreshold);
  for (const [label, value] of [
    ['minValidationExamples', policy.minValidationExamples],
    ['minPositiveExamples', policy.minPositiveExamples],
    ['minCounterexamples', policy.minCounterexamples],
    ['minDistinctContexts', policy.minDistinctContexts],
  ] as const) {
    if (!Number.isInteger(value) || value <= 0) throw new Error(`${label} must be a positive integer`);
  }
  for (const [label, value] of [
    ['minPrecision', policy.minPrecision],
    ['minRecall', policy.minRecall],
    ['maxCounterexampleActivationRate', policy.maxCounterexampleActivationRate],
    ['minMeanActivatedEffect', policy.minMeanActivatedEffect],
  ] as const) {
    if (!Number.isFinite(value) || value < 0 || value > 1) {
      throw new Error(`${label} must be in [0, 1]`);
    }
  }
  return policy;
}

function selectComparisons(
  comparisons: readonly VerifiedMemoryIntervention[],
  ids: readonly string[],
  memoryId: string,
): readonly VerifiedMemoryIntervention[] {
  if (!Array.isArray(comparisons)) throw new TypeError('applicability comparisons must be an array');
  const selected: VerifiedMemoryIntervention[] = [];
  for (const id of ids) {
    const matches = comparisons.filter((comparison) => comparison.id === id);
    if (matches.length !== 1) throw new Error(`applicability comparison id is absent or duplicated: ${id}`);
    const comparison = matches[0];
    if (comparison === undefined) throw new Error(`unknown applicability comparison: ${id}`);
    assertIssuedMemoryIntervention(comparison);
    if (comparison.memoryId !== memoryId) {
      throw new Error(`comparison ${id} belongs to a different memory`);
    }
    normalizeFeatures(comparison.contextFeatures);
    selected.push(comparison);
  }
  return Object.freeze(selected);
}

function assertIndependentComparisons(
  comparisons: readonly VerifiedMemoryIntervention[],
  label: string,
): void {
  const units = new Set<string>();
  const sources = new Set<string>();
  for (const comparison of comparisons) {
    if (units.has(comparison.unitDigest)) {
      throw new Error(`${label} reuses experimental unit ${comparison.unitDigest}`);
    }
    units.add(comparison.unitDigest);
    for (const source of comparison.sourceGroups) {
      if (sources.has(source)) throw new Error(`${label} reuses verifier source group ${source}`);
      sources.add(source);
    }
  }
}

function examplesFor(
  comparisons: readonly VerifiedMemoryIntervention[],
  positiveThreshold: number,
  negativeThreshold: number,
): readonly Example[] {
  return Object.freeze(
    comparisons.map((comparison) => {
      const features = normalizeFeatures(comparison.contextFeatures);
      return Object.freeze({
        comparison,
        features,
        featureSet: new Set(features),
        label: labelEffect(comparison.effect, positiveThreshold, negativeThreshold),
      });
    }),
  );
}

export function applicabilityRuleApplies(
  rule: ApplicabilityRule,
  contextFeatures: readonly string[],
): boolean {
  const features = new Set(normalizeFeatures(contextFeatures));
  return (
    rule.requiredFeatures.every((feature) => features.has(feature)) &&
    rule.forbiddenFeatures.every((feature) => !features.has(feature))
  );
}

function contradictorySignatures(examples: readonly Example[]): readonly string[] {
  const labels = new Map<string, Set<EffectLabel>>();
  for (const example of examples) {
    const signature = example.features.join('\u0001');
    const set = labels.get(signature) ?? new Set<EffectLabel>();
    set.add(example.label);
    labels.set(signature, set);
  }
  return Object.freeze(
    [...labels.entries()]
      .filter(([, set]) => set.has('positive') && (set.has('negative') || set.has('neutral')))
      .map(([signature]) => signature)
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
    const applies =
      rule.requiredFeatures.every((feature) => example.featureSet.has(feature)) &&
      rule.forbiddenFeatures.every((feature) => !example.featureSet.has(feature));
    if (example.label === 'positive') positiveCount += 1;
    else if (example.label === 'negative') negativeCount += 1;
    else neutralCount += 1;
    if (applies) {
      activatedCount += 1;
      activatedEffect += example.comparison.effect;
      if (example.label === 'positive') truePositive += 1;
      else falsePositive += 1;
    } else if (example.label === 'positive') {
      falseNegative += 1;
    } else {
      trueNegative += 1;
    }
  }
  const counterexamples = negativeCount + neutralCount;
  const precision = truePositive + falsePositive === 0 ? 0 : truePositive / (truePositive + falsePositive);
  const recall = positiveCount === 0 ? 0 : truePositive / positiveCount;
  const specificity = counterexamples === 0 ? 0 : trueNegative / counterexamples;
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
    counterexampleActivationRate: counterexamples === 0 ? 0 : falsePositive / counterexamples,
    meanActivatedEffect: activatedCount === 0 ? 0 : activatedEffect / activatedCount,
    distinctContexts: new Set(examples.map((example) => example.comparison.contextFingerprint)).size,
    contradictoryFeatureSignatures: contradictorySignatures(examples),
  });
}

function score(rule: ApplicabilityRule, examples: readonly Example[], complexityPenalty: number): number {
  const result = metrics(rule, examples);
  return (
    (result.recall + result.specificity) / 2 -
    complexityPenalty * (rule.requiredFeatures.length + rule.forbiddenFeatures.length)
  );
}

interface Literal {
  readonly kind: 'required' | 'forbidden';
  readonly feature: string;
}

function addLiteral(rule: ApplicabilityRule, literal: Literal): ApplicabilityRule {
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

function candidateFeatures(examples: readonly Example[], maximum: number): readonly string[] {
  const positives = examples.filter((example) => example.label === 'positive');
  const counterexamples = examples.filter((example) => example.label !== 'positive');
  const all = new Set(examples.flatMap((example) => example.features));
  return Object.freeze(
    [...all]
      .map((feature) => {
        const positiveRate =
          positives.length === 0
            ? 0
            : positives.filter((example) => example.featureSet.has(feature)).length / positives.length;
        const counterRate =
          counterexamples.length === 0
            ? 0
            : counterexamples.filter((example) => example.featureSet.has(feature)).length /
              counterexamples.length;
        return { feature, discrimination: Math.abs(positiveRate - counterRate) };
      })
      .sort(
        (left, right) =>
          right.discrimination - left.discrimination || left.feature.localeCompare(right.feature),
      )
      .slice(0, maximum)
      .map((item) => item.feature),
  );
}

function induceRule(
  examples: readonly Example[],
  policy: ApplicabilityInductionPolicy,
): { readonly rule: ApplicabilityRule; readonly consideredFeatures: readonly string[] } {
  const considered = candidateFeatures(examples, policy.maxCandidateFeatures);
  let rule: ApplicabilityRule = Object.freeze({
    requiredFeatures: Object.freeze([]),
    forbiddenFeatures: Object.freeze([]),
  });
  let currentScore = score(rule, examples, policy.complexityPenalty);
  for (let step = 0; step < policy.maxClauses; step += 1) {
    let winner:
      | { readonly literal: Literal; readonly rule: ApplicabilityRule; readonly score: number; readonly metrics: ApplicabilityMetrics }
      | undefined;
    for (const feature of considered) {
      for (const kind of ['required', 'forbidden'] as const) {
        if (
          rule.requiredFeatures.includes(feature) ||
          rule.forbiddenFeatures.includes(feature)
        ) {
          continue;
        }
        const next = addLiteral(rule, { kind, feature });
        const nextMetrics = metrics(next, examples);
        if (nextMetrics.recall < policy.minDiscoveryRecall) continue;
        const nextScore = score(next, examples, policy.complexityPenalty);
        const candidate = { literal: { kind, feature }, rule: next, score: nextScore, metrics: nextMetrics };
        if (
          winner === undefined ||
          candidate.score > winner.score + 1e-12 ||
          (Math.abs(candidate.score - winner.score) <= 1e-12 &&
            (candidate.metrics.falsePositive < winner.metrics.falsePositive ||
              (candidate.metrics.falsePositive === winner.metrics.falsePositive &&
                `${candidate.literal.kind}:${candidate.literal.feature}` <
                  `${winner.literal.kind}:${winner.literal.feature}`)))
        ) {
          winner = candidate;
        }
      }
    }
    if (winner === undefined || winner.score <= currentScore + 1e-12) break;
    rule = winner.rule;
    currentScore = winner.score;
  }
  return Object.freeze({ rule, consideredFeatures: considered });
}

function sourceGroups(comparisons: readonly VerifiedMemoryIntervention[]): readonly string[] {
  return Object.freeze([...new Set(comparisons.flatMap((comparison) => comparison.sourceGroups))].sort());
}

export function induceApplicabilityHypothesis(
  comparisons: readonly VerifiedMemoryIntervention[],
  input: ApplicabilityHypothesisInput,
): ApplicabilityHypothesisCandidate {
  assertIdentifier(input.id, 'applicability hypothesis id');
  assertIdentifier(input.memoryId, 'applicability memory id');
  assertIdentifier(input.actor, 'applicability hypothesis actor');
  if (!Number.isFinite(input.recordedAt) || input.recordedAt < 0) {
    throw new Error('applicability hypothesis recordedAt is invalid');
  }
  const ids = uniqueIds(input.discoveryComparisonIds, 'discoveryComparisonIds');
  const selected = selectComparisons(comparisons, ids, input.memoryId);
  assertIndependentComparisons(selected, 'discovery set');
  const policy = inductionPolicy(input.policy);
  const examples = examplesFor(selected, policy.positiveThreshold, policy.negativeThreshold);
  const positive = examples.filter((example) => example.label === 'positive').length;
  const counterexamples = examples.length - positive;
  const contexts = new Set(selected.map((comparison) => comparison.contextFingerprint)).size;
  const blockers: string[] = [];
  if (positive < policy.minPositiveExamples) {
    blockers.push(`needs ${policy.minPositiveExamples - positive} more positive discovery examples`);
  }
  if (counterexamples < policy.minCounterexamples) {
    blockers.push(`needs ${policy.minCounterexamples - counterexamples} more discovery counterexamples`);
  }
  if (contexts < policy.minDistinctContexts) {
    blockers.push(`needs ${policy.minDistinctContexts - contexts} more discovery contexts`);
  }
  const induced = induceRule(examples, policy);
  const discoveryMetrics = metrics(induced.rule, examples);
  if (discoveryMetrics.contradictoryFeatureSignatures.length > 0) {
    blockers.push('identical context-feature signatures have contradictory discovery effects');
  }
  if (discoveryMetrics.recall < policy.minDiscoveryRecall) {
    blockers.push('induced rule does not retain the minimum discovery recall');
  }
  const unsigned = Object.freeze({
    schemaVersion: APPLICABILITY_SCHEMA_VERSION,
    id: input.id,
    memoryId: input.memoryId,
    rule: induced.rule,
    discoveryComparisonIds: ids,
    discoveryUnitDigests: Object.freeze(selected.map((comparison) => comparison.unitDigest).sort()),
    discoverySourceGroups: sourceGroups(selected),
    discoveryMetrics,
    consideredFeatures: induced.consideredFeatures,
    actor: input.actor,
    recordedAt: input.recordedAt,
    policy,
    blockers: Object.freeze(blockers),
  });
  const result = canonicalClone({
    ...unsigned,
    candidateDigest: syncDigest({ domain: 'cl-applicability-candidate-v1', candidate: unsigned }),
  });
  ISSUED_CANDIDATES.add(result as object);
  return result;
}

export function validateApplicabilityHypothesis(
  candidate: ApplicabilityHypothesisCandidate,
  comparisons: readonly VerifiedMemoryIntervention[],
  input: ApplicabilityValidationInput,
): VerifiedApplicabilityHypothesis {
  if (!ISSUED_CANDIDATES.has(candidate as object)) {
    throw new Error('applicability validation requires an issued hypothesis candidate');
  }
  assertIdentifier(input.id, 'applicability validation id');
  assertIdentifier(input.candidateId, 'applicability candidate id');
  assertIdentifier(input.actor, 'applicability validation actor');
  if (input.candidateId !== candidate.id) throw new Error('applicability validation candidate id is wrong');
  if (!Number.isFinite(input.recordedAt) || input.recordedAt < candidate.recordedAt) {
    throw new Error('applicability validation time is invalid');
  }
  const ids = uniqueIds(input.validationComparisonIds, 'validationComparisonIds');
  const selected = selectComparisons(comparisons, ids, candidate.memoryId);
  assertIndependentComparisons(selected, 'validation set');
  const discoveryUnits = new Set(candidate.discoveryUnitDigests);
  const discoverySources = new Set(candidate.discoverySourceGroups);
  for (const comparison of selected) {
    if (discoveryUnits.has(comparison.unitDigest)) {
      throw new Error('validation set overlaps a discovery experimental unit');
    }
    if (comparison.sourceGroups.some((source) => discoverySources.has(source))) {
      throw new Error('validation set overlaps a discovery verifier source group');
    }
  }
  const policy = validationPolicy(input.policy);
  const examples = examplesFor(selected, policy.positiveThreshold, policy.negativeThreshold);
  const validationMetrics = metrics(candidate.rule, examples);
  const blockers: string[] = [];
  if (candidate.blockers.length > 0) blockers.push('candidate did not clear its discovery gate');
  if (validationMetrics.exampleCount < policy.minValidationExamples) {
    blockers.push(`needs ${policy.minValidationExamples - validationMetrics.exampleCount} more validation examples`);
  }
  if (validationMetrics.positiveCount < policy.minPositiveExamples) {
    blockers.push(`needs ${policy.minPositiveExamples - validationMetrics.positiveCount} more positive validation examples`);
  }
  const counterexamples = validationMetrics.negativeCount + validationMetrics.neutralCount;
  if (counterexamples < policy.minCounterexamples) {
    blockers.push(`needs ${policy.minCounterexamples - counterexamples} more validation counterexamples`);
  }
  if (validationMetrics.distinctContexts < policy.minDistinctContexts) {
    blockers.push(`needs ${policy.minDistinctContexts - validationMetrics.distinctContexts} more validation contexts`);
  }
  if (validationMetrics.precision < policy.minPrecision) {
    blockers.push(`precision ${validationMetrics.precision.toFixed(3)} is below ${policy.minPrecision}`);
  }
  if (validationMetrics.recall < policy.minRecall) {
    blockers.push(`recall ${validationMetrics.recall.toFixed(3)} is below ${policy.minRecall}`);
  }
  if (validationMetrics.counterexampleActivationRate > policy.maxCounterexampleActivationRate) {
    blockers.push(
      `counterexample activation rate ${validationMetrics.counterexampleActivationRate.toFixed(3)} exceeds ${policy.maxCounterexampleActivationRate}`,
    );
  }
  if (validationMetrics.meanActivatedEffect < policy.minMeanActivatedEffect) {
    blockers.push(
      `mean activated effect ${validationMetrics.meanActivatedEffect.toFixed(3)} is below ${policy.minMeanActivatedEffect}`,
    );
  }

  let status: VerifiedApplicabilityHypothesis['status'];
  if (
    validationMetrics.contradictoryFeatureSignatures.length > 0 ||
    candidate.discoveryMetrics.contradictoryFeatureSignatures.length > 0
  ) {
    status = 'ambiguous';
  } else if (
    validationMetrics.exampleCount < policy.minValidationExamples ||
    validationMetrics.positiveCount < policy.minPositiveExamples ||
    counterexamples < policy.minCounterexamples ||
    validationMetrics.distinctContexts < policy.minDistinctContexts
  ) {
    status = 'insufficient';
  } else if (blockers.length === 0) {
    status = 'validated';
  } else {
    status = 'rejected';
  }

  const unsigned = Object.freeze({
    schemaVersion: APPLICABILITY_SCHEMA_VERSION,
    id: input.id,
    candidateId: candidate.id,
    candidateDigest: candidate.candidateDigest,
    memoryId: candidate.memoryId,
    rule: candidate.rule,
    status,
    validationComparisonIds: ids,
    validationUnitDigests: Object.freeze(selected.map((comparison) => comparison.unitDigest).sort()),
    validationSourceGroups: sourceGroups(selected),
    validationMetrics,
    actor: input.actor,
    recordedAt: input.recordedAt,
    policy,
    blockers: Object.freeze(blockers),
  });
  const result = canonicalClone({
    ...unsigned,
    validationDigest: syncDigest({ domain: 'cl-applicability-validation-v1', validation: unsigned }),
  });
  ISSUED_VALIDATIONS.add(result as object);
  return result;
}

export function assertIssuedApplicabilityHypothesis(
  value: unknown,
): asserts value is VerifiedApplicabilityHypothesis {
  if (typeof value !== 'object' || value === null || !ISSUED_VALIDATIONS.has(value)) {
    throw new Error('operation requires an issued applicability hypothesis');
  }
}
