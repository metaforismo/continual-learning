import {
  DEFAULT_MEMORY_UTILITY_POLICY,
  EXPERIENCE_ATTRIBUTION_SCHEMA_VERSION,
  assessMemoryUtility as assessMemoryUtilityCore,
  recordExperienceTrace,
  verifyMemoryIntervention as verifyMemoryInterventionCore,
  type AttributionEvidenceReference,
  type AttributionRuntimeIdentity,
  type ExperienceTraceInput,
  type ExperienceUnit,
  type MemoryInterventionInput,
  type MemoryUseCaptureMode,
  type MemoryUseInput,
  type MemoryUseStage,
  type MemoryUtilityAssessment as CoreMemoryUtilityAssessment,
  type MemoryUtilityAssessmentRequest,
  type MemoryUtilityClassification,
  type MemoryUtilityPolicy,
  type OutcomeVerifier,
  type VerifiedExperienceTrace,
  type VerifiedMemoryIntervention as CoreVerifiedMemoryIntervention,
  type VerifiedMemoryUse,
} from './experience-attribution.js';
import { canonicalJson, contentDigest } from '../retrieval/canonical.js';

const MAX_ASSESSMENT_INTERVENTIONS = 4_096;
const issuedInterventions = new WeakSet<object>();
const issuedAssessments = new WeakSet<object>();

export {
  DEFAULT_MEMORY_UTILITY_POLICY,
  EXPERIENCE_ATTRIBUTION_SCHEMA_VERSION,
  recordExperienceTrace,
};

export type {
  AttributionEvidenceReference,
  AttributionRuntimeIdentity,
  ExperienceTraceInput,
  ExperienceUnit,
  MemoryInterventionInput,
  MemoryUseCaptureMode,
  MemoryUseInput,
  MemoryUseStage,
  MemoryUtilityAssessmentRequest,
  MemoryUtilityClassification,
  MemoryUtilityPolicy,
  OutcomeVerifier,
  VerifiedExperienceTrace,
  VerifiedMemoryUse,
};

export type VerifiedMemoryIntervention = Omit<
  CoreVerifiedMemoryIntervention,
  'independenceDigest' | 'comparisonDigest'
> & {
  /** Exact matched experimental identity, including context, goal, runtime, and canonical prefix. */
  readonly experimentalUnitDigest: string;
  readonly independenceDigest: string;
  readonly comparisonDigest: string;
};

export type MemoryUtilityAssessment = Omit<
  CoreMemoryUtilityAssessment,
  'assessmentDigest'
> & {
  readonly conflictingSourceFamilies: number;
  readonly conflictingSourceFamilyDigests: readonly string[];
  readonly assessmentDigest: string;
};

function canonicalSnapshot<T>(value: T): T {
  return Object.freeze(JSON.parse(canonicalJson(value)) as T);
}

function snapshotArray<T>(value: readonly T[], label: string): readonly T[] {
  if (!Array.isArray(value)) throw new TypeError(`${label} must be an array`);
  return Object.freeze(Array.from(value));
}

function direction(effect: number, neutralThreshold: number): -1 | 0 | 1 {
  if (effect > neutralThreshold) return 1;
  if (effect < -neutralThreshold) return -1;
  return 0;
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

function conservativeRepresentative(
  comparisons: readonly VerifiedMemoryIntervention[],
): VerifiedMemoryIntervention {
  const selected = [...comparisons].sort(
    (left, right) =>
      Math.abs(left.effect) - Math.abs(right.effect) ||
      left.comparisonDigest.localeCompare(right.comparisonDigest),
  )[0];
  if (selected === undefined) throw new Error('attribution component cannot be empty');
  return selected;
}

function hasOppositeDirections(
  comparisons: readonly VerifiedMemoryIntervention[],
  neutralThreshold: number,
): boolean {
  const directions = new Set(
    comparisons.map((comparison) => direction(comparison.effect, neutralThreshold)),
  );
  return directions.has(1) && directions.has(-1);
}

function sourceFamilyComponents(
  comparisons: readonly VerifiedMemoryIntervention[],
): readonly (readonly VerifiedMemoryIntervention[])[] {
  const parent = comparisons.map((_, index) => index);

  const find = (index: number): number => {
    let root = index;
    while (parent[root] !== root) root = parent[root] as number;
    let cursor = index;
    while (parent[cursor] !== cursor) {
      const next = parent[cursor] as number;
      parent[cursor] = root;
      cursor = next;
    }
    return root;
  };

  const union = (left: number, right: number): void => {
    const leftRoot = find(left);
    const rightRoot = find(right);
    if (leftRoot === rightRoot) return;
    if (leftRoot < rightRoot) parent[rightRoot] = leftRoot;
    else parent[leftRoot] = rightRoot;
  };

  const firstBySourceGroup = new Map<string, number>();
  for (let index = 0; index < comparisons.length; index += 1) {
    const comparison = comparisons[index];
    if (comparison === undefined) continue;
    for (const sourceGroup of comparison.sourceGroups) {
      const first = firstBySourceGroup.get(sourceGroup);
      if (first === undefined) firstBySourceGroup.set(sourceGroup, index);
      else union(first, index);
    }
  }

  const components = new Map<number, VerifiedMemoryIntervention[]>();
  for (let index = 0; index < comparisons.length; index += 1) {
    const comparison = comparisons[index];
    if (comparison === undefined) continue;
    const root = find(index);
    const component = components.get(root) ?? [];
    component.push(comparison);
    components.set(root, component);
  }

  return Object.freeze(
    [...components.values()]
      .map((component) =>
        Object.freeze(
          component.sort((left, right) =>
            left.comparisonDigest.localeCompare(right.comparisonDigest),
          ),
        ),
      )
      .sort((left, right) =>
        (left[0]?.comparisonDigest ?? '').localeCompare(right[0]?.comparisonDigest ?? ''),
      ),
  );
}

function assertIssuedIntervention(
  intervention: VerifiedMemoryIntervention,
): void {
  if (
    typeof intervention !== 'object' ||
    intervention === null ||
    !issuedInterventions.has(intervention as object)
  ) {
    throw new Error('memory utility requires an issued paired intervention capability');
  }
}

/**
 * Strengthen the core pair verifier with an experimental-unit identity that includes every matched
 * context relevant to causal interpretation. The returned object is a new process-local capability.
 */
export function verifyMemoryIntervention(
  tracesInput: readonly VerifiedExperienceTrace[],
  input: MemoryInterventionInput,
): VerifiedMemoryIntervention {
  const traces = snapshotArray(tracesInput, 'paired intervention traces');
  const core = verifyMemoryInterventionCore(traces, input);
  const treatment = traces.find((trace) => trace.id === core.treatmentTraceId);
  if (treatment === undefined) {
    throw new Error('paired intervention treatment trace disappeared after verification');
  }

  const experimentalUnitDigest = contentDigest({
    domain: 'cl-memory-intervention-unit-v1',
    scope: core.scope,
    memoryId: core.memoryId,
    taskId: core.taskId,
    unitDigest: core.unitDigest,
    contextFingerprint: core.contextFingerprint,
    goalDigest: core.goalDigest,
    runtimeDigest: core.runtimeDigest,
    canonicalFingerprint: treatment.canonicalFingerprint,
    verifier: treatment.verifier,
  });
  const {
    independenceDigest: _discardedIndependence,
    comparisonDigest: _discardedComparison,
    ...base
  } = core;
  const independenceDigest = contentDigest({
    domain: 'cl-memory-intervention-independence-v2',
    experimentalUnitDigest,
    sourceGroups: core.sourceGroups,
  });
  const unsigned = {
    ...base,
    experimentalUnitDigest,
    independenceDigest,
  };
  const comparison = canonicalSnapshot({
    ...unsigned,
    comparisonDigest: contentDigest({
      domain: 'cl-memory-intervention-v2',
      comparison: unsigned,
    }),
  }) as VerifiedMemoryIntervention;
  issuedInterventions.add(comparison as object);
  return comparison;
}

/**
 * Assess memory utility without making independence depend on caller order.
 *
 * - one experimental identity contributes at most one conservative observation;
 * - transitive source-group overlap becomes one source-family component;
 * - opposite directions inside a unit or source-family component remain explicit conflicts;
 * - same-direction correlated observations choose the effect closest to zero, with a digest tie-break.
 */
export function assessMemoryUtility(
  requestInput: MemoryUtilityAssessmentRequest,
  tracesInput: readonly VerifiedExperienceTrace[],
  interventionsInput: readonly VerifiedMemoryIntervention[],
  policyInput: MemoryUtilityPolicy = DEFAULT_MEMORY_UTILITY_POLICY,
): MemoryUtilityAssessment {
  const traces = snapshotArray(tracesInput, 'memory utility traces');
  const interventions = snapshotArray(interventionsInput, 'memory utility interventions');
  if (interventions.length > MAX_ASSESSMENT_INTERVENTIONS) {
    throw new RangeError(
      `memory utility cannot inspect more than ${MAX_ASSESSMENT_INTERVENTIONS} interventions`,
    );
  }
  const request = canonicalSnapshot(requestInput);
  const policy = canonicalSnapshot(policyInput);

  // Reuse the core boundary to validate request, policy, trace issuance, duplicate trace ids, bounds,
  // and diagnostic correlation. Interventions are assessed below under the stronger v2 contract.
  const correlation = assessMemoryUtilityCore(request, traces, [], policy);

  const interventionIds = new Set<string>();
  for (const intervention of interventions) {
    assertIssuedIntervention(intervention);
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
    .sort((left, right) => left.comparisonDigest.localeCompare(right.comparisonDigest));

  const excluded = new Map<string, VerifiedMemoryIntervention>();
  const conflictingUnitDigests: string[] = [];
  const byExperimentalUnit = new Map<string, VerifiedMemoryIntervention[]>();
  for (const comparison of candidates) {
    const group = byExperimentalUnit.get(comparison.experimentalUnitDigest) ?? [];
    group.push(comparison);
    byExperimentalUnit.set(comparison.experimentalUnitDigest, group);
  }

  const unitRepresentatives: VerifiedMemoryIntervention[] = [];
  for (const [unitDigest, group] of [...byExperimentalUnit].sort(([left], [right]) =>
    left.localeCompare(right),
  )) {
    if (hasOppositeDirections(group, policy.neutralThreshold)) {
      conflictingUnitDigests.push(unitDigest);
      for (const comparison of group) excluded.set(comparison.id, comparison);
      continue;
    }
    const representative = conservativeRepresentative(group);
    unitRepresentatives.push(representative);
    for (const comparison of group) {
      if (comparison !== representative) excluded.set(comparison.id, comparison);
    }
  }

  const accepted: VerifiedMemoryIntervention[] = [];
  const conflictingSourceFamilyDigests: string[] = [];
  for (const component of sourceFamilyComponents(unitRepresentatives)) {
    if (hasOppositeDirections(component, policy.neutralThreshold)) {
      const componentDigest = contentDigest({
        domain: 'cl-memory-source-family-conflict-v1',
        comparisonDigests: component.map((comparison) => comparison.comparisonDigest),
        sourceGroups: [...new Set(component.flatMap((comparison) => comparison.sourceGroups))].sort(),
      });
      conflictingSourceFamilyDigests.push(componentDigest);
      for (const comparison of component) excluded.set(comparison.id, comparison);
      continue;
    }
    const representative = conservativeRepresentative(component);
    accepted.push(representative);
    for (const comparison of component) {
      if (comparison !== representative) excluded.set(comparison.id, comparison);
    }
  }
  accepted.sort((left, right) => left.comparisonDigest.localeCompare(right.comparisonDigest));

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
    blockers.push('the same experimental identity produced opposite effect directions');
  }
  if (conflictingSourceFamilyDigests.length > 0) {
    blockers.push('one transitive source family produced opposite effect directions');
  }

  let classification: MemoryUtilityClassification = 'insufficient';
  if (
    conflictingUnitDigests.length > 0 ||
    conflictingSourceFamilyDigests.length > 0
  ) {
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

  const excludedComparisons = [...excluded.values()].sort((left, right) =>
    left.comparisonDigest.localeCompare(right.comparisonDigest),
  );
  const unsigned = {
    schemaVersion: EXPERIENCE_ATTRIBUTION_SCHEMA_VERSION,
    scope: request.scope,
    memoryId: request.memoryId,
    classification,
    causalBasis: accepted.length > 0 ? ('paired-intervention' as const) : ('none' as const),
    independentPairs: accepted.length,
    excludedCorrelatedPairs: excludedComparisons.length,
    conflictingExperimentalUnits: conflictingUnitDigests.length,
    conflictingSourceFamilies: conflictingSourceFamilyDigests.length,
    distinctContexts,
    positivePairs: positive.length,
    negativePairs: negative.length,
    neutralPairs: neutral,
    meanEffect,
    positiveRate,
    negativeRate,
    positiveWilsonLowerBound: positiveWilson,
    negativeWilsonLowerBound: negativeWilson,
    correlatedAppliedSuccesses: correlation.correlatedAppliedSuccesses,
    runtimeInstrumentedAppliedSuccesses: correlation.runtimeInstrumentedAppliedSuccesses,
    comparisonIds: Object.freeze(accepted.map((comparison) => comparison.id)),
    excludedComparisonIds: Object.freeze(
      excludedComparisons.map((comparison) => comparison.id),
    ),
    conflictingUnitDigests: Object.freeze([...conflictingUnitDigests].sort()),
    conflictingSourceFamilyDigests: Object.freeze(
      [...conflictingSourceFamilyDigests].sort(),
    ),
    correlatedTraceIds: correlation.correlatedTraceIds,
    blockers: Object.freeze(blockers),
    procedurePromotionAuthorized: false,
    executionAuthorized: false,
  } as const;
  const assessment = canonicalSnapshot({
    ...unsigned,
    assessmentDigest: contentDigest({
      domain: 'cl-memory-utility-assessment-v2',
      assessment: unsigned,
    }),
  }) as MemoryUtilityAssessment;
  issuedAssessments.add(assessment as object);
  return assessment;
}

export function isIssuedMemoryUtilityAssessment(
  assessment: MemoryUtilityAssessment,
): boolean {
  return (
    typeof assessment === 'object' &&
    assessment !== null &&
    issuedAssessments.has(assessment as object)
  );
}
