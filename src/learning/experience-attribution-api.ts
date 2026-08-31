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
  /** Conservative cross-pair identity for one task instance in one context. */
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

interface UnitObservation {
  readonly representative: VerifiedMemoryIntervention;
  /** Union of every verifier origin observed for this experimental identity. */
  readonly sourceGroups: readonly string[];
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

function canonicalSnapshot<T>(value: T): T {
  return deepFreeze(JSON.parse(canonicalJson(value)) as T);
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
  observations: readonly UnitObservation[],
): readonly (readonly UnitObservation[])[] {
  const parent = observations.map((_, index) => index);

  const parentAt = (index: number): number => {
    const value = parent[index];
    if (value === undefined) {
      throw new Error('source-family union-find index is out of bounds');
    }
    return value;
  };

  const setParent = (index: number, value: number): void => {
    if (index < 0 || index >= parent.length) {
      throw new Error('source-family union-find write is out of bounds');
    }
    parent[index] = value;
  };

  const find = (index: number): number => {
    let root = index;
    while (parentAt(root) !== root) root = parentAt(root);
    let cursor = index;
    while (parentAt(cursor) !== cursor) {
      const next = parentAt(cursor);
      setParent(cursor, root);
      cursor = next;
    }
    return root;
  };

  const union = (left: number, right: number): void => {
    const leftRoot = find(left);
    const rightRoot = find(right);
    if (leftRoot === rightRoot) return;
    if (leftRoot < rightRoot) setParent(rightRoot, leftRoot);
    else setParent(leftRoot, rightRoot);
  };

  const firstBySourceGroup = new Map<string, number>();
  for (let index = 0; index < observations.length; index += 1) {
    const observation = observations[index];
    if (observation === undefined) continue;
    for (const sourceGroup of observation.sourceGroups) {
      const first = firstBySourceGroup.get(sourceGroup);
      if (first === undefined) firstBySourceGroup.set(sourceGroup, index);
      else union(first, index);
    }
  }

  const components = new Map<number, UnitObservation[]>();
  for (let index = 0; index < observations.length; index += 1) {
    const observation = observations[index];
    if (observation === undefined) continue;
    const root = find(index);
    const component = components.get(root) ?? [];
    component.push(observation);
    components.set(root, component);
  }

  return Object.freeze(
    [...components.values()]
      .map((component) =>
        Object.freeze(
          component.sort((left, right) =>
            left.representative.comparisonDigest.localeCompare(
              right.representative.comparisonDigest,
            ),
          ),
        ),
      )
      .sort((left, right) =>
        (left[0]?.representative.comparisonDigest ?? '').localeCompare(
          right[0]?.representative.comparisonDigest ?? '',
        ),
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
 * Strengthen the core pair verifier with a conservative cross-pair experimental identity.
 *
 * Pair validity is still bound to exact task/runtime/verifier/canonical identities by the core
 * verifier. For evidence independence, repeated trials of one raw task instance in the same
 * context and goal remain one unit even if the ledger, run id, or verifier receipt later changes.
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
    unitDigest: core.unitDigest,
    contextFingerprint: core.contextFingerprint,
    goalDigest: core.goalDigest,
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
  const comparisonDigest = contentDigest({
    domain: 'cl-memory-intervention-v2',
    comparison: {
      ...base,
      experimentalUnitDigest,
      independenceDigest,
    },
  });
  const comparison = canonicalSnapshot<VerifiedMemoryIntervention>({
    ...base,
    experimentalUnitDigest,
    independenceDigest,
    comparisonDigest,
  });
  issuedInterventions.add(comparison as object);
  return comparison;
}

/**
 * Assess memory utility without making independence depend on caller order.
 *
 * - one experimental identity contributes at most one conservative observation;
 * - duplicate observations preserve the union of their verifier-source lineage;
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

  const unitObservations: UnitObservation[] = [];
  for (const [unitDigest, group] of [...byExperimentalUnit].sort(([left], [right]) =>
    left.localeCompare(right),
  )) {
    if (hasOppositeDirections(group, policy.neutralThreshold)) {
      conflictingUnitDigests.push(unitDigest);
      for (const comparison of group) excluded.set(comparison.id, comparison);
      continue;
    }
    const representative = conservativeRepresentative(group);
    unitObservations.push(
      Object.freeze({
        representative,
        sourceGroups: Object.freeze(
          [...new Set(group.flatMap((comparison) => comparison.sourceGroups))].sort(),
        ),
      }),
    );
    for (const comparison of group) {
      if (comparison !== representative) excluded.set(comparison.id, comparison);
    }
  }

  const accepted: VerifiedMemoryIntervention[] = [];
  const conflictingSourceFamilyDigests: string[] = [];
  for (const component of sourceFamilyComponents(unitObservations)) {
    const componentComparisons = component.map((observation) => observation.representative);
    if (hasOppositeDirections(componentComparisons, policy.neutralThreshold)) {
      const componentDigest = contentDigest({
        domain: 'cl-memory-source-family-conflict-v1',
        comparisonDigests: componentComparisons.map(
          (comparison) => comparison.comparisonDigest,
        ),
        sourceGroups: [
          ...new Set(component.flatMap((observation) => observation.sourceGroups)),
        ].sort(),
      });
      conflictingSourceFamilyDigests.push(componentDigest);
      for (const comparison of componentComparisons) excluded.set(comparison.id, comparison);
      continue;
    }
    const representative = conservativeRepresentative(componentComparisons);
    accepted.push(representative);
    for (const comparison of componentComparisons) {
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
  const causalBasis: MemoryUtilityAssessment['causalBasis'] =
    accepted.length > 0 ? 'paired-intervention' : 'none';
  const comparisonIds = Object.freeze(accepted.map((comparison) => comparison.id));
  const excludedComparisonIds = Object.freeze(
    excludedComparisons.map((comparison) => comparison.id),
  );
  const sortedConflictingUnits = Object.freeze([...conflictingUnitDigests].sort());
  const sortedConflictingFamilies = Object.freeze(
    [...conflictingSourceFamilyDigests].sort(),
  );
  const frozenBlockers = Object.freeze(blockers);
  const unsigned = {
    schemaVersion: EXPERIENCE_ATTRIBUTION_SCHEMA_VERSION,
    scope: request.scope,
    memoryId: request.memoryId,
    classification,
    causalBasis,
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
    comparisonIds,
    excludedComparisonIds,
    conflictingUnitDigests: sortedConflictingUnits,
    conflictingSourceFamilyDigests: sortedConflictingFamilies,
    correlatedTraceIds: correlation.correlatedTraceIds,
    blockers: frozenBlockers,
    procedurePromotionAuthorized: false as const,
    executionAuthorized: false as const,
  };
  const assessmentDigest = contentDigest({
    domain: 'cl-memory-utility-assessment-v2',
    assessment: unsigned,
  });
  const assessment = canonicalSnapshot<MemoryUtilityAssessment>({
    ...unsigned,
    assessmentDigest,
  });
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
