export interface ProcedureDefinition {
  readonly id: string;
  readonly name: string;
  readonly goalSignature: string;
  readonly requiredFeatures: readonly string[];
  readonly forbiddenFeatures: readonly string[];
  readonly steps: readonly string[];
  readonly derivedFromEpisodes: readonly string[];
}

export interface ProcedureEvidence {
  readonly id: string;
  /** Prevents retries or duplicated reports from masquerading as independent evidence. */
  readonly sourceGroup: string;
  readonly contextFingerprint: string;
  readonly kind: 'application' | 'counterexample-search';
  readonly outcome: 'success' | 'failure' | 'partial' | 'unknown';
  readonly verifier: 'none' | 'model' | 'tool' | 'test' | 'human';
  readonly recordedAt: number;
  readonly notes?: string;
}

export interface PromotionPolicy {
  readonly minIndependentApplications: number;
  readonly minDistinctContexts: number;
  readonly minStronglyVerifiedSuccesses: number;
  readonly minCounterexampleSearches: number;
  readonly minWilsonLowerBound: number;
  readonly maxFailureRate: number;
}

export interface ProcedureStatistics {
  readonly independentApplications: number;
  readonly distinctContexts: number;
  readonly successes: number;
  readonly failures: number;
  readonly partials: number;
  readonly stronglyVerifiedSuccesses: number;
  readonly counterexampleSearches: number;
  readonly wilsonLowerBound: number;
  readonly failureRate: number;
}

export interface ProcedureAssessment {
  readonly stage: 'candidate' | 'validated' | 'trusted' | 'deprecated';
  readonly promotable: boolean;
  readonly statistics: ProcedureStatistics;
  readonly blockers: readonly string[];
}

export const DEFAULT_VALIDATION_POLICY: Readonly<PromotionPolicy> = Object.freeze({
  minIndependentApplications: 5,
  minDistinctContexts: 2,
  minStronglyVerifiedSuccesses: 2,
  minCounterexampleSearches: 1,
  minWilsonLowerBound: 0.45,
  maxFailureRate: 0.25,
});

export const DEFAULT_TRUST_POLICY: Readonly<PromotionPolicy> = Object.freeze({
  minIndependentApplications: 20,
  minDistinctContexts: 4,
  minStronglyVerifiedSuccesses: 8,
  minCounterexampleSearches: 3,
  minWilsonLowerBound: 0.7,
  maxFailureRate: 0.1,
});

function wilsonLowerBound(successes: number, trials: number, z = 1.96): number {
  if (trials <= 0) return 0;
  const proportion = successes / trials;
  const denominator = 1 + (z * z) / trials;
  const centre = proportion + (z * z) / (2 * trials);
  const margin =
    z * Math.sqrt((proportion * (1 - proportion) + (z * z) / (4 * trials)) / trials);
  return Math.max(0, (centre - margin) / denominator);
}

function deduplicateEvidence(evidence: readonly ProcedureEvidence[]): readonly ProcedureEvidence[] {
  const ids = new Set<string>();
  const sourceGroups = new Set<string>();
  const result: ProcedureEvidence[] = [];

  for (const item of [...evidence].sort((a, b) => a.recordedAt - b.recordedAt || a.id.localeCompare(b.id))) {
    if (ids.has(item.id)) throw new Error(`duplicate procedure evidence id: ${item.id}`);
    ids.add(item.id);

    // One application report per source group is counted. Further reports remain audit evidence,
    // but they cannot inflate independence statistics.
    if (item.kind === 'application' && sourceGroups.has(item.sourceGroup)) continue;
    if (item.kind === 'application') sourceGroups.add(item.sourceGroup);
    result.push(item);
  }

  return Object.freeze(result);
}

function statistics(evidence: readonly ProcedureEvidence[]): ProcedureStatistics {
  const independent = deduplicateEvidence(evidence);
  const applications = independent.filter((item) => item.kind === 'application');
  const successes = applications.filter((item) => item.outcome === 'success').length;
  const failures = applications.filter((item) => item.outcome === 'failure').length;
  const partials = applications.filter((item) => item.outcome === 'partial').length;
  const decidedTrials = successes + failures;
  const stronglyVerifiedSuccesses = applications.filter(
    (item) =>
      item.outcome === 'success' &&
      (item.verifier === 'tool' || item.verifier === 'test' || item.verifier === 'human'),
  ).length;

  return Object.freeze({
    independentApplications: applications.length,
    distinctContexts: new Set(applications.map((item) => item.contextFingerprint)).size,
    successes,
    failures,
    partials,
    stronglyVerifiedSuccesses,
    counterexampleSearches: independent.filter((item) => item.kind === 'counterexample-search').length,
    wilsonLowerBound: wilsonLowerBound(successes, decidedTrials),
    failureRate: decidedTrials === 0 ? 1 : failures / decidedTrials,
  });
}

function blockersFor(stats: ProcedureStatistics, policy: PromotionPolicy): readonly string[] {
  const blockers: string[] = [];
  if (stats.independentApplications < policy.minIndependentApplications) {
    blockers.push(
      `needs ${policy.minIndependentApplications - stats.independentApplications} more independent applications`,
    );
  }
  if (stats.distinctContexts < policy.minDistinctContexts) {
    blockers.push(`needs evidence from ${policy.minDistinctContexts - stats.distinctContexts} more contexts`);
  }
  if (stats.stronglyVerifiedSuccesses < policy.minStronglyVerifiedSuccesses) {
    blockers.push(
      `needs ${policy.minStronglyVerifiedSuccesses - stats.stronglyVerifiedSuccesses} more strongly verified successes`,
    );
  }
  if (stats.counterexampleSearches < policy.minCounterexampleSearches) {
    blockers.push(
      `needs ${policy.minCounterexampleSearches - stats.counterexampleSearches} more counterexample searches`,
    );
  }
  if (stats.wilsonLowerBound < policy.minWilsonLowerBound) {
    blockers.push(
      `success lower bound ${stats.wilsonLowerBound.toFixed(3)} is below ${policy.minWilsonLowerBound}`,
    );
  }
  if (stats.failureRate > policy.maxFailureRate) {
    blockers.push(`failure rate ${stats.failureRate.toFixed(3)} exceeds ${policy.maxFailureRate}`);
  }
  return Object.freeze(blockers);
}

/**
 * Assess whether a textual lesson has earned the right to become an actionable procedure.
 * Repetition alone is insufficient: evidence must be independent, cross-context, verified, and
 * accompanied by deliberate counterexample search.
 */
export function assessProcedure(
  definition: ProcedureDefinition,
  evidence: readonly ProcedureEvidence[],
  options: { readonly deprecated?: boolean } = {},
): ProcedureAssessment {
  if (definition.steps.length === 0) throw new Error('a procedure requires at least one step');
  if (new Set(definition.derivedFromEpisodes).size !== definition.derivedFromEpisodes.length) {
    throw new Error('derivedFromEpisodes must not contain duplicates');
  }

  const stats = statistics(evidence);
  if (options.deprecated === true) {
    return Object.freeze({
      stage: 'deprecated',
      promotable: false,
      statistics: stats,
      blockers: Object.freeze(['procedure was explicitly deprecated']),
    });
  }

  const trustBlockers = blockersFor(stats, DEFAULT_TRUST_POLICY);
  if (trustBlockers.length === 0) {
    return Object.freeze({
      stage: 'trusted',
      promotable: true,
      statistics: stats,
      blockers: Object.freeze([]),
    });
  }

  const validationBlockers = blockersFor(stats, DEFAULT_VALIDATION_POLICY);
  if (validationBlockers.length === 0) {
    return Object.freeze({
      stage: 'validated',
      promotable: true,
      statistics: stats,
      blockers: trustBlockers,
    });
  }

  return Object.freeze({
    stage: 'candidate',
    promotable: false,
    statistics: stats,
    blockers: validationBlockers,
  });
}

export function procedureApplies(
  procedure: ProcedureDefinition,
  observedFeatures: readonly string[],
): boolean {
  const features = new Set(observedFeatures);
  return (
    procedure.requiredFeatures.every((feature) => features.has(feature)) &&
    procedure.forbiddenFeatures.every((feature) => !features.has(feature))
  );
}
