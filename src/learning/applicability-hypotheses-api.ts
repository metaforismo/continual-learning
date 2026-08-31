import {
  induceApplicabilityHypothesis as induceApplicabilityHypothesisCore,
  validateApplicabilityHypothesis as validateApplicabilityHypothesisCore,
  type ApplicabilityHypothesisCandidate,
  type ApplicabilityHypothesisInput,
  type ApplicabilityValidationInput,
  type VerifiedApplicabilityHypothesis,
  type VerifiedApplicabilityObservation,
} from './applicability-hypotheses.js';

export {
  APPLICABILITY_HYPOTHESES_SCHEMA_VERSION,
  DEFAULT_APPLICABILITY_INDUCTION_POLICY,
  DEFAULT_APPLICABILITY_VALIDATION_POLICY,
  applicabilityRuleApplies,
  isIssuedApplicabilityHypothesisCandidate,
  isIssuedApplicabilityObservation,
  isIssuedVerifiedApplicabilityHypothesis,
  verifyApplicabilityObservation,
} from './applicability-hypotheses.js';

export type {
  ApplicabilityHypothesisCandidate,
  ApplicabilityHypothesisInput,
  ApplicabilityHypothesisStatus,
  ApplicabilityInductionPolicy,
  ApplicabilityMetrics,
  ApplicabilityObservationInput,
  ApplicabilityRule,
  ApplicabilityValidationInput,
  ApplicabilityValidationPolicy,
  ApplicabilityValidationStatus,
  VerifiedApplicabilityHypothesis,
  VerifiedApplicabilityObservation,
} from './applicability-hypotheses.js';

const MAX_OBSERVATIONS = 4_096;

function snapshotArray<T>(values: readonly T[], label: string): readonly T[] {
  if (!Array.isArray(values)) throw new TypeError(`${label} must be an array`);
  if (values.length > MAX_OBSERVATIONS) {
    throw new RangeError(`${label} cannot exceed ${MAX_OBSERVATIONS} entries`);
  }
  return Object.freeze(Array.from(values));
}

function selectedForManifestCheck(
  observationsInput: readonly VerifiedApplicabilityObservation[],
  idsInput: readonly string[],
  label: string,
): readonly VerifiedApplicabilityObservation[] {
  const observations = snapshotArray(observationsInput, `${label} observations`);
  if (!Array.isArray(idsInput)) throw new TypeError(`${label} observation ids must be an array`);
  const ids = Object.freeze(Array.from(idsInput));
  const selected: VerifiedApplicabilityObservation[] = [];
  for (const id of ids) {
    const matches = observations.filter((observation) => observation.id === id);
    if (matches.length !== 1) {
      throw new Error(`${label} observation id is absent or duplicated: ${String(id)}`);
    }
    const observation = matches[0];
    if (observation === undefined) {
      throw new Error(`${label} observation disappeared: ${String(id)}`);
    }
    selected.push(observation);
  }
  return Object.freeze(selected);
}

function assertConsistentFeatureManifests(
  observations: readonly VerifiedApplicabilityObservation[],
  label: string,
): void {
  const byExperimentalUnit = new Map<string, string>();
  const byContextFingerprint = new Map<string, string>();
  for (const observation of observations) {
    const unitManifest = byExperimentalUnit.get(observation.experimentalUnitDigest);
    if (unitManifest !== undefined && unitManifest !== observation.featureSetDigest) {
      throw new Error(`${label} assigns different feature manifests to one experimental unit`);
    }
    byExperimentalUnit.set(observation.experimentalUnitDigest, observation.featureSetDigest);

    const contextManifest = byContextFingerprint.get(observation.contextFingerprint);
    if (contextManifest !== undefined && contextManifest !== observation.featureSetDigest) {
      throw new Error(`${label} assigns different feature manifests to one context fingerprint`);
    }
    byContextFingerprint.set(observation.contextFingerprint, observation.featureSetDigest);
  }
}

/** Public induction boundary with a fail-closed feature-manifest consistency gate. */
export function induceApplicabilityHypothesis(
  observationsInput: readonly VerifiedApplicabilityObservation[],
  requestInput: ApplicabilityHypothesisInput,
): ApplicabilityHypothesisCandidate {
  const selected = selectedForManifestCheck(
    observationsInput,
    requestInput.discoveryObservationIds,
    'discovery',
  );
  assertConsistentFeatureManifests(selected, 'discovery');
  return induceApplicabilityHypothesisCore(observationsInput, requestInput);
}

/** Public held-out validation boundary with the same manifest consistency gate. */
export function validateApplicabilityHypothesis(
  candidate: ApplicabilityHypothesisCandidate,
  observationsInput: readonly VerifiedApplicabilityObservation[],
  requestInput: ApplicabilityValidationInput,
): VerifiedApplicabilityHypothesis {
  const selected = selectedForManifestCheck(
    observationsInput,
    requestInput.validationObservationIds,
    'validation',
  );
  assertConsistentFeatureManifests(selected, 'validation');
  return validateApplicabilityHypothesisCore(candidate, observationsInput, requestInput);
}
