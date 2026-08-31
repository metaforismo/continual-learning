import {
  induceApplicabilityHypothesis as induceApplicabilityHypothesisCore,
  isIssuedApplicabilityHypothesisCandidate as isIssuedCandidateCore,
  isIssuedApplicabilityObservation as isIssuedObservationCore,
  validateApplicabilityHypothesis as validateApplicabilityHypothesisCore,
  type ApplicabilityHypothesisCandidate,
  type ApplicabilityHypothesisInput,
  type ApplicabilityValidationInput,
  type VerifiedApplicabilityHypothesis,
  type VerifiedApplicabilityObservation,
} from './applicability-hypotheses.js';
import { canonicalJson } from '../retrieval/canonical.js';

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
const MAX_INPUT_CHARACTERS = 1_000_000;

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

function snapshotObservations(
  values: readonly VerifiedApplicabilityObservation[],
  label: string,
): readonly VerifiedApplicabilityObservation[] {
  if (!Array.isArray(values)) throw new TypeError(`${label} must be an array`);
  if (values.length > MAX_OBSERVATIONS) {
    throw new RangeError(`${label} cannot exceed ${MAX_OBSERVATIONS} entries`);
  }
  const snapshot = Object.freeze(Array.from(values));
  for (const observation of snapshot) {
    if (!isIssuedObservationCore(observation)) {
      throw new Error(`${label} requires issued observation capabilities`);
    }
  }
  return snapshot;
}

function selectedForManifestCheck(
  observations: readonly VerifiedApplicabilityObservation[],
  idsInput: readonly string[],
  label: string,
): readonly VerifiedApplicabilityObservation[] {
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

/** Public induction boundary with single-read inputs and feature-manifest consistency. */
export function induceApplicabilityHypothesis(
  observationsInput: readonly VerifiedApplicabilityObservation[],
  requestInput: ApplicabilityHypothesisInput,
): ApplicabilityHypothesisCandidate {
  const observations = snapshotObservations(observationsInput, 'discovery observations');
  const request = canonicalSnapshot(requestInput, 'applicability hypothesis request');
  const selected = selectedForManifestCheck(
    observations,
    request.discoveryObservationIds,
    'discovery',
  );
  assertConsistentFeatureManifests(selected, 'discovery');
  return induceApplicabilityHypothesisCore(observations, request);
}

/** Public held-out validation boundary with the same fail-closed input contract. */
export function validateApplicabilityHypothesis(
  candidate: ApplicabilityHypothesisCandidate,
  observationsInput: readonly VerifiedApplicabilityObservation[],
  requestInput: ApplicabilityValidationInput,
): VerifiedApplicabilityHypothesis {
  if (!isIssuedCandidateCore(candidate)) {
    throw new Error('applicability validation requires an issued hypothesis candidate');
  }
  const observations = snapshotObservations(observationsInput, 'validation observations');
  const request = canonicalSnapshot(requestInput, 'applicability validation request');
  const selected = selectedForManifestCheck(
    observations,
    request.validationObservationIds,
    'validation',
  );
  assertConsistentFeatureManifests(selected, 'validation');
  return validateApplicabilityHypothesisCore(candidate, observations, request);
}
