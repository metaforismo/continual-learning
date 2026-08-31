import {
  induceApplicabilityHypothesis as induceApplicabilityHypothesisCore,
  isIssuedApplicabilityHypothesisCandidate as isIssuedCandidateCore,
  isIssuedApplicabilityObservation as isIssuedObservationCore,
  validateApplicabilityHypothesis as validateApplicabilityHypothesisCore,
  verifyApplicabilityObservation as verifyApplicabilityObservationCore,
  type ApplicabilityHypothesisCandidate,
  type ApplicabilityHypothesisInput,
  type ApplicabilityObservationInput,
  type ApplicabilityValidationInput,
  type VerifiedApplicabilityHypothesis,
  type VerifiedApplicabilityObservation,
} from './applicability-hypotheses.js';
import type {
  MemoryInterventionInput,
  VerifiedExperienceTrace,
} from './experience-attribution-api.js';
import { canonicalJson } from '../retrieval/canonical.js';

export {
  APPLICABILITY_HYPOTHESES_SCHEMA_VERSION,
  DEFAULT_APPLICABILITY_INDUCTION_POLICY,
  DEFAULT_APPLICABILITY_VALIDATION_POLICY,
  applicabilityRuleApplies,
  isIssuedApplicabilityHypothesisCandidate,
  isIssuedApplicabilityObservation,
  isIssuedVerifiedApplicabilityHypothesis,
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

const MAX_IDENTIFIERS = 4_096;
const MAX_INPUT_CHARACTERS = 1_000_000;
const MAX_IDENTIFIER_CHARACTERS = 512;

interface IssuedIdentity<T> {
  readonly digest: string;
  readonly value: T;
}

const issuedObservationsById = new Map<
  string,
  IssuedIdentity<VerifiedApplicabilityObservation>
>();
const issuedCandidatesById = new Map<
  string,
  IssuedIdentity<ApplicabilityHypothesisCandidate>
>();
const issuedValidationsById = new Map<
  string,
  IssuedIdentity<VerifiedApplicabilityHypothesis>
>();

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

function snapshotArray<T>(values: readonly T[], label: string): readonly T[] {
  if (!Array.isArray(values)) throw new TypeError(`${label} must be an array`);
  if (values.length > MAX_IDENTIFIERS) {
    throw new RangeError(`${label} cannot exceed ${MAX_IDENTIFIERS} entries`);
  }
  return Object.freeze(Array.from(values));
}

function snapshotObservations(
  values: readonly VerifiedApplicabilityObservation[],
  label: string,
): readonly VerifiedApplicabilityObservation[] {
  const snapshot = snapshotArray(values, label);
  for (const observation of snapshot) {
    if (!isIssuedObservationCore(observation)) {
      throw new Error(`${label} requires issued observation capabilities`);
    }
  }
  return snapshot;
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

function bindIdentity<T>(
  id: string,
  digest: string,
  value: T,
  registry: Map<string, IssuedIdentity<T>>,
  label: string,
): T {
  const previous = registry.get(id);
  if (previous === undefined) {
    registry.set(id, Object.freeze({ digest, value }));
    return value;
  }
  if (previous.digest !== digest) {
    throw new Error(`${label} conflicts with an already issued identity: ${id}`);
  }
  return previous.value;
}

function selectedForManifestCheck(
  observations: readonly VerifiedApplicabilityObservation[],
  idsInput: readonly string[],
  label: string,
): readonly VerifiedApplicabilityObservation[] {
  const ids = snapshotArray(idsInput, `${label} observation ids`);
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

/** Public observation boundary with single-read inputs and conflict-safe idempotency. */
export function verifyApplicabilityObservation(
  tracesInput: readonly VerifiedExperienceTrace[],
  interventionInput: MemoryInterventionInput,
  observationInput: ApplicabilityObservationInput,
): VerifiedApplicabilityObservation {
  const traces = snapshotArray(tracesInput, 'applicability trial traces');
  const intervention = canonicalSnapshot(interventionInput, 'applicability intervention input');
  const input = canonicalSnapshot(observationInput, 'applicability observation input');
  assertIdentifier(input.id, 'applicability observation id');
  const observation = verifyApplicabilityObservationCore(traces, intervention, input);
  return bindIdentity(
    observation.id,
    observation.observationDigest,
    observation,
    issuedObservationsById,
    'applicability observation id',
  );
}

/** Public induction boundary with single-read inputs and feature-manifest consistency. */
export function induceApplicabilityHypothesis(
  observationsInput: readonly VerifiedApplicabilityObservation[],
  requestInput: ApplicabilityHypothesisInput,
): ApplicabilityHypothesisCandidate {
  const observations = snapshotObservations(observationsInput, 'discovery observations');
  const request = canonicalSnapshot(requestInput, 'applicability hypothesis request');
  assertIdentifier(request.id, 'applicability hypothesis id');
  const selected = selectedForManifestCheck(
    observations,
    request.discoveryObservationIds,
    'discovery',
  );
  assertConsistentFeatureManifests(selected, 'discovery');
  const candidate = induceApplicabilityHypothesisCore(observations, request);
  return bindIdentity(
    candidate.id,
    candidate.candidateDigest,
    candidate,
    issuedCandidatesById,
    'applicability hypothesis id',
  );
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
  assertIdentifier(request.id, 'applicability validation id');
  const selected = selectedForManifestCheck(
    observations,
    request.validationObservationIds,
    'validation',
  );
  assertConsistentFeatureManifests(selected, 'validation');
  const validation = validateApplicabilityHypothesisCore(candidate, observations, request);
  return bindIdentity(
    validation.id,
    validation.validationDigest,
    validation,
    issuedValidationsById,
    'applicability validation id',
  );
}
