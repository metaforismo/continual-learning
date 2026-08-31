import type { MemoryEvent } from '../domain.js';
import { canonicalJson } from '../retrieval/canonical.js';
import {
  createVerifiedProcedureCandidate as createVerifiedProcedureCandidateCore,
  isIssuedVerifiedProcedureCandidate as isIssuedCandidateCore,
  type VerifiedProcedureCandidate,
  type VerifiedProcedureCandidateInput,
} from './verified-procedure-candidates.js';
import {
  isIssuedVerifiedApplicabilityHypothesis,
  type VerifiedApplicabilityHypothesis,
} from './applicability-hypotheses-api.js';

export {
  VERIFIED_PROCEDURE_CANDIDATE_SCHEMA_VERSION,
  isIssuedVerifiedProcedureCandidate,
} from './verified-procedure-candidates.js';

export type {
  ProcedureCandidateRisk,
  ProcedureContraindicationInput,
  ProcedureDependencyInput,
  ProcedureDependencyKind,
  ProcedureEvidenceBinding,
  ProcedureFailureAction,
  ProcedureRollbackContract,
  ProcedureRollbackContractInput,
  ProcedureRollbackStrategy,
  ProcedureStepInput,
  ProcedureStepKind,
  ProcedureVerificationContract,
  ProcedureVerificationContractInput,
  ProcedureVerifier,
  VerifiedApplicabilityBinding,
  VerifiedProcedureCandidate,
  VerifiedProcedureContraindication,
  VerifiedProcedureCandidateInput,
  VerifiedProcedureDependency,
  VerifiedProcedureStep,
} from './verified-procedure-candidates.js';

const MAX_EVENTS = 10_000_000;
const MAX_ISSUED_IDENTITIES = 65_536;
const MAX_INPUT_CHARACTERS = 1_000_000;

interface IssuedIdentity<T> {
  readonly digest: string;
  readonly value: T;
}

const candidatesById = new Map<string, IssuedIdentity<VerifiedProcedureCandidate>>();
const candidatesByVersion = new Map<string, IssuedIdentity<VerifiedProcedureCandidate>>();

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

function snapshotEvents(eventsInput: readonly MemoryEvent[]): readonly MemoryEvent[] {
  if (!Array.isArray(eventsInput)) throw new TypeError('procedure candidate events must be an array');
  if (eventsInput.length > MAX_EVENTS) {
    throw new RangeError(`procedure candidate events cannot exceed ${MAX_EVENTS} entries`);
  }
  return Object.freeze(Array.from(eventsInput));
}

function assertCompatibleIdentity(
  key: string,
  candidate: VerifiedProcedureCandidate,
  registry: Map<string, IssuedIdentity<VerifiedProcedureCandidate>>,
  label: string,
): IssuedIdentity<VerifiedProcedureCandidate> | undefined {
  const previous = registry.get(key);
  if (previous !== undefined && previous.digest !== candidate.candidateDigest) {
    throw new Error(`${label} conflicts with an already issued identity: ${key}`);
  }
  return previous;
}

function bindCandidateAtomically(
  candidate: VerifiedProcedureCandidate,
): VerifiedProcedureCandidate {
  const versionKey = `${candidate.scope}:${candidate.procedureId}@${candidate.version}`;
  const byId = assertCompatibleIdentity(
    candidate.id,
    candidate,
    candidatesById,
    'procedure candidate id',
  );
  const byVersion = assertCompatibleIdentity(
    versionKey,
    candidate,
    candidatesByVersion,
    'procedure version',
  );
  if (byId === undefined && candidatesById.size >= MAX_ISSUED_IDENTITIES) {
    throw new RangeError(
      `procedure candidate id registry cannot exceed ${MAX_ISSUED_IDENTITIES} process-local identities`,
    );
  }
  if (byVersion === undefined && candidatesByVersion.size >= MAX_ISSUED_IDENTITIES) {
    throw new RangeError(
      `procedure version registry cannot exceed ${MAX_ISSUED_IDENTITIES} process-local identities`,
    );
  }
  const issued = byId?.value ?? byVersion?.value ?? candidate;
  if (byId !== undefined && byVersion !== undefined && byId.digest !== byVersion.digest) {
    throw new Error('procedure candidate id and immutable version bindings disagree');
  }
  if (byId === undefined) {
    candidatesById.set(
      candidate.id,
      Object.freeze({ digest: candidate.candidateDigest, value: issued }),
    );
  }
  if (byVersion === undefined) {
    candidatesByVersion.set(
      versionKey,
      Object.freeze({ digest: candidate.candidateDigest, value: issued }),
    );
  }
  return issued;
}

/**
 * Guarded process-local procedure-candidate boundary.
 *
 * The applicability capability is checked before its fields are inspected. Event and request
 * inputs are snapshotted once, and both candidate IDs and immutable procedure versions are bound
 * to one exact digest. A successful call still grants no canary, promotion, or execution authority.
 */
export function createVerifiedProcedureCandidate(
  memoryEventsInput: readonly MemoryEvent[],
  applicability: VerifiedApplicabilityHypothesis,
  input: VerifiedProcedureCandidateInput,
): VerifiedProcedureCandidate {
  if (!isIssuedVerifiedApplicabilityHypothesis(applicability)) {
    throw new Error('procedure candidate requires an issued applicability validation capability');
  }
  const events = snapshotEvents(memoryEventsInput);
  const request = canonicalSnapshot(input, 'verified procedure candidate input');
  const candidate = createVerifiedProcedureCandidateCore(events, applicability, request);
  if (!isIssuedCandidateCore(candidate)) {
    throw new Error('procedure candidate core did not issue a capability');
  }
  return bindCandidateAtomically(candidate);
}
