import { createHash } from 'node:crypto';

import { ClaimProjection } from '../claims.js';
import {
  AUTHORITY_RANK,
  evidenceRoles,
  type ClaimLifecycle,
  type ClaimRecord,
  type EvidenceAvailability,
  type EvidenceRef,
  type MemoryEvent,
  type MemoryEventInput,
} from '../domain.js';
import { EvidenceProjection } from '../evidence.js';
import { MemoryKernel } from '../kernel.js';
import { adjudicateState } from '../state/adjudicator.js';
import { validateStateSchema } from '../state/schema.js';
import type {
  StateSnapshotExpectation,
  StateSnapshotObservation,
  TransitionDelta,
  TransitionExternalCheck,
  TransitionExternalCheckKind,
  TransitionFinding,
  TransitionFindingCategory,
  TransitionProposal,
  TransitionRisk,
  TransitionStateExpectation,
  TransitionStateObservation,
  TransitionVerificationPolicy,
  TransitionVerificationResult,
  TransitionVerifierIdentity,
} from './types.js';

const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const RISK_RANK: Readonly<Record<TransitionRisk, number>> = Object.freeze({
  low: 0,
  medium: 1,
  high: 2,
  destructive: 3,
});
const RISKS: ReadonlySet<string> = new Set(Object.keys(RISK_RANK));
const VERDICTS = new Set(['accept', 'quarantine', 'human-review', 'reject']);
const STATE_IMPACTS = new Set(['none', 'declared', 'unknown']);
const CHECK_KINDS: ReadonlySet<string> = new Set<TransitionExternalCheckKind>([
  'semantic-coverage',
  'semantic-preservation',
  'semantic-faithfulness',
  'security',
]);
const CHECK_STATUSES = new Set(['pass', 'fail', 'unknown']);
const EVENT_TYPES: ReadonlySet<string> = new Set<MemoryEvent['type']>([
  'evidence.captured',
  'evidence.availability-changed',
  'claim.asserted',
  'claim.admitted',
  'claim.superseded',
  'claim.revoked',
  'association.added',
  'outcome.recorded',
]);

export const DEFAULT_TRANSITION_POLICY: Readonly<TransitionVerificationPolicy> = Object.freeze({
  id: 'transition-verifier/default',
  version: '1',
  maxOperations: 64,
  requireIndependentVerifier: true,
  requiredExternalChecks: Object.freeze({
    high: Object.freeze(['semantic-faithfulness']),
    destructive: Object.freeze([
      'semantic-faithfulness',
      'semantic-preservation',
      'security',
    ]),
  }),
  humanReviewAtOrAbove: 'destructive',
  taintedActiveWritesRequireSecurityCheck: true,
});

function canonicalJson(value: unknown, path = '$', ancestors = new WeakSet<object>()): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      throw new TypeError(`${path} must contain only finite JSON numbers`);
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (ancestors.has(value)) throw new TypeError(`${path} cannot contain a circular reference`);
    ancestors.add(value);
    const items: string[] = [];
    for (let index = 0; index < value.length; index += 1) {
      if (!(index in value)) throw new TypeError(`${path} cannot contain a sparse array`);
      items.push(canonicalJson(value[index], `${path}[${index}]`, ancestors));
    }
    ancestors.delete(value);
    return `[${items.join(',')}]`;
  }
  if (typeof value === 'object') {
    if (ancestors.has(value)) throw new TypeError(`${path} cannot contain a circular reference`);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(`${path} must be a plain JSON object`);
    }
    ancestors.add(value);
    const objectValue = value as Record<string, unknown>;
    const entries = Object.keys(objectValue)
      .sort()
      .map((key) => {
        const item = objectValue[key];
        if (item === undefined) throw new TypeError(`${path}.${key} cannot be undefined`);
        return `${JSON.stringify(key)}:${canonicalJson(item, `${path}.${key}`, ancestors)}`;
      });
    ancestors.delete(value);
    return `{${entries.join(',')}}`;
  }
  throw new TypeError(`${path} contains a non-JSON value`);
}

function digest(value: unknown): string {
  return `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

function uniqueSorted(values: readonly string[]): readonly string[] {
  return Object.freeze([...new Set(values)].sort());
}

function finding(
  code: string,
  category: TransitionFindingCategory,
  severity: TransitionFinding['severity'],
  message: string,
  objectIds: readonly string[] = [],
): TransitionFinding {
  return Object.freeze({
    code,
    category,
    severity,
    message,
    objectIds: uniqueSorted(objectIds),
  });
}

function isRisk(value: unknown): value is TransitionRisk {
  return typeof value === 'string' && RISKS.has(value);
}

function riskAtLeast(value: TransitionRisk, threshold: TransitionRisk): boolean {
  return RISK_RANK[value] >= RISK_RANK[threshold];
}

function maxRisk(left: TransitionRisk, right: TransitionRisk): TransitionRisk {
  return RISK_RANK[left] >= RISK_RANK[right] ? left : right;
}

function riskForOperation(operation: MemoryEventInput): TransitionRisk {
  switch (operation.type) {
    case 'evidence.captured':
      return operation.data.evidence.derivedFrom.length === 0 ? 'low' : 'medium';
    case 'evidence.availability-changed':
      return operation.data.availability === 'deleted' ? 'destructive' : 'high';
    case 'claim.asserted':
      return operation.data.initialLifecycle === 'active' ? 'high' : 'medium';
    case 'claim.admitted':
    case 'claim.superseded':
      return 'high';
    case 'claim.revoked':
      return 'destructive';
    case 'association.added':
    case 'outcome.recorded':
      return 'medium';
  }
}

function operationCanChangeAuthorizedState(operation: MemoryEventInput): boolean {
  return (
    operation.type === 'claim.admitted' ||
    operation.type === 'claim.superseded' ||
    operation.type === 'claim.revoked' ||
    operation.type === 'evidence.availability-changed' ||
    (operation.type === 'claim.asserted' && operation.data.initialLifecycle === 'active')
  );
}

function validateVerifierIdentity(
  verifier: TransitionVerifierIdentity,
  label: string,
  findings: TransitionFinding[],
): void {
  if (verifier.id.trim().length === 0) {
    findings.push(finding('verifier-id-empty', 'verification', 'error', `${label} id cannot be empty`));
  }
  if (verifier.actor.trim().length === 0) {
    findings.push(
      finding('verifier-actor-empty', 'verification', 'error', `${label} actor cannot be empty`),
    );
  }
  if (!['deterministic', 'model', 'tool', 'human'].includes(verifier.kind)) {
    findings.push(
      finding('verifier-kind-invalid', 'verification', 'error', `${label} kind is invalid`),
    );
  }
  if (verifier.implementation.trim().length === 0 || verifier.version.trim().length === 0) {
    findings.push(
      finding(
        'verifier-version-missing',
        'verification',
        'error',
        `${label} implementation and version are required`,
      ),
    );
  }
  if (!SHA256_PATTERN.test(verifier.configDigest)) {
    findings.push(
      finding(
        'verifier-config-digest-invalid',
        'verification',
        'error',
        `${label} configDigest must be a SHA-256 content address`,
      ),
    );
  }
}

function validatePolicy(policy: TransitionVerificationPolicy, findings: TransitionFinding[]): void {
  if (policy.id.trim().length === 0 || policy.version.trim().length === 0) {
    findings.push(
      finding(
        'transition-policy-identity-missing',
        'verification',
        'error',
        'transition policy id and version are required',
      ),
    );
  }
  if (!Number.isInteger(policy.maxOperations) || policy.maxOperations <= 0) {
    findings.push(
      finding(
        'transition-policy-max-operations-invalid',
        'verification',
        'error',
        'transition policy maxOperations must be a positive integer',
      ),
    );
  }
  if (
    policy.requireIndependentVerifier !== undefined &&
    typeof policy.requireIndependentVerifier !== 'boolean'
  ) {
    findings.push(
      finding(
        'transition-policy-independent-verifier-invalid',
        'verification',
        'error',
        'requireIndependentVerifier must be boolean',
      ),
    );
  }
  if (
    policy.taintedActiveWritesRequireSecurityCheck !== undefined &&
    typeof policy.taintedActiveWritesRequireSecurityCheck !== 'boolean'
  ) {
    findings.push(
      finding(
        'transition-policy-taint-flag-invalid',
        'verification',
        'error',
        'taintedActiveWritesRequireSecurityCheck must be boolean',
      ),
    );
  }
  if (
    policy.humanReviewAtOrAbove !== undefined &&
    !isRisk(policy.humanReviewAtOrAbove)
  ) {
    findings.push(
      finding(
        'transition-policy-human-threshold-invalid',
        'verification',
        'error',
        'humanReviewAtOrAbove contains an unknown risk',
      ),
    );
  }
  if (policy.allowedEventTypes !== undefined) {
    if (new Set(policy.allowedEventTypes).size !== policy.allowedEventTypes.length) {
      findings.push(
        finding(
          'transition-policy-event-types-duplicate',
          'verification',
          'error',
          'allowedEventTypes cannot contain duplicates',
        ),
      );
    }
    if (policy.allowedEventTypes.some((type) => !EVENT_TYPES.has(type))) {
      findings.push(
        finding(
          'transition-policy-event-type-invalid',
          'verification',
          'error',
          'allowedEventTypes contains an unknown event type',
        ),
      );
    }
  }
  for (const [risk, kinds] of Object.entries(policy.requiredExternalChecks ?? {})) {
    if (!isRisk(risk)) {
      findings.push(
        finding(
          'transition-policy-check-risk-invalid',
          'verification',
          'error',
          `requiredExternalChecks contains unknown risk ${risk}`,
        ),
      );
      continue;
    }
    if (!Array.isArray(kinds)) {
      findings.push(
        finding(
          'transition-policy-check-list-invalid',
          'verification',
          'error',
          `requiredExternalChecks.${risk} must be an array`,
        ),
      );
      continue;
    }
    if (new Set(kinds).size !== kinds.length || kinds.some((kind) => !CHECK_KINDS.has(kind))) {
      findings.push(
        finding(
          'transition-policy-check-kind-invalid',
          'verification',
          'error',
          `requiredExternalChecks.${risk} contains duplicate or unknown check kinds`,
        ),
      );
    }
  }
}

function validateProposal(
  proposal: TransitionProposal,
  policy: TransitionVerificationPolicy,
  findings: TransitionFinding[],
): void {
  if (proposal.id.trim().length === 0) {
    findings.push(finding('transition-id-empty', 'structure', 'error', 'proposal id cannot be empty'));
  }
  if (proposal.proposer.trim().length === 0) {
    findings.push(
      finding('transition-proposer-empty', 'verification', 'error', 'proposal proposer cannot be empty'),
    );
  }
  if (!SHA256_PATTERN.test(proposal.baseFingerprint)) {
    findings.push(
      finding(
        'transition-base-fingerprint-invalid',
        'concurrency',
        'error',
        'proposal baseFingerprint must be a SHA-256 content address',
      ),
    );
  }
  if (!isRisk(proposal.declaredRisk)) {
    findings.push(
      finding('transition-risk-invalid', 'structure', 'error', 'proposal declaredRisk is invalid'),
    );
  }
  if (!STATE_IMPACTS.has(proposal.stateImpact)) {
    findings.push(
      finding('transition-state-impact-invalid', 'structure', 'error', 'proposal stateImpact is invalid'),
    );
  }
  if (proposal.authorizedScopes.length === 0) {
    findings.push(
      finding(
        'transition-scopes-empty',
        'scope',
        'error',
        'proposal requires at least one authorized scope',
      ),
    );
  }
  if (
    proposal.authorizedScopes.some((scope) => scope.trim().length === 0) ||
    new Set(proposal.authorizedScopes).size !== proposal.authorizedScopes.length
  ) {
    findings.push(
      finding(
        'transition-scopes-invalid',
        'scope',
        'error',
        'authorizedScopes cannot contain empty or duplicate values',
      ),
    );
  }
  if (proposal.operations.length === 0 || proposal.operations.length > policy.maxOperations) {
    findings.push(
      finding(
        'transition-operation-count-invalid',
        'structure',
        'error',
        `proposal requires 1..${policy.maxOperations} operations`,
      ),
    );
  }
  const eventIds = new Set<string>();
  for (const operation of proposal.operations) {
    if (!EVENT_TYPES.has(operation.type)) {
      findings.push(
        finding(
          'transition-event-type-invalid',
          'structure',
          'error',
          `proposal contains unknown event type ${String(operation.type)}`,
        ),
      );
    }
    if (operation.id.trim().length === 0 || eventIds.has(operation.id)) {
      findings.push(
        finding(
          'transition-event-id-invalid',
          'structure',
          'error',
          'proposal event ids must be non-empty and unique',
          [operation.id],
        ),
      );
    }
    eventIds.add(operation.id);
    if (!Number.isFinite(operation.recordedAt)) {
      findings.push(
        finding(
          'transition-event-time-invalid',
          'temporal',
          'error',
          `event ${operation.id} recordedAt must be finite`,
          [operation.id],
        ),
      );
    }
    if (operation.actor.trim().length === 0) {
      findings.push(
        finding(
          'transition-event-actor-empty',
          'verification',
          'error',
          `event ${operation.id} actor cannot be empty`,
          [operation.id],
        ),
      );
    }
    if (
      policy.allowedEventTypes !== undefined &&
      !policy.allowedEventTypes.includes(operation.type)
    ) {
      findings.push(
        finding(
          'transition-event-type-disallowed',
          'structure',
          'error',
          `event type ${operation.type} is disallowed by policy`,
          [operation.id],
        ),
      );
    }
  }
  if (
    proposal.inputEvidenceIds.some((id) => id.trim().length === 0) ||
    new Set(proposal.inputEvidenceIds).size !== proposal.inputEvidenceIds.length
  ) {
    findings.push(
      finding(
        'transition-input-evidence-invalid',
        'coverage',
        'error',
        'inputEvidenceIds cannot contain empty or duplicate ids',
      ),
    );
  }
  const ignored = new Set<string>();
  for (const item of proposal.ignoredInputEvidence) {
    if (item.sourceId.trim().length === 0 || item.reason.trim().length === 0 || ignored.has(item.sourceId)) {
      findings.push(
        finding(
          'transition-ignored-evidence-invalid',
          'coverage',
          'error',
          'ignored input evidence requires a unique source id and non-empty reason',
          [item.sourceId],
        ),
      );
    }
    ignored.add(item.sourceId);
  }
  if (new Set(proposal.externalChecks.map((check) => check.id)).size !== proposal.externalChecks.length) {
    findings.push(
      finding(
        'transition-external-check-id-duplicate',
        'verification',
        'error',
        'external check ids must be unique',
      ),
    );
  }
  if (
    new Set(proposal.stateExpectations.map((expectation) => expectation.id)).size !==
    proposal.stateExpectations.length
  ) {
    findings.push(
      finding(
        'transition-state-expectation-id-duplicate',
        'preservation',
        'error',
        'state expectation ids must be unique',
      ),
    );
  }
  if (proposal.rationale.trim().length === 0) {
    findings.push(
      finding('transition-rationale-empty', 'structure', 'error', 'proposal rationale cannot be empty'),
    );
  }
}

function applyOperation(kernel: MemoryKernel, operation: MemoryEventInput): MemoryEvent {
  const envelope = {
    eventId: operation.id,
    recordedAt: operation.recordedAt,
    actor: operation.actor,
  };
  switch (operation.type) {
    case 'evidence.captured':
      return kernel.captureEvidence(envelope, operation.data.evidence);
    case 'evidence.availability-changed':
      return kernel.setEvidenceAvailability(
        envelope,
        operation.data.evidenceId,
        operation.data.availability,
        operation.data.reason,
      );
    case 'claim.asserted':
      return kernel.assertClaim(envelope, operation.data.claim, {
        authorizeImmediately: operation.data.initialLifecycle === 'active',
      });
    case 'claim.admitted':
      return kernel.admitClaim(envelope, operation.data.claimId, operation.data.reason);
    case 'claim.superseded':
      return kernel.supersedeClaim(
        envelope,
        operation.data.previousClaimId,
        operation.data.replacementClaimId,
        operation.data.effectiveAt,
        operation.data.reason,
      );
    case 'claim.revoked':
      return kernel.revokeClaim(envelope, operation.data.claimId, operation.data.reason);
    case 'association.added':
      return kernel.addAssociation(envelope, operation.data.association);
    case 'outcome.recorded':
      return kernel.recordOutcome(envelope, operation.data);
  }
}

function claimIds(events: readonly MemoryEvent[]): readonly string[] {
  return uniqueSorted(
    events.flatMap((event) => (event.type === 'claim.asserted' ? [event.data.claim.id] : [])),
  );
}

function evidenceIds(events: readonly MemoryEvent[]): readonly string[] {
  return uniqueSorted(
    events.flatMap((event) => (event.type === 'evidence.captured' ? [event.data.evidence.id] : [])),
  );
}

function inferTouchedScopes(
  operations: readonly MemoryEventInput[],
  claims: ClaimProjection,
  evidence: EvidenceProjection,
): readonly string[] {
  const scopes: string[] = [];
  for (const operation of operations) {
    switch (operation.type) {
      case 'evidence.captured':
        scopes.push(operation.data.evidence.scope);
        break;
      case 'evidence.availability-changed': {
        const scope = evidence.get(operation.data.evidenceId)?.record.scope;
        if (scope !== undefined) scopes.push(scope);
        break;
      }
      case 'claim.asserted':
        scopes.push(operation.data.claim.key.scope);
        break;
      case 'claim.admitted':
      case 'claim.revoked': {
        const claimId =
          operation.type === 'claim.admitted'
            ? operation.data.claimId
            : operation.data.claimId;
        const scope = claims.get(claimId)?.key.scope;
        if (scope !== undefined) scopes.push(scope);
        break;
      }
      case 'claim.superseded': {
        const previousScope = claims.get(operation.data.previousClaimId)?.key.scope;
        const replacementScope = claims.get(operation.data.replacementClaimId)?.key.scope;
        if (previousScope !== undefined) scopes.push(previousScope);
        if (replacementScope !== undefined) scopes.push(replacementScope);
        break;
      }
      case 'association.added':
        scopes.push(operation.data.association.scope);
        break;
      case 'outcome.recorded':
        scopes.push(operation.data.scope);
        break;
    }
  }
  return uniqueSorted(scopes);
}

function computeDelta(
  beforeEvents: readonly MemoryEvent[],
  afterEvents: readonly MemoryEvent[],
  operations: readonly MemoryEventInput[],
): TransitionDelta {
  const beforeClaims = ClaimProjection.from(beforeEvents);
  const afterClaims = ClaimProjection.from(afterEvents);
  const beforeEvidence = EvidenceProjection.from(beforeEvents);
  const afterEvidence = EvidenceProjection.from(afterEvents);
  const beforeClaimIds = new Set(claimIds(beforeEvents));
  const afterClaimIds = claimIds(afterEvents);
  const beforeEvidenceIds = new Set(evidenceIds(beforeEvents));
  const afterEvidenceIds = evidenceIds(afterEvents);

  const createdEvidence = afterEvidenceIds
    .filter((id) => !beforeEvidenceIds.has(id))
    .map((id) => {
      const availability = afterEvidence.get(id)?.availability;
      if (availability === undefined) throw new Error(`created evidence ${id} is not projected`);
      return Object.freeze({ evidenceId: id, availability });
    });
  const evidenceAvailabilityChanges = [...beforeEvidenceIds]
    .flatMap((id) => {
      const before = beforeEvidence.get(id)?.availability;
      const after = afterEvidence.get(id)?.availability;
      return before !== undefined && after !== undefined && before !== after
        ? [Object.freeze({ evidenceId: id, before, after })]
        : [];
    })
    .sort((left, right) => left.evidenceId.localeCompare(right.evidenceId));

  const createdClaims = afterClaimIds
    .filter((id) => !beforeClaimIds.has(id))
    .map((id) => {
      const lifecycle = afterClaims.lifecycle(id);
      if (lifecycle === undefined) throw new Error(`created claim ${id} is not projected`);
      return Object.freeze({ claimId: id, lifecycle });
    });
  const claimLifecycleChanges = [...beforeClaimIds]
    .flatMap((id) => {
      const before = beforeClaims.lifecycle(id);
      const after = afterClaims.lifecycle(id);
      return before !== undefined && after !== undefined && before !== after
        ? [Object.freeze({ claimId: id, before, after })]
        : [];
    })
    .sort((left, right) => left.claimId.localeCompare(right.claimId));

  return Object.freeze({
    appendedEventIds: Object.freeze(operations.map((operation) => operation.id)),
    appendedEventTypes: Object.freeze(operations.map((operation) => operation.type)),
    createdEvidence: Object.freeze(createdEvidence),
    evidenceAvailabilityChanges: Object.freeze(evidenceAvailabilityChanges),
    createdClaims: Object.freeze(createdClaims),
    claimLifecycleChanges: Object.freeze(claimLifecycleChanges),
    createdAssociationIds: Object.freeze(
      operations
        .flatMap((operation) =>
          operation.type === 'association.added' ? [operation.data.association.id] : [],
        )
        .sort(),
    ),
    outcomeEventIds: Object.freeze(
      operations
        .flatMap((operation) => (operation.type === 'outcome.recorded' ? [operation.id] : []))
        .sort(),
    ),
    touchedScopes: inferTouchedScopes(operations, afterClaims, afterEvidence),
  });
}

function verifyProjectionPreservation(
  proposal: TransitionProposal,
  delta: TransitionDelta,
  beforeEvents: readonly MemoryEvent[],
  findings: TransitionFinding[],
): void {
  const beforeClaimIds = new Set(claimIds(beforeEvents));
  const lifecycleTargets = new Set<string>();
  const availabilityTargets = new Set<string>();
  for (const operation of proposal.operations) {
    if (operation.type === 'claim.admitted' || operation.type === 'claim.revoked') {
      lifecycleTargets.add(operation.data.claimId);
    } else if (operation.type === 'claim.superseded') {
      lifecycleTargets.add(operation.data.previousClaimId);
    } else if (operation.type === 'evidence.availability-changed') {
      availabilityTargets.add(operation.data.evidenceId);
    }
  }

  const unexpectedClaims = delta.claimLifecycleChanges
    .map((change) => change.claimId)
    .filter((id) => !lifecycleTargets.has(id));
  if (unexpectedClaims.length > 0) {
    findings.push(
      finding(
        'transition-unexpected-claim-lifecycle-change',
        'preservation',
        'error',
        'the staged transition changed claim lifecycle outside its explicit targets',
        unexpectedClaims,
      ),
    );
  }
  const unexpectedEvidence = delta.evidenceAvailabilityChanges
    .map((change) => change.evidenceId)
    .filter((id) => !availabilityTargets.has(id));
  if (unexpectedEvidence.length > 0) {
    findings.push(
      finding(
        'transition-unexpected-evidence-availability-change',
        'preservation',
        'error',
        'the staged transition changed evidence availability outside its explicit targets',
        unexpectedEvidence,
      ),
    );
  }

  const assertedIds = new Set(
    proposal.operations.flatMap((operation) =>
      operation.type === 'claim.asserted' ? [operation.data.claim.id] : [],
    ),
  );
  const unexpectedCreatedClaims = delta.createdClaims
    .map((entry) => entry.claimId)
    .filter((id) => !assertedIds.has(id) || beforeClaimIds.has(id));
  if (unexpectedCreatedClaims.length > 0) {
    findings.push(
      finding(
        'transition-unexpected-created-claim',
        'preservation',
        'error',
        'the staged transition created a claim not declared by claim.asserted',
        unexpectedCreatedClaims,
      ),
    );
  }
}

function evidenceUsedByProposal(
  proposal: TransitionProposal,
  afterClaims: ClaimProjection,
): ReadonlySet<string> {
  const used = new Set<string>();
  for (const operation of proposal.operations) {
    switch (operation.type) {
      case 'evidence.captured':
        for (const id of operation.data.evidence.derivedFrom) used.add(id);
        break;
      case 'claim.asserted':
        for (const reference of operation.data.claim.evidence) used.add(reference.sourceId);
        break;
      case 'claim.admitted': {
        const claim = afterClaims.get(operation.data.claimId);
        for (const reference of claim?.evidence ?? []) used.add(reference.sourceId);
        break;
      }
      case 'claim.superseded': {
        const claim = afterClaims.get(operation.data.replacementClaimId);
        for (const reference of claim?.evidence ?? []) used.add(reference.sourceId);
        break;
      }
      case 'association.added':
        for (const reference of operation.data.association.evidence) used.add(reference.sourceId);
        break;
      case 'outcome.recorded':
        for (const reference of operation.data.evidence) used.add(reference.sourceId);
        break;
      case 'evidence.availability-changed':
      case 'claim.revoked':
        break;
    }
  }
  for (const check of proposal.externalChecks) {
    for (const reference of check.evidence) used.add(reference.sourceId);
  }
  return used;
}

function verifyCoverage(
  proposal: TransitionProposal,
  afterEvents: readonly MemoryEvent[],
  findings: TransitionFinding[],
): void {
  const evidence = EvidenceProjection.from(afterEvents);
  const claims = ClaimProjection.from(afterEvents);
  const used = evidenceUsedByProposal(proposal, claims);
  const ignored = new Map(
    proposal.ignoredInputEvidence.map((item) => [item.sourceId, item.reason] as const),
  );
  const input = new Set(proposal.inputEvidenceIds);
  const allowedScopes = new Set(proposal.authorizedScopes);

  for (const operation of proposal.operations) {
    if (operation.type === 'evidence.captured' && !input.has(operation.data.evidence.id)) {
      findings.push(
        finding(
          'transition-new-evidence-not-declared-as-input',
          'coverage',
          'error',
          'newly captured evidence must be declared in inputEvidenceIds',
          [operation.data.evidence.id],
        ),
      );
    }
  }

  for (const sourceId of proposal.inputEvidenceIds) {
    const projected = evidence.get(sourceId);
    if (projected === undefined) {
      findings.push(
        finding(
          'transition-input-evidence-missing',
          'coverage',
          'error',
          'declared input evidence does not exist after staging',
          [sourceId],
        ),
      );
      continue;
    }
    if (projected.record.scope !== 'global' && !allowedScopes.has(projected.record.scope)) {
      findings.push(
        finding(
          'transition-input-evidence-scope-unauthorized',
          'scope',
          'error',
          `input evidence scope ${projected.record.scope} is not authorized`,
          [sourceId],
        ),
      );
    }
    if (used.has(sourceId) && ignored.has(sourceId)) {
      findings.push(
        finding(
          'transition-input-evidence-used-and-ignored',
          'coverage',
          'error',
          'input evidence cannot be both used and explicitly ignored',
          [sourceId],
        ),
      );
    } else if (!used.has(sourceId) && !ignored.has(sourceId)) {
      findings.push(
        finding(
          'transition-input-evidence-omitted',
          'coverage',
          'error',
          'input evidence was neither used nor explicitly ignored with a reason',
          [sourceId],
        ),
      );
    }
  }

  for (const item of proposal.ignoredInputEvidence) {
    if (!input.has(item.sourceId)) {
      findings.push(
        finding(
          'transition-ignored-evidence-not-input',
          'coverage',
          'error',
          'ignored evidence must be part of inputEvidenceIds',
          [item.sourceId],
        ),
      );
    }
  }
}

function authorityFloorForVerifier(verifier: TransitionVerifierIdentity): number {
  switch (verifier.kind) {
    case 'human':
      return AUTHORITY_RANK['human-explicit'];
    case 'deterministic':
    case 'tool':
      return AUTHORITY_RANK['tool-verified'];
    case 'model':
      return AUTHORITY_RANK['model-inference'];
  }
}

function validateExternalChecks(
  proposal: TransitionProposal,
  verifier: TransitionVerifierIdentity,
  policy: TransitionVerificationPolicy,
  afterEvents: readonly MemoryEvent[],
  findings: TransitionFinding[],
): {
  readonly passedKinds: ReadonlySet<TransitionExternalCheckKind>;
  readonly hasHumanPass: boolean;
} {
  const evidence = EvidenceProjection.from(afterEvents);
  const passedKinds = new Set<TransitionExternalCheckKind>();
  const operationActors = new Set(proposal.operations.map((operation) => operation.actor));
  let hasHumanPass = false;

  for (const check of proposal.externalChecks) {
    if (check.id.trim().length === 0 || !CHECK_KINDS.has(check.kind) || !CHECK_STATUSES.has(check.status)) {
      findings.push(
        finding(
          'transition-external-check-shape-invalid',
          'verification',
          'error',
          'external check id, kind, or status is invalid',
          [check.id],
        ),
      );
    }
    validateVerifierIdentity(check.verifier, `external check ${check.id} verifier`, findings);
    if (!SHA256_PATTERN.test(check.reportDigest)) {
      findings.push(
        finding(
          'transition-external-check-digest-invalid',
          'verification',
          'error',
          'external check reportDigest must be a SHA-256 content address',
          [check.id],
        ),
      );
    }
    if (
      check.subjectIds.length === 0 ||
      check.subjectIds.some((id) => id.trim().length === 0) ||
      new Set(check.subjectIds).size !== check.subjectIds.length
    ) {
      findings.push(
        finding(
          'transition-external-check-subjects-invalid',
          'verification',
          'error',
          'external check subjects must be non-empty and unique',
          [check.id],
        ),
      );
    }
    if (check.evidence.length === 0) {
      findings.push(
        finding(
          'transition-external-check-evidence-missing',
          'verification',
          'error',
          'external checks require evidence of the verifier result',
          [check.id],
        ),
      );
    }

    let strongest = -1;
    for (const reference of check.evidence) {
      const projected = evidence.get(reference.sourceId);
      if (!evidence.validatesReference(reference) || projected === undefined) {
        findings.push(
          finding(
            'transition-external-check-evidence-invalid',
            'verification',
            'error',
            'external check cites unavailable or forged evidence',
            [check.id, reference.sourceId],
          ),
        );
        continue;
      }
      if (reference.roles?.includes('verifies') !== true) {
        findings.push(
          finding(
            'transition-external-check-role-invalid',
            'verification',
            'error',
            'external check evidence must explicitly use the verifies role',
            [check.id, reference.sourceId],
          ),
        );
      }
      if (
        projected.record.scope !== 'global' &&
        !proposal.authorizedScopes.includes(projected.record.scope)
      ) {
        findings.push(
          finding(
            'transition-external-check-scope-unauthorized',
            'scope',
            'error',
            `external check evidence scope ${projected.record.scope} is not authorized`,
            [check.id, reference.sourceId],
          ),
        );
      }
      strongest = Math.max(strongest, AUTHORITY_RANK[projected.record.authority]);
    }
    if (strongest < authorityFloorForVerifier(check.verifier)) {
      findings.push(
        finding(
          'transition-external-check-authority-insufficient',
          'authority',
          'error',
          'external check evidence is weaker than its declared verifier',
          [check.id],
        ),
      );
    }

    if (
      (policy.requireIndependentVerifier ?? true) &&
      (check.verifier.actor === proposal.proposer || operationActors.has(check.verifier.actor))
    ) {
      findings.push(
        finding(
          'transition-external-check-not-independent',
          'verification',
          'error',
          'external check verifier is not independent from the proposal actors',
          [check.id, check.verifier.id],
        ),
      );
    }

    if (check.status === 'fail') {
      findings.push(
        finding(
          'transition-external-check-failed',
          'faithfulness',
          'error',
          `external check ${check.id} failed`,
          [check.id, ...check.subjectIds],
        ),
      );
    } else if (check.status === 'unknown') {
      findings.push(
        finding(
          'transition-external-check-unknown',
          'verification',
          'warning',
          `external check ${check.id} did not reach a verdict`,
          [check.id],
        ),
      );
    } else {
      passedKinds.add(check.kind);
      if (check.verifier.kind === 'human') hasHumanPass = true;
    }
  }

  if (
    (policy.requireIndependentVerifier ?? true) &&
    (verifier.actor === proposal.proposer || operationActors.has(verifier.actor))
  ) {
    findings.push(
      finding(
        'transition-primary-verifier-not-independent',
        'verification',
        'error',
        'primary verifier is not independent from the proposal actors',
        [verifier.id],
      ),
    );
  }

  return Object.freeze({ passedKinds, hasHumanPass });
}

function snapshotFor(events: readonly MemoryEvent[], expectation: TransitionStateExpectation): StateSnapshotObservation {
  const decision = adjudicateState(events, expectation.schema, expectation.request);
  return Object.freeze({
    status: decision.status,
    ...(decision.value === undefined ? {} : { value: decision.value }),
  });
}

function snapshotMatches(
  expected: StateSnapshotExpectation | undefined,
  actual: StateSnapshotObservation,
): readonly string[] {
  if (expected === undefined) return Object.freeze([]);
  const reasons: string[] = [];
  if (expected.status !== undefined && expected.status !== actual.status) {
    reasons.push(`expected status ${expected.status}, received ${actual.status}`);
  }
  if (Object.prototype.hasOwnProperty.call(expected, 'value')) {
    const expectedValue = canonicalJson(expected.value);
    const actualValue = Object.prototype.hasOwnProperty.call(actual, 'value')
      ? canonicalJson(actual.value)
      : '<absent>';
    if (expectedValue !== actualValue) reasons.push('state value does not match the expectation');
  }
  return Object.freeze(reasons);
}

function verifyStateExpectations(
  proposal: TransitionProposal,
  beforeEvents: readonly MemoryEvent[],
  afterEvents: readonly MemoryEvent[],
  findings: TransitionFinding[],
): readonly TransitionStateObservation[] {
  const observations: TransitionStateObservation[] = [];
  for (const expectation of proposal.stateExpectations) {
    const reasons: string[] = [];
    if (expectation.id.trim().length === 0) reasons.push('state expectation id cannot be empty');
    if (!['assert', 'preserve', 'change'].includes(expectation.mode)) {
      reasons.push('state expectation mode is invalid');
    }
    try {
      validateStateSchema(expectation.schema);
      const before = snapshotFor(beforeEvents, expectation);
      const after = snapshotFor(afterEvents, expectation);
      if (expectation.mode === 'preserve' && canonicalJson(before) !== canonicalJson(after)) {
        reasons.push('state changed even though preservation was required');
      }
      if (expectation.mode === 'change' && canonicalJson(before) === canonicalJson(after)) {
        reasons.push('state did not change even though a transition was required');
      }
      if (
        expectation.mode === 'assert' &&
        expectation.before === undefined &&
        expectation.after === undefined
      ) {
        reasons.push('assert mode requires a before or after expectation');
      }
      reasons.push(...snapshotMatches(expectation.before, before));
      reasons.push(...snapshotMatches(expectation.after, after));
      const observation = Object.freeze({
        id: expectation.id,
        mode: expectation.mode,
        passed: reasons.length === 0,
        before,
        after,
        reasons: Object.freeze(reasons),
      });
      observations.push(observation);
      if (!observation.passed) {
        findings.push(
          finding(
            'transition-state-expectation-failed',
            'preservation',
            'error',
            `state expectation ${expectation.id} failed: ${reasons.join('; ')}`,
            [expectation.id, expectation.request.slotId],
          ),
        );
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'unknown state verification error';
      findings.push(
        finding(
          'transition-state-expectation-invalid',
          'preservation',
          'error',
          `state expectation ${expectation.id} is invalid: ${message}`,
          [expectation.id],
        ),
      );
    }
  }
  return Object.freeze(observations);
}

function activeClaimIds(proposal: TransitionProposal): readonly string[] {
  const ids: string[] = [];
  for (const operation of proposal.operations) {
    if (operation.type === 'claim.asserted' && operation.data.initialLifecycle === 'active') {
      ids.push(operation.data.claim.id);
    } else if (operation.type === 'claim.admitted') {
      ids.push(operation.data.claimId);
    } else if (operation.type === 'claim.superseded') {
      ids.push(operation.data.replacementClaimId);
    }
  }
  return uniqueSorted(ids);
}

function hasTaintedActiveWrite(
  proposal: TransitionProposal,
  afterEvents: readonly MemoryEvent[],
): readonly string[] {
  const claims = ClaimProjection.from(afterEvents);
  const evidence = EvidenceProjection.from(afterEvents);
  const tainted: string[] = [];
  for (const claimId of activeClaimIds(proposal)) {
    const claim = claims.get(claimId);
    if (claim === undefined) continue;
    const dangerous = claim.evidence.some((reference) => {
      const record = evidence.get(reference.sourceId)?.record;
      return (
        record?.taints.includes('prompt-like') === true ||
        record?.taints.includes('untrusted-source') === true ||
        record?.taints.includes('secret-detected') === true
      );
    });
    if (dangerous) tainted.push(claimId);
  }
  return uniqueSorted(tainted);
}

function requiredChecksForRisk(
  policy: TransitionVerificationPolicy,
  risk: TransitionRisk,
): readonly TransitionExternalCheckKind[] {
  return Object.freeze([...(policy.requiredExternalChecks?.[risk] ?? [])]);
}

function resultPayload(
  result: Omit<TransitionVerificationResult, 'resultDigest' | 'stagedEvents'>,
): unknown {
  return result;
}

export function fingerprintMemoryEvents(events: readonly MemoryEvent[]): string {
  MemoryKernel.from(events);
  return digest(events);
}

export function verifyTransition(
  beforeEvents: readonly MemoryEvent[],
  proposal: TransitionProposal,
  verifier: TransitionVerifierIdentity,
  policy: TransitionVerificationPolicy = DEFAULT_TRANSITION_POLICY,
): TransitionVerificationResult {
  const proposalDigest = digest(proposal);
  const policyDigest = digest(policy);
  const findings: TransitionFinding[] = [];
  validatePolicy(policy, findings);
  validateProposal(proposal, policy, findings);
  validateVerifierIdentity(verifier, 'primary verifier', findings);

  let baseFingerprint = digest(beforeEvents);
  let stagedEvents: readonly MemoryEvent[] | undefined;
  let afterFingerprint: string | undefined;
  let delta: TransitionDelta | undefined;
  let stateObservations: readonly TransitionStateObservation[] = Object.freeze([]);
  let actualRisk: TransitionRisk = 'low';

  for (const operation of proposal.operations) {
    actualRisk = maxRisk(actualRisk, riskForOperation(operation));
  }
  if (RISK_RANK[proposal.declaredRisk] < RISK_RANK[actualRisk]) {
    findings.push(
      finding(
        'transition-risk-underdeclared',
        'verification',
        'error',
        `declared risk ${proposal.declaredRisk} is lower than computed risk ${actualRisk}`,
      ),
    );
  }

  try {
    const baseKernel = MemoryKernel.from(beforeEvents);
    baseFingerprint = digest(baseKernel.events());
    if (proposal.baseFingerprint !== baseFingerprint) {
      findings.push(
        finding(
          'transition-base-fingerprint-mismatch',
          'concurrency',
          'error',
          'proposal was prepared against a different canonical prefix',
        ),
      );
    }

    if (proposal.operations.length > 0 && proposal.operations.length <= policy.maxOperations) {
      const staged = MemoryKernel.from(baseKernel.events());
      for (const operation of proposal.operations) applyOperation(staged, operation);
      stagedEvents = staged.events();
      afterFingerprint = digest(stagedEvents);
      delta = computeDelta(baseKernel.events(), stagedEvents, proposal.operations);
      verifyProjectionPreservation(proposal, delta, baseKernel.events(), findings);
      verifyCoverage(proposal, stagedEvents, findings);

      const allowedScopes = new Set(proposal.authorizedScopes);
      const unauthorizedScopes = delta.touchedScopes.filter(
        (scope) => scope !== 'global' && !allowedScopes.has(scope),
      );
      if (unauthorizedScopes.length > 0) {
        findings.push(
          finding(
            'transition-touched-scope-unauthorized',
            'scope',
            'error',
            'staged transition touches scopes outside authorizedScopes',
            unauthorizedScopes,
          ),
        );
      }

      const stateAffecting = proposal.operations.some(operationCanChangeAuthorizedState);
      if (stateAffecting && proposal.stateImpact === 'none') {
        findings.push(
          finding(
            'transition-state-impact-denied',
            'preservation',
            'error',
            'proposal declares no state impact but contains state-affecting operations',
          ),
        );
      }
      if (proposal.stateImpact === 'declared' && proposal.stateExpectations.length === 0) {
        findings.push(
          finding(
            'transition-state-expectations-missing',
            'preservation',
            'error',
            'declared state impact requires at least one state expectation',
          ),
        );
      }
      stateObservations = verifyStateExpectations(
        proposal,
        baseKernel.events(),
        stagedEvents,
        findings,
      );
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'unknown transition staging failure';
    findings.push(
      finding(
        'transition-semantic-replay-failed',
        'structure',
        'error',
        `proposed operations cannot be replayed atomically: ${message}`,
      ),
    );
  }

  let passedKinds: ReadonlySet<TransitionExternalCheckKind> = new Set();
  let hasHumanPass = false;
  if (stagedEvents !== undefined) {
    const checks = validateExternalChecks(
      proposal,
      verifier,
      policy,
      stagedEvents,
      findings,
    );
    passedKinds = checks.passedKinds;
    hasHumanPass = checks.hasHumanPass;
  } else if (
    (policy.requireIndependentVerifier ?? true) &&
    verifier.actor === proposal.proposer
  ) {
    findings.push(
      finding(
        'transition-primary-verifier-not-independent',
        'verification',
        'error',
        'primary verifier is not independent from the proposer',
        [verifier.id],
      ),
    );
  }

  let requiresHumanReview = proposal.stateImpact === 'unknown';
  for (const kind of requiredChecksForRisk(policy, actualRisk)) {
    if (!passedKinds.has(kind)) {
      findings.push(
        finding(
          'transition-required-external-check-missing',
          'verification',
          'warning',
          `risk ${actualRisk} requires a passing ${kind} check`,
          [kind],
        ),
      );
      requiresHumanReview = true;
    }
  }

  const humanThreshold = policy.humanReviewAtOrAbove ?? 'destructive';
  if (
    riskAtLeast(actualRisk, humanThreshold) &&
    verifier.kind !== 'human' &&
    !hasHumanPass
  ) {
    findings.push(
      finding(
        'transition-human-review-required',
        'verification',
        'warning',
        `risk ${actualRisk} requires an independent human review`,
      ),
    );
    requiresHumanReview = true;
  }

  let requiresQuarantine = false;
  if (
    stagedEvents !== undefined &&
    (policy.taintedActiveWritesRequireSecurityCheck ?? true)
  ) {
    const taintedClaims = hasTaintedActiveWrite(proposal, stagedEvents);
    if (taintedClaims.length > 0 && !passedKinds.has('security')) {
      findings.push(
        finding(
          'transition-tainted-active-write',
          'faithfulness',
          'warning',
          'active state derived from tainted evidence requires a passing security check',
          taintedClaims,
        ),
      );
      requiresQuarantine = true;
    }
  }

  const hasErrors = findings.some((item) => item.severity === 'error');
  const verdict = hasErrors
    ? 'reject'
    : requiresHumanReview
      ? 'human-review'
      : requiresQuarantine
        ? 'quarantine'
        : 'accept';

  const unsigned = Object.freeze({
    proposalId: proposal.id,
    proposalDigest,
    policyId: policy.id,
    policyVersion: policy.version,
    policyDigest,
    verifier: Object.freeze({ ...verifier }),
    verdict,
    actualRisk,
    baseFingerprint,
    ...(afterFingerprint === undefined ? {} : { afterFingerprint }),
    findings: Object.freeze(findings),
    ...(delta === undefined ? {} : { delta }),
    stateObservations,
    externalCheckIds: Object.freeze(proposal.externalChecks.map((check) => check.id).sort()),
  });
  const resultDigest = digest(resultPayload(unsigned));

  return Object.freeze({
    ...unsigned,
    ...(stagedEvents === undefined ? {} : { stagedEvents }),
    resultDigest,
  });
}

export function verifyTransitionResultIntegrity(result: TransitionVerificationResult): boolean {
  try {
    if (!VERDICTS.has(result.verdict) || !isRisk(result.actualRisk)) return false;
    if (!SHA256_PATTERN.test(result.resultDigest)) return false;
    if (!SHA256_PATTERN.test(result.proposalDigest) || !SHA256_PATTERN.test(result.policyDigest)) {
      return false;
    }
    if (!SHA256_PATTERN.test(result.baseFingerprint)) return false;
    if (result.stagedEvents !== undefined) {
      if (result.afterFingerprint === undefined) return false;
      if (fingerprintMemoryEvents(result.stagedEvents) !== result.afterFingerprint) return false;
    } else if (result.afterFingerprint !== undefined) {
      return false;
    }
    if (result.verdict === 'accept' && result.stagedEvents === undefined) return false;

    const unsigned = {
      proposalId: result.proposalId,
      proposalDigest: result.proposalDigest,
      policyId: result.policyId,
      policyVersion: result.policyVersion,
      policyDigest: result.policyDigest,
      verifier: result.verifier,
      verdict: result.verdict,
      actualRisk: result.actualRisk,
      baseFingerprint: result.baseFingerprint,
      ...(result.afterFingerprint === undefined ? {} : { afterFingerprint: result.afterFingerprint }),
      findings: result.findings,
      ...(result.delta === undefined ? {} : { delta: result.delta }),
      stateObservations: result.stateObservations,
      externalCheckIds: result.externalCheckIds,
    };
    return digest(unsigned) === result.resultDigest;
  } catch {
    return false;
  }
}

/**
 * Commit by returning a new kernel. The caller's kernel is never mutated, so a failed multi-event
 * transition cannot leave a partial prefix in memory. Durable providers must implement the same
 * base-fingerprint compare-and-swap inside one database transaction.
 */
export function commitVerifiedTransition(
  current: MemoryKernel,
  result: TransitionVerificationResult,
): MemoryKernel {
  if (!verifyTransitionResultIntegrity(result)) {
    throw new Error('transition verification result failed integrity checks');
  }
  if (result.verdict !== 'accept') {
    throw new Error(`only accepted transitions may commit; received ${result.verdict}`);
  }
  const currentEvents = current.events();
  const currentFingerprint = fingerprintMemoryEvents(currentEvents);
  if (currentFingerprint !== result.baseFingerprint) {
    throw new Error('transition base is stale; canonical memory changed after verification');
  }
  const staged = result.stagedEvents;
  if (staged === undefined) throw new Error('accepted transition has no staged event stream');
  const stagedPrefix = staged.slice(0, currentEvents.length);
  if (fingerprintMemoryEvents(stagedPrefix) !== result.baseFingerprint) {
    throw new Error('staged transition does not preserve the canonical prefix');
  }
  return MemoryKernel.from(staged);
}
