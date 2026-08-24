import { validateClaimForAdmission, validateSupersession } from './admission.js';
import { ClaimProjection, type ClaimResolution, type ResolveClaimOptions } from './claims.js';
import {
  AUTHORITY_RANK,
  evidenceRoles,
  type AssociationRecord,
  type ClaimKey,
  type ClaimRecord,
  type EvidenceAvailability,
  type EvidenceRecord,
  type EvidenceRef,
  type MemoryEvent,
  type MemoryEventInput,
} from './domain.js';
import {
  EvidenceProjection,
  validateEvidenceForCapture,
  type ProjectedEvidence,
} from './evidence.js';
import { EventLedger } from './ledger.js';

export interface EventEnvelope {
  readonly eventId: string;
  readonly recordedAt: number;
  readonly actor: string;
}

function canonicalStrings(values: readonly string[]): readonly string[] {
  return Object.freeze([...new Set(values)].sort());
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

export class MemoryKernel {
  readonly #ledger: EventLedger;

  constructor(ledger: EventLedger = new EventLedger()) {
    this.#ledger = ledger;
  }

  /**
   * Rebuild through the public write contract rather than merely accepting typed-looking JSON.
   * This verifies that every event was legal against the exact transaction-time prefix in which it
   * originally appeared: evidence existed before claims cited it, scopes were authorized, lifecycle
   * transitions were legal, and reasons/provenance were present.
   */
  static from(events: readonly MemoryEvent[]): MemoryKernel {
    const normalized = EventLedger.from(events).all();
    const replay = new MemoryKernel();

    for (const event of normalized) {
      const envelope: EventEnvelope = {
        eventId: event.id,
        recordedAt: event.recordedAt,
        actor: event.actor,
      };
      switch (event.type) {
        case 'evidence.captured':
          replay.captureEvidence(envelope, event.data.evidence);
          break;
        case 'evidence.availability-changed':
          replay.setEvidenceAvailability(
            envelope,
            event.data.evidenceId,
            event.data.availability,
            event.data.reason,
          );
          break;
        case 'claim.asserted':
          replay.assertClaim(envelope, event.data.claim, {
            authorizeImmediately: event.data.initialLifecycle === 'active',
          });
          break;
        case 'claim.admitted':
          replay.admitClaim(envelope, event.data.claimId, event.data.reason);
          break;
        case 'claim.superseded':
          replay.supersedeClaim(
            envelope,
            event.data.previousClaimId,
            event.data.replacementClaimId,
            event.data.effectiveAt,
            event.data.reason,
          );
          break;
        case 'claim.revoked':
          replay.revokeClaim(envelope, event.data.claimId, event.data.reason);
          break;
        case 'association.added':
          replay.addAssociation(envelope, event.data.association);
          break;
        case 'outcome.recorded':
          replay.recordOutcome(envelope, event.data);
          break;
      }
    }

    return replay;
  }

  events(): readonly MemoryEvent[] {
    return this.#ledger.all();
  }

  captureEvidence(envelope: EventEnvelope, evidence: EvidenceRecord): MemoryEvent {
    const projection = EvidenceProjection.from(this.#ledger.all(), envelope.recordedAt);
    const validation = validateEvidenceForCapture(
      evidence,
      projection.records(),
      envelope.recordedAt,
    );
    if (!validation.ok) {
      throw new Error(`evidence capture failed: ${validation.errors.join('; ')}`);
    }

    return this.#append({
      id: envelope.eventId,
      type: 'evidence.captured',
      recordedAt: envelope.recordedAt,
      actor: envelope.actor,
      data: { evidence },
    });
  }

  setEvidenceAvailability(
    envelope: EventEnvelope,
    evidenceId: string,
    availability: EvidenceAvailability,
    reason: string,
  ): MemoryEvent {
    const projection = EvidenceProjection.from(this.#ledger.all(), envelope.recordedAt);
    const current = projection.get(evidenceId);
    if (current === undefined) throw new Error(`unknown evidence: ${evidenceId}`);
    if (current.availability === 'deleted') {
      throw new Error(`deleted evidence cannot transition again: ${evidenceId}`);
    }
    if (current.availability === availability) {
      throw new Error(`evidence ${evidenceId} is already ${availability}`);
    }
    if (reason.trim().length === 0) throw new Error('evidence availability changes require a reason');

    return this.#append({
      id: envelope.eventId,
      type: 'evidence.availability-changed',
      recordedAt: envelope.recordedAt,
      actor: envelope.actor,
      data: { evidenceId, availability, reason },
    });
  }

  evidence(evidenceId: string, knownAt = Number.POSITIVE_INFINITY): ProjectedEvidence | undefined {
    return EvidenceProjection.from(this.#ledger.all(), knownAt).get(evidenceId);
  }

  assertClaim(
    envelope: EventEnvelope,
    claim: ClaimRecord,
    options: { readonly authorizeImmediately?: boolean } = {},
  ): MemoryEvent {
    const validation = validateClaimForAdmission(claim);
    if (!validation.ok) {
      throw new Error(`claim admission failed: ${validation.errors.join('; ')}`);
    }

    const claims = ClaimProjection.from(this.#ledger.all(), envelope.recordedAt);
    if (claims.get(claim.id) !== undefined) throw new Error(`claim id already exists: ${claim.id}`);
    this.#validateClaimLineage(claim, claims);
    this.#validateEvidenceRefs(claim.evidence, envelope.recordedAt, claim.key.scope);

    if (
      options.authorizeImmediately === true &&
      claim.authority === 'model-inference' &&
      claim.epistemicStatus !== 'verified'
    ) {
      throw new Error('unverified model inference must enter quarantine');
    }

    return this.#append({
      id: envelope.eventId,
      type: 'claim.asserted',
      recordedAt: envelope.recordedAt,
      actor: envelope.actor,
      data: {
        claim,
        initialLifecycle: options.authorizeImmediately === true ? 'active' : 'quarantined',
      },
    });
  }

  admitClaim(envelope: EventEnvelope, claimId: string, reason: string): MemoryEvent {
    if (reason.trim().length === 0) throw new Error('claim admission requires a reason');
    const projection = ClaimProjection.from(this.#ledger.all(), envelope.recordedAt);
    if (projection.lifecycle(claimId) !== 'quarantined') {
      throw new Error(`claim ${claimId} is not awaiting admission`);
    }
    const claim = projection.get(claimId);
    if (claim === undefined) throw new Error(`unknown claim: ${claimId}`);
    this.#validateEvidenceRefs(claim.evidence, envelope.recordedAt, claim.key.scope);

    return this.#append({
      id: envelope.eventId,
      type: 'claim.admitted',
      recordedAt: envelope.recordedAt,
      actor: envelope.actor,
      data: { claimId, reason },
    });
  }

  supersedeClaim(
    envelope: EventEnvelope,
    previousClaimId: string,
    replacementClaimId: string,
    effectiveAt: number,
    reason: string,
  ): MemoryEvent {
    if (reason.trim().length === 0) throw new Error('claim supersession requires a reason');
    const projection = ClaimProjection.from(this.#ledger.all(), envelope.recordedAt);
    const previous = projection.get(previousClaimId);
    const replacement = projection.get(replacementClaimId);
    if (previous === undefined || replacement === undefined) {
      throw new Error('supersession requires two existing claims');
    }
    if (projection.lifecycle(previousClaimId) !== 'active') {
      throw new Error('the previous claim must be active');
    }
    if (projection.lifecycle(replacementClaimId) !== 'active') {
      throw new Error('the replacement claim must be active');
    }

    const validation = validateSupersession(previous, replacement, effectiveAt);
    if (!validation.ok) {
      throw new Error(`supersession validation failed: ${validation.errors.join('; ')}`);
    }
    this.#validateEvidenceRefs(replacement.evidence, envelope.recordedAt, replacement.key.scope);

    return this.#append({
      id: envelope.eventId,
      type: 'claim.superseded',
      recordedAt: envelope.recordedAt,
      actor: envelope.actor,
      data: { previousClaimId, replacementClaimId, effectiveAt, reason },
    });
  }

  revokeClaim(envelope: EventEnvelope, claimId: string, reason: string): MemoryEvent {
    if (reason.trim().length === 0) throw new Error('claim revocation requires a reason');
    const projection = ClaimProjection.from(this.#ledger.all(), envelope.recordedAt);
    const lifecycle = projection.lifecycle(claimId);
    if (lifecycle === undefined || lifecycle === 'revoked') {
      throw new Error(`claim ${claimId} cannot be revoked from lifecycle ${String(lifecycle)}`);
    }

    return this.#append({
      id: envelope.eventId,
      type: 'claim.revoked',
      recordedAt: envelope.recordedAt,
      actor: envelope.actor,
      data: { claimId, reason },
    });
  }

  addAssociation(envelope: EventEnvelope, association: AssociationRecord): MemoryEvent {
    if (association.id.trim().length === 0) throw new Error('association id cannot be empty');
    if (association.scope.trim().length === 0) throw new Error('association scope cannot be empty');
    if (association.from.trim().length === 0 || association.to.trim().length === 0) {
      throw new Error('association endpoints cannot be empty');
    }
    if (
      this.#ledger
        .all()
        .some(
          (event) =>
            event.type === 'association.added' && event.data.association.id === association.id,
        )
    ) {
      throw new Error(`association id already exists: ${association.id}`);
    }
    if (!Number.isFinite(association.weight) || association.weight < 0 || association.weight > 1) {
      throw new RangeError('association weight must be in [0, 1]');
    }
    if (association.from === association.to) {
      throw new Error('self-associations are not accepted by the foundational kernel');
    }
    if (association.evidence.length === 0) {
      throw new Error('associations require recoverable evidence');
    }
    this.#validateEvidenceRefs(association.evidence, envelope.recordedAt, association.scope);

    return this.#append({
      id: envelope.eventId,
      type: 'association.added',
      recordedAt: envelope.recordedAt,
      actor: envelope.actor,
      data: { association },
    });
  }

  recordOutcome(
    envelope: EventEnvelope,
    data: Extract<MemoryEvent, { type: 'outcome.recorded' }>['data'],
  ): MemoryEvent {
    if (data.scope.trim().length === 0) throw new Error('outcome scope cannot be empty');
    if (data.subjectId.trim().length === 0) throw new Error('outcome subjectId cannot be empty');
    if (data.taskId.trim().length === 0) throw new Error('outcome taskId cannot be empty');
    if (data.contextFingerprint.trim().length === 0) {
      throw new Error('outcome contextFingerprint cannot be empty');
    }
    if (data.evidence.length === 0) throw new Error('outcomes require recoverable evidence');

    const projected = this.#validateEvidenceRefs(data.evidence, envelope.recordedAt, data.scope);
    const inheritedGroups = canonicalStrings(
      projected.flatMap((entry) => entry.record.sourceGroups),
    );
    if (!sameStrings(data.sourceGroups, inheritedGroups)) {
      throw new Error('outcome source groups must exactly match their evidence lineage');
    }

    const authorityFloor =
      data.verifier === 'human'
        ? AUTHORITY_RANK['human-explicit']
        : data.verifier === 'tool' || data.verifier === 'test'
          ? AUTHORITY_RANK['tool-verified']
          : data.verifier === 'model'
            ? AUTHORITY_RANK['model-inference']
            : -1;
    const verifyingEvidence = projected.filter((_, index) => {
      const reference = data.evidence[index];
      return (
        reference !== undefined &&
        (reference.roles === undefined || evidenceRoles(reference).includes('verifies'))
      );
    });
    const strongestVerifyingEvidence =
      verifyingEvidence.length === 0
        ? -1
        : Math.max(
            ...verifyingEvidence.map((entry) => AUTHORITY_RANK[entry.record.authority]),
          );
    if (strongestVerifyingEvidence < authorityFloor) {
      throw new Error(
        `outcome verifier ${data.verifier} lacks explicit verifying evidence with sufficient authority`,
      );
    }

    return this.#append({
      id: envelope.eventId,
      type: 'outcome.recorded',
      recordedAt: envelope.recordedAt,
      actor: envelope.actor,
      data,
    });
  }

  resolveClaim(
    key: ClaimKey,
    options: ResolveClaimOptions & { readonly knownAt?: number },
  ): ClaimResolution {
    const knownAt = options.knownAt ?? Number.POSITIVE_INFINITY;
    const claimProjection = ClaimProjection.from(this.#ledger.all(), knownAt);
    const evidenceProjection = EvidenceProjection.from(this.#ledger.all(), knownAt);
    return claimProjection.resolve(key, options, (claim) =>
      claim.evidence.every((reference) => evidenceProjection.validatesReference(reference)),
    );
  }

  #validateClaimLineage(claim: ClaimRecord, projection: ClaimProjection): void {
    for (const parentId of claim.derivedFrom) {
      const parent = projection.get(parentId);
      if (parent === undefined) throw new Error(`unknown parent claim: ${parentId}`);
      if (parent.key.scope !== 'global' && parent.key.scope !== claim.key.scope) {
        throw new Error(
          `parent claim scope ${parent.key.scope} cannot be promoted implicitly into ${claim.key.scope}`,
        );
      }
    }
  }

  #validateEvidenceRefs(
    references: readonly EvidenceRef[],
    knownAt: number,
    targetScope?: string,
  ): readonly ProjectedEvidence[] {
    if (references.length === 0) return Object.freeze([]);
    const projection = EvidenceProjection.from(this.#ledger.all(), knownAt);
    const seen = new Set<string>();
    const result: ProjectedEvidence[] = [];

    for (const reference of references) {
      if (seen.has(reference.sourceId)) {
        throw new Error(`duplicate evidence reference: ${reference.sourceId}`);
      }
      seen.add(reference.sourceId);

      const projected = projection.get(reference.sourceId);
      if (projected === undefined) {
        throw new Error(`unknown evidence reference: ${reference.sourceId}`);
      }
      if (!projection.validatesReference(reference)) {
        throw new Error(`unavailable or forged evidence reference: ${reference.sourceId}`);
      }
      if (
        targetScope !== undefined &&
        projected.record.scope !== 'global' &&
        projected.record.scope !== targetScope
      ) {
        throw new Error(
          `evidence scope ${projected.record.scope} cannot be promoted implicitly into ${targetScope}`,
        );
      }
      result.push(projected);
    }

    return Object.freeze(result);
  }

  #append(event: MemoryEventInput): MemoryEvent {
    return this.#ledger.append(event);
  }
}
