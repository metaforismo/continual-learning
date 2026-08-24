import { validateClaimForAdmission, validateSupersession } from './admission.js';
import { ClaimProjection, type ClaimResolution, type ResolveClaimOptions } from './claims.js';
import type {
  AssociationRecord,
  ClaimKey,
  ClaimRecord,
  MemoryEvent,
  MemoryEventInput,
} from './domain.js';
import { EventLedger } from './ledger.js';

export interface EventEnvelope {
  readonly eventId: string;
  readonly recordedAt: number;
  readonly actor: string;
}

export class MemoryKernel {
  readonly #ledger = new EventLedger();

  events(): readonly MemoryEvent[] {
    return this.#ledger.all();
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
    const projection = ClaimProjection.from(this.#ledger.all(), envelope.recordedAt);
    if (projection.lifecycle(claimId) !== 'quarantined') {
      throw new Error(`claim ${claimId} is not awaiting admission`);
    }

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

    return this.#append({
      id: envelope.eventId,
      type: 'claim.superseded',
      recordedAt: envelope.recordedAt,
      actor: envelope.actor,
      data: { previousClaimId, replacementClaimId, effectiveAt, reason },
    });
  }

  revokeClaim(envelope: EventEnvelope, claimId: string, reason: string): MemoryEvent {
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
    if (!Number.isFinite(association.weight) || association.weight < 0 || association.weight > 1) {
      throw new RangeError('association weight must be in [0, 1]');
    }
    if (association.from === association.to) {
      throw new Error('self-associations are not accepted by the foundational kernel');
    }
    if (association.evidence.length === 0) {
      throw new Error('associations require recoverable evidence');
    }

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
    const projection = ClaimProjection.from(
      this.#ledger.all(),
      options.knownAt ?? Number.POSITIVE_INFINITY,
    );
    return projection.resolve(key, options);
  }

  #append(event: MemoryEventInput): MemoryEvent {
    return this.#ledger.append(event);
  }
}
