import type { CanonicalChangeFeed } from '../durable/change-feed.js';
import {
  CanonicalObjectReadIndexIntegrityError,
  type AnySelectedObjectProof,
  type CanonicalObjectAddress,
  type CanonicalObjectReadOptions,
  type RehydratedClaimProof,
} from './object-read-index-contract.js';
import { CanonicalObjectReadIndex as CanonicalObjectReadIndexCore } from './object-read-index.js';

interface CheckpointBinding {
  readonly cursorDigest: string;
  readonly revision: number;
  readonly lastBatchId: string;
  readonly configurationDigest: string;
}

function sameCheckpoint(left: CheckpointBinding, right: CheckpointBinding): boolean {
  return (
    left.cursorDigest === right.cursorDigest &&
    left.revision === right.revision &&
    left.lastBatchId === right.lastBatchId &&
    left.configurationDigest === right.configurationDigest
  );
}

function proofMatchesCheckpoint(
  proof: Pick<
    AnySelectedObjectProof,
    'canonicalCursorDigest' | 'consumerRevision' | 'lastBatchId' | 'configurationDigest'
  >,
  checkpoint: CheckpointBinding,
): boolean {
  return (
    proof.canonicalCursorDigest === checkpoint.cursorDigest &&
    proof.consumerRevision === checkpoint.revision &&
    proof.lastBatchId === checkpoint.lastBatchId &&
    proof.configurationDigest === checkpoint.configurationDigest
  );
}

/**
 * Public selected-object read API.
 *
 * The core reader validates each lookup independently. This facade additionally guarantees that
 * bounded multi-object and provenance-closure results cannot mix consumer revisions if the
 * canonical tail and projection advance between individual lookups. A final current-tail check
 * establishes one successful checkpoint boundary for the compound read. Concurrent advancement
 * fails closed; callers retry against the new current cursor.
 */
export class CanonicalObjectReadIndex extends CanonicalObjectReadIndexCore {
  override rehydrateAddresses(
    feed: CanonicalChangeFeed,
    addresses: readonly CanonicalObjectAddress[],
    options: CanonicalObjectReadOptions,
  ): readonly AnySelectedObjectProof[] {
    const before = this.currentCheckpoint(feed);
    const selected = super.rehydrateAddresses(feed, addresses, options);
    const after = this.currentCheckpoint(feed);
    if (!sameCheckpoint(before, after)) {
      throw new CanonicalObjectReadIndexIntegrityError(
        'canonical object rehydration advanced during the compound read',
      );
    }
    for (const proof of selected) {
      if (!proofMatchesCheckpoint(proof, before)) {
        throw new CanonicalObjectReadIndexIntegrityError(
          'canonical object rehydration crossed a projection checkpoint boundary',
        );
      }
    }
    return selected;
  }

  override rehydrateClaim(
    feed: CanonicalChangeFeed,
    claimId: string,
    options: CanonicalObjectReadOptions,
  ): RehydratedClaimProof {
    const before = this.currentCheckpoint(feed);
    const rehydrated = super.rehydrateClaim(feed, claimId, options);
    const after = this.currentCheckpoint(feed);
    if (!sameCheckpoint(before, after)) {
      throw new CanonicalObjectReadIndexIntegrityError(
        `claim provenance advanced during rehydration: ${claimId}`,
      );
    }
    const claim = rehydrated.claim;
    if (!proofMatchesCheckpoint(claim, before)) {
      throw new CanonicalObjectReadIndexIntegrityError(
        `claim provenance crossed a projection checkpoint boundary: ${claimId}`,
      );
    }
    for (const evidence of rehydrated.evidence) {
      if (!proofMatchesCheckpoint(evidence, before)) {
        throw new CanonicalObjectReadIndexIntegrityError(
          `claim provenance crossed a projection checkpoint boundary: ${claimId}`,
        );
      }
    }
    return rehydrated;
  }
}

export * from './object-read-index-contract.js';
