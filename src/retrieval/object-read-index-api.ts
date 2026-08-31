import type { CanonicalChangeFeed } from '../durable/change-feed.js';
import {
  CanonicalObjectReadIndexIntegrityError,
  type AnySelectedObjectProof,
  type CanonicalObjectAddress,
  type CanonicalObjectReadOptions,
  type RehydratedClaimProof,
} from './object-read-index-contract.js';
import { CanonicalObjectReadIndex as CanonicalObjectReadIndexCore } from './object-read-index.js';

/**
 * Public selected-object read API.
 *
 * The core reader validates each lookup independently. This facade additionally guarantees that
 * bounded multi-object and provenance-closure results cannot mix consumer revisions if the
 * canonical tail and projection advance between individual lookups. Concurrent advancement fails
 * closed; callers retry against the new current cursor.
 */
export class CanonicalObjectReadIndex extends CanonicalObjectReadIndexCore {
  override rehydrateAddresses(
    feed: CanonicalChangeFeed,
    addresses: readonly CanonicalObjectAddress[],
    options: CanonicalObjectReadOptions,
  ): readonly AnySelectedObjectProof[] {
    const checkpoint = this.currentCheckpoint(feed);
    const selected = super.rehydrateAddresses(feed, addresses, options);
    for (const proof of selected) {
      if (
        proof.canonicalCursorDigest !== checkpoint.cursorDigest ||
        proof.consumerRevision !== checkpoint.revision ||
        proof.lastBatchId !== checkpoint.lastBatchId ||
        proof.configurationDigest !== checkpoint.configurationDigest
      ) {
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
    const rehydrated = super.rehydrateClaim(feed, claimId, options);
    const claim = rehydrated.claim;
    for (const evidence of rehydrated.evidence) {
      if (
        evidence.canonicalCursorDigest !== claim.canonicalCursorDigest ||
        evidence.consumerRevision !== claim.consumerRevision ||
        evidence.lastBatchId !== claim.lastBatchId ||
        evidence.configurationDigest !== claim.configurationDigest
      ) {
        throw new CanonicalObjectReadIndexIntegrityError(
          `claim provenance crossed a projection checkpoint boundary: ${claimId}`,
        );
      }
    }
    return rehydrated;
  }
}

export * from './object-read-index-contract.js';
