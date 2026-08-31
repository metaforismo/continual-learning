import type { EvidenceRef } from '../domain.js';
import { canonicalReadCursorDigest, type CanonicalChangeFeed } from '../durable/change-feed.js';
import type { ConsumerProjectionReadTransaction } from '../durable/consumer-store.js';
import { contentDigest, snapshotScopeChain } from './canonical.js';
import {
  CANONICAL_OBJECT_READ_INDEX_SCHEMA_VERSION,
  CanonicalObjectReadIndexIntegrityError,
  MAX_OBJECT_READ_LOOKUPS,
  type AnySelectedObjectProof,
  type CanonicalClaimValidAtOptions,
  type CanonicalObjectAddress,
  type CanonicalObjectKind,
  type CanonicalObjectKnownAtOptions,
  type CanonicalObjectReadIndexAudit,
  type CanonicalObjectReadOptions,
  type ClaimReadRecord,
  type DecodedObjectReadHead,
  type DecodedObjectReadVersion,
  type EvidenceReadRecord,
  type IndexedClaimState,
  type IndexedEvidenceState,
  type ObjectReadBucketRow,
  type ObjectReadHeadRow,
  type ObjectReadMode,
  type ObjectReadNodeRow,
  type ObjectReadTreeKind,
  type ObjectReadTreeValue,
  type ObjectReadVersionRow,
  type RehydratedClaimProof,
  type SelectedClaimProof,
  type SelectedEvidenceProof,
  type SelectedObjectProof,
  type SparseBucketProof,
  type SparseBucketSibling,
  type VerifiedObjectReadMeta,
} from './object-read-index-contract.js';
import {
  assertDigest,
  assertInteger,
  assertObjectId,
  assertObjectKind,
  assertTreeKind,
  bucketForObject,
  claimCoversWorldTime,
  claimReadView,
  decodeHeadRow,
  decodeNodeRow,
  decodeVersionRow,
  deepFreeze,
  encodeString,
  evidenceReadView,
  evidenceReferenceMatches,
  headBucketDigest,
  sparseInternalDigest,
  sparseLeafDigest,
  versionBucketDigest,
} from './object-read-index-integrity.js';
import { CanonicalObjectReadIndexProjection } from './object-read-index-projection.js';

interface VerifiedBucket {
  readonly proof: SparseBucketProof;
  readonly heads?: readonly DecodedObjectReadHead[];
  readonly versions?: readonly DecodedObjectReadVersion[];
}

/**
 * Authenticated, rebuildable selected-object projection over the durable canonical change feed.
 *
 * It is not a second source of truth. Registration requires genesis, projection writes consume
 * exact verified batches, and current reads require the durable consumer cursor to equal the
 * canonical ledger tail observed by `CanonicalChangeFeed`.
 */
export class CanonicalObjectReadIndexReader extends CanonicalObjectReadIndexProjection {
  protected verifyBucket(
    tx: ConsumerProjectionReadTransaction,
    tree: ObjectReadTreeKind,
    bucket: number,
    meta: VerifiedObjectReadMeta,
  ): VerifiedBucket {
    if (!Number.isSafeInteger(bucket) || bucket < 0 || bucket >= this._bucketCount) {
      throw new CanonicalObjectReadIndexIntegrityError('selected object bucket is out of range');
    }
    const heads = tree === 'head' ? this.headRowsForBucket(tx, bucket) : undefined;
    const versions = tree === 'version' ? this.versionRowsForBucket(tx, bucket) : undefined;
    const rows = heads ?? versions ?? Object.freeze([]);
    const computedBucketDigest = tree === 'head'
      ? headBucketDigest(bucket, heads ?? Object.freeze([]))
      : versionBucketDigest(bucket, versions ?? Object.freeze([]));
    const stored = this.bucketRow(tx, tree, bucket);
    if (rows.length === 0) {
      if (stored !== undefined) {
        throw new CanonicalObjectReadIndexIntegrityError(
          `empty ${tree} bucket ${bucket} has a stored manifest`,
        );
      }
    } else {
      if (stored === undefined) {
        throw new CanonicalObjectReadIndexIntegrityError(
          `${tree} bucket ${bucket} manifest is missing`,
        );
      }
      const decoded = this.decodeBucketRow(stored, tree, bucket);
      if (decoded.itemCount !== rows.length || decoded.digest !== computedBucketDigest) {
        throw new CanonicalObjectReadIndexIntegrityError(
          `${tree} bucket ${bucket} failed integrity verification`,
        );
      }
    }

    const siblings: SparseBucketSibling[] = [];
    let current = rows.length === 0
      ? Object.freeze({
          digest: this._emptyDigests[tree][0] as string,
          itemCount: 0,
        })
      : Object.freeze({
          digest: sparseLeafDigest(tree, bucket, rows.length, computedBucketDigest),
          itemCount: rows.length,
        });
    let prefix = bucket;
    for (let level = 1; level <= this._bucketBits; level += 1) {
      const siblingPrefix = prefix % 2 === 0 ? prefix + 1 : prefix - 1;
      const sibling = this.treeValue(tx, tree, level - 1, siblingPrefix);
      const siblingSide = prefix % 2 === 0 ? 'right' : 'left';
      siblings.push(
        Object.freeze({
          level: level - 1,
          side: siblingSide,
          digest: sibling.digest,
          itemCount: sibling.itemCount,
        }),
      );
      const left = siblingSide === 'right' ? current : sibling;
      const right = siblingSide === 'right' ? sibling : current;
      current = Object.freeze({
        digest: sparseInternalDigest(tree, level, left.digest, right.digest),
        itemCount: left.itemCount + right.itemCount,
      });
      prefix = Math.floor(prefix / 2);
      const storedParent = this.nodeRow(tx, tree, level, prefix);
      if (current.itemCount === 0) {
        if (storedParent !== undefined) {
          throw new CanonicalObjectReadIndexIntegrityError(
            `empty sparse node is materialized at ${tree}/${level}/${prefix}`,
          );
        }
      } else {
        if (storedParent === undefined) {
          throw new CanonicalObjectReadIndexIntegrityError(
            `sparse node is missing at ${tree}/${level}/${prefix}`,
          );
        }
        const decodedParent = decodeNodeRow(storedParent, tree, level, prefix);
        if (
          decodedParent.digest !== current.digest ||
          decodedParent.itemCount !== current.itemCount
        ) {
          throw new CanonicalObjectReadIndexIntegrityError(
            `sparse node diverged at ${tree}/${level}/${prefix}`,
          );
        }
      }
    }
    const expectedRoot = tree === 'head' ? meta.headRootDigest : meta.versionRootDigest;
    const expectedCount = tree === 'head' ? meta.headCount : meta.versionCount;
    if (current.digest !== expectedRoot || current.itemCount !== expectedCount) {
      throw new CanonicalObjectReadIndexIntegrityError(
        `${tree} sparse proof does not reach the published object root`,
      );
    }
    return Object.freeze({
      proof: Object.freeze({
        tree,
        bucket,
        bucketItemCount: rows.length,
        bucketDigest: computedBucketDigest,
        siblings: Object.freeze(siblings),
        rootDigest: current.digest,
        rootItemCount: current.itemCount,
      }),
      ...(heads === undefined ? {} : { heads }),
      ...(versions === undefined ? {} : { versions }),
    });
  }

  protected historicalVersionRow(
    tx: ConsumerProjectionReadTransaction,
    kind: CanonicalObjectKind,
    canonicalId: string,
    knownAt: number,
  ): ObjectReadVersionRow | undefined {
    if (!Number.isFinite(knownAt)) throw new TypeError('knownAt must be finite');
    const t = this.tables();
    return tx.get(`SELECT kind, object_id_json, version_seq, recorded_at, known_to, state_json, state_digest, row_digest, bucket FROM ${t.versions} WHERE kind = ? AND object_id_json = ? AND recorded_at <= ? AND (known_to IS NULL OR known_to > ?) ORDER BY recorded_at DESC, version_seq DESC LIMIT ?`, kind, encodeString(canonicalId), knownAt, knownAt, 1) as ObjectReadVersionRow | undefined;
  }

  protected selectedVersion(
    tx: ConsumerProjectionReadTransaction,
    kind: CanonicalObjectKind,
    canonicalId: string,
    mode: ObjectReadMode,
    knownAt: number | undefined,
  ): DecodedObjectReadVersion | undefined {
    if (mode === 'current') {
      return this.currentState(tx, kind, canonicalId)?.version;
    }
    if (knownAt === undefined) throw new TypeError('historical object read requires knownAt');
    const row = this.historicalVersionRow(tx, kind, canonicalId, knownAt);
    return row === undefined ? undefined : this.decodeVersion(row);
  }

  protected lookup<TRecord extends EvidenceReadRecord | ClaimReadRecord>(
    feed: CanonicalChangeFeed,
    kind: TRecord['kind'],
    canonicalId: string,
    mode: ObjectReadMode,
    options: CanonicalObjectReadOptions & { readonly knownAt?: number; readonly validAt?: number },
  ): SelectedObjectProof<TRecord> | undefined {
    assertObjectId(canonicalId);
    const scopeChain = snapshotScopeChain(options.scopeChain);
    const allowedScopes = new Set(scopeChain);
    if (options.knownAt !== undefined && !Number.isFinite(options.knownAt)) {
      throw new TypeError('knownAt must be finite');
    }
    if (options.validAt !== undefined && !Number.isFinite(options.validAt)) {
      throw new TypeError('validAt must be finite');
    }
    const checkpoint = this.currentCheckpoint(feed);
    return this._store.readProjection(this._binding, (tx) => {
      const context = this.readContext(tx, checkpoint);
      const current = this.currentState(tx, kind, canonicalId);
      if (current === undefined) {
        const bucket = bucketForObject(
          'head',
          `${kind}\u0000${canonicalId}`,
          this._bucketCount,
        );
        const verified = this.verifyBucket(tx, 'head', bucket, context.meta);
        if (
          verified.heads?.some(
            (head) => head.kind === kind && head.canonicalId === canonicalId,
          ) === true
        ) {
          throw new CanonicalObjectReadIndexIntegrityError(
            `selected ${kind} is present in its authenticated bucket but missing from direct lookup`,
          );
        }
        return undefined;
      }

      const headVerified = this.verifyBucket(tx, 'head', current.head.bucket, context.meta);
      if (
        headVerified.heads?.some(
          (head) =>
            head.kind === kind &&
            head.canonicalId === canonicalId &&
            head.headDigest === current.head.headDigest,
        ) !== true
      ) {
        throw new CanonicalObjectReadIndexIntegrityError(
          `selected ${kind} head is absent from its authenticated bucket`,
        );
      }
      const currentVersionVerified = this.verifyBucket(
        tx,
        'version',
        current.version.bucket,
        context.meta,
      );
      if (
        currentVersionVerified.versions?.some(
          (version) =>
            version.kind === kind &&
            version.canonicalId === canonicalId &&
            version.versionSeq === current.version.versionSeq &&
            version.rowDigest === current.version.rowDigest,
        ) !== true
      ) {
        throw new CanonicalObjectReadIndexIntegrityError(
          `current ${kind} version is absent from its authenticated bucket`,
        );
      }

      const selected = this.selectedVersion(tx, kind, canonicalId, mode, options.knownAt);
      if (selected === undefined) {
        throw new CanonicalObjectReadIndexIntegrityError(
          `historical absence is not authenticated for ${kind}/${canonicalId}`,
        );
      }
      const selectedVerified = selected.rowDigest === current.version.rowDigest
        ? currentVersionVerified
        : this.verifyBucket(tx, 'version', selected.bucket, context.meta);
      if (
        selectedVerified.versions?.some(
          (version) =>
            version.kind === kind &&
            version.canonicalId === canonicalId &&
            version.versionSeq === selected.versionSeq &&
            version.rowDigest === selected.rowDigest,
        ) !== true
      ) {
        throw new CanonicalObjectReadIndexIntegrityError(
          `selected ${kind} version is absent from its authenticated bucket`,
        );
      }

      let record: EvidenceReadRecord | ClaimReadRecord;
      if (kind === 'evidence') {
        if (selected.state.kind !== 'evidence' || current.version.state.kind !== 'evidence') {
          throw new CanonicalObjectReadIndexIntegrityError('selected evidence state kind diverged');
        }
        record = evidenceReadView(selected.state, current.version.state);
        if (!allowedScopes.has(record.record.scope)) return undefined;
      } else {
        if (selected.state.kind !== 'claim' || current.version.state.kind !== 'claim') {
          throw new CanonicalObjectReadIndexIntegrityError('selected claim state kind diverged');
        }
        if (
          mode === 'valid-at' &&
          (options.validAt === undefined || !claimCoversWorldTime(selected.state, options.validAt))
        ) {
          return undefined;
        }
        record = claimReadView(selected.state);
        if (!allowedScopes.has(record.claim.key.scope)) return undefined;
      }

      const unsigned = deepFreeze({
        schemaVersion: CANONICAL_OBJECT_READ_INDEX_SCHEMA_VERSION,
        kind,
        canonicalId,
        mode,
        ...(options.knownAt === undefined ? {} : { knownAt: options.knownAt }),
        ...(options.validAt === undefined ? {} : { validAt: options.validAt }),
        record,
        stateDigest: selected.stateDigest,
        versionSeq: selected.versionSeq,
        recordedAt: selected.recordedAt,
        ...(selected.knownTo === undefined ? {} : { knownTo: selected.knownTo }),
        versionDigest: selected.rowDigest,
        headDigest: current.head.headDigest,
        headProof: headVerified.proof,
        versionProof: selectedVerified.proof,
        canonicalCursor: checkpoint.cursor,
        canonicalCursorDigest: checkpoint.cursorDigest,
        consumerRevision: checkpoint.revision,
        lastBatchId: checkpoint.lastBatchId,
        configurationDigest: checkpoint.configurationDigest,
      });
      return deepFreeze({
        ...unsigned,
        proofDigest: contentDigest({
          domain: 'cl-canonical-object-selected-proof-v1',
          proof: unsigned,
        }),
      }) as SelectedObjectProof<TRecord>;
    });
  }

  lookupEvidence(
    feed: CanonicalChangeFeed,
    canonicalId: string,
    options: CanonicalObjectReadOptions,
  ): SelectedEvidenceProof | undefined {
    return this.lookup<EvidenceReadRecord>(feed, 'evidence', canonicalId, 'current', options);
  }

  lookupClaim(
    feed: CanonicalChangeFeed,
    canonicalId: string,
    options: CanonicalObjectReadOptions,
  ): SelectedClaimProof | undefined {
    return this.lookup<ClaimReadRecord>(feed, 'claim', canonicalId, 'current', options);
  }

  lookupEvidenceKnownAt(
    feed: CanonicalChangeFeed,
    canonicalId: string,
    options: CanonicalObjectKnownAtOptions,
  ): SelectedEvidenceProof | undefined {
    return this.lookup<EvidenceReadRecord>(feed, 'evidence', canonicalId, 'known-at', options);
  }

  lookupClaimKnownAt(
    feed: CanonicalChangeFeed,
    canonicalId: string,
    options: CanonicalObjectKnownAtOptions,
  ): SelectedClaimProof | undefined {
    return this.lookup<ClaimReadRecord>(feed, 'claim', canonicalId, 'known-at', options);
  }

  lookupClaimValidAt(
    feed: CanonicalChangeFeed,
    canonicalId: string,
    options: CanonicalClaimValidAtOptions,
  ): SelectedClaimProof | undefined {
    return this.lookup<ClaimReadRecord>(feed, 'claim', canonicalId, 'valid-at', options);
  }

  rehydrateAddresses(
    feed: CanonicalChangeFeed,
    addresses: readonly CanonicalObjectAddress[],
    options: CanonicalObjectReadOptions,
  ): readonly AnySelectedObjectProof[] {
    if (!Array.isArray(addresses)) throw new TypeError('canonical object addresses must be an array');
    if (addresses.length > MAX_OBJECT_READ_LOOKUPS) {
      throw new RangeError(
        `canonical object rehydration cannot exceed ${MAX_OBJECT_READ_LOOKUPS} addresses`,
      );
    }
    const checkpoint = this.currentCheckpoint(feed);
    const snapshot = Object.freeze(
      Array.from(addresses, (address) => Object.freeze({ ...address })),
    );
    const seen = new Set<string>();
    const selected: AnySelectedObjectProof[] = [];
    for (const address of snapshot) {
      assertObjectKind(address.kind, 'canonical object address kind');
      assertObjectId(address.canonicalId);
      if (
        address.expectedCursorDigest !== undefined &&
        address.expectedCursorDigest !== checkpoint.cursorDigest
      ) {
        throw new CanonicalObjectReadIndexIntegrityError(
          `canonical object candidate is stale: ${address.kind}/${address.canonicalId}`,
        );
      }
      const identity = `${address.kind}\u0000${address.canonicalId}`;
      if (seen.has(identity)) {
        throw new CanonicalObjectReadIndexIntegrityError(
          `duplicate canonical object address: ${address.kind}/${address.canonicalId}`,
        );
      }
      seen.add(identity);
      const proof = address.kind === 'evidence'
        ? this.lookupEvidence(feed, address.canonicalId, options)
        : this.lookupClaim(feed, address.canonicalId, options);
      if (proof !== undefined) selected.push(proof);
    }
    return Object.freeze(selected);
  }

  rehydrateClaim(
    feed: CanonicalChangeFeed,
    claimId: string,
    options: CanonicalObjectReadOptions,
  ): RehydratedClaimProof {
    const claim = this.lookupClaim(feed, claimId, options);
    if (claim === undefined) {
      throw new CanonicalObjectReadIndexIntegrityError(
        `claim is unavailable or unauthorized: ${claimId}`,
      );
    }
    const evidenceById = new Map<string, SelectedEvidenceProof>();
    const unavailable: string[] = [];
    for (const reference of claim.record.claim.evidence) {
      const existing = evidenceById.get(reference.sourceId);
      const proof = existing ?? this.lookupEvidence(feed, reference.sourceId, options);
      if (proof === undefined) {
        unavailable.push(reference.sourceId);
        continue;
      }
      if (!evidenceReferenceMatches(proof.record.record, reference)) {
        throw new CanonicalObjectReadIndexIntegrityError(
          `claim evidence reference diverged: ${claimId} -> ${reference.sourceId}`,
        );
      }
      if (existing === undefined) evidenceById.set(reference.sourceId, proof);
      if (!proof.record.contentAvailable) unavailable.push(reference.sourceId);
    }
    const evidence = Object.freeze([...evidenceById.values()]);
    const unavailableEvidenceIds = Object.freeze([...new Set(unavailable)].sort());
    const unsigned = deepFreeze({
      claim,
      evidence,
      complete:
        unavailableEvidenceIds.length === 0 &&
        evidence.length === new Set(claim.record.claim.evidence.map((ref: EvidenceRef) => ref.sourceId)).size,
      unavailableEvidenceIds,
    });
    return deepFreeze({
      ...unsigned,
      proofDigest: contentDigest({
        domain: 'cl-canonical-claim-rehydration-proof-v1',
        value: unsigned,
      }),
    });
  }

}
