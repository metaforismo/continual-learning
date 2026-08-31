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
import { CanonicalObjectReadIndexReader } from './object-read-index-reader.js';

export class CanonicalObjectReadIndex extends CanonicalObjectReadIndexReader {
  protected expectedSparseNodes(
    tree: ObjectReadTreeKind,
    buckets: ReadonlyMap<number, ObjectReadTreeValue>,
  ): ReadonlyMap<string, ObjectReadTreeValue> {
    const nodes = new Map<string, ObjectReadTreeValue>();
    let current = new Map<number, ObjectReadTreeValue>();
    for (const [bucket, value] of buckets) {
      current.set(
        bucket,
        Object.freeze({
          digest: sparseLeafDigest(tree, bucket, value.itemCount, value.digest),
          itemCount: value.itemCount,
        }),
      );
    }
    for (let level = 1; level <= this._bucketBits; level += 1) {
      const parents = new Set<number>();
      for (const childPrefix of current.keys()) parents.add(Math.floor(childPrefix / 2));
      const next = new Map<number, ObjectReadTreeValue>();
      const emptyChild = this._emptyDigests[tree][level - 1];
      if (emptyChild === undefined) throw new Error('empty sparse child digest is unavailable');
      for (const prefix of [...parents].sort((left, right) => left - right)) {
        const left = current.get(prefix * 2) ?? Object.freeze({ digest: emptyChild, itemCount: 0 });
        const right = current.get(prefix * 2 + 1) ?? Object.freeze({ digest: emptyChild, itemCount: 0 });
        const value = Object.freeze({
          digest: sparseInternalDigest(tree, level, left.digest, right.digest),
          itemCount: left.itemCount + right.itemCount,
        });
        if (value.itemCount > 0) {
          next.set(prefix, value);
          nodes.set(`${tree}\u0000${level}\u0000${prefix}`, value);
        }
      }
      current = next;
    }
    return nodes;
  }

  audit(): CanonicalObjectReadIndexAudit {
    const consumerAudit = this._store.audit(this._binding.consumerId);
    const checkpoint = this._store.checkpoint(this._binding.consumerId);
    if (checkpoint === undefined) {
      return Object.freeze({
        ok: false,
        errors: Object.freeze([
          ...(consumerAudit.ok ? [] : consumerAudit.errors),
          'canonical object read consumer has no checkpoint',
        ]),
        headCount: 0,
        versionCount: 0,
      });
    }
    return this._store.readProjection(this._binding, (tx) => {
      const errors: string[] = [...(consumerAudit.ok ? [] : consumerAudit.errors)];
      let headCount = 0;
      let versionCount = 0;
      try {
        const status = this.statusFromRead(tx, checkpoint);
        if (!status.fresh) errors.push(status.reason);
        const rawMeta = this.meta(tx);
        if (rawMeta === undefined) {
          throw new CanonicalObjectReadIndexIntegrityError('canonical object read metadata is missing');
        }
        const meta = this.decodeMeta(rawMeta);
        const t = this.tables();
        const rawHeads = tx.all(`SELECT kind, object_id_json, version_seq, recorded_at, state_digest, version_digest, head_digest, bucket FROM ${t.heads} ORDER BY kind, object_id_json`) as readonly ObjectReadHeadRow[];
        const rawVersions = tx.all(`SELECT kind, object_id_json, version_seq, recorded_at, known_to, state_json, state_digest, row_digest, bucket FROM ${t.versions} ORDER BY kind, object_id_json, version_seq`) as readonly ObjectReadVersionRow[];
        const heads = rawHeads.map((row) => decodeHeadRow(row, this._bucketCount));
        const versions = rawVersions.map((row) => decodeVersionRow(row, this._bucketCount));
        headCount = heads.length;
        versionCount = versions.length;

        const versionsByObject = new Map<string, DecodedObjectReadVersion[]>();
        for (const version of versions) {
          const identity = `${version.kind}\u0000${version.canonicalId}`;
          const list = versionsByObject.get(identity) ?? [];
          list.push(version);
          versionsByObject.set(identity, list);
        }
        for (const head of heads) {
          const identity = `${head.kind}\u0000${head.canonicalId}`;
          const list = versionsByObject.get(identity);
          if (list === undefined || list.length === 0) {
            throw new CanonicalObjectReadIndexIntegrityError(`head has no history: ${identity}`);
          }
          list.sort((left, right) => left.versionSeq - right.versionSeq);
          for (let index = 0; index < list.length; index += 1) {
            const version = list[index];
            const next = list[index + 1];
            if (version === undefined) throw new Error('version audit invariant failed');
            if (next === undefined) {
              if (version.knownTo !== undefined) {
                throw new CanonicalObjectReadIndexIntegrityError(`latest version is closed: ${identity}`);
              }
            } else if (version.knownTo !== next.recordedAt) {
              throw new CanonicalObjectReadIndexIntegrityError(
                `transaction interval chain failed: ${identity}@${version.versionSeq}`,
              );
            }
          }
          const latest = list.at(-1);
          if (
            latest === undefined ||
            latest.versionSeq !== head.versionSeq ||
            latest.rowDigest !== head.versionDigest ||
            latest.stateDigest !== head.stateDigest ||
            latest.recordedAt !== head.recordedAt
          ) {
            throw new CanonicalObjectReadIndexIntegrityError(`head/history parity failed: ${identity}`);
          }
          versionsByObject.delete(identity);
        }
        if (versionsByObject.size !== 0) {
          throw new CanonicalObjectReadIndexIntegrityError(
            'version history exists without an object head',
          );
        }

        const expectedBuckets = new Map<string, ObjectReadTreeValue>();
        const headGroups = new Map<number, DecodedObjectReadHead[]>();
        for (const head of heads) {
          const list = headGroups.get(head.bucket) ?? [];
          list.push(head);
          headGroups.set(head.bucket, list);
        }
        const versionGroups = new Map<number, DecodedObjectReadVersion[]>();
        for (const version of versions) {
          const list = versionGroups.get(version.bucket) ?? [];
          list.push(version);
          versionGroups.set(version.bucket, list);
        }
        for (const [bucket, members] of headGroups) {
          members.sort(
            (left, right) =>
              left.kind.localeCompare(right.kind) || left.canonicalId.localeCompare(right.canonicalId),
          );
          expectedBuckets.set(
            `head\u0000${bucket}`,
            Object.freeze({ digest: headBucketDigest(bucket, members), itemCount: members.length }),
          );
        }
        for (const [bucket, members] of versionGroups) {
          members.sort(
            (left, right) =>
              left.kind.localeCompare(right.kind) ||
              left.canonicalId.localeCompare(right.canonicalId) ||
              left.versionSeq - right.versionSeq,
          );
          expectedBuckets.set(
            `version\u0000${bucket}`,
            Object.freeze({ digest: versionBucketDigest(bucket, members), itemCount: members.length }),
          );
        }

        const rawBuckets = tx.all(`SELECT tree_kind, bucket, item_count, bucket_digest FROM ${t.buckets} ORDER BY tree_kind, bucket`) as readonly ObjectReadBucketRow[];
        if (rawBuckets.length !== expectedBuckets.size) {
          throw new CanonicalObjectReadIndexIntegrityError(
            'bucket manifest count differs from derived state',
          );
        }
        const treeBuckets: Record<ObjectReadTreeKind, Map<number, ObjectReadTreeValue>> = {
          head: new Map(),
          version: new Map(),
        };
        for (const row of rawBuckets) {
          assertTreeKind(row.tree_kind, 'audited bucket tree kind');
          assertInteger(row.bucket, 'audited bucket number', 0);
          const value = this.decodeBucketRow(row, row.tree_kind, row.bucket);
          const expected = expectedBuckets.get(`${row.tree_kind}\u0000${row.bucket}`);
          if (
            expected === undefined ||
            expected.digest !== value.digest ||
            expected.itemCount !== value.itemCount
          ) {
            throw new CanonicalObjectReadIndexIntegrityError(
              `bucket audit failed: ${row.tree_kind}/${row.bucket}`,
            );
          }
          treeBuckets[row.tree_kind].set(row.bucket, value);
        }

        const expectedNodes = new Map<string, ObjectReadTreeValue>([
          ...this.expectedSparseNodes('head', treeBuckets.head),
          ...this.expectedSparseNodes('version', treeBuckets.version),
        ]);
        const rawNodes = tx.all(`SELECT tree_kind, level, prefix, item_count, node_digest FROM ${t.nodes} ORDER BY tree_kind, level, prefix`) as readonly ObjectReadNodeRow[];
        if (rawNodes.length !== expectedNodes.size) {
          throw new CanonicalObjectReadIndexIntegrityError(
            'sparse node count differs from derived buckets',
          );
        }
        for (const row of rawNodes) {
          assertTreeKind(row.tree_kind, 'audited node tree kind');
          assertInteger(row.level, 'audited node level', 1);
          assertInteger(row.prefix, 'audited node prefix', 0);
          const value = decodeNodeRow(row, row.tree_kind, row.level, row.prefix);
          const expected = expectedNodes.get(`${row.tree_kind}\u0000${row.level}\u0000${row.prefix}`);
          if (
            expected === undefined ||
            expected.digest !== value.digest ||
            expected.itemCount !== value.itemCount
          ) {
            throw new CanonicalObjectReadIndexIntegrityError(
              `sparse node audit failed: ${row.tree_kind}/${row.level}/${row.prefix}`,
            );
          }
        }

        const headRoot = this.rootValue(tx, 'head');
        const versionRoot = this.rootValue(tx, 'version');
        if (
          meta.headCount !== heads.length ||
          meta.versionCount !== versions.length ||
          meta.headRootDigest !== headRoot.digest ||
          meta.versionRootDigest !== versionRoot.digest ||
          headRoot.itemCount !== heads.length ||
          versionRoot.itemCount !== versions.length ||
          meta.afterCursorDigest !== checkpoint.cursorDigest ||
          meta.lastBatchId !== checkpoint.lastBatchId ||
          meta.eventCount !== checkpoint.cursor.eventCount
        ) {
          throw new CanonicalObjectReadIndexIntegrityError(
            'canonical object publication metadata diverges from audited state',
          );
        }
      } catch (error) {
        errors.push(error instanceof Error ? error.message : 'unknown canonical object audit failure');
      }
      return Object.freeze({
        ok: errors.length === 0,
        errors: Object.freeze(errors),
        headCount,
        versionCount,
      });
    });
  }
}

export * from './object-read-index-contract.js';
