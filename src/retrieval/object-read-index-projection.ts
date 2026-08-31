import type {
  ClaimRecord,
  EvidenceRecord,
  MemoryEvent,
} from '../domain.js';
import {
  CanonicalChangeFeed,
  canonicalGenesisCursor,
  canonicalReadCursorDigest,
  sameCanonicalReadCursor,
  type CanonicalAppendBatch,
  type CanonicalReadCursor,
} from '../durable/change-feed.js';
import {
  SqliteConsumerCheckpointStore,
  type ConsumerApplyResult,
  type ConsumerBinding,
  type ConsumerProjectionReadTransaction,
  type ConsumerProjectionTransaction,
  type DurableConsumerCheckpoint,
  type DurableConsumerRegistration,
} from '../durable/consumer-store.js';
import { canonicalJson, contentDigest } from './canonical.js';
import {
  CANONICAL_OBJECT_READ_INDEX_SCHEMA_VERSION,
  CanonicalObjectReadIndexIntegrityError,
  CanonicalObjectReadIndexRebuildRequiredError,
  DEFAULT_OBJECT_READ_BUCKET_BITS,
  MAX_OBJECT_READ_BUCKET_BITS,
  MIN_OBJECT_READ_BUCKET_BITS,
  type CanonicalObjectKind,
  type CanonicalObjectReadIndexApplySummary,
  type CanonicalObjectReadIndexCatchUpSummary,
  type CanonicalObjectReadIndexOptions,
  type CanonicalObjectReadIndexStatus,
  type DecodedObjectReadHead,
  type DecodedObjectReadVersion,
  type IndexedCanonicalObjectState,
  type IndexedClaimState,
  type IndexedEvidenceState,
  type ObjectReadBucketRow,
  type ObjectReadContext,
  type ObjectReadHeadRow,
  type ObjectReadMetaRow,
  type ObjectReadNodeRow,
  type ObjectReadTreeKind,
  type ObjectReadTreeValue,
  type ObjectReadVersionRow,
  type VerifiedObjectReadMeta,
} from './object-read-index-contract.js';
import {
  assertDigest,
  assertInteger,
  assertObjectKind,
  assertProjectionPrefix,
  assertTreeKind,
  bucketForObject,
  canonicalClone,
  decodeHeadRow,
  decodeNodeRow,
  decodeString,
  decodeVersionRow,
  deepFreeze,
  encodeString,
  headBucketDigest,
  indexedStateDigest,
  objectHeadDigest,
  objectVersionDigest,
  sparseEmptyDigests,
  sparseInternalDigest,
  sparseLeafDigest,
  versionBucketDigest,
} from './object-read-index-integrity.js';
import { CanonicalObjectReadIndexStorage } from './object-read-index-storage.js';

interface EventProjectionDelta {
  readonly changedObjects: number;
  readonly newHeads: number;
  readonly newVersions: number;
}

interface AppendStateResult {
  readonly createdHead: boolean;
}

export class CanonicalObjectReadIndexProjection extends CanonicalObjectReadIndexStorage {
  protected appendStateVersion(
    tx: ConsumerProjectionTransaction,
    kind: CanonicalObjectKind,
    canonicalId: string,
    state: IndexedCanonicalObjectState,
    event: MemoryEvent,
    touchedHeads: Set<number>,
    touchedVersions: Set<number>,
  ): AppendStateResult {
    if (event.seq <= 0 || !Number.isSafeInteger(event.seq)) {
      throw new CanonicalObjectReadIndexIntegrityError('canonical event sequence is malformed');
    }
    if (!Number.isSafeInteger(event.recordedAt) || event.recordedAt < 0) {
      throw new CanonicalObjectReadIndexIntegrityError('canonical event recordedAt is malformed');
    }
    const t = this.tables();
    const existing = this.currentState(tx, kind, canonicalId);
    if (existing !== undefined) {
      const previous = existing.version;
      const closedUnsigned = Object.freeze({
        kind: previous.kind,
        canonicalId: previous.canonicalId,
        versionSeq: previous.versionSeq,
        recordedAt: previous.recordedAt,
        knownTo: event.recordedAt,
        stateDigest: previous.stateDigest,
        bucket: previous.bucket,
      });
      tx.run(`UPDATE ${t.versions} SET known_to = ?, row_digest = ? WHERE kind = ? AND object_id_json = ? AND version_seq = ?`, event.recordedAt, objectVersionDigest(closedUnsigned), kind, encodeString(canonicalId), previous.versionSeq);
      touchedVersions.add(previous.bucket);
    }

    const stateSnapshot = canonicalClone(state);
    const stateJson = canonicalJson(stateSnapshot);
    const stateDigest = indexedStateDigest(stateSnapshot);
    const versionBucket = bucketForObject(
      'version',
      `${kind}\u0000${canonicalId}\u0000${event.seq}`,
      this._bucketCount,
    );
    const versionUnsigned = Object.freeze({
      kind,
      canonicalId,
      versionSeq: event.seq,
      recordedAt: event.recordedAt,
      stateDigest,
      bucket: versionBucket,
    });
    const versionDigest = objectVersionDigest(versionUnsigned);
    tx.run(`INSERT INTO ${t.versions} (kind, object_id_json, version_seq, recorded_at, known_to, state_json, state_digest, row_digest, bucket) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, kind, encodeString(canonicalId), event.seq, event.recordedAt, null, stateJson, stateDigest, versionDigest, versionBucket);
    touchedVersions.add(versionBucket);

    const headBucket = bucketForObject(
      'head',
      `${kind}\u0000${canonicalId}`,
      this._bucketCount,
    );
    const headUnsigned = Object.freeze({
      kind,
      canonicalId,
      versionSeq: event.seq,
      recordedAt: event.recordedAt,
      stateDigest,
      versionDigest,
      bucket: headBucket,
    });
    const headDigest = objectHeadDigest(headUnsigned);
    tx.run(`DELETE FROM ${t.heads} WHERE kind = ? AND object_id_json = ?`, kind, encodeString(canonicalId));
    tx.run(`INSERT INTO ${t.heads} (kind, object_id_json, version_seq, recorded_at, state_digest, version_digest, head_digest, bucket) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, kind, encodeString(canonicalId), event.seq, event.recordedAt, stateDigest, versionDigest, headDigest, headBucket);
    touchedHeads.add(headBucket);
    return Object.freeze({ createdHead: existing === undefined });
  }

  protected requireEvidenceState(
    tx: ConsumerProjectionReadTransaction,
    evidenceId: string,
  ): IndexedEvidenceState {
    const current = this.currentState(tx, 'evidence', evidenceId);
    if (current === undefined || current.version.state.kind !== 'evidence') {
      throw new CanonicalObjectReadIndexIntegrityError(`unknown evidence state: ${evidenceId}`);
    }
    return current.version.state;
  }

  protected requireClaimState(
    tx: ConsumerProjectionReadTransaction,
    claimId: string,
  ): IndexedClaimState {
    const current = this.currentState(tx, 'claim', claimId);
    if (current === undefined || current.version.state.kind !== 'claim') {
      throw new CanonicalObjectReadIndexIntegrityError(`unknown claim state: ${claimId}`);
    }
    return current.version.state;
  }

  protected processEvent(
    tx: ConsumerProjectionTransaction,
    event: MemoryEvent,
    touchedHeads: Set<number>,
    touchedVersions: Set<number>,
  ): EventProjectionDelta {
    switch (event.type) {
      case 'evidence.captured': {
        const record = event.data.evidence;
        if (this.currentState(tx, 'evidence', record.id) !== undefined) {
          throw new CanonicalObjectReadIndexIntegrityError(
            `duplicate evidence object in read index: ${record.id}`,
          );
        }
        const state: IndexedEvidenceState = deepFreeze({
          kind: 'evidence',
          record: canonicalClone(record),
          availability: 'available',
          capturedSeq: event.seq,
        });
        const result = this.appendStateVersion(
          tx,
          'evidence',
          record.id,
          state,
          event,
          touchedHeads,
          touchedVersions,
        );
        return Object.freeze({ changedObjects: 1, newHeads: result.createdHead ? 1 : 0, newVersions: 1 });
      }
      case 'evidence.availability-changed': {
        const previous = this.requireEvidenceState(tx, event.data.evidenceId);
        if (previous.availability === 'deleted') {
          throw new CanonicalObjectReadIndexIntegrityError(
            `deleted evidence cannot transition again: ${event.data.evidenceId}`,
          );
        }
        if (previous.availability === event.data.availability) {
          throw new CanonicalObjectReadIndexIntegrityError(
            `evidence is already ${event.data.availability}: ${event.data.evidenceId}`,
          );
        }
        const state: IndexedEvidenceState = deepFreeze({
          kind: 'evidence',
          record: canonicalClone(previous.record),
          availability: event.data.availability,
          capturedSeq: previous.capturedSeq,
          latestAvailabilitySeq: event.seq,
        });
        this.appendStateVersion(
          tx,
          'evidence',
          event.data.evidenceId,
          state,
          event,
          touchedHeads,
          touchedVersions,
        );
        return Object.freeze({ changedObjects: 1, newHeads: 0, newVersions: 1 });
      }
      case 'claim.asserted': {
        const { claim, initialLifecycle } = event.data;
        if (this.currentState(tx, 'claim', claim.id) !== undefined) {
          throw new CanonicalObjectReadIndexIntegrityError(
            `duplicate claim object in read index: ${claim.id}`,
          );
        }
        const state: IndexedClaimState = deepFreeze({
          kind: 'claim',
          claim: canonicalClone(claim),
          lifecycle: initialLifecycle,
          assertedSeq: event.seq,
        });
        const result = this.appendStateVersion(
          tx,
          'claim',
          claim.id,
          state,
          event,
          touchedHeads,
          touchedVersions,
        );
        return Object.freeze({ changedObjects: 1, newHeads: result.createdHead ? 1 : 0, newVersions: 1 });
      }
      case 'claim.admitted': {
        const previous = this.requireClaimState(tx, event.data.claimId);
        if (previous.lifecycle !== 'quarantined') {
          throw new CanonicalObjectReadIndexIntegrityError(
            `claim ${event.data.claimId} is not quarantined`,
          );
        }
        const state: IndexedClaimState = deepFreeze({
          ...canonicalClone(previous),
          lifecycle: 'active',
          admittedSeq: event.seq,
        });
        this.appendStateVersion(
          tx,
          'claim',
          event.data.claimId,
          state,
          event,
          touchedHeads,
          touchedVersions,
        );
        return Object.freeze({ changedObjects: 1, newHeads: 0, newVersions: 1 });
      }
      case 'claim.superseded': {
        const previous = this.requireClaimState(tx, event.data.previousClaimId);
        const replacement = this.requireClaimState(tx, event.data.replacementClaimId);
        if (previous.lifecycle !== 'active' || replacement.lifecycle !== 'active') {
          throw new CanonicalObjectReadIndexIntegrityError(
            'claim supersession requires active previous and replacement claims',
          );
        }
        const state: IndexedClaimState = deepFreeze({
          ...canonicalClone(previous),
          lifecycle: 'superseded',
          supersededAt: event.data.effectiveAt,
          supersededBy: event.data.replacementClaimId,
        });
        this.appendStateVersion(
          tx,
          'claim',
          event.data.previousClaimId,
          state,
          event,
          touchedHeads,
          touchedVersions,
        );
        return Object.freeze({ changedObjects: 1, newHeads: 0, newVersions: 1 });
      }
      case 'claim.revoked': {
        const previous = this.requireClaimState(tx, event.data.claimId);
        const state: IndexedClaimState = deepFreeze({
          ...canonicalClone(previous),
          lifecycle: 'revoked',
          revokedSeq: event.seq,
        });
        this.appendStateVersion(
          tx,
          'claim',
          event.data.claimId,
          state,
          event,
          touchedHeads,
          touchedVersions,
        );
        return Object.freeze({ changedObjects: 1, newHeads: 0, newVersions: 1 });
      }
      case 'association.added':
      case 'outcome.recorded':
        return Object.freeze({ changedObjects: 0, newHeads: 0, newVersions: 0 });
    }
  }

  protected writeMeta(
    tx: ConsumerProjectionTransaction,
    batch: CanonicalAppendBatch,
    headCount: number,
    versionCount: number,
  ): VerifiedObjectReadMeta {
    const t = this.tables();
    const headRoot = this.rootValue(tx, 'head');
    const versionRoot = this.rootValue(tx, 'version');
    if (headRoot.itemCount !== headCount || versionRoot.itemCount !== versionCount) {
      throw new CanonicalObjectReadIndexIntegrityError(
        'sparse object roots do not match projected object counts',
      );
    }
    const afterCursorDigest = canonicalReadCursorDigest(batch.after);
    tx.run(`DELETE FROM ${t.meta} WHERE id = ?`, 1);
    tx.run(`INSERT INTO ${t.meta} (id, schema_version, config_digest, last_batch_id, after_cursor_digest, event_count, head_count, version_count, head_root_digest, version_root_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, 1, CANONICAL_OBJECT_READ_INDEX_SCHEMA_VERSION, this._configurationDigest, batch.id, afterCursorDigest, batch.after.eventCount, headCount, versionCount, headRoot.digest, versionRoot.digest);
    return Object.freeze({
      schemaVersion: CANONICAL_OBJECT_READ_INDEX_SCHEMA_VERSION,
      configDigest: this._configurationDigest,
      lastBatchId: batch.id,
      afterCursorDigest,
      eventCount: batch.after.eventCount,
      headCount,
      versionCount,
      headRootDigest: headRoot.digest,
      versionRootDigest: versionRoot.digest,
    });
  }

  apply(
    feed: CanonicalChangeFeed,
    batch: CanonicalAppendBatch,
  ): ConsumerApplyResult<CanonicalObjectReadIndexApplySummary> {
    return this._store.apply(feed, batch, this._binding, (tx, authorizedBatch) => {
      this.ensureSchema(tx);
      const rawPrevious = this.meta(tx);
      let headCount = 0;
      let versionCount = 0;
      if (rawPrevious === undefined) {
        this.initializeEmptyState(tx);
        if (authorizedBatch.base.eventCount !== 0) {
          throw new CanonicalObjectReadIndexRebuildRequiredError(
            'canonical object structural state is absent for a non-genesis checkpoint',
          );
        }
      } else {
        const previous = this.decodeMeta(rawPrevious);
        if (
          previous.eventCount !== authorizedBatch.base.eventCount ||
          previous.afterCursorDigest !== canonicalReadCursorDigest(authorizedBatch.base)
        ) {
          throw new CanonicalObjectReadIndexIntegrityError(
            'canonical object metadata does not match the batch base',
          );
        }
        headCount = previous.headCount;
        versionCount = previous.versionCount;
      }

      const touchedHeads = new Set<number>();
      const touchedVersions = new Set<number>();
      let changedObjects = 0;
      for (const event of authorizedBatch.events) {
        const delta = this.processEvent(tx, event, touchedHeads, touchedVersions);
        changedObjects += delta.changedObjects;
        headCount += delta.newHeads;
        versionCount += delta.newVersions;
      }
      for (const bucket of [...touchedHeads].sort((left, right) => left - right)) {
        this.refreshBucket(tx, 'head', bucket);
      }
      for (const bucket of [...touchedVersions].sort((left, right) => left - right)) {
        this.refreshBucket(tx, 'version', bucket);
      }
      this.writeMeta(tx, authorizedBatch, headCount, versionCount);
      return Object.freeze({
        appliedEvents: authorizedBatch.events.length,
        changedObjects,
        touchedHeadBuckets: touchedHeads.size,
        touchedVersionBuckets: touchedVersions.size,
      });
    });
  }

  catchUp(feed: CanonicalChangeFeed): CanonicalObjectReadIndexCatchUpSummary {
    if (!(feed instanceof CanonicalChangeFeed)) {
      throw new TypeError('canonical object read catch-up requires a CanonicalChangeFeed');
    }
    let batches = 0;
    let events = 0;
    let changedObjects = 0;
    for (;;) {
      const batch = feed.poll();
      if (batch === undefined) break;
      const result = this.apply(feed, batch);
      batches += 1;
      events += batch.events.length;
      changedObjects += result.value?.changedObjects ?? 0;
    }
    return Object.freeze({ batches, events, changedObjects });
  }

  protected statusFromRead(
    tx: ConsumerProjectionReadTransaction,
    checkpoint: DurableConsumerCheckpoint,
    registration?: DurableConsumerRegistration,
  ): CanonicalObjectReadIndexStatus {
    const raw = this.meta(tx);
    if (raw === undefined) {
      return Object.freeze({
        initialized: false,
        fresh: false,
        reason: 'canonical object read projection has not consumed a batch',
        ...(registration === undefined ? {} : { registration }),
        checkpoint,
        headCount: 0,
        versionCount: 0,
      });
    }
    const meta = this.decodeMeta(raw);
    const headRoot = this.rootValue(tx, 'head');
    const versionRoot = this.rootValue(tx, 'version');
    const fresh =
      checkpoint.configurationDigest === this._configurationDigest &&
      checkpoint.lastBatchId === meta.lastBatchId &&
      checkpoint.cursorDigest === meta.afterCursorDigest &&
      checkpoint.cursor.eventCount === meta.eventCount &&
      headRoot.digest === meta.headRootDigest &&
      headRoot.itemCount === meta.headCount &&
      versionRoot.digest === meta.versionRootDigest &&
      versionRoot.itemCount === meta.versionCount;
    return Object.freeze({
      initialized: true,
      fresh,
      reason: fresh
        ? 'canonical object read projection matches its durable consumer checkpoint'
        : 'canonical object read metadata or sparse roots diverge from the durable consumer checkpoint',
      ...(registration === undefined ? {} : { registration }),
      checkpoint,
      headCount: meta.headCount,
      versionCount: meta.versionCount,
      headRootDigest: meta.headRootDigest,
      versionRootDigest: meta.versionRootDigest,
    });
  }

  status(): CanonicalObjectReadIndexStatus {
    const checkpoint = this._store.checkpoint(this._binding.consumerId);
    const registration = this._store.registration(this._binding.consumerId);
    if (checkpoint === undefined) {
      return Object.freeze({
        initialized: false,
        fresh: false,
        reason: 'canonical object read consumer has no durable checkpoint',
        ...(registration === undefined ? {} : { registration }),
        headCount: 0,
        versionCount: 0,
      });
    }
    return this._store.readProjection(this._binding, (tx) =>
      this.statusFromRead(tx, checkpoint, registration),
    );
  }

  protected currentCheckpoint(feed: CanonicalChangeFeed): DurableConsumerCheckpoint {
    if (!(feed instanceof CanonicalChangeFeed)) {
      throw new TypeError('canonical object read requires the CanonicalChangeFeed observing the ledger');
    }
    const checkpoint = this._store.checkpoint(this._binding.consumerId);
    if (checkpoint === undefined) {
      throw new CanonicalObjectReadIndexIntegrityError(
        'canonical object read projection has no durable consumer checkpoint',
      );
    }
    const durableTail = feed.status().durableTail;
    if (!sameCanonicalReadCursor(checkpoint.cursor, durableTail)) {
      throw new CanonicalObjectReadIndexIntegrityError(
        'canonical object read projection is behind or forked from the current canonical ledger tail',
      );
    }
    return checkpoint;
  }

  protected readContext(
    tx: ConsumerProjectionReadTransaction,
    checkpoint: DurableConsumerCheckpoint,
  ): ObjectReadContext {
    const status = this.statusFromRead(tx, checkpoint);
    if (!status.fresh) {
      throw new CanonicalObjectReadIndexIntegrityError(
        `canonical object read projection is unavailable: ${status.reason}`,
      );
    }
    const raw = this.meta(tx);
    if (raw === undefined) {
      throw new CanonicalObjectReadIndexIntegrityError('canonical object read metadata is missing');
    }
    return Object.freeze({ checkpoint, meta: this.decodeMeta(raw) });
  }
}
