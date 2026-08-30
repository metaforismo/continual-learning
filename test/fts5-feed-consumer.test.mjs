import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import {
  MemoryKernel,
  TransitionVerifier,
  evidenceRefFor,
  fingerprintMemoryEvents,
} from '../dist/index.js';
import {
  CanonicalChangeFeed,
  SqliteCanonicalLedger,
  SqliteConsumerCheckpointStore,
} from '../dist/durable/index.js';
import {
  Fts5FeedConsumer,
  Fts5FeedRebuildRequiredError,
  SqliteFts5Projection,
} from '../dist/retrieval/index.js';
import { documentDigest } from '../dist/retrieval/canonical.js';

function sha(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function temporaryDatabase(prefix) {
  const directory = mkdtempSync(join(tmpdir(), `${prefix}-`));
  return {
    database: join(directory, 'state.sqlite'),
    cleanup() {
      rmSync(directory, { recursive: true, force: true });
    },
  };
}

function verifierIdentity(suffix = 'fts-feed') {
  return {
    id: `verifier/fts-feed/${suffix}`,
    actor: `verifier/fts-feed/${suffix}`,
    kind: 'deterministic',
    implementation: 'fts5-feed-consumer-test-verifier',
    version: '1',
    configDigest: sha(`verifier/fts-feed/${suffix}/config`),
  };
}

function externalVerifierIdentity(suffix = 'semantic') {
  return {
    id: `verifier/external/${suffix}`,
    actor: `verifier/external/${suffix}`,
    kind: 'tool',
    implementation: 'fts5-feed-external-check',
    version: '1',
    configDigest: sha(`verifier/external/${suffix}/config`),
  };
}

function evidence(id, recordedAt, overrides = {}) {
  const preview = overrides.preview ?? `searchable lighthouse memory ${id}`;
  return {
    id: `evidence/${id}`,
    scope: 'project/fts-feed',
    kind: 'human-feedback',
    sourceGroups: [`origin/${id}`],
    authority: 'human-explicit',
    observedAt: recordedAt,
    sensitivity: 'public',
    taints: [],
    artifact: {
      uri: `memory://artifact/${id}`,
      digest: sha(`artifact/${id}`),
      sizeBytes: preview.length,
      mediaType: 'text/plain',
      encryption: 'none',
      retention: 'durable',
    },
    preview,
    derivedFrom: [],
    labels: ['fts-feed'],
    ...overrides,
  };
}

function claimFromEvidence(record, id = 'editor-claim') {
  return {
    id: `claim/${id}`,
    key: {
      scope: record.scope,
      subject: 'francesco',
      predicate: 'preferred-editor',
    },
    value: 'zed',
    valid: { from: 10 },
    authority: record.authority,
    epistemicStatus: 'observed',
    confidence: 1,
    evidence: [evidenceRefFor(record, ['supports'])],
    derivedFrom: [],
    tags: ['editor', 'preference', 'fts-feed'],
  };
}

const editorSchema = Object.freeze({
  id: 'fts-feed-user-preferences',
  version: '1',
  slots: Object.freeze([
    Object.freeze({
      id: 'preferred-editor',
      domain: 'personal-preference',
      key: Object.freeze({
        scope: 'project/fts-feed',
        subject: 'francesco',
        predicate: 'preferred-editor',
      }),
      strategy: 'role-authority',
      evidencePolicy: Object.freeze([
        Object.freeze({
          role: 'supports',
          authorityPrecedence: Object.freeze([
            'human-explicit',
            'tool-verified',
            'external-source',
            'repeated-observation',
            'model-inference',
          ]),
          required: true,
        }),
      ]),
      minimumConfidence: 0.8,
    }),
  ]),
});

function proposal(beforeEvents, overrides = {}) {
  return {
    id: 'transition/fts-feed/default',
    proposer: 'memory-writer',
    baseFingerprint: fingerprintMemoryEvents(beforeEvents),
    authorizedScopes: ['project/fts-feed'],
    declaredRisk: 'low',
    stateImpact: 'none',
    operations: [],
    inputEvidenceIds: [],
    ignoredInputEvidence: [],
    externalChecks: [],
    stateExpectations: [],
    rationale: 'exercise FTS5 feed consumer',
    ...overrides,
  };
}

function issue(verifier, beforeEvents, transition) {
  const result = verifier.verify(beforeEvents, transition);
  assert.equal(result.verdict, 'accept', JSON.stringify(result.findings));
  assert.ok(result.stagedAppend?.length > 0);
  const all = MemoryKernel.from([...beforeEvents, ...result.stagedAppend]).events();
  return { result, all };
}

function issueEvidence(verifier, beforeEvents, id, recordedAt, overrides = {}) {
  const record = evidence(id, recordedAt, overrides);
  return {
    record,
    ...issue(
      verifier,
      beforeEvents,
      proposal(beforeEvents, {
        id: `transition/fts-feed/evidence/${id}`,
        declaredRisk:
          record.sensitivity === 'personal' ||
          record.derivedFrom.length > 0 ||
          record.taints.includes('prompt-like') ||
          record.taints.includes('untrusted-source') ||
          record.taints.includes('model-generated')
            ? 'medium'
            : 'low',
        operations: [
          {
            id: `event/fts-feed/evidence/${id}`,
            type: 'evidence.captured',
            recordedAt,
            actor: 'source-ingestor',
            data: { evidence: record },
          },
        ],
        inputEvidenceIds: [record.id],
      }),
    ),
  };
}

function issueActiveClaim(verifier, beforeEvents, support, report, id = 'editor-claim') {
  const claim = claimFromEvidence(support, id);
  const proposalId = `transition/fts-feed/claim/${id}`;
  const check = {
    id: `semantic-faithfulness/${id}`,
    kind: 'semantic-faithfulness',
    status: 'pass',
    verifier: externalVerifierIdentity(`claim/${id}`),
    subjectIds: [proposalId],
    reportDigest: report.artifact.digest,
    evidence: [evidenceRefFor(report, ['verifies'])],
  };
  const transition = proposal(beforeEvents, {
    id: proposalId,
    declaredRisk: 'high',
    stateImpact: 'declared',
    operations: [
      {
        id: `event/fts-feed/claim/${id}`,
        type: 'claim.asserted',
        recordedAt: 10,
        actor: 'memory-writer',
        data: { claim, initialLifecycle: 'active' },
      },
    ],
    inputEvidenceIds: [support.id, report.id],
    externalChecks: [check],
    stateExpectations: [
      {
        id: `expectation/${id}`,
        schema: editorSchema,
        request: { slotId: 'preferred-editor', view: 'current', validAt: 20 },
        mode: 'change',
        before: { status: 'unknown' },
        after: { status: 'current', value: claim.value },
      },
    ],
  });
  return { claim, ...issue(verifier, beforeEvents, transition) };
}

function issueRestriction(verifier, beforeEvents, target, report, recordedAt = 20) {
  const proposalId = `transition/fts-feed/restrict/${target.id}`;
  const check = {
    id: `semantic-faithfulness/restrict/${target.id}`,
    kind: 'semantic-faithfulness',
    status: 'pass',
    verifier: externalVerifierIdentity(`restrict/${target.id}`),
    subjectIds: [proposalId],
    reportDigest: report.artifact.digest,
    evidence: [evidenceRefFor(report, ['verifies'])],
  };
  return issue(
    verifier,
    beforeEvents,
    proposal(beforeEvents, {
      id: proposalId,
      declaredRisk: 'high',
      stateImpact: 'declared',
      operations: [
        {
          id: `event/fts-feed/restrict/${target.id}`,
          type: 'evidence.availability-changed',
          recordedAt,
          actor: 'privacy-controller',
          data: {
            evidenceId: target.id,
            availability: 'restricted',
            reason: 'privacy review requires temporary restriction',
          },
        },
      ],
      inputEvidenceIds: [target.id, report.id],
      externalChecks: [check],
      stateExpectations: [
        {
          id: `expectation/restrict/${target.id}`,
          schema: editorSchema,
          request: { slotId: 'preferred-editor', view: 'current', validAt: 20 },
          mode: 'change',
          before: { status: 'current', value: 'zed' },
          after: { status: 'unknown' },
        },
      ],
    }),
  );
}

function issueRestore(verifier, beforeEvents, target, report, recordedAt = 30) {
  const proposalId = `transition/fts-feed/restore/${target.id}`;
  const check = {
    id: `semantic-faithfulness/restore/${target.id}`,
    kind: 'semantic-faithfulness',
    status: 'pass',
    verifier: externalVerifierIdentity(`restore/${target.id}`),
    subjectIds: [proposalId],
    reportDigest: report.artifact.digest,
    evidence: [evidenceRefFor(report, ['verifies'])],
  };
  return issue(
    verifier,
    beforeEvents,
    proposal(beforeEvents, {
      id: proposalId,
      declaredRisk: 'high',
      stateImpact: 'declared',
      operations: [
        {
          id: `event/fts-feed/restore/${target.id}`,
          type: 'evidence.availability-changed',
          recordedAt,
          actor: 'privacy-controller',
          data: {
            evidenceId: target.id,
            availability: 'available',
            reason: 'privacy review completed and evidence may be used again',
          },
        },
      ],
      inputEvidenceIds: [target.id, report.id],
      externalChecks: [check],
      stateExpectations: [
        {
          id: `expectation/restore/${target.id}`,
          schema: editorSchema,
          request: { slotId: 'preferred-editor', view: 'current', validAt: 30 },
          mode: 'change',
          before: { status: 'unknown' },
          after: { status: 'current', value: 'zed' },
        },
      ],
    }),
  );
}

function request(base, result, number, recordedAt) {
  return {
    base,
    result,
    envelope: {
      idempotencyKey: `fts-feed-ledger/${number}`,
      auditId: `audit/fts-feed/${number}`,
      recordedAt,
      actor: 'fts-feed-auditor',
      committedBy: 'fts-feed-host',
    },
  };
}

function commitIssued(ledger, generated, number, recordedAt) {
  return ledger.commit(request(ledger.cursor(), generated.result, number, recordedAt));
}

function durableEvents(ledger) {
  const cursor = ledger.cursor();
  return cursor.eventCount === 0 ? [] : ledger.readRange(1, cursor.eventCount);
}

function makeRuntime(suffix = 'default', options = {}) {
  const ledgerLocation = temporaryDatabase(`cl-fts-feed-ledger-${suffix}`);
  const projectionLocation = temporaryDatabase(`cl-fts-feed-projection-${suffix}`);
  const verifier = new TransitionVerifier(verifierIdentity(suffix));
  const ledger = new SqliteCanonicalLedger({
    database: ledgerLocation.database,
    transitionVerifier: verifier,
  });
  const feed = CanonicalChangeFeed.open(ledger, options.feedOptions);
  const store = new SqliteConsumerCheckpointStore({
    database: projectionLocation.database,
    ...(options.storeOptions ?? {}),
  });
  const consumer = new Fts5FeedConsumer(store, {
    consumerId: `projection/fts/${suffix}`,
    projectionTablePrefix: `fts_${suffix.replace(/[^a-z0-9]+/g, '_')}_`,
    bucketCount: 16,
  });
  consumer.register(feed.checkpoint());
  return {
    ledger,
    verifier,
    feed,
    store,
    consumer,
    ledgerLocation,
    projectionLocation,
    cleanup() {
      ledger.close();
      store.close();
      ledgerLocation.cleanup();
      projectionLocation.cleanup();
    },
  };
}

function applyPending(runtime) {
  const batch = runtime.feed.poll();
  assert.ok(batch);
  const applied = runtime.consumer.apply(runtime.feed, batch);
  return { batch, applied };
}

test('canonical evidence flows through durable feed into address-only FTS search and exact rehydration', () => {
  const runtime = makeRuntime('e2e');
  try {
    const first = issueEvidence(runtime.verifier, [], 'lighthouse', 1, {
      preview: 'lighthouse migration decision for the project',
    });
    commitIssued(runtime.ledger, first, 1, 1);
    const { batch } = applyPending(runtime);

    const status = runtime.consumer.status();
    assert.equal(status.fresh, true);
    assert.equal(status.checkpoint?.lastBatchId, batch.id);
    assert.equal(runtime.consumer.audit().ok, true);

    const candidates = runtime.consumer.search(runtime.feed, 'lighthouse migration', {
      scopeChain: ['project/fts-feed'],
    });
    assert.equal(candidates.length, 1);
    assert.equal(candidates[0].canonicalId, first.record.id);
    assert.equal(Object.hasOwn(candidates[0], 'searchText'), false);
    assert.equal(Object.hasOwn(candidates[0], 'value'), false);

    const hydrated = runtime.consumer.rehydrate(durableEvents(runtime.ledger), candidates, {
      scopeChain: ['project/fts-feed'],
    });
    assert.equal(hydrated[0].evidence?.id, first.record.id);
    assert.equal(hydrated[0].evidence?.preview, first.record.preview);
  } finally {
    runtime.cleanup();
  }
});

test('personal evidence is retained only as non-searchable structural state under the default plaintext policy', () => {
  const runtime = makeRuntime('personal');
  try {
    const privateEvidence = issueEvidence(runtime.verifier, [], 'personal', 1, {
      preview: 'private narwhal phrase',
      sensitivity: 'personal',
    });
    commitIssued(runtime.ledger, privateEvidence, 1, 1);
    applyPending(runtime);

    assert.equal(
      runtime.consumer.search(runtime.feed, 'narwhal', { scopeChain: ['project/fts-feed'] }).length,
      0,
    );
    const state = runtime.store.readProjection(runtime.consumer.binding, (tx) =>
      tx.get('SELECT support_eligible, search_text FROM fts_personal_evidence_state'),
    );
    assert.equal(state.support_eligible, 0);
    assert.equal(state.search_text, null);
    assert.equal(runtime.consumer.audit().ok, true);
  } finally {
    runtime.cleanup();
  }
});

test('bounded catch-up consumes only the next canonical event per batch and remains fresh', () => {
  const runtime = makeRuntime('bounded', { feedOptions: { maxBatchEvents: 1 } });
  try {
    const first = issueEvidence(runtime.verifier, [], 'first', 1, { preview: 'first comet memory' });
    commitIssued(runtime.ledger, first, 1, 1);
    const second = issueEvidence(runtime.verifier, first.all, 'second', 2, { preview: 'second aurora memory' });
    commitIssued(runtime.ledger, second, 2, 2);

    const one = applyPending(runtime);
    assert.equal(one.batch.events.length, 1);
    assert.throws(
      () => runtime.consumer.search(runtime.feed, 'comet', { scopeChain: ['project/fts-feed'] }),
      /behind the current canonical ledger tail/,
    );

    const two = applyPending(runtime);
    assert.equal(two.batch.events.length, 1);
    assert.equal(runtime.feed.poll(), undefined);
    assert.equal(runtime.consumer.search(runtime.feed, 'aurora', { scopeChain: ['project/fts-feed'] }).length, 1);
    assert.equal(runtime.consumer.status().fresh, true);
  } finally {
    runtime.cleanup();
  }
});

test('active claim indexing depends on canonical supporting evidence and restriction scrubs both source and claim', () => {
  const runtime = makeRuntime('restriction');
  try {
    const support = issueEvidence(runtime.verifier, [], 'editor-support', 1, {
      preview: 'Zed editor preference source',
    });
    commitIssued(runtime.ledger, support, 1, 1);
    const report = issueEvidence(runtime.verifier, support.all, 'claim-report', 2, {
      preview: 'independent semantic verification report',
      kind: 'tool-result',
      authority: 'tool-verified',
      sourceGroups: ['origin/claim-report'],
    });
    commitIssued(runtime.ledger, report, 2, 2);
    const active = issueActiveClaim(runtime.verifier, report.all, support.record, report.record);
    commitIssued(runtime.ledger, active, 3, 10);

    for (;;) {
      const batch = runtime.feed.poll();
      if (batch === undefined) break;
      runtime.consumer.apply(runtime.feed, batch);
    }

    const before = runtime.consumer.search(runtime.feed, 'editor preference', {
      scopeChain: ['project/fts-feed'],
    });
    assert.ok(before.some((item) => item.kind === 'claim' && item.canonicalId === active.claim.id));
    assert.ok(runtime.consumer.search(runtime.feed, 'Zed editor', { scopeChain: ['project/fts-feed'] }).length >= 1);

    const privacyReport = issueEvidence(runtime.verifier, active.all, 'privacy-report', 11, {
      preview: 'independent privacy restriction verification',
      kind: 'tool-result',
      authority: 'tool-verified',
      sourceGroups: ['origin/privacy-report'],
    });
    commitIssued(runtime.ledger, privacyReport, 4, 11);
    const restricted = issueRestriction(runtime.verifier, privacyReport.all, support.record, privacyReport.record, 12);
    commitIssued(runtime.ledger, restricted, 5, 12);

    for (;;) {
      const batch = runtime.feed.poll();
      if (batch === undefined) break;
      runtime.consumer.apply(runtime.feed, batch);
    }

    assert.equal(runtime.consumer.search(runtime.feed, 'Zed editor', { scopeChain: ['project/fts-feed'] }).length, 0);
    assert.equal(runtime.consumer.search(runtime.feed, 'editor preference', { scopeChain: ['project/fts-feed'] }).some((item) => item.canonicalId === active.claim.id), false);
    assert.equal(runtime.consumer.audit().ok, true);

    const restoreReport = issueEvidence(runtime.verifier, restricted.all, 'restore-report', 21, {
      preview: 'independent privacy restoration verification',
      kind: 'tool-result',
      authority: 'tool-verified',
      sourceGroups: ['origin/restore-report'],
    });
    commitIssued(runtime.ledger, restoreReport, 6, 21);
    applyPending(runtime);
    const restored = issueRestore(runtime.verifier, restoreReport.all, support.record, restoreReport.record, 22);
    commitIssued(runtime.ledger, restored, 7, 22);
    const restoreBatch = runtime.feed.poll();
    assert.ok(restoreBatch);
    assert.throws(
      () => runtime.consumer.apply(runtime.feed, restoreBatch),
      (error) => error instanceof Fts5FeedRebuildRequiredError,
    );
    assert.equal(runtime.feed.retry(restoreBatch), restoreBatch);
    assert.throws(
      () => runtime.consumer.search(runtime.feed, 'Zed editor', { scopeChain: ['project/fts-feed'] }),
      /behind the current canonical ledger tail/,
    );
  } finally {
    runtime.cleanup();
  }
});

test('consumer fault rollback preserves FTS state, receipt, cursor, and exact batch retry', () => {
  let fail = true;
  const runtime = makeRuntime('rollback', {
    storeOptions: {
      faultInjector(phase) {
        if (fail && phase === 'after-receipt') throw new Error('injected FTS consumer failure');
      },
    },
  });
  try {
    const first = issueEvidence(runtime.verifier, [], 'rollback', 1, { preview: 'rollback canary phrase' });
    commitIssued(runtime.ledger, first, 1, 1);
    const batch = runtime.feed.poll();
    assert.ok(batch);

    assert.throws(() => runtime.consumer.apply(runtime.feed, batch), /injected FTS consumer failure/);
    assert.equal(runtime.feed.retry(batch), batch);
    assert.equal(runtime.store.checkpoint(runtime.consumer.binding.consumerId), undefined);

    fail = false;
    runtime.consumer.apply(runtime.feed, batch);
    assert.equal(runtime.consumer.search(runtime.feed, 'rollback canary', { scopeChain: ['project/fts-feed'] }).length, 1);
    assert.equal(runtime.consumer.audit().ok, true);
  } finally {
    runtime.cleanup();
  }
});

test('projection read capability is read-only and revoked after the callback', () => {
  const runtime = makeRuntime('readcap');
  try {
    const first = issueEvidence(runtime.verifier, [], 'readcap', 1, { preview: 'read capability memory' });
    commitIssued(runtime.ledger, first, 1, 1);
    applyPending(runtime);

    let leaked;
    const rows = runtime.store.readProjection(runtime.consumer.binding, (tx) => {
      leaked = tx;
      assert.equal(typeof tx.run, 'undefined');
      return tx.all('SELECT canonical_id_json FROM fts_readcap_documents ORDER BY canonical_id_json');
    });
    assert.equal(rows.length, 1);
    assert.throws(() => leaked.all('SELECT canonical_id_json FROM fts_readcap_documents'), /no longer active|revoked/);
  } finally {
    runtime.cleanup();
  }
});

test('tampered shadow FTS rows and document rows fail closed before a candidate is trusted', () => {
  const runtime = makeRuntime('tamper');
  try {
    const first = issueEvidence(runtime.verifier, [], 'tamper', 1, { preview: 'integrity constellation phrase' });
    commitIssued(runtime.ledger, first, 1, 1);
    applyPending(runtime);
    runtime.store.close();

    const raw = new DatabaseSync(runtime.projectionLocation.database);
    raw.prepare("UPDATE fts_tamper_fts SET search_text = 'forged constellation phrase'").run();
    raw.close();

    const reopenedStore = new SqliteConsumerCheckpointStore({ database: runtime.projectionLocation.database });
    const reopened = new Fts5FeedConsumer(reopenedStore, {
      consumerId: runtime.consumer.binding.consumerId,
      projectionTablePrefix: 'fts_tamper_',
      bucketCount: 16,
    });
    assert.throws(
      () => reopened.search(runtime.feed, 'forged', { scopeChain: ['project/fts-feed'] }),
      /shadow row diverged|integrity|unavailable/,
    );
    assert.equal(reopened.audit().ok, false);
    reopenedStore.close();

    // Prevent runtime.cleanup() from closing the already-closed original store twice through SQLite.
    runtime.ledger.close();
    runtime.ledgerLocation.cleanup();
    runtime.projectionLocation.cleanup();
  } catch (error) {
    // runtime.cleanup is intentionally not called because the store was closed for raw tampering.
    throw error;
  }
});

test('coherent document and FTS row tampering is rejected by the selected bucket manifest', () => {
  const runtime = makeRuntime('bucket-tamper');
  let originalStoreClosed = false;
  try {
    const first = issueEvidence(runtime.verifier, [], 'bucket-tamper', 1, {
      preview: 'original nebula integrity phrase',
    });
    commitIssued(runtime.ledger, first, 1, 1);
    applyPending(runtime);
    runtime.store.close();
    originalStoreClosed = true;

    const forgedText = 'forged nebula integrity phrase';
    const forgedDigest = documentDigest({
      canonicalId: first.record.id,
      kind: 'evidence',
      scope: first.record.scope,
      lifecycle: '',
      sourceDigest: first.record.artifact.digest,
      searchText: forgedText,
    });
    const raw = new DatabaseSync(runtime.projectionLocation.database);
    raw.prepare('UPDATE fts_bucket_tamper_documents SET search_text = ?, entry_digest = ?').run(forgedText, forgedDigest);
    raw.prepare('UPDATE fts_bucket_tamper_fts SET search_text = ?, entry_digest = ?').run(forgedText, forgedDigest);
    raw.close();

    const reopenedStore = new SqliteConsumerCheckpointStore({ database: runtime.projectionLocation.database });
    const reopened = new Fts5FeedConsumer(reopenedStore, {
      consumerId: runtime.consumer.binding.consumerId,
      projectionTablePrefix: 'fts_bucket_tamper_',
      bucketCount: 16,
    });
    assert.throws(
      () => reopened.search(runtime.feed, 'forged nebula', { scopeChain: ['project/fts-feed'] }),
      /bucket .*failed integrity verification/,
    );
    assert.equal(reopened.audit().ok, false);
    reopenedStore.close();
  } finally {
    runtime.ledger.close();
    if (!originalStoreClosed) runtime.store.close();
    runtime.ledgerLocation.cleanup();
    runtime.projectionLocation.cleanup();
  }
});

test('feed-driven lexical results match a clean canonical rebuild for the same current history', () => {
  const runtime = makeRuntime('parity');
  const rebuildLocation = temporaryDatabase('cl-fts-feed-rebuild-parity');
  try {
    const first = issueEvidence(runtime.verifier, [], 'parity-alpha', 1, {
      preview: 'alpha observatory migration memory',
    });
    commitIssued(runtime.ledger, first, 1, 1);
    const second = issueEvidence(runtime.verifier, first.all, 'parity-beta', 2, {
      preview: 'beta observatory migration memory',
    });
    commitIssued(runtime.ledger, second, 2, 2);
    for (;;) {
      const batch = runtime.feed.poll();
      if (batch === undefined) break;
      runtime.consumer.apply(runtime.feed, batch);
    }

    const events = durableEvents(runtime.ledger);
    const rebuilt = SqliteFts5Projection.open(rebuildLocation.database);
    rebuilt.rebuild(events, 3);
    const feedIds = runtime.consumer
      .search(runtime.feed, 'observatory migration', { scopeChain: ['project/fts-feed'] })
      .map((candidate) => `${candidate.kind}:${candidate.canonicalId}`)
      .sort();
    const rebuildIds = rebuilt
      .search(events, 'observatory migration', { scopeChain: ['project/fts-feed'] })
      .map((candidate) => `${candidate.kind}:${candidate.canonicalId}`)
      .sort();
    assert.deepEqual(feedIds, rebuildIds);
    rebuilt.close();
  } finally {
    runtime.cleanup();
    rebuildLocation.cleanup();
  }
});

test('non-genesis registration is rejected because it would silently skip searchable history', () => {
  const ledgerLocation = temporaryDatabase('cl-fts-feed-ledger-nongenesis');
  const projectionLocation = temporaryDatabase('cl-fts-feed-projection-nongenesis');
  const verifier = new TransitionVerifier(verifierIdentity('nongenesis'));
  const ledger = new SqliteCanonicalLedger({ database: ledgerLocation.database, transitionVerifier: verifier });
  const first = issueEvidence(verifier, [], 'historical', 1, { preview: 'historical memory that must not be skipped' });
  commitIssued(ledger, first, 1, 1);
  const tailFeed = CanonicalChangeFeed.open(ledger, { startAt: 'tail' });
  const store = new SqliteConsumerCheckpointStore({ database: projectionLocation.database });
  const consumer = new Fts5FeedConsumer(store, {
    consumerId: 'projection/fts/nongenesis',
    projectionTablePrefix: 'fts_nongenesis_',
    bucketCount: 16,
  });
  try {
    assert.throws(() => consumer.register(tailFeed.checkpoint()), Fts5FeedRebuildRequiredError);
  } finally {
    ledger.close();
    store.close();
    ledgerLocation.cleanup();
    projectionLocation.cleanup();
  }
});
