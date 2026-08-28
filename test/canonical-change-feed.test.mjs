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
  fingerprintMemoryEvents,
} from '../dist/index.js';
import {
  CanonicalChangeFeed,
  SqliteCanonicalLedger,
} from '../dist/durable/index.js';

function sha(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function temporaryDatabase() {
  const directory = mkdtempSync(join(tmpdir(), 'cl-change-feed-'));
  return {
    database: join(directory, 'canonical.sqlite'),
    cleanup() {
      rmSync(directory, { recursive: true, force: true });
    },
  };
}

function verifierIdentity(suffix = 'default') {
  return {
    id: `verifier/change-feed/${suffix}`,
    actor: `verifier/change-feed/${suffix}`,
    kind: 'deterministic',
    implementation: 'canonical-change-feed-test-verifier',
    version: '1',
    configDigest: sha(`verifier/change-feed/${suffix}/config`),
  };
}

function openLedger(options = {}) {
  const verifier = options.verifier ?? new TransitionVerifier(verifierIdentity(options.suffix));
  const ledger = new SqliteCanonicalLedger({ ...options, transitionVerifier: verifier });
  return { ledger, verifier };
}

function evidence(id, recordedAt) {
  return {
    id: `evidence/${id}`,
    scope: 'project/change-feed',
    kind: 'human-feedback',
    sourceGroups: [`origin/${id}`],
    authority: 'human-explicit',
    observedAt: recordedAt,
    sensitivity: 'public',
    taints: [],
    artifact: {
      uri: `memory://artifact/${id}`,
      digest: sha(`artifact/${id}`),
      sizeBytes: id.length,
      mediaType: 'text/plain',
      encryption: 'none',
      retention: 'durable',
    },
    preview: `change feed memory ${id}`,
    derivedFrom: [],
    labels: ['change-feed'],
  };
}

function issueEvidence(verifier, beforeEvents, id, recordedAt) {
  const record = evidence(id, recordedAt);
  const proposal = {
    id: `transition/change-feed/${id}`,
    proposer: 'memory-writer',
    baseFingerprint: fingerprintMemoryEvents(beforeEvents),
    authorizedScopes: ['project/change-feed'],
    declaredRisk: 'low',
    stateImpact: 'none',
    operations: [
      {
        id: `event/${id}`,
        type: 'evidence.captured',
        recordedAt,
        actor: 'source-ingestor',
        data: { evidence: record },
      },
    ],
    inputEvidenceIds: [record.id],
    ignoredInputEvidence: [],
    externalChecks: [],
    stateExpectations: [],
    rationale: 'exercise canonical change-feed delivery',
  };
  const result = verifier.verify(beforeEvents, proposal);
  assert.equal(result.verdict, 'accept');
  assert.equal(result.stagedAppend?.length, 1);
  const all = MemoryKernel.from([...beforeEvents, ...result.stagedAppend]).events();
  return { result, append: result.stagedAppend, all };
}

function request(base, result, number, recordedAt) {
  return {
    base,
    result,
    envelope: {
      idempotencyKey: `change-feed/${number}`,
      auditId: `audit/change-feed/${number}`,
      recordedAt,
      actor: 'independent-change-feed-auditor',
      committedBy: 'trusted-change-feed-host',
    },
  };
}

function commitAppend(ledger, verifier, existing, id, number, recordedAt) {
  const generated = issueEvidence(verifier, existing, id, recordedAt);
  const committed = ledger.commit(request(ledger.cursor(), generated.result, number, recordedAt));
  return { ...generated, committed };
}

test('a tail consumer receives the complete durable delta and advances only after ack', () => {
  const { ledger, verifier } = openLedger({ suffix: 'tail' });
  const feed = CanonicalChangeFeed.open(ledger);
  assert.equal(feed.poll(), undefined);

  const one = commitAppend(ledger, verifier, [], 'one', 1, 1);
  const batch = feed.poll();
  assert.ok(batch);
  assert.equal(batch.appendFromSeq, 1);
  assert.equal(batch.appendToSeq, 1);
  assert.deepEqual(batch.events, one.append);
  assert.equal(feed.status().pending, true);
  assert.equal(feed.status().lagEvents, 1);

  const checkpoint = feed.ack(batch);
  assert.equal(checkpoint.eventCount, 1);
  assert.equal(feed.status().lagEvents, 0);
  assert.equal(feed.poll(), undefined);
  ledger.close();
});

test('poll is stable while pending and copied batches cannot acknowledge progress', () => {
  const { ledger, verifier } = openLedger({ suffix: 'pending' });
  const feed = CanonicalChangeFeed.open(ledger);
  commitAppend(ledger, verifier, [], 'pending', 1, 1);

  const first = feed.poll();
  assert.ok(first);
  assert.equal(feed.poll(), first);
  assert.throws(() => feed.ack(structuredClone(first)), /outstanding capability/);

  feed.retry(first);
  const second = feed.poll();
  assert.ok(second);
  assert.notEqual(second, first);
  assert.equal(second.id, first.id);
  feed.ack(second);
  ledger.close();
});

test('a persisted read checkpoint resumes across process restart and catches only missed events', () => {
  const location = temporaryDatabase();
  try {
    const firstVerifier = new TransitionVerifier(verifierIdentity('restart-one'));
    const firstProcess = new SqliteCanonicalLedger({
      database: location.database,
      transitionVerifier: firstVerifier,
    });
    const one = commitAppend(firstProcess, firstVerifier, [], 'restart-one', 1, 1);
    const firstFeed = CanonicalChangeFeed.open(firstProcess, { startAt: 'tail' });
    const checkpoint = firstFeed.checkpoint();
    firstProcess.close();

    const secondVerifier = new TransitionVerifier(verifierIdentity('restart-two'));
    const secondProcess = new SqliteCanonicalLedger({
      database: location.database,
      transitionVerifier: secondVerifier,
    });
    const two = commitAppend(secondProcess, secondVerifier, one.all, 'restart-two', 2, 2);
    const resumed = CanonicalChangeFeed.open(secondProcess, { checkpoint });
    const batch = resumed.poll();
    assert.ok(batch);
    assert.deepEqual(batch.events, two.append);
    resumed.ack(batch);
    assert.equal(resumed.checkpoint().eventCount, 2);
    secondProcess.close();
  } finally {
    location.cleanup();
  }
});

test('a forged persisted checkpoint fails prefix verification', () => {
  const { ledger, verifier } = openLedger({ suffix: 'forged-checkpoint' });
  commitAppend(ledger, verifier, [], 'forged-checkpoint', 1, 1);
  const checkpoint = CanonicalChangeFeed.open(ledger, { startAt: 'tail' }).checkpoint();
  const forged = { ...checkpoint, chainDigest: sha('forged-chain') };
  assert.throws(
    () => CanonicalChangeFeed.open(ledger, { checkpoint: forged }),
    /genesis|conflicts|failed prefix verification/,
  );
  ledger.close();
});

test('lag larger than one budget is emitted as bounded contiguous batches', () => {
  const { ledger, verifier } = openLedger({ suffix: 'lag' });
  const feed = CanonicalChangeFeed.open(ledger, { maxBatchEvents: 1 });
  const first = commitAppend(ledger, verifier, [], 'lag-one', 1, 1);
  const second = commitAppend(ledger, verifier, first.all, 'lag-two', 2, 2);

  const batchOne = feed.poll();
  assert.ok(batchOne);
  assert.deepEqual(batchOne.events, first.append);
  assert.equal(batchOne.durableTailAtIssue.eventCount, 2);
  feed.ack(batchOne);

  const batchTwo = feed.poll();
  assert.ok(batchTwo);
  assert.deepEqual(batchTwo.events, second.append);
  assert.equal(batchTwo.base.eventCount, 1);
  feed.ack(batchTwo);
  assert.equal(feed.poll(), undefined);
  ledger.close();
});


test('the same bounded canonical range keeps a stable batch id when the durable tail advances', () => {
  const { ledger, verifier } = openLedger({ suffix: 'stable-batch-id' });
  const genesis = CanonicalChangeFeed.open(ledger).checkpoint();
  const one = commitAppend(ledger, verifier, [], 'stable-one', 1, 1);

  const firstFeed = CanonicalChangeFeed.open(ledger, { checkpoint: genesis, maxBatchEvents: 1 });
  const firstBatch = firstFeed.poll();
  assert.ok(firstBatch);
  assert.equal(firstBatch.durableTailAtIssue.eventCount, 1);

  commitAppend(ledger, verifier, one.all, 'stable-two', 2, 2);
  const retryFeed = CanonicalChangeFeed.open(ledger, { checkpoint: genesis, maxBatchEvents: 1 });
  const retryBatch = retryFeed.poll();
  assert.ok(retryBatch);
  assert.equal(retryBatch.durableTailAtIssue.eventCount, 2);
  assert.equal(retryBatch.id, firstBatch.id);
  assert.deepEqual(retryBatch.events, firstBatch.events);
  ledger.close();
});

test('ack remains valid if the durable ledger advances after the batch was issued', () => {
  const { ledger, verifier } = openLedger({ suffix: 'advance' });
  const feed = CanonicalChangeFeed.open(ledger);
  const one = commitAppend(ledger, verifier, [], 'advance-one', 1, 1);
  const batchOne = feed.poll();
  assert.ok(batchOne);

  const two = commitAppend(ledger, verifier, one.all, 'advance-two', 2, 2);
  feed.ack(batchOne);
  const batchTwo = feed.poll();
  assert.ok(batchTwo);
  assert.deepEqual(batchTwo.events, two.append);
  feed.ack(batchTwo);
  assert.equal(feed.checkpoint().eventCount, 2);
  ledger.close();
});

test('durable recovery rejects historical tampering before a change feed can open', () => {
  const location = temporaryDatabase();
  try {
    const verifier = new TransitionVerifier(verifierIdentity('tamper'));
    const writer = new SqliteCanonicalLedger({
      database: location.database,
      transitionVerifier: verifier,
    });
    const one = commitAppend(writer, verifier, [], 'tamper-one', 1, 1);
    commitAppend(writer, verifier, one.all, 'tamper-two', 2, 2);
    writer.close();

    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare('UPDATE cl_canonical_events SET event_json = ? WHERE seq = 1')
      .run('{"tampered":true}');
    attacker.close();

    assert.throws(
      () => new SqliteCanonicalLedger({ database: location.database }),
      /recovery audit failed|metadata diverges/,
    );
  } finally {
    location.cleanup();
  }
});


test('omitting a checkpoint starts at genesis while tail skipping is explicit', () => {
  const { ledger, verifier } = openLedger({ suffix: 'bootstrap' });
  const one = commitAppend(ledger, verifier, [], 'bootstrap', 1, 1);

  const safeDefault = CanonicalChangeFeed.open(ledger);
  const history = safeDefault.poll();
  assert.ok(history);
  assert.deepEqual(history.events, one.append);

  const explicitTail = CanonicalChangeFeed.open(ledger, { startAt: 'tail' });
  assert.equal(explicitTail.poll(), undefined);
  assert.throws(
    () => CanonicalChangeFeed.open(ledger, { checkpoint: safeDefault.checkpoint(), startAt: 'tail' }),
    /mutually exclusive/,
  );
  ledger.close();
});

test('consumer callbacks cannot reenter poll, ack, retry, or consume', () => {
  const { ledger, verifier } = openLedger({ suffix: 'reentrant' });
  const feed = CanonicalChangeFeed.open(ledger);
  commitAppend(ledger, verifier, [], 'reentrant', 1, 1);
  const batch = feed.poll();
  assert.ok(batch);

  assert.throws(
    () =>
      feed.consume(batch, () => {
        feed.ack(batch);
      }),
    /not allowed during an active consumer transaction/,
  );
  assert.equal(feed.poll(), batch);

  const value = feed.consume(batch, () => 'committed');
  assert.equal(value, 'committed');
  assert.equal(feed.poll(), undefined);
  ledger.close();
});

test('checkpoint and option bounds fail closed', () => {
  const ledger = new SqliteCanonicalLedger();
  assert.throws(() => CanonicalChangeFeed.open(ledger, { maxBatchEvents: 0 }), /maxBatchEvents/);
  assert.throws(
    () => CanonicalChangeFeed.open(ledger, { verificationChunkSize: 1_001 }),
    /verificationChunkSize/,
  );
  assert.throws(
    () =>
      CanonicalChangeFeed.open(ledger, {
        checkpoint: {
          schemaVersion: 1,
          eventCount: 0,
          lastSeq: 0,
          lastRecordedAt: 0,
          chainDigest: sha('not-genesis'),
        },
      }),
    /genesis/,
  );
  ledger.close();
});
