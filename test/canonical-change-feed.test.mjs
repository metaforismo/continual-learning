import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { MemoryKernel } from '../dist/index.js';
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

function appendEvidence(existing, id, recordedAt) {
  const kernel = MemoryKernel.from(existing);
  kernel.captureEvidence(
    { eventId: `event/${id}`, recordedAt, actor: 'human' },
    evidence(id, recordedAt),
  );
  return {
    all: kernel.events(),
    append: kernel.events().slice(existing.length),
  };
}

function transition(number) {
  return {
    proposalId: `proposal/feed/${number}`,
    proposalDigest: sha(`proposal/feed/${number}`),
    resultDigest: sha(`result/feed/${number}`),
    verdict: 'accept',
    actualRisk: 'low',
    policyId: 'policy/feed',
    policyVersion: '1',
    policyDigest: sha('policy/feed/v1'),
    verifierId: 'verifier/feed',
    verifierConfigDigest: sha('verifier/feed/v1'),
  };
}

function request(base, events, number, recordedAt) {
  const metadata = transition(number);
  return {
    base,
    idempotencyKey: `feed/${number}`,
    committedBy: 'trusted-host',
    events,
    transition: metadata,
    audit: {
      schemaVersion: 1,
      id: `audit/feed/${number}`,
      seq: number,
      recordedAt,
      actor: 'independent-verifier',
      proposalId: metadata.proposalId,
      proposalDigest: metadata.proposalDigest,
      resultDigest: metadata.resultDigest,
      verdict: metadata.verdict,
      actualRisk: metadata.actualRisk,
      policyId: metadata.policyId,
      policyVersion: metadata.policyVersion,
      policyDigest: metadata.policyDigest,
      verifierId: metadata.verifierId,
      verifierConfigDigest: metadata.verifierConfigDigest,
      findingCodes: [],
    },
  };
}

function commitAppend(ledger, existing, id, number, recordedAt) {
  const generated = appendEvidence(existing, id, recordedAt);
  const result = ledger.commit(request(ledger.cursor(), generated.append, number, recordedAt));
  return { ...generated, result };
}

test('a tail consumer receives the complete durable delta and advances only after ack', () => {
  const ledger = new SqliteCanonicalLedger();
  const feed = CanonicalChangeFeed.open(ledger);
  assert.equal(feed.poll(), undefined);

  const one = commitAppend(ledger, [], 'one', 1, 1);
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
  const ledger = new SqliteCanonicalLedger();
  const feed = CanonicalChangeFeed.open(ledger);
  commitAppend(ledger, [], 'pending', 1, 1);

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
    const firstProcess = new SqliteCanonicalLedger({ database: location.database });
    const one = commitAppend(firstProcess, [], 'restart-one', 1, 1);
    const firstFeed = CanonicalChangeFeed.open(firstProcess);
    const checkpoint = firstFeed.checkpoint();
    firstProcess.close();

    const secondProcess = new SqliteCanonicalLedger({ database: location.database });
    const two = commitAppend(secondProcess, one.all, 'restart-two', 2, 2);
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
  const ledger = new SqliteCanonicalLedger();
  commitAppend(ledger, [], 'forged-checkpoint', 1, 1);
  const checkpoint = CanonicalChangeFeed.open(ledger).checkpoint();
  const forged = { ...checkpoint, chainDigest: sha('forged-chain') };
  assert.throws(
    () => CanonicalChangeFeed.open(ledger, { checkpoint: forged }),
    /conflicts|failed prefix verification/,
  );
  ledger.close();
});

test('lag beyond the declared batch budget fails rather than silently truncating', () => {
  const ledger = new SqliteCanonicalLedger();
  const feed = CanonicalChangeFeed.open(ledger, { maxBatchEvents: 1 });
  const first = appendEvidence([], 'lag-one', 1);
  const second = appendEvidence(first.all, 'lag-two', 2);
  ledger.commit(request(ledger.cursor(), second.all, 1, 2));

  assert.throws(() => feed.poll(), /exceeds maxBatchEvents/);
  ledger.close();
});

test('ack remains valid if the durable ledger advances after the batch was issued', () => {
  const ledger = new SqliteCanonicalLedger();
  const feed = CanonicalChangeFeed.open(ledger);
  const one = commitAppend(ledger, [], 'advance-one', 1, 1);
  const batchOne = feed.poll();
  assert.ok(batchOne);

  const two = commitAppend(ledger, one.all, 'advance-two', 2, 2);
  feed.ack(batchOne);
  const batchTwo = feed.poll();
  assert.ok(batchTwo);
  assert.deepEqual(batchTwo.events, two.append);
  feed.ack(batchTwo);
  assert.equal(feed.checkpoint().eventCount, 2);
  ledger.close();
});

test('full-audit startup catches historical tampering that tail-only explicitly does not prove', () => {
  const location = temporaryDatabase();
  try {
    const writer = new SqliteCanonicalLedger({ database: location.database });
    const one = commitAppend(writer, [], 'tamper-one', 1, 1);
    commitAppend(writer, one.all, 'tamper-two', 2, 2);
    writer.close();

    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare('UPDATE cl_canonical_events SET event_json = ? WHERE seq = 1')
      .run('{"tampered":true}');
    attacker.close();

    const reader = new SqliteCanonicalLedger({ database: location.database });
    assert.throws(() => CanonicalChangeFeed.open(reader), /cannot open/);
    const tailOnly = CanonicalChangeFeed.open(reader, { startupVerification: 'tail-only' });
    assert.equal(tailOnly.status().lagEvents, 0);
    reader.close();
  } finally {
    location.cleanup();
  }
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
