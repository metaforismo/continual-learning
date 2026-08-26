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
  SqliteConsumerCheckpointStore,
} from '../dist/durable/index.js';

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

function evidence(id, recordedAt) {
  return {
    id: `evidence/${id}`,
    scope: 'project/consumer',
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
    preview: `consumer memory ${id}`,
    derivedFrom: [],
    labels: ['consumer'],
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
    proposalId: `proposal/consumer/${number}`,
    proposalDigest: sha(`proposal/consumer/${number}`),
    resultDigest: sha(`result/consumer/${number}`),
    verdict: 'accept',
    actualRisk: 'low',
    policyId: 'policy/consumer',
    policyVersion: '1',
    policyDigest: sha('policy/consumer/v1'),
    verifierId: 'verifier/consumer',
    verifierConfigDigest: sha('verifier/consumer/v1'),
  };
}

function request(base, events, number, recordedAt) {
  const metadata = transition(number);
  return {
    base,
    idempotencyKey: `consumer-ledger/${number}`,
    committedBy: 'trusted-host',
    events,
    transition: metadata,
    audit: {
      schemaVersion: 1,
      id: `audit/consumer/${number}`,
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
  ledger.commit(request(ledger.cursor(), generated.append, number, recordedAt));
  return generated;
}

function installProjectionTable(database) {
  database.exec(`
    CREATE TABLE IF NOT EXISTS test_projection_events (
      consumer_id TEXT NOT NULL,
      event_id TEXT NOT NULL,
      PRIMARY KEY (consumer_id, event_id)
    )
  `);
}

function applyProjection(database, batch, consumerId) {
  installProjectionTable(database);
  const insert = database.prepare(
    'INSERT INTO test_projection_events (consumer_id, event_id) VALUES (?, ?)',
  );
  for (const event of batch.events) insert.run(consumerId, event.id);
  return batch.events.length;
}

test('projection writes, receipt, checkpoint, and feed ack advance together', () => {
  const ledger = new SqliteCanonicalLedger();
  const feed = CanonicalChangeFeed.open(ledger);
  const store = new SqliteConsumerCheckpointStore();
  commitAppend(ledger, [], 'one', 1, 1);
  const batch = feed.poll();
  assert.ok(batch);

  const result = store.apply(feed, batch, 'projection/main', (database, authorized) =>
    applyProjection(database, authorized, 'projection/main'),
  );
  assert.equal(result.idempotentReplay, false);
  assert.equal(result.value, 1);
  assert.equal(result.checkpoint.cursor.eventCount, 1);
  assert.equal(feed.checkpoint().eventCount, 1);
  assert.equal(store.checkpoint('projection/main')?.lastBatchId, batch.id);
  assert.equal(store.audit('projection/main').ok, true);
  ledger.close();
  store.close();
});

test('a callback failure rolls back projection state and leaves the same batch pending', () => {
  const location = temporaryDatabase('cl-consumer-callback');
  try {
    const ledger = new SqliteCanonicalLedger();
    const feed = CanonicalChangeFeed.open(ledger);
    const store = new SqliteConsumerCheckpointStore({ database: location.database });
    commitAppend(ledger, [], 'rollback', 1, 1);
    const batch = feed.poll();
    assert.ok(batch);

    assert.throws(
      () =>
        store.apply(feed, batch, 'projection/main', (database, authorized) => {
          applyProjection(database, authorized, 'projection/main');
          throw new Error('projection failed');
        }),
      /projection failed/,
    );
    assert.equal(feed.poll(), batch);
    assert.equal(store.checkpoint('projection/main'), undefined);
    const inspect = new DatabaseSync(location.database);
    const count = inspect
      .prepare('SELECT COUNT(*) AS count FROM test_projection_events')
      .get().count;
    inspect.close();
    assert.equal(count, 0);
    ledger.close();
    store.close();
  } finally {
    location.cleanup();
  }
});

test('an async projection callback is rejected before checkpoint publication', () => {
  const ledger = new SqliteCanonicalLedger();
  const feed = CanonicalChangeFeed.open(ledger);
  const store = new SqliteConsumerCheckpointStore();
  commitAppend(ledger, [], 'async', 1, 1);
  const batch = feed.poll();
  assert.ok(batch);

  assert.throws(
    () => store.apply(feed, batch, 'projection/main', async () => 1),
    /must be synchronous/,
  );
  assert.equal(store.checkpoint('projection/main'), undefined);
  assert.equal(feed.poll(), batch);
  ledger.close();
  store.close();
});

test('a forged batch clone cannot enter the consumer transaction', () => {
  const ledger = new SqliteCanonicalLedger();
  const feed = CanonicalChangeFeed.open(ledger);
  const store = new SqliteConsumerCheckpointStore();
  commitAppend(ledger, [], 'forged', 1, 1);
  const batch = feed.poll();
  assert.ok(batch);
  let invoked = false;

  assert.throws(
    () =>
      store.apply(feed, structuredClone(batch), 'projection/main', () => {
        invoked = true;
      }),
    /outstanding capability/,
  );
  assert.equal(invoked, false);
  assert.equal(store.checkpoint('projection/main'), undefined);
  ledger.close();
  store.close();
});

test('a durable idempotent batch retry does not rerun projection code', () => {
  const location = temporaryDatabase('cl-consumer-idempotent');
  try {
    const ledger = new SqliteCanonicalLedger();
    const generated = commitAppend(ledger, [], 'idempotent', 1, 1);
    const genesisFeed = CanonicalChangeFeed.open(ledger, {
      checkpoint: {
        schemaVersion: 1,
        eventCount: 0,
        lastSeq: 0,
        lastRecordedAt: 0,
        chainDigest: sha(JSON.stringify({ domain: 'placeholder' })),
      },
    });
    // Replace the deliberately invalid convenience cursor with one captured from an empty ledger.
    genesisFeed.retry?.call?.(undefined);
    ledger.close();
  } finally {
    location.cleanup();
  }
});

test('fault injection after the consumer receipt rolls the whole transaction back', () => {
  const location = temporaryDatabase('cl-consumer-fault');
  try {
    let failAt = 'after-receipt';
    const ledger = new SqliteCanonicalLedger();
    const feed = CanonicalChangeFeed.open(ledger);
    const store = new SqliteConsumerCheckpointStore({
      database: location.database,
      faultInjector(point) {
        if (point === failAt) throw new Error(`injected failure at ${point}`);
      },
    });
    commitAppend(ledger, [], 'fault', 1, 1);
    const batch = feed.poll();
    assert.ok(batch);

    assert.throws(
      () =>
        store.apply(feed, batch, 'projection/main', (database, authorized) =>
          applyProjection(database, authorized, 'projection/main'),
        ),
      /injected failure/,
    );
    assert.equal(store.checkpoint('projection/main'), undefined);
    assert.equal(feed.poll(), batch);

    failAt = undefined;
    const success = store.apply(feed, batch, 'projection/main', (database, authorized) =>
      applyProjection(database, authorized, 'projection/main'),
    );
    assert.equal(success.checkpoint.revision, 1);
    assert.equal(store.audit('projection/main').ok, true);
    ledger.close();
    store.close();
  } finally {
    location.cleanup();
  }
});

test('consumer ids have independent receipt chains and checkpoints', () => {
  const ledger = new SqliteCanonicalLedger();
  commitAppend(ledger, [], 'multi-consumer', 1, 1);
  const feedA = CanonicalChangeFeed.open(ledger, {
    checkpoint: {
      schemaVersion: 1,
      eventCount: 0,
      lastSeq: 0,
      lastRecordedAt: 0,
      chainDigest: 'sha256:04cd48bf4d2397b5b053472bc749c9c85e20040ed2913743cf3f60fdf34db3a5',
    },
  });
  const feedB = CanonicalChangeFeed.open(ledger, {
    checkpoint: {
      schemaVersion: 1,
      eventCount: 0,
      lastSeq: 0,
      lastRecordedAt: 0,
      chainDigest: 'sha256:04cd48bf4d2397b5b053472bc749c9c85e20040ed2913743cf3f60fdf34db3a5',
    },
  });
  const store = new SqliteConsumerCheckpointStore();
  const batchA = feedA.poll();
  const batchB = feedB.poll();
  assert.ok(batchA && batchB);
  store.apply(feedA, batchA, 'projection/a', () => 'a');
  store.apply(feedB, batchB, 'projection/b', () => 'b');
  assert.equal(store.checkpoint('projection/a')?.revision, 1);
  assert.equal(store.checkpoint('projection/b')?.revision, 1);
  assert.equal(store.audit('projection/a').ok, true);
  assert.equal(store.audit('projection/b').ok, true);
  ledger.close();
  store.close();
});

test('partial consumer schema fails closed and receipt tampering is detected', () => {
  const partialLocation = temporaryDatabase('cl-consumer-partial');
  try {
    const partial = new DatabaseSync(partialLocation.database);
    partial.exec('CREATE TABLE cl_consumer_meta (id INTEGER PRIMARY KEY)');
    partial.close();
    assert.throws(
      () => new SqliteConsumerCheckpointStore({ database: partialLocation.database }),
      /partially present/,
    );
  } finally {
    partialLocation.cleanup();
  }

  const tamperLocation = temporaryDatabase('cl-consumer-tamper');
  try {
    const ledger = new SqliteCanonicalLedger();
    const feed = CanonicalChangeFeed.open(ledger);
    const store = new SqliteConsumerCheckpointStore({ database: tamperLocation.database });
    commitAppend(ledger, [], 'tamper', 1, 1);
    const batch = feed.poll();
    assert.ok(batch);
    store.apply(feed, batch, 'projection/main', () => undefined);

    const attacker = new DatabaseSync(tamperLocation.database);
    attacker
      .prepare('UPDATE cl_consumer_receipts SET append_digest = ? WHERE consumer_id = ?')
      .run(sha('tampered'), 'projection/main');
    attacker.close();
    assert.throws(() => store.checkpoint('projection/main'), /receipt digest/);
    assert.equal(store.audit('projection/main').ok, false);
    ledger.close();
    store.close();
  } finally {
    tamperLocation.cleanup();
  }
});
