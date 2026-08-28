import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
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

function verifierIdentity(suffix = 'default') {
  return {
    id: `verifier/consumer/${suffix}`,
    actor: `verifier/consumer/${suffix}`,
    kind: 'deterministic',
    implementation: 'durable-consumer-test-verifier',
    version: '1',
    configDigest: sha(`verifier/consumer/${suffix}/config`),
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

function issueEvidence(verifier, beforeEvents, id, recordedAt) {
  const record = evidence(id, recordedAt);
  const proposal = {
    id: `transition/consumer/${id}`,
    proposer: 'memory-writer',
    baseFingerprint: fingerprintMemoryEvents(beforeEvents),
    authorizedScopes: ['project/consumer'],
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
    rationale: 'exercise durable consumer delivery',
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
      idempotencyKey: `consumer-ledger/${number}`,
      auditId: `audit/consumer/${number}`,
      recordedAt,
      actor: 'independent-consumer-auditor',
      committedBy: 'trusted-consumer-host',
    },
  };
}

function commitAppend(ledger, verifier, existing, id, number, recordedAt) {
  const generated = issueEvidence(verifier, existing, id, recordedAt);
  ledger.commit(request(ledger.cursor(), generated.result, number, recordedAt));
  return generated;
}

function durableEvents(ledger) {
  const cursor = ledger.cursor();
  return cursor.eventCount === 0 ? [] : ledger.readRange(1, cursor.eventCount);
}


function installProjectionTable(transaction) {
  transaction.run(`
    CREATE TABLE IF NOT EXISTS test_projection_events (
      consumer_id TEXT NOT NULL,
      event_id TEXT NOT NULL,
      PRIMARY KEY (consumer_id, event_id)
    )
  `);
}

function applyProjection(transaction, batch, consumerId) {
  installProjectionTable(transaction);
  for (const event of batch.events) {
    transaction.run(
      'INSERT INTO test_projection_events (consumer_id, event_id) VALUES (?, ?)',
      consumerId,
      event.id,
    );
  }
  return batch.events.length;
}

function binding(id = 'projection/main') {
  return {
    consumerId: id,
    configurationDigest: sha(`consumer-config/${id}/v1`),
  };
}

function register(store, feed, consumer = binding(), registeredAt = 1) {
  return store.register({
    ...consumer,
    initialCursor: feed.checkpoint(),
    registeredAt,
  });
}

test('projection writes, receipt, checkpoint, and feed ack advance together', () => {
  const { ledger, verifier } = openLedger({ suffix: 'atomic' });
  const feed = CanonicalChangeFeed.open(ledger);
  const store = new SqliteConsumerCheckpointStore();
  const consumer = binding();
  register(store, feed, consumer);
  commitAppend(ledger, verifier, [], 'one', 1, 1);
  const batch = feed.poll();
  assert.ok(batch);

  const result = store.apply(feed, batch, consumer, (database, authorized) =>
    applyProjection(database, authorized, consumer.consumerId),
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
    const { ledger, verifier } = openLedger({ suffix: 'callback' });
    const feed = CanonicalChangeFeed.open(ledger);
    const store = new SqliteConsumerCheckpointStore({ database: location.database });
    const consumer = binding();
    register(store, feed, consumer);
    commitAppend(ledger, verifier, [], 'rollback', 1, 1);
    const batch = feed.poll();
    assert.ok(batch);

    assert.throws(
      () =>
        store.apply(feed, batch, consumer, (database, authorized) => {
          applyProjection(database, authorized, consumer.consumerId);
          throw new Error('projection failed');
        }),
      /projection failed/,
    );
    assert.equal(feed.poll(), batch);
    assert.equal(store.checkpoint('projection/main'), undefined);
    const inspect = new DatabaseSync(location.database);
    const projectionTable = inspect
      .prepare("SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = 'test_projection_events'")
      .get().count;
    inspect.close();
    assert.equal(projectionTable, 0);
    ledger.close();
    store.close();
  } finally {
    location.cleanup();
  }
});

test('an async projection callback is rejected before checkpoint publication', () => {
  const { ledger, verifier } = openLedger({ suffix: 'async' });
  const feed = CanonicalChangeFeed.open(ledger);
  const store = new SqliteConsumerCheckpointStore();
  const consumer = binding();
  register(store, feed, consumer);
  commitAppend(ledger, verifier, [], 'async', 1, 1);
  const batch = feed.poll();
  assert.ok(batch);

  assert.throws(
    () => store.apply(feed, batch, consumer, async () => 1),
    /must be synchronous/,
  );
  assert.equal(store.checkpoint('projection/main'), undefined);
  assert.equal(feed.poll(), batch);
  ledger.close();
  store.close();
});

test('a forged batch clone cannot enter the consumer transaction', () => {
  const { ledger, verifier } = openLedger({ suffix: 'forged' });
  const feed = CanonicalChangeFeed.open(ledger);
  const store = new SqliteConsumerCheckpointStore();
  const consumer = binding();
  register(store, feed, consumer);
  commitAppend(ledger, verifier, [], 'forged', 1, 1);
  const batch = feed.poll();
  assert.ok(batch);
  let invoked = false;

  assert.throws(
    () =>
      store.apply(feed, structuredClone(batch), consumer, () => {
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
    const { ledger, verifier } = openLedger({ suffix: 'idempotent' });
    const genesis = CanonicalChangeFeed.open(ledger).checkpoint();
    commitAppend(ledger, verifier, [], 'idempotent', 1, 1);

    let invocations = 0;
    const firstFeed = CanonicalChangeFeed.open(ledger, { checkpoint: genesis });
    const firstBatch = firstFeed.poll();
    assert.ok(firstBatch);
    const firstStore = new SqliteConsumerCheckpointStore({ database: location.database });
    const consumer = binding();
    register(firstStore, firstFeed, consumer);
    const first = firstStore.apply(firstFeed, firstBatch, consumer, (database, authorized) => {
      invocations += 1;
      return applyProjection(database, authorized, consumer.consumerId);
    });
    assert.equal(first.idempotentReplay, false);
    assert.equal(first.value, 1);
    firstStore.close();

    commitAppend(ledger, verifier, durableEvents(ledger), 'idempotent-tail', 2, 2);
    const retryFeed = CanonicalChangeFeed.open(ledger, { checkpoint: genesis, maxBatchEvents: 1 });
    const retryBatch = retryFeed.poll();
    assert.ok(retryBatch);
    assert.equal(retryBatch.id, firstBatch.id);
    const retryStore = new SqliteConsumerCheckpointStore({ database: location.database });
    const replay = retryStore.apply(retryFeed, retryBatch, consumer, () => {
      invocations += 1;
      throw new Error('idempotent replay must not invoke projection code');
    });
    assert.equal(replay.idempotentReplay, true);
    assert.equal(replay.value, undefined);
    assert.equal(invocations, 1);
    assert.equal(retryFeed.checkpoint().eventCount, 1);
    const nextBatch = retryFeed.poll();
    assert.ok(nextBatch);
    assert.equal(nextBatch.appendFromSeq, 2);
    assert.equal(retryStore.audit('projection/main').ok, true);

    const inspect = new DatabaseSync(location.database);
    const count = inspect
      .prepare('SELECT COUNT(*) AS count FROM test_projection_events')
      .get().count;
    inspect.close();
    assert.equal(count, 1);

    retryStore.close();
    ledger.close();
  } finally {
    location.cleanup();
  }
});

test('fault injection after the consumer receipt rolls the whole transaction back', () => {
  const location = temporaryDatabase('cl-consumer-fault');
  try {
    let failAt = 'after-receipt';
    const { ledger, verifier } = openLedger({ suffix: 'fault' });
    const feed = CanonicalChangeFeed.open(ledger);
    const store = new SqliteConsumerCheckpointStore({
      database: location.database,
      faultInjector(point) {
        if (point === failAt) throw new Error(`injected failure at ${point}`);
      },
    });
    const consumer = binding();
    register(store, feed, consumer);
    commitAppend(ledger, verifier, [], 'fault', 1, 1);
    const batch = feed.poll();
    assert.ok(batch);

    assert.throws(
      () =>
        store.apply(feed, batch, consumer, (database, authorized) =>
          applyProjection(database, authorized, consumer.consumerId),
        ),
      /injected failure/,
    );
    assert.equal(store.checkpoint('projection/main'), undefined);
    assert.equal(feed.poll(), batch);

    failAt = undefined;
    const success = store.apply(feed, batch, consumer, (database, authorized) =>
      applyProjection(database, authorized, consumer.consumerId),
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
  const { ledger, verifier } = openLedger({ suffix: 'multi-consumer' });
  const genesis = CanonicalChangeFeed.open(ledger).checkpoint();
  commitAppend(ledger, verifier, [], 'multi-consumer', 1, 1);
  const feedA = CanonicalChangeFeed.open(ledger, { checkpoint: genesis });
  const feedB = CanonicalChangeFeed.open(ledger, { checkpoint: genesis });
  const store = new SqliteConsumerCheckpointStore();
  const consumerA = binding('projection/a');
  const consumerB = binding('projection/b');
  register(store, feedA, consumerA);
  register(store, feedB, consumerB);
  const batchA = feedA.poll();
  const batchB = feedB.poll();
  assert.ok(batchA && batchB);
  store.apply(feedA, batchA, consumerA, () => 'a');
  store.apply(feedB, batchB, consumerB, () => 'b');
  assert.equal(store.checkpoint('projection/a')?.revision, 1);
  assert.equal(store.checkpoint('projection/b')?.revision, 1);
  assert.equal(store.audit('projection/a').ok, true);
  assert.equal(store.audit('projection/b').ok, true);
  ledger.close();
  store.close();
});


test('registration binds completeness and configuration before the first batch', () => {
  const { ledger, verifier } = openLedger({ suffix: 'registration' });
  commitAppend(ledger, verifier, [], 'registration', 1, 1);
  const feed = CanonicalChangeFeed.open(ledger);
  const store = new SqliteConsumerCheckpointStore();
  const consumer = binding();
  register(store, feed, consumer);
  const batch = feed.poll();
  assert.ok(batch);

  assert.throws(
    () => store.apply(feed, batch, { ...consumer, configurationDigest: sha('different') }, () => undefined),
    /configuration digest differs/,
  );
  assert.throws(
    () =>
      store.register({
        ...consumer,
        initialCursor: { ...feed.checkpoint(), chainDigest: sha('different-cursor') },
        registeredAt: 1,
      }),
    /different durable configuration|cursor/,
  );
  assert.equal(store.checkpoint(consumer.consumerId), undefined);
  ledger.close();
  store.close();
});

test('projection callbacks cannot mutate consumer-owned tables or end the outer transaction', () => {
  const { ledger, verifier } = openLedger({ suffix: 'callback-boundary' });
  const feed = CanonicalChangeFeed.open(ledger);
  const store = new SqliteConsumerCheckpointStore();
  const consumer = binding();
  register(store, feed, consumer);
  commitAppend(ledger, verifier, [], 'callback-boundary', 1, 1);
  const batch = feed.poll();
  assert.ok(batch);

  assert.throws(
    () =>
      store.apply(feed, batch, consumer, (database) => {
        database.run('DELETE FROM cl_consumer_registrations WHERE consumer_id = ?', consumer.consumerId);
      }),
    /cannot access consumer-owned|FOREIGN KEY/,
  );
  assert.equal(feed.poll(), batch);
  assert.ok(store.registration(consumer.consumerId));

  assert.throws(
    () =>
      store.apply(feed, batch, consumer, (database) => {
        database.run(`
          CREATE TRIGGER evil_consumer_trigger
          AFTER INSERT ON cl_consumer_receipts
          BEGIN
            SELECT 1;
          END
        `);
      }),
    /exactly one statement|cannot access consumer-owned/,
  );
  assert.equal(feed.poll(), batch);

  assert.throws(
    () =>
      store.apply(feed, batch, consumer, (database) => {
        database.run('COMMIT');
      }),
    /cannot control transactions/,
  );
  assert.equal(feed.poll(), batch);
  ledger.close();
  store.close();
});



test('the restricted projection transaction permits local SQL but blocks authority escapes', () => {
  const { ledger, verifier } = openLedger({ suffix: 'restricted-writer' });
  const feed = CanonicalChangeFeed.open(ledger);
  const store = new SqliteConsumerCheckpointStore();
  const consumer = binding();
  register(store, feed, consumer);
  commitAppend(ledger, verifier, [], 'restricted-writer', 1, 1);
  const batch = feed.poll();
  assert.ok(batch);

  assert.throws(
    () =>
      store.apply(feed, batch, consumer, (transaction) => {
        transaction.run('PRAGMA foreign_keys = OFF');
      }),
    /cannot control transactions, attachments, or connection PRAGMAs/,
  );
  assert.equal(feed.poll(), batch);

  assert.throws(
    () =>
      store.apply(feed, batch, consumer, (transaction) => {
        transaction.run('CREATE TABLE escape_one (id INTEGER); DROP TABLE escape_one');
      }),
    /exactly one statement/,
  );
  assert.equal(feed.poll(), batch);

  assert.throws(
    () =>
      store.apply(feed, batch, consumer, () => {
        store.checkpoint(consumer.consumerId);
      }),
    /not allowed during an active projection transaction/,
  );
  assert.equal(feed.poll(), batch);

  const result = store.apply(feed, batch, consumer, (transaction, authorized) => {
    transaction.run('CREATE TABLE restricted_projection (event_id TEXT PRIMARY KEY, score INTEGER)');
    transaction.run(
      'INSERT INTO restricted_projection (event_id, score) VALUES (?, ?)',
      authorized.events[0].id,
      2,
    );
    const row = transaction.get(
      'SELECT CASE WHEN score = 2 THEN 1 ELSE 0 END AS ok FROM restricted_projection WHERE event_id = ?',
      authorized.events[0].id,
    );
    return row.ok;
  });
  assert.equal(result.value, 1);
  assert.equal(store.audit(consumer.consumerId).ok, true);
  ledger.close();
  store.close();
});

test('registration is idempotent without replaying the original registration timestamp', () => {
  const ledger = new SqliteCanonicalLedger();
  const feed = CanonicalChangeFeed.open(ledger);
  const store = new SqliteConsumerCheckpointStore();
  const consumer = binding();
  const first = store.register({ ...consumer, initialCursor: feed.checkpoint(), registeredAt: 7 });
  const replay = store.register({ ...consumer, initialCursor: feed.checkpoint() });
  assert.deepEqual(replay, first);
  assert.throws(
    () => store.register({ ...consumer, initialCursor: feed.checkpoint(), registeredAt: 8 }),
    /different durable configuration/,
  );
  ledger.close();
  store.close();
});

test('consumer identities and stored text fail closed at the SQLite byte boundary', () => {
  const location = temporaryDatabase('cl-consumer-bytes');
  try {
    const { ledger, verifier } = openLedger({ suffix: 'bytes' });
    const feed = CanonicalChangeFeed.open(ledger);
    const store = new SqliteConsumerCheckpointStore({ database: location.database });
    assert.throws(
      () =>
        store.register({
          consumerId: 'projection/main\u0000alias',
          configurationDigest: sha('nul-config'),
          initialCursor: feed.checkpoint(),
          registeredAt: 1,
        }),
      /U\+0000/,
    );

    const consumer = binding();
    register(store, feed, consumer);
    commitAppend(ledger, verifier, [], 'bytes', 1, 1);
    const batch = feed.poll();
    assert.ok(batch);
    store.apply(feed, batch, consumer, () => undefined);
    store.close();

    const attacker = new DatabaseSync(location.database);
    attacker.exec('PRAGMA foreign_keys = OFF');
    attacker.prepare(
      "UPDATE cl_consumer_checkpoints SET cursor_digest = CAST(X'80' AS TEXT) WHERE consumer_id = ?",
    ).run(consumer.consumerId);
    attacker.close();

    const reopened = new SqliteConsumerCheckpointStore({ database: location.database });
    assert.throws(() => reopened.checkpoint(consumer.consumerId), /non-canonical SQLite text encoding/);
    assert.equal(reopened.audit(consumer.consumerId).ok, false);
    reopened.close();
    ledger.close();
  } finally {
    location.cleanup();
  }
});

test('a real process crash before commit leaves registration but no projection, receipt, or checkpoint', () => {
  const location = temporaryDatabase('cl-consumer-crash');
  const ledgerLocation = temporaryDatabase('cl-consumer-crash-ledger');
  try {
    const script = `
      import { createHash } from 'node:crypto';
      import {
        MemoryKernel,
        TransitionVerifier,
        fingerprintMemoryEvents,
      } from './dist/index.js';
      import {
        CanonicalChangeFeed,
        SqliteCanonicalLedger,
        SqliteConsumerCheckpointStore,
      } from './dist/durable/index.js';
      const sha = (value) => 'sha256:' + createHash('sha256').update(value).digest('hex');
      const verifier = new TransitionVerifier({
        id: 'verifier/crash', actor: 'verifier/crash', kind: 'deterministic',
        implementation: 'consumer-crash-test', version: '1', configDigest: sha('crash-config'),
      });
      const ledger = new SqliteCanonicalLedger({ database: process.env.LEDGER_DB, transitionVerifier: verifier });
      const record = {
        id: 'evidence/crash', scope: 'project/consumer', kind: 'human-feedback',
        sourceGroups: ['origin/crash'], authority: 'human-explicit', observedAt: 1,
        sensitivity: 'public', taints: [],
        artifact: { uri: 'memory://artifact/crash', digest: sha('artifact/crash'), sizeBytes: 1,
          mediaType: 'text/plain', encryption: 'none', retention: 'durable' },
        preview: 'crash', derivedFrom: [], labels: ['consumer'],
      };
      const proposal = {
        id: 'transition/crash', proposer: 'writer', baseFingerprint: fingerprintMemoryEvents([]),
        authorizedScopes: ['project/consumer'], declaredRisk: 'low', stateImpact: 'none',
        operations: [{ id: 'event/crash', type: 'evidence.captured', recordedAt: 1,
          actor: 'source-ingestor', data: { evidence: record } }],
        inputEvidenceIds: [record.id], ignoredInputEvidence: [], externalChecks: [],
        stateExpectations: [], rationale: 'crash test',
      };
      const result = verifier.verify([], proposal);
      ledger.commit({ base: ledger.cursor(), result, envelope: {
        idempotencyKey: 'crash/1', auditId: 'audit/crash/1', recordedAt: 1,
        actor: 'auditor', committedBy: 'host',
      }});
      const feed = CanonicalChangeFeed.open(ledger);
      const store = new SqliteConsumerCheckpointStore({ database: process.env.CONSUMER_DB });
      const binding = { consumerId: 'projection/crash', configurationDigest: sha('projection/crash/v1') };
      store.register({ ...binding, initialCursor: feed.checkpoint(), registeredAt: 1 });
      const batch = feed.poll();
      store.apply(feed, batch, binding, (database, authorized) => {
        database.run('CREATE TABLE crash_projection (event_id TEXT PRIMARY KEY)');
        database.run('INSERT INTO crash_projection (event_id) VALUES (?)', authorized.events[0].id);
        process.exit(0);
      });
    `;
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
      cwd: new URL('..', import.meta.url).pathname,
      env: {
        ...process.env,
        CONSUMER_DB: location.database,
        LEDGER_DB: ledgerLocation.database,
      },
      encoding: 'utf8',
    });
    assert.equal(child.status, 0, child.stderr);

    const store = new SqliteConsumerCheckpointStore({ database: location.database });
    assert.ok(store.registration('projection/crash'));
    assert.equal(store.checkpoint('projection/crash'), undefined);
    assert.equal(store.audit('projection/crash').receiptCount, 0);
    const inspect = new DatabaseSync(location.database);
    const projectionCount = inspect
      .prepare("SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = 'crash_projection'")
      .get().count;
    inspect.close();
    assert.equal(projectionCount, 0);
    store.close();
  } finally {
    location.cleanup();
    ledgerLocation.cleanup();
  }
});


test('orphaned checkpoint state is not hidden when its registration is removed', () => {
  const location = temporaryDatabase('cl-consumer-orphan');
  try {
    const { ledger, verifier } = openLedger({ suffix: 'orphan' });
    const feed = CanonicalChangeFeed.open(ledger);
    const store = new SqliteConsumerCheckpointStore({ database: location.database });
    const consumer = binding();
    register(store, feed, consumer);
    commitAppend(ledger, verifier, [], 'orphan', 1, 1);
    const batch = feed.poll();
    assert.ok(batch);
    store.apply(feed, batch, consumer, () => undefined);
    store.close();

    const attacker = new DatabaseSync(location.database);
    attacker.exec('PRAGMA foreign_keys = OFF');
    attacker.prepare('DELETE FROM cl_consumer_registrations WHERE consumer_id = ?').run(consumer.consumerId);
    attacker.close();

    const reopened = new SqliteConsumerCheckpointStore({ database: location.database });
    assert.throws(
      () => reopened.checkpoint(consumer.consumerId),
      /state exists without a durable registration/,
    );
    assert.equal(reopened.audit(consumer.consumerId).ok, false);
    reopened.close();
    ledger.close();
  } finally {
    location.cleanup();
  }
});

test('a lookalike all-table schema without the required constraints fails attestation', () => {
  const location = temporaryDatabase('cl-consumer-schema-lookalike');
  try {
    const database = new DatabaseSync(location.database);
    database.exec(`
      CREATE TABLE cl_consumer_meta (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL) STRICT;
      CREATE TABLE cl_consumer_registrations (
        consumer_id TEXT PRIMARY KEY,
        configuration_digest TEXT NOT NULL,
        initial_cursor_json TEXT NOT NULL,
        initial_cursor_digest TEXT NOT NULL,
        registered_at INTEGER NOT NULL,
        registration_digest TEXT NOT NULL
      ) STRICT;
      CREATE TABLE cl_consumer_checkpoints (
        consumer_id TEXT PRIMARY KEY,
        configuration_digest TEXT NOT NULL,
        initial_cursor_digest TEXT NOT NULL,
        revision INTEGER NOT NULL,
        cursor_json TEXT NOT NULL,
        cursor_digest TEXT NOT NULL,
        last_batch_id TEXT NOT NULL,
        last_append_digest TEXT NOT NULL,
        latest_receipt_digest TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE cl_consumer_receipts (
        consumer_id TEXT NOT NULL,
        configuration_digest TEXT NOT NULL,
        initial_cursor_digest TEXT NOT NULL,
        revision INTEGER NOT NULL,
        batch_id TEXT NOT NULL,
        base_cursor_json TEXT NOT NULL,
        base_cursor_digest TEXT NOT NULL,
        after_cursor_json TEXT NOT NULL,
        after_cursor_digest TEXT NOT NULL,
        append_digest TEXT NOT NULL,
        previous_receipt_digest TEXT NOT NULL,
        receipt_digest TEXT NOT NULL,
        applied_at INTEGER NOT NULL,
        PRIMARY KEY (consumer_id, revision),
        UNIQUE (consumer_id, batch_id)
      ) STRICT;
      INSERT INTO cl_consumer_meta (id, schema_version) VALUES (1, 1);
    `);
    database.close();
    assert.throws(
      () => new SqliteConsumerCheckpointStore({ database: location.database }),
      /definition is incompatible/,
    );
  } finally {
    location.cleanup();
  }
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
    const { ledger, verifier } = openLedger({ suffix: 'tamper' });
    const feed = CanonicalChangeFeed.open(ledger);
    const store = new SqliteConsumerCheckpointStore({ database: tamperLocation.database });
    const consumer = binding();
    register(store, feed, consumer);
    commitAppend(ledger, verifier, [], 'tamper', 1, 1);
    const batch = feed.poll();
    assert.ok(batch);
    store.apply(feed, batch, consumer, () => undefined);

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
