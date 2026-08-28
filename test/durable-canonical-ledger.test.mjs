import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import {
  MemoryKernel,
  SqliteCanonicalLedger,
  TransitionVerifier,
  fingerprintMemoryEvents,
  verifyTransitionResultIntegrity,
} from '../dist/index.js';

function sha(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function temporaryDatabase() {
  const directory = mkdtempSync(join(tmpdir(), 'cl-canonical-ledger-'));
  return {
    directory,
    database: join(directory, 'canonical.sqlite'),
    cleanup() {
      rmSync(directory, { recursive: true, force: true });
    },
  };
}

function verifierIdentity(suffix = 'default') {
  return {
    id: `verifier/durable/${suffix}`,
    actor: `verifier/durable/${suffix}`,
    kind: 'deterministic',
    implementation: 'durable-ledger-test-verifier',
    version: '1',
    configDigest: sha(`verifier/durable/${suffix}/config`),
  };
}

function evidence(id, preview, observedAt = 1) {
  return {
    id,
    scope: 'project/durable',
    kind: 'human-feedback',
    sourceGroups: [`origin/${id}`],
    authority: 'human-explicit',
    observedAt,
    sensitivity: 'public',
    taints: [],
    artifact: {
      uri: `memory://artifact/${id}`,
      digest: sha(`artifact:${id}`),
      sizeBytes: preview.length,
      mediaType: 'text/plain',
      encryption: 'none',
      retention: 'durable',
    },
    preview,
    derivedFrom: [],
    labels: ['durable'],
  };
}

function evidenceProposal(beforeEvents, suffix, recordedAt, options = {}) {
  const record = evidence(
    options.evidenceId ?? `evidence/${suffix}`,
    options.preview ?? `durable memory ${suffix}`,
    recordedAt,
  );
  const eventId = options.eventId ?? `event/evidence/${suffix}`;
  return {
    record,
    proposal: {
      id: options.proposalId ?? `transition/${suffix}`,
      proposer: 'memory-writer',
      baseFingerprint: fingerprintMemoryEvents(beforeEvents),
      authorizedScopes: ['project/durable'],
      declaredRisk: 'low',
      stateImpact: 'none',
      operations: [
        {
          id: eventId,
          type: 'evidence.captured',
          recordedAt,
          actor: options.operationActor ?? 'source-ingestor',
          data: { evidence: record },
        },
      ],
      inputEvidenceIds: [record.id],
      ignoredInputEvidence: [],
      externalChecks: [],
      stateExpectations: [],
      rationale: 'exercise durable canonical publication',
    },
  };
}

function issueEvidence(verifier, beforeEvents, suffix, recordedAt, options = {}) {
  const { record, proposal } = evidenceProposal(beforeEvents, suffix, recordedAt, options);
  const result = verifier.verify(beforeEvents, proposal);
  assert.equal(result.verdict, 'accept');
  assert.equal(result.stagedAppend?.length, 1);
  assert.equal(verifyTransitionResultIntegrity(result), true);
  const all = MemoryKernel.from([...beforeEvents, ...result.stagedAppend]).events();
  return { record, proposal, result, append: result.stagedAppend, all };
}

function issueMultiEvidence(verifier, beforeEvents, suffix, recordedAt, count = 2) {
  const records = Array.from({ length: count }, (_, index) =>
    evidence(`evidence/${suffix}/${index + 1}`, `durable memory ${suffix} ${index + 1}`, recordedAt),
  );
  const proposal = {
    id: `transition/${suffix}`,
    proposer: 'memory-writer',
    baseFingerprint: fingerprintMemoryEvents(beforeEvents),
    authorizedScopes: ['project/durable'],
    declaredRisk: 'low',
    stateImpact: 'none',
    operations: records.map((record, index) => ({
      id: `event/evidence/${suffix}/${index + 1}`,
      type: 'evidence.captured',
      recordedAt,
      actor: 'source-ingestor',
      data: { evidence: record },
    })),
    inputEvidenceIds: records.map((record) => record.id),
    ignoredInputEvidence: [],
    externalChecks: [],
    stateExpectations: [],
    rationale: 'exercise a multi-event durable append',
  };
  const result = verifier.verify(beforeEvents, proposal);
  assert.equal(result.verdict, 'accept');
  assert.equal(result.stagedAppend?.length, count);
  const all = MemoryKernel.from([...beforeEvents, ...result.stagedAppend]).events();
  return { records, proposal, result, append: result.stagedAppend, all };
}

function request(base, result, number, recordedAt, key = `idempotency/${number}`) {
  return {
    base,
    result,
    envelope: {
      idempotencyKey: key,
      auditId: `audit/${number}`,
      recordedAt,
      actor: 'independent-durable-auditor',
      committedBy: 'trusted-durable-host',
    },
  };
}

function openLedger(options = {}) {
  const verifier = options.verifier ?? new TransitionVerifier(verifierIdentity(options.suffix));
  const ledger = new SqliteCanonicalLedger({ ...options, transitionVerifier: verifier });
  return { ledger, verifier };
}

function hex(value) {
  return Buffer.from(value, 'utf8').toString('hex');
}

test('one transaction publishes verifier-issued canonical bytes, audit, receipt, and cursor', () => {
  const { ledger, verifier } = openLedger({ suffix: 'one' });
  const empty = ledger.status();
  assert.equal(empty.ok, true);
  assert.equal(empty.cursor.revision, 0);

  const first = issueEvidence(verifier, [], 'one', 1);
  const committed = ledger.commit(request(empty.cursor, first.result, 1, 1));

  assert.equal(committed.idempotentReplay, false);
  assert.equal(committed.cursor.revision, 1);
  assert.equal(committed.cursor.eventCount, 1);
  assert.equal(committed.receipt.appendFromSeq, 1);
  assert.equal(committed.receipt.appendToSeq, 1);
  assert.equal(committed.receipt.transition.resultDigest, first.result.resultDigest);
  assert.deepEqual(ledger.readRange(1), first.append);
  assert.deepEqual(ledger.loadKernel().events(), first.all);
  assert.equal(ledger.receipt('idempotency/1')?.receiptDigest, committed.receipt.receiptDigest);
  assert.equal(ledger.status().ok, true);
  assert.equal(ledger.audit().ok, true);
  ledger.close();
});

test('a caller cannot persist an accepted-looking copy that was not issued by the configured verifier', () => {
  const { ledger, verifier } = openLedger({ suffix: 'capability' });
  const generated = issueEvidence(verifier, [], 'copy', 1);
  const copiedResult = structuredClone(generated.result);

  assert.equal(verifyTransitionResultIntegrity(copiedResult), true);
  assert.throws(
    () => ledger.commit(request(ledger.cursor(), copiedResult, 1, 1)),
    /not issued by this verifier runtime/,
  );
  assert.equal(ledger.cursor().revision, 0);
  ledger.close();
});

test('a second commit extends receipt and event chains while stale and copied cursors fail', () => {
  const { ledger, verifier } = openLedger({ suffix: 'chain' });
  const base = ledger.cursor();
  const first = issueEvidence(verifier, [], 'first', 1);
  const committedOne = ledger.commit(request(base, first.result, 1, 1));
  const second = issueEvidence(verifier, first.all, 'second', 2);

  assert.throws(
    () => ledger.commit(request(base, second.result, 2, 2, 'idempotency/stale')),
    /stale/,
  );
  assert.throws(
    () =>
      ledger.commit(
        request(structuredClone(committedOne.cursor), second.result, 2, 2, 'idempotency/copied'),
      ),
    /capability issued by this ledger/,
  );

  const committedTwo = ledger.commit(request(committedOne.cursor, second.result, 2, 2));
  assert.equal(committedTwo.cursor.revision, 2);
  assert.equal(committedTwo.receipt.previousReceiptDigest, committedOne.receipt.receiptDigest);
  assert.equal(committedTwo.receipt.baseChainDigest, committedOne.receipt.afterChainDigest);
  assert.equal(ledger.audit().ok, true);
  ledger.close();
});

test('an exact idempotent retry survives restart without granting new mutation authority', () => {
  const location = temporaryDatabase();
  try {
    const verifier = new TransitionVerifier(verifierIdentity('restart'));
    const firstProcess = new SqliteCanonicalLedger({
      database: location.database,
      transitionVerifier: verifier,
    });
    const generated = issueEvidence(verifier, [], 'restart', 1);
    const original = request(firstProcess.cursor(), generated.result, 1, 1, 'retry/restart');
    const initial = firstProcess.commit(original);
    const portableRetry = structuredClone(original);
    firstProcess.close();

    const secondProcess = new SqliteCanonicalLedger({ database: location.database });
    const retry = secondProcess.commit(portableRetry);
    assert.equal(retry.idempotentReplay, true);
    assert.equal(retry.receipt.receiptDigest, initial.receipt.receiptDigest);
    assert.equal(retry.cursor.revision, 1);

    const changed = structuredClone(portableRetry);
    changed.envelope.committedBy = 'different-host';
    assert.throws(() => secondProcess.commit(changed), /different durable request/);

    const nextVerifier = new TransitionVerifier(verifierIdentity('restart-next'));
    const next = issueEvidence(nextVerifier, generated.all, 'restart-next', 2);
    assert.throws(
      () => secondProcess.commit(request(secondProcess.cursor(), next.result, 2, 2)),
      /configured TransitionVerifier/,
    );
    secondProcess.close();
  } finally {
    location.cleanup();
  }
});

test('the same verifier result cannot be committed under a second idempotency identity', () => {
  const { ledger, verifier } = openLedger({ suffix: 'result-reuse' });
  const generated = issueEvidence(verifier, [], 'result-reuse', 1);
  const base = ledger.cursor();
  ledger.commit(request(base, generated.result, 1, 1, 'result/original'));
  assert.throws(
    () => ledger.commit(request(base, generated.result, 2, 1, 'result/other-key')),
    /already committed under a different idempotency key/,
  );
  ledger.close();
});

test('every fault point rolls back events, audit, receipt, and cursor together', () => {
  const points = [
    'after-begin',
    'after-prefix-audit',
    'after-events',
    'after-audit',
    'after-receipt',
    'after-cursor',
    'before-commit',
  ];

  for (const point of points) {
    let enabled = true;
    const verifier = new TransitionVerifier(verifierIdentity(`fault-${point}`));
    const ledger = new SqliteCanonicalLedger({
      transitionVerifier: verifier,
      faultInjector(current) {
        if (enabled && current === point) throw new Error(`injected failure at ${point}`);
      },
    });
    const generated = issueEvidence(verifier, [], `fault-${point}`, 1);
    const pending = request(ledger.cursor(), generated.result, 1, 1, `rollback/${point}`);

    assert.throws(() => ledger.commit(pending), /injected failure/);
    assert.equal(ledger.cursor().revision, 0);
    assert.equal(ledger.readRange(1).length, 0);
    assert.equal(ledger.receipt(`rollback/${point}`), undefined);
    assert.equal(ledger.audit().ok, true);

    enabled = false;
    assert.equal(ledger.commit(pending).cursor.revision, 1);
    ledger.close();
  }
});

test('two writers cannot both publish from the same canonical cursor', () => {
  const location = temporaryDatabase();
  try {
    const verifierA = new TransitionVerifier(verifierIdentity('writer-a'));
    const verifierB = new TransitionVerifier(verifierIdentity('writer-b'));
    const writerA = new SqliteCanonicalLedger({
      database: location.database,
      transitionVerifier: verifierA,
    });
    const writerB = new SqliteCanonicalLedger({
      database: location.database,
      transitionVerifier: verifierB,
    });
    const cursorA = writerA.cursor();
    const cursorB = writerB.cursor();
    const appendA = issueEvidence(verifierA, [], 'writer-a', 1);
    const appendB = issueEvidence(verifierB, [], 'writer-b', 1);

    writerA.commit(request(cursorA, appendA.result, 1, 1, 'writer/a'));
    assert.throws(
      () => writerB.commit(request(cursorB, appendB.result, 2, 1, 'writer/b')),
      /stale/,
    );
    assert.equal(writerA.audit().ok, true);
    writerA.close();
    writerB.close();
  } finally {
    location.cleanup();
  }
});

test('fast status checks the tail while full audit detects older event-byte tampering', () => {
  const location = temporaryDatabase();
  try {
    const verifier = new TransitionVerifier(verifierIdentity('old-tamper'));
    const ledger = new SqliteCanonicalLedger({
      database: location.database,
      transitionVerifier: verifier,
    });
    const first = issueEvidence(verifier, [], 'tamper-one', 1);
    const one = ledger.commit(request(ledger.cursor(), first.result, 1, 1));
    const second = issueEvidence(verifier, first.all, 'tamper-two', 2);
    ledger.commit(request(one.cursor, second.result, 2, 2));

    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare('UPDATE cl_canonical_events SET event_json = ? WHERE seq = 1')
      .run('{"tampered":true}');
    attacker.close();

    assert.equal(ledger.status().ok, true);
    assert.throws(() => ledger.loadKernel(), /canonical event/);
    assert.equal(ledger.audit().ok, false);
    ledger.close();
  } finally {
    location.cleanup();
  }
});

test('fast status validates the predecessor anchor of the latest event', () => {
  const location = temporaryDatabase();
  try {
    const verifier = new TransitionVerifier(verifierIdentity('anchor'));
    const ledger = new SqliteCanonicalLedger({
      database: location.database,
      transitionVerifier: verifier,
    });
    const first = issueEvidence(verifier, [], 'anchor-one', 1);
    const one = ledger.commit(request(ledger.cursor(), first.result, 1, 1));
    const second = issueEvidence(verifier, first.all, 'anchor-two', 2);
    ledger.commit(request(one.cursor, second.result, 2, 2));

    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare('UPDATE cl_canonical_events SET chain_digest = ? WHERE seq = 1')
      .run(sha('forged-predecessor'));
    attacker.close();

    assert.throws(() => ledger.status(), /predecessor|chain/);
    ledger.close();
  } finally {
    location.cleanup();
  }
});

test('fast status recomputes latest audit and receipt integrity', () => {
  const location = temporaryDatabase();
  try {
    const verifier = new TransitionVerifier(verifierIdentity('audit-tamper'));
    const ledger = new SqliteCanonicalLedger({
      database: location.database,
      transitionVerifier: verifier,
    });
    const generated = issueEvidence(verifier, [], 'audit-tamper', 1);
    ledger.commit(request(ledger.cursor(), generated.result, 1, 1));

    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare('UPDATE cl_canonical_audits SET audit_json = ? WHERE revision = 1')
      .run('{"schemaVersion":1,"tampered":true}');
    attacker.close();

    assert.throws(() => ledger.status(), /audit/);
    assert.equal(ledger.audit().ok, false);
    ledger.close();
  } finally {
    location.cleanup();
  }
});

test('raw SQLite NUL and malformed UTF-8 aliases fail closed', () => {
  for (const attackSql of [
    `UPDATE cl_canonical_events SET actor = CAST(X'${hex('source-ingestor')}00' AS TEXT) WHERE seq = 1`,
    "UPDATE cl_canonical_events SET actor = CAST(X'80' AS TEXT) WHERE seq = 1",
  ]) {
    const location = temporaryDatabase();
    try {
      const verifier = new TransitionVerifier(verifierIdentity(sha(attackSql).slice(-8)));
      const ledger = new SqliteCanonicalLedger({
        database: location.database,
        transitionVerifier: verifier,
      });
      const generated = issueEvidence(verifier, [], `raw-${sha(attackSql).slice(-8)}`, 1);
      ledger.commit(request(ledger.cursor(), generated.result, 1, 1));
      const attacker = new DatabaseSync(location.database);
      attacker.exec(attackSql);
      attacker.close();
      assert.throws(() => ledger.status(), /SQLite text encoding|U\+0000|Unicode/);
      ledger.close();
    } finally {
      location.cleanup();
    }
  }
});

test('new canonical event identifiers and actors reject embedded NUL and malformed Unicode', () => {
  for (const [suffix, eventId, actor] of [
    ['nul-id', 'event/nul\u0000suffix', 'source-ingestor'],
    ['bad-actor', 'event/bad-actor', '\ud800'],
  ]) {
    const { ledger, verifier } = openLedger({ suffix });
    const generated = issueEvidence(verifier, [], suffix, 1, {
      eventId,
      operationActor: actor,
    });
    assert.throws(
      () => ledger.commit(request(ledger.cursor(), generated.result, 1, 1)),
      /U\+0000|well-formed Unicode/,
    );
    assert.equal(ledger.cursor().revision, 0);
    ledger.close();
  }
});

test('range reads verify predecessor time, local row digests, contiguous rows, and bounds', () => {
  const location = temporaryDatabase();
  try {
    const verifier = new TransitionVerifier(verifierIdentity('range'));
    const ledger = new SqliteCanonicalLedger({
      database: location.database,
      transitionVerifier: verifier,
    });
    const first = issueEvidence(verifier, [], 'range-one', 10);
    const one = ledger.commit(request(ledger.cursor(), first.result, 1, 10));
    const second = issueEvidence(verifier, first.all, 'range-two', 20);
    ledger.commit(request(one.cursor, second.result, 2, 20));

    assert.deepEqual(ledger.readRange(2, 1), second.append);
    assert.throws(() => ledger.readRange(0), /positive/);
    assert.throws(() => ledger.readRange(1, 1_001), /range limit/);

    const attacker = new DatabaseSync(location.database);
    attacker.prepare('UPDATE cl_canonical_events SET recorded_at = 30 WHERE seq = 1').run();
    attacker.close();
    assert.throws(() => ledger.readRange(2, 1), /transaction time regresses/);
    ledger.close();
  } finally {
    location.cleanup();
  }
});

test('fast status verifies every event in the latest bounded append, not only its tail', () => {
  const location = temporaryDatabase();
  try {
    const verifier = new TransitionVerifier(verifierIdentity('multi-tail'));
    const ledger = new SqliteCanonicalLedger({
      database: location.database,
      transitionVerifier: verifier,
    });
    const generated = issueMultiEvidence(verifier, [], 'multi-tail', 1, 2);
    ledger.commit(request(ledger.cursor(), generated.result, 1, 1));

    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare('UPDATE cl_canonical_events SET event_json = ? WHERE seq = 1')
      .run('{"tampered":true}');
    attacker.close();

    assert.throws(() => ledger.status(), /canonical event|append integrity/);
    ledger.close();
  } finally {
    location.cleanup();
  }
});

test('startup performs a full recovery audit rather than trusting a healthy-looking tail', () => {
  const location = temporaryDatabase();
  try {
    const verifier = new TransitionVerifier(verifierIdentity('startup-audit'));
    const writer = new SqliteCanonicalLedger({
      database: location.database,
      transitionVerifier: verifier,
    });
    const first = issueEvidence(verifier, [], 'startup-one', 1);
    const one = writer.commit(request(writer.cursor(), first.result, 1, 1));
    const second = issueEvidence(verifier, first.all, 'startup-two', 2);
    writer.commit(request(one.cursor, second.result, 2, 2));
    writer.close();

    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare('UPDATE cl_canonical_events SET event_json = ? WHERE seq = 1')
      .run('{"old":"tampered"}');
    attacker.close();

    assert.throws(
      () => new SqliteCanonicalLedger({ database: location.database }),
      /recovery audit failed|canonical event/,
    );
  } finally {
    location.cleanup();
  }
});

test('schema validation rejects missing uniqueness constraints and database triggers', () => {
  const weakLocation = temporaryDatabase();
  try {
    const weak = new DatabaseSync(weakLocation.database);
    weak.exec(`
      CREATE TABLE cl_canonical_meta (
        id INTEGER PRIMARY KEY,
        schema_version INTEGER NOT NULL,
        revision INTEGER NOT NULL,
        event_count INTEGER NOT NULL,
        last_seq INTEGER NOT NULL,
        last_recorded_at INTEGER NOT NULL,
        canonical_fingerprint TEXT NOT NULL,
        chain_digest TEXT NOT NULL,
        latest_receipt_digest TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE cl_canonical_events (
        seq INTEGER PRIMARY KEY,
        event_id TEXT NOT NULL,
        schema_version INTEGER NOT NULL,
        type TEXT NOT NULL,
        recorded_at INTEGER NOT NULL,
        actor TEXT NOT NULL,
        event_json TEXT NOT NULL,
        event_digest TEXT NOT NULL,
        previous_chain_digest TEXT NOT NULL,
        chain_digest TEXT NOT NULL,
        revision INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE cl_canonical_receipts (
        revision INTEGER PRIMARY KEY,
        idempotency_key TEXT NOT NULL,
        request_digest TEXT NOT NULL,
        result_digest TEXT NOT NULL,
        transition_json TEXT NOT NULL,
        transition_digest TEXT NOT NULL,
        audit_id TEXT NOT NULL,
        audit_digest TEXT NOT NULL,
        base_chain_digest TEXT NOT NULL,
        after_chain_digest TEXT NOT NULL,
        append_from_seq INTEGER NOT NULL,
        append_to_seq INTEGER NOT NULL,
        append_digest TEXT NOT NULL,
        previous_receipt_digest TEXT NOT NULL,
        receipt_digest TEXT NOT NULL,
        committed_by TEXT NOT NULL,
        committed_at INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE cl_canonical_audits (
        revision INTEGER PRIMARY KEY,
        audit_id TEXT NOT NULL,
        audit_json TEXT NOT NULL,
        audit_digest TEXT NOT NULL,
        receipt_digest TEXT NOT NULL
      ) STRICT;
    `);
    weak.close();
    assert.throws(
      () => new SqliteCanonicalLedger({ database: weakLocation.database }),
      /uniqueness contract/,
    );
  } finally {
    weakLocation.cleanup();
  }

  const triggerLocation = temporaryDatabase();
  try {
    const ledger = new SqliteCanonicalLedger({ database: triggerLocation.database });
    ledger.close();
    const attacker = new DatabaseSync(triggerLocation.database);
    attacker.exec(`
      CREATE TRIGGER mutate_canonical_meta
      AFTER INSERT ON cl_canonical_events
      BEGIN
        UPDATE cl_canonical_meta SET updated_at = updated_at;
      END
    `);
    attacker.close();
    assert.throws(
      () => new SqliteCanonicalLedger({ database: triggerLocation.database }),
      /must not have database triggers/,
    );
  } finally {
    triggerLocation.cleanup();
  }
});

test('partially created and column-incompatible durable schemas fail closed', () => {
  const partialLocation = temporaryDatabase();
  try {
    const partial = new DatabaseSync(partialLocation.database);
    partial.exec('CREATE TABLE cl_canonical_meta (id INTEGER PRIMARY KEY)');
    partial.close();
    assert.throws(
      () => new SqliteCanonicalLedger({ database: partialLocation.database }),
      /partially present/,
    );
  } finally {
    partialLocation.cleanup();
  }

  const changedLocation = temporaryDatabase();
  try {
    const ledger = new SqliteCanonicalLedger({ database: changedLocation.database });
    ledger.close();
    const changed = new DatabaseSync(changedLocation.database);
    changed.exec('ALTER TABLE cl_canonical_meta ADD COLUMN unexpected TEXT');
    changed.close();
    assert.throws(
      () => new SqliteCanonicalLedger({ database: changedLocation.database }),
      /incompatible column set/,
    );
  } finally {
    changedLocation.cleanup();
  }
});

test('new commits require an issued cursor even when fields match the empty ledger', () => {
  const { ledger, verifier } = openLedger({ suffix: 'forged-cursor' });
  const generated = issueEvidence(verifier, [], 'forged-cursor', 1);
  const forged = structuredClone(ledger.cursor());
  assert.throws(
    () => ledger.commit(request(forged, generated.result, 1, 1, 'forged/cursor')),
    /capability issued by this ledger/,
  );
  ledger.close();
});

test('a durable request snapshots top-level capability fields once before validation and commit', () => {
  const { ledger, verifier } = openLedger({ suffix: 'single-read' });
  const generated = issueEvidence(verifier, [], 'single-read', 1);
  const base = ledger.cursor();
  const envelope = request(base, generated.result, 1, 1).envelope;
  const reads = { base: 0, result: 0, envelope: 0 };
  const input = {
    get base() {
      reads.base += 1;
      return base;
    },
    get result() {
      reads.result += 1;
      return generated.result;
    },
    get envelope() {
      reads.envelope += 1;
      return envelope;
    },
  };

  assert.equal(ledger.commit(input).cursor.revision, 1);
  assert.deepEqual(reads, { base: 1, result: 1, envelope: 1 });
  ledger.close();
});


test('historical receipt corruption blocks new commits, exact retries, and receipt reads after open', () => {
  const location = temporaryDatabase();
  try {
    const verifier = new TransitionVerifier(verifierIdentity('historical-receipt'));
    const ledger = new SqliteCanonicalLedger({
      database: location.database,
      transitionVerifier: verifier,
    });
    const first = issueEvidence(verifier, [], 'historical-receipt-one', 1);
    const firstRequest = request(ledger.cursor(), first.result, 1, 1, 'historical/one');
    const one = ledger.commit(firstRequest);
    const second = issueEvidence(verifier, first.all, 'historical-receipt-two', 2);
    const secondRequest = request(one.cursor, second.result, 2, 2, 'historical/two');
    const two = ledger.commit(secondRequest);

    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare("UPDATE cl_canonical_receipts SET committed_by = 'tampered-host' WHERE revision = 1")
      .run();
    attacker.close();

    const third = issueEvidence(verifier, second.all, 'historical-receipt-three', 3);
    assert.throws(
      () => ledger.commit(request(two.cursor, third.result, 3, 3, 'historical/three')),
      /receipt digest mismatch|receipt chain mismatch/,
    );
    assert.throws(
      () => ledger.commit(structuredClone(secondRequest)),
      /receipt digest mismatch|receipt chain mismatch/,
    );
    assert.throws(
      () => ledger.receipt('historical/two'),
      /receipt digest mismatch|receipt chain mismatch/,
    );
    ledger.close();
  } finally {
    location.cleanup();
  }
});

test('receipt and audit raw SQLite text aliases fail closed', () => {
  const attacks = [
    {
      suffix: 'receipt-nul',
      sql: `UPDATE cl_canonical_receipts
               SET committed_by = CAST(X'${hex('trusted-durable-host')}00' AS TEXT)
             WHERE revision = 1`,
    },
    {
      suffix: 'receipt-utf8',
      sql: "UPDATE cl_canonical_receipts SET idempotency_key = CAST(X'80' AS TEXT) WHERE revision = 1",
    },
    {
      suffix: 'audit-nul',
      sql: `UPDATE cl_canonical_audits
               SET audit_id = CAST(X'${hex('audit/1')}00' AS TEXT)
             WHERE revision = 1`,
    },
    {
      suffix: 'audit-utf8',
      sql: "UPDATE cl_canonical_audits SET audit_json = CAST(X'80' AS TEXT) WHERE revision = 1",
    },
  ];

  for (const attack of attacks) {
    const location = temporaryDatabase();
    try {
      const verifier = new TransitionVerifier(verifierIdentity(attack.suffix));
      const ledger = new SqliteCanonicalLedger({
        database: location.database,
        transitionVerifier: verifier,
      });
      const generated = issueEvidence(verifier, [], attack.suffix, 1);
      ledger.commit(request(ledger.cursor(), generated.result, 1, 1));

      const attacker = new DatabaseSync(location.database);
      attacker.exec(attack.sql);
      attacker.close();

      assert.throws(
        () => ledger.status(),
        /non-canonical SQLite text encoding|receipt digest|audit\/receipt metadata/,
      );
      assert.equal(ledger.audit().ok, false);
      ledger.close();
    } finally {
      location.cleanup();
    }
  }
});

test('a real process crash after cursor mutation leaves no partial durable publication', () => {
  const location = temporaryDatabase();
  try {
    const childPath = join(location.directory, 'crash-child.mjs');
    const moduleUrl = new URL('../dist/index.js', import.meta.url).href;
    writeFileSync(
      childPath,
      `
import { createHash } from 'node:crypto';
import {
  SqliteCanonicalLedger,
  TransitionVerifier,
  fingerprintMemoryEvents,
} from ${JSON.stringify(moduleUrl)};

const sha = (value) =>
  \`sha256:\${createHash('sha256').update(value).digest('hex')}\`;
const verifier = new TransitionVerifier({
  id: 'verifier/durable/crash-child',
  actor: 'verifier/durable/crash-child',
  kind: 'deterministic',
  implementation: 'durable-ledger-crash-child',
  version: '1',
  configDigest: sha('verifier/durable/crash-child/config'),
});
const record = {
  id: 'evidence/crash-child',
  scope: 'project/durable',
  kind: 'human-feedback',
  sourceGroups: ['origin/evidence/crash-child'],
  authority: 'human-explicit',
  observedAt: 1,
  sensitivity: 'public',
  taints: [],
  artifact: {
    uri: 'memory://artifact/evidence/crash-child',
    digest: sha('artifact:evidence/crash-child'),
    sizeBytes: 5,
    mediaType: 'text/plain',
    encryption: 'none',
    retention: 'durable',
  },
  preview: 'crash',
  derivedFrom: [],
  labels: ['durable'],
};
const proposal = {
  id: 'transition/crash-child',
  proposer: 'memory-writer',
  baseFingerprint: fingerprintMemoryEvents([]),
  authorizedScopes: ['project/durable'],
  declaredRisk: 'low',
  stateImpact: 'none',
  operations: [{
    id: 'event/evidence/crash-child',
    type: 'evidence.captured',
    recordedAt: 1,
    actor: 'source-ingestor',
    data: { evidence: record },
  }],
  inputEvidenceIds: [record.id],
  ignoredInputEvidence: [],
  externalChecks: [],
  stateExpectations: [],
  rationale: 'exercise a real SQLite crash boundary',
};
const result = verifier.verify([], proposal);
const ledger = new SqliteCanonicalLedger({
  database: process.argv[2],
  transitionVerifier: verifier,
  faultInjector(point) {
    if (point === 'after-cursor') process.exit(91);
  },
});
ledger.commit({
  base: ledger.cursor(),
  result,
  envelope: {
    idempotencyKey: 'crash/real-process',
    auditId: 'audit/crash-real-process',
    recordedAt: 1,
    actor: 'independent-durable-auditor',
    committedBy: 'trusted-durable-host',
  },
});
process.exit(0);
`,
    );

    const crashed = spawnSync(process.execPath, [childPath, location.database], {
      cwd: process.cwd(),
      encoding: 'utf8',
      timeout: 30_000,
    });
    assert.equal(crashed.status, 91, `${crashed.stdout}\n${crashed.stderr}`);

    const recovered = new SqliteCanonicalLedger({ database: location.database });
    assert.equal(recovered.cursor().revision, 0);
    assert.equal(recovered.cursor().eventCount, 0);
    assert.equal(recovered.receipt('crash/real-process'), undefined);
    assert.equal(recovered.audit().ok, true);
    recovered.close();
  } finally {
    location.cleanup();
  }
});

test('repeated reopen and mixed-size appends preserve exact event and receipt history', () => {
  const location = temporaryDatabase();
  try {
    const verifier = new TransitionVerifier(verifierIdentity('long-stream'));
    let canonical = [];
    let expectedRevision = 0;

    for (let step = 1; step <= 12; step += 1) {
      const ledger = new SqliteCanonicalLedger({
        database: location.database,
        transitionVerifier: verifier,
      });
      const generated = issueMultiEvidence(
        verifier,
        canonical,
        `long-stream-${step}`,
        step,
        1 + (step % 3),
      );
      const committed = ledger.commit(
        request(ledger.cursor(), generated.result, step, step, `long-stream/${step}`),
      );
      expectedRevision += 1;
      canonical = generated.all;
      assert.equal(committed.cursor.revision, expectedRevision);
      assert.equal(committed.cursor.eventCount, canonical.length);
      assert.deepEqual(ledger.loadKernel().events(), canonical);
      assert.equal(ledger.audit().ok, true);
      ledger.close();
    }

    const final = new SqliteCanonicalLedger({ database: location.database });
    assert.equal(final.cursor().revision, 12);
    assert.deepEqual(final.readRange(1, canonical.length), canonical);
    assert.equal(final.audit().receiptCount, 12);
    final.close();
  } finally {
    location.cleanup();
  }
});

test('historical append validity is independent from a stricter future admission limit', () => {
  const location = temporaryDatabase();
  try {
    const verifier = new TransitionVerifier(verifierIdentity('append-policy-drift'));
    const writer = new SqliteCanonicalLedger({
      database: location.database,
      transitionVerifier: verifier,
      maxAppendEvents: 3,
    });
    const first = issueMultiEvidence(verifier, [], 'append-policy-drift-one', 1, 2);
    const originalRequest = request(writer.cursor(), first.result, 1, 1);
    const original = writer.commit(originalRequest);
    const portableRetry = structuredClone(originalRequest);
    writer.close();

    const stricter = new SqliteCanonicalLedger({
      database: location.database,
      transitionVerifier: verifier,
      maxAppendEvents: 1,
    });
    assert.equal(stricter.audit().ok, true);
    const retry = stricter.commit(portableRetry);
    assert.equal(retry.idempotentReplay, true);
    assert.equal(retry.receipt.receiptDigest, original.receipt.receiptDigest);
    const second = issueMultiEvidence(
      verifier,
      first.all,
      'append-policy-drift-two',
      2,
      2,
    );
    assert.throws(
      () => stricter.commit(request(stricter.cursor(), second.result, 2, 2)),
      /append exceeds the 1-event limit/,
    );
    stricter.close();
  } finally {
    location.cleanup();
  }
});

test('an audit cursor is descriptive and cannot authorize a new durable commit', () => {
  const { ledger, verifier } = openLedger({ suffix: 'audit-cursor' });
  const generated = issueEvidence(verifier, [], 'audit-cursor', 1);
  const descriptiveCursor = ledger.audit().cursor;
  assert.throws(
    () => ledger.commit(request(descriptiveCursor, generated.result, 1, 1, 'audit/cursor')),
    /capability issued by this ledger/,
  );
  ledger.close();
});

test('file-backed durable ledgers persist SQLite WAL mode', () => {
  const location = temporaryDatabase();
  try {
    const ledger = new SqliteCanonicalLedger({ database: location.database });
    ledger.close();
    const inspector = new DatabaseSync(location.database);
    const row = inspector.prepare('PRAGMA journal_mode').get();
    assert.equal(row.journal_mode, 'wal');
    inspector.close();
  } finally {
    location.cleanup();
  }
});
