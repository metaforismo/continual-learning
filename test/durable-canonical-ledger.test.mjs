import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { MemoryKernel, evidenceRefFor } from '../dist/index.js';
import { SqliteCanonicalLedger } from '../dist/durable/canonical-ledger.js';

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
      digest: sha(id),
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

function claim(id, source, from = 2) {
  return {
    id,
    key: {
      scope: 'project/durable',
      subject: 'francesco',
      predicate: 'preferred-editor',
    },
    value: 'zed',
    valid: { from },
    authority: 'human-explicit',
    epistemicStatus: 'observed',
    confidence: 1,
    evidence: [evidenceRefFor(source, ['supports'])],
    derivedFrom: [],
    tags: ['editor'],
  };
}

function appendEvidence(events, suffix, recordedAt) {
  const kernel = MemoryKernel.from(events);
  const source = evidence(`evidence/${suffix}`, `durable memory ${suffix}`, recordedAt);
  kernel.captureEvidence(
    { eventId: `event/evidence/${suffix}`, recordedAt, actor: 'human' },
    source,
  );
  return {
    source,
    all: kernel.events(),
    append: kernel.events().slice(events.length),
  };
}

function appendClaim(events, source, suffix, recordedAt) {
  const kernel = MemoryKernel.from(events);
  kernel.assertClaim(
    { eventId: `event/claim/${suffix}`, recordedAt, actor: 'human' },
    claim(`claim/${suffix}`, source, recordedAt),
    { authorizeImmediately: true },
  );
  return {
    all: kernel.events(),
    append: kernel.events().slice(events.length),
  };
}

function transition(number) {
  return {
    proposalId: `proposal/${number}`,
    proposalDigest: sha(`proposal/${number}`),
    resultDigest: sha(`result/${number}`),
    verdict: 'accept',
    actualRisk: number % 2 === 0 ? 'medium' : 'low',
    policyId: 'policy/durable-tests',
    policyVersion: '1',
    policyDigest: sha('policy/durable-tests/v1'),
    verifierId: 'verifier/durable-tests',
    verifierConfigDigest: sha('verifier/durable-tests/v1'),
  };
}

function audit(number, metadata, recordedAt) {
  return {
    schemaVersion: 1,
    id: `audit/${number}`,
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
  };
}

function request(base, events, number, recordedAt, key = `idempotency/${number}`) {
  const metadata = transition(number);
  return {
    base,
    idempotencyKey: key,
    committedBy: 'trusted-host',
    events,
    transition: metadata,
    audit: audit(number, metadata, recordedAt),
  };
}

test('one transaction publishes canonical bytes, audit, receipt, and cursor', () => {
  const ledger = new SqliteCanonicalLedger();
  const empty = ledger.status();
  assert.equal(empty.ok, true);
  assert.equal(empty.cursor.revision, 0);

  const first = appendEvidence([], 'one', 1);
  const committed = ledger.commit(request(empty.cursor, first.append, 1, 1));

  assert.equal(committed.idempotentReplay, false);
  assert.equal(committed.cursor.revision, 1);
  assert.equal(committed.cursor.eventCount, 1);
  assert.equal(committed.receipt.appendFromSeq, 1);
  assert.equal(committed.receipt.appendToSeq, 1);
  assert.deepEqual(ledger.readRange(1), first.append);
  assert.deepEqual(ledger.loadKernel().events(), first.all);
  assert.equal(ledger.receipt('idempotency/1')?.receiptDigest, committed.receipt.receiptDigest);
  assert.equal(ledger.status().ok, true);
  assert.equal(ledger.audit().ok, true);
  ledger.close();
});

test('a second commit extends the receipt and event chains while stale and copied cursors fail', () => {
  const ledger = new SqliteCanonicalLedger();
  const base = ledger.cursor();
  const first = appendEvidence([], 'first', 1);
  const committedOne = ledger.commit(request(base, first.append, 1, 1));

  const second = appendClaim(first.all, first.source, 'editor', 2);
  assert.throws(
    () => ledger.commit(request(base, second.append, 2, 2, 'idempotency/stale')),
    /stale/,
  );
  assert.throws(
    () =>
      ledger.commit(
        request(structuredClone(committedOne.cursor), second.append, 2, 2, 'idempotency/copied'),
      ),
    /capability issued by this ledger/,
  );

  const committedTwo = ledger.commit(request(committedOne.cursor, second.append, 2, 2));
  assert.equal(committedTwo.cursor.revision, 2);
  assert.equal(committedTwo.receipt.previousReceiptDigest, committedOne.receipt.receiptDigest);
  assert.equal(committedTwo.receipt.baseChainDigest, committedOne.receipt.afterChainDigest);
  assert.equal(ledger.audit().ok, true);
  ledger.close();
});

test('an exact idempotent retry survives process restart without granting a new mutation capability', () => {
  const location = temporaryDatabase();
  try {
    const firstProcess = new SqliteCanonicalLedger({ database: location.database });
    const generated = appendEvidence([], 'restart', 1);
    const original = request(firstProcess.cursor(), generated.append, 1, 1, 'retry/restart');
    const initial = firstProcess.commit(original);
    const portableRetry = structuredClone(original);
    firstProcess.close();

    const secondProcess = new SqliteCanonicalLedger({ database: location.database });
    const retry = secondProcess.commit(portableRetry);
    assert.equal(retry.idempotentReplay, true);
    assert.equal(retry.receipt.receiptDigest, initial.receipt.receiptDigest);
    assert.equal(retry.cursor.revision, 1);

    const changed = structuredClone(portableRetry);
    changed.events[0].actor = 'different-actor';
    assert.throws(() => secondProcess.commit(changed), /different durable request/);
    secondProcess.close();
  } finally {
    location.cleanup();
  }
});

test('fault injection rolls back events, audit, receipt, and cursor together', () => {
  const location = temporaryDatabase();
  try {
    let failAt = 'after-receipt';
    const ledger = new SqliteCanonicalLedger({
      database: location.database,
      faultInjector(point) {
        if (point === failAt) throw new Error(`injected failure at ${point}`);
      },
    });
    const generated = appendEvidence([], 'rollback', 1);
    const pending = request(ledger.cursor(), generated.append, 1, 1, 'rollback/key');
    assert.throws(() => ledger.commit(pending), /injected failure/);
    assert.equal(ledger.cursor().revision, 0);
    assert.equal(ledger.readRange(1).length, 0);
    assert.equal(ledger.receipt('rollback/key'), undefined);
    assert.equal(ledger.audit().ok, true);

    failAt = undefined;
    assert.equal(ledger.commit(pending).cursor.revision, 1);
    ledger.close();
  } finally {
    location.cleanup();
  }
});

test('two writers cannot both publish from the same canonical cursor', () => {
  const location = temporaryDatabase();
  try {
    const writerA = new SqliteCanonicalLedger({ database: location.database });
    const writerB = new SqliteCanonicalLedger({ database: location.database });
    const cursorA = writerA.cursor();
    const cursorB = writerB.cursor();
    const appendA = appendEvidence([], 'writer-a', 1);
    const appendB = appendEvidence([], 'writer-b', 1);

    writerA.commit(request(cursorA, appendA.append, 1, 1, 'writer/a'));
    assert.throws(
      () => writerB.commit(request(cursorB, appendB.append, 2, 1, 'writer/b')),
      /stale/,
    );
    assert.equal(writerA.audit().ok, true);
    writerA.close();
    writerB.close();
  } finally {
    location.cleanup();
  }
});

test('fast status checks the durable tail while full audit detects older event-byte tampering', () => {
  const location = temporaryDatabase();
  try {
    const ledger = new SqliteCanonicalLedger({ database: location.database });
    const first = appendEvidence([], 'tamper-one', 1);
    const one = ledger.commit(request(ledger.cursor(), first.append, 1, 1));
    const second = appendEvidence(first.all, 'tamper-two', 2);
    ledger.commit(request(one.cursor, second.append, 2, 2));

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

test('fast status recomputes the latest audit and receipt integrity', () => {
  const location = temporaryDatabase();
  try {
    const ledger = new SqliteCanonicalLedger({ database: location.database });
    const generated = appendEvidence([], 'audit-tamper', 1);
    ledger.commit(request(ledger.cursor(), generated.append, 1, 1));

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

test('range reads verify local row digests, predecessor links, and bounds', () => {
  const ledger = new SqliteCanonicalLedger();
  const first = appendEvidence([], 'range-one', 1);
  const one = ledger.commit(request(ledger.cursor(), first.append, 1, 1));
  const second = appendEvidence(first.all, 'range-two', 2);
  ledger.commit(request(one.cursor, second.append, 2, 2));

  assert.deepEqual(ledger.readRange(2, 1), second.append);
  assert.throws(() => ledger.readRange(0), /positive/);
  assert.throws(() => ledger.readRange(1, 1_001), /range limit/);
  ledger.close();
});

test('a partially created durable schema fails closed instead of being silently reset', () => {
  const location = temporaryDatabase();
  try {
    const partial = new DatabaseSync(location.database);
    partial.exec('CREATE TABLE cl_canonical_meta (id INTEGER PRIMARY KEY)');
    partial.close();
    assert.throws(
      () => new SqliteCanonicalLedger({ database: location.database }),
      /partially present/,
    );
  } finally {
    location.cleanup();
  }
});

test('new commits require an issued cursor even when supplied metadata matches the empty ledger', () => {
  const ledger = new SqliteCanonicalLedger();
  const generated = appendEvidence([], 'forged-cursor', 1);
  const forged = structuredClone(ledger.cursor());
  assert.throws(
    () => ledger.commit(request(forged, generated.append, 1, 1, 'forged/cursor')),
    /capability issued by this ledger/,
  );
  ledger.close();
});
