import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import {
  MemoryKernel,
  SqliteCanonicalLedger,
  digestCanonical,
  fingerprintMemoryEvents,
} from '../dist/index.js';

function sha(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function evidence(id, observedAt) {
  return {
    id,
    scope: 'project/durable-ledger',
    kind: 'human-feedback',
    sourceGroups: [`origin/${id}`],
    authority: 'human-explicit',
    observedAt,
    sensitivity: 'internal',
    taints: [],
    artifact: {
      uri: `memory://artifact/${id}`,
      digest: sha(`artifact:${id}`),
      sizeBytes: id.length,
      mediaType: 'text/plain',
      encryption: 'none',
      retention: 'durable',
    },
    preview: `evidence ${id}`,
    derivedFrom: [],
    labels: ['durability-test'],
  };
}

function acceptedCapture(baseEvents, id, recordedAt) {
  const staged = MemoryKernel.from(baseEvents);
  staged.captureEvidence(
    { eventId: `capture/${id}`, recordedAt, actor: 'trusted-writer' },
    evidence(id, recordedAt),
  );
  const nextEvents = staged.events();
  const append = Object.freeze(nextEvents.slice(baseEvents.length));
  const baseFingerprint = fingerprintMemoryEvents(baseEvents);
  const afterFingerprint = fingerprintMemoryEvents(nextEvents);
  const proposalDigest = sha(`proposal:${id}:${baseFingerprint}`);
  const policyDigest = sha('policy:durable-ledger-test:v1');
  const appendFingerprint = digestCanonical(append);
  const resultDigest = sha(
    JSON.stringify({ proposalDigest, policyDigest, baseFingerprint, afterFingerprint, appendFingerprint }),
  );

  return Object.freeze({
    proposalId: `proposal/${id}`,
    proposalDigest,
    policyId: 'policy/durable-ledger-test',
    policyVersion: '1',
    policyDigest,
    verifier: Object.freeze({
      id: 'verifier/durable-ledger-test',
      actor: 'independent-verifier',
      kind: 'deterministic',
      implementation: 'test-fixture',
      version: '1',
      configDigest: sha('verifier-config:durable-ledger-test:v1'),
    }),
    verdict: 'accept',
    actualRisk: 'low',
    baseFingerprint,
    afterFingerprint,
    appendFingerprint,
    findings: Object.freeze([]),
    stateObservations: Object.freeze([]),
    externalCheckIds: Object.freeze([]),
    stagedAppend: append,
    resultDigest,
  });
}

function trustedCommitter(current, result) {
  return MemoryKernel.from([...current.events(), ...result.stagedAppend]);
}

function withDatabase(run) {
  const directory = mkdtempSync(join(tmpdir(), 'continual-ledger-'));
  const path = join(directory, 'canonical.sqlite');
  try {
    return run(path);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test('accepted transition, receipt, and revision survive a process-style reopen', () => {
  withDatabase((path) => {
    const store = new SqliteCanonicalLedger(path);
    const result = acceptedCapture(store.events(), 'first', 10);
    const committed = store.commitVerifiedTransition(
      result,
      trustedCommitter,
      { id: 'receipt/first', recordedAt: 11, actor: 'durable-host' },
    );

    assert.equal(committed.idempotent, false);
    assert.equal(committed.revision.revision, 1);
    assert.equal(committed.revision.eventCount, 1);
    assert.equal(committed.revision.receiptCount, 1);
    assert.equal(committed.appendedEvents.length, 1);
    assert.equal(store.verifyIntegrity().ok, true);
    store.close();

    const reopened = new SqliteCanonicalLedger(path);
    assert.equal(reopened.events().length, 1);
    assert.equal(reopened.receipts().length, 1);
    assert.equal(reopened.loadKernel().evidence('first')?.availability, 'available');

    let capabilityCalled = false;
    const retried = reopened.commitVerifiedTransition(
      result,
      () => {
        capabilityCalled = true;
        throw new Error('an idempotent retry must not consume the process-local capability again');
      },
      { id: 'receipt/retry-is-ignored', recordedAt: 12, actor: 'durable-host' },
    );
    assert.equal(retried.idempotent, true);
    assert.equal(capabilityCalled, false);
    assert.equal(reopened.revision().eventCount, 1);
    assert.equal(reopened.revision().receiptCount, 1);
    reopened.close();
  });
});

test('every injected pre-commit failure rolls back events, receipt, and metadata together', () => {
  const phases = [
    'after-begin',
    'after-event-inserts',
    'after-receipt-insert',
    'after-metadata-update',
    'before-commit',
  ];

  for (const phase of phases) {
    withDatabase((path) => {
      const store = new SqliteCanonicalLedger(path, {
        faultInjector(current) {
          if (current === phase) throw new Error(`injected:${phase}`);
        },
      });
      const result = acceptedCapture(store.events(), `rollback-${phase}`, 20);
      assert.throws(
        () =>
          store.commitVerifiedTransition(
            result,
            trustedCommitter,
            { id: `receipt/${phase}`, recordedAt: 21, actor: 'durable-host' },
          ),
        new RegExp(`injected:${phase}`),
      );
      assert.equal(store.revision().eventCount, 0, phase);
      assert.equal(store.revision().receiptCount, 0, phase);
      assert.equal(store.verifyIntegrity().ok, true, phase);
      store.close();

      const reopened = new SqliteCanonicalLedger(path);
      assert.equal(reopened.revision().eventCount, 0, phase);
      assert.equal(reopened.revision().receiptCount, 0, phase);
      reopened.close();
    });
  }
});

test('two writers prepared from one prefix cannot both commit', () => {
  withDatabase((path) => {
    const first = new SqliteCanonicalLedger(path);
    const second = new SqliteCanonicalLedger(path);
    const base = first.events();
    const resultA = acceptedCapture(base, 'writer-a', 30);
    const resultB = acceptedCapture(base, 'writer-b', 30);

    first.commitVerifiedTransition(
      resultA,
      trustedCommitter,
      { id: 'receipt/writer-a', recordedAt: 31, actor: 'host-a' },
    );
    assert.throws(
      () =>
        second.commitVerifiedTransition(
          resultB,
          trustedCommitter,
          { id: 'receipt/writer-b', recordedAt: 31, actor: 'host-b' },
        ),
      /base is stale/,
    );
    assert.equal(second.revision().eventCount, 1);
    assert.equal(second.revision().receiptCount, 1);
    first.close();
    second.close();
  });
});

test('the durable boundary rejects a committer that rewrites the canonical prefix', () => {
  withDatabase((path) => {
    const store = new SqliteCanonicalLedger(path);
    const first = acceptedCapture(store.events(), 'prefix-original', 40);
    store.commitVerifiedTransition(
      first,
      trustedCommitter,
      { id: 'receipt/prefix-original', recordedAt: 41, actor: 'durable-host' },
    );

    const second = acceptedCapture(store.events(), 'prefix-next', 42);
    assert.throws(
      () =>
        store.commitVerifiedTransition(
          second,
          (current, result) => {
            const rewritten = structuredClone(current.events());
            rewritten[0].data.evidence.preview = 'rewritten historical evidence';
            return MemoryKernel.from([...rewritten, ...result.stagedAppend]);
          },
          { id: 'receipt/prefix-next', recordedAt: 43, actor: 'durable-host' },
        ),
      /rewrote canonical prefix/,
    );
    assert.equal(store.revision().eventCount, 1);
    assert.equal(store.revision().receiptCount, 1);
    store.close();
  });
});

test('event-row or receipt-row tampering is detected on reopen', () => {
  withDatabase((path) => {
    const store = new SqliteCanonicalLedger(path);
    const result = acceptedCapture(store.events(), 'tamper-event', 50);
    store.commitVerifiedTransition(
      result,
      trustedCommitter,
      { id: 'receipt/tamper-event', recordedAt: 51, actor: 'durable-host' },
    );
    store.close();

    const raw = new DatabaseSync(path);
    raw.prepare("UPDATE cl_ledger_events SET actor = 'forged-actor' WHERE seq = 1").run();
    raw.close();
    assert.throws(() => new SqliteCanonicalLedger(path), /columns do not match|integrity failed/);
  });

  withDatabase((path) => {
    const store = new SqliteCanonicalLedger(path);
    const result = acceptedCapture(store.events(), 'tamper-receipt', 60);
    store.commitVerifiedTransition(
      result,
      trustedCommitter,
      { id: 'receipt/tamper-receipt', recordedAt: 61, actor: 'durable-host' },
    );
    store.close();

    const raw = new DatabaseSync(path);
    raw.prepare('DELETE FROM cl_transition_receipts WHERE seq = 1').run();
    raw.close();
    assert.throws(() => new SqliteCanonicalLedger(path), /receipt row count|integrity failed/);
  });
});
