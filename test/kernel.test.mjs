import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';

import { EventLedger, MemoryKernel } from '../dist/index.js';

const DAY = 86_400_000;

function digestFor(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function evidence(sourceId, authority = 'human-explicit', sourceGroup = sourceId) {
  return { sourceId, sourceGroups: [sourceGroup], authority, contentHash: digestFor(sourceId) };
}

function evidenceRecord(sourceId, authority = 'human-explicit', sourceGroup = sourceId) {
  return {
    id: sourceId,
    scope: 'user/francesco',
    kind: 'human-feedback',
    sourceGroups: [sourceGroup],
    authority,
    observedAt: 0,
    sensitivity: 'personal',
    taints: authority === 'model-inference' ? ['model-generated'] : [],
    artifact: {
      uri: `memory://evidence/${sourceId}`,
      digest: digestFor(sourceId),
      sizeBytes: 1,
      mediaType: 'application/json',
      encryption: 'none',
      retention: 'durable',
    },
    derivedFrom: [],
    labels: ['test'],
  };
}

function captureClaimEvidence(kernel, candidate, recordedAt) {
  for (const reference of candidate.evidence) {
    kernel.captureEvidence(
      { eventId: `capture-${reference.sourceId}`, recordedAt, actor: 'test-evidence-writer' },
      evidenceRecord(reference.sourceId, reference.authority, reference.sourceGroups[0]),
    );
  }
}

function claim({
  id,
  value,
  from = 0,
  authority = 'human-explicit',
  epistemicStatus = 'observed',
  sourceId = `${id}-source`,
}) {
  return {
    id,
    key: { scope: 'user/francesco', subject: 'francesco', predicate: 'preferred-editor' },
    value,
    valid: { from },
    authority,
    epistemicStatus,
    confidence: 0.95,
    evidence: [evidence(sourceId, authority)],
    derivedFrom: [],
    tags: ['preference', 'editor'],
  };
}

test('the ledger is append-only, snapshots inputs, and rejects duplicate event ids', () => {
  const ledger = new EventLedger();
  const mutableClaim = claim({ id: 'claim-1', value: 'vim' });

  const event = ledger.append({
    id: 'event-1',
    type: 'claim.asserted',
    recordedAt: 1,
    actor: 'test',
    data: { claim: mutableClaim, initialLifecycle: 'active' },
  });

  mutableClaim.tags.push?.('mutated-after-write');
  assert.deepEqual(event.data.claim.tags, ['preference', 'editor']);
  assert.equal(event.seq, 1);
  assert.throws(
    () =>
      ledger.append({
        id: 'event-1',
        type: 'claim.asserted',
        recordedAt: 2,
        actor: 'test',
        data: { claim: claim({ id: 'claim-2', value: 'emacs' }), initialLifecycle: 'active' },
      }),
    /duplicate event id/,
  );
});

test('unverified model inference is quarantined and cannot drive state before admission', () => {
  const kernel = new MemoryKernel();
  const inferred = claim({
    id: 'claim-inferred',
    value: 'neovim',
    authority: 'model-inference',
    epistemicStatus: 'inferred',
  });

  captureClaimEvidence(kernel, inferred, 9);
  kernel.assertClaim({ eventId: 'event-assert', recordedAt: 10, actor: 'memory-writer' }, inferred);

  const before = kernel.resolveClaim(inferred.key, { validAt: 10 });
  assert.equal(before.status, 'unknown');

  kernel.admitClaim(
    { eventId: 'event-admit', recordedAt: 11, actor: 'human-reviewer' },
    inferred.id,
    'explicitly confirmed',
  );

  const after = kernel.resolveClaim(inferred.key, { validAt: 10 });
  assert.equal(after.status, 'resolved');
  assert.equal(after.claim?.value, 'neovim');

  const another = claim({
    id: 'claim-bad-immediate',
    value: 'zed',
    authority: 'model-inference',
    epistemicStatus: 'inferred',
  });
  captureClaimEvidence(kernel, another, 12);
  assert.throws(
    () =>
      kernel.assertClaim(
        { eventId: 'event-bad', recordedAt: 12, actor: 'memory-writer' },
        another,
        { authorizeImmediately: true },
      ),
    /must enter quarantine/,
  );
});

test('bitemporal supersession preserves historical truth and current truth', () => {
  const kernel = new MemoryKernel();
  const oldClaim = claim({ id: 'claim-old', value: 'vim', from: 0 });
  const newClaim = claim({ id: 'claim-new', value: 'zed', from: 30 * DAY });

  captureClaimEvidence(kernel, oldClaim, 0);
  kernel.assertClaim(
    { eventId: 'event-old', recordedAt: 1 * DAY, actor: 'human' },
    oldClaim,
    { authorizeImmediately: true },
  );
  captureClaimEvidence(kernel, newClaim, 30 * DAY);
  kernel.assertClaim(
    { eventId: 'event-new', recordedAt: 31 * DAY, actor: 'human' },
    newClaim,
    { authorizeImmediately: true },
  );
  kernel.supersedeClaim(
    { eventId: 'event-supersede', recordedAt: 31 * DAY + 1, actor: 'human' },
    oldClaim.id,
    newClaim.id,
    30 * DAY,
    'preference changed',
  );

  const historical = kernel.resolveClaim(oldClaim.key, { validAt: 10 * DAY });
  assert.equal(historical.status, 'resolved');
  assert.equal(historical.claim?.value, 'vim');

  const current = kernel.resolveClaim(oldClaim.key, { validAt: 40 * DAY });
  assert.equal(current.status, 'resolved');
  assert.equal(current.claim?.value, 'zed');

  const asKnownBeforeUpdate = kernel.resolveClaim(oldClaim.key, {
    validAt: 40 * DAY,
    knownAt: 20 * DAY,
  });
  assert.equal(asKnownBeforeUpdate.status, 'resolved');
  assert.equal(asKnownBeforeUpdate.claim?.value, 'vim');
});

test('conflicting claims remain ambiguous unless an explicit authority policy resolves them', () => {
  const kernel = new MemoryKernel();
  const inferred = claim({
    id: 'claim-low',
    value: 'vim',
    authority: 'model-inference',
    epistemicStatus: 'inferred',
  });
  const human = claim({ id: 'claim-high', value: 'zed', authority: 'human-explicit' });

  captureClaimEvidence(kernel, inferred, 0);
  kernel.assertClaim(
    { eventId: 'event-low', recordedAt: 1, actor: 'writer' },
    inferred,
    { authorizeImmediately: false },
  );
  kernel.admitClaim(
    { eventId: 'event-low-admit', recordedAt: 2, actor: 'reviewer' },
    inferred.id,
    'kept as a competing hypothesis',
  );
  captureClaimEvidence(kernel, human, 2);
  kernel.assertClaim(
    { eventId: 'event-high', recordedAt: 3, actor: 'human' },
    human,
    { authorizeImmediately: true },
  );

  const conservative = kernel.resolveClaim(human.key, { validAt: 4 });
  assert.equal(conservative.status, 'ambiguous');

  const policyResolved = kernel.resolveClaim(human.key, {
    validAt: 4,
    allowAuthorityDominance: true,
  });
  assert.equal(policyResolved.status, 'resolved');
  assert.equal(policyResolved.claim?.id, human.id);
});

test('transaction time is monotonic so known-at replay cannot observe orphaned later events', () => {
  const ledger = new EventLedger();
  ledger.append({
    id: 'event-time-1',
    type: 'claim.asserted',
    recordedAt: 100,
    actor: 'test',
    data: { claim: claim({ id: 'claim-time-1', value: 'vim' }), initialLifecycle: 'active' },
  });

  assert.throws(
    () =>
      ledger.append({
        id: 'event-time-2',
        type: 'claim.asserted',
        recordedAt: 99,
        actor: 'test',
        data: { claim: claim({ id: 'claim-time-2', value: 'zed' }), initialLifecycle: 'active' },
      }),
    /recordedAt must be monotonic/,
  );
});

test('the ledger snapshots stateful input properties once before validation', () => {
  const ledger = new EventLedger();
  let reads = 0;
  const input = {
    get id() {
      reads += 1;
      return reads === 1 ? 'stable-event-id' : 'changed-event-id';
    },
    type: 'claim.asserted',
    recordedAt: 1,
    actor: 'test',
    data: { claim: claim({ id: 'stable-claim', value: 'vim' }), initialLifecycle: 'active' },
  };

  const event = ledger.append(input);
  assert.equal(reads, 1);
  assert.equal(event.id, 'stable-event-id');
});

test('the ledger rejects circular and sparse structures instead of persisting ambiguous JSON', () => {
  const ledger = new EventLedger();
  const circular = {};
  circular.self = circular;
  const sparse = [];
  sparse.length = 1;

  assert.throws(
    () =>
      ledger.append({
        id: 'circular-event',
        type: 'outcome.recorded',
        recordedAt: 1,
        actor: 'test',
        data: circular,
      }),
    /circular reference/,
  );
  assert.throws(
    () =>
      ledger.append({
        id: 'sparse-event',
        type: 'outcome.recorded',
        recordedAt: 1,
        actor: 'test',
        data: sparse,
      }),
    /sparse array/,
  );
});

test('claim identities and derivation lineage cannot be invented or reused', () => {
  const kernel = new MemoryKernel();
  const original = claim({ id: 'stable-claim-id', value: 'vim' });
  captureClaimEvidence(kernel, original, 1);
  kernel.assertClaim(
    { eventId: 'assert-stable-claim', recordedAt: 2, actor: 'writer' },
    original,
    { authorizeImmediately: true },
  );

  assert.throws(
    () =>
      kernel.assertClaim(
        { eventId: 'assert-duplicate-claim', recordedAt: 3, actor: 'writer' },
        { ...original, value: 'zed' },
        { authorizeImmediately: true },
      ),
    /claim id already exists/,
  );

  const derived = claim({ id: 'derived-with-missing-parent', value: 'zed' });
  captureClaimEvidence(kernel, derived, 3);
  assert.throws(
    () =>
      kernel.assertClaim(
        { eventId: 'assert-missing-parent', recordedAt: 4, actor: 'writer' },
        { ...derived, derivedFrom: ['missing-parent'] },
        { authorizeImmediately: true },
      ),
    /unknown parent claim/,
  );
});

test('strict JSON snapshotting preserves __proto__ as data without prototype pollution', () => {
  const ledger = new EventLedger();
  const malicious = JSON.parse('{"__proto__":{"polluted":true},"value":"safe"}');
  const event = ledger.append({
    id: 'prototype-data-event',
    type: 'outcome.recorded',
    recordedAt: 1,
    actor: 'test',
    data: malicious,
  });

  assert.equal({}.polluted, undefined);
  assert.equal(Object.prototype.hasOwnProperty.call(event.data, '__proto__'), true);
  assert.equal(event.data.__proto__.polluted, true);
  assert.equal(Object.getPrototypeOf(event.data), Object.prototype);
});
