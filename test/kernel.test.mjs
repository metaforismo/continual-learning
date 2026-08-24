import assert from 'node:assert/strict';
import test from 'node:test';

import { EventLedger, MemoryKernel } from '../dist/index.js';

const DAY = 86_400_000;

function evidence(sourceId, authority = 'human-explicit', sourceGroup = sourceId) {
  return { sourceId, sourceGroup, authority };
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

  kernel.assertClaim(
    { eventId: 'event-old', recordedAt: 1 * DAY, actor: 'human' },
    oldClaim,
    { authorizeImmediately: true },
  );
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
