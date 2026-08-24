import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  MemoryKernel,
  adjudicateState,
  compileContext,
  evidenceRefFor,
  stateDecisionToContextPacket,
  validateStateSchema,
} from '../dist/index.js';

function digest(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function evidenceRecord({
  id,
  scope = 'user/francesco',
  authority = 'human-explicit',
  kind = 'human-feedback',
  observedAt = 1,
}) {
  return {
    id,
    scope,
    kind,
    sourceGroups: [`origin:${id}`],
    authority,
    observedAt,
    sensitivity: scope === 'global' ? 'public' : 'personal',
    taints: authority === 'model-inference' ? ['model-generated'] : [],
    artifact: {
      uri: `memory://evidence/${id}`,
      digest: digest(id),
      sizeBytes: id.length,
      mediaType: 'application/json',
      encryption: 'none',
      retention: 'durable',
    },
    derivedFrom: [],
    labels: ['state-test'],
  };
}

function claim({
  id,
  key,
  value,
  evidence,
  authority = evidence.authority,
  from = 1,
  confidence = 1,
  epistemicStatus = 'observed',
}) {
  return {
    id,
    key,
    value,
    valid: { from },
    authority,
    epistemicStatus,
    confidence,
    evidence: [evidence],
    derivedFrom: [],
    tags: ['state'],
  };
}

function addClaim(kernel, {
  evidenceId,
  eventTime,
  key,
  value,
  roles = ['supports'],
  authority = 'human-explicit',
  epistemicStatus = 'observed',
  claimId = `claim:${evidenceId}`,
  scope = key.scope,
  kind = authority === 'tool-verified' ? 'test-result' : 'human-feedback',
}) {
  const source = evidenceRecord({
    id: evidenceId,
    scope,
    authority,
    kind,
    observedAt: eventTime,
  });
  kernel.captureEvidence(
    { eventId: `capture:${evidenceId}`, recordedAt: eventTime, actor: 'test' },
    source,
  );
  const record = claim({
    id: claimId,
    key,
    value,
    evidence: evidenceRefFor(source, roles),
    authority,
    from: eventTime,
    epistemicStatus,
  });
  kernel.assertClaim(
    { eventId: `assert:${claimId}`, recordedAt: eventTime + 1, actor: 'test' },
    record,
    { authorizeImmediately: true },
  );
  return { source, claim: record };
}

function schema(slots, invalidations = []) {
  return {
    id: 'state-test-schema',
    version: '1',
    slots,
    invalidations,
    maxInvalidationHops: 8,
    maxInvalidatedSlots: 32,
  };
}

function preferenceSlot(id, predicate) {
  return {
    id,
    domain: 'user-preference',
    key: { scope: 'user/francesco', subject: 'francesco', predicate },
    strategy: 'role-authority',
    evidencePolicy: [
      {
        role: 'supports',
        authorityPrecedence: [
          'human-explicit',
          'repeated-observation',
          'tool-verified',
          'external-source',
          'model-inference',
        ],
        required: true,
      },
    ],
  };
}

function executionSlot(id, predicate) {
  return {
    id,
    domain: 'execution-state',
    key: { scope: 'project/showstead', subject: 'build', predicate },
    strategy: 'role-authority',
    evidencePolicy: [
      {
        role: 'verifies',
        authorityPrecedence: [
          'tool-verified',
          'human-explicit',
          'system-policy',
          'external-source',
          'model-inference',
        ],
        required: true,
      },
      {
        role: 'supports',
        authorityPrecedence: [
          'human-explicit',
          'tool-verified',
          'external-source',
          'model-inference',
        ],
      },
    ],
  };
}

test('authority is adjudicated by evidence role and domain rather than one global rank', () => {
  const kernel = new MemoryKernel();
  const slot = preferenceSlot('preferred-editor', 'preferred-editor');
  addClaim(kernel, {
    evidenceId: 'tool-editor-observation',
    eventTime: 1,
    key: slot.key,
    value: 'vim',
    authority: 'tool-verified',
  });
  addClaim(kernel, {
    evidenceId: 'human-editor-preference',
    eventTime: 3,
    key: slot.key,
    value: 'zed',
    authority: 'human-explicit',
  });

  const decision = adjudicateState(kernel.events(), schema([slot]), {
    slotId: slot.id,
    view: 'current',
    validAt: 10,
  });
  assert.equal(decision.status, 'current');
  assert.equal(decision.value, 'zed');
});

test('a slot requiring verification rejects merely supportive high-authority evidence', () => {
  const kernel = new MemoryKernel();
  const slot = executionSlot('build-status', 'status');
  addClaim(kernel, {
    evidenceId: 'human-build-opinion',
    eventTime: 1,
    key: slot.key,
    value: 'failed',
    roles: ['supports'],
    authority: 'human-explicit',
    scope: 'project/showstead',
  });
  addClaim(kernel, {
    evidenceId: 'actual-build-result',
    eventTime: 3,
    key: slot.key,
    value: 'passed',
    roles: ['verifies'],
    authority: 'tool-verified',
    epistemicStatus: 'verified',
    scope: 'project/showstead',
  });

  const decision = adjudicateState(kernel.events(), schema([slot]), {
    slotId: slot.id,
    view: 'current',
    validAt: 10,
  });
  assert.equal(decision.status, 'current');
  assert.equal(decision.value, 'passed');
  assert.ok(
    decision.explanation.valueGroups.some(
      (group) => group.value === 'failed' && group.reasons.some((reason) => reason.includes('verifies')),
    ),
  );
});

test('equal role-specific authority leaves conflicting values disputed', () => {
  const kernel = new MemoryKernel();
  const slot = preferenceSlot('preferred-shell', 'preferred-shell');
  addClaim(kernel, {
    evidenceId: 'human-shell-a',
    eventTime: 1,
    key: slot.key,
    value: 'zsh',
  });
  addClaim(kernel, {
    evidenceId: 'human-shell-b',
    eventTime: 3,
    key: slot.key,
    value: 'fish',
  });

  const decision = adjudicateState(kernel.events(), schema([slot]), {
    slotId: slot.id,
    view: 'current',
    validAt: 10,
  });
  assert.equal(decision.status, 'disputed');
  assert.equal(decision.value, undefined);
});

test('bitemporal views preserve historical truth and reject a stale current premise', () => {
  const kernel = new MemoryKernel();
  const slot = preferenceSlot('preferred-editor', 'preferred-editor');
  const oldState = addClaim(kernel, {
    evidenceId: 'old-editor',
    eventTime: 1,
    key: slot.key,
    value: 'vim',
  });
  const newState = addClaim(kernel, {
    evidenceId: 'new-editor',
    eventTime: 100,
    key: slot.key,
    value: 'zed',
  });
  kernel.supersedeClaim(
    { eventId: 'supersede-editor', recordedAt: 102, actor: 'human' },
    oldState.claim.id,
    newState.claim.id,
    100,
    'preference changed',
  );

  const current = adjudicateState(kernel.events(), schema([slot]), {
    slotId: slot.id,
    view: 'current',
    validAt: 200,
    premise: 'vim',
  });
  assert.equal(current.status, 'current');
  assert.equal(current.value, 'zed');
  assert.equal(current.premise.status, 'rejected');

  const historical = adjudicateState(kernel.events(), schema([slot]), {
    slotId: slot.id,
    view: 'historical',
    validAt: 50,
    premise: 'vim',
  });
  assert.equal(historical.status, 'historical');
  assert.equal(historical.value, 'vim');
  assert.equal(historical.premise.status, 'accepted');
});

test('a newer upstream state makes an older dependent state unknown-current', () => {
  const kernel = new MemoryKernel();
  const residence = preferenceSlot('residence', 'residence');
  const commute = preferenceSlot('commute', 'commute');
  addClaim(kernel, {
    evidenceId: 'old-commute',
    eventTime: 10,
    key: commute.key,
    value: '20 minutes',
  });
  const residenceState = addClaim(kernel, {
    evidenceId: 'new-residence',
    eventTime: 100,
    key: residence.key,
    value: 'Zurich',
  });

  const decision = adjudicateState(
    kernel.events(),
    schema([residence, commute], [
      {
        id: 'residence-invalidates-commute',
        sourceSlotId: residence.id,
        targetSlotId: commute.id,
        reason: 'a relocation invalidates the previous commute assumption',
      },
    ]),
    {
      slotId: commute.id,
      view: 'current',
      validAt: 200,
      premise: '20 minutes',
    },
  );

  assert.equal(decision.status, 'unknown-current');
  assert.equal(decision.premise.status, 'rejected');
  assert.deepEqual(decision.invalidations[0]?.sourceClaimIds, [residenceState.claim.id]);
});

test('implicit invalidation propagates transitively with bounded provenance paths', () => {
  const kernel = new MemoryKernel();
  const residence = preferenceSlot('residence', 'residence');
  const commute = preferenceSlot('commute', 'commute');
  const morningPlan = preferenceSlot('morning-plan', 'morning-plan');
  addClaim(kernel, {
    evidenceId: 'old-plan',
    eventTime: 40,
    key: morningPlan.key,
    value: 'leave at 08:10',
  });
  addClaim(kernel, {
    evidenceId: 'old-commute',
    eventTime: 50,
    key: commute.key,
    value: '20 minutes',
  });
  addClaim(kernel, {
    evidenceId: 'new-residence',
    eventTime: 100,
    key: residence.key,
    value: 'Zurich',
  });

  const decision = adjudicateState(
    kernel.events(),
    schema([residence, commute, morningPlan], [
      {
        id: 'residence-to-commute',
        sourceSlotId: residence.id,
        targetSlotId: commute.id,
        reason: 'residence affects commute',
      },
      {
        id: 'commute-to-plan',
        sourceSlotId: commute.id,
        targetSlotId: morningPlan.id,
        reason: 'commute affects departure plan',
      },
    ]),
    { slotId: morningPlan.id, view: 'current', validAt: 200 },
  );

  assert.equal(decision.status, 'unknown-current');
  assert.deepEqual(decision.invalidations[0]?.path, [
    'residence-to-commute',
    'commute-to-plan',
  ]);
  assert.equal(decision.invalidations[0]?.effectiveAt, 100);
});

test('a state packet carries role-aware evidence closure into bounded context', () => {
  const kernel = new MemoryKernel();
  const slot = preferenceSlot('preferred-editor', 'preferred-editor');
  const item = addClaim(kernel, {
    evidenceId: 'editor-source',
    eventTime: 1,
    key: slot.key,
    value: 'zed',
  });
  const decision = adjudicateState(kernel.events(), schema([slot]), {
    slotId: slot.id,
    view: 'current',
    validAt: 10,
  });
  const statePacket = stateDecisionToContextPacket(decision, {
    id: 'editor-state-packet',
    activationScore: 10,
    evidencePacketIdBySourceId: { [item.source.id]: 'editor-source-packet' },
    enforceEvidenceDependencies: true,
  });
  const sourcePacket = {
    id: 'editor-source-packet',
    kind: 'source',
    content: 'Francesco explicitly selected Zed.',
    estimatedTokens: 10,
    activationScore: 1,
    topics: ['editor'],
    authorization: 'authorized-current',
  };
  const compiled = compileContext([statePacket, sourcePacket], {
    tokenBudget: 200,
    view: 'current',
  });

  assert.deepEqual(
    new Set(compiled.selected.map((packet) => packet.id)),
    new Set(['editor-state-packet', 'editor-source-packet']),
  );
  assert.deepEqual(statePacket.evidenceLinks, [
    { packetId: 'editor-source-packet', roles: ['supports'] },
  ]);
});

test('cyclic invalidation schemas are rejected before any state decision', () => {
  const first = preferenceSlot('first', 'first');
  const second = preferenceSlot('second', 'second');
  assert.throws(
    () =>
      validateStateSchema(
        schema([first, second], [
          { id: 'first-second', sourceSlotId: 'first', targetSlotId: 'second', reason: 'x' },
          { id: 'second-first', sourceSlotId: 'second', targetSlotId: 'first', reason: 'y' },
        ]),
      ),
    /cycle/,
  );
});

test('currently available contradicting evidence prevents a claim from governing state', () => {
  const kernel = new MemoryKernel();
  const slot = preferenceSlot('preferred-editor', 'preferred-editor');
  addClaim(kernel, {
    evidenceId: 'self-contradicting-editor',
    eventTime: 1,
    key: slot.key,
    value: 'vim',
    roles: ['supports', 'contradicts'],
  });

  const decision = adjudicateState(kernel.events(), schema([slot]), {
    slotId: slot.id,
    view: 'current',
    validAt: 10,
  });
  assert.equal(decision.status, 'unknown');
  assert.ok(
    decision.explanation.candidates[0]?.reasons.some((reason) => reason.includes('contradicting')),
  );
});

test('strict packet construction refuses incomplete provenance mapping', () => {
  const kernel = new MemoryKernel();
  const slot = preferenceSlot('preferred-editor', 'preferred-editor');
  addClaim(kernel, {
    evidenceId: 'unmapped-editor-source',
    eventTime: 1,
    key: slot.key,
    value: 'zed',
  });
  const decision = adjudicateState(kernel.events(), schema([slot]), {
    slotId: slot.id,
    view: 'current',
    validAt: 10,
  });

  assert.throws(
    () =>
      stateDecisionToContextPacket(decision, {
        enforceEvidenceDependencies: true,
        evidencePacketIdBySourceId: {},
      }),
    /missing evidence packet mappings/,
  );
});
