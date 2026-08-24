import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  MemoryKernel,
  adjudicateState,
  evidenceRefFor,
} from '../dist/index.js';

function digest(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function stateSlot(id, predicate, strategy = 'latest-valid') {
  return {
    id,
    domain: 'eligibility-test',
    key: { scope: 'user/francesco', subject: 'francesco', predicate },
    strategy,
    evidencePolicy: [
      {
        role: 'supports',
        authorityPrecedence: ['human-explicit'],
        required: true,
      },
    ],
  };
}

function addClaim(kernel, { id, key, value, at, epistemicStatus = 'observed' }) {
  const source = {
    id: `evidence:${id}`,
    scope: key.scope,
    kind: 'human-feedback',
    sourceGroups: [`origin:${id}`],
    authority: 'human-explicit',
    observedAt: at,
    sensitivity: 'personal',
    taints: [],
    artifact: {
      uri: `memory://evidence/${id}`,
      digest: digest(id),
      sizeBytes: id.length,
      mediaType: 'application/json',
      encryption: 'none',
      retention: 'durable',
    },
    derivedFrom: [],
    labels: ['eligibility-test'],
  };
  kernel.captureEvidence(
    { eventId: `capture:${id}`, recordedAt: at, actor: 'test' },
    source,
  );
  kernel.assertClaim(
    { eventId: `assert:${id}`, recordedAt: at + 1, actor: 'test' },
    {
      id: `claim:${id}`,
      key,
      value,
      valid: { from: at },
      authority: 'human-explicit',
      epistemicStatus,
      confidence: 1,
      evidence: [evidenceRefFor(source, ['supports'])],
      derivedFrom: [],
      tags: ['state'],
    },
    { authorizeImmediately: true },
  );
}

function schema(slots, invalidations = []) {
  return {
    id: 'eligibility-schema',
    version: '1',
    slots,
    invalidations,
  };
}

test('an ineligible newer claim cannot win latest-valid selection', () => {
  const kernel = new MemoryKernel();
  const slot = stateSlot('editor', 'editor');
  addClaim(kernel, { id: 'eligible-old', key: slot.key, value: 'zed', at: 10 });
  addClaim(kernel, {
    id: 'inferred-new',
    key: slot.key,
    value: 'vim',
    at: 100,
    epistemicStatus: 'inferred',
  });

  const decision = adjudicateState(kernel.events(), schema([slot]), {
    slotId: slot.id,
    view: 'current',
    validAt: 200,
  });
  assert.equal(decision.status, 'current');
  assert.equal(decision.value, 'zed');
});

test('an ineligible newer target claim cannot hide a valid upstream invalidation', () => {
  const kernel = new MemoryKernel();
  const source = stateSlot('residence', 'residence', 'role-authority');
  const target = stateSlot('commute', 'commute');
  addClaim(kernel, { id: 'eligible-commute', key: target.key, value: '20 minutes', at: 10 });
  addClaim(kernel, { id: 'residence-change', key: source.key, value: 'Zurich', at: 100 });
  addClaim(kernel, {
    id: 'ineligible-commute',
    key: target.key,
    value: '15 minutes',
    at: 150,
    epistemicStatus: 'inferred',
  });

  const decision = adjudicateState(
    kernel.events(),
    schema([source, target], [
      {
        id: 'residence-to-commute',
        sourceSlotId: source.id,
        targetSlotId: target.id,
        reason: 'residence changes invalidate commute assumptions',
      },
    ]),
    { slotId: target.id, view: 'current', validAt: 300 },
  );
  assert.equal(decision.status, 'unknown-current');
});

test('an ineligible newer source claim cannot create a disputed invalidation frontier', () => {
  const kernel = new MemoryKernel();
  const source = stateSlot('location', 'location', 'role-authority');
  const target = stateSlot('weather-plan', 'weather-plan');
  addClaim(kernel, { id: 'source-a', key: source.key, value: 'Rome', at: 50 });
  addClaim(kernel, { id: 'source-b', key: source.key, value: 'Milan', at: 60 });
  addClaim(kernel, { id: 'target', key: target.key, value: 'take umbrella', at: 100 });
  addClaim(kernel, {
    id: 'source-ineligible',
    key: source.key,
    value: 'Zurich',
    at: 200,
    epistemicStatus: 'inferred',
  });

  const sourceDecision = adjudicateState(kernel.events(), schema([source, target]), {
    slotId: source.id,
    view: 'current',
    validAt: 300,
  });
  assert.equal(sourceDecision.status, 'disputed');

  const targetDecision = adjudicateState(
    kernel.events(),
    schema([source, target], [
      {
        id: 'location-to-plan',
        sourceSlotId: source.id,
        targetSlotId: target.id,
        reason: 'location affects the weather plan',
      },
    ]),
    { slotId: target.id, view: 'current', validAt: 300 },
  );
  assert.equal(targetDecision.status, 'current');
  assert.equal(targetDecision.value, 'take umbrella');
});
