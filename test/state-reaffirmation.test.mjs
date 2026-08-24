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

function slot(id, predicate) {
  return {
    id,
    domain: 'user-state',
    key: { scope: 'user/francesco', subject: 'francesco', predicate },
    strategy: 'role-authority',
    evidencePolicy: [
      {
        role: 'supports',
        authorityPrecedence: ['human-explicit', 'repeated-observation'],
        required: true,
      },
    ],
  };
}

function addClaim(kernel, id, key, value, at) {
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
    labels: ['state-test'],
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
      epistemicStatus: 'observed',
      confidence: 1,
      evidence: [evidenceRefFor(source, ['supports'])],
      derivedFrom: [],
      tags: ['state'],
    },
    { authorizeImmediately: true },
  );
}

test('a reaffirmation does not invalidate dependents unless the rule explicitly triggers on new claims', () => {
  const kernel = new MemoryKernel();
  const residence = slot('residence', 'residence');
  const commute = slot('commute', 'commute');
  addClaim(kernel, 'commute-old', commute.key, '20 minutes', 10);
  addClaim(kernel, 'residence-old', residence.key, 'Rome', 20);
  addClaim(kernel, 'residence-reaffirmed', residence.key, 'Rome', 100);

  const baseSchema = {
    id: 'reaffirmation-schema',
    version: '1',
    slots: [residence, commute],
    invalidations: [
      {
        id: 'residence-to-commute',
        sourceSlotId: residence.id,
        targetSlotId: commute.id,
        reason: 'a residence change invalidates the commute estimate',
      },
    ],
  };

  const valueChangeOnly = adjudicateState(kernel.events(), baseSchema, {
    slotId: commute.id,
    view: 'current',
    validAt: 200,
  });
  assert.equal(valueChangeOnly.status, 'current');
  assert.equal(valueChangeOnly.value, '20 minutes');

  const everyClaim = adjudicateState(
    kernel.events(),
    {
      ...baseSchema,
      invalidations: [{ ...baseSchema.invalidations[0], trigger: 'new-claim' }],
    },
    { slotId: commute.id, view: 'current', validAt: 200 },
  );
  assert.equal(everyClaim.status, 'unknown-current');
});
