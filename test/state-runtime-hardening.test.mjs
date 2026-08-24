import assert from 'node:assert/strict';
import test from 'node:test';

import {
  stateDecisionToContextPacket,
  validateStateSchema,
} from '../dist/index.js';

function baseSlot(overrides = {}) {
  return {
    id: 'slot',
    domain: 'runtime-hardening',
    key: { scope: 'global', subject: 'subject', predicate: 'predicate' },
    strategy: 'role-authority',
    evidencePolicy: [
      {
        role: 'supports',
        authorityPrecedence: ['human-explicit'],
        required: true,
      },
    ],
    ...overrides,
  };
}

test('state schemas reject non-boolean optional policy flags from runtime JSON', () => {
  assert.throws(
    () =>
      validateStateSchema({
        id: 'bad-allow-inferred',
        version: '1',
        slots: [baseSlot({ allowInferred: 'yes' })],
      }),
    /allowInferred must be boolean/,
  );

  assert.throws(
    () =>
      validateStateSchema({
        id: 'bad-required',
        version: '1',
        slots: [
          baseSlot({
            evidencePolicy: [
              {
                role: 'supports',
                authorityPrecedence: ['human-explicit'],
                required: 'yes',
              },
            ],
          }),
        ],
      }),
    /required must be boolean/,
  );

  const source = baseSlot({ id: 'source', key: { scope: 'global', subject: 's', predicate: 'p1' } });
  const target = baseSlot({ id: 'target', key: { scope: 'global', subject: 's', predicate: 'p2' } });
  assert.throws(
    () =>
      validateStateSchema({
        id: 'bad-propagation-flag',
        version: '1',
        slots: [source, target],
        invalidations: [
          {
            id: 'source-target',
            sourceSlotId: 'source',
            targetSlotId: 'target',
            reason: 'test',
            propagateWhenSourceUncertain: 'yes',
          },
        ],
      }),
    /propagateWhenSourceUncertain must be boolean/,
  );
});

function evidence(sourceId) {
  return {
    sourceId,
    sourceGroups: [`origin:${sourceId}`],
    authority: 'human-explicit',
    contentHash: `sha256:${sourceId.padEnd(64, '0').slice(0, 64)}`,
    roles: ['supports'],
  };
}

function claim(id, value, sourceId) {
  return {
    id,
    key: { scope: 'global', subject: 'subject', predicate: 'predicate' },
    value,
    valid: { from: 1 },
    authority: 'human-explicit',
    epistemicStatus: 'observed',
    confidence: 1,
    evidence: [evidence(sourceId)],
    derivedFrom: [],
    tags: ['state'],
  };
}

test('disputed context packets expose and require provenance only for eligible candidates', () => {
  const eligibleA = claim('claim-a', 'a', 'source-a');
  const eligibleB = claim('claim-b', 'b', 'source-b');
  const ineligible = claim('claim-ineligible', 'c', 'source-ineligible');
  const slot = baseSlot();

  const decision = {
    slot,
    request: { slotId: slot.id, view: 'current', validAt: 10 },
    status: 'disputed',
    candidates: [eligibleA, eligibleB, ineligible],
    invalidations: [],
    premise: {
      status: 'unsupported',
      reason: 'no premise',
    },
    explanation: {
      schemaId: 'schema',
      schemaVersion: '1',
      slotId: slot.id,
      strategy: slot.strategy,
      reasons: ['two eligible values remain tied'],
      candidates: [
        { claim: eligibleA, eligible: true, reasons: [], roleRanks: [] },
        { claim: eligibleB, eligible: true, reasons: [], roleRanks: [] },
        {
          claim: ineligible,
          eligible: false,
          reasons: ['not authorized'],
          roleRanks: [],
        },
      ],
      valueGroups: [],
    },
  };

  const packet = stateDecisionToContextPacket(decision, {
    evidencePacketIdBySourceId: {
      'source-a': 'packet-a',
      'source-b': 'packet-b',
    },
  });

  assert.match(packet.content, /claim-a/);
  assert.match(packet.content, /claim-b/);
  assert.doesNotMatch(packet.content, /claim-ineligible/);
  assert.deepEqual(
    packet.evidenceLinks.map((link) => link.packetId),
    ['packet-a', 'packet-b'],
  );
});
