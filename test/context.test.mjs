import assert from 'node:assert/strict';
import test from 'node:test';

import { compileContext } from '../dist/index.js';

function packet(overrides) {
  return {
    id: 'packet',
    kind: 'episode',
    content: 'memory',
    estimatedTokens: 50,
    activationScore: 1,
    topics: ['memory'],
    authorization: 'authorized-current',
    ...overrides,
  };
}

test('the compiler activates many candidates but materializes a diverse bounded working set', () => {
  const packets = [
    packet({
      id: 'current-state',
      kind: 'state',
      content: 'current project is Showstead',
      estimatedTokens: 30,
      activationScore: 10,
      topics: ['showstead', 'state'],
      mandatory: true,
    }),
    packet({
      id: 'procedure',
      kind: 'procedure',
      content: 'serialize auth setup',
      estimatedTokens: 80,
      activationScore: 9,
      topics: ['auth', 'race'],
      evidencePacketIds: ['source'],
      risk: 'high',
    }),
    packet({
      id: 'source',
      kind: 'source',
      content: 'test output proving the race',
      estimatedTokens: 50,
      activationScore: 5,
      topics: ['auth', 'test'],
    }),
    packet({
      id: 'episode',
      kind: 'episode',
      content: 'prior auth debugging episode',
      estimatedTokens: 70,
      activationScore: 7,
      topics: ['auth', 'debug'],
    }),
    packet({
      id: 'duplicate-episode',
      kind: 'episode',
      content: 'nearly identical prior auth debugging episode',
      estimatedTokens: 70,
      activationScore: 6.9,
      topics: ['auth', 'debug'],
    }),
    packet({
      id: 'stale-state',
      kind: 'state',
      content: 'old project state',
      estimatedTokens: 20,
      activationScore: 100,
      topics: ['state'],
      authorization: 'authorized-historical',
    }),
    packet({
      id: 'quarantined',
      kind: 'procedure',
      content: 'unverified lesson',
      estimatedTokens: 10,
      activationScore: 100,
      topics: ['auth'],
      authorization: 'quarantined',
    }),
  ];

  const compiled = compileContext(packets, {
    tokenBudget: 250,
    view: 'current',
    maxPerKind: { episode: 1 },
  });

  assert.ok(compiled.totalTokens <= 250);
  assert.deepEqual(
    new Set(compiled.selected.map((item) => item.id)),
    new Set(['current-state', 'procedure', 'source', 'episode']),
  );
  assert.match(
    compiled.rejected.find((item) => item.id === 'stale-state')?.reason ?? '',
    /historical memory/,
  );
  assert.match(
    compiled.rejected.find((item) => item.id === 'quarantined')?.reason ?? '',
    /quarantined/,
  );
});

test('high-risk learned procedures cannot enter context without their evidence', () => {
  const packets = [
    packet({
      id: 'unsafe-procedure',
      kind: 'procedure',
      risk: 'high',
      activationScore: 100,
      evidencePacketIds: [],
    }),
  ];

  const compiled = compileContext(packets, { tokenBudget: 100, view: 'current' });
  assert.equal(compiled.selected.length, 0);
  assert.match(compiled.rejected[0]?.reason ?? '', /evidence/);
});

test('dependency closures cannot collectively exceed a per-kind cap', () => {
  const packets = [
    packet({
      id: 'procedure-with-two-episodes',
      kind: 'procedure',
      activationScore: 100,
      dependsOn: ['episode-a', 'episode-b'],
    }),
    packet({ id: 'episode-a', kind: 'episode', activationScore: 1 }),
    packet({ id: 'episode-b', kind: 'episode', activationScore: 1 }),
  ];

  const compiled = compileContext(packets, {
    tokenBudget: 500,
    view: 'current',
    maxPerKind: { episode: 1 },
  });

  assert.equal(compiled.selected.some((item) => item.id === 'procedure-with-two-episodes'), false);
  assert.ok(compiled.selected.filter((item) => item.kind === 'episode').length <= 1);
  assert.match(
    compiled.rejected.find((item) => item.id === 'procedure-with-two-episodes')?.reason ?? '',
    /maxPerKind/,
  );
});
