import assert from 'node:assert/strict';
import test from 'node:test';

import { activateMemories } from '../dist/index.js';

const now = 1_800_000_000_000;

const nodes = [
  {
    id: 'generic-react',
    kind: 'entity',
    scope: 'global',
    text: 'React JavaScript user interface library',
    goalTags: [],
    authority: 'external-source',
    recordedAt: now - 1000,
  },
  {
    id: 'showstead-auth-episode',
    kind: 'episode',
    scope: 'project/showstead',
    text: 'Showstead flaky authentication test caused by session race',
    goalTags: ['debug', 'auth'],
    authority: 'tool-verified',
    recordedAt: now - 2000,
    successes: 1,
    failures: 0,
  },
  {
    id: 'race-procedure',
    kind: 'procedure',
    scope: 'project/showstead',
    text: 'Serialize session setup before asserting authenticated state',
    goalTags: ['debug', 'auth'],
    authority: 'tool-verified',
    recordedAt: now - 3000,
    successes: 12,
    failures: 1,
  },
  ...Array.from({ length: 16 }, (_, index) => ({
    id: `generic-child-${index}`,
    kind: 'source',
    scope: 'global',
    text: `generic React source ${index}`,
    goalTags: [],
    authority: 'external-source',
    recordedAt: now - 4000,
  })),
];

const edges = [
  {
    from: 'showstead-auth-episode',
    to: 'race-procedure',
    weight: 0.95,
    kind: 'procedural',
  },
  ...Array.from({ length: 16 }, (_, index) => ({
    from: 'generic-react',
    to: `generic-child-${index}`,
    weight: 0.9,
    kind: 'semantic',
  })),
];

test('associative activation recalls a useful procedure without placing the whole graph in context', () => {
  const result = activateMemories(nodes, edges, {
    text: 'debug the flaky authentication test in Showstead',
    scopeChain: ['project/showstead', 'user/francesco', 'global'],
    goalTags: ['debug', 'auth'],
    now,
    maxHops: 2,
    limit: 8,
  });

  const ids = result.map((entry) => entry.id);
  assert.ok(ids.includes('showstead-auth-episode'));
  assert.ok(ids.includes('race-procedure'));
  assert.ok(result.find((entry) => entry.id === 'race-procedure')?.components.propagation > 0);
  assert.ok(ids.length <= 8);
});

test('fan-out inhibition prevents a generic hub from flooding the activation frontier', () => {
  const result = activateMemories(nodes, edges, {
    text: 'React authentication debugging',
    scopeChain: ['project/showstead', 'global'],
    goalTags: ['debug', 'auth'],
    now,
    maxHops: 1,
    limit: 6,
  });

  const genericChildren = result.filter((entry) => entry.id.startsWith('generic-child-'));
  assert.ok(genericChildren.length < 5);
  assert.ok(result.some((entry) => entry.id === 'race-procedure'));
});

test('scope authorization is a hard boundary even for exact, seeded, or associated matches', () => {
  const scopedNodes = [
    ...nodes,
    {
      id: 'other-user-secret',
      kind: 'episode',
      scope: 'user/other',
      text: 'Showstead flaky authentication test secret exact match',
      goalTags: ['debug', 'auth'],
      authority: 'human-explicit',
      recordedAt: now,
      successes: 100,
      failures: 0,
    },
  ];
  const scopedEdges = [
    ...edges,
    {
      from: 'showstead-auth-episode',
      to: 'other-user-secret',
      weight: 1,
      kind: 'causal',
    },
  ];

  const result = activateMemories(scopedNodes, scopedEdges, {
    text: 'Showstead flaky authentication test secret exact match',
    scopeChain: ['project/showstead', 'user/francesco', 'global'],
    goalTags: ['debug', 'auth'],
    seedIds: ['other-user-secret'],
    semanticScores: { 'other-user-secret': 1 },
    now,
    maxHops: 2,
  });

  assert.equal(result.some((entry) => entry.id === 'other-user-secret'), false);
});

test('authority and recency do not activate an unrelated memory without a cue', () => {
  const result = activateMemories(
    [
      {
        id: 'unrelated',
        kind: 'episode',
        scope: 'project/showstead',
        text: 'completely unrelated cooking note',
        goalTags: [],
        authority: 'system-policy',
        recordedAt: now,
        successes: 100,
        failures: 0,
      },
    ],
    [],
    {
      text: 'debug authentication',
      scopeChain: ['project/showstead'],
      goalTags: ['debug'],
      now,
    },
  );

  assert.deepEqual(result, []);
});
