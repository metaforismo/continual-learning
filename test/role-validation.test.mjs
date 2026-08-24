import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  MemoryKernel,
  compileContext,
  evidenceRefFor,
  validateStateSchema,
} from '../dist/index.js';

function digest(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function toolEvidence(id) {
  return {
    id,
    scope: 'project/showstead',
    kind: 'test-result',
    sourceGroups: [`run:${id}`],
    authority: 'tool-verified',
    observedAt: 1,
    sensitivity: 'internal',
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
    labels: ['test'],
  };
}

test('an explicit support role cannot masquerade as test verification', () => {
  const kernel = new MemoryKernel();
  const source = toolEvidence('build-result');
  kernel.captureEvidence(
    { eventId: 'capture-build-result', recordedAt: 1, actor: 'test-runner' },
    source,
  );

  assert.throws(
    () =>
      kernel.recordOutcome(
        { eventId: 'record-build-outcome', recordedAt: 2, actor: 'verifier' },
        {
          scope: 'project/showstead',
          subjectId: 'build',
          taskId: 'task-build',
          contextFingerprint: 'linux-node22',
          sourceGroups: source.sourceGroups,
          outcome: 'success',
          verifier: 'test',
          evidence: [evidenceRefFor(source, ['supports'])],
        },
      ),
    /explicit verifying evidence/,
  );
});

test('evidenceRefFor rejects unknown runtime roles', () => {
  const source = toolEvidence('invalid-role-source');
  assert.throws(
    () => evidenceRefFor(source, ['not-a-real-role']),
    /unknown role/,
  );
});

test('the context compiler rejects unknown evidence-link roles', () => {
  assert.throws(
    () =>
      compileContext(
        [
          {
            id: 'state',
            kind: 'state',
            content: 'state',
            estimatedTokens: 5,
            activationScore: 1,
            topics: ['state'],
            authorization: 'authorized-current',
            evidenceLinks: [{ packetId: 'source', roles: ['not-a-real-role'] }],
          },
          {
            id: 'source',
            kind: 'source',
            content: 'source',
            estimatedTokens: 5,
            activationScore: 1,
            topics: ['source'],
            authorization: 'authorized-current',
          },
        ],
        { tokenBudget: 100, view: 'current' },
      ),
    /unknown role/,
  );
});

test('state schemas reject unknown runtime strategies and authorities', () => {
  const base = {
    id: 'invalid-policy',
    version: '1',
    slots: [
      {
        id: 'slot',
        domain: 'test',
        key: { scope: 'global', subject: 'x', predicate: 'y' },
        strategy: 'not-a-strategy',
        evidencePolicy: [
          {
            role: 'supports',
            authorityPrecedence: ['not-an-authority'],
          },
        ],
      },
    ],
  };
  assert.throws(() => validateStateSchema(base), /unknown resolution strategy/);

  assert.throws(
    () =>
      validateStateSchema({
        ...base,
        slots: [
          {
            ...base.slots[0],
            strategy: 'role-authority',
          },
        ],
      }),
    /unknown authority/,
  );
});
