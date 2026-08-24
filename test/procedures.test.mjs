import assert from 'node:assert/strict';
import test from 'node:test';

import { assessProcedure, procedureApplies } from '../dist/index.js';

const definition = {
  id: 'procedure-auth-race',
  name: 'Stabilize auth setup before assertions',
  goalSignature: 'debug flaky authentication tests',
  requiredFeatures: ['authentication', 'asynchronous-session'],
  forbiddenFeatures: ['stateless-test'],
  steps: ['create the session', 'await durable readiness', 'run assertions'],
  derivedFromEpisodes: ['episode-1', 'episode-2'],
};

function evidence(index, overrides = {}) {
  return {
    id: `evidence-${index}`,
    sourceGroup: `run-${index}`,
    contextFingerprint: index % 2 === 0 ? 'nextjs-auth' : 'react-auth',
    kind: 'application',
    outcome: 'success',
    verifier: index % 2 === 0 ? 'test' : 'tool',
    recordedAt: index,
    ...overrides,
  };
}

test('a lesson is not promoted merely because one trajectory is repeated', () => {
  const repeated = Array.from({ length: 20 }, (_, index) =>
    evidence(index, { id: `repeat-${index}`, sourceGroup: 'same-run' }),
  );
  const assessment = assessProcedure(definition, repeated);
  assert.equal(assessment.stage, 'candidate');
  assert.equal(assessment.statistics.independentApplications, 1);
});

test('promotion requires independent verified outcomes and counterexample search', () => {
  const applications = Array.from({ length: 8 }, (_, index) => evidence(index));
  const withoutCounterexamples = assessProcedure(definition, applications);
  assert.equal(withoutCounterexamples.stage, 'candidate');
  assert.ok(withoutCounterexamples.blockers.some((blocker) => blocker.includes('counterexample')));

  const withCounterexamples = assessProcedure(definition, [
    ...applications,
    evidence(99, {
      id: 'counterexample-search',
      sourceGroup: 'counterexample-search',
      contextFingerprint: 'broader-auth-space',
      kind: 'counterexample-search',
      outcome: 'unknown',
      verifier: 'human',
    }),
  ]);
  assert.equal(withCounterexamples.stage, 'validated');
});

test('procedure applicability preserves positive and negative boundary conditions', () => {
  assert.equal(
    procedureApplies(definition, ['authentication', 'asynchronous-session', 'nextjs']),
    true,
  );
  assert.equal(
    procedureApplies(definition, ['authentication', 'asynchronous-session', 'stateless-test']),
    false,
  );
});

test('duplicate counterexample reports from one source group do not inflate trust', () => {
  const applications = Array.from({ length: 20 }, (_, index) =>
    evidence(index, {
      contextFingerprint: `context-${index % 4}`,
    }),
  );
  const duplicateCounterexamples = Array.from({ length: 3 }, (_, index) =>
    evidence(100 + index, {
      id: `counterexample-${index}`,
      sourceGroup: 'one-counterexample-run',
      contextFingerprint: 'counterexample-space',
      kind: 'counterexample-search',
      outcome: 'unknown',
      verifier: 'human',
    }),
  );

  const assessment = assessProcedure(definition, [...applications, ...duplicateCounterexamples]);
  assert.equal(assessment.statistics.counterexampleSearches, 1);
  assert.equal(assessment.stage, 'validated');
});

test('contradictory applicability boundaries are rejected', () => {
  assert.throws(
    () =>
      assessProcedure(
        {
          ...definition,
          requiredFeatures: ['authentication'],
          forbiddenFeatures: ['authentication'],
        },
        [],
      ),
    /both required and forbidden/,
  );
});
