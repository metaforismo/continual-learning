import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  MemoryKernel,
  evidenceRefFor,
  fingerprintMemoryEvents,
  induceApplicabilityHypothesis,
  recordExperienceTrace,
  validateApplicabilityHypothesis,
  verifyMemoryIntervention,
} from '../dist/index.js';

function sha(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function evidence(id, group, recordedAt, overrides = {}) {
  return {
    id,
    scope: 'project/applicability',
    kind: 'test-result',
    sourceGroups: [group],
    authority: 'tool-verified',
    observedAt: recordedAt,
    sensitivity: 'internal',
    taints: [],
    artifact: {
      uri: `memory://artifact/${id}`,
      digest: sha(`artifact/${id}`),
      sizeBytes: id.length,
      mediaType: 'application/json',
      encryption: 'none',
      retention: 'durable',
    },
    preview: `applicability evidence ${id}`,
    derivedFrom: [],
    labels: ['applicability'],
    ...overrides,
  };
}

class Scenario {
  constructor() {
    this.kernel = new MemoryKernel();
    this.time = 1;
    this.memoryEvidence = evidence('evidence/memory', 'origin/memory', this.time, {
      kind: 'human-feedback',
      authority: 'human-explicit',
      preview: 'memory procedure source',
    });
    this.kernel.captureEvidence(
      { eventId: 'event/memory', recordedAt: this.time, actor: 'human' },
      this.memoryEvidence,
    );
    this.time += 1;
  }

  addRun(id, outcome, contextFingerprint, sourceGroup) {
    const result = evidence(`evidence/result/${id}`, sourceGroup, this.time);
    this.kernel.captureEvidence(
      { eventId: `event/result/${id}`, recordedAt: this.time, actor: 'test-runner' },
      result,
    );
    this.kernel.recordOutcome(
      { eventId: `event/outcome/${id}`, recordedAt: this.time + 1, actor: 'verifier' },
      {
        scope: 'project/applicability',
        subjectId: `run/${id}`,
        taskId: `task/${id}`,
        contextFingerprint,
        sourceGroups: [sourceGroup],
        outcome,
        verifier: 'test',
        evidence: [evidenceRefFor(result, ['verifies'])],
      },
    );
    const run = {
      id,
      taskId: `task/${id}`,
      contextFingerprint,
      outcomeEventId: `event/outcome/${id}`,
      startedAt: this.time - 1,
      completedAt: this.time,
    };
    this.time += 2;
    return run;
  }

  events() {
    return this.kernel.events();
  }
}

function unit(id, environment) {
  return {
    taskFamily: 'debug-authentication',
    instanceDigest: sha(`instance/${id}`),
    environmentDigest: sha(`environment/${environment}`),
    seed: `seed/${id}`,
  };
}

function traceInput(scenario, run, sharedUnit, contextFeatures, applied) {
  return {
    id: `trace/${run.id}`,
    scope: 'project/applicability',
    runId: `run/${run.id}`,
    taskId: run.taskId,
    contextFingerprint: run.contextFingerprint,
    contextFeatures,
    goalSignature: 'repair authentication behavior',
    unit: sharedUnit,
    startedAt: run.startedAt,
    completedAt: run.completedAt,
    captureMode: 'runtime-instrumented',
    recorder: 'instrumented-runtime',
    canonicalFingerprint: fingerprintMemoryEvents(scenario.events()),
    outcomeEventId: run.outcomeEventId,
    exposures: [
      {
        memoryId: 'memory/target',
        kind: 'procedure',
        stage: applied ? 'applied' : 'activated',
        evidenceSourceIds: [scenario.memoryEvidence.id],
        roles: ['supports'],
        ...(applied ? {} : { nonUseReason: 'withheld by paired intervention' }),
      },
      {
        memoryId: 'memory/baseline',
        kind: 'constraint',
        stage: 'applied',
        evidenceSourceIds: [scenario.memoryEvidence.id],
        roles: ['constrains'],
      },
    ],
  };
}

function pair(scenario, id, treatmentOutcome, controlOutcome, context, features, options = {}) {
  const treatment = scenario.addRun(
    `${id}/treatment`,
    treatmentOutcome,
    context,
    options.treatmentGroup ?? `origin/${id}/treatment`,
  );
  const control = scenario.addRun(
    `${id}/control`,
    controlOutcome,
    context,
    options.controlGroup ?? `origin/${id}/control`,
  );
  const events = scenario.events();
  const sharedUnit = unit(options.unitId ?? id, options.environment ?? context);
  const treatmentTrace = recordExperienceTrace(
    events,
    traceInput(scenario, treatment, sharedUnit, features, true),
  );
  const controlTrace = recordExperienceTrace(
    events,
    traceInput(scenario, control, sharedUnit, options.controlFeatures ?? features, false),
  );
  const comparison = verifyMemoryIntervention(
    [treatmentTrace, controlTrace],
    {
      id: `comparison/${id}`,
      memoryId: 'memory/target',
      treatmentTraceId: treatmentTrace.id,
      controlTraceId: controlTrace.id,
      intervention: 'removed',
      actor: 'experiment-controller',
      recordedAt: Math.max(treatmentTrace.completedAt, controlTrace.completedAt) + 1,
    },
  );
  return { treatmentTrace, controlTrace, comparison };
}

function positiveFeatures(repo) {
  return ['framework:nextjs', 'runtime:node', 'symptom:race', `repo:${repo}`];
}

function negativeFeatures(framework, repo) {
  return [`framework:${framework}`, 'runtime:python', 'symptom:race', `repo:${repo}`];
}

test('discovery and held-out validation produce a validated applicability rule', () => {
  const scenario = new Scenario();
  const discovery = [
    pair(scenario, 'd-pos-1', 'success', 'failure', 'context/next/a', positiveFeatures('a')),
    pair(scenario, 'd-pos-2', 'success', 'failure', 'context/next/b', positiveFeatures('b')),
    pair(scenario, 'd-pos-3', 'success', 'failure', 'context/next/c', positiveFeatures('c')),
    pair(scenario, 'd-pos-4', 'success', 'failure', 'context/next/d', positiveFeatures('d')),
    pair(scenario, 'd-neg-1', 'failure', 'success', 'context/python/a', negativeFeatures('fastapi', 'e')),
    pair(scenario, 'd-neg-2', 'failure', 'success', 'context/python/b', negativeFeatures('fastapi', 'f')),
  ];
  const candidate = induceApplicabilityHypothesis(
    discovery.map((item) => item.comparison),
    {
      id: 'hypothesis/nextjs-race',
      memoryId: 'memory/target',
      discoveryComparisonIds: discovery.map((item) => item.comparison.id),
      actor: 'hypothesis-controller',
      recordedAt: scenario.time,
    },
  );
  assert.equal(candidate.blockers.length, 0);
  assert.ok(
    candidate.rule.requiredFeatures.includes('framework:nextjs') ||
      candidate.rule.forbiddenFeatures.includes('framework:fastapi') ||
      candidate.rule.requiredFeatures.includes('runtime:node') ||
      candidate.rule.forbiddenFeatures.includes('runtime:python'),
  );

  const validation = [
    pair(scenario, 'v-pos-1', 'success', 'failure', 'context/next/e', positiveFeatures('g')),
    pair(scenario, 'v-pos-2', 'success', 'failure', 'context/next/f', positiveFeatures('h')),
    pair(scenario, 'v-pos-3', 'success', 'failure', 'context/next/g', positiveFeatures('i')),
    pair(scenario, 'v-neg-1', 'failure', 'success', 'context/python/c', negativeFeatures('fastapi', 'j')),
    pair(scenario, 'v-neg-2', 'failure', 'success', 'context/python/d', negativeFeatures('fastapi', 'k')),
  ];
  const result = validateApplicabilityHypothesis(
    candidate,
    validation.map((item) => item.comparison),
    {
      id: 'validation/nextjs-race',
      candidateId: candidate.id,
      validationComparisonIds: validation.map((item) => item.comparison.id),
      actor: 'validation-controller',
      recordedAt: scenario.time,
    },
  );
  assert.equal(result.status, 'validated');
  assert.equal(result.validationMetrics.precision, 1);
  assert.equal(result.validationMetrics.recall, 1);
});

test('validation cannot reuse a discovery unit or verifier source group', () => {
  const scenario = new Scenario();
  const discovery = [
    pair(scenario, 'overlap-pos-1', 'success', 'failure', 'context/a', positiveFeatures('a')),
    pair(scenario, 'overlap-pos-2', 'success', 'failure', 'context/b', positiveFeatures('b')),
    pair(scenario, 'overlap-pos-3', 'success', 'failure', 'context/c', positiveFeatures('c')),
    pair(scenario, 'overlap-neg', 'failure', 'success', 'context/d', negativeFeatures('fastapi', 'd')),
  ];
  const candidate = induceApplicabilityHypothesis(
    discovery.map((item) => item.comparison),
    {
      id: 'hypothesis/overlap',
      memoryId: 'memory/target',
      discoveryComparisonIds: discovery.map((item) => item.comparison.id),
      actor: 'hypothesis-controller',
      recordedAt: scenario.time,
      policy: { minDistinctContexts: 1 },
    },
  );
  const validation = pair(
    scenario,
    'overlap-validation',
    'success',
    'failure',
    'context/e',
    positiveFeatures('e'),
    { unitId: 'overlap-pos-1' },
  );
  assert.throws(
    () =>
      validateApplicabilityHypothesis(candidate, [validation.comparison], {
        id: 'validation/overlap',
        candidateId: candidate.id,
        validationComparisonIds: [validation.comparison.id],
        actor: 'validation-controller',
        recordedAt: scenario.time,
        policy: {
          minValidationExamples: 1,
          minPositiveExamples: 1,
          minCounterexamples: 1,
          minDistinctContexts: 1,
        },
      }),
    /overlaps a discovery experimental unit/,
  );
});

test('identical feature signatures with opposite held-out effects remain ambiguous', () => {
  const scenario = new Scenario();
  const discovery = [
    pair(scenario, 'amb-pos-1', 'success', 'failure', 'context/a', positiveFeatures('a')),
    pair(scenario, 'amb-pos-2', 'success', 'failure', 'context/b', positiveFeatures('b')),
    pair(scenario, 'amb-pos-3', 'success', 'failure', 'context/c', positiveFeatures('c')),
    pair(scenario, 'amb-neg', 'failure', 'success', 'context/d', negativeFeatures('fastapi', 'd')),
  ];
  const candidate = induceApplicabilityHypothesis(
    discovery.map((item) => item.comparison),
    {
      id: 'hypothesis/ambiguous',
      memoryId: 'memory/target',
      discoveryComparisonIds: discovery.map((item) => item.comparison.id),
      actor: 'hypothesis-controller',
      recordedAt: scenario.time,
      policy: { minDistinctContexts: 1 },
    },
  );
  const signature = ['framework:nextjs', 'runtime:node', 'symptom:race', 'repo:same'];
  const validation = [
    pair(scenario, 'amb-v-positive', 'success', 'failure', 'context/e', signature),
    pair(scenario, 'amb-v-negative', 'failure', 'success', 'context/f', signature),
    pair(scenario, 'amb-v-positive-2', 'success', 'failure', 'context/g', positiveFeatures('g')),
    pair(scenario, 'amb-v-negative-2', 'failure', 'success', 'context/h', negativeFeatures('fastapi', 'h')),
    pair(scenario, 'amb-v-positive-3', 'success', 'failure', 'context/i', positiveFeatures('i')),
  ];
  const result = validateApplicabilityHypothesis(
    candidate,
    validation.map((item) => item.comparison),
    {
      id: 'validation/ambiguous',
      candidateId: candidate.id,
      validationComparisonIds: validation.map((item) => item.comparison.id),
      actor: 'validation-controller',
      recordedAt: scenario.time,
      policy: { minDistinctContexts: 1 },
    },
  );
  assert.equal(result.status, 'ambiguous');
  assert.ok(result.validationMetrics.contradictoryFeatureSignatures.length > 0);
});

test('a discovery-specific forbidden feature can fail held-out generalization', () => {
  const scenario = new Scenario();
  const discovery = [
    pair(scenario, 'overfit-pos-1', 'success', 'failure', 'context/a', positiveFeatures('a')),
    pair(scenario, 'overfit-pos-2', 'success', 'failure', 'context/b', positiveFeatures('b')),
    pair(scenario, 'overfit-pos-3', 'success', 'failure', 'context/c', positiveFeatures('c')),
    pair(scenario, 'overfit-neg-1', 'failure', 'success', 'context/d', negativeFeatures('fastapi', 'd')),
    pair(scenario, 'overfit-neg-2', 'failure', 'success', 'context/e', negativeFeatures('fastapi', 'e')),
  ];
  const candidate = induceApplicabilityHypothesis(
    discovery.map((item) => item.comparison),
    {
      id: 'hypothesis/overfit',
      memoryId: 'memory/target',
      discoveryComparisonIds: discovery.map((item) => item.comparison.id),
      actor: 'hypothesis-controller',
      recordedAt: scenario.time,
      policy: { minDistinctContexts: 1 },
    },
  );
  const validation = [
    pair(scenario, 'overfit-v-pos-1', 'success', 'failure', 'context/f', positiveFeatures('f')),
    pair(scenario, 'overfit-v-pos-2', 'success', 'failure', 'context/g', positiveFeatures('g')),
    pair(scenario, 'overfit-v-pos-3', 'success', 'failure', 'context/h', positiveFeatures('h')),
    pair(scenario, 'overfit-v-neg-1', 'failure', 'success', 'context/i', negativeFeatures('django', 'i')),
    pair(scenario, 'overfit-v-neg-2', 'failure', 'success', 'context/j', negativeFeatures('flask', 'j')),
  ];
  const result = validateApplicabilityHypothesis(
    candidate,
    validation.map((item) => item.comparison),
    {
      id: 'validation/overfit',
      candidateId: candidate.id,
      validationComparisonIds: validation.map((item) => item.comparison.id),
      actor: 'validation-controller',
      recordedAt: scenario.time,
      policy: { minDistinctContexts: 1 },
    },
  );
  assert.notEqual(result.status, 'validated');
  assert.ok(result.blockers.length > 0);
});

test('a structural clone cannot masquerade as an issued hypothesis candidate', () => {
  const scenario = new Scenario();
  const discovery = [
    pair(scenario, 'clone-pos-1', 'success', 'failure', 'context/a', positiveFeatures('a')),
    pair(scenario, 'clone-pos-2', 'success', 'failure', 'context/b', positiveFeatures('b')),
    pair(scenario, 'clone-pos-3', 'success', 'failure', 'context/c', positiveFeatures('c')),
    pair(scenario, 'clone-neg', 'failure', 'success', 'context/d', negativeFeatures('fastapi', 'd')),
  ];
  const candidate = induceApplicabilityHypothesis(
    discovery.map((item) => item.comparison),
    {
      id: 'hypothesis/clone',
      memoryId: 'memory/target',
      discoveryComparisonIds: discovery.map((item) => item.comparison.id),
      actor: 'hypothesis-controller',
      recordedAt: scenario.time,
      policy: { minDistinctContexts: 1 },
    },
  );
  const validation = pair(
    scenario,
    'clone-validation',
    'success',
    'failure',
    'context/e',
    positiveFeatures('e'),
  );
  assert.throws(
    () =>
      validateApplicabilityHypothesis(structuredClone(candidate), [validation.comparison], {
        id: 'validation/clone',
        candidateId: candidate.id,
        validationComparisonIds: [validation.comparison.id],
        actor: 'validation-controller',
        recordedAt: scenario.time,
      }),
    /issued hypothesis candidate/,
  );
});

test('treatment and control must use the same instrumented context features', () => {
  const scenario = new Scenario();
  assert.throws(
    () =>
      pair(
        scenario,
        'feature-mismatch',
        'success',
        'failure',
        'context/a',
        positiveFeatures('a'),
        { controlFeatures: negativeFeatures('fastapi', 'a') },
      ),
    /context features/,
  );
});
