import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  MemoryKernel,
  assessMemoryUtility,
  evidenceRefFor,
  fingerprintMemoryEvents,
  recordExperienceTrace,
  verifyMemoryIntervention,
} from '../dist/index.js';

function sha(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

const runtime = Object.freeze({
  modelDigest: sha('model/v1'),
  toolDigest: sha('tools/v1'),
  harnessDigest: sha('harness/v1'),
  verifierDigest: sha('verifier/v1'),
});

const permissivePolicy = Object.freeze({
  minIndependentPairs: 1,
  minDistinctContexts: 1,
  minMeanAbsoluteEffect: 0.2,
  minDirectionalRate: 0.5,
  minDirectionalWilsonLowerBound: 0,
  maxOppositeRate: 0.5,
  neutralThreshold: 0.1,
});

function evidence(id, sourceGroup, recordedAt, scope = 'project/attribution-order') {
  const preview = `evidence ${id}`;
  return {
    id,
    scope,
    kind: 'test-result',
    sourceGroups: [sourceGroup],
    authority: 'tool-verified',
    observedAt: recordedAt,
    sensitivity: 'internal',
    taints: [],
    artifact: {
      uri: `memory://artifact/${id}`,
      digest: sha(`artifact/${id}`),
      sizeBytes: preview.length,
      mediaType: 'application/json',
      encryption: 'none',
      retention: 'durable',
    },
    preview,
    derivedFrom: [],
    labels: ['attribution-order'],
  };
}

class Scenario {
  constructor() {
    this.scope = 'project/attribution-order';
    this.kernel = new MemoryKernel();
    this.time = 1;
    this.memoryEvidence = evidence('evidence/memory', 'origin/memory', this.time, this.scope);
    this.memoryEvidence = {
      ...this.memoryEvidence,
      kind: 'human-feedback',
      authority: 'human-explicit',
    };
    this.kernel.captureEvidence(
      { eventId: 'event/memory', recordedAt: this.time, actor: 'human' },
      this.memoryEvidence,
    );
    this.time += 1;
  }

  addRun(pairId, arm, outcome, context, sourceGroup) {
    const result = evidence(
      `evidence/${pairId}/${arm}/${this.time}`,
      sourceGroup,
      this.time,
      this.scope,
    );
    this.kernel.captureEvidence(
      { eventId: `event/result/${pairId}/${arm}/${this.time}`, recordedAt: this.time, actor: 'test-runner' },
      result,
    );
    const outcomeEventId = `event/outcome/${pairId}/${arm}/${this.time + 1}`;
    this.kernel.recordOutcome(
      { eventId: outcomeEventId, recordedAt: this.time + 1, actor: 'test-runner' },
      {
        scope: this.scope,
        subjectId: `run/${pairId}/${arm}`,
        taskId: `task/${pairId}`,
        contextFingerprint: context,
        sourceGroups: [sourceGroup],
        outcome,
        verifier: 'test',
        evidence: [evidenceRefFor(result, ['verifies'])],
      },
    );
    const run = {
      pairId,
      arm,
      runId: `run/${pairId}/${arm}`,
      taskId: `task/${pairId}`,
      context,
      outcomeEventId,
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

function defaultUnit(id) {
  return {
    taskFamily: 'maintenance',
    instanceDigest: sha(`instance/${id}`),
    environmentDigest: sha(`environment/${id}`),
    seed: `seed/${id}`,
  };
}

function memoryUses(scenario, includeTarget) {
  const uses = [];
  if (includeTarget) {
    uses.push({
      memoryId: 'memory/target',
      kind: 'procedure',
      stages: ['activated', 'materialized', 'consulted', 'applied'],
      evidence: [evidenceRefFor(scenario.memoryEvidence, ['supports'])],
    });
  }
  uses.push({
    memoryId: 'memory/baseline',
    kind: 'constraint',
    stages: ['activated', 'materialized', 'consulted', 'applied'],
    evidence: [evidenceRefFor(scenario.memoryEvidence, ['constrains'])],
  });
  return uses;
}

function makeTrace(scenario, run, unit, includeTarget) {
  return recordExperienceTrace(scenario.events(), {
    id: `trace/${run.pairId}/${run.arm}`,
    scope: scenario.scope,
    runId: run.runId,
    taskId: run.taskId,
    contextFingerprint: run.context,
    goalSignature: 'repair the same maintenance behavior',
    unit,
    runtime,
    startedAt: run.startedAt,
    completedAt: run.completedAt,
    captureMode: 'runtime-instrumented',
    recorder: 'instrumented-runtime',
    canonicalFingerprint: fingerprintMemoryEvents(scenario.events()),
    outcomeEventId: run.outcomeEventId,
    memoryUses: memoryUses(scenario, includeTarget),
  });
}

function makePair(
  scenario,
  pairId,
  treatmentOutcome,
  controlOutcome,
  context,
  options = {},
) {
  const treatmentRun = scenario.addRun(
    pairId,
    'treatment',
    treatmentOutcome,
    context,
    options.treatmentSourceGroup ?? options.sourceGroup ?? `source/${pairId}`,
  );
  const controlRun = scenario.addRun(
    pairId,
    'control',
    controlOutcome,
    context,
    options.controlSourceGroup ?? options.sourceGroup ?? `source/${pairId}`,
  );
  const unit = options.unit ?? defaultUnit(pairId);
  const treatment = makeTrace(scenario, treatmentRun, unit, true);
  const control = makeTrace(scenario, controlRun, unit, false);
  const comparison = verifyMemoryIntervention([treatment, control], {
    id: `comparison/${pairId}`,
    memoryId: 'memory/target',
    treatmentTraceId: treatment.id,
    controlTraceId: control.id,
    intervention: 'withheld',
    actor: 'experiment-controller',
    recordedAt: Math.max(treatment.completedAt, control.completedAt) + 1,
  });
  return { treatment, control, comparison };
}

test('assessment is invariant to caller order for overlapping source families', () => {
  const scenario = new Scenario();
  const first = makePair(scenario, 'order/a', 'success', 'failure', 'context/a', {
    sourceGroup: 'source/shared',
  });
  const second = makePair(scenario, 'order/b', 'success', 'failure', 'context/b', {
    sourceGroup: 'source/shared',
  });
  const third = makePair(scenario, 'order/c', 'success', 'failure', 'context/c');
  const traces = [
    first.treatment,
    first.control,
    second.treatment,
    second.control,
    third.treatment,
    third.control,
  ];
  const comparisons = [first.comparison, second.comparison, third.comparison];

  const forward = assessMemoryUtility(
    { scope: scenario.scope, memoryId: 'memory/target' },
    traces,
    comparisons,
    permissivePolicy,
  );
  const reversed = assessMemoryUtility(
    { scope: scenario.scope, memoryId: 'memory/target' },
    [...traces].reverse(),
    [...comparisons].reverse(),
    permissivePolicy,
  );

  assert.deepEqual(reversed, forward);
  assert.equal(forward.independentPairs, 2);
  assert.equal(forward.excludedCorrelatedPairs, 1);
  assert.equal(forward.classification, 'supported-positive');
});

test('opposite effects inside one transitive source family remain mixed', () => {
  const scenario = new Scenario();
  const positive = makePair(scenario, 'family/positive', 'success', 'failure', 'context/a', {
    treatmentSourceGroup: 'source/family/a',
    controlSourceGroup: 'source/family/shared',
  });
  const negative = makePair(scenario, 'family/negative', 'failure', 'success', 'context/b', {
    treatmentSourceGroup: 'source/family/shared',
    controlSourceGroup: 'source/family/b',
  });

  const assessment = assessMemoryUtility(
    { scope: scenario.scope, memoryId: 'memory/target' },
    [positive.treatment, positive.control, negative.treatment, negative.control],
    [positive.comparison, negative.comparison],
    permissivePolicy,
  );

  assert.equal(assessment.classification, 'mixed');
  assert.equal(assessment.independentPairs, 0);
  assert.equal(assessment.conflictingExperimentalUnits, 0);
  assert.equal(assessment.conflictingSourceFamilies, 1);
  assert.equal(assessment.excludedCorrelatedPairs, 2);
});

test('experimental identity includes context even when the raw unit object is reused', () => {
  const scenario = new Scenario();
  const sharedUnit = defaultUnit('shared-raw-unit');
  const first = makePair(scenario, 'identity/a', 'success', 'failure', 'context/a', {
    unit: sharedUnit,
  });
  const second = makePair(scenario, 'identity/b', 'success', 'failure', 'context/b', {
    unit: sharedUnit,
  });

  assert.notEqual(
    first.comparison.experimentalUnitDigest,
    second.comparison.experimentalUnitDigest,
  );
  const assessment = assessMemoryUtility(
    { scope: scenario.scope, memoryId: 'memory/target' },
    [first.treatment, first.control, second.treatment, second.control],
    [first.comparison, second.comparison],
    permissivePolicy,
  );
  assert.equal(assessment.independentPairs, 2);
  assert.equal(assessment.conflictingExperimentalUnits, 0);
});
