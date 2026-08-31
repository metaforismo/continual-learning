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

const scope = 'project/attribution-lineage';
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

function evidence(id, sourceGroup, recordedAt, overrides = {}) {
  const preview = overrides.preview ?? `evidence ${id}`;
  return {
    id,
    scope,
    kind: overrides.kind ?? 'test-result',
    sourceGroups: [sourceGroup],
    authority: overrides.authority ?? 'tool-verified',
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
    labels: ['attribution-lineage'],
  };
}

class Scenario {
  constructor() {
    this.kernel = new MemoryKernel();
    this.time = 1;
    this.memoryEvidence = evidence('evidence/memory', 'origin/memory', this.time, {
      kind: 'human-feedback',
      authority: 'human-explicit',
      preview: 'verified target-memory source',
    });
    this.kernel.captureEvidence(
      { eventId: 'event/memory', recordedAt: this.time, actor: 'human' },
      this.memoryEvidence,
    );
    this.time += 1;
  }

  addRun(pairId, arm, outcome, context, sourceGroup) {
    const resultTime = this.time;
    const result = evidence(
      `evidence/${pairId}/${arm}/${resultTime}`,
      sourceGroup,
      resultTime,
    );
    this.kernel.captureEvidence(
      { eventId: `event/result/${pairId}/${arm}/${resultTime}`, recordedAt: resultTime, actor: 'test-runner' },
      result,
    );
    const outcomeEventId = `event/outcome/${pairId}/${arm}/${resultTime + 1}`;
    this.kernel.recordOutcome(
      { eventId: outcomeEventId, recordedAt: resultTime + 1, actor: 'test-runner' },
      {
        scope,
        subjectId: `run/${pairId}/${arm}`,
        taskId: `task/${pairId}`,
        contextFingerprint: context,
        sourceGroups: [sourceGroup],
        outcome,
        verifier: 'test',
        evidence: [evidenceRefFor(result, ['verifies'])],
      },
    );
    this.time += 2;
    return {
      pairId,
      arm,
      runId: `run/${pairId}/${arm}`,
      taskId: `task/${pairId}`,
      context,
      outcomeEventId,
      startedAt: Math.max(0, resultTime - 1),
      completedAt: resultTime,
    };
  }

  events() {
    return this.kernel.events();
  }
}

function unit(id) {
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

function makeTrace(scenario, run, experimentalUnit, includeTarget) {
  return recordExperienceTrace(scenario.events(), {
    id: `trace/${run.pairId}/${run.arm}`,
    scope,
    runId: run.runId,
    taskId: run.taskId,
    contextFingerprint: run.context,
    goalSignature: 'repair the maintenance behavior',
    unit: experimentalUnit,
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
  sourceGroup,
  experimentalUnit,
) {
  const treatmentRun = scenario.addRun(
    pairId,
    'treatment',
    treatmentOutcome,
    context,
    sourceGroup,
  );
  const controlRun = scenario.addRun(
    pairId,
    'control',
    controlOutcome,
    context,
    sourceGroup,
  );
  const treatment = makeTrace(scenario, treatmentRun, experimentalUnit, true);
  const control = makeTrace(scenario, controlRun, experimentalUnit, false);
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

test('same-unit duplicates retain every source-family edge before independence collapse', () => {
  const scenario = new Scenario();
  const sharedUnit = unit('shared');
  const bridgeDuplicate = makePair(
    scenario,
    'shared/bridge',
    'success',
    'failure',
    'context/shared',
    'source/bridge',
    sharedUnit,
  );
  const conservativeDuplicate = makePair(
    scenario,
    'shared/private',
    'success',
    'partial',
    'context/shared',
    'source/private',
    sharedUnit,
  );
  const otherUnit = makePair(
    scenario,
    'other',
    'success',
    'failure',
    'context/other',
    'source/bridge',
    unit('other'),
  );
  const traces = [
    bridgeDuplicate.treatment,
    bridgeDuplicate.control,
    conservativeDuplicate.treatment,
    conservativeDuplicate.control,
    otherUnit.treatment,
    otherUnit.control,
  ];
  const comparisons = [
    bridgeDuplicate.comparison,
    conservativeDuplicate.comparison,
    otherUnit.comparison,
  ];

  const forward = assessMemoryUtility(
    { scope, memoryId: 'memory/target' },
    traces,
    comparisons,
    permissivePolicy,
  );
  const reversed = assessMemoryUtility(
    { scope, memoryId: 'memory/target' },
    [...traces].reverse(),
    [...comparisons].reverse(),
    permissivePolicy,
  );

  assert.deepEqual(reversed, forward);
  assert.equal(forward.classification, 'supported-positive');
  assert.equal(forward.independentPairs, 1);
  assert.equal(forward.excludedCorrelatedPairs, 2);
  assert.deepEqual(forward.comparisonIds, [conservativeDuplicate.comparison.id]);
  assert.deepEqual(
    [...forward.excludedComparisonIds].sort(),
    [bridgeDuplicate.comparison.id, otherUnit.comparison.id].sort(),
  );
});
