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

function evidence(id, sourceGroup, recordedAt, overrides = {}) {
  return {
    id,
    scope: 'project/experience',
    kind: 'test-result',
    sourceGroups: [sourceGroup],
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
    preview: `verified result ${id}`,
    derivedFrom: [],
    labels: ['experience'],
    ...overrides,
  };
}

class Scenario {
  constructor() {
    this.kernel = new MemoryKernel();
    this.time = 1;
    this.memoryEvidence = evidence(
      'evidence/memory-source',
      'origin/memory-source',
      this.time,
      {
        kind: 'human-feedback',
        authority: 'human-explicit',
        preview: 'validated memory procedure source',
      },
    );
    this.kernel.captureEvidence(
      { eventId: 'event/memory-source', recordedAt: this.time, actor: 'human' },
      this.memoryEvidence,
    );
    this.time += 1;
    this.runs = new Map();
  }

  addRun(id, outcome, context, sourceGroup = `run/${id}`) {
    const recordedAt = this.time + 1;
    const result = evidence(`evidence/result/${id}`, sourceGroup, this.time);
    this.kernel.captureEvidence(
      { eventId: `event/result/${id}`, recordedAt: this.time, actor: 'test-runner' },
      result,
    );
    this.kernel.recordOutcome(
      { eventId: `event/outcome/${id}`, recordedAt, actor: 'verifier' },
      {
        scope: 'project/experience',
        subjectId: `run/${id}`,
        taskId: `task/${id}`,
        contextFingerprint: context,
        sourceGroups: [sourceGroup],
        outcome,
        verifier: 'test',
        evidence: [evidenceRefFor(result, ['verifies'])],
      },
    );
    const run = {
      id,
      taskId: `task/${id}`,
      context,
      outcomeEventId: `event/outcome/${id}`,
      startedAt: this.time - 1,
      completedAt: this.time,
      sourceGroup,
      resultEvidenceId: result.id,
    };
    this.runs.set(id, run);
    this.time += 2;
    return run;
  }

  events() {
    return this.kernel.events();
  }
}

function unit(id, context) {
  return {
    taskFamily: 'debug-authentication',
    instanceDigest: sha(`instance/${id}`),
    environmentDigest: sha(`environment/${context}`),
    seed: `seed/${id}`,
  };
}

function traceInput(scenario, run, options = {}) {
  const targetStage = options.targetStage ?? 'applied';
  const target = {
    memoryId: options.memoryId ?? 'memory/target',
    kind: 'procedure',
    stage: targetStage,
    evidenceSourceIds: [scenario.memoryEvidence.id],
    roles: ['supports'],
    ...(targetStage === 'applied' ? {} : { nonUseReason: 'withheld by intervention' }),
  };
  const baseline = {
    memoryId: 'memory/baseline',
    kind: 'constraint',
    stage: 'applied',
    evidenceSourceIds: [scenario.memoryEvidence.id],
    roles: ['constrains'],
  };
  return {
    id: `trace/${run.id}`,
    scope: 'project/experience',
    runId: `run/${run.id}`,
    taskId: run.taskId,
    contextFingerprint: run.context,
    goalSignature: 'repair authentication behavior',
    unit: options.unit ?? unit(options.unitId ?? run.id, run.context),
    startedAt: run.startedAt,
    completedAt: run.completedAt,
    captureMode: options.captureMode ?? 'runtime-instrumented',
    recorder: options.recorder ?? 'instrumented-runtime',
    canonicalFingerprint: fingerprintMemoryEvents(scenario.events()),
    outcomeEventId: run.outcomeEventId,
    exposures: options.exposures ?? [target, baseline],
  };
}

function recordPair(scenario, pairId, treatmentOutcome, controlOutcome, context, options = {}) {
  const treatmentRun = scenario.addRun(`${pairId}/treatment`, treatmentOutcome, context);
  const controlRun = scenario.addRun(`${pairId}/control`, controlOutcome, context);
  const events = scenario.events();
  const sharedUnit = unit(options.unitId ?? pairId, context);
  const treatment = recordExperienceTrace(
    events,
    traceInput(scenario, treatmentRun, {
      unit: sharedUnit,
      memoryId: options.memoryId,
    }),
  );
  const control = recordExperienceTrace(
    events,
    traceInput(scenario, controlRun, {
      unit: sharedUnit,
      memoryId: options.memoryId,
      targetStage: 'activated',
    }),
  );
  const comparison = verifyMemoryIntervention(
    [treatment, control],
    {
      id: `comparison/${pairId}`,
      memoryId: options.memoryId ?? 'memory/target',
      treatmentTraceId: treatment.id,
      controlTraceId: control.id,
      intervention: 'removed',
      actor: 'experiment-controller',
      recordedAt: Math.max(treatment.completedAt, control.completedAt) + 1,
    },
  );
  return { treatment, control, comparison };
}

test('trace admission distinguishes exposure from runtime-proven application', () => {
  const scenario = new Scenario();
  const run = scenario.addRun('trace-admission', 'success', 'context/a');
  const runtime = recordExperienceTrace(
    scenario.events(),
    traceInput(scenario, run, {
      exposures: [
        {
          memoryId: 'memory/not-selected',
          kind: 'episode',
          stage: 'activated',
          evidenceSourceIds: [scenario.memoryEvidence.id],
          nonUseReason: 'lost ranking competition',
        },
        {
          memoryId: 'memory/applied',
          kind: 'procedure',
          stage: 'applied',
          evidenceSourceIds: [scenario.memoryEvidence.id],
        },
      ],
    }),
  );
  assert.equal(runtime.exposures[0].creditEligible, false);
  assert.equal(runtime.exposures[1].creditEligible, true);

  const model = recordExperienceTrace(
    scenario.events(),
    {
      ...traceInput(scenario, run),
      id: 'trace/model-self-report',
      captureMode: 'model-self-report',
      recorder: 'model',
    },
  );
  assert.equal(model.exposures.find((item) => item.stage === 'applied').creditEligible, false);
});

test('stale canonical fingerprints and unavailable outcome evidence fail closed', () => {
  const scenario = new Scenario();
  const run = scenario.addRun('stale', 'success', 'context/a');
  const stale = traceInput(scenario, run);
  stale.canonicalFingerprint = sha('not-the-ledger');
  assert.throws(() => recordExperienceTrace(scenario.events(), stale), /stale or forged/);

  scenario.kernel.setEvidenceAvailability(
    { eventId: 'event/restrict-result', recordedAt: scenario.time, actor: 'privacy-controller' },
    run.resultEvidenceId,
    'restricted',
    'review required',
  );
  const unavailable = traceInput(scenario, run);
  assert.throws(
    () => recordExperienceTrace(scenario.events(), unavailable),
    /outcome evidence is unavailable/,
  );
});

test('paired attribution requires runtime instrumentation and exactly one applied-memory difference', () => {
  const scenario = new Scenario();
  const treatmentRun = scenario.addRun('strict/treatment', 'success', 'context/a');
  const controlRun = scenario.addRun('strict/control', 'failure', 'context/a');
  const events = scenario.events();
  const shared = unit('strict', 'context/a');
  const treatment = recordExperienceTrace(
    events,
    traceInput(scenario, treatmentRun, { unit: shared }),
  );
  const controlWithExtra = recordExperienceTrace(
    events,
    traceInput(scenario, controlRun, {
      unit: shared,
      targetStage: 'activated',
      exposures: [
        {
          memoryId: 'memory/target',
          kind: 'procedure',
          stage: 'activated',
          evidenceSourceIds: [scenario.memoryEvidence.id],
          nonUseReason: 'withheld',
        },
        {
          memoryId: 'memory/baseline',
          kind: 'constraint',
          stage: 'applied',
          evidenceSourceIds: [scenario.memoryEvidence.id],
        },
        {
          memoryId: 'memory/control-only',
          kind: 'procedure',
          stage: 'applied',
          evidenceSourceIds: [scenario.memoryEvidence.id],
        },
      ],
    }),
  );
  assert.throws(
    () =>
      verifyMemoryIntervention([treatment, controlWithExtra], {
        id: 'comparison/hidden-difference',
        memoryId: 'memory/target',
        treatmentTraceId: treatment.id,
        controlTraceId: controlWithExtra.id,
        intervention: 'removed',
        actor: 'experiment-controller',
        recordedAt: scenario.time,
      }),
    /differ only/,
  );

  const modelTreatment = recordExperienceTrace(
    events,
    {
      ...traceInput(scenario, treatmentRun, { unit: shared }),
      id: 'trace/model-treatment',
      captureMode: 'model-self-report',
      recorder: 'model',
    },
  );
  assert.throws(
    () =>
      verifyMemoryIntervention([modelTreatment, controlWithExtra], {
        id: 'comparison/model',
        memoryId: 'memory/target',
        treatmentTraceId: modelTreatment.id,
        controlTraceId: controlWithExtra.id,
        intervention: 'removed',
        actor: 'experiment-controller',
        recordedAt: scenario.time,
      }),
    /runtime-instrumented/,
  );
});

test('plain cloned traces cannot masquerade as verifier-issued experience records', () => {
  const scenario = new Scenario();
  const pair = recordPair(scenario, 'capability', 'success', 'failure', 'context/a');
  assert.throws(
    () =>
      verifyMemoryIntervention([structuredClone(pair.treatment), pair.control], {
        id: 'comparison/forged-trace',
        memoryId: 'memory/target',
        treatmentTraceId: pair.treatment.id,
        controlTraceId: pair.control.id,
        intervention: 'removed',
        actor: 'experiment-controller',
        recordedAt: scenario.time,
      }),
    /issued experience trace/,
  );
});

test('five independent positive pairs across contexts support positive utility', () => {
  const scenario = new Scenario();
  const traces = [];
  const comparisons = [];
  for (let index = 0; index < 5; index += 1) {
    const pair = recordPair(
      scenario,
      `positive/${index}`,
      'success',
      'failure',
      index % 2 === 0 ? 'context/a' : 'context/b',
    );
    traces.push(pair.treatment, pair.control);
    comparisons.push(pair.comparison);
  }
  const assessment = assessMemoryUtility('memory/target', traces, comparisons);
  assert.equal(assessment.status, 'supported-positive');
  assert.equal(assessment.independentPairs, 5);
  assert.equal(assessment.distinctContexts, 2);
  assert.equal(assessment.positivePairs, 5);
  assert.equal(assessment.negativePairs, 0);
});

test('unpaired correlated successes are diagnostic but never sufficient for promotion', () => {
  const scenario = new Scenario();
  const traces = [];
  for (let index = 0; index < 10; index += 1) {
    const run = scenario.addRun(`correlated/${index}`, 'success', 'context/a');
    traces.push(recordExperienceTrace(scenario.events(), traceInput(scenario, run)));
  }
  const assessment = assessMemoryUtility('memory/target', traces, []);
  assert.equal(assessment.status, 'insufficient');
  assert.equal(assessment.independentPairs, 0);
  assert.equal(assessment.correlatedVerifiedSuccesses, 10);
});

test('duplicate experimental units and overlapping verifier origins are not counted twice', () => {
  const scenario = new Scenario();
  const traces = [];
  const comparisons = [];
  const first = recordPair(scenario, 'duplicate/one', 'success', 'failure', 'context/a', {
    unitId: 'same-unit',
  });
  const second = recordPair(scenario, 'duplicate/two', 'success', 'failure', 'context/a', {
    unitId: 'same-unit',
  });
  traces.push(first.treatment, first.control, second.treatment, second.control);
  comparisons.push(first.comparison, second.comparison);
  const assessment = assessMemoryUtility('memory/target', traces, comparisons, {
    minIndependentPairs: 1,
    minDistinctContexts: 1,
    minMeanAbsoluteEffect: 0.2,
    minDirectionalRate: 0.5,
    minDirectionalWilsonLowerBound: 0,
    maxOppositeRate: 0.5,
    neutralThreshold: 0.1,
  });
  assert.equal(assessment.independentPairs, 1);
  assert.equal(assessment.excludedCorrelatedPairs, 1);
});

test('independent negative pairs support a harmful-memory conclusion', () => {
  const scenario = new Scenario();
  const traces = [];
  const comparisons = [];
  for (let index = 0; index < 5; index += 1) {
    const pair = recordPair(
      scenario,
      `negative/${index}`,
      'failure',
      'success',
      index % 2 === 0 ? 'context/a' : 'context/b',
      { memoryId: 'memory/harmful' },
    );
    traces.push(pair.treatment, pair.control);
    comparisons.push(pair.comparison);
  }
  const assessment = assessMemoryUtility('memory/harmful', traces, comparisons);
  assert.equal(assessment.status, 'supported-negative');
  assert.equal(assessment.negativePairs, 5);
});

test('cloned comparisons cannot be injected into a utility assessment', () => {
  const scenario = new Scenario();
  const pair = recordPair(scenario, 'forged-comparison', 'success', 'failure', 'context/a');
  assert.throws(
    () =>
      assessMemoryUtility(
        'memory/target',
        [pair.treatment, pair.control],
        [structuredClone(pair.comparison)],
      ),
    /issued memory intervention/,
  );
});
