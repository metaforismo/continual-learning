import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  MemoryKernel,
  assessMemoryUtility,
  evidenceRefFor,
  fingerprintMemoryEvents,
  isIssuedMemoryUtilityAssessment,
  recordExperienceTrace,
  verifyMemoryIntervention,
} from '../dist/index.js';

function sha(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function evidence(id, sourceGroup, recordedAt, overrides = {}) {
  const preview = overrides.preview ?? `verified evidence ${id}`;
  return {
    id,
    scope: overrides.scope ?? 'project/experience',
    kind: overrides.kind ?? 'test-result',
    sourceGroups: [sourceGroup],
    authority: overrides.authority ?? 'tool-verified',
    observedAt: recordedAt,
    sensitivity: overrides.sensitivity ?? 'internal',
    taints: overrides.taints ?? [],
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
    labels: ['experience-attribution'],
  };
}

const runtimeIdentity = Object.freeze({
  modelDigest: sha('model/version/1'),
  toolDigest: sha('tools/version/1'),
  harnessDigest: sha('harness/version/1'),
  verifierDigest: sha('verifier/version/1'),
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

class Scenario {
  constructor(scope = 'project/experience') {
    this.scope = scope;
    this.kernel = new MemoryKernel();
    this.time = 1;
    this.memoryEvidence = evidence('evidence/memory-source', 'origin/memory-source', this.time, {
      scope,
      kind: 'human-feedback',
      authority: 'human-explicit',
      preview: 'validated memory source',
    });
    this.kernel.captureEvidence(
      { eventId: 'event/memory-source', recordedAt: this.time, actor: 'human' },
      this.memoryEvidence,
    );
    this.time += 1;
  }

  addRun(pairId, arm, outcome, context, options = {}) {
    const resultTime = this.time;
    const sourceGroup = options.sourceGroup ?? `verifier/${pairId}`;
    const verifier = options.verifier ?? 'test';
    const authority =
      verifier === 'human'
        ? 'human-explicit'
        : verifier === 'model'
          ? 'model-inference'
          : 'tool-verified';
    const result = evidence(`evidence/result/${pairId}/${arm}/${resultTime}`, sourceGroup, resultTime, {
      scope: this.scope,
      authority,
      taints: verifier === 'model' ? ['model-generated'] : [],
      preview: `${verifier} outcome ${pairId}/${arm}`,
    });
    this.kernel.captureEvidence(
      { eventId: `event/result/${pairId}/${arm}/${resultTime}`, recordedAt: resultTime, actor: 'verifier' },
      result,
    );
    const outcomeTime = resultTime + 1;
    const outcomeEventId = `event/outcome/${pairId}/${arm}/${outcomeTime}`;
    this.kernel.recordOutcome(
      { eventId: outcomeEventId, recordedAt: outcomeTime, actor: 'verifier' },
      {
        scope: this.scope,
        subjectId: `run/${pairId}/${arm}`,
        taskId: `task/${pairId}`,
        contextFingerprint: context,
        sourceGroups: [sourceGroup],
        outcome,
        verifier,
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
      resultEvidenceId: result.id,
      startedAt: Math.max(0, resultTime - 1),
      completedAt: resultTime,
    };
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

function appliedUse(scenario, memoryId = 'memory/target', overrides = {}) {
  const { kind = 'procedure', roles = ['supports'] } = overrides;
  return {
    memoryId,
    kind,
    stages: ['activated', 'materialized', 'consulted', 'applied'],
    evidence: [evidenceRefFor(scenario.memoryEvidence, roles)],
  };
}

function nonAppliedUse(scenario, memoryId, stages = ['activated'], reason = 'not selected') {
  return {
    memoryId,
    kind: 'episode',
    stages,
    evidence: [evidenceRefFor(scenario.memoryEvidence, ['context'])],
    nonUseReason: reason,
  };
}

function traceInput(scenario, run, options = {}) {
  const memoryUses = options.memoryUses ?? [
    ...(options.includeTarget === false
      ? []
      : [appliedUse(scenario, options.memoryId ?? 'memory/target')]),
    appliedUse(scenario, 'memory/baseline', { kind: 'constraint', roles: ['constrains'] }),
  ];
  return {
    id: options.id ?? `trace/${run.pairId}/${run.arm}`,
    scope: scenario.scope,
    runId: run.runId,
    taskId: run.taskId,
    contextFingerprint: run.context,
    goalSignature: 'repair authentication behavior',
    unit: options.unit ?? unit(options.unitId ?? run.pairId, run.context),
    runtime: options.runtime ?? runtimeIdentity,
    startedAt: run.startedAt,
    completedAt: run.completedAt,
    captureMode: options.captureMode ?? 'runtime-instrumented',
    recorder: options.recorder ?? 'instrumented-runtime',
    canonicalFingerprint: fingerprintMemoryEvents(scenario.events()),
    outcomeEventId: run.outcomeEventId,
    memoryUses,
  };
}

function recordPair(scenario, pairId, treatmentOutcome, controlOutcome, context, options = {}) {
  const treatmentRun = scenario.addRun(pairId, 'treatment', treatmentOutcome, context, {
    sourceGroup: options.sourceGroup,
    verifier: options.verifier,
  });
  const controlRun = scenario.addRun(pairId, 'control', controlOutcome, context, {
    sourceGroup: options.sourceGroup,
    verifier: options.verifier,
  });
  const events = scenario.events();
  const sharedUnit = unit(options.unitId ?? pairId, context);
  const treatment = recordExperienceTrace(
    events,
    traceInput(scenario, treatmentRun, {
      unit: sharedUnit,
      memoryId: options.memoryId,
      runtime: options.runtime,
    }),
  );
  const control = recordExperienceTrace(
    events,
    traceInput(scenario, controlRun, {
      unit: sharedUnit,
      includeTarget: false,
      runtime: options.runtime,
    }),
  );
  const comparison = verifyMemoryIntervention([treatment, control], {
    id: `comparison/${pairId}`,
    memoryId: options.memoryId ?? 'memory/target',
    treatmentTraceId: treatment.id,
    controlTraceId: control.id,
    intervention: 'withheld',
    actor: 'experiment-controller',
    recordedAt: Math.max(treatment.completedAt, control.completedAt) + 1,
  });
  return { treatment, control, comparison };
}

test('trace admission preserves the full use funnel and only runtime-applied use is causal-credit eligible', () => {
  const scenario = new Scenario();
  const run = scenario.addRun('funnel', 'observed', 'success', 'context/a');
  const runtime = recordExperienceTrace(
    scenario.events(),
    traceInput(scenario, run, {
      memoryUses: [
        nonAppliedUse(scenario, 'memory/activated'),
        nonAppliedUse(
          scenario,
          'memory/consulted',
          ['activated', 'materialized', 'consulted'],
          'consulted but not applied',
        ),
        appliedUse(scenario, 'memory/applied'),
      ],
    }),
  );
  assert.deepEqual(runtime.memoryUses.find((use) => use.memoryId === 'memory/activated').stages, ['activated']);
  assert.deepEqual(runtime.memoryUses.find((use) => use.memoryId === 'memory/consulted').stages, ['activated', 'materialized', 'consulted']);
  assert.deepEqual(runtime.memoryUses.find((use) => use.memoryId === 'memory/applied').stages, [
    'activated',
    'materialized',
    'consulted',
    'applied',
  ]);
  assert.equal(runtime.memoryUses.find((use) => use.memoryId === 'memory/activated').causalCreditEligible, false);
  assert.equal(runtime.memoryUses.find((use) => use.memoryId === 'memory/applied').causalCreditEligible, true);
  assert.equal(runtime.procedurePromotionAuthorized, false);
  assert.equal(runtime.executionAuthorized, false);

  const reconstructed = recordExperienceTrace(
    scenario.events(),
    traceInput(scenario, run, {
      id: 'trace/reconstructed',
      captureMode: 'host-reconstructed',
    }),
  );
  assert.equal(reconstructed.memoryUses.find((use) => use.memoryId === 'memory/target').causalCreditEligible, false);
  assert.equal(reconstructed.causalOutcomeEligible, false);
});

test('skipped or regressed use stages and missing non-use reasons fail closed', () => {
  const scenario = new Scenario();
  const run = scenario.addRun('stages', 'observed', 'success', 'context/a');
  assert.throws(
    () =>
      recordExperienceTrace(
        scenario.events(),
        traceInput(scenario, run, {
          memoryUses: [
            nonAppliedUse(
              scenario,
              'memory/skipped',
              ['activated', 'consulted'],
              'invalid sequence',
            ),
          ],
        }),
      ),
    /exact monotonic exposure prefix/,
  );
  assert.throws(
    () =>
      recordExperienceTrace(
        scenario.events(),
        traceInput(scenario, run, {
          id: 'trace/no-reason',
          memoryUses: [
            {
              memoryId: 'memory/no-reason',
              kind: 'episode',
              stages: ['activated'],
              evidence: [evidenceRefFor(scenario.memoryEvidence)],
            },
          ],
        }),
      ),
    /nonUseReason/,
  );
});

test('stale canonical fingerprints and unavailable evidence fail closed', () => {
  const scenario = new Scenario();
  const run = scenario.addRun('stale', 'observed', 'success', 'context/a');
  const stale = traceInput(scenario, run);
  stale.canonicalFingerprint = sha('not-the-ledger');
  assert.throws(() => recordExperienceTrace(scenario.events(), stale), /stale or forged/);

  scenario.kernel.setEvidenceAvailability(
    { eventId: 'event/restrict-result', recordedAt: scenario.time, actor: 'privacy-controller' },
    run.resultEvidenceId,
    'restricted',
    'review required',
  );
  scenario.time += 1;
  assert.throws(
    () => recordExperienceTrace(scenario.events(), traceInput(scenario, run)),
    /unavailable or forged evidence/,
  );
});

test('paired attribution allows one verifier family but requires exact matched runtime and target absence', () => {
  const scenario = new Scenario();
  const valid = recordPair(scenario, 'strict', 'success', 'failure', 'context/a');
  assert.equal(valid.comparison.effect, 1);
  assert.deepEqual(valid.comparison.sourceGroups, ['verifier/strict']);
  assert.equal(valid.comparison.causalEvidence, true);

  const treatmentRun = scenario.addRun('target-present', 'treatment', 'success', 'context/a');
  const controlRun = scenario.addRun('target-present', 'control', 'failure', 'context/a');
  const events = scenario.events();
  const sharedUnit = unit('target-present', 'context/a');
  const treatment = recordExperienceTrace(
    events,
    traceInput(scenario, treatmentRun, { unit: sharedUnit }),
  );
  const control = recordExperienceTrace(
    events,
    traceInput(scenario, controlRun, {
      unit: sharedUnit,
      memoryUses: [
        nonAppliedUse(scenario, 'memory/target', ['activated'], 'withheld after activation'),
        appliedUse(scenario, 'memory/baseline', { kind: 'constraint', roles: ['constrains'] }),
      ],
    }),
  );
  assert.throws(
    () =>
      verifyMemoryIntervention([treatment, control], {
        id: 'comparison/target-present',
        memoryId: 'memory/target',
        treatmentTraceId: treatment.id,
        controlTraceId: control.id,
        intervention: 'withheld',
        actor: 'experiment-controller',
        recordedAt: scenario.time,
      }),
    /omit the target memory entirely/,
  );
});

test('paired attribution rejects hidden changes in other memories or runtime identity', () => {
  const scenario = new Scenario();
  const treatmentRun = scenario.addRun('hidden', 'treatment', 'success', 'context/a');
  const controlRun = scenario.addRun('hidden', 'control', 'failure', 'context/a');
  const events = scenario.events();
  const sharedUnit = unit('hidden', 'context/a');
  const treatment = recordExperienceTrace(
    events,
    traceInput(scenario, treatmentRun, { unit: sharedUnit }),
  );
  const controlExtra = recordExperienceTrace(
    events,
    traceInput(scenario, controlRun, {
      unit: sharedUnit,
      includeTarget: false,
      memoryUses: [
        appliedUse(scenario, 'memory/baseline', { kind: 'constraint', roles: ['constrains'] }),
        appliedUse(scenario, 'memory/control-only'),
      ],
    }),
  );
  assert.throws(
    () =>
      verifyMemoryIntervention([treatment, controlExtra], {
        id: 'comparison/hidden-memory',
        memoryId: 'memory/target',
        treatmentTraceId: treatment.id,
        controlTraceId: controlExtra.id,
        intervention: 'withheld',
        actor: 'experiment-controller',
        recordedAt: scenario.time,
      }),
    /differ only by the target memory/,
  );

  const controlRuntime = recordExperienceTrace(
    events,
    traceInput(scenario, controlRun, {
      id: 'trace/hidden/control-runtime',
      unit: sharedUnit,
      includeTarget: false,
      runtime: { ...runtimeIdentity, modelDigest: sha('model/version/2') },
    }),
  );
  assert.throws(
    () =>
      verifyMemoryIntervention([treatment, controlRuntime], {
        id: 'comparison/hidden-runtime',
        memoryId: 'memory/target',
        treatmentTraceId: treatment.id,
        controlTraceId: controlRuntime.id,
        intervention: 'withheld',
        actor: 'experiment-controller',
        recordedAt: scenario.time,
      }),
    /not matched/,
  );
});

test('model-reported or weakly verified successful traces remain correlational', () => {
  const scenario = new Scenario();
  const treatmentRun = scenario.addRun('weak', 'treatment', 'success', 'context/a', {
    verifier: 'model',
  });
  const controlRun = scenario.addRun('weak', 'control', 'failure', 'context/a', {
    verifier: 'model',
  });
  const events = scenario.events();
  const sharedUnit = unit('weak', 'context/a');
  const treatment = recordExperienceTrace(
    events,
    traceInput(scenario, treatmentRun, {
      unit: sharedUnit,
      captureMode: 'model-reported',
      recorder: 'model',
    }),
  );
  const control = recordExperienceTrace(
    events,
    traceInput(scenario, controlRun, {
      unit: sharedUnit,
      includeTarget: false,
      captureMode: 'model-reported',
      recorder: 'model',
    }),
  );
  assert.equal(treatment.causalOutcomeEligible, false);
  assert.throws(
    () =>
      verifyMemoryIntervention([treatment, control], {
        id: 'comparison/weak',
        memoryId: 'memory/target',
        treatmentTraceId: treatment.id,
        controlTraceId: control.id,
        intervention: 'withheld',
        actor: 'experiment-controller',
        recordedAt: scenario.time,
      }),
    /runtime-instrumented strongly verified/,
  );
});

test('plain cloned traces and interventions cannot masquerade as issued capabilities', () => {
  const scenario = new Scenario();
  const pair = recordPair(scenario, 'capability', 'success', 'failure', 'context/a');
  assert.throws(
    () =>
      verifyMemoryIntervention([structuredClone(pair.treatment), pair.control], {
        id: 'comparison/forged-trace',
        memoryId: 'memory/target',
        treatmentTraceId: pair.treatment.id,
        controlTraceId: pair.control.id,
        intervention: 'withheld',
        actor: 'experiment-controller',
        recordedAt: scenario.time,
      }),
    /issued experience trace capability/,
  );
  assert.throws(
    () =>
      assessMemoryUtility(
        { scope: scenario.scope, memoryId: 'memory/target' },
        [pair.treatment, pair.control],
        [structuredClone(pair.comparison)],
        permissivePolicy,
      ),
    /issued paired intervention capability/,
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
  const assessment = assessMemoryUtility(
    { scope: scenario.scope, memoryId: 'memory/target' },
    traces,
    comparisons,
  );
  assert.equal(assessment.classification, 'supported-positive');
  assert.equal(assessment.independentPairs, 5);
  assert.equal(assessment.distinctContexts, 2);
  assert.equal(assessment.positivePairs, 5);
  assert.equal(assessment.procedurePromotionAuthorized, false);
  assert.equal(assessment.executionAuthorized, false);
  assert.equal(isIssuedMemoryUtilityAssessment(assessment), true);
  assert.equal(isIssuedMemoryUtilityAssessment(structuredClone(assessment)), false);
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
  const assessment = assessMemoryUtility(
    { scope: scenario.scope, memoryId: 'memory/harmful' },
    traces,
    comparisons,
  );
  assert.equal(assessment.classification, 'supported-negative');
  assert.equal(assessment.negativePairs, 5);
});

test('sufficient matched zero-effect pairs produce a neutral assessment', () => {
  const scenario = new Scenario();
  const traces = [];
  const comparisons = [];
  for (let index = 0; index < 5; index += 1) {
    const pair = recordPair(
      scenario,
      `neutral/${index}`,
      'partial',
      'partial',
      index % 2 === 0 ? 'context/a' : 'context/b',
    );
    traces.push(pair.treatment, pair.control);
    comparisons.push(pair.comparison);
  }
  const assessment = assessMemoryUtility(
    { scope: scenario.scope, memoryId: 'memory/target' },
    traces,
    comparisons,
  );
  assert.equal(assessment.classification, 'neutral');
  assert.equal(assessment.neutralPairs, 5);
  assert.equal(assessment.meanEffect, 0);
});

test('opposite effects across independent contexts remain mixed instead of majority-voted', () => {
  const scenario = new Scenario();
  const traces = [];
  const comparisons = [];
  for (let index = 0; index < 5; index += 1) {
    const positive = index < 3;
    const pair = recordPair(
      scenario,
      `mixed/${index}`,
      positive ? 'success' : 'failure',
      positive ? 'failure' : 'success',
      index % 2 === 0 ? 'context/a' : 'context/b',
    );
    traces.push(pair.treatment, pair.control);
    comparisons.push(pair.comparison);
  }
  const assessment = assessMemoryUtility(
    { scope: scenario.scope, memoryId: 'memory/target' },
    traces,
    comparisons,
  );
  assert.equal(assessment.classification, 'mixed');
  assert.equal(assessment.positivePairs, 3);
  assert.equal(assessment.negativePairs, 2);
});

test('opposite effects for the same experimental unit force a mixed result and are not independent votes', () => {
  const scenario = new Scenario();
  const positive = recordPair(scenario, 'unit-conflict/a', 'success', 'failure', 'context/a', {
    unitId: 'same-unit',
  });
  const negative = recordPair(scenario, 'unit-conflict/b', 'failure', 'success', 'context/a', {
    unitId: 'same-unit',
  });
  const assessment = assessMemoryUtility(
    { scope: scenario.scope, memoryId: 'memory/target' },
    [positive.treatment, positive.control, negative.treatment, negative.control],
    [positive.comparison, negative.comparison],
    permissivePolicy,
  );
  assert.equal(assessment.classification, 'mixed');
  assert.equal(assessment.independentPairs, 0);
  assert.equal(assessment.conflictingExperimentalUnits, 1);
  assert.equal(assessment.excludedCorrelatedPairs, 2);
});

test('duplicate units and overlapping source groups do not inflate independent evidence', () => {
  const scenario = new Scenario();
  const first = recordPair(scenario, 'dedup/a', 'success', 'failure', 'context/a', {
    unitId: 'duplicate-unit',
  });
  const duplicateUnit = recordPair(scenario, 'dedup/b', 'success', 'failure', 'context/a', {
    unitId: 'duplicate-unit',
  });
  const overlappingOrigin = recordPair(scenario, 'dedup/c', 'success', 'failure', 'context/b', {
    sourceGroup: 'verifier/dedup/a',
  });
  const assessment = assessMemoryUtility(
    { scope: scenario.scope, memoryId: 'memory/target' },
    [
      first.treatment,
      first.control,
      duplicateUnit.treatment,
      duplicateUnit.control,
      overlappingOrigin.treatment,
      overlappingOrigin.control,
    ],
    [first.comparison, duplicateUnit.comparison, overlappingOrigin.comparison],
    permissivePolicy,
  );
  assert.equal(assessment.independentPairs, 1);
  assert.equal(assessment.excludedCorrelatedPairs, 2);
  assert.equal(assessment.classification, 'supported-positive');
});

test('unpaired successful use remains diagnostic correlation and never becomes causal utility', () => {
  const scenario = new Scenario();
  const traces = [];
  for (let index = 0; index < 10; index += 1) {
    const run = scenario.addRun(`correlated/${index}`, 'observed', 'success', 'context/a');
    traces.push(recordExperienceTrace(scenario.events(), traceInput(scenario, run)));
  }
  const assessment = assessMemoryUtility(
    { scope: scenario.scope, memoryId: 'memory/target' },
    traces,
    [],
  );
  assert.equal(assessment.classification, 'insufficient');
  assert.equal(assessment.causalBasis, 'none');
  assert.equal(assessment.independentPairs, 0);
  assert.equal(assessment.correlatedAppliedSuccesses, 10);
  assert.equal(assessment.runtimeInstrumentedAppliedSuccesses, 10);
});

test('scope is a hard boundary for memory evidence and utility aggregation', () => {
  const scenario = new Scenario();
  const pair = recordPair(scenario, 'scope', 'success', 'failure', 'context/a');
  const otherScope = assessMemoryUtility(
    { scope: 'project/other', memoryId: 'memory/target' },
    [pair.treatment, pair.control],
    [pair.comparison],
    permissivePolicy,
  );
  assert.equal(otherScope.classification, 'insufficient');
  assert.equal(otherScope.independentPairs, 0);

  const run = scenario.addRun('scope-evidence', 'observed', 'success', 'context/a');
  const foreign = evidence('evidence/foreign', 'origin/foreign', scenario.time, {
    scope: 'project/other',
  });
  scenario.kernel.captureEvidence(
    { eventId: 'event/foreign', recordedAt: scenario.time, actor: 'foreign' },
    foreign,
  );
  scenario.time += 1;
  assert.throws(
    () =>
      recordExperienceTrace(
        scenario.events(),
        traceInput(scenario, run, {
          id: 'trace/foreign-evidence',
          memoryUses: [
            {
              memoryId: 'memory/foreign',
              kind: 'source',
              stages: ['activated'],
              evidence: [evidenceRefFor(foreign)],
              nonUseReason: 'foreign memory',
            },
          ],
        }),
      ),
    /crosses scope/,
  );
});

test('trace requests are snapshotted once and reject circular or sparse input', () => {
  const scenario = new Scenario();
  const run = scenario.addRun('snapshot', 'observed', 'success', 'context/a');
  const base = traceInput(scenario, run);
  let reads = 0;
  const stateful = { ...base };
  Object.defineProperty(stateful, 'id', {
    enumerable: true,
    get() {
      reads += 1;
      return reads === 1 ? 'trace/stateful' : 'trace/mutated';
    },
  });
  const trace = recordExperienceTrace(scenario.events(), stateful);
  assert.equal(reads, 1);
  assert.equal(trace.id, 'trace/stateful');

  const circular = traceInput(scenario, run, { id: 'trace/circular' });
  circular.self = circular;
  assert.throws(() => recordExperienceTrace(scenario.events(), circular), /circular reference/);

  const sparse = traceInput(scenario, run, { id: 'trace/sparse' });
  sparse.memoryUses = new Array(1);
  assert.throws(() => recordExperienceTrace(scenario.events(), sparse), /sparse array/);
});

test('invalid policy values, repeated ids, and oversized fan-in fail closed', () => {
  const scenario = new Scenario();
  const pair = recordPair(scenario, 'bounds', 'success', 'failure', 'context/a');
  assert.throws(
    () =>
      assessMemoryUtility(
        { scope: scenario.scope, memoryId: 'memory/target' },
        [pair.treatment, pair.control],
        [pair.comparison],
        { ...permissivePolicy, neutralThreshold: 2 },
      ),
    /must be in \[0, 1\]/,
  );
  assert.throws(
    () =>
      assessMemoryUtility(
        { scope: scenario.scope, memoryId: 'memory/target' },
        [pair.treatment, pair.treatment],
        [pair.comparison],
        permissivePolicy,
      ),
    /repeats trace id/,
  );
  assert.throws(
    () =>
      assessMemoryUtility(
        { scope: scenario.scope, memoryId: 'memory/target' },
        [],
        new Array(4097).fill(pair.comparison),
        permissivePolicy,
      ),
    /cannot inspect more than 4096 interventions/,
  );
});
