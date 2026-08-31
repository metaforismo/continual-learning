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
  verifyApplicabilityObservation,
} from '../dist/index.js';

function sha(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

const scope = 'project/applicability-api';
const runtime = Object.freeze({
  modelDigest: sha('model/v1'),
  toolDigest: sha('tools/v1'),
  harnessDigest: sha('harness/v1'),
  verifierDigest: sha('verifier/v1'),
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
    labels: ['applicability-api'],
  };
}

class Scenario {
  constructor() {
    this.kernel = new MemoryKernel();
    this.time = 1;
    this.memoryEvidence = evidence('evidence/memory', 'origin/memory', this.time, {
      kind: 'human-feedback',
      authority: 'human-explicit',
      preview: 'validated memory source',
    });
    this.kernel.captureEvidence(
      { eventId: 'event/memory', recordedAt: this.time, actor: 'human' },
      this.memoryEvidence,
    );
    this.time += 1;
  }

  addRun(pairId, arm, outcome, context, sourceGroup) {
    const resultTime = this.time;
    const result = evidence(`evidence/${pairId}/${arm}/${resultTime}`, sourceGroup, resultTime);
    this.kernel.captureEvidence(
      {
        eventId: `event/result/${pairId}/${arm}/${resultTime}`,
        recordedAt: resultTime,
        actor: 'test-runner',
      },
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

function memoryUses(scenario, includeTarget) {
  const baseline = {
    memoryId: 'memory/baseline',
    kind: 'constraint',
    stages: ['activated', 'materialized', 'consulted', 'applied'],
    evidence: [evidenceRefFor(scenario.memoryEvidence, ['constrains'])],
  };
  const target = {
    memoryId: 'memory/target',
    kind: 'procedure',
    stages: ['activated', 'materialized', 'consulted', 'applied'],
    evidence: [evidenceRefFor(scenario.memoryEvidence, ['supports'])],
  };
  return includeTarget ? [target, baseline] : [baseline];
}

function pairFixture(scenario, id, treatmentOutcome, controlOutcome, context, sourceGroup) {
  const treatmentRun = scenario.addRun(id, 'treatment', treatmentOutcome, context, sourceGroup);
  const controlRun = scenario.addRun(id, 'control', controlOutcome, context, sourceGroup);
  const unit = {
    taskFamily: 'maintenance',
    instanceDigest: sha(`instance/${id}`),
    environmentDigest: sha(`environment/${context}`),
    seed: `seed/${id}`,
  };
  const events = scenario.events();
  const trace = (run, includeTarget) =>
    recordExperienceTrace(events, {
      id: `trace/${run.pairId}/${run.arm}`,
      scope,
      runId: run.runId,
      taskId: run.taskId,
      contextFingerprint: run.context,
      goalSignature: 'repair maintenance behavior',
      unit,
      runtime,
      startedAt: run.startedAt,
      completedAt: run.completedAt,
      captureMode: 'runtime-instrumented',
      recorder: 'instrumented-runtime',
      canonicalFingerprint: fingerprintMemoryEvents(events),
      outcomeEventId: run.outcomeEventId,
      memoryUses: memoryUses(scenario, includeTarget),
    });
  const treatment = trace(treatmentRun, true);
  const control = trace(controlRun, false);
  return {
    traces: [treatment, control],
    intervention: {
      id: `comparison/${id}`,
      memoryId: 'memory/target',
      treatmentTraceId: treatment.id,
      controlTraceId: control.id,
      intervention: 'withheld',
      actor: 'experiment-controller',
      recordedAt: Math.max(treatment.completedAt, control.completedAt) + 1,
    },
  };
}

function observe(fixture, id, features) {
  return verifyApplicabilityObservation(fixture.traces, fixture.intervention, {
    id,
    contextFeatures: features,
    featureSchemaDigest: sha('feature-schema/v1'),
    featureObservedAt: 0,
    recorder: 'context-instrumentation',
  });
}

test('unissued observations are rejected before any forged property getter is read', () => {
  let idReads = 0;
  const forged = {};
  Object.defineProperty(forged, 'id', {
    enumerable: true,
    get() {
      idReads += 1;
      return 'observation/forged';
    },
  });
  assert.throws(
    () =>
      induceApplicabilityHypothesis([forged], {
        id: 'hypothesis/forged',
        scope,
        memoryId: 'memory/target',
        discoveryObservationIds: ['observation/forged'],
        actor: 'hypothesis-controller',
        recordedAt: 1,
      }),
    /issued observation capability/,
  );
  assert.equal(idReads, 0);
});

test('public request and observation arrays are snapshotted exactly once', () => {
  let requestReads = 0;
  const request = {
    id: 'hypothesis/snapshot-missing',
    scope,
    memoryId: 'memory/target',
    get discoveryObservationIds() {
      requestReads += 1;
      return ['observation/missing'];
    },
    actor: 'hypothesis-controller',
    recordedAt: 1,
  };
  assert.throws(
    () => induceApplicabilityHypothesis([], request),
    /absent or duplicated/,
  );
  assert.equal(requestReads, 1);

  let arrayReads = 0;
  const forged = {};
  const observations = [];
  Object.defineProperty(observations, 0, {
    enumerable: true,
    configurable: true,
    get() {
      arrayReads += 1;
      return forged;
    },
  });
  observations.length = 1;
  assert.throws(
    () =>
      induceApplicabilityHypothesis(observations, {
        id: 'hypothesis/snapshot-array',
        scope,
        memoryId: 'memory/target',
        discoveryObservationIds: ['observation/forged'],
        actor: 'hypothesis-controller',
        recordedAt: 1,
      }),
    /issued observation capability/,
  );
  assert.equal(arrayReads, 1);
});

test('same applicability ids are exact-retry idempotent and reject conflicting content', () => {
  const scenario = new Scenario();
  const discoveryFixture = pairFixture(
    scenario,
    'identity/discovery',
    'success',
    'failure',
    'context/discovery',
    'source/discovery',
  );
  const observationInput = {
    id: 'observation/identity',
    contextFeatures: ['runtime:node', 'symptom:race'],
    featureSchemaDigest: sha('feature-schema/v1'),
    featureObservedAt: 0,
    recorder: 'context-instrumentation',
  };
  const firstObservation = verifyApplicabilityObservation(
    discoveryFixture.traces,
    discoveryFixture.intervention,
    observationInput,
  );
  const retryObservation = verifyApplicabilityObservation(
    discoveryFixture.traces,
    discoveryFixture.intervention,
    observationInput,
  );
  assert.equal(retryObservation, firstObservation);
  assert.throws(
    () =>
      verifyApplicabilityObservation(
        discoveryFixture.traces,
        discoveryFixture.intervention,
        { ...observationInput, contextFeatures: ['runtime:python', 'symptom:race'] },
      ),
    /conflicts with an already issued identity/,
  );

  const candidateRequest = {
    id: 'hypothesis/identity',
    scope,
    memoryId: 'memory/target',
    discoveryObservationIds: [firstObservation.id],
    actor: 'hypothesis-controller',
    recordedAt: scenario.time + 1,
    policy: {
      minPositiveExamples: 1,
      minCounterexamples: 1,
      minDistinctContexts: 1,
      minFeatureSupport: 1,
      minDiscoveryPrecision: 0,
      minDiscoveryRecall: 0,
      maxDiscoveryCounterexampleActivationRate: 1,
      minMeanActivatedEffect: 0,
    },
  };
  const candidate = induceApplicabilityHypothesis([firstObservation], candidateRequest);
  const candidateRetry = induceApplicabilityHypothesis([firstObservation], candidateRequest);
  assert.equal(candidateRetry, candidate);
  assert.throws(
    () =>
      induceApplicabilityHypothesis([firstObservation], {
        ...candidateRequest,
        recordedAt: candidateRequest.recordedAt + 1,
      }),
    /conflicts with an already issued identity/,
  );

  const validationFixture = pairFixture(
    scenario,
    'identity/validation',
    'failure',
    'success',
    'context/validation',
    'source/validation',
  );
  const heldOut = observe(
    validationFixture,
    'observation/identity-validation',
    ['runtime:python', 'symptom:race'],
  );
  const validationRequest = {
    id: 'validation/identity',
    candidateId: candidate.id,
    validationObservationIds: [heldOut.id],
    actor: 'validation-controller',
    recordedAt: scenario.time + 1,
    policy: {
      minValidationExamples: 1,
      minPositiveExamples: 1,
      minCounterexamples: 1,
      minDistinctContexts: 1,
      minPrecision: 0,
      minRecall: 0,
      minSpecificity: 0,
      maxCounterexampleActivationRate: 1,
      minMeanActivatedEffect: 0,
    },
  };
  const validation = validateApplicabilityHypothesis(candidate, [heldOut], validationRequest);
  const validationRetry = validateApplicabilityHypothesis(candidate, [heldOut], validationRequest);
  assert.equal(validationRetry, validation);
  assert.throws(
    () =>
      validateApplicabilityHypothesis(candidate, [heldOut], {
        ...validationRequest,
        recordedAt: validationRequest.recordedAt + 1,
      }),
    /conflicts with an already issued identity/,
  );
});

test('held-out validation cannot rewrite a reused discovery context manifest', () => {
  const scenario = new Scenario();
  const sharedContext = 'context/shared-manifest';
  const discoveryFixture = pairFixture(
    scenario,
    'context-manifest/discovery',
    'success',
    'failure',
    sharedContext,
    'source/context-manifest/discovery',
  );
  const discovery = observe(
    discoveryFixture,
    'observation/context-manifest/discovery',
    ['runtime:node', 'symptom:race'],
  );
  const candidate = induceApplicabilityHypothesis([discovery], {
    id: 'hypothesis/context-manifest',
    scope,
    memoryId: 'memory/target',
    discoveryObservationIds: [discovery.id],
    actor: 'hypothesis-controller',
    recordedAt: scenario.time + 1,
    policy: {
      minPositiveExamples: 1,
      minCounterexamples: 1,
      minDistinctContexts: 1,
      minFeatureSupport: 1,
      minDiscoveryPrecision: 0,
      minDiscoveryRecall: 0,
      maxDiscoveryCounterexampleActivationRate: 1,
      minMeanActivatedEffect: 0,
    },
  });

  const validationFixture = pairFixture(
    scenario,
    'context-manifest/validation',
    'failure',
    'success',
    sharedContext,
    'source/context-manifest/validation',
  );
  const rewritten = observe(
    validationFixture,
    'observation/context-manifest/validation',
    ['runtime:python', 'symptom:race'],
  );
  assert.throws(
    () =>
      validateApplicabilityHypothesis(candidate, [rewritten], {
        id: 'validation/context-manifest',
        candidateId: candidate.id,
        validationObservationIds: [rewritten.id],
        actor: 'validation-controller',
        recordedAt: scenario.time + 1,
      }),
    /rewrites the feature manifest of a discovery context fingerprint/,
  );
});
