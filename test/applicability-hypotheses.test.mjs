import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  MemoryKernel,
  applicabilityRuleApplies,
  evidenceRefFor,
  fingerprintMemoryEvents,
  induceApplicabilityHypothesis,
  isIssuedApplicabilityHypothesisCandidate,
  isIssuedApplicabilityObservation,
  isIssuedVerifiedApplicabilityHypothesis,
  recordExperienceTrace,
  validateApplicabilityHypothesis,
  verifyApplicabilityObservation,
} from '../dist/index.js';

function sha(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

const scope = 'project/applicability';
const featureSchemaDigest = sha('context-feature-schema/v1');
const runtimeIdentity = Object.freeze({
  modelDigest: sha('model/version/1'),
  toolDigest: sha('tools/version/1'),
  harnessDigest: sha('harness/version/1'),
  verifierDigest: sha('verifier/version/1'),
});

function evidence(id, sourceGroup, recordedAt, overrides = {}) {
  const preview = overrides.preview ?? `verified evidence ${id}`;
  return {
    id,
    scope: overrides.scope ?? scope,
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
    labels: ['applicability'],
  };
}

class Scenario {
  constructor() {
    this.kernel = new MemoryKernel();
    this.time = 1;
    this.memoryEvidence = evidence('evidence/memory', 'origin/memory', this.time, {
      kind: 'human-feedback',
      authority: 'human-explicit',
      preview: 'validated target memory source',
    });
    this.kernel.captureEvidence(
      { eventId: 'event/memory', recordedAt: this.time, actor: 'human' },
      this.memoryEvidence,
    );
    this.time += 1;
  }

  addRun(pairId, arm, outcome, contextFingerprint, sourceGroup) {
    const resultTime = this.time;
    const result = evidence(
      `evidence/result/${pairId}/${arm}/${resultTime}`,
      sourceGroup,
      resultTime,
    );
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
        contextFingerprint,
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
      contextFingerprint,
      outcomeEventId,
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

function appliedUse(scenario, memoryId = 'memory/target', kind = 'procedure', roles = ['supports']) {
  return {
    memoryId,
    kind,
    stages: ['activated', 'materialized', 'consulted', 'applied'],
    evidence: [evidenceRefFor(scenario.memoryEvidence, roles)],
  };
}

function traceInput(scenario, run, sharedUnit, includeTarget) {
  return {
    id: `trace/${run.pairId}/${run.arm}`,
    scope,
    runId: run.runId,
    taskId: run.taskId,
    contextFingerprint: run.contextFingerprint,
    goalSignature: 'repair authentication behavior',
    unit: sharedUnit,
    runtime: runtimeIdentity,
    startedAt: run.startedAt,
    completedAt: run.completedAt,
    captureMode: 'runtime-instrumented',
    recorder: 'instrumented-runtime',
    canonicalFingerprint: fingerprintMemoryEvents(scenario.events()),
    outcomeEventId: run.outcomeEventId,
    memoryUses: [
      ...(includeTarget ? [appliedUse(scenario)] : []),
      appliedUse(scenario, 'memory/baseline', 'constraint', ['constrains']),
    ],
  };
}

function observation(
  scenario,
  id,
  treatmentOutcome,
  controlOutcome,
  contextFingerprint,
  contextFeatures,
  options = {},
) {
  const sourceGroup = options.sourceGroup ?? `verifier/${id}`;
  const treatmentRun = scenario.addRun(
    id,
    'treatment',
    treatmentOutcome,
    contextFingerprint,
    sourceGroup,
  );
  const controlRun = scenario.addRun(
    id,
    'control',
    controlOutcome,
    contextFingerprint,
    sourceGroup,
  );
  const events = scenario.events();
  const sharedUnit = unit(options.unitId ?? id, contextFingerprint);
  const treatment = recordExperienceTrace(
    events,
    traceInput(scenario, treatmentRun, sharedUnit, true),
  );
  const control = recordExperienceTrace(
    events,
    traceInput(scenario, controlRun, sharedUnit, false),
  );
  return verifyApplicabilityObservation(
    [treatment, control],
    {
      id: `comparison/${id}`,
      memoryId: 'memory/target',
      treatmentTraceId: treatment.id,
      controlTraceId: control.id,
      intervention: 'withheld',
      actor: 'experiment-controller',
      recordedAt: Math.max(treatment.completedAt, control.completedAt) + 1,
    },
    {
      id: `observation/${id}`,
      contextFeatures,
      featureSchemaDigest: options.featureSchemaDigest ?? featureSchemaDigest,
      featureObservedAt: options.featureObservedAt ?? 0,
      recorder: 'context-instrumentation',
    },
  );
}

function positiveFeatures(repo) {
  return ['framework:nextjs', 'runtime:node', 'symptom:race', `repo:${repo}`];
}

function negativeFeatures(framework, repo) {
  return [`framework:${framework}`, 'runtime:python', 'symptom:race', `repo:${repo}`];
}

function discoverySet(scenario, prefix = 'discovery') {
  return [
    observation(scenario, `${prefix}/pos-1`, 'success', 'failure', `${prefix}/next/a`, positiveFeatures('a')),
    observation(scenario, `${prefix}/pos-2`, 'success', 'failure', `${prefix}/next/b`, positiveFeatures('b')),
    observation(scenario, `${prefix}/pos-3`, 'success', 'failure', `${prefix}/next/c`, positiveFeatures('c')),
    observation(scenario, `${prefix}/neg-1`, 'failure', 'success', `${prefix}/python/a`, negativeFeatures('fastapi', 'd')),
    observation(scenario, `${prefix}/neg-2`, 'failure', 'success', `${prefix}/python/b`, negativeFeatures('flask', 'e')),
  ];
}

function validationSet(scenario, prefix = 'validation') {
  return [
    observation(scenario, `${prefix}/pos-1`, 'success', 'failure', `${prefix}/next/a`, positiveFeatures('f')),
    observation(scenario, `${prefix}/pos-2`, 'success', 'failure', `${prefix}/next/b`, positiveFeatures('g')),
    observation(scenario, `${prefix}/pos-3`, 'success', 'failure', `${prefix}/next/c`, positiveFeatures('h')),
    observation(scenario, `${prefix}/pos-4`, 'success', 'failure', `${prefix}/next/d`, positiveFeatures('i')),
    observation(scenario, `${prefix}/neg-1`, 'failure', 'success', `${prefix}/python/a`, negativeFeatures('django', 'j')),
    observation(scenario, `${prefix}/neg-2`, 'failure', 'success', `${prefix}/python/b`, negativeFeatures('flask', 'k')),
  ];
}

function induceCandidate(scenario, observations, id = 'hypothesis/nextjs-race', policy = undefined) {
  return induceApplicabilityHypothesis(observations, {
    id,
    scope,
    memoryId: 'memory/target',
    discoveryObservationIds: observations.map((item) => item.id),
    actor: 'hypothesis-controller',
    recordedAt: scenario.time + 1,
    ...(policy === undefined ? {} : { policy }),
  });
}

test('held-out validation learns a bounded rule without memorizing unique repository features', () => {
  const scenario = new Scenario();
  const discovery = discoverySet(scenario);
  const candidate = induceCandidate(scenario, discovery);
  assert.equal(candidate.status, 'candidate');
  assert.equal(candidate.blockers.length, 0);
  assert.equal(isIssuedApplicabilityHypothesisCandidate(candidate), true);
  assert.ok(candidate.rule.requiredFeatures.length + candidate.rule.forbiddenFeatures.length > 0);
  assert.equal(
    [...candidate.rule.requiredFeatures, ...candidate.rule.forbiddenFeatures].some((feature) =>
      feature.startsWith('repo:'),
    ),
    false,
  );
  assert.equal(applicabilityRuleApplies(candidate.rule, positiveFeatures('held-out')), true);
  assert.equal(applicabilityRuleApplies(candidate.rule, negativeFeatures('django', 'held-out')), false);

  const validation = validationSet(scenario);
  const result = validateApplicabilityHypothesis(candidate, validation, {
    id: 'validation/nextjs-race',
    candidateId: candidate.id,
    validationObservationIds: validation.map((item) => item.id),
    actor: 'validation-controller',
    recordedAt: scenario.time + 1,
  });
  assert.equal(result.status, 'validated');
  assert.equal(result.validationMetrics.precision, 1);
  assert.equal(result.validationMetrics.recall, 1);
  assert.equal(result.validationMetrics.specificity, 1);
  assert.equal(result.procedurePromotionAuthorized, false);
  assert.equal(result.executionAuthorized, false);
  assert.equal(isIssuedVerifiedApplicabilityHypothesis(result), true);
});

test('context features must be bound by one schema before either trial arm starts', () => {
  const scenario = new Scenario();
  const valid = observation(
    scenario,
    'pretrial/valid',
    'success',
    'failure',
    'context/pretrial/valid',
    ['Runtime:Node', 'Framework:NextJS'],
  );
  assert.deepEqual(valid.contextFeatures, ['framework:nextjs', 'runtime:node']);
  assert.equal(isIssuedApplicabilityObservation(valid), true);

  assert.throws(
    () =>
      observation(
        scenario,
        'pretrial/late',
        'success',
        'failure',
        'context/pretrial/late',
        positiveFeatures('late'),
        { featureObservedAt: scenario.time + 100 },
      ),
    /before both trial arms start/,
  );
  assert.throws(
    () =>
      observation(
        scenario,
        'pretrial/schema',
        'success',
        'failure',
        'context/pretrial/schema',
        ['runtime:node', 'runtime:node'],
      ),
    /duplicates after normalization/,
  );
});

test('discovery and validation are invariant to observation and id ordering', () => {
  const scenario = new Scenario();
  const discovery = discoverySet(scenario, 'order-discovery');
  const request = {
    id: 'hypothesis/order',
    scope,
    memoryId: 'memory/target',
    discoveryObservationIds: discovery.map((item) => item.id),
    actor: 'hypothesis-controller',
    recordedAt: scenario.time + 1,
  };
  const forward = induceApplicabilityHypothesis(discovery, request);
  const reversed = induceApplicabilityHypothesis([...discovery].reverse(), {
    ...request,
    discoveryObservationIds: [...request.discoveryObservationIds].reverse(),
  });
  assert.deepEqual(reversed, forward);

  const heldOut = validationSet(scenario, 'order-validation');
  const validationRequest = {
    id: 'validation/order',
    candidateId: forward.id,
    validationObservationIds: heldOut.map((item) => item.id),
    actor: 'validation-controller',
    recordedAt: scenario.time + 1,
  };
  const validationForward = validateApplicabilityHypothesis(forward, heldOut, validationRequest);
  const validationReversed = validateApplicabilityHypothesis(forward, [...heldOut].reverse(), {
    ...validationRequest,
    validationObservationIds: [...validationRequest.validationObservationIds].reverse(),
  });
  assert.deepEqual(validationReversed, validationForward);
});

test('cloned observations and candidates cannot cross process-local capability boundaries', () => {
  const scenario = new Scenario();
  const discovery = discoverySet(scenario, 'clone-discovery');
  assert.throws(
    () =>
      induceCandidate(
        scenario,
        [structuredClone(discovery[0]), ...discovery.slice(1)],
        'hypothesis/cloned-observation',
      ),
    /issued observation capability/,
  );
  const candidate = induceCandidate(scenario, discovery, 'hypothesis/clone');
  const heldOut = validationSet(scenario, 'clone-validation');
  assert.throws(
    () =>
      validateApplicabilityHypothesis(structuredClone(candidate), heldOut, {
        id: 'validation/clone',
        candidateId: candidate.id,
        validationObservationIds: heldOut.map((item) => item.id),
        actor: 'validation-controller',
        recordedAt: scenario.time + 1,
      }),
    /issued hypothesis candidate/,
  );
});

test('held-out validation rejects reused units, comparisons, source groups, and feature schemas', () => {
  const scenario = new Scenario();
  const discovery = discoverySet(scenario, 'overlap-discovery');
  const candidate = induceCandidate(scenario, discovery, 'hypothesis/overlap');

  const reusedUnit = observation(
    scenario,
    'overlap/unit',
    'success',
    'failure',
    'overlap-discovery/next/a',
    positiveFeatures('unit'),
    { unitId: 'overlap-discovery/pos-1' },
  );
  assert.throws(
    () =>
      validateApplicabilityHypothesis(candidate, [reusedUnit], {
        id: 'validation/reused-unit',
        candidateId: candidate.id,
        validationObservationIds: [reusedUnit.id],
        actor: 'validation-controller',
        recordedAt: scenario.time + 1,
      }),
    /reuses a discovery experimental unit/,
  );

  const reusedSource = observation(
    scenario,
    'overlap/source',
    'success',
    'failure',
    'overlap-validation/source',
    positiveFeatures('source'),
    { sourceGroup: 'verifier/overlap-discovery/pos-1' },
  );
  assert.throws(
    () =>
      validateApplicabilityHypothesis(candidate, [reusedSource], {
        id: 'validation/reused-source',
        candidateId: candidate.id,
        validationObservationIds: [reusedSource.id],
        actor: 'validation-controller',
        recordedAt: scenario.time + 1,
      }),
    /reuses a discovery verifier source group/,
  );

  const wrongSchema = observation(
    scenario,
    'overlap/schema',
    'success',
    'failure',
    'overlap-validation/schema',
    positiveFeatures('schema'),
    { featureSchemaDigest: sha('context-feature-schema/v2') },
  );
  assert.throws(
    () =>
      validateApplicabilityHypothesis(candidate, [wrongSchema], {
        id: 'validation/wrong-schema',
        candidateId: candidate.id,
        validationObservationIds: [wrongSchema.id],
        actor: 'validation-controller',
        recordedAt: scenario.time + 1,
      }),
    /feature schema does not match discovery/,
  );

  assert.throws(
    () =>
      validateApplicabilityHypothesis(candidate, discovery, {
        id: 'validation/reused-comparison',
        candidateId: candidate.id,
        validationObservationIds: [discovery[0].id],
        actor: 'validation-controller',
        recordedAt: scenario.time + 1,
      }),
    /reuses a discovery comparison/,
  );
});

test('identical held-out feature signatures with opposite effects remain ambiguous', () => {
  const scenario = new Scenario();
  const candidate = induceCandidate(
    scenario,
    discoverySet(scenario, 'ambiguous-discovery'),
    'hypothesis/ambiguous',
  );
  const signature = ['framework:nextjs', 'runtime:node', 'symptom:race', 'deployment:edge'];
  const heldOut = [
    observation(scenario, 'ambiguous/positive', 'success', 'failure', 'ambiguous/context/a', signature),
    observation(scenario, 'ambiguous/negative', 'failure', 'success', 'ambiguous/context/b', signature),
    observation(scenario, 'ambiguous/positive-2', 'success', 'failure', 'ambiguous/context/c', positiveFeatures('c')),
    observation(scenario, 'ambiguous/positive-3', 'success', 'failure', 'ambiguous/context/d', positiveFeatures('d')),
    observation(scenario, 'ambiguous/negative-2', 'failure', 'success', 'ambiguous/context/e', negativeFeatures('django', 'e')),
    observation(scenario, 'ambiguous/negative-3', 'failure', 'success', 'ambiguous/context/f', negativeFeatures('flask', 'f')),
  ];
  const result = validateApplicabilityHypothesis(candidate, heldOut, {
    id: 'validation/ambiguous',
    candidateId: candidate.id,
    validationObservationIds: heldOut.map((item) => item.id),
    actor: 'validation-controller',
    recordedAt: scenario.time + 1,
  });
  assert.equal(result.status, 'ambiguous');
  assert.ok(result.validationMetrics.contradictoryFeatureSignatureDigests.length > 0);
});

test('held-out metric failure rejects an overgeneralized rule instead of preserving discovery success', () => {
  const scenario = new Scenario();
  const candidate = induceCandidate(
    scenario,
    discoverySet(scenario, 'rejection-discovery'),
    'hypothesis/rejection',
  );
  const heldOut = [
    observation(scenario, 'rejection/positive-1', 'success', 'failure', 'rejection/context/a', positiveFeatures('a')),
    observation(scenario, 'rejection/positive-2', 'success', 'failure', 'rejection/context/b', positiveFeatures('b')),
    observation(scenario, 'rejection/positive-3', 'success', 'failure', 'rejection/context/c', positiveFeatures('c')),
    observation(scenario, 'rejection/positive-4', 'success', 'failure', 'rejection/context/d', positiveFeatures('d')),
    observation(
      scenario,
      'rejection/counter-1',
      'failure',
      'success',
      'rejection/context/e',
      ['framework:nextjs', 'runtime:node', 'symptom:race', 'deployment:edge', 'repo:e'],
    ),
    observation(
      scenario,
      'rejection/counter-2',
      'failure',
      'success',
      'rejection/context/f',
      ['framework:nextjs', 'runtime:node', 'symptom:race', 'deployment:serverless', 'repo:f'],
    ),
  ];
  const result = validateApplicabilityHypothesis(candidate, heldOut, {
    id: 'validation/rejection',
    candidateId: candidate.id,
    validationObservationIds: heldOut.map((item) => item.id),
    actor: 'validation-controller',
    recordedAt: scenario.time + 1,
  });
  assert.equal(result.status, 'rejected');
  assert.ok(result.validationMetrics.falsePositive > 0);
  assert.ok(result.blockers.some((blocker) => blocker.includes('specificity')));
});

test('small discovery sets remain insufficient and cannot be rescued by validation', () => {
  const scenario = new Scenario();
  const discovery = [
    observation(scenario, 'insufficient/positive', 'success', 'failure', 'insufficient/context/a', positiveFeatures('a')),
    observation(scenario, 'insufficient/negative', 'failure', 'success', 'insufficient/context/b', negativeFeatures('flask', 'b')),
  ];
  const candidate = induceCandidate(scenario, discovery, 'hypothesis/insufficient');
  assert.equal(candidate.status, 'insufficient');
  assert.ok(candidate.blockers.length > 0);
  const heldOut = validationSet(scenario, 'insufficient-validation');
  const result = validateApplicabilityHypothesis(candidate, heldOut, {
    id: 'validation/insufficient',
    candidateId: candidate.id,
    validationObservationIds: heldOut.map((item) => item.id),
    actor: 'validation-controller',
    recordedAt: scenario.time + 1,
  });
  assert.equal(result.status, 'insufficient');
});

test('duplicate units and transitive source families are collapsed before rule induction', () => {
  const scenario = new Scenario();
  const duplicateBridge = observation(
    scenario,
    'collapse/duplicate-bridge',
    'success',
    'failure',
    'collapse/context/shared',
    positiveFeatures('shared'),
    { unitId: 'collapse/shared-unit', sourceGroup: 'source/bridge' },
  );
  const duplicatePrivate = observation(
    scenario,
    'collapse/duplicate-private',
    'success',
    'partial',
    'collapse/context/shared',
    positiveFeatures('shared'),
    { unitId: 'collapse/shared-unit', sourceGroup: 'source/private' },
  );
  const bridgedUnit = observation(
    scenario,
    'collapse/bridged-unit',
    'success',
    'failure',
    'collapse/context/bridged',
    positiveFeatures('bridged'),
    { sourceGroup: 'source/bridge' },
  );
  const otherPositive = observation(
    scenario,
    'collapse/other-positive',
    'success',
    'failure',
    'collapse/context/positive',
    positiveFeatures('positive'),
  );
  const negativeOne = observation(
    scenario,
    'collapse/negative-1',
    'failure',
    'success',
    'collapse/context/negative-1',
    negativeFeatures('fastapi', 'negative-1'),
  );
  const negativeTwo = observation(
    scenario,
    'collapse/negative-2',
    'failure',
    'success',
    'collapse/context/negative-2',
    negativeFeatures('flask', 'negative-2'),
  );
  const selected = [
    duplicateBridge,
    duplicatePrivate,
    bridgedUnit,
    otherPositive,
    negativeOne,
    negativeTwo,
  ];
  const candidate = induceCandidate(scenario, selected, 'hypothesis/collapse', {
    minPositiveExamples: 2,
  });
  assert.equal(candidate.status, 'candidate');
  assert.equal(candidate.acceptedDiscoveryObservationIds.length, 4);
  assert.equal(candidate.excludedDiscoveryObservationIds.length, 2);
  assert.deepEqual(
    [...candidate.excludedDiscoveryObservationIds].sort(),
    [duplicateBridge.id, bridgedUnit.id].sort(),
  );
});

test('one experimental unit or context fingerprint cannot carry inconsistent feature manifests', () => {
  const scenario = new Scenario();
  const first = observation(
    scenario,
    'manifest/first',
    'success',
    'failure',
    'manifest/context/shared',
    positiveFeatures('a'),
    { unitId: 'manifest/shared' },
  );
  const inconsistentUnit = observation(
    scenario,
    'manifest/unit',
    'success',
    'partial',
    'manifest/context/shared',
    ['framework:nextjs', 'runtime:node', 'symptom:different', 'repo:a'],
    { unitId: 'manifest/shared' },
  );
  assert.throws(
    () => induceCandidate(scenario, [first, inconsistentUnit], 'hypothesis/inconsistent-unit'),
    /different feature manifests to one experimental unit/,
  );

  const inconsistentContext = observation(
    scenario,
    'manifest/context',
    'success',
    'failure',
    'manifest/context/shared',
    ['framework:nextjs', 'runtime:node', 'symptom:other', 'repo:a'],
    { unitId: 'manifest/other-unit' },
  );
  assert.throws(
    () => induceCandidate(scenario, [first, inconsistentContext], 'hypothesis/inconsistent-context'),
    /different feature manifests to one context fingerprint/,
  );
});

test('public rule evaluation and policy inputs fail closed on malformed runtime JSON', () => {
  assert.throws(
    () =>
      applicabilityRuleApplies(
        { requiredFeatures: ['runtime:node'], forbiddenFeatures: ['runtime:node'] },
        ['runtime:node'],
      ),
    /both required and forbidden/,
  );
  assert.throws(
    () => applicabilityRuleApplies({ requiredFeatures: [], forbiddenFeatures: [] }, []),
    /requires 1/,
  );

  const scenario = new Scenario();
  const discovery = discoverySet(scenario, 'policy-discovery');
  assert.throws(
    () =>
      induceCandidate(scenario, discovery, 'hypothesis/policy', {
        maxCandidateFeatures: 10_000,
      }),
    /cannot exceed/,
  );
  const circular = {
    id: 'hypothesis/circular',
    scope,
    memoryId: 'memory/target',
    discoveryObservationIds: discovery.map((item) => item.id),
    actor: 'hypothesis-controller',
    recordedAt: scenario.time + 1,
  };
  circular.self = circular;
  assert.throws(
    () => induceApplicabilityHypothesis(discovery, circular),
    /circular/,
  );
});
