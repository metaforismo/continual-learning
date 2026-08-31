import { createHash } from 'node:crypto';

import {
  MemoryKernel,
  evidenceRefFor,
  fingerprintMemoryEvents,
  induceApplicabilityHypothesis,
  recordExperienceTrace,
  validateApplicabilityHypothesis,
  verifyApplicabilityObservation,
} from '../dist/index.js';

export function sha(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

export function makeEvidence(id, scope, sourceGroup, recordedAt, overrides = {}) {
  const sensitivity = overrides.sensitivity ?? 'internal';
  const preview = overrides.preview ?? `verified evidence ${id}`;
  return {
    id,
    scope: overrides.scope ?? scope,
    kind: overrides.kind ?? 'test-result',
    sourceGroups: overrides.sourceGroups ?? [sourceGroup],
    authority: overrides.authority ?? 'tool-verified',
    observedAt: overrides.observedAt ?? recordedAt,
    sensitivity,
    taints: overrides.taints ?? [],
    artifact: {
      uri: overrides.uri ?? `memory://artifact/${id}`,
      digest: overrides.artifactDigest ?? sha(`artifact/${id}`),
      sizeBytes: overrides.sizeBytes ?? preview.length,
      mediaType: overrides.mediaType ?? 'application/json',
      encryption:
        overrides.encryption ??
        (sensitivity === 'sensitive' || sensitivity === 'secret'
          ? 'provider-managed'
          : 'none'),
      retention: overrides.retention ?? 'durable',
    },
    ...(sensitivity === 'sensitive' || sensitivity === 'secret'
      ? {}
      : { preview }),
    derivedFrom: overrides.derivedFrom ?? [],
    labels: overrides.labels ?? ['learning-fixture'],
  };
}

export class LearningScenario {
  constructor(prefix) {
    this.prefix = prefix;
    this.scope = `project/${prefix}`;
    this.kernel = new MemoryKernel();
    this.time = 1;
    this.runtimeIdentity = Object.freeze({
      modelDigest: sha(`${prefix}/model/version/1`),
      toolDigest: sha(`${prefix}/tools/version/1`),
      harnessDigest: sha(`${prefix}/harness/version/1`),
      verifierDigest: sha(`${prefix}/attribution-verifier/version/1`),
    });
    this.featureSchemaDigest = sha(`${prefix}/context-feature-schema/v1`);
    this.memoryEvidence = this.captureEvidence('memory', 'origin/memory', {
      kind: 'human-feedback',
      authority: 'human-explicit',
      preview: 'validated target memory source',
    });
  }

  captureEvidence(localId, sourceGroup, overrides = {}) {
    const id = `evidence/${this.prefix}/${localId}`;
    const recordedAt = this.time;
    const record = makeEvidence(id, this.scope, sourceGroup, recordedAt, overrides);
    this.kernel.captureEvidence(
      {
        eventId: `event/${this.prefix}/capture/${localId}/${recordedAt}`,
        recordedAt,
        actor: overrides.actor ?? 'fixture-recorder',
      },
      record,
    );
    this.time += 1;
    return record;
  }

  setAvailability(record, availability, reason = 'fixture availability transition') {
    const recordedAt = this.time;
    this.kernel.setEvidenceAvailability(
      {
        eventId: `event/${this.prefix}/availability/${record.id}/${recordedAt}`,
        recordedAt,
        actor: 'fixture-controller',
      },
      record.id,
      availability,
      reason,
    );
    this.time += 1;
  }

  addRun(localId, arm, outcome, contextFingerprint, sourceGroup) {
    const resultTime = this.time;
    const result = this.captureEvidence(
      `result/${localId}/${arm}/${resultTime}`,
      sourceGroup,
      { kind: 'test-result', authority: 'tool-verified' },
    );
    const outcomeEventId = `event/${this.prefix}/outcome/${localId}/${arm}/${this.time}`;
    this.kernel.recordOutcome(
      { eventId: outcomeEventId, recordedAt: this.time, actor: 'test-runner' },
      {
        scope: this.scope,
        subjectId: `run/${this.prefix}/${localId}/${arm}`,
        taskId: `task/${this.prefix}/${localId}`,
        contextFingerprint,
        sourceGroups: [sourceGroup],
        outcome,
        verifier: 'test',
        evidence: [evidenceRefFor(result, ['verifies'])],
      },
    );
    this.time += 1;
    return {
      localId,
      arm,
      runId: `run/${this.prefix}/${localId}/${arm}`,
      taskId: `task/${this.prefix}/${localId}`,
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

function unit(scenario, id, contextFingerprint) {
  return {
    taskFamily: 'debug-authentication',
    instanceDigest: sha(`${scenario.prefix}/instance/${id}`),
    environmentDigest: sha(`${scenario.prefix}/environment/${contextFingerprint}`),
    seed: `seed/${scenario.prefix}/${id}`,
  };
}

function traceInput(scenario, run, sharedUnit, includeTarget) {
  return {
    id: `trace/${scenario.prefix}/${run.localId}/${run.arm}`,
    scope: scenario.scope,
    runId: run.runId,
    taskId: run.taskId,
    contextFingerprint: run.contextFingerprint,
    goalSignature: 'repair authentication behavior',
    unit: sharedUnit,
    runtime: scenario.runtimeIdentity,
    startedAt: run.startedAt,
    completedAt: run.completedAt,
    captureMode: 'runtime-instrumented',
    recorder: 'instrumented-runtime',
    canonicalFingerprint: fingerprintMemoryEvents(scenario.events()),
    outcomeEventId: run.outcomeEventId,
    memoryUses: includeTarget
      ? [
          {
            memoryId: 'memory/target',
            kind: 'procedure',
            stages: ['activated', 'materialized', 'consulted', 'applied'],
            evidence: [evidenceRefFor(scenario.memoryEvidence, ['supports'])],
          },
        ]
      : [],
  };
}

function observation(
  scenario,
  localId,
  treatmentOutcome,
  controlOutcome,
  contextFingerprint,
  contextFeatures,
) {
  const sourceGroup = `verifier/${scenario.prefix}/${localId}`;
  const treatmentRun = scenario.addRun(
    localId,
    'treatment',
    treatmentOutcome,
    contextFingerprint,
    sourceGroup,
  );
  const controlRun = scenario.addRun(
    localId,
    'control',
    controlOutcome,
    contextFingerprint,
    sourceGroup,
  );
  const events = scenario.events();
  const sharedUnit = unit(scenario, localId, contextFingerprint);
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
      id: `comparison/${scenario.prefix}/${localId}`,
      memoryId: 'memory/target',
      treatmentTraceId: treatment.id,
      controlTraceId: control.id,
      intervention: 'withheld',
      actor: 'experiment-controller',
      recordedAt: Math.max(treatment.completedAt, control.completedAt) + 1,
    },
    {
      id: `observation/${scenario.prefix}/${localId}`,
      contextFeatures,
      featureSchemaDigest: scenario.featureSchemaDigest,
      featureObservedAt: 0,
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

export function createValidatedApplicability(prefix) {
  const scenario = new LearningScenario(prefix);
  const discovery = [
    observation(scenario, 'discovery/pos-1', 'success', 'failure', 'discovery/next/a', positiveFeatures('a')),
    observation(scenario, 'discovery/pos-2', 'success', 'failure', 'discovery/next/b', positiveFeatures('b')),
    observation(scenario, 'discovery/pos-3', 'success', 'failure', 'discovery/next/c', positiveFeatures('c')),
    observation(scenario, 'discovery/neg-1', 'failure', 'success', 'discovery/python/a', negativeFeatures('fastapi', 'd')),
    observation(scenario, 'discovery/neg-2', 'failure', 'success', 'discovery/python/b', negativeFeatures('flask', 'e')),
  ];
  const candidate = induceApplicabilityHypothesis(discovery, {
    id: `hypothesis/${prefix}`,
    scope: scenario.scope,
    memoryId: 'memory/target',
    discoveryObservationIds: discovery.map((item) => item.id),
    actor: 'hypothesis-controller',
    recordedAt: scenario.time + 1,
  });
  const validation = [
    observation(scenario, 'validation/pos-1', 'success', 'failure', 'validation/next/a', positiveFeatures('f')),
    observation(scenario, 'validation/pos-2', 'success', 'failure', 'validation/next/b', positiveFeatures('g')),
    observation(scenario, 'validation/pos-3', 'success', 'failure', 'validation/next/c', positiveFeatures('h')),
    observation(scenario, 'validation/pos-4', 'success', 'failure', 'validation/next/d', positiveFeatures('i')),
    observation(scenario, 'validation/neg-1', 'failure', 'success', 'validation/python/a', negativeFeatures('django', 'j')),
    observation(scenario, 'validation/neg-2', 'failure', 'success', 'validation/python/b', negativeFeatures('flask', 'k')),
  ];
  const applicability = validateApplicabilityHypothesis(candidate, validation, {
    id: `validation/${prefix}`,
    candidateId: candidate.id,
    validationObservationIds: validation.map((item) => item.id),
    actor: 'validation-controller',
    recordedAt: scenario.time + 1,
  });
  if (applicability.status !== 'validated') {
    throw new Error(`fixture applicability did not validate: ${applicability.status}`);
  }
  scenario.time = Math.max(scenario.time, applicability.recordedAt + 1);
  return { scenario, candidate, applicability, discovery, validation };
}
