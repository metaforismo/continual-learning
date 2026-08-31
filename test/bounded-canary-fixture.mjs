import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  MemoryKernel,
  createBoundedCanaryPlan,
  createVerifiedProcedureCandidate,
  evidenceRefFor,
  fingerprintMemoryEvents,
  induceApplicabilityHypothesis,
  isIssuedBoundedCanaryPlan,
  isIssuedCanaryPlanReview,
  recordExperienceTrace,
  reviewBoundedCanaryPlan,
  validateApplicabilityHypothesis,
  verifyApplicabilityObservation,
} from '../dist/index.js';

function sha(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

const scope = 'project/bounded-canary';
const featureSchemaDigest = sha('bounded-canary-context-schema/v1');
const traceRuntime = Object.freeze({
  modelDigest: sha('model/v1'),
  toolDigest: sha('tools/v1'),
  harnessDigest: sha('trace-harness/v1'),
  verifierDigest: sha('trace-verifier/v1'),
});

function evidence(id, sourceGroup, observedAt, overrides = {}) {
  const preview = overrides.preview ?? `evidence ${id}`;
  return {
    id,
    scope: overrides.scope ?? scope,
    kind: overrides.kind ?? 'test-result',
    sourceGroups: [sourceGroup],
    authority: overrides.authority ?? 'tool-verified',
    observedAt,
    sensitivity: overrides.sensitivity ?? 'internal',
    taints: overrides.taints ?? [],
    artifact: {
      uri: `memory://artifact/${id}`,
      digest: sha(`artifact/${id}`),
      sizeBytes: preview.length,
      mediaType: 'application/json',
      encryption: overrides.encryption ?? 'none',
      retention: 'durable',
    },
    ...(overrides.preview === null ? {} : { preview }),
    derivedFrom: [],
    labels: ['bounded-canary'],
  };
}

class Scenario {
  constructor(prefix) {
    this.prefix = prefix;
    this.kernel = new MemoryKernel();
    this.time = 1;
    this.memoryEvidence = evidence(
      `${prefix}/memory`,
      `${prefix}/memory-origin`,
      this.time,
      { kind: 'human-feedback', authority: 'human-explicit' },
    );
    this.kernel.captureEvidence(
      { eventId: `${prefix}/event-memory`, recordedAt: this.time, actor: 'human' },
      this.memoryEvidence,
    );
    this.time += 1;
  }

  capture(id, sourceGroup, overrides = {}) {
    const record = evidence(`${this.prefix}/${id}`, `${this.prefix}/${sourceGroup}`, this.time, overrides);
    this.kernel.captureEvidence(
      {
        eventId: `${this.prefix}/event-${id}`,
        recordedAt: this.time,
        actor: 'evidence-recorder',
      },
      record,
    );
    this.time += 1;
    return record;
  }

  addRun(pairId, arm, outcome, contextFingerprint, sourceGroup) {
    const resultTime = this.time;
    const result = evidence(
      `${this.prefix}/result/${pairId}/${arm}/${resultTime}`,
      `${this.prefix}/${sourceGroup}`,
      resultTime,
    );
    this.kernel.captureEvidence(
      {
        eventId: `${this.prefix}/event-result/${pairId}/${arm}/${resultTime}`,
        recordedAt: resultTime,
        actor: 'test-runner',
      },
      result,
    );
    const outcomeEventId = `${this.prefix}/outcome/${pairId}/${arm}/${resultTime + 1}`;
    this.kernel.recordOutcome(
      { eventId: outcomeEventId, recordedAt: resultTime + 1, actor: 'test-runner' },
      {
        scope,
        subjectId: `${this.prefix}/run/${pairId}/${arm}`,
        taskId: `${this.prefix}/task/${pairId}`,
        contextFingerprint,
        sourceGroups: [`${this.prefix}/${sourceGroup}`],
        outcome,
        verifier: 'test',
        evidence: [evidenceRefFor(result, ['verifies'])],
      },
    );
    this.time += 2;
    return {
      pairId,
      arm,
      runId: `${this.prefix}/run/${pairId}/${arm}`,
      taskId: `${this.prefix}/task/${pairId}`,
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

function experimentalUnit(prefix, id, context) {
  return {
    taskFamily: 'repair-authentication',
    instanceDigest: sha(`${prefix}/instance/${id}`),
    environmentDigest: sha(`${prefix}/environment/${context}`),
    seed: `${prefix}/seed/${id}`,
  };
}

function appliedUse(scenario, memoryId = 'memory/target', kind = 'procedure') {
  return {
    memoryId,
    kind,
    stages: ['activated', 'materialized', 'consulted', 'applied'],
    evidence: [evidenceRefFor(scenario.memoryEvidence, ['supports'])],
  };
}

function traceInput(scenario, run, sharedUnit, includeTarget) {
  return {
    id: `${scenario.prefix}/trace/${run.pairId}/${run.arm}`,
    scope,
    runId: run.runId,
    taskId: run.taskId,
    contextFingerprint: run.contextFingerprint,
    goalSignature: 'repair authentication behavior',
    unit: sharedUnit,
    runtime: traceRuntime,
    startedAt: run.startedAt,
    completedAt: run.completedAt,
    captureMode: 'runtime-instrumented',
    recorder: 'instrumented-runtime',
    canonicalFingerprint: fingerprintMemoryEvents(scenario.events()),
    outcomeEventId: run.outcomeEventId,
    memoryUses: [
      ...(includeTarget ? [appliedUse(scenario)] : []),
      appliedUse(scenario, 'memory/baseline', 'constraint'),
    ],
  };
}

function observation(scenario, id, treatmentOutcome, controlOutcome, contextFeatures) {
  const contextFingerprint = `${scenario.prefix}/context/${id}`;
  const sourceGroup = `experiment/${id}`;
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
  const sharedUnit = experimentalUnit(scenario.prefix, id, contextFingerprint);
  const treatment = recordExperienceTrace(
    scenario.events(),
    traceInput(scenario, treatmentRun, sharedUnit, true),
  );
  const control = recordExperienceTrace(
    scenario.events(),
    traceInput(scenario, controlRun, sharedUnit, false),
  );
  return verifyApplicabilityObservation(
    [treatment, control],
    {
      id: `${scenario.prefix}/comparison/${id}`,
      memoryId: 'memory/target',
      treatmentTraceId: treatment.id,
      controlTraceId: control.id,
      intervention: 'withheld',
      actor: 'experiment-controller',
      recordedAt: Math.max(treatment.completedAt, control.completedAt) + 1,
    },
    {
      id: `${scenario.prefix}/observation/${id}`,
      contextFeatures,
      featureSchemaDigest,
      featureObservedAt: 0,
      recorder: 'context-instrumentation',
    },
  );
}

function positive(repo) {
  return ['framework:nextjs', 'runtime:node', 'symptom:race', `repo:${repo}`];
}

function negative(repo) {
  return ['framework:flask', 'runtime:python', 'symptom:race', `repo:${repo}`];
}

function validatedApplicability(scenario) {
  const discovery = [
    observation(scenario, 'discovery-pos-1', 'success', 'failure', positive('a')),
    observation(scenario, 'discovery-pos-2', 'success', 'failure', positive('b')),
    observation(scenario, 'discovery-pos-3', 'success', 'failure', positive('c')),
    observation(scenario, 'discovery-neg-1', 'failure', 'success', negative('d')),
    observation(scenario, 'discovery-neg-2', 'failure', 'success', negative('e')),
  ];
  const candidate = induceApplicabilityHypothesis(discovery, {
    id: `${scenario.prefix}/hypothesis`,
    scope,
    memoryId: 'memory/target',
    discoveryObservationIds: discovery.map((item) => item.id),
    actor: 'hypothesis-controller',
    recordedAt: scenario.time + 1,
  });
  const validation = [
    observation(scenario, 'validation-pos-1', 'success', 'failure', positive('f')),
    observation(scenario, 'validation-pos-2', 'success', 'failure', positive('g')),
    observation(scenario, 'validation-pos-3', 'success', 'failure', positive('h')),
    observation(scenario, 'validation-pos-4', 'success', 'failure', positive('i')),
    observation(scenario, 'validation-neg-1', 'failure', 'success', negative('j')),
    observation(scenario, 'validation-neg-2', 'failure', 'success', negative('k')),
  ];
  const result = validateApplicabilityHypothesis(candidate, validation, {
    id: `${scenario.prefix}/validation`,
    candidateId: candidate.id,
    validationObservationIds: validation.map((item) => item.id),
    actor: 'validation-controller',
    recordedAt: scenario.time + 1,
  });
  assert.equal(result.status, 'validated');
  return result;
}

function procedureEvidence(scenario, options = {}) {
  return {
    goal: scenario.capture('procedure-goal', 'procedure-goal-origin', {
      kind: 'document',
      authority: options.human ? 'human-explicit' : 'external-source',
    }),
    inspect: scenario.capture('procedure-inspect', 'procedure-inspect-origin', {
      kind: 'document',
      authority: options.human ? 'human-explicit' : 'external-source',
    }),
    mutate: scenario.capture('procedure-mutate', 'procedure-mutate-origin', {
      kind: 'document',
      authority: options.human ? 'human-explicit' : 'external-source',
    }),
    verify: scenario.capture('procedure-verify', 'procedure-verify-origin', {
      kind: 'test-result',
      authority: options.human ? 'human-explicit' : 'tool-verified',
    }),
    rollback: scenario.capture('procedure-rollback', 'procedure-rollback-origin', {
      kind: 'document',
      authority: options.human ? 'human-explicit' : 'external-source',
    }),
    dependency: scenario.capture('procedure-dependency', 'procedure-dependency-origin', {
      kind: 'tool-result',
      authority: options.human ? 'human-explicit' : 'tool-verified',
    }),
    verifier: scenario.capture('procedure-verifier', 'procedure-verifier-origin', {
      kind: 'test-result',
      authority: options.human ? 'human-explicit' : 'tool-verified',
    }),
    checkpoint: scenario.capture('procedure-checkpoint', 'procedure-checkpoint-origin', {
      kind: 'environment-transition',
      authority: options.human ? 'human-explicit' : 'tool-verified',
    }),
  };
}

function procedureInput(scenario, refs, options = {}) {
  const mutative = options.mutative ?? false;
  const risk = options.risk ?? (mutative ? 'medium' : 'low');
  const human = risk === 'high' || risk === 'destructive';
  const steps = [
    {
      id: 'inspect',
      kind: 'inspect',
      instruction: 'Inspect the bounded authentication state.',
      expectedOutcome: 'The exact failing state is identified.',
      evidence: [evidenceRefFor(refs.inspect, ['supports'])],
    },
    ...(mutative
      ? [
          {
            id: 'mutate',
            kind: 'mutate',
            instruction: 'Apply the bounded authentication repair.',
            expectedOutcome: 'Only the targeted state is changed.',
            dependsOn: ['inspect'],
            evidence: [evidenceRefFor(refs.mutate, ['supports'])],
          },
        ]
      : []),
    {
      id: 'verify',
      kind: 'verify',
      instruction: 'Run the bounded authentication verification.',
      expectedOutcome: 'All exact verification criteria pass.',
      dependsOn: mutative ? ['mutate'] : ['inspect'],
      evidence: [evidenceRefFor(refs.verify, ['verifies'])],
    },
  ];
  return {
    id: `${scenario.prefix}/procedure-candidate`,
    procedureId: `${scenario.prefix}/repair-auth`,
    version: '1.0.0',
    name: 'Repair authentication race',
    goalSignature: 'repair authentication race without broadening scope',
    goalEvidence: [evidenceRefFor(refs.goal, ['supports'])],
    rationale: 'Held-out evidence supports one bounded procedure candidate.',
    steps,
    dependencies: [
      {
        id: 'auth-test-harness',
        kind: 'tool',
        versionDigest: refs.dependency.artifact.digest,
        evidence: [evidenceRefFor(refs.dependency, ['verifies'])],
      },
    ],
    risk,
    verification: {
      verificationStepId: 'verify',
      verifier: human ? 'human' : 'test',
      verifierDigest: refs.verifier.artifact.digest,
      evidence: [evidenceRefFor(refs.verifier, ['verifies'])],
      successCriteria: ['all bounded authentication tests pass'],
      failureCriteria: ['any bounded authentication test fails'],
      timeoutMs: 30_000,
      maxAttempts: human ? 1 : 2,
      onFailure: human ? 'human-review' : 'quarantine',
    },
    rollback: human
      ? {
          strategy: 'manual',
          instructions: 'Restore the reviewed prior state under human control.',
          evidence: [evidenceRefFor(refs.rollback, ['supports'])],
        }
      : mutative
        ? {
            strategy: 'restore-checkpoint',
            instructions: 'Restore the exact pre-canary checkpoint.',
            evidence: [evidenceRefFor(refs.checkpoint, ['verifies'])],
            checkpointDigest: refs.checkpoint.artifact.digest,
          }
        : {
            strategy: 'disable-candidate',
            instructions: 'Disable the candidate and preserve the prior state.',
            evidence: [evidenceRefFor(refs.rollback, ['supports'])],
          },
    canonicalFingerprint: fingerprintMemoryEvents(scenario.events()),
    actor: 'procedure-controller',
    recordedAt: scenario.time + 1,
  };
}

function setup(prefix, options = {}) {
  const scenario = new Scenario(prefix);
  const applicability = validatedApplicability(scenario);
  const human = options.risk === 'high' || options.risk === 'destructive';
  const refs = procedureEvidence(scenario, { human });
  const candidate = createVerifiedProcedureCandidate(
    scenario.events(),
    applicability,
    procedureInput(scenario, refs, options),
  );
  const planEvidence = {
    runtime: {
      scheduler: scenario.capture('canary-runtime-scheduler', 'canary-runtime-scheduler-origin', { kind: 'tool-result', authority: 'tool-verified' }),
      harness: scenario.capture('canary-runtime-harness', 'canary-runtime-harness-origin', { kind: 'tool-result', authority: 'tool-verified' }),
      observer: scenario.capture('canary-runtime-observer', 'canary-runtime-observer-origin', { kind: 'tool-result', authority: 'tool-verified' }),
      verifier: scenario.capture('canary-runtime-verifier', 'canary-runtime-verifier-origin', { kind: 'test-result', authority: 'tool-verified' }),
      rollbackController: scenario.capture('canary-runtime-rollback', 'canary-runtime-rollback-origin', { kind: 'tool-result', authority: 'tool-verified' }),
      environment: scenario.capture('canary-runtime-environment', 'canary-runtime-environment-origin', { kind: 'environment-transition', authority: 'tool-verified' }),
    },
    quality: scenario.capture('canary-quality', 'canary-quality-origin', {
      kind: 'document',
      authority: 'external-source',
    }),
    cost: scenario.capture('canary-cost', 'canary-cost-origin', {
      kind: 'document',
      authority: 'external-source',
    }),
    safety: scenario.capture('canary-safety', 'canary-safety-origin', {
      kind: 'document',
      authority: 'external-source',
    }),
    security: scenario.capture('canary-security', 'canary-security-origin', {
      kind: 'document',
      authority: 'external-source',
    }),
    abort: scenario.capture('canary-abort', 'canary-abort-origin', {
      kind: 'document',
      authority: 'external-source',
    }),
  };
  return { scenario, candidate, planEvidence };
}

function population(prefix, options = {}) {
  const repos = options.repos ?? ['one', 'two', 'three', 'four'];
  const subjects = repos.map((repo, index) => ({
    subjectDigest: sha(`${prefix}/subject/${index}`),
    experimentalUnitDigest: sha(`${prefix}/unit/${index}`),
    contextFeatures: positive(repo),
  }));
  if (options.includeExcluded) {
    subjects.push({
      subjectDigest: sha(`${prefix}/subject/excluded`),
      experimentalUnitDigest: sha(`${prefix}/unit/excluded`),
      contextFeatures: negative('excluded'),
    });
  }
  return {
    id: `${prefix}/population`,
    featureSchemaDigest,
    subjects,
  };
}

function stopConditions(refs, options = {}) {
  const conditions = [
    {
      id: 'quality-stop',
      category: 'quality',
      metric: 'verified_failure_rate',
      comparator: 'gte',
      threshold: 0.25,
      observationWindowRuns: 2,
      action: 'abort',
      evidence: [evidenceRefFor(refs.quality, ['constrains'])],
    },
    {
      id: 'cost-stop',
      category: 'cost',
      metric: 'cost_micros',
      comparator: 'gte',
      threshold: 1_000_000,
      observationWindowRuns: 1,
      action: 'pause',
      evidence: [evidenceRefFor(refs.cost, ['constrains'])],
    },
  ];
  if (options.mutative) {
    conditions.push(
      {
        id: 'safety-stop',
        category: 'safety',
        metric: 'safety_violation_count',
        comparator: 'gte',
        threshold: 1,
        observationWindowRuns: 1,
        action: 'rollback',
        evidence: [evidenceRefFor(refs.safety, ['constrains'])],
      },
      {
        id: 'security-stop',
        category: 'security',
        metric: 'security_violation_count',
        comparator: 'gte',
        threshold: 1,
        observationWindowRuns: 1,
        action: 'rollback',
        evidence: [evidenceRefFor(refs.security, ['constrains'])],
      },
    );
  }
  return conditions;
}

function planInput(scenario, candidate, refs, options = {}) {
  const manifest = options.population ?? population(scenario.prefix, options);
  const eligible = manifest.subjects.filter((subject) => subject.contextFeatures.includes('runtime:node')).length;
  const highRisk = candidate.risk === 'high';
  return {
    id: options.id ?? `${scenario.prefix}/canary-plan`,
    candidateDigest: candidate.candidateDigest,
    assignmentSeedDigest: sha(`${scenario.prefix}/assignment-seed/v1`),
    population: manifest,
    budget: options.budget ?? {
      maxSubjects: eligible,
      maxRuns: eligible,
      maxConcurrentRuns: highRisk ? 1 : 2,
      maxDurationMs: highRisk ? 3_600_000 : 7_200_000,
      maxToolCalls: eligible * 10,
      maxCostMicros: 2_000_000,
      maxRetriesPerSubject: 0,
    },
    runtime: {
      schedulerDigest: refs.runtime.scheduler.artifact.digest,
      harnessDigest: refs.runtime.harness.artifact.digest,
      observerDigest: refs.runtime.observer.artifact.digest,
      verifierDigest: refs.runtime.verifier.artifact.digest,
      rollbackControllerDigest: refs.runtime.rollbackController.artifact.digest,
      environmentDigest: refs.runtime.environment.artifact.digest,
      evidence: [
        evidenceRefFor(refs.runtime.scheduler, ['verifies']),
        evidenceRefFor(refs.runtime.harness, ['verifies']),
        evidenceRefFor(refs.runtime.observer, ['verifies']),
        evidenceRefFor(refs.runtime.verifier, ['verifies']),
        evidenceRefFor(refs.runtime.rollbackController, ['verifies']),
        evidenceRefFor(refs.runtime.environment, ['verifies']),
      ],
    },
    stopConditions: options.stopConditions ?? stopConditions(refs, options),
    abort: {
      instructions: 'Stop new assignments, preserve receipts, and invoke the inherited rollback when required.',
      evidence: [evidenceRefFor(refs.abort, ['constrains'])],
    },
    canonicalFingerprint: fingerprintMemoryEvents(scenario.events()),
    actor: 'canary-plan-controller',
    recordedAt: scenario.time + 1,
  };
}




function buildCanaryFixture(prefix, options = {}) {
  const base = setup(prefix, options);
  const scenario = base.scenario;
  const fixture = {
    prefix: scenario.prefix,
    kernel: scenario.kernel,
    events: () => scenario.events(),
    get time() {
      return scenario.time;
    },
    set time(value) {
      scenario.time = value;
    },
    capture(id, overrides = {}) {
      const sourceGroupInput = overrides.sourceGroup ?? `receipt-source/${id}`;
      const sourceGroup = sourceGroupInput.startsWith(`${scenario.prefix}/`)
        ? sourceGroupInput
        : `${scenario.prefix}/${sourceGroupInput}`;
      const record = evidence(
        `${scenario.prefix}/${id}`,
        sourceGroup,
        scenario.time,
        {
          scope: overrides.scope,
          kind: overrides.kind,
          authority: overrides.authority,
          sensitivity: overrides.sensitivity,
          taints: overrides.taints,
          preview: overrides.preview,
          encryption: overrides.encryption,
        },
      );
      if (overrides.digest !== undefined) {
        record.artifact = { ...record.artifact, digest: overrides.digest };
      }
      scenario.kernel.captureEvidence(
        {
          eventId: `${scenario.prefix}/event-receipt/${id}/${scenario.time}`,
          recordedAt: scenario.time,
          actor: 'receipt-evidence-recorder',
        },
        record,
      );
      scenario.time += 1;
      return record;
    },
    restrict(record) {
      scenario.kernel.setEvidenceAvailability(
        {
          eventId: `${scenario.prefix}/event-restrict/${record.id}/${scenario.time}`,
          recordedAt: scenario.time,
          actor: 'privacy-controller',
        },
        record.id,
        'restricted',
        'receipt evidence no longer authorized',
      );
      scenario.time += 1;
    },
  };
  return {
    fixture,
    scenario,
    candidate: base.candidate,
    planEvidence: base.planEvidence,
    scheduler: { record: base.planEvidence.runtime.scheduler },
    harness: { record: base.planEvidence.runtime.harness },
    observer: { record: base.planEvidence.runtime.observer },
    verifier: { record: base.planEvidence.runtime.verifier },
    rollbackController: { record: base.planEvidence.runtime.rollbackController },
  };
}

function issuePlan(bundle, budgetOverrides = {}) {
  const input = planInput(
    bundle.scenario,
    bundle.candidate,
    bundle.planEvidence,
  );
  input.budget = {
    ...input.budget,
    maxToolCalls: 8,
    maxCostMicros: 100_000,
    ...budgetOverrides,
  };
  input.stopConditions = input.stopConditions.map((condition) =>
    condition.category === 'quality'
      ? {
          ...condition,
          id: 'quality-regression',
          metric: 'quality.failure_rate',
          action: 'rollback',
        }
      : condition,
  );
  return createBoundedCanaryPlan(
    bundle.fixture.events(),
    bundle.candidate,
    input,
  );
}

function reviewInput(bundle, plan, suffix = 'review', overrides = {}) {
  const rawDecision = overrides.decision ?? 'approve';
  const decision =
    rawDecision === 'changes-required'
      ? 'request-changes'
      : rawDecision === 'rejected'
        ? 'reject'
        : rawDecision;
  const evidenceRecord = bundle.fixture.capture(`review/${suffix}`, {
    kind: 'human-feedback',
    authority: 'human-explicit',
    sourceGroup: `independent-review/${suffix}`,
  });
  return {
    id: `${bundle.fixture.prefix}/review/${suffix}`,
    planId: plan.id,
    decision,
    findings: overrides.findings ?? [],
    evidence: [evidenceRefFor(evidenceRecord, ['verifies'])],
    canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
    reviewer: overrides.reviewer ?? `${bundle.fixture.prefix}/independent-reviewer/${suffix}`,
    recordedAt: bundle.fixture.time + 1,
  };
}

export {
  buildCanaryFixture,
  issuePlan,
  reviewInput,
  sha,
};
