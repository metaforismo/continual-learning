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
  };
}

function procedureInput(scenario, refs, options = {}) {
  const mutative = options.mutative ?? false;
  const risk = options.risk ?? 'low';
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
        versionDigest: sha(`${scenario.prefix}/auth-test-harness/v1`),
      },
    ],
    risk,
    verification: {
      verificationStepId: 'verify',
      verifier: human ? 'human' : 'test',
      verifierDigest: sha(`${scenario.prefix}/procedure-verifier/v1`),
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
    runtime: scenario.capture('canary-runtime', 'canary-runtime-origin', {
      kind: 'test-result',
      authority: 'tool-verified',
    }),
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
      schedulerDigest: sha(`${scenario.prefix}/scheduler/v1`),
      harnessDigest: sha(`${scenario.prefix}/canary-harness/v1`),
      observerDigest: sha(`${scenario.prefix}/observer/v1`),
      verifierDigest: sha(`${scenario.prefix}/canary-verifier/v1`),
      rollbackControllerDigest: sha(`${scenario.prefix}/rollback-controller/v1`),
      environmentDigest: sha(`${scenario.prefix}/environment/v1`),
      evidence: [evidenceRefFor(refs.runtime, ['verifies'])],
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

test('a bounded plan deterministically creates non-empty treatment and control arms', () => {
  const { scenario, candidate, planEvidence } = setup('basic');
  const input = planInput(scenario, candidate, planEvidence, { includeExcluded: true });
  const plan = createBoundedCanaryPlan(scenario.events(), candidate, input);
  assert.equal(plan.status, 'plan');
  assert.equal(plan.population.eligibleCount, 4);
  assert.equal(plan.population.treatmentCount, 2);
  assert.equal(plan.population.controlCount, 2);
  assert.equal(plan.population.excludedCount, 1);
  assert.equal(plan.executable, false);
  assert.equal(plan.hostSchedulingAuthorized, false);
  assert.equal(plan.procedurePromotionAuthorized, false);
  assert.equal(plan.executionAuthorized, false);
  assert.equal(plan.candidateDigest, candidate.candidateDigest);
  assert.equal(isIssuedBoundedCanaryPlan(plan), true);
});

test('population and request ordering do not change the exact issued plan', () => {
  const { scenario, candidate, planEvidence } = setup('ordering');
  const input = planInput(scenario, candidate, planEvidence, { includeExcluded: true });
  const forward = createBoundedCanaryPlan(scenario.events(), candidate, input);
  const reversed = createBoundedCanaryPlan(scenario.events(), candidate, {
    ...structuredClone(input),
    population: {
      ...structuredClone(input.population),
      subjects: [...input.population.subjects].reverse(),
    },
    stopConditions: [...input.stopConditions].reverse(),
  });
  assert.equal(reversed, forward);
  assert.deepEqual(reversed, forward);
});

test('cloned procedure and plan capabilities fail closed', () => {
  const { scenario, candidate, planEvidence } = setup('capabilities');
  const input = planInput(scenario, candidate, planEvidence);
  assert.throws(
    () => createBoundedCanaryPlan(scenario.events(), structuredClone(candidate), input),
    /issued verified procedure candidate/,
  );
  const plan = createBoundedCanaryPlan(scenario.events(), candidate, input);
  const reviewEvidence = scenario.capture('review-evidence', 'independent-review-origin', {
    kind: 'human-feedback',
    authority: 'human-explicit',
  });
  assert.throws(
    () =>
      reviewBoundedCanaryPlan(scenario.events(), structuredClone(plan), {
        id: 'capabilities/review',
        planId: plan.id,
        decision: 'approve',
        findings: [],
        evidence: [evidenceRefFor(reviewEvidence, ['verifies'])],
        canonicalFingerprint: fingerprintMemoryEvents(scenario.events()),
        reviewer: 'independent-reviewer',
        recordedAt: scenario.time + 1,
      }),
    /issued guarded plan capability/,
  );
});

test('population manifests reject raw identity fields, duplicates, and too few applicable subjects', () => {
  const { scenario, candidate, planEvidence } = setup('population-guards');
  const rawIdentity = population('population-guards');
  rawIdentity.subjects[0] = { ...rawIdentity.subjects[0], rawSubjectId: 'person@example.com' };
  assert.throws(
    () =>
      createBoundedCanaryPlan(
        scenario.events(),
        candidate,
        planInput(scenario, candidate, planEvidence, { population: rawIdentity }),
      ),
    /unexpected or missing field/,
  );

  const duplicate = population('population-guards/duplicate');
  duplicate.subjects[1] = {
    ...duplicate.subjects[1],
    experimentalUnitDigest: duplicate.subjects[0].experimentalUnitDigest,
  };
  assert.throws(
    () =>
      createBoundedCanaryPlan(
        scenario.events(),
        candidate,
        planInput(scenario, candidate, planEvidence, { population: duplicate }),
      ),
    /experimental units must be unique/,
  );

  const tiny = population('population-guards/tiny', { repos: ['one', 'two', 'three'] });
  assert.throws(
    () =>
      createBoundedCanaryPlan(
        scenario.events(),
        candidate,
        planInput(scenario, candidate, planEvidence, { population: tiny }),
      ),
    /at least 4 applicable subjects/,
  );
});

test('budgets are coherent and high-risk canaries are strictly smaller', () => {
  const regular = setup('budget-regular');
  assert.throws(
    () =>
      createBoundedCanaryPlan(
        regular.scenario.events(),
        regular.candidate,
        planInput(regular.scenario, regular.candidate, regular.planEvidence, {
          budget: {
            maxSubjects: 4,
            maxRuns: 3,
            maxConcurrentRuns: 2,
            maxDurationMs: 1_000,
            maxToolCalls: 10,
            maxCostMicros: 10,
            maxRetriesPerSubject: 0,
          },
        }),
      ),
    /maxRuns is incoherent/,
  );

  const high = setup('budget-high', { risk: 'high' });
  assert.throws(
    () =>
      createBoundedCanaryPlan(
        high.scenario.events(),
        high.candidate,
        planInput(high.scenario, high.candidate, high.planEvidence, {
          budget: {
            maxSubjects: 4,
            maxRuns: 4,
            maxConcurrentRuns: 2,
            maxDurationMs: 3_600_000,
            maxToolCalls: 40,
            maxCostMicros: 2_000_000,
            maxRetriesPerSubject: 0,
          },
        }),
      ),
    /high-risk canaries require/,
  );

  const destructive = setup('budget-destructive', { risk: 'destructive' });
  assert.throws(
    () =>
      createBoundedCanaryPlan(
        destructive.scenario.events(),
        destructive.candidate,
        planInput(destructive.scenario, destructive.candidate, destructive.planEvidence),
      ),
    /destructive procedure candidates are not eligible/,
  );
});

test('mutative canaries require safety and security rollback conditions', () => {
  const { scenario, candidate, planEvidence } = setup('mutative', { mutative: true });
  assert.throws(
    () =>
      createBoundedCanaryPlan(
        scenario.events(),
        candidate,
        planInput(scenario, candidate, planEvidence),
      ),
    /mutative canaries require safety and security/,
  );
  const plan = createBoundedCanaryPlan(
    scenario.events(),
    candidate,
    planInput(scenario, candidate, planEvidence, {
      mutative: true,
      stopConditions: stopConditions(planEvidence, { mutative: true }),
    }),
  );
  assert.ok(plan.stopConditions.some((condition) => condition.category === 'safety'));
  assert.ok(plan.stopConditions.some((condition) => condition.category === 'security'));
  assert.ok(plan.stopConditions.some((condition) => condition.action === 'rollback'));
});

test('stale history, restricted evidence, and secret evidence fail closed', () => {
  const stale = setup('stale-plan');
  const staleInput = planInput(stale.scenario, stale.candidate, stale.planEvidence);
  stale.scenario.capture('later-event', 'later-origin', { authority: 'external-source' });
  assert.throws(
    () => createBoundedCanaryPlan(stale.scenario.events(), stale.candidate, staleInput),
    /canonical fingerprint is stale or forged/,
  );

  const restricted = setup('restricted-plan');
  const recordedAt = restricted.scenario.time + 1;
  restricted.scenario.kernel.setEvidenceAvailability(
    {
      eventId: 'restricted-plan/restrict-runtime',
      recordedAt: restricted.scenario.time + 2,
      actor: 'privacy-controller',
    },
    restricted.planEvidence.runtime.id,
    'restricted',
    'runtime evidence is no longer authorized',
  );
  const restrictedInput = planInput(
    restricted.scenario,
    restricted.candidate,
    restricted.planEvidence,
  );
  assert.throws(
    () =>
      createBoundedCanaryPlan(restricted.scenario.events(), restricted.candidate, {
        ...restrictedInput,
        recordedAt,
        canonicalFingerprint: fingerprintMemoryEvents(restricted.scenario.events()),
      }),
    /not currently available/,
  );

  const secret = setup('secret-plan');
  const secretRuntime = secret.scenario.capture('secret-runtime', 'secret-runtime-origin', {
    authority: 'human-explicit',
    sensitivity: 'secret',
    taints: ['secret-detected'],
    encryption: 'provider-managed',
    preview: null,
  });
  const secretInput = planInput(secret.scenario, secret.candidate, secret.planEvidence);
  assert.throws(
    () =>
      createBoundedCanaryPlan(secret.scenario.events(), secret.candidate, {
        ...secretInput,
        runtime: {
          ...secretInput.runtime,
          evidence: [evidenceRefFor(secretRuntime, ['verifies'])],
        },
        canonicalFingerprint: fingerprintMemoryEvents(secret.scenario.events()),
        recordedAt: secret.scenario.time + 1,
      }),
    /secret evidence/,
  );
});

test('independent review is advisory and cannot reuse plan source families', () => {
  const { scenario, candidate, planEvidence } = setup('review');
  const plan = createBoundedCanaryPlan(
    scenario.events(),
    candidate,
    planInput(scenario, candidate, planEvidence),
  );
  assert.throws(
    () =>
      reviewBoundedCanaryPlan(scenario.events(), plan, {
        id: 'review/same-author',
        planId: plan.id,
        decision: 'approve',
        findings: [],
        evidence: [evidenceRefFor(planEvidence.runtime, ['verifies'])],
        canonicalFingerprint: fingerprintMemoryEvents(scenario.events()),
        reviewer: plan.actor,
        recordedAt: scenario.time + 1,
      }),
    /reviewer must be independent/,
  );

  assert.throws(
    () =>
      reviewBoundedCanaryPlan(scenario.events(), plan, {
        id: 'review/reused-source',
        planId: plan.id,
        decision: 'approve',
        findings: [],
        evidence: [evidenceRefFor(planEvidence.runtime, ['verifies'])],
        canonicalFingerprint: fingerprintMemoryEvents(scenario.events()),
        reviewer: 'independent-reviewer',
        recordedAt: scenario.time + 1,
      }),
    /reuses a source family/,
  );

  const independent = scenario.capture('independent-review', 'independent-review-origin', {
    kind: 'human-feedback',
    authority: 'human-explicit',
  });
  const review = reviewBoundedCanaryPlan(scenario.events(), plan, {
    id: 'review/approved',
    planId: plan.id,
    decision: 'approve',
    findings: [],
    evidence: [evidenceRefFor(independent, ['verifies'])],
    canonicalFingerprint: fingerprintMemoryEvents(scenario.events()),
    reviewer: 'independent-reviewer',
    recordedAt: scenario.time + 1,
  });
  assert.equal(review.recommendation, 'ready-for-host-scheduling');
  assert.equal(review.executable, false);
  assert.equal(review.hostSchedulingAuthorized, false);
  assert.equal(review.procedurePromotionAuthorized, false);
  assert.equal(review.executionAuthorized, false);
  assert.equal(isIssuedCanaryPlanReview(review), true);
});

test('candidate/population conflicts do not poison a fresh plan id', () => {
  const { scenario, candidate, planEvidence } = setup('plan-registry');
  const firstInput = planInput(scenario, candidate, planEvidence, {
    id: 'plan-registry/plan-a',
  });
  const first = createBoundedCanaryPlan(scenario.events(), candidate, firstInput);
  assert.equal(isIssuedBoundedCanaryPlan(first), true);

  assert.throws(
    () =>
      createBoundedCanaryPlan(scenario.events(), candidate, {
        ...structuredClone(firstInput),
        id: 'plan-registry/plan-b',
        abort: {
          ...structuredClone(firstInput.abort),
          instructions: 'Conflicting instructions for the same candidate and population.',
        },
      }),
    /candidate\/population identity conflicts/,
  );

  const secondPopulation = population('plan-registry/second');
  const recovered = createBoundedCanaryPlan(
    scenario.events(),
    candidate,
    planInput(scenario, candidate, planEvidence, {
      id: 'plan-registry/plan-b',
      population: secondPopulation,
    }),
  );
  assert.equal(recovered.id, 'plan-registry/plan-b');
  assert.equal(isIssuedBoundedCanaryPlan(recovered), true);
});

test('sparse, circular, and non-canonical inputs fail before planning', () => {
  const { scenario, candidate, planEvidence } = setup('malformed-plan');
  const input = planInput(scenario, candidate, planEvidence);
  const sparse = Array(4);
  sparse[0] = input.population.subjects[0];
  assert.throws(
    () =>
      createBoundedCanaryPlan(scenario.events(), candidate, {
        ...input,
        population: { ...input.population, subjects: sparse },
      }),
    /sparse array/,
  );
  const circular = { ...input };
  circular.self = circular;
  assert.throws(
    () => createBoundedCanaryPlan(scenario.events(), candidate, circular),
    /circular reference/,
  );
  assert.throws(
    () =>
      createBoundedCanaryPlan(scenario.events(), candidate, {
        ...input,
        budget: { ...input.budget, maxCostMicros: -0 },
      }),
    /canonical number/,
  );
});
