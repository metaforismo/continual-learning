import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  MemoryKernel,
  assessMemoryUtility,
  assertIssuedProcedureCandidate,
  createProcedureCandidate,
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
    scope: 'project/procedure-candidate',
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
    preview: `procedure candidate evidence ${id}`,
    derivedFrom: [],
    labels: ['procedure-candidate'],
    ...overrides,
  };
}

class Scenario {
  constructor(options = {}) {
    this.kernel = new MemoryKernel();
    this.time = 1;
    this.memoryEvidence = evidence('evidence/memory', 'origin/memory', this.time, {
      kind: 'human-feedback',
      authority: 'human-explicit',
      sensitivity: options.memorySensitivity ?? 'public',
      taints: options.memoryTaints ?? [],
      preview: 'memory procedure source',
    });
    this.stepEvidenceA = evidence('evidence/step/a', 'origin/step/a', this.time, {
      kind: 'human-feedback',
      authority: 'human-explicit',
      sensitivity: options.stepSensitivity ?? 'public',
      taints: options.stepTaints ?? [],
      preview: 'wait for durable session readiness before assertions',
    });
    this.stepEvidenceB = evidence('evidence/step/b', 'origin/step/b', this.time, {
      kind: 'test-result',
      authority: 'tool-verified',
      preview: 'test verifies serialized session setup',
    });
    for (const source of [this.memoryEvidence, this.stepEvidenceA, this.stepEvidenceB]) {
      this.kernel.captureEvidence(
        { eventId: `event/${source.id}`, recordedAt: this.time, actor: 'source-ingestor' },
        source,
      );
      this.time += 1;
    }
  }

  addRun(id, outcome, context, features) {
    const treatmentResult = evidence(
      `evidence/result/${id}/treatment`,
      `origin/result/${id}/treatment`,
      this.time,
    );
    this.kernel.captureEvidence(
      { eventId: `event/result/${id}/treatment`, recordedAt: this.time, actor: 'test-runner' },
      treatmentResult,
    );
    this.kernel.recordOutcome(
      { eventId: `event/outcome/${id}/treatment`, recordedAt: this.time + 1, actor: 'verifier' },
      {
        scope: 'project/procedure-candidate',
        subjectId: `run/${id}/treatment`,
        taskId: `task/${id}/treatment`,
        contextFingerprint: context,
        sourceGroups: treatmentResult.sourceGroups,
        outcome,
        verifier: 'test',
        evidence: [evidenceRefFor(treatmentResult, ['verifies'])],
      },
    );
    const controlOutcome = outcome === 'success' ? 'failure' : 'success';
    const controlResult = evidence(
      `evidence/result/${id}/control`,
      `origin/result/${id}/control`,
      this.time + 2,
    );
    this.kernel.captureEvidence(
      { eventId: `event/result/${id}/control`, recordedAt: this.time + 2, actor: 'test-runner' },
      controlResult,
    );
    this.kernel.recordOutcome(
      { eventId: `event/outcome/${id}/control`, recordedAt: this.time + 3, actor: 'verifier' },
      {
        scope: 'project/procedure-candidate',
        subjectId: `run/${id}/control`,
        taskId: `task/${id}/control`,
        contextFingerprint: context,
        sourceGroups: controlResult.sourceGroups,
        outcome: controlOutcome,
        verifier: 'test',
        evidence: [evidenceRefFor(controlResult, ['verifies'])],
      },
    );
    const events = this.kernel.events();
    const sharedUnit = {
      taskFamily: 'debug-authentication',
      instanceDigest: sha(`instance/${id}`),
      environmentDigest: sha(`environment/${context}`),
      seed: `seed/${id}`,
    };
    const trace = (arm, applied, eventId, taskId, startedAt, completedAt) =>
      recordExperienceTrace(events, {
        id: `trace/${id}/${arm}`,
        scope: 'project/procedure-candidate',
        runId: `run/${id}/${arm}`,
        taskId,
        contextFingerprint: context,
        contextFeatures: features,
        goalSignature: 'repair authentication behavior',
        unit: sharedUnit,
        startedAt,
        completedAt,
        captureMode: 'runtime-instrumented',
        recorder: 'instrumented-runtime',
        canonicalFingerprint: fingerprintMemoryEvents(events),
        outcomeEventId: eventId,
        exposures: [
          {
            memoryId: 'memory/target',
            kind: 'procedure',
            stage: applied ? 'applied' : 'activated',
            evidenceSourceIds: [this.memoryEvidence.id],
            roles: ['supports'],
            ...(applied ? {} : { nonUseReason: 'withheld by paired intervention' }),
          },
          {
            memoryId: 'memory/baseline',
            kind: 'constraint',
            stage: 'applied',
            evidenceSourceIds: [this.memoryEvidence.id],
            roles: ['constrains'],
          },
        ],
      });
    const treatmentTrace = trace(
      'treatment',
      true,
      `event/outcome/${id}/treatment`,
      `task/${id}/treatment`,
      this.time - 1,
      this.time,
    );
    const controlTrace = trace(
      'control',
      false,
      `event/outcome/${id}/control`,
      `task/${id}/control`,
      this.time + 1,
      this.time + 2,
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
        recordedAt: this.time + 3,
      },
    );
    this.time += 4;
    return { treatmentTrace, controlTrace, comparison };
  }

  events() {
    return this.kernel.events();
  }
}

function learningEvidence(scenario) {
  const discoveryPositive = scenario.addRun(
    'discovery-positive',
    'success',
    'context/next/discovery',
    ['framework:nextjs', 'runtime:node', 'symptom:race'],
  );
  const discoveryNegative = scenario.addRun(
    'discovery-negative',
    'failure',
    'context/python/discovery',
    ['framework:fastapi', 'runtime:python', 'symptom:race'],
  );
  const validationPositive = scenario.addRun(
    'validation-positive',
    'success',
    'context/next/validation',
    ['framework:nextjs', 'runtime:node', 'symptom:race'],
  );
  const validationNegative = scenario.addRun(
    'validation-negative',
    'failure',
    'context/python/validation',
    ['framework:fastapi', 'runtime:python', 'symptom:race'],
  );
  const traces = [
    discoveryPositive.treatmentTrace,
    discoveryPositive.controlTrace,
    discoveryNegative.treatmentTrace,
    discoveryNegative.controlTrace,
    validationPositive.treatmentTrace,
    validationPositive.controlTrace,
    validationNegative.treatmentTrace,
    validationNegative.controlTrace,
  ];
  const utility = assessMemoryUtility(
    'memory/target',
    traces,
    [discoveryPositive.comparison, validationPositive.comparison],
    {
      minIndependentPairs: 2,
      minDistinctContexts: 1,
      minMeanAbsoluteEffect: 0.2,
      minDirectionalRate: 0.5,
      minDirectionalWilsonLowerBound: 0,
      maxOppositeRate: 0.5,
      neutralThreshold: 0.1,
    },
  );
  assert.equal(utility.status, 'supported-positive');
  const candidate = induceApplicabilityHypothesis(
    [discoveryPositive.comparison, discoveryNegative.comparison],
    {
      id: 'hypothesis/procedure-candidate',
      memoryId: 'memory/target',
      discoveryComparisonIds: [
        discoveryPositive.comparison.id,
        discoveryNegative.comparison.id,
      ],
      actor: 'hypothesis-controller',
      recordedAt: scenario.time,
      policy: {
        minPositiveExamples: 1,
        minCounterexamples: 1,
        minDistinctContexts: 1,
      },
    },
  );
  const applicability = validateApplicabilityHypothesis(
    candidate,
    [validationPositive.comparison, validationNegative.comparison],
    {
      id: 'validation/procedure-candidate',
      candidateId: candidate.id,
      validationComparisonIds: [
        validationPositive.comparison.id,
        validationNegative.comparison.id,
      ],
      actor: 'validation-controller',
      recordedAt: scenario.time + 1,
      policy: {
        minValidationExamples: 2,
        minPositiveExamples: 1,
        minCounterexamples: 1,
        minDistinctContexts: 1,
        minPrecision: 1,
        minRecall: 1,
        maxCounterexampleActivationRate: 0,
        minMeanActivatedEffect: 0.5,
      },
    },
  );
  assert.equal(applicability.status, 'validated');
  scenario.time += 2;
  return { utility, applicability };
}

function candidateInput(scenario, overrides = {}) {
  return {
    id: 'procedure-candidate/auth-race/1.0.0',
    procedureId: 'procedure/auth-race',
    version: '1.0.0',
    memoryId: 'memory/target',
    scope: 'project/procedure-candidate',
    name: 'Stabilize asynchronous authentication setup',
    goalSignature: 'repair authentication behavior',
    rationale: 'Paired interventions support waiting for durable session readiness before assertions.',
    steps: [
      {
        id: 'create-session',
        instruction: 'Create the authentication session using the configured test identity.',
        evidence: [evidenceRefFor(scenario.stepEvidenceA, ['supports'])],
      },
      {
        id: 'wait-readiness',
        instruction: 'Wait for durable session readiness before running assertions.',
        evidence: [evidenceRefFor(scenario.stepEvidenceB, ['verifies'])],
      },
    ],
    toolDependencies: ['test-runner', 'session-store'],
    risk: 'low',
    verification: {
      requiredVerifier: 'test',
      timeoutMs: 30_000,
      maxAttempts: 1,
      onFailure: 'disable',
      successPredicate: 'auth-session-regression-suite',
    },
    rollback: { kind: 'disable' },
    canonicalFingerprint: fingerprintMemoryEvents(scenario.events()),
    actor: 'procedure-inducer',
    recordedAt: scenario.time,
    ...overrides,
  };
}

test('a valid object remains a non-executable candidate and may enter a future canary gate', () => {
  const scenario = new Scenario();
  const learning = learningEvidence(scenario);
  const procedure = createProcedureCandidate(
    scenario.events(),
    learning.utility,
    learning.applicability,
    candidateInput(scenario),
  );
  assert.equal(procedure.status, 'candidate');
  assert.equal(procedure.executable, false);
  assert.equal(procedure.canaryEligible, true);
  assert.equal(procedure.blockers.length, 0);
  assert.deepEqual(procedure.applicabilityRule, learning.applicability.rule);
  assert.equal(procedure.sourceGroups.length, 2);
  assert.doesNotThrow(() => assertIssuedProcedureCandidate(procedure));
  assert.throws(
    () => assertIssuedProcedureCandidate(structuredClone(procedure)),
    /issued procedure candidate/,
  );
});

test('cloned utility and applicability results cannot authorize a candidate', () => {
  const scenario = new Scenario();
  const learning = learningEvidence(scenario);
  assert.throws(
    () =>
      createProcedureCandidate(
        scenario.events(),
        structuredClone(learning.utility),
        learning.applicability,
        candidateInput(scenario),
      ),
    /issued memory utility assessment/,
  );
  assert.throws(
    () =>
      createProcedureCandidate(
        scenario.events(),
        learning.utility,
        structuredClone(learning.applicability),
        candidateInput(scenario),
      ),
    /issued applicability hypothesis/,
  );
});

test('step evidence must be exact, available, scope-compatible, and explicitly supportive', () => {
  const scenario = new Scenario();
  const learning = learningEvidence(scenario);
  const contextualOnly = candidateInput(scenario);
  contextualOnly.steps[0].evidence = [evidenceRefFor(scenario.stepEvidenceA, ['context'])];
  assert.throws(
    () =>
      createProcedureCandidate(
        scenario.events(),
        learning.utility,
        learning.applicability,
        contextualOnly,
      ),
    /supports or verifies/,
  );

  scenario.kernel.setEvidenceAvailability(
    { eventId: 'event/restrict-step', recordedAt: scenario.time + 1, actor: 'privacy-controller' },
    scenario.stepEvidenceB.id,
    'restricted',
    'review required',
  );
  const unavailable = candidateInput(scenario, {
    canonicalFingerprint: fingerprintMemoryEvents(scenario.events()),
    recordedAt: scenario.time + 2,
  });
  assert.throws(
    () =>
      createProcedureCandidate(
        scenario.events(),
        learning.utility,
        learning.applicability,
        unavailable,
      ),
    /unavailable or forged/,
  );
});

test('a stale canonical fingerprint fails before candidate issuance', () => {
  const scenario = new Scenario();
  const learning = learningEvidence(scenario);
  assert.throws(
    () =>
      createProcedureCandidate(
        scenario.events(),
        learning.utility,
        learning.applicability,
        candidateInput(scenario, { canonicalFingerprint: sha('stale') }),
      ),
    /stale or forged/,
  );
});

test('tainted or personal evidence preserves the candidate but blocks the default canary path', () => {
  const scenario = new Scenario({
    stepTaints: ['prompt-like', 'untrusted-source'],
    stepSensitivity: 'personal',
  });
  const learning = learningEvidence(scenario);
  const procedure = createProcedureCandidate(
    scenario.events(),
    learning.utility,
    learning.applicability,
    candidateInput(scenario),
  );
  assert.equal(procedure.status, 'candidate');
  assert.equal(procedure.executable, false);
  assert.equal(procedure.canaryEligible, false);
  assert.ok(procedure.blockers.some((blocker) => blocker.includes('security review')));
  assert.ok(procedure.blockers.some((blocker) => blocker.includes('personal')));
});

test('high and destructive risk require stronger human gates and destructive remains ineligible', () => {
  const scenario = new Scenario();
  const learning = learningEvidence(scenario);
  const high = createProcedureCandidate(
    scenario.events(),
    learning.utility,
    learning.applicability,
    candidateInput(scenario, {
      id: 'procedure-candidate/high',
      version: '1.1.0',
      risk: 'high',
    }),
  );
  assert.equal(high.canaryEligible, false);
  assert.ok(high.blockers.some((blocker) => blocker.includes('human verification')));
  assert.ok(high.blockers.some((blocker) => blocker.includes('human review')));

  const destructive = createProcedureCandidate(
    scenario.events(),
    learning.utility,
    learning.applicability,
    candidateInput(scenario, {
      id: 'procedure-candidate/destructive',
      version: '2.0.0',
      risk: 'destructive',
      verification: {
        requiredVerifier: 'human',
        timeoutMs: 30_000,
        maxAttempts: 1,
        onFailure: 'human-review',
        successPredicate: 'human-destructive-review',
      },
    }),
  );
  assert.equal(destructive.canaryEligible, false);
  assert.ok(destructive.blockers.some((blocker) => blocker.includes('not canary-eligible')));
});

test('a procedure with one independent step-source family remains candidate-only', () => {
  const scenario = new Scenario();
  const learning = learningEvidence(scenario);
  const oneFamily = candidateInput(scenario);
  oneFamily.steps[1].evidence = [evidenceRefFor(scenario.stepEvidenceA, ['supports'])];
  const procedure = createProcedureCandidate(
    scenario.events(),
    learning.utility,
    learning.applicability,
    oneFamily,
  );
  assert.equal(procedure.canaryEligible, false);
  assert.ok(procedure.blockers.some((blocker) => blocker.includes('two independent')));
});
