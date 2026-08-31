import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createCanaryAdmissionReceipt,
  evaluateCanaryStopCondition,
  evidenceRefFor,
  fingerprintMemoryEvents,
  isIssuedCanaryAdmissionReceipt,
  isIssuedCanaryMonitoringObservation,
  isIssuedCanaryOutcomeReceipt,
  isIssuedCanaryRollbackReceipt,
  isIssuedCanaryRunCompletionReceipt,
  isIssuedCanaryRunStartReceipt,
  isIssuedCanaryStopEvaluation,
  recordCanaryMonitoringObservation,
  recordCanaryRollbackReceipt,
  recordCanaryRunCompletionReceipt,
  recordCanaryRunStartReceipt,
  reviewBoundedCanaryPlan,
  verifyCanaryOutcomeReceipt,
} from '../dist/index.js';
import {
  createCanaryAdmissionReceipt as createCanaryAdmissionReceiptCore,
  isIssuedCanaryAdmissionReceipt as isIssuedCanaryAdmissionReceiptCore,
} from '../dist/learning/canonical-canary-receipts.js';
import {
  buildCanaryFixture,
  issuePlan,
  reviewInput,
  sha,
} from './bounded-canary-fixture.mjs';

function readyCanary(prefix, budgetOverrides = {}) {
  const bundle = buildCanaryFixture(prefix);
  const plan = issuePlan(bundle, budgetOverrides);
  const input = reviewInput(bundle, plan);
  const review = reviewBoundedCanaryPlan(
    bundle.fixture.events(),
    plan,
    input,
  );
  bundle.fixture.time = Math.max(bundle.fixture.time, review.recordedAt + 1);
  return { ...bundle, plan, review };
}

function captureReceiptEvidence(bundle, id, digest, sourceGroup, overrides = {}) {
  return bundle.fixture.capture(`receipt/${id}`, {
    authority: overrides.authority ?? 'tool-verified',
    kind: overrides.kind ?? 'test-result',
    digest,
    sourceGroup,
    ...overrides,
  });
}

function assignmentFor(bundle, arm = undefined, offset = 0) {
  const matching = bundle.plan.population.subjects.filter(
    (assignment) =>
      assignment.applicable &&
      assignment.assignment !== 'excluded' &&
      (arm === undefined || assignment.assignment === arm),
  );
  const assignment = matching[offset];
  if (assignment === undefined) throw new Error(`missing ${arm ?? 'any'} assignment at ${offset}`);
  return assignment;
}

function prepareAdmission(bundle, assignment, suffix = assignment.subjectDigest.slice(-8)) {
  const digest = sha(`${bundle.fixture.prefix}/host-admission/${suffix}`);
  const sourceGroup = bundle.scheduler.record.sourceGroups[0];
  const evidence = captureReceiptEvidence(
    bundle,
    `admission/${suffix}`,
    digest,
    sourceGroup,
  );
  const admittedAt = Math.max(bundle.fixture.time + 1, bundle.review.recordedAt + 1);
  return {
    evidence,
    input: {
      id: `${bundle.fixture.prefix}/admission/${suffix}`,
      subjectDigest: assignment.subjectDigest,
      assignmentDigest: assignment.assignmentDigest,
      hostAdmissionDigest: digest,
      evidence: [evidenceRefFor(evidence, ['verifies'])],
      canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
      actor: `${bundle.fixture.prefix}/scheduler-host`,
      admittedAt,
    },
  };
}

function issueAdmission(bundle, assignment, suffix = assignment.subjectDigest.slice(-8)) {
  const prepared = prepareAdmission(bundle, assignment, suffix);
  const receipt = createCanaryAdmissionReceipt(
    bundle.fixture.events(),
    bundle.plan,
    bundle.review,
    prepared.input,
  );
  bundle.fixture.time = Math.max(bundle.fixture.time, receipt.admittedAt + 1);
  return { ...prepared, receipt };
}

function prepareStart(bundle, admission, suffix, attempt = 1) {
  const runnerDigest = sha(`${bundle.fixture.prefix}/runner/${suffix}`);
  const runnerGroup = bundle.harness.record.sourceGroups[0];
  const runnerEvidence = captureReceiptEvidence(
    bundle,
    `runner/${suffix}`,
    runnerDigest,
    runnerGroup,
  );
  const grantDigest = sha(`${bundle.fixture.prefix}/execution-grant/${suffix}`);
  const grantEvidence = captureReceiptEvidence(
    bundle,
    `grant/${suffix}`,
    grantDigest,
    bundle.scheduler.record.sourceGroups[0],
  );
  const startedAt = Math.max(bundle.fixture.time + 1, admission.receipt.admittedAt + 1);
  return {
    runnerEvidence,
    grantEvidence,
    runnerGroup,
    input: {
      id: `${bundle.fixture.prefix}/start/${suffix}`,
      runId: `${bundle.fixture.prefix}/run/${suffix}`,
      attempt,
      runner: {
        id: `${bundle.fixture.prefix}/runner/${suffix}`,
        digest: runnerDigest,
        evidence: [evidenceRefFor(runnerEvidence, ['verifies'])],
      },
      environmentDigest: bundle.plan.runtime.environmentDigest,
      executionGrantDigest: grantDigest,
      grantEvidence: [evidenceRefFor(grantEvidence, ['verifies'])],
      canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
      actor: `${bundle.fixture.prefix}/run-controller`,
      startedAt,
    },
  };
}

function issueStart(bundle, admission, suffix, attempt = 1) {
  const prepared = prepareStart(bundle, admission, suffix, attempt);
  const receipt = recordCanaryRunStartReceipt(
    bundle.fixture.events(),
    bundle.plan,
    bundle.review,
    admission.receipt,
    prepared.input,
  );
  bundle.fixture.time = Math.max(bundle.fixture.time, receipt.startedAt + 1);
  return { ...prepared, receipt };
}

function prepareCompletion(bundle, start, suffix, overrides = {}) {
  const digest = sha(`${bundle.fixture.prefix}/run-completion/${suffix}`);
  const evidence = captureReceiptEvidence(
    bundle,
    `completion/${suffix}`,
    digest,
    start.runnerGroup,
  );
  const completedAt =
    overrides.completedAt ?? Math.max(bundle.fixture.time + 1, start.receipt.startedAt + 1_000);
  return {
    evidence,
    input: {
      id: `${bundle.fixture.prefix}/completion/${suffix}`,
      runId: start.receipt.runId,
      terminalStatus: overrides.terminalStatus ?? 'success',
      costMicrounits: overrides.costMicrounits ?? 10_000,
      toolCalls: overrides.toolCalls ?? 4,
      externalRunReceiptDigest: digest,
      evidence: [evidenceRefFor(evidence, ['verifies'])],
      canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
      actor: `${bundle.fixture.prefix}/runner-host`,
      completedAt,
    },
  };
}

function issueCompletion(bundle, start, suffix, overrides = {}) {
  const prepared = prepareCompletion(bundle, start, suffix, overrides);
  const receipt = recordCanaryRunCompletionReceipt(
    bundle.fixture.events(),
    bundle.plan,
    bundle.review,
    start.receipt,
    prepared.input,
  );
  bundle.fixture.time = Math.max(bundle.fixture.time, receipt.completedAt + 1);
  return { ...prepared, receipt };
}

function prepareObservation(bundle, metric, sequence, value, sampleCount, suffix = `${sequence}`) {
  const digest = sha(`${bundle.fixture.prefix}/observation/${metric}/${suffix}`);
  const evidence = captureReceiptEvidence(
    bundle,
    `observation/${metric}/${suffix}`,
    digest,
    bundle.observer.record.sourceGroups[0],
  );
  const observedAt = Math.max(bundle.fixture.time + 1, bundle.review.recordedAt + 1);
  return {
    evidence,
    input: {
      id: `${bundle.fixture.prefix}/observation/${metric}/${suffix}`,
      metric,
      sequence,
      value,
      sampleCount,
      observerDigest: bundle.plan.runtime.observerDigest,
      externalObservationDigest: digest,
      evidence: [evidenceRefFor(evidence, ['verifies'])],
      canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
      actor: `${bundle.fixture.prefix}/observer-host`,
      observedAt,
    },
  };
}

function issueObservation(bundle, metric, sequence, value, sampleCount, suffix = `${sequence}`) {
  const prepared = prepareObservation(bundle, metric, sequence, value, sampleCount, suffix);
  const receipt = recordCanaryMonitoringObservation(
    bundle.fixture.events(),
    bundle.plan,
    bundle.review,
    prepared.input,
  );
  bundle.fixture.time = Math.max(bundle.fixture.time, receipt.observedAt + 1);
  return { ...prepared, receipt };
}

function evaluateQualityStop(bundle, observations, suffix = 'quality') {
  const evaluatedAt = Math.max(
    bundle.fixture.time + 1,
    ...observations.map((observation) => observation.receipt.observedAt + 1),
  );
  const input = {
    id: `${bundle.fixture.prefix}/evaluation/${suffix}`,
    conditionId: 'quality-regression',
    observationIds: observations.map((observation) => observation.receipt.id),
    canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
    actor: `${bundle.fixture.prefix}/stop-evaluator`,
    evaluatedAt,
  };
  const receipt = evaluateCanaryStopCondition(
    bundle.fixture.events(),
    bundle.plan,
    bundle.review,
    observations.map((observation) => observation.receipt),
    input,
  );
  bundle.fixture.time = Math.max(bundle.fixture.time, receipt.evaluatedAt + 1);
  return { input, receipt };
}

test('an external host admission preserves deterministic assignment and no authority', () => {
  const bundle = readyCanary('receipt-admission');
  const assignment = assignmentFor(bundle, 'treatment');
  const admission = issueAdmission(bundle, assignment, 'treatment');
  assert.equal(isIssuedCanaryAdmissionReceipt(admission.receipt), true);
  assert.equal(isIssuedCanaryAdmissionReceipt(structuredClone(admission.receipt)), false);
  assert.equal(admission.receipt.subjectDigest, assignment.subjectDigest);
  assert.equal(admission.receipt.arm, assignment.assignment);
  assert.equal(admission.receipt.externalHostActionObserved, true);
  assert.equal(admission.receipt.hostSchedulingAuthorized, false);
  assert.equal(admission.receipt.executionAuthorized, false);
});

test('admission requires a ready matching review and the exact assignment', () => {
  const unready = buildCanaryFixture('receipt-unready');
  const plan = issuePlan(unready);
  const reviewRequest = reviewInput(unready, plan, 'changes', {
    decision: 'changes-required',
    findings: ['population policy requires revision'],
  });
  const review = reviewBoundedCanaryPlan(
    unready.fixture.events(),
    plan,
    reviewRequest,
  );
  unready.fixture.time = Math.max(unready.fixture.time, review.recordedAt + 1);
  const bundle = { ...unready, plan, review };
  const assignment = assignmentFor(bundle);
  const prepared = prepareAdmission(bundle, assignment, 'unready');
  assert.throws(
    () =>
      createCanaryAdmissionReceipt(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        prepared.input,
      ),
    /ready-for-host-scheduling/,
  );

  const ready = readyCanary('receipt-wrong-assignment');
  const first = assignmentFor(ready, undefined, 0);
  const second = assignmentFor(ready, undefined, 1);
  const wrong = prepareAdmission(ready, first, 'wrong-assignment');
  wrong.input.assignmentDigest = second.assignmentDigest;
  assert.throws(
    () =>
      createCanaryAdmissionReceipt(
        ready.fixture.events(),
        ready.plan,
        ready.review,
        wrong.input,
      ),
    /does not match the deterministic plan assignment/,
  );
});

test('host admission evidence must bind the digest and planned scheduler source family', () => {
  const bundle = readyCanary('receipt-admission-evidence');
  const assignment = assignmentFor(bundle);
  const prepared = prepareAdmission(bundle, assignment, 'evidence');
  const unbound = structuredClone(prepared.input);
  unbound.hostAdmissionDigest = sha('receipt-admission-evidence/unbound');
  assert.throws(
    () => createCanaryAdmissionReceipt(bundle.fixture.events(), bundle.plan, bundle.review, unbound),
    /does not bind the declared receipt digest/,
  );

  const foreignDigest = sha('receipt-admission-evidence/foreign');
  const foreign = captureReceiptEvidence(
    bundle,
    'admission/foreign',
    foreignDigest,
    'foreign/scheduler/source',
  );
  const foreignInput = {
    ...structuredClone(prepared.input),
    id: `${bundle.fixture.prefix}/admission/foreign`,
    hostAdmissionDigest: foreignDigest,
    evidence: [evidenceRefFor(foreign, ['verifies'])],
    canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
  };
  assert.throws(
    () => createCanaryAdmissionReceipt(bundle.fixture.events(), bundle.plan, bundle.review, foreignInput),
    /exact receipt digest is not linked to the planned identity source family/,
  );

  const schedulerDecoy = captureReceiptEvidence(
    bundle,
    'admission/scheduler-decoy',
    sha('receipt-admission-evidence/scheduler-decoy'),
    bundle.scheduler.record.sourceGroups[0],
  );
  const splitInput = {
    ...foreignInput,
    id: `${bundle.fixture.prefix}/admission/split-evidence`,
    evidence: [
      evidenceRefFor(foreign, ['verifies']),
      evidenceRefFor(schedulerDecoy, ['verifies']),
    ],
    canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
  };
  assert.throws(
    () => createCanaryAdmissionReceipt(bundle.fixture.events(), bundle.plan, bundle.review, splitInput),
    /exact receipt digest is not linked to the planned identity source family/,
  );
});

test('receipt digests cannot borrow scheduler or runner identity from decoy evidence', () => {
  const bundle = readyCanary('receipt-split-evidence');
  const admission = issueAdmission(bundle, assignmentFor(bundle), 'subject');

  const start = prepareStart(bundle, admission, 'split-grant');
  const foreignRunnerDigest = sha(`${bundle.fixture.prefix}/foreign-runner`);
  const foreignRunner = captureReceiptEvidence(
    bundle,
    'runner/foreign-exact',
    foreignRunnerDigest,
    'foreign/runner-identity-source',
  );
  const harnessDecoy = captureReceiptEvidence(
    bundle,
    'runner/harness-decoy',
    sha(`${bundle.fixture.prefix}/harness-decoy`),
    bundle.harness.record.sourceGroups[0],
  );
  const splitRunnerInput = {
    ...start.input,
    id: `${bundle.fixture.prefix}/start/split-runner`,
    runId: `${bundle.fixture.prefix}/run/split-runner`,
    runner: {
      id: `${bundle.fixture.prefix}/runner/split-runner`,
      digest: foreignRunnerDigest,
      evidence: [
        evidenceRefFor(foreignRunner, ['verifies']),
        evidenceRefFor(harnessDecoy, ['verifies']),
      ],
    },
    canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
  };
  assert.throws(
    () =>
      recordCanaryRunStartReceipt(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        admission.receipt,
        splitRunnerInput,
      ),
    /exact receipt digest is not linked to the planned identity source family/,
  );

  const foreignGrantDigest = sha(`${bundle.fixture.prefix}/foreign-grant`);
  const foreignGrant = captureReceiptEvidence(
    bundle,
    'grant/foreign-exact',
    foreignGrantDigest,
    'foreign/grant-source',
  );
  const schedulerDecoy = captureReceiptEvidence(
    bundle,
    'grant/scheduler-decoy',
    sha(`${bundle.fixture.prefix}/scheduler-decoy`),
    bundle.scheduler.record.sourceGroups[0],
  );
  const splitGrantInput = {
    ...start.input,
    id: `${bundle.fixture.prefix}/start/split-grant`,
    runId: `${bundle.fixture.prefix}/run/split-grant`,
    startedAt: Math.max(bundle.fixture.time + 1, admission.receipt.admittedAt + 1),
    executionGrantDigest: foreignGrantDigest,
    grantEvidence: [
      evidenceRefFor(foreignGrant, ['verifies']),
      evidenceRefFor(schedulerDecoy, ['verifies']),
    ],
    canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
  };
  assert.throws(
    () =>
      recordCanaryRunStartReceipt(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        admission.receipt,
        splitGrantInput,
      ),
    /exact receipt digest is not linked to the planned identity source family/,
  );

  const realStart = issueStart(bundle, admission, 'real-run');
  const completion = prepareCompletion(bundle, realStart, 'split-completion');
  const foreignCompletionDigest = sha(`${bundle.fixture.prefix}/foreign-completion`);
  const foreignCompletion = captureReceiptEvidence(
    bundle,
    'completion/foreign-exact',
    foreignCompletionDigest,
    'foreign/runner-source',
  );
  const runnerDecoy = captureReceiptEvidence(
    bundle,
    'completion/runner-decoy',
    sha(`${bundle.fixture.prefix}/runner-decoy`),
    realStart.runnerGroup,
  );
  const splitCompletionInput = {
    ...completion.input,
    externalRunReceiptDigest: foreignCompletionDigest,
    evidence: [
      evidenceRefFor(foreignCompletion, ['verifies']),
      evidenceRefFor(runnerDecoy, ['verifies']),
    ],
    canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
  };
  assert.throws(
    () =>
      recordCanaryRunCompletionReceipt(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        realStart.receipt,
        splitCompletionInput,
      ),
    /exact receipt digest is not linked to the planned identity source family/,
  );
});

test('outcome verification digest cannot borrow the verifier family from decoy evidence', () => {
  const bundle = readyCanary('receipt-outcome-split-evidence');
  const admission = issueAdmission(bundle, assignmentFor(bundle), 'subject');
  const start = issueStart(bundle, admission, 'run');
  const completion = issueCompletion(bundle, start, 'run');
  bundle.fixture.time = Math.max(bundle.fixture.time, completion.receipt.completedAt + 1);

  const verificationDigest = sha(`${bundle.fixture.prefix}/foreign-outcome-verification`);
  const foreignExact = captureReceiptEvidence(
    bundle,
    'outcome/foreign-exact',
    verificationDigest,
    'foreign/verifier-source',
  );
  const verifierGroup = bundle.verifier.record.sourceGroups[0];
  const verifierDecoy = captureReceiptEvidence(
    bundle,
    'outcome/verifier-decoy',
    sha(`${bundle.fixture.prefix}/verifier-decoy`),
    verifierGroup,
  );
  const outcomeEventId = `${bundle.fixture.prefix}/event/outcome/split-evidence`;
  bundle.fixture.kernel.recordOutcome(
    {
      eventId: outcomeEventId,
      recordedAt: bundle.fixture.time,
      actor: `${bundle.fixture.prefix}/verifier-host`,
    },
    {
      scope: bundle.plan.scope,
      subjectId: completion.receipt.runId,
      taskId: bundle.plan.procedureId,
      contextFingerprint: bundle.plan.population.manifestDigest,
      sourceGroups: [...new Set([
        ...foreignExact.sourceGroups,
        ...verifierDecoy.sourceGroups,
      ])].sort(),
      outcome: 'success',
      verifier: 'test',
      evidence: [
        evidenceRefFor(foreignExact, ['verifies']),
        evidenceRefFor(verifierDecoy, ['verifies']),
      ],
    },
  );
  bundle.fixture.time += 1;
  assert.throws(
    () =>
      verifyCanaryOutcomeReceipt(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        completion.receipt,
        {
          id: `${bundle.fixture.prefix}/outcome/split-evidence`,
          completionId: completion.receipt.id,
          outcomeEventId,
          verifierDigest: bundle.plan.runtime.verifierDigest,
          externalVerificationDigest: verificationDigest,
          evidence: [
            evidenceRefFor(foreignExact, ['verifies']),
            evidenceRefFor(verifierDecoy, ['verifies']),
          ],
          canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
          actor: `${bundle.fixture.prefix}/outcome-controller`,
          verifiedAt: bundle.fixture.time + 1,
        },
      ),
    /exact receipt digest is not linked to the planned identity source family/,
  );
});

test('observation and rollback digests cannot borrow runtime identity from decoy evidence', () => {
  const observationBundle = readyCanary('receipt-observation-split-evidence');
  const observationDigest = sha(`${observationBundle.fixture.prefix}/foreign-observation`);
  const foreignObservation = captureReceiptEvidence(
    observationBundle,
    'observation/foreign-exact',
    observationDigest,
    'foreign/observer-source',
  );
  const observerDecoy = captureReceiptEvidence(
    observationBundle,
    'observation/observer-decoy',
    sha(`${observationBundle.fixture.prefix}/observer-decoy`),
    observationBundle.observer.record.sourceGroups[0],
  );
  assert.throws(
    () =>
      recordCanaryMonitoringObservation(
        observationBundle.fixture.events(),
        observationBundle.plan,
        observationBundle.review,
        {
          id: `${observationBundle.fixture.prefix}/observation/split-evidence`,
          metric: 'quality.failure_rate',
          sequence: 1,
          value: 0.3,
          sampleCount: 2,
          observerDigest: observationBundle.plan.runtime.observerDigest,
          externalObservationDigest: observationDigest,
          evidence: [
            evidenceRefFor(foreignObservation, ['verifies']),
            evidenceRefFor(observerDecoy, ['verifies']),
          ],
          canonicalFingerprint: fingerprintMemoryEvents(observationBundle.fixture.events()),
          actor: `${observationBundle.fixture.prefix}/observer-host`,
          observedAt: observationBundle.fixture.time + 1,
        },
      ),
    /exact receipt digest is not linked to the planned identity source family/,
  );

  const rollbackBundle = readyCanary('receipt-rollback-split-evidence');
  const first = issueObservation(
    rollbackBundle,
    'quality.failure_rate',
    1,
    0.1,
    1,
    'first',
  );
  const second = issueObservation(
    rollbackBundle,
    'quality.failure_rate',
    2,
    0.3,
    2,
    'second',
  );
  const evaluation = evaluateQualityStop(rollbackBundle, [first, second]);
  const rollbackDigest = sha(`${rollbackBundle.fixture.prefix}/foreign-rollback`);
  const foreignRollback = captureReceiptEvidence(
    rollbackBundle,
    'rollback/foreign-exact',
    rollbackDigest,
    'foreign/rollback-source',
  );
  const controllerDecoy = captureReceiptEvidence(
    rollbackBundle,
    'rollback/controller-decoy',
    sha(`${rollbackBundle.fixture.prefix}/controller-decoy`),
    rollbackBundle.rollbackController.record.sourceGroups[0],
  );
  const startedAt = Math.max(
    rollbackBundle.fixture.time + 1,
    evaluation.receipt.evaluatedAt + 1,
  );
  assert.throws(
    () =>
      recordCanaryRollbackReceipt(
        rollbackBundle.fixture.events(),
        rollbackBundle.plan,
        rollbackBundle.review,
        evaluation.receipt,
        {
          id: `${rollbackBundle.fixture.prefix}/rollback/split-evidence`,
          evaluationId: evaluation.receipt.id,
          controllerDigest: rollbackBundle.plan.runtime.rollbackControllerDigest,
          externalRollbackDigest: rollbackDigest,
          outcome: 'succeeded',
          evidence: [
            evidenceRefFor(foreignRollback, ['verifies']),
            evidenceRefFor(controllerDecoy, ['verifies']),
          ],
          canonicalFingerprint: fingerprintMemoryEvents(rollbackBundle.fixture.events()),
          actor: `${rollbackBundle.fixture.prefix}/rollback-host`,
          startedAt,
          completedAt: startedAt + 1_000,
        },
      ),
    /exact receipt digest is not linked to the planned identity source family/,
  );
});

test('external action receipts cannot reuse planned component identity digests', () => {
  const admissionBundle = readyCanary('receipt-identity-reuse-admission');
  const admission = prepareAdmission(admissionBundle, assignmentFor(admissionBundle), 'subject');
  admission.input.hostAdmissionDigest = admissionBundle.plan.runtime.schedulerDigest;
  admission.input.evidence = [evidenceRefFor(admissionBundle.scheduler.record, ['verifies'])];
  admission.input.canonicalFingerprint = fingerprintMemoryEvents(admissionBundle.fixture.events());
  assert.throws(
    () =>
      createCanaryAdmissionReceipt(
        admissionBundle.fixture.events(),
        admissionBundle.plan,
        admissionBundle.review,
        admission.input,
      ),
    /host admission digest must differ from the planned identity digest/,
  );

  const startBundle = readyCanary('receipt-identity-reuse-grant');
  const startAdmission = issueAdmission(startBundle, assignmentFor(startBundle), 'subject');
  const start = prepareStart(startBundle, startAdmission, 'run');
  start.input.executionGrantDigest = startBundle.plan.runtime.schedulerDigest;
  start.input.grantEvidence = [evidenceRefFor(startBundle.scheduler.record, ['verifies'])];
  start.input.canonicalFingerprint = fingerprintMemoryEvents(startBundle.fixture.events());
  assert.throws(
    () =>
      recordCanaryRunStartReceipt(
        startBundle.fixture.events(),
        startBundle.plan,
        startBundle.review,
        startAdmission.receipt,
        start.input,
      ),
    /execution grant digest must differ from the planned identity digest/,
  );

  const completionBundle = readyCanary('receipt-identity-reuse-completion');
  const completionAdmission = issueAdmission(
    completionBundle,
    assignmentFor(completionBundle),
    'subject',
  );
  const completionStart = issueStart(completionBundle, completionAdmission, 'run');
  const completion = prepareCompletion(completionBundle, completionStart, 'run');
  completion.input.externalRunReceiptDigest = completionStart.input.runner.digest;
  completion.input.evidence = [evidenceRefFor(completionStart.runnerEvidence, ['verifies'])];
  completion.input.canonicalFingerprint = fingerprintMemoryEvents(completionBundle.fixture.events());
  assert.throws(
    () =>
      recordCanaryRunCompletionReceipt(
        completionBundle.fixture.events(),
        completionBundle.plan,
        completionBundle.review,
        completionStart.receipt,
        completion.input,
      ),
    /external run receipt digest must differ from the planned identity digest/,
  );

  const observationBundle = readyCanary('receipt-identity-reuse-observation');
  const observation = prepareObservation(
    observationBundle,
    'quality.failure_rate',
    1,
    0.1,
    1,
    'identity-reuse',
  );
  observation.input.externalObservationDigest = observationBundle.plan.runtime.observerDigest;
  observation.input.evidence = [evidenceRefFor(observationBundle.observer.record, ['verifies'])];
  observation.input.canonicalFingerprint = fingerprintMemoryEvents(observationBundle.fixture.events());
  assert.throws(
    () =>
      recordCanaryMonitoringObservation(
        observationBundle.fixture.events(),
        observationBundle.plan,
        observationBundle.review,
        observation.input,
      ),
    /external observation digest must differ from the planned identity digest/,
  );

  const rollbackBundle = readyCanary('receipt-identity-reuse-rollback');
  const first = issueObservation(
    rollbackBundle,
    'quality.failure_rate',
    1,
    0.1,
    1,
    'first',
  );
  const second = issueObservation(
    rollbackBundle,
    'quality.failure_rate',
    2,
    0.3,
    2,
    'second',
  );
  const evaluation = evaluateQualityStop(rollbackBundle, [first, second]);
  const rollbackStartedAt = Math.max(
    rollbackBundle.fixture.time + 1,
    evaluation.receipt.evaluatedAt + 1,
  );
  assert.throws(
    () =>
      recordCanaryRollbackReceipt(
        rollbackBundle.fixture.events(),
        rollbackBundle.plan,
        rollbackBundle.review,
        evaluation.receipt,
        {
          id: `${rollbackBundle.fixture.prefix}/rollback/identity-reuse`,
          evaluationId: evaluation.receipt.id,
          controllerDigest: rollbackBundle.plan.runtime.rollbackControllerDigest,
          externalRollbackDigest: rollbackBundle.plan.runtime.rollbackControllerDigest,
          outcome: 'succeeded',
          evidence: [evidenceRefFor(rollbackBundle.rollbackController.record, ['verifies'])],
          canonicalFingerprint: fingerprintMemoryEvents(rollbackBundle.fixture.events()),
          actor: `${rollbackBundle.fixture.prefix}/rollback-host`,
          startedAt: rollbackStartedAt,
          completedAt: rollbackStartedAt + 1_000,
        },
      ),
    /external rollback digest must differ from the planned identity digest/,
  );

  const outcomeBundle = readyCanary('receipt-identity-reuse-outcome');
  const outcomeAdmission = issueAdmission(outcomeBundle, assignmentFor(outcomeBundle), 'subject');
  const outcomeStart = issueStart(outcomeBundle, outcomeAdmission, 'run');
  const outcomeCompletion = issueCompletion(outcomeBundle, outcomeStart, 'run');
  assert.throws(
    () =>
      verifyCanaryOutcomeReceipt(
        outcomeBundle.fixture.events(),
        outcomeBundle.plan,
        outcomeBundle.review,
        outcomeCompletion.receipt,
        {
          id: `${outcomeBundle.fixture.prefix}/outcome/identity-reuse`,
          completionId: outcomeCompletion.receipt.id,
          outcomeEventId: `${outcomeBundle.fixture.prefix}/event/outcome/identity-reuse`,
          verifierDigest: outcomeBundle.plan.runtime.verifierDigest,
          externalVerificationDigest: outcomeBundle.plan.runtime.verifierDigest,
          evidence: [evidenceRefFor(outcomeBundle.verifier.record, ['verifies'])],
          canonicalFingerprint: fingerprintMemoryEvents(outcomeBundle.fixture.events()),
          actor: `${outcomeBundle.fixture.prefix}/outcome-controller`,
          verifiedAt: outcomeCompletion.receipt.completedAt + 1,
        },
      ),
    /external verification digest must differ from the planned identity digest/,
  );
});

test('run starts require external grants and enforce plan concurrency', () => {
  const bundle = readyCanary('receipt-concurrency');
  const admissions = [0, 1, 2].map((index) =>
    issueAdmission(bundle, assignmentFor(bundle, undefined, index), `subject-${index}`),
  );
  const first = issueStart(bundle, admissions[0], 'first');
  const second = issueStart(bundle, admissions[1], 'second');
  const third = prepareStart(bundle, admissions[2], 'third');
  assert.equal(isIssuedCanaryRunStartReceipt(first.receipt), true);
  assert.equal(isIssuedCanaryRunStartReceipt(structuredClone(first.receipt)), false);
  assert.equal(first.receipt.externalExecutionGrantObserved, true);
  assert.equal(first.receipt.executionAuthorized, false);
  assert.throws(
    () =>
      recordCanaryRunStartReceipt(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        admissions[2].receipt,
        third.input,
      ),
    /maximum concurrent run count/,
  );
  issueCompletion(bundle, first, 'first');
  const acceptedThird = issueStart(
    bundle,
    admissions[2],
    'third-after-completion',
  );
  assert.equal(acceptedThird.receipt.runId, acceptedThird.input.runId);
  assert.equal(second.receipt.status, 'started');
});

test('one subject attempt cannot be relabeled as another run', () => {
  const bundle = readyCanary('receipt-attempt');
  const admission = issueAdmission(bundle, assignmentFor(bundle), 'subject');
  issueStart(bundle, admission, 'first-run');
  const duplicate = prepareStart(bundle, admission, 'second-run', 1);
  assert.throws(
    () =>
      recordCanaryRunStartReceipt(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        admission.receipt,
        duplicate.input,
      ),
    /subject attempt already has another run/,
  );
});

test('subject retries are sequential, non-overlapping, and never follow success', () => {
  const bundle = readyCanary('receipt-retry-order', {
    maxRuns: 6,
    maxRetriesPerSubject: 2,
  });
  const admission = issueAdmission(bundle, assignmentFor(bundle), 'subject');

  const missingFirst = prepareStart(bundle, admission, 'missing-first', 2);
  assert.throws(
    () =>
      recordCanaryRunStartReceipt(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        admission.receipt,
        missingFirst.input,
      ),
    /immediately preceding subject attempt/,
  );

  const first = issueStart(bundle, admission, 'first', 1);
  const overlappingRetry = prepareStart(bundle, admission, 'overlapping-retry', 2);
  assert.throws(
    () =>
      recordCanaryRunStartReceipt(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        admission.receipt,
        overlappingRetry.input,
      ),
    /already has an active run/,
  );

  issueCompletion(bundle, first, 'first', { terminalStatus: 'failure' });
  const second = issueStart(bundle, admission, 'second', 2);
  assert.equal(second.receipt.attempt, 2);
  assert.equal(second.receipt.subjectDigest, admission.receipt.subjectDigest);

  issueCompletion(bundle, second, 'second');
  const retryAfterSuccess = prepareStart(bundle, admission, 'retry-after-success', 3);
  assert.throws(
    () =>
      recordCanaryRunStartReceipt(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        admission.receipt,
        retryAfterSuccess.input,
      ),
    /cannot follow a successful subject attempt/,
  );
});

test('completion closes an active slot and exposes cumulative limit breaches', () => {
  const bundle = readyCanary('receipt-completion');
  const a = issueAdmission(bundle, assignmentFor(bundle, undefined, 0), 'a');
  const b = issueAdmission(bundle, assignmentFor(bundle, undefined, 1), 'b');
  const startA = issueStart(bundle, a, 'a');
  const startB = issueStart(bundle, b, 'b');
  const completionA = issueCompletion(bundle, startA, 'a', { costMicrounits: 60_000 });
  const completionB = issueCompletion(bundle, startB, 'b', {
    costMicrounits: 50_000,
    toolCalls: 5,
    completedAt: startB.receipt.startedAt + bundle.plan.budget.maxDurationMs + 1,
  });
  assert.equal(isIssuedCanaryRunCompletionReceipt(completionA.receipt), true);
  assert.equal(isIssuedCanaryRunCompletionReceipt(structuredClone(completionA.receipt)), false);
  assert.equal(completionB.receipt.cumulativeCostMicrounits, 110_000);
  assert.equal(completionB.receipt.cumulativeToolCalls, 9);
  assert.deepEqual(completionB.receipt.limitBreaches, ['duration', 'tool-calls', 'plan-cost']);
  assert.equal(completionB.receipt.executionAuthorized, false);
});

test('completion retries preserve their original cumulative budget position', () => {
  const bundle = readyCanary('receipt-completion-retry');
  const admissionA = issueAdmission(bundle, assignmentFor(bundle, undefined, 0), 'a');
  const admissionB = issueAdmission(bundle, assignmentFor(bundle, undefined, 1), 'b');
  const startA = issueStart(bundle, admissionA, 'a');
  const startB = issueStart(bundle, admissionB, 'b');

  const preparedA = prepareCompletion(bundle, startA, 'a', {
    costMicrounits: 25_000,
    toolCalls: 2,
  });
  const eventsAtA = bundle.fixture.events();
  const firstA = recordCanaryRunCompletionReceipt(
    eventsAtA,
    bundle.plan,
    bundle.review,
    startA.receipt,
    preparedA.input,
  );
  bundle.fixture.time = Math.max(bundle.fixture.time, firstA.completedAt + 1);

  const completionB = issueCompletion(bundle, startB, 'b', {
    costMicrounits: 30_000,
    toolCalls: 3,
  });
  assert.equal(completionB.receipt.cumulativeCostMicrounits, 55_000);
  assert.equal(completionB.receipt.cumulativeToolCalls, 5);

  const retryA = recordCanaryRunCompletionReceipt(
    eventsAtA,
    bundle.plan,
    bundle.review,
    startA.receipt,
    preparedA.input,
  );
  assert.equal(retryA, firstA);
  assert.equal(retryA.cumulativeCostMicrounits, 25_000);
  assert.equal(retryA.cumulativeToolCalls, 2);
});

test('monitoring observations are declared, monotonic, and observer-bound', () => {
  const bundle = readyCanary('receipt-monitoring');
  const first = issueObservation(bundle, 'quality.failure_rate', 1, 0.1, 1, 'first');
  assert.equal(isIssuedCanaryMonitoringObservation(first.receipt), true);
  assert.equal(isIssuedCanaryMonitoringObservation(structuredClone(first.receipt)), false);
  assert.equal(first.receipt.observerIdentityDigest, bundle.plan.runtime.observerDigest);
  assert.notEqual(first.receipt.observerIdentityDigest, bundle.plan.runtime.identityDigest);

  const gap = prepareObservation(bundle, 'quality.failure_rate', 3, 0.2, 2, 'gap');
  assert.throws(
    () => recordCanaryMonitoringObservation(bundle.fixture.events(), bundle.plan, bundle.review, gap.input),
    /sequence must advance to 2/,
  );

  const regression = prepareObservation(bundle, 'quality.failure_rate', 2, 0.2, 0, 'regression');
  assert.throws(
    () => recordCanaryMonitoringObservation(bundle.fixture.events(), bundle.plan, bundle.review, regression.input),
    /sampleCount/,
  );

  const undeclared = prepareObservation(bundle, 'unknown.metric', 1, 1, 1, 'unknown');
  assert.throws(
    () => recordCanaryMonitoringObservation(bundle.fixture.events(), bundle.plan, bundle.review, undeclared.input),
    /not declared by the plan/,
  );
});

test('monitoring admission stops before the complete prefix becomes inevaluable', () => {
  const bundle = readyCanary('receipt-monitoring-prefix-bound');
  const observations = [];
  const escapedPadding = String.fromCharCode(1).repeat(480);
  let rejected = false;

  for (let sequence = 1; sequence <= 256; sequence += 1) {
    const prepared = prepareObservation(
      bundle,
      'quality.failure_rate',
      sequence,
      0.1,
      1,
      `bounded-${sequence}`,
    );
    prepared.input.id = `observation-${sequence}-${escapedPadding}`;
    try {
      const receipt = recordCanaryMonitoringObservation(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        prepared.input,
      );
      bundle.fixture.time = Math.max(bundle.fixture.time, receipt.observedAt + 1);
      observations.push(receipt);
    } catch (error) {
      assert.match(
        error instanceof Error ? error.message : String(error),
        /complete-evaluation representation bound/,
      );
      rejected = true;
      break;
    }
  }

  assert.equal(rejected, true);
  assert.ok(observations.length > 0 && observations.length < 256);
  const evaluatedAt = bundle.fixture.time + 1;
  const evaluation = evaluateCanaryStopCondition(
    bundle.fixture.events(),
    bundle.plan,
    bundle.review,
    observations,
    {
      id: `${bundle.fixture.prefix}/evaluation/bounded-prefix`,
      conditionId: 'quality-regression',
      observationIds: observations.map((observation) => observation.id),
      canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
      actor: `${bundle.fixture.prefix}/stop-evaluator`,
      evaluatedAt,
    },
  );
  assert.equal(evaluation.observationIds.length, observations.length);
  assert.equal(evaluation.executionAuthorized, false);
});

test('stop evaluation uses the complete admitted prefix and triggers deterministically', () => {
  const bundle = readyCanary('receipt-stop');
  const first = issueObservation(bundle, 'quality.failure_rate', 1, 0.1, 1, 'first');
  const second = issueObservation(bundle, 'quality.failure_rate', 2, 0.3, 2, 'second');
  const evaluatedAt = Math.max(bundle.fixture.time + 1, second.receipt.observedAt + 1);
  assert.throws(
    () =>
      evaluateCanaryStopCondition(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        [second.receipt],
        {
          id: `${bundle.fixture.prefix}/evaluation/omitted`,
          conditionId: 'quality-regression',
          observationIds: [second.receipt.id],
          canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
          actor: `${bundle.fixture.prefix}/stop-evaluator`,
          evaluatedAt,
        },
      ),
    /omits or invents admitted monitoring observations/,
  );
  const evaluation = evaluateQualityStop(bundle, [second, first]);
  assert.equal(isIssuedCanaryStopEvaluation(evaluation.receipt), true);
  assert.equal(isIssuedCanaryStopEvaluation(structuredClone(evaluation.receipt)), false);
  assert.equal(evaluation.receipt.triggered, true);
  assert.equal(evaluation.receipt.action, 'rollback');
  assert.equal(evaluation.receipt.latestObservationId, second.receipt.id);
  assert.equal(evaluation.receipt.executionAuthorized, false);
});

test('rollback receipt requires the triggered action and planned controller family', () => {
  const bundle = readyCanary('receipt-rollback');
  const first = issueObservation(bundle, 'quality.failure_rate', 1, 0.1, 1, 'first');
  const second = issueObservation(bundle, 'quality.failure_rate', 2, 0.3, 2, 'second');
  const evaluation = evaluateQualityStop(bundle, [first, second]);
  const digest = sha(`${bundle.fixture.prefix}/rollback-receipt`);
  const evidence = captureReceiptEvidence(
    bundle,
    'rollback/receipt',
    digest,
    bundle.rollbackController.record.sourceGroups[0],
  );
  const startedAt = Math.max(bundle.fixture.time + 1, evaluation.receipt.evaluatedAt + 1);
  const receipt = recordCanaryRollbackReceipt(
    bundle.fixture.events(),
    bundle.plan,
    bundle.review,
    evaluation.receipt,
    {
      id: `${bundle.fixture.prefix}/rollback/receipt`,
      evaluationId: evaluation.receipt.id,
      controllerDigest: bundle.plan.runtime.rollbackControllerDigest,
      externalRollbackDigest: digest,
      outcome: 'succeeded',
      evidence: [evidenceRefFor(evidence, ['verifies'])],
      canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
      actor: `${bundle.fixture.prefix}/rollback-host`,
      startedAt,
      completedAt: startedAt + 1_000,
    },
  );
  assert.equal(isIssuedCanaryRollbackReceipt(receipt), true);
  assert.equal(isIssuedCanaryRollbackReceipt(structuredClone(receipt)), false);
  assert.equal(receipt.outcome, 'succeeded');
  assert.equal(receipt.externalHostActionObserved, true);
  assert.equal(receipt.executionAuthorized, false);
});

test('canonical outcome verification binds completion, run, event evidence, and verifier family', () => {
  const bundle = readyCanary('receipt-outcome');
  const admission = issueAdmission(bundle, assignmentFor(bundle), 'subject');
  const start = issueStart(bundle, admission, 'run');
  const completion = issueCompletion(bundle, start, 'run');
  bundle.fixture.time = Math.max(bundle.fixture.time, completion.receipt.completedAt + 1);
  const digest = sha(`${bundle.fixture.prefix}/outcome-verification`);
  const verifierGroup = bundle.verifier.record.sourceGroups[0];
  const evidence = captureReceiptEvidence(
    bundle,
    'outcome/verification',
    digest,
    verifierGroup,
  );
  const outcomeEventId = `${bundle.fixture.prefix}/event/outcome/canary-run`;
  bundle.fixture.kernel.recordOutcome(
    {
      eventId: outcomeEventId,
      recordedAt: bundle.fixture.time,
      actor: `${bundle.fixture.prefix}/verifier-host`,
    },
    {
      scope: bundle.plan.scope,
      subjectId: completion.receipt.runId,
      taskId: bundle.plan.procedureId,
      contextFingerprint: bundle.plan.population.manifestDigest,
      sourceGroups: [verifierGroup],
      outcome: 'success',
      verifier: 'test',
      evidence: [evidenceRefFor(evidence, ['verifies'])],
    },
  );
  bundle.fixture.time += 1;
  const receipt = verifyCanaryOutcomeReceipt(
    bundle.fixture.events(),
    bundle.plan,
    bundle.review,
    completion.receipt,
    {
      id: `${bundle.fixture.prefix}/outcome/receipt`,
      completionId: completion.receipt.id,
      outcomeEventId,
      verifierDigest: bundle.plan.runtime.verifierDigest,
      externalVerificationDigest: digest,
      evidence: [evidenceRefFor(evidence, ['verifies'])],
      canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
      actor: `${bundle.fixture.prefix}/outcome-controller`,
      verifiedAt: bundle.fixture.time + 1,
    },
  );
  assert.equal(isIssuedCanaryOutcomeReceipt(receipt), true);
  assert.equal(isIssuedCanaryOutcomeReceipt(structuredClone(receipt)), false);
  assert.equal(receipt.outcome, 'success');
  assert.equal(receipt.verifier, 'test');
  assert.equal(receipt.runId, completion.receipt.runId);
  assert.equal(receipt.procedurePromotionAuthorized, false);
  assert.equal(receipt.hostSchedulingAuthorized, false);
  assert.equal(receipt.executionAuthorized, false);
});

test('canonical outcome verification binds procedure, population context, and verifier class', () => {
  const bundle = readyCanary('receipt-outcome-semantic-binding');
  const admission = issueAdmission(bundle, assignmentFor(bundle), 'subject');
  const start = issueStart(bundle, admission, 'run');
  const completion = issueCompletion(bundle, start, 'run');
  bundle.fixture.time = Math.max(bundle.fixture.time, completion.receipt.completedAt + 1);
  const digest = sha(`${bundle.fixture.prefix}/outcome-verification`);
  const verifierGroup = bundle.verifier.record.sourceGroups[0];
  const evidence = captureReceiptEvidence(
    bundle,
    'outcome/verification',
    digest,
    verifierGroup,
  );

  for (const [suffix, taskId, contextFingerprint] of [
    ['wrong-procedure', `${bundle.plan.procedureId}/other`, bundle.plan.population.manifestDigest],
    ['wrong-population', bundle.plan.procedureId, sha(`${bundle.fixture.prefix}/other-population`)],
  ]) {
    const outcomeEventId = `${bundle.fixture.prefix}/event/outcome/${suffix}`;
    bundle.fixture.kernel.recordOutcome(
      {
        eventId: outcomeEventId,
        recordedAt: bundle.fixture.time,
        actor: `${bundle.fixture.prefix}/verifier-host`,
      },
      {
        scope: bundle.plan.scope,
        subjectId: completion.receipt.runId,
        taskId,
        contextFingerprint,
        sourceGroups: [verifierGroup],
        outcome: 'success',
        verifier: 'test',
        evidence: [evidenceRefFor(evidence, ['verifies'])],
      },
    );
    bundle.fixture.time += 1;
    assert.throws(
      () =>
        verifyCanaryOutcomeReceipt(
          bundle.fixture.events(),
          bundle.plan,
          bundle.review,
          completion.receipt,
          {
            id: `${bundle.fixture.prefix}/outcome/${suffix}`,
            completionId: completion.receipt.id,
            outcomeEventId,
            verifierDigest: bundle.plan.runtime.verifierDigest,
            externalVerificationDigest: digest,
            evidence: [evidenceRefFor(evidence, ['verifies'])],
            canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
            actor: `${bundle.fixture.prefix}/outcome-controller`,
            verifiedAt: bundle.fixture.time + 1,
          },
        ),
      /procedure, population context/,
    );
  }

  const modelEventId = `${bundle.fixture.prefix}/event/outcome/model-only`;
  bundle.fixture.kernel.recordOutcome(
    {
      eventId: modelEventId,
      recordedAt: bundle.fixture.time,
      actor: `${bundle.fixture.prefix}/verifier-host`,
    },
    {
      scope: bundle.plan.scope,
      subjectId: completion.receipt.runId,
      taskId: bundle.plan.procedureId,
      contextFingerprint: bundle.plan.population.manifestDigest,
      sourceGroups: [verifierGroup],
      outcome: 'success',
      verifier: 'model',
      evidence: [evidenceRefFor(evidence, ['verifies'])],
    },
  );
  bundle.fixture.time += 1;
  assert.throws(
    () =>
      verifyCanaryOutcomeReceipt(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        completion.receipt,
        {
          id: `${bundle.fixture.prefix}/outcome/model-only`,
          completionId: completion.receipt.id,
          outcomeEventId: modelEventId,
          verifierDigest: bundle.plan.runtime.verifierDigest,
          externalVerificationDigest: digest,
          evidence: [evidenceRefFor(evidence, ['verifies'])],
          canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
          actor: `${bundle.fixture.prefix}/outcome-controller`,
          verifiedAt: bundle.fixture.time + 1,
        },
      ),
    /external verifier classification/,
  );
});

test('a human outcome label requires exact human-explicit verification evidence', () => {
  const bundle = readyCanary('receipt-outcome-human-authority');
  const admission = issueAdmission(bundle, assignmentFor(bundle), 'subject');
  const start = issueStart(bundle, admission, 'run');
  const completion = issueCompletion(bundle, start, 'run');
  bundle.fixture.time = Math.max(bundle.fixture.time, completion.receipt.completedAt + 1);
  const verifierGroup = bundle.verifier.record.sourceGroups[0];

  const toolDigest = sha(`${bundle.fixture.prefix}/tool-verification`);
  const toolEvidence = captureReceiptEvidence(
    bundle,
    'outcome/tool-verification',
    toolDigest,
    verifierGroup,
  );
  const humanDecoy = captureReceiptEvidence(
    bundle,
    'outcome/human-decoy',
    sha(`${bundle.fixture.prefix}/human-decoy`),
    verifierGroup,
    { authority: 'human-explicit' },
  );
  const mislabeledEventId = `${bundle.fixture.prefix}/event/outcome/mislabeled-human`;
  bundle.fixture.kernel.recordOutcome(
    {
      eventId: mislabeledEventId,
      recordedAt: bundle.fixture.time,
      actor: `${bundle.fixture.prefix}/verifier-host`,
    },
    {
      scope: bundle.plan.scope,
      subjectId: completion.receipt.runId,
      taskId: bundle.plan.procedureId,
      contextFingerprint: bundle.plan.population.manifestDigest,
      sourceGroups: [verifierGroup],
      outcome: 'success',
      verifier: 'human',
      evidence: [
        evidenceRefFor(toolEvidence, ['verifies']),
        evidenceRefFor(humanDecoy, ['verifies']),
      ],
    },
  );
  bundle.fixture.time += 1;
  assert.throws(
    () =>
      verifyCanaryOutcomeReceipt(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        completion.receipt,
        {
          id: `${bundle.fixture.prefix}/outcome/mislabeled-human`,
          completionId: completion.receipt.id,
          outcomeEventId: mislabeledEventId,
          verifierDigest: bundle.plan.runtime.verifierDigest,
          externalVerificationDigest: toolDigest,
          evidence: [
            evidenceRefFor(toolEvidence, ['verifies']),
            evidenceRefFor(humanDecoy, ['verifies']),
          ],
          canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
          actor: `${bundle.fixture.prefix}/outcome-controller`,
          verifiedAt: bundle.fixture.time + 1,
        },
      ),
    /exact receipt digest lacks human-explicit authority/,
  );

  const humanDigest = sha(`${bundle.fixture.prefix}/human-verification`);
  const humanEvidence = captureReceiptEvidence(
    bundle,
    'outcome/human-verification',
    humanDigest,
    verifierGroup,
    { authority: 'human-explicit' },
  );
  const humanEventId = `${bundle.fixture.prefix}/event/outcome/human`;
  bundle.fixture.kernel.recordOutcome(
    {
      eventId: humanEventId,
      recordedAt: bundle.fixture.time,
      actor: `${bundle.fixture.prefix}/human-verifier`,
    },
    {
      scope: bundle.plan.scope,
      subjectId: completion.receipt.runId,
      taskId: bundle.plan.procedureId,
      contextFingerprint: bundle.plan.population.manifestDigest,
      sourceGroups: [verifierGroup],
      outcome: 'success',
      verifier: 'human',
      evidence: [evidenceRefFor(humanEvidence, ['verifies'])],
    },
  );
  bundle.fixture.time += 1;
  const receipt = verifyCanaryOutcomeReceipt(
    bundle.fixture.events(),
    bundle.plan,
    bundle.review,
    completion.receipt,
    {
      id: `${bundle.fixture.prefix}/outcome/human`,
      completionId: completion.receipt.id,
      outcomeEventId: humanEventId,
      verifierDigest: bundle.plan.runtime.verifierDigest,
      externalVerificationDigest: humanDigest,
      evidence: [evidenceRefFor(humanEvidence, ['verifies'])],
      canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
      actor: `${bundle.fixture.prefix}/outcome-controller`,
      verifiedAt: bundle.fixture.time + 1,
    },
  );
  assert.equal(receipt.verifier, 'human');
  assert.equal(receipt.evidence[0]?.authority, 'human-explicit');
  assert.equal(receipt.executionAuthorized, false);
});

test('canonical outcome verification rejects a different run or verifier family', () => {
  const bundle = readyCanary('receipt-outcome-reject');
  const admission = issueAdmission(bundle, assignmentFor(bundle), 'subject');
  const start = issueStart(bundle, admission, 'run');
  const completion = issueCompletion(bundle, start, 'run');
  bundle.fixture.time = Math.max(bundle.fixture.time, completion.receipt.completedAt + 1);
  const digest = sha(`${bundle.fixture.prefix}/outcome-verification`);
  const foreignGroup = `${bundle.fixture.prefix}/foreign-verifier`;
  const evidence = captureReceiptEvidence(bundle, 'outcome/foreign', digest, foreignGroup);
  const outcomeEventId = `${bundle.fixture.prefix}/event/outcome/foreign`;
  bundle.fixture.kernel.recordOutcome(
    {
      eventId: outcomeEventId,
      recordedAt: bundle.fixture.time,
      actor: 'foreign-verifier',
    },
    {
      scope: bundle.plan.scope,
      subjectId: `${completion.receipt.runId}/other`,
      taskId: bundle.plan.procedureId,
      contextFingerprint: bundle.plan.population.manifestDigest,
      sourceGroups: [foreignGroup],
      outcome: 'success',
      verifier: 'test',
      evidence: [evidenceRefFor(evidence, ['verifies'])],
    },
  );
  bundle.fixture.time += 1;
  assert.throws(
    () =>
      verifyCanaryOutcomeReceipt(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        completion.receipt,
        {
          id: `${bundle.fixture.prefix}/outcome/foreign`,
          completionId: completion.receipt.id,
          outcomeEventId,
          verifierDigest: bundle.plan.runtime.verifierDigest,
          externalVerificationDigest: digest,
          evidence: [evidenceRefFor(evidence, ['verifies'])],
          canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
          actor: 'outcome-controller',
          verifiedAt: bundle.fixture.time + 1,
        },
      ),
    /does not bind the completed run|planned runtime identity source family/,
  );
});

test('receipt runtime JSON rejects unknown top-level and nested runner fields', () => {
  const bundle = readyCanary('receipt-unknown-fields');
  const assignment = assignmentFor(bundle);
  const admission = prepareAdmission(bundle, assignment, 'unknown-field');
  assert.throws(
    () =>
      createCanaryAdmissionReceipt(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        { ...admission.input, arm: 'treatment' },
      ),
    /exactly the declared fields/,
  );

  const issuedAdmission = issueAdmission(bundle, assignment, 'subject');
  const start = prepareStart(bundle, issuedAdmission, 'run');
  assert.throws(
    () =>
      recordCanaryRunStartReceipt(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        issuedAdmission.receipt,
        { ...start.input, executionAuthorized: true },
      ),
    /exactly the declared fields/,
  );
  assert.throws(
    () =>
      recordCanaryRunStartReceipt(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        issuedAdmission.receipt,
        {
          ...start.input,
          runner: { ...start.input.runner, trusted: true },
        },
      ),
    /exactly the declared fields/,
  );
});

test('structural clones cannot cross guarded receipt boundaries', () => {
  const bundle = readyCanary('receipt-clones');
  const assignment = assignmentFor(bundle);
  const admission = issueAdmission(bundle, assignment, 'subject');
  const start = prepareStart(bundle, admission, 'run');
  assert.throws(
    () =>
      recordCanaryRunStartReceipt(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        structuredClone(admission.receipt),
        start.input,
      ),
    /guarded public admission receipt/,
  );

  const realStart = issueStart(bundle, admission, 'real-run');
  const completion = prepareCompletion(bundle, realStart, 'real-run');
  assert.throws(
    () =>
      recordCanaryRunCompletionReceipt(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        structuredClone(realStart.receipt),
        completion.input,
      ),
    /guarded public run start receipt/,
  );
});

test('public capability predicates reject receipts issued only by the internal core', () => {
  const bundle = readyCanary('receipt-core-boundary');
  const assignment = assignmentFor(bundle);
  const prepared = prepareAdmission(bundle, assignment, 'core-only');
  const coreOnly = createCanaryAdmissionReceiptCore(
    bundle.fixture.events(),
    bundle.plan,
    bundle.review,
    prepared.input,
  );
  assert.equal(isIssuedCanaryAdmissionReceiptCore(coreOnly), true);
  assert.equal(isIssuedCanaryAdmissionReceipt(coreOnly), false);

  const start = prepareStart(bundle, { receipt: coreOnly }, 'core-only');
  assert.throws(
    () =>
      recordCanaryRunStartReceipt(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        coreOnly,
        start.input,
      ),
    /guarded public admission receipt/,
  );
});

test('current privacy overlays receipt-time historical availability', () => {
  const bundle = readyCanary('receipt-privacy');
  const assignment = assignmentFor(bundle);
  const prepared = prepareAdmission(bundle, assignment, 'privacy');
  const admittedAt = prepared.input.admittedAt;
  bundle.fixture.time = Math.max(bundle.fixture.time, admittedAt + 1);
  bundle.fixture.restrict(prepared.evidence);
  const input = {
    ...prepared.input,
    admittedAt,
    canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
  };
  assert.throws(
    () => createCanaryAdmissionReceipt(bundle.fixture.events(), bundle.plan, bundle.review, input),
    /not currently available/,
  );
});

test('admission ID and assignment registries fail atomically', () => {
  const bundle = readyCanary('receipt-admission-atomicity');
  const firstAssignment = assignmentFor(bundle, undefined, 0);
  const secondAssignment = assignmentFor(bundle, undefined, 1);
  const first = issueAdmission(bundle, firstAssignment, 'first');

  const sameId = prepareAdmission(bundle, secondAssignment, 'second');
  sameId.input.id = first.input.id;
  assert.throws(
    () => createCanaryAdmissionReceipt(bundle.fixture.events(), bundle.plan, bundle.review, sameId.input),
    /admission id conflicts/,
  );

  const acceptedSecond = createCanaryAdmissionReceipt(
    bundle.fixture.events(),
    bundle.plan,
    bundle.review,
    { ...sameId.input, id: `${bundle.fixture.prefix}/admission/second-valid` },
  );
  assert.equal(acceptedSecond.assignmentDigest, secondAssignment.assignmentDigest);

  const sameAssignment = prepareAdmission(bundle, assignmentFor(bundle, undefined, 2), 'third');
  sameAssignment.input.assignmentDigest = firstAssignment.assignmentDigest;
  sameAssignment.input.subjectDigest = firstAssignment.subjectDigest;
  assert.throws(
    () => createCanaryAdmissionReceipt(bundle.fixture.events(), bundle.plan, bundle.review, sameAssignment.input),
    /admitted assignment conflicts/,
  );
});

test('process-local exact retries remain bound to their original canonical snapshot', () => {
  const bundle = readyCanary('receipt-snapshot-bound-retry');
  const admission = issueAdmission(bundle, assignmentFor(bundle), 'subject');
  captureReceiptEvidence(
    bundle,
    'unrelated-tail-event',
    sha(`${bundle.fixture.prefix}/unrelated-tail-event`),
    `${bundle.fixture.prefix}/unrelated-tail-source`,
  );

  assert.throws(
    () =>
      createCanaryAdmissionReceipt(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        admission.input,
      ),
    /canonical fingerprint is stale or forged/,
  );

  assert.throws(
    () =>
      createCanaryAdmissionReceipt(
        bundle.fixture.events(),
        bundle.plan,
        bundle.review,
        {
          ...admission.input,
          canonicalFingerprint: fingerprintMemoryEvents(bundle.fixture.events()),
        },
      ),
    /admission id conflicts/,
  );
});
