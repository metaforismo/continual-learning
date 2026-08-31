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
  buildCanaryFixture,
  issuePlan,
  reviewInput,
  sha,
} from './bounded-canary-fixture.mjs';

function readyCanary(prefix) {
  const bundle = buildCanaryFixture(prefix);
  const plan = issuePlan(bundle);
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
  const runnerGroup = `${bundle.fixture.prefix}/receipt-source/runner/${suffix}`;
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
    /planned component source family/,
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

test('completion closes an active slot and exposes cumulative limit breaches', () => {
  const bundle = readyCanary('receipt-completion');
  const a = issueAdmission(bundle, assignmentFor(bundle, undefined, 0), 'a');
  const b = issueAdmission(bundle, assignmentFor(bundle, undefined, 1), 'b');
  const startA = issueStart(bundle, a, 'a');
  const startB = issueStart(bundle, b, 'b');
  const completionA = issueCompletion(bundle, startA, 'a', { costMicrounits: 60_000 });
  const completionB = issueCompletion(bundle, startB, 'b', {
    costMicrounits: 50_000,
    toolCalls: bundle.plan.budget.maxToolCalls + 1,
    completedAt: startB.receipt.startedAt + bundle.plan.budget.maxDurationMs + 1,
  });
  assert.equal(isIssuedCanaryRunCompletionReceipt(completionA.receipt), true);
  assert.equal(completionB.receipt.cumulativeCostMicrounits, 110_000);
  assert.deepEqual(completionB.receipt.limitBreaches, ['duration', 'tool-calls', 'plan-cost']);
  assert.equal(completionB.receipt.executionAuthorized, false);
});

test('monitoring observations are declared, monotonic, and observer-bound', () => {
  const bundle = readyCanary('receipt-monitoring');
  const first = issueObservation(bundle, 'quality.failure_rate', 1, 0.1, 1, 'first');
  assert.equal(isIssuedCanaryMonitoringObservation(first.receipt), true);

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
  assert.equal(receipt.outcome, 'success');
  assert.equal(receipt.runId, completion.receipt.runId);
  assert.equal(receipt.procedurePromotionAuthorized, false);
  assert.equal(receipt.hostSchedulingAuthorized, false);
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
