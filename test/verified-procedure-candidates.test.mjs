import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createVerifiedProcedureCandidate,
  evidenceRefFor,
  fingerprintMemoryEvents,
  isIssuedVerifiedProcedureCandidate,
} from '../dist/index.js';
import { createValidatedApplicability, sha } from './learning-fixtures.mjs';

function procedureFixture(prefix) {
  const { scenario, applicability } = createValidatedApplicability(prefix);
  const goal = scenario.captureEvidence('procedure/goal', `source/${prefix}/goal`, {
    kind: 'document',
    authority: 'external-source',
  });
  const shared = scenario.captureEvidence('procedure/shared', `source/${prefix}/shared`, {
    kind: 'document',
    authority: 'external-source',
  });
  const inspect = scenario.captureEvidence('procedure/inspect', `source/${prefix}/inspect`, {
    kind: 'document',
    authority: 'external-source',
  });
  const mutate = scenario.captureEvidence('procedure/mutate', `source/${prefix}/mutate`, {
    kind: 'test-result',
    authority: 'tool-verified',
  });
  const verify = scenario.captureEvidence('procedure/verify', `source/${prefix}/verify`, {
    kind: 'test-result',
    authority: 'tool-verified',
  });
  const dependencyNode = scenario.captureEvidence(
    'procedure/dependency-node',
    `source/${prefix}/dependency-node`,
    { kind: 'tool-result', authority: 'external-source' },
  );
  const dependencyPolicy = scenario.captureEvidence(
    'procedure/dependency-policy',
    `source/${prefix}/dependency-policy`,
    { kind: 'document', authority: 'tool-verified' },
  );
  const verifier = scenario.captureEvidence('procedure/verifier', `source/${prefix}/verifier`, {
    kind: 'test-result',
    authority: 'tool-verified',
  });
  const checkpoint = scenario.captureEvidence(
    'procedure/checkpoint',
    `source/${prefix}/checkpoint`,
    { kind: 'environment-transition', authority: 'tool-verified' },
  );
  const contraindicationProd = scenario.captureEvidence(
    'procedure/contraindication-prod',
    `source/${prefix}/contraindication-prod`,
    { kind: 'document', authority: 'external-source' },
  );
  const contraindicationNoTests = scenario.captureEvidence(
    'procedure/contraindication-no-tests',
    `source/${prefix}/contraindication-no-tests`,
    { kind: 'document', authority: 'tool-verified' },
  );
  const records = {
    goal,
    shared,
    inspect,
    mutate,
    verify,
    dependencyNode,
    dependencyPolicy,
    verifier,
    checkpoint,
    contraindicationProd,
    contraindicationNoTests,
  };
  const input = {
    id: `procedure-candidate/${prefix}`,
    procedureId: `procedure/${prefix}`,
    version: '1.0.0',
    name: 'Repair stateful authentication races',
    goalSignature: 'repair a stateful authentication race without widening scope',
    goalEvidence: [evidenceRefFor(goal, ['supports'])],
    rationale: 'Held-out attribution supports this bounded procedure only in the validated context.',
    steps: [
      {
        id: 'inspect-state',
        kind: 'inspect',
        instruction: 'Inspect the current authentication state transition and reproduce the race.',
        expectedOutcome: 'A deterministic failing state transition is identified.',
        evidence: [
          evidenceRefFor(shared, ['supports']),
          evidenceRefFor(inspect, ['supports']),
        ],
      },
      {
        id: 'apply-guard',
        kind: 'mutate',
        instruction: 'Apply the smallest state-transition guard that removes the reproduced race.',
        expectedOutcome: 'The guarded transition preserves the authorized state boundary.',
        dependsOn: ['inspect-state'],
        evidence: [
          evidenceRefFor(shared, ['supports']),
          evidenceRefFor(mutate, ['supports']),
        ],
      },
      {
        id: 'verify-guard',
        kind: 'verify',
        instruction: 'Run the exact regression verifier against the guarded transition.',
        expectedOutcome: 'The race is absent and the authorized behavior remains unchanged.',
        dependsOn: ['inspect-state', 'apply-guard'],
        evidence: [
          evidenceRefFor(shared, ['supports']),
          evidenceRefFor(verify, ['verifies']),
        ],
      },
    ],
    dependencies: [
      {
        id: 'node-runtime',
        kind: 'tool',
        versionDigest: dependencyNode.artifact.digest,
        evidence: [evidenceRefFor(dependencyNode, ['verifies'])],
      },
      {
        id: 'auth-policy',
        kind: 'policy',
        versionDigest: dependencyPolicy.artifact.digest,
        evidence: [evidenceRefFor(dependencyPolicy, ['verifies'])],
      },
    ],
    contraindications: [
      {
        id: 'production-without-canary',
        condition: 'Do not apply directly to production without an independently reviewed canary.',
        evidence: [evidenceRefFor(contraindicationProd, ['constrains'])],
      },
      {
        id: 'missing-regression-verifier',
        condition: 'Do not apply when the exact regression verifier is unavailable.',
        evidence: [evidenceRefFor(contraindicationNoTests, ['verifies'])],
      },
    ],
    risk: 'medium',
    verification: {
      verificationStepId: 'verify-guard',
      verifier: 'test',
      verifierDigest: verifier.artifact.digest,
      evidence: [evidenceRefFor(verifier, ['verifies'])],
      successCriteria: ['authorized behavior remains unchanged', 'race reproduction no longer fails'],
      failureCriteria: ['authorization boundary widens', 'race remains reproducible'],
      timeoutMs: 60_000,
      maxAttempts: 2,
      onFailure: 'quarantine',
    },
    rollback: {
      strategy: 'restore-checkpoint',
      instructions: 'Restore the exact pre-change checkpoint and rerun the regression verifier.',
      evidence: [evidenceRefFor(checkpoint, ['verifies'])],
      checkpointDigest: checkpoint.artifact.digest,
    },
    canonicalFingerprint: fingerprintMemoryEvents(scenario.events()),
    actor: 'procedure-learning-controller',
    recordedAt: scenario.time + 1,
  };
  return { scenario, applicability, records, input };
}

function issue(fixture, overrides = {}) {
  const input = {
    ...structuredClone(fixture.input),
    ...overrides,
  };
  return createVerifiedProcedureCandidate(
    fixture.scenario.events(),
    fixture.applicability,
    input,
  );
}

test('a validated applicability boundary yields an immutable, provenance-complete, non-executable candidate', () => {
  const fixture = procedureFixture('procedure-happy');
  const candidate = issue(fixture);

  assert.equal(candidate.status, 'candidate');
  assert.equal(candidate.executable, false);
  assert.equal(candidate.procedurePromotionAuthorized, false);
  assert.equal(candidate.canaryPlanAuthorized, false);
  assert.equal(candidate.executionAuthorized, false);
  assert.equal(candidate.risk, 'medium');
  assert.equal(candidate.steps.length, 3);
  assert.equal(candidate.dependencies.length, 2);
  assert.equal(candidate.contraindications.length, 2);
  assert.deepEqual(candidate.steps[2].dependsOn, ['apply-guard', 'inspect-state']);
  assert.equal(candidate.steps.every((step) => step.exclusiveEvidenceSourceIds.length > 0), true);
  assert.equal(candidate.dependencies.every((dependency) => dependency.evidence.length > 0), true);
  assert.equal(candidate.verification.evidence[0].contentHash, fixture.records.verifier.artifact.digest);
  assert.equal(candidate.rollback.checkpointDigest, fixture.records.checkpoint.artifact.digest);
  assert.deepEqual(
    candidate.applicability.discoveryObservationIds,
    fixture.applicability.discoveryObservationIds,
  );
  assert.deepEqual(
    candidate.applicability.excludedValidationObservationIds,
    fixture.applicability.excludedValidationObservationIds,
  );
  assert.equal(
    candidate.applicability.validationAssessmentDigest,
    fixture.applicability.validationAssessmentDigest,
  );
  assert.equal(
    fixture.applicability.discoverySourceGroups.every((group) =>
      candidate.sourceGroups.includes(group),
    ),
    true,
  );
  assert.equal(
    fixture.applicability.validationSourceGroups.every((group) =>
      candidate.sourceGroups.includes(group),
    ),
    true,
  );
  assert.equal(isIssuedVerifiedProcedureCandidate(candidate), true);
  assert.equal(isIssuedVerifiedProcedureCandidate(structuredClone(candidate)), false);
  assert.equal(Object.isFrozen(candidate), true);
  assert.equal(Object.isFrozen(candidate.steps), true);
  assert.equal(Object.isFrozen(candidate.steps[0].evidence), true);
  assert.match(candidate.candidateDigest, /^sha256:[0-9a-f]{64}$/);

  const retry = issue(fixture);
  assert.strictEqual(retry, candidate);
});

test('semantically unordered evidence, dependencies, contraindications, criteria, and dependency edges are canonicalized', () => {
  const fixture = procedureFixture('procedure-order');
  const first = issue(fixture);
  const reordered = structuredClone(fixture.input);
  reordered.goalEvidence.reverse();
  reordered.steps = reordered.steps.map((step) => ({
    ...step,
    evidence: [...step.evidence].reverse(),
    ...(step.dependsOn === undefined ? {} : { dependsOn: [...step.dependsOn].reverse() }),
  }));
  reordered.dependencies.reverse();
  reordered.contraindications.reverse();
  reordered.verification.evidence.reverse();
  reordered.verification.successCriteria.reverse();
  reordered.verification.failureCriteria.reverse();
  reordered.rollback.evidence.reverse();

  const second = createVerifiedProcedureCandidate(
    fixture.scenario.events(),
    fixture.applicability,
    reordered,
  );
  assert.strictEqual(second, first);
});

test('candidate id and immutable procedure version registries commit atomically', () => {
  const fixture = procedureFixture('procedure-atomic-registry');
  const first = issue(fixture);
  const conflicting = {
    ...structuredClone(fixture.input),
    id: `${fixture.input.id}/second`,
    name: 'Conflicting contents for the same immutable version',
  };
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        fixture.scenario.events(),
        fixture.applicability,
        conflicting,
      ),
    /procedure version conflicts/,
  );

  const repaired = {
    ...conflicting,
    version: '1.0.1',
  };
  const second = createVerifiedProcedureCandidate(
    fixture.scenario.events(),
    fixture.applicability,
    repaired,
  );
  assert.equal(second.id, repaired.id);
  assert.equal(second.version, '1.0.1');
  assert.notEqual(second.candidateDigest, first.candidateDigest);

  const sameIdNewVersion = {
    ...structuredClone(fixture.input),
    version: '2.0.0',
    name: 'Conflicting contents for one candidate id',
  };
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        fixture.scenario.events(),
        fixture.applicability,
        sameIdNewVersion,
      ),
    /procedure candidate id conflicts/,
  );
  const alternateIdentity = {
    ...sameIdNewVersion,
    id: `${fixture.input.id}/third`,
  };
  const third = createVerifiedProcedureCandidate(
    fixture.scenario.events(),
    fixture.applicability,
    alternateIdentity,
  );
  assert.equal(third.version, '2.0.0');
  assert.equal(third.id, alternateIdentity.id);
});

test('public candidate inputs are snapshotted once and malformed JSON fails closed', () => {
  const once = procedureFixture('procedure-single-read');
  const request = structuredClone(once.input);
  let nameReads = 0;
  Object.defineProperty(request, 'name', {
    enumerable: true,
    configurable: true,
    get() {
      nameReads += 1;
      return 'Single-read procedure candidate';
    },
  });
  const candidate = createVerifiedProcedureCandidate(
    once.scenario.events(),
    once.applicability,
    request,
  );
  assert.equal(candidate.name, 'Single-read procedure candidate');
  assert.equal(nameReads, 1);

  const circular = procedureFixture('procedure-circular-input');
  const circularInput = structuredClone(circular.input);
  circularInput.self = circularInput;
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        circular.scenario.events(),
        circular.applicability,
        circularInput,
      ),
    /circular reference/,
  );

  const sparse = procedureFixture('procedure-sparse-input');
  const sparseInput = structuredClone(sparse.input);
  const sparseSteps = new Array(3);
  sparseSteps[0] = sparseInput.steps[0];
  sparseSteps[2] = sparseInput.steps[2];
  sparseInput.steps = sparseSteps;
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        sparse.scenario.events(),
        sparse.applicability,
        sparseInput,
      ),
    /sparse array/,
  );
});

test('candidate collections and immutable versions are bounded before deeper semantic work', () => {
  const version = procedureFixture('procedure-bounded-version');
  assert.throws(
    () => issue(version, { version: `${'1'.repeat(129)}.0.0` }),
    /procedure version must be non-empty well-formed text within 128 characters/,
  );

  const steps = procedureFixture('procedure-bounded-steps');
  const stepsInput = structuredClone(steps.input);
  stepsInput.steps = Array.from({ length: 33 }, (_, index) => ({
    ...stepsInput.steps[0],
    id: `step-${index}`,
  }));
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        steps.scenario.events(),
        steps.applicability,
        stepsInput,
      ),
    /requires 2\.\.32 ordered steps/,
  );

  const dependencies = procedureFixture('procedure-bounded-dependencies');
  const dependencyInput = structuredClone(dependencies.input);
  dependencyInput.dependencies = Array.from({ length: 65 }, (_, index) => ({
    ...dependencyInput.dependencies[0],
    id: `dependency-${index}`,
  }));
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        dependencies.scenario.events(),
        dependencies.applicability,
        dependencyInput,
      ),
    /dependencies cannot exceed 64/,
  );

  const contraindications = procedureFixture('procedure-bounded-contraindications');
  const contraindicationInput = structuredClone(contraindications.input);
  contraindicationInput.contraindications = Array.from({ length: 33 }, (_, index) => ({
    ...contraindicationInput.contraindications[0],
    id: `contraindication-${index}`,
  }));
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        contraindications.scenario.events(),
        contraindications.applicability,
        contraindicationInput,
      ),
    /contraindications cannot exceed 32/,
  );
});

test('an unissued applicability clone is rejected before its properties can execute', () => {
  const fixture = procedureFixture('procedure-forged-applicability');
  let propertyReads = 0;
  const forged = new Proxy(
    {},
    {
      get() {
        propertyReads += 1;
        throw new Error('forged getter executed');
      },
    },
  );
  assert.throws(
    () => createVerifiedProcedureCandidate(fixture.scenario.events(), forged, fixture.input),
    /issued applicability validation capability/,
  );
  assert.equal(propertyReads, 0);
});

test('candidate identity is bound to the current canonical tail and cannot be stale or backdated', () => {
  const stale = procedureFixture('procedure-stale');
  assert.throws(
    () => issue(stale, { canonicalFingerprint: sha('stale-canonical-prefix') }),
    /canonical fingerprint is stale or forged/,
  );

  const backdated = procedureFixture('procedure-backdated');
  const latest = backdated.scenario.events().at(-1).recordedAt;
  assert.throws(
    () => issue(backdated, { recordedAt: latest - 1 }),
    /cannot be backdated before the canonical tail/,
  );
});

test('dependency, verifier, and checkpoint digests require exact authoritative evidence bindings', () => {
  const dependency = procedureFixture('procedure-dependency-digest');
  const dependencyInput = structuredClone(dependency.input);
  dependencyInput.dependencies[0].versionDigest = sha('wrong dependency version');
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        dependency.scenario.events(),
        dependency.applicability,
        dependencyInput,
      ),
    /dependency .* declared digest/,
  );

  const verifier = procedureFixture('procedure-verifier-digest');
  const verifierInput = structuredClone(verifier.input);
  verifierInput.verification.verifierDigest = sha('wrong verifier version');
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        verifier.scenario.events(),
        verifier.applicability,
        verifierInput,
      ),
    /procedure verifier requires verifies evidence/,
  );

  const checkpoint = procedureFixture('procedure-checkpoint-digest');
  const checkpointInput = structuredClone(checkpoint.input);
  checkpointInput.rollback.checkpointDigest = sha('wrong checkpoint');
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        checkpoint.scenario.events(),
        checkpoint.applicability,
        checkpointInput,
      ),
    /rollback checkpoint requires verifies evidence/,
  );
});

test('goal, step, and rollback evidence require positive support rather than constraints alone', () => {
  const goal = procedureFixture('procedure-constrained-goal');
  const goalInput = structuredClone(goal.input);
  goalInput.goalEvidence = [evidenceRefFor(goal.records.goal, ['constrains'])];
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        goal.scenario.events(),
        goal.applicability,
        goalInput,
      ),
    /procedure goal requires supports or verifies evidence/,
  );

  const step = procedureFixture('procedure-constrained-step');
  const stepInput = structuredClone(step.input);
  stepInput.steps[0].evidence = [evidenceRefFor(step.records.inspect, ['constrains'])];
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        step.scenario.events(),
        step.applicability,
        stepInput,
      ),
    /step inspect-state requires supports or verifies evidence/,
  );

  const rollback = procedureFixture('procedure-constrained-rollback');
  const rollbackInput = structuredClone(rollback.input);
  rollbackInput.rollback.evidence = [
    evidenceRefFor(rollback.records.checkpoint, ['constrains']),
  ];
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        rollback.scenario.events(),
        rollback.applicability,
        rollbackInput,
      ),
    /rollback requires supports or verifies evidence/,
  );
});

test('step evidence cannot be contextual, contradictory, weakly verified, or generic across every step', () => {
  const contextual = procedureFixture('procedure-context-only');
  const contextualInput = structuredClone(contextual.input);
  contextualInput.steps[0].evidence = [
    evidenceRefFor(contextual.records.inspect, ['context']),
  ];
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        contextual.scenario.events(),
        contextual.applicability,
        contextualInput,
      ),
    /context-only or contradicting evidence/,
  );

  const weakVerify = procedureFixture('procedure-weak-verify');
  const weakInput = structuredClone(weakVerify.input);
  weakInput.steps[2].evidence = [
    evidenceRefFor(weakVerify.records.verify, ['supports']),
  ];
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        weakVerify.scenario.events(),
        weakVerify.applicability,
        weakInput,
      ),
    /requires evidence with the verifies role/,
  );

  const generic = procedureFixture('procedure-generic-evidence');
  const genericInput = structuredClone(generic.input);
  const genericReference = evidenceRefFor(generic.records.shared, ['supports']);
  genericInput.steps = genericInput.steps.map((step) => ({
    ...step,
    evidence:
      step.kind === 'verify'
        ? [genericReference, evidenceRefFor(generic.records.verify, ['verifies'])]
        : [genericReference],
  }));
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        generic.scenario.events(),
        generic.applicability,
        genericInput,
      ),
    /step .* requires a step-exclusive evidence anchor/,
  );
});

test('verification criteria are disjoint and the final verifier covers every prior step', () => {
  const overlap = procedureFixture('procedure-overlap-criteria');
  const overlapInput = structuredClone(overlap.input);
  overlapInput.verification.failureCriteria = [
    overlapInput.verification.successCriteria[0],
    ...overlapInput.verification.failureCriteria,
  ];
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        overlap.scenario.events(),
        overlap.applicability,
        overlapInput,
      ),
    /success and failure criteria overlap/,
  );

  const uncovered = procedureFixture('procedure-uncovered-step');
  const uncoveredInput = structuredClone(uncovered.input);
  uncoveredInput.steps[2].dependsOn = ['apply-guard'];
  uncoveredInput.steps[1].dependsOn = [];
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        uncovered.scenario.events(),
        uncovered.applicability,
        uncoveredInput,
      ),
    /does not cover every prior step/,
  );
});

test('mutating candidates cannot underdeclare risk or use a non-reverting rollback', () => {
  const lowRisk = procedureFixture('procedure-low-risk-mutation');
  assert.throws(
    () => issue(lowRisk, { risk: 'low' }),
    /mutate steps require medium risk or stronger/,
  );

  const noRollback = procedureFixture('procedure-disable-only-mutation');
  const rollback = {
    strategy: 'disable-candidate',
    instructions: 'Disable the candidate.',
    evidence: [evidenceRefFor(noRollback.records.checkpoint, ['verifies'])],
  };
  assert.throws(
    () => issue(noRollback, { rollback }),
    /mutate steps require restore-checkpoint or manual rollback/,
  );
});

test('a human verifier requires an exact human-explicit report rather than a stronger-looking policy label', () => {
  const fixture = procedureFixture('procedure-human-verifier-authority');
  const policyVerifier = fixture.scenario.captureEvidence(
    'procedure/policy-verifier',
    `source/${fixture.scenario.prefix}/policy-verifier`,
    { kind: 'document', authority: 'system-policy' },
  );
  const input = structuredClone(fixture.input);
  input.risk = 'high';
  input.verification = {
    ...input.verification,
    verifier: 'human',
    verifierDigest: policyVerifier.artifact.digest,
    evidence: [evidenceRefFor(policyVerifier, ['verifies'])],
    onFailure: 'human-review',
  };
  input.canonicalFingerprint = fingerprintMemoryEvents(fixture.scenario.events());
  input.recordedAt = fixture.scenario.time + 1;
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        fixture.scenario.events(),
        fixture.applicability,
        input,
      ),
    /exact human-explicit verifier evidence/,
  );
});

test('high and destructive risk remain review-only and never acquire canary or execution authority', () => {
  for (const risk of ['high', 'destructive']) {
    const fixture = procedureFixture(`procedure-${risk}`);
    const humanVerifier = fixture.scenario.captureEvidence(
      'procedure/human-verifier',
      `source/${fixture.scenario.prefix}/human-verifier`,
      { kind: 'human-feedback', authority: 'human-explicit' },
    );
    const input = structuredClone(fixture.input);
    input.risk = risk;
    input.verification = {
      ...input.verification,
      verifier: 'human',
      verifierDigest: humanVerifier.artifact.digest,
      evidence: [evidenceRefFor(humanVerifier, ['verifies'])],
      onFailure: 'human-review',
    };
    input.canonicalFingerprint = fingerprintMemoryEvents(fixture.scenario.events());
    input.recordedAt = fixture.scenario.time + 1;
    const candidate = createVerifiedProcedureCandidate(
      fixture.scenario.events(),
      fixture.applicability,
      input,
    );
    assert.equal(candidate.humanReviewRequired, true);
    assert.equal(candidate.reviewReasons.some((reason) => reason.includes(risk)), true);
    assert.equal(candidate.canaryPlanAuthorized, false);
    assert.equal(candidate.executionAuthorized, false);
  }
});

test('scope, privacy, current availability, and secret evidence remain hard boundaries', () => {
  const crossScope = procedureFixture('procedure-cross-scope');
  const foreign = crossScope.scenario.captureEvidence(
    'procedure/foreign',
    'source/foreign',
    { scope: 'project/another-tenant', kind: 'document', authority: 'external-source' },
  );
  const crossInput = structuredClone(crossScope.input);
  crossInput.goalEvidence = [evidenceRefFor(foreign, ['supports'])];
  crossInput.canonicalFingerprint = fingerprintMemoryEvents(crossScope.scenario.events());
  crossInput.recordedAt = crossScope.scenario.time + 1;
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        crossScope.scenario.events(),
        crossScope.applicability,
        crossInput,
      ),
    /crosses scope/,
  );

  const secretFixture = procedureFixture('procedure-secret');
  const secret = secretFixture.scenario.captureEvidence(
    'procedure/secret',
    'source/secret',
    {
      kind: 'document',
      authority: 'human-explicit',
      sensitivity: 'secret',
      taints: ['secret-detected'],
    },
  );
  const secretInput = structuredClone(secretFixture.input);
  secretInput.goalEvidence = [evidenceRefFor(secret, ['supports'])];
  secretInput.canonicalFingerprint = fingerprintMemoryEvents(secretFixture.scenario.events());
  secretInput.recordedAt = secretFixture.scenario.time + 1;
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        secretFixture.scenario.events(),
        secretFixture.applicability,
        secretInput,
      ),
    /cannot derive a procedure candidate from secret evidence/,
  );

  const restricted = procedureFixture('procedure-restricted');
  restricted.scenario.setAvailability(restricted.records.inspect, 'restricted');
  const restrictedInput = structuredClone(restricted.input);
  restrictedInput.canonicalFingerprint = fingerprintMemoryEvents(restricted.scenario.events());
  restrictedInput.recordedAt = restricted.scenario.time + 1;
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        restricted.scenario.events(),
        restricted.applicability,
        restrictedInput,
      ),
    /unavailable or forged|not currently available/,
  );
});

test('contraindications require authoritative constraining or verifying evidence', () => {
  const fixture = procedureFixture('procedure-contraindication-role');
  const input = structuredClone(fixture.input);
  input.contraindications[0].evidence = [
    evidenceRefFor(fixture.records.contraindicationProd, ['supports']),
  ];
  assert.throws(
    () =>
      createVerifiedProcedureCandidate(
        fixture.scenario.events(),
        fixture.applicability,
        input,
      ),
    /contraindication .* constrains or verifies evidence/,
  );
});
