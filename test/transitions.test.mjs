import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  DEFAULT_TRANSITION_POLICY,
  MemoryKernel,
  TransitionAuditJournal,
  TransitionVerifier,
  adjudicateState,
  evidenceRefFor,
  fingerprintMemoryEvents,
  verifyTransition,
  verifyTransitionResultIntegrity,
} from '../dist/index.js';

function sha(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function evidenceRecord({
  id,
  scope = 'project/demo',
  authority = 'human-explicit',
  kind = 'human-feedback',
  taints = [],
  observedAt = 1,
  sensitivity = 'internal',
  sourceGroup = `${id}-origin`,
} = {}) {
  return {
    id,
    scope,
    kind,
    sourceGroups: [sourceGroup],
    authority,
    observedAt,
    sensitivity,
    taints,
    artifact: {
      uri: `memory://artifact/${id}`,
      digest: sha(`artifact:${id}`),
      sizeBytes: 1,
      mediaType: 'application/json',
      encryption: sensitivity === 'sensitive' || sensitivity === 'secret'
        ? 'provider-managed'
        : 'none',
      retention: 'durable',
    },
    derivedFrom: [],
    labels: ['transition-test'],
  };
}

function capture(kernel, record, recordedAt, actor = 'source-ingestor') {
  kernel.captureEvidence(
    { eventId: `capture:${record.id}`, recordedAt, actor },
    record,
  );
}

function claimFromEvidence(record, {
  id = `claim:${record.id}`,
  value = 'zed',
  validFrom = 10,
  predicate = 'preferred-editor',
  authority = record.authority,
  epistemicStatus = 'observed',
} = {}) {
  return {
    id,
    key: { scope: record.scope, subject: 'francesco', predicate },
    value,
    valid: { from: validFrom },
    authority,
    epistemicStatus,
    confidence: 1,
    evidence: [evidenceRefFor(record, ['supports'])],
    derivedFrom: [],
    tags: ['transition-test'],
  };
}

const editorSchema = Object.freeze({
  id: 'user-preferences',
  version: '1',
  slots: Object.freeze([
    Object.freeze({
      id: 'preferred-editor',
      domain: 'personal-preference',
      key: Object.freeze({
        scope: 'project/demo',
        subject: 'francesco',
        predicate: 'preferred-editor',
      }),
      strategy: 'role-authority',
      evidencePolicy: Object.freeze([
        Object.freeze({
          role: 'supports',
          authorityPrecedence: Object.freeze([
            'human-explicit',
            'tool-verified',
            'external-source',
            'repeated-observation',
            'model-inference',
          ]),
          required: true,
        }),
      ]),
      minimumConfidence: 0.8,
    }),
  ]),
});

const residenceSchema = Object.freeze({
  id: 'residence-state',
  version: '1',
  slots: Object.freeze([
    Object.freeze({
      id: 'residence',
      domain: 'location',
      key: Object.freeze({
        scope: 'project/demo',
        subject: 'francesco',
        predicate: 'residence',
      }),
      strategy: 'require-agreement',
      evidencePolicy: Object.freeze([
        Object.freeze({
          role: 'supports',
          authorityPrecedence: Object.freeze(['human-explicit']),
          required: true,
        }),
      ]),
    }),
  ]),
});

function stateExpectation({
  id = 'editor-transition',
  schema = editorSchema,
  slotId = 'preferred-editor',
  mode = 'change',
  validAt = 20,
  before,
  after,
} = {}) {
  return {
    id,
    schema,
    request: { slotId, view: 'current', validAt },
    mode,
    ...(before === undefined ? {} : { before }),
    ...(after === undefined ? {} : { after }),
  };
}

function verifierIdentity({
  id = 'transition-verifier',
  actor = 'transition-verifier',
  kind = 'deterministic',
  implementation = 'transition-verifier-v1',
  version = '1',
} = {}) {
  return {
    id,
    actor,
    kind,
    implementation,
    version,
    configDigest: sha(`config:${id}:${version}`),
  };
}

function externalCheck({
  proposalId,
  record,
  kind = 'semantic-faithfulness',
  id = `${kind}:${proposalId}`,
  verifier = verifierIdentity({
    id: `${kind}-checker`,
    actor: `${kind}-checker`,
    kind: 'tool',
    implementation: kind,
  }),
  status = 'pass',
  roles = ['verifies'],
  reportDigest = record.artifact.digest,
} = {}) {
  return {
    id,
    kind,
    status,
    verifier,
    subjectIds: [proposalId],
    reportDigest,
    evidence: [evidenceRefFor(record, roles)],
  };
}

function proposalFor(kernel, overrides = {}) {
  return {
    id: 'transition-1',
    proposer: 'memory-writer',
    baseFingerprint: fingerprintMemoryEvents(kernel.events()),
    authorizedScopes: ['project/demo'],
    declaredRisk: 'low',
    stateImpact: 'none',
    operations: [],
    inputEvidenceIds: [],
    ignoredInputEvidence: [],
    externalChecks: [],
    stateExpectations: [],
    rationale: 'exercise the transition verification contract',
    ...overrides,
  };
}

function activeClaimProposal(kernel, {
  proposalId = 'activate-editor',
  support,
  report,
  claim = claimFromEvidence(support),
  checks,
  stateImpact = 'declared',
  expectations = [stateExpectation({
    before: { status: 'unknown' },
    after: { status: 'current', value: claim.value },
  })],
  declaredRisk = 'high',
} = {}) {
  const externalChecks = checks ?? [externalCheck({ proposalId, record: report })];
  return proposalFor(kernel, {
    id: proposalId,
    declaredRisk,
    stateImpact,
    operations: [
      {
        id: `assert:${claim.id}`,
        type: 'claim.asserted',
        recordedAt: 10,
        actor: 'memory-writer',
        data: { claim, initialLifecycle: 'active' },
      },
    ],
    inputEvidenceIds: [
      ...new Set([
        support.id,
        ...externalChecks.flatMap((check) => check.evidence.map((reference) => reference.sourceId)),
      ]),
    ],
    externalChecks,
    stateExpectations: expectations,
  });
}

function findingCodes(result) {
  return new Set(result.findings.map((item) => item.code));
}

test('a low-risk raw evidence capture verifies and commits atomically without mutating the original kernel', () => {
  const kernel = new MemoryKernel();
  const record = evidenceRecord({ id: 'raw-observation' });
  const proposal = proposalFor(kernel, {
    operations: [
      {
        id: 'capture-raw-observation',
        type: 'evidence.captured',
        recordedAt: 1,
        actor: 'source-ingestor',
        data: { evidence: record },
      },
    ],
    inputEvidenceIds: [record.id],
  });

  const runtime = new TransitionVerifier(verifierIdentity());
  const result = runtime.verify(kernel.events(), proposal);
  assert.equal(result.verdict, 'accept');
  assert.equal(result.stagedAppend?.length, 1);
  assert.equal(kernel.events().length, 0);
  assert.equal(verifyTransitionResultIntegrity(result), true);

  const committed = runtime.commit(kernel, result);
  assert.equal(kernel.events().length, 0);
  assert.equal(committed.events().length, 1);
  assert.equal(committed.evidence(record.id)?.availability, 'available');
});

test('transition results are deterministic while commits require the exact issued object', () => {
  const kernel = new MemoryKernel();
  const record = evidenceRecord({ id: 'deterministic-observation' });
  const proposal = proposalFor(kernel, {
    id: 'deterministic-transition',
    operations: [
      {
        id: 'capture-deterministic-observation',
        type: 'evidence.captured',
        recordedAt: 1,
        actor: 'source-ingestor',
        data: { evidence: record },
      },
    ],
    inputEvidenceIds: [record.id],
  });

  const runtime = new TransitionVerifier(verifierIdentity());
  const first = runtime.verify(kernel.events(), proposal);
  const second = runtime.verify(kernel.events(), proposal);
  assert.equal(first.resultDigest, second.resultDigest);
  assert.equal(first.appendFingerprint, second.appendFingerprint);

  const copied = structuredClone(first);
  assert.equal(verifyTransitionResultIntegrity(copied), true);
  assert.throws(
    () => runtime.commit(kernel, copied),
    /not issued by this verifier runtime/,
  );
});

test('a multi-event staging failure leaves no partial append in the original kernel', () => {
  const kernel = new MemoryKernel();
  const record = evidenceRecord({ id: 'partial-observation' });
  const missingRef = {
    sourceId: 'missing-evidence',
    sourceGroups: ['missing-origin'],
    authority: 'human-explicit',
    contentHash: sha('missing'),
    roles: ['supports'],
  };
  const invalidClaim = {
    ...claimFromEvidence(record, { id: 'invalid-claim' }),
    evidence: [missingRef],
  };
  const proposal = proposalFor(kernel, {
    id: 'partial-transition',
    declaredRisk: 'high',
    stateImpact: 'unknown',
    operations: [
      {
        id: 'capture-partial-observation',
        type: 'evidence.captured',
        recordedAt: 1,
        actor: 'source-ingestor',
        data: { evidence: record },
      },
      {
        id: 'assert-invalid-claim',
        type: 'claim.asserted',
        recordedAt: 2,
        actor: 'memory-writer',
        data: { claim: invalidClaim, initialLifecycle: 'active' },
      },
    ],
    inputEvidenceIds: [record.id],
  });

  const result = verifyTransition(kernel.events(), proposal, verifierIdentity());
  assert.equal(result.verdict, 'reject');
  assert.equal(result.stagedAppend, undefined);
  assert.equal(kernel.events().length, 0);
  assert.ok(findingCodes(result).has('transition-semantic-replay-failed'));
});

test('new evidence must be declared as transition input', () => {
  const kernel = new MemoryKernel();
  const record = evidenceRecord({ id: 'undeclared-input' });
  const proposal = proposalFor(kernel, {
    id: 'missing-input-declaration',
    operations: [
      {
        id: 'capture-undeclared-input',
        type: 'evidence.captured',
        recordedAt: 1,
        actor: 'source-ingestor',
        data: { evidence: record },
      },
    ],
  });

  const result = verifyTransition(kernel.events(), proposal, verifierIdentity());
  assert.equal(result.verdict, 'reject');
  assert.ok(findingCodes(result).has('transition-new-evidence-not-declared-as-input'));
});

test('every supplied input is either used or explicitly ignored with a reason', () => {
  const kernel = new MemoryKernel();
  const used = evidenceRecord({ id: 'used-input' });
  const ignored = evidenceRecord({ id: 'ignored-input' });
  capture(kernel, used, 1);
  capture(kernel, ignored, 2);
  const claim = claimFromEvidence(used, { id: 'quarantined-lesson' });
  const proposal = proposalFor(kernel, {
    id: 'explicit-ignore',
    declaredRisk: 'medium',
    operations: [
      {
        id: 'assert-quarantined-lesson',
        type: 'claim.asserted',
        recordedAt: 3,
        actor: 'memory-writer',
        data: { claim, initialLifecycle: 'quarantined' },
      },
    ],
    inputEvidenceIds: [used.id, ignored.id],
    ignoredInputEvidence: [
      { sourceId: ignored.id, reason: 'the second observation concerns another task' },
    ],
  });

  const result = verifyTransition(kernel.events(), proposal, verifierIdentity());
  assert.equal(result.verdict, 'accept');
  assert.deepEqual(result.delta?.createdClaims, [
    { claimId: claim.id, lifecycle: 'quarantined' },
  ]);
});

test('the proposal cannot verify itself', () => {
  const kernel = new MemoryKernel();
  const record = evidenceRecord({ id: 'self-verified' });
  const proposal = proposalFor(kernel, {
    id: 'self-verification',
    operations: [
      {
        id: 'capture-self-verified',
        type: 'evidence.captured',
        recordedAt: 1,
        actor: 'source-ingestor',
        data: { evidence: record },
      },
    ],
    inputEvidenceIds: [record.id],
  });

  const result = verifyTransition(
    kernel.events(),
    proposal,
    verifierIdentity({ actor: proposal.proposer }),
  );
  assert.equal(result.verdict, 'reject');
  assert.ok(findingCodes(result).has('transition-primary-verifier-not-independent'));
});

test('a global write requires explicit global authorization', () => {
  const kernel = new MemoryKernel();
  const record = evidenceRecord({ id: 'global-write', scope: 'global' });
  const proposal = proposalFor(kernel, {
    id: 'unauthorized-global-write',
    operations: [
      {
        id: 'capture-global-write',
        type: 'evidence.captured',
        recordedAt: 1,
        actor: 'source-ingestor',
        data: { evidence: record },
      },
    ],
    inputEvidenceIds: [record.id],
  });

  const result = verifyTransition(kernel.events(), proposal, verifierIdentity());
  assert.equal(result.verdict, 'reject');
  assert.ok(findingCodes(result).has('transition-touched-scope-unauthorized'));
});

test('high-risk active state requires a passing semantic faithfulness check', () => {
  const kernel = new MemoryKernel();
  const support = evidenceRecord({ id: 'editor-support' });
  const report = evidenceRecord({
    id: 'faithfulness-report',
    authority: 'tool-verified',
    kind: 'test-result',
  });
  capture(kernel, support, 1);
  capture(kernel, report, 2, 'semantic-faithfulness-checker');
  const proposal = activeClaimProposal(kernel, {
    proposalId: 'missing-faithfulness',
    support,
    report,
    checks: [],
  });

  const runtime = new TransitionVerifier(verifierIdentity());
  const result = runtime.verify(kernel.events(), proposal);
  assert.equal(result.verdict, 'human-review');
  assert.ok(findingCodes(result).has('transition-required-external-check-missing'));
  assert.throws(() => runtime.commit(kernel, result), /only accepted transitions/);
});

test('an independently verified active state transition commits with exact state assertions', () => {
  const kernel = new MemoryKernel();
  const support = evidenceRecord({ id: 'verified-editor-support' });
  const report = evidenceRecord({
    id: 'verified-faithfulness-report',
    authority: 'tool-verified',
    kind: 'test-result',
  });
  capture(kernel, support, 1);
  capture(kernel, report, 2, 'semantic-faithfulness-checker');
  const claim = claimFromEvidence(support, { id: 'verified-editor-claim' });
  const proposal = activeClaimProposal(kernel, {
    proposalId: 'verified-active-state',
    support,
    report,
    claim,
  });

  const runtime = new TransitionVerifier(verifierIdentity());
  const result = runtime.verify(kernel.events(), proposal);
  assert.equal(result.verdict, 'accept');
  assert.equal(result.stateObservations[0]?.passed, true);
  assert.equal(result.stagedAppend?.length, 1);

  const committed = runtime.commit(kernel, result);
  const decision = adjudicateState(committed.events(), editorSchema, {
    slotId: 'preferred-editor',
    view: 'current',
    validAt: 20,
  });
  assert.equal(decision.status, 'current');
  assert.equal(decision.value, 'zed');
});

test('a semantic check digest must be bound to explicit verifying evidence', () => {
  const kernel = new MemoryKernel();
  const support = evidenceRecord({ id: 'digest-support' });
  const report = evidenceRecord({
    id: 'digest-report',
    authority: 'tool-verified',
    kind: 'test-result',
  });
  capture(kernel, support, 1);
  capture(kernel, report, 2, 'semantic-faithfulness-checker');
  const proposalId = 'unbound-report';
  const proposal = activeClaimProposal(kernel, {
    proposalId,
    support,
    report,
    checks: [
      externalCheck({
        proposalId,
        record: report,
        reportDigest: sha('some-other-report'),
      }),
    ],
  });

  const result = verifyTransition(kernel.events(), proposal, verifierIdentity());
  assert.equal(result.verdict, 'reject');
  assert.ok(findingCodes(result).has('transition-external-check-report-unbound'));
});

test('supportive evidence cannot masquerade as an external verifier report', () => {
  const kernel = new MemoryKernel();
  const support = evidenceRecord({ id: 'role-support' });
  const report = evidenceRecord({
    id: 'role-report',
    authority: 'tool-verified',
    kind: 'test-result',
  });
  capture(kernel, support, 1);
  capture(kernel, report, 2, 'semantic-faithfulness-checker');
  const proposalId = 'wrong-check-role';
  const proposal = activeClaimProposal(kernel, {
    proposalId,
    support,
    report,
    checks: [externalCheck({ proposalId, record: report, roles: ['supports'] })],
  });

  const result = verifyTransition(kernel.events(), proposal, verifierIdentity());
  assert.equal(result.verdict, 'reject');
  assert.ok(findingCodes(result).has('transition-external-check-role-invalid'));
});

test('external checks must name the transition they verify', () => {
  const kernel = new MemoryKernel();
  const support = evidenceRecord({ id: 'subject-support' });
  const report = evidenceRecord({
    id: 'subject-report',
    authority: 'tool-verified',
    kind: 'test-result',
  });
  capture(kernel, support, 1);
  capture(kernel, report, 2, 'semantic-faithfulness-checker');
  const proposalId = 'subject-bound-transition';
  const check = externalCheck({ proposalId, record: report });
  const proposal = activeClaimProposal(kernel, {
    proposalId,
    support,
    report,
    checks: [{ ...check, subjectIds: ['unrelated-object'] }],
  });

  const result = verifyTransition(kernel.events(), proposal, verifierIdentity());
  assert.equal(result.verdict, 'reject');
  assert.ok(findingCodes(result).has('transition-external-check-subject-mismatch'));
});

test('state expectations must cover the actual affected claim key', () => {
  const kernel = new MemoryKernel();
  const support = evidenceRecord({ id: 'coverage-support' });
  const report = evidenceRecord({
    id: 'coverage-report',
    authority: 'tool-verified',
    kind: 'test-result',
  });
  capture(kernel, support, 1);
  capture(kernel, report, 2, 'semantic-faithfulness-checker');
  const proposal = activeClaimProposal(kernel, {
    proposalId: 'wrong-state-expectation',
    support,
    report,
    expectations: [
      stateExpectation({
        id: 'unrelated-residence',
        schema: residenceSchema,
        slotId: 'residence',
        mode: 'preserve',
      }),
    ],
  });

  const result = verifyTransition(kernel.events(), proposal, verifierIdentity());
  assert.equal(result.verdict, 'reject');
  assert.ok(findingCodes(result).has('transition-state-impact-coverage-missing'));
});

test('a preservation assertion catches an unexpected state change', () => {
  const kernel = new MemoryKernel();
  const support = evidenceRecord({ id: 'preservation-support' });
  const report = evidenceRecord({
    id: 'preservation-report',
    authority: 'tool-verified',
    kind: 'test-result',
  });
  capture(kernel, support, 1);
  capture(kernel, report, 2, 'semantic-faithfulness-checker');
  const proposal = activeClaimProposal(kernel, {
    proposalId: 'unexpected-state-change',
    support,
    report,
    expectations: [stateExpectation({ mode: 'preserve' })],
  });

  const result = verifyTransition(kernel.events(), proposal, verifierIdentity());
  assert.equal(result.verdict, 'reject');
  assert.ok(findingCodes(result).has('transition-state-expectation-failed'));
});

test('an active claim cannot deny its state impact', () => {
  const kernel = new MemoryKernel();
  const support = evidenceRecord({ id: 'denied-impact-support' });
  const report = evidenceRecord({
    id: 'denied-impact-report',
    authority: 'tool-verified',
    kind: 'test-result',
  });
  capture(kernel, support, 1);
  capture(kernel, report, 2, 'semantic-faithfulness-checker');
  const proposal = activeClaimProposal(kernel, {
    proposalId: 'denied-state-impact',
    support,
    report,
    stateImpact: 'none',
    expectations: [],
  });

  const result = verifyTransition(kernel.events(), proposal, verifierIdentity());
  assert.equal(result.verdict, 'reject');
  assert.ok(findingCodes(result).has('transition-state-impact-denied'));
});

test('risk under-declaration is rejected', () => {
  const kernel = new MemoryKernel();
  const support = evidenceRecord({ id: 'risk-support' });
  const report = evidenceRecord({
    id: 'risk-report',
    authority: 'tool-verified',
    kind: 'test-result',
  });
  capture(kernel, support, 1);
  capture(kernel, report, 2, 'semantic-faithfulness-checker');
  const proposal = activeClaimProposal(kernel, {
    proposalId: 'underdeclared-risk',
    support,
    report,
    declaredRisk: 'low',
  });

  const result = verifyTransition(kernel.events(), proposal, verifierIdentity());
  assert.equal(result.verdict, 'reject');
  assert.ok(findingCodes(result).has('transition-risk-underdeclared'));
});

test('tainted evidence cannot become active state without a security check', () => {
  const kernel = new MemoryKernel();
  const support = evidenceRecord({
    id: 'tainted-support',
    authority: 'external-source',
    kind: 'document',
    taints: ['external-content', 'prompt-like'],
  });
  const faithfulnessReport = evidenceRecord({
    id: 'tainted-faithfulness-report',
    authority: 'tool-verified',
    kind: 'test-result',
  });
  const securityReport = evidenceRecord({
    id: 'tainted-security-report',
    authority: 'tool-verified',
    kind: 'test-result',
  });
  capture(kernel, support, 1);
  capture(kernel, faithfulnessReport, 2, 'semantic-faithfulness-checker');
  capture(kernel, securityReport, 3, 'security-checker');
  const claim = claimFromEvidence(support, {
    id: 'tainted-active-claim',
    authority: 'external-source',
  });

  const quarantineProposalId = 'tainted-without-security';
  const quarantineProposal = activeClaimProposal(kernel, {
    proposalId: quarantineProposalId,
    support,
    report: faithfulnessReport,
    claim,
    checks: [externalCheck({ proposalId: quarantineProposalId, record: faithfulnessReport })],
  });
  const quarantined = verifyTransition(
    kernel.events(),
    quarantineProposal,
    verifierIdentity(),
  );
  assert.equal(quarantined.verdict, 'quarantine');
  assert.ok(findingCodes(quarantined).has('transition-tainted-active-write'));

  const acceptedProposalId = 'tainted-with-security';
  const acceptedProposal = activeClaimProposal(kernel, {
    proposalId: acceptedProposalId,
    support,
    report: faithfulnessReport,
    claim,
    checks: [
      externalCheck({ proposalId: acceptedProposalId, record: faithfulnessReport }),
      externalCheck({
        proposalId: acceptedProposalId,
        record: securityReport,
        kind: 'security',
        verifier: verifierIdentity({
          id: 'security-checker',
          actor: 'security-checker',
          kind: 'tool',
          implementation: 'security-scan',
        }),
      }),
    ],
  });
  const accepted = verifyTransition(kernel.events(), acceptedProposal, verifierIdentity());
  assert.equal(accepted.verdict, 'accept');
});

test('destructive evidence deletion requires cumulative semantic, security, and human review', () => {
  const kernel = new MemoryKernel();
  const target = evidenceRecord({ id: 'deletion-target' });
  const humanReport = evidenceRecord({
    id: 'deletion-human-report',
    authority: 'human-explicit',
    kind: 'human-feedback',
  });
  capture(kernel, target, 1);
  capture(kernel, humanReport, 2, 'privacy-reviewer');

  const proposalId = 'delete-evidence';
  const makeCheck = (kind) => externalCheck({
    proposalId,
    record: humanReport,
    kind,
    id: `${kind}:delete-evidence`,
    verifier: verifierIdentity({
      id: 'privacy-reviewer',
      actor: 'privacy-reviewer',
      kind: 'human',
      implementation: 'privacy-review',
    }),
  });
  const proposal = proposalFor(kernel, {
    id: proposalId,
    declaredRisk: 'destructive',
    operations: [
      {
        id: 'delete-deletion-target',
        type: 'evidence.availability-changed',
        recordedAt: 3,
        actor: 'privacy-controller',
        data: {
          evidenceId: target.id,
          availability: 'deleted',
          reason: 'approved retention deletion',
        },
      },
    ],
    inputEvidenceIds: [target.id, humanReport.id],
    externalChecks: [
      makeCheck('semantic-faithfulness'),
      makeCheck('semantic-preservation'),
      makeCheck('security'),
    ],
  });

  const runtime = new TransitionVerifier(verifierIdentity());
  const result = runtime.verify(kernel.events(), proposal);
  assert.equal(result.verdict, 'accept');
  const committed = runtime.commit(kernel, result);
  assert.equal(committed.evidence(target.id)?.availability, 'deleted');
});

test('a stale proposal base is rejected and an accepted result cannot commit after concurrent change', () => {
  const empty = new MemoryKernel();
  const firstRecord = evidenceRecord({ id: 'stale-first' });
  const proposal = proposalFor(empty, {
    id: 'stale-transition',
    operations: [
      {
        id: 'capture-stale-first',
        type: 'evidence.captured',
        recordedAt: 1,
        actor: 'source-ingestor',
        data: { evidence: firstRecord },
      },
    ],
    inputEvidenceIds: [firstRecord.id],
  });
  const runtime = new TransitionVerifier(verifierIdentity());
  const accepted = runtime.verify(empty.events(), proposal);
  assert.equal(accepted.verdict, 'accept');

  const changed = new MemoryKernel();
  const concurrent = evidenceRecord({ id: 'concurrent-record' });
  capture(changed, concurrent, 1);
  assert.throws(
    () => runtime.commit(changed, accepted),
    /base is stale/,
  );

  const mismatched = verifyTransition(changed.events(), proposal, verifierIdentity());
  assert.equal(mismatched.verdict, 'reject');
  assert.ok(findingCodes(mismatched).has('transition-base-fingerprint-mismatch'));
});

test('transition policy event allowlists are enforced', () => {
  const kernel = new MemoryKernel();
  const support = evidenceRecord({ id: 'allowlist-support' });
  capture(kernel, support, 1);
  const claim = claimFromEvidence(support, { id: 'allowlist-claim' });
  const proposal = proposalFor(kernel, {
    id: 'disallowed-claim-event',
    declaredRisk: 'medium',
    operations: [
      {
        id: 'assert-allowlist-claim',
        type: 'claim.asserted',
        recordedAt: 2,
        actor: 'memory-writer',
        data: { claim, initialLifecycle: 'quarantined' },
      },
    ],
    inputEvidenceIds: [support.id],
  });
  const policy = {
    ...DEFAULT_TRANSITION_POLICY,
    id: 'evidence-only-policy',
    allowedEventTypes: ['evidence.captured'],
  };

  const runtime = new TransitionVerifier(verifierIdentity(), policy);
  const result = runtime.verify(kernel.events(), proposal);
  assert.equal(result.verdict, 'reject');
  assert.ok(findingCodes(result).has('transition-event-type-disallowed'));
});

test('accepted verdicts retain only the append rather than copying the historical ledger', () => {
  const kernel = new MemoryKernel();
  for (let index = 0; index < 12; index += 1) {
    capture(kernel, evidenceRecord({ id: `history-${index}` }), index + 1);
  }
  const record = evidenceRecord({ id: 'one-more', observedAt: 20 });
  const proposal = proposalFor(kernel, {
    id: 'bounded-verdict-size',
    operations: [
      {
        id: 'capture-one-more',
        type: 'evidence.captured',
        recordedAt: 20,
        actor: 'source-ingestor',
        data: { evidence: record },
      },
    ],
    inputEvidenceIds: [record.id],
  });

  const result = verifyTransition(kernel.events(), proposal, verifierIdentity());
  assert.equal(result.verdict, 'accept');
  assert.equal(result.stagedAppend?.length, 1);
  assert.equal(kernel.events().length, 12);
});

test('the audit journal is append-only, replayable, and content-addressed', () => {
  const kernel = new MemoryKernel();
  const record = evidenceRecord({ id: 'audited-record' });
  const proposal = proposalFor(kernel, {
    id: 'audited-transition',
    operations: [
      {
        id: 'capture-audited-record',
        type: 'evidence.captured',
        recordedAt: 1,
        actor: 'source-ingestor',
        data: { evidence: record },
      },
    ],
    inputEvidenceIds: [record.id],
  });
  const result = verifyTransition(kernel.events(), proposal, verifierIdentity());
  const journal = new TransitionAuditJournal();
  const audit = journal.append(
    { id: 'audit-1', recordedAt: 2, actor: 'transition-auditor' },
    result,
  );

  assert.equal(audit.appendFingerprint, result.appendFingerprint);
  assert.equal(audit.policyDigest, result.policyDigest);
  assert.equal(audit.verifierConfigDigest, result.verifier.configDigest);
  assert.equal(TransitionAuditJournal.from(journal.all()).size, 1);
  assert.throws(
    () => journal.append(
      { id: 'audit-1', recordedAt: 3, actor: 'transition-auditor' },
      result,
    ),
    /unique/,
  );
  assert.throws(
    () => journal.append(
      { id: 'audit-2', recordedAt: 1, actor: 'transition-auditor' },
      result,
    ),
    /monotonic/,
  );
});

test('evidence used by an operation must also be declared as transition input', () => {
  const kernel = new MemoryKernel();
  const support = evidenceRecord({ id: 'undeclared-used-source' });
  capture(kernel, support, 1);
  const claim = claimFromEvidence(support, { id: 'undeclared-used-claim' });
  const proposal = proposalFor(kernel, {
    id: 'undeclared-used-evidence',
    declaredRisk: 'medium',
    operations: [
      {
        id: 'assert-undeclared-used-claim',
        type: 'claim.asserted',
        recordedAt: 2,
        actor: 'memory-writer',
        data: { claim, initialLifecycle: 'quarantined' },
      },
    ],
  });

  const result = verifyTransition(kernel.events(), proposal, verifierIdentity());
  assert.equal(result.verdict, 'reject');
  assert.ok(findingCodes(result).has('transition-used-evidence-not-declared'));
});

test('state-impact coverage cannot use a world time before the affected transition', () => {
  const kernel = new MemoryKernel();
  const support = evidenceRecord({ id: 'early-expectation-support' });
  const report = evidenceRecord({
    id: 'early-expectation-report',
    authority: 'tool-verified',
    kind: 'test-result',
  });
  capture(kernel, support, 1);
  capture(kernel, report, 2, 'semantic-faithfulness-checker');
  const proposal = activeClaimProposal(kernel, {
    proposalId: 'early-state-expectation',
    support,
    report,
    expectations: [
      stateExpectation({
        validAt: 5,
        mode: 'assert',
        after: { status: 'unknown' },
      }),
    ],
  });

  const result = verifyTransition(kernel.events(), proposal, verifierIdentity());
  assert.equal(result.verdict, 'reject');
  assert.ok(findingCodes(result).has('transition-state-impact-coverage-missing'));
});

test('transition state assertions cannot hide new writes behind an old knownAt prefix', () => {
  const kernel = new MemoryKernel();
  const support = evidenceRecord({ id: 'known-at-support' });
  const report = evidenceRecord({
    id: 'known-at-report',
    authority: 'tool-verified',
    kind: 'test-result',
  });
  capture(kernel, support, 1);
  capture(kernel, report, 2, 'semantic-faithfulness-checker');
  const expectation = stateExpectation({
    mode: 'assert',
    after: { status: 'unknown' },
  });
  expectation.request.knownAt = 2;
  const proposal = activeClaimProposal(kernel, {
    proposalId: 'known-at-bypass',
    support,
    report,
    expectations: [expectation],
  });

  const result = verifyTransition(kernel.events(), proposal, verifierIdentity());
  assert.equal(result.verdict, 'reject');
  assert.ok(findingCodes(result).has('transition-state-impact-coverage-missing'));
  assert.ok(findingCodes(result).has('transition-state-expectation-failed'));
});

test('sensitive evidence capture is high risk and requires both semantic and security checks', () => {
  const kernel = new MemoryKernel();
  const secret = evidenceRecord({
    id: 'secret-input',
    sensitivity: 'secret',
    taints: ['secret-detected'],
  });
  const proposal = proposalFor(kernel, {
    id: 'capture-secret-input',
    declaredRisk: 'high',
    operations: [
      {
        id: 'capture-secret-evidence',
        type: 'evidence.captured',
        recordedAt: 1,
        actor: 'secret-ingestor',
        data: { evidence: secret },
      },
    ],
    inputEvidenceIds: [secret.id],
  });

  const result = verifyTransition(kernel.events(), proposal, verifierIdentity());
  assert.equal(result.actualRisk, 'high');
  assert.equal(result.verdict, 'human-review');
  const missing = result.findings
    .filter((item) => item.code === 'transition-required-external-check-missing')
    .map((item) => item.objectIds[0]);
  assert.deepEqual(new Set(missing), new Set(['semantic-faithfulness', 'security']));
});

test('tainted associations are quarantined unless a security check authorizes them', () => {
  const kernel = new MemoryKernel();
  const source = evidenceRecord({
    id: 'tainted-association-source',
    authority: 'external-source',
    kind: 'document',
    taints: ['external-content', 'prompt-like'],
  });
  const report = evidenceRecord({
    id: 'association-faithfulness-report',
    authority: 'tool-verified',
    kind: 'test-result',
  });
  capture(kernel, source, 1);
  capture(kernel, report, 2, 'semantic-faithfulness-checker');
  const proposalId = 'tainted-association-transition';
  const proposal = proposalFor(kernel, {
    id: proposalId,
    declaredRisk: 'high',
    operations: [
      {
        id: 'add-tainted-association',
        type: 'association.added',
        recordedAt: 3,
        actor: 'association-learner',
        data: {
          association: {
            id: 'tainted-association',
            scope: 'project/demo',
            from: 'episode-a',
            to: 'procedure-a',
            kind: 'procedural',
            weight: 0.8,
            evidence: [evidenceRefFor(source, ['supports'])],
          },
        },
      },
    ],
    inputEvidenceIds: [source.id, report.id],
    externalChecks: [externalCheck({ proposalId, record: report })],
  });

  const result = verifyTransition(kernel.events(), proposal, verifierIdentity());
  assert.equal(result.actualRisk, 'high');
  assert.equal(result.verdict, 'quarantine');
  assert.ok(findingCodes(result).has('transition-tainted-active-write'));
});

test('unknown runtime event types fail closed during risk analysis and staging', () => {
  const kernel = new MemoryKernel();
  const proposal = proposalFor(kernel, {
    id: 'future-event-type',
    declaredRisk: 'destructive',
    stateImpact: 'unknown',
    operations: [
      {
        id: 'future-event',
        type: 'memory.teleported',
        recordedAt: 1,
        actor: 'future-writer',
        data: {},
      },
    ],
  });

  const result = verifyTransition(kernel.events(), proposal, verifierIdentity());
  assert.equal(result.actualRisk, 'destructive');
  assert.equal(result.verdict, 'reject');
  assert.ok(findingCodes(result).has('transition-event-type-invalid'));
  assert.ok(findingCodes(result).has('transition-semantic-replay-failed'));
});

test('a transition result is a capability of the verifier runtime that issued it', () => {
  const kernel = new MemoryKernel();
  const record = evidenceRecord({ id: 'runtime-capability-record' });
  const proposal = proposalFor(kernel, {
    id: 'runtime-capability-transition',
    operations: [
      {
        id: 'capture-runtime-capability-record',
        type: 'evidence.captured',
        recordedAt: 1,
        actor: 'source-ingestor',
        data: { evidence: record },
      },
    ],
    inputEvidenceIds: [record.id],
  });
  const firstRuntime = new TransitionVerifier(verifierIdentity({ id: 'runtime-a' }));
  const secondRuntime = new TransitionVerifier(verifierIdentity({ id: 'runtime-b' }));
  const result = firstRuntime.verify(kernel.events(), proposal);

  assert.equal(result.verdict, 'accept');
  assert.throws(
    () => secondRuntime.commit(kernel, result),
    /not issued by this verifier runtime/,
  );
  assert.equal(firstRuntime.commit(kernel, result).events().length, 1);
});

test('verifier policy and identity are canonical immutable snapshots', () => {
  const mutablePolicy = structuredClone(DEFAULT_TRANSITION_POLICY);
  mutablePolicy.id = 'mutable-policy';
  const mutableVerifier = verifierIdentity({ id: 'mutable-verifier' });
  const runtime = new TransitionVerifier(mutableVerifier, mutablePolicy);

  mutablePolicy.maxOperations = 1;
  mutablePolicy.requiredExternalChecks.high = [];
  mutableVerifier.id = 'mutated-after-construction';

  assert.equal(runtime.policy.maxOperations, DEFAULT_TRANSITION_POLICY.maxOperations);
  assert.deepEqual(runtime.policy.requiredExternalChecks.high, ['semantic-faithfulness']);
  assert.equal(runtime.verifier.id, 'mutable-verifier');
  assert.equal(Object.isFrozen(runtime.policy), true);
  assert.equal(Object.isFrozen(runtime.policy.requiredExternalChecks.high), true);
  assert.equal(Object.isFrozen(runtime.verifier), true);
});

test('transition policies bound evidence fan-in before semantic staging', () => {
  const kernel = new MemoryKernel();
  const first = evidenceRecord({ id: 'bounded-input-a' });
  const second = evidenceRecord({ id: 'bounded-input-b' });
  const policy = {
    ...structuredClone(DEFAULT_TRANSITION_POLICY),
    maxInputEvidence: 1,
  };
  const runtime = new TransitionVerifier(verifierIdentity({ id: 'bounded-input-verifier' }), policy);
  const proposal = proposalFor(kernel, {
    id: 'bounded-input-transition',
    operations: [
      {
        id: 'capture-bounded-a',
        type: 'evidence.captured',
        recordedAt: 1,
        actor: 'source-ingestor',
        data: { evidence: first },
      },
      {
        id: 'capture-bounded-b',
        type: 'evidence.captured',
        recordedAt: 2,
        actor: 'source-ingestor',
        data: { evidence: second },
      },
    ],
    inputEvidenceIds: [first.id, second.id],
  });

  const result = runtime.verify(kernel.events(), proposal);
  assert.equal(result.verdict, 'reject');
  assert.ok(findingCodes(result).has('transition-input-evidence-limit-exceeded'));
  assert.equal(result.stagedAppend, undefined);
  assert.equal(result.delta, undefined);
});

test('transition policies bound canonical proposal size', () => {
  const kernel = new MemoryKernel();
  const record = evidenceRecord({ id: 'oversized-proposal-input' });
  const policy = {
    ...structuredClone(DEFAULT_TRANSITION_POLICY),
    maxProposalCharacters: 256,
  };
  const runtime = new TransitionVerifier(verifierIdentity({ id: 'proposal-size-verifier' }), policy);
  const proposal = proposalFor(kernel, {
    id: 'oversized-proposal',
    operations: [
      {
        id: 'capture-oversized-proposal-input',
        type: 'evidence.captured',
        recordedAt: 1,
        actor: 'source-ingestor',
        data: { evidence: record },
      },
    ],
    inputEvidenceIds: [record.id],
    rationale: 'x'.repeat(2_000),
  });

  const result = runtime.verify(kernel.events(), proposal);
  assert.equal(result.verdict, 'reject');
  assert.ok(findingCodes(result).has('transition-proposal-size-exceeded'));
  assert.equal(result.stagedAppend, undefined);
  assert.equal(result.delta, undefined);
});

test('assert and admit are verified and committed as one atomic state transition', () => {
  const kernel = new MemoryKernel();
  const support = evidenceRecord({ id: 'atomic-admission-support' });
  const report = evidenceRecord({
    id: 'atomic-admission-report',
    authority: 'tool-verified',
    kind: 'test-result',
  });
  capture(kernel, support, 1);
  capture(kernel, report, 2, 'semantic-faithfulness-checker');
  const claim = claimFromEvidence(support, {
    id: 'atomic-admission-claim',
    value: 'zed',
    validFrom: 10,
  });
  const proposalId = 'atomic-assert-admit';
  const proposal = proposalFor(kernel, {
    id: proposalId,
    declaredRisk: 'high',
    stateImpact: 'declared',
    operations: [
      {
        id: 'assert-atomic-admission-claim',
        type: 'claim.asserted',
        recordedAt: 10,
        actor: 'memory-writer',
        data: { claim, initialLifecycle: 'quarantined' },
      },
      {
        id: 'admit-atomic-admission-claim',
        type: 'claim.admitted',
        recordedAt: 11,
        actor: 'memory-admitter',
        data: { claimId: claim.id, reason: 'independent verification passed' },
      },
    ],
    inputEvidenceIds: [support.id, report.id],
    externalChecks: [externalCheck({ proposalId, record: report })],
    stateExpectations: [stateExpectation({
      validAt: 20,
      before: { status: 'unknown' },
      after: { status: 'current', value: 'zed' },
    })],
  });
  const runtime = new TransitionVerifier(verifierIdentity({ id: 'atomic-admission-verifier' }));

  const result = runtime.verify(kernel.events(), proposal);
  assert.equal(result.verdict, 'accept');
  assert.deepEqual(result.delta?.createdClaims, [
    { claimId: claim.id, lifecycle: 'active' },
  ]);
  const committed = runtime.commit(kernel, result);
  assert.equal(committed.events().length, kernel.events().length + 2);
  assert.equal(
    adjudicateState(committed.events(), editorSchema, {
      slotId: 'preferred-editor',
      view: 'current',
      validAt: 20,
    }).value,
    'zed',
  );
});

test('tainted verified outcomes remain quarantined without a security check', () => {
  const kernel = new MemoryKernel();
  const taintedResult = evidenceRecord({
    id: 'tainted-outcome-result',
    authority: 'tool-verified',
    kind: 'test-result',
    taints: ['external-content', 'prompt-like'],
  });
  const report = evidenceRecord({
    id: 'tainted-outcome-faithfulness-report',
    authority: 'tool-verified',
    kind: 'test-result',
  });
  capture(kernel, taintedResult, 1, 'test-runner');
  capture(kernel, report, 2, 'semantic-faithfulness-checker');
  const proposalId = 'tainted-outcome-transition';
  const proposal = proposalFor(kernel, {
    id: proposalId,
    declaredRisk: 'high',
    operations: [
      {
        id: 'record-tainted-outcome',
        type: 'outcome.recorded',
        recordedAt: 3,
        actor: 'outcome-writer',
        data: {
          scope: 'project/demo',
          subjectId: 'procedure/example',
          taskId: 'task/example',
          contextFingerprint: 'demo-context',
          sourceGroups: [...taintedResult.sourceGroups],
          outcome: 'success',
          verifier: 'test',
          evidence: [evidenceRefFor(taintedResult, ['verifies'])],
        },
      },
    ],
    inputEvidenceIds: [taintedResult.id, report.id],
    externalChecks: [externalCheck({ proposalId, record: report })],
  });

  const result = verifyTransition(kernel.events(), proposal, verifierIdentity());
  assert.equal(result.actualRisk, 'high');
  assert.equal(result.verdict, 'quarantine');
  assert.ok(findingCodes(result).has('transition-tainted-active-write'));
});

test('external check authority must belong to the digest-bound report evidence', () => {
  const kernel = new MemoryKernel();
  const input = evidenceRecord({ id: 'authority-bound-input' });
  const weakReport = evidenceRecord({
    id: 'weak-bound-report',
    authority: 'model-inference',
    kind: 'assistant-message',
    taints: ['model-generated'],
  });
  const unrelatedStrongEvidence = evidenceRecord({
    id: 'unrelated-strong-check-evidence',
    authority: 'tool-verified',
    kind: 'test-result',
  });
  capture(kernel, weakReport, 1, 'model-checker');
  capture(kernel, unrelatedStrongEvidence, 2, 'tool-checker');
  const proposalId = 'bound-report-authority-transition';
  const proposal = proposalFor(kernel, {
    id: proposalId,
    operations: [
      {
        id: 'capture-authority-bound-input',
        type: 'evidence.captured',
        recordedAt: 3,
        actor: 'source-ingestor',
        data: { evidence: input },
      },
    ],
    inputEvidenceIds: [input.id, weakReport.id, unrelatedStrongEvidence.id],
    externalChecks: [externalCheck({
      proposalId,
      record: weakReport,
      verifier: verifierIdentity({
        id: 'tool-grade-checker',
        actor: 'tool-grade-checker',
        kind: 'tool',
        implementation: 'semantic-faithfulness',
      }),
      reportDigest: weakReport.artifact.digest,
      roles: ['verifies'],
      id: 'authority-bound-check',
    })],
  });
  proposal.externalChecks[0].evidence = [
    evidenceRefFor(weakReport, ['verifies']),
    evidenceRefFor(unrelatedStrongEvidence, ['verifies']),
  ];

  const result = verifyTransition(kernel.events(), proposal, verifierIdentity());
  assert.equal(result.verdict, 'reject');
  assert.ok(findingCodes(result).has('transition-external-check-authority-insufficient'));
});

test('transition proposals are snapshotted once before digest, validation, and replay', () => {
  const kernel = new MemoryKernel();
  const record = evidenceRecord({ id: 'single-read-transition-input' });
  let operationReads = 0;
  const validOperations = [
    {
      id: 'capture-single-read-transition-input',
      type: 'evidence.captured',
      recordedAt: 1,
      actor: 'source-ingestor',
      data: { evidence: record },
    },
  ];
  const proposal = proposalFor(kernel, { inputEvidenceIds: [record.id] });
  Object.defineProperty(proposal, 'operations', {
    enumerable: true,
    configurable: true,
    get() {
      operationReads += 1;
      return operationReads === 1
        ? validOperations
        : [{
            id: 'changed-after-digest',
            type: 'claim.revoked',
            recordedAt: 1,
            actor: 'malicious-getter',
            data: { claimId: 'not-present', reason: 'changed after digest' },
          }];
    },
  });

  const result = verifyTransition(kernel.events(), proposal, verifierIdentity());
  assert.equal(operationReads, 1);
  assert.equal(result.verdict, 'accept');
  assert.equal(result.stagedAppend?.[0]?.id, 'capture-single-read-transition-input');
});

test('the audit journal snapshots a copied verdict once before integrity validation', () => {
  const kernel = new MemoryKernel();
  const record = evidenceRecord({ id: 'single-read-audit-input' });
  const proposal = proposalFor(kernel, {
    id: 'single-read-audit-transition',
    operations: [
      {
        id: 'capture-single-read-audit-input',
        type: 'evidence.captured',
        recordedAt: 1,
        actor: 'source-ingestor',
        data: { evidence: record },
      },
    ],
    inputEvidenceIds: [record.id],
  });
  const result = structuredClone(verifyTransition(kernel.events(), proposal, verifierIdentity()));
  let reads = 0;
  Object.defineProperty(result, 'proposalId', {
    enumerable: true,
    configurable: true,
    get() {
      reads += 1;
      return reads === 1 ? proposal.id : 'changed-after-integrity';
    },
  });

  const journal = new TransitionAuditJournal();
  const audit = journal.append(
    { id: 'single-read-audit', recordedAt: 2, actor: 'transition-auditor' },
    result,
  );
  assert.equal(reads, 1);
  assert.equal(audit.proposalId, proposal.id);
});

test('transition verifier construction rejects invalid resource limits', () => {
  const invalidPolicy = {
    ...structuredClone(DEFAULT_TRANSITION_POLICY),
    maxExternalChecks: 0,
  };
  assert.throws(
    () => new TransitionVerifier(verifierIdentity({ id: 'invalid-limit-verifier' }), invalidPolicy),
    /maxExternalChecks must be a positive integer/,
  );
});
