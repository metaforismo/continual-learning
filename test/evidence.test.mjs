import assert from 'node:assert/strict';
import test from 'node:test';

import {
  EVENT_SCHEMA_VERSION,
  EventLedger,
  MemoryKernel,
  evidenceRefFor,
} from '../dist/index.js';

const DIGEST_A = `sha256:${'a'.repeat(64)}`;
const DIGEST_B = `sha256:${'b'.repeat(64)}`;
const DIGEST_C = `sha256:${'c'.repeat(64)}`;
const DIGEST_D = `sha256:${'d'.repeat(64)}`;
const DIGEST_E = `sha256:${'e'.repeat(64)}`;

function record(overrides = {}) {
  return {
    id: 'evidence-1',
    scope: 'user/francesco',
    kind: 'human-feedback',
    sourceGroups: ['human-message-1'],
    authority: 'human-explicit',
    observedAt: 1,
    sensitivity: 'personal',
    taints: [],
    artifact: {
      uri: 'memory://artifact/evidence-1',
      digest: DIGEST_A,
      sizeBytes: 12,
      mediaType: 'text/plain',
      encryption: 'none',
      retention: 'durable',
    },
    preview: 'prefers Zed',
    derivedFrom: [],
    labels: ['preference'],
    ...overrides,
  };
}

function claimFromEvidence(evidence, overrides = {}) {
  return {
    id: 'claim-from-evidence',
    key: {
      scope: 'user/francesco',
      subject: 'francesco',
      predicate: 'preferred-editor',
    },
    value: 'zed',
    valid: { from: 1 },
    authority: evidence.authority,
    epistemicStatus: 'observed',
    confidence: 1,
    evidence: [evidenceRefFor(evidence)],
    derivedFrom: [],
    tags: ['preference'],
    ...overrides,
  };
}

test('evidence metadata is content-addressed, versioned, replayable, and provenance-linked', () => {
  const kernel = new MemoryKernel();
  const parent = record();
  const derived = record({
    id: 'evidence-2',
    kind: 'source-span',
    artifact: {
      ...parent.artifact,
      uri: 'memory://artifact/evidence-2',
      digest: DIGEST_B,
    },
    preview: 'editor preference span',
    derivedFrom: [parent.id],
  });

  kernel.captureEvidence({ eventId: 'capture-1', recordedAt: 1, actor: 'human' }, parent);
  kernel.captureEvidence({ eventId: 'capture-2', recordedAt: 2, actor: 'extractor' }, derived);

  assert.equal(kernel.events()[0]?.schemaVersion, EVENT_SCHEMA_VERSION);
  assert.deepEqual(kernel.evidence(derived.id)?.record.derivedFrom, [parent.id]);

  const replayed = MemoryKernel.from(kernel.events());
  assert.equal(replayed.evidence(parent.id)?.availability, 'available');
  assert.equal(replayed.evidence(derived.id)?.record.artifact.digest, DIGEST_B);
});

test('derived evidence cannot cite a future, unknown, or self source', () => {
  const kernel = new MemoryKernel();
  assert.throws(
    () =>
      kernel.captureEvidence(
        { eventId: 'capture-bad-derived', recordedAt: 1, actor: 'extractor' },
        record({ id: 'derived', derivedFrom: ['missing'] }),
      ),
    /must already exist/,
  );
  assert.throws(
    () =>
      kernel.captureEvidence(
        { eventId: 'capture-self', recordedAt: 1, actor: 'extractor' },
        record({ id: 'self', derivedFrom: ['self'] }),
      ),
    /cannot derive from itself/,
  );
});

test('sensitive and secret bytes stay outside the canonical log and require encrypted artifacts', () => {
  const kernel = new MemoryKernel();
  assert.throws(
    () =>
      kernel.captureEvidence(
        { eventId: 'capture-secret-bad', recordedAt: 1, actor: 'scanner' },
        record({
          id: 'secret-bad',
          sensitivity: 'secret',
          taints: ['secret-detected'],
          preview: 'API_KEY=should-not-be-here',
        }),
      ),
    /cannot place raw preview|requires provider-managed encryption/,
  );

  const secret = record({
    id: 'secret-good',
    sensitivity: 'secret',
    taints: ['secret-detected'],
    artifact: {
      ...record().artifact,
      uri: 'vault://artifact/secret-good',
      encryption: 'provider-managed',
    },
  });
  delete secret.preview;
  kernel.captureEvidence({ eventId: 'capture-secret-good', recordedAt: 1, actor: 'scanner' }, secret);
  assert.equal(kernel.evidence(secret.id)?.record.preview, undefined);
});

test('claims cannot cite unknown, forged, unavailable, or implicitly broader-scope evidence', () => {
  const unknownKernel = new MemoryKernel();
  const unknownSource = record({ id: 'unknown' });
  assert.throws(
    () =>
      unknownKernel.assertClaim(
        { eventId: 'claim-unknown', recordedAt: 1, actor: 'writer' },
        claimFromEvidence(unknownSource),
        { authorizeImmediately: true },
      ),
    /unknown evidence reference/,
  );

  const forgedKernel = new MemoryKernel();
  const source = record();
  forgedKernel.captureEvidence({ eventId: 'capture-source', recordedAt: 1, actor: 'human' }, source);
  const forged = claimFromEvidence(source, {
    evidence: [{ ...evidenceRefFor(source), contentHash: DIGEST_B }],
  });
  assert.throws(
    () =>
      forgedKernel.assertClaim(
        { eventId: 'claim-forged', recordedAt: 2, actor: 'writer' },
        forged,
        { authorizeImmediately: true },
      ),
    /forged evidence reference/,
  );

  const scopedKernel = new MemoryKernel();
  const projectSource = record({ id: 'project-source', scope: 'project/showstead' });
  scopedKernel.captureEvidence(
    { eventId: 'capture-project-source', recordedAt: 1, actor: 'human' },
    projectSource,
  );
  assert.throws(
    () =>
      scopedKernel.assertClaim(
        { eventId: 'claim-scope-promotion', recordedAt: 2, actor: 'writer' },
        claimFromEvidence(projectSource),
        { authorizeImmediately: true },
      ),
    /cannot be promoted implicitly/,
  );
});

test('evidence availability is bitemporal and automatically gates derived claims', () => {
  const kernel = new MemoryKernel();
  const source = record();
  const claim = claimFromEvidence(source);

  kernel.captureEvidence({ eventId: 'capture', recordedAt: 1, actor: 'human' }, source);
  kernel.assertClaim(
    { eventId: 'claim', recordedAt: 2, actor: 'writer' },
    claim,
    { authorizeImmediately: true },
  );
  assert.equal(kernel.resolveClaim(claim.key, { validAt: 2 }).status, 'resolved');

  kernel.setEvidenceAvailability(
    { eventId: 'restrict', recordedAt: 3, actor: 'privacy-controller' },
    source.id,
    'restricted',
    'requires re-authorization',
  );

  assert.equal(kernel.resolveClaim(claim.key, { validAt: 2 }).status, 'unknown');
  assert.equal(
    kernel.resolveClaim(claim.key, { validAt: 2, knownAt: 2 }).status,
    'resolved',
  );
});

test('deleted evidence is terminal while restricted evidence can be re-authorized', () => {
  const kernel = new MemoryKernel();
  const source = record();
  kernel.captureEvidence({ eventId: 'capture', recordedAt: 1, actor: 'human' }, source);
  kernel.setEvidenceAvailability(
    { eventId: 'restrict', recordedAt: 2, actor: 'privacy-controller' },
    source.id,
    'restricted',
    'review',
  );
  kernel.setEvidenceAvailability(
    { eventId: 'restore', recordedAt: 3, actor: 'privacy-controller' },
    source.id,
    'available',
    'review completed',
  );
  kernel.setEvidenceAvailability(
    { eventId: 'delete', recordedAt: 4, actor: 'privacy-controller' },
    source.id,
    'deleted',
    'retention request',
  );
  assert.throws(
    () =>
      kernel.setEvidenceAvailability(
        { eventId: 'restore-after-delete', recordedAt: 5, actor: 'privacy-controller' },
        source.id,
        'available',
        'invalid restore',
      ),
    /deleted evidence cannot transition again/,
  );
});

test('persisted replay fails closed on schema-version and sequence drift', () => {
  const kernel = new MemoryKernel();
  kernel.captureEvidence({ eventId: 'capture', recordedAt: 1, actor: 'human' }, record());

  const wrongVersion = structuredClone(kernel.events());
  wrongVersion[0].schemaVersion = 99;
  assert.throws(() => EventLedger.from(wrongVersion), /unsupported event schema version/);

  const wrongSequence = structuredClone(kernel.events());
  wrongSequence[0].seq = 2;
  assert.throws(() => EventLedger.from(wrongSequence), /seq must be contiguous/);
});

test('identical artifact bytes cannot masquerade as independent evidence', () => {
  const kernel = new MemoryKernel();
  const original = record();
  kernel.captureEvidence({ eventId: 'capture-original', recordedAt: 1, actor: 'human' }, original);

  const duplicate = record({
    id: 'evidence-copy',
    sourceGroups: ['invented-independent-origin'],
    artifact: {
      ...original.artifact,
      uri: 'memory://artifact/evidence-copy',
    },
  });
  assert.throws(
    () =>
      kernel.captureEvidence(
        { eventId: 'capture-copy', recordedAt: 2, actor: 'extractor' },
        duplicate,
      ),
    /artifact digest is already captured/,
  );
});

test('derived evidence cannot launder source identity, taint, sensitivity, or authority', () => {
  const kernel = new MemoryKernel();
  const parent = record({
    id: 'sensitive-parent',
    sourceGroups: ['external-origin'],
    authority: 'external-source',
    sensitivity: 'sensitive',
    taints: ['external-content', 'prompt-like'],
    artifact: {
      ...record().artifact,
      uri: 'vault://artifact/sensitive-parent',
      digest: DIGEST_C,
      encryption: 'provider-managed',
    },
  });
  delete parent.preview;
  kernel.captureEvidence({ eventId: 'capture-sensitive-parent', recordedAt: 2, actor: 'ingestor' }, parent);

  const laundered = record({
    id: 'laundered-summary',
    sourceGroups: ['fake-new-origin'],
    authority: 'human-explicit',
    sensitivity: 'personal',
    taints: [],
    artifact: {
      ...record().artifact,
      uri: 'memory://artifact/laundered-summary',
      digest: DIGEST_D,
    },
    derivedFrom: [parent.id],
  });
  assert.throws(
    () =>
      kernel.captureEvidence(
        { eventId: 'capture-laundered', recordedAt: 3, actor: 'summarizer' },
        laundered,
      ),
    /source groups must equal|cannot drop inherited taint|authority cannot exceed|cannot reduce inherited sensitivity/,
  );

  const validDerived = record({
    id: 'safe-derived-span',
    sourceGroups: ['external-origin'],
    authority: 'external-source',
    sensitivity: 'sensitive',
    taints: ['external-content', 'prompt-like'],
    artifact: {
      ...record().artifact,
      uri: 'vault://artifact/safe-derived-span',
      digest: DIGEST_E,
      encryption: 'provider-managed',
    },
    derivedFrom: [parent.id],
  });
  delete validDerived.preview;
  kernel.captureEvidence(
    { eventId: 'capture-safe-derived', recordedAt: 3, actor: 'deterministic-span-extractor' },
    validDerived,
  );
  assert.deepEqual(kernel.evidence(validDerived.id)?.record.sourceGroups, ['external-origin']);
});

test('evidence cannot claim to have been observed after its capture event', () => {
  const kernel = new MemoryKernel();
  assert.throws(
    () =>
      kernel.captureEvidence(
        { eventId: 'capture-from-future', recordedAt: 5, actor: 'ingestor' },
        record({ id: 'future-evidence', observedAt: 6 }),
      ),
    /cannot be observed after/,
  );
});

test('restricted evidence blocks admission as well as later claim resolution', () => {
  const kernel = new MemoryKernel();
  const source = record();
  const candidate = claimFromEvidence(source);
  kernel.captureEvidence({ eventId: 'capture-for-admission', recordedAt: 1, actor: 'human' }, source);
  kernel.assertClaim(
    { eventId: 'assert-quarantined', recordedAt: 2, actor: 'writer' },
    candidate,
  );
  kernel.setEvidenceAvailability(
    { eventId: 'restrict-before-admission', recordedAt: 3, actor: 'privacy-controller' },
    source.id,
    'restricted',
    'awaiting authorization',
  );
  assert.throws(
    () =>
      kernel.admitClaim(
        { eventId: 'admit-with-restricted-evidence', recordedAt: 4, actor: 'reviewer' },
        candidate.id,
        'should not pass',
      ),
    /unavailable or forged evidence/,
  );
});

test('global evidence may support a scoped claim without copying the artifact', () => {
  const kernel = new MemoryKernel();
  const source = record({ id: 'global-source', scope: 'global' });
  const candidate = claimFromEvidence(source, { id: 'claim-from-global' });
  kernel.captureEvidence({ eventId: 'capture-global', recordedAt: 1, actor: 'human' }, source);
  kernel.assertClaim(
    { eventId: 'assert-from-global', recordedAt: 2, actor: 'writer' },
    candidate,
    { authorizeImmediately: true },
  );
  assert.equal(kernel.resolveClaim(candidate.key, { validAt: 2 }).status, 'resolved');
});

test('semantic replay rejects an event stream that cited evidence before it existed', () => {
  const source = record();
  const candidate = claimFromEvidence(source);
  const structurallyValid = new EventLedger();
  structurallyValid.append({
    id: 'claim-before-source',
    type: 'claim.asserted',
    recordedAt: 1,
    actor: 'writer',
    data: { claim: candidate, initialLifecycle: 'active' },
  });
  structurallyValid.append({
    id: 'late-source',
    type: 'evidence.captured',
    recordedAt: 2,
    actor: 'human',
    data: { evidence: source },
  });

  assert.throws(() => MemoryKernel.from(structurallyValid.all()), /unknown evidence reference/);
});

test('verified outcomes are scoped derived objects and must cite authoritative evidence', () => {
  const kernel = new MemoryKernel();
  const result = record({
    id: 'test-result',
    scope: 'project/showstead',
    kind: 'test-result',
    sourceGroups: ['run-42'],
    authority: 'tool-verified',
    sensitivity: 'internal',
    artifact: {
      ...record().artifact,
      uri: 'memory://artifact/test-result',
      digest: DIGEST_C,
    },
  });
  kernel.captureEvidence({ eventId: 'capture-test-result', recordedAt: 2, actor: 'test-runner' }, result);

  const event = kernel.recordOutcome(
    { eventId: 'outcome-success', recordedAt: 3, actor: 'verifier' },
    {
      scope: 'project/showstead',
      subjectId: 'procedure/auth-race',
      taskId: 'task-42',
      contextFingerprint: 'showstead-auth-linux',
      sourceGroups: ['run-42'],
      outcome: 'success',
      verifier: 'test',
      evidence: [evidenceRefFor(result)],
    },
  );
  assert.equal(event.type, 'outcome.recorded');

  assert.throws(
    () =>
      kernel.recordOutcome(
        { eventId: 'outcome-forged-groups', recordedAt: 4, actor: 'verifier' },
        {
          scope: 'project/showstead',
          subjectId: 'procedure/auth-race',
          taskId: 'task-43',
          contextFingerprint: 'showstead-auth-linux',
          sourceGroups: ['fake-independent-run'],
          outcome: 'success',
          verifier: 'test',
          evidence: [evidenceRefFor(result)],
        },
      ),
    /source groups must exactly match/,
  );

  assert.throws(
    () =>
      kernel.recordOutcome(
        { eventId: 'outcome-fake-human', recordedAt: 4, actor: 'verifier' },
        {
          scope: 'project/showstead',
          subjectId: 'procedure/auth-race',
          taskId: 'task-44',
          contextFingerprint: 'showstead-auth-linux',
          sourceGroups: ['run-42'],
          outcome: 'success',
          verifier: 'human',
          evidence: [evidenceRefFor(result)],
        },
      ),
    /lacks evidence with sufficient authority/,
  );
});

test('association provenance cannot cross its declared scope implicitly', () => {
  const kernel = new MemoryKernel();
  const source = record({
    id: 'project-association-source',
    scope: 'project/showstead',
    sourceGroups: ['showstead-run'],
    artifact: {
      ...record().artifact,
      uri: 'memory://artifact/project-association-source',
      digest: DIGEST_C,
    },
  });
  kernel.captureEvidence(
    { eventId: 'capture-association-source', recordedAt: 2, actor: 'human' },
    source,
  );

  const association = {
    id: 'association-1',
    scope: 'project/showstead',
    from: 'episode-1',
    to: 'procedure-1',
    kind: 'procedural',
    weight: 0.9,
    evidence: [evidenceRefFor(source)],
  };
  kernel.addAssociation(
    { eventId: 'add-project-association', recordedAt: 3, actor: 'learner' },
    association,
  );

  assert.throws(
    () =>
      kernel.addAssociation(
        { eventId: 'add-global-association', recordedAt: 4, actor: 'learner' },
        { ...association, id: 'association-global', scope: 'global' },
      ),
    /cannot be promoted implicitly/,
  );
});
