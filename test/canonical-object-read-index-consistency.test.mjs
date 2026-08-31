import assert from 'node:assert/strict';
import test from 'node:test';

import {
  CanonicalObjectReadIndex,
  CanonicalObjectReadIndexIntegrityError,
} from '../dist/retrieval/index.js';

const DIGEST_A = `sha256:${'a'.repeat(64)}`;
const DIGEST_B = `sha256:${'b'.repeat(64)}`;
const DIGEST_C = `sha256:${'c'.repeat(64)}`;
const DIGEST_D = `sha256:${'d'.repeat(64)}`;

function checkpoint() {
  return Object.freeze({
    cursorDigest: DIGEST_A,
    revision: 7,
    lastBatchId: DIGEST_B,
    configurationDigest: DIGEST_C,
  });
}

function selectedProof(overrides = {}) {
  return Object.freeze({
    canonicalCursorDigest: DIGEST_A,
    consumerRevision: 7,
    lastBatchId: DIGEST_B,
    configurationDigest: DIGEST_C,
    ...overrides,
  });
}

function unconstructedIndex() {
  const index = Object.create(CanonicalObjectReadIndex.prototype);
  Object.defineProperty(index, 'currentCheckpoint', {
    value: () => checkpoint(),
    configurable: true,
  });
  return index;
}

test('bounded address rehydration fails closed when individual lookups cross a checkpoint', () => {
  const index = unconstructedIndex();
  let calls = 0;
  Object.defineProperty(index, 'lookupEvidence', {
    value: () => {
      calls += 1;
      return calls === 1
        ? selectedProof()
        : selectedProof({ canonicalCursorDigest: DIGEST_D, consumerRevision: 8 });
    },
    configurable: true,
  });

  assert.throws(
    () =>
      index.rehydrateAddresses(
        {},
        [
          { kind: 'evidence', canonicalId: 'evidence/one' },
          { kind: 'evidence', canonicalId: 'evidence/two' },
        ],
        { scopeChain: ['project/object-read'] },
      ),
    (error) =>
      error instanceof CanonicalObjectReadIndexIntegrityError &&
      /crossed a projection checkpoint boundary/.test(error.message),
  );
});

test('claim provenance closure fails closed when supporting evidence comes from another checkpoint', () => {
  const index = unconstructedIndex();
  const evidenceRecord = Object.freeze({
    id: 'evidence/support',
    scope: 'project/object-read',
    sourceGroups: Object.freeze(['origin/support']),
    authority: 'human-explicit',
    artifact: Object.freeze({ digest: DIGEST_D }),
  });
  const reference = Object.freeze({
    sourceId: evidenceRecord.id,
    sourceGroups: evidenceRecord.sourceGroups,
    authority: evidenceRecord.authority,
    contentHash: evidenceRecord.artifact.digest,
    roles: Object.freeze(['supports']),
  });
  const claimProof = selectedProof({
    record: Object.freeze({
      claim: Object.freeze({ evidence: Object.freeze([reference]) }),
    }),
  });
  const evidenceProof = selectedProof({
    canonicalCursorDigest: DIGEST_D,
    consumerRevision: 8,
    record: Object.freeze({
      record: evidenceRecord,
      contentAvailable: true,
    }),
  });

  Object.defineProperty(index, 'lookupClaim', {
    value: () => claimProof,
    configurable: true,
  });
  Object.defineProperty(index, 'lookupEvidence', {
    value: () => evidenceProof,
    configurable: true,
  });

  assert.throws(
    () =>
      index.rehydrateClaim({}, 'claim/editor', {
        scopeChain: ['project/object-read'],
      }),
    (error) =>
      error instanceof CanonicalObjectReadIndexIntegrityError &&
      /claim provenance crossed a projection checkpoint boundary/.test(error.message),
  );
});
