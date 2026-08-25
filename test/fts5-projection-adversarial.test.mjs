import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { MemoryKernel } from '../dist/index.js';
import { SqliteFts5Projection } from '../dist/retrieval/index.js';
import { appendEvidence, evidence, fixture, sha } from './fts5-fixtures.mjs';

test('secret-detected evidence stays out of plaintext FTS when sensitivity is misclassified', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    appendEvidence(
      kernel,
      evidence('mislabeled-secret', {
        sensitivity: 'internal',
        taints: ['secret-detected'],
        preview: 'credential phoenix phrase',
      }),
    );
    const projection = SqliteFts5Projection.open(files.filename);
    const watermark = projection.rebuild(kernel.events(), 2);
    assert.equal(watermark.entryCount, 0);
    assert.equal(
      projection.search(kernel.events(), 'phoenix', { scopeChain: ['project/search'] }).length,
      0,
    );
    projection.close();
  } finally {
    files.cleanup();
  }
});

test('evidence-less global policy values are not copied into the plaintext cache', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    kernel.assertClaim(
      { eventId: 'assert-global-policy', recordedAt: 1, actor: 'system' },
      {
        id: 'global-policy-claim',
        key: { scope: 'global', subject: 'runtime', predicate: 'private-bootstrap-token' },
        value: 'obsidian-policy-secret',
        valid: { from: 1 },
        authority: 'system-policy',
        epistemicStatus: 'verified',
        confidence: 1,
        evidence: [],
        derivedFrom: [],
        tags: ['bootstrap'],
      },
      { authorizeImmediately: true },
    );
    const projection = SqliteFts5Projection.open(files.filename);
    const watermark = projection.rebuild(kernel.events(), 2);
    assert.equal(watermark.entryCount, 0);
    assert.equal(
      projection.search(kernel.events(), 'obsidian', { scopeChain: ['global'] }).length,
      0,
    );
    projection.close();
  } finally {
    files.cleanup();
  }
});

test('deleted cache rows fail the manifest check instead of causing silent recall omission', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    appendEvidence(kernel, evidence('omission-source', { preview: 'omission canary phrase' }));
    const projection = SqliteFts5Projection.open(files.filename);
    projection.rebuild(kernel.events(), 2);
    projection.close();

    const raw = new DatabaseSync(files.filename);
    raw.prepare('DELETE FROM cl_fts_entries').run();
    raw.close();

    const reopened = SqliteFts5Projection.open(files.filename);
    const status = reopened.status(kernel.events());
    assert.equal(status.fresh, false);
    assert.match(status.reason, /integrity failed/);
    assert.throws(
      () => reopened.search(kernel.events(), 'omission', { scopeChain: ['project/search'] }),
      /projection is unavailable/,
    );
    reopened.close();
  } finally {
    files.cleanup();
  }
});

test('a delayed older rebuild cannot regress a newer committed watermark', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    appendEvidence(kernel, evidence('first-revision', { preview: 'first revision phrase' }), 1);
    const olderEvents = kernel.events();
    const projection = SqliteFts5Projection.open(files.filename);
    projection.rebuild(olderEvents, 2);

    appendEvidence(
      kernel,
      evidence('second-revision', {
        preview: 'second revision phrase',
        artifact: { ...evidence('second-revision').artifact, digest: sha('second-revision-unique') },
        sourceGroups: ['origin-second-revision-unique'],
        observedAt: 3,
      }),
      3,
    );
    const newer = projection.rebuild(kernel.events(), 4);
    assert.throws(
      () => projection.rebuild(olderEvents, 5),
      /cannot regress an existing canonical watermark/,
    );
    assert.equal(projection.watermark()?.canonicalFingerprint, newer.canonicalFingerprint);
    assert.equal(
      projection.search(kernel.events(), 'second revision', {
        scopeChain: ['project/search'],
      })[0]?.canonicalId,
      'second-revision',
    );
    projection.close();
  } finally {
    files.cleanup();
  }
});

test('scope fan-in is bounded before SQL statement construction', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    appendEvidence(kernel, evidence('bounded-scope-source', { preview: 'bounded scope phrase' }));
    const projection = SqliteFts5Projection.open(files.filename);
    projection.rebuild(kernel.events(), 2);
    assert.throws(
      () =>
        projection.search(kernel.events(), 'bounded', {
          scopeChain: Array.from({ length: 65 }, (_, index) => `project/${index}`),
        }),
      /cannot exceed 64 values/,
    );
    projection.close();
  } finally {
    files.cleanup();
  }
});
