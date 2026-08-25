import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { MemoryKernel, evidenceRefFor } from '../dist/index.js';
import { SqliteFts5Projection } from '../dist/retrieval/index.js';

function sha(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function evidence(id, overrides = {}) {
  return {
    id,
    scope: 'project/search',
    kind: 'document',
    sourceGroups: [`origin-${id}`],
    authority: 'external-source',
    observedAt: 1,
    sensitivity: 'internal',
    taints: [],
    artifact: {
      uri: `memory://artifact/${id}`,
      digest: sha(id),
      sizeBytes: id.length,
      mediaType: 'text/plain',
      encryption: 'none',
      retention: 'durable',
    },
    preview: `Canonical source ${id}`,
    derivedFrom: [],
    labels: ['searchable'],
    ...overrides,
  };
}

function claim(id, source, value, overrides = {}) {
  return {
    id,
    key: {
      scope: source.scope,
      subject: 'project-search',
      predicate: 'preferred-editor',
    },
    value,
    valid: { from: 2 },
    authority: source.authority,
    epistemicStatus: 'observed',
    confidence: 1,
    evidence: [evidenceRefFor(source, ['supports'])],
    derivedFrom: [],
    tags: ['editor', 'preference'],
    ...overrides,
  };
}

function appendEvidence(kernel, source, time = 1) {
  kernel.captureEvidence(
    { eventId: `capture-${source.id}`, recordedAt: time, actor: 'ingestor' },
    source,
  );
}

function appendClaim(kernel, candidate, time = 2) {
  kernel.assertClaim(
    { eventId: `assert-${candidate.id}`, recordedAt: time, actor: 'writer' },
    candidate,
    { authorizeImmediately: true },
  );
}

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), 'continual-learning-fts-'));
  const filename = join(directory, 'projection.sqlite');
  return {
    directory,
    filename,
    cleanup() {
      rmSync(directory, { recursive: true, force: true });
    },
  };
}

test('FTS returns canonical addresses only and requires explicit rehydration', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    const source = evidence('editor-source', { preview: 'Zed editor decision for the project' });
    const preference = claim('editor-claim', source, 'zed');
    appendEvidence(kernel, source);
    appendClaim(kernel, preference);

    const projection = SqliteFts5Projection.open(files.filename);
    const watermark = projection.rebuild(kernel.events(), 10);
    assert.equal(watermark.eventCount, 2);

    const candidates = projection.search(kernel.events(), 'zed editor', {
      scopeChain: ['project/search'],
    });
    assert.ok(candidates.length >= 1);
    for (const candidate of candidates) {
      assert.equal(Object.hasOwn(candidate, 'content'), false);
      assert.equal(Object.hasOwn(candidate, 'searchText'), false);
      assert.equal(Object.hasOwn(candidate, 'value'), false);
    }

    const hydrated = projection.rehydrate(kernel.events(), candidates, {
      scopeChain: ['project/search'],
    });
    assert.ok(hydrated.some((item) => item.candidate.canonicalId === 'editor-claim'));
    projection.close();
  } finally {
    files.cleanup();
  }
});

test('scope authorization is a hard search and rehydration boundary', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    const alpha = evidence('alpha-source', {
      scope: 'project/alpha',
      preview: 'alpha-only migration token',
    });
    const beta = evidence('beta-source', {
      scope: 'project/beta',
      preview: 'beta-only migration token',
      artifact: { ...evidence('beta-source').artifact, digest: sha('beta-source-unique') },
      sourceGroups: ['origin-beta-source-unique'],
    });
    appendEvidence(kernel, alpha, 1);
    appendEvidence(kernel, beta, 2);

    const projection = SqliteFts5Projection.open(files.filename);
    projection.rebuild(kernel.events(), 3);
    const alphaResults = projection.search(kernel.events(), 'migration token', {
      scopeChain: ['project/alpha'],
    });
    assert.deepEqual(alphaResults.map((item) => item.canonicalId), ['alpha-source']);
    assert.throws(
      () => projection.rehydrate(kernel.events(), alphaResults, { scopeChain: ['project/beta'] }),
      /scope is not authorized/,
    );
    projection.close();
  } finally {
    files.cleanup();
  }
});

test('plaintext FTS excludes personal, sensitive, and secret source text by default', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    const publicSource = evidence('public-source', {
      sensitivity: 'public',
      preview: 'public lighthouse phrase',
    });
    const personalSource = evidence('personal-source', {
      sensitivity: 'personal',
      preview: 'private narwhal phrase',
      artifact: { ...evidence('personal-source').artifact, digest: sha('personal-source-unique') },
      sourceGroups: ['origin-personal-source-unique'],
    });
    const secretSource = evidence('secret-source', {
      sensitivity: 'secret',
      taints: ['secret-detected'],
      artifact: {
        ...evidence('secret-source').artifact,
        digest: sha('secret-source-unique'),
        encryption: 'provider-managed',
      },
      sourceGroups: ['origin-secret-source-unique'],
    });
    delete secretSource.preview;
    appendEvidence(kernel, publicSource, 1);
    appendEvidence(kernel, personalSource, 2);
    appendEvidence(kernel, secretSource, 3);

    const projection = SqliteFts5Projection.open(files.filename);
    const watermark = projection.rebuild(kernel.events(), 4);
    assert.equal(watermark.entryCount, 1);
    assert.equal(
      projection.search(kernel.events(), 'lighthouse', { scopeChain: ['project/search'] }).length,
      1,
    );
    assert.equal(
      projection.search(kernel.events(), 'narwhal', { scopeChain: ['project/search'] }).length,
      0,
    );
    projection.close();
  } finally {
    files.cleanup();
  }
});

test('a changed canonical ledger makes the projection stale before any hit can be used', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    const source = evidence('stale-source', { preview: 'stale watermark phrase' });
    appendEvidence(kernel, source);
    const projection = SqliteFts5Projection.open(files.filename);
    projection.rebuild(kernel.events(), 2);

    const later = evidence('later-source', {
      preview: 'later phrase',
      artifact: { ...evidence('later-source').artifact, digest: sha('later-source-unique') },
      sourceGroups: ['origin-later-source-unique'],
    });
    appendEvidence(kernel, later, 3);
    assert.equal(projection.status(kernel.events()).fresh, false);
    assert.throws(
      () => projection.search(kernel.events(), 'stale', { scopeChain: ['project/search'] }),
      /projection is stale/,
    );
    projection.close();
  } finally {
    files.cleanup();
  }
});

test('atomic rebuild rollback leaves the prior generation searchable', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    const source = evidence('stable-source', { preview: 'stable generation phrase' });
    appendEvidence(kernel, source);
    const stable = SqliteFts5Projection.open(files.filename);
    const first = stable.rebuild(kernel.events(), 2);
    stable.close();

    const failing = SqliteFts5Projection.open(files.filename, {
      faultInjector(phase) {
        if (phase === 'after-watermark') throw new Error('injected rebuild failure');
      },
    });
    assert.throws(() => failing.rebuild(kernel.events(), 3), /injected rebuild failure/);
    failing.close();

    const reopened = SqliteFts5Projection.open(files.filename);
    assert.equal(reopened.watermark()?.generation, first.generation);
    assert.equal(
      reopened.search(kernel.events(), 'stable generation', {
        scopeChain: ['project/search'],
      })[0]?.canonicalId,
      'stable-source',
    );
    reopened.close();
  } finally {
    files.cleanup();
  }
});

test('row tampering is detected before an index hit becomes a candidate', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    const source = evidence('integrity-source', { preview: 'integrity canary phrase' });
    appendEvidence(kernel, source);
    const projection = SqliteFts5Projection.open(files.filename);
    projection.rebuild(kernel.events(), 2);
    projection.close();

    const raw = new DatabaseSync(files.filename);
    raw.prepare("UPDATE cl_fts_entries SET search_text = 'forged canary phrase'").run();
    raw.close();

    const reopened = SqliteFts5Projection.open(files.filename);
    assert.throws(
      () => reopened.search(kernel.events(), 'forged', { scopeChain: ['project/search'] }),
      /row integrity failed/,
    );
    reopened.close();
  } finally {
    files.cleanup();
  }
});

test('safe query compilation treats MATCH operators as ordinary tokens and bounds input', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    appendEvidence(kernel, evidence('query-source', { preview: 'operator or near phrase' }));
    const projection = SqliteFts5Projection.open(files.filename);
    projection.rebuild(kernel.events(), 2);
    assert.doesNotThrow(() =>
      projection.search(kernel.events(), 'operator OR NEAR(*)', {
        scopeChain: ['project/search'],
      }),
    );
    assert.throws(
      () => projection.search(kernel.events(), '***', { scopeChain: ['project/search'] }),
      /searchable token/,
    );
    assert.throws(
      () => projection.search(kernel.events(), 'one two three', {
        scopeChain: ['project/search'],
        maxQueryTokens: 2,
      }),
      /token limit/,
    );
    assert.throws(
      () => projection.search(kernel.events(), 'operator', {
        scopeChain: ['project/search'],
        limit: 101,
      }),
      /result limit/,
    );
    projection.close();
  } finally {
    files.cleanup();
  }
});

test('historical search can recall superseded claims while current search cannot', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    const oldSource = evidence('old-editor-source', { preview: 'Vim editor historical decision' });
    const newSource = evidence('new-editor-source', {
      preview: 'Zed editor current decision',
      artifact: { ...evidence('new-editor-source').artifact, digest: sha('new-editor-source-unique') },
      sourceGroups: ['origin-new-editor-source-unique'],
      observedAt: 5,
    });
    const oldClaim = claim('old-editor-claim', oldSource, 'vim', { valid: { from: 2 } });
    const newClaim = claim('new-editor-claim', newSource, 'zed', { valid: { from: 5 } });
    appendEvidence(kernel, oldSource, 1);
    appendClaim(kernel, oldClaim, 2);
    appendEvidence(kernel, newSource, 5);
    appendClaim(kernel, newClaim, 6);
    kernel.supersedeClaim(
      { eventId: 'supersede-editor', recordedAt: 7, actor: 'human' },
      oldClaim.id,
      newClaim.id,
      5,
      'preference changed',
    );

    const projection = SqliteFts5Projection.open(files.filename);
    projection.rebuild(kernel.events(), 8);
    const current = projection.search(kernel.events(), 'vim preference', {
      scopeChain: ['project/search'],
      view: 'current',
    });
    assert.equal(current.some((item) => item.canonicalId === oldClaim.id), false);
    const historical = projection.search(kernel.events(), 'vim preference', {
      scopeChain: ['project/search'],
      view: 'historical',
    });
    assert.equal(historical.some((item) => item.canonicalId === oldClaim.id), true);
    const hydrated = projection.rehydrate(kernel.events(), historical, {
      scopeChain: ['project/search'],
      view: 'historical',
    });
    assert.equal(
      hydrated.find((item) => item.candidate.canonicalId === oldClaim.id)?.lifecycle,
      'superseded',
    );
    projection.close();
  } finally {
    files.cleanup();
  }
});

test('rebuild is deterministic and retires inactive generations', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    appendEvidence(kernel, evidence('deterministic-a', { preview: 'deterministic phrase alpha' }), 1);
    appendEvidence(
      kernel,
      evidence('deterministic-b', {
        preview: 'deterministic phrase beta',
        artifact: { ...evidence('deterministic-b').artifact, digest: sha('deterministic-b-unique') },
        sourceGroups: ['origin-deterministic-b-unique'],
        observedAt: 2,
      }),
      2,
    );
    const projection = SqliteFts5Projection.open(files.filename);
    const first = projection.rebuild(kernel.events(), 3);
    const firstIds = projection
      .search(kernel.events(), 'deterministic phrase', { scopeChain: ['project/search'] })
      .map((item) => item.canonicalId);
    const second = projection.rebuild(kernel.events(), 4);
    const secondIds = projection
      .search(kernel.events(), 'deterministic phrase', { scopeChain: ['project/search'] })
      .map((item) => item.canonicalId);
    assert.ok(second.generation > first.generation);
    assert.deepEqual(secondIds, firstIds);

    const raw = new DatabaseSync(files.filename);
    const generations = raw.prepare('SELECT DISTINCT generation FROM cl_fts_entries').all();
    assert.equal(generations.length, 1);
    raw.close();
    projection.close();
  } finally {
    files.cleanup();
  }
});

test('projection survives close and reopen with an exact watermark', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    appendEvidence(kernel, evidence('reopen-source', { preview: 'reopen persistence phrase' }));
    const first = SqliteFts5Projection.open(files.filename);
    const watermark = first.rebuild(kernel.events(), 2);
    first.close();

    const reopened = SqliteFts5Projection.open(files.filename);
    assert.deepEqual(reopened.watermark(), watermark);
    assert.equal(reopened.status(kernel.events()).fresh, true);
    assert.equal(
      reopened.search(kernel.events(), 'reopen persistence', {
        scopeChain: ['project/search'],
      })[0]?.canonicalId,
      'reopen-source',
    );
    reopened.close();
  } finally {
    files.cleanup();
  }
});
