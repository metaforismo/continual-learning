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
        epistemicStatus: 'observed',
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


test('claim values are omitted from plaintext FTS unless the host explicitly opts in', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    const source = evidence('claim-metadata-source', {
      preview: 'generic preference observation',
    });
    appendEvidence(kernel, source, 1);
    kernel.assertClaim(
      { eventId: 'assert-value-canary', recordedAt: 2, actor: 'writer' },
      {
        id: 'value-canary-claim',
        key: {
          scope: 'project/search',
          subject: 'project-search',
          predicate: 'preferred-editor',
        },
        value: 'quasar-value-canary',
        valid: { from: 2 },
        authority: source.authority,
        epistemicStatus: 'observed',
        confidence: 1,
        evidence: [{
          sourceId: source.id,
          sourceGroups: source.sourceGroups,
          authority: source.authority,
          contentHash: source.artifact.digest,
          roles: ['supports'],
        }],
        derivedFrom: [],
        tags: ['editor', 'preference'],
      },
      { authorizeImmediately: true },
    );
    const projection = SqliteFts5Projection.open(files.filename);
    projection.rebuild(kernel.events(), 3);
    assert.equal(
      projection.search(kernel.events(), 'quasar-value-canary', {
        scopeChain: ['project/search'],
      }).some((candidate) => candidate.canonicalId === 'value-canary-claim'),
      false,
    );
    assert.equal(
      projection.search(kernel.events(), 'editor preference', {
        scopeChain: ['project/search'],
      }).some((candidate) => candidate.canonicalId === 'value-canary-claim'),
      true,
    );
    projection.close();
  } finally {
    files.cleanup();
  }
});

test('query character count is bounded before Unicode tokenization', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    appendEvidence(kernel, evidence('query-size-source', { preview: 'bounded query phrase' }));
    const projection = SqliteFts5Projection.open(files.filename);
    projection.rebuild(kernel.events(), 2);
    assert.throws(
      () => projection.search(kernel.events(), 'x'.repeat(4_097), {
        scopeChain: ['project/search'],
      }),
      /cannot exceed 4096 characters/,
    );
    projection.close();
  } finally {
    files.cleanup();
  }
});

test('rehydration is bounded and remains valid after the disposable cache is closed', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    appendEvidence(kernel, evidence('portable-candidate', { preview: 'portable candidate phrase' }));
    const projection = SqliteFts5Projection.open(files.filename);
    projection.rebuild(kernel.events(), 2);
    const candidates = projection.search(kernel.events(), 'portable candidate', {
      scopeChain: ['project/search'],
    });
    projection.close();
    const hydrated = projection.rehydrate(kernel.events(), candidates, {
      scopeChain: ['project/search'],
    });
    assert.equal(hydrated[0]?.candidate.canonicalId, 'portable-candidate');
    const oversized = Array.from({ length: 101 }, (_, index) => ({
      ...candidates[0],
      canonicalId: `candidate-${index}`,
      rank: index + 1,
    }));
    assert.throws(
      () => projection.rehydrate(kernel.events(), oversized, {
        scopeChain: ['project/search'],
      }),
      /cannot exceed 100 candidates/,
    );
  } finally {
    files.cleanup();
  }
});

test('search uses one SQLite read snapshot across integrity validation and MATCH', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    appendEvidence(kernel, evidence('snapshot-source', { preview: 'snapshot race phrase' }));
    const writer = SqliteFts5Projection.open(files.filename);
    writer.rebuild(kernel.events(), 2);
    const rawReader = new DatabaseSync(files.filename);
    let rebuilt = false;
    const readerDb = {
      exec(sql) { return rawReader.exec(sql); },
      prepare(sql) {
        if (!rebuilt && sql.includes('bm25(cl_fts_entries)')) {
          rebuilt = true;
          writer.rebuild(kernel.events(), 3);
        }
        return rawReader.prepare(sql);
      },
      close() { rawReader.close(); },
    };
    const reader = new SqliteFts5Projection(readerDb);
    const candidates = reader.search(kernel.events(), 'snapshot race', {
      scopeChain: ['project/search'],
    });
    assert.equal(rebuilt, true);
    assert.equal(candidates[0]?.canonicalId, 'snapshot-source');
    const hydrated = reader.rehydrate(kernel.events(), candidates, {
      scopeChain: ['project/search'],
    });
    assert.equal(hydrated[0]?.record.id, 'snapshot-source');
    reader.close();
    rawReader.close();
    writer.close();
  } finally {
    files.cleanup();
  }
});

test('claim-value indexing requires an explicit boolean opt-in', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    const source = evidence('claim-value-source', { preview: 'generic editor observation' });
    appendEvidence(kernel, source, 1);
    kernel.assertClaim(
      { eventId: 'assert-opt-in-value', recordedAt: 2, actor: 'writer' },
      {
        id: 'opt-in-value-claim',
        key: {
          scope: 'project/search',
          subject: 'project-search',
          predicate: 'preferred-editor',
        },
        value: 'heliosphere-editor',
        valid: { from: 2 },
        authority: source.authority,
        epistemicStatus: 'observed',
        confidence: 1,
        evidence: [{
          sourceId: source.id,
          sourceGroups: source.sourceGroups,
          authority: source.authority,
          contentHash: source.artifact.digest,
          roles: ['supports'],
        }],
        derivedFrom: [],
        tags: ['editor'],
      },
      { authorizeImmediately: true },
    );
    assert.throws(
      () => SqliteFts5Projection.open(files.filename, { indexClaimValues: 'yes' }),
      /must be boolean/,
    );
    const projection = SqliteFts5Projection.open(files.filename, {
      indexClaimValues: true,
    });
    projection.rebuild(kernel.events(), 3);
    assert.equal(
      projection.search(kernel.events(), 'heliosphere-editor', {
        scopeChain: ['project/search'],
      }).some((candidate) => candidate.canonicalId === 'opt-in-value-claim'),
      true,
    );
    projection.close();
  } finally {
    files.cleanup();
  }
});

test('a same-length canonical fork cannot replace an existing projection', () => {
  const files = fixture();
  try {
    const left = new MemoryKernel();
    appendEvidence(left, evidence('fork-left', { preview: 'left fork phrase' }), 1);
    const right = new MemoryKernel();
    appendEvidence(right, evidence('fork-right', {
      preview: 'right fork phrase',
      artifact: { ...evidence('fork-right').artifact, digest: sha('fork-right-unique') },
      sourceGroups: ['origin-fork-right-unique'],
    }), 1);
    const projection = SqliteFts5Projection.open(files.filename);
    const original = projection.rebuild(left.events(), 2);
    assert.throws(
      () => projection.rebuild(right.events(), 3),
      /same-length canonical fork/,
    );
    assert.equal(projection.watermark()?.canonicalFingerprint, original.canonicalFingerprint);
    assert.equal(
      projection.search(left.events(), 'left fork', {
        scopeChain: ['project/search'],
      })[0]?.canonicalId,
      'fork-left',
    );
    projection.close();
  } finally {
    files.cleanup();
  }
});


test('projection fingerprinting and indexing share one canonical single-read event snapshot', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    appendEvidence(kernel, evidence('single-read-source', { preview: 'canonical single-read phrase' }));
    const events = structuredClone(kernel.events());
    let reads = 0;
    Object.defineProperty(events[0].data.evidence, 'preview', {
      enumerable: true,
      configurable: true,
      get() {
        reads += 1;
        return reads === 1 ? 'canonical single-read phrase' : 'forged second-read phrase';
      },
    });
    const projection = SqliteFts5Projection.open(files.filename);
    projection.rebuild(events, 2);
    assert.equal(reads, 1);
    assert.equal(
      projection.search(kernel.events(), 'canonical single-read', {
        scopeChain: ['project/search'],
      })[0]?.canonicalId,
      'single-read-source',
    );
    assert.equal(
      projection.search(kernel.events(), 'forged second-read', {
        scopeChain: ['project/search'],
      }).length,
      0,
    );
    projection.close();
  } finally {
    files.cleanup();
  }
});

test('a projection cannot be reused under a different privacy configuration', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    const source = evidence('config-source', { preview: 'generic config observation' });
    appendEvidence(kernel, source, 1);
    kernel.assertClaim(
      { eventId: 'assert-config-value', recordedAt: 2, actor: 'writer' },
      {
        id: 'config-value-claim',
        key: {
          scope: 'project/search',
          subject: 'project-search',
          predicate: 'preferred-editor',
        },
        value: 'config-private-value',
        valid: { from: 2 },
        authority: source.authority,
        epistemicStatus: 'observed',
        confidence: 1,
        evidence: [{
          sourceId: source.id,
          sourceGroups: source.sourceGroups,
          authority: source.authority,
          contentHash: source.artifact.digest,
          roles: ['supports'],
        }],
        derivedFrom: [],
        tags: ['editor'],
      },
      { authorizeImmediately: true },
    );
    const permissive = SqliteFts5Projection.open(files.filename, {
      indexClaimValues: true,
    });
    permissive.rebuild(kernel.events(), 3);
    assert.equal(
      permissive.search(kernel.events(), 'config-private-value', {
        scopeChain: ['project/search'],
      }).some((candidate) => candidate.canonicalId === 'config-value-claim'),
      true,
    );
    permissive.close();
    const restrictive = SqliteFts5Projection.open(files.filename);
    const status = restrictive.status(kernel.events());
    assert.equal(status.fresh, false);
    assert.match(status.reason, /configuration does not match/);
    assert.throws(
      () => restrictive.search(kernel.events(), 'config-private-value', {
        scopeChain: ['project/search'],
      }),
      /projection is unavailable/,
    );
    restrictive.ensureFresh(kernel.events(), 4);
    assert.equal(
      restrictive.search(kernel.events(), 'config-private-value', {
        scopeChain: ['project/search'],
      }).some((candidate) => candidate.canonicalId === 'config-value-claim'),
      false,
    );
    restrictive.close();
  } finally {
    files.cleanup();
  }
});

test('a longer history must extend the exact projected prefix rather than a different fork', () => {
  const files = fixture();
  try {
    const left = new MemoryKernel();
    appendEvidence(left, evidence('left-prefix', { preview: 'left prefix phrase' }), 1);

    const right = new MemoryKernel();
    appendEvidence(
      right,
      evidence('right-prefix', {
        preview: 'right prefix phrase',
        artifact: { ...evidence('right-prefix').artifact, digest: sha('right-prefix-unique') },
        sourceGroups: ['origin-right-prefix-unique'],
      }),
      1,
    );
    appendEvidence(
      right,
      evidence('right-extension', {
        preview: 'right extension phrase',
        artifact: {
          ...evidence('right-extension').artifact,
          digest: sha('right-extension-unique'),
        },
        sourceGroups: ['origin-right-extension-unique'],
        observedAt: 2,
      }),
      2,
    );

    const projection = SqliteFts5Projection.open(files.filename);
    const original = projection.rebuild(left.events(), 2);
    assert.throws(
      () => projection.rebuild(right.events(), 3),
      /canonical fork before the new append range/,
    );
    assert.equal(projection.watermark()?.canonicalFingerprint, original.canonicalFingerprint);
    assert.equal(
      projection.search(left.events(), 'left prefix', {
        scopeChain: ['project/search'],
      })[0]?.canonicalId,
      'left-prefix',
    );
    projection.close();
  } finally {
    files.cleanup();
  }
});

test('a restrictive host rejects a mismatched cache configuration before reading indexed rows', () => {
  const files = fixture();
  try {
    const kernel = new MemoryKernel();
    const source = evidence('config-scan-source', { preview: 'configuration scan phrase' });
    appendEvidence(kernel, source, 1);

    const permissive = SqliteFts5Projection.open(files.filename, {
      indexClaimValues: true,
    });
    permissive.rebuild(kernel.events(), 2);
    permissive.close();

    const raw = new DatabaseSync(files.filename);
    let entryReads = 0;
    const guardedDb = {
      exec(sql) { return raw.exec(sql); },
      prepare(sql) {
        if (/\bFROM\s+cl_fts_entries\b/i.test(sql)) entryReads += 1;
        return raw.prepare(sql);
      },
      close() { raw.close(); },
    };
    const restrictive = new SqliteFts5Projection(guardedDb);
    const status = restrictive.status(kernel.events());
    assert.equal(status.fresh, false);
    assert.match(status.reason, /configuration does not match/);
    assert.equal(entryReads, 0);
    restrictive.close();
    raw.close();
  } finally {
    files.cleanup();
  }
});
