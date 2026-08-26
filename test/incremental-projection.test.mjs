import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { MemoryKernel, SqliteIncrementalFts5Projection, evidenceRefFor } from '../dist/index.js';

function sha(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function evidence(id, preview, overrides = {}) {
  return {
    id,
    scope: 'project/incremental',
    kind: 'human-feedback',
    sourceGroups: [`origin/${id}`],
    authority: 'human-explicit',
    observedAt: 1,
    sensitivity: 'public',
    taints: [],
    artifact: {
      uri: `memory://artifact/${id}`,
      digest: sha(id),
      sizeBytes: preview.length,
      mediaType: 'text/plain',
      encryption: 'none',
      retention: 'durable',
    },
    preview,
    derivedFrom: [],
    labels: ['incremental'],
    ...overrides,
  };
}

function claim(id, source, value = 'zed') {
  return {
    id,
    key: {
      scope: 'project/incremental',
      subject: 'francesco',
      predicate: 'preferred-editor',
    },
    value,
    valid: { from: 1 },
    authority: 'human-explicit',
    epistemicStatus: 'observed',
    confidence: 1,
    evidence: [evidenceRefFor(source, ['supports'])],
    derivedFrom: [],
    tags: ['editor', 'preference'],
  };
}

function baseKernel() {
  const kernel = new MemoryKernel();
  const source = evidence('evidence/editor', 'Francesco prefers a fast editor');
  kernel.captureEvidence({ eventId: 'event/evidence/editor', recordedAt: 1, actor: 'human' }, source);
  kernel.assertClaim(
    { eventId: 'event/claim/editor', recordedAt: 2, actor: 'human' },
    claim('claim/editor', source),
    { authorizeImmediately: true },
  );
  return { kernel, source };
}

function temporaryDatabase() {
  const directory = mkdtempSync(join(tmpdir(), 'cl-incremental-'));
  return {
    directory,
    database: join(directory, 'projection.sqlite'),
    cleanup() {
      rmSync(directory, { recursive: true, force: true });
    },
  };
}

test('rebuild exposes address-only candidates and requires canonical rehydration', () => {
  const { kernel } = baseKernel();
  const projection = new SqliteIncrementalFts5Projection();
  const checkpoint = projection.rebuild(kernel.events());

  assert.equal(checkpoint.generation, 1);
  assert.equal(checkpoint.baseEventCount, 0);
  assert.equal(checkpoint.appendFromSeq, 1);
  assert.equal(checkpoint.appendToSeq, 2);
  assert.equal(projection.status(kernel.events()).fresh, true);
  assert.equal(projection.audit(kernel.events()).ok, true);

  const candidates = projection.search(kernel.events(), 'preferred editor', {
    scopeChain: ['project/incremental'],
  });
  assert.ok(candidates.length >= 1);
  assert.equal('searchText' in candidates[0], false);
  assert.equal('value' in candidates[0], false);

  const hydrated = projection.rehydrate(kernel.events(), candidates, {
    scopeChain: ['project/incremental'],
  });
  assert.equal(hydrated.length, candidates.length);
  assert.ok(hydrated.some((item) => item.claim?.id === 'claim/editor'));
  projection.close();
});

test('update publishes only the canonical append range in a hash-chained checkpoint', () => {
  const { kernel } = baseKernel();
  const projection = new SqliteIncrementalFts5Projection();
  const first = projection.rebuild(kernel.events());
  const next = evidence('evidence/compiler', 'Incremental compiler checkpoint');
  kernel.captureEvidence({ eventId: 'event/evidence/compiler', recordedAt: 3, actor: 'human' }, next);

  const second = projection.update(kernel.events());
  assert.equal(second.generation, first.generation + 1);
  assert.equal(second.previousDigest, first.checkpointDigest);
  assert.equal(second.baseEventCount, 2);
  assert.equal(second.eventCount, 3);
  assert.equal(second.appendFromSeq, 3);
  assert.equal(second.appendToSeq, 3);
  assert.equal(projection.audit(kernel.events()).ok, true);

  const candidates = projection.search(kernel.events(), 'compiler checkpoint', {
    scopeChain: ['project/incremental'],
  });
  assert.deepEqual(candidates.map((item) => item.canonicalId), ['evidence/compiler']);
  projection.close();
});

test('evidence restriction incrementally removes both the source and its dependent claim', () => {
  const { kernel, source } = baseKernel();
  const projection = new SqliteIncrementalFts5Projection();
  projection.rebuild(kernel.events());
  kernel.setEvidenceAvailability(
    { eventId: 'event/restrict/editor', recordedAt: 3, actor: 'privacy-controller' },
    source.id,
    'restricted',
    'privacy review',
  );

  projection.update(kernel.events());
  assert.equal(
    projection.search(kernel.events(), 'preferred editor', {
      scopeChain: ['project/incremental'],
    }).length,
    0,
  );
  assert.equal(projection.audit(kernel.events()).ok, true);
  projection.close();
});

test('privacy-excluded evidence and claim values do not leak into plaintext defaults', () => {
  const kernel = new MemoryKernel();
  const personal = evidence('evidence/personal', 'private medical memory', {
    sensitivity: 'personal',
  });
  kernel.captureEvidence({ eventId: 'event/evidence/personal', recordedAt: 1, actor: 'human' }, personal);
  const publicSource = evidence('evidence/public', 'editor preference source');
  kernel.captureEvidence({ eventId: 'event/evidence/public', recordedAt: 2, actor: 'human' }, publicSource);
  kernel.assertClaim(
    { eventId: 'event/claim/value', recordedAt: 3, actor: 'human' },
    claim('claim/value', publicSource, 'uniquetopsecretvalue'),
    { authorizeImmediately: true },
  );

  const conservative = new SqliteIncrementalFts5Projection();
  conservative.rebuild(kernel.events());
  assert.equal(
    conservative.search(kernel.events(), 'medical', {
      scopeChain: ['project/incremental'],
    }).length,
    0,
  );
  assert.equal(
    conservative.search(kernel.events(), 'uniquetopsecretvalue', {
      scopeChain: ['project/incremental'],
    }).length,
    0,
  );
  conservative.close();

  const explicit = new SqliteIncrementalFts5Projection({ indexClaimValues: true });
  explicit.rebuild(kernel.events());
  assert.deepEqual(
    explicit
      .search(kernel.events(), 'uniquetopsecretvalue', {
        scopeChain: ['project/incremental'],
      })
      .map((item) => item.canonicalId),
    ['claim/value'],
  );
  explicit.close();
});

test('a canonical fork is rejected even when it extends to a larger event count', () => {
  const { kernel } = baseKernel();
  const projection = new SqliteIncrementalFts5Projection();
  projection.rebuild(kernel.events());

  const fork = new MemoryKernel();
  const forkSource = evidence('evidence/fork-editor', 'A different canonical editor history');
  fork.captureEvidence(
    { eventId: 'event/evidence/fork-editor', recordedAt: 1, actor: 'human' },
    forkSource,
  );
  fork.assertClaim(
    { eventId: 'event/claim/fork-editor', recordedAt: 2, actor: 'human' },
    claim('claim/fork-editor', forkSource, 'vim'),
    { authorizeImmediately: true },
  );
  const append = evidence('evidence/fork-append', 'Fork-only appended event');
  fork.captureEvidence(
    { eventId: 'event/evidence/fork-append', recordedAt: 3, actor: 'human' },
    append,
  );

  assert.throws(() => projection.update(fork.events()), /fork detected/);
  assert.equal(projection.status(kernel.events()).fresh, true);
  projection.close();
});

test('an injected publication failure rolls back documents, checkpoint, and watermark together', () => {
  const { kernel } = baseKernel();
  let failAt;
  const projection = new SqliteIncrementalFts5Projection({
    faultInjector(point) {
      if (point === failAt) throw new Error(`injected failure at ${point}`);
    },
  });
  const before = projection.rebuild(kernel.events());
  const source = evidence('evidence/rollback', 'rollback sentinel memory');
  kernel.captureEvidence({ eventId: 'event/evidence/rollback', recordedAt: 3, actor: 'human' }, source);

  failAt = 'after-checkpoint';
  assert.throws(() => projection.update(kernel.events()), /injected failure/);
  failAt = undefined;

  const oldEvents = kernel.events().slice(0, 2);
  const status = projection.status(oldEvents);
  assert.equal(status.fresh, true);
  assert.equal(status.checkpoint?.checkpointDigest, before.checkpointDigest);
  assert.equal(
    projection.search(oldEvents, 'rollback sentinel', {
      scopeChain: ['project/incremental'],
    }).length,
    0,
  );
  projection.close();
});

test('fast status detects bucket tampering and full audit checks canonical rows', () => {
  const location = temporaryDatabase();
  try {
    const { kernel } = baseKernel();
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    projection.rebuild(kernel.events());
    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare(`
        UPDATE cl_incremental_buckets
           SET item_count = item_count + 1
         WHERE manifest_kind = 'document' AND bucket = 0
      `)
      .run();
    attacker.close();
    assert.throws(() => projection.status(kernel.events()), /bucket root|bucket counts/);
    assert.equal(projection.audit(kernel.events()).ok, false);
    projection.close();
  } finally {
    location.cleanup();
  }
});

test('a partially created schema is reset before the first durable rebuild', () => {
  const location = temporaryDatabase();
  try {
    const partial = new DatabaseSync(location.database);
    partial.exec('CREATE TABLE cl_incremental_meta (id INTEGER PRIMARY KEY)');
    partial.close();

    const { kernel } = baseKernel();
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    projection.rebuild(kernel.events());
    assert.equal(projection.audit(kernel.events()).ok, true);
    projection.close();
  } finally {
    location.cleanup();
  }
});


test('unchanged rows keep their last-modified generation while changed rows advance', () => {
  const location = temporaryDatabase();
  try {
    const { kernel } = baseKernel();
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    projection.rebuild(kernel.events());
    const before = new DatabaseSync(location.database)
      .prepare(`
        SELECT generation
          FROM cl_incremental_documents
         WHERE kind = 'claim' AND canonical_id = 'claim/editor'
      `)
      .get();
    assert.equal(before.generation, 1);

    const appended = evidence('evidence/unrelated', 'An unrelated incremental event');
    kernel.captureEvidence(
      { eventId: 'event/evidence/unrelated', recordedAt: 3, actor: 'human' },
      appended,
    );
    const checkpoint = projection.update(kernel.events());
    assert.equal(checkpoint.generation, 2);

    const reader = new DatabaseSync(location.database);
    const unchanged = reader
      .prepare(`
        SELECT generation
          FROM cl_incremental_documents
         WHERE kind = 'claim' AND canonical_id = 'claim/editor'
      `)
      .get();
    const created = reader
      .prepare(`
        SELECT generation
          FROM cl_incremental_documents
         WHERE kind = 'evidence' AND canonical_id = 'evidence/unrelated'
      `)
      .get();
    reader.close();
    assert.equal(unchanged.generation, 1);
    assert.equal(created.generation, 2);
    assert.equal(projection.audit(kernel.events()).ok, true);
    projection.close();
  } finally {
    location.cleanup();
  }
});

test('fast verification rejects bucket generations that do not match the active checkpoint', () => {
  const location = temporaryDatabase();
  try {
    const { kernel } = baseKernel();
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    projection.rebuild(kernel.events());
    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare(`
        UPDATE cl_incremental_buckets
           SET generation = generation + 1
         WHERE manifest_kind = 'document' AND bucket = 0
      `)
      .run();
    attacker.close();
    assert.throws(() => projection.status(kernel.events()), /bucket metadata or generation/);
    projection.close();
  } finally {
    location.cleanup();
  }
});

test('fast verification binds metadata to every active-checkpoint field', () => {
  const location = temporaryDatabase();
  try {
    const { kernel } = baseKernel();
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    projection.rebuild(kernel.events());
    const attacker = new DatabaseSync(location.database);
    attacker.prepare(`UPDATE cl_incremental_meta SET updated_at = updated_at + 1 WHERE id = 1`).run();
    attacker.close();
    assert.throws(() => projection.status(kernel.events()), /metadata diverges/);
    projection.close();
  } finally {
    location.cleanup();
  }
});

test('fast verification rejects hidden suffixes in bucket digests', () => {
  const location = temporaryDatabase();
  try {
    const { kernel } = baseKernel();
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    projection.rebuild(kernel.events());
    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare(`
        UPDATE cl_incremental_buckets
           SET bucket_digest = bucket_digest || char(0) || 'hidden-suffix'
         WHERE manifest_kind = 'document' AND bucket = 0
      `)
      .run();
    attacker.close();

    assert.throws(() => projection.status(kernel.events()), /bucket digest encoding is non-canonical/);
    assert.equal(projection.audit(kernel.events()).ok, false);
    projection.rebuild(kernel.events());
    assert.equal(projection.audit(kernel.events()).ok, true);
    projection.close();
  } finally {
    location.cleanup();
  }
});

test('fast verification rejects hidden suffixes in active metadata digests', () => {
  const location = temporaryDatabase();
  try {
    const { kernel } = baseKernel();
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    projection.rebuild(kernel.events());
    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare(`
        UPDATE cl_incremental_meta
           SET active_checkpoint_digest = active_checkpoint_digest || char(0) || 'hidden-suffix'
         WHERE id = 1
      `)
      .run();
    attacker.close();

    assert.throws(() => projection.status(kernel.events()), /metadata text encoding is non-canonical/);
    assert.equal(projection.audit(kernel.events()).ok, false);
    projection.close();
  } finally {
    location.cleanup();
  }
});

test('fast verification rejects hidden suffixes in checkpoint digests', () => {
  const location = temporaryDatabase();
  try {
    const { kernel } = baseKernel();
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    projection.rebuild(kernel.events());
    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare(`
        UPDATE cl_incremental_checkpoints
           SET previous_digest = previous_digest || char(0) || 'hidden-suffix'
         WHERE generation = 1
      `)
      .run();
    attacker.close();

    assert.throws(() => projection.status(kernel.events()), /checkpoint 1 text encoding is non-canonical/);
    assert.equal(projection.audit(kernel.events()).ok, false);
    projection.close();
  } finally {
    location.cleanup();
  }
});

test('fast verification recomputes the immediate predecessor checkpoint digest', () => {
  const location = temporaryDatabase();
  try {
    const { kernel } = baseKernel();
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    projection.rebuild(kernel.events());
    const appended = evidence('evidence/second-checkpoint', 'second checkpoint memory');
    kernel.captureEvidence(
      { eventId: 'event/evidence/second-checkpoint', recordedAt: 3, actor: 'human' },
      appended,
    );
    projection.update(kernel.events());

    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare(`UPDATE cl_incremental_checkpoints SET document_count = document_count + 1 WHERE generation = 1`)
      .run();
    attacker.close();
    assert.throws(() => projection.status(kernel.events()), /predecessor digest is invalid/);
    projection.close();
  } finally {
    location.cleanup();
  }
});

test('checkpoint time remains strictly monotonic when the supplied clock regresses', () => {
  let now = 1_000;
  const { kernel } = baseKernel();
  const projection = new SqliteIncrementalFts5Projection({ clock: () => now });
  const first = projection.rebuild(kernel.events());
  now = 100;
  const appended = evidence('evidence/clock', 'clock rollback memory');
  kernel.captureEvidence(
    { eventId: 'event/evidence/clock', recordedAt: 3, actor: 'human' },
    appended,
  );
  const second = projection.update(kernel.events());
  assert.ok(second.createdAt > first.createdAt);
  projection.close();
});

test('rehydration snapshots caller candidates once and remains cache-independent', () => {
  const { kernel } = baseKernel();
  const projection = new SqliteIncrementalFts5Projection();
  projection.rebuild(kernel.events());
  const [candidate] = projection.search(kernel.events(), 'preferred editor', {
    scopeChain: ['project/incremental'],
    limit: 1,
  });
  assert.ok(candidate);

  let reads = 0;
  const unstable = { ...candidate };
  Object.defineProperty(unstable, 'canonicalId', {
    enumerable: true,
    get() {
      reads += 1;
      return reads === 1 ? candidate.canonicalId : 'forged/id';
    },
  });
  projection.close();
  const hydrated = projection.rehydrate(kernel.events(), [unstable], {
    scopeChain: ['project/incremental'],
  });
  assert.equal(reads, 1);
  assert.equal(hydrated[0]?.candidate.canonicalId, candidate.canonicalId);
});

test('rehydration rejects duplicate or malformed candidate metadata', () => {
  const { kernel } = baseKernel();
  const projection = new SqliteIncrementalFts5Projection();
  projection.rebuild(kernel.events());
  const [candidate] = projection.search(kernel.events(), 'preferred editor', {
    scopeChain: ['project/incremental'],
    limit: 1,
  });
  assert.ok(candidate);
  assert.throws(
    () =>
      projection.rehydrate(kernel.events(), [candidate, candidate], {
        scopeChain: ['project/incremental'],
      }),
    /duplicate incremental candidate/,
  );
  assert.throws(
    () =>
      projection.rehydrate(
        kernel.events(),
        [{ ...candidate, entryDigest: 'not-a-digest' }],
        { scopeChain: ['project/incremental'] },
      ),
    /metadata is malformed/,
  );
  projection.close();
});

test('search rejects a shadow row whose searchable text diverges from the canonical document row', () => {
  const location = temporaryDatabase();
  try {
    const { kernel } = baseKernel();
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    projection.rebuild(kernel.events());
    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare(`
        UPDATE cl_incremental_fts
           SET search_text = 'forgedshadowtoken'
         WHERE kind = 'claim' AND canonical_id = 'claim/editor'
      `)
      .run();
    attacker.close();
    assert.throws(
      () =>
        projection.search(kernel.events(), 'forgedshadowtoken', {
          scopeChain: ['project/incremental'],
        }),
      /shadow row diverged/,
    );
    projection.close();
  } finally {
    location.cleanup();
  }
});

test('an unrelated canonical append repairs corrupted unchanged document and shadow rows', () => {
  const location = temporaryDatabase();
  try {
    const { kernel } = baseKernel();
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    projection.rebuild(kernel.events());
    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare(`
        UPDATE cl_incremental_documents
           SET scope = 'project/forged', search_text = 'forged text'
         WHERE kind = 'claim' AND canonical_id = 'claim/editor'
      `)
      .run();
    attacker
      .prepare(`
        UPDATE cl_incremental_fts
           SET scope = 'project/forged', search_text = 'forged text'
         WHERE kind = 'claim' AND canonical_id = 'claim/editor'
      `)
      .run();
    attacker.close();

    const appended = evidence('evidence/repair-trigger', 'repair trigger memory');
    kernel.captureEvidence(
      { eventId: 'event/evidence/repair-trigger', recordedAt: 3, actor: 'human' },
      appended,
    );
    const checkpoint = projection.update(kernel.events());
    const repaired = projection.search(kernel.events(), 'preferred editor', {
      scopeChain: ['project/incremental'],
    });
    assert.ok(repaired.some((item) => item.canonicalId === 'claim/editor'));
    const reader = new DatabaseSync(location.database);
    const row = reader
      .prepare(`
        SELECT scope, generation
          FROM cl_incremental_documents
         WHERE kind = 'claim' AND canonical_id = 'claim/editor'
      `)
      .get();
    reader.close();
    assert.equal(row.scope, 'project/incremental');
    assert.equal(row.generation, checkpoint.generation);
    assert.equal(projection.audit(kernel.events()).ok, true);
    projection.close();
  } finally {
    location.cleanup();
  }
});

test('publication rejects event-prefix rows beyond the active canonical checkpoint', () => {
  const location = temporaryDatabase();
  try {
    const { kernel } = baseKernel();
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    projection.rebuild(kernel.events());
    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare(`
        INSERT INTO cl_incremental_event_digests (seq, event_id, recorded_at, event_digest)
        VALUES (999, 'future/event', 999, ?)
      `)
      .run(sha('future/event'));
    attacker.close();

    const appended = evidence('evidence/tail', 'tail detection memory');
    kernel.captureEvidence(
      { eventId: 'event/evidence/tail', recordedAt: 3, actor: 'human' },
      appended,
    );
    assert.throws(() => projection.update(kernel.events()), /unpublished tail rows/);
    projection.close();
  } finally {
    location.cleanup();
  }
});

test('configuration changes require explicit rebuild and publish a new checkpoint generation', () => {
  const location = temporaryDatabase();
  try {
    const { kernel } = baseKernel();
    const conservative = new SqliteIncrementalFts5Projection({ database: location.database });
    const first = conservative.rebuild(kernel.events());
    conservative.close();

    const permissive = new SqliteIncrementalFts5Projection({
      database: location.database,
      indexClaimValues: true,
    });
    assert.throws(() => permissive.update(kernel.events()), /configuration changed/);
    const second = permissive.rebuild(kernel.events());
    assert.equal(second.generation, first.generation + 1);
    assert.notEqual(second.configDigest, first.configDigest);
    assert.equal(permissive.audit(kernel.events()).ok, true);
    permissive.close();
  } finally {
    location.cleanup();
  }
});

test('a complete-looking but column-incompatible schema is reset before use', () => {
  const location = temporaryDatabase();
  try {
    const malformed = new DatabaseSync(location.database);
    for (const table of [
      'cl_incremental_meta',
      'cl_incremental_event_digests',
      'cl_incremental_documents',
      'cl_incremental_dependencies',
      'cl_incremental_buckets',
      'cl_incremental_checkpoints',
      'cl_incremental_fts',
    ]) {
      malformed.exec(`CREATE TABLE ${table} (placeholder TEXT)`);
    }
    malformed.close();

    const { kernel } = baseKernel();
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    projection.rebuild(kernel.events());
    assert.equal(projection.audit(kernel.events()).ok, true);
    projection.close();
  } finally {
    location.cleanup();
  }
});

test('constructor options are snapshotted once before validation and storage', () => {
  let databaseReads = 0;
  let sensitivityReads = 0;
  let faultReads = 0;
  let clockReads = 0;
  const options = {
    get database() {
      databaseReads += 1;
      return ':memory:';
    },
    get searchableSensitivities() {
      sensitivityReads += 1;
      return ['public', 'internal'];
    },
    get faultInjector() {
      faultReads += 1;
      return undefined;
    },
    get clock() {
      clockReads += 1;
      return () => 1_000;
    },
  };
  const projection = new SqliteIncrementalFts5Projection(options);
  assert.equal(databaseReads, 1);
  assert.equal(sensitivityReads, 1);
  assert.equal(faultReads, 1);
  assert.equal(clockReads, 1);
  projection.close();
});

test('a no-op update returns the active checkpoint without write amplification', () => {
  const location = temporaryDatabase();
  try {
    const { kernel } = baseKernel();
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    const first = projection.rebuild(kernel.events());
    const second = projection.update(kernel.events());
    assert.equal(second.checkpointDigest, first.checkpointDigest);
    const reader = new DatabaseSync(location.database);
    const count = reader.prepare('SELECT COUNT(*) AS count FROM cl_incremental_checkpoints').get();
    reader.close();
    assert.equal(count.count, 1);
    projection.close();
  } finally {
    location.cleanup();
  }
});

test('explicit rebuild republishes the complete cache as a new repair checkpoint', () => {
  const location = temporaryDatabase();
  try {
    const { kernel } = baseKernel();
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    const first = projection.rebuild(kernel.events());
    const second = projection.rebuild(kernel.events());
    assert.equal(second.generation, first.generation + 1);
    assert.equal(second.baseEventCount, first.eventCount);
    assert.equal(second.eventCount, first.eventCount);
    assert.equal(second.appendFromSeq, second.eventCount + 1);
    assert.equal(second.appendToSeq, second.eventCount);
    assert.equal(projection.audit(kernel.events()).ok, true);
    projection.close();
  } finally {
    location.cleanup();
  }
});

test('search keeps one SQLite read snapshot while a concurrent writer publishes a new checkpoint', () => {
  const location = temporaryDatabase();
  try {
    const { kernel } = baseKernel();
    const writer = new SqliteIncrementalFts5Projection({ database: location.database });
    writer.rebuild(kernel.events());

    const next = evidence('evidence/concurrent', 'concurrent checkpoint memory');
    kernel.captureEvidence(
      { eventId: 'event/evidence/concurrent', recordedAt: 3, actor: 'human' },
      next,
    );
    const oldEvents = kernel.events().slice(0, 2);
    let published = false;
    const reader = new SqliteIncrementalFts5Projection({
      database: location.database,
      faultInjector(point) {
        if (point === 'after-search-verify' && !published) {
          published = true;
          writer.update(kernel.events());
        }
      },
    });

    const candidates = reader.search(oldEvents, 'preferred editor', {
      scopeChain: ['project/incremental'],
    });
    assert.equal(published, true);
    assert.ok(candidates.some((item) => item.canonicalId === 'claim/editor'));
    const hydrated = reader.rehydrate(oldEvents, candidates, {
      scopeChain: ['project/incremental'],
    });
    assert.ok(hydrated.some((item) => item.claim?.id === 'claim/editor'));
    assert.equal(writer.status(kernel.events()).fresh, true);
    reader.close();
    writer.close();
  } finally {
    location.cleanup();
  }
});

test('canonical SQLite text containing U+0000 is rejected before publication', () => {
  const eventKernel = new MemoryKernel();
  eventKernel.captureEvidence(
    { eventId: 'event\u0000suffix', recordedAt: 1, actor: 'human' },
    evidence('evidence/event-nul', 'ordinary text'),
  );
  const eventProjection = new SqliteIncrementalFts5Projection();
  assert.throws(() => eventProjection.rebuild(eventKernel.events()), /event id cannot contain U\+0000/);
  assert.equal(eventProjection.status([]).initialized, false);
  eventProjection.close();

  const textKernel = new MemoryKernel();
  textKernel.captureEvidence(
    { eventId: 'event/evidence/text-nul', recordedAt: 1, actor: 'human' },
    evidence('evidence/text-nul', 'prefix\u0000suffix'),
  );
  const textProjection = new SqliteIncrementalFts5Projection();
  assert.throws(
    () => textProjection.rebuild(textKernel.events()),
    /search text cannot contain U\+0000/,
  );
  assert.equal(textProjection.status([]).initialized, false);
  textProjection.close();

  const malformedUnicodeKernel = new MemoryKernel();
  malformedUnicodeKernel.captureEvidence(
    { eventId: 'event/evidence/malformed-unicode', recordedAt: 1, actor: 'human' },
    evidence('evidence/malformed-unicode', 'prefix\ud800suffix'),
  );
  const malformedUnicodeProjection = new SqliteIncrementalFts5Projection();
  assert.throws(
    () => malformedUnicodeProjection.rebuild(malformedUnicodeKernel.events()),
    /search text must be well-formed Unicode/,
  );
  assert.equal(malformedUnicodeProjection.status([]).initialized, false);
  malformedUnicodeProjection.close();

  const emojiKernel = new MemoryKernel();
  emojiKernel.captureEvidence(
    { eventId: 'event/evidence/emoji', recordedAt: 1, actor: 'human' },
    evidence('evidence/emoji', 'well-formed emoji 😀 memory'),
  );
  const emojiProjection = new SqliteIncrementalFts5Projection();
  emojiProjection.rebuild(emojiKernel.events());
  assert.equal(emojiProjection.audit(emojiKernel.events()).ok, true);
  emojiProjection.close();
});

test('raw FTS generation type corruption is rejected, audited, and repaired on append', () => {
  const location = temporaryDatabase();
  try {
    const { kernel } = baseKernel();
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    projection.rebuild(kernel.events());
    const attacker = new DatabaseSync(location.database);
    attacker.prepare(`UPDATE cl_incremental_fts SET generation = '1junk'`).run();
    attacker.close();

    assert.throws(
      () =>
        projection.search(kernel.events(), 'preferred editor', {
          scopeChain: ['project/incremental'],
        }),
      /malformed raw SQLite metadata/,
    );
    assert.equal(projection.audit(kernel.events()).ok, false);

    const appended = evidence('evidence/generation-repair', 'generation repair trigger');
    kernel.captureEvidence(
      { eventId: 'event/evidence/generation-repair', recordedAt: 3, actor: 'human' },
      appended,
    );
    projection.update(kernel.events());
    const reader = new DatabaseSync(location.database);
    const malformed = reader
      .prepare(`SELECT COUNT(*) AS count FROM cl_incremental_fts WHERE typeof(generation) NOT IN ('integer', 'real')`)
      .get();
    reader.close();
    assert.equal(malformed.count, 0);
    assert.equal(projection.audit(kernel.events()).ok, true);
    projection.close();
  } finally {
    location.cleanup();
  }
});

test('search rejects duplicate exact FTS rows at the caller limit boundary', () => {
  const location = temporaryDatabase();
  try {
    const { kernel } = baseKernel();
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    projection.rebuild(kernel.events());
    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare(`
        INSERT INTO cl_incremental_fts
          (canonical_id, kind, scope, lifecycle, entry_digest, generation, search_text)
        SELECT canonical_id, kind, scope, lifecycle, entry_digest, generation, search_text
          FROM cl_incremental_fts
         WHERE kind = 'claim' AND canonical_id = 'claim/editor'
      `)
      .run();
    attacker.close();

    assert.throws(
      () =>
        projection.search(kernel.events(), 'preferred editor', {
          scopeChain: ['project/incremental'],
          limit: 1,
        }),
      /duplicate incremental FTS row/,
    );
    assert.equal(projection.audit(kernel.events()).ok, false);
    projection.close();
  } finally {
    location.cleanup();
  }
});

test('NUL-suffixed FTS text corruption cannot hide behind Node SQLite text truncation', () => {
  const location = temporaryDatabase();
  try {
    const { kernel } = baseKernel();
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    projection.rebuild(kernel.events());
    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare(`
        UPDATE cl_incremental_fts
           SET entry_digest = entry_digest || char(0) || 'hidden-suffix'
         WHERE kind = 'claim' AND canonical_id = 'claim/editor'
      `)
      .run();
    attacker.close();

    assert.throws(
      () =>
        projection.search(kernel.events(), 'preferred editor', {
          scopeChain: ['project/incremental'],
        }),
      /malformed raw SQLite metadata/,
    );
    assert.equal(projection.audit(kernel.events()).ok, false);

    const appended = evidence('evidence/nul-repair', 'NUL repair trigger');
    kernel.captureEvidence(
      { eventId: 'event/evidence/nul-repair', recordedAt: 3, actor: 'human' },
      appended,
    );
    projection.update(kernel.events());
    assert.equal(projection.audit(kernel.events()).ok, true);
    projection.close();
  } finally {
    location.cleanup();
  }
});


test('invalid UTF-8 FTS bytes cannot masquerade as a canonical replacement-character id', () => {
  const location = temporaryDatabase();
  try {
    const kernel = new MemoryKernel();
    kernel.captureEvidence(
      { eventId: 'event/evidence/replacement', recordedAt: 1, actor: 'human' },
      evidence('evidence/�', 'UTF-8 encoding sentinel'),
    );
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    projection.rebuild(kernel.events());
    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare(`
        UPDATE cl_incremental_fts
           SET canonical_id = CAST(X'65766964656E63652FFF' AS TEXT)
         WHERE kind = 'evidence' AND canonical_id = 'evidence/�'
      `)
      .run();
    attacker.close();

    assert.throws(
      () =>
        projection.search(kernel.events(), 'encoding sentinel', {
          scopeChain: ['project/incremental'],
        }),
      /malformed raw SQLite metadata/,
    );
    assert.equal(projection.audit(kernel.events()).ok, false);

    const appended = evidence('evidence/utf8-repair', 'UTF-8 repair trigger');
    kernel.captureEvidence(
      { eventId: 'event/evidence/utf8-repair', recordedAt: 2, actor: 'human' },
      appended,
    );
    projection.update(kernel.events());
    assert.equal(projection.audit(kernel.events()).ok, true);
    projection.close();
  } finally {
    location.cleanup();
  }
});

test('invalid UTF-8 document identities are audited and repaired by rowid', () => {
  const location = temporaryDatabase();
  try {
    const kernel = new MemoryKernel();
    kernel.captureEvidence(
      { eventId: 'event/evidence/document-encoding', recordedAt: 1, actor: 'human' },
      evidence('evidence/�', 'document encoding sentinel'),
    );
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    projection.rebuild(kernel.events());
    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare(`
        UPDATE cl_incremental_documents
           SET canonical_id = CAST(X'65766964656E63652FFF' AS TEXT)
         WHERE kind = 'evidence' AND canonical_id = 'evidence/�'
      `)
      .run();
    attacker.close();

    assert.throws(
      () =>
        projection.search(kernel.events(), 'document encoding sentinel', {
          scopeChain: ['project/incremental'],
        }),
      /shadow row diverged/,
    );
    assert.equal(projection.audit(kernel.events()).ok, false);

    const appended = evidence('evidence/document-repair', 'document repair trigger');
    kernel.captureEvidence(
      { eventId: 'event/evidence/document-repair', recordedAt: 2, actor: 'human' },
      appended,
    );
    projection.update(kernel.events());
    const reader = new DatabaseSync(location.database);
    const repaired = reader
      .prepare(`
        SELECT hex(canonical_id) AS encoded
          FROM cl_incremental_documents
         WHERE kind = 'evidence' AND canonical_id = 'evidence/�'
      `)
      .get();
    reader.close();
    assert.equal(repaired.encoded, '65766964656E63652FEFBFBD');
    assert.equal(projection.audit(kernel.events()).ok, true);
    projection.close();
  } finally {
    location.cleanup();
  }
});

test('invalid UTF-8 dependency identities are audited and repaired by rowid', () => {
  const location = temporaryDatabase();
  try {
    const kernel = new MemoryKernel();
    const source = evidence('evidence/�', 'dependency encoding sentinel');
    kernel.captureEvidence(
      { eventId: 'event/evidence/dependency-encoding', recordedAt: 1, actor: 'human' },
      source,
    );
    kernel.assertClaim(
      { eventId: 'event/claim/dependency-encoding', recordedAt: 2, actor: 'human' },
      claim('claim/dependency-encoding', source),
      { authorizeImmediately: true },
    );
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    projection.rebuild(kernel.events());
    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare(`
        UPDATE cl_incremental_dependencies
           SET evidence_id = CAST(X'65766964656E63652FFF' AS TEXT)
         WHERE evidence_id = 'evidence/�'
      `)
      .run();
    attacker.close();

    assert.equal(projection.audit(kernel.events()).ok, false);
    const appended = evidence('evidence/dependency-repair', 'dependency repair trigger');
    kernel.captureEvidence(
      { eventId: 'event/evidence/dependency-repair', recordedAt: 3, actor: 'human' },
      appended,
    );
    projection.update(kernel.events());
    const reader = new DatabaseSync(location.database);
    const repaired = reader
      .prepare(`
        SELECT hex(evidence_id) AS encoded
          FROM cl_incremental_dependencies
         WHERE claim_id = 'claim/dependency-encoding'
      `)
      .get();
    reader.close();
    assert.equal(repaired.encoded, '65766964656E63652FEFBFBD');
    assert.equal(projection.audit(kernel.events()).ok, true);
    projection.close();
  } finally {
    location.cleanup();
  }
});

test('duplicate document byte aliases are removed during append repair', () => {
  const location = temporaryDatabase();
  try {
    const kernel = new MemoryKernel();
    kernel.captureEvidence(
      { eventId: 'event/evidence/document-alias', recordedAt: 1, actor: 'human' },
      evidence('evidence/�', 'document alias sentinel'),
    );
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    projection.rebuild(kernel.events());
    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare(`
        INSERT INTO cl_incremental_documents
          (canonical_id, kind, scope, lifecycle, source_digest, search_text,
           entry_digest, bucket, generation)
        SELECT CAST(X'65766964656E63652FFF' AS TEXT), kind, scope, lifecycle,
               source_digest, search_text, entry_digest, bucket, generation
          FROM cl_incremental_documents
         WHERE kind = 'evidence' AND canonical_id = 'evidence/�'
      `)
      .run();
    attacker.close();

    assert.equal(projection.audit(kernel.events()).ok, false);
    const appended = evidence('evidence/document-alias-repair', 'document alias repair trigger');
    kernel.captureEvidence(
      { eventId: 'event/evidence/document-alias-repair', recordedAt: 2, actor: 'human' },
      appended,
    );
    projection.update(kernel.events());
    const reader = new DatabaseSync(location.database);
    const aliases = reader
      .prepare(`
        SELECT COUNT(*) AS count
          FROM cl_incremental_documents
         WHERE kind = 'evidence'
           AND CAST(canonical_id AS BLOB) IN (X'65766964656E63652FFF', X'65766964656E63652FEFBFBD')
      `)
      .get();
    reader.close();
    assert.equal(aliases.count, 1);
    assert.equal(projection.audit(kernel.events()).ok, true);
    projection.close();
  } finally {
    location.cleanup();
  }
});

test('duplicate dependency byte aliases are removed during append repair', () => {
  const location = temporaryDatabase();
  try {
    const kernel = new MemoryKernel();
    const source = evidence('evidence/�', 'dependency alias sentinel');
    kernel.captureEvidence(
      { eventId: 'event/evidence/dependency-alias', recordedAt: 1, actor: 'human' },
      source,
    );
    kernel.assertClaim(
      { eventId: 'event/claim/dependency-alias', recordedAt: 2, actor: 'human' },
      claim('claim/dependency-alias', source),
      { authorizeImmediately: true },
    );
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    projection.rebuild(kernel.events());
    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare(`
        INSERT INTO cl_incremental_dependencies (evidence_id, claim_id, bucket, generation)
        SELECT CAST(X'65766964656E63652FFF' AS TEXT), claim_id, bucket, generation
          FROM cl_incremental_dependencies
         WHERE evidence_id = 'evidence/�' AND claim_id = 'claim/dependency-alias'
      `)
      .run();
    attacker.close();

    assert.equal(projection.audit(kernel.events()).ok, false);
    const appended = evidence('evidence/dependency-alias-repair', 'dependency alias repair trigger');
    kernel.captureEvidence(
      { eventId: 'event/evidence/dependency-alias-repair', recordedAt: 3, actor: 'human' },
      appended,
    );
    projection.update(kernel.events());
    const reader = new DatabaseSync(location.database);
    const aliases = reader
      .prepare(`
        SELECT COUNT(*) AS count
          FROM cl_incremental_dependencies
         WHERE claim_id = 'claim/dependency-alias'
           AND CAST(evidence_id AS BLOB) IN (X'65766964656E63652FFF', X'65766964656E63652FEFBFBD')
      `)
      .get();
    reader.close();
    assert.equal(aliases.count, 1);
    assert.equal(projection.audit(kernel.events()).ok, true);
    projection.close();
  } finally {
    location.cleanup();
  }
});

test('invalid UTF-8 event-prefix identities fail closed as canonical lineage corruption', () => {
  const location = temporaryDatabase();
  try {
    const kernel = new MemoryKernel();
    kernel.captureEvidence(
      { eventId: 'event/�', recordedAt: 1, actor: 'human' },
      evidence('evidence/event-encoding', 'event encoding sentinel'),
    );
    const projection = new SqliteIncrementalFts5Projection({ database: location.database });
    projection.rebuild(kernel.events());
    const attacker = new DatabaseSync(location.database);
    attacker
      .prepare(`
        UPDATE cl_incremental_event_digests
           SET event_id = CAST(X'6576656E742FFF' AS TEXT)
         WHERE seq = 1
      `)
      .run();
    attacker.close();

    assert.equal(projection.audit(kernel.events()).ok, false);
    kernel.captureEvidence(
      { eventId: 'event/append-after-corruption', recordedAt: 2, actor: 'human' },
      evidence('evidence/append-after-corruption', 'append after corruption'),
    );
    assert.throws(() => projection.update(kernel.events()), /fork detected at sequence 1/);
    projection.close();
  } finally {
    location.cleanup();
  }
});
