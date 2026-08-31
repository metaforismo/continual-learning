import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import {
  ClaimProjection,
  EvidenceProjection,
  evidenceRefFor,
} from '../dist/index.js';
import {
  CanonicalChangeFeed,
  canonicalReadCursorForEvents,
} from '../dist/durable/index.js';
import { SqliteConsumerCheckpointStore } from '../dist/durable/index.js';
import {
  CanonicalObjectReadIndex,
  CanonicalObjectReadIndexIntegrityError,
  CanonicalObjectReadIndexRebuildRequiredError,
} from '../dist/retrieval/index.js';
import { canonicalJson } from '../dist/retrieval/canonical.js';

function sha(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function temporaryDatabase(prefix) {
  const directory = mkdtempSync(join(tmpdir(), `${prefix}-`));
  return {
    database: join(directory, 'state.sqlite'),
    cleanup() {
      rmSync(directory, { recursive: true, force: true });
    },
  };
}

function evidence(id, recordedAt, overrides = {}) {
  const preview = overrides.preview ?? `canonical object memory ${id}`;
  return {
    id: `evidence/${id}`,
    scope: 'project/object-read',
    kind: 'human-feedback',
    sourceGroups: [`origin/${id}`],
    authority: 'human-explicit',
    observedAt: recordedAt,
    sensitivity: 'public',
    taints: [],
    artifact: {
      uri: `memory://artifact/${id}`,
      digest: sha(`artifact/${id}`),
      sizeBytes: preview.length,
      mediaType: 'text/plain',
      encryption: 'none',
      retention: 'durable',
    },
    preview,
    derivedFrom: [],
    labels: ['object-read'],
    ...overrides,
  };
}

function claimFromEvidence(record, id, value, validFrom = 10) {
  return {
    id: `claim/${id}`,
    key: {
      scope: record.scope,
      subject: 'agent',
      predicate: 'preferred-editor',
    },
    value,
    valid: { from: validFrom },
    authority: record.authority,
    epistemicStatus: 'observed',
    confidence: 1,
    evidence: [evidenceRefFor(record, ['supports'])],
    derivedFrom: [],
    tags: ['editor', 'object-read'],
  };
}

function event(seq, type, data, recordedAt = seq) {
  return Object.freeze({
    schemaVersion: 1,
    id: `event/object-read/${seq}`,
    seq,
    type,
    recordedAt,
    actor: 'object-read-test',
    data,
  });
}

function canonicalScenario(options = {}) {
  const support = evidence('support', 1, { preview: 'Zed editor canonical support' });
  const first = claimFromEvidence(support, 'editor-v1', 'zed', 10);
  const replacement = claimFromEvidence(support, 'editor-v2', 'vscode', 30);
  const events = [
    event(1, 'evidence.captured', { evidence: support }, 1),
    event(2, 'claim.asserted', { claim: first, initialLifecycle: 'active' }, 2),
    ...(options.includeReplacement === false
      ? []
      : [
          event(3, 'claim.asserted', { claim: replacement, initialLifecycle: 'active' }, 3),
          event(
            4,
            'claim.superseded',
            {
              previousClaimId: first.id,
              replacementClaimId: replacement.id,
              effectiveAt: 30,
              reason: 'maintainer preference changed',
            },
            4,
          ),
        ]),
    ...(options.restrictEvidence === true
      ? [
          event(
            options.includeReplacement === false ? 3 : 5,
            'evidence.availability-changed',
            {
              evidenceId: support.id,
              availability: 'restricted',
              reason: 'privacy review',
            },
            options.includeReplacement === false ? 3 : 5,
          ),
        ]
      : []),
  ];
  return { support, first, replacement, events: Object.freeze(events) };
}

function fakeDurableLedger(events) {
  const snapshot = Object.freeze([...events]);
  const cursor = canonicalReadCursorForEvents(snapshot);
  let rangeReads = 0;
  return {
    audit() {
      return Object.freeze({ ok: true, errors: Object.freeze([]) });
    },
    status() {
      return Object.freeze({ ok: true, reason: 'synthetic canonical ledger is healthy' });
    },
    cursor() {
      return cursor;
    },
    readRange(firstSeq, count) {
      rangeReads += 1;
      return snapshot.slice(firstSeq - 1, firstSeq - 1 + count);
    },
    resetRangeReads() {
      rangeReads = 0;
    },
    rangeReads() {
      return rangeReads;
    },
  };
}

function feedFor(events, maxBatchEvents = 256) {
  const ledger = fakeDurableLedger(events);
  const feed = CanonicalChangeFeed.open(ledger, {
    maxBatchEvents,
    startupVerification: 'tail-only',
  });
  return { ledger, feed };
}

function makeRuntime(suffix, events, options = {}) {
  const location = temporaryDatabase(`cl-object-read-${suffix}`);
  const store = new SqliteConsumerCheckpointStore({ database: location.database });
  const { ledger, feed } = feedFor(events, options.maxBatchEvents ?? 256);
  const prefix = `obj_${suffix.replace(/[^a-z0-9]+/g, '_')}_`;
  const index = new CanonicalObjectReadIndex(store, {
    consumerId: `projection/object-read/${suffix}`,
    projectionTablePrefix: prefix,
    bucketBits: options.bucketBits ?? 8,
  });
  index.register();
  return {
    location,
    store,
    ledger,
    feed,
    index,
    prefix,
    cleanup() {
      store.close();
      location.cleanup();
    },
  };
}

function catchUp(runtime) {
  return runtime.index.catchUp(runtime.feed);
}

test('selected current objects equal deterministic canonical replay without lifetime rehydration', () => {
  const scenario = canonicalScenario();
  const runtime = makeRuntime('parity', scenario.events, { maxBatchEvents: 1 });
  try {
    const summary = catchUp(runtime);
    assert.equal(summary.batches, scenario.events.length);
    assert.equal(summary.events, scenario.events.length);

    const evidenceProjection = EvidenceProjection.from(scenario.events);
    const claimProjection = ClaimProjection.from(scenario.events);
    runtime.ledger.resetRangeReads();

    const selectedEvidence = runtime.index.lookupEvidence(runtime.feed, scenario.support.id, {
      scopeChain: ['project/object-read'],
    });
    const selectedClaim = runtime.index.lookupClaim(runtime.feed, scenario.first.id, {
      scopeChain: ['project/object-read'],
    });

    assert.ok(selectedEvidence);
    assert.ok(selectedClaim);
    assert.deepEqual(selectedEvidence.record.record, evidenceProjection.get(scenario.support.id).record);
    assert.equal(selectedEvidence.record.availabilityAtSelection, 'available');
    assert.deepEqual(selectedClaim.record.claim, claimProjection.get(scenario.first.id));
    assert.equal(selectedClaim.record.lifecycle, claimProjection.lifecycle(scenario.first.id));
    assert.equal(selectedEvidence.canonicalCursor.eventCount, scenario.events.length);
    assert.equal(selectedClaim.canonicalCursorDigest, selectedEvidence.canonicalCursorDigest);
    assert.equal(selectedEvidence.headProof.siblings.length, 8);
    assert.equal(selectedEvidence.versionProof.siblings.length, 8);
    assert.equal(runtime.ledger.rangeReads(), 0, 'selected reads must not ask the ledger for lifetime events');
    assert.equal(runtime.index.audit().ok, true, runtime.index.audit().errors.join('; '));
  } finally {
    runtime.cleanup();
  }
});

test('knownAt and validAt preserve transaction time separately from world time', () => {
  const scenario = canonicalScenario();
  const runtime = makeRuntime('bitemporal', scenario.events);
  try {
    catchUp(runtime);

    const beforeSupersession = runtime.index.lookupClaimKnownAt(runtime.feed, scenario.first.id, {
      scopeChain: ['project/object-read'],
      knownAt: 3,
    });
    const afterSupersession = runtime.index.lookupClaimKnownAt(runtime.feed, scenario.first.id, {
      scopeChain: ['project/object-read'],
      knownAt: 4,
    });
    assert.equal(beforeSupersession.record.lifecycle, 'active');
    assert.equal(afterSupersession.record.lifecycle, 'superseded');
    assert.equal(afterSupersession.record.supersededAt, 30);
    assert.equal(beforeSupersession.knownTo, 4);
    assert.equal(afterSupersession.knownTo, undefined);

    assert.ok(
      runtime.index.lookupClaimValidAt(runtime.feed, scenario.first.id, {
        scopeChain: ['project/object-read'],
        knownAt: 4,
        validAt: 29,
      }),
    );
    assert.equal(
      runtime.index.lookupClaimValidAt(runtime.feed, scenario.first.id, {
        scopeChain: ['project/object-read'],
        knownAt: 4,
        validAt: 30,
      }),
      undefined,
    );
    assert.ok(
      runtime.index.lookupClaimValidAt(runtime.feed, scenario.first.id, {
        scopeChain: ['project/object-read'],
        knownAt: 3,
        validAt: 35,
      }),
      'before transaction time 4 the system did not yet know the claim would be superseded',
    );
  } finally {
    runtime.cleanup();
  }
});

test('current privacy overlays historical reads and provenance closure reports unavailable evidence', () => {
  const scenario = canonicalScenario({ restrictEvidence: true });
  const runtime = makeRuntime('privacy', scenario.events);
  try {
    catchUp(runtime);
    const current = runtime.index.lookupEvidence(runtime.feed, scenario.support.id, {
      scopeChain: ['project/object-read'],
    });
    const historical = runtime.index.lookupEvidenceKnownAt(runtime.feed, scenario.support.id, {
      scopeChain: ['project/object-read'],
      knownAt: 1,
    });
    assert.equal(current.record.availabilityAtSelection, 'restricted');
    assert.equal(current.record.contentAvailable, false);
    assert.equal(Object.hasOwn(current.record.record, 'preview'), false);
    assert.equal(historical.record.availabilityAtSelection, 'available');
    assert.equal(historical.record.currentAvailability, 'restricted');
    assert.equal(historical.record.contentAvailable, false);
    assert.equal(Object.hasOwn(historical.record.record, 'preview'), false);

    const hydrated = runtime.index.rehydrateClaim(runtime.feed, scenario.replacement.id, {
      scopeChain: ['project/object-read'],
    });
    assert.equal(hydrated.complete, false);
    assert.deepEqual(hydrated.unavailableEvidenceIds, [scenario.support.id]);
    assert.equal(hydrated.evidence[0].record.contentAvailable, false);
  } finally {
    runtime.cleanup();
  }
});

test('exact provenance closure is complete while every referenced evidence object remains available', () => {
  const scenario = canonicalScenario({ includeReplacement: false });
  const runtime = makeRuntime('closure', scenario.events);
  try {
    catchUp(runtime);
    const hydrated = runtime.index.rehydrateClaim(runtime.feed, scenario.first.id, {
      scopeChain: ['project/object-read'],
    });
    assert.equal(hydrated.complete, true);
    assert.equal(hydrated.evidence.length, 1);
    assert.equal(hydrated.evidence[0].canonicalId, scenario.support.id);
    assert.deepEqual(hydrated.unavailableEvidenceIds, []);
  } finally {
    runtime.cleanup();
  }
});

test('scope is a hard lookup boundary and stale candidate cursors fail closed', () => {
  const scenario = canonicalScenario({ includeReplacement: false });
  const runtime = makeRuntime('scope', scenario.events);
  try {
    catchUp(runtime);
    assert.equal(
      runtime.index.lookupEvidence(runtime.feed, scenario.support.id, {
        scopeChain: ['project/other'],
      }),
      undefined,
    );
    const current = runtime.index.lookupEvidence(runtime.feed, scenario.support.id, {
      scopeChain: ['project/object-read'],
    });
    assert.throws(
      () =>
        runtime.index.rehydrateAddresses(
          runtime.feed,
          [
            {
              kind: 'evidence',
              canonicalId: scenario.support.id,
              expectedCursorDigest: sha('stale-cursor'),
            },
          ],
          { scopeChain: ['project/object-read'] },
        ),
      (error) =>
        error instanceof CanonicalObjectReadIndexIntegrityError && /stale/.test(error.message),
    );
    const selected = runtime.index.rehydrateAddresses(
      runtime.feed,
      [
        {
          kind: 'evidence',
          canonicalId: scenario.support.id,
          expectedCursorDigest: current.canonicalCursorDigest,
        },
      ],
      { scopeChain: ['project/object-read'] },
    );
    assert.equal(selected[0].proofDigest, current.proofDigest);
  } finally {
    runtime.cleanup();
  }
});

test('registration rejects tail bootstrap because incomplete history cannot be authenticated', () => {
  const scenario = canonicalScenario({ includeReplacement: false });
  const runtime = makeRuntime('genesis', scenario.events);
  try {
    const tailFeed = CanonicalChangeFeed.open(fakeDurableLedger(scenario.events), {
      startAt: 'tail',
      startupVerification: 'tail-only',
    });
    const otherStore = new SqliteConsumerCheckpointStore();
    const other = new CanonicalObjectReadIndex(otherStore, {
      consumerId: 'projection/object-read/tail',
      projectionTablePrefix: 'obj_tail_',
      bucketBits: 8,
    });
    assert.throws(
      () => other.register(tailFeed.checkpoint()),
      (error) => error instanceof CanonicalObjectReadIndexRebuildRequiredError,
    );
    otherStore.close();
  } finally {
    runtime.cleanup();
  }
});

test('restart preserves the same cursor-bound selected read and forensic audit', () => {
  const scenario = canonicalScenario();
  const runtime = makeRuntime('restart', scenario.events);
  let before;
  try {
    catchUp(runtime);
    before = runtime.index.lookupClaim(runtime.feed, scenario.first.id, {
      scopeChain: ['project/object-read'],
    });
    runtime.store.close();

    const reopenedStore = new SqliteConsumerCheckpointStore({ database: runtime.location.database });
    const reopened = new CanonicalObjectReadIndex(reopenedStore, {
      consumerId: runtime.index.binding.consumerId,
      projectionTablePrefix: runtime.index.binding.projectionTablePrefix,
      bucketBits: 8,
    });
    reopened.register();
    const { feed } = feedFor(scenario.events);
    const after = reopened.lookupClaim(feed, scenario.first.id, {
      scopeChain: ['project/object-read'],
    });
    assert.equal(after.proofDigest, before.proofDigest);
    assert.equal(reopened.audit().ok, true, reopened.audit().errors.join('; '));
    reopenedStore.close();
  } finally {
    runtime.location.cleanup();
  }
});

test('independent genesis rebuilds produce equivalent object roots and selected state', () => {
  const scenario = canonicalScenario({ restrictEvidence: true });
  const first = makeRuntime('rebuild_a', scenario.events);
  const second = makeRuntime('rebuild_b', scenario.events);
  try {
    catchUp(first);
    catchUp(second);
    const firstStatus = first.index.status();
    const secondStatus = second.index.status();
    assert.equal(firstStatus.headRootDigest, secondStatus.headRootDigest);
    assert.equal(firstStatus.versionRootDigest, secondStatus.versionRootDigest);
    assert.equal(firstStatus.headCount, secondStatus.headCount);
    assert.equal(firstStatus.versionCount, secondStatus.versionCount);

    const firstRead = first.index.lookupClaim(first.feed, scenario.first.id, {
      scopeChain: ['project/object-read'],
    });
    const secondRead = second.index.lookupClaim(second.feed, scenario.first.id, {
      scopeChain: ['project/object-read'],
    });
    assert.equal(firstRead.stateDigest, secondRead.stateDigest);
    assert.equal(firstRead.versionDigest, secondRead.versionDigest);
    assert.deepEqual(firstRead.record, secondRead.record);
    assert.equal(first.index.audit().ok, true);
    assert.equal(second.index.audit().ok, true);
  } finally {
    first.cleanup();
    second.cleanup();
  }
});

test('selected lookup remains independent of lifetime ledger reads as history grows', () => {
  const records = Array.from({ length: 512 }, (_, index) => evidence(`scale-${index}`, index + 1));
  const events = records.map((record, index) =>
    event(index + 1, 'evidence.captured', { evidence: record }, index + 1),
  );
  const runtime = makeRuntime('scale', events, { maxBatchEvents: 128, bucketBits: 10 });
  try {
    catchUp(runtime);
    runtime.ledger.resetRangeReads();
    const selected = runtime.index.lookupEvidence(runtime.feed, records[411].id, {
      scopeChain: ['project/object-read'],
    });
    assert.equal(selected.record.record.id, records[411].id);
    assert.equal(selected.headProof.siblings.length, 10);
    assert.equal(selected.versionProof.siblings.length, 10);
    assert.equal(runtime.ledger.rangeReads(), 0);
  } finally {
    runtime.cleanup();
  }
});

const tamperCases = [
  {
    name: 'object bytes',
    mutate(raw, prefix) {
      raw.prepare(`UPDATE ${prefix}versions SET state_json = ? WHERE kind = ?`).run('{}', 'claim');
    },
  },
  {
    name: 'row digest',
    mutate(raw, prefix) {
      raw.prepare(`UPDATE ${prefix}versions SET row_digest = ? WHERE kind = ?`).run(
        sha('forged-version-digest'),
        'claim',
      );
    },
  },
  {
    name: 'transaction interval',
    mutate(raw, prefix) {
      raw.prepare(`UPDATE ${prefix}versions SET known_to = ? WHERE kind = ? AND known_to IS NULL`).run(
        999,
        'claim',
      );
    },
  },
  {
    name: 'head metadata',
    mutate(raw, prefix) {
      raw.prepare(`UPDATE ${prefix}heads SET recorded_at = recorded_at + 1 WHERE kind = ?`).run(
        'claim',
      );
    },
  },
  {
    name: 'evidence references',
    mutate(raw, prefix) {
      const row = raw
        .prepare(`SELECT rowid, state_json FROM ${prefix}versions WHERE kind = ? ORDER BY version_seq DESC LIMIT 1`)
        .get('claim');
      const state = JSON.parse(row.state_json);
      state.claim.evidence[0].sourceId = 'evidence/forged';
      raw.prepare(`UPDATE ${prefix}versions SET state_json = ? WHERE rowid = ?`).run(
        canonicalJson(state),
        row.rowid,
      );
    },
  },
  {
    name: 'publication cursor',
    mutate(raw, prefix) {
      raw.prepare(`UPDATE ${prefix}meta SET after_cursor_digest = ?`).run(sha('forged-cursor'));
    },
  },
];

for (const tamper of tamperCases) {
  test(`tampered ${tamper.name} fails closed on selected read and audit`, () => {
    const scenario = canonicalScenario();
    const suffix = `tamper_${tamper.name.replace(/[^a-z0-9]+/g, '_')}`;
    const runtime = makeRuntime(suffix, scenario.events);
    try {
      catchUp(runtime);
      runtime.store.close();
      const raw = new DatabaseSync(runtime.location.database);
      tamper.mutate(raw, runtime.prefix);
      raw.close();

      const reopenedStore = new SqliteConsumerCheckpointStore({ database: runtime.location.database });
      const reopened = new CanonicalObjectReadIndex(reopenedStore, {
        consumerId: runtime.index.binding.consumerId,
        projectionTablePrefix: runtime.prefix,
        bucketBits: 8,
      });
      reopened.register();
      const { feed } = feedFor(scenario.events);
      assert.throws(
        () =>
          reopened.lookupClaim(feed, scenario.first.id, {
            scopeChain: ['project/object-read'],
          }),
        /integrity|invalid|diverged|unavailable|interval|metadata|cursor|state/i,
      );
      assert.equal(reopened.audit().ok, false);
      reopenedStore.close();
    } finally {
      runtime.location.cleanup();
    }
  });
}
