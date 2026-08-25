import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { evidenceRefFor } from '../dist/index.js';

export function sha(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

export function evidence(id, overrides = {}) {
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

export function claim(id, source, value, overrides = {}) {
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

export function appendEvidence(kernel, source, time = 1) {
  kernel.captureEvidence(
    { eventId: `capture-${source.id}`, recordedAt: time, actor: 'ingestor' },
    source,
  );
}

export function appendClaim(kernel, candidate, time = 2) {
  kernel.assertClaim(
    { eventId: `assert-${candidate.id}`, recordedAt: time, actor: 'writer' },
    candidate,
    { authorizeImmediately: true },
  );
}

export function fixture() {
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
