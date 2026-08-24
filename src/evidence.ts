import {
  AUTHORITY_RANK,
  type EvidenceAvailability,
  type EvidenceRecord,
  type EvidenceRef,
  type EvidenceSensitivity,
  type MemoryEvent,
} from './domain.js';

const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const MAX_PREVIEW_LENGTH = 512;

const SENSITIVITY_RANK: Readonly<Record<EvidenceSensitivity, number>> = Object.freeze({
  public: 0,
  internal: 1,
  personal: 2,
  sensitive: 3,
  secret: 4,
});

export interface EvidenceValidationReport {
  readonly ok: boolean;
  readonly errors: readonly string[];
  readonly warnings: readonly string[];
}

export interface ProjectedEvidence {
  readonly record: EvidenceRecord;
  readonly availability: EvidenceAvailability;
  readonly capturedSeq: number;
  readonly latestAvailabilitySeq?: number;
}

function freezeReport(errors: string[], warnings: string[]): EvidenceValidationReport {
  return Object.freeze({
    ok: errors.length === 0,
    errors: Object.freeze(errors),
    warnings: Object.freeze(warnings),
  });
}

function normalizedStrings(values: readonly string[]): readonly string[] {
  return Object.freeze([...new Set(values)].sort());
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

/**
 * Validate one content-addressed evidence record before it enters the canonical ledger.
 *
 * `existingRecords` is the transaction-time prefix that already exists. Requiring all parents to
 * pre-exist makes the provenance graph a DAG. Derived evidence inherits source-group identity,
 * taints, sensitivity, and an authority ceiling from its parents, preventing summaries or extracted
 * spans from laundering origin, trust, or privacy labels.
 */
export function validateEvidenceForCapture(
  record: EvidenceRecord,
  existingRecords: ReadonlyMap<string, EvidenceRecord> = new Map(),
  recordedAt?: number,
): EvidenceValidationReport {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (record.id.trim().length === 0) errors.push('evidence id cannot be empty');
  if (existingRecords.has(record.id)) errors.push(`evidence id already exists: ${record.id}`);
  if (record.scope.trim().length === 0) errors.push('evidence scope cannot be empty');
  if (!Number.isFinite(record.observedAt)) errors.push('evidence observedAt must be finite');
  if (recordedAt !== undefined) {
    if (!Number.isFinite(recordedAt)) errors.push('evidence recordedAt must be finite');
    if (record.observedAt > recordedAt) {
      errors.push('evidence cannot be observed after its canonical capture time');
    }
  }

  if (record.sourceGroups.length === 0) errors.push('evidence requires at least one source group');
  if (record.sourceGroups.some((group) => group.trim().length === 0)) {
    errors.push('evidence source groups cannot contain empty values');
  }
  if (new Set(record.sourceGroups).size !== record.sourceGroups.length) {
    errors.push('evidence source groups must not contain duplicates');
  }
  if (!sameStrings(record.sourceGroups, normalizedStrings(record.sourceGroups))) {
    errors.push('evidence source groups must be sorted canonically');
  }

  if (record.artifact.uri.trim().length === 0) errors.push('artifact uri cannot be empty');
  if (!SHA256_PATTERN.test(record.artifact.digest)) {
    errors.push('artifact digest must be sha256 followed by 64 lowercase hex characters');
  }
  if (!Number.isInteger(record.artifact.sizeBytes) || record.artifact.sizeBytes < 0) {
    errors.push('artifact sizeBytes must be a non-negative integer');
  }
  if (record.artifact.mediaType.trim().length === 0) errors.push('artifact mediaType cannot be empty');

  for (const existing of existingRecords.values()) {
    if (existing.artifact.digest === record.artifact.digest) {
      errors.push(
        `artifact digest is already captured as ${existing.id}; reuse that evidence instead of duplicating its source identity`,
      );
      break;
    }
  }

  if (record.preview !== undefined) {
    if (record.preview.length > MAX_PREVIEW_LENGTH) {
      errors.push(`evidence preview cannot exceed ${MAX_PREVIEW_LENGTH} characters`);
    }
    if (record.sensitivity === 'sensitive' || record.sensitivity === 'secret') {
      errors.push('sensitive or secret evidence cannot place raw preview text in the canonical ledger');
    }
  }

  if (
    (record.sensitivity === 'sensitive' || record.sensitivity === 'secret') &&
    record.artifact.encryption !== 'provider-managed'
  ) {
    errors.push('sensitive or secret evidence requires provider-managed encryption');
  }

  if (record.sensitivity === 'secret' && !record.taints.includes('secret-detected')) {
    warnings.push('secret evidence should normally carry the secret-detected taint');
  }
  if (record.authority === 'model-inference' && !record.taints.includes('model-generated')) {
    warnings.push('model-inference evidence should normally carry the model-generated taint');
  }

  if (new Set(record.taints).size !== record.taints.length) {
    errors.push('evidence taints must not contain duplicates');
  }
  if (record.labels.some((label) => label.trim().length === 0)) {
    errors.push('evidence labels cannot contain empty values');
  }
  if (new Set(record.labels).size !== record.labels.length) {
    errors.push('evidence labels must not contain duplicates');
  }
  if (record.derivedFrom.some((sourceId) => sourceId.trim().length === 0)) {
    errors.push('evidence derivedFrom cannot contain empty values');
  }
  if (new Set(record.derivedFrom).size !== record.derivedFrom.length) {
    errors.push('evidence derivedFrom must not contain duplicates');
  }
  if (record.derivedFrom.includes(record.id)) {
    errors.push('evidence cannot derive from itself');
  }

  const parents: EvidenceRecord[] = [];
  for (const sourceId of record.derivedFrom) {
    const parent = existingRecords.get(sourceId);
    if (parent === undefined) {
      errors.push(`derived evidence source must already exist: ${sourceId}`);
      continue;
    }
    parents.push(parent);
    if (parent.scope !== 'global' && parent.scope !== record.scope) {
      errors.push(
        `derived evidence scope ${parent.scope} cannot be promoted implicitly into ${record.scope}`,
      );
    }
  }

  if (parents.length === 0) {
    if (record.sourceGroups.length !== 1) {
      errors.push('raw evidence must have exactly one independent source group');
    }
  } else {
    const inheritedGroups = normalizedStrings(parents.flatMap((parent) => parent.sourceGroups));
    if (!sameStrings(record.sourceGroups, inheritedGroups)) {
      errors.push('derived evidence source groups must equal the union inherited from its parents');
    }

    const inheritedTaints = new Set(parents.flatMap((parent) => parent.taints));
    for (const taint of inheritedTaints) {
      if (!record.taints.includes(taint)) {
        errors.push(`derived evidence cannot drop inherited taint: ${taint}`);
      }
    }

    const strongestParentAuthority = Math.max(
      ...parents.map((parent) => AUTHORITY_RANK[parent.authority]),
    );
    if (AUTHORITY_RANK[record.authority] > strongestParentAuthority) {
      errors.push('derived evidence authority cannot exceed its strongest parent authority');
    }

    const strongestParentSensitivity = Math.max(
      ...parents.map((parent) => SENSITIVITY_RANK[parent.sensitivity]),
    );
    if (SENSITIVITY_RANK[record.sensitivity] < strongestParentSensitivity) {
      errors.push('derived evidence cannot reduce inherited sensitivity without an explicit declassification event');
    }
  }

  return freezeReport(errors, warnings);
}

export function evidenceRefFor(record: EvidenceRecord): EvidenceRef {
  return Object.freeze({
    sourceId: record.id,
    sourceGroups: Object.freeze([...record.sourceGroups]),
    authority: record.authority,
    contentHash: record.artifact.digest,
  });
}

/**
 * Replayable evidence metadata projection.
 *
 * Raw bytes remain in a content-addressed artifact provider. The canonical ledger stores the
 * immutable identity, digest, provenance, taint, sensitivity, and availability history needed to
 * audit memory writes without making private-byte deletion impossible.
 */
export class EvidenceProjection {
  readonly #evidence = new Map<string, ProjectedEvidence>();

  static from(events: readonly MemoryEvent[], knownAt = Number.POSITIVE_INFINITY): EvidenceProjection {
    if (Number.isNaN(knownAt)) throw new TypeError('knownAt cannot be NaN');
    const projection = new EvidenceProjection();
    for (const event of events) {
      if (event.recordedAt <= knownAt) projection.#apply(event);
    }
    return projection;
  }

  #apply(event: MemoryEvent): void {
    switch (event.type) {
      case 'evidence.captured': {
        const record = event.data.evidence;
        const validation = validateEvidenceForCapture(record, this.records(), event.recordedAt);
        if (!validation.ok) {
          throw new Error(`invalid evidence ${record.id}: ${validation.errors.join('; ')}`);
        }
        this.#evidence.set(
          record.id,
          Object.freeze({
            record,
            availability: 'available',
            capturedSeq: event.seq,
          }),
        );
        return;
      }
      case 'evidence.availability-changed': {
        const current = this.#evidence.get(event.data.evidenceId);
        if (current === undefined) {
          throw new Error(`unknown evidence in availability event: ${event.data.evidenceId}`);
        }
        if (current.availability === 'deleted') {
          throw new Error(`deleted evidence cannot transition again: ${event.data.evidenceId}`);
        }
        if (current.availability === event.data.availability) {
          throw new Error(`evidence is already ${event.data.availability}: ${event.data.evidenceId}`);
        }
        if (event.data.reason.trim().length === 0) {
          throw new Error('evidence availability changes require a reason');
        }
        this.#evidence.set(
          current.record.id,
          Object.freeze({
            record: current.record,
            availability: event.data.availability,
            capturedSeq: current.capturedSeq,
            latestAvailabilitySeq: event.seq,
          }),
        );
        return;
      }
      case 'claim.asserted':
      case 'claim.admitted':
      case 'claim.superseded':
      case 'claim.revoked':
      case 'association.added':
      case 'outcome.recorded':
        return;
    }
  }

  get(id: string): ProjectedEvidence | undefined {
    return this.#evidence.get(id);
  }

  records(): ReadonlyMap<string, EvidenceRecord> {
    return new Map([...this.#evidence].map(([id, projected]) => [id, projected.record] as const));
  }

  ids(): ReadonlySet<string> {
    return new Set(this.#evidence.keys());
  }

  isAvailable(id: string): boolean {
    return this.#evidence.get(id)?.availability === 'available';
  }

  validatesReference(reference: EvidenceRef): boolean {
    const projected = this.#evidence.get(reference.sourceId);
    if (projected === undefined || projected.availability !== 'available') return false;
    const record = projected.record;
    return (
      sameStrings(reference.sourceGroups, record.sourceGroups) &&
      reference.authority === record.authority &&
      reference.contentHash === record.artifact.digest
    );
  }

  all(): readonly ProjectedEvidence[] {
    return Object.freeze([...this.#evidence.values()]);
  }
}
