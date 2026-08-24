import {
  TRANSITION_AUDIT_SCHEMA_VERSION,
  type TransitionAuditRecord,
  type TransitionRisk,
  type TransitionVerificationResult,
  type TransitionVerdict,
} from './types.js';
import {
  snapshotTransitionVerificationResult,
  verifyTransitionResultIntegrity,
} from './verifier.js';

const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const RISKS: ReadonlySet<string> = new Set<TransitionRisk>([
  'low',
  'medium',
  'high',
  'destructive',
]);
const VERDICTS: ReadonlySet<string> = new Set<TransitionVerdict>([
  'accept',
  'quarantine',
  'human-review',
  'reject',
]);

export interface TransitionAuditEnvelope {
  readonly id: string;
  readonly recordedAt: number;
  readonly actor: string;
}

function snapshotRecord(record: TransitionAuditRecord): TransitionAuditRecord {
  const {
    schemaVersion,
    id,
    seq,
    recordedAt,
    actor,
    proposalId,
    proposalDigest,
    resultDigest,
    verdict,
    actualRisk,
    baseFingerprint,
    afterFingerprint,
    appendFingerprint,
    policyId,
    policyVersion,
    policyDigest,
    verifierId,
    verifierConfigDigest,
    findingCodes,
  } = record;
  return Object.freeze({
    schemaVersion,
    id,
    seq,
    recordedAt,
    actor,
    proposalId,
    proposalDigest,
    resultDigest,
    verdict,
    actualRisk,
    baseFingerprint,
    ...(afterFingerprint === undefined ? {} : { afterFingerprint }),
    ...(appendFingerprint === undefined ? {} : { appendFingerprint }),
    policyId,
    policyVersion,
    policyDigest,
    verifierId,
    verifierConfigDigest,
    findingCodes: Object.freeze([...findingCodes]),
  });
}

function validateRecord(
  record: TransitionAuditRecord,
  expectedSeq: number,
  previousRecordedAt: number | undefined,
  ids: ReadonlySet<string>,
): void {
  if (record.schemaVersion !== TRANSITION_AUDIT_SCHEMA_VERSION) {
    throw new Error(
      `unsupported transition audit schema version: ${String(record.schemaVersion)}`,
    );
  }
  if (!Number.isInteger(record.seq) || record.seq !== expectedSeq) {
    throw new Error(
      `transition audit seq must be contiguous: expected ${expectedSeq}, received ${String(record.seq)}`,
    );
  }
  if (record.id.trim().length === 0 || ids.has(record.id)) {
    throw new Error(`transition audit id must be non-empty and unique: ${record.id}`);
  }
  if (!Number.isFinite(record.recordedAt)) {
    throw new TypeError('transition audit recordedAt must be finite');
  }
  if (previousRecordedAt !== undefined && record.recordedAt < previousRecordedAt) {
    throw new Error('transition audit recordedAt must be monotonic');
  }
  if (record.actor.trim().length === 0) throw new Error('transition audit actor cannot be empty');
  if (record.proposalId.trim().length === 0) {
    throw new Error('transition audit proposalId cannot be empty');
  }
  if (!SHA256_PATTERN.test(record.proposalDigest) || !SHA256_PATTERN.test(record.resultDigest)) {
    throw new Error('transition audit proposal and result digests must be SHA-256 content addresses');
  }
  if (!SHA256_PATTERN.test(record.baseFingerprint)) {
    throw new Error('transition audit baseFingerprint must be a SHA-256 content address');
  }
  if (record.afterFingerprint !== undefined && !SHA256_PATTERN.test(record.afterFingerprint)) {
    throw new Error('transition audit afterFingerprint must be a SHA-256 content address');
  }
  if (record.appendFingerprint !== undefined && !SHA256_PATTERN.test(record.appendFingerprint)) {
    throw new Error('transition audit appendFingerprint must be a SHA-256 content address');
  }
  if (!VERDICTS.has(record.verdict) || !RISKS.has(record.actualRisk)) {
    throw new Error('transition audit verdict or risk is invalid');
  }
  if (
    record.verdict === 'accept' &&
    (record.afterFingerprint === undefined || record.appendFingerprint === undefined)
  ) {
    throw new Error('accepted transition audit records require after and append fingerprints');
  }
  if (
    record.policyId.trim().length === 0 ||
    record.policyVersion.trim().length === 0 ||
    record.verifierId.trim().length === 0
  ) {
    throw new Error('transition audit policy and verifier identity are required');
  }
  if (
    !SHA256_PATTERN.test(record.policyDigest) ||
    !SHA256_PATTERN.test(record.verifierConfigDigest)
  ) {
    throw new Error('transition audit policy and verifier configuration require SHA-256 digests');
  }
  if (
    record.findingCodes.some((code) => code.trim().length === 0) ||
    new Set(record.findingCodes).size !== record.findingCodes.length
  ) {
    throw new Error('transition audit finding codes must be non-empty and unique');
  }
}

/**
 * Append-only audit journal for transition verdicts.
 *
 * This journal deliberately remains separate from the canonical memory ledger in v1. A durable
 * provider must persist the verdict and accepted memory events atomically, or retain a recovery
 * protocol that can prove which side committed. The digest is an integrity address, not a signature.
 */
export class TransitionAuditJournal {
  readonly #records: TransitionAuditRecord[] = [];
  readonly #ids = new Set<string>();

  static from(records: readonly TransitionAuditRecord[]): TransitionAuditJournal {
    const journal = new TransitionAuditJournal();
    for (const input of records) {
      const record = snapshotRecord(input);
      journal.#accept(record);
    }
    return journal;
  }

  append(
    envelope: TransitionAuditEnvelope,
    result: TransitionVerificationResult,
  ): TransitionAuditRecord {
    const resultSnapshot = snapshotTransitionVerificationResult(result);
    if (!verifyTransitionResultIntegrity(resultSnapshot)) {
      throw new Error('cannot audit a transition result that fails integrity checks');
    }
    const record = snapshotRecord({
      schemaVersion: TRANSITION_AUDIT_SCHEMA_VERSION,
      id: envelope.id,
      seq: this.#records.length + 1,
      recordedAt: envelope.recordedAt,
      actor: envelope.actor,
      proposalId: resultSnapshot.proposalId,
      proposalDigest: resultSnapshot.proposalDigest,
      resultDigest: resultSnapshot.resultDigest,
      verdict: resultSnapshot.verdict,
      actualRisk: resultSnapshot.actualRisk,
      baseFingerprint: resultSnapshot.baseFingerprint,
      ...(resultSnapshot.afterFingerprint === undefined
        ? {}
        : { afterFingerprint: resultSnapshot.afterFingerprint }),
      ...(resultSnapshot.appendFingerprint === undefined
        ? {}
        : { appendFingerprint: resultSnapshot.appendFingerprint }),
      policyId: resultSnapshot.policyId,
      policyVersion: resultSnapshot.policyVersion,
      policyDigest: resultSnapshot.policyDigest,
      verifierId: resultSnapshot.verifier.id,
      verifierConfigDigest: resultSnapshot.verifier.configDigest,
      findingCodes: Object.freeze(
        [...new Set(resultSnapshot.findings.map((item) => item.code))].sort(),
      ),
    });
    this.#accept(record);
    return record;
  }

  #accept(record: TransitionAuditRecord): void {
    validateRecord(
      record,
      this.#records.length + 1,
      this.#records.at(-1)?.recordedAt,
      this.#ids,
    );
    this.#records.push(record);
    this.#ids.add(record.id);
  }

  all(): readonly TransitionAuditRecord[] {
    return Object.freeze([...this.#records]);
  }

  get size(): number {
    return this.#records.length;
  }
}
