import type { MemoryEvent } from '../domain.js';
import type { MemoryKernel } from '../kernel.js';
import type {
  TransitionAuditRecord,
  TransitionVerificationResult,
} from '../transitions/types.js';

export const DURABLE_LEDGER_SCHEMA_VERSION = 1 as const;

export type DurableCommitPhase =
  | 'after-begin'
  | 'after-event-inserts'
  | 'after-receipt-insert'
  | 'after-metadata-update'
  | 'before-commit';

export interface SqliteCanonicalLedgerOptions {
  readonly busyTimeoutMs?: number;
  readonly faultInjector?: (phase: DurableCommitPhase) => void;
}

export interface DurableLedgerRevision {
  readonly schemaVersion: typeof DURABLE_LEDGER_SCHEMA_VERSION;
  readonly revision: number;
  readonly eventCount: number;
  readonly lastSeq: number;
  readonly lastRecordedAt?: number;
  readonly canonicalFingerprint: string;
  readonly eventChainDigest: string;
  readonly receiptCount: number;
  readonly lastReceiptDigest: string;
}

export interface DurableReceiptEnvelope {
  readonly id: string;
  readonly recordedAt: number;
  readonly actor: string;
}

export interface DurableTransitionReceipt {
  readonly audit: TransitionAuditRecord;
  readonly previousReceiptDigest: string;
  readonly auditRecordDigest: string;
  readonly receiptDigest: string;
}

export interface DurableCommitResult {
  readonly idempotent: boolean;
  readonly revision: DurableLedgerRevision;
  readonly receipt: DurableTransitionReceipt;
  readonly appendedEvents: readonly MemoryEvent[];
}

export interface DurableIntegrityReport {
  readonly ok: boolean;
  readonly revision?: DurableLedgerRevision;
  readonly errors: readonly string[];
}

/**
 * Trusted-host capability used to consume a process-local accepted transition result.
 *
 * The durable store verifies that the returned kernel preserves the exact canonical prefix and
 * equals the result's staged append and fingerprints. It does not turn an arbitrary caller into a
 * trusted transition verifier; the host remains responsible for supplying the real capability.
 */
export type VerifiedTransitionCommitter = (
  current: MemoryKernel,
  result: TransitionVerificationResult,
) => MemoryKernel;
