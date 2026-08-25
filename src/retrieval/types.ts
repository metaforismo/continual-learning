import type { ClaimLifecycle, ClaimRecord, EvidenceRecord, MemoryEvent } from '../domain.js';

export const FTS5_PROJECTION_SCHEMA_VERSION = 1 as const;

export type Fts5ProjectionDocumentKind = 'evidence' | 'claim';
export type Fts5ProjectionView = 'current' | 'historical';

export interface Fts5ProjectionWatermark {
  readonly schemaVersion: typeof FTS5_PROJECTION_SCHEMA_VERSION;
  readonly generation: number;
  readonly eventCount: number;
  readonly lastSeq: number;
  readonly canonicalFingerprint: string;
  readonly entryCount: number;
  readonly rebuiltAt: number;
}

export interface Fts5ProjectionStatus {
  readonly initialized: boolean;
  readonly fresh: boolean;
  readonly watermark?: Fts5ProjectionWatermark;
  readonly canonicalFingerprint: string;
  readonly eventCount: number;
  readonly reason: string;
}

export interface Fts5SearchOptions {
  /** Explicit authorized scopes. `global` is never added implicitly. */
  readonly scopeChain: readonly string[];
  readonly view?: Fts5ProjectionView;
  readonly limit?: number;
  readonly maxQueryTokens?: number;
}

/**
 * A cache hit is intentionally only an address. Search text and canonical values never leave the
 * index boundary. Call `rehydrate` before a candidate may influence model context or action.
 */
export interface Fts5SearchCandidate {
  readonly canonicalId: string;
  readonly kind: Fts5ProjectionDocumentKind;
  readonly scope: string;
  readonly lifecycle?: Extract<ClaimLifecycle, 'active' | 'superseded'>;
  readonly rank: number;
  readonly score: number;
  readonly entryDigest: string;
  readonly canonicalFingerprint: string;
  readonly generation: number;
}

export interface RehydratedEvidenceCandidate {
  readonly candidate: Fts5SearchCandidate & { readonly kind: 'evidence' };
  readonly record: EvidenceRecord;
}

export interface RehydratedClaimCandidate {
  readonly candidate: Fts5SearchCandidate & { readonly kind: 'claim' };
  readonly record: ClaimRecord;
  readonly lifecycle: Extract<ClaimLifecycle, 'active' | 'superseded'>;
}

export type RehydratedFts5Candidate =
  | RehydratedEvidenceCandidate
  | RehydratedClaimCandidate;

export interface Fts5RehydrateOptions {
  readonly scopeChain: readonly string[];
  readonly view?: Fts5ProjectionView;
}

export type Fts5RebuildPhase =
  | 'after-begin'
  | 'after-clear-next-generation'
  | 'after-insert'
  | 'after-watermark'
  | 'after-retire-old-generation'
  | 'before-commit';

export interface Fts5ProjectionOptions {
  /**
   * Only evidence at these sensitivity levels may contribute searchable text. Defaults to public
   * and internal. Personal/sensitive/secret text therefore never enters the plaintext FTS cache.
   */
  readonly searchableSensitivities?: readonly EvidenceRecord['sensitivity'][];
  readonly busyTimeoutMs?: number;
  /** Test-only deterministic failure injection for transaction rollback verification. */
  readonly faultInjector?: (phase: Fts5RebuildPhase) => void;
}

export interface Fts5ProjectionDatabase {
  exec(sql: string): void;
  prepare(sql: string): Fts5ProjectionStatement;
  close(): void;
}

export interface Fts5ProjectionStatement {
  run(...params: (string | number | bigint | null)[]): unknown;
  get(...params: (string | number | bigint | null)[]): unknown;
  all(...params: (string | number | bigint | null)[]): readonly unknown[];
}

export interface Fts5ProjectionSnapshot {
  readonly events: readonly MemoryEvent[];
  readonly fingerprint: string;
}
