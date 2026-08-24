import {
  AUTHORITY_RANK,
  claimKeyToString,
  intervalContains,
  type ClaimKey,
  type ClaimLifecycle,
  type ClaimRecord,
  type JsonValue,
  type MemoryEvent,
} from './domain.js';

interface ProjectedClaim {
  readonly claim: ClaimRecord;
  lifecycle: ClaimLifecycle;
  readonly assertedSeq: number;
  admittedSeq?: number;
  supersededAt?: number;
  supersededBy?: string;
  revokedSeq?: number;
}

export interface ClaimResolution {
  readonly status: 'resolved' | 'ambiguous' | 'unknown';
  readonly claim?: ClaimRecord;
  readonly candidates: readonly ClaimRecord[];
  readonly reason: string;
}

export interface ResolveClaimOptions {
  /** World time being asked about. */
  readonly validAt: number;
  /** Minimum authority rank accepted as actionable state. Defaults to model inference. */
  readonly minimumAuthority?: keyof typeof AUTHORITY_RANK;
  /** Resolve a strictly stronger authority automatically; ties remain ambiguous. */
  readonly allowAuthorityDominance?: boolean;
}

function canonicalJson(value: JsonValue): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${(value as readonly JsonValue[]).map(canonicalJson).join(',')}]`;
  }
  const objectValue = value as { readonly [key: string]: JsonValue };
  return `{${Object.keys(objectValue)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(objectValue[key] as JsonValue)}`)
    .join(',')}}`;
}

function effectiveIntervalContains(projected: ProjectedClaim, instant: number): boolean {
  const explicitTo = projected.claim.valid.to;
  const effectiveTo =
    explicitTo === undefined
      ? projected.supersededAt
      : projected.supersededAt === undefined
        ? explicitTo
        : Math.min(explicitTo, projected.supersededAt);

  return intervalContains(
    effectiveTo === undefined
      ? projected.claim.valid
      : { from: projected.claim.valid.from, to: effectiveTo },
    instant,
  );
}

/**
 * Deterministic bitemporal projection over claim events.
 *
 * Transaction time is selected while constructing the projection (`knownAt`). World time is
 * selected per query (`validAt`). This prevents "latest text wins" from silently replacing
 * historical truth.
 */
export class ClaimProjection {
  readonly #claims = new Map<string, ProjectedClaim>();

  static from(events: readonly MemoryEvent[], knownAt = Number.POSITIVE_INFINITY): ClaimProjection {
    if (Number.isNaN(knownAt)) throw new TypeError('knownAt cannot be NaN');
    const projection = new ClaimProjection();
    for (const event of events) {
      if (event.recordedAt <= knownAt) projection.#apply(event);
    }
    return projection;
  }

  #apply(event: MemoryEvent): void {
    switch (event.type) {
      case 'claim.asserted': {
        const { claim, initialLifecycle } = event.data;
        if (this.#claims.has(claim.id)) throw new Error(`duplicate claim id in replay: ${claim.id}`);
        this.#claims.set(claim.id, {
          claim,
          lifecycle: initialLifecycle,
          assertedSeq: event.seq,
        });
        return;
      }
      case 'claim.admitted': {
        const projected = this.#require(event.data.claimId);
        if (projected.lifecycle !== 'quarantined') {
          throw new Error(`claim ${projected.claim.id} is not quarantined`);
        }
        projected.lifecycle = 'active';
        projected.admittedSeq = event.seq;
        return;
      }
      case 'claim.superseded': {
        const previous = this.#require(event.data.previousClaimId);
        const replacement = this.#require(event.data.replacementClaimId);
        if (replacement.lifecycle !== 'active') {
          throw new Error('a replacement must be active before supersession commits');
        }
        if (previous.lifecycle !== 'active') {
          throw new Error('only an active claim may be superseded');
        }
        previous.lifecycle = 'superseded';
        previous.supersededAt = event.data.effectiveAt;
        previous.supersededBy = replacement.claim.id;
        return;
      }
      case 'claim.revoked': {
        const projected = this.#require(event.data.claimId);
        projected.lifecycle = 'revoked';
        projected.revokedSeq = event.seq;
        return;
      }
      case 'evidence.captured':
      case 'evidence.availability-changed':
      case 'association.added':
      case 'outcome.recorded':
        return;
    }
  }

  #require(claimId: string): ProjectedClaim {
    const projected = this.#claims.get(claimId);
    if (projected === undefined) throw new Error(`unknown claim: ${claimId}`);
    return projected;
  }

  get(claimId: string): ClaimRecord | undefined {
    return this.#claims.get(claimId)?.claim;
  }

  lifecycle(claimId: string): ClaimLifecycle | undefined {
    return this.#claims.get(claimId)?.lifecycle;
  }

  candidates(
    key: ClaimKey,
    options: Pick<ResolveClaimOptions, 'validAt' | 'minimumAuthority'>,
    authorizeClaim: (claim: ClaimRecord) => boolean = () => true,
  ): readonly ClaimRecord[] {
    if (!Number.isFinite(options.validAt)) throw new TypeError('validAt must be finite');
    const minimumRank = AUTHORITY_RANK[options.minimumAuthority ?? 'model-inference'];
    const keyString = claimKeyToString(key);
    return Object.freeze(
      [...this.#claims.values()]
        .filter((projected) => {
          if (claimKeyToString(projected.claim.key) !== keyString) return false;
          if (projected.lifecycle === 'quarantined' || projected.lifecycle === 'revoked') return false;
          if (AUTHORITY_RANK[projected.claim.authority] < minimumRank) return false;
          if (!authorizeClaim(projected.claim)) return false;
          return effectiveIntervalContains(projected, options.validAt);
        })
        .sort(
          (left, right) =>
            right.claim.valid.from - left.claim.valid.from ||
            right.assertedSeq - left.assertedSeq ||
            left.claim.id.localeCompare(right.claim.id),
        )
        .map((projected) => projected.claim),
    );
  }

  history(
    key: ClaimKey,
    authorizeClaim: (claim: ClaimRecord) => boolean = () => true,
  ): readonly ClaimRecord[] {
    const keyString = claimKeyToString(key);
    return Object.freeze(
      [...this.#claims.values()]
        .filter((projected) => {
          if (claimKeyToString(projected.claim.key) !== keyString) return false;
          if (projected.lifecycle === 'quarantined' || projected.lifecycle === 'revoked') return false;
          return authorizeClaim(projected.claim);
        })
        .sort(
          (left, right) =>
            left.claim.valid.from - right.claim.valid.from ||
            left.assertedSeq - right.assertedSeq ||
            left.claim.id.localeCompare(right.claim.id),
        )
        .map((projected) => projected.claim),
    );
  }

  resolve(
    key: ClaimKey,
    options: ResolveClaimOptions,
    authorizeClaim: (claim: ClaimRecord) => boolean = () => true,
  ): ClaimResolution {
    if (!Number.isFinite(options.validAt)) throw new TypeError('validAt must be finite');

    const minimumAuthority = options.minimumAuthority ?? 'model-inference';
    const minimumRank = AUTHORITY_RANK[minimumAuthority];
    const keyString = claimKeyToString(key);

    const projectedCandidates = [...this.#claims.values()].filter((projected) => {
      if (claimKeyToString(projected.claim.key) !== keyString) return false;
      if (projected.lifecycle === 'quarantined' || projected.lifecycle === 'revoked') return false;
      if (AUTHORITY_RANK[projected.claim.authority] < minimumRank) return false;
      if (!authorizeClaim(projected.claim)) return false;
      return effectiveIntervalContains(projected, options.validAt);
    });

    if (projectedCandidates.length === 0) {
      return Object.freeze({
        status: 'unknown',
        candidates: Object.freeze([]),
        reason: 'no authorized claim covers the requested world time',
      });
    }

    const groups = new Map<string, ProjectedClaim[]>();
    for (const candidate of projectedCandidates) {
      const valueKey = canonicalJson(candidate.claim.value);
      const group = groups.get(valueKey) ?? [];
      group.push(candidate);
      groups.set(valueKey, group);
    }

    const sorted = projectedCandidates.sort((left, right) => {
      const authorityDelta = AUTHORITY_RANK[right.claim.authority] - AUTHORITY_RANK[left.claim.authority];
      if (authorityDelta !== 0) return authorityDelta;
      const verifiedDelta =
        Number(right.claim.epistemicStatus === 'verified') -
        Number(left.claim.epistemicStatus === 'verified');
      if (verifiedDelta !== 0) return verifiedDelta;
      const confidenceDelta = right.claim.confidence - left.claim.confidence;
      if (confidenceDelta !== 0) return confidenceDelta;
      return right.assertedSeq - left.assertedSeq;
    });

    const candidates = Object.freeze(sorted.map((candidate) => candidate.claim));

    if (groups.size === 1) {
      const winner = sorted[0];
      if (winner === undefined) throw new Error('resolution invariant violated');
      return Object.freeze({
        status: 'resolved',
        claim: winner.claim,
        candidates,
        reason: 'all authorized evidence agrees on one value',
      });
    }

    const [first, second] = sorted;
    if (
      options.allowAuthorityDominance === true &&
      first !== undefined &&
      second !== undefined &&
      first.claim.epistemicStatus !== 'disputed' &&
      AUTHORITY_RANK[first.claim.authority] > AUTHORITY_RANK[second.claim.authority]
    ) {
      return Object.freeze({
        status: 'resolved',
        claim: first.claim,
        candidates,
        reason: 'a uniquely stronger authority dominates conflicting candidates',
      });
    }

    return Object.freeze({
      status: 'ambiguous',
      candidates,
      reason: 'conflicting authorized claims require adjudication; recency alone is insufficient',
    });
  }
}
