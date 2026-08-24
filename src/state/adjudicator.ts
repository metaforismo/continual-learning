import { ClaimProjection } from '../claims.js';
import {
  evidenceRoles,
  type Authority,
  type ClaimRecord,
  type EvidenceRef,
  type JsonValue,
  type MemoryEvent,
} from '../domain.js';
import { EvidenceProjection } from '../evidence.js';
import {
  DEFAULT_MAX_INVALIDATED_SLOTS,
  DEFAULT_MAX_INVALIDATION_HOPS,
  validateStateSchema,
} from './schema.js';
import type {
  PremiseAssessment,
  StateAdjudicationSchema,
  StateCandidateEvaluation,
  StateDecision,
  StateEvidenceRolePolicy,
  StateExplanation,
  StateInvalidation,
  StateRequest,
  StateRoleRank,
  StateSlotDefinition,
  StateStatus,
  StateValueGroupEvaluation,
} from './types.js';

interface InternalStateDecision {
  readonly slot: StateSlotDefinition;
  readonly status: StateStatus;
  readonly claim?: ClaimRecord;
  readonly value?: JsonValue;
  readonly candidates: readonly ClaimRecord[];
  readonly invalidations: readonly StateInvalidation[];
  readonly explanation: StateExplanation;
  readonly budgetBlocked: boolean;
}

interface StateFrontier {
  readonly effectiveAt: number;
  readonly uncertain: boolean;
  readonly claimIds: readonly string[];
  readonly evidenceSourceIds: readonly string[];
  readonly path: readonly string[];
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

function uniqueSorted(values: readonly string[]): readonly string[] {
  return Object.freeze([...new Set(values)].sort());
}

function authorityRank(policy: StateEvidenceRolePolicy, authority: Authority): number {
  const index = policy.authorityPrecedence.indexOf(authority);
  return index < 0 ? -1 : policy.authorityPrecedence.length - index;
}

function rankEvidence(
  references: readonly EvidenceRef[],
  policy: StateEvidenceRolePolicy,
): StateRoleRank {
  let bestRank = -1;
  const authorities: Authority[] = [];
  const sourceIds: string[] = [];

  for (const reference of references) {
    if (!evidenceRoles(reference).includes(policy.role)) continue;
    const rank = authorityRank(policy, reference.authority);
    if (rank < 0) continue;
    if (rank > bestRank) {
      bestRank = rank;
      authorities.length = 0;
      sourceIds.length = 0;
    }
    if (rank === bestRank) {
      authorities.push(reference.authority);
      sourceIds.push(reference.sourceId);
    }
  }

  return Object.freeze({
    role: policy.role,
    rank: bestRank,
    authorities: Object.freeze([...new Set(authorities)]),
    sourceIds: uniqueSorted(sourceIds),
  });
}

function compareRoleRanks(
  left: readonly StateRoleRank[],
  right: readonly StateRoleRank[],
): number {
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const delta = (left[index]?.rank ?? -1) - (right[index]?.rank ?? -1);
    if (delta !== 0) return delta;
  }
  return 0;
}

function evidenceIds(claims: readonly ClaimRecord[]): readonly string[] {
  return uniqueSorted(claims.flatMap((claim) => claim.evidence.map((reference) => reference.sourceId)));
}

function evaluateCandidate(
  claim: ClaimRecord,
  slot: StateSlotDefinition,
  evidenceProjection: EvidenceProjection,
): StateCandidateEvaluation {
  const reasons: string[] = [];
  const validReferences: EvidenceRef[] = [];

  for (const reference of claim.evidence) {
    if (evidenceProjection.validatesReference(reference)) {
      validReferences.push(reference);
    } else {
      reasons.push(`evidence ${reference.sourceId} is unavailable or does not match canonical metadata`);
    }
  }

  if (claim.epistemicStatus === 'unknown') reasons.push('claim epistemic status is unknown');
  if (claim.epistemicStatus === 'disputed') reasons.push('claim is already marked disputed');
  if (claim.epistemicStatus === 'inferred' && slot.allowInferred !== true) {
    reasons.push('inferred claims are not authorized for this state slot');
  }
  if (claim.confidence < (slot.minimumConfidence ?? 0)) {
    reasons.push(
      `claim confidence ${claim.confidence} is below ${slot.minimumConfidence ?? 0}`,
    );
  }
  if (
    validReferences.some((reference) => evidenceRoles(reference).includes('contradicts'))
  ) {
    reasons.push('claim carries currently available contradicting evidence');
  }

  const roleRanks = Object.freeze(
    slot.evidencePolicy.map((policy) => rankEvidence(validReferences, policy)),
  );
  if (roleRanks.every((rank) => rank.rank < 0)) {
    reasons.push('no available evidence matches the slot evidence policy');
  }

  return Object.freeze({
    claim,
    eligible: reasons.length === 0,
    reasons: Object.freeze(reasons),
    roleRanks,
  });
}

function buildValueGroups(
  evaluations: readonly StateCandidateEvaluation[],
  slot: StateSlotDefinition,
  evidenceProjection: EvidenceProjection,
): readonly StateValueGroupEvaluation[] {
  const grouped = new Map<string, StateCandidateEvaluation[]>();
  for (const evaluation of evaluations) {
    const valueKey = canonicalJson(evaluation.claim.value);
    const bucket = grouped.get(valueKey) ?? [];
    bucket.push(evaluation);
    grouped.set(valueKey, bucket);
  }

  const groups: StateValueGroupEvaluation[] = [];
  for (const [valueKey, group] of grouped) {
    const claims = group.map((evaluation) => evaluation.claim);
    const eligibleClaims = group
      .filter((evaluation) => evaluation.eligible)
      .map((evaluation) => evaluation.claim);
    const eligibleReferences = eligibleClaims.flatMap((claim) =>
      claim.evidence.filter((reference) => evidenceProjection.validatesReference(reference)),
    );
    const roleRanks = Object.freeze(
      slot.evidencePolicy.map((policy) => rankEvidence(eligibleReferences, policy)),
    );
    const reasons: string[] = [];
    if (eligibleClaims.length === 0) reasons.push('no eligible claim supports this value');
    for (let index = 0; index < slot.evidencePolicy.length; index += 1) {
      const policy = slot.evidencePolicy[index];
      const rank = roleRanks[index];
      if (policy?.required === true && (rank?.rank ?? -1) < 0) {
        reasons.push(`required evidence role ${policy.role} is missing`);
      }
    }

    const firstClaim = claims[0];
    if (firstClaim === undefined) throw new Error('state grouping invariant violated');
    groups.push(
      Object.freeze({
        value: firstClaim.value,
        valueKey,
        claimIds: uniqueSorted(claims.map((claim) => claim.id)),
        eligibleClaimIds: uniqueSorted(eligibleClaims.map((claim) => claim.id)),
        eligible: reasons.length === 0,
        reasons: Object.freeze(reasons),
        roleRanks,
        newestValidFrom: Math.max(...claims.map((claim) => claim.valid.from)),
        highestConfidence: Math.max(...claims.map((claim) => claim.confidence)),
      }),
    );
  }

  return Object.freeze(
    groups.sort(
      (left, right) =>
        right.newestValidFrom - left.newestValidFrom ||
        left.valueKey.localeCompare(right.valueKey),
    ),
  );
}

function chooseGroup(
  groups: readonly StateValueGroupEvaluation[],
  slot: StateSlotDefinition,
): { readonly selected?: StateValueGroupEvaluation; readonly reason: string } {
  const eligible = groups.filter((group) => group.eligible);
  if (eligible.length === 0) return { reason: 'no value group satisfies the state policy' };
  if (eligible.length === 1) {
    return { selected: eligible[0], reason: 'one value group satisfies the state policy' };
  }

  if (slot.strategy === 'require-agreement') {
    return { reason: 'multiple eligible values violate the require-agreement strategy' };
  }

  let best: StateValueGroupEvaluation | undefined;
  let tied = false;
  for (const group of eligible) {
    if (best === undefined) {
      best = group;
      tied = false;
      continue;
    }

    let comparison = 0;
    if (slot.strategy === 'latest-valid') {
      comparison = group.newestValidFrom - best.newestValidFrom;
    } else {
      comparison = compareRoleRanks(group.roleRanks, best.roleRanks);
      if (comparison === 0 && slot.strategy === 'role-authority-then-latest') {
        comparison = group.newestValidFrom - best.newestValidFrom;
      }
    }

    if (comparison > 0) {
      best = group;
      tied = false;
    } else if (comparison === 0) {
      tied = true;
    }
  }

  if (best === undefined || tied) {
    return { reason: 'multiple eligible values remain tied under the slot strategy' };
  }
  return { selected: best, reason: `slot strategy ${slot.strategy} selected one value` };
}

function chooseRepresentativeClaim(
  selected: StateValueGroupEvaluation,
  evaluations: readonly StateCandidateEvaluation[],
): ClaimRecord {
  const matching = evaluations.filter(
    (evaluation) =>
      evaluation.eligible && canonicalJson(evaluation.claim.value) === selected.valueKey,
  );
  matching.sort((left, right) => {
    const authorityDelta = compareRoleRanks(right.roleRanks, left.roleRanks);
    if (authorityDelta !== 0) return authorityDelta;
    const dateDelta = right.claim.valid.from - left.claim.valid.from;
    if (dateDelta !== 0) return dateDelta;
    const confidenceDelta = right.claim.confidence - left.claim.confidence;
    if (confidenceDelta !== 0) return confidenceDelta;
    return left.claim.id.localeCompare(right.claim.id);
  });
  const winner = matching[0]?.claim;
  if (winner === undefined) throw new Error('selected state has no representative claim');
  return winner;
}

function baseDecision(
  slot: StateSlotDefinition,
  request: StateRequest,
  claims: ClaimProjection,
  evidence: EvidenceProjection,
  schema: StateAdjudicationSchema,
): InternalStateDecision {
  const candidates = claims.candidates(slot.key, { validAt: request.validAt });
  const evaluations = Object.freeze(
    candidates.map((claim) => evaluateCandidate(claim, slot, evidence)),
  );
  const groups = buildValueGroups(evaluations, slot, evidence);
  const choice = chooseGroup(groups, slot);
  const reasons = [choice.reason];

  if (choice.selected === undefined) {
    const hasEligibleGroups = groups.some((group) => group.eligible);
    const status: StateStatus = hasEligibleGroups ? 'disputed' : 'unknown';
    return Object.freeze({
      slot,
      status,
      candidates,
      invalidations: Object.freeze([]),
      explanation: Object.freeze({
        schemaId: schema.id,
        schemaVersion: schema.version,
        slotId: slot.id,
        strategy: slot.strategy,
        reasons: Object.freeze(reasons),
        candidates: evaluations,
        valueGroups: groups,
      }),
      budgetBlocked: false,
    });
  }

  const claim = chooseRepresentativeClaim(choice.selected, evaluations);
  const status: StateStatus = request.view === 'current' ? 'current' : 'historical';
  return Object.freeze({
    slot,
    status,
    claim,
    value: choice.selected.value,
    candidates,
    invalidations: Object.freeze([]),
    explanation: Object.freeze({
      schemaId: schema.id,
      schemaVersion: schema.version,
      slotId: slot.id,
      strategy: slot.strategy,
      reasons: Object.freeze(reasons),
      candidates: evaluations,
      valueGroups: groups,
      selectedValueKey: choice.selected.valueKey,
    }),
    budgetBlocked: false,
  });
}

function frontiersForDecision(decision: InternalStateDecision): readonly StateFrontier[] {
  if (decision.claim !== undefined) {
    return Object.freeze([
      Object.freeze({
        effectiveAt: decision.claim.valid.from,
        uncertain: false,
        claimIds: Object.freeze([decision.claim.id]),
        evidenceSourceIds: evidenceIds([decision.claim]),
        path: Object.freeze([]),
      }),
    ]);
  }

  if (decision.status === 'unknown-current' && decision.invalidations.length > 0) {
    return Object.freeze(
      decision.invalidations.map((invalidation) =>
        Object.freeze({
          effectiveAt: invalidation.effectiveAt,
          uncertain: true,
          claimIds: invalidation.sourceClaimIds,
          evidenceSourceIds: invalidation.sourceEvidenceSourceIds,
          path: invalidation.path,
        }),
      ),
    );
  }

  if (decision.status === 'disputed' && decision.candidates.length > 0) {
    const effectiveAt = Math.max(...decision.candidates.map((claim) => claim.valid.from));
    const newest = decision.candidates.filter((claim) => claim.valid.from === effectiveAt);
    return Object.freeze([
      Object.freeze({
        effectiveAt,
        uncertain: true,
        claimIds: uniqueSorted(newest.map((claim) => claim.id)),
        evidenceSourceIds: evidenceIds(newest),
        path: Object.freeze([]),
      }),
    ]);
  }

  return Object.freeze([]);
}

function premiseAssessment(
  request: StateRequest,
  decision: InternalStateDecision,
): PremiseAssessment {
  if (request.premise === undefined) {
    return Object.freeze({
      status: 'unsupported',
      reason: 'the request supplied no premise to assess',
    });
  }

  if (decision.value !== undefined) {
    const accepted = canonicalJson(request.premise) === canonicalJson(decision.value);
    return accepted
      ? Object.freeze({
          status: 'accepted',
          reason: 'the premise matches the authorized state',
          requested: request.premise,
          authorized: decision.value,
        })
      : Object.freeze({
          status: 'rejected',
          reason: 'the premise conflicts with the authorized state',
          requested: request.premise,
          authorized: decision.value,
        });
  }

  if (decision.status === 'unknown-current') {
    return Object.freeze({
      status: 'rejected',
      reason: 'no concrete current value is authorized after upstream invalidation',
      requested: request.premise,
    });
  }

  return Object.freeze({
    status: 'unsupported',
    reason: 'the state is unresolved, so the premise cannot be accepted as a fact',
    requested: request.premise,
  });
}

/**
 * Resolve one state slot under a declared, deterministic policy.
 *
 * The function separates retrieval from authority, represents uncertainty explicitly, rejects stale
 * premises, and propagates bounded implicit invalidation through a validated DAG. It never asks a
 * language model to choose the final current value.
 */
export function adjudicateState(
  events: readonly MemoryEvent[],
  schema: StateAdjudicationSchema,
  request: StateRequest,
): StateDecision {
  validateStateSchema(schema);
  if (!Number.isFinite(request.validAt)) throw new TypeError('state request validAt must be finite');
  const knownAt = request.knownAt ?? Number.POSITIVE_INFINITY;
  if (Number.isNaN(knownAt)) throw new TypeError('state request knownAt cannot be NaN');

  const slotById = new Map(schema.slots.map((slot) => [slot.id, slot] as const));
  const requestedSlot = slotById.get(request.slotId);
  if (requestedSlot === undefined) throw new Error(`unknown state slot: ${request.slotId}`);

  const incoming = new Map<string, NonNullable<StateAdjudicationSchema['invalidations']>>();
  for (const rule of schema.invalidations ?? []) {
    const bucket = incoming.get(rule.targetSlotId) ?? [];
    bucket.push(rule);
    incoming.set(rule.targetSlotId, bucket);
  }

  const claims = ClaimProjection.from(events, knownAt);
  const evidence = EvidenceProjection.from(events, knownAt);
  const memo = new Map<string, InternalStateDecision>();
  const resolving = new Set<string>();
  const invalidatedSlots = new Set<string>();
  const maxHops = schema.maxInvalidationHops ?? DEFAULT_MAX_INVALIDATION_HOPS;
  const maxSlots = schema.maxInvalidatedSlots ?? DEFAULT_MAX_INVALIDATED_SLOTS;

  const resolveSlot = (slotId: string): InternalStateDecision => {
    const cached = memo.get(slotId);
    if (cached !== undefined) return cached;
    if (resolving.has(slotId)) throw new Error(`state invalidation recursion reached ${slotId}`);
    const slot = slotById.get(slotId);
    if (slot === undefined) throw new Error(`unknown state slot during resolution: ${slotId}`);

    resolving.add(slotId);
    const localRequest: StateRequest = {
      slotId,
      view: request.view,
      validAt: request.validAt,
      ...(request.knownAt === undefined ? {} : { knownAt: request.knownAt }),
    };
    const base = baseDecision(slot, localRequest, claims, evidence, schema);
    const invalidations: StateInvalidation[] = [];
    let budgetBlocked = false;
    const baseline =
      base.claim?.valid.from ??
      (base.candidates.length > 0
        ? Math.max(...base.candidates.map((claim) => claim.valid.from))
        : undefined);

    if (baseline !== undefined) {
      for (const rule of incoming.get(slotId) ?? []) {
        const source = resolveSlot(rule.sourceSlotId);
        if (source.budgetBlocked) budgetBlocked = true;
        for (const frontier of frontiersForDecision(source)) {
          if (frontier.uncertain && rule.propagateWhenSourceUncertain === false) continue;
          const path = [...frontier.path, rule.id];
          if (path.length > maxHops) {
            budgetBlocked = true;
            continue;
          }
          if (frontier.effectiveAt <= baseline || frontier.effectiveAt > request.validAt) continue;
          invalidations.push(
            Object.freeze({
              ruleId: rule.id,
              sourceSlotId: rule.sourceSlotId,
              targetSlotId: rule.targetSlotId,
              effectiveAt: frontier.effectiveAt,
              reason: rule.reason,
              path: Object.freeze(path),
              sourceWasUncertain: frontier.uncertain,
              sourceClaimIds: frontier.claimIds,
              sourceEvidenceSourceIds: frontier.evidenceSourceIds,
            }),
          );
        }
      }
    }

    if (invalidations.length > 0) {
      invalidatedSlots.add(slotId);
      if (invalidatedSlots.size > maxSlots) budgetBlocked = true;
    }

    let result: InternalStateDecision;
    if (budgetBlocked || invalidations.length > 0) {
      const reasons = [
        ...base.explanation.reasons,
        ...(budgetBlocked
          ? ['invalidation budget was exhausted; state failed closed']
          : ['newer upstream state invalidates the previously usable value']),
      ];
      result = Object.freeze({
        slot,
        status: request.view === 'current' ? 'unknown-current' : 'unknown',
        candidates: base.candidates,
        invalidations: Object.freeze(invalidations),
        explanation: Object.freeze({
          schemaId: schema.id,
          schemaVersion: schema.version,
          slotId: slot.id,
          strategy: slot.strategy,
          reasons: Object.freeze(reasons),
          candidates: base.explanation.candidates,
          valueGroups: base.explanation.valueGroups,
        }),
        budgetBlocked,
      });
    } else {
      result = base;
    }

    resolving.delete(slotId);
    memo.set(slotId, result);
    return result;
  };

  const internal = resolveSlot(request.slotId);
  const premise = premiseAssessment(request, internal);
  return Object.freeze({
    slot: internal.slot,
    request,
    status: internal.status,
    ...(internal.claim === undefined ? {} : { claim: internal.claim }),
    ...(internal.value === undefined ? {} : { value: internal.value }),
    candidates: internal.candidates,
    invalidations: internal.invalidations,
    premise,
    explanation: internal.explanation,
  });
}
