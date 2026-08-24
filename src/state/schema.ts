import { claimKeyToString } from '../domain.js';
import type {
  StateAdjudicationSchema,
  StateInvalidationRule,
  StateSlotDefinition,
} from './types.js';

export const DEFAULT_MAX_INVALIDATION_HOPS = 8;
export const DEFAULT_MAX_INVALIDATED_SLOTS = 128;

function assertNonEmpty(value: string, label: string): void {
  if (value.trim().length === 0) throw new Error(`${label} cannot be empty`);
}

function validateSlot(slot: StateSlotDefinition): void {
  assertNonEmpty(slot.id, 'state slot id');
  assertNonEmpty(slot.domain, `state slot ${slot.id} domain`);
  assertNonEmpty(slot.key.scope, `state slot ${slot.id} scope`);
  assertNonEmpty(slot.key.subject, `state slot ${slot.id} subject`);
  assertNonEmpty(slot.key.predicate, `state slot ${slot.id} predicate`);

  if (slot.evidencePolicy.length === 0) {
    throw new Error(`state slot ${slot.id} requires an explicit evidence policy`);
  }
  const roles = new Set<string>();
  for (const policy of slot.evidencePolicy) {
    if (roles.has(policy.role)) {
      throw new Error(`state slot ${slot.id} repeats evidence role ${policy.role}`);
    }
    roles.add(policy.role);
    if (policy.authorityPrecedence.length === 0) {
      throw new Error(
        `state slot ${slot.id} role ${policy.role} requires an authority precedence`,
      );
    }
    if (new Set(policy.authorityPrecedence).size !== policy.authorityPrecedence.length) {
      throw new Error(
        `state slot ${slot.id} role ${policy.role} repeats an authority`,
      );
    }
  }

  if (
    slot.minimumConfidence !== undefined &&
    (!Number.isFinite(slot.minimumConfidence) ||
      slot.minimumConfidence < 0 ||
      slot.minimumConfidence > 1)
  ) {
    throw new RangeError(`state slot ${slot.id} minimumConfidence must be in [0, 1]`);
  }
}

function validateRule(
  rule: StateInvalidationRule,
  slotIds: ReadonlySet<string>,
): void {
  assertNonEmpty(rule.id, 'state invalidation rule id');
  assertNonEmpty(rule.sourceSlotId, `state invalidation ${rule.id} sourceSlotId`);
  assertNonEmpty(rule.targetSlotId, `state invalidation ${rule.id} targetSlotId`);
  assertNonEmpty(rule.reason, `state invalidation ${rule.id} reason`);
  if (!slotIds.has(rule.sourceSlotId)) {
    throw new Error(`state invalidation ${rule.id} references unknown source slot ${rule.sourceSlotId}`);
  }
  if (!slotIds.has(rule.targetSlotId)) {
    throw new Error(`state invalidation ${rule.id} references unknown target slot ${rule.targetSlotId}`);
  }
  if (rule.sourceSlotId === rule.targetSlotId) {
    throw new Error(`state invalidation ${rule.id} cannot invalidate its own slot`);
  }
}

function assertAcyclic(rules: readonly StateInvalidationRule[]): void {
  const adjacency = new Map<string, string[]>();
  for (const rule of rules) {
    const targets = adjacency.get(rule.sourceSlotId) ?? [];
    targets.push(rule.targetSlotId);
    adjacency.set(rule.sourceSlotId, targets);
  }

  const visiting = new Set<string>();
  const visited = new Set<string>();

  const visit = (slotId: string): void => {
    if (visited.has(slotId)) return;
    if (visiting.has(slotId)) {
      throw new Error(`state invalidation graph contains a cycle at ${slotId}`);
    }
    visiting.add(slotId);
    for (const target of adjacency.get(slotId) ?? []) visit(target);
    visiting.delete(slotId);
    visited.add(slotId);
  };

  for (const source of adjacency.keys()) visit(source);
}

export function validateStateSchema(schema: StateAdjudicationSchema): void {
  assertNonEmpty(schema.id, 'state schema id');
  assertNonEmpty(schema.version, 'state schema version');
  if (schema.slots.length === 0) throw new Error('state schema requires at least one slot');

  const slotIds = new Set<string>();
  const claimKeys = new Set<string>();
  for (const slot of schema.slots) {
    validateSlot(slot);
    if (slotIds.has(slot.id)) throw new Error(`duplicate state slot id: ${slot.id}`);
    slotIds.add(slot.id);
    const key = claimKeyToString(slot.key);
    if (claimKeys.has(key)) {
      throw new Error(`multiple state slots target the same claim key: ${slot.id}`);
    }
    claimKeys.add(key);
  }

  const maxHops = schema.maxInvalidationHops ?? DEFAULT_MAX_INVALIDATION_HOPS;
  if (!Number.isInteger(maxHops) || maxHops < 0 || maxHops > 32) {
    throw new RangeError('maxInvalidationHops must be an integer in [0, 32]');
  }
  const maxSlots = schema.maxInvalidatedSlots ?? DEFAULT_MAX_INVALIDATED_SLOTS;
  if (!Number.isInteger(maxSlots) || maxSlots <= 0) {
    throw new RangeError('maxInvalidatedSlots must be a positive integer');
  }

  const rules = schema.invalidations ?? [];
  const ruleIds = new Set<string>();
  for (const rule of rules) {
    validateRule(rule, slotIds);
    if (ruleIds.has(rule.id)) throw new Error(`duplicate state invalidation rule id: ${rule.id}`);
    ruleIds.add(rule.id);
  }
  assertAcyclic(rules);
}
