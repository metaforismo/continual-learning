export type MemoryPacketKind =
  | 'state'
  | 'episode'
  | 'procedure'
  | 'source'
  | 'constraint'
  | 'summary';

export type PacketAuthorization =
  | 'authorized-current'
  | 'authorized-historical'
  | 'ambiguous'
  | 'quarantined'
  | 'revoked';

export interface MemoryPacket {
  readonly id: string;
  readonly kind: MemoryPacketKind;
  readonly content: string;
  readonly estimatedTokens: number;
  readonly activationScore: number;
  readonly topics: readonly string[];
  readonly authorization: PacketAuthorization;
  readonly mandatory?: boolean;
  readonly dependsOn?: readonly string[];
  readonly evidencePacketIds?: readonly string[];
  readonly risk?: 'low' | 'medium' | 'high';
}

export interface ContextCompilerOptions {
  readonly tokenBudget: number;
  readonly view: 'current' | 'historical';
  readonly allowAmbiguous?: boolean;
  readonly maxPerKind?: Partial<Readonly<Record<MemoryPacketKind, number>>>;
  readonly redundancyPenalty?: number;
}

export interface RejectedPacket {
  readonly id: string;
  readonly reason: string;
}

export interface CompiledContext {
  readonly selected: readonly MemoryPacket[];
  readonly rejected: readonly RejectedPacket[];
  readonly totalTokens: number;
}

function jaccard(left: readonly string[], right: readonly string[]): number {
  const leftSet = new Set(left);
  const rightSet = new Set(right);
  if (leftSet.size === 0 && rightSet.size === 0) return 0;
  let intersection = 0;
  for (const value of leftSet) if (rightSet.has(value)) intersection += 1;
  return intersection / (leftSet.size + rightSet.size - intersection);
}

function authorizationReason(
  packet: MemoryPacket,
  options: ContextCompilerOptions,
): string | undefined {
  if (packet.authorization === 'quarantined') return 'quarantined memory is not model-authorized';
  if (packet.authorization === 'revoked') return 'revoked memory is not model-authorized';
  if (packet.authorization === 'ambiguous' && options.allowAmbiguous !== true) {
    return 'ambiguous state must be adjudicated or represented by an explicit ambiguity packet';
  }
  if (packet.authorization === 'authorized-historical' && options.view !== 'historical') {
    return 'historical memory is not valid for the requested current-state view';
  }
  return undefined;
}

/**
 * Materialize a bounded working set from a much larger activated set.
 *
 * Selection is budgeted, dependency-aware, risk-aware, and diversity-seeking. It deliberately
 * refuses quarantined, revoked, stale-current, or unresolved raw state even when activation is high.
 */
export function compileContext(
  packets: readonly MemoryPacket[],
  options: ContextCompilerOptions,
): CompiledContext {
  if (!Number.isInteger(options.tokenBudget) || options.tokenBudget <= 0) {
    throw new RangeError('tokenBudget must be a positive integer');
  }

  const packetById = new Map<string, MemoryPacket>();
  for (const packet of packets) {
    if (packetById.has(packet.id)) throw new Error(`duplicate packet id: ${packet.id}`);
    if (!Number.isInteger(packet.estimatedTokens) || packet.estimatedTokens <= 0) {
      throw new RangeError(`packet ${packet.id} must have a positive integer token estimate`);
    }
    if (!Number.isFinite(packet.activationScore) || packet.activationScore < 0) {
      throw new RangeError(`packet ${packet.id} must have a non-negative activation score`);
    }
    packetById.set(packet.id, packet);
  }

  const selected = new Map<string, MemoryPacket>();
  const rejected = new Map<string, string>();
  const kindCounts = new Map<MemoryPacketKind, number>();
  let totalTokens = 0;

  const addClosure = (rootId: string, required: boolean): boolean => {
    const visiting = new Set<string>();
    const closure: MemoryPacket[] = [];
    const seen = new Set<string>();

    const visit = (id: string): boolean => {
      if (selected.has(id) || seen.has(id)) return true;
      if (visiting.has(id)) {
        if (required) throw new Error(`dependency cycle detected at ${id}`);
        rejected.set(rootId, `dependency cycle detected at ${id}`);
        return false;
      }
      const packet = packetById.get(id);
      if (packet === undefined) {
        if (required) throw new Error(`required dependency does not exist: ${id}`);
        rejected.set(rootId, `missing dependency: ${id}`);
        return false;
      }
      const authFailure = authorizationReason(packet, options);
      if (authFailure !== undefined) {
        if (required) throw new Error(`required packet ${id} is unauthorized: ${authFailure}`);
        rejected.set(rootId, `dependency ${id} is unauthorized: ${authFailure}`);
        return false;
      }
      if (packet.risk === 'high' && (packet.evidencePacketIds?.length ?? 0) === 0) {
        if (required) throw new Error(`high-risk packet ${id} has no evidence dependency`);
        rejected.set(rootId, `high-risk packet ${id} has no evidence dependency`);
        return false;
      }

      visiting.add(id);
      for (const dependency of packet.dependsOn ?? []) {
        if (!visit(dependency)) return false;
      }
      for (const evidenceId of packet.evidencePacketIds ?? []) {
        if (!visit(evidenceId)) return false;
      }
      visiting.delete(id);
      seen.add(id);
      closure.push(packet);
      return true;
    };

    if (!visit(rootId)) return false;

    const additionalCost = closure
      .filter((packet) => !selected.has(packet.id))
      .reduce((sum, packet) => sum + packet.estimatedTokens, 0);
    if (totalTokens + additionalCost > options.tokenBudget) {
      if (required) {
        throw new Error(`mandatory packet closure ${rootId} exceeds the context budget`);
      }
      rejected.set(rootId, 'packet plus dependencies would exceed the context budget');
      return false;
    }

    const projectedKindCounts = new Map(kindCounts);
    for (const packet of closure) {
      if (selected.has(packet.id)) continue;
      const maximum = options.maxPerKind?.[packet.kind];
      const current = projectedKindCounts.get(packet.kind) ?? 0;
      if (maximum !== undefined && current >= maximum && packet.mandatory !== true) {
        if (required) throw new Error(`mandatory closure exceeds maxPerKind for ${packet.kind}`);
        rejected.set(rootId, `maxPerKind reached for ${packet.kind}`);
        return false;
      }
      projectedKindCounts.set(packet.kind, current + 1);
    }

    for (const packet of closure) {
      if (selected.has(packet.id)) continue;
      selected.set(packet.id, packet);
      totalTokens += packet.estimatedTokens;
      kindCounts.set(packet.kind, (kindCounts.get(packet.kind) ?? 0) + 1);
    }
    return true;
  };

  for (const packet of packets.filter((candidate) => candidate.mandatory === true)) {
    const failure = authorizationReason(packet, options);
    if (failure !== undefined) throw new Error(`mandatory packet ${packet.id} is unauthorized: ${failure}`);
    addClosure(packet.id, true);
  }

  const redundancyPenalty = options.redundancyPenalty ?? 0.55;
  const pending = packets.filter((packet) => packet.mandatory !== true && !selected.has(packet.id));

  while (pending.length > 0) {
    let bestIndex = -1;
    let bestUtility = Number.NEGATIVE_INFINITY;

    for (let index = 0; index < pending.length; index += 1) {
      const packet = pending[index];
      if (packet === undefined || rejected.has(packet.id)) continue;
      const failure = authorizationReason(packet, options);
      if (failure !== undefined) {
        rejected.set(packet.id, failure);
        continue;
      }
      if (packet.risk === 'high' && (packet.evidencePacketIds?.length ?? 0) === 0) {
        rejected.set(packet.id, 'high-risk memory lacks recoverable evidence');
        continue;
      }
      const maximum = options.maxPerKind?.[packet.kind];
      if (maximum !== undefined && (kindCounts.get(packet.kind) ?? 0) >= maximum) {
        rejected.set(packet.id, `maxPerKind reached for ${packet.kind}`);
        continue;
      }

      let maxSimilarity = 0;
      for (const chosen of selected.values()) {
        maxSimilarity = Math.max(maxSimilarity, jaccard(packet.topics, chosen.topics));
      }
      const diversityFactor = Math.max(0.05, 1 - redundancyPenalty * maxSimilarity);
      const utility = (packet.activationScore * diversityFactor) / packet.estimatedTokens;
      if (utility > bestUtility) {
        bestUtility = utility;
        bestIndex = index;
      }
    }

    if (bestIndex < 0) break;
    const [candidate] = pending.splice(bestIndex, 1);
    if (candidate !== undefined) addClosure(candidate.id, false);
  }

  for (const packet of packets) {
    if (!selected.has(packet.id) && !rejected.has(packet.id)) {
      rejected.set(packet.id, 'not selected within the working-context budget');
    }
  }

  return Object.freeze({
    selected: Object.freeze([...selected.values()]),
    rejected: Object.freeze(
      [...rejected.entries()].map(([id, reason]) => Object.freeze({ id, reason })),
    ),
    totalTokens,
  });
}
