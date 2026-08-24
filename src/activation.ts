import { AUTHORITY_RANK, type Authority } from './domain.js';

export type ActivatableKind =
  | 'episode'
  | 'claim'
  | 'procedure'
  | 'source'
  | 'summary'
  | 'entity';

export interface ActivationNode {
  readonly id: string;
  readonly kind: ActivatableKind;
  readonly scope: string;
  readonly text: string;
  readonly goalTags: readonly string[];
  readonly authority: Authority;
  readonly recordedAt: number;
  readonly successes?: number;
  readonly failures?: number;
}

export interface ActivationEdge {
  readonly from: string;
  readonly to: string;
  readonly weight: number;
  readonly kind: 'semantic' | 'temporal' | 'causal' | 'procedural' | 'co-occurrence';
}

export interface ActivationQuery {
  readonly text: string;
  /** Ordered from most specific to least specific. */
  readonly scopeChain: readonly string[];
  readonly goalTags?: readonly string[];
  readonly seedIds?: readonly string[];
  /** Optional score supplied by a vector or learned retriever. */
  readonly semanticScores?: Readonly<Record<string, number>>;
  readonly now: number;
  readonly maxHops?: number;
  readonly limit?: number;
}

export interface ScoreComponents {
  lexical: number;
  semantic: number;
  scope: number;
  goal: number;
  authority: number;
  utility: number;
  recency: number;
  seed: number;
  propagation: number;
  fanoutPenalty: number;
}

export interface ActivatedMemory {
  readonly id: string;
  readonly score: number;
  readonly components: Readonly<ScoreComponents>;
  readonly activatedBy: readonly string[];
}

export function tokenize(text: string): readonly string[] {
  return Object.freeze(
    [...new Set(text.toLocaleLowerCase().match(/[\p{L}\p{N}_-]+/gu) ?? [])].sort(),
  );
}

function overlap(left: readonly string[], right: readonly string[]): number {
  if (left.length === 0 || right.length === 0) return 0;
  const rightSet = new Set(right);
  let matches = 0;
  for (const token of left) if (rightSet.has(token)) matches += 1;
  return matches / Math.sqrt(left.length * right.length);
}

function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.min(1, Math.max(0, value));
}

/**
 * Sparse multi-signal activation with associative expansion and fan-out inhibition.
 *
 * The result is an activated set of ids, not prompt text. A separate context compiler decides
 * which activated memories are materialized into the bounded model context.
 */
export function activateMemories(
  nodes: readonly ActivationNode[],
  edges: readonly ActivationEdge[],
  query: ActivationQuery,
): readonly ActivatedMemory[] {
  if (!Number.isFinite(query.now)) throw new TypeError('query.now must be finite');

  const nodeById = new Map(nodes.map((node) => [node.id, node] as const));
  if (nodeById.size !== nodes.length) throw new Error('activation node ids must be unique');

  const adjacency = new Map<string, ActivationEdge[]>();
  for (const edge of edges) {
    if (!nodeById.has(edge.from) || !nodeById.has(edge.to)) {
      throw new Error(`association references an unknown node: ${edge.from} -> ${edge.to}`);
    }
    if (!Number.isFinite(edge.weight) || edge.weight < 0 || edge.weight > 1) {
      throw new RangeError('association weights must be in [0, 1]');
    }
    const bucket = adjacency.get(edge.from) ?? [];
    bucket.push(edge);
    adjacency.set(edge.from, bucket);
  }

  const queryTokens = tokenize(query.text);
  const goalTags = query.goalTags ?? [];
  const seedIds = new Set(query.seedIds ?? []);
  const scoreById = new Map<string, number>();
  const componentById = new Map<string, ScoreComponents>();
  const activatedBy = new Map<string, Set<string>>();

  for (const node of nodes) {
    const scopeIndex = query.scopeChain.indexOf(node.scope);
    const scope =
      scopeIndex < 0 || query.scopeChain.length === 0
        ? 0
        : (query.scopeChain.length - scopeIndex) / query.scopeChain.length;
    const semantic = clamp01(query.semanticScores?.[node.id] ?? 0);
    const successes = Math.max(0, node.successes ?? 0);
    const failures = Math.max(0, node.failures ?? 0);
    const utility = (successes + 1) / (successes + failures + 2);
    const ageDays = Math.max(0, query.now - node.recordedAt) / 86_400_000;
    const recency = Math.exp((-Math.log(2) * ageDays) / 180);
    const outDegree = adjacency.get(node.id)?.length ?? 0;

    const components: ScoreComponents = {
      lexical: overlap(queryTokens, tokenize(node.text)) * 2.2,
      semantic: semantic * 1.7,
      scope: scope * 0.9,
      goal: overlap(goalTags, node.goalTags) * 1.1,
      authority: (AUTHORITY_RANK[node.authority] / 5) * 0.55,
      utility: utility * 0.55,
      recency: recency * 0.2,
      seed: seedIds.has(node.id) ? 3 : 0,
      propagation: 0,
      fanoutPenalty: Math.log1p(outDegree) * 0.12,
    };

    const direct =
      components.lexical +
      components.semantic +
      components.scope +
      components.goal +
      components.authority +
      components.utility +
      components.recency +
      components.seed -
      components.fanoutPenalty;

    scoreById.set(node.id, Math.max(0, direct));
    componentById.set(node.id, components);
    activatedBy.set(node.id, new Set(seedIds.has(node.id) ? ['explicit-seed'] : []));
  }

  let frontier = new Map(scoreById);
  const maxHops = query.maxHops ?? 2;
  const propagationDecay = 0.42;

  for (let hop = 1; hop <= maxHops; hop += 1) {
    const next = new Map<string, number>();
    for (const [sourceId, sourceActivation] of frontier) {
      if (sourceActivation <= 0) continue;
      const outgoing = adjacency.get(sourceId) ?? [];
      if (outgoing.length === 0) continue;
      const normalization = Math.sqrt(outgoing.length);

      for (const edge of outgoing) {
        const contribution =
          (sourceActivation * edge.weight * propagationDecay ** hop) / normalization;
        if (contribution <= 0.01) continue;
        next.set(edge.to, (next.get(edge.to) ?? 0) + contribution);
        activatedBy.get(edge.to)?.add(`${sourceId}:${edge.kind}:h${hop}`);
      }
    }

    for (const [targetId, contribution] of next) {
      scoreById.set(targetId, (scoreById.get(targetId) ?? 0) + contribution);
      const components = componentById.get(targetId);
      if (components !== undefined) components.propagation += contribution;
    }
    frontier = next;
  }

  const results = [...scoreById.entries()]
    .filter(([, score]) => score > 0)
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, query.limit ?? 128)
    .map(([id, score]) =>
      Object.freeze({
        id,
        score,
        components: Object.freeze({ ...(componentById.get(id) as ScoreComponents) }),
        activatedBy: Object.freeze([...(activatedBy.get(id) ?? [])].sort()),
      }),
    );

  return Object.freeze(results);
}
