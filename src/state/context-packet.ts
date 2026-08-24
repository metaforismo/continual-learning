import type { EvidenceRole, JsonValue } from '../domain.js';
import { evidenceRoles } from '../domain.js';
import type { EvidencePacketLink, MemoryPacket } from '../context.js';
import type { StateContextPacketOptions, StateDecision } from './types.js';

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

function eligibleClaimIds(decision: StateDecision): ReadonlySet<string> {
  return new Set(
    decision.explanation.candidates
      .filter((evaluation) => evaluation.eligible)
      .map((evaluation) => evaluation.claim.id),
  );
}

function contentForDecision(decision: StateDecision): string {
  const identity = `${decision.slot.domain}/${decision.slot.id}`;
  if (decision.value !== undefined) {
    return [
      `Authorized ${decision.status} state for ${identity}: ${canonicalJson(decision.value)}.`,
      `Representative claim: ${decision.claim?.id ?? 'multiple agreeing claims'}.`,
      decision.premise.status === 'rejected'
        ? `Reject the request premise: ${decision.premise.reason}.`
        : '',
    ]
      .filter((line) => line.length > 0)
      .join('\n');
  }

  if (decision.status === 'unknown-current') {
    const causes = decision.invalidations
      .map((invalidation) => `${invalidation.path.join(' -> ')}: ${invalidation.reason}`)
      .join('; ');
    return [
      `Current state for ${identity} is unknown because newer upstream state invalidated the previous value.`,
      'Do not reuse a historical candidate as a current premise.',
      causes.length === 0 ? '' : `Invalidation basis: ${causes}.`,
    ]
      .filter((line) => line.length > 0)
      .join('\n');
  }

  if (decision.status === 'disputed') {
    const eligibleIds = eligibleClaimIds(decision);
    const disputedIds = decision.candidates
      .filter((claim) => eligibleIds.has(claim.id))
      .map((claim) => claim.id);
    return [
      `State for ${identity} is disputed; no candidate is authorized as the single value.`,
      `Eligible candidate claim ids: ${disputedIds.join(', ') || 'none'}.`,
      'Preserve the conflict or request verification instead of selecting by prompt wording.',
    ].join('\n');
  }

  return [
    `State for ${identity} is unknown; no value satisfies the declared policy.`,
    'Do not assume a default value from stale, quarantined, or unsupported memory.',
  ].join('\n');
}

function selectedClaims(decision: StateDecision) {
  const eligibleIds = eligibleClaimIds(decision);

  if (decision.value !== undefined) {
    const selectedGroup = decision.explanation.valueGroups.find(
      (group) => group.valueKey === decision.explanation.selectedValueKey,
    );
    const selectedIds = new Set(selectedGroup?.eligibleClaimIds ?? []);
    return decision.candidates.filter(
      (claim) => eligibleIds.has(claim.id) && selectedIds.has(claim.id),
    );
  }

  if (decision.status === 'disputed') {
    return decision.candidates.filter((claim) => eligibleIds.has(claim.id));
  }

  // Unknown-current packets should carry the newer invalidation basis, not rematerialize the stale
  // candidate whose use they are explicitly blocking.
  return [];
}

function mergeRole(
  byPacketId: Map<string, Set<EvidenceRole>>,
  packetId: string,
  roles: readonly EvidenceRole[],
): void {
  const merged = byPacketId.get(packetId) ?? new Set<EvidenceRole>();
  for (const role of roles) merged.add(role);
  byPacketId.set(packetId, merged);
}

function mappedPacketId(
  mapping: Readonly<Record<string, string>>,
  sourceId: string,
): string | undefined {
  if (!Object.prototype.hasOwnProperty.call(mapping, sourceId)) return undefined;
  const packetId = mapping[sourceId];
  return typeof packetId === 'string' && packetId.trim().length > 0 ? packetId : undefined;
}

/**
 * Convert an adjudicated state into one context packet with provenance closure.
 *
 * Raw conflicting claims are never emitted as independently authoritative packet text. Resolved
 * state becomes a `state` packet; disputed or unknown state becomes a model-authorized constraint.
 * Provenance mapping is strict by default; callers must explicitly opt out for non-model UI views.
 */
export function stateDecisionToContextPacket(
  decision: StateDecision,
  options: StateContextPacketOptions = {},
): MemoryPacket {
  const byPacketId = new Map<string, Set<EvidenceRole>>();
  const packetMap = options.evidencePacketIdBySourceId ?? {};
  const missing = new Set<string>();

  for (const claim of selectedClaims(decision)) {
    for (const reference of claim.evidence) {
      const packetId = mappedPacketId(packetMap, reference.sourceId);
      if (packetId === undefined) {
        missing.add(reference.sourceId);
        continue;
      }
      mergeRole(byPacketId, packetId, evidenceRoles(reference));
    }
  }

  for (const invalidation of decision.invalidations) {
    for (const sourceId of invalidation.sourceEvidenceSourceIds) {
      const packetId = mappedPacketId(packetMap, sourceId);
      if (packetId === undefined) {
        missing.add(sourceId);
        continue;
      }
      mergeRole(byPacketId, packetId, ['constrains']);
    }
  }

  const enforceEvidenceDependencies = options.enforceEvidenceDependencies ?? true;
  if (enforceEvidenceDependencies && missing.size > 0) {
    throw new Error(
      `state packet is missing evidence packet mappings for: ${[...missing].sort().join(', ')}`,
    );
  }

  const evidenceLinks: EvidencePacketLink[] = [...byPacketId]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([packetId, roles]) =>
      Object.freeze({
        packetId,
        roles: Object.freeze([...roles].sort()),
      }),
    );
  const requiredEvidenceRoles =
    decision.value === undefined
      ? []
      : decision.slot.evidencePolicy
          .filter((policy) => policy.required === true)
          .map((policy) => policy.role);
  const content = contentForDecision(decision);
  const topics = [
    decision.slot.domain,
    decision.slot.key.subject,
    decision.slot.key.predicate,
    ...(options.topics ?? []),
  ];

  return Object.freeze({
    id: options.id ?? `state:${decision.slot.id}:${decision.status}`,
    kind: decision.value === undefined ? 'constraint' : 'state',
    content,
    estimatedTokens: options.estimatedTokens ?? Math.max(1, Math.ceil(content.length / 4)),
    activationScore: options.activationScore ?? 1,
    topics: Object.freeze([...new Set(topics)]),
    authorization:
      decision.status === 'historical' ? 'authorized-historical' : 'authorized-current',
    evidenceLinks: Object.freeze(evidenceLinks),
    ...(requiredEvidenceRoles.length === 0
      ? {}
      : { requiredEvidenceRoles: Object.freeze([...new Set(requiredEvidenceRoles)]) }),
    ...(options.mandatory === undefined ? {} : { mandatory: options.mandatory }),
    ...(options.dependsOn === undefined
      ? {}
      : { dependsOn: Object.freeze([...options.dependsOn]) }),
    risk: options.risk ?? 'medium',
  });
}
