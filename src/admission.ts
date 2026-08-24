import {
  AUTHORITY_RANK,
  assertValidInterval,
  claimKeyToString,
  type ClaimRecord,
} from './domain.js';

export interface ValidationReport {
  readonly ok: boolean;
  readonly errors: readonly string[];
  readonly warnings: readonly string[];
}

function report(errors: string[], warnings: string[]): ValidationReport {
  return Object.freeze({
    ok: errors.length === 0,
    errors: Object.freeze(errors),
    warnings: Object.freeze(warnings),
  });
}

/**
 * Write-time admission rules. These rules are intentionally conservative: a rejected claim may
 * remain in the immutable episode/source archive, but it cannot become authorized agent state.
 */
export function validateClaimForAdmission(claim: ClaimRecord): ValidationReport {
  const errors: string[] = [];
  const warnings: string[] = [];

  try {
    assertValidInterval(claim.valid);
  } catch (error) {
    errors.push(error instanceof Error ? error.message : 'invalid validity interval');
  }

  if (claim.id.trim().length === 0) errors.push('claim id cannot be empty');
  if (claim.key.scope.trim().length === 0) errors.push('claim scope cannot be empty');
  if (claim.key.subject.trim().length === 0) errors.push('claim subject cannot be empty');
  if (claim.key.predicate.trim().length === 0) errors.push('claim predicate cannot be empty');

  if (!Number.isFinite(claim.confidence) || claim.confidence < 0 || claim.confidence > 1) {
    errors.push('claim confidence must be in [0, 1]');
  }

  if (claim.derivedFrom.includes(claim.id)) {
    errors.push('a claim cannot derive from itself');
  }
  if (new Set(claim.derivedFrom).size !== claim.derivedFrom.length) {
    errors.push('claim derivedFrom must not contain duplicates');
  }

  const evidenceIds = new Set<string>();
  const sourceGroups = new Set<string>();
  let strongestEvidenceRank = -1;
  let hasStrongVerification = false;

  for (const evidence of claim.evidence) {
    if (evidence.sourceId.trim().length === 0) errors.push('evidence sourceId cannot be empty');
    if (evidence.sourceGroups.length === 0) errors.push('evidence reference requires source groups');
    if (evidence.sourceGroups.some((group) => group.trim().length === 0)) {
      errors.push('evidence reference source groups cannot contain empty values');
    }
    if (new Set(evidence.sourceGroups).size !== evidence.sourceGroups.length) {
      errors.push('evidence reference source groups must not contain duplicates');
    }
    if (evidenceIds.has(evidence.sourceId)) errors.push(`duplicate evidence source: ${evidence.sourceId}`);
    evidenceIds.add(evidence.sourceId);
    for (const group of evidence.sourceGroups) sourceGroups.add(group);
    strongestEvidenceRank = Math.max(strongestEvidenceRank, AUTHORITY_RANK[evidence.authority]);
    if (AUTHORITY_RANK[evidence.authority] >= AUTHORITY_RANK['tool-verified']) {
      hasStrongVerification = true;
    }
  }

  if (claim.authority !== 'system-policy' && claim.evidence.length === 0) {
    errors.push('non-policy claims require recoverable evidence');
  }

  if (
    claim.authority !== 'system-policy' &&
    strongestEvidenceRank >= 0 &&
    AUTHORITY_RANK[claim.authority] > strongestEvidenceRank
  ) {
    errors.push('claim authority cannot exceed the strongest cited evidence');
  }

  if (claim.epistemicStatus === 'verified' && !hasStrongVerification) {
    errors.push('verified claims require tool, human, or policy-grade evidence');
  }

  if (claim.evidence.length > 1 && sourceGroups.size === 1) {
    warnings.push('multiple citations from one source group are not independent evidence');
  }

  if (claim.tags.some((tag) => tag.trim().length === 0)) {
    errors.push('claim tags cannot contain empty values');
  }
  if (new Set(claim.tags).size !== claim.tags.length) {
    errors.push('claim tags must not contain duplicates');
  }

  return report(errors, warnings);
}

export function validateSupersession(
  previous: ClaimRecord,
  replacement: ClaimRecord,
  effectiveAt: number,
): ValidationReport {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (previous.id === replacement.id) {
    errors.push('a claim cannot supersede itself');
  }
  if (claimKeyToString(previous.key) !== claimKeyToString(replacement.key)) {
    errors.push('supersession requires the same scope, subject, and predicate');
  }
  if (!Number.isFinite(effectiveAt)) {
    errors.push('supersession effectiveAt must be finite');
  }
  if (effectiveAt < previous.valid.from) {
    errors.push('supersession cannot predate the previous claim');
  }
  if (replacement.valid.from !== effectiveAt) {
    errors.push('replacement valid.from must equal supersession effectiveAt');
  }
  if (previous.valid.to !== undefined && effectiveAt > previous.valid.to) {
    warnings.push('supersession occurs after the previous claim already ended');
  }

  const replacementReport = validateClaimForAdmission(replacement);
  errors.push(...replacementReport.errors);
  warnings.push(...replacementReport.warnings);

  return report(errors, warnings);
}
