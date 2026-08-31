import type { MemoryEvent } from '../domain.js';
import { canonicalJson } from '../retrieval/canonical.js';
import {
  createBoundedCanaryPlan as createBoundedCanaryPlanCore,
  isIssuedBoundedCanaryPlan as isIssuedPlanCore,
  isIssuedCanaryPlanReview as isIssuedReviewCore,
  reviewBoundedCanaryPlan as reviewBoundedCanaryPlanCore,
  type BoundedCanaryPlan,
  type BoundedCanaryPlanInput,
  type CanaryPlanReview,
  type CanaryPlanReviewInput,
} from './bounded-canary-plans.js';
import {
  isIssuedVerifiedProcedureCandidate,
  type VerifiedProcedureCandidate,
} from './verified-procedure-candidates-api.js';

export { BOUNDED_CANARY_PLAN_SCHEMA_VERSION } from './bounded-canary-plans.js';

export type {
  BoundedCanaryPlan,
  BoundedCanaryPlanInput,
  CanaryAbortContractInput,
  CanaryAssignment,
  CanaryBudgetInput,
  CanaryPlanReview,
  CanaryPlanReviewInput,
  CanaryPopulationManifestInput,
  CanaryReviewDecision,
  CanaryReviewRecommendation,
  CanaryRuntimeIdentityInput,
  CanaryStopAction,
  CanaryStopCategory,
  CanaryStopComparator,
  CanaryStopConditionInput,
  CanarySubjectInput,
  VerifiedCanaryAbortContract,
  VerifiedCanaryBudget,
  VerifiedCanaryPopulationManifest,
  VerifiedCanaryRuntimeIdentity,
  VerifiedCanaryStopCondition,
  VerifiedCanarySubject,
} from './bounded-canary-plans.js';

const MAX_EVENTS = 10_000_000;
const MAX_INPUT_CHARACTERS = 1_000_000;
const MAX_ISSUED_IDENTITIES = 65_536;

interface IssuedIdentity<T> {
  readonly digest: string;
  readonly value: T;
}

const plansById = new Map<string, IssuedIdentity<BoundedCanaryPlan>>();
const plansByCandidateAndPopulation = new Map<string, IssuedIdentity<BoundedCanaryPlan>>();
const reviewsById = new Map<string, IssuedIdentity<CanaryPlanReview>>();
const reviewsByPlanAndReviewer = new Map<string, IssuedIdentity<CanaryPlanReview>>();
const issuedPlans = new WeakSet<object>();
const issuedReviews = new WeakSet<object>();

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as unknown as Record<string, unknown>)) {
      deepFreeze(child);
    }
    Object.freeze(value);
  }
  return value;
}

function canonicalSnapshot<T>(value: T, label: string): T {
  const encoded = canonicalJson(value);
  if (encoded.length > MAX_INPUT_CHARACTERS) {
    throw new RangeError(`${label} cannot exceed ${MAX_INPUT_CHARACTERS} canonical characters`);
  }
  return deepFreeze(JSON.parse(encoded) as T);
}

function snapshotEvents(eventsInput: readonly MemoryEvent[]): readonly MemoryEvent[] {
  if (!Array.isArray(eventsInput)) throw new TypeError('canary events must be an array');
  if (eventsInput.length > MAX_EVENTS) {
    throw new RangeError(`canary events cannot exceed ${MAX_EVENTS} entries`);
  }
  return Object.freeze(Array.from(eventsInput));
}

function inspectIdentity<T extends BoundedCanaryPlan | CanaryPlanReview>(
  key: string,
  digest: string,
  registry: ReadonlyMap<string, IssuedIdentity<T>>,
  label: string,
): T | undefined {
  const previous = registry.get(key);
  if (previous === undefined) return undefined;
  if (previous.digest !== digest) {
    throw new Error(`${label} conflicts with an already issued identity: ${key}`);
  }
  return previous.value;
}

function assertCapacity<T>(
  key: string,
  registry: ReadonlyMap<string, IssuedIdentity<T>>,
  label: string,
): void {
  if (!registry.has(key) && registry.size >= MAX_ISSUED_IDENTITIES) {
    throw new RangeError(
      `${label} registry cannot exceed ${MAX_ISSUED_IDENTITIES} process-local identities`,
    );
  }
}

function commitIdentity<T>(
  key: string,
  digest: string,
  value: T,
  registry: Map<string, IssuedIdentity<T>>,
): void {
  if (!registry.has(key)) registry.set(key, Object.freeze({ digest, value }));
}

/**
 * Guarded process-local canary-plan boundary.
 *
 * The procedure candidate capability is checked before any candidate property is read. Event and
 * request inputs are snapshotted once. Plan ID and candidate/population identity are both
 * preflighted before either registry is mutated. The returned object remains advisory and grants
 * neither host scheduling nor execution authority.
 */
export function createBoundedCanaryPlan(
  memoryEventsInput: readonly MemoryEvent[],
  candidate: VerifiedProcedureCandidate,
  input: BoundedCanaryPlanInput,
): BoundedCanaryPlan {
  if (!isIssuedVerifiedProcedureCandidate(candidate)) {
    throw new Error('canary planning requires an issued verified procedure candidate');
  }
  const events = snapshotEvents(memoryEventsInput);
  const request = canonicalSnapshot(input, 'bounded canary plan input');
  const plan = createBoundedCanaryPlanCore(events, candidate, request);
  if (!isIssuedPlanCore(plan)) throw new Error('canary plan core did not issue a capability');

  const populationKey = `${plan.candidateDigest}:${plan.population.manifestDigest}`;
  const byId = inspectIdentity(plan.id, plan.planDigest, plansById, 'canary plan id');
  const byPopulation = inspectIdentity(
    populationKey,
    plan.planDigest,
    plansByCandidateAndPopulation,
    'canary candidate/population identity',
  );
  if ((byId === undefined) !== (byPopulation === undefined)) {
    throw new Error('canary plan identity registries are internally inconsistent');
  }
  if (byId !== undefined) return byId;

  assertCapacity(plan.id, plansById, 'canary plan id');
  assertCapacity(
    populationKey,
    plansByCandidateAndPopulation,
    'canary candidate/population identity',
  );
  commitIdentity(plan.id, plan.planDigest, plan, plansById);
  commitIdentity(
    populationKey,
    plan.planDigest,
    plan,
    plansByCandidateAndPopulation,
  );
  issuedPlans.add(plan as object);
  return plan;
}

/**
 * Guarded independent-review boundary. One reviewer may issue one immutable review for one exact
 * plan digest. Approval is only a recommendation for a separate host scheduling gate.
 */
export function reviewBoundedCanaryPlan(
  memoryEventsInput: readonly MemoryEvent[],
  plan: BoundedCanaryPlan,
  input: CanaryPlanReviewInput,
): CanaryPlanReview {
  if (!isIssuedBoundedCanaryPlan(plan)) {
    throw new Error('canary review requires an issued guarded plan capability');
  }
  const events = snapshotEvents(memoryEventsInput);
  const request = canonicalSnapshot(input, 'canary plan review input');
  const review = reviewBoundedCanaryPlanCore(events, plan, request);
  if (!isIssuedReviewCore(review)) throw new Error('canary review core did not issue a capability');

  const reviewerKey = `${review.planDigest}:${review.reviewer}`;
  const byId = inspectIdentity(review.id, review.reviewDigest, reviewsById, 'canary review id');
  const byReviewer = inspectIdentity(
    reviewerKey,
    review.reviewDigest,
    reviewsByPlanAndReviewer,
    'canary plan/reviewer identity',
  );
  if ((byId === undefined) !== (byReviewer === undefined)) {
    throw new Error('canary review identity registries are internally inconsistent');
  }
  if (byId !== undefined) return byId;

  assertCapacity(review.id, reviewsById, 'canary review id');
  assertCapacity(reviewerKey, reviewsByPlanAndReviewer, 'canary plan/reviewer identity');
  commitIdentity(review.id, review.reviewDigest, review, reviewsById);
  commitIdentity(
    reviewerKey,
    review.reviewDigest,
    review,
    reviewsByPlanAndReviewer,
  );
  issuedReviews.add(review as object);
  return review;
}

export function isIssuedBoundedCanaryPlan(plan: BoundedCanaryPlan): boolean {
  return typeof plan === 'object' && plan !== null && issuedPlans.has(plan as object);
}

export function isIssuedCanaryPlanReview(review: CanaryPlanReview): boolean {
  return typeof review === 'object' && review !== null && issuedReviews.has(review as object);
}
