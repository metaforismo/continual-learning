# Verified procedure candidates

## Purpose

A successful memory intervention and a validated applicability rule are not yet a procedure.
They establish that one memory helped under a bounded context boundary; they do not establish an
ordered, evidence-backed behavior that may be promoted or executed.

`verified-procedure-candidates-v1` introduces one process-local derived object:

```text
VerifiedApplicabilityHypothesis
        +
current canonical evidence
        +
ordered typed procedure contract
        ↓
VerifiedProcedureCandidate
```

The result is deliberately non-executable. It preserves enough provenance for review and later
canary planning without turning free-form model output into instruction authority.

## Upstream gate

`createVerifiedProcedureCandidate()` requires the exact process-issued applicability validation
capability. A structural clone is rejected before its properties are inspected.

The applicability result must be:

```text
status = validated
blockers = []
```

The candidate copies the complete discovery and held-out lineage rather than retaining only the
final rule:

- discovery and validation observation IDs;
- accepted and excluded observations;
- comparison IDs and experimental-unit digests;
- discovery and validation source groups;
- assessment digests and metrics;
- considered feature set;
- required and forbidden feature rule.

This makes the candidate self-describing for later review. It does not make the applicability
record durable or cryptographically authenticated.

## Canonical boundary

The request is bound to an exact canonical event fingerprint. Candidate creation semantically
replays the supplied event history and rejects:

- malformed, sparse, circular, or non-canonical JSON;
- a stale or forged fingerprint;
- a candidate timestamp before the applicability validation;
- a candidate timestamp before the canonical tail it fingerprints;
- evidence that did not exist at the candidate transaction time;
- evidence that is no longer currently available;
- evidence crossing the applicability scope;
- secret or `secret-detected` evidence.

The v1 boundary therefore creates current-tail candidates only. It does not issue a historical
candidate against an older canonical prefix.

## Candidate shape

A verified candidate binds:

```text
candidate ID
procedure ID + immutable version
goal signature + goal evidence
ordered typed steps
step dependencies
dependency versions
contraindications
risk
verification contract
rollback contract
complete applicability lineage
canonical fingerprint
aggregate provenance and privacy metadata
```

The candidate digest covers the complete normalized object.

### Ordered steps

Supported step kinds are:

```text
inspect
decide
mutate
verify
communicate
```

Step order is semantic and is never sorted. Each step carries:

- a stable step ID;
- an instruction;
- an expected outcome;
- dependencies on earlier steps only;
- exact canonical evidence bindings;
- at least one `supports` or `verifies` reference;
- at least one step-exclusive supportive evidence anchor with `external-source` authority or
  stronger.

A `verify` step additionally requires at least one evidence reference with the `verifies` role.
The final verification step must transitively depend on every preceding step, so a successful
verifier cannot silently omit part of the procedure.

Evidence used only as `context` or `contradicts` cannot support a step. `constrains` evidence may
accompany a step, but it cannot be the sole positive basis for its instruction.

### Dependencies

A dependency is identified by:

```text
kind: tool | service | procedure | policy
id
versionDigest
```

The declared version digest is not accepted as an unattested string. At least one exact evidence
binding must:

- have role `verifies`;
- have content hash equal to `versionDigest`;
- have `external-source` authority or stronger.

Dependencies are canonicalized by kind and ID, but the procedure's step order remains unchanged.

### Contraindications

Contraindications are first-class negative knowledge. Each one carries:

- an ID;
- a bounded condition;
- exact evidence with `constrains` or `verifies` role;
- `external-source` authority or stronger.

They remain visible in the candidate digest and cannot be discarded when a later canary plan is
constructed.

## Verification contract

The contract binds:

- the final `verify` step;
- verifier kind: `tool`, `test`, or `human`;
- verifier implementation/report digest;
- exact evidence whose content hash equals that digest;
- disjoint success and failure criteria;
- timeout and attempt limits;
- failure action.

Tool and test verifiers require digest-matching `tool-verified` evidence or stronger. A human
verifier requires an exact digest-matching `human-explicit` report; a stronger-looking policy label
cannot masquerade as human review.

Criteria are bounded, deduplicated, and canonicalized. They are still declarative text in v1; this
module does not execute or interpret them.

## Rollback and risk

Rollback strategies are:

```text
disable-candidate
restore-checkpoint
manual
```

Rollback instructions require positive `supports` or `verifies` evidence with
`external-source` authority or stronger. `restore-checkpoint` additionally requires
`tool-verified` digest-matching evidence for the exact checkpoint.

A candidate containing a `mutate` step:

- cannot declare `low` risk;
- cannot use `disable-candidate` as if disabling future use reverted an already-applied mutation.

High and destructive candidates additionally require:

- a human verifier;
- `human-review` on verification failure;
- restore-checkpoint or manual rollback;
- human-explicit supporting evidence.

These requirements set `humanReviewRequired` and review reasons. They do not grant approval.

## Identity and idempotency

The guarded API snapshots caller inputs once and binds two process-local identities:

```text
candidate ID
scope:procedureId@version
```

Both registries are preflighted before either is mutated. Therefore a conflicting version cannot
poison the candidate-ID registry, and a conflicting candidate ID cannot reserve an otherwise valid
version. Exact retries return the original issued capability.

This is process-local software capability semantics, not durable authentication. Restart-safe
identity requires a future canonical admission protocol.

## Explicit absence of authority

Every candidate carries:

```text
status = candidate
executable = false
procedurePromotionAuthorized = false
canaryPlanAuthorized = false
executionAuthorized = false
```

A positive applicability result does not authorize a canary. A human-review requirement does not
constitute human approval. A candidate is data for the next review boundary, not a trusted skill or
harness command.

The intended path is:

```text
verified attribution
  -> held-out applicability
  -> verified procedure candidate
  -> bounded canary plan
  -> independently verified canary trials
  -> human-reviewed lifecycle
  -> separate harness execution authority
```

## Complexity

Candidate creation currently performs:

```text
O(N) semantic replay and canonical fingerprinting
+ O(S + E + D + C) candidate normalization
```

where `N` is lifetime canonical history, `S` steps, `E` evidence references, `D` dependencies, and
`C` contraindications. The procedure-candidate boundary is correctness-first and does not yet use
the selected-object read index. No production-scale latency claim is made.

## Security boundary and known limitations

V1 does not provide:

- durable or signed candidate admission;
- authenticated actors, feature extractors, experiment controllers, or verifier identities;
- remote attestation that evidence bytes correspond to the named tool, test, dependency, or human;
- semantic proof that free-text instructions follow from cited evidence;
- machine-executable success/failure criteria;
- automatic counterexample search beyond the inherited applicability evidence;
- procedure composition or conflict resolution;
- canary assignment, resource metering, trial completeness, scheduling, or execution;
- deletion propagation into a future durable candidate store;
- an independently authenticated commitment to the supplied canonical prefix.

Exact digests and process-local issuance prevent several accidental and in-process forgery paths,
but they are not signatures and do not defend against a trusted host fabricating the entire input.

## Evaluation gates

Before this object may feed canary planning, test at least:

- cloned and forged upstream capabilities;
- stale fingerprints, backdating, and unavailable evidence;
- cross-scope, restricted, deleted, personal, sensitive, and secret evidence;
- context-only, contradicting, constraints-only, or generic evidence laundering;
- step ordering, forward dependencies, missing dependency closure, and duplicate IDs;
- dependency, verifier, and checkpoint digest mismatch;
- contradictory success/failure criteria;
- low-risk mutation and non-reverting rollback;
- high/destructive human-review requirements;
- immutable ID/version conflicts and exact retry;
- input-order invariance for semantically unordered sets;
- sparse, circular, oversized, and stateful-getter inputs;
- explicit absence of promotion, canary, scheduling, and execution authority.

The allowed v1 claim is narrow:

> A validated applicability capability can be transformed into an immutable, current-tail,
> provenance-complete procedure candidate whose steps, dependencies, contraindications,
> verification, rollback, and risk are evidence-bound, while all promotion and execution authority
> remains explicitly absent.

## Next gate

`verified-canary-plans-v1` should bind this exact candidate digest to a bounded rollout intent:
population, deterministic treatment/control assignment, concurrency and resource budgets, sandbox
and network policy, tool allow/deny lists, stop rules, rollback coverage, independent review, and an
exact intent digest. It must remain non-executable and must not grant host scheduling authority.
