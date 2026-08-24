# State adjudication

## Purpose

Retrieval answers:

> Which memories may be relevant?

State adjudication answers a different question:

> Which value, if any, is authorized to govern the current decision?

The distinction is mandatory because a retrieved memory may be relevant while also being stale, disputed, unsupported, scoped to a different domain, contradicted, or valid only historically.

```text
retrieval candidates
        ↓
evidence-role and availability checks
        ↓
domain-specific state policy
        ↓
current / historical / disputed / unknown-current / unknown
        ↓
role-aware context packet
```

The v1 adjudicator is deterministic. Models or extractors may propose claims and relationships, but they do not choose the final state value inside the adjudication boundary.

## Evidence roles

Authority is not sufficient by itself. The same source can play different roles in different derived objects.

- `supports`: evidence in favor of a claim;
- `verifies`: evidence that directly checks the claim under a declared verifier;
- `context`: relevant background that does not independently establish the value;
- `contradicts`: evidence against the claim;
- `constrains`: evidence that limits how a state or procedure may be used.

A legacy evidence reference without an explicit role is interpreted as `supports`. New correctness-sensitive integrations should declare roles explicitly.

A high-authority contextual source does not automatically verify a claim. A currently available `contradicts` reference prevents that claim from directly governing state in v1.

Runtime role validation is fail-closed. Unknown role names are rejected at evidence-reference construction, claim admission, state-schema validation, and context-packet compilation rather than being silently ignored.

## State slots

A state schema contains typed slots. Each slot declares:

```text
id
domain
claim key: scope + subject + predicate
resolution strategy
evidence-role policy
role-specific authority precedence
minimum confidence
whether inference is permitted
```

Authority precedence is local to a domain and evidence role. For example:

- a human may be the strongest source for a personal preference;
- a reproducible test may be the strongest verifier of build status;
- a policy may be authoritative for authorization without being evidence that an execution succeeded.

The kernel therefore does not use one universal authority rank to settle every state conflict.

## Deterministic strategies

### `require-agreement`

Exactly one eligible value may remain. Multiple eligible values produce `disputed`.

### `latest-valid`

The eligible value with the unique latest world-valid start time wins. A tie remains disputed.

### `role-authority`

Values are compared lexicographically using the slot's ordered evidence-role policies and the authority precedence declared for each role. Equal vectors remain disputed; citation count does not break the tie.

### `role-authority-then-latest`

Role-specific authority is compared first. World-valid start time is used only when authority vectors tie.

No strategy silently chooses by prompt order, retrieval rank, or raw repetition count. Ineligible claims are retained for explanation but cannot influence latest-valid scoring, group confidence, invalidation baselines, or disputed-state frontiers indirectly.

## State roles

- `current`: one value is authorized for the requested current-world time;
- `historical`: one value is authorized for a historical view;
- `disputed`: multiple eligible values remain unresolved;
- `unknown-current`: an older value existed, but newer upstream state invalidates its current use and no replacement is authorized;
- `unknown`: no value satisfies the policy for the requested view.

`unknown-current` is intentionally different from absence. It means that reusing the historical value is unsafe.

## Premise resistance

A user or downstream agent may ask a question that embeds a stale assumption:

```text
Given that the commute is still 20 minutes, when should I leave?
```

The adjudicator assesses the premise separately from retrieval:

- `accepted`: it matches authorized state;
- `rejected`: it conflicts with authorized state or assumes a concrete value after invalidation;
- `unsupported`: state is unresolved and the premise cannot be accepted as fact.

The resulting context packet tells the model to reject the stale premise rather than allowing question wording to reactivate it.

## Implicit invalidation

Some updates invalidate related assumptions without directly replacing the same claim key:

```text
residence changed
    ↓ invalidates
commute estimate
    ↓ invalidates
departure plan
```

V1 uses an explicit, validated dependency DAG. Each rule declares a source slot, target slot, reason, and optional trigger.

### Transition triggers

The default trigger is `value-change`:

```text
Rome → Zurich          invalidates dependents
Rome → Rome            reaffirmation; does not invalidate
```

This prevents a later confirmation of the same authorized value from retiring otherwise valid downstream state. A rule may instead declare `trigger: new-claim` when every newer claim occurrence should invalidate the target regardless of whether the authorized value changed.

For `value-change`, the adjudicator reconstructs the authorized source state immediately before the selected source claim's world-valid start and compares values. This is deterministic and bitemporal, but it currently assumes millisecond-granularity world time; richer event-order semantics remain future work.

Propagation is:

- acyclic;
- bounded by maximum hops;
- bounded by the number of affected slots;
- provenance-preserving;
- fail-closed when a budget is exhausted.

Uncertain upstream state propagates invalidation by default. A rule may explicitly disable that behavior when uncertainty should not invalidate downstream state.

Every invalidation records:

```text
rule and slot path
effective world time
whether the source was uncertain
source claim ids
source evidence ids
reason
```

This is a correctness overlay, not automatic commonsense discovery. Learned or model-proposed invalidation edges must eventually pass a separate admission and transition-verification boundary.

## Context packets

A state decision becomes one model-facing packet:

- resolved decisions become `state` packets;
- disputed and unknown decisions become `constraint` packets;
- historical packets are authorized only in historical context views;
- evidence dependencies retain their roles;
- required evidence roles are enforced by the context compiler;
- packet provenance includes only eligible claims that actually contributed to the decision;
- `unknown-current` packets include the newer invalidation basis but do not rematerialize the stale candidate as current evidence.

Provenance mapping is strict by default. Packet construction fails when any adjudicating evidence source lacks a corresponding source packet. A caller may explicitly opt out only for non-model inspection surfaces that are not used as an authoritative context boundary.

## Implemented invariants

1. schemas have unique slots, claim keys, rules, and evidence-role policies;
2. schema strategies, roles, authorities, and invalidation triggers are runtime validated;
3. invalidation graphs are acyclic and bounded;
4. unavailable or forged evidence cannot authorize a candidate;
5. inferred, disputed, unknown, low-confidence, or contradicted claims fail declared policies;
6. required evidence roles are evaluated per value, not inferred from source authority;
7. repeated evidence does not win a state conflict by count;
8. equal policy authority remains disputed;
9. ineligible claims cannot affect scoring, invalidation, or context provenance indirectly;
10. world time and transaction time remain distinct;
11. newer upstream state can retire an older dependent assumption without inventing a replacement;
12. same-value reaffirmations do not invalidate dependents unless a rule explicitly uses `new-claim`;
13. request premises are assessed independently;
14. context closure contains only eligible claims that contributed to the decision;
15. unresolved-state packets constrain the model instead of presenting raw candidates as truth.

## Current limitations

The implementation does not yet provide:

- persisted and signed state-policy versions in the canonical ledger;
- dynamic ontology or dependency discovery;
- a transition verifier for coverage, preservation, and faithfulness;
- serializable per-state write partitions;
- logged model-judge verdicts;
- human review UI for high-impact ambiguity;
- learned authority routing;
- public benchmark evidence for premise resistance or implicit invalidation;
- automatic repair after a slot becomes `unknown-current`;
- richer than millisecond-granularity world-event ordering for transition detection.

These are explicit future gates, not capabilities implied by the v1 API.
