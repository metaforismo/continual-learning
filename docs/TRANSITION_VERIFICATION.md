# Transition verification

## Purpose

A valid memory event is not automatically a valid memory update.

An agent may produce a sequence that is individually schema-correct while still:

- omitting relevant incoming evidence;
- modifying the wrong scope;
- activating unsupported state;
- deleting or retiring unrelated knowledge;
- relying on a stale ledger prefix;
- laundering prompt-injected or secret-bearing evidence;
- declaring its own work successful;
- partially committing before a later operation fails.

The transition verifier inserts a correctness boundary between proposed writes and the canonical
ledger:

```text
untrusted or fallible proposer
        ↓
transition proposal
        ↓
isolated semantic replay
        ↓
computed delta + evidence/state checks
        ↓
accept / quarantine / human-review / reject
        ↓
trusted commit capability
        ↓
new canonical ledger prefix
```

A language model may propose a transition. It does not receive direct authority to append it.

## Trust boundary

`verifyTransition(...)` is a pure evaluator. It can produce a content-addressed verdict, but that
verdict alone is **not** commit authority.

`TransitionVerifier` is the trusted host capability:

```ts
const runtime = new TransitionVerifier(verifierIdentity, trustedPolicy);
const result = runtime.verify(kernel.events(), proposal);
const nextKernel = runtime.commit(kernel, result);
```

The runtime:

- canonicalizes and freezes its verifier identity and policy at construction;
- remembers the exact result objects it issued;
- refuses copied or independently manufactured result objects;
- checks that the result still matches its policy and verifier identity;
- checks the current canonical prefix again at commit time.

This is a process-local capability, not an operating-system sandbox or durable signature. The host
must keep the kernel and `TransitionVerifier` instance away from untrusted model/plugin code.
After a restart, a future durable implementation will need authenticated verifier identities and a
transactional persistence protocol rather than relying on the in-memory issuance capability.

## Proposal contract

A `TransitionProposal` declares:

- stable proposal id and proposer identity;
- exact base-ledger fingerprint;
- scopes the writer is authorized to touch;
- declared risk;
- whether authorized state should change;
- ordered canonical event operations;
- incoming evidence expected to be considered;
- explicit reasons for intentionally ignored input evidence;
- independent semantic/security checks;
- before/after state assertions;
- rationale.

The base fingerprint is a compare-and-swap precondition. Verification rejects a proposal prepared
against a different prefix, and commit rechecks the prefix so an intervening write cannot be lost.

## Atomic staging

The verifier reconstructs the base kernel, applies every proposed event to an isolated kernel, and
replays the same public write contract used by normal code.

If event 1 succeeds and event 2 fails:

```text
canonical kernel: unchanged
staged kernel: discarded
verdict: reject
```

An accepted result retains only the newly staged append, not a copy of the historical ledger. Commit
constructs a new kernel from:

```text
current canonical prefix + verified staged append
```

and verifies the resulting fingerprint. The caller's original kernel is never mutated.

## Deterministic checks

### Structural replay

The proposal must satisfy the canonical event schema, ordering, replay, provenance, scope, authority,
and lifecycle invariants already enforced by `MemoryKernel`.

### Risk computation

Risk is recomputed from operations rather than trusted from the proposer.

Examples:

- ordinary public evidence capture: `low`;
- derived, personal, tainted, association, or outcome writes: at least `medium` or `high`;
- active claims, admission, supersession, evidence restriction: `high`;
- claim revocation or evidence deletion: `destructive`.

Under-declaring risk is an error. Required external checks accumulate across all lower risk tiers.

### Coverage

Every declared input evidence object must be:

- available after staging;
- within an authorized scope;
- used by a proposed derived object/check; or
- explicitly ignored with a non-empty reason.

Every evidence object actually used by a write must also be declared as input. Newly captured evidence
must be included in the input set.

This establishes **mechanical coverage**. It cannot prove that the proposer discovered every
semantically relevant fact in a document; that stronger claim requires an independent
`semantic-coverage` check.

### Projection preservation

The verifier computes the exact before/after delta for:

- created evidence;
- evidence availability;
- created claims and final lifecycle;
- lifecycle changes to existing claims;
- associations;
- outcomes;
- touched scopes.

Unexpected projection mutations are rejected. This detects changes outside the explicit event
targets, but it is not a complete proof that every untouched belief should semantically remain
unchanged.

### State impact

State-affecting operations cannot declare `stateImpact: none`.

For `stateImpact: declared`, the verifier derives affected claim keys and requires state expectations
that cover the actual transition time. Assertions cannot:

- inspect an instant before the change;
- use a historical `knownAt` cutoff to hide staged writes;
- assert a different slot while leaving the affected key unchecked.

Expectations may require:

- an exact before/after state;
- preservation;
- a real state change.

`stateImpact: unknown` never auto-commits; it requires review and a better-specified proposal.

### Scope

Every touched scope must appear explicitly in `authorizedScopes`. `global` is not treated as an
implicit wildcard or free promotion target.

### Taint and sensitivity

Secret or sensitive capture dynamically requires a security check. Authoritative claims,
associations, and outcomes derived from prompt-like, untrusted, or secret-bearing evidence remain
quarantined unless a passing security check is present.

## External checks

Semantic claims cannot be proven by structure alone. A proposal may attach checks of type:

- `semantic-coverage`;
- `semantic-preservation`;
- `semantic-faithfulness`;
- `security`.

A passing check must have:

- a versioned verifier identity and configuration digest;
- a non-empty subject set that names the transition;
- a content-addressed report digest;
- available evidence explicitly used in the `verifies` role;
- evidence authority sufficient for the declared verifier;
- an actor independent from the proposer and derived-memory mutation actors.

The check report digest must match its verifying evidence. Merely supportive evidence cannot become a
verifier report.

These controls prevent accidental or obvious verifier laundering, but actor strings and evidence
authority are not yet cryptographically authenticated. A trusted host must construct or authorize
external checks; it must not accept arbitrary check metadata emitted by the same model that proposed
the write. Signed/attested checks remain a future production gate.

## Verdicts

### `accept`

No error remains, all required checks passed, no review gate remains, and no tainted authoritative
write requires quarantine. Only this verdict may commit.

### `quarantine`

The transition is structurally valid but an authoritative object is derived from tainted evidence
without the required security assurance. The result does not mutate memory. The caller must submit a
revised proposal, usually with the claim remaining quarantined or with an independent security check.

### `human-review`

The operation is too risky or insufficiently specified for automatic acceptance, for example:

- a required semantic/security check is absent;
- destructive risk lacks human approval;
- state impact is unknown.

The result does not commit automatically. Human review should produce a new evidence-backed proposal
or verifier result rather than editing the old verdict in place.

### `reject`

A structural, authority, scope, temporal, preservation, coverage, verification, or concurrency error
was found.

## Content addressing and audit

The verifier computes SHA-256 content addresses for:

- proposal;
- policy;
- result;
- base ledger;
- staged append;
- resulting ledger.

These digests make accidental mutation and mismatched artifacts detectable. They are **not digital
signatures** and do not identify who produced the bytes.

`TransitionAuditJournal` is an append-only, replay-validated record of verdict metadata. In v1 it is
separate from the memory ledger. A durable provider must atomically persist:

```text
accepted audit verdict + accepted memory append
```

or implement a recovery protocol that can prove which side committed.

## Resource bounds

The trusted policy limits:

- operations;
- authorized scopes;
- input/ignored evidence fan-in;
- external checks;
- state expectations;
- canonical proposal characters.

These limits reduce write storms and verification-time denial of service. They apply after the value
has entered the TypeScript API; a network/file host must also cap raw request bytes, parser depth,
artifact sizes, and request time before JSON parsing.

## Current limitations

The v1 implementation does not yet provide:

- authenticated actors, ACLs, signatures, or remote attestation;
- atomic durable commit of the audit journal and memory ledger;
- process-restart recovery of the in-memory verifier capability;
- automatic semantic verification without external evidence-backed checks;
- a guarantee that external report metadata faithfully describes report bytes;
- serializable per-belief partitions beyond whole-ledger fingerprint CAS;
- incremental fingerprints/checkpoints; verification currently replays the in-memory history;
- provenance-closure deletion across providers and learned parameters;
- public benchmark evidence for transition quality.

The implemented claim is narrower: the kernel enforces the tested deterministic transition contract
for an in-memory, trusted-host deployment.
