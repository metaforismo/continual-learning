# Non-executable procedure candidates

## Purpose

A memory can have:

```text
supported-positive paired utility
+
held-out validated applicability
```

without being safe to execute.

The next representation is therefore a **procedure candidate**, not a skill and not execution authority.

```text
paired utility evidence
        ↓
validated applicability hypothesis
        ↓
evidence-backed procedure candidate
        ↓
future canary gate
        ↓
future trusted procedure lifecycle
```

This layer closes the gap between “the memory helped under these features” and “here is the concrete behavior we propose testing.”

## Immutable non-authority

Every emitted object has:

```text
status = candidate
executable = false
```

No option can set those fields to `trusted` or `true`.

`canaryEligible` means only that the candidate cleared the static admission boundary. It does not authorize execution. A later canary controller must still supply sandboxing, traffic limits, current-state checks, approval policy, outcome verification, rollback, and monitoring.

## Required learning evidence

Creation accepts only process-issued capabilities:

- a `MemoryUtilityAssessment` with `status = supported-positive`;
- a `VerifiedApplicabilityHypothesis` with `status = validated`.

Both must refer to the same `memoryId` as the procedure candidate.

A structural clone with identical JSON is rejected. V1 capabilities are process-local and are not recoverable after restart without a future canonical re-admission protocol.

The candidate binds the utility assessment digest and applicability validation digest. Later lifecycle stages can therefore identify the exact learning evidence used at induction time.

## Exact canonical snapshot

The candidate is created against an exact canonical memory fingerprint.

Every evidence reference must still be:

- present in the canonical evidence projection;
- currently available;
- exact in source id, source groups, authority, and content digest;
- global or scope-compatible with the procedure;
- explicit about its use-site role.

A stale fingerprint or restricted/deleted source fails candidate creation rather than silently preserving an old instruction.

V1 recomputes the full canonical fingerprint, so creation remains `O(N)`.

## Step-level evidence

Every procedure step has:

```text
step id
instruction
evidence references
```

Each step requires at least one exact `EvidenceRef` whose explicit roles include:

```text
supports
or
verifies
```

`context` alone does not establish an instruction. `contradicts` cannot be used as support. The same evidence may support multiple steps, but every step must declare its own use-site relationship.

The candidate computes:

```text
source evidence ids
independent source groups
source authorities
taint union
maximum sensitivity
```

from the canonical records, not from caller-supplied summary fields.

## Definition

A candidate carries:

```text
stable procedure id
candidate version
name and goal signature
bounded rationale
ordered evidence-backed steps
tool dependencies
risk
verification contract
rollback target
validated applicability rule
learning-evidence digests
canonical evidence/provenance summary
```

Versions use a bounded semantic-version-like syntax.

## Applicability rule

The candidate copies the exact required/forbidden feature conjunction from the issued held-out validation.

V1 does not allow the candidate author to broaden, weaken, or reinterpret the rule while writing the steps. Any later change requires a new applicability hypothesis and candidate version.

## Verification contract

A candidate must declare:

```text
required verifier: tool | test | human
timeout
maximum attempts
failure action: disable | quarantine | human-review
success predicate identifier
```

The success predicate is a bounded identifier/contract name, not an arbitrary claim that the candidate succeeded.

The future canary layer must resolve that identifier to a registered verifier implementation and canonical outcome evidence.

## Rollback target

A candidate must define one rollback behavior:

```text
disable
```

or:

```text
procedure-version:
  procedure id
  earlier version
```

A candidate cannot roll back to its own version.

Rollback metadata is declarative in this layer; execution and verification arrive in the canary controller.

## Static canary blockers

The object is still emitted for inspection, but `canaryEligible = false` when static checks find conditions such as:

- fewer than two independent procedure-source groups;
- `prompt-like`, `untrusted-source`, or `secret-detected` evidence;
- personal, sensitive, or secret evidence in the default path;
- steps supported only by model-inference evidence;
- high/destructive risk without human-explicit evidence;
- high/destructive risk without a human verifier contract;
- high/destructive failure not routed to human review;
- destructive risk, which is never canary-eligible in v1.

These blockers do not erase the candidate or its evidence. They identify work required before experimentation.

## Why candidate evidence is separate from paired utility

Paired interventions can establish:

> applying memory M improved an outcome in contexts C

They do not necessarily establish:

> this exact newly written step sequence faithfully represents M

Step-level evidence closes part of that gap. A future transition verifier or human review must still check coverage, preservation, and semantic faithfulness between source experience, candidate steps, and executable implementation.

## Process-local issuance

Candidates are process-local capabilities. A cloned JSON object is not accepted by later lifecycle stages.

A durable candidate format will require:

- canonical schema-versioned bytes;
- exact utility/applicability references;
- evidence references and roles;
- actor and policy authentication;
- supersession and revocation;
- procedure-family version constraints;
- signed or trusted-host receipts.

## Complexity

```text
canonical replay/fingerprint: O(N)
evidence projection lookup:   O(N + references)
step validation:              O(steps + references)
```

V1 bounds:

```text
steps <= 64
instruction <= 2,000 characters
evidence refs per step <= 64
tool dependencies <= 64
```

No production-scale induction claim is made.

## Security boundary

The module does not provide:

- execution sandboxing;
- tool authorization;
- authenticated actors or reviewers;
- semantic proof that step text follows its sources;
- verifier registry resolution;
- current-state or premise checks at execution time;
- procedure conflict/composition analysis;
- canary traffic allocation;
- rollback execution;
- digital signatures or remote attestation.

An operator able to fabricate canonical evidence and issued learning capabilities can fabricate a candidate.

## Non-claims

This layer does not prove:

- trusted skill acquisition;
- safe autonomous execution;
- continual learning;
- infinite context;
- causal completeness;
- absence of negative transfer.

It establishes a narrower invariant:

> A concrete procedure cannot even enter the canary queue unless it is tied to process-issued positive utility, held-out validated applicability, exact canonical state, and evidence-backed steps; the emitted object remains explicitly non-executable.
