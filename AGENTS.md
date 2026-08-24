# Repository instructions for coding agents

## Source of truth

Inspect the current repository, branch, pull requests, workflows, tests, and recent commits before making changes. Do not rely on stale handoffs.

## Scientific boundary

- Persistent memory is not automatically continual learning.
- Do not claim infinite context, solved continual learning, human-like memory, or benchmark superiority without the corresponding evidence level.
- Distinguish implemented code, tested invariant, benchmark result, hypothesis, and long-term ambition.
- Preserve negative results and failure evidence.

## Architectural invariants

- Canonical experience history is append-only.
- Derived state, indexes, summaries, outcomes, associations, and procedures must preserve exact provenance.
- Evidence identity, authority, scope, source groups, taint, sensitivity, and digest cannot be invented by a derived object.
- Evidence role and evidence authority are separate dimensions; supportive or contextual evidence is not verification.
- Do not destructively replace raw episodes with summaries.
- Raw sensitive bytes stay outside the immutable event log; metadata and tombstones remain auditable.
- Retrieval does not imply authorization.
- State adjudication is deterministic at the correctness boundary; models may propose candidates but do not silently choose current truth.
- Current, historical, disputed, unknown-current, and unknown state must remain distinguishable.
- Ineligible claims must not affect ranking, confidence, invalidation, or context provenance indirectly.
- A same-value reaffirmation is not a state transition unless a rule explicitly declares a `new-claim` trigger.
- Ambiguity and unknown-current are legal outcomes.
- Unverified model inference must not silently become authoritative state.
- Repeated copies, chunks, retries, and summaries of one origin do not count as independent evidence.
- Learned procedures require applicability boundaries and counterexamples.
- Activation, state adjudication, and model-context materialization remain separate stages.
- Model-facing state packets require provenance closure by default.
- All learned behavior must be inspectable, suppressible, and testable.

## Engineering

- Use strict TypeScript and keep the core free of model, database, and harness dependencies.
- Prefer pure functions and deterministic state projections for correctness boundaries.
- Runtime-validate public discriminants and policy enums; TypeScript types alone do not protect replayed JSON.
- Add focused tests for every invariant and regression, including negative and indirect-influence cases.
- Keep README, architecture, failure modes, evaluation, and roadmap aligned with reality.
- Use isolated branches and pull requests for nontrivial work.
- Do not merge merely to show progress when verification gates are not satisfied.
- Avoid hidden network calls, telemetry, or persistent personal-data capture.

## Verification

Run at minimum:

```bash
npm test
```

For benchmark work, store a machine-readable run manifest with commit, data/model versions, prompts, seeds, budgets, costs, and raw results.
