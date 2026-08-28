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
- Retrieval indexes are rebuildable caches, never canonical truth. Search results must be canonically rehydrated before context or action.
- Cache generations are publication metadata, not epistemic state. Unchanged rows may retain an older last-modified generation.
- Canonical rehydration must remain possible without trusting or reopening the disposable retrieval cache.
- Retriever ranks and scores are advisory candidate-routing signals, not evidence authority or state truth.
- A retrieval miss is not evidence of absence; exhaustive claims require an explicit coverage protocol.
- Transaction lifecycle (`active` or `superseded`) is not a substitute for bitemporal state adjudication.
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
- Model- or plugin-proposed memory operations must pass a trusted-host `TransitionVerifier`; do not append them directly.
- A pure transition verdict is not commit authority; only the owning verifier runtime may commit its exact accepted result.
- New durable canonical writes require both an exact ledger-issued cursor and the exact accepted result issued by the configured verifier runtime. Matching JSON is not authority.
- Canonical event bytes, event-chain advancement, transition audit, idempotency receipt, receipt-chain advancement, and cursor publication must commit atomically.
- Exact idempotent retries may cross restart only after the complete durable event/receipt/audit history verifies.
- Raw SQLite text used for canonical identity or integrity must be checked at the byte level; decoded string equality is insufficient.
- The canonical SQLite ledger is not a rebuildable cache. Never reset or repair it silently after schema, byte, chain, or semantic corruption.
- New change-feed consumers start at genesis unless tail skipping is explicit; an omitted checkpoint must never silently discard history.
- Change-feed batch identity is bound to the exact canonical range, not to a later tail observation, so exact retry remains stable.
- Projection consumers require a durable configuration digest and explicit initial cursor before the first batch.
- Projection mutation, consumer receipt, and consumer cursor must commit atomically; async callbacks and reentrant feed mutation are forbidden.
- Trusted projection callbacks use the restricted projection transaction only; raw connection access, transaction control, PRAGMAs, catalog access, and `cl_consumer_*` SQL are forbidden.
- External checks are untrusted metadata unless the host has authenticated or independently authorized the verifier/evidence path.
- Transition proposals must remain within policy resource bounds and exact authorized scopes.
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
