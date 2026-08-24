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
- Derived state, indexes, summaries, and procedures must preserve provenance.
- Do not destructively replace raw episodes with summaries.
- Retrieval does not imply authorization.
- Current and historical state must remain distinguishable.
- Ambiguity and unknown-current are legal outcomes.
- Unverified model inference must not silently become authoritative state.
- Repeated copies of one source do not count as independent evidence.
- Learned procedures require applicability boundaries and counterexamples.
- Activation and model-context materialization remain separate stages.
- All learned behavior must be inspectable, suppressible, and testable.

## Engineering

- Use strict TypeScript and keep the core free of model, database, and harness dependencies.
- Prefer pure functions and deterministic state projections for correctness boundaries.
- Add focused tests for every invariant and regression.
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
