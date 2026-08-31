# Canonical canary receipt review evidence

Before publication, the canonical canary receipt and outcome tranche was checked from a clean worktree with:

- TypeScript build;
- dedicated adversarial receipt and outcome tests;
- the complete repository test suite;
- complete patch whitespace validation;
- production dependency audit;
- an independent adversarial review with authority to block publication.

The review targeted frozen treatment/control assignment, privacy-preserving subject identities, temporal and current-privacy evidence checks, exact runtime and verifier identity, terminal-state consistency, missing monitor coverage, threshold direction and units, safety/security rollback triggers, authoritative rollback completion, negative-transfer visibility, incidents, aborts, rollback failures, uncertainty, atomic logical identities, and the absence of implicit promotion, scheduling, or execution authority.

A follow-up adversarial probe found and closed a split-evidence laundering path: an exact external digest from a foreign source family could previously be paired with unrelated decoy evidence from the planned family. Every scheduler, harness-bound runner, observer, verifier, and rollback receipt now requires the exact digest-bearing binding itself to preserve source-family continuity.

A second probe found that planned component identity evidence could otherwise be reused directly as an external action receipt by setting both digests equal. Admission, execution grant, completion, observation, rollback, and outcome verification now require the external action digest to differ from the relevant component identity digest.

The same review also tightened canonical outcome binding to the exact canary procedure ID and population manifest, and rejects `none` or model-only verifier classifications even when stronger evidence is supplied separately.

Retry ordering was hardened independently: attempt `N` cannot be admitted until attempt `N - 1` exists and has a guarded completion receipt, preventing skipped or overlapping retries for one subject.

Runtime input review also added exact-key validation for every receipt request and nested runner identity, so undeclared authority-like fields cannot be ignored silently. The verified outcome receipt now retains the accepted external verifier classification.

Verifier-class review prevents label laundering: a canonical outcome labeled `human` now requires the exact external verification digest itself to carry `human-explicit` authority. Tool evidence cannot borrow a human label from event metadata.

The resource-meter review also corrected `maxToolCalls` to operate as a cumulative plan budget. Per-run and cumulative tool-call counts are both retained, and exact completion retries reuse their original pre-completion meter state.

Those process-local exact retries remain bound to the original canonical snapshot. Retrying after unrelated canonical tail advancement is deliberately not claimed as v1 idempotency and is deferred to a durable registry boundary.

Complete-prefix review also closed an exhaustion edge: observation admission now stops before a metric can exceed the evaluator's count or canonical-ID representation bounds. The API cannot first accept a prefix that its own stop evaluator can never represent.

GitHub CI on the exact connector-authored head and fresh post-merge verification on `main` remain mandatory gates.
