# Roadmap

The roadmap is ordered by evidence dependency. Later phases must not be used to hide failures in earlier ones.

## Phase 0 — Foundational contracts (current)

- [x] initialize canonical append-only ledger;
- [x] strict JSON snapshot and replay model;
- [x] claim admission and quarantine;
- [x] bitemporal state resolution;
- [x] explicit supersession and revocation;
- [x] sparse associative activation;
- [x] fan-out inhibition;
- [x] bounded context compiler;
- [x] evidence-aware procedure promotion;
- [x] first deterministic tests and CI;
- [x] event-schema version header and fail-closed replay fixtures;
- [x] content-addressed evidence metadata plane and provenance DAG;
- [x] source-group, taint, authority, sensitivity, and scope inheritance;
- [x] evidence-backed claims, associations, and verified outcomes;
- [ ] concurrency/isolation contract;
- [ ] provenance-closure deletion model.

Exit gate: all Level 1 evidence requirements in [EVALUATION.md](EVALUATION.md).

## Phase 1 — Durable local memory substrate

- [x] crash-safe SQLite canonical event-byte ledger with event/receipt hash chains, transition audit, idempotent receipts, and whole-ledger cursor CAS;
- [x] rebuildable FTS5 lexical candidate projection with canonical rehydration;
- pluggable embedding interface and optional vector index;
- association and temporal indexes;
- hot/warm/cold storage boundaries;
- [x] configuration-bound projection watermarks, full manifests, atomic rebuild, and fork detection;
- [x] source/artifact content-addressing contract;
- artifact/blob provider with digest verification;
- [x] checkpointed FTS5 changed-row publication, exact-prefix verification, fixed bucket manifests, and hash-chained projection checkpoints;
- [x] evidence and transition metadata persistence through canonical event bytes;
- [x] bounded canonical change-feed consumption with verified restart checkpoints and stable range identities;
- [x] atomic registered projection-consumer transaction with configuration binding, exclusive SQL namespaces, revocable capabilities, receipts, and durable cursors;
- [x] FTS5 canonical change-feed consumer with incremental reverse-dependency updates, current-tail gating, privacy scrubbing, bucket integrity checks, and rebuild-required fallback;
- [x] canonical object-read index for selected evidence/claim rehydration with provenance, bitemporal versions, sparse integrity proofs, privacy overlays, and no lifetime-history scan on the selected-read path;
- [ ] externally authenticated projection-root commitment independent of the derived projection database;
- O(k) authenticated startup checkpoint/recovery without genesis replay;
- export, inspect, supersede, suppress, and forget APIs;
- [x] deterministic semantic replay, real-process crash recovery, and persisted corruption fixtures.

Exit gate: state and retrieval correctness remain stable while the dataset grows by several orders of magnitude.

## Phase 2 — Activation and context virtualization

- query/view classifier;
- scope router;
- multi-retriever candidate fusion;
- sparse spreading activation;
- competition, inhibition, diversity, and source-family collapse;
- hierarchical anchors and on-demand evidence expansion;
- token-aware packet compiler for multiple model templates;
- [x] typed retrieval/use traces with non-selection reasons at the experience-attribution boundary;
- synthetic million-event scale tests.

Exit gate: bounded p95 read/context cost and no material degradation on controlled interference suites.

## Phase 3 — State adjudication and trustworthy writes

- [x] typed static state slots and explicit domain policies;
- [x] bounded implicit invalidation search and transitive propagation;
- [x] `current / historical / disputed / unknown-current / unknown` state roles;
- [x] deterministic transition verifier for structural coverage, projection preservation, state assertions, and evidence-backed semantic checks;
- [x] role- and domain-specific authority policy;
- [x] deterministic policy execution after candidate extraction;
- [x] premise resistance and role-aware context packets;
- [ ] human review UI for high-impact ambiguity;
- [x] content-addressed process-local transition verdict journal;
- [x] atomic durable ledger + exact verifier verdict/audit/receipt commit;
- [ ] serializable per-belief partitions and authenticated judge identities;
- [ ] persisted, signed state-policy versions and migration fixtures.

Exit gate: strong current-state, historical-state, premise-resistance, and contamination results.

## Phase 4 — Experience and procedural learning

- [x] `experience-attribution-v1`: typed activation/materialization/consultation/application traces;
- [x] separate correlational trajectory evidence from paired causal intervention evidence;
- [x] verifier-bound treatment/control identity and experimental-unit checks;
- [x] order-independent source-family collapse and explicit conflicting-unit/family handling;
- [x] conservative positive/negative/mixed/neutral/insufficient utility assessment;
- [ ] durable authenticated recorder/controller identities and restart-safe attribution admission;
- [ ] randomized assignment and complete experiment registry preventing selective trial omission;
- [x] contextual applicability hypotheses with required and forbidden features;
- [x] pre-trial feature-schema binding and consistent unit/context manifests;
- [x] discovery/held-out validation separation with comparison, unit, and source-family non-overlap;
- [x] precision, recall, specificity, counterexample activation, and mean-effect validation gates;
- [x] provenance-complete procedure candidates with ordered typed steps and exact step-level canonical evidence;
- [x] immutable procedure-version identity plus evidence-bound dependencies, contraindications, verifier digest, risk, and rollback contract;
- [x] full discovery/held-out applicability lineage preserved inside the candidate without granting promotion or execution authority;
- [ ] procedure-specific counterexample search beyond inherited applicability evidence;
- [ ] contextual success/failure models beyond bounded conjunction rules;
- [ ] bounded non-executable canary plans with exact rollout-intent approval;
- [ ] complete canary trial registry, monotonic resource meter, and fail-safe reducer;
- [ ] procedure mixtures and conflict router;
- [ ] staged promotion, deprecation, supersession, revocation, and rollback.

Next gate: `verified-canary-plans-v1`. An exact procedure-candidate digest must remain non-executable while population, deterministic treatment/control assignment, budgets, sandbox/network/tool policy, stop rules, rollback coverage, verifier identity, independent review, and rollout-intent digest are bound into a bounded plan.

Exit gate: lower same-error recurrence and positive transfer on held-out tasks without increased negative transfer.

## Phase 5 — Learned memory controller

- offline dataset from replayable memory decisions;
- transparent heuristic baseline;
- learned store/retrieve/suppress/expand/consolidate policy;
- step-level transition rewards;
- counterfactual or paired memory ablations;
- conservative policy improvement;
- shadow mode, canary, and rollback;
- retention and continued-learnability evaluation.

Exit gate: the learned controller beats the deterministic controller on held-out task streams while preserving safety and cost constraints.

## Phase 6 — DeepSeek Harness integration

- host-level memory service plugin;
- session-event capture;
- pre-step activation and context injection;
- tool/result and verifier outcome capture;
- durable flush/checkpoint integration;
- memory management tools and UI;
- model/provider portability tests;
- profile/bundle distribution.

The adapter may begin earlier for experiments, but it is not allowed to define the core memory semantics.

## Phase 7 — Multi-agent and production scale

- shared versus private memory domains;
- actor trust and delegated write authority;
- multi-tenant encryption and isolation;
- backpressure, dead-letter queues, and idempotent workers;
- distributed index consistency;
- storage lifecycle and legal deletion;
- p99 latency and cost SLOs;
- adversarial red-team suite.

## Phase 8 — Optional parametric consolidation

- adapter/LoRA training from validated procedures;
- replay-interleaved continual training;
- capability-retention and deletion tests;
- adapter routing and rollback;
- proof that measured gains live in learned parameters rather than hidden retrieval.

This phase is deliberately last. Parametric updates amplify unresolved provenance, forgetting, privacy, and rollback problems.
