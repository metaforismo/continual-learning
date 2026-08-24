# DeepSeek Harness integration plan

DeepSeek Harness is a suitable runtime host because models, tools, sessions, storage, loops, skills, subagents, and UI are composed as plugins, and model-visible state is derived from an append-only session event stream.

This project should integrate as an out-of-tree plugin/bundle, not as a long-lived fork of the Harness core.

## Boundary

```text
DeepSeek Harness owns:
- agent lifecycle
- model adapters
- tools and sandboxes
- session event capture
- subagents/workflows/goals
- UI/runtime composition

Continual Learning owns:
- canonical cross-session experience model
- claim admission and state adjudication
- activation and context compilation
- procedure learning and outcome credit
- memory-controller training/evaluation
```

## Proposed capability seam

A future adapter should expose a model-neutral service similar to:

```ts
interface MemoryService {
  capture(input: EvidenceInput): Promise<CaptureReceipt>
  propose(input: MemoryProposal): Promise<ProposalReceipt>
  adjudicate(ref: ProposalRef): Promise<AdjudicationResult>
  activate(query: ActivationRequest): Promise<ActivatedSet>
  compile(request: ContextRequest): Promise<CompiledMemoryContext>
  expand(id: MemoryId, request: ExpansionRequest): Promise<MemoryPacket[]>
  recordOutcome(input: OutcomeInput): Promise<void>
  inspect(id: MemoryId): Promise<MemoryAuditView>
  supersede(input: SupersessionInput): Promise<void>
  suppress(input: SuppressionInput): Promise<void>
  forget(input: ForgetRequest): Promise<ForgetReceipt>
}
```

The core package must remain usable without Cordis or DeepSeek Harness. The DSH package adapts the service to the runtime.

## Event mapping

### Session events -> evidence capture

Capture durable, model-visible facts after they enter the DSH session log. Avoid indexing transient in-process objects as canonical memory.

Potential inputs:

- user and assistant surface messages;
- tool calls and results;
- request headers and model provenance;
- compaction checkpoints;
- goal and workflow lifecycle records;
- source/artifact references;
- human message feedback.

The adapter must filter its own injected memory packets to prevent recursive writeback.

### `agent/pre-step` -> activation and injection

Before request derivation:

1. infer query view and scope;
2. activate memory ids;
3. adjudicate current state;
4. compile a bounded packet set;
5. inject one identified, replayable context message;
6. log the exact memory ids, versions, scores, and reasons behind the injection.

No hidden side channel should influence the model. Model-visible means reconstructable from durable records.

### Tool/result and verifier events -> outcomes

A completed tool call is not automatically a successful task. Outcome capture should use task-specific verifiers, tests, environment state, human feedback, or explicit goal completion evidence.

### `session/flush` -> durability boundary

The adapter should drain accepted capture events and checkpoints at an awaited flush boundary, with bounded network wait and a persistent retry/dead-letter path. Memory service failure should not corrupt the DSH session log.

## Suggested packages

```text
packages/core                 Cordis-free domain and invariants
packages/storage-sqlite       local durable provider
packages/retrieval            lexical/vector/graph adapters
packages/controller           activation and learned policy
packages/evals                datasets, runners, manifests
packages/dsh-service          host memory service plugin
packages/dsh-tools            inspect/search/expand/forget tools
packages/dsh-ui               memory and learning inspector
packages/dsh-bundle           installable profile layer
```

## Model-facing tools

Keep the initial tool surface small and explicit:

```text
memory_search
memory_expand
memory_evidence
memory_history
memory_explain
```

Model-initiated write tools should be separated from read tools and remain proposal-oriented:

```text
memory_propose
memory_propose_supersession
memory_report_outcome
```

A model should not receive an unrestricted `delete truth` primitive.

## Prompt contribution

The always-on prompt contribution should contain only:

- memory policy;
- tool availability;
- current state basis within a strict budget;
- unresolved high-impact ambiguity;
- provenance identifiers.

Do not inject an ever-growing user profile or skill catalog in full. Use progressive disclosure.

## Compatibility strategy

DeepSeek Harness is in developer preview, so the adapter must:

- pin exact compatible versions;
- isolate all DSH imports in adapter packages;
- keep contract tests against real DSH profiles;
- verify model-visible injection replay;
- avoid patching `AgentLoop`;
- fail closed on unsupported event/schema versions;
- publish a compatibility matrix.
