# Research basis

This is a living map of research informing the design. Inclusion does not mean the repository has reproduced a result or adopted every mechanism.

## Agent harness substrate

### DeepSeek Harness

- Site: https://deepseek.com/harness/en/
- Repository: https://github.com/deepseek-ai/deepseek-harness
- Architecture: https://deepseek-harness.github.io/deepseek-harness/en/reference/

Relevant ideas:

- capabilities as replaceable plugins;
- append-only session events as the source of model-visible history;
- replay, fork, compaction, tools, subagents, workflows, and skills as runtime seams;
- an integration path that does not require patching the core loop.

### Cordis and spatiotemporal composability

- Paper/repository: https://github.com/cordiverse/paper
- Framework: https://github.com/cordiverse/cordis

Relevant ideas:

- reversible component effects;
- dynamic dependency composition;
- runtime replacement of memory, retrieval, controller, and storage providers.

## Human learning and memory

### Complementary Learning Systems

- McClelland, McNaughton, and O'Reilly (1995): https://web.stanford.edu/~jlmcc/papers/McCMcNaughtonOReilly95.pdf
- O'Reilly et al. review (2014): https://ccnlab.org/papers/OReillyBhattacharyyaHowardEtAl14.pdf

Relevant computational principle:

- fast, pattern-separated episodic storage and slow, interleaved generalization solve different optimization problems;
- rapid learning and stable abstraction should not be collapsed into one continuously rewritten textual memory.

The project uses this as design inspiration, not as a claim of neural fidelity.

## Current agent-memory failure evidence

### Useful Memories Become Faulty When Continuously Updated by LLMs

- https://arxiv.org/abs/2605.12978

Design consequence:

- preserve raw episodes;
- gate consolidation;
- do not assume every rewrite is neutral or beneficial;
- evaluate update order and grouping sensitivity.

### STALE: Can LLM Agents Know When Their Memories Are No Longer Valid?

- https://arxiv.org/abs/2605.06527

Design consequence:

- retrieving the update is not enough;
- current-state adjudication, premise resistance, and downstream policy adaptation are separate boundaries;
- invalidation may propagate beyond the directly changed slot.

### MINTEval

- https://arxiv.org/abs/2605.18565

Design consequence:

- evaluate multi-target aggregation, repeated revisions, distant lookback, and interference rather than static one-fact recall;
- decompose memory-construction errors from answer-use errors.

### Reliable Post-Retrieval Assembly for Agent Memory

- https://arxiv.org/abs/2606.01435

Design consequence:

- separate semantic evidence extraction from deterministic or typed policy execution;
- do not ask one free-text generation pass to retrieve, filter, resolve freshness, suppress priors, and answer simultaneously.

### TOKI

- https://arxiv.org/abs/2606.06240

Design consequence:

- treat contradiction resolution as a versioned write/concurrency problem;
- preserve losing claims in audit history;
- log adjudicator configuration and verdicts for replay consistency.

### TRUSTMEM

- https://arxiv.org/abs/2606.25161

Design consequence:

- evaluate each memory transition for coverage, preservation, and faithfulness;
- use local transition signals rather than only terminal task reward.

### Supersede

- https://arxiv.org/abs/2606.27472

Design consequence:

- memory size and model size alone do not guarantee correct state currency;
- a trainable memory-update policy and dedicated reward are plausible research targets.

## Learned memory management

### Agentic Memory / AgeMem

- https://aclanthology.org/2026.acl-long.981/

Design consequence:

- long- and short-term memory operations can be part of a learned agent policy;
- progressive and step-level rewards are useful baselines for a future controller.

### Memory-R1

- https://aclanthology.org/2026.acl-long.583/

Design consequence:

- separate memory-manager and answer-use policies;
- compare learned ADD/UPDATE/DELETE/NOOP behavior against deterministic baselines.

## Research stance

The repository deliberately combines ideas only after decomposing their failure boundaries. More subsystems are not automatically better. Every graph, hierarchy, retriever, controller, and consolidation model must justify itself through ablations against simpler baselines.
