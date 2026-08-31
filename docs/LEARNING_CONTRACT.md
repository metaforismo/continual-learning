# Continual-learning contract

This project uses a stronger definition of learning than "the agent can recall an old fact."

## Terms

### Memory

The ability to preserve and later recover information from prior experience.

### Adaptation

A change in current behavior caused by retrieved state, instructions, examples, or an updated controller.

### Continual learning

A persistent improvement in the agent's policy or competence from an ongoing stream of experience, demonstrated on held-out tasks while preserving previously acquired capabilities and the capacity to learn further tasks.

A system does not satisfy this definition merely because it:

- stores all transcripts;
- retrieves a fact stated earlier;
- adds a rule to a Markdown file;
- repeats a correction inside a prompt;
- fine-tunes once on a static dataset;
- performs better when the exact successful trajectory is replayed.

## Required properties

A candidate continual-learning system must demonstrate all of the following.

### 1. Plasticity

New evidence or verified feedback changes future behavior where it should.

### 2. Stability

Learning a later task does not materially erase earlier validated capabilities.

### 3. Transfer

A learned procedure improves performance on new instances not present in the original episodes.

### 4. Applicability control

The system learns when a procedure applies and when it does not. A rule without boundary conditions is not a skill; it is a contamination risk.

### 5. State currency

When facts change, current-state actions use the valid replacement while historical queries can still recover the old state.

### 6. Evidence preservation

Learned abstractions never destroy the raw episodes and sources needed to audit, repair, or reconsolidate them.

### 7. Causal usefulness

Improvement must be attributable to the memory or learned policy. Correlation between retrieval and success is insufficient.

### 8. Bounded operation

Read cost, write cost, and model-context cost must remain controlled as total history grows.

### 9. Reversibility

A harmful memory, procedure, controller update, or adapter must be suppressible or rolled back without reconstructing the whole agent.

### 10. Continued learnability

After many updates, the system must retain the ability to acquire another new task. A frozen archive with perfect recall is not continual learning.

## Procedure-candidate boundary

A validated applicability rule is evidence about *when* a memory helped. It is not yet an
executable skill. Procedural learning must pass through a separate typed candidate that preserves
the held-out boundary and binds ordered steps, dependencies, contraindications, risk, verification,
and rollback to exact canonical evidence.

Even a provenance-complete candidate remains:

```text
status = candidate
executable = false
procedurePromotionAuthorized = false
canaryPlanAuthorized = false
executionAuthorized = false
```

Canary planning, lifecycle trust, activation, and harness execution are separate claims and require
separate evidence.

## Measurement

For task family `A`, followed by learning streams `B ... Z`, report at minimum:

```text
A_before_learning
A_after_learning
A_after_B_to_Z
transfer_to_unseen_A
error_recurrence_after_correction
next_task_learning_rate
memory_read/write/context cost
```

The key retention quantity is:

```text
retention(A) = performance(A after B...Z) / performance(A after learning A)
```

The key recurrence quantity is:

```text
ERR = P(repeat the same failure | the failure was previously corrected and applicable)
```

A credible system should improve transfer and lower `ERR` without hiding regressions through growing context or selective reporting.

## Learning levels

The architecture recognizes four levels:

1. **episodic learning** — remember what happened;
2. **associative learning** — learn which prior states tend to matter together;
3. **procedural learning** — learn a strategy and its applicability conditions;
4. **parametric learning** — update a learned controller, adapter, fast weights, or model weights.

The first research target is reliable levels 1–3. Level 4 is optional and cannot bypass the same evaluation, provenance, rollback, and privacy requirements.
