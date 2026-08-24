# Contributing

This is a research-first repository. Contributions should improve a clearly defined correctness, learning, evaluation, security, or scalability boundary.

## Development

```bash
npm install
npm test
```

Use Node.js 22 or newer.

## Pull requests

A pull request should include:

- the problem and failure mode;
- the invariant or hypothesis being changed;
- tests or an evaluation plan;
- compatibility and migration impact;
- security/privacy impact;
- documentation updates;
- explicit limitations.

Avoid architecture-by-feature-list. A new memory type, retriever, graph, or model call must explain which measurable failure it addresses and why a simpler mechanism is insufficient.

## Research results

Do not publish only aggregate headline scores. Include reproducible run manifests and preserve failed cases.
