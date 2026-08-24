import type { MemoryEvent, MemoryEventInput } from './domain.js';

function cloneAndFreezeJson<T>(value: T, path = '$'): T {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }

  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      throw new TypeError(`${path} must contain only finite JSON numbers`);
    }
    return value;
  }

  if (Array.isArray(value)) {
    const cloned = value.map((item, index) => cloneAndFreezeJson(item, `${path}[${index}]`));
    return Object.freeze(cloned) as T;
  }

  if (typeof value === 'object') {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(`${path} must be a plain JSON object`);
    }

    const cloned: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (item === undefined) {
        throw new TypeError(`${path}.${key} cannot be undefined`);
      }
      cloned[key] = cloneAndFreezeJson(item, `${path}.${key}`);
    }
    return Object.freeze(cloned) as T;
  }

  throw new TypeError(`${path} contains a non-JSON value`);
}

/**
 * Canonical append-only event ledger.
 *
 * Derived memories, indexes, summaries, and skill views are projections. The ledger is the
 * only authoritative history, so replay must produce the same state after a process restart.
 */
export class EventLedger {
  readonly #events: MemoryEvent[] = [];
  readonly #ids = new Set<string>();

  append(input: MemoryEventInput): MemoryEvent {
    if (input.id.trim().length === 0) {
      throw new TypeError('event id cannot be empty');
    }
    if (this.#ids.has(input.id)) {
      throw new Error(`duplicate event id: ${input.id}`);
    }
    if (!Number.isFinite(input.recordedAt)) {
      throw new TypeError('recordedAt must be a finite Unix epoch millisecond value');
    }
    if (input.actor.trim().length === 0) {
      throw new TypeError('actor cannot be empty');
    }

    const event = cloneAndFreezeJson({
      ...input,
      seq: this.#events.length + 1,
    }) as MemoryEvent;

    this.#events.push(event);
    this.#ids.add(event.id);
    return event;
  }

  all(): readonly MemoryEvent[] {
    return Object.freeze([...this.#events]);
  }

  throughTransactionTime(knownAt: number): readonly MemoryEvent[] {
    if (!Number.isFinite(knownAt)) {
      throw new TypeError('knownAt must be finite');
    }
    return Object.freeze(this.#events.filter((event) => event.recordedAt <= knownAt));
  }

  get size(): number {
    return this.#events.length;
  }
}
