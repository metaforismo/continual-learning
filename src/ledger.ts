import type { MemoryEvent, MemoryEventInput } from './domain.js';

function cloneAndFreezeJson<T>(value: T, path = '$', ancestors = new WeakSet<object>()): T {
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
    if (ancestors.has(value)) throw new TypeError(`${path} cannot contain a circular reference`);
    ancestors.add(value);
    const cloned: unknown[] = [];
    for (let index = 0; index < value.length; index += 1) {
      if (!(index in value)) throw new TypeError(`${path} cannot contain a sparse array`);
      cloned.push(cloneAndFreezeJson(value[index], `${path}[${index}]`, ancestors));
    }
    ancestors.delete(value);
    return Object.freeze(cloned) as T;
  }

  if (typeof value === 'object') {
    if (ancestors.has(value)) throw new TypeError(`${path} cannot contain a circular reference`);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(`${path} must be a plain JSON object`);
    }

    ancestors.add(value);
    const cloned: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (item === undefined) {
        throw new TypeError(`${path}.${key} cannot be undefined`);
      }
      cloned[key] = cloneAndFreezeJson(item, `${path}.${key}`, ancestors);
    }
    ancestors.delete(value);
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
    // Snapshot once before validation. This prevents stateful getters from presenting one value
    // to validation and another value to storage.
    const event = cloneAndFreezeJson({
      ...input,
      seq: this.#events.length + 1,
    }) as MemoryEvent;

    if (event.id.trim().length === 0) {
      throw new TypeError('event id cannot be empty');
    }
    if (this.#ids.has(event.id)) {
      throw new Error(`duplicate event id: ${event.id}`);
    }
    if (!Number.isFinite(event.recordedAt)) {
      throw new TypeError('recordedAt must be a finite Unix epoch millisecond value');
    }
    const latest = this.#events.at(-1);
    if (latest !== undefined && event.recordedAt < latest.recordedAt) {
      throw new RangeError('recordedAt must be monotonic within one canonical ledger');
    }
    if (event.actor.trim().length === 0) {
      throw new TypeError('actor cannot be empty');
    }

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
