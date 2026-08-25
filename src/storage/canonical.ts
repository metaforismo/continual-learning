import { createHash } from 'node:crypto';

import type { MemoryEvent } from '../domain.js';

export const SHA256_CONTENT_ADDRESS = /^sha256:[0-9a-f]{64}$/;

export const EVENT_CHAIN_GENESIS = sha256Text('continual-learning:event-chain:v1');
export const RECEIPT_CHAIN_GENESIS = sha256Text('continual-learning:receipt-chain:v1');

export function canonicalJson(
  value: unknown,
  path = '$',
  ancestors = new WeakSet<object>(),
): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      throw new TypeError(`${path} must contain only finite JSON numbers`);
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (ancestors.has(value)) throw new TypeError(`${path} cannot contain a circular reference`);
    ancestors.add(value);
    const items: string[] = [];
    for (let index = 0; index < value.length; index += 1) {
      if (!(index in value)) throw new TypeError(`${path} cannot contain a sparse array`);
      items.push(canonicalJson(value[index], `${path}[${index}]`, ancestors));
    }
    ancestors.delete(value);
    return `[${items.join(',')}]`;
  }
  if (typeof value === 'object') {
    if (ancestors.has(value)) throw new TypeError(`${path} cannot contain a circular reference`);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(`${path} must be a plain JSON object`);
    }
    ancestors.add(value);
    const objectValue = value as Record<string, unknown>;
    const entries = Object.keys(objectValue)
      .sort()
      .map((key) => {
        const item = objectValue[key];
        if (item === undefined) throw new TypeError(`${path}.${key} cannot be undefined`);
        return `${JSON.stringify(key)}:${canonicalJson(item, `${path}.${key}`, ancestors)}`;
      });
    ancestors.delete(value);
    return `{${entries.join(',')}}`;
  }
  throw new TypeError(`${path} contains a non-JSON value`);
}

export function sha256Text(value: string): string {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

export function digestCanonical(value: unknown): string {
  return sha256Text(canonicalJson(value));
}

export function eventDigest(event: MemoryEvent): string {
  return digestCanonical(event);
}

export function nextEventChainDigest(previousDigest: string, event: MemoryEvent): string {
  if (!SHA256_CONTENT_ADDRESS.test(previousDigest)) {
    throw new Error('previous event-chain digest is malformed');
  }
  return sha256Text(`continual-learning:event-chain:v1\n${previousDigest}\n${eventDigest(event)}`);
}

export function nextReceiptChainDigest(
  previousDigest: string,
  auditRecordDigest: string,
): string {
  if (!SHA256_CONTENT_ADDRESS.test(previousDigest)) {
    throw new Error('previous receipt-chain digest is malformed');
  }
  if (!SHA256_CONTENT_ADDRESS.test(auditRecordDigest)) {
    throw new Error('audit-record digest is malformed');
  }
  return sha256Text(
    `continual-learning:receipt-chain:v1\n${previousDigest}\n${auditRecordDigest}`,
  );
}

export function canonicalValuesEqual(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right);
}
