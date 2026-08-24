declare module 'node:crypto' {
  interface Hash {
    update(data: string): Hash;
    digest(encoding: 'hex'): string;
  }

  export function createHash(algorithm: 'sha256'): Hash;
}

/**
 * TypeScript's standard `Object.freeze(arrayLiteral)` overload widens string literals to
 * `readonly string[]`. Preserve readonly tuple literals so frozen configuration arrays remain
 * assignable to their declared discriminated-union types without runtime casts.
 */
interface ObjectConstructor {
  freeze<const T extends readonly unknown[]>(value: T): Readonly<T>;
}
