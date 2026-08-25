declare module 'node:crypto' {
  interface Hash {
    update(data: string): Hash;
    digest(encoding: 'hex'): string;
  }

  export function createHash(algorithm: 'sha256'): Hash;
}

declare module 'node:sqlite' {
  export interface StatementSync {
    run(...params: (string | number | bigint | null)[]): unknown;
    get(...params: (string | number | bigint | null)[]): unknown;
    all(...params: (string | number | bigint | null)[]): readonly unknown[];
  }

  export class DatabaseSync {
    constructor(location: string);
    exec(sql: string): void;
    prepare(sql: string): StatementSync;
    close(): void;
  }
}
