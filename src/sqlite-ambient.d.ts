declare module 'node:sqlite' {
  export interface StatementResultingChanges {
    readonly changes: number | bigint;
    readonly lastInsertRowid: number | bigint;
  }

  export interface StatementSync {
    all(...anonymousParameters: readonly unknown[]): readonly unknown[];
    get(...anonymousParameters: readonly unknown[]): unknown;
    run(...anonymousParameters: readonly unknown[]): StatementResultingChanges;
  }

  export interface DatabaseSyncOptions {
    readonly open?: boolean;
    readonly readOnly?: boolean;
    readonly enableForeignKeyConstraints?: boolean;
  }

  export class DatabaseSync {
    constructor(location: string, options?: DatabaseSyncOptions);
    exec(sql: string): void;
    prepare(sql: string): StatementSync;
    close(): void;
  }
}
