/**
 * The narrow persistence seam the accounts layer is written against.
 *
 * The repositories in `db/accounts.ts` and `db/usage.ts` depend only on this
 * {@link Database} interface — never on the concrete `D1Database` binding — so
 * the whole accounts layer is testable under the Node test runtime with an
 * in-memory fake, with no `@cloudflare/vitest-pool-workers` dependency.
 *
 * The surface is deliberately tiny: a parameterized `queryOne` (read a single
 * row) and a parameterized `execute` (run a write). Everything the repos need
 * — `INSERT ... ON CONFLICT DO UPDATE` upserts, joined reads, tier updates —
 * composes from these two primitives.
 */

/** A single row read back from the database, column name → value. */
export type Row = Record<string, unknown>

/**
 * Minimal database surface used by the accounts and usage repositories.
 *
 * Implementations bind `params` positionally to the `?` placeholders in `sql`,
 * exactly matching D1's prepared-statement semantics.
 */
export interface Database {
  /**
   * Run a read query expected to return at most one row.
   *
   * @returns The first matching row, or `null` when the query matched nothing.
   */
  queryOne(sql: string, params: readonly unknown[]): Promise<Row | null>

  /**
   * Run a write (INSERT / UPDATE / upsert). The result is intentionally not
   * surfaced — callers that need a row back read it separately, keeping the
   * seam minimal.
   */
  execute(sql: string, params: readonly unknown[]): Promise<void>
}

/**
 * Adapt a Cloudflare {@link D1Database} binding to the narrow {@link Database}
 * seam. Each call prepares, binds, and runs a single statement; D1 already
 * pools connections, so there is no per-call setup cost beyond the prepare.
 *
 * Time complexity: O(1) wrapper overhead; query cost is the database's.
 * Space complexity: O(1).
 *
 * @param db - The `env.DB` D1 binding.
 * @returns A {@link Database} backed by `db`.
 */
export function d1Database(db: D1Database): Database {
  return {
    async queryOne(sql: string, params: readonly unknown[]): Promise<Row | null> {
      return db
        .prepare(sql)
        .bind(...params)
        .first<Row>()
    },
    async execute(sql: string, params: readonly unknown[]): Promise<void> {
      await db
        .prepare(sql)
        .bind(...params)
        .run()
    },
  }
}
