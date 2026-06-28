/**
 * The narrow persistence seam the accounts layer is written against.
 *
 * The repositories in `db/accounts.ts` and `db/usage.ts` depend only on this
 * {@link Database} interface — never on the concrete `D1Database` binding — so
 * the whole accounts layer is testable under the Node test runtime with an
 * in-memory fake, with no `@cloudflare/vitest-pool-workers` dependency.
 *
 * The surface is deliberately tiny: a parameterized `queryOne` (read a single
 * row), a parameterized `queryAll` (read many rows, for the stats range read),
 * and a parameterized `execute` (run a write). Everything the repos need
 * — `INSERT ... ON CONFLICT DO UPDATE` upserts, joined reads, range reads, tier
 * updates — composes from these primitives.
 */

/** A single row read back from the database, column name → value. */
export type Row = Record<string, unknown>

/**
 * The outcome of a write. `changes` is the number of rows the statement
 * actually mutated — the load-bearing field for idempotency: an
 * `INSERT ... ON CONFLICT DO NOTHING` reports 0 on a conflict and 1 on a fresh
 * insert, so a duplicate can be detected without a follow-up read.
 */
export interface WriteResult {
  readonly changes: number
}

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
   * Run a read query that may return many rows (e.g. a `(subject, day)` range
   * read for protection stats).
   *
   * @returns Every matching row in query order, or `[]` when none matched.
   */
  queryAll(sql: string, params: readonly unknown[]): Promise<Row[]>

  /**
   * Run a write (INSERT / UPDATE / upsert). Returns the row-change count so
   * idempotency gates (e.g. `ON CONFLICT DO NOTHING`) can detect a no-op
   * without a follow-up read. Callers that do not need it simply ignore it.
   */
  execute(sql: string, params: readonly unknown[]): Promise<WriteResult>
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
    async queryAll(sql: string, params: readonly unknown[]): Promise<Row[]> {
      const result = await db
        .prepare(sql)
        .bind(...params)
        .all<Row>()
      return result.results
    },
    async execute(sql: string, params: readonly unknown[]): Promise<WriteResult> {
      const result = await db
        .prepare(sql)
        .bind(...params)
        .run()
      // D1 surfaces the affected-row count in `meta.changes`. Default to 0 so a
      // backend that omits it fails closed (treated as a no-op) rather than
      // falsely reporting a change.
      return { changes: result.meta.changes ?? 0 }
    },
  }
}
