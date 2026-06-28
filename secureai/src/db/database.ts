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

import { PersistenceError } from '../errors'

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
 * One statement in a {@link Database.batch}: a parameterized SQL string plus its
 * positionally-bound params. Mirrors the `(sql, params)` pair every other seam
 * method takes, so a builder can return one of these and the same SQL runs either
 * standalone (via {@link Database.execute}) or inside a batch.
 */
export interface BatchStatement {
  readonly sql: string
  readonly params: readonly unknown[]
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

  /**
   * Run several writes as ONE atomic batch (D1 wraps the list in a single
   * implicit transaction: sequential, all-or-nothing). Returns one
   * {@link WriteResult} per statement, in input order. Use this to collapse a
   * fixed set of independent writes (e.g. the per-scan metering + history + detail
   * inserts) into a single round trip with transactional integrity.
   *
   * @throws {PersistenceError} If the underlying batch rejects (nothing committed).
   */
  batch(statements: readonly BatchStatement[]): Promise<readonly WriteResult[]>
}

/**
 * A {@link Database} backed by a D1 read-replication SESSION. Identical surface,
 * plus {@link getBookmark} which surfaces the session's latest bookmark so a
 * caller can return it to the client for read-your-writes on the next request.
 */
export interface SessionDatabase extends Database {
  /** The session's current bookmark, or `null` if the driver exposes none yet. */
  getBookmark(): string | null
}

/**
 * The D1 surface the adapter calls — `prepare` + `batch` over prepared
 * statements. Declared structurally so the in-memory test fake (and a D1 session,
 * which has the same shape) both satisfy it.
 */
interface D1Runner {
  prepare(sql: string): { bind(...params: unknown[]): unknown }
  batch(statements: unknown[]): Promise<{ meta?: { changes?: number } }[]>
}

/**
 * The D1 binding's session entry point. `withSession` accepts a prior bookmark
 * (read-your-writes) or a constraint literal; the returned session is a runner
 * that also exposes `getBookmark()`.
 */
interface D1SessionCapable {
  withSession(constraint?: string): D1Runner & { getBookmark?: () => string | null }
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
  return makeDatabase(db as unknown as D1Runner)
}

/**
 * Adapt a D1 binding to a read-replication {@link SessionDatabase}. Reads may be
 * served by a replica while writes go to the primary; passing the client's prior
 * `bookmark` gives read-your-writes (that client always sees at least its own
 * latest write). A missing/blank bookmark falls back to `'first-unconstrained'`
 * (others may read a replica). After the request's writes, return
 * {@link SessionDatabase.getBookmark} to the client (see `db/bookmark.ts`).
 *
 * Time complexity: O(1) wrapper. Space complexity: O(1).
 *
 * @param db - The `env.DB` D1 binding (must support `withSession`).
 * @param bookmark - The caller's prior bookmark, or `null`/empty for none.
 * @returns A session-backed {@link SessionDatabase}.
 */
export function d1Session(db: D1Database, bookmark: string | null): SessionDatabase {
  const constraint =
    bookmark !== null && bookmark.trim().length > 0 ? bookmark : 'first-unconstrained'
  const session = (db as unknown as D1SessionCapable).withSession(constraint)
  const base = makeDatabase(session)
  return {
    ...base,
    getBookmark(): string | null {
      return typeof session.getBookmark === 'function' ? (session.getBookmark() ?? null) : null
    },
  }
}

/**
 * Build the {@link Database} surface over any D1 {@link D1Runner} — the raw
 * binding (plain reads/writes) or a session (read-replicated). Both expose the
 * same `prepare`/`batch`, so the five methods are identical; only how the runner
 * routes reads differs.
 *
 * Time complexity: O(1) wrapper overhead; query cost is the database's.
 * Space complexity: O(1).
 */
function makeDatabase(runner: D1Runner): Database {
  return {
    async queryOne(sql: string, params: readonly unknown[]): Promise<Row | null> {
      return (runner.prepare(sql).bind(...params) as D1PreparedStatement).first<Row>()
    },
    async queryAll(sql: string, params: readonly unknown[]): Promise<Row[]> {
      const result = await (runner.prepare(sql).bind(...params) as D1PreparedStatement).all<Row>()
      return result.results
    },
    async execute(sql: string, params: readonly unknown[]): Promise<WriteResult> {
      const result = await (runner.prepare(sql).bind(...params) as D1PreparedStatement).run()
      // D1 surfaces the affected-row count in `meta.changes`. Default to 0 so a
      // backend that omits it fails closed (treated as a no-op) rather than
      // falsely reporting a change.
      return { changes: result.meta.changes ?? 0 }
    },
    async batch(statements: readonly BatchStatement[]): Promise<readonly WriteResult[]> {
      // D1.batch runs the prepared list as one implicit transaction (atomic,
      // sequential). Wrap a rejection as a typed PersistenceError so callers can
      // tell a batch fault from a single-statement one; nothing committed on throw.
      const prepared = statements.map((statement) =>
        runner.prepare(statement.sql).bind(...statement.params),
      )
      let results: { meta?: { changes?: number } }[]
      try {
        results = await runner.batch(prepared)
      } catch (error: unknown) {
        throw new PersistenceError('database batch write failed', { cause: error })
      }
      return results.map((result) => ({ changes: result.meta?.changes ?? 0 }))
    },
  }
}
