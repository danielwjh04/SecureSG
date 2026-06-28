/**
 * Structured, leveled logging for SecureAI. Every log is one JSON line
 * (`{ts, level, module, msg, ...fields}`), so Cloudflare Workers Logs indexes the
 * fields and an operator can filter by `module`/`level` instead of grepping prose.
 *
 * Request correlation: rather than thread a request id through every call site,
 * each log relies on the per-invocation id Workers Logs already attaches (the
 * `cf-ray`, also echoed as the `x-request-id` response header by the worker
 * entry). {@link createLogger} can still bind a `requestId` (or any base fields)
 * for a scoped logger.
 *
 * PII discipline (CLAUDE.md §6): {@link LogFields} is SCALAR-ONLY, so it is a
 * COMPILE error to pass a result object, request body, or array — structurally
 * preventing content/PII from leaking into a log. Keep `msg` static; never
 * interpolate user content. Errors are logged by CLASS via {@link errorClassOf},
 * never by message (which can carry input).
 */

/** Severity levels in ascending order. */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error'

/**
 * Structured fields attached to a log line. SCALAR-ONLY by design: objects and
 * arrays are rejected at compile time so content/PII cannot be logged by accident.
 */
export interface LogFields {
  readonly [key: string]: string | number | boolean | null | undefined
}

/** The logging surface used across the codebase. */
export interface Logger {
  debug(module: string, message: string, fields?: LogFields): void
  info(module: string, message: string, fields?: LogFields): void
  warn(module: string, message: string, fields?: LogFields): void
  error(module: string, message: string, fields?: LogFields & { errorClass?: string }): void
  /** A child logger that merges `fields` into every line it emits. */
  child(fields: LogFields): Logger
}

/** Numeric rank per level, for the `minLevel` threshold comparison. */
const LEVEL_RANK: Readonly<Record<LogLevel, number>> = { debug: 10, info: 20, warn: 30, error: 40 }

/**
 * The module-level minimum level, mutated once per request from config by
 * {@link setLogLevel}. The default module {@link log} reads this live, so a
 * config-driven level applies without recreating loggers.
 */
let defaultMinLevel: LogLevel = 'info'

/** Set the process-wide minimum log level (called once from the worker entry). */
export function setLogLevel(level: LogLevel): void {
  defaultMinLevel = level
}

/** The exact string class name of an error (`InferenceError`, …), or the typeof. */
export function errorClassOf(error: unknown): string {
  return error instanceof Error ? error.constructor.name : typeof error
}

/** Default sink: warn/error → `console.error`, info/debug → `console.log`. */
function defaultSink(level: LogLevel, line: string): void {
  if (level === 'error' || level === 'warn') {
    console.error(line)
  } else {
    console.log(line)
  }
}

/**
 * Build a {@link Logger}. With no args, returns a logger bound to the live
 * module-level level (the {@link log} singleton). Pass `requestId`/`base` to bind
 * fields onto every line, `minLevel` to fix this logger's threshold, or `sink`/
 * `now` for tests.
 *
 * Time complexity: O(f) per call in the field count. Space complexity: O(f).
 */
export function createLogger(args: {
  requestId?: string
  base?: LogFields
  minLevel?: LogLevel
  sink?: (level: LogLevel, line: string) => void
  now?: () => string
} = {}): Logger {
  const sink = args.sink ?? defaultSink
  const now = args.now ?? ((): string => new Date().toISOString())
  const base: LogFields = {
    ...(args.requestId !== undefined ? { requestId: args.requestId } : {}),
    ...args.base,
  }
  const thresholdRank = (): number => LEVEL_RANK[args.minLevel ?? defaultMinLevel]

  function emit(level: LogLevel, module: string, message: string, fields?: LogFields): void {
    if (LEVEL_RANK[level] < thresholdRank()) {
      return
    }
    // The record is built field-by-field; the scalar-only LogFields type keeps any
    // object/array out at compile time, so no content can ride along.
    const record: Record<string, unknown> = { ts: now(), level, module, msg: message, ...base }
    if (fields !== undefined) {
      for (const [key, value] of Object.entries(fields)) {
        if (value !== undefined) {
          record[key] = value
        }
      }
    }
    try {
      sink(level, JSON.stringify(record))
    } catch {
      // Logging must never throw into business logic; a sink fault is swallowed.
    }
  }

  return {
    debug: (module, message, fields) => emit('debug', module, message, fields),
    info: (module, message, fields) => emit('info', module, message, fields),
    warn: (module, message, fields) => emit('warn', module, message, fields),
    error: (module, message, fields) => emit('error', module, message, fields),
    child: (childFields) => createLogger({ ...args, base: { ...base, ...childFields } }),
  }
}

/** The default module logger used across the codebase (level from {@link setLogLevel}). */
export const log: Logger = createLogger()
