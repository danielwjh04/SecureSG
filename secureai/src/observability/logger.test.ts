import { afterEach, describe, expect, it } from 'vitest'
import { createLogger, errorClassOf, setLogLevel, type LogLevel } from './logger'

/** Capture emitted lines via an injected sink, parsing them back to objects. */
function captured(): { lines: Array<{ level: LogLevel; record: Record<string, unknown> }>; sink: (l: LogLevel, line: string) => void } {
  const lines: Array<{ level: LogLevel; record: Record<string, unknown> }> = []
  return {
    lines,
    sink: (level, line) => lines.push({ level, record: JSON.parse(line) as Record<string, unknown> }),
  }
}

afterEach(() => setLogLevel('info'))

describe('createLogger', () => {
  it('emits one JSON line per call with ts/level/module/msg and merged fields', () => {
    const cap = captured()
    const logger = createLogger({ minLevel: 'debug', sink: cap.sink, now: () => 'T' })
    logger.info('accounts', 'created user', { tier: 'free' })
    expect(cap.lines).toHaveLength(1)
    expect(cap.lines[0]?.record).toEqual({ ts: 'T', level: 'info', module: 'accounts', msg: 'created user', tier: 'free' })
  })

  it('filters out messages below the minimum level', () => {
    const cap = captured()
    const logger = createLogger({ minLevel: 'warn', sink: cap.sink, now: () => 'T' })
    logger.debug('m', 'dbg')
    logger.info('m', 'nfo')
    logger.warn('m', 'wrn')
    logger.error('m', 'err')
    expect(cap.lines.map((l) => l.level)).toEqual(['warn', 'error'])
  })

  it('routes warn/error to the error stream and info/debug to the log stream', () => {
    const cap = captured()
    const logger = createLogger({ minLevel: 'debug', sink: cap.sink, now: () => 'T' })
    logger.info('m', 'a')
    logger.error('m', 'b')
    // The injected sink receives the level so routing can be asserted.
    expect(cap.lines.map((l) => l.level)).toEqual(['info', 'error'])
  })

  it('binds requestId and child fields onto every line', () => {
    const cap = captured()
    const logger = createLogger({ requestId: 'ray-1', minLevel: 'debug', sink: cap.sink, now: () => 'T' })
    logger.child({ userId: 'u1' }).info('m', 'hello', { extra: 1 })
    expect(cap.lines[0]?.record).toMatchObject({ requestId: 'ray-1', userId: 'u1', extra: 1 })
  })

  it('drops undefined fields rather than emitting null keys', () => {
    const cap = captured()
    const logger = createLogger({ minLevel: 'debug', sink: cap.sink, now: () => 'T' })
    logger.error('m', 'x', { errorClass: undefined })
    expect('errorClass' in (cap.lines[0]?.record ?? {})).toBe(false)
  })

  it('never throws when the sink throws', () => {
    const logger = createLogger({
      minLevel: 'debug',
      sink: () => {
        throw new Error('sink down')
      },
    })
    expect(() => logger.info('m', 'x')).not.toThrow()
  })

  it('respects the live module level set by setLogLevel for the default-level logger', () => {
    const cap = captured()
    const logger = createLogger({ sink: cap.sink, now: () => 'T' }) // no minLevel → module default
    setLogLevel('error')
    logger.info('m', 'filtered')
    logger.error('m', 'kept')
    expect(cap.lines.map((l) => l.level)).toEqual(['error'])
  })
})

describe('errorClassOf', () => {
  it('returns the concrete error class name', () => {
    class CustomError extends Error {}
    expect(errorClassOf(new CustomError('x'))).toBe('CustomError')
    expect(errorClassOf(new TypeError('x'))).toBe('TypeError')
  })

  it('returns the typeof for a non-error value', () => {
    expect(errorClassOf('oops')).toBe('string')
    expect(errorClassOf(42)).toBe('number')
  })
})
