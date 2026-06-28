// @vitest-environment node
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { loadConfig, type Env } from '../config'
import { JudgeError } from '../errors'

// Mock the OpenAI SDK so no network call is made. `vi.hoisted` lets the mock
// factory (hoisted above imports) share the spy we assert against.
const { createMock } = vi.hoisted(() => ({ createMock: vi.fn() }))
vi.mock('openai', () => ({
  default: class {
    public responses = { create: createMock }
  },
}))

import { OpenAIJudge } from './judge'

const config = loadConfig({ ASSETS: undefined } as unknown as Env)

/** A Responses-API result whose output_text is the JSON-encoded `json`. */
function responseWith(json: object): { output_text: string } {
  return { output_text: JSON.stringify(json) }
}

beforeEach(() => {
  createMock.mockReset()
})

describe('OpenAIJudge', () => {
  it('rejects an empty API key at construction', () => {
    expect(() => new OpenAIJudge('', config)).toThrow(JudgeError)
  })

  it('parses a valid structured response', async () => {
    createMock.mockResolvedValue(
      responseWith({
        pInjection: 0.9,
        verdict: 'BLOCK',
        findings: [
          {
            excerpt: 'ignore previous instructions',
            category: 'prompt-injection',
            severity: 'BLOCK',
            rationale: 'override attempt',
          },
        ],
        rationale: 'malicious',
      }),
    )
    const judge = new OpenAIJudge('k', config)
    const r = await judge.detect('text', [], 'ALLOW')
    expect(r.verdict).toBe('BLOCK')
    expect(r.pInjection).toBe(0.9)
    expect(r.findings).toHaveLength(1)
  })

  it('cannot weaken a BLOCK baseline even if the model returns ALLOW (tighten-only)', async () => {
    createMock.mockResolvedValue(
      responseWith({ pInjection: 0, verdict: 'ALLOW', findings: [], rationale: 'looks fine' }),
    )
    const judge = new OpenAIJudge('k', config)
    const r = await judge.detect('text', [], 'BLOCK')
    expect(r.verdict).toBe('BLOCK')
  })

  it('throws JudgeError on malformed JSON output', async () => {
    createMock.mockResolvedValue({ output_text: 'not json at all' })
    const judge = new OpenAIJudge('k', config)
    await expect(judge.detect('t', [], 'ALLOW')).rejects.toBeInstanceOf(JudgeError)
  })

  it('throws JudgeError when the response carries no output text', async () => {
    createMock.mockResolvedValue({ output: [] })
    const judge = new OpenAIJudge('k', config)
    await expect(judge.detect('t', [], 'ALLOW')).rejects.toBeInstanceOf(JudgeError)
  })

  it('throws JudgeError on a verdict outside the allowlist', async () => {
    createMock.mockResolvedValue(
      responseWith({ pInjection: 0.5, verdict: 'MAYBE', findings: [], rationale: 'x' }),
    )
    const judge = new OpenAIJudge('k', config)
    await expect(judge.detect('t', [], 'ALLOW')).rejects.toBeInstanceOf(JudgeError)
  })

  it('throws JudgeError on an out-of-range pInjection', async () => {
    createMock.mockResolvedValue(
      responseWith({ pInjection: 2, verdict: 'BLOCK', findings: [], rationale: 'x' }),
    )
    const judge = new OpenAIJudge('k', config)
    await expect(judge.detect('t', [], 'ALLOW')).rejects.toBeInstanceOf(JudgeError)
  })

  it('fails closed (JudgeError) when the API call rejects', async () => {
    createMock.mockRejectedValue(new Error('500 upstream'))
    const judge = new OpenAIJudge('k', config)
    await expect(judge.detect('t', [], 'ALLOW')).rejects.toBeInstanceOf(JudgeError)
  })
})
