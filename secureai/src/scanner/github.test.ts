// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { SourceResolutionError } from '../errors'
import {
  parseGithubWebUrl,
  resolveGithubSkillUrl,
  type GithubTarget,
} from './github'

// These tests drive the GitHub source resolver with a MOCK fetch, so no real
// network or GitHub API is touched. They assert the two responsibilities the
// resolver owns: (1) parsing a GitHub *web* URL into a structured target (or
// `null` for shapes we must not rewrite), and (2) turning that target into the
// raw SKILL.md URL — via a deterministic blob rewrite (no API), or via the
// repo/tree discovery API with a reproducible shallowest-path choice.

const TIMEOUT_MS = 5000

/** A GitHub tree entry as the recursive trees API returns it (subset we read). */
interface TreeEntry {
  path: string
  type: 'blob' | 'tree'
}

/**
 * Build a mock `fetch` from a routing table of `url -> json | status`. A routed
 * entry returns its JSON with status 200 unless an explicit status is given; an
 * unrouted URL throws, surfacing accidental or unexpected requests (e.g. a blob
 * rewrite that wrongly hit the API).
 */
function mockFetch(
  routes: Record<string, { json?: unknown; status?: number }>,
): { fetch: typeof fetch; calls: string[] } {
  const calls: string[] = []
  const impl = async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === 'string' ? input : input.toString()
    calls.push(url)
    const route = routes[url]
    if (route === undefined) {
      throw new Error(`unexpected fetch for ${url}`)
    }
    const status = route.status ?? 200
    const body = route.json === undefined ? '' : JSON.stringify(route.json)
    return new Response(body, {
      status,
      headers: { 'content-type': 'application/json' },
    })
  }
  return { fetch: impl as unknown as typeof fetch, calls }
}

/** A fetch that fails the test if it is ever called (for the no-API blob path). */
const NEVER_FETCH: typeof fetch = (() => {
  throw new Error('resolver must not fetch for a blob URL')
}) as unknown as typeof fetch

const API = 'https://api.github.com/repos/netresearch/context7-skill'
const TREE_MAIN = `${API}/git/trees/main?recursive=1`
const RAW = 'https://raw.githubusercontent.com/netresearch/context7-skill'

describe('parseGithubWebUrl', () => {
  it('parses a bare repository root', () => {
    const target = parseGithubWebUrl(
      new URL('https://github.com/netresearch/context7-skill'),
    )
    expect(target).toEqual<GithubTarget>({
      kind: 'repo',
      owner: 'netresearch',
      repo: 'context7-skill',
    })
  })

  it('normalizes www. and strips a trailing .git', () => {
    const target = parseGithubWebUrl(
      new URL('https://www.github.com/netresearch/context7-skill.git'),
    )
    expect(target).toEqual<GithubTarget>({
      kind: 'repo',
      owner: 'netresearch',
      repo: 'context7-skill',
    })
  })

  it('parses a blob URL into a ref + path', () => {
    const target = parseGithubWebUrl(
      new URL(
        'https://github.com/netresearch/context7-skill/blob/main/skills/context7/SKILL.md',
      ),
    )
    expect(target).toEqual<GithubTarget>({
      kind: 'blob',
      owner: 'netresearch',
      repo: 'context7-skill',
      ref: 'main',
      path: 'skills/context7/SKILL.md',
    })
  })

  it('parses a tree URL into a ref + subdir', () => {
    const target = parseGithubWebUrl(
      new URL(
        'https://github.com/netresearch/context7-skill/tree/main/skills',
      ),
    )
    expect(target).toEqual<GithubTarget>({
      kind: 'tree',
      owner: 'netresearch',
      repo: 'context7-skill',
      ref: 'main',
      subdir: 'skills',
    })
  })

  it('returns null for a non-GitHub host', () => {
    expect(
      parseGithubWebUrl(new URL('https://gitlab.com/owner/repo')),
    ).toBeNull()
  })

  it('returns null for a non-skill GitHub path (issues)', () => {
    expect(
      parseGithubWebUrl(
        new URL('https://github.com/netresearch/context7-skill/issues/1'),
      ),
    ).toBeNull()
  })

  it('returns null for an owner-only URL', () => {
    expect(parseGithubWebUrl(new URL('https://github.com/netresearch'))).toBeNull()
  })
})

describe('resolveGithubSkillUrl — blob (no API call)', () => {
  it('rewrites a blob URL straight to the raw host', async () => {
    const target: GithubTarget = {
      kind: 'blob',
      owner: 'netresearch',
      repo: 'context7-skill',
      ref: 'main',
      path: 'skills/context7/SKILL.md',
    }
    const url = await resolveGithubSkillUrl(target, NEVER_FETCH, TIMEOUT_MS)
    expect(url).toBe(`${RAW}/main/skills/context7/SKILL.md`)
  })
})

describe('resolveGithubSkillUrl — repo root (default branch + tree)', () => {
  it('finds the SKILL.md via the default branch and tree API', async () => {
    const { fetch, calls } = mockFetch({
      [API]: { json: { default_branch: 'main' } },
      [TREE_MAIN]: {
        json: {
          tree: [
            { path: 'README.md', type: 'blob' },
            { path: 'skills/context7/SKILL.md', type: 'blob' },
            { path: 'skills', type: 'tree' },
          ] satisfies TreeEntry[],
          truncated: false,
        },
      },
    })
    const target: GithubTarget = {
      kind: 'repo',
      owner: 'netresearch',
      repo: 'context7-skill',
    }

    const url = await resolveGithubSkillUrl(target, fetch, TIMEOUT_MS)

    expect(url).toBe(`${RAW}/main/skills/context7/SKILL.md`)
    // Exactly two discovery calls: repo meta, then the recursive tree.
    expect(calls).toEqual([API, TREE_MAIN])
  })

  it('passes an optional token as a Bearer Authorization header', async () => {
    let seenAuth: string | null = null
    const impl = async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      const url = typeof input === 'string' ? input : input.toString()
      const headers = new Headers(init?.headers)
      if (url === API) {
        seenAuth = headers.get('Authorization')
        return new Response(JSON.stringify({ default_branch: 'main' }), {
          status: 200,
        })
      }
      return new Response(
        JSON.stringify({ tree: [{ path: 'SKILL.md', type: 'blob' }] }),
        { status: 200 },
      )
    }
    const target: GithubTarget = {
      kind: 'repo',
      owner: 'netresearch',
      repo: 'context7-skill',
    }

    const url = await resolveGithubSkillUrl(
      target,
      impl as unknown as typeof fetch,
      TIMEOUT_MS,
      'ghp_secret',
    )

    expect(url).toBe(`${RAW}/main/SKILL.md`)
    expect(seenAuth).toBe('Bearer ghp_secret')
  })

  it('chooses the shallowest SKILL.md, breaking ties lexicographically', async () => {
    const { fetch } = mockFetch({
      [API]: { json: { default_branch: 'main' } },
      [TREE_MAIN]: {
        json: {
          tree: [
            { path: 'deep/nested/SKILL.md', type: 'blob' },
            { path: 'zeta/SKILL.md', type: 'blob' },
            { path: 'alpha/SKILL.md', type: 'blob' },
          ] satisfies TreeEntry[],
        },
      },
    })
    const target: GithubTarget = {
      kind: 'repo',
      owner: 'netresearch',
      repo: 'context7-skill',
    }

    const url = await resolveGithubSkillUrl(target, fetch, TIMEOUT_MS)

    // 'alpha/SKILL.md' and 'zeta/SKILL.md' are both depth 2; 'alpha' < 'zeta'.
    expect(url).toBe(`${RAW}/main/alpha/SKILL.md`)
  })

  it('throws SourceResolutionError when the repo has no SKILL.md', async () => {
    const { fetch } = mockFetch({
      [API]: { json: { default_branch: 'main' } },
      [TREE_MAIN]: {
        json: {
          tree: [
            { path: 'README.md', type: 'blob' },
            { path: 'src/index.ts', type: 'blob' },
          ] satisfies TreeEntry[],
        },
      },
    })
    const target: GithubTarget = {
      kind: 'repo',
      owner: 'netresearch',
      repo: 'context7-skill',
    }

    await expect(
      resolveGithubSkillUrl(target, fetch, TIMEOUT_MS),
    ).rejects.toBeInstanceOf(SourceResolutionError)
  })

  it('throws SourceResolutionError on a GitHub API error status', async () => {
    const { fetch } = mockFetch({ [API]: { status: 404 } })
    const target: GithubTarget = {
      kind: 'repo',
      owner: 'netresearch',
      repo: 'context7-skill',
    }

    await expect(
      resolveGithubSkillUrl(target, fetch, TIMEOUT_MS),
    ).rejects.toBeInstanceOf(SourceResolutionError)
  })

  it('throws SourceResolutionError on a 403 rate-limit response', async () => {
    const { fetch } = mockFetch({ [API]: { status: 403 } })
    const target: GithubTarget = {
      kind: 'repo',
      owner: 'netresearch',
      repo: 'context7-skill',
    }

    await expect(
      resolveGithubSkillUrl(target, fetch, TIMEOUT_MS),
    ).rejects.toThrow(/rate limit/i)
  })
})

describe('resolveGithubSkillUrl — tree (scoped to a subdir)', () => {
  it('only considers SKILL.md under the requested subdir', async () => {
    const { fetch, calls } = mockFetch({
      [TREE_MAIN]: {
        json: {
          tree: [
            { path: 'other/SKILL.md', type: 'blob' },
            { path: 'skills/context7/SKILL.md', type: 'blob' },
          ] satisfies TreeEntry[],
        },
      },
    })
    const target: GithubTarget = {
      kind: 'tree',
      owner: 'netresearch',
      repo: 'context7-skill',
      ref: 'main',
      subdir: 'skills',
    }

    const url = await resolveGithubSkillUrl(target, fetch, TIMEOUT_MS)

    // A tree URL carries its ref, so only the tree API is hit (no repo-meta call).
    expect(url).toBe(`${RAW}/main/skills/context7/SKILL.md`)
    expect(calls).toEqual([TREE_MAIN])
  })

  it('throws when no SKILL.md exists under the subdir', async () => {
    const { fetch } = mockFetch({
      [TREE_MAIN]: {
        json: {
          tree: [
            { path: 'other/SKILL.md', type: 'blob' },
          ] satisfies TreeEntry[],
        },
      },
    })
    const target: GithubTarget = {
      kind: 'tree',
      owner: 'netresearch',
      repo: 'context7-skill',
      ref: 'main',
      subdir: 'skills',
    }

    await expect(
      resolveGithubSkillUrl(target, fetch, TIMEOUT_MS),
    ).rejects.toBeInstanceOf(SourceResolutionError)
  })
})
