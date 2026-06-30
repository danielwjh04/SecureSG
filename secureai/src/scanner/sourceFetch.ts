/**
 * Safe remote source fetching for scanner inputs. This is the single helper for
 * turning an untrusted `sourceUrl` into bounded text: parse, apply the SSRF
 * guard, resolve supported GitHub web URLs to raw content, re-check the resolved
 * URL, fetch with a timeout, and stream under the configured byte cap.
 */

import type { ScannerConfig } from '../config/env'
import type { ScanResult } from '../schemas/contract'
import { ParseError, SourceResolutionError } from '../errors'
import { assertSafeUrl } from '../pipeline/redirects'
import { parseGithubWebUrl, resolveGithubSkillUrl } from './github'

export interface RemoteSourceFetchOptions {
  readonly config: ScannerConfig
  readonly fetchImpl: typeof fetch
  readonly githubToken?: string
}

/**
 * Resolve and fetch a remote source URL safely.
 *
 * Time complexity: O(n) in the fetched body length plus bounded GitHub discovery
 * calls. Space complexity: O(n) up to the configured skill byte cap.
 *
 * @throws {ParseError} If the URL is malformed or the body exceeds the byte cap.
 * @throws {RedirectResolutionError} If a URL trips the SSRF guard.
 * @throws {SourceResolutionError} If the source cannot be resolved or fetched.
 */
export async function fetchRemoteSourceText(
  sourceUrl: string,
  options: RemoteSourceFetchOptions,
): Promise<{ text: string; source: ScanResult['source'] }> {
  const trimmed = sourceUrl.trim()
  let parsed: URL
  try {
    parsed = new URL(trimmed)
  } catch (error: unknown) {
    throw new ParseError(`sourceUrl is not a valid URL: ${trimmed}`, { cause: error })
  }

  const schemes = new Set(options.config.allowedSchemes)
  assertSafeUrl(parsed, { allowedSchemes: schemes })

  const githubTarget = parseGithubWebUrl(parsed)
  let fetchUrl = parsed
  if (githubTarget !== null) {
    const rawUrl = await resolveGithubSkillUrl(
      githubTarget,
      options.fetchImpl,
      options.config.redirectTimeoutMs,
      options.githubToken,
    )
    fetchUrl = new URL(rawUrl)
    assertSafeUrl(fetchUrl, { allowedSchemes: schemes })
  }

  const response = await options.fetchImpl(fetchUrl.href, {
    signal: AbortSignal.timeout(options.config.redirectTimeoutMs),
  })
  if (!response.ok) {
    throw new SourceResolutionError(
      `source URL returned HTTP ${response.status}: ${fetchUrl.href}`,
    )
  }

  return {
    text: await readResponseTextCapped(response, options.config.skillMaxBytes),
    source: { kind: 'url', ref: fetchUrl.href },
  }
}

/**
 * Read a fetched source body with a hard byte cap.
 *
 * Time complexity: O(n) up to `maxBytes + 1`. Space complexity: O(n) up to
 * `maxBytes`.
 *
 * @throws {ParseError} If the response body exceeds the configured byte cap.
 */
export async function readResponseTextCapped(response: Response, maxBytes: number): Promise<string> {
  if (response.body === null) {
    return ''
  }

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let bytesRead = 0
  let text = ''

  try {
    for (;;) {
      const chunk = await reader.read()
      if (chunk.done) {
        break
      }
      const value = chunk.value
      if (value === undefined) {
        continue
      }
      bytesRead += value.byteLength
      if (bytesRead > maxBytes) {
        await reader.cancel()
        throw new ParseError(`source body exceeds limit ${maxBytes}`)
      }
      text += decoder.decode(value, { stream: true })
    }
  } finally {
    reader.releaseLock()
  }

  text += decoder.decode()
  return text
}
