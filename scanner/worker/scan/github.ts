/**
 * GitHub-aware source resolution.
 *
 * The scanner's unit of input is a skill *manifest* (`SKILL.md`). A user,
 * however, naturally pastes a GitHub *web* URL — a repository root
 * (`github.com/owner/repo`), a tree (`.../tree/branch/dir`), or a blob
 * (`.../blob/branch/path`). Fetching those web URLs returns a ~350 KB HTML page
 * (GitHub's UI chrome), not the manifest: it overflows the parser's byte cap
 * and, even if it fit, would extract GitHub's own asset links instead of the
 * skill's. This module maps a GitHub web URL to the *raw* `SKILL.md` the agent
 * would actually learn, so the scan is meaningful instead of scanning chrome.
 *
 * Resolution strategy (fewest subrequests first):
 *   - blob URL  → deterministic rewrite to raw.githubusercontent.com (0 API calls).
 *   - tree URL  → list the ref's file tree once, pick the SKILL.md under the dir.
 *   - repo root → read the repo's default branch, then list its tree, pick the
 *                 SKILL.md. Selection is deterministic (shallowest path, then
 *                 lexicographic) so the produced proof is reproducible.
 *
 * All host/endpoint identifiers are GitHub-platform constants, pinned here and
 * deliberately NOT env-overridable (mirroring how `config.ts` pins the hash
 * algorithm): they are facts of the integration, not deployment tunables, and
 * making the API host overridable would be a needless SSRF footgun.
 *
 * Subrequest budget: resolution adds at most two subrequests (default-branch +
 * tree) on top of the single content fetch `resolveSkillText` already performs,
 * which stays within the free-plan cap for the default `maxUrls`/`maxRedirectHops`.
 */

import { SourceResolutionError } from '../errors'

/** GitHub web host whose URLs we rewrite. `www.` is normalized in too. */
const GITHUB_WEB_HOST = 'github.com'
/** Raw content host that serves file bytes (what we actually fetch + parse). */
const GITHUB_RAW_HOST = 'raw.githubusercontent.com'
/** GitHub REST API host used to discover the default branch and file tree. */
const GITHUB_API_HOST = 'api.github.com'
/** The skill manifest filename (Anthropic Agent Skills convention). */
const SKILL_MANIFEST_FILENAME = 'SKILL.md'
/** GitHub requires a User-Agent on every API request; an unset one yields 403. */
const GITHUB_API_USER_AGENT = 'SecureSG-Skill-Safety-Scanner'
/** Pin the REST API media type for stable response shapes. */
const GITHUB_API_ACCEPT = 'application/vnd.github+json'
/** Trailing `.git` to strip from a clone-style repo segment. */
const GIT_SUFFIX = '.git'
/** Path markers that introduce a `ref` + path within a repository. */
const BLOB_MARKER = 'blob'
const TREE_MARKER = 'tree'

/** A parsed GitHub web URL, discriminated by the shape we recognized. */
export type GithubTarget =
  | { readonly kind: 'repo'; readonly owner: string; readonly repo: string }
  | {
      readonly kind: 'tree'
      readonly owner: string
      readonly repo: string
      readonly ref: string
      readonly subdir: string
    }
  | {
      readonly kind: 'blob'
      readonly owner: string
      readonly repo: string
      readonly ref: string
      readonly path: string
    }

/**
 * Parse a GitHub *web* URL into a structured {@link GithubTarget}, or return
 * `null` if the URL is not a GitHub web URL we know how to resolve (a non-GitHub
 * host, or a GitHub path like `/owner/repo/issues/1` that is not a skill
 * location). A `null` result tells the caller to fetch the URL unchanged.
 *
 * Recognized shapes (path segments after the host):
 *   - [owner, repo]                         → repo root
 *   - [owner, repo, 'tree', ref, ...subdir] → a directory at a ref
 *   - [owner, repo, 'blob', ref, ...path]   → a single file at a ref
 *
 * A trailing `.git` on the repo segment is stripped; segments are percent-decoded
 * so an escaped path round-trips through {@link buildRawUrl}. A branch name
 * containing a slash is only handled correctly for repo-root inputs (where the
 * exact branch comes from the API); for blob/tree URLs the first post-marker
 * segment is taken as the ref, matching GitHub's own single-segment-ref default.
 *
 * Time complexity: O(s) in the number of path segments. Space complexity: O(s).
 *
 * @param url - A fully-parsed candidate URL.
 * @returns The structured target, or `null` if not a resolvable GitHub web URL.
 */
export function parseGithubWebUrl(url: URL): GithubTarget | null {
  const host = url.hostname.toLowerCase()
  if (host !== GITHUB_WEB_HOST && host !== `www.${GITHUB_WEB_HOST}`) {
    return null
  }

  const segments = url.pathname
    .split('/')
    .filter((segment) => segment.length > 0)
    .map((segment) => decodeURIComponent(segment))
  if (segments.length < 2) {
    return null
  }

  const owner = segments[0]!
  const repo = stripGitSuffix(segments[1]!)
  if (owner.length === 0 || repo.length === 0) {
    return null
  }

  if (segments.length === 2) {
    return { kind: 'repo', owner, repo }
  }

  const marker = segments[2]
  if (marker === BLOB_MARKER && segments.length >= 5) {
    return {
      kind: 'blob',
      owner,
      repo,
      ref: segments[3]!,
      path: segments.slice(4).join('/'),
    }
  }
  if (marker === TREE_MARKER && segments.length >= 4) {
    return {
      kind: 'tree',
      owner,
      repo,
      ref: segments[3]!,
      subdir: segments.slice(4).join('/'),
    }
  }

  // A github.com URL we do not recognize as a skill location (issues, pulls,
  // wiki, …). Tell the caller to fetch it unchanged rather than guess.
  return null
}

/**
 * Resolve a {@link GithubTarget} to the raw `SKILL.md` URL to fetch and scan.
 *
 * - blob: a direct, deterministic rewrite to the raw host — no API call.
 * - tree/repo: discover the ref (repo → default branch) and list the file tree
 *   once, then choose the SKILL.md deterministically (shallowest path, then
 *   lexicographic) so the resulting proof is reproducible across runs.
 *
 * Time complexity: O(t) in the repo tree entry count (one linear filter plus an
 *   O(m log m) sort of the m SKILL.md matches). Space complexity: O(m).
 *
 * @param target - The parsed GitHub web URL.
 * @param fetchImpl - Injected fetch (kept injectable for tests and the gallery).
 * @param timeoutMs - Per-request timeout for the discovery API calls.
 * @returns The absolute raw.githubusercontent.com URL of the chosen SKILL.md.
 * @throws {SourceResolutionError} If the API is unreachable/errors, or no
 *   SKILL.md exists under the requested scope.
 */
export async function resolveGithubSkillUrl(
  target: GithubTarget,
  fetchImpl: typeof fetch,
  timeoutMs: number,
  token?: string,
): Promise<string> {
  if (target.kind === 'blob') {
    return buildRawUrl(target.owner, target.repo, target.ref, target.path)
  }

  const ref =
    target.kind === 'repo'
      ? await fetchDefaultBranch(
          target.owner,
          target.repo,
          fetchImpl,
          timeoutMs,
          token,
        )
      : target.ref
  const subdir = target.kind === 'tree' ? target.subdir : ''

  const skillPaths = await fetchSkillManifestPaths(
    target.owner,
    target.repo,
    ref,
    fetchImpl,
    timeoutMs,
    token,
  )
  const chosen = chooseSkillPath(skillPaths, subdir)
  if (chosen === null) {
    const scope = subdir.length > 0 ? ` under '${subdir}'` : ''
    throw new SourceResolutionError(
      `no ${SKILL_MANIFEST_FILENAME} found in ${target.owner}/${target.repo}` +
        `${scope}; paste the raw ${SKILL_MANIFEST_FILENAME} URL or the skill ` +
        `text directly`,
    )
  }
  return buildRawUrl(target.owner, target.repo, ref, chosen)
}

/**
 * Strip a trailing `.git` from a clone-style repo segment (`repo.git` → `repo`).
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function stripGitSuffix(repo: string): string {
  return repo.endsWith(GIT_SUFFIX) ? repo.slice(0, -GIT_SUFFIX.length) : repo
}

/**
 * Read a repository's default branch via the GitHub REST API.
 *
 * Time complexity: O(1) request + O(b) JSON parse. Space complexity: O(b).
 *
 * @throws {SourceResolutionError} On an API failure or a missing branch field.
 */
async function fetchDefaultBranch(
  owner: string,
  repo: string,
  fetchImpl: typeof fetch,
  timeoutMs: number,
  token: string | undefined,
): Promise<string> {
  const url =
    `https://${GITHUB_API_HOST}/repos/` +
    `${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`
  const body = await githubApiJson(url, fetchImpl, timeoutMs, token)
  const branch = (body as { default_branch?: unknown }).default_branch
  if (typeof branch !== 'string' || branch.length === 0) {
    throw new SourceResolutionError(
      `could not determine the default branch for ${owner}/${repo}`,
    )
  }
  return branch
}

/**
 * List every `SKILL.md` path in a repo's tree at `ref` via the recursive GitHub
 * trees API. Only `blob` (file) entries are considered.
 *
 * Note: for a very large repository GitHub may mark the tree `truncated`; in
 * that rare case a deeply-nested SKILL.md beyond the truncation point is not
 * seen and resolution fails loudly (the caller raises a SourceResolutionError),
 * which is the fail-closed outcome — never a silent wrong pick.
 *
 * Time complexity: O(t) in the tree entry count. Space complexity: O(m) in the
 *   number of SKILL.md matches.
 *
 * @throws {SourceResolutionError} On an API failure or an unexpected response.
 */
async function fetchSkillManifestPaths(
  owner: string,
  repo: string,
  ref: string,
  fetchImpl: typeof fetch,
  timeoutMs: number,
  token: string | undefined,
): Promise<string[]> {
  const url =
    `https://${GITHUB_API_HOST}/repos/` +
    `${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/trees/` +
    `${encodeURIComponent(ref)}?recursive=1`
  const body = await githubApiJson(url, fetchImpl, timeoutMs, token)
  const tree = (body as { tree?: unknown }).tree
  if (!Array.isArray(tree)) {
    throw new SourceResolutionError(
      `unexpected tree response for ${owner}/${repo}@${ref}`,
    )
  }

  const paths: string[] = []
  for (const entry of tree) {
    if (entry === null || typeof entry !== 'object') {
      continue
    }
    const record = entry as { path?: unknown; type?: unknown }
    if (record.type !== 'blob' || typeof record.path !== 'string') {
      continue
    }
    if (isSkillManifestPath(record.path)) {
      paths.push(record.path)
    }
  }
  return paths
}

/**
 * GET a GitHub API URL and parse it as JSON, with the required `User-Agent`, a
 * pinned media type, and a per-request timeout. Every failure mode (transport,
 * non-2xx, non-JSON) becomes a typed `SourceResolutionError` rather than an
 * unhandled exception.
 *
 * Time complexity: O(b) in the body length. Space complexity: O(b).
 *
 * @throws {SourceResolutionError} On a transport fault, a non-OK status, or a
 *   body that is not valid JSON.
 */
async function githubApiJson(
  url: string,
  fetchImpl: typeof fetch,
  timeoutMs: number,
  token: string | undefined,
): Promise<unknown> {
  const headers: Record<string, string> = {
    'User-Agent': GITHUB_API_USER_AGENT,
    Accept: GITHUB_API_ACCEPT,
  }
  // An optional token raises the GitHub API rate limit from 60/hr (shared per
  // egress IP, which Cloudflare Workers pool) to 5000/hr. Public repos need no
  // scopes on the token; it is only used to authenticate the read.
  if (token !== undefined && token.length > 0) {
    headers.Authorization = `Bearer ${token}`
  }

  let response: Response
  try {
    response = await fetchImpl(url, {
      headers,
      signal: AbortSignal.timeout(timeoutMs),
    })
  } catch (error: unknown) {
    const cause = error instanceof Error ? error.constructor.name : 'unknown'
    throw new SourceResolutionError(
      `GitHub API request to ${url} failed (${cause})`,
      { cause: error },
    )
  }
  if (!response.ok) {
    // 403/429 from the GitHub API is almost always the unauthenticated rate
    // limit. Surface an actionable message rather than a bare status.
    if (response.status === 403 || response.status === 429) {
      throw new SourceResolutionError(
        'GitHub rate limit reached for this scanner. Try again shortly, or ' +
          'paste the skill text or a raw SKILL.md URL instead.',
      )
    }
    throw new SourceResolutionError(
      `GitHub API returned HTTP ${response.status} for ${url}`,
    )
  }
  try {
    return await response.json()
  } catch (error: unknown) {
    throw new SourceResolutionError(
      `GitHub API returned a non-JSON body for ${url}`,
      { cause: error },
    )
  }
}

/**
 * Report whether a repo-relative path's basename is the skill manifest filename
 * (case-insensitive, so `Skill.md` is matched while `mySKILL.md.txt` is not).
 *
 * Time complexity: O(p) in the path length. Space complexity: O(1).
 */
function isSkillManifestPath(path: string): boolean {
  const basename = path.slice(path.lastIndexOf('/') + 1)
  return basename.toLowerCase() === SKILL_MANIFEST_FILENAME.toLowerCase()
}

/**
 * Choose one SKILL.md path from the candidates, scoped to `subdir` when given.
 *
 * Selection is fully deterministic so the produced proof is reproducible: the
 * shallowest path (fewest segments — the most top-level skill) wins, with ties
 * broken lexicographically. No clock and no randomness participate.
 *
 * Time complexity: O(m log m) in the candidate count. Space complexity: O(m).
 *
 * @returns The chosen path, or `null` if nothing matched the scope.
 */
function chooseSkillPath(paths: readonly string[], subdir: string): string | null {
  const prefix = subdir.length > 0 ? `${subdir}/` : ''
  const scoped = paths.filter((path) => path.startsWith(prefix))
  if (scoped.length === 0) {
    return null
  }
  const sorted = [...scoped].sort((a, b) => {
    const depthA = a.split('/').length
    const depthB = b.split('/').length
    if (depthA !== depthB) {
      return depthA - depthB
    }
    return a < b ? -1 : a > b ? 1 : 0
  })
  return sorted[0] ?? null
}

/**
 * Build a raw.githubusercontent.com URL from repo coordinates, percent-encoding
 * every segment so an owner/repo/ref/path with reserved characters cannot break
 * out of its position in the URL.
 *
 * Time complexity: O(p) in the path segment count. Space complexity: O(p).
 */
function buildRawUrl(
  owner: string,
  repo: string,
  ref: string,
  path: string,
): string {
  const encodedPath = path
    .split('/')
    .map((segment) => encodeURIComponent(segment))
    .join('/')
  return (
    `https://${GITHUB_RAW_HOST}/${encodeURIComponent(owner)}/` +
    `${encodeURIComponent(repo)}/${encodeURIComponent(ref)}/${encodedPath}`
  )
}
